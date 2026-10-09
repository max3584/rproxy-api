//! `forward_auth` for the Gateway API's ExternalAuth filter (v0.4.3): Envoy's
//! HTTP ext_authz (`client_request`, `allow_status`, `forward_body`,
//! `response_headers: ["*"]`, `service`), the gRPC ext_authz protocol
//! (`protocol: grpc`) and `forward_auth` per server.

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use common::*;
use rproxy_api::l7::middleware::ext_authz::encode;

/// One request as a server saw it: method, path with query, headers, body.
#[derive(Clone, Debug, Default)]
struct Seen {
	method: String,
	path: String,
	headers: HashMap<String, Vec<String>>,
	body: Vec<u8>,
}

type Log = Arc<Mutex<Vec<Seen>>>;

async fn seen(req: axum::extract::Request) -> Seen {
	let (parts, body) = req.into_parts();
	let mut headers: HashMap<String, Vec<String>> = HashMap::new();
	for (k, v) in &parts.headers {
		headers.entry(k.as_str().to_string()).or_default().push(String::from_utf8_lossy(v.as_bytes()).into_owned());
	}
	let body = axum::body::to_bytes(body, 1 << 20).await.unwrap_or_default().to_vec();
	Seen { method: parts.method.to_string(), path: parts.uri.path_and_query().map(|p| p.to_string()).unwrap_or_default(), headers, body }
}

/// An HTTP auth server: `authorization: allow` gets 200 with identity headers, `ok204` 204,
/// anything else 403 with a body and a header.
async fn http_auth() -> (SocketAddr, Log) {
	let log: Log = Arc::default();
	let l = log.clone();
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
		let l = l.clone();
		async move {
			let s = seen(req).await;
			let auth = s.headers.get("authorization").and_then(|v| v.first()).cloned().unwrap_or_default();
			l.lock().unwrap().push(s);
			let b = axum::response::Response::builder();
			match auth.as_str() {
				"allow" => b
					.status(200)
					.header("x-auth-user", "alice")
					.header("x-extra", "e")
					.header("content-type", "text/plain")
					.body(axum::body::Body::from("ok"))
					.unwrap(),
				"ok204" => b.status(204).body(axum::body::Body::empty()).unwrap(),
				_ => b.status(403).header("x-why", "nope").body(axum::body::Body::from("denied")).unwrap(),
			}
		}
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(addr, log)
}

/// A backend answering what it received as JSON.
async fn echo(tag: &'static str) -> (SocketAddr, Log) {
	let log: Log = Arc::default();
	let l = log.clone();
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
		let l = l.clone();
		async move {
			let s = seen(req).await;
			l.lock().unwrap().push(s.clone());
			axum::Json(json!({"tag": tag, "path": s.path, "headers": s.headers, "body": String::from_utf8_lossy(&s.body)}))
		}
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(addr, log)
}

/// A gRPC ext_authz server (HTTP/2 with prior knowledge): `authorization: allow` is OK with a
/// header for the request and one for the response, `broken` answers grpc-status 12
/// (UNIMPLEMENTED), anything else is denied with 401.
async fn grpc_auth() -> (SocketAddr, Arc<Mutex<Vec<encode::Seen>>>) {
	let log: Arc<Mutex<Vec<encode::Seen>>> = Arc::default();
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let l = log.clone();
	tokio::spawn(async move {
		loop {
			let Ok((tcp, _)) = listener.accept().await else { return };
			let l = l.clone();
			tokio::spawn(async move {
				let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
					let l = l.clone();
					async move {
						assert_eq!(req.uri().path(), "/envoy.service.auth.v3.Authorization/Check");
						assert_eq!(req.headers()["content-type"], "application/grpc");
						let body = req.into_body().collect().await.unwrap().to_bytes();
						let check = encode::read_request(&body).unwrap();
						let auth = check.headers.iter().find(|(k, _)| k == "authorization").map(|(_, v)| v.clone()).unwrap_or_default();
						l.lock().unwrap().push(check);
						let (message, status) = match auth.as_str() {
							"allow" => (
								encode::ok(
									&[encode::header("x-user", "alice", None)],
									&["x-drop"],
									&[encode::header("x-resp", "from-authz", None)],
								),
								"0",
							),
							"broken" => (Bytes::new(), "12"),
							_ => (encode::denied(401, &[encode::header("www-authenticate", "Bearer", None)], "who are you"), "0"),
						};
						let mut trailers = hyper::HeaderMap::new();
						trailers.insert("grpc-status", status.parse().unwrap());
						let frames: Vec<Result<Frame<Bytes>, Infallible>> = vec![Ok(Frame::data(message)), Ok(Frame::trailers(trailers))];
						let resp = hyper::Response::builder()
							.header("content-type", "application/grpc")
							.body(StreamBody::new(futures_util::stream::iter(frames)))
							.unwrap();
						Ok::<_, Infallible>(resp)
					}
				});
				let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
					.serve_connection(hyper_util::rt::TokioIo::new(tcp), service)
					.await;
			});
		}
	});
	(addr, log)
}

async fn rule(h: &Harness, http: Value) -> u16 {
	let port = free_port();
	let (status, v) = h.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	port
}

fn client() -> reqwest::Client {
	reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build().unwrap()
}

async fn send(req: reqwest::RequestBuilder) -> (StatusCode, reqwest::header::HeaderMap, Value) {
	let r = req.send().await.unwrap();
	let (status, headers) = (r.status(), r.headers().clone());
	let text = r.text().await.unwrap_or_default();
	(status, headers, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

#[tokio::test]
async fn envoy_style_http_ext_authz() {
	let h = harness().await;
	let (auth, auth_log) = http_auth().await;
	let (b, _) = echo("b").await;
	let port = rule(
		&h,
		json!({
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "b", "middlewares": ["ext"]}],
			"services": {
				"b": {"servers": [{"url": format!("http://{b}")}]},
				"authz": {"servers": [{"url": format!("http://{auth}")}]},
			},
			"middlewares": {"ext": {"forward_auth": {
				"service": "authz", "path": "/auth", "client_request": true, "allow_status": ["200"],
				"request_headers": ["authorization", "x-allowed"], "response_headers": ["*"], "forward_body": {"max_size": 16},
			}}},
		}),
	)
	.await;
	let base = format!("http://127.0.0.1:{port}");
	let post = |auth: &str, body: &'static str| {
		client()
			.post(format!("{base}/app/x?q=1"))
			.header("host", "app.example")
			.header("authorization", auth)
			.header("x-allowed", "1")
			.header("x-secret", "s")
			.header("content-type", "application/json")
			.body(body)
	};
	let (status, _, v) = send(post("allow", "hello")).await;
	assert_eq!(status, 200, "{v}");
	{
		let log = auth_log.lock().unwrap();
		let s = log.last().unwrap();
		assert_eq!((s.method.as_str(), s.path.as_str()), ("POST", "/auth/app/x?q=1"), "the client's method, the path after the prefix");
		assert_eq!(s.headers["host"], ["app.example"], "the client's Host");
		assert_eq!(s.headers["content-length"], ["5"]);
		assert_eq!(s.body, b"hello");
		assert_eq!(s.headers["x-allowed"], ["1"]);
		assert!(!s.headers.contains_key("x-secret"), "only the headers asked for");
	}
	assert_eq!(v["headers"]["x-auth-user"], json!(["alice"]), "all of the answer's headers");
	assert_eq!(v["headers"]["x-extra"], json!(["e"]));
	assert_eq!(v["headers"]["content-type"], json!(["application/json"]), "not those about the answer");
	assert_eq!(v["body"], "hello", "the body still reaches the backend");

	let (status, headers, v) = send(post("deny", "x")).await;
	assert_eq!((status.as_u16(), headers["x-why"].to_str().unwrap(), v.as_str()), (403, "nope", Some("denied")));
	// only 200 allows: the auth server's 204 goes to the client
	assert_eq!(send(post("ok204", "x")).await.0, 204);
	// a body larger than forward_body.max_size
	assert_eq!(send(post("allow", "0123456789abcdefg")).await.0, 413);
	// without a body: Content-Length 0
	let (status, _, _) = send(client().get(format!("{base}/g")).header("authorization", "allow")).await;
	assert_eq!(status, 200);
	assert_eq!(auth_log.lock().unwrap().last().unwrap().headers["content-length"], ["0"]);
}

#[tokio::test]
async fn grpc_ext_authz() {
	let h = harness().await;
	let (authz, log) = grpc_auth().await;
	let (b, _) = echo("b").await;
	let port = rule(
		&h,
		json!({
			"routes": [
				{"name": "addr", "match": "PathPrefix(`/a`)", "service": "b", "middlewares": ["by-address"]},
				{"name": "svc", "match": "PathPrefix(`/s`)", "service": "b", "middlewares": ["by-service"]},
			],
			"services": {
				"b": {"servers": [{"url": format!("http://{b}")}]},
				"authz": {"protocol": "h2c", "servers": [{"url": format!("http://{authz}")}]},
			},
			"middlewares": {
				"by-address": {"forward_auth": {"address": format!("http://{authz}"), "protocol": "grpc"}},
				"by-service": {"forward_auth": {"service": "authz", "protocol": "grpc", "request_headers": ["authorization"],
					"forward_body": {"max_size": 100}}},
			},
		}),
	)
	.await;
	let base = format!("http://127.0.0.1:{port}");
	for path in ["/a/1?x=y", "/s/1?x=y"] {
		let (status, headers, v) = send(
			client()
				.post(format!("{base}{path}"))
				.header("host", "app.example")
				.header("authorization", "allow")
				.header("x-drop", "d")
				.header("x-other", "o")
				.body("payload"),
		)
		.await;
		assert_eq!(status, 200, "{path}: {v}");
		assert_eq!(v["headers"]["x-user"], json!(["alice"]), "{path}");
		assert!(v["headers"].get("x-drop").is_none(), "{path}: headers_to_remove");
		assert_eq!(headers["x-resp"], "from-authz", "{path}: response_headers_to_add");
		let check = log.lock().unwrap().last().unwrap().clone();
		assert_eq!((check.method.as_str(), check.path.as_str(), check.host.as_str()), ("POST", path, "app.example"));
		let names: Vec<&str> = check.headers.iter().map(|(k, _)| k.as_str()).collect();
		if path.starts_with("/a") {
			assert!(names.contains(&"x-other"), "all headers by default: {names:?}");
			assert!(check.body.is_empty());
		} else {
			assert!(!names.contains(&"x-other") && names.contains(&"authorization"), "{names:?}");
			assert_eq!(check.body, b"payload");
		}
		assert!(names.contains(&":authority") && names.contains(&":path"), "{names:?}");
	}
	let (status, headers, v) = send(client().get(format!("{base}/a")).header("authorization", "nope")).await;
	assert_eq!((status.as_u16(), v.as_str()), (401, Some("who are you")));
	assert_eq!(headers["www-authenticate"], "Bearer");
	// an auth server failing at the gRPC level lets nothing through
	assert_eq!(send(client().get(format!("{base}/a")).header("authorization", "broken")).await.0, 403);
}

#[tokio::test]
async fn forward_auth_per_server() {
	// the Gateway API's ExternalAuth filter on one backendRef: only requests to that server ask
	let h = harness().await;
	let (auth, auth_log) = http_auth().await;
	let (v1, _) = echo("v1").await;
	let (v2, _) = echo("v2").await;
	let port = rule(
		&h,
		json!({
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "pair"}],
			"services": {
				"pair": {"servers": [
					{"url": format!("http://{v1}"), "middlewares": ["ext"]},
					{"url": format!("http://{v2}")},
				]},
				"authz": {"servers": [{"url": format!("http://{auth}")}]},
			},
			"middlewares": {"ext": {"forward_auth": {"service": "authz", "client_request": true, "request_headers": ["authorization"]}}},
		}),
	)
	.await;
	let mut statuses = vec![];
	for _ in 0..4 {
		let (status, _, v) = send(client().get(format!("http://127.0.0.1:{port}/p")).header("authorization", "deny")).await;
		statuses.push((status.as_u16(), v["tag"].as_str().unwrap_or("").to_string()));
	}
	statuses.sort();
	assert_eq!(statuses, [(200, "v2".to_string()), (200, "v2".to_string()), (403, String::new()), (403, String::new())]);
	assert_eq!(auth_log.lock().unwrap().len(), 2, "asked only for v1");
	let (status, _, v) = send(client().get(format!("http://127.0.0.1:{port}/p")).header("authorization", "allow")).await;
	assert_eq!(status, 200);
	if v["tag"] == "v1" {
		assert_eq!(v["headers"]["authorization"], json!(["allow"]));
	}
}

#[tokio::test]
async fn forward_auth_shapes_are_checked() {
	let h = harness().await;
	let svc = json!({"b": {"servers": [{"url": "http://127.0.0.1:1"}]}, "a1": {"servers": [{"url": "http://127.0.0.1:2"}]}});
	for (fa, want) in [
		(json!({"address": "http://127.0.0.1:2", "service": "a1"}), "exactly one"),
		(json!({}), "exactly one"),
		(json!({"service": "nope"}), "not defined"),
		(json!({"address": "http://127.0.0.1:2", "path": "/x"}), "only with service"),
		(json!({"service": "a1", "path": "x"}), "must start with /"),
		(json!({"service": "a1", "protocol": "grpc"}), "h2 or h2c"),
		(json!({"address": "http://127.0.0.1:2", "protocol": "grpc", "client_request": true}), "takes no client_request"),
		(json!({"address": "https://127.0.0.1:2", "protocol": "grpc"}), "needs http://"),
		(json!({"address": "http://127.0.0.1:2", "allow_status": ["999"]}), "allow_status"),
		(json!({"address": "http://127.0.0.1:2", "forward_body": {"max_size": 0}}), "at least 1"),
		(json!({"address": "http://127.0.0.1:2", "response_headers": ["*", "x-a"]}), "stands alone"),
	] {
		let (status, v) = h
			.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "b", "middlewares": ["fa"]}],
				"services": svc, "middlewares": {"fa": {"forward_auth": fa}}}}))
			.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{fa}: {v}");
		assert!(v["error"].as_str().unwrap().contains(want), "{fa}: {v}");
	}
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(
		caps["features"]["forward_auth"],
		json!(["service", "grpc", "client_request", "allow_status", "forward_body", "all_response_headers"])
	);
	assert!(caps["features"]["server_middleware_kinds"].as_array().unwrap().iter().any(|k| k == "forward_auth"));
}
