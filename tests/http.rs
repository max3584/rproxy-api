//! `http` rules: L7 routing through real sockets (src/http/server.rs).

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use reqwest::StatusCode;
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::pki::Pki;
use common::*;

/// An HTTP backend answering what it received as JSON; `/slow` takes two seconds.
async fn echo_backend(tag: &'static str) -> SocketAddr {
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| async move {
		if req.uri().path() == "/slow" {
			tokio::time::sleep(Duration::from_secs(2)).await;
		}
		let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		axum::Json(json!({
			"tag": tag, "uri": req.uri().to_string(), "host": h("host"), "xff": h("x-forwarded-for"),
			"proto": h("x-forwarded-proto"), "xhost": h("x-forwarded-host"), "real": h("x-real-ip"),
			"xport": h("x-forwarded-port"), "secret": h("x-secret"), "prefix": h("x-forwarded-prefix"),
			"replaced": h("x-replaced-path"), "xa": h("x-a"), "xb": h("x-b"),
		}))
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

fn http_rule(port: u16, http: Value) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})
}

fn url(addr: SocketAddr) -> String {
	format!("http://{addr}")
}

async fn get(port: u16, host: &str, path: &str) -> (StatusCode, Value) {
	let r = reqwest::Client::new()
		.get(format!("http://127.0.0.1:{port}{path}"))
		.header("Host", host)
		.header("X-Forwarded-For", "203.0.113.9")
		.timeout(Duration::from_secs(10))
		.send()
		.await
		.unwrap();
	let status = r.status();
	let text = r.text().await.unwrap();
	(status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

#[tokio::test]
async fn routes_by_host_path_and_priority() {
	let h = harness().await;
	let (a, b, c) = (echo_backend("A").await, echo_backend("B").await, echo_backend("C").await);
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [
					{"name": "site", "match": "Host(`a.test`)", "to": url(a)},
					{"name": "api", "match": "Host(`a.test`) && PathPrefix(`/api/`)", "to": url(b)},
					{"name": "forced", "match": "Path(`/api/pinned`) || Query(`pin`)", "priority": 1000, "to": url(c)},
				],
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["remote_addr"], "", "{v}");

	assert_eq!(get(port, "a.test", "/").await.1["tag"], "A");
	assert_eq!(get(port, "A.test:8080", "/x").await.1["tag"], "A", "host is compared without port, ignoring case");
	assert_eq!(get(port, "a.test", "/api/v4/users?x=1").await.1["uri"], "/api/v4/users?x=1");
	assert_eq!(get(port, "a.test", "/api/v4").await.1["tag"], "B");
	assert_eq!(get(port, "a.test", "/api/pinned").await.1["tag"], "C");
	assert_eq!(get(port, "b.test", "/?pin").await.1["tag"], "C");
	let (status, _) = get(port, "b.test", "/").await;
	assert_eq!(status, StatusCode::NOT_FOUND, "no route and no default");

	// changes apply to the next request
	let (status, v) = h
		.patch(
			&format!("tcp/127.0.0.1/{port}"),
			json!({"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": url(c)}], "default": {"status": 421}}}),
		)
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(get(port, "a.test", "/").await.1["tag"], "C");

	let (_, rules) = h.get("/rules").await;
	let r = &rules.as_array().unwrap()[0];
	assert!(r["stats"]["total_connections"].as_u64().unwrap() >= 1, "{r}");
	assert!(r["stats"]["rx_bytes"].as_u64().unwrap() > 0, "{r}");
}

#[tokio::test]
async fn services_weights_and_defaults() {
	let h = harness().await;
	let (a, b, d) = (echo_backend("A").await, echo_backend("B").await, echo_backend("D").await);
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [{"name": "app", "match": "Host(`app.test`)", "service": "app"}],
				"services": {
					"app": {"servers": [{"url": url(a), "weight": 2}, {"url": url(b)}]},
					"fallback": {"servers": [{"url": format!("{}/base/", url(d))}]},
				},
				"default": {"service": "fallback"},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut tags = vec![];
	for _ in 0..6 {
		tags.push(get(port, "app.test", "/").await.1["tag"].as_str().unwrap().to_string());
	}
	assert_eq!(tags.iter().filter(|t| *t == "A").count(), 4, "{tags:?}");
	assert_eq!(tags.iter().filter(|t| *t == "B").count(), 2, "{tags:?}");
	let (_, v) = get(port, "other.test", "/p?q=1").await;
	assert_eq!((v["tag"].as_str(), v["uri"].as_str()), (Some("D"), Some("/base/p?q=1")), "the server's path is a prefix: {v}");
}

#[tokio::test]
async fn forwarded_headers_and_host() {
	let h = harness().await;
	let a = echo_backend("A").await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [
					{"name": "keep", "match": "Host(`keep.test`)", "to": url(a)},
					{"name": "backend", "match": "Host(`own.test`)", "service": "own"},
				],
				"services": {"own": {"servers": [{"url": url(a)}], "pass_host_header": false}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (_, v) = get(port, "keep.test", "/").await;
	assert_eq!(v["host"], "keep.test", "{v}");
	assert_eq!(v["xff"], "127.0.0.1", "the client's own X-Forwarded-For is replaced: {v}");
	assert_eq!(v["real"], "127.0.0.1", "{v}");
	assert_eq!(v["proto"], "http", "{v}");
	assert_eq!(v["xhost"], "keep.test", "{v}");
	assert_eq!(v["xport"], port.to_string(), "{v}");
	let (_, v) = get(port, "own.test", "/").await;
	assert_eq!(v["host"], a.to_string(), "pass_host_header: false sends the backend's host: {v}");
	assert_eq!(v["xhost"], "own.test", "{v}");

	// headers named in Connection are hop-by-hop
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"GET / HTTP/1.1\r\nHost: keep.test\r\nConnection: close, x-secret\r\nX-Secret: 1\r\n\r\n").await.unwrap();
	let mut out = String::new();
	s.read_to_string(&mut out).await.unwrap();
	assert!(out.contains(r#""secret":"""#), "{out}");
}

#[tokio::test]
async fn backend_failures_are_502_and_504() {
	let h = harness().await;
	let a = echo_backend("A").await;
	// nothing listens on a port that was just free
	let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [
					{"name": "dead", "match": "Host(`dead.test`)", "to": url(dead)},
					{"name": "slow", "match": "Host(`slow.test`)", "service": "slow"},
				],
				"services": {"slow": {"servers": [{"url": url(a)}], "timeouts": {"response": "300ms"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(get(port, "dead.test", "/").await.0, StatusCode::BAD_GATEWAY);
	assert_eq!(get(port, "slow.test", "/slow").await.0, StatusCode::GATEWAY_TIMEOUT);
	assert_eq!(get(port, "slow.test", "/").await.1["tag"], "A");
}

/// A backend that accepts a WebSocket-style upgrade and then echoes with a prefix.
async fn upgrade_backend() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let mut head = vec![];
				let mut b = [0u8; 1];
				while !head.ends_with(b"\r\n\r\n") {
					if s.read(&mut b).await.unwrap_or(0) == 0 {
						return;
					}
					head.push(b[0]);
				}
				let head = String::from_utf8_lossy(&head).to_ascii_lowercase();
				if !head.contains("upgrade: websocket") || !head.contains("connection: upgrade") {
					let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n").await;
					return;
				}
				s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
				let mut buf = [0u8; 256];
				while let Ok(n) = s.read(&mut buf).await {
					if n == 0 || s.write_all(&[b"WS:", &buf[..n]].concat()).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

#[tokio::test]
async fn upgrades_pass_through() {
	let h = harness().await;
	let ws = upgrade_backend().await;
	let port = free_port();
	let (status, v) =
		h.post(http_rule(port, json!({"routes": [{"name": "ws", "match": "Path(`/ws`)", "to": url(ws)}]}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"GET /ws HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
	let mut head = vec![];
	let mut b = [0u8; 1];
	while !head.ends_with(b"\r\n\r\n") {
		assert_eq!(s.read(&mut b).await.unwrap(), 1, "{}", String::from_utf8_lossy(&head));
		head.push(b[0]);
	}
	assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
	s.write_all(b"ping").await.unwrap();
	let mut buf = [0u8; 16];
	let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
	assert_eq!(&buf[..n], b"WS:ping");

	// deleting the rule closes upgraded connections too
	assert_eq!(h.delete(&format!("tcp/127.0.0.1/{port}")).await, StatusCode::NO_CONTENT);
	let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap_or(0);
	assert_eq!(n, 0);
}

/// An HTTPS backend with a certificate from `pki`, answering with a fixed body.
async fn https_backend(pki: &Pki) -> SocketAddr {
	let acceptor = pki.acceptor(&pki.server("back", &["back.test"]));
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (s, _) = listener.accept().await.unwrap();
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				let Ok(mut s) = acceptor.accept(s).await else { return };
				let mut head = vec![];
				let mut b = [0u8; 1];
				while !head.ends_with(b"\r\n\r\n") {
					if s.read(&mut b).await.unwrap_or(0) == 0 {
						return;
					}
					head.push(b[0]);
				}
				let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\nsecure").await;
				let _ = s.shutdown().await;
			});
		}
	});
	addr
}

#[tokio::test]
async fn tls_terminate_with_http2_and_https_backends() {
	let pki = Pki::new("l7");
	let front = pki.server("front", &["a.test"]);
	let a = echo_backend("A").await;
	let secure = https_backend(&pki).await;
	let h = harness().await;
	let port = free_port();
	let mut body = http_rule(
		port,
		json!({
			"routes": [
				// as long as the other match: the order decides
				{"name": "secure", "match": "Path(`/secure`)", "to": format!("https://{secure}")},
				{"name": "plain", "match": "PathPrefix(`/`)", "to": url(a)},
			],
		}),
	);
	body["tls"] = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
		"upstream": {"server_name": "back.test", "ca_file": pki.ca_file},
	});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(v["tls"]["alpn"].as_array().is_none_or(|a| a.is_empty()), "the settings stay as given: {v}");

	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let tls = pki.connector_alpn(None, &["h2", "http/1.1"]).connect(ServerName::try_from("a.test").unwrap(), tcp).await.unwrap();
	assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]), "HTTP/2 is offered to http rules");
	let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await.unwrap();
	tokio::spawn(conn);
	let mut send = |path: &str| {
		let req = hyper::Request::get(format!("https://a.test{path}")).body(Empty::<Bytes>::new()).unwrap();
		sender.send_request(req)
	};
	let resp = send("/h2?x").await.unwrap();
	assert_eq!(resp.status(), StatusCode::OK);
	let v: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
	assert_eq!((v["tag"].as_str(), v["uri"].as_str(), v["proto"].as_str()), (Some("A"), Some("/h2?x"), Some("https")), "{v}");
	assert_eq!(v["host"], "a.test", "HTTP/2 :authority becomes Host: {v}");

	let resp = send("/secure").await.unwrap();
	assert_eq!(resp.status(), StatusCode::OK);
	assert_eq!(&resp.into_body().collect().await.unwrap().to_bytes()[..], b"secure", "https:// backend verified with tls.upstream.ca_file");
}

#[tokio::test]
async fn http_rules_refuse_what_does_not_fit() {
	let h = harness().await;
	let routes = json!({"routes": [{"name": "a", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:1"}]});
	let mut body = http_rule(free_port(), routes.clone());
	body["tls"] = json!({"mode": "sni", "routes": [{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": 1}]});
	assert_eq!(h.post(body).await.0, StatusCode::BAD_REQUEST);
	let mut body = http_rule(free_port(), routes.clone());
	body["protocol"] = json!("udp");
	assert_eq!(h.post(body).await.0, StatusCode::BAD_REQUEST);

	// an L4 rule does not become an http rule
	let a = echo_backend("A").await;
	let port = free_port();
	assert_eq!(h.post(rule("tcp", port, a)).await.0, StatusCode::CREATED);
	let (status, v) = h.patch(&format!("tcp/127.0.0.1/{port}"), json!({"http": routes})).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("unsupported")), "{v}");
}

/// A request without following redirects; returns the response.
async fn raw(port: u16, method: reqwest::Method, host: &str, path: &str, headers: &[(&str, &str)]) -> reqwest::Response {
	let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
	let mut req = client.request(method, format!("http://127.0.0.1:{port}{path}")).header("Host", host);
	for (k, v) in headers {
		req = req.header(*k, *v);
	}
	req.timeout(Duration::from_secs(10)).send().await.unwrap()
}

#[tokio::test]
async fn redirects_and_fixed_answers() {
	let h = harness().await;
	let cdn = echo_backend("CDN").await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [
					{"name": "www", "match": "HostRegexp(`^www\\.`)", "middlewares": ["no-www"]},
					{"name": "to-https", "match": "Host(`secure.test`)", "middlewares": ["to-https"]},
					{"name": "cdn-allowed", "match": "Host(`cdn.test`) && PathPrefix(`/file/`)", "to": url(cdn)},
					{"name": "cdn-block", "match": "Host(`cdn.test`)", "middlewares": ["forbidden"]},
				],
				"middlewares": {
					"no-www": {"redirect_regex": {"regex": "^http://www\\.([^/]+)(.*)$", "replacement": "https://$1$2", "permanent": true}},
					"to-https": {"redirect_scheme": {"scheme": "https"}},
					"forbidden": {"respond": {"status": 403, "body": "blocked"}},
				},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let r = raw(port, reqwest::Method::GET, "secure.test:8080", "/a?b=1", &[]).await;
	assert_eq!((r.status(), r.headers()["location"].to_str().unwrap()), (StatusCode::FOUND, "https://secure.test/a?b=1"));
	let r = raw(port, reqwest::Method::POST, "secure.test", "/", &[]).await;
	assert_eq!(r.status(), StatusCode::TEMPORARY_REDIRECT, "other methods keep method and body");
	let r = raw(port, reqwest::Method::GET, "www.site.test", "/p?q", &[]).await;
	assert_eq!((r.status(), r.headers()["location"].to_str().unwrap()), (StatusCode::MOVED_PERMANENTLY, "https://site.test/p?q"));

	assert_eq!(get(port, "cdn.test", "/file/x").await.1["tag"], "CDN");
	let r = raw(port, reqwest::Method::GET, "cdn.test", "/admin", &[]).await;
	assert_eq!(r.status(), StatusCode::FORBIDDEN);
	assert_eq!(r.text().await.unwrap(), "blocked");
}

#[tokio::test]
async fn ip_allow_headers_and_paths() {
	let h = harness().await;
	let a = echo_backend("A").await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [
					{"name": "internal", "match": "PathPrefix(`/internal`)", "to": url(a), "middlewares": ["lan"]},
					{"name": "api", "match": "PathPrefix(`/api/`)", "to": url(a), "middlewares": ["sec", "strip"]},
					{"name": "files", "match": "PathPrefix(`/files/`)", "to": url(a), "middlewares": ["rewrite"]},
				],
				"middlewares": {
					"lan": {"ip_allow": {"source_range": ["10.0.0.0/8"]}},
					"sec": {"headers": {
						"request": {"set": {"X-A": "1"}, "remove": ["X-B"]},
						"response": {"set": {"X-Served-By": "rproxy"}},
						"hsts": {"max_age": 31536000},
						"frame_deny": true,
						"cors": {"allow_origins": ["https://app.test"], "allow_methods": ["GET", "POST"], "max_age": 60},
					}},
					"strip": {"strip_prefix": {"prefixes": ["/api"]}},
					"rewrite": {"replace_path_regex": {"regex": "^/files/(.*)$", "replacement": "/storage/$1"}},
				},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let (status, _) = get(port, "x.test", "/internal/x").await;
	assert_eq!(status, StatusCode::FORBIDDEN, "127.0.0.1 is outside 10.0.0.0/8");

	let r = raw(port, reqwest::Method::GET, "x.test", "/api/users?id=1", &[("x-b", "drop me"), ("origin", "https://app.test")]).await;
	assert_eq!(r.headers()["x-served-by"], "rproxy");
	assert_eq!(r.headers()["x-frame-options"], "DENY");
	assert_eq!(r.headers()["access-control-allow-origin"], "https://app.test");
	assert!(r.headers().get("strict-transport-security").is_none(), "HSTS only over https");
	let v: Value = r.json().await.unwrap();
	assert_eq!((v["uri"].as_str(), v["prefix"].as_str()), (Some("/users?id=1"), Some("/api")), "{v}");
	assert_eq!((v["xa"].as_str(), v["xb"].as_str()), (Some("1"), Some("")), "{v}");

	// CORS preflight from an allowed origin is answered by rproxy
	let r = raw(
		port,
		reqwest::Method::OPTIONS,
		"x.test",
		"/api/users",
		&[("origin", "https://app.test"), ("access-control-request-method", "POST")],
	)
	.await;
	assert_eq!(r.status(), StatusCode::NO_CONTENT);
	assert_eq!(r.headers()["access-control-allow-methods"], "GET, POST");
	assert_eq!(r.headers()["access-control-allow-origin"], "https://app.test");
	assert_eq!(r.headers()["access-control-max-age"], "60");

	let (_, v) = get(port, "x.test", "/files/a/b.iso").await;
	assert_eq!((v["uri"].as_str(), v["replaced"].as_str()), (Some("/storage/a/b.iso"), Some("/files/a/b.iso")), "{v}");
}

#[tokio::test]
async fn hsts_over_https() {
	let pki = Pki::new("hsts");
	let front = pki.server("front", &["a.test"]);
	let a = echo_backend("A").await;
	let h = harness().await;
	let port = free_port();
	let mut body = http_rule(
		port,
		json!({
			"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": url(a), "middlewares": ["hsts"]}],
			"middlewares": {"hsts": {"headers": {"hsts": {"max_age": 60, "include_subdomains": true, "preload": true}}}},
		}),
	);
	body["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}]});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let tls = pki.connector_alpn(None, &["http/1.1"]).connect(ServerName::try_from("a.test").unwrap(), tcp).await.unwrap();
	let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
	tokio::spawn(conn);
	let req = hyper::Request::get("/").header("host", "a.test").body(Empty::<Bytes>::new()).unwrap();
	let resp = sender.send_request(req).await.unwrap();
	assert_eq!(resp.headers()["strict-transport-security"], "max-age=60; includeSubDomains; preload");
}
