//! The `cache` middleware (#340) through real sockets: one backend request per key and
//! `ttl` however many clients ask at once, the answer when the backend fails
//! (`stale_on_error`), what is never kept, the route's checks, and the statistics.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode as AxStatus};
use axum::response::IntoResponse;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use common::pki::{Issued, Pki};
use common::*;

/// A backend that counts requests, answers with the count and can be slowed down or broken.
struct Backend {
	hits: AtomicU64,
	status: AtomicU16,
	delay_ms: AtomicU64,
	addr: std::net::SocketAddr,
}

async fn backend() -> Arc<Backend> {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let b = Arc::new(Backend {
		hits: AtomicU64::new(0),
		status: AtomicU16::new(200),
		delay_ms: AtomicU64::new(0),
		addr: listener.local_addr().unwrap(),
	});
	fn count(b: &Backend) -> u64 {
		b.hits.fetch_add(1, Ordering::SeqCst) + 1
	}
	let app = axum::Router::new()
		.route(
			"/data",
			axum::routing::get(|State(b): State<Arc<Backend>>, headers: HeaderMap| async move {
				let n = count(&b);
				let delay = b.delay_ms.load(Ordering::SeqCst);
				if delay > 0 {
					tokio::time::sleep(Duration::from_millis(delay)).await;
				}
				let status = AxStatus::from_u16(b.status.load(Ordering::SeqCst)).unwrap();
				let user = headers.get("x-forwarded-user").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
				(status, [("content-type", "application/json")], axum::Json(json!({"n": n, "user": user}))).into_response()
			}),
		)
		.route(
			"/cookie",
			axum::routing::get(|State(b): State<Arc<Backend>>| async move { ([("set-cookie", "s=1")], count(&b).to_string()) }),
		)
		.route(
			"/private",
			axum::routing::get(|State(b): State<Arc<Backend>>| async move { ([("cache-control", "private")], count(&b).to_string()) }),
		)
		.route("/big", axum::routing::get(|State(b): State<Arc<Backend>>| async move { format!("{}{}", count(&b), "x".repeat(4096)) }))
		.fallback(|State(b): State<Arc<Backend>>| async move { count(&b).to_string() })
		.with_state(b.clone());
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	b
}

fn client() -> reqwest::Client {
	reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap()
}

/// A rule with one route through `middlewares` to `b`.
async fn rule(h: &Harness, b: &Backend, cache: Value) -> u16 {
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"routes": [{"name": "api", "match": "PathPrefix(`/`)", "to": format!("http://{}", b.addr), "middlewares": ["micro"]}],
				"middlewares": {"micro": {"cache": cache}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	port
}

async fn get(port: u16, path: &str, headers: &[(&str, &str)]) -> reqwest::Response {
	let mut r = client().get(format!("http://127.0.0.1:{port}{path}"));
	for (k, v) in headers {
		r = r.header(*k, *v);
	}
	r.send().await.unwrap()
}

fn x_cache(r: &reqwest::Response) -> String {
	r.headers().get("x-cache").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
}

#[tokio::test]
async fn many_clients_one_backend_request_per_ttl() {
	let h = harness().await;
	let b = backend().await;
	let port = rule(&h, &b, json!({"ttl": "1s"})).await;
	// the backend is slow: all of these come while the first is on its way
	b.delay_ms.store(300, Ordering::SeqCst);
	let answers = futures_util::future::join_all((0..40).map(|_| async move {
		let r = get(port, "/data", &[]).await;
		assert_eq!(r.status(), StatusCode::OK);
		let x = x_cache(&r);
		(x, r.json::<Value>().await.unwrap()["n"].clone())
	}))
	.await;
	assert_eq!(b.hits.load(Ordering::SeqCst), 1, "one request to the backend: {answers:?}");
	assert!(answers.iter().all(|(_, n)| *n == 1), "{answers:?}");
	assert_eq!(answers.iter().filter(|(x, _)| x == "MISS").count(), 1, "{answers:?}");
	b.delay_ms.store(0, Ordering::SeqCst);
	// fresh for ttl, with Age
	let r = get(port, "/data", &[]).await;
	assert_eq!((x_cache(&r).as_str(), r.headers().contains_key("age")), ("HIT", true));
	// another query is another key
	assert_eq!(get(port, "/data?page=2", &[]).await.json::<Value>().await.unwrap()["n"], 2);
	// a new answer once ttl has passed
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let r = get(port, "/data", &[]).await;
	assert_eq!(x_cache(&r), "MISS");
	assert_eq!(r.json::<Value>().await.unwrap()["n"], 3);
	// HEAD is answered from GET's answer
	let r = client().head(format!("http://127.0.0.1:{port}/data")).send().await.unwrap();
	assert_eq!((r.status(), x_cache(&r).as_str()), (StatusCode::OK, "HIT"));
	assert!(r.headers()["content-length"].to_str().unwrap().parse::<u64>().unwrap() > 0);
	assert_eq!(b.hits.load(Ordering::SeqCst), 3);

	// counted in stats.http and /metrics
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let v = wait_for(&h, &path, |v| v["stats"]["http"]["cache"]["hit"].as_u64() >= Some(41)).await;
	let stats = &v["stats"]["http"];
	assert_eq!(stats["cache"]["miss"], 3, "{stats}");
	assert_eq!(stats["routes"]["api"]["cache"]["micro"]["miss"], 3, "{stats}");
	let text = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	let labels = format!("protocol=\"tcp\",listen=\"127.0.0.1:{port}\"");
	assert!(text.contains(&format!("rproxy_http_cache_total{{{labels},route=\"api\",middleware=\"micro\",result=\"miss\"}} 3")), "{text}");
	// ?page=2 went out of date for good and was dropped when /data came again
	assert!(text.contains(&format!("rproxy_http_cache_entries{{{labels},middleware=\"micro\"}} 1")), "{text}");
	let (_, caps) = h.get("/capabilities").await;
	assert!(caps["features"]["middlewares"].as_array().unwrap().contains(&json!("cache")), "{caps}");
}

#[tokio::test]
async fn the_last_answer_while_the_backend_fails() {
	let h = harness().await;
	let b = backend().await;
	let port = rule(&h, &b, json!({"ttl": "200ms", "stale_on_error": "1s"})).await;
	assert_eq!(get(port, "/data", &[]).await.json::<Value>().await.unwrap()["n"], 1);
	b.status.store(503, Ordering::SeqCst);
	tokio::time::sleep(Duration::from_millis(250)).await;
	let r = get(port, "/data", &[]).await;
	assert_eq!((r.status(), x_cache(&r).as_str()), (StatusCode::OK, "STALE"));
	assert_eq!(r.json::<Value>().await.unwrap()["n"], 1);
	// a backend nobody listens on is a failure too
	let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
	let path = format!("tcp/127.0.0.1/{port}");
	let (status, v) = h
		.patch(
			&path,
			json!({"http": {
				"routes": [{"name": "api", "match": "PathPrefix(`/`)", "to": format!("http://{dead}"), "middlewares": ["micro"]}],
				"middlewares": {"micro": {"cache": {"ttl": "200ms", "stale_on_error": "1s"}}},
			}}),
		)
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	// a changed rule starts with nothing kept: the error goes through
	assert_eq!(get(port, "/data", &[]).await.status(), StatusCode::BAD_GATEWAY);
	// past stale_on_error the error goes through as well
	let port = rule(&h, &b, json!({"ttl": "100ms", "stale_on_error": "100ms"})).await;
	b.status.store(200, Ordering::SeqCst);
	assert_eq!(get(port, "/data", &[]).await.status(), StatusCode::OK);
	b.status.store(500, Ordering::SeqCst);
	tokio::time::sleep(Duration::from_millis(250)).await;
	let r = get(port, "/data", &[]).await;
	assert_eq!((r.status(), x_cache(&r).as_str()), (StatusCode::INTERNAL_SERVER_ERROR, "MISS"));
}

#[tokio::test]
async fn what_is_never_kept() {
	let h = harness().await;
	let b = backend().await;
	let port = rule(&h, &b, json!({"ttl": "10s", "max_body": 1024})).await;
	let b = &b;
	let twice = |path: &'static str, headers: &'static [(&'static str, &'static str)]| async move {
		let before = b.hits.load(Ordering::SeqCst);
		let first = get(port, path, headers).await;
		let x = x_cache(&first);
		first.bytes().await.unwrap();
		get(port, path, headers).await.bytes().await.unwrap();
		(b.hits.load(Ordering::SeqCst) - before, x)
	};
	assert_eq!(twice("/cookie", &[]).await, (2, "MISS".into()), "Set-Cookie");
	assert_eq!(twice("/private", &[]).await, (2, "MISS".into()), "Cache-Control: private");
	assert_eq!(twice("/big", &[]).await, (2, "MISS".into()), "over max_body");
	assert_eq!(twice("/data", &[("authorization", "Bearer t")]).await, (2, "BYPASS".into()), "Authorization");
	assert_eq!(twice("/data", &[("cookie", "s=1")]).await, (2, "BYPASS".into()), "Cookie");
	let before = b.hits.load(Ordering::SeqCst);
	for _ in 0..2 {
		client().post(format!("http://127.0.0.1:{port}/other")).send().await.unwrap();
	}
	assert_eq!(b.hits.load(Ordering::SeqCst) - before, 2, "POST");
	// the big body arrives whole
	let body = get(port, "/big", &[]).await.text().await.unwrap();
	assert_eq!(body.len(), 4096 + body.find('x').unwrap());
}

#[tokio::test]
async fn routes_keep_the_cache_away_from_authentication() {
	let h = harness().await;
	let b = backend().await;
	let post = |middlewares: Vec<&'static str>, defs: Value| {
		let h = &h;
		let to = format!("http://{}", b.addr);
		async move {
			h.post(json!({
				"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(),
				"http": {
					"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": to, "middlewares": middlewares}],
					"middlewares": defs,
				},
			}))
			.await
		}
	};
	let auth = json!({"forward_auth": {"address": "http://127.0.0.1:9/auth"}});
	let (status, v) =
		post(vec!["c", "lan"], json!({"c": {"cache": {"ttl": "1s"}}, "lan": {"ip_allow": {"source_range": ["127.0.0.0/8"]}}})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("before the cache"), "{v}");
	let (status, v) = post(vec!["a", "c"], json!({"c": {"cache": {"ttl": "1s"}}, "a": auth.clone()})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("share_after_auth"), "{v}");
	let (status, v) = post(vec!["a", "c"], json!({"c": {"cache": {"ttl": "1s", "share_after_auth": true}}, "a": auth})).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v) = post(vec!["c", "c2"], json!({"c": {"cache": {"ttl": "1s"}}, "c2": {"cache": {"ttl": "2s"}}})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	let (status, v) = post(vec!["c"], json!({"c": {"cache": {"ttl": "10ms"}}})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	// a server's forward_auth would be skipped too
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"services": {"s": {"servers": [{"url": format!("http://{}", b.addr), "middlewares": ["a"]}]}},
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "s", "middlewares": ["c"]}],
				"middlewares": {"c": {"cache": {"ttl": "1s"}}, "a": {"forward_auth": {"address": "http://127.0.0.1:9/auth"}}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("forward_auth"), "{v}");
}

/// One request over HTTP/2 with prior knowledge (h2c), with or without a body: status and X-Cache.
async fn h2_get(port: u16, path: &str, body: Option<&'static str>) -> (StatusCode, String) {
	use http_body_util::BodyExt;
	let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	type Boxed = http_body_util::combinators::BoxBody<bytes::Bytes, std::convert::Infallible>;
	let (mut sender, conn) =
		hyper::client::conn::http2::handshake::<_, _, Boxed>(hyper_util::rt::TokioExecutor::new(), hyper_util::rt::TokioIo::new(tcp))
			.await
			.unwrap();
	tokio::spawn(conn);
	// a body of unknown length: DATA frames without Content-Length
	let body: Boxed = match body {
		Some(b) => http_body_util::StreamBody::new(futures_util::stream::iter([Ok(hyper::body::Frame::data(bytes::Bytes::from_static(
			b.as_bytes(),
		)))]))
		.boxed(),
		None => http_body_util::Empty::new().boxed(),
	};
	let req = hyper::Request::get(format!("http://a.test{path}")).body(body).unwrap();
	let resp = sender.send_request(req).await.unwrap();
	let x = resp.headers().get("x-cache").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
	let status = StatusCode::from_u16(resp.status().as_u16()).unwrap();
	resp.into_body().collect().await.unwrap();
	(status, x)
}

#[tokio::test]
async fn a_get_with_a_body_over_http2_is_not_kept() {
	let h = harness().await;
	let b = backend().await;
	let port = rule(&h, &b, json!({"ttl": "10s"})).await;
	// DATA frames without Content-Length: BYPASS, every time to the backend
	assert_eq!(h2_get(port, "/x", Some("payload")).await, (StatusCode::OK, "BYPASS".into()));
	assert_eq!(h2_get(port, "/x", Some("payload")).await, (StatusCode::OK, "BYPASS".into()));
	assert_eq!(b.hits.load(Ordering::SeqCst), 2);
	// without a body: kept
	assert_eq!(h2_get(port, "/x", None).await, (StatusCode::OK, "MISS".into()));
	assert_eq!(h2_get(port, "/x", None).await, (StatusCode::OK, "HIT".into()));
	assert_eq!(b.hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn routes_keep_their_own_answers() {
	let h = harness().await;
	let (stable, beta) = (backend().await, backend().await);
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"routes": [
					{"name": "beta", "match": "Host(`a.test`) && Header(`X-Beta`, `1`)", "to": format!("http://{}", beta.addr), "middlewares": ["micro"]},
					{"name": "stable", "match": "Host(`a.test`)", "to": format!("http://{}", stable.addr), "middlewares": ["micro"]},
					{"name": "inside", "match": "Host(`in.test`)", "to": format!("http://{}", stable.addr), "middlewares": ["lan", "micro"]},
					{"name": "outside", "match": "Host(`out.test`)", "to": format!("http://{}", stable.addr), "middlewares": ["micro"]},
				],
				"middlewares": {"micro": {"cache": {"ttl": "10s"}}, "lan": {"ip_allow": {"source_range": ["127.0.0.0/8"]}}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let r = get(port, "/data", &[("host", "a.test"), ("x-beta", "1")]).await;
	assert_eq!(x_cache(&r), "MISS");
	// the stable route does not get the beta answer kept under the same middleware
	let r = get(port, "/data", &[("host", "a.test")]).await;
	assert_eq!(x_cache(&r), "MISS");
	assert_eq!((beta.hits.load(Ordering::SeqCst), stable.hits.load(Ordering::SeqCst)), (1, 1));
	assert_eq!(x_cache(&get(port, "/data", &[("host", "a.test"), ("x-beta", "1")]).await), "HIT");
	// an answer behind ip_allow stays on its route
	assert_eq!(x_cache(&get(port, "/data", &[("host", "in.test")]).await), "MISS");
	assert_eq!(x_cache(&get(port, "/data", &[("host", "out.test")]).await), "MISS");
}

#[tokio::test]
async fn cors_after_the_cache_keeps_origins_apart() {
	let h = harness().await;
	let b = backend().await;
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"routes": [{"name": "api", "match": "PathPrefix(`/`)", "to": format!("http://{}", b.addr), "middlewares": ["micro", "c"]}],
				"middlewares": {"micro": {"cache": {"ttl": "10s"}}, "c": {"cors": {"allow_origins": ["https://app.example"]}}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let r = get(port, "/data", &[("origin", "https://evil.example")]).await;
	assert!(!r.headers().contains_key("access-control-allow-origin"));
	let r = get(port, "/data", &[("origin", "https://app.example")]).await;
	assert_eq!((x_cache(&r).as_str(), r.headers()["access-control-allow-origin"].to_str().unwrap()), ("MISS", "https://app.example"));
	let r = get(port, "/data", &[("origin", "https://app.example")]).await;
	assert_eq!((x_cache(&r).as_str(), r.headers()["access-control-allow-origin"].to_str().unwrap()), ("HIT", "https://app.example"));
	let r = get(port, "/data", &[("origin", "https://evil.example")]).await;
	assert!(!r.headers().contains_key("access-control-allow-origin"), "{:?}", r.headers());
}

#[tokio::test]
async fn an_outage_does_not_hold_every_client() {
	let h = harness().await;
	let b = backend().await;
	let port = rule(&h, &b, json!({"ttl": "1s", "stale_on_error": "30s"})).await;
	assert_eq!(get(port, "/data", &[]).await.json::<Value>().await.unwrap()["n"], 1);
	tokio::time::sleep(Duration::from_millis(1050)).await;
	b.status.store(503, Ordering::SeqCst);
	b.delay_ms.store(300, Ordering::SeqCst);
	let r = get(port, "/data", &[]).await;
	assert_eq!(x_cache(&r), "STALE");
	// within ttl after the failure: the old answer at once, the backend is left alone
	for _ in 0..5 {
		let r = get(port, "/data", &[]).await;
		assert_eq!(x_cache(&r), "STALE");
		assert_eq!(r.json::<Value>().await.unwrap()["n"], 1);
	}
	assert_eq!(b.hits.load(Ordering::SeqCst), 2);
}

/// One HTTPS/1.1 request to `a.test` with an optional client certificate: X-Cache and the backend's count.
async fn tls_get(pki: &Pki, port: u16, client: Option<&Issued>, path: &str) -> (String, Value) {
	use http_body_util::BodyExt;
	let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let name = rustls::pki_types::ServerName::try_from("a.test").unwrap();
	let tls = pki.connector_alpn(client, &["http/1.1"]).connect(name, tcp).await.unwrap();
	let (mut sender, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
	tokio::spawn(conn);
	let req = hyper::Request::get(path).header("host", "a.test").body(http_body_util::Empty::<bytes::Bytes>::new()).unwrap();
	let resp = sender.send_request(req).await.unwrap();
	let x = resp.headers().get("x-cache").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
	let body = resp.into_body().collect().await.unwrap().to_bytes();
	(x, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn client_certificates_are_credentials() {
	let h = harness().await;
	let b = backend().await;
	let pki = Pki::new("cache-mtls");
	let server = pki.server("a", &["a.test"]);
	let (alice, bob) = (pki.client("alice", "alice"), pki.client("bob", "bob"));
	let port = free_port();
	let to = format!("http://{}", b.addr);
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"tls": {"mode": "terminate", "certificates": [{"cert_file": server.cert_file, "key_file": server.key_file}],
				"client_auth": {"mode": "optional", "ca_file": pki.ca_file}},
			"http": {
				"routes": [
					{"name": "strict", "match": "PathPrefix(`/strict`)", "to": to, "middlewares": ["strict"]},
					{"name": "shared", "match": "PathPrefix(`/`)", "to": to, "middlewares": ["shared"]},
				],
				"middlewares": {"strict": {"cache": {"ttl": "10s"}}, "shared": {"cache": {"ttl": "10s", "share_credentials": true}}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(tls_get(&pki, port, Some(&alice), "/strict").await.0, "BYPASS");
	assert_eq!(tls_get(&pki, port, Some(&alice), "/strict").await.0, "BYPASS");
	assert_eq!(tls_get(&pki, port, None, "/strict").await.0, "MISS");
	// shared, but one answer per certificate (and one for none)
	let (x, first) = tls_get(&pki, port, Some(&alice), "/data").await;
	assert_eq!(x, "MISS");
	assert_eq!(tls_get(&pki, port, Some(&alice), "/data").await, ("HIT".into(), first));
	assert_eq!(tls_get(&pki, port, Some(&bob), "/data").await.0, "MISS");
	assert_eq!(tls_get(&pki, port, None, "/data").await.0, "MISS");
	assert_eq!(tls_get(&pki, port, None, "/data").await.0, "HIT");
}
