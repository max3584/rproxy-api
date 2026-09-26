//! `http` rules: health checks, sticky sessions, compression, buffering,
//! retry, circuit breaker, error pages and kept backend connections (#61, #63,
//! #64, #65) through real sockets.

mod common;

use std::collections::HashSet;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode as AxStatus};
use axum::response::IntoResponse;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use common::*;

/// A backend whose health answer, hits and client connections the test can see.
struct Backend {
	tag: &'static str,
	health: AtomicU16,
	hits: AtomicU64,
	peers: Mutex<HashSet<SocketAddr>>,
	addr: SocketAddr,
}

async fn backend(tag: &'static str) -> Arc<Backend> {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let b = Arc::new(Backend { tag, health: AtomicU16::new(200), hits: AtomicU64::new(0), peers: Mutex::default(), addr: listener.local_addr().unwrap() });
	let state = b.clone();
	let app = axum::Router::new()
		.route("/health", axum::routing::get(|State(b): State<Arc<Backend>>| async move { AxStatus::from_u16(b.health.load(Ordering::Relaxed)).unwrap() }))
		.route("/big", axum::routing::get(|| async { ([("content-type", "text/html")], "<p>big page</p>\n".repeat(400)) }))
		.route("/small", axum::routing::get(|| async { ([("content-type", "text/html")], "tiny") }))
		.route("/png", axum::routing::get(|| async { ([("content-type", "image/png")], vec![7u8; 5000]) }))
		.route("/fail", axum::routing::any(|State(b): State<Arc<Backend>>| async move {
			b.hits.fetch_add(1, Ordering::Relaxed);
			(AxStatus::INTERNAL_SERVER_ERROR, "backend broke")
		}))
		.route("/page/{status}", axum::routing::get(|Path(status): Path<String>| async move { ([("content-type", "text/html")], format!("<h1>page {status}</h1>")) }))
		.fallback(|State(b): State<Arc<Backend>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, headers: HeaderMap, body: axum::body::Bytes| async move {
			b.hits.fetch_add(1, Ordering::Relaxed);
			b.peers.lock().unwrap().insert(peer);
			let cookie = headers.get("cookie").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
			axum::Json(json!({"tag": b.tag, "body": body.len(), "cookie": cookie})).into_response()
		})
		.with_state(state);
	tokio::spawn(async move { axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap() });
	b
}

fn url(b: &Backend) -> String {
	format!("http://{}", b.addr)
}

fn http_rule(port: u16, http: Value) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})
}

/// An address nothing listens on.
fn dead() -> String {
	let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	format!("http://{}", l.local_addr().unwrap())
}

fn client() -> reqwest::Client {
	reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap()
}

async fn get(port: u16, path: &str) -> (StatusCode, String) {
	let r = client().get(format!("http://127.0.0.1:{port}{path}")).send().await.unwrap();
	(r.status(), r.text().await.unwrap())
}

async fn tag(port: u16, path: &str) -> String {
	let (status, text) = get(port, path).await;
	assert_eq!(status, StatusCode::OK, "{text}");
	serde_json::from_str::<Value>(&text).unwrap()["tag"].as_str().unwrap().to_string()
}

async fn rule_view(h: &Harness, port: u16) -> Value {
	h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await.1
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
	F: FnMut() -> Fut,
	Fut: std::future::Future<Output = bool>,
{
	let deadline = Instant::now() + Duration::from_secs(10);
	while !check().await {
		assert!(Instant::now() < deadline, "timed out waiting for {what}");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}

#[tokio::test]
async fn health_checks_take_servers_out_and_back() {
	let h = harness().await;
	let (a, b) = (backend("A").await, backend("B").await);
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [{"name": "app", "match": "PathPrefix(`/`)", "service": "app"}],
				"services": {"app": {"servers": [{"url": url(&a)}, {"url": url(&b)}],
					"health_check": {"path": "/health", "interval": "100ms", "timeout": "500ms"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let tags: HashSet<String> = futures_util::future::join_all((0..4).map(|_| tag(port, "/x"))).await.into_iter().collect();
	assert_eq!(tags.len(), 2, "both serve while up");

	b.health.store(503, Ordering::Relaxed);
	eventually("B marked down", || async { rule_view(&h, port).await["stats"]["http"]["services"]["app"][1]["up"] == false }).await;
	for _ in 0..4 {
		assert_eq!(tag(port, "/x").await, "A");
	}
	let metrics = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	assert!(metrics.contains(&format!("rproxy_http_server_up{{protocol=\"tcp\",listen=\"127.0.0.1:{port}\",service=\"app\",server=\"{}\"}} 0", url(&b))), "{metrics}");

	a.health.store(500, Ordering::Relaxed);
	eventually("A marked down", || async { rule_view(&h, port).await["stats"]["http"]["services"]["app"][0]["up"] == false }).await;
	assert_eq!(get(port, "/x").await.0, StatusCode::SERVICE_UNAVAILABLE, "no server is up");

	b.health.store(200, Ordering::Relaxed);
	eventually("B back", || async { rule_view(&h, port).await["stats"]["http"]["services"]["app"][1]["up"] == true }).await;
	assert_eq!(tag(port, "/x").await, "B");
}

#[tokio::test]
async fn sticky_cookie_keeps_a_client_on_one_server() {
	let h = harness().await;
	let (a, b) = (backend("A").await, backend("B").await);
	let port = free_port();
	h.post(http_rule(
		port,
		json!({
			"routes": [{"name": "app", "match": "PathPrefix(`/`)", "service": "app"}],
			"services": {"app": {"servers": [{"url": url(&a)}, {"url": url(&b)}], "sticky": {"cookie": "lb"}}},
		}),
	))
	.await;
	let r = client().get(format!("http://127.0.0.1:{port}/")).send().await.unwrap();
	let set = r.headers()["set-cookie"].to_str().unwrap().to_string();
	assert!(set.starts_with("lb=") && set.contains("HttpOnly"), "{set}");
	let first: Value = r.json().await.unwrap();
	let cookie = set.split(';').next().unwrap().to_string();
	for _ in 0..5 {
		let r = client().get(format!("http://127.0.0.1:{port}/")).header("cookie", &cookie).send().await.unwrap();
		assert!(!r.headers().contains_key("set-cookie"), "already pinned");
		let v: Value = r.json().await.unwrap();
		assert_eq!(v["tag"], first["tag"]);
		assert_eq!(v["cookie"], cookie.as_str(), "the cookie still reaches the backend");
	}
	// an unknown value is re-pinned
	let r = client().get(format!("http://127.0.0.1:{port}/")).header("cookie", "lb=nope").send().await.unwrap();
	assert!(r.headers().contains_key("set-cookie"));
}

fn decode(encoding: &str, body: &[u8]) -> String {
	let mut out = String::new();
	match encoding {
		"gzip" => flate2::read::GzDecoder::new(body).read_to_string(&mut out).unwrap(),
		"br" => brotli::Decompressor::new(body, 4096).read_to_string(&mut out).unwrap(),
		"zstd" => zstd::stream::read::Decoder::new(body).unwrap().read_to_string(&mut out).unwrap(),
		other => panic!("{other}"),
	};
	out
}

#[tokio::test]
async fn compresses_what_the_client_accepts() {
	let h = harness().await;
	let a = backend("A").await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [{"name": "app", "match": "PathPrefix(`/`)", "to": url(&a), "middlewares": ["gz"]}],
				"middlewares": {"gz": {"compress": {}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let plain = "<p>big page</p>\n".repeat(400);
	for (accept, want) in [("gzip", "gzip"), ("gzip, deflate, br, zstd", "br"), ("zstd;q=1, br;q=0.2", "zstd")] {
		let r = client().get(format!("http://127.0.0.1:{port}/big")).header("accept-encoding", accept).send().await.unwrap();
		assert_eq!(r.headers()["content-encoding"], want, "{accept}");
		assert!(r.headers()["vary"].to_str().unwrap().contains("Accept-Encoding"));
		assert!(!r.headers().contains_key("content-length") || r.headers()["content-length"] != plain.len().to_string().as_str());
		let body = r.bytes().await.unwrap();
		assert!(body.len() < plain.len() / 4, "{want}: {}", body.len());
		assert_eq!(decode(want, &body), plain, "{want}");
	}
	for (path, accept) in [("/big", ""), ("/small", "gzip"), ("/png", "gzip")] {
		let mut req = client().get(format!("http://127.0.0.1:{port}{path}"));
		if !accept.is_empty() {
			req = req.header("accept-encoding", accept);
		}
		let r = req.send().await.unwrap();
		assert!(!r.headers().contains_key("content-encoding"), "{path} {accept:?}");
	}
}

#[tokio::test]
async fn buffering_limits_request_bodies() {
	let h = harness().await;
	let a = backend("A").await;
	let port = free_port();
	h.post(http_rule(
		port,
		json!({
			"routes": [{"name": "app", "match": "PathPrefix(`/`)", "to": url(&a), "middlewares": ["buf"]}],
			"middlewares": {"buf": {"buffering": {"max_request_body": 100}}},
		}),
	))
	.await;
	let post = |body: Vec<u8>| client().post(format!("http://127.0.0.1:{port}/upload")).body(body).send();
	let r = post(vec![b'x'; 50]).await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(r.json::<Value>().await.unwrap()["body"], 50);
	assert_eq!(post(vec![b'x'; 1000]).await.unwrap().status(), StatusCode::PAYLOAD_TOO_LARGE);
	// without Content-Length (chunked), the limit holds too
	let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"POST /upload HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
	for _ in 0..20 {
		s.write_all(b"a\r\nyyyyyyyyyy\r\n").await.unwrap();
	}
	s.write_all(b"0\r\n\r\n").await.unwrap();
	let mut head = [0u8; 12];
	s.read_exact(&mut head).await.unwrap();
	assert_eq!(&head, b"HTTP/1.1 413");
	assert_eq!(a.hits.load(Ordering::Relaxed), 1, "refused bodies never reach the backend");
}

#[tokio::test]
async fn retry_moves_to_another_server() {
	let h = harness().await;
	let a = backend("A").await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [
					{"name": "retry", "match": "PathPrefix(`/r`)", "service": "app", "middlewares": ["again"]},
					{"name": "plain", "match": "PathPrefix(`/p`)", "service": "app2"},
				],
				"services": {
					"app": {"servers": [{"url": dead()}, {"url": url(&a)}]},
					"app2": {"servers": [{"url": dead()}, {"url": url(&a)}]},
				},
				"middlewares": {"again": {"retry": {"attempts": 3, "initial_interval": "10ms"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	for _ in 0..4 {
		assert_eq!(tag(port, "/r").await, "A", "the dead server is skipped by retrying");
	}
	// without retry, every other request hits the dead server
	let statuses: Vec<StatusCode> = futures_util::future::join_all((0..4).map(|_| async { get(port, "/p").await.0 })).await;
	assert_eq!(statuses.iter().filter(|s| **s == StatusCode::BAD_GATEWAY).count(), 2, "{statuses:?}");
	// a POST with a body is not sent twice (no buffering): the dead pick fails
	let mut codes = vec![];
	for _ in 0..2 {
		codes.push(client().post(format!("http://127.0.0.1:{port}/r")).body("x").send().await.unwrap().status());
	}
	assert!(codes.contains(&StatusCode::BAD_GATEWAY), "{codes:?}");
}

#[tokio::test]
async fn circuit_breaker_opens_and_recovers() {
	let h = harness().await;
	let a = backend("A").await;
	let port = free_port();
	h.post(http_rule(
		port,
		json!({
			"routes": [{"name": "app", "match": "PathPrefix(`/`)", "to": url(&a), "middlewares": ["cb"]}],
			"middlewares": {"cb": {"circuit_breaker": {"failure_percent": 50, "window": "10s", "recovery": "500ms"}}},
		}),
	))
	.await;
	for _ in 0..10 {
		assert_eq!(get(port, "/fail").await.0, StatusCode::INTERNAL_SERVER_ERROR);
	}
	let hits = a.hits.load(Ordering::Relaxed);
	assert_eq!(get(port, "/ok").await.0, StatusCode::SERVICE_UNAVAILABLE, "open");
	assert_eq!(a.hits.load(Ordering::Relaxed), hits, "the backend is spared while open");
	tokio::time::sleep(Duration::from_millis(600)).await;
	assert_eq!(tag(port, "/ok").await, "A", "one probe after recovery");
	assert_eq!(tag(port, "/ok").await, "A", "closed again");
}

#[tokio::test]
async fn error_pages_replace_failed_responses() {
	let h = harness().await;
	let (a, pages) = (backend("A").await, backend("P").await);
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [{"name": "app", "match": "PathPrefix(`/`)", "to": url(&a), "middlewares": ["oops"]}],
				"services": {"pages": {"servers": [{"url": url(&pages)}]}},
				"middlewares": {"oops": {"errors": {"status": ["500-599"], "service": "pages", "path": "/page/{status}"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let r = client().get(format!("http://127.0.0.1:{port}/fail")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::INTERNAL_SERVER_ERROR, "the status stays");
	assert_eq!(r.headers()["content-type"], "text/html", "the page's own headers");
	assert_eq!(r.text().await.unwrap(), "<h1>page 500</h1>");
	assert_eq!(tag(port, "/fine").await, "A", "other responses are untouched");
}

#[tokio::test]
async fn backend_connections_are_kept_between_requests() {
	let h = harness().await;
	let a = backend("A").await;
	let port = free_port();
	h.post(http_rule(port, json!({"routes": [{"name": "app", "match": "PathPrefix(`/`)", "to": url(&a)}]}))).await;
	for _ in 0..5 {
		// a new client connection each time; rproxy's connection to the backend is reused
		let c = reqwest::Client::builder().pool_max_idle_per_host(0).build().unwrap();
		let v: Value = c.get(format!("http://127.0.0.1:{port}/")).send().await.unwrap().json().await.unwrap();
		assert_eq!(v["tag"], "A");
	}
	assert_eq!(a.peers.lock().unwrap().len(), 1, "one backend connection for five requests");
}
