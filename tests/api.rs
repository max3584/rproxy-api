//! End-to-end tests: a real control API on loopback, real listeners, echo backends.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use rproxy_api::api::{router, AppState};
use rproxy_api::auth::Tokens;
use rproxy_api::registry::{Config, Registry};
use rproxy_api::resolve::Lookup;

type Names = Arc<Mutex<HashMap<String, SocketAddr>>>;

struct Harness {
	base: String,
	http: reqwest::Client,
	registry: Arc<Registry>,
	names: Names,
}

/// Resolves IP literals directly and other hosts from `names`; unknown names fail like a DNS outage.
fn fake_lookup(names: Names) -> Lookup {
	Arc::new(move |target: String| {
		let names = names.clone();
		Box::pin(async move {
			if let Ok(addr) = target.parse::<SocketAddr>() {
				return Ok(vec![addr]);
			}
			let host = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(&target);
			names
				.lock()
				.unwrap()
				.get(host)
				.map(|a| vec![*a])
				.ok_or_else(|| io::Error::other("no such host"))
		})
	})
}

async fn harness_with(tokens: Tokens) -> Harness {
	let names: Names = Arc::default();
	let registry = Registry::new(Config {
		dns_interval: Duration::from_millis(100),
		lookup: fake_lookup(names.clone()),
		transparent: false,
	});
	let app = router(Arc::new(AppState { registry: registry.clone(), tokens: Arc::new(tokens) }));
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	Harness { base, http: reqwest::Client::new(), registry, names }
}

async fn harness() -> Harness {
	harness_with(Tokens::disabled()).await
}

fn free_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn free_udp_port() -> u16 {
	std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// TCP backend that answers every read with `tag` + the bytes read.
async fn tcp_backend(tag: &'static str) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let mut buf = [0u8; 1024];
				while let Ok(n) = s.read(&mut buf).await {
					if n == 0 {
						break;
					}
					let mut out = tag.as_bytes().to_vec();
					out.extend_from_slice(&buf[..n]);
					if s.write_all(&out).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

/// UDP backend that answers every datagram with `tag` + the datagram.
async fn udp_backend(tag: &'static str) -> SocketAddr {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr = sock.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = [0u8; 1024];
		loop {
			let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
			let mut out = tag.as_bytes().to_vec();
			out.extend_from_slice(&buf[..n]);
			let _ = sock.send_to(&out, peer).await;
		}
	});
	addr
}

fn rule(protocol: &str, port: u16, target: SocketAddr) -> Value {
	json!({
		"protocol": protocol,
		"listen_addr": "127.0.0.1",
		"listen_port": port,
		"remote_addr": target.ip().to_string(),
		"remote_port": target.port(),
	})
}

impl Harness {
	async fn post(&self, body: Value) -> (StatusCode, Value) {
		let r = self.http.post(format!("{}/rules", self.base)).json(&body).send().await.unwrap();
		let status = r.status();
		(status, r.json().await.unwrap_or(Value::Null))
	}

	async fn patch(&self, path: &str, body: Value) -> (StatusCode, Value) {
		let r = self.http.patch(format!("{}/rules/{path}", self.base)).json(&body).send().await.unwrap();
		let status = r.status();
		(status, r.json().await.unwrap_or(Value::Null))
	}

	async fn delete(&self, path: &str) -> StatusCode {
		self.http.delete(format!("{}/rules/{path}", self.base)).send().await.unwrap().status()
	}

	async fn get(&self, path: &str) -> (StatusCode, Value) {
		let r = self.http.get(format!("{}{path}", self.base)).send().await.unwrap();
		let status = r.status();
		(status, r.json().await.unwrap_or(Value::Null))
	}
}

async fn roundtrip(stream: &mut TcpStream, msg: &str) -> String {
	stream.write_all(msg.as_bytes()).await.unwrap();
	let mut buf = [0u8; 1024];
	let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await.unwrap().unwrap();
	String::from_utf8_lossy(&buf[..n]).into_owned()
}

async fn udp_roundtrip(sock: &UdpSocket, msg: &str) -> String {
	sock.send(msg.as_bytes()).await.unwrap();
	let mut buf = [0u8; 1024];
	let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await.unwrap().unwrap();
	String::from_utf8_lossy(&buf[..n]).into_owned()
}

async fn wait_for<F: Fn(&Value) -> bool>(h: &Harness, path: &str, cond: F) -> Value {
	let deadline = Instant::now() + Duration::from_secs(3);
	loop {
		let (_, v) = h.get(path).await;
		if cond(&v) {
			return v;
		}
		assert!(Instant::now() < deadline, "condition not met, last: {v}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

#[tokio::test]
async fn tcp_lifecycle_stops_immediately_and_port_is_reusable() {
	let h = harness().await;
	let backend = tcp_backend("A:").await;
	let port = free_port();

	let (status, view) = h.post(rule("TCP", port, backend)).await;
	assert_eq!(status, StatusCode::CREATED, "{view}");
	assert_eq!(view["protocol"], "tcp");
	assert_eq!(view["state"], "running");
	assert_eq!(view["udp_idle_secs"], 30);

	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut conn, "hi").await, "A:hi");
	wait_for(&h, &format!("/rules/tcp/127.0.0.1/{port}"), |v| v["connections"] == 1).await;

	let started = Instant::now();
	assert_eq!(h.delete(&format!("tcp/127.0.0.1/{port}")).await, StatusCode::NO_CONTENT);
	assert!(started.elapsed() < Duration::from_secs(1), "STOP took {:?}", started.elapsed());

	// the established connection is closed too
	let mut buf = [0u8; 16];
	let n = tokio::time::timeout(Duration::from_secs(1), conn.read(&mut buf)).await.unwrap().unwrap_or(0);
	assert_eq!(n, 0);
	assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());

	let (status, _) = h.post(rule("tcp", port, backend)).await;
	assert_eq!(status, StatusCode::CREATED);
}

#[tokio::test]
async fn update_retargets_new_tcp_connections_at_once() {
	let h = harness().await;
	let (a, b) = (tcp_backend("A:").await, tcp_backend("B:").await);
	let port = free_port();
	h.post(rule("tcp", port, a)).await;

	let mut old = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut old, "1").await, "A:1");

	let (status, view) = h
		.patch(&format!("tcp/127.0.0.1/{port}"), json!({"remote_addr": "127.0.0.1", "remote_port": b.port()}))
		.await;
	assert_eq!(status, StatusCode::OK, "{view}");
	assert_eq!(view["resolved"][0], b.to_string());

	let mut new = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut new, "2").await, "B:2");
	assert_eq!(roundtrip(&mut old, "3").await, "A:3", "existing connections keep their backend");
}

#[tokio::test]
async fn errors_use_the_api_format() {
	let h = harness().await;
	let backend = tcp_backend("A:").await;
	let port = free_port();
	h.post(rule("tcp", port, backend)).await;

	let (status, v) = h.post(rule("tcp", port, backend)).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")));

	let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let busy = held.local_addr().unwrap().port();
	let (status, v) = h.post(rule("tcp", busy, backend)).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("bind_failed")));
	let (_, rules) = h.get("/rules").await;
	assert_eq!(rules.as_array().unwrap().len(), 1, "a failed create leaves nothing behind");

	let (status, v) = h.post(json!({"protocol": "tcp"})).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")));

	let mut udp_v2 = rule("udp", free_udp_port(), backend);
	udp_v2["source_ip"] = json!("proxy_v2");
	let (status, v) = h.post(udp_v2).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("unsupported")));

	let mut unresolvable = rule("tcp", free_port(), backend);
	unresolvable["remote_addr"] = json!("nowhere.invalid");
	let (status, v) = h.post(unresolvable).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("resolve_failed")));

	assert_eq!(h.delete("tcp/127.0.0.1/1").await, StatusCode::NOT_FOUND);
	let (status, v) = h.get("/nope").await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));
}

#[tokio::test]
async fn bearer_token_is_required_when_configured() {
	let dir = std::env::temp_dir().join(format!("rproxy-it-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let file = dir.join("tokens");
	std::fs::write(&file, "secret\n").unwrap();
	let h = harness_with(Tokens::from_file(file).unwrap()).await;

	let (status, v) = h.get("/rules").await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("unauthorized")));
	let r = h.http.get(format!("{}/rules", h.base)).bearer_auth("secret").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let r = h.http.get(format!("{}/healthz", h.base)).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn udp_sessions_follow_updates_and_port_is_reusable() {
	let h = harness().await;
	let (a, b) = (udp_backend("A:").await, udp_backend("B:").await);
	let port = free_udp_port();

	let (status, v) = h.post(rule("udp", port, a)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	client.connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(udp_roundtrip(&client, "1").await, "A:1");

	h.patch(&format!("udp/127.0.0.1/{port}"), json!({"remote_addr": "127.0.0.1", "remote_port": b.port()})).await;
	// the live session switches too; give the session task a moment to see the change
	tokio::time::sleep(Duration::from_millis(50)).await;
	assert_eq!(udp_roundtrip(&client, "2").await, "B:2");

	let started = Instant::now();
	assert_eq!(h.delete(&format!("udp/127.0.0.1/{port}")).await, StatusCode::NO_CONTENT);
	assert!(started.elapsed() < Duration::from_secs(1));

	// the socket is released, so the same port can be opened again right away
	let (status, v) = h.post(rule("udp", port, a)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(udp_roundtrip(&client, "3").await, "A:3");
}

#[tokio::test]
async fn udp_sessions_expire_after_idle_timeout() {
	let h = harness().await;
	let backend = udp_backend("A:").await;
	let port = free_udp_port();
	let mut body = rule("udp", port, backend);
	body["udp_idle_secs"] = json!(1);
	h.post(body).await;

	let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	client.connect(("127.0.0.1", port)).await.unwrap();
	udp_roundtrip(&client, "x").await;
	let path = format!("/rules/udp/127.0.0.1/{port}");
	wait_for(&h, &path, |v| v["connections"] == 1).await;
	wait_for(&h, &path, |v| v["connections"] == 0).await;
}

#[tokio::test]
async fn proxy_protocol_v2_header_carries_the_client() {
	let h = harness().await;
	let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	let port = free_port();
	let mut body = rule("tcp", port, target);
	body["source_ip"] = json!("proxy_v2");
	h.post(body).await;

	let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let client_port = client.local_addr().unwrap().port();
	client.write_all(b"payload").await.unwrap();

	let (mut upstream, _) = backend.accept().await.unwrap();
	let mut header = [0u8; 28];
	upstream.read_exact(&mut header).await.unwrap();
	assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
	assert_eq!(&header[12..16], &[0x21, 0x11, 0, 12]);
	assert_eq!(&header[16..20], &[127, 0, 0, 1]);
	assert_eq!(u16::from_be_bytes([header[24], header[25]]), client_port);
	assert_eq!(u16::from_be_bytes([header[26], header[27]]), port);
	let mut payload = [0u8; 7];
	upstream.read_exact(&mut payload).await.unwrap();
	assert_eq!(&payload, b"payload");
}

#[tokio::test]
async fn drain_waits_for_connections_to_finish() {
	let h = harness().await;
	let backend = tcp_backend("A:").await;
	let port = free_port();
	h.post(rule("tcp", port, backend)).await;
	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	roundtrip(&mut conn, "x").await;

	let path = format!("tcp/127.0.0.1/{port}?drain_secs=5");
	let delete = tokio::spawn({
		let url = format!("{}/rules/{path}", h.base);
		let http = h.http.clone();
		async move { http.delete(url).send().await.unwrap().status() }
	});
	tokio::time::sleep(Duration::from_millis(200)).await;
	assert!(!delete.is_finished(), "delete should wait while the connection is open");
	assert_eq!(roundtrip(&mut conn, "y").await, "A:y", "draining connections keep working");
	drop(conn);
	let status = tokio::time::timeout(Duration::from_secs(2), delete).await.unwrap().unwrap();
	assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn restore_retries_rules_whose_target_does_not_resolve_yet() {
	let h = harness().await;
	let backend = tcp_backend("A:").await;
	let port = free_port();
	let rules = serde_json::from_value(json!([{
		"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
		"remote_addr": "backend.test", "remote_port": backend.port(),
	}]))
	.unwrap();
	h.registry.restore(rules).await;

	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let (_, v) = h.get(&path).await;
	assert_eq!(v["state"], "failed");
	assert!(v["error"].as_str().unwrap().contains("backend.test"));

	h.names.lock().unwrap().insert("backend.test".into(), backend);
	wait_for(&h, &path, |v| v["state"] == "running").await;
	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut conn, "ok").await, "A:ok");
}

#[tokio::test]
async fn dns_outage_keeps_forwarding_to_cached_address() {
	let h = harness().await;
	let backend = tcp_backend("A:").await;
	h.names.lock().unwrap().insert("svc.test".into(), backend);
	let port = free_port();
	let mut body = rule("tcp", port, backend);
	body["remote_addr"] = json!("svc.test");
	let (status, _) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED);

	h.names.lock().unwrap().clear();
	tokio::time::sleep(Duration::from_millis(300)).await; // several failed refreshes
	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut conn, "still").await, "A:still");
}

#[tokio::test]
async fn metrics_and_capabilities() {
	let h = harness().await;
	let backend = tcp_backend("A:").await;
	let port = free_port();
	h.post(rule("tcp", port, backend)).await;
	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	roundtrip(&mut conn, "abc").await;
	drop(conn);
	wait_for(&h, &format!("/rules/tcp/127.0.0.1/{port}"), |v| v["connections"] == 0).await;

	let text = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	let labels = format!("protocol=\"tcp\",listen=\"127.0.0.1:{port}\"");
	assert!(text.contains(&format!("rproxy_rule_up{{{labels}}} 1")), "{text}");
	assert!(text.contains(&format!("rproxy_connections_total{{{labels}}} 1")), "{text}");
	assert!(text.contains(&format!("rproxy_bytes_total{{{labels},direction=\"rx\"}} 3")), "{text}");

	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["transparent"], false);
	assert_eq!(caps["source_ip"], json!(["proxy", "proxy_v1", "proxy_v2"]));
}
