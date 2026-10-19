//! `proxy_protocol` of a rule (#296): PROXY v1 / v2 headers read from trusted front
//! ends, and the client they name used everywhere the source counts. Every
//! connection here comes from 127.0.0.1, so `from: ["127.0.0.1/32"]` makes the test
//! the front end, and another range makes it an untrusted peer.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::*;
use rproxy_api::net::source::{proxy_v1_header, proxy_v2_header};

const CLIENT: &str = "192.0.2.7:4000";

fn client() -> SocketAddr {
	CLIENT.parse().unwrap()
}

fn with_pp(mut body: Value, pp: Value) -> Value {
	body["proxy_protocol"] = pp;
	body
}

fn trusted() -> Value {
	json!({"from": ["127.0.0.1/32"]})
}

/// Connects, sends `first` (a header, or not) and `msg`, and returns the answer, or
/// None when rproxy closes the connection.
async fn exchange(port: u16, first: &[u8], msg: &[u8]) -> Option<(TcpStream, String)> {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(first).await.ok()?;
	s.write_all(msg).await.ok()?;
	let mut buf = [0u8; 1024];
	match tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await {
		Ok(Ok(n)) if n > 0 => Some((s, String::from_utf8_lossy(&buf[..n]).into_owned())),
		_ => None,
	}
}

fn local(port: u16) -> SocketAddr {
	SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn the_shape_validation_and_capabilities() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["proxy_protocol_in"], true, "{caps}");
	let backend = tcp_backend("B:").await;
	let port = free_port();
	let (status, v) = h.post(with_pp(rule("tcp", port, backend), json!({"from": ["10.2.0.0/16", "172.16.10.19"]}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["proxy_protocol"], json!({"from": ["10.2.0.0/16", "172.16.10.19/32"], "required": true}), "{v}");
	// PATCH replaces it, `{}` removes it
	let path = format!("tcp/127.0.0.1/{port}");
	let target = json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()});
	let (status, v) = h.patch(&path, with_pp(target.clone(), json!({"from": ["127.0.0.1"], "required": false}))).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(v["proxy_protocol"], json!({"from": ["127.0.0.1/32"], "required": false}), "{v}");
	let (_, v) = h.patch(&path, target.clone()).await;
	assert_eq!(v["proxy_protocol"]["required"], false, "left out: kept");
	let (_, v) = h.patch(&path, with_pp(target.clone(), json!({}))).await;
	assert!(v.get("proxy_protocol").is_none(), "{v}");
	for (pp, code) in [
		(json!({"from": []}), "invalid"),
		(json!({"required": true}), "invalid"),
		(json!({"from": ["0.0.0.0/0"]}), "invalid"),
		(json!({"from": ["not-an-address"]}), "invalid"),
	] {
		let (status, v) = h.post(with_pp(rule("tcp", free_port(), backend), pp.clone())).await;
		assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{pp}: {v}");
		let (status, v) = h.patch(&path, with_pp(target.clone(), pp.clone())).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "PATCH {pp}: {v}");
	}
	let (status, v) = h.post(with_pp(rule("udp", free_udp_port(), backend), trusted())).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("unsupported")), "{v}");
}

/// The header's client is who `allow_from` judges; v1 and v2 both.
#[tokio::test]
async fn allow_from_judges_the_client_in_the_header() {
	let h = harness().await;
	let port = free_port();
	let mut body = with_pp(rule("tcp", port, tcp_backend("B:").await), trusted());
	body["allow_from"] = json!(["192.0.2.0/24"]);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let to = local(port);
	let (_s, got) = exchange(port, &proxy_v2_header(client(), to), b"hi").await.expect("v2: allowed");
	assert_eq!(got, "B:hi", "the header is not passed on");
	let (_s, got) = exchange(port, &proxy_v1_header(client(), to), b"hi").await.expect("v1: allowed");
	assert_eq!(got, "B:hi");
	let other: SocketAddr = "198.51.100.1:4000".parse().unwrap();
	assert!(exchange(port, &proxy_v2_header(other, to), b"hi").await.is_none(), "198.51.100.1 is outside allow_from");
	// without a header, the peer (127.0.0.1) would be judged: refused (required anyway)
	assert!(exchange(port, b"", b"hi").await.is_none());
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!(v["stats"]["denied"], 2, "{v}");
}

#[tokio::test]
async fn required_refuses_a_connection_without_a_header() {
	let h = harness().await;
	let backend = tcp_backend("B:").await;
	let (port, lax) = (free_port(), free_port());
	h.post(with_pp(rule("tcp", port, backend), trusted())).await;
	h.post(with_pp(rule("tcp", lax, backend), json!({"from": ["127.0.0.1/32"], "required": false}))).await;
	assert!(exchange(port, b"", b"hi").await.is_none(), "required (the default)");
	assert!(exchange(port, b"PROXY TCP4 192.0.2.7\r\n", b"hi").await.is_none(), "a broken header");
	let (_s, got) = exchange(lax, b"", b"hi").await.expect("not required: the peer's address");
	assert_eq!(got, "B:hi");
	assert!(exchange(lax, b"PROXY TCP4 192.0.2.7\r\n", b"hi").await.is_none(), "a broken header is refused all the same");
	let (_s, got) = exchange(lax, &proxy_v2_header(client(), local(lax)), b"hi").await.expect("with one");
	assert_eq!(got, "B:hi");
}

/// A peer outside `from` that sends a header is refused; without one it is served as before.
#[tokio::test]
async fn a_header_from_outside_from_is_refused() {
	logs::capture();
	let h = harness().await;
	let backend = tcp_backend("B:").await;
	let (plain, tls_port) = (free_port(), free_port());
	h.post(with_pp(rule("tcp", plain, backend), json!({"from": ["10.0.0.0/8"]}))).await;
	let (_s, got) = exchange(plain, b"", b"hello").await.expect("no header: an ordinary connection");
	assert_eq!(got, "B:hello");
	assert!(exchange(plain, &proxy_v1_header(client(), local(plain)), b"hi").await.is_none(), "v1 from outside from");
	assert!(exchange(plain, &proxy_v2_header(client(), local(plain)), b"hi").await.is_none(), "v2 from outside from");
	let line = logs::wait_for("proxy_protocol_untrusted", |l| {
		l["event"] == "conn.denied" && l["reason"] == "proxy_protocol_untrusted" && l["rule"] == format!("tcp/127.0.0.1:{plain}")
	})
	.await;
	assert!(line["client"].as_str().unwrap().starts_with("127.0.0.1:"), "{line}");
	// a rule where the client speaks first (tls sni): its first bytes are waited for
	let mut body = with_pp(rule("tcp", tls_port, backend), json!({"from": ["10.0.0.0/8"]}));
	body["tls"] = json!({"mode": "sni"});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut s = TcpStream::connect(("127.0.0.1", tls_port)).await.unwrap();
	tokio::time::sleep(Duration::from_millis(100)).await;
	s.write_all(&proxy_v2_header(client(), local(tls_port))).await.unwrap();
	let mut buf = [0u8; 16];
	let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.unwrap().unwrap_or(0);
	assert_eq!(n, 0, "closed");
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{tls_port}")).await;
	assert_eq!(v["stats"]["denied"], 1, "{v}");
}

/// `source_ip: proxy_v2` passes the client of the header on (PROXY v2 in, PROXY v2 out);
/// a LOCAL header (a health check) leaves the peer's address.
#[tokio::test]
async fn proxy_v2_out_carries_the_client_of_the_header() {
	logs::capture();
	let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	let h = harness().await;
	let port = free_port();
	let mut body = with_pp(rule("tcp", port, target), trusted());
	body["source_ip"] = json!("proxy_v2");
	h.post(body).await;

	let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let peer = c.local_addr().unwrap();
	c.write_all(&proxy_v1_header(client(), "198.51.100.1:443".parse().unwrap())).await.unwrap();
	c.write_all(b"data").await.unwrap();
	let (mut up, _) = tokio::time::timeout(Duration::from_secs(3), backend.accept()).await.unwrap().unwrap();
	let expected = proxy_v2_header(client(), local(port));
	let mut got = vec![0u8; expected.len() + 4];
	up.read_exact(&mut got).await.unwrap();
	assert_eq!(&got[..expected.len()], &expected[..], "the client of the header, and rproxy's own address");
	assert_eq!(&got[expected.len()..], b"data");
	let open = logs::wait_for("conn.open", |l| l["event"] == "conn.open" && l["rule"] == format!("tcp/127.0.0.1:{port}")).await;
	assert_eq!(open["client"], CLIENT, "{open}");
	assert_eq!(open["proxy_peer"], peer.to_string(), "the front end in its own field: {open}");

	// LOCAL: version 2, command 0, no addresses
	let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let peer = c.local_addr().unwrap();
	c.write_all(b"\r\n\r\n\0\r\nQUIT\n\x20\x00\x00\x00ping").await.unwrap();
	let (mut up, _) = tokio::time::timeout(Duration::from_secs(3), backend.accept()).await.unwrap().unwrap();
	let expected = proxy_v2_header(peer, local(port));
	let mut got = vec![0u8; expected.len() + 4];
	up.read_exact(&mut got).await.unwrap();
	assert_eq!(&got[..expected.len()], &expected[..], "LOCAL: the peer's own address");
	assert_eq!(&got[expected.len()..], b"ping");
}

/// Per-source `limits` count the client of the header, not the front end.
#[tokio::test]
async fn per_source_limits_count_the_client_of_the_header() {
	let h = harness().await;
	let port = free_port();
	let mut body = with_pp(rule("tcp", port, tcp_backend("B:").await), trusted());
	body["limits"] = json!({"per_source": {"max_connections": 1}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let a = exchange(port, &proxy_v2_header(client(), local(port)), b"1").await.expect("a's first");
	assert!(exchange(port, &proxy_v2_header(client(), local(port)), b"2").await.is_none(), "a's second");
	let other: SocketAddr = "192.0.2.8:4000".parse().unwrap();
	let b = exchange(port, &proxy_v2_header(other, local(port)), b"3").await;
	assert!(b.is_some(), "another client behind the same front end");
	drop((a, b));
}

/// `http` rules: X-Forwarded-For / X-Real-IP and the access log name the client of the header.
#[tokio::test]
async fn http_rules_forward_the_client_of_the_header() {
	logs::capture();
	let app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
		let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		format!("xff={} real={}", h("x-forwarded-for"), h("x-real-ip"))
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let backend = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	let h = harness().await;
	let port = free_port();
	let body = with_pp(
		json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
			"routes": [{"name": "all", "match": "PathPrefix(`/`)", "service": "s"}],
			"services": {"s": {"servers": [{"url": format!("http://{backend}")}]}}}}),
		trusted(),
	);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let peer = s.local_addr().unwrap();
	s.write_all(&proxy_v2_header(client(), local(port))).await.unwrap();
	s.write_all(b"GET /pp HTTP/1.1\r\nHost: x.test\r\nConnection: close\r\n\r\n").await.unwrap();
	let mut resp = String::new();
	tokio::time::timeout(Duration::from_secs(3), s.read_to_string(&mut resp)).await.unwrap().unwrap();
	assert!(resp.contains("xff=192.0.2.7 real=192.0.2.7"), "{resp}");
	let line = logs::wait_for("http.access", |l| l["event"] == "http.access" && l["rule"] == format!("tcp/127.0.0.1:{port}")).await;
	assert_eq!(line["client"], "192.0.2.7", "{line}");
	assert_eq!(line["proxy_peer"], peer.to_string(), "{line}");
}
