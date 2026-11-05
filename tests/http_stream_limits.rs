//! Limits on what one client can hold of an `http` rule (#356): an upgraded connection
//! (WebSocket) keeps its place in the rule's `limits` and ends after `upgraded_idle`, a
//! client that stops reading is closed after `write_stall`, and `timeouts.request` covers
//! the middlewares.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::*;

async fn with_timeouts(spec: Value) -> Harness {
	let spec: rproxy_api::l7::timeouts::HttpTimeoutsSpec = serde_json::from_value(spec).unwrap();
	spec.check().unwrap();
	let global = rproxy_api::l7::access::HttpGlobal::default().with_timeouts(spec.resolve());
	harness_with_global(rproxy_api::control::auth::Tokens::disabled(), global).await
}

/// Accepts a WebSocket-style upgrade, then echoes with a prefix.
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

async fn upgraded(port: u16) -> TcpStream {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"GET /ws HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n").await.unwrap();
	let mut head = vec![];
	let mut b = [0u8; 1];
	while !head.ends_with(b"\r\n\r\n") {
		assert_eq!(s.read(&mut b).await.unwrap(), 1, "{}", String::from_utf8_lossy(&head));
		head.push(b[0]);
	}
	assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
	s
}

async fn echo(s: &mut TcpStream, msg: &[u8]) -> Vec<u8> {
	s.write_all(msg).await.unwrap();
	let mut buf = [0u8; 64];
	let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
	buf[..n].to_vec()
}

/// Waits for the peer to close; how long it took.
async fn closed_after(s: &mut TcpStream, most: Duration) -> Duration {
	let started = Instant::now();
	let mut buf = [0u8; 4096];
	loop {
		match tokio::time::timeout(most, s.read(&mut buf)).await {
			Ok(Ok(0)) | Ok(Err(_)) => return started.elapsed(),
			Ok(Ok(_)) => continue,
			Err(_) => panic!("still open after {most:?}"),
		}
	}
}

#[tokio::test]
async fn an_upgraded_connection_keeps_its_place_and_ends_when_idle() {
	let h = with_timeouts(json!({"upgraded_idle": "1s"})).await;
	let ws = upgrade_backend().await;
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"limits": {"max_connections": 1},
			"http": {"routes": [{"name": "ws", "match": "Path(`/ws`)", "to": format!("http://{ws}")}]},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut s = upgraded(port).await;
	// the tunnel still counts: a second connection is over max_connections
	tokio::time::sleep(Duration::from_millis(200)).await;
	let mut second = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let _ = second.write_all(b"GET / HTTP/1.1\r\nHost: ws.test\r\n\r\n").await;
	let mut buf = [0u8; 64];
	let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf)).await.unwrap().unwrap_or(0);
	assert_eq!(n, 0, "refused while the tunnel is open: {}", String::from_utf8_lossy(&buf[..n]));
	// traffic keeps it open past upgraded_idle
	for i in 0..4 {
		tokio::time::sleep(Duration::from_millis(400)).await;
		assert_eq!(echo(&mut s, format!("m{i}").as_bytes()).await, format!("WS:m{i}").as_bytes());
	}
	// then silence: closed after about a second (checked every quarter of it)
	let quiet = closed_after(&mut s, Duration::from_secs(5)).await;
	assert!(quiet >= Duration::from_millis(900) && quiet < Duration::from_secs(3), "{quiet:?}");
	// and its place is free again
	tokio::time::sleep(Duration::from_millis(200)).await;
	let mut again = upgraded(port).await;
	assert_eq!(echo(&mut again, b"x").await, b"WS:x");
}

/// Answers every request with `size` bytes.
async fn big_backend(size: usize) -> SocketAddr {
	let app = axum::Router::new().fallback(move || async move { vec![b'x'; size] });
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

#[tokio::test]
async fn a_client_that_stops_reading_is_closed() {
	let h = with_timeouts(json!({"write_stall": "1s"})).await;
	const SIZE: usize = 64 << 20;
	let big = big_backend(SIZE).await;
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {"routes": [{"name": "big", "match": "PathPrefix(`/`)", "to": format!("http://{big}")}]},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"GET / HTTP/1.1\r\nHost: big.test\r\n\r\n").await.unwrap();
	// reads nothing for longer than write_stall: rproxy gives up on the connection
	tokio::time::sleep(Duration::from_secs(4)).await;
	let mut got = 0usize;
	let mut buf = vec![0u8; 1 << 16];
	loop {
		match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.expect("closed by rproxy") {
			Ok(0) | Err(_) => break,
			Ok(n) => got += n,
		}
	}
	assert!(got < SIZE, "the whole answer came: {got}");
	let (_, rules) = h.get("/rules").await;
	assert_eq!(rules[0]["connections"], 0, "{rules}");
}

/// An auth server that answers after `wait`.
async fn slow_auth(wait: Duration) -> SocketAddr {
	let app = axum::Router::new().fallback(move || async move {
		tokio::time::sleep(wait).await;
		"ok"
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

#[tokio::test]
async fn the_request_timeout_covers_the_middlewares() {
	let h = harness().await;
	let auth = slow_auth(Duration::from_secs(3)).await;
	let backend = big_backend(10).await;
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["fa"], "timeouts": {"request": "500ms"}}],
				"middlewares": {"fa": {"forward_auth": {"address": format!("http://{auth}/"), "timeout": "10s"}}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let started = Instant::now();
	let r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/")).timeout(Duration::from_secs(10)).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::GATEWAY_TIMEOUT);
	assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
}

#[tokio::test]
async fn the_new_limits_are_in_the_features() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["http_stream_limits"], true, "{caps}");
}
