//! The default cap of a udp rule's sessions (#332 L3, `RPROXY_UDP_MAX_SESSIONS`):
//! without `limits.max_connections`, a rule takes at most that many sessions (each a
//! socket to the backend until `udp_idle`), so spoofed sources cannot open them
//! without end. The cap is for the whole process, so it is set by this file's
//! only test. Sessions not replied to by their backend end after 5 s and are the
//! ones that make room at the cap (#354).

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use common::*;

/// A new client socket of `port`, and whether its first datagram is answered.
async fn new_session(port: u16) -> (UdpSocket, bool) {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(("127.0.0.1", port)).await.unwrap();
	sock.send(b"x").await.unwrap();
	let mut buf = [0u8; 64];
	let answered = tokio::time::timeout(Duration::from_millis(500), sock.recv(&mut buf)).await.is_ok();
	(sock, answered)
}

/// A backend that never answers; the source ports it hears from.
async fn silent_backend() -> (SocketAddr, mpsc::UnboundedReceiver<u16>) {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr = sock.local_addr().unwrap();
	let (tx, rx) = mpsc::unbounded_channel();
	tokio::spawn(async move {
		let mut buf = [0u8; 64];
		while let Ok((_, from)) = sock.recv_from(&mut buf).await {
			let _ = tx.send(from.port());
		}
	});
	(addr, rx)
}

#[tokio::test]
async fn udp_sessions_have_a_default_cap() {
	assert_eq!(rproxy_api::l4::udp::max_sessions(), rproxy_api::l4::udp::DEFAULT_MAX_SESSIONS);
	rproxy_api::l4::udp::set_max_sessions(3);
	let h = harness().await;

	// #354: at the cap, the oldest session its backend never answered makes room (spoofed sources are
	// never answered); and such sessions end after 5 s, not udp_idle
	let (silent, mut heard) = silent_backend().await;
	let port = free_udp_port();
	let (status, v) = h.post(rule("udp", port, silent)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let path = format!("/rules/udp/127.0.0.1/{port}");
	let mut socks = vec![];
	let mut ports = std::collections::HashSet::new();
	for i in 0..5 {
		let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		sock.send_to(b"x", ("127.0.0.1", port)).await.unwrap();
		let from = tokio::time::timeout(Duration::from_secs(2), heard.recv()).await.expect("each session reaches the backend").unwrap();
		assert!(ports.insert(from), "session {i} has its own backend socket");
		socks.push(sock);
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	let (_, v) = h.get(&path).await;
	assert_eq!(v["stats"]["limited"], 0, "none refused: {v}");
	assert!(v["connections"].as_u64().unwrap() <= 3, "the oldest made room: {v}");
	let started = std::time::Instant::now();
	loop {
		let (_, v) = h.get(&path).await;
		if v["connections"] == 0 {
			break;
		}
		assert!(started.elapsed() < Duration::from_secs(8), "unreplied sessions end after 5 s: {v}");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	assert_eq!(h.delete(&path[7..]).await, StatusCode::NO_CONTENT);

	let backend = udp_backend("U:").await;
	let port = free_udp_port();
	let mut body = rule("udp", port, backend);
	body["udp_idle_secs"] = json!(1);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let path = format!("/rules/udp/127.0.0.1/{port}");

	let mut open = vec![];
	for _ in 0..3 {
		let (sock, answered) = new_session(port).await;
		assert!(answered, "within the cap");
		open.push(sock);
	}
	let (_, answered) = new_session(port).await;
	assert!(!answered, "a fourth session is refused");
	// the open sessions go on
	assert_eq!(udp_roundtrip(&open[0], "again").await, "U:again");
	let (_, v) = h.get(&path).await;
	assert_eq!(v["stats"]["limited"], 1, "counted as limits are: {v}");
	assert_eq!(v["stats"]["total_connections"], 3, "{v}");
	let metrics = h
		.http
		.get(format!("{}/metrics", h.base))
		.send()
		.await
		.unwrap()
		.text()
		.await
		.unwrap();
	let line = format!("rproxy_rule_limited_total{{protocol=\"udp\",listen=\"127.0.0.1:{port}\",reason=\"max_connections\"}} 1");
	assert!(metrics.contains(&line), "{line} not in\n{metrics}");

	// once they go idle (1 s), new ones are taken again
	drop(open);
	wait_for(&h, &path, |v| v["connections"] == 0).await;
	tokio::time::sleep(Duration::from_millis(100)).await;
	assert!(new_session(port).await.1, "after the idle ones ended");

	// a rule's own limits.max_connections is its cap, above the default too
	let port = free_udp_port();
	let mut body = rule("udp", port, backend);
	body["limits"] = json!({"max_connections": 5});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut open = vec![];
	for i in 0..5 {
		let (sock, answered) = new_session(port).await;
		assert!(answered, "session {i} within limits.max_connections");
		open.push(sock);
	}
	assert!(!new_session(port).await.1, "over limits.max_connections");

	// 0: no cap
	rproxy_api::l4::udp::set_max_sessions(0);
	let port = free_udp_port();
	let (status, v) = h.post(rule("udp", port, backend)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	for i in 0..8 {
		let (sock, answered) = new_session(port).await;
		assert!(answered, "session {i} without a cap");
		open.push(sock);
	}
}
