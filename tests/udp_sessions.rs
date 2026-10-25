//! The default cap of a udp rule's sessions (#332 L3, `RPROXY_UDP_MAX_SESSIONS`):
//! without `limits.max_connections`, a rule takes at most that many sessions (each a
//! socket to the backend until `udp_idle`), so spoofed sources cannot open them
//! without end. The cap is for the whole process, so it is set by this file's
//! only test.

mod common;

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::json;
use tokio::net::UdpSocket;

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

#[tokio::test]
async fn udp_sessions_have_a_default_cap() {
	assert_eq!(rproxy_api::l4::udp::max_sessions(), rproxy_api::l4::udp::DEFAULT_MAX_SESSIONS);
	rproxy_api::l4::udp::set_max_sessions(3);
	let h = harness().await;
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
