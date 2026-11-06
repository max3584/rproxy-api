//! The process's descriptor budget (#373, `core::budget`) bounds TCP relays (2 each), `http`
//! connections (2 to be accepted, then 1 each) and their connections to servers (1 each), as
//! it bounds UDP sessions: past it, new ones are refused (`reason: fd_budget`) and the control API still answers.
//!
//! The budget is the process's, so this file is its own test binary with one test, and sets
//! a budget of 4 before anything takes from it.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::*;

use rproxy_api::core::budget;

const BUDGET: u64 = 4;

/// A connection to `port` the backend answers through, or None when it is closed at once.
async fn tcp_served(port: u16) -> Option<TcpStream> {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"x").await.ok()?;
	let mut buf = [0u8; 64];
	match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
		Ok(Ok(n)) if n > 0 => Some(s),
		_ => None,
	}
}

/// An HTTP server that answers every request with 200 and closes its connection, so no
/// connection to it is kept between requests.
async fn closing_backend() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let mut head = Vec::new();
				let mut buf = [0u8; 1024];
				while !head.windows(4).any(|w| w == b"\r\n\r\n") {
					match s.read(&mut buf).await {
						Ok(0) | Err(_) => return,
						Ok(n) => head.extend_from_slice(&buf[..n]),
					}
				}
				let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
				let _ = s.shutdown().await;
			});
		}
	});
	addr
}

/// The status of one request on `s` (kept open), or None when the connection was closed.
async fn request(s: &mut TcpStream) -> Option<u16> {
	s.write_all(b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n").await.ok()?;
	let mut got = Vec::new();
	let mut buf = [0u8; 4096];
	loop {
		if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
			let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
			let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length:")).map_or(0, |v| v.trim().parse().unwrap());
			if got.len() >= end + 4 + len {
				return head.split(' ').nth(1).and_then(|c| c.parse().ok());
			}
		}
		match tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await {
			Ok(Ok(0)) | Ok(Err(_)) => return None,
			Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
			Err(_) => panic!("no response"),
		}
	}
}

/// Whether a new connection to `port` is closed at once, before anything is read from it.
async fn closed_at_once(port: u16) -> bool {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	request(&mut s).await.is_none()
}

async fn in_use_becomes(n: u64) {
	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	while budget::in_use() != n {
		assert!(tokio::time::Instant::now() < deadline, "in use {} (want {n})", budget::in_use());
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

async fn metrics(h: &Harness) -> String {
	h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap()
}

/// `rproxy_rule_limited_total` with `reason="fd_budget"` of the rule on `port`.
fn fd_budget_refused(metrics: &str, port: u16) -> u64 {
	let label = format!("listen=\"127.0.0.1:{port}\",reason=\"fd_budget\"}} ");
	metrics
		.lines()
		.find_map(|l| l.strip_prefix("rproxy_rule_limited_total{protocol=\"tcp\",")?.strip_prefix(&label)?.parse().ok())
		.unwrap_or(0)
}

#[tokio::test]
async fn connections_over_the_descriptor_budget_are_refused() {
	assert_eq!(budget::init_exact(BUDGET), BUDGET, "nothing set the budget before");
	let h = harness().await;
	let echo = tcp_backend("E:").await;
	let web = closing_backend().await;
	let (tcp_port, http_port) = (free_port(), free_port());
	let (status, v) = h.post(rule("tcp", tcp_port, echo)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": http_port,
			"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{web}")}]}}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(budget::in_use(), 0, "health checks and listeners take none");

	// TCP relays: 2 each
	let a = tcp_served(tcp_port).await.expect("first relay");
	let b = tcp_served(tcp_port).await.expect("second relay");
	in_use_becomes(BUDGET).await;
	assert!(tcp_served(tcp_port).await.is_none(), "a third relay is over the budget");
	assert!(closed_at_once(http_port).await, "so is an http connection");
	// the control API is not in the budget
	let (status, rules) = h.get("/rules").await;
	assert_eq!(status, StatusCode::OK, "{rules}");
	let m = metrics(&h).await;
	assert_eq!(fd_budget_refused(&m, tcp_port), 1, "{m}");
	assert_eq!(fd_budget_refused(&m, http_port), 1, "{m}");
	assert!(m.contains(&format!("rproxy_session_budget_limit {BUDGET}")), "{m}");
	assert!(m.contains(&format!("rproxy_session_budget_in_use {BUDGET}")), "{m}");
	let (_, r) = h.get(&format!("/rules/tcp/127.0.0.1/{tcp_port}")).await;
	assert_eq!(r["stats"]["limited"], 1, "{r}");
	drop(b);
	in_use_becomes(2).await;

	// an http connection needs room for 2 when accepted, as any TCP connection, and keeps 1;
	// its connection to the server takes 1 while it is open
	let mut x = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
	assert_eq!(request(&mut x).await, Some(200));
	// the server closed its connection: given back
	in_use_becomes(3).await;
	assert!(closed_at_once(http_port).await, "no room for 2");
	drop(a);
	in_use_becomes(1).await;
	let mut y = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
	assert_eq!(request(&mut y).await, Some(200));
	in_use_becomes(2).await;
	let b = tcp_served(tcp_port).await.expect("a relay in the 2 left");
	in_use_becomes(BUDGET).await;
	// no room for a connection to the server: 503, and the client's connection stays
	assert_eq!(request(&mut x).await, Some(503));
	assert_eq!(request(&mut y).await, Some(503));
	assert_eq!(fd_budget_refused(&metrics(&h).await, http_port), 4, "2 connections + two 503s");

	// room again once the relay ends
	drop(b);
	in_use_becomes(2).await;
	assert_eq!(request(&mut x).await, Some(200));
	drop((x, y));
	in_use_becomes(0).await;
	let a = tcp_served(tcp_port).await.expect("served again");
	drop(a);
	in_use_becomes(0).await;
}
