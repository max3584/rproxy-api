//! `limits` (#165) and `bandwidth` (#166) of a rule, and the counters for
//! collecting traffic (#166 5.2): real clients and backends on loopback.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use common::*;

/// Whether a new connection to `port` is served (the backend answers) or closed at once.
async fn tcp_served(port: u16) -> Option<TcpStream> {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"x").await.ok()?;
	let mut buf = [0u8; 64];
	match tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await {
		Ok(Ok(n)) if n > 0 => Some(s),
		_ => None,
	}
}

async fn stats(h: &Harness, path: &str) -> Value {
	h.get(path).await.1["stats"].clone()
}

async fn metrics(h: &Harness) -> String {
	h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap()
}

#[tokio::test]
async fn capabilities_say_limits_and_bandwidth_run() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["limits"], true, "{caps}");
	assert_eq!(caps["features"]["bandwidth"], true, "{caps}");
}

/// Concurrent connections of a source and of the rule; PATCH keeps the count,
/// `{}` removes the limits.
#[tokio::test]
async fn tcp_connections_are_limited_per_source_and_per_rule() {
	let h = harness().await;
	let backend = tcp_backend("L:").await;
	let port = free_port();
	let mut body = rule("tcp", port, backend);
	body["limits"] = json!({"max_connections": 5, "per_source": {"max_connections": 2}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["limits"]["per_source"]["max_connections"], 2, "{v}");
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let s = stats(&h, &path).await;
	assert_eq!(s["limited"], 0, "{s}");
	assert!(s["counters_since"].as_u64().unwrap() > 1_700_000_000, "{s}");

	let a = tcp_served(port).await.expect("first");
	let b = tcp_served(port).await.expect("second");
	assert!(tcp_served(port).await.is_none(), "a third from the same source is closed");
	assert_eq!(stats(&h, &path).await["limited"], 1);
	let m = metrics(&h).await;
	assert!(
		m.contains(&format!("rproxy_rule_limited_total{{protocol=\"tcp\",listen=\"127.0.0.1:{port}\",reason=\"source_connections\"}} 1")),
		"{m}"
	);
	assert!(m.contains("rproxy_process_start_time_seconds "), "{m}");

	drop(a);
	let a = wait_served(port).await;

	// the rule's limit, lowered by PATCH: the two open connections still count
	let target = json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()});
	let mut patch = target.clone();
	patch["limits"] = json!({"max_connections": 2});
	let (status, v) = h.patch(&path["/rules/".len()..], patch).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(tcp_served(port).await.is_none(), "over the rule's max_connections");
	let m = metrics(&h).await;
	assert!(m.contains(&format!("listen=\"127.0.0.1:{port}\",reason=\"max_connections\"}} 1")), "{m}");

	let mut clear = target;
	clear["limits"] = json!({});
	let (status, v) = h.patch(&path["/rules/".len()..], clear).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(v.get("limits").is_none(), "{v}");
	let more: Vec<_> = futures_util::future::join_all((0..3).map(|_| tcp_served(port))).await;
	assert!(more.iter().all(Option::is_some), "no limits any more");
	drop((a, b, more));
}

/// After a connection closes, its place is free again (the close is seen asynchronously).
async fn wait_served(port: u16) -> TcpStream {
	let deadline = Instant::now() + Duration::from_secs(3);
	loop {
		if let Some(s) = tcp_served(port).await {
			return s;
		}
		assert!(Instant::now() < deadline, "the closed connection's place was not given back");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

#[tokio::test]
async fn tcp_new_connections_are_a_rate() {
	let h = harness().await;
	let port = free_port();
	let mut body = rule("tcp", port, tcp_backend("R:").await);
	body["limits"] = json!({"per_source": {"new_connections": {"average": 2, "period": "1h"}}});
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	assert!(tcp_served(port).await.is_some());
	assert!(tcp_served(port).await.is_some());
	assert!(tcp_served(port).await.is_none(), "a third new connection within the period");
	let m = metrics(&h).await;
	assert!(m.contains(&format!("listen=\"127.0.0.1:{port}\",reason=\"new_connections\"}} 1")), "{m}");
}

/// An `http` rule: the limits apply to its TCP connections.
#[tokio::test]
async fn http_rules_limit_their_connections() {
	let h = harness().await;
	let backend = http_body_backend(10).await;
	let port = free_port();
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
		"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}")}]},
		"limits": {"per_source": {"max_connections": 1}}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	first.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
	let mut buf = [0u8; 256];
	assert!(first.read(&mut buf).await.unwrap() > 0);
	let mut second = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let _ = second.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await;
	let n = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf)).await.unwrap().unwrap_or(0);
	assert_eq!(n, 0, "closed without an answer");
	assert_eq!(stats(&h, &format!("/rules/tcp/127.0.0.1/{port}")).await["limited"], 1);
}

#[tokio::test]
async fn udp_sessions_and_datagrams_are_limited() {
	let h = harness().await;
	let backend = udp_backend("U:").await;
	let port = free_udp_port();
	let mut body = rule("udp", port, backend);
	body["limits"] = json!({"max_connections": 1, "per_source": {"packets": {"average": 3, "period": "1h"}}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let path = format!("/rules/udp/127.0.0.1/{port}");

	let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	a.connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(udp_roundtrip(&a, "1").await, "U:1");
	// the second client socket would be a second session
	let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	b.connect(("127.0.0.1", port)).await.unwrap();
	b.send(b"2").await.unwrap();
	let mut buf = [0u8; 64];
	assert!(tokio::time::timeout(Duration::from_millis(300), b.recv(&mut buf)).await.is_err(), "no second session");
	// 3 datagrams per hour from 127.0.0.1: the first two passed, one more does
	assert_eq!(udp_roundtrip(&a, "3").await, "U:3");
	a.send(b"4").await.unwrap();
	assert!(tokio::time::timeout(Duration::from_millis(300), a.recv(&mut buf)).await.is_err(), "over packets");
	let s = stats(&h, &path).await;
	assert_eq!(s["limited"], 2, "{s}");
	assert_eq!(s["total_connections"], 1, "{s}");
	let m = metrics(&h).await;
	for reason in ["max_connections", "packets"] {
		assert!(m.contains(&format!("listen=\"127.0.0.1:{port}\",reason=\"{reason}\"}} 1")), "{reason}: {m}");
	}
}

/// A backend that sends `pattern` bytes (`i % 251`) until the client closes.
async fn streaming_backend() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let chunk: Vec<u8> = (0..251u32 * 64).map(|i| (i % 251) as u8).collect();
				while s.write_all(&chunk).await.is_ok() {}
			});
		}
	});
	addr
}

/// Reads `n` bytes and checks they continue the pattern from `*at`.
async fn read_pattern(s: &mut TcpStream, n: usize, at: &mut u64) {
	let mut buf = vec![0u8; n];
	tokio::time::timeout(Duration::from_secs(20), s.read_exact(&mut buf)).await.unwrap().unwrap();
	for (i, b) in buf.iter().enumerate() {
		assert_eq!(u64::from(*b), (*at + i as u64) % 251, "byte {} changed", *at + i as u64);
	}
	*at += n as u64;
}

/// TCP download: a limit added by PATCH slows a connection that is already
/// moving a bulk transfer (and so is spliced), without losing a byte; removed,
/// the connection is fast again.
#[tokio::test]
async fn tcp_bandwidth_waits_and_applies_to_open_connections() {
	let h = harness().await;
	let backend = streaming_backend().await;
	let port = free_port();
	assert_eq!(h.post(rule("tcp", port, backend)).await.0, StatusCode::CREATED);
	let rule_path = format!("tcp/127.0.0.1/{port}");
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut at = 0;
	let started = Instant::now();
	read_pattern(&mut s, 8 << 20, &mut at).await;
	assert!(started.elapsed() < Duration::from_secs(10), "unlimited: {:?}", started.elapsed());

	// 8 Mbit/s = 1 MB/s; burst 64 KiB
	let target = json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()});
	let mut patch = target.clone();
	patch["bandwidth"] = json!({"download": "8Mbps", "burst": "64KiB"});
	let (status, v) = h.patch(&rule_path, patch).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(v["bandwidth"]["download"], "8Mbps", "{v}");
	// what was already in the socket buffers still comes fast (MBs on loopback); then the limit
	let mut chunks = 0;
	loop {
		let started = Instant::now();
		read_pattern(&mut s, 256 << 10, &mut at).await;
		if started.elapsed() >= Duration::from_millis(150) {
			break;
		}
		chunks += 1;
		assert!(chunks < 128, "32 MiB came fast after the limit");
	}
	let started = Instant::now();
	read_pattern(&mut s, 2_000_000, &mut at).await;
	let took = started.elapsed();
	assert!(took >= Duration::from_millis(1600) && took < Duration::from_secs(10), "2 MB at 1 MB/s took {took:?}");

	let mut clear = target;
	clear["bandwidth"] = json!({});
	assert_eq!(h.patch(&rule_path, clear).await.0, StatusCode::OK);
	let started = Instant::now();
	read_pattern(&mut s, 8 << 20, &mut at).await;
	assert!(started.elapsed() < Duration::from_secs(5), "removed: {:?}", started.elapsed());

	drop(s);
}

/// TCP upload, per source: what the client writes is read at the limit's pace.
#[tokio::test]
async fn tcp_upload_per_source_waits() {
	let h = harness().await;
	let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let up_port = free_port();
	let mut body = rule("tcp", up_port, sink.local_addr().unwrap());
	body["bandwidth"] = json!({"per_source": {"upload": "4Mbps"}});
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	let received = tokio::spawn(async move {
		let (mut s, _) = sink.accept().await.unwrap();
		let mut got = Vec::new();
		s.read_to_end(&mut got).await.unwrap();
		got.len()
	});
	let mut c = TcpStream::connect(("127.0.0.1", up_port)).await.unwrap();
	let started = Instant::now();
	// 4 Mbit/s = 500 kB/s: 1 MB takes about 2 s (the socket buffers take some at once)
	c.write_all(&vec![1u8; 1_000_000]).await.unwrap();
	c.shutdown().await.unwrap();
	assert_eq!(received.await.unwrap(), 1_000_000);
	let took = started.elapsed();
	assert!(took >= Duration::from_millis(1200), "1 MB at 500 kB/s took {took:?}");
	let s = stats(&h, &format!("/rules/tcp/127.0.0.1/{up_port}")).await;
	assert_eq!(s["rx_bytes"], 1_000_000, "{s}");
}

/// An HTTP backend answering every request with `kib` KiB of body.
async fn http_body_backend(kib: usize) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let mut buf = vec![0u8; 8192];
				let mut seen = Vec::new();
				loop {
					let Ok(n) = s.read(&mut buf).await else { return };
					if n == 0 {
						return;
					}
					seen.extend_from_slice(&buf[..n]);
					while let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
						seen.drain(..end + 4);
						let body = vec![b'b'; kib * 1024];
						let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len());
						if s.write_all(head.as_bytes()).await.is_err() || s.write_all(&body).await.is_err() {
							return;
						}
					}
				}
			});
		}
	});
	addr
}

/// An `http` rule's responses wait for the download limit.
#[tokio::test]
async fn http_rules_are_shaped() {
	let h = harness().await;
	let backend = http_body_backend(1024).await;
	let port = free_port();
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
		"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}")}]},
		"bandwidth": {"download": "4Mbps"}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let started = Instant::now();
	let r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/")).timeout(Duration::from_secs(20)).send().await.unwrap();
	let bytes = r.bytes().await.unwrap();
	let took = started.elapsed();
	assert_eq!(bytes.len(), 1 << 20);
	// 1 MiB at 500 kB/s
	assert!(took >= Duration::from_millis(1600), "{took:?}");
}

/// UDP: datagrams over the rate are dropped and counted.
#[tokio::test]
async fn udp_bandwidth_drops_over_the_rate() {
	let h = harness().await;
	let backend = udp_backend("B:").await;
	let port = free_udp_port();
	let mut body = rule("udp", port, backend);
	// 80 kbit/s = 10 kB/s, 2 KiB at once
	body["bandwidth"] = json!({"download": "80kbps", "burst": "2KiB"});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	c.connect(("127.0.0.1", port)).await.unwrap();
	let payload = vec![b'p'; 1000];
	for _ in 0..10 {
		c.send(&payload).await.unwrap();
	}
	let mut answers = 0;
	let mut buf = [0u8; 2048];
	while tokio::time::timeout(Duration::from_millis(400), c.recv(&mut buf)).await.is_ok() {
		answers += 1;
	}
	assert!((2..=5).contains(&answers), "{answers} answers");
	let path = format!("/rules/udp/127.0.0.1/{port}");
	let s = stats(&h, &path).await;
	assert_eq!(s["rx_bytes"], 10_000, "the upload has no limit: {s}");
	let dropped = s["dropped"].as_u64().unwrap();
	assert_eq!(dropped, 10 - answers, "{s}");
	let m = metrics(&h).await;
	assert!(
		m.contains(&format!("rproxy_rule_bandwidth_dropped_total{{protocol=\"udp\",listen=\"127.0.0.1:{port}\"}} {dropped}")),
		"{m}"
	);
}
