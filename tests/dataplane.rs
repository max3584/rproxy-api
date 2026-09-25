//! Forwarding behaviour: data integrity, concurrency, half-close, failures,
//! address fallback, UDP isolation, IPv6 and PROXY protocol v1.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use common::*;

/// Echoes every byte back until the client closes.
async fn tcp_echo() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let (mut r, mut w) = s.split();
				let _ = tokio::io::copy(&mut r, &mut w).await;
			});
		}
	});
	addr
}

fn pattern(len: usize) -> Vec<u8> {
	(0..len).map(|i| (i * 31 % 251) as u8).collect()
}

#[tokio::test]
async fn large_transfer_keeps_every_byte() {
	let h = harness().await;
	let port = free_port();
	h.post(rule("tcp", port, tcp_echo().await)).await;

	let data = pattern(16 * 1024 * 1024);
	let conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let (mut r, mut w) = conn.into_split();
	let send = data.clone();
	let writer = tokio::spawn(async move {
		w.write_all(&send).await.unwrap();
		w.shutdown().await.unwrap();
	});
	let mut got = Vec::with_capacity(data.len());
	tokio::time::timeout(Duration::from_secs(20), r.read_to_end(&mut got)).await.unwrap().unwrap();
	writer.await.unwrap();
	assert_eq!(got.len(), data.len());
	assert!(got == data, "payload corrupted");
}

#[tokio::test]
async fn many_concurrent_connections() {
	let h = harness().await;
	let port = free_port();
	h.post(rule("tcp", port, tcp_echo().await)).await;

	let clients: Vec<_> = (0..200)
		.map(|i| {
			tokio::spawn(async move {
				let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
				let msg = format!("client-{i}");
				s.write_all(msg.as_bytes()).await.unwrap();
				let mut buf = vec![0u8; msg.len()];
				s.read_exact(&mut buf).await.unwrap();
				assert_eq!(buf, msg.as_bytes());
			})
		})
		.collect();
	for c in clients {
		tokio::time::timeout(Duration::from_secs(10), c).await.unwrap().unwrap();
	}
}

#[tokio::test]
async fn half_close_lets_the_backend_answer_after_client_eof() {
	// backend reads until EOF, then answers with the byte count
	let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	tokio::spawn(async move {
		let (mut s, _) = backend.accept().await.unwrap();
		let mut all = vec![];
		s.read_to_end(&mut all).await.unwrap();
		s.write_all(format!("got {}", all.len()).as_bytes()).await.unwrap();
	});
	let h = harness().await;
	let port = free_port();
	h.post(rule("tcp", port, target)).await;

	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	conn.write_all(b"12345").await.unwrap();
	conn.shutdown().await.unwrap();
	let mut reply = String::new();
	tokio::time::timeout(Duration::from_secs(3), conn.read_to_string(&mut reply)).await.unwrap().unwrap();
	assert_eq!(reply, "got 5");
}

#[tokio::test]
async fn backend_closing_first_reaches_the_client() {
	let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	tokio::spawn(async move {
		let (mut s, _) = backend.accept().await.unwrap();
		s.write_all(b"bye").await.unwrap();
	});
	let h = harness().await;
	let port = free_port();
	h.post(rule("tcp", port, target)).await;

	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut reply = String::new();
	tokio::time::timeout(Duration::from_secs(3), conn.read_to_string(&mut reply)).await.unwrap().unwrap();
	assert_eq!(reply, "bye");
}

#[tokio::test]
async fn backend_down_closes_the_client_and_recovers() {
	let h = harness().await;
	let dead = free_port(); // nothing listens here yet
	let port = free_port();
	let target: SocketAddr = format!("127.0.0.1:{dead}").parse().unwrap();
	let (status, _) = h.post(rule("tcp", port, target)).await;
	assert_eq!(status, StatusCode::CREATED);

	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut buf = [0u8; 8];
	let n = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf)).await.unwrap().unwrap_or(0);
	assert_eq!(n, 0, "client is closed instead of hanging");
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!(v["state"], "running", "a dead backend does not fail the rule");

	// the backend comes up on the same address
	let backend = TcpListener::bind(target).await.unwrap();
	tokio::spawn(async move {
		let (mut s, _) = backend.accept().await.unwrap();
		s.write_all(b"up").await.unwrap();
	});
	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut reply = String::new();
	conn.read_to_string(&mut reply).await.unwrap();
	assert_eq!(reply, "up");
}

#[tokio::test]
async fn falls_back_to_the_next_resolved_address() {
	let h = harness().await;
	// two A records: 127.0.0.1 (sorted first) refuses, 127.0.0.2 serves
	let Ok(listener) = TcpListener::bind("127.0.0.2:0").await else {
		eprintln!("skipping: 127.0.0.2 is not usable");
		return;
	};
	let alive = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let (mut s, _) = listener.accept().await.unwrap();
		let mut buf = [0u8; 16];
		let n = s.read(&mut buf).await.unwrap();
		s.write_all(&[b"B:", &buf[..n]].concat()).await.unwrap();
	});
	let refused: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
	h.names.lock().unwrap().insert("multi.test".into(), vec![alive, refused]);
	let port = free_port();
	let mut body = rule("tcp", port, alive);
	body["remote_addr"] = json!("multi.test");
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["resolved"][0], refused.to_string(), "the refusing address is tried first");

	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut conn, "x").await, "B:x");
}

#[tokio::test]
async fn udp_clients_do_not_see_each_others_replies() {
	let h = harness().await;
	let port = free_udp_port();
	h.post(rule("udp", port, udp_backend("E:").await)).await;

	let mut clients = vec![];
	for _ in 0..20 {
		let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		s.connect(("127.0.0.1", port)).await.unwrap();
		clients.push(s);
	}
	for round in 0..3 {
		for (i, c) in clients.iter().enumerate() {
			c.send(format!("{i}-{round}").as_bytes()).await.unwrap();
		}
		for (i, c) in clients.iter().enumerate() {
			let mut buf = [0u8; 64];
			let n = tokio::time::timeout(Duration::from_secs(2), c.recv(&mut buf)).await.unwrap().unwrap();
			assert_eq!(&buf[..n], format!("E:{i}-{round}").as_bytes());
		}
	}
	wait_for(&h, &format!("/rules/udp/127.0.0.1/{port}"), |v| v["connections"] == 20).await;
}

#[tokio::test]
async fn udp_large_datagram_is_forwarded_whole() {
	let h = harness().await;
	let port = free_udp_port();
	h.post(rule("udp", port, udp_backend("").await)).await;
	let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	client.connect(("127.0.0.1", port)).await.unwrap();

	// the backend buffer is 1024 bytes, so stay under it; the proxy itself accepts 64 KiB
	let data = pattern(1000);
	client.send(&data).await.unwrap();
	let mut buf = vec![0u8; 2048];
	let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf)).await.unwrap().unwrap();
	assert_eq!(&buf[..n], &data[..]);
}

#[tokio::test]
async fn udp_datagram_near_64k_is_forwarded_whole() {
	// dedicated backend with a full-size buffer
	let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = vec![0u8; 65_535];
		let (n, peer) = backend.recv_from(&mut buf).await.unwrap();
		backend.send_to(&buf[..n], peer).await.unwrap();
	});
	let h = harness().await;
	let port = free_udp_port();
	h.post(rule("udp", port, target)).await;
	let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	client.connect(("127.0.0.1", port)).await.unwrap();

	let data = pattern(60_000);
	client.send(&data).await.unwrap();
	let mut buf = vec![0u8; 65_535];
	let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf)).await.unwrap().unwrap();
	assert_eq!(n, data.len());
	assert!(buf[..n] == data[..]);
}

#[tokio::test]
async fn ipv6_listen_and_target() {
	if std::net::TcpListener::bind("[::1]:0").is_err() {
		eprintln!("skipping: no IPv6 loopback");
		return;
	}
	let backend = TcpListener::bind("[::1]:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	tokio::spawn(async move {
		let (mut s, peer) = backend.accept().await.unwrap();
		s.write_all(format!("from {}", peer.ip()).as_bytes()).await.unwrap();
	});
	let h = harness().await;
	let port = std::net::TcpListener::bind("[::1]:0").unwrap().local_addr().unwrap().port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "::1", "listen_port": port,
			"remote_addr": "::1", "remote_port": target.port(),
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let mut conn = TcpStream::connect(("::1", port)).await.unwrap();
	let mut reply = String::new();
	conn.read_to_string(&mut reply).await.unwrap();
	assert_eq!(reply, "from ::1");
	// IPv6 keys work in the path when URL-encoded
	assert_eq!(h.delete(&format!("tcp/%3A%3A1/{port}")).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn proxy_protocol_v1_header_carries_the_client() {
	let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	let h = harness().await;
	let port = free_port();
	let mut body = rule("tcp", port, target);
	body["source_ip"] = json!("proxy_v1");
	h.post(body).await;

	let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let client_port = client.local_addr().unwrap().port();
	client.write_all(b"data").await.unwrap();
	let (mut upstream, _) = backend.accept().await.unwrap();
	let expected = format!("PROXY TCP4 127.0.0.1 127.0.0.1 {client_port} {port}\r\ndata");
	let mut got = vec![0u8; expected.len()];
	upstream.read_exact(&mut got).await.unwrap();
	assert_eq!(String::from_utf8(got).unwrap(), expected);
}

#[tokio::test]
async fn concurrent_creates_of_the_same_rule_yield_one_winner() {
	let h = harness().await;
	let backend = tcp_echo().await;
	// free_port() can race with other tests; retry on bind_failed, which is not what we test
	let mut created = 0;
	for _ in 0..5 {
		let body = rule("tcp", free_port(), backend);
		let attempts: Vec<_> = (0..10)
			.map(|_| {
				let (http, url, body) = (h.http.clone(), format!("{}/rules", h.base), body.clone());
				tokio::spawn(async move {
					let r = http.post(url).json(&body).send().await.unwrap();
					let status = r.status();
					let v: serde_json::Value = r.json().await.unwrap_or_default();
					(status, v["code"].as_str().unwrap_or("").to_string())
				})
			})
			.collect();
		let mut results = vec![];
		for a in attempts {
			results.push(a.await.unwrap());
		}
		if results.iter().all(|(_, code)| code == "bind_failed") {
			continue;
		}
		for (status, code) in results {
			match (status, code.as_str()) {
				(StatusCode::CREATED, _) => created += 1,
				(StatusCode::CONFLICT, "already_exists") => {}
				other => panic!("unexpected {other:?}"),
			}
		}
		break;
	}
	assert_eq!(created, 1);
}

#[tokio::test]
async fn a_silent_api_client_does_not_block_others() {
	// the original implementation read requests inline in its accept loop,
	// so one idle connection stalled every later command
	let h = harness().await;
	let addr = h.base.trim_start_matches("http://").to_string();
	let _idle: Vec<TcpStream> = futures_join(addr.clone(), 5).await;
	let started = std::time::Instant::now();
	let (status, _) = h.get("/rules").await;
	assert_eq!(status, StatusCode::OK);
	assert!(started.elapsed() < Duration::from_secs(1));
}

async fn futures_join(addr: String, n: usize) -> Vec<TcpStream> {
	let mut out = vec![];
	for _ in 0..n {
		out.push(TcpStream::connect(&addr).await.unwrap());
	}
	out
}

#[tokio::test]
async fn bytes_are_counted_while_connections_are_open() {
	let h = harness().await;
	let tcp_port = free_port();
	h.post(rule("tcp", tcp_port, tcp_echo().await)).await;
	let udp_port = free_udp_port();
	h.post(rule("udp", udp_port, udp_backend("U:").await)).await;

	// a TCP connection that stays open
	let mut conn = TcpStream::connect(("127.0.0.1", tcp_port)).await.unwrap();
	conn.write_all(b"12345").await.unwrap();
	let mut buf = [0u8; 5];
	conn.read_exact(&mut buf).await.unwrap();
	let v = wait_for(&h, &format!("/rules/tcp/127.0.0.1/{tcp_port}"), |v| v["stats"]["rx_bytes"] == 5).await;
	assert_eq!(v["stats"]["tx_bytes"], 5);
	assert_eq!(v["connections"], 1, "still open");

	// a UDP session that has not timed out yet
	let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	client.connect(("127.0.0.1", udp_port)).await.unwrap();
	udp_roundtrip(&client, "abc").await;
	let v = wait_for(&h, &format!("/rules/udp/127.0.0.1/{udp_port}"), |v| v["stats"]["rx_bytes"] == 3).await;
	assert_eq!(v["stats"]["tx_bytes"], 5, "reply is \"U:abc\"");
	assert_eq!(v["connections"], 1, "session still active");
	drop(conn);
}
