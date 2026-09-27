//! One rule listening on several addresses (`extra_listen_addrs`, #99).

mod common;

use std::net::SocketAddr;

use reqwest::StatusCode;
use serde_json::json;
use tokio::net::{TcpStream, UdpSocket};

use common::*;

/// Whether this host has IPv6 loopback; tests that need it are skipped otherwise.
fn has_ipv6() -> bool {
	std::net::TcpListener::bind("[::1]:0").is_ok()
}

/// A TCP port free on both 127.0.0.1 and ::1.
fn dual_port() -> u16 {
	loop {
		let p = free_port();
		if std::net::TcpListener::bind(("::1", p)).is_ok() {
			return p;
		}
	}
}

fn dual_udp_port() -> u16 {
	loop {
		let p = free_udp_port();
		if std::net::UdpSocket::bind(("::1", p)).is_ok() {
			return p;
		}
	}
}

async fn tcp_says(addr: &str, msg: &str) -> std::io::Result<String> {
	let mut s = TcpStream::connect(addr).await?;
	Ok(roundtrip(&mut s, msg).await)
}

#[tokio::test]
async fn tcp_and_udp_on_ipv4_and_ipv6() {
	if !has_ipv6() {
		return;
	}
	let h = harness().await;
	let backend = tcp_backend("T:").await;
	let port = dual_port();
	let mut body = rule("tcp", port, backend);
	body["extra_listen_addrs"] = json!(["::1"]);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["extra_listen_addrs"], json!(["::1"]));
	assert_eq!(tcp_says(&format!("127.0.0.1:{port}"), "4").await.unwrap(), "T:4");
	assert_eq!(tcp_says(&format!("[::1]:{port}"), "6").await.unwrap(), "T:6");
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!(v["stats"]["total_connections"], 2, "one rule for both: {v}");

	let backend = udp_backend("U:").await;
	let port = dual_udp_port();
	let mut body = rule("udp", port, backend);
	body["extra_listen_addrs"] = json!(["::1"]);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	for (bind, to, msg) in [("127.0.0.1:0", format!("127.0.0.1:{port}"), "4"), ("[::1]:0", format!("[::1]:{port}"), "6")] {
		let s = UdpSocket::bind(bind).await.unwrap();
		s.connect(&to).await.unwrap();
		assert_eq!(udp_roundtrip(&s, msg).await, format!("U:{msg}"));
	}
}

#[tokio::test]
async fn ipv4_and_ipv6_wildcards_in_one_rule() {
	if !has_ipv6() {
		return;
	}
	let h = harness().await;
	let backend = tcp_backend("W:").await;
	let port = dual_port();
	let mut body = rule("tcp", port, backend);
	body["listen_addr"] = json!("0.0.0.0");
	body["extra_listen_addrs"] = json!(["::"]);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(tcp_says(&format!("127.0.0.1:{port}"), "a").await.unwrap(), "W:a");
	assert_eq!(tcp_says(&format!("[::1]:{port}"), "b").await.unwrap(), "W:b");

	// the rule's :: covers every IPv6 address on the port
	let mut other = rule("tcp", port, backend);
	other["listen_addr"] = json!("::1");
	assert_eq!(h.post(other).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn overlaps_count_extra_addresses() {
	if !has_ipv6() {
		return;
	}
	let h = harness().await;
	let backend = tcp_backend("O:").await;
	let port = dual_port();
	let mut body = rule("tcp", port, backend);
	body["extra_listen_addrs"] = json!(["::1"]);
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);

	let mut same = rule("tcp", port, backend);
	same["listen_addr"] = json!("::1");
	let (status, v) = h.post(same).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")), "{v}");

	let mut extra = rule("tcp", port, backend);
	extra["listen_addr"] = json!("127.0.0.2");
	extra["extra_listen_addrs"] = json!(["::1"]);
	assert_eq!(h.post(extra).await.0, StatusCode::CONFLICT, "an extra address clashes too");

	// a lone :: takes IPv4 as well (the OS default), so 0.0.0.0 on its port clashes
	let port = dual_port();
	let mut lone = rule("tcp", port, backend);
	lone["listen_addr"] = json!("::");
	assert_eq!(h.post(lone).await.0, StatusCode::CREATED);
	let mut v4 = rule("tcp", port, backend);
	v4["listen_addr"] = json!("0.0.0.0");
	assert_eq!(h.post(v4).await.0, StatusCode::CONFLICT);

	for bad in [json!(["not-an-ip"]), json!(["127.0.0.1"]), json!(["::1", "::1"])] {
		let mut b = rule("tcp", dual_port(), backend);
		b["extra_listen_addrs"] = bad.clone();
		let (status, v) = h.post(b).await;
		assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{bad}: {v}");
	}
}

#[tokio::test]
async fn patch_adds_and_removes_addresses() {
	if !has_ipv6() {
		return;
	}
	let h = harness().await;
	let backend = tcp_backend("P:").await;
	let port = dual_port();
	assert_eq!(h.post(rule("tcp", port, backend)).await.0, StatusCode::CREATED);
	assert!(TcpStream::connect(format!("[::1]:{port}")).await.is_err());
	let path = format!("tcp/127.0.0.1/{port}");
	let target = json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port()});

	let mut add = target.clone();
	add["extra_listen_addrs"] = json!(["::1"]);
	let (status, v) = h.patch(&path, add).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(v["extra_listen_addrs"], json!(["::1"]));
	let mut held = TcpStream::connect(format!("[::1]:{port}")).await.unwrap();
	assert_eq!(roundtrip(&mut held, "1").await, "P:1");

	// left out: the addresses stay
	let (status, v) = h.patch(&path, target.clone()).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(v["extra_listen_addrs"], json!(["::1"]));

	let mut remove = target.clone();
	remove["extra_listen_addrs"] = json!([]);
	let (status, v) = h.patch(&path, remove).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(v.get("extra_listen_addrs").is_none(), "{v}");
	// closing the address leaves its open connections and the other address alone
	assert_eq!(roundtrip(&mut held, "2").await, "P:2");
	assert_eq!(tcp_says(&format!("127.0.0.1:{port}"), "3").await.unwrap(), "P:3");
	let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
	while TcpStream::connect(format!("[::1]:{port}")).await.is_ok() {
		assert!(std::time::Instant::now() < deadline, "::1 still listening");
		tokio::time::sleep(std::time::Duration::from_millis(50)).await;
	}
	let (_, v) = h.get(&format!("/rules/{path}")).await;
	assert_eq!(v["state"], "running", "{v}");
}

#[tokio::test]
async fn a_port_range_on_both_addresses() {
	if !has_ipv6() {
		return;
	}
	let h = harness().await;
	let backends = [tcp_backend("R0:").await, tcp_backend("R1:").await];
	// two consecutive backend ports cannot be arranged; check the range is opened on both addresses
	let port = loop {
		let p = free_tcp_block(2);
		if (0..2).all(|i| std::net::TcpListener::bind(("::1", p + i)).is_ok()) {
			break p;
		}
	};
	let body = json!({
		"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "listen_port_end": port + 1,
		"extra_listen_addrs": ["::1"], "remote_addr": "127.0.0.1", "remote_port": backends[0].port(),
	});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	for i in 0..2 {
		assert!(TcpStream::connect(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], port + i))).await.is_ok(), "::1 port {}", port + i);
	}
	assert_eq!(tcp_says(&format!("[::1]:{port}"), "x").await.unwrap(), "R0:x");
}
