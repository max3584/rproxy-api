//! UDP rules read each port with several sockets (`SO_REUSEPORT`, one per worker
//! thread, #194), each with its own sessions. The kernel picks the socket by a
//! hash of the datagram's addresses and ports, so a client keeps reaching the
//! same one: its session must not be opened twice, replies must still leave
//! from the address it sent to (#137), and the counters add up over the shards.
//! One socket per port is the default; these tests ask for four
//! (`RPROXY_UDP_SHARDS`, here through `force_udp_shards`).

#![cfg(target_os = "linux")]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::json;
use tokio::net::UdpSocket;

use common::*;

/// A harness whose UDP rules get four sockets per port.
async fn sharded() -> Harness {
	rproxy_api::core::registry::force_udp_shards(4);
	harness().await
}

/// Sockets bound to exactly `ip:port` (UDP over IPv4), from /proc/net/udp.
/// Only the exact local address counts: tests run in parallel, and their
/// clients' ephemeral ports (on 127.0.0.1) can happen to equal `port`.
///
/// The file is not a snapshot: the kernel hands it out about a page per read
/// and finds where to go on by counting lines again, so sockets that other tests
/// open or close meanwhile make lines repeat or go missing (#206). Sockets are
/// counted by inode, and the table is read until two reads agree.
fn sockets_on(ip: [u8; 4], port: u16) -> usize {
	// /proc shows the address as a little-endian u32 in hex
	let want = format!("{:08X}:{port:04X}", u32::from_le_bytes(ip));
	let read = || {
		let table = std::fs::read_to_string("/proc/net/udp").unwrap();
		table
			.lines()
			.skip(1)
			.filter_map(|l| {
				let f: Vec<&str> = l.split_whitespace().collect();
				(f.get(1) == Some(&want.as_str())).then(|| f[9].to_string())
			})
			.collect::<std::collections::BTreeSet<_>>()
	};
	let mut last = read();
	for _ in 0..50 {
		let next = read();
		if next == last {
			return next.len();
		}
		last = next;
	}
	panic!("/proc/net/udp kept changing");
}

const LOOPBACK: [u8; 4] = [127, 0, 0, 1];
const ANY: [u8; 4] = [0, 0, 0, 0];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clients_keep_one_session_across_shards() {
	let h = sharded().await;
	let backend = udp_backend("U:").await;
	let port = free_udp_port();
	let (status, v) = h.post(rule("udp", port, backend)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(sockets_on(LOOPBACK, port), 4, "one socket per worker thread");

	// many clients, so that every shard gets some; several round trips each
	let mut clients = vec![];
	for i in 0..64 {
		let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		s.connect(("127.0.0.1", port)).await.unwrap();
		clients.push((i, s));
	}
	for round in 0..3 {
		for (i, s) in &clients {
			assert_eq!(udp_roundtrip(s, &format!("{i}.{round}")).await, format!("U:{i}.{round}"));
		}
	}
	let v = wait_for(&h, &format!("/rules/udp/127.0.0.1/{port}"), |v| v["connections"] == 64).await;
	assert_eq!(v["stats"]["total_connections"], 64, "one session per client, not one per shard: {v}");
	assert_eq!(v["stats"]["dropped"], 0, "{v}");

	// deleting the rule closes every socket of the group
	assert_eq!(h.delete(&format!("udp/127.0.0.1/{port}")).await, StatusCode::NO_CONTENT);
	assert_eq!(sockets_on(LOOPBACK, port), 0);
	std::net::UdpSocket::bind(("127.0.0.1", port)).expect("the port is free again");
}

/// A burst from one client goes through in order (batched receive and send),
/// each datagram behind its own PROXY v2 header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bursts_keep_their_order_and_headers() {
	let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let backend_addr = backend.local_addr().unwrap();
	let h = sharded().await;
	let port = free_udp_port();
	let mut r = rule("udp", port, backend_addr);
	r["source_ip"] = json!("proxy_v2");
	let (status, v) = h.post(r).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	client.connect(("127.0.0.1", port)).await.unwrap();
	// bursts of 100: more could overflow the backend's socket buffer (net.core.rmem_max)
	let mut buf = [0u8; 256];
	for burst in 0..5u32 {
		for i in burst * 100..(burst + 1) * 100 {
			client.send(&i.to_be_bytes()).await.unwrap();
		}
		for i in burst * 100..(burst + 1) * 100 {
			let (n, _) = tokio::time::timeout(Duration::from_secs(3), backend.recv_from(&mut buf)).await.unwrap_or_else(|_| panic!("datagram {i} lost")).unwrap();
			// signature (12), ver/cmd, family, length (2), addresses (12), payload
			assert_eq!(&buf[..12], b"\r\n\r\n\0\r\nQUIT\n");
			assert_eq!(buf[13], 0x12, "IPv4 DGRAM");
			assert_eq!(&buf[28..n], &i.to_be_bytes(), "datagram {i} in order");
		}
	}
	let (_, v) = h.get(&format!("/rules/udp/127.0.0.1/{port}")).await;
	assert_eq!(v["stats"]["total_connections"], 1, "{v}");
}

/// On a wildcard address every shard learns where datagrams were sent to and
/// answers from there (#137); `allow_from` and its counter hold on every shard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wildcard_replies_and_allow_from_on_every_shard() {
	let h = sharded().await;
	let backend = udp_backend("W:").await;
	let port = free_udp_port();
	let mut r = rule("udp", port, backend);
	r["listen_addr"] = json!("0.0.0.0");
	// 127.0.0.1 is allowed, 127.0.0.4 is not
	r["allow_from"] = json!(["127.0.0.1/32"]);
	let (status, v) = h.post(r).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(sockets_on(ANY, port), 4);
	let to = SocketAddr::from(([127, 0, 0, 2], port));
	// keep every client open: a dropped socket's ephemeral port can be handed
	// to the next client, which is then (rightly) the same session
	let mut clients = Vec::new();
	for i in 0..32 {
		// connected: hears only from 127.0.0.2
		let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		s.connect(to).await.unwrap();
		assert_eq!(udp_roundtrip(&s, &format!("{i}")).await, format!("W:{i}"), "reply from the address sent to");
		clients.push(s);
	}
	let mut denied = 0;
	for _ in 0..32 {
		let s = UdpSocket::bind("127.0.0.4:0").await.unwrap();
		s.send_to(b"no", to).await.unwrap();
		denied += 1;
	}
	let v = wait_for(&h, &format!("/rules/udp/0.0.0.0/{port}"), |v| v["stats"]["denied"] == denied).await;
	assert_eq!(v["stats"]["total_connections"], 32, "{v}");
}

/// The group is not opened on a port that another `SO_REUSEPORT` socket holds
/// (it would silently share the port's datagrams with it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_port_held_by_another_reuseport_socket_is_in_use() {
	let port = free_udp_port();
	let other = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
	other.set_reuse_port(true).unwrap();
	other.bind(&SocketAddr::from(([127, 0, 0, 1], port)).into()).unwrap();
	let h = sharded().await;
	let (status, v) = h.post(rule("udp", port, "127.0.0.1:9".parse().unwrap())).await;
	assert_ne!(status, StatusCode::CREATED, "{v}");
	assert_eq!(sockets_on(LOOPBACK, port), 1, "only the other socket");
}
