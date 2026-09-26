//! Access control: allow_from, `unmatched: reject`, and static rules.

mod common;

use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use common::pki::Pki;
use common::*;
use rproxy_api::rule::RuleRequest;

/// Whether the proxy answers `msg` on a fresh connection (closed = refused).
async fn tcp_answers(port: u16, msg: &str) -> bool {
	let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await else { return false };
	if s.write_all(msg.as_bytes()).await.is_err() {
		return false;
	}
	let mut buf = [0u8; 64];
	matches!(tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await, Ok(Ok(n)) if n > 0)
}

async fn udp_answers(port: u16) -> bool {
	let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	c.connect(("127.0.0.1", port)).await.unwrap();
	c.send(b"ping").await.unwrap();
	let mut buf = [0u8; 64];
	tokio::time::timeout(Duration::from_millis(500), c.recv(&mut buf)).await.is_ok()
}

async fn denied(h: &Harness, path: &str) -> u64 {
	h.get(path).await.1["stats"]["denied"].as_u64().unwrap()
}

#[tokio::test]
async fn allow_from_limits_tcp_clients_and_can_change_live() {
	let h = harness().await;
	let port = free_port();
	let mut body = rule("tcp", port, tcp_backend("A:").await);
	body["allow_from"] = json!(["10.0.0.0/8", "fd00::/8"]);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["allow_from"], json!(["10.0.0.0/8", "fd00::/8"]));

	let path = format!("/rules/tcp/127.0.0.1/{port}");
	assert!(!tcp_answers(port, "x").await, "127.0.0.1 is outside allow_from");
	assert_eq!(denied(&h, &path).await, 1);
	assert_eq!(h.get(&path).await.1["stats"]["total_connections"], 0, "a refused client is not a connection");

	let backend = h.get(&path).await.1["remote_port"].as_u64().unwrap();
	let (status, v) = h
		.patch(&format!("tcp/127.0.0.1/{port}"), json!({"remote_addr": "127.0.0.1", "remote_port": backend, "allow_from": ["127.0.0.1"]}))
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(v["allow_from"], json!(["127.0.0.1/32"]));
	assert!(tcp_answers(port, "x").await, "allowed after PATCH");

	let (status, v) = h
		.patch(&format!("tcp/127.0.0.1/{port}"), json!({"remote_addr": "127.0.0.1", "remote_port": backend, "allow_from": ["300.1.1.1"]}))
		.await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")));
}

#[tokio::test]
async fn allow_from_limits_udp_clients() {
	let h = harness().await;
	let backend = udp_backend("U:").await;
	let (denied_port, allowed_port) = (free_udp_port(), free_udp_port());
	let mut a = rule("udp", denied_port, backend);
	a["allow_from"] = json!(["192.0.2.0/24"]);
	h.post(a).await;
	let mut b = rule("udp", allowed_port, backend);
	b["allow_from"] = json!(["127.0.0.0/8"]);
	h.post(b).await;

	assert!(!udp_answers(denied_port).await);
	assert_eq!(denied(&h, &format!("/rules/udp/127.0.0.1/{denied_port}")).await, 1);
	assert_eq!(h.get(&format!("/rules/udp/127.0.0.1/{denied_port}")).await.1["connections"], 0, "no session for refused clients");
	assert!(udp_answers(allowed_port).await);
}

async fn tls_ok(pki: &Pki, port: u16, name: &str) -> bool {
	let Ok(tcp) = TcpStream::connect(("127.0.0.1", port)).await else { return false };
	let Ok(mut s) = pki.connector(None).connect(name.to_string().try_into().unwrap(), tcp).await else { return false };
	if s.write_all(b"x").await.is_err() {
		return false;
	}
	let mut buf = [0u8; 64];
	matches!(tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await, Ok(Ok(n)) if n > 0)
}

#[tokio::test]
async fn unmatched_names_are_rejected_when_asked() {
	let pki = Pki::new("unmatched");
	let cert = pki.server("front", &["dashboard.proxy.test", "other.proxy.test"]);
	let h = harness().await;
	let backend = tcp_backend("UI:").await;
	let route = json!([{"server_name": "dashboard.proxy.test", "remote_addr": "127.0.0.1", "remote_port": backend.port()}]);

	// terminate: only dashboard.proxy.test gets a handshake
	let port = free_port();
	let mut body = rule("tcp", port, backend);
	body["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}],
		"routes": route, "unmatched": "reject"});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(tls_ok(&pki, port, "dashboard.proxy.test").await);
	assert!(!tls_ok(&pki, port, "other.proxy.test").await, "a valid certificate name that no route serves");
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	assert_eq!(denied(&h, &path).await, 1);
	assert_eq!(h.get(&path).await.1["stats"]["tls_failures"], 0, "a refusal is not a TLS failure");

	// the same rule with unmatched: default sends other names to the rule's target
	let port2 = free_port();
	let mut body = rule("tcp", port2, backend);
	body["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}], "routes": route});
	h.post(body).await;
	assert!(tls_ok(&pki, port2, "other.proxy.test").await);

	// unmatched: reject needs routes
	let mut bad = rule("tcp", free_port(), backend);
	bad["tls"] = json!({"mode": "sni", "unmatched": "reject"});
	assert_eq!(h.post(bad).await.1["code"], "tls_config");
}

#[tokio::test]
async fn sni_rules_reject_unmatched_names_before_forwarding() {
	let pki = Pki::new("sni-reject");
	let cert = pki.server("backend", &["a.test", "b.test"]);
	// a TLS backend
	let acceptor = pki.acceptor(&cert);
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let backend = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (s, _) = listener.accept().await.unwrap();
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				if let Ok(mut s) = acceptor.accept(s).await {
					let mut buf = [0u8; 16];
					if let Ok(n) = s.read(&mut buf).await {
						let _ = s.write_all(&buf[..n]).await;
					}
				}
			});
		}
	});
	let h = harness().await;
	let port = free_port();
	let mut body = rule("tcp", port, backend);
	body["tls"] = json!({"mode": "sni", "unmatched": "reject",
		"routes": [{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": backend.port()}]});
	h.post(body).await;
	assert!(tls_ok(&pki, port, "a.test").await);
	assert!(!tls_ok(&pki, port, "b.test").await);
	assert_eq!(denied(&h, &format!("/rules/tcp/127.0.0.1/{port}")).await, 1);
}

fn static_rule(port: u16, backend: std::net::SocketAddr) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
		"remote_addr": "127.0.0.1", "remote_port": backend.port(), "allow_from": ["127.0.0.0/8"]})
}

fn requests(v: Value) -> Vec<RuleRequest> {
	serde_json::from_value(v).unwrap()
}

#[tokio::test]
async fn static_rules_are_protected_from_the_api() {
	let h = harness().await;
	let backend = tcp_backend("S:").await;
	let port = free_port();
	assert_eq!(h.registry.load_static(requests(json!([static_rule(port, backend)]))).await, Ok(1));

	let path = format!("tcp/127.0.0.1/{port}");
	let (_, v) = h.get(&format!("/rules/{path}")).await;
	assert_eq!((v["origin"].as_str(), v["state"].as_str()), (Some("static"), Some("running")), "{v}");
	assert!(tcp_answers(port, "x").await);

	let (status, v) = h.patch(&path, json!({"remote_addr": "127.0.0.1", "remote_port": 9})).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("static")));
	let r = h.http.delete(format!("{}/rules/{path}", h.base)).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::CONFLICT);
	assert_eq!(r.json::<Value>().await.unwrap()["code"], "static");
	assert!(tcp_answers(port, "y").await, "still running");

	// API (and DB) rules cannot take its place
	let (status, v) = h.post(rule("tcp", port, backend)).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")));

	// shutdown still stops it
	h.registry.shutdown().await;
	assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

#[tokio::test]
async fn a_broken_static_file_starts_nothing() {
	let h = harness().await;
	let backend = tcp_backend("S:").await;
	let (good, other) = (free_port(), free_port());

	let mut invalid = static_rule(other, backend);
	invalid["allow_from"] = json!(["not-an-address"]);
	let err = h.registry.load_static(requests(json!([static_rule(good, backend), invalid]))).await.unwrap_err();
	assert!(err.contains("static rule #2"), "{err}");

	let err = h.registry.load_static(requests(json!([static_rule(good, backend), static_rule(good, backend)]))).await.unwrap_err();
	assert!(err.contains("overlaps"), "{err}");

	let (_, rules) = h.get("/rules").await;
	assert_eq!(rules.as_array().unwrap().len(), 0, "validation happens before anything starts");
}

/// Without CAP_NET_ADMIN (the harness has no transparent), a transparent rule
/// from the static file or the database becomes a failed rule with the reason;
/// the rest keeps running and the startup goes on.
#[tokio::test]
async fn rules_needing_a_missing_capability_fail_with_the_reason() {
	let h = harness().await;
	let backend = tcp_backend("S:").await;
	let (tp, ok, restored) = (free_port(), free_port(), free_port());
	let mut transparent = static_rule(tp, backend);
	transparent["source_ip"] = json!("transparent");
	assert_eq!(h.registry.load_static(requests(json!([transparent, static_rule(ok, backend)]))).await, Ok(2));

	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{tp}")).await;
	assert_eq!((v["state"].as_str(), v["origin"].as_str()), (Some("failed"), Some("static")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("CAP_NET_ADMIN"), "{v}");
	assert!(tcp_answers(ok, "x").await, "the other static rule runs");

	let mut from_db = rule("tcp", restored, backend);
	from_db["source_ip"] = json!("transparent");
	h.registry.restore(requests(json!([from_db]))).await;
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{restored}")).await;
	assert_eq!(v["state"], "failed", "{v}");
	assert!(v["error"].as_str().unwrap().contains("CAP_NET_ADMIN"), "{v}");

	// a mistake in the file still stops the startup (transparent is IPv4 only)
	let mut v6 = static_rule(free_port(), backend);
	v6["source_ip"] = json!("transparent");
	v6["listen_addr"] = json!("::1");
	let err = h.registry.load_static(requests(json!([v6]))).await.unwrap_err();
	assert!(err.contains("IPv4"), "{err}");
}
