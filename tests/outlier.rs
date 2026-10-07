//! Passive health checks / outlier detection (#170): L4 targets that keep
//! failing in real traffic (refused connections, connections the target closes
//! at once) and `http` servers that keep answering 5xx are ejected for a while,
//! reported in `stats` and as `target.down` / `target.up` with `reason: outlier`.
//! The defaults without the setting (one failure, 10 s) are in tests/targets.rs.

mod common;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use common::*;

fn target(addr: SocketAddr) -> Value {
	json!({"addr": addr.ip().to_string(), "port": addr.port()})
}

/// An address nothing listens on (connections are refused).
fn dead() -> SocketAddr {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap()
}

/// A backend that accepts and closes at once (a broken service behind a port that is open).
async fn closer() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((s, _)) = listener.accept().await {
			drop(s);
		}
	});
	addr
}

/// The tag of the backend a new connection reaches.
async fn which(port: u16) -> String {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	roundtrip(&mut s, "x").await.trim_end_matches('x').to_string()
}

async fn wait_view<F: Fn(&Value) -> bool>(h: &Harness, path: &str, what: &str, cond: F) -> Value {
	let deadline = Instant::now() + Duration::from_secs(5);
	loop {
		let (_, v) = h.get(path).await;
		if cond(&v) {
			return v;
		}
		assert!(Instant::now() < deadline, "{what}: {v}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

#[tokio::test]
async fn consecutive_failures_eject_a_target_for_a_while() {
	logs::capture();
	let h = harness().await;
	let (a, b) = (dead(), tcp_backend("B:").await);
	let port = free_port();
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "targets": [target(a), target(b)],
		"balance": "failover", "outlier_detection": {"consecutive_failures": 3, "ejection_time": "1s"}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["outlier_detection"], json!({"consecutive_failures": 3, "ejection_time": "1s"}));
	let path = format!("/rules/tcp/127.0.0.1/{port}");

	// each connection tries the dead target first, then goes on to B
	for _ in 0..2 {
		assert_eq!(which(port).await, "B:");
	}
	let (_, v) = h.get(&path).await;
	assert_eq!((&v["stats"]["targets"][0]["up"], &v["stats"]["targets"][0]["ejections"]), (&json!(true), &json!(0)), "{v}");
	assert!(v["stats"]["targets"][0]["ejected_until"].is_null(), "{v}");
	assert_eq!(which(port).await, "B:");
	let (_, v) = h.get(&path).await;
	let t = &v["stats"]["targets"][0];
	assert_eq!((&t["up"], &t["ejections"]), (&json!(false), &json!(1)), "{v}");
	assert!(t["ejected_until"].as_u64().is_some(), "{v}");
	let rule = format!("tcp/127.0.0.1:{port}");
	let down = logs::wait_for("target.down", |l| l["event"] == "target.down" && l["rule"] == rule).await;
	assert_eq!((&down["reason"], &down["cause"]), (&json!("outlier"), &json!("connect")), "{down}");

	// back by itself once the ejection is over
	wait_view(&h, &path, "the target is back", |v| v["stats"]["targets"][0]["up"] == true).await;
	let up = logs::wait_for("target.up", |l| l["event"] == "target.up" && l["rule"] == rule).await;
	assert_eq!(up["reason"], "outlier", "{up}");
	let (_, v) = h.get(&path).await;
	assert!(v["stats"]["targets"][0]["ejected_until"].is_null(), "{v}");
}

#[tokio::test]
async fn short_lived_connections_count_as_failures() {
	logs::capture();
	let h = harness().await;
	let (a, b) = (closer().await, tcp_backend("B:").await);
	let port = free_port();
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "targets": [target(a), target(b)],
		"balance": "failover", "outlier_detection": {"short_lived": "2s", "ejection_time": "30s"}});
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);

	// the first connection reaches A, which closes it at once
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut buf = [0u8; 16];
	let n = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await.unwrap().unwrap_or(0);
	assert_eq!(n, 0, "closed by A");
	// the connection ends when the client closes its side too
	drop(s);
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	wait_view(&h, &path, "A is ejected", |v| v["stats"]["targets"][0]["up"] == false).await;
	let rule = format!("tcp/127.0.0.1:{port}");
	let down = logs::wait_for("target.down", |l| l["event"] == "target.down" && l["rule"] == rule).await;
	assert_eq!(down["cause"], "short_lived", "{down}");
	assert_eq!(which(port).await, "B:");

	// a connection the client ends is not the target's fault
	let port2 = free_port();
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port2, "targets": [target(b), target(a)],
		"balance": "failover", "outlier_detection": {"short_lived": "2s"}});
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	assert_eq!(which(port2).await, "B:");
	let path2 = format!("/rules/tcp/127.0.0.1/{port2}");
	let v = wait_view(&h, &path2, "the connection ended", |v| v["connections"] == 0).await;
	assert_eq!(v["stats"]["targets"][0]["up"], true, "{v}");
}

#[tokio::test]
async fn max_ejected_percent_keeps_targets_and_patch_changes_it_in_place() {
	let h = harness().await;
	let (a, b) = (dead(), tcp_backend("B:").await);
	let port = free_port();
	let targets = json!([target(a), target(b)]);
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "targets": targets,
		"balance": "failover", "outlier_detection": {"max_ejected_percent": 0}});
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	assert_eq!(which(port).await, "B:");
	let (_, v) = h.get(&path).await;
	assert_eq!((&v["stats"]["targets"][0]["up"], &v["stats"]["targets"][0]["ejections"]), (&json!(true), &json!(0)), "never ejected: {v}");

	// PATCH: back to the defaults (one failure ejects for 10 s)
	let patch = json!({"targets": targets, "balance": "failover", "outlier_detection": {}});
	let (status, v) = h.patch(&format!("tcp/127.0.0.1/{port}"), patch).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(v.get("outlier_detection").is_none(), "{v}");
	assert_eq!(which(port).await, "B:");
	let (_, v) = h.get(&path).await;
	assert_eq!((&v["stats"]["targets"][0]["up"], &v["stats"]["targets"][0]["ejections"]), (&json!(false), &json!(1)), "{v}");
}

/// A backend that answers 500 while `failing` is set; counts its requests.
async fn http_backend(tag: &'static str, failing: bool) -> (SocketAddr, Arc<AtomicU64>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let hits = Arc::new(AtomicU64::new(0));
	let counter = hits.clone();
	let app = axum::Router::new().fallback(move || {
		let counter = counter.clone();
		async move {
			counter.fetch_add(1, Ordering::Relaxed);
			let status = if failing { axum::http::StatusCode::INTERNAL_SERVER_ERROR } else { axum::http::StatusCode::OK };
			(status, tag)
		}
	});
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(addr, hits)
}

#[tokio::test]
async fn http_servers_that_keep_failing_are_ejected() {
	logs::capture();
	let h = harness().await;
	let (bad, bad_hits) = http_backend("bad", true).await;
	let (good, _) = http_backend("good", false).await;
	let (other, _) = http_backend("other", false).await;
	let port = free_port();
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "web", "match": "PathPrefix(`/`)", "service": "s"}],
		"services": {"s": {"servers": [{"url": format!("http://{bad}")}, {"url": format!("http://{good}")}, {"url": format!("http://{other}")}],
			"outlier_detection": {"consecutive_5xx": 2, "ejection_time": "30s"}}}
	}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let client = reqwest::Client::new();
	let mut statuses = vec![];
	for _ in 0..12 {
		statuses.push(client.get(format!("http://127.0.0.1:{port}/")).send().await.unwrap().status().as_u16());
	}
	assert_eq!(bad_hits.load(Ordering::Relaxed), 2, "ejected after two 500s: {statuses:?}");
	assert_eq!(statuses.iter().filter(|s| **s == 500).count(), 2, "{statuses:?}");
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	let servers = &v["stats"]["http"]["services"]["s"];
	assert_eq!((&servers[0]["up"], &servers[0]["ejected"]), (&json!(false), &json!(true)), "{v}");
	assert!(servers[1].get("ejected").is_none() && servers[1]["up"] == true, "{v}");
	let rule = format!("tcp/127.0.0.1:{port}");
	let down = logs::wait_for("target.down", |l| l["event"] == "target.down" && l["rule"] == rule).await;
	assert_eq!((&down["reason"], &down["service"], &down["cause"]), (&json!("outlier"), &json!("s"), &json!("consecutive_5xx")), "{down}");
	assert_eq!(down["server"], format!("http://{bad}"));
}

#[tokio::test]
async fn wrong_settings_are_invalid() {
	let h = harness().await;
	let backend = tcp_backend("W:").await;
	let mut body = rule("tcp", free_port(), backend);
	body["outlier_detection"] = json!({"ejection_time": "1m", "max_ejection_time": "10s"});
	assert_eq!(h.post(body).await.1["code"], "invalid");
	let mut body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
		"routes": [{"name": "a", "match": "PathPrefix(`/`)", "service": "s"}],
		"services": {"s": {"servers": [{"url": "http://127.0.0.1:9"}], "outlier_detection": {"failure_percent": 0}}}
	}});
	assert_eq!(h.post(body.clone()).await.1["code"], "invalid");
	// a rule's outlier_detection is for L4 only
	body["http"]["services"]["s"]["outlier_detection"] = Value::Null;
	body["outlier_detection"] = json!({"consecutive_failures": 2});
	let (_, v) = h.post(body).await;
	assert_eq!(v["code"], "invalid", "{v}");
}

#[tokio::test]
async fn http_ejection_leaves_at_least_half_by_default() {
	let h = harness().await;
	let (a, a_hits) = http_backend("a", true).await;
	let (b, b_hits) = http_backend("b", true).await;
	let port = free_port();
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "web", "match": "PathPrefix(`/`)", "service": "s"}],
		"services": {"s": {"servers": [{"url": format!("http://{a}")}, {"url": format!("http://{b}")}],
			"outlier_detection": {"consecutive_5xx": 1}}}
	}});
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	let client = reqwest::Client::new();
	for _ in 0..6 {
		assert_eq!(client.get(format!("http://127.0.0.1:{port}/")).send().await.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR);
	}
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	let ejected = v["stats"]["http"]["services"]["s"].as_array().unwrap().iter().filter(|s| s["ejected"] == true).count();
	assert_eq!(ejected, 1, "max_ejected_percent 50: {v}");
	let (ah, bh) = (a_hits.load(Ordering::Relaxed), b_hits.load(Ordering::Relaxed));
	assert!(ah == 1 || bh == 1, "the ejected one got one request: {ah} {bh}");
}
