//! `max_connections` of a target (#341): L4 `targets[]` (TCP connections, UDP sessions) and
//! the `servers[]` of `http` services (requests in progress). A full target is skipped by
//! every `balance`; when all are full the connection is refused (`reason: target_full`).

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use common::*;

fn capped(addr: SocketAddr, max: u32) -> Value {
	json!({"addr": addr.ip().to_string(), "port": addr.port(), "max_connections": max})
}

fn l4(protocol: &str, port: u16, targets: Vec<Value>, balance: &str) -> Value {
	json!({"protocol": protocol, "listen_addr": "127.0.0.1", "listen_port": port, "targets": targets, "balance": balance})
}

/// A connection through the rule and the tag of the backend it reached.
async fn open(port: u16) -> (TcpStream, String) {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let tag = roundtrip(&mut s, "x").await.trim_end_matches('x').to_string();
	(s, tag)
}

/// A connection rproxy closes at once, with nothing sent.
async fn refused(port: u16) {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut buf = [0u8; 16];
	let read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await.expect("closed by rproxy");
	assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
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

async fn metrics(h: &Harness) -> String {
	h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap()
}

fn limited_line(protocol: &str, port: u16, n: u64) -> String {
	format!("rproxy_rule_limited_total{{protocol=\"{protocol}\",listen=\"127.0.0.1:{port}\",reason=\"target_full\"}} {n}")
}

#[tokio::test]
async fn tcp_failover_fills_the_targets_in_order_then_refuses() {
	let h = harness().await;
	let (a, b) = (tcp_backend("A:").await, tcp_backend("B:").await);
	let port = free_port();
	let (status, v) = h.post(l4("tcp", port, vec![capped(a, 2), capped(b, 1)], "failover")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["targets"][0]["max_connections"], 2, "{v}");
	let path = format!("/rules/tcp/127.0.0.1/{port}");

	let (c1, t1) = open(port).await;
	let (_c2, t2) = open(port).await;
	let (_c3, t3) = open(port).await;
	assert_eq!([t1.as_str(), t2.as_str(), t3.as_str()], ["A:", "A:", "B:"], "spillover: A until full, then B");
	let (_, v) = h.get(&path).await;
	let t = &v["stats"]["targets"];
	assert_eq!((&t[0]["connections"], &t[0]["max_connections"], &t[0]["full"]), (&json!(2), &json!(2), &json!(true)), "{v}");
	assert_eq!((&t[1]["connections"], &t[1]["full"]), (&json!(1), &json!(true)), "{v}");
	assert!(metrics(&h).await.contains(&format!("rproxy_target_full{{protocol=\"tcp\",listen=\"127.0.0.1:{port}\",target=\"{a}\"}} 1")));

	// every target full: closed, counted in limited, and not as a connection
	let total = v["stats"]["total_connections"].clone();
	refused(port).await;
	let v = wait_view(&h, &path, "refusal counted", |v| v["stats"]["limited"] == 1).await;
	assert_eq!(v["stats"]["total_connections"], total, "{v}");
	assert!(metrics(&h).await.contains(&limited_line("tcp", port, 1)));

	// a connection to A ends: its place is free again
	drop(c1);
	wait_view(&h, &path, "the closed connection is given back", |v| v["stats"]["targets"][0]["connections"] == 1).await;
	assert_eq!(open(port).await.1, "A:");
}

#[tokio::test]
async fn failed_connections_give_their_place_back() {
	let h = harness().await;
	let a = tcp_backend("A:").await;
	let dead = SocketAddr::from(([127, 0, 0, 1], std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()));
	let port = free_port();
	// the dead target is tried (and fails) for some connections; it must not fill up
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "targets": [capped(dead, 1), capped(a, 1)],
		"outlier_detection": {"consecutive_failures": 1000}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	for _ in 0..6 {
		let (s, tag) = open(port).await;
		assert_eq!(tag, "A:");
		drop(s);
		wait_view(&h, &format!("/rules/tcp/127.0.0.1/{port}"), "closed", |v| v["stats"]["targets"][1]["connections"] == 0).await;
	}
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!((&v["stats"]["targets"][0]["connections"], &v["stats"]["targets"][0]["full"]), (&json!(0), &json!(false)), "{v}");
	assert_eq!(v["stats"]["limited"], 0, "{v}");
}

#[tokio::test]
async fn patching_the_targets_keeps_the_open_connections_counted() {
	let h = harness().await;
	let (a, b) = (tcp_backend("A:").await, tcp_backend("B:").await);
	let port = free_port();
	let (status, v) = h.post(l4("tcp", port, vec![capped(a, 1)], "failover")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	assert_eq!(h.get(&path).await.1["stats"]["targets"][0]["max_connections"], 1, "one target with a cap is shown");
	let (c1, t1) = open(port).await;
	assert_eq!(t1, "A:");

	let (status, v) =
		h.patch(&format!("tcp/127.0.0.1/{port}"), json!({"targets": [capped(a, 1), capped(b, 1)], "balance": "failover"})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let (_, v) = h.get(&path).await;
	assert_eq!((&v["stats"]["targets"][0]["connections"], &v["stats"]["targets"][0]["full"]), (&json!(1), &json!(true)), "{v}");
	let (_c2, t2) = open(port).await;
	assert_eq!(t2, "B:", "A is still full with the connection from before the PATCH");
	refused(port).await;
	drop(c1);
	wait_view(&h, &path, "given back to the new pool", |v| v["stats"]["targets"][0]["connections"] == 0).await;
	assert_eq!(open(port).await.1, "A:");
}

/// One datagram and its answer, or None when none comes back in time.
async fn try_udp(sock: &UdpSocket, msg: &str) -> Option<String> {
	sock.send(msg.as_bytes()).await.ok()?;
	let mut buf = [0u8; 1024];
	let n = tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut buf)).await.ok()?.ok()?;
	Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

async fn udp_client(port: u16) -> UdpSocket {
	let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	s.connect(("127.0.0.1", port)).await.unwrap();
	s
}

#[tokio::test]
async fn udp_sessions_fill_the_targets_and_come_back_when_idle() {
	let h = harness().await;
	let (a, b) = (udp_backend("A:").await, udp_backend("B:").await);
	let port = free_udp_port();
	let mut body = l4("udp", port, vec![capped(a, 1), capped(b, 1)], "failover");
	body["udp_idle_secs"] = json!(1);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let path = format!("/rules/udp/127.0.0.1/{port}");

	let (s1, s2, s3) = (udp_client(port).await, udp_client(port).await, udp_client(port).await);
	assert_eq!(udp_roundtrip(&s1, "x").await, "A:x");
	assert_eq!(udp_roundtrip(&s2, "x").await, "B:x");
	// both full: the third client's datagrams are dropped (again with each one)
	assert_eq!(try_udp(&s3, "x").await, None);
	assert_eq!(udp_roundtrip(&s1, "y").await, "A:y", "the open sessions go on");
	let v = wait_view(&h, &path, "refusal counted", |v| v["stats"]["limited"].as_u64().is_some_and(|n| n >= 1)).await;
	assert_eq!((&v["stats"]["targets"][0]["full"], &v["stats"]["targets"][1]["full"]), (&json!(true), &json!(true)), "{v}");
	assert!(metrics(&h).await.contains("reason=\"target_full\""));

	// the sessions end when idle: their places come back
	wait_view(&h, &path, "idle sessions given back", |v| {
		v["stats"]["targets"][0]["connections"] == 0 && v["stats"]["targets"][1]["connections"] == 0
	})
	.await;
	assert_eq!(udp_roundtrip(&s3, "z").await, "A:z");
}

/// An HTTP backend answering its tag; a path ending in `/slow` takes a second.
async fn http_backend(tag: &'static str) -> (SocketAddr, JoinHandle<()>) {
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| async move {
		if req.uri().path().ends_with("/slow") {
			tokio::time::sleep(Duration::from_secs(1)).await;
		}
		tag
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	(addr, tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }))
}

#[tokio::test]
async fn http_servers_take_their_max_requests_then_spill_over_or_answer_503() {
	let h = harness().await;
	let (a, _a) = http_backend("A").await;
	let (b, _b) = http_backend("B").await;
	let port = free_port();
	let http = json!({
		"routes": [{"name": "all", "match": "PathPrefix(`/`)", "service": "s"}, {"name": "one", "match": "PathPrefix(`/one`)", "service": "one"}],
		"services": {
			"s": {"servers": [{"url": format!("http://{a}"), "max_connections": 1}, {"url": format!("http://{b}")}], "balance": "failover"},
			"one": {"servers": [{"url": format!("http://{a}"), "max_connections": 1}]}
		}
	});
	let (status, v) = h.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["http"]["services"]["s"]["servers"][0]["max_connections"], 1, "{v}");
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let get = |p: &'static str| {
		let client = h.http.clone();
		async move {
			let r = client.get(format!("http://127.0.0.1:{port}{p}")).send().await.unwrap();
			(r.status(), r.text().await.unwrap())
		}
	};

	// failover: A while it has room, B while A is busy
	assert_eq!(get("/").await, (StatusCode::OK, "A".into()));
	let slow = tokio::spawn(get("/slow"));
	wait_view(&h, &path, "the slow request is in progress", |v| v["stats"]["http"]["services"]["s"][0]["full"] == true).await;
	assert_eq!(get("/fast").await, (StatusCode::OK, "B".into()));
	assert_eq!(slow.await.unwrap(), (StatusCode::OK, "A".into()));
	let v = wait_view(&h, &path, "done", |v| v["stats"]["http"]["services"]["s"][0]["in_flight"] == 0).await;
	assert_eq!(v["stats"]["limited"], 0, "{v}");

	// one server, full: 503, counted in limited
	let slow = tokio::spawn(get("/one/slow"));
	wait_view(&h, &path, "the slow request is in progress", |v| v["stats"]["http"]["services"]["one"][0]["full"] == true).await;
	assert_eq!(get("/one/fast").await.0, StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(slow.await.unwrap(), (StatusCode::OK, "A".into()));
	let v = wait_view(&h, &path, "refusal counted", |v| v["stats"]["limited"] == 1).await;
	assert_eq!(v["stats"]["http"]["services"]["one"][0]["in_flight"], 0, "{v}");
	assert!(metrics(&h).await.contains(&limited_line("tcp", port, 1)));
	assert_eq!(get("/one/fast").await, (StatusCode::OK, "A".into()), "its place came back");
}

#[tokio::test]
async fn caps_are_validated_and_shown_in_features() {
	let h = harness().await;
	let a = tcp_backend("A:").await;
	let (status, v) = h.post(l4("tcp", free_port(), vec![capped(a, 0)], "round_robin")).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap_or_default().contains("max_connections"), "{v}");
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["target_max_connections"], true, "{caps}");
}
