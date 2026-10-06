//! Several destinations for one rule (#98): `targets`, `balance`
//! (round_robin / least_conn / failover), `backup` and `health_check`, for L4
//! rules and for the services of `http` rules.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

use common::*;

/// A TCP echo backend tagged `tag` on `ip`; aborting the task closes it.
async fn tcp_backend_on(ip: &str, port: u16, tag: &'static str) -> (SocketAddr, JoinHandle<()>) {
	let listener = TcpListener::bind((ip, port)).await.unwrap();
	let addr = listener.local_addr().unwrap();
	let task = tokio::spawn(async move {
		loop {
			let Ok((mut s, _)) = listener.accept().await else { return };
			tokio::spawn(async move {
				let mut buf = [0u8; 1024];
				while let Ok(n) = s.read(&mut buf).await {
					if n == 0 {
						break;
					}
					let mut out = tag.as_bytes().to_vec();
					out.extend_from_slice(&buf[..n]);
					if s.write_all(&out).await.is_err() {
						break;
					}
				}
			});
		}
	});
	(addr, task)
}

async fn udp_backend_on(ip: &str, tag: &'static str) -> SocketAddr {
	let sock = UdpSocket::bind((ip, 0)).await.unwrap();
	let addr = sock.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = [0u8; 1024];
		loop {
			let Ok((n, peer)) = sock.recv_from(&mut buf).await else { return };
			let mut out = tag.as_bytes().to_vec();
			out.extend_from_slice(&buf[..n]);
			let _ = sock.send_to(&out, peer).await;
		}
	});
	addr
}

/// One datagram and its answer, or None when none comes back in time.
async fn try_udp(sock: &UdpSocket, msg: &str) -> Option<String> {
	sock.send(msg.as_bytes()).await.ok()?;
	let mut buf = [0u8; 1024];
	let n = tokio::time::timeout(Duration::from_millis(300), sock.recv(&mut buf)).await.ok()?.ok()?;
	Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// A port nothing listens on (connections are refused).
fn dead_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn target(addr: SocketAddr) -> Value {
	json!({"addr": addr.ip().to_string(), "port": addr.port()})
}

fn multi(protocol: &str, port: u16, targets: Vec<Value>, extra: Value) -> Value {
	let mut body = json!({"protocol": protocol, "listen_addr": "127.0.0.1", "listen_port": port, "targets": targets});
	for (k, v) in extra.as_object().unwrap() {
		body[k] = v.clone();
	}
	body
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
async fn round_robin_follows_the_weights() {
	let h = harness().await;
	let (a, b) = (tcp_backend("A:").await, tcp_backend("B:").await);
	let port = free_port();
	let mut ta = target(a);
	ta["weight"] = json!(2);
	let (status, v) = h.post(multi("tcp", port, vec![ta, target(b)], json!({}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["balance"], "round_robin");
	assert_eq!((v["remote_addr"].as_str(), v["remote_port"].as_u64()), (Some("127.0.0.1"), Some(u64::from(a.port()))),
		"the first target stands in for remote_addr / remote_port");
	assert_eq!(v["targets"].as_array().unwrap().len(), 2);

	let mut seen: HashMap<String, usize> = HashMap::new();
	for _ in 0..6 {
		*seen.entry(which(port).await).or_default() += 1;
	}
	assert_eq!((seen.get("A:"), seen.get("B:")), (Some(&4), Some(&2)), "{seen:?}");
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let v = wait_view(&h, &path, "connections end", |v| v["stats"]["targets"][0]["connections"] == 0).await;
	assert_eq!(v["stats"]["targets"][0]["total_connections"], 4);
	assert_eq!(v["stats"]["targets"][1]["up"], true);
}

#[tokio::test]
async fn least_conn_takes_the_emptiest_target() {
	let h = harness().await;
	let backends = [tcp_backend("A:").await, tcp_backend("B:").await, tcp_backend("C:").await];
	let port = free_port();
	let targets = backends.iter().map(|b| target(*b)).collect();
	let (status, v) = h.post(multi("tcp", port, targets, json!({"balance": "least_conn"}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	// three open connections: one on each target
	let mut open = vec![];
	for _ in 0..3 {
		let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
		let tag = roundtrip(&mut s, "x").await.trim_end_matches('x').to_string();
		open.push((tag, s));
	}
	let mut tags: Vec<&str> = open.iter().map(|(t, _)| t.as_str()).collect();
	tags.sort();
	assert_eq!(tags, ["A:", "B:", "C:"]);

	// B's connection ends: B is the emptiest now
	open.retain(|(t, _)| t != "B:");
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	wait_view(&h, &path, "B's connection is gone", |v| v["stats"]["targets"][1]["connections"] == 0).await;
	assert_eq!(which(port).await, "B:");
}

#[tokio::test]
async fn failover_skips_a_dead_target_and_comes_back_with_health_checks() {
	let h = harness().await;
	let dead = dead_port();
	let b = tcp_backend("B:").await;
	let port = free_port();
	let a_addr: SocketAddr = format!("127.0.0.1:{dead}").parse().unwrap();
	let (status, v) = h.post(multi("tcp", port, vec![target(a_addr), target(b)], json!({"balance": "failover"}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let path = format!("/rules/tcp/127.0.0.1/{port}");

	// the refused target is marked down and the connection goes on to the next
	assert_eq!(which(port).await, "B:");
	let (_, v) = h.get(&path).await;
	assert_eq!(v["stats"]["targets"][0]["up"], false, "{v}");
	assert_eq!(which(port).await, "B:");

	// with health checks, the first target is used again once it answers
	let hc = json!({"targets": [target(a_addr), target(b)], "balance": "failover", "health_check": {"interval": "100ms", "timeout": "200ms"}});
	let (status, v) = h.patch(&format!("tcp/127.0.0.1/{port}"), hc).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!((v["balance"].as_str(), v["health_check"]["interval"].as_str()), (Some("failover"), Some("100ms")));
	wait_view(&h, &path, "the dead target is checked down", |v| v["stats"]["targets"][0]["up"] == false).await;
	let (_, _a) = tcp_backend_on("127.0.0.1", dead, "A:").await;
	wait_view(&h, &path, "the target comes back", |v| v["stats"]["targets"][0]["up"] == true).await;
	assert_eq!(which(port).await, "A:");
}

#[tokio::test]
async fn backups_serve_only_while_every_other_target_is_down() {
	let h = harness().await;
	let (a, a_task) = tcp_backend_on("127.0.0.1", 0, "A:").await;
	let b = tcp_backend("B:").await;
	let port = free_port();
	let mut tb = target(b);
	tb["backup"] = json!(true);
	let body = multi("tcp", port, vec![target(a), tb], json!({"health_check": {"interval": "100ms", "timeout": "200ms"}}));
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["targets"][1]["backup"], true);
	for _ in 0..3 {
		assert_eq!(which(port).await, "A:");
	}
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	assert_eq!(h.get(&path).await.1["all_targets_down"], false);
	a_task.abort();
	wait_view(&h, &path, "A is checked down", |v| v["stats"]["targets"][0]["up"] == false).await;
	assert_eq!(which(port).await, "B:");
	assert_eq!(h.get(&path).await.1["all_targets_down"], false, "the backup is up");
}

/// A rule whose every target is down says so (#115), in the rule and in /metrics.
#[tokio::test]
async fn a_rule_with_every_target_down_says_so() {
	let h = harness().await;
	let (a, a_task) = tcp_backend_on("127.0.0.1", 0, "A:").await;
	let (b, b_task) = tcp_backend_on("127.0.0.1", 0, "B:").await;
	let port = free_port();
	let body = multi("tcp", port, vec![target(a), target(b)], json!({"health_check": {"interval": "100ms", "timeout": "200ms"}}));
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let metric = |n: u8| format!("rproxy_rule_all_targets_down{{protocol=\"tcp\",listen=\"127.0.0.1:{port}\"}} {n}");
	let metrics = || async { h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap() };
	assert_eq!(h.get(&path).await.1["all_targets_down"], false);
	assert!(metrics().await.contains(&metric(0)));

	a_task.abort();
	b_task.abort();
	let v = wait_view(&h, &path, "every target down", |v| v["all_targets_down"] == true).await;
	assert_eq!(v["stats"]["targets"][0]["up"], false, "{v}");
	assert!(metrics().await.contains(&metric(1)));

	// back when one answers again
	let (_, _a) = tcp_backend_on("127.0.0.1", a.port(), "A:").await;
	wait_view(&h, &path, "a target back", |v| v["all_targets_down"] == false).await;
}

#[tokio::test]
async fn udp_sessions_are_spread_and_move_off_a_target_that_goes_down() {
	let h = harness().await;
	// two loopback addresses so each target has its own health check port
	let (a, b) = (udp_backend_on("127.0.0.2", "A:").await, udp_backend_on("127.0.0.3", "B:").await);
	let (check_a, check_a_task) = tcp_backend_on("127.0.0.2", 0, "").await;
	let (_, _check_b) = tcp_backend_on("127.0.0.3", check_a.port(), "").await;

	// round robin: two clients, one on each target
	let port = free_udp_port();
	let (status, v) = h.post(multi("udp", port, vec![target(a), target(b)], json!({}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut tags = vec![];
	for _ in 0..2 {
		let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		c.connect(("127.0.0.1", port)).await.unwrap();
		tags.push(udp_roundtrip(&c, "x").await);
	}
	tags.sort();
	assert_eq!(tags, ["A:x", "B:x"]);

	// failover with a TCP health check: the session moves when A goes down
	let port = free_udp_port();
	let hc = json!({"balance": "failover", "health_check": {"interval": "100ms", "timeout": "200ms", "port": check_a.port()}});
	let (status, v) = h.post(multi("udp", port, vec![target(a), target(b)], hc)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	c.connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(udp_roundtrip(&c, "1").await, "A:1");
	check_a_task.abort();
	let path = format!("/rules/udp/127.0.0.1/{port}");
	wait_view(&h, &path, "A is checked down", |v| v["stats"]["targets"][0]["up"] == false).await;
	// the same session (client address) now reaches B
	let deadline = Instant::now() + Duration::from_secs(3);
	loop {
		if try_udp(&c, "2").await.as_deref() == Some("B:2") {
			break;
		}
		assert!(Instant::now() < deadline, "the session did not move to B");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	let v = wait_view(&h, &path, "the session is counted on B", |v| v["stats"]["targets"][1]["connections"] == 1).await;
	assert_eq!(v["stats"]["targets"][0]["connections"], 0);
}

#[tokio::test]
async fn patch_switches_between_one_and_several_targets() {
	let h = harness().await;
	let (a, b) = (tcp_backend("A:").await, tcp_backend("B:").await);
	let port = free_port();
	let (status, v) = h.post(rule("tcp", port, a)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(v.get("targets").is_none() && v.get("balance").is_none() && v["stats"].get("targets").is_none(), "{v}");
	let path = format!("tcp/127.0.0.1/{port}");

	let body = json!({"targets": [target(a), target(b)], "balance": "least_conn", "health_check": {"interval": "1s"}});
	let (status, v) = h.patch(&path, body).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!((v["balance"].as_str(), v["targets"].as_array().map(Vec::len)), (Some("least_conn"), Some(2)));
	assert_eq!(v["stats"]["targets"].as_array().map(Vec::len), Some(2));

	// the backends are replaced as a whole: what is left out goes back to the default
	let (status, v) = h.patch(&path, json!({"targets": [target(a), target(b)]})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(v.get("health_check").is_none(), "left out: no health check: {v}");
	assert_eq!(v["balance"], "round_robin", "left out: round_robin");

	// back to one destination (the UI sends an empty targets with it)
	let (status, v) = h.patch(&path, json!({"remote_addr": "127.0.0.1", "remote_port": b.port(), "targets": []})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(v.get("targets").is_none() && v.get("balance").is_none(), "{v}");
	assert_eq!(which(port).await, "B:");

	let both = json!({"remote_addr": "127.0.0.1", "remote_port": a.port(), "targets": [target(b)]});
	let (status, v) = h.patch(&path, both).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
}

async fn refused(h: &Harness, body: Value) -> String {
	let (status, v) = h.post(body).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	v["error"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn target_settings_are_checked() {
	let h = harness().await;
	let a = tcp_backend("A:").await;
	let mut both = multi("tcp", free_port(), vec![target(a)], json!({}));
	both["remote_addr"] = json!("127.0.0.1");
	both["remote_port"] = json!(a.port());
	assert!(refused(&h, both).await.contains("not both"));
	let mut backup = target(a);
	backup["backup"] = json!(true);
	assert!(refused(&h, multi("tcp", free_port(), vec![backup], json!({}))).await.contains("backup"));
	let mut zero = target(a);
	zero["weight"] = json!(0);
	assert!(refused(&h, multi("tcp", free_port(), vec![zero], json!({}))).await.contains("weight"));
	let udp_check = multi("udp", free_udp_port(), vec![target(a)], json!({"health_check": {"interval": "1s"}}));
	assert!(refused(&h, udp_check).await.contains("port"));
	let (status, _) = h.post(multi("tcp", free_port(), vec![target(a)], json!({"balance": "random"}))).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "unknown balance");

	// a target that cannot be resolved yet does not stop the others
	let port = free_port();
	let unknown = json!({"addr": "not-yet.internal", "port": 80});
	let (status, v) = h.post(multi("tcp", port, vec![unknown, target(a)], json!({}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(which(port).await, "A:");
	h.names.lock().unwrap().insert("not-yet.internal".into(), vec![a]);
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	wait_view(&h, &path, "resolved later", |v| v["stats"]["targets"][0]["resolved"].as_array().is_some_and(|r| !r.is_empty())).await;
	let metrics = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	assert!(metrics.contains(&format!("rproxy_target_up{{protocol=\"tcp\",listen=\"127.0.0.1:{port}\",target=\"not-yet.internal:80\"}} 1")), "{metrics}");
	assert!(metrics.contains("rproxy_target_connections{"), "{metrics}");
}

/// An HTTP backend answering its tag; `/slow` takes a second. Aborting the task stops it.
async fn http_backend(tag: &'static str) -> (SocketAddr, JoinHandle<()>) {
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| async move {
		if req.uri().path() == "/slow" {
			tokio::time::sleep(Duration::from_secs(1)).await;
		}
		tag
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	(addr, tokio::spawn(async move { axum::serve(listener, app).await.unwrap() }))
}

async fn get(h: &Harness, port: u16, path: &str) -> String {
	let r = h.http.get(format!("http://127.0.0.1:{port}{path}")).send().await.unwrap();
	r.text().await.unwrap()
}

#[tokio::test]
async fn http_services_balance_by_least_conn_and_failover() {
	let h = harness().await;
	let (a, _a) = http_backend("A").await;
	let (b, _b) = http_backend("B").await;
	let port = free_port();
	let http = json!({
		"routes": [{"name": "all", "match": "PathPrefix(`/`)", "service": "s"}],
		"services": {"s": {"servers": [{"url": format!("http://{a}")}, {"url": format!("http://{b}")}], "balance": "least_conn"}}
	});
	let (status, v) = h.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["http"]["services"]["s"]["balance"], "least_conn");
	// a slow request keeps one server busy: the next goes to the other
	let slow = {
		let client = h.http.clone();
		tokio::spawn(async move { client.get(format!("http://127.0.0.1:{port}/slow")).send().await.unwrap().text().await.unwrap() })
	};
	tokio::time::sleep(Duration::from_millis(200)).await;
	let fast = get(&h, port, "/fast").await;
	let slow = slow.await.unwrap();
	assert_ne!(fast, slow, "least_conn sends the request to the idle server");

	// failover: the first server while it is up, then the next
	let (c, c_task) = http_backend("C").await;
	let port = free_port();
	let http = json!({
		"routes": [{"name": "all", "match": "PathPrefix(`/`)", "service": "s"}],
		"services": {"s": {"servers": [{"url": format!("http://{c}")}, {"url": format!("http://{b}")}], "balance": "failover",
			"health_check": {"path": "/", "interval": "100ms", "timeout": "200ms"}}}
	});
	let (status, v) = h.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	for _ in 0..3 {
		assert_eq!(get(&h, port, "/").await, "C");
	}
	c_task.abort();
	let deadline = Instant::now() + Duration::from_secs(5);
	loop {
		let r = h.http.get(format!("http://127.0.0.1:{port}/")).send().await.unwrap();
		if r.status() == StatusCode::OK && r.text().await.unwrap() == "B" {
			break;
		}
		assert!(Instant::now() < deadline, "failover did not move to B");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}
