//! Live upgrades (#174, docs/DESIGN-v0.4.md 10.1) with the real binary: the
//! running process hands its sockets to the binary on disk (SIGUSR2,
//! `POST /admin/upgrade`). TCP connections the old process holds keep working
//! until they end, new connections reach the new process, rules made through
//! the API and the counters carry over, UDP goes on (a new session).

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::net::{TcpStream, UdpSocket};

use common::*;

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-handoff-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

/// The first process (our child) and every pid that took over from it; all
/// are stopped when the test ends.
struct Procs {
	first: Child,
	pids: Vec<i32>,
	log: PathBuf,
}

impl Drop for Procs {
	fn drop(&mut self) {
		for pid in &self.pids {
			signal(*pid, libc::SIGKILL);
		}
		let _ = self.first.kill();
		let _ = self.first.wait();
	}
}

fn signal(pid: i32, sig: libc::c_int) {
	// SAFETY: a signal to a process this test started
	unsafe { libc::kill(pid, sig) };
}

fn alive(pid: i32) -> bool {
	match fs::read_to_string(format!("/proc/{pid}/stat")) {
		// the state follows the command name in parentheses
		Ok(stat) => stat.rsplit(')').next().map(|r| !r.trim_start().starts_with('Z')).unwrap_or(false),
		Err(_) => false,
	}
}

fn start(dir: &Path, env: &[(&str, String)]) -> Procs {
	let log = dir.join("out.log");
	let out = fs::File::create(&log).unwrap();
	let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.current_dir(dir)
		.env_clear()
		.envs(env.iter().map(|(k, v)| (*k, v.as_str())))
		.stdout(out.try_clone().unwrap())
		.stderr(out)
		.stdin(Stdio::null())
		.spawn()
		.unwrap();
	let pid = child.id() as i32;
	Procs { first: child, pids: vec![pid], log }
}

fn lines(log: &Path) -> Vec<Value> {
	fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

/// Waits for the `n`-th log line (1-based) with this event.
async fn wait_event(log: &Path, event: &str, n: usize) -> Value {
	let deadline = Instant::now() + Duration::from_secs(40);
	loop {
		let found: Vec<Value> = lines(log).into_iter().filter(|l| l["event"] == event).collect();
		if found.len() >= n {
			return found[n - 1].clone();
		}
		assert!(Instant::now() < deadline, "no {event} #{n}; log:\n{}", fs::read_to_string(log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

async fn wait_until(what: &str, log: &Path, mut f: impl FnMut() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(40);
	while !f() {
		assert!(Instant::now() < deadline, "timed out waiting for {what}; log:\n{}", fs::read_to_string(log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

/// The process holding the server side of the TCP connection from `client` to `port`.
fn owner(client: SocketAddr, port: u16, pids: &[i32]) -> Option<i32> {
	let hex = |a: SocketAddr| match a {
		SocketAddr::V4(v4) => format!("{:08X}:{:04X}", u32::from_le_bytes(v4.ip().octets()), v4.port()),
		SocketAddr::V6(_) => String::new(),
	};
	let local = hex(SocketAddr::from(([127, 0, 0, 1], port)));
	let remote = hex(client);
	let table = fs::read_to_string("/proc/net/tcp").ok()?;
	let inode = table.lines().skip(1).find_map(|l| {
		let f: Vec<&str> = l.split_whitespace().collect();
		(f.get(1) == Some(&local.as_str()) && f.get(2) == Some(&remote.as_str())).then(|| f[9].to_string())
	})?;
	let want = format!("socket:[{inode}]");
	pids.iter().copied().find(|pid| {
		fs::read_dir(format!("/proc/{pid}/fd"))
			.into_iter()
			.flatten()
			.flatten()
			.any(|e| fs::read_link(e.path()).map(|l| l.to_string_lossy() == want).unwrap_or(false))
	})
}

/// One HTTP/1.1 request over the control API's Unix socket: (status, body).
fn unix_request(path: &Path, method: &str, uri: &str) -> (u16, String) {
	let mut s = std::os::unix::net::UnixStream::connect(path).unwrap();
	s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
	write!(s, "{method} {uri} HTTP/1.1\r\nHost: rproxy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
	let mut out = String::new();
	let _ = s.read_to_string(&mut out);
	let status = out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
	let body = out.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
	(status, body)
}

async fn api_get(port: u16, path: &str) -> Option<Value> {
	let r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}{path}")).timeout(Duration::from_secs(5)).send().await.ok()?;
	r.json().await.ok()
}

async fn api_text(port: u16, path: &str) -> String {
	let r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}{path}")).send().await.unwrap();
	r.text().await.unwrap()
}

fn metric(text: &str, name: &str) -> Option<String> {
	text.lines().find(|l| l.starts_with(name)).and_then(|l| l.rsplit(' ').next()).map(str::to_string)
}

async fn rule_stats(api: u16, port: u16) -> Value {
	let rules = api_get(api, "/rules").await.unwrap();
	rules.as_array().unwrap().iter().find(|r| r["listen_port"] == port).cloned().unwrap_or(Value::Null)["stats"].clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_connections_survive_and_new_ones_go_to_the_new_process() {
	let dir = workdir("tcp");
	let backend = tcp_backend("B:").await;
	let udp_target = udp_backend("U:").await;
	let (api, static_port, api_port, udp_port) = (free_port(), free_port(), free_port(), free_udp_port());
	let set_port = free_port();
	fs::write(
		dir.join("rproxy.yaml"),
		format!("version: 1\nrules:\n  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {static_port}, remote_addr: 127.0.0.1, remote_port: {}}}\n", backend.port()),
	)
	.unwrap();
	let sock = dir.join("api.sock");
	let mut procs = start(
		&dir,
		&[
			("RPROXY_API_PORT", api.to_string()),
			("RPROXY_API_SOCKET", sock.display().to_string()),
			("RPROXY_HANDOFF_SOCKET", dir.join("handoff.sock").display().to_string()),
			("RPROXY_HANDOFF_DRAIN", "60s".into()),
			("RPROXY_CONFIG", dir.join("rproxy.yaml").display().to_string()),
		],
	);
	let log = procs.log.clone();
	let old = procs.pids[0];
	let deadline = Instant::now() + Duration::from_secs(20);
	while api_get(api, "/capabilities").await.is_none() {
		assert!(Instant::now() < deadline, "API down:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let caps = api_get(api, "/capabilities").await.unwrap();
	assert_eq!((&caps["features"]["handoff"], &caps["features"]["self_update"]), (&json!(true), &json!(true)), "{caps}");
	assert_eq!(caps["build"]["version"], caps["version"], "{caps}");

	// rules made through the API: TCP with targets and allow_from, UDP
	let http = reqwest::Client::new();
	let tcp_rule = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": api_port,
		"targets": [{"addr": "127.0.0.1", "port": backend.port()}], "allow_from": ["127.0.0.0/8"]});
	let r = http.post(format!("http://127.0.0.1:{api}/rules")).json(&tcp_rule).send().await.unwrap();
	assert_eq!(r.status(), 201, "{:?}", r.text().await);
	let r = http.post(format!("http://127.0.0.1:{api}/rules")).json(&rule("udp", udp_port, udp_target)).send().await.unwrap();
	assert_eq!(r.status(), 201);
	// a rule set (#28) goes over as a set
	let set = json!({"generation": 7, "rules": [rule("tcp", set_port, backend)]});
	let r = http.put(format!("http://127.0.0.1:{api}/rulesets/k8s/default/gw")).json(&set).send().await.unwrap();
	assert_eq!(r.status(), 200, "{:?}", r.text().await);
	let set_before = api_get(api, "/rulesets/k8s/default/gw").await.unwrap();
	let before: Vec<Value> = api_get(api, "/rules").await.unwrap().as_array().unwrap().clone();
	let start_time = metric(&api_text(api, "/metrics").await, "rproxy_process_start_time_seconds").unwrap();

	let mut held_static = TcpStream::connect(("127.0.0.1", static_port)).await.unwrap();
	let mut held = TcpStream::connect(("127.0.0.1", api_port)).await.unwrap();
	assert_eq!(roundtrip(&mut held_static, "one").await, "B:one");
	assert_eq!(roundtrip(&mut held, "hello").await, "B:hello");
	let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	udp.connect(("127.0.0.1", udp_port)).await.unwrap();
	assert_eq!(udp_roundtrip(&udp, "ping").await, "U:ping");

	// SIGUSR2: the binary on disk takes over
	signal(old, libc::SIGUSR2);
	let ready = wait_event(&log, "handoff.ready", 1).await;
	let new = ready["pid"].as_i64().unwrap() as i32;
	procs.pids.push(new);
	assert_ne!(new, old);
	let received = wait_event(&log, "handoff.received", 1).await;
	assert!(received["sockets"].as_u64().unwrap() >= 5, "rules, API TCP and Unix socket: {received}");
	wait_event(&log, "handoff.drain", 1).await;
	tokio::time::sleep(Duration::from_millis(300)).await;

	// the old process still carries what it held
	assert_eq!(roundtrip(&mut held_static, "two").await, "B:two");
	assert_eq!(roundtrip(&mut held, "again").await, "B:again");
	assert!(alive(old), "the old process drains");

	// new connections are the new process's
	for port in [static_port, api_port] {
		let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
		assert_eq!(roundtrip(&mut c, "fresh").await, "B:fresh");
		let o = owner(c.local_addr().unwrap(), port, &[old, new]);
		assert_eq!(o, Some(new), "port {port}");
	}
	let held_owner = owner(held.local_addr().unwrap(), api_port, &[old, new]);
	assert_eq!(held_owner, Some(old));

	// UDP goes on (in a new session of the new process; a datagram may be lost)
	let mut answered = false;
	for _ in 0..20 {
		udp.send(b"pong").await.unwrap();
		let mut buf = [0u8; 64];
		if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(500), udp.recv(&mut buf)).await {
			assert_eq!(&buf[..n], b"U:pong");
			answered = true;
			break;
		}
	}
	assert!(answered, "UDP after the handoff");

	// the API (TCP and Unix socket) is the new process's, with the same rules
	let after: Vec<Value> = api_get(api, "/rules").await.unwrap().as_array().unwrap().clone();
	let shape = |v: &Vec<Value>| {
		let mut out: Vec<Value> = v
			.iter()
			.map(|r| json!([r["protocol"], r["listen_port"], r["origin"], r["targets"], r["allow_from"], r["remote_port"]]))
			.collect();
		out.sort_by_key(|v| v.to_string());
		out
	};
	assert_eq!(shape(&after), shape(&before));
	let set_after = api_get(api, "/rulesets/k8s/default/gw").await.unwrap();
	assert_eq!((&set_after["generation"], &set_after["etag"]), (&set_before["generation"], &set_before["etag"]), "{set_after}");
	assert_eq!(after.iter().find(|r| r["listen_port"] == set_port).unwrap()["ruleset"], json!("k8s/default/gw"));
	let mut c = TcpStream::connect(("127.0.0.1", set_port)).await.unwrap();
	assert_eq!(roundtrip(&mut c, "set").await, "B:set");
	drop(c);
	let ready = reqwest::get(format!("http://127.0.0.1:{api}/readyz")).await.unwrap();
	assert_eq!(ready.status(), 200, "the new process is ready");
	let (status, body) = unix_request(&sock, "GET", "/capabilities");
	assert_eq!(status, 200, "{body}");
	assert_eq!(metric(&api_text(api, "/metrics").await, "rproxy_process_start_time_seconds").unwrap(), start_time);

	// the old process ends when its connections do, and its last counts arrive
	drop(held_static);
	drop(held);
	let deadline = Instant::now() + Duration::from_secs(30);
	let status = loop {
		if let Some(s) = procs.first.try_wait().unwrap() {
			break s;
		}
		assert!(Instant::now() < deadline, "the old process did not end:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	};
	assert!(status.success(), "{status:?}");
	wait_event(&log, "handoff.done", 1).await;
	wait_event(&log, "handoff.counters", 1).await;
	// "hello" + "again" through the old process, "fresh" through the new one
	let stats = rule_stats(api, api_port).await;
	assert_eq!((&stats["total_connections"], &stats["rx_bytes"]), (&json!(2), &json!(15)), "{stats}");

	// a second upgrade, through the API on the Unix socket
	let (status, body) = unix_request(&sock, "POST", "/admin/upgrade");
	assert_eq!(status, 202, "{body}");
	let ready = wait_event(&log, "handoff.ready", 2).await;
	let third = ready["pid"].as_i64().unwrap() as i32;
	procs.pids.push(third);
	wait_until("the second process to end", &log, || !alive(new)).await;
	let stats = rule_stats(api, api_port).await;
	assert_eq!(stats["total_connections"], json!(2), "{stats}");
	assert!(sock.exists(), "the socket file stays");
	let mut c = TcpStream::connect(("127.0.0.1", api_port)).await.unwrap();
	assert_eq!(roundtrip(&mut c, "third").await, "B:third");
	drop(c);
	signal(third, libc::SIGTERM);
	wait_until("the last process to stop", &log, || !alive(third)).await;
	assert!(!sock.exists(), "a plain stop removes the socket file");
	drop(procs);
	let _ = fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_handoff_keeps_the_old_process() {
	let dir = workdir("failed");
	let api = free_port();
	let procs = start(
		&dir,
		&[
			("RPROXY_API_PORT", api.to_string()),
			// the new process cannot be reached: the directory does not exist
			("RPROXY_HANDOFF_SOCKET", dir.join("missing/handoff.sock").display().to_string()),
		],
	);
	let log = procs.log.clone();
	let deadline = Instant::now() + Duration::from_secs(20);
	while api_get(api, "/capabilities").await.is_none() {
		assert!(Instant::now() < deadline, "API down:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	// over TCP the strong operation is refused by default
	let r = reqwest::Client::new().post(format!("http://127.0.0.1:{api}/admin/upgrade")).send().await.unwrap();
	assert_eq!(r.status(), 403);

	signal(procs.pids[0], libc::SIGUSR2);
	let failed = wait_event(&log, "handoff.failed", 1).await;
	assert!(failed["error"].as_str().unwrap().contains("handoff socket"), "{failed}");
	assert!(api_get(api, "/capabilities").await.is_some(), "still serving");
	let m = api_text(api, "/metrics").await;
	assert!(m.contains("rproxy_handoffs_total{outcome=\"failed\"} 1"), "{m}");
	assert!(m.contains("rproxy_build_info{version="), "{m}");
	drop(procs);
	let _ = fs::remove_dir_all(dir);
}

/// Rules made by a `persist: true` token come back as `api` rules with who
/// made them and when (#144), without the database; `stats.http` (requests by
/// route) carries over too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_rules_and_http_counters_carry_over() {
	let dir = workdir("api");
	let sha = |s: &str| {
		use sha2::Digest;
		sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>()
	};
	fs::write(
		dir.join("tokens.yaml"),
		format!("tokens:\n  - {{name: ci, sha256: {}, scopes: [rules:read, rules:write, metrics:read, admin], persist: true}}\n", sha("secret")),
	)
	.unwrap();
	let (api, port) = (free_port(), free_port());
	let mut procs = start(
		&dir,
		&[
			("RPROXY_API_PORT", api.to_string()),
			("RPROXY_TOKEN_FILE", dir.join("tokens.yaml").display().to_string()),
			("RPROXY_HANDOFF_SOCKET", dir.join("handoff.sock").display().to_string()),
			("RPROXY_HANDOFF_DRAIN", "10s".into()),
		],
	);
	let log = procs.log.clone();
	let http = reqwest::Client::new();
	let get = |path: String| {
		let http = http.clone();
		async move {
			let r = http.get(format!("http://127.0.0.1:{api}{path}")).bearer_auth("secret").timeout(Duration::from_secs(5)).send().await.ok()?;
			r.json::<Value>().await.ok()
		}
	};
	let deadline = Instant::now() + Duration::from_secs(20);
	while get("/capabilities".into()).await.is_none() {
		assert!(Instant::now() < deadline, "API down:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let rule = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "gone", "match": "PathPrefix(`/`)", "middlewares": ["410"]}],
		"middlewares": {"410": {"respond": {"status": 410}}},
	}});
	let r = http.post(format!("http://127.0.0.1:{api}/rules")).bearer_auth("secret").json(&rule).send().await.unwrap();
	assert_eq!(r.status(), 201, "{:?}", r.text().await);
	let request = || async {
		let c = reqwest::Client::builder().pool_max_idle_per_host(0).build().unwrap();
		c.get(format!("http://127.0.0.1:{port}/x")).send().await.unwrap().status().as_u16()
	};
	for _ in 0..3 {
		assert_eq!(request().await, 410);
	}
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let deadline = Instant::now() + Duration::from_secs(10);
	let before = loop {
		let v = get(path.clone()).await.unwrap();
		if v["stats"]["http"]["requests"] == 3 {
			break v;
		}
		assert!(Instant::now() < deadline, "{v}");
		tokio::time::sleep(Duration::from_millis(50)).await;
	};
	assert_eq!((&before["origin"], &before["created_by"], &before["persisted"]), (&json!("api"), &json!("ci"), &json!(false)), "{before}");

	signal(procs.pids[0], libc::SIGUSR2);
	let ready = wait_event(&log, "handoff.ready", 1).await;
	procs.pids.push(ready["pid"].as_i64().unwrap() as i32);
	wait_event(&log, "handoff.drain", 1).await;
	tokio::time::sleep(Duration::from_millis(300)).await;
	let after = get(path.clone()).await.unwrap();
	for k in ["origin", "created_by", "created_at", "persisted"] {
		assert_eq!(after[k], before[k], "{k}: {after}");
	}
	assert_eq!(after["stats"]["http"]["routes"]["gone"]["requests"], json!(3), "{after}");
	assert_eq!(request().await, 410);
	let deadline = Instant::now() + Duration::from_secs(10);
	loop {
		let v = get(path.clone()).await.unwrap();
		if v["stats"]["http"]["requests"] == 4 && v["stats"]["http"]["by_status"]["4xx"] == 4 {
			break;
		}
		assert!(Instant::now() < deadline, "{v}");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	drop(procs);
	let _ = fs::remove_dir_all(dir);
}
