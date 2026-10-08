//! Abnormal termination: the real binary is killed with SIGKILL (as by the OOM
//! killer or `kill -9`) at random moments, then started again on the same
//! files, as systemd or the launcher would. Nothing written may be half done:
//! stored certificates (`PUT` / `DELETE /certs`), rules and rule sets of
//! `persist: true` tokens in MariaDB, and the startup must not trip over what
//! a killed process left behind (the control API's socket, the handoff socket,
//! temporary files). A kill in the middle of a live upgrade (old process, new
//! process, both) must leave a service that starts again; under traffic the
//! restart comes back with the same rules, and `/readyz` says ready only once
//! they are all back.
//!
//! Every case runs `RPROXY_TEST_CRASH_ROUNDS` rounds (default 3) with random
//! kill times; the manual Crash workflow runs many more. The MariaDB cases run
//! only when RPROXY_TEST_DATABASE_URL points at a scratch database (CI starts
//! one); they use their own node names and leave the tables in place.

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tokio::net::{TcpStream, UdpSocket};

use common::pki::Pki;
use common::*;

/// Rounds per case (`RPROXY_TEST_CRASH_ROUNDS`).
fn rounds() -> usize {
	std::env::var("RPROXY_TEST_CRASH_ROUNDS").ok().and_then(|v| v.parse().ok()).unwrap_or(3)
}

/// A random number in `[lo, hi)`.
fn random(lo: u64, hi: u64) -> u64 {
	let mut b = [0u8; 8];
	ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).unwrap();
	lo + u64::from_le_bytes(b) % (hi - lo).max(1)
}

fn workdir(tag: &str) -> PathBuf {
	// keys and secrets written here must pass the owner check (net::files)
	rproxy_api::net::files::private_umask();
	let dir = std::env::temp_dir().join(format!("rproxy-crash-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn sha(s: &str) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// `ci`: everything, and its rules and sets are stored (with a database).
fn token_file(dir: &Path) {
	fs::write(dir.join("tokens.yaml"), format!("tokens:\n  - {{name: ci, sha256: {}, scopes: [admin], persist: true}}\n", sha("ci"))).unwrap();
}

fn signal(pid: i32, sig: libc::c_int) {
	// SAFETY: a signal to a process this test started
	unsafe { libc::kill(pid, sig) };
}

fn alive(pid: i32) -> bool {
	fs::read_to_string(format!("/proc/{pid}/stat")).map(|s| s.rsplit(')').next().is_some_and(|r| !r.trim_start().starts_with('Z'))).unwrap_or(false)
}

fn children_of(pid: i32) -> Vec<i32> {
	fs::read_dir("/proc")
		.unwrap()
		.flatten()
		.filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()))
		.filter(|p| {
			fs::read_to_string(format!("/proc/{p}/status"))
				.ok()
				.and_then(|s| s.lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|v| v.trim().parse::<i32>().ok()))
				== Some(pid)
		})
		.filter(|p| alive(*p))
		.collect()
}

/// One run of the binary, in a process group of its own: a live upgrade's new
/// process is in it too, and `kill9` takes them all, like systemd's
/// `KillMode=control-group` or the end of a container.
struct Server {
	child: Child,
	log: PathBuf,
	api: u16,
}

impl Server {
	fn start(dir: &Path, tag: &str, api: u16, env: &[(&str, String)]) -> Server {
		let log = dir.join(format!("{tag}.log"));
		let out = fs::File::create(&log).unwrap();
		let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(dir)
			.env_clear()
			.env("RPROXY_API_PORT", api.to_string())
			.env("RPROXY_TOKEN_FILE", dir.join("tokens.yaml"))
			.env("RPROXY_HANDOFF_SOCKET", dir.join("handoff.sock"))
			.env("RPROXY_API_SOCKET", dir.join("api.sock"))
			.env("RPROXY_CERT_STORE", dir.join("certs"))
			.envs(env.iter().map(|(k, v)| (*k, v.as_str())))
			.stdout(out.try_clone().unwrap())
			.stderr(out)
			.stdin(Stdio::null())
			.process_group(0)
			.spawn()
			.unwrap();
		Server { child, log, api }
	}

	fn pid(&self) -> i32 {
		self.child.id() as i32
	}

	fn log(&self) -> String {
		fs::read_to_string(&self.log).unwrap_or_default()
	}

	/// SIGKILL to every process of the group, and wait for this one.
	fn kill9(&mut self) {
		// SAFETY: the process group this test started
		unsafe { libc::killpg(self.pid(), libc::SIGKILL) };
		let _ = self.child.wait();
		// the rest of the group (a new process of a live upgrade) goes with it
		let deadline = Instant::now() + Duration::from_secs(10);
		while group_alive(self.pid()) {
			assert!(Instant::now() < deadline, "the process group did not stop");
			std::thread::sleep(Duration::from_millis(20));
		}
	}

	/// Waits for `GET /readyz` 200.
	async fn ready(&self) {
		let client = reqwest::Client::new();
		let deadline = Instant::now() + Duration::from_secs(30);
		loop {
			let r = client.get(format!("http://127.0.0.1:{}/readyz", self.api)).timeout(Duration::from_secs(2)).send().await;
			if r.is_ok_and(|r| r.status() == StatusCode::OK) {
				return;
			}
			assert!(Instant::now() < deadline, "not ready:\n{}", self.log());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}

	async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<(StatusCode, Value), reqwest::Error> {
		let mut req = reqwest::Client::new()
			.request(method, format!("http://127.0.0.1:{}{path}", self.api))
			.bearer_auth("ci")
			.timeout(Duration::from_secs(10));
		if let Some(b) = body {
			req = req.json(&b);
		}
		let r = req.send().await?;
		let status = r.status();
		Ok((status, r.json().await.unwrap_or(Value::Null)))
	}

	async fn get(&self, path: &str) -> (StatusCode, Value) {
		self.call(Method::GET, path, None).await.unwrap_or_else(|e| panic!("GET {path}: {e}\n{}", self.log()))
	}

	/// The startup reported nothing broken.
	fn assert_clean_start(&self) {
		let log = self.log();
		for line in log.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()) {
			assert!(line["event"] != "fatal", "{line}\n{log}");
			assert!(
				!(line["event"] == "degraded" && ["api_socket", "cert_store", "api"].contains(&line["part"].as_str().unwrap_or(""))),
				"{line}\n{log}"
			);
		}
	}
}

impl Drop for Server {
	fn drop(&mut self) {
		// SAFETY: the process group this test started
		unsafe { libc::killpg(self.pid(), libc::SIGKILL) };
		let _ = self.child.wait();
	}
}

/// Whether a process of the group `pgid` is still there.
fn group_alive(pgid: i32) -> bool {
	fs::read_dir("/proc").unwrap().flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<i32>().ok())).any(|p| {
		fs::read_to_string(format!("/proc/{p}/stat"))
			.ok()
			.and_then(|s| {
				let rest = s.rsplit_once(')')?.1.split_whitespace().collect::<Vec<_>>();
				// state, ppid, pgrp
				(rest.first()? != &"Z").then(|| rest.get(2)?.parse::<i32>().ok()).flatten()
			})
			== Some(pgid)
	})
}

/// `GET /rules` without what changes on its own (counters, open connections,
/// conditions' times, when the rule started), in a stable order.
fn normalised(rules: &Value) -> Vec<Value> {
	let mut out: Vec<Value> = rules
		.as_array()
		.unwrap()
		.iter()
		.map(|r| {
			let mut r = r.clone();
			let o = r.as_object_mut().unwrap();
			for k in ["stats", "connections", "conditions", "cert_status", "started_at"] {
				o.remove(k);
			}
			r
		})
		.collect();
	out.sort_by_key(|r| (r["protocol"].to_string(), r["listen_port"].as_u64()));
	out
}

/// A TLS client for a rule terminating with a certificate for `name`; the
/// fingerprint of what it served.
async fn served(pki: &Pki, port: u16, name: &str) -> String {
	use sha2::Digest;
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let s = pki.connector(None).connect(name.to_string().try_into().unwrap(), tcp).await.unwrap();
	let leaf = s.get_ref().1.peer_certificates().unwrap()[0].clone();
	sha2::Sha256::digest(leaf.as_ref()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Every certificate on disk loads with its key: `<store>/<name>/current/{tls.crt,tls.key}`.
fn check_store_on_disk(store: &Path) -> Vec<String> {
	let mut names = vec![];
	for e in fs::read_dir(store).unwrap().flatten() {
		let name = e.file_name().to_string_lossy().into_owned();
		assert!(!name.starts_with(".removing-"), "a removal set aside was not cleaned up: {name}");
		if name.starts_with('.') {
			continue;
		}
		let current = e.path().join("current");
		if !current.exists() {
			// killed during its first PUT: not a certificate (GET says 404)
			continue;
		}
		let (cert, key) = (current.join("tls.crt"), current.join("tls.key"));
		rproxy_api::tls::config::KeyedCert::load(cert.to_str().unwrap(), None, key.to_str().unwrap())
			.unwrap_or_else(|e| panic!("{name}: the stored pair does not load: {}", e.message));
		names.push(name);
	}
	names.sort();
	names
}

/// `PUT` / `DELETE /certs` from several writers while the process is killed:
/// after the restart every stored certificate is one that was sent, whole,
/// with its own key; a rule using one starts with it; nothing a removal set
/// aside is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stored_certificates_survive_kills_during_writes() {
	let dir = workdir("certs");
	token_file(&dir);
	let pki = Pki::new("crash-certs");
	let names = ["web", "api", "spare"];
	// two versions of each name
	let versions: Vec<Vec<(Value, String)>> = names
		.iter()
		.map(|n| {
			(0..2)
				.map(|i| {
					let issued = pki.server(&format!("{n}{i}.pem"), &[&format!("{n}.test")]);
					let body = json!({"cert": issued.cert.pem(), "key": issued.key.serialize_pem()});
					let print = {
						use sha2::Digest;
						sha2::Sha256::digest(issued.der().as_ref()).iter().map(|b| format!("{b:02x}")).collect::<String>()
					};
					(body, print)
				})
				.collect()
		})
		.collect();
	let versions = Arc::new(versions);
	let backend = tcp_backend("C:").await;
	let tls_port = free_port();
	let mut tls_rule = rule("tcp", tls_port, backend);
	tls_rule["tls"] = json!({"mode": "terminate", "certificates": [{"cert": "web"}]});
	fs::write(dir.join("rules.yaml"), json!({"version": 1, "rules": [tls_rule]}).to_string()).unwrap();
	let env = [("RPROXY_CONFIG", dir.join("rules.yaml").display().to_string())];
	let api = free_port();

	// "web" exists before the first kill (the rule uses it, so it is never deleted)
	{
		let s = Server::start(&dir, "setup", api, &env);
		s.ready().await;
		let (status, v) = s.call(Method::PUT, "/certs/web", Some(versions[0][0].0.clone())).await.unwrap();
		assert!(status.is_success(), "{v}\n{}", s.log());
	}
	for round in 0..rounds() {
		let mut s = Server::start(&dir, &format!("round{round}"), api, &env);
		s.ready().await;
		s.assert_clean_start();
		let stop = Arc::new(AtomicBool::new(false));
		let done = Arc::new(AtomicU64::new(0));
		let mut writers = vec![];
		for w in 0..4u64 {
			let (stop, done, versions, port) = (stop.clone(), done.clone(), versions.clone(), api);
			writers.push(tokio::spawn(async move {
				let client = reqwest::Client::new();
				let mut i = w;
				while !stop.load(Ordering::Relaxed) {
					i += 1;
					let n = (i % 3) as usize;
					let url = format!("http://127.0.0.1:{port}/certs/{}", names[n]);
					// "spare" is also deleted; the others only replaced
					let req = if n == 2 && i % 2 == 0 {
						client.delete(url)
					} else {
						client.put(url).json(&versions[n][(i / 3 % 2) as usize].0)
					};
					match req.bearer_auth("ci").timeout(Duration::from_secs(5)).send().await {
						Ok(_) => {
							done.fetch_add(1, Ordering::Relaxed);
						}
						Err(_) => return,
					}
				}
			}));
		}
		tokio::time::sleep(Duration::from_millis(random(20, 400))).await;
		s.kill9();
		stop.store(true, Ordering::Relaxed);
		for w in writers {
			let _ = w.await;
		}
		assert!(done.load(Ordering::Relaxed) > 0, "no write got through before the kill:\n{}", s.log());
		drop(s);

		let s = Server::start(&dir, &format!("after{round}"), api, &env);
		s.ready().await;
		s.assert_clean_start();
		let on_disk = check_store_on_disk(&dir.join("certs"));
		let (status, listed) = s.get("/certs").await;
		assert_eq!(status, StatusCode::OK, "{listed}");
		let listed: Vec<String> = listed.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap().to_string()).collect();
		assert_eq!(listed, on_disk, "GET /certs and the store's files");
		assert!(listed.contains(&"web".to_string()), "{listed:?}");
		for (n, name) in names.iter().enumerate() {
			let (status, v) = s.get(&format!("/certs/{name}")).await;
			if status == StatusCode::NOT_FOUND {
				assert!(!listed.contains(&name.to_string()));
				continue;
			}
			let print = v["fingerprint_sha256"].as_str().unwrap().to_string();
			assert!(versions[n].iter().any(|(_, p)| *p == print), "{name}: {v} is not one that was sent");
		}
		// the rule came back with a certificate that was sent for "web"
		let (_, view) = s.get(&format!("/rules/tcp/127.0.0.1/{tls_port}")).await;
		assert_eq!(view["state"], "running", "{view}\n{}", s.log());
		let print = served(&pki, tls_port, "web.test").await;
		assert!(versions[0].iter().any(|(_, p)| *p == print), "served {print}");
	}
	let _ = fs::remove_dir_all(&dir);
}

/// What a killed process left behind does not stop the next start: the
/// control API's Unix socket and the handoff socket (files without a process),
/// temporary files and a half-made certificate in the store, a removal set
/// aside.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leftovers_of_a_killed_process_do_not_stop_the_startup() {
	let dir = workdir("leftovers");
	token_file(&dir);
	let api = free_port();
	let pki = Pki::new("crash-left");
	let issued = pki.server("left.pem", &["left.test"]);
	// a real run stores a certificate and is killed
	{
		let mut s = Server::start(&dir, "first", api, &[]);
		s.ready().await;
		let (status, _) = s.call(Method::PUT, "/certs/left", Some(json!({"cert": issued.cert.pem(), "key": issued.key.serialize_pem()}))).await.unwrap();
		assert!(status.is_success());
		s.kill9();
		assert!(dir.join("api.sock").exists(), "the killed process left its socket");
	}
	// what a kill at other moments leaves
	let store = dir.join("certs");
	let version = fs::read_link(store.join("left/current")).unwrap();
	fs::write(store.join("left").join(&version).join("tls.tmp"), "half a key").unwrap();
	fs::write(store.join("left/meta.tmp"), "{").unwrap();
	std::os::unix::fs::symlink("0123456789abcdef", store.join("left/current.tmp")).unwrap();
	fs::create_dir_all(store.join("half/0123456789abcdef")).unwrap();
	fs::write(store.join("half/0123456789abcdef/tls.crt"), "-----BEGIN CERTIFICATE-----\nAAAA").unwrap();
	fs::create_dir_all(store.join(".removing-old-424242/0123456789abcdef")).unwrap();
	fs::write(store.join(".probe-424242"), "").unwrap();
	drop(std::os::unix::net::UnixListener::bind(dir.join("handoff.sock")).unwrap());

	let s = Server::start(&dir, "second", api, &[]);
	s.ready().await;
	s.assert_clean_start();
	let (_, listed) = s.get("/certs").await;
	let listed: Vec<&str> = listed.as_array().unwrap().iter().map(|c| c["name"].as_str().unwrap()).collect();
	assert_eq!(listed, ["left"], "only the whole certificate");
	assert!(!store.join(".removing-old-424242").exists(), "a removal set aside is cleaned up");
	// the control API is on the Unix socket again
	let mut sock = std::os::unix::net::UnixStream::connect(dir.join("api.sock")).unwrap();
	{
		use std::io::{Read, Write};
		sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
		write!(sock, "GET /readyz HTTP/1.1\r\nHost: rproxy\r\nConnection: close\r\n\r\n").unwrap();
		let mut out = String::new();
		let _ = sock.read_to_string(&mut out);
		assert!(out.starts_with("HTTP/1.1 200"), "{out}");
	}
	// a live upgrade still works with the stale handoff socket file
	signal(s.pid(), libc::SIGUSR2);
	let deadline = Instant::now() + Duration::from_secs(30);
	while !s.log().contains("\"handoff.ready\"") {
		assert!(!s.log().contains("\"handoff.failed\""), "{}", s.log());
		assert!(Instant::now() < deadline, "no handoff:\n{}", s.log());
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	drop(s);
	let _ = fs::remove_dir_all(&dir);
}

/// An HTTP backend answering `ok`.
async fn http_backend() -> std::net::SocketAddr {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let app = axum::Router::new().fallback(|| async { "ok" });
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

async fn tcp_once(port: u16) -> bool {
	let Ok(Ok(mut s)) = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(("127.0.0.1", port))).await else { return false };
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	if s.write_all(b"ping").await.is_err() {
		return false;
	}
	let mut buf = [0u8; 64];
	matches!(tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await, Ok(Ok(n)) if n > 0)
}

async fn udp_once(port: u16) -> bool {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(("127.0.0.1", port)).await.unwrap();
	if sock.send(b"ping").await.is_err() {
		return false;
	}
	let mut buf = [0u8; 64];
	matches!(tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await, Ok(Ok(n)) if n > 0)
}

async fn http_once(client: &reqwest::Client, port: u16) -> bool {
	matches!(client.get(format!("http://127.0.0.1:{port}/x")).timeout(Duration::from_secs(2)).send().await, Ok(r) if r.status() == StatusCode::OK)
}

/// Killed under TCP, UDP and HTTP traffic: the restart comes back with the
/// same rules, `/readyz` is 200 only once all of them are there, traffic flows
/// again, and the counters start from zero (`counters_since` is the new start).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_kill_under_traffic_comes_back_with_the_same_rules() {
	let dir = workdir("traffic");
	token_file(&dir);
	let (tcp_b, udp_b, http_b) = (tcp_backend("T:").await, udp_backend("U:").await, http_backend().await);
	let (tcp_p, udp_p, http_p) = (free_port(), free_udp_port(), free_port());
	let rules = json!({"version": 1, "rules": [
		rule("tcp", tcp_p, tcp_b),
		rule("udp", udp_p, udp_b),
		{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": http_p, "http": {
			"routes": [{"name": "app", "match": "PathPrefix(`/`)", "service": "app"}],
			"services": {"app": {"servers": [{"url": format!("http://{http_b}")}]}}
		}},
	]});
	fs::write(dir.join("rules.yaml"), rules.to_string()).unwrap();
	let env = [("RPROXY_CONFIG", dir.join("rules.yaml").display().to_string())];
	let api = free_port();
	let mut before = None;
	for round in 0..rounds() {
		let mut s = Server::start(&dir, &format!("round{round}"), api, &env);
		// the first 200 of /readyz: every rule is there already
		let client = reqwest::Client::new();
		let deadline = Instant::now() + Duration::from_secs(30);
		loop {
			let r = client.get(format!("http://127.0.0.1:{api}/readyz")).timeout(Duration::from_secs(2)).send().await;
			if r.is_ok_and(|r| r.status() == StatusCode::OK) {
				break;
			}
			assert!(Instant::now() < deadline, "not ready:\n{}", s.log());
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
		let started = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
		let (_, now) = s.get("/rules").await;
		let now_rules = normalised(&now);
		assert_eq!(now_rules.len(), 3, "{now}");
		match &before {
			None => before = Some(now_rules),
			Some(b) => assert_eq!(&now_rules, b, "the rules after the restart"),
		}
		// the counters started over
		for r in now.as_array().unwrap() {
			let since = r["stats"]["counters_since"].as_u64().unwrap_or(0);
			assert!(since + 30 >= started, "counters_since {since} is from before the restart: {r}");
		}
		assert!(tcp_once(tcp_p).await && udp_once(udp_p).await && http_once(&client, http_p).await, "traffic after the start:\n{}", s.log());

		// traffic on all three, killed at a random moment
		let stop = Arc::new(AtomicBool::new(false));
		let mut load = vec![];
		for kind in 0..3 {
			let stop = stop.clone();
			load.push(tokio::spawn(async move {
				let client = reqwest::Client::new();
				let mut ok = 0u64;
				while !stop.load(Ordering::Relaxed) {
					let good = match kind {
						0 => tcp_once(tcp_p).await,
						1 => udp_once(udp_p).await,
						_ => http_once(&client, http_p).await,
					};
					ok += good as u64;
					if !good {
						tokio::time::sleep(Duration::from_millis(10)).await;
					}
				}
				ok
			}));
		}
		tokio::time::sleep(Duration::from_millis(random(100, 1000))).await;
		s.kill9();
		stop.store(true, Ordering::Relaxed);
		for l in load {
			l.await.unwrap();
		}
	}
	let _ = fs::remove_dir_all(&dir);
}

/// Where in a live upgrade the kill comes: at once, or right after one of these
/// (the old process's and the new one's log lines).
const PHASES: [&str; 6] = ["", "handoff.start", "handoff.received", "handoff.sent", "restore.start", "handoff.ready"];

/// Kills during a live upgrade (SIGUSR2) at random moments: the old process,
/// the new one, or both. A new process killed before it is ready leaves the
/// old one serving; whatever is left, the service starts again on the same
/// files with every listener (the control API on TCP and on its socket, the
/// rules).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kills_during_a_live_upgrade_leave_a_service_that_starts_again() {
	let dir = workdir("handoff");
	token_file(&dir);
	let backend = tcp_backend("H:").await;
	let port = free_port();
	fs::write(dir.join("rules.yaml"), json!({"version": 1, "rules": [rule("tcp", port, backend)]}).to_string()).unwrap();
	let env = [
		("RPROXY_CONFIG", dir.join("rules.yaml").display().to_string()),
		("RPROXY_HANDOFF_TIMEOUT", "5s".into()),
		("RPROXY_HANDOFF_DRAIN", "1s".into()),
	];
	let api = free_port();
	for round in 0..rounds() * 2 {
		let mut s = Server::start(&dir, &format!("round{round}"), api, &env);
		s.ready().await;
		s.assert_clean_start();
		assert!(tcp_once(port).await, "{}", s.log());
		// a connection the old process holds: it drains (up to RPROXY_HANDOFF_DRAIN)
		// instead of ending at once
		let held = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
		let old = s.pid();
		// 0: the old process, 1: the new one, 2: both; right after a phase of the
		// handoff (or at once), plus a little
		let which = round % 3;
		let phase = PHASES[(round / 3 + random(0, PHASES.len() as u64) as usize) % PHASES.len()];
		signal(old, libc::SIGUSR2);
		let deadline = Instant::now() + Duration::from_secs(20);
		while !phase.is_empty() && !s.log().contains(&format!("\"event\":\"{phase}\"")) {
			assert!(Instant::now() < deadline, "no {phase}:\n{}", s.log());
			std::thread::sleep(Duration::from_micros(500));
		}
		std::thread::sleep(Duration::from_micros(random(0, 5000)));
		let new = children_of(old);
		match which {
			0 => signal(old, libc::SIGKILL),
			1 => new.iter().for_each(|p| signal(*p, libc::SIGKILL)),
			_ => {
				signal(old, libc::SIGKILL);
				new.iter().for_each(|p| signal(*p, libc::SIGKILL));
			}
		}
		eprintln!("round {round}: killed {} after {:?} ({} new process)", ["the old process", "the new process", "both"][which], phase, new.len());
		if which == 1 && alive(old) {
			// the old process goes on, or drains when the new one was ready already
			let deadline = Instant::now() + Duration::from_secs(15);
			loop {
				let log = s.log();
				if log.contains("\"handoff.failed\"") {
					// it serves as before, changes included
					assert!(tcp_once(port).await, "{log}");
					let (status, v) = s.call(Method::POST, "/rules?dry_run=true", Some(rule("tcp", free_port(), backend))).await.unwrap();
					assert_eq!(status, StatusCode::OK, "{v}\n{log}");
					break;
				}
				if log.contains("\"handoff.drain\"") || !alive(old) {
					break;
				}
				assert!(Instant::now() < deadline, "the old process neither failed the handoff nor drained:\n{log}");
				tokio::time::sleep(Duration::from_millis(50)).await;
			}
		}
		if which == 0 {
			// a new process left alone either took over or stops by itself (it does not hang)
			let deadline = Instant::now() + Duration::from_secs(15);
			for p in &new {
				while alive(*p) {
					let r = reqwest::Client::new().get(format!("http://127.0.0.1:{api}/readyz")).timeout(Duration::from_secs(1)).send().await;
					if r.is_ok_and(|r| r.status() == StatusCode::OK) && s.log().contains("\"handoff.ready\"") {
						break;
					}
					assert!(Instant::now() < deadline, "the new process neither took over nor stopped:\n{}", s.log());
					tokio::time::sleep(Duration::from_millis(50)).await;
				}
			}
		}
		// the service manager restarts the service
		drop(held);
		s.kill9();
		drop(s);
		let s = Server::start(&dir, &format!("after{round}"), api, &env);
		s.ready().await;
		s.assert_clean_start();
		assert!(tcp_once(port).await, "the rule after the restart:\n{}", s.log());
		let (_, rules) = s.get("/rules").await;
		assert_eq!(rules.as_array().unwrap().len(), 1, "{rules}");
		assert!(std::os::unix::net::UnixStream::connect(dir.join("api.sock")).is_ok(), "the control API's socket");
	}
	let _ = fs::remove_dir_all(&dir);
}

async fn database() -> Option<(String, sqlx::MySqlPool)> {
	use sqlx::Executor;
	let url = std::env::var("RPROXY_TEST_DATABASE_URL").ok()?;
	let pool = sqlx::mysql::MySqlPoolOptions::new().max_connections(2).connect(&url).await.unwrap();
	// the DDL in docs/API.md; other test binaries drop and create them, one binary at a time
	pool.execute(
		"CREATE TABLE IF NOT EXISTS forward_rules (
			id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, auth_id VARCHAR(255) NOT NULL, protocol VARCHAR(3) NOT NULL,
			src_addr VARCHAR(45) NOT NULL, src_port INT NOT NULL, src_port_end INT NULL, dist_addr VARCHAR(253) NOT NULL,
			dist_port INT NOT NULL, source_ip VARCHAR(16) NOT NULL DEFAULT 'proxy', udp_idle_secs INT NOT NULL DEFAULT 30, options JSON NULL)",
	)
	.await
	.unwrap();
	pool.execute(
		"CREATE TABLE IF NOT EXISTS rproxy_rules (
			node VARCHAR(255) NOT NULL, protocol VARCHAR(3) NOT NULL, listen_addr VARCHAR(45) NOT NULL, listen_port INT UNSIGNED NOT NULL,
			spec JSON NOT NULL, spec_version INT UNSIGNED NOT NULL DEFAULT 1, created_by VARCHAR(255) NOT NULL, created_at DATETIME(3) NOT NULL,
			updated_by VARCHAR(255) NOT NULL, updated_at DATETIME(3) NOT NULL, PRIMARY KEY (node, protocol, listen_addr, listen_port))",
	)
	.await
	.unwrap();
	pool.execute(
		"CREATE TABLE IF NOT EXISTS rproxy_rule_sets (
			node VARCHAR(255) NOT NULL, name VARCHAR(253) NOT NULL, generation BIGINT UNSIGNED NOT NULL, etag VARCHAR(64) NOT NULL,
			owner VARCHAR(255) NOT NULL, rules JSON NOT NULL, spec_version INT UNSIGNED NOT NULL DEFAULT 1, updated_by VARCHAR(255) NOT NULL,
			updated_at DATETIME(3) NOT NULL, PRIMARY KEY (node, name)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
	)
	.await
	.unwrap();
	Some((url, pool))
}

/// A rule's state as the test knows it: its `udp_idle_secs`, or absent.
type RuleState = Option<u64>;

/// What one writer knows of its rule: the last answered change, and the one
/// sent when the process was killed (it may or may not have been written).
#[derive(Debug, Default)]
struct Known {
	acked: RuleState,
	inflight: Option<RuleState>,
}

/// Rules of a `persist: true` token are created, changed and deleted by
/// several writers while the process is killed: after the restart each rule
/// is as the last answered change left it, or as the change sent at the kill.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stored_rules_survive_kills_with_mariadb() {
	let Some((url, pool)) = database().await else {
		eprintln!("skipping: RPROXY_TEST_DATABASE_URL is not set");
		return;
	};
	let node = format!("crash-rules-{}", std::process::id());
	sqlx::query("DELETE FROM rproxy_rules WHERE node = ?").bind(&node).execute(&pool).await.unwrap();
	let dir = workdir("db-rules");
	token_file(&dir);
	let backend = tcp_backend("D:").await;
	let ports: Vec<u16> = (0..6).map(|_| free_port()).collect();
	let env = [("RPROXY_DATABASE_URL", url.clone()), ("RPROXY_NODE_NAME", node.clone())];
	let api = free_port();
	let mut known: Vec<Known> = ports.iter().map(|_| Known::default()).collect();
	// udp_idle_secs (1-86400) tells the changes apart: a range per round and writer
	let mut step = 0u64;
	for round in 0..rounds() {
		let mut s = Server::start(&dir, &format!("round{round}"), api, &env);
		s.ready().await;
		s.assert_clean_start();
		let mut writers = vec![];
		for (i, &port) in ports.iter().enumerate() {
			let mut k = Known { acked: known[i].acked, inflight: None };
			let base = step + i as u64 * 3000;
			writers.push(tokio::spawn(async move {
				let client = reqwest::Client::new();
				let path = format!("http://127.0.0.1:{api}/rules/tcp/127.0.0.1/{port}");
				let mut n = 0;
				loop {
					n += 1;
					let idle = 1 + (base + n) % 86_000;
					let (req, target) = match k.acked {
						None => {
							let mut body = rule("tcp", port, backend);
							body["udp_idle_secs"] = json!(idle);
							(client.post(format!("http://127.0.0.1:{api}/rules")).json(&body), Some(idle))
						}
						Some(_) if n % 3 == 2 => (client.delete(&path), None),
						Some(_) => (
							client.patch(&path).json(&json!({"remote_addr": "127.0.0.1", "remote_port": backend.port(), "udp_idle_secs": idle})),
							Some(idle),
						),
					};
					k.inflight = Some(target);
					match req.bearer_auth("ci").timeout(Duration::from_secs(10)).send().await {
						Ok(r) if r.status().is_success() => {
							let v: Value = r.json().await.unwrap_or(Value::Null);
							if target.is_some() {
								assert_eq!(v["persisted"], true, "{v}");
							}
							k.acked = target;
							k.inflight = None;
						}
						// the answer was cut off by the kill
						Ok(r) if r.status().is_server_error() => return k,
						Ok(r) => panic!("{} {}", r.status(), r.text().await.unwrap_or_default()),
						Err(_) => return k,
					}
				}
			}));
		}
		tokio::time::sleep(Duration::from_millis(random(100, 800))).await;
		s.kill9();
		for (i, w) in writers.into_iter().enumerate() {
			known[i] = w.await.unwrap();
		}
		step += 20_000;
		drop(s);

		let s = Server::start(&dir, &format!("after{round}"), api, &env);
		s.ready().await;
		s.assert_clean_start();
		for (i, &port) in ports.iter().enumerate() {
			let (status, v) = s.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
			let got: RuleState = match status {
				StatusCode::NOT_FOUND => None,
				StatusCode::OK => {
					assert_eq!((&v["origin"], &v["persisted"], &v["state"]), (&json!("api"), &json!(true), &json!("running")), "{v}");
					v["udp_idle_secs"].as_u64()
				}
				other => panic!("{other}: {v}"),
			};
			let k = &known[i];
			assert!(got == k.acked || Some(got) == k.inflight, "port {port}: {got:?}, but the last answer left {:?} (sent at the kill: {:?})\n{}", k.acked, k.inflight, s.log());
			// what is there now is what the next round starts from
			known[i] = Known { acked: got, inflight: None };
		}
		// the restored rules are exactly the stored rows
		let rows: Vec<(u32, String)> = sqlx::query_as("SELECT listen_port, CAST(spec AS CHAR) FROM rproxy_rules WHERE node = ?").bind(&node).fetch_all(&pool).await.unwrap();
		for (port, spec) in &rows {
			let spec: Value = serde_json::from_str(spec).unwrap();
			let i = ports.iter().position(|p| u32::from(*p) == *port).unwrap();
			assert_eq!(spec["udp_idle_secs"].as_u64(), known[i].acked, "row of {port}: {spec}");
		}
		assert_eq!(rows.len(), known.iter().filter(|k| k.acked.is_some()).count());
	}
	sqlx::query("DELETE FROM rproxy_rules WHERE node = ?").bind(&node).execute(&pool).await.unwrap();
	let _ = fs::remove_dir_all(&dir);
}

/// A rule set of a `persist: true` token is `PUT` with growing generations
/// while the process is killed: after the restart it has the last answered
/// generation (or the one sent at the kill), with exactly that generation's
/// rules.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stored_rule_sets_survive_kills_with_mariadb() {
	let Some((url, pool)) = database().await else {
		eprintln!("skipping: RPROXY_TEST_DATABASE_URL is not set");
		return;
	};
	let node = format!("crash-sets-{}", std::process::id());
	sqlx::query("DELETE FROM rproxy_rule_sets WHERE node = ?").bind(&node).execute(&pool).await.unwrap();
	let dir = workdir("db-sets");
	token_file(&dir);
	let backend = tcp_backend("S:").await;
	let ports: Arc<Vec<u16>> = Arc::new((0..4).map(|_| free_port()).collect());
	// generation g holds the first g % 4 + 1 ports
	let of = |g: u64, ports: &[u16]| -> Vec<u16> { ports[..(g % 4 + 1) as usize].to_vec() };
	let env = [("RPROXY_DATABASE_URL", url.clone()), ("RPROXY_NODE_NAME", node.clone())];
	let api = free_port();
	let (mut acked, mut generation) = (0u64, 0u64);
	for round in 0..rounds() {
		let mut s = Server::start(&dir, &format!("round{round}"), api, &env);
		s.ready().await;
		s.assert_clean_start();
		let ports2 = ports.clone();
		let writer = tokio::spawn(async move {
			let client = reqwest::Client::new();
			let (mut acked, mut g) = (acked, generation);
			loop {
				g += 1;
				let rules: Vec<Value> = of(g, &ports2).into_iter().map(|p| rule("tcp", p, backend)).collect();
				let r = client
					.put(format!("http://127.0.0.1:{api}/rulesets/ci/crash"))
					.bearer_auth("ci")
					.json(&json!({"generation": g, "rules": rules}))
					.timeout(Duration::from_secs(10))
					.send()
					.await;
				match r {
					Ok(r) if r.status().is_success() => {
						let v: Value = r.json().await.unwrap_or(Value::Null);
						assert_eq!(v["persisted"], true, "{v}");
						acked = g;
					}
					Ok(r) if r.status().is_server_error() => return (acked, g),
					Ok(r) => panic!("{} {}", r.status(), r.text().await.unwrap_or_default()),
					Err(_) => return (acked, g),
				}
			}
		});
		tokio::time::sleep(Duration::from_millis(random(100, 800))).await;
		s.kill9();
		let (a, sent) = writer.await.unwrap();
		drop(s);

		let s = Server::start(&dir, &format!("after{round}"), api, &env);
		s.ready().await;
		s.assert_clean_start();
		let (status, v) = s.get("/rulesets/ci/crash").await;
		let got = match status {
			StatusCode::OK => v["generation"].as_u64().unwrap(),
			StatusCode::NOT_FOUND => 0,
			other => panic!("{other}: {v}"),
		};
		assert!(got == a || got == sent, "generation {got}, but the last answer was {a} (sent at the kill: {sent})\n{v}");
		if got > 0 {
			assert_eq!(v["persisted"], true, "{v}");
		}
		let want = if got == 0 { vec![] } else { of(got, &ports) };
		for &p in ports.iter() {
			let (status, view) = s.get(&format!("/rules/tcp/127.0.0.1/{p}")).await;
			assert_eq!(status == StatusCode::OK, want.contains(&p), "port {p} in generation {got}: {view}");
			if status == StatusCode::OK {
				assert_eq!((&view["ruleset"], &view["state"]), (&json!("ci/crash"), &json!("running")), "{view}");
			}
		}
		(acked, generation) = (got, sent.max(got));
	}
	let _ = acked;
	sqlx::query("DELETE FROM rproxy_rule_sets WHERE node = ?").bind(&node).execute(&pool).await.unwrap();
	let _ = fs::remove_dir_all(&dir);
}
