//! Shutting down on SIGTERM (docs/DESIGN-v0.4.x.md 2.) with the real binary:
//! by default rproxy stops at once; with `RPROXY_SHUTDOWN_DELAY` it keeps
//! accepting while `/readyz` says draining, then with `RPROXY_SHUTDOWN_DRAIN`
//! it closes the listeners and lets connections end. A second SIGTERM stops
//! at once.

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use common::*;

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-shutdown-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

struct Proc {
	child: Child,
	log: PathBuf,
	dir: PathBuf,
}

impl Drop for Proc {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
		let _ = fs::remove_dir_all(&self.dir);
	}
}

impl Proc {
	fn term(&self) {
		// SAFETY: a signal to a process this test started
		unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
	}

	/// Waits for the process to exit; how long it took.
	async fn exited_within(&mut self, limit: Duration) -> Duration {
		let start = Instant::now();
		loop {
			if self.child.try_wait().unwrap().is_some() {
				return start.elapsed();
			}
			assert!(start.elapsed() < limit, "still running after {limit:?}; log:\n{}", self.log_text());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}

	fn log_text(&self) -> String {
		fs::read_to_string(&self.log).unwrap_or_default()
	}

	fn events(&self, event: &str) -> Vec<Value> {
		self.log_text().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|l| l["event"] == event).collect()
	}

	async fn wait_event(&self, event: &str) -> Value {
		let deadline = Instant::now() + Duration::from_secs(20);
		loop {
			if let Some(v) = self.events(event).into_iter().next() {
				return v;
			}
			assert!(Instant::now() < deadline, "no {event}; log:\n{}", self.log_text());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}
}

async fn start(tag: &str, env: &[(&str, &str)]) -> (Proc, u16) {
	let dir = workdir(tag);
	let api = free_port();
	let log = dir.join("out.log");
	let out = fs::File::create(&log).unwrap();
	let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.current_dir(&dir)
		.env_clear()
		.env("RPROXY_API_PORT", api.to_string())
		.envs(env.iter().copied())
		.stdout(out.try_clone().unwrap())
		.stderr(out)
		.stdin(Stdio::null())
		.spawn()
		.unwrap();
	let p = Proc { child, log, dir };
	let deadline = Instant::now() + Duration::from_secs(20);
	while api_get(api, "/readyz").await.0 != 200 {
		assert!(Instant::now() < deadline, "not ready:\n{}", p.log_text());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	(p, api)
}

async fn api_get(port: u16, path: &str) -> (u16, Value) {
	match reqwest::Client::new().get(format!("http://127.0.0.1:{port}{path}")).timeout(Duration::from_secs(5)).send().await {
		Ok(r) => (r.status().as_u16(), r.json().await.unwrap_or(Value::Null)),
		Err(_) => (0, Value::Null),
	}
}

async fn api_post(port: u16, body: Value) -> (u16, Value) {
	let r = reqwest::Client::new().post(format!("http://127.0.0.1:{port}/rules")).json(&body).send().await.unwrap();
	(r.status().as_u16(), r.json().await.unwrap_or(Value::Null))
}

/// An HTTP/1.1 backend that answers `/slow` after four seconds, anything else at once.
async fn http_backend() -> std::net::SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let mut buf = vec![0u8; 4096];
				let mut have = 0;
				loop {
					let Ok(n) = s.read(&mut buf[have..]).await else { return };
					if n == 0 {
						return;
					}
					have += n;
					let Some(end) = buf[..have].windows(4).position(|w| w == b"\r\n\r\n") else { continue };
					let head = String::from_utf8_lossy(&buf[..end]).into_owned();
					buf.copy_within(end + 4..have, 0);
					have -= end + 4;
					if head.starts_with("GET /slow") {
						tokio::time::sleep(Duration::from_secs(4)).await;
					}
					if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.is_err() {
						return;
					}
				}
			});
		}
	});
	addr
}

/// Sends one request on a kept-alive HTTP/1.1 connection; the response head (lower case) and body.
async fn http_request(s: &mut TcpStream, path: &str) -> Option<(String, String)> {
	s.write_all(format!("GET {path} HTTP/1.1\r\nHost: t\r\n\r\n").as_bytes()).await.ok()?;
	let mut buf = vec![];
	let mut chunk = [0u8; 1024];
	loop {
		let n = tokio::time::timeout(Duration::from_secs(10), s.read(&mut chunk)).await.ok()?.ok()?;
		if n == 0 {
			return None;
		}
		buf.extend_from_slice(&chunk[..n]);
		let text = String::from_utf8_lossy(&buf).into_owned();
		if let Some((head, body)) = text.split_once("\r\n\r\n") {
			if body.len() >= 2 {
				return Some((head.to_ascii_lowercase(), body.to_string()));
			}
		}
	}
}

/// Whether the peer closed (or reset) the connection within a few seconds.
async fn closed(s: &mut TcpStream) -> bool {
	let mut b = [0u8; 16];
	matches!(tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await, Ok(Ok(0)) | Ok(Err(_)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn by_default_sigterm_stops_at_once() {
	let backend = tcp_backend("B:").await;
	let (mut p, api) = start("default", &[]).await;
	let caps = api_get(api, "/capabilities").await.1;
	assert_eq!(caps["features"]["graceful_shutdown"], json!(true), "{caps}");
	let port = free_port();
	assert_eq!(api_post(api, rule("tcp", port, backend)).await.0, 201);
	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut conn, "x").await, "B:x");

	p.term();
	let took = p.exited_within(Duration::from_secs(10)).await;
	assert!(took < Duration::from_secs(4), "took {took:?}");
	assert!(closed(&mut conn).await, "the connection outlived the process");
	assert!(p.events("shutdown.start").is_empty(), "{}", p.log_text());
	assert_eq!(p.events("shutdown").len(), 1, "{}", p.log_text());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delay_keeps_accepting_then_drain_lets_connections_end() {
	let backend = tcp_backend("B:").await;
	let udp_target = udp_backend("U:").await;
	let web = http_backend().await;
	let (mut p, api) = start("graceful", &[("RPROXY_SHUTDOWN_DELAY", "2s"), ("RPROXY_SHUTDOWN_DRAIN", "4s")]).await;
	let (tcp_port, udp_port, http_port) = (free_port(), free_udp_port(), free_port());
	assert_eq!(api_post(api, rule("tcp", tcp_port, backend)).await.0, 201);
	assert_eq!(api_post(api, rule("udp", udp_port, udp_target)).await.0, 201);
	let http = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": http_port,
		"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{web}")}]}});
	let (status, v) = api_post(api, http).await;
	assert_eq!(status, 201, "{v}");

	// before SIGTERM: a TCP connection, a UDP session, a kept-alive HTTP connection
	let mut old = TcpStream::connect(("127.0.0.1", tcp_port)).await.unwrap();
	assert_eq!(roundtrip(&mut old, "a").await, "B:a");
	let session = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	session.connect(("127.0.0.1", udp_port)).await.unwrap();
	assert_eq!(udp_roundtrip(&session, "s").await, "U:s");
	let mut kept = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
	assert_eq!(http_request(&mut kept, "/").await.unwrap().1, "ok");
	// a slow request in flight across the start of the drain (answered at 4s, the drain starts at 2.5s)
	let mut slow_conn = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
	let slow = tokio::spawn(async move {
		let r = http_request(&mut slow_conn, "/slow").await;
		(r, closed(&mut slow_conn).await)
	});
	tokio::time::sleep(Duration::from_millis(500)).await;

	p.term();
	let start = p.wait_event("shutdown.start").await;
	assert_eq!((start["delay_secs"].as_f64(), start["drain_secs"].as_f64()), (Some(2.0), Some(4.0)), "{start}");

	// the delay: not ready, reads answer, changes are refused, new connections pass
	assert_eq!(api_get(api, "/readyz").await.0, 503);
	let (status, rules) = api_get(api, "/rules").await;
	assert_eq!((status, rules.as_array().map(Vec::len)), (200, Some(3)), "{rules}");
	let (status, v) = api_post(api, rule("tcp", free_port(), backend)).await;
	assert_eq!((status, v["code"].as_str()), (503, Some("shutting_down")), "{v}");
	let mut during = TcpStream::connect(("127.0.0.1", tcp_port)).await.unwrap();
	assert_eq!(roundtrip(&mut during, "d").await, "B:d");
	assert!(p.events("shutdown.drain").is_empty(), "the drain began too early:\n{}", p.log_text());

	// the drain: listeners closed, open connections and sessions go on
	let drain = p.wait_event("shutdown.drain").await;
	assert!(drain["connections"].as_u64().unwrap() >= 4, "{drain}");
	tokio::time::sleep(Duration::from_millis(200)).await;
	assert!(TcpStream::connect(("127.0.0.1", tcp_port)).await.is_err(), "a new connection was accepted while draining");
	assert_eq!(roundtrip(&mut old, "b").await, "B:b");
	assert_eq!(roundtrip(&mut during, "e").await, "B:e");
	assert_eq!(udp_roundtrip(&session, "t").await, "U:t");
	let fresh = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	fresh.connect(("127.0.0.1", udp_port)).await.unwrap();
	fresh.send(b"n").await.unwrap();
	let mut buf = [0u8; 64];
	assert!(tokio::time::timeout(Duration::from_millis(500), fresh.recv(&mut buf)).await.is_err(), "a new UDP session while draining");
	// HTTP: the idle kept-alive connection is closed, the request in flight ends with Connection: close
	assert!(closed(&mut kept).await, "the idle keep-alive connection stayed open");
	let (response, slow_closed) = slow.await.unwrap();
	let (head, body) = response.expect("the request in flight did not finish");
	assert_eq!(body, "ok");
	assert!(head.contains("connection: close"), "{head}");
	assert!(slow_closed);
	assert_eq!(api_get(api, "/rules").await.0, 200, "the control API stopped answering while draining");

	// past the drain: what is left is cut
	let took = p.exited_within(Duration::from_secs(15)).await;
	assert!(took < Duration::from_secs(8), "took {took:?}");
	assert!(closed(&mut old).await);
	let done = p.events("shutdown.done");
	assert_eq!(done.len(), 1, "{}", p.log_text());
	assert!(done[0]["cut"].as_u64().unwrap() >= 2, "{}", done[0]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_sigterm_stops_at_once() {
	let backend = tcp_backend("B:").await;
	let (mut p, api) = start("second", &[("RPROXY_SHUTDOWN_DELAY", "60s"), ("RPROXY_SHUTDOWN_DRAIN", "60s")]).await;
	let port = free_port();
	assert_eq!(api_post(api, rule("tcp", port, backend)).await.0, 201);
	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut conn, "x").await, "B:x");

	p.term();
	p.wait_event("shutdown.start").await;
	tokio::time::sleep(Duration::from_millis(300)).await;
	p.term();
	let took = p.exited_within(Duration::from_secs(10)).await;
	assert!(took < Duration::from_secs(5), "took {took:?}");
	assert_eq!(p.events("shutdown.now").len(), 1, "{}", p.log_text());
	assert!(closed(&mut conn).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_sigterm_cuts_the_drain_short() {
	let backend = tcp_backend("B:").await;
	let (mut p, api) = start("second-drain", &[("RPROXY_SHUTDOWN_DRAIN", "60s")]).await;
	let port = free_port();
	assert_eq!(api_post(api, rule("tcp", port, backend)).await.0, 201);
	let mut conn = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut conn, "x").await, "B:x");

	p.term();
	p.wait_event("shutdown.drain").await;
	assert_eq!(roundtrip(&mut conn, "y").await, "B:y");
	p.term();
	let took = p.exited_within(Duration::from_secs(10)).await;
	assert!(took < Duration::from_secs(5), "took {took:?}");
	assert!(closed(&mut conn).await);
	assert_eq!(p.events("shutdown.done")[0]["cut"], json!(1), "{}", p.log_text());
}

#[test]
fn values_out_of_range_stop_the_startup() {
	let out = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.env_clear()
		.env("RPROXY_API_PORT", free_port().to_string())
		.env("RPROXY_SHUTDOWN_DRAIN", "2h")
		.output()
		.unwrap();
	assert!(!out.status.success());
	let text = String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
	assert!(text.contains("--shutdown-drain"), "{text}");
}
