//! Resource probe (.github/workflows/bench.yml): CPU time and memory of rproxy-api
//! as its own process, for several builds side by side (the merge base and the PR).
//!
//! Every workload starts a fresh `rproxy-api` (no configuration file, the rules come
//! through the API on 127.0.0.1), drives a fixed amount of traffic over loopback and
//! reads the process from /proc: CPU time (utime + stime of /proc/<pid>/stat, all
//! threads), VmRSS / VmHWM of /proc/<pid>/status and the open FDs. No namespaces, no
//! root: it runs in the bench job's unprivileged container.
//!
//! - `udp`: `--sessions` sockets, one session each (memory = RSS after them − RSS
//!   before, per session), then `--datagrams` 64-byte round trips per session
//!   through an echo backend (CPU per round trip)
//! - `udp-pp`: the same with `proxy_protocol` on the rule: every datagram from a
//!   socket carries a PROXY v2 DGRAM header naming its own client (198.18.0.0/15,
//!   the benchmarking range), so each socket is a session of its header client.
//!   Skipped for builds whose `/capabilities` lacks `features.proxy_protocol_in_udp`
//! - `tcp`: `--conns` idle connections (memory per connection), `--churn`
//!   connections that echo 1 KiB and close (CPU per connection), and `--mib` MiB
//!   uploaded over 4 connections to a discarding backend (CPU per MiB)
//!
//! The builds take turns (A, B, B, A, ...) for `--rounds` rounds; the tables show the
//! median. Prints a Markdown table (and writes it to `--markdown`), the raw numbers
//! to `--json`, and a GitHub Actions `::warning::` line for every figure of the last
//! build that is worse than the first by more than the threshold (`--cpu-threshold`,
//! `--mem-threshold` in %). Always exits 0 unless a build fails to run: a
//! regression is a warning, as for the criterion benchmarks.
//!
//!     cargo build --release --bin rproxy-api --example resource_probe
//!     target/release/examples/resource_probe --rproxy base=/path/to/old --rproxy pr=target/release/rproxy-api

use std::collections::BTreeMap;
use std::io::{Read, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

const PAYLOAD: usize = 64;
/// UDP sessions that do their round trips at the same time.
const UDP_PARALLEL: usize = 64;
const CHURN_WORKERS: usize = 16;
const UPLOAD_STREAMS: usize = 4;

struct Args {
	builds: Vec<(String, String)>,
	rounds: usize,
	sessions: usize,
	datagrams: usize,
	conns: usize,
	churn: usize,
	mib: usize,
	cpu_threshold: f64,
	mem_threshold: f64,
	markdown: Option<String>,
	json: Option<String>,
}

fn args() -> Args {
	let mut a = Args {
		builds: Vec::new(),
		rounds: 5,
		sessions: 1000,
		datagrams: 100,
		conns: 1000,
		churn: 2000,
		mib: 1024,
		cpu_threshold: 15.0,
		mem_threshold: 15.0,
		markdown: None,
		json: None,
	};
	let mut it = std::env::args().skip(1);
	while let Some(k) = it.next() {
		let v = it.next().unwrap_or_else(|| panic!("{k} needs a value"));
		let num = |v: &str| v.parse::<usize>().unwrap_or_else(|_| panic!("bad {k} {v}"));
		match k.as_str() {
			"--rproxy" => {
				let (label, path) = v.split_once('=').unwrap_or_else(|| panic!("--rproxy label=path, not {v}"));
				// absolute: each rproxy runs in a directory of its own
				let path = std::fs::canonicalize(path).unwrap_or_else(|e| panic!("{path}: {e}"));
				a.builds.push((label.to_string(), path.display().to_string()));
			}
			"--rounds" => a.rounds = num(&v).max(1),
			"--sessions" => a.sessions = num(&v).max(1),
			"--datagrams" => a.datagrams = num(&v).max(1),
			"--conns" => a.conns = num(&v).max(1),
			"--churn" => a.churn = num(&v).max(1),
			"--mib" => a.mib = num(&v).max(1),
			"--cpu-threshold" => a.cpu_threshold = v.parse().unwrap(),
			"--mem-threshold" => a.mem_threshold = v.parse().unwrap(),
			"--markdown" => a.markdown = Some(v),
			"--json" => a.json = Some(v),
			other => panic!("unknown option {other}"),
		}
	}
	assert!(!a.builds.is_empty(), "give at least one --rproxy label=path");
	a
}

// ---------------------------------------------------------------- /proc

fn clk_tck() -> f64 {
	// SAFETY: sysconf has no preconditions
	(unsafe { libc::sysconf(libc::_SC_CLK_TCK) }) as f64
}

/// CPU time of the whole process (user + system, all threads), µs.
fn cpu_us(pid: u32) -> f64 {
	let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("read /proc/<pid>/stat");
	let fields: Vec<&str> = stat.rsplit_once(')').expect("stat").1.split_whitespace().collect();
	let ticks: u64 = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
	ticks as f64 * 1e6 / clk_tck()
}

/// A line of /proc/<pid>/status in KiB (VmRSS, VmHWM).
fn status_kib(pid: u32, key: &str) -> f64 {
	let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read /proc/<pid>/status");
	status
		.lines()
		.find_map(|l| l.strip_prefix(key).and_then(|r| r.trim_start_matches(':').split_whitespace().next()))
		.and_then(|v| v.parse().ok())
		.unwrap_or(0.0)
}

fn fds(pid: u32) -> f64 {
	std::fs::read_dir(format!("/proc/{pid}/fd")).map(|d| d.count() as f64).unwrap_or(0.0)
}

/// RSS (KiB) and FDs after the process has had a moment to settle.
async fn settled(pid: u32) -> (f64, f64) {
	tokio::time::sleep(Duration::from_millis(700)).await;
	(status_kib(pid, "VmRSS"), fds(pid))
}

fn raise_nofile() {
	// SAFETY: plain getrlimit / setrlimit on a local struct
	unsafe {
		let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
		if libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) == 0 && r.rlim_cur < r.rlim_max {
			r.rlim_cur = r.rlim_max;
			libc::setrlimit(libc::RLIMIT_NOFILE, &r);
		}
	}
}

// ---------------------------------------------------------------- rproxy as its own process

struct Rproxy {
	child: Child,
	pid: u32,
	api: u16,
	_dir: TempDir,
}

struct TempDir(PathBuf);

impl Drop for TempDir {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.0);
	}
}

impl Drop for Rproxy {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

fn free_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn free_udp_port() -> u16 {
	std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

impl Rproxy {
	async fn start(binary: &str) -> Rproxy {
		static SEQ: AtomicU64 = AtomicU64::new(0);
		let dir = std::env::temp_dir().join(format!("resource-probe-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed)));
		std::fs::create_dir_all(&dir).unwrap();
		let api = free_port();
		let child = Command::new(binary)
			.env_clear()
			.env("PATH", std::env::var("PATH").unwrap_or_default())
			.env("RPROXY_API_ADDR", "127.0.0.1")
			.env("RPROXY_API_PORT", api.to_string())
			.env("RPROXY_LOG_LEVEL", "error")
			.current_dir(&dir)
			.stdout(Stdio::null())
			.spawn()
			.unwrap_or_else(|e| panic!("start {binary}: {e}"));
		let pid = child.id();
		let rp = Rproxy { child, pid, api, _dir: TempDir(dir) };
		for _ in 0..100 {
			if rp.call("GET", "/healthz", None).map(|(s, _)| s == 200).unwrap_or(false) {
				return rp;
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		panic!("{binary} did not answer /healthz on 127.0.0.1:{api}");
	}

	/// A small HTTP/1.1 request to the control API (Connection: close).
	fn call(&self, method: &str, path: &str, body: Option<&Value>) -> std::io::Result<(u16, Value)> {
		let mut s = std::net::TcpStream::connect(("127.0.0.1", self.api))?;
		s.set_read_timeout(Some(Duration::from_secs(30)))?;
		let body = body.map(|b| b.to_string()).unwrap_or_default();
		write!(
			s,
			"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
			body.len()
		)?;
		let mut raw = Vec::new();
		s.read_to_end(&mut raw)?;
		let text = String::from_utf8_lossy(&raw);
		let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
		let status = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
		let body = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunk(rest) } else { rest.to_string() };
		Ok((status, serde_json::from_str(&body).unwrap_or(Value::String(body))))
	}

	fn add(&self, rule: Value) {
		let (status, v) = self.call("POST", "/rules", Some(&rule)).expect("POST /rules");
		assert!((200..300).contains(&status), "POST /rules {rule}: {status} {v}");
	}

	fn feature(&self, name: &str) -> bool {
		let (_, v) = self.call("GET", "/capabilities", None).expect("GET /capabilities");
		v["features"][name].as_bool().unwrap_or(false)
	}

	fn cpu_us(&self) -> f64 {
		cpu_us(self.pid)
	}
}

fn dechunk(mut s: &str) -> String {
	let mut out = String::new();
	while let Some((size, rest)) = s.split_once("\r\n") {
		let n = usize::from_str_radix(size.trim(), 16).unwrap_or(0);
		if n == 0 || rest.len() < n {
			break;
		}
		out.push_str(&rest[..n]);
		s = rest[n..].trim_start_matches("\r\n");
	}
	out
}

// ---------------------------------------------------------------- backends (in this process)

async fn udp_echo() -> SocketAddr {
	let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr = s.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = vec![0u8; 65536];
		loop {
			if let Ok((n, from)) = s.recv_from(&mut buf).await {
				let _ = s.send_to(&buf[..n], from).await;
			}
		}
	});
	addr
}

async fn tcp_echo() -> SocketAddr {
	let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = l.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut c, _)) = l.accept().await {
			tokio::spawn(async move {
				let (mut r, mut w) = c.split();
				let _ = tokio::io::copy(&mut r, &mut w).await;
			});
		}
	});
	addr
}

/// Reads until EOF, then answers with the number of bytes it got (u64 LE).
async fn tcp_discard() -> SocketAddr {
	let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = l.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut c, _)) = l.accept().await {
			tokio::spawn(async move {
				let mut buf = vec![0u8; 256 << 10];
				let mut n = 0u64;
				while let Ok(k) = c.read(&mut buf).await {
					if k == 0 {
						break;
					}
					n += k as u64;
				}
				let _ = c.write_all(&n.to_le_bytes()).await;
			});
		}
	});
	addr
}

struct Backends {
	uecho: SocketAddr,
	echo: SocketAddr,
	discard: SocketAddr,
}

// ---------------------------------------------------------------- workloads

type Metrics = BTreeMap<&'static str, f64>;

/// A PROXY v2 header (PROXY, UDP over IPv4) naming client `i` (198.18.0.0/15 + i) and the rule's address.
fn proxy_v2_dgram(i: usize, dst: SocketAddr) -> Vec<u8> {
	let mut h = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
	h.extend_from_slice(&[0x21, 0x12, 0, 12]);
	h.extend_from_slice(&(u32::from(Ipv4Addr::new(198, 18, 0, 0)) + i as u32).to_be_bytes());
	let SocketAddr::V4(dst) = dst else { panic!("IPv4 only") };
	h.extend_from_slice(&dst.ip().octets());
	h.extend_from_slice(&(1024 + (i % 60000) as u16).to_be_bytes());
	h.extend_from_slice(&dst.port().to_be_bytes());
	h
}

/// Sends `msg` and waits for its echo (PAYLOAD bytes) up to `wait`; false when nothing came back in time.
async fn ping(s: &UdpSocket, msg: &[u8], buf: &mut [u8], wait: Duration, bad: &AtomicU64) -> bool {
	if s.send(msg).await.is_err() {
		return false;
	}
	match tokio::time::timeout(wait, s.recv(buf)).await {
		Ok(Ok(n)) => {
			// the echo of the payload only: with proxy_protocol rproxy must have stripped the header
			if n != PAYLOAD {
				bad.fetch_add(1, Ordering::Relaxed);
			}
			true
		}
		_ => false,
	}
}

async fn udp(binary: &str, b: &Backends, a: &Args, pp: bool) -> Metrics {
	let rp = Rproxy::start(binary).await;
	let port = free_udp_port();
	let listen: SocketAddr = ([127, 0, 0, 1], port).into();
	let mut rule = json!({"protocol": "udp", "listen_addr": "127.0.0.1", "listen_port": port,
		"remote_addr": "127.0.0.1", "remote_port": b.uecho.port(), "udp_idle_secs": 600});
	if pp {
		rule["proxy_protocol"] = json!({"from": ["127.0.0.1/32"], "required": true});
	}
	rp.add(rule);
	let (rss0, fd0) = settled(rp.pid).await;

	// one socket per session; with proxy_protocol each has a header of its own client
	let mut socks = Vec::with_capacity(a.sessions);
	for i in 0..a.sessions {
		let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		s.connect(listen).await.unwrap();
		let mut msg = if pp { proxy_v2_dgram(i, listen) } else { Vec::new() };
		msg.extend_from_slice(&[0x5a; PAYLOAD]);
		socks.push((Arc::new(s), Arc::new(msg)));
	}
	let bad = Arc::new(AtomicU64::new(0));
	let mut up = 0usize;
	for chunk in socks.chunks(100) {
		let mut set = JoinSet::new();
		for (s, msg) in chunk {
			let (s, msg, bad) = (s.clone(), msg.clone(), bad.clone());
			set.spawn(async move {
				let mut buf = [0u8; 2048];
				for _ in 0..5 {
					if ping(&s, &msg, &mut buf, Duration::from_millis(500), &bad).await {
						return true;
					}
				}
				false
			});
		}
		up += set.join_all().await.into_iter().filter(|ok| *ok).count();
	}
	let (rss1, fd1) = settled(rp.pid).await;

	// round trips: UDP_PARALLEL sessions at a time, each --datagrams in turn
	let sem = Arc::new(Semaphore::new(UDP_PARALLEL));
	let lost = Arc::new(AtomicU64::new(0));
	let cpu0 = rp.cpu_us();
	let t0 = Instant::now();
	let mut set = JoinSet::new();
	for (s, msg) in &socks {
		let (s, msg, sem, lost, bad, n) = (s.clone(), msg.clone(), sem.clone(), lost.clone(), bad.clone(), a.datagrams);
		set.spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let mut buf = [0u8; 2048];
			for _ in 0..n {
				if !ping(&s, &msg, &mut buf, Duration::from_millis(200), &bad).await {
					lost.fetch_add(1, Ordering::Relaxed);
				}
			}
		});
	}
	set.join_all().await;
	let secs = t0.elapsed().as_secs_f64();
	let cpu = rp.cpu_us() - cpu0;
	let total = (a.sessions * a.datagrams) as f64;
	let lost = lost.load(Ordering::Relaxed) as f64;
	let done = (total - lost).max(1.0);
	let n = up.max(1) as f64;
	BTreeMap::from([
		("sessions", up as f64),
		("kib_per_session", (rss1 - rss0) / n),
		("fds_per_session", (fd1 - fd0) / n),
		("cpu_us_per_rt", cpu / done),
		("rt_per_s", done / secs),
		("loss_pct", 100.0 * lost / total),
		("bad_replies", bad.load(Ordering::Relaxed) as f64),
		("rss_idle_mib", rss0 / 1024.0),
		("rss_hwm_mib", status_kib(rp.pid, "VmHWM") / 1024.0),
	])
}

async fn tcp(binary: &str, b: &Backends, a: &Args) -> Metrics {
	let rp = Rproxy::start(binary).await;
	let (echo_port, sink_port) = (free_port(), free_port());
	for (port, to) in [(echo_port, b.echo), (sink_port, b.discard)] {
		rp.add(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"remote_addr": "127.0.0.1", "remote_port": to.port()}));
	}
	let echo: SocketAddr = ([127, 0, 0, 1], echo_port).into();
	let sink: SocketAddr = ([127, 0, 0, 1], sink_port).into();
	let (rss0, fd0) = settled(rp.pid).await;

	// idle connections, each proven through to the backend with a 1-byte echo
	let mut held = Vec::with_capacity(a.conns);
	for _ in 0..a.conns.div_ceil(100) {
		let mut set = JoinSet::new();
		for _ in 0..100.min(a.conns - held.len()) {
			set.spawn(async move {
				let mut c = TcpStream::connect(echo).await.ok()?;
				c.write_all(b"x").await.ok()?;
				let mut one = [0u8; 1];
				tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut one)).await.ok()?.ok()?;
				Some(c)
			});
		}
		held.extend(set.join_all().await.into_iter().flatten());
	}
	let (rss1, fd1) = settled(rp.pid).await;
	let conns = held.len().max(1) as f64;
	drop(held);
	tokio::time::sleep(Duration::from_millis(300)).await;

	// churn: connect, echo 1 KiB, close
	let failed = Arc::new(AtomicU64::new(0));
	let next = Arc::new(AtomicU64::new(0));
	let cpu0 = rp.cpu_us();
	let t0 = Instant::now();
	let mut set = JoinSet::new();
	for _ in 0..CHURN_WORKERS {
		let (failed, next, total) = (failed.clone(), next.clone(), a.churn as u64);
		set.spawn(async move {
			let msg = [0x33u8; 1024];
			let mut back = [0u8; 1024];
			while next.fetch_add(1, Ordering::Relaxed) < total {
				let ok = async {
					let mut c = TcpStream::connect(echo).await.ok()?;
					c.write_all(&msg).await.ok()?;
					tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut back)).await.ok()?.ok()?;
					Some(())
				}
				.await;
				if ok.is_none() {
					failed.fetch_add(1, Ordering::Relaxed);
				}
			}
		});
	}
	set.join_all().await;
	let churn_secs = t0.elapsed().as_secs_f64();
	let churn_cpu = rp.cpu_us() - cpu0;
	let churned = (a.churn as f64 - failed.load(Ordering::Relaxed) as f64).max(1.0);

	// upload to the discarding backend
	let per = (a.mib << 20) / UPLOAD_STREAMS;
	let cpu0 = rp.cpu_us();
	let t0 = Instant::now();
	let mut set = JoinSet::new();
	for _ in 0..UPLOAD_STREAMS {
		set.spawn(async move {
			let mut c = TcpStream::connect(sink).await.ok()?;
			let chunk = vec![0xa5u8; 256 << 10];
			let mut left = per;
			while left > 0 {
				let k = left.min(chunk.len());
				c.write_all(&chunk[..k]).await.ok()?;
				left -= k;
			}
			c.shutdown().await.ok()?;
			let mut n = [0u8; 8];
			c.read_exact(&mut n).await.ok()?;
			Some(u64::from_le_bytes(n))
		});
	}
	let got: u64 = set.join_all().await.into_iter().map(|n| n.unwrap_or(0)).sum();
	let up_secs = t0.elapsed().as_secs_f64();
	let up_cpu = rp.cpu_us() - cpu0;
	let mib = got as f64 / (1 << 20) as f64;
	BTreeMap::from([
		("conns", conns),
		("kib_per_conn", (rss1 - rss0) / conns),
		("fds_per_conn", (fd1 - fd0) / conns),
		("cpu_us_per_conn", churn_cpu / churned),
		("conns_per_s", churned / churn_secs),
		("churn_failed", failed.load(Ordering::Relaxed) as f64),
		("cpu_us_per_mib", if mib > 0.0 { up_cpu / mib } else { f64::NAN }),
		("gbps", got as f64 * 8.0 / 1e9 / up_secs),
		("upload_short_mib", ((a.mib << 20) as f64 - got as f64) / (1 << 20) as f64),
		("rss_idle_mib", rss0 / 1024.0),
		("rss_hwm_mib", status_kib(rp.pid, "VmHWM") / 1024.0),
	])
}

// ---------------------------------------------------------------- report

/// (metric, label, format precision, kind): kind "cpu" / "mem" are compared with their threshold
/// (lower is better), "info" is shown without a verdict.
type Shown = (&'static str, &'static str, usize, &'static str);

/// (workload, title, metrics)
const SHOWN: &[(&str, &str, &[Shown])] = &[
	(
		"udp",
		"UDP (plain)",
		&[
			("cpu_us_per_rt", "CPU µs / round trip (2 datagrams)", 2, "cpu"),
			("kib_per_session", "KiB / session", 2, "mem"),
			("fds_per_session", "FDs / session", 2, "info"),
			("rss_hwm_mib", "peak RSS MiB", 1, "mem"),
			("rt_per_s", "round trips / s", 0, "info"),
			("loss_pct", "loss %", 3, "info"),
		],
	),
	(
		"udp-pp",
		"UDP with proxy_protocol (PROXY v2 header on every datagram)",
		&[
			("cpu_us_per_rt", "CPU µs / round trip (2 datagrams)", 2, "cpu"),
			("kib_per_session", "KiB / session", 2, "mem"),
			("fds_per_session", "FDs / session", 2, "info"),
			("rss_hwm_mib", "peak RSS MiB", 1, "mem"),
			("rt_per_s", "round trips / s", 0, "info"),
			("loss_pct", "loss %", 3, "info"),
		],
	),
	(
		"tcp",
		"TCP",
		&[
			("cpu_us_per_conn", "CPU µs / connection (connect, 1 KiB echo, close)", 1, "cpu"),
			("cpu_us_per_mib", "CPU µs / MiB uploaded", 1, "cpu"),
			("kib_per_conn", "KiB / idle connection", 2, "mem"),
			("fds_per_conn", "FDs / connection", 2, "info"),
			("rss_hwm_mib", "peak RSS MiB", 1, "mem"),
			("conns_per_s", "connections / s", 0, "info"),
			("gbps", "upload Gbit/s", 2, "info"),
		],
	),
];

fn median(mut v: Vec<f64>) -> Option<f64> {
	v.retain(|x| x.is_finite());
	if v.is_empty() {
		return None;
	}
	v.sort_by(|a, b| a.partial_cmp(b).unwrap());
	let m = v.len() / 2;
	Some(if v.len() % 2 == 1 { v[m] } else { (v[m - 1] + v[m]) / 2.0 })
}

#[tokio::main]
async fn main() {
	let a = args();
	raise_nofile();
	let b = Backends { uecho: udp_echo().await, echo: tcp_echo().await, discard: tcp_discard().await };

	// which builds read proxy_protocol on udp rules
	let mut pp_ok = Vec::new();
	for (label, path) in &a.builds {
		let rp = Rproxy::start(path).await;
		let ok = rp.feature("proxy_protocol_in_udp");
		eprintln!("{label}: {path}, proxy_protocol_in_udp {ok}");
		pp_ok.push(ok);
	}

	// raw[workload][build] = one Metrics per round
	let mut raw: BTreeMap<&str, Vec<Vec<Metrics>>> = BTreeMap::new();
	let started = Instant::now();
	for round in 0..a.rounds {
		let mut order: Vec<usize> = (0..a.builds.len()).collect();
		if round % 2 == 1 {
			order.reverse();
		}
		for (workload, _, _) in SHOWN {
			for &i in &order {
				let path = &a.builds[i].1;
				let m = match *workload {
					"udp" => udp(path, &b, &a, false).await,
					"udp-pp" if pp_ok[i] => udp(path, &b, &a, true).await,
					"udp-pp" => continue,
					_ => tcp(path, &b, &a).await,
				};
				eprintln!("round {} {workload} {}: {m:?}", round + 1, a.builds[i].0);
				raw.entry(workload).or_insert_with(|| vec![Vec::new(); a.builds.len()])[i].push(m);
			}
		}
	}
	let secs = started.elapsed().as_secs_f64();

	let med = |w: &str, i: usize, k: &str| -> Option<f64> {
		raw.get(w).and_then(|per| median(per[i].iter().filter_map(|m| m.get(k).copied()).collect()))
	};
	let labels: Vec<&str> = a.builds.iter().map(|(l, _)| l.as_str()).collect();
	let last = labels.len() - 1;
	let mut warnings = Vec::new();
	let mut out = vec![
		format!("## Resource usage ({})", labels.join(" → ")),
		String::new(),
		format!(
			"rproxy-api as its own process on loopback, a fresh process per workload; median of {} rounds (the builds take turns). \
			 CPU = utime + stime of the process, memory = VmRSS after the sessions / connections − before, per one; peak RSS = VmHWM. \
			 Lower is better; ⚠️ marks a figure worse than `{}` by more than {} % (CPU) / {} % (memory). \
			 {} UDP sessions × {} round trips of {PAYLOAD} B ({UDP_PARALLEL} sessions at a time), {} idle TCP connections, \
			 {} TCP connections churned ({CHURN_WORKERS} workers), {} MiB uploaded over {UPLOAD_STREAMS} connections. {:.0} s in all.",
			a.rounds, labels[0], a.cpu_threshold, a.mem_threshold, a.sessions, a.datagrams, a.conns, a.churn, a.mib, secs
		),
		String::new(),
		format!(
			"| workload | metric | {} |{}",
			labels.iter().map(|l| format!("`{l}`")).collect::<Vec<_>>().join(" | "),
			if last > 0 { " change | |" } else { "" }
		),
		format!("|---|---|{}", "---|".repeat(labels.len() + if last > 0 { 2 } else { 0 })),
	];
	for (w, title, metrics) in SHOWN {
		for (k, label, prec, kind) in *metrics {
			let vals: Vec<Option<f64>> = (0..labels.len()).map(|i| med(w, i, k)).collect();
			let cells: Vec<String> = vals.iter().map(|v| v.map(|x| format!("{x:.prec$}")).unwrap_or_else(|| "—".into())).collect();
			let mut row = format!("| {title} | {label} | {} |", cells.join(" | "));
			if last > 0 {
				let (change, mark) = match (vals[0], vals[last]) {
					(Some(base), Some(new)) if base.abs() > 1e-9 => {
						let pct = (new - base) / base.abs() * 100.0;
						let limit = match *kind {
							"cpu" => Some(a.cpu_threshold),
							"mem" => Some(a.mem_threshold),
							_ => None,
						};
						let mark = match limit {
							Some(l) if pct > l => {
								warnings.push(format!("{title}: {label} {pct:+.1} % against {}", labels[0]));
								"⚠️ worse"
							}
							Some(l) if pct < -l => "better",
							_ => "",
						};
						(format!("{pct:+.1} %"), mark)
					}
					(None, Some(_)) => ("new".into(), ""),
					_ => ("".into(), ""),
				};
				row += &format!(" {change} | {mark} |");
			}
			out.push(row);
		}
	}
	// the cost of proxy_protocol itself, within the last build
	if let (Some(plain), Some(pp)) = (med("udp", last, "cpu_us_per_rt"), med("udp-pp", last, "cpu_us_per_rt")) {
		let mem = match (med("udp", last, "kib_per_session"), med("udp-pp", last, "kib_per_session")) {
			(Some(m0), Some(m1)) => format!(", memory per session {:+.2} KiB", m1 - m0),
			_ => String::new(),
		};
		out.push(String::new());
		out.push(format!(
			"proxy_protocol on UDP in `{}`: CPU per round trip {:+.1} % against plain UDP{mem}.",
			labels[last],
			(pp - plain) / plain * 100.0
		));
	}
	let mut anomalies = Vec::new();
	for (w, per) in &raw {
		for (i, rounds) in per.iter().enumerate() {
			for m in rounds {
				let bad: f64 = ["bad_replies", "churn_failed", "upload_short_mib"].iter().filter_map(|k| m.get(k)).sum();
				if bad > 0.0 {
					anomalies.push(format!("{w} `{}`: {m:?}", labels[i]));
				}
			}
		}
	}
	if !anomalies.is_empty() {
		out.push(String::new());
		out.push("Rounds with wrong replies, failed connections or a short upload:".into());
		out.extend(anomalies.iter().map(|x| format!("- {x}")));
	}
	if raw.get("udp-pp").is_some_and(|per| per.iter().any(Vec::is_empty)) {
		out.push(String::new());
		out.push("`udp-pp` is left out for builds without `features.proxy_protocol_in_udp`.".into());
	}
	let md = out.join("\n");
	println!("{md}");
	if let Some(path) = &a.markdown {
		std::fs::write(path, format!("{md}\n")).expect("write --markdown");
	}
	if let Some(path) = &a.json {
		let builds: Vec<Value> = a.builds.iter().map(|(l, p)| json!({"label": l, "path": p})).collect();
		let results: BTreeMap<&str, Vec<&Vec<Metrics>>> = raw.iter().map(|(w, per)| (*w, per.iter().collect())).collect();
		let doc = json!({"builds": builds, "rounds": a.rounds, "results": results});
		std::fs::write(path, serde_json::to_string_pretty(&doc).unwrap()).expect("write --json");
	}
	for w in warnings {
		eprintln!("::warning title=Resource usage::{w}");
	}
}
