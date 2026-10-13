//! Hostile traffic: broken and malicious input is thrown at the real binary
//! while a legitimate client uses the same rules. The legitimate exchanges
//! must all succeed byte for byte, the process must stay up with its control
//! API answering and its rules running, and once the hostile load stops the
//! open descriptors, connections and threads must come back to where they
//! were, and the memory must not keep growing from one round to the next.
//!
//! One test per kind of input rproxy parses: plain TCP, TLS (`sni`,
//! `terminate`, `terminate` with a passthrough route), `http` rules, STARTTLS
//! (SMTP, IMAP, POP3) and UDP (plain, `sni` with QUIC and DTLS, DTLS
//! `terminate`). rproxy only sends PROXY protocol headers and never reads
//! them, so there is nothing to attack there.
//!
//! The hostile input is random but repeatable: each test prints its seed, and
//! `RPROXY_TEST_HOSTILE_SEED` replays it (the interleaving of the concurrent
//! clients still varies). Each round lasts `RPROXY_TEST_HOSTILE_SECS` seconds
//! (default 2; two rounds per test); set it higher for longer manual runs.

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dtls::config::{Config as DtlsConfig, ExtendedMasterSecretType};
use dtls::conn::DTLSConn;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use webrtc_util::conn::{Conn, Listener};

use common::pki::{Issued, Pki};
use common::*;
use rproxy_api::l4::starttls::Lines;

// ---- knobs and randomness ----

/// Seconds of hostile load per round (`RPROXY_TEST_HOSTILE_SECS`, default 2).
fn round_secs() -> f64 {
	std::env::var("RPROXY_TEST_HOSTILE_SECS").ok().and_then(|v| v.parse().ok()).filter(|s: &f64| *s > 0.0).unwrap_or(2.0)
}

const ROUNDS: usize = 2;
const HOSTILE_WORKERS: usize = 16;
const LEGIT_WORKERS: usize = 2;
/// Open descriptors allowed above the baseline once the load is gone.
const FD_SLACK: usize = 16;
/// Threads allowed above the baseline (tokio's blocking pool keeps idle threads for 10 s).
const THREAD_SLACK: u64 = 8;

/// The seed of a test: `RPROXY_TEST_HOSTILE_SEED`, or a new one, printed.
fn seed(case: &str) -> u64 {
	let seed = std::env::var("RPROXY_TEST_HOSTILE_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or_else(|| {
		let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
		(t.as_nanos() as u64) ^ (u64::from(std::process::id()) << 32)
	});
	eprintln!("hostile {case}: seed {seed} (RPROXY_TEST_HOSTILE_SEED={seed} repeats the input)");
	seed
}

/// splitmix64: small, fast, and the same everywhere for a seed.
#[derive(Clone)]
struct Rng(u64);

impl Rng {
	fn next(&mut self) -> u64 {
		self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
		let mut z = self.0;
		z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
		z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
		z ^ (z >> 31)
	}
	/// In `[lo, hi)`.
	fn range(&mut self, lo: usize, hi: usize) -> usize {
		lo + (self.next() % (hi.saturating_sub(lo).max(1) as u64)) as usize
	}
	fn one_in(&mut self, n: u64) -> bool {
		self.next().is_multiple_of(n)
	}
	fn bytes(&mut self, n: usize) -> Vec<u8> {
		(0..n).map(|_| self.next() as u8).collect()
	}
	/// Random bytes, `[lo, hi)` of them.
	fn bytes_in(&mut self, lo: usize, hi: usize) -> Vec<u8> {
		let n = self.range(lo, hi);
		self.bytes(n)
	}
	fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
		&xs[self.range(0, xs.len())]
	}
	fn fork(&mut self) -> Rng {
		Rng(self.next())
	}
	fn hex(&mut self, n: usize) -> String {
		(0..n).map(|_| char::from(b"0123456789abcdef"[self.range(0, 16)])).collect()
	}
}

type BoxFut = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
/// One exchange (legitimate) or one attack (hostile), from its own random stream.
type Job = Arc<dyn Fn(Rng) -> BoxFut + Send + Sync>;

fn job<F, Fut>(f: F) -> Job
where
	F: Fn(Rng) -> Fut + Send + Sync + 'static,
	Fut: Future<Output = Result<(), String>> + Send + 'static,
{
	Arc::new(move |r| Box::pin(f(r)))
}

fn err<E: std::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> String {
	move |e| format!("{what}: {e}")
}

// ---- the binary ----

#[derive(Debug, Clone, Copy)]
struct Usage {
	fds: usize,
	rss_kib: u64,
	threads: u64,
}

/// One run of the binary with `rules` as its configuration file.
struct Server {
	child: Child,
	dir: PathBuf,
	api: u16,
}

impl Server {
	async fn start(tag: &str, rules: Vec<Value>) -> Server {
		rproxy_api::net::files::private_umask();
		let dir = std::env::temp_dir().join(format!("rproxy-hostile-{tag}-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		let sha = {
			use sha2::Digest;
			sha2::Sha256::digest(b"ci").iter().map(|b| format!("{b:02x}")).collect::<String>()
		};
		fs::write(dir.join("tokens.yaml"), format!("tokens:\n  - {{name: ci, sha256: {sha}, scopes: [admin]}}\n")).unwrap();
		fs::write(dir.join("rules.yaml"), json!({"version": 1, "rules": rules}).to_string()).unwrap();
		let api = free_port();
		let out = fs::File::create(dir.join("rproxy.log")).unwrap();
		let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(&dir)
			.env_clear()
			.env("RPROXY_API_PORT", api.to_string())
			.env("RPROXY_TOKEN_FILE", dir.join("tokens.yaml"))
			.env("RPROXY_CONFIG", dir.join("rules.yaml"))
			.env("RPROXY_HANDOFF_SOCKET", dir.join("handoff.sock"))
			.env("RPROXY_API_SOCKET", dir.join("api.sock"))
			.env("RPROXY_CERT_STORE", dir.join("certs"))
			.stdout(out.try_clone().unwrap())
			.stderr(out)
			.stdin(Stdio::null())
			.process_group(0)
			.spawn()
			.unwrap();
		let s = Server { child, dir, api };
		let deadline = Instant::now() + Duration::from_secs(30);
		loop {
			if let Ok((StatusCode::OK, rules)) = s.try_get("/rules").await {
				let rules = rules.as_array().cloned().unwrap_or_default();
				if !rules.is_empty() && rules.iter().all(|r| r["state"] == "running") {
					return s;
				}
				assert!(rules.iter().all(|r| r["state"] != "failed"), "a rule failed: {rules:?}\n{}", s.log());
			}
			assert!(Instant::now() < deadline, "rproxy did not start:\n{}", s.log());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}

	fn pid(&self) -> i32 {
		self.child.id() as i32
	}

	/// The last lines of the log, without the connections' own lines.
	fn log(&self) -> String {
		let log = fs::read_to_string(self.dir.join("rproxy.log")).unwrap_or_default();
		let lines: Vec<&str> = log.lines().filter(|l| !l.contains("\"event\":\"conn.")).collect();
		lines[lines.len().saturating_sub(40)..].join("\n")
	}

	async fn try_get(&self, path: &str) -> Result<(StatusCode, Value), reqwest::Error> {
		let r = reqwest::Client::new()
			.get(format!("http://127.0.0.1:{}{path}", self.api))
			.bearer_auth("ci")
			.timeout(Duration::from_secs(5))
			.send()
			.await?;
		let status = r.status();
		Ok((status, r.json().await.unwrap_or(Value::Null)))
	}

	fn alive(&self) -> bool {
		fs::read_to_string(format!("/proc/{}/stat", self.pid()))
			.map(|s| s.rsplit(')').next().is_some_and(|r| !r.trim_start().starts_with('Z')))
			.unwrap_or(false)
	}

	fn usage(&self) -> Usage {
		let pid = self.pid();
		let fds = fs::read_dir(format!("/proc/{pid}/fd")).map(|d| d.count()).unwrap_or(0);
		let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
		let field = |name: &str| {
			status
				.lines()
				.find_map(|l| l.strip_prefix(name))
				.and_then(|v| v.split_whitespace().next())
				.and_then(|v| v.parse().ok())
				.unwrap_or(0)
		};
		Usage { fds, rss_kib: field("VmRSS:"), threads: field("Threads:") }
	}

	/// The process is up, the control API answers and every rule still runs;
	/// the open connections (TCP) and sessions (UDP) of all rules.
	async fn check_up(&self, case: &str) -> u64 {
		assert!(self.alive(), "{case}: rproxy died\n{}", self.log());
		let (status, rules) =
			self.try_get("/rules").await.unwrap_or_else(|e| panic!("{case}: the control API does not answer: {e}\n{}", self.log()));
		assert_eq!(status, StatusCode::OK, "{case}: {rules}");
		let rules = rules.as_array().unwrap();
		for r in rules {
			assert_eq!(r["state"], "running", "{case}: a rule stopped running: {r}\n{}", self.log());
		}
		rules.iter().map(|r| r["connections"].as_u64().unwrap_or(0)).sum()
	}

	/// Waits until the connections are gone and the descriptors and threads are
	/// back near `base` (or, without `base`, for the connections only); the usage then.
	async fn settle(&self, case: &str, base: Option<Usage>) -> Usage {
		let deadline = Instant::now() + Duration::from_secs(30);
		loop {
			let conns = self.check_up(case).await;
			let now = self.usage();
			let back = match base {
				None => true,
				Some(b) => now.fds <= b.fds + FD_SLACK && now.threads <= b.threads + THREAD_SLACK,
			};
			if conns == 0 && back {
				return now;
			}
			assert!(
				Instant::now() < deadline,
				"{case}: resources did not come back after the hostile load: {conns} connections, {now:?} (baseline {base:?})\n{}",
				self.log()
			);
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}

	/// No panic, no fatal error, no rule failed.
	fn check_log(&self, case: &str) {
		let log = fs::read_to_string(self.dir.join("rproxy.log")).unwrap_or_default();
		assert!(!log.contains("panicked"), "{case}: rproxy panicked\n{}", self.log());
		for line in log.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()) {
			assert!(!["fatal", "rule.failed"].contains(&line["event"].as_str().unwrap_or("")), "{case}: {line}");
		}
	}
}

impl Drop for Server {
	fn drop(&mut self) {
		// SAFETY: the process group this test started
		unsafe { libc::killpg(self.pid(), libc::SIGKILL) };
		let _ = self.child.wait();
		if !std::thread::panicking() {
			let _ = fs::remove_dir_all(&self.dir);
		}
	}
}

// ---- the driver ----

/// Warms up with `legit`, then runs `ROUNDS` rounds of the hostile jobs (picked
/// at random by `HOSTILE_WORKERS` workers) alongside `LEGIT_WORKERS` legitimate
/// clients, and checks the process and its resources after each round.
async fn exercise(s: &Server, case: &str, legit: Job, hostile: Vec<(&'static str, Job)>) {
	let mut rng = Rng(seed(case));
	for _ in 0..4 {
		legit(rng.fork()).await.unwrap_or_else(|e| panic!("{case}: warm-up: {e}\n{}", s.log()));
	}
	// let what the warm-up started (pooled backend connections, sessions) settle
	s.settle(case, None).await;
	tokio::time::sleep(Duration::from_millis(500)).await;
	let base = s.usage();
	// RPROXY_TEST_HOSTILE_ONLY=name,name narrows the attacks (to find which one breaks something)
	let only = std::env::var("RPROXY_TEST_HOSTILE_ONLY").unwrap_or_default();
	let hostile: Vec<_> = hostile.into_iter().filter(|(n, _)| only.is_empty() || only.split(',').any(|o| o == *n)).collect();
	if hostile.is_empty() {
		return;
	}
	let hostile = Arc::new(hostile);
	let mut after = vec![];
	for round in 1..=ROUNDS {
		let stop = Arc::new(AtomicBool::new(false));
		let counts: Arc<Vec<AtomicU64>> = Arc::new(hostile.iter().map(|_| AtomicU64::new(0)).collect());
		let failures: Arc<Mutex<Vec<String>>> = Arc::default();
		let good = Arc::new(AtomicU64::new(0));
		let mut tasks = vec![];
		for _ in 0..HOSTILE_WORKERS {
			let (stop, counts, hostile, mut r) = (stop.clone(), counts.clone(), hostile.clone(), rng.fork());
			tasks.push(tokio::spawn(async move {
				while !stop.load(Ordering::Relaxed) {
					let k = r.range(0, hostile.len());
					counts[k].fetch_add(1, Ordering::Relaxed);
					// what the attack itself saw does not matter
					let _ = tokio::time::timeout(Duration::from_secs(5), (hostile[k].1)(r.fork())).await;
				}
			}));
		}
		for _ in 0..LEGIT_WORKERS {
			let (stop, failures, good, legit, mut r) = (stop.clone(), failures.clone(), good.clone(), legit.clone(), rng.fork());
			tasks.push(tokio::spawn(async move {
				while !stop.load(Ordering::Relaxed) {
					match tokio::time::timeout(Duration::from_secs(15), legit(r.fork())).await {
						Ok(Ok(())) => {
							good.fetch_add(1, Ordering::Relaxed);
						}
						Ok(Err(e)) => failures.lock().unwrap().push(e),
						Err(_) => failures.lock().unwrap().push("a legitimate exchange did not finish within 15 s".into()),
					}
				}
			}));
		}
		tokio::time::sleep(Duration::from_secs_f64(round_secs())).await;
		stop.store(true, Ordering::Relaxed);
		for t in tasks {
			t.await.unwrap();
		}
		let attacks: Vec<String> =
			hostile.iter().zip(counts.iter()).map(|((n, _), c)| format!("{n}={}", c.load(Ordering::Relaxed))).collect();
		let good = good.load(Ordering::Relaxed);
		eprintln!("hostile {case} round {round}: {good} legitimate exchanges, attacks: {}", attacks.join(" "));
		let failures = failures.lock().unwrap().clone();
		assert!(
			failures.is_empty(),
			"{case} round {round}: {} legitimate exchanges failed, first: {:?}\n{}",
			failures.len(),
			&failures[..failures.len().min(5)],
			s.log()
		);
		assert!(good > 0, "{case} round {round}: no legitimate exchange finished");
		let now = s.settle(case, Some(base)).await;
		eprintln!("hostile {case} round {round}: {now:?} (baseline {base:?})");
		after.push(now);
	}
	// still serves, and the memory of the last round is not much above the first
	for _ in 0..4 {
		legit(rng.fork()).await.unwrap_or_else(|e| panic!("{case}: after the hostile load: {e}\n{}", s.log()));
	}
	let (first, last) = (after[0].rss_kib, after[ROUNDS - 1].rss_kib);
	assert!(
		last <= first + (first / 2).max(32 * 1024),
		"{case}: memory keeps growing: {first} KiB after the first round, {last} KiB after the last (baseline {} KiB)",
		base.rss_kib
	);
	assert!(last <= base.rss_kib + 256 * 1024, "{case}: memory did not come back: {last} KiB (baseline {} KiB)", base.rss_kib);
	s.check_log(case);
}

// ---- shared clients and backends ----

/// Closes `s` with a RST instead of a FIN.
fn reset(s: &TcpStream) {
	let _ = socket2::SockRef::from(s).set_linger(Some(Duration::ZERO));
}

/// Reads and drops whatever comes for at most `wait` (or up to EOF / 1 MiB).
async fn drain<S: AsyncRead + Unpin>(s: &mut S, wait: Duration) {
	let mut buf = vec![0u8; 16 * 1024];
	let mut total = 0;
	let _ = tokio::time::timeout(wait, async {
		while let Ok(n) = s.read(&mut buf).await {
			total += n;
			if n == 0 || total > 1 << 20 {
				break;
			}
		}
	})
	.await;
}

/// Writes `chunks` (with `gap` between them), reads a little, closes (sometimes with a RST).
async fn raw(port: u16, chunks: Vec<Vec<u8>>, gap: Duration, mut r: Rng) -> Result<(), String> {
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
	for c in chunks {
		if s.write_all(&c).await.is_err() {
			break;
		}
		if !gap.is_zero() {
			tokio::time::sleep(gap).await;
		}
	}
	drain(&mut s, Duration::from_millis(r.range(0, 800) as u64)).await;
	if r.one_in(2) {
		reset(&s);
	}
	Ok(())
}

/// Splits `data` into writes of 1 byte (`tiny`) or random sizes.
fn pieces(data: &[u8], tiny: bool, r: &mut Rng) -> Vec<Vec<u8>> {
	let mut out = vec![];
	let mut rest = data;
	while !rest.is_empty() {
		let n = if tiny { 1 } else { r.range(1, rest.len() + 1) };
		let (a, b) = rest.split_at(n.min(rest.len()));
		out.push(a.to_vec());
		rest = b;
	}
	out
}

/// Plain TCP echo: every byte back, and FIN for FIN.
async fn echo_backend() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((s, _)) = listener.accept().await {
			tokio::spawn(async move {
				let (mut r, mut w) = s.into_split();
				let _ = tokio::io::copy(&mut r, &mut w).await;
				let _ = w.shutdown().await;
			});
		}
	});
	addr
}

/// TLS echo with `issued`'s certificate.
async fn tls_echo_backend(pki: &Pki, issued: &Issued) -> SocketAddr {
	let acceptor = pki.acceptor(issued);
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((s, _)) = listener.accept().await {
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(s)).await else {
					return;
				};
				let (mut r, mut w) = tokio::io::split(tls);
				let _ = tokio::io::copy(&mut r, &mut w).await;
				let _ = w.shutdown().await;
			});
		}
	});
	addr
}

/// Sends `len` random bytes in random pieces while reading them back; they
/// must come back exactly, followed by a clean end once this side is done.
async fn echo_exchange<S: AsyncRead + AsyncWrite + Unpin + Send>(s: S, len: usize, r: &mut Rng) -> Result<(), String> {
	let data = r.bytes(len);
	let (mut rd, mut wr) = tokio::io::split(s);
	let chunks = pieces(&data, false, r);
	let writer = async move {
		for c in chunks {
			wr.write_all(&c).await.map_err(err("write"))?;
		}
		wr.shutdown().await.map_err(err("shutdown"))?;
		Ok::<_, String>(wr)
	};
	let reader = async {
		let mut got = vec![0u8; len];
		rd.read_exact(&mut got).await.map_err(|e| format!("read {len} bytes back: {e}"))?;
		if got != data {
			let at = got.iter().zip(&data).position(|(a, b)| a != b).unwrap_or(0);
			return Err(format!("corrupted echo: {len} bytes differ from byte {at}"));
		}
		let mut more = [0u8; 64];
		match rd.read(&mut more).await {
			Ok(0) => Ok(()),
			Ok(n) => Err(format!("{n} unexpected bytes after the echo")),
			Err(e) => Err(format!("no clean end after the echo: {e}")),
		}
	};
	let (w, rd_result) = tokio::join!(writer, reader);
	w?;
	rd_result
}

// ---- TLS input ----

/// A real ClientHello from rustls for `name`.
fn real_hello(name: &str) -> Vec<u8> {
	let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_safe_default_protocol_versions()
		.unwrap()
		.with_root_certificates(rustls::RootCertStore::empty())
		.with_no_client_auth();
	let mut conn = rustls::ClientConnection::new(Arc::new(config), name.to_string().try_into().unwrap()).unwrap();
	let mut out = vec![];
	conn.write_tls(&mut out).unwrap();
	out
}

/// Handshake bytes in TLS records of at most 16 KiB.
fn records(hs: &[u8]) -> Vec<u8> {
	let mut out = vec![];
	for c in hs.chunks(16 * 1024) {
		out.extend_from_slice(&[0x16, 0x03, 0x01]);
		out.extend_from_slice(&(c.len() as u16).to_be_bytes());
		out.extend_from_slice(c);
	}
	out
}

/// A hand-made ClientHello with `sni` as raw bytes (any length, any byte) and `extra` extensions.
fn crafted_hello(sni: Option<&[u8]>, extra: &[(u16, Vec<u8>)]) -> Vec<u8> {
	let mut exts = vec![];
	if let Some(name) = sni {
		let mut entry = vec![0u8];
		entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
		entry.extend_from_slice(name);
		let mut list = (entry.len() as u16).to_be_bytes().to_vec();
		list.extend_from_slice(&entry);
		exts.extend_from_slice(&0u16.to_be_bytes());
		exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
		exts.extend_from_slice(&list);
	}
	for (kind, data) in extra {
		exts.extend_from_slice(&kind.to_be_bytes());
		exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
		exts.extend_from_slice(data);
	}
	let mut body = vec![0x03, 0x03];
	body.extend_from_slice(&[7u8; 32]);
	body.push(0);
	body.extend_from_slice(&[0, 4, 0x13, 0x01, 0xc0, 0x2f, 1, 0]);
	body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
	body.extend_from_slice(&exts);
	let mut hs = vec![1];
	hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
	hs.extend_from_slice(&body);
	records(&hs)
}

/// A server name that is not one: control bytes, non-UTF-8, separators, or very long.
fn bad_name(r: &mut Rng) -> Vec<u8> {
	match r.range(0, 6) {
		0 => r.bytes_in(0, 64),
		1 => b"a.test\0evil.test".to_vec(),
		2 => b"a.test\r\nX-Injected: 1".to_vec(),
		3 => "\u{0430}.test/../%2e%2e\\x".as_bytes().to_vec(),
		4 => vec![b'a'; r.range(254, 300)],
		_ => {
			// as long as fits in one ClientHello, sometimes past rproxy's 16 KiB limit
			let n = r.range(1000, 20_000);
			(0..n).map(|i| if i % 64 == 63 { b'.' } else { b'a' + (i % 26) as u8 }).collect()
		}
	}
}

/// Random extensions: unknown types, empty, huge, repeated server names.
fn garbage_extensions(r: &mut Rng) -> Vec<(u16, Vec<u8>)> {
	let mut out = vec![];
	let mut size = 0;
	for _ in 0..r.range(1, 40) {
		let kind = if r.one_in(4) { 0 } else { r.next() as u16 };
		let len = if r.one_in(8) { r.range(4000, 15_000) } else { r.range(0, 300) };
		if size + len > 50_000 {
			break;
		}
		size += len;
		out.push((kind, r.bytes(len)));
	}
	out
}

/// `data` with a few bytes changed at random.
fn mutate(mut data: Vec<u8>, r: &mut Rng) -> Vec<u8> {
	for _ in 0..r.range(1, 8) {
		if data.is_empty() {
			break;
		}
		let at = r.range(0, data.len());
		data[at] = r.next() as u8;
	}
	data
}

/// The TLS attacks against `ports` (rules reading a ClientHello).
fn tls_attacks(ports: Vec<u16>, names: &'static [&'static str]) -> Vec<(&'static str, Job)> {
	let ports = Arc::new(ports);
	let p = move |r: &mut Rng, ports: &[u16]| *r.pick(ports);
	let mut out: Vec<(&'static str, Job)> = vec![];
	macro_rules! attack {
		($name:literal, |$r:ident, $port:ident| $body:expr) => {{
			let ports = ports.clone();
			out.push((
				$name,
				job(move |mut $r: Rng| {
					let $port = p(&mut $r, &ports);
					async move { $body }
				}),
			));
		}};
	}
	attack!("random_bytes", |r, port| {
		let mut data = r.bytes_in(1, 4096);
		if r.one_in(2) {
			// looks like a handshake record at first
			data[0] = 0x16;
			if data.len() > 2 {
				data[1] = 0x03;
			}
		}
		raw(port, vec![data], Duration::ZERO, r).await
	});
	attack!("truncated_hello", |r, port| {
		let hello = real_hello(r.pick(names));
		let cut = r.range(1, hello.len());
		// either hang up or keep the connection open without the rest
		let wait = if r.one_in(2) { Duration::ZERO } else { Duration::from_millis(r.range(100, 1500) as u64) };
		raw(port, vec![hello[..cut].to_vec()], wait, r).await
	});
	attack!("hello_in_1_byte_writes", |r, port| {
		let hello = real_hello(r.pick(names));
		let chunks = pieces(&hello, true, &mut r);
		raw(port, chunks, Duration::from_micros(r.range(0, 500) as u64), r).await
	});
	attack!("garbage_extensions", |r, port| {
		let name = r.pick(names).as_bytes().to_vec();
		let hello = crafted_hello(if r.one_in(3) { None } else { Some(&name) }, &garbage_extensions(&mut r));
		raw(port, vec![hello], Duration::ZERO, r).await
	});
	attack!("bad_server_name", |r, port| {
		let hello = crafted_hello(Some(&bad_name(&mut r)), &[]);
		raw(port, vec![hello], Duration::ZERO, r).await
	});
	attack!("mutated_hello", |r, port| {
		let hello = mutate(real_hello(r.pick(names)), &mut r);
		raw(port, vec![hello], Duration::ZERO, r).await
	});
	attack!("empty_records", |r, port| {
		// many zero-length handshake records, then maybe a hello
		let mut data = [0x16, 0x03, 0x01, 0, 0].repeat(r.range(1, 5000));
		if r.one_in(2) {
			data.extend(real_hello(r.pick(names)));
		}
		raw(port, pieces(&data, false, &mut r), Duration::ZERO, r).await
	});
	attack!("huge_record_length", |r, port| {
		// a record claiming 64 KiB, followed by garbage up to rproxy's limit and beyond
		let mut data = vec![0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff];
		data.extend(r.bytes_in(0, 70_000));
		raw(port, pieces(&data, false, &mut r), Duration::ZERO, r).await
	});
	attack!("garbage_after_hello", |r, port| {
		let mut data = real_hello(r.pick(names));
		data.extend(r.bytes_in(1, 20_000));
		raw(port, vec![data], Duration::ZERO, r).await
	});
	attack!("slowloris", |r, port| {
		let hello = real_hello(r.pick(names));
		let n = r.range(5, 30).min(hello.len());
		raw(port, pieces(&hello[..n], true, &mut r), Duration::from_millis(r.range(30, 120) as u64), r).await
	});
	out
}

// ---- plain TCP ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_survives_hostile_traffic() {
	let backend = echo_backend().await;
	let port = free_port();
	let s = Server::start("tcp", vec![rule("tcp", port, backend)]).await;

	let legit = job(move |mut r| async move {
		let tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
		let len = if r.one_in(8) { r.range(256 * 1024, 2 << 20) } else { r.range(1, 64 * 1024) };
		echo_exchange(tcp, len, &mut r).await
	});
	let hostile: Vec<(&'static str, Job)> = vec![
		("random_bytes", job(move |mut r| async move { raw(port, vec![r.bytes_in(1, 8192)], Duration::ZERO, r).await })),
		(
			"immediate_close",
			job(move |mut r| async move {
				let s = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
				if r.one_in(2) {
					reset(&s);
				}
				Ok(())
			}),
		),
		(
			"half_open",
			job(move |mut r| async move {
				// connect, send nothing, hang on, then go away
				let _s = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
				tokio::time::sleep(Duration::from_millis(r.range(200, 2000) as u64)).await;
				Ok(())
			}),
		),
		(
			"slowloris",
			job(move |mut r| async move {
				let chunks = (0..r.range(5, 40)).map(|_| vec![r.next() as u8]).collect();
				raw(port, chunks, Duration::from_millis(r.range(20, 100) as u64), r).await
			}),
		),
		(
			"huge_write",
			job(move |mut r| async move {
				// megabytes without reading the echo, then a RST
				let mut s = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
				let data = r.bytes_in(1 << 20, 8 << 20);
				let _ = tokio::time::timeout(Duration::from_millis(1500), s.write_all(&data)).await;
				reset(&s);
				Ok(())
			}),
		),
		(
			"reset_midstream",
			job(move |mut r| async move {
				let mut s = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
				let _ = s.write_all(&r.bytes_in(1, 100_000)).await;
				let mut buf = vec![0u8; r.range(1, 50_000)];
				let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut buf)).await;
				reset(&s);
				Ok(())
			}),
		),
	];
	exercise(&s, "tcp", legit, hostile).await;
}

// ---- TLS ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_survives_hostile_traffic() {
	let pki = Arc::new(Pki::new("hostile-tls"));
	let behind = pki.server("behind", &["a.test", "p.test"]);
	let front = pki.server("front", &["b.test", "c.test"]);
	let tls_backend = tls_echo_backend(&pki, &behind).await;
	let plain = echo_backend().await;
	let (sni, term, pass) = (free_port(), free_port(), free_port());
	let cert = json!([{"cert_file": front.cert_file, "key_file": front.key_file}]);
	let mut rules = vec![rule("tcp", sni, tls_backend), rule("tcp", term, plain), rule("tcp", pass, plain)];
	rules[0]["tls"] =
		json!({"mode": "sni", "routes": [{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": tls_backend.port()}]});
	rules[1]["tls"] = json!({"mode": "terminate", "certificates": cert});
	rules[2]["tls"] = json!({
		"mode": "terminate",
		"certificates": cert,
		"routes": [
			{"server_name": "p.test", "remote_addr": "127.0.0.1", "remote_port": tls_backend.port(), "passthrough": true},
			{"server_name": "c.test", "remote_addr": "127.0.0.1", "remote_port": plain.port()},
		],
		"unmatched": "reject",
	});
	let s = Server::start("tls", rules).await;

	let targets = Arc::new([(sni, "a.test"), (term, "b.test"), (pass, "p.test"), (pass, "c.test")]);
	let legit = {
		let pki = pki.clone();
		job(move |mut r| {
			let (pki, (port, name)) = (pki.clone(), *r.pick(&targets[..]));
			async move {
				let tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
				let tls = pki.connector(None).connect(name.try_into().unwrap(), tcp).await.map_err(|e| format!("TLS to {name}: {e}"))?;
				let len = r.range(1, 48 * 1024);
				echo_exchange(tls, len, &mut r).await.map_err(|e| format!("{name}: {e}"))
			}
		})
	};
	let hostile = tls_attacks(vec![sni, term, pass], &["a.test", "b.test", "c.test", "p.test", "x.test"]);
	exercise(&s, "tls", legit, hostile).await;
}

// ---- HTTP ----

/// Echoes the request body, and the `x-id` header back; counts requests smuggled
/// in behind another one (`/injected`, sent after a body whose framing is ambiguous).
/// A header on the hostile client's own request is not counted: HTTP/1.1 lets a
/// recipient take a bare LF as a line end, so `X-A: a\nX-Injected: 1` is two headers
/// of that request, and rproxy writes the request out again for the backend.
async fn http_backend(smuggled: Arc<AtomicU64>) -> SocketAddr {
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
		let smuggled = smuggled.clone();
		async move {
			if req.uri().path().contains("injected") {
				smuggled.fetch_add(1, Ordering::Relaxed);
			}
			let id = req.headers().get("x-id").cloned();
			match axum::body::to_bytes(req.into_body(), 16 << 20).await {
				Ok(body) => {
					let mut resp = axum::response::Response::new(axum::body::Body::from(body));
					if let Some(id) = id {
						resp.headers_mut().insert("x-id", id);
					}
					resp
				}
				Err(_) => {
					let mut resp = axum::response::Response::new(axum::body::Body::empty());
					*resp.status_mut() = StatusCode::BAD_REQUEST;
					resp
				}
			}
		}
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

/// An HTTP/2 frame.
fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
	let mut f = (payload.len() as u32).to_be_bytes()[1..].to_vec();
	f.extend_from_slice(&[kind, flags]);
	f.extend_from_slice(&stream.to_be_bytes());
	f.extend_from_slice(payload);
	f
}

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Broken and malicious HTTP/1.1 and HTTP/2 requests.
fn http_attacks(port: u16) -> Vec<(&'static str, Job)> {
	type Gen = fn(&mut Rng) -> Vec<u8>;
	let gens: Vec<(&'static str, Gen)> = vec![
		("invalid_method", |r| {
			let method: Vec<u8> = match r.range(0, 5) {
				0 => b"G\0T".to_vec(),
				1 => b"GE T".to_vec(),
				2 => vec![b'A'; r.range(100, 100_000)],
				3 => r.bytes_in(1, 20),
				_ => b"".to_vec(),
			};
			[method, b" / HTTP/1.1\r\nHost: h.test\r\n\r\n".to_vec()].concat()
		}),
		("missing_host", |r| {
			r.pick(&[
				&b"GET / HTTP/1.1\r\n\r\n"[..],
				b"GET / HTTP/1.1\r\nHost:\r\n\r\n",
				b"GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n",
				b"GET http://other.test/ HTTP/1.1\r\nHost: h.test\r\n\r\n",
				b"GET / HTTP/1.0\r\n\r\n",
				b"GET / HTTP/9.9\r\nHost: h.test\r\n\r\n",
				b"GET /\r\n\r\n",
			])
			.to_vec()
		}),
		("huge_header", |r| {
			let mut req = b"GET / HTTP/1.1\r\nHost: h.test\r\nX-Big: ".to_vec();
			req.extend(vec![b'a'; r.range(64 * 1024, 1 << 20)]);
			req.extend_from_slice(b"\r\n\r\n");
			req
		}),
		("many_headers", |r| {
			let mut req = b"GET / HTTP/1.1\r\nHost: h.test\r\n".to_vec();
			for i in 0..r.range(100, 20_000) {
				req.extend(format!("X-H{i}: v\r\n").into_bytes());
			}
			req.extend_from_slice(b"\r\n");
			req
		}),
		("long_uri", |r| {
			let mut req = b"GET /".to_vec();
			req.extend(vec![b'u'; r.range(8 * 1024, 1 << 20)]);
			req.extend_from_slice(b" HTTP/1.1\r\nHost: h.test\r\n\r\n");
			req
		}),
		("invalid_chunked", |r| {
			let body = *r.pick(&[
				&b"zz\r\nabc\r\n0\r\n\r\n"[..],
				b"ffffffffffffffffffffffff\r\nabc\r\n",
				b"5\r\nabc\r\n",
				b"3\r\nabcdef\r\n0\r\n\r\n",
				b"-1\r\nx\r\n0\r\n\r\n",
				b"3;ext=\x01\x02\r\nabc\r\n0\r\n\r\n",
				b"0\r\nBad Trailer\r\n\r\n",
				b"3\nabc\n0\n\n",
				b"3\r\nabc",
			]);
			[b"POST /chunked HTTP/1.1\r\nHost: h.test\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(), body.to_vec()].concat()
		}),
		("smuggling", |r| {
			let head = *r.pick(&[
				&b"Content-Length: 6\r\nTransfer-Encoding: chunked\r\n"[..],
				b"Transfer-Encoding: chunked\r\nContent-Length: 6\r\n",
				b"Content-Length: 4\r\nContent-Length: 40\r\n",
				b"Content-Length: 4, 40\r\n",
				b"Content-Length: +4\r\n",
				b"Content-Length: 99999999999999999999999\r\n",
				b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n",
				b"Transfer-Encoding: xchunked\r\n",
				b"Transfer-Encoding : chunked\r\n",
				b"Transfer-Encoding:\x0bchunked\r\n",
				b"X-Fold: a\r\n Transfer-Encoding: chunked\r\n",
				b"Transfer-Encoding: chunked, identity\r\n",
			]);
			[
				b"POST /smuggle HTTP/1.1\r\nHost: h.test\r\n".to_vec(),
				head.to_vec(),
				b"\r\n0\r\n\r\nGET /injected HTTP/1.1\r\nHost: h.test\r\nX-Injected: 1\r\n\r\n".to_vec(),
			]
			.concat()
		}),
		("header_injection", |r| {
			let line = *r.pick(&[
				&b"X-A: a\rX-Injected: 1\r\n"[..],
				b"X-A: a\nX-Injected: 1\r\n",
				b"X-A: a\0X-Injected: 1\r\n",
				b"X Injected: 1\r\n",
				b"X-Injected\r\n",
				b": empty-name\r\n",
				b"X-A: \xff\xfe\r\n",
				b"Host: h.test\r\n\r\n\r\nX-Injected: 1\r\n",
			]);
			[b"GET / HTTP/1.1\r\nHost: h.test\r\n".to_vec(), line.to_vec(), b"\r\n".to_vec()].concat()
		}),
		("pipelined_garbage", |r| {
			let mut req = b"GET /a HTTP/1.1\r\nHost: h.test\r\n\r\n".to_vec();
			req.extend(r.bytes_in(1, 2000));
			req.extend_from_slice(b"\r\n\r\nGET /b HTTP/1.1\r\nHost: h.test\r\n\r\n");
			req
		}),
		("h2_preface_garbage", |r| {
			let mut data = H2_PREFACE.to_vec();
			match r.range(0, 4) {
				0 => data.extend(r.bytes_in(1, 5000)),
				1 => {
					// frames of random types, flags, streams and lengths
					for _ in 0..r.range(1, 50) {
						let payload = r.bytes_in(0, 2000);
						data.extend(h2_frame(r.next() as u8, r.next() as u8, r.next() as u32, &payload));
					}
				}
				2 => {
					// a frame claiming 16 MiB
					data.extend_from_slice(&[0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 1]);
					data.extend(r.bytes_in(0, 70_000));
				}
				_ => data.truncate(r.range(1, H2_PREFACE.len())),
			}
			data
		}),
		("h2_continuation_flood", |r| {
			// HEADERS without END_HEADERS, then CONTINUATION frames without end
			let mut data = H2_PREFACE.to_vec();
			data.extend(h2_frame(4, 0, 0, &[]));
			data.extend(h2_frame(1, 0, 1, &r.bytes_in(1, 100)));
			for _ in 0..r.range(100, 3000) {
				data.extend(h2_frame(9, 0, 1, &r.bytes_in(1, 1000)));
			}
			data
		}),
		("partial_body", |r| {
			let mut req = format!("POST / HTTP/1.1\r\nHost: h.test\r\nContent-Length: {}\r\n\r\n", r.range(1000, 1 << 30)).into_bytes();
			req.extend(r.bytes_in(0, 500));
			req
		}),
		("upgrade_garbage", |r| {
			let mut req = b"GET / HTTP/1.1\r\nHost: h.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".to_vec();
			req.extend(r.bytes_in(0, 4000));
			req
		}),
		("random_bytes", |r| r.bytes_in(1, 8192)),
	];
	let mut out: Vec<(&'static str, Job)> = gens
		.into_iter()
		.map(|(name, gen)| {
			(
				name,
				job(move |mut r: Rng| async move {
					let data = gen(&mut r);
					let chunks = pieces(&data, false, &mut r);
					raw(port, chunks, Duration::ZERO, r).await
				}),
			)
		})
		.collect();
	out.push((
		"slowloris",
		job(move |mut r| async move {
			let req = b"GET /slow HTTP/1.1\r\nHost: h.test\r\nX-A: b\r\n\r\n";
			let n = r.range(5, 30);
			raw(port, pieces(&req[..n], true, &mut r), Duration::from_millis(r.range(30, 120) as u64), r).await
		}),
	));
	out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_survives_hostile_traffic() {
	let smuggled = Arc::new(AtomicU64::new(0));
	let backend = http_backend(smuggled.clone()).await;
	let port = free_port();
	let rules = vec![json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}")}],
	}})];
	let s = Server::start("http", rules).await;

	let legit = job(move |mut r| async move {
		let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().map_err(err("client"))?;
		for _ in 0..r.range(1, 4) {
			let id = r.hex(16);
			let body = if r.one_in(8) { r.bytes_in(256 * 1024, 2 << 20) } else { r.bytes_in(0, 32 * 1024) };
			let resp = client
				.post(format!("http://127.0.0.1:{port}/echo/{id}"))
				.header("x-id", &id)
				.body(body.clone())
				.send()
				.await
				.map_err(err("request"))?;
			let status = resp.status();
			let echoed = resp.headers().get("x-id").and_then(|v| v.to_str().ok()).map(str::to_string);
			let got = resp.bytes().await.map_err(err("response body"))?;
			if status != StatusCode::OK || echoed.as_deref() != Some(id.as_str()) {
				return Err(format!("request {id}: status {status}, x-id {echoed:?}"));
			}
			if got[..] != body[..] {
				return Err(format!("request {id}: the body came back different ({} bytes sent, {} received)", body.len(), got.len()));
			}
		}
		Ok(())
	});
	exercise(&s, "http", legit, http_attacks(port)).await;
	assert_eq!(smuggled.load(Ordering::Relaxed), 0, "a header or request injected by a hostile client reached the backend");
}

// ---- STARTTLS ----

#[derive(Clone, Copy)]
enum Mail {
	Smtp,
	Imap,
	Pop3,
}

/// A plain mail server echoing each command in its reply; notes any command
/// carrying the marker the hostile clients inject before TLS.
async fn mail_backend(mail: Mail, injected: Arc<AtomicU64>) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut s, _)) = listener.accept().await {
			let injected = injected.clone();
			tokio::spawn(async move {
				let greeting: &[u8] = match mail {
					Mail::Smtp => b"220 mail.backend ESMTP\r\n",
					Mail::Imap => b"* OK backend ready\r\n",
					Mail::Pop3 => b"+OK backend ready\r\n",
				};
				if s.write_all(greeting).await.is_err() {
					return;
				}
				let mut lines = Lines::default();
				while let Ok(Some(line)) = lines.next(&mut s).await {
					if line.contains("INJECTED") {
						injected.fetch_add(1, Ordering::Relaxed);
					}
					let reply = match mail {
						Mail::Smtp if line.to_ascii_uppercase().starts_with("EHLO") => "250-mail.backend\r\n250 PIPELINING\r\n".to_string(),
						Mail::Smtp => format!("250 {line}\r\n"),
						Mail::Imap => {
							format!("{} OK {line}\r\n", line.split(' ').next().unwrap_or("*"))
						}
						Mail::Pop3 => format!("+OK {line}\r\n"),
					};
					if s.write_all(reply.as_bytes()).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

async fn line<S: AsyncRead + Unpin>(lines: &mut Lines, s: &mut S) -> Result<String, String> {
	lines.next(s).await.map_err(err("read"))?.ok_or_else(|| "connection closed".to_string())
}

/// Reads one reply: SMTP continues while the 4th byte is '-'. The last line.
async fn reply<S: AsyncRead + Unpin>(lines: &mut Lines, s: &mut S, mail: Mail) -> Result<String, String> {
	loop {
		let l = line(lines, s).await?;
		if !(matches!(mail, Mail::Smtp) && l.as_bytes().get(3) == Some(&b'-')) {
			return Ok(l);
		}
	}
}

/// Up to STARTTLS: greeting, (EHLO,) the STARTTLS command and its positive answer.
async fn upgrade(s: &mut TcpStream, mail: Mail) -> Result<(), String> {
	let mut lines = Lines::default();
	reply(&mut lines, s, mail).await?;
	let cmd: &[u8] = match mail {
		Mail::Smtp => {
			s.write_all(b"EHLO client.test\r\n").await.map_err(err("write"))?;
			reply(&mut lines, s, mail).await?;
			b"STARTTLS\r\n"
		}
		Mail::Imap => b"a1 STARTTLS\r\n",
		Mail::Pop3 => b"STLS\r\n",
	};
	s.write_all(cmd).await.map_err(err("write"))?;
	let answer = reply(&mut lines, s, mail).await?;
	let ok = match mail {
		Mail::Smtp => answer.starts_with("220"),
		Mail::Imap => answer.starts_with("a1 OK"),
		Mail::Pop3 => answer.starts_with("+OK"),
	};
	if ok {
		Ok(())
	} else {
		Err(format!("STARTTLS refused: {answer}"))
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn starttls_survives_hostile_traffic() {
	let pki = Arc::new(Pki::new("hostile-mail"));
	let cert = pki.server("mx", &["mx.test"]);
	let injected = Arc::new(AtomicU64::new(0));
	let mut rules = vec![];
	let mut ports = vec![];
	for (mail, name) in [(Mail::Smtp, "smtp"), (Mail::Imap, "imap"), (Mail::Pop3, "pop3")] {
		let port = free_port();
		let mut r = rule("tcp", port, mail_backend(mail, injected.clone()).await);
		r["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]});
		r["starttls"] = json!(name);
		r["starttls_required"] = json!(true);
		rules.push(r);
		ports.push((port, mail));
	}
	let s = Server::start("starttls", rules).await;
	let ports = Arc::new(ports);

	let legit = {
		let (pki, ports) = (pki.clone(), ports.clone());
		job(move |mut r| {
			let (pki, (port, mail)) = (pki.clone(), *r.pick(&ports[..]));
			async move {
				let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
				upgrade(&mut tcp, mail).await?;
				let mut tls = pki.connector(None).connect("mx.test".try_into().unwrap(), tcp).await.map_err(err("TLS"))?;
				let mut lines = Lines::default();
				for _ in 0..r.range(1, 4) {
					let len = r.range(8, 200);
					let token = r.hex(len);
					let (cmd, want) = match mail {
						Mail::Smtp => (format!("MAIL FROM:<{token}@x.test>"), format!("250 MAIL FROM:<{token}@x.test>")),
						Mail::Imap => (format!("t1 NOOP {token}"), format!("t1 OK t1 NOOP {token}")),
						Mail::Pop3 => (format!("NOOP {token}"), format!("+OK NOOP {token}")),
					};
					tls.write_all(format!("{cmd}\r\n").as_bytes()).await.map_err(err("write"))?;
					let got = reply(&mut lines, &mut tls, mail).await?;
					if got != want {
						return Err(format!("expected {want:?}, got {got:?}"));
					}
				}
				Ok(())
			}
		})
	};

	let pick = |r: &mut Rng, ports: &[(u16, Mail)]| *r.pick(ports);
	let mut hostile: Vec<(&'static str, Job)> = vec![];
	macro_rules! attack {
		($name:literal, |$r:ident, $port:ident, $mail:ident, $pki:ident| $body:expr) => {{
			let (ports, pki) = (ports.clone(), pki.clone());
			hostile.push((
				$name,
				job(move |mut $r: Rng| {
					let ($port, $mail) = pick(&mut $r, &ports);
					let $pki = pki.clone();
					async move { $body }
				}),
			));
		}};
	}
	attack!("random_bytes", |r, port, _mail, _pki| raw(port, vec![r.bytes_in(1, 8192)], Duration::ZERO, r).await);
	attack!("injected_commands", |r, port, mail, _pki| {
		// commands after STARTTLS in the same write must never reach the server
		let data: &[u8] = match mail {
			Mail::Smtp => b"EHLO x.test\r\nSTARTTLS\r\nMAIL FROM:<INJECTED@x.test>\r\nRCPT TO:<INJECTED@x.test>\r\n",
			Mail::Imap => b"a1 STARTTLS\r\na2 LOGIN INJECTED secret\r\n",
			Mail::Pop3 => b"STLS\r\nUSER INJECTED\r\nPASS secret\r\n",
		};
		let mut s = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
		let mut lines = Lines::default();
		let _ = line(&mut lines, &mut s).await;
		s.write_all(data).await.map_err(err("write"))?;
		drain(&mut s, Duration::from_millis(r.range(50, 500) as u64)).await;
		Ok(())
	});
	attack!("commands_before_tls", |r, port, mail, _pki| {
		// plain-text commands that need TLS, and too many of them
		let cmd: &[u8] = match mail {
			Mail::Smtp => b"MAIL FROM:<INJECTED@x.test>\r\n",
			Mail::Imap => b"a LOGIN INJECTED secret\r\n",
			Mail::Pop3 => b"USER INJECTED\r\n",
		};
		raw(port, vec![cmd.repeat(r.range(1, 2000))], Duration::ZERO, r).await
	});
	attack!("long_line", |r, port, _mail, _pki| {
		let data = vec![b'A'; r.range(4000, 2 << 20)];
		raw(port, pieces(&data, false, &mut r), Duration::ZERO, r).await
	});
	attack!("control_bytes", |r, port, _mail, _pki| {
		let line = *r.pick(&[&b"EHLO a\0b\r\n"[..], b"STARTTLS\rINJECTED\r\n", b"\xff\xfe\xfd\r\n", b"\r\n\r\n\r\n", b"STARTTLS\n"]);
		raw(port, vec![line.to_vec()], Duration::ZERO, r).await
	});
	attack!("garbage_instead_of_hello", |r, port, mail, _pki| {
		let mut s = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
		upgrade(&mut s, mail).await?;
		let data = match r.range(0, 3) {
			0 => r.bytes_in(1, 4096),
			1 => {
				let hello = real_hello("mx.test");
				hello[..r.range(1, hello.len())].to_vec()
			}
			_ => mutate(real_hello("mx.test"), &mut r),
		};
		let _ = s.write_all(&data).await;
		drain(&mut s, Duration::from_millis(r.range(0, 500) as u64)).await;
		Ok(())
	});
	attack!("hello_without_starttls", |r, port, _mail, _pki| raw(port, vec![real_hello("mx.test")], Duration::ZERO, r).await);
	attack!("slowloris", |r, port, _mail, _pki| {
		let chunks = pieces(b"EHLO slow.test\r\n", true, &mut r);
		raw(port, chunks, Duration::from_millis(r.range(30, 120) as u64), r).await
	});
	attack!("tls_then_gone", |r, port, mail, pki| {
		// a real upgrade and handshake, then a RST
		let mut s = TcpStream::connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
		upgrade(&mut s, mail).await?;
		let tls = pki.connector(None).connect("mx.test".try_into().unwrap(), s).await.map_err(err("TLS"))?;
		reset(tls.get_ref().0);
		if r.one_in(2) {
			drop(tls);
		}
		Ok(())
	});
	exercise(&s, "starttls", legit, hostile).await;
	assert_eq!(injected.load(Ordering::Relaxed), 0, "a command sent before TLS reached the mail server");
}

// ---- UDP ----

/// UDP echo: every datagram back as it came.
async fn udp_echo_backend() -> SocketAddr {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr = sock.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = vec![0u8; 65536];
		while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
			let _ = sock.send_to(&buf[..n], peer).await;
		}
	});
	addr
}

/// Datagrams with a sequence number and random payloads, each resent until its
/// echo comes back (a datagram may be lost under the flood); every reply must
/// be one of the datagrams sent, byte for byte.
async fn udp_exchange(port: u16, r: &mut Rng) -> Result<(), String> {
	let sock = UdpSocket::bind((FROM_PLAIN, 0)).await.map_err(err("bind"))?;
	sock.connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
	let mut sent: Vec<Vec<u8>> = vec![];
	let mut buf = vec![0u8; 65536];
	for seq in 0..r.range(1, 8) as u64 {
		let mut d = seq.to_be_bytes().to_vec();
		d.extend(r.bytes_in(0, 1400));
		sent.push(d.clone());
		let mut answered = false;
		for _ in 0..10 {
			sock.send(&d).await.map_err(err("send"))?;
			let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
			while let Ok(got) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
				let n = got.map_err(err("recv"))?;
				if buf[..n] == d[..] {
					answered = true;
					break;
				}
				if !sent.iter().any(|s| s[..] == buf[..n]) {
					return Err(format!("a reply that was never sent: {} bytes", n));
				}
			}
			if answered {
				break;
			}
		}
		if !answered {
			return Err(format!("datagram {seq} got no echo after 10 tries"));
		}
	}
	Ok(())
}

const ALPN: &[u8] = b"echo";

/// A QUIC echo server: `tag` + what came on each stream.
async fn quic_backend(issued: &Issued, tag: &'static str) -> SocketAddr {
	let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_no_client_auth()
		.with_single_cert(issued.full_chain(), issued.key_der())
		.unwrap();
	tls.alpn_protocols = vec![ALPN.to_vec()];
	let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
	let endpoint = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), "127.0.0.1:0".parse().unwrap()).unwrap();
	let addr = endpoint.local_addr().unwrap();
	tokio::spawn(async move {
		while let Some(incoming) = endpoint.accept().await {
			tokio::spawn(async move {
				let Ok(conn) = incoming.await else { return };
				while let Ok((mut send, mut recv)) = conn.accept_bi().await {
					let Ok(data) = recv.read_to_end(64 * 1024).await else {
						return;
					};
					let _ = send.write_all(&[tag.as_bytes(), &data].concat()).await;
					let _ = send.finish();
				}
			});
		}
	});
	addr
}

fn quic_client(pki: &Pki) -> Result<quinn::Endpoint, String> {
	let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_root_certificates(pki.roots())
		.with_no_client_auth();
	tls.alpn_protocols = vec![ALPN.to_vec()];
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
	let mut config = quinn::ClientConfig::new(Arc::new(crypto));
	let mut transport = quinn::TransportConfig::default();
	transport.max_idle_timeout(Some(Duration::from_secs(3).try_into().unwrap()));
	config.transport_config(Arc::new(transport));
	let mut endpoint = quinn::Endpoint::client((FROM_QUIC, 0).into()).map_err(err("QUIC endpoint"))?;
	endpoint.set_default_client_config(config);
	Ok(endpoint)
}

async fn quic_echo(pki: &Pki, port: u16, name: &str, msg: &[u8]) -> Result<Vec<u8>, String> {
	let endpoint = quic_client(pki)?;
	let connecting = endpoint.connect(SocketAddr::from(([127, 0, 0, 1], port)), name).map_err(err("QUIC connect"))?;
	let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
		.await
		.map_err(|_| "QUIC handshake timed out".to_string())?
		.map_err(err("QUIC handshake"))?;
	let (mut send, mut recv) = conn.open_bi().await.map_err(err("open stream"))?;
	send.write_all(msg).await.map_err(err("QUIC write"))?;
	send.finish().map_err(err("QUIC finish"))?;
	let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
		.await
		.map_err(|_| "no QUIC reply".to_string())?
		.map_err(err("QUIC read"))?;
	conn.close(0u32.into(), b"done");
	endpoint.wait_idle().await;
	Ok(reply)
}

// UDP sessions are keyed by the client's address and outlive its socket for
// `udp_idle_secs`, so a client that gets a port another kind of client just
// let go would land in that one's session. Each kind sends from its own address.
const FROM_PLAIN: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const FROM_QUIC: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
const FROM_DTLS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const FROM_HOSTILE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

/// A DTLS echo server: `tag` + each datagram.
async fn dtls_backend(issued: &Issued, tag: &'static str) -> SocketAddr {
	let listener = dtls::listener::listen(
		"127.0.0.1:0",
		DtlsConfig { certificates: vec![issued.dtls()], extended_master_secret: ExtendedMasterSecretType::Require, ..Default::default() },
	)
	.await
	.unwrap();
	let addr = listener.addr().await.unwrap();
	tokio::spawn(async move {
		while let Ok((conn, _)) = listener.accept().await {
			tokio::spawn(async move {
				let mut buf = vec![0u8; 1500];
				while let Ok(n) = conn.recv(&mut buf).await {
					if conn.send(&[tag.as_bytes(), &buf[..n]].concat()).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

async fn dtls_echo(pki: &Pki, port: u16, name: &str, msg: &[u8]) -> Result<Vec<u8>, String> {
	let sock = UdpSocket::bind((FROM_DTLS, 0)).await.map_err(err("bind"))?;
	sock.connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(sock);
	let config = DtlsConfig {
		roots_cas: pki.roots(),
		server_name: name.to_string(),
		extended_master_secret: ExtendedMasterSecretType::Require,
		..Default::default()
	};
	// UDP under the flood loses datagrams; a lost flight costs a retransmission
	let c = tokio::time::timeout(Duration::from_secs(10), DTLSConn::new(conn, config, true, None))
		.await
		.map_err(|_| format!("DTLS handshake for {name} timed out"))?
		.map_err(|e| format!("DTLS handshake for {name}: {e}"))?;
	// application data is not retransmitted by DTLS: resend until the echo comes back
	let mut buf = vec![0u8; 1500];
	for _ in 0..5 {
		c.write(msg, None).await.map_err(err("DTLS write"))?;
		if let Ok(got) = tokio::time::timeout(Duration::from_secs(1), c.read(&mut buf, None)).await {
			let n = got.map_err(err("DTLS read"))?;
			let _ = c.close().await;
			return Ok(buf[..n].to_vec());
		}
	}
	Err(format!("no DTLS reply from {name}"))
}

/// The first datagram a real QUIC client sends (its Initial with the ClientHello).
async fn captured_quic_initial(pki: &Pki, name: &str) -> Vec<u8> {
	let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let endpoint = quic_client(pki).unwrap();
	let _connecting = endpoint.connect(sink.local_addr().unwrap(), name).unwrap();
	let mut buf = vec![0u8; 65536];
	let n = tokio::time::timeout(Duration::from_secs(5), sink.recv(&mut buf)).await.unwrap().unwrap();
	buf.truncate(n);
	buf
}

/// The first datagram a real DTLS client sends (its ClientHello).
async fn captured_dtls_hello(pki: &Pki, name: &str) -> Vec<u8> {
	let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(sink.local_addr().unwrap()).await.unwrap();
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(sock);
	let config = DtlsConfig {
		roots_cas: pki.roots(),
		server_name: name.to_string(),
		extended_master_secret: ExtendedMasterSecretType::Require,
		..Default::default()
	};
	let client = tokio::spawn(async move {
		let _ = DTLSConn::new(conn, config, true, None).await;
	});
	let mut buf = vec![0u8; 65536];
	let n = tokio::time::timeout(Duration::from_secs(5), sink.recv(&mut buf)).await.unwrap().unwrap();
	client.abort();
	buf.truncate(n);
	buf
}

/// Sends `datagrams` from one new socket, reads a little, and goes away.
async fn burst(port: u16, datagrams: Vec<Vec<u8>>, r: &mut Rng) -> Result<(), String> {
	let sock = UdpSocket::bind((FROM_HOSTILE, 0)).await.map_err(err("bind"))?;
	sock.connect(("127.0.0.1", port)).await.map_err(err("connect"))?;
	for d in datagrams {
		// EMSGSIZE and the like are the attack's problem
		let _ = sock.send(&d).await;
	}
	let mut buf = vec![0u8; 65536];
	let _ = tokio::time::timeout(Duration::from_millis(r.range(0, 300) as u64), sock.recv(&mut buf)).await;
	Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_survives_hostile_traffic() {
	let pki = Arc::new(Pki::new("hostile-udp"));
	let behind = pki.server("behind", &["q.test", "d.test"]);
	let front = pki.server("front", &["t.test"]);
	let (quic, dtls, echo) = (quic_backend(&behind, "Q:").await, dtls_backend(&behind, "D:").await, udp_echo_backend().await);
	let (plain, sni, term) = (free_udp_port(), free_udp_port(), free_udp_port());
	let mut rules = vec![rule("udp", plain, echo), rule("udp", sni, echo), rule("udp", term, echo)];
	for r in &mut rules {
		// sessions of hostile clients go away soon after the load
		r["udp_idle_secs"] = json!(2);
	}
	rules[1]["tls"] = json!({"mode": "sni", "routes": [
		{"server_name": "q.test", "remote_addr": "127.0.0.1", "remote_port": quic.port()},
		{"server_name": "d.test", "remote_addr": "127.0.0.1", "remote_port": dtls.port()},
	]});
	rules[2]["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}]});
	let s = Server::start("udp", rules).await;

	let legit = {
		let pki = pki.clone();
		job(move |mut r| {
			let pki = pki.clone();
			async move {
				let msg = r.bytes_in(1, 1000);
				match r.range(0, 5) {
					// plain datagrams on the plain rule, and on the sni rule (its own target)
					0 => udp_exchange(plain, &mut r).await,
					1 => udp_exchange(sni, &mut r).await,
					2 => {
						let got = quic_echo(&pki, sni, "q.test", &msg).await?;
						(got == [b"Q:", &msg[..]].concat()).then_some(()).ok_or_else(|| "QUIC echo differs".to_string())
					}
					3 => {
						let got = dtls_echo(&pki, sni, "d.test", &msg).await?;
						(got == [b"D:", &msg[..]].concat()).then_some(()).ok_or_else(|| "DTLS (sni) echo differs".to_string())
					}
					_ => {
						let got = dtls_echo(&pki, term, "t.test", &msg).await?;
						(got == msg).then_some(()).ok_or_else(|| "DTLS (terminate) echo differs".to_string())
					}
				}
			}
		})
	};

	let initials = Arc::new(vec![captured_quic_initial(&pki, "q.test").await, captured_quic_initial(&pki, "x.test").await]);
	let hellos = Arc::new(vec![captured_dtls_hello(&pki, "d.test").await]);
	let ports = Arc::new([plain, sni, term]);
	let mut hostile: Vec<(&'static str, Job)> = vec![];
	macro_rules! attack {
		($name:literal, |$r:ident, $port:ident, $initials:ident, $hellos:ident| $body:expr) => {{
			let (ports, initials, hellos) = (ports.clone(), initials.clone(), hellos.clone());
			hostile.push((
				$name,
				job(move |mut $r: Rng| {
					let ($port, $initials, $hellos) = (*$r.pick(&ports[..]), initials.clone(), hellos.clone());
					async move { $body }
				}),
			));
		}};
	}
	attack!("random_datagrams", |r, port, _i, _h| {
		let ds = (0..r.range(1, 20)).map(|_| r.bytes_in(0, 1500)).collect();
		burst(port, ds, &mut r).await
	});
	attack!("oversized_datagrams", |r, port, _i, _h| {
		let ds = (0..r.range(1, 4)).map(|_| r.bytes_in(9000, 65_507)).collect();
		burst(port, ds, &mut r).await
	});
	attack!("many_source_ports", |r, port, _i, _h| {
		// a new session from each of many ports
		let mut socks = vec![];
		for _ in 0..r.range(16, 64) {
			let sock = UdpSocket::bind((FROM_HOSTILE, 0)).await.map_err(err("bind"))?;
			let _ = sock.send_to(&r.bytes_in(1, 200), ("127.0.0.1", port)).await;
			socks.push(sock);
		}
		tokio::time::sleep(Duration::from_millis(r.range(0, 200) as u64)).await;
		Ok(())
	});
	attack!("quic_garbage", |r, port, _i, _h| {
		// long headers with any version and connection ID lengths, short headers
		let ds = (0..r.range(1, 8))
			.map(|_| {
				let mut d = r.bytes_in(1, 1500);
				d[0] = if r.one_in(4) { 0x40 | (d[0] & 0x3f) } else { 0xc0 | (d[0] & 0x3f) };
				if d.len() > 6 {
					let version: [u8; 4] = *r.pick(&[[0, 0, 0, 1], [0x6b, 0x33, 0x43, 0xcf], [0, 0, 0, 0], [0xff, 0, 0, 0x1d]]);
					d[1..5].copy_from_slice(&version);
					d[5] = r.next() as u8;
				}
				d
			})
			.collect();
		burst(port, ds, &mut r).await
	});
	attack!("quic_initial_mutated", |r, port, initials, _h| {
		let initial = r.pick(&initials[..]).clone();
		let d = match r.range(0, 3) {
			0 => initial[..r.range(1, initial.len())].to_vec(),
			1 => mutate(initial, &mut r),
			// the same Initial again and again (replayed)
			_ => initial,
		};
		let n = r.range(1, 20);
		burst(port, vec![d; n], &mut r).await
	});
	attack!("dtls_garbage", |r, port, _i, _h| {
		// handshake records with lying fragment headers
		let ds = (0..r.range(1, 20))
			.map(|_| {
				let mut d = vec![0x16, 0xfe, 0xfd, 0, 0];
				d.extend(r.bytes(6));
				let body = r.bytes_in(0, 1200);
				d.extend_from_slice(&((body.len() + 12) as u16).to_be_bytes());
				d.push(1);
				d.extend(r.bytes(3)); // message length
				d.extend(r.bytes(2)); // message sequence
				d.extend(r.bytes(3)); // fragment offset
				d.extend(r.bytes(3)); // fragment length
				d.extend(body);
				d
			})
			.collect();
		burst(port, ds, &mut r).await
	});
	attack!("empty_datagrams", |r, port, _i, _h| burst(port, vec![vec![]; r.range(1, 50)], &mut r).await);
	exercise(&s, "udp", legit, hostile).await;
}
