//! Stall probe (#187): repeats the 1 MiB echo of the `dataplane` benchmark many
//! times with a timeout per iteration, in several variants, to tell a problem of
//! the benchmark harness from a stall in rproxy:
//!
//! - through rproxy: L4 TCP, and TLS `terminate`
//! - TLS directly to a TLS echo server (no rproxy at all)
//! - the client flushing after writing, or not (as the benchmark did before #187)
//! - the default client send buffer, or a 4 KiB one (makes a full socket common)
//! - rproxy in this process on the same tokio runtime as the clients (like the
//!   benchmark, `--rproxy` not given), or rproxy as its own process (`--rproxy <binary>`)
//!
//! A stalled iteration is recorded (with how far each side got and whether the TLS
//! client still holds unsent records) and the connection is replaced; a variant
//! stops after `MAX_STALLS`. Prints a
//! Markdown table (also to `$GITHUB_STEP_SUMMARY`) and exits 1 if a variant that
//! flushes stalled — that is never the harness.
//!
//!     cargo run --release --example stall_probe -- [--iters 300] [--timeout 3] [--rproxy target/release/rproxy-api]

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::pki::Pki;

const SIZE: usize = 1024 * 1024;
/// A variant stops after this many stalls (enough to see the pattern).
const MAX_STALLS: usize = 5;

struct Args {
	iters: usize,
	timeout: Duration,
	rproxy: Option<String>,
}

fn args() -> Args {
	let mut a = Args { iters: 300, timeout: Duration::from_secs(3), rproxy: None };
	let mut it = std::env::args().skip(1);
	while let Some(k) = it.next() {
		let v = it.next().unwrap_or_else(|| panic!("{k} needs a value"));
		match k.as_str() {
			"--iters" => a.iters = v.parse().unwrap(),
			"--timeout" => a.timeout = Duration::from_secs(v.parse().unwrap()),
			"--rproxy" => a.rproxy = Some(v),
			other => panic!("unknown option {other}"),
		}
	}
	a
}

async fn tcp_echo() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			s.set_nodelay(true).unwrap();
			tokio::spawn(async move {
				let (mut r, mut w) = s.split();
				let _ = tokio::io::copy(&mut r, &mut w).await;
			});
		}
	});
	addr
}

/// A TLS echo server, for the variant without rproxy. tokio's copy flushes when it has nothing to read.
async fn tls_echo(acceptor: tokio_rustls::TlsAcceptor) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (s, _) = listener.accept().await.unwrap();
			s.set_nodelay(true).unwrap();
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				let Ok(tls) = acceptor.accept(s).await else { return };
				let (mut r, mut w) = tokio::io::split(tls);
				let _ = tokio::io::copy(&mut r, &mut w).await;
			});
		}
	});
	addr
}

fn free_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// rproxy as its own process, with the two rules in a configuration file.
struct External(std::process::Child);

impl Drop for External {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

async fn wait_listening(port: u16) {
	for _ in 0..100 {
		if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
			return;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	panic!("rproxy did not listen on {port}");
}

/// How one iteration ended when it did not finish in time.
struct Stall {
	iteration: usize,
	wrote: usize,
	read: usize,
	tls_wants_write: Option<bool>,
}

/// One 1 MiB echo: write (and flush if asked) while reading the same amount back.
async fn echo<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, flush: bool, data: &[u8], back: &mut [u8], timeout: Duration) -> Result<Duration, (usize, usize)> {
	let start = Instant::now();
	let (mut r, mut w) = tokio::io::split(s);
	let (mut wrote, mut read) = (0, 0);
	let len = back.len();
	let work = async {
		let write = async {
			while wrote < data.len() {
				match w.write(&data[wrote..]).await? {
					0 => return Err(std::io::ErrorKind::WriteZero.into()),
					n => wrote += n,
				}
			}
			if flush {
				w.flush().await?;
			}
			Ok::<_, std::io::Error>(())
		};
		let fill = async {
			while read < len {
				match r.read(&mut back[read..]).await? {
					0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
					n => read += n,
				}
			}
			Ok(())
		};
		let (a, b) = tokio::join!(write, fill);
		a.and(b)
	};
	let result = tokio::time::timeout(timeout, work).await;
	match result {
		Ok(Ok(())) => Ok(start.elapsed()),
		Ok(Err(e)) => panic!("echo failed: {e}"),
		Err(_) => Err((wrote, read)),
	}
}

#[derive(Clone, Copy)]
enum Kind {
	Tcp,
	Tls,
}

struct Variant {
	name: &'static str,
	kind: Kind,
	addr: SocketAddr,
	flush: bool,
	sndbuf: Option<usize>,
}

struct Outcome {
	times: Vec<Duration>,
	stalls: Vec<Stall>,
}

async fn connect_tcp(addr: SocketAddr, sndbuf: Option<usize>) -> TcpStream {
	let tcp = TcpStream::connect(addr).await.unwrap();
	tcp.set_nodelay(true).unwrap();
	if let Some(n) = sndbuf {
		socket2::SockRef::from(&tcp).set_send_buffer_size(n).unwrap();
	}
	tcp
}

async fn run(v: &Variant, connector: &tokio_rustls::TlsConnector, iters: usize, timeout: Duration) -> Outcome {
	let data: Vec<u8> = (0..SIZE).map(|i| (i * 31 % 251) as u8).collect();
	let mut back = vec![0u8; SIZE];
	let mut out = Outcome { times: vec![], stalls: vec![] };
	match v.kind {
		Kind::Tcp => {
			let mut s = connect_tcp(v.addr, v.sndbuf).await;
			for i in 0..iters {
				match echo(&mut s, v.flush, &data, &mut back, timeout).await {
					Ok(t) => out.times.push(t),
					Err((wrote, read)) => {
						out.stalls.push(Stall { iteration: i, wrote, read, tls_wants_write: None });
						if out.stalls.len() == MAX_STALLS {
							break;
						}
						s = connect_tcp(v.addr, v.sndbuf).await;
					}
				}
			}
		}
		Kind::Tls => {
			let tls = |addr, sndbuf| async move {
				connector.connect("probe.test".try_into().unwrap(), connect_tcp(addr, sndbuf).await).await.unwrap()
			};
			let mut s = tls(v.addr, v.sndbuf).await;
			for i in 0..iters {
				match echo(&mut s, v.flush, &data, &mut back, timeout).await {
					Ok(t) => out.times.push(t),
					Err((wrote, read)) => {
						let wants = s.get_ref().1.wants_write();
						out.stalls.push(Stall { iteration: i, wrote, read, tls_wants_write: Some(wants) });
						if out.stalls.len() == MAX_STALLS {
							break;
						}
						s = tls(v.addr, v.sndbuf).await;
					}
				}
			}
		}
	}
	out
}

fn pct(times: &mut [Duration], p: f64) -> String {
	if times.is_empty() {
		return "—".into();
	}
	times.sort();
	let i = ((times.len() as f64 - 1.0) * p).round() as usize;
	format!("{:.2} ms", times[i].as_secs_f64() * 1e3)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
	let a = args();
	let pki = Pki::new("probe");
	let cert = pki.server("front", &["probe.test"]);
	let echo_addr = tcp_echo().await;
	let direct = tls_echo(pki.acceptor(&cert)).await;

	let tls_rule = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]});
	let (tcp_port, tls_port) = (free_port(), free_port());
	let rules = json!([
		{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": tcp_port, "remote_addr": "127.0.0.1", "remote_port": echo_addr.port()},
		{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": tls_port, "remote_addr": "127.0.0.1", "remote_port": echo_addr.port(), "tls": tls_rule},
	]);
	// keep whichever rproxy runs alive until the end
	let mut _external = None;
	let mut _harness = None;
	let place = match &a.rproxy {
		Some(binary) => {
			let config = pki.write("probe.yaml", &json!({"version": 1, "rules": rules}).to_string());
			let child = std::process::Command::new(binary)
				.env_clear()
				.env("PATH", std::env::var("PATH").unwrap_or_default())
				.env("RPROXY_CONFIG", &config)
				.env("RPROXY_API_ADDR", "127.0.0.1")
				.env("RPROXY_API_PORT", free_port().to_string())
				.env("RPROXY_LOG_LEVEL", "error")
				.stdout(std::process::Stdio::null())
				.spawn()
				.expect("start rproxy");
			_external = Some(External(child));
			wait_listening(tcp_port).await;
			wait_listening(tls_port).await;
			"own process"
		}
		None => {
			let h = common::harness().await;
			for r in rules.as_array().unwrap() {
				let (status, v) = h.post(r.clone()).await;
				assert!(status.is_success(), "{v}");
			}
			_harness = Some(h);
			"in this process (same runtime as the clients)"
		}
	};

	let connector = tokio_rustls::TlsConnector::from(Arc::new(
		rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_root_certificates(pki.roots())
			.with_no_client_auth(),
	));
	let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
	let mut variants = vec![];
	for sndbuf in [None, Some(4096)] {
		for flush in [false, true] {
			variants.push(Variant { name: "TCP via rproxy", kind: Kind::Tcp, addr: at(tcp_port), flush, sndbuf });
			variants.push(Variant { name: "TLS via rproxy (terminate)", kind: Kind::Tls, addr: at(tls_port), flush, sndbuf });
			variants.push(Variant { name: "TLS direct (no rproxy)", kind: Kind::Tls, addr: direct, flush, sndbuf });
		}
	}

	let mut report = vec![
		format!("### Stall probe: rproxy {place}, {} × 1 MiB per variant, {:?} per iteration", a.iters, a.timeout),
		String::new(),
		"| variant | client flush | client SO_SNDBUF | iterations | stalls | p50 | p99 | max | stalled iterations |".into(),
		"|---|---|---|---|---|---|---|---|---|".into(),
	];
	let mut bad = false;
	for v in &variants {
		let mut o = run(v, &connector, a.iters, a.timeout).await;
		if v.flush && !o.stalls.is_empty() {
			bad = true;
		}
		let detail: Vec<String> = o
			.stalls
			.iter()
			.take(5)
			.map(|s| {
				let tls = s.tls_wants_write.map(|w| format!(", client TLS wants_write={w}")).unwrap_or_default();
				format!("#{} wrote {} read {}{tls}", s.iteration, s.wrote, s.read)
			})
			.collect();
		let line = format!(
			"| {} | {} | {} | {} | {} | {} | {} | {} | {} |",
			v.name,
			if v.flush { "yes" } else { "no" },
			v.sndbuf.map(|n| n.to_string()).unwrap_or_else(|| "default".into()),
			o.times.len() + o.stalls.len(),
			o.stalls.len(),
			pct(&mut o.times, 0.5),
			pct(&mut o.times, 0.99),
			pct(&mut o.times, 1.0),
			detail.join("; ")
		);
		eprintln!("{line}");
		report.push(line);
	}
	let report = report.join("\n") + "\n";
	println!("{report}");
	if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
		if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(path) {
			let _ = f.write_all(report.as_bytes());
		}
	}
	if bad {
		eprintln!("a variant that flushes stalled: that is not the harness");
		std::process::exit(1);
	}
}
