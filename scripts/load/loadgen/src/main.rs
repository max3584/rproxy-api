//! Traffic generator and test servers for the load / soak suite (scripts/load/, issue #183).
//!
//! std only (no dependencies), one thread per connection: simple enough that the
//! numbers measure rproxy, not this program. Every subcommand prints its result as
//! one JSON object per line on stdout. Data streams are deterministic pseudo-random
//! bytes (a 1 MiB block; each 64 KiB chunk starts at an offset derived from the
//! stream's seed and the chunk number), so the receiver checks every byte against
//! what the sender must have sent: a lost, duplicated, reordered or shifted chunk
//! fails the check, which is stricter than comparing checksums at the end.
//!
//! TCP servers (backend side):
//!   sink        --listen A               read "header + data", verify, reply "OK n" (JSON line per connection)
//!   echo        --listen A               echo everything back
//!   http-server --listen A [--small N]   HTTP/1.1 keep-alive: /stream/<bytes>/<seed> or a small body
//! TCP clients:
//!   send   --connect A --bytes N [--streams P] [--seed S]       upload P verified streams in parallel
//!   gen    --bytes N [--seed S] [--header 1]                    write a stream to stdout (for socat / TLS)
//!   verify --bytes N [--seed S]                                 verify a stream from stdin (curl downloads)
//!   rtt    --connect A [--conns C] [--secs T] [--size B]        ping-pong latency on C connections
//!   churn  --connect A [--workers W] [--secs T] [--size B]      connect, echo B bytes, close, repeat
//!   hold   --connect A --conns N [--size B]                     hold N connections; stdin: active / idle / quit
//! UDP:
//!   udp-sink  --listen A [--idle S] [--max-secs T]              count datagrams until S seconds of silence
//!   udp-echo  --listen A
//!   udp-flood --connect A [--sources K] [--secs T] [--size B] [--pps R] [--rotate S] [--threads N]
//!   udp-hold  --connect A --sources N                           one session per source; stdin: quit

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const BLOCK: usize = 1 << 20;
const CHUNK: usize = 64 << 10;
const MAGIC: &[u8; 8] = b"LOADGEN1";
const HEADER: usize = 24; // magic, seed (u64 LE), length (u64 LE)
const STACK: usize = 256 << 10;

// ---------------------------------------------------------------- data streams

fn block() -> &'static [u8] {
	static B: OnceLock<Vec<u8>> = OnceLock::new();
	B.get_or_init(|| {
		let mut x = 0x2545_f491_4f6c_dd1du64;
		let mut v = Vec::with_capacity(BLOCK);
		while v.len() < BLOCK {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			v.extend_from_slice(&x.to_le_bytes());
		}
		v
	})
}

fn mix(mut z: u64) -> u64 {
	z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
	z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
	z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
	z ^ (z >> 31)
}

/// The bytes stream `seed` carries from `pos` to the end of that chunk.
fn expected(seed: u64, pos: u64) -> &'static [u8] {
	let idx = pos / CHUNK as u64;
	let off = (pos % CHUNK as u64) as usize;
	let start = (mix(seed ^ mix(idx)) % (BLOCK - CHUNK) as u64) as usize;
	&block()[start + off..start + CHUNK]
}

fn write_stream(w: &mut impl Write, seed: u64, len: u64) -> io::Result<()> {
	let mut pos = 0;
	while pos < len {
		let e = expected(seed, pos);
		let n = e.len().min((len - pos) as usize);
		w.write_all(&e[..n])?;
		pos += n as u64;
	}
	Ok(())
}

struct Verifier {
	seed: u64,
	pos: u64,
	bad: Option<u64>,
}

impl Verifier {
	fn new(seed: u64) -> Self {
		Verifier { seed, pos: 0, bad: None }
	}
	fn feed(&mut self, mut data: &[u8]) {
		while !data.is_empty() {
			let e = expected(self.seed, self.pos);
			let n = e.len().min(data.len());
			if self.bad.is_none() && e[..n] != data[..n] {
				let i = e[..n].iter().zip(&data[..n]).position(|(a, b)| a != b).unwrap_or(0);
				self.bad = Some(self.pos + i as u64);
			}
			self.pos += n as u64;
			data = &data[n..];
		}
	}
}

fn header(seed: u64, len: u64) -> [u8; HEADER] {
	let mut h = [0u8; HEADER];
	h[..8].copy_from_slice(MAGIC);
	h[8..16].copy_from_slice(&seed.to_le_bytes());
	h[16..24].copy_from_slice(&len.to_le_bytes());
	h
}

// ---------------------------------------------------------------- small helpers

struct Args(HashMap<String, String>);

impl Args {
	fn parse(v: &[String]) -> Args {
		let mut m = HashMap::new();
		let mut i = 0;
		while i < v.len() {
			let Some(k) = v[i].strip_prefix("--") else {
				die(&format!("unexpected argument {}", v[i]));
			};
			let val = v.get(i + 1).filter(|x| !x.starts_with("--")).cloned();
			i += if val.is_some() { 2 } else { 1 };
			m.insert(k.to_string(), val.unwrap_or_else(|| "1".into()));
		}
		Args(m)
	}
	fn num<T: std::str::FromStr>(&self, k: &str, default: T) -> T {
		match self.0.get(k) {
			Some(v) => v.parse().unwrap_or_else(|_| die(&format!("bad --{k} {v}"))),
			None => default,
		}
	}
	fn addr(&self, k: &str) -> SocketAddr {
		let v = self.0.get(k).unwrap_or_else(|| die(&format!("--{k} is required")));
		v.parse().unwrap_or_else(|_| die(&format!("bad --{k} {v}")))
	}
}

fn die(msg: &str) -> ! {
	eprintln!("loadgen: {msg}");
	exit(2)
}

/// A JSON object written by hand (numbers, strings, booleans).
#[derive(Default)]
struct Obj(Vec<String>);

impl Obj {
	fn n(mut self, k: &str, v: impl std::fmt::Display) -> Self {
		self.0.push(format!("\"{k}\":{v}"));
		self
	}
	fn f(self, k: &str, v: f64) -> Self {
		if v.is_finite() {
			self.n(k, format!("{v:.6}"))
		} else {
			self.n(k, "null")
		}
	}
	fn s(mut self, k: &str, v: &str) -> Self {
		let esc: String = v
			.chars()
			.flat_map(|c| match c {
				'"' => vec!['\\', '"'],
				'\\' => vec!['\\', '\\'],
				c if (c as u32) < 0x20 => vec![' '],
				c => vec![c],
			})
			.collect();
		self.0.push(format!("\"{k}\":\"{esc}\""));
		self
	}
	fn print(self) {
		println!("{{{}}}", self.0.join(","));
	}
}

fn spawn<F: FnOnce() -> T + Send + 'static, T: Send + 'static>(f: F) -> thread::JoinHandle<T> {
	thread::Builder::new().stack_size(STACK).spawn(f).unwrap_or_else(|e| die(&format!("spawn: {e}")))
}

fn percentile(sorted: &[u32], p: f64) -> u32 {
	if sorted.is_empty() {
		return 0;
	}
	let i = ((sorted.len() as f64 - 1.0) * p).round() as usize;
	sorted[i.min(sorted.len() - 1)]
}

fn latency(o: Obj, mut lat: Vec<u32>) -> Obj {
	lat.sort_unstable();
	o.n("p50_us", percentile(&lat, 0.50))
		.n("p90_us", percentile(&lat, 0.90))
		.n("p99_us", percentile(&lat, 0.99))
		.n("max_us", lat.last().copied().unwrap_or(0))
}

fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
	let mut last = None;
	for i in 0..5 {
		match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
			Ok(c) => {
				let _ = c.set_nodelay(true);
				return Ok(c);
			}
			Err(e) => last = Some(e),
		}
		thread::sleep(Duration::from_millis(20 << i));
	}
	Err(last.unwrap_or_else(|| io::Error::other("connect failed")))
}

extern "C" {
	fn setsockopt(fd: i32, level: i32, name: i32, val: *const std::ffi::c_void, len: u32) -> i32;
}

/// A larger receive / send buffer for UDP (SO_RCVBUFFORCE needs CAP_NET_ADMIN; else capped by rmem_max).
fn big_buffers(fd: i32) {
	const SOL_SOCKET: i32 = 1;
	const SO_SNDBUF: i32 = 7;
	const SO_RCVBUF: i32 = 8;
	const SO_RCVBUFFORCE: i32 = 33;
	let size: i32 = 8 << 20;
	let p = &size as *const i32 as *const std::ffi::c_void;
	// SAFETY: plain setsockopt with a valid fd and a pointer to an i32 that lives across the call
	unsafe {
		if setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, p, 4) != 0 {
			setsockopt(fd, SOL_SOCKET, SO_RCVBUF, p, 4);
		}
		setsockopt(fd, SOL_SOCKET, SO_SNDBUF, p, 4);
	}
}

fn serve(addr: SocketAddr, handle: impl Fn(TcpStream) + Send + Sync + Clone + 'static) {
	let l = TcpListener::bind(addr).unwrap_or_else(|e| die(&format!("bind {addr}: {e}")));
	eprintln!("loadgen: listening on {addr}");
	for c in l.incoming() {
		match c {
			Ok(c) => {
				let h = handle.clone();
				spawn(move || h(c));
			}
			Err(e) => {
				eprintln!("loadgen: accept: {e}");
				thread::sleep(Duration::from_millis(10));
			}
		}
	}
}

// ---------------------------------------------------------------- TCP servers

fn sink_conn(mut c: TcpStream) -> Result<(u64, u64, f64, Option<u64>), String> {
	let mut h = [0u8; HEADER];
	c.read_exact(&mut h).map_err(|e| format!("header: {e}"))?;
	if &h[..8] != MAGIC {
		return Err("bad magic".into());
	}
	let seed = u64::from_le_bytes(h[8..16].try_into().unwrap_or_default());
	let len = u64::from_le_bytes(h[16..24].try_into().unwrap_or_default());
	let t0 = Instant::now();
	let mut v = Verifier::new(seed);
	let mut buf = vec![0u8; 256 << 10];
	loop {
		match c.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => v.feed(&buf[..n]),
			Err(e) => return Err(format!("after {} bytes: {e}", v.pos)),
		}
	}
	let secs = t0.elapsed().as_secs_f64();
	let reply = if v.bad.is_none() && v.pos == len { format!("OK {}\n", v.pos) } else { format!("BAD {} {:?}\n", v.pos, v.bad) };
	let _ = c.write_all(reply.as_bytes());
	Ok((seed, v.pos, secs, v.bad.or(if v.pos == len { None } else { Some(v.pos) })))
}

fn cmd_sink(a: &Args) {
	serve(a.addr("listen"), |c| {
		let o = Obj::default().s("event", "sink");
		match sink_conn(c) {
			Ok((seed, bytes, secs, bad)) => {
				let o = o.n("seed", seed).n("bytes", bytes).f("secs", secs).f("gbps", bytes as f64 * 8.0 / secs / 1e9);
				match bad {
					None => o.n("ok", true).print(),
					Some(at) => o.n("ok", false).n("bad_at", at).print(),
				}
			}
			Err(e) => o.n("ok", false).s("error", &e).print(),
		}
	});
}

fn cmd_echo(a: &Args) {
	serve(a.addr("listen"), |mut c| {
		let _ = c.set_nodelay(true);
		let mut buf = vec![0u8; 64 << 10];
		loop {
			match c.read(&mut buf) {
				Ok(0) | Err(_) => break,
				Ok(n) => {
					if c.write_all(&buf[..n]).is_err() {
						return;
					}
				}
			}
		}
		let _ = c.shutdown(Shutdown::Write);
	});
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
	h.windows(n.len()).position(|w| w == n)
}

fn http_conn(mut c: TcpStream, small: &[u8]) -> io::Result<()> {
	c.set_nodelay(true)?;
	let mut buf: Vec<u8> = Vec::with_capacity(8192);
	let mut tmp = [0u8; 8192];
	loop {
		let end = loop {
			if let Some(i) = find(&buf, b"\r\n\r\n") {
				break i + 4;
			}
			let n = c.read(&mut tmp)?;
			if n == 0 || buf.len() > 65536 {
				return Ok(());
			}
			buf.extend_from_slice(&tmp[..n]);
		};
		let head = String::from_utf8_lossy(&buf[..end]).into_owned();
		buf.drain(..end);
		let mut lines = head.split("\r\n");
		let path = lines.next().unwrap_or("").split(' ').nth(1).unwrap_or("/").to_string();
		let (mut close, mut body) = (false, 0usize);
		for l in lines {
			if let Some((k, v)) = l.split_once(':') {
				let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
				if k == "connection" && v.eq_ignore_ascii_case("close") {
					close = true;
				}
				if k == "content-length" {
					body = v.parse().unwrap_or(0);
				}
			}
		}
		while buf.len() < body {
			let n = c.read(&mut tmp)?;
			if n == 0 {
				return Ok(());
			}
			buf.extend_from_slice(&tmp[..n]);
		}
		buf.drain(..body);
		let conn = if close { "close" } else { "keep-alive" };
		if let Some(rest) = path.strip_prefix("/stream/") {
			let mut it = rest.split('/');
			let len: u64 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
			let seed: u64 = it.next().and_then(|x| x.parse().ok()).unwrap_or(0);
			let h = format!("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {len}\r\nConnection: {conn}\r\n\r\n");
			c.write_all(h.as_bytes())?;
			write_stream(&mut c, seed, len)?;
		} else {
			let mut r = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: {conn}\r\n\r\n", small.len()).into_bytes();
			r.extend_from_slice(small);
			c.write_all(&r)?;
		}
		if close {
			return Ok(());
		}
	}
}

fn cmd_http_server(a: &Args) {
	let small: Arc<Vec<u8>> = Arc::new(vec![b'x'; a.num("small", 1024usize)]);
	serve(a.addr("listen"), move |c| {
		let _ = http_conn(c, &small);
	});
}

// ---------------------------------------------------------------- TCP clients

fn cmd_send(a: &Args) {
	let addr = a.addr("connect");
	let bytes: u64 = a.num("bytes", 1 << 30);
	let streams: u64 = a.num("streams", 1);
	let seed: u64 = a.num("seed", 1);
	let t0 = Instant::now();
	let hs: Vec<_> = (0..streams)
		.map(|i| {
			spawn(move || -> Result<(), String> {
				let s = seed.wrapping_add(i);
				let mut c = connect(addr).map_err(|e| format!("connect: {e}"))?;
				c.write_all(&header(s, bytes)).map_err(|e| format!("write: {e}"))?;
				write_stream(&mut c, s, bytes).map_err(|e| format!("write: {e}"))?;
				c.shutdown(Shutdown::Write).map_err(|e| format!("shutdown: {e}"))?;
				let mut r = String::new();
				c.read_to_string(&mut r).map_err(|e| format!("reply: {e}"))?;
				if r.starts_with("OK ") {
					Ok(())
				} else {
					Err(format!("sink: {}", r.trim()))
				}
			})
		})
		.collect();
	let errs: Vec<String> = hs.into_iter().filter_map(|h| h.join().unwrap_or_else(|_| Err("panic".into())).err()).collect();
	let secs = t0.elapsed().as_secs_f64();
	let total = bytes * (streams - errs.len() as u64);
	let o = Obj::default().n("bytes", total).f("secs", secs).f("gbps", total as f64 * 8.0 / secs / 1e9).n("ok", errs.is_empty()).n("errors", errs.len());
	match errs.first() {
		Some(e) => o.s("error", e).print(),
		None => o.print(),
	}
}

fn cmd_gen(a: &Args) {
	let bytes: u64 = a.num("bytes", 1 << 30);
	let seed: u64 = a.num("seed", 1);
	// SAFETY: fd 1 is stdout, owned by this process for its whole life
	let mut out = unsafe { File::from_raw_fd(1) };
	if a.num("header", 0u8) == 1 {
		if let Err(e) = out.write_all(&header(seed, bytes)) {
			die(&format!("write: {e}"));
		}
	}
	if let Err(e) = write_stream(&mut out, seed, bytes) {
		die(&format!("write: {e}"));
	}
}

fn cmd_verify(a: &Args) {
	let bytes: u64 = a.num("bytes", 1 << 30);
	let mut v = Verifier::new(a.num("seed", 1));
	// SAFETY: fd 0 is stdin, owned by this process for its whole life
	let mut inp = unsafe { File::from_raw_fd(0) };
	let mut buf = vec![0u8; 256 << 10];
	let mut t0 = None;
	let mut err = None;
	loop {
		match inp.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => {
				t0.get_or_insert_with(Instant::now);
				v.feed(&buf[..n]);
			}
			Err(e) => {
				err = Some(e.to_string());
				break;
			}
		}
	}
	let secs = t0.map(|t| t.elapsed().as_secs_f64()).unwrap_or(0.0);
	let ok = v.bad.is_none() && v.pos == bytes && err.is_none();
	let o = Obj::default().n("bytes", v.pos).n("expected", bytes).f("secs", secs).f("gbps", v.pos as f64 * 8.0 / secs / 1e9).n("ok", ok);
	let o = match v.bad {
		Some(at) => o.n("bad_at", at),
		None => o,
	};
	match err {
		Some(e) => o.s("error", &e).print(),
		None => o.print(),
	}
}

fn ping(c: &mut TcpStream, out: &[u8], back: &mut [u8]) -> io::Result<bool> {
	c.write_all(out)?;
	c.read_exact(back)?;
	Ok(out == back)
}

fn cmd_rtt(a: &Args) {
	let addr = a.addr("connect");
	let conns: usize = a.num("conns", 1);
	let secs: f64 = a.num("secs", 10.0);
	let size: usize = a.num("size", 64);
	let mut cs = Vec::new();
	for _ in 0..conns {
		cs.push(connect(addr).unwrap_or_else(|e| die(&format!("connect: {e}"))));
	}
	let deadline = Instant::now() + Duration::from_secs_f64(secs);
	let t0 = Instant::now();
	let hs: Vec<_> = cs
		.into_iter()
		.enumerate()
		.map(|(i, mut c)| {
			spawn(move || {
				let out: Vec<u8> = (0..size).map(|j| (i + j) as u8).collect();
				let mut back = vec![0u8; size];
				let (mut lat, mut bad) = (Vec::with_capacity(100_000), 0u64);
				while Instant::now() < deadline {
					let t = Instant::now();
					match ping(&mut c, &out, &mut back) {
						Ok(true) => lat.push(t.elapsed().as_micros().min(u32::MAX as u128) as u32),
						Ok(false) => bad += 1,
						Err(_) => {
							bad += 1;
							break;
						}
					}
				}
				(lat, bad)
			})
		})
		.collect();
	let (mut lat, mut bad) = (Vec::new(), 0);
	for h in hs {
		if let Ok((l, b)) = h.join() {
			lat.extend(l);
			bad += b;
		}
	}
	let wall = t0.elapsed().as_secs_f64();
	let o = Obj::default().n("count", lat.len()).n("errors", bad).f("rps", lat.len() as f64 / wall);
	latency(o, lat).n("ok", bad == 0).print();
}

fn cmd_churn(a: &Args) {
	let addr = a.addr("connect");
	let workers: usize = a.num("workers", 16);
	let secs: f64 = a.num("secs", 10.0);
	let size: usize = a.num("size", 1024);
	let deadline = Instant::now() + Duration::from_secs_f64(secs);
	let t0 = Instant::now();
	let hs: Vec<_> = (0..workers)
		.map(|i| {
			spawn(move || {
				let out: Vec<u8> = (0..size).map(|j| (i * 7 + j) as u8).collect();
				let mut back = vec![0u8; size];
				let (mut lat, mut fail, mut first) = (Vec::new(), 0u64, None);
				while Instant::now() < deadline {
					let t = Instant::now();
					let r = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).and_then(|mut c| {
						let _ = c.set_nodelay(true);
						let ok = ping(&mut c, &out, &mut back)?;
						c.shutdown(Shutdown::Write)?;
						// wait for the far side's FIN, so the connection really ended
						let mut rest = [0u8; 16];
						let _ = c.read(&mut rest);
						Ok(ok)
					});
					match r {
						Ok(true) => lat.push(t.elapsed().as_micros().min(u32::MAX as u128) as u32),
						Ok(false) => {
							fail += 1;
							first.get_or_insert_with(|| "echo mismatch".to_string());
						}
						Err(e) => {
							fail += 1;
							first.get_or_insert_with(|| e.to_string());
							thread::sleep(Duration::from_millis(10));
						}
					}
				}
				(lat, fail, first)
			})
		})
		.collect();
	let (mut lat, mut fail, mut first) = (Vec::new(), 0, None);
	for h in hs {
		if let Ok((l, f, e)) = h.join() {
			lat.extend(l);
			fail += f;
			first = first.or(e);
		}
	}
	let wall = t0.elapsed().as_secs_f64();
	let o = Obj::default().n("count", lat.len()).n("failed", fail).f("conns_per_s", lat.len() as f64 / wall);
	let o = latency(o, lat);
	match first {
		Some(e) => o.s("error", &e).print(),
		None => o.print(),
	}
}

fn cmd_hold(a: &Args) {
	let addr = a.addr("connect");
	let n: usize = a.num("conns", 1000);
	let size: usize = a.num("size", 4096);
	let mut conns = Vec::with_capacity(n);
	let mut errs = 0;
	let mut first = String::new();
	for _ in 0..n {
		match connect(addr) {
			Ok(c) => conns.push(c),
			Err(e) => {
				errs += 1;
				if first.is_empty() {
					first = e.to_string();
				}
			}
		}
	}
	// make sure every connection reached the backend through the proxy
	let mut dead = 0;
	for c in conns.iter_mut() {
		let _ = c.set_read_timeout(Some(Duration::from_secs(10)));
		if !matches!(ping(c, b"hello", &mut [0u8; 5]), Ok(true)) {
			dead += 1;
		}
		let _ = c.set_read_timeout(None);
	}
	Obj::default().s("state", "ready").n("conns", conns.len() - dead).n("errors", errs + dead).s("error", &first).print();
	let stop = Arc::new(AtomicBool::new(false));
	let rounds = Arc::new(AtomicU64::new(0));
	let mut workers = Vec::new();
	for line in io::stdin().lock().lines() {
		let Ok(line) = line else { break };
		match line.trim() {
			"active" if workers.is_empty() => {
				stop.store(false, Ordering::SeqCst);
				let warm = Arc::new(AtomicU64::new(0));
				for (i, c) in conns.iter().enumerate() {
					let Ok(mut c) = c.try_clone() else { continue };
					let (stop, rounds, warm) = (stop.clone(), rounds.clone(), warm.clone());
					workers.push(spawn(move || {
						let out: Vec<u8> = (0..size).map(|j| (i + j) as u8).collect();
						let mut back = vec![0u8; size];
						let mut first = true;
						while !stop.load(Ordering::Relaxed) {
							if !matches!(ping(&mut c, &out, &mut back), Ok(true)) {
								break;
							}
							rounds.fetch_add(1, Ordering::Relaxed);
							if first {
								warm.fetch_add(1, Ordering::SeqCst);
								first = false;
							}
						}
					}));
				}
				let t = Instant::now();
				while warm.load(Ordering::SeqCst) < workers.len() as u64 && t.elapsed() < Duration::from_secs(60) {
					thread::sleep(Duration::from_millis(50));
				}
				Obj::default().s("state", "active").n("conns", warm.load(Ordering::SeqCst)).print();
			}
			"idle" => {
				stop.store(true, Ordering::SeqCst);
				for w in workers.drain(..) {
					let _ = w.join();
				}
				Obj::default().s("state", "idle").n("rounds", rounds.load(Ordering::SeqCst)).print();
			}
			"quit" => break,
			_ => {}
		}
	}
	stop.store(true, Ordering::SeqCst);
	drop(conns);
	Obj::default().s("state", "done").n("rounds", rounds.load(Ordering::SeqCst)).print();
	exit(0);
}

// ---------------------------------------------------------------- UDP

fn cmd_udp_sink(a: &Args) {
	let addr = a.addr("listen");
	let idle = Duration::from_secs_f64(a.num("idle", 2.0));
	let max = Duration::from_secs_f64(a.num("max-secs", 3600.0));
	let s = UdpSocket::bind(addr).unwrap_or_else(|e| die(&format!("bind {addr}: {e}")));
	big_buffers(s.as_raw_fd());
	let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
	Obj::default().s("state", "ready").print();
	let mut buf = vec![0u8; 65536];
	let (mut n, mut bytes) = (0u64, 0u64);
	let mut sources = HashSet::new();
	let mut last_src = None;
	let start = Instant::now();
	let (mut first, mut last) = (None, Instant::now());
	loop {
		match s.recv_from(&mut buf) {
			Ok((len, src)) => {
				n += 1;
				bytes += len as u64;
				last = Instant::now();
				first.get_or_insert(last);
				if last_src != Some(src) {
					sources.insert(src);
					last_src = Some(src);
				}
			}
			Err(_) => {
				if first.is_some() && last.elapsed() >= idle {
					break;
				}
			}
		}
		if start.elapsed() >= max {
			break;
		}
	}
	let secs = first.map(|f| (last - f).as_secs_f64()).unwrap_or(0.0);
	Obj::default().n("received", n).n("bytes", bytes).f("secs", secs).f("pps", n as f64 / secs).n("sources", sources.len()).print();
}

fn cmd_udp_echo(a: &Args) {
	let addr = a.addr("listen");
	let s = UdpSocket::bind(addr).unwrap_or_else(|e| die(&format!("bind {addr}: {e}")));
	big_buffers(s.as_raw_fd());
	eprintln!("loadgen: udp echo on {addr}");
	let mut buf = vec![0u8; 65536];
	loop {
		if let Ok((n, src)) = s.recv_from(&mut buf) {
			let _ = s.send_to(&buf[..n], src);
		}
	}
}

fn udp_sockets(addr: SocketAddr, k: usize) -> Vec<UdpSocket> {
	let any = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
	(0..k)
		.map(|_| {
			let s = UdpSocket::bind(any).unwrap_or_else(|e| die(&format!("bind: {e}")));
			s.connect(addr).unwrap_or_else(|e| die(&format!("connect: {e}")));
			s
		})
		.collect()
}

fn cmd_udp_flood(a: &Args) {
	let addr = a.addr("connect");
	let sources: usize = a.num("sources", 16);
	let secs: f64 = a.num("secs", 10.0);
	let size: usize = a.num::<usize>("size", 64).max(16);
	let pps: f64 = a.num("pps", 0.0);
	let rotate: f64 = a.num("rotate", 0.0);
	let threads: usize = a.num::<usize>("threads", 1).clamp(1, sources.max(1));
	let deadline = Instant::now() + Duration::from_secs_f64(secs);
	let t0 = Instant::now();
	let hs: Vec<_> = (0..threads)
		.map(|t| {
			let k = sources / threads + usize::from(t < sources % threads);
			spawn(move || {
				let mut socks = udp_sockets(addr, k);
				let mut buf = vec![0u8; size];
				let (mut sent, mut errs, mut seq) = (0u64, 0u64, 0u64);
				let rate = pps / threads as f64;
				let start = Instant::now();
				let mut rotated = Instant::now();
				'outer: loop {
					for (i, s) in socks.iter().enumerate() {
						seq += 1;
						buf[..8].copy_from_slice(&seq.to_le_bytes());
						buf[8..12].copy_from_slice(&((t * 1_000_000 + i) as u32).to_le_bytes());
						match s.send(&buf) {
							Ok(_) => sent += 1,
							Err(_) => errs += 1,
						}
						if seq % 64 == 0 {
							let now = Instant::now();
							if now >= deadline {
								break 'outer;
							}
							if rate > 0.0 {
								let due = start + Duration::from_secs_f64(seq as f64 / rate);
								if due > now {
									thread::sleep(due - now);
								}
							}
						}
					}
					if rotate > 0.0 && rotated.elapsed().as_secs_f64() >= rotate {
						socks = udp_sockets(addr, k);
						rotated = Instant::now();
					}
				}
				(sent, errs)
			})
		})
		.collect();
	let (mut sent, mut errs) = (0, 0);
	for h in hs {
		if let Ok((s, e)) = h.join() {
			sent += s;
			errs += e;
		}
	}
	let secs = t0.elapsed().as_secs_f64();
	Obj::default().n("sent", sent).n("errors", errs).f("secs", secs).f("pps", sent as f64 / secs).print();
}

fn cmd_udp_hold(a: &Args) {
	let addr = a.addr("connect");
	let n: usize = a.num("sources", 1000);
	let socks = udp_sockets(addr, n);
	// a burst of thousands of first datagrams overflows the proxy's receive buffer: send in
	// paced batches, then retry the sources that got no answer (a few rounds)
	let mut up = vec![false; n];
	let mut buf = [0u8; 64];
	for s in &socks {
		let _ = s.set_nonblocking(true);
	}
	for _round in 0..5 {
		for (i, s) in socks.iter().enumerate() {
			if !up[i] {
				let _ = s.send(b"hello");
				if i % 100 == 99 {
					thread::sleep(Duration::from_millis(5));
				}
			}
		}
		let end = Instant::now() + Duration::from_secs(2);
		while Instant::now() < end && up.iter().any(|u| !u) {
			for (i, s) in socks.iter().enumerate() {
				while s.recv(&mut buf).is_ok() {
					up[i] = true;
				}
			}
			thread::sleep(Duration::from_millis(20));
		}
		if up.iter().all(|u| *u) {
			break;
		}
	}
	let up = up.iter().filter(|u| **u).count();
	Obj::default().s("state", "ready").n("sessions", up).n("sources", n).print();
	for line in io::stdin().lock().lines() {
		match line.as_deref().map(str::trim) {
			Ok("quit") | Err(_) => break,
			_ => {}
		}
	}
	Obj::default().s("state", "done").print();
}

fn main() {
	let argv: Vec<String> = std::env::args().skip(1).collect();
	let Some(cmd) = argv.first() else {
		die("usage: loadgen <subcommand> [--key value]... (see the top of src/main.rs)");
	};
	let a = Args::parse(&argv[1..]);
	match cmd.as_str() {
		"sink" => cmd_sink(&a),
		"echo" => cmd_echo(&a),
		"http-server" => cmd_http_server(&a),
		"send" => cmd_send(&a),
		"gen" => cmd_gen(&a),
		"verify" => cmd_verify(&a),
		"rtt" => cmd_rtt(&a),
		"churn" => cmd_churn(&a),
		"hold" => cmd_hold(&a),
		"udp-sink" => cmd_udp_sink(&a),
		"udp-echo" => cmd_udp_echo(&a),
		"udp-flood" => cmd_udp_flood(&a),
		"udp-hold" => cmd_udp_hold(&a),
		other => die(&format!("unknown subcommand {other}")),
	}
}
