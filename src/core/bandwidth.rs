//! Bandwidth limits of a rule (#166, docs/DESIGN-v0.4.md 5.): the whole rule
//! and per client source, each way. TCP waits (shaping), UDP drops over the rate.
//!
//! At run time a rule has a `Bandwidth` (`Runtime.bandwidth`); a connection
//! has a `Gate` per direction. Upload is what is read from the client, download
//! what is read from the backend (L4) or written to the client (L7).
//!
//! - TCP waits: before each read (`Shaped`, around the reader of `l4::relay`) or
//!   write (`l7::server::Metered`) the gate gives how much may move now, or
//!   returns `Pending` until the buckets have refilled. A relay that waits gives
//!   its pooled buffer back meanwhile (`relay::Copy` does on `Pending`), so a
//!   throttled connection holds no buffer.
//! - splice(2) (`l4::splice`) is only used while the rule has no bandwidth
//!   limit: a direction checks before each splice and goes back to the shaped
//!   user-space copy when one applies, and does not hand over to splice again
//!   while it does.
//! - UDP drops the datagrams over the rate (`Gate::admit`; `stats.dropped` and
//!   `rproxy_rule_bandwidth_dropped_total`).
//!
//! The buckets may go below zero (a read of a few KiB, a datagram larger than
//! what is left); the debt is waited out, so the long-run rate holds. A rule
//! without limits costs one relaxed load per read.
//!
//! Also the start time of the process (`rproxy_process_start_time_seconds`, #166 5.2).

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::core::limits::{lock, SourceTable, TokenBucket};

use crate::error::ApiError;

/// 8 kbit/s .. 100 Gbit/s.
const MIN_RATE: u64 = 8_000;
const MAX_RATE: u64 = 100_000_000_000;
/// 1 KiB .. 1 GiB.
const MIN_BURST: u64 = 1 << 10;
const MAX_BURST: u64 = 1 << 30;
const MAX_SOURCES: u64 = 10_000_000;

/// `bandwidth` of a rule. `{}` means no limits (how PATCH removes them).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BandwidthSpec {
	/// Client → backend, the whole rule (`"100Mbps"`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub upload: Option<String>,
	/// Backend → client, the whole rule.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub download: Option<String>,
	/// What may pass at once (`"1MiB"`; default: 100 ms worth of the rate).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub burst: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub per_source: Option<PerSourceBandwidth>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerSourceBandwidth {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub upload: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub download: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prefix_v4: Option<u8>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prefix_v6: Option<u8>,
	/// Most sources remembered (default 65536).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_sources: Option<u64>,
}

/// A rate in bits per second: `"<n>bps"`, `kbps`, `Mbps`, `Gbps` (steps of 1000).
pub fn parse_rate(s: &str) -> Result<u64, String> {
	let bad = || format!("{s:?} is not a rate (e.g. 500kbps, 10Mbps, 1Gbps)");
	let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(bad)?;
	let (num, unit) = s.split_at(split);
	let n: u64 = num.parse().map_err(|_| bad())?;
	let mult: u64 = match unit {
		"bps" => 1,
		"kbps" => 1_000,
		"Mbps" => 1_000_000,
		"Gbps" => 1_000_000_000,
		_ => return Err(bad()),
	};
	let rate = n.checked_mul(mult).ok_or_else(bad)?;
	if !(MIN_RATE..=MAX_RATE).contains(&rate) {
		return Err(format!("{s:?} must be 8kbps-100Gbps"));
	}
	Ok(rate)
}

/// A size in bytes: a plain number or `"<n>B"`, `KiB`, `MiB`, `GiB` (steps of 1024).
pub fn parse_size(s: &str) -> Result<u64, String> {
	let bad = || format!("{s:?} is not a size (e.g. 4096, 64KiB, 1MiB)");
	let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
	let (num, unit) = s.split_at(split);
	let n: u64 = num.parse().map_err(|_| bad())?;
	let mult: u64 = match unit {
		"" | "B" => 1,
		"KiB" => 1 << 10,
		"MiB" => 1 << 20,
		"GiB" => 1 << 30,
		_ => return Err(bad()),
	};
	n.checked_mul(mult).ok_or_else(bad)
}

fn rate(what: &str, value: &Option<String>) -> Result<(), ApiError> {
	if let Some(v) = value {
		parse_rate(v).map_err(|e| ApiError::invalid(format!("{what}: {e}")))?;
	}
	Ok(())
}

impl BandwidthSpec {
	/// `{}`: no limits.
	pub fn is_empty(&self) -> bool {
		*self == BandwidthSpec::default()
	}

	pub fn validate(&self) -> Result<(), ApiError> {
		rate("bandwidth.upload", &self.upload)?;
		rate("bandwidth.download", &self.download)?;
		if let Some(b) = &self.burst {
			let n = parse_size(b).map_err(|e| ApiError::invalid(format!("bandwidth.burst: {e}")))?;
			if !(MIN_BURST..=MAX_BURST).contains(&n) {
				return Err(ApiError::invalid("bandwidth.burst must be 1KiB-1GiB"));
			}
		}
		let mut any = self.upload.is_some() || self.download.is_some();
		if let Some(p) = &self.per_source {
			rate("bandwidth.per_source.upload", &p.upload)?;
			rate("bandwidth.per_source.download", &p.download)?;
			if p.prefix_v4.is_some_and(|n| n == 0 || n > 32) {
				return Err(ApiError::invalid("bandwidth.per_source.prefix_v4 must be 1-32"));
			}
			if p.prefix_v6.is_some_and(|n| n == 0 || n > 128) {
				return Err(ApiError::invalid("bandwidth.per_source.prefix_v6 must be 1-128"));
			}
			if p.max_sources.is_some_and(|n| n == 0 || n > MAX_SOURCES) {
				return Err(ApiError::invalid(format!("bandwidth.per_source.max_sources must be 1-{MAX_SOURCES}")));
			}
			if p.upload.is_none() && p.download.is_none() {
				return Err(ApiError::invalid("bandwidth.per_source needs upload or download"));
			}
			any = true;
		}
		if !any {
			return Err(ApiError::invalid("bandwidth needs a rate (upload, download or per_source)"));
		}
		Ok(())
	}
}

// ---- run time ----

/// A waiting connection is let through once a bucket has refilled this much
/// (or its whole size, when smaller): fewer, larger reads than byte by byte.
const CHUNK: f64 = 4096.0;

static PROCESS_START: AtomicU64 = AtomicU64::new(0);

fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// When this process started, in Unix seconds (`rproxy_process_start_time_seconds`);
/// the first call fixes it (the registry calls it at startup).
pub fn process_start() -> u64 {
	let now = unix_now();
	match PROCESS_START.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed) {
		Ok(_) => now,
		Err(v) => v,
	}
}

/// Takes over the start time of the process handing its sockets over (#174).
pub fn set_process_start(secs: u64) {
	PROCESS_START.store(secs, Ordering::Relaxed);
}

/// Which way the bytes go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
	/// Client to backend.
	Up,
	/// Backend to client.
	Down,
}

/// One rate, in bytes.
struct Bucket {
	per_sec: f64,
	cap: f64,
	state: Mutex<TokenBucket>,
}

impl Bucket {
	fn new(rate: &Option<String>, burst: Option<u64>) -> Option<Bucket> {
		let bps = parse_rate(rate.as_deref()?).ok()?;
		let per_sec = bps as f64 / 8.0;
		// default: 100 ms worth of the rate
		let cap = burst.map_or(per_sec / 10.0, |b| b as f64);
		Some(Bucket { per_sec, cap, state: Mutex::new(TokenBucket::full(cap, Instant::now())) })
	}

	fn tokens(&self, now: Instant) -> f64 {
		lock(&self.state).refill(self.cap, self.per_sec, now)
	}

	fn spend(&self, n: usize, now: Instant) {
		let mut s = lock(&self.state);
		s.refill(self.cap, self.per_sec, now);
		s.spend(n as f64);
	}

	/// How long until there are `want` tokens, from `tokens`.
	fn wait(&self, tokens: f64, want: f64) -> Duration {
		Duration::from_secs_f64(((want - tokens) / self.per_sec).max(0.0)).max(Duration::from_millis(1))
	}
}

/// The buckets of one source group.
pub struct SourceBuckets {
	up: Option<Bucket>,
	down: Option<Bucket>,
}

struct PerSource {
	table: SourceTable<Arc<SourceBuckets>>,
	upload: Option<String>,
	download: Option<String>,
}

/// The `bandwidth` of a rule at run time.
pub struct Shaper {
	up: Option<Bucket>,
	down: Option<Bucket>,
	burst: Option<u64>,
	per_source: Option<PerSource>,
}

impl Shaper {
	pub fn new(spec: &BandwidthSpec) -> Shaper {
		let burst = spec.burst.as_deref().and_then(|b| parse_size(b).ok());
		Shaper {
			up: Bucket::new(&spec.upload, burst),
			down: Bucket::new(&spec.download, burst),
			burst,
			per_source: spec.per_source.as_ref().filter(|p| p.upload.is_some() || p.download.is_some()).map(|p| PerSource {
				table: SourceTable::new(p.prefix_v4, p.prefix_v6, p.max_sources),
				upload: p.upload.clone(),
				download: p.download.clone(),
			}),
		}
	}

	/// The buckets of `client`'s source group (shared by its connections).
	fn source(&self, client: IpAddr) -> Option<Arc<SourceBuckets>> {
		let p = self.per_source.as_ref()?;
		let burst = self.burst;
		Some(p.table.with(
			p.table.key(client),
			|| Arc::new(SourceBuckets { up: Bucket::new(&p.upload, burst), down: Bucket::new(&p.download, burst) }),
			// a source whose connections still hold its buckets
			|b| Arc::strong_count(b) > 1,
			|b| b.clone(),
		))
	}

	/// Sources remembered now.
	pub fn sources(&self) -> usize {
		self.per_source.as_ref().map_or(0, |p| p.table.len())
	}
}

/// A rule's `bandwidth` (`Runtime.bandwidth`).
#[derive(Default)]
pub struct Bandwidth {
	on: AtomicBool,
	/// Bumped on each change, for gates to pick up the new `Shaper`.
	generation: AtomicU64,
	current: RwLock<Option<Arc<Shaper>>>,
}

impl Bandwidth {
	/// Whether the rule has a limit now.
	pub fn is_on(&self) -> bool {
		self.on.load(Ordering::Relaxed)
	}

	pub fn get(&self) -> Option<Arc<Shaper>> {
		self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
	}

	/// Puts `spec` into effect from the next read (or datagram) on; None removes it.
	pub fn set(&self, spec: Option<&BandwidthSpec>) {
		let mut current = self.current.write().unwrap_or_else(|e| e.into_inner());
		*current = spec.map(|s| Arc::new(Shaper::new(s)));
		self.generation.fetch_add(1, Ordering::Release);
		self.on.store(current.is_some(), Ordering::Release);
	}
}

/// One direction of one connection or UDP session.
pub struct Gate {
	client: IpAddr,
	dir: Dir,
	/// The shaper of `generation`, and the client's source buckets in it.
	cache: Option<(u64, Arc<Shaper>, Option<Arc<SourceBuckets>>)>,
	sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl Gate {
	pub fn new(client: IpAddr, dir: Dir) -> Gate {
		Gate { client, dir, cache: None, sleep: None }
	}

	/// The rule's bucket and the source's for this direction (none: no limit now).
	fn buckets(&mut self, bw: &Bandwidth) -> [Option<&Bucket>; 2] {
		if !bw.is_on() {
			self.cache = None;
			self.sleep = None;
			return [None, None];
		}
		let generation = bw.generation.load(Ordering::Acquire);
		if self.cache.as_ref().is_none_or(|(g, _, _)| *g != generation) {
			self.cache = bw.get().map(|s| {
				let source = s.source(self.client);
				(generation, s, source)
			});
		}
		let Some((_, shaper, source)) = &self.cache else { return [None, None] };
		match self.dir {
			Dir::Up => [shaper.up.as_ref(), source.as_ref().and_then(|s| s.up.as_ref())],
			Dir::Down => [shaper.down.as_ref(), source.as_ref().and_then(|s| s.down.as_ref())],
		}
	}

	/// TCP: how much may move now (`Ready(None)`: no limit), or `Pending`
	/// until the buckets have refilled.
	pub fn poll_allow(&mut self, bw: &Bandwidth, cx: &mut Context<'_>) -> Poll<Option<usize>> {
		loop {
			if !bw.is_on() {
				self.cache = None;
				self.sleep = None;
				return Poll::Ready(None);
			}
			if let Some(sleep) = self.sleep.as_mut() {
				ready!(sleep.as_mut().poll(cx));
				self.sleep = None;
			}
			let now = Instant::now();
			let mut allow = f64::INFINITY;
			let mut wait = Duration::ZERO;
			let buckets = self.buckets(bw);
			if buckets.iter().all(Option::is_none) {
				return Poll::Ready(None);
			}
			for b in buckets.into_iter().flatten() {
				let tokens = b.tokens(now);
				let want = b.cap.min(CHUNK);
				if tokens < want {
					wait = wait.max(b.wait(tokens, want));
				}
				allow = allow.min(tokens);
			}
			if wait.is_zero() {
				return Poll::Ready(Some(allow.max(1.0) as usize));
			}
			self.sleep = Some(Box::pin(tokio::time::sleep(wait)));
		}
	}

	/// Takes `n` bytes that moved from the buckets.
	pub fn spend(&mut self, bw: &Bandwidth, n: usize) {
		if n == 0 {
			return;
		}
		let now = Instant::now();
		for b in self.buckets(bw).into_iter().flatten() {
			b.spend(n, now);
		}
	}

	/// UDP: whether a datagram of `len` bytes may pass now (and takes it from
	/// the buckets); over the rate it is to be dropped.
	pub fn admit(&mut self, bw: &Bandwidth, len: usize) -> bool {
		let buckets = self.buckets(bw);
		if buckets.iter().all(Option::is_none) {
			return true;
		}
		let now = Instant::now();
		if buckets.iter().flatten().any(|b| b.tokens(now) <= 0.0) {
			return false;
		}
		for b in buckets.into_iter().flatten() {
			b.spend(len, now);
		}
		true
	}
}

/// Reads from `inner` at the pace of `gate` (writes pass through).
pub struct Shaped<'a, S> {
	inner: S,
	bw: &'a Bandwidth,
	gate: Gate,
}

impl<'a, S> Shaped<'a, S> {
	pub fn new(inner: S, bw: &'a Bandwidth, gate: Gate) -> Self {
		Shaped { inner, bw, gate }
	}

	pub fn into_inner(self) -> S {
		self.inner
	}

	pub fn into_parts(self) -> (S, Gate) {
		(self.inner, self.gate)
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for Shaped<'_, S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		let Some(allow) = ready!(this.gate.poll_allow(this.bw, cx)) else {
			return Pin::new(&mut this.inner).poll_read(cx, buf);
		};
		let mut part = buf.take(allow.min(buf.remaining()));
		let poll = Pin::new(&mut this.inner).poll_read(cx, &mut part);
		let n = part.filled().len();
		// SAFETY: `part` is the unfilled part of `buf`, and its first `n` bytes were filled
		unsafe { buf.assume_init(n) };
		buf.advance(n);
		this.gate.spend(this.bw, n);
		poll
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Shaped<'_, S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rates_and_sizes() {
		assert_eq!(parse_rate("10Mbps"), Ok(10_000_000));
		assert_eq!(parse_rate("8kbps"), Ok(8_000));
		assert!(parse_rate("1bps").is_err(), "below 8kbps");
		assert!(parse_rate("200Gbps").is_err());
		assert!(parse_rate("10MB/s").is_err());
		assert!(parse_rate("Mbps").is_err());
		assert_eq!(parse_size("64KiB"), Ok(65_536));
		assert_eq!(parse_size("4096"), Ok(4096));
		assert!(parse_size("1MB").is_err());
	}

	#[test]
	fn shape_and_validation() {
		let parse = |v: serde_json::Value| serde_json::from_value::<BandwidthSpec>(v).unwrap();
		parse(serde_json::json!({"upload": "100Mbps", "download": "500Mbps", "burst": "1MiB",
			"per_source": {"upload": "2Mbps", "prefix_v6": 64}}))
		.validate()
		.unwrap();
		assert!(parse(serde_json::json!({})).is_empty());
		for bad in [
			serde_json::json!({}),
			serde_json::json!({"upload": "fast"}),
			serde_json::json!({"upload": "1Mbps", "burst": "10B"}),
			serde_json::json!({"per_source": {"prefix_v4": 24}}),
			serde_json::json!({"per_source": {"upload": "1Mbps", "prefix_v6": 0}}),
		] {
			assert_eq!(parse(bad.clone()).validate().unwrap_err().code, "invalid", "{bad}");
		}
	}

	fn bandwidth(v: serde_json::Value) -> Bandwidth {
		let bw = Bandwidth::default();
		bw.set(Some(&serde_json::from_value(v).unwrap()));
		bw
	}

	#[test]
	fn udp_drops_over_the_rate() {
		// 80 kbit/s = 10 000 B/s, 2 KiB at once
		let bw = bandwidth(serde_json::json!({"upload": "80kbps", "burst": "2KiB"}));
		let mut up = Gate::new("192.0.2.1".parse().unwrap(), Dir::Up);
		let passed = (0..10).filter(|_| up.admit(&bw, 1000)).count();
		assert_eq!(passed, 3, "2048 B of tokens: the third datagram goes into debt, the fourth is dropped");
		let mut down = Gate::new("192.0.2.1".parse().unwrap(), Dir::Down);
		assert!((0..10).all(|_| down.admit(&bw, 1000)), "no download limit");
		bw.set(None);
		assert!(up.admit(&bw, 1_000_000), "removed: no limit");
	}

	#[test]
	fn per_source_buckets_are_shared_by_a_source() {
		let bw = bandwidth(serde_json::json!({"per_source": {"download": "80kbps", "prefix_v4": 24}}));
		// default burst: 100 ms = 1000 B
		let mut a = Gate::new("192.0.2.1".parse().unwrap(), Dir::Down);
		let mut b = Gate::new("192.0.2.2".parse().unwrap(), Dir::Down);
		let mut c = Gate::new("198.51.100.1".parse().unwrap(), Dir::Down);
		assert!(a.admit(&bw, 1500));
		assert!(!b.admit(&bw, 10), "the same /24 shares the bucket");
		assert!(c.admit(&bw, 10), "another source has its own");
		assert_eq!(bw.get().unwrap().sources(), 2);
	}

	#[tokio::test]
	async fn tcp_reads_wait_for_the_rate() {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};
		// 800 kbit/s = 100 000 B/s, burst 10 KiB: 60 KB take about 0.5 s
		let bw = bandwidth(serde_json::json!({"upload": "800kbps", "burst": "10KiB"}));
		let (mut w, r) = tokio::io::duplex(1 << 20);
		w.write_all(&vec![7u8; 60_000]).await.unwrap();
		drop(w);
		let mut shaped = Shaped::new(r, &bw, Gate::new("192.0.2.1".parse().unwrap(), Dir::Up));
		let started = Instant::now();
		let mut got = Vec::new();
		shaped.read_to_end(&mut got).await.unwrap();
		let took = started.elapsed();
		assert_eq!(got.len(), 60_000);
		assert!(took >= Duration::from_millis(400) && took < Duration::from_secs(3), "{took:?}");
	}

	#[test]
	fn the_process_start_is_fixed_once() {
		let first = process_start();
		assert!(first > 1_700_000_000);
		assert_eq!(process_start(), first);
	}
}
