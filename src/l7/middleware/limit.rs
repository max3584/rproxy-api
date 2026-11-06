//! `rate_limit` (token bucket per source) and `in_flight` (concurrent requests
//! per client) middlewares (#54). Their state belongs to the compiled router, so
//! changing the rule's `http` starts the counts afresh.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::header::{HeaderMap, HeaderName};

use crate::error::ApiError;

/// At most this many sources are tracked per middleware; beyond it the buckets that are
/// full again are dropped (they are like new ones), then if needed the idle half, so
/// clients rotating addresses cannot exhaust memory. From half of it on (`PRESSURE`), IPv6
/// clients are counted by /48 instead of /64 (#356): rotating /64s of a /48 does not fill it.
pub const MAX_KEYS: usize = 100_000;
const PRESSURE: usize = MAX_KEYS / 2;

/// Whose requests share a bucket.
#[derive(Debug, Clone)]
pub enum Source {
	/// The client address (after `global.trusted_proxies`).
	Ip,
	/// The value of a request header; the client address when the header is missing.
	Header(HeaderName),
}

impl Source {
	pub fn parse(s: &str) -> Result<Source, ApiError> {
		if s == "ip" {
			return Ok(Source::Ip);
		}
		let name = s.strip_prefix("header:").map(str::trim).filter(|n| !n.is_empty());
		let name = name.ok_or_else(|| ApiError::invalid(format!("source {s:?} must be ip or header:<name>")))?;
		HeaderName::from_bytes(name.as_bytes())
			.map(Source::Header)
			.map_err(|_| ApiError::invalid(format!("source {s:?}: {name:?} is not a header name")))
	}

	/// The bucket's key (#333): a header's value longer than `MAX_KEY_VALUE` is kept as its
	/// SHA-256 (100 000 keys of 64 KiB values would be 6 GiB), an IPv6 client as its /64
	/// (one host usually has a whole /64 and could take a new address for every request).
	pub fn key(&self, headers: &HeaderMap, client: IpAddr) -> String {
		self.key_by(headers, client, 64)
	}

	/// `key` with IPv6 clients by `/v6` (64 or, under pressure, 48).
	fn key_by(&self, headers: &HeaderMap, client: IpAddr, v6: u8) -> String {
		match self {
			Source::Header(name) => match headers.get(name).and_then(|v| v.to_str().ok()) {
				Some(v) if v.len() <= MAX_KEY_VALUE => format!("h:{v}"),
				Some(v) => {
					use sha2::Digest as _;
					let digest = sha2::Sha256::digest(v.as_bytes());
					let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
					format!("s:{hex}")
				}
				None => ip_key(client, v6),
			},
			Source::Ip => ip_key(client, v6),
		}
	}
}

/// Header values up to this length are keys as they are; longer ones by their hash.
pub const MAX_KEY_VALUE: usize = 64;

/// An IPv4 client by its address, an IPv6 one by its /`v6` (64 or 48).
fn ip_key(client: IpAddr, v6: u8) -> String {
	match client {
		IpAddr::V4(a) => a.to_string(),
		IpAddr::V6(a) => match a.to_ipv4_mapped() {
			Some(v4) => v4.to_string(),
			None => {
				let prefix = u128::from(a) & !((1u128 << (128 - u32::from(v6))) - 1);
				format!("{}/{v6}", std::net::Ipv6Addr::from(prefix))
			}
		},
	}
}

#[derive(Debug)]
struct Bucket {
	tokens: f64,
	at: Instant,
}

#[derive(Debug)]
struct Buckets {
	map: HashMap<String, Bucket>,
	last_sweep: Instant,
}

/// Token bucket per source: `average` requests per `period`, at most `burst` at once.
#[derive(Debug)]
pub struct RateLimiter {
	pub source: Source,
	/// Tokens added per second.
	rate: f64,
	burst: f64,
	buckets: Mutex<Buckets>,
	/// `PRESSURE` sources or more are tracked: IPv6 clients by /48.
	pressure: std::sync::atomic::AtomicBool,
}

impl RateLimiter {
	pub fn new(average: u64, period: Duration, burst: Option<u64>, source: Source) -> RateLimiter {
		RateLimiter {
			source,
			rate: average as f64 / period.as_secs_f64().max(f64::MIN_POSITIVE),
			// as in Traefik: without burst, one request at a time
			burst: burst.unwrap_or(1).max(1) as f64,
			buckets: Mutex::new(Buckets { map: HashMap::new(), last_sweep: Instant::now() }),
			pressure: Default::default(),
		}
	}

	/// The bucket's key of a request (`Source::key`; IPv6 clients by /48 under pressure).
	pub fn key(&self, headers: &HeaderMap, client: IpAddr) -> String {
		let v6 = if self.pressure.load(std::sync::atomic::Ordering::Relaxed) { 48 } else { 64 };
		self.source.key_by(headers, client, v6)
	}

	/// Time for an empty bucket to fill up; an idle bucket that long is like a new one.
	fn refill_time(&self) -> Duration {
		Duration::from_secs_f64((self.burst / self.rate).min(86_400.0 * 365.0))
	}

	/// Takes a token for `key`; when there is none, how long until there is.
	pub fn check(&self, key: &str) -> Result<(), Duration> {
		self.check_at(key, Instant::now())
	}

	fn check_at(&self, key: &str, now: Instant) -> Result<(), Duration> {
		let mut b = self.buckets.lock().unwrap();
		let refill = self.refill_time();
		if now.saturating_duration_since(b.last_sweep) >= refill.max(Duration::from_secs(10)) {
			b.map.retain(|_, v| now.saturating_duration_since(v.at) < refill);
			b.last_sweep = now;
		}
		if !b.map.contains_key(key) && b.map.len() >= MAX_KEYS {
			self.shrink(&mut b.map, now);
		}
		let bucket = b.map.entry(key.to_string()).or_insert(Bucket { tokens: self.burst, at: now });
		let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
		bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
		bucket.at = now;
		let verdict = if bucket.tokens >= 1.0 {
			bucket.tokens -= 1.0;
			Ok(())
		} else {
			Err(Duration::from_secs_f64((1.0 - bucket.tokens) / self.rate))
		};
		let len = b.map.len();
		let pressure = &self.pressure;
		if len >= PRESSURE {
			pressure.store(true, std::sync::atomic::Ordering::Relaxed);
		} else if len < PRESSURE / 2 {
			pressure.store(false, std::sync::atomic::Ordering::Relaxed);
		}
		verdict
	}

	/// Makes room: drops the buckets that are full again (as good as new ones, so a client
	/// being limited keeps its bucket), then, while that is not a quarter, the least recently
	/// used half.
	fn shrink(&self, map: &mut HashMap<String, Bucket>, now: Instant) {
		map.retain(|_, b| b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * self.rate < self.burst);
		if map.len() >= MAX_KEYS - MAX_KEYS / 4 {
			shrink(map);
		}
	}

	#[cfg(test)]
	fn tracked(&self) -> usize {
		self.buckets.lock().unwrap().map.len()
	}
}

/// Drops the least recently used half of the buckets.
fn shrink(map: &mut HashMap<String, Bucket>) {
	let mut times: Vec<Instant> = map.values().map(|b| b.at).collect();
	let mid = times.len() / 2;
	let (_, median, _) = times.select_nth_unstable(mid);
	let median = *median;
	map.retain(|_, b| b.at > median);
}

/// Requests in progress per client, released when the response has been sent.
#[derive(Debug)]
pub struct InFlight {
	amount: u64,
	counts: Mutex<HashMap<String, u64>>,
}

/// One request counted by `in_flight` (or on a server, for `balance:
/// least_conn`); dropping it frees the place.
#[derive(Debug)]
pub struct Hold {
	limiter: Option<Arc<InFlight>>,
	key: String,
	/// A plain counter (requests in progress on a server).
	counter: Option<Arc<std::sync::atomic::AtomicU64>>,
}

impl Hold {
	/// Counts one request on `counter` until dropped.
	pub fn counting(counter: Arc<std::sync::atomic::AtomicU64>) -> Hold {
		counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		Hold { limiter: None, key: String::new(), counter: Some(counter) }
	}

	/// Counts one request on `counter` unless `max` are counted already (a server's
	/// `max_connections`, #341); the check and the count are one atomic step.
	pub fn counting_below(counter: Arc<std::sync::atomic::AtomicU64>, max: u64) -> Option<Hold> {
		use std::sync::atomic::Ordering::Relaxed;
		let mut n = counter.load(Relaxed);
		loop {
			if n >= max {
				return None;
			}
			match counter.compare_exchange_weak(n, n + 1, Relaxed, Relaxed) {
				Ok(_) => return Some(Hold { limiter: None, key: String::new(), counter: Some(counter) }),
				Err(now) => n = now,
			}
		}
	}
}

impl Drop for Hold {
	fn drop(&mut self) {
		if let Some(c) = &self.counter {
			c.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
		}
		let Some(limiter) = &self.limiter else { return };
		let mut counts = limiter.counts.lock().unwrap();
		if let Some(n) = counts.get_mut(&self.key) {
			*n -= 1;
			if *n == 0 {
				counts.remove(&self.key);
			}
		}
	}
}

impl InFlight {
	pub fn new(amount: u64) -> Arc<InFlight> {
		Arc::new(InFlight { amount, counts: Mutex::new(HashMap::new()) })
	}

	/// A place for one more request of `key`, or None when all are taken.
	pub fn acquire(self: &Arc<Self>, key: &str) -> Option<Hold> {
		let mut counts = self.counts.lock().unwrap();
		let n = counts.entry(key.to_string()).or_insert(0);
		if *n >= self.amount {
			return None;
		}
		*n += 1;
		Some(Hold { limiter: Some(self.clone()), key: key.to_string(), counter: None })
	}

	#[cfg(test)]
	fn in_use(&self, key: &str) -> u64 {
		self.counts.lock().unwrap().get(key).copied().unwrap_or(0)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn buckets_allow_the_burst_then_the_average() {
		let t0 = Instant::now();
		// 2 per second, burst 3
		let l = RateLimiter::new(2, Duration::from_secs(1), Some(3), Source::Ip);
		for _ in 0..3 {
			assert!(l.check_at("a", t0).is_ok());
		}
		let wait = l.check_at("a", t0).unwrap_err();
		assert!((wait.as_secs_f64() - 0.5).abs() < 1e-6, "{wait:?}");
		assert!(l.check_at("b", t0).is_ok(), "sources are separate");
		// half a second later one token is back, not more
		let t1 = t0 + Duration::from_millis(500);
		assert!(l.check_at("a", t1).is_ok());
		assert!(l.check_at("a", t1).is_err());
		// a long pause refills to the burst, not beyond
		let t2 = t1 + Duration::from_secs(60);
		for _ in 0..3 {
			assert!(l.check_at("a", t2).is_ok());
		}
		assert!(l.check_at("a", t2).is_err());
	}

	#[test]
	fn without_burst_one_at_a_time() {
		let t0 = Instant::now();
		// 5 per minute
		let l = RateLimiter::new(5, Duration::from_secs(60), None, Source::Ip);
		assert!(l.check_at("a", t0).is_ok());
		assert_eq!(l.check_at("a", t0).unwrap_err().as_secs(), 12);
		assert!(l.check_at("a", t0 + Duration::from_secs(12)).is_ok());
	}

	#[test]
	fn idle_and_excess_buckets_are_dropped() {
		let t0 = Instant::now();
		let l = RateLimiter::new(1, Duration::from_secs(1), Some(1), Source::Ip);
		for i in 0..10 {
			l.check_at(&i.to_string(), t0).unwrap();
		}
		assert_eq!(l.tracked(), 10);
		// after the sweep interval every bucket has refilled and is forgotten
		l.check_at("new", t0 + Duration::from_secs(11)).unwrap();
		assert_eq!(l.tracked(), 1);

		let mut map = HashMap::new();
		for i in 0..10u64 {
			map.insert(i.to_string(), Bucket { tokens: 0.0, at: t0 + Duration::from_secs(i) });
		}
		shrink(&mut map);
		assert_eq!(map.len(), 4);
		assert!(map.contains_key("9") && !map.contains_key("0"), "the least recently used go");
	}

	#[test]
	fn sources() {
		let mut h = HeaderMap::new();
		h.insert("x-api-key", "k1".parse().unwrap());
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		assert_eq!(Source::parse("ip").unwrap().key(&h, ip), "10.0.0.1");
		let s = Source::parse("header: X-Api-Key").unwrap();
		assert_eq!(s.key(&h, ip), "h:k1");
		assert_eq!(s.key(&HeaderMap::new(), ip), "10.0.0.1", "no header: the client address");
	}

	#[test]
	fn keys_are_bounded() {
		// #333: a long header value is kept as its hash, the same value the same key
		let s = Source::parse("header:x-key").unwrap();
		let ip: IpAddr = "10.0.0.1".parse().unwrap();
		let mut h = HeaderMap::new();
		h.insert("x-key", "k".repeat(MAX_KEY_VALUE).parse().unwrap());
		assert_eq!(s.key(&h, ip), format!("h:{}", "k".repeat(MAX_KEY_VALUE)));
		h.insert("x-key", "k".repeat(60_000).parse().unwrap());
		let long = s.key(&h, ip);
		assert!(long.starts_with("s:") && long.len() == 66, "{long}");
		assert_eq!(s.key(&h, ip), long);
		h.insert("x-key", format!("{}x", "k".repeat(59_999)).parse().unwrap());
		assert_ne!(s.key(&h, ip), long);
		// IPv6 clients by their /64; IPv4 (and IPv4-mapped) by the address
		let v6 = |a: &str| Source::Ip.key(&HeaderMap::new(), a.parse().unwrap());
		assert_eq!(v6("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::/64");
		assert_eq!(v6("2001:db8:1:2:ffff:1:2:3"), v6("2001:db8:1:2::9"));
		assert_ne!(v6("2001:db8:1:2::1"), v6("2001:db8:1:3::1"));
		assert_eq!(v6("::ffff:10.0.0.1"), "10.0.0.1");
		assert_eq!(s.key(&HeaderMap::new(), "2001:db8::5".parse().unwrap()), "2001:db8::/64", "no header: the client's /64");
		assert!(Source::parse("cookie:x").is_err());
		assert!(Source::parse("header:").is_err());
		assert!(Source::parse("header:bad name").is_err());
	}

	#[test]
	fn in_flight_places_are_freed() {
		let f = InFlight::new(2);
		let a = f.acquire("c").unwrap();
		let _b = f.acquire("c").unwrap();
		assert!(f.acquire("c").is_none());
		assert!(f.acquire("d").is_some(), "per client");
		drop(a);
		assert_eq!(f.in_use("c"), 1);
		assert!(f.acquire("c").is_some());
	}

	#[test]
	fn full_buckets_go_first_and_ipv6_is_coarser_under_pressure() {
		let t0 = Instant::now();
		let l = RateLimiter::new(1, Duration::from_secs(1000), Some(2), Source::Ip);
		let mut map = HashMap::new();
		// a limited client (empty bucket) among many new ones whose buckets are full again
		map.insert("limited".to_string(), Bucket { tokens: 0.0, at: t0 });
		for i in 0..MAX_KEYS {
			map.insert(i.to_string(), Bucket { tokens: 2.0, at: t0 });
		}
		l.shrink(&mut map, t0);
		assert!(map.contains_key("limited"), "kept");
		assert_eq!(map.len(), 1);

		let h = HeaderMap::new();
		let v6: IpAddr = "2001:db8:1:2:3::4".parse().unwrap();
		assert_eq!(l.key(&h, v6), "2001:db8:1:2::/64");
		l.pressure.store(true, std::sync::atomic::Ordering::Relaxed);
		assert_eq!(l.key(&h, v6), "2001:db8:1::/48");
		assert_eq!(l.key(&h, "10.0.0.1".parse().unwrap()), "10.0.0.1");
	}
}
