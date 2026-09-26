//! `rate_limit` (token bucket per source) and `in_flight` (concurrent requests
//! per client) middlewares (#54). Their state belongs to the compiled router, so
//! changing the rule's `http` starts the counts afresh.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hyper::header::{HeaderMap, HeaderName};

use crate::error::ApiError;

/// At most this many sources are tracked per middleware; beyond it the idle half
/// is dropped, so clients rotating addresses cannot exhaust memory.
pub const MAX_KEYS: usize = 100_000;

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

	pub fn key(&self, headers: &HeaderMap, client: IpAddr) -> String {
		match self {
			Source::Header(name) => match headers.get(name).and_then(|v| v.to_str().ok()) {
				Some(v) => format!("h:{v}"),
				None => client.to_string(),
			},
			Source::Ip => client.to_string(),
		}
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
}

impl RateLimiter {
	pub fn new(average: u64, period: Duration, burst: Option<u64>, source: Source) -> RateLimiter {
		RateLimiter {
			source,
			rate: average as f64 / period.as_secs_f64().max(f64::MIN_POSITIVE),
			// as in Traefik: without burst, one request at a time
			burst: burst.unwrap_or(1).max(1) as f64,
			buckets: Mutex::new(Buckets { map: HashMap::new(), last_sweep: Instant::now() }),
		}
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
			shrink(&mut b.map);
		}
		let bucket = b.map.entry(key.to_string()).or_insert(Bucket { tokens: self.burst, at: now });
		let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
		bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
		bucket.at = now;
		if bucket.tokens >= 1.0 {
			bucket.tokens -= 1.0;
			Ok(())
		} else {
			Err(Duration::from_secs_f64((1.0 - bucket.tokens) / self.rate))
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

/// One request counted by `in_flight`; dropping it frees the place.
#[derive(Debug)]
pub struct Hold {
	limiter: Arc<InFlight>,
	key: String,
}

impl Drop for Hold {
	fn drop(&mut self) {
		let mut counts = self.limiter.counts.lock().unwrap();
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
		Some(Hold { limiter: self.clone(), key: key.to_string() })
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
}
