//! L4 limits of a rule (#165, docs/DESIGN-v0.4.md 4.): the whole rule's
//! concurrent connections, and per client source (an address or a prefix)
//! concurrent connections, new connections and UDP datagrams.
//!
//! The checks run right after a connection is accepted (TCP) or a datagram
//! received (UDP), after `allow_from` and CrowdSec and before TLS or a PROXY
//! header: `Limits::get` gives the rule's `Limiter` (None, after one relaxed
//! load, when the rule has no limits), `Limiter::admit` a `Permit` that counts the
//! connection or UDP session until it is dropped, `Limiter::packet` the datagram
//! rate. A PATCH replaces the `Limiter` and keeps what it counts (`Limits::set`).
//!
//! Sources are kept in a `SourceTable` (also used by `core::bandwidth`): an
//! address grouped by prefix, at most `max_sources` of them, in shards with a
//! lock each; when a shard is full, the oldest idle source is forgotten. A
//! source that still has connections is never forgotten (its limits would start
//! over): while a shard is full of them, new sources are refused (`limits`) or
//! share one overflow bucket (`bandwidth`). Security review L8.

use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use tracing::{debug, info};

use serde::{Deserialize, Serialize};

use crate::core::rule::Protocol;
use crate::error::ApiError;

const MAX_CONNECTIONS: u64 = 10_000_000;
const MAX_SOURCE_CONNECTIONS: u64 = 1_000_000;
pub const DEFAULT_MAX_SOURCES: u64 = 65_536;
const MAX_SOURCES: u64 = 1_000_000;

/// `limits` of a rule. `{}` means no limits (how PATCH removes them).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSpec {
	/// Concurrent connections of the whole rule (UDP: sessions).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_connections: Option<u64>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub per_source: Option<PerSourceLimits>,
}

/// Limits per client source.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerSourceLimits {
	/// How IPv4 sources are grouped (default 32: one address).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prefix_v4: Option<u8>,
	/// How IPv6 sources are grouped (default 64).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prefix_v6: Option<u8>,
	/// Concurrent connections of one source (UDP: sessions).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_connections: Option<u64>,
	/// New connections (UDP: new sessions) of one source.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub new_connections: Option<RateSpec>,
	/// Datagrams of one source (udp only).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub packets: Option<RateSpec>,
	/// Most sources remembered; the oldest are forgotten first (default 65536).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_sources: Option<u64>,
}

/// A token bucket, the shape of the L7 `rate_limit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateSpec {
	/// Events per `period` on average.
	pub average: u64,
	/// Default 1s.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub period: Option<String>,
	/// Events allowed at once (default `average`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub burst: Option<u64>,
}

impl RateSpec {
	/// Checks the values; returns the period.
	pub fn validate(&self, what: &str) -> Result<Duration, ApiError> {
		if self.average == 0 {
			return Err(ApiError::invalid(format!("{what}.average must be at least 1")));
		}
		let period = match &self.period {
			Some(p) => crate::l7::parse_duration(p).map_err(|e| ApiError::invalid(format!("{what}.period: {e}")))?,
			None => Duration::from_secs(1),
		};
		if period < Duration::from_millis(1) || period > Duration::from_secs(3600) {
			return Err(ApiError::invalid(format!("{what}.period must be 1ms-1h")));
		}
		if self.burst.is_some_and(|b| b < self.average) {
			return Err(ApiError::invalid(format!("{what}.burst must not be below average")));
		}
		Ok(period)
	}
}

fn range(what: &str, value: Option<u64>, max: u64) -> Result<(), ApiError> {
	match value {
		Some(v) if v == 0 || v > max => Err(ApiError::invalid(format!("{what} must be 1-{max}"))),
		_ => Ok(()),
	}
}

impl LimitsSpec {
	/// `{}`: no limits.
	pub fn is_empty(&self) -> bool {
		self.max_connections.is_none() && self.per_source.is_none()
	}

	pub fn validate(&self, protocol: Protocol) -> Result<(), ApiError> {
		range("limits.max_connections", self.max_connections, MAX_CONNECTIONS)?;
		let Some(p) = &self.per_source else { return Ok(()) };
		if p.prefix_v4.is_some_and(|n| n == 0 || n > 32) {
			return Err(ApiError::invalid("limits.per_source.prefix_v4 must be 1-32"));
		}
		if p.prefix_v6.is_some_and(|n| n == 0 || n > 128) {
			return Err(ApiError::invalid("limits.per_source.prefix_v6 must be 1-128"));
		}
		range("limits.per_source.max_connections", p.max_connections, MAX_SOURCE_CONNECTIONS)?;
		range("limits.per_source.max_sources", p.max_sources, MAX_SOURCES)?;
		if let Some(r) = &p.new_connections {
			r.validate("limits.per_source.new_connections")?;
		}
		if let Some(r) = &p.packets {
			if protocol != Protocol::Udp {
				return Err(ApiError::invalid("limits.per_source.packets is for udp rules only"));
			}
			r.validate("limits.per_source.packets")?;
		}
		if p.max_connections.is_none() && p.new_connections.is_none() && p.packets.is_none() {
			return Err(ApiError::invalid(
				"limits.per_source needs max_connections, new_connections or packets",
			));
		}
		Ok(())
	}
}

// ---- run time ----

const DEFAULT_PREFIX_V4: u8 = 32;
const DEFAULT_PREFIX_V6: u8 = 64;
/// Shards of a source table (fewer when `max_sources` is smaller).
const TABLE_SHARDS: usize = 16;
/// Sources that still have connections are moved to the back this many times
/// before one is forgotten anyway.
/// Entries of a full shard looked at for one that can be forgotten.
const SCAN: usize = 64;

/// Locks a mutex even if a thread panicked while holding it (the data is
/// counters: still usable).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
	m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The source group of a client address: the address with only its first
/// `v4` / `v6` bits (IPv4-mapped IPv6 addresses count as IPv4).
pub fn source_key(ip: IpAddr, v4: u8, v6: u8) -> IpAddr {
	match ip.to_canonical() {
		IpAddr::V4(a) => {
			let mask = u32::MAX.checked_shl(32 - u32::from(v4.min(32))).unwrap_or(0);
			IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
		}
		IpAddr::V6(a) => {
			let mask = u128::MAX.checked_shl(128 - u32::from(v6.min(128))).unwrap_or(0);
			IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
		}
	}
}

/// A token bucket's state; its size and rate are given on each use, so they can
/// change (PATCH) while the state is kept.
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
	tokens: f64,
	at: Instant,
}

impl TokenBucket {
	pub fn full(cap: f64, now: Instant) -> Self {
		TokenBucket { tokens: cap, at: now }
	}

	/// The tokens now (at most `cap`; may be negative after `spend`).
	pub fn refill(&mut self, cap: f64, per_sec: f64, now: Instant) -> f64 {
		self.tokens = (self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * per_sec).min(cap);
		self.at = now;
		self.tokens
	}

	/// Takes one token if there is one.
	pub fn take_one(&mut self, cap: f64, per_sec: f64, now: Instant) -> bool {
		if self.refill(cap, per_sec, now) >= 1.0 {
			self.tokens -= 1.0;
			true
		} else {
			false
		}
	}

	/// Takes `n`, going below zero if need be (a debt paid back by waiting).
	pub fn spend(&mut self, n: f64) {
		self.tokens -= n;
	}
}

/// `{average, period, burst}` as a bucket size and a rate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rate {
	pub cap: f64,
	pub per_sec: f64,
}

impl Rate {
	fn of(spec: &RateSpec) -> Rate {
		let period = spec.validate("").unwrap_or(Duration::from_secs(1));
		Rate { cap: spec.burst.unwrap_or(spec.average) as f64, per_sec: spec.average as f64 / period.as_secs_f64() }
	}
}

struct Shard<V> {
	map: HashMap<IpAddr, V>,
	/// Keys in the order they were added (each once).
	order: VecDeque<IpAddr>,
}

/// Values per source group, bounded (see the module comment).
pub struct SourceTable<V> {
	shards: Box<[Mutex<Shard<V>>]>,
	per_shard: usize,
	hasher: std::collections::hash_map::RandomState,
	pub prefix_v4: u8,
	pub prefix_v6: u8,
	pub max_sources: u64,
}

impl<V> SourceTable<V> {
	pub fn new(prefix_v4: Option<u8>, prefix_v6: Option<u8>, max_sources: Option<u64>) -> Self {
		let max = max_sources.unwrap_or(DEFAULT_MAX_SOURCES).max(1);
		let n = TABLE_SHARDS.min(usize::try_from(max).unwrap_or(usize::MAX));
		let per_shard = usize::try_from(max.div_ceil(n as u64)).unwrap_or(usize::MAX);
		SourceTable {
			shards: (0..n).map(|_| Mutex::new(Shard { map: HashMap::new(), order: VecDeque::new() })).collect(),
			per_shard,
			hasher: Default::default(),
			prefix_v4: prefix_v4.unwrap_or(DEFAULT_PREFIX_V4),
			prefix_v6: prefix_v6.unwrap_or(DEFAULT_PREFIX_V6),
			max_sources: max,
		}
	}

	/// Whether this table groups and bounds sources as `other` would.
	pub fn same_shape(&self, prefix_v4: Option<u8>, prefix_v6: Option<u8>, max_sources: Option<u64>) -> bool {
		self.prefix_v4 == prefix_v4.unwrap_or(DEFAULT_PREFIX_V4)
			&& self.prefix_v6 == prefix_v6.unwrap_or(DEFAULT_PREFIX_V6)
			&& self.max_sources == max_sources.unwrap_or(DEFAULT_MAX_SOURCES).max(1)
	}

	pub fn key(&self, ip: IpAddr) -> IpAddr {
		source_key(ip, self.prefix_v4, self.prefix_v6)
	}

	fn shard(&self, key: &IpAddr) -> MutexGuard<'_, Shard<V>> {
		let i = (self.hasher.hash_one(key) % self.shards.len() as u64) as usize;
		lock(&self.shards[i])
	}

	/// Runs `f` on the value of `key`'s source, made with `new` if there is none
	/// (forgetting the oldest idle source of a full shard). A `busy` source (with
	/// connections now) is never forgotten: that would start its limits over, which
	/// a flood of new (spoofed) sources could use to get round them (security
	/// review L8). None when the shard is full of busy sources.
	pub fn try_with<R>(&self, key: IpAddr, new: impl FnOnce() -> V, busy: impl Fn(&V) -> bool, f: impl FnOnce(&mut V) -> R) -> Option<R> {
		let mut shard = self.shard(&key);
		let shard = &mut *shard;
		if !shard.map.contains_key(&key) {
			let mut looked = 0;
			while shard.map.len() >= self.per_shard {
				if looked >= SCAN.min(shard.order.len()) {
					return None;
				}
				let Some(old) = shard.order.pop_front() else { break };
				looked += 1;
				if shard.map.get(&old).is_some_and(&busy) {
					shard.order.push_back(old);
					continue;
				}
				shard.map.remove(&old);
			}
			shard.order.push_back(key);
		}
		Some(f(shard.map.entry(key).or_insert_with(new)))
	}


	/// Runs `f` on the value of `key`'s source if it is still remembered.
	pub fn with_existing(&self, key: IpAddr, f: impl FnOnce(&mut V)) {
		if let Some(v) = self.shard(&key).map.get_mut(&key) {
			f(v);
		}
	}

	/// Sources remembered now.
	pub fn len(&self) -> usize {
		self.shards.iter().map(|s| lock(s).map.len()).sum()
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}
}

/// Why a connection or datagram was refused (`conn.limited`'s `reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
	MaxConnections,
	SourceConnections,
	NewConnections,
	Packets,
}

impl Reason {
	pub const ALL: [Reason; 4] = [Reason::MaxConnections, Reason::SourceConnections, Reason::NewConnections, Reason::Packets];

	pub fn as_str(self) -> &'static str {
		match self {
			Reason::MaxConnections => "max_connections",
			Reason::SourceConnections => "source_connections",
			Reason::NewConnections => "new_connections",
			Reason::Packets => "packets",
		}
	}

	pub fn index(self) -> usize {
		self as usize
	}
}

/// What a `Limiter` counts; kept when a PATCH replaces it.
#[derive(Default)]
struct Counts {
	/// Connections / sessions of the rule holding a `Permit`.
	active: AtomicU64,
}

#[derive(Default)]
struct SourceState {
	active: u64,
	new: Option<TokenBucket>,
	packets: Option<TokenBucket>,
}

struct SourceLimits {
	max_connections: Option<u64>,
	new_connections: Option<Rate>,
	packets: Option<Rate>,
	table: Arc<SourceTable<SourceState>>,
}

/// The `limits` of a rule at run time.
pub struct Limiter {
	max_connections: Option<u64>,
	per_source: Option<SourceLimits>,
	counts: Arc<Counts>,
}

/// Counts one connection or UDP session (of the rule and of its source) while it lives.
pub struct Permit {
	counts: Arc<Counts>,
	source: Option<(Arc<SourceTable<SourceState>>, IpAddr)>,
}

impl Drop for Permit {
	fn drop(&mut self) {
		self.counts.active.fetch_sub(1, Ordering::Relaxed);
		if let Some((table, key)) = &self.source {
			table.with_existing(*key, |s| s.active = s.active.saturating_sub(1));
		}
	}
}

impl Limiter {
	/// `prev`: the limiter it replaces, whose counts it keeps (the sources too
	/// while they are grouped and bounded the same way).
	pub fn new(spec: &LimitsSpec, prev: Option<&Limiter>) -> Limiter {
		let per_source = spec.per_source.as_ref().map(|p| {
			let table = prev
				.and_then(|l| l.per_source.as_ref())
				.map(|s| &s.table)
				.filter(|t| t.same_shape(p.prefix_v4, p.prefix_v6, p.max_sources))
				.cloned()
				.unwrap_or_else(|| Arc::new(SourceTable::new(p.prefix_v4, p.prefix_v6, p.max_sources)));
			SourceLimits {
				max_connections: p.max_connections,
				new_connections: p.new_connections.as_ref().map(Rate::of),
				packets: p.packets.as_ref().map(Rate::of),
				table,
			}
		});
		Limiter {
			max_connections: spec.max_connections,
			per_source,
			counts: prev.map(|l| l.counts.clone()).unwrap_or_default(),
		}
	}

	/// A new connection (UDP: session) from `client`: a permit to hold while it
	/// lasts, or why it is refused.
	pub fn admit(&self, client: IpAddr) -> Result<Permit, Reason> {
		let before = self.counts.active.fetch_add(1, Ordering::Relaxed);
		// from here on, dropping the permit gives the place back
		let mut permit = Permit { counts: self.counts.clone(), source: None };
		if self.max_connections.is_some_and(|max| before >= max) {
			return Err(Reason::MaxConnections);
		}
		let Some(p) = &self.per_source else { return Ok(permit) };
		let key = p.table.key(client);
		let now = Instant::now();
		// a table full of sources with connections: a new source waits until one ends
		p.table.try_with(
			key,
			SourceState::default,
			|s| s.active > 0,
			|s| {
				if p.max_connections.is_some_and(|max| s.active >= max) {
					return Err(Reason::SourceConnections);
				}
				if let Some(r) = p.new_connections {
					if !s.new.get_or_insert(TokenBucket::full(r.cap, now)).take_one(r.cap, r.per_sec, now) {
						return Err(Reason::NewConnections);
					}
				}
				s.active += 1;
				Ok(())
			},
		)
		.unwrap_or(Err(Reason::SourceConnections))?;
		permit.source = Some((p.table.clone(), key));
		Ok(permit)
	}

	/// Whether a datagram from `client` is within `per_source.packets`.
	pub fn packet(&self, client: IpAddr) -> bool {
		let Some(p) = &self.per_source else { return true };
		let Some(r) = p.packets else { return true };
		let now = Instant::now();
		p.table
			.try_with(
				p.table.key(client),
				SourceState::default,
				|s| s.active > 0,
				|s| s.packets.get_or_insert(TokenBucket::full(r.cap, now)).take_one(r.cap, r.per_sec, now),
			)
			.unwrap_or(false)
	}

	/// Connections / sessions counted now.
	pub fn active(&self) -> u64 {
		self.counts.active.load(Ordering::Relaxed)
	}

	/// Sources remembered now.
	pub fn sources(&self) -> usize {
		self.per_source.as_ref().map_or(0, |p| p.table.len())
	}
}

/// A rule's `limits` (`Runtime.limits`): nothing to do but one relaxed load
/// when the rule has none.
#[derive(Default)]
pub struct Limits {
	on: AtomicBool,
	current: RwLock<Option<Arc<Limiter>>>,
}

impl Limits {
	pub fn get(&self) -> Option<Arc<Limiter>> {
		if !self.on.load(Ordering::Relaxed) {
			return None;
		}
		self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
	}

	/// Puts `spec` into effect for the next connections and datagrams, keeping
	/// what the current limiter counts. None removes the limits.
	pub fn set(&self, spec: Option<&LimitsSpec>) {
		let mut current = self.current.write().unwrap_or_else(|e| e.into_inner());
		let next = spec.map(|s| Arc::new(Limiter::new(s, current.as_deref())));
		self.on.store(next.is_some(), Ordering::Relaxed);
		*current = next;
	}
}

/// A refused connection (TCP) or datagram (UDP): counted in `stats.limited`,
/// logged as `conn.limited` at most `Throttle`'s rate per client.
pub fn refused(rt: &crate::core::proxy::Runtime, client: SocketAddr, reason: Reason, transport: &'static str) {
	rt.stats.limited(reason);
	match rt.limited_log.check(&client.ip()) {
		Some(suppressed) => info!(event = "conn.limited", rule = %rt.key, client = %client, reason = reason.as_str(), transport, suppressed),
		None => debug!(event = "conn.limited", rule = %rt.key, client = %client, reason = reason.as_str(), transport, throttled = true),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(v: serde_json::Value) -> LimitsSpec {
		serde_json::from_value(v).unwrap()
	}

	#[test]
	fn shape_and_validation() {
		let ok = parse(serde_json::json!({
			"max_connections": 20000,
			"per_source": {"prefix_v6": 56, "max_connections": 8,
				"new_connections": {"average": 10, "period": "1s", "burst": 20},
				"packets": {"average": 2000}}
		}));
		ok.validate(Protocol::Udp).unwrap();
		assert_eq!(ok.validate(Protocol::Tcp).unwrap_err().code, "invalid", "packets is udp only");
		assert!(parse(serde_json::json!({})).is_empty());
		for bad in [
			serde_json::json!({"max_connections": 0}),
			serde_json::json!({"per_source": {"prefix_v4": 33, "max_connections": 1}}),
			serde_json::json!({"per_source": {"max_connections": 1, "max_sources": 0}}),
			serde_json::json!({"per_source": {"new_connections": {"average": 0}}}),
			serde_json::json!({"per_source": {"new_connections": {"average": 5, "burst": 1}}}),
			serde_json::json!({"per_source": {"new_connections": {"average": 5, "period": "2h"}}}),
			serde_json::json!({"per_source": {"prefix_v4": 24}}),
		] {
			assert_eq!(parse(bad.clone()).validate(Protocol::Tcp).unwrap_err().code, "invalid", "{bad}");
		}
		assert!(serde_json::from_value::<LimitsSpec>(serde_json::json!({"max_conns": 1})).is_err(), "unknown fields");
	}

	fn limiter(v: serde_json::Value) -> Limiter {
		Limiter::new(&parse(v), None)
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	#[test]
	fn sources_are_grouped_by_prefix() {
		assert_eq!(source_key(ip("192.0.2.77"), 24, 64), ip("192.0.2.0"));
		assert_eq!(source_key(ip("192.0.2.77"), 32, 64), ip("192.0.2.77"));
		assert_eq!(source_key(ip("::ffff:192.0.2.77"), 24, 64), ip("192.0.2.0"), "IPv4-mapped is IPv4");
		assert_eq!(source_key(ip("2001:db8:1:2:3:4:5:6"), 32, 48), ip("2001:db8:1::"));
		assert_eq!(source_key(ip("2001:db8::1"), 32, 128), ip("2001:db8::1"));
	}

	#[test]
	fn connections_of_the_rule_and_of_a_source() {
		let l = limiter(serde_json::json!({"max_connections": 3, "per_source": {"max_connections": 2}}));
		let a1 = l.admit(ip("192.0.2.1")).unwrap();
		let a2 = l.admit(ip("192.0.2.1")).unwrap();
		assert_eq!(l.admit(ip("192.0.2.1")).err(), Some(Reason::SourceConnections));
		let b1 = l.admit(ip("192.0.2.2")).unwrap();
		assert_eq!(l.admit(ip("192.0.2.3")).err(), Some(Reason::MaxConnections));
		assert_eq!(l.active(), 3, "refusals give their place back");
		drop(a1);
		assert!(l.admit(ip("192.0.2.1")).is_ok(), "a closed connection frees its place");
		drop((a2, b1));
		assert_eq!(l.active(), 0);
	}

	#[test]
	fn new_connections_and_packets_are_rates() {
		let l = limiter(serde_json::json!({"per_source": {"prefix_v4": 24,
			"new_connections": {"average": 2, "period": "1h"}, "packets": {"average": 3, "period": "1h", "burst": 3}}}));
		assert!(l.admit(ip("192.0.2.1")).is_ok());
		assert!(l.admit(ip("192.0.2.2")).is_ok(), "the same /24");
		assert_eq!(l.admit(ip("192.0.2.3")).err(), Some(Reason::NewConnections));
		assert!(l.admit(ip("198.51.100.1")).is_ok(), "another source has its own bucket");
		let passed = (0..5).filter(|_| l.packet(ip("192.0.2.9"))).count();
		assert_eq!(passed, 3);
	}

	#[test]
	fn a_replacement_keeps_the_counts() {
		let old = limiter(serde_json::json!({"per_source": {"max_connections": 1}}));
		let p = old.admit(ip("192.0.2.1")).unwrap();
		let new = Limiter::new(&parse(serde_json::json!({"max_connections": 1, "per_source": {"max_connections": 1}})), Some(&old));
		assert_eq!(new.admit(ip("192.0.2.2")).err(), Some(Reason::MaxConnections), "the open connection still counts");
		drop(p);
		assert!(new.admit(ip("192.0.2.1")).is_ok());
	}

	#[test]
	fn sources_are_bounded_and_the_oldest_forgotten() {
		let l = limiter(serde_json::json!({"per_source": {"new_connections": {"average": 1, "period": "1h"}, "max_sources": 4}}));
		for i in 0..100 {
			let _ = l.admit(IpAddr::V4(Ipv4Addr::from(0xc000_0200 + i)));
		}
		assert!(l.sources() <= 4, "{}", l.sources());
		let t: SourceTable<u32> = SourceTable::new(None, None, Some(1));
		t.try_with(ip("192.0.2.1"), || 1, |_| false, |_| ()).unwrap();
		t.try_with(ip("192.0.2.2"), || 2, |_| false, |_| ()).unwrap();
		assert_eq!(t.len(), 1);
		let mut seen = 0;
		t.with_existing(ip("192.0.2.2"), |v| seen = *v);
		assert_eq!(seen, 2, "the newest stays");
	}

	#[test]
	fn sources_with_connections_are_never_forgotten() {
		// security review L8: a flood of new sources must not start a busy source's count over
		let l = limiter(serde_json::json!({"per_source": {"max_connections": 1, "max_sources": 1}}));
		let held = l.admit(ip("192.0.2.1")).unwrap();
		assert!(matches!(l.admit(ip("192.0.2.2")), Err(Reason::SourceConnections)), "the table is full of busy sources");
		assert!(matches!(l.admit(ip("192.0.2.1")), Err(Reason::SourceConnections)), "still counted");
		drop(held);
		assert!(l.admit(ip("192.0.2.2")).is_ok(), "an idle source is forgotten");
	}

	#[test]
	fn limits_are_switched_by_set() {
		let limits = Limits::default();
		assert!(limits.get().is_none());
		limits.set(Some(&parse(serde_json::json!({"max_connections": 1}))));
		let p = limits.get().unwrap().admit(ip("192.0.2.1")).unwrap();
		limits.set(Some(&parse(serde_json::json!({"max_connections": 2}))));
		assert_eq!(limits.get().unwrap().active(), 1);
		drop(p);
		limits.set(None);
		assert!(limits.get().is_none());
	}
}
