//! `cache` (#340): answers of GET kept in memory for `ttl`, in this process only (nodes do not
//! share them). Made for many clients polling the same JSON every few seconds: the backend gets
//! one request per key and `ttl`, however many clients ask.
//!
//! - The key: the route (each route has its own answers, even with the same middleware), the
//!   scheme and port the request came to, host, path and query, the `vary` headers, and on
//!   rules with `tls.client_auth` the client certificate as rproxy saw it.
//! - A request that finds nothing fresh leads: it goes to the backend, and the others asking
//!   for the same key meanwhile wait for its answer (coalescing) instead of going too, at most
//!   `WAIT_LIMIT`. When `STRIKES` leads in a row get answers that may not be kept for a reason
//!   of their own (Cache-Control, Set-Cookie, Vary: *, size, a stream), the requests of the
//!   next `ttl` with the same values of the answer's `Vary` go to the backend without waiting
//!   (`Store.passes`); a status outside `status` or a slow or broken body (which a request may
//!   cause) starts the count again, and a fresh answer is always given first. An error
//!   without an old answer is handed to those waiting (`Done::Error`, not kept).
//! - `stale_on_error`: when the backend fails (5xx, rproxy's 502 / 504), the last answer is
//!   given for that long after it went out of date. After a failure (of the leading request,
//!   or of one that went alone) the old answer is given at once for `ttl` (no request goes),
//!   and while one request tries again (`Slot.failed`).
//! - Never kept: other methods than GET (HEAD is answered from GET's answers), requests with
//!   `Authorization` / `Cookie` / a client certificate (unless `share_credentials`), `Range`,
//!   `Upgrade` or a body (also HTTP/2 and HTTP/3 DATA frames without a length: `settle`);
//!   answers with `Set-Cookie`, `Cache-Control: no-store / private / no-cache`, `Vary: *`,
//!   `Content-Range`, `text/event-stream`, a status outside `status`, a body over `max_body`
//!   or still coming after `COLLECT_LIMIT`, trailers, or a body that broke off. The route's
//!   checks keep it out of the way of authentication (`HttpSpec::check_cache_route`).
//! - The answer's `Vary` (and `Accept-Encoding` for an encoded body) is kept with it: a
//!   request with other values of those headers does not get it.
//! - Memory: each cache has its own `max_memory`, and all of them together at most
//!   `RPROXY_CACHE_MAX_MEMORY` (#349, `Budget`, live in `global.cache_max_memory`). An answer
//!   that does not fit drops the oldest answers of its own cache (after the answers of the
//!   other caches past `stale_on_error`), and is not kept when that is not enough.

use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Frame;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio::time::Instant;

use crate::error::ApiError;
use crate::l7::parse_duration;
use crate::l7::server::{Body, BoxError};

/// Kinds that decide who gets in: an answer from the cache would skip them, so a route may
/// not have them after its cache.
pub const GATES: &[&str] = &["ip_allow", "geoip", "crowdsec", "basic_auth", "forward_auth", "oidc"];
/// Kinds that sign users in: before a cache only with `share_after_auth`.
pub const SIGN_IN: &[&str] = &["basic_auth", "forward_auth", "oidc"];
/// Statuses `status` may name (cacheable by default in RFC 9110 §15.1, less 206 / 405 / 414 / 501).
pub const STATUSES: &[u16] = &[200, 203, 204, 300, 301, 308, 404, 410];
/// Names `header` may not take: hop-by-hop, framing, and what the cache itself sets or reads.
const RESERVED_HEADERS: &[&str] = &[
	"connection",
	"keep-alive",
	"proxy-connection",
	"te",
	"trailer",
	"transfer-encoding",
	"upgrade",
	"content-length",
	"content-encoding",
	"content-range",
	"content-type",
	"host",
	"age",
	"vary",
	"set-cookie",
	"etag",
	"cache-control",
	"date",
];
const MIN_TTL: Duration = Duration::from_millis(100);
const MAX_TTL: Duration = Duration::from_secs(24 * 3600);
pub const DEFAULT_MAX_BODY: u64 = 1 << 20;
const MAX_BODY: u64 = 64 << 20;
pub const DEFAULT_MAX_ENTRIES: u64 = 1024;
const MAX_ENTRIES: u64 = 1_000_000;
pub const DEFAULT_MAX_MEMORY: u64 = 64 << 20;
const MAX_MEMORY: u64 = 1 << 34;
/// Times a waiting request looks again after the request it waited for went away.
const RETRIES: usize = 3;
/// How long a request waits for the one that went to the backend; then it goes itself.
pub const WAIT_LIMIT: Duration = Duration::from_secs(10);
/// How long the body of an answer is read to keep it; one still coming is sent on as it comes
/// (long polls, slow streams) and not kept.
pub const COLLECT_LIMIT: Duration = Duration::from_secs(5);
/// How long a GET's body is looked for when the request does not say it has none (HTTP/2 and
/// HTTP/3 can send DATA frames without Content-Length).
const BODY_PEEK: Duration = Duration::from_secs(1);
const DEFAULT_HEADER: &str = "x-cache";
/// Leads in a row with answers that may not be kept before requests stop waiting for leads.
const STRIKES: u8 = 3;
/// `RPROXY_CACHE_MAX_MEMORY` by default: bytes of all caches of the process together.
pub const DEFAULT_PROCESS_MAX_MEMORY: u64 = 512 << 20;

/// The memory of all caches together (#349): what they keep (answers and passes) is counted
/// in `used`, and an answer is kept only when it fits under `limit` (0: no limit).
pub struct Budget {
	limit: AtomicU64,
	used: AtomicU64,
	/// Every cache's store, to drop the answers past `stale_on_error` that caches not asked
	/// lately still hold when the budget is full.
	stores: Mutex<Vec<Weak<Mutex<Store>>>>,
}

/// The process's budget.
static BUDGET: Budget = Budget::new(DEFAULT_PROCESS_MAX_MEMORY);

/// Sets the bytes all caches may keep together (0: no limit). Lowered, the answers kept stay
/// until they go out of date or make room; new ones are kept when they fit.
pub fn set_max_memory(max: u64) {
	BUDGET.limit.store(max, Ordering::Relaxed);
}

/// The limit and the bytes all caches keep together (`/metrics`).
pub fn memory() -> (u64, u64) {
	(BUDGET.limit.load(Ordering::Relaxed), BUDGET.used.load(Ordering::Relaxed))
}

impl Budget {
	const fn new(limit: u64) -> Budget {
		Budget { limit: AtomicU64::new(limit), used: AtomicU64::new(0), stores: Mutex::new(Vec::new()) }
	}

	/// Counts `n` bytes in when they fit.
	fn reserve(&self, n: u64) -> bool {
		let limit = self.limit.load(Ordering::Relaxed);
		if limit == 0 {
			self.used.fetch_add(n, Ordering::Relaxed);
			return true;
		}
		let mut u = self.used.load(Ordering::Relaxed);
		loop {
			let Some(t) = u.checked_add(n).filter(|t| *t <= limit) else { return false };
			match self.used.compare_exchange_weak(u, t, Ordering::Relaxed, Ordering::Relaxed) {
				Ok(_) => return true,
				Err(now) => u = now,
			}
		}
	}

	fn release(&self, n: u64) {
		self.used.fetch_sub(n, Ordering::Relaxed);
	}

	/// Bytes left under the limit (u64::MAX without one).
	fn free(&self) -> u64 {
		match self.limit.load(Ordering::Relaxed) {
			0 => u64::MAX,
			limit => limit.saturating_sub(self.used.load(Ordering::Relaxed)),
		}
	}

	fn register(&self, store: &Arc<Mutex<Store>>) {
		let mut stores = self.stores.lock().unwrap_or_else(|e| e.into_inner());
		stores.retain(|w| w.strong_count() > 0);
		stores.push(Arc::downgrade(store));
	}

	/// Drops what the other caches keep past its time. Called with `own` locked: the others
	/// are only tried (never waited for), so two caches doing this at once do not deadlock.
	fn purge_others(&self, own: *const Store, now: Instant) {
		// under the list's lock, nothing collected: a store dropped meanwhile only gives its
		// bytes back (`Store::drop` takes no lock)
		let mut stores = self.stores.lock().unwrap_or_else(|e| e.into_inner());
		stores.retain(|w| w.strong_count() > 0);
		for store in stores.iter().filter_map(Weak::upgrade) {
			let mut guard = match store.try_lock() {
				Ok(g) => g,
				Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
				Err(std::sync::TryLockError::WouldBlock) => continue,
			};
			if !std::ptr::eq(&*guard, own) {
				guard.purge(now);
			}
		}
	}
}

fn is_false(b: &bool) -> bool {
	!*b
}

/// `http.middlewares.<name>.cache`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSpec {
	/// How long an answer is given from memory (100ms-24h).
	pub ttl: String,
	/// How long after `ttl` the answer may still be given when the backend fails (default 0s).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub stale_on_error: Option<String>,
	/// Bytes; larger bodies are not kept (default 1 MiB, up to 64 MiB).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_body: Option<u64>,
	/// Answers kept at most; the oldest go first (default 1024).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_entries: Option<u64>,
	/// Bytes of all answers kept (bodies and headers; default 64 MiB).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_memory: Option<u64>,
	/// Request headers that are part of the key besides host, path and query.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub vary: Vec<String>,
	/// Statuses that are kept (default [200]; of `STATUSES`).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub status: Vec<u16>,
	/// Requests with `Authorization` / `Cookie` / a client certificate are answered from the
	/// cache too (the backend's answer does not depend on them; a client certificate stays
	/// part of the key).
	#[serde(default, skip_serializing_if = "is_false")]
	pub share_credentials: bool,
	/// The route may sign users in before the cache (basic_auth, forward_auth, oidc): every
	/// user who gets in may see the same answer.
	#[serde(default, skip_serializing_if = "is_false")]
	pub share_after_auth: bool,
	/// The response header with HIT / MISS / STALE / BYPASS (default X-Cache; "" for none).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub header: Option<String>,
}

impl CacheSpec {
	pub fn validate(&self, what: &str) -> Result<(), ApiError> {
		Settings::of(self, what).map(|_| ())
	}
}

/// `CacheSpec` checked.
#[derive(Debug)]
struct Settings {
	ttl: Duration,
	stale: Duration,
	max_body: u64,
	max_entries: usize,
	max_memory: u64,
	vary: Vec<HeaderName>,
	status: Vec<u16>,
	share_credentials: bool,
	header: Option<HeaderName>,
}

impl Settings {
	fn of(spec: &CacheSpec, what: &str) -> Result<Settings, ApiError> {
		let bad = |m: String| ApiError::invalid(format!("{what}: {m}"));
		let ttl = parse_duration(&spec.ttl).map_err(|e| bad(format!("ttl: {e}")))?;
		if !(MIN_TTL..=MAX_TTL).contains(&ttl) {
			return Err(bad(format!("ttl {:?} must be from 100ms to 24h", spec.ttl)));
		}
		let stale = match &spec.stale_on_error {
			Some(d) => parse_duration(d).map_err(|e| bad(format!("stale_on_error: {e}")))?,
			None => Duration::ZERO,
		};
		if stale > MAX_TTL {
			return Err(bad("stale_on_error must be at most 24h".into()));
		}
		let max_body = spec.max_body.unwrap_or(DEFAULT_MAX_BODY);
		if !(1..=MAX_BODY).contains(&max_body) {
			return Err(bad(format!("max_body {max_body} must be from 1 to {MAX_BODY} (64 MiB)")));
		}
		let max_entries = spec.max_entries.unwrap_or(DEFAULT_MAX_ENTRIES);
		if !(1..=MAX_ENTRIES).contains(&max_entries) {
			return Err(bad(format!("max_entries {max_entries} must be from 1 to {MAX_ENTRIES}")));
		}
		let max_memory = spec.max_memory.unwrap_or(DEFAULT_MAX_MEMORY);
		if !(max_body..=MAX_MEMORY).contains(&max_memory) {
			return Err(bad(format!("max_memory {max_memory} must be from max_body ({max_body}) to {MAX_MEMORY} (16 GiB)")));
		}
		let mut vary = vec![];
		for v in &spec.vary {
			let name = HeaderName::from_bytes(v.as_bytes()).map_err(|_| bad(format!("vary: {v:?} is not a header name")))?;
			if !vary.contains(&name) {
				vary.push(name);
			}
		}
		let status = if spec.status.is_empty() { vec![200] } else { spec.status.clone() };
		if let Some(s) = status.iter().find(|s| !STATUSES.contains(s)) {
			return Err(bad(format!(
				"status {s} cannot be kept; only {}",
				STATUSES.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
			)));
		}
		let header = match spec.header.as_deref() {
			None => Some(HeaderName::from_static(DEFAULT_HEADER)),
			Some("") => None,
			Some(h) => {
				let name = HeaderName::from_bytes(h.as_bytes()).map_err(|_| bad(format!("header: {h:?} is not a header name")))?;
				if RESERVED_HEADERS.contains(&name.as_str()) {
					return Err(bad(format!("header: {h:?} is a header of the HTTP framing or of caching; pick another name")));
				}
				Some(name)
			}
		};
		Ok(Settings {
			ttl,
			stale,
			max_body,
			max_entries: usize::try_from(max_entries).unwrap_or(usize::MAX),
			max_memory,
			vary,
			status,
			share_credentials: spec.share_credentials,
			header,
		})
	}
}

/// What became of a request at the cache: `stats.http` and the access log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
	/// From memory.
	Hit,
	/// From the backend (kept or not), or the error the request waited for.
	Miss,
	/// From memory although out of date: the backend failed (`stale_on_error`).
	Stale,
	/// Not for the cache (method, credentials, a body, …): from the backend.
	Bypass,
}

impl Outcome {
	pub const ALL: [Outcome; 4] = [Outcome::Hit, Outcome::Miss, Outcome::Stale, Outcome::Bypass];

	pub fn as_str(self) -> &'static str {
		match self {
			Outcome::Hit => "HIT",
			Outcome::Miss => "MISS",
			Outcome::Stale => "STALE",
			Outcome::Bypass => "BYPASS",
		}
	}

	pub fn index(self) -> usize {
		self as usize
	}
}

/// What the server knows of a request besides its parts.
pub struct Ask<'a> {
	/// Host without the port, lower case.
	pub host: &'a str,
	/// The route's name: each route keeps its own answers.
	pub route: &'a str,
	pub https: bool,
	/// The port the request came to.
	pub port: u16,
	/// The client certificate on rules with `tls.client_auth`: whether one was given, and
	/// what rproxy passes on about it (X-Client-Verify and X-Forwarded-Client-Cert).
	pub cert: Option<(bool, &'a str)>,
	/// The request has no body (`settle`).
	pub body_empty: bool,
}

/// Whether the request's body is empty. One that may still send DATA frames (HTTP/2 and
/// HTTP/3 without Content-Length) is looked at for `BODY_PEEK`; what was read is put back.
pub async fn settle(body: &mut Body) -> bool {
	use hyper::body::Body as _;
	if body.is_end_stream() {
		return true;
	}
	let until = Instant::now() + BODY_PEEK;
	let first = loop {
		match tokio::time::timeout_at(until, body.frame()).await {
			Ok(None) => {
				*body = empty();
				return true;
			}
			// HTTP/2: HEADERS without END_STREAM, then an empty DATA frame that ends the stream
			Ok(Some(Ok(f))) if f.data_ref().is_some_and(Bytes::is_empty) => continue,
			Ok(Some(f)) => break f,
			Err(_) => return false,
		}
	};
	let rest = std::mem::replace(body, empty());
	let failed = first.is_err();
	*body = Resumed { read: None, next: Some(first), rest: (!failed).then_some(rest) }.boxed();
	false
}

/// A kept answer.
pub struct Entry {
	status: StatusCode,
	headers: HeaderMap,
	body: Bytes,
	stored: Instant,
	fresh_until: Instant,
	stale_until: Instant,
	/// The answer's `Vary` headers with the values of the request it answered.
	varies: Vec<(HeaderName, Option<Vec<u8>>)>,
	/// `Age` the backend gave.
	age: u64,
	/// Position in `Store.order`.
	seq: u64,
	size: u64,
}

impl Entry {
	fn fits(&self, request: &HeaderMap) -> bool {
		self.varies.iter().all(|(name, v)| joined(request, name) == *v)
	}
}

/// What a waiting request learns from the one it waits for.
#[derive(Clone)]
enum Done {
	Pending,
	Fresh(Arc<Entry>),
	Stale(Arc<Entry>),
	/// The backend failed and there is no old answer: this is its error answer (not kept).
	Error(Arc<Entry>),
	/// The answer is not kept: go to the backend.
	Uncacheable,
	/// The request went away (its client did): look again.
	Abandoned,
}

type Varies = Vec<(HeaderName, Option<Vec<u8>>)>;

/// What the end of a flight leaves for the key.
enum Mark {
	Nothing,
	/// The answer may not be kept for a reason of its own (Cache-Control, Set-Cookie, Vary: *,
	/// size, a stream), with its `Vary` and the request's values: one strike (`Store::strike`).
	Strike(Varies),
	/// Not kept for a reason a request may cause (a status outside `status`, a slow or broken
	/// body): the strikes start again.
	Reset,
	/// The backend failed: the old answer is given at once for `ttl`.
	Failed,
}

/// Strikes against a key: after `STRIKES` in a row, requests with the same `Vary` values do
/// not wait for leads until `until`.
struct Pass {
	strikes: u8,
	/// The end of the streak (each strike gives `ttl` more), and of the pass.
	until: Instant,
	varies: Varies,
	/// Counted in `Store.memory`.
	size: u64,
}

impl Pass {
	fn on(&self, now: Instant, request: &HeaderMap) -> bool {
		self.strikes >= STRIKES && now < self.until && self.varies.iter().all(|(name, v)| joined(request, name) == *v)
	}
}

/// Whether an answer may be kept, by its head.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
	Keep,
	Strike,
	Reset,
}

struct Flight {
	tx: watch::Sender<Done>,
}

#[derive(Default)]
struct Slot {
	entry: Option<Arc<Entry>>,
	flight: Option<Arc<Flight>>,
	/// When the backend last failed for this key (cleared by a new answer).
	failed: Option<Instant>,
}

struct Store {
	budget: &'static Budget,
	map: HashMap<Vec<u8>, Slot>,
	/// Keys of the entries, oldest first (all have the same `ttl`, so this is also the order
	/// in which they go out of date).
	order: BTreeMap<u64, Vec<u8>>,
	/// Bytes of the entries and passes, also counted in `budget`.
	memory: u64,
	/// Of `memory`, the passes' (only the entries can be dropped to make room).
	pass_memory: u64,
	/// Keys whose answers were not kept for a reason of their own (at most `max_entries`).
	passes: HashMap<Vec<u8>, Pass>,
}

impl Drop for Store {
	fn drop(&mut self) {
		self.budget.release(self.memory);
	}
}

impl Store {
	fn new(budget: &'static Budget) -> Store {
		Store { budget, map: HashMap::new(), order: BTreeMap::new(), memory: 0, pass_memory: 0, passes: HashMap::new() }
	}

	fn free(&mut self, n: u64) {
		self.memory -= n;
		self.budget.release(n);
	}

	/// Counts `n` more bytes in (already counted in the budget).
	fn hold(&mut self, n: u64) {
		self.memory += n;
	}
	/// Takes the entry of `key` out of the bookkeeping (the slot stays while a request leads).
	fn take(&mut self, key: &[u8]) {
		let Some(slot) = self.map.get_mut(key) else { return };
		let entry = slot.entry.take();
		if slot.flight.is_none() {
			self.map.remove(key);
		}
		if let Some(e) = entry {
			self.order.remove(&e.seq);
			self.free(e.size);
		}
	}

	fn take_oldest(&mut self) {
		let Some((&seq, key)) = self.order.first_key_value() else { return };
		let key = key.clone();
		self.take(&key);
		self.order.remove(&seq);
	}

	/// Drops the oldest entry other than `key`'s; false when there is none.
	fn take_oldest_but(&mut self, key: &[u8]) -> bool {
		let Some(other) = self.order.values().find(|k| k.as_slice() != key).cloned() else { return false };
		self.take(&other);
		true
	}

	/// Bytes of the entries but one of `old` bytes (what dropping the others can free).
	fn droppable(&self, old: u64) -> u64 {
		self.memory - self.pass_memory - old
	}

	/// Drops the entries past `stale_on_error` (they are at the front), and passes past theirs.
	fn purge(&mut self, now: Instant) {
		self.sweep(now);
		while let Some(k) = self.order.first_key_value().map(|(_, k)| k.clone()) {
			let dead = self.map.get(&k).and_then(|s| s.entry.as_ref()).is_none_or(|e| e.stale_until <= now);
			if !dead {
				break;
			}
			self.take_oldest();
		}
	}

	fn sweep(&mut self, now: Instant) {
		let mut freed = 0;
		self.passes.retain(|_, p| {
			let keep = p.until > now;
			if !keep {
				freed += p.size;
			}
			keep
		});
		self.pass_memory -= freed;
		self.free(freed);
	}

	fn unpass(&mut self, key: &[u8]) {
		if let Some(p) = self.passes.remove(key) {
			self.pass_memory -= p.size;
			self.free(p.size);
		}
	}

	/// One more strike in a row (within `ttl` of the last one).
	fn strike(&mut self, key: &[u8], varies: Varies, now: Instant, ttl: Duration, max: usize) {
		let strikes = match self.passes.get(key) {
			Some(p) if now < p.until => p.strikes.saturating_add(1),
			_ => 1,
		};
		self.unpass(key);
		if self.passes.len() >= max {
			self.sweep(now);
			if self.passes.len() >= max {
				let freed: u64 = self.passes.values().map(|p| p.size).sum();
				self.passes.clear();
				self.pass_memory -= freed;
				self.free(freed);
			}
		}
		let size =
			(key.len() + varies.iter().map(|(n, v)| n.as_str().len() + v.as_ref().map_or(0, Vec::len) + 32).sum::<usize>() + 96) as u64;
		// counted in the process's budget too; a pass that does not fit is not kept (requests
		// then wait for leads as before)
		if !self.budget.reserve(size) {
			self.budget.purge_others(self, now);
			if !self.budget.reserve(size) {
				return;
			}
		}
		self.hold(size);
		self.pass_memory += size;
		self.passes.insert(key.to_vec(), Pass { strikes, until: now + ttl, varies, size });
	}
}

/// A compiled `cache`. Its memory belongs to this version of the rule's `http`.
pub struct Cache {
	pub name: String,
	settings: Settings,
	store: Arc<Mutex<Store>>,
	/// The next `Entry.seq`.
	next: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for Cache {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Cache").field("name", &self.name).field("settings", &self.settings).finish_non_exhaustive()
	}
}

/// The request that went to the backend for a key; the others wait for it.
pub struct Lead {
	cache: Arc<Cache>,
	key: Vec<u8>,
	flight: Arc<Flight>,
	done: bool,
}

impl Lead {
	/// Ends the flight: the slot no longer has it, and those waiting learn `done`.
	fn finish(&mut self, done: Done, entry: Option<Arc<Entry>>, mark: Mark) {
		if self.done {
			return;
		}
		self.done = true;
		{
			let cache = &self.cache;
			let mut store = cache.store.lock().unwrap_or_else(|e| e.into_inner());
			let now = Instant::now();
			if let Some(e) = entry {
				cache.insert(&mut store, &self.key, e);
				store.unpass(&self.key);
			}
			let failed = matches!(mark, Mark::Failed);
			match mark {
				Mark::Strike(varies) => store.strike(&self.key, varies, now, cache.settings.ttl, cache.settings.max_entries),
				Mark::Reset => store.unpass(&self.key),
				Mark::Nothing | Mark::Failed => {}
			}
			if let Some(slot) = store.map.get_mut(&self.key) {
				if slot.flight.as_ref().is_some_and(|f| Arc::ptr_eq(f, &self.flight)) {
					slot.flight = None;
				}
				if failed {
					slot.failed = Some(now);
				} else if slot.entry.as_ref().is_some_and(|e| e.fresh_until > now) {
					slot.failed = None;
				}
				if slot.flight.is_none() && slot.entry.is_none() {
					store.map.remove(&self.key);
				}
			}
		}
		self.flight.tx.send_replace(done);
	}
}

impl Drop for Lead {
	fn drop(&mut self) {
		self.finish(Done::Abandoned, None, Mark::Nothing);
	}
}

/// A request that went past the cache to the backend; its response comes back through
/// `Cache::response`.
pub struct Pending {
	/// None: not for the cache (BYPASS).
	key: Option<Vec<u8>>,
	lead: Option<Lead>,
	/// The request's headers as they came (vary, If-None-Match).
	headers: HeaderMap,
	head: bool,
}

impl Pending {
	fn bypass() -> Box<Pending> {
		Box::new(Pending { key: None, lead: None, headers: HeaderMap::new(), head: false })
	}

	fn alone(key: Vec<u8>, parts: &Parts, head: bool) -> Box<Pending> {
		Box::new(Pending { key: Some(key), lead: None, headers: parts.headers.clone(), head })
	}
}

impl Cache {
	pub fn new(name: &str, spec: &CacheSpec, what: &str) -> Result<Cache, ApiError> {
		Cache::within(name, spec, what, &BUDGET)
	}

	fn within(name: &str, spec: &CacheSpec, what: &str, budget: &'static Budget) -> Result<Cache, ApiError> {
		let settings = Settings::of(spec, what)?;
		let store = Arc::new(Mutex::new(Store::new(budget)));
		budget.register(&store);
		Ok(Cache { name: name.to_string(), settings, store, next: Default::default() })
	}

	/// Answers kept (those past `stale_on_error` are dropped first) and the bytes they take (`/metrics`).
	pub fn usage(&self) -> (usize, u64) {
		let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
		store.purge(Instant::now());
		(store.order.len(), store.memory)
	}

	/// Whether the request may be answered from the cache by its head (`settle` looks at the
	/// body after this, so a request that is BYPASS anyway does not wait for it). `Expect:
	/// 100-continue` is BYPASS, so that the body is not asked for.
	pub fn admits(&self, parts: &Parts, ask: &Ask) -> bool {
		let h = &parts.headers;
		let credentials = h.contains_key(header::AUTHORIZATION)
			|| h.contains_key(header::COOKIE)
			|| h.contains_key(header::PROXY_AUTHORIZATION)
			|| ask.cert.is_some_and(|(given, _)| given);
		(parts.method == Method::GET || parts.method == Method::HEAD)
			&& !h.contains_key(header::EXPECT)
			&& !h.contains_key(header::RANGE)
			&& !h.contains_key(header::UPGRADE)
			&& !h.contains_key(header::TRANSFER_ENCODING)
			&& h.get(header::CONTENT_LENGTH).is_none_or(|v| v.as_bytes() == b"0")
			&& (self.settings.share_credentials || !credentials)
	}

	fn eligible(&self, parts: &Parts, ask: &Ask) -> bool {
		ask.body_empty && self.admits(parts, ask)
	}

	/// The route, scheme and port, host, path and query, the `vary` headers and the client
	/// certificate (rules with `tls.client_auth`).
	fn key(&self, parts: &Parts, ask: &Ask) -> Vec<u8> {
		let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
		let mut key = Vec::with_capacity(ask.route.len() + ask.host.len() + pq.len() + 16);
		key.extend_from_slice(ask.route.as_bytes());
		key.push(0);
		key.extend_from_slice(if ask.https { b"https:" } else { b"http:" });
		key.extend_from_slice(ask.port.to_string().as_bytes());
		key.push(0);
		key.extend(ask.host.bytes().map(|b| b.to_ascii_lowercase()));
		key.push(0);
		key.extend_from_slice(pq.as_bytes());
		for name in &self.settings.vary {
			key.push(b'\n');
			if let Some(v) = joined(&parts.headers, name) {
				key.push(b'=');
				key.extend_from_slice(&v);
			}
		}
		if let Some((_, cert)) = ask.cert {
			key.extend_from_slice(b"\ncert=");
			key.extend_from_slice(cert.as_bytes());
		}
		key
	}

	/// The request side: an answer from memory, or what the response side needs. A request
	/// that finds another one already asking the backend for its key waits for that answer.
	pub async fn request(self: &Arc<Self>, parts: &mut Parts, ask: &Ask<'_>) -> Result<(Response<Body>, Outcome), Box<Pending>> {
		if !self.eligible(parts, ask) {
			return Err(Pending::bypass());
		}
		let key = self.key(parts, ask);
		let head = parts.method == Method::HEAD;
		let mut tries = 0;
		loop {
			let mut rx = {
				let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
				let now = Instant::now();
				let slot = store.map.get(&key);
				let entry = slot.and_then(|s| s.entry.as_ref()).filter(|e| e.fits(&parts.headers));
				if let Some(e) = entry.filter(|e| now < e.fresh_until) {
					let e = e.clone();
					drop(store);
					return Ok((self.answer(&e, &parts.headers, head, Outcome::Hit), Outcome::Hit));
				}
				// the backend failed lately: the old answer at once, for `ttl` and while one tries again
				if let (Some(e), Some(failed)) = (entry.filter(|e| now < e.stale_until), slot.and_then(|s| s.failed)) {
					if now < failed + self.settings.ttl || slot.is_some_and(|s| s.flight.is_some()) {
						let e = e.clone();
						drop(store);
						return Ok((self.answer(&e, &parts.headers, head, Outcome::Stale), Outcome::Stale));
					}
				}
				// answers for this key are not kept for a reason of their own: do not wait in line
				if store.passes.get(&key).is_some_and(|p| p.on(now, &parts.headers)) {
					return Err(Pending::alone(key, parts, head));
				}
				// HEAD does not lead: its answer has no body to keep
				if head || tries >= RETRIES {
					return Err(Pending::alone(key, parts, head));
				}
				match slot.and_then(|s| s.flight.as_ref()) {
					Some(f) => f.tx.subscribe(),
					None => {
						let flight = Arc::new(Flight { tx: watch::channel(Done::Pending).0 });
						store.map.entry(key.clone()).or_default().flight = Some(flight.clone());
						drop(store);
						let headers = parts.headers.clone();
						// the backend's full answer is what is kept; the client's condition is
						// answered from it (`answer`)
						parts.headers.remove(header::IF_NONE_MATCH);
						parts.headers.remove(header::IF_MODIFIED_SINCE);
						let lead = Lead { cache: self.clone(), key: key.clone(), flight, done: false };
						return Err(Box::new(Pending { key: Some(key), lead: Some(lead), headers, head }));
					}
				}
			};
			let done = match tokio::time::timeout(WAIT_LIMIT, rx.wait_for(|d| !matches!(d, Done::Pending))).await {
				Ok(Ok(d)) => d.clone(),
				Ok(Err(_)) => Done::Abandoned,
				// the request ahead takes too long: go too (without leading)
				Err(_) => return Err(Pending::alone(key, parts, head)),
			};
			match done {
				Done::Fresh(e) if e.fits(&parts.headers) => return Ok((self.answer(&e, &parts.headers, head, Outcome::Hit), Outcome::Hit)),
				Done::Stale(e) if e.fits(&parts.headers) => {
					return Ok((self.answer(&e, &parts.headers, head, Outcome::Stale), Outcome::Stale));
				}
				Done::Error(e) if e.fits(&parts.headers) => {
					return Ok((self.answer(&e, &parts.headers, head, Outcome::Miss), Outcome::Miss));
				}
				Done::Abandoned => tries += 1,
				_ => return Err(Pending::alone(key, parts, head)),
			}
		}
	}

	/// The response side: keeps the backend's answer (when this request led and it may be
	/// kept), or gives the out-of-date one when the backend failed.
	pub async fn response(&self, mut pending: Box<Pending>, resp: Response<Body>) -> (Response<Body>, Outcome) {
		let Some(key) = pending.key.take() else { return (self.mark(resp, Outcome::Bypass), Outcome::Bypass) };
		let p = &mut *pending;
		if resp.status().is_server_error() {
			if let Some(e) = self.stale(&key, &p.headers) {
				match p.lead.as_mut() {
					Some(lead) => lead.finish(Done::Stale(e.clone()), None, Mark::Failed),
					None => self.failed(&key),
				}
				return (self.answer(&e, &p.headers, p.head, Outcome::Stale), Outcome::Stale);
			}
			let Some(lead) = p.lead.as_mut() else { return (self.mark(resp, Outcome::Miss), Outcome::Miss) };
			// no old answer: those waiting get this error rather than all asking the failing backend
			if !shareable(resp.headers()) {
				lead.finish(Done::Uncacheable, None, Mark::Nothing);
				return (self.mark(resp, Outcome::Miss), Outcome::Miss);
			}
			let (parts, body) = resp.into_parts();
			return match collect(body, self.settings.max_body).await {
				Ok(bytes) => {
					let e = Arc::new(self.entry(&key, parts.status, parts.headers, bytes, &p.headers));
					lead.finish(Done::Error(e.clone()), None, Mark::Nothing);
					(self.answer(&e, &p.headers, p.head, Outcome::Miss), Outcome::Miss)
				}
				Err((body, _)) => {
					lead.finish(Done::Uncacheable, None, Mark::Nothing);
					(self.mark(Response::from_parts(parts, body), Outcome::Miss), Outcome::Miss)
				}
			};
		}
		let Some(lead) = p.lead.as_mut() else { return (self.mark(resp, Outcome::Miss), Outcome::Miss) };
		let strike = |headers: &HeaderMap| Mark::Strike(varies_of(headers, &p.headers));
		match self.verdict(&resp) {
			Verdict::Keep => {}
			Verdict::Strike => {
				let mark = strike(resp.headers());
				lead.finish(Done::Uncacheable, None, mark);
				return (self.mark(resp, Outcome::Miss), Outcome::Miss);
			}
			Verdict::Reset => {
				lead.finish(Done::Uncacheable, None, Mark::Reset);
				return (self.mark(resp, Outcome::Miss), Outcome::Miss);
			}
		}
		let (parts, body) = resp.into_parts();
		match collect(body, self.settings.max_body).await {
			Ok(bytes) => {
				let e = Arc::new(self.entry(&key, parts.status, parts.headers, bytes, &p.headers));
				if e.size <= self.settings.max_memory {
					lead.finish(Done::Fresh(e.clone()), Some(e.clone()), Mark::Nothing);
				} else {
					let mark = strike(&e.headers);
					lead.finish(Done::Uncacheable, None, mark);
				}
				(self.answer(&e, &p.headers, p.head, Outcome::Miss), Outcome::Miss)
			}
			Err((body, too_big)) => {
				let mark = if too_big { strike(&parts.headers) } else { Mark::Reset };
				lead.finish(Done::Uncacheable, None, mark);
				(self.mark(Response::from_parts(parts, body), Outcome::Miss), Outcome::Miss)
			}
		}
	}

	fn stale(&self, key: &[u8], request: &HeaderMap) -> Option<Arc<Entry>> {
		if self.settings.stale.is_zero() {
			return None;
		}
		let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
		let e = store.map.get(key)?.entry.as_ref()?;
		(Instant::now() < e.stale_until && e.fits(request)).then(|| e.clone())
	}

	/// A request that did not lead saw the backend fail.
	fn failed(&self, key: &[u8]) {
		let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(slot) = store.map.get_mut(key) {
			slot.failed = Some(Instant::now());
		}
	}

	/// Whether an answer may be kept. A status outside `status` or a `Content-Range` may come
	/// from what one request sent (an unkeyed header the backend refuses): `Reset`, never a
	/// strike, so that one client cannot make the others stop waiting for leads.
	fn verdict(&self, resp: &Response<Body>) -> Verdict {
		let h = resp.headers();
		let streaming = h
			.get(header::CONTENT_TYPE)
			.and_then(|v| v.to_str().ok())
			.is_some_and(|t| t.trim_start().get(..17).is_some_and(|t| t.eq_ignore_ascii_case("text/event-stream")));
		let too_big =
			h.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse::<u64>().ok()).is_some_and(|n| n > self.settings.max_body);
		if !self.settings.status.contains(&resp.status().as_u16()) || h.contains_key(header::CONTENT_RANGE) {
			Verdict::Reset
		} else if !shareable(h) || streaming || too_big {
			Verdict::Strike
		} else {
			Verdict::Keep
		}
	}

	fn entry(&self, key: &[u8], status: StatusCode, mut headers: HeaderMap, body: Bytes, request: &HeaderMap) -> Entry {
		headers.remove(header::TRANSFER_ENCODING);
		if status == StatusCode::NO_CONTENT {
			headers.remove(header::CONTENT_LENGTH);
		} else {
			headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
		}
		let age = headers.remove(header::AGE).and_then(|v| v.to_str().ok()?.trim().parse().ok()).unwrap_or(0);
		let varies = varies_of(&headers, request);
		let size = body.len() as u64
			+ headers.iter().map(|(n, v)| (n.as_str().len() + v.len() + 32) as u64).sum::<u64>()
			+ varies.iter().map(|(n, v)| (n.as_str().len() + v.as_ref().map_or(0, Vec::len) + 32) as u64).sum::<u64>()
			+ 2 * key.len() as u64
			+ 256;
		let now = Instant::now();
		let fresh_until = now + self.settings.ttl;
		let seq = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
		Entry { status, headers, body, stored: now, fresh_until, stale_until: fresh_until + self.settings.stale, varies, age, seq, size }
	}

	/// Puts an entry in place of the key's old one, making room by dropping the oldest. Not
	/// kept when the process's budget has no room for it even without this cache's other
	/// answers: then nothing is dropped, and the key's old answer stays (`stale_on_error`).
	fn insert(&self, store: &mut Store, key: &[u8], entry: Arc<Entry>) -> bool {
		let now = Instant::now();
		store.purge(now);
		let old = store.map.get(key).and_then(|s| s.entry.as_ref()).map_or(0, |e| e.size);
		// the budget first: the old answer is replaced, so only what the new one adds
		let grow = entry.size.saturating_sub(old);
		if grow > 0 && !store.budget.reserve(grow) {
			store.budget.purge_others(store, now);
			loop {
				if store.budget.reserve(grow) {
					break;
				}
				// dropping this cache's other answers would not make room (looked at again
				// each time: other caches take from the budget too): keep them
				if store.droppable(old).saturating_add(store.budget.free()) < grow || !store.take_oldest_but(key) {
					return false;
				}
			}
		}
		// this cache's own limits, the key's old answer aside
		loop {
			let others = store.order.len() - usize::from(old > 0);
			if others == 0 || (others < self.settings.max_entries && store.memory - old + entry.size <= self.settings.max_memory) {
				break;
			}
			store.take_oldest_but(key);
		}
		if let Some(slot) = store.map.get_mut(key) {
			if let Some(e) = slot.entry.take() {
				store.order.remove(&e.seq);
				store.memory -= e.size;
			}
		}
		// counted: `grow` reserved above; a smaller answer gives the rest back
		store.memory += entry.size;
		if old > entry.size {
			store.budget.release(old - entry.size);
		}
		store.order.insert(entry.seq, key.to_vec());
		store.map.entry(key.to_vec()).or_default().entry = Some(entry);
		true
	}

	/// The answer from an entry: `Age` (the backend's, plus the time kept for HIT / STALE),
	/// 304 for a matching If-None-Match.
	fn answer(&self, e: &Entry, request: &HeaderMap, head: bool, outcome: Outcome) -> Response<Body> {
		let not_modified = e.status == StatusCode::OK && none_match(request, e.headers.get(header::ETAG));
		let body = if head || not_modified || e.body.is_empty() { empty() } else { full(e.body.clone()) };
		let mut resp = Response::new(body);
		*resp.status_mut() = if not_modified { StatusCode::NOT_MODIFIED } else { e.status };
		*resp.headers_mut() = e.headers.clone();
		if not_modified {
			resp.headers_mut().remove(header::CONTENT_LENGTH);
		}
		let age = if outcome == Outcome::Miss { e.age } else { e.age.saturating_add(e.stored.elapsed().as_secs()) };
		if outcome != Outcome::Miss || e.age > 0 {
			resp.headers_mut().insert(header::AGE, HeaderValue::from(age));
		}
		self.mark(resp, outcome)
	}

	fn mark(&self, mut resp: Response<Body>, outcome: Outcome) -> Response<Body> {
		if let Some(h) = &self.settings.header {
			resp.headers_mut().insert(h.clone(), HeaderValue::from_static(outcome.as_str()));
		}
		resp
	}
}

/// The names in the answer's `Vary` (and `Accept-Encoding` for an encoded body: it is for
/// clients that accept the encoding, whatever Vary says) with the request's values.
fn varies_of(headers: &HeaderMap, request: &HeaderMap) -> Varies {
	let mut names: Vec<HeaderName> = vary_names(headers).iter().filter_map(|n| HeaderName::from_bytes(n.as_bytes()).ok()).collect();
	let encoded = headers.get(header::CONTENT_ENCODING).is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
	if encoded && !names.contains(&header::ACCEPT_ENCODING) {
		names.push(header::ACCEPT_ENCODING);
	}
	names
		.into_iter()
		.map(|n| {
			let v = joined(request, &n);
			(n, v)
		})
		.collect()
}

/// All values of a header, joined with ", ". `Accept-Encoding` is compared by its codings:
/// lower case, without spaces, sorted.
fn joined(headers: &HeaderMap, name: &HeaderName) -> Option<Vec<u8>> {
	let mut values = headers.get_all(name).iter().peekable();
	values.peek()?;
	if name == header::ACCEPT_ENCODING {
		let mut codings: Vec<Vec<u8>> = values
			.flat_map(|v| v.as_bytes().split(|b| *b == b','))
			.map(|c| c.iter().filter(|b| !b.is_ascii_whitespace()).map(u8::to_ascii_lowercase).collect::<Vec<u8>>())
			.filter(|c| !c.is_empty())
			.collect();
		codings.sort();
		codings.dedup();
		return Some(codings.join(&b","[..]));
	}
	let mut out = vec![];
	for (i, v) in values.enumerate() {
		if i > 0 {
			out.extend_from_slice(b", ");
		}
		out.extend_from_slice(v.as_bytes());
	}
	Some(out)
}

/// The names in `Vary`, lowercase.
fn vary_names(headers: &HeaderMap) -> Vec<String> {
	headers
		.get_all(header::VARY)
		.iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|v| v.split(','))
		.map(|n| n.trim().to_ascii_lowercase())
		.filter(|n| !n.is_empty())
		.collect()
}

/// An answer that may go to other clients: no `Set-Cookie`, no `Cache-Control: no-store`,
/// `private` or `no-cache` (also with field names), no `Vary: *`.
fn shareable(headers: &HeaderMap) -> bool {
	let forbids = headers.get_all(header::CACHE_CONTROL).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).any(|d| {
		let name = d.split('=').next().unwrap_or("").trim();
		["no-store", "private", "no-cache"].iter().any(|f| name.eq_ignore_ascii_case(f))
	});
	!forbids && !headers.contains_key(header::SET_COOKIE) && !vary_names(headers).iter().any(|n| n == "*")
}

/// The entity tags of a list (`If-None-Match`, `ETag`): their opaque part, `W/` dropped for
/// the weak comparison; `*` as itself. Commas inside the quotes are part of the tag.
fn entity_tags(v: &str) -> Vec<&str> {
	let mut tags = vec![];
	let mut rest = v;
	loop {
		rest = rest.trim_start_matches(|c: char| c == ',' || c.is_ascii_whitespace());
		if rest.is_empty() {
			return tags;
		}
		if let Some(r) = rest.strip_prefix('*') {
			tags.push("*");
			rest = r;
			continue;
		}
		let r = rest.strip_prefix("W/").unwrap_or(rest);
		let Some(r) = r.strip_prefix('"') else { return tags };
		let Some(end) = r.find('"') else { return tags };
		tags.push(&r[..end]);
		rest = &r[end + 1..];
	}
}

/// Whether If-None-Match names the ETag (weak comparison, RFC 9110 §13.1.2).
fn none_match(request: &HeaderMap, etag: Option<&HeaderValue>) -> bool {
	let Some(etag) = etag.and_then(|e| e.to_str().ok()).and_then(|e| entity_tags(e).first().copied()) else { return false };
	request.get_all(header::IF_NONE_MATCH).iter().filter_map(|v| v.to_str().ok()).flat_map(entity_tags).any(|t| t == "*" || t == etag)
}

fn full(bytes: Bytes) -> Body {
	Full::new(bytes).map_err(|never| match never {}).boxed()
}

fn empty() -> Body {
	Empty::new().map_err(|never| match never {}).boxed()
}

/// Reads a body of at most `max` bytes within `COLLECT_LIMIT`. Otherwise (larger, slower,
/// trailers, an error) gives back a body that sends what was read and then the rest as it
/// comes, the error included; and whether it was too large (`true`) rather than slow or broken.
async fn collect(mut body: Body, max: u64) -> Result<Bytes, (Body, bool)> {
	use hyper::body::Body as _;
	if body.size_hint().lower() > max {
		return Err((body, true));
	}
	let until = Instant::now() + COLLECT_LIMIT;
	let mut buf = BytesMut::new();
	loop {
		let Ok(frame) = tokio::time::timeout_at(until, body.frame()).await else {
			return Err((Resumed { read: Some(buf.freeze()), next: None, rest: Some(body) }.boxed(), false));
		};
		match frame {
			None => return Ok(buf.freeze()),
			Some(Ok(frame)) => match frame.into_data() {
				Ok(data) => {
					buf.extend_from_slice(&data);
					if buf.len() as u64 > max {
						return Err((Resumed { read: Some(buf.freeze()), next: None, rest: Some(body) }.boxed(), true));
					}
				}
				Err(frame) => return Err((Resumed { read: Some(buf.freeze()), next: Some(Ok(frame)), rest: Some(body) }.boxed(), false)),
			},
			Some(Err(e)) => return Err((Resumed { read: Some(buf.freeze()), next: Some(Err(e)), rest: None }.boxed(), false)),
		}
	}
}

/// What was read, then the frame it stopped at, then the rest of the body.
struct Resumed {
	read: Option<Bytes>,
	next: Option<Result<Frame<Bytes>, BoxError>>,
	rest: Option<Body>,
}

impl hyper::body::Body for Resumed {
	type Data = Bytes;
	type Error = BoxError;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
		if let Some(read) = self.read.take().filter(|b| !b.is_empty()) {
			return Poll::Ready(Some(Ok(Frame::data(read))));
		}
		if let Some(next) = self.next.take() {
			return Poll::Ready(Some(next));
		}
		match self.rest.as_mut() {
			Some(rest) => Pin::new(rest).poll_frame(cx),
			None => Poll::Ready(None),
		}
	}

	fn is_end_stream(&self) -> bool {
		self.read.as_ref().is_none_or(Bytes::is_empty) && self.next.is_none() && self.rest.as_ref().is_none_or(|r| r.is_end_stream())
	}

	/// The rest's, with what was read (so a known length stays known).
	fn size_hint(&self) -> hyper::body::SizeHint {
		let mut hint = self.rest.as_ref().map_or_else(|| hyper::body::SizeHint::with_exact(0), |r| r.size_hint());
		let held = self.read.as_ref().map_or(0, Bytes::len)
			+ self.next.as_ref().and_then(|n| n.as_ref().ok()).and_then(Frame::data_ref).map_or(0, Bytes::len);
		let held = held as u64;
		if let Some(upper) = hint.upper() {
			hint.set_upper(upper.saturating_add(held));
		}
		hint.set_lower(hint.lower().saturating_add(held));
		hint
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cache(yaml: &str) -> Arc<Cache> {
		let spec: CacheSpec = serde_json::from_value(crate::config::yaml::<serde_json::Value>(yaml).unwrap()).unwrap();
		Arc::new(Cache::new("c", &spec, "middleware c").unwrap())
	}

	fn req(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
		let mut b = hyper::Request::builder().method(method).uri(uri);
		for (k, v) in headers {
			b = b.header(*k, *v);
		}
		b.body(()).unwrap().into_parts().0
	}

	fn resp(status: u16, headers: &[(&str, &str)], body: &'static str) -> Response<Body> {
		let mut r = Response::new(full(Bytes::from_static(body.as_bytes())));
		*r.status_mut() = StatusCode::from_u16(status).unwrap();
		for (k, v) in headers {
			r.headers_mut().append(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
		}
		r
	}

	async fn text(r: Response<Body>) -> String {
		String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
	}

	const ASK: Ask<'static> = Ask { host: "a.example", route: "r", https: false, port: 80, cert: None, body_empty: true };

	async fn ask(c: &Arc<Cache>, parts: &mut Parts) -> Result<(Response<Body>, Outcome), Box<Pending>> {
		c.request(parts, &ASK).await
	}

	/// Until `n` requests wait for the one of `pending`.
	async fn waiters(pending: &Pending, n: usize) {
		let flight = &pending.lead.as_ref().unwrap().flight;
		while flight.tx.receiver_count() < n {
			tokio::time::sleep(Duration::from_millis(1)).await;
		}
	}

	/// The request leads and the backend answers `back`; returns the outcome.
	async fn fill(c: &Arc<Cache>, parts: &mut Parts, back: Response<Body>) -> (Response<Body>, Outcome) {
		let pending = ask(c, parts).await.expect_err("a miss");
		c.response(pending, back).await
	}

	#[tokio::test(start_paused = true)]
	async fn kept_for_ttl_with_age_and_header() {
		let c = cache("{ttl: 100ms}");
		let (r, o) = fill(&c, &mut req("GET", "/j?x=1", &[]), resp(200, &[("content-type", "application/json")], "{\"n\":1}")).await;
		assert_eq!((o, r.headers()["x-cache"].to_str().unwrap()), (Outcome::Miss, "MISS"));
		assert!(!r.headers().contains_key("age"));
		assert_eq!(text(r).await, "{\"n\":1}");
		let (r, o) = ask(&c, &mut req("GET", "/j?x=1", &[])).await.ok().expect("a hit");
		assert_eq!((o, &r.headers()["age"], &r.headers()["content-length"]), (Outcome::Hit, &HeaderValue::from(0), &HeaderValue::from(7)));
		assert_eq!(text(r).await, "{\"n\":1}");
		// HEAD from GET's answer, without the body
		let (r, _) = ask(&c, &mut req("HEAD", "/j?x=1", &[])).await.ok().expect("a hit");
		assert_eq!(r.headers()["content-length"], HeaderValue::from(7));
		assert_eq!(text(r).await, "");
		// another query, another key
		assert!(ask(&c, &mut req("GET", "/j?x=2", &[])).await.is_err());
		tokio::time::advance(Duration::from_millis(101)).await;
		assert!(ask(&c, &mut req("GET", "/j?x=1", &[])).await.is_err(), "out of date");
		// the backend's Age stays on a MISS and grows on a HIT
		fill(&c, &mut req("GET", "/aged", &[]), resp(200, &[("age", "30")], "x")).await;
		tokio::time::advance(Duration::from_millis(50)).await;
		let (r, _) = ask(&c, &mut req("GET", "/aged", &[])).await.ok().unwrap();
		assert_eq!(r.headers()["age"], "30");
		let (r, _) = fill(&c, &mut req("GET", "/aged2", &[]), resp(200, &[("age", "7")], "x")).await;
		assert_eq!(r.headers()["age"], "7");
	}

	#[tokio::test]
	async fn the_key_has_route_scheme_port_and_certificate() {
		let c = cache("{ttl: 10s, share_credentials: true}");
		fill(&c, &mut req("GET", "/", &[]), resp(200, &[], "x")).await;
		for other in [
			Ask { route: "other", ..ASK },
			Ask { https: true, ..ASK },
			Ask { port: 8080, ..ASK },
			Ask { cert: Some((false, "NONE ")), ..ASK },
		] {
			assert!(c.request(&mut req("GET", "/", &[]), &other).await.is_err());
		}
		// a client certificate is a credential: not without share_credentials, and one per certificate
		let alice = Ask { cert: Some((true, "SUCCESS Hash=aa")), ..ASK };
		let bob = Ask { cert: Some((true, "SUCCESS Hash=bb")), ..ASK };
		let strict = cache("{ttl: 10s}");
		assert!(strict.request(&mut req("GET", "/", &[]), &alice).await.unwrap_err().key.is_none(), "BYPASS");
		let p = c.request(&mut req("GET", "/", &[]), &alice).await.unwrap_err();
		c.response(p, resp(200, &[], "alice")).await;
		assert!(c.request(&mut req("GET", "/", &[]), &alice).await.is_ok());
		assert!(c.request(&mut req("GET", "/", &[]), &bob).await.is_err());
		// a request that may have a body is not for the cache
		assert!(c.request(&mut req("GET", "/", &[]), &Ask { body_empty: false, ..ASK }).await.unwrap_err().key.is_none());
	}

	#[tokio::test]
	async fn bodies_are_looked_for() {
		let mut body = empty();
		assert!(settle(&mut body).await);
		// a stream that ends without data (HTTP/3 GET)
		let mut body = http_body_util::StreamBody::new(futures_util::stream::iter(Vec::<Result<Frame<Bytes>, BoxError>>::new())).boxed();
		assert!(settle(&mut body).await);
		// HTTP/2: an empty DATA frame that ends the stream
		let frames = vec![Ok::<_, BoxError>(Frame::data(Bytes::new()))];
		let mut body = http_body_util::StreamBody::new(futures_util::stream::iter(frames)).boxed();
		assert!(settle(&mut body).await);
		// DATA frames without a length: put back
		let frames = vec![Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"ab"))), Ok(Frame::data(Bytes::from_static(b"c")))];
		let mut body = http_body_util::StreamBody::new(futures_util::stream::iter(frames)).boxed();
		assert!(!settle(&mut body).await);
		assert_eq!(body.collect().await.unwrap().to_bytes(), "abc");
	}

	#[tokio::test]
	async fn what_is_never_kept() {
		let c = cache("{ttl: 10s}");
		for (method, headers) in [
			("POST", vec![]),
			("GET", vec![("authorization", "Bearer x")]),
			("GET", vec![("cookie", "s=1")]),
			("GET", vec![("range", "bytes=0-1")]),
		] {
			let p = ask(&c, &mut req(method, "/", &headers)).await.err().unwrap();
			let (r, o) = c.response(p, resp(200, &[], "x")).await;
			assert_eq!((o, &r.headers()["x-cache"]), (Outcome::Bypass, &HeaderValue::from_static("BYPASS")), "{method} {headers:?}");
		}
		for (i, headers) in [
			vec![("set-cookie", "a=1")],
			vec![("cache-control", "private, max-age=60")],
			vec![("cache-control", "no-store")],
			vec![("cache-control", "no-cache=\"x\"")],
			vec![("vary", "*")],
			vec![("content-type", "text/event-stream")],
		]
		.into_iter()
		.enumerate()
		{
			let path = format!("/{i}");
			for n in 1..=STRIKES {
				let p = ask(&c, &mut req("GET", &path, &[])).await.expect_err("not kept");
				assert!(p.lead.is_some(), "{headers:?}: lead {n} of {STRIKES}");
				c.response(p, resp(200, &headers, "x")).await;
			}
			let p = ask(&c, &mut req("GET", &path, &[])).await.expect_err("not kept");
			assert!(p.lead.is_none(), "{headers:?}: after {STRIKES} in a row the next ttl goes without waiting in line");
		}
		fill(&c, &mut req("GET", "/s", &[]), resp(404, &[], "x")).await;
		assert!(ask(&c, &mut req("GET", "/s", &[])).await.is_err(), "only 200 by default");
		let c = cache("{ttl: 10s, status: [200, 404], share_credentials: true}");
		fill(&c, &mut req("GET", "/", &[("cookie", "s=1")]), resp(404, &[], "x")).await;
		assert!(ask(&c, &mut req("GET", "/", &[("authorization", "x")])).await.is_ok());
	}

	/// One client cannot make the others stop waiting for leads (or skip a fresh answer).
	#[tokio::test(start_paused = true)]
	async fn one_client_cannot_switch_the_cache_off() {
		let c = cache("{ttl: 1s}");
		let lead = |c: &Arc<Cache>, headers: &'static [(&'static str, &'static str)]| {
			let c = c.clone();
			async move { ask(&c, &mut req("GET", "/", headers)).await.expect_err("goes to the backend") }
		};
		// an unkeyed header the backend refuses (406), or a slow body: never a strike
		for _ in 0..5 {
			let p = lead(&c, &[("x-odd", "1")]).await;
			assert!(p.lead.is_some());
			c.response(p, resp(406, &[], "no")).await;
		}
		let p = lead(&c, &[]).await;
		assert!(p.lead.is_some(), "406s do not make a pass");
		c.response(p, resp(200, &[], "ok")).await;
		assert_eq!(ask(&c, &mut req("GET", "/", &[])).await.ok().unwrap().1, Outcome::Hit);
		// a Set-Cookie once or twice (a session made for one request) does not either
		tokio::time::advance(Duration::from_millis(1001)).await;
		for _ in 0..STRIKES - 1 {
			let p = lead(&c, &[]).await;
			c.response(p, resp(200, &[("set-cookie", "s=1")], "x")).await;
		}
		let p = lead(&c, &[]).await;
		assert!(p.lead.is_some(), "two strikes are not a pass");
		c.response(p, resp(200, &[], "ok")).await;
		// a fresh answer comes before a pass; and a pass is for the Vary values it was made with
		let c = cache("{ttl: 1s}");
		fill(&c, &mut req("GET", "/v", &[("accept-language", "ja")]), resp(200, &[("vary", "Accept-Language")], "ja")).await;
		for _ in 0..STRIKES {
			let p = ask(&c, &mut req("GET", "/v", &[("accept-language", "en")])).await.unwrap_err();
			c.response(p, resp(200, &[("vary", "Accept-Language"), ("cache-control", "private")], "en")).await;
		}
		assert!(ask(&c, &mut req("GET", "/v", &[("accept-language", "en")])).await.unwrap_err().lead.is_none(), "a pass for en");
		assert_eq!(ask(&c, &mut req("GET", "/v", &[("accept-language", "ja")])).await.ok().unwrap().1, Outcome::Hit);
		tokio::time::advance(Duration::from_millis(1001)).await;
		assert!(ask(&c, &mut req("GET", "/v", &[("accept-language", "ja")])).await.unwrap_err().lead.is_some(), "ja still leads");
		// passes are counted in the memory and swept when out of date
		let (_, bytes) = c.usage();
		assert_eq!(bytes, 0, "the pass and the old answer are gone");
	}

	#[tokio::test]
	async fn the_head_decides_before_the_body_is_looked_at() {
		let c = cache("{ttl: 1s}");
		for (method, headers) in [("POST", vec![]), ("GET", vec![("expect", "100-continue")]), ("GET", vec![("cookie", "a=1")])] {
			assert!(!c.admits(&req(method, "/", &headers), &ASK), "{method} {headers:?}");
		}
		assert!(c.admits(&req("GET", "/", &[]), &ASK));
	}

	#[tokio::test]
	async fn large_bodies_and_broken_ones_pass_untouched() {
		let c = cache("{ttl: 10s, max_body: 4}");
		let (r, _) = fill(&c, &mut req("GET", "/", &[]), resp(200, &[], "0123456789")).await;
		assert_eq!(text(r).await, "0123456789");
		// no Content-Length: read up to max_body, then sent on
		let stream = futures_util::stream::iter([
			Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"012"))),
			Ok(Frame::data(Bytes::from_static(b"3456"))),
		]);
		let (r, _) = fill(&c, &mut req("GET", "/b", &[]), Response::new(http_body_util::StreamBody::new(stream).boxed())).await;
		assert_eq!(text(r).await, "0123456");
		// an error stays an error
		let stream = futures_util::stream::iter([
			Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"01"))),
			Err(BoxError::new(std::io::Error::other("cut"))),
		]);
		let (r, _) = fill(&c, &mut req("GET", "/c", &[]), Response::new(http_body_util::StreamBody::new(stream).boxed())).await;
		let mut body = r.into_body();
		assert_eq!(body.frame().await.unwrap().unwrap().into_data().unwrap(), "01");
		assert!(body.frame().await.unwrap().is_err());
		assert!(ask(&c, &mut req("GET", "/c", &[])).await.is_err(), "nothing kept");
		// an answer larger than max_memory is given but not kept
		let c = cache("{ttl: 10s, max_body: 1000, max_memory: 1000}");
		let (r, o) = fill(&c, &mut req("GET", "/", &[]), resp(200, &[], Box::leak("y".repeat(900).into_boxed_str()))).await;
		assert_eq!((o, text(r).await.len()), (Outcome::Miss, 900));
		// nothing kept but the strike against the key (counted in the memory)
		let (n, bytes) = c.usage();
		assert!(n == 0 && bytes > 0 && bytes < 1000, "{n} {bytes}");
	}

	#[tokio::test(start_paused = true)]
	async fn slow_bodies_are_sent_on() {
		let c = cache("{ttl: 10s}");
		let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(4);
		tx.send(Ok(Frame::data(Bytes::from_static(b"first")))).await.unwrap();
		let body = http_body_util::StreamBody::new(tokio_stream_from(rx)).boxed();
		let (r, o) = fill(&c, &mut req("GET", "/", &[]), Response::new(body)).await;
		assert_eq!(o, Outcome::Miss);
		tx.send(Ok(Frame::data(Bytes::from_static(b" second")))).await.unwrap();
		drop(tx);
		assert_eq!(text(r).await, "first second");
		assert_eq!(c.usage().0, 0);
	}

	fn tokio_stream_from(
		mut rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
	) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, BoxError>> {
		futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
	}

	#[tokio::test]
	async fn vary_and_encodings() {
		let c = cache("{ttl: 10s, vary: [X-Lang]}");
		fill(&c, &mut req("GET", "/", &[("x-lang", "ja")]), resp(200, &[], "ja")).await;
		assert!(ask(&c, &mut req("GET", "/", &[("x-lang", "en")])).await.is_err());
		assert!(ask(&c, &mut req("GET", "/", &[("x-lang", "ja")])).await.is_ok());
		// the answer's Vary, and Accept-Encoding for an encoded body (compared by its codings)
		fill(&c, &mut req("GET", "/g", &[("accept-encoding", "gzip, br")]), resp(200, &[("content-encoding", "gzip")], "z")).await;
		assert!(ask(&c, &mut req("GET", "/g", &[])).await.is_err());
		assert!(ask(&c, &mut req("GET", "/g", &[("accept-encoding", "br,GZIP")])).await.is_ok());
		fill(&c, &mut req("GET", "/o", &[("origin", "https://a")]), resp(200, &[("vary", "Origin")], "z")).await;
		assert!(ask(&c, &mut req("GET", "/o", &[("origin", "https://b")])).await.is_err());
		assert!(ask(&c, &mut req("GET", "/o", &[])).await.is_err());
	}

	#[tokio::test]
	async fn conditional_requests() {
		let c = cache("{ttl: 10s}");
		// the leader's own condition is not sent on: the full answer is kept
		let mut p = req("GET", "/", &[("if-none-match", "\"v1\"")]);
		let pending = ask(&c, &mut p).await.err().unwrap();
		assert!(!p.headers.contains_key("if-none-match"));
		let (r, _) = c.response(pending, resp(200, &[("etag", "\"v1\"")], "body")).await;
		assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
		let (r, _) = ask(&c, &mut req("GET", "/", &[("if-none-match", "W/\"v1\"")])).await.ok().unwrap();
		assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
		let (r, _) = ask(&c, &mut req("GET", "/", &[("if-none-match", "\"v0\"")])).await.ok().unwrap();
		assert_eq!((r.status(), text(r).await.as_str()), (StatusCode::OK, "body"));
		// commas inside the quotes belong to the tag
		fill(&c, &mut req("GET", "/c", &[]), resp(200, &[("etag", "\"a,b\"")], "body")).await;
		let (r, _) = ask(&c, &mut req("GET", "/c", &[("if-none-match", "\"x\", \"a,b\"")])).await.ok().unwrap();
		assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
		let (r, _) = ask(&c, &mut req("GET", "/c", &[("if-none-match", "\"a\", \"b\"")])).await.ok().unwrap();
		assert_eq!(r.status(), StatusCode::OK);
		assert_eq!(entity_tags("W/\"x\" ,\"y,z\", *"), ["x", "y,z", "*"]);
	}

	#[tokio::test]
	async fn one_request_per_key_and_the_others_wait() {
		let c = cache("{ttl: 10s}");
		let pending = ask(&c, &mut req("GET", "/", &[])).await.err().unwrap();
		let waiting: Vec<_> = (0..10)
			.map(|_| {
				let c = c.clone();
				tokio::spawn(async move { ask(&c, &mut req("GET", "/", &[])).await.ok().map(|(_, o)| o) })
			})
			.collect();
		waiters(&pending, 10).await;
		assert!(waiting.iter().all(|w| !w.is_finished()), "they wait for the first");
		c.response(pending, resp(200, &[], "x")).await;
		for w in waiting {
			assert_eq!(w.await.unwrap(), Some(Outcome::Hit));
		}
		// the first goes away: one of the others leads
		let c = cache("{ttl: 10s}");
		let pending = ask(&c, &mut req("GET", "/", &[])).await.err().unwrap();
		let other = {
			let c = c.clone();
			tokio::spawn(async move { ask(&c, &mut req("GET", "/", &[])).await.err().is_some_and(|p| p.lead.is_some()) })
		};
		waiters(&pending, 1).await;
		drop(pending);
		assert!(other.await.unwrap(), "it leads instead");
		// an answer that is not kept: the others go to the backend without waiting in line
		let c = cache("{ttl: 10s}");
		let pending = ask(&c, &mut req("GET", "/", &[])).await.err().unwrap();
		let other = {
			let c = c.clone();
			tokio::spawn(async move { ask(&c, &mut req("GET", "/", &[])).await.err().map(|p| p.lead.is_none()) })
		};
		waiters(&pending, 1).await;
		c.response(pending, resp(200, &[("set-cookie", "a=1")], "x")).await;
		assert_eq!(other.await.unwrap(), Some(true));
	}

	#[tokio::test]
	async fn waiting_has_its_limits() {
		// those ahead keep going away: after RETRIES it goes alone
		let c = cache("{ttl: 10s}");
		let mut first = ask(&c, &mut req("GET", "/", &[])).await.err().unwrap();
		let other = {
			let c = c.clone();
			tokio::spawn(async move { ask(&c, &mut req("GET", "/", &[])).await.err().map(|p| (p.key.is_some(), p.lead.is_none())) })
		};
		for _ in 0..RETRIES {
			waiters(&first, 1).await;
			// put another one ahead before letting this one go
			let flight = first.lead.as_ref().unwrap().flight.clone();
			let next = Arc::new(Flight { tx: watch::channel(Done::Pending).0 });
			let lead = Lead { cache: c.clone(), key: first.key.clone().unwrap(), flight: next.clone(), done: false };
			let replacement = Box::new(Pending { key: first.key.clone(), lead: Some(lead), headers: HeaderMap::new(), head: false });
			{
				let mut store = c.store.lock().unwrap();
				store.map.get_mut(first.key.as_ref().unwrap()).unwrap().flight = Some(next);
			}
			first.lead.as_mut().unwrap().done = true;
			flight.tx.send_replace(Done::Abandoned);
			first = replacement;
		}
		assert_eq!(other.await.unwrap(), Some((true, true)), "a MISS of its own");
		drop(first);
	}

	#[tokio::test(start_paused = true)]
	async fn a_slow_request_ahead_is_not_waited_for_forever() {
		let c = cache("{ttl: 10s}");
		let pending = ask(&c, &mut req("GET", "/", &[])).await.err().unwrap();
		let other = {
			let c = c.clone();
			tokio::spawn(async move { ask(&c, &mut req("GET", "/", &[])).await.err().map(|p| p.lead.is_none()) })
		};
		waiters(&pending, 1).await;
		tokio::time::advance(WAIT_LIMIT + Duration::from_millis(1)).await;
		assert_eq!(other.await.unwrap(), Some(true));
		drop(pending);
	}

	#[tokio::test(start_paused = true)]
	async fn stale_on_error() {
		let c = cache("{ttl: 100ms, stale_on_error: 10s}");
		fill(&c, &mut req("GET", "/", &[]), resp(200, &[], "old")).await;
		tokio::time::advance(Duration::from_millis(101)).await;
		let (r, o) = fill(&c, &mut req("GET", "/", &[]), resp(502, &[], "down")).await;
		assert_eq!((o, r.headers()["x-cache"].to_str().unwrap()), (Outcome::Stale, "STALE"));
		assert_eq!(text(r).await, "old");
		// for ttl after the failure, the old answer at once (nobody goes to the backend)
		let (r, o) = ask(&c, &mut req("GET", "/", &[])).await.ok().expect("at once");
		assert_eq!((o, text(r).await.as_str()), (Outcome::Stale, "old"));
		let (r, o) = ask(&c, &mut req("HEAD", "/", &[])).await.ok().expect("HEAD too");
		assert_eq!((o, text(r).await.as_str()), (Outcome::Stale, ""));
		// then one tries again, and the others get the old answer meanwhile
		tokio::time::advance(Duration::from_millis(101)).await;
		let pending = ask(&c, &mut req("GET", "/", &[])).await.expect_err("one tries");
		assert!(pending.lead.is_some());
		let (_, o) = ask(&c, &mut req("GET", "/", &[])).await.ok().expect("not waiting");
		assert_eq!(o, Outcome::Stale);
		let (r, o) = c.response(pending, resp(200, &[], "new")).await;
		assert_eq!((o, text(r).await.as_str()), (Outcome::Miss, "new"));
		let (r, o) = ask(&c, &mut req("GET", "/", &[])).await.ok().unwrap();
		assert_eq!((o, text(r).await.as_str()), (Outcome::Hit, "new"));
		// HEAD alone sees the backend fail: the old answer without the body
		let c = cache("{ttl: 100ms, stale_on_error: 10s}");
		fill(&c, &mut req("GET", "/", &[]), resp(200, &[], "old")).await;
		tokio::time::advance(Duration::from_millis(101)).await;
		let p = ask(&c, &mut req("HEAD", "/", &[])).await.expect_err("HEAD goes");
		let (r, o) = c.response(p, resp(503, &[], "")).await;
		assert_eq!((o, r.status(), text(r).await.as_str()), (Outcome::Stale, StatusCode::OK, ""));
		// without stale_on_error the error goes through
		let c = cache("{ttl: 100ms, header: ''}");
		fill(&c, &mut req("GET", "/", &[]), resp(200, &[], "old")).await;
		tokio::time::advance(Duration::from_millis(101)).await;
		let (r, o) = fill(&c, &mut req("GET", "/", &[]), resp(503, &[], "down")).await;
		assert_eq!((o, r.status(), r.headers().contains_key("x-cache")), (Outcome::Miss, StatusCode::SERVICE_UNAVAILABLE, false));
	}

	#[tokio::test]
	async fn an_error_is_handed_to_those_waiting() {
		let c = cache("{ttl: 10s}");
		let pending = ask(&c, &mut req("GET", "/", &[])).await.err().unwrap();
		let other = {
			let c = c.clone();
			tokio::spawn(async move {
				let (r, o) = ask(&c, &mut req("GET", "/", &[])).await.ok().expect("the error");
				(o, r.status(), text(r).await)
			})
		};
		waiters(&pending, 1).await;
		c.response(pending, resp(503, &[], "down")).await;
		assert_eq!(other.await.unwrap(), (Outcome::Miss, StatusCode::SERVICE_UNAVAILABLE, "down".to_string()));
		assert!(ask(&c, &mut req("GET", "/", &[])).await.err().unwrap().lead.is_some(), "the error is not kept");
		// one with Set-Cookie is not handed on
		let pending = ask(&c, &mut req("GET", "/", &[])).await.err().unwrap();
		let other = {
			let c = c.clone();
			tokio::spawn(async move { ask(&c, &mut req("GET", "/", &[])).await.is_err() })
		};
		waiters(&pending, 1).await;
		c.response(pending, resp(503, &[("set-cookie", "s=1")], "down")).await;
		assert!(other.await.unwrap());
	}

	#[tokio::test(start_paused = true)]
	async fn the_oldest_go_first() {
		let c = cache("{ttl: 10s, max_entries: 2}");
		for p in ["/1", "/2", "/3"] {
			fill(&c, &mut req("GET", p, &[]), resp(200, &[], "x")).await;
		}
		assert_eq!(c.usage().0, 2);
		assert!(ask(&c, &mut req("GET", "/1", &[])).await.is_err());
		assert!(ask(&c, &mut req("GET", "/3", &[])).await.is_ok());
		// by memory
		let c = cache("{ttl: 10s, max_body: 1000, max_memory: 2000}");
		for p in ["/1", "/2", "/3"] {
			fill(&c, &mut req("GET", p, &[]), resp(200, &[], Box::leak("x".repeat(900).into_boxed_str()))).await;
		}
		let (n, bytes) = c.usage();
		assert!(n < 3 && bytes <= 2000, "{n} {bytes}");
		assert!(ask(&c, &mut req("GET", "/3", &[])).await.is_ok());
		// out of date for good: not counted
		tokio::time::advance(Duration::from_secs(11)).await;
		assert_eq!(c.usage(), (0, 0));
	}

	fn cache_in(yaml: &str, budget: &'static Budget) -> Arc<Cache> {
		let spec: CacheSpec = serde_json::from_value(crate::config::yaml::<serde_json::Value>(yaml).unwrap()).unwrap();
		Arc::new(Cache::within("c", &spec, "middleware c", budget).unwrap())
	}

	fn used(budget: &Budget) -> u64 {
		budget.used.load(Ordering::Relaxed)
	}

	/// All caches together stay under the process's budget (#349).
	#[tokio::test(start_paused = true)]
	async fn caches_share_the_process_budget() {
		let budget: &'static Budget = Box::leak(Box::new(Budget::new(3000)));
		let a = cache_in("{ttl: 10s, max_body: 1000}", budget);
		let b = cache_in("{ttl: 10s, max_body: 1000}", budget);
		let big = || resp(200, &[], Box::leak("x".repeat(900).into_boxed_str()));
		fill(&a, &mut req("GET", "/1", &[]), big()).await;
		fill(&a, &mut req("GET", "/2", &[]), big()).await;
		let (n, bytes) = a.usage();
		assert!(n == 2 && bytes > 2000 && bytes <= 3000, "{n} {bytes}");
		assert_eq!(used(budget), bytes);
		// no room for b's answer and nothing of b's own to drop: given, not kept (a keeps its own)
		let (r, o) = fill(&b, &mut req("GET", "/1", &[]), big()).await;
		assert_eq!((o, text(r).await.len()), (Outcome::Miss, 900));
		assert_eq!(b.usage(), (0, 0));
		assert!(ask(&b, &mut req("GET", "/1", &[])).await.is_err(), "not kept");
		assert_eq!(a.usage().0, 2);
		// a new answer of a drops a's oldest
		fill(&a, &mut req("GET", "/3", &[]), big()).await;
		assert_eq!(a.usage().0, 2);
		assert!(ask(&a, &mut req("GET", "/1", &[])).await.is_err(), "the oldest went");
		assert_eq!(ask(&a, &mut req("GET", "/2", &[])).await.ok().unwrap().1, Outcome::Hit);
		assert_eq!(ask(&a, &mut req("GET", "/3", &[])).await.ok().unwrap().1, Outcome::Hit);
		assert!(used(budget) <= 3000);
		// a's answers out of date for good (a not asked since): dropped to make room for b's
		tokio::time::advance(Duration::from_secs(11)).await;
		fill(&b, &mut req("GET", "/1", &[]), big()).await;
		assert_eq!(b.usage().0, 1);
		assert_eq!(used(budget), b.usage().1, "a's answers went");
		assert_eq!(a.usage(), (0, 0));
		// passes are counted too
		let c = cache_in("{ttl: 10s}", budget);
		for _ in 0..STRIKES {
			fill(&c, &mut req("GET", "/p", &[]), resp(200, &[("set-cookie", "s=1")], "x")).await;
		}
		let (n, pass) = c.usage();
		assert!(n == 0 && pass > 0, "{n} {pass}");
		assert_eq!(used(budget), b.usage().1 + pass);
		// a cache that goes (its rule changed) gives its memory back
		drop((a, b, c));
		assert_eq!(used(budget), 0);
	}

	/// When dropping this cache's own answers cannot make room, none is dropped (#350).
	#[tokio::test(start_paused = true)]
	async fn nothing_is_dropped_when_it_cannot_fit() {
		let budget: &'static Budget = Box::leak(Box::new(Budget::new(3000)));
		let big = || resp(200, &[], Box::leak("x".repeat(900).into_boxed_str()));
		let b = cache_in("{ttl: 60s, max_body: 1000}", budget);
		fill(&b, &mut req("GET", "/1", &[]), big()).await;
		fill(&b, &mut req("GET", "/2", &[]), big()).await;
		let a = cache_in("{ttl: 10s, max_body: 1000}", budget);
		fill(&a, &mut req("GET", "/s", &[]), resp(200, &[], "abc")).await;
		// strikes too: passes cannot be dropped to make room
		for _ in 0..STRIKES {
			fill(&a, &mut req("GET", "/p", &[]), resp(200, &[("set-cookie", "s=1")], "x")).await;
		}
		let before = used(budget);
		assert!(before <= 3000 && b.usage().0 == 2 && a.usage().0 == 1, "{before}");
		let (r, o) = fill(&a, &mut req("GET", "/1", &[]), big()).await;
		assert_eq!((o, text(r).await.len()), (Outcome::Miss, 900));
		assert!(ask(&a, &mut req("GET", "/1", &[])).await.is_err(), "not kept");
		assert_eq!(ask(&a, &mut req("GET", "/s", &[])).await.ok().unwrap().1, Outcome::Hit, "a's answer stays");
		assert_eq!((used(budget), b.usage().0), (before, 2));
	}

	/// A new answer that does not fit leaves the old one for `stale_on_error` (#350).
	#[tokio::test(start_paused = true)]
	async fn a_refresh_that_does_not_fit_keeps_the_old_answer() {
		let budget: &'static Budget = Box::leak(Box::new(Budget::new(0)));
		let body = |n: usize| resp(200, &[], Box::leak("x".repeat(n).into_boxed_str()));
		let a = cache_in("{ttl: 1s, stale_on_error: 30s, max_body: 2000}", budget);
		fill(&a, &mut req("GET", "/1", &[]), body(900)).await;
		let b = cache_in("{ttl: 60s, max_body: 2000}", budget);
		fill(&b, &mut req("GET", "/1", &[]), body(900)).await;
		budget.limit.store(used(budget) + 50, Ordering::Relaxed);
		tokio::time::advance(Duration::from_millis(1100)).await;
		// the backend's new answer is 100 bytes larger: given, not kept
		let (r, o) = fill(&a, &mut req("GET", "/1", &[]), body(1000)).await;
		assert_eq!((o, text(r).await.len()), (Outcome::Miss, 1000));
		// the backend fails: the old answer is still there
		let (r, o) = fill(&a, &mut req("GET", "/1", &[]), resp(500, &[], "down")).await;
		assert_eq!((o, text(r).await.len()), (Outcome::Stale, 900));
		assert!(used(budget) <= budget.limit.load(Ordering::Relaxed));
		// a smaller answer replaces it and gives the difference back (after the `ttl` of
		// immediate STALE that follows a failure)
		tokio::time::advance(Duration::from_millis(1100)).await;
		let before = used(budget);
		fill(&a, &mut req("GET", "/1", &[]), body(100)).await;
		assert_eq!(used(budget), before - 800);
		assert_eq!(ask(&a, &mut req("GET", "/1", &[])).await.ok().unwrap().1, Outcome::Hit);
	}

	#[tokio::test(start_paused = true)]
	async fn the_process_budget_can_change_and_be_lifted() {
		let budget: &'static Budget = Box::leak(Box::new(Budget::new(100)));
		let c = cache_in("{ttl: 10s}", budget);
		fill(&c, &mut req("GET", "/1", &[]), resp(200, &[], "abc")).await;
		assert_eq!(c.usage().0, 0, "over the budget");
		// 0: no limit of the process (each cache's max_memory still holds)
		budget.limit.store(0, Ordering::Relaxed);
		fill(&c, &mut req("GET", "/1", &[]), resp(200, &[], "abc")).await;
		fill(&c, &mut req("GET", "/2", &[]), resp(200, &[], "abc")).await;
		assert_eq!(c.usage().0, 2);
		// lowered below what is kept: the answers stay, new ones are not kept unless this
		// cache's own make room
		budget.limit.store(used(budget) / 2, Ordering::Relaxed);
		assert_eq!(c.usage().0, 2);
		fill(&c, &mut req("GET", "/3", &[]), resp(200, &[], "abc")).await;
		assert!(used(budget) <= budget.limit.load(Ordering::Relaxed), "this cache dropped its oldest");
		assert_eq!(ask(&c, &mut req("GET", "/3", &[])).await.ok().unwrap().1, Outcome::Hit);
		drop(c);
		assert_eq!(used(budget), 0);
	}

	#[test]
	fn settings_are_checked() {
		let bad = |yaml: &str| {
			let spec: CacheSpec = serde_json::from_value(crate::config::yaml::<serde_json::Value>(yaml).unwrap()).unwrap();
			spec.validate("m").unwrap_err().message
		};
		assert!(bad("{ttl: 50ms}").contains("100ms"));
		assert!(bad("{ttl: 2d}").contains("ttl"));
		assert!(bad("{ttl: 1s, status: [500]}").contains("cannot be kept"));
		assert!(bad("{ttl: 1s, max_body: 0}").contains("max_body"));
		assert!(bad("{ttl: 1s, max_body: 2048, max_memory: 1024}").contains("max_memory"));
		assert!(bad("{ttl: 1s, vary: ['a b']}").contains("vary"));
		assert!(bad("{ttl: 1s, max_entries: 0}").contains("max_entries"));
		for h in ["Connection", "transfer-encoding", "Content-Length", "age", "set-cookie"] {
			assert!(bad(&format!("{{ttl: 1s, header: {h}}}")).contains("header"), "{h}");
		}
	}
}
