//! `cache` (#340): answers of GET kept in memory for `ttl`, in this process only (nodes do not
//! share them). Made for many clients polling the same JSON every few seconds: the backend gets
//! one request per key and `ttl`, however many clients ask.
//!
//! - A request that finds nothing fresh leads: it goes to the backend, and the others asking
//!   for the same key meanwhile wait for its answer (coalescing) instead of going too.
//! - `stale_on_error`: when the backend fails (5xx, rproxy's 502 / 504), the last answer is
//!   given for that long after it went out of date.
//! - Never kept: other methods than GET (HEAD is answered from GET's answers), requests with
//!   `Authorization` / `Cookie` (unless `share_credentials`), `Range`, `Upgrade` or a body;
//!   answers with `Set-Cookie`, `Cache-Control: no-store / private / no-cache`, `Vary: *`,
//!   `Content-Range`, a status outside `status`, a body over `max_body`, trailers, or a body
//!   that broke off. The route's checks keep it out of the way of authentication
//!   (`HttpSpec::check_cache_route`): nothing that decides who gets in may come after it.
//! - The answer's `Vary` (and `Accept-Encoding` for an encoded body) is kept with it: a
//!   request with other values of those headers does not get it.

use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Frame;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

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
const DEFAULT_HEADER: &str = "x-cache";

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
	/// Requests with `Authorization` / `Cookie` are answered from the cache too (the backend's
	/// answer does not depend on them).
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
			Some(h) => Some(HeaderName::from_bytes(h.as_bytes()).map_err(|_| bad(format!("header: {h:?} is not a header name")))?),
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
	/// From the backend (kept or not).
	Miss,
	/// From memory although out of date: the backend failed (`stale_on_error`).
	Stale,
	/// Not for the cache (method, credentials, …): from the backend.
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
	/// The answer is not kept: go to the backend.
	Uncacheable,
	/// The request went away (its client did): look again.
	Abandoned,
}

struct Flight {
	tx: watch::Sender<Done>,
}

#[derive(Default)]
struct Slot {
	entry: Option<Arc<Entry>>,
	flight: Option<Arc<Flight>>,
}

#[derive(Default)]
struct Store {
	map: HashMap<Vec<u8>, Slot>,
	/// Keys of the entries, oldest first (all have the same `ttl`, so this is also the order
	/// in which they go out of date).
	order: BTreeMap<u64, Vec<u8>>,
	memory: u64,
}

impl Store {
	/// Takes the entry of `key` out of the bookkeeping (the slot stays while a request leads).
	fn take(&mut self, key: &[u8]) {
		let Some(slot) = self.map.get_mut(key) else { return };
		if let Some(e) = slot.entry.take() {
			self.order.remove(&e.seq);
			self.memory -= e.size;
		}
		if slot.flight.is_none() {
			self.map.remove(key);
		}
	}

	fn take_oldest(&mut self) {
		let Some((&seq, key)) = self.order.first_key_value() else { return };
		let key = key.clone();
		self.take(&key);
		self.order.remove(&seq);
	}
}

/// A compiled `cache`. Its memory belongs to this version of the rule's `http`.
pub struct Cache {
	pub name: String,
	settings: Settings,
	store: Mutex<Store>,
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
	fn finish(&mut self, done: Done, entry: Option<Arc<Entry>>) {
		if self.done {
			return;
		}
		self.done = true;
		{
			let mut store = self.cache.store.lock().unwrap_or_else(|e| e.into_inner());
			if let Some(e) = entry {
				self.cache.insert(&mut store, &self.key, e);
			}
			if let Some(slot) = store.map.get_mut(&self.key) {
				if slot.flight.as_ref().is_some_and(|f| Arc::ptr_eq(f, &self.flight)) {
					slot.flight = None;
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
		self.finish(Done::Abandoned, None);
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
	fn bypass() -> Pending {
		Pending { key: None, lead: None, headers: HeaderMap::new(), head: false }
	}
}

impl Cache {
	pub fn new(name: &str, spec: &CacheSpec, what: &str) -> Result<Cache, ApiError> {
		Ok(Cache { name: name.to_string(), settings: Settings::of(spec, what)?, store: Mutex::default(), next: Default::default() })
	}

	/// Answers kept and the bytes they take (`/metrics`).
	pub fn usage(&self) -> (usize, u64) {
		let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
		(store.order.len(), store.memory)
	}

	fn eligible(&self, parts: &Parts) -> bool {
		let h = &parts.headers;
		(parts.method == Method::GET || parts.method == Method::HEAD)
			&& !h.contains_key(header::RANGE)
			&& !h.contains_key(header::UPGRADE)
			&& !h.contains_key(header::TRANSFER_ENCODING)
			&& h.get(header::CONTENT_LENGTH).is_none_or(|v| v.as_bytes() == b"0")
			&& (self.settings.share_credentials
				|| !(h.contains_key(header::AUTHORIZATION)
					|| h.contains_key(header::COOKIE)
					|| h.contains_key(header::PROXY_AUTHORIZATION)))
	}

	/// Host (lowercase, without the port), path and query, and the `vary` headers.
	fn key(&self, parts: &Parts, host: &str) -> Vec<u8> {
		let pq = parts.uri.path_and_query().map_or("/", |p| p.as_str());
		let mut key = Vec::with_capacity(host.len() + pq.len() + 1);
		key.extend(host.bytes().map(|b| b.to_ascii_lowercase()));
		key.push(b' ');
		key.extend_from_slice(pq.as_bytes());
		for name in &self.settings.vary {
			key.push(b'\n');
			if let Some(v) = joined(&parts.headers, name) {
				key.push(b'=');
				key.extend_from_slice(&v);
			}
		}
		key
	}

	/// The request side: an answer from memory, or what the response side needs. A request
	/// that finds another one already asking the backend for its key waits for that answer.
	pub async fn request(self: &Arc<Self>, parts: &mut Parts, host: &str) -> Result<(Response<Body>, Outcome), Box<Pending>> {
		if !self.eligible(parts) {
			return Err(Box::new(Pending::bypass()));
		}
		let key = self.key(parts, host);
		let head = parts.method == Method::HEAD;
		for _ in 0..RETRIES {
			let mut rx = {
				let mut store = self.store.lock().unwrap_or_else(|e| e.into_inner());
				let slot = store.map.get(&key);
				let now = Instant::now();
				if let Some(e) = slot.and_then(|s| s.entry.as_ref()).filter(|e| now < e.fresh_until && e.fits(&parts.headers)) {
					let e = e.clone();
					drop(store);
					return Ok((self.answer(&e, &parts.headers, head, Outcome::Hit), Outcome::Hit));
				}
				// HEAD does not lead: its answer has no body to keep
				if head {
					return Err(Box::new(Pending { key: Some(key), lead: None, headers: parts.headers.clone(), head }));
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
			let done = match rx.wait_for(|d| !matches!(d, Done::Pending)).await {
				Ok(d) => d.clone(),
				Err(_) => Done::Abandoned,
			};
			match done {
				Done::Fresh(e) if e.fits(&parts.headers) => return Ok((self.answer(&e, &parts.headers, head, Outcome::Hit), Outcome::Hit)),
				Done::Stale(e) if e.fits(&parts.headers) => {
					return Ok((self.answer(&e, &parts.headers, head, Outcome::Stale), Outcome::Stale));
				}
				Done::Abandoned => continue,
				_ => break,
			}
		}
		Err(Box::new(Pending { key: Some(key), lead: None, headers: parts.headers.clone(), head }))
	}

	/// The response side: keeps the backend's answer (when this request led and it may be
	/// kept), or gives the out-of-date one when the backend failed.
	pub async fn response(&self, mut pending: Box<Pending>, resp: Response<Body>) -> (Response<Body>, Outcome) {
		let Some(key) = pending.key.take() else { return (self.mark(resp, Outcome::Bypass), Outcome::Bypass) };
		if resp.status().is_server_error() && !self.settings.stale.is_zero() {
			if let Some(e) = self.stale(&key, &pending.headers) {
				if let Some(lead) = pending.lead.as_mut() {
					lead.finish(Done::Stale(e.clone()), None);
				}
				return (self.answer(&e, &pending.headers, pending.head, Outcome::Stale), Outcome::Stale);
			}
		}
		let Some(lead) = pending.lead.as_mut() else { return (self.mark(resp, Outcome::Miss), Outcome::Miss) };
		if !self.storable(&resp) {
			lead.finish(Done::Uncacheable, None);
			return (self.mark(resp, Outcome::Miss), Outcome::Miss);
		}
		let (parts, body) = resp.into_parts();
		match collect(body, self.settings.max_body).await {
			Ok(bytes) => {
				let e = Arc::new(self.entry(&key, parts.status, parts.headers, bytes, &pending.headers));
				if e.size <= self.settings.max_memory {
					lead.finish(Done::Fresh(e.clone()), Some(e.clone()));
				} else {
					lead.finish(Done::Uncacheable, None);
				}
				(self.answer(&e, &pending.headers, pending.head, Outcome::Miss), Outcome::Miss)
			}
			Err(body) => {
				lead.finish(Done::Uncacheable, None);
				(self.mark(Response::from_parts(parts, body), Outcome::Miss), Outcome::Miss)
			}
		}
	}

	fn stale(&self, key: &[u8], request: &HeaderMap) -> Option<Arc<Entry>> {
		let store = self.store.lock().unwrap_or_else(|e| e.into_inner());
		let e = store.map.get(key)?.entry.as_ref()?;
		(Instant::now() < e.stale_until && e.fits(request)).then(|| e.clone())
	}

	fn storable(&self, resp: &Response<Body>) -> bool {
		let h = resp.headers();
		self.settings.status.contains(&resp.status().as_u16())
			&& !h.contains_key(header::SET_COOKIE)
			&& !h.contains_key(header::CONTENT_RANGE)
			&& !forbids(h)
			&& !vary_names(h).iter().any(|n| n == "*")
			&& h.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()?.parse::<u64>().ok()).is_none_or(|n| n <= self.settings.max_body)
	}

	fn entry(&self, key: &[u8], status: StatusCode, mut headers: HeaderMap, body: Bytes, request: &HeaderMap) -> Entry {
		headers.remove(header::TRANSFER_ENCODING);
		if status == StatusCode::NO_CONTENT {
			headers.remove(header::CONTENT_LENGTH);
		} else {
			headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
		}
		let age = headers.remove(header::AGE).and_then(|v| v.to_str().ok()?.trim().parse().ok()).unwrap_or(0);
		let mut names: Vec<HeaderName> = vary_names(&headers).iter().filter_map(|n| HeaderName::from_bytes(n.as_bytes()).ok()).collect();
		// an encoded body is for clients that accept the encoding, whatever Vary says
		let encoded = headers.get(header::CONTENT_ENCODING).is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"));
		if encoded && !names.contains(&header::ACCEPT_ENCODING) {
			names.push(header::ACCEPT_ENCODING);
		}
		let varies: Vec<(HeaderName, Option<Vec<u8>>)> = names
			.into_iter()
			.map(|n| {
				let v = joined(request, &n);
				(n, v)
			})
			.collect();
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

	/// Puts an entry in place of the key's old one, making room by dropping the oldest.
	fn insert(&self, store: &mut Store, key: &[u8], entry: Arc<Entry>) {
		store.take(key);
		let now = Instant::now();
		// out of date for good
		while let Some(k) = store.order.first_key_value().map(|(_, k)| k.clone()) {
			let dead = store.map.get(&k).and_then(|s| s.entry.as_ref()).is_none_or(|e| e.stale_until <= now);
			if !dead {
				break;
			}
			store.take_oldest();
		}
		while !store.order.is_empty()
			&& (store.order.len() >= self.settings.max_entries || store.memory + entry.size > self.settings.max_memory)
		{
			store.take_oldest();
		}
		store.memory += entry.size;
		store.order.insert(entry.seq, key.to_vec());
		store.map.entry(key.to_vec()).or_default().entry = Some(entry);
	}

	/// The answer from an entry: `Age` for HIT / STALE, 304 for a matching If-None-Match.
	fn answer(&self, e: &Entry, request: &HeaderMap, head: bool, outcome: Outcome) -> Response<Body> {
		let not_modified = e.status == StatusCode::OK && none_match(request, e.headers.get(header::ETAG));
		let body = if head || not_modified || e.body.is_empty() { empty() } else { full(e.body.clone()) };
		let mut resp = Response::new(body);
		*resp.status_mut() = if not_modified { StatusCode::NOT_MODIFIED } else { e.status };
		*resp.headers_mut() = e.headers.clone();
		if not_modified {
			resp.headers_mut().remove(header::CONTENT_LENGTH);
		}
		if outcome != Outcome::Miss {
			resp.headers_mut().insert(header::AGE, HeaderValue::from(e.age.saturating_add(e.stored.elapsed().as_secs())));
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

/// All values of a header, joined with ", ".
fn joined(headers: &HeaderMap, name: &HeaderName) -> Option<Vec<u8>> {
	let mut values = headers.get_all(name).iter();
	let first = values.next()?;
	let mut out = first.as_bytes().to_vec();
	for v in values {
		out.extend_from_slice(b", ");
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

/// `Cache-Control: no-store`, `private` or `no-cache` (also with field names) of an answer.
fn forbids(headers: &HeaderMap) -> bool {
	headers.get_all(header::CACHE_CONTROL).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(',')).any(|d| {
		let name = d.split('=').next().unwrap_or("").trim();
		["no-store", "private", "no-cache"].iter().any(|f| name.eq_ignore_ascii_case(f))
	})
}

/// Whether If-None-Match names the ETag (weak comparison, RFC 9110 §13.1.2).
fn none_match(request: &HeaderMap, etag: Option<&HeaderValue>) -> bool {
	let Some(etag) = etag.and_then(|e| e.to_str().ok()) else { return false };
	let weak = |t: &str| t.trim().trim_start_matches("W/").to_string();
	let etag = weak(etag);
	request
		.get_all(header::IF_NONE_MATCH)
		.iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|v| v.split(','))
		.any(|t| t.trim() == "*" || weak(t) == etag)
}

fn full(bytes: Bytes) -> Body {
	Full::new(bytes).map_err(|never| match never {}).boxed()
}

fn empty() -> Body {
	Empty::new().map_err(|never| match never {}).boxed()
}

/// Reads a body of at most `max` bytes. Otherwise (larger, trailers, an error) gives back a
/// body that sends what was read and then the rest as it comes, the error included.
async fn collect(mut body: Body, max: u64) -> Result<Bytes, Body> {
	use hyper::body::Body as _;
	if body.size_hint().lower() > max {
		return Err(body);
	}
	let mut buf = BytesMut::new();
	loop {
		match body.frame().await {
			None => return Ok(buf.freeze()),
			Some(Ok(frame)) => match frame.into_data() {
				Ok(data) => {
					buf.extend_from_slice(&data);
					if buf.len() as u64 > max {
						return Err(Resumed { read: Some(buf.freeze()), next: None, rest: Some(body) }.boxed());
					}
				}
				Err(frame) => return Err(Resumed { read: Some(buf.freeze()), next: Some(Ok(frame)), rest: Some(body) }.boxed()),
			},
			Some(Err(e)) => return Err(Resumed { read: Some(buf.freeze()), next: Some(Err(e)), rest: None }.boxed()),
		}
	}
}

/// What `collect` read, then the frame it stopped at, then the rest of the body.
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

	/// Until `n` requests wait for the one of `pending`.
	async fn waiters(pending: &Pending, n: usize) {
		let flight = &pending.lead.as_ref().unwrap().flight;
		while flight.tx.receiver_count() < n {
			tokio::time::sleep(Duration::from_millis(1)).await;
		}
	}

	/// The request leads and the backend answers `back`; returns the outcome.
	async fn fill(c: &Arc<Cache>, parts: &mut Parts, back: Response<Body>) -> (Response<Body>, Outcome) {
		let pending = c.request(parts, "a.example").await.expect_err("a miss");
		c.response(pending, back).await
	}

	#[tokio::test]
	async fn kept_for_ttl_with_age_and_header() {
		let c = cache("{ttl: 100ms}");
		let (r, o) = fill(&c, &mut req("GET", "/j?x=1", &[]), resp(200, &[("content-type", "application/json")], "{\"n\":1}")).await;
		assert_eq!((o, r.headers()["x-cache"].to_str().unwrap()), (Outcome::Miss, "MISS"));
		assert!(!r.headers().contains_key("age"));
		assert_eq!(text(r).await, "{\"n\":1}");
		let (r, o) = c.request(&mut req("GET", "/j?x=1", &[]), "A.example").await.ok().expect("a hit");
		assert_eq!((o, &r.headers()["age"], &r.headers()["content-length"]), (Outcome::Hit, &HeaderValue::from(0), &HeaderValue::from(7)));
		assert_eq!(text(r).await, "{\"n\":1}");
		// HEAD from GET's answer, without the body
		let (r, _) = c.request(&mut req("HEAD", "/j?x=1", &[]), "a.example").await.ok().expect("a hit");
		assert_eq!(r.headers()["content-length"], HeaderValue::from(7));
		assert_eq!(text(r).await, "");
		// another query, another key
		assert!(c.request(&mut req("GET", "/j?x=2", &[]), "a.example").await.is_err());
		tokio::time::sleep(Duration::from_millis(120)).await;
		assert!(c.request(&mut req("GET", "/j?x=1", &[]), "a.example").await.is_err(), "out of date");
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
			let p = c.request(&mut req(method, "/", &headers), "a.example").await.err().unwrap();
			let (r, o) = c.response(p, resp(200, &[], "x")).await;
			assert_eq!((o, &r.headers()["x-cache"]), (Outcome::Bypass, &HeaderValue::from_static("BYPASS")), "{method} {headers:?}");
		}
		for headers in [
			vec![("set-cookie", "a=1")],
			vec![("cache-control", "private, max-age=60")],
			vec![("cache-control", "no-store")],
			vec![("cache-control", "no-cache=\"x\"")],
			vec![("vary", "*")],
		] {
			fill(&c, &mut req("GET", "/", &[]), resp(200, &headers, "x")).await;
			assert!(c.request(&mut req("GET", "/", &[]), "a.example").await.is_err(), "{headers:?} was kept");
		}
		fill(&c, &mut req("GET", "/", &[]), resp(500, &[], "x")).await;
		fill(&c, &mut req("GET", "/", &[]), resp(404, &[], "x")).await;
		assert!(c.request(&mut req("GET", "/", &[]), "a.example").await.is_err(), "only 200 by default");
		let c = cache("{ttl: 10s, status: [200, 404], share_credentials: true}");
		fill(&c, &mut req("GET", "/", &[("cookie", "s=1")]), resp(404, &[], "x")).await;
		assert!(c.request(&mut req("GET", "/", &[("authorization", "x")]), "a.example").await.is_ok());
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
		let (r, _) = fill(&c, &mut req("GET", "/", &[]), Response::new(http_body_util::StreamBody::new(stream).boxed())).await;
		assert_eq!(text(r).await, "0123456");
		// an error stays an error
		let stream = futures_util::stream::iter([
			Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"01"))),
			Err(BoxError::new(std::io::Error::other("cut"))),
		]);
		let (r, _) = fill(&c, &mut req("GET", "/", &[]), Response::new(http_body_util::StreamBody::new(stream).boxed())).await;
		let mut body = r.into_body();
		assert_eq!(body.frame().await.unwrap().unwrap().into_data().unwrap(), "01");
		assert!(body.frame().await.unwrap().is_err());
		assert!(c.request(&mut req("GET", "/", &[]), "a.example").await.is_err(), "nothing kept");
	}

	#[tokio::test]
	async fn vary_and_encodings() {
		let c = cache("{ttl: 10s, vary: [X-Lang]}");
		fill(&c, &mut req("GET", "/", &[("x-lang", "ja")]), resp(200, &[], "ja")).await;
		assert!(c.request(&mut req("GET", "/", &[("x-lang", "en")]), "a.example").await.is_err());
		assert!(c.request(&mut req("GET", "/", &[("x-lang", "ja")]), "a.example").await.is_ok());
		// the answer's Vary, and Accept-Encoding for an encoded body
		fill(&c, &mut req("GET", "/g", &[("accept-encoding", "gzip")]), resp(200, &[("content-encoding", "gzip")], "z")).await;
		assert!(c.request(&mut req("GET", "/g", &[]), "a.example").await.is_err());
		assert!(c.request(&mut req("GET", "/g", &[("accept-encoding", "gzip")]), "a.example").await.is_ok());
		fill(&c, &mut req("GET", "/o", &[("origin", "https://a")]), resp(200, &[("vary", "Origin")], "z")).await;
		assert!(c.request(&mut req("GET", "/o", &[("origin", "https://b")]), "a.example").await.is_err());
	}

	#[tokio::test]
	async fn conditional_requests() {
		let c = cache("{ttl: 10s}");
		// the leader's own condition is not sent on: the full answer is kept
		let mut p = req("GET", "/", &[("if-none-match", "\"v1\"")]);
		let pending = c.request(&mut p, "a.example").await.err().unwrap();
		assert!(!p.headers.contains_key("if-none-match"));
		let (r, _) = c.response(pending, resp(200, &[("etag", "\"v1\"")], "body")).await;
		assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
		let (r, _) = c.request(&mut req("GET", "/", &[("if-none-match", "W/\"v1\"")]), "a.example").await.ok().unwrap();
		assert_eq!(r.status(), StatusCode::NOT_MODIFIED);
		let (r, _) = c.request(&mut req("GET", "/", &[("if-none-match", "\"v0\"")]), "a.example").await.ok().unwrap();
		assert_eq!((r.status(), text(r).await.as_str()), (StatusCode::OK, "body"));
	}

	#[tokio::test]
	async fn one_request_per_key_and_the_others_wait() {
		let c = cache("{ttl: 10s}");
		let mut first = req("GET", "/", &[]);
		let pending = c.request(&mut first, "a.example").await.err().unwrap();
		let waiting: Vec<_> = (0..10)
			.map(|_| {
				let c = c.clone();
				tokio::spawn(async move { c.request(&mut req("GET", "/", &[]), "a.example").await.ok().map(|(_, o)| o) })
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
		let pending = c.request(&mut req("GET", "/", &[]), "a.example").await.err().unwrap();
		let other = {
			let c = c.clone();
			tokio::spawn(async move { c.request(&mut req("GET", "/", &[]), "a.example").await.is_err() })
		};
		waiters(&pending, 1).await;
		drop(pending);
		assert!(other.await.unwrap(), "it goes to the backend itself");
		// an answer that is not kept: the others go to the backend without waiting in line
		let c = cache("{ttl: 10s}");
		let pending = c.request(&mut req("GET", "/", &[]), "a.example").await.err().unwrap();
		let other = {
			let c = c.clone();
			tokio::spawn(async move { c.request(&mut req("GET", "/", &[]), "a.example").await.err().map(|p| p.lead.is_none()) })
		};
		waiters(&pending, 1).await;
		c.response(pending, resp(200, &[("set-cookie", "a=1")], "x")).await;
		assert_eq!(other.await.unwrap(), Some(true));
	}

	#[tokio::test]
	async fn stale_on_error() {
		let c = cache("{ttl: 100ms, stale_on_error: 10s}");
		fill(&c, &mut req("GET", "/", &[]), resp(200, &[], "old")).await;
		tokio::time::sleep(Duration::from_millis(120)).await;
		let (r, o) = fill(&c, &mut req("GET", "/", &[]), resp(502, &[], "down")).await;
		assert_eq!((o, r.headers()["x-cache"].to_str().unwrap()), (Outcome::Stale, "STALE"));
		assert_eq!(text(r).await, "old");
		let (r, o) = fill(&c, &mut req("GET", "/", &[]), resp(200, &[], "new")).await;
		assert_eq!((o, text(r).await.as_str()), (Outcome::Miss, "new"));
		// without stale_on_error the error goes through
		let c = cache("{ttl: 100ms, header: ''}");
		fill(&c, &mut req("GET", "/", &[]), resp(200, &[], "old")).await;
		tokio::time::sleep(Duration::from_millis(120)).await;
		let (r, o) = fill(&c, &mut req("GET", "/", &[]), resp(503, &[], "down")).await;
		assert_eq!((o, r.status(), r.headers().contains_key("x-cache")), (Outcome::Miss, StatusCode::SERVICE_UNAVAILABLE, false));
	}

	#[tokio::test]
	async fn the_oldest_go_first() {
		let c = cache("{ttl: 10s, max_entries: 2}");
		for p in ["/1", "/2", "/3"] {
			fill(&c, &mut req("GET", p, &[]), resp(200, &[], "x")).await;
		}
		assert_eq!(c.usage().0, 2);
		assert!(c.request(&mut req("GET", "/1", &[]), "a.example").await.is_err());
		assert!(c.request(&mut req("GET", "/3", &[]), "a.example").await.is_ok());
		// by memory
		let c = cache("{ttl: 10s, max_body: 1000, max_memory: 2000}");
		for p in ["/1", "/2", "/3"] {
			fill(&c, &mut req("GET", p, &[]), resp(200, &[], Box::leak("x".repeat(900).into_boxed_str()))).await;
		}
		let (n, bytes) = c.usage();
		assert!(n < 3 && bytes <= 2000, "{n} {bytes}");
		assert!(c.request(&mut req("GET", "/3", &[]), "a.example").await.is_ok());
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
	}
}
