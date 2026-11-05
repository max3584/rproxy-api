use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tracing_appender::non_blocking::{ErrorCounter, NonBlockingBuilder, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;

/// Writes one JSON object per line, to a daily-rotated file or to stdout.
/// Keep the returned guard alive until exit so buffered lines are flushed.
///
/// A bad level or a log directory that does not exist is a configuration
/// error. A directory that exists but cannot be written falls back to stdout;
/// the second value then says why, for the caller to log.
pub fn init(level: &str, file: Option<&Path>, keep_files: usize) -> Result<(WorkerGuard, Option<String>), String> {
	let filter = EnvFilter::try_new(level).map_err(|e| format!("invalid log level {level:?}: {e}"))?;

	let mut fallback = None;
	let (writer, guard) = match file {
		Some(path) => {
			let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
			if !dir.is_dir() {
				return Err(format!("log directory {} does not exist", dir.display()));
			}
			let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("rproxy");
			let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");
			let appender = RollingFileAppender::builder()
				.rotation(Rotation::DAILY)
				.filename_prefix(stem)
				.filename_suffix(ext)
				.max_log_files(keep_files)
				.build(dir);
			match appender {
				Ok(appender) => non_blocking(appender),
				Err(e) => {
					fallback = Some(format!("cannot write log file in {}: {e}; logging to stdout", dir.display()));
					non_blocking(std::io::stdout())
				}
			}
		}
		None => non_blocking(std::io::stdout()),
	};

	tracing_subscriber::fmt()
		.json()
		.flatten_event(true)
		.with_current_span(false)
		.with_span_list(false)
		.with_target(false)
		.with_env_filter(filter)
		.with_writer(writer)
		.try_init()
		.map_err(|e| e.to_string())?;
	Ok((guard, fallback))
}

/// A writer thread for `writer` that keeps at most `BUFFERED_LINES` waiting and
/// drops lines past that (never blocks the caller).
/// Its lines dropped count in `dropped_total`.
pub fn non_blocking<W: std::io::Write + Send + 'static>(writer: W) -> (tracing_appender::non_blocking::NonBlocking, WorkerGuard) {
	let (writer, guard) = NonBlockingBuilder::default().buffered_lines_limit(BUFFERED_LINES).lossy(true).finish(writer);
	WRITERS.lock().unwrap_or_else(|e| e.into_inner()).push(writer.error_counter());
	(writer, guard)
}

/// The drop counters of every writer opened (the main log, access log files; a few
/// per run, kept so that the total never goes back).
static WRITERS: Mutex<Vec<ErrorCounter>> = Mutex::new(Vec::new());

/// Lines dropped because the writer thread fell behind (`rproxy_log_dropped_total`).
pub fn dropped_total() -> u64 {
	WRITERS.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|c| c.dropped_lines() as u64).sum()
}

/// Lines a `Throttle` left out, in total (`rproxy_log_suppressed_total`).
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Lines waiting for the writer thread at most; past that, lines are dropped rather
/// than holding up the data plane (tracing-appender's default is 128,000, which with
/// long lines is hundreds of MB; #357).
pub const BUFFERED_LINES: usize = 8192;

/// Attacker-controlled text (a path, a query, a User-Agent, a Host, an SNI) is cut
/// to this many bytes in log lines (#357), with `TRUNCATED` after it.
pub const MAX_FIELD: usize = 2048;
pub const TRUNCATED: &str = "...[truncated]";

/// `text` cut to `MAX_FIELD` bytes (at a character boundary) with `TRUNCATED` after
/// it; as it is when shorter.
pub fn clip(text: &str) -> Cow<'_, str> {
	clip_to(text, MAX_FIELD)
}

fn clip_to(text: &str, max: usize) -> Cow<'_, str> {
	if text.len() <= max {
		return Cow::Borrowed(text);
	}
	let mut end = max;
	while !text.is_char_boundary(end) {
		end -= 1;
	}
	Cow::Owned(format!("{}{TRUNCATED}", &text[..end]))
}

/// Cuts `text` in place as `clip` does.
pub fn clip_in_place(text: &mut String) {
	if let Cow::Owned(cut) = clip(text) {
		*text = cut;
	}
}

/// A bound on the lines of a whole class of throttles together, so that many
/// sources at once (spoofed UDP sources, a botnet) cannot flood the log either.
/// Sources a throttle does not remember yet take from a share of their own (a
/// quarter of the bound, on top of it): busy known sources cannot starve the
/// first lines of new ones, nor a flood of new (spoofed) ones the known.
pub struct Global {
	burst: f64,
	per_sec: f64,
	known: Mutex<Option<Bucket>>,
	fresh: Mutex<Option<Bucket>>,
}

/// The share of a `Global` for sources not remembered yet, as a part of it.
const FRESH_SHARE: f64 = 0.25;

impl Global {
	const fn new(burst: f64, per_sec: f64) -> Global {
		Global { burst, per_sec, known: Mutex::new(None), fresh: Mutex::new(None) }
	}

	fn take(&self, fresh: bool, now: Instant) -> bool {
		let (slot, burst, per_sec) = match fresh {
			true => (&self.fresh, (self.burst * FRESH_SHARE).max(1.0), self.per_sec * FRESH_SHARE),
			false => (&self.known, self.burst, self.per_sec),
		};
		let mut bucket = slot.lock().unwrap_or_else(|e| e.into_inner());
		bucket.get_or_insert_with(|| Bucket::full(burst, now)).take(burst, per_sec, now)
	}
}

/// TCP refusals and errors (the data plane): sources cannot be spoofed, and CrowdSec's
/// scenarios count these lines, so the bound is wide (a scan from many addresses at
/// once still shows each source's first lines).
pub static TCP: Global = Global::new(2000.0, 500.0);
/// UDP (and QUIC) refusals and errors, whose sources may be spoofed.
pub static UDP: Global = Global::new(200.0, 50.0);
/// The control API's `audit` refusals: a flood on the data plane does not hide
/// them, nor they the data plane's lines.
pub static CONTROL: Global = Global::new(200.0, 50.0);

/// Lines left out by throttles since the start.
pub fn suppressed_total() -> u64 {
	SUPPRESSED.load(Ordering::Relaxed)
}

/// A token bucket of log lines.
#[derive(Clone, Copy, Debug)]
struct Bucket {
	tokens: f64,
	/// The last time it was looked at: when its key was last seen.
	at: Instant,
}

impl Bucket {
	fn full(burst: f64, now: Instant) -> Bucket {
		Bucket { tokens: burst, at: now }
	}

	/// Fills it up to `now`; whether it has a line to give (not taken yet: `spend`).
	fn ready(&mut self, burst: f64, per_sec: f64, now: Instant) -> bool {
		self.tokens = (self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * per_sec).min(burst);
		self.at = now;
		self.tokens >= 1.0
	}

	fn spend(&mut self) {
		self.tokens -= 1.0;
	}

	fn take(&mut self, burst: f64, per_sec: f64, now: Instant) -> bool {
		let ready = self.ready(burst, per_sec, now);
		if ready {
			self.spend();
		}
		ready
	}

	/// Whether it has filled up again (nothing to remember).
	fn idle(&self, burst: f64, per_sec: f64, now: Instant) -> bool {
		self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * per_sec >= burst
	}
}

struct Seen {
	bucket: Bucket,
	/// Lines left out for this key since the last one written.
	skipped: u64,
}

/// What a `Throttle` counts by. IPv6 addresses count each on its own (as CrowdSec
/// groups them, by IP) and together with the rest of their /64 (one host usually
/// has a whole /64 to pick from); IPv4-mapped ones count as IPv4.
pub trait Key: Hash + Eq + Clone {
	/// The form it is counted in.
	fn canonical(&self) -> Self {
		self.clone()
	}

	/// The wider group it also counts against (an IPv6 address's /64), if any.
	fn group(&self) -> Option<Self> {
		None
	}
}

impl Key for IpAddr {
	fn canonical(&self) -> Self {
		crate::l7::access::canonical(*self)
	}

	fn group(&self) -> Option<Self> {
		match self {
			IpAddr::V6(v6) => {
				let s = v6.segments();
				Some(IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0)))
			}
			IpAddr::V4(_) => None,
		}
	}
}

/// The control API's client (`Client`: an address, `unix` or `unknown`).
impl Key for String {
	fn canonical(&self) -> Self {
		match self.parse::<IpAddr>() {
			Ok(ip) => ip.canonical().to_string(),
			Err(_) => self.clone(),
		}
	}

	fn group(&self) -> Option<Self> {
		self.parse::<IpAddr>().ok().and_then(|ip| ip.group()).map(|g| g.to_string())
	}
}

impl Key for u8 {}
impl Key for u32 {}

/// How often a `Throttle` looks for keys to forget, at most.
const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// A key not seen for this long is forgotten even with lines left out; how many
/// goes into one `log.suppressed` line.
const MAX_AGE: Duration = Duration::from_secs(60);
/// A group (an IPv6 /64) takes this many times a single key's lines.
const GROUP_FACTOR: f64 = 5.0;

struct Table<K> {
	keys: HashMap<K, Seen>,
	/// The groups' buckets (`Key::group`), up to `max_keys` too.
	groups: HashMap<K, Bucket>,
	swept: Option<Instant>,
	/// Lines of keys left out while the table was full, since the last sweep.
	overflow: u64,
}

impl<K> Default for Table<K> {
	fn default() -> Self {
		Table { keys: HashMap::new(), groups: HashMap::new(), swept: None, overflow: 0 }
	}
}

/// Limits log lines per key (a client's address) so that refusals under attack
/// do not flood the log: `burst` lines at once, then `per_sec`, an IPv6 /64
/// `GROUP_FACTOR` times that, and all keys together the `Global` bound. The line
/// that is written next says how many were left out before it (`suppressed`).
/// Keys are remembered up to `max_keys` (a few hundred KB at most); when that is
/// full, a new key's lines take only the global bound's share for new sources.
pub struct Throttle<K> {
	burst: f64,
	per_sec: f64,
	max_keys: usize,
	global: &'static Global,
	/// Names it in `log.suppressed` lines.
	label: &'static str,
	seen: Mutex<Table<K>>,
}

impl<K: Key> Default for Throttle<K> {
	/// 20 lines at once per key, then one a second; under `TCP`.
	fn default() -> Self {
		Throttle::new(20, 1.0, 4096)
	}
}

/// What one sweep let go of, for one `log.suppressed` line: keys forgotten with
/// lines left out, and the lines of keys there was no room to remember.
#[derive(Debug, Default, PartialEq)]
struct Dropped {
	sources: u64,
	lines: u64,
	overflow: u64,
}

impl<K: Key> Throttle<K> {
	pub fn new(burst: u32, per_sec: f64, max_keys: usize) -> Self {
		Throttle { burst: f64::from(burst.max(1)), per_sec, max_keys: max_keys.max(1), global: &TCP, label: "tcp", seen: Mutex::default() }
	}

	/// The default for a rule's refusals: UDP ones under `UDP`, TCP ones under `TCP`.
	pub fn for_protocol(protocol: crate::core::rule::Protocol) -> Self {
		match protocol {
			crate::core::rule::Protocol::Udp => Throttle::default().under(&UDP, "udp"),
			_ => Throttle::default(),
		}
	}

	/// The same under another global bound, named `label` in `log.suppressed`.
	pub fn under(mut self, global: &'static Global, label: &'static str) -> Self {
		self.global = global;
		self.label = label;
		self
	}

	/// `Some(n)`: write the line, `n` lines of this key were left out before it.
	/// `None`: leave it out (counted).
	pub fn check(&self, key: &K) -> Option<u64> {
		let (out, dropped) = self.check_at(key, Instant::now());
		if dropped != Dropped::default() {
			tracing::info!(
				event = "log.suppressed",
				throttle = self.label,
				sources = dropped.sources,
				suppressed = dropped.lines,
				overflow = dropped.overflow,
				"lines left out for sources no longer seen, or not remembered"
			);
		}
		out
	}

	fn check_at(&self, key: &K, now: Instant) -> (Option<u64>, Dropped) {
		let key = key.canonical();
		let group = key.group();
		let (burst, per_sec) = (self.burst, self.per_sec);
		let (group_burst, group_per_sec) = (burst * GROUP_FACTOR, per_sec * GROUP_FACTOR);
		let mut dropped = Dropped::default();
		let mut table = self.seen.lock().unwrap_or_else(|e| e.into_inner());
		let table = &mut *table;
		if table.swept.is_none_or(|at| now.saturating_duration_since(at) >= SWEEP_EVERY) {
			table.swept = Some(now);
			table.keys.retain(|_, s| {
				if s.skipped == 0 {
					return !s.bucket.idle(burst, per_sec, now);
				}
				if now.saturating_duration_since(s.bucket.at) < MAX_AGE {
					return true;
				}
				dropped.sources += 1;
				dropped.lines += s.skipped;
				false
			});
			table.groups.retain(|_, b| !b.idle(group_burst, group_per_sec, now));
			dropped.overflow = std::mem::take(&mut table.overflow);
		}
		// the group's own bound, while there is room to remember it
		if let Some(g) = &group {
			if !table.groups.contains_key(g) && table.groups.len() < self.max_keys {
				table.groups.insert(g.clone(), Bucket::full(group_burst, now));
			}
		}
		let group_ready = match &group {
			Some(g) => table.groups.get_mut(g).is_none_or(|b| b.ready(group_burst, group_per_sec, now)),
			None => true,
		};
		let known = table.keys.contains_key(&key);
		let written = if !known && table.keys.len() >= self.max_keys {
			// no room to remember it: only the global bound's share for new sources
			if group_ready && self.global.take(true, now) {
				Some(0)
			} else {
				table.overflow += 1;
				None
			}
		} else {
			let entry = table.keys.entry(key).or_insert(Seen { bucket: Bucket::full(burst, now), skipped: 0 });
			// the global bound is asked last, and the key's line is taken only when it is written
			if entry.bucket.ready(burst, per_sec, now) && group_ready && self.global.take(!known, now) {
				entry.bucket.spend();
				Some(std::mem::take(&mut entry.skipped))
			} else {
				entry.skipped += 1;
				None
			}
		};
		match written {
			Some(_) => {
				if let Some(b) = group.as_ref().and_then(|g| table.groups.get_mut(g)) {
					b.spend();
				}
			}
			None => {
				SUPPRESSED.fetch_add(1, Ordering::Relaxed);
			}
		}
		(written, dropped)
	}
}

/// Lines at most `once` apart, with how many were left out (`accept.error` of one
/// listener, #357).
pub struct Every {
	once: Duration,
	last: Option<Instant>,
	skipped: u64,
}

impl Every {
	pub fn new(once: Duration) -> Every {
		Every { once, last: None, skipped: 0 }
	}

	/// `Some(n)`: write the line, `n` were left out since the last one.
	pub fn check(&mut self) -> Option<u64> {
		self.check_at(Instant::now())
	}

	fn check_at(&mut self, now: Instant) -> Option<u64> {
		if self.last.is_some_and(|at| now.saturating_duration_since(at) < self.once) {
			self.skipped += 1;
			SUPPRESSED.fetch_add(1, Ordering::Relaxed);
			return None;
		}
		self.last = Some(now);
		Some(std::mem::take(&mut self.skipped))
	}
}

/// `conn.error` / `tls.error` lines of TCP rules, by client.
pub fn tcp_errors() -> &'static Throttle<IpAddr> {
	static T: LazyLock<Throttle<IpAddr>> = LazyLock::new(Throttle::default);
	&T
}

/// `conn.error` / `tls.error` lines of UDP rules, by client.
pub fn udp_errors() -> &'static Throttle<IpAddr> {
	static T: LazyLock<Throttle<IpAddr>> = LazyLock::new(|| Throttle::default().under(&UDP, "udp"));
	&T
}

/// `conn.denied` lines of HTTP/3 (QUIC), by client: under `UDP`, since the source of
/// a QUIC Initial may be spoofed (the rule is a TCP one, whose own `denied_log` is
/// under `TCP`).
pub fn quic_denied() -> &'static Throttle<IpAddr> {
	static T: LazyLock<Throttle<IpAddr>> = LazyLock::new(|| Throttle::default().under(&UDP, "quic"));
	&T
}

/// A log line through a `Throttle`: `throttled!(throttle, key, warn, event = "...", ...)`
/// writes it at that level with `suppressed`, or at `debug` with `throttled = true`
/// when it is left out. The event and its fields stay as they are.
macro_rules! throttled {
	($throttle:expr, $key:expr, $level:ident, $($field:tt)*) => {
		match $throttle.check(&$key) {
			Some(suppressed) => tracing::$level!(suppressed, $($field)*),
			None => tracing::debug!(throttled = true, $($field)*),
		}
	};
}
pub(crate) use throttled;

#[cfg(test)]
mod tests {
	use super::*;

	/// A throttle under a global bound of its own, so that tests do not share one.
	fn throttle<K: Key>(burst: u32, max_keys: usize, global: &'static Global) -> Throttle<K> {
		Throttle::new(burst, 1.0, max_keys).under(global, "test")
	}

	fn wide() -> &'static Global {
		Box::leak(Box::new(Global::new(1e9, 1e9)))
	}

	fn line<K: Key>(t: &Throttle<K>, key: K, at: Instant) -> Option<u64> {
		t.check_at(&key, at).0
	}

	#[test]
	fn a_burst_then_one_a_second_with_the_count_of_lines_left_out() {
		let t: Throttle<u8> = throttle(3, 10, wide());
		let now = Instant::now();
		let lines: Vec<Option<u64>> = (0..5).map(|_| line(&t, 1, now)).collect();
		assert_eq!(lines, [Some(0), Some(0), Some(0), None, None]);
		assert_eq!(line(&t, 2, now), Some(0), "another key has its own lines");
		assert_eq!(line(&t, 1, now + Duration::from_millis(1100)), Some(2), "the next line says how many were left out");
		assert_eq!(line(&t, 1, now + Duration::from_millis(1200)), None);
	}

	#[test]
	fn a_full_table_leaves_new_keys_to_the_share_for_new_sources() {
		// fresh share: a quarter of 8, 2 lines
		let global = Box::leak(Box::new(Global::new(8.0, 0.001)));
		let t: Throttle<u32> = throttle(5, 2, global);
		let now = Instant::now();
		assert_eq!(line(&t, 1, now), Some(0));
		assert_eq!(line(&t, 2, now), Some(0));
		assert_eq!(t.seen.lock().unwrap().keys.len(), 2);
		assert_eq!(line(&t, 3, now), None, "the share for new sources is used up by 1 and 2");
		assert_eq!(line(&t, 1, now), Some(0), "known sources still have the rest of the bound");
		// the lines of keys not remembered are counted for the summary
		assert_eq!(line(&t, 4, now), None);
		let (_, dropped) = t.check_at(&1, now + Duration::from_millis(1500));
		assert_eq!(dropped.overflow, 2, "{dropped:?}");
	}

	#[test]
	fn a_flood_of_new_sources_does_not_starve_known_ones_nor_the_reverse() {
		let global = Box::leak(Box::new(Global::new(8.0, 0.001)));
		let t: Throttle<u32> = throttle(100, 1000, global);
		let now = Instant::now();
		// key 1 uses up the known share (its first line is from the fresh one)
		let written = (0..20).filter(|_| line(&t, 1, now).is_some()).count();
		assert_eq!(written, 9, "1 fresh + 8 known");
		assert_eq!(line(&t, 2, now), Some(0), "a new source's first line still passes");
	}

	#[test]
	fn a_line_left_out_by_the_global_bound_does_not_use_up_the_key() {
		let global = Box::leak(Box::new(Global::new(4.0, 0.0)));
		let t: Throttle<u32> = throttle(10, 10, global);
		let now = Instant::now();
		let written = (0..8).filter(|_| line(&t, 1, now).is_some()).count();
		assert_eq!(written, 5, "1 fresh + 4 known");
		let tokens = t.seen.lock().unwrap().keys[&1].bucket.tokens;
		assert_eq!(tokens, 5.0, "only the lines written were taken from the key");
	}

	#[test]
	fn the_table_is_swept_at_most_once_a_second() {
		let t: Throttle<u32> = throttle(1, 100, wide());
		let now = Instant::now();
		let at = |ms| now + Duration::from_millis(ms);
		let len = || t.seen.lock().unwrap().keys.len();
		assert_eq!(line(&t, 1, at(0)), Some(0));
		assert_eq!(line(&t, 2, at(500)), Some(0));
		assert_eq!(line(&t, 3, at(1000)), Some(0));
		assert_eq!(len(), 2, "swept at 1 s: key 1 had calmed down (with no lines left out) and is forgotten");
		assert_eq!(line(&t, 4, at(1600)), Some(0));
		assert_eq!(len(), 3, "key 2 has calmed down at 1.5 s, but the table is not swept again before 2 s");
		assert_eq!(line(&t, 5, at(2100)), Some(0));
		assert_eq!(len(), 2, "keys 2 and 3 are forgotten at 2.1 s; 4 is still busy");
	}

	#[test]
	fn old_keys_are_forgotten_with_their_lines_left_out_in_one_summary() {
		let t: Throttle<u32> = throttle(1, 10, wide());
		let now = Instant::now();
		for key in [1, 2] {
			assert_eq!(line(&t, key, now), Some(0));
			assert_eq!(line(&t, key, now), None);
			assert_eq!(line(&t, key, now), None);
		}
		let (_, dropped) = t.check_at(&3, now + Duration::from_secs(30));
		assert_eq!(dropped, Dropped::default(), "kept while recent, so that the next line can say how many");
		let (out, dropped) = t.check_at(&3, now + Duration::from_secs(61));
		assert_eq!(out, Some(0));
		assert_eq!(dropped, Dropped { sources: 2, lines: 4, overflow: 0 });
		assert_eq!(t.seen.lock().unwrap().keys.len(), 1);
	}

	#[test]
	fn ipv6_sources_count_by_address_and_together_by_their_64() {
		let t: Throttle<IpAddr> = throttle(1, 100, wide());
		let now = Instant::now();
		let ip = |s: &str| s.parse::<IpAddr>().unwrap();
		assert_eq!(line(&t, ip("2001:db8:1:2::1"), now), Some(0));
		assert_eq!(line(&t, ip("2001:db8:1:2::1"), now), None);
		// each address its own lines (as CrowdSec groups by IP), the /64 five times one's
		let others: Vec<Option<u64>> = (2..=6).map(|i| line(&t, ip(&format!("2001:db8:1:2::{i}")), now)).collect();
		assert_eq!(others, [Some(0), Some(0), Some(0), Some(0), None], "the /64 has 5 lines at once");
		assert_eq!(line(&t, ip("2001:db8:1:3::1"), now), Some(0), "another /64");
		assert_eq!(line(&t, ip("192.0.2.1"), now), Some(0));
		assert_eq!(line(&t, ip("::ffff:192.0.2.1"), now), None, "IPv4-mapped is the IPv4 address, not one /64 for all of them");
		assert_eq!(line(&t, ip("::ffff:192.0.2.2"), now), Some(0));
		assert_eq!("::ffff:192.0.2.9".to_string().canonical(), "192.0.2.9", "the control API's client");
		assert_eq!("2001:db8::5".to_string().group().as_deref(), Some("2001:db8::"));
		assert_eq!("unix".to_string().group(), None);
	}

	#[test]
	fn the_control_api_and_http3_have_their_own_global_bounds() {
		let data = Box::leak(Box::new(Global::new(4.0, 0.001)));
		let control = Box::leak(Box::new(Global::new(4.0, 0.001)));
		let (d, c): (Throttle<u32>, Throttle<u32>) = (throttle(5, 10, data), throttle(5, 10, control));
		let now = Instant::now();
		assert_eq!(line(&d, 1, now), Some(0));
		assert_eq!(line(&d, 2, now), None, "the data plane's share for new sources is used up");
		assert_eq!(line(&c, 1, now), Some(0), "the control API's lines are not");
		assert!(!std::ptr::eq(&TCP, &CONTROL) && !std::ptr::eq(&UDP, &CONTROL));
		// HTTP/3 (spoofable QUIC Initials) is under UDP, not the TCP rule's bound
		assert!(std::ptr::eq(quic_denied().global, &UDP));
		assert!(std::ptr::eq(udp_errors().global, &UDP) && std::ptr::eq(tcp_errors().global, &TCP));
		assert!(std::ptr::eq(Throttle::<IpAddr>::for_protocol(crate::core::rule::Protocol::Udp).global, &UDP));
		assert!(std::ptr::eq(Throttle::<IpAddr>::for_protocol(crate::core::rule::Protocol::Tcp).global, &TCP));
	}

	#[test]
	fn every_writes_a_line_at_most_once_an_interval() {
		let mut e = Every::new(Duration::from_secs(1));
		let now = Instant::now();
		assert_eq!(e.check_at(now), Some(0));
		assert_eq!(e.check_at(now + Duration::from_millis(100)), None);
		assert_eq!(e.check_at(now + Duration::from_millis(200)), None);
		assert_eq!(e.check_at(now + Duration::from_millis(1100)), Some(2));
	}

	#[test]
	fn long_text_is_cut_with_a_marker() {
		assert_eq!(clip("/short"), "/short");
		let long = "a".repeat(MAX_FIELD + 10);
		let cut = clip(&long);
		assert_eq!(cut.len(), MAX_FIELD + TRUNCATED.len());
		assert!(cut.ends_with(TRUNCATED));
		// at a character boundary
		assert_eq!(clip_to("aあい", 2), format!("a{TRUNCATED}"));
		assert_eq!(clip_to("aあい", 4), format!("aあ{TRUNCATED}"));
		let mut s = long.clone();
		clip_in_place(&mut s);
		assert_eq!(s, cut);
	}

	#[test]
	fn the_macro_keeps_the_fields_and_a_message() {
		let t: Throttle<IpAddr> = throttle(1, 10, wide());
		let ip: IpAddr = "192.0.2.1".parse().unwrap();
		throttled!(t, ip, warn, event = "conn.error", client = %ip, error = "x", "reading the ClientHello");
		throttled!(t, ip, info, event = "conn.denied", client = %ip, reason = "allow_from");
		assert_eq!(t.seen.lock().unwrap().keys[&ip].skipped, 1);
	}
}
