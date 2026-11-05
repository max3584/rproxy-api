use std::borrow::Cow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tracing_appender::non_blocking::{NonBlockingBuilder, WorkerGuard};
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
pub fn non_blocking<W: std::io::Write + Send + 'static>(writer: W) -> (tracing_appender::non_blocking::NonBlocking, WorkerGuard) {
	NonBlockingBuilder::default().buffered_lines_limit(BUFFERED_LINES).lossy(true).finish(writer)
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
pub struct Global {
	burst: f64,
	per_sec: f64,
	bucket: Mutex<Option<Bucket>>,
}

impl Global {
	const fn new(burst: f64, per_sec: f64) -> Global {
		Global { burst, per_sec, bucket: Mutex::new(None) }
	}

	fn take(&self, now: Instant) -> bool {
		let mut bucket = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
		bucket.get_or_insert_with(|| Bucket::full(self.burst, now)).take(self.burst, self.per_sec, now)
	}
}

/// TCP refusals and errors (the data plane): sources cannot be spoofed, and CrowdSec's
/// scenarios count these lines, so the bound is wide (a scan from many addresses at
/// once still shows each source's first lines).
pub static TCP: Global = Global::new(2000.0, 500.0);
/// UDP refusals and errors, whose sources may be spoofed.
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
	/// The last time it was taken from: when its key was last seen.
	at: Instant,
}

impl Bucket {
	fn full(burst: f64, now: Instant) -> Bucket {
		Bucket { tokens: burst, at: now }
	}

	fn take(&mut self, burst: f64, per_sec: f64, now: Instant) -> bool {
		self.tokens = (self.tokens + now.saturating_duration_since(self.at).as_secs_f64() * per_sec).min(burst);
		self.at = now;
		if self.tokens >= 1.0 {
			self.tokens -= 1.0;
			true
		} else {
			false
		}
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

/// What a `Throttle` counts by: IPv6 addresses by their /64 (one host usually has
/// a whole /64 to pick from), IPv4-mapped ones as IPv4.
pub trait Key: Hash + Eq + Clone {
	fn group(&self) -> Self {
		self.clone()
	}
}

impl Key for IpAddr {
	fn group(&self) -> Self {
		match crate::l7::access::canonical(*self) {
			IpAddr::V6(v6) => {
				let s = v6.segments();
				IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
			}
			v4 => v4,
		}
	}
}

/// The control API's client (`Client`: an address, `unix` or `unknown`).
impl Key for String {
	fn group(&self) -> Self {
		match self.parse::<IpAddr>() {
			Ok(ip) => ip.group().to_string(),
			Err(_) => self.clone(),
		}
	}
}

impl Key for u8 {}
impl Key for u32 {}

/// How often a `Throttle` looks for keys to forget, at most.
const SWEEP_EVERY: Duration = Duration::from_secs(1);
/// A key not seen for this long is forgotten even with lines left out; how many
/// goes into one `log.suppressed` line.
const MAX_AGE: Duration = Duration::from_secs(60);

struct Table<K> {
	keys: HashMap<K, Seen>,
	swept: Option<Instant>,
}

impl<K> Default for Table<K> {
	fn default() -> Self {
		Table { keys: HashMap::new(), swept: None }
	}
}

/// Limits log lines per key (a client's address) so that refusals under attack
/// do not flood the log: `burst` lines at once, then `per_sec`, and all keys
/// together the `Global` bound. The line that is written next says how many were
/// left out before it (`suppressed`). Keys are remembered up to `max_keys`; when
/// that is full, a new key's lines take only the global bound.
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

/// Forgotten keys that had lines left out, for one `log.suppressed` line.
#[derive(Debug, Default, PartialEq)]
struct Dropped {
	sources: u64,
	lines: u64,
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
		if dropped.sources > 0 {
			tracing::info!(
				event = "log.suppressed",
				throttle = self.label,
				sources = dropped.sources,
				suppressed = dropped.lines,
				"lines left out for sources no longer seen"
			);
		}
		out
	}

	fn check_at(&self, key: &K, now: Instant) -> (Option<u64>, Dropped) {
		let key = key.group();
		let mut dropped = Dropped::default();
		let mut table = self.seen.lock().unwrap_or_else(|e| e.into_inner());
		let table = &mut *table;
		if table.swept.is_none_or(|at| now.saturating_duration_since(at) >= SWEEP_EVERY) {
			table.swept = Some(now);
			let (burst, per_sec) = (self.burst, self.per_sec);
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
		}
		let full = table.keys.len() >= self.max_keys;
		let entry = match table.keys.get_mut(&key) {
			Some(e) => e,
			// no room to remember it: only the global bound
			None if full => {
				if self.global.take(now) {
					return (Some(0), dropped);
				}
				SUPPRESSED.fetch_add(1, Ordering::Relaxed);
				return (None, dropped);
			}
			None => table.keys.entry(key).or_insert(Seen { bucket: Bucket::full(self.burst, now), skipped: 0 }),
		};
		if !(entry.bucket.take(self.burst, self.per_sec, now) && self.global.take(now)) {
			entry.skipped += 1;
			SUPPRESSED.fetch_add(1, Ordering::Relaxed);
			return (None, dropped);
		}
		(Some(std::mem::take(&mut entry.skipped)), dropped)
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
	fn a_full_table_leaves_new_keys_to_the_global_bound() {
		let global = Box::leak(Box::new(Global::new(1.0, 0.001)));
		let t: Throttle<u32> = throttle(1, 2, global);
		let now = Instant::now();
		assert_eq!(line(&t, 1, now), Some(0));
		assert_eq!(line(&t, 2, now), None, "the global bound is shared by every key");
		// keys 1 and 2 are remembered: key 3 is not, but still has the global bound
		let global = Box::leak(Box::new(Global::new(3.0, 0.001)));
		let t: Throttle<u32> = throttle(1, 2, global);
		assert_eq!(line(&t, 1, now), Some(0));
		assert_eq!(line(&t, 2, now), Some(0));
		assert_eq!(line(&t, 3, now), Some(0), "a new source is not hidden because the table is full");
		assert_eq!(line(&t, 4, now), None, "until the global bound is used up");
		assert_eq!(t.seen.lock().unwrap().keys.len(), 2);
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
		assert_eq!(dropped, Dropped { sources: 2, lines: 4 });
		assert_eq!(t.seen.lock().unwrap().keys.len(), 1);
	}

	#[test]
	fn ipv6_sources_are_counted_by_their_64() {
		let t: Throttle<IpAddr> = throttle(1, 10, wide());
		let now = Instant::now();
		let ip = |s: &str| s.parse::<IpAddr>().unwrap();
		assert_eq!(line(&t, ip("2001:db8:1:2::1"), now), Some(0));
		assert_eq!(line(&t, ip("2001:db8:1:2:ffff::9"), now), None, "the same /64");
		assert_eq!(line(&t, ip("2001:db8:1:3::1"), now), Some(0), "another /64");
		assert_eq!(line(&t, ip("192.0.2.1"), now), Some(0));
		assert_eq!(line(&t, ip("::ffff:192.0.2.1"), now), None, "IPv4-mapped is the IPv4 address, not one /64 for all of them");
		assert_eq!(line(&t, ip("::ffff:192.0.2.2"), now), Some(0));
		assert_eq!("2001:db8::5".to_string().group(), "2001:db8::", "the control API's client");
		assert_eq!("unix".to_string().group(), "unix");
	}

	#[test]
	fn the_control_api_has_its_own_global_bound() {
		let data = Box::leak(Box::new(Global::new(1.0, 0.001)));
		let control = Box::leak(Box::new(Global::new(1.0, 0.001)));
		let (d, c): (Throttle<u32>, Throttle<u32>) = (throttle(5, 10, data), throttle(5, 10, control));
		let now = Instant::now();
		assert_eq!(line(&d, 1, now), Some(0));
		assert_eq!(line(&d, 2, now), None, "the data plane's bound is used up");
		assert_eq!(line(&c, 1, now), Some(0), "the control API's lines are not");
		assert!(!std::ptr::eq(&TCP, &CONTROL) && !std::ptr::eq(&UDP, &CONTROL));
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
