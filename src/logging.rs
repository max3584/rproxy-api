use std::collections::HashMap;
use std::hash::Hash;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use tracing_appender::non_blocking::WorkerGuard;
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
				Ok(appender) => tracing_appender::non_blocking(appender),
				Err(e) => {
					fallback = Some(format!("cannot write log file in {}: {e}; logging to stdout", dir.display()));
					tracing_appender::non_blocking(std::io::stdout())
				}
			}
		}
		None => tracing_appender::non_blocking(std::io::stdout()),
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

/// Lines a `Throttle` left out, in total (`rproxy_log_suppressed_total`).
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Every throttled line also takes a place here, so that many sources at once
/// (spoofed UDP sources) cannot flood the log either.
static ALL: Mutex<Option<Bucket>> = Mutex::new(None);
const ALL_BURST: f64 = 200.0;
const ALL_PER_SEC: f64 = 50.0;

/// Lines left out by throttles since the start.
pub fn suppressed_total() -> u64 {
	SUPPRESSED.load(Ordering::Relaxed)
}

/// A token bucket of log lines.
#[derive(Clone, Copy, Debug)]
struct Bucket {
	tokens: f64,
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

/// Limits log lines per key (a client's address) so that refusals under attack
/// do not flood the log: `burst` lines at once, then `per_sec`. The line that is
/// written next says how many were left out before it (`suppressed`).
pub struct Throttle<K> {
	burst: f64,
	per_sec: f64,
	/// Keys remembered at most; when full, keys that have calmed down are forgotten.
	max_keys: usize,
	seen: Mutex<HashMap<K, Seen>>,
}

impl<K: Hash + Eq + Clone> Default for Throttle<K> {
	/// 20 lines at once per key, then one a second.
	fn default() -> Self {
		Throttle::new(20, 1.0, 4096)
	}
}

impl<K: Hash + Eq + Clone> Throttle<K> {
	pub fn new(burst: u32, per_sec: f64, max_keys: usize) -> Self {
		Throttle { burst: f64::from(burst.max(1)), per_sec, max_keys: max_keys.max(1), seen: Mutex::default() }
	}

	/// `Some(n)`: write the line, `n` lines of this key were left out before it.
	/// `None`: leave it out (counted).
	pub fn check(&self, key: &K) -> Option<u64> {
		self.check_at(key, Instant::now())
	}

	fn check_at(&self, key: &K, now: Instant) -> Option<u64> {
		let mut seen = self.seen.lock().unwrap();
		if !seen.contains_key(key) && seen.len() >= self.max_keys {
			let (burst, per_sec) = (self.burst, self.per_sec);
			seen.retain(|_, s| s.skipped > 0 || !s.bucket.idle(burst, per_sec, now));
		}
		let full = seen.len() >= self.max_keys;
		let entry = match seen.get_mut(key) {
			Some(e) => e,
			None if full => {
				SUPPRESSED.fetch_add(1, Ordering::Relaxed);
				return None;
			}
			None => seen.entry(key.clone()).or_insert(Seen { bucket: Bucket::full(self.burst, now), skipped: 0 }),
		};
		let allowed = entry.bucket.take(self.burst, self.per_sec, now) && {
			let mut all = ALL.lock().unwrap();
			all.get_or_insert_with(|| Bucket::full(ALL_BURST, now)).take(ALL_BURST, ALL_PER_SEC, now)
		};
		if !allowed {
			entry.skipped += 1;
			SUPPRESSED.fetch_add(1, Ordering::Relaxed);
			return None;
		}
		Some(std::mem::take(&mut entry.skipped))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::Duration;

	#[test]
	fn a_burst_then_one_a_second_with_the_count_of_lines_left_out() {
		let t: Throttle<u8> = Throttle::new(3, 1.0, 10);
		let now = Instant::now();
		let lines: Vec<Option<u64>> = (0..5).map(|_| t.check_at(&1, now)).collect();
		assert_eq!(lines, [Some(0), Some(0), Some(0), None, None]);
		assert_eq!(t.check_at(&2, now), Some(0), "another key has its own lines");
		assert_eq!(t.check_at(&1, now + Duration::from_millis(1100)), Some(2), "the next line says how many were left out");
		assert_eq!(t.check_at(&1, now + Duration::from_millis(1200)), None);
	}

	#[test]
	fn keys_are_bounded() {
		let t: Throttle<u32> = Throttle::new(1, 1.0, 2);
		let now = Instant::now();
		assert_eq!(t.check_at(&1, now), Some(0));
		assert_eq!(t.check_at(&2, now), Some(0));
		assert_eq!(t.check_at(&3, now), None, "full of keys that are still busy");
		// once the others have calmed down, they are forgotten
		assert_eq!(t.check_at(&3, now + Duration::from_secs(5)), Some(0));
	}
}
