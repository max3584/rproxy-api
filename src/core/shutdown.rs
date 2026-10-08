//! Shutting down on SIGTERM (docs/DESIGN-v0.4.x.md 2.): after SIGTERM, keep
//! accepting for `RPROXY_SHUTDOWN_DELAY` while `/readyz` says `draining`, then
//! close the listeners and let connections end for up to
//! `RPROXY_SHUTDOWN_DRAIN`. Both default to zero: stop at once, as before.
//!
//! The phase is process-wide: the control API answers changes with
//! `503 shutting_down` (`control::upgrade::guard`), and UDP listeners keep
//! their sessions while draining instead of closing (`l4::udp::serve`).

use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

/// The longest `delay` and `drain` may be.
pub const MAX: Duration = Duration::from_secs(3600);

const RUNNING: u8 = 0;
const DELAY: u8 = 1;
const DRAINING: u8 = 2;

static PHASE: AtomicU8 = AtomicU8::new(RUNNING);

/// `RPROXY_SHUTDOWN_DELAY` and `RPROXY_SHUTDOWN_DRAIN`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Config {
	pub delay: Duration,
	pub drain: Duration,
}

impl Config {
	/// Reads the two values (`30s`, `2m`, seconds); None is zero.
	pub fn parse(delay: Option<&str>, drain: Option<&str>) -> Result<Config, String> {
		let one = |what: &str, v: Option<&str>| -> Result<Duration, String> {
			let Some(v) = v else { return Ok(Duration::ZERO) };
			let v = v.trim();
			// a bare number is seconds
			let d = match v.parse::<u64>() {
				Ok(secs) => Duration::from_secs(secs),
				Err(_) => crate::l7::parse_duration(v).map_err(|e| format!("{what}: {e}"))?,
			};
			if d > MAX {
				return Err(format!("{what}: {v} is out of range (at most 1h)"));
			}
			Ok(d)
		};
		Ok(Config { delay: one("--shutdown-delay", delay)?, drain: one("--shutdown-drain", drain)? })
	}

	/// Whether SIGTERM stops at once (both zero, the default).
	pub fn immediate(&self) -> bool {
		self.delay.is_zero() && self.drain.is_zero()
	}
}

/// SIGTERM came in: changes are refused from now on.
pub fn begin() {
	PHASE.store(DELAY, Ordering::Release);
}

/// The listeners are about to close.
pub fn start_drain() {
	PHASE.store(DRAINING, Ordering::Release);
}

/// Whether a graceful shutdown has begun (delay or drain).
pub fn active() -> bool {
	PHASE.load(Ordering::Acquire) != RUNNING
}

/// Whether the listeners are closing for a graceful shutdown (UDP keeps its
/// sessions but makes no new ones).
pub fn draining() -> bool {
	PHASE.load(Ordering::Acquire) == DRAINING
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn values_default_to_zero_and_are_bounded() {
		assert_eq!(Config::parse(None, None).unwrap(), Config::default());
		assert!(Config::parse(None, None).unwrap().immediate());
		let c = Config::parse(Some("5s"), Some("25s")).unwrap();
		assert_eq!((c.delay, c.drain), (Duration::from_secs(5), Duration::from_secs(25)));
		assert!(!c.immediate());
		assert!(!Config::parse(Some("0s"), Some("1")).unwrap().immediate());
		assert!(Config::parse(Some("2h"), None).unwrap_err().contains("--shutdown-delay"));
		assert!(Config::parse(None, Some("soon")).unwrap_err().contains("--shutdown-drain"));
		assert_eq!(Config::parse(Some("1h"), None).unwrap().delay, MAX);
	}
}
