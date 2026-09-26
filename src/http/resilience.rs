//! Limits and fault tolerance (#64): `buffering` (request bodies read up front,
//! with a size limit), `retry` (again on another server when the backend could
//! not be reached) and `circuit_breaker` (503 for a while when too many
//! responses fail).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::header::{self, HeaderMap};
use hyper::Method;
use tracing::{info, warn};

use super::server::Body;

/// A breaker judges only once the window holds this many responses.
pub const MIN_REQUESTS: usize = 10;

/// Default first wait of `retry`; it doubles with each attempt.
pub const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Reads a request body of at most `max` bytes. `Err(true)` when it is larger,
/// `Err(false)` when the client's body broke off.
pub async fn buffer(headers: &HeaderMap, body: Body, max: u64) -> Result<Bytes, bool> {
	let declared = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
	if declared.is_some_and(|n| n > max) {
		return Err(true);
	}
	match Limited::new(body, usize::try_from(max).unwrap_or(usize::MAX)).collect().await {
		Ok(c) => Ok(c.to_bytes()),
		Err(e) => Err(e.is::<http_body_util::LengthLimitError>()),
	}
}

/// Methods that may be sent again (RFC 9110 9.2.2).
pub fn idempotent(method: &Method) -> bool {
	matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS | Method::PUT | Method::DELETE | Method::TRACE)
}

#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
	/// Attempts in all, the first one included.
	pub attempts: u32,
	pub interval: Duration,
}

impl RetryPolicy {
	/// The wait before attempt `n` (2, 3, ...).
	pub fn wait(&self, n: u32) -> Duration {
		self.interval.saturating_mul(1u32 << n.saturating_sub(2).min(16))
	}
}

#[derive(Debug, PartialEq, Eq)]
enum Phase {
	Closed,
	Open { until: Instant },
	/// One request goes through to see whether the backend has recovered.
	HalfOpen,
}

#[derive(Debug)]
struct State {
	phase: Phase,
	/// (time, failed) of recent responses.
	samples: VecDeque<(Instant, bool)>,
}

#[derive(Debug)]
pub struct Breaker {
	pub name: String,
	/// Failed responses (5xx) out of all, 0-1, that open the breaker.
	ratio: f64,
	window: Duration,
	recovery: Duration,
	state: Mutex<State>,
}

/// Admission of one request through a breaker; tells the breaker how it went.
#[derive(Debug)]
pub struct Ticket {
	breaker: Arc<Breaker>,
	probe: bool,
	done: bool,
}

impl Ticket {
	pub fn record(mut self, failed: bool) {
		self.done = true;
		self.breaker.record_at(self.probe, failed, Instant::now());
	}
}

impl Drop for Ticket {
	fn drop(&mut self) {
		// a probe whose client went away proves nothing: stay open for another round
		if !self.done && self.probe {
			self.breaker.record_at(true, true, Instant::now());
		}
	}
}

impl Breaker {
	pub fn new(name: &str, failure_percent: u8, window: Duration, recovery: Duration) -> Arc<Breaker> {
		Arc::new(Breaker {
			name: name.to_string(),
			ratio: f64::from(failure_percent.clamp(1, 100)) / 100.0,
			window: window.max(Duration::from_millis(1)),
			recovery,
			state: Mutex::new(State { phase: Phase::Closed, samples: VecDeque::new() }),
		})
	}

	/// `None` refuses the request (the breaker is open).
	pub fn admit(self: &Arc<Self>) -> Option<Ticket> {
		self.admit_at(Instant::now())
	}

	fn admit_at(self: &Arc<Self>, now: Instant) -> Option<Ticket> {
		let mut s = self.state.lock().unwrap();
		let probe = match s.phase {
			Phase::Closed => false,
			Phase::Open { until } if now >= until => {
				s.phase = Phase::HalfOpen;
				true
			}
			Phase::Open { .. } | Phase::HalfOpen => return None,
		};
		Some(Ticket { breaker: self.clone(), probe, done: false })
	}

	fn record_at(&self, probe: bool, failed: bool, now: Instant) {
		let mut s = self.state.lock().unwrap();
		if probe {
			s.samples.clear();
			if failed {
				s.phase = Phase::Open { until: now + self.recovery };
			} else {
				s.phase = Phase::Closed;
				info!(event = "http.breaker", middleware = %self.name, state = "closed");
			}
			return;
		}
		if s.phase != Phase::Closed {
			return;
		}
		s.samples.push_back((now, failed));
		while s.samples.front().is_some_and(|(t, _)| now.duration_since(*t) > self.window) {
			s.samples.pop_front();
		}
		let total = s.samples.len();
		let failures = s.samples.iter().filter(|(_, f)| *f).count();
		if total >= MIN_REQUESTS && failures as f64 >= self.ratio * total as f64 {
			s.phase = Phase::Open { until: now + self.recovery };
			s.samples.clear();
			warn!(event = "http.breaker", middleware = %self.name, state = "open", failures, requests = total,
				recovery_ms = self.recovery.as_millis() as u64);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn opens_on_the_failure_ratio_and_recovers_through_one_probe() {
		let b = Breaker::new("cb", 50, Duration::from_secs(10), Duration::from_secs(5));
		let t0 = Instant::now();
		// 9 responses are too few to judge, even all failed
		for _ in 0..9 {
			b.admit_at(t0).unwrap();
			b.record_at(false, true, t0);
		}
		assert!(b.admit_at(t0).is_some());
		b.record_at(false, true, t0);
		assert!(b.admit_at(t0).is_none(), "10 failures of 10: open");
		assert!(b.admit_at(t0 + Duration::from_secs(4)).is_none());

		// after `recovery`, one probe; the others still wait
		let probe = b.admit_at(t0 + Duration::from_secs(5)).unwrap();
		assert!(probe.probe);
		assert!(b.admit_at(t0 + Duration::from_secs(5)).is_none());
		b.record_at(true, true, t0 + Duration::from_secs(5));
		std::mem::forget(probe);
		assert!(b.admit_at(t0 + Duration::from_secs(9)).is_none(), "the probe failed: open again");
		let probe = b.admit_at(t0 + Duration::from_secs(10)).unwrap();
		probe.record(false);
		assert!(b.admit_at(t0 + Duration::from_secs(10)).is_some_and(|t| !t.probe), "closed");
	}

	#[test]
	fn old_responses_leave_the_window() {
		let b = Breaker::new("cb", 50, Duration::from_secs(10), Duration::from_secs(5));
		let t0 = Instant::now();
		for _ in 0..10 {
			b.record_at(false, true, t0);
		}
		// open now; start over with a fresh breaker to look at the window
		let b = Breaker::new("cb", 50, Duration::from_secs(10), Duration::from_secs(5));
		for _ in 0..6 {
			b.record_at(false, true, t0);
		}
		for _ in 0..10 {
			b.record_at(false, false, t0 + Duration::from_secs(11));
		}
		assert!(b.admit_at(t0 + Duration::from_secs(11)).is_some(), "the failures are older than the window");
		let _ = b;
	}

	#[test]
	fn a_dropped_probe_keeps_the_breaker_open() {
		let b = Breaker::new("cb", 10, Duration::from_secs(10), Duration::from_millis(0));
		let t0 = Instant::now();
		for _ in 0..10 {
			b.record_at(false, true, t0);
		}
		drop(b.admit().unwrap());
		assert!(matches!(b.state.lock().unwrap().phase, Phase::Open { .. }));
	}

	#[test]
	fn retry_waits_double() {
		let p = RetryPolicy { attempts: 4, interval: Duration::from_millis(100) };
		assert_eq!([p.wait(2), p.wait(3), p.wait(4)], [100, 200, 400].map(Duration::from_millis));
		assert!(idempotent(&Method::PUT) && !idempotent(&Method::POST));
	}
}
