//! Passive health checks / outlier detection (#170, docs/DESIGN-v0.4.md 9.):
//! targets that keep failing in real traffic are ejected for a while. L4 is a
//! rule's `outlier_detection`; L7 is `http.services.<name>.outlier_detection`.
//!
//! Without the setting, L4 keeps skipping a target for `balance::FAIL_COOLDOWN`
//! after one failed connection (the defaults below); `http` services eject
//! only with the setting. An ejected target or server is skipped by the
//! balancing like one that is down (L4 still tries it when every target is
//! out, as before), and comes back by itself at the end of the ejection
//! (`target.up`, `reason: outlier`).

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

const MAX_CONSECUTIVE: u32 = 1000;

/// `outlier_detection` of an L4 rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct L4OutlierSpec {
	/// Connection failures in a row (default 1).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub consecutive_failures: Option<u32>,
	/// Connections the backend closes sooner than this count as failures (default 0s: not counted).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub short_lived: Option<String>,
	/// The first ejection (default 10s, `FAIL_COOLDOWN`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ejection_time: Option<String>,
	/// Doubled on each ejection up to this (default `ejection_time`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_ejection_time: Option<String>,
	/// Share of the targets that may be ejected at once (default 100).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_ejected_percent: Option<u8>,
}

/// `outlier_detection` of an `http` service.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpOutlierSpec {
	/// 5xx answers in a row (0: ignored; default 5).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub consecutive_5xx: Option<u32>,
	/// 502 / 503 / 504, connection failures and timeouts in a row (0: ignored; default 3).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub consecutive_gateway_failures: Option<u32>,
	/// Share of failures within `window` (1-100; left out: ignored).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub failure_percent: Option<u8>,
	/// Fewest requests in `window` before `failure_percent` counts (default 20).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub min_requests: Option<u32>,
	/// Default 30s.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub window: Option<String>,
	/// Default 30s.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ejection_time: Option<String>,
	/// Default 5m.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_ejection_time: Option<String>,
	/// Default 50: never all of them.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_ejected_percent: Option<u8>,
}

fn duration(what: &str, value: &Option<String>, min: Duration, max: Duration) -> Result<Option<Duration>, ApiError> {
	let Some(v) = value else { return Ok(None) };
	let d = if v == "0s" { Duration::ZERO } else { crate::l7::parse_duration(v).map_err(|e| ApiError::invalid(format!("{what}: {e}")))? };
	if d < min || d > max {
		return Err(ApiError::invalid(format!("{what} must be {}-{}", fmt(min), fmt(max))));
	}
	Ok(Some(d))
}

fn fmt(d: Duration) -> String {
	match d.as_secs() {
		0 => "0s".into(),
		s if s % 3600 == 0 => format!("{}h", s / 3600),
		s if s % 60 == 0 => format!("{}m", s / 60),
		s => format!("{s}s"),
	}
}

fn ejection(what: &str, first: &Option<String>, max: &Option<String>, default_first: Duration) -> Result<(), ApiError> {
	let hour = Duration::from_secs(3600);
	let first = duration(&format!("{what}.ejection_time"), first, Duration::from_secs(1), hour)?.unwrap_or(default_first);
	if let Some(max) = duration(&format!("{what}.max_ejection_time"), max, Duration::from_secs(1), hour)? {
		if max < first {
			return Err(ApiError::invalid(format!("{what}.max_ejection_time must not be below ejection_time")));
		}
	}
	Ok(())
}

fn percent(what: &str, value: Option<u8>, min: u8) -> Result<(), ApiError> {
	match value {
		Some(p) if p < min || p > 100 => Err(ApiError::invalid(format!("{what} must be {min}-100"))),
		_ => Ok(()),
	}
}

impl L4OutlierSpec {
	/// `{}`: back to the defaults (how PATCH removes the setting).
	pub fn is_empty(&self) -> bool {
		*self == L4OutlierSpec::default()
	}

	pub fn validate(&self) -> Result<(), ApiError> {
		if self.consecutive_failures.is_some_and(|n| n == 0 || n > MAX_CONSECUTIVE) {
			return Err(ApiError::invalid(format!("outlier_detection.consecutive_failures must be 1-{MAX_CONSECUTIVE}")));
		}
		duration("outlier_detection.short_lived", &self.short_lived, Duration::ZERO, Duration::from_secs(60))?;
		ejection("outlier_detection", &self.ejection_time, &self.max_ejection_time, crate::core::balance::FAIL_COOLDOWN)?;
		percent("outlier_detection.max_ejected_percent", self.max_ejected_percent, 0)
	}
}

impl HttpOutlierSpec {
	pub fn validate(&self, what: &str) -> Result<(), ApiError> {
		for (key, n) in [("consecutive_5xx", self.consecutive_5xx), ("consecutive_gateway_failures", self.consecutive_gateway_failures)] {
			if n.is_some_and(|n| n > MAX_CONSECUTIVE) {
				return Err(ApiError::invalid(format!("{what}.{key} must be 0-{MAX_CONSECUTIVE}")));
			}
		}
		percent(&format!("{what}.failure_percent"), self.failure_percent, 1)?;
		if self.min_requests.is_some_and(|n| n == 0 || n > 1_000_000) {
			return Err(ApiError::invalid(format!("{what}.min_requests must be 1-1000000")));
		}
		duration(&format!("{what}.window"), &self.window, Duration::from_secs(1), Duration::from_secs(3600))?;
		ejection(what, &self.ejection_time, &self.max_ejection_time, Duration::from_secs(30))?;
		percent(&format!("{what}.max_ejected_percent"), self.max_ejected_percent, 0)?;
		let nothing = self.consecutive_5xx == Some(0) && self.consecutive_gateway_failures == Some(0) && self.failure_percent.is_none();
		if nothing {
			return Err(ApiError::invalid(format!("{what} turns every check off")));
		}
		Ok(())
	}
}


// ---- run time ----

/// How long, how much longer each time, and how many at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ejecting {
	pub time: Duration,
	pub max_time: Duration,
	pub max_percent: u8,
}

impl Ejecting {
	fn new(time: &Option<String>, max: &Option<String>, percent: Option<u8>, default_time: Duration, default_max: Option<Duration>, default_percent: u8) -> Ejecting {
		let parse = |v: &Option<String>| v.as_deref().and_then(|s| crate::l7::parse_duration(s).ok());
		let time = parse(time).unwrap_or(default_time);
		let max_time = parse(max).or(default_max).unwrap_or(time).max(time);
		Ejecting { time, max_time, max_percent: percent.unwrap_or(default_percent).min(100) }
	}

	/// Whether one more of `total` may be ejected while `ejected` are.
	pub fn allows(&self, ejected: usize, total: usize) -> bool {
		(ejected + 1) * 100 <= usize::from(self.max_percent) * total
	}
}

/// `outlier_detection` of an L4 rule at run time. Without the setting, the
/// defaults are what rproxy always did: one failed connection skips the target
/// for `FAIL_COOLDOWN` (10 s).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L4Outlier {
	pub consecutive_failures: u32,
	/// Zero: connections are judged when they are made, not when they end.
	pub short_lived: Duration,
	pub ejecting: Ejecting,
}

impl L4Outlier {
	/// `spec` must be validated.
	pub fn new(spec: Option<&L4OutlierSpec>) -> L4Outlier {
		let d = L4OutlierSpec::default();
		let spec = spec.unwrap_or(&d);
		let short_lived = spec.short_lived.as_deref().and_then(|s| crate::l7::parse_duration(s).ok()).unwrap_or(Duration::ZERO);
		L4Outlier {
			consecutive_failures: spec.consecutive_failures.unwrap_or(1).max(1),
			short_lived,
			ejecting: Ejecting::new(&spec.ejection_time, &spec.max_ejection_time, spec.max_ejected_percent, crate::core::balance::FAIL_COOLDOWN, None, 100),
		}
	}
}

impl Default for L4Outlier {
	fn default() -> Self {
		L4Outlier::new(None)
	}
}

/// `outlier_detection` of an `http` service at run time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpOutlier {
	/// Zero: not looked at.
	pub consecutive_5xx: u32,
	pub consecutive_gateway_failures: u32,
	pub failure_percent: Option<u8>,
	pub min_requests: u32,
	pub window: Duration,
	pub ejecting: Ejecting,
}

impl HttpOutlier {
	/// `spec` must be validated.
	pub fn new(spec: &HttpOutlierSpec) -> HttpOutlier {
		let window = spec.window.as_deref().and_then(|s| crate::l7::parse_duration(s).ok()).unwrap_or(Duration::from_secs(30));
		HttpOutlier {
			consecutive_5xx: spec.consecutive_5xx.unwrap_or(5),
			consecutive_gateway_failures: spec.consecutive_gateway_failures.unwrap_or(3),
			failure_percent: spec.failure_percent,
			min_requests: spec.min_requests.unwrap_or(20).max(1),
			window: window.max(Duration::from_secs(1)),
			ejecting: Ejecting::new(
				&spec.ejection_time,
				&spec.max_ejection_time,
				spec.max_ejected_percent,
				Duration::from_secs(30),
				Some(Duration::from_secs(300)),
				50,
			),
		}
	}
}

/// What one request to an `http` server came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpOutcome {
	Ok,
	/// A 5xx answer other than 502 / 503 / 504.
	ServerError,
	/// 502 / 503 / 504, or rproxy could not connect / got no answer in time.
	Gateway,
}

impl HttpOutcome {
	pub fn of_status(status: u16) -> HttpOutcome {
		match status {
			502..=504 => HttpOutcome::Gateway,
			500..=599 => HttpOutcome::ServerError,
			_ => HttpOutcome::Ok,
		}
	}
}

/// Milliseconds on a monotonic clock, from 1 (0 means "not ejected").
fn now_ms() -> u64 {
	static START: OnceLock<Instant> = OnceLock::new();
	START.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Default)]
struct Counts {
	/// In a row: failures (L4), 5xx and gateway failures (L7).
	failures: u32,
	server_errors: u32,
	gateway: u32,
	/// `failure_percent`: the current window.
	window_start: u64,
	requests: u32,
	failed: u32,
	/// Doublings of the next ejection.
	level: u32,
	/// When the last ejection ended (ms).
	last_end: u64,
}

/// Outlier state of one L4 target or `http` server.
#[derive(Default)]
pub struct Ejection {
	/// Ejected until then (`now_ms`); 0: not ejected.
	until: AtomicU64,
	until_unix: AtomicU64,
	ejections: AtomicU64,
	counts: Mutex<Counts>,
}

impl std::fmt::Debug for Ejection {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Ejection").field("ejected", &self.is_ejected()).field("ejections", &self.ejections()).finish()
	}
}

impl Ejection {
	fn counts(&self) -> std::sync::MutexGuard<'_, Counts> {
		self.counts.lock().unwrap_or_else(|e| e.into_inner())
	}

	pub fn is_ejected(&self) -> bool {
		let until = self.until.load(Ordering::Relaxed);
		until != 0 && now_ms() < until
	}

	/// Until when (Unix seconds) while ejected.
	pub fn ejected_until(&self) -> Option<u64> {
		self.is_ejected().then(|| self.until_unix.load(Ordering::Relaxed))
	}

	pub fn ejections(&self) -> u64 {
		self.ejections.load(Ordering::Relaxed)
	}

	/// Back in use at once (an active health check saw it recover).
	pub fn clear(&self) {
		self.until.store(0, Ordering::Relaxed);
		let mut c = self.counts();
		c.failures = 0;
		c.server_errors = 0;
		c.gateway = 0;
	}

	/// An L4 connection: true when `consecutive_failures` is reached.
	pub fn record_l4(&self, cfg: &L4Outlier, failed: bool) -> bool {
		let mut c = self.counts();
		if !failed {
			c.failures = 0;
			return false;
		}
		c.failures = c.failures.saturating_add(1);
		c.failures >= cfg.consecutive_failures
	}

	/// An `http` request: the threshold reached, if one is (`consecutive_5xx`,
	/// `consecutive_gateway_failures` or `failure_percent`).
	pub fn record_http(&self, cfg: &HttpOutlier, outcome: HttpOutcome) -> Option<&'static str> {
		let now = now_ms();
		let mut c = self.counts();
		if now.saturating_sub(c.window_start) >= cfg.window.as_millis() as u64 {
			c.window_start = now;
			c.requests = 0;
			c.failed = 0;
		}
		c.requests = c.requests.saturating_add(1);
		match outcome {
			HttpOutcome::Ok => {
				c.server_errors = 0;
				c.gateway = 0;
			}
			HttpOutcome::ServerError => {
				c.server_errors = c.server_errors.saturating_add(1);
				c.gateway = 0;
				c.failed = c.failed.saturating_add(1);
			}
			HttpOutcome::Gateway => {
				c.server_errors = c.server_errors.saturating_add(1);
				c.gateway = c.gateway.saturating_add(1);
				c.failed = c.failed.saturating_add(1);
			}
		}
		let five = cfg.consecutive_5xx > 0 && c.server_errors >= cfg.consecutive_5xx;
		let gateway = cfg.consecutive_gateway_failures > 0 && c.gateway >= cfg.consecutive_gateway_failures;
		let percent = cfg
			.failure_percent
			.is_some_and(|p| c.requests >= cfg.min_requests && u64::from(c.failed) * 100 >= u64::from(p) * u64::from(c.requests));
		if gateway {
			Some("consecutive_gateway_failures")
		} else if five {
			Some("consecutive_5xx")
		} else if percent {
			Some("failure_percent")
		} else {
			None
		}
	}

	/// Ejects for `ejection_time`, doubled for each ejection that followed the
	/// previous one within `max_ejection_time`, up to it. Returns how long and
	/// the deadline (for `after`). Already ejected: the ejection starts over at
	/// the same length (not counted again).
	pub fn eject(&self, e: &Ejecting) -> (Duration, u64) {
		let now = now_ms();
		let mut c = self.counts();
		let again = self.is_ejected();
		if !again {
			if c.last_end != 0 && now.saturating_sub(c.last_end) > e.max_time.as_millis() as u64 {
				c.level = 0;
			}
			c.level = c.level.saturating_add(1);
			self.ejections.fetch_add(1, Ordering::Relaxed);
		}
		let factor = 1u32.checked_shl(c.level.saturating_sub(1)).unwrap_or(u32::MAX);
		let length = e.time.saturating_mul(factor).min(e.max_time);
		let until = now + length.as_millis() as u64;
		c.last_end = until;
		c.failures = 0;
		c.server_errors = 0;
		c.gateway = 0;
		c.requests = 0;
		c.failed = 0;
		self.until.store(until, Ordering::Relaxed);
		self.until_unix.store(unix_now() + length.as_secs_f64().ceil() as u64, Ordering::Relaxed);
		(length, until)
	}

	/// Whether the ejection that ends at `until` (from `eject`) is still the current one.
	pub fn ends_at(&self, until: u64) -> bool {
		self.until.load(Ordering::Relaxed) == until
	}
}

/// Runs `back` once the ejection that ends at `until` is over, unless another
/// one replaced it or `ejection` is gone (the rule changed or was deleted).
pub fn after(ejection: &Arc<Ejection>, until: u64, length: Duration, back: impl FnOnce() + Send + 'static) {
	if tokio::runtime::Handle::try_current().is_err() {
		return;
	}
	let ejection = Arc::downgrade(ejection);
	tokio::spawn(async move {
		tokio::time::sleep(length).await;
		if ejection.upgrade().is_some_and(|e| e.ends_at(until)) {
			back();
		}
	});
}

/// Which side of a relayed TCP connection ended first (`short_lived`).
#[derive(Debug, Default)]
pub struct FirstEnd(AtomicU8);

impl FirstEnd {
	const CLIENT: u8 = 1;
	const BACKEND: u8 = 2;

	/// The reading of one side ended (EOF or an error).
	pub fn mark(&self, backend: bool) {
		let side = if backend { Self::BACKEND } else { Self::CLIENT };
		let _ = self.0.compare_exchange(0, side, Ordering::Relaxed, Ordering::Relaxed);
	}

	pub fn backend(&self) -> bool {
		self.0.load(Ordering::Relaxed) == Self::BACKEND
	}
}

/// A stream whose end of reading is noted in a `FirstEnd`.
pub struct Watched<'a, S: ?Sized> {
	inner: &'a mut S,
	first: Option<&'a FirstEnd>,
	backend: bool,
}

impl<'a, S: ?Sized> Watched<'a, S> {
	pub fn new(inner: &'a mut S, first: Option<&'a FirstEnd>, backend: bool) -> Self {
		Watched { inner, first, backend }
	}
}

impl<S: tokio::io::AsyncRead + Unpin + ?Sized> tokio::io::AsyncRead for Watched<'_, S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		let (before, room) = (buf.filled().len(), buf.remaining());
		let poll = Pin::new(&mut *this.inner).poll_read(cx, buf);
		if let Some(first) = this.first {
			match &poll {
				Poll::Ready(Ok(())) if room > 0 && buf.filled().len() == before => first.mark(this.backend),
				Poll::Ready(Err(_)) => first.mark(this.backend),
				_ => {}
			}
		}
		poll
	}
}

impl<S: tokio::io::AsyncWrite + Unpin + ?Sized> tokio::io::AsyncWrite for Watched<'_, S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn defaults_are_the_old_fail_cooldown() {
		let d = L4Outlier::default();
		assert_eq!(d.consecutive_failures, 1);
		assert_eq!(d.short_lived, Duration::ZERO);
		assert_eq!(d.ejecting, Ejecting { time: crate::core::balance::FAIL_COOLDOWN, max_time: crate::core::balance::FAIL_COOLDOWN, max_percent: 100 });
		let h = HttpOutlier::new(&HttpOutlierSpec::default());
		assert_eq!((h.consecutive_5xx, h.consecutive_gateway_failures, h.failure_percent, h.min_requests), (5, 3, None, 20));
		assert_eq!(h.ejecting, Ejecting { time: Duration::from_secs(30), max_time: Duration::from_secs(300), max_percent: 50 });
		// at most half of 2, none of 1
		assert!(h.ejecting.allows(0, 2) && !h.ejecting.allows(1, 2) && !h.ejecting.allows(0, 1));
		assert!(d.ejecting.allows(1, 2) && d.ejecting.allows(0, 1));
	}

	#[test]
	fn ejections_double_up_to_the_maximum() {
		let e = Ejection::default();
		let cfg = L4Outlier::new(Some(&L4OutlierSpec {
			consecutive_failures: Some(2),
			ejection_time: Some("1s".into()),
			max_ejection_time: Some("3s".into()),
			..Default::default()
		}));
		assert!(!e.record_l4(&cfg, true));
		assert!(!e.record_l4(&cfg, false), "a success ends the run");
		assert!(!e.record_l4(&cfg, true));
		assert!(e.record_l4(&cfg, true));
		let (first, until) = e.eject(&cfg.ejecting);
		assert_eq!(first, Duration::from_secs(1));
		assert!(e.is_ejected() && e.ends_at(until) && e.ejected_until().is_some());
		// failing again while ejected starts it over at the same length, not counted
		assert_eq!(e.eject(&cfg.ejecting).0, Duration::from_secs(1));
		assert_eq!(e.ejections(), 1);
		e.until.store(1, Ordering::Relaxed); // the ejection is over
		assert!(!e.is_ejected() && e.ejected_until().is_none());
		assert_eq!(e.eject(&cfg.ejecting).0, Duration::from_secs(2), "doubled");
		e.until.store(1, Ordering::Relaxed);
		assert_eq!(e.eject(&cfg.ejecting).0, Duration::from_secs(3), "up to max_ejection_time");
		assert_eq!(e.ejections(), 3);
		e.clear();
		assert!(!e.is_ejected());
	}

	#[test]
	fn http_thresholds() {
		let spec = |v: serde_json::Value| HttpOutlier::new(&serde_json::from_value::<HttpOutlierSpec>(v).unwrap());
		let e = Ejection::default();
		let cfg = spec(serde_json::json!({"consecutive_5xx": 3, "consecutive_gateway_failures": 0}));
		assert!(e.record_http(&cfg, HttpOutcome::ServerError).is_none());
		assert!(e.record_http(&cfg, HttpOutcome::Gateway).is_none(), "gateway failures are 5xx too");
		assert!(e.record_http(&cfg, HttpOutcome::Ok).is_none());
		assert!(e.record_http(&cfg, HttpOutcome::ServerError).is_none());
		assert!(e.record_http(&cfg, HttpOutcome::ServerError).is_none());
		assert_eq!(e.record_http(&cfg, HttpOutcome::ServerError), Some("consecutive_5xx"));

		let e = Ejection::default();
		let cfg = spec(serde_json::json!({}));
		assert!(e.record_http(&cfg, HttpOutcome::Gateway).is_none());
		assert!(e.record_http(&cfg, HttpOutcome::Gateway).is_none());
		assert_eq!(e.record_http(&cfg, HttpOutcome::Gateway), Some("consecutive_gateway_failures"), "3 gateway failures by default");

		let e = Ejection::default();
		let cfg = spec(serde_json::json!({"consecutive_5xx": 0, "consecutive_gateway_failures": 0, "failure_percent": 50, "min_requests": 4}));
		for outcome in [HttpOutcome::ServerError, HttpOutcome::Ok, HttpOutcome::ServerError] {
			assert!(e.record_http(&cfg, outcome).is_none(), "fewer than min_requests");
		}
		assert_eq!(e.record_http(&cfg, HttpOutcome::Ok), Some("failure_percent"), "2 of 4 failed");
		assert_eq!(HttpOutcome::of_status(503), HttpOutcome::Gateway);
		assert_eq!(HttpOutcome::of_status(500), HttpOutcome::ServerError);
		assert_eq!(HttpOutcome::of_status(404), HttpOutcome::Ok);
	}

	#[test]
	fn the_first_side_to_end_is_kept() {
		let f = FirstEnd::default();
		f.mark(true);
		f.mark(false);
		assert!(f.backend());
		let f = FirstEnd::default();
		f.mark(false);
		f.mark(true);
		assert!(!f.backend());
	}

	#[test]
	fn l4_shape_and_validation() {
		let parse = |v: serde_json::Value| serde_json::from_value::<L4OutlierSpec>(v).unwrap();
		parse(serde_json::json!({"consecutive_failures": 3, "short_lived": "500ms", "ejection_time": "10s",
			"max_ejection_time": "5m", "max_ejected_percent": 50}))
		.validate()
		.unwrap();
		parse(serde_json::json!({})).validate().unwrap();
		for bad in [
			serde_json::json!({"consecutive_failures": 0}),
			serde_json::json!({"short_lived": "2m"}),
			serde_json::json!({"ejection_time": "2h"}),
			serde_json::json!({"ejection_time": "1m", "max_ejection_time": "30s"}),
			serde_json::json!({"max_ejection_time": "5s"}),
			serde_json::json!({"max_ejected_percent": 101}),
		] {
			assert_eq!(parse(bad.clone()).validate().unwrap_err().code, "invalid", "{bad}");
		}
	}

	#[test]
	fn http_shape_and_validation() {
		let parse = |v: serde_json::Value| serde_json::from_value::<HttpOutlierSpec>(v).unwrap();
		parse(serde_json::json!({"consecutive_5xx": 5, "failure_percent": 50, "min_requests": 20, "window": "30s",
			"ejection_time": "30s", "max_ejection_time": "5m", "max_ejected_percent": 50}))
		.validate("s")
		.unwrap();
		for bad in [
			serde_json::json!({"failure_percent": 0}),
			serde_json::json!({"min_requests": 0}),
			serde_json::json!({"window": "0s"}),
			serde_json::json!({"consecutive_5xx": 0, "consecutive_gateway_failures": 0}),
		] {
			assert_eq!(parse(bad.clone()).validate("s").unwrap_err().code, "invalid", "{bad}");
		}
	}
}
