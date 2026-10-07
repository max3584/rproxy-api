//! Passive health checks / outlier detection (#170, docs/DESIGN-v0.4.md 9.):
//! targets that keep failing in real traffic are ejected for a while. L4 is a
//! rule's `outlier_detection`; L7 is `http.services.<name>.outlier_detection`.
//!
//! v0.4.0 settles the shape; `features.outlier_detection` (L4) and the
//! `outlier_detection` entry of `features.services` (L7) say whether this
//! build applies it. Without the setting, L4 keeps skipping a target for
//! `balance::FAIL_COOLDOWN` after one failed connection (the defaults below).

use std::time::Duration;

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

#[cfg(test)]
mod tests {
	use super::*;

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
