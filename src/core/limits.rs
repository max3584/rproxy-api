//! L4 limits of a rule (#165, docs/DESIGN-v0.4.md 4.): the whole rule's
//! concurrent connections, and per client source (an address or a prefix)
//! concurrent connections, new connections and UDP datagrams.
//!
//! v0.4.0 settles the shape; `features.limits` says whether this build applies it.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::core::rule::Protocol;
use crate::error::ApiError;

const MAX_CONNECTIONS: u64 = 10_000_000;
const MAX_SOURCE_CONNECTIONS: u64 = 1_000_000;
pub const DEFAULT_MAX_SOURCES: u64 = 65_536;
const MAX_SOURCES: u64 = 10_000_000;

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
}
