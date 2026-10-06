//! Bandwidth limits of a rule (#166, docs/DESIGN-v0.4.md 5.): the whole rule
//! and per client source, each way. TCP waits (shaping), UDP drops over the rate.
//!
//! v0.4.0 settles the shape; `features.bandwidth` says whether this build applies it.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// 8 kbit/s .. 100 Gbit/s.
const MIN_RATE: u64 = 8_000;
const MAX_RATE: u64 = 100_000_000_000;
/// 1 KiB .. 1 GiB.
const MIN_BURST: u64 = 1 << 10;
const MAX_BURST: u64 = 1 << 30;
const MAX_SOURCES: u64 = 10_000_000;

/// `bandwidth` of a rule. `{}` means no limits (how PATCH removes them).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BandwidthSpec {
	/// Client → backend, the whole rule (`"100Mbps"`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub upload: Option<String>,
	/// Backend → client, the whole rule.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub download: Option<String>,
	/// What may pass at once (`"1MiB"`; default: 100 ms worth of the rate).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub burst: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub per_source: Option<PerSourceBandwidth>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerSourceBandwidth {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub upload: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub download: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prefix_v4: Option<u8>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub prefix_v6: Option<u8>,
	/// Most sources remembered (default 65536).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_sources: Option<u64>,
}

/// A rate in bits per second: `"<n>bps"`, `kbps`, `Mbps`, `Gbps` (steps of 1000).
pub fn parse_rate(s: &str) -> Result<u64, String> {
	let bad = || format!("{s:?} is not a rate (e.g. 500kbps, 10Mbps, 1Gbps)");
	let split = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(bad)?;
	let (num, unit) = s.split_at(split);
	let n: u64 = num.parse().map_err(|_| bad())?;
	let mult: u64 = match unit {
		"bps" => 1,
		"kbps" => 1_000,
		"Mbps" => 1_000_000,
		"Gbps" => 1_000_000_000,
		_ => return Err(bad()),
	};
	let rate = n.checked_mul(mult).ok_or_else(bad)?;
	if !(MIN_RATE..=MAX_RATE).contains(&rate) {
		return Err(format!("{s:?} must be 8kbps-100Gbps"));
	}
	Ok(rate)
}

/// A size in bytes: a plain number or `"<n>B"`, `KiB`, `MiB`, `GiB` (steps of 1024).
pub fn parse_size(s: &str) -> Result<u64, String> {
	let bad = || format!("{s:?} is not a size (e.g. 4096, 64KiB, 1MiB)");
	let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
	let (num, unit) = s.split_at(split);
	let n: u64 = num.parse().map_err(|_| bad())?;
	let mult: u64 = match unit {
		"" | "B" => 1,
		"KiB" => 1 << 10,
		"MiB" => 1 << 20,
		"GiB" => 1 << 30,
		_ => return Err(bad()),
	};
	n.checked_mul(mult).ok_or_else(bad)
}

fn rate(what: &str, value: &Option<String>) -> Result<(), ApiError> {
	if let Some(v) = value {
		parse_rate(v).map_err(|e| ApiError::invalid(format!("{what}: {e}")))?;
	}
	Ok(())
}

impl BandwidthSpec {
	/// `{}`: no limits.
	pub fn is_empty(&self) -> bool {
		*self == BandwidthSpec::default()
	}

	pub fn validate(&self) -> Result<(), ApiError> {
		rate("bandwidth.upload", &self.upload)?;
		rate("bandwidth.download", &self.download)?;
		if let Some(b) = &self.burst {
			let n = parse_size(b).map_err(|e| ApiError::invalid(format!("bandwidth.burst: {e}")))?;
			if !(MIN_BURST..=MAX_BURST).contains(&n) {
				return Err(ApiError::invalid("bandwidth.burst must be 1KiB-1GiB"));
			}
		}
		let mut any = self.upload.is_some() || self.download.is_some();
		if let Some(p) = &self.per_source {
			rate("bandwidth.per_source.upload", &p.upload)?;
			rate("bandwidth.per_source.download", &p.download)?;
			if p.prefix_v4.is_some_and(|n| n == 0 || n > 32) {
				return Err(ApiError::invalid("bandwidth.per_source.prefix_v4 must be 1-32"));
			}
			if p.prefix_v6.is_some_and(|n| n == 0 || n > 128) {
				return Err(ApiError::invalid("bandwidth.per_source.prefix_v6 must be 1-128"));
			}
			if p.max_sources.is_some_and(|n| n == 0 || n > MAX_SOURCES) {
				return Err(ApiError::invalid(format!("bandwidth.per_source.max_sources must be 1-{MAX_SOURCES}")));
			}
			if p.upload.is_none() && p.download.is_none() {
				return Err(ApiError::invalid("bandwidth.per_source needs upload or download"));
			}
			any = true;
		}
		if !any {
			return Err(ApiError::invalid("bandwidth needs a rate (upload, download or per_source)"));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn rates_and_sizes() {
		assert_eq!(parse_rate("10Mbps"), Ok(10_000_000));
		assert_eq!(parse_rate("8kbps"), Ok(8_000));
		assert!(parse_rate("1bps").is_err(), "below 8kbps");
		assert!(parse_rate("200Gbps").is_err());
		assert!(parse_rate("10MB/s").is_err());
		assert!(parse_rate("Mbps").is_err());
		assert_eq!(parse_size("64KiB"), Ok(65_536));
		assert_eq!(parse_size("4096"), Ok(4096));
		assert!(parse_size("1MB").is_err());
	}

	#[test]
	fn shape_and_validation() {
		let parse = |v: serde_json::Value| serde_json::from_value::<BandwidthSpec>(v).unwrap();
		parse(serde_json::json!({"upload": "100Mbps", "download": "500Mbps", "burst": "1MiB",
			"per_source": {"upload": "2Mbps", "prefix_v6": 64}}))
		.validate()
		.unwrap();
		assert!(parse(serde_json::json!({})).is_empty());
		for bad in [
			serde_json::json!({}),
			serde_json::json!({"upload": "fast"}),
			serde_json::json!({"upload": "1Mbps", "burst": "10B"}),
			serde_json::json!({"per_source": {"prefix_v4": 24}}),
			serde_json::json!({"per_source": {"upload": "1Mbps", "prefix_v6": 0}}),
		] {
			assert_eq!(parse(bad.clone()).validate().unwrap_err().code, "invalid", "{bad}");
		}
	}
}
