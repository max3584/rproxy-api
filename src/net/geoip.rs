//! GeoIP (#168, docs/DESIGN-v0.4.md 7.): MaxMind databases (mmdb) given in
//! `global.geoip`, and allow / deny lists of countries and ASNs for a rule (L4,
//! right after accepting) and for the `geoip` middleware (L7).
//!
//! v0.4.0 settles the shape; `features.geoip` (L4 and `global.geoip`) and the
//! `geoip` entry of `features.middlewares` say whether this build applies it.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// `global.geoip`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoipGlobal {
	/// A Country or City database (mmdb); needed by `*_countries`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub country_db: Option<String>,
	/// An ASN database (mmdb); needed by `*_asns`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub asn_db: Option<String>,
	/// How often to check the files for changes (default 1m; 0s: never).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub check_interval: Option<String>,
	/// Add the country (and ASN) to conn.open, conn.denied and http.access.
	#[serde(default)]
	pub log_country: bool,
}

impl GeoipGlobal {
	pub fn check(&self) -> Result<(), String> {
		if self.country_db.is_none() && self.asn_db.is_none() {
			return Err("global.geoip needs country_db or asn_db".into());
		}
		for (what, path) in [("country_db", &self.country_db), ("asn_db", &self.asn_db)] {
			if path.as_ref().is_some_and(|p| p.trim().is_empty()) {
				return Err(format!("global.geoip.{what} must not be empty"));
			}
		}
		if let Some(i) = &self.check_interval {
			if i != "0s" {
				crate::l7::parse_duration(i).map_err(|e| format!("global.geoip.check_interval: {e}"))?;
			}
		}
		Ok(())
	}
}

/// What to do with clients the databases do not know (or private addresses).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unknown {
	#[default]
	Allow,
	Deny,
}

/// `geoip` of a rule, and of the `geoip` middleware.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoipSpec {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allow_countries: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub deny_countries: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allow_asns: Vec<u32>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub deny_asns: Vec<u32>,
	#[serde(default, skip_serializing_if = "is_allow")]
	pub unknown: Unknown,
}

fn is_allow(u: &Unknown) -> bool {
	*u == Unknown::Allow
}

impl GeoipSpec {
	/// `{}`: no lists (how PATCH removes them).
	pub fn is_empty(&self) -> bool {
		*self == GeoipSpec::default()
	}

	pub fn uses_countries(&self) -> bool {
		!self.allow_countries.is_empty() || !self.deny_countries.is_empty()
	}

	pub fn uses_asns(&self) -> bool {
		!self.allow_asns.is_empty() || !self.deny_asns.is_empty()
	}

	pub fn validate(&self, what: &str) -> Result<(), ApiError> {
		if !self.uses_countries() && !self.uses_asns() {
			return Err(ApiError::invalid(format!("{what} needs a list (allow_countries, deny_countries, allow_asns or deny_asns)")));
		}
		for c in self.allow_countries.iter().chain(&self.deny_countries) {
			if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
				return Err(ApiError::invalid(format!("{what}: {c:?} is not a country code (ISO 3166-1 alpha-2, e.g. JP)")));
			}
		}
		if let Some(c) = self.allow_countries.iter().find(|c| self.deny_countries.contains(c)) {
			return Err(ApiError::invalid(format!("{what}: {c} is in both allow_countries and deny_countries")));
		}
		if self.allow_asns.iter().chain(&self.deny_asns).any(|a| *a == 0) {
			return Err(ApiError::invalid(format!("{what}: ASNs are 1-4294967295")));
		}
		if let Some(a) = self.allow_asns.iter().find(|a| self.deny_asns.contains(a)) {
			return Err(ApiError::invalid(format!("{what}: AS{a} is in both allow_asns and deny_asns")));
		}
		Ok(())
	}

	/// The databases the lists need, against `global.geoip` (settings file).
	pub fn check_databases(&self, what: &str, global: Option<&GeoipGlobal>) -> Result<(), String> {
		let has = |f: fn(&GeoipGlobal) -> bool| global.is_some_and(f);
		if self.uses_countries() && !has(|g| g.country_db.is_some()) {
			return Err(format!("{what}: country lists need global.geoip.country_db"));
		}
		if self.uses_asns() && !has(|g| g.asn_db.is_some()) {
			return Err(format!("{what}: ASN lists need global.geoip.asn_db"));
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(v: serde_json::Value) -> GeoipSpec {
		serde_json::from_value(v).unwrap()
	}

	#[test]
	fn shape_and_validation() {
		let ok = parse(serde_json::json!({"allow_countries": ["JP", "US"], "deny_asns": [64496], "unknown": "deny"}));
		ok.validate("geoip").unwrap();
		assert_eq!(ok.unknown, Unknown::Deny);
		for bad in [
			serde_json::json!({}),
			serde_json::json!({"allow_countries": ["jp"]}),
			serde_json::json!({"allow_countries": ["JPN"]}),
			serde_json::json!({"allow_countries": ["JP"], "deny_countries": ["JP"]}),
			serde_json::json!({"deny_asns": [0]}),
			serde_json::json!({"allow_asns": [1], "deny_asns": [1]}),
		] {
			assert_eq!(parse(bad.clone()).validate("geoip").unwrap_err().code, "invalid", "{bad}");
		}
		assert!(serde_json::from_value::<GeoipSpec>(serde_json::json!({"unknown": "maybe"})).is_err());
	}

	#[test]
	fn lists_need_their_databases() {
		let spec = parse(serde_json::json!({"allow_countries": ["JP"], "deny_asns": [64496]}));
		assert!(spec.check_databases("rule", None).unwrap_err().contains("country_db"));
		let country = GeoipGlobal { country_db: Some("/c.mmdb".into()), ..Default::default() };
		assert!(spec.check_databases("rule", Some(&country)).unwrap_err().contains("asn_db"));
		let both = GeoipGlobal { asn_db: Some("/a.mmdb".into()), ..country };
		spec.check_databases("rule", Some(&both)).unwrap();
		both.check().unwrap();
		assert!(GeoipGlobal::default().check().is_err());
		assert!(GeoipGlobal { check_interval: Some("soon".into()), ..both }.check().is_err());
	}
}
