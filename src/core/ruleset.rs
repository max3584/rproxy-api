//! What a Kubernetes controller needs from rproxy (#28, docs/DESIGN-v0.4.md 3.):
//! rule sets applied as a whole (`PUT /rulesets/{name}`), rule `labels`, and
//! per-rule `conditions` shaped for Gateway API status.
//!
//! v0.4.0 settles the shape; `features.rulesets`, `features.labels` and
//! `features.conditions` say whether this build applies it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::core::rule::RuleRequest;
use crate::error::ApiError;

pub const MAX_LABELS: usize = 16;
const MAX_KEY: usize = 63;
const MAX_VALUE: usize = 253;
const MAX_NAME: usize = 253;
/// Most rules in one set.
pub const MAX_RULES: usize = 10_000;

/// A rule's `labels`.
pub type Labels = BTreeMap<String, String>;

/// Keys: `[A-Za-z0-9]([A-Za-z0-9._/-]{0,61}[A-Za-z0-9])?`; values: 0-253
/// characters without control characters; at most 16.
pub fn validate_labels(labels: &Labels) -> Result<(), ApiError> {
	if labels.len() > MAX_LABELS {
		return Err(ApiError::invalid(format!("labels: at most {MAX_LABELS}")));
	}
	for (k, v) in labels {
		let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
		let inner = k.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'));
		if k.is_empty() || k.len() > MAX_KEY || !inner || !edge(k.chars().next()) || !edge(k.chars().last()) {
			return Err(ApiError::invalid(format!("labels: {k:?} is not a key (letters, digits, . _ / -, at most {MAX_KEY})")));
		}
		if v.chars().count() > MAX_VALUE || v.chars().any(char::is_control) {
			return Err(ApiError::invalid(format!("labels.{k}: at most {MAX_VALUE} characters, no control characters")));
		}
	}
	Ok(())
}

/// Set names: `[a-z0-9]([a-z0-9._/-]{0,251}[a-z0-9])?`, e.g. `k8s/default/web-gateway`.
pub fn validate_name(name: &str) -> Result<(), ApiError> {
	let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
	let inner = name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-'));
	if name.is_empty() || name.len() > MAX_NAME || !inner || !edge(name.chars().next()) || !edge(name.chars().last()) {
		return Err(ApiError::invalid(format!(
			"{name:?} is not a rule set name (lower-case letters, digits, . _ / -, at most {MAX_NAME})"
		)));
	}
	Ok(())
}

/// The body of `PUT /rulesets/{name}`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesetRequest {
	/// The caller's generation (e.g. Kubernetes `metadata.generation`); stored and echoed.
	pub generation: u64,
	pub rules: Vec<RuleRequest>,
}

impl RulesetRequest {
	/// The checks that need no registry: the size and keys appearing twice.
	pub fn validate_shape(&self) -> Result<(), ApiError> {
		if self.rules.len() > MAX_RULES {
			return Err(ApiError::invalid(format!("a rule set holds at most {MAX_RULES} rules")));
		}
		let mut seen = std::collections::HashSet::new();
		for (i, r) in self.rules.iter().enumerate() {
			let listen = crate::core::rule::parse_listen(&r.listen_addr, r.listen_port)
				.map_err(|e| ApiError::invalid(format!("rules[{i}]: {}", e.message)))?;
			if !seen.insert((r.protocol, listen)) {
				return Err(ApiError::invalid(format!("rules[{i}]: {}/{listen} is in the set twice", r.protocol)));
			}
		}
		Ok(())
	}
}

/// One result of `PUT /rulesets/{name}` (and of a dry run).
#[derive(Clone, Debug, Serialize)]
pub struct ApplyResult {
	pub rule: String,
	/// `create`, `update`, `delete` or `none`.
	pub action: &'static str,
	/// `none`, `in_place` or `recreate`.
	pub change: &'static str,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub state: Option<crate::core::rule::State>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

/// One entry of a rule's `conditions` (Gateway API style).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Condition {
	/// `Accepted`, `Programmed`, `ResolvedRefs` or `BackendsHealthy`.
	#[serde(rename = "type")]
	pub kind: &'static str,
	/// `True` or `False`.
	pub status: &'static str,
	pub reason: &'static str,
	pub message: String,
	/// Unix seconds.
	pub last_transition: u64,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn label_keys_and_values() {
		let ok: Labels =
			[("tenant", "act"), ("gateway.networking.k8s.io/gateway-name", "web"), ("a", "")].map(|(k, v)| (k.into(), v.into())).into();
		validate_labels(&ok).unwrap();
		for (k, v) in [("", "x"), ("-a", "x"), ("a-", "x"), ("a b", "x"), ("a", "x\ny")] {
			let one: Labels = [(k.to_string(), v.to_string())].into();
			assert_eq!(validate_labels(&one).unwrap_err().code, "invalid", "{k:?}={v:?}");
		}
		let many: Labels = (0..17).map(|i| (format!("k{i}"), String::new())).collect();
		assert!(validate_labels(&many).is_err());
		assert!(validate_labels(&[("k".repeat(64), String::new())].into()).is_err());
	}

	#[test]
	fn set_names_and_bodies() {
		validate_name("k8s/default/web-gateway").unwrap();
		for bad in ["", "K8s", "/a", "a/", "a b", &"a".repeat(254)] {
			assert!(validate_name(bad).is_err(), "{bad:?}");
		}
		let body: RulesetRequest = serde_json::from_value(serde_json::json!({"generation": 3, "rules": [
			{"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 80, "remote_addr": "a", "remote_port": 1},
			{"protocol": "udp", "listen_addr": "0.0.0.0", "listen_port": 80, "remote_addr": "a", "remote_port": 1}
		]}))
		.unwrap();
		body.validate_shape().unwrap();
		let mut twice = body.clone();
		twice.rules[1].protocol = crate::core::rule::Protocol::Tcp;
		assert!(twice.validate_shape().unwrap_err().message.contains("twice"));
		assert!(serde_json::from_value::<RulesetRequest>(serde_json::json!({"rules": []})).is_err(), "generation is required");
	}
}
