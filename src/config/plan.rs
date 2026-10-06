//! Diff before change (#169, docs/DESIGN-v0.4.md 8.): `dry_run` on the rule
//! endpoints and `POST /config/reload`, `POST /config/plan`, and
//! `rproxy-api --check-config --diff`.
//!
//! v0.4.0 settles the shape; `features.dry_run` says whether this build answers it.

use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// `?dry_run=true|false|1|0` (absent: false).
pub fn dry_run(query: &std::collections::HashMap<String, String>) -> Result<bool, ApiError> {
	match query.get("dry_run").map(|s| s.trim()) {
		None | Some("false" | "0") => Ok(false),
		Some("" | "true" | "1") => Ok(true),
		Some(other) => Err(ApiError::invalid(format!("invalid dry_run: {other} (true or false)"))),
	}
}

/// What a change would do to one rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
	Create,
	Update,
	Delete,
	None,
}

/// How a change would be put into effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
	None,
	/// Without dropping connections.
	InPlace,
	/// The listeners are rebuilt; current connections are dropped.
	Recreate,
}

/// One changed value: a JSON path (keys joined with `.`; arrays as a whole).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DiffEntry {
	pub path: String,
	pub before: serde_json::Value,
	pub after: serde_json::Value,
}

/// The answer of a dry run on one rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RulePlan {
	pub dry_run: bool,
	pub action: Action,
	pub change: Change,
	pub rule: String,
	pub before: Option<serde_json::Value>,
	pub after: Option<serde_json::Value>,
	pub diff: Vec<DiffEntry>,
	#[serde(default)]
	pub warnings: Vec<String>,
}

/// The values that differ between two JSON documents.
pub fn diff(before: &serde_json::Value, after: &serde_json::Value) -> Vec<DiffEntry> {
	fn walk(path: &str, a: &serde_json::Value, b: &serde_json::Value, out: &mut Vec<DiffEntry>) {
		use serde_json::Value::Object;
		match (a, b) {
			(Object(x), Object(y)) => {
				let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
				keys.sort();
				keys.dedup();
				let null = serde_json::Value::Null;
				for k in keys {
					let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
					walk(&p, x.get(k).unwrap_or(&null), y.get(k).unwrap_or(&null), out);
				}
			}
			_ if a != b => out.push(DiffEntry { path: path.to_string(), before: a.clone(), after: b.clone() }),
			_ => {}
		}
	}
	let mut out = vec![];
	walk("", before, after, &mut out);
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn dry_run_query() {
		let q = |v: &str| std::collections::HashMap::from([("dry_run".to_string(), v.to_string())]);
		assert!(!dry_run(&Default::default()).unwrap());
		assert!(dry_run(&q("true")).unwrap() && dry_run(&q("")).unwrap());
		assert!(!dry_run(&q("0")).unwrap());
		assert_eq!(dry_run(&q("maybe")).unwrap_err().code, "invalid");
	}

	#[test]
	fn diff_paths() {
		let a = json!({"remote_port": 80, "tls": {"mode": "passthrough"}, "targets": [1, 2]});
		let b = json!({"remote_port": 81, "tls": {"mode": "passthrough"}, "targets": [1], "labels": {"a": "b"}});
		let d = diff(&a, &b);
		let paths: Vec<&str> = d.iter().map(|e| e.path.as_str()).collect();
		assert_eq!(paths, ["labels", "remote_port", "targets"]);
		assert!(diff(&a, &a).is_empty());
	}
}
