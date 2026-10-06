//! Storing rules created through the API (#144, docs/DESIGN-v0.4.md 11.):
//! rproxy writes only its own table, `rproxy_rules` (the UI's `forward_rules`
//! is never touched), for tokens marked `persist: true`, and restores its own
//! node's rows at startup after the UI's (the UI's win on the same key).
//!
//! v0.4.0 settles the shape; `features.persistence` says whether this build stores rules.

use serde::Deserialize;

use crate::core::rule::RuleRequest;

/// rproxy's own table (definition and GRANT: the UI repository's `db/` migrations).
pub const TABLE: &str = "rproxy_rules";

/// How `spec` is written; bumped when its reading changes.
pub const SPEC_VERSION: u32 = 1;

/// One row of `rproxy_rules`.
#[derive(Clone, Debug, Deserialize)]
pub struct StoredRule {
	/// `RPROXY_NODE_NAME` (default: the host name); only this node's rows are restored.
	pub node: String,
	/// The rule as in the body of `POST /rules`.
	pub spec: RuleRequest,
	pub spec_version: u32,
	/// The token that created it, and when (Unix seconds).
	pub created_by: String,
	pub created_at: u64,
	pub updated_by: String,
	pub updated_at: u64,
}

