//! Storing rules created through the API (#144, docs/DESIGN-v0.4.md 11.):
//! rproxy writes only its own table, `rproxy_rules` (the UI's `forward_rules`
//! is never touched), for tokens marked `persist: true`, and restores its own
//! node's rows at startup after the UI's (the UI's win on the same key).
//!
//! A rule created by a `persist: true` token has `origin: "api"`; its row is
//! written on every change to it (whichever token makes it) and deleted with
//! it, before the answer. A write that fails leaves the rule running
//! (`persisted: false`, `event = "degraded"`, `part = "db"`).

use std::collections::HashMap;
use std::time::Duration;

use serde::Deserialize;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Row;
use tracing::{info, warn};

use crate::core::registry::Registry;
use crate::core::rule::{parse_listen, Key, Origin, RuleRequest, RuleView};

/// rproxy's own table (definition and GRANT: the UI repository's `db/` migrations;
/// the DDL is in docs/API.md).
pub const TABLE: &str = "rproxy_rules";

/// How `spec` is written; bumped when its reading changes.
pub const SPEC_VERSION: u32 = 1;

/// Longest a write may hold up the answer.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

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

impl StoredRule {
	pub fn key(&self) -> Option<Key> {
		Some(Key { protocol: self.spec.protocol, listen: parse_listen(&self.spec.listen_addr, self.spec.listen_port).ok()? })
	}
}

/// What the rule view shows of a stored rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
	pub created_by: String,
	pub created_at: u64,
	/// Whether the row in `rproxy_rules` is up to date.
	pub persisted: bool,
}

enum Backend {
	/// No `RPROXY_DATABASE_URL`: nothing is stored (`persisted: false`).
	None,
	Db(MySqlPool),
	/// For tests: rows kept in memory; `fail` makes writes fail.
	Memory { rows: std::sync::Mutex<HashMap<Key, StoredRule>>, fail: std::sync::atomic::AtomicBool },
}

pub struct Store {
	node: String,
	backend: Backend,
	meta: std::sync::Mutex<HashMap<Key, Meta>>,
	/// One write at a time, so rows follow the order of the changes.
	writes: tokio::sync::Mutex<()>,
}

/// The host name (`RPROXY_NODE_NAME`'s default).
pub fn host_name() -> String {
	#[cfg(unix)]
	{
		let mut buf = [0u8; 256];
		// SAFETY: the buffer is valid for its length; gethostname writes at most that much
		if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0 {
			let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
			let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
			if !name.is_empty() {
				return name;
			}
		}
	}
	"localhost".into()
}

fn unix_millis() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Store {
	/// `url`: `RPROXY_DATABASE_URL`; the pool connects when first used.
	pub fn new(node: String, url: Option<&str>) -> Result<Store, String> {
		let backend = match url {
			Some(url) => Backend::Db(
				MySqlPoolOptions::new()
					.max_connections(2)
					.acquire_timeout(WRITE_TIMEOUT)
					.connect_lazy(url)
					.map_err(|e| format!("database: {e}"))?,
			),
			None => Backend::None,
		};
		Ok(Store { node, backend, meta: Default::default(), writes: Default::default() })
	}

	/// A store that keeps its rows in memory (tests).
	#[doc(hidden)]
	pub fn memory(node: &str) -> Store {
		Store {
			node: node.into(),
			backend: Backend::Memory { rows: Default::default(), fail: Default::default() },
			meta: Default::default(),
			writes: Default::default(),
		}
	}

	/// Makes the writes of a memory store fail (tests).
	#[doc(hidden)]
	pub fn fail_writes(&self, fail: bool) {
		if let Backend::Memory { fail: f, .. } = &self.backend {
			f.store(fail, std::sync::atomic::Ordering::Relaxed);
		}
	}

	/// The rows of a memory store (tests).
	#[doc(hidden)]
	pub fn memory_rows(&self) -> Vec<StoredRule> {
		match &self.backend {
			Backend::Memory { rows, .. } => rows.lock().unwrap().values().cloned().collect(),
			_ => vec![],
		}
	}

	pub fn node(&self) -> &str {
		&self.node
	}

	/// Whether rows can be written at all (`RPROXY_DATABASE_URL` is set).
	pub fn enabled(&self) -> bool {
		!matches!(self.backend, Backend::None)
	}

	/// Fills in `persisted`, `created_by` and `created_at` of an `api` rule's view.
	pub fn decorate(&self, key: &Key, view: &mut RuleView) {
		let meta = self.meta.lock().unwrap();
		match meta.get(key) {
			Some(m) => {
				view.persisted = Some(m.persisted);
				view.created_by = Some(m.created_by.clone());
				view.created_at = Some(m.created_at);
			}
			None => view.persisted = Some(false),
		}
	}

	/// This node's rows (startup). Rows written by a newer rproxy (`spec_version`)
	/// or that do not read are skipped with `restore.skip`.
	pub async fn load(&self) -> Result<Vec<StoredRule>, String> {
		let rows = match &self.backend {
			Backend::None => return Ok(vec![]),
			Backend::Memory { rows, .. } => return Ok(rows.lock().unwrap().values().filter(|r| r.node == self.node).cloned().collect()),
			Backend::Db(pool) => sqlx::query(
				"SELECT CAST(spec AS CHAR) AS spec, CAST(spec_version AS SIGNED) AS spec_version, created_by, \
				 CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created_at, updated_by, \
				 CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at \
				 FROM rproxy_rules WHERE node = ? ORDER BY protocol, listen_addr, listen_port",
			)
			.bind(&self.node)
			.fetch_all(pool)
			.await
			.map_err(|e| e.to_string())?,
		};
		let mut out = vec![];
		for row in rows {
			match self.read_row(&row) {
				Ok(rule) => out.push(rule),
				Err(e) => warn!(event = "restore.skip", table = TABLE, error = %e),
			}
		}
		Ok(out)
	}

	fn read_row(&self, row: &sqlx::mysql::MySqlRow) -> Result<StoredRule, String> {
		let get_str = |c: &str| row.try_get::<String, _>(c).map_err(|e| format!("{c}: {e}"));
		let get_int = |c: &str| row.try_get::<i64, _>(c).map_err(|e| format!("{c}: {e}"));
		let spec_version = u32::try_from(get_int("spec_version")?).unwrap_or(u32::MAX);
		if spec_version > SPEC_VERSION {
			return Err(format!("spec_version {spec_version} is newer than this build reads ({SPEC_VERSION})"));
		}
		let spec: RuleRequest = serde_json::from_str(&get_str("spec")?).map_err(|e| format!("spec: {e}"))?;
		Ok(StoredRule {
			node: self.node.clone(),
			spec,
			spec_version,
			created_by: get_str("created_by")?,
			created_at: get_int("created_at")?.max(0) as u64,
			updated_by: get_str("updated_by")?,
			updated_at: get_int("updated_at")?.max(0) as u64,
		})
	}

	/// Remembers the rules restored from the table (as stored).
	pub fn restored(&self, rules: &[StoredRule]) {
		let mut meta = self.meta.lock().unwrap();
		for r in rules {
			if let Some(key) = r.key() {
				meta.insert(key, Meta { created_by: r.created_by.clone(), created_at: r.created_at, persisted: true });
			}
		}
	}

	/// Writes the current version of an `api` rule (after it was created or
	/// changed by `by`); does nothing for other rules. Returns whether the row is
	/// up to date.
	pub async fn save(&self, registry: &Registry, key: &Key, by: &str) -> bool {
		let _write = self.writes.lock().await;
		let Some((spec, _, _)) = registry.current(key).await else { return false };
		if spec.origin != Origin::Api {
			return false;
		}
		let now = unix_millis();
		let (created_by, created_at) = {
			let meta = self.meta.lock().unwrap();
			meta.get(key).map(|m| (m.created_by.clone(), m.created_at)).unwrap_or_else(|| (by.to_string(), now / 1000))
		};
		let shape = crate::config::plan::shape(&spec);
		let result = match &self.backend {
			Backend::None => Err("no database (RPROXY_DATABASE_URL) is configured".to_string()),
			Backend::Memory { rows, fail } => {
				if fail.load(std::sync::atomic::Ordering::Relaxed) {
					Err("writes fail (test)".into())
				} else {
					serde_json::from_value::<RuleRequest>(shape.clone()).map_err(|e| e.to_string()).map(|spec| {
						rows.lock().unwrap().insert(
							*key,
							StoredRule {
								node: self.node.clone(),
								spec,
								spec_version: SPEC_VERSION,
								created_by: created_by.clone(),
								created_at,
								updated_by: by.into(),
								updated_at: now / 1000,
							},
						);
					})
				}
			}
			Backend::Db(pool) => {
				let query = sqlx::query(
					"INSERT INTO rproxy_rules (node, protocol, listen_addr, listen_port, spec, spec_version, \
					 created_by, created_at, updated_by, updated_at) \
					 VALUES (?, ?, ?, ?, ?, ?, ?, FROM_UNIXTIME(? / 1000), ?, FROM_UNIXTIME(? / 1000)) \
					 ON DUPLICATE KEY UPDATE spec = VALUES(spec), spec_version = VALUES(spec_version), \
					 updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
				)
				.bind(&self.node)
				.bind(key.protocol.to_string())
				.bind(key.listen.ip().to_string())
				.bind(u32::from(key.listen.port()))
				.bind(shape.to_string())
				.bind(SPEC_VERSION)
				.bind(&created_by)
				.bind(created_at.saturating_mul(1000))
				.bind(by)
				.bind(now);
				match tokio::time::timeout(WRITE_TIMEOUT, query.execute(pool)).await {
					Ok(r) => r.map(|_| ()).map_err(|e| e.to_string()),
					Err(_) => Err("timed out".into()),
				}
			}
		};
		let persisted = result.is_ok();
		match result {
			Ok(()) => info!(event = "rule.persist", rule = %key, action = "save", token = by),
			// without a database nothing is stored, as documented; not a degradation
			Err(_) if !self.enabled() => {}
			Err(e) => warn!(event = "degraded", part = "db", rule = %key, error = %e,
				"the rule runs but is not stored in rproxy_rules (it is lost on restart)"),
		}
		let mut meta = self.meta.lock().unwrap();
		meta.insert(*key, Meta { created_by, created_at, persisted });
		persisted
	}

	/// Deletes the row of a deleted `api` rule.
	pub async fn remove(&self, key: &Key, by: &str) -> bool {
		let _write = self.writes.lock().await;
		self.meta.lock().unwrap().remove(key);
		let result = match &self.backend {
			Backend::None => return false,
			Backend::Memory { rows, fail } => {
				if fail.load(std::sync::atomic::Ordering::Relaxed) {
					Err("writes fail (test)".to_string())
				} else {
					rows.lock().unwrap().remove(key);
					Ok(())
				}
			}
			Backend::Db(pool) => {
				let query = sqlx::query(
					"DELETE FROM rproxy_rules WHERE node = ? AND protocol = ? AND listen_addr = ? AND listen_port = ?",
				)
				.bind(&self.node)
				.bind(key.protocol.to_string())
				.bind(key.listen.ip().to_string())
				.bind(u32::from(key.listen.port()));
				match tokio::time::timeout(WRITE_TIMEOUT, query.execute(pool)).await {
					Ok(r) => r.map(|_| ()).map_err(|e| e.to_string()),
					Err(_) => Err("timed out".into()),
				}
			}
		};
		match result {
			Ok(()) => {
				info!(event = "rule.persist", rule = %key, action = "delete", token = by);
				true
			}
			Err(e) => {
				warn!(event = "degraded", part = "db", rule = %key, error = %e,
					"the row of the deleted rule stays in rproxy_rules (the rule comes back on restart)");
				false
			}
		}
	}
}

/// Rows of `rproxy_rules` without the keys the UI's `forward_rules` has
/// (the UI's rule is used; `restore.conflict`).
pub fn without_conflicts(ui: &[RuleRequest], stored: Vec<StoredRule>) -> Vec<StoredRule> {
	let taken: std::collections::HashSet<Key> = ui
		.iter()
		.filter_map(|r| Some(Key { protocol: r.protocol, listen: parse_listen(&r.listen_addr, r.listen_port).ok()? }))
		.collect();
	stored
		.into_iter()
		.filter(|r| match r.key() {
			Some(key) if taken.contains(&key) => {
				warn!(event = "restore.conflict", rule = %key, created_by = %r.created_by,
					"the same rule is in forward_rules (the UI's) and rproxy_rules; the UI's is used");
				false
			}
			_ => true,
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn req(port: u16) -> RuleRequest {
		serde_json::from_value(serde_json::json!({"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": port,
			"remote_addr": "10.0.0.1", "remote_port": 80}))
		.unwrap()
	}

	fn stored(port: u16) -> StoredRule {
		StoredRule {
			node: "n1".into(),
			spec: req(port),
			spec_version: 1,
			created_by: "ci".into(),
			created_at: 1,
			updated_by: "ci".into(),
			updated_at: 1,
		}
	}

	#[test]
	fn the_ui_wins_on_the_same_key() {
		let kept = without_conflicts(&[req(80), req(443)], vec![stored(443), stored(8443)]);
		assert_eq!(kept.iter().map(|r| r.spec.listen_port).collect::<Vec<_>>(), [8443]);
	}

	#[test]
	fn host_name_is_never_empty() {
		assert!(!host_name().is_empty());
	}
}
