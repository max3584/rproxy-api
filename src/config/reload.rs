//! Applying the settings file again: shared by the file watcher, SIGHUP and
//! `POST /config/reload`, so they never run at the same time and agree on what
//! was last applied.

use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::check::{self, CheckInput, Finding};
use crate::config::{fingerprint, ConfigDoc, LoadError};
use crate::core::registry::{ConfigStatus, Registry, ReloadCounts};

/// What one reload did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Applied {
	#[serde(flatten)]
	pub counts: ReloadCounts,
	/// `global` settings changed in the file that take effect only after a restart.
	pub restart_needed: Vec<String>,
	/// Files read, in order.
	pub files: Vec<String>,
	/// Rules in the files.
	pub rules: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
	/// Nothing changed since the last check (only for checks that are not forced).
	Unchanged,
	Applied(Applied),
	/// The file could not be read or has a mistake; the rules of the last good
	/// version stay in effect.
	Failed(String),
}

struct State {
	/// Fingerprint of what was last applied (or found broken); None: try again on every check.
	seen: Option<u64>,
	last_error: Option<String>,
}

pub struct ConfigReloader {
	path: PathBuf,
	/// The version the process started with; `global` changes against it need a restart.
	base: ConfigDoc,
	registry: Arc<Registry>,
	/// For the detailed findings of `--check-config` when a reload fails.
	check: CheckInput,
	state: Mutex<State>,
}

fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl ConfigReloader {
	/// `check.path` is the settings file or directory.
	pub fn new(base: ConfigDoc, registry: Arc<Registry>, check: CheckInput) -> ConfigReloader {
		let path = check.path.clone();
		let started_ok = registry.config_status().is_some_and(|s| s.error.is_none());
		let seen = started_ok.then(|| fingerprint(&path));
		ConfigReloader { path, base, registry, check, state: Mutex::new(State { seen, last_error: None }) }
	}

	pub fn path(&self) -> &PathBuf {
		&self.path
	}

	/// The settings the process started with (`global` changes against them need a restart).
	pub fn base(&self) -> &ConfigDoc {
		&self.base
	}

	/// Reads the settings again and applies the differences. `forced` (SIGHUP,
	/// the API) reads even when the files look unchanged.
	pub async fn reload(&self, forced: bool) -> Outcome {
		let mut state = self.state.lock().await;
		let now = fingerprint(&self.path);
		if !forced && state.seen == Some(now) {
			return Outcome::Unchanged;
		}
		let mut status = self.registry.config_status().unwrap_or_default();
		status.path = self.path.display().to_string();
		let result = match ConfigDoc::load(&self.path) {
			Ok(doc) => {
				let restart: Vec<String> = doc.restart_needed(&self.base).into_iter().map(String::from).collect();
				let files: Vec<String> = doc.files.iter().map(|f| f.display().to_string()).collect();
				let rules = doc.rules.len();
				match self.registry.reload_static(doc.labeled_rules()).await {
					Ok(counts) => {
						info!(event = "config.reload", added = counts.added, removed = counts.removed, changed = counts.changed,
							unchanged = counts.unchanged, failed = counts.failed, files = files.len(), forced);
						if !restart.is_empty() {
							warn!(event = "config.reload", restart_needed = ?restart, "these settings take effect after a restart");
						}
						status = ConfigStatus {
							path: status.path,
							files: files.clone(),
							loaded_at: Some(unix_now()),
							rules,
							last_reload: Some(counts),
							error: None,
							restart_needed: restart.clone(),
						};
						state.seen = Some(now);
						state.last_error = None;
						Ok(Applied { counts, restart_needed: restart, files, rules })
					}
					Err(e) => Err((format!("{}: {e}", self.path.display()), true)),
				}
			}
			Err(LoadError::Invalid(e)) => Err((e, true)),
			// e.g. permissions: the fingerprint may not change when fixed, so keep trying
			Err(e @ LoadError::Read(..)) => Err((e.to_string(), false)),
		};
		let outcome = match result {
			Ok(applied) => Outcome::Applied(applied),
			Err((error, settled)) => {
				if state.last_error.as_deref() != Some(error.as_str()) {
					error!(event = "config.error", error = %error, "keeping the rules of the last good settings");
				}
				if settled {
					state.seen = Some(now);
				}
				status.error = Some(error.clone());
				state.last_error = Some(error.clone());
				Outcome::Failed(error)
			}
		};
		self.registry.set_config_status(status);
		outcome
	}

	/// Every problem `--check-config` finds in the current files (for a failed reload's answer).
	pub async fn findings(&self) -> (Vec<Finding>, Vec<Finding>) {
		let report = check::check(&self.check).await;
		(report.errors, report.warnings)
	}
}
