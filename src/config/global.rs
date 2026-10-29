//! `global` through the control API (#342, docs/API.md "global の設定の API"):
//! `GET /config/global` and `PATCH /config/global`.
//!
//! The settings file (and the environment) owns what it names: an item written
//! there is fixed, as a static rule is, and the API cannot change it (`409
//! static`). The API sets the items the file leaves out; those values are kept
//! by `Settings` (the registry's), stored in `rproxy_global` when the database
//! is configured (`persist::Store::save_global`), read back at the start before
//! the rules, and handed over by a live upgrade.
//!
//! Items that can change while running (`Apply::Live`) are swapped in the shared
//! `HttpGlobal` as one snapshot (the next request or connection takes it) or the
//! UDP default session cap (the next session). Items read once at the start
//! (`Apply::Restart`: `acme`, `geoip`, `performance`, `files`, the control API's
//! listener) are only shown; the API does not change them (`409 restart_only`).
//!
//! A change is built first (files opened, a new CrowdSec bouncer started and
//! synced with its LAPI) and swapped in under the registry's rules lock, where
//! what the rules use of CrowdSec is read too (`Registry::under_rules_lock`): a
//! rule is never left with a CrowdSec that went away, and a rule started at the
//! same time sees the bouncer in force (`Registry::crowdsec_gate`).
//!
//! When a reload of the file brings an item the API has a value for, the file
//! wins: the API value is kept but not in force (`shadowed`, `config.global_shadowed`),
//! and is in force again once the file leaves the item out.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::config::{CrowdsecGlobal, GlobalSpec};
use crate::core::registry::Registry;
use crate::l7::access::{AccessLog, AccessLogError, Update};
use crate::l7::middleware::crowdsec::{Bouncer, CrowdsecError};
use crate::l7::timeouts::{HttpGlobalSpec, HttpTimeouts, HttpTimeoutsSpec};
use crate::net::cidr::{self, Cidr};

/// How `rproxy_global.spec` is written; bumped when its reading changes. Read item
/// by item: items this build does not know are kept and written back (#345, a
/// rollback to an older patch).
pub const GLOBAL_SPEC_VERSION: u32 = 1;

/// How long a new CrowdSec bouncer may take for its first pull before the change
/// is given up (the bouncer in force stays).
pub const BOUNCER_SYNC_WAIT: Duration = Duration::from_secs(10);

/// How an item takes a new value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Apply {
	/// Swapped while running: the next request, connection or session takes it.
	Live,
	/// Read once at the start; the API does not change it.
	Restart,
}

/// Where the value in force comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
	File,
	Env,
	Api,
	Default,
}

/// One item of `GET /config/global`.
pub struct Item {
	pub name: &'static str,
	pub apply: Apply,
	/// Changes what rproxy trusts, writes or whom it gives secrets: changed only over
	/// the Unix socket while `RPROXY_API_RELOAD_UNIX_ONLY` is on.
	pub unix_only: bool,
	/// Where it is in the file's `global`: the key, and the key under it (`http.timeouts`).
	pub path: (&'static str, Option<&'static str>),
	/// Whether the settings file can name it (else the environment only).
	pub in_file: bool,
}

/// Every item, in the order shown.
pub const ITEMS: &[Item] = &[
	// who may speak for a client (X-Forwarded-For): widened, it opens what rules guard by address
	Item { name: "trusted_proxies", apply: Apply::Live, unix_only: true, path: ("trusted_proxies", None), in_file: true },
	// writes files (confined to RPROXY_API_ACCESS_LOG_DIR)
	Item { name: "access_log", apply: Apply::Live, unix_only: true, path: ("access_log", None), in_file: true },
	// reads a key file and sends it to the LAPI
	Item { name: "crowdsec", apply: Apply::Live, unix_only: true, path: ("crowdsec", None), in_file: true },
	Item { name: "http.timeouts", apply: Apply::Live, unix_only: false, path: ("http", Some("timeouts")), in_file: true },
	// RPROXY_UDP_MAX_SESSIONS (no file key)
	Item { name: "udp_max_sessions", apply: Apply::Live, unix_only: false, path: ("udp_max_sessions", None), in_file: false },
	// later through the API (#345); read at the start now
	Item { name: "acme", apply: Apply::Restart, unix_only: true, path: ("acme", None), in_file: true },
	Item { name: "geoip", apply: Apply::Restart, unix_only: false, path: ("geoip", None), in_file: true },
	Item { name: "performance", apply: Apply::Restart, unix_only: false, path: ("performance", None), in_file: true },
	Item { name: "files", apply: Apply::Restart, unix_only: false, path: ("files", None), in_file: true },
	// RPROXY_API_ADDR / _PORT / _SOCKET
	Item { name: "control_api", apply: Apply::Restart, unix_only: false, path: ("control_api", None), in_file: false },
];

pub fn item(name: &str) -> Option<&'static Item> {
	ITEMS.iter().find(|i| i.name == name)
}

fn live_items() -> impl Iterator<Item = &'static Item> {
	ITEMS.iter().filter(|i| i.apply == Apply::Live)
}

/// The JSON at an item's place in a `global` object.
fn get_at<'a>(v: &'a Value, i: &Item) -> Option<&'a Value> {
	let top = v.get(i.path.0)?;
	match i.path.1 {
		None => Some(top),
		Some(sub) => top.get(sub),
	}
}

/// Takes the JSON at an item's place out of a `global` object (an `http` left empty goes too).
fn take_at(v: &mut Value, i: &Item) -> Option<Value> {
	let obj = v.as_object_mut()?;
	match i.path.1 {
		None => obj.remove(i.path.0),
		Some(sub) => {
			let inner = obj.get_mut(i.path.0)?.as_object_mut()?;
			let out = inner.remove(sub);
			if inner.is_empty() {
				obj.remove(i.path.0);
			}
			out
		}
	}
}

/// Puts JSON at an item's place in a `global` object.
fn put_at(v: &mut Value, i: &Item, value: Value) {
	if !v.is_object() {
		*v = json!({});
	}
	let Some(obj) = v.as_object_mut() else { return };
	match i.path.1 {
		None => {
			obj.insert(i.path.0.into(), value);
		}
		Some(sub) => {
			let inner = obj.entry(i.path.0).or_insert_with(|| json!({}));
			if !inner.is_object() {
				*inner = json!({});
			}
			if let Some(m) = inner.as_object_mut() {
				m.insert(sub.into(), value);
			}
		}
	}
}

/// The live items' values as the file, the environment or the API give them:
/// the shape of the settings file's `global` (what `PATCH` takes, the row of
/// `rproxy_global` and the handoff hold).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Values {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub trusted_proxies: Option<Vec<String>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub access_log: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub crowdsec: Option<CrowdsecGlobal>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub http: Option<HttpGlobalSpec>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub udp_max_sessions: Option<u64>,
}

/// The live items in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Live {
	pub trusted_proxies: Vec<String>,
	pub access_log: Option<String>,
	pub crowdsec: Option<CrowdsecGlobal>,
	pub timeouts: Option<HttpTimeoutsSpec>,
	pub udp_max_sessions: u64,
}

impl Default for Live {
	fn default() -> Self {
		Live {
			trusted_proxies: vec![],
			access_log: None,
			crowdsec: None,
			timeouts: None,
			udp_max_sessions: crate::l4::udp::DEFAULT_MAX_SESSIONS,
		}
	}
}

impl Values {
	/// The live items the file names (`raw`: its `global` as written, to tell an
	/// item left out from one written empty).
	pub fn of_file(spec: &GlobalSpec, raw: &Value) -> Values {
		let has = |name: &str| item(name).is_some_and(|i| get_at(raw, i).is_some());
		Values {
			trusted_proxies: has("trusted_proxies").then(|| spec.trusted_proxies.clone()),
			access_log: spec.access_log.clone().filter(|_| has("access_log")),
			crowdsec: spec.crowdsec.clone(),
			http: spec.http.as_ref().and_then(|h| h.timeouts.clone()).map(|t| HttpGlobalSpec { timeouts: Some(t) }),
			udp_max_sessions: None,
		}
	}

	pub fn has(&self, item: &str) -> bool {
		match item {
			"trusted_proxies" => self.trusted_proxies.is_some(),
			"access_log" => self.access_log.is_some(),
			"crowdsec" => self.crowdsec.is_some(),
			"http.timeouts" => self.timeouts().is_some(),
			"udp_max_sessions" => self.udp_max_sessions.is_some(),
			_ => false,
		}
	}

	fn timeouts(&self) -> Option<&HttpTimeoutsSpec> {
		self.http.as_ref().and_then(|h| h.timeouts.as_ref())
	}

	/// The item's value as JSON (None: not set here).
	pub fn get(&self, item: &str) -> Option<Value> {
		let v = match item {
			"trusted_proxies" => serde_json::to_value(self.trusted_proxies.as_ref()?),
			"access_log" => serde_json::to_value(self.access_log.as_ref()?),
			"crowdsec" => serde_json::to_value(self.crowdsec.as_ref()?),
			"http.timeouts" => serde_json::to_value(self.timeouts()?),
			"udp_max_sessions" => serde_json::to_value(self.udp_max_sessions?),
			_ => return None,
		};
		v.ok()
	}

	/// Sets (or, with None, clears) one live item from JSON, checking its shape and values.
	pub fn set(&mut self, item: &str, value: Option<Value>) -> Result<(), String> {
		fn parse<T: serde::de::DeserializeOwned>(item: &str, v: Value) -> Result<T, String> {
			serde_json::from_value(v).map_err(|e| format!("global.{item}: {e}"))
		}
		let mut next = self.clone();
		match (item, value) {
			("trusted_proxies", v) => next.trusted_proxies = v.map(|v| parse(item, v)).transpose()?,
			("access_log", v) => next.access_log = v.map(|v| parse(item, v)).transpose()?,
			("crowdsec", v) => next.crowdsec = v.map(|v| parse(item, v)).transpose()?,
			("http.timeouts", v) => {
				next.http = v.map(|v| parse::<HttpTimeoutsSpec>(item, v)).transpose()?.map(|t| HttpGlobalSpec { timeouts: Some(t) })
			}
			("udp_max_sessions", v) => next.udp_max_sessions = v.map(|v| parse(item, v)).transpose()?,
			_ => return Err(format!("global.{item} is not an item the API sets")),
		}
		next.check_item(item)?;
		*self = next;
		Ok(())
	}

	/// Clears one item.
	fn clear(&mut self, item: &str) {
		let _ = self.set(item, None);
	}

	/// The values of one item are valid (as the settings file's would be; paths given
	/// to the API must be absolute).
	fn check_item(&self, item: &str) -> Result<(), String> {
		let absolute = |what: &str, p: &str| {
			if p.trim().is_empty() || !Path::new(p).is_absolute() {
				return Err(format!("{what}: {p:?} is not an absolute path"));
			}
			Ok(())
		};
		match item {
			"trusted_proxies" => {
				for c in self.trusted_proxies.iter().flatten() {
					c.parse::<Cidr>().map_err(|e| format!("global.trusted_proxies: {}", e.message))?;
				}
			}
			"access_log" => {
				if let Some(p) = &self.access_log {
					absolute("global.access_log", p)?;
				}
			}
			"crowdsec" => {
				if let Some(cs) = &self.crowdsec {
					absolute("global.crowdsec.api_key_file", &cs.api_key_file)?;
					crate::net::url::parse_base(cs.lapi_url.trim()).map_err(|e| format!("global.crowdsec.lapi_url: {e}"))?;
					if let Some(u) = &cs.appsec_url {
						crate::net::url::parse_base(u.trim()).map_err(|e| format!("global.crowdsec.appsec_url: {e}"))?;
					}
					if let Some(i) = &cs.update_interval {
						crate::l7::parse_duration(i).map_err(|e| format!("global.crowdsec.update_interval: {e}"))?;
					}
				}
			}
			"http.timeouts" => {
				if let Some(t) = self.timeouts() {
					t.check()?;
				}
			}
			_ => {}
		}
		Ok(())
	}

	/// Reads stored values item by item: the items that read, and the rest as stored
	/// (unknown items, values this build does not take), with why for the known ones.
	pub fn read_stored(spec: &Value) -> (Values, Value, BTreeMap<&'static str, String>) {
		let mut rest = if spec.is_object() { spec.clone() } else { json!({}) };
		let mut values = Values::default();
		let mut errors = BTreeMap::new();
		for i in live_items() {
			let Some(v) = take_at(&mut rest, i) else { continue };
			if let Err(e) = values.set(i.name, Some(v.clone())) {
				errors.insert(i.name, e);
				put_at(&mut rest, i, v);
			}
		}
		(values, rest, errors)
	}
}

/// Where each live item comes from, first that has it: the file, the environment, the API.
fn effective(file: &Values, env: &Values, api: &Values) -> (Live, BTreeMap<&'static str, Source>) {
	let mut sources = BTreeMap::new();
	let mut pick = |item: &'static str| -> Option<&Values> {
		let (source, from) = if file.has(item) {
			(Source::File, Some(file))
		} else if env.has(item) {
			(Source::Env, Some(env))
		} else if api.has(item) {
			(Source::Api, Some(api))
		} else {
			(Source::Default, None)
		};
		sources.insert(item, source);
		from
	};
	let d = Live::default();
	let live = Live {
		trusted_proxies: pick("trusted_proxies").and_then(|v| v.trusted_proxies.clone()).unwrap_or(d.trusted_proxies),
		access_log: pick("access_log").and_then(|v| v.access_log.clone()),
		crowdsec: pick("crowdsec").and_then(|v| v.crowdsec.clone()),
		timeouts: pick("http.timeouts").and_then(|v| v.timeouts().cloned()),
		udp_max_sessions: pick("udp_max_sessions").and_then(|v| v.udp_max_sessions).unwrap_or(d.udp_max_sessions),
	};
	(live, sources)
}

/// The live items that differ between two versions.
fn differing(a: &Live, b: &Live) -> Vec<&'static str> {
	let mut out = vec![];
	if a.trusted_proxies != b.trusted_proxies {
		out.push("trusted_proxies");
	}
	if a.access_log != b.access_log {
		out.push("access_log");
	}
	if a.crowdsec != b.crowdsec {
		out.push("crowdsec");
	}
	if a.timeouts != b.timeouts {
		out.push("http.timeouts");
	}
	if a.udp_max_sessions != b.udp_max_sessions {
		out.push("udp_max_sessions");
	}
	out
}

fn live_value(l: &Live, item: &str) -> Value {
	match item {
		"trusted_proxies" => json!(l.trusted_proxies),
		"access_log" => json!(l.access_log),
		"crowdsec" => serde_json::to_value(&l.crowdsec).unwrap_or(Value::Null),
		"http.timeouts" => serde_json::to_value(&l.timeouts).unwrap_or(Value::Null),
		"udp_max_sessions" => json!(l.udp_max_sessions),
		_ => Value::Null,
	}
}

/// Keeps one item's value of `before` in `to`.
fn keep_item(to: &mut Live, before: &Live, item: &str) {
	match item {
		"trusted_proxies" => to.trusted_proxies = before.trusted_proxies.clone(),
		"access_log" => to.access_log = before.access_log.clone(),
		"crowdsec" => to.crowdsec = before.crowdsec.clone(),
		"http.timeouts" => to.timeouts = before.timeouts.clone(),
		"udp_max_sessions" => to.udp_max_sessions = before.udp_max_sessions,
		_ => {}
	}
}

/// How long a restored bouncer (database, live upgrade) is waited for before it is
/// put in force anyway (it then decides as one started with the settings file).
pub const HANDOFF_SYNC_WAIT: Duration = Duration::from_secs(2);

/// How strict building a new value is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
	/// The API: every problem refuses the change; a new bouncer must sync first.
	Api,
	/// The settings file read again: mistakes refuse the reload; an access log
	/// that cannot be written goes to the main log (`degraded`, tried again), as at
	/// the start; a new bouncer that does not sync leaves the one in force.
	File,
	/// Values restored (database, live upgrade): an item that cannot be built is
	/// not put in force (`error`); a bouncer is not waited for (as at the start).
	Restore,
}

/// A bouncer started for a change; stopped unless the change took it.
struct NewBouncer(Option<Arc<Bouncer>>);

impl NewBouncer {
	fn take(&mut self) -> Option<Arc<Bouncer>> {
		self.0.take()
	}
}

impl Drop for NewBouncer {
	fn drop(&mut self) {
		if let Some(b) = self.0.take() {
			b.stop();
		}
	}
}

/// The live items built for a change, swapped in by `commit`.
#[derive(Default)]
struct Built {
	trusted_proxies: Option<Vec<Cidr>>,
	access_log: Option<AccessLog>,
	/// The access log went to the main log for now (it is tried again).
	access_log_fallback: Option<bool>,
	/// Some(None): no bouncer; Some(Some): the new one.
	crowdsec: Option<NewBouncer>,
	timeouts: Option<HttpTimeouts>,
	udp_max_sessions: Option<u64>,
}

/// Why building one item failed.
enum BuildError {
	/// A mistake in the value.
	Invalid(String),
	/// The new bouncer did not sync in time.
	NotSynced(String),
}

impl BuildError {
	fn message(self) -> String {
		match self {
			BuildError::Invalid(e) | BuildError::NotSynced(e) => e,
		}
	}
}

/// Starts a bouncer and, unless `wait` is zero, waits for its first pull (`required`:
/// one that has not pulled by then is given up; otherwise it is used anyway).
async fn start_bouncer(c: &CrowdsecGlobal, wait: Duration, required: bool) -> Result<NewBouncer, BuildError> {
	let b = match Bouncer::new(c) {
		Ok(b) => b,
		Err(CrowdsecError::Config(e)) => return Err(BuildError::Invalid(e)),
	};
	b.spawn();
	let b = NewBouncer(Some(b));
	if wait.is_zero() {
		return Ok(b);
	}
	let deadline = tokio::time::Instant::now() + wait;
	loop {
		let Some(bouncer) = b.0.as_ref() else { return Ok(b) };
		if bouncer.synced() {
			return Ok(b);
		}
		if tokio::time::Instant::now() >= deadline && !required {
			warn!(event = "crowdsec.error", "the new bouncer has not pulled from its LAPI yet; in force anyway (as at the start)");
			return Ok(b);
		}
		if tokio::time::Instant::now() >= deadline {
			let why = bouncer.status().last_error.unwrap_or_else(|| "no answer".into());
			return Err(BuildError::NotSynced(format!(
				"global.crowdsec: the LAPI did not answer within {}s ({why}); the CrowdSec in force stays",
				wait.as_secs()
			)));
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}

/// Builds one item (files opened, the bouncer started and synced; nothing swapped yet).
async fn build_item(item: &str, to: &Live, built: &mut Built, opts: &Options, mode: Mode) -> Result<(), BuildError> {
	match item {
		"trusted_proxies" => {
			built.trusted_proxies = Some(cidr::parse_list(&to.trusted_proxies).map_err(|e| BuildError::Invalid(e.message))?)
		}
		"access_log" => {
			let (log, fallback) = match AccessLog::open(to.access_log.as_deref().map(Path::new), opts.keep_files) {
				Ok(log) => (log, false),
				Err(AccessLogError::Config(e)) => return Err(BuildError::Invalid(format!("global.access_log: {e}"))),
				Err(AccessLogError::Unavailable(e)) if mode == Mode::Api => {
					return Err(BuildError::Invalid(format!("global.access_log: {e}")));
				}
				Err(AccessLogError::Unavailable(e)) => {
					warn!(event = "degraded", part = "global.access_log", error = %e,
						"access log lines go to the main log (tried again on each check of the settings file)");
					(AccessLog::main_log(), true)
				}
			};
			built.access_log = Some(log);
			built.access_log_fallback = Some(fallback);
		}
		"crowdsec" => {
			// restores (no bouncer to keep) wait a little and go on: a live upgrade's new
			// process mostly gets the decisions before it takes connections
			let (wait, required) = match mode {
				Mode::Restore => (HANDOFF_SYNC_WAIT.min(opts.sync_wait), false),
				_ => (opts.sync_wait, true),
			};
			built.crowdsec = Some(match &to.crowdsec {
				None => NewBouncer(None),
				Some(c) => start_bouncer(c, wait, required).await?,
			});
		}
		"http.timeouts" => built.timeouts = Some(to.timeouts.as_ref().map(HttpTimeoutsSpec::resolve).unwrap_or_default()),
		"udp_max_sessions" => built.udp_max_sessions = Some(to.udp_max_sessions),
		_ => return Err(BuildError::Invalid(format!("global.{item} cannot change while running"))),
	}
	Ok(())
}

/// What the rules use of `global.crowdsec`: any crowdsec, and AppSec (`Registry::under_rules_lock`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CrowdsecUse {
	pub any: bool,
	pub appsec: bool,
}

impl CrowdsecUse {
	/// Why the rules cannot run with `c` in force, if they cannot.
	fn refuses(&self, c: Option<&CrowdsecGlobal>) -> Option<&'static str> {
		match c {
			None if self.any => Some("rules use crowdsec"),
			Some(c) if self.appsec && c.appsec_url.is_none() => Some("rules use crowdsec appsec, which needs appsec_url"),
			_ => None,
		}
	}
}

/// Why a `PATCH /config/global` was refused.
#[derive(Debug)]
pub enum PatchError {
	/// `400 invalid`.
	Invalid(String),
	/// `409 static`: the file (or the environment) owns these items.
	Static(Vec<String>),
	/// `409 restart_only`: these items are read at the start only.
	RestartOnly(Vec<String>),
	/// `409 in_use`: rules use what the change takes away.
	InUse(String),
	/// `403 protected_file` (#319): a path names one of rproxy's own files, or is
	/// outside the directory access logs may be in.
	Protected(String),
	/// `502 crowdsec_unavailable`: the new LAPI did not answer; nothing changed.
	Unavailable(String),
	/// `503 not_loaded`: the stored values could not be read yet (a change would
	/// overwrite them); tried again by the periodic check.
	NotLoaded,
}

/// One item's change, for the answer and `dry_run`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Change {
	pub item: &'static str,
	/// The values in force before and after (an API value that is shadowed changes nothing in force).
	pub before: Value,
	pub after: Value,
	/// The API value before and after (null: none).
	pub api_before: Value,
	pub api_after: Value,
}

/// A change accepted (or, `dry_run`, what it would do).
#[derive(Debug, Serialize)]
pub struct Patched {
	pub changes: Vec<Change>,
	/// Items whose value in force changed.
	pub applied: Vec<&'static str>,
}

/// What a live upgrade hands over (`handoff::State::global`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handoff {
	/// The API values as stored (the shape of `global`; items this build does not take too).
	pub values: Value,
	#[serde(default)]
	pub updated_by: Option<String>,
	#[serde(default)]
	pub updated_at: Option<u64>,
	/// Whether the row of `rproxy_global` was up to date (None: no database).
	#[serde(default)]
	pub persisted: Option<bool>,
	/// The stored values had not been read (the new process reads them).
	#[serde(default)]
	pub not_loaded: bool,
	/// A `crowdsec` the file dropped and rules still use, kept in force.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub kept_crowdsec: Option<CrowdsecGlobal>,
}

/// What the start gives (`main`).
#[derive(Clone, Debug)]
pub struct Options {
	/// Access log files kept (`RPROXY_LOG_KEEP`).
	pub keep_files: usize,
	/// The directory access logs set through the API must be in
	/// (`RPROXY_API_ACCESS_LOG_DIR`, else that of `RPROXY_LOG_FILE`); None: none.
	pub access_log_dir: Option<PathBuf>,
	/// rproxy's own log (`RPROXY_LOG_FILE`): an access log may not rotate it away.
	pub main_log: Option<PathBuf>,
	/// A database stores the API values.
	pub database: bool,
	/// `BOUNCER_SYNC_WAIT` (shorter in tests).
	pub sync_wait: Duration,
}

impl Default for Options {
	fn default() -> Self {
		Options { keep_files: 14, access_log_dir: None, main_log: None, database: false, sync_wait: BOUNCER_SYNC_WAIT }
	}
}

#[derive(Default)]
struct State {
	/// The file's live items, and its `global` as written.
	file: Values,
	file_raw: Value,
	/// The environment's live items (RPROXY_UDP_MAX_SESSIONS).
	env: Values,
	/// The API's values (also those not in force: `failed`).
	api: Values,
	/// What was stored that this build does not take (unknown items, values that do
	/// not read): written back as it was.
	kept: Value,
	/// API values not in force, and why (a restored value refused or not built).
	failed: BTreeMap<&'static str, String>,
	/// A `crowdsec` the file dropped while rules use it: in force until they do not.
	kept_crowdsec: Option<CrowdsecGlobal>,
	/// The start-only items not from the file: (source, value) as started.
	startup: BTreeMap<&'static str, (Source, Value)>,
	/// What is in force, and where each item comes from.
	live: Live,
	sources: BTreeMap<&'static str, Source>,
	/// The access log in force goes to the main log for now.
	access_log_fallback: bool,
	updated_by: Option<String>,
	updated_at: Option<u64>,
	/// Whether the row is up to date; None: no database (the values live in this process only).
	persisted: Option<bool>,
	/// The stored values could not be read at the start (`PATCH` waits for them).
	not_loaded: bool,
	/// `config.global_shadowed` said for these items (until they are not shadowed).
	shadow_warned: BTreeSet<&'static str>,
	opts: Options,
}

impl State {
	/// The API values in force (without those that failed).
	fn api_in_force(&self) -> Values {
		let mut v = self.api.clone();
		for item in self.failed.keys() {
			v.clear(item);
		}
		v
	}

	/// What would be in force with these file and API values (the kept crowdsec too).
	fn effective_with(&self, file: &Values, api: &Values) -> (Live, BTreeMap<&'static str, Source>) {
		let (mut live, sources) = effective(file, &self.env, api);
		if live.crowdsec.is_none() {
			live.crowdsec = self.kept_crowdsec.clone();
		}
		(live, sources)
	}

	fn shadowed(&self) -> Vec<(&'static str, Source)> {
		live_items()
			.filter(|i| self.api.has(i.name))
			.filter_map(|i| match self.sources.get(i.name) {
				Some(s @ (Source::File | Source::Env)) => Some((i.name, *s)),
				_ => None,
			})
			.collect()
	}

	/// `config.global_shadowed` once for each item that became shadowed.
	fn warn_shadowed(&mut self) {
		let now = self.shadowed();
		for (item, source) in &now {
			if self.shadow_warned.insert(item) {
				let by = if *source == Source::File { "the settings file" } else { "the environment" };
				warn!(event = "config.global_shadowed", item, source = ?source,
					"{by} sets global.{item}, which wins over the value set through the API; that value is kept, not in force");
			}
		}
		self.shadow_warned.retain(|i| now.iter().any(|(n, _)| n == i));
	}

	/// Why the API may not name a path (#319): rproxy's secrets and stores, and for
	/// the access log, anything outside `access_log_dir`.
	fn path_refused(&self, registry: &Registry, values: &Values) -> Option<(&'static str, String)> {
		let entries = crate::net::protected::current(registry.acme().map(|a| a.as_ref()), None);
		let paths = [("access_log", values.access_log.as_deref()), ("crowdsec", values.crowdsec.as_ref().map(|c| c.api_key_file.as_str()))];
		for (item, path) in paths {
			let Some(path) = path else { continue };
			if let Some(what) = crate::net::protected::protecting(path, &entries) {
				return Some((item, format!("{path} is {what}; the API may not name it in global")));
			}
		}
		if let Some(p) = &values.access_log {
			if let Err(e) = self.access_log_allowed(p) {
				return Some(("access_log", e));
			}
		}
		None
	}

	/// An access log set through the API is a file right in `access_log_dir`
	/// (not a link) whose rotation does not touch rproxy's own log.
	fn access_log_allowed(&self, p: &str) -> Result<(), String> {
		let Some(dir) = &self.opts.access_log_dir else {
			return Err("no directory for access logs set through the API: set RPROXY_API_ACCESS_LOG_DIR".into());
		};
		let path = Path::new(p);
		let outside = || format!("{p} is not in {} (RPROXY_API_ACCESS_LOG_DIR)", dir.display());
		let (Some(parent), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
			return Err(outside());
		};
		let real = |d: &Path| std::fs::canonicalize(d).ok();
		if name.starts_with('.') || real(parent).is_none() || real(parent) != real(dir) {
			return Err(outside());
		}
		if std::fs::symlink_metadata(path).is_ok_and(|m| !m.file_type().is_file()) {
			return Err(format!("{p} is not a regular file"));
		}
		// the rotation would prune every file that starts with the stem (#347)
		if name.ends_with('.') {
			return Err(format!("{p} has an empty extension; choose another name"));
		}
		// the appender prunes the files that start with the name's stem and end with its extension
		let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
		if let Some(main) = &self.opts.main_log {
			let main_name = main.file_name().and_then(|n| n.to_str()).unwrap_or_default();
			let main_stem = main.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
			let same_dir = main.parent().and_then(real) == real(parent);
			if same_dir && (main_name.starts_with(stem) || stem.starts_with(main_stem)) {
				return Err(format!("{p} would rotate rproxy's own log {}; choose another name", main.display()));
			}
		}
		// the files the rotation would delete must be its own (<stem>.<YYYY-MM-DD>.<ext>)
		let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");
		if let Ok(entries) = std::fs::read_dir(parent) {
			for e in entries.flatten() {
				let other = e.file_name().to_string_lossy().into_owned();
				if other.starts_with(stem) && other.ends_with(ext) && !rotated_name(&other, stem, ext) {
					return Err(format!(
						"{} is in {} and would be deleted by the rotation of {p}; choose another name",
						other,
						dir.display()
					));
				}
			}
		}
		Ok(())
	}

	/// Puts the values in force (sources, the API's, kept) after a commit.
	fn settle(&mut self, live: Live, file: Values, api: Values) {
		let (_, sources) = effective(&file, &self.env, &api);
		self.file = file;
		self.api = api;
		self.live = live;
		self.sources = sources;
		if self.live.crowdsec.is_some() && self.live.crowdsec == self.kept_crowdsec && !self.api.has("crowdsec") {
			self.sources.insert("crowdsec", Source::File);
		}
		self.warn_shadowed();
	}
}

/// Whether `name` is `<stem>.<YYYY-MM-DD>.<ext>` (a file the access log's rotation wrote).
fn rotated_name(name: &str, stem: &str, ext: &str) -> bool {
	let Some(date) =
		name.strip_prefix(stem).and_then(|r| r.strip_prefix('.')).and_then(|r| r.strip_suffix(ext)).and_then(|r| r.strip_suffix('.'))
	else {
		return false;
	};
	let b = date.as_bytes();
	b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// The `global` items: the file's, the environment's and the API's, and what is in force.
#[derive(Default)]
pub struct Settings {
	state: std::sync::Mutex<State>,
	/// One change at a time (`PATCH`, a reload of the file from `prepare_file` to
	/// `commit_file`, a restore).
	turn: Arc<tokio::sync::Mutex<()>>,
}

/// Unix seconds.
fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A version of the settings file's live items, built and waiting for the rules
/// to validate (`ConfigReloader::reload`).
pub struct FilePrepared {
	/// No other change runs until the commit (or until this is dropped).
	_turn: tokio::sync::OwnedMutexGuard<()>,
	file: Values,
	raw: Value,
	to: Live,
	built: Built,
	changed: Vec<&'static str>,
	/// File items left as they were (a new LAPI that did not answer), and why.
	not_in_force: Vec<(&'static str, String)>,
}

/// What a commit replaced, let go of after the rules lock.
struct Swapped {
	bouncer: Option<Arc<Bouncer>>,
	snapshot: Arc<crate::l7::access::Snapshot>,
}

impl Swapped {
	/// Stops the bouncer replaced; the snapshot before goes off the data plane (its
	/// access log file is flushed and closed there).
	fn finish(self) {
		if let Some(b) = self.bouncer {
			b.stop();
		}
		let old = self.snapshot;
		if tokio::runtime::Handle::try_current().is_ok() {
			drop(tokio::task::spawn_blocking(move || drop(old)));
		}
	}
}

/// Swaps what was built in, under the rules lock.
fn commit(registry: &Registry, built: Built) -> Swapped {
	let Built { trusted_proxies, access_log, crowdsec, timeouts, udp_max_sessions, .. } = built;
	let crowdsec = crowdsec.map(|mut b| b.take());
	if let Some(Some(b)) = &crowdsec {
		info!(event = "crowdsec.swap", synced = b.synced(), "a new CrowdSec bouncer is in force");
	}
	let (bouncer, snapshot) = registry.http_global().update(Update { trusted_proxies, access_log, crowdsec, timeouts });
	if let Some(n) = udp_max_sessions {
		crate::l4::udp::set_max_sessions(n);
	}
	Swapped { bouncer, snapshot }
}

impl Settings {
	fn state(&self) -> std::sync::MutexGuard<'_, State> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// What the start applied (`main`): the file's `global` (with `raw`, as written),
	/// the environment's live items and the start-only items not from the file.
	pub fn init(&self, file: Option<(&GlobalSpec, &Value)>, env: Values, startup: BTreeMap<&'static str, (Source, Value)>, opts: Options) {
		let mut s = self.state();
		if let Some((spec, raw)) = file {
			s.file = Values::of_file(spec, raw);
			s.file_raw = raw.clone();
		}
		s.env = env;
		s.startup = startup;
		s.persisted = opts.database.then_some(true);
		s.opts = opts;
		let (live, sources) = effective(&s.file, &s.env, &s.api);
		s.live = live;
		s.sources = sources;
	}

	/// The stored values could not be read at the start: `PATCH` answers `503
	/// not_loaded` and nothing is written until `restore` reads them.
	pub fn set_not_loaded(&self) {
		self.state().not_loaded = true;
	}

	pub fn loaded(&self) -> bool {
		!self.state().not_loaded
	}

	/// Puts stored API values in force (`spec`: the row of `rproxy_global`, or what a
	/// live upgrade handed over), before the rules are restored (rules using
	/// `crowdsec` need it). Read item by item: what does not read, or names a path
	/// the API may not (#319), is kept as stored but not in force (`error`), as is
	/// an item that cannot be built. Items the file owns stay shadowed.
	#[allow(clippy::too_many_arguments)]
	pub async fn restore(
		&self,
		registry: &Arc<Registry>,
		spec: &Value,
		updated_by: Option<String>,
		updated_at: Option<u64>,
		persisted: Option<bool>,
		kept_crowdsec: Option<CrowdsecGlobal>,
		from: &str,
	) {
		let turn = self.turn.lock().await;
		let (api, kept, mut failed) = Values::read_stored(spec);
		for (item, e) in &failed {
			warn!(event = "restore.skip", what = "global", item, from, error = %e, "a stored global value does not read; kept as stored, not in force");
		}
		let (before, file, opts) = {
			let mut s = self.state();
			if s.live.crowdsec.is_none() {
				s.kept_crowdsec = kept_crowdsec;
			}
			// the paths the API may not name, checked again (#319)
			let mut check = api.clone();
			while let Some((item, e)) = s.path_refused(registry, &check) {
				warn!(event = "restore.skip", what = "global", item, from, error = %e, "not put in force");
				check.clear(item);
				failed.insert(item, e);
			}
			(s.live.clone(), s.file.clone(), s.opts.clone())
		};
		let mut in_force = api.clone();
		for item in failed.keys() {
			in_force.clear(item);
		}
		let (mut to, _) = self.state().effective_with(&file, &in_force);
		let mut built = Built::default();
		for item in differing(&before, &to) {
			if let Err(e) = build_item(item, &to, &mut built, &opts, Mode::Restore).await {
				let e = e.message();
				warn!(event = "degraded", part = "global", item, from, error = %e,
					"a global value set through the API cannot be put in force; the value before it stays");
				keep_item(&mut to, &before, item);
				failed.insert(item, e);
			}
		}
		let fallback = built.access_log_fallback;
		let brings_crowdsec = to.crowdsec.is_some() && to.crowdsec != before.crowdsec;
		registry.under_rules_lock(|_| commit(registry, built)).await.finish();
		{
			let mut s = self.state();
			s.kept = kept;
			s.failed = failed;
			if let Some(f) = fallback {
				s.access_log_fallback = f;
			}
			s.settle(to, file, api);
			s.updated_by = updated_by;
			s.updated_at = updated_at;
			s.not_loaded = false;
			if s.persisted.is_some() {
				s.persisted = Some(persisted.unwrap_or(true));
			}
			if s.api != Values::default() {
				info!(event = "restore.global", from, items = ?live_items().filter(|i| s.api.has(i.name)).map(|i| i.name).collect::<Vec<_>>());
			}
		}
		// rules that could not start without it (read late by the periodic check);
		// not under the turn: name resolution may take a while, and each rule is
		// checked again (its generation, `crowdsec_gate`) under the rules lock (#347)
		drop(turn);
		if brings_crowdsec {
			registry.retry_waiting_for_crowdsec().await;
		}
	}

	/// Builds the live items of a version of the settings file (`ConfigReloader::reload`,
	/// before the rules are checked): files opened, a new bouncer started and synced.
	/// A mistake (an access log directory that does not exist, a CrowdSec key file that
	/// cannot be read) refuses the reload with nothing changed; a new LAPI that does not
	/// answer leaves the CrowdSec in force (`config.global_kept`).
	pub async fn prepare_file(&self, spec: &GlobalSpec, raw: &Value) -> Result<FilePrepared, String> {
		// held to the commit: a PATCH in between would be undone by it
		let turn = match self.turn.clone().try_lock_owned() {
			Ok(t) => t,
			Err(_) => {
				info!(event = "config.reload", "waiting for a change of global under way (a PATCH may wait up to 10 s for a new LAPI)");
				self.turn.clone().lock_owned().await
			}
		};
		let (before, mut to, opts, file) = {
			let s = self.state();
			let file = Values::of_file(spec, raw);
			let (to, _) = s.effective_with(&file, &s.api_in_force());
			(s.live.clone(), to, s.opts.clone(), file)
		};
		let mut built = Built::default();
		let mut changed = vec![];
		let mut not_in_force = vec![];
		for item in differing(&before, &to) {
			match build_item(item, &to, &mut built, &opts, Mode::File).await {
				Ok(()) => changed.push(item),
				Err(BuildError::NotSynced(e)) => {
					warn!(event = "config.global_kept", item, error = %e, "the CrowdSec in force stays until its LAPI answers (reload again)");
					keep_item(&mut to, &before, item);
					not_in_force.push((item, e));
				}
				Err(BuildError::Invalid(e)) => return Err(e),
			}
		}
		Ok(FilePrepared { _turn: turn, file, raw: raw.clone(), to, built, changed, not_in_force })
	}

	/// Swaps a prepared version of the file in (after the rules were checked), under
	/// the rules lock. A `crowdsec` the rules use (or its `appsec_url`) is not taken
	/// away: it stays in force (`kept`, `config.global_in_use`) until no rule uses it.
	/// Answers the items whose value in force changed.
	pub async fn commit_file(&self, registry: &Arc<Registry>, prepared: FilePrepared) -> Vec<&'static str> {
		let FilePrepared { _turn: turn, file, raw, mut to, mut built, mut changed, not_in_force } = prepared;
		let before = self.state().live.clone();
		let replaced = registry
			.under_rules_lock(|uses| {
				if let Some(why) = uses.refuses(to.crowdsec.as_ref()).filter(|_| before.crowdsec.is_some()) {
					warn!(
						event = "config.global_in_use",
						item = "crowdsec",
						reason = why,
						"global.crowdsec stays in force until no rule needs it (then reload again)"
					);
					to.crowdsec = before.crowdsec.clone();
					built.crowdsec = None;
					changed.retain(|i| *i != "crowdsec");
					self.state().kept_crowdsec = before.crowdsec.clone();
				} else if uses.refuses(None).is_none() {
					// no rule uses it any more: a kept one goes
					let mut s = self.state();
					if s.kept_crowdsec.is_some() && to.crowdsec == s.kept_crowdsec && !file.has("crowdsec") && !s.api.has("crowdsec") {
						to.crowdsec = None;
						s.kept_crowdsec = None;
						drop(s);
						if !changed.contains(&"crowdsec") {
							built.crowdsec = Some(NewBouncer(None));
							changed.push("crowdsec");
						}
					}
				}
				commit(registry, built_with_fallback(&mut built))
			})
			.await;
		replaced.finish();
		let brings_crowdsec = {
			let mut s = self.state();
			s.file_raw = raw;
			if let Some(f) = built.access_log_fallback {
				s.access_log_fallback = f;
			}
			for item in &changed {
				s.failed.remove(item);
			}
			for (item, e) in not_in_force {
				s.failed.insert(item, e);
			}
			let api = s.api.clone();
			let brings = changed.contains(&"crowdsec") && to.crowdsec.is_some();
			s.settle(to, file, api);
			brings
		};
		// not under the turn (#347, as in `restore`)
		drop(turn);
		if brings_crowdsec {
			registry.retry_waiting_for_crowdsec().await;
		}
		changed
	}

	/// Tries again an access log that went to the main log (it could not be written).
	pub fn retry_access_log(&self, registry: &Registry) {
		let mut s = self.state();
		if !s.access_log_fallback {
			return;
		}
		let Some(path) = s.live.access_log.clone() else {
			s.access_log_fallback = false;
			return;
		};
		if let Ok(log) = AccessLog::open(Some(Path::new(&path)), s.opts.keep_files) {
			let (_, old) = registry.http_global().update(Update { access_log: Some(log), ..Default::default() });
			Swapped { bouncer: None, snapshot: old }.finish();
			s.access_log_fallback = false;
			info!(event = "config.global", item = "access_log", "the access log can be written again");
		}
	}

	/// The live items a version of the file would change in force (`POST /config/reload?dry_run`).
	pub fn preview(&self, spec: &GlobalSpec, raw: &Value) -> Vec<&'static str> {
		let s = self.state();
		let (to, _) = s.effective_with(&Values::of_file(spec, raw), &s.api_in_force());
		differing(&s.live, &to)
	}

	/// `PATCH /config/global`: `body` in the shape of the file's `global`, an item
	/// set to null clears the API's value. With `dry_run`, nothing changes.
	pub async fn patch(
		&self,
		registry: &Arc<Registry>,
		body: &serde_json::Map<String, Value>,
		by: &str,
		dry_run: bool,
	) -> Result<Patched, PatchError> {
		let named = named_items(body).map_err(PatchError::Invalid)?;
		let turn = self.turn.lock().await;
		let (before, opts, api_before, file, api, to) = {
			let s = self.state();
			if s.not_loaded {
				return Err(PatchError::NotLoaded);
			}
			let restart: Vec<String> =
				named.iter().filter(|(i, _)| item(i).is_some_and(|d| d.apply == Apply::Restart)).map(|(i, _)| i.clone()).collect();
			if !restart.is_empty() {
				return Err(PatchError::RestartOnly(restart));
			}
			let owned: Vec<String> = named.iter().filter(|(i, _)| s.file.has(i) || s.env.has(i)).map(|(i, _)| i.clone()).collect();
			if !owned.is_empty() {
				return Err(PatchError::Static(owned));
			}
			let mut api = s.api.clone();
			for (i, v) in &named {
				api.set(i, v.clone().filter(|v| !v.is_null())).map_err(PatchError::Invalid)?;
			}
			// the API may not point rproxy at its own secrets or stores (#319), nor write
			// access logs outside their directory
			let mut touched = Values::default();
			for (i, _) in &named {
				let _ = touched.set(i, api.get(i));
			}
			if let Some((_, e)) = s.path_refused(registry, &touched) {
				return Err(PatchError::Protected(e));
			}
			// the named items are in force as given; the others as they are
			let mut in_force = s.api_in_force();
			for (i, _) in &named {
				let _ = in_force.set(i, api.get(i));
			}
			let (mut to, _) = s.effective_with(&s.file, &in_force);
			// the items not named stay as they are in force (one the reload could not put
			// in force is not tried again here)
			for d in live_items().filter(|d| !named.iter().any(|(i, _)| i == d.name)) {
				keep_item(&mut to, &s.live, d.name);
			}
			(s.live.clone(), s.opts.clone(), s.api.clone(), s.file.clone(), api, to)
		};
		let changes: Vec<Change> = named
			.iter()
			.filter_map(|(i, _)| item(i))
			.map(|d| Change {
				item: d.name,
				before: shown(d, live_value(&before, d.name)),
				after: shown(d, live_value(&to, d.name)),
				api_before: shown(d, api_before.get(d.name).unwrap_or(Value::Null)),
				api_after: shown(d, api.get(d.name).unwrap_or(Value::Null)),
			})
			.collect();
		let applied = differing(&before, &to);
		if dry_run {
			// checked as far as it goes without opening files or starting a bouncer
			let uses = registry.under_rules_lock(|uses| uses).await;
			if let Some(why) = uses.refuses(to.crowdsec.as_ref()).filter(|_| applied.contains(&"crowdsec")) {
				return Err(PatchError::InUse(format!("{why}; change those rules first")));
			}
			if let (true, Some(p)) = (applied.contains(&"access_log"), &to.access_log) {
				if let Err(AccessLogError::Config(e) | AccessLogError::Unavailable(e)) = crate::l7::access::access_log_dir(Path::new(p)) {
					return Err(PatchError::Invalid(format!("global.access_log: {e}")));
				}
			}
			if let (true, Some(c)) = (applied.contains(&"crowdsec"), &to.crowdsec) {
				Bouncer::new(c).map_err(|CrowdsecError::Config(e)| PatchError::Invalid(e))?;
			}
			return Ok(Patched { changes, applied });
		}
		let mut built = Built::default();
		for item in &applied {
			build_item(item, &to, &mut built, &opts, Mode::Api).await.map_err(|e| match e {
				BuildError::Invalid(e) => PatchError::Invalid(e),
				BuildError::NotSynced(e) => PatchError::Unavailable(e),
			})?;
		}
		// swapped in with the rules lock held: no rule is created or changed meanwhile
		let replaced = registry
			.under_rules_lock(|uses| {
				if let Some(why) = uses.refuses(to.crowdsec.as_ref()).filter(|_| applied.contains(&"crowdsec")) {
					return Err(PatchError::InUse(format!("{why}; change those rules first")));
				}
				Ok(commit(registry, built_with_fallback(&mut built)))
			})
			.await?;
		replaced.finish();
		let brings_crowdsec = {
			let mut s = self.state();
			for (i, _) in &named {
				if let Some(d) = item(i) {
					s.failed.remove(d.name);
					take_at(&mut s.kept, d);
				}
			}
			if to.crowdsec != s.kept_crowdsec {
				s.kept_crowdsec = None;
			}
			if let Some(f) = built.access_log_fallback {
				s.access_log_fallback = f;
			}
			s.settle(to, file, api);
			s.updated_by = Some(by.to_string());
			s.updated_at = Some(unix_now());
			if s.persisted.is_some() {
				// written next (`persist::Store::save_global`)
				s.persisted = Some(false);
			}
			info!(event = "config.global", token = by, items = ?changes.iter().map(|c| c.item).collect::<Vec<_>>(), applied = ?applied);
			applied.contains(&"crowdsec") && s.live.crowdsec.is_some()
		};
		// not under the turn (#347, as in `restore`)
		drop(turn);
		if brings_crowdsec {
			registry.retry_waiting_for_crowdsec().await;
		}
		Ok(Patched { changes, applied })
	}

	/// The values as stored (the row of `rproxy_global`: the API's, and what was
	/// stored that this build does not take) and who set them last. None while the
	/// stored values have not been read (they would be overwritten).
	pub fn stored(&self) -> Option<(Value, String)> {
		let s = self.state();
		if s.not_loaded {
			return None;
		}
		Some((merged(&s.api, &s.kept), s.updated_by.clone().unwrap_or_default()))
	}

	/// Whether the row is up to date (`persist::Store::save_global`).
	pub fn set_persisted(&self, persisted: bool) {
		let mut s = self.state();
		if s.persisted.is_some() {
			s.persisted = Some(persisted);
		}
	}

	pub fn persisted(&self) -> Option<bool> {
		self.state().persisted
	}

	/// Whether there is anything to hand over.
	pub fn has_api_values(&self) -> bool {
		let s = self.state();
		s.api != Values::default() || s.kept.as_object().is_some_and(|m| !m.is_empty()) || s.not_loaded || s.kept_crowdsec.is_some()
	}

	/// For the new process of a live upgrade.
	pub fn handoff(&self) -> Handoff {
		let s = self.state();
		Handoff {
			values: merged(&s.api, &s.kept),
			updated_by: s.updated_by.clone(),
			updated_at: s.updated_at,
			persisted: s.persisted,
			not_loaded: s.not_loaded,
			kept_crowdsec: s.kept_crowdsec.clone(),
		}
	}

	/// `GET /config/global`.
	pub fn view(&self) -> Value {
		let s = self.state();
		let mut items = serde_json::Map::new();
		for i in ITEMS {
			let mut v = serde_json::Map::new();
			let (source, value) = match i.apply {
				Apply::Live => (s.sources.get(i.name).copied().unwrap_or(Source::Default), live_value(&s.live, i.name)),
				Apply::Restart => match get_at(&s.file_raw, i).filter(|_| i.in_file) {
					Some(raw) => (Source::File, raw.clone()),
					None => s.startup.get(i.name).cloned().unwrap_or((Source::Default, Value::Null)),
				},
			};
			// what may be a secret is masked (#347)
			let shown = |v: Value| shown(i, v);
			v.insert("value".into(), shown(value));
			v.insert("source".into(), json!(source));
			v.insert("apply".into(), json!(i.apply));
			v.insert("unix_only".into(), json!(i.unix_only));
			// whether the API may set it now
			let settable = i.apply == Apply::Live && !s.file.has(i.name) && !s.env.has(i.name);
			v.insert("settable".into(), json!(settable));
			if let Some(api) = s.api.get(i.name).or_else(|| get_at(&s.kept, i).cloned()) {
				v.insert("api_value".into(), shown(api));
				v.insert("shadowed".into(), json!(matches!(source, Source::File | Source::Env)));
			}
			if i.name == "crowdsec" && s.kept_crowdsec.is_some() && s.live.crowdsec == s.kept_crowdsec && !s.file.has("crowdsec") {
				// the file dropped it; rules still use it
				v.insert("kept".into(), json!(true));
			}
			if let Some(e) = s.failed.get(i.name) {
				v.insert("error".into(), json!(e));
			}
			items.insert(i.name.into(), Value::Object(v));
		}
		let warnings: Vec<Value> = s
			.shadowed()
			.into_iter()
			.map(|(item, source)| {
				let by = if source == Source::File { "the settings file" } else { "the environment" };
				json!({"code": "config.global_shadowed", "item": item,
					"message": format!("{by} sets global.{item}; the value set through the API is kept, not in force")})
			})
			.collect();
		json!({
			"items": items,
			// where the API values are kept: the database, or this process only (lost on restart)
			"storage": if s.persisted.is_some() { "database" } else { "memory" },
			"persisted": s.persisted,
			"loaded": !s.not_loaded,
			"updated_by": s.updated_by,
			"updated_at": s.updated_at,
			"warnings": warnings,
		})
	}
}

/// What `GET /config/global` shows in place of a value that may be a secret (#347).
pub const MASKED: &str = "***";

/// An item's value as `GET` / `PATCH /config/global` show it (#347): a restart
/// item `redacted`, the user and query of `crowdsec`'s URLs masked.
fn shown(i: &Item, v: Value) -> Value {
	match (i.apply, i.name, v) {
		(Apply::Restart, name, v) => redacted(name, v),
		(_, "crowdsec", Value::Object(mut m)) => {
			for k in ["lapi_url", "appsec_url"] {
				if let Some(Value::String(u)) = m.get_mut(k) {
					*u = masked_url(u);
				}
			}
			Value::Object(m)
		}
		(_, _, v) => v,
	}
}

/// A restart item's value as `GET /config/global` shows it (#347): written by hand,
/// so it may hold secrets inline. `acme` (accounts, contacts, EAB, DNS calls) keeps
/// only its shape: every string is masked. In the others, headers, request bodies,
/// anything named like a secret (`secret`, `token`, `key`, `password`, `credential`,
/// `eab`; the files' places too) and the user and query of URLs are masked.
fn redacted(item: &str, v: Value) -> Value {
	if item == "acme" {
		return masked(v);
	}
	redact_named(v)
}

/// Parts of names whose values `redacted` masks.
const SECRET_NAMES: [&str; 8] = ["headers", "body", "secret", "token", "key", "password", "credential", "eab"];

fn redact_named(v: Value) -> Value {
	match v {
		Value::Object(m) => Value::Object(
			m.into_iter()
				.map(|(k, v)| {
					let lower = k.to_ascii_lowercase();
					let v = if SECRET_NAMES.iter().any(|n| lower.contains(n)) {
						masked(v)
					} else if lower == "url" || lower.ends_with("_url") {
						match v {
							Value::String(u) => Value::String(masked_url(&u)),
							other => redact_named(other),
						}
					} else {
						redact_named(v)
					};
					(k, v)
				})
				.collect(),
		),
		Value::Array(a) => Value::Array(a.into_iter().map(redact_named).collect()),
		other => other,
	}
}

/// Every string masked; the shape (keys, numbers, booleans, null) kept.
fn masked(v: Value) -> Value {
	match v {
		Value::String(_) => Value::String(MASKED.into()),
		Value::Object(m) => Value::Object(m.into_iter().map(|(k, v)| (k, masked(v))).collect()),
		Value::Array(a) => Value::Array(a.into_iter().map(masked).collect()),
		other => other,
	}
}

/// A URL without its user (and password), query and fragment.
fn masked_url(u: &str) -> String {
	let u = u.split_once('#').map_or(u, |(base, _)| base);
	let (u, query) = match u.split_once('?') {
		Some((base, _)) => (base, true),
		None => (u, false),
	};
	let mut out = match u.split_once("://") {
		Some((scheme, rest)) => {
			let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
			match authority.rsplit_once('@') {
				Some((_, host)) => format!("{scheme}://{MASKED}@{host}{path}"),
				None => u.to_string(),
			}
		}
		None => u.to_string(),
	};
	if query {
		out.push('?');
		out.push_str(MASKED);
	}
	out
}

/// Takes what `commit` swaps in out of `built`, leaving the fallback flag.
fn built_with_fallback(built: &mut Built) -> Built {
	Built {
		trusted_proxies: built.trusted_proxies.take(),
		access_log: built.access_log.take(),
		access_log_fallback: built.access_log_fallback,
		crowdsec: built.crowdsec.take(),
		timeouts: built.timeouts.take(),
		udp_max_sessions: built.udp_max_sessions.take(),
	}
}

/// The values as stored: `kept` with the API's items put in.
fn merged(api: &Values, kept: &Value) -> Value {
	let mut out = if kept.is_object() { kept.clone() } else { json!({}) };
	for i in live_items() {
		if let Some(v) = api.get(i.name) {
			put_at(&mut out, i, v);
		}
	}
	out
}

/// The items a `PATCH` body names, with their values (None or null: clear). The
/// body has the shape of the file's `global`: `http` is `{"timeouts": ...}`.
pub fn named_items(body: &serde_json::Map<String, Value>) -> Result<Vec<(String, Option<Value>)>, String> {
	let mut out = vec![];
	for (k, v) in body {
		match k.as_str() {
			"http" => match v {
				Value::Null => out.push(("http.timeouts".to_string(), None)),
				Value::Object(m) => {
					for (sub, v) in m {
						if sub != "timeouts" {
							return Err(format!("global.http.{sub} is not known"));
						}
						out.push(("http.timeouts".to_string(), Some(v.clone())));
					}
				}
				_ => return Err("global.http: an object ({\"timeouts\": ...}) or null".into()),
			},
			"http.timeouts" => out.push((k.clone(), Some(v.clone()))),
			name if item(name).is_some() => out.push((k.clone(), Some(v.clone()))),
			name => return Err(format!("global.{name} is not known")),
		}
	}
	if out.is_empty() {
		return Err("name at least one item of global".into());
	}
	Ok(out)
}

/// The items of a `PATCH` body that only the Unix socket may change (`Item::unix_only`).
pub fn unix_only_items(body: &serde_json::Map<String, Value>) -> Vec<&'static str> {
	named_items(body).unwrap_or_default().iter().filter_map(|(i, _)| item(i)).filter(|i| i.unix_only).map(|i| i.name).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn file(text: &str) -> (GlobalSpec, Value) {
		let raw: Value = crate::config::yaml(text).unwrap();
		(serde_json::from_value(raw.clone()).unwrap(), raw)
	}

	fn body(v: Value) -> serde_json::Map<String, Value> {
		v.as_object().unwrap().clone()
	}

	fn registry() -> Arc<Registry> {
		Registry::new(crate::core::registry::Config {
			dns_interval: Duration::from_secs(30),
			lookup: crate::core::resolve::system_lookup(),
			transparent: false,
			transparent_ipv6: false,
			max_range_ports: 100,
			reserved: vec![],
			http: Arc::new(crate::l7::access::HttpGlobal::default()),
		})
	}

	#[test]
	fn restart_items_are_shown_without_their_secrets() {
		let acme = json!({"accounts": {"le": {"contact": ["mailto:a@example.com"], "eab": {"kid": "k1", "hmac_key_file": "/s/h"}}},
			"dns_providers": {"x": {"kind": "http", "zones": ["example.com"], "ttl": 60,
				"add": {"url": "https://h/add?token=t", "headers": {"Authorization": "Bearer t"}}}}});
		let acme = redacted("acme", acme);
		assert_eq!(acme["accounts"]["le"]["contact"], json!([MASKED]));
		assert_eq!(acme["accounts"]["le"]["eab"], json!({"kid": MASKED, "hmac_key_file": MASKED}));
		assert_eq!(acme["dns_providers"]["x"]["add"]["headers"], json!({"Authorization": MASKED}));
		assert_eq!((&acme["dns_providers"]["x"]["zones"], &acme["dns_providers"]["x"]["ttl"]), (&json!([MASKED]), &json!(60)));
		assert!(!acme.to_string().contains("example.com") && !acme.to_string().contains("Bearer"));
		let other = json!({"tls": {"cert_file": "/c.pem", "key_file": "/k.pem", "client_secret": "s"}, "api_token": "t",
			"url": "https://u:p@h:1/x?token=t", "lapi_url": "http://h/", "workers": 2,
			"call": {"headers": {"X-Api-Key": "k"}, "body": "{\"token\":\"t\"}"}});
		assert_eq!(
			redacted("performance", other),
			json!({"tls": {"cert_file": "/c.pem", "key_file": MASKED, "client_secret": MASKED}, "api_token": MASKED,
				"url": format!("https://{MASKED}@h:1/x?{MASKED}"), "lapi_url": "http://h/", "workers": 2,
				"call": {"headers": {"X-Api-Key": MASKED}, "body": MASKED}})
		);
		// in the view: the file's acme, and a kept one (stored by a later release)
		let r = registry();
		let s = r.global();
		let (spec, raw) = file("acme: {accounts: {le: {contact: [\"mailto:a@example.com\"]}}}\n");
		s.init(Some((&spec, &raw)), Values::default(), BTreeMap::new(), Options::default());
		let view = s.view();
		assert_eq!(view["items"]["acme"]["value"]["accounts"]["le"]["contact"], json!([MASKED]), "{view}");
		assert!(!view.to_string().contains("a@example.com"), "{view}");
		assert_eq!(masked_url("http://u:p@h:8080/v1?k=t#f"), format!("http://{MASKED}@h:8080/v1?{MASKED}"));
		assert_eq!(masked_url("http://h:8080/#f"), "http://h:8080/");
		let cs = item("crowdsec").unwrap();
		let v = shown(cs, json!({"lapi_url": "http://u:p@lapi/?k=t", "appsec_url": "http://w/#x", "api_key_file": "/k"}));
		assert_eq!(v, json!({"lapi_url": format!("http://{MASKED}@lapi/?{MASKED}"), "appsec_url": "http://w/", "api_key_file": "/k"}));
	}

	#[test]
	fn items_written_in_the_file_are_the_file_s() {
		let (spec, raw) = file("trusted_proxies: []\nhttp: {}\n");
		let v = Values::of_file(&spec, &raw);
		assert!(v.has("trusted_proxies"), "written empty is written");
		assert!(!v.has("http.timeouts") && !v.has("access_log") && !v.has("crowdsec"));
		let (spec, raw) = file("http: {timeouts: {idle: 5s}}\naccess_log: /tmp/a.log\n");
		let v = Values::of_file(&spec, &raw);
		assert!(v.has("http.timeouts") && v.has("access_log") && !v.has("trusted_proxies"));
	}

	#[test]
	fn the_file_then_the_environment_then_the_api() {
		let (spec, raw) = file("trusted_proxies: [10.0.0.0/8]\n");
		let f = Values::of_file(&spec, &raw);
		let env = Values { udp_max_sessions: Some(5), ..Default::default() };
		let mut api = Values::default();
		api.set("trusted_proxies", Some(json!(["192.0.2.0/24"]))).unwrap();
		api.set("udp_max_sessions", Some(json!(7))).unwrap();
		api.set("http.timeouts", Some(json!({"idle": "5s"}))).unwrap();
		let (live, sources) = effective(&f, &env, &api);
		assert_eq!(live.trusted_proxies, ["10.0.0.0/8"]);
		assert_eq!(live.udp_max_sessions, 5);
		assert_eq!(live.timeouts.unwrap().idle.as_deref(), Some("5s"));
		assert_eq!(sources["trusted_proxies"], Source::File);
		assert_eq!(sources["udp_max_sessions"], Source::Env);
		assert_eq!(sources["http.timeouts"], Source::Api);
		assert_eq!(sources["access_log"], Source::Default);
	}

	#[test]
	fn values_are_checked() {
		let mut v = Values::default();
		assert!(v.set("trusted_proxies", Some(json!(["nope"]))).unwrap_err().contains("trusted_proxies"));
		assert!(v.set("access_log", Some(json!("relative.log"))).unwrap_err().contains("absolute"));
		assert!(v.set("http.timeouts", Some(json!({"idle": "soon"}))).unwrap_err().contains("idle"));
		assert!(v.set("http.timeouts", Some(json!({"idel": "1s"}))).unwrap_err().contains("unknown field"));
		let e = v.set("crowdsec", Some(json!({"lapi_url": "http://127.0.0.1:8080", "api_key_file": "k"}))).unwrap_err();
		assert!(e.contains("absolute"), "{e}");
		let e = v.set("crowdsec", Some(json!({"lapi_url": "nope", "api_key_file": "/k"}))).unwrap_err();
		assert!(e.contains("lapi_url"), "{e}");
		assert!(v.set("udp_max_sessions", Some(json!(-1))).is_err());
		assert!(v.set("performance", Some(json!({}))).is_err());
		assert_eq!(v, Values::default(), "a refused value changes nothing");
	}

	#[test]
	fn stored_values_are_read_item_by_item_and_the_rest_is_kept() {
		let spec =
			json!({"trusted_proxies": ["nope"], "http": {"timeouts": {"idle": "5s"}, "later": 1}, "acme": {"x": 1}, "udp_max_sessions": 9});
		let (values, kept, errors) = Values::read_stored(&spec);
		assert_eq!(values.udp_max_sessions, Some(9));
		assert_eq!(values.timeouts().unwrap().idle.as_deref(), Some("5s"));
		assert!(values.trusted_proxies.is_none() && errors.contains_key("trusted_proxies"));
		assert_eq!(kept, json!({"trusted_proxies": ["nope"], "http": {"later": 1}, "acme": {"x": 1}}));
		// written back as it was, with the API's items
		assert_eq!(merged(&values, &kept), spec);
	}

	#[test]
	fn the_body_names_items_in_the_shape_of_global() {
		let named = named_items(&body(json!({"http": {"timeouts": {"idle": "1s"}}, "access_log": null}))).unwrap();
		assert_eq!(named, [("access_log".to_string(), Some(Value::Null)), ("http.timeouts".to_string(), Some(json!({"idle": "1s"})))]);
		assert_eq!(named_items(&body(json!({"http": null}))).unwrap(), [("http.timeouts".to_string(), None)]);
		assert!(named_items(&body(json!({"http": {"other": 1}}))).unwrap_err().contains("global.http.other"));
		assert!(named_items(&body(json!({"nope": 1}))).unwrap_err().contains("global.nope"));
		assert!(named_items(&body(json!({}))).is_err());
		assert_eq!(
			unix_only_items(&body(json!({"crowdsec": null, "trusted_proxies": [], "udp_max_sessions": 1}))),
			["crowdsec", "trusted_proxies"]
		);
	}

	#[tokio::test]
	async fn patch_refuses_file_items_and_start_only_items() {
		let r = registry();
		let s = r.global();
		let (spec, raw) = file("trusted_proxies: [10.0.0.0/8]\n");
		s.init(Some((&spec, &raw)), Values::default(), BTreeMap::new(), Options::default());
		let e = s.patch(&r, &body(json!({"trusted_proxies": [], "access_log": null})), "t", false).await;
		assert!(matches!(e, Err(PatchError::Static(ref i)) if i == &["trusted_proxies"]), "{e:?}");
		let e = s.patch(&r, &body(json!({"performance": {"workers": 2}})), "t", false).await;
		assert!(matches!(e, Err(PatchError::RestartOnly(ref i)) if i == &["performance"]), "{e:?}");
		// no directory for access logs through the API
		let e = s.patch(&r, &body(json!({"access_log": "/tmp/a.log"})), "t", false).await;
		assert!(matches!(e, Err(PatchError::Protected(ref m)) if m.contains("RPROXY_API_ACCESS_LOG_DIR")), "{e:?}");
		// a live item the file leaves out: in force for the next connection
		let p = s.patch(&r, &body(json!({"http": {"timeouts": {"idle": "7s"}}})), "t", false).await.unwrap();
		assert_eq!(p.applied, ["http.timeouts"]);
		let http = r.http_global();
		assert_eq!(http.timeouts().idle, Some(Duration::from_secs(7)));
		let view = s.view();
		assert_eq!(view["items"]["http.timeouts"]["source"], "api");
		assert_eq!(view["items"]["trusted_proxies"]["source"], "file");
		assert_eq!(view["items"]["trusted_proxies"]["settable"], false);
		assert_eq!(view["items"]["performance"]["apply"], "restart");
		assert_eq!(view["storage"], "memory");
		// dry run: nothing changes
		let p = s.patch(&r, &body(json!({"http": null})), "t", true).await.unwrap();
		assert_eq!(p.applied, ["http.timeouts"]);
		assert_eq!(http.timeouts().idle, Some(Duration::from_secs(7)));
		// clearing goes back to the default
		s.patch(&r, &body(json!({"http": null})), "t", false).await.unwrap();
		assert_eq!(http.timeouts(), Default::default());
		assert!(!s.has_api_values());
	}

	#[tokio::test]
	async fn access_logs_through_the_api_stay_in_their_directory() {
		let dir = std::env::temp_dir().join(format!("rproxy-global-logs-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(dir.join("sub")).unwrap();
		let r = registry();
		let s = r.global();
		let opts = Options { access_log_dir: Some(dir.clone()), main_log: Some(dir.join("rproxy.log")), ..Default::default() };
		s.init(None, Values::default(), BTreeMap::new(), opts);
		let refused = |p: PathBuf| {
			let p = p.to_str().unwrap().to_string();
			let s = &s;
			let r = &r;
			async move { s.patch(r, &body(json!({"access_log": p})), "t", true).await }
		};
		for p in [
			PathBuf::from("/etc/profile.d/x.sh"),
			dir.join("sub/a.log"),
			dir.join("../a.log"),
			dir.join("r.log"),
			dir.join("rproxy-access.log"),
			dir.join(".hidden.log"),
			dir.join("x."),
		] {
			assert!(matches!(refused(p.clone()).await, Err(PatchError::Protected(_))), "{}", p.display());
		}
		// what the rotation would delete must be its own files
		std::fs::write(dir.join("web-old.log"), "").unwrap();
		std::fs::write(dir.join("api.2026-10-01.log"), "").unwrap();
		assert!(matches!(refused(dir.join("web.log")).await, Err(PatchError::Protected(ref m)) if m.contains("web-old.log")));
		assert!(refused(dir.join("api.log")).await.is_ok(), "its own rotated files are fine");
		assert!(rotated_name("a.2026-10-01.log", "a", "log") && !rotated_name("a.x.log", "a", "log") && !rotated_name("a.log", "a", "log"));
		std::os::unix::fs::symlink("/etc/passwd", dir.join("link.log")).unwrap();
		assert!(matches!(refused(dir.join("link.log")).await, Err(PatchError::Protected(_))));
		assert!(refused(dir.join("access.log")).await.is_ok());
		assert!(matches!(refused(dir.join("web.")).await, Err(PatchError::Protected(ref m)) if m.contains("empty extension")));
		// restored values are checked the same way: not in force
		s.restore(&r, &json!({"access_log": "/etc/s.conf"}), None, None, None, None, "database").await;
		let view = s.view();
		assert_eq!(view["items"]["access_log"]["value"], Value::Null);
		assert!(view["items"]["access_log"]["error"].as_str().unwrap().contains("RPROXY_API_ACCESS_LOG_DIR"), "{view}");
		assert_eq!(s.stored().unwrap().0, json!({"access_log": "/etc/s.conf"}), "kept as stored");
		std::fs::remove_dir_all(dir).unwrap();
	}

	#[tokio::test]
	async fn a_file_item_shadows_the_api_value_and_lets_go_of_it() {
		let r = registry();
		let s = r.global();
		s.init(None, Values::default(), BTreeMap::new(), Options { database: true, ..Default::default() });
		let http = r.http_global();
		s.patch(&r, &body(json!({"trusted_proxies": ["192.0.2.0/24"]})), "t", false).await.unwrap();
		assert!(http.trusts("192.0.2.1".parse().unwrap()));
		assert_eq!(s.persisted(), Some(false), "not written yet");
		let (spec, raw) = file("trusted_proxies: [10.0.0.0/8]\n");
		let prepared = s.prepare_file(&spec, &raw).await.unwrap();
		assert!(http.trusts("192.0.2.1".parse().unwrap()), "nothing in force before the commit");
		assert_eq!(s.commit_file(&r, prepared).await, ["trusted_proxies"]);
		assert!(!http.trusts("192.0.2.1".parse().unwrap()) && http.trusts("10.1.2.3".parse().unwrap()));
		let view = s.view();
		assert_eq!(view["items"]["trusted_proxies"]["shadowed"], true);
		assert_eq!(view["items"]["trusted_proxies"]["api_value"], json!(["192.0.2.0/24"]));
		assert_eq!(view["warnings"][0]["code"], "config.global_shadowed");
		// the file leaves it out again: the API value is in force
		let (spec, raw) = file("{}");
		let prepared = s.prepare_file(&spec, &raw).await.unwrap();
		s.commit_file(&r, prepared).await;
		assert!(http.trusts("192.0.2.1".parse().unwrap()));
		assert_eq!(s.view()["warnings"], json!([]));
	}

	#[tokio::test]
	async fn restored_values_that_cannot_be_built_are_not_in_force() {
		let r = registry();
		let s = r.global();
		let dir = std::env::temp_dir();
		s.init(None, Values::default(), BTreeMap::new(), Options { database: true, access_log_dir: Some(dir), ..Default::default() });
		let spec = json!({"access_log": "/nonexistent-rproxy/a.log", "trusted_proxies": ["192.0.2.0/24"], "later": {"x": 1}});
		s.restore(&r, &spec, Some("ui".into()), Some(1), Some(true), None, "database").await;
		let view = s.view();
		assert_eq!(view["items"]["access_log"]["value"], Value::Null);
		assert!(view["items"]["access_log"]["error"].is_string(), "{view}");
		assert_eq!(view["items"]["trusted_proxies"]["source"], "api");
		assert!(r.http_global().trusts("192.0.2.1".parse().unwrap()));
		assert_eq!(view["persisted"], true);
		assert_eq!(s.stored().unwrap().0, spec, "everything stored is written back");
	}

	#[tokio::test]
	async fn nothing_is_changed_or_written_until_the_stored_values_are_read() {
		let r = registry();
		let s = r.global();
		s.init(None, Values::default(), BTreeMap::new(), Options { database: true, ..Default::default() });
		s.set_not_loaded();
		assert!(matches!(s.patch(&r, &body(json!({"udp_max_sessions": 5})), "t", false).await, Err(PatchError::NotLoaded)));
		assert!(s.stored().is_none() && s.handoff().not_loaded);
		s.restore(&r, &json!({"http": {"timeouts": {"idle": "3s"}}}), None, None, Some(true), None, "database").await;
		assert!(s.loaded());
		s.patch(&r, &body(json!({"http": {"timeouts": {"idle": "4s"}}})), "t", false).await.unwrap();
	}
}
