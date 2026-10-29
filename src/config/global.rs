//! `global` through the control API (#342, docs/API.md "global の設定の API"):
//! `GET /config/global` and `PATCH /config/global`.
//!
//! The settings file (and the environment) owns what it names: an item written
//! there is fixed, as a static rule is, and the API cannot change it (`409
//! static`). The API sets the items the file leaves out; those values are kept
//! by `Settings` (the registry's), stored in `rproxy_global` when the database
//! is configured (`RPROXY_PERSIST` of the rules, `persist::Store::save_global`),
//! read back at the start before the rules, and handed over by a live upgrade.
//!
//! Items that can change while running (`Apply::Live`) are swapped in the shared
//! `HttpGlobal` (the next request or connection takes them) or the UDP default
//! session cap (the next session). Items read once at the start
//! (`Apply::Restart`: `acme`, `geoip`, `performance`, `files`, the control API's
//! listener) are only shown; the API does not change them (`409 restart_only`).
//!
//! When a reload of the file brings an item the API has a value for, the file
//! wins: the API value is kept but not in force (`shadowed`, `config.global_shadowed`),
//! and is in force again once the file leaves the item out.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};

use crate::config::{CrowdsecGlobal, GlobalSpec};
use crate::l7::access::{AccessLog, AccessLogError, HttpGlobal};
use crate::l7::middleware::crowdsec::{Bouncer, CrowdsecError};
use crate::l7::timeouts::{HttpGlobalSpec, HttpTimeoutsSpec};
use crate::net::cidr::{self, Cidr};

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
	/// Names secrets (key files) or where secrets go: changed only over the Unix
	/// socket while `RPROXY_API_RELOAD_UNIX_ONLY` is on.
	pub unix_only: bool,
	/// Where it is in the file's `global` (JSON pointer); None: not a file item.
	pub pointer: Option<&'static str>,
}

/// Every item, in the order shown.
pub const ITEMS: &[Item] = &[
	Item { name: "trusted_proxies", apply: Apply::Live, unix_only: false, pointer: Some("/trusted_proxies") },
	Item { name: "access_log", apply: Apply::Live, unix_only: false, pointer: Some("/access_log") },
	Item { name: "crowdsec", apply: Apply::Live, unix_only: true, pointer: Some("/crowdsec") },
	Item { name: "http.timeouts", apply: Apply::Live, unix_only: false, pointer: Some("/http/timeouts") },
	// RPROXY_UDP_MAX_SESSIONS (no file key)
	Item { name: "udp_max_sessions", apply: Apply::Live, unix_only: false, pointer: None },
	// later through the API (a follow-up issue); read at the start now
	Item { name: "acme", apply: Apply::Restart, unix_only: true, pointer: Some("/acme") },
	Item { name: "geoip", apply: Apply::Restart, unix_only: false, pointer: Some("/geoip") },
	Item { name: "performance", apply: Apply::Restart, unix_only: false, pointer: Some("/performance") },
	Item { name: "files", apply: Apply::Restart, unix_only: false, pointer: Some("/files") },
	// RPROXY_API_ADDR / _PORT / _SOCKET
	Item { name: "control_api", apply: Apply::Restart, unix_only: false, pointer: None },
];

pub fn item(name: &str) -> Option<&'static Item> {
	ITEMS.iter().find(|i| i.name == name)
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
		let has = |p: &str| raw.pointer(p).is_some();
		Values {
			trusted_proxies: has("/trusted_proxies").then(|| spec.trusted_proxies.clone()),
			access_log: spec.access_log.clone().filter(|_| has("/access_log")),
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
		match (item, value) {
			("trusted_proxies", v) => self.trusted_proxies = v.map(|v| parse(item, v)).transpose()?,
			("access_log", v) => self.access_log = v.map(|v| parse(item, v)).transpose()?,
			("crowdsec", v) => self.crowdsec = v.map(|v| parse(item, v)).transpose()?,
			("http.timeouts", v) => {
				self.http = v.map(|v| parse::<HttpTimeoutsSpec>(item, v)).transpose()?.map(|t| HttpGlobalSpec { timeouts: Some(t) })
			}
			("udp_max_sessions", v) => self.udp_max_sessions = v.map(|v| parse(item, v)).transpose()?,
			_ => return Err(format!("global.{item} is not an item the API sets")),
		}
		self.check_item(item)
	}

	/// Clears one item.
	fn clear(&mut self, item: &str) {
		let _ = self.set(item, None);
	}

	/// The values of the items set here are valid (as the settings file's would be;
	/// paths given to the API must be absolute).
	pub fn check(&self) -> Result<(), String> {
		for i in ITEMS.iter().filter(|i| i.apply == Apply::Live) {
			self.check_item(i.name)?;
		}
		Ok(())
	}

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

/// How strict building a new value is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
	/// The API: every problem refuses the change.
	Api,
	/// The settings file read again: mistakes refuse the reload; an access log
	/// that cannot be written goes to the main log (`degraded`), as at the start.
	File,
	/// Values restored (database, live upgrade): an item that cannot be built
	/// keeps the value before it (`failed`).
	Restore,
}

/// A live item built, to be swapped in.
enum Built {
	Trusted(Vec<Cidr>),
	AccessLog(AccessLog),
	Crowdsec(Option<Arc<Bouncer>>),
	Timeouts(crate::l7::timeouts::HttpTimeouts),
	UdpMaxSessions(u64),
}

/// Builds the value of one item (files read, the bouncer set up, nothing swapped yet).
fn build(item: &str, to: &Live, keep_files: usize, mode: Mode) -> Result<Built, String> {
	Ok(match item {
		"trusted_proxies" => Built::Trusted(cidr::parse_list(&to.trusted_proxies).map_err(|e| e.message)?),
		"access_log" => match AccessLog::open(to.access_log.as_deref().map(Path::new), keep_files) {
			Ok(log) => Built::AccessLog(log),
			Err(AccessLogError::Config(e)) => return Err(format!("global.access_log: {e}")),
			Err(AccessLogError::Unavailable(e)) if mode == Mode::Api => return Err(format!("global.access_log: {e}")),
			Err(AccessLogError::Unavailable(e)) => {
				warn!(event = "degraded", part = "global.access_log", error = %e, "access log lines go to the main log");
				Built::AccessLog(AccessLog::main_log())
			}
		},
		"crowdsec" => match &to.crowdsec {
			None => Built::Crowdsec(None),
			Some(c) => match Bouncer::new(c) {
				Ok(b) => Built::Crowdsec(Some(b)),
				Err(CrowdsecError::Config(e)) => return Err(e),
			},
		},
		"http.timeouts" => Built::Timeouts(to.timeouts.as_ref().map(HttpTimeoutsSpec::resolve).unwrap_or_default()),
		"udp_max_sessions" => Built::UdpMaxSessions(to.udp_max_sessions),
		_ => return Err(format!("global.{item} cannot change while running")),
	})
}

/// Swaps the built values in.
fn commit(built: Vec<Built>, http: &HttpGlobal) {
	for b in built {
		match b {
			Built::Trusted(list) => http.set_trusted_proxies(list),
			Built::AccessLog(log) => http.set_access_log(log),
			Built::Crowdsec(bouncer) => {
				if let Some(b) = &bouncer {
					b.spawn();
				}
				if let Some(old) = http.set_crowdsec(bouncer) {
					old.stop();
				}
			}
			Built::Timeouts(t) => http.set_timeouts(t),
			Built::UdpMaxSessions(n) => crate::l4::udp::set_max_sessions(n),
		}
	}
}

/// What the rules use of `global.crowdsec`: any crowdsec, and AppSec (`Registry::uses_crowdsec`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CrowdsecUse {
	pub any: bool,
	pub appsec: bool,
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
	/// `403 protected_file` (#319): a path names one of rproxy's own files.
	Protected(String),
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
	/// The API values (`Values`).
	pub values: Value,
	#[serde(default)]
	pub updated_by: Option<String>,
	#[serde(default)]
	pub updated_at: Option<u64>,
	/// Whether the row of `rproxy_global` was up to date (None: no database).
	#[serde(default)]
	pub persisted: Option<bool>,
}

#[derive(Default)]
struct State {
	/// The file's live items, and its `global` as written.
	file: Values,
	file_raw: Value,
	/// The environment's live items (RPROXY_UDP_MAX_SESSIONS).
	env: Values,
	api: Values,
	/// The start-only items not from the file: (source, value) as started.
	startup: BTreeMap<&'static str, (Source, Value)>,
	/// What is in force, and where each item comes from.
	live: Live,
	sources: BTreeMap<&'static str, Source>,
	/// Restored API values that could not be built: why (the value before stays).
	failed: BTreeMap<&'static str, String>,
	updated_by: Option<String>,
	updated_at: Option<u64>,
	/// Whether the row is up to date; None: no database (the values live in this process only).
	persisted: Option<bool>,
	/// `config.global_shadowed` said for these items (until they are not shadowed).
	shadow_warned: BTreeSet<&'static str>,
	keep_files: usize,
}

impl State {
	fn shadowed(&self) -> Vec<(&'static str, Source)> {
		ITEMS
			.iter()
			.filter(|i| i.apply == Apply::Live && self.api.has(i.name))
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
}

/// The `global` items: the file's, the environment's and the API's, and what is in force.
#[derive(Default)]
pub struct Settings {
	state: std::sync::Mutex<State>,
	/// One change at a time (`PATCH`, a reload of the file, a restore).
	turn: tokio::sync::Mutex<()>,
}

/// Unix seconds.
fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Settings {
	fn state(&self) -> std::sync::MutexGuard<'_, State> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// What the start applied (`main`): the file's `global` (with `raw`, as written),
	/// the environment's live items, the start-only items not from the file, and
	/// whether a database stores the API values.
	pub fn init(
		&self,
		file: Option<(&GlobalSpec, &Value)>,
		env: Values,
		startup: BTreeMap<&'static str, (Source, Value)>,
		keep_files: usize,
		database: bool,
	) {
		let mut s = self.state();
		if let Some((spec, raw)) = file {
			s.file = Values::of_file(spec, raw);
			s.file_raw = raw.clone();
		}
		s.env = env;
		s.startup = startup;
		s.keep_files = keep_files;
		s.persisted = database.then_some(true);
		let (live, sources) = effective(&s.file, &s.env, &s.api);
		s.live = live;
		s.sources = sources;
	}

	/// Puts API values in force (restored from the database or a live upgrade),
	/// before the rules are restored (rules using `crowdsec` need it). Items the
	/// file owns stay shadowed; one that cannot be built keeps its value before it.
	pub async fn restore(
		&self,
		http: &HttpGlobal,
		values: Values,
		updated_by: Option<String>,
		updated_at: Option<u64>,
		persisted: Option<bool>,
		from: &str,
	) {
		let _turn = self.turn.lock().await;
		let mut values = values;
		for i in ITEMS.iter().filter(|i| i.apply == Apply::Live) {
			if let Err(e) = values.check_item(i.name) {
				warn!(event = "restore.skip", what = "global", item = i.name, from, error = %e, "a stored global value is not valid; left out");
				values.clear(i.name);
			}
		}
		let (before, keep_files) = {
			let s = self.state();
			(s.live.clone(), s.keep_files)
		};
		let (mut to, _) = {
			let s = self.state();
			effective(&s.file, &s.env, &values)
		};
		let mut built = vec![];
		let mut failed = BTreeMap::new();
		for item in differing(&before, &to) {
			match build(item, &to, keep_files, Mode::Restore) {
				Ok(b) => built.push(b),
				Err(e) => {
					warn!(event = "degraded", part = "global", item, from, error = %e,
						"a global value set through the API cannot be put in force; the value before it stays");
					keep_item(&mut to, &before, item);
					failed.insert(item, e);
				}
			}
		}
		commit(built, http);
		let mut s = self.state();
		let (_, sources) = effective(&s.file, &s.env, &values);
		s.api = values;
		s.live = to;
		s.sources = sources;
		s.failed = failed;
		s.updated_by = updated_by;
		s.updated_at = updated_at;
		if s.persisted.is_some() {
			s.persisted = Some(persisted.unwrap_or(true));
		}
		if s.api != Values::default() {
			info!(event = "restore.global", from, items = ?ITEMS.iter().filter(|i| s.api.has(i.name)).map(|i| i.name).collect::<Vec<_>>());
		}
		s.warn_shadowed();
	}

	/// The settings file was read again (`ConfigReloader::reload`, before the rules):
	/// its live items are put in force (it wins over the API's). A mistake (an access
	/// log directory that does not exist, a CrowdSec key file that cannot be read)
	/// refuses the reload, with nothing changed. Answers the items whose value in force changed.
	pub async fn file_changed(
		&self,
		http: &HttpGlobal,
		spec: &GlobalSpec,
		raw: &Value,
		uses: CrowdsecUse,
	) -> Result<Vec<&'static str>, String> {
		let _turn = self.turn.lock().await;
		let (before, keep_files, file) = {
			let s = self.state();
			(s.live.clone(), s.keep_files, Values::of_file(spec, raw))
		};
		let (mut to, sources) = {
			let s = self.state();
			effective(&file, &s.env, &s.api)
		};
		// CrowdSec is not taken away from rules that use it: kept until they are changed
		if to.crowdsec.is_none() && before.crowdsec.is_some() && uses.any {
			warn!(
				event = "config.global_in_use",
				item = "crowdsec",
				"rules use crowdsec: global.crowdsec stays in force until no rule uses it (then reload again)"
			);
			to.crowdsec = before.crowdsec.clone();
		}
		let changed = differing(&before, &to);
		let mut built = vec![];
		for item in &changed {
			built.push(build(item, &to, keep_files, Mode::File)?);
		}
		commit(built, http);
		let mut s = self.state();
		s.file = file;
		s.file_raw = raw.clone();
		s.live = to;
		s.sources = sources;
		for item in &changed {
			s.failed.remove(item);
		}
		s.warn_shadowed();
		Ok(changed)
	}

	/// The live items a version of the file would change in force (`POST /config/reload?dry_run`).
	pub fn preview(&self, spec: &GlobalSpec, raw: &Value) -> Vec<&'static str> {
		let s = self.state();
		let (to, _) = effective(&Values::of_file(spec, raw), &s.env, &s.api);
		differing(&s.live, &to)
	}

	/// `PATCH /config/global`: `body` in the shape of the file's `global`, an item
	/// set to null clears the API's value. `uses` says what rules use of CrowdSec,
	/// `protected` why a path may not be named (#319). With `dry_run`, nothing changes.
	pub async fn patch(
		&self,
		http: &HttpGlobal,
		body: &serde_json::Map<String, Value>,
		by: &str,
		dry_run: bool,
		uses: CrowdsecUse,
		protected: impl Fn(&str) -> Option<String>,
	) -> Result<Patched, PatchError> {
		let named = named_items(body).map_err(PatchError::Invalid)?;
		let _turn = self.turn.lock().await;
		let (before, keep_files, api_before, file, env) = {
			let s = self.state();
			(s.live.clone(), s.keep_files, s.api.clone(), s.file.clone(), s.env.clone())
		};
		let restart: Vec<String> =
			named.iter().filter(|(i, _)| item(i).is_some_and(|d| d.apply == Apply::Restart)).map(|(i, _)| i.clone()).collect();
		if !restart.is_empty() {
			return Err(PatchError::RestartOnly(restart));
		}
		let owned: Vec<String> = named.iter().filter(|(i, _)| file.has(i) || env.has(i)).map(|(i, _)| i.clone()).collect();
		if !owned.is_empty() {
			return Err(PatchError::Static(owned));
		}
		let mut api = api_before.clone();
		for (i, v) in &named {
			api.set(i, v.clone().filter(|v| !v.is_null())).map_err(PatchError::Invalid)?;
		}
		// the API may not point rproxy at its own secrets or stores (#319)
		for path in [api.access_log.as_deref(), api.crowdsec.as_ref().map(|c| c.api_key_file.as_str())].into_iter().flatten() {
			if let Some(what) = protected(path) {
				return Err(PatchError::Protected(format!("{path} is {what}; the API may not name it in global")));
			}
		}
		let (to, _) = effective(&file, &env, &api);
		if uses.any && to.crowdsec.is_none() && before.crowdsec.is_some() {
			return Err(PatchError::InUse("rules use crowdsec; change them before clearing global.crowdsec".into()));
		}
		if uses.appsec && to.crowdsec.as_ref().is_some_and(|c| c.appsec_url.is_none()) {
			return Err(PatchError::InUse("rules use crowdsec appsec; global.crowdsec needs appsec_url".into()));
		}
		let changes: Vec<Change> = named
			.iter()
			.filter_map(|(i, _)| item(i))
			.map(|d| Change {
				item: d.name,
				before: live_value(&before, d.name),
				after: live_value(&to, d.name),
				api_before: api_before.get(d.name).unwrap_or(Value::Null),
				api_after: api.get(d.name).unwrap_or(Value::Null),
			})
			.collect();
		let applied = differing(&before, &to);
		let mut built = vec![];
		for item in &applied {
			// a dry run opens no access log file (it would create it)
			if dry_run && *item == "access_log" {
				if let Some(p) = &to.access_log {
					match crate::l7::access::access_log_dir(Path::new(p)) {
						Ok(_) => {}
						Err(AccessLogError::Config(e) | AccessLogError::Unavailable(e)) => {
							return Err(PatchError::Invalid(format!("global.access_log: {e}")));
						}
					}
				}
				continue;
			}
			built.push(build(item, &to, keep_files, Mode::Api).map_err(PatchError::Invalid)?);
		}
		if dry_run {
			// a bouncer built to check the settings never runs
			return Ok(Patched { changes, applied });
		}
		commit(built, http);
		let mut s = self.state();
		let (_, sources) = effective(&s.file, &s.env, &api);
		s.api = api;
		s.live = to;
		s.sources = sources;
		for item in &applied {
			s.failed.remove(item);
		}
		for c in &changes {
			s.failed.remove(c.item);
		}
		s.updated_by = Some(by.to_string());
		s.updated_at = Some(unix_now());
		if s.persisted.is_some() {
			// written next (`persist::Store::save_global`)
			s.persisted = Some(false);
		}
		info!(event = "config.global", token = by, items = ?changes.iter().map(|c| c.item).collect::<Vec<_>>(), applied = ?applied);
		Ok(Patched { changes, applied })
	}

	/// The API values as stored (the row of `rproxy_global`) and who set them last.
	pub fn stored(&self) -> (Value, String) {
		let s = self.state();
		(serde_json::to_value(&s.api).unwrap_or_else(|_| json!({})), s.updated_by.clone().unwrap_or_default())
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

	/// Whether the API has set any value.
	pub fn has_api_values(&self) -> bool {
		self.state().api != Values::default()
	}

	/// For the new process of a live upgrade.
	pub fn handoff(&self) -> Handoff {
		let s = self.state();
		Handoff {
			values: serde_json::to_value(&s.api).unwrap_or_else(|_| json!({})),
			updated_by: s.updated_by.clone(),
			updated_at: s.updated_at,
			persisted: s.persisted,
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
				Apply::Restart => match i.pointer.and_then(|p| s.file_raw.pointer(p)) {
					Some(raw) => (Source::File, raw.clone()),
					None => s.startup.get(i.name).cloned().unwrap_or((Source::Default, Value::Null)),
				},
			};
			v.insert("value".into(), value);
			v.insert("source".into(), json!(source));
			v.insert("apply".into(), json!(i.apply));
			v.insert("unix_only".into(), json!(i.unix_only));
			// whether the API may set it now
			let free = i.apply == Apply::Live && !matches!(source, Source::File | Source::Env);
			v.insert("settable".into(), json!(free));
			if let Some(api) = s.api.get(i.name) {
				v.insert("api_value".into(), api);
				v.insert("shadowed".into(), json!(matches!(source, Source::File | Source::Env)));
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
			"updated_by": s.updated_by,
			"updated_at": s.updated_at,
			"warnings": warnings,
		})
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

/// The secret-related items a `PATCH` body names (`Item::unix_only`).
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
	}

	#[test]
	fn the_body_names_items_in_the_shape_of_global() {
		let named = named_items(&body(json!({"http": {"timeouts": {"idle": "1s"}}, "access_log": null}))).unwrap();
		assert_eq!(named, [("access_log".to_string(), Some(Value::Null)), ("http.timeouts".to_string(), Some(json!({"idle": "1s"})))]);
		assert_eq!(named_items(&body(json!({"http": null}))).unwrap(), [("http.timeouts".to_string(), None)]);
		assert!(named_items(&body(json!({"http": {"other": 1}}))).unwrap_err().contains("global.http.other"));
		assert!(named_items(&body(json!({"nope": 1}))).unwrap_err().contains("global.nope"));
		assert!(named_items(&body(json!({}))).is_err());
		assert_eq!(unix_only_items(&body(json!({"crowdsec": null, "trusted_proxies": []}))), ["crowdsec"]);
	}

	#[tokio::test]
	async fn patch_refuses_file_items_and_start_only_items() {
		let s = Settings::default();
		let (spec, raw) = file("trusted_proxies: [10.0.0.0/8]\n");
		s.init(Some((&spec, &raw)), Values::default(), BTreeMap::new(), 1, false);
		let http = HttpGlobal::default();
		let none = |_: &str| None;
		let e = s.patch(&http, &body(json!({"trusted_proxies": [], "access_log": null})), "t", false, CrowdsecUse::default(), none).await;
		assert!(matches!(e, Err(PatchError::Static(ref i)) if i == &["trusted_proxies"]), "{e:?}");
		let e = s.patch(&http, &body(json!({"performance": {"workers": 2}})), "t", false, CrowdsecUse::default(), none).await;
		assert!(matches!(e, Err(PatchError::RestartOnly(ref i)) if i == &["performance"]), "{e:?}");
		// a live item the file leaves out: in force for the next connection
		let p =
			s.patch(&http, &body(json!({"http": {"timeouts": {"idle": "7s"}}})), "t", false, CrowdsecUse::default(), none).await.unwrap();
		assert_eq!(p.applied, ["http.timeouts"]);
		assert_eq!(http.timeouts().idle, Some(std::time::Duration::from_secs(7)));
		let view = s.view();
		assert_eq!(view["items"]["http.timeouts"]["source"], "api");
		assert_eq!(view["items"]["trusted_proxies"]["source"], "file");
		assert_eq!(view["items"]["trusted_proxies"]["settable"], false);
		assert_eq!(view["items"]["performance"]["apply"], "restart");
		assert_eq!(view["storage"], "memory");
		// dry run: nothing changes
		let p = s.patch(&http, &body(json!({"http": null})), "t", true, CrowdsecUse::default(), none).await.unwrap();
		assert_eq!(p.applied, ["http.timeouts"]);
		assert_eq!(http.timeouts().idle, Some(std::time::Duration::from_secs(7)));
		// clearing goes back to the default
		s.patch(&http, &body(json!({"http": null})), "t", false, CrowdsecUse::default(), none).await.unwrap();
		assert_eq!(http.timeouts(), Default::default());
		assert!(!s.has_api_values());
	}

	#[tokio::test]
	async fn a_file_item_shadows_the_api_value_and_lets_go_of_it() {
		let s = Settings::default();
		s.init(None, Values::default(), BTreeMap::new(), 1, true);
		let http = HttpGlobal::default();
		let none = |_: &str| None;
		s.patch(&http, &body(json!({"trusted_proxies": ["192.0.2.0/24"]})), "t", false, CrowdsecUse::default(), none).await.unwrap();
		assert!(http.trusts("192.0.2.1".parse().unwrap()));
		assert_eq!(s.persisted(), Some(false), "not written yet");
		let (spec, raw) = file("trusted_proxies: [10.0.0.0/8]\n");
		assert_eq!(s.file_changed(&http, &spec, &raw, CrowdsecUse::default()).await.unwrap(), ["trusted_proxies"]);
		assert!(!http.trusts("192.0.2.1".parse().unwrap()) && http.trusts("10.1.2.3".parse().unwrap()));
		let view = s.view();
		assert_eq!(view["items"]["trusted_proxies"]["shadowed"], true);
		assert_eq!(view["items"]["trusted_proxies"]["api_value"], json!(["192.0.2.0/24"]));
		assert_eq!(view["warnings"][0]["code"], "config.global_shadowed");
		// the file leaves it out again: the API value is in force
		let (spec, raw) = file("{}");
		s.file_changed(&http, &spec, &raw, CrowdsecUse::default()).await.unwrap();
		assert!(http.trusts("192.0.2.1".parse().unwrap()));
		assert_eq!(s.view()["warnings"], json!([]));
	}

	#[tokio::test]
	async fn restored_values_that_cannot_be_built_keep_the_value_before() {
		let s = Settings::default();
		s.init(None, Values::default(), BTreeMap::new(), 1, true);
		let http = HttpGlobal::default();
		let values: Values =
			serde_json::from_value(json!({"access_log": "/nonexistent-rproxy/a.log", "trusted_proxies": ["192.0.2.0/24"]})).unwrap();
		s.restore(&http, values, Some("ui".into()), Some(1), Some(true), "database").await;
		let view = s.view();
		assert_eq!(view["items"]["access_log"]["value"], Value::Null);
		assert!(view["items"]["access_log"]["error"].as_str().unwrap().contains("does not exist"));
		assert_eq!(view["items"]["trusted_proxies"]["source"], "api");
		assert!(http.trusts("192.0.2.1".parse().unwrap()));
		assert_eq!(view["persisted"], true);
	}

	#[tokio::test]
	async fn crowdsec_used_by_rules_is_not_taken_away() {
		let s = Settings::default();
		s.init(None, Values::default(), BTreeMap::new(), 1, false);
		let http = HttpGlobal::default();
		let dir = std::env::temp_dir().join(format!("rproxy-global-cs-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let key = dir.join("key");
		crate::net::files::private_umask();
		std::fs::write(&key, "k\n").unwrap();
		let none = |_: &str| None;
		let cs = json!({"crowdsec": {"lapi_url": "http://127.0.0.1:9", "api_key_file": key}});
		s.patch(&http, &body(cs), "t", false, CrowdsecUse::default(), none).await.unwrap();
		assert!(http.crowdsec().is_some());
		let used = CrowdsecUse { any: true, appsec: true };
		let e = s.patch(&http, &body(json!({"crowdsec": null})), "t", false, used, none).await;
		assert!(matches!(e, Err(PatchError::InUse(_))), "{e:?}");
		let cs = json!({"crowdsec": {"lapi_url": "http://127.0.0.1:9", "api_key_file": key}});
		assert!(matches!(s.patch(&http, &body(cs), "t", false, used, none).await, Err(PatchError::InUse(_))), "appsec needs appsec_url");
		let protected = |p: &str| (p == key.to_str().unwrap()).then(|| "a secret".to_string());
		let cs = json!({"crowdsec": {"lapi_url": "http://127.0.0.1:9", "api_key_file": key}});
		assert!(matches!(s.patch(&http, &body(cs), "t", false, CrowdsecUse::default(), protected).await, Err(PatchError::Protected(_))));
		s.patch(&http, &body(json!({"crowdsec": null})), "t", false, CrowdsecUse::default(), none).await.unwrap();
		assert!(http.crowdsec().is_none());
		std::fs::remove_dir_all(dir).unwrap();
	}
}
