//! What a Kubernetes controller needs from rproxy (#28, docs/DESIGN-v0.4.md 3.):
//! rule sets applied as a whole (`PUT /rulesets/{name}`), rule `labels`, and
//! per-rule `conditions` shaped for Gateway API status, and readiness
//! (`GET /readyz`).
//!
//! Rule sets live in memory only (never in the database): after a restart the
//! controller PUTs them again once `GET /readyz` answers 200.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::core::registry::{overlaps, Entry, Registry};
use crate::core::rule::{Key, Origin, RuleRequest, RuleSpec, RuleView, State};
use crate::error::ApiError;

pub const MAX_LABELS: usize = 16;
const MAX_KEY: usize = 63;
const MAX_VALUE: usize = 253;
const MAX_NAME: usize = 253;
/// Most rules in one set.
pub const MAX_RULES: usize = 10_000;
/// Largest body of `PUT /rulesets/{name}` (the API's default is 2 MiB).
pub const MAX_BODY: usize = 32 << 20;

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

/// Labels for a log line: `k=v,k2=v2` (empty without labels).
pub fn labels_text(labels: &Labels) -> String {
	labels.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",")
}

/// `rproxy_rule_labels{rule="tcp/0.0.0.0:443",label_tenant="act"} 1` per rule
/// with labels (an info metric). A key becomes `label_` and its letters and
/// digits, other characters `_`; of keys that end up the same, the first (in
/// sort order) is kept.
pub fn label_metrics<'a>(out: &mut String, rules: impl Iterator<Item = (&'a Key, &'a Labels)>) {
	let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n");
	let mut samples = vec![];
	for (key, labels) in rules.filter(|(_, l)| !l.is_empty()) {
		let mut names = HashSet::new();
		let mut line = format!("rproxy_rule_labels{{rule=\"{key}\"");
		for (k, v) in labels {
			let name: String = format!("label_{}", k.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect::<String>());
			if names.insert(name.clone()) {
				let _ = write!(line, ",{name}=\"{}\"", esc(v));
			}
		}
		line.push_str("} 1");
		samples.push(line);
	}
	if samples.is_empty() {
		return;
	}
	samples.sort();
	let _ = writeln!(out, "# HELP rproxy_rule_labels The labels of each rule that has some (always 1).");
	let _ = writeln!(out, "# TYPE rproxy_rule_labels gauge");
	for line in samples {
		let _ = writeln!(out, "{line}");
	}
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

/// `409 owned`: a rule of a set is changed only through its set.
pub fn owned(key: &Key, set: &str) -> ApiError {
	ApiError::owned(format!("{key} belongs to rule set {set:?}; change it with PUT /rulesets/{set}"))
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
		// JSON clients (JavaScript, Go's float64) read larger numbers wrong (security review M3)
		if self.generation > MAX_GENERATION {
			return Err(ApiError::invalid(format!("generation must be at most {MAX_GENERATION} (2^53 - 1)")));
		}
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
	/// `update`: `in_place` (connections kept) or `recreate` (the listeners
	/// are opened again; connections are dropped); `none` otherwise.
	pub change: &'static str,
	/// The rule's state after the change (left out for `delete` and dry runs).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub state: Option<State>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
	/// Dry runs: what would change (`update` only).
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub diff: Vec<crate::config::plan::DiffEntry>,
}

/// The answer of `PUT /rulesets/{name}`.
#[derive(Clone, Debug, Serialize)]
pub struct RulesetApplied {
	pub name: String,
	pub generation: u64,
	/// The set's etag after the change (a dry run: what it would be).
	pub etag: String,
	pub dry_run: bool,
	pub results: Vec<ApplyResult>,
	/// Whether the set's row in `rproxy_rule_sets` is up to date (#241; only
	/// for stored sets).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub persisted: Option<bool>,
}

/// The largest `generation` (JSON's safe integers).
pub const MAX_GENERATION: u64 = (1 << 53) - 1;

/// `GET /rulesets/{name}`.
#[derive(Clone, Debug, Serialize)]
pub struct RulesetView {
	pub name: String,
	pub generation: u64,
	pub etag: String,
	pub updated_at: u64,
	pub updated_by: String,
	/// The token that created the set; only it (or an `admin` token) may change or delete it.
	pub owner: String,
	/// Stored sets only (#241): whether the row is up to date.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub persisted: Option<bool>,
	pub rules: Vec<RuleView>,
}

/// One entry of `GET /rulesets`.
#[derive(Clone, Debug, Serialize)]
pub struct RulesetSummary {
	pub name: String,
	pub generation: u64,
	pub etag: String,
	pub rules: usize,
	pub updated_at: u64,
	pub updated_by: String,
	pub owner: String,
	/// Stored sets only (#241): whether the row is up to date.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub persisted: Option<bool>,
}

/// A refused `PUT /rulesets/{name}`: the first problem as `code` / `error`,
/// every problem in `errors`.
#[derive(Debug)]
pub struct SetError {
	pub error: ApiError,
	pub errors: Vec<SetFinding>,
}

/// One problem with a rule of the body (`index` is its place in `rules`).
#[derive(Clone, Debug, Serialize)]
pub struct SetFinding {
	pub index: usize,
	pub rule: String,
	pub code: &'static str,
	pub message: String,
}

impl From<ApiError> for SetError {
	fn from(error: ApiError) -> Self {
		SetError { error, errors: vec![] }
	}
}

impl SetError {
	fn of(mut findings: Vec<(SetFinding, StatusCode)>) -> SetError {
		findings.sort_by_key(|(f, _)| f.index);
		let (first, status) = findings[0].clone();
		let error = ApiError { status, code: first.code, message: format!("rules[{}]: {}", first.index, first.message) };
		SetError { error, errors: findings.into_iter().map(|(f, _)| f).collect() }
	}
}

impl IntoResponse for SetError {
	fn into_response(self) -> Response {
		let mut body = serde_json::json!({"error": self.error.message, "code": self.error.code});
		if !self.errors.is_empty() {
			body["errors"] = serde_json::to_value(&self.errors).unwrap_or_default();
		}
		(self.error.status, Json(body)).into_response()
	}
}

/// One entry of a rule's `conditions` (Gateway API style).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Condition {
	/// `Accepted`, `Programmed`, `ResolvedRefs` or `BackendsHealthy`.
	#[serde(rename = "type")]
	pub kind: &'static str,
	/// `True`, `False` or `Unknown`.
	pub status: &'static str,
	pub reason: &'static str,
	pub message: String,
	/// Unix seconds.
	pub last_transition: u64,
}

/// A condition as found now, before `ConditionLog` dates it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
	pub kind: &'static str,
	pub status: &'static str,
	pub reason: &'static str,
	pub message: String,
	/// When it is known to have started (e.g. `started_at` for `Programmed`).
	pub since: Option<u64>,
}

fn found(kind: &'static str, ok: Result<&'static str, (&'static str, String)>) -> Found {
	match ok {
		Ok(reason) => Found { kind, status: "True", reason, message: String::new(), since: None },
		Err((reason, message)) => Found { kind, status: "False", reason, message, since: None },
	}
}

/// A rule's conditions from its view; `cause` is (error code, retrying name
/// resolution) of a failed rule, None for a running one.
pub fn conditions(view: &RuleView, cause: Option<(&'static str, bool)>) -> Vec<Found> {
	use crate::tls::certstore::CertState;
	use crate::tls::config::{is_cert_expired_text, CertRole};
	let error = view.error.clone().unwrap_or_default();
	let accepted = match cause {
		Some(("unsupported", _)) => Err(("Unsupported", error.clone())),
		_ => Ok("Accepted"),
	};
	let mut programmed = found(
		"Programmed",
		match cause {
			None => Ok("Listening"),
			Some(("bind_failed" | "reserved" | "already_exists", _)) => Err(("BindFailed", error.clone())),
			Some(("resolve_failed", true)) => Err(("Pending", error.clone())),
			Some(_) => Err(("Failed", error.clone())),
		},
	);
	if cause.is_none() {
		programmed.since = view.started_at;
	}
	let expired = view.cert_status.iter().find(|c| c.role == CertRole::Certificate && c.state == CertState::Expired);
	let unresolved: Vec<String> =
		view.stats.targets.iter().filter(|t| t.resolved.is_empty()).map(|t| format!("{}:{}: no address", t.addr, t.port)).collect();
	let refs = match cause {
		Some(("resolve_failed", _)) => Err(("ResolveFailed", error.clone())),
		Some(_) if is_cert_expired_text(&error) => Err(("CertificateExpired", error.clone())),
		Some(("tls_config", _)) => Err(("CertificateUnreadable", error.clone())),
		// a secret file of an http middleware could not be read when starting
		Some(("invalid", _)) => Err(("SecretUnreadable", error.clone())),
		_ if expired.is_some() => Err(("CertificateExpired", expired.map(|c| format!("{} expired at {}", c.file, c.not_after)).unwrap_or_default())),
		_ if !unresolved.is_empty() => Err(("ResolveFailed", unresolved.join("; "))),
		_ => Ok("ResolvedRefs"),
	};
	let backends = match cause {
		Some(_) => Found {
			kind: "BackendsHealthy",
			status: "Unknown",
			reason: "NotProgrammed",
			message: String::new(),
			since: None,
		},
		None if view.all_targets_down => found("BackendsHealthy", Err(("AllTargetsDown", "every target is down".into()))),
		None if !view.down_services.is_empty() => {
			found("BackendsHealthy", Err(("ServiceDown", format!("no server up: {}", view.down_services.join(", ")))))
		}
		None => found("BackendsHealthy", Ok("Healthy")),
	};
	vec![found("Accepted", accepted), programmed, found("ResolvedRefs", refs), backends]
}

fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The conditions last seen per rule, so `last_transition` stays put while a
/// condition's status does not change. A change is seen when the rule is read
/// (`GET /rules`, `GET /rulesets/{name}`, the answer of a PUT).
#[derive(Default)]
pub struct ConditionLog(std::sync::Mutex<HashMap<Key, Vec<Condition>>>);

impl ConditionLog {
	pub fn stamp(&self, key: Key, found: Vec<Found>) -> Vec<Condition> {
		self.stamp_at(key, found, unix_now())
	}

	fn stamp_at(&self, key: Key, found: Vec<Found>, now: u64) -> Vec<Condition> {
		let mut seen = self.0.lock().unwrap_or_else(|e| e.into_inner());
		let before = seen.get(&key);
		let out: Vec<Condition> = found
			.into_iter()
			.map(|f| {
				let last_transition = match before.and_then(|b| b.iter().find(|c| c.kind == f.kind)) {
					Some(c) if c.status == f.status => c.last_transition,
					Some(_) => now,
					None => f.since.unwrap_or(now),
				};
				Condition { kind: f.kind, status: f.status, reason: f.reason, message: f.message, last_transition }
			})
			.collect();
		seen.insert(key, out.clone());
		out
	}

	/// The rule was stopped (deleted or re-created).
	pub fn forget(&self, key: &Key) {
		self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
	}
}

/// `GET /readyz`: starting until the startup restore is done, draining once
/// the process stops taking work (shutdown, #174 handoff).
#[derive(Default)]
pub struct Readiness(AtomicU8);

const STARTING: u8 = 0;
const READY: u8 = 1;
const DRAINING: u8 = 2;

impl Readiness {
	/// The startup restore (settings file, database) is done.
	pub fn set_ready(&self) {
		let _ = self.0.compare_exchange(STARTING, READY, Ordering::SeqCst, Ordering::SeqCst);
	}

	/// No longer taking work; not ready again.
	pub fn set_draining(&self) {
		self.0.store(DRAINING, Ordering::SeqCst);
	}

	/// Ok when ready, else the reason (`starting` or `draining`).
	pub fn check(&self) -> Result<(), &'static str> {
		match self.0.load(Ordering::SeqCst) {
			READY => Ok(()),
			DRAINING => Err("draining"),
			_ => Err("starting"),
		}
	}
}

/// What rproxy keeps of a set besides its rules (which carry the set's name).
#[derive(Clone, Debug)]
struct SetState {
	generation: u64,
	etag: String,
	updated_at: u64,
	updated_by: String,
	/// The token that created the set (security review M3).
	owner: String,
}

/// A token other than the set's owner may change it only with `admin` (security review M3).
fn check_owner(name: &str, current: Option<&SetState>, by: &str, admin: bool) -> Result<(), ApiError> {
	match current {
		Some(s) if s.owner != by && !admin => Err(ApiError::forbidden(format!(
			"rule set {name:?} belongs to token {:?}; only it or an admin token may change it",
			s.owner
		))),
		_ => Ok(()),
	}
}

/// Every rule set, by name. Changes to sets run one at a time (`write` is
/// held through a whole PUT or DELETE); reads do not wait for them.
#[derive(Default)]
pub struct Rulesets {
	write: tokio::sync::Mutex<()>,
	sets: std::sync::Mutex<BTreeMap<String, SetState>>,
}

impl Rulesets {
	fn snapshot(&self) -> BTreeMap<String, SetState> {
		self.sets.lock().unwrap_or_else(|e| e.into_inner()).clone()
	}

	fn get(&self, name: &str) -> Option<SetState> {
		self.sets.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned()
	}

	fn set(&self, name: &str, state: Option<SetState>) {
		let mut sets = self.sets.lock().unwrap_or_else(|e| e.into_inner());
		match state {
			Some(s) => sets.insert(name.to_string(), s),
			None => sets.remove(name),
		};
	}
}

/// A rule's shape as JSON: what `GET /rules` shows of it, without the run-time
/// fields. For etags and the diffs of dry runs.
pub fn spec_json(spec: &RuleSpec) -> serde_json::Value {
	let mut v = serde_json::to_value(RuleView::new(spec, State::Running, None, &[], 0)).unwrap_or_default();
	if let Some(map) = v.as_object_mut() {
		for k in [
			"state", "error", "resolved", "connections", "all_targets_down", "down_services", "stats", "started_at", "cert_status",
			"acme", "conditions", "persisted", "created_by", "created_at", "origin", "ruleset",
		] {
			map.remove(k);
		}
	}
	sorted(v)
}

/// The same JSON with the keys of every object in order.
fn sorted(v: serde_json::Value) -> serde_json::Value {
	use serde_json::Value;
	match v {
		Value::Object(map) => {
			let mut entries: Vec<(String, Value)> = map.into_iter().collect();
			entries.sort_by(|a, b| a.0.cmp(&b.0));
			Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
		}
		Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
		other => other,
	}
}

/// `g<generation>-<the first 16 hex digits of the SHA-256 of the rules>`:
/// the rules' shapes in key order, as JSON.
pub fn etag(generation: u64, specs: &[&RuleSpec]) -> String {
	use sha2::Digest;
	let mut specs: Vec<&RuleSpec> = specs.to_vec();
	specs.sort_by_key(|s| (s.key.protocol == crate::core::rule::Protocol::Udp, s.key.listen));
	let doc = serde_json::Value::Array(specs.into_iter().map(spec_json).collect());
	let hash = sha2::Sha256::digest(doc.to_string().as_bytes());
	let hex: String = hash.iter().take(8).map(|b| format!("{b:02x}")).collect();
	format!("g{generation}-{hex}")
}

/// Whether an `If-Match` header matches an etag (`*`, a list, quoted or not, `W/`).
pub fn if_match(header: &str, etag: &str) -> bool {
	header.split(',').map(|t| t.trim().trim_start_matches("W/").trim_matches('"')).any(|t| t == "*" || t == etag)
}

fn check_if_match(header: Option<&str>, current: Option<&SetState>) -> Result<(), ApiError> {
	let Some(header) = header else { return Ok(()) };
	match current {
		Some(s) if if_match(header, &s.etag) => Ok(()),
		Some(s) => Err(ApiError::precondition_failed(format!("If-Match {header} does not match the rule set's etag \"{}\"", s.etag))),
		None => Err(ApiError::precondition_failed(format!("If-Match {header}: there is no such rule set"))),
	}
}

/// What a PUT would do to one rule.
struct Step {
	/// Its place in the body; None for a rule the set drops.
	index: Option<usize>,
	key: Key,
	action: &'static str,
	change: &'static str,
	/// The new shape (None for `delete`).
	spec: Option<RuleSpec>,
	/// The current shape (None for `create`).
	old: Option<RuleSpec>,
}

/// Who asks and what they may touch.
pub struct PutOptions<'a> {
	/// The `If-Match` header.
	pub if_match: Option<&'a str>,
	pub dry_run: bool,
	/// The token's name (`updated_by`; the owner of a set it creates).
	pub by: &'a str,
	/// The token has `admin`: it may change sets of other tokens.
	pub admin: bool,
	/// The owner to keep (handoff); None: the set's own, or `by` for a new set.
	pub owner: Option<&'a str>,
	/// The token's `allow_listen_ports`: (first, last) of a rule's ports.
	pub may_use_ports: &'a (dyn Fn(u16, u16) -> bool + Send + Sync),
}

/// A rule as it is now, for planning a PUT.
struct Current {
	spec: RuleSpec,
	running: bool,
	/// Failed and its names are being resolved again in the background.
	retrying: bool,
}

fn label_of(r: &RuleRequest) -> String {
	match crate::core::rule::parse_listen(&r.listen_addr, r.listen_port) {
		Ok(listen) => format!("{}/{listen}", r.protocol),
		Err(_) => format!("{}/{}:{}", r.protocol, r.listen_addr, r.listen_port),
	}
}

fn finding(index: usize, rule: String, e: ApiError) -> (SetFinding, StatusCode) {
	(SetFinding { index, rule, code: e.code, message: e.message }, e.status)
}

/// Whether PATCH's path can change `old` into `new` without dropping
/// connections (the plan engine's rule, shared with reloads and dry runs).
fn in_place(old: &RuleSpec, new: &RuleSpec) -> bool {
	crate::config::plan::in_place(old, new)
}

fn port_range(spec: &RuleSpec) -> (u16, u16) {
	let first = spec.key.listen.port();
	(first, first.saturating_add(spec.port_count.saturating_sub(1)))
}

impl Registry {
	/// `GET /rulesets`.
	pub async fn list_rulesets(&self) -> Vec<RulesetSummary> {
		let sets = self.rulesets.snapshot();
		let mut counts: HashMap<String, usize> = HashMap::new();
		for e in self.rules.lock().await.values() {
			if let Some(set) = &e.spec().ruleset {
				*counts.entry(set.clone()).or_default() += 1;
			}
		}
		sets.into_iter()
			.map(|(name, s)| RulesetSummary {
				rules: counts.get(&name).copied().unwrap_or(0),
				persisted: self.set_persisted(&name),
				name,
				generation: s.generation,
				etag: s.etag,
				updated_at: s.updated_at,
				updated_by: s.updated_by,
				owner: s.owner,
			})
			.collect()
	}

	/// `GET /rulesets/{name}`.
	pub async fn get_ruleset(&self, name: &str) -> Result<RulesetView, ApiError> {
		validate_name(name)?;
		let s = self.rulesets.get(name).ok_or_else(|| ApiError::not_found(format!("no rule set {name:?}")))?;
		let rules = self.rules.lock().await;
		let mut keys: Vec<&Key> = rules.iter().filter(|(_, e)| e.spec().ruleset.as_deref() == Some(name)).map(|(k, _)| k).collect();
		keys.sort_by_key(|k| (k.protocol == crate::core::rule::Protocol::Udp, k.listen));
		Ok(RulesetView {
			name: name.to_string(),
			generation: s.generation,
			etag: s.etag,
			updated_at: s.updated_at,
			updated_by: s.updated_by,
			owner: s.owner,
			persisted: self.set_persisted(name),
			rules: keys.into_iter().map(|k| self.view_of(&rules[k])).collect(),
		})
	}

	/// `DELETE /rulesets/{name}`: stops every rule of the set (all at once,
	/// each after `drain`) and forgets the set.
	pub async fn delete_ruleset(
		&self,
		name: &str,
		if_match_header: Option<&str>,
		drain: Option<Duration>,
		may_use_ports: &(dyn Fn(u16, u16) -> bool + Send + Sync),
		(by, admin): (&str, bool),
	) -> Result<usize, ApiError> {
		validate_name(name)?;
		let _write = self.rulesets.write.lock().await;
		let current = self.rulesets.get(name).ok_or_else(|| ApiError::not_found(format!("no rule set {name:?}")))?;
		check_owner(name, Some(&current), by, admin)?;
		check_if_match(if_match_header, Some(&current))?;
		let entries: Vec<(Key, Entry)> = {
			let mut rules = self.rules.lock().await;
			let keys: Vec<Key> =
				rules.iter().filter(|(_, e)| e.spec().ruleset.as_deref() == Some(name)).map(|(k, _)| *k).collect();
			for k in &keys {
				let (first, last) = port_range(rules[k].spec());
				if !may_use_ports(first, last) {
					return Err(ApiError::forbidden(format!("{k}: this token may not use listen port {first}-{last}")));
				}
			}
			keys.into_iter().filter_map(|k| rules.remove(&k).map(|e| (k, e))).collect()
		};
		self.rulesets.set(name, None);
		let count = entries.len();
		futures_util::future::join_all(entries.into_iter().map(|(key, entry)| async move {
			self.stop_entry(&key, entry, drain).await;
			info!(event = "rule.delete", rule = %key, ruleset = name, drain_secs = drain.map(|d| d.as_secs()));
		}))
		.await;
		self.gc_certs().await;
		info!(event = "ruleset.delete", ruleset = name, rules = count);
		Ok(count)
	}

	/// `PUT /rulesets/{name}`: makes the set's rules exactly `req.rules`.
	/// Every rule is validated (shape, conflicts with other rules, certificate
	/// and secret files) before anything changes; then rules the set drops are
	/// stopped, changed rules are changed in place where PATCH could (keeping
	/// connections) or re-created, new rules started, and unchanged rules left
	/// alone. A rule that cannot bind or resolve its targets is registered as
	/// failed (its `conditions` say why); the others are applied.
	pub async fn put_ruleset(self: &Arc<Self>, name: &str, req: RulesetRequest, opts: PutOptions<'_>) -> Result<RulesetApplied, SetError> {
		validate_name(name)?;
		req.validate_shape()?;
		let write = self.rulesets.write.lock().await;
		let current_set = self.rulesets.get(name);
		check_owner(name, current_set.as_ref(), opts.by, opts.admin)?;
		check_if_match(opts.if_match, current_set.as_ref())?;
		if let Some(s) = &current_set {
			if req.generation < s.generation {
				return Err(ApiError::stale_generation(format!(
					"generation {} is older than the rule set's {}",
					req.generation, s.generation
				))
				.into());
			}
		}

		// 1. the shape of every rule
		let caps = self.caps();
		let mut problems = vec![];
		let mut specs: Vec<(usize, RuleSpec)> = vec![];
		for (i, r) in req.rules.into_iter().enumerate() {
			let label = label_of(&r);
			match r.validate(&caps) {
				Ok(mut spec) => {
					spec.ruleset = Some(name.to_string());
					specs.push((i, spec));
				}
				Err(e) => problems.push(finding(i, label, e)),
			}
		}
		for (n, (i, spec)) in specs.iter().enumerate() {
			if let Some((j, other)) = specs[..n].iter().find(|(_, o)| overlaps(o, spec)) {
				let e = ApiError::invalid(format!("{} overlaps with rules[{j}] ({})", spec.key, other.key));
				problems.push(finding(*i, spec.key.to_string(), e));
			}
		}
		if !problems.is_empty() {
			return Err(SetError::of(problems));
		}

		// 2. against the rules that run now
		let current: HashMap<Key, Current> = self
			.rules
			.lock()
			.await
			.iter()
			.map(|(k, e)| {
				let (running, retrying) = match e {
					Entry::Running(_) => (true, false),
					Entry::Failed(f) => (false, f.cause().1),
				};
				(*k, Current { spec: e.spec().clone(), running, retrying })
			})
			.collect();
		let ours = |c: &Current| c.spec.ruleset.as_deref() == Some(name);
		for (i, spec) in &specs {
			let label = spec.key.to_string();
			if let Some(api) = self.reserved_clash(spec) {
				problems.push(finding(*i, label, ApiError::reserved(format!("{} would take rproxy's control API ({api})", spec.key))));
				continue;
			}
			if let Some(c) = current.get(&spec.key).filter(|c| !ours(c)) {
				let e = if c.spec.origin == Origin::Static {
					ApiError::static_rule(format!("{} is a static rule of the settings file", spec.key))
				} else if let Some(other) = &c.spec.ruleset {
					owned(&spec.key, other)
				} else {
					ApiError::already_exists(format!("{} exists and does not belong to this rule set", spec.key))
				};
				problems.push(finding(*i, label, e));
				continue;
			}
			if let Some((other, _)) = current.iter().find(|(k, c)| **k != spec.key && !ours(c) && overlaps(&c.spec, spec)) {
				problems.push(finding(*i, label, ApiError::already_exists(format!("{} overlaps with {other}", spec.key))));
				continue;
			}
			let (first, last) = port_range(spec);
			if !(opts.may_use_ports)(first, last) {
				problems.push(finding(*i, label, ApiError::forbidden(format!("this token may not use listen port {first}-{last}"))));
				continue;
			}
			// changing a rule of the set also takes away what it listens on now (security review M2)
			if let Some(c) = current.get(&spec.key).filter(|c| ours(c)) {
				let (first, last) = port_range(&c.spec);
				if !(opts.may_use_ports)(first, last) {
					problems.push(finding(*i, label, ApiError::forbidden(format!("this token may not change the rule listening on {first}-{last}"))));
				}
			}
		}
		if !problems.is_empty() {
			return Err(SetError::of(problems));
		}

		// 3. what changes; the files of what is created or changed
		let wanted: HashSet<Key> = specs.iter().map(|(_, s)| s.key).collect();
		let mut steps = vec![];
		for (i, spec) in specs {
			let step = match current.get(&spec.key) {
				None => Step { index: Some(i), key: spec.key, action: "create", change: "none", spec: Some(spec), old: None },
				Some(c) => {
					let (action, change) = if c.spec == spec && (c.running || c.retrying) {
						("none", "none")
					} else if c.running && in_place(&c.spec, &spec) {
						("update", "in_place")
					} else {
						// a failed rule is started again even when unchanged
						("update", "recreate")
					};
					Step { index: Some(i), key: spec.key, action, change, spec: Some(spec), old: Some(c.spec.clone()) }
				}
			};
			if step.action != "none" {
				if let Some(spec) = &step.spec {
					if let Err(e) = self.build_parts(spec) {
						problems.push(finding(i, spec.key.to_string(), e));
					}
				}
			}
			steps.push(step);
		}
		let mut dropped: Vec<(&Key, &Current)> = current.iter().filter(|(k, c)| ours(c) && !wanted.contains(k)).collect();
		dropped.sort_by_key(|(k, _)| (k.protocol == crate::core::rule::Protocol::Udp, k.listen));
		for (key, c) in dropped {
			let (first, last) = port_range(&c.spec);
			if !(opts.may_use_ports)(first, last) {
				return Err(ApiError::forbidden(format!("{key}: this token may not use listen port {first}-{last}")).into());
			}
			steps.push(Step { index: None, key: *key, action: "delete", change: "none", spec: None, old: Some(c.spec.clone()) });
		}
		if !problems.is_empty() {
			self.gc_certs().await;
			return Err(SetError::of(problems));
		}

		let wanted_specs: Vec<&RuleSpec> = steps.iter().filter_map(|s| s.spec.as_ref()).collect();
		if opts.dry_run {
			let etag = etag(req.generation, &wanted_specs);
			drop(write);
			self.gc_certs().await;
			return self.ruleset_dry_run(name, req.generation, etag, &steps);
		}

		// 4. apply: dropped rules first (a rule that moved must not overlap itself)
		let mut results: Vec<(Option<usize>, Key, ApplyResult)> = vec![];
		let removed: Vec<(Key, Entry)> = {
			let mut rules = self.rules.lock().await;
			steps
				.iter()
				.filter(|s| s.action == "delete")
				.filter_map(|s| match rules.get(&s.key) {
					Some(e) if e.spec().ruleset.as_deref() == Some(name) => rules.remove(&s.key).map(|e| (s.key, e)),
					_ => None,
				})
				.collect()
		};
		futures_util::future::join_all(removed.into_iter().map(|(key, entry)| async move {
			self.stop_entry(&key, entry, None).await;
			info!(event = "rule.delete", rule = %key, ruleset = name, phase = "ruleset");
		}))
		.await;
		let (mut created, mut updated, mut deleted, mut unchanged) = (0, 0, 0, 0);
		for step in &steps {
			let mut result =
				ApplyResult { rule: step.key.to_string(), action: step.action, change: step.change, state: None, error: None, diff: vec![] };
			match (step.action, &step.spec, &step.old) {
				("delete", _, _) => deleted += 1,
				("none", _, _) => unchanged += 1,
				("update", Some(spec), Some(old)) if step.change == "in_place" => {
					updated += 1;
					let tls_changed =
						old.tls != spec.tls || old.starttls != spec.starttls || old.starttls_required != spec.starttls_required;
					let http_changed = old.http != spec.http;
					if let Err(e) = self.apply(&step.key, spec.clone(), tls_changed, http_changed).await {
						tracing::warn!(event = "rule.update", rule = %step.key, error = %e.message, ruleset = name,
							"could not change in place; re-creating");
						result.change = "recreate";
						result.error = self.recreate_member(spec.clone()).await.err().map(|e| e.message);
					}
				}
				("update", Some(spec), _) => {
					updated += 1;
					result.error = self.recreate_member(spec.clone()).await.err().map(|e| e.message);
				}
				("create", Some(spec), _) => {
					created += 1;
					result.error = self.start_member(spec.clone()).await.err().map(|e| e.message);
				}
				_ => {}
			}
			results.push((step.index, step.key, result));
		}
		self.gc_certs().await;

		// 5. the outcome
		let (members, mut failed) = {
			let rules = self.rules.lock().await;
			let mut failed = 0;
			for (_, key, r) in results.iter_mut().filter(|(i, _, _)| i.is_some()) {
				if let Some(e) = rules.get(key).filter(|e| e.spec().ruleset.as_deref() == Some(name)) {
					let view = self.view_of(e);
					if view.state == State::Failed {
						failed += 1;
					}
					r.error = r.error.take().or(view.error);
					r.state = Some(view.state);
				}
			}
			let members: Vec<RuleSpec> =
				rules.values().filter(|e| e.spec().ruleset.as_deref() == Some(name)).map(|e| e.spec().clone()).collect();
			(members, failed)
		};
		failed += results.iter().filter(|(i, _, r)| i.is_some() && r.state.is_none()).count();
		let etag = etag(req.generation, &members.iter().collect::<Vec<_>>());
		let owner = opts.owner.map(str::to_string).or_else(|| current_set.as_ref().map(|s| s.owner.clone())).unwrap_or_else(|| opts.by.to_string());
		let state = SetState { generation: req.generation, etag: etag.clone(), updated_at: unix_now(), updated_by: opts.by.to_string(), owner };
		self.rulesets.set(name, Some(state));
		drop(write);
		info!(event = "ruleset.apply", ruleset = name, generation = req.generation, etag = %etag, created, updated, deleted,
			unchanged, failed, by = opts.by);
		Ok(RulesetApplied {
			name: name.to_string(),
			generation: req.generation,
			etag,
			dry_run: false,
			results: results.into_iter().map(|(_, _, r)| r).collect(),
			persisted: None,
		})
	}

	/// `persisted` of a set's views (#241): None unless it is stored.
	fn set_persisted(&self, name: &str) -> Option<bool> {
		self.persist().filter(|_| self.caps().features.ruleset_persistence).and_then(|s| s.set_persisted(name))
	}

	/// What a set's row in `rproxy_rule_sets` holds (#241): (generation, etag,
	/// owner, the rules as `config::plan::shape` in key order).
	pub async fn ruleset_row(&self, name: &str) -> Option<(u64, String, String, serde_json::Value)> {
		let s = self.rulesets.get(name)?;
		let rules = self.rules.lock().await;
		let mut specs: Vec<&RuleSpec> = rules.values().map(|e| e.spec()).filter(|s| s.ruleset.as_deref() == Some(name)).collect();
		specs.sort_by_key(|s| (s.key.protocol == crate::core::rule::Protocol::Udp, s.key.listen));
		let shapes = serde_json::Value::Array(specs.into_iter().map(crate::config::plan::shape).collect());
		Some((s.generation, s.etag, s.owner, shapes))
	}

	/// Restores the stored rule sets at startup (#241), after every other rule:
	/// each as a `PUT` by its owner. A rule that cannot be applied (its key or
	/// ports are taken by a rule restored before, a file it names is refused)
	/// is left out with `restore.conflict` / `restore.skip`; the rest of its
	/// set is applied.
	pub async fn restore_rulesets(self: &Arc<Self>, sets: Vec<crate::config::persist::StoredSet>) -> usize {
		let mut restored = 0;
		let everything = |_: u16, _: u16| true;
		for set in sets {
			let mut rules: Vec<(usize, RuleRequest)> = set.rules.into_iter().enumerate().collect();
			let mut outcome = Err(String::new());
			// each round leaves out the rules the last one refused
			for _ in 0..4 {
				let req = RulesetRequest { generation: set.generation, rules: rules.iter().map(|(_, r)| r.clone()).collect() };
				let opts = PutOptions {
					if_match: None,
					dry_run: false,
					by: &set.updated_by,
					admin: true,
					owner: Some(&set.owner),
					may_use_ports: &everything,
				};
				match self.put_ruleset(&set.name, req, opts).await {
					Ok(applied) => {
						outcome = Ok(applied.etag);
						break;
					}
					Err(e) if e.errors.is_empty() => {
						outcome = Err(e.error.message);
						break;
					}
					Err(e) => {
						let refused: HashSet<usize> = e.errors.iter().map(|f| f.index).collect();
						for f in &e.errors {
							let event = if matches!(f.code, "static" | "owned" | "already_exists" | "reserved") { "restore.conflict" } else { "restore.skip" };
							warn!(event, ruleset = %set.name, rule = %f.rule, code = f.code, error = %f.message,
								"left out of the stored rule set; the rest is restored");
						}
						rules = rules.into_iter().enumerate().filter(|(i, _)| !refused.contains(i)).map(|(_, r)| r).collect();
						outcome = Err(e.error.message);
					}
				}
			}
			match outcome {
				Ok(etag) => {
					restored += 1;
					if etag != set.etag {
						info!(event = "ruleset.restore", ruleset = %set.name, generation = set.generation, etag = %etag,
							stored_etag = %set.etag, "restored with a different etag (rules were left out)");
					} else {
						info!(event = "ruleset.restore", ruleset = %set.name, generation = set.generation, etag = %etag);
					}
				}
				Err(e) => error!(event = "restore.error", ruleset = %set.name, error = %e, "the stored rule set is not restored"),
			}
		}
		restored
	}

	/// `?dry_run=true` on `PUT /rulesets/{name}` (#169): what the PUT would do,
	/// after the same checks; nothing changes. The hook for the plan engine
	/// (`config::plan`).
	fn ruleset_dry_run(&self, name: &str, generation: u64, etag: String, steps: &[Step]) -> Result<RulesetApplied, SetError> {
		let results = steps
			.iter()
			.map(|s| ApplyResult {
				rule: s.key.to_string(),
				action: s.action,
				change: s.change,
				state: None,
				error: None,
				diff: match (s.action, &s.old, &s.spec) {
					// the same shapes and paths as the other dry runs (#169)
					("update", Some(old), Some(new)) => crate::config::plan::rule_diff(Some(old), Some(new)),
					_ => vec![],
				},
			})
			.collect();
		Ok(RulesetApplied { name: name.to_string(), generation, etag, dry_run: true, results, persisted: None })
	}

	/// Starts a rule of a set. One that cannot bind or resolve its targets is
	/// registered as failed (Ok); Err when it could not be registered at all
	/// (its key was taken meanwhile).
	async fn start_member(self: &Arc<Self>, spec: RuleSpec) -> Result<(), ApiError> {
		let key = spec.key;
		match self.create_spec(spec.clone()).await {
			Ok(_) => Ok(()),
			Err(e) if e.code == "already_exists" || e.code == "reserved" => {
				error!(event = "rule.failed", rule = %key, error = %e.message, phase = "ruleset");
				Err(e)
			}
			Err(e) => {
				error!(event = "rule.failed", rule = %key, error = %e.message, phase = "ruleset");
				self.insert_failed(spec, e).await;
				Ok(())
			}
		}
	}

	/// Stops a rule of a set and starts it with its new shape.
	async fn recreate_member(self: &Arc<Self>, spec: RuleSpec) -> Result<(), ApiError> {
		let key = spec.key;
		let entry = {
			let mut rules = self.rules.lock().await;
			match rules.get(&key) {
				Some(e) if e.spec().ruleset == spec.ruleset => rules.remove(&key),
				_ => None,
			}
		};
		if let Some(entry) = entry {
			self.stop_entry(&key, entry, None).await;
		}
		self.start_member(spec).await
	}
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

	fn spec(port: u16) -> RuleSpec {
		let req: RuleRequest = serde_json::from_value(serde_json::json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "remote_addr": "127.0.0.1", "remote_port": 9,
			"labels": {"b": "2", "a": "1"}
		}))
		.unwrap();
		req.validate(&crate::core::rule::Caps { features: crate::core::rule::Features::ALL, ..Default::default() }).unwrap()
	}

	#[test]
	fn etags_follow_the_rules_and_the_generation() {
		let (a, b) = (spec(1), spec(2));
		let tag = etag(3, &[&a, &b]);
		assert!(tag.starts_with("g3-") && tag.len() == 19, "{tag}");
		assert_eq!(tag, etag(3, &[&b, &a]), "the order of the rules does not matter");
		assert_ne!(tag, etag(4, &[&a, &b]));
		let mut c = b.clone();
		c.remote_port = 10;
		assert_ne!(tag, etag(3, &[&a, &c]));
		assert!(spec_json(&a).get("state").is_none() && spec_json(&a).get("labels").is_some());
		assert!(if_match("\"g3-x\"", "g3-x") && if_match("g3-x", "g3-x") && if_match("W/\"g3-x\"", "g3-x"));
		assert!(if_match("\"a\", \"g3-x\"", "g3-x") && if_match("*", "g3-x"));
		assert!(!if_match("\"g3-y\"", "g3-x"));
	}

	#[test]
	fn last_transition_moves_only_when_the_status_changes() {
		let log = ConditionLog::default();
		let key = spec(1).key;
		let f = |status: &'static str, reason: &'static str, since: Option<u64>| {
			vec![Found { kind: "Programmed", status, reason, message: String::new(), since }]
		};
		assert_eq!(log.stamp_at(key, f("True", "Listening", Some(50)), 100)[0].last_transition, 50, "known start");
		assert_eq!(log.stamp_at(key, f("True", "Listening", Some(60)), 200)[0].last_transition, 50);
		let failed = log.stamp_at(key, f("False", "BindFailed", None), 300);
		assert_eq!((failed[0].status, failed[0].last_transition), ("False", 300));
		assert_eq!(log.stamp_at(key, f("False", "Failed", None), 400)[0].last_transition, 300, "a new reason alone keeps the time");
		log.forget(&key);
		assert_eq!(log.stamp_at(key, f("False", "Failed", None), 500)[0].last_transition, 500);
	}

	#[test]
	fn conditions_from_the_view() {
		let s = spec(1);
		let mut view = RuleView::new(&s, State::Running, None, &[], 0);
		view.started_at = Some(42);
		let c = conditions(&view, None);
		let kinds: Vec<(&str, &str, &str)> = c.iter().map(|f| (f.kind, f.status, f.reason)).collect();
		assert_eq!(
			kinds,
			[("Accepted", "True", "Accepted"), ("Programmed", "True", "Listening"), ("ResolvedRefs", "True", "ResolvedRefs"), ("BackendsHealthy", "True", "Healthy")]
		);
		assert_eq!(c[1].since, Some(42));
		view.all_targets_down = true;
		assert_eq!(conditions(&view, None)[3].reason, "AllTargetsDown");
		view.all_targets_down = false;
		view.down_services = vec!["api".into()];
		let c = conditions(&view, None);
		assert_eq!((c[3].reason, c[3].message.as_str()), ("ServiceDown", "no server up: api"));

		let failed = |code: &'static str, retrying: bool, error: &str| {
			let view = RuleView::new(&s, State::Failed, Some(error.into()), &[], 0);
			conditions(&view, Some((code, retrying))).into_iter().map(|f| (f.status, f.reason)).collect::<Vec<_>>()
		};
		assert_eq!(failed("bind_failed", false, "in use")[1], ("False", "BindFailed"));
		assert_eq!(failed("bind_failed", false, "in use")[3], ("Unknown", "NotProgrammed"));
		let resolve = failed("resolve_failed", true, "a: no addresses");
		assert_eq!((resolve[1], resolve[2]), (("False", "Pending"), ("False", "ResolveFailed")));
		let unsupported = failed("unsupported", false, "limits is not available");
		assert_eq!((unsupported[0], unsupported[1]), (("False", "Unsupported"), ("False", "Failed")));
		assert_eq!(failed("tls_config", false, "cannot read cert.pem")[2], ("False", "CertificateUnreadable"));
		let expired = format!("{} cert.pem", crate::tls::config::CERT_EXPIRED);
		assert_eq!(failed("tls_config", false, &expired)[2], ("False", "CertificateExpired"));
		assert_eq!(failed("invalid", false, "users_file: no such file")[2], ("False", "SecretUnreadable"));
		assert_eq!(failed("failed", false, "listener stopped")[1], ("False", "Failed"));
	}

	#[test]
	fn label_metrics_lines() {
		let a = spec(1);
		let mut odd = Labels::new();
		odd.insert("a.b".into(), "x\"y".into());
		odd.insert("a_b".into(), "dropped".into());
		let none = Labels::new();
		let mut out = String::new();
		label_metrics(&mut out, [(&a.key, &a.labels), (&a.key, &odd), (&a.key, &none)].into_iter());
		assert!(out.contains("rproxy_rule_labels{rule=\"tcp/127.0.0.1:1\",label_a=\"1\",label_b=\"2\"} 1\n"), "{out}");
		assert!(out.contains("rproxy_rule_labels{rule=\"tcp/127.0.0.1:1\",label_a_b=\"x\\\"y\"} 1\n"), "{out}");
		assert_eq!(out.matches("rproxy_rule_labels{").count(), 2);
		let mut empty = String::new();
		label_metrics(&mut empty, [(&a.key, &none)].into_iter());
		assert!(empty.is_empty());
		assert_eq!(labels_text(&a.labels), "a=1,b=2");
	}

	#[test]
	fn readiness_states() {
		let r = Readiness::default();
		assert_eq!(r.check(), Err("starting"));
		r.set_ready();
		assert_eq!(r.check(), Ok(()));
		r.set_draining();
		r.set_ready();
		assert_eq!(r.check(), Err("draining"), "not ready again once draining");
	}
}
