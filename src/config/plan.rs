//! Diff before change (#169, docs/DESIGN-v0.4.md 8.): `dry_run` on the rule
//! endpoints and `POST /config/reload`, `POST /config/plan`, and
//! `rproxy-api --check-config --diff`.
//!
//! A dry run goes through the same validation as the change itself (the same
//! `400` / `409` answers), reads certificates and secret files, and neither
//! binds sockets nor resolves names. The functions here are what the rule
//! endpoints, the settings file and rule sets (`PUT /rulesets/{name}?dry_run`,
//! #28: `plan_replace` and `plan_delete` per rule) share.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::check::Finding;
use crate::config::ConfigDoc;
use crate::core::registry::{is_dual_stack_wildcard, overlaps, Registry, ReloadCounts};
use crate::core::rule::{Key, Origin, RuleRequest, RuleSpec, State, UpdateRequest};
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

/// A rule in the shape of the body of `POST /rules` (the view without its
/// state, counters and origin): what `before` / `after` are compared in, and
/// what `rproxy_rules.spec` stores (#144). Reads back as a `RuleRequest` that
/// validates to the same rule.
pub fn shape(spec: &RuleSpec) -> Value {
	let view = crate::core::rule::RuleView::new(spec, State::Running, None, &[], 0);
	let mut v = serde_json::to_value(view).unwrap_or_default();
	if let Some(map) = v.as_object_mut() {
		for key in [
			"origin", "ruleset", "conditions", "persisted", "created_by", "created_at", "state", "error", "resolved",
			"connections", "all_targets_down", "down_services", "stats", "started_at", "cert_status", "acme",
		] {
			map.remove(key);
		}
		// with targets (or http services) the first target is only shown for older clients
		if !spec.targets.is_empty() || spec.http.is_some() {
			map.remove("remote_addr");
			map.remove("remote_port");
		}
		if map.get("listen_port_end").is_some_and(Value::is_null) {
			map.remove("listen_port_end");
		}
	}
	v
}

/// Whether `new` can take the place of the running `old` without dropping
/// connections (what PATCH can change); otherwise the rule is re-created.
pub fn in_place(old: &RuleSpec, new: &RuleSpec) -> bool {
	old.key == new.key
		&& old.port_count == new.port_count
		&& old.source_ip == new.source_ip
		&& old.listen_freebind == new.listen_freebind
		&& old.http.is_some() == new.http.is_some()
		&& !(is_dual_stack_wildcard(&old.key) && old.v6only() != new.v6only())
}

/// How replacing `old` (running or not) with `new` takes effect.
fn change_of(old: &RuleSpec, running: bool, new: &RuleSpec) -> (Action, Change) {
	if old == new {
		(Action::None, Change::None)
	} else if running && in_place(old, new) {
		(Action::Update, Change::InPlace)
	} else {
		(Action::Update, Change::Recreate)
	}
}

fn connections_warning(view: &crate::core::rule::RuleView) -> Vec<String> {
	if view.connections > 0 {
		vec![format!("{} open connection(s) would be closed", view.connections)]
	} else {
		vec![]
	}
}

/// `POST /rules?dry_run=true`: a new rule.
///
/// `change` says how an `update` takes effect (`in_place` or `recreate`);
/// it is `none` for `create`, `delete` and `none` (as in `PUT /rulesets`).
pub async fn plan_create(registry: &Registry, req: RuleRequest) -> Result<RulePlan, ApiError> {
	let spec = req.validate(&registry.caps())?;
	registry.check_start(&spec, None).await?;
	let after = shape(&spec);
	Ok(RulePlan {
		dry_run: true,
		action: Action::Create,
		change: Change::None,
		rule: spec.key.to_string(),
		before: None,
		diff: diff(&Value::Object(Default::default()), &after),
		after: Some(after),
		warnings: vec![],
	})
}

/// `PATCH /rules/...?dry_run=true`. PATCH changes rules in place (what it
/// cannot is refused, as the change itself would); a failed rule is started.
pub async fn plan_update(registry: &Registry, key: &Key, req: UpdateRequest) -> Result<RulePlan, ApiError> {
	let (old, new, _, _) = registry.updated_spec(key, req).await?;
	let (_, running, view) = registry.current(key).await.ok_or_else(|| ApiError::not_found(key.to_string()))?;
	if running && old.extra_listen != new.extra_listen && is_dual_stack_wildcard(key) && old.v6only() != new.v6only() {
		return Err(ApiError::unsupported(
			"a rule on :: listens dual-stack alone and IPv6-only with extra_listen_addrs; delete and re-create it to switch",
		));
	}
	registry.check_start(&new, Some(key)).await?;
	let (action, change) = match change_of(&old, running, &new) {
		(Action::None, _) => (Action::None, Change::None),
		_ if running => (Action::Update, Change::InPlace),
		_ => (Action::Update, Change::Recreate),
	};
	Ok(rule_plan(action, change, key, Some(&old), Some(view), Some(&new), vec![]))
}

/// `DELETE /rules/...?dry_run=true`.
pub async fn plan_delete(registry: &Registry, key: &Key) -> Result<RulePlan, ApiError> {
	let (old, _, view) = registry.current(key).await.ok_or_else(|| ApiError::not_found(key.to_string()))?;
	if old.origin == Origin::Static {
		return Err(ApiError::static_rule(format!(
			"{key} is a static rule; edit the settings file (RPROXY_CONFIG), which is re-read when it changes"
		)));
	}
	if let Some(set) = &old.ruleset {
		return Err(crate::core::ruleset::owned(key, set));
	}
	let warnings = connections_warning(&view);
	Ok(rule_plan(Action::Delete, Change::None, key, Some(&old), Some(view), None, warnings))
}

/// A rule put in place as a whole (a rule set's rule, #28): created when its
/// key is free, otherwise compared with the running rule (in place when PATCH
/// could do it, else re-created). The caller checks ownership (`409 owned`).
pub async fn plan_replace(registry: &Registry, spec: &RuleSpec) -> Result<RulePlan, ApiError> {
	let key = spec.key;
	let Some((old, running, view)) = registry.current(&key).await else {
		registry.check_start(spec, None).await?;
		return Ok(rule_plan(Action::Create, Change::None, &key, None, None, Some(spec), vec![]));
	};
	registry.check_start(spec, Some(&key)).await?;
	let (action, change) = change_of(&old, running, spec);
	let warnings = if change == Change::Recreate { connections_warning(&view) } else { vec![] };
	Ok(rule_plan(action, change, &key, Some(&old), Some(view), Some(spec), warnings))
}

/// The difference between two versions of a rule, compared in their shapes
/// (`None`: no rule, compared as `{}`). What every dry run answers in `diff`.
pub fn rule_diff(old: Option<&RuleSpec>, new: Option<&RuleSpec>) -> Vec<DiffEntry> {
	let empty = Value::Object(Default::default());
	diff(&old.map(shape).unwrap_or_else(|| empty.clone()), &new.map(shape).unwrap_or(empty))
}

fn rule_plan(
	action: Action,
	change: Change,
	key: &Key,
	old: Option<&RuleSpec>,
	view: Option<crate::core::rule::RuleView>,
	new: Option<&RuleSpec>,
	warnings: Vec<String>,
) -> RulePlan {
	let after = new.map(shape);
	let diff = rule_diff(old, new);
	RulePlan {
		dry_run: true,
		action,
		change,
		rule: key.to_string(),
		before: view.map(|v| serde_json::to_value(v).unwrap_or_default()),
		after,
		diff,
		warnings,
	}
}

/// One rule in a `ConfigPlan`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigChange {
	pub rule: String,
	pub action: Action,
	pub change: Change,
	pub diff: Vec<DiffEntry>,
}

/// What applying settings (`POST /config/reload?dry_run`, `POST /config/plan`)
/// would do. The counts are those `POST /config/reload` answers.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ConfigPlan {
	pub dry_run: bool,
	#[serde(flatten)]
	pub counts: ReloadCounts,
	/// `global` settings that would take effect only after a restart.
	pub restart_needed: Vec<String>,
	/// Rules that would be created, changed or deleted.
	pub changes: Vec<ConfigChange>,
	/// Rules that would be registered as failed, certificates about to expire, ...
	pub warnings: Vec<Finding>,
}

/// Settings that could not be applied: the reason and what `--check-config` finds.
#[derive(Debug)]
pub struct PlanError {
	pub error: String,
	pub errors: Vec<Finding>,
	pub warnings: Vec<Finding>,
}

fn findings(list: Vec<(String, String)>) -> Vec<Finding> {
	list.into_iter().map(|(rule, message)| Finding { rule, message }).collect()
}

/// The settings `doc` against the static rules that run now. `base` is the
/// version the process started with (`global` changes need a restart).
pub async fn plan_config(registry: &Arc<Registry>, base: &ConfigDoc, doc: &ConfigDoc) -> Result<ConfigPlan, PlanError> {
	let check = registry.check_rules(doc.labeled_rules());
	let specs = match registry.validate_static(doc.labeled_rules()) {
		Ok(specs) => specs,
		Err(error) => {
			let errors = findings(check.errors);
			let errors = if errors.is_empty() { vec![Finding { rule: String::new(), message: error.clone() }] } else { errors };
			return Err(PlanError { error, errors, warnings: findings(check.warnings) });
		}
	};
	// what would be registered as failed is reported, as a reload reports it
	let mut plan = ConfigPlan {
		dry_run: true,
		restart_needed: doc.restart_needed(base).into_iter().map(String::from).collect(),
		warnings: findings(check.errors.into_iter().chain(check.warnings).collect()),
		..Default::default()
	};
	let all = registry.specs().await;
	let current: HashMap<Key, (RuleSpec, bool)> =
		all.iter().filter(|(s, _)| s.origin == Origin::Static).map(|(s, r)| (s.key, (s.clone(), *r))).collect();
	let others: Vec<&RuleSpec> = all.iter().map(|(s, _)| s).filter(|s| s.origin != Origin::Static).collect();
	let empty = Value::Object(Default::default());
	let wanted: std::collections::HashSet<Key> = specs.iter().map(|(s, _)| s.key).collect();
	let mut removed: Vec<&(RuleSpec, bool)> = current.iter().filter(|(k, _)| !wanted.contains(k)).map(|(_, v)| v).collect();
	removed.sort_by_key(|(s, _)| (s.key.protocol as u8, s.key.listen));
	for (old, _) in removed {
		plan.counts.removed += 1;
		plan.changes.push(ConfigChange {
			rule: old.key.to_string(),
			action: Action::Delete,
			change: Change::None,
			diff: diff(&shape(old), &empty),
		});
	}
	for (spec, missing) in specs {
		let key = spec.key;
		// starting fails when a rule made through the API holds the address
		let blocked = others.iter().find(|o| overlaps(o, &spec)).map(|o| o.key);
		let fails = missing.is_some() || blocked.is_some();
		if let Some(other) = blocked {
			plan.warnings.push(Finding {
				rule: key.to_string(),
				message: format!("{other} (not from the settings file) holds this address; the rule would be registered as failed"),
			});
		}
		match current.get(&key) {
			None => {
				plan.counts.added += 1;
				plan.counts.failed += usize::from(fails);
				plan.changes.push(ConfigChange {
					rule: key.to_string(),
					action: Action::Create,
					change: Change::None,
					diff: diff(&empty, &shape(&spec)),
				});
			}
			Some((old, _)) if *old == spec => plan.counts.unchanged += 1,
			Some((old, running)) => {
				plan.counts.changed += 1;
				plan.counts.failed += usize::from(fails);
				let (_, change) = change_of(old, *running && missing.is_none(), &spec);
				plan.changes.push(ConfigChange { rule: key.to_string(), action: Action::Update, change, diff: diff(&shape(old), &shape(&spec)) });
			}
		}
	}
	Ok(plan)
}

/// The settings file (or directory) as one JSON document in the shape
/// `POST /config/plan` takes: the rules of every file, `global` of the one that has it.
pub fn document_json(path: &std::path::Path) -> Result<Value, String> {
	let mut rules = vec![];
	let mut global = None;
	for file in crate::config::config_files(path).map_err(|e| format!("{}: {e}", path.display()))? {
		let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
		let value: Value = match file.extension().and_then(|e| e.to_str()) {
			Some("yaml" | "yml") => serde_yaml_ng::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?,
			_ => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?,
		};
		match value {
			Value::Array(list) => rules.extend(list),
			Value::Object(mut map) => {
				if let Some(Value::Array(list)) = map.remove("rules") {
					rules.extend(list);
				}
				if let Some(g) = map.remove("global") {
					global = Some(g);
				}
			}
			_ => return Err(format!("{}: not a settings document", file.display())),
		}
	}
	let mut doc = serde_json::json!({"version": 1, "rules": rules});
	if let Some(g) = global {
		doc["global"] = g;
	}
	Ok(doc)
}

/// Where `--check-config --diff` asks: `unix:/path` or an http(s) URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Api {
	Unix(std::path::PathBuf),
	Url(String),
}

impl std::str::FromStr for Api {
	type Err = String;

	fn from_str(api: &str) -> Result<Api, String> {
		match api.strip_prefix("unix:") {
			Some(path) if path.starts_with('/') => Ok(Api::Unix(path.into())),
			None if api.starts_with("http://") || api.starts_with("https://") => Ok(Api::Url(api.trim_end_matches('/').to_string())),
			_ => Err(format!("--diff-api {api:?} must be unix:/path or an http(s):// URL")),
		}
	}
}

/// Asks the running rproxy what the settings `doc` would change
/// (`POST /config/plan`). `ca_file` verifies an https control API (its own
/// certificate, `RPROXY_TLS_CERT`; else the web PKI).
pub async fn ask(api: &Api, token: Option<&str>, doc: &Value, ca_file: Option<&str>) -> Result<Value, String> {
	use bytes::Bytes;
	use http_body_util::{BodyExt, Full};
	use hyper::header;

	let body = Bytes::from(serde_json::to_vec(doc).map_err(|e| e.to_string())?);
	let mut req = hyper::Request::post("/config/plan").header(header::CONTENT_TYPE, "application/json");
	if let Some(token) = token {
		req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
	}
	let response = match api {
		Api::Unix(path) => {
			#[cfg(unix)]
			{
				let work = async {
					let stream = tokio::net::UnixStream::connect(path).await.map_err(|e| format!("{}: {e}", path.display()))?;
					let (mut sender, conn) =
						hyper::client::conn::http1::handshake::<_, Full<Bytes>>(hyper_util::rt::TokioIo::new(stream))
							.await
							.map_err(|e| e.to_string())?;
					tokio::spawn(conn);
					let req = req.header(header::HOST, "localhost").body(Full::new(body)).map_err(|e| e.to_string())?;
					let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
					let (parts, body) = resp.into_parts();
					let bytes = http_body_util::Limited::new(body, 16 << 20).collect().await.map_err(|e| e.to_string())?.to_bytes();
					Ok::<_, String>(hyper::Response::from_parts(parts, bytes))
				};
				tokio::time::timeout(std::time::Duration::from_secs(30), work)
					.await
					.map_err(|_| format!("{}: timed out", path.display()))??
			}
			#[cfg(not(unix))]
			return Err(format!("{}: Unix sockets are not available here", path.display()));
		}
		Api::Url(base) => {
			let tls = crate::acme::http::connector(ca_file)?;
			let req = req.uri(format!("{base}/config/plan")).body(body).map_err(|e| e.to_string())?;
			crate::acme::http::send(&tls, req).await?
		}
	};
	let status = response.status();
	let value: Value = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
	if !status.is_success() {
		let why = value["error"].as_str().map(str::to_string).unwrap_or_else(|| String::from_utf8_lossy(response.body()).into_owned());
		return Err(format!("POST /config/plan: {status}: {why}"));
	}
	Ok(value)
}

/// A plan for people: one line per changed rule, then what needs a restart.
pub fn plan_text(plan: &Value) -> String {
	let mut out = String::new();
	for c in plan["changes"].as_array().into_iter().flatten() {
		let mark = match c["action"].as_str() {
			Some("create") => "+",
			Some("delete") => "-",
			_ => "~",
		};
		let paths: Vec<&str> = c["diff"].as_array().into_iter().flatten().filter_map(|d| d["path"].as_str()).collect();
		out.push_str(&format!(
			"{mark} {} ({}, {}){}\n",
			c["rule"].as_str().unwrap_or(""),
			c["action"].as_str().unwrap_or(""),
			c["change"].as_str().unwrap_or(""),
			if paths.is_empty() || mark != "~" { String::new() } else { format!(": {}", paths.join(", ")) }
		));
	}
	for r in plan["restart_needed"].as_array().into_iter().flatten() {
		out.push_str(&format!("! {} changes after a restart\n", r.as_str().unwrap_or("")));
	}
	let n = |k: &str| plan[k].as_u64().unwrap_or(0);
	out.push_str(&format!(
		"plan: {} to add, {} to change, {} to remove, {} unchanged, {} would fail\n",
		n("added"),
		n("changed"),
		n("removed"),
		n("unchanged"),
		n("failed")
	));
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

	fn spec(v: Value) -> RuleSpec {
		serde_json::from_value::<RuleRequest>(v).unwrap().validate(&crate::core::rule::Caps::default()).unwrap()
	}

	/// The shape reads back as a request that validates to the same rule (it
	/// is what rproxy_rules stores, #144).
	#[test]
	fn shape_round_trips() {
		for v in [
			json!({"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 80, "remote_addr": "example.com", "remote_port": 8080}),
			json!({"protocol": "udp", "listen_addr": "::", "listen_port": 5000, "listen_port_end": 5009, "remote_addr": "2001:db8::1",
				"remote_port": 6000, "udp_idle_secs": 90, "extra_listen_addrs": ["0.0.0.0"], "source_ip": "proxy_v2"}),
			json!({"protocol": "tcp", "listen_addr": "192.0.2.10", "listen_port": 443, "listen_freebind": true, "remote_addr": "10.0.0.1",
				"remote_port": 443, "connect_timeout": "1500ms"}),
			json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": 5432, "targets": [{"addr": "db1", "port": 5432, "weight": 2},
				{"addr": "db2", "port": 5432, "backup": true}], "balance": "failover", "health_check": {"interval": "5s"},
				"allow_from": ["10.0.0.0/8", "fd00::1"], "labels": {"tenant": "a"}}),
			json!({"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 8080, "http": {
				"routes": [{"name": "a", "match": "PathPrefix(`/`)", "service": "s", "middlewares": ["h"]}],
				"services": {"s": {"servers": [{"url": "http://10.0.0.1:80"}]}},
				"middlewares": {"h": {"headers": {"request": {"set": {"X-A": "b"}}}}}}}),
		] {
			let caps = crate::core::rule::Caps { features: crate::core::rule::Features::ALL, ..Default::default() };
			let original = serde_json::from_value::<RuleRequest>(v.clone()).unwrap().validate(&caps).unwrap();
			let shaped = shape(&original);
			for gone in ["state", "stats", "origin", "connections", "resolved"] {
				assert!(shaped.get(gone).is_none(), "{gone}: {shaped}");
			}
			let back = serde_json::from_value::<RuleRequest>(shaped.clone()).unwrap_or_else(|e| panic!("{e}: {shaped}"));
			assert_eq!(back.validate(&caps).unwrap(), original, "{shaped}");
		}
	}

	#[test]
	fn what_changes_in_place() {
		let a = spec(json!({"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 80, "remote_addr": "a", "remote_port": 1}));
		let mut b = a.clone();
		b.remote_port = 2;
		assert_eq!(change_of(&a, true, &a), (Action::None, Change::None));
		assert_eq!(change_of(&a, true, &b), (Action::Update, Change::InPlace));
		assert_eq!(change_of(&a, false, &b), (Action::Update, Change::Recreate), "a failed rule is started");
		// geoip and outlier_detection (#168, #170) are changed by PATCH in place
		let mut c = a.clone();
		c.geoip = Some(serde_json::from_value(json!({"unknown": "deny"})).unwrap());
		c.outlier_detection = Some(serde_json::from_value(json!({"consecutive_failures": 3})).unwrap());
		assert!(in_place(&a, &c) && in_place(&c, &a));
		assert_eq!(change_of(&a, true, &c), (Action::Update, Change::InPlace));
		b.source_ip = crate::core::rule::SourceIp::ProxyV2;
		assert_eq!(change_of(&a, true, &b), (Action::Update, Change::Recreate), "PATCH cannot change source_ip");
		let wide = spec(json!({"protocol": "tcp", "listen_addr": "::", "listen_port": 80, "remote_addr": "a", "remote_port": 1}));
		let mut v6only = wide.clone();
		v6only.extra_listen = vec!["0.0.0.0".parse().unwrap()];
		assert!(!in_place(&wide, &v6only), ":: alone is dual-stack, with extra addresses IPv6 only");
	}

	#[test]
	fn diff_api_addresses() {
		assert_eq!("unix:/run/rproxy/api.sock".parse::<Api>().unwrap(), Api::Unix("/run/rproxy/api.sock".into()));
		assert_eq!("https://127.0.0.1:8080/".parse::<Api>().unwrap(), Api::Url("https://127.0.0.1:8080".into()));
		assert!("ftp://x".parse::<Api>().unwrap_err().contains("--diff-api"));
		assert!("unix:relative".parse::<Api>().is_err());
	}

	#[test]
	fn a_plan_as_text() {
		let plan = json!({"added": 1, "changed": 1, "removed": 1, "unchanged": 2, "failed": 0, "restart_needed": ["global.acme"],
			"changes": [
				{"rule": "tcp/0.0.0.0:80", "action": "create", "change": "none", "diff": [{"path": "remote_port", "before": null, "after": 1}]},
				{"rule": "tcp/0.0.0.0:81", "action": "update", "change": "in_place", "diff": [{"path": "remote_port", "before": 1, "after": 2}]},
				{"rule": "udp/0.0.0.0:53", "action": "delete", "change": "none", "diff": []}]});
		let text = plan_text(&plan);
		assert!(text.contains("+ tcp/0.0.0.0:80 (create, none)\n"), "{text}");
		assert!(text.contains("~ tcp/0.0.0.0:81 (update, in_place): remote_port\n"), "{text}");
		assert!(text.contains("- udp/0.0.0.0:53 (delete, none)\n"), "{text}");
		assert!(text.contains("! global.acme changes after a restart"), "{text}");
		assert!(text.contains("1 to add, 1 to change, 1 to remove, 2 unchanged"), "{text}");
	}

	#[test]
	fn a_directory_is_one_document() {
		let dir = std::env::temp_dir().join(format!("rproxy-plan-doc-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		std::fs::write(dir.join("a.yaml"), "version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}\nrules:\n  - {protocol: tcp, listen_addr: 0.0.0.0, listen_port: 1, remote_addr: a, remote_port: 1}\n").unwrap();
		std::fs::write(dir.join("b.json"), r#"[{"protocol": "udp", "listen_addr": "0.0.0.0", "listen_port": 2, "remote_addr": "b", "remote_port": 2}]"#).unwrap();
		let doc = document_json(&dir).unwrap();
		assert_eq!(doc["rules"].as_array().unwrap().len(), 2);
		assert_eq!(doc["global"]["trusted_proxies"], json!(["10.0.0.0/8"]));
		assert!(ConfigDoc::from_value(doc).is_ok());
		std::fs::remove_dir_all(dir).unwrap();
	}
}
