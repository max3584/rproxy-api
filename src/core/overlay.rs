//! What the API adds on a static rule's listener (#397, docs/DESIGN-v0.4.x.md 26.):
//! routes, services and middlewares of `http`, and `tls.routes`, held apart from the
//! file's rule (`Registry.overlays`) and merged into what the rule runs with
//! (`Registry::prepare`). The file wins: its routes are tried first, and a name both
//! define is the file's (the overlay's item is left out, `shadowed`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::core::rule::{Features, RuleSpec};
use crate::error::ApiError;
use crate::l7::{HttpSpec, MiddlewareSpec, OverlayMarks, RouteSpec, ServiceSpec};
use crate::tls::config::{ClientAuthMode, Route, TlsMode};

/// The body of `PUT /rules/{key}/overlay`, as stored (`rproxy_rule_overlays.spec`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlaySpec {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub http: Option<OverlayHttp>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tls: Option<OverlayTls>,
}

/// The overlay's part of `http`: what may be added. `pre_routing`, `default`, `http3`,
/// `raw_path` and `strict_path` are the file's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayHttp {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub routes: Vec<RouteSpec>,
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub services: BTreeMap<String, ServiceSpec>,
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub middlewares: BTreeMap<String, MiddlewareSpec>,
}

impl OverlayHttp {
	fn is_empty(&self) -> bool {
		self.routes.is_empty() && self.services.is_empty() && self.middlewares.is_empty()
	}
}

/// The overlay's part of `tls`: more server names (`routes`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayTls {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub routes: Vec<Route>,
}

impl OverlaySpec {
	fn http_part(&self) -> Option<&OverlayHttp> {
		self.http.as_ref().filter(|h| !h.is_empty())
	}

	fn tls_routes(&self) -> &[Route] {
		self.tls.as_ref().map(|t| t.routes.as_slice()).unwrap_or_default()
	}

	/// Whether the http part changes between `self` and `other` (the router is rebuilt).
	pub fn http_differs(&self, other: Option<&OverlaySpec>) -> bool {
		self.http_part() != other.and_then(OverlaySpec::http_part)
	}

	/// Whether `tls.routes` change between `self` and `other`.
	pub fn tls_differs(&self, other: Option<&OverlaySpec>) -> bool {
		self.tls_routes() != other.map(OverlaySpec::tls_routes).unwrap_or_default()
	}

	/// What the API is sent must hold on its own: names (`l7::check_name`), and no file
	/// read for a `tls.routes` entry (`upstream`).
	pub fn check(&self) -> Result<(), ApiError> {
		if let Some(h) = &self.http {
			let alone = HttpSpec {
				routes: h.routes.clone(),
				services: h.services.clone(),
				middlewares: h.middlewares.clone(),
				..Default::default()
			};
			alone.check_names()?;
		}
		for r in self.tls_routes() {
			if r.upstream.is_some() {
				return Err(ApiError::invalid(format!(
					"tls.routes {}: an overlay's route takes no upstream (the rule's is used)",
					r.patterns().join(",")
				)));
			}
		}
		Ok(())
	}

	/// `ETag` of `GET` / `PUT` and what `If-Match` is compared with: the first 16 hex digits
	/// of the SHA-256 of the shape.
	pub fn etag(&self) -> String {
		use sha2::Digest;
		let body = serde_json::to_vec(self).unwrap_or_default();
		let digest = sha2::Sha256::digest(&body);
		let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
		format!("\"o-{hex}\"")
	}

	/// Files it names (#319, #323): its services' `tls`, its middlewares' secrets.
	pub fn file_refs(&self) -> Vec<crate::net::protected::FileRef> {
		match &self.http {
			Some(h) => {
				let http = HttpSpec {
					routes: h.routes.clone(),
					services: h.services.clone(),
					middlewares: h.middlewares.clone(),
					..Default::default()
				};
				crate::net::protected::refs(None, Some(&http))
			}
			None => vec![],
		}
	}
}

/// An item of the overlay left out because the file has the name (or uses such an item).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shadowed {
	/// `route`, `service`, `middleware` or `tls_route` (one server name pattern).
	pub kind: String,
	pub name: String,
	pub reason: String,
}

/// Why an overlay does not apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
	/// No static rule has the key (any more).
	NoStaticRule,
	/// The file's rule cannot take it: no `http`, another `tls.mode`.
	Shape,
	/// Merged, it does not validate (the file took away a service it used, ...).
	Invalid,
	/// Building it failed (a file it names, a name in it).
	Failed,
}

impl Reason {
	pub fn as_str(&self) -> &'static str {
		match self {
			Reason::NoStaticRule => "no_static_rule",
			Reason::Shape => "shape",
			Reason::Invalid => "invalid",
			Reason::Failed => "failed",
		}
	}
}

/// Whether an overlay is in what its rule runs with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
	Applied { shadowed: Vec<Shadowed> },
	NotApplied { reason: Reason, error: String },
}

/// One rule's overlay as the registry holds it.
#[derive(Clone, Debug)]
pub struct Overlay {
	pub spec: OverlaySpec,
	pub created_by: String,
	/// Unix seconds.
	pub created_at: u64,
	pub updated_by: String,
	pub updated_at: u64,
	pub status: Status,
}

/// A static rule's spec with its overlay merged in.
#[derive(Debug)]
pub struct Merged {
	pub spec: RuleSpec,
	/// Where the overlay's `tls.routes` start (the file's count).
	pub tls_from: usize,
	pub shadowed: Vec<Shadowed>,
}

fn shape(message: impl Into<String>) -> (Reason, ApiError) {
	(Reason::Shape, ApiError::invalid(message))
}

/// The service a middleware sends to (`mirror`, `forward_auth`'s `service`, `errors`).
fn service_of(m: &MiddlewareSpec) -> Option<&String> {
	match m {
		MiddlewareSpec::Mirror { service, .. } | MiddlewareSpec::Errors { service, .. } => Some(service),
		MiddlewareSpec::ForwardAuth { service, .. } => service.as_ref(),
		_ => None,
	}
}

/// Merges `overlay` into the file's rule `file`: the file's routes first, the overlay's
/// after them (`OverlayMarks`, `tls_from`); a name both define is the file's, and the
/// overlay's item goes (with what of the overlay uses it) into `shadowed`. The result is
/// validated as a whole. Err: why it cannot apply.
pub fn merge(file: &RuleSpec, overlay: &OverlaySpec, features: &Features) -> Result<Merged, (Reason, ApiError)> {
	let mut spec = file.clone();
	let mut shadowed = vec![];
	let mut shadow = |kind: &str, name: &str, reason: String| shadowed.push(Shadowed { kind: kind.into(), name: name.into(), reason });
	if let Some(ov) = overlay.http_part() {
		let Some(f) = &file.http else {
			return Err(shape("the static rule has no http; routes, services and middlewares need an http rule"));
		};
		let mut gone_services: BTreeSet<&String> = BTreeSet::new();
		let mut gone_middlewares: BTreeSet<&String> = BTreeSet::new();
		for name in ov.services.keys().filter(|n| f.services.contains_key(*n)) {
			shadow("service", name, "the settings file defines it".into());
			gone_services.insert(name);
		}
		for name in ov.middlewares.keys().filter(|n| f.middlewares.contains_key(*n)) {
			shadow("middleware", name, "the settings file defines it".into());
			gone_middlewares.insert(name);
		}
		// what uses an item left out goes too: it would use the file's namesake instead
		loop {
			let mut more = false;
			for (name, m) in &ov.middlewares {
				if gone_middlewares.contains(name) {
					continue;
				}
				if let Some(s) = service_of(m).filter(|s| gone_services.contains(s)) {
					shadow("middleware", name, format!("uses service {s:?}, which the settings file defines"));
					gone_middlewares.insert(name);
					more = true;
				}
			}
			for (name, svc) in &ov.services {
				if gone_services.contains(name) {
					continue;
				}
				if let Some(m) = svc.servers.iter().flat_map(|s| &s.middlewares).find(|m| gone_middlewares.contains(m)) {
					shadow("service", name, format!("uses middleware {m:?}, which is left out"));
					gone_services.insert(name);
					more = true;
				}
			}
			if !more {
				break;
			}
		}
		let mut merged = f.clone();
		let mut marks = OverlayMarks { first_route: f.routes.len(), middlewares: BTreeSet::new() };
		for (name, s) in ov.services.iter().filter(|(n, _)| !gone_services.contains(n)) {
			merged.services.insert(name.clone(), s.clone());
		}
		for (name, m) in ov.middlewares.iter().filter(|(n, _)| !gone_middlewares.contains(n)) {
			merged.middlewares.insert(name.clone(), m.clone());
			marks.middlewares.insert(name.clone());
		}
		for r in &ov.routes {
			if f.routes.iter().any(|x| x.name == r.name) {
				shadow("route", &r.name, "the settings file defines it".into());
			} else if let Some(s) = r.service.as_ref().filter(|s| gone_services.contains(s)) {
				shadow("route", &r.name, format!("uses service {s:?}, which the settings file defines"));
			} else if let Some(m) = r.middlewares.iter().find(|m| gone_middlewares.contains(m)) {
				shadow("route", &r.name, format!("uses middleware {m:?}, which is left out"));
			} else {
				merged.routes.push(r.clone());
			}
		}
		merged.overlay = Some(marks);
		merged.validate().map_err(|e| (Reason::Invalid, e))?;
		crate::core::rule::check_http_tls(&spec.tls, spec.source_ip, &merged).map_err(|e| (Reason::Invalid, e))?;
		spec.http = Some(merged);
	}
	let tls_from = file.tls.routes.len();
	if !overlay.tls_routes().is_empty() {
		match file.tls.mode {
			TlsMode::Sni => {}
			TlsMode::Terminate if file.http.is_some() => {
				return Err(shape("tls.routes cannot be added to an http rule (they would skip its routes); add http.routes"));
			}
			TlsMode::Terminate if file.tls.client_auth.mode != ClientAuthMode::None => {
				return Err(shape("tls.routes cannot be added to a rule with client_auth (they would skip the client check)"));
			}
			TlsMode::Terminate => {}
			_ => return Err(shape("tls.routes need a static rule with tls mode sni (or terminate without http and client_auth)")),
		}
		let taken: BTreeSet<String> = file.tls.routes.iter().flat_map(|r| r.patterns()).collect();
		for r in overlay.tls_routes() {
			let mut kept = vec![];
			for p in r.patterns() {
				if taken.contains(&p) {
					shadow("tls_route", &p, "the settings file routes this name".into());
				} else if !kept.contains(&p) {
					kept.push(p);
				}
			}
			if kept.is_empty() {
				continue;
			}
			let mut route = r.clone();
			if kept != r.patterns() {
				route.server_name = String::new();
				route.server_names = kept;
			}
			spec.tls.routes.push(route);
		}
		crate::tls::config::validate_range(spec.key.protocol, &spec.tls, spec.starttls, spec.port_count)
			.map_err(|e| (Reason::Invalid, e))?;
	}
	features.check(&spec.tls, spec.http.as_ref()).map_err(|e| (Reason::Invalid, e))?;
	Ok(Merged { spec, tls_from, shadowed })
}

/// What a `PUT` / `DELETE` of an overlay does (the answer of a dry run, `action` of the audit).
#[derive(Clone, Debug, Serialize)]
pub struct Change {
	pub dry_run: bool,
	/// `create`, `update`, `delete` or `none`.
	pub action: &'static str,
	pub rule: String,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub before: Option<serde_json::Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub after: Option<serde_json::Value>,
	pub diff: Vec<crate::config::plan::DiffEntry>,
}

impl Change {
	pub fn of(key: &crate::core::rule::Key, before: Option<&OverlaySpec>, after: Option<&OverlaySpec>) -> Change {
		let action = match (before, after) {
			(None, Some(_)) => "create",
			(Some(_), None) => "delete",
			(Some(b), Some(a)) if b == a => "none",
			_ => "update",
		};
		let json = |o: Option<&OverlaySpec>| o.map(|o| serde_json::to_value(o).unwrap_or_default());
		let (before, after) = (json(before), json(after));
		let empty = serde_json::Value::Object(Default::default());
		let diff = crate::config::plan::diff(before.as_ref().unwrap_or(&empty), after.as_ref().unwrap_or(&empty));
		Change { dry_run: true, action, rule: key.to_string(), before, after, diff }
	}
}

/// What `GET /rules/{key}/overlay` answers.
#[derive(Clone, Debug, Serialize)]
pub struct OverlayView {
	pub rule: String,
	#[serde(flatten)]
	pub spec: OverlaySpec,
	/// `applied` or `not_applied`.
	pub state: &'static str,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reason: Option<&'static str>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub shadowed: Vec<Shadowed>,
	pub etag: String,
	pub created_by: String,
	pub created_at: u64,
	pub updated_by: String,
	pub updated_at: u64,
	/// Whether `rproxy_rule_overlays` has it as it is (absent without a database).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub persisted: Option<bool>,
}

/// What a rule's view says of its overlay (`overlay` in `GET /rules`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OverlaySummary {
	pub state: &'static str,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub reason: Option<&'static str>,
	/// Items of the overlay in force (routes, services, middlewares, tls.routes entries).
	pub routes: usize,
	pub tls_routes: usize,
	#[serde(skip_serializing_if = "is_zero")]
	pub shadowed: usize,
}

fn is_zero(n: &usize) -> bool {
	*n == 0
}

impl Overlay {
	/// `state` and `reason`, with no static rule under the key (`exists` false) said first.
	pub fn state(&self, exists: bool) -> (&'static str, Option<Reason>) {
		match (&self.status, exists) {
			(_, false) => ("not_applied", Some(Reason::NoStaticRule)),
			(Status::Applied { .. }, true) => ("applied", None),
			(Status::NotApplied { reason, .. }, true) => ("not_applied", Some(*reason)),
		}
	}

	pub fn view(&self, rule: String, exists: bool, persisted: Option<bool>) -> OverlayView {
		let (state, reason) = self.state(exists);
		let (shadowed, error) = match &self.status {
			Status::Applied { shadowed } if exists => (shadowed.clone(), None),
			Status::NotApplied { error, .. } if exists => (vec![], Some(error.clone())),
			_ => (vec![], None),
		};
		OverlayView {
			rule,
			etag: self.spec.etag(),
			spec: self.spec.clone(),
			state,
			reason: reason.map(|r| r.as_str()),
			error,
			shadowed,
			created_by: self.created_by.clone(),
			created_at: self.created_at,
			updated_by: self.updated_by.clone(),
			updated_at: self.updated_at,
			persisted,
		}
	}

	pub fn summary(&self) -> OverlaySummary {
		let (state, reason) = self.state(true);
		let shadowed = match &self.status {
			Status::Applied { shadowed } => shadowed.as_slice(),
			Status::NotApplied { .. } => &[],
		};
		let gone = |kind: &str, name: &str| shadowed.iter().any(|s| s.kind == kind && s.name == name);
		let applied = state == "applied";
		OverlaySummary {
			state,
			reason: reason.map(|r| r.as_str()),
			routes: if applied {
				self.spec.http.as_ref().map_or(0, |h| h.routes.iter().filter(|r| !gone("route", &r.name)).count())
			} else {
				0
			},
			tls_routes: if applied {
				self.spec.tls_routes().iter().filter(|r| r.patterns().iter().any(|p| !gone("tls_route", p))).count()
			} else {
				0
			},
			shadowed: shadowed.len(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::core::rule::{Caps, RuleRequest};

	fn rule(body: serde_json::Value) -> RuleSpec {
		let req: RuleRequest = serde_json::from_value(body).unwrap();
		let caps = Caps { transparent: false, transparent_ipv6: false, max_range_ports: 100, features: Features::CURRENT };
		req.validate(&caps).unwrap()
	}

	fn http_rule() -> RuleSpec {
		rule(serde_json::json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": 8080,
			"http": {
				"routes": [{"name": "app", "match": "Host(`a.test`)", "service": "app", "middlewares": ["auth"]}],
				"services": {"app": {"servers": [{"url": "http://127.0.0.1:1"}]}},
				"middlewares": {"auth": {"ip_allow": {"source_range": ["10.0.0.0/8"]}}}
			}
		}))
	}

	fn overlay(body: serde_json::Value) -> OverlaySpec {
		serde_json::from_value(body).unwrap()
	}

	#[test]
	fn routes_services_and_middlewares_are_added_after_the_files() {
		let ov = overlay(serde_json::json!({"http": {
			"routes": [{"name": "b", "match": "Host(`b.test`)", "service": "b", "middlewares": ["auth", "hdr"], "priority": 9999}],
			"services": {"b": {"servers": [{"url": "http://127.0.0.1:2"}]}},
			"middlewares": {"hdr": {"headers": {"request": {"set": {"x-a": "1"}}}}}
		}}));
		let m = merge(&http_rule(), &ov, &Features::CURRENT).unwrap();
		let h = m.spec.http.unwrap();
		assert_eq!(h.routes.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["app", "b"]);
		assert_eq!(h.overlay.as_ref().unwrap().first_route, 1);
		assert!(h.overlay.as_ref().unwrap().middlewares.contains("hdr"));
		assert!(h.services.contains_key("b"));
		assert!(m.shadowed.is_empty());
	}

	#[test]
	fn the_file_wins_on_names_and_what_uses_the_overlays_item_goes_too() {
		let ov = overlay(serde_json::json!({"http": {
			"routes": [
				{"name": "app", "match": "Host(`x.test`)", "to": "http://127.0.0.1:3"},
				{"name": "uses", "match": "Host(`y.test`)", "service": "app"},
				{"name": "mw", "match": "Host(`z.test`)", "to": "http://127.0.0.1:3", "middlewares": ["auth"]},
				{"name": "ok", "match": "Host(`w.test`)", "to": "http://127.0.0.1:3"}
			],
			"services": {"app": {"servers": [{"url": "http://127.0.0.1:2"}]}},
			"middlewares": {"auth": {"respond": {"status": 200}}}
		}}));
		let m = merge(&http_rule(), &ov, &Features::CURRENT).unwrap();
		let names: Vec<_> = m.shadowed.iter().map(|s| format!("{}:{}", s.kind, s.name)).collect();
		assert_eq!(names, ["service:app", "middleware:auth", "route:app", "route:uses", "route:mw"]);
		let h = m.spec.http.unwrap();
		assert_eq!(h.routes.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["app", "ok"]);
		assert_eq!(h.services["app"].servers[0].url, "http://127.0.0.1:1", "the file's service stays");
	}

	#[test]
	fn http_needs_an_http_rule_and_a_merge_that_validates() {
		let plain = rule(
			serde_json::json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": 8081, "remote_addr": "127.0.0.1", "remote_port": 1}),
		);
		let ov = overlay(serde_json::json!({"http": {"routes": [{"name": "b", "match": "Host(`b.test`)", "to": "http://127.0.0.1:2"}]}}));
		assert_eq!(merge(&plain, &ov, &Features::CURRENT).unwrap_err().0, Reason::Shape);
		let missing = overlay(serde_json::json!({"http": {"routes": [{"name": "b", "match": "Host(`b.test`)", "service": "nope"}]}}));
		assert_eq!(merge(&http_rule(), &missing, &Features::CURRENT).unwrap_err().0, Reason::Invalid);
	}

	#[test]
	fn tls_routes_add_names_the_file_does_not_route() {
		let sni = rule(serde_json::json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": 8443, "remote_addr": "127.0.0.1", "remote_port": 1,
			"tls": {"mode": "sni", "routes": [{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": 2}]}
		}));
		let ov = overlay(serde_json::json!({"tls": {"routes": [
			{"server_names": ["A.test", "b.test"], "remote_addr": "127.0.0.1", "remote_port": 3},
			{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": 4}
		]}}));
		let m = merge(&sni, &ov, &Features::CURRENT).unwrap();
		assert_eq!(m.tls_from, 1);
		assert_eq!(m.spec.tls.routes.len(), 2);
		assert_eq!(m.spec.tls.routes[1].server_names, ["b.test"]);
		assert_eq!(m.shadowed.len(), 2);
		let terminate_http = http_rule();
		assert_eq!(merge(&terminate_http, &ov, &Features::CURRENT).unwrap_err().0, Reason::Shape);
	}

	#[test]
	fn an_overlay_route_takes_no_upstream_and_names_are_checked() {
		let ov = overlay(
			serde_json::json!({"tls": {"routes": [{"server_name": "b.test", "remote_addr": "127.0.0.1", "remote_port": 3, "upstream": {"tls": true}}]}}),
		);
		assert!(ov.check().is_err());
		let bad = overlay(serde_json::json!({"http": {"services": {"a b": {"servers": [{"url": "http://127.0.0.1:2"}]}}}}));
		assert!(bad.check().is_err());
		assert!(serde_json::from_value::<OverlaySpec>(serde_json::json!({"http": {"pre_routing": ["x"]}})).is_err());
	}

	#[test]
	fn the_etag_follows_the_shape() {
		let a = overlay(serde_json::json!({"http": {"routes": [{"name": "b", "match": "Host(`b.test`)", "to": "http://127.0.0.1:2"}]}}));
		let b = overlay(serde_json::json!({"http": {"routes": [{"name": "b", "match": "Host(`b.test`)", "to": "http://127.0.0.1:3"}]}}));
		assert_ne!(a.etag(), b.etag());
		assert_eq!(a.etag(), a.clone().etag());
	}
}
