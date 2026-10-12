//! Traefik middlewares → rproxy middlewares (`http.middlewares`, docs/API.md). What
//! has no rproxy equivalent is left out with a note (docs/MIGRATING-FROM-TRAEFIK.md).
//!
//! The parts that depend on where the middleware comes from go through
//! [`MiddlewareEnv`]: the users of `basicAuth`, the service of `errors` and the
//! CrowdSec bouncer's global settings. The file provider (this crate's converter)
//! and Kubernetes CRDs (rproxy-gateway) answer them differently.

use std::sync::LazyLock;

use regex::Regex;

use crate::value::{
	as_bool, as_int, as_list, as_str_list, g, map, py_repr, py_str, py_str_opt, strip_provider, truthy, Map, Value,
};
use crate::NoteSink;

/// The kinds of rproxy middleware this converter writes, which rproxy-api runs (the
/// rest is refused as `unsupported` until a newer version adds it; `GET /capabilities`
/// tells for sure). Kept in step with rproxy-api's middlewares.
pub const KNOWN_MIDDLEWARES: &[&str] = &[
	"redirect_scheme",
	"redirect_regex",
	"ip_allow",
	"headers",
	"strip_prefix",
	"add_prefix",
	"replace_path",
	"replace_path_regex",
	"respond",
	"rate_limit",
	"in_flight",
	"crowdsec",
	"compress",
	"buffering",
	"retry",
	"circuit_breaker",
	"errors",
	"basic_auth",
	"forward_auth",
	"oidc",
];

/// The service options this converter writes (`http.services.<name>`).
pub const KNOWN_SERVICE_OPTIONS: &[&str] = &["health_check", "sticky", "balance"];

/// What converting a middleware needs from where it comes from.
pub trait MiddlewareEnv: NoteSink {
	/// The htpasswd file for a `basicAuth` (`cfg` is its settings). The file provider
	/// uses `usersFile`, or names a file to fill in (`/etc/rproxy/auth/<name>.htpasswd`)
	/// without copying `users`; rproxy-gateway writes the Secret's users to a file.
	/// `None` leaves the middleware out (note why).
	fn basic_auth_users_file(&mut self, name: &str, cfg: &Value, where_: &str) -> Option<String>;
	/// The rproxy service for the `service` of an `errors` middleware (a service name in
	/// the file provider, a Service reference in a CRD); the caller adds that service to
	/// the rule. `None` leaves the middleware out (note why).
	fn errors_service(&mut self, service: Option<&Value>, where_: &str) -> Option<String>;
	/// The CrowdSec bouncer's settings for `global.crowdsec` (`lapi_url`,
	/// `api_key_file`, …) and `forwardedHeadersTrustedIPs` for `global.trusted_proxies`.
	fn crowdsec_global(&mut self, global: Map, trusted_ips: Vec<Value>, where_: &str);
}

/// A middleware chain entry: a name (provider stripped) and, in a CRD, its namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainRef {
	pub name: String,
	pub namespace: Option<String>,
}

/// One converted middleware.
#[derive(Clone, Debug, PartialEq)]
pub enum Converted {
	/// An rproxy middleware (`{kind: settings}`).
	One(Value),
	/// A `chain`: the middlewares it names, in order (the caller converts them).
	Chain(Vec<ChainRef>),
	/// Nothing: left out (with a note).
	None,
}

/// A Go duration (or seconds as a number) as rproxy writes it: `500ms`, `10s`, `5m`,
/// `1h`. `default` when missing; a note and `default` when not understood.
pub fn duration(v: Option<&Value>, where_: &str, default: Option<&str>, notes: &mut dyn NoteSink) -> Option<String> {
	static PART: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"([0-9.]+)(ns|us|µs|ms|s|m|h)").unwrap());
	static NUMBER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9.]+$").unwrap());
	let ms: i64 = match v {
		None | Some(Value::Null) => return default.map(str::to_string),
		Some(Value::Str(s)) if s.is_empty() => return default.map(str::to_string),
		Some(Value::Int(i)) => i.saturating_mul(1000),
		Some(Value::Bool(b)) => *b as i64 * 1000,
		Some(Value::Float(f)) => (f * 1000.0) as i64,
		Some(other) => {
			let text = py_str(other);
			let not_understood = |notes: &mut dyn NoteSink| {
				notes.note(where_, &format!("duration {} not understood; left out", py_repr(other)));
				default.map(str::to_string)
			};
			let parts: Vec<(String, String)> = PART.captures_iter(&text).map(|c| (c[1].to_string(), c[2].to_string())).collect();
			let joined: String = parts.iter().map(|(a, b)| format!("{a}{b}")).collect();
			if parts.is_empty() || joined != text.trim() {
				if NUMBER.is_match(text.trim()) {
					return match text.trim().parse::<f64>() {
						Ok(f) => duration(Some(&Value::Float(f)), where_, default, notes),
						Err(_) => not_understood(notes),
					};
				}
				return not_understood(notes);
			}
			let mut total = 0.0;
			for (num, unit) in &parts {
				let Ok(n) = num.parse::<f64>() else { return not_understood(notes) };
				total += n * match unit.as_str() {
					"ns" => 1e-6,
					"us" | "µs" => 1e-3,
					"ms" => 1.0,
					"s" => 1000.0,
					"m" => 60000.0,
					_ => 3600000.0,
				};
			}
			total.round_ties_even() as i64
		}
	};
	for (size, unit) in [(3600000, "h"), (60000, "m"), (1000, "s")] {
		if ms != 0 && ms % size == 0 {
			return Some(format!("{}{unit}", ms.div_euclid(size)));
		}
	}
	Some(format!("{}ms", ms.max(1)))
}

fn s(v: Option<&Value>) -> Value {
	v.cloned().unwrap_or(Value::Null)
}

fn headers(cfg: &Value, where_: &str, env: &mut dyn MiddlewareEnv) -> Value {
	let mut out = Map::new();
	let mut req = (Map::new(), Vec::<Value>::new());
	let mut resp = (Map::new(), Vec::<Value>::new());
	for (key, ops) in [("customRequestHeaders", &mut req), ("customResponseHeaders", &mut resp)] {
		if let Some(Value::Map(m)) = g(cfg, &[key]) {
			for (k, v) in m.iter() {
				if matches!(v, Value::Null) || matches!(v, Value::Str(s) if s.is_empty()) {
					ops.1.push(k.into());
				} else {
					ops.0.insert(k.clone(), py_str(v));
				}
			}
		}
	}
	if let Some(v) = g(cfg, &["customFrameOptionsValue"]).filter(|v| v.truthy()) {
		resp.0.insert("X-Frame-Options", py_str(v));
	}
	if as_bool(g(cfg, &["browserXssFilter"]), false) {
		resp.0.insert("X-XSS-Protection", "1; mode=block");
	}
	if let Some(v) = g(cfg, &["permissionsPolicy"]).filter(|v| v.truthy()) {
		resp.0.insert("Permissions-Policy", py_str(v));
	}
	for (side, (set, remove)) in [("request", req), ("response", resp)] {
		let mut entry = Map::new();
		if !set.is_empty() {
			entry.insert("set", set);
		}
		if !remove.is_empty() {
			entry.insert("remove", remove);
		}
		if !entry.is_empty() {
			out.insert(side, entry);
		}
	}
	let sts = as_int(g(cfg, &["stsSeconds"]), Some(0)).unwrap_or(0);
	if sts > 0 {
		out.insert(
			"hsts",
			map([
				("max_age", sts.into()),
				("include_subdomains", as_bool(g(cfg, &["stsIncludeSubdomains"]), false).into()),
				("preload", as_bool(g(cfg, &["stsPreload"]), false).into()),
			]),
		);
		if as_bool(g(cfg, &["forceSTSHeader"]), false) {
			env.note(where_, "forceSTSHeader: rproxy sends HSTS only on HTTPS");
		}
	}
	if as_bool(g(cfg, &["frameDeny"]), false) {
		out.insert("frame_deny", true);
	}
	if as_bool(g(cfg, &["contentTypeNosniff"]), false) {
		out.insert("content_type_nosniff", true);
	}
	if let Some(v) = g(cfg, &["referrerPolicy"]).filter(|v| v.truthy()) {
		out.insert("referrer_policy", py_str(v));
	}
	if let Some(v) = g(cfg, &["contentSecurityPolicy"]).filter(|v| v.truthy()) {
		out.insert("csp", py_str(v));
	}
	let origins = as_list(g(cfg, &["accessControlAllowOriginList"]));
	if !origins.is_empty() {
		let mut cors = map([("allow_origins", origins.into())]);
		if truthy(g(cfg, &["accessControlAllowMethods"])) {
			cors.insert("allow_methods", as_list(g(cfg, &["accessControlAllowMethods"])));
		}
		if truthy(g(cfg, &["accessControlAllowHeaders"])) {
			cors.insert("allow_headers", as_list(g(cfg, &["accessControlAllowHeaders"])));
		}
		if as_bool(g(cfg, &["accessControlAllowCredentials"]), false) {
			cors.insert("allow_credentials", true);
		}
		if let Some(age) = as_int(g(cfg, &["accessControlMaxAge"]), None).filter(|a| *a != 0) {
			cors.insert("max_age", age);
		}
		out.insert("cors", cors);
	}
	const KNOWN: &[&str] = &[
		"customrequestheaders",
		"customresponseheaders",
		"customframeoptionsvalue",
		"browserxssfilter",
		"permissionspolicy",
		"stsseconds",
		"stsincludesubdomains",
		"stspreload",
		"forcestsheader",
		"framedeny",
		"contenttypenosniff",
		"referrerpolicy",
		"contentsecuritypolicy",
		"accesscontrolalloworiginlist",
		"accesscontrolallowmethods",
		"accesscontrolallowheaders",
		"accesscontrolallowcredentials",
		"accesscontrolmaxage",
		"addvaryheader",
	];
	if let Value::Map(m) = cfg {
		for k in m.keys() {
			if !KNOWN.contains(&k.to_lowercase().as_str()) {
				env.note(where_, &format!("headers.{k} is not converted"));
			}
		}
	}
	Value::Map(map([("headers", out.into())]))
}

fn circuit_breaker(cfg: &Value, where_: &str, env: &mut dyn MiddlewareEnv) -> Converted {
	static RATIO: LazyLock<Regex> =
		LazyLock::new(|| Regex::new(r"(NetworkErrorRatio\(\)|ResponseCodeRatio\([^)]*\))\s*>=?\s*([0-9.]+)").unwrap());
	static OTHERS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"&&|\|\||LatencyAtQuantileMS").unwrap());
	let expr = g(cfg, &["expression"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default();
	let found = RATIO.captures(&expr).and_then(|c| Some((c[0].to_string(), c[1].to_string(), c[2].parse::<f64>().ok()?)));
	let Some((whole, func, ratio)) = found else {
		env.note(
			where_,
			&format!(
				"circuitBreaker expression {} cannot be converted (only NetworkErrorRatio / ResponseCodeRatio); left out",
				crate::value::str_repr(&expr)
			),
		);
		return Converted::None;
	};
	if OTHERS.is_match(&expr) {
		env.note(
			where_,
			&format!("circuitBreaker expression {}: only {} is used", crate::value::str_repr(&expr), crate::value::str_repr(&whole)),
		);
	}
	if func.starts_with("ResponseCodeRatio") {
		env.note(where_, "circuitBreaker ResponseCodeRatio: rproxy counts 5xx and connection failures as failures");
	}
	let percent = ((ratio * 100.0).ceil() as i64).clamp(1, 100);
	let recovery = duration(g(cfg, &["fallbackDuration"]), where_, Some("10s"), env);
	Converted::One(Value::Map(map([(
		"circuit_breaker",
		map([("failure_percent", percent.into()), ("window", "10s".into()), ("recovery", recovery.into())]).into(),
	)])))
}

fn crowdsec(cfg: &Value, where_: &str, env: &mut dyn MiddlewareEnv) -> Converted {
	if !as_bool(g(cfg, &["enabled"]), true) {
		return Converted::None;
	}
	let scheme = g(cfg, &["crowdsecLapiScheme"]).filter(|v| v.truthy()).map_or_else(|| "http".into(), py_str);
	let host = g(cfg, &["crowdsecLapiHost"]).filter(|v| v.truthy()).map_or_else(|| "crowdsec:8080".into(), py_str);
	let key_file = match g(cfg, &["crowdsecLapiKeyFile"]).filter(|v| v.truthy()) {
		Some(f) => f.clone(),
		None => {
			let f = "/etc/rproxy/crowdsec.key";
			if truthy(g(cfg, &["crowdsecLapiKey"])) {
				env.note(where_, &format!("the CrowdSec bouncer key is not copied; write it to {f} (owner root, group rproxy, mode 640)"));
			}
			f.into()
		}
	};
	let appsec = as_bool(g(cfg, &["crowdsecAppsecEnabled"]), false);
	let mut glob = map([("lapi_url", format!("{scheme}://{host}").into()), ("api_key_file", key_file)]);
	if appsec {
		let host = g(cfg, &["crowdsecAppsecHost"]).filter(|v| v.truthy()).map_or_else(|| "crowdsec:7422".into(), py_str);
		glob.insert("appsec_url", format!("http://{host}"));
	}
	if let Some(interval) = as_int(g(cfg, &["updateIntervalSeconds"]), None).filter(|i| *i != 0) {
		glob.insert("update_interval", format!("{interval}s"));
	}
	env.crowdsec_global(glob, as_list(g(cfg, &["forwardedHeadersTrustedIPs"])), where_);
	let mode = g(cfg, &["crowdsecMode"]).filter(|v| v.truthy());
	if let Some(mode) = mode {
		if matches!(py_str(mode).to_lowercase().as_str(), "alone" | "appsec") {
			env.note(where_, &format!("crowdsecMode {}: rproxy always reads decisions from the LAPI stream", py_str(mode)));
		}
	}
	let mut mw = map([("appsec", appsec.into())]);
	if appsec && as_bool(g(cfg, &["crowdsecAppsecUnreachableBlock"]), true) {
		mw.insert("on_error", "block");
	}
	Converted::One(Value::Map(map([("crowdsec", mw.into())])))
}

fn one(kind: &str, settings: Map) -> Converted {
	Converted::One(Value::Map(map([(kind, settings.into())])))
}

/// Converts one Traefik middleware `spec` (`{type: settings}`, as in the dynamic
/// configuration or a `Middleware` CRD's `spec`) named `name`. Notes go to `env` under
/// `where_` (the file provider uses `middleware <name>`).
pub fn convert_middleware(name: &str, spec: &Value, where_: &str, env: &mut dyn MiddlewareEnv) -> Converted {
	let Some((kind, cfg)) = spec.as_map().filter(|m| m.len() == 1).and_then(Map::first) else {
		env.note(where_, "not one middleware type; left out");
		return Converted::None;
	};
	let empty = Value::Map(Map::new());
	let cfg = if cfg.truthy() { cfg } else { &empty };
	let get = |k: &str| g(cfg, &[k]);
	match kind.to_lowercase().as_str() {
		"chain" => Converted::Chain(
			as_list(get("middlewares"))
				.iter()
				.map(|m| match m {
					Value::Map(_) => ChainRef {
						name: strip_provider(&py_str_opt(g(m, &["name"]))),
						namespace: g(m, &["namespace"]).map(py_str),
					},
					other => ChainRef { name: strip_provider(&py_str(other)), namespace: None },
				})
				.collect(),
		),
		"redirectscheme" => {
			let scheme = get("scheme").filter(|v| v.truthy()).cloned().unwrap_or_else(|| "https".into());
			let mut out = map([("scheme", scheme.clone()), ("permanent", as_bool(get("permanent"), false).into())]);
			if let Some(port) = as_int(get("port"), None).filter(|p| *p != 0) {
				if !((scheme == Value::from("https") && port == 443) || (scheme == Value::from("http") && port == 80)) {
					out.insert("port", port);
				}
			}
			one("redirect_scheme", out)
		}
		"redirectregex" => one(
			"redirect_regex",
			map([("regex", s(get("regex"))), ("replacement", s(get("replacement"))), ("permanent", as_bool(get("permanent"), false).into())]),
		),
		"stripprefix" => {
			if as_bool(get("forceSlash"), false) {
				env.note(where_, "stripPrefix.forceSlash is not converted");
			}
			one("strip_prefix", map([("prefixes", as_list(get("prefixes")).into())]))
		}
		"addprefix" => one("add_prefix", map([("prefix", s(get("prefix")))])),
		"replacepath" => one("replace_path", map([("path", s(get("path")))])),
		"replacepathregex" => one("replace_path_regex", map([("regex", s(get("regex"))), ("replacement", s(get("replacement")))])),
		"headers" => Converted::One(headers(cfg, where_, env)),
		"ratelimit" => {
			let average = as_int(get("average"), Some(0)).unwrap_or(0);
			if average <= 0 {
				env.note(where_, "rateLimit.average 0 means no limit; left out");
				return Converted::None;
			}
			let mut out = map([("average", average.into()), ("period", duration(get("period"), where_, Some("1s"), env).into())]);
			if let Some(burst) = as_int(get("burst"), None).filter(|b| *b > 0) {
				out.insert("burst", burst);
			}
			let source = get("sourceCriterion").filter(|v| v.truthy()).cloned().unwrap_or_else(|| empty.clone());
			if let Some(h) = g(&source, &["requestHeaderName"]).filter(|v| v.truthy()) {
				out.insert("source", format!("header:{}", py_str(h)));
			} else if as_bool(g(&source, &["requestHost"]), false) {
				env.note(where_, "rateLimit by request host is not converted; limited per client IP");
			}
			if truthy(g(&source, &["ipStrategy"])) {
				env.note(where_, "ipStrategy is not converted; rproxy uses global.trusted_proxies for the client IP");
			}
			one("rate_limit", out)
		}
		"inflightreq" => {
			if truthy(get("sourceCriterion")) {
				env.note(where_, "inFlightReq.sourceCriterion is not converted; counted per client IP");
			}
			one("in_flight", map([("amount", as_int(get("amount"), Some(1)).into())]))
		}
		"ipallowlist" | "ipwhitelist" => {
			if truthy(get("ipStrategy")) {
				env.note(where_, "ipStrategy is not converted; rproxy uses global.trusted_proxies for the client IP");
			}
			if truthy(get("rejectStatusCode")) {
				env.note(where_, "rejectStatusCode is not converted (rproxy answers 403)");
			}
			one("ip_allow", map([("source_range", as_list(get("sourceRange")).into())]))
		}
		"basicauth" => {
			let Some(users_file) = env.basic_auth_users_file(name, cfg, where_) else { return Converted::None };
			let mut out = map([("users_file", users_file.into())]);
			if let Some(r) = get("realm").filter(|v| v.truthy()) {
				out.insert("realm", r);
			}
			// Traefik passes Authorization on unless removeHeader; rproxy removes it unless keep_authorization
			if !as_bool(get("removeHeader"), false) {
				out.insert("keep_authorization", true);
			}
			if let Some(h) = get("headerField").filter(|v| v.truthy()) {
				out.insert("user_header", h);
			}
			one("basic_auth", out)
		}
		"forwardauth" => {
			let mut out = map([("address", s(get("address")))]);
			if truthy(get("authResponseHeaders")) {
				out.insert("response_headers", as_list(get("authResponseHeaders")));
			}
			if as_bool(get("trustForwardHeader"), false) {
				out.insert("trust_forward_header", true);
			}
			if truthy(get("authRequestHeaders")) {
				out.insert("request_headers", as_list(get("authRequestHeaders")));
			}
			for opt in ["tls", "authResponseHeadersRegex", "addAuthCookiesToResponse"] {
				if get(opt).is_some() {
					env.note(where_, &format!("forwardAuth.{opt} is not converted"));
				}
			}
			one("forward_auth", out)
		}
		"compress" => {
			let mut out = Map::new();
			if truthy(get("encodings")) {
				out.insert("encodings", as_list(get("encodings")));
			}
			if let Some(m) = as_int(get("minResponseBodyBytes"), None).filter(|m| *m > 0) {
				out.insert("min_size", m);
			}
			for opt in ["excludedContentTypes", "includedContentTypes", "defaultEncoding"] {
				if get(opt).is_some() {
					env.note(where_, &format!("compress.{opt} is not converted"));
				}
			}
			one("compress", out)
		}
		"retry" => {
			let mut out = map([("attempts", as_int(get("attempts"), Some(1)).into())]);
			if truthy(get("initialInterval")) {
				if let Some(d) = duration(get("initialInterval"), where_, None, env) {
					out.insert("initial_interval", d);
				}
			}
			one("retry", out)
		}
		"circuitbreaker" => circuit_breaker(cfg, where_, env),
		"errors" => {
			let Some(service) = env.errors_service(get("service"), where_) else { return Converted::None };
			let status: Vec<String> = as_str_list(get("status"));
			let path = get("query").filter(|v| v.truthy()).cloned().unwrap_or_else(|| "/".into());
			one("errors", map([("status", status.into()), ("service", service.into()), ("path", path)]))
		}
		"buffering" => {
			let Some(limit) = as_int(get("maxRequestBodyBytes"), None).filter(|l| *l > 0) else {
				env.note(where_, "buffering without maxRequestBodyBytes is not converted");
				return Converted::None;
			};
			for opt in ["maxResponseBodyBytes", "memRequestBodyBytes", "memResponseBodyBytes", "retryExpression"] {
				if get(opt).is_some() {
					env.note(where_, &format!("buffering.{opt} is not converted"));
				}
			}
			one("buffering", map([("max_request_body", limit.into())]))
		}
		"plugin" => {
			if let Value::Map(plugins) = cfg {
				for (plugin, pcfg) in plugins.iter() {
					let p = plugin.to_lowercase();
					if p.contains("crowdsec") || p.contains("bouncer") {
						let pcfg = if pcfg.truthy() { pcfg } else { &empty };
						return crowdsec(pcfg, where_, env);
					}
					env.note(where_, &format!("plugin {plugin} has no rproxy equivalent; left out"));
				}
			}
			Converted::None
		}
		_ => {
			env.note(where_, &format!("middleware type {kind} has no rproxy equivalent; left out"));
			Converted::None
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Notes;

	#[derive(Default)]
	struct Env {
		notes: Notes,
		global: Vec<Map>,
	}
	impl NoteSink for Env {
		fn note(&mut self, where_: &str, text: &str) {
			self.notes.note(where_, text);
		}
	}
	impl MiddlewareEnv for Env {
		fn basic_auth_users_file(&mut self, name: &str, _: &Value, _: &str) -> Option<String> {
			Some(format!("/f/{name}"))
		}
		fn errors_service(&mut self, service: Option<&Value>, _: &str) -> Option<String> {
			service.map(py_str)
		}
		fn crowdsec_global(&mut self, global: Map, _: Vec<Value>, _: &str) {
			self.global.push(global);
		}
	}

	fn conv(yaml: &str) -> (Converted, Vec<String>) {
		let spec: Value = crate::load::yaml_from_slice(yaml.as_bytes()).unwrap();
		let mut env = Env::default();
		let out = convert_middleware("m", &spec, "middleware m", &mut env);
		(out, env.notes.items)
	}

	fn one_of(yaml: &str) -> Value {
		match conv(yaml).0 {
			Converted::One(v) => v,
			other => panic!("{other:?}"),
		}
	}

	#[test]
	fn middlewares() {
		let v = one_of("redirectScheme: {scheme: https, permanent: true, port: '443'}");
		assert_eq!(v, Value::Map(map([("redirect_scheme", map([("scheme", "https".into()), ("permanent", true.into())]).into())])));
		let v = one_of("rateLimit: {average: 100, burst: 50, period: 1m}");
		assert_eq!(g(&v, &["rate_limit", "period"]), Some(&Value::from("1m")));
		let (c, notes) = conv("circuitBreaker: {expression: 'ResponseCodeRatio(500, 600, 0, 600) > 0.25 && NetworkErrorRatio() > 0.5'}");
		let Converted::One(v) = c else { panic!() };
		assert_eq!(g(&v, &["circuit_breaker", "failure_percent"]), Some(&Value::Int(25)));
		assert_eq!(notes.len(), 2, "{notes:?}");
		assert!(matches!(conv("chain: {middlewares: [a@file, b]}").0, Converted::Chain(c) if c.len() == 2 && c[0].name == "a"));
		assert!(matches!(conv("chain: {middlewares: [{name: x, namespace: ns}]}").0, Converted::Chain(c) if c[0].namespace.as_deref() == Some("ns")));
		let (c, notes) = conv("digestAuth: {}");
		assert_eq!(c, Converted::None);
		assert_eq!(notes, ["middleware m: middleware type digestAuth has no rproxy equivalent; left out"]);
		assert_eq!(conv("a: {}\nb: {}").0, Converted::None);
	}

	#[test]
	fn durations() {
		let mut n = Notes::default();
		let d = |v: Value, n: &mut Notes| duration(Some(&v), "w", None, n);
		assert_eq!(d("1m30s".into(), &mut n).as_deref(), Some("90s"));
		assert_eq!(d(Value::Float(0.5), &mut n).as_deref(), Some("500ms"));
		assert_eq!(d("10".into(), &mut n).as_deref(), Some("10s"));
		assert_eq!(d("1h".into(), &mut n).as_deref(), Some("1h"));
		assert_eq!(d("100us".into(), &mut n).as_deref(), Some("1ms"));
		assert!(n.items.is_empty());
		assert_eq!(d("soon".into(), &mut n), None);
		assert_eq!(n.items, ["w: duration 'soon' not understood; left out"]);
	}
}
