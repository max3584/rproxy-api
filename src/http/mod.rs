//! L7 (HTTP) settings of a rule: routes, services and middlewares
//! (docs/DESIGN-v0.3.md). v0.3.0 settles their shape and validates them; the
//! parts that can already run are listed in `GET /capabilities` `features`.

pub mod access;
pub mod crowdsec;
pub mod limit;
pub mod backend;
pub mod compress;
pub mod h3;
pub mod matcher;
pub mod resilience;
pub mod middleware;
pub mod server;

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cidr::Cidr;
use crate::error::ApiError;
pub use matcher::Matcher;

fn invalid(message: impl Into<String>) -> ApiError {
	ApiError::invalid(message)
}

/// `http` of a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSpec {
	/// Also answer HTTP/3 (QUIC) on the same UDP port.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub http3: bool,
	#[serde(default)]
	pub routes: Vec<RouteSpec>,
	/// What a request that matches no route gets (404 when left out).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub default: Option<DefaultSpec>,
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub services: BTreeMap<String, ServiceSpec>,
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub middlewares: BTreeMap<String, MiddlewareSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
	pub name: String,
	#[serde(rename = "match")]
	pub rule: String,
	/// Higher first; by default the length of `match`, as in Traefik.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub priority: Option<i64>,
	/// A service by name, or `to` for a single backend.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub service: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub to: Option<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub middlewares: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultSpec {
	#[serde(default = "not_found")]
	pub status: u16,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub service: Option<String>,
}

fn not_found() -> u16 {
	404
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
	pub servers: Vec<ServerSpec>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub health_check: Option<HealthCheckSpec>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub sticky: Option<StickySpec>,
	/// Send the client's Host header to the backend (default true).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub pass_host_header: Option<bool>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub timeouts: Option<TimeoutsSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSpec {
	/// http:// or https://
	pub url: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub weight: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckSpec {
	pub path: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub interval: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub timeout: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StickySpec {
	pub cookie: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutsSpec {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub connect: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub response: Option<String>,
}

/// One middleware: exactly one of the kinds below.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MiddlewareSpec {
	RedirectScheme {
		#[serde(default = "https")]
		scheme: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		port: Option<u16>,
		#[serde(default)]
		permanent: bool,
	},
	RedirectRegex {
		regex: String,
		replacement: String,
		#[serde(default)]
		permanent: bool,
	},
	RateLimit {
		/// Requests per `period` on average.
		average: u64,
		#[serde(default = "one_second")]
		period: String,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		burst: Option<u64>,
		/// `ip` (the client, after trusted proxies) or `header:<name>`.
		#[serde(default = "ip")]
		source: String,
	},
	InFlight {
		amount: u64,
	},
	Crowdsec {
		#[serde(default)]
		appsec: bool,
		/// When CrowdSec cannot be asked: `allow` or `block`.
		#[serde(default = "allow")]
		on_error: String,
	},
	IpAllow {
		source_range: Vec<String>,
	},
	Headers {
		#[serde(default, skip_serializing_if = "Option::is_none")]
		request: Option<HeaderOps>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		response: Option<HeaderOps>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		hsts: Option<HstsSpec>,
		#[serde(default)]
		frame_deny: bool,
		#[serde(default)]
		content_type_nosniff: bool,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		referrer_policy: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		csp: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		cors: Option<CorsSpec>,
	},
	ForwardAuth {
		address: String,
		#[serde(default)]
		response_headers: Vec<String>,
		#[serde(default)]
		trust_forward_header: bool,
	},
	Oidc {
		issuer: String,
		client_id: String,
		client_secret_file: String,
		#[serde(default)]
		scopes: Vec<String>,
		cookie_secret_file: String,
	},
	BasicAuth {
		users_file: String,
	},
	StripPrefix {
		prefixes: Vec<String>,
	},
	AddPrefix {
		prefix: String,
	},
	ReplacePath {
		path: String,
	},
	ReplacePathRegex {
		regex: String,
		replacement: String,
	},
	Compress {
		#[serde(default)]
		encodings: Vec<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		min_size: Option<u64>,
	},
	Buffering {
		/// Bytes; larger request bodies get 413.
		max_request_body: u64,
	},
	Retry {
		attempts: u32,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		initial_interval: Option<String>,
	},
	CircuitBreaker {
		/// Percentage of failed responses (1-100) in `window` that opens the breaker.
		failure_percent: u8,
		window: String,
		recovery: String,
	},
	Errors {
		/// e.g. ["500-599", "404"]
		status: Vec<String>,
		service: String,
		path: String,
	},
	Respond {
		status: u16,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		body: Option<String>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		content_type: Option<String>,
	},
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderOps {
	#[serde(default)]
	pub set: BTreeMap<String, String>,
	#[serde(default)]
	pub remove: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HstsSpec {
	pub max_age: u64,
	#[serde(default)]
	pub include_subdomains: bool,
	#[serde(default)]
	pub preload: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsSpec {
	pub allow_origins: Vec<String>,
	#[serde(default)]
	pub allow_methods: Vec<String>,
	#[serde(default)]
	pub allow_headers: Vec<String>,
	#[serde(default)]
	pub allow_credentials: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_age: Option<u64>,
}

fn https() -> String {
	"https".into()
}
fn one_second() -> String {
	"1s".into()
}
fn ip() -> String {
	"ip".into()
}
fn allow() -> String {
	"allow".into()
}

impl MiddlewareSpec {
	/// The name used in settings and in `GET /capabilities` `features.middlewares`.
	pub fn kind(&self) -> &'static str {
		match self {
			MiddlewareSpec::RedirectScheme { .. } => "redirect_scheme",
			MiddlewareSpec::RedirectRegex { .. } => "redirect_regex",
			MiddlewareSpec::RateLimit { .. } => "rate_limit",
			MiddlewareSpec::InFlight { .. } => "in_flight",
			MiddlewareSpec::Crowdsec { .. } => "crowdsec",
			MiddlewareSpec::IpAllow { .. } => "ip_allow",
			MiddlewareSpec::Headers { .. } => "headers",
			MiddlewareSpec::ForwardAuth { .. } => "forward_auth",
			MiddlewareSpec::Oidc { .. } => "oidc",
			MiddlewareSpec::BasicAuth { .. } => "basic_auth",
			MiddlewareSpec::StripPrefix { .. } => "strip_prefix",
			MiddlewareSpec::AddPrefix { .. } => "add_prefix",
			MiddlewareSpec::ReplacePath { .. } => "replace_path",
			MiddlewareSpec::ReplacePathRegex { .. } => "replace_path_regex",
			MiddlewareSpec::Compress { .. } => "compress",
			MiddlewareSpec::Buffering { .. } => "buffering",
			MiddlewareSpec::Retry { .. } => "retry",
			MiddlewareSpec::CircuitBreaker { .. } => "circuit_breaker",
			MiddlewareSpec::Errors { .. } => "errors",
			MiddlewareSpec::Respond { .. } => "respond",
		}
	}

	/// Answers the request itself, so a route using it needs no service.
	fn answers(&self) -> bool {
		matches!(
			self,
			MiddlewareSpec::RedirectScheme { .. } | MiddlewareSpec::RedirectRegex { .. } | MiddlewareSpec::Respond { .. }
		)
	}

	fn validate(&self, name: &str, services: &BTreeMap<String, ServiceSpec>) -> Result<(), ApiError> {
		let bad = |msg: String| Err(invalid(format!("middleware {name}: {msg}")));
		match self {
			MiddlewareSpec::RedirectScheme { scheme, .. } if scheme != "http" && scheme != "https" => bad(format!("scheme {scheme:?} must be http or https")),
			MiddlewareSpec::RedirectRegex { regex, .. } | MiddlewareSpec::ReplacePathRegex { regex, .. } => {
				regex::Regex::new(regex).map(|_| ()).or_else(|e| bad(e.to_string()))
			}
			MiddlewareSpec::RateLimit { average, period, source, .. } => {
				if *average == 0 {
					return bad("average must be at least 1".into());
				}
				parse_duration(period).map_err(|e| invalid(format!("middleware {name}: period: {e}")))?;
				if source != "ip" && !source.starts_with("header:") {
					return bad(format!("source {source:?} must be ip or header:<name>"));
				}
				Ok(())
			}
			MiddlewareSpec::InFlight { amount: 0 } => bad("amount must be at least 1".into()),
			MiddlewareSpec::Crowdsec { on_error, .. } if on_error != "allow" && on_error != "block" => {
				bad(format!("on_error {on_error:?} must be allow or block"))
			}
			MiddlewareSpec::IpAllow { source_range } => {
				if source_range.is_empty() {
					return bad("source_range is empty".into());
				}
				for c in source_range {
					c.parse::<Cidr>().map_err(|e| invalid(format!("middleware {name}: {}", e.message)))?;
				}
				Ok(())
			}
			MiddlewareSpec::StripPrefix { prefixes } if prefixes.iter().any(|p| !p.starts_with('/')) => {
				bad("prefixes must start with /".into())
			}
			MiddlewareSpec::AddPrefix { prefix } | MiddlewareSpec::ReplacePath { path: prefix } if !prefix.starts_with('/') => {
				bad(format!("{prefix:?} must start with /"))
			}
			MiddlewareSpec::Retry { attempts: 0, .. } => bad("attempts must be at least 1".into()),
			MiddlewareSpec::CircuitBreaker { failure_percent, window, recovery } => {
				if !(1..=100).contains(failure_percent) {
					return bad("failure_percent must be 1-100".into());
				}
				for d in [window, recovery] {
					parse_duration(d).map_err(|e| invalid(format!("middleware {name}: {e}")))?;
				}
				Ok(())
			}
			MiddlewareSpec::Errors { status, service, path } => {
				if status.is_empty() {
					return bad("status is empty".into());
				}
				for s in status {
					parse_status_range(s).map_err(|e| invalid(format!("middleware {name}: {e}")))?;
				}
				if !services.contains_key(service) {
					return bad(format!("service {service:?} is not defined"));
				}
				if !path.starts_with('/') {
					return bad(format!("path {path:?} must start with /"));
				}
				Ok(())
			}
			MiddlewareSpec::Compress { encodings, .. } => compress::encodings(encodings).map(|_| ()).or_else(bad),
			MiddlewareSpec::Buffering { max_request_body: 0 } => bad("max_request_body must be at least 1".into()),
			MiddlewareSpec::Retry { initial_interval: Some(d), .. } => {
				parse_duration(d).map(|_| ()).map_err(|e| invalid(format!("middleware {name}: initial_interval: {e}")))
			}
			MiddlewareSpec::Respond { status, .. } if !(100..=599).contains(status) => bad(format!("status {status} is not an HTTP status")),
			_ => Ok(()),
		}
	}
}

/// `10s`, `500ms`, `1m`, `2h`
pub fn parse_duration(s: &str) -> Result<Duration, String> {
	let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
	let (num, unit) = s.split_at(split);
	let n: u64 = num.parse().map_err(|_| format!("{s:?} is not a duration (e.g. 10s, 500ms, 1m)"))?;
	Ok(match unit {
		"ms" => Duration::from_millis(n),
		"s" => Duration::from_secs(n),
		"m" => Duration::from_secs(n * 60),
		"h" => Duration::from_secs(n * 3600),
		_ => return Err(format!("{s:?} is not a duration (e.g. 10s, 500ms, 1m)")),
	})
}

pub(crate) fn parse_status_range(s: &str) -> Result<(u16, u16), String> {
	let (a, b) = s.split_once('-').unwrap_or((s, s));
	let parse = |v: &str| v.trim().parse::<u16>().ok().filter(|n| (100..=599).contains(n));
	match (parse(a), parse(b)) {
		(Some(a), Some(b)) if a <= b => Ok((a, b)),
		_ => Err(format!("{s:?} is not a status or a range like 500-599")),
	}
}

fn check_url(url: &str, what: &str) -> Result<(), ApiError> {
	let rest = url
		.strip_prefix("http://")
		.or_else(|| url.strip_prefix("https://"))
		.ok_or_else(|| invalid(format!("{what}: {url:?} must start with http:// or https://")))?;
	if rest.is_empty() || rest.starts_with('/') {
		return Err(invalid(format!("{what}: {url:?} has no host")));
	}
	Ok(())
}

impl HttpSpec {
	/// Checks the settings on their own (names, references, expressions).
	pub fn validate(&self) -> Result<(), ApiError> {
		for (name, svc) in &self.services {
			if svc.servers.is_empty() {
				return Err(invalid(format!("service {name}: servers is empty")));
			}
			for s in &svc.servers {
				check_url(&s.url, &format!("service {name}"))?;
			}
			if let Some(h) = &svc.health_check {
				if !h.path.starts_with('/') {
					return Err(invalid(format!("service {name}: health_check.path must start with /")));
				}
				for d in [&h.interval, &h.timeout].into_iter().flatten() {
					parse_duration(d).map_err(|e| invalid(format!("service {name}: {e}")))?;
				}
			}
			if let Some(s) = &svc.sticky {
				if s.cookie.is_empty() || !s.cookie.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
					return Err(invalid(format!("service {name}: sticky.cookie {:?} is not a cookie name", s.cookie)));
				}
			}
			if let Some(t) = &svc.timeouts {
				for d in [&t.connect, &t.response].into_iter().flatten() {
					parse_duration(d).map_err(|e| invalid(format!("service {name}: {e}")))?;
				}
			}
		}
		for (name, mw) in &self.middlewares {
			mw.validate(name, &self.services)?;
		}
		let mut seen = std::collections::HashSet::new();
		for r in &self.routes {
			if r.name.is_empty() || !seen.insert(r.name.as_str()) {
				return Err(invalid(format!("route {:?}: names must be present and unique", r.name)));
			}
			Matcher::parse(&r.rule).map_err(|e| invalid(format!("route {}: match: {e}", r.name)))?;
			for m in &r.middlewares {
				if !self.middlewares.contains_key(m) {
					return Err(invalid(format!("route {}: middleware {m:?} is not defined", r.name)));
				}
			}
			let answered = r.middlewares.iter().any(|m| self.middlewares[m].answers());
			match (&r.service, &r.to) {
				(Some(_), Some(_)) => return Err(invalid(format!("route {}: give service or to, not both", r.name))),
				(Some(s), None) if !self.services.contains_key(s) => {
					return Err(invalid(format!("route {}: service {s:?} is not defined", r.name)));
				}
				(None, Some(to)) => check_url(to, &format!("route {}", r.name))?,
				(None, None) if !answered => {
					return Err(invalid(format!("route {}: needs service or to (or a redirect / respond middleware)", r.name)));
				}
				_ => {}
			}
		}
		if let Some(d) = &self.default {
			if !(100..=599).contains(&d.status) {
				return Err(invalid(format!("default: status {} is not an HTTP status", d.status)));
			}
			if let Some(s) = &d.service {
				if !self.services.contains_key(s) {
					return Err(invalid(format!("default: service {s:?} is not defined")));
				}
			}
		}
		Ok(())
	}

	/// Middleware kinds used, for checking against what this version can run.
	pub fn middleware_kinds(&self) -> impl Iterator<Item = &'static str> + '_ {
		self.middlewares.values().map(MiddlewareSpec::kind)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn spec(v: serde_json::Value) -> Result<HttpSpec, String> {
		let s: HttpSpec = serde_json::from_value(v).map_err(|e| e.to_string())?;
		s.validate().map_err(|e| e.message)?;
		Ok(s)
	}

	#[test]
	fn the_design_example_validates() {
		let yaml = r#"
http3: true
routes:
  - name: gitlab-login
    match: Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)
    service: gitlab
    middlewares: [crowdsec, rate-limit-login]
  - name: cdn-block
    match: Host(`cdn.example.com`)
    middlewares: [forbidden]
  - name: metrics
    match: PathPrefix(`/metrics`)
    to: http://10.0.0.40:9100
    middlewares: [internal-only]
services:
  gitlab: {servers: [{url: "http://10.0.0.20:80"}], timeouts: {connect: 5s, response: 60s}}
middlewares:
  crowdsec: {crowdsec: {appsec: true}}
  rate-limit-login: {rate_limit: {average: 5, period: 1m, burst: 10}}
  internal-only: {ip_allow: {source_range: [10.0.0.0/8]}}
  forbidden: {respond: {status: 403}}
"#;
		let s: HttpSpec = crate::config::from_yaml(yaml).unwrap();
		s.validate().unwrap();
		assert_eq!(s.middleware_kinds().collect::<Vec<_>>(), ["crowdsec", "respond", "ip_allow", "rate_limit"], "by middleware name");
		// round trip through JSON (API and DB)
		let back: HttpSpec = serde_json::from_value(serde_json::to_value(&s).unwrap()).unwrap();
		assert_eq!(back, s);
	}

	#[test]
	fn mistakes_are_reported() {
		use serde_json::json;
		let svc = json!({"s": {"servers": [{"url": "http://10.0.0.1"}]}});
		for (v, want) in [
			(json!({"routes": [{"name": "a", "match": "Host(`x`)"}]}), "needs service or to"),
			(json!({"routes": [{"name": "a", "match": "Host(`x`)", "service": "nope"}]}), "not defined"),
			(json!({"routes": [{"name": "a", "match": "Hots(`x`)", "services": svc}]}), "unknown field"),
			(json!({"routes": [{"name": "a", "match": "Hots(`x`)", "to": "http://h"}]}), "unknown matcher"),
			(json!({"routes": [{"name": "a", "match": "Host(`x`)", "to": "h:80"}]}), "http://"),
			(json!({"routes": [{"name": "a", "match": "Host(`x`)", "to": "http://h"}, {"name": "a", "match": "Host(`y`)", "to": "http://h"}]}), "unique"),
			(json!({"middlewares": {"m": {"rate_limit": {"average": 5, "period": "soon"}}}}), "not a duration"),
			(json!({"middlewares": {"m": {"ip_allow": {"source_range": ["nope"]}}}}), "middleware m"),
			(json!({"middlewares": {"m": {"teleport": {}}}}), "unknown variant"),
			(json!({"middlewares": {"m": {"redirect_scheme": {"scheme": "ftp"}}}}), "http or https"),
		] {
			let err = spec(v.clone()).unwrap_err();
			assert!(err.contains(want), "{v}: {err}");
		}
		assert!(parse_duration("250ms").unwrap() == Duration::from_millis(250));
		assert_eq!(parse_status_range("500-599"), Ok((500, 599)));
	}
}
