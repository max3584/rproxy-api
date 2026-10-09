//! L7 (HTTP) settings of a rule: routes, services and middlewares
//! (docs/DESIGN-v0.3.md). v0.3.0 settles their shape and validates them; the
//! parts that can already run are listed in `GET /capabilities` `features`.

pub mod access;
pub mod backend;
pub mod backend_tls;
pub mod compress;
pub mod deadline;
pub mod h3;
pub mod matcher;
pub mod mirror;
pub mod resilience;
pub mod middleware;
pub mod server;

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::net::cidr::Cidr;
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
	/// Time limits of the whole request and of one attempt to a backend (#227).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub timeouts: Option<RouteTimeoutsSpec>,
}

/// `timeouts` of a route (#227, the Gateway API's `timeouts.request` / `backendRequest`).
/// `0s` is no limit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteTimeoutsSpec {
	/// From receiving the request until the end of the response body.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub request: Option<String>,
	/// One attempt to a backend, from starting to send until the end of the response body.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub backend_request: Option<String>,
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
	/// How requests are spread over `servers` (#98): round_robin (default),
	/// least_conn (fewest requests in progress) or failover (the first that is up).
	#[serde(default, skip_serializing_if = "crate::core::balance::Balance::is_default")]
	pub balance: crate::core::balance::Balance,
	/// Passive health checks: servers failing in real traffic are ejected for a while (#170, v0.4).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub outlier_detection: Option<crate::core::outlier::HttpOutlierSpec>,
	/// HTTP version towards the servers (#233): http1 (default), h2, h2c or auto.
	#[serde(default, skip_serializing_if = "UpstreamProtocol::is_default")]
	pub protocol: UpstreamProtocol,
	/// TLS towards this service's https:// servers instead of the rule's `tls.upstream` (#236).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tls: Option<backend_tls::ServiceTlsSpec>,
}

/// `protocol` of a service (#233).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
	#[default]
	Http1,
	/// HTTP/2 over TLS (ALPN h2), https:// servers.
	H2,
	/// HTTP/2 with prior knowledge, http:// servers.
	H2c,
	/// https://: what the server picks of h2 and http/1.1 (ALPN); http://: HTTP/1.1.
	Auto,
}

impl UpstreamProtocol {
	pub fn is_default(&self) -> bool {
		*self == UpstreamProtocol::Http1
	}
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSpec {
	/// http:// or https:// (or `status` instead)
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub url: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub weight: Option<u32>,
	/// Answer with this status instead of forwarding (#235, partially invalid backendRefs).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub status: Option<u16>,
	/// Middlewares (names in `http.middlewares`) for requests sent to this server only (#229).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub middlewares: Vec<String>,
}

/// Middleware kinds that `servers[].middlewares` may use: those that only rewrite (#229), and
/// since v0.4.3 CORS, redirects, copies and authentication (the Gateway API's filters on backendRefs).
pub const SERVER_MIDDLEWARES: &[&str] = &[
	"headers", "replace_host", "strip_prefix", "add_prefix", "replace_path", "replace_path_regex", "cors", "redirect_scheme",
	"redirect_regex", "mirror", "forward_auth",
];

/// The service a middleware sends to besides the request's (`mirror`, `forward_auth` with `service`).
fn other_service(m: &MiddlewareSpec) -> Option<&String> {
	match m {
		MiddlewareSpec::Mirror { service, .. } => Some(service),
		MiddlewareSpec::ForwardAuth { service, .. } => service.as_ref(),
		_ => None,
	}
}

/// Whether a service's servers send to other services themselves (a `mirror`, or a
/// `forward_auth` with `service`, in `servers[].middlewares`).
pub fn copies_per_server(service: &ServiceSpec, middlewares: &BTreeMap<String, MiddlewareSpec>) -> bool {
	service.servers.iter().flat_map(|s| &s.middlewares).any(|m| middlewares.get(m).and_then(other_service).is_some())
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
		/// 301, 302, 303, 307 or 308; over `permanent` (#226).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		status: Option<u16>,
	},
	RedirectRegex {
		regex: String,
		replacement: String,
		#[serde(default)]
		permanent: bool,
		/// 301, 302, 303, 307 or 308; over `permanent` (#226).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		status: Option<u16>,
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
		/// The auth server's URL (or `service` instead).
		#[serde(default, skip_serializing_if = "String::is_empty")]
		address: String,
		/// Headers of the auth server's answer copied to the request; `["*"]` for all (v0.4.3).
		#[serde(default)]
		response_headers: Vec<String>,
		#[serde(default)]
		trust_forward_header: bool,
		/// Headers of the request sent to the auth server (default: all).
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		request_headers: Vec<String>,
		/// Time for the auth server to answer (default 10s).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		timeout: Option<String>,
		/// Instead of `address`: a service of the rule (its servers, balance, health checks, tls; v0.4.3).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		service: Option<String>,
		/// With `service`: the path asked (default `/`; v0.4.3).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		path: Option<String>,
		/// `http` (default) or `grpc`: Envoy's ext_authz v3 `Authorization/Check` (v0.4.3).
		#[serde(default, skip_serializing_if = "AuthProtocol::is_default")]
		protocol: AuthProtocol,
		/// The auth request carries the client's method, its path after the auth path, and
		/// its Host, as Envoy's HTTP ext_authz (instead of GET with X-Forwarded-Uri; v0.4.3).
		#[serde(default, skip_serializing_if = "std::ops::Not::not")]
		client_request: bool,
		/// Statuses of the auth server meaning "allowed" (default 200-299; v0.4.3).
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		allow_status: Vec<String>,
		/// Send the client's body to the auth server, up to `max_size` bytes (larger: 413; v0.4.3).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		forward_body: Option<ForwardBodySpec>,
	},
	Oidc {
		issuer: String,
		client_id: String,
		client_secret_file: String,
		#[serde(default)]
		scopes: Vec<String>,
		cookie_secret_file: String,
		/// CA of the provider's HTTPS certificate (default: the Mozilla roots).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		ca_file: Option<String>,
		/// Default /_rproxy/oidc/callback; register it at the provider.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		callback_path: Option<String>,
		/// Default /_rproxy/oidc/logout.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		logout_path: Option<String>,
		/// Default _rproxy_oidc.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		cookie_name: Option<String>,
		/// Claim (dot path) sent as X-Forwarded-Groups; default groups.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		groups_claim: Option<String>,
	},
	BasicAuth {
		users_file: String,
		/// Default rproxy.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		realm: Option<String>,
		/// Pass Authorization on to the backend (default: removed).
		#[serde(default, skip_serializing_if = "std::ops::Not::not")]
		keep_authorization: bool,
		/// Header that tells the backend the user name (e.g. X-Forwarded-User).
		#[serde(default, skip_serializing_if = "Option::is_none")]
		user_header: Option<String>,
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
		/// Also again when the backend answers one of these (e.g. ["500", "502-504"], #231).
		#[serde(default, skip_serializing_if = "Vec::is_empty")]
		status: Vec<String>,
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
	/// Country / ASN allow and deny lists for the client IP (#168, v0.4).
	Geoip(crate::net::geoip::GeoipSpec),
	/// CORS as the Gateway API's HTTPCORSFilter (#230).
	Cors(middleware::cors::CorsFilterSpec),
	/// A copy of requests to another service (#232).
	Mirror {
		service: String,
		/// 0-100; all when left out.
		#[serde(default, skip_serializing_if = "Option::is_none")]
		percent: Option<u8>,
		#[serde(default, skip_serializing_if = "Option::is_none")]
		fraction: Option<FractionSpec>,
	},
	/// The Host sent to the backend (#228).
	ReplaceHost {
		host: String,
	},
}

/// `protocol` of `forward_auth` (v0.4.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProtocol {
	#[default]
	Http,
	/// Envoy's ext_authz v3 over HTTP/2 (h2c for an http:// `address`).
	Grpc,
}

impl AuthProtocol {
	pub fn is_default(&self) -> bool {
		*self == AuthProtocol::Http
	}
}

/// `forward_body` of `forward_auth` (v0.4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardBodySpec {
	pub max_size: u64,
}

/// `fraction` of `mirror`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FractionSpec {
	pub numerator: u32,
	#[serde(default = "hundred")]
	pub denominator: u32,
}

fn hundred() -> u32 {
	100
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderOps {
	#[serde(default)]
	pub set: BTreeMap<String, String>,
	#[serde(default)]
	pub remove: Vec<String>,
	/// Appended after an existing value with `,` (#224).
	#[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
	pub add: BTreeMap<String, String>,
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
			MiddlewareSpec::Geoip(_) => "geoip",
			MiddlewareSpec::Cors(_) => "cors",
			MiddlewareSpec::Mirror { .. } => "mirror",
			MiddlewareSpec::ReplaceHost { .. } => "replace_host",
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
		if let MiddlewareSpec::RedirectScheme { status: Some(s), .. } | MiddlewareSpec::RedirectRegex { status: Some(s), .. } = self {
			if ![301, 302, 303, 307, 308].contains(s) {
				return bad(format!("status {s} must be 301, 302, 303, 307 or 308"));
			}
		}
		if let MiddlewareSpec::Retry { status, .. } = self {
			for s in status {
				parse_status_range(s).map_err(|e| invalid(format!("middleware {name}: status: {e}")))?;
			}
		}
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
			MiddlewareSpec::Geoip(g) => g.validate(&format!("middleware {name}")),
			MiddlewareSpec::Cors(c) => c.validate(&format!("middleware {name}")),
			MiddlewareSpec::Mirror { service, percent, fraction } => {
				if !services.contains_key(service) {
					return bad(format!("service {service:?} is not defined"));
				}
				if percent.is_some() && fraction.is_some() {
					return bad("give percent or fraction, not both".into());
				}
				if percent.is_some_and(|p| p > 100) {
					return bad("percent must be 0-100".into());
				}
				if let Some(f) = fraction {
					if f.denominator == 0 || f.numerator > f.denominator {
						return bad("fraction: denominator must be at least 1 and numerator at most denominator".into());
					}
				}
				Ok(())
			}
			MiddlewareSpec::ReplaceHost { host } => {
				let ok = !host.is_empty() && host.parse::<hyper::http::uri::Authority>().is_ok_and(|a| a.as_str() == host && !host.contains('@'));
				if ok {
					Ok(())
				} else {
					bad(format!("host {host:?} must be host or host:port"))
				}
			}
			MiddlewareSpec::ForwardAuth {
				address,
				timeout,
				service,
				path,
				protocol,
				client_request,
				allow_status,
				forward_body,
				response_headers,
				..
			} => {
				match (address.is_empty(), service) {
					(false, None) => check_url(address, &format!("middleware {name}"))?,
					(true, Some(s)) => {
						let Some(svc) = services.get(s) else {
							return bad(format!("service {s:?} is not defined"));
						};
						if *protocol == AuthProtocol::Grpc && !matches!(svc.protocol, UpstreamProtocol::H2 | UpstreamProtocol::H2c) {
							return bad(format!("protocol grpc needs service {s:?} to have protocol h2 or h2c"));
						}
					}
					_ => return bad("give address or service (exactly one)".into()),
				}
				if let Some(p) = path {
					if service.is_none() || !p.starts_with('/') || p.parse::<hyper::http::uri::PathAndQuery>().is_err() {
						return bad(format!("path {p:?}: only with service, and must start with /"));
					}
				}
				if let Some(t) = timeout {
					parse_duration(t).map_err(|e| invalid(format!("middleware {name}: timeout: {e}")))?;
				}
				for s in allow_status {
					parse_status_range(s).map_err(|e| invalid(format!("middleware {name}: allow_status: {e}")))?;
				}
				if forward_body.is_some_and(|b| b.max_size == 0) {
					return bad("forward_body.max_size must be at least 1 (leave forward_body out not to send the body)".into());
				}
				if *protocol == AuthProtocol::Grpc {
					if *client_request || !allow_status.is_empty() || path.is_some() || !response_headers.is_empty() {
						return bad("protocol grpc takes no client_request, allow_status, path or response_headers (the auth server's answer says)".into());
					}
					if address.starts_with("https://") {
						return bad("protocol grpc with address needs http:// (h2c); for TLS use a service with protocol h2 and tls".into());
					}
				}
				if response_headers.iter().any(|h| h == "*") && response_headers.len() > 1 {
					return bad("response_headers: \"*\" (all) stands alone".into());
				}
				Ok(())
			}
			MiddlewareSpec::Oidc { issuer, client_id, callback_path, logout_path, cookie_name, .. } => {
				check_url(issuer, &format!("middleware {name}: issuer"))?;
				if client_id.is_empty() {
					return bad("client_id is empty".into());
				}
				let paths = [callback_path.as_deref().unwrap_or(middleware::oidc::DEFAULT_CALLBACK), logout_path.as_deref().unwrap_or(middleware::oidc::DEFAULT_LOGOUT)];
				if paths.iter().any(|p| !p.starts_with('/')) || paths[0] == paths[1] {
					return bad("callback_path and logout_path must start with / and differ".into());
				}
				if let Some(c) = cookie_name {
					if c.is_empty() || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
						return bad(format!("cookie_name {c:?} is not a cookie name"));
					}
				}
				Ok(())
			}
			_ => Ok(()),
		}
	}
}

/// `10s`, `500ms`, `1m`, `2h`
/// The longest duration accepted (#180): 365 days. Durations are added to
/// `Instant`s (e.g. the circuit breaker's recovery), which panics on overflow.
pub const MAX_DURATION: Duration = Duration::from_secs(365 * 24 * 3600);

pub fn parse_duration(s: &str) -> Result<Duration, String> {
	let not_a_duration = || format!("{s:?} is not a duration (e.g. 10s, 500ms, 1m)");
	let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
	let (num, unit) = s.split_at(split);
	let n: u64 = num.parse().map_err(|_| not_a_duration())?;
	let d = match unit {
		"ms" => Some(Duration::from_millis(n)),
		"s" => Some(Duration::from_secs(n)),
		"m" => n.checked_mul(60).map(Duration::from_secs),
		"h" => n.checked_mul(3600).map(Duration::from_secs),
		_ => return Err(not_a_duration()),
	};
	match d {
		Some(d) if d <= MAX_DURATION => Ok(d),
		_ => Err(format!("{s:?} is longer than 365 days (8760h)")),
	}
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
			for (i, s) in svc.servers.iter().enumerate() {
				let what = format!("service {name}: servers[{i}]");
				match (s.url.is_empty(), s.status) {
					(false, None) => check_url(&s.url, &format!("service {name}"))?,
					(true, Some(st)) if (100..=599).contains(&st) => {
						if !s.middlewares.is_empty() {
							return Err(invalid(format!("{what}: a status entry takes no middlewares")));
						}
					}
					(true, Some(st)) => return Err(invalid(format!("{what}: status {st} is not an HTTP status"))),
					_ => return Err(invalid(format!("{what}: give url or status (exactly one)"))),
				}
				if s.weight == Some(0) {
					return Err(invalid(format!("{what}: weight must be at least 1")));
				}
				for m in &s.middlewares {
					match self.middlewares.get(m) {
						None => return Err(invalid(format!("{what}: middleware {m:?} is not defined"))),
						Some(spec) if !SERVER_MIDDLEWARES.contains(&spec.kind()) => {
							return Err(invalid(format!(
								"{what}: middleware {m:?} ({}) cannot run per server; only {}",
								spec.kind(),
								SERVER_MIDDLEWARES.join(", ")
							)));
						}
						Some(spec)
							if other_service(spec).and_then(|to| self.services.get(to)).is_some_and(|t| copies_per_server(t, &self.middlewares)) =>
						{
							let to = other_service(spec).map(String::as_str).unwrap_or_default();
							return Err(invalid(format!(
								"{what}: middleware {m:?} sends to service {to:?}, whose servers send to other services themselves (mirror, forward_auth)"
							)));
						}
						Some(_) => {}
					}
				}
				let https = s.url.starts_with("https://");
				match svc.protocol {
					UpstreamProtocol::H2 if !s.url.is_empty() && !https => {
						return Err(invalid(format!("{what}: protocol h2 needs https:// servers (h2c is HTTP/2 without TLS)")));
					}
					UpstreamProtocol::H2c if https => {
						return Err(invalid(format!("{what}: protocol h2c needs http:// servers (h2 is HTTP/2 over TLS)")));
					}
					_ => {}
				}
			}
			if svc.servers.iter().all(|s| s.status.is_some()) && (svc.health_check.is_some() || svc.sticky.is_some()) {
				return Err(invalid(format!("service {name}: health_check and sticky need a server with url")));
			}
			if let Some(t) = &svc.tls {
				t.validate(&format!("service {name}: tls"))?;
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
			if let Some(o) = &svc.outlier_detection {
				o.validate(&format!("service {name}: outlier_detection"))?;
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
			if let Some(t) = &r.timeouts {
				for d in [&t.request, &t.backend_request].into_iter().flatten() {
					parse_duration(d).map_err(|e| invalid(format!("route {}: timeouts: {e}", r.name)))?;
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

	/// Names in `Features::http_options` that these settings use (#224, #226-#235).
	pub fn options_used(&self) -> Vec<&'static str> {
		let mut used = vec![];
		let ops = |o: &Option<HeaderOps>| o.as_ref().is_some_and(|o| !o.add.is_empty());
		for m in self.middlewares.values() {
			match m {
				MiddlewareSpec::Headers { request, response, .. } if ops(request) || ops(response) => used.push("headers_add"),
				MiddlewareSpec::RedirectScheme { status: Some(_), .. } | MiddlewareSpec::RedirectRegex { status: Some(_), .. } => used.push("redirect_status"),
				MiddlewareSpec::Retry { status, .. } if !status.is_empty() => used.push("retry_status"),
				_ => {}
			}
		}
		if self.routes.iter().any(|r| r.timeouts.is_some()) {
			used.push("route_timeouts");
		}
		let servers = || self.services.values().flat_map(|s| &s.servers);
		if servers().any(|s| !s.middlewares.is_empty()) {
			used.push("server_middlewares");
		}
		if servers().any(|s| s.status.is_some()) {
			used.push("server_status");
		}
		used
	}

	/// Names in `Features::forward_auth` that these settings use (v0.4.3).
	pub fn forward_auth_used(&self) -> Vec<&'static str> {
		let mut used = vec![];
		for m in self.middlewares.values() {
			if let MiddlewareSpec::ForwardAuth { service, path, protocol, client_request, allow_status, forward_body, response_headers, .. } = m {
				for (name, on) in [
					("service", service.is_some() || path.is_some()),
					("grpc", *protocol == AuthProtocol::Grpc),
					("client_request", *client_request),
					("allow_status", !allow_status.is_empty()),
					("forward_body", forward_body.is_some()),
					("all_response_headers", response_headers.iter().any(|h| h == "*")),
				] {
					if on && !used.contains(&name) {
						used.push(name);
					}
				}
			}
		}
		used
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
			(json!({"routes": [{"name": "a", "match": "(".repeat(1000) + "Host(`x`)" + &")".repeat(1000), "to": "http://h"}]}), "nested deeper than 32"),
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

	#[test]
	fn huge_durations_are_errors_not_overflows() {
		// #180: `n * 60` / `n * 3600` wrapped around in release builds
		assert_eq!(parse_duration("8760h"), Ok(MAX_DURATION));
		assert_eq!(parse_duration("525600m"), Ok(MAX_DURATION));
		for s in ["8761h", "525601m", "31536001s", "31536000001ms", "18446744073709551615h", "5124095576030432m", "18446744073709551615s"] {
			let err = parse_duration(s).unwrap_err();
			assert!(err.contains("longer than 365 days"), "{s}: {err}");
		}
		assert!(parse_duration("99999999999999999999s").unwrap_err().contains("not a duration"));
		// in a rule (the API and the settings file)
		use serde_json::json;
		let err = spec(json!({"middlewares": {"m": {"rate_limit": {"average": 5, "period": "5124095576030432m"}}}})).unwrap_err();
		assert!(err.contains("longer than 365 days"), "{err}");
	}
}
