use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::core::balance::{self, Balance, HealthCheckSpec, TargetSpec};
use crate::net::cidr::{self, Cidr};
use crate::error::ApiError;
use crate::l7::HttpSpec;
use crate::tls::config::{self as tlsconf, StartTls, TlsMode, TlsSpec};

pub const DEFAULT_UDP_IDLE_SECS: u64 = 30;
pub const DEFAULT_MAX_RANGE_PORTS: u16 = 20_000;
const MAX_UDP_IDLE_SECS: u64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
	Tcp,
	Udp,
}

impl FromStr for Protocol {
	type Err = ApiError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"tcp" => Ok(Protocol::Tcp),
			"udp" => Ok(Protocol::Udp),
			_ => Err(ApiError::invalid(format!("unknown protocol: {s}"))),
		}
	}
}

impl<'de> Deserialize<'de> for Protocol {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		let s = String::deserialize(d)?;
		s.parse().map_err(|e: ApiError| serde::de::Error::custom(e.message))
	}
}

impl fmt::Display for Protocol {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Protocol::Tcp => "tcp",
			Protocol::Udp => "udp",
		})
	}
}

/// How the client's address is passed on to the backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceIp {
	/// Backend sees the proxy's own address.
	#[default]
	Proxy,
	ProxyV1,
	ProxyV2,
	/// Connect from the client's own address (IP_TRANSPARENT).
	Transparent,
}

impl SourceIp {
	pub fn as_str(&self) -> &'static str {
		match self {
			SourceIp::Proxy => "proxy",
			SourceIp::ProxyV1 => "proxy_v1",
			SourceIp::ProxyV2 => "proxy_v2",
			SourceIp::Transparent => "transparent",
		}
	}
}

impl FromStr for SourceIp {
	type Err = ApiError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		serde_json::from_value(serde_json::Value::String(s.to_string()))
			.map_err(|_| ApiError::invalid(format!("unknown source_ip: {s}")))
	}
}

/// Identity of a rule: only one listener may exist per protocol and address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Key {
	pub protocol: Protocol,
	pub listen: SocketAddr,
}

impl fmt::Display for Key {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}", self.protocol, self.listen)
	}
}

/// What this process can do; limits checked while validating rules.
#[derive(Clone, Copy, Debug)]
pub struct Caps {
	/// IP_TRANSPARENT (IPv4 and IPv4-mapped clients)
	pub transparent: bool,
	/// IPV6_TRANSPARENT
	pub transparent_ipv6: bool,
	pub max_range_ports: u16,
	/// Settings whose shape exists (v0.3) and which this build can run.
	pub features: Features,
}

impl Default for Caps {
	fn default() -> Self {
		Caps {
			transparent: false,
			transparent_ipv6: false,
			max_range_ports: DEFAULT_MAX_RANGE_PORTS,
			features: Features::CURRENT,
		}
	}
}

/// Which of the v0.3 settings (docs/DESIGN-v0.3.md) this build can run.
/// Reported in `GET /capabilities` as `features`; a rule that uses anything
/// else is refused with `unsupported`. Patch releases turn these on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Features {
	/// L7 routing (`http` in a rule)
	pub http: bool,
	pub http3: bool,
	/// `acme` certificates
	pub acme: bool,
	/// `tls.options`
	pub tls_options: bool,
	/// Middleware kinds (`http.middlewares`) that can run
	pub middlewares: &'static [&'static str],
	/// Options of `http.services` that can run (`health_check`, `sticky`, `balance`)
	pub services: &'static [&'static str],
}

impl Features {
	pub const CURRENT: Features =
		Features {
		http: true,
		http3: true,
		acme: true,
		tls_options: true,
		middlewares: &[
			"redirect_scheme", "redirect_regex", "ip_allow", "headers", "strip_prefix", "add_prefix", "replace_path",
			"replace_path_regex", "respond", "rate_limit", "in_flight", "crowdsec", "compress", "buffering", "retry",
			"circuit_breaker", "errors", "basic_auth", "forward_auth", "oidc",
		],
		services: &["health_check", "sticky", "balance"],
	};

	/// Everything the settings can describe; for registering a startup rule
	/// that this build cannot run as failed, with the reason.
	pub const ALL: Features = Features {
		http: true,
		http3: true,
		acme: true,
		tls_options: true,
		middlewares: &[
			"redirect_scheme", "redirect_regex", "rate_limit", "in_flight", "crowdsec", "ip_allow", "headers",
			"forward_auth", "oidc", "basic_auth", "strip_prefix", "add_prefix", "replace_path", "replace_path_regex",
			"compress", "buffering", "retry", "circuit_breaker", "errors", "respond",
		],
		services: &["health_check", "sticky", "balance"],
	};

	/// The first setting in `tls` / `http` that this build cannot run.
	pub fn check(&self, tls: &TlsSpec, http: Option<&HttpSpec>) -> Result<(), ApiError> {
		let missing = |what: &str| {
			Err(ApiError::unsupported(format!("{what} is not available in this version (see GET /capabilities features)")))
		};
		if !self.acme && tls.certificates.iter().any(|c| c.acme.is_some()) {
			return missing("an acme certificate");
		}
		if !self.tls_options && tls.options.is_some() {
			return missing("tls.options");
		}
		if let Some(h) = http {
			if !self.http {
				return missing("http (L7 routing)");
			}
			if h.http3 && !self.http3 {
				return missing("http3");
			}
			if let Some(kind) = h.middleware_kinds().find(|k| !self.middlewares.contains(k)) {
				return missing(&format!("the {kind} middleware"));
			}
			for (name, s) in &h.services {
				for (option, used) in [("health_check", s.health_check.is_some()), ("sticky", s.sticky.is_some())] {
					if used && !self.services.contains(&option) {
						return missing(&format!("service {name}: {option}"));
					}
				}
			}
		}
		Ok(())
	}
}

/// A rule as accepted from the API or the database.
#[derive(Clone, Debug, Deserialize)]
pub struct RuleRequest {
	pub protocol: Protocol,
	pub listen_addr: String,
	pub listen_port: u16,
	/// Last port of a range; ports map one to one onto `remote_port` upwards.
	pub listen_port_end: Option<u16>,
	/// More addresses to listen on with the same port or range, e.g. an IPv6
	/// address next to an IPv4 `listen_addr` (#99).
	#[serde(default)]
	pub extra_listen_addrs: Vec<String>,
	/// The backend; left out on `http` rules, whose backends are `http.services`,
	/// and on rules with `targets`.
	#[serde(default)]
	pub remote_addr: String,
	#[serde(default)]
	pub remote_port: u16,
	/// Several backends instead of `remote_addr` / `remote_port` (#98).
	#[serde(default)]
	pub targets: Vec<TargetSpec>,
	/// How connections are spread over `targets`.
	#[serde(default)]
	pub balance: Balance,
	/// TCP connection checks of the backends.
	#[serde(default)]
	pub health_check: Option<HealthCheckSpec>,
	#[serde(default)]
	pub source_ip: SourceIp,
	pub udp_idle_secs: Option<u64>,
	pub tls: Option<TlsSpec>,
	pub starttls: Option<StartTls>,
	pub starttls_required: Option<bool>,
	/// Client addresses allowed to connect (CIDR or single IP); empty means everyone.
	#[serde(default)]
	pub allow_from: Vec<String>,
	/// L7 routing (v0.3): routes, services and middlewares.
	#[serde(default)]
	pub http: Option<HttpSpec>,
	/// Refuse clients blocked by the CrowdSec decisions (`global.crowdsec`) right
	/// after accepting them, before TLS (UDP: drop their datagrams).
	#[serde(default)]
	pub crowdsec: bool,
}

/// Where a rule came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
	/// Created through the API or restored from the database.
	#[default]
	Dynamic,
	/// From the static rules file; the API cannot change it.
	Static,
}

/// A validated rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSpec {
	pub key: Key,
	/// Number of consecutive ports, 1 for a single port.
	pub port_count: u16,
	/// More addresses listening with the same ports as `key.listen`.
	pub extra_listen: Vec<IpAddr>,
	/// The backend; with `targets`, the first target (for logs and older clients).
	pub remote_host: String,
	pub remote_port: u16,
	/// Several backends; empty when the rule has just `remote_addr` / `remote_port`.
	pub targets: Vec<TargetSpec>,
	pub balance: Balance,
	pub health_check: Option<HealthCheckSpec>,
	pub source_ip: SourceIp,
	pub udp_idle: Duration,
	pub tls: TlsSpec,
	pub starttls: Option<StartTls>,
	pub starttls_required: bool,
	pub allow_from: Vec<Cidr>,
	pub http: Option<HttpSpec>,
	pub crowdsec: bool,
	pub origin: Origin,
}

impl RuleSpec {
	/// Every address the rule listens on: `key.listen`'s first, then `extra_listen`.
	pub fn listen_ips(&self) -> Vec<IpAddr> {
		std::iter::once(self.key.listen.ip()).chain(self.extra_listen.iter().copied()).collect()
	}

	/// Whether IPv6 listeners take `IPV6_V6ONLY`: with more than one address, so
	/// `0.0.0.0` and `::` can listen side by side. A lone `::` keeps the OS default.
	pub fn v6only(&self) -> bool {
		!self.extra_listen.is_empty()
	}

	/// The TLS settings to run with: an `http` rule that terminates TLS offers
	/// HTTP/2 and HTTP/1.1 by ALPN unless `alpn` says otherwise.
	pub fn runtime_tls(&self) -> TlsSpec {
		let mut tls = self.tls.clone();
		if self.http.is_some() && tls.mode == TlsMode::Terminate && tls.alpn.is_empty() {
			tls.alpn = vec!["h2".into(), "http/1.1".into()];
		}
		tls
	}

	/// The backends to spread connections over: `targets`, or the single
	/// `remote_addr` / `remote_port`; none for `http` rules.
	pub fn members(&self) -> Vec<TargetSpec> {
		if !self.targets.is_empty() {
			return self.targets.clone();
		}
		if self.http.is_some() || self.remote_host.is_empty() {
			return vec![];
		}
		vec![TargetSpec { addr: self.remote_host.clone(), port: self.remote_port, weight: None, backup: false }]
	}

	pub fn remote(&self) -> String {
		match self.remote_host.parse::<IpAddr>() {
			Ok(IpAddr::V6(ip)) => SocketAddr::new(IpAddr::V6(ip), self.remote_port).to_string(),
			_ => format!("{}:{}", self.remote_host, self.remote_port),
		}
	}
}

pub fn parse_listen(addr: &str, port: u16) -> Result<SocketAddr, ApiError> {
	let ip: IpAddr = addr
		.trim_matches(|c| c == '[' || c == ']')
		.parse()
		.map_err(|_| ApiError::invalid(format!("listen_addr must be an IP address: {addr}")))?;
	if port == 0 {
		return Err(ApiError::invalid("listen_port must be 1-65535"));
	}
	Ok(SocketAddr::new(ip, port))
}

pub fn validate_remote(host: &str, port: u16) -> Result<String, ApiError> {
	let host = host.trim().trim_matches(|c| c == '[' || c == ']');
	if host.is_empty() || host.len() > 253 || host.contains(char::is_whitespace) || host.contains('/') {
		return Err(ApiError::invalid(format!("invalid remote_addr: {host}")));
	}
	if port == 0 {
		return Err(ApiError::invalid("remote_port must be 1-65535"));
	}
	Ok(host.to_string())
}

/// The backend of a rule: `remote_addr` / `remote_port`, or nothing for `http` rules.
pub fn validate_target(host: &str, port: u16, http: bool) -> Result<String, ApiError> {
	if !http {
		return validate_remote(host, port);
	}
	if !host.trim().is_empty() || port != 0 {
		return Err(ApiError::invalid("remote_addr / remote_port are not used with http; put the backends in http.services"));
	}
	Ok(String::new())
}

/// The backends of a rule: `remote_addr` / `remote_port` or `targets` (exactly
/// one of them), none for `http` rules. Returns the host and port shown as the
/// rule's `remote_addr` / `remote_port` (the first target with `targets`).
pub fn validate_backends(
	host: &str,
	port: u16,
	targets: &mut [TargetSpec],
	http: bool,
	port_count: u16,
) -> Result<(String, u16), ApiError> {
	if targets.is_empty() {
		let host = validate_target(host, port, http)?;
		return Ok((host, port));
	}
	if http {
		return Err(ApiError::invalid("targets are not used with http; put the backends in http.services"));
	}
	if !host.trim().is_empty() || port != 0 {
		return Err(ApiError::invalid("give remote_addr / remote_port or targets, not both"));
	}
	balance::validate_targets(targets, port_count)?;
	Ok((targets[0].addr.clone(), targets[0].port))
}

/// What an `http` rule cannot combine with: the backend is chosen per request.
pub fn check_http_tls(tls: &TlsSpec, source_ip: SourceIp, http: &HttpSpec) -> Result<(), ApiError> {
	if http.http3 && tls.mode != TlsMode::Terminate {
		return Err(ApiError::tls_config("http3 needs tls mode terminate (QUIC is always encrypted)"));
	}
	if http.http3 && source_ip == SourceIp::Transparent {
		return Err(ApiError::unsupported("http3 cannot be combined with source_ip transparent"));
	}
	if tls.routes.iter().any(|r| !r.passthrough) {
		return Err(ApiError::tls_config(
			"http rules route by match; only passthrough tls.routes are used (use Host(...) in http.routes)",
		));
	}
	if tls.unmatched == crate::tls::config::Unmatched::Reject {
		return Err(ApiError::tls_config("http rules answer unmatched names with http.default; unmatched: reject is not used"));
	}
	if tls.upstream.tls {
		return Err(ApiError::tls_config("http rules pick TLS towards a backend by its URL (https://); tls.upstream.tls is not used"));
	}
	if matches!(source_ip, SourceIp::ProxyV1 | SourceIp::ProxyV2) {
		return Err(ApiError::invalid("http rules send the client address in X-Forwarded-For; source_ip proxy_v1 / proxy_v2 is not used"));
	}
	Ok(())
}

/// Most extra listen addresses a rule may have.
pub const MAX_EXTRA_LISTEN: usize = 16;

/// `extra_listen_addrs`: IP addresses, none twice and none equal to `listen_addr`.
pub fn validate_extra_listen(primary: IpAddr, addrs: &[String]) -> Result<Vec<IpAddr>, ApiError> {
	if addrs.len() > MAX_EXTRA_LISTEN {
		return Err(ApiError::invalid(format!("extra_listen_addrs takes at most {MAX_EXTRA_LISTEN} addresses")));
	}
	let mut out: Vec<IpAddr> = vec![];
	for a in addrs {
		let ip: IpAddr = a
			.trim()
			.trim_matches(|c| c == '[' || c == ']')
			.parse()
			.map_err(|_| ApiError::invalid(format!("extra_listen_addrs must be IP addresses: {a}")))?;
		if ip == primary || out.contains(&ip) {
			return Err(ApiError::invalid(format!("{ip} is listed twice (listen_addr and extra_listen_addrs)")));
		}
		out.push(ip);
	}
	Ok(out)
}

/// With `transparent`, the connection to the backend is made from the client's
/// address, so each extra listening family needs a backend of that family.
/// Backends given by name are resolved later and not checked here.
pub fn check_transparent_families(extra: &[IpAddr], members: &[TargetSpec], caps: &Caps) -> Result<(), ApiError> {
	let literals: Vec<IpAddr> = members.iter().filter_map(|m| m.addr.trim_matches(|c| c == '[' || c == ']').parse().ok()).collect();
	for ip in extra {
		if ip.is_ipv6() && !caps.transparent_ipv6 {
			return Err(ApiError::unsupported(format!(
				"transparent over IPv6 ({ip} in extra_listen_addrs) is not available (needs IPV6_TRANSPARENT: Linux, CAP_NET_ADMIN and IPv6)"
			)));
		}
		if !members.is_empty() && literals.len() == members.len() && !literals.iter().any(|t| t.is_ipv6() == ip.is_ipv6()) {
			return Err(ApiError::invalid(format!(
				"transparent needs a backend of the same address family as each listen address; {ip} has none"
			)));
		}
	}
	Ok(())
}

pub fn validate_udp_idle(secs: Option<u64>) -> Result<Duration, ApiError> {
	let secs = secs.unwrap_or(DEFAULT_UDP_IDLE_SECS);
	if secs == 0 || secs > MAX_UDP_IDLE_SECS {
		return Err(ApiError::invalid(format!("udp_idle_secs must be 1-{MAX_UDP_IDLE_SECS}")));
	}
	Ok(Duration::from_secs(secs))
}

pub fn port_count(start: u16, end: Option<u16>, remote_port: u16, caps: &Caps) -> Result<u16, ApiError> {
	let Some(end) = end else { return Ok(1) };
	if end < start {
		return Err(ApiError::invalid("listen_port_end must not be below listen_port"));
	}
	let count = end - start + 1;
	if count > caps.max_range_ports {
		return Err(ApiError::invalid(format!("a range may hold at most {} ports", caps.max_range_ports)));
	}
	if u32::from(remote_port) + u32::from(count) - 1 > 65_535 {
		return Err(ApiError::invalid("remote_port + range length exceeds 65535"));
	}
	Ok(count)
}

impl RuleRequest {
	pub fn validate(self, caps: &Caps) -> Result<RuleSpec, ApiError> {
		let transparent_available = caps.transparent;
		let listen = parse_listen(&self.listen_addr, self.listen_port)?;
		let extra_listen = validate_extra_listen(listen.ip(), &self.extra_listen_addrs)?;
		let udp_idle = validate_udp_idle(self.udp_idle_secs)?;
		// every target's port must leave room for the range
		let highest = self.targets.iter().map(|t| t.port).max().unwrap_or(self.remote_port);
		let port_count = port_count(self.listen_port, self.listen_port_end, highest, caps)?;
		let mut targets = self.targets;
		let (remote_host, remote_port) =
			validate_backends(&self.remote_addr, self.remote_port, &mut targets, self.http.is_some(), port_count)?;
		if let Some(h) = &self.health_check {
			if self.http.is_some() {
				return Err(ApiError::invalid("health_check of a rule is not used with http; use http.services.<name>.health_check"));
			}
			h.validate(self.protocol)?;
		}
		let allow_from = cidr::parse_list(&self.allow_from)?;
		let tls = self.tls.unwrap_or_default();
		tlsconf::validate_range(self.protocol, &tls, self.starttls, port_count)?;
		if self.starttls.is_none() && self.starttls_required == Some(false) {
			return Err(ApiError::invalid("starttls_required needs starttls"));
		}
		if let Some(http) = &self.http {
			if self.protocol != Protocol::Tcp {
				return Err(ApiError::invalid("http needs protocol tcp (HTTP/3 is http.http3 on the same rule)"));
			}
			if tls.mode == TlsMode::Sni {
				return Err(ApiError::tls_config("http needs tls mode terminate (or no TLS for plain HTTP)"));
			}
			if self.starttls.is_some() {
				return Err(ApiError::invalid("http and starttls cannot be combined"));
			}
			if port_count > 1 {
				return Err(ApiError::invalid("http rules take a single port"));
			}
			check_http_tls(&tls, self.source_ip, http)?;
			http.validate()?;
		}
		caps.features.check(&tls, self.http.as_ref())?;
		match (self.protocol, self.source_ip) {
			(Protocol::Udp, SourceIp::ProxyV1) => {
				return Err(ApiError::unsupported("PROXY protocol v1 is text over tcp; use proxy_v2 for udp"));
			}
			// the header would end up inside the backend's DTLS
			(Protocol::Udp, SourceIp::ProxyV2) if tls.upstream.tls => {
				return Err(ApiError::unsupported("proxy_v2 over udp cannot be combined with upstream.tls (DTLS to the backend)"));
			}
			(_, SourceIp::Transparent) if !transparent_available => {
				return Err(ApiError::unsupported(
					"transparent is not available (needs Linux and CAP_NET_ADMIN)",
				));
			}
			(_, SourceIp::Transparent) if !listen.is_ipv4() && !caps.transparent_ipv6 => {
				return Err(ApiError::unsupported(
					"transparent over IPv6 is not available (needs IPV6_TRANSPARENT: Linux, CAP_NET_ADMIN and IPv6)",
				));
			}
			_ => {}
		}
		let spec = RuleSpec {
			key: Key { protocol: self.protocol, listen },
			port_count,
			extra_listen,
			remote_host,
			remote_port,
			targets,
			balance: self.balance,
			health_check: self.health_check,
			source_ip: self.source_ip,
			udp_idle,
			tls,
			starttls: self.starttls,
			// only SMTP may continue without TLS
			starttls_required: self.starttls != Some(StartTls::Smtp) || self.starttls_required.unwrap_or(true),
			allow_from,
			http: self.http,
			crowdsec: self.crowdsec,
			origin: Origin::Dynamic,
		};
		if spec.source_ip == SourceIp::Transparent {
			check_transparent_families(&spec.extra_listen, &spec.members(), caps)?;
		}
		Ok(spec)
	}
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateRequest {
	#[serde(default)]
	pub remote_addr: String,
	#[serde(default)]
	pub remote_port: u16,
	/// Several targets instead of remote_addr / remote_port. The backends
	/// (remote_addr or targets, balance, health_check) are replaced as a whole:
	/// `balance` left out is round_robin, `health_check` left out is none.
	#[serde(default)]
	pub targets: Vec<TargetSpec>,
	pub balance: Option<Balance>,
	pub health_check: Option<HealthCheckSpec>,
	pub udp_idle_secs: Option<u64>,
	pub source_ip: Option<SourceIp>,
	/// Replaces the TLS settings (with `starttls` / `starttls_required`) when present.
	pub tls: Option<TlsSpec>,
	pub starttls: Option<StartTls>,
	pub starttls_required: Option<bool>,
	/// The range cannot change; accepted only if it matches.
	pub listen_port_end: Option<u16>,
	/// Replaces the allowed client addresses when present.
	pub allow_from: Option<Vec<String>>,
	/// Replaces the L7 routing when present (v0.3).
	pub http: Option<HttpSpec>,
	/// Turns the CrowdSec check at accept time on or off when present.
	pub crowdsec: Option<bool>,
	/// Replaces the extra listen addresses when present (`[]` removes them all).
	pub extra_listen_addrs: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum State {
	Running,
	Failed,
}

/// Counters since the rule started (for dashboards).
#[derive(Clone, Debug, Default, Serialize)]
pub struct RuleStats {
	pub total_connections: u64,
	pub rx_bytes: u64,
	pub tx_bytes: u64,
	pub tls_failures: u64,
	/// Refused by allow_from, `crowdsec` or `unmatched: reject` (UDP: datagrams).
	pub denied: u64,
	/// UDP datagrams rproxy dropped (a session's queue full, or sending failed).
	pub dropped: u64,
	/// Requests of an `http` rule, in total and by route.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub http: Option<crate::l7::access::HttpStatsView>,
	/// State of each backend, for rules with `targets` or `health_check`.
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub targets: Vec<balance::TargetStatus>,
}

/// A rule as returned by the API.
#[derive(Clone, Debug, Serialize)]
pub struct RuleView {
	pub protocol: Protocol,
	pub listen_addr: String,
	pub listen_port: u16,
	pub listen_port_end: Option<u16>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub extra_listen_addrs: Vec<String>,
	pub remote_addr: String,
	pub remote_port: u16,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub targets: Vec<TargetSpec>,
	/// Shown with `targets`.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub balance: Option<Balance>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub health_check: Option<HealthCheckSpec>,
	pub source_ip: &'static str,
	pub udp_idle_secs: u64,
	pub tls: TlsSpec,
	pub starttls: Option<StartTls>,
	pub starttls_required: bool,
	pub allow_from: Vec<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub http: Option<HttpSpec>,
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub crowdsec: bool,
	pub origin: Origin,
	pub state: State,
	pub error: Option<String>,
	pub resolved: Vec<String>,
	pub connections: u64,
	/// Every target is down (#115): rules with several targets or a health check
	/// (`stats.targets`). False for other rules and while failed.
	pub all_targets_down: bool,
	/// `http` services with `health_check` that have no server up (#115).
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub down_services: Vec<String>,
	pub stats: RuleStats,
	/// When the listener started, in Unix seconds (null while failed).
	pub started_at: Option<u64>,
	/// Expiry of the certificates the rule uses (terminate); filled in by the registry.
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub cert_status: Vec<crate::tls::certstore::CertStatusView>,
	/// State of the rule's ACME certificates (`tls.certificates[].acme`); filled in by the registry.
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub acme: Vec<crate::acme::CertStatus>,
}

impl RuleView {
	pub fn new(spec: &RuleSpec, state: State, error: Option<String>, resolved: &[SocketAddr], connections: u64) -> Self {
		RuleView {
			protocol: spec.key.protocol,
			listen_addr: spec.key.listen.ip().to_string(),
			listen_port: spec.key.listen.port(),
			listen_port_end: (spec.port_count > 1).then(|| spec.key.listen.port() + spec.port_count - 1),
			extra_listen_addrs: spec.extra_listen.iter().map(|ip| ip.to_string()).collect(),
			remote_addr: spec.remote_host.clone(),
			remote_port: spec.remote_port,
			targets: spec.targets.clone(),
			balance: (!spec.targets.is_empty()).then_some(spec.balance),
			health_check: spec.health_check.clone(),
			source_ip: spec.source_ip.as_str(),
			udp_idle_secs: spec.udp_idle.as_secs(),
			tls: spec.tls.clone(),
			starttls: spec.starttls,
			starttls_required: spec.starttls_required,
			allow_from: spec.allow_from.iter().map(|c| c.to_string()).collect(),
			http: spec.http.clone(),
			crowdsec: spec.crowdsec,
			origin: spec.origin,
			state,
			error,
			resolved: resolved.iter().map(|a| a.to_string()).collect(),
			connections,
			all_targets_down: false,
			down_services: vec![],
			stats: RuleStats::default(),
			started_at: None,
			cert_status: vec![],
			acme: vec![],
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn req() -> RuleRequest {
		RuleRequest {
			protocol: Protocol::Tcp,
			listen_addr: "127.0.0.1".into(),
			listen_port: 8888,
			listen_port_end: None,
			extra_listen_addrs: vec![],
			remote_addr: "example.com".into(),
			remote_port: 80,
			targets: vec![],
			balance: Balance::RoundRobin,
			health_check: None,
			source_ip: SourceIp::Proxy,
			udp_idle_secs: None,
			tls: None,
			starttls: None,
			starttls_required: None,
			allow_from: vec![],
			http: None,
			crowdsec: false,
		}
	}

	#[test]
	fn protocol_is_case_insensitive() {
		let r: RuleRequest = serde_json::from_str(
			r#"{"protocol":"TCP","listen_addr":"0.0.0.0","listen_port":1,"remote_addr":"a","remote_port":2}"#,
		)
		.unwrap();
		assert_eq!(r.protocol, Protocol::Tcp);
		assert_eq!(r.source_ip, SourceIp::Proxy);
	}

	#[test]
	fn defaults_udp_idle() {
		let spec = req().validate(&Caps::default()).unwrap();
		assert_eq!(spec.udp_idle, Duration::from_secs(DEFAULT_UDP_IDLE_SECS));
	}

	#[test]
	fn rejects_hostname_listen_and_zero_ports() {
		let mut r = req();
		r.listen_addr = "localhost".into();
		assert_eq!(r.validate(&Caps::default()).unwrap_err().code, "invalid");
		let mut r = req();
		r.remote_port = 0;
		assert_eq!(r.validate(&Caps::default()).unwrap_err().code, "invalid");
	}

	#[test]
	fn extra_listen_addresses_and_transparent_families() {
		let mut r = req();
		r.remote_addr = "10.0.0.1".into();
		r.extra_listen_addrs = vec!["[2001:db8::5]".into(), "0.0.0.0".into()];
		let spec = r.clone().validate(&Caps::default()).unwrap();
		assert_eq!(spec.extra_listen, vec!["2001:db8::5".parse::<IpAddr>().unwrap(), "0.0.0.0".parse().unwrap()]);
		assert!(spec.v6only());
		assert_eq!(spec.listen_ips().len(), 3);

		// transparent: the IPv6 address has no IPv6 backend
		let caps = Caps { transparent: true, transparent_ipv6: true, ..Default::default() };
		r.source_ip = SourceIp::Transparent;
		assert_eq!(r.clone().validate(&caps).unwrap_err().code, "invalid");
		r.targets = vec![
			TargetSpec { addr: "10.0.0.1".into(), port: 80, weight: None, backup: false },
			TargetSpec { addr: "2001:db8::10".into(), port: 80, weight: None, backup: false },
		];
		r.remote_addr = String::new();
		r.remote_port = 0;
		assert!(r.clone().validate(&caps).is_ok());
		let no_v6 = Caps { transparent: true, transparent_ipv6: false, ..Default::default() };
		assert_eq!(r.clone().validate(&no_v6).unwrap_err().code, "unsupported");
		// a backend given by name is not checked here
		r.targets = vec![TargetSpec { addr: "backend.local".into(), port: 80, weight: None, backup: false }];
		assert!(r.validate(&caps).is_ok());
	}

	#[test]
	fn http_rules_take_their_backends_from_services() {
		let caps = Caps { features: Features::ALL, ..Default::default() };
		let http = || -> HttpSpec {
			serde_json::from_value(serde_json::json!({
				"routes": [{"name": "a", "match": "PathPrefix(`/`)", "service": "s"}],
				"services": {"s": {"servers": [{"url": "http://10.0.0.1"}]}}
			}))
			.unwrap()
		};
		let mut r = req();
		r.remote_addr = String::new();
		r.remote_port = 0;
		assert_eq!(r.clone().validate(&caps).unwrap_err().code, "invalid");
		r.http = Some(http());
		assert_eq!(r.clone().validate(&caps).unwrap().remote_host, "");
		let mut r = req();
		r.http = Some(http());
		let e = r.validate(&caps).unwrap_err();
		assert!(e.message.contains("http.services"), "{}", e.message);
	}

	#[test]
	fn udp_takes_proxy_v2_but_not_v1() {
		let mut r = req();
		r.protocol = Protocol::Udp;
		r.source_ip = SourceIp::ProxyV1;
		assert_eq!(r.clone().validate(&Caps::default()).unwrap_err().code, "unsupported");
		r.source_ip = SourceIp::ProxyV2;
		assert!(r.clone().validate(&Caps::default()).is_ok());
		// the header would end up inside the DTLS to the backend
		let tls = serde_json::from_value(serde_json::json!({"mode": "terminate",
			"certificates": [{"cert_file": "/c.pem", "key_file": "/c.key"}], "upstream": {"tls": true}})).unwrap();
		r.tls = Some(tls);
		assert_eq!(r.validate(&Caps::default()).unwrap_err().code, "unsupported");
	}

	#[test]
	fn transparent_needs_the_capability_of_the_family() {
		let mut r = req();
		r.source_ip = SourceIp::Transparent;
		assert_eq!(r.clone().validate(&Caps::default()).unwrap_err().code, "unsupported");
		assert!(r.clone().validate(&Caps { transparent: true, ..Caps::default() }).is_ok());
		r.listen_addr = "::1".into();
		assert_eq!(r.clone().validate(&Caps { transparent: true, ..Caps::default() }).unwrap_err().code, "unsupported");
		let both = Caps { transparent: true, transparent_ipv6: true, ..Caps::default() };
		assert!(r.validate(&both).is_ok(), "IPv6 with IPV6_TRANSPARENT");
	}

	#[test]
	fn starttls_required_is_only_optional_for_smtp() {
		let terminate = || {
			Some(TlsSpec {
				mode: crate::tls::config::TlsMode::Terminate,
				certificates: vec![crate::tls::config::CertFiles { cert_file: "a".into(), chain_file: None, key_file: "b".into(), ..Default::default() }],
				..Default::default()
			})
		};
		let mut r = req();
		r.tls = terminate();
		r.starttls = Some(StartTls::Imap);
		r.starttls_required = Some(false);
		assert!(r.clone().validate(&Caps::default()).unwrap().starttls_required, "IMAP always requires STARTTLS");
		r.starttls = Some(StartTls::Smtp);
		assert!(!r.clone().validate(&Caps::default()).unwrap().starttls_required);
		r.starttls = None;
		assert_eq!(r.validate(&Caps::default()).unwrap_err().code, "invalid", "starttls_required without starttls");
	}

	#[test]
	fn allow_from_is_parsed() {
		let mut r = req();
		r.allow_from = vec!["172.16.0.0/16".into(), "10.0.0.5".into()];
		let spec = r.clone().validate(&Caps::default()).unwrap();
		assert_eq!(spec.allow_from.len(), 2);
		r.allow_from = vec!["nope".into()];
		assert_eq!(r.validate(&Caps::default()).unwrap_err().code, "invalid");
	}

	#[test]
	fn port_ranges() {
		let mut r = req();
		r.listen_port_end = Some(8899);
		assert_eq!(r.clone().validate(&Caps::default()).unwrap().port_count, 12);
		r.listen_port_end = Some(8000);
		assert_eq!(r.clone().validate(&Caps::default()).unwrap_err().code, "invalid");
		r.listen_port_end = Some(9000);
		let small = Caps { max_range_ports: 10, ..Caps::default() };
		assert_eq!(r.clone().validate(&small).unwrap_err().code, "invalid");
		r.listen_port_end = Some(8889);
		r.remote_port = 65_535;
		assert_eq!(r.validate(&Caps::default()).unwrap_err().code, "invalid");
	}

	#[test]
	fn ipv6_remote_is_bracketed() {
		let mut r = req();
		r.remote_addr = "::1".into();
		assert_eq!(r.validate(&Caps::default()).unwrap().remote(), "[::1]:80");
	}
}
