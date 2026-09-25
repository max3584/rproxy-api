use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cidr::{self, Cidr};
use crate::error::ApiError;
use crate::tlsconf::{self, StartTls, TlsSpec};

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
	pub transparent: bool,
	pub max_range_ports: u16,
}

impl Default for Caps {
	fn default() -> Self {
		Caps { transparent: false, max_range_ports: DEFAULT_MAX_RANGE_PORTS }
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
	pub remote_addr: String,
	pub remote_port: u16,
	#[serde(default)]
	pub source_ip: SourceIp,
	pub udp_idle_secs: Option<u64>,
	pub tls: Option<TlsSpec>,
	pub starttls: Option<StartTls>,
	pub starttls_required: Option<bool>,
	/// Client addresses allowed to connect (CIDR or single IP); empty means everyone.
	#[serde(default)]
	pub allow_from: Vec<String>,
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
	pub remote_host: String,
	pub remote_port: u16,
	pub source_ip: SourceIp,
	pub udp_idle: Duration,
	pub tls: TlsSpec,
	pub starttls: Option<StartTls>,
	pub starttls_required: bool,
	pub allow_from: Vec<Cidr>,
	pub origin: Origin,
}

impl RuleSpec {
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
		let remote_host = validate_remote(&self.remote_addr, self.remote_port)?;
		let udp_idle = validate_udp_idle(self.udp_idle_secs)?;
		let port_count = port_count(self.listen_port, self.listen_port_end, self.remote_port, caps)?;
		let allow_from = cidr::parse_list(&self.allow_from)?;
		let tls = self.tls.unwrap_or_default();
		tlsconf::validate_range(self.protocol, &tls, self.starttls, port_count)?;
		if self.starttls.is_none() && self.starttls_required == Some(false) {
			return Err(ApiError::invalid("starttls_required needs starttls"));
		}
		match (self.protocol, self.source_ip) {
			(Protocol::Udp, SourceIp::ProxyV1 | SourceIp::ProxyV2) => {
				return Err(ApiError::unsupported("PROXY protocol is supported for tcp only"));
			}
			(_, SourceIp::Transparent) if !transparent_available => {
				return Err(ApiError::unsupported(
					"transparent is not available (needs Linux and CAP_NET_ADMIN)",
				));
			}
			(_, SourceIp::Transparent) if !listen.is_ipv4() => {
				return Err(ApiError::unsupported("transparent is supported for IPv4 only"));
			}
			_ => {}
		}
		Ok(RuleSpec {
			key: Key { protocol: self.protocol, listen },
			port_count,
			remote_host,
			remote_port: self.remote_port,
			source_ip: self.source_ip,
			udp_idle,
			tls,
			starttls: self.starttls,
			// only SMTP may continue without TLS
			starttls_required: self.starttls != Some(StartTls::Smtp) || self.starttls_required.unwrap_or(true),
			allow_from,
			origin: Origin::Dynamic,
		})
	}
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateRequest {
	pub remote_addr: String,
	pub remote_port: u16,
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
	/// Refused by allow_from or `unmatched: reject` (UDP: datagrams).
	pub denied: u64,
}

/// A rule as returned by the API.
#[derive(Clone, Debug, Serialize)]
pub struct RuleView {
	pub protocol: Protocol,
	pub listen_addr: String,
	pub listen_port: u16,
	pub listen_port_end: Option<u16>,
	pub remote_addr: String,
	pub remote_port: u16,
	pub source_ip: &'static str,
	pub udp_idle_secs: u64,
	pub tls: TlsSpec,
	pub starttls: Option<StartTls>,
	pub starttls_required: bool,
	pub allow_from: Vec<String>,
	pub origin: Origin,
	pub state: State,
	pub error: Option<String>,
	pub resolved: Vec<String>,
	pub connections: u64,
	pub stats: RuleStats,
	/// When the listener started, in Unix seconds (null while failed).
	pub started_at: Option<u64>,
}

impl RuleView {
	pub fn new(spec: &RuleSpec, state: State, error: Option<String>, resolved: &[SocketAddr], connections: u64) -> Self {
		RuleView {
			protocol: spec.key.protocol,
			listen_addr: spec.key.listen.ip().to_string(),
			listen_port: spec.key.listen.port(),
			listen_port_end: (spec.port_count > 1).then(|| spec.key.listen.port() + spec.port_count - 1),
			remote_addr: spec.remote_host.clone(),
			remote_port: spec.remote_port,
			source_ip: spec.source_ip.as_str(),
			udp_idle_secs: spec.udp_idle.as_secs(),
			tls: spec.tls.clone(),
			starttls: spec.starttls,
			starttls_required: spec.starttls_required,
			allow_from: spec.allow_from.iter().map(|c| c.to_string()).collect(),
			origin: spec.origin,
			state,
			error,
			resolved: resolved.iter().map(|a| a.to_string()).collect(),
			connections,
			stats: RuleStats::default(),
			started_at: None,
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
			remote_addr: "example.com".into(),
			remote_port: 80,
			source_ip: SourceIp::Proxy,
			udp_idle_secs: None,
			tls: None,
			starttls: None,
			starttls_required: None,
			allow_from: vec![],
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
	fn proxy_protocol_is_tcp_only() {
		let mut r = req();
		r.protocol = Protocol::Udp;
		r.source_ip = SourceIp::ProxyV2;
		assert_eq!(r.validate(&Caps::default()).unwrap_err().code, "unsupported");
	}

	#[test]
	fn transparent_needs_capability_and_ipv4() {
		let mut r = req();
		r.source_ip = SourceIp::Transparent;
		assert_eq!(r.clone().validate(&Caps::default()).unwrap_err().code, "unsupported");
		assert!(r.clone().validate(&Caps { transparent: true, ..Caps::default() }).is_ok());
		r.listen_addr = "::1".into();
		assert_eq!(r.validate(&Caps { transparent: true, ..Caps::default() }).unwrap_err().code, "unsupported");
	}

	#[test]
	fn starttls_required_is_only_optional_for_smtp() {
		let terminate = || {
			Some(TlsSpec {
				mode: crate::tlsconf::TlsMode::Terminate,
				certificates: vec![crate::tlsconf::CertFiles { cert_file: "a".into(), chain_file: None, key_file: "b".into() }],
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
