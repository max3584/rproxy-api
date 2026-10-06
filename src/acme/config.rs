//! `global.acme` as written in the settings file (docs/API.md "ACME"), and the
//! checks that need nothing but the text: names, references, allowlists.
//!
//! Secrets (DNS API keys, the EAB HMAC key) are only ever named by a file here;
//! the control API can refer to a resolver by name but cannot read, create or
//! change any of this (#208).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use serde::Deserialize;

/// Let's Encrypt (production) when an account leaves `directory` out.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Where account keys and certificates go when `storage` is left out.
pub const DEFAULT_STORAGE: &str = "/var/lib/rproxy/acme";
/// Orders per period when `rate_limit` is left out.
pub const DEFAULT_ORDERS: u32 = 10;
pub const DEFAULT_PERIOD: Duration = Duration::from_secs(3600);
/// How long DNS-01 waits for the TXT record to be visible before asking the CA anyway.
pub const DEFAULT_PROPAGATION: Duration = Duration::from_secs(120);
/// Names one certificate may hold.
pub const MAX_NAMES: usize = 100;

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcmeGlobal {
	/// Account keys, certificates and the DNS-01 journal (`DEFAULT_STORAGE`).
	pub storage: Option<String>,
	#[serde(default)]
	pub accounts: BTreeMap<String, AccountSpec>,
	#[serde(default)]
	pub dns_providers: BTreeMap<String, DnsProviderSpec>,
	/// What rules name in `tls.certificates[].acme`: an account and a challenge.
	#[serde(default)]
	pub resolvers: BTreeMap<String, ResolverSpec>,
	/// At most this many orders (new certificates and renewals, failed ones
	/// too) per period, for the whole process.
	pub rate_limit: Option<RateLimitSpec>,
	/// Renew this long before expiry (`30d`, `720h`); by default 30 days, or a
	/// third of the lifetime for shorter certificates.
	pub renew_before: Option<String>,
	/// Name servers for DNS-01 lookups (CNAME of `_acme-challenge`, the zone,
	/// whether the TXT record is visible): `ip` or `ip:port`. Default: /etc/resolv.conf.
	#[serde(default)]
	pub dns_servers: Vec<String>,
	/// How long to wait for the TXT record to be visible (`2m` by default).
	pub dns_propagation_timeout: Option<String>,
	/// Addresses (`ip:port`) of a built-in responder for HTTP-01, for hosts
	/// without an `http` rule on port 80. It answers nothing else.
	#[serde(default)]
	pub http01_listen: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountSpec {
	/// The CA's directory URL (`LETS_ENCRYPT` by default).
	pub directory: Option<String>,
	/// `mailto:` addresses given to the CA.
	#[serde(default)]
	pub contact: Vec<String>,
	/// The account key (PKCS#8 PEM, ECDSA P-256), created (0600) when missing.
	/// Default: `<storage>/accounts/<name>.key`.
	pub key_file: Option<String>,
	/// External account binding, for CAs that need one (ZeroSSL, Google, ...).
	pub eab: Option<EabSpec>,
	/// CA certificates (PEM) the directory's HTTPS certificate chains to, for
	/// a private CA (step-ca, Pebble). Default: the web PKI roots.
	pub ca_file: Option<String>,
	/// Names this account may obtain certificates for (`example.com`,
	/// `*.example.com`: one label, `**.example.com`: any depth). Required.
	#[serde(default)]
	pub allowed_names: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EabSpec {
	pub kid: String,
	/// The HMAC key (base64url, as the CA shows it) in a file.
	pub hmac_key_file: String,
}

/// One HTTP call of a `type: http` provider; `{fqdn}`, `{value}`, `{zone}` and
/// `{secret}` are replaced in `url`, `headers` and `body`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpCallSpec {
	/// POST by default.
	pub method: Option<String>,
	pub url: String,
	#[serde(default)]
	pub headers: BTreeMap<String, String>,
	pub body: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsProviderSpec {
	/// `powerdns` (the PowerDNS HTTP API) or `http` (a REST template).
	#[serde(rename = "type")]
	pub kind: String,
	/// powerdns: `http://127.0.0.1:8081` (the API's base, without `/api/v1`).
	pub api_url: Option<String>,
	/// powerdns: the server id (`localhost` by default).
	pub server_id: Option<String>,
	/// powerdns: the API key (X-API-Key) in a file.
	pub api_key_file: Option<String>,
	/// http: what adds and removes one TXT value.
	pub add: Option<HttpCallSpec>,
	pub remove: Option<HttpCallSpec>,
	/// http: a secret (token) in a file, for `{secret}` in the templates.
	pub secret_file: Option<String>,
	/// CA certificates for an `https://` API.
	pub ca_file: Option<String>,
	/// Zones this provider may write to (after following the CNAME of
	/// `_acme-challenge`). Default: whatever zone the record falls in.
	#[serde(default)]
	pub zones: Vec<String>,
	/// Names this provider may prove (as for accounts). Required.
	#[serde(default)]
	pub allowed_names: Vec<String>,
	/// TTL of the TXT record (60 by default).
	pub ttl: Option<u32>,
	/// rfc2136: the primary server for DNS UPDATE (`ip` or `ip:port`).
	pub server: Option<String>,
	/// rfc2136: the TSIG key's name, algorithm (`hmac-sha256` by default, or
	/// `hmac-sha512`) and secret (base64, as in BIND's key files) in a file.
	pub tsig_key_name: Option<String>,
	pub tsig_algorithm: Option<String>,
	pub tsig_secret_file: Option<String>,
	/// acme_dns: the accounts of acme-dns (JSON, `{"<name>": {"username",
	/// "password", "fulldomain", "subdomain"}}`, as lego keeps them). A name
	/// without one is registered (`POST /register`) and written here (0600).
	pub credentials_file: Option<String>,
}

impl DnsProviderSpec {
	/// The fields that are set, by name (for checking which belong to the type).
	fn set_fields(&self) -> Vec<&'static str> {
		let mut out = vec![];
		for (name, set) in [
			("api_url", self.api_url.is_some()),
			("server_id", self.server_id.is_some()),
			("api_key_file", self.api_key_file.is_some()),
			("add", self.add.is_some()),
			("remove", self.remove.is_some()),
			("secret_file", self.secret_file.is_some()),
			("zones", !self.zones.is_empty()),
			("ttl", self.ttl.is_some()),
			("server", self.server.is_some()),
			("tsig_key_name", self.tsig_key_name.is_some()),
			("tsig_algorithm", self.tsig_algorithm.is_some()),
			("tsig_secret_file", self.tsig_secret_file.is_some()),
			("credentials_file", self.credentials_file.is_some()),
		] {
			if set {
				out.push(name);
			}
		}
		out
	}
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolverSpec {
	pub account: String,
	/// `http-01`, `tls-alpn-01` or `dns-01`.
	pub challenge: String,
	/// dns-01: the `dns_providers` entry that writes the TXT record.
	pub dns_provider: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitSpec {
	pub orders: u32,
	/// `1h` by default.
	pub period: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Challenge {
	Http01,
	TlsAlpn01,
	Dns01,
}

impl Challenge {
	pub fn parse(s: &str) -> Option<Challenge> {
		match s {
			"http-01" => Some(Challenge::Http01),
			"tls-alpn-01" => Some(Challenge::TlsAlpn01),
			"dns-01" => Some(Challenge::Dns01),
			_ => None,
		}
	}

	pub fn as_str(self) -> &'static str {
		match self {
			Challenge::Http01 => "http-01",
			Challenge::TlsAlpn01 => "tls-alpn-01",
			Challenge::Dns01 => "dns-01",
		}
	}
}

/// A duration with days too (`30d`), besides what `l7::parse_duration` reads.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
	if let Some(days) = s.strip_suffix('d') {
		let n: u64 = days.parse().map_err(|_| format!("{s:?} is not a duration (e.g. 30d, 720h, 2m)"))?;
		return n.checked_mul(86_400).filter(|&secs| secs <= 365 * 86_400).map(Duration::from_secs).ok_or_else(|| format!("{s:?} is longer than 365 days"));
	}
	crate::l7::parse_duration(s)
}

/// `ip` or `ip:port` (port 53 by default).
pub fn parse_dns_server(s: &str) -> Result<SocketAddr, String> {
	if let Ok(addr) = s.parse::<SocketAddr>() {
		return Ok(addr);
	}
	s.trim_matches(|c| c == '[' || c == ']')
		.parse::<std::net::IpAddr>()
		.map(|ip| SocketAddr::new(ip, 53))
		.map_err(|_| format!("{s:?} is not an address (ip or ip:port)"))
}

/// A DNS name as the CA sees it: lower case, without the final dot.
pub fn normalize_name(name: &str) -> String {
	name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `name` is a host name a certificate can hold: labels of letters,
/// digits and `-`, optionally `*.` in front.
pub fn valid_name(name: &str) -> bool {
	let host = name.strip_prefix("*.").unwrap_or(name);
	if host.is_empty() || host.len() > 253 || host.parse::<std::net::IpAddr>().is_ok() {
		return false;
	}
	host.split('.').count() >= 2
		&& host.split('.').all(|l| {
			!l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
		})
}

/// An `allowed_names` pattern: `example.com`, `*.example.com` or `**.example.com`.
pub fn valid_pattern(p: &str) -> bool {
	let base = p.strip_prefix("**.").or_else(|| p.strip_prefix("*.")).unwrap_or(p);
	valid_name(base)
}

/// Whether `pattern` allows a certificate for `name` (both normalized). `*.`
/// allows one label (and the wildcard `*.example.com` itself), `**.` any depth.
pub fn name_allowed(pattern: &str, name: &str) -> bool {
	if pattern == name {
		return true;
	}
	if let Some(suffix) = pattern.strip_prefix("**.") {
		return name.len() > suffix.len() + 1 && name.ends_with(suffix) && name.as_bytes()[name.len() - suffix.len() - 1] == b'.';
	}
	if let Some(suffix) = pattern.strip_prefix("*.") {
		return match name.split_once('.') {
			Some((label, rest)) => rest == suffix && !label.is_empty(),
			None => false,
		};
	}
	false
}

pub fn allowed_by(patterns: &[String], name: &str) -> bool {
	patterns.iter().any(|p| name_allowed(&normalize_name(p), name))
}

impl AcmeGlobal {
	/// Mistakes in `global.acme` itself.
	pub fn check(&self) -> Result<(), String> {
		let at = |what: String| format!("global.acme.{what}");
		for (name, a) in &self.accounts {
			let here = |m: &str| at(format!("accounts.{name}: {m}"));
			if !safe_name(name) {
				return Err(here("names are letters, digits, '-' and '_'"));
			}
			if let Some(d) = &a.directory {
				if !(d.starts_with("https://") || d.starts_with("http://")) {
					return Err(here("directory must be an http(s) URL"));
				}
			}
			for c in &a.contact {
				if !c.starts_with("mailto:") {
					return Err(here(&format!("contact {c:?} must start with mailto:")));
				}
			}
			if a.allowed_names.is_empty() {
				return Err(here("allowed_names is required (the names this account may obtain certificates for)"));
			}
			for p in &a.allowed_names {
				if !valid_pattern(&normalize_name(p)) {
					return Err(here(&format!("allowed_names: {p:?} is not a name or pattern (example.com, *.example.com, **.example.com)")));
				}
			}
			if let Some(e) = &a.eab {
				if e.kid.is_empty() || e.hmac_key_file.is_empty() {
					return Err(here("eab needs kid and hmac_key_file"));
				}
			}
		}
		for (name, p) in &self.dns_providers {
			let here = |m: &str| at(format!("dns_providers.{name}: {m}"));
			let fields: &[&str] = match p.kind.as_str() {
				"powerdns" => &["api_url", "server_id", "api_key_file", "zones", "ttl"],
				"http" => &["add", "remove", "secret_file", "zones"],
				"rfc2136" => &["server", "tsig_key_name", "tsig_algorithm", "tsig_secret_file", "zones", "ttl"],
				"acme_dns" => &["api_url", "credentials_file"],
				other => return Err(here(&format!("type {other:?} is not known (powerdns, rfc2136, acme_dns or http)"))),
			};
			if let Some(f) = p.set_fields().into_iter().find(|f| !fields.contains(f)) {
				return Err(here(&format!("{f} is not used with type {} (it takes {})", p.kind, fields.join(", "))));
			}
			let http_url = |u: &str| u.starts_with("http://") || u.starts_with("https://");
			match p.kind.as_str() {
				"powerdns" => {
					if p.api_url.is_none() || p.api_key_file.is_none() {
						return Err(here("type powerdns needs api_url and api_key_file"));
					}
					if !http_url(p.api_url.as_deref().unwrap_or_default()) {
						return Err(here("api_url must be an http(s) URL"));
					}
				}
				"rfc2136" => {
					let (Some(server), Some(key), Some(_)) = (&p.server, &p.tsig_key_name, &p.tsig_secret_file) else {
						return Err(here("type rfc2136 needs server, tsig_key_name and tsig_secret_file"));
					};
					parse_dns_server(server).map_err(|e| here(&format!("server: {e}")))?;
					if key.is_empty() {
						return Err(here("tsig_key_name is empty"));
					}
					if let Some(a) = &p.tsig_algorithm {
						if super::rfc2136::Algorithm::parse(a).is_none() {
							return Err(here(&format!("tsig_algorithm {a:?} must be hmac-sha256 or hmac-sha512")));
						}
					}
				}
				"acme_dns" => {
					if p.api_url.is_none() || p.credentials_file.is_none() {
						return Err(here("type acme_dns needs api_url and credentials_file"));
					}
					if !http_url(p.api_url.as_deref().unwrap_or_default()) {
						return Err(here("api_url must be an http(s) URL"));
					}
				}
				_ => {
					let (Some(add), Some(remove)) = (&p.add, &p.remove) else {
						return Err(here("type http needs add and remove"));
					};
					for (what, call) in [("add", add), ("remove", remove)] {
						if !(call.url.starts_with("http://") || call.url.starts_with("https://")) {
							return Err(here(&format!("{what}.url must be an http(s) URL")));
						}
						if let Some(m) = &call.method {
							if m.parse::<hyper::Method>().is_err() {
								return Err(here(&format!("{what}.method {m:?} is not an HTTP method")));
							}
						}
						let uses_secret = call.url.contains("{secret}")
							|| call.headers.values().any(|v| v.contains("{secret}"))
							|| call.body.as_deref().unwrap_or_default().contains("{secret}");
						if uses_secret && p.secret_file.is_none() {
							return Err(here(&format!("{what} uses {{secret}}, which needs secret_file")));
						}
						if call.url.contains("{secret}") {
							return Err(here(&format!("{what}.url: put {{secret}} in a header or the body, not the URL (URLs end up in logs)")));
						}
					}
				}
			}
			if p.allowed_names.is_empty() {
				return Err(here("allowed_names is required (the names this provider may prove)"));
			}
			for n in p.allowed_names.iter().chain(&p.zones) {
				let ok = if p.zones.contains(n) { valid_name(&normalize_name(n)) } else { valid_pattern(&normalize_name(n)) };
				if !ok {
					return Err(here(&format!("{n:?} is not a name or pattern")));
				}
			}
		}
		for (name, r) in &self.resolvers {
			let here = |m: &str| at(format!("resolvers.{name}: {m}"));
			let Some(challenge) = Challenge::parse(&r.challenge) else {
				return Err(here("challenge must be http-01, tls-alpn-01 or dns-01"));
			};
			if !self.accounts.contains_key(&r.account) {
				return Err(here(&format!("account {:?} is not defined in global.acme.accounts", r.account)));
			}
			match (&r.dns_provider, challenge) {
				(None, Challenge::Dns01) => return Err(here("dns-01 needs dns_provider")),
				(Some(_), c) if c != Challenge::Dns01 => return Err(here("dns_provider is only used with dns-01")),
				(Some(p), _) if !self.dns_providers.contains_key(p) => {
					return Err(here(&format!("dns_provider {p:?} is not defined in global.acme.dns_providers")))
				}
				_ => {}
			}
		}
		if let Some(l) = &self.rate_limit {
			if l.orders == 0 {
				return Err(at("rate_limit.orders must be at least 1".into()));
			}
			if let Some(p) = &l.period {
				parse_duration(p).map_err(|e| at(format!("rate_limit.period: {e}")))?;
			}
		}
		if let Some(r) = &self.renew_before {
			parse_duration(r).map_err(|e| at(format!("renew_before: {e}")))?;
		}
		if let Some(t) = &self.dns_propagation_timeout {
			parse_duration(t).map_err(|e| at(format!("dns_propagation_timeout: {e}")))?;
		}
		for s in &self.dns_servers {
			parse_dns_server(s).map_err(|e| at(format!("dns_servers: {e}")))?;
		}
		for s in &self.http01_listen {
			s.parse::<SocketAddr>().map_err(|_| at(format!("http01_listen: {s:?} is not ip:port")))?;
		}
		Ok(())
	}

	/// Whether a certificate for `names` may be obtained through `resolver`:
	/// the names are valid and allowed by the account (and the DNS provider).
	pub fn check_names(&self, resolver: &str, names: &[String]) -> Result<(), String> {
		let r = self
			.resolvers
			.get(resolver)
			.ok_or_else(|| format!("acme resolver {resolver:?} is not defined in global.acme.resolvers"))?;
		if names.is_empty() {
			return Err("an acme certificate needs at least one name in domains".into());
		}
		if names.len() > MAX_NAMES {
			return Err(format!("an acme certificate holds at most {MAX_NAMES} names"));
		}
		let challenge = Challenge::parse(&r.challenge).unwrap_or(Challenge::Http01);
		let account = self.accounts.get(&r.account);
		let provider = r.dns_provider.as_ref().and_then(|p| self.dns_providers.get(p));
		for raw in names {
			let name = normalize_name(raw);
			if !valid_name(&name) {
				return Err(format!("acme domains: {raw:?} is not a host name"));
			}
			if name.starts_with("*.") && challenge != Challenge::Dns01 {
				return Err(format!("acme domains: the wildcard {raw:?} needs a resolver with challenge dns-01"));
			}
			if !account.is_some_and(|a| allowed_by(&a.allowed_names, &name)) {
				return Err(format!("acme domains: {raw:?} is not in allowed_names of account {:?}", r.account));
			}
			if let (Some(p), Some(pname)) = (provider, &r.dns_provider) {
				if !allowed_by(&p.allowed_names, &name) {
					return Err(format!("acme domains: {raw:?} is not in allowed_names of dns provider {pname:?}"));
				}
			}
		}
		Ok(())
	}
}

/// Names used in paths: letters, digits, `-` and `_`.
pub fn safe_name(s: &str) -> bool {
	!s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(yaml: &str) -> AcmeGlobal {
		crate::config::from_yaml(yaml).unwrap()
	}

	const BASE: &str = r#"
accounts:
  le: {contact: ['mailto:a@example.com'], allowed_names: [example.com, '*.example.com', '**.deep.example.net']}
dns_providers:
  pdns: {type: powerdns, api_url: 'http://127.0.0.1:8081', api_key_file: /k, allowed_names: ['*.example.com', example.com]}
  relay:
    type: http
    add: {url: 'http://127.0.0.1:1/add', headers: {Authorization: 'Bearer {secret}'}, body: '{"fqdn":"{fqdn}","value":"{value}"}'}
    remove: {method: DELETE, url: 'http://127.0.0.1:1/del/{fqdn}'}
    secret_file: /s
    allowed_names: [only.example.com]
resolvers:
  http: {account: le, challenge: http-01}
  dns: {account: le, challenge: dns-01, dns_provider: pdns}
  relay: {account: le, challenge: dns-01, dns_provider: relay}
"#;

	#[test]
	fn patterns() {
		assert!(name_allowed("example.com", "example.com"));
		assert!(name_allowed("*.example.com", "a.example.com"));
		assert!(name_allowed("*.example.com", "*.example.com"));
		assert!(!name_allowed("*.example.com", "a.b.example.com"));
		assert!(!name_allowed("*.example.com", "example.com"));
		assert!(!name_allowed("*.example.com", "aexample.com"));
		assert!(name_allowed("**.example.com", "a.b.example.com"));
		assert!(name_allowed("**.example.com", "*.b.example.com"));
		assert!(!name_allowed("**.example.com", "badexample.com"));
		assert!(!name_allowed("**.example.com", "example.com"));
		assert!(valid_name("*.example.com") && valid_name("a-b.example.com"));
		assert!(!valid_name("example") && !valid_name("a..b") && !valid_name("*.*.a.b") && !valid_name("127.0.0.1"));
		assert!(!valid_name("a_b.example.com") && !valid_name("-a.example.com") && !valid_name("a b.c"));
		assert_eq!(normalize_name(" WWW.Example.COM. "), "www.example.com");
		assert_eq!(parse_duration("30d").unwrap(), Duration::from_secs(30 * 86_400));
		assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
		assert!(parse_duration("400d").is_err());
		assert_eq!(parse_dns_server("10.0.0.1").unwrap(), "10.0.0.1:53".parse::<SocketAddr>().unwrap());
		assert_eq!(parse_dns_server("[::1]:5353").unwrap(), "[::1]:5353".parse::<SocketAddr>().unwrap());
	}

	#[test]
	fn allowlists_are_enforced() {
		let g = parse(BASE);
		g.check().unwrap();
		g.check_names("http", &["Example.com".into(), "www.example.com".into(), "x.y.deep.example.net".into()]).unwrap();
		let e = g.check_names("http", &["evil.example.org".into()]).unwrap_err();
		assert!(e.contains("not in allowed_names of account"), "{e}");
		let e = g.check_names("http", &["*.example.com".into()]).unwrap_err();
		assert!(e.contains("needs a resolver with challenge dns-01"), "{e}");
		g.check_names("dns", &["*.example.com".into(), "example.com".into()]).unwrap();
		let e = g.check_names("dns", &["x.y.deep.example.net".into()]).unwrap_err();
		assert!(e.contains("dns provider \"pdns\""), "the provider's list counts too: {e}");
		let e = g.check_names("relay", &["www.example.com".into()]).unwrap_err();
		assert!(e.contains("relay"), "{e}");
		assert!(g.check_names("nope", &["example.com".into()]).unwrap_err().contains("not defined"));
		assert!(g.check_names("http", &[]).is_err());
		assert!(g.check_names("http", &["exa mple.com".into()]).unwrap_err().contains("not a host name"));
	}

	#[test]
	fn mistakes() {
		for (change, want) in [
			(("allowed_names: [example.com, '*.example.com', '**.deep.example.net']", "allowed_names: []"), "allowed_names is required"),
			(("challenge: http-01", "challenge: http-02"), "challenge must be"),
			(("{account: le, challenge: http-01}", "{account: nope, challenge: http-01}"), "account \"nope\""),
			(("challenge: dns-01, dns_provider: pdns", "challenge: dns-01"), "dns-01 needs dns_provider"),
			(("challenge: dns-01, dns_provider: pdns", "challenge: dns-01, dns_provider: x"), "dns_provider \"x\""),
			(("type: powerdns", "type: bind"), "not known"),
			(("api_key_file: /k, ", ""), "needs api_url and api_key_file"),
			(("    secret_file: /s\n", ""), "needs secret_file"),
			(("'http://127.0.0.1:1/add'", "'http://127.0.0.1:1/add?t={secret}'"), "not the URL"),
			(("{method: DELETE", "{method: 'NO PE'"), "not an HTTP method"),
			(("['mailto:a@example.com']", "[a@example.com]"), "mailto:"),
			(("api_key_file: /k, ", "api_key_file: /k, server: '10.0.0.1', "), "server is not used with type powerdns"),
		] {
			let yaml = BASE.replacen(change.0, change.1, 1);
			assert_ne!(yaml, BASE, "{change:?}");
			let e = parse(&yaml).check().unwrap_err();
			assert!(e.contains(want), "{change:?}: {e}");
		}
		let ok = "accounts: {le: {allowed_names: [a.example.com]}}\ndns_providers:\n  r: {type: rfc2136, server: '10.0.0.53', tsig_key_name: rproxy, tsig_algorithm: hmac-sha512, tsig_secret_file: /k, zones: [example.com], allowed_names: [a.example.com]}\n  d: {type: acme_dns, api_url: 'https://auth.example.org', credentials_file: /c, allowed_names: [a.example.com]}\n";
		parse(ok).check().unwrap();
		for (from, to, want) in [
			("server: '10.0.0.53', ", "", "needs server, tsig_key_name"),
			("hmac-sha512", "hmac-md5", "hmac-sha256 or hmac-sha512"),
			("server: '10.0.0.53'", "server: 'dns.example.com'", "server:"),
			("credentials_file: /c, ", "", "needs api_url and credentials_file"),
			("credentials_file: /c, ", "credentials_file: /c, zones: [x.example.com], ", "zones is not used with type acme_dns"),
			("type: acme_dns", "type: route53", "is not known"),
		] {
			let e = parse(&ok.replacen(from, to, 1)).check().unwrap_err();
			assert!(e.contains(want), "{from}: {e}");
		}
		let e = parse("rate_limit: {orders: 0}").check().unwrap_err();
		assert!(e.contains("rate_limit"), "{e}");
		assert!(parse("http01_listen: ['80']").check().unwrap_err().contains("http01_listen"));
		assert!(parse("accounts: {'a/b': {allowed_names: [a.example]}}").check().unwrap_err().contains("names are"));
	}
}
