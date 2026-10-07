use std::io;
use std::path::PathBuf;
use std::sync::RwLock;

use crate::control::hardening::{ClientAuth, Lockout, LockoutConfig};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// What a token may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub enum Scope {
	#[serde(rename = "rules:read")]
	RulesRead,
	#[serde(rename = "rules:write")]
	RulesWrite,
	#[serde(rename = "metrics:read")]
	MetricsRead,
	/// Rules with ACME certificates (`tls.certificates[].acme`), and the ACME
	/// operations (`POST /acme/...`, over the Unix socket by default).
	#[serde(rename = "acme:write")]
	AcmeWrite,
	/// Everything.
	#[serde(rename = "admin")]
	Admin,
}

impl Scope {
	pub fn as_str(self) -> &'static str {
		match self {
			Scope::RulesRead => "rules:read",
			Scope::RulesWrite => "rules:write",
			Scope::MetricsRead => "metrics:read",
			Scope::AcmeWrite => "acme:write",
			Scope::Admin => "admin",
		}
	}
}

/// The caller of a request, once its token is accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
	/// The token's name (`token-1`… for the one-per-line format, empty without authentication).
	pub name: String,
	scopes: Vec<Scope>,
	/// Listen ports the token may create, change or delete rules on.
	ports: Option<(u16, u16)>,
	/// Rules this token creates, changes or deletes are stored in `rproxy_rules` (#144, v0.4).
	pub persist: bool,
	/// How the request was authenticated, for the audit log (#167): `token`,
	/// `cert` or `token+cert` (empty without a token file).
	pub auth: &'static str,
	/// Name prefixes of the rule sets the token may create, change or delete
	/// (`allow_rulesets`; None: any). Security review M3.
	rulesets: Option<Vec<String>>,
}

impl Principal {
	/// Without a token file every request is allowed.
	fn anonymous() -> Self {
		Principal { name: String::new(), scopes: vec![Scope::Admin], ports: None, persist: false, auth: "", rulesets: None }
	}

	pub fn has(&self, scope: Scope) -> bool {
		self.scopes.iter().any(|s| *s == scope || *s == Scope::Admin)
	}

	/// Whether the listen ports `first..=last` are all within `allow_listen_ports`.
	pub fn may_use_ports(&self, first: u16, last: u16) -> bool {
		self.ports.is_none_or(|(lo, hi)| lo <= first && last <= hi)
	}

	/// Whether the token may change rule set `name` (`allow_rulesets`).
	pub fn may_use_ruleset(&self, name: &str) -> Result<(), crate::error::ApiError> {
		match &self.rulesets {
			Some(prefixes) if !prefixes.iter().any(|p| name.starts_with(p.as_str())) => Err(crate::error::ApiError::forbidden(format!(
				"this token may not change rule set {name:?} (allow_rulesets: {})",
				prefixes.join(", ")
			))),
			_ => Ok(()),
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Secret {
	Plain(String),
	Sha256([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
	/// None: authenticated by the client certificate alone.
	secret: Option<Secret>,
	/// The client certificate's name the request must come with (#167).
	client_cert: Option<String>,
	principal: Principal,
	expires: Option<time::Date>,
}

/// One entry of the YAML token file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenEntry {
	name: String,
	/// Required unless `client_cert` is given; with both, both must match.
	#[serde(default)]
	sha256: Option<String>,
	/// The client certificate's name (a DNS or URI SAN, else the CN) for the
	/// control API's mTLS (#167, v0.4).
	#[serde(default)]
	client_cert: Option<String>,
	/// Store the rules this token changes in `rproxy_rules` (#144, v0.4; default false).
	#[serde(default)]
	persist: bool,
	scopes: Vec<Scope>,
	#[serde(default)]
	allow_listen_ports: Option<String>,
	/// Name prefixes of the rule sets this token may change (security review M3).
	#[serde(default)]
	allow_rulesets: Option<Vec<String>>,
	#[serde(default)]
	expires: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenDoc {
	tokens: Vec<TokenEntry>,
}

fn invalid(path: &std::path::Path, message: impl std::fmt::Display) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, format!("{}: {message}", path.display()))
}

fn parse_hex(s: &str) -> Option<[u8; 32]> {
	let s = s.trim();
	if s.len() != 64 {
		return None;
	}
	let mut out = [0u8; 32];
	for (i, byte) in out.iter_mut().enumerate() {
		*byte = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
	}
	Some(out)
}

fn parse_ports(s: &str) -> Option<(u16, u16)> {
	let (lo, hi) = s.split_once('-').unwrap_or((s, s));
	let (lo, hi): (u16, u16) = (lo.trim().parse().ok()?, hi.trim().parse().ok()?);
	(lo >= 1 && lo <= hi).then_some((lo, hi))
}

fn parse_date(s: &str) -> Option<time::Date> {
	let mut it = s.trim().splitn(3, '-');
	let year: i32 = it.next()?.parse().ok()?;
	let month: u8 = it.next()?.parse().ok()?;
	let day: u8 = it.next()?.parse().ok()?;
	time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()
}

/// The token file: either one token per line (each with every permission), or
/// YAML with `tokens:` (named tokens stored as SHA-256, with scopes).
fn read_tokens(path: &PathBuf) -> io::Result<Vec<Token>> {
	let text = std::fs::read_to_string(path)?;
	let structured = text.lines().any(|l| l.trim_start().starts_with("tokens:"));
	let tokens = if structured {
		let value: serde_json::Value = serde_yaml_ng::from_str(&text).map_err(|e| invalid(path, e))?;
		let doc: TokenDoc = serde_json::from_value(value).map_err(|e| invalid(path, e))?;
		let mut tokens = Vec::new();
		for e in doc.tokens {
			if e.name.is_empty() || tokens.iter().any(|t: &Token| t.principal.name == e.name) {
				return Err(invalid(path, format!("token names must be unique and not empty: {:?}", e.name)));
			}
			if let Some(name) = &e.client_cert {
				if name.trim().is_empty() || name.contains(char::is_whitespace) {
					return Err(invalid(path, format!("{}: client_cert must be a certificate name (DNS or URI SAN, or CN)", e.name)));
				}
				// a certificate alone must point at one token
				if e.sha256.is_none()
					&& tokens.iter().any(|t: &Token| t.secret.is_none() && t.client_cert.as_deref() == Some(name.as_str()))
				{
					return Err(invalid(path, format!("{}: another token without sha256 has client_cert {name}", e.name)));
				}
			}
			if e.sha256.is_none() && e.client_cert.is_none() {
				return Err(invalid(path, format!("{}: give sha256 (sha256sum of the token) or client_cert", e.name)));
			}
			let secret = match &e.sha256 {
				Some(sha256) => Some(Secret::Sha256(parse_hex(sha256).ok_or_else(|| {
					invalid(path, format!("{}: sha256 must be 64 hex digits (sha256sum of the token)", e.name))
				})?)),
				None => None,
			};
			if e.allow_rulesets.as_ref().is_some_and(|p| p.is_empty() || p.iter().any(|p| p.is_empty())) {
				return Err(invalid(path, format!("{}: allow_rulesets must list name prefixes (none empty)", e.name)));
			}
			if e.scopes.is_empty() {
				return Err(invalid(path, format!("{}: scopes must not be empty", e.name)));
			}
			let ports = match &e.allow_listen_ports {
				Some(p) => Some(parse_ports(p).ok_or_else(|| invalid(path, format!("{}: allow_listen_ports: {p}", e.name)))?),
				None => None,
			};
			let expires = match &e.expires {
				Some(d) => Some(parse_date(d).ok_or_else(|| invalid(path, format!("{}: expires must be YYYY-MM-DD: {d}", e.name)))?),
				None => None,
			};
			let auth = match (&secret, &e.client_cert) {
				(Some(_), Some(_)) => "token+cert",
				(None, _) => "cert",
				_ => "token",
			};
			tokens.push(Token {
				secret,
				client_cert: e.client_cert,
				principal: Principal { name: e.name, scopes: e.scopes, ports, persist: e.persist, auth, rulesets: e.allow_rulesets },
				expires,
			});
		}
		tokens
	} else {
		text.lines()
			.map(str::trim)
			.filter(|l| !l.is_empty() && !l.starts_with('#'))
			.enumerate()
			.map(|(i, l)| Token {
				secret: Some(Secret::Plain(l.to_string())),
				client_cert: None,
				principal: Principal {
					name: format!("token-{}", i + 1),
					scopes: vec![Scope::Admin],
					ports: None,
					persist: false,
					auth: "token",
					rulesets: None,
				},
				expires: None,
			})
			.collect()
	};
	if tokens.is_empty() {
		return Err(invalid(path, "no tokens"));
	}
	Ok(tokens)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Bearer tokens read from a file. Several may be valid at once so that a token
/// can be rotated without a gap.
pub struct Tokens {
	path: Option<PathBuf>,
	tokens: RwLock<Vec<Token>>,
	/// Whether the control API asks for client certificates
	/// (`--tls-client-auth`); without, tokens with `client_cert` are refused.
	client_auth: ClientAuth,
	/// Sources failing authentication over TCP (#167).
	lockout: Lockout,
}

impl Tokens {
	/// No token file: every request is allowed.
	pub fn disabled() -> Self {
		Self::with(None, vec![])
	}

	fn with(path: Option<PathBuf>, tokens: Vec<Token>) -> Self {
		// until with_client_auth says otherwise, client_cert entries are not refused
		Tokens { path, tokens: RwLock::new(tokens), client_auth: ClientAuth::Optional, lockout: Lockout::default() }
	}

	pub fn from_file(path: PathBuf) -> io::Result<Self> {
		let tokens = read_tokens(&path)?;
		Ok(Self::with(Some(path), tokens))
	}

	/// Authentication is on but no token is known yet (the file could not be
	/// read): every request is refused until a reload succeeds.
	pub fn locked(path: PathBuf) -> Self {
		Self::with(Some(path), vec![])
	}

	/// How the control API asks for client certificates. A token with
	/// `client_cert` while it asks for none is a mistake (now and on reload):
	/// the entry could never be used as written.
	pub fn with_client_auth(mut self, auth: ClientAuth) -> io::Result<Self> {
		self.client_auth = auth;
		let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
		self.check_client_auth(&tokens)?;
		drop(tokens);
		Ok(self)
	}

	fn check_client_auth(&self, tokens: &[Token]) -> io::Result<()> {
		if self.client_auth != ClientAuth::None {
			return Ok(());
		}
		match tokens.iter().find(|t| t.client_cert.is_some()) {
			Some(t) => Err(io::Error::new(
				io::ErrorKind::InvalidData,
				format!(
					"{}: token {}: client_cert needs --tls-client-auth optional or required (RPROXY_TLS_CLIENT_AUTH) and --tls-client-ca",
					self.path.as_deref().unwrap_or(std::path::Path::new("")).display(),
					t.principal.name
				),
			)),
			None => Ok(()),
		}
	}

	/// `--api-lockout-*` (on by default: 20 failures in 1m lock out for 5m).
	pub fn with_lockout(mut self, config: LockoutConfig) -> Self {
		self.lockout = Lockout::new(config);
		self
	}

	pub fn lockout(&self) -> &Lockout {
		&self.lockout
	}

	/// Tokens with `expires` (name, last valid day), for `token.expiring` and `/metrics`.
	pub fn expiries(&self) -> Vec<(String, time::Date)> {
		let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
		tokens.iter().filter_map(|t| t.expires.map(|d| (t.principal.name.clone(), d))).collect()
	}

	pub fn enabled(&self) -> bool {
		self.path.is_some()
	}

	/// Names of the tokens marked `persist: true` (#144).
	pub fn persisting(&self) -> Vec<String> {
		self.tokens.read().unwrap().iter().filter(|t| t.principal.persist).map(|t| t.principal.name.clone()).collect()
	}

	/// Re-reads the token file; on error the current tokens stay in effect.
	pub fn reload(&self) -> io::Result<usize> {
		let Some(path) = &self.path else { return Ok(0) };
		let tokens = read_tokens(path)?;
		self.check_client_auth(&tokens)?;
		let count = tokens.len();
		*self.tokens.write().unwrap() = tokens;
		Ok(count)
	}

	/// Checks an `Authorization` header value; `None` if it is missing, unknown or expired.
	pub fn authenticate(&self, header: Option<&str>) -> Option<Principal> {
		self.check(header).ok()
	}

	/// Like `authenticate`, with why a request is refused (for the audit log; never
	/// the token): `missing` (no bearer token), `invalid` (unknown) or `expired`.
	pub fn check(&self, header: Option<&str>) -> Result<Principal, &'static str> {
		self.check_with(header, &[])
	}

	/// Like `check`, with the names of the connection's verified client
	/// certificate (#167; empty without one). A bearer token, when given,
	/// decides (and needs its `client_cert` when it has one, else
	/// `client_cert`); without one, a token with `client_cert` and no `sha256`
	/// whose name the certificate has is used.
	pub fn check_with(&self, header: Option<&str>, cert: &[String]) -> Result<Principal, &'static str> {
		self.authenticate_on(header, cert, time::OffsetDateTime::now_utc().date())
	}

	fn authenticate_on(&self, header: Option<&str>, cert: &[String], today: time::Date) -> Result<Principal, &'static str> {
		if !self.enabled() {
			return Ok(Principal::anonymous());
		}
		let valid = |t: &Token| if t.expires.is_none_or(|d| today <= d) { Ok(t.principal.clone()) } else { Err("expired") };
		let has_cert = |t: &Token| t.client_cert.as_ref().is_some_and(|c| cert.iter().any(|n| n == c));
		let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
		let Some(presented) = header.and_then(|h| h.strip_prefix("Bearer ")).map(str::trim) else {
			if cert.is_empty() {
				return Err("missing");
			}
			return tokens.iter().find(|t| t.secret.is_none() && has_cert(t)).map_or(Err("invalid"), valid);
		};
		let hash: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
		// check every token so the time taken does not reveal which one matched
		let mut found = Err("invalid");
		for t in tokens.iter() {
			let ok = match &t.secret {
				Some(Secret::Plain(s)) => constant_time_eq(s.as_bytes(), presented.as_bytes()),
				Some(Secret::Sha256(h)) => constant_time_eq(h, &hash),
				None => false,
			};
			if ok && found.is_err() {
				found = if t.client_cert.is_some() && !has_cert(t) { Err("client_cert") } else { valid(t) };
			}
		}
		found
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn tempfile(name: &str, text: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("rproxy-auth-{}-{name}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let file = dir.join("tokens");
		std::fs::write(&file, text).unwrap();
		file
	}

	fn sha(s: &str) -> String {
		Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
	}

	#[test]
	fn rotates_tokens() {
		let file = tempfile("rotate", "# comment\nold\nnew\n");
		let tokens = Tokens::from_file(file.clone()).unwrap();
		let allows = |h: Option<&str>| tokens.authenticate(h).is_some();
		assert!(allows(Some("Bearer old")));
		assert!(allows(Some("Bearer new")));
		assert!(!allows(Some("Bearer nope")));
		assert!(!allows(Some("old")));
		assert!(!allows(None));
		let p = tokens.authenticate(Some("Bearer new")).unwrap();
		assert_eq!(p.name, "token-2");
		assert!(p.has(Scope::RulesWrite) && p.has(Scope::MetricsRead), "one-per-line tokens may do everything");

		std::fs::write(&file, "new\n").unwrap();
		assert_eq!(tokens.reload().unwrap(), 1);
		assert!(tokens.authenticate(Some("Bearer old")).is_none());

		std::fs::write(&file, "\n").unwrap();
		assert!(tokens.reload().is_err());
		assert!(tokens.authenticate(Some("Bearer new")).is_some(), "a bad file keeps the current tokens");
		std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
	}

	#[test]
	fn named_tokens_with_scopes() {
		let file = tempfile(
			"yaml",
			&format!(
				"# hashes only\ntokens:\n  - name: ui\n    sha256: {}\n    scopes: [rules:read, rules:write]\n  - name: ci\n    sha256: {}\n    scopes: [rules:write]\n    allow_listen_ports: 20000-29999\n    expires: 2027-03-31\n",
				sha("ui-secret"),
				sha("ci-secret").to_uppercase()
			),
		);
		let tokens = Tokens::from_file(file.clone()).unwrap();
		let ui = tokens.authenticate(Some("Bearer ui-secret")).unwrap();
		assert_eq!(ui.name, "ui");
		assert!(ui.has(Scope::RulesRead) && ui.has(Scope::RulesWrite) && !ui.has(Scope::MetricsRead));
		assert!(ui.may_use_ports(1, 65535));
		assert!(tokens.authenticate(Some(&format!("Bearer {}", sha("ui-secret")))).is_none(), "the hash is not the token");

		let day = |s| parse_date(s).unwrap();
		let ci = tokens.authenticate_on(Some("Bearer ci-secret"), &[], day("2027-03-31")).unwrap();
		assert!(!ci.has(Scope::RulesRead));
		assert!(ci.may_use_ports(20000, 20010) && !ci.may_use_ports(19999, 20000) && !ci.may_use_ports(29999, 30000));
		assert_eq!(tokens.authenticate_on(Some("Bearer ci-secret"), &[], day("2027-04-01")).err(), Some("expired"));
		// why a request is refused, for the audit log
		assert_eq!(tokens.check(None).err(), Some("missing"));
		assert_eq!(tokens.check(Some("Basic dTpw")).err(), Some("missing"));
		assert_eq!(tokens.check(Some("Bearer nope")).err(), Some("invalid"));
		std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
	}

	#[test]
	fn mistakes_in_the_token_file() {
		for (text, want) in [
			("tokens:\n  - name: a\n    sha256: abc\n    scopes: [admin]\n", "64 hex"),
			("tokens:\n  - name: a\n    sha256: x\n    scopes: [root]\n", "unknown variant"),
			(&format!("tokens:\n  - name: a\n    sha256: {}\n    scopes: []\n", sha("a")), "scopes must not be empty"),
			(
				&format!("tokens:\n  - {{name: a, sha256: {0}, scopes: [admin]}}\n  - {{name: a, sha256: {0}, scopes: [admin]}}\n", sha("a")),
				"unique",
			),
			(&format!("tokens:\n  - {{name: a, sha256: {}, scopes: [admin], allow_listen_ports: 9-1}}\n", sha("a")), "allow_listen_ports"),
			(&format!("tokens:\n  - {{name: a, sha256: {}, scopes: [admin], expires: 2027-02-30}}\n", sha("a")), "YYYY-MM-DD"),
			(&format!("tokens:\n  - {{name: a, sha256: {}, scope: [admin]}}\n", sha("a")), "unknown field"),
			("tokens:\n  - {name: a, scopes: [admin]}\n", "give sha256"),
			("tokens:\n  - {name: a, client_cert: ui.example, scopes: [admin]}\n  - {name: b, client_cert: ui.example, scopes: [admin]}\n", "another token"),
			("tokens:\n  - {name: a, client_cert: 'a b', scopes: [admin]}\n", "certificate name"),
			("tokens: []\n", "no tokens"),
		] {
			let file = tempfile("bad", text);
			let e = Tokens::from_file(file.clone()).err().unwrap_or_else(|| panic!("accepted: {text}")).to_string();
			assert!(e.contains(want), "{text}: {e}");
			std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
		}
	}

	/// v0.4 (#144): `persist` is read; it is false unless given.
	#[test]
	fn persist_marks() {
		let file = tempfile(
			"persist",
			&format!(
				"tokens:\n  - {{name: ci, sha256: {}, scopes: [rules:write], persist: true}}\n  - {{name: ui, sha256: {}, scopes: [rules:write]}}\n",
				sha("ci"),
				sha("ui")
			),
		);
		let tokens = Tokens::from_file(file.clone()).unwrap();
		assert_eq!(tokens.persisting(), ["ci"]);
		assert!(!tokens.authenticate(Some("Bearer ui")).unwrap().persist);
		std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
	}

	/// v0.4 (#167): `client_cert` alone, or bound to a token.
	#[test]
	fn client_certificates() {
		let file = tempfile(
			"certs",
			&format!(
				"tokens:\n  - {{name: ui, client_cert: ui.rproxy.internal, scopes: [rules:read]}}\n  - {{name: ctl, sha256: {}, client_cert: 'spiffe://c/ns/x/sa/ctl', scopes: [admin], expires: 2027-01-31}}\n  - {{name: ci, sha256: {}, scopes: [rules:write]}}\n",
				sha("ctl"),
				sha("ci")
			),
		);
		let tokens = Tokens::from_file(file.clone()).unwrap();
		let day = |s| parse_date(s).unwrap();
		let today = day("2027-01-01");
		let names = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
		let check = |h: Option<&str>, cert: &[String]| tokens.authenticate_on(h, cert, today);
		// the certificate alone
		let ui = check(None, &names(&["other", "ui.rproxy.internal"])).unwrap();
		assert_eq!((ui.name.as_str(), ui.auth), ("ui", "cert"));
		assert_eq!(check(None, &names(&["nobody"])).err(), Some("invalid"));
		assert_eq!(check(None, &[]).err(), Some("missing"));
		// a bearer token decides: an unknown one is not saved by the certificate
		assert_eq!(check(Some("Bearer nope"), &names(&["ui.rproxy.internal"])).err(), Some("invalid"));
		// a token bound to a certificate needs both
		let ctl = check(Some("Bearer ctl"), &names(&["spiffe://c/ns/x/sa/ctl"])).unwrap();
		assert_eq!((ctl.name.as_str(), ctl.auth), ("ctl", "token+cert"));
		assert_eq!(check(Some("Bearer ctl"), &[]).err(), Some("client_cert"));
		assert_eq!(check(Some("Bearer ctl"), &names(&["ui.rproxy.internal"])).err(), Some("client_cert"));
		assert_eq!(tokens.authenticate_on(Some("Bearer ctl"), &names(&["spiffe://c/ns/x/sa/ctl"]), day("2027-02-01")).err(), Some("expired"));
		// plain tokens work with or without a certificate
		assert_eq!(check(Some("Bearer ci"), &names(&["ui.rproxy.internal"])).unwrap().auth, "token");
		assert_eq!(tokens.expiries(), [("ctl".to_string(), day("2027-01-31"))]);

		// client_cert needs the control API to ask for certificates
		let e = Tokens::from_file(file.clone()).unwrap().with_client_auth(ClientAuth::None).err().unwrap().to_string();
		assert!(e.contains("token ui: client_cert needs --tls-client-auth"), "{e}");
		let tokens = Tokens::from_file(file.clone()).unwrap().with_client_auth(ClientAuth::Required).unwrap();
		assert!(tokens.reload().is_ok());
		let plain = tempfile("plain", "secret\n");
		let tokens = Tokens::from_file(plain.clone()).unwrap().with_client_auth(ClientAuth::None).unwrap();
		std::fs::copy(&file, &plain).unwrap();
		assert!(tokens.reload().is_err(), "a reload adding client_cert is refused too");
		assert!(tokens.authenticate(Some("Bearer secret")).is_some(), "the current tokens stay");
		std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
		std::fs::remove_dir_all(plain.parent().unwrap()).unwrap();
	}

	#[test]
	fn disabled_allows_all() {
		let p = Tokens::disabled().authenticate(None).unwrap();
		assert!(p.has(Scope::Admin) && p.may_use_ports(1, 65535));
	}
}
