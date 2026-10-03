use std::io;
use std::path::PathBuf;
use std::sync::RwLock;

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
}

impl Principal {
	/// Without a token file every request is allowed.
	fn anonymous() -> Self {
		Principal { name: String::new(), scopes: vec![Scope::Admin], ports: None }
	}

	pub fn has(&self, scope: Scope) -> bool {
		self.scopes.iter().any(|s| *s == scope || *s == Scope::Admin)
	}

	/// Whether the listen ports `first..=last` are all within `allow_listen_ports`.
	pub fn may_use_ports(&self, first: u16, last: u16) -> bool {
		self.ports.is_none_or(|(lo, hi)| lo <= first && last <= hi)
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Secret {
	Plain(String),
	Sha256([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Token {
	secret: Secret,
	principal: Principal,
	expires: Option<time::Date>,
}

/// One entry of the YAML token file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenEntry {
	name: String,
	sha256: String,
	scopes: Vec<Scope>,
	#[serde(default)]
	allow_listen_ports: Option<String>,
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
			let hash = parse_hex(&e.sha256)
				.ok_or_else(|| invalid(path, format!("{}: sha256 must be 64 hex digits (sha256sum of the token)", e.name)))?;
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
			tokens.push(Token {
				secret: Secret::Sha256(hash),
				principal: Principal { name: e.name, scopes: e.scopes, ports },
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
				secret: Secret::Plain(l.to_string()),
				principal: Principal { name: format!("token-{}", i + 1), scopes: vec![Scope::Admin], ports: None },
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
}

impl Tokens {
	/// No token file: every request is allowed.
	pub fn disabled() -> Self {
		Tokens { path: None, tokens: RwLock::default() }
	}

	pub fn from_file(path: PathBuf) -> io::Result<Self> {
		let tokens = read_tokens(&path)?;
		Ok(Tokens { path: Some(path), tokens: RwLock::new(tokens) })
	}

	/// Authentication is on but no token is known yet (the file could not be
	/// read): every request is refused until a reload succeeds.
	pub fn locked(path: PathBuf) -> Self {
		Tokens { path: Some(path), tokens: RwLock::default() }
	}

	pub fn enabled(&self) -> bool {
		self.path.is_some()
	}

	/// Re-reads the token file; on error the current tokens stay in effect.
	pub fn reload(&self) -> io::Result<usize> {
		let Some(path) = &self.path else { return Ok(0) };
		let tokens = read_tokens(path)?;
		let count = tokens.len();
		*self.tokens.write().unwrap() = tokens;
		Ok(count)
	}

	/// Checks an `Authorization` header value; `None` if it is missing, unknown or expired.
	pub fn authenticate(&self, header: Option<&str>) -> Option<Principal> {
		self.authenticate_on(header, time::OffsetDateTime::now_utc().date())
	}

	fn authenticate_on(&self, header: Option<&str>, today: time::Date) -> Option<Principal> {
		if !self.enabled() {
			return Some(Principal::anonymous());
		}
		let presented = header.and_then(|h| h.strip_prefix("Bearer ")).map(str::trim)?;
		let hash: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
		// check every token so the time taken does not reveal which one matched
		let mut found = None;
		for t in self.tokens.read().unwrap().iter() {
			let ok = match &t.secret {
				Secret::Plain(s) => constant_time_eq(s.as_bytes(), presented.as_bytes()),
				Secret::Sha256(h) => constant_time_eq(h, &hash),
			};
			if ok && found.is_none() && t.expires.is_none_or(|d| today <= d) {
				found = Some(t.principal.clone());
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
		let ci = tokens.authenticate_on(Some("Bearer ci-secret"), day("2027-03-31")).unwrap();
		assert!(!ci.has(Scope::RulesRead));
		assert!(ci.may_use_ports(20000, 20010) && !ci.may_use_ports(19999, 20000) && !ci.may_use_ports(29999, 30000));
		assert!(tokens.authenticate_on(Some("Bearer ci-secret"), day("2027-04-01")).is_none(), "expired");
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
			("tokens: []\n", "no tokens"),
		] {
			let file = tempfile("bad", text);
			let e = Tokens::from_file(file.clone()).err().unwrap_or_else(|| panic!("accepted: {text}")).to_string();
			assert!(e.contains(want), "{text}: {e}");
			std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
		}
	}

	#[test]
	fn disabled_allows_all() {
		let p = Tokens::disabled().authenticate(None).unwrap();
		assert!(p.has(Scope::Admin) && p.may_use_ports(1, 65535));
	}
}
