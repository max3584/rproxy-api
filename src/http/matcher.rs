//! The `match` expressions of L7 routes, written as in Traefik:
//! ``Host(`a.example`) && (PathPrefix(`/api/`) || Method(`POST`)) && !ClientIP(`10.0.0.0/8`)``.

use std::fmt;
use std::net::IpAddr;

use regex::Regex;

use crate::cidr::Cidr;

/// A parsed `match` expression.
#[derive(Clone, Debug)]
pub enum Matcher {
	And(Box<Matcher>, Box<Matcher>),
	Or(Box<Matcher>, Box<Matcher>),
	Not(Box<Matcher>),
	/// Host names, `*.example.com` wildcards allowed; case-insensitive, port ignored.
	Host(Vec<String>),
	HostRegexp(Regex),
	Path(Vec<String>),
	PathPrefix(Vec<String>),
	PathRegexp(Regex),
	/// Upper-case method names.
	Method(Vec<String>),
	Header(String, String),
	HeaderRegexp(String, Regex),
	/// `Query(key)` (present) or `Query(key, value)`.
	Query(String, Option<String>),
	QueryRegexp(String, Regex),
	ClientIP(Vec<Cidr>),
}

/// What a matcher looks at in one request.
pub struct RequestInfo<'a> {
	pub host: &'a str,
	pub path: &'a str,
	pub query: &'a str,
	pub method: &'a str,
	/// Header names in lower case.
	pub headers: &'a [(String, String)],
	pub client: IpAddr,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl fmt::Display for ParseError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

#[derive(Debug, PartialEq)]
enum Token {
	Ident(String),
	Str(String),
	LParen,
	RParen,
	Comma,
	And,
	Or,
	Not,
}

fn tokenize(src: &str) -> Result<Vec<Token>, ParseError> {
	let mut out = vec![];
	let mut chars = src.char_indices().peekable();
	while let Some((i, c)) = chars.next() {
		match c {
			c if c.is_whitespace() => {}
			'(' => out.push(Token::LParen),
			')' => out.push(Token::RParen),
			',' => out.push(Token::Comma),
			'!' => out.push(Token::Not),
			'&' | '|' => match chars.next() {
				Some((_, n)) if n == c => out.push(if c == '&' { Token::And } else { Token::Or }),
				_ => return Err(ParseError(format!("expected {c}{c} at {i}"))),
			},
			'`' | '"' => {
				let mut s = String::new();
				loop {
					match chars.next() {
						Some((_, q)) if q == c => break,
						Some((_, ch)) => s.push(ch),
						None => return Err(ParseError(format!("unterminated string starting at {i}"))),
					}
				}
				out.push(Token::Str(s));
			}
			c if c.is_ascii_alphabetic() => {
				let mut s = c.to_string();
				while let Some(&(_, n)) = chars.peek() {
					if n.is_ascii_alphanumeric() {
						s.push(n);
						chars.next();
					} else {
						break;
					}
				}
				out.push(Token::Ident(s));
			}
			c => return Err(ParseError(format!("unexpected '{c}' at {i}"))),
		}
	}
	Ok(out)
}

struct Parser {
	tokens: Vec<Token>,
	pos: usize,
}

impl Parser {
	fn peek(&self) -> Option<&Token> {
		self.tokens.get(self.pos)
	}

	fn next(&mut self) -> Option<Token> {
		let t = self.tokens.get(self.pos).map(|t| match t {
			Token::Ident(s) => Token::Ident(s.clone()),
			Token::Str(s) => Token::Str(s.clone()),
			Token::LParen => Token::LParen,
			Token::RParen => Token::RParen,
			Token::Comma => Token::Comma,
			Token::And => Token::And,
			Token::Or => Token::Or,
			Token::Not => Token::Not,
		});
		self.pos += 1;
		t
	}

	fn or(&mut self) -> Result<Matcher, ParseError> {
		let mut left = self.and()?;
		while self.peek() == Some(&Token::Or) {
			self.next();
			left = Matcher::Or(Box::new(left), Box::new(self.and()?));
		}
		Ok(left)
	}

	fn and(&mut self) -> Result<Matcher, ParseError> {
		let mut left = self.unary()?;
		while self.peek() == Some(&Token::And) {
			self.next();
			left = Matcher::And(Box::new(left), Box::new(self.unary()?));
		}
		Ok(left)
	}

	fn unary(&mut self) -> Result<Matcher, ParseError> {
		match self.next() {
			Some(Token::Not) => Ok(Matcher::Not(Box::new(self.unary()?))),
			Some(Token::LParen) => {
				let inner = self.or()?;
				match self.next() {
					Some(Token::RParen) => Ok(inner),
					_ => Err(ParseError("expected )".into())),
				}
			}
			Some(Token::Ident(name)) => self.call(&name),
			other => Err(ParseError(format!("expected a matcher, got {other:?}"))),
		}
	}

	fn call(&mut self, name: &str) -> Result<Matcher, ParseError> {
		if self.next() != Some(Token::LParen) {
			return Err(ParseError(format!("expected ( after {name}")));
		}
		let mut args = vec![];
		loop {
			match self.next() {
				Some(Token::Str(s)) => args.push(s),
				Some(Token::RParen) if args.is_empty() => break,
				other => return Err(ParseError(format!("{name}: expected a quoted argument, got {other:?}"))),
			}
			match self.next() {
				Some(Token::Comma) => continue,
				Some(Token::RParen) => break,
				other => return Err(ParseError(format!("{name}: expected , or ), got {other:?}"))),
			}
		}
		build(name, args)
	}
}

fn regex(name: &str, pattern: &str) -> Result<Regex, ParseError> {
	Regex::new(pattern).map_err(|e| ParseError(format!("{name}: {e}")))
}

fn build(name: &str, args: Vec<String>) -> Result<Matcher, ParseError> {
	let count = |n: std::ops::RangeInclusive<usize>| {
		if n.contains(&args.len()) {
			Ok(())
		} else {
			Err(ParseError(format!("{name} takes {} argument(s), got {}", fmt_range(&n), args.len())))
		}
	};
	Ok(match name {
		"Host" => {
			count(1..=usize::MAX)?;
			Matcher::Host(args.into_iter().map(|h| h.to_ascii_lowercase()).collect())
		}
		"HostRegexp" => {
			count(1..=1)?;
			Matcher::HostRegexp(regex(name, &args[0])?)
		}
		"Path" | "PathPrefix" => {
			count(1..=usize::MAX)?;
			if let Some(p) = args.iter().find(|p| !p.starts_with('/')) {
				return Err(ParseError(format!("{name}: {p:?} must start with /")));
			}
			if name == "Path" {
				Matcher::Path(args)
			} else {
				Matcher::PathPrefix(args)
			}
		}
		"PathRegexp" => {
			count(1..=1)?;
			Matcher::PathRegexp(regex(name, &args[0])?)
		}
		"Method" => {
			count(1..=usize::MAX)?;
			Matcher::Method(args.into_iter().map(|m| m.to_ascii_uppercase()).collect())
		}
		"Header" => {
			count(2..=2)?;
			let mut a = args.into_iter();
			Matcher::Header(a.next().unwrap().to_ascii_lowercase(), a.next().unwrap())
		}
		"HeaderRegexp" => {
			count(2..=2)?;
			Matcher::HeaderRegexp(args[0].to_ascii_lowercase(), regex(name, &args[1])?)
		}
		"Query" => {
			count(1..=2)?;
			let mut a = args.into_iter();
			Matcher::Query(a.next().unwrap(), a.next())
		}
		"QueryRegexp" => {
			count(2..=2)?;
			Matcher::QueryRegexp(args[0].clone(), regex(name, &args[1])?)
		}
		"ClientIP" => {
			count(1..=usize::MAX)?;
			let cidrs = args
				.iter()
				.map(|c| c.parse::<Cidr>().map_err(|e| ParseError(format!("ClientIP: {}", e.message))))
				.collect::<Result<_, _>>()?;
			Matcher::ClientIP(cidrs)
		}
		other => return Err(ParseError(format!("unknown matcher {other}"))),
	})
}

fn fmt_range(r: &std::ops::RangeInclusive<usize>) -> String {
	match (*r.start(), *r.end()) {
		(a, b) if a == b => a.to_string(),
		(a, usize::MAX) => format!("{a} or more"),
		(a, b) => format!("{a} to {b}"),
	}
}

impl Matcher {
	pub fn parse(src: &str) -> Result<Matcher, ParseError> {
		let mut p = Parser { tokens: tokenize(src)?, pos: 0 };
		if p.tokens.is_empty() {
			return Err(ParseError("empty match".into()));
		}
		let m = p.or()?;
		if p.pos != p.tokens.len() {
			return Err(ParseError(format!("unexpected {:?} after the expression", p.tokens[p.pos])));
		}
		Ok(m)
	}

	pub fn matches(&self, r: &RequestInfo) -> bool {
		match self {
			Matcher::And(a, b) => a.matches(r) && b.matches(r),
			Matcher::Or(a, b) => a.matches(r) || b.matches(r),
			Matcher::Not(a) => !a.matches(r),
			Matcher::Host(hosts) => {
				let host = strip_port(r.host).to_ascii_lowercase();
				hosts.iter().any(|h| crate::tlsconf::name_matches(h, &host))
			}
			Matcher::HostRegexp(re) => re.is_match(&strip_port(r.host).to_ascii_lowercase()),
			Matcher::Path(paths) => paths.iter().any(|p| p == r.path),
			Matcher::PathPrefix(prefixes) => prefixes.iter().any(|p| r.path.starts_with(p.as_str())),
			Matcher::PathRegexp(re) => re.is_match(r.path),
			Matcher::Method(methods) => methods.iter().any(|m| m == r.method),
			Matcher::Header(name, value) => r.headers.iter().any(|(n, v)| n == name && v == value),
			Matcher::HeaderRegexp(name, re) => r.headers.iter().any(|(n, v)| n == name && re.is_match(v)),
			Matcher::Query(key, value) => query_pairs(r.query).any(|(k, v)| k == key && value.as_deref().is_none_or(|want| v == want)),
			Matcher::QueryRegexp(key, re) => query_pairs(r.query).any(|(k, v)| k == key && re.is_match(v)),
			Matcher::ClientIP(cidrs) => cidrs.iter().any(|c| c.contains(r.client)),
		}
	}

	/// Traefik's default priority: the length of the expression.
	pub fn default_priority(src: &str) -> i64 {
		src.len() as i64
	}
}

fn strip_port(host: &str) -> &str {
	if host.starts_with('[') {
		return host.split(']').next().map(|h| h.trim_start_matches('[')).unwrap_or(host);
	}
	host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(host, |(h, _)| h)
}

fn query_pairs(query: &str) -> impl Iterator<Item = (&str, &str)> {
	query.split('&').filter(|kv| !kv.is_empty()).map(|kv| kv.split_once('=').unwrap_or((kv, "")))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn req<'a>(host: &'a str, method: &'a str, path: &'a str, client: &str, headers: &'a [(String, String)]) -> RequestInfo<'a> {
		let (path, query) = path.split_once('?').unwrap_or((path, ""));
		RequestInfo { host, path, query, method, headers, client: client.parse().unwrap() }
	}

	#[test]
	fn parses_the_gitlab_and_cdn_routes() {
		for src in [
			"Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)",
			"Host(`gitlab.example.com`) && (PathPrefix(`/assets/`) || PathPrefix(`/uploads/`))",
			"Host(`gitlab.example.com`) && ClientIP(`10.0.0.0/8`, `fd00::/8`)",
			"Host(`cdn.example.com`) && (PathPrefix(`/file/`) || PathPrefix(`/images/`) || PathPrefix(`/iso/`))",
			"HostRegexp(`^.+$`)",
			"!ClientIP(`192.0.2.0/24`) && Header(`X-Requested-With`, `XMLHttpRequest`) && Query(`preview`)",
		] {
			Matcher::parse(src).unwrap_or_else(|e| panic!("{src}: {e}"));
		}
	}

	#[test]
	fn matches_like_traefik() {
		let none: &[(String, String)] = &[];
		let login = Matcher::parse("Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)").unwrap();
		assert!(login.matches(&req("gitlab.example.com", "POST", "/users/sign_in", "198.51.100.1", none)));
		assert!(login.matches(&req("GitLab.Example.com:443", "POST", "/users/sign_in", "198.51.100.1", none)));
		assert!(!login.matches(&req("gitlab.example.com", "GET", "/users/sign_in", "198.51.100.1", none)));

		let assets = Matcher::parse("Host(`gitlab.example.com`) && (PathPrefix(`/assets/`) || PathPrefix(`/uploads/`))").unwrap();
		assert!(assets.matches(&req("gitlab.example.com", "GET", "/uploads/x.png?v=1", "198.51.100.1", none)));
		assert!(!assets.matches(&req("gitlab.example.com", "GET", "/api/v4", "198.51.100.1", none)));

		let internal = Matcher::parse("ClientIP(`10.0.0.0/8`, `fd00::/8`)").unwrap();
		assert!(internal.matches(&req("x", "GET", "/", "10.1.2.3", none)));
		assert!(internal.matches(&req("x", "GET", "/", "fd00::5", none)));
		assert!(!internal.matches(&req("x", "GET", "/", "2001:db8::1", none)));

		let wildcard = Matcher::parse("Host(`*.example.com`) && !Query(`debug`, `1`)").unwrap();
		assert!(wildcard.matches(&req("cdn.example.com", "GET", "/", "10.0.0.1", none)));
		assert!(!wildcard.matches(&req("cdn.example.com", "GET", "/?debug=1", "10.0.0.1", none)));

		let headers = vec![("x-requested-with".to_string(), "XMLHttpRequest".to_string())];
		let xhr = Matcher::parse("Header(`X-Requested-With`, `XMLHttpRequest`)").unwrap();
		assert!(xhr.matches(&req("x", "GET", "/", "10.0.0.1", &headers)));
	}

	#[test]
	fn rejects_mistakes_with_a_reason() {
		for (src, want) in [
			("", "empty"),
			("Host(`a`) &", "&&"),
			("Host(`a`", "expected"),
			("Hots(`a`)", "unknown matcher Hots"),
			("Path(`api`)", "must start with /"),
			("Header(`X`)", "takes 2"),
			("ClientIP(`not-an-ip`)", "ClientIP"),
			("PathRegexp(`(`)", "PathRegexp"),
			("Host(`a`) Host(`b`)", "after the expression"),
		] {
			let err = Matcher::parse(src).unwrap_err().0;
			assert!(err.contains(want), "{src:?}: {err}");
		}
	}
}
