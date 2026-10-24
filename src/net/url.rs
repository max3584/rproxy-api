//! The one strict reading of the http(s) URLs rproxy connects to (#324): services'
//! `servers[].url`, routes' `to`, `forward_auth.address`, `oidc.issuer` and the
//! provider's endpoints, `global.crowdsec`, ACME and the self-update.
//!
//! What another URL parser (the WHATWG one of browsers and the UI, `http::Uri`, a
//! resolver) could read differently is refused, so a front-end check and rproxy
//! never disagree on where a URL goes:
//! - `http://` or `https://` (lower case) only;
//! - visible ASCII only: no whitespace, control characters, non-ASCII or `\`
//!   (which WHATWG reads as `/`), and no `#` (fragments are never sent); base URLs
//!   that paths are appended to ([`parse_base`]) take no query either;
//! - no userinfo (`user:pass@`): it would end up in `Host`, and WHATWG strips it;
//! - a host that is not empty: a name of letters, digits, `-`, `_` and `.` (no empty
//!   label, no `-` at either end of a label), an
//!   IPv4 address in the dotted-quad form only (WHATWG reads `127.1` or `0x7f.1`
//!   as addresses, resolvers may not), or an IPv6 literal in `[]` without a zone ID;
//! - a port, when given, of decimal digits between 1 and 65535 (`:`, `:0`,
//!   `:65536`, `:8a` are refused, not read as the default port).

use std::net::{Ipv4Addr, Ipv6Addr};

use hyper::Uri;

/// An http(s) URL that passed [`parse`].
#[derive(Debug, Clone)]
pub struct HttpUrl {
	pub uri: Uri,
	pub https: bool,
	/// The host as connected to: a name, an IPv4 address or an IPv6 address without the brackets.
	pub host: String,
	/// The given port, or 80 / 443.
	pub port: u16,
}

impl HttpUrl {
	/// `host[:port]` as written (for `Host`).
	pub fn authority(&self) -> &str {
		self.uri.authority().map(|a| a.as_str()).unwrap_or_default()
	}

	/// The path and query to send (`/` when the URL has none).
	pub fn path_and_query(&self) -> &str {
		match self.uri.path_and_query().map(|p| p.as_str()) {
			Some(p) if !p.is_empty() => p,
			_ => "/",
		}
	}
}

/// Reads an http(s) URL strictly (see the module); the error says what is wrong.
pub fn parse(url: &str) -> Result<HttpUrl, String> {
	if let Some(c) = url.chars().find(|c| !c.is_ascii_graphic() || *c == '\\' || *c == '#') {
		return Err(format!("contains {c:?} (only visible ASCII, without \\ and #)"));
	}
	let (https, rest) = match (url.strip_prefix("http://"), url.strip_prefix("https://")) {
		(Some(r), _) => (false, r),
		(_, Some(r)) => (true, r),
		_ => return Err("must start with http:// or https://".into()),
	};
	let authority = &rest[..rest.find(['/', '?']).unwrap_or(rest.len())];
	if authority.contains('@') {
		return Err("must not contain user information (user@)".into());
	}
	let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
		let (inside, after) = v6.split_once(']').ok_or("has an IPv6 address without the closing ]")?;
		if inside.contains('%') {
			return Err(format!("IPv6 address [{inside}]: zone IDs are not allowed"));
		}
		inside
			.parse::<Ipv6Addr>()
			.map_err(|_| format!("[{inside}] is not an IPv6 address"))?;
		let port = match after {
			"" => None,
			p => Some(
				p.strip_prefix(':')
					.ok_or_else(|| format!("{after:?} after the IPv6 address is not :port"))?,
			),
		};
		(inside, port)
	} else {
		match authority.split_once(':') {
			Some((h, p)) => (h, Some(p)),
			None => (authority, None),
		}
	};
	if host.is_empty() {
		return Err("has no host".into());
	}
	if !authority.starts_with('[') {
		check_name(host)?;
	}
	let port = match port {
		None => {
			if https {
				443
			} else {
				80
			}
		}
		Some(p) => {
			let n = (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
				.then(|| p.trim_start_matches('0'))
				.filter(|d| d.len() <= 5);
			match n.and_then(|d| d.parse::<u16>().ok()).filter(|n| *n > 0) {
				Some(n) => n,
				None => return Err(format!("port {p:?} is not a number between 1 and 65535")),
			}
		}
	};
	let uri: Uri = url.parse().map_err(|e| format!("{e}"))?;
	// what http::Uri read must be what was checked above
	match uri.authority() {
		Some(a) if a.as_str() == authority && uri.scheme_str() == Some(if https { "https" } else { "http" }) => {}
		_ => return Err("is not read the same way by every URL parser".into()),
	}
	Ok(HttpUrl {
		uri,
		https,
		host: host.to_string(),
		port,
	})
}

/// [`parse`] for a base URL that rproxy appends paths to (`oidc.issuer`, the CrowdSec
/// LAPI and AppSec): no query either, which would end up before the appended path.
pub fn parse_base(url: &str) -> Result<HttpUrl, String> {
	let u = parse(url)?;
	if u.uri.query().is_some() || url.contains('?') {
		return Err("must not have a query (?): paths are appended to it".into());
	}
	Ok(u)
}

/// A host name or a dotted-quad IPv4 address.
fn check_name(host: &str) -> Result<(), String> {
	if let Some(c) = host.chars().find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))) {
		return Err(format!("host {host:?} contains {c:?}"));
	}
	// labels (one trailing dot, a fully qualified name, is allowed): not empty, no - at either end
	let labels = host.strip_suffix('.').unwrap_or(host);
	if labels.split('.').any(|l| l.is_empty() || l.starts_with('-') || l.ends_with('-')) {
		return Err(format!("host {host:?} has an empty label or one that starts or ends with -"));
	}
	// WHATWG reads a host whose last label is a number (decimal or 0x) as an IPv4
	// address, in forms (127.1, 0x7f.1, 010.0.0.1) resolvers read otherwise
	let last = host.trim_end_matches('.').rsplit('.').next().unwrap_or_default();
	let numeric = !last.is_empty()
		&& (last.bytes().all(|b| b.is_ascii_digit())
			|| last.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("0x")) && last[2..].bytes().all(|b| b.is_ascii_hexdigit()));
	if numeric && host.parse::<Ipv4Addr>().is_err() {
		return Err(format!("host {host:?} is not an IPv4 address in the form a.b.c.d"));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn valid_urls_and_their_ports() {
		for (url, https, host, port, pq) in [
			("http://a", false, "a", 80, "/"),
			("https://a", true, "a", 443, "/"),
			("http://10.0.0.1:8080/base/?x=1", false, "10.0.0.1", 8080, "/base/?x=1"),
			("https://b.example:8443/base/", true, "b.example", 8443, "/base/"),
			("http://[::1]:9000/p", false, "::1", 9000, "/p"),
			("https://[2001:db8::1]", true, "2001:db8::1", 443, "/"),
			("http://a:65535", false, "a", 65535, "/"),
			("http://a:1", false, "a", 1, "/"),
			("http://a:080", false, "a", 80, "/"),
			("http://keycloak_1.internal.:80", false, "keycloak_1.internal.", 80, "/"),
			("http://status-503.invalid", false, "status-503.invalid", 80, "/"),
			("http://a?q", false, "a", 80, "?q"),
			// found by fuzzing: '@' in the path is not userinfo
			("http://369.254th/v@p//", false, "369.254th", 80, "/v@p//"),
		] {
			let u = parse(url).unwrap_or_else(|e| panic!("{url}: {e}"));
			assert_eq!(
				(u.https, u.host.as_str(), u.port, u.path_and_query()),
				(https, host, port, pq),
				"{url}"
			);
		}
		assert_eq!(parse("http://[::1]:9000/p").unwrap().authority(), "[::1]:9000");
	}

	#[test]
	fn base_urls_take_no_query() {
		assert_eq!(parse_base("https://id.example/realms/x").unwrap().path_and_query(), "/realms/x");
		assert!(parse_base("http://a-b.example:8080/").is_ok());
		for url in ["https://id.example/realms/x?a=1", "http://127.0.0.1:8080?", "http://a/?"] {
			let e = parse_base(url).err().unwrap_or_else(|| panic!("{url:?} was accepted"));
			assert!(e.contains("query"), "{url:?}: {e}");
		}
		assert!(parse_base("http://a/#x").unwrap_err().contains("#"));
	}

	#[test]
	fn ports_hosts_and_characters_other_parsers_read_otherwise_are_refused() {
		for (url, why) in [
			("http://127.0.0.1:8a/", "port"),
			("http://169.254.169.254:65536/", "port"),
			("http://a:99999999999/", "port"),
			("http://a:/", "port"),
			("http://a:0/", "port"),
			("http://a:-1/", "port"),
			("http://a:+80/", "port"),
			("http://a: 80/", "visible ASCII"),
			("http://[fe80::1%25eth0]/", "zone"),
			("http://[fe80::1%eth0]:80/", "zone"),
			("http://[::1/", "closing"),
			("http://[::1]x/", "after the IPv6"),
			("http://[::g]/", "IPv6"),
			("http://[::1]:8a/", "port"),
			("http://", "no host"),
			("http:///x", "no host"),
			("https://:443/", "no host"),
			("http://user:pw@a/", "user"),
			("http://evil@127.0.0.1/", "user"),
			("http://a\\@b/", "visible ASCII"),
			("http://a\\b/", "visible ASCII"),
			("http://a/b c", "visible ASCII"),
			("http://a/\tb", "visible ASCII"),
			(" http://a/", "visible ASCII"),
			("http://a/\n", "visible ASCII"),
			("http://ä.example/", "visible ASCII"),
			("http://a/#x", "visible ASCII"),
			("http://a%2eb/", "contains"),
			("http://a,b/", "contains"),
			("http://127.1/", "IPv4"),
			("http://0x7f.0.0.1/", "IPv4"),
			("http://010.0.0.1/", "IPv4"),
			("http://1.2.3.4./", "IPv4"),
			("http://2130706433/", "IPv4"),
			("http://./", "label"),
			("http://a..b/", "label"),
			("http://.a/", "label"),
			("http://a.b../", "label"),
			("http://-/", "label"),
			("http://-a.example/", "label"),
			("http://a-.example/", "label"),
			("HTTP://a/", "http://"),
			("ftp://a/", "http://"),
			("a:80", "http://"),
			("//a/", "http://"),
		] {
			let e = parse(url).err().unwrap_or_else(|| panic!("{url:?} was accepted"));
			assert!(e.contains(why), "{url:?}: {e}");
		}
	}
}
