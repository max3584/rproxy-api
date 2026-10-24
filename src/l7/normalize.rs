//! The request target as routes see it (#320): the path is normalised like
//! Traefik v3's `sanitizePath` before `match` runs and before the request goes on,
//! so `/%61dmin`, `//admin`, `/x/../admin` and `/admin/.` cannot slip past a
//! `PathPrefix(`/admin`)` route with an authentication middleware; the host is
//! compared without a trailing dot.
//!
//! Path rules (docs/API.md "HTTP の転送の扱い"):
//! - percent-encoded unreserved characters (RFC 3986 2.3: `A-Z a-z 0-9 - . _ ~`)
//!   are decoded; every other escape stays encoded with upper-case hex digits
//!   (`%2f` → `%2F`; `%2F` is never a separator);
//! - `.` segments go, `..` removes the segment before it (never above the root:
//!   `/../a` is `/a`), empty segments (`//`) go;
//! - a trailing `/` is kept when the path ended with one (Go's `path.Clean` plus
//!   the slash, as Traefik does: `/admin/.` is `/admin`, `/admin/./` is `/admin/`);
//! - a `%` not followed by two hex digits makes the request invalid (400).
//!
//! A path that is already normal is passed back borrowed: no allocation.

use std::borrow::Cow;

/// A `%` not followed by two hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPath;

impl std::fmt::Display for InvalidPath {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("invalid percent-encoding in the path")
	}
}

impl std::error::Error for InvalidPath {}

/// RFC 3986 2.3.
fn unreserved(b: u8) -> bool {
	b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn hex(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

/// The byte of the escape at `at` (`%XY`).
fn escape(p: &[u8], at: usize) -> Result<u8, InvalidPath> {
	match (p.get(at + 1).copied().and_then(hex), p.get(at + 2).copied().and_then(hex)) {
		(Some(h), Some(l)) => Ok(h << 4 | l),
		_ => Err(InvalidPath),
	}
}

/// Whether `path` (starting with `/`) is already normal: one pass, no allocation.
/// `Ok(false)` as soon as something must change; the slow path then checks the rest.
fn is_normal(p: &[u8]) -> Result<bool, InvalidPath> {
	let mut i = 1;
	while i < p.len() {
		let b = p[i];
		if b == b'%' {
			let decoded = escape(p, i)?;
			if unreserved(decoded) || p[i + 1].is_ascii_lowercase() || p[i + 2].is_ascii_lowercase() {
				return Ok(false);
			}
			i += 3;
			continue;
		}
		// the start of a segment: empty (`//`), `.` or `..`
		if p[i - 1] == b'/' {
			if b == b'/' {
				return Ok(false);
			}
			if b == b'.' {
				let rest = &p[i + 1..];
				if rest.first().is_none_or(|&c| c == b'/') || (rest[0] == b'.' && rest.get(1).is_none_or(|&c| c == b'/')) {
					return Ok(false);
				}
			}
		}
		i += 1;
	}
	Ok(true)
}

/// The normalised form of a request path. Paths that do not start with `/`
/// (`*` of `OPTIONS *`, the empty path of CONNECT) are left as they are.
pub fn path(path: &str) -> Result<Cow<'_, str>, InvalidPath> {
	let p = path.as_bytes();
	if p.first() != Some(&b'/') || is_normal(p)? {
		return Ok(Cow::Borrowed(path));
	}
	// decode the unreserved escapes, upper-case the others
	let mut decoded = String::with_capacity(p.len());
	let mut i = 0;
	while i < p.len() {
		if p[i] == b'%' {
			let b = escape(p, i)?;
			if unreserved(b) {
				decoded.push(b as char);
			} else {
				decoded.push('%');
				decoded.push(p[i + 1].to_ascii_uppercase() as char);
				decoded.push(p[i + 2].to_ascii_uppercase() as char);
			}
			i += 3;
		} else {
			// copied as it is, a whole UTF-8 character at a time: the `http` crate takes bytes
			// from 0x80 up in a path (and `path()` is a `&str`), so `i` must stay on a boundary
			let next = path[i..].chars().next().map_or(1, char::len_utf8);
			decoded.push_str(&path[i..i + next]);
			i += next;
		}
	}
	// dot segments and empty segments
	let trailing = decoded.ends_with('/');
	let mut segments: Vec<&str> = Vec::new();
	for seg in decoded.split('/') {
		match seg {
			"" | "." => {}
			".." => {
				segments.pop();
			}
			s => segments.push(s),
		}
	}
	let mut out = String::with_capacity(decoded.len());
	for seg in &segments {
		out.push('/');
		out.push_str(seg);
	}
	if out.is_empty() || trailing {
		out.push('/');
	}
	Ok(Cow::Owned(out))
}

/// Characters some backends read differently from rproxy (#320, `http.strict_path`):
/// an encoded `/`, `\`, `;` or `%`, a raw `;` (Tomcat's `..;/`) or `\`.
pub fn risky(path: &str) -> bool {
	let p = path.as_bytes();
	p.iter().enumerate().any(|(i, &b)| match b {
		b';' | b'\\' => true,
		b'%' => matches!(
			(p.get(i + 1).map(u8::to_ascii_uppercase), p.get(i + 2).map(u8::to_ascii_uppercase)),
			(Some(b'2'), Some(b'F' | b'5')) | (Some(b'5'), Some(b'C')) | (Some(b'3'), Some(b'B'))
		),
		_ => false,
	})
}

/// The host for matching: `request_host` has taken the port off and lowered it;
/// a fully qualified name's trailing dot goes too (`example.com.` is `example.com`).
pub fn host(host: &str) -> &str {
	host.strip_suffix('.').unwrap_or(host)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn n(p: &str) -> String {
		path(p).unwrap().into_owned()
	}

	#[test]
	fn normal_paths_are_borrowed() {
		for p in [
			"/",
			"/admin",
			"/admin/",
			"/a/b/c.txt",
			"/a%2Fb",
			"/%E3%81%82",
			"/a?b",
			"/.well-known/x",
			"/a..b/c.",
			"/~u/-_.x",
			"*",
			"",
		] {
			assert!(matches!(path(p), Ok(Cow::Borrowed(_))), "{p}");
		}
	}

	#[test]
	fn bypasses_are_closed() {
		assert_eq!(n("/%61dmin"), "/admin");
		assert_eq!(n("/%41dmin"), "/Admin");
		assert_eq!(n("//admin"), "/admin");
		assert_eq!(n("/x/../admin"), "/admin");
		assert_eq!(n("/admin/."), "/admin");
		assert_eq!(n("/admin/./"), "/admin/");
		assert_eq!(n("/x/%2e%2e/admin"), "/admin");
		assert_eq!(n("/x/.%2E/admin"), "/admin");
		assert_eq!(n("/./admin//secret/"), "/admin/secret/");
	}

	#[test]
	fn reserved_escapes_stay_encoded() {
		assert_eq!(n("/a%2fb"), "/a%2Fb");
		assert_eq!(n("/a%2F..%2Fadmin"), "/a%2F..%2Fadmin");
		assert_eq!(n("/x/%2F/../a"), "/x/a");
		assert_eq!(n("/%e3%81%82"), "/%E3%81%82");
		assert_eq!(n("/a%20b"), "/a%20b");
		assert_eq!(n("/%7euser"), "/~user");
	}

	#[test]
	fn above_the_root_stays_at_the_root() {
		assert_eq!(n("/.."), "/");
		assert_eq!(n("/../"), "/");
		assert_eq!(n("/../../a"), "/a");
		assert_eq!(n("/a/b/../../.."), "/");
		assert_eq!(n("/a/b/.."), "/a");
		assert_eq!(n("/a/b/../"), "/a/");
		assert_eq!(n("//"), "/");
	}

	#[test]
	fn broken_escapes_are_refused() {
		for p in ["/%", "/%4", "/%zz", "/a%2", "/a%g0", "//%"] {
			assert_eq!(path(p), Err(InvalidPath), "{p}");
		}
	}

	#[test]
	fn normalising_twice_changes_nothing() {
		for p in ["/%61/%2e/./b//c/..", "/a%2fb/", "/x/../../y/%7E", "//a//b//"] {
			let once = n(p);
			assert!(matches!(path(&once), Ok(Cow::Borrowed(_))), "{p} -> {once}");
		}
	}

	#[test]
	fn risky_characters() {
		for p in ["/a%2Fb", "/a%2fb", "/a%5cb", "/a%3B", "/a%25", "/a;b", "/..;/admin", "/a\\b"] {
			assert!(risky(p), "{p}");
		}
		for p in ["/a/b", "/%61dmin", "/a%20b", "/%E3%81%82", "/a%2"] {
			assert!(!risky(p), "{p}");
		}
	}

	#[test]
	fn trailing_dot_of_the_host() {
		assert_eq!(host("example.com."), "example.com");
		assert_eq!(host("example.com"), "example.com");
		assert_eq!(host("::1"), "::1");
	}
}
