//! Router rules: Traefik's HTTP `rule` (v2 and v3) → rproxy's `match` (the v3
//! syntax, src/l7/matcher.rs), the names of `Host(...)` (certificate domains), and
//! `HostSNIRegexp` → rproxy's server-name patterns.

use std::sync::LazyLock;

use regex::{Captures, Regex};

use crate::NoteSink;

/// One matcher call: ``Name(`a`, "b")``.
pub(crate) static CALL: LazyLock<Regex> =
	LazyLock::new(|| Regex::new(r#"([A-Za-z]+)\(((?:\s*(?:`[^`]*`|"(?:[^"\\]|\\.)*")\s*,?)*)\)"#).unwrap());
static ARG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"`([^`]*)`|"((?:[^"\\]|\\.)*)""#).unwrap());
/// A Traefik v2 placeholder: `{name}` or `{name:regex}`.
static PLACEHOLDER: LazyLock<Regex> =
	LazyLock::new(|| Regex::new(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::((?:[^{}]|\{[^{}]*\})*))?\}").unwrap());
static SNI_SUFFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$").unwrap());
static SNI_V2: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\{[a-z]+:(.+?)\}\.([A-Za-z0-9.-]+)$").unwrap());

/// The matchers rproxy's `match` has.
pub const HTTP_MATCHERS: &[&str] =
	&["Host", "HostRegexp", "Path", "PathPrefix", "PathRegexp", "Method", "Header", "HeaderRegexp", "Query", "QueryRegexp", "ClientIP"];

/// The arguments of one matcher call, unquoted. A double-quoted argument is a Go
/// string literal in Traefik (`"^a\\.b$"` is `^a\.b$`), a backquoted one is raw.
pub(crate) fn call_args(text: &str) -> Vec<String> {
	ARG.captures_iter(text)
		.map(|c| match c.get(1) {
			Some(raw) => raw.as_str().to_string(),
			None => go_unquote(&c[2]),
		})
		.collect()
}

/// The body of a Go interpreted string literal without its quotes (`\\`, `\"`, `\n`,
/// `\t`, `\xNN`, `\uNNNN` …); an escape it does not know is kept as written.
fn go_unquote(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	let mut chars = s.chars().peekable();
	while let Some(c) = chars.next() {
		if c != '\\' {
			out.push(c);
			continue;
		}
		let Some(e) = chars.next() else {
			out.push('\\');
			break;
		};
		let simple = match e {
			'\\' => Some('\\'),
			'"' => Some('"'),
			'\'' => Some('\''),
			'n' => Some('\n'),
			't' => Some('\t'),
			'r' => Some('\r'),
			'a' => Some('\u{7}'),
			'b' => Some('\u{8}'),
			'f' => Some('\u{c}'),
			'v' => Some('\u{b}'),
			_ => None,
		};
		if let Some(c) = simple {
			out.push(c);
			continue;
		}
		let len = match e {
			'x' => 2,
			'u' => 4,
			'U' => 8,
			_ => 0,
		};
		let hex: String = chars.clone().take(len).collect();
		match (len > 0 && hex.len() == len).then(|| u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)).flatten() {
			Some(c) => {
				out.push(c);
				for _ in 0..len {
					chars.next();
				}
			}
			None => {
				out.push('\\');
				out.push(e);
			}
		}
	}
	out
}

/// Quotes arguments for rproxy's `match`: backquotes, or double quotes for an argument
/// with a backquote (rproxy's strings have no escapes). `None` if one has both.
fn quote(args: &[String]) -> Option<String> {
	let mut out = vec![];
	for a in args {
		if !a.contains('`') {
			out.push(format!("`{a}`"));
		} else if !a.contains('"') {
			out.push(format!("\"{a}\""));
		} else {
			return None;
		}
	}
	Some(out.join(", "))
}

/// Python's `re.escape` (3.7+): escapes `()[]{}?*+-|^$\.&~#` and whitespace.
pub(crate) fn re_escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		if "()[]{}?*+-|^$\\.&~# \t\n\r\u{b}\u{c}".contains(c) {
			out.push('\\');
		}
		out.push(c);
	}
	out
}

fn has_placeholder(s: &str) -> bool {
	PLACEHOLDER.is_match(s)
}

/// Traefik v2 placeholders (`{name}` or `{name:regex}`) as a regular expression; a
/// placeholder without a regex matches `segment`.
pub fn v2_template(value: &str, segment: &str) -> String {
	let mut out = String::new();
	let mut pos = 0;
	for c in PLACEHOLDER.captures_iter(value) {
		let m = c.get(0).unwrap();
		out.push_str(&re_escape(&value[pos..m.start()]));
		out.push_str("(?:");
		out.push_str(c.get(2).map_or(segment, |r| r.as_str()));
		out.push(')');
		pos = m.end();
	}
	out.push_str(&re_escape(&value[pos..]));
	out
}

/// A Traefik v2 / v3 router rule → rproxy's `match` (the v3 syntax).
///
/// v2's `Headers` / `HeadersRegexp` become `Header` / `HeaderRegexp`, `HostHeader`
/// becomes `Host`, ``Query(`a=b`)`` becomes ``Query(`a`, `b`)``, several
/// `HostRegexp` arguments one alternation, and v2 placeholders (`{sub:[a-z]+}`) in
/// `Host` / `Path` / `PathPrefix` a `HostRegexp` / `PathRegexp`. Notes go to `notes`
/// under `where_`. `None` (with a note) if the rule has a matcher rproxy lacks, so the
/// router has to be left out.
pub fn translate_http_rule(rule: &str, where_: &str, notes: &mut dyn NoteSink) -> Option<String> {
	let mut failed: Vec<String> = vec![];
	let mut unquotable = false;
	let out = CALL.replace_all(rule.trim(), |m: &Captures| {
		let mut name = m[1].to_string();
		let mut args = call_args(&m[2]);
		if name == "Headers" || name == "HeadersRegexp" {
			name = name.replace("Headers", "Header");
		}
		if name == "HostHeader" {
			name = "Host".into();
		}
		if name == "Query" && args.len() == 1 && args[0].contains('=') {
			let (k, v) = args[0].split_once('=').unwrap();
			args = vec![k.to_string(), v.to_string()];
		}
		if (name == "Host" || name == "HostRegexp") && args.iter().any(|a| has_placeholder(a)) {
			let regex: Vec<String> =
				args.iter().map(|a| if has_placeholder(a) { v2_template(a, "[^.]+") } else { re_escape(a) }).collect();
			notes.note(where_, "v2 host placeholders converted to HostRegexp");
			return wrap("HostRegexp", &format!("^(?:{})$", regex.join("|")), &mut unquotable);
		}
		if (name == "Path" || name == "PathPrefix") && args.iter().any(|a| has_placeholder(a)) {
			let regex: Vec<String> =
				args.iter().map(|a| if has_placeholder(a) { v2_template(a, "[^/]+") } else { re_escape(a) }).collect();
			let end = if name == "Path" { "$" } else { "" };
			notes.note(where_, "v2 path placeholders converted to PathRegexp");
			return wrap("PathRegexp", &format!("^(?:{}){end}", regex.join("|")), &mut unquotable);
		}
		if name == "HostRegexp" && args.len() > 1 {
			args = vec![args.iter().map(|a| format!("(?:{a})")).collect::<Vec<_>>().join("|")];
		}
		if !HTTP_MATCHERS.contains(&name.as_str()) {
			failed.push(name);
			return m[0].to_string();
		}
		match quote(&args) {
			Some(q) => format!("{name}({q})"),
			None => {
				unquotable = true;
				m[0].to_string()
			}
		}
	});
	if !failed.is_empty() {
		failed.sort();
		failed.dedup();
		notes.note(where_, &format!("matcher {} has no rproxy equivalent; router left out", failed.join(", ")));
		return None;
	}
	if unquotable {
		notes.note(where_, "an argument has both ` and \" (rproxy's match cannot quote it); router left out");
		return None;
	}
	Some(out.into_owned())
}

fn wrap(name: &str, arg: &str, unquotable: &mut bool) -> String {
	match quote(&[arg.to_string()]) {
		Some(q) => format!("{name}({q})"),
		None => {
			*unquotable = true;
			String::new()
		}
	}
}

const SNI_ANY_DEPTH: &[&str] = &[".+", ".*", "(.+)", "(.*)"];
const SNI_ONE_LABEL: &[&str] = &["[^.]+", "[^\\.]+", "[a-z0-9-]+", "[a-zA-Z0-9-]+", "[0-9a-z-]+", "[-a-z0-9]+"];

/// A `HostSNIRegexp` that is a plain suffix → rproxy's server-name pattern:
/// `^.+\.example\.com$` → `**.example.com` (any depth), `^[^.]+\.example\.com$` →
/// `*.example.com` (one label); also v2's `{name:regex}.example.com`. `None` otherwise.
pub fn sni_regexp_pattern(regex: &str) -> Option<String> {
	let body = regex.trim();
	let body = body.strip_prefix('^').unwrap_or(body);
	let body = body.strip_suffix('$').unwrap_or(body);
	for (prefixes, wildcard) in [(SNI_ANY_DEPTH, "**."), (SNI_ONE_LABEL, "*.")] {
		for prefix in prefixes {
			if let Some(rest) = body.strip_prefix(&format!("{prefix}\\.")) {
				let suffix = rest.replace("\\.", ".");
				if !suffix.is_empty() && SNI_SUFFIX.is_match(&suffix) {
					return Some(format!("{wildcard}{}", suffix.to_lowercase()));
				}
			}
		}
	}
	let c = SNI_V2.captures(body)?;
	let inner = &c[1];
	if SNI_ANY_DEPTH.contains(&inner) {
		return Some(format!("**.{}", c[2].to_lowercase()));
	}
	if SNI_ONE_LABEL.contains(&inner) {
		return Some(format!("*.{}", c[2].to_lowercase()));
	}
	None
}

/// The host names of a rule's `Host(...)` / `HostHeader(...)` (lowercase, without
/// v2 placeholders): the domains of a certificate.
pub fn host_names(rule: &str) -> Vec<String> {
	let mut names = vec![];
	for m in CALL.captures_iter(rule) {
		if &m[1] == "Host" || &m[1] == "HostHeader" {
			names.extend(call_args(&m[2]).into_iter().filter(|a| !has_placeholder(a)).map(|a| a.to_lowercase()));
		}
	}
	names
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::Notes;

	fn tr(rule: &str) -> (Option<String>, Vec<String>) {
		let mut n = Notes::default();
		let out = translate_http_rule(rule, "r", &mut n);
		(out, n.items)
	}

	#[test]
	fn rules() {
		assert_eq!(tr("Host(`a.example`) && PathPrefix(`/api`)").0.as_deref(), Some("Host(`a.example`) && PathPrefix(`/api`)"));
		assert_eq!(tr("Headers(`X`, `1`) || HostHeader(`a`)").0.as_deref(), Some("Header(`X`, `1`) || Host(`a`)"));
		assert_eq!(tr("Query(`a=b`)").0.as_deref(), Some("Query(`a`, `b`)"));
		assert_eq!(tr("HostRegexp(`a`, `b`)").0.as_deref(), Some("HostRegexp(`(?:a)|(?:b)`)"));
		let (out, notes) = tr("Host(`{sub:[a-z]+}.example.com`)");
		assert_eq!(out.as_deref(), Some("HostRegexp(`^(?:(?:[a-z]+)\\.example\\.com)$`)"));
		assert_eq!(notes, ["r: v2 host placeholders converted to HostRegexp"]);
		assert_eq!(tr("PathPrefix(`/p/{id}`)").0.as_deref(), Some("PathRegexp(`^(?:/p/(?:[^/]+))`)"));
		assert_eq!(tr("Path(`/a-b/{id}`)").0.as_deref(), Some("PathRegexp(`^(?:/a\\-b/(?:[^/]+))$`)"));
		let (out, notes) = tr("Host(`a`) && Foo(`x`)");
		assert!(out.is_none());
		assert_eq!(notes, ["r: matcher Foo has no rproxy equivalent; router left out"]);
		// double-quoted arguments are Go strings
		assert_eq!(tr(r#"HostRegexp("^a\\.b$")"#).0.as_deref(), Some(r"HostRegexp(`^a\.b$`)"));
		assert_eq!(tr(r#"Header("X", "a`b")"#).0.as_deref(), Some("Header(`X`, \"a`b\")"));
		assert!(tr(r#"Header("X", "a`\"b")"#).0.is_none());
	}

	#[test]
	fn sni_and_hosts() {
		assert_eq!(sni_regexp_pattern(r"^.+\.Tenant\.example\.com$").as_deref(), Some("**.tenant.example.com"));
		assert_eq!(sni_regexp_pattern(r"^[^.]+\.apps\.example\.com$").as_deref(), Some("*.apps.example.com"));
		assert_eq!(sni_regexp_pattern(r"{sub:[a-z0-9-]+}.example.com").as_deref(), Some("*.example.com"));
		assert_eq!(sni_regexp_pattern(r"^(a|b)\.example\.com$"), None);
		assert_eq!(host_names("Host(`A.example`, `{x}.b`) || HostHeader(`c`)"), ["a.example", "c"]);
	}
}
