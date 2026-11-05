//! The Prometheus text format of `GET /metrics`.

use std::borrow::Cow;

/// A label value as the text format writes it between `"`: `\`, `"` and a line feed
/// escaped (#358). Every label of `GET /metrics` goes through this, so a name in a
/// rule (a route, a middleware, a file) cannot end a sample or add one.
pub fn label(s: &str) -> Cow<'_, str> {
	if !s.contains(['\\', '"', '\n']) {
		return Cow::Borrowed(s);
	}
	let mut out = String::with_capacity(s.len() + 8);
	for c in s.chars() {
		match c {
			'\\' => out.push_str("\\\\"),
			'"' => out.push_str("\\\""),
			'\n' => out.push_str("\\n"),
			c => out.push(c),
		}
	}
	Cow::Owned(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn label_values_are_escaped() {
		assert_eq!(label("plain/name"), "plain/name");
		assert!(matches!(label("plain"), Cow::Borrowed(_)));
		assert_eq!(label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
		assert_eq!(label("x\"} 1\nrproxy_fake 1"), "x\\\"} 1\\nrproxy_fake 1");
	}
}
