//! Writing the settings document: YAML as PyYAML's `safe_dump(sort_keys=False,
//! allow_unicode=True, default_flow_style=False, width=200)` writes it (the output of
//! the Python converter this replaces, kept byte for byte), and JSON as Python's
//! `json.dumps(indent=2, ensure_ascii=False)`.
//!
//! The YAML writer follows PyYAML's emitter for what a settings document holds
//! (block maps and lists, `{}` / `[]` when empty, scalars): the same choice of plain,
//! single- or double-quoted scalars (YAML 1.1 resolution: `'yes'`, `'1.0'` and
//! `'*.example.com'` are quoted), the same indentation and the same folding of long
//! lines.

use std::sync::LazyLock;

use regex::Regex;

use crate::value::{float_repr, Map, Value};

const BEST_INDENT: usize = 2;
const BEST_WIDTH: usize = 200;

/// The document as YAML.
pub fn to_yaml(v: &Value) -> String {
	let mut w = Yaml { out: String::new(), column: 0, whitespace: true, indention: true, indent: None };
	w.node(v, Ctx::Root);
	// the document end
	w.write_indent();
	w.out
}

#[derive(Clone, Copy, PartialEq)]
enum Ctx {
	Root,
	MapValue,
	SeqItem,
	SimpleKey,
	ComplexKey,
}

struct Yaml {
	out: String,
	column: usize,
	whitespace: bool,
	indention: bool,
	indent: Option<usize>,
}

/// What the emitter may do with one scalar (PyYAML's `analyze_scalar`).
struct Analysis {
	empty: bool,
	multiline: bool,
	allow_block_plain: bool,
	allow_single_quoted: bool,
}

fn is_break(c: char) -> bool {
	matches!(c, '\n' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

fn is_space_or_break(c: Option<char>) -> bool {
	matches!(c, None | Some('\0' | ' ' | '\t' | '\r' | '\n' | '\u{85}' | '\u{2028}' | '\u{2029}'))
}

fn analyze(scalar: &str) -> Analysis {
	if scalar.is_empty() {
		return Analysis { empty: true, multiline: false, allow_block_plain: true, allow_single_quoted: true };
	}
	let chars: Vec<char> = scalar.chars().collect();
	let mut block_indicators = false;
	let mut line_breaks = false;
	let mut special = false;
	let (mut leading_space, mut leading_break, mut trailing_space, mut trailing_break) = (false, false, false, false);
	let (mut break_space, mut space_break) = (false, false);
	if scalar.starts_with("---") || scalar.starts_with("...") {
		block_indicators = true;
	}
	let mut preceded_by_ws = true;
	let mut followed_by_ws = chars.len() == 1 || is_space_or_break(chars.get(1).copied());
	let (mut previous_space, mut previous_break) = (false, false);
	for (index, &ch) in chars.iter().enumerate() {
		if index == 0 {
			if "#,[]{}&*!|>'\"%@`".contains(ch) {
				block_indicators = true;
			}
			if (ch == '?' || ch == ':') && followed_by_ws {
				block_indicators = true;
			}
			if ch == '-' && followed_by_ws {
				block_indicators = true;
			}
		} else {
			if ch == ':' && followed_by_ws {
				block_indicators = true;
			}
			if ch == '#' && preceded_by_ws {
				block_indicators = true;
			}
		}
		if is_break(ch) {
			line_breaks = true;
		}
		if !(ch == '\n' || ('\x20'..='\x7e').contains(&ch)) {
			let unicode = (ch == '\u{85}'
				|| ('\u{a0}'..='\u{d7ff}').contains(&ch)
				|| ('\u{e000}'..='\u{fffd}').contains(&ch)
				|| ('\u{10000}'..'\u{10ffff}').contains(&ch))
				&& ch != '\u{feff}';
			if !unicode {
				special = true;
			}
		}
		if ch == ' ' {
			if index == 0 {
				leading_space = true;
			}
			if index == chars.len() - 1 {
				trailing_space = true;
			}
			if previous_break {
				break_space = true;
			}
			previous_space = true;
			previous_break = false;
		} else if is_break(ch) {
			if index == 0 {
				leading_break = true;
			}
			if index == chars.len() - 1 {
				trailing_break = true;
			}
			if previous_space {
				space_break = true;
			}
			previous_space = false;
			previous_break = true;
		} else {
			previous_space = false;
			previous_break = false;
		}
		preceded_by_ws = is_space_or_break(Some(ch));
		followed_by_ws = index + 2 >= chars.len() || is_space_or_break(chars.get(index + 2).copied());
	}
	let mut allow_block_plain = true;
	let mut allow_single_quoted = true;
	if leading_space || leading_break || trailing_space || trailing_break {
		allow_block_plain = false;
	}
	if break_space {
		allow_block_plain = false;
		allow_single_quoted = false;
	}
	if space_break || special {
		allow_block_plain = false;
		allow_single_quoted = false;
	}
	if line_breaks {
		allow_block_plain = false;
	}
	if block_indicators {
		allow_block_plain = false;
	}
	Analysis { empty: false, multiline: line_breaks, allow_block_plain, allow_single_quoted }
}

/// Whether a plain scalar reads back as this string (YAML 1.1, PyYAML's resolver):
/// not a boolean, number, null, timestamp, `<<` or `=`.
fn plain_is_str(s: &str) -> bool {
	static IMPLICIT: LazyLock<Vec<Regex>> = LazyLock::new(|| {
		[
			r"^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)$",
			r"^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9][0-9_]*(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$",
			r"^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)$",
			r"^(?:<<)$",
			r"^(?:~|null|Null|NULL|)$",
			r"^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)$",
			r"^(?:=)$",
		]
		.iter()
		.map(|r| Regex::new(r).unwrap())
		.collect()
	});
	// Python's `$` also matches before a final newline
	let s = s.strip_suffix('\n').unwrap_or(s);
	!IMPLICIT.iter().any(|r| r.is_match(s))
}

impl Yaml {
	fn write(&mut self, data: &str) {
		self.column += data.chars().count();
		self.out.push_str(data);
	}

	fn line_break(&mut self) {
		self.out.push('\n');
		self.whitespace = true;
		self.indention = true;
		self.column = 0;
	}

	fn write_indent(&mut self) {
		let indent = self.indent.unwrap_or(0);
		if !self.indention || self.column > indent || (self.column == indent && !self.whitespace) {
			self.line_break();
		}
		if self.column < indent {
			self.whitespace = true;
			let pad = " ".repeat(indent - self.column);
			self.write(&pad);
		}
	}

	fn write_indicator(&mut self, indicator: &str, need_whitespace: bool, whitespace: bool, indention: bool) {
		if self.whitespace || !need_whitespace {
			self.write(indicator);
		} else {
			self.write(&format!(" {indicator}"));
		}
		self.whitespace = whitespace;
		self.indention = self.indention && indention;
	}

	fn increase_indent(&mut self, flow: bool, indentless: bool) -> Option<usize> {
		let saved = self.indent;
		self.indent = match self.indent {
			None => Some(if flow { BEST_INDENT } else { 0 }),
			Some(i) if !indentless => Some(i + BEST_INDENT),
			Some(i) => Some(i),
		};
		saved
	}

	fn node(&mut self, v: &Value, ctx: Ctx) {
		match v {
			Value::Map(m) if !m.is_empty() => self.block_map(m),
			Value::List(l) if !l.is_empty() => self.block_seq(l, ctx),
			Value::Map(_) => self.empty_flow("{", "}"),
			Value::List(_) => self.empty_flow("[", "]"),
			Value::Null => self.scalar("null", false, ctx),
			Value::Bool(b) => self.scalar(if *b { "true" } else { "false" }, false, ctx),
			Value::Int(i) => self.scalar(&i.to_string(), false, ctx),
			Value::Float(f) => self.scalar(&yaml_float(*f), false, ctx),
			Value::Str(s) => self.scalar(s, true, ctx),
		}
	}

	fn empty_flow(&mut self, open: &str, close: &str) {
		self.write_indicator(open, true, true, false);
		self.write_indicator(close, false, false, false);
	}

	fn block_map(&mut self, m: &Map) {
		let saved = self.increase_indent(false, false);
		for (k, v) in m.iter() {
			self.write_indent();
			let a = analyze(k);
			// PyYAML counts the tag (`!!str`) too
			if k.chars().count() + 5 < 128 && !a.empty && !a.multiline {
				self.node(&Value::Str(k.clone()), Ctx::SimpleKey);
				self.write_indicator(":", false, false, false);
			} else {
				self.write_indicator("?", true, false, true);
				self.node(&Value::Str(k.clone()), Ctx::ComplexKey);
				self.write_indent();
				self.write_indicator(":", true, false, true);
			}
			self.node(v, Ctx::MapValue);
		}
		self.indent = saved;
	}

	fn block_seq(&mut self, l: &[Value], ctx: Ctx) {
		let mapping_context = matches!(ctx, Ctx::MapValue | Ctx::SimpleKey | Ctx::ComplexKey);
		let saved = self.increase_indent(false, mapping_context && !self.indention);
		for item in l {
			self.write_indent();
			self.write_indicator("-", true, false, true);
			self.node(item, Ctx::SeqItem);
		}
		self.indent = saved;
	}

	fn scalar(&mut self, text: &str, is_str: bool, ctx: Ctx) {
		let saved = self.increase_indent(true, false);
		let simple_key = ctx == Ctx::SimpleKey;
		let a = analyze(text);
		let implicit = !is_str || plain_is_str(text);
		let split = !simple_key;
		if implicit && !(simple_key && (a.empty || a.multiline)) && a.allow_block_plain {
			self.write_plain(text, split);
		} else if a.allow_single_quoted && !(simple_key && a.multiline) {
			self.write_single_quoted(text, split);
		} else {
			self.write_double_quoted(text, split);
		}
		self.indent = saved;
	}

	fn write_plain(&mut self, text: &str, split: bool) {
		if text.is_empty() {
			return;
		}
		if !self.whitespace {
			self.write(" ");
		}
		self.whitespace = false;
		self.indention = false;
		let chars: Vec<char> = text.chars().collect();
		let (mut spaces, mut breaks) = (false, false);
		let (mut start, mut end) = (0, 0);
		while end <= chars.len() {
			let ch = chars.get(end).copied();
			if spaces {
				if ch != Some(' ') {
					if start + 1 == end && self.column > BEST_WIDTH && split {
						self.write_indent();
						self.whitespace = false;
						self.indention = false;
					} else {
						let data: String = chars[start..end].iter().collect();
						self.write(&data);
					}
					start = end;
				}
			} else if breaks {
				if !ch.is_some_and(is_break) {
					if chars[start] == '\n' {
						self.line_break();
					}
					for &br in &chars[start..end] {
						if br == '\n' {
							self.line_break();
						} else {
							self.out.push(br);
							self.whitespace = true;
							self.indention = true;
							self.column = 0;
						}
					}
					self.write_indent();
					self.whitespace = false;
					self.indention = false;
					start = end;
				}
			} else if ch.is_none_or(|c| c == ' ' || is_break(c)) {
				let data: String = chars[start..end].iter().collect();
				self.write(&data);
				start = end;
			}
			if let Some(c) = ch {
				spaces = c == ' ';
				breaks = is_break(c);
			}
			end += 1;
		}
	}

	fn write_single_quoted(&mut self, text: &str, split: bool) {
		self.write_indicator("'", true, false, false);
		let chars: Vec<char> = text.chars().collect();
		let (mut spaces, mut breaks) = (false, false);
		let (mut start, mut end) = (0, 0);
		while end <= chars.len() {
			let ch = chars.get(end).copied();
			if spaces {
				if ch != Some(' ') {
					if start + 1 == end && self.column > BEST_WIDTH && split && start != 0 && end != chars.len() {
						self.write_indent();
					} else {
						let data: String = chars[start..end].iter().collect();
						self.write(&data);
					}
					start = end;
				}
			} else if breaks {
				if !ch.is_some_and(is_break) {
					if chars[start] == '\n' {
						self.line_break();
					}
					for &br in &chars[start..end] {
						if br == '\n' {
							self.line_break();
						} else {
							self.out.push(br);
							self.whitespace = true;
							self.indention = true;
							self.column = 0;
						}
					}
					self.write_indent();
					start = end;
				}
			} else if ch.is_none_or(|c| c == ' ' || is_break(c) || c == '\'') && start < end {
				let data: String = chars[start..end].iter().collect();
				self.write(&data);
				start = end;
			}
			if ch == Some('\'') {
				self.write("''");
				start = end + 1;
			}
			if let Some(c) = ch {
				spaces = c == ' ';
				breaks = is_break(c);
			}
			end += 1;
		}
		self.write_indicator("'", false, false, false);
	}

	fn write_double_quoted(&mut self, text: &str, split: bool) {
		self.write_indicator("\"", true, false, false);
		let chars: Vec<char> = text.chars().collect();
		let (mut start, mut end) = (0, 0);
		while end <= chars.len() {
			let ch = chars.get(end).copied();
			let escape = match ch {
				None => true,
				Some(c) => {
					"\"\\\u{85}\u{2028}\u{2029}\u{feff}".contains(c)
						|| !(('\x20'..='\x7e').contains(&c) || ('\u{a0}'..='\u{d7ff}').contains(&c) || ('\u{e000}'..='\u{fffd}').contains(&c))
				}
			};
			if escape {
				if start < end {
					let data: String = chars[start..end].iter().collect();
					self.write(&data);
					start = end;
				}
				if let Some(c) = ch {
					let data = match c {
						'\0' => "\\0".to_string(),
						'\x07' => "\\a".into(),
						'\x08' => "\\b".into(),
						'\x09' => "\\t".into(),
						'\x0a' => "\\n".into(),
						'\x0b' => "\\v".into(),
						'\x0c' => "\\f".into(),
						'\x0d' => "\\r".into(),
						'\x1b' => "\\e".into(),
						'"' => "\\\"".into(),
						'\\' => "\\\\".into(),
						'\u{85}' => "\\N".into(),
						'\u{a0}' => "\\_".into(),
						'\u{2028}' => "\\L".into(),
						'\u{2029}' => "\\P".into(),
						c if (c as u32) <= 0xff => format!("\\x{:02X}", c as u32),
						c if (c as u32) <= 0xffff => format!("\\u{:04X}", c as u32),
						c => format!("\\U{:08X}", c as u32),
					};
					self.write(&data);
					start = end + 1;
				}
			}
			if end > 0
				&& end + 1 < chars.len()
				&& (ch == Some(' ') || start >= end)
				&& self.column as isize + end as isize - start as isize > BEST_WIDTH as isize
				&& split
			{
				let mut data: String = chars[start.min(end)..end].iter().collect();
				data.push('\\');
				if start < end {
					start = end;
				}
				self.write(&data);
				self.write_indent();
				self.whitespace = false;
				self.indention = false;
				if chars.get(start) == Some(&' ') {
					self.write("\\");
				}
			}
			end += 1;
		}
		self.write_indicator("\"", false, false, false);
	}
}

/// PyYAML's float: `repr()`, lower case, `1.0e+16` rather than `1e+16`.
fn yaml_float(f: f64) -> String {
	if f.is_nan() {
		return ".nan".into();
	}
	if f.is_infinite() {
		return if f > 0.0 { ".inf".into() } else { "-.inf".into() };
	}
	let r = float_repr(f).to_lowercase();
	if !r.contains('.') && r.contains('e') {
		r.replacen('e', ".0e", 1)
	} else {
		r
	}
}

/// The document as JSON, indented by 2 (Python's `json.dumps(indent=2,
/// ensure_ascii=False)`), with a final newline.
pub fn to_json(v: &Value) -> String {
	let mut out = String::new();
	json_value(v, 0, &mut out);
	out.push('\n');
	out
}

fn json_value(v: &Value, level: usize, out: &mut String) {
	match v {
		Value::Null => out.push_str("null"),
		Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
		Value::Int(i) => out.push_str(&i.to_string()),
		Value::Float(f) if f.is_nan() => out.push_str("NaN"),
		Value::Float(f) if f.is_infinite() => out.push_str(if *f > 0.0 { "Infinity" } else { "-Infinity" }),
		Value::Float(f) => out.push_str(&float_repr(*f)),
		Value::Str(s) => json_str(s, out),
		Value::List(l) if l.is_empty() => out.push_str("[]"),
		Value::Map(m) if m.is_empty() => out.push_str("{}"),
		Value::List(l) => {
			out.push('[');
			for (i, item) in l.iter().enumerate() {
				out.push_str(if i == 0 { "\n" } else { ",\n" });
				out.push_str(&"  ".repeat(level + 1));
				json_value(item, level + 1, out);
			}
			out.push('\n');
			out.push_str(&"  ".repeat(level));
			out.push(']');
		}
		Value::Map(m) => {
			out.push('{');
			for (i, (k, item)) in m.iter().enumerate() {
				out.push_str(if i == 0 { "\n" } else { ",\n" });
				out.push_str(&"  ".repeat(level + 1));
				json_str(k, out);
				out.push_str(": ");
				json_value(item, level + 1, out);
			}
			out.push('\n');
			out.push_str(&"  ".repeat(level));
			out.push('}');
		}
	}
}

fn json_str(s: &str, out: &mut String) {
	out.push('"');
	for c in s.chars() {
		match c {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			'\t' => out.push_str("\\t"),
			'\x08' => out.push_str("\\b"),
			'\x0c' => out.push_str("\\f"),
			c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
			c => out.push(c),
		}
	}
	out.push('"');
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::value::map;

	#[test]
	fn yaml_like_pyyaml() {
		let doc = Value::Map(map([
			("version", Value::Int(1)),
			("names", vec!["*.example.com", "yes", "1.0", "a: b", "plain", "", "it's", "Host(`a`)", "10"].into()),
			("empty", Value::Map(Map::new())),
			("none", Value::List(vec![])),
			("nested", Value::List(vec![Value::Map(map([("a", 1.into()), ("b", Value::List(vec![2.into()]))])), Value::List(vec!["x".into()])])),
			("tab", "a\tb".into()),
			("multi", "a\nb".into()),
			("null", Value::Null),
			("f", Value::Float(1e16)),
		]));
		assert_eq!(
			to_yaml(&doc),
			"version: 1\nnames:\n- '*.example.com'\n- 'yes'\n- '1.0'\n- 'a: b'\n- plain\n- ''\n- it's\n- Host(`a`)\n- '10'\nempty: {}\nnone: []\nnested:\n- a: 1\n  b:\n  - 2\n- - x\ntab: \"a\\tb\"\nmulti: 'a\n\n  b'\n'null': null\nf: 1.0e+16\n"
		);
	}

	#[test]
	fn json_like_python() {
		let doc = Value::Map(map([("a", Value::List(vec![1.into(), Value::Map(Map::new())])), ("b", "µ\"\u{1}".into())]));
		assert_eq!(to_json(&doc), "{\n  \"a\": [\n    1,\n    {}\n  ],\n  \"b\": \"µ\\\"\\u0001\"\n}\n");
	}
}
