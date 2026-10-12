//! The value the converter works on: what a Traefik configuration file holds (YAML,
//! TOML, JSON) and what the rproxy settings document is built from. Maps keep their
//! keys in order (the output lists them as the input and the converter wrote them),
//! and the helpers read values as loosely as Traefik (and the Python converter this
//! replaces) did: `"true"`, `"10"` and `10` all count.

use std::fmt;

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// A configuration value.
#[derive(Clone, Debug)]
pub enum Value {
	Null,
	Bool(bool),
	Int(i64),
	Float(f64),
	Str(String),
	List(Vec<Value>),
	Map(Map),
}

/// A map that keeps its keys in insertion order. Setting a key that is already there
/// replaces its value in place (like a Python dict).
#[derive(Clone, Debug, Default)]
pub struct Map(Vec<(String, Value)>);

impl Map {
	pub fn new() -> Map {
		Map(Vec::new())
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	/// The value of exactly this key.
	pub fn get(&self, key: &str) -> Option<&Value> {
		self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v)
	}

	pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
		self.0.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v)
	}

	pub fn contains_key(&self, key: &str) -> bool {
		self.get(key).is_some()
	}

	pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) {
		let key = key.into();
		let value = value.into();
		match self.get_mut(&key) {
			Some(v) => *v = value,
			None => self.0.push((key, value)),
		}
	}

	pub fn remove(&mut self, key: &str) -> Option<Value> {
		let i = self.0.iter().position(|(k, _)| k == key)?;
		Some(self.0.remove(i).1)
	}

	pub fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
		self.0.iter().map(|(k, v)| (k, v))
	}

	pub fn iter_mut(&mut self) -> impl Iterator<Item = (&String, &mut Value)> {
		self.0.iter_mut().map(|(k, v)| (&*k, v))
	}

	pub fn keys(&self) -> impl Iterator<Item = &String> {
		self.0.iter().map(|(k, _)| k)
	}

	pub fn values(&self) -> impl Iterator<Item = &Value> {
		self.0.iter().map(|(_, v)| v)
	}

	/// The first key and its value.
	pub fn first(&self) -> Option<(&String, &Value)> {
		self.0.first().map(|(k, v)| (k, v))
	}
}

impl IntoIterator for Map {
	type Item = (String, Value);
	type IntoIter = std::vec::IntoIter<(String, Value)>;
	fn into_iter(self) -> Self::IntoIter {
		self.0.into_iter()
	}
}

impl FromIterator<(String, Value)> for Map {
	fn from_iter<I: IntoIterator<Item = (String, Value)>>(iter: I) -> Map {
		let mut m = Map::new();
		for (k, v) in iter {
			m.insert(k, v);
		}
		m
	}
}

/// Maps are equal with the same entries in any order (as Python dicts).
impl PartialEq for Map {
	fn eq(&self, other: &Map) -> bool {
		self.len() == other.len() && self.iter().all(|(k, v)| other.get(k) == Some(v))
	}
}

/// Numbers compare by value (`1 == 1.0`, `true == 1`), as in Python.
impl PartialEq for Value {
	fn eq(&self, other: &Value) -> bool {
		use Value::*;
		match (self, other) {
			(Null, Null) => true,
			(Str(a), Str(b)) => a == b,
			(List(a), List(b)) => a == b,
			(Map(a), Map(b)) => a == b,
			(a, b) => match (a.number(), b.number()) {
				(Some(x), Some(y)) => x == y,
				_ => false,
			},
		}
	}
}

impl Value {
	fn number(&self) -> Option<f64> {
		match self {
			Value::Bool(b) => Some(*b as i64 as f64),
			Value::Int(i) => Some(*i as f64),
			Value::Float(f) => Some(*f),
			_ => None,
		}
	}

	pub fn as_str(&self) -> Option<&str> {
		match self {
			Value::Str(s) => Some(s),
			_ => None,
		}
	}

	pub fn as_map(&self) -> Option<&Map> {
		match self {
			Value::Map(m) => Some(m),
			_ => None,
		}
	}

	pub fn as_map_mut(&mut self) -> Option<&mut Map> {
		match self {
			Value::Map(m) => Some(m),
			_ => None,
		}
	}

	pub fn as_list(&self) -> Option<&Vec<Value>> {
		match self {
			Value::List(l) => Some(l),
			_ => None,
		}
	}

	pub fn is_null(&self) -> bool {
		matches!(self, Value::Null)
	}

	/// Python's truth value: `None`, `false`, 0, `""`, `[]` and `{}` are false.
	pub fn truthy(&self) -> bool {
		match self {
			Value::Null => false,
			Value::Bool(b) => *b,
			Value::Int(i) => *i != 0,
			Value::Float(f) => *f != 0.0,
			Value::Str(s) => !s.is_empty(),
			Value::List(l) => !l.is_empty(),
			Value::Map(m) => !m.is_empty(),
		}
	}
}

impl From<&str> for Value {
	fn from(s: &str) -> Value {
		Value::Str(s.to_string())
	}
}
impl From<String> for Value {
	fn from(s: String) -> Value {
		Value::Str(s)
	}
}
impl From<&String> for Value {
	fn from(s: &String) -> Value {
		Value::Str(s.clone())
	}
}
impl From<i64> for Value {
	fn from(i: i64) -> Value {
		Value::Int(i)
	}
}
impl From<bool> for Value {
	fn from(b: bool) -> Value {
		Value::Bool(b)
	}
}
impl From<Map> for Value {
	fn from(m: Map) -> Value {
		Value::Map(m)
	}
}
impl<T: Into<Value>> From<Vec<T>> for Value {
	fn from(l: Vec<T>) -> Value {
		Value::List(l.into_iter().map(Into::into).collect())
	}
}
impl<T: Into<Value>> From<Option<T>> for Value {
	fn from(o: Option<T>) -> Value {
		o.map_or(Value::Null, Into::into)
	}
}
impl From<&Value> for Value {
	fn from(v: &Value) -> Value {
		v.clone()
	}
}

/// A map from `(key, value)` pairs, in this order.
pub fn map<const N: usize>(pairs: [(&str, Value); N]) -> Map {
	let mut m = Map::new();
	for (k, v) in pairs {
		m.insert(k, v);
	}
	m
}

/// From serde_json's value (rproxy-gateway reads Kubernetes objects with serde_json).
/// Without serde_json's `preserve_order` its maps come sorted by key.
impl From<&serde_json::Value> for Value {
	fn from(v: &serde_json::Value) -> Value {
		match v {
			serde_json::Value::Null => Value::Null,
			serde_json::Value::Bool(b) => Value::Bool(*b),
			serde_json::Value::Number(n) => match n.as_i64() {
				Some(i) => Value::Int(i),
				None => Value::Float(n.as_f64().unwrap_or(0.0)),
			},
			serde_json::Value::String(s) => Value::Str(s.clone()),
			serde_json::Value::Array(a) => Value::List(a.iter().map(Value::from).collect()),
			serde_json::Value::Object(o) => Value::Map(o.iter().map(|(k, v)| (k.clone(), Value::from(v))).collect()),
		}
	}
}

/// To serde_json's value (key order is serde_json's).
impl From<&Value> for serde_json::Value {
	fn from(v: &Value) -> serde_json::Value {
		match v {
			Value::Null => serde_json::Value::Null,
			Value::Bool(b) => serde_json::Value::Bool(*b),
			Value::Int(i) => serde_json::Value::from(*i),
			Value::Float(f) => serde_json::Number::from_f64(*f).map_or(serde_json::Value::Null, serde_json::Value::Number),
			Value::Str(s) => serde_json::Value::String(s.clone()),
			Value::List(l) => serde_json::Value::Array(l.iter().map(serde_json::Value::from).collect()),
			Value::Map(m) => serde_json::Value::Object(m.iter().map(|(k, v)| (k.clone(), serde_json::Value::from(v))).collect()),
		}
	}
}

// ---------------------------------------------------------------- reading (serde)

impl<'de> Deserialize<'de> for Value {
	fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
		d.deserialize_any(ValueVisitor)
	}
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
	type Value = Value;

	fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_str("a configuration value")
	}

	fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
		Ok(Value::Bool(v))
	}
	fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
		Ok(Value::Int(v))
	}
	fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
		Ok(i64::try_from(v).map_or(Value::Float(v as f64), Value::Int))
	}
	fn visit_i128<E>(self, v: i128) -> Result<Value, E> {
		Ok(i64::try_from(v).map_or(Value::Float(v as f64), Value::Int))
	}
	fn visit_u128<E>(self, v: u128) -> Result<Value, E> {
		Ok(i64::try_from(v).map_or(Value::Float(v as f64), Value::Int))
	}
	fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
		Ok(Value::Float(v))
	}
	fn visit_str<E>(self, v: &str) -> Result<Value, E> {
		Ok(Value::Str(v.to_string()))
	}
	fn visit_string<E>(self, v: String) -> Result<Value, E> {
		Ok(Value::Str(v))
	}
	fn visit_bytes<E>(self, v: &[u8]) -> Result<Value, E> {
		Ok(Value::Str(String::from_utf8_lossy(v).into_owned()))
	}
	fn visit_none<E>(self) -> Result<Value, E> {
		Ok(Value::Null)
	}
	fn visit_unit<E>(self) -> Result<Value, E> {
		Ok(Value::Null)
	}
	fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
		Value::deserialize(d)
	}
	fn visit_newtype_struct<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
		Value::deserialize(d)
	}
	fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
		let mut out = Vec::new();
		while let Some(v) = seq.next_element::<Value>()? {
			out.push(v);
		}
		Ok(Value::List(out))
	}
	fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Value, A::Error> {
		let mut m = Map::new();
		while let Some((k, v)) = access.next_entry::<Value, Value>()? {
			// later keys win, as in Python's parsers
			m.insert(py_str(&k), v);
		}
		// TOML date-times come as a map with one private key
		if m.len() == 1 {
			if let Some(Value::Str(s)) = m.get("$__toml_private_datetime") {
				return Ok(Value::Str(s.clone()));
			}
		}
		Ok(Value::Map(m))
	}
}

/// YAML merge keys (`<<: *anchor`), as PyYAML applies them: the merged maps' keys
/// first (a later map of a list before an earlier one), then the map's own.
pub(crate) fn apply_yaml_merge(v: &mut Value) {
	match v {
		Value::List(l) => l.iter_mut().for_each(apply_yaml_merge),
		Value::Map(m) => {
			m.iter_mut().for_each(|(_, v)| apply_yaml_merge(v));
			let Some(merge) = m.remove("<<") else { return };
			let sources: Vec<Map> = match merge {
				Value::Map(src) => vec![src],
				Value::List(l) => l.into_iter().rev().filter_map(|v| if let Value::Map(src) = v { Some(src) } else { None }).collect(),
				other => {
					m.insert("<<", other);
					return;
				}
			};
			let mut out = Map::new();
			for src in sources {
				for (k, v) in src {
					out.insert(k, v);
				}
			}
			for (k, v) in std::mem::take(m) {
				out.insert(k, v);
			}
			*m = out;
		}
		_ => {}
	}
}

// ---------------------------------------------------------------- loose reading

/// Case-insensitive lookup through nested maps (TOML and labels differ in case): an
/// exact key first, then the first key that matches ignoring case. `null` counts as
/// missing.
pub fn g<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Value> {
	let mut cur = v;
	for key in keys {
		let Value::Map(m) = cur else { return None };
		cur = match m.get(key) {
			Some(x) => x,
			None => {
				let low = key.to_lowercase();
				m.iter().find(|(k, _)| k.to_lowercase() == low).map(|(_, x)| x)?
			}
		};
	}
	if cur.is_null() {
		None
	} else {
		Some(cur)
	}
}

/// `g` from an optional value.
pub fn go<'a>(v: Option<&'a Value>, keys: &[&str]) -> Option<&'a Value> {
	v.and_then(|v| g(v, keys))
}

/// Whether a value is there and true (Python's `if value:`).
pub fn truthy(v: Option<&Value>) -> bool {
	v.is_some_and(Value::truthy)
}

/// A list: a comma-separated string, a map of labels (`domains[0]` → `{"0": …}`, by
/// index) or a list.
pub fn as_list(v: Option<&Value>) -> Vec<Value> {
	match v {
		None | Some(Value::Null) => vec![],
		Some(Value::Str(s)) => s.split(',').map(str::trim).filter(|s| !s.is_empty()).map(Value::from).collect(),
		Some(Value::Map(m)) => {
			let mut items: Vec<(&String, &Value)> = m.iter().collect();
			items.sort_by_key(|(k, _)| {
				if !k.is_empty() && k.bytes().all(|b| b.is_ascii_digit()) {
					k.parse::<i128>().unwrap_or(i128::MAX)
				} else {
					0
				}
			});
			items.into_iter().map(|(_, v)| v.clone()).collect()
		}
		Some(Value::List(l)) => l.clone(),
		Some(other) => vec![other.clone()],
	}
}

/// `as_list` of strings (`str()` of each item).
pub fn as_str_list(v: Option<&Value>) -> Vec<String> {
	as_list(v).iter().map(py_str).collect()
}

/// A boolean: strings `true`, `1` and `yes` (any case) are true, other values by
/// Python's truth value; `default` when missing.
pub fn as_bool(v: Option<&Value>, default: bool) -> bool {
	match v {
		None | Some(Value::Null) => default,
		Some(Value::Str(s)) => matches!(s.trim().to_lowercase().as_str(), "true" | "1" | "yes"),
		Some(other) => other.truthy(),
	}
}

/// An integer (`int(float(v))` in Python: `"10"`, `"1e3"`, `2.5` → 2); `default` when
/// missing, empty or not a number.
pub fn as_int(v: Option<&Value>, default: Option<i64>) -> Option<i64> {
	let f = match v {
		None | Some(Value::Null) => return default,
		Some(Value::Str(s)) if s.is_empty() => return default,
		Some(Value::Int(i)) => return Some(*i),
		Some(Value::Bool(b)) => return Some(*b as i64),
		Some(Value::Float(f)) => *f,
		Some(Value::Str(s)) => match py_float(s) {
			Some(f) => f,
			None => return default,
		},
		Some(_) => return default,
	};
	if f.is_finite() {
		Some(f.trunc() as i64)
	} else {
		default
	}
}

/// Python's `float(str)`: surrounding whitespace and `_` between digits allowed.
pub(crate) fn py_float(s: &str) -> Option<f64> {
	let s = s.trim();
	let cleaned: String;
	let s = if s.contains('_') {
		let b = s.as_bytes();
		for (i, c) in b.iter().enumerate() {
			if *c == b'_' && !(i > 0 && i + 1 < b.len() && b[i - 1].is_ascii_digit() && b[i + 1].is_ascii_digit()) {
				return None;
			}
		}
		cleaned = s.replace('_', "");
		&cleaned
	} else {
		s
	};
	let low = s.to_ascii_lowercase();
	let body = low.trim_start_matches(['+', '-']);
	if body.starts_with("inf") || body.starts_with("nan") {
		return matches!(body, "inf" | "infinity" | "nan").then(|| s.parse::<f64>().ok()).flatten();
	}
	s.parse::<f64>().ok()
}

/// Python's `str()` of a value.
pub fn py_str(v: &Value) -> String {
	match v {
		Value::Str(s) => s.clone(),
		other => py_repr(other),
	}
}

/// `str()` of an optional value (`None` when missing).
pub fn py_str_opt(v: Option<&Value>) -> String {
	v.map_or_else(|| "None".to_string(), py_str)
}

/// Python's `repr()` of a value (as notes show values: `'10x'`, `None`).
pub fn py_repr(v: &Value) -> String {
	match v {
		Value::Null => "None".into(),
		Value::Bool(true) => "True".into(),
		Value::Bool(false) => "False".into(),
		Value::Int(i) => i.to_string(),
		Value::Float(f) => float_repr(*f),
		Value::Str(s) => str_repr(s),
		Value::List(l) => format!("[{}]", l.iter().map(py_repr).collect::<Vec<_>>().join(", ")),
		Value::Map(m) => {
			format!("{{{}}}", m.iter().map(|(k, v)| format!("{}: {}", str_repr(k), py_repr(v))).collect::<Vec<_>>().join(", "))
		}
	}
}

/// `repr()` of an optional value.
pub fn py_repr_opt(v: Option<&Value>) -> String {
	v.map_or_else(|| "None".to_string(), py_repr)
}

/// Whether Python's `str.isprintable()` holds for one character (close enough: control
/// and format characters, separators other than the space, unassigned surrogates).
fn printable(c: char) -> bool {
	!(c.is_control()
		|| matches!(c, '\u{a0}' | '\u{ad}' | '\u{1680}' | '\u{2000}'..='\u{200f}' | '\u{2028}'..='\u{202f}' | '\u{205f}'..='\u{206f}' | '\u{3000}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}'))
}

/// Python's `repr()` of a string.
pub fn str_repr(s: &str) -> String {
	let quote = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
	let mut out = String::with_capacity(s.len() + 2);
	out.push(quote);
	for c in s.chars() {
		match c {
			'\\' => out.push_str("\\\\"),
			'\t' => out.push_str("\\t"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			c if c == quote => {
				out.push('\\');
				out.push(c);
			}
			c if !printable(c) => {
				let n = c as u32;
				if n <= 0xff {
					out.push_str(&format!("\\x{n:02x}"));
				} else if n <= 0xffff {
					out.push_str(&format!("\\u{n:04x}"));
				} else {
					out.push_str(&format!("\\U{n:08x}"));
				}
			}
			c => out.push(c),
		}
	}
	out.push(quote);
	out
}

/// Python's `repr()` of a float: the shortest form that reads back, `1.0`, `1e+16`,
/// `1.5e-05`.
pub fn float_repr(f: f64) -> String {
	if f.is_nan() {
		return "nan".into();
	}
	if f.is_infinite() {
		return if f > 0.0 { "inf".into() } else { "-inf".into() };
	}
	let sci = format!("{f:e}");
	let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
	let exp: i32 = exp.parse().unwrap_or(0);
	let (sign, mantissa) = match mantissa.strip_prefix('-') {
		Some(m) => ("-", m),
		None => ("", mantissa),
	};
	let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
	if (-4..16).contains(&exp) {
		let n = digits.len() as i32;
		let body = if exp >= 0 {
			if n <= exp + 1 {
				format!("{digits}{}.0", "0".repeat((exp + 1 - n) as usize))
			} else {
				format!("{}.{}", &digits[..(exp + 1) as usize], &digits[(exp + 1) as usize..])
			}
		} else {
			format!("0.{}{digits}", "0".repeat((-exp - 1) as usize))
		};
		format!("{sign}{body}")
	} else {
		let m = if digits.len() > 1 { format!("{}.{}", &digits[..1], &digits[1..]) } else { digits };
		format!("{sign}{m}e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs())
	}
}

/// A name without its provider (`auth@docker` → `auth`).
pub fn strip_provider(name: &str) -> String {
	name.split('@').next().unwrap_or(name).to_string()
}

/// The provider of a name (`api@internal` → `internal`), or empty.
pub fn provider_of(name: &str) -> String {
	name.split_once('@').map(|(_, p)| p.to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn python_like_reading() {
		assert_eq!(as_int(Some(&Value::from("10")), None), Some(10));
		assert_eq!(as_int(Some(&Value::from(" 1e3 ")), None), Some(1000));
		assert_eq!(as_int(Some(&Value::Float(2.9)), None), Some(2));
		assert_eq!(as_int(Some(&Value::from("x")), Some(1)), Some(1));
		assert_eq!(as_int(Some(&Value::from("")), Some(7)), Some(7));
		assert_eq!(as_int(Some(&Value::from("1_000")), None), Some(1000));
		assert_eq!(as_int(Some(&Value::from("inf")), Some(3)), Some(3));
		assert!(as_bool(Some(&Value::from("Yes")), false));
		assert!(!as_bool(Some(&Value::from("on")), true));
		assert!(as_bool(None, true));
		let l = as_list(Some(&Value::Map(map([("1", "b".into()), ("0", "a".into()), ("10", "c".into())]))));
		assert_eq!(l, vec![Value::from("a"), Value::from("b"), Value::from("c")]);
		assert_eq!(as_str_list(Some(&Value::from(" a, ,b "))), ["a", "b"]);
	}

	#[test]
	fn python_repr() {
		assert_eq!(str_repr("10x"), "'10x'");
		assert_eq!(str_repr("it's"), "\"it's\"");
		assert_eq!(str_repr("a'\"b"), "'a\\'\"b'");
		assert_eq!(str_repr("t\tµ\u{7f}"), "'t\\tµ\\x7f'");
		assert_eq!(float_repr(1.0), "1.0");
		assert_eq!(float_repr(0.3), "0.3");
		assert_eq!(float_repr(1e16), "1e+16");
		assert_eq!(float_repr(1.5e-5), "1.5e-05");
		assert_eq!(float_repr(123456.789), "123456.789");
		assert_eq!(float_repr(-0.0001), "-0.0001");
		assert_eq!(py_repr(&Value::Null), "None");
	}

	#[test]
	fn case_insensitive_lookup() {
		let v = Value::Map(map([("HTTP", Value::Map(map([("Routers", Value::Int(1))])))]));
		assert_eq!(g(&v, &["http", "routers"]), Some(&Value::Int(1)));
		assert_eq!(g(&v, &["http", "x"]), None);
	}

	#[test]
	fn merge_keys() {
		let mut v: Value = serde_yaml_ng::from_str("base: &b {a: 1, b: 2}\nx:\n  <<: *b\n  b: 3\n  c: 4\n").unwrap();
		apply_yaml_merge(&mut v);
		let x = g(&v, &["x"]).unwrap().as_map().unwrap();
		assert_eq!(x.keys().collect::<Vec<_>>(), ["a", "b", "c"]);
		assert_eq!(x.get("b"), Some(&Value::Int(3)));
	}
}
