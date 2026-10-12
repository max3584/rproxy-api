//! Reading Traefik's configuration: files (YAML, TOML, JSON), a directory of dynamic
//! configuration files (like the file provider), and `docker inspect` output (labels).

use std::fs;
use std::path::Path;

use regex::Regex;

use crate::value::{apply_yaml_merge, as_bool, g, py_str, Map, Value};
use crate::{NoteSink, Notes};

/// An input that cannot be read (exit code 2).
#[derive(Debug)]
pub struct InputError(pub String);

impl std::fmt::Display for InputError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for InputError {}

fn ext_of(path: &Path) -> String {
	path.extension().map(|e| format!(".{}", e.to_string_lossy().to_lowercase())).unwrap_or_default()
}

/// YAML 1.2 (serde-saphyr): `yes` / `on` stay strings, duplicate keys are refused, one-line errors. Merge keys
/// (`<<`) are kept as ordinary keys here and expanded by `apply_yaml_merge`, in PyYAML's order.
pub(crate) fn yaml_from_slice<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, String> {
	let mut options = serde_saphyr::Options::default();
	options.strict_booleans = true;
	options.with_snippet = false;
	options.merge_keys = serde_saphyr::options::MergeKeyPolicy::AsOrdinary;
	serde_saphyr::from_slice_with_options(data, options).map_err(|e| e.to_string())
}

/// Parses configuration text by its file type (`.yml`, `.yaml`, `.toml`, `.json`).
/// An empty YAML document is an empty map.
pub fn parse_text(path: &Path, data: &[u8]) -> Result<Value, InputError> {
	let shown = path.display();
	match ext_of(path).as_str() {
		".yml" | ".yaml" => {
			if data.iter().all(u8::is_ascii_whitespace) {
				return Ok(Value::Map(Map::new()));
			}
			let mut v: Value = yaml_from_slice(data).map_err(|e| InputError(format!("{shown}: {e}")))?;
			apply_yaml_merge(&mut v);
			Ok(if v.truthy() { v } else { Value::Map(Map::new()) })
		}
		".toml" => {
			let text = std::str::from_utf8(data).map_err(|e| InputError(format!("{shown}: {e}")))?;
			toml::from_str::<Value>(text).map_err(|e| InputError(format!("{shown}: {}", e.to_string().trim_end())))
		}
		".json" => serde_json::from_slice::<Value>(data).map_err(|e| InputError(format!("{shown}: {e}"))),
		_ => Err(InputError(format!("{shown}: unknown file type (use .yml, .yaml, .toml or .json)"))),
	}
}

/// Reads one configuration file.
pub fn load_file(path: &Path) -> Result<Value, InputError> {
	let data = fs::read(path).map_err(|e| InputError(format!("{}: {e}", path.display())))?;
	parse_text(path, &data)
}

/// A file, or every configuration file of a directory in name order (like the file
/// provider), merged.
pub fn load_dynamic(path: &Path) -> Result<Value, InputError> {
	if path.is_dir() {
		let mut names: Vec<String> = fs::read_dir(path)
			.map_err(|e| InputError(format!("{}: {e}", path.display())))?
			.filter_map(|e| e.ok())
			.map(|e| e.file_name().to_string_lossy().into_owned())
			.collect();
		names.sort();
		let mut merged = Value::Map(Map::new());
		for name in names {
			let p = path.join(&name);
			if name.starts_with('.') || !matches!(ext_of(&p).as_str(), ".yml" | ".yaml" | ".toml" | ".json") {
				continue;
			}
			deep_merge(&mut merged, load_file(&p)?);
		}
		return Ok(merged);
	}
	load_file(path)
}

/// Merges `other` into `into`: maps key by key, anything else replaced.
pub fn deep_merge(into: &mut Value, other: Value) {
	let Value::Map(other) = other else { return };
	if !matches!(into, Value::Map(_)) {
		*into = Value::Map(Map::new());
	}
	let Value::Map(target) = into else { unreachable!() };
	for (k, v) in other {
		match (target.get_mut(&k), v) {
			(Some(cur @ Value::Map(_)), v @ Value::Map(_)) => deep_merge(cur, v),
			(_, v) => target.insert(k, v),
		}
	}
}

/// `traefik.http.routers.x.rule=…` labels as a nested map like the file provider's.
pub fn labels_to_config(labels: &Map) -> Value {
	let index = Regex::new(r"^(.+)\[(\d+)\]$").unwrap();
	let mut root = Map::new();
	for (key, value) in labels.iter() {
		let Some(rest) = key.strip_prefix("traefik.") else { continue };
		let parts: Vec<&str> = rest.split('.').collect();
		let mut names: Vec<String> = vec![];
		for part in &parts {
			match index.captures(part) {
				Some(c) => {
					names.push(c[1].to_string());
					names.push(c[2].to_string());
				}
				None => names.push(part.to_string()),
			}
		}
		set_path(&mut root, &names, value.clone());
	}
	Value::Map(root)
}

fn set_path(cur: &mut Map, names: &[String], value: Value) {
	let (first, rest) = names.split_first().unwrap();
	if rest.is_empty() {
		cur.insert(first.clone(), value);
		return;
	}
	if !matches!(cur.get(first), Some(Value::Map(_))) {
		cur.insert(first.clone(), Value::Map(Map::new()));
	}
	set_path(cur.get_mut(first).and_then(Value::as_map_mut).unwrap(), rest, value);
}

/// Reads `docker inspect` output: the containers' Traefik labels as dynamic
/// configuration, with the container's address as the backend.
pub fn load_docker(path: &Path, notes: &mut Notes) -> Result<Value, InputError> {
	let containers = match load_file(path)? {
		Value::List(l) => l,
		other => vec![other],
	};
	let mut dynamic = Value::Map(Map::new());
	for c in &containers {
		let labels = match g(c, &["Config", "Labels"]).filter(|v| v.truthy()).or_else(|| g(c, &["Labels"])) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		let name_v = g(c, &["Name"]).filter(|v| v.truthy()).or_else(|| g(c, &["Names"])).filter(|v| v.truthy());
		let name = name_v.map_or_else(|| "container".to_string(), py_str).trim_start_matches('/').to_string();
		if !as_bool(labels.get("traefik.enable"), true) {
			continue;
		}
		let where_ = format!("docker {name}");
		let Value::Map(mut conf) = labels_to_config(&labels) else { unreachable!() };
		let mut http = match g(&Value::Map(conf.clone()), &["http"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		let mut routers = match g(&Value::Map(http.clone()), &["routers"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		let mut services = match g(&Value::Map(http.clone()), &["services"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		let networks = match g(c, &["NetworkSettings", "Networks"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		let wanted = labels.get("traefik.docker.network").filter(|v| v.truthy());
		let mut ip: Option<Value> = None;
		for (net, info) in networks.iter() {
			if let Some(w) = wanted {
				if Value::from(net) != *w {
					continue;
				}
			}
			if let Some(v) = g(info, &["IPAddress"]).filter(|v| v.truthy()) {
				ip = Some(v.clone());
			}
			if ip.is_some() {
				break;
			}
		}
		let host = ip.as_ref().map_or_else(|| name.clone(), py_str);
		if ip.is_none() {
			notes.note(&where_, &format!("no container IP in the inspect output; the backend is written as {}", crate::value::str_repr(&name)));
		}
		let mut exposed: Vec<String> = match g(c, &["Config", "ExposedPorts"]) {
			Some(Value::Map(m)) => m.keys().cloned().collect(),
			_ => vec![],
		};
		exposed.sort();
		let default_port = exposed.first().map(|p| Value::from(p.split('/').next().unwrap_or("")));
		if !routers.is_empty() && services.is_empty() {
			services = Map::new();
			services.insert(name.clone(), Value::Map(Map::new()));
		}
		let mut converted = Map::new();
		for (sname, svc) in services.iter() {
			let lb = match g(svc, &["loadBalancer"]) {
				Some(Value::Map(m)) => m.clone(),
				_ => Map::new(),
			};
			let server = match g(&Value::Map(lb.clone()), &["server"]) {
				Some(Value::Map(m)) => m.clone(),
				_ => Map::new(),
			};
			let port = server.get("port").filter(|v| v.truthy()).cloned().or_else(|| default_port.clone());
			let scheme = server.get("scheme").filter(|v| v.truthy()).map_or_else(|| "http".to_string(), py_str);
			let Some(port) = port else {
				notes.note(&where_, &format!("service {sname}: no port (loadbalancer.server.port); left out"));
				converted.insert(sname.clone(), svc.clone());
				continue;
			};
			let mut lb = lb;
			lb.remove("server");
			lb.insert("servers", vec![Value::Map(crate::value::map([("url", format!("{scheme}://{host}:{}", py_str(&port)).into())]))]);
			let mut svc = match svc {
				Value::Map(m) => m.clone(),
				_ => Map::new(),
			};
			svc.insert("loadBalancer", lb);
			converted.insert(sname.clone(), svc);
		}
		let services = converted;
		let only = (services.len() == 1).then(|| services.keys().next().unwrap().clone());
		let mut kept = Map::new();
		for (rname, r) in routers.iter_mut() {
			if !crate::value::truthy(g(r, &["service"])) {
				if let (Some(only), Value::Map(m)) = (&only, &mut *r) {
					m.insert("service", only.as_str());
				}
			}
			if !crate::value::truthy(g(r, &["rule"])) {
				notes.note(&where_, &format!("router {rname}: no rule (Traefik's defaultRule is not converted); left out"));
			} else {
				kept.insert(rname.clone(), r.clone());
			}
		}
		http.insert("routers", kept);
		http.insert("services", services);
		conf.insert("http", http);
		deep_merge(&mut dynamic, Value::Map(conf));
	}
	Ok(dynamic)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn labels() {
		let labels: Map = [
			("traefik.http.routers.a.rule".to_string(), Value::from("Host(`a`)")),
			("traefik.http.routers.a.tls.domains[0].main".to_string(), Value::from("a.example")),
			("other".to_string(), Value::from("x")),
		]
		.into_iter()
		.collect();
		let conf = labels_to_config(&labels);
		assert_eq!(g(&conf, &["http", "routers", "a", "rule"]), Some(&Value::from("Host(`a`)")));
		assert_eq!(g(&conf, &["http", "routers", "a", "tls", "domains", "0", "main"]), Some(&Value::from("a.example")));
	}

	#[test]
	fn merge() {
		let mut a = parse_text(Path::new("a.yaml"), b"x: {a: 1, b: {c: 1}}\ny: 1\n").unwrap();
		deep_merge(&mut a, parse_text(Path::new("b.yaml"), b"x: {b: {d: 2}}\ny: [1]\n").unwrap());
		assert_eq!(g(&a, &["x", "b", "d"]), Some(&Value::Int(2)));
		assert_eq!(g(&a, &["x", "b", "c"]), Some(&Value::Int(1)));
		assert_eq!(g(&a, &["y"]), Some(&Value::List(vec![Value::Int(1)])));
		assert!(parse_text(Path::new("e.yml"), b"\n").unwrap().as_map().unwrap().is_empty());
		assert!(parse_text(Path::new("e.ini"), b"").is_err());
	}
}
