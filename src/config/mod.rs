//! Settings files written by people: YAML (`.yaml` / `.yml`) or JSON (docs/DESIGN-v0.3.md).

use serde::de::DeserializeOwned;

/// Reads YAML through a JSON value, so YAML and JSON mean exactly the same
/// (`{kind: {...}}` maps select an enum variant, as in the API).
pub fn from_yaml<T: DeserializeOwned>(text: &str) -> Result<T, String> {
	let value: serde_json::Value = serde_yaml_ng::from_str(text).map_err(|e| e.to_string())?;
	serde_json::from_value(value).map_err(|e| e.to_string())
}

/// YAML for .yaml / .yml, JSON otherwise.
pub fn from_file_text<T: DeserializeOwned>(path: &std::path::Path, text: &str) -> Result<T, String> {
	match path.extension().and_then(|e| e.to_str()) {
		Some("yaml" | "yml") => from_yaml(text),
		_ => serde_json::from_str(text).map_err(|e| e.to_string()),
	}
}

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::cidr::Cidr;
use crate::rule::RuleRequest;

/// `RPROXY_CONFIG` / `RPROXY_STATIC_RULES`: a document (`version`, `global`,
/// `rules`) or, as in 0.2, just the array of rules.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDoc {
	pub version: u32,
	#[serde(default)]
	pub global: GlobalSpec,
	#[serde(default)]
	pub rules: Vec<RuleRequest>,
	/// Where each rule came from (`file rule #n`), for messages.
	#[serde(skip)]
	pub labels: Vec<String>,
	/// The files read, in order (one unless `RPROXY_CONFIG` is a directory).
	#[serde(skip)]
	pub files: Vec<PathBuf>,
}

/// Process-wide settings (docs/DESIGN-v0.3.md 2.).
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GlobalSpec {
	/// Proxies whose X-Forwarded-For / PROXY headers are trusted (#67).
	#[serde(default)]
	pub trusted_proxies: Vec<String>,
	/// Log file for L7 requests (#57).
	pub access_log: Option<String>,
	pub acme: Option<AcmeGlobal>,
	pub crowdsec: Option<CrowdsecGlobal>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcmeGlobal {
	pub resolvers: BTreeMap<String, AcmeResolver>,
	pub storage: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcmeResolver {
	pub email: String,
	pub directory: Option<String>,
	/// http-01, tls-alpn-01 or dns-01
	pub challenge: String,
	pub dns: Option<AcmeDns>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcmeDns {
	pub provider: String,
	pub credentials_file: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CrowdsecGlobal {
	pub lapi_url: String,
	pub api_key_file: String,
	pub appsec_url: Option<String>,
	pub update_interval: Option<String>,
}

/// Why `ConfigDoc::load` failed.
#[derive(Debug)]
pub enum LoadError {
	/// A file or the directory could not be read.
	Read(PathBuf, std::io::Error),
	/// A mistake in the settings.
	Invalid(String),
}

impl std::fmt::Display for LoadError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			LoadError::Read(path, e) => write!(f, "{}: {e}", path.display()),
			LoadError::Invalid(e) => f.write_str(e),
		}
	}
}

/// The files `RPROXY_CONFIG` stands for.
pub fn config_files(path: &Path) -> std::io::Result<Vec<PathBuf>> {
	if !std::fs::metadata(path)?.is_dir() {
		return Ok(vec![path.to_path_buf()]);
	}
	let mut files = vec![];
	for entry in std::fs::read_dir(path)? {
		let entry = entry?;
		let name = entry.file_name().to_string_lossy().into_owned();
		let wanted = !name.starts_with('.') && [".yaml", ".yml", ".json"].iter().any(|ext| name.ends_with(ext));
		// follows symbolic links (Kubernetes mounts files as links into ..data)
		if wanted && std::fs::metadata(entry.path()).is_ok_and(|m| m.is_file()) {
			files.push(entry.path());
		}
	}
	files.sort();
	Ok(files)
}

/// Changes when any file of `RPROXY_CONFIG` is rewritten, added, removed or
/// swapped through a symbolic link.
pub fn fingerprint(path: &Path) -> u64 {
	match config_files(path) {
		Ok(files) => crate::tlsconf::fingerprint(files.iter().filter_map(|f| f.to_str())),
		Err(e) => crate::tlsconf::fingerprint([format!("{:?}", e.kind()).as_str()]),
	}
}

impl ConfigDoc {
	/// Reads a settings file; YAML or JSON by extension. Only the shape is
	/// checked here; the rules are validated when they are created.
	pub fn parse(path: &Path, text: &str) -> Result<ConfigDoc, String> {
		let (doc, _) = ConfigDoc::parse_unchecked(path, text)?;
		doc.check()?;
		Ok(doc)
	}

	/// Parses one file; also says whether it had a `global` section.
	fn parse_unchecked(path: &Path, text: &str) -> Result<(ConfigDoc, bool), String> {
		let value: serde_json::Value = match path.extension().and_then(|e| e.to_str()) {
			Some("yaml" | "yml") => serde_yaml_ng::from_str(text).map_err(|e| e.to_string())?,
			_ => serde_json::from_str(text).map_err(|e| e.to_string())?,
		};
		let has_global = value.get("global").is_some();
		let mut doc = if value.is_array() {
			ConfigDoc { version: 1, rules: serde_json::from_value(value).map_err(|e| format!("rules: {e}"))?, ..Default::default() }
		} else {
			serde_json::from_value::<ConfigDoc>(value).map_err(|e| e.to_string())?
		};
		let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
		doc.labels = (1..=doc.rules.len()).map(|i| format!("{name} rule #{i}")).collect();
		doc.files = vec![path.to_path_buf()];
		Ok((doc, has_global))
	}

	/// Reads `RPROXY_CONFIG`: one file, or every `*.yaml` / `*.yml` / `*.json` of a
	/// directory in name order (hidden entries skipped, so a mounted Kubernetes
	/// ConfigMap works). Rules are concatenated; `global` may be in one file only.
	pub fn load(path: &Path) -> Result<ConfigDoc, LoadError> {
		let files = config_files(path).map_err(|e| LoadError::Read(path.to_path_buf(), e))?;
		let mut merged = ConfigDoc { version: 1, ..Default::default() };
		let mut global_in: Option<PathBuf> = None;
		for file in &files {
			let text = std::fs::read_to_string(file).map_err(|e| LoadError::Read(file.clone(), e))?;
			let (doc, has_global) =
				ConfigDoc::parse_unchecked(file, &text).map_err(|e| LoadError::Invalid(format!("{}: {e}", file.display())))?;
			if doc.version != 1 {
				return Err(LoadError::Invalid(format!(
					"{}: version {} is not known (this build reads version 1)",
					file.display(),
					doc.version
				)));
			}
			if has_global {
				if let Some(first) = &global_in {
					return Err(LoadError::Invalid(format!(
						"global is in both {} and {}; put it in one file",
						first.display(),
						file.display()
					)));
				}
				global_in = Some(file.clone());
				merged.global = doc.global;
			}
			merged.rules.extend(doc.rules);
			merged.labels.extend(doc.labels);
		}
		merged.files = files;
		merged.check_duplicates().map_err(LoadError::Invalid)?;
		merged.check().map_err(|e| LoadError::Invalid(format!("{}: {e}", path.display())))?;
		Ok(merged)
	}

	/// The rules with their labels, for `Registry::load_static_labeled` / `reload_static`.
	pub fn labeled_rules(&self) -> Vec<(String, RuleRequest)> {
		self.labels.iter().cloned().zip(self.rules.iter().cloned()).collect()
	}

	fn label(&self, i: usize) -> String {
		self.labels.get(i).cloned().unwrap_or_else(|| format!("rule #{}", i + 1))
	}

	/// The same protocol, address and port twice (in one file or across files).
	fn check_duplicates(&self) -> Result<(), String> {
		let mut seen: std::collections::HashMap<(crate::rule::Protocol, std::net::SocketAddr), usize> = Default::default();
		for (i, r) in self.rules.iter().enumerate() {
			let Ok(listen) = crate::rule::parse_listen(&r.listen_addr, r.listen_port) else { continue };
			if let Some(first) = seen.insert((r.protocol, listen), i) {
				return Err(format!(
					"{} and {} both listen on {}/{listen}",
					self.label(first),
					self.label(i),
					r.protocol
				));
			}
		}
		Ok(())
	}

	/// `global` settings that differ from `other` and take effect only after a
	/// restart (the registry and the CrowdSec bouncer are built once).
	pub fn restart_needed(&self, other: &ConfigDoc) -> Vec<&'static str> {
		let (a, b) = (&self.global, &other.global);
		let mut out = vec![];
		if a.trusted_proxies != b.trusted_proxies {
			out.push("global.trusted_proxies");
		}
		if a.access_log != b.access_log {
			out.push("global.access_log");
		}
		if a.acme != b.acme {
			out.push("global.acme");
		}
		if a.crowdsec != b.crowdsec {
			out.push("global.crowdsec");
		}
		out
	}

	fn check(&self) -> Result<(), String> {
		if self.version != 1 {
			return Err(format!("version {} is not known (this build reads version 1)", self.version));
		}
		for c in &self.global.trusted_proxies {
			c.parse::<Cidr>().map_err(|e| format!("global.trusted_proxies: {}", e.message))?;
		}
		if let Some(acme) = &self.global.acme {
			for (name, r) in &acme.resolvers {
				if !["http-01", "tls-alpn-01", "dns-01"].contains(&r.challenge.as_str()) {
					return Err(format!("global.acme.resolvers.{name}: challenge must be http-01, tls-alpn-01 or dns-01"));
				}
				if (r.challenge == "dns-01") != r.dns.is_some() {
					return Err(format!("global.acme.resolvers.{name}: dns is needed with dns-01 and only then"));
				}
			}
		}
		if let Some(cs) = &self.global.crowdsec {
			if let Some(i) = &cs.update_interval {
				crate::http::parse_duration(i).map_err(|e| format!("global.crowdsec.update_interval: {e}"))?;
			}
		}
		// crowdsec middlewares need global.crowdsec (and appsec_url for appsec)
		for (i, r) in self.rules.iter().enumerate() {
			for (name, m) in r.http.iter().flat_map(|h| &h.middlewares) {
				if let crate::http::MiddlewareSpec::Crowdsec { appsec, .. } = m {
					match &self.global.crowdsec {
						None => return Err(format!("{}: middleware {name}: crowdsec needs global.crowdsec", self.label(i))),
						Some(cs) if *appsec && cs.appsec_url.is_none() => {
							return Err(format!("{}: middleware {name}: appsec needs global.crowdsec.appsec_url", self.label(i)))
						}
						_ => {}
					}
				}
			}
		}
		// acme certificates must name a resolver defined here
		let resolvers: Vec<&String> = self.global.acme.iter().flat_map(|a| a.resolvers.keys()).collect();
		for (i, r) in self.rules.iter().enumerate() {
			for c in r.tls.iter().flat_map(|t| &t.certificates) {
				if let Some(name) = &c.acme {
					if !resolvers.contains(&name) {
						return Err(format!("{}: acme resolver {name:?} is not defined in global.acme.resolvers", self.label(i)));
					}
				}
			}
		}
		Ok(())
	}

	/// Global settings present in the file that this build cannot run yet.
	pub fn unsupported_globals(&self) -> Vec<&'static str> {
		let g = &self.global;
		let mut out = vec![];
		if g.acme.is_some() {
			out.push("acme");
		}
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reads_the_0_2_array_and_the_v0_3_document_in_yaml_and_json() {
		let array = r#"[{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": 8443, "remote_addr": "127.0.0.1", "remote_port": 443}]"#;
		assert_eq!(ConfigDoc::parse(Path::new("rules.json"), array).unwrap().rules.len(), 1);
		let yaml = r#"
version: 1
global:
  trusted_proxies: [10.0.0.0/8]
  acme:
    resolvers:
      letsencrypt: {email: admin@example.com, challenge: tls-alpn-01}
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 127.0.0.1
    remote_port: 3000
    tls:
      mode: terminate
      certificates: [{acme: letsencrypt, domains: [dashboard.example.com]}]
    http:
      routes:
        - {name: ui, match: "Host(`dashboard.example.com`)", to: "http://127.0.0.1:3000"}
"#;
		let doc = ConfigDoc::parse(Path::new("rproxy.yaml"), yaml).unwrap();
		assert_eq!(doc.rules.len(), 1);
		assert_eq!(doc.unsupported_globals(), ["acme"]);
		assert!(doc.rules[0].http.is_some());
	}

	/// The examples people copy must stay valid.
	#[test]
	fn the_examples_in_the_repository_are_valid() {
		let caps = crate::rule::Caps { features: crate::rule::Features::ALL, ..Default::default() };
		let example = ConfigDoc::parse(Path::new("rproxy.example.yaml"), include_str!("../contrib/rproxy.example.yaml")).unwrap();
		for r in example.rules {
			r.validate(&caps).unwrap();
		}
		// docs/DESIGN-v0.3.md, 7.: the Traefik settings written for rproxy
		let design = include_str!("../docs/DESIGN-v0.3.md");
		let section = &design[design.find("## 7.").unwrap()..];
		let yaml = section.split("```yaml").nth(1).unwrap().split("```").next().unwrap();
		// the example refers to a resolver defined elsewhere in the document
		let yaml = yaml.replacen("version: 1", "version: 1\nglobal: {acme: {resolvers: {letsencrypt: {email: a@example.com, challenge: tls-alpn-01}}}, crowdsec: {lapi_url: 'http://127.0.0.1:8080', api_key_file: /etc/rproxy/crowdsec.key, appsec_url: 'http://127.0.0.1:7422'}}", 1);
		let doc = ConfigDoc::parse(Path::new("design.yaml"), &yaml).unwrap();
		assert_eq!(doc.rules.len(), 2);
		for r in doc.rules {
			r.validate(&caps).unwrap_or_else(|e| panic!("{}", e.message));
		}
	}

	fn dir(tag: &str) -> PathBuf {
		let d = std::env::temp_dir().join(format!("rproxy-config-{}-{tag}", std::process::id()));
		let _ = std::fs::remove_dir_all(&d);
		std::fs::create_dir_all(&d).unwrap();
		d
	}

	fn rule(port: u16) -> String {
		format!("{{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {port}, remote_addr: 127.0.0.1, remote_port: 1}}")
	}

	#[test]
	fn a_directory_of_files_is_one_document() {
		let d = dir("dir");
		std::fs::write(d.join("20-web.yaml"), format!("version: 1\nrules: [{}]\n", rule(2))).unwrap();
		std::fs::write(d.join("10-base.yml"), format!("version: 1\nglobal: {{trusted_proxies: [10.0.0.0/8]}}\nrules: [{}]\n", rule(1))).unwrap();
		std::fs::write(d.join("30-old.json"), format!("[{}]", r#"{"protocol": "udp", "listen_addr": "127.0.0.1", "listen_port": 3, "remote_addr": "127.0.0.1", "remote_port": 1}"#)).unwrap();
		std::fs::write(d.join("README.md"), "not read").unwrap();
		std::fs::write(d.join(".hidden.yaml"), "not: read").unwrap();
		let doc = ConfigDoc::load(&d).unwrap();
		assert_eq!(doc.rules.iter().map(|r| r.listen_port).collect::<Vec<_>>(), [1, 2, 3], "in name order");
		assert_eq!(doc.labels, ["10-base.yml rule #1", "20-web.yaml rule #1", "30-old.json rule #1"]);
		assert_eq!(doc.global.trusted_proxies, ["10.0.0.0/8"]);
		assert_eq!(doc.files.len(), 3);

		let before = fingerprint(&d);
		assert_eq!(fingerprint(&d), before);
		std::fs::write(d.join("40-new.yaml"), "version: 1\n").unwrap();
		assert_ne!(fingerprint(&d), before, "a new file is a change");

		// global in two files, or the same key twice, names both files
		std::fs::write(d.join("40-new.yaml"), "version: 1\nglobal: {}\n").unwrap();
		let e = ConfigDoc::load(&d).unwrap_err().to_string();
		assert!(e.contains("10-base.yml") && e.contains("40-new.yaml"), "{e}");
		std::fs::write(d.join("40-new.yaml"), format!("version: 1\nrules: [{}]\n", rule(2))).unwrap();
		let e = ConfigDoc::load(&d).unwrap_err().to_string();
		assert!(e.contains("20-web.yaml rule #1") && e.contains("40-new.yaml rule #1"), "{e}");
		std::fs::write(d.join("40-new.yaml"), "version: 3\n").unwrap();
		assert!(ConfigDoc::load(&d).unwrap_err().to_string().contains("40-new.yaml: version 3"));
		std::fs::remove_dir_all(d).unwrap();
	}

	#[test]
	fn global_changes_that_need_a_restart() {
		let a = ConfigDoc::parse(Path::new("a.yaml"), "version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}").unwrap();
		let b = ConfigDoc::parse(Path::new("b.yaml"), "version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}\nrules: []").unwrap();
		assert!(a.restart_needed(&b).is_empty());
		let c = ConfigDoc::parse(Path::new("c.yaml"), "version: 1\nglobal: {access_log: /tmp/a.log}").unwrap();
		assert_eq!(c.restart_needed(&a), ["global.trusted_proxies", "global.access_log"]);
	}

	#[test]
	fn reports_mistakes_in_the_document() {
		for (text, want) in [
			("version: 2", "version 2"),
			("version: 1\nglobal: {trusted_proxies: [nope]}", "trusted_proxies"),
			("version: 1\nglobal: {acme: {resolvers: {le: {email: a, challenge: dns-01}}}}", "dns is needed"),
			("version: 1\nglobl: {}", "unknown field"),
			(
				"version: 1\nrules: [{protocol: tcp, listen_addr: 0.0.0.0, listen_port: 443, remote_addr: a, remote_port: 1, tls: {mode: terminate, certificates: [{acme: le, domains: [a]}]}}]",
				"not defined in global.acme",
			),
			(
				"version: 1\nrules: [{protocol: tcp, listen_addr: 0.0.0.0, listen_port: 80, http: {routes: [{name: a, match: 'PathPrefix(`/`)', to: 'http://a', middlewares: [cs]}], middlewares: {cs: {crowdsec: {}}}}}]",
				"crowdsec needs global.crowdsec",
			),
			(
				"version: 1\nglobal: {crowdsec: {lapi_url: 'http://a', api_key_file: k}}\nrules: [{protocol: tcp, listen_addr: 0.0.0.0, listen_port: 80, http: {routes: [{name: a, match: 'PathPrefix(`/`)', to: 'http://a', middlewares: [cs]}], middlewares: {cs: {crowdsec: {appsec: true}}}}}]",
				"appsec needs global.crowdsec.appsec_url",
			),
		] {
			let err = ConfigDoc::parse(Path::new("x.yaml"), text).unwrap_err();
			assert!(err.contains(want), "{text}: {err}");
		}
	}
}
