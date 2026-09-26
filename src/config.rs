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
}

/// Process-wide settings (docs/DESIGN-v0.3.md 2.).
#[derive(Debug, Default, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeGlobal {
	pub resolvers: BTreeMap<String, AcmeResolver>,
	pub storage: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeResolver {
	pub email: String,
	pub directory: Option<String>,
	/// http-01, tls-alpn-01 or dns-01
	pub challenge: String,
	pub dns: Option<AcmeDns>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeDns {
	pub provider: String,
	pub credentials_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrowdsecGlobal {
	pub lapi_url: String,
	pub api_key_file: String,
	pub appsec_url: Option<String>,
	pub update_interval: Option<String>,
}

impl ConfigDoc {
	/// Reads a settings file; YAML or JSON by extension. Only the shape is
	/// checked here; the rules are validated when they are created.
	pub fn parse(path: &std::path::Path, text: &str) -> Result<ConfigDoc, String> {
		let value: serde_json::Value = match path.extension().and_then(|e| e.to_str()) {
			Some("yaml" | "yml") => serde_yaml_ng::from_str(text).map_err(|e| e.to_string())?,
			_ => serde_json::from_str(text).map_err(|e| e.to_string())?,
		};
		let doc = if value.is_array() {
			ConfigDoc { version: 1, rules: serde_json::from_value(value).map_err(|e| format!("rules: {e}"))?, ..Default::default() }
		} else {
			serde_json::from_value::<ConfigDoc>(value).map_err(|e| e.to_string())?
		};
		doc.check()?;
		Ok(doc)
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
		// acme certificates must name a resolver defined here
		let resolvers: Vec<&String> = self.global.acme.iter().flat_map(|a| a.resolvers.keys()).collect();
		for (i, r) in self.rules.iter().enumerate() {
			for c in r.tls.iter().flat_map(|t| &t.certificates) {
				if let Some(name) = &c.acme {
					if !resolvers.contains(&name) {
						return Err(format!("rule #{}: acme resolver {name:?} is not defined in global.acme.resolvers", i + 1));
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
		if !g.trusted_proxies.is_empty() {
			out.push("trusted_proxies");
		}
		if g.access_log.is_some() {
			out.push("access_log");
		}
		if g.acme.is_some() {
			out.push("acme");
		}
		if g.crowdsec.is_some() {
			out.push("crowdsec");
		}
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::path::Path;

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
		assert_eq!(doc.unsupported_globals(), ["trusted_proxies", "acme"]);
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
		let yaml = yaml.replacen("version: 1", "version: 1\nglobal: {acme: {resolvers: {letsencrypt: {email: a@example.com, challenge: tls-alpn-01}}}}", 1);
		let doc = ConfigDoc::parse(Path::new("design.yaml"), &yaml).unwrap();
		assert_eq!(doc.rules.len(), 2);
		for r in doc.rules {
			r.validate(&caps).unwrap_or_else(|e| panic!("{}", e.message));
		}
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
		] {
			let err = ConfigDoc::parse(Path::new("x.yaml"), text).unwrap_err();
			assert!(err.contains(want), "{text}: {err}");
		}
	}
}
