//! DNS-01: writing and removing the TXT record through a DNS provider
//! (`global.acme.dns_providers`): the PowerDNS HTTP API, or a generic REST
//! template. Secrets are read from files when a call is made and never logged;
//! error texts from a provider are cut short and have the secret masked.
//!
//! Every record is noted in a journal (`dns-pending.json`) before it is
//! written and taken out once it is removed, so records left by a crash or a
//! failed removal are removed after a restart.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use hyper::{Method, Request};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::config::{normalize_name, DnsProviderSpec, HttpCallSpec};
use super::dnsq;
use super::http;

const DEFAULT_TTL: u32 = 60;

/// One provider, ready to call.
pub struct Provider {
	pub name: String,
	spec: DnsProviderSpec,
	tls: tokio_rustls::TlsConnector,
}

/// A TXT record rproxy wrote (or is about to): enough to remove it later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Written {
	pub provider: String,
	/// Where the record is (after following CNAMEs), without the final dot.
	pub fqdn: String,
	pub zone: String,
	pub value: String,
}

fn read_secret(file: &str) -> Result<String, String> {
	std::fs::read_to_string(file).map(|s| s.trim().to_string()).map_err(|e| format!("{file}: {e}"))
}

/// Replaces `{fqdn}`, `{value}`, `{zone}` and `{secret}`.
fn fill(template: &str, w: &Written, secret: &str) -> String {
	template.replace("{fqdn}", &w.fqdn).replace("{value}", &w.value).replace("{zone}", &w.zone).replace("{secret}", secret)
}

/// A provider's answer for an error message: short, without the secret.
fn excerpt(body: &[u8], secret: &str) -> String {
	let mut text: String = String::from_utf8_lossy(body).chars().take(200).collect();
	if !secret.is_empty() {
		text = text.replace(secret, "***");
	}
	text.replace(['\n', '\r'], " ")
}

impl Provider {
	pub fn new(name: &str, spec: &DnsProviderSpec) -> Result<Provider, String> {
		Ok(Provider { name: name.to_string(), spec: spec.clone(), tls: http::connector(spec.ca_file.as_deref())? })
	}

	pub fn kind(&self) -> &str {
		&self.spec.kind
	}

	pub fn zones(&self) -> &[String] {
		&self.spec.zones
	}

	pub fn allowed_names(&self) -> &[String] {
		&self.spec.allowed_names
	}

	/// Secret files this provider reads (for `--check-config`'s readability warnings).
	pub fn secret_files(spec: &DnsProviderSpec) -> Vec<String> {
		[&spec.api_key_file, &spec.secret_file, &spec.ca_file].into_iter().flatten().cloned().collect()
	}

	/// The zone a record goes into: the longest of `zones` that holds it; or
	/// (without `zones`) PowerDNS's own list of zones, or the SOA in DNS.
	pub async fn zone_for(&self, fqdn: &str, servers: &[SocketAddr]) -> Result<String, String> {
		let within = |zone: &str| fqdn == zone || fqdn.ends_with(&format!(".{zone}"));
		if !self.spec.zones.is_empty() {
			return self
				.spec
				.zones
				.iter()
				.map(|z| normalize_name(z))
				.filter(|z| within(z))
				.max_by_key(|z| z.len())
				.ok_or_else(|| format!("{fqdn} is not in the zones of dns provider {:?} ({})", self.name, self.spec.zones.join(", ")));
		}
		if self.spec.kind == "powerdns" {
			let zones = self.powerdns_zones().await?;
			return zones
				.into_iter()
				.filter(|z| within(z))
				.max_by_key(|z| z.len())
				.ok_or_else(|| format!("{fqdn}: no zone on the PowerDNS server of dns provider {:?} holds it", self.name));
		}
		dnsq::find_zone(servers, fqdn).await
	}

	fn powerdns_base(&self) -> String {
		let base = self.spec.api_url.as_deref().unwrap_or_default().trim_end_matches('/');
		let server = self.spec.server_id.as_deref().unwrap_or("localhost");
		format!("{base}/api/v1/servers/{server}")
	}

	async fn powerdns(&self, method: Method, url: String, body: Option<serde_json::Value>) -> Result<Bytes, String> {
		let key = read_secret(self.spec.api_key_file.as_deref().unwrap_or_default())?;
		let mut req = Request::builder().method(method).uri(&url).header("X-API-Key", &key).header("Accept", "application/json");
		if body.is_some() {
			req = req.header("Content-Type", "application/json");
		}
		let body = body.map(|b| Bytes::from(b.to_string())).unwrap_or_default();
		let req = req.body(body).map_err(|e| e.to_string())?;
		let resp = http::send(&self.tls, req).await?;
		if !resp.status().is_success() {
			return Err(format!("PowerDNS {url}: {} {}", resp.status(), excerpt(resp.body(), &key)));
		}
		Ok(resp.into_body())
	}

	async fn powerdns_zones(&self) -> Result<Vec<String>, String> {
		let body = self.powerdns(Method::GET, format!("{}/zones", self.powerdns_base()), None).await?;
		#[derive(Deserialize)]
		struct Zone {
			name: String,
		}
		let zones: Vec<Zone> = serde_json::from_slice(&body).map_err(|e| format!("PowerDNS zones: {e}"))?;
		Ok(zones.into_iter().map(|z| normalize_name(&z.name)).collect())
	}

	/// Sets the TXT values of one name (PowerDNS replaces the whole set, so all
	/// values of a name go in one call; the REST template adds them one by one).
	pub async fn present(&self, records: &[Written]) -> Result<(), String> {
		let Some(first) = records.first() else { return Ok(()) };
		match self.spec.kind.as_str() {
			"powerdns" => {
				let rrset = serde_json::json!({"rrsets": [{
					"name": format!("{}.", first.fqdn),
					"type": "TXT",
					"ttl": self.spec.ttl.unwrap_or(DEFAULT_TTL),
					"changetype": "REPLACE",
					"records": records.iter().map(|r| serde_json::json!({"content": format!("\"{}\"", r.value), "disabled": false})).collect::<Vec<_>>(),
				}]});
				let url = format!("{}/zones/{}.", self.powerdns_base(), first.zone);
				self.powerdns(Method::PATCH, url, Some(rrset)).await.map(|_| ())
			}
			_ => {
				for r in records {
					self.template(self.spec.add.as_ref(), r).await?;
				}
				Ok(())
			}
		}
	}

	/// Removes the TXT values of one name.
	pub async fn cleanup(&self, records: &[Written]) -> Result<(), String> {
		let Some(first) = records.first() else { return Ok(()) };
		match self.spec.kind.as_str() {
			"powerdns" => {
				let rrset = serde_json::json!({"rrsets": [{"name": format!("{}.", first.fqdn), "type": "TXT", "changetype": "DELETE"}]});
				let url = format!("{}/zones/{}.", self.powerdns_base(), first.zone);
				self.powerdns(Method::PATCH, url, Some(rrset)).await.map(|_| ())
			}
			_ => {
				let mut first_error = None;
				for r in records {
					if let Err(e) = self.template(self.spec.remove.as_ref(), r).await {
						first_error.get_or_insert(e);
					}
				}
				first_error.map_or(Ok(()), Err)
			}
		}
	}

	async fn template(&self, call: Option<&HttpCallSpec>, w: &Written) -> Result<(), String> {
		let call = call.ok_or("no template")?;
		let secret = match &self.spec.secret_file {
			Some(f) => read_secret(f)?,
			None => String::new(),
		};
		let method: Method = call.method.as_deref().unwrap_or("POST").parse().map_err(|_| "invalid method".to_string())?;
		let url = fill(&call.url, w, "");
		let mut req = Request::builder().method(method).uri(&url);
		for (name, value) in &call.headers {
			req = req.header(name.as_str(), fill(value, w, &secret));
		}
		let body = call.body.as_deref().map(|b| fill(b, w, &secret)).unwrap_or_default();
		let req = req.body(Bytes::from(body)).map_err(|e| format!("{url}: {}", excerpt(e.to_string().as_bytes(), &secret)))?;
		let resp = http::send(&self.tls, req).await?;
		if !resp.status().is_success() {
			return Err(format!("{url}: {} {}", resp.status(), excerpt(resp.body(), &secret)));
		}
		Ok(())
	}
}

/// `dns-pending.json`: records written and not removed yet.
pub struct Journal {
	path: PathBuf,
	lock: Mutex<()>,
}

impl Journal {
	pub fn new(storage: &Path) -> Journal {
		Journal { path: storage.join("dns-pending.json"), lock: Mutex::new(()) }
	}

	pub fn read(&self) -> Vec<Written> {
		std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
	}

	fn update(&self, f: impl FnOnce(&mut Vec<Written>)) {
		let _guard = self.lock.lock();
		let mut all = self.read();
		f(&mut all);
		all.sort();
		all.dedup();
		let result = if all.is_empty() {
			match std::fs::remove_file(&self.path) {
				Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
				_ => Ok(()),
			}
		} else {
			super::store::write_private(&self.path, &serde_json::to_vec_pretty(&all).unwrap_or_default())
		};
		if let Err(e) = result {
			warn!(event = "acme.error", part = "dns journal", file = %self.path.display(), error = %e,
				"records left over by a crash may not be removed after a restart");
		}
	}

	pub fn add(&self, records: &[Written]) {
		self.update(|all| all.extend_from_slice(records));
	}

	pub fn remove(&self, records: &[Written]) {
		self.update(|all| all.retain(|w| !records.contains(w)));
	}
}

/// Groups records by (provider, fqdn): one call per name.
pub fn by_name(records: &[Written]) -> BTreeMap<(String, String), Vec<Written>> {
	let mut out: BTreeMap<(String, String), Vec<Written>> = BTreeMap::new();
	for r in records {
		out.entry((r.provider.clone(), r.fqdn.clone())).or_default().push(r.clone());
	}
	out
}

/// Removes records and takes them out of the journal; failures stay in it
/// (and are tried again after a restart).
pub async fn remove_all(providers: &BTreeMap<String, Provider>, journal: &Journal, records: &[Written], reason: &str) {
	for ((provider, fqdn), group) in by_name(records) {
		let Some(p) = providers.get(&provider) else {
			warn!(event = "acme.dns", action = "remove", provider, fqdn, outcome = "error", error = "the provider is no longer configured");
			continue;
		};
		match p.cleanup(&group).await {
			Ok(()) => {
				info!(event = "acme.dns", action = "remove", provider, fqdn, zone = %group[0].zone, reason, outcome = "ok");
				journal.remove(&group);
			}
			Err(e) => warn!(event = "acme.dns", action = "remove", provider, fqdn, reason, outcome = "error", error = %e),
		}
	}
}

/// Waits until every value is visible in DNS, or `timeout` passes (then the CA
/// is asked anyway: it may see the record before the name servers here do).
pub async fn wait_visible(servers: &[SocketAddr], records: &[Written], timeout: Duration) -> bool {
	let deadline = tokio::time::Instant::now() + timeout;
	loop {
		let mut all = true;
		for r in records {
			match dnsq::txt(servers, &r.fqdn).await {
				Ok(values) if values.contains(&r.value) => {}
				_ => {
					all = false;
					break;
				}
			}
		}
		if all {
			return true;
		}
		if tokio::time::Instant::now() >= deadline {
			return false;
		}
		tokio::time::sleep(Duration::from_secs(2)).await;
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn templates_and_excerpts() {
		let w = Written { provider: "p".into(), fqdn: "_acme-challenge.a.example".into(), zone: "a.example".into(), value: "v4lue".into() };
		assert_eq!(fill("{\"fqdn\":\"{fqdn}\",\"value\":\"{value}\",\"zone\":\"{zone}\"}", &w, "s"), r#"{"fqdn":"_acme-challenge.a.example","value":"v4lue","zone":"a.example"}"#);
		assert_eq!(fill("Bearer {secret}", &w, "tok"), "Bearer tok");
		assert_eq!(excerpt(b"bad token tok\nend", "tok"), "bad ***en *** end");
		assert_eq!(excerpt(&[b'x'; 500], "").len(), 200);
	}

	#[test]
	fn journal_survives_a_restart() {
		let dir = std::env::temp_dir().join(format!("rproxy-acme-journal-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		let j = Journal::new(&dir);
		let a = Written { provider: "p".into(), fqdn: "a".into(), zone: "z".into(), value: "1".into() };
		let b = Written { value: "2".into(), ..a.clone() };
		j.add(&[a.clone(), b.clone()]);
		assert_eq!(Journal::new(&dir).read(), [a.clone(), b.clone()]);
		assert_eq!(by_name(&[a.clone(), b.clone()]).len(), 1, "one call per name");
		j.remove(&[a]);
		assert_eq!(j.read(), std::slice::from_ref(&b));
		j.remove(&[b]);
		assert!(!dir.join("dns-pending.json").exists());
		let _ = std::fs::remove_dir_all(&dir);
	}
}
