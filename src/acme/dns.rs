//! DNS-01: writing and removing the TXT record through a DNS provider
//! (`global.acme.dns_providers`): the PowerDNS HTTP API, DNS UPDATE (RFC 2136,
//! TSIG), acme-dns, or a generic REST template. Secrets are read from files when a call is made and never logged;
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
	/// acme_dns: one registration at a time (the credentials file is rewritten).
	register: tokio::sync::Mutex<()>,
}

/// An acme-dns account (one per name), as lego keeps them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcmeDnsAccount {
	pub username: String,
	pub password: String,
	pub fulldomain: String,
	pub subdomain: String,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allowfrom: Vec<String>,
}

/// A TXT record rproxy wrote (or is about to): enough to remove it later.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Written {
	pub provider: String,
	/// The name being validated (without `*.`), for the helper to check.
	#[serde(default)]
	pub domain: String,
	/// Where the record is (after following CNAMEs), without the final dot.
	pub fqdn: String,
	pub zone: String,
	pub value: String,
}

fn read_secret(file: &str) -> Result<String, String> {
	crate::net::files::read_to_string(file, crate::net::files::Kind::Secret).map(|s| s.trim().to_string()).map_err(|e| format!("{file}: {e}"))
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
		Ok(Provider {
			name: name.to_string(),
			spec: spec.clone(),
			tls: http::connector(spec.ca_file.as_deref())?,
			register: tokio::sync::Mutex::new(()),
		})
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

	/// Files this provider reads (for `--check-config`'s readability warnings).
	pub fn secret_files(spec: &DnsProviderSpec) -> Vec<String> {
		let mut out = Self::required_files(spec);
		out.extend(spec.credentials_file.clone());
		out
	}

	/// Files that must exist (acme-dns's credentials file is created when missing).
	pub fn required_files(spec: &DnsProviderSpec) -> Vec<String> {
		[&spec.api_key_file, &spec.secret_file, &spec.ca_file, &spec.tsig_secret_file].into_iter().flatten().cloned().collect()
	}

	/// Where the TXT record for `domain` goes: `_acme-challenge.<domain>` after
	/// following CNAMEs (acme-dns: the account's `fulldomain`), and its zone.
	pub async fn locate(&self, domain: &str, value: &str, servers: &[SocketAddr]) -> Result<Written, String> {
		let name = format!("_acme-challenge.{domain}");
		let fqdn = dnsq::follow_cname(servers, &name).await.unwrap_or_else(|e| {
			tracing::debug!(event = "acme.dns", action = "cname", name, error = %e, "using the name itself");
			name.clone()
		});
		if self.spec.kind == "acme_dns" {
			let account = self.acme_dns_account(domain).await?;
			let full = normalize_name(&account.fulldomain);
			// acme-dns answers only for its own names: _acme-challenge must point there
			if fqdn != full {
				return Err(format!(
					"acme-dns: create the CNAME record {name}. -> {full}. (dns provider {:?}); it is not there yet",
					self.name
				));
			}
			return Ok(Written { provider: self.name.clone(), domain: domain.to_string(), fqdn, zone: String::new(), value: value.to_string() });
		}
		let zone = self.zone_for(&fqdn, servers).await?;
		Ok(Written { provider: self.name.clone(), domain: domain.to_string(), fqdn, zone, value: value.to_string() })
	}

	fn tsig_key(&self) -> Result<super::rfc2136::TsigKey, String> {
		use base64::Engine;
		let file = self.spec.tsig_secret_file.as_deref().unwrap_or_default();
		let text = read_secret(file)?;
		let secret = base64::engine::general_purpose::STANDARD
			.decode(text.trim())
			.map_err(|_| format!("{file}: the TSIG secret is not base64"))?;
		Ok(super::rfc2136::TsigKey {
			name: self.spec.tsig_key_name.clone().unwrap_or_default(),
			algorithm: super::rfc2136::Algorithm::parse(self.spec.tsig_algorithm.as_deref().unwrap_or("hmac-sha256"))
				.unwrap_or(super::rfc2136::Algorithm::HmacSha256),
			secret,
		})
	}

	fn rfc2136_server(&self) -> Result<SocketAddr, String> {
		super::config::parse_dns_server(self.spec.server.as_deref().unwrap_or_default())
	}

	fn acme_dns_accounts(&self) -> Result<BTreeMap<String, AcmeDnsAccount>, String> {
		let file = self.spec.credentials_file.as_deref().unwrap_or_default();
		match crate::net::files::read(file, crate::net::files::Kind::Secret) {
			Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{file}: {e}")),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
			Err(e) => Err(format!("{file}: {e}")),
		}
	}

	/// The acme-dns account of `domain`, registered (and kept, 0600) when there is none.
	async fn acme_dns_account(&self, domain: &str) -> Result<AcmeDnsAccount, String> {
		let _one = self.register.lock().await;
		let mut all = self.acme_dns_accounts()?;
		if let Some(a) = all.get(domain) {
			return Ok(a.clone());
		}
		let base = self.spec.api_url.as_deref().unwrap_or_default().trim_end_matches('/');
		let req = Request::builder()
			.method(Method::POST)
			.uri(format!("{base}/register"))
			.header("Content-Type", "application/json")
			.body(Bytes::from_static(b"{}"))
			.map_err(|e| e.to_string())?;
		let resp = http::send(&self.tls, req).await?;
		if !resp.status().is_success() {
			return Err(format!("acme-dns {base}/register: {} {}", resp.status(), excerpt(resp.body(), "")));
		}
		let account: AcmeDnsAccount = serde_json::from_slice(resp.body()).map_err(|e| format!("acme-dns register: {e}"))?;
		all.insert(domain.to_string(), account.clone());
		let file = self.spec.credentials_file.as_deref().unwrap_or_default();
		super::store::write_private(Path::new(file), &serde_json::to_vec_pretty(&all).unwrap_or_default())
			.map_err(|e| format!("{file}: {e} (registered at acme-dns, but the account could not be kept)"))?;
		info!(event = "acme.dns", action = "register", provider = %self.name, domain, fulldomain = %account.fulldomain,
			"registered at acme-dns; create the CNAME _acme-challenge.{domain} -> {}", account.fulldomain);
		Ok(account)
	}

	async fn acme_dns_update(&self, r: &Written) -> Result<(), String> {
		let account = self.acme_dns_accounts()?.get(&r.domain).cloned().ok_or_else(|| format!("acme-dns: no account for {}", r.domain))?;
		let base = self.spec.api_url.as_deref().unwrap_or_default().trim_end_matches('/');
		let body = serde_json::json!({"subdomain": account.subdomain, "txt": r.value}).to_string();
		let req = Request::builder()
			.method(Method::POST)
			.uri(format!("{base}/update"))
			.header("X-Api-User", &account.username)
			.header("X-Api-Key", &account.password)
			.header("Content-Type", "application/json")
			.body(Bytes::from(body))
			.map_err(|e| excerpt(e.to_string().as_bytes(), &account.password))?;
		let resp = http::send(&self.tls, req).await?;
		if !resp.status().is_success() {
			return Err(format!("acme-dns {base}/update: {} {}", resp.status(), excerpt(resp.body(), &account.password)));
		}
		Ok(())
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
		if self.spec.kind == "rfc2136" {
			// the primary server knows its zones
			return dnsq::find_zone(&[self.rfc2136_server()?], fqdn).await;
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
			"rfc2136" => {
				let ttl = self.spec.ttl.unwrap_or(DEFAULT_TTL);
				let changes: Vec<_> =
					records.iter().map(|r| super::rfc2136::Change::Add { name: &r.fqdn, value: &r.value, ttl }).collect();
				super::rfc2136::send(self.rfc2136_server()?, &first.zone, &changes, &self.tsig_key()?).await
			}
			"acme_dns" => {
				for r in records {
					self.acme_dns_update(r).await?;
				}
				Ok(())
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
			"rfc2136" => {
				let changes: Vec<_> = records.iter().map(|r| super::rfc2136::Change::Delete { name: &r.fqdn, value: &r.value }).collect();
				super::rfc2136::send(self.rfc2136_server()?, &first.zone, &changes, &self.tsig_key()?).await
			}
			// acme-dns keeps the two latest values and has no removal
			"acme_dns" => Ok(()),
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

/// Who writes the TXT records: the DNS providers in this process, or the ACME
/// helper (`global.acme.helper`), which holds their secrets.
pub enum Backend {
	Local(BTreeMap<String, Provider>),
	Helper(PathBuf),
}

impl Backend {
	pub async fn locate(&self, provider: &str, domain: &str, value: &str, servers: &[SocketAddr]) -> Result<Written, String> {
		match self {
			Backend::Local(all) => all.get(provider).ok_or_else(|| format!("dns provider {provider:?} is not configured"))?.locate(domain, value, servers).await,
			Backend::Helper(socket) => {
				let req = super::helper::Request::Locate { provider: provider.into(), domain: domain.into(), value: value.into() };
				super::helper::call(socket, &req).await?.record.ok_or_else(|| "acme helper: no record in the answer".to_string())
			}
		}
	}

	pub async fn present(&self, provider: &str, records: &[Written]) -> Result<(), String> {
		match self {
			Backend::Local(all) => all.get(provider).ok_or_else(|| format!("dns provider {provider:?} is not configured"))?.present(records).await,
			Backend::Helper(socket) => {
				let req = super::helper::Request::Present { provider: provider.into(), records: records.to_vec() };
				super::helper::call(socket, &req).await.map(|_| ())
			}
		}
	}

	pub async fn cleanup(&self, provider: &str, records: &[Written]) -> Result<(), String> {
		match self {
			Backend::Local(all) => all.get(provider).ok_or_else(|| "the provider is no longer configured".to_string())?.cleanup(records).await,
			Backend::Helper(socket) => {
				let req = super::helper::Request::Cleanup { provider: provider.into(), records: records.to_vec() };
				super::helper::call(socket, &req).await.map(|_| ())
			}
		}
	}
}

/// Removes records and takes them out of the journal; failures stay in it
/// (and are tried again after a restart).
pub async fn remove_all(backend: &Backend, journal: &Journal, records: &[Written], reason: &str) {
	for ((provider, fqdn), group) in by_name(records) {
		match backend.cleanup(&provider, &group).await {
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
		let w = Written { provider: "p".into(), domain: "a.example".into(), fqdn: "_acme-challenge.a.example".into(), zone: "a.example".into(), value: "v4lue".into() };
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
		let a = Written { provider: "p".into(), domain: "a.example".into(), fqdn: "a".into(), zone: "z".into(), value: "1".into() };
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
