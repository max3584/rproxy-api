//! The certificate store (#115): every certificate file rules name is loaded
//! once and shared. Rules read their certificates from here (`rule_certs`);
//! file changes (#90, `refresh`), SIGHUP (`reload_all`) and expiry
//! (`newly_expired`) are handled per certificate, and the registry then
//! rebuilds only the rules that use a certificate that changed.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tracing::{error, info, warn};

use crate::error::ApiError;
use crate::tls::config::{self as tlsconf, CertBundle, CertRole, ClientAuthMode, KeyedCert, RuleCerts, TlsMode, TlsSpec};

/// Warn this long before a certificate expires, unless `set_warn_days` says otherwise.
pub const DEFAULT_WARN_DAYS: u64 = 14;

/// One set of files the store loads as a unit.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Source {
	/// A certificate (with its chain) and its key: `tls.certificates[]`, `tls.upstream`.
	Keyed { cert: String, chain: Option<String>, key: String },
	/// CA certificates: `client_auth.ca_file` / `chain_file`, `upstream.ca_file`.
	Bundle(String),
	/// A certificate obtained through ACME (`tls.certificates[].acme`): the files
	/// under `global.acme.storage`, or a self-signed stand-in for `id`'s names
	/// until they are written.
	Acme { cert: String, key: String, id: crate::acme::CertId },
	/// A certificate stored through the control API (`tls.certificates[].cert`,
	/// #240): the files of `name` in the store (`tls::named`).
	Named { name: String, cert: String, key: String },
}

impl Source {
	/// The certificate file, as shown in views, metrics and logs.
	pub fn file(&self) -> &str {
		match self {
			Source::Keyed { cert, .. } | Source::Acme { cert, .. } | Source::Named { cert, .. } => cert,
			Source::Bundle(file) => file,
		}
	}

	/// Every file of the set (certificate, chain, key).
	pub fn files(&self) -> Vec<&str> {
		match self {
			Source::Keyed { cert, chain, key } => [Some(cert.as_str()), chain.as_deref(), Some(key.as_str())].into_iter().flatten().collect(),
			Source::Bundle(file) => vec![file],
			Source::Acme { cert, key, .. } | Source::Named { cert, key, .. } => vec![cert, key],
		}
	}

	fn keyed(cert: &str, chain: Option<&str>, key: &str) -> Source {
		Source::Keyed { cert: cert.to_string(), chain: chain.map(str::to_string), key: key.to_string() }
	}
}

/// The certificate files a rule's TLS settings use, with what each is for.
/// Only `terminate` reads certificates.
pub fn sources(spec: &TlsSpec) -> Vec<(CertRole, Source)> {
	sources_with(spec, None)
}

/// `sources`, with the ACME certificates' files under `acme`'s storage (left
/// out without `global.acme`; such a rule does not build).
pub fn sources_with(spec: &TlsSpec, acme: Option<&crate::acme::Acme>) -> Vec<(CertRole, Source)> {
	if spec.mode != TlsMode::Terminate {
		return vec![];
	}
	let mut out: Vec<(CertRole, Source)> = spec
		.certificates
		.iter()
		.filter_map(|c| match (&c.acme, acme) {
			_ if c.cert.is_some() => {
				let name = c.cert.clone().unwrap_or_default();
				let (cert, key) = crate::tls::named::files(&name);
				Some((CertRole::Certificate, Source::Named { name, cert, key }))
			}
			(None, _) => Some((CertRole::Certificate, Source::keyed(&c.cert_file, c.chain_file.as_deref(), &c.key_file))),
			(Some(resolver), Some(acme)) => {
				let id = crate::acme::CertId::new(resolver, &c.domains);
				let (cert, key) = acme.files(&id);
				Some((CertRole::Certificate, Source::Acme { cert, key, id }))
			}
			(Some(_), None) => None,
		})
		.collect();
	if spec.client_auth.mode != ClientAuthMode::None {
		out.extend(spec.client_auth.ca_file.clone().map(|f| (CertRole::ClientCa, Source::Bundle(f))));
		out.extend(spec.client_auth.chain_file.clone().map(|f| (CertRole::ClientChain, Source::Bundle(f))));
	}
	if spec.upstream.tls {
		out.extend(spec.upstream.ca_file.clone().map(|f| (CertRole::UpstreamCa, Source::Bundle(f))));
		if let (Some(cert), Some(key)) = (&spec.upstream.cert_file, &spec.upstream.key_file) {
			out.push((CertRole::UpstreamCertificate, Source::keyed(cert, spec.upstream.chain_file.as_deref(), key)));
		}
	}
	out
}

/// How close to expiry a certificate is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertState {
	Ok,
	/// Within the warning period (`RPROXY_CERT_WARN_DAYS`).
	Expiring,
	Expired,
}

impl CertState {
	pub fn of(not_after: i64, now: i64, warn_secs: i64) -> CertState {
		if not_after <= now {
			CertState::Expired
		} else if not_after - now <= warn_secs {
			CertState::Expiring
		} else {
			CertState::Ok
		}
	}
}

/// Expiry of one certificate a rule uses, in the rule view (`cert_status`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CertStatusView {
	pub role: CertRole,
	pub file: String,
	/// RFC 3339 (UTC).
	pub not_after: String,
	/// Whole days left; negative once expired.
	pub days_left: i64,
	pub state: CertState,
}

impl CertStatusView {
	pub fn new(role: CertRole, file: &str, not_after: i64, now: i64, warn_secs: i64) -> Self {
		CertStatusView {
			role,
			file: file.to_string(),
			not_after: rfc3339(not_after),
			days_left: (not_after - now).div_euclid(86_400),
			state: CertState::of(not_after, now, warn_secs),
		}
	}
}

/// RFC 3339 (UTC) for views and logs; empty when out of range.
pub fn rfc3339(unix: i64) -> String {
	time::OffsetDateTime::from_unix_timestamp(unix)
		.ok()
		.and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
		.unwrap_or_default()
}

#[derive(Clone)]
enum Material {
	Keyed(Arc<KeyedCert>),
	Bundle(Arc<CertBundle>),
}

impl Material {
	fn load(source: &Source) -> Result<Material, ApiError> {
		Ok(match source {
			Source::Keyed { cert, chain, key } => Material::Keyed(Arc::new(KeyedCert::load(cert, chain.as_deref(), key)?)),
			Source::Bundle(file) => Material::Bundle(Arc::new(CertBundle::load(file)?)),
			Source::Named { name, cert, key } => {
				if !std::path::Path::new(cert).exists() {
					return Err(crate::tls::named::missing(name));
				}
				Material::Keyed(Arc::new(KeyedCert::load(cert, None, key)?))
			}
			Source::Acme { cert, key, id } => {
				let stored = match std::path::Path::new(cert).exists() {
					true => Some(KeyedCert::load(cert, None, key)?),
					false => None,
				};
				match stored {
					// expired on disk (rproxy was stopped past the renewal): the stand-in until it is renewed
					Some(k) if !k.expired(tlsconf::unix_now()) => Material::Keyed(Arc::new(k)),
					// not issued yet: a self-signed stand-in (never written to disk)
					_ => {
						let (chain, der) = crate::acme::placeholder(&id.domains).map_err(ApiError::tls_config)?;
						Material::Keyed(Arc::new(KeyedCert::from_parts(chain, der, cert, key)?))
					}
				}
			}
		})
	}

	fn not_after(&self) -> i64 {
		match self {
			Material::Keyed(k) => k.not_after,
			Material::Bundle(b) => b.not_after,
		}
	}
}

struct Slot {
	material: Option<Material>,
	/// Fingerprint of the files when `material` was read.
	print: u64,
	/// Fingerprint of a version of the files that did not load (logged once).
	failed: Option<u64>,
	/// State last logged (`cert.expiring` / `cert.expired` once per change).
	logged: Option<CertState>,
	/// Whether `newly_expired` last saw it expired.
	expired: bool,
}

/// What `refresh` / `reload_all` did.
#[derive(Debug, Default)]
pub struct Changes {
	/// Reloaded: rules using these need new TLS settings.
	pub changed: HashSet<Source>,
	/// Changed on disk but could not be loaded; the previous certificate stays in use.
	pub failed: HashSet<Source>,
}

/// Certificates checked outside the store (the control API's): (role, file) → (notAfter, state last logged).
type External = HashMap<(CertRole, String), (i64, Option<CertState>)>;

pub struct CertStore {
	slots: Mutex<HashMap<Source, Slot>>,
	warn_secs: AtomicI64,
	external: Mutex<External>,
}

impl Default for CertStore {
	fn default() -> Self {
		CertStore {
			slots: Mutex::default(),
			warn_secs: AtomicI64::new(DEFAULT_WARN_DAYS as i64 * 86_400),
			external: Mutex::default(),
		}
	}
}

impl CertStore {
	pub fn set_warn_days(&self, days: u64) {
		self.warn_secs.store(days.min(36_500) as i64 * 86_400, Ordering::Relaxed);
	}

	pub fn warn_secs(&self) -> i64 {
		self.warn_secs.load(Ordering::Relaxed)
	}

	/// The loaded certificate of `source`, loading it the first time (or after
	/// an earlier attempt failed).
	fn get(&self, source: &Source) -> Result<Material, ApiError> {
		let mut slots = self.slots.lock().unwrap();
		if let Some(material) = slots.get(source).and_then(|s| s.material.clone()) {
			return Ok(material);
		}
		let print = tlsconf::fingerprint(source.files());
		let material = Material::load(source)?;
		let now = tlsconf::unix_now();
		let mut slot = Slot { material: Some(material.clone()), print, failed: None, logged: None, expired: material.not_after() <= now };
		log_change(&mut slot.logged, source.file(), material.not_after(), now, self.warn_secs());
		slots.insert(source.clone(), slot);
		Ok(material)
	}

	fn keyed(&self, source: &Source) -> Result<Arc<KeyedCert>, ApiError> {
		match self.get(source)? {
			Material::Keyed(k) => Ok(k),
			Material::Bundle(_) => unreachable!("a keyed source loads a keyed certificate"),
		}
	}

	fn bundle(&self, file: &str) -> Result<Arc<CertBundle>, ApiError> {
		match self.get(&Source::Bundle(file.to_string()))? {
			Material::Bundle(b) => Ok(b),
			Material::Keyed(_) => unreachable!("a bundle source loads a bundle"),
		}
	}

	/// The certificates one rule's TLS settings use, shared with other rules
	/// that name the same files.
	pub fn rule_certs(&self, spec: &TlsSpec) -> Result<RuleCerts, ApiError> {
		self.rule_certs_with(spec, None)
	}

	/// `rule_certs` with ACME certificates (`sources_with`).
	pub fn rule_certs_with(&self, spec: &TlsSpec, acme: Option<&crate::acme::Acme>) -> Result<RuleCerts, ApiError> {
		let mut certs = RuleCerts::default();
		for (role, source) in sources_with(spec, acme) {
			match (role, &source) {
				(CertRole::Certificate, _) => certs.servers.push(self.keyed(&source)?),
				(CertRole::ClientCa, s) => certs.client_ca = Some(self.bundle(s.file())?),
				(CertRole::ClientChain, s) => certs.client_chain = Some(self.bundle(s.file())?),
				(CertRole::UpstreamCa, s) => certs.upstream_ca = Some(self.bundle(s.file())?),
				(CertRole::UpstreamCertificate, _) => certs.upstream_cert = Some(self.keyed(&source)?),
				(CertRole::Api, _) => {}
			}
		}
		Ok(certs)
	}

	/// Reloads certificates whose files changed (size, time, inode; #90). A
	/// version that does not load (half written) keeps the previous one and is
	/// tried again on the next call.
	pub fn refresh(&self) -> Changes {
		self.reload(false)
	}

	/// Reloads every certificate (SIGHUP).
	pub fn reload_all(&self) -> Changes {
		self.reload(true)
	}

	fn reload(&self, all: bool) -> Changes {
		let mut changes = Changes::default();
		let now = tlsconf::unix_now();
		let warn = self.warn_secs();
		let mut slots = self.slots.lock().unwrap();
		for (source, slot) in slots.iter_mut() {
			let print = tlsconf::fingerprint(source.files());
			if !all && print == slot.print && slot.material.is_some() {
				continue;
			}
			match Material::load(source) {
				Ok(material) => {
					slot.expired = material.not_after() <= now;
					log_change(&mut slot.logged, source.file(), material.not_after(), now, warn);
					slot.material = Some(material);
					slot.print = print;
					slot.failed = None;
					changes.changed.insert(source.clone());
				}
				Err(e) => {
					if slot.failed != Some(print) {
						warn!(event = "reload.tls", file = %source.file(), error = %e.message, "keeping the current certificate");
						slot.failed = Some(print);
					}
					changes.failed.insert(source.clone());
				}
			}
		}
		changes
	}

	/// Server certificates that have expired since the last call (the daily
	/// check); rules using them drop them, or stop when none is left.
	pub fn newly_expired(&self, now: i64) -> HashSet<Source> {
		let warn = self.warn_secs();
		let mut out = HashSet::new();
		for (source, slot) in self.slots.lock().unwrap().iter_mut() {
			let Some(material) = &slot.material else { continue };
			let not_after = material.not_after();
			log_change(&mut slot.logged, source.file(), not_after, now, warn);
			let expired = not_after <= now;
			if expired && !slot.expired && matches!(material, Material::Keyed(_)) {
				out.insert(source.clone());
			}
			slot.expired = expired;
		}
		out
	}

	/// Forgets certificates no rule uses any more.
	pub fn retain(&self, used: &HashSet<Source>) {
		self.slots.lock().unwrap().retain(|s, _| used.contains(s));
	}

	/// notAfter (Unix seconds) of a loaded certificate.
	pub fn not_after(&self, source: &Source) -> Option<i64> {
		self.slots.lock().unwrap().get(source).and_then(|s| s.material.as_ref()).map(Material::not_after)
	}

	/// Records a certificate checked outside the store (the control API's), for
	/// the same logs and metrics.
	pub fn note_external(&self, role: CertRole, file: &str, not_after: i64, now: i64) {
		let mut external = self.external.lock().unwrap();
		let entry = external.entry((role, file.to_string())).or_insert((not_after, None));
		entry.0 = not_after;
		log_change(&mut entry.1, file, not_after, now, self.warn_secs());
	}

	/// Certificates recorded by `note_external`: (role, file, notAfter).
	pub fn external(&self) -> Vec<(CertRole, String, i64)> {
		let mut out: Vec<_> = self.external.lock().unwrap().iter().map(|((r, f), (n, _))| (*r, f.clone(), *n)).collect();
		out.sort_by(|a, b| a.1.cmp(&b.1));
		out
	}
}

/// Logs `cert.expiring` / `cert.expired` (and `cert.ok` after a renewal) when
/// the state differs from the one last logged.
fn log_change(logged: &mut Option<CertState>, file: &str, not_after: i64, now: i64, warn_secs: i64) {
	let state = CertState::of(not_after, now, warn_secs);
	if *logged == Some(state) || (logged.is_none() && state == CertState::Ok) {
		*logged = Some(state);
		return;
	}
	let days_left = (not_after - now).div_euclid(86_400);
	let not_after = rfc3339(not_after);
	match state {
		CertState::Expired => error!(event = "cert.expired", file, not_after, days_left, "certificate has expired"),
		CertState::Expiring => warn!(event = "cert.expiring", file, not_after, days_left, "certificate expires soon"),
		CertState::Ok => info!(event = "cert.ok", file, not_after, days_left, "certificate renewed"),
	}
	*logged = Some(state);
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn states() {
		let day = 86_400;
		assert_eq!(CertState::of(100 * day, 0, 14 * day), CertState::Ok);
		assert_eq!(CertState::of(14 * day, 0, 14 * day), CertState::Expiring);
		assert_eq!(CertState::of(0, 0, 14 * day), CertState::Expired);
		assert_eq!(CertState::of(-5, 0, 14 * day), CertState::Expired);
		assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
	}

	#[test]
	fn sources_follow_the_settings() {
		let spec: TlsSpec = serde_json::from_value(serde_json::json!({
			"mode": "terminate",
			"certificates": [{"cert_file": "/a.pem", "key_file": "/a.key"}, {"cert_file": "/b.pem", "chain_file": "/b-chain.pem", "key_file": "/b.key"}],
			"client_auth": {"mode": "required", "ca_file": "/ca.pem"},
			"upstream": {"tls": true, "ca_file": "/up-ca.pem"}
		}))
		.unwrap();
		let got: Vec<(CertRole, String)> = sources(&spec).into_iter().map(|(r, s)| (r, s.file().to_string())).collect();
		assert_eq!(
			got,
			[
				(CertRole::Certificate, "/a.pem".to_string()),
				(CertRole::Certificate, "/b.pem".to_string()),
				(CertRole::ClientCa, "/ca.pem".to_string()),
				(CertRole::UpstreamCa, "/up-ca.pem".to_string()),
			]
		);
		let passthrough: TlsSpec = serde_json::from_value(serde_json::json!({"mode": "passthrough"})).unwrap();
		assert!(sources(&passthrough).is_empty());
	}
}
