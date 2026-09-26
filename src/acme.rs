//! Certificates from an ACME CA (`global.acme`, `tls.certificates[].acme`, #17).
//!
//! One `AcmeManager` per process holds the resolvers (ACME accounts) and the
//! certificates the rules ask for. A certificate is shared by every rule that
//! names the same resolver and domains; a background task obtains it, stores it
//! under `global.acme.storage`, and renews it 30 days before it expires. Until
//! the first certificate arrives, handshakes get a self-signed placeholder.
//!
//! Challenges: `tls-alpn-01` is answered by any `terminate` listener (the
//! `acme-tls/1` ALPN, src/tcp.rs), `http-01` by any `http` rule
//! (`/.well-known/acme-challenge/`, src/http/server.rs). `dns-01` is not
//! available yet.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use instant_acme::{
	Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
	RetryPolicy,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::AcmeGlobal;
use crate::error::ApiError;

/// Let's Encrypt (production) when `directory` is left out.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Where certificates and account keys go when `storage` is left out.
pub const DEFAULT_STORAGE: &str = "/var/lib/rproxy/acme";
/// Renew this long before the certificate expires.
pub const RENEW_BEFORE: Duration = Duration::from_secs(30 * 86_400);
/// The ALPN protocol of tls-alpn-01 (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
/// The challenges this build can answer (`GET /capabilities` `features.acme_challenges`).
pub const CHALLENGES: &[&str] = &["http-01", "tls-alpn-01"];

const FIRST_RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(6 * 3600);
/// A sleeping task wakes at least this often to notice that no rule uses its certificate any more.
const MAX_SLEEP: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Challenge {
	Http01,
	TlsAlpn01,
	Dns01,
}

#[derive(Debug)]
struct Resolver {
	email: String,
	directory: String,
	challenge: Challenge,
	ca_file: Option<PathBuf>,
}

/// Why `global.acme` could not be set up.
#[derive(Debug)]
pub enum AcmeError {
	/// A mistake in the settings: stop the startup.
	Config(String),
}

impl std::fmt::Display for AcmeError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AcmeError::Config(e) => f.write_str(e),
		}
	}
}

/// State of one certificate, shown in the rule view (`acme`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AcmeStatus {
	pub resolver: String,
	pub domains: Vec<String>,
	/// `pending` (placeholder served), `valid`, or `error` (the last attempt failed;
	/// a certificate obtained earlier stays in use).
	pub state: &'static str,
	/// Expiry of the certificate in use (Unix seconds), once there is one.
	pub not_after: Option<u64>,
	pub error: Option<String>,
}

/// A certificate the rules use; swapped in place when it is (re)issued, so
/// handshakes pick up the new one without the rule restarting.
pub struct ManagedCert {
	resolver: String,
	domains: Vec<String>,
	current: RwLock<Arc<CertifiedKey>>,
	status: RwLock<AcmeStatus>,
	/// Whether `current` came from the CA (not the placeholder).
	issued: RwLock<Option<u64>>,
}

impl std::fmt::Debug for ManagedCert {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ManagedCert").field("resolver", &self.resolver).field("domains", &self.domains).finish()
	}
}

impl ManagedCert {
	pub fn domains(&self) -> &[String] {
		&self.domains
	}

	pub fn current(&self) -> Arc<CertifiedKey> {
		self.current.read().unwrap().clone()
	}

	pub fn status(&self) -> AcmeStatus {
		self.status.read().unwrap().clone()
	}

	fn install(&self, key: Arc<CertifiedKey>, not_after: u64) {
		*self.current.write().unwrap() = key;
		*self.issued.write().unwrap() = Some(not_after);
		let mut s = self.status.write().unwrap();
		s.state = "valid";
		s.not_after = Some(not_after);
		s.error = None;
	}

	fn failed(&self, error: String) {
		let mut s = self.status.write().unwrap();
		s.state = "error";
		s.error = Some(error);
	}

	/// How long until the next attempt: now without a certificate, else when renewal is due.
	fn due_in(&self, now: u64) -> Duration {
		match *self.issued.read().unwrap() {
			None => Duration::ZERO,
			Some(not_after) => renew_in(not_after, now),
		}
	}
}

/// Time until renewal of a certificate expiring at `not_after` is due.
fn renew_in(not_after: u64, now: u64) -> Duration {
	let due = not_after.saturating_sub(RENEW_BEFORE.as_secs());
	Duration::from_secs(due.saturating_sub(now))
}

fn now_secs() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

type CertKey = (String, Vec<String>);

pub struct AcmeManager {
	resolvers: HashMap<String, Resolver>,
	storage: PathBuf,
	certs: Mutex<HashMap<CertKey, Weak<ManagedCert>>>,
	accounts: tokio::sync::Mutex<HashMap<String, Account>>,
}

impl std::fmt::Debug for AcmeManager {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("AcmeManager").field("storage", &self.storage).finish_non_exhaustive()
	}
}

/// Domains as the CA sees them: lower case, sorted, without repeats.
fn normalize(domains: &[String]) -> Vec<String> {
	let mut d: Vec<String> = domains.iter().map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase()).collect();
	d.sort();
	d.dedup();
	d
}

/// Directory of one certificate: the first domain plus a hash of all of them.
fn cert_dir_name(domains: &[String]) -> String {
	let first: String = domains[0].chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
	let hash = Sha256::digest(domains.join(",").as_bytes());
	format!("{first}-{}", hash.iter().take(4).map(|b| format!("{b:02x}")).collect::<String>())
}

fn safe_name(s: &str) -> String {
	s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// Writes a file readable only by rproxy, replacing it atomically.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
	let tmp = path.with_extension("tmp");
	let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
	f.write_all(data)?;
	f.sync_all()?;
	std::fs::rename(&tmp, path)
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
	// every directory created on the way is private too
	std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
	std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

/// Builds a signing key for rustls from a PKCS#8 DER key.
fn certified(chain: Vec<CertificateDer<'static>>, key_der: Vec<u8>) -> Result<Arc<CertifiedKey>, String> {
	let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
	let signing = any_supported_type(&key).map_err(|e| e.to_string())?;
	Ok(Arc::new(CertifiedKey::new(chain, signing)))
}

/// A self-signed certificate for `names` (placeholder, and tls-alpn-01 answers).
fn self_signed(names: &[String], acme_digest: Option<&[u8]>) -> Result<Arc<CertifiedKey>, String> {
	let mut params = rcgen::CertificateParams::new(names.to_vec()).map_err(|e| e.to_string())?;
	if let Some(digest) = acme_digest {
		params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
	}
	let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
	let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
	certified(vec![cert.der().clone()], key.serialize_der())
}

/// Reads a chain (PEM) and key (PKCS#8 PEM); returns the key, its expiry and names.
fn load_pem(chain_pem: &[u8], key_pem: &[u8]) -> Result<(Arc<CertifiedKey>, u64, Vec<String>), String> {
	let chain: Vec<CertificateDer<'static>> =
		rustls_pemfile::certs(&mut &chain_pem[..]).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
	let leaf = chain.first().ok_or("no certificate")?;
	let (_, parsed) = x509_parser::parse_x509_certificate(leaf).map_err(|e| e.to_string())?;
	let not_after = parsed.validity().not_after.timestamp().max(0) as u64;
	let names = crate::tlsconf::cert_names(leaf);
	let key = rustls_pemfile::private_key(&mut &key_pem[..]).map_err(|e| e.to_string())?.ok_or("no private key")?;
	let key_der = match key {
		PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
		_ => return Err("the key is not PKCS#8".into()),
	};
	Ok((certified(chain, key_der)?, not_after, names))
}

/// Challenge answers waiting for the CA, shared by every listener of the process.
#[derive(Default)]
struct Pending {
	/// tls-alpn-01: server name → certificate with the acmeIdentifier extension.
	tls_alpn: HashMap<String, Arc<CertifiedKey>>,
	/// http-01: token → key authorization.
	http: HashMap<String, String>,
}

fn pending() -> &'static RwLock<Pending> {
	static PENDING: OnceLock<RwLock<Pending>> = OnceLock::new();
	PENDING.get_or_init(Default::default)
}

/// The tls-alpn-01 answer for `server_name`, while a challenge is open.
pub fn tls_alpn_answer(server_name: &str) -> Option<Arc<CertifiedKey>> {
	pending().read().unwrap().tls_alpn.get(&server_name.to_ascii_lowercase()).cloned()
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
	fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		Some(self.0.clone())
	}
}

/// TLS settings that answer the open tls-alpn-01 challenge for `server_name`:
/// the challenge certificate and `acme-tls/1` as the only protocol.
pub fn tls_alpn_config(server_name: &str) -> Option<Arc<rustls::ServerConfig>> {
	let key = tls_alpn_answer(server_name)?;
	let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_safe_default_protocol_versions()
		.ok()?
		.with_no_client_auth()
		.with_cert_resolver(Arc::new(Fixed(key)));
	config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
	Some(Arc::new(config))
}

/// The http-01 answer for a request path, while a challenge is open.
pub fn http_answer(path: &str) -> Option<String> {
	let token = path.strip_prefix("/.well-known/acme-challenge/")?;
	pending().read().unwrap().http.get(token).cloned()
}

/// Removes the answers of one order when it ends, however it ends.
struct Answers {
	tls_alpn: Vec<String>,
	http: Vec<String>,
}

impl Drop for Answers {
	fn drop(&mut self) {
		let mut p = pending().write().unwrap();
		for n in &self.tls_alpn {
			p.tls_alpn.remove(n);
		}
		for t in &self.http {
			p.http.remove(t);
		}
	}
}

/// The stored account of a resolver.
#[derive(Serialize, Deserialize)]
struct StoredAccount {
	directory: String,
	credentials: AccountCredentials,
}

impl AcmeManager {
	/// Sets up `global.acme`. A storage directory that cannot be created is
	/// reported (`degraded`) by the caller through `storage_problem`; certificates
	/// are then kept in memory only.
	pub fn new(global: &AcmeGlobal) -> Result<Arc<AcmeManager>, AcmeError> {
		let _ = rustls::crypto::ring::default_provider().install_default();
		let mut resolvers = HashMap::new();
		for (name, r) in &global.resolvers {
			let challenge = match r.challenge.as_str() {
				"http-01" => Challenge::Http01,
				"tls-alpn-01" => Challenge::TlsAlpn01,
				"dns-01" => Challenge::Dns01,
				other => return Err(AcmeError::Config(format!("global.acme.resolvers.{name}: unknown challenge {other}"))),
			};
			let ca_file = r.ca_file.as_ref().map(PathBuf::from);
			if let Some(ca) = &ca_file {
				if !ca.is_file() {
					return Err(AcmeError::Config(format!("global.acme.resolvers.{name}: ca_file {} does not exist", ca.display())));
				}
			}
			resolvers.insert(
				name.clone(),
				Resolver {
					email: r.email.clone(),
					directory: r.directory.clone().unwrap_or_else(|| LETS_ENCRYPT.to_string()),
					challenge,
					ca_file,
				},
			);
		}
		Ok(Arc::new(AcmeManager {
			resolvers,
			storage: PathBuf::from(global.storage.clone().unwrap_or_else(|| DEFAULT_STORAGE.to_string())),
			certs: Mutex::default(),
			accounts: tokio::sync::Mutex::default(),
		}))
	}

	/// Checks that the storage directory can be written; the error for `degraded`.
	pub fn storage_problem(&self) -> Option<String> {
		let probe = self.storage.join(".rproxy-write-test");
		let result = create_private_dir(&self.storage).and_then(|()| write_private(&probe, b"ok"));
		let _ = std::fs::remove_file(&probe);
		result.err().map(|e| format!("{}: {e}", self.storage.display()))
	}

	/// Resolvers whose challenge this build cannot answer (dns-01).
	pub fn unsupported_resolvers(&self) -> Vec<String> {
		let mut v: Vec<String> =
			self.resolvers.iter().filter(|(_, r)| r.challenge == Challenge::Dns01).map(|(n, _)| n.clone()).collect();
		v.sort();
		v
	}

	/// The certificate for `resolver` + `domains`, shared with other rules; starts
	/// obtaining it when it is new.
	pub fn certificate(self: &Arc<Self>, resolver: &str, domains: &[String]) -> Result<Arc<ManagedCert>, ApiError> {
		let r = self
			.resolvers
			.get(resolver)
			.ok_or_else(|| ApiError::invalid(format!("acme resolver {resolver:?} is not defined in global.acme.resolvers")))?;
		if r.challenge == Challenge::Dns01 {
			return Err(ApiError::unsupported(format!(
				"acme resolver {resolver:?} uses dns-01, which is not available in this version (see GET /capabilities features.acme_challenges)"
			)));
		}
		let domains = normalize(domains);
		if domains.iter().any(|d| d.is_empty() || d.contains(char::is_whitespace)) {
			return Err(ApiError::tls_config("acme domains must be host names"));
		}
		if r.challenge != Challenge::Dns01 && domains.iter().any(|d| d.starts_with("*.")) {
			return Err(ApiError::tls_config("wildcard domains need the dns-01 challenge"));
		}
		let key = (resolver.to_string(), domains.clone());
		let mut certs = self.certs.lock().unwrap();
		if let Some(existing) = certs.get(&key).and_then(Weak::upgrade) {
			return Ok(existing);
		}
		let placeholder = self_signed(&domains, None).map_err(|e| ApiError::tls_config(format!("placeholder certificate: {e}")))?;
		let cert = Arc::new(ManagedCert {
			resolver: resolver.to_string(),
			domains: domains.clone(),
			current: RwLock::new(placeholder),
			status: RwLock::new(AcmeStatus {
				resolver: resolver.to_string(),
				domains: domains.clone(),
				state: "pending",
				not_after: None,
				error: None,
			}),
			issued: RwLock::new(None),
		});
		match self.load_stored(&cert) {
			Ok(Some((key, not_after))) => {
				cert.install(key, not_after);
				info!(event = "acme.load", resolver, domains = ?domains, not_after);
			}
			Ok(None) => {}
			Err(e) => warn!(event = "acme.error", resolver, domains = ?domains, error = %e, "stored certificate ignored"),
		}
		certs.retain(|_, w| w.strong_count() > 0);
		certs.insert(key, Arc::downgrade(&cert));
		// rules are also built outside a runtime in unit tests; there is nothing to obtain then
		if let Ok(handle) = tokio::runtime::Handle::try_current() {
			handle.spawn(self.clone().maintain(Arc::downgrade(&cert)));
		}
		Ok(cert)
	}

	fn cert_dir(&self, cert: &ManagedCert) -> PathBuf {
		self.storage.join("certs").join(safe_name(&cert.resolver)).join(cert_dir_name(&cert.domains))
	}

	/// A stored certificate that still covers every domain and has not expired.
	fn load_stored(&self, cert: &ManagedCert) -> Result<Option<(Arc<CertifiedKey>, u64)>, String> {
		let dir = self.cert_dir(cert);
		let (Ok(chain), Ok(key)) = (std::fs::read(dir.join("cert.pem")), std::fs::read(dir.join("key.pem"))) else {
			return Ok(None);
		};
		let (key, not_after, names) = load_pem(&chain, &key)?;
		if not_after <= now_secs() || !cert.domains.iter().all(|d| names.iter().any(|n| n.eq_ignore_ascii_case(d))) {
			return Ok(None);
		}
		Ok(Some((key, not_after)))
	}

	/// Obtains the certificate, then renews it, until no rule uses it any more.
	async fn maintain(self: Arc<Self>, cert: Weak<ManagedCert>) {
		let mut retry = FIRST_RETRY;
		loop {
			let wait = match cert.upgrade() {
				Some(c) => c.due_in(now_secs()),
				None => return,
			};
			if !wait.is_zero() {
				tokio::time::sleep(wait.min(MAX_SLEEP)).await;
				continue;
			}
			let Some(c) = cert.upgrade() else { return };
			let renewal = c.issued.read().unwrap().is_some();
			match self.issue(&c).await {
				Ok(not_after) => {
					retry = FIRST_RETRY;
					let event = if renewal { "acme.renew" } else { "acme.issue" };
					info!(event, resolver = %c.resolver, domains = ?c.domains, not_after);
				}
				Err(e) => {
					warn!(event = "acme.error", resolver = %c.resolver, domains = ?c.domains, error = %e,
						retry_secs = retry.as_secs());
					c.failed(e);
					drop(c);
					tokio::time::sleep(retry).await;
					retry = (retry * 2).min(MAX_RETRY);
				}
			}
		}
	}

	async fn account(&self, name: &str, r: &Resolver) -> Result<Account, String> {
		let mut accounts = self.accounts.lock().await;
		if let Some(a) = accounts.get(name) {
			return Ok(a.clone());
		}
		let builder = || match &r.ca_file {
			Some(ca) => Account::builder_with_root(ca),
			None => Account::builder(),
		};
		let path = self.storage.join("accounts").join(format!("{}.json", safe_name(name)));
		let stored = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice::<StoredAccount>(&b).ok());
		let account = match stored.filter(|s| s.directory == r.directory) {
			Some(s) => builder().map_err(|e| e.to_string())?.from_credentials(s.credentials).await.map_err(|e| e.to_string())?,
			None => {
				let contact = format!("mailto:{}", r.email);
				let contacts = [contact.as_str()];
				let (account, credentials) = builder()
					.map_err(|e| e.to_string())?
					.create(
						&NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false },
						r.directory.clone(),
						None,
					)
					.await
					.map_err(|e| format!("creating the account: {e}"))?;
				let stored = StoredAccount { directory: r.directory.clone(), credentials };
				let saved = serde_json::to_vec_pretty(&stored)
					.map_err(|e| e.to_string())
					.and_then(|json| {
						create_private_dir(path.parent().unwrap_or(&self.storage)).map_err(|e| e.to_string())?;
						write_private(&path, &json).map_err(|e| e.to_string())
					});
				if let Err(e) = saved {
					warn!(event = "acme.error", resolver = name, error = %format!("{}: {e}", path.display()),
						"account not stored; a new one is created after a restart");
				}
				info!(event = "acme.account", resolver = name, directory = %r.directory);
				account
			}
		};
		accounts.insert(name.to_string(), account.clone());
		Ok(account)
	}

	/// One order: answer the challenges, finalize, install and store the certificate.
	async fn issue(&self, cert: &ManagedCert) -> Result<u64, String> {
		let r = self.resolvers.get(&cert.resolver).ok_or("resolver disappeared")?;
		let account = self.account(&cert.resolver, r).await?;
		let identifiers: Vec<Identifier> = cert.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
		let mut order = account.new_order(&NewOrder::new(&identifiers)).await.map_err(|e| format!("new order: {e}"))?;
		let mut answers = Answers { tls_alpn: vec![], http: vec![] };
		let kind = match r.challenge {
			Challenge::Http01 => ChallengeType::Http01,
			Challenge::TlsAlpn01 => ChallengeType::TlsAlpn01,
			Challenge::Dns01 => return Err("dns-01 is not available".into()),
		};
		let mut authorizations = order.authorizations();
		while let Some(authz) = authorizations.next().await {
			let mut authz = authz.map_err(|e| format!("authorization: {e}"))?;
			match authz.status {
				AuthorizationStatus::Valid => continue,
				AuthorizationStatus::Pending => {}
				other => return Err(format!("authorization is {other:?}")),
			}
			let mut challenge = authz.challenge(kind.clone()).ok_or_else(|| format!("the CA offers no {} challenge", r_challenge(r)))?;
			let domain = challenge.identifier().to_string();
			let key_auth = challenge.key_authorization();
			match r.challenge {
				Challenge::Http01 => {
					let token = challenge.token.clone();
					pending().write().unwrap().http.insert(token.clone(), key_auth.as_str().to_string());
					answers.http.push(token);
				}
				Challenge::TlsAlpn01 => {
					let answer = self_signed(std::slice::from_ref(&domain), Some(key_auth.digest().as_ref()))?;
					let name = domain.to_ascii_lowercase();
					pending().write().unwrap().tls_alpn.insert(name.clone(), answer);
					answers.tls_alpn.push(name);
				}
				Challenge::Dns01 => unreachable!("refused above"),
			}
			debug!(event = "acme.challenge", resolver = %cert.resolver, domain, challenge = r_challenge(r));
			challenge.set_ready().await.map_err(|e| format!("challenge {domain}: {e}"))?;
		}
		let retry = RetryPolicy::new().timeout(Duration::from_secs(120)).initial_delay(Duration::from_millis(500));
		let status = order.poll_ready(&retry).await.map_err(|e| format!("waiting for validation: {e}"))?;
		if status != OrderStatus::Ready {
			let detail = order.state().error.as_ref().map(|p| p.to_string()).unwrap_or_default();
			return Err(format!("order is {status:?} {detail}").trim().to_string());
		}
		drop(answers);

		let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
		let csr = rcgen::CertificateParams::new(cert.domains.clone())
			.and_then(|p| p.serialize_request(&key))
			.map_err(|e| format!("CSR: {e}"))?;
		order.finalize_csr(csr.der()).await.map_err(|e| format!("finalize: {e}"))?;
		let chain_pem = order.poll_certificate(&retry).await.map_err(|e| format!("certificate: {e}"))?;
		let key_pem = key.serialize_pem();
		let (certified, not_after, _) = load_pem(chain_pem.as_bytes(), key_pem.as_bytes())?;
		cert.install(certified, not_after);

		let dir = self.cert_dir(cert);
		let stored = create_private_dir(&dir)
			.and_then(|()| write_private(&dir.join("key.pem"), key_pem.as_bytes()))
			.and_then(|()| write_private(&dir.join("cert.pem"), chain_pem.as_bytes()));
		if let Err(e) = stored {
			warn!(event = "acme.error", resolver = %cert.resolver, error = %format!("{}: {e}", dir.display()),
				"certificate not stored; it is obtained again after a restart");
		}
		Ok(not_after)
	}
}

fn r_challenge(r: &Resolver) -> &'static str {
	match r.challenge {
		Challenge::Http01 => "http-01",
		Challenge::TlsAlpn01 => "tls-alpn-01",
		Challenge::Dns01 => "dns-01",
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn renewal_is_due_30_days_before_expiry() {
		let day = 86_400;
		assert_eq!(renew_in(100 * day, 10 * day), Duration::from_secs(60 * day));
		assert_eq!(renew_in(100 * day, 70 * day), Duration::ZERO);
		assert_eq!(renew_in(100 * day, 200 * day), Duration::ZERO);
		assert_eq!(renew_in(10 * day, 0), Duration::ZERO, "a short-lived certificate is renewed at once");
	}

	#[test]
	fn domains_are_normalized_and_named() {
		let d = normalize(&["B.example.".into(), "a.example".into(), "b.example".into()]);
		assert_eq!(d, ["a.example", "b.example"]);
		let name = cert_dir_name(&d);
		assert!(name.starts_with("a.example-") && name.len() == "a.example-".len() + 8, "{name}");
		assert_ne!(name, cert_dir_name(&["a.example".to_string()]));
		assert_eq!(safe_name("le/../x"), "le____x");
	}

	fn manager(dir: &Path, challenge: &str) -> Arc<AcmeManager> {
		let yaml = format!(
			"resolvers: {{le: {{email: a@example.com, challenge: {challenge}, directory: 'https://127.0.0.1:1/dir'}}}}\nstorage: {}",
			dir.display()
		);
		AcmeManager::new(&crate::config::from_yaml::<AcmeGlobal>(&yaml).unwrap()).unwrap()
	}

	#[test]
	fn certificates_are_shared_and_reloaded_from_storage() {
		let dir = std::env::temp_dir().join(format!("rproxy-acme-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		let m = manager(&dir, "tls-alpn-01");
		assert!(m.storage_problem().is_none());
		assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);

		let a = m.certificate("le", &["www.example".into(), "example".into()]).unwrap();
		let b = m.certificate("le", &["example".into(), "WWW.example".into()]).unwrap();
		assert!(Arc::ptr_eq(&a, &b), "same resolver and domains share one certificate");
		assert_eq!(a.status().state, "pending");
		assert_eq!(crate::tlsconf::cert_names(&a.current().cert[0]), ["example", "www.example"], "placeholder");
		assert_eq!(a.due_in(now_secs()), Duration::ZERO);

		// a stored certificate is used at once, and renewed 30 days before it expires
		let params = rcgen::CertificateParams::new(vec!["x.example".to_string()]).unwrap();
		let key = rcgen::KeyPair::generate().unwrap();
		let issued = params.self_signed(&key).unwrap();
		let probe = m.certificate("le", &["x.example".into()]).unwrap();
		let cdir = m.cert_dir(&probe);
		drop(probe);
		create_private_dir(&cdir).unwrap();
		write_private(&cdir.join("cert.pem"), issued.pem().as_bytes()).unwrap();
		write_private(&cdir.join("key.pem"), key.serialize_pem().as_bytes()).unwrap();
		let loaded = m.certificate("le", &["x.example".into()]).unwrap();
		assert_eq!(loaded.status().state, "valid");
		assert_eq!(loaded.current().cert[0], *issued.der());
		assert!(loaded.due_in(now_secs()) > Duration::from_secs(86_400 * 365), "rcgen certificates last years");
		std::fs::remove_dir_all(&dir).unwrap();
	}

	#[test]
	fn refusals() {
		let dir = std::env::temp_dir().join(format!("rproxy-acme-refuse-{}", std::process::id()));
		let m = manager(&dir, "http-01");
		assert_eq!(m.certificate("nope", &["a.example".into()]).unwrap_err().code, "invalid");
		assert_eq!(m.certificate("le", &["*.a.example".into()]).unwrap_err().code, "tls_config");
		let yaml = "resolvers: {d: {email: a@b, challenge: dns-01, dns: {provider: x, credentials_file: /x}}}";
		let d = AcmeManager::new(&crate::config::from_yaml::<AcmeGlobal>(yaml).unwrap()).unwrap();
		assert_eq!(d.unsupported_resolvers(), ["d"]);
		assert_eq!(d.certificate("d", &["a.example".into()]).unwrap_err().code, "unsupported");
		let _ = std::fs::remove_dir_all(dir);
	}

	#[test]
	fn answers_are_withdrawn_when_the_order_ends() {
		pending().write().unwrap().http.insert("tok-1".into(), "tok-1.thumb".into());
		pending().write().unwrap().tls_alpn.insert("a.example".into(), self_signed(&["a.example".into()], Some(&[0; 32])).unwrap());
		assert_eq!(http_answer("/.well-known/acme-challenge/tok-1").as_deref(), Some("tok-1.thumb"));
		assert!(http_answer("/tok-1").is_none());
		assert!(tls_alpn_answer("A.example").is_some());
		drop(Answers { tls_alpn: vec!["a.example".into()], http: vec!["tok-1".into()] });
		assert!(http_answer("/.well-known/acme-challenge/tok-1").is_none());
		assert!(tls_alpn_answer("a.example").is_none());
	}
}
