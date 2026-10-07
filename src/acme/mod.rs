//! Certificates from an ACME CA (`global.acme`, `tls.certificates[].acme`, #208).
//!
//! `Acme` holds the settings (accounts, DNS providers, resolvers) and the
//! certificates the rules want (`set_wanted`, from the registry). One task
//! (`spawn`) obtains each certificate, writes it under `storage`, and renews
//! it before it expires; the registry's certificate store reads those files
//! like any other certificate files (`certstore::Source::Acme`), and swaps the
//! new certificate in on `on_change`. Until a certificate is first issued, the
//! store serves a self-signed stand-in.
//!
//! Challenges: HTTP-01 is answered by `http` rules and `http01_listen`,
//! TLS-ALPN-01 by `terminate` rules (`challenge`), DNS-01 through a DNS
//! provider (`dns`). Secrets stay in files named by the settings file; nothing
//! here is reachable from the control API but names and states.

pub mod challenge;
pub mod config;
pub mod dns;
pub mod dnsq;
pub mod helper;
pub mod http;
pub mod rfc2136;
pub mod store;

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine;
use instant_acme::{
	Account, AuthorizationStatus, ChallengeType, ExternalAccountKey, Identifier, Key, NewAccount, NewOrder, OrderStatus,
	RetryPolicy,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::error::ApiError;
use config::{AcmeGlobal, Challenge};

/// The first wait after a failed order; doubled up to `MAX_RETRY`.
const FIRST_RETRY: Duration = Duration::from_secs(60);
const MAX_RETRY: Duration = Duration::from_secs(6 * 3600);
/// The task looks at its certificates at least this often.
const MAX_SLEEP: Duration = Duration::from_secs(3600);
/// Renew this long before expiry, or a third of the lifetime if that is shorter.
const RENEW_BEFORE: i64 = 30 * 86_400;
/// How long the CA has to validate and to issue.
const ORDER_TIMEOUT: Duration = Duration::from_secs(180);

/// A certificate: the resolver that obtains it and its names (normalized, sorted).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct CertId {
	pub resolver: String,
	pub domains: Vec<String>,
}

impl CertId {
	pub fn new(resolver: &str, domains: &[String]) -> CertId {
		let mut d: Vec<String> = domains.iter().map(|d| config::normalize_name(d)).collect();
		d.sort();
		d.dedup();
		CertId { resolver: resolver.to_string(), domains: d }
	}
}

/// State of one certificate, in `GET /acme` and the rule view (`acme`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CertStatus {
	pub resolver: String,
	pub domains: Vec<String>,
	/// `pending` (not issued yet; a self-signed stand-in is served), `valid`,
	/// `renewing` (due for renewal), or `error` (the last attempt failed; a
	/// certificate issued earlier stays in use).
	pub state: &'static str,
	/// notAfter of the issued certificate (RFC 3339).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub not_after: Option<String>,
	/// When it is renewed (RFC 3339).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub renew_at: Option<String>,
	/// The next attempt after a failure, or while the rate limit holds it back (RFC 3339).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub next_attempt: Option<String>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
	/// The renewal window the CA suggests (ACME renewal information, RFC 9773),
	/// when it offers one; `renew_at` is a random point in it.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub ari: Option<AriWindow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AriWindow {
	/// RFC 3339.
	pub start: String,
	pub end: String,
}

/// A renewal window from the CA (Unix seconds) and the point chosen in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ari {
	start: i64,
	end: i64,
	at: i64,
}

/// ARI is asked again after the CA's Retry-After, within these bounds; after an error, `ARI_RETRY`.
const ARI_MIN_RECHECK: i64 = 3600;
const ARI_MAX_RECHECK: i64 = 24 * 3600;
const ARI_RETRY: i64 = 6 * 3600;

#[derive(Default)]
struct Managed {
	/// Validity of the issued certificate on disk (Unix seconds).
	issued: Option<(i64, i64)>,
	/// Not before this time (Unix seconds): after a failure, or rate limited.
	next_try: i64,
	failures: u32,
	error: Option<String>,
	/// Renew now (`POST /acme/renew`, `POST /acme/revoke`).
	force: bool,
	/// The CA's renewal window (RFC 9773), when it has one.
	ari: Option<Ari>,
	/// When to ask the CA for the renewal window (Unix seconds; `i64::MAX`: the CA has no ARI).
	ari_check: i64,
}

/// A uniformly random point in `[start, end]`.
fn random_in(start: i64, end: i64) -> i64 {
	if end <= start {
		return start;
	}
	let mut b = [0u8; 8];
	let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
	start + (u64::from_le_bytes(b) % ((end - start) as u64 + 1)) as i64
}

impl Managed {
	fn new(issued: Option<(i64, i64)>) -> Managed {
		Managed { issued, ..Default::default() }
	}

	fn renew_at(&self, renew_before: Option<Duration>) -> Option<i64> {
		let (not_before, not_after) = self.issued?;
		// the CA's suggestion first (it may ask for an early renewal, e.g. before a mass revocation)
		if let Some(ari) = self.ari {
			return Some(ari.at.min(not_after - 3600));
		}
		let before = match renew_before {
			Some(d) => d.as_secs() as i64,
			None => RENEW_BEFORE.min((not_after - not_before).max(0) / 3),
		};
		Some(not_after - before)
	}

	/// When this certificate needs an order (Unix seconds).
	fn due(&self, renew_before: Option<Duration>) -> i64 {
		if self.force {
			return self.next_try;
		}
		match self.renew_at(renew_before) {
			None => self.next_try,
			Some(at) => at.max(self.next_try),
		}
	}
}

struct AccountCfg {
	directory: String,
	contact: Vec<String>,
	key_file: PathBuf,
	eab: Option<config::EabSpec>,
	ca_file: Option<String>,
	allowed_names: Vec<String>,
}

struct ResolverCfg {
	account: String,
	challenge: Challenge,
	dns_provider: Option<String>,
}

#[derive(Default)]
struct State {
	certs: BTreeMap<CertId, Managed>,
	/// Start of each order within the rate limit's period.
	orders: VecDeque<Instant>,
	/// Accounts loaded at the CA (`accounts` view: registered).
	registered: BTreeSet<String>,
}

/// What `<storage>/accounts/<name>.json` holds: the account URL (not a secret).
#[derive(Serialize, Deserialize)]
struct AccountMeta {
	directory: String,
	url: String,
}

type OnChange = Box<dyn Fn() + Send + Sync>;

pub struct Acme {
	global: AcmeGlobal,
	storage: PathBuf,
	accounts: BTreeMap<String, AccountCfg>,
	/// Who writes DNS-01 records (this process, or the helper).
	dns: dns::Backend,
	resolvers: BTreeMap<String, ResolverCfg>,
	orders_limit: u32,
	period: Duration,
	renew_before: Option<Duration>,
	dns_servers: Vec<SocketAddr>,
	propagation: Duration,
	http01_listen: Vec<SocketAddr>,
	journal: dns::Journal,
	state: Mutex<State>,
	wake: Notify,
	on_change: OnceLock<OnChange>,
	clients: tokio::sync::Mutex<HashMap<String, Account>>,
	stop: CancellationToken,
}

impl std::fmt::Debug for Acme {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Acme").field("storage", &self.storage).finish_non_exhaustive()
	}
}

fn now() -> i64 {
	crate::tls::config::unix_now()
}

fn rfc3339(t: i64) -> String {
	crate::tls::certstore::rfc3339(t)
}

/// Validity (notBefore, notAfter) of the first certificate in a PEM file.
fn validity(cert_file: &str) -> Option<(i64, i64)> {
	let data = std::fs::read(cert_file).ok()?;
	let first = CertificateDer::pem_slice_iter(&data).next()?.ok()?;
	let check = crate::tls::config::inspect_certificate(first.as_ref(), now()).ok()?;
	Some((check.not_before, check.not_after))
}

impl Acme {
	/// Sets up `global.acme` (already checked by `ConfigDoc::load`). Nothing
	/// starts until `spawn`.
	pub fn new(global: &AcmeGlobal) -> Result<Arc<Acme>, String> {
		global.check()?;
		let storage = PathBuf::from(global.storage.clone().unwrap_or_else(|| config::DEFAULT_STORAGE.to_string()));
		let accounts = global
			.accounts
			.iter()
			.map(|(name, a)| {
				let key_file = a.key_file.clone().map(PathBuf::from).unwrap_or_else(|| storage.join("accounts").join(format!("{name}.key")));
				let cfg = AccountCfg {
					directory: a.directory.clone().unwrap_or_else(|| config::LETS_ENCRYPT.to_string()),
					contact: a.contact.clone(),
					key_file,
					eab: a.eab.clone(),
					ca_file: a.ca_file.clone(),
					allowed_names: a.allowed_names.clone(),
				};
				(name.clone(), cfg)
			})
			.collect();
		// files named in the settings must exist (a mistake stops the startup);
		// one that cannot be read now is reported when it is used
		for (what, file) in Self::named_files(global) {
			if let Err(e) = std::fs::metadata(&file) {
				if e.kind() == std::io::ErrorKind::NotFound {
					return Err(format!("global.acme.{what}: {file} does not exist"));
				}
			}
		}
		for (name, a) in &global.accounts {
			http::connector(a.ca_file.as_deref()).map_err(|e| format!("global.acme.accounts.{name}.ca_file: {e}"))?;
		}
		// with the helper, the DNS providers (and their secrets) are its business
		let dns = match &global.helper {
			Some(h) => dns::Backend::Helper(PathBuf::from(&h.socket)),
			None => {
				let mut providers = BTreeMap::new();
				for (name, p) in &global.dns_providers {
					providers.insert(name.clone(), dns::Provider::new(name, p).map_err(|e| format!("global.acme.dns_providers.{name}: {e}"))?);
				}
				dns::Backend::Local(providers)
			}
		};
		let resolvers = global
			.resolvers
			.iter()
			.map(|(name, r)| {
				let cfg = ResolverCfg {
					account: r.account.clone(),
					challenge: Challenge::parse(&r.challenge).unwrap_or(Challenge::Http01),
					dns_provider: r.dns_provider.clone(),
				};
				(name.clone(), cfg)
			})
			.collect();
		let duration = |s: &Option<String>, default| s.as_deref().map(config::parse_duration).transpose().map(|d| d.unwrap_or(default));
		let dns_servers = if global.dns_servers.is_empty() {
			dnsq::system_servers()
		} else {
			global.dns_servers.iter().map(|s| config::parse_dns_server(s)).collect::<Result<_, _>>()?
		};
		Ok(Arc::new(Acme {
			storage: storage.clone(),
			accounts,
			dns,
			resolvers,
			orders_limit: global.rate_limit.as_ref().map_or(config::DEFAULT_ORDERS, |l| l.orders),
			period: duration(&global.rate_limit.as_ref().and_then(|l| l.period.clone()), config::DEFAULT_PERIOD)?,
			renew_before: global.renew_before.as_deref().map(config::parse_duration).transpose()?,
			dns_servers,
			propagation: duration(&global.dns_propagation_timeout, config::DEFAULT_PROPAGATION)?,
			http01_listen: global.http01_listen.iter().filter_map(|s| s.parse().ok()).collect(),
			journal: dns::Journal::new(&storage),
			state: Mutex::default(),
			wake: Notify::new(),
			on_change: OnceLock::new(),
			clients: tokio::sync::Mutex::default(),
			stop: CancellationToken::new(),
			global: global.clone(),
		}))
	}

	pub fn storage(&self) -> &Path {
		&self.storage
	}

	/// The addresses of `http01_listen` (rules may not take them).
	pub fn http01_listen(&self) -> &[SocketAddr] {
		&self.http01_listen
	}

	/// Files the settings name (where, file): secrets and CA certificates.
	fn named_files(global: &AcmeGlobal) -> Vec<(String, String)> {
		let mut out = vec![];
		// with the helper, these files are its own (this process may not even see them)
		for (name, p) in global.dns_providers.iter().filter(|_| global.helper.is_none()) {
			out.extend(dns::Provider::required_files(p).into_iter().map(|f| (format!("dns_providers.{name}"), f)));
		}
		for (name, a) in &global.accounts {
			out.extend(a.eab.as_ref().map(|e| (format!("accounts.{name}.eab"), e.hmac_key_file.clone())));
			out.extend(a.ca_file.clone().map(|f| (format!("accounts.{name}.ca_file"), f)));
		}
		out
	}

	/// Files read while running, for `--check-config`'s readability warnings.
	pub fn secret_files(&self) -> Vec<String> {
		let mut out: Vec<String> = Self::named_files(&self.global).into_iter().map(|(_, f)| f).collect();
		if self.global.helper.is_none() {
			out.extend(self.global.dns_providers.values().filter_map(|p| p.credentials_file.clone()));
		}
		out
	}

	/// Whether the storage directory can be written; the error for `degraded`.
	pub fn storage_problem(&self) -> Option<String> {
		let probe = self.storage.join(".rproxy-write-test");
		let result = store::write_private(&probe, b"ok");
		let _ = std::fs::remove_file(&probe);
		result.err().map(|e| format!("{}: {e}", self.storage.display()))
	}

	/// Called after a certificate was written (the registry reloads it).
	pub fn set_on_change(&self, f: OnChange) {
		let _ = self.on_change.set(f);
	}

	/// Checks a rule's `{acme, domains}` entry: the resolver exists and every
	/// name is valid and allowed (`400 invalid` otherwise).
	pub fn check(&self, resolver: &str, domains: &[String]) -> Result<CertId, ApiError> {
		self.global.check_names(resolver, domains).map_err(ApiError::invalid)?;
		Ok(CertId::new(resolver, domains))
	}

	/// The (certificate, key) files of a certificate.
	pub fn files(&self, id: &CertId) -> (String, String) {
		store::cert_files(&self.storage, &id.resolver, &id.domains)
	}

	/// The certificates the rules use now: new ones are obtained, ones no rule
	/// uses any more are no longer renewed (their files stay).
	pub fn set_wanted(&self, wanted: BTreeSet<CertId>) {
		let mut changed = false;
		{
			let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
			let before = state.certs.len();
			state.certs.retain(|id, _| wanted.contains(id));
			changed |= state.certs.len() != before;
			for id in wanted {
				if state.certs.contains_key(&id) {
					continue;
				}
				let (cert, _) = self.files(&id);
				state.certs.insert(id, Managed::new(validity(&cert)));
				changed = true;
			}
		}
		if changed {
			self.wake.notify_one();
		}
	}

	fn status_of(&self, id: &CertId, m: &Managed) -> CertStatus {
		let renew_at = m.renew_at(self.renew_before);
		let t = now();
		let state = match (&m.issued, &m.error) {
			(_, Some(_)) => "error",
			(None, None) => "pending",
			(Some(_), None) if m.force || renew_at.is_some_and(|r| r <= t) => "renewing",
			(Some(_), None) => "valid",
		};
		CertStatus {
			resolver: id.resolver.clone(),
			domains: id.domains.clone(),
			state,
			not_after: m.issued.map(|(_, a)| rfc3339(a)),
			renew_at: renew_at.map(rfc3339),
			next_attempt: (m.next_try > t).then(|| rfc3339(m.next_try)),
			error: m.error.clone(),
			ari: m.ari.map(|a| AriWindow { start: rfc3339(a.start), end: rfc3339(a.end) }),
		}
	}

	/// The state of one certificate.
	pub fn status(&self, id: &CertId) -> Option<CertStatus> {
		let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
		state.certs.get(id).map(|m| self.status_of(id, m))
	}

	/// `GET /acme`: names and states only (no secret, no file of one).
	pub fn view(&self) -> serde_json::Value {
		let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
		let accounts: Vec<serde_json::Value> = self
			.accounts
			.iter()
			.map(|(name, a)| {
				serde_json::json!({
					"name": name,
					"directory": a.directory,
					"contact": a.contact,
					"eab": a.eab.is_some(),
					"allowed_names": a.allowed_names,
					"registered": state.registered.contains(name) || self.account_meta(name, a).is_some(),
				})
			})
			.collect();
		let providers: Vec<serde_json::Value> = self
			.global
			.dns_providers
			.iter()
			.map(|(name, p)| serde_json::json!({"name": name, "type": p.kind, "zones": p.zones, "allowed_names": p.allowed_names}))
			.collect();
		let resolvers: Vec<serde_json::Value> = self
			.resolvers
			.iter()
			.map(|(name, r)| serde_json::json!({"name": name, "account": r.account, "challenge": r.challenge.as_str(), "dns_provider": r.dns_provider}))
			.collect();
		let certificates: Vec<CertStatus> = state.certs.iter().map(|(id, m)| self.status_of(id, m)).collect();
		let since = Instant::now().checked_sub(self.period);
		let used = state.orders.iter().filter(|t| since.is_none_or(|s| **t >= s)).count();
		serde_json::json!({
			"accounts": accounts,
			"dns_providers": providers,
			"resolvers": resolvers,
			"certificates": certificates,
			"rate_limit": {"orders": self.orders_limit, "period_secs": self.period.as_secs(), "used": used},
			"helper": matches!(self.dns, dns::Backend::Helper(_)),
		})
	}

	/// Starts the task that obtains and renews certificates (and removes TXT
	/// records left over from before), and the HTTP-01 responder. Returns the
	/// addresses of `http01_listen` that could not be opened.
	pub async fn spawn(self: &Arc<Self>) -> Vec<(SocketAddr, String)> {
		let mut failed = vec![];
		for addr in &self.http01_listen {
			match challenge::serve_http01(*addr, self.stop.clone()).await {
				Ok(()) => info!(event = "acme.listening", addr = %addr),
				Err(e) => failed.push((*addr, e.to_string())),
			}
		}
		let me = self.clone();
		tokio::spawn(async move { me.run().await });
		failed
	}

	pub fn shutdown(&self) {
		self.stop.cancel();
	}

	/// `POST /acme/renew`: renews a certificate now (still within the rate limit).
	pub fn renew(&self, id: &CertId) -> Result<(), ApiError> {
		{
			let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
			let m = state.certs.get_mut(id).ok_or_else(|| ApiError::not_found("no rule uses this acme certificate"))?;
			m.force = true;
			m.next_try = 0;
		}
		self.wake.notify_one();
		Ok(())
	}

	fn account_meta(&self, name: &str, a: &AccountCfg) -> Option<String> {
		let path = self.storage.join("accounts").join(format!("{name}.json"));
		let meta: AccountMeta = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
		(meta.directory == a.directory && a.key_file.exists()).then_some(meta.url)
	}

	/// The account at the CA: the stored one, or a new one (its key is written
	/// to `key_file`, 0600).
	async fn account(&self, name: &str) -> Result<Account, String> {
		let mut clients = self.clients.lock().await;
		if let Some(a) = clients.get(name) {
			return Ok(a.clone());
		}
		let cfg = self.accounts.get(name).ok_or_else(|| format!("account {name:?} is not configured"))?;
		let builder = || http::AcmeHttp::new(cfg.ca_file.as_deref()).map(|h| Account::builder_with_http(Box::new(h)));
		let meta_path = self.storage.join("accounts").join(format!("{name}.json"));
		let contacts: Vec<&str> = cfg.contact.iter().map(String::as_str).collect();
		let account = if cfg.key_file.exists() {
			let pem = crate::net::files::read(&cfg.key_file, crate::net::files::Kind::Secret).map_err(|e| format!("{}: {e}", cfg.key_file.display()))?;
			let der = PrivatePkcs8KeyDer::from_pem_slice(&pem)
				.map_err(|e| format!("{}: not a PKCS#8 key: {e}", cfg.key_file.display()))?;
			match self.account_meta(name, cfg) {
				Some(url) => builder()?.from_parts(url, der, cfg.directory.clone()).await.map_err(|e| format!("account {name}: {e}"))?,
				None => {
					let key = Key::from_pkcs8_der(der.clone_key()).map_err(|e| format!("{}: {e}", cfg.key_file.display()))?;
					let (account, _) = builder()?
						.create_from_key((key, PrivateKeyDer::Pkcs8(der)), cfg.directory.clone())
						.await
						.map_err(|e| format!("account {name}: {e}"))?;
					if !contacts.is_empty() {
						if let Err(e) = account.update_contacts(&contacts).await {
							warn!(event = "acme.account", account = name, outcome = "error", error = %e, "contact not updated");
						}
					}
					self.save_meta(&meta_path, cfg, account.id());
					info!(event = "acme.account", account = name, action = "found", directory = %cfg.directory);
					account
				}
			}
		} else {
			let eab = match &cfg.eab {
				Some(e) => {
					let text = crate::net::files::read_to_string(&e.hmac_key_file, crate::net::files::Kind::Secret).map_err(|err| format!("{}: {err}", e.hmac_key_file))?;
					let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
						.decode(text.trim().trim_end_matches('='))
						.map_err(|_| format!("{}: the HMAC key is not base64url", e.hmac_key_file))?;
					Some(ExternalAccountKey::new(e.kid.clone(), &raw))
				}
				None => None,
			};
			let new = NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false };
			let (account, credentials) =
				builder()?.create(&new, cfg.directory.clone(), eab.as_ref()).await.map_err(|e| format!("creating account {name}: {e}"))?;
			let pem = store::pem("PRIVATE KEY", credentials.private_key().secret_pkcs8_der());
			store::write_private(&cfg.key_file, pem.as_bytes())
				.map_err(|e| format!("account {name}: {}: {e} (the account was created at the CA, but its key could not be kept)", cfg.key_file.display()))?;
			self.save_meta(&meta_path, cfg, account.id());
			info!(event = "acme.account", account = name, action = "created", directory = %cfg.directory);
			account
		};
		self.state.lock().unwrap_or_else(|e| e.into_inner()).registered.insert(name.to_string());
		clients.insert(name.to_string(), account.clone());
		Ok(account)
	}

	fn save_meta(&self, path: &Path, cfg: &AccountCfg, url: &str) {
		let meta = AccountMeta { directory: cfg.directory.clone(), url: url.to_string() };
		if let Err(e) = store::write_private(path, &serde_json::to_vec_pretty(&meta).unwrap_or_default()) {
			warn!(event = "acme.error", part = "account", file = %path.display(), error = %e);
		}
	}

	/// `POST /acme/accounts/{name}/register`: makes sure the account exists at the CA.
	pub async fn register(&self, name: &str) -> Result<(), ApiError> {
		if !self.accounts.contains_key(name) {
			return Err(ApiError::not_found(format!("account {name:?} is not in global.acme.accounts")));
		}
		self.account(name).await.map(|_| ()).map_err(ApiError::internal)
	}

	/// `POST /acme/accounts/{name}/deactivate`: deactivates the account at the
	/// CA and sets its key aside (`<key_file>.deactivated`); the next order
	/// creates a new account.
	pub async fn deactivate(&self, name: &str) -> Result<(), ApiError> {
		let cfg = self.accounts.get(name).ok_or_else(|| ApiError::not_found(format!("account {name:?} is not in global.acme.accounts")))?;
		if !cfg.key_file.exists() {
			return Err(ApiError::invalid(format!("account {name:?} has no key; there is nothing to deactivate")));
		}
		let account = self.account(name).await.map_err(ApiError::internal)?;
		account.deactivate().await.map_err(|e| ApiError::internal(format!("account {name}: {e}")))?;
		self.clients.lock().await.remove(name);
		self.state.lock().unwrap_or_else(|e| e.into_inner()).registered.remove(name);
		let mut aside = cfg.key_file.clone().into_os_string();
		aside.push(".deactivated");
		let _ = std::fs::rename(&cfg.key_file, &aside);
		let _ = std::fs::remove_file(self.storage.join("accounts").join(format!("{name}.json")));
		info!(event = "acme.account", account = name, action = "deactivated");
		Ok(())
	}

	/// Takes one order from the rate limit, or says how long to wait.
	fn take_order(&self) -> Result<(), Duration> {
		let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
		let now = Instant::now();
		while state.orders.front().is_some_and(|t| now.duration_since(*t) >= self.period) {
			state.orders.pop_front();
		}
		if state.orders.len() >= self.orders_limit as usize {
			let oldest = state.orders.front().copied().unwrap_or(now);
			return Err(self.period.saturating_sub(now.duration_since(oldest)));
		}
		state.orders.push_back(now);
		Ok(())
	}

	async fn run(self: Arc<Self>) {
		// TXT records a crash or a failed removal left behind
		let leftover = self.journal.read();
		if !leftover.is_empty() {
			dns::remove_all(&self.dns, &self.journal, &leftover, "left over").await;
		}
		loop {
			// the CA's renewal windows (RFC 9773) for issued certificates
			let ari_due: Vec<CertId> = {
				let t = now();
				let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
				state.certs.iter().filter(|(_, m)| m.issued.is_some() && m.ari_check <= t).map(|(id, _)| id.clone()).collect()
			};
			for id in ari_due {
				tokio::select! {
					_ = self.stop.cancelled() => return,
					_ = self.check_ari(&id) => {}
				}
			}
			let t = now();
			let (next, next_ari) = {
				let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
				let next = state.certs.iter().map(|(id, m)| (m.due(self.renew_before), id.clone())).min();
				let ari = state.certs.values().filter(|m| m.issued.is_some()).map(|m| m.ari_check).min();
				(next, ari)
			};
			let wait = match &next {
				Some((due, _)) if *due <= t => Duration::ZERO,
				Some((due, _)) => Duration::from_secs((due - t) as u64).min(MAX_SLEEP),
				None => MAX_SLEEP,
			};
			let wait = match next_ari {
				Some(at) if at > t => wait.min(Duration::from_secs((at - t) as u64)),
				Some(_) if !wait.is_zero() => continue,
				_ => wait,
			};
			if !wait.is_zero() {
				tokio::select! {
					_ = self.stop.cancelled() => return,
					_ = self.wake.notified() => {}
					_ = tokio::time::sleep(wait) => {}
				}
				continue;
			}
			let Some((_, id)) = next else { continue };
			if let Err(wait) = self.take_order() {
				let until = now() + wait.as_secs() as i64 + 1;
				warn!(event = "acme.rate_limited", resolver = %id.resolver, domains = ?id.domains, retry_at = %rfc3339(until),
					limit = self.orders_limit, period_secs = self.period.as_secs());
				if let Some(m) = self.state.lock().unwrap_or_else(|e| e.into_inner()).certs.get_mut(&id) {
					m.next_try = until;
				}
				continue;
			}
			let renewal = self.status(&id).is_some_and(|s| s.not_after.is_some());
			info!(event = "acme.order", resolver = %id.resolver, domains = ?id.domains, renewal);
			let result = tokio::select! {
				_ = self.stop.cancelled() => return,
				r = self.issue(&id) => r,
			};
			let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
			let Some(m) = state.certs.get_mut(&id) else { continue };
			match result {
				Ok((not_before, not_after)) => {
					m.issued = Some((not_before, not_after));
					m.failures = 0;
					m.error = None;
					m.force = false;
					m.next_try = 0;
					// a new certificate: ask for its renewal window (unless the CA has none)
					m.ari = None;
					if m.ari_check != i64::MAX {
						m.ari_check = 0;
					}
					let event = if renewal { "acme.renew" } else { "acme.issue" };
					info!(event, resolver = %id.resolver, domains = ?id.domains, not_after = %rfc3339(not_after));
					drop(state);
					if let Some(f) = self.on_change.get() {
						f();
					}
				}
				Err(e) => {
					let wait = FIRST_RETRY.saturating_mul(1 << m.failures.min(10)).min(MAX_RETRY);
					m.failures += 1;
					m.next_try = now() + wait.as_secs() as i64;
					m.error = Some(e.clone());
					error!(event = "acme.error", resolver = %id.resolver, domains = ?id.domains, error = %e,
						retry_at = %rfc3339(m.next_try), failures = m.failures);
				}
			}
		}
	}

	/// The issued certificate on disk (leaf).
	fn issued_cert(&self, id: &CertId) -> Result<CertificateDer<'static>, String> {
		let (cert, _) = self.files(id);
		let data = std::fs::read(&cert).map_err(|e| format!("{cert}: {e}"))?;
		CertificateDer::pem_slice_iter(&data).next().ok_or("no certificate")?.map_err(|e| e.to_string())
	}

	/// The certificate's ARI identifier (authority key identifier and serial).
	fn cert_identifier(&self, id: &CertId) -> Result<instant_acme::CertificateIdentifier<'static>, String> {
		let der = self.issued_cert(id)?;
		instant_acme::CertificateIdentifier::try_from(&der).map(|c| c.into_owned())
	}

	/// Asks the CA for the certificate's renewal window (RFC 9773) and picks
	/// the time to renew in it. A CA without ARI is not asked again.
	async fn check_ari(&self, id: &CertId) {
		let result: Result<(instant_acme::RenewalInfo, Duration), (bool, String)> = async {
			let r = self.resolvers.get(&id.resolver).ok_or((false, "the resolver is no longer configured".to_string()))?;
			let cid = self.cert_identifier(id).map_err(|e| (false, e))?;
			let account = self.account(&r.account).await.map_err(|e| (false, e))?;
			account.renewal_info(&cid).await.map_err(|e| (matches!(e, instant_acme::Error::Unsupported(_)), e.to_string()))
		}
		.await;
		let t = now();
		let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
		let Some(m) = state.certs.get_mut(id) else { return };
		match result {
			Ok((info, retry)) => {
				let (start, end) = (info.suggested_window.start.unix_timestamp(), info.suggested_window.end.unix_timestamp());
				let at = match m.ari {
					// the same window: keep the point chosen before
					Some(a) if a.start == start && a.end == end => a.at,
					_ => random_in(start, end),
				};
				if m.ari.is_none_or(|a| a.at != at) {
					info!(event = "acme.ari", resolver = %id.resolver, domains = ?id.domains, start = %rfc3339(start), end = %rfc3339(end), renew_at = %rfc3339(at));
				}
				m.ari = Some(Ari { start, end, at });
				m.ari_check = t + (retry.as_secs() as i64).clamp(ARI_MIN_RECHECK, ARI_MAX_RECHECK);
			}
			Err((true, _)) => m.ari_check = i64::MAX,
			Err((false, e)) => {
				debug!(event = "acme.ari", resolver = %id.resolver, domains = ?id.domains, error = %e);
				m.ari_check = t + ARI_RETRY;
			}
		}
	}

	/// `POST /acme/revoke`: revokes the issued certificate at the CA, then
	/// orders a new one at once (within the rate limit). The revoked one is
	/// served until the new one is written.
	pub async fn revoke(&self, id: &CertId, reason: Option<instant_acme::RevocationReason>) -> Result<(), ApiError> {
		if self.status(id).is_none() {
			return Err(ApiError::not_found("no rule uses this acme certificate"));
		}
		let der = self.issued_cert(id).map_err(|_| ApiError::not_found("this acme certificate has not been issued"))?;
		let r = self.resolvers.get(&id.resolver).ok_or_else(|| ApiError::not_found("the resolver is no longer configured"))?;
		let account = self.account(&r.account).await.map_err(ApiError::internal)?;
		let reason_text = reason.as_ref().map(|r| format!("{r:?}")).unwrap_or_default();
		account
			.revoke(&instant_acme::RevocationRequest { certificate: &der, reason })
			.await
			.map_err(|e| ApiError::internal(format!("revoke: {e}")))?;
		info!(event = "acme.revoke", resolver = %id.resolver, domains = ?id.domains, reason = %reason_text);
		{
			let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
			if let Some(m) = state.certs.get_mut(id) {
				m.force = true;
				m.next_try = 0;
				m.ari = None;
			}
		}
		self.wake.notify_one();
		Ok(())
	}

	/// One order: answer the challenges, finalize, write the certificate.
	/// Returns its validity.
	async fn issue(&self, id: &CertId) -> Result<(i64, i64), String> {
		let r = self.resolvers.get(&id.resolver).ok_or("the resolver is no longer configured")?;
		// the settings may have changed since the rule was checked
		self.global.check_names(&id.resolver, &id.domains)?;
		let account = self.account(&r.account).await?;
		let identifiers: Vec<Identifier> = id.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
		// a renewal names the certificate it replaces when the CA has ARI (RFC 9773 5.)
		let replaces = {
			let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
			state.certs.get(id).is_some_and(|m| m.ari.is_some())
		}
		.then(|| self.cert_identifier(id).ok())
		.flatten();
		let mut order = match replaces {
			Some(cid) => match account.new_order(&NewOrder::new(&identifiers).replaces(cid)).await {
				Ok(o) => o,
				// the CA may refuse it (already replaced): order without it
				Err(e) => {
					debug!(event = "acme.order", resolver = %id.resolver, error = %e, "ordering without replaces");
					account.new_order(&NewOrder::new(&identifiers)).await.map_err(|e| format!("new order: {e}"))?
				}
			},
			None => account.new_order(&NewOrder::new(&identifiers)).await.map_err(|e| format!("new order: {e}"))?,
		};
		let kind = match r.challenge {
			Challenge::Http01 => ChallengeType::Http01,
			Challenge::TlsAlpn01 => ChallengeType::TlsAlpn01,
			Challenge::Dns01 => ChallengeType::Dns01,
		};
		let provider = r.dns_provider.as_deref();

		// first the answers for every authorization, then tell the CA
		let mut answers = challenge::Answers::default();
		let mut records: Vec<dns::Written> = vec![];
		{
			let mut authorizations = order.authorizations();
			while let Some(authz) = authorizations.next().await {
				let mut authz = authz.map_err(|e| format!("authorization: {e}"))?;
				match authz.status {
					AuthorizationStatus::Valid => continue,
					AuthorizationStatus::Pending => {}
					other => return Err(format!("authorization is {other:?}")),
				}
				let Identifier::Dns(domain) = authz.identifier().identifier.clone() else {
					return Err("an identifier that is not a DNS name".into());
				};
				let challenge = authz.challenge(kind.clone()).ok_or_else(|| format!("the CA offers no {} challenge for {domain}", r.challenge.as_str()))?;
				let key_auth = challenge.key_authorization();
				match r.challenge {
					Challenge::Http01 => answers.add_http(&challenge.token, key_auth.as_str()),
					Challenge::TlsAlpn01 => answers.add_tls_alpn(&domain, key_auth.digest().as_ref())?,
					Challenge::Dns01 => {
						let p = provider.ok_or("dns-01 without a dns provider")?;
						records.push(self.dns.locate(p, &domain, &key_auth.dns_value(), &self.dns_servers).await?);
					}
				}
				debug!(event = "acme.challenge", resolver = %id.resolver, domain, challenge = r.challenge.as_str());
			}
		}
		let result = self.validate_and_finalize(&mut order, kind, &records, id).await;
		drop(answers);
		if !records.is_empty() {
			dns::remove_all(&self.dns, &self.journal, &records, "validated").await;
		}
		result
	}

	async fn validate_and_finalize(
		&self,
		order: &mut instant_acme::Order,
		kind: ChallengeType,
		records: &[dns::Written],
		id: &CertId,
	) -> Result<(i64, i64), String> {
		if !records.is_empty() {
			self.journal.add(records);
			for ((provider, fqdn), group) in dns::by_name(records) {
				self.dns.present(&provider, &group).await.map_err(|e| format!("dns provider {provider}: {e}"))?;
				info!(event = "acme.dns", action = "add", provider, fqdn, zone = %group[0].zone, outcome = "ok");
			}
			if !dns::wait_visible(&self.dns_servers, records, self.propagation).await {
				warn!(event = "acme.dns", action = "wait", resolver = %id.resolver, timeout_secs = self.propagation.as_secs(),
					"the TXT record is not visible yet; asking the CA anyway");
			}
		}
		{
			let mut authorizations = order.authorizations();
			while let Some(authz) = authorizations.next().await {
				let mut authz = authz.map_err(|e| format!("authorization: {e}"))?;
				if authz.status != AuthorizationStatus::Pending {
					continue;
				}
				let mut challenge = authz.challenge(kind.clone()).ok_or("the challenge disappeared")?;
				challenge.set_ready().await.map_err(|e| format!("challenge: {e}"))?;
			}
		}
		let retry = RetryPolicy::new().timeout(ORDER_TIMEOUT).initial_delay(Duration::from_millis(500)).backoff(1.5);
		let status = order.poll_ready(&retry).await.map_err(|e| format!("validation: {e}"))?;
		if status != OrderStatus::Ready {
			return Err(format!("the order is {status:?}"));
		}
		let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
		let mut params = rcgen::CertificateParams::new(id.domains.clone()).map_err(|e| format!("CSR: {e}"))?;
		params.distinguished_name = rcgen::DistinguishedName::new();
		let csr = params.serialize_request(&key).map_err(|e| format!("CSR: {e}"))?;
		order.finalize_csr(csr.der()).await.map_err(|e| format!("finalize: {e}"))?;
		let chain = order.poll_certificate(&retry).await.map_err(|e| format!("certificate: {e}"))?;

		// check what came back before it replaces anything
		let (cert_file, key_file) = self.files(id);
		let key_pem = key.serialize_pem();
		let chain_der: Vec<CertificateDer<'static>> =
			CertificateDer::pem_slice_iter(chain.as_bytes()).collect::<Result<_, _>>().map_err(|e| format!("certificate: {e}"))?;
		let first = chain_der.first().ok_or("the CA sent no certificate")?;
		let check = crate::tls::config::inspect_certificate(first.as_ref(), now())?;
		let names = crate::tls::config::cert_names(first);
		if let Some(missing) = id.domains.iter().find(|d| !names.iter().any(|n| n.eq_ignore_ascii_case(d))) {
			return Err(format!("the certificate does not hold {missing}"));
		}
		// the key first: the certificate store reloads once the certificate changes
		store::write_private(Path::new(&key_file), key_pem.as_bytes()).map_err(|e| format!("{key_file}: {e}"))?;
		store::write_private(Path::new(&cert_file), chain.as_bytes()).map_err(|e| format!("{cert_file}: {e}"))?;
		Ok((check.not_before, check.not_after))
	}
}

/// A self-signed stand-in for a certificate that has not been issued yet:
/// (chain, PKCS#8 key) DER.
pub fn placeholder(domains: &[String]) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
	let (cert, key) = challenge::self_signed(domains, None)?;
	Ok((vec![CertificateDer::from(cert)], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key))))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn manager(dir: &Path, extra: &str) -> Arc<Acme> {
		let yaml = format!(
			"storage: {}\naccounts: {{le: {{directory: 'https://127.0.0.1:1/dir', allowed_names: ['**.example.com', example.com]}}}}\nresolvers: {{le: {{account: le, challenge: tls-alpn-01}}}}\n{extra}",
			dir.display()
		);
		Acme::new(&crate::config::from_yaml::<AcmeGlobal>(&yaml).unwrap()).unwrap()
	}

	#[test]
	fn renewal_is_due_30_days_or_a_third_of_the_lifetime_before_expiry() {
		let day = 86_400;
		let m = |nb, na| Managed::new(Some((nb, na)));
		assert_eq!(m(0, 90 * day).due(None), 60 * day);
		assert_eq!(m(0, 6 * day).due(None), 4 * day, "short-lived: a third of the lifetime");
		assert_eq!(m(0, 90 * day).due(Some(Duration::from_secs(10 * day as u64))), 80 * day);
		let mut failed = m(0, 90 * day);
		failed.next_try = 70 * day;
		assert_eq!(failed.due(None), 70 * day, "a failure waits");
		failed.force = true;
		assert_eq!(failed.due(None), 70 * day);
		let fresh = Managed::new(None);
		assert_eq!(fresh.due(None), 0, "not issued: now");
		// the CA's window (ARI) wins over the default rule, but not past expiry
		let mut ari = m(0, 90 * day);
		ari.ari = Some(Ari { start: 20 * day, end: 21 * day, at: 20 * day + 5 });
		assert_eq!(ari.due(None), 20 * day + 5);
		ari.ari = Some(Ari { start: 95 * day, end: 96 * day, at: 95 * day });
		assert_eq!(ari.due(None), 90 * day - 3600);
		for _ in 0..100 {
			let p = random_in(10, 20);
			assert!((10..=20).contains(&p));
		}
		assert_eq!(random_in(5, 5), 5);
	}

	#[test]
	fn wanted_certificates_and_their_state() {
		let dir = std::env::temp_dir().join(format!("rproxy-acme-mgr-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		let m = manager(&dir, "");
		assert!(m.storage_problem().is_none());
		let id = m.check("le", &["B.example.com".into(), "a.example.com".into(), "b.example.com".into()]).unwrap();
		assert_eq!(id.domains, ["a.example.com", "b.example.com"]);
		assert_eq!(m.check("le", &["evil.org".into()]).unwrap_err().code, "invalid");
		assert_eq!(m.check("nope", &["a.example.com".into()]).unwrap_err().code, "invalid");

		m.set_wanted([id.clone()].into());
		assert_eq!(m.status(&id).unwrap().state, "pending");
		// a certificate on disk is picked up when it is wanted again
		m.set_wanted(BTreeSet::new());
		assert!(m.status(&id).is_none());
		let (cert, key) = m.files(&id);
		let mut params = rcgen::CertificateParams::new(id.domains.clone()).unwrap();
		params.not_before = time::OffsetDateTime::from_unix_timestamp(now() - 86_400).unwrap();
		params.not_after = time::OffsetDateTime::from_unix_timestamp(now() + 89 * 86_400).unwrap();
		let k = rcgen::KeyPair::generate().unwrap();
		let issued = params.self_signed(&k).unwrap();
		store::write_private(Path::new(&cert), issued.pem().as_bytes()).unwrap();
		store::write_private(Path::new(&key), k.serialize_pem().as_bytes()).unwrap();
		m.set_wanted([id.clone()].into());
		let s = m.status(&id).unwrap();
		assert_eq!(s.state, "valid", "{s:?}");
		assert!(s.not_after.is_some() && s.renew_at.is_some());
		m.renew(&id).unwrap();
		assert_eq!(m.status(&id).unwrap().state, "renewing");
		let v = m.view();
		assert_eq!(v["certificates"][0]["domains"][0], "a.example.com");
		assert_eq!(v["resolvers"][0]["challenge"], "tls-alpn-01");
		assert_eq!(v["rate_limit"]["orders"], 10);
		let text = v.to_string();
		assert!(!text.contains("key_file") && !text.contains(".key"), "no key files in the view: {text}");
		std::fs::remove_dir_all(&dir).unwrap();
	}

	#[test]
	fn the_rate_limit_holds_orders_back() {
		let dir = std::env::temp_dir().join(format!("rproxy-acme-rl-{}", std::process::id()));
		let m = manager(&dir, "rate_limit: {orders: 2, period: 1h}");
		assert!(m.take_order().is_ok());
		assert!(m.take_order().is_ok());
		let wait = m.take_order().unwrap_err();
		assert!(wait > Duration::from_secs(3500) && wait <= Duration::from_secs(3600), "{wait:?}");
	}

	#[test]
	fn placeholders_cover_the_names() {
		let (chain, _) = placeholder(&["a.example".into(), "*.b.example".into()]).unwrap();
		assert_eq!(crate::tls::config::cert_names(&chain[0]), ["a.example", "*.b.example"]);
	}
}
