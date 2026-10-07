//! Control API hardening (#167, docs/DESIGN-v0.4.md 6.): client certificates
//! (mTLS) for the control API's TLS, token expiry warnings, and locking out
//! sources that keep failing authentication.
//!
//! The Unix socket is outside all of this: it has no TLS, and the file's
//! permissions guard it, so it is never locked out.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tower_layer::Layer;
use tracing::{info, warn};

use crate::core::rule::Features;

/// `--tls-client-auth` / `RPROXY_TLS_CLIENT_AUTH`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ClientAuth {
	/// No client certificates (default).
	#[default]
	None,
	/// Verified when presented.
	Optional,
	/// Connections without a valid certificate fail the TLS handshake.
	Required,
}

pub const DEFAULT_TOKEN_WARN_DAYS: u64 = 14;
pub const DEFAULT_LOCKOUT_FAILURES: u32 = 20;
pub const DEFAULT_LOCKOUT_WINDOW: Duration = Duration::from_secs(60);
pub const DEFAULT_LOCKOUT_DURATION: Duration = Duration::from_secs(300);
/// Most sources remembered by the lockout.
pub const LOCKOUT_SOURCES: usize = 4096;

/// The hardening options as given (None: left out, so the default applies).
#[derive(Clone, Debug, Default)]
pub struct HardeningOptions {
	pub tls_client_ca: Option<std::path::PathBuf>,
	pub tls_client_auth: Option<ClientAuth>,
	pub has_tls_cert: bool,
	pub token_warn_days: Option<u64>,
	pub lockout_failures: Option<u32>,
	pub lockout_window: Option<String>,
	pub lockout_duration: Option<String>,
}

/// What the options mean for this build: errors stop the startup, warnings
/// are logged as `degraded` and the option is ignored.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
	pub errors: Vec<String>,
	/// Options this build cannot apply yet (`--flag` names).
	pub ignored: Vec<&'static str>,
}

fn lockout_duration(what: &str, v: &Option<String>) -> Result<Option<Duration>, String> {
	let Some(v) = v else { return Ok(None) };
	let d = crate::l7::parse_duration(v).map_err(|e| format!("{what}: {e}"))?;
	if d < Duration::from_secs(1) || d > Duration::from_secs(86_400) {
		return Err(format!("{what} must be 1s-24h"));
	}
	Ok(Some(d))
}

impl HardeningOptions {
	pub fn check(&self, features: &Features) -> Verdict {
		let mut v = Verdict::default();
		let auth = self.client_auth();
		if auth != ClientAuth::None && self.tls_client_ca.is_none() {
			v.errors.push("--tls-client-auth optional / required needs --tls-client-ca (RPROXY_TLS_CLIENT_CA)".into());
		}
		if self.tls_client_ca.is_some() && !self.has_tls_cert {
			v.errors.push("--tls-client-ca needs --tls-cert / --tls-key (client certificates are part of TLS)".into());
		}
		// ignoring these would leave the control API weaker than asked for
		if !features.client_cert_auth && (auth != ClientAuth::None || self.tls_client_ca.is_some()) {
			v.errors.push(
				"client certificates for the control API (--tls-client-auth, --tls-client-ca) are not available in this version (see GET /capabilities features)".into(),
			);
		}
		if self.token_warn_days.is_some_and(|d| d == 0 || d > 3650) {
			v.errors.push("--token-warn-days must be 1-3650".into());
		}
		if self.lockout_failures.is_some_and(|n| n > 1_000_000) {
			v.errors.push("--api-lockout-failures must be 0-1000000".into());
		}
		for (what, value) in [("--api-lockout-window", &self.lockout_window), ("--api-lockout-duration", &self.lockout_duration)] {
			if let Err(e) = lockout_duration(what, value) {
				v.errors.push(e);
			}
		}
		if !features.token_expiry && self.token_warn_days.is_some() {
			v.ignored.push("--token-warn-days");
		}
		if !features.api_lockout && (self.lockout_failures.is_some() || self.lockout_window.is_some() || self.lockout_duration.is_some()) {
			v.ignored.push("--api-lockout-*");
		}
		v
	}

	pub fn client_auth(&self) -> ClientAuth {
		self.tls_client_auth.unwrap_or_default()
	}

	pub fn token_warn_days(&self) -> u64 {
		self.token_warn_days.unwrap_or(DEFAULT_TOKEN_WARN_DAYS)
	}

	/// The lockout settings (after `check`: mistakes fall back to the defaults).
	pub fn lockout(&self) -> LockoutConfig {
		let d = LockoutConfig::default();
		LockoutConfig {
			failures: self.lockout_failures.unwrap_or(d.failures),
			window: lockout_duration("", &self.lockout_window).ok().flatten().unwrap_or(d.window),
			duration: lockout_duration("", &self.lockout_duration).ok().flatten().unwrap_or(d.duration),
		}
	}
}

// ---------------------------------------------------------------------------
// Client certificates (mTLS)

/// The control API's TLS files: certificate, key and, for client
/// certificates, the CA that verifies them. All re-read on SIGHUP.
#[derive(Clone, Debug)]
pub struct ApiTlsFiles {
	pub cert: PathBuf,
	pub key: PathBuf,
	pub client_ca: Option<PathBuf>,
	pub client_auth: ClientAuth,
}

/// Why the control API's TLS could not be set up.
#[derive(Debug)]
pub enum ApiTlsError {
	/// Wrong path or not a certificate / key / CA: stop the startup.
	Config(String),
	/// Exists but cannot be read now: retry.
	Unreadable(String),
}

impl std::fmt::Display for ApiTlsError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			ApiTlsError::Config(e) | ApiTlsError::Unreadable(e) => f.write_str(e),
		}
	}
}

fn config_error(e: &io::Error) -> bool {
	matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput)
}

impl ApiTlsFiles {
	/// The files to watch for changes.
	pub fn paths(&self) -> Vec<&Path> {
		let mut v = vec![self.cert.as_path(), self.key.as_path()];
		v.extend(self.client_ca.as_deref());
		v
	}

	/// Reads the files and builds the server configuration.
	pub fn load(&self) -> Result<ServerConfig, ApiTlsError> {
		let read = |path: &Path| {
			std::fs::read(path).map_err(|e| {
				let msg = format!("TLS {}: {e}", path.display());
				if config_error(&e) {
					ApiTlsError::Config(msg)
				} else {
					ApiTlsError::Unreadable(msg)
				}
			})
		};
		let cert = read(&self.cert)?;
		let key = read(&self.key)?;
		let ca = match (&self.client_ca, self.client_auth) {
			(Some(path), mode) if mode != ClientAuth::None => Some((read(path)?, path.as_path(), mode)),
			_ => None,
		};
		server_config(&cert, &key, ca.as_ref().map(|(pem, path, mode)| (pem.as_slice(), *path, *mode)))
			.map_err(ApiTlsError::Config)
	}

	/// Loads a `RustlsConfig` for the listener.
	pub fn rustls(&self) -> Result<RustlsConfig, ApiTlsError> {
		Ok(RustlsConfig::from_config(Arc::new(self.load()?)))
	}

	/// Re-reads the files into a running listener; on error the current
	/// configuration stays.
	pub fn reload(&self, config: &RustlsConfig) -> Result<(), ApiTlsError> {
		config.reload_from_config(Arc::new(self.load()?));
		Ok(())
	}
}

/// The control API's TLS: the certificate chain and key (PEM) and, for
/// client certificates, the CA bundle (PEM) and how strict to be.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8], client: Option<(&[u8], &Path, ClientAuth)>) -> Result<ServerConfig, String> {
	let provider = Arc::new(rustls::crypto::ring::default_provider());
	let chain: Vec<CertificateDer<'static>> =
		CertificateDer::pem_slice_iter(cert_pem).collect::<Result<_, _>>().map_err(|e| format!("TLS: certificate: {e}"))?;
	if chain.is_empty() {
		return Err("TLS: no CERTIFICATE block in the certificate file".into());
	}
	let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("TLS: private key: {e}"))?;
	let builder = ServerConfig::builder_with_provider(provider.clone())
		.with_safe_default_protocol_versions()
		.map_err(|e| format!("TLS: {e}"))?;
	let builder = match client {
		Some((ca_pem, path, mode)) if mode != ClientAuth::None => {
			let mut roots = RootCertStore::empty();
			for cert in CertificateDer::pem_slice_iter(ca_pem) {
				let cert = cert.map_err(|e| format!("{}: {e}", path.display()))?;
				roots.add(cert).map_err(|e| format!("{}: {e}", path.display()))?;
			}
			if roots.is_empty() {
				return Err(format!("{}: no CERTIFICATE block (the CA for client certificates)", path.display()));
			}
			let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
			let verifier = if mode == ClientAuth::Optional { verifier.allow_unauthenticated() } else { verifier };
			builder.with_client_cert_verifier(verifier.build().map_err(|e| format!("{}: {e}", path.display()))?)
		}
		_ => builder.with_no_client_auth(),
	};
	let mut config = builder.with_single_cert(chain, key).map_err(|e| format!("TLS: {e}"))?;
	config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
	Ok(config)
}

/// The names of the verified client certificate of a connection: DNS and URI
/// SANs, or the CN when there is no such SAN. Empty without a certificate.
/// Requests over TLS carry it as an extension (`ClientCertAcceptor`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientCert(pub Arc<Vec<String>>);

impl ClientCert {
	pub fn from_der(cert: &[u8]) -> ClientCert {
		use x509_parser::extensions::GeneralName;
		let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert) else { return ClientCert::default() };
		let mut names: Vec<String> = parsed
			.subject_alternative_name()
			.ok()
			.flatten()
			.map(|san| {
				san.value
					.general_names
					.iter()
					.filter_map(|n| match n {
						GeneralName::DNSName(d) => Some(d.to_string()),
						GeneralName::URI(u) => Some(u.to_string()),
						_ => None,
					})
					.collect()
			})
			.unwrap_or_default();
		if names.is_empty() {
			names.extend(crate::tls::config::common_name(cert));
		}
		ClientCert(Arc::new(names))
	}

	fn of(conn: &rustls::ServerConnection) -> ClientCert {
		conn.peer_certificates().and_then(|c| c.first()).map(|c| ClientCert::from_der(c.as_ref())).unwrap_or_default()
	}

	pub fn names(&self) -> &[String] {
		&self.0
	}
}

/// The TLS acceptor of the control API: after the handshake, the requests of
/// the connection carry the client certificate's names (`ClientCert`).
#[derive(Clone)]
pub struct ClientCertAcceptor {
	inner: RustlsAcceptor,
}

impl ClientCertAcceptor {
	pub fn new(config: RustlsConfig) -> Self {
		ClientCertAcceptor { inner: RustlsAcceptor::new(config) }
	}
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

impl<I, S> Accept<I, S> for ClientCertAcceptor
where
	I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
	S: Send + 'static,
{
	type Stream = TlsStream<I>;
	type Service = <axum::Extension<ClientCert> as Layer<S>>::Service;
	type Future = BoxFuture<io::Result<(Self::Stream, Self::Service)>>;

	fn accept(&self, stream: I, service: S) -> Self::Future {
		let handshake = self.inner.accept(stream, service);
		Box::pin(async move {
			let (stream, service) = handshake.await?;
			let cert = ClientCert::of(stream.get_ref().1);
			Ok((stream, axum::Extension(cert).layer(service)))
		})
	}
}

// ---------------------------------------------------------------------------
// Token expiry

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpiryState {
	Valid,
	Expiring,
	Expired,
}

/// What a check reported about one token (also logged).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExpiryNotice {
	/// `token.expiring`
	Expiring { token: String, expires: time::Date, days_left: i64 },
	/// `token.expired`
	Expired { token: String, expires: time::Date },
}

/// Reports tokens whose `expires` is near (`token.expiring`) or past
/// (`token.expired`), once each time a token's state changes. Checked at
/// startup, after SIGHUP and once a day.
pub struct TokenExpiry {
	warn_days: u64,
	seen: Mutex<HashMap<String, (time::Date, ExpiryState)>>,
}

impl TokenExpiry {
	pub fn new(warn_days: u64) -> Self {
		TokenExpiry { warn_days, seen: Mutex::default() }
	}

	/// Checks the tokens with an `expires` (name, last valid day) as of today (UTC).
	pub fn check(&self, tokens: &[(String, time::Date)]) -> Vec<ExpiryNotice> {
		self.check_on(tokens, time::OffsetDateTime::now_utc().date())
	}

	pub fn check_on(&self, tokens: &[(String, time::Date)], today: time::Date) -> Vec<ExpiryNotice> {
		let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
		let mut notices = vec![];
		let mut next = HashMap::new();
		for (name, expires) in tokens {
			let days_left = (*expires - today).whole_days();
			let state = if days_left < 0 {
				ExpiryState::Expired
			} else if (days_left as u64) < self.warn_days {
				ExpiryState::Expiring
			} else {
				ExpiryState::Valid
			};
			let changed = seen.get(name).is_none_or(|(d, s)| d != expires || *s != state);
			if changed {
				match state {
					ExpiryState::Expiring => {
						warn!(event = "token.expiring", token = %name, expires = %expires, days_left,
							"rotate the token: add the new one, SIGHUP, switch the clients, then remove the old one");
						notices.push(ExpiryNotice::Expiring { token: name.clone(), expires: *expires, days_left });
					}
					ExpiryState::Expired => {
						warn!(event = "token.expired", token = %name, expires = %expires, "requests with this token are refused");
						notices.push(ExpiryNotice::Expired { token: name.clone(), expires: *expires });
					}
					ExpiryState::Valid => {}
				}
			}
			next.insert(name.clone(), (*expires, state));
		}
		*seen = next;
		notices
	}
}

/// The moment a token stops being valid: the start (UTC) of the day after `expires`.
pub fn expiry_timestamp(expires: time::Date) -> i64 {
	expires.next_day().map(|d| d.midnight().assume_utc().unix_timestamp()).unwrap_or(i64::MAX)
}

// ---------------------------------------------------------------------------
// Lockout

/// `--api-lockout-*`: `failures` failed authentications (401) within
/// `window` lock a source out for `duration`; `failures` 0 turns it off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockoutConfig {
	pub failures: u32,
	pub window: Duration,
	pub duration: Duration,
}

impl Default for LockoutConfig {
	fn default() -> Self {
		LockoutConfig { failures: DEFAULT_LOCKOUT_FAILURES, window: DEFAULT_LOCKOUT_WINDOW, duration: DEFAULT_LOCKOUT_DURATION }
	}
}

#[derive(Clone, Copy, Debug)]
struct Source {
	window_start: Instant,
	failures: u32,
	locked_until: Option<Instant>,
	last: Instant,
}

/// The key a source is counted under: the IPv4 address, or the IPv6 /64.
pub fn source_key(ip: IpAddr) -> IpAddr {
	match crate::l7::access::canonical(ip) {
		IpAddr::V6(v6) => {
			let s = v6.segments();
			IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
		}
		v4 => v4,
	}
}

fn show(key: IpAddr) -> String {
	match key {
		IpAddr::V6(v6) => format!("{v6}/64"),
		v4 => v4.to_string(),
	}
}

fn unix_after(d: Duration) -> u64 {
	(SystemTime::now() + d).duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Sources of the TCP control API that keep failing authentication, locked
/// out for a while (`429 locked_out`). The Unix socket is never counted.
pub struct Lockout {
	config: LockoutConfig,
	sources: Mutex<HashMap<IpAddr, Source>>,
	total: AtomicU64,
}

impl Default for Lockout {
	fn default() -> Self {
		Lockout::new(LockoutConfig::default())
	}
}

impl Lockout {
	pub fn new(config: LockoutConfig) -> Self {
		Lockout { config, sources: Mutex::default(), total: AtomicU64::new(0) }
	}

	pub fn config(&self) -> LockoutConfig {
		self.config
	}

	fn enabled(&self) -> bool {
		self.config.failures > 0
	}

	/// How long the source stays locked out, if it is.
	pub fn locked(&self, ip: IpAddr) -> Option<Duration> {
		self.locked_at(ip, Instant::now())
	}

	pub fn locked_at(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
		if !self.enabled() {
			return None;
		}
		let key = source_key(ip);
		let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
		let until = sources.get(&key)?.locked_until?;
		if until > now {
			return Some(until - now);
		}
		sources.remove(&key);
		info!(event = "api.unlock", client = %show(key));
		None
	}

	/// Counts a failed authentication (401); locks the source out when it
	/// reaches the limit. Returns whether this failure locked it.
	pub fn failed(&self, ip: IpAddr) -> bool {
		self.failed_at(ip, Instant::now())
	}

	pub fn failed_at(&self, ip: IpAddr, now: Instant) -> bool {
		if !self.enabled() {
			return false;
		}
		let key = source_key(ip);
		let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
		if !sources.contains_key(&key) && sources.len() >= LOCKOUT_SOURCES {
			Self::forget_one(&mut sources, now);
		}
		let s = sources.entry(key).or_insert(Source { window_start: now, failures: 0, locked_until: None, last: now });
		s.last = now;
		if s.locked_until.is_some_and(|u| u > now) {
			return false;
		}
		if s.locked_until.is_some() || now.duration_since(s.window_start) > self.config.window {
			*s = Source { window_start: now, failures: 0, locked_until: None, last: now };
		}
		s.failures += 1;
		if s.failures < self.config.failures {
			return false;
		}
		s.locked_until = Some(now + self.config.duration);
		self.total.fetch_add(1, Ordering::Relaxed);
		warn!(event = "api.lockout", client = %show(key), failures = s.failures, until = unix_after(self.config.duration),
			duration_secs = self.config.duration.as_secs(), "too many failed authentications; refusing this source for a while");
		true
	}

	/// Makes room: forgets the source seen longest ago, preferring those not locked out.
	fn forget_one(sources: &mut HashMap<IpAddr, Source>, now: Instant) {
		let oldest = |locked: bool| {
			sources
				.iter()
				.filter(|(_, s)| s.locked_until.is_some_and(|u| u > now) == locked)
				.min_by_key(|(_, s)| s.last)
				.map(|(k, _)| *k)
		};
		if let Some(k) = oldest(false).or_else(|| oldest(true)) {
			sources.remove(&k);
		}
	}

	/// Unlocks sources whose time is up (`api.unlock`) and forgets counts
	/// whose window has passed. Run every few seconds.
	pub fn sweep(&self) {
		self.sweep_at(Instant::now());
	}

	pub fn sweep_at(&self, now: Instant) {
		let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
		let window = self.config.window;
		sources.retain(|key, s| match s.locked_until {
			Some(u) if u <= now => {
				info!(event = "api.unlock", client = %show(*key));
				false
			}
			Some(_) => true,
			None => now.duration_since(s.window_start) <= window,
		});
	}

	/// Sources locked out now (`rproxy_api_locked_sources`).
	pub fn locked_sources(&self) -> usize {
		let now = Instant::now();
		let sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
		sources.values().filter(|s| s.locked_until.is_some_and(|u| u > now)).count()
	}

	/// Lockouts since the start (`rproxy_api_lockouts_total`).
	pub fn lockouts_total(&self) -> u64 {
		self.total.load(Ordering::Relaxed)
	}

	/// Sources remembered now (for tests).
	pub fn remembered(&self) -> usize {
		self.sources.lock().unwrap_or_else(|e| e.into_inner()).len()
	}
}

// ---------------------------------------------------------------------------
// Metrics

fn label(s: &str) -> String {
	s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// The hardening lines of `GET /metrics`.
pub fn metrics(tokens: &crate::control::auth::Tokens) -> String {
	let mut out = String::new();
	let expiries = tokens.expiries();
	if !expiries.is_empty() {
		let _ = writeln!(out, "# HELP rproxy_token_expiry_timestamp_seconds When a control API token stops being valid (the end of its expires day, UTC).");
		let _ = writeln!(out, "# TYPE rproxy_token_expiry_timestamp_seconds gauge");
		for (name, expires) in &expiries {
			let _ = writeln!(out, "rproxy_token_expiry_timestamp_seconds{{token=\"{}\"}} {}", label(name), expiry_timestamp(*expires));
		}
	}
	if tokens.enabled() {
		let lockout = tokens.lockout();
		let _ = writeln!(out, "# HELP rproxy_api_lockouts_total Sources of the control API locked out after failed authentications.");
		let _ = writeln!(out, "# TYPE rproxy_api_lockouts_total counter");
		let _ = writeln!(out, "rproxy_api_lockouts_total {}", lockout.lockouts_total());
		let _ = writeln!(out, "# HELP rproxy_api_locked_sources Sources of the control API locked out now.");
		let _ = writeln!(out, "# TYPE rproxy_api_locked_sources gauge");
		let _ = writeln!(out, "rproxy_api_locked_sources {}", lockout.locked_sources());
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn options_are_checked() {
		let all = Features::CURRENT;
		assert_eq!(HardeningOptions::default().check(&all), Verdict::default());
		let mtls = HardeningOptions {
			tls_client_ca: Some("/ca.pem".into()),
			tls_client_auth: Some(ClientAuth::Required),
			has_tls_cert: true,
			..Default::default()
		};
		assert!(mtls.check(&all).errors.is_empty());
		let mut none = Features::CURRENT;
		none.client_cert_auth = false;
		assert!(mtls.check(&none).errors.iter().any(|e| e.contains("not available")), "refused when not available");
		let no_ca = HardeningOptions { tls_client_auth: Some(ClientAuth::Optional), has_tls_cert: true, ..Default::default() };
		assert!(no_ca.check(&all).errors[0].contains("needs --tls-client-ca"));
		let no_cert = HardeningOptions { tls_client_ca: Some("/ca.pem".into()), ..Default::default() };
		assert!(no_cert.check(&all).errors[0].contains("needs --tls-cert"));
		let lockout = HardeningOptions { lockout_failures: Some(5), lockout_window: Some("30s".into()), ..Default::default() };
		assert!(lockout.check(&all).ignored.is_empty());
		assert_eq!(lockout.lockout(), LockoutConfig { failures: 5, window: Duration::from_secs(30), duration: DEFAULT_LOCKOUT_DURATION });
		assert_eq!(HardeningOptions::default().lockout(), LockoutConfig::default(), "on by default (20 / 1m / 5m)");
		assert_eq!(HardeningOptions::default().token_warn_days(), 14);
		let bad = HardeningOptions { lockout_duration: Some("2d".into()), token_warn_days: Some(0), ..Default::default() };
		assert_eq!(bad.check(&all).errors.len(), 2);
	}

	#[test]
	fn client_certificate_names_are_dns_and_uri_sans_else_the_cn() {
		let cert = |sans: Vec<rcgen::SanType>| {
			let key = rcgen::KeyPair::generate().unwrap();
			let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
			p.subject_alt_names = sans;
			p.distinguished_name.push(rcgen::DnType::CommonName, "cn-name");
			p.self_signed(&key).unwrap().der().to_vec()
		};
		let uri = rcgen::string::Ia5String::try_from("spiffe://cluster.local/ns/rproxy/sa/controller").unwrap();
		let dns = rcgen::string::Ia5String::try_from("ui.rproxy.internal").unwrap();
		let ip = rcgen::SanType::IpAddress("192.0.2.1".parse().unwrap());
		let both = ClientCert::from_der(&cert(vec![rcgen::SanType::DnsName(dns), rcgen::SanType::URI(uri), ip.clone()]));
		assert_eq!(both.names(), ["ui.rproxy.internal", "spiffe://cluster.local/ns/rproxy/sa/controller"]);
		assert_eq!(ClientCert::from_der(&cert(vec![ip])).names(), ["cn-name"], "no DNS / URI SAN: the CN");
		assert!(ClientCert::from_der(b"junk").names().is_empty());
	}

	#[test]
	fn lockout_counts_failures_in_the_window_per_source() {
		let lock = Lockout::new(LockoutConfig { failures: 3, window: Duration::from_secs(60), duration: Duration::from_secs(300) });
		let t0 = Instant::now();
		let a: IpAddr = "192.0.2.1".parse().unwrap();
		let b: IpAddr = "192.0.2.2".parse().unwrap();
		assert!(!lock.failed_at(a, t0));
		assert!(!lock.failed_at(a, t0 + Duration::from_secs(10)));
		assert!(!lock.failed_at(b, t0), "counted per source");
		assert_eq!(lock.locked_at(a, t0), None);
		assert!(lock.failed_at(a, t0 + Duration::from_secs(20)), "the third failure in the window locks");
		assert_eq!(lock.locked_at(a, t0 + Duration::from_secs(20)), Some(Duration::from_secs(300)));
		assert_eq!(lock.locked_at(b, t0 + Duration::from_secs(20)), None);
		assert_eq!(lock.lockouts_total(), 1);
		// the time is up: unlocked, counting starts over
		assert_eq!(lock.locked_at(a, t0 + Duration::from_secs(321)), None);
		assert!(!lock.failed_at(a, t0 + Duration::from_secs(322)));
		// failures spread wider than the window do not lock
		assert!(!lock.failed_at(b, t0 + Duration::from_secs(61)));
		assert!(!lock.failed_at(b, t0 + Duration::from_secs(62)));
		assert_eq!(lock.locked_at(b, t0 + Duration::from_secs(62)), None);
	}

	#[test]
	fn ipv6_sources_are_grouped_by_64_and_mapped_ipv4_is_ipv4() {
		assert_eq!(source_key("2001:db8:1:2:aaaa::1".parse().unwrap()), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
		assert_eq!(source_key("::ffff:192.0.2.9".parse().unwrap()), "192.0.2.9".parse::<IpAddr>().unwrap());
		let lock = Lockout::new(LockoutConfig { failures: 2, ..Default::default() });
		let t0 = Instant::now();
		assert!(!lock.failed_at("2001:db8:1:2::1".parse().unwrap(), t0));
		assert!(lock.failed_at("2001:db8:1:2::ffff".parse().unwrap(), t0));
		assert!(lock.locked_at("2001:db8:1:2:1:2:3:4".parse().unwrap(), t0).is_some());
		assert!(lock.locked_at("2001:db8:1:3::1".parse().unwrap(), t0).is_none());
	}

	#[test]
	fn lockout_off_and_bounded() {
		let off = Lockout::new(LockoutConfig { failures: 0, ..Default::default() });
		let ip: IpAddr = "192.0.2.1".parse().unwrap();
		for _ in 0..100 {
			assert!(!off.failed(ip));
		}
		assert_eq!(off.locked(ip), None);

		let lock = Lockout::new(LockoutConfig { failures: 2, ..Default::default() });
		let t0 = Instant::now();
		let locked: IpAddr = "198.51.100.1".parse().unwrap();
		lock.failed_at(locked, t0);
		assert!(lock.failed_at(locked, t0));
		for i in 0..(LOCKOUT_SOURCES as u32 + 10) {
			let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
			lock.failed_at(ip, t0 + Duration::from_millis(u64::from(i) + 1));
		}
		assert_eq!(lock.remembered(), LOCKOUT_SOURCES);
		assert!(lock.locked_at(locked, t0 + Duration::from_secs(1)).is_some(), "a flood of sources forgets the others first");
		lock.sweep_at(t0 + Duration::from_secs(10_000));
		assert_eq!(lock.remembered(), 0, "unlocked and forgotten");
	}

	#[test]
	fn expiry_is_reported_once_per_change() {
		let day = |s: &str| {
			let (y, rest) = s.split_once('-').unwrap();
			let (m, d) = rest.split_once('-').unwrap();
			time::Date::from_calendar_date(y.parse().unwrap(), time::Month::try_from(m.parse::<u8>().unwrap()).unwrap(), d.parse().unwrap())
				.unwrap()
		};
		let watch = TokenExpiry::new(14);
		let tokens = vec![("ci".to_string(), day("2027-03-31")), ("ui".to_string(), day("2028-01-01"))];
		assert!(watch.check_on(&tokens, day("2027-03-01")).is_empty());
		let n = watch.check_on(&tokens, day("2027-03-18"));
		assert_eq!(n, [ExpiryNotice::Expiring { token: "ci".into(), expires: day("2027-03-31"), days_left: 13 }]);
		assert!(watch.check_on(&tokens, day("2027-03-19")).is_empty(), "once per change");
		assert!(watch.check_on(&tokens, day("2027-03-31")).is_empty(), "the last day is still valid");
		let n = watch.check_on(&tokens, day("2027-04-01"));
		assert_eq!(n, [ExpiryNotice::Expired { token: "ci".into(), expires: day("2027-03-31") }]);
		// rotated: a new date for the same name starts over
		let rotated = vec![("ci".to_string(), day("2027-04-10"))];
		assert_eq!(watch.check_on(&rotated, day("2027-04-01")).len(), 1);
		assert_eq!(expiry_timestamp(day("2027-03-31")), 1_806_537_600, "2027-04-01T00:00:00Z");
	}
}
