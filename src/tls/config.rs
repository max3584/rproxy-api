//! TLS / DTLS settings of a rule: what the API accepts, and the rustls /
//! the dtls crate configurations built from it.

use std::fs;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::client::danger::HandshakeSignatureValid as SigValid;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::DistinguishedName;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::core::rule::Protocol;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
	/// Bytes are forwarded untouched (the default).
	#[default]
	Passthrough,
	/// Read the server name from the ClientHello and pick the backend, without decrypting.
	Sni,
	/// Decrypt here (TLS for tcp, DTLS for udp) and forward plain or re-encrypted.
	Terminate,
}

/// What happens to server names that no route matches (and to clients sending no SNI).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unmatched {
	/// Send them to the rule's own target.
	#[default]
	Default,
	/// Close the connection (for terminate, before completing the handshake).
	Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
	/// `mail.example.com`, `*.example.com` for one label under it, or
	/// `**.example.com` for one or more labels under it.
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub server_name: String,
	/// Several names for one backend (instead of `server_name`).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub server_names: Vec<String>,
	pub remote_addr: String,
	pub remote_port: u16,
	/// `terminate` only: send matching connections through without terminating
	/// TLS (the ClientHello is replayed to the backend, as with mode `sni`).
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub passthrough: bool,
}

impl Route {
	/// The names this route answers (`server_name` or `server_names`).
	pub fn patterns(&self) -> Vec<String> {
		if self.server_names.is_empty() {
			vec![self.server_name.to_ascii_lowercase()]
		} else {
			self.server_names.iter().map(|n| n.to_ascii_lowercase()).collect()
		}
	}

	/// A name for messages.
	pub fn label(&self) -> String {
		self.patterns().join(",")
	}
}

/// One certificate: PEM files, or (v0.3) one obtained through an ACME resolver.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertFiles {
	/// PEM server certificate. May also hold the chain after it (leaf first).
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub cert_file: String,
	/// PEM intermediate CA certificates, sent after the server certificate.
	/// The root may be left out; clients already trust it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub chain_file: Option<String>,
	/// PEM private key (PKCS#8; for tcp also PKCS#1 / SEC1).
	#[serde(default, skip_serializing_if = "String::is_empty")]
	pub key_file: String,
	/// Name of a `global.acme.resolvers` entry that obtains this certificate.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub acme: Option<String>,
	/// Names the ACME certificate covers.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub domains: Vec<String>,
}

/// TLS protocol settings (v0.3; see GET /capabilities features.tls_options).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsOptions {
	/// "1.2" or "1.3"
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub min_version: Option<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub cipher_suites: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMode {
	#[default]
	None,
	/// Verify a client certificate if one is sent.
	Optional,
	/// Reject clients without a valid certificate (mTLS).
	Required,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientAuth {
	#[serde(default)]
	pub mode: ClientAuthMode,
	/// PEM file of the root CA(s) that client certificates must chain to.
	pub ca_file: Option<String>,
	/// PEM intermediate CAs of client certificates, for clients that send only
	/// their own certificate. They help build the path; the root stays the anchor.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub chain_file: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
	/// Re-encrypt towards the backend (TLS for tcp, DTLS for udp).
	#[serde(default)]
	pub tls: bool,
	/// Name to verify on the backend's certificate (default: the target host).
	pub server_name: Option<String>,
	/// CA certificates for the backend (default: the Mozilla root set).
	pub ca_file: Option<String>,
	/// Skip verifying the backend's certificate. For testing only.
	#[serde(default)]
	pub insecure_skip_verify: bool,
	/// Client certificate presented to the backend (mTLS towards the backend).
	pub cert_file: Option<String>,
	/// Intermediate CA certificates for `cert_file`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub chain_file: Option<String>,
	pub key_file: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSpec {
	#[serde(default)]
	pub mode: TlsMode,
	/// Per-server-name backends (sni and terminate). Unmatched names use the rule's own target.
	#[serde(default)]
	pub routes: Vec<Route>,
	#[serde(default)]
	pub certificates: Vec<CertFiles>,
	#[serde(default)]
	pub client_auth: ClientAuth,
	/// ALPN protocols offered to clients when terminating, e.g. ["h2", "http/1.1"].
	#[serde(default)]
	pub alpn: Vec<String>,
	#[serde(default)]
	pub upstream: Upstream,
	#[serde(default)]
	pub unmatched: Unmatched,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub options: Option<TlsOptions>,
}

impl TlsSpec {
	/// Every file these settings read (certificates, keys, CAs), for noticing changes.
	pub fn files(&self) -> Vec<&str> {
		let mut files: Vec<&str> = vec![];
		for c in &self.certificates {
			files.extend([c.cert_file.as_str(), c.key_file.as_str()].into_iter().filter(|f| !f.is_empty()));
			files.extend(c.chain_file.as_deref());
		}
		files.extend(self.client_auth.ca_file.as_deref());
		files.extend(self.client_auth.chain_file.as_deref());
		let u = &self.upstream;
		files.extend([&u.ca_file, &u.cert_file, &u.chain_file, &u.key_file].into_iter().filter_map(|f| f.as_deref()));
		files
	}
}

/// Size, modification time and inode of files: changes when a file is rewritten or,
/// as Kubernetes does with mounted secrets, replaced through a symbolic link.
pub fn fingerprint<'a>(files: impl IntoIterator<Item = &'a str>) -> u64 {
	use std::hash::{Hash, Hasher};
	let mut h = std::collections::hash_map::DefaultHasher::new();
	for f in files {
		f.hash(&mut h);
		match std::fs::metadata(f) {
			Ok(m) => {
				m.len().hash(&mut h);
				m.modified().ok().hash(&mut h);
				#[cfg(unix)]
				{
					use std::os::unix::fs::MetadataExt;
					(m.dev(), m.ino()).hash(&mut h);
				}
			}
			Err(e) => e.kind().hash(&mut h),
		}
	}
	h.finish()
}

/// Mail protocols whose plain-text STARTTLS dialogue rproxy answers itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartTls {
	Smtp,
	Imap,
	Pop3,
}

impl StartTls {
	pub fn as_str(&self) -> &'static str {
		match self {
			StartTls::Smtp => "smtp",
			StartTls::Imap => "imap",
			StartTls::Pop3 => "pop3",
		}
	}
}

fn tls_error(message: impl Into<String>) -> ApiError {
	ApiError::tls_config(message)
}

/// Checks the combination of fields; files are read later by `build`.
/// `port_count` is the size of the rule's port range (1 for a single port).
pub fn validate(protocol: Protocol, tls: &TlsSpec, starttls: Option<StartTls>) -> Result<(), ApiError> {
	validate_range(protocol, tls, starttls, 1)
}

pub fn validate_range(protocol: Protocol, tls: &TlsSpec, starttls: Option<StartTls>, port_count: u16) -> Result<(), ApiError> {
	match (protocol, tls.mode) {
		(_, TlsMode::Terminate) if tls.certificates.is_empty() => {
			return Err(tls_error("terminate needs at least one entry in certificates"));
		}
		(_, TlsMode::Passthrough | TlsMode::Sni) if !tls.certificates.is_empty() => {
			return Err(tls_error("certificates are only used with mode terminate"));
		}
		(_, TlsMode::Passthrough) if !tls.routes.is_empty() => {
			return Err(tls_error("routes need mode sni or terminate"));
		}
		_ => {}
	}
	for c in &tls.certificates {
		match &c.acme {
			Some(resolver) => {
				if resolver.is_empty() || c.domains.is_empty() {
					return Err(tls_error("an acme certificate needs the resolver name and at least one domain"));
				}
				if !c.cert_file.is_empty() || !c.key_file.is_empty() || c.chain_file.is_some() {
					return Err(tls_error("an acme certificate takes no cert_file, key_file or chain_file"));
				}
			}
			None if c.cert_file.is_empty() || c.key_file.is_empty() => {
				return Err(tls_error("a certificate needs cert_file and key_file (or acme and domains)"));
			}
			None if !c.domains.is_empty() => return Err(tls_error("domains is only used with acme")),
			None => {}
		}
	}
	if let Some(o) = &tls.options {
		if tls.mode != TlsMode::Terminate {
			return Err(tls_error("options are only used with mode terminate"));
		}
		if let Some(v) = &o.min_version {
			if v != "1.2" && v != "1.3" {
				return Err(tls_error(format!("options.min_version {v:?} must be 1.2 or 1.3")));
			}
		}
		if protocol == Protocol::Udp {
			return Err(ApiError::unsupported("tls.options are not available for DTLS (udp); they apply to tcp only"));
		}
		server_crypto(Some(o))?;
	}
	if tls.mode != TlsMode::Terminate
		&& (tls.client_auth.mode != ClientAuthMode::None || tls.upstream != Upstream::default() || !tls.alpn.is_empty())
	{
		return Err(tls_error("client_auth, upstream and alpn are only used with mode terminate"));
	}
	if tls.client_auth.mode != ClientAuthMode::None && tls.client_auth.ca_file.is_none() {
		return Err(tls_error("client_auth needs ca_file"));
	}
	if tls.client_auth.mode == ClientAuthMode::None && tls.client_auth.chain_file.is_some() {
		return Err(tls_error("client_auth chain_file needs mode optional or required"));
	}
	// udp: only mode sni reads a name before choosing the backend (DTLS terminate does not route by name)
	if tls.unmatched == Unmatched::Reject
		&& ((protocol == Protocol::Udp && tls.mode != TlsMode::Sni) || tls.mode == TlsMode::Passthrough || tls.routes.is_empty())
	{
		return Err(tls_error("unmatched: reject needs mode sni (tcp or udp) or terminate (tcp), and at least one route"));
	}
	if protocol == Protocol::Udp && !tls.alpn.is_empty() {
		return Err(tls_error("alpn is supported for tcp only"));
	}
	if tls.upstream.cert_file.is_some() != tls.upstream.key_file.is_some() {
		return Err(tls_error("upstream cert_file and key_file must be given together"));
	}
	if tls.upstream.chain_file.is_some() && tls.upstream.cert_file.is_none() {
		return Err(tls_error("upstream chain_file needs cert_file"));
	}
	for route in &tls.routes {
		if route.server_name.is_empty() == route.server_names.is_empty() {
			return Err(tls_error("each route needs server_name or server_names (not both)"));
		}
		for name in route.patterns() {
			if !valid_pattern(&name) {
				return Err(tls_error(format!("invalid server_name: {name}")));
			}
		}
		if route.passthrough && protocol == Protocol::Udp {
			return Err(tls_error("passthrough routes are for tcp; a udp rule with mode sni passes every route through"));
		}
		if route.passthrough && tls.mode != TlsMode::Terminate {
			return Err(tls_error("passthrough routes are for mode terminate (with mode sni every route is passed through)"));
		}
		if route.passthrough && starttls.is_some() {
			return Err(tls_error("passthrough routes cannot be combined with starttls (TLS starts after the plain-text dialogue)"));
		}
		crate::core::rule::validate_remote(&route.remote_addr, route.remote_port)?;
		if u32::from(route.remote_port) + u32::from(port_count) - 1 > 65_535 {
			return Err(ApiError::invalid(format!("route {}: remote_port + range length exceeds 65535", route.label())));
		}
	}
	if let Some(proto) = starttls {
		if protocol != Protocol::Tcp || tls.mode != TlsMode::Terminate {
			return Err(tls_error(format!("starttls {} needs protocol tcp and tls mode terminate", proto.as_str())));
		}
	}
	Ok(())
}

fn valid_pattern(p: &str) -> bool {
	let name = p.strip_prefix("**.").or_else(|| p.strip_prefix("*.")).unwrap_or(p);
	!name.is_empty()
		&& name.len() <= 253
		&& name.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// Whether `name` (from SNI) matches `pattern`; `*.` matches exactly one label,
/// `**.` one or more labels (not the name itself).
pub fn name_matches(pattern: &str, name: &str) -> bool {
	match_rank(pattern, name).is_some()
}

/// How closely `pattern` matches `name`, for choosing among several matches:
/// lower is better. An exact name comes first, then `*.`, then `**.` with the
/// longest suffix first.
pub fn match_rank(pattern: &str, name: &str) -> Option<(u8, usize)> {
	let (pattern, name) = (pattern.to_ascii_lowercase(), name.to_ascii_lowercase());
	if let Some(suffix) = pattern.strip_prefix("**.") {
		let dotted = format!(".{suffix}");
		return (name.len() > dotted.len() && name.ends_with(&dotted) && !name.starts_with('.'))
			.then(|| (2, usize::MAX - suffix.len()));
	}
	match pattern.strip_prefix("*.") {
		Some(suffix) => name
			.split_once('.')
			.is_some_and(|(label, rest)| !label.is_empty() && rest == suffix)
			.then_some((1, 0)),
		None => (pattern == name).then_some((0, 0)),
	}
}

/// The best of several pattern lists for `name`: the index of the list with the
/// closest match (ties go to the earlier list).
pub fn best_match<'a>(lists: impl IntoIterator<Item = &'a [String]>, name: &str) -> Option<usize> {
	lists
		.into_iter()
		.enumerate()
		.filter_map(|(i, patterns)| patterns.iter().filter_map(|p| match_rank(p, name)).min().map(|r| (r, i)))
		.min()
		.map(|(_, i)| i)
}

fn read(path: &str) -> Result<Vec<u8>, ApiError> {
	fs::read(path).map_err(|e| tls_error(format!("{path}: {e}")))
}

fn load_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, ApiError> {
	let data = read(path)?;
	let certs: Vec<_> = CertificateDer::pem_slice_iter(&data)
		.collect::<Result<_, _>>()
		.map_err(|e| tls_error(format!("{path}: {e}")))?;
	if certs.is_empty() {
		return Err(tls_error(format!("{path}: no CERTIFICATE block")));
	}
	Ok(certs)
}

/// Server (or client) certificate followed by its intermediates, checked for order.
fn load_full_chain(cert_file: &str, chain_file: Option<&str>) -> Result<Vec<CertificateDer<'static>>, ApiError> {
	let mut chain = load_chain(cert_file)?;
	if let Some(extra) = chain_file {
		for cert in load_chain(extra)? {
			if !chain.contains(&cert) {
				chain.push(cert);
			}
		}
	}
	check_order(&chain, chain_file.unwrap_or(cert_file))?;
	Ok(chain)
}

/// Each certificate must be issued by the next one: leaf, intermediates, (root).
fn check_order(chain: &[CertificateDer<'_>], file: &str) -> Result<(), ApiError> {
	let parsed: Vec<_> = chain
		.iter()
		.map(|c| x509_parser::parse_x509_certificate(c.as_ref()).map(|(_, x)| x))
		.collect::<Result<_, _>>()
		.map_err(|e| tls_error(format!("{file}: {e}")))?;
	for (i, pair) in parsed.windows(2).enumerate() {
		if pair[0].issuer().as_raw() != pair[1].subject().as_raw() {
			return Err(tls_error(format!(
				"{file}: certificate {} ({}) was not issued by certificate {} ({}); put the server certificate first, then intermediates from the one that issued it up towards the root",
				i + 1,
				pair[0].subject(),
				i + 2,
				pair[1].subject()
			)));
		}
	}
	Ok(())
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, ApiError> {
	let data = read(path)?;
	// the first PKCS#8, PKCS#1 (RSA) or SEC1 (EC) key in the file
	PrivateKeyDer::from_pem_slice(&data).map_err(|e| match e {
		pem::Error::NoItemsFound => tls_error(format!("{path}: no private key block")),
		e => tls_error(format!("{path}: {e}")),
	})
}

/// DNS names a certificate is valid for (subjectAltName, else the common name).
pub fn cert_names(cert: &CertificateDer<'_>) -> Vec<String> {
	let Ok((_, parsed)) = x509_parser::parse_x509_certificate(cert.as_ref()) else { return vec![] };
	let mut names: Vec<String> = parsed
		.subject_alternative_name()
		.ok()
		.flatten()
		.map(|san| {
			san.value
				.general_names
				.iter()
				.filter_map(|n| match n {
					x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
					_ => None,
				})
				.collect()
		})
		.unwrap_or_default();
	if names.is_empty() {
		names.extend(common_name(cert));
	}
	names
}

/// Subject common name, used to tell backends who a verified client is.
pub fn common_name(cert: &[u8]) -> Option<String> {
	let (_, parsed) = x509_parser::parse_x509_certificate(cert).ok()?;
	let cn = parsed.subject().iter_common_name().next()?.as_str().ok()?.to_string();
	Some(cn)
}

/// Start of the message of the error a rule gets when every server certificate
/// has expired; `is_cert_expired` recognises it.
pub const CERT_EXPIRED: &str = "certificate expired";

/// Whether `e` says every server certificate of the rule has expired.
pub fn is_cert_expired(e: &ApiError) -> bool {
	e.code == "tls_config" && e.message.starts_with(CERT_EXPIRED)
}

/// Whether a rule's error text is the one of `is_cert_expired`.
pub fn is_cert_expired_text(message: &str) -> bool {
	message.starts_with(CERT_EXPIRED)
}

/// When one certificate stops being valid. Pure: `now` is Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertCheck {
	/// notAfter, Unix seconds.
	pub not_after: i64,
	pub seconds_left: i64,
	pub expired: bool,
}

/// Reads the validity of one certificate (DER). The only place certificate
/// expiry is worked out; everything else goes through it.
pub fn inspect_certificate(der: &[u8], now: i64) -> Result<CertCheck, String> {
	let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| e.to_string())?;
	let not_after = cert.validity().not_after.timestamp();
	Ok(CertCheck { not_after, seconds_left: not_after - now, expired: not_after <= now })
}

/// The earliest notAfter of `certs` (a chain or a bundle), through `inspect_certificate`.
pub fn earliest_expiry(certs: &[CertificateDer<'_>]) -> Option<i64> {
	certs.iter().filter_map(|c| inspect_certificate(c.as_ref(), 0).ok()).map(|c| c.not_after).min()
}

pub fn unix_now() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}

/// Earliest notAfter of the certificates in a PEM file (the control API's
/// certificate, which is not in the certificate store).
pub fn file_expiry(file: &str) -> Result<i64, ApiError> {
	earliest_expiry(&load_chain(file)?).ok_or_else(|| tls_error(format!("{file}: cannot read the certificate's validity")))
}

/// What a certificate file is for. Only `certificate` (the rule's own server
/// certificates) takes a rule out of service when it expires; the others warn.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertRole {
	/// `tls.certificates[]` (with its `chain_file`).
	Certificate,
	/// `tls.client_auth.ca_file`
	ClientCa,
	/// `tls.client_auth.chain_file`
	ClientChain,
	/// `tls.upstream.ca_file`
	UpstreamCa,
	/// `tls.upstream.cert_file` (with its `chain_file`).
	UpstreamCertificate,
	/// The control API's certificate (`RPROXY_TLS_CERT`).
	Api,
}

impl CertRole {
	pub fn as_str(self) -> &'static str {
		match self {
			CertRole::Certificate => "certificate",
			CertRole::ClientCa => "client_ca",
			CertRole::ClientChain => "client_chain",
			CertRole::UpstreamCa => "upstream_ca",
			CertRole::UpstreamCertificate => "upstream_certificate",
			CertRole::Api => "api",
		}
	}
}

/// A certificate with its key, loaded once and shared by every rule that
/// names the same files (see `certstore`).
pub struct KeyedCert {
	/// The certificate followed by its intermediates.
	pub chain: Vec<CertificateDer<'static>>,
	pub key: PrivateKeyDer<'static>,
	/// For serving TLS (tcp).
	pub certified: Arc<CertifiedKey>,
	/// DNS names it is valid for, for SNI selection.
	pub names: Vec<String>,
	/// For serving DTLS (udp): needs a PKCS#8 key; the error only matters to udp rules.
	pub dtls: Result<dtls::crypto::Certificate, ApiError>,
	/// Earliest notAfter of the chain.
	pub not_after: i64,
}

impl std::fmt::Debug for KeyedCert {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("KeyedCert").field("names", &self.names).field("not_after", &self.not_after).finish_non_exhaustive()
	}
}

impl KeyedCert {
	/// Reads the certificate, its chain and its key, and checks they belong together.
	pub fn load(cert_file: &str, chain_file: Option<&str>, key_file: &str) -> Result<KeyedCert, ApiError> {
		let chain = load_full_chain(cert_file, chain_file)?;
		let key = load_key(key_file)?;
		let signing = provider()
			.key_provider
			.load_private_key(key.clone_key())
			.map_err(|e| tls_error(format!("{key_file}: {e}")))?;
		let certified = CertifiedKey::new(chain.clone(), signing);
		certified
			.keys_match()
			.map_err(|e| tls_error(format!("{key_file} does not belong to {cert_file}: {e}")))?;
		let dtls = dtls_certificate(&chain, &key, cert_file, key_file);
		Ok(KeyedCert {
			names: cert_names(&chain[0]),
			not_after: earliest_expiry(&chain).unwrap_or(i64::MAX),
			chain,
			key,
			certified: Arc::new(certified),
			dtls,
		})
	}

	pub fn expired(&self, now: i64) -> bool {
		self.not_after <= now
	}
}

/// CA certificates (a root bundle or intermediates), loaded once and shared.
#[derive(Debug)]
pub struct CertBundle {
	pub certs: Vec<CertificateDer<'static>>,
	pub not_after: i64,
}

impl CertBundle {
	pub fn load(file: &str) -> Result<CertBundle, ApiError> {
		let certs = load_chain(file)?;
		Ok(CertBundle { not_after: earliest_expiry(&certs).unwrap_or(i64::MAX), certs })
	}

	fn roots(&self, file: &str) -> Result<RootCertStore, ApiError> {
		let mut roots = RootCertStore::empty();
		for cert in &self.certs {
			roots.add(cert.clone()).map_err(|e| tls_error(format!("{file}: {e}")))?;
		}
		Ok(roots)
	}
}

/// The loaded certificates one rule's TLS settings use (terminate mode).
#[derive(Clone, Default)]
pub struct RuleCerts {
	/// `tls.certificates`, in order.
	pub servers: Vec<Arc<KeyedCert>>,
	pub client_ca: Option<Arc<CertBundle>>,
	pub client_chain: Option<Arc<CertBundle>>,
	pub upstream_ca: Option<Arc<CertBundle>>,
	pub upstream_cert: Option<Arc<KeyedCert>>,
}

impl RuleCerts {
	/// Reads every file directly (callers without a certificate store, tests).
	pub fn load(spec: &TlsSpec) -> Result<RuleCerts, ApiError> {
		if spec.mode != TlsMode::Terminate {
			return Ok(RuleCerts::default());
		}
		let mut certs = RuleCerts::default();
		for c in &spec.certificates {
			certs.servers.push(Arc::new(KeyedCert::load(&c.cert_file, c.chain_file.as_deref(), &c.key_file)?));
		}
		let bundle = |f: &Option<String>| f.as_deref().map(|f| CertBundle::load(f).map(Arc::new)).transpose();
		if spec.client_auth.mode != ClientAuthMode::None {
			certs.client_ca = bundle(&spec.client_auth.ca_file)?;
			certs.client_chain = bundle(&spec.client_auth.chain_file)?;
		}
		if spec.upstream.tls {
			certs.upstream_ca = bundle(&spec.upstream.ca_file)?;
			if let (Some(cert), Some(key)) = (&spec.upstream.cert_file, &spec.upstream.key_file) {
				certs.upstream_cert = Some(Arc::new(KeyedCert::load(cert, spec.upstream.chain_file.as_deref(), key)?));
			}
		}
		Ok(certs)
	}
}

/// The error when no server certificate of the rule is still valid.
fn all_expired(spec: &TlsSpec) -> ApiError {
	let files: Vec<&str> = spec.certificates.iter().map(|c| c.cert_file.as_str()).collect();
	tls_error(format!("{CERT_EXPIRED}: every certificate of this rule has expired ({}); renew the files", files.join(", ")))
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
	Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Picks a certificate by SNI; the first certificate is the fallback.
#[derive(Debug)]
struct SniCertResolver {
	certs: Vec<(Vec<String>, Arc<CertifiedKey>)>,
}

impl ResolvesServerCert for SniCertResolver {
	fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		if let Some(name) = hello.server_name() {
			if let Some((_, key)) = self.certs.iter().find(|(names, _)| names.iter().any(|p| name_matches(p, name))) {
				return Some(key.clone());
			}
		}
		self.certs.first().map(|(_, key)| key.clone())
	}
}

/// Name of a cipher suite as written in `tls.options.cipher_suites`
/// (rustls / IANA style, e.g. `TLS13_AES_128_GCM_SHA256`).
fn suite_name(suite: &rustls::SupportedCipherSuite) -> String {
	format!("{:?}", suite.suite())
}

/// Cipher suites and protocol versions for terminating TLS, narrowed by `tls.options`.
/// A version left without any of the chosen suites is not offered.
fn server_crypto(
	options: Option<&TlsOptions>,
) -> Result<(Arc<rustls::crypto::CryptoProvider>, Vec<&'static rustls::SupportedProtocolVersion>), ApiError> {
	let mut provider = rustls::crypto::aws_lc_rs::default_provider();
	let mut versions: Vec<&'static rustls::SupportedProtocolVersion> = vec![&rustls::version::TLS13, &rustls::version::TLS12];
	let Some(o) = options else { return Ok((Arc::new(provider), versions)) };
	if o.min_version.as_deref() == Some("1.3") {
		versions.retain(|v| v.version == rustls::ProtocolVersion::TLSv1_3);
	}
	if !o.cipher_suites.is_empty() {
		let mut chosen = vec![];
		for name in &o.cipher_suites {
			let suite = provider.cipher_suites.iter().find(|s| suite_name(s) == *name).ok_or_else(|| {
				let known: Vec<String> = provider.cipher_suites.iter().map(suite_name).collect();
				tls_error(format!("options.cipher_suites: unknown {name:?} (known: {})", known.join(", ")))
			})?;
			if !chosen.contains(suite) {
				chosen.push(*suite);
			}
		}
		provider.cipher_suites = chosen;
	}
	versions.retain(|v| provider.cipher_suites.iter().any(|s| s.version() == *v));
	if versions.is_empty() {
		return Err(tls_error("options: none of cipher_suites can be used with min_version 1.3"));
	}
	Ok((Arc::new(provider), versions))
}

/// The server side of TLS termination: for TCP, and for QUIC (HTTP/3: TLS 1.3
/// only, the same certificates and client authentication, ALPN `h3`). The QUIC
/// side is an error text when `tls.options` leaves it without a TLS 1.3 suite.
/// The QUIC server settings, or why QUIC cannot be used with these TLS settings.
pub type QuicConfig = Result<Arc<ServerConfig>, String>;

fn server_configs(tls: &TlsSpec, loaded: &RuleCerts, now: i64) -> Result<(Arc<ServerConfig>, QuicConfig), ApiError> {
	let (provider, versions) = server_crypto(tls.options.as_ref())?;
	// an expired certificate is left out; its names get the first remaining one
	let certs: Vec<(Vec<String>, Arc<CertifiedKey>)> =
		loaded.servers.iter().filter(|c| !c.expired(now)).map(|c| (c.names.clone(), c.certified.clone())).collect();
	if certs.is_empty() {
		return Err(all_expired(tls));
	}

	let verifier = client_verifier(&tls.client_auth, loaded)?;
	let resolver = Arc::new(SniCertResolver { certs });
	let builder = ServerConfig::builder_with_provider(provider.clone())
		.with_protocol_versions(&versions)
		.map_err(|e| tls_error(e.to_string()))?;
	let builder = match &verifier {
		Some(verifier) => builder.with_client_cert_verifier(verifier.clone()),
		None => builder.with_no_client_auth(),
	};
	let mut config = builder.with_cert_resolver(resolver.clone());
	config.alpn_protocols = tls.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();

	let quic = (|| {
		let mut quic_provider = (*provider).clone();
		quic_provider.cipher_suites.retain(|s| s.version() == &rustls::version::TLS13);
		if quic_provider.cipher_suites.is_empty() {
			return Err("QUIC needs TLS 1.3, and tls.options.cipher_suites has no TLS 1.3 suite".to_string());
		}
		let builder = ServerConfig::builder_with_provider(Arc::new(quic_provider))
			.with_protocol_versions(&[&rustls::version::TLS13])
			.map_err(|e| e.to_string())?;
		let builder = match &verifier {
			Some(verifier) => builder.with_client_cert_verifier(verifier.clone()),
			None => builder.with_no_client_auth(),
		};
		let mut quic = builder.with_cert_resolver(resolver);
		quic.alpn_protocols = vec![b"h3".to_vec()];
		Ok(Arc::new(quic))
	})();
	Ok((Arc::new(config), quic))
}

/// Adds the configured intermediate CAs to whatever the client sent, so
/// clients that present only their own certificate still verify against the root.
#[derive(Debug)]
struct WithIntermediates {
	inner: Arc<dyn ClientCertVerifier>,
	extra: Vec<CertificateDer<'static>>,
}

impl ClientCertVerifier for WithIntermediates {
	fn offer_client_auth(&self) -> bool {
		self.inner.offer_client_auth()
	}

	fn client_auth_mandatory(&self) -> bool {
		self.inner.client_auth_mandatory()
	}

	fn root_hint_subjects(&self) -> &[DistinguishedName] {
		self.inner.root_hint_subjects()
	}

	fn verify_client_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		intermediates: &[CertificateDer<'_>],
		now: UnixTime,
	) -> Result<ClientCertVerified, rustls::Error> {
		let mut all: Vec<CertificateDer<'_>> = intermediates.to_vec();
		for cert in &self.extra {
			if !all.iter().any(|c| c.as_ref() == cert.as_ref()) {
				all.push(cert.clone());
			}
		}
		self.inner.verify_client_cert(end_entity, &all, now)
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<SigValid, rustls::Error> {
		self.inner.verify_tls12_signature(message, cert, dss)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<SigValid, rustls::Error> {
		self.inner.verify_tls13_signature(message, cert, dss)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.inner.supported_verify_schemes()
	}
}

/// Client certificate verification for TLS and DTLS alike: the root(s) in
/// `ca_file` are the only trust anchors; `chain_file` fills in intermediates.
fn client_verifier(auth: &ClientAuth, loaded: &RuleCerts) -> Result<Option<Arc<dyn ClientCertVerifier>>, ApiError> {
	let (mode, Some(ca), Some(bundle)) = (auth.mode, &auth.ca_file, &loaded.client_ca) else { return Ok(None) };
	if mode == ClientAuthMode::None {
		return Ok(None);
	}
	let builder = WebPkiClientVerifier::builder_with_provider(Arc::new(bundle.roots(ca)?), provider());
	let builder = if mode == ClientAuthMode::Optional { builder.allow_unauthenticated() } else { builder };
	let inner = builder.build().map_err(|e| tls_error(format!("{ca}: {e}")))?;
	let extra = loaded.client_chain.as_ref().map(|b| b.certs.clone()).unwrap_or_default();
	Ok(Some(Arc::new(WithIntermediates { inner, extra })))
}

/// Accepts any backend certificate (`insecure_skip_verify`).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
	fn verify_server_cert(
		&self,
		_: &CertificateDer<'_>,
		_: &[CertificateDer<'_>],
		_: &ServerName<'_>,
		_: &[u8],
		_: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.0.signature_verification_algorithms.supported_schemes()
	}
}

/// Client TLS towards a backend, reading the files of `up` (L7 backends, OIDC, CrowdSec).
pub(crate) fn client_config(up: &Upstream) -> Result<Arc<ClientConfig>, ApiError> {
	let upstream_cert = match (&up.cert_file, &up.key_file) {
		(Some(cert), Some(key)) => Some(Arc::new(KeyedCert::load(cert, up.chain_file.as_deref(), key)?)),
		_ => None,
	};
	let loaded = RuleCerts {
		upstream_ca: up.ca_file.as_deref().map(|f| CertBundle::load(f).map(Arc::new)).transpose()?,
		upstream_cert,
		..Default::default()
	};
	client_config_from(up, &loaded)
}

/// Client TLS towards a backend from certificates already loaded.
fn client_config_from(up: &Upstream, loaded: &RuleCerts) -> Result<Arc<ClientConfig>, ApiError> {
	let provider = provider();
	let builder = ClientConfig::builder_with_provider(provider.clone())
		.with_safe_default_protocol_versions()
		.map_err(|e| tls_error(e.to_string()))?;
	let builder = if up.insecure_skip_verify {
		builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
	} else {
		let roots = match (&up.ca_file, &loaded.upstream_ca) {
			(Some(ca), Some(bundle)) => bundle.roots(ca)?,
			_ => RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() },
		};
		builder.with_root_certificates(roots)
	};
	let config = match (&up.cert_file, &loaded.upstream_cert) {
		(Some(cert), Some(keyed)) => builder
			.with_client_auth_cert(keyed.chain.clone(), keyed.key.clone_key())
			.map_err(|e| tls_error(format!("{cert}: {e}")))?,
		_ => builder.with_no_client_auth(),
	};
	Ok(Arc::new(config))
}

fn dtls_certificate(
	chain: &[CertificateDer<'static>],
	key: &PrivateKeyDer<'static>,
	cert_file: &str,
	key_file: &str,
) -> Result<dtls::crypto::Certificate, ApiError> {
	let PrivateKeyDer::Pkcs8(key) = key else {
		return Err(tls_error(format!(
			"{key_file}: DTLS needs a PKCS#8 key (convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem)"
		)));
	};
	let private_key = dtls_private_key(key.secret_pkcs8_der()).map_err(|e| tls_error(format!("{key_file}: {e}")))?;
	let leaf_key = x509_parser::parse_x509_certificate(chain[0].as_ref())
		.map(|(_, c)| c.public_key().subject_public_key.data.to_vec())
		.map_err(|e| tls_error(format!("{cert_file}: {e}")))?;
	if leaf_key != dtls_public_key(&private_key) {
		return Err(tls_error(format!("{key_file} does not belong to {cert_file}")));
	}
	Ok(dtls::crypto::Certificate { certificate: chain.to_vec(), private_key })
}

/// A DTLS private key from PKCS#8 DER: ECDSA P-256, Ed25519 or RSA (what the
/// dtls crate can sign with). Built with ring directly, so no rcgen type has to
/// cross into the dtls crate (which uses an older rcgen).
pub fn dtls_private_key(pkcs8: &[u8]) -> Result<dtls::crypto::CryptoPrivateKey, String> {
	use dtls::crypto::{CryptoPrivateKey, CryptoPrivateKeyKind};
	use ring::signature::{EcdsaKeyPair, Ed25519KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
	let kind = if let Ok(k) = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &ring::rand::SystemRandom::new()) {
		CryptoPrivateKeyKind::Ecdsa256(k)
	} else if let Ok(k) = Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8) {
		CryptoPrivateKeyKind::Ed25519(k)
	} else if let Ok(k) = ring::rsa::KeyPair::from_pkcs8(pkcs8) {
		CryptoPrivateKeyKind::Rsa256(k)
	} else {
		return Err("DTLS needs an ECDSA P-256, Ed25519 or RSA key".into());
	};
	Ok(CryptoPrivateKey { kind, serialized_der: pkcs8.to_vec() })
}

/// The public key as it appears in a certificate's subjectPublicKey.
fn dtls_public_key(key: &dtls::crypto::CryptoPrivateKey) -> Vec<u8> {
	use dtls::crypto::CryptoPrivateKeyKind;
	use ring::signature::KeyPair;
	match &key.kind {
		CryptoPrivateKeyKind::Ecdsa256(k) => k.public_key().as_ref().to_vec(),
		CryptoPrivateKeyKind::Ed25519(k) => k.public_key().as_ref().to_vec(),
		CryptoPrivateKeyKind::Rsa256(k) => k.public_key().as_ref().to_vec(),
	}
}

/// Everything needed per connection, rebuilt when the rule changes or on SIGHUP.
pub struct TlsRuntime {
	pub spec: TlsSpec,
	pub starttls: Option<StartTls>,
	pub starttls_required: bool,
	/// Host name rproxy uses in its own STARTTLS greeting.
	pub greeting_name: String,
	/// Server side of TLS termination (tcp).
	pub server_config: Option<Arc<ServerConfig>>,
	/// Server side of QUIC for HTTP/3 (tcp terminate); an error text when it cannot be used.
	pub quic_config: Option<QuicConfig>,
	pub connector: Option<tokio_rustls::TlsConnector>,
	dtls_certs: Vec<dtls::crypto::Certificate>,
	dtls_client_verifier: Option<Arc<dyn ClientCertVerifier>>,
	dtls_upstream_roots: Option<RootCertStore>,
	dtls_upstream_cert: Option<dtls::crypto::Certificate>,
}

impl TlsRuntime {
	/// `build` with certificates read directly from the files (no certificate store).
	pub fn load(protocol: Protocol, spec: &TlsSpec, starttls: Option<StartTls>, starttls_required: bool) -> Result<Self, ApiError> {
		validate(protocol, spec, starttls)?;
		Self::build(protocol, spec, starttls, starttls_required, &RuleCerts::load(spec)?)
	}

	/// Builds the TLS / DTLS settings from certificates already loaded
	/// (`RuleCerts`, from the certificate store). Expired server certificates
	/// are left out; if every one has expired it fails (`is_cert_expired`).
	pub fn build(
		protocol: Protocol,
		spec: &TlsSpec,
		starttls: Option<StartTls>,
		starttls_required: bool,
		loaded: &RuleCerts,
	) -> Result<Self, ApiError> {
		validate(protocol, spec, starttls)?;
		let mut rt = TlsRuntime {
			spec: spec.clone(),
			starttls,
			starttls_required,
			greeting_name: "rproxy".to_string(),
			server_config: None,
			quic_config: None,
			connector: None,
			dtls_certs: vec![],
			dtls_client_verifier: None,
			dtls_upstream_roots: None,
			dtls_upstream_cert: None,
		};
		if spec.mode != TlsMode::Terminate {
			return Ok(rt);
		}
		let now = unix_now();
		match protocol {
			Protocol::Tcp => {
				let (tcp, quic) = server_configs(spec, loaded, now)?;
				rt.server_config = Some(tcp);
				rt.quic_config = Some(quic);
				if let Some(name) =
					loaded.servers.first().and_then(|c| c.names.iter().find(|n| !n.starts_with("*.")).cloned())
				{
					rt.greeting_name = name;
				}
				if spec.upstream.tls {
					rt.connector = Some(tokio_rustls::TlsConnector::from(client_config_from(&spec.upstream, loaded)?));
				}
			}
			Protocol::Udp => {
				for cert in &loaded.servers {
					let dtls = cert.dtls.clone()?;
					if !cert.expired(now) {
						rt.dtls_certs.push(dtls);
					}
				}
				if rt.dtls_certs.is_empty() {
					return Err(all_expired(spec));
				}
				rt.dtls_client_verifier = client_verifier(&spec.client_auth, loaded)?;
				if spec.upstream.tls {
					rt.dtls_upstream_roots = Some(match (&spec.upstream.ca_file, &loaded.upstream_ca) {
						(Some(ca), Some(bundle)) => bundle.roots(ca)?,
						_ => RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() },
					});
					if let (Some(cert), Some(keyed)) = (&spec.upstream.cert_file, &loaded.upstream_cert) {
						rt.dtls_upstream_cert = Some(
							keyed.dtls.clone().map_err(|e| ApiError::tls_config(format!("{cert}: {}", e.message)))?,
						);
					}
				}
			}
		}
		Ok(rt)
	}

	pub fn mode(&self) -> TlsMode {
		self.spec.mode
	}

	/// DTLS server settings for one client session. the dtls crate proves the
	/// client holds its key (CertificateVerify); the chain is checked by
	/// `verify_dtls_client` right after the handshake, before any data flows.
	pub fn dtls_server_config(&self) -> dtls::config::Config {
		use dtls::config::ClientAuthType;
		let client_auth = match self.spec.client_auth.mode {
			ClientAuthMode::None => ClientAuthType::NoClientCert,
			ClientAuthMode::Optional => ClientAuthType::RequestClientCert,
			ClientAuthMode::Required => ClientAuthType::RequireAnyClientCert,
		};
		dtls::config::Config {
			certificates: self.dtls_certs.clone(),
			client_auth,
			extended_master_secret: dtls::config::ExtendedMasterSecretType::Require,
			..Default::default()
		}
	}

	/// Checks a DTLS client's certificate chain the same way TLS does.
	pub fn verify_dtls_client(&self, peer: &[Vec<u8>]) -> Result<(), String> {
		let Some(verifier) = &self.dtls_client_verifier else { return Ok(()) };
		let Some((leaf, rest)) = peer.split_first() else {
			return if self.spec.client_auth.mode == ClientAuthMode::Required {
				Err("client certificate required".into())
			} else {
				Ok(())
			};
		};
		let leaf = CertificateDer::from(leaf.clone());
		let rest: Vec<CertificateDer<'_>> = rest.iter().map(|c| CertificateDer::from(c.clone())).collect();
		verifier.verify_client_cert(&leaf, &rest, UnixTime::now()).map(|_| ()).map_err(|e| e.to_string())
	}

	/// DTLS client settings towards the backend.
	pub fn dtls_client_config(&self, target_host: &str) -> dtls::config::Config {
		let up = &self.spec.upstream;
		dtls::config::Config {
			certificates: self.dtls_upstream_cert.clone().into_iter().collect(),
			roots_cas: self.dtls_upstream_roots.clone().unwrap_or_else(RootCertStore::empty),
			server_name: up.server_name.clone().unwrap_or_else(|| target_host.to_string()),
			insecure_skip_verify: up.insecure_skip_verify,
			extended_master_secret: dtls::config::ExtendedMasterSecretType::Require,
			..Default::default()
		}
	}

	/// Server name to verify on the backend's TLS certificate.
	pub fn upstream_name(&self, target_host: &str) -> Result<ServerName<'static>, ApiError> {
		let name = self.spec.upstream.server_name.clone().unwrap_or_else(|| target_host.to_string());
		ServerName::try_from(name.clone()).map_err(|_| tls_error(format!("invalid upstream server_name: {name}")))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn inspects_certificate_expiry() {
		let key = rcgen::KeyPair::generate().unwrap();
		let mut params = rcgen::CertificateParams::new(vec!["a.test".to_string()]).unwrap();
		params.not_before = time::OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
		params.not_after = time::OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap();
		let cert = params.self_signed(&key).unwrap();
		let check = inspect_certificate(cert.der(), 1_999_999_000).unwrap();
		assert_eq!(check, CertCheck { not_after: 2_000_000_000, seconds_left: 1000, expired: false });
		assert!(inspect_certificate(cert.der(), 2_000_000_000).unwrap().expired, "expired at notAfter");
		assert_eq!(earliest_expiry(&[cert.der().clone()]), Some(2_000_000_000));
		assert!(inspect_certificate(b"not a certificate", 0).is_err());
	}

	fn route() -> Route {
		Route {
			server_name: String::new(),
			server_names: vec![],
			remote_addr: "10.0.0.1".into(),
			remote_port: 443,
			passthrough: false,
		}
	}

	#[test]
	fn double_wildcard_matches_any_depth_and_priorities() {
		assert!(name_matches("**.tenant.example", "a.tenant.example"));
		assert!(name_matches("**.tenant.example", "a.b.c.tenant.example"));
		assert!(name_matches("**.Tenant.example", "A.B.TENANT.example"));
		assert!(!name_matches("**.tenant.example", "tenant.example"), "not the apex");
		assert!(!name_matches("**.tenant.example", "xtenant.example"));
		assert!(!name_matches("**.tenant.example", ".tenant.example"));

		let lists: Vec<Vec<String>> = [
			vec!["**.example"],
			vec!["**.tenant.example"],
			vec!["*.tenant.example"],
			vec!["registry.example", "a.tenant.example"],
		]
		.into_iter()
		.map(|l| l.into_iter().map(String::from).collect())
		.collect();
		let best = |name| best_match(lists.iter().map(Vec::as_slice), name);
		assert_eq!(best("a.tenant.example"), Some(3), "exact first");
		assert_eq!(best("b.tenant.example"), Some(2), "then *.");
		assert_eq!(best("x.b.tenant.example"), Some(1), "then the longer **. suffix");
		assert_eq!(best("other.example"), Some(0));
		assert_eq!(best("registry.example"), Some(3));
		assert_eq!(best("example"), None);
		// equal matches: the earlier list wins
		let same: Vec<Vec<String>> = vec![vec!["**.a.test".into()], vec!["**.a.test".into()]];
		assert_eq!(best_match(same.iter().map(Vec::as_slice), "x.a.test"), Some(0));
	}

	#[test]
	fn route_names_and_passthrough_are_validated() {
		let cert = CertFiles { cert_file: "c".into(), key_file: "k".into(), ..Default::default() };
		let spec = |routes: Vec<Route>, mode| TlsSpec { mode, routes, certificates: if mode == TlsMode::Terminate { vec![cert.clone()] } else { vec![] }, ..Default::default() };
		let check = |s: &TlsSpec, starttls| validate_range(Protocol::Tcp, s, starttls, 1).map_err(|e| e.message);
		let names = Route { server_names: vec!["registry.example".into(), "**.tenant.example".into()], passthrough: true, ..route() };
		assert_eq!(check(&spec(vec![names.clone()], TlsMode::Terminate), None), Ok(()));
		let both = Route { server_name: "a.test".into(), ..names.clone() };
		assert!(check(&spec(vec![both], TlsMode::Terminate), None).unwrap_err().contains("not both"));
		assert!(check(&spec(vec![route()], TlsMode::Terminate), None).unwrap_err().contains("server_name"));
		let bad = Route { server_names: vec!["***.x".into()], ..route() };
		assert!(check(&spec(vec![bad], TlsMode::Terminate), None).unwrap_err().contains("invalid server_name"));
		assert!(check(&spec(vec![names.clone()], TlsMode::Sni), None).unwrap_err().contains("mode terminate"));
		assert!(check(&spec(vec![names], TlsMode::Terminate), Some(StartTls::Smtp)).unwrap_err().contains("starttls"));
	}

	#[test]
	fn wildcard_matches_one_label() {
		assert!(name_matches("*.example.com", "mail.example.com"));
		assert!(name_matches("*.Example.com", "MAIL.example.com"));
		assert!(!name_matches("*.example.com", "a.b.example.com"));
		assert!(!name_matches("*.example.com", "example.com"));
		assert!(name_matches("example.com", "example.com"));
	}

	#[test]
	fn validation_rules() {
		let terminate = TlsSpec { mode: TlsMode::Terminate, ..Default::default() };
		assert_eq!(validate(Protocol::Tcp, &terminate, None).unwrap_err().code, "tls_config");
		let sni = TlsSpec { mode: TlsMode::Sni, ..Default::default() };
		// udp sni (#130): DTLS and QUIC server names
		assert!(validate(Protocol::Udp, &sni, None).is_ok());
		assert!(validate(Protocol::Tcp, &sni, None).is_ok());
		assert_eq!(validate(Protocol::Tcp, &sni, Some(StartTls::Smtp)).unwrap_err().code, "tls_config");
		let mut auth = TlsSpec {
			mode: TlsMode::Terminate,
			certificates: vec![CertFiles { cert_file: "a".into(), chain_file: None, key_file: "b".into(), ..Default::default() }],
			..Default::default()
		};
		auth.client_auth.mode = ClientAuthMode::Required;
		assert_eq!(validate(Protocol::Tcp, &auth, None).unwrap_err().code, "tls_config");
		let mut dtls_alpn = TlsSpec {
			mode: TlsMode::Terminate,
			certificates: vec![CertFiles { cert_file: "a".into(), chain_file: None, key_file: "b".into(), ..Default::default() }],
			..Default::default()
		};
		dtls_alpn.alpn = vec!["h2".into()];
		assert_eq!(validate(Protocol::Udp, &dtls_alpn, None).unwrap_err().code, "tls_config");
		let reject_without_routes = TlsSpec { mode: TlsMode::Sni, unmatched: Unmatched::Reject, ..Default::default() };
		assert_eq!(validate(Protocol::Tcp, &reject_without_routes, None).unwrap_err().code, "tls_config");
		let routed = TlsSpec {
			mode: TlsMode::Sni,
			routes: vec![Route { server_name: "a.test".into(), remote_addr: "10.0.0.1".into(), remote_port: 65_530, ..route() }],
			..Default::default()
		};
		assert!(validate_range(Protocol::Tcp, &routed, None, 6).is_ok());
		assert_eq!(validate_range(Protocol::Tcp, &routed, None, 7).unwrap_err().code, "invalid");
	}

	#[test]
	fn missing_files_are_reported() {
		let spec = TlsSpec {
			mode: TlsMode::Terminate,
			certificates: vec![CertFiles { cert_file: "/nonexistent.pem".into(), chain_file: None, key_file: "/nonexistent.key".into(), ..Default::default() }],
			..Default::default()
		};
		let err = TlsRuntime::load(Protocol::Tcp, &spec, None, true).err().unwrap();
		assert_eq!(err.code, "tls_config");
		assert!(err.message.contains("/nonexistent.pem"));
	}
}
