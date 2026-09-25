//! TLS / DTLS settings of a rule: what the API accepts, and the rustls /
//! webrtc-dtls configurations built from it.

use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::client::danger::HandshakeSignatureValid as SigValid;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::DistinguishedName;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::rule::Protocol;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
	/// `mail.example.com`, or `*.example.com` for one label under it.
	pub server_name: String,
	pub remote_addr: String,
	pub remote_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertFiles {
	/// PEM server certificate. May also hold the chain after it (leaf first).
	pub cert_file: String,
	/// PEM intermediate CA certificates, sent after the server certificate.
	/// The root may be left out; clients already trust it.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub chain_file: Option<String>,
	/// PEM private key (PKCS#8; for tcp also PKCS#1 / SEC1).
	pub key_file: String,
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
pub fn validate(protocol: Protocol, tls: &TlsSpec, starttls: Option<StartTls>) -> Result<(), ApiError> {
	match (protocol, tls.mode) {
		(Protocol::Udp, TlsMode::Sni) => {
			return Err(ApiError::unsupported("sni routing is supported for tcp only; use terminate for DTLS"));
		}
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
	if tls.upstream.cert_file.is_some() != tls.upstream.key_file.is_some() {
		return Err(tls_error("upstream cert_file and key_file must be given together"));
	}
	if tls.upstream.chain_file.is_some() && tls.upstream.cert_file.is_none() {
		return Err(tls_error("upstream chain_file needs cert_file"));
	}
	for route in &tls.routes {
		if !valid_pattern(&route.server_name) {
			return Err(tls_error(format!("invalid server_name: {}", route.server_name)));
		}
		crate::rule::validate_remote(&route.remote_addr, route.remote_port)?;
	}
	if let Some(proto) = starttls {
		if protocol != Protocol::Tcp || tls.mode != TlsMode::Terminate {
			return Err(tls_error(format!("starttls {} needs protocol tcp and tls mode terminate", proto.as_str())));
		}
	}
	Ok(())
}

fn valid_pattern(p: &str) -> bool {
	let name = p.strip_prefix("*.").unwrap_or(p);
	!name.is_empty()
		&& name.len() <= 253
		&& name.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// Whether `name` (from SNI) matches `pattern`; `*.` matches exactly one label.
pub fn name_matches(pattern: &str, name: &str) -> bool {
	let (pattern, name) = (pattern.to_ascii_lowercase(), name.to_ascii_lowercase());
	match pattern.strip_prefix("*.") {
		Some(suffix) => name.split_once('.').is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
		None => pattern == name,
	}
}

fn read(path: &str) -> Result<Vec<u8>, ApiError> {
	fs::read(path).map_err(|e| tls_error(format!("{path}: {e}")))
}

fn load_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, ApiError> {
	let data = read(path)?;
	let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(&data[..]))
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
	rustls_pemfile::private_key(&mut BufReader::new(&data[..]))
		.map_err(|e| tls_error(format!("{path}: {e}")))?
		.ok_or_else(|| tls_error(format!("{path}: no private key block")))
}

fn load_roots(path: &str) -> Result<RootCertStore, ApiError> {
	let mut roots = RootCertStore::empty();
	for cert in load_chain(path)? {
		roots.add(cert).map_err(|e| tls_error(format!("{path}: {e}")))?;
	}
	Ok(roots)
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

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
	Arc::new(rustls::crypto::ring::default_provider())
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

fn server_config(tls: &TlsSpec) -> Result<Arc<ServerConfig>, ApiError> {
	let provider = provider();
	let mut certs = vec![];
	for files in &tls.certificates {
		let chain = load_full_chain(&files.cert_file, files.chain_file.as_deref())?;
		let key = load_key(&files.key_file)?;
		let signing = provider
			.key_provider
			.load_private_key(key)
			.map_err(|e| tls_error(format!("{}: {e}", files.key_file)))?;
		let names = cert_names(&chain[0]);
		let certified = CertifiedKey::new(chain, signing);
		certified
			.keys_match()
			.map_err(|e| tls_error(format!("{} does not belong to {}: {e}", files.key_file, files.cert_file)))?;
		certs.push((names, Arc::new(certified)));
	}

	let builder = ServerConfig::builder_with_provider(provider.clone())
		.with_safe_default_protocol_versions()
		.map_err(|e| tls_error(e.to_string()))?;
	let builder = match client_verifier(&tls.client_auth)? {
		Some(verifier) => builder.with_client_cert_verifier(verifier),
		None => builder.with_no_client_auth(),
	};
	let mut config = builder.with_cert_resolver(Arc::new(SniCertResolver { certs }));
	config.alpn_protocols = tls.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
	Ok(Arc::new(config))
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
fn client_verifier(auth: &ClientAuth) -> Result<Option<Arc<dyn ClientCertVerifier>>, ApiError> {
	let (mode, Some(ca)) = (auth.mode, &auth.ca_file) else { return Ok(None) };
	if mode == ClientAuthMode::None {
		return Ok(None);
	}
	let builder = WebPkiClientVerifier::builder_with_provider(Arc::new(load_roots(ca)?), provider());
	let builder = if mode == ClientAuthMode::Optional { builder.allow_unauthenticated() } else { builder };
	let inner = builder.build().map_err(|e| tls_error(format!("{ca}: {e}")))?;
	let extra = match &auth.chain_file {
		Some(file) => load_chain(file)?,
		None => vec![],
	};
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

fn client_config(up: &Upstream) -> Result<Arc<ClientConfig>, ApiError> {
	let provider = provider();
	let builder = ClientConfig::builder_with_provider(provider.clone())
		.with_safe_default_protocol_versions()
		.map_err(|e| tls_error(e.to_string()))?;
	let builder = if up.insecure_skip_verify {
		builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
	} else {
		let roots = match &up.ca_file {
			Some(ca) => load_roots(ca)?,
			None => RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() },
		};
		builder.with_root_certificates(roots)
	};
	let config = match (&up.cert_file, &up.key_file) {
		(Some(cert), Some(key)) => builder
			.with_client_auth_cert(load_full_chain(cert, up.chain_file.as_deref())?, load_key(key)?)
			.map_err(|e| tls_error(format!("{cert}: {e}")))?,
		_ => builder.with_no_client_auth(),
	};
	Ok(Arc::new(config))
}

fn dtls_certificate(files: &CertFiles) -> Result<webrtc_dtls::crypto::Certificate, ApiError> {
	let chain = load_full_chain(&files.cert_file, files.chain_file.as_deref())?;
	let PrivateKeyDer::Pkcs8(key) = load_key(&files.key_file)? else {
		return Err(tls_error(format!(
			"{}: DTLS needs a PKCS#8 key (convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem)",
			files.key_file
		)));
	};
	let pair = rcgen::KeyPair::try_from(key.secret_pkcs8_der()).map_err(|e| tls_error(format!("{}: {e}", files.key_file)))?;
	let leaf_spki = x509_parser::parse_x509_certificate(chain[0].as_ref())
		.map(|(_, c)| c.public_key().raw.to_vec())
		.map_err(|e| tls_error(format!("{}: {e}", files.cert_file)))?;
	if leaf_spki != pair.public_key_der() {
		return Err(tls_error(format!("{} does not belong to {}", files.key_file, files.cert_file)));
	}
	let private_key = webrtc_dtls::crypto::CryptoPrivateKey::try_from(&pair)
		.map_err(|e| tls_error(format!("{}: {e}", files.key_file)))?;
	Ok(webrtc_dtls::crypto::Certificate { certificate: chain, private_key })
}

/// Everything needed per connection, rebuilt when the rule changes or on SIGHUP.
pub struct TlsRuntime {
	pub spec: TlsSpec,
	pub starttls: Option<StartTls>,
	pub starttls_required: bool,
	/// Host name rproxy uses in its own STARTTLS greeting.
	pub greeting_name: String,
	pub acceptor: Option<tokio_rustls::TlsAcceptor>,
	pub connector: Option<tokio_rustls::TlsConnector>,
	dtls_certs: Vec<webrtc_dtls::crypto::Certificate>,
	dtls_client_verifier: Option<Arc<dyn ClientCertVerifier>>,
	dtls_upstream_roots: Option<RootCertStore>,
	dtls_upstream_cert: Option<webrtc_dtls::crypto::Certificate>,
}

impl TlsRuntime {
	/// Reads every file the spec names; fails if any is missing or invalid.
	pub fn build(
		protocol: Protocol,
		spec: &TlsSpec,
		starttls: Option<StartTls>,
		starttls_required: bool,
	) -> Result<Self, ApiError> {
		validate(protocol, spec, starttls)?;
		let mut rt = TlsRuntime {
			spec: spec.clone(),
			starttls,
			starttls_required,
			greeting_name: "rproxy".to_string(),
			acceptor: None,
			connector: None,
			dtls_certs: vec![],
			dtls_client_verifier: None,
			dtls_upstream_roots: None,
			dtls_upstream_cert: None,
		};
		if spec.mode != TlsMode::Terminate {
			return Ok(rt);
		}
		match protocol {
			Protocol::Tcp => {
				rt.acceptor = Some(tokio_rustls::TlsAcceptor::from(server_config(spec)?));
				if let Some(name) = load_chain(&spec.certificates[0].cert_file)?
					.first()
					.and_then(|c| cert_names(c).into_iter().find(|n| !n.starts_with("*.")))
				{
					rt.greeting_name = name;
				}
				if spec.upstream.tls {
					rt.connector = Some(tokio_rustls::TlsConnector::from(client_config(&spec.upstream)?));
				}
			}
			Protocol::Udp => {
				rt.dtls_certs = spec.certificates.iter().map(dtls_certificate).collect::<Result<_, _>>()?;
				rt.dtls_client_verifier = client_verifier(&spec.client_auth)?;
				if spec.upstream.tls {
					rt.dtls_upstream_roots = Some(match &spec.upstream.ca_file {
						Some(ca) => load_roots(ca)?,
						None => RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() },
					});
					if let (Some(cert), Some(key)) = (&spec.upstream.cert_file, &spec.upstream.key_file) {
						rt.dtls_upstream_cert = Some(dtls_certificate(&CertFiles {
							cert_file: cert.clone(),
							chain_file: spec.upstream.chain_file.clone(),
							key_file: key.clone(),
						})?);
					}
				}
			}
		}
		Ok(rt)
	}

	pub fn mode(&self) -> TlsMode {
		self.spec.mode
	}

	/// DTLS server settings for one client session. webrtc-dtls proves the
	/// client holds its key (CertificateVerify); the chain is checked by
	/// `verify_dtls_client` right after the handshake, before any data flows.
	pub fn dtls_server_config(&self) -> webrtc_dtls::config::Config {
		use webrtc_dtls::config::ClientAuthType;
		let client_auth = match self.spec.client_auth.mode {
			ClientAuthMode::None => ClientAuthType::NoClientCert,
			ClientAuthMode::Optional => ClientAuthType::RequestClientCert,
			ClientAuthMode::Required => ClientAuthType::RequireAnyClientCert,
		};
		webrtc_dtls::config::Config {
			certificates: self.dtls_certs.clone(),
			client_auth,
			extended_master_secret: webrtc_dtls::config::ExtendedMasterSecretType::Require,
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
	pub fn dtls_client_config(&self, target_host: &str) -> webrtc_dtls::config::Config {
		let up = &self.spec.upstream;
		webrtc_dtls::config::Config {
			certificates: self.dtls_upstream_cert.clone().into_iter().collect(),
			roots_cas: self.dtls_upstream_roots.clone().unwrap_or_else(RootCertStore::empty),
			server_name: up.server_name.clone().unwrap_or_else(|| target_host.to_string()),
			insecure_skip_verify: up.insecure_skip_verify,
			extended_master_secret: webrtc_dtls::config::ExtendedMasterSecretType::Require,
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
		assert_eq!(validate(Protocol::Udp, &sni, None).unwrap_err().code, "unsupported");
		assert!(validate(Protocol::Tcp, &sni, None).is_ok());
		assert_eq!(validate(Protocol::Tcp, &sni, Some(StartTls::Smtp)).unwrap_err().code, "tls_config");
		let mut auth = TlsSpec {
			mode: TlsMode::Terminate,
			certificates: vec![CertFiles { cert_file: "a".into(), chain_file: None, key_file: "b".into() }],
			..Default::default()
		};
		auth.client_auth.mode = ClientAuthMode::Required;
		assert_eq!(validate(Protocol::Tcp, &auth, None).unwrap_err().code, "tls_config");
	}

	#[test]
	fn missing_files_are_reported() {
		let spec = TlsSpec {
			mode: TlsMode::Terminate,
			certificates: vec![CertFiles { cert_file: "/nonexistent.pem".into(), chain_file: None, key_file: "/nonexistent.key".into() }],
			..Default::default()
		};
		let err = TlsRuntime::build(Protocol::Tcp, &spec, None, true).err().unwrap();
		assert_eq!(err.code, "tls_config");
		assert!(err.message.contains("/nonexistent.pem"));
	}
}
