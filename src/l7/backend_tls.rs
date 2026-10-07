//! TLS towards the https:// servers of one service (#236, the Gateway API's
//! BackendTLSPolicy): its own CA, SNI name and client certificate instead of the
//! rule's `tls.upstream`, and `subject_alt_names` checked instead of the name.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::tls::config::{CertBundle, Upstream};

/// `tls` of a service.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceTlsSpec {
	/// SNI and the name verified on the certificate (default: the URL's host).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub server_name: Option<String>,
	/// CA certificates for the servers (default: the Mozilla root set).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ca_file: Option<String>,
	/// One of these must be a DNS name or URI in the certificate's SAN (instead of `server_name`).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub subject_alt_names: Vec<String>,
	/// Client certificate shown to the servers.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cert_file: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub key_file: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub chain_file: Option<String>,
	/// Skip verifying the servers' certificates. For testing only.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub insecure_skip_verify: bool,
}

impl ServiceTlsSpec {
	pub fn validate(&self, what: &str) -> Result<(), ApiError> {
		let bad = |m: String| Err(ApiError::invalid(format!("{what}: {m}")));
		if self.cert_file.is_some() != self.key_file.is_some() {
			return bad("cert_file and key_file must be given together".into());
		}
		if self.chain_file.is_some() && self.cert_file.is_none() {
			return bad("chain_file needs cert_file".into());
		}
		if let Some(n) = &self.server_name {
			if ServerName::try_from(n.as_str()).is_err() {
				return bad(format!("server_name {n:?} is not a host name or IP address"));
			}
		}
		for n in &self.subject_alt_names {
			if n.is_empty() || n.chars().any(|c| c.is_whitespace() || c.is_control()) {
				return bad(format!("subject_alt_names: {n:?} is not a DNS name or URI"));
			}
		}
		if self.insecure_skip_verify && (!self.subject_alt_names.is_empty() || self.ca_file.is_some()) {
			return bad("insecure_skip_verify takes no ca_file or subject_alt_names".into());
		}
		Ok(())
	}

	/// The files this uses (for `--check-config`).
	pub fn files(&self) -> impl Iterator<Item = &String> {
		[&self.ca_file, &self.cert_file, &self.key_file, &self.chain_file].into_iter().flatten()
	}

	fn upstream(&self) -> Upstream {
		Upstream {
			tls: true,
			server_name: self.server_name.clone(),
			ca_file: self.ca_file.clone(),
			insecure_skip_verify: self.insecure_skip_verify,
			cert_file: self.cert_file.clone(),
			chain_file: self.chain_file.clone(),
			key_file: self.key_file.clone(),
		}
	}

	/// The client configuration (files read now), without ALPN.
	pub fn client_config(&self) -> Result<ClientConfig, ApiError> {
		let mut config = (*crate::tls::config::client_config(&self.upstream())?).clone();
		if !self.subject_alt_names.is_empty() {
			let roots = match &self.ca_file {
				Some(f) => CertBundle::load(f)?.roots(f)?,
				None => RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() },
			};
			let verifier = SanVerifier {
				roots: Arc::new(roots),
				provider: crate::tls::config::provider(),
				names: self.subject_alt_names.clone(),
			};
			config.dangerous().set_certificate_verifier(Arc::new(verifier));
		}
		Ok(config)
	}
}

/// Verifies the chain to `roots`, then that one of `names` is a SAN (DNS name or URI) of the certificate.
#[derive(Debug)]
struct SanVerifier {
	roots: Arc<RootCertStore>,
	provider: Arc<rustls::crypto::CryptoProvider>,
	names: Vec<String>,
}

/// Whether one of `wanted` is among the certificate's SAN DNS names or URIs (#236).
pub fn san_matches(der: &[u8], wanted: &[String]) -> Result<bool, String> {
	use x509_parser::extensions::GeneralName;
	let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| e.to_string())?;
	let Ok(Some(san)) = cert.subject_alternative_name() else { return Ok(false) };
	Ok(san.value.general_names.iter().any(|g| match g {
		GeneralName::URI(uri) => wanted.iter().any(|w| w == uri),
		GeneralName::DNSName(dns) => wanted.iter().any(|w| dns_matches(dns, w)),
		_ => false,
	}))
}

/// A SAN DNS name (`*.example.com` covers one label) against a wanted name.
fn dns_matches(san: &str, wanted: &str) -> bool {
	let (san, wanted) = (san.trim_end_matches('.').to_ascii_lowercase(), wanted.trim_end_matches('.').to_ascii_lowercase());
	if san == wanted {
		return true;
	}
	match (san.strip_prefix("*."), wanted.split_once('.')) {
		(Some(base), Some((label, rest))) => !label.is_empty() && base == rest,
		_ => false,
	}
}

impl ServerCertVerifier for SanVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp: &[u8],
		now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;
		rustls::client::verify_server_cert_signed_by_trust_anchor(
			&cert,
			&self.roots,
			intermediates,
			now,
			self.provider.signature_verification_algorithms.all,
		)?;
		match san_matches(end_entity.as_ref(), &self.names) {
			Ok(true) => Ok(ServerCertVerified::assertion()),
			Ok(false) => Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)),
			Err(e) => Err(rustls::Error::General(format!("certificate: {e}"))),
		}
	}

	fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
	}

	fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		self.provider.signature_verification_algorithms.supported_schemes()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn san_names_and_uris() {
		let mut params = rcgen::CertificateParams::new(vec!["abc.example.com".to_string(), "*.wild.example".to_string()]).unwrap();
		params.subject_alt_names.push(rcgen::SanType::URI("spiffe://abc.example.com/test-identity".try_into().unwrap()));
		let key = rcgen::KeyPair::generate().unwrap();
		let der = params.self_signed(&key).unwrap().der().to_vec();
		let has = |names: &[&str]| san_matches(&der, &names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
		assert!(has(&["abc.example.com"]));
		assert!(has(&["ABC.example.com."]));
		assert!(has(&["dce.example.com", "spiffe://abc.example.com/test-identity"]));
		assert!(has(&["x.wild.example"]));
		assert!(!has(&["a.b.wild.example"]), "a wildcard covers one label");
		assert!(!has(&["dce.example.com"]));
		assert!(!has(&["spiffe://abc.example.com/other"]));
	}

	#[test]
	fn validation() {
		let spec = |v: serde_json::Value| serde_json::from_value::<ServiceTlsSpec>(v).unwrap().validate("t");
		assert!(spec(serde_json::json!({"server_name": "abc.example.com", "subject_alt_names": ["spiffe://a/b"]})).is_ok());
		assert!(spec(serde_json::json!({"cert_file": "/c"})).unwrap_err().message.contains("together"));
		assert!(spec(serde_json::json!({"server_name": "not a name"})).is_err());
		assert!(spec(serde_json::json!({"insecure_skip_verify": true, "ca_file": "/x"})).is_err());
		assert!(serde_json::from_value::<ServiceTlsSpec>(serde_json::json!({"sni": "x"})).is_err());
	}
}
