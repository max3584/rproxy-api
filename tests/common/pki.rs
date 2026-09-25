//! A throwaway CA with server and client certificates, written to a temp dir.

use std::path::PathBuf;
use std::sync::Arc;

use rcgen::{
	BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;

pub struct Issued {
	pub cert: Certificate,
	pub key: KeyPair,
	pub cert_file: String,
	pub key_file: String,
}

impl Issued {
	pub fn der(&self) -> CertificateDer<'static> {
		self.cert.der().clone()
	}

	pub fn key_der(&self) -> PrivateKeyDer<'static> {
		PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()))
	}

	/// The same certificate for webrtc-dtls.
	pub fn dtls(&self) -> webrtc_dtls::crypto::Certificate {
		webrtc_dtls::crypto::Certificate {
			certificate: vec![self.der()],
			private_key: webrtc_dtls::crypto::CryptoPrivateKey::try_from(&self.key).unwrap(),
		}
	}
}

pub struct Pki {
	pub dir: PathBuf,
	ca: Certificate,
	ca_key: KeyPair,
	pub ca_file: String,
}

impl Pki {
	pub fn new(tag: &str) -> Pki {
		let dir = std::env::temp_dir().join(format!("rproxy-pki-{tag}-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let ca_key = KeyPair::generate().unwrap();
		let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.distinguished_name.push(DnType::CommonName, "rproxy test CA");
		params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
		let ca = params.self_signed(&ca_key).unwrap();
		let ca_file = dir.join("ca.pem").to_string_lossy().into_owned();
		std::fs::write(&ca_file, ca.pem()).unwrap();
		Pki { dir, ca, ca_key, ca_file }
	}

	fn issue(&self, name: &str, cn: &str, sans: &[&str], client: bool) -> Issued {
		let key = KeyPair::generate().unwrap();
		let mut params = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
		params.distinguished_name.push(DnType::CommonName, cn);
		params.extended_key_usages =
			vec![if client { ExtendedKeyUsagePurpose::ClientAuth } else { ExtendedKeyUsagePurpose::ServerAuth }];
		let cert = params.signed_by(&key, &self.ca, &self.ca_key).unwrap();
		let cert_file = self.dir.join(format!("{name}.pem")).to_string_lossy().into_owned();
		let key_file = self.dir.join(format!("{name}.key")).to_string_lossy().into_owned();
		std::fs::write(&cert_file, cert.pem()).unwrap();
		std::fs::write(&key_file, key.serialize_pem()).unwrap();
		Issued { cert, key, cert_file, key_file }
	}

	pub fn server(&self, name: &str, sans: &[&str]) -> Issued {
		self.issue(name, sans.first().copied().unwrap_or(name), sans, false)
	}

	pub fn client(&self, name: &str, cn: &str) -> Issued {
		self.issue(name, cn, &[], true)
	}

	pub fn roots(&self) -> RootCertStore {
		let mut roots = RootCertStore::empty();
		roots.add(self.ca.der().clone()).unwrap();
		roots
	}

	/// A TLS client that trusts this CA, optionally presenting `client`.
	pub fn connector(&self, client: Option<&Issued>) -> tokio_rustls::TlsConnector {
		self.connector_alpn(client, &[])
	}

	/// Like `connector`, offering the given ALPN protocols.
	pub fn connector_alpn(&self, client: Option<&Issued>, alpn: &[&str]) -> tokio_rustls::TlsConnector {
		let builder = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_root_certificates(self.roots());
		let mut config = match client {
			Some(c) => builder.with_client_auth_cert(vec![c.der()], c.key_der()).unwrap(),
			None => builder.with_no_client_auth(),
		};
		config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
		tokio_rustls::TlsConnector::from(Arc::new(config))
	}

	/// A TLS server with `issued` as its certificate.
	pub fn acceptor(&self, issued: &Issued) -> tokio_rustls::TlsAcceptor {
		let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_no_client_auth()
			.with_single_cert(vec![issued.der()], issued.key_der())
			.unwrap();
		tokio_rustls::TlsAcceptor::from(Arc::new(config))
	}
}

impl Drop for Pki {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}
