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
	/// Intermediate CA certificates between this certificate and the root (3-tier PKI).
	pub intermediates: Vec<CertificateDer<'static>>,
}

impl Issued {
	pub fn der(&self) -> CertificateDer<'static> {
		self.cert.der().clone()
	}

	pub fn key_der(&self) -> PrivateKeyDer<'static> {
		PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()))
	}

	/// The certificate followed by its intermediates.
	pub fn full_chain(&self) -> Vec<CertificateDer<'static>> {
		[vec![self.der()], self.intermediates.clone()].concat()
	}

	/// The same certificate for webrtc-dtls.
	pub fn dtls(&self) -> webrtc_dtls::crypto::Certificate {
		webrtc_dtls::crypto::Certificate {
			certificate: self.full_chain(),
			private_key: webrtc_dtls::crypto::CryptoPrivateKey::try_from(&self.key).unwrap(),
		}
	}
}

pub struct Pki {
	pub dir: PathBuf,
	ca: Certificate,
	ca_key: KeyPair,
	/// The root only.
	pub ca_file: String,
	/// With `tiers`: intermediate CAs from the root downwards; the last one issues leaves.
	intermediates: Vec<(Certificate, KeyPair)>,
	/// The intermediates as a server would send them: nearest to the leaf first.
	pub chain_file: Option<String>,
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
		Pki { dir, ca, ca_key, ca_file, intermediates: vec![], chain_file: None }
	}

	/// Root → intermediate → leaf; `ca_file` holds only the root.
	pub fn three_tier(tag: &str) -> Pki {
		Pki::tiers(tag, 1)
	}

	/// Root → `n` intermediates → leaf (`n = 2` is a 4-tier PKI).
	pub fn tiers(tag: &str, n: usize) -> Pki {
		let mut pki = Pki::new(tag);
		for level in 0..n {
			let key = KeyPair::generate().unwrap();
			let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
			params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
			params.distinguished_name.push(DnType::CommonName, format!("rproxy test intermediate CA {}", level + 1));
			params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
			let cert = match pki.intermediates.last() {
				Some((parent, parent_key)) => params.signed_by(&key, parent, parent_key).unwrap(),
				None => params.signed_by(&key, &pki.ca, &pki.ca_key).unwrap(),
			};
			pki.intermediates.push((cert, key));
		}
		if n > 0 {
			let file = pki.dir.join("chain.pem").to_string_lossy().into_owned();
			let pem: String = pki.intermediates.iter().rev().map(|(c, _)| c.pem()).collect();
			std::fs::write(&file, pem).unwrap();
			pki.chain_file = Some(file);
		}
		pki
	}

	/// Writes `pem` to a file in the PKI directory and returns its path.
	pub fn write(&self, name: &str, pem: &str) -> String {
		let file = self.dir.join(name).to_string_lossy().into_owned();
		std::fs::write(&file, pem).unwrap();
		file
	}

	/// Root and intermediate in one file (a CA bundle).
	pub fn bundle_file(&self) -> String {
		let file = self.dir.join("bundle.pem").to_string_lossy().into_owned();
		let mut pem = self.ca.pem();
		for (cert, _) in &self.intermediates {
			pem.push_str(&cert.pem());
		}
		std::fs::write(&file, pem).unwrap();
		file
	}

	fn issue(&self, name: &str, cn: &str, sans: &[&str], client: bool) -> Issued {
		let key = KeyPair::generate().unwrap();
		let mut params = CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
		params.distinguished_name.push(DnType::CommonName, cn);
		params.extended_key_usages =
			vec![if client { ExtendedKeyUsagePurpose::ClientAuth } else { ExtendedKeyUsagePurpose::ServerAuth }];
		let (issuer, issuer_key) = match self.intermediates.last() {
			Some((c, k)) => (c, k),
			None => (&self.ca, &self.ca_key),
		};
		let cert = params.signed_by(&key, issuer, issuer_key).unwrap();
		let cert_file = self.dir.join(format!("{name}.pem")).to_string_lossy().into_owned();
		let key_file = self.dir.join(format!("{name}.key")).to_string_lossy().into_owned();
		std::fs::write(&cert_file, cert.pem()).unwrap();
		std::fs::write(&key_file, key.serialize_pem()).unwrap();
		let intermediates = self.intermediates.iter().rev().map(|(c, _)| c.der().clone()).collect();
		Issued { cert, key, cert_file, key_file, intermediates }
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

	/// A client presenting only its own certificate, without intermediates.
	pub fn connector_leaf_only(&self, client: &Issued) -> tokio_rustls::TlsConnector {
		let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_root_certificates(self.roots())
			.with_client_auth_cert(vec![client.der()], client.key_der())
			.unwrap();
		tokio_rustls::TlsConnector::from(Arc::new(config))
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
			Some(c) => builder.with_client_auth_cert(c.full_chain(), c.key_der()).unwrap(),
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
			.with_single_cert(issued.full_chain(), issued.key_der())
			.unwrap();
		tokio_rustls::TlsAcceptor::from(Arc::new(config))
	}
}

impl Drop for Pki {
	fn drop(&mut self) {
		let _ = std::fs::remove_dir_all(&self.dir);
	}
}
