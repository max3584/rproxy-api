//! Multi-tier PKIs (root → intermediates → leaf): server certificates with
//! `chain_file`, and client certificates for mTLS over TLS and DTLS.

mod common;

use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use webrtc_dtls::config::{Config, ExtendedMasterSecretType};
use webrtc_dtls::conn::DTLSConn;
use webrtc_util::conn::Conn;

use common::pki::{Issued, Pki};
use common::*;

async fn roundtrip_with(connector: &TlsConnector, port: u16, name: &str) -> std::io::Result<String> {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
	let mut s = connector.connect(name.to_string().try_into().unwrap(), tcp).await?;
	s.write_all(b"x").await?;
	let mut buf = [0u8; 64];
	let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await??;
	if n == 0 {
		return Err(std::io::Error::other("closed"));
	}
	Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn cert(cert_file: &str, chain_file: Option<&str>, key_file: &str) -> Value {
	json!({"cert_file": cert_file, "chain_file": chain_file, "key_file": key_file})
}

async fn terminate_rule(h: &Harness, tls: Value) -> (StatusCode, Value, u16) {
	let port = free_port();
	let mut body = rule("tcp", port, tcp_backend("OK:").await);
	body["tls"] = tls;
	let (status, v) = h.post(body).await;
	(status, v, port)
}

#[tokio::test]
async fn server_certificates_need_their_intermediates() {
	for tiers in [1, 2] {
		let pki = Pki::tiers(&format!("srv{tiers}"), tiers);
		let leaf = pki.server("front", &["svc.test"]);
		let h = harness().await;
		let client = pki.connector(None); // trusts only the root

		// without the chain the client cannot build a path to its root
		let (status, _, port) =
			terminate_rule(&h, json!({"mode": "terminate", "certificates": [cert(&leaf.cert_file, None, &leaf.key_file)]})).await;
		assert_eq!(status, StatusCode::CREATED);
		assert!(roundtrip_with(&client, port, "svc.test").await.is_err(), "{tiers} intermediates, no chain_file");

		// with chain_file it verifies
		let (status, v, port) = terminate_rule(
			&h,
			json!({"mode": "terminate", "certificates": [cert(&leaf.cert_file, pki.chain_file.as_deref(), &leaf.key_file)]}),
		)
		.await;
		assert_eq!(status, StatusCode::CREATED, "{v}");
		assert_eq!(roundtrip_with(&client, port, "svc.test").await.unwrap(), "OK:x", "{tiers} intermediates");
		assert_eq!(v["tls"]["certificates"][0]["chain_file"], json!(pki.chain_file));
	}
}

#[tokio::test]
async fn a_full_chain_in_cert_file_still_works() {
	let pki = Pki::tiers("fullchain", 2);
	let leaf = pki.server("front", &["svc.test"]);
	let pem = std::fs::read_to_string(&leaf.cert_file).unwrap() + &std::fs::read_to_string(pki.chain_file.as_ref().unwrap()).unwrap();
	let fullchain = pki.write("fullchain.pem", &pem);
	let h = harness().await;
	let (status, v, port) = terminate_rule(&h, json!({"mode": "terminate", "certificates": [cert(&fullchain, None, &leaf.key_file)]})).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(roundtrip_with(&pki.connector(None), port, "svc.test").await.unwrap(), "OK:x");
}

#[tokio::test]
async fn wrong_order_and_wrong_key_are_rejected() {
	let pki = Pki::tiers("order", 2);
	let leaf = pki.server("front", &["svc.test"]);
	let other = pki.server("other", &["other.test"]);
	let h = harness().await;

	// the chain file reversed: root side first
	let chain = std::fs::read_to_string(pki.chain_file.as_ref().unwrap()).unwrap();
	let blocks: Vec<&str> = chain.split_inclusive("-----END CERTIFICATE-----\n").collect();
	let reversed = pki.write("reversed.pem", &blocks.iter().rev().copied().collect::<String>());
	let (status, v, _) = terminate_rule(&h, json!({"mode": "terminate", "certificates": [cert(&leaf.cert_file, Some(&reversed), &leaf.key_file)]})).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("was not issued by"), "{v}");

	// a key that belongs to another certificate
	let (status, v, _) = terminate_rule(
		&h,
		json!({"mode": "terminate", "certificates": [cert(&leaf.cert_file, pki.chain_file.as_deref(), &other.key_file)]}),
	)
	.await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("does not belong to"), "{v}");
}

async fn mtls_rule(h: &Harness, pki: &Pki, server: &Issued, chain_file: Option<&str>) -> u16 {
	let mut auth = json!({"mode": "required", "ca_file": pki.ca_file});
	if let Some(chain) = chain_file {
		auth["chain_file"] = json!(chain);
	}
	let (status, v, port) = terminate_rule(
		h,
		json!({"mode": "terminate", "certificates": [cert(&server.cert_file, pki.chain_file.as_deref(), &server.key_file)], "client_auth": auth}),
	)
	.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	port
}

#[tokio::test]
async fn mtls_with_multi_tier_client_certificates() {
	for tiers in [1, 2] {
		let pki = Pki::tiers(&format!("mtls{tiers}"), tiers);
		let server = pki.server("front", &["api.test"]);
		let alice = pki.client("alice", "alice");
		let h = harness().await;

		// ca_file holds only the root: a client sending its intermediates verifies
		let port = mtls_rule(&h, &pki, &server, None).await;
		assert_eq!(roundtrip_with(&pki.connector(Some(&alice)), port, "api.test").await.unwrap(), "OK:x");
		// a client sending only its own certificate cannot be chained to the root
		assert!(roundtrip_with(&pki.connector_leaf_only(&alice), port, "api.test").await.is_err());

		// client_auth.chain_file lets rproxy fill in the intermediates
		let port = mtls_rule(&h, &pki, &server, pki.chain_file.as_deref()).await;
		assert_eq!(roundtrip_with(&pki.connector_leaf_only(&alice), port, "api.test").await.unwrap(), "OK:x", "{tiers} intermediates");
		assert_eq!(roundtrip_with(&pki.connector(Some(&alice)), port, "api.test").await.unwrap(), "OK:x");

		// a certificate from an unrelated PKI still fails, even with the same shape
		let stranger_pki = Pki::tiers(&format!("stranger{tiers}"), tiers);
		let mallory = stranger_pki.client("mallory", "mallory");
		let with_roots = {
			let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
				.with_safe_default_protocol_versions()
				.unwrap()
				.with_root_certificates(pki.roots())
				.with_client_auth_cert(mallory.full_chain(), mallory.key_der())
				.unwrap();
			TlsConnector::from(Arc::new(config))
		};
		assert!(roundtrip_with(&with_roots, port, "api.test").await.is_err());
	}
}

async fn dtls_client(pki: &Pki, port: u16, cert: Option<webrtc_dtls::crypto::Certificate>) -> Result<DTLSConn, String> {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(("127.0.0.1", port)).await.unwrap();
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(sock);
	let config = Config {
		roots_cas: pki.roots(),
		server_name: "media.test".into(),
		certificates: cert.into_iter().collect(),
		extended_master_secret: ExtendedMasterSecretType::Require,
		..Default::default()
	};
	tokio::time::timeout(Duration::from_secs(5), DTLSConn::new(conn, config, true, None))
		.await
		.map_err(|_| "timeout".to_string())?
		.map_err(|e| e.to_string())
}

/// Sends a datagram and reports whether the echo came back (the session is
/// dropped right after the handshake when the chain does not verify).
async fn dtls_echo(c: &DTLSConn) -> bool {
	if c.write(b"ping", None).await.is_err() {
		return false;
	}
	let mut buf = vec![0u8; 64];
	matches!(tokio::time::timeout(Duration::from_millis(800), c.read(&mut buf, None)).await, Ok(Ok(n)) if &buf[..n] == b"E:ping")
}

#[tokio::test]
async fn dtls_mtls_with_multi_tier_client_certificates() {
	let pki = Pki::tiers("dtls-chain", 2);
	let server = pki.server("front", &["media.test"]);
	let alice = pki.client("alice", "alice");
	let h = harness().await;

	let rule_with = |chain: Option<String>| {
		let mut auth = json!({"mode": "required", "ca_file": pki.ca_file});
		if let Some(c) = chain {
			auth["chain_file"] = json!(c);
		}
		json!({"mode": "terminate", "certificates": [cert(&server.cert_file, pki.chain_file.as_deref(), &server.key_file)], "client_auth": auth})
	};
	let backend = udp_backend("E:").await;

	let port = free_udp_port();
	let mut body = rule("udp", port, backend);
	body["tls"] = rule_with(None);
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	// the server's own chain lets the client verify it; the client's full chain verifies against the root
	let c = dtls_client(&pki, port, Some(alice.dtls())).await.unwrap();
	assert!(dtls_echo(&c).await, "full client chain");
	// leaf only: the handshake completes, but rproxy drops the session before forwarding anything
	let leaf_only = webrtc_dtls::crypto::Certificate {
		certificate: vec![alice.der()],
		private_key: webrtc_dtls::crypto::CryptoPrivateKey::try_from(&alice.key).unwrap(),
	};
	if let Ok(c) = dtls_client(&pki, port, Some(leaf_only.clone())).await {
		assert!(!dtls_echo(&c).await, "leaf only must not be forwarded");
	}

	let port = free_udp_port();
	let mut body = rule("udp", port, backend);
	body["tls"] = rule_with(pki.chain_file.clone());
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	let c = dtls_client(&pki, port, Some(leaf_only)).await.unwrap();
	assert!(dtls_echo(&c).await, "chain_file fills in the intermediates");
	// no certificate: refused in the handshake, or at least never forwarded
	if let Ok(c) = dtls_client(&pki, port, None).await {
		assert!(!dtls_echo(&c).await, "a client without a certificate must not be forwarded");
	}
}
