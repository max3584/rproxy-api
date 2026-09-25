//! DTLS termination on UDP rules, with client certificates and re-encryption.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::UdpSocket;
use webrtc_dtls::config::{Config, ExtendedMasterSecretType};
use webrtc_dtls::conn::DTLSConn;
use webrtc_util::conn::{Conn, Listener};

use common::pki::{Issued, Pki};
use common::*;

async fn dtls_client(pki: &Pki, port: u16, name: &str, cert: Option<&Issued>) -> Result<DTLSConn, String> {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(("127.0.0.1", port)).await.unwrap();
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(sock);
	let config = Config {
		roots_cas: pki.roots(),
		server_name: name.to_string(),
		certificates: cert.map(|c| vec![c.dtls()]).unwrap_or_default(),
		extended_master_secret: ExtendedMasterSecretType::Require,
		..Default::default()
	};
	tokio::time::timeout(Duration::from_secs(5), DTLSConn::new(conn, config, true, None))
		.await
		.map_err(|_| "timeout".to_string())?
		.map_err(|e| e.to_string())
}

async fn dtls_roundtrip(c: &DTLSConn, msg: &str) -> String {
	c.write(msg.as_bytes(), None).await.unwrap();
	let mut buf = vec![0u8; 1500];
	let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf, None)).await.unwrap().unwrap();
	String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn dtls_rule(port: u16, target: SocketAddr, tls: Value) -> Value {
	let mut r = rule("udp", port, target);
	r["tls"] = tls;
	r
}

#[tokio::test]
async fn dtls_is_terminated_and_forwarded_as_plain_udp() {
	let pki = Pki::new("dtls");
	let cert = pki.server("front", &["media.test"]);
	let h = harness().await;
	let port = free_udp_port();
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]});
	let (status, v) = h.post(dtls_rule(port, udp_backend("P:").await, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let c = dtls_client(&pki, port, "media.test", None).await.unwrap();
	assert_eq!(dtls_roundtrip(&c, "a").await, "P:a");
	assert_eq!(dtls_roundtrip(&c, "b").await, "P:b");
	wait_for(&h, &format!("/rules/udp/127.0.0.1/{port}"), |v| v["connections"] == 1).await;
	c.close().await.unwrap();

	// a second client gets its own session
	let c2 = dtls_client(&pki, port, "media.test", None).await.unwrap();
	assert_eq!(dtls_roundtrip(&c2, "c").await, "P:c");
}

#[tokio::test]
async fn dtls_client_certificates_can_be_required() {
	let pki = Pki::new("dtls-mtls");
	let cert = pki.server("front", &["media.test"]);
	let alice = pki.client("alice", "alice");
	let h = harness().await;
	let port = free_udp_port();
	let tls = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}],
		"client_auth": {"mode": "required", "ca_file": pki.ca_file},
	});
	h.post(dtls_rule(port, udp_backend("M:").await, tls)).await;

	assert!(dtls_client(&pki, port, "media.test", None).await.is_err(), "no client certificate");
	let c = dtls_client(&pki, port, "media.test", Some(&alice)).await.unwrap();
	assert_eq!(dtls_roundtrip(&c, "ok").await, "M:ok");
}

#[tokio::test]
async fn dtls_can_be_re_encrypted_towards_the_backend() {
	let pki = Pki::new("dtls-up");
	let front = pki.server("front", &["front.test"]);
	let back = pki.server("back", &["back.test"]);

	// a DTLS echo backend
	let listener = webrtc_dtls::listener::listen(
		"127.0.0.1:0",
		Config { certificates: vec![back.dtls()], extended_master_secret: ExtendedMasterSecretType::Require, ..Default::default() },
	)
	.await
	.unwrap();
	let backend = listener.addr().await.unwrap();
	tokio::spawn(async move {
		while let Ok((conn, _)) = listener.accept().await {
			tokio::spawn(async move {
				let mut buf = vec![0u8; 1500];
				while let Ok(n) = conn.recv(&mut buf).await {
					if conn.send(&[b"D:", &buf[..n]].concat()).await.is_err() {
						break;
					}
				}
			});
		}
	});

	let h = harness().await;
	let port = free_udp_port();
	let tls = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
		"upstream": {"tls": true, "server_name": "back.test", "ca_file": pki.ca_file},
	});
	let (status, v) = h.post(dtls_rule(port, backend, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let c = dtls_client(&pki, port, "front.test", None).await.unwrap();
	assert_eq!(dtls_roundtrip(&c, "x").await, "D:x");
}

#[tokio::test]
async fn dtls_needs_a_pkcs8_key() {
	let pki = Pki::new("dtls-key");
	let cert = pki.server("front", &["media.test"]);
	// rewrite the key as SEC1 ("EC PRIVATE KEY"), which webrtc-dtls cannot load
	let pem = std::fs::read_to_string(&cert.key_file).unwrap();
	assert!(pem.contains("BEGIN PRIVATE KEY"));
	let sec1_file = format!("{}.sec1", cert.key_file);
	std::fs::write(&sec1_file, pem.replace("PRIVATE KEY", "EC PRIVATE KEY")).unwrap();

	let h = harness().await;
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": sec1_file}]});
	let (status, v) = h.post(dtls_rule(free_udp_port(), udp_backend("").await, tls)).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
}
