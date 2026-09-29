//! Server-name routing of UDP rules (`tls.mode: sni`, #130) with real QUIC
//! (quinn) and DTLS (dtls crate) clients and backends. rproxy has no
//! certificates here: each client verifies the certificate of the backend it
//! reached, which proves the handshake went through untouched.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dtls::config::{Config, ExtendedMasterSecretType};
use dtls::conn::DTLSConn;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::UdpSocket;
use webrtc_util::conn::{Conn, Listener};

use common::pki::{Issued, Pki};
use common::*;

const ALPN: &[u8] = b"echo";

// ---- QUIC ----

/// A QUIC echo server: every bidirectional stream gets `tag` + what was sent.
async fn quic_backend(issued: &Issued, tag: &'static str) -> SocketAddr {
	let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_no_client_auth()
		.with_single_cert(issued.full_chain(), issued.key_der())
		.unwrap();
	tls.alpn_protocols = vec![ALPN.to_vec()];
	let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
	let endpoint = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), "127.0.0.1:0".parse().unwrap()).unwrap();
	let addr = endpoint.local_addr().unwrap();
	tokio::spawn(async move {
		while let Some(incoming) = endpoint.accept().await {
			tokio::spawn(async move {
				let Ok(conn) = incoming.await else { return };
				while let Ok((mut send, mut recv)) = conn.accept_bi().await {
					let Ok(data) = recv.read_to_end(64 * 1024).await else { return };
					let _ = send.write_all(&[tag.as_bytes(), &data].concat()).await;
					let _ = send.finish();
				}
			});
		}
	});
	addr
}

/// A QUIC client trusting the test CA; `extra_alpn` makes the ClientHello bigger.
fn quic_client(pki: &Pki, extra_alpn: usize) -> quinn::Endpoint {
	let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_root_certificates(pki.roots())
		.with_no_client_auth();
	tls.alpn_protocols = (0..extra_alpn).map(|i| format!("{i:0>200}").into_bytes()).collect();
	tls.alpn_protocols.push(ALPN.to_vec());
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
	let mut config = quinn::ClientConfig::new(Arc::new(crypto));
	let mut transport = quinn::TransportConfig::default();
	transport.max_idle_timeout(Some(Duration::from_secs(3).try_into().unwrap()));
	config.transport_config(Arc::new(transport));
	let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
	endpoint.set_default_client_config(config);
	endpoint
}

/// Connects to rproxy's `port` as `name` and sends `msg` on a stream; the reply.
async fn quic_echo(endpoint: &quinn::Endpoint, port: u16, name: &str, msg: &str) -> Result<String, String> {
	let connecting = endpoint.connect(SocketAddr::from(([127, 0, 0, 1], port)), name).map_err(|e| e.to_string())?;
	let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
		.await
		.map_err(|_| "QUIC handshake timed out".to_string())?
		.map_err(|e| e.to_string())?;
	let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
	send.write_all(msg.as_bytes()).await.map_err(|e| e.to_string())?;
	send.finish().map_err(|e| e.to_string())?;
	let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64 * 1024))
		.await
		.map_err(|_| "no reply".to_string())?
		.map_err(|e| e.to_string())?;
	conn.close(0u32.into(), b"done");
	Ok(String::from_utf8_lossy(&reply).into_owned())
}

fn sni_rule(port: u16, default: SocketAddr, routes: Value, unmatched: &str) -> Value {
	let mut r = rule("udp", port, default);
	r["tls"] = json!({"mode": "sni", "routes": routes, "unmatched": unmatched});
	r
}

fn route(names: &[&str], to: SocketAddr) -> Value {
	let mut r = json!({"remote_addr": to.ip().to_string(), "remote_port": to.port()});
	if names.len() == 1 {
		r["server_name"] = json!(names[0]);
	} else {
		r["server_names"] = json!(names);
	}
	r
}

#[tokio::test]
async fn quic_is_routed_by_server_name_without_terminating() {
	let pki = Pki::new("udp-sni-quic");
	let a = quic_backend(&pki.server("a", &["a.test", "alias.test"]), "A:").await;
	let b = quic_backend(&pki.server("b", &["b.test", "deep.x.b.test"]), "B:").await;
	let fallback = quic_backend(&pki.server("c", &["other.test"]), "C:").await;
	let h = harness().await;
	let port = free_udp_port();
	let routes = json!([route(&["a.test", "alias.test"], a), route(&["**.b.test"], b)]);
	let (status, v) = h.post(sni_rule(port, fallback, routes, "default")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["tls"]["mode"], "sni", "{v}");

	// one client endpoint (one UDP socket) for every connection below: rproxy keeps
	// UDP sessions per client address and port, and starts over when a new QUIC
	// connection from the same socket asks for another name
	let client = quic_client(&pki, 0);
	assert_eq!(quic_echo(&client, port, "a.test", "1").await.unwrap(), "A:1");
	assert_eq!(quic_echo(&client, port, "a.test", "1b").await.unwrap(), "A:1b", "same name again from the same socket");
	assert_eq!(quic_echo(&client, port, "alias.test", "2").await.unwrap(), "A:2", "server_names");
	assert_eq!(quic_echo(&client, port, "deep.x.b.test", "3").await.unwrap(), "B:3", "** matches several labels");
	assert_eq!(quic_echo(&client, port, "other.test", "4").await.unwrap(), "C:4", "unmatched: default");
	// the backend's own certificate is what the client verified: a.test cannot be reached as b.test
	let wrong = quic_echo(&client, port, "b.test", "5").await.unwrap_err();
	assert!(wrong.contains("certificate") || wrong.contains("timed out") || wrong.contains("closed"), "{wrong}");

	let (_, v) = h.get(&format!("/rules/udp/127.0.0.1/{port}")).await;
	assert!(v["stats"]["total_connections"].as_u64().unwrap() >= 4, "{v}");
}

#[tokio::test]
async fn quic_client_hello_over_two_initial_packets() {
	let pki = Pki::new("udp-sni-big");
	let a = quic_backend(&pki.server("a", &["big.test"]), "A:").await;
	let other = quic_backend(&pki.server("o", &["x.test"]), "O:").await;
	let h = harness().await;
	let port = free_udp_port();
	let (status, v) = h.post(sni_rule(port, other, json!([route(&["big.test"], a)]), "default")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	// ~20 × 200-byte ALPN names: a ClientHello of more than 4 KiB, in several Initial packets
	let client = quic_client(&pki, 20);
	assert_eq!(quic_echo(&client, port, "big.test", "large").await.unwrap(), "A:large");
}

#[tokio::test]
async fn quic_unmatched_reject_and_concurrent_clients() {
	let pki = Pki::new("udp-sni-reject");
	let a = quic_backend(&pki.server("a", &["a.test"]), "A:").await;
	let b = quic_backend(&pki.server("b", &["b.test"]), "B:").await;
	let h = harness().await;
	let port = free_udp_port();
	let (status, v) = h.post(sni_rule(port, a, json!([route(&["a.test"], a), route(&["b.test"], b)]), "reject")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	// two clients at once, each to its own backend
	let (ca, cb) = (quic_client(&pki, 0), quic_client(&pki, 0));
	let (ra, rb) = tokio::join!(quic_echo(&ca, port, "a.test", "x"), quic_echo(&cb, port, "b.test", "y"));
	assert_eq!((ra.unwrap(), rb.unwrap()), ("A:x".to_string(), "B:y".to_string()));
	// a name no route has: dropped
	assert!(quic_echo(&quic_client(&pki, 0), port, "nobody.test", "z").await.is_err());
	let (_, v) = h.get(&format!("/rules/udp/127.0.0.1/{port}")).await;
	assert!(v["stats"]["denied"].as_u64().unwrap() >= 1, "{v}");
}

// ---- DTLS ----

/// A DTLS echo server (with the HelloVerifyRequest cookie exchange of the dtls crate).
async fn dtls_backend(issued: &Issued, tag: &'static str) -> SocketAddr {
	let listener = dtls::listener::listen(
		"127.0.0.1:0",
		Config { certificates: vec![issued.dtls()], extended_master_secret: ExtendedMasterSecretType::Require, ..Default::default() },
	)
	.await
	.unwrap();
	let addr = listener.addr().await.unwrap();
	tokio::spawn(async move {
		while let Ok((conn, _)) = listener.accept().await {
			tokio::spawn(async move {
				let mut buf = vec![0u8; 1500];
				while let Ok(n) = conn.recv(&mut buf).await {
					if conn.send(&[tag.as_bytes(), &buf[..n]].concat()).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

async fn dtls_echo(pki: &Pki, port: u16, name: &str, msg: &str) -> Result<String, String> {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(("127.0.0.1", port)).await.unwrap();
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(sock);
	let config = Config {
		roots_cas: pki.roots(),
		server_name: name.to_string(),
		extended_master_secret: ExtendedMasterSecretType::Require,
		..Default::default()
	};
	let c = tokio::time::timeout(Duration::from_secs(5), DTLSConn::new(conn, config, true, None))
		.await
		.map_err(|_| "DTLS handshake timed out".to_string())?
		.map_err(|e| e.to_string())?;
	c.write(msg.as_bytes(), None).await.map_err(|e| e.to_string())?;
	let mut buf = vec![0u8; 1500];
	let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf, None))
		.await
		.map_err(|_| "no reply".to_string())?
		.map_err(|e| e.to_string())?;
	let _ = c.close().await;
	Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[tokio::test]
async fn dtls_is_routed_by_server_name_without_terminating() {
	let pki = Pki::new("udp-sni-dtls");
	let a = dtls_backend(&pki.server("a", &["turn-a.test"]), "A:").await;
	let b = dtls_backend(&pki.server("b", &["x.turn.test"]), "B:").await;
	let fallback = dtls_backend(&pki.server("c", &["else.test"]), "C:").await;
	let h = harness().await;
	let port = free_udp_port();
	let (status, v) = h.post(sni_rule(port, fallback, json!([route(&["turn-a.test"], a), route(&["*.turn.test"], b)]), "default")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	assert_eq!(dtls_echo(&pki, port, "turn-a.test", "1").await.unwrap(), "A:1");
	assert_eq!(dtls_echo(&pki, port, "x.turn.test", "2").await.unwrap(), "B:2");
	assert_eq!(dtls_echo(&pki, port, "else.test", "3").await.unwrap(), "C:3", "unmatched: default");
}

// ---- other traffic on an sni rule ----

#[tokio::test]
async fn other_udp_traffic_goes_to_the_rules_own_target() {
	let pki = Pki::new("udp-sni-plain");
	let a = quic_backend(&pki.server("a", &["a.test"]), "A:").await;
	let plain = udp_backend("U:").await;
	let h = harness().await;
	let port = free_udp_port();
	let (status, v) = h.post(sni_rule(port, plain, json!([route(&["a.test"], a)]), "default")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	// not DTLS or QUIC: no name, so the rule's own target, with every datagram in order
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(udp_roundtrip(&sock, "first").await, "U:first");
	assert_eq!(udp_roundtrip(&sock, "second").await, "U:second");
	// QUIC on the same port still goes by name
	assert_eq!(quic_echo(&quic_client(&pki, 0), port, "a.test", "q").await.unwrap(), "A:q");
}

#[tokio::test]
async fn udp_sni_settings_are_validated() {
	let h = harness().await;
	let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
	// passthrough routes are for tcp terminate rules
	let mut r = rule("udp", free_udp_port(), target);
	r["tls"] = json!({"mode": "sni", "routes": [{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": 9, "passthrough": true}]});
	assert_eq!(h.post(r).await.1["code"], "tls_config");
	// reject needs a route
	let mut r = rule("udp", free_udp_port(), target);
	r["tls"] = json!({"mode": "sni", "unmatched": "reject"});
	assert_eq!(h.post(r).await.1["code"], "tls_config");
	// reject on a DTLS terminate rule still makes no sense (it does not route by name)
	let mut r = rule("udp", free_udp_port(), target);
	r["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": "/x", "key_file": "/y"}], "unmatched": "reject",
		"routes": [{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": 9}]});
	assert_eq!(h.post(r).await.1["code"], "tls_config");
	// a udp port range with sni routes is fine, like tcp
	let port = free_udp_block(3);
	let mut r = rule("udp", port, target);
	r["listen_port_end"] = json!(port + 2);
	r["tls"] = json!({"mode": "sni", "routes": [{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": 9}]});
	let (status, v) = h.post(r).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
}
