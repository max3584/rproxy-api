//! Port ranges and TLS: sni routing, termination, mTLS, re-encryption,
//! PROXY v2 TLVs and certificate reload.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use common::pki::{Issued, Pki};
use common::*;

/// `n` consecutive free TCP ports on 127.0.0.1, bound (so they stay free).
fn consecutive_tcp(n: u16) -> Vec<std::net::TcpListener> {
	let base = free_tcp_block(n);
	(0..n).map(|i| std::net::TcpListener::bind(("127.0.0.1", base + i)).unwrap()).collect()
}

fn consecutive_udp(n: u16) -> Vec<std::net::UdpSocket> {
	let base = free_udp_block(n);
	(0..n).map(|i| std::net::UdpSocket::bind(("127.0.0.1", base + i)).unwrap()).collect()
}

/// A plain backend answering `tag` + what it read, on an already bound listener.
fn serve_tag(listener: std::net::TcpListener, tag: String) {
	listener.set_nonblocking(true).unwrap();
	let listener = TcpListener::from_std(listener).unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			let tag = tag.clone();
			tokio::spawn(async move {
				let mut buf = [0u8; 256];
				while let Ok(n) = s.read(&mut buf).await {
					if n == 0 || s.write_all(&[tag.as_bytes(), &buf[..n]].concat()).await.is_err() {
						break;
					}
				}
			});
		}
	});
}

/// A TLS backend that answers `tag` + what it read.
async fn tls_backend(pki: &Pki, cert: &Issued, tag: &'static str) -> SocketAddr {
	let acceptor = pki.acceptor(cert);
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (s, _) = listener.accept().await.unwrap();
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				let Ok(mut s) = acceptor.accept(s).await else { return };
				let mut buf = [0u8; 256];
				while let Ok(n) = s.read(&mut buf).await {
					if n == 0 || s.write_all(&[tag.as_bytes(), &buf[..n]].concat()).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

async fn tls_roundtrip(pki: &Pki, port: u16, name: &str, client: Option<&Issued>, msg: &str) -> std::io::Result<String> {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
	let mut s = pki.connector(client).connect(name.to_string().try_into().unwrap(), tcp).await?;
	s.write_all(msg.as_bytes()).await?;
	let mut buf = [0u8; 256];
	let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await??;
	if n == 0 {
		return Err(std::io::Error::other("closed"));
	}
	Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

fn tcp_rule(port: u16, target: SocketAddr, tls: Value) -> Value {
	let mut r = rule("tcp", port, target);
	r["tls"] = tls;
	r
}

#[tokio::test]
async fn tcp_port_range_maps_one_to_one() {
	let h = harness().await;
	let backends = consecutive_tcp(3);
	let first = backends[0].local_addr().unwrap();
	for (i, b) in backends.into_iter().enumerate() {
		serve_tag(b, format!("B{i}:"));
	}
	let listens = consecutive_tcp(3);
	let port = listens[0].local_addr().unwrap().port();
	drop(listens);

	let mut body = rule("tcp", port, first);
	body["listen_port_end"] = json!(port + 2);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["listen_port_end"], port + 2);

	for i in 0..3u16 {
		let mut s = TcpStream::connect(("127.0.0.1", port + i)).await.unwrap();
		assert_eq!(roundtrip(&mut s, "x").await, format!("B{i}:x"));
	}
	assert_eq!(h.delete(&format!("tcp/127.0.0.1/{port}")).await, StatusCode::NO_CONTENT);
	for i in 0..3u16 {
		assert!(TcpStream::connect(("127.0.0.1", port + i)).await.is_err(), "port {} still open", port + i);
	}
}

#[tokio::test]
async fn udp_port_range_maps_one_to_one() {
	let h = harness().await;
	let backends = consecutive_udp(2);
	let first = backends[0].local_addr().unwrap();
	for (i, b) in backends.into_iter().enumerate() {
		b.set_nonblocking(true).unwrap();
		let b = UdpSocket::from_std(b).unwrap();
		tokio::spawn(async move {
			let mut buf = [0u8; 64];
			loop {
				let (n, peer) = b.recv_from(&mut buf).await.unwrap();
				let _ = b.send_to(&[format!("U{i}:").as_bytes(), &buf[..n]].concat(), peer).await;
			}
		});
	}
	let listens = consecutive_udp(2);
	let port = listens[0].local_addr().unwrap().port();
	drop(listens);
	let mut body = rule("udp", port, first);
	body["listen_port_end"] = json!(port + 1);
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);

	for i in 0..2u16 {
		let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		c.connect(("127.0.0.1", port + i)).await.unwrap();
		assert_eq!(udp_roundtrip(&c, "y").await, format!("U{i}:y"));
	}
}

#[tokio::test]
async fn overlapping_ranges_are_rejected() {
	let h = harness().await;
	let backend = tcp_backend("A:").await;
	let listens = consecutive_tcp(10);
	let port = listens[0].local_addr().unwrap().port();
	drop(listens);
	let mut body = rule("tcp", port, backend);
	body["listen_port_end"] = json!(port + 5);
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);

	let mut clash = rule("tcp", port + 5, backend);
	clash["listen_port_end"] = json!(port + 9);
	let (status, v) = h.post(clash).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")), "{v}");
	// the same ports on udp are fine
	let mut udp = rule("udp", port, backend);
	udp["listen_port_end"] = json!(port + 5);
	assert_eq!(h.post(udp).await.0, StatusCode::CREATED);
}

#[tokio::test]
async fn sni_routes_without_decrypting() {
	let pki = Pki::new("sni");
	let cert = pki.server("backend", &["a.test", "b.test", "other.test"]);
	let (a, b, fallback) = (
		tls_backend(&pki, &cert, "A:").await,
		tls_backend(&pki, &cert, "B:").await,
		tls_backend(&pki, &cert, "D:").await,
	);
	let h = harness().await;
	let port = free_port();
	let tls = json!({
		"mode": "sni",
		"routes": [
			{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": a.port()},
			{"server_name": "*.test", "remote_addr": "127.0.0.1", "remote_port": b.port()},
		],
	});
	let (status, v) = h.post(tcp_rule(port, fallback, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	// end-to-end TLS with the backend's own certificate: rproxy never decrypts
	assert_eq!(tls_roundtrip(&pki, port, "a.test", None, "1").await.unwrap(), "A:1");
	assert_eq!(tls_roundtrip(&pki, port, "b.test", None, "2").await.unwrap(), "B:2");
	assert_eq!(tls_roundtrip(&pki, port, "other.test", None, "3").await.unwrap(), "B:3", "wildcard route");

	// plain text on an sni port is refused
	let mut plain = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	plain.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
	let mut buf = [0u8; 16];
	assert_eq!(tokio::time::timeout(Duration::from_secs(3), plain.read(&mut buf)).await.unwrap().unwrap_or(0), 0);
}

#[tokio::test]
async fn terminate_sends_plain_text_and_tls_details_in_proxy_v2() {
	let pki = Pki::new("term");
	let cert = pki.server("front", &["mail.test"]);
	let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	let h = harness().await;
	let port = free_port();
	let mut body = tcp_rule(port, target, json!({
		"mode": "terminate",
		"certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}],
		"alpn": ["imap"],
	}));
	body["source_ip"] = json!("proxy_v2");
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let client = tokio::spawn({
		let connector = pki.connector_alpn(None, &["imap"]);
		async move {
			let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
			let mut s = connector.connect("mail.test".try_into().unwrap(), tcp).await.unwrap();
			s.write_all(b"hello").await.unwrap();
			let mut buf = [0u8; 16];
			let n = s.read(&mut buf).await.unwrap();
			String::from_utf8_lossy(&buf[..n]).into_owned()
		}
	});
	let (mut up, _) = backend.accept().await.unwrap();
	let mut head = [0u8; 16];
	up.read_exact(&mut head).await.unwrap();
	let len = u16::from_be_bytes([head[14], head[15]]) as usize;
	let mut rest = vec![0u8; len];
	up.read_exact(&mut rest).await.unwrap();
	let tlvs = &rest[12..];
	assert!(tlvs.windows(9).any(|w| w == b"mail.test"), "authority TLV carries the SNI");
	assert!(tlvs.windows(4).any(|w| w == b"imap"), "ALPN TLV");
	let mut plain = [0u8; 5];
	up.read_exact(&mut plain).await.unwrap();
	assert_eq!(&plain, b"hello", "the backend receives decrypted bytes");
	up.write_all(b"plain-reply").await.unwrap();
	assert_eq!(client.await.unwrap(), "plain-reply");
}

#[tokio::test]
async fn mtls_required_checks_client_certificates() {
	let pki = Pki::new("mtls");
	let cert = pki.server("front", &["api.test"]);
	let alice = pki.client("alice", "alice");
	let other_ca = Pki::new("mtls-other");
	let mallory = other_ca.client("mallory", "mallory");
	let h = harness().await;
	let port = free_port();
	let tls = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}],
		"client_auth": {"mode": "required", "ca_file": pki.ca_file},
	});
	let (status, v) = h.post(tcp_rule(port, tcp_backend("OK:").await, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	assert_eq!(tls_roundtrip(&pki, port, "api.test", Some(&alice), "x").await.unwrap(), "OK:x");
	assert!(tls_roundtrip(&pki, port, "api.test", None, "x").await.is_err(), "no certificate");
	assert!(tls_roundtrip(&pki, port, "api.test", Some(&mallory), "x").await.is_err(), "certificate from another CA");

	let metrics = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	let line = metrics.lines().find(|l| l.starts_with("rproxy_tls_failures_total{")).unwrap();
	assert!(line.ends_with(" 2"), "{line}");
}

#[tokio::test]
async fn terminate_can_re_encrypt_towards_the_backend() {
	let pki = Pki::new("reenc");
	let front = pki.server("front", &["front.test"]);
	let back = pki.server("back", &["back.test"]);
	let backend = tls_backend(&pki, &back, "TLS:").await;
	let h = harness().await;
	let port = free_port();
	let tls = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
		"upstream": {"tls": true, "server_name": "back.test", "ca_file": pki.ca_file},
	});
	let (status, v) = h.post(tcp_rule(port, backend, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(tls_roundtrip(&pki, port, "front.test", None, "z").await.unwrap(), "TLS:z");

	// a wrong expected name fails the backend handshake
	let port2 = free_port();
	let tls = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
		"upstream": {"tls": true, "server_name": "wrong.test", "ca_file": pki.ca_file},
	});
	h.post(tcp_rule(port2, backend, tls)).await;
	assert!(tls_roundtrip(&pki, port2, "front.test", None, "z").await.is_err());
}

#[tokio::test]
async fn certificates_are_chosen_by_sni() {
	let pki = Pki::new("multi");
	let a = pki.server("a", &["a.test"]);
	let b = pki.server("b", &["b.test"]);
	let h = harness().await;
	let port = free_port();
	let tls = json!({
		"mode": "terminate",
		"certificates": [
			{"cert_file": a.cert_file, "key_file": a.key_file},
			{"cert_file": b.cert_file, "key_file": b.key_file},
		],
	});
	h.post(tcp_rule(port, tcp_backend("E:").await, tls)).await;
	// verification against each name only passes if the matching certificate is served
	assert_eq!(tls_roundtrip(&pki, port, "a.test", None, "1").await.unwrap(), "E:1");
	assert_eq!(tls_roundtrip(&pki, port, "b.test", None, "2").await.unwrap(), "E:2");
}

#[tokio::test]
async fn bad_tls_settings_are_reported() {
	let h = harness().await;
	let backend = tcp_backend("A:").await;
	let (status, v) = h
		.post(tcp_rule(free_port(), backend, json!({
			"mode": "terminate",
			"certificates": [{"cert_file": "/nonexistent/cert.pem", "key_file": "/nonexistent/key.pem"}],
		})))
		.await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("/nonexistent/cert.pem"));

	let (status, v) = h.post(tcp_rule(free_port(), backend, json!({"mode": "terminate"}))).await;
	assert_eq!(v["code"], "tls_config", "{status} {v}");
	let (status, v) = h.post(tcp_rule(free_port(), backend, json!({"mode": "bogus"}))).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")));
	let mut udp_sni = rule("udp", free_udp_port(), backend);
	udp_sni["tls"] = json!({"mode": "sni"});
	assert_eq!(h.post(udp_sni).await.1["code"], "unsupported");
	let (_, rules) = h.get("/rules").await;
	assert_eq!(rules.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn reload_picks_up_renewed_certificates_and_patch_changes_tls() {
	let pki = Pki::new("reload");
	let old = pki.server("front", &["old.test"]);
	let h = harness().await;
	let port = free_port();
	let backend = tcp_backend("R:").await;
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": old.cert_file, "key_file": old.key_file}]});
	h.post(tcp_rule(port, backend, tls)).await;
	assert!(tls_roundtrip(&pki, port, "old.test", None, "1").await.is_ok());
	assert!(tls_roundtrip(&pki, port, "new.test", None, "1").await.is_err());

	// renew the certificate in place, as certbot would, then reload
	let renewed = pki.server("front", &["new.test"]);
	assert_eq!(renewed.cert_file, old.cert_file);
	assert_eq!(h.registry.reload_tls().await, (1, 0));
	assert_eq!(tls_roundtrip(&pki, port, "new.test", None, "2").await.unwrap(), "R:2");

	// PATCH can switch the rule back to passthrough
	let (status, v) = h
		.patch(&format!("tcp/127.0.0.1/{port}"), json!({"remote_addr": "127.0.0.1", "remote_port": backend.port(), "tls": {"mode": "passthrough"}}))
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(v["tls"]["mode"], "passthrough");
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(roundtrip(&mut s, "plain").await, "R:plain");
}
