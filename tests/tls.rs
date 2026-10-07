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
	// udp takes mode sni (#130, tests/udp_sni.rs), but not passthrough routes
	udp_sni["tls"] = json!({"mode": "sni", "routes": [{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": 9, "passthrough": true}]});
	assert_eq!(h.post(udp_sni).await.1["code"], "tls_config");
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

#[tokio::test]
async fn changed_certificate_files_are_noticed() {
	let pki = Pki::new("watch");
	let first = pki.server("front", &["one.test"]);
	// cert-manager / Kubernetes secrets: the path is a symbolic link that gets swapped
	let dir = std::path::Path::new(&first.cert_file).parent().unwrap().join("live");
	std::fs::create_dir_all(&dir).unwrap();
	let (cert, key) = (dir.join("tls.crt"), dir.join("tls.key"));
	std::os::unix::fs::symlink(&first.cert_file, &cert).unwrap();
	std::os::unix::fs::symlink(&first.key_file, &key).unwrap();

	let h = harness().await;
	let port = free_port();
	let backend = tcp_backend("W:").await;
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": cert, "key_file": key}]});
	let (status, v) = h.post(tcp_rule(port, backend, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(h.registry.reload_changed_tls().await, (0, 0), "loaded when the rule was created");
	assert_eq!(h.registry.reload_changed_tls().await, (0, 0), "nothing changed");
	assert!(tls_roundtrip(&pki, port, "one.test", None, "1").await.is_ok());

	// renewed in place (certbot)
	let second = pki.server("front", &["two.test"]);
	assert_eq!(h.registry.reload_changed_tls().await, (1, 0));
	assert_eq!(tls_roundtrip(&pki, port, "two.test", None, "2").await.unwrap(), "W:2");
	assert_eq!(h.registry.reload_changed_tls().await, (0, 0));

	// half-written: the key no longer matches; the current certificate stays
	std::fs::write(&second.key_file, "not a key").unwrap();
	assert_eq!(h.registry.reload_changed_tls().await, (0, 1));
	assert_eq!(h.registry.reload_changed_tls().await, (0, 1), "tried again on the next check");
	assert_eq!(tls_roundtrip(&pki, port, "two.test", None, "3").await.unwrap(), "W:3");

	// the links are swapped to a new pair
	let third = pki.server("other", &["three.test"]);
	for (link, target) in [(&cert, &third.cert_file), (&key, &third.key_file)] {
		let tmp = link.with_extension("new");
		std::os::unix::fs::symlink(target, &tmp).unwrap();
		std::fs::rename(&tmp, link).unwrap();
	}
	assert_eq!(h.registry.reload_changed_tls().await, (1, 0));
	assert_eq!(tls_roundtrip(&pki, port, "three.test", None, "4").await.unwrap(), "W:4");
}

/// Handshakes with `connector` and returns the negotiated (version, cipher suite).
async fn negotiate(port: u16, name: &str, connector: tokio_rustls::TlsConnector) -> std::io::Result<(String, String)> {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
	let mut s = connector.connect(name.to_string().try_into().unwrap(), tcp).await?;
	s.write_all(b"x").await?;
	let mut buf = [0u8; 64];
	tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await??;
	let (_, conn) = s.get_ref();
	Ok((format!("{:?}", conn.protocol_version().unwrap()), format!("{:?}", conn.negotiated_cipher_suite().unwrap().suite())))
}

fn client_with(pki: &Pki, versions: &[&'static rustls::SupportedProtocolVersion]) -> tokio_rustls::TlsConnector {
	let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
		.with_protocol_versions(versions)
		.unwrap()
		.with_root_certificates(pki.roots())
		.with_no_client_auth();
	tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
}

#[tokio::test]
async fn tls_options_limit_versions_and_cipher_suites() {
	let pki = Pki::new("opts");
	let cert = pki.server("front", &["opts.test"]);
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["tls_options"], true, "{caps}");
	let backend = tcp_backend("O:").await;
	let files = json!([{"cert_file": cert.cert_file, "key_file": cert.key_file}]);
	let (tls12, tls13) = (&rustls::version::TLS12, &rustls::version::TLS13);

	let only13 = free_port();
	let (status, v) = h
		.post(tcp_rule(only13, backend, json!({"mode": "terminate", "certificates": files, "options": {"min_version": "1.3"}})))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(negotiate(only13, "opts.test", client_with(&pki, &[tls12])).await.is_err(), "TLS 1.2 clients are refused");
	assert_eq!(negotiate(only13, "opts.test", client_with(&pki, &[tls13, tls12])).await.unwrap().0, "TLSv1_3");

	let chacha = free_port();
	let suites = json!([
		"TLS13_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	]);
	let (status, v) = h
		.post(tcp_rule(chacha, backend, json!({"mode": "terminate", "certificates": files, "options": {"cipher_suites": suites}})))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["tls"]["options"]["cipher_suites"], suites, "{v}");
	let (version, suite) = negotiate(chacha, "opts.test", client_with(&pki, &[tls13, tls12])).await.unwrap();
	assert_eq!((version.as_str(), suite.as_str()), ("TLSv1_3", "TLS13_CHACHA20_POLY1305_SHA256"));
	let (version, suite) = negotiate(chacha, "opts.test", client_with(&pki, &[tls12])).await.unwrap();
	assert_eq!(version, "TLSv1_2");
	assert!(suite.contains("CHACHA20_POLY1305"), "{suite}");

	// mistakes
	for (options, code, text) in [
		(json!({"cipher_suites": ["TLS_RSA_WITH_RC4_128_MD5"]}), "tls_config", "known:"),
		(json!({"min_version": "1.3", "cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]}), "tls_config", "min_version 1.3"),
		(json!({"min_version": "1.1"}), "tls_config", "1.2 or 1.3"),
	] {
		let (status, v) = h
			.post(tcp_rule(free_port(), backend, json!({"mode": "terminate", "certificates": files, "options": options})))
			.await;
		assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{options}: {v}");
		assert!(v["error"].as_str().unwrap().contains(text), "{options}: {v}");
	}
	let mut dtls = rule("udp", free_udp_port(), backend);
	dtls["tls"] = json!({"mode": "terminate", "certificates": files, "options": {"min_version": "1.3"}});
	assert_eq!(h.post(dtls).await.1["code"], "unsupported", "no options for DTLS");
}

/// One HTTP/1.1 request over TLS (`name` as SNI and Host); returns the response.
async fn https_get(pki: &Pki, port: u16, name: &str) -> std::io::Result<String> {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
	let mut s = pki.connector(None).connect(name.to_string().try_into().unwrap(), tcp).await?;
	s.write_all(format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
	let mut out = Vec::new();
	let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await?;
	Ok(String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn terminate_passes_some_names_through() {
	let pki = Pki::new("pass");
	// the backend's certificate covers the passthrough names; rproxy's does not
	let own = pki.server("k8s", &["registry.test", "a.tenant.test", "x.y.tenant.test"]);
	let passed = tls_backend(&pki, &own, "P:").await;
	let front = pki.server("front", &["front.test", "nope.test"]);
	let plain = tcp_backend("R:").await;
	let h = harness().await;
	let port = free_port();
	let tls = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
		"routes": [
			{"server_names": ["registry.test", "**.tenant.test"], "remote_addr": "127.0.0.1", "remote_port": passed.port(), "passthrough": true},
			{"server_name": "front.test", "remote_addr": "127.0.0.1", "remote_port": plain.port()},
		],
		"unmatched": "reject",
	});
	let (status, v) = h.post(tcp_rule(port, plain, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["tls"]["routes"][0]["passthrough"], true, "{v}");
	assert_eq!(v["tls"]["routes"][0]["server_names"][1], "**.tenant.test", "{v}");

	// end to end with the backend's own certificate: rproxy did not terminate
	assert_eq!(tls_roundtrip(&pki, port, "registry.test", None, "1").await.unwrap(), "P:1");
	assert_eq!(tls_roundtrip(&pki, port, "a.tenant.test", None, "2").await.unwrap(), "P:2");
	assert_eq!(tls_roundtrip(&pki, port, "x.y.tenant.test", None, "3").await.unwrap(), "P:3", "**. matches any depth");
	// other names are terminated by rproxy and routed as before
	assert_eq!(tls_roundtrip(&pki, port, "front.test", None, "4").await.unwrap(), "R:4");
	assert!(tls_roundtrip(&pki, port, "nope.test", None, "5").await.is_err(), "unmatched: reject still refuses");
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert!(v["stats"]["total_connections"].as_u64().unwrap() >= 4, "{v}");

	// allow_from also applies to passthrough connections
	let port2 = free_port();
	let mut limited = tcp_rule(
		port2,
		plain,
		json!({
			"mode": "terminate",
			"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
			"routes": [{"server_name": "registry.test", "remote_addr": "127.0.0.1", "remote_port": passed.port(), "passthrough": true}],
		}),
	);
	limited["allow_from"] = json!(["10.9.9.9"]);
	assert_eq!(h.post(limited).await.0, StatusCode::CREATED);
	assert!(tls_roundtrip(&pki, port2, "registry.test", None, "6").await.is_err());

	// mistakes in the routes
	let mut bad = tcp_rule(
		free_port(),
		plain,
		json!({
			"mode": "sni",
			"routes": [{"server_name": "registry.test", "remote_addr": "127.0.0.1", "remote_port": passed.port(), "passthrough": true}],
		}),
	);
	let (status, v) = h.post(bad.clone()).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
	bad["tls"] = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
		"routes": [{"server_name": "a.test", "server_names": ["b.test"], "remote_addr": "127.0.0.1", "remote_port": 1}],
	});
	let (status, v) = h.post(bad).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
}

#[tokio::test]
async fn http_rules_pass_some_names_through_on_the_same_port() {
	let pki = Pki::new("passhttp");
	let own = pki.server("k8s", &["registry.test", "deep.a.tenant.test"]);
	let passed = tls_backend(&pki, &own, "P:").await;
	let front = pki.server("front", &["cdn.test"]);
	let h = harness().await;
	let port = free_port();
	let mut body = rule("tcp", port, passed);
	let obj = body.as_object_mut().unwrap();
	obj.remove("remote_addr");
	obj.remove("remote_port");
	body["tls"] = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
		"routes": [{"server_names": ["registry.test", "**.tenant.test"], "remote_addr": "127.0.0.1", "remote_port": passed.port(), "passthrough": true}],
	});
	body["http"] = json!({
		"routes": [{"name": "cdn", "match": "Host(`cdn.test`)", "middlewares": ["hello"]}],
		"middlewares": {"hello": {"respond": {"status": 200, "body": "from L7"}}},
	});
	let (status, v) = h.post(body.clone()).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let resp = https_get(&pki, port, "cdn.test").await.unwrap();
	assert!(resp.starts_with("HTTP/1.1 200") && resp.ends_with("from L7"), "{resp}");
	assert_eq!(tls_roundtrip(&pki, port, "registry.test", None, "1").await.unwrap(), "P:1");
	assert_eq!(tls_roundtrip(&pki, port, "deep.a.tenant.test", None, "2").await.unwrap(), "P:2");

	// only passthrough routes are used by http rules
	body["tls"]["routes"][0]["passthrough"] = json!(false);
	body["listen_port"] = json!(free_port());
	let (status, v) = h.post(body).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
}

fn unix_now() -> i64 {
	rproxy_api::tls::config::unix_now()
}

/// The `cert_status` entry of a rule view for `file`.
fn cert_status<'a>(view: &'a Value, file: &str) -> &'a Value {
	view["cert_status"].as_array().unwrap().iter().find(|c| c["file"] == file).unwrap_or_else(|| panic!("{file} not in {view}"))
}

#[tokio::test]
async fn expired_certificates_are_left_out_and_stop_the_rule_when_none_is_left() {
	let pki = Pki::new("expiry");
	let old = pki.server_until("old", &["old.test"], unix_now() - 86_400);
	let valid = pki.server("ok", &["ok.test"]);
	let h = harness().await;
	let port = free_port();
	let backend = tcp_backend("X:").await;
	let tls = json!({"mode": "terminate", "certificates": [
		{"cert_file": old.cert_file, "key_file": old.key_file},
		{"cert_file": valid.cert_file, "key_file": valid.key_file}
	]});
	let (status, v) = h.post(tcp_rule(port, backend, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "one certificate is still valid: {v}");
	let key = format!("tcp/127.0.0.1/{port}");
	let (_, v) = h.get(&format!("/rules/{key}")).await;
	let expired = cert_status(&v, &old.cert_file);
	assert_eq!((expired["role"].as_str(), expired["state"].as_str()), (Some("certificate"), Some("expired")), "{v}");
	// issued to end a day ago; whole days are rounded down, so a second either way gives -1 or -2
	assert!(matches!(expired["days_left"].as_i64(), Some(-2..=-1)), "{v}");
	assert!(expired["not_after"].as_str().unwrap().ends_with('Z'), "{v}");
	assert_eq!(cert_status(&v, &valid.cert_file)["state"], "ok");
	assert_eq!(tls_roundtrip(&pki, port, "ok.test", None, "1").await.unwrap(), "X:1");
	// the expired certificate is not offered: its name gets the first remaining one
	// (a name mismatch for the client), never the expired certificate
	assert!(tls_roundtrip(&pki, port, "old.test", None, "2").await.is_err());

	let text = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	let line = text.lines().find(|l| l.starts_with("rproxy_cert_expiry_seconds") && l.contains(&old.cert_file)).unwrap();
	assert!(line.contains("role=\"certificate\"") && line.ends_with(|c: char| c.is_ascii_digit()), "{line}");
	assert!(line.rsplit(' ').next().unwrap().starts_with('-'), "negative once expired: {line}");

	// the last valid certificate expires too (renewed with an expired one): the rule stops
	pki.server_until("ok", &["ok.test"], unix_now() - 60);
	assert_eq!(h.registry.reload_changed_tls().await, (0, 0));
	let (_, v) = h.get(&format!("/rules/{key}")).await;
	assert_eq!(v["state"], "failed", "{v}");
	assert!(v["error"].as_str().unwrap().starts_with("certificate expired"), "{v}");
	assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err(), "the port is closed");

	// renewed: the rule comes back on its own
	pki.server("ok", &["ok.test"]);
	assert_eq!(h.registry.reload_changed_tls().await, (1, 0));
	let (_, v) = h.get(&format!("/rules/{key}")).await;
	assert_eq!(v["state"], "running", "{v}");
	assert_eq!(tls_roundtrip(&pki, port, "ok.test", None, "3").await.unwrap(), "X:3");
}

#[tokio::test]
async fn the_daily_check_stops_a_rule_whose_certificate_has_just_expired() {
	let pki = Pki::new("expiry-daily");
	let soon = pki.server_until("soon", &["soon.test"], unix_now() + 2);
	let h = harness().await;
	let port = free_port();
	let backend = tcp_backend("D:").await;
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": soon.cert_file, "key_file": soon.key_file}]});
	let (status, v) = h.post(tcp_rule(port, backend, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(cert_status(&v, &soon.cert_file)["state"], "expiring", "within the warning period: {v}");
	assert_eq!(h.registry.check_certificate_expiry().await, 0, "not expired yet");
	tokio::time::sleep(Duration::from_millis(3_100)).await;
	h.registry.check_certificate_expiry().await;
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!(v["state"], "failed", "{v}");
	assert_eq!(cert_status(&v, &soon.cert_file)["state"], "expired", "{v}");
}

#[tokio::test]
async fn a_rule_whose_certificates_have_all_expired_is_refused() {
	let pki = Pki::new("expiry-refused");
	let old = pki.server_until("old", &["old.test"], unix_now() - 3600);
	let h = harness().await;
	let backend = tcp_backend("R:").await;
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": old.cert_file, "key_file": old.key_file}]});
	let (status, v) = h.post(tcp_rule(free_port(), backend, tls)).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
	assert!(v["error"].as_str().unwrap().starts_with("certificate expired"), "{v}");
}

#[tokio::test]
async fn an_expired_client_ca_only_warns() {
	let pki = Pki::new("expiry-ca");
	let server = pki.server("front", &["ca.test"]);
	let old_ca = pki.ca_until("old-ca", unix_now() - 86_400);
	let h = harness().await;
	let port = free_port();
	let backend = tcp_backend("C:").await;
	let tls = json!({"mode": "terminate",
		"certificates": [{"cert_file": server.cert_file, "key_file": server.key_file}],
		"client_auth": {"mode": "optional", "ca_file": old_ca}});
	let (status, v) = h.post(tcp_rule(port, backend, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["state"], "running");
	let ca = cert_status(&v, &old_ca);
	assert_eq!((ca["role"].as_str(), ca["state"].as_str()), (Some("client_ca"), Some("expired")), "{v}");
	assert_eq!(tls_roundtrip(&pki, port, "ca.test", None, "1").await.unwrap(), "C:1");
	assert_eq!(h.registry.check_certificate_expiry().await, 0, "a CA does not stop the rule");
}

/// Every certificate file a rule uses is reported with its role: the client
/// CA's intermediates (`client_chain`) and both files towards the backend.
#[tokio::test]
async fn cert_status_names_every_role() {
	let pki = Pki::three_tier("roles");
	let server = pki.server("front", &["roles.test"]);
	let to_backend = pki.client("to-backend", "rproxy");
	let upstream_ca = pki.bundle_file();
	let chain = pki.chain_file.clone().unwrap();
	let h = harness().await;
	let port = free_port();
	let backend = tcp_backend("R:").await;
	let tls = json!({"mode": "terminate",
		"certificates": [{"cert_file": server.cert_file, "chain_file": chain, "key_file": server.key_file}],
		"client_auth": {"mode": "optional", "ca_file": pki.ca_file, "chain_file": chain},
		"upstream": {"tls": true, "ca_file": upstream_ca, "cert_file": to_backend.cert_file, "key_file": to_backend.key_file}});
	let (status, v) = h.post(tcp_rule(port, backend, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let roles: Vec<(String, String)> = v["cert_status"]
		.as_array()
		.unwrap()
		.iter()
		.map(|c| (c["role"].as_str().unwrap().to_string(), c["file"].as_str().unwrap().to_string()))
		.collect();
	for (role, file) in [
		("certificate", &server.cert_file),
		("client_ca", &pki.ca_file),
		("client_chain", &chain),
		("upstream_ca", &upstream_ca),
		("upstream_certificate", &to_backend.cert_file),
	] {
		assert!(roles.contains(&(role.to_string(), file.clone())), "{role} {file} not in {roles:?}");
	}
	for c in v["cert_status"].as_array().unwrap() {
		assert_eq!(c["state"], "ok", "{c}");
		assert!(c["days_left"].as_i64().unwrap() > 300, "{c}");
	}
	let text = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	for role in ["client_chain", "upstream_ca", "upstream_certificate"] {
		let labels = format!("protocol=\"tcp\",listen=\"127.0.0.1:{port}\",role=\"{role}\"");
		assert!(text.lines().any(|l| l.starts_with(&format!("rproxy_cert_expiry_seconds{{{labels}"))), "{role}: {text}");
	}
}

/// Large echoes through `terminate` with a small client send buffer (#187): rproxy
/// passes every byte on in both directions, round after round. The client must
/// flush after writing: with a full socket, rustls keeps the last records until
/// then (what stalled the `tls_terminate/throughput_1MiB` benchmark).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminate_does_not_stall_under_backpressure() {
	let pki = Pki::new("stall");
	let cert = pki.server("front", &["big.test"]);
	let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let target = backend.local_addr().unwrap();
	tokio::spawn(async move {
		let (mut s, _) = backend.accept().await.unwrap();
		let (mut r, mut w) = s.split();
		let _ = tokio::io::copy(&mut r, &mut w).await;
	});
	let h = harness().await;
	let port = free_port();
	let body = tcp_rule(port, target, json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]}));
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);

	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	// (not SO_RCVBUF: a receive window far below the loopback MSS stalls the kernel
	// itself until the persist timer, whoever the sender is)
	socket2::SockRef::from(&tcp).set_send_buffer_size(4096).unwrap();
	let mut tls = pki.connector(None).connect("big.test".try_into().unwrap(), tcp).await.unwrap();
	let data: Vec<u8> = (0..1usize << 20).map(|i| (i * 31 % 251) as u8).collect();
	let mut back = vec![0u8; data.len()];
	for round in 0..16 {
		let (mut r, mut w) = tokio::io::split(&mut tls);
		let done = tokio::time::timeout(Duration::from_secs(20), async {
			let write = async {
				w.write_all(&data).await?;
				w.flush().await
			};
			let (a, b) = tokio::join!(write, r.read_exact(&mut back));
			a.and(b.map(|_| ()))
		})
		.await;
		let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;

		done.unwrap_or_else(|_| panic!("round {round} stalled; rule stats {}", v["stats"])).unwrap();
		assert!(back == data, "round {round}: corrupted");
	}
}

#[tokio::test]
async fn a_tls_route_spreads_over_several_targets() {
	// #234: TLSRoute with several backends
	let pki = Pki::new("sni-targets");
	let cert = pki.server("backend", &["a.test", "f.test"]);
	let (a, b, fallback) = (tls_backend(&pki, &cert, "A:").await, tls_backend(&pki, &cert, "B:").await, tls_backend(&pki, &cert, "D:").await);
	let dead = {
		let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		l.local_addr().unwrap().port()
	};
	let h = harness().await;
	let port = free_port();
	let tls = json!({
		"mode": "sni",
		"routes": [
			{"server_name": "a.test", "targets": [
				{"addr": "127.0.0.1", "port": a.port(), "weight": 1},
				{"addr": "127.0.0.1", "port": b.port(), "weight": 1},
				{"addr": "127.0.0.1", "port": dead, "weight": 1},
			]},
			{"server_name": "f.test", "balance": "failover", "targets": [
				{"addr": "127.0.0.1", "port": dead},
				{"addr": "127.0.0.1", "port": b.port()},
			]},
		],
	});
	let (status, v) = h.post(tcp_rule(port, fallback, tls)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["tls"]["routes"][0]["targets"].as_array().unwrap().len(), 3, "{v}");
	let mut seen = std::collections::HashMap::new();
	for i in 0..12 {
		let got = tls_roundtrip(&pki, port, "a.test", None, &i.to_string()).await.unwrap();
		*seen.entry(got[..2].to_string()).or_insert(0) += 1;
	}
	assert!(seen["A:"] >= 4 && seen["B:"] >= 4 && seen.len() == 2, "{seen:?}");
	for i in 0..3 {
		assert_eq!(tls_roundtrip(&pki, port, "f.test", None, &i.to_string()).await.unwrap(), format!("B:{i}"), "past the dead first target");
	}

	// remote_addr and targets together, or neither, are refused
	for route in [
		json!({"server_name": "x.test", "remote_addr": "127.0.0.1", "remote_port": 1, "targets": [{"addr": "127.0.0.1", "port": 2}]}),
		json!({"server_name": "x.test"}),
		json!({"server_name": "x.test", "remote_addr": "127.0.0.1", "remote_port": 1, "balance": "least_conn"}),
	] {
		let (status, v) = h.post(tcp_rule(free_port(), fallback, json!({"mode": "sni", "routes": [route]}))).await;
		assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
	}
}
