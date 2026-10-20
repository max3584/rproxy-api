//! `proxy_protocol` of a `udp` rule (#312): every datagram from a front end in
//! `from` carries a PROXY v2 (DGRAM) header, which rproxy reads and strips; the client
//! it names is used everywhere the source counts, and replies go back to the front
//! end's address and port without a header. Every datagram here comes from
//! 127.0.0.1, so `from: ["127.0.0.1/32"]` makes the test (or an outer rproxy rule)
//! the front end, and another range makes it an untrusted peer. Nothing is read
//! once right after a change: replies and counters are waited for.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::UdpSocket;

use common::pki::{Issued, Pki};
use common::*;
use rproxy_api::net::proxy_in::{parse_dgram, Parsed};
use rproxy_api::net::source::{proxy_v1_header, proxy_v2_dgram_header, proxy_v2_header};

fn sa(s: &str) -> SocketAddr {
	s.parse().unwrap()
}

fn local(port: u16) -> SocketAddr {
	SocketAddr::from(([127, 0, 0, 1], port))
}

fn with_pp(mut body: Value, pp: Value) -> Value {
	body["proxy_protocol"] = pp;
	body
}

fn trusted() -> Value {
	json!({"from": ["127.0.0.1/32"]})
}

/// A socket connected to rproxy's `port`.
async fn sender(port: u16) -> UdpSocket {
	let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	s.connect(local(port)).await.unwrap();
	s
}

/// Sends `datagram` and waits a little for a reply (None: dropped).
async fn ask(s: &UdpSocket, datagram: &[u8]) -> Option<String> {
	s.send(datagram).await.unwrap();
	let mut buf = [0u8; 2048];
	match tokio::time::timeout(Duration::from_millis(700), s.recv(&mut buf)).await {
		Ok(Ok(n)) => Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
		_ => None,
	}
}

/// Sends `datagram` until a reply comes (a change may take a moment to apply).
async fn ask_until(s: &UdpSocket, datagram: &[u8], want: &str) {
	let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
	loop {
		let got = ask(s, datagram).await;
		if got.as_deref() == Some(want) {
			return;
		}
		assert!(tokio::time::Instant::now() < deadline, "no {want:?}, last {got:?}");
	}
}

fn header(client: &str, port: u16) -> Vec<u8> {
	proxy_v2_dgram_header(sa(client), local(port))
}

/// A backend that reads the PROXY v2 header of each datagram and answers with the
/// client it names and the payload (`<client>|<payload>`), or `none|<datagram>`.
async fn reading_backend() -> SocketAddr {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr = sock.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = vec![0u8; 65_536];
		loop {
			let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
			let d = &buf[..n];
			let out = match parse_dgram(d) {
				Parsed::Header(h) => {
					format!("{}|{}", h.addrs.map(|a| a.0.to_string()).unwrap_or_default(), String::from_utf8_lossy(&d[h.len..]))
				}
				_ => format!("none|{}", String::from_utf8_lossy(d)),
			};
			let _ = sock.send_to(out.as_bytes(), from).await;
		}
	});
	addr
}

#[tokio::test]
async fn the_shape_validation_and_patch_in_place() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["proxy_protocol_in_udp"], true, "{caps}");
	let backend = udp_backend("B:").await;
	let port = free_udp_port();
	let (status, v) = h.post(rule("udp", port, backend)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let s = sender(port).await;
	let hdr = [header("192.0.2.7:4000", port), b"x".to_vec()].concat();
	// without proxy_protocol the header is only data
	assert_eq!(ask(&s, b"plain").await.as_deref(), Some("B:plain"));

	// PATCH adds it in place: the same socket's next datagrams are read for a header
	let path = format!("udp/127.0.0.1/{port}");
	let target = json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()});
	let (status, v) = h.patch(&path, with_pp(target.clone(), trusted())).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(v["proxy_protocol"], json!({"from": ["127.0.0.1/32"], "required": true}), "{v}");
	assert_eq!(v["state"], "running", "{v}");
	ask_until(&s, &hdr, "B:x").await;
	assert_eq!(ask(&s, b"plain").await, None, "required: a datagram without a header is dropped");
	// `{}` removes it: headers are data again
	let (status, v) = h.patch(&path, with_pp(target.clone(), json!({}))).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(v.get("proxy_protocol").is_none(), "{v}");
	ask_until(&s, b"plain", "B:plain").await;

	for (pp, code) in [
		(json!({"from": []}), "invalid"),
		(json!({"required": true}), "invalid"),
		(json!({"from": ["0.0.0.0/0"]}), "invalid"),
		(json!({"from": ["::/0"]}), "invalid"),
		(json!({"from": ["not-an-address"]}), "invalid"),
	] {
		let (status, v) = h.post(with_pp(rule("udp", free_udp_port(), backend), pp.clone())).await;
		assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{pp}: {v}");
		let (status, v) = h.patch(&path, with_pp(target.clone(), pp.clone())).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "PATCH {pp}: {v}");
	}
	let (status, v) = h.post(with_pp(rule("udp", free_udp_port(), backend), json!({"from": ["10.0.0.0/8"], "required": false}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["proxy_protocol"], json!({"from": ["10.0.0.0/8"], "required": false}), "{v}");
}

/// Two rproxy hops over UDP: the outer rule's `source_ip: proxy_v2` writes the client
/// in front of each datagram, the inner rule reads it and writes it again for its
/// backend; replies reach the client through both hops, without headers.
#[tokio::test]
async fn two_hops_keep_the_client() {
	logs::capture();
	let backend = reading_backend().await;
	let h = harness().await;
	let (outer, inner) = (free_udp_port(), free_udp_port());
	let mut body = with_pp(rule("udp", inner, backend), trusted());
	body["source_ip"] = json!("proxy_v2");
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut body = rule("udp", outer, local(inner));
	body["source_ip"] = json!("proxy_v2");
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let client = sender(outer).await;
	let me = client.local_addr().unwrap();
	for msg in ["one", "two"] {
		ask_until(&client, msg.as_bytes(), &format!("{me}|{msg}")).await;
	}
	// another client: its own session on both hops
	let other = sender(outer).await;
	let them = other.local_addr().unwrap();
	ask_until(&other, b"three", &format!("{them}|three")).await;

	let open = logs::wait_for("the inner conn.open", |l| {
		l["event"] == "conn.open" && l["rule"] == format!("udp/127.0.0.1:{inner}") && l["client"] == me.to_string()
	})
	.await;
	let via = open["proxy_peer"].as_str().expect("proxy_peer").to_string();
	assert!(via.starts_with("127.0.0.1:") && via != me.to_string(), "the outer rule's socket: {open}");
	let v = wait_for(&h, &format!("/rules/udp/127.0.0.1/{inner}"), |v| v["connections"] == 2).await;
	assert_eq!(v["stats"]["denied"], 0, "{v}");
}

/// `allow_from` judges the client of the header; `required` drops datagrams without
/// one, and v1, STREAM and broken headers are dropped all the same.
#[tokio::test]
async fn allow_from_required_and_bad_headers() {
	logs::capture();
	let h = harness().await;
	let backend = udp_backend("B:").await;
	let (port, lax) = (free_udp_port(), free_udp_port());
	let mut body = with_pp(rule("udp", port, backend), trusted());
	body["allow_from"] = json!(["192.0.2.0/24"]);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v) = h.post(with_pp(rule("udp", lax, backend), json!({"from": ["127.0.0.1/32"], "required": false}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let s = sender(port).await;
	ask_until(&s, &[header("192.0.2.7:4000", port), b"a".to_vec()].concat(), "B:a").await;
	assert_eq!(ask(&s, &[header("198.51.100.1:4000", port), b"b".to_vec()].concat()).await, None, "outside allow_from");
	// without a header the peer (127.0.0.1) would be judged; refused as required anyway
	assert_eq!(ask(&s, b"c").await, None);
	let v = wait_for(&h, &format!("/rules/udp/127.0.0.1/{port}"), |v| v["stats"]["denied"] == 2).await;
	assert_eq!(v["connections"], 1, "{v}");
	logs::wait_for("proxy_protocol", |l| {
		l["event"] == "conn.denied" && l["reason"] == "proxy_protocol" && l["rule"] == format!("udp/127.0.0.1:{port}")
	})
	.await;

	let s = sender(lax).await;
	ask_until(&s, b"plain", "B:plain").await;
	ask_until(&s, &[header("192.0.2.9:1", lax), b"h".to_vec()].concat(), "B:h").await;
	let bad = [
		[proxy_v1_header(sa("192.0.2.7:1"), local(lax)), b"v1".to_vec()].concat(),
		[proxy_v2_header(sa("192.0.2.7:1"), local(lax)), b"stream".to_vec()].concat(),
		header("192.0.2.7:1", lax)[..20].to_vec(),
	];
	for d in &bad {
		assert_eq!(ask(&s, d).await, None, "{d:?}");
	}
	wait_for(&h, &format!("/rules/udp/127.0.0.1/{lax}"), |v| v["stats"]["denied"] == 3).await;
}

/// A peer outside `from` that sends a header is dropped; without one it is served as before.
#[tokio::test]
async fn a_header_from_outside_from_is_dropped() {
	logs::capture();
	let h = harness().await;
	let port = free_udp_port();
	let (status, v) = h.post(with_pp(rule("udp", port, udp_backend("B:").await), json!({"from": ["10.0.0.0/8"]}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let s = sender(port).await;
	ask_until(&s, b"hello", "B:hello").await;
	assert_eq!(ask(&s, &[header("192.0.2.7:4000", port), b"x".to_vec()].concat()).await, None, "v2 from outside from");
	assert_eq!(ask(&s, b"PROXY UDP4 192.0.2.7 192.0.2.1 1 2\r\nx").await, None, "v1 from outside from");
	let line = logs::wait_for("proxy_protocol_untrusted", |l| {
		l["event"] == "conn.denied" && l["reason"] == "proxy_protocol_untrusted" && l["rule"] == format!("udp/127.0.0.1:{port}")
	})
	.await;
	assert_eq!(line["client"], s.local_addr().unwrap().to_string(), "{line}");
	wait_for(&h, &format!("/rules/udp/127.0.0.1/{port}"), |v| v["stats"]["denied"] == 2).await;
}

/// Per-source `limits` count the client of the header, not the front end; the same
/// front end port with another client in its header is another session.
#[tokio::test]
async fn per_source_limits_count_the_client_of_the_header() {
	let h = harness().await;
	let port = free_udp_port();
	let mut body = with_pp(rule("udp", port, reading_backend().await), trusted());
	body["limits"] = json!({"per_source": {"max_connections": 1}});
	body["source_ip"] = json!("proxy_v2");
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (front_a, front_b) = (sender(port).await, sender(port).await);
	let a = |m: &str| [header("192.0.2.7:4000", port), m.as_bytes().to_vec()].concat();
	let b = |m: &str| [header("192.0.2.8:4000", port), m.as_bytes().to_vec()].concat();
	ask_until(&front_a, &a("1"), "192.0.2.7:4000|1").await;
	// the same client through another front end socket: a second session of 192.0.2.7
	assert_eq!(ask(&front_b, &a("2")).await, None, "a's second session");
	// another client in the header of the same front end socket: its own session
	ask_until(&front_a, &b("3"), "192.0.2.8:4000|3").await;
	ask_until(&front_a, &a("4"), "192.0.2.7:4000|4").await;
	let v = wait_for(&h, &format!("/rules/udp/127.0.0.1/{port}"), |v| v["connections"] == 2).await;
	assert_eq!(v["stats"]["limited"], 1, "{v}");
}

// ---- tls.mode: sni (QUIC) behind a front end ----

const ALPN: &[u8] = b"echo";

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

fn quic_client(pki: &Pki) -> quinn::Endpoint {
	let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_root_certificates(pki.roots())
		.with_no_client_auth();
	tls.alpn_protocols = vec![ALPN.to_vec()];
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
	let mut config = quinn::ClientConfig::new(Arc::new(crypto));
	let mut transport = quinn::TransportConfig::default();
	transport.max_idle_timeout(Some(Duration::from_secs(3).try_into().unwrap()));
	config.transport_config(Arc::new(transport));
	let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
	endpoint.set_default_client_config(config);
	endpoint
}

async fn quic_echo(endpoint: &quinn::Endpoint, port: u16, name: &str, msg: &str) -> Result<String, String> {
	let connecting = endpoint.connect(local(port), name).map_err(|e| e.to_string())?;
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

/// An outer rule (`source_ip: proxy_v2`) in front of an inner `tls.mode: sni` rule
/// with `proxy_protocol`: the inner rule reads the server name past the header, a new
/// QUIC connection to another name from the same socket still moves to its route, and
/// a route's own `source_ip: proxy_v2` (#297) writes the client of the header.
#[tokio::test]
async fn sni_reads_the_name_past_the_header() {
	let pki = Pki::new("pp-udp-sni");
	let a = quic_backend(&pki.server("a", &["a.test"]), "A:").await;
	let b = quic_backend(&pki.server("b", &["b.test"]), "B:").await;
	let recording = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let h = harness().await;
	let (outer, inner) = (free_udp_port(), free_udp_port());
	let mut body = with_pp(rule("udp", inner, a), trusted());
	body["tls"] = json!({"mode": "sni", "unmatched": "reject", "routes": [
		{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": a.port()},
		{"server_name": "b.test", "remote_addr": "127.0.0.1", "remote_port": b.port()},
		{"server_name": "rec.test", "remote_addr": "127.0.0.1", "remote_port": recording.local_addr().unwrap().port(), "source_ip": "proxy_v2"},
	]});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut body = rule("udp", outer, local(inner));
	body["source_ip"] = json!("proxy_v2");
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	// one client socket: the second connection, to another name, restarts the session
	let client = quic_client(&pki);
	assert_eq!(quic_echo(&client, outer, "a.test", "1").await.unwrap(), "A:1");
	assert_eq!(quic_echo(&client, outer, "b.test", "2").await.unwrap(), "B:2");

	let me = client.local_addr().unwrap();
	let connecting = client.connect(local(outer), "rec.test").unwrap();
	let pending = tokio::spawn(async move {
		let _ = tokio::time::timeout(Duration::from_secs(3), connecting).await;
	});
	let mut buf = vec![0u8; 65_536];
	let n = tokio::time::timeout(Duration::from_secs(5), recording.recv(&mut buf)).await.expect("no datagram").unwrap();
	pending.abort();
	let expected = proxy_v2_dgram_header(me, local(inner));
	assert_eq!(&buf[..expected.len()], &expected[..], "the client of the header, and the inner rule's address");
	assert_eq!(buf[expected.len()] & 0xc0, 0xc0, "then the QUIC Initial, without the outer header");
	assert!(n > expected.len());
}
