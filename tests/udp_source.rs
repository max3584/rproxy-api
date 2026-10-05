//! UDP replies on rules listening on a wildcard address (`0.0.0.0` / `::`) leave
//! from the address the client sent to (#137). On a host with several
//! addresses the kernel would otherwise pick the source by the route back to the
//! client, and clients that match replies by address (IKE, WebRTC, QUIC, DTLS
//! on a connected socket) drop them.
//!
//! Loopback reproduces it without extra addresses: a client on 127.0.0.1 sends
//! to 127.0.0.2, and the route back to 127.0.0.1 would answer from 127.0.0.1.
//! Clients here use connected sockets, which the kernel lets hear only from the
//! address they connected to, like those clients.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Buf;
use dtls::config::{Config, ExtendedMasterSecretType};
use dtls::conn::DTLSConn;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::{TcpListener, UdpSocket};
use webrtc_util::conn::Conn;

use common::pki::{Issued, Pki};
use common::*;

const TO: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));

/// A rule listening on `wildcard`; creation is retried on another port when a
/// parallel test holds the chosen one on a specific address.
async fn create(h: &Harness, wildcard: &str, body: impl Fn(u16) -> Value, both: bool) -> u16 {
	let mut last = Value::Null;
	for _ in 0..20 {
		let port = if both { free_tcp_udp_port() } else { free_udp_port() };
		let mut b = body(port);
		b["listen_addr"] = json!(wildcard);
		let (status, v) = h.post(b).await;
		if status == StatusCode::CREATED {
			return port;
		}
		last = v;
	}
	panic!("no free port: {last}");
}

fn free_tcp_udp_port() -> u16 {
	loop {
		let port = free_port();
		if std::net::UdpSocket::bind(("0.0.0.0", port)).is_ok() {
			return port;
		}
	}
}

/// A client socket on 127.0.0.1 that hears only from `to`.
async fn connected(to: SocketAddr) -> UdpSocket {
	let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	s.connect(to).await.unwrap();
	s
}

async fn ask(sock: &UdpSocket, msg: &str) -> Result<String, String> {
	sock.send(msg.as_bytes()).await.map_err(|e| e.to_string())?;
	let mut buf = [0u8; 1500];
	let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf))
		.await
		.map_err(|_| "no reply from the address sent to".to_string())?
		.map_err(|e| e.to_string())?;
	Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[tokio::test]
async fn relayed_replies_come_from_the_address_sent_to() {
	let h = harness().await;
	let backend = udp_backend("U:").await;
	for wildcard in ["0.0.0.0", "::"] {
		let port = create(&h, wildcard, |p| rule("udp", p, backend), false).await;
		for to in [TO, "127.0.0.3".parse().unwrap()] {
			let sock = connected(SocketAddr::new(to, port)).await;
			assert_eq!(ask(&sock, "x").await, Ok("U:x".to_string()), "{wildcard} -> {to}");
		}
		// one client socket reaching the rule at two addresses: each is answered from its own
		let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		for to in [TO, "127.0.0.3".parse().unwrap()] {
			sock.send_to(b"y", (to, port)).await.unwrap();
			let mut buf = [0u8; 64];
			let (n, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await.unwrap().unwrap();
			assert_eq!((&buf[..n], from), (&b"U:y"[..], SocketAddr::new(to, port)), "{wildcard}");
		}
		let (_, v) = h.get(&format!("/rules/udp/{}/{port}", if wildcard == "::" { "%3A%3A" } else { wildcard })).await;
		assert!(v["stats"]["total_connections"].as_u64().unwrap() >= 4, "{v}");
	}
}

/// `source_ip: proxy_v2` names the address the client sent to, not 0.0.0.0.
#[tokio::test]
async fn proxy_v2_names_the_address_sent_to() {
	let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let backend_addr = backend.local_addr().unwrap();
	let h = harness().await;
	let port = create(&h, "0.0.0.0", |p| {
		let mut r = rule("udp", p, backend_addr);
		r["source_ip"] = json!("proxy_v2");
		r
	}, false)
	.await;
	let sock = connected(SocketAddr::new(TO, port)).await;
	sock.send(b"hi").await.unwrap();
	let mut buf = [0u8; 256];
	let (n, _) = tokio::time::timeout(Duration::from_secs(2), backend.recv_from(&mut buf)).await.unwrap().unwrap();
	// signature (12), ver/cmd, family, length (2), src (4), dst (4), ports
	assert_eq!(buf[13], 0x12, "IPv4 DGRAM");
	assert_eq!(&buf[20..24], &[127, 0, 0, 2], "destination address");
	assert_eq!(u16::from_be_bytes([buf[26], buf[27]]), port);
	assert_eq!(&buf[28..n], b"hi");
}

#[tokio::test]
async fn dtls_handshakes_with_the_address_sent_to() {
	let pki = Pki::new("udp-source-dtls");
	let cert = pki.server("front", &["media.test"]);
	let h = harness().await;
	let backend = udp_backend("D:").await;
	let port = create(&h, "0.0.0.0", |p| {
		let mut r = rule("udp", p, backend);
		r["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]});
		r
	}, false)
	.await;
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(connected(SocketAddr::new(TO, port)).await);
	let config = Config {
		roots_cas: pki.roots(),
		server_name: "media.test".into(),
		extended_master_secret: ExtendedMasterSecretType::Require,
		..Default::default()
	};
	let c = tokio::time::timeout(Duration::from_secs(5), DTLSConn::new(conn, config, true, None))
		.await
		.expect("DTLS handshake timed out: replies came from another address")
		.unwrap();
	c.write(b"a", None).await.unwrap();
	let mut buf = vec![0u8; 1500];
	let n = tokio::time::timeout(Duration::from_secs(3), c.read(&mut buf, None)).await.unwrap().unwrap();
	assert_eq!(&buf[..n], b"D:a");
}

/// A quinn client endpoint on a socket connected to `to`.
fn quic_endpoint(tls: rustls::ClientConfig, to: SocketAddr) -> quinn::Endpoint {
	let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
	sock.connect(to).unwrap();
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
	let mut config = quinn::ClientConfig::new(Arc::new(crypto));
	let mut transport = quinn::TransportConfig::default();
	transport.max_idle_timeout(Some(Duration::from_secs(3).try_into().unwrap()));
	config.transport_config(Arc::new(transport));
	let mut endpoint = quinn::Endpoint::new(quinn::EndpointConfig::default(), None, sock, Arc::new(quinn::TokioRuntime)).unwrap();
	endpoint.set_default_client_config(config);
	endpoint
}

fn client_tls(pki: &Pki, alpn: &[u8]) -> rustls::ClientConfig {
	let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_root_certificates(pki.roots())
		.with_no_client_auth();
	tls.alpn_protocols = vec![alpn.to_vec()];
	tls
}

async fn quic_backend(issued: &Issued) -> SocketAddr {
	let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_no_client_auth()
		.with_single_cert(issued.full_chain(), issued.key_der())
		.unwrap();
	tls.alpn_protocols = vec![b"echo".to_vec()];
	let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
	let endpoint = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), "127.0.0.1:0".parse().unwrap()).unwrap();
	let addr = endpoint.local_addr().unwrap();
	tokio::spawn(async move {
		while let Some(incoming) = endpoint.accept().await {
			tokio::spawn(async move {
				let Ok(conn) = incoming.await else { return };
				while let Ok((mut send, mut recv)) = conn.accept_bi().await {
					let Ok(data) = recv.read_to_end(64 * 1024).await else { return };
					let _ = send.write_all(&[b"Q:".as_slice(), &data].concat()).await;
					let _ = send.finish();
				}
			});
		}
	});
	addr
}

/// `tls.mode: sni` (#130): the QUIC handshake relayed to the backend completes.
#[tokio::test]
async fn quic_by_server_name_answers_from_the_address_sent_to() {
	let pki = Pki::new("udp-source-sni");
	let backend = quic_backend(&pki.server("q", &["q.test"])).await;
	let h = harness().await;
	let port = create(&h, "0.0.0.0", |p| {
		let mut r = rule("udp", p, backend);
		r["tls"] = json!({"mode": "sni", "routes": [{"server_name": "q.test", "remote_addr": backend.ip().to_string(), "remote_port": backend.port()}]});
		r
	}, false)
	.await;
	let to = SocketAddr::new(TO, port);
	let endpoint = quic_endpoint(client_tls(&pki, b"echo"), to);
	let conn = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(to, "q.test").unwrap())
		.await
		.expect("QUIC handshake timed out: replies came from another address")
		.unwrap();
	let (mut send, mut recv) = conn.open_bi().await.unwrap();
	send.write_all(b"m").await.unwrap();
	send.finish().unwrap();
	let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024)).await.unwrap().unwrap();
	assert_eq!(reply, b"Q:m");
}

async fn http_backend() -> SocketAddr {
	let app = axum::Router::new().fallback(|| async { "h3 ok" });
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

/// HTTP/3 (`http.http3`) on a wildcard address: quinn's endpoint answers from
/// the address the client used.
#[tokio::test]
async fn http3_answers_from_the_address_sent_to() {
	let pki = Pki::new("udp-source-h3");
	let cert = pki.server("front", &["a.test"]);
	let backend = http_backend().await;
	let h = harness().await;
	let port = create(&h, "0.0.0.0", |p| json!({
		"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": p,
		"tls": {"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]},
		"http": {"http3": true, "routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}")}]},
	}), true)
	.await;
	let (_, v) = h.get(&format!("/rules/tcp/0.0.0.0/{port}")).await;
	assert_eq!(v["stats"]["http"]["http3"], json!({"listening": true}), "{v}");
	let to = SocketAddr::new(TO, port);
	let endpoint = quic_endpoint(client_tls(&pki, b"h3"), to);
	let conn = tokio::time::timeout(Duration::from_secs(5), endpoint.connect(to, "a.test").unwrap())
		.await
		.expect("QUIC handshake timed out: replies came from another address")
		.unwrap();
	let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
	tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
	let req = hyper::Request::get("https://a.test/").body(()).unwrap();
	let mut stream = send.send_request(req).await.unwrap();
	stream.finish().await.unwrap();
	let resp = stream.recv_response().await.unwrap();
	assert_eq!(resp.status().as_u16(), 200);
	let mut out = vec![];
	while let Some(mut chunk) = stream.recv_data().await.unwrap() {
		out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
	}
	assert_eq!(out, b"h3 ok");
}
