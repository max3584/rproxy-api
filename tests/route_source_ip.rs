//! `source_ip` of `tls.routes[]` (#297): a route relayed at L4 (a `passthrough`
//! route of `terminate`, a route of `sni`) passes the client's address on in its
//! own way, while the rest of the rule keeps the rule's `source_ip`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use common::pki::Pki;
use common::*;
use rproxy_api::net::source::{proxy_v1_header, proxy_v2_dgram_header, proxy_v2_header};

fn local(port: u16) -> SocketAddr {
	SocketAddr::from(([127, 0, 0, 1], port))
}

/// A backend that only records: the first bytes of the next connection it accepts.
async fn next_bytes(backend: &TcpListener, at_least: usize) -> Vec<u8> {
	let (mut s, _) = tokio::time::timeout(Duration::from_secs(5), backend.accept()).await.expect("no connection").unwrap();
	let mut got = Vec::new();
	let mut buf = [0u8; 4096];
	while got.len() < at_least {
		let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.expect("no data").unwrap();
		if n == 0 {
			break;
		}
		got.extend_from_slice(&buf[..n]);
	}
	got
}

/// Starts a TLS handshake as `name` towards rproxy's `port` (left unfinished: the
/// recording backends do not answer); the client's own address.
async fn hello(pki: &Pki, port: u16, name: &str) -> SocketAddr {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let me = tcp.local_addr().unwrap();
	let connector = pki.connector(None);
	let name = name.to_string();
	tokio::spawn(async move {
		let _ = tokio::time::timeout(Duration::from_secs(5), connector.connect(name.try_into().unwrap(), tcp)).await;
	});
	me
}

/// `got` starts with `header` and then a TLS handshake record (the ClientHello as sent).
fn assert_header_then_hello(got: &[u8], header: &[u8], what: &str) {
	assert!(got.len() > header.len(), "{what}: {} bytes", got.len());
	assert_eq!(&got[..header.len()], header, "{what}: the PROXY header");
	assert_eq!(got[header.len()], 0x16, "{what}: then the ClientHello");
}

/// An `http` rule on one port: the L7 route's backend gets plain HTTP (no header),
/// the passthrough route with `source_ip: proxy_v2` gets a v2 header with the client.
#[tokio::test]
async fn a_passthrough_route_of_an_http_rule_sends_proxy_v2_and_l7_does_not() {
	let pki = Pki::new("route-sip-http");
	let front = pki.server("front", &["cdn.test"]);
	let passed = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let l7 = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let l7_addr = l7.local_addr().unwrap();
	let h = harness().await;
	let port = free_port();
	let body = json!({
		"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
		"tls": {
			"mode": "terminate",
			"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
			"routes": [{"server_names": ["**.tenant.test"], "remote_addr": "127.0.0.1",
				"remote_port": passed.local_addr().unwrap().port(), "passthrough": true, "source_ip": "proxy_v2"}],
		},
		"http": {
			"routes": [{"name": "cdn", "match": "Host(`cdn.test`)", "service": "s"}],
			"services": {"s": {"servers": [{"url": format!("http://{l7_addr}")}]}},
		},
	});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["tls"]["routes"][0]["source_ip"], "proxy_v2", "{v}");
	assert_eq!(v["source_ip"], "proxy", "the rule's own is unchanged: {v}");

	// the passthrough name: header, then the ClientHello untouched
	let me = hello(&pki, port, "a.tenant.test").await;
	let got = next_bytes(&passed, proxy_v2_header(me, local(port)).len() + 1).await;
	assert_header_then_hello(&got, &proxy_v2_header(me, local(port)), "passthrough route");

	// the L7 name: terminated by rproxy, plain HTTP to the service without a header
	let pki2 = pki.connector(None);
	let client = tokio::spawn(async move {
		let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
		let mut s = pki2.connect("cdn.test".try_into().unwrap(), tcp).await.unwrap();
		s.write_all(b"GET / HTTP/1.1\r\nHost: cdn.test\r\nConnection: close\r\n\r\n").await.unwrap();
		let mut out = Vec::new();
		let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
		String::from_utf8_lossy(&out).into_owned()
	});
	let (mut s, _) = tokio::time::timeout(Duration::from_secs(5), l7.accept()).await.unwrap().unwrap();
	let mut req = Vec::new();
	let mut buf = [0u8; 4096];
	while !req.windows(4).any(|w| w == b"\r\n\r\n") {
		let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
		assert!(n > 0, "closed before the request");
		req.extend_from_slice(&buf[..n]);
	}
	assert!(req.starts_with(b"GET / HTTP/1.1\r\n"), "no PROXY header in front: {:?}", String::from_utf8_lossy(&req));
	s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
	drop(s);
	let resp = client.await.unwrap();
	assert!(resp.starts_with("HTTP/1.1 200") && resp.ends_with("ok"), "{resp}");
}

/// A `terminate` rule with `proxy_protocol` in front (#296): the passthrough route's
/// v1 header carries the client of the incoming header, not the front end.
#[tokio::test]
async fn a_passthrough_route_passes_on_the_client_of_an_incoming_proxy_header() {
	let pki = Pki::new("route-sip-ppin");
	let front = pki.server("front", &["front.test"]);
	let passed = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let plain = tcp_backend("R:").await;
	let h = harness().await;
	let port = free_port();
	let mut body = rule("tcp", port, plain);
	body["proxy_protocol"] = json!({"from": ["127.0.0.1/32"]});
	body["tls"] = json!({
		"mode": "terminate",
		"certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}],
		"routes": [{"server_name": "registry.test", "remote_addr": "127.0.0.1",
			"remote_port": passed.local_addr().unwrap().port(), "passthrough": true, "source_ip": "proxy_v1"}],
	});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let client: SocketAddr = "192.0.2.7:4000".parse().unwrap();
	let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	tcp.write_all(&proxy_v2_header(client, "198.51.100.1:443".parse().unwrap())).await.unwrap();
	let connector = pki.connector(None);
	tokio::spawn(async move {
		let _ = tokio::time::timeout(Duration::from_secs(5), connector.connect("registry.test".try_into().unwrap(), tcp)).await;
	});
	let expected = proxy_v1_header(client, local(port));
	let got = next_bytes(&passed, expected.len() + 1).await;
	assert_header_then_hello(&got, &expected, "the client of the incoming header");
}

/// A `sni` rule: each route may override the rule's `source_ip`, the others keep it.
#[tokio::test]
async fn routes_of_an_sni_rule_override_the_rules_source_ip() {
	let pki = Pki::new("route-sip-sni");
	let (none, v1, inherit, default) = (
		TcpListener::bind("127.0.0.1:0").await.unwrap(),
		TcpListener::bind("127.0.0.1:0").await.unwrap(),
		TcpListener::bind("127.0.0.1:0").await.unwrap(),
		TcpListener::bind("127.0.0.1:0").await.unwrap(),
	);
	let to = |l: &TcpListener| l.local_addr().unwrap().port();
	let h = harness().await;
	let port = free_port();
	let mut body = rule("tcp", port, default.local_addr().unwrap());
	body["source_ip"] = json!("proxy_v2");
	body["tls"] = json!({"mode": "sni", "routes": [
		{"server_name": "none.test", "remote_addr": "127.0.0.1", "remote_port": to(&none), "source_ip": "proxy"},
		{"server_name": "v1.test", "remote_addr": "127.0.0.1", "remote_port": to(&v1), "source_ip": "proxy_v1"},
		{"server_name": "inherit.test", "remote_addr": "127.0.0.1", "remote_port": to(&inherit)},
	]});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(v["tls"]["routes"][2].get("source_ip").is_none(), "left out stays out: {v}");

	let me = hello(&pki, port, "none.test").await;
	let got = next_bytes(&none, 1).await;
	assert_eq!(got[0], 0x16, "source_ip proxy: the ClientHello first ({me})");
	let me = hello(&pki, port, "v1.test").await;
	let header = proxy_v1_header(me, local(port));
	assert_header_then_hello(&next_bytes(&v1, header.len() + 1).await, &header, "proxy_v1 route");
	let me = hello(&pki, port, "inherit.test").await;
	let header = proxy_v2_header(me, local(port));
	assert_header_then_hello(&next_bytes(&inherit, header.len() + 1).await, &header, "a route without one: the rule's");
	let me = hello(&pki, port, "other.test").await;
	assert_header_then_hello(&next_bytes(&default, header.len() + 1).await, &proxy_v2_header(me, local(port)), "unmatched: the rule's");

	// PATCH changes a route's source_ip in place (from the next connection)
	let path = format!("tcp/127.0.0.1/{port}");
	let patched = json!({
		"remote_addr": "127.0.0.1", "remote_port": to(&default),
		"tls": {"mode": "sni", "routes": [
			{"server_name": "none.test", "remote_addr": "127.0.0.1", "remote_port": to(&none), "source_ip": "proxy_v2"},
		]},
	});
	let (status, v) = h.patch(&format!("{path}?dry_run=true"), patched.clone()).await;
	assert_eq!((status, v["change"].as_str()), (StatusCode::OK, Some("in_place")), "{v}");
	let (status, v) = h.patch(&path, patched).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(v["tls"]["routes"][0]["source_ip"], "proxy_v2", "{v}");
	let me = hello(&pki, port, "none.test").await;
	let header = proxy_v2_header(me, local(port));
	assert_header_then_hello(&next_bytes(&none, header.len() + 1).await, &header, "after PATCH");
}

/// udp `sni` (QUIC): a route's `proxy_v2` puts the DGRAM header in front of the
/// datagrams of that route only.
#[tokio::test]
async fn a_udp_sni_route_sends_proxy_v2_datagrams() {
	let pki = Pki::new("route-sip-quic");
	let routed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let default = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let h = harness().await;
	let port = free_udp_port();
	let mut body = rule("udp", port, default.local_addr().unwrap());
	body["tls"] = json!({"mode": "sni", "routes": [
		{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": routed.local_addr().unwrap().port(), "source_ip": "proxy_v2"},
	]});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let first_datagram = |backend: UdpSocket, name: &'static str| {
		let pki = &pki;
		async move {
			let client = quic_client(pki);
			let me = client.local_addr().unwrap();
			let connecting = client.connect(local(port), name).unwrap();
			let pending = tokio::spawn(async move {
				let _ = tokio::time::timeout(Duration::from_secs(3), connecting).await;
			});
			let mut buf = vec![0u8; 65_536];
			let n = tokio::time::timeout(Duration::from_secs(5), backend.recv(&mut buf)).await.expect("no datagram").unwrap();
			pending.abort();
			buf.truncate(n);
			(me, buf)
		}
	};
	let (me, got) = first_datagram(routed, "a.test").await;
	let header = proxy_v2_dgram_header(me, local(port));
	assert_eq!(&got[..header.len()], &header[..], "the route's proxy_v2");
	assert_eq!(got[header.len()] & 0xc0, 0xc0, "then the QUIC Initial (long header)");
	let (_, got) = first_datagram(default, "other.test").await;
	assert_eq!(got[0] & 0xc0, 0xc0, "the rule's (proxy): no header");
}

/// A QUIC client trusting the test CA.
fn quic_client(pki: &Pki) -> quinn::Endpoint {
	let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_root_certificates(pki.roots())
		.with_no_client_auth();
	tls.alpn_protocols = vec![b"echo".to_vec()];
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
	let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
	endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
	endpoint
}

#[tokio::test]
async fn route_source_ip_is_validated_and_advertised() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["route_source_ip"], true, "{caps}");
	let pki = Pki::new("route-sip-check");
	let front = pki.server("front", &["front.test"]);
	let backend = tcp_backend("B:").await;
	let terminate = |route: Value| {
		let mut body = rule("tcp", free_port(), backend);
		body["tls"] =
			json!({"mode": "terminate", "certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}], "routes": [route]});
		body
	};
	let sni = |protocol: &str, route: Value| {
		let mut body = rule(protocol, if protocol == "udp" { free_udp_port() } else { free_port() }, backend);
		body["tls"] = json!({"mode": "sni", "routes": [route]});
		body
	};
	let r = |extra: Value| {
		let mut route = json!({"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": backend.port()});
		for (k, v) in extra.as_object().unwrap() {
			route[k] = v.clone();
		}
		route
	};
	let cases: Vec<(Value, StatusCode, Option<&str>)> = vec![
		// a terminated route keeps the rule's
		(terminate(r(json!({"source_ip": "proxy_v2"}))), StatusCode::BAD_REQUEST, Some("unsupported")),
		// transparent is per rule
		(terminate(r(json!({"source_ip": "transparent", "passthrough": true}))), StatusCode::BAD_REQUEST, Some("unsupported")),
		(sni("tcp", r(json!({"source_ip": "transparent"}))), StatusCode::BAD_REQUEST, Some("unsupported")),
		// udp: v2 only
		(sni("udp", r(json!({"source_ip": "proxy_v1"}))), StatusCode::BAD_REQUEST, Some("unsupported")),
		(terminate(r(json!({"source_ip": "proxy_v2", "passthrough": true}))), StatusCode::CREATED, None),
		(sni("udp", r(json!({"source_ip": "proxy_v2"}))), StatusCode::CREATED, None),
	];
	for (body, want, code) in cases {
		let (status, v) = h.post(body.clone()).await;
		assert_eq!(status, want, "{body}: {v}");
		if let Some(code) = code {
			assert_eq!(v["code"], code, "{body}: {v}");
		}
	}
	let (status, v) = h.post(sni("tcp", r(json!({"source_ip": "proxy_v3"})))).await;
	assert!(status.is_client_error(), "an unknown name: {v}");
}
