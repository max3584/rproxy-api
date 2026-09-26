//! HTTP/3 (QUIC) on `http` rules with `http3: true` (#56), with a quinn + h3 client.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use reqwest::StatusCode;
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};

use common::pki::{Issued, Pki};
use common::*;

/// An HTTP backend answering with what it received.
async fn backend(tag: &'static str) -> SocketAddr {
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| async move {
		let (parts, body) = req.into_parts();
		let body = axum::body::to_bytes(body, 1 << 20).await.unwrap_or_default();
		let h = |n: &str| parts.headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		axum::Json(json!({
			"tag": tag, "method": parts.method.as_str(), "uri": parts.uri.to_string(), "host": h("host"),
			"proto": h("x-forwarded-proto"), "body": String::from_utf8_lossy(&body),
		}))
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

/// A port free for both TCP and UDP.
fn free_tcp_udp_port() -> u16 {
	loop {
		let port = free_port();
		if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
			return port;
		}
	}
}

fn h3_rule(port: u16, cert: &Issued, to: SocketAddr) -> Value {
	json!({
		"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
		"tls": {"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]},
		"http": {"http3": true, "routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{to}")}]},
	})
}

type H3Send = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Connects over QUIC and HTTP/3, verifying the server as `name`.
async fn h3_connect(pki: &Pki, port: u16, name: &str) -> Result<(H3Send, quinn::Endpoint), String> {
	let provider = Arc::new(rustls::crypto::ring::default_provider());
	let mut tls = rustls::ClientConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13])
		.unwrap()
		.with_root_certificates(pki.roots())
		.with_no_client_auth();
	tls.alpn_protocols = vec![b"h3".to_vec()];
	let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
	let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
	endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
	let connecting = endpoint.connect(SocketAddr::from(([127, 0, 0, 1], port)), name).map_err(|e| e.to_string())?;
	let conn = tokio::time::timeout(Duration::from_secs(5), connecting)
		.await
		.map_err(|_| "QUIC handshake timed out".to_string())?
		.map_err(|e| e.to_string())?;
	let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await.map_err(|e| e.to_string())?;
	tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
	Ok((send, endpoint))
}

/// One HTTP/3 request; the response status and body.
async fn h3_request(send: &mut H3Send, method: &str, url: &str, body: &[u8]) -> (StatusCode, Value) {
	let req = hyper::Request::builder().method(method).uri(url).body(()).unwrap();
	let mut stream = send.send_request(req).await.unwrap();
	if !body.is_empty() {
		stream.send_data(Bytes::copy_from_slice(body)).await.unwrap();
	}
	stream.finish().await.unwrap();
	let resp = stream.recv_response().await.unwrap();
	let mut out = vec![];
	while let Some(mut chunk) = stream.recv_data().await.unwrap() {
		out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
	}
	let status = StatusCode::from_u16(resp.status().as_u16()).unwrap();
	(status, serde_json::from_slice(&out).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&out).into())))
}

/// An HTTPS/1.1 request over TCP; the response headers.
async fn https_head(pki: &Pki, port: u16) -> hyper::HeaderMap {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let tls = pki.connector_alpn(None, &["http/1.1"]).connect(ServerName::try_from("a.test").unwrap(), tcp).await.unwrap();
	let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
	tokio::spawn(conn);
	let req = hyper::Request::get("/tcp").header("host", "a.test").body(Empty::<Bytes>::new()).unwrap();
	let resp = sender.send_request(req).await.unwrap();
	let headers = resp.headers().clone();
	let _ = resp.into_body().collect().await;
	headers
}

#[tokio::test]
async fn http3_answers_on_the_same_port() {
	let pki = Pki::new("h3");
	let cert = pki.server("front", &["a.test"]);
	let (a, b) = (backend("A").await, backend("B").await);
	let h = harness().await;
	let port = free_tcp_udp_port();
	let (status, v) = h.post(h3_rule(port, &cert, a)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["stats"]["http"]["http3"], json!({"listening": true}), "{v}");

	let (mut send, _ep) = h3_connect(&pki, port, "a.test").await.unwrap();
	let (status, v) = h3_request(&mut send, "GET", "https://a.test/hello?x=1", b"").await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!((v["tag"].as_str(), v["uri"].as_str(), v["host"].as_str(), v["proto"].as_str()), (Some("A"), Some("/hello?x=1"), Some("a.test"), Some("https")), "{v}");
	let (status, v) = h3_request(&mut send, "POST", "https://a.test/upload", b"posted over QUIC").await;
	assert_eq!((status, v["method"].as_str(), v["body"].as_str()), (StatusCode::OK, Some("POST"), Some("posted over QUIC")), "{v}");

	// HTTP/1.1 and HTTP/2 over TCP are told about HTTP/3
	let headers = https_head(&pki, port).await;
	assert_eq!(headers["alt-svc"], format!("h3=\":{port}\"; ma=86400"));

	// PATCH applies to HTTP/3 too
	let (status, v) = h
		.patch(&format!("tcp/127.0.0.1/{port}"), json!({"http": {"http3": true, "routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{b}")}]}}))
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(h3_request(&mut send, "GET", "https://a.test/", b"").await.1["tag"], "B");

	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert!(v["stats"]["http"]["requests"].as_u64().unwrap() >= 4, "{v}");

	// turning http3 off closes the QUIC side
	let (status, v) = h
		.patch(&format!("tcp/127.0.0.1/{port}"), json!({"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{b}")}]}}))
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(v["stats"]["http"].get("http3").is_none(), "{v}");
	assert!(https_head(&pki, port).await.get("alt-svc").is_none());
	wait_udp_free(port).await;

	// and on again
	let (status, v) = h
		.patch(&format!("tcp/127.0.0.1/{port}"), json!({"http": {"http3": true, "routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{a}")}]}}))
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let (mut send, _ep) = h3_connect(&pki, port, "a.test").await.unwrap();
	assert_eq!(h3_request(&mut send, "GET", "https://a.test/", b"").await.1["tag"], "A");

	// deleting the rule closes the UDP port
	assert_eq!(h.delete(&format!("tcp/127.0.0.1/{port}")).await, StatusCode::NO_CONTENT);
	wait_udp_free(port).await;
}

async fn wait_udp_free(port: u16) {
	for _ in 0..50 {
		if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
			return;
		}
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	panic!("udp port {port} is still in use");
}

#[tokio::test]
async fn http3_follows_allow_from_and_renewed_certificates() {
	let pki = Pki::new("h3-renew");
	let cert = pki.server("front", &["old.test"]);
	let a = backend("A").await;
	let h = harness().await;

	// clients outside allow_from are refused before the handshake
	let port = free_tcp_udp_port();
	let mut body = h3_rule(port, &cert, a);
	body["allow_from"] = json!(["10.9.9.9"]);
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);
	assert!(h3_connect(&pki, port, "old.test").await.is_err());
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert!(v["stats"]["denied"].as_u64().unwrap() >= 1, "{v}");

	let port = free_tcp_udp_port();
	assert_eq!(h.post(h3_rule(port, &cert, a)).await.0, StatusCode::CREATED);
	let (mut send, _ep) = h3_connect(&pki, port, "old.test").await.unwrap();
	assert_eq!(h3_request(&mut send, "GET", "https://old.test/", b"").await.0, StatusCode::OK);
	assert!(h3_connect(&pki, port, "new.test").await.is_err(), "not in the certificate yet");

	// renewed in place, as certbot would; QUIC picks it up like TCP
	let renewed = pki.server("front", &["new.test"]);
	assert_eq!(renewed.cert_file, cert.cert_file);
	let (ok, _) = h.registry.reload_tls().await;
	assert!(ok >= 1);
	let (mut send, _ep) = h3_connect(&pki, port, "new.test").await.unwrap();
	assert_eq!(h3_request(&mut send, "GET", "https://new.test/", b"").await.0, StatusCode::OK);
}

#[tokio::test]
async fn http3_needs_tls_and_a_free_udp_port() {
	let pki = Pki::new("h3-busy");
	let cert = pki.server("front", &["a.test"]);
	let a = backend("A").await;
	let h = harness().await;

	let mut plain = h3_rule(free_tcp_udp_port(), &cert, a);
	plain.as_object_mut().unwrap().remove("tls");
	let (status, v) = h.post(plain).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");

	// the UDP port is taken: the rule runs over TCP and says why HTTP/3 does not
	let port = free_tcp_udp_port();
	let _taken = std::net::UdpSocket::bind(("127.0.0.1", port)).unwrap();
	let (status, v) = h.post(h3_rule(port, &cert, a)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["state"], "running");
	assert_eq!(v["stats"]["http"]["http3"]["listening"], false, "{v}");
	assert!(v["stats"]["http"]["http3"]["error"].as_str().unwrap().contains("udp"), "{v}");
	assert!(https_head(&pki, port).await.get("alt-svc").is_none(), "no Alt-Svc while HTTP/3 is not answered");
}

/// The authentication middlewares run for HTTP/3 requests too (the same handler).
#[tokio::test]
async fn http3_requests_go_through_basic_auth() {
	let pki = Pki::new("h3-auth");
	let cert = pki.server("front", &["a.test"]);
	let users = std::path::Path::new(&cert.cert_file).with_file_name("users");
	std::fs::write(&users, format!("alice:{}\n", bcrypt::hash("pw", 4).unwrap())).unwrap();
	let h = harness().await;
	let port = free_tcp_udp_port();
	let mut rule = h3_rule(port, &cert, backend("A").await);
	rule["http"]["routes"][0]["middlewares"] = json!(["auth"]);
	rule["http"]["middlewares"] = json!({"auth": {"basic_auth": {"users_file": users}}});
	let (status, v) = h.post(rule).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (mut send, _ep) = h3_connect(&pki, port, "a.test").await.unwrap();
	assert_eq!(h3_request(&mut send, "GET", "https://a.test/x", b"").await.0, StatusCode::UNAUTHORIZED);
	let auth = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "alice:pw"));
	let req = hyper::Request::get("https://a.test/x").header("authorization", auth).body(()).unwrap();
	let mut stream = send.send_request(req).await.unwrap();
	stream.finish().await.unwrap();
	assert_eq!(stream.recv_response().await.unwrap().status().as_u16(), 200);
}
