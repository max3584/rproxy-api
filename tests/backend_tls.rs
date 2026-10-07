//! TLS towards the https:// servers of one service (#236, the Gateway API's
//! BackendTLSPolicy): its own CA and SNI name, `subject_alt_names`, a client
//! certificate, and plain-HTTP rules (no `tls` on the rule).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo};
use reqwest::StatusCode;
use rustls::server::WebPkiClientVerifier;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use common::pki::{Issued, Pki};
use common::*;

/// An HTTPS backend answering the SNI it got and the client certificate's CN as JSON;
/// with `client_ca`, it requires a client certificate from that CA.
async fn https_backend(cert: &Issued, client_ca: Option<&Pki>) -> SocketAddr {
	let provider = Arc::new(rustls::crypto::ring::default_provider());
	let builder = rustls::ServerConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions().unwrap();
	let builder = match client_ca {
		Some(ca) => builder.with_client_cert_verifier(WebPkiClientVerifier::builder_with_provider(Arc::new(ca.roots()), provider).build().unwrap()),
		None => builder.with_no_client_auth(),
	};
	let mut config = builder.with_single_cert(cert.full_chain(), cert.key_der()).unwrap();
	config.alpn_protocols = vec![b"http/1.1".to_vec()];
	let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let Ok((tcp, _)) = listener.accept().await else { return };
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				let Ok(tls) = acceptor.accept(tcp).await else { return };
				let sni = tls.get_ref().1.server_name().unwrap_or("").to_string();
				let client = tls
					.get_ref()
					.1
					.peer_certificates()
					.and_then(|c| c.first().map(|c| rproxy_api::tls::config::common_name(c).unwrap_or_default()))
					.unwrap_or_default();
				let service = hyper::service::service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
					let body = json!({"sni": sni, "client": client}).to_string();
					async move { Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from(body)))) }
				});
				let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), service).await;
			});
		}
	});
	addr
}

async fn get(port: u16, path: &str) -> (StatusCode, Value) {
	let r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}{path}")).timeout(Duration::from_secs(10)).send().await.unwrap();
	let status = r.status();
	let text = r.text().await.unwrap();
	(status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

#[tokio::test]
async fn services_verify_their_servers_with_their_own_ca_name_and_sans() {
	let pki = Pki::new("btls");
	let other = Pki::new("btls-other");
	// a SAN URI (SPIFFE) besides the DNS name
	let cert = pki.server_with_uris("backend", &["abc.example.com"], &["spiffe://abc.example.com/test-identity"]);
	let b = https_backend(&cert, None).await;
	let h = harness().await;
	let port = free_port();
	let svc = |tls: Value| json!({"servers": [{"url": format!("https://{b}")}], "tls": tls});
	let ca = pki.ca_file.clone();
	let routes: Vec<Value> = ["ok", "wrong-ca", "wrong-name", "san-dns", "san-uri", "san-miss", "san-multi"]
		.iter()
		.map(|n| json!({"name": n, "match": format!("PathPrefix(`/{n}/`)"), "service": n}))
		.collect();
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
			"routes": routes,
			"services": {
				"ok": svc(json!({"server_name": "abc.example.com", "ca_file": ca})),
				"wrong-ca": svc(json!({"server_name": "abc.example.com", "ca_file": other.ca_file})),
				"wrong-name": svc(json!({"server_name": "dce.example.com", "ca_file": ca})),
				"san-dns": svc(json!({"server_name": "abc.example.com", "ca_file": ca, "subject_alt_names": ["abc.example.com"]})),
				"san-uri": svc(json!({"server_name": "abc.example.com", "ca_file": ca, "subject_alt_names": ["spiffe://abc.example.com/test-identity"]})),
				"san-miss": svc(json!({"server_name": "abc.example.com", "ca_file": ca, "subject_alt_names": ["dce.example.com", "spiffe://abc.example.com/other"]})),
				"san-multi": svc(json!({"server_name": "abc.example.com", "ca_file": ca, "subject_alt_names": ["dce.example.com", "spiffe://abc.example.com/test-identity"]})),
			},
		}}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v) = get(port, "/ok/").await;
	assert_eq!((status, v["sni"].as_str()), (StatusCode::OK, Some("abc.example.com")), "a plain-HTTP rule, the service's SNI: {v}");
	for bad in ["wrong-ca", "wrong-name", "san-miss"] {
		assert_eq!(get(port, &format!("/{bad}/")).await.0, StatusCode::BAD_GATEWAY, "{bad}");
	}
	for good in ["san-dns", "san-uri", "san-multi"] {
		assert_eq!(get(port, &format!("/{good}/")).await.0, StatusCode::OK, "{good}");
	}
}

#[tokio::test]
async fn a_service_shows_its_client_certificate() {
	let pki = Pki::new("btls-mtls");
	let cert = pki.server("backend", &["backend.test"]);
	let client = pki.client("client", "rproxy-client");
	let b = https_backend(&cert, Some(&pki)).await;
	let h = harness().await;
	let port = free_port();
	let tls = |with_cert: bool| {
		let mut t = json!({"server_name": "backend.test", "ca_file": pki.ca_file});
		if with_cert {
			t["cert_file"] = json!(client.cert_file);
			t["key_file"] = json!(client.key_file);
		}
		t
	};
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
			"routes": [{"name": "a", "match": "PathPrefix(`/a/`)", "service": "a"}, {"name": "n", "match": "PathPrefix(`/n/`)", "service": "n"}],
			"services": {"a": {"servers": [{"url": format!("https://{b}")}], "tls": tls(true)}, "n": {"servers": [{"url": format!("https://{b}")}], "tls": tls(false)}},
		}}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v) = get(port, "/a/").await;
	assert_eq!((status, v["client"].as_str()), (StatusCode::OK, Some("rproxy-client")), "{v}");
	assert_eq!(get(port, "/n/").await.0, StatusCode::BAD_GATEWAY, "without the client certificate");

	// shapes and files
	for (tls, want) in [
		(json!({"cert_file": client.cert_file}), "together"),
		(json!({"ca_file": "/nonexistent/ca.pem"}), "ca.pem"),
		(json!({"server_name": "not a name"}), "server_name"),
	] {
		let (status, v) = h
			.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
				"routes": [{"name": "a", "match": "PathPrefix(`/`)", "service": "a"}],
				"services": {"a": {"servers": [{"url": format!("https://{b}")}], "tls": tls}}}}))
			.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
		assert!(v["error"].as_str().unwrap().contains(want), "{want}: {v}");
	}
}
