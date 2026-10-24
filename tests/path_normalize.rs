//! The request target before routing (#320): paths normalised like Traefik's
//! `sanitizePath` and hosts without a trailing dot, so an authentication or
//! `ip_allow` route cannot be slipped past over HTTP/1.1, HTTP/2 or HTTP/3;
//! identity headers of the rule's authentication middlewares dropped from every
//! request; and the time limits of client connections (`global.http.timeouts`).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use reqwest::StatusCode;
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::pki::Pki;
use common::*;

type ClientBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

/// A backend answering with what it received: the request target, the headers and the body length.
async fn echo() -> SocketAddr {
	let app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
		let (parts, body) = req.into_parts();
		let len = axum::body::to_bytes(body, 64 << 20).await.map(|b| b.len() as i64).unwrap_or(-1);
		let headers: serde_json::Map<String, Value> = parts
			.headers
			.iter()
			.map(|(k, v)| {
				(
					k.as_str().to_string(),
					Value::String(String::from_utf8_lossy(v.as_bytes()).into_owned()),
				)
			})
			.collect();
		axum::Json(json!({"uri": parts.uri.to_string(), "headers": headers, "body_len": len}))
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

fn free_tcp_udp_port() -> u16 {
	loop {
		let port = free_port();
		if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
			return port;
		}
	}
}

/// `/admin` (and the host admin.test) refused by `ip_allow` (nobody is in 192.0.2.0/24);
/// everything else reaches the echo backend.
fn guarded_http(backend: SocketAddr, raw_path: bool) -> Value {
	let to = format!("http://{backend}");
	json!({
		"http3": true,
		"raw_path": raw_path,
		"routes": [
			{"name": "admin", "match": "PathPrefix(`/admin`)", "to": to, "middlewares": ["nobody"]},
			{"name": "admin-host", "match": "Host(`admin.test`)", "to": to, "middlewares": ["nobody"], "priority": 1000},
			{"name": "open", "match": "PathPrefix(`/`)", "to": to},
		],
		"middlewares": {"nobody": {"ip_allow": {"source_range": ["192.0.2.0/24"]}}},
	})
}

struct Tls {
	pki: Pki,
	port: u16,
	_h: Harness,
}

async fn tls_rule(tag: &str, raw_path: bool) -> Tls {
	let pki = Pki::new(tag);
	let cert = pki.server("front", &["a.test", "admin.test"]);
	let h = harness().await;
	let port = free_tcp_udp_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"tls": {"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]},
			"http": guarded_http(echo().await, raw_path),
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	Tls { pki, port, _h: h }
}

impl Tls {
	async fn connect(&self, alpn: &[&str]) -> tokio_rustls::client::TlsStream<TcpStream> {
		let tcp = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
		self.pki
			.connector_alpn(None, alpn)
			.connect(ServerName::try_from("a.test").unwrap(), tcp)
			.await
			.unwrap()
	}

	/// HTTP/1.1 with the request target and Host as written.
	async fn h1(&self, target: &str, host: &str) -> (u16, Option<Value>) {
		let mut s = self.connect(&["http/1.1"]).await;
		s.write_all(format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
			.await
			.unwrap();
		let mut out = vec![];
		let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
		parse_h1(&out)
	}

	async fn h2(&self) -> hyper::client::conn::http2::SendRequest<ClientBody> {
		let tls = self.connect(&["h2"]).await;
		let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
			.await
			.unwrap();
		tokio::spawn(conn);
		sender
	}

	async fn h3(&self) -> (h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, quinn::Endpoint) {
		let provider = Arc::new(rustls::crypto::ring::default_provider());
		let mut tls = rustls::ClientConfig::builder_with_provider(provider)
			.with_protocol_versions(&[&rustls::version::TLS13])
			.unwrap()
			.with_root_certificates(self.pki.roots())
			.with_no_client_auth();
		tls.alpn_protocols = vec![b"h3".to_vec()];
		let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
		let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
		let conn = endpoint
			.connect(SocketAddr::from(([127, 0, 0, 1], self.port)), "a.test")
			.unwrap()
			.await
			.unwrap();
		let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
		tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
		(send, endpoint)
	}
}

fn parse_h1(resp: &[u8]) -> (u16, Option<Value>) {
	let text = String::from_utf8_lossy(resp);
	let status = text.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
	let body = text.find('{').and_then(|start| text.rfind('}').map(|end| &text[start..=end]));
	(status, body.and_then(|b| serde_json::from_str(b).ok()))
}

fn empty() -> ClientBody {
	Empty::new().map_err(|never| match never {}).boxed()
}

async fn h2_get(sender: &mut hyper::client::conn::http2::SendRequest<ClientBody>, uri: &str) -> (u16, Option<Value>) {
	let resp = sender.send_request(hyper::Request::get(uri).body(empty()).unwrap()).await.unwrap();
	let status = resp.status().as_u16();
	let body = resp.into_body().collect().await.unwrap().to_bytes();
	(status, serde_json::from_slice(&body).ok())
}

async fn h3_get(send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, uri: &str) -> (u16, Option<Value>) {
	let mut stream = send.send_request(hyper::Request::get(uri).body(()).unwrap()).await.unwrap();
	stream.finish().await.unwrap();
	let resp = stream.recv_response().await.unwrap();
	let mut out = vec![];
	while let Some(mut chunk) = stream.recv_data().await.unwrap() {
		out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
	}
	(resp.status().as_u16(), serde_json::from_slice(&out).ok())
}

/// Request targets that are `/admin` once normalised.
const BYPASSES: [&str; 7] = [
	"/%61dmin",
	"/%61%64%6D%69%6E/x",
	"//admin",
	"/x/../admin",
	"/admin/.",
	"/x/%2e%2e/admin",
	"/./admin",
];

#[tokio::test]
async fn normalised_paths_reach_the_guarded_route_on_every_protocol() {
	let s = tls_rule("pn-bypass", false).await;
	let (mut h3, _ep) = s.h3().await;
	let mut h2 = s.h2().await;
	for target in BYPASSES {
		assert_eq!(s.h1(target, "a.test").await.0, 403, "HTTP/1.1 {target}");
		assert_eq!(h2_get(&mut h2, &format!("https://a.test{target}")).await.0, 403, "HTTP/2 {target}");
		assert_eq!(h3_get(&mut h3, &format!("https://a.test{target}")).await.0, 403, "HTTP/3 {target}");
	}
	// a trailing dot or capitals in the host: still admin.test
	assert_eq!(s.h1("/", "admin.test.").await.0, 403);
	assert_eq!(s.h1("/", "ADMIN.test.:443").await.0, 403);
	assert_eq!(h2_get(&mut h2, "https://admin.test./").await.0, 403);
	assert_eq!(h3_get(&mut h3, "https://admin.test./").await.0, 403);
	// what is not /admin still passes, and the backend gets the normalised path with the query as sent
	let (status, v) = s.h1("/x/../app//%7euser/%2fy?q=/../%2e", "a.test").await;
	assert_eq!(status, 200);
	assert_eq!(v.unwrap()["uri"], "/app/~user/%2Fy?q=/../%2e");
	let (status, v) = h2_get(&mut h2, "https://a.test/%61pp/./x/").await;
	assert_eq!(status, 200);
	assert_eq!(v.unwrap()["uri"], "/app/x/");
	let (status, v) = h3_get(&mut h3, "https://a.test//app/../app2").await;
	assert_eq!(status, 200);
	assert_eq!(v.unwrap()["uri"], "/app2");
	// `..` above the root stays at the root; the host sent goes to the backend as it was
	let (status, v) = s.h1("/../../etc/passwd", "A.Test.").await;
	assert_eq!(status, 200);
	let v = v.unwrap();
	assert_eq!(v["uri"], "/etc/passwd");
	assert_eq!(v["headers"]["host"], "A.Test.");
	// a broken percent-encoding is refused
	assert_eq!(s.h1("/a%zz", "a.test").await.0, 400);
	assert_eq!(h2_get(&mut h2, "https://a.test/a%2").await.0, 400);
	assert_eq!(h3_get(&mut h3, "https://a.test/%").await.0, 400);
}

#[tokio::test]
async fn raw_path_keeps_the_path_as_sent() {
	let s = tls_rule("pn-raw", true).await;
	// unsafe by design: the escape does not match PathPrefix(`/admin`)
	let (status, v) = s.h1("/%61dmin//x/../y", "a.test").await;
	assert_eq!(status, 200);
	assert_eq!(v.unwrap()["uri"], "/%61dmin//x/../y");
	assert_eq!(s.h1("/admin", "a.test").await.0, 403);
	// the host is normalised all the same
	assert_eq!(s.h1("/", "admin.test.").await.0, 403);
}

#[tokio::test]
async fn identity_headers_of_authentication_middlewares_are_dropped_on_every_route() {
	let dir = std::env::temp_dir().join(format!("rproxy-pn-identity-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	rproxy_api::net::files::private_umask();
	let users = dir.join("users");
	std::fs::write(&users, format!("alice:{}\n", bcrypt::hash("wonderland", 4).unwrap())).unwrap();
	let backend = echo().await;
	let h = harness().await;
	let port = free_port();
	let to = format!("http://{backend}");
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"routes": [
					{"name": "admin", "match": "PathPrefix(`/admin`)", "to": to, "middlewares": ["basic"]},
					{"name": "sso", "match": "PathPrefix(`/sso`)", "to": to, "middlewares": ["fa"]},
					{"name": "open", "match": "PathPrefix(`/`)", "to": to},
				],
				"middlewares": {
					"basic": {"basic_auth": {"users_file": users, "user_header": "X-Forwarded-User"}},
					"fa": {"forward_auth": {"address": "http://127.0.0.1:1/auth", "request_headers": ["X-Token", "Cookie"],
						"response_headers": ["X-Auth-Request-Email", "X-Token", "Authorization"]}},
				},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let client = reqwest::Client::new();
	let resp = client
		.get(format!("http://127.0.0.1:{port}/public"))
		.header("X-Forwarded-User", "root")
		.header("X-Auth-Request-Email", "root@example.test")
		.header("X-Token", "t0k3n")
		.header("Authorization", "Bearer abc")
		.header("X-Other", "kept")
		.send()
		.await
		.unwrap();
	assert_eq!(resp.status(), StatusCode::OK);
	let v: Value = resp.json().await.unwrap();
	let headers = &v["headers"];
	assert!(headers.get("x-forwarded-user").is_none(), "{v}");
	assert!(headers.get("x-auth-request-email").is_none(), "{v}");
	// what the client sends to authenticate stays
	assert_eq!(headers["x-token"], "t0k3n");
	assert_eq!(headers["authorization"], "Bearer abc");
	assert_eq!(headers["x-other"], "kept");
	// through basic_auth the header is rproxy's
	let resp = client
		.get(format!("http://127.0.0.1:{port}/admin"))
		.basic_auth("alice", Some("wonderland"))
		.header("X-Forwarded-User", "root")
		.send()
		.await
		.unwrap();
	let v: Value = resp.json().await.unwrap();
	assert_eq!(v["headers"]["x-forwarded-user"], "alice");
}

/// A plain `http` rule with short time limits.
async fn limited(tag: &str, spec: Value) -> (u16, Harness) {
	let spec: rproxy_api::l7::timeouts::HttpTimeoutsSpec = serde_json::from_value(spec).unwrap();
	spec.check().unwrap();
	let global = rproxy_api::l7::access::HttpGlobal::default().with_timeouts(spec.resolve());
	let h = harness_with_global(rproxy_api::control::auth::Tokens::disabled(), global).await;
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {"routes": [{"name": tag, "match": "PathPrefix(`/`)", "to": format!("http://{}", echo().await)}]},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	(port, h)
}

/// Waits for the peer to close; how long it took.
async fn closed_after(s: &mut TcpStream, most: Duration) -> Duration {
	let started = Instant::now();
	let mut buf = [0u8; 1024];
	loop {
		match tokio::time::timeout(most, s.read(&mut buf)).await {
			Ok(Ok(0)) | Ok(Err(_)) => return started.elapsed(),
			Ok(Ok(_)) => continue,
			Err(_) => panic!("still open after {most:?}"),
		}
	}
}

#[tokio::test]
async fn silent_and_slow_header_connections_are_closed() {
	let (port, _h) = limited("slow", json!({"first_byte": "300ms", "request_headers": "800ms", "idle": "5s"})).await;
	// nothing at all: first_byte
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let t = closed_after(&mut s, Duration::from_secs(5)).await;
	assert!(t < Duration::from_millis(1500), "{t:?}");
	// headers a byte at a time (slowloris): request_headers, although bytes keep coming
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let started = Instant::now();
	let drip = async {
		for b in b"GET / HTTP/1.1\r\nHost: a.test\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			.iter()
			.cycle()
		{
			if s.write_all(&[*b]).await.is_err() {
				break;
			}
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	};
	let _ = tokio::time::timeout(Duration::from_secs(5), drip).await;
	assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
	// HTTP/2 preface only, then nothing: request_headers
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
	let t = closed_after(&mut s, Duration::from_secs(5)).await;
	assert!(t < Duration::from_secs(3), "{t:?}");
}

#[tokio::test]
async fn idle_http2_connections_are_closed_after_their_last_request() {
	let (port, _h) = limited("idle", json!({"idle": "700ms"})).await;
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
		.await
		.unwrap();
	let conn = tokio::spawn(conn);
	// a request that takes longer than `idle` is not cut
	let slow = StreamBody::new(futures_util::stream::unfold(0, |i| async move {
		if i == 4 {
			return None;
		}
		tokio::time::sleep(Duration::from_millis(400)).await;
		Some((Ok::<_, std::io::Error>(Frame::data(Bytes::from_static(b"0123456789"))), i + 1))
	}));
	let resp = sender
		.send_request(hyper::Request::post("http://a.test/up").body(slow.boxed()).unwrap())
		.await
		.unwrap();
	assert_eq!(resp.status(), 200);
	let v: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
	assert_eq!(v["body_len"], 40);
	// then nothing: the connection goes
	let started = Instant::now();
	let _ = tokio::time::timeout(Duration::from_secs(5), conn).await.expect("closed by rproxy");
	assert!(started.elapsed() >= Duration::from_millis(500), "{:?}", started.elapsed());
}

#[tokio::test]
async fn a_slow_upload_passes_and_a_silent_one_is_cut() {
	let (port, _h) = limited(
		"upload",
		json!({"request_body_idle": "600ms", "request_headers": "1s", "idle": "1s"}),
	)
	.await;
	// 12 chunks 300 ms apart: far longer than every limit, never silent for 600 ms
	let chunks = StreamBody::new(futures_util::stream::unfold(0, |i| async move {
		if i == 12 {
			return None;
		}
		tokio::time::sleep(Duration::from_millis(300)).await;
		Some((Ok::<_, std::io::Error>(Frame::data(Bytes::from(vec![b'x'; 1000]))), i + 1))
	}));
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, ClientBody>(TokioIo::new(tcp))
		.await
		.unwrap();
	tokio::spawn(conn);
	let req = hyper::Request::post("/upload")
		.header("host", "a.test")
		.body(chunks.boxed())
		.unwrap();
	let resp = sender.send_request(req).await.unwrap();
	assert_eq!(resp.status(), 200);
	let v: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
	assert_eq!(v["body_len"], 12_000);
	// a body that stops: cut after request_body_idle, never passed on as complete
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"POST /upload HTTP/1.1\r\nHost: a.test\r\nContent-Length: 1000\r\n\r\n0123456789")
		.await
		.unwrap();
	let started = Instant::now();
	let mut out = vec![];
	let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
	assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
	let (status, body) = parse_h1(&out);
	assert!(
		status != 200 || body.is_some_and(|v| v["body_len"] != 1000),
		"{}",
		String::from_utf8_lossy(&out)
	);
}
