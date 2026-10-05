//! What a reverse proxy must keep or change when it forwards HTTP: session
//! cookies, repeated fields, hop-by-hop headers, bodies, large headers and
//! timeouts, through HTTP/1.1, HTTP/2 and HTTP/3 clients (src/l7/server.rs).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::Frame;
use hyper_util::rt::{TokioExecutor, TokioIo};
use reqwest::StatusCode;
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::pki::{Issued, Pki};
use common::*;

const SET_COOKIES: [&str; 3] = [
	"_gitlab_session=abc123; path=/; secure; HttpOnly; SameSite=Lax",
	"known_sign_in=xyz; path=/; expires=Wed, 01 Oct 2031 00:00:00 GMT; secure; HttpOnly",
	"preferred_language=ja; Domain=example.test; Path=/",
];

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A backend that answers what it received, byte for byte, plus a few special paths.
async fn backend() -> SocketAddr {
	let app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
		let (parts, body) = req.into_parts();
		let path = parts.uri.path().to_string();
		match path.as_str() {
			// several Set-Cookie fields, a Location, and hop-by-hop fields that must not reach the client
			"/set-cookies" => {
				let mut resp = axum::response::Response::builder().status(302).header("location", "https://gitlab.example.test/users/sign_in?x=1");
				for c in SET_COOKIES {
					resp = resp.header("set-cookie", c);
				}
				resp.header("keep-alive", "timeout=5")
					.header("x-resp-hop", "1")
					.header("connection", "x-resp-hop")
					.header("content-type", "text/plain")
					.body(axum::body::Body::from("a".repeat(2000)))
					.unwrap()
			}
			// headers at once, then the body over about 2.4 seconds
			"/stream" => {
				let chunks = futures_util::stream::unfold(0u32, |i| async move {
					if i == 6 {
						return None;
					}
					tokio::time::sleep(Duration::from_millis(400)).await;
					Some((Ok::<_, std::io::Error>(Bytes::from(format!("chunk{i};"))), i + 1))
				});
				axum::response::Response::builder().header("content-type", "application/octet-stream").body(axum::body::Body::from_stream(chunks)).unwrap()
			}
			// the response headers only after two seconds
			"/late" => {
				tokio::time::sleep(Duration::from_secs(2)).await;
				axum::response::Response::new(axum::body::Body::from("late"))
			}
			"/head" => axum::response::Response::builder().header("content-length", "1234").header("x-head", "1").body(axum::body::Body::empty()).unwrap(),
			_ => {
				let body = axum::body::to_bytes(body, 64 << 20).await.unwrap_or_default();
				let fields: Vec<Value> = parts.headers.iter().map(|(k, v)| json!([k.as_str(), hex(v.as_bytes())])).collect();
				let v = json!({
					"method": parts.method.as_str(), "uri": parts.uri.to_string(), "fields": fields,
					"body_len": body.len(), "body_prefix": String::from_utf8_lossy(&body[..body.len().min(32)]),
				});
				axum::response::Response::builder().header("content-type", "application/json").body(axum::body::Body::from(v.to_string())).unwrap()
			}
		}
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

/// The values of `name` the backend received, as bytes, in order.
fn received(v: &Value, name: &str) -> Vec<Vec<u8>> {
	v["fields"]
		.as_array()
		.unwrap()
		.iter()
		.filter(|f| f[0] == name)
		.map(|f| (0..f[1].as_str().unwrap().len()).step_by(2).map(|i| u8::from_str_radix(&f[1].as_str().unwrap()[i..i + 2], 16).unwrap()).collect())
		.collect()
}

fn received_text(v: &Value, name: &str) -> Vec<String> {
	received(v, name).into_iter().map(|b| String::from_utf8_lossy(&b).into_owned()).collect()
}

struct Setup {
	pki: Pki,
	port: u16,
	_h: Harness,
}

/// A port free for both TCP and UDP (HTTP/3 listens on the same port).
fn free_tcp_udp_port() -> u16 {
	loop {
		let port = free_port();
		if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
			return port;
		}
	}
}

/// An `http` rule terminating TLS (HTTP/1.1, HTTP/2 and HTTP/3) in front of `backend()`,
/// with a one-second response timeout; `middlewares` apply to every request.
async fn setup(tag: &str, middlewares: Value) -> Setup {
	let pki = Pki::new(tag);
	let cert: Issued = pki.server("front", &["a.test"]);
	let b = backend().await;
	let h = harness().await;
	let port = free_tcp_udp_port();
	let names: Vec<String> = middlewares.as_object().map(|m| m.keys().cloned().collect()).unwrap_or_default();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"tls": {"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]},
			"http": {
				"http3": true,
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "service": "b", "middlewares": names}],
				"services": {"b": {"servers": [{"url": format!("http://{b}")}], "timeouts": {"response": "1s"}}},
				"middlewares": middlewares,
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	Setup { pki, port, _h: h }
}

impl Setup {
	async fn tls(&self, alpn: &[&str]) -> tokio_rustls::client::TlsStream<TcpStream> {
		let tcp = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
		self.pki.connector_alpn(None, alpn).connect(ServerName::try_from("a.test").unwrap(), tcp).await.unwrap()
	}

	/// Sends raw HTTP/1.1 bytes (ending with `Connection: close`) and returns the raw response.
	async fn h1_raw(&self, request: &[u8]) -> Vec<u8> {
		let mut s = self.tls(&["http/1.1"]).await;
		s.write_all(request).await.unwrap();
		let mut out = vec![];
		let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
		out
	}

	async fn h2(&self) -> hyper::client::conn::http2::SendRequest<http_body_util::combinators::BoxBody<Bytes, std::io::Error>> {
		let tls = self.tls(&["h2"]).await;
		assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
		let (sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
			.max_header_list_size(1 << 20)
			.handshake(TokioIo::new(tls))
			.await
			.unwrap();
		tokio::spawn(conn);
		sender
	}

	async fn h3(&self) -> (h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>, quinn::Endpoint) {
		let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
		let mut tls = rustls::ClientConfig::builder_with_provider(provider)
			.with_protocol_versions(&[&rustls::version::TLS13])
			.unwrap()
			.with_root_certificates(self.pki.roots())
			.with_no_client_auth();
		tls.alpn_protocols = vec![b"h3".to_vec()];
		let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
		let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
		endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
		let conn = endpoint.connect(SocketAddr::from(([127, 0, 0, 1], self.port)), "a.test").unwrap().await.unwrap();
		let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
		tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
		(send, endpoint)
	}
}

fn boxed(b: impl hyper::body::Body<Data = Bytes, Error = std::io::Error> + Send + Sync + 'static) -> http_body_util::combinators::BoxBody<Bytes, std::io::Error> {
	b.boxed()
}

fn empty() -> http_body_util::combinators::BoxBody<Bytes, std::io::Error> {
	boxed(Empty::new().map_err(|never| match never {}))
}

async fn h2_send(
	sender: &mut hyper::client::conn::http2::SendRequest<http_body_util::combinators::BoxBody<Bytes, std::io::Error>>,
	req: hyper::Request<http_body_util::combinators::BoxBody<Bytes, std::io::Error>>,
) -> (StatusCode, hyper::HeaderMap, Bytes) {
	let resp = sender.send_request(req).await.unwrap();
	let status = StatusCode::from_u16(resp.status().as_u16()).unwrap();
	let headers = resp.headers().clone();
	let body = resp.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
	(status, headers, body)
}

async fn h3_get(
	send: &mut h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
	req: hyper::Request<()>,
) -> (StatusCode, hyper::HeaderMap, Vec<u8>) {
	let mut stream = send.send_request(req).await.unwrap();
	stream.finish().await.unwrap();
	let resp = stream.recv_response().await.unwrap();
	let mut out = vec![];
	while let Some(mut chunk) = stream.recv_data().await.unwrap() {
		out.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
	}
	(StatusCode::from_u16(resp.status().as_u16()).unwrap(), resp.headers().clone(), out)
}

/// The header section of a raw HTTP/1.1 response, lower-cased names, in order.
fn h1_fields(resp: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
	let end = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("a complete header section");
	let head = String::from_utf8_lossy(&resp[..end]);
	let mut lines = head.split("\r\n");
	let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
	let fields = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect();
	(status, fields, resp[end + 4..].to_vec())
}

fn values<'a>(fields: &'a [(String, String)], name: &str) -> Vec<&'a str> {
	fields.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str()).collect()
}

fn json_body(body: &[u8]) -> Value {
	// a chunked HTTP/1.1 body: take the JSON between the first '{' and the last '}'
	let start = body.iter().position(|&b| b == b'{').unwrap_or(0);
	let end = body.iter().rposition(|&b| b == b'}').map(|e| e + 1).unwrap_or(body.len());
	serde_json::from_slice(&body[start..end]).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(body)))
}

#[tokio::test]
async fn set_cookie_fields_and_location_reach_the_client_untouched() {
	let s = setup("sem-setcookie", json!({})).await;

	// HTTP/1.1: three Set-Cookie lines, never joined with commas
	let resp = s.h1_raw(b"GET /set-cookies HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n").await;
	let (status, fields, _) = h1_fields(&resp);
	assert_eq!(status, 302);
	assert_eq!(values(&fields, "set-cookie"), SET_COOKIES, "{fields:?}");
	assert_eq!(values(&fields, "location"), ["https://gitlab.example.test/users/sign_in?x=1"]);
	for hop in ["x-resp-hop", "keep-alive"] {
		assert!(values(&fields, hop).is_empty(), "{hop} is hop-by-hop: {fields:?}");
	}

	// HTTP/2
	let mut h2 = s.h2().await;
	let (status, headers, _) = h2_send(&mut h2, hyper::Request::get("https://a.test/set-cookies").body(empty()).unwrap()).await;
	assert_eq!(status, StatusCode::FOUND);
	let got: Vec<&str> = headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).collect();
	assert_eq!(got, SET_COOKIES);
	assert!(!headers.contains_key("x-resp-hop") && !headers.contains_key("keep-alive") && !headers.contains_key("connection"));

	// HTTP/3
	let (mut h3, _ep) = s.h3().await;
	let (status, headers, _) = h3_get(&mut h3, hyper::Request::get("https://a.test/set-cookies").body(()).unwrap()).await;
	assert_eq!(status, StatusCode::FOUND);
	let got: Vec<&str> = headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).collect();
	assert_eq!(got, SET_COOKIES);
}

#[tokio::test]
async fn set_cookie_survives_compression_and_header_middlewares() {
	let s = setup(
		"sem-compress",
		json!({"gz": {"compress": {}}, "hdr": {"headers": {"response": {"set": {"x-frame-options": "DENY"}}}}}),
	)
	.await;
	let mut h2 = s.h2().await;
	let req = hyper::Request::get("https://a.test/set-cookies").header("accept-encoding", "gzip").body(empty()).unwrap();
	let (_, headers, _) = h2_send(&mut h2, req).await;
	let got: Vec<&str> = headers.get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).collect();
	assert_eq!(got, SET_COOKIES);
	assert_eq!(headers["content-encoding"], "gzip");
	assert!(headers.get_all("vary").iter().any(|v| v.to_str().unwrap().eq_ignore_ascii_case("accept-encoding")));
	assert_eq!(headers["x-frame-options"], "DENY");
}

#[tokio::test]
async fn request_fields_pass_through_and_hop_by_hop_ones_are_dropped() {
	let s = setup("sem-reqfields", json!({})).await;

	let mut req = b"GET /echo?q=1 HTTP/1.1\r\nHost: a.test\r\n".to_vec();
	req.extend_from_slice(b"X-Multi: first\r\nX-Multi: second\r\n");
	req.extend_from_slice(b"X-Bin: caf\xe9 \xff\r\n");
	req.extend_from_slice(b"Cookie: a=1; _gitlab_session=xyz\r\n");
	req.extend_from_slice(b"Authorization: Bearer token\r\nProxy-Authorization: Basic c2VjcmV0\r\n");
	req.extend_from_slice(b"Connection: close, x-hop\r\nX-Hop: 1\r\nKeep-Alive: timeout=5\r\nTE: trailers\r\n");
	req.extend_from_slice(b"Origin: https://a.test\r\nX-CSRF-Token: t0k3n\r\n\r\n");
	let (status, _, body) = h1_fields(&s.h1_raw(&req).await);
	assert_eq!(status, 200);
	let v = json_body(&body);
	assert_eq!(v["uri"], "/echo?q=1", "origin-form to the backend");
	assert_eq!(received_text(&v, "x-multi"), ["first", "second"], "repeated fields keep their order");
	assert_eq!(received(&v, "x-bin"), [b"caf\xe9 \xff".to_vec()], "non-ASCII bytes pass unchanged");
	assert_eq!(received_text(&v, "cookie"), ["a=1; _gitlab_session=xyz"]);
	assert_eq!(received_text(&v, "authorization"), ["Bearer token"], "end-to-end credentials pass");
	assert_eq!(received_text(&v, "origin"), ["https://a.test"]);
	assert_eq!(received_text(&v, "x-csrf-token"), ["t0k3n"]);
	for hop in ["proxy-authorization", "x-hop", "keep-alive", "te"] {
		assert!(received(&v, hop).is_empty(), "{hop} is not forwarded: {v}");
	}
	assert_eq!(received_text(&v, "host"), ["a.test"]);
	assert_eq!(received_text(&v, "x-forwarded-proto"), ["https"]);
	assert_eq!(received_text(&v, "x-forwarded-host"), ["a.test"]);

	// HTTP/2: repeated fields and cookies (joined) the same way
	let mut h2 = s.h2().await;
	let req = hyper::Request::get("https://a.test/echo")
		.header("x-multi", "first")
		.header("x-multi", "second")
		.header("cookie", "a=1")
		.header("cookie", "_gitlab_session=xyz")
		.header("te", "trailers")
		.body(empty())
		.unwrap();
	let (status, _, body) = h2_send(&mut h2, req).await;
	assert_eq!(status, StatusCode::OK);
	let v: Value = serde_json::from_slice(&body).unwrap();
	assert_eq!(received_text(&v, "x-multi"), ["first", "second"]);
	assert_eq!(received_text(&v, "cookie"), ["a=1; _gitlab_session=xyz"]);
	assert_eq!(received_text(&v, "host"), ["a.test"], ":authority becomes Host");
	assert!(received(&v, "te").is_empty());
}

#[tokio::test]
async fn the_authority_of_an_absolute_form_request_wins_over_host() {
	let s = setup("sem-absolute", json!({})).await;
	// RFC 9112 §3.2.2: with an absolute-form target, the Host field is replaced by its authority
	let (status, _, body) = h1_fields(&s.h1_raw(b"GET https://a.test/abs HTTP/1.1\r\nHost: other.test\r\nConnection: close\r\n\r\n").await);
	assert_eq!(status, 200);
	let v = json_body(&body);
	assert_eq!(v["uri"], "/abs");
	assert_eq!(received_text(&v, "host"), ["a.test"]);
	assert_eq!(received_text(&v, "x-forwarded-host"), ["a.test"]);
}

#[tokio::test]
async fn large_cookies_fit_on_every_protocol() {
	let s = setup("sem-bigheaders", json!({})).await;
	// browsers keep sending cookies up to about 4 KB each; with a few sites' worth of
	// cookies (GitLab, Keycloak) the field section passes 16 KiB, hyper's HTTP/2 default
	let big = format!("big={}", "x".repeat(40 * 1024));

	let req = format!("GET /echo HTTP/1.1\r\nHost: a.test\r\nCookie: {big}\r\nConnection: close\r\n\r\n");
	let (status, _, body) = h1_fields(&s.h1_raw(req.as_bytes()).await);
	assert_eq!(status, 200);
	assert_eq!(received_text(&json_body(&body), "cookie"), std::slice::from_ref(&big));

	let mut h2 = s.h2().await;
	let (status, _, body) = h2_send(&mut h2, hyper::Request::get("https://a.test/echo").header("cookie", &big).body(empty()).unwrap()).await;
	assert_eq!(status, StatusCode::OK, "HTTP/2 takes a 40 KiB cookie");
	assert_eq!(received_text(&serde_json::from_slice(&body).unwrap(), "cookie"), std::slice::from_ref(&big));

	let (mut h3, _ep) = s.h3().await;
	let (status, _, body) = h3_get(&mut h3, hyper::Request::get("https://a.test/echo").header("cookie", &big).body(()).unwrap()).await;
	assert_eq!(status, StatusCode::OK, "HTTP/3 takes a 40 KiB cookie");
	assert_eq!(received_text(&serde_json::from_slice(&body).unwrap(), "cookie"), std::slice::from_ref(&big));

	// far beyond the limit: refused (431 or the stream reset), not forwarded
	let huge = format!("huge={}", "x".repeat(200 * 1024));
	let mut h2 = s.h2().await;
	if let Ok(resp) = h2.send_request(hyper::Request::get("https://a.test/echo").header("cookie", &huge).body(empty()).unwrap()).await {
		assert_eq!(resp.status().as_u16(), 431);
	}
}

#[tokio::test]
async fn bodies_expect_continue_chunked_and_head() {
	let s = setup("sem-bodies", json!({})).await;

	// Expect: 100-continue (curl for bodies over 1 KB, git push): the interim response comes, then the body goes through
	let mut t = s.tls(&["http/1.1"]).await;
	t.write_all(b"POST /upload HTTP/1.1\r\nHost: a.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n").await.unwrap();
	let mut buf = vec![0u8; 256];
	let n = tokio::time::timeout(Duration::from_secs(3), t.read(&mut buf)).await.expect("100 Continue").unwrap();
	assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 100"), "{}", String::from_utf8_lossy(&buf[..n]));
	t.write_all(b"hello").await.unwrap();
	let mut out = vec![];
	let _ = tokio::time::timeout(Duration::from_secs(5), t.read_to_end(&mut out)).await;
	let (status, _, body) = h1_fields(&out);
	assert_eq!(status, 200);
	assert_eq!(json_body(&body)["body_len"], 5);

	// a chunked request body without Content-Length
	let req = b"POST /chunked HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
	let (status, _, body) = h1_fields(&s.h1_raw(req).await);
	assert_eq!(status, 200);
	let v = json_body(&body);
	assert_eq!((v["body_len"].as_u64(), v["body_prefix"].as_str()), (Some(11), Some("hello world")));

	// HEAD keeps the Content-Length and sends no body
	let (status, fields, body) = h1_fields(&s.h1_raw(b"HEAD /head HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n").await);
	assert_eq!(status, 200);
	assert_eq!(values(&fields, "content-length"), ["1234"]);
	assert!(body.is_empty());
}

#[tokio::test]
async fn the_response_timeout_counts_from_the_end_of_the_request_body() {
	let s = setup("sem-timeouts", json!({})).await;
	let mut h2 = s.h2().await;

	// an upload that takes longer than timeouts.response (1s) is not cut: the timeout waits for the answer, not the upload
	let chunks = futures_util::stream::unfold(0u32, |i| async move {
		if i == 5 {
			return None;
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
		Some((Ok::<_, std::io::Error>(Frame::data(Bytes::from(vec![b'u'; 1000]))), i + 1))
	});
	let req = hyper::Request::post("https://a.test/upload").body(boxed(StreamBody::new(chunks))).unwrap();
	let (status, _, body) = h2_send(&mut h2, req).await;
	assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
	assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["body_len"], 5000);

	// a response body that streams for longer than the timeout arrives whole (downloads, SSE, long polling)
	let (status, _, body) = h2_send(&mut h2, hyper::Request::get("https://a.test/stream").body(empty()).unwrap()).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(&body[..], b"chunk0;chunk1;chunk2;chunk3;chunk4;chunk5;");

	// response headers later than the timeout: 504
	let (status, _, _) = h2_send(&mut h2, hyper::Request::get("https://a.test/late").body(empty()).unwrap()).await;
	assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);

	// a large upload in one go (streamed through, not buffered)
	let big = Bytes::from(vec![b'z'; 8 << 20]);
	let req = hyper::Request::post("https://a.test/upload").body(boxed(Full::new(big).map_err(|never| match never {}))).unwrap();
	let (status, _, body) = h2_send(&mut h2, req).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["body_len"], 8 << 20);
}

