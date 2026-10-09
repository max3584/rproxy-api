//! Data integrity through rproxy (#134): large pseudo-random streams compared by
//! SHA-256 on every path (TCP, UDP, DTLS, HTTP/1.1 / 2 / 3, WebSocket and the
//! middlewares that touch bodies), a stream cut off on one side never reaching
//! the other side as a complete one, and UDP datagrams neither reordered nor
//! duplicated. `RPROXY_TEST_INTEGRITY_MB` sets the size of each case (default 32).

mod common;

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper_util::rt::{TokioExecutor, TokioIo};
use reqwest::StatusCode;
use rustls::pki_types::ServerName;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use common::pki::{Issued, Pki};
use common::*;

/// Bytes per case: `RPROXY_TEST_INTEGRITY_MB` MiB (default 32).
fn case_bytes() -> u64 {
	let mb: u64 = std::env::var("RPROXY_TEST_INTEGRITY_MB").ok().and_then(|v| v.parse().ok()).unwrap_or(32);
	mb.max(1) << 20
}

const CHUNK: usize = 64 * 1024;
const BLOCK: usize = 1 << 20;

/// A megabyte of pseudo-random bytes (xorshift64*), made once.
fn block() -> &'static [u8] {
	static B: OnceLock<Vec<u8>> = OnceLock::new();
	B.get_or_init(|| {
		let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
		let mut out = Vec::with_capacity(BLOCK);
		while out.len() < BLOCK {
			x ^= x >> 12;
			x ^= x << 25;
			x ^= x >> 27;
			out.extend_from_slice(&x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
		}
		out
	})
}

/// Chunk `i` of stream `seed`: a slice of `block()` at an offset that depends on
/// both, so reordered, repeated or shifted chunks change the hash.
fn chunk(seed: u64, i: u64, len: usize) -> &'static [u8] {
	let span = (BLOCK - CHUNK) as u64;
	let at = (seed.wrapping_mul(7919).wrapping_add(i.wrapping_mul(4099)) % span) as usize;
	&block()[at..at + len]
}

/// The chunks of stream `seed`, `len` bytes long.
fn chunks(seed: u64, len: u64) -> impl Iterator<Item = &'static [u8]> {
	(0..len.div_ceil(CHUNK as u64)).map(move |i| chunk(seed, i, ((len - i * CHUNK as u64) as usize).min(CHUNK)))
}

fn expected(seed: u64, len: u64) -> [u8; 32] {
	let mut h = Sha256::new();
	for c in chunks(seed, len) {
		h.update(c);
	}
	h.finalize().into()
}

fn hex(h: &[u8]) -> String {
	h.iter().map(|b| format!("{b:02x}")).collect()
}

async fn write_stream<W: AsyncWrite + Unpin>(w: &mut W, seed: u64, len: u64) -> std::io::Result<()> {
	for c in chunks(seed, len) {
		w.write_all(c).await?;
	}
	Ok(())
}

/// Reads to the end; the hash and the length.
async fn read_hash<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<([u8; 32], u64)> {
	let mut h = Sha256::new();
	let mut buf = vec![0u8; CHUNK];
	let mut n = 0u64;
	loop {
		let got = r.read(&mut buf).await?;
		if got == 0 {
			return Ok((h.finalize().into(), n));
		}
		h.update(&buf[..got]);
		n += got as u64;
	}
}

// ---- TCP ----------------------------------------------------------------------

/// What the backend received on one connection: the seed it was asked to send
/// back, and the hash and length of what came after the preamble.
#[derive(Debug, PartialEq)]
struct Received {
	down_seed: u64,
	hash: [u8; 32],
	len: u64,
}

/// A backend that, per connection, reads a 16-byte preamble (seed and length of
/// the stream to send back), then at the same time sends that stream (and closes
/// its side) and hashes everything else it receives up to the client's close.
/// With `proxy_v2`, a PROXY v2 header comes first and is checked and skipped.
async fn hash_backend(tls: Option<tokio_rustls::TlsAcceptor>, proxy_v2: bool) -> (SocketAddr, mpsc::UnboundedReceiver<Received>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let (tx, rx) = mpsc::unbounded_channel();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			let tls = tls.clone();
			let tx = tx.clone();
			tokio::spawn(async move {
				if proxy_v2 {
					let mut head = [0u8; 16];
					s.read_exact(&mut head).await.unwrap();
					assert_eq!(&head[..12], b"\r\n\r\n\0\r\nQUIT\n", "a PROXY v2 header first");
					let mut rest = vec![0u8; u16::from_be_bytes([head[14], head[15]]) as usize];
					s.read_exact(&mut rest).await.unwrap();
				}
				match tls {
					Some(acceptor) => serve_hash(acceptor.accept(s).await.unwrap(), tx).await,
					None => serve_hash(s, tx).await,
				}
			});
		}
	});
	(addr, rx)
}

async fn serve_hash<S: AsyncRead + AsyncWrite + Unpin>(s: S, tx: mpsc::UnboundedSender<Received>) {
	let (mut r, mut w) = tokio::io::split(s);
	let mut pre = [0u8; 16];
	r.read_exact(&mut pre).await.unwrap();
	let seed = u64::from_le_bytes(pre[..8].try_into().unwrap());
	let len = u64::from_le_bytes(pre[8..].try_into().unwrap());
	let send = async {
		write_stream(&mut w, seed, len).await.unwrap();
		w.shutdown().await.unwrap();
	};
	let (_, got) = tokio::join!(send, read_hash(&mut r));
	let (hash, n) = got.unwrap();
	let _ = tx.send(Received { down_seed: seed, hash, len: n });
}

/// One connection through the rule: asks for `len` bytes of stream `down`, sends
/// `len` bytes of stream `up`, both at once, and checks what came back.
async fn hash_exchange<S: AsyncRead + AsyncWrite + Unpin>(s: S, up: u64, down: u64, len: u64) {
	let (mut r, mut w) = tokio::io::split(s);
	let send = async {
		let mut pre = down.to_le_bytes().to_vec();
		pre.extend_from_slice(&len.to_le_bytes());
		w.write_all(&pre).await.unwrap();
		write_stream(&mut w, up, len).await.unwrap();
		w.shutdown().await.unwrap();
	};
	let (_, got) = tokio::join!(send, read_hash(&mut r));
	let (hash, n) = got.unwrap();
	assert_eq!((n, hex(&hash)), (len, hex(&expected(down, len))), "download of stream {down}");
}

/// `conns` concurrent connections of `case_bytes() / conns` each way; `connect`
/// opens one (plain or TLS). Every upload must reach the backend unchanged.
async fn tcp_case<F, Fut, S>(label: &str, conns: u64, mut reports: mpsc::UnboundedReceiver<Received>, connect: F)
where
	F: Fn() -> Fut,
	Fut: std::future::Future<Output = S> + Send + 'static,
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let len = case_bytes() / conns;
	let mut tasks = vec![];
	for i in 0..conns {
		let (up, down) = (1000 + i, 2000 + i);
		let conn = connect();
		tasks.push(tokio::spawn(async move { hash_exchange(conn.await, up, down, len).await }));
	}
	for t in tasks {
		t.await.unwrap_or_else(|e| panic!("{label}: {e}"));
	}
	let mut got = BTreeMap::new();
	for _ in 0..conns {
		let r = tokio::time::timeout(Duration::from_secs(30), reports.recv()).await.unwrap().unwrap();
		got.insert(r.down_seed, (hex(&r.hash), r.len));
	}
	for i in 0..conns {
		assert_eq!(got[&(2000 + i)], (hex(&expected(1000 + i, len)), len), "{label}: upload of stream {}", 1000 + i);
	}
}

fn tcp_rule(port: u16, target: SocketAddr, extra: Value) -> Value {
	let mut r = rule("tcp", port, target);
	for (k, v) in extra.as_object().unwrap() {
		r[k] = v.clone();
	}
	r
}

async fn plain(port: u16) -> TcpStream {
	TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_streams_arrive_unchanged_on_every_path() {
	let pki = Pki::new("integrity-tcp");
	let front = pki.server("front", &["a.test"]);
	let back = pki.server("back", &["back.test"]);
	let h = harness().await;
	let certs = json!([{"cert_file": front.cert_file, "key_file": front.key_file}]);

	// passthrough
	let (b, reports) = hash_backend(None, false).await;
	let port = free_port();
	assert_eq!(h.post(tcp_rule(port, b, json!({}))).await.0, StatusCode::CREATED);
	tcp_case("passthrough", 4, reports, move || plain(port)).await;

	// passthrough with a PROXY v2 header in front
	let (b, reports) = hash_backend(None, true).await;
	let port = free_port();
	assert_eq!(h.post(tcp_rule(port, b, json!({"source_ip": "proxy_v2"}))).await.0, StatusCode::CREATED);
	tcp_case("proxy_v2", 4, reports, move || plain(port)).await;

	// TLS terminated by rproxy, plain to the backend
	let (b, reports) = hash_backend(None, false).await;
	let port = free_port();
	let (status, v) = h.post(tcp_rule(port, b, json!({"tls": {"mode": "terminate", "certificates": certs}}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let connector = pki.connector(None);
	tcp_case("terminate", 4, reports, move || {
		let connector = connector.clone();
		async move { connector.connect(ServerName::try_from("a.test").unwrap(), plain(port).await).await.unwrap() }
	})
	.await;

	// terminated and encrypted again towards a TLS backend (upstream.tls)
	let (b, reports) = hash_backend(Some(pki.acceptor(&back)), false).await;
	let port = free_port();
	let tls = json!({"mode": "terminate", "certificates": certs, "upstream": {"tls": true, "server_name": "back.test", "ca_file": pki.ca_file}});
	let (status, v) = h.post(tcp_rule(port, b, json!({"tls": tls}))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let connector = pki.connector(None);
	tcp_case("upstream.tls", 4, reports, move || {
		let connector = connector.clone();
		async move { connector.connect(ServerName::try_from("a.test").unwrap(), plain(port).await).await.unwrap() }
	})
	.await;
	// offload-verify builds: the kernel fast path (when on) matched throughout
	assert_offload_verified();
}

/// A single-connection backend doing what `f` says with the accepted socket.
async fn one_shot<F, Fut>(f: F) -> SocketAddr
where
	F: FnOnce(TcpStream) -> Fut + Send + 'static,
	Fut: std::future::Future<Output = ()> + Send,
{
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let (s, _) = listener.accept().await.unwrap();
		f(s).await;
	});
	addr
}

fn reset(s: TcpStream) {
	socket2::SockRef::from(&s).set_linger(Some(Duration::ZERO)).unwrap();
	drop(s);
}

/// Reads until the end or an error: what was read and how it ended.
async fn read_until_end<R: AsyncRead + Unpin>(r: &mut R) -> (Vec<u8>, std::io::Result<()>) {
	let mut out = vec![];
	let mut buf = vec![0u8; CHUNK];
	loop {
		match tokio::time::timeout(Duration::from_secs(10), r.read(&mut buf)).await {
			Err(_) => return (out, Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "no end"))),
			Ok(Ok(0)) => return (out, Ok(())),
			Ok(Ok(n)) => out.extend_from_slice(&buf[..n]),
			Ok(Err(e)) => return (out, Err(e)),
		}
	}
}

#[tokio::test]
async fn a_reset_is_passed_on_as_a_reset_and_a_close_as_a_close() {
	let h = harness().await;
	let sent = chunk(7, 0, 50_000).to_vec();

	// the backend resets after sending part of the data: the client sees a reset, not an end
	let data = sent.clone();
	let b = one_shot(move |mut s| async move {
		s.write_all(&data).await.unwrap();
		tokio::time::sleep(Duration::from_millis(300)).await;
		reset(s);
	})
	.await;
	let port = free_port();
	assert_eq!(h.post(tcp_rule(port, b, json!({}))).await.0, StatusCode::CREATED);
	let mut c = plain(port).await;
	let (got, end) = read_until_end(&mut c).await;
	assert_eq!(got, sent);
	assert_eq!(end.map_err(|e| e.kind()), Err(std::io::ErrorKind::ConnectionReset), "a backend reset reaches the client as a reset");

	// the client resets while sending: the backend sees a reset, not a complete stream
	let (tx, mut rx) = mpsc::unbounded_channel();
	let b = one_shot(move |mut s| async move {
		let _ = tx.send(read_until_end(&mut s).await);
	})
	.await;
	let port = free_port();
	assert_eq!(h.post(tcp_rule(port, b, json!({}))).await.0, StatusCode::CREATED);
	let mut c = plain(port).await;
	c.write_all(&sent).await.unwrap();
	tokio::time::sleep(Duration::from_millis(300)).await;
	reset(c);
	let (got, end) = tokio::time::timeout(Duration::from_secs(10), rx.recv()).await.unwrap().unwrap();
	assert_eq!(got.len(), sent.len());
	assert_eq!(end.map_err(|e| e.kind()), Err(std::io::ErrorKind::ConnectionReset), "a client reset reaches the backend as a reset");

	// a clean close is a half-close: the client ends its side, the backend still answers
	let b = one_shot(|mut s| async move {
		let (req, end) = read_until_end(&mut s).await;
		end.unwrap();
		s.write_all(format!("got {} bytes", req.len()).as_bytes()).await.unwrap();
		s.shutdown().await.unwrap();
	})
	.await;
	let port = free_port();
	assert_eq!(h.post(tcp_rule(port, b, json!({}))).await.0, StatusCode::CREATED);
	let mut c = plain(port).await;
	c.write_all(&sent).await.unwrap();
	c.shutdown().await.unwrap();
	let (got, end) = read_until_end(&mut c).await;
	end.unwrap();
	assert_eq!(String::from_utf8(got).unwrap(), format!("got {} bytes", sent.len()));

	// through TLS termination: a backend reset is not a clean TLS end (close_notify)
	let pki = Pki::new("integrity-rst-tls");
	let front = pki.server("front", &["a.test"]);
	let data = sent.clone();
	let b = one_shot(move |mut s| async move {
		s.write_all(&data).await.unwrap();
		tokio::time::sleep(Duration::from_millis(300)).await;
		reset(s);
	})
	.await;
	let port = free_port();
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}]});
	assert_eq!(h.post(tcp_rule(port, b, json!({"tls": tls}))).await.0, StatusCode::CREATED);
	let mut c = pki.connector(None).connect(ServerName::try_from("a.test").unwrap(), plain(port).await).await.unwrap();
	let (got, end) = read_until_end(&mut c).await;
	assert_eq!(got, sent);
	assert!(end.is_err(), "the TLS stream must not end cleanly");
}

// ---- UDP ----------------------------------------------------------------------

/// Datagram `seq` of a numbered sequence: its number, then bytes that depend on it.
fn datagram(seq: u32, sizes: &[usize]) -> Vec<u8> {
	let len = sizes[seq as usize % sizes.len()].max(4);
	let mut d = seq.to_le_bytes().to_vec();
	d.extend_from_slice(chunk(u64::from(seq), 0, len - 4));
	d
}

async fn udp_echo() -> SocketAddr {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr = sock.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = vec![0u8; 65_535];
		loop {
			let (n, from) = sock.recv_from(&mut buf).await.unwrap();
			sock.send_to(&buf[..n], from).await.unwrap();
		}
	});
	addr
}

/// Sends numbered datagrams (at most `window` bytes and `count` datagrams in
/// flight, so the sockets' receive buffers never overflow in the kernel, which
/// no proxy could see) and checks the echoes come back complete, once each and in order.
async fn numbered<S, R>(send: S, recv: R, sizes: &[usize], total: u64, window: usize, count: usize) -> u32
where
	S: Fn(Vec<u8>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
	R: Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send>>,
{
	let (mut next, mut expect, mut sent_bytes, mut in_flight) = (0u32, 0u32, 0u64, std::collections::VecDeque::new());
	loop {
		while sent_bytes < total && in_flight.len() < count && in_flight.iter().sum::<usize>() < window {
			let d = datagram(next, sizes);
			in_flight.push_back(d.len());
			sent_bytes += d.len() as u64;
			send(d).await;
			next += 1;
		}
		if in_flight.is_empty() {
			return next;
		}
		let got = tokio::time::timeout(Duration::from_secs(5), recv()).await.unwrap_or_else(|_| panic!("datagram {expect} lost"));
		let seq = u32::from_le_bytes(got[..4].try_into().unwrap());
		assert_eq!(seq, expect, "datagrams in order, none repeated or lost");
		assert!(got == datagram(seq, sizes), "datagram {seq} unchanged ({} bytes)", got.len());
		in_flight.pop_front();
		expect += 1;
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_datagrams_arrive_unchanged_once_and_in_order() {
	let h = harness().await;
	let port = free_udp_port();
	assert_eq!(h.post(rule("udp", port, udp_echo().await)).await.0, StatusCode::CREATED);
	// one client from a byte to the largest IPv4 UDP payload, three more with small datagrams
	let big = vec![1, 64, 512, 1200, 1472, 4096, 9000, 32_768, 65_507];
	let small = vec![1, 64, 512, 1200, 1472, 4096];
	let mut tasks = vec![];
	for i in 0..4 {
		let (sizes, window) = if i == 0 { (big.clone(), 70_000) } else { (small.clone(), 16 * 1024) };
		tasks.push(tokio::spawn(async move {
			let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
			sock.connect(("127.0.0.1", port)).await.unwrap();
			let (s1, s2) = (sock.clone(), sock.clone());
			numbered(
				move |d| {
					let s = s1.clone();
					Box::pin(async move {
						s.send(&d).await.unwrap();
					})
				},
				move || {
					let s = s2.clone();
					Box::pin(async move {
						let mut buf = vec![0u8; 65_535];
						let n = s.recv(&mut buf).await.unwrap();
						buf.truncate(n);
						buf
					})
				},
				&sizes,
				case_bytes() / 4,
				window,
				4,
			)
			.await
		}));
	}
	let mut datagrams = 0;
	for t in tasks {
		datagrams += t.await.unwrap();
	}
	let (_, v) = h.get(&format!("/rules/udp/127.0.0.1/{port}")).await;
	assert_eq!(v["stats"]["dropped"], 0, "{v}");
	assert!(datagrams > 0);
	// offload-verify builds: the kernel fast path (when on) matched throughout
	assert_offload_verified();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dtls_records_arrive_unchanged_once_and_in_order() {
	use dtls::config::{Config, ExtendedMasterSecretType};
	use dtls::conn::DTLSConn;
	use webrtc_util::conn::Conn;

	let pki = Pki::new("integrity-dtls");
	let cert: Issued = pki.server("front", &["media.test"]);
	let h = harness().await;
	let port = free_udp_port();
	let mut r = rule("udp", port, udp_echo().await);
	r["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]});
	let (status, v) = h.post(r).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	sock.connect(("127.0.0.1", port)).await.unwrap();
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(sock);
	let config = Config {
		roots_cas: pki.roots(),
		server_name: "media.test".into(),
		extended_master_secret: ExtendedMasterSecretType::Require,
		..Default::default()
	};
	let c = Arc::new(DTLSConn::new(conn, config, true, None).await.unwrap());
	let (c1, c2) = (c.clone(), c.clone());
	let sizes = [1, 100, 1000, 1200, 4000, 8000];
	numbered(
		move |d| {
			let c = c1.clone();
			Box::pin(async move {
				c.write(&d, None).await.unwrap();
			})
		},
		move || {
			let c = c2.clone();
			Box::pin(async move {
				let mut buf = vec![0u8; 16_384];
				let n = c.read(&mut buf, None).await.unwrap();
				buf.truncate(n);
				buf
			})
		},
		&sizes,
		case_bytes() / 8,
		32 * 1024,
		8,
	)
	.await;
	let (_, v) = h.get(&format!("/rules/udp/127.0.0.1/{port}")).await;
	assert_eq!(v["stats"]["dropped"], 0, "{v}");
}

// ---- HTTP ---------------------------------------------------------------------

type BoxErr = Box<dyn std::error::Error + Send + Sync>;
type ClientBody = http_body_util::combinators::BoxBody<Bytes, BoxErr>;
type ServerBody = http_body_util::combinators::BoxBody<Bytes, BoxErr>;

/// What the backend saw of a request body it was told to watch (`/sink`).
#[derive(Debug)]
enum Sink {
	Started(String),
	Ended(String, Result<u64, String>),
}

fn query(uri: &hyper::Uri) -> HashMap<String, String> {
	uri.query()
		.unwrap_or("")
		.split('&')
		.filter_map(|p| p.split_once('='))
		.map(|(k, v)| (k.to_string(), v.to_string()))
		.collect()
}

/// A stream of chunks as a body, optionally failing after `fail_after` bytes.
fn stream_body(seed: u64, len: u64, fail_after: Option<u64>) -> ServerBody {
	let mut items: Vec<Result<Frame<Bytes>, BoxErr>> = vec![];
	let mut sent = 0u64;
	for c in chunks(seed, len) {
		if fail_after.is_some_and(|f| sent >= f) {
			items.push(Err("cut off on purpose".into()));
			break;
		}
		sent += c.len() as u64;
		items.push(Ok(Frame::data(Bytes::from_static(c))));
	}
	StreamBody::new(futures_util::stream::iter(items)).boxed()
}

/// The HTTP/1.1 backend of the HTTP cases:
/// - `POST /up?id=`: hashes the request body, answers `{"id", "hash", "len"}`
/// - `GET /down?seed=&len=&mode=cl|chunked`: sends that stream
/// - `GET /cut?...&cut=N`: sends N bytes of it and then fails (the connection is cut)
/// - `POST /sink?id=`: reports to the test when the body started and how it ended
/// - `GET /ws`: switches protocols and echoes the bytes
/// - `GET /slow?n=`: n chunks, one every 200 ms
///
/// The second address serves the same over HTTP/2 without TLS (h2c, #233).
async fn http_backend() -> (SocketAddr, SocketAddr, mpsc::UnboundedReceiver<Sink>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let (tx, rx) = mpsc::unbounded_channel();
	let h2_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let h2_addr = h2_listener.local_addr().unwrap();
	let h2_tx = tx.clone();
	tokio::spawn(async move {
		loop {
			let (s, _) = h2_listener.accept().await.unwrap();
			let tx = h2_tx.clone();
			let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
				let tx = tx.clone();
				async move { Ok::<_, std::convert::Infallible>(backend_answer(req, tx).await) }
			});
			tokio::spawn(async move {
				let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(s), service).await;
			});
		}
	});
	tokio::spawn(async move {
		loop {
			let (s, _) = listener.accept().await.unwrap();
			let tx = tx.clone();
			let service = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
				let tx = tx.clone();
				async move { Ok::<_, std::convert::Infallible>(backend_answer(req, tx).await) }
			});
			tokio::spawn(async move {
				let _ = hyper::server::conn::http1::Builder::new()
					.serve_connection(TokioIo::new(s), service)
					.with_upgrades()
					.await;
			});
		}
	});
	(addr, h2_addr, rx)
}

async fn backend_answer(mut req: hyper::Request<Incoming>, tx: mpsc::UnboundedSender<Sink>) -> hyper::Response<ServerBody> {
	let q = query(req.uri());
	let num = |k: &str| q.get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
	let path = req.uri().path().rsplit('/').next().unwrap_or("").to_string();
	match path.as_str() {
		"up" => {
			let mut h = Sha256::new();
			let mut n = 0u64;
			let mut body = req.into_body();
			while let Some(frame) = body.frame().await {
				let Ok(frame) = frame else {
					return hyper::Response::builder().status(400).body(Empty::new().map_err(|e| match e {}).boxed()).unwrap();
				};
				if let Some(d) = frame.data_ref() {
					h.update(d);
					n += d.len() as u64;
				}
			}
			let out = json!({"id": q.get("id"), "hash": hex(&h.finalize()), "len": n}).to_string();
			hyper::Response::new(http_body_util::Full::new(Bytes::from(out)).map_err(|e| match e {}).boxed())
		}
		"down" | "cut" => {
			let (seed, len) = (num("seed"), num("len"));
			let fail = (path == "cut").then(|| num("cut"));
			let mut resp = hyper::Response::new(stream_body(seed, len, fail));
			resp.headers_mut().insert("content-type", "text/plain".parse().unwrap());
			if q.get("mode").map(String::as_str) == Some("cl") {
				resp.headers_mut().insert("content-length", len.to_string().parse().unwrap());
			}
			resp
		}
		"sink" => {
			let id = q.get("id").cloned().unwrap_or_default();
			let mut body = req.into_body();
			let mut n = 0u64;
			let mut started = false;
			let result = loop {
				match body.frame().await {
					None => break Ok(n),
					Some(Err(e)) => break Err(e.to_string()),
					Some(Ok(f)) => {
						if let Some(d) = f.data_ref() {
							n += d.len() as u64;
						}
						if !started {
							started = true;
							let _ = tx.send(Sink::Started(id.clone()));
						}
					}
				}
			};
			let _ = tx.send(Sink::Ended(id, result));
			hyper::Response::new(Empty::new().map_err(|e| match e {}).boxed())
		}
		"slow" => {
			let n = num("n");
			let items = futures_util::stream::unfold(0u64, move |i| async move {
				if i == n {
					return None;
				}
				tokio::time::sleep(Duration::from_millis(200)).await;
				Some((Ok::<_, BoxErr>(Frame::data(Bytes::from_static(chunk(3, i, 1000)))), i + 1))
			});
			hyper::Response::new(StreamBody::new(items).boxed())
		}
		"ws" => {
			let upgrade = hyper::upgrade::on(&mut req);
			tokio::spawn(async move {
				let io = TokioIo::new(upgrade.await.unwrap());
				let (mut r, mut w) = tokio::io::split(io);
				let _ = tokio::io::copy(&mut r, &mut w).await;
				let _ = w.shutdown().await;
			});
			hyper::Response::builder()
				.status(101)
				.header("connection", "upgrade")
				.header("upgrade", "websocket")
				.body(Empty::new().map_err(|e| match e {}).boxed())
				.unwrap()
		}
		_ => hyper::Response::builder().status(404).body(Empty::new().map_err(|e| match e {}).boxed()).unwrap(),
	}
}

struct Http {
	pki: Pki,
	port: u16,
	sinks: tokio::sync::Mutex<mpsc::UnboundedReceiver<Sink>>,
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

/// An `http` rule (TLS, HTTP/1.1 / 2 / 3) in front of `http_backend()`:
/// `/c/*` compressed, `/b/*` buffered, `/r/*` retried over a dead server first.
async fn http_setup(tag: &str) -> Http {
	let pki = Pki::new(tag);
	let cert = pki.server("front", &["a.test"]);
	let (b, b2, sinks) = http_backend().await;
	let dead = {
		let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		l.local_addr().unwrap()
	};
	let h = harness().await;
	let port = free_tcp_udp_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"tls": {"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]},
			"http": {
				"http3": true,
				"routes": [
					{"name": "c", "match": "PathPrefix(`/c/`)", "service": "b", "middlewares": ["zip"]},
					{"name": "buf", "match": "PathPrefix(`/b/`)", "service": "b", "middlewares": ["buffer"]},
					{"name": "r", "match": "PathPrefix(`/r/`)", "service": "retried", "middlewares": ["again", "buffer"]},
					{"name": "h2", "match": "PathPrefix(`/h2/`)", "service": "h2c"},
					{"name": "t", "match": "PathPrefix(`/t/`)", "service": "b", "timeouts": {"request": "1s"}},
					{"name": "tb", "match": "PathPrefix(`/tb/`)", "service": "h2c", "timeouts": {"backend_request": "1s"}},
					{"name": "m", "match": "PathPrefix(`/m/`)", "service": "b", "middlewares": ["copy"]},
					{"name": "all", "match": "PathPrefix(`/`)", "service": "b"},
				],
				"services": {
					"b": {"servers": [{"url": format!("http://{b}")}]},
					"retried": {"servers": [{"url": format!("http://{dead}")}, {"url": format!("http://{b}")}]},
					"h2c": {"protocol": "h2c", "servers": [{"url": format!("http://{b2}")}]},
				},
				"middlewares": {
					"zip": {"compress": {"min_size": 0}},
					"buffer": {"buffering": {"max_request_body": 1u64 << 31}},
					"again": {"retry": {"attempts": 3, "initial_interval": "10ms"}},
					"copy": {"mirror": {"service": "h2c"}},
				},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	Http { pki, port, sinks: tokio::sync::Mutex::new(sinks), _h: h }
}

#[derive(Clone, Copy, Debug)]
enum Proto {
	H1,
	H2,
	H3,
}

/// A response: its status, headers and body frames as they came, and how the body ended.
struct Got {
	status: u16,
	headers: hyper::HeaderMap,
	hash: [u8; 32],
	len: u64,
	raw: Vec<u8>,
	end: Result<(), String>,
}

impl Http {
	async fn tls(&self, alpn: &[&str]) -> tokio_rustls::client::TlsStream<TcpStream> {
		self.pki.connector_alpn(None, alpn).connect(ServerName::try_from("a.test").unwrap(), plain(self.port).await).await.unwrap()
	}

	/// Sends one request over a new connection of `proto`; keeps the body (`keep`) or only its hash.
	async fn send(&self, proto: Proto, req: hyper::Request<ClientBody>, keep: bool) -> Got {
		match proto {
			Proto::H1 => {
				let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(self.tls(&["http/1.1"]).await)).await.unwrap();
				tokio::spawn(conn);
				let resp = sender.send_request(req).await.unwrap();
				collect(resp, keep).await
			}
			Proto::H2 => {
				let mut sender = self.h2().await;
				let resp = sender.send_request(req).await.unwrap();
				collect(resp, keep).await
			}
			Proto::H3 => self.h3_send(req, keep).await,
		}
	}

	async fn h2(&self) -> hyper::client::conn::http2::SendRequest<ClientBody> {
		let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(self.tls(&["h2"]).await)).await.unwrap();
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
		let conn = endpoint.connect(SocketAddr::from(([127, 0, 0, 1], self.port)), "a.test").unwrap().await.unwrap();
		let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn)).await.unwrap();
		tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
		(send, endpoint)
	}

	async fn h3_send(&self, req: hyper::Request<ClientBody>, keep: bool) -> Got {
		let (mut send, _ep) = self.h3().await;
		let (parts, mut body) = req.into_parts();
		let mut stream = send.send_request(hyper::Request::from_parts(parts, ())).await.unwrap();
		while let Some(frame) = body.frame().await {
			if let Some(d) = frame.unwrap().data_ref() {
				stream.send_data(d.clone()).await.unwrap();
			}
		}
		stream.finish().await.unwrap();
		let resp = stream.recv_response().await.unwrap();
		let mut h = Sha256::new();
		let (mut len, mut raw) = (0u64, vec![]);
		let end = loop {
			match stream.recv_data().await {
				Ok(Some(mut d)) => {
					let b = d.copy_to_bytes(d.remaining());
					h.update(&b);
					len += b.len() as u64;
					if keep {
						raw.extend_from_slice(&b);
					}
				}
				Ok(None) => break Ok(()),
				Err(e) => break Err(e.to_string()),
			}
		};
		Got { status: resp.status().as_u16(), headers: resp.headers().clone(), hash: h.finalize().into(), len, raw, end }
	}

	async fn next_sink(&self) -> Sink {
		tokio::time::timeout(Duration::from_secs(15), self.sinks.lock().await.recv()).await.expect("the backend saw the request").unwrap()
	}
}

async fn collect(resp: hyper::Response<Incoming>, keep: bool) -> Got {
	let status = resp.status().as_u16();
	let headers = resp.headers().clone();
	let mut body = resp.into_body();
	let mut h = Sha256::new();
	let (mut len, mut raw) = (0u64, vec![]);
	let end = loop {
		match body.frame().await {
			None => break Ok(()),
			Some(Err(e)) => break Err(e.to_string()),
			Some(Ok(f)) => {
				if let Some(d) = f.data_ref() {
					h.update(d);
					len += d.len() as u64;
					if keep {
						raw.extend_from_slice(d);
					}
				}
			}
		}
	};
	Got { status, headers, hash: h.finalize().into(), len, raw, end }
}

fn client_stream(seed: u64, len: u64) -> ClientBody {
	let items: Vec<Result<Frame<Bytes>, BoxErr>> = chunks(seed, len).map(|c| Ok(Frame::data(Bytes::from_static(c)))).collect();
	StreamBody::new(futures_util::stream::iter(items)).boxed()
}

fn empty() -> ClientBody {
	Empty::new().map_err(|e| match e {}).boxed()
}

fn get(path: &str) -> hyper::Request<ClientBody> {
	hyper::Request::get(format!("https://a.test{path}")).body(empty()).unwrap()
}

fn upload(path: &str, seed: u64, len: u64, content_length: bool) -> hyper::Request<ClientBody> {
	let mut b = hyper::Request::post(format!("https://a.test{path}"));
	if content_length {
		b = b.header("content-length", len);
	}
	b.body(client_stream(seed, len)).unwrap()
}

fn upload_result(g: &Got, label: &str) -> Value {
	assert_eq!(g.status, 200, "{label}: {}", String::from_utf8_lossy(&g.raw));
	serde_json::from_slice(&g.raw).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_bodies_arrive_unchanged_on_every_protocol() {
	let s = Arc::new(http_setup("integrity-http").await);
	let len = case_bytes() / 4;
	for proto in [Proto::H1, Proto::H2, Proto::H3] {
		let mut tasks = vec![];
		for i in 0..4u64 {
			let s = s.clone();
			tasks.push(tokio::spawn(async move {
				let seed = 100 + i;
				// downloads, with a length and streamed
				let mode = if i % 2 == 0 { "cl" } else { "chunked" };
				let g = s.send(proto, get(&format!("/down?seed={seed}&len={len}&mode={mode}")), false).await;
				assert_eq!((g.status, &g.end), (200, &Ok(())), "{proto:?} {mode}");
				assert_eq!((g.len, hex(&g.hash)), (len, hex(&expected(seed, len))), "{proto:?} download {mode}");
				// uploads, with a length and streamed (HTTP/1.1 chunked)
				let g = s.send(proto, upload(&format!("/up?id={i}"), seed + 50, len, i % 2 == 0), true).await;
				let v = upload_result(&g, &format!("{proto:?} upload {i}"));
				assert_eq!((v["len"].as_u64(), v["hash"].as_str()), (Some(len), Some(hex(&expected(seed + 50, len)).as_str())), "{proto:?} upload");
			}));
		}
		for t in tasks {
			t.await.unwrap();
		}
	}
}

/// Decompresses as the data comes and hashes the result.
struct Decoded(Sha256, u64);

impl std::io::Write for Decoded {
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		self.0.update(buf);
		self.1 += buf.len() as u64;
		Ok(buf.len())
	}
	fn flush(&mut self) -> std::io::Result<()> {
		Ok(())
	}
}

fn decompress(encoding: &str, data: &[u8]) -> ([u8; 32], u64) {
	let out = Decoded(Sha256::new(), 0);
	let out = match encoding {
		"gzip" => {
			let mut d = flate2::write::GzDecoder::new(out);
			d.write_all(data).unwrap();
			d.finish().unwrap()
		}
		"br" => {
			let mut d = brotli::DecompressorWriter::new(out, 4096);
			d.write_all(data).unwrap();
			d.into_inner().unwrap_or_else(|_| panic!("brotli stream incomplete"))
		}
		"zstd" => {
			let mut d = zstd::stream::write::Decoder::new(out).unwrap();
			d.write_all(data).unwrap();
			d.flush().unwrap();
			d.into_inner()
		}
		_ => unreachable!(),
	};
	(out.0.finalize().into(), out.1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn middlewares_keep_bodies_intact() {
	let s = http_setup("integrity-mw").await;
	// compressed text streams (random bytes do not shrink, which is fine: they must round-trip)
	let len = (case_bytes() / 4).min(8 << 20);
	for proto in [Proto::H1, Proto::H2, Proto::H3] {
		for encoding in ["gzip", "br", "zstd"] {
			let mut req = get(&format!("/c/down?seed=31&len={len}&mode=chunked"));
			req.headers_mut().insert("accept-encoding", encoding.parse().unwrap());
			let g = s.send(proto, req, true).await;
			assert_eq!((g.status, &g.end), (200, &Ok(())), "{proto:?} {encoding}");
			assert_eq!(g.headers.get("content-encoding").and_then(|v| v.to_str().ok()), Some(encoding), "{proto:?}");
			let (hash, n) = decompress(encoding, &g.raw);
			assert_eq!((n, hex(&hash)), (len, hex(&expected(31, len))), "{proto:?} {encoding} round trip");
		}
	}
	let len = case_bytes() / 4;
	for proto in [Proto::H1, Proto::H2, Proto::H3] {
		// buffered uploads
		let v = upload_result(&s.send(proto, upload("/b/up?id=b", 41, len, false), true).await, &format!("{proto:?} buffered"));
		assert_eq!(v["hash"], hex(&expected(41, len)), "{proto:?} buffered upload");
		// retried (the first server is down) downloads and buffered uploads
		let g = s.send(proto, get(&format!("/r/down?seed=42&len={len}&mode=cl")), false).await;
		assert_eq!((g.status, g.len, hex(&g.hash)), (200, len, hex(&expected(42, len))), "{proto:?} retried download");
		// PUT: retry only sends idempotent requests again (a POST would get the 502)
		let mut put = upload("/r/up?id=r", 43, len, true);
		*put.method_mut() = hyper::Method::PUT;
		let v = upload_result(&s.send(proto, put, true).await, &format!("{proto:?} retried"));
		assert_eq!(v["hash"], hex(&expected(43, len)), "{proto:?} retried upload");
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reused_backend_connections_never_mix_bodies() {
	let s = Arc::new(http_setup("integrity-reuse").await);
	// many requests over one HTTP/2 connection share a few pooled backend connections
	let mut sender = s.h2().await;
	let mut tasks = vec![];
	for i in 0..48u64 {
		let len = 64 * 1024 + i * 4099;
		let mut sender = sender.clone();
		tasks.push(tokio::spawn(async move {
			let req = if i % 2 == 0 {
				upload(&format!("/up?id={i}"), 500 + i, len, i % 4 == 0)
			} else {
				get(&format!("/down?seed={}&len={len}&mode={}", 500 + i, if i % 3 == 0 { "cl" } else { "chunked" }))
			};
			let g = collect(sender.send_request(req).await.unwrap(), i % 2 == 0).await;
			assert_eq!((g.status, &g.end), (200, &Ok(())));
			if i % 2 == 0 {
				let v: Value = serde_json::from_slice(&g.raw).unwrap();
				assert_eq!((v["id"].as_str(), v["hash"].as_str()), (Some(i.to_string().as_str()), Some(hex(&expected(500 + i, len)).as_str())), "request {i}");
			} else {
				assert_eq!((g.len, hex(&g.hash)), (len, hex(&expected(500 + i, len))), "response {i}");
			}
		}));
	}
	for t in tasks {
		t.await.unwrap();
	}
	// and sequentially over the same connection
	for i in 0..16u64 {
		let len = 10_000 + i * 777;
		let g = collect(sender.send_request(get(&format!("/down?seed={}&len={len}&mode=cl", 900 + i))).await.unwrap(), false).await;
		assert_eq!(hex(&g.hash), hex(&expected(900 + i, len)), "sequential {i}");
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_streams_arrive_unchanged() {
	let s = http_setup("integrity-ws").await;
	let mut tls = s.tls(&["http/1.1"]).await;
	tls.write_all(b"GET /ws HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
		.await
		.unwrap();
	let mut head = vec![];
	while !head.ends_with(b"\r\n\r\n") {
		let mut b = [0u8; 1];
		tls.read_exact(&mut b).await.unwrap();
		head.push(b[0]);
	}
	assert!(head.starts_with(b"HTTP/1.1 101"), "{}", String::from_utf8_lossy(&head));
	let len = case_bytes();
	let (mut r, mut w) = tokio::io::split(tls);
	let send = async {
		write_stream(&mut w, 77, len).await.unwrap();
		w.shutdown().await.unwrap();
	};
	let (_, got) = tokio::join!(send, read_hash(&mut r));
	let (hash, n) = got.unwrap();
	assert_eq!((n, hex(&hash)), (len, hex(&expected(77, len))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_response_cut_off_by_the_backend_never_looks_complete() {
	let s = http_setup("integrity-cut").await;
	let len = 4 << 20;
	for proto in [Proto::H1, Proto::H2, Proto::H3] {
		for (path, mode) in [("/cut", "cl"), ("/cut", "chunked"), ("/c/cut", "chunked")] {
			let mut req = get(&format!("{path}?seed=5&len={len}&cut={}&mode={mode}", len / 2));
			req.headers_mut().insert("accept-encoding", "gzip".parse().unwrap());
			let g = s.send(proto, req, false).await;
			assert_eq!(g.status, 200, "{proto:?} {path} {mode}");
			assert!(g.end.is_err(), "{proto:?} {path} {mode}: the body ended cleanly after {} bytes", g.len);
			assert!(g.len < len, "{proto:?} {path} {mode}");
		}
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_cut_off_by_the_client_never_reaches_the_backend_as_complete() {
	let s = http_setup("integrity-abort").await;
	let started = |sink: Sink, id: &str| match sink {
		Sink::Started(got) => assert_eq!(got, id),
		other => panic!("{id}: {other:?}"),
	};
	let ended = |sink: Sink, id: &str| match sink {
		Sink::Ended(got, result) => {
			assert_eq!(got, id);
			assert!(result.is_err(), "{id}: the backend got a complete body ({result:?})");
		}
		other => panic!("{id}: {other:?}"),
	};

	// HTTP/1.1, with a length and chunked: the client goes away in the middle
	for (id, head) in [
		("h1-cl", "Content-Length: 1000000\r\n"),
		("h1-chunked", "Transfer-Encoding: chunked\r\n"),
	] {
		let mut tls = s.tls(&["http/1.1"]).await;
		tls.write_all(format!("POST /sink?id={id} HTTP/1.1\r\nHost: a.test\r\n{head}\r\n").as_bytes()).await.unwrap();
		let part = chunk(9, 0, 60_000);
		if id == "h1-chunked" {
			tls.write_all(format!("{:x}\r\n", part.len()).as_bytes()).await.unwrap();
			tls.write_all(part).await.unwrap();
			tls.write_all(b"\r\n").await.unwrap();
		} else {
			tls.write_all(part).await.unwrap();
		}
		tls.flush().await.unwrap();
		started(s.next_sink().await, id);
		let (tcp, _) = tls.into_inner();
		reset(tcp);
		ended(s.next_sink().await, id);
	}

	// HTTP/2: the body fails, so the client resets the stream
	let mut sender = s.h2().await;
	let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, BoxErr>>(4);
	let body = StreamBody::new(tokio_stream_from(rx)).boxed();
	let req = hyper::Request::post("https://a.test/sink?id=h2").body(body).unwrap();
	let pending = tokio::spawn(async move { sender.send_request(req).await });
	tx.send(Ok(Frame::data(Bytes::from_static(chunk(9, 1, 60_000))))).await.unwrap();
	started(s.next_sink().await, "h2");
	tx.send(Err("client gave up".into())).await.unwrap();
	ended(s.next_sink().await, "h2");
	let _ = pending.await;

	// HTTP/3: the client resets its side of the stream
	let (mut send, _ep) = s.h3().await;
	let mut stream = send.send_request(hyper::Request::post("https://a.test/sink?id=h3").body(()).unwrap()).await.unwrap();
	stream.send_data(Bytes::from_static(chunk(9, 2, 60_000))).await.unwrap();
	started(s.next_sink().await, "h3");
	stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
	ended(s.next_sink().await, "h3");
}

/// An mpsc receiver as a stream (no tokio-stream dependency).
fn tokio_stream_from<T: Send + 'static>(mut rx: mpsc::Receiver<T>) -> impl futures_util::Stream<Item = T> {
	futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_backends_and_mirrors_keep_bodies_intact() {
	// #233: an h2c backend; #232: a mirrored request's body must reach the backend unchanged
	let s = Arc::new(http_setup("integrity-h2back").await);
	let len = case_bytes() / 4;
	for proto in [Proto::H1, Proto::H2, Proto::H3] {
		let mut tasks = vec![];
		for i in 0..2u64 {
			let s = s.clone();
			tasks.push(tokio::spawn(async move {
				let seed = 300 + i;
				let mode = if i == 0 { "cl" } else { "chunked" };
				let g = s.send(proto, get(&format!("/h2/down?seed={seed}&len={len}&mode={mode}")), false).await;
				assert_eq!((g.status, &g.end), (200, &Ok(())), "{proto:?} {mode}");
				assert_eq!((g.len, hex(&g.hash)), (len, hex(&expected(seed, len))), "{proto:?} h2 download {mode}");
				let g = s.send(proto, upload(&format!("/h2/up?id={i}"), seed + 50, len, i == 0), true).await;
				let v = upload_result(&g, &format!("{proto:?} h2 upload {i}"));
				assert_eq!(v["hash"], hex(&expected(seed + 50, len)), "{proto:?} h2 upload");
				let g = s.send(proto, upload(&format!("/m/up?id=m{i}"), seed + 70, len, i == 0), true).await;
				let v = upload_result(&g, &format!("{proto:?} mirrored upload {i}"));
				assert_eq!(v["hash"], hex(&expected(seed + 70, len)), "{proto:?} mirrored upload");
			}));
		}
		for t in tasks {
			t.await.unwrap();
		}
	}
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http2_backend_cut_offs_and_route_timeouts_never_look_complete() {
	let s = http_setup("integrity-h2cut").await;
	let len = 4 << 20;
	for proto in [Proto::H1, Proto::H2, Proto::H3] {
		for mode in ["cl", "chunked"] {
			let g = s.send(proto, get(&format!("/h2/cut?seed=5&len={len}&cut={}&mode={mode}", len / 2)), false).await;
			assert_eq!(g.status, 200, "{proto:?} {mode}");
			assert!(g.end.is_err(), "{proto:?} {mode}: an h2 backend's cut body ended cleanly after {} bytes", g.len);
		}
		// #227: a body still streaming at the deadline is cut, not ended
		for path in ["/t/slow?n=20", "/tb/slow?n=20"] {
			let g = s.send(proto, get(path), false).await;
			assert_eq!(g.status, 200, "{proto:?} {path}");
			assert!(g.end.is_err(), "{proto:?} {path}: ended cleanly after {} bytes", g.len);
			assert!(g.len < 20_000, "{proto:?} {path}");
		}
	}
}
