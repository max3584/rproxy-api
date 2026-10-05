//! End-to-end benchmarks over loopback: rules are created through the control
//! API exactly as in tests/ (the same harness, tests/common), then real clients
//! talk to real backends through rproxy. Run with `cargo bench --bench dataplane`;
//! CI compares a PR with its merge base (.github/workflows/bench.yml, docs/TESTING.md).
//!
//! The numbers include the clients and backends on the same machine, so they are
//! only meaningful compared with each other on one machine (base vs. head).

#[path = "../tests/common/mod.rs"]
mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::runtime::Runtime;

use common::pki::Pki;
use common::*;

/// Bytes moved per iteration of the throughput benchmarks.
const CHUNK: usize = 1024 * 1024;
const DATAGRAM: usize = 1024;

fn runtime() -> Runtime {
	tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap()
}

/// Echoes every byte back until the client closes.
async fn tcp_echo() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			// the backend must not be the one that waits (Nagle) in the measurements
			s.set_nodelay(true).unwrap();
			tokio::spawn(async move {
				let (mut r, mut w) = s.split();
				let _ = tokio::io::copy(&mut r, &mut w).await;
			});
		}
	});
	addr
}

/// Echoes every datagram back to its sender.
async fn udp_echo() -> SocketAddr {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr = sock.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = vec![0u8; 65536];
		loop {
			let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
			let _ = sock.send_to(&buf[..n], peer).await;
		}
	});
	addr
}

/// An HTTP/1.1 backend answering `ok` to everything.
async fn http_backend() -> SocketAddr {
	use axum::serve::ListenerExt;
	let app = axum::Router::new().fallback(|| async { "ok" });
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let listener = listener.tap_io(|tcp| {
		let _ = tcp.set_nodelay(true);
	});
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

async fn create(h: &Harness, body: Value) {
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
}

/// Writes `data` and reads the same number of bytes back at the same time.
async fn echo<S: tokio::io::AsyncRead + tokio::io::AsyncWrite>(s: S, data: &[u8], back: &mut [u8]) {
	let (mut r, mut w) = tokio::io::split(s);
	let (wrote, read) = tokio::join!(w.write_all(data), r.read_exact(back));
	wrote.unwrap();
	read.unwrap();
}

/// Sends `data` and waits for the answer, sending again if a datagram was lost.
async fn udp_ask(sock: &UdpSocket, data: &[u8], back: &mut [u8]) {
	for _ in 0..20 {
		sock.send(data).await.unwrap();
		if let Ok(n) = tokio::time::timeout(Duration::from_millis(250), sock.recv(back)).await {
			assert_eq!(n.unwrap(), data.len());
			return;
		}
	}
	panic!("no UDP answer through rproxy");
}

fn l4_tcp(c: &mut Criterion) {
	let rt = runtime();
	let (_h, port) = rt.block_on(async {
		let h = harness().await;
		let port = free_port();
		create(&h, rule("tcp", port, tcp_echo().await)).await;
		(h, port)
	});
	let mut g = c.benchmark_group("l4_tcp");

	let mut conn = rt.block_on(TcpStream::connect(("127.0.0.1", port))).unwrap();
	conn.set_nodelay(true).unwrap();
	let data = vec![0x5au8; CHUNK];
	let mut back = vec![0u8; CHUNK];
	g.throughput(Throughput::Bytes(CHUNK as u64));
	g.bench_function("throughput_1MiB", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					echo(&mut conn, &data, &mut back).await;
				}
				start.elapsed()
			})
		})
	});

	// a new connection each time: accept, connect to the backend, one byte each way, close
	g.throughput(Throughput::Elements(1));
	g.bench_function("connect", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
					s.write_all(b"x").await.unwrap();
					let mut one = [0u8; 1];
					s.read_exact(&mut one).await.unwrap();
				}
				start.elapsed()
			})
		})
	});
	g.finish();
}

fn l4_udp(c: &mut Criterion) {
	let rt = runtime();
	let (_h, port) = rt.block_on(async {
		let h = harness().await;
		let port = free_udp_port();
		let mut body = rule("udp", port, udp_echo().await);
		// the new_session benchmark opens thousands of sessions; let them go quickly
		body["udp_idle_secs"] = json!(1);
		create(&h, body).await;
		(h, port)
	});
	let mut g = c.benchmark_group("l4_udp");
	let data = vec![0x5au8; DATAGRAM];
	let mut back = vec![0u8; 65536];

	let sock = rt.block_on(async {
		let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		sock.connect(("127.0.0.1", port)).await.unwrap();
		sock
	});
	g.throughput(Throughput::Bytes(DATAGRAM as u64));
	g.bench_function("roundtrip_1KiB", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					udp_ask(&sock, &data, &mut back).await;
				}
				start.elapsed()
			})
		})
	});

	// a new client address each time: a new session and a new socket towards the backend
	g.throughput(Throughput::Elements(1));
	g.bench_function("new_session", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
					s.connect(("127.0.0.1", port)).await.unwrap();
					udp_ask(&s, b"x", &mut back).await;
				}
				start.elapsed()
			})
		})
	});
	g.finish();
}

fn tls_terminate(c: &mut Criterion) {
	let rt = runtime();
	let pki = Pki::new("bench");
	let cert = pki.server("front", &["bench.test"]);
	let (_h, port) = rt.block_on(async {
		let h = harness().await;
		let port = free_port();
		let mut body = rule("tcp", port, tcp_echo().await);
		body["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]});
		create(&h, body).await;
		(h, port)
	});
	// full handshakes every time (no session resumption)
	let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_safe_default_protocol_versions()
		.unwrap()
		.with_root_certificates(pki.roots())
		.with_no_client_auth();
	config.resumption = rustls::client::Resumption::disabled();
	let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
	let connect = || {
		let connector = connector.clone();
		async move {
			let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
			tcp.set_nodelay(true).unwrap();
			connector.connect("bench.test".try_into().unwrap(), tcp).await.unwrap()
		}
	};
	let mut g = c.benchmark_group("tls_terminate");

	g.throughput(Throughput::Elements(1));
	g.bench_function("handshake", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					let mut s = connect().await;
					s.write_all(b"x").await.unwrap();
					let mut one = [0u8; 1];
					s.read_exact(&mut one).await.unwrap();
				}
				start.elapsed()
			})
		})
	});

	let mut conn = rt.block_on(connect());
	let data = vec![0x5au8; CHUNK];
	let mut back = vec![0u8; CHUNK];
	g.throughput(Throughput::Bytes(CHUNK as u64));
	g.bench_function("throughput_1MiB", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					echo(&mut conn, &data, &mut back).await;
				}
				start.elapsed()
			})
		})
	});
	g.finish();
}

/// An `http` rule with a few routes and middlewares in front of `backend`; the
/// benchmarks request `/api/…`, which goes through `sec` and `strip`.
async fn http_rule(h: &Harness, backend: SocketAddr) -> u16 {
	let to = format!("http://{backend}");
	let port = free_port();
	create(
		h,
		json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"routes": [
					{"name": "admin", "match": "Host(`app.test`) && PathPrefix(`/admin/`)", "to": to, "middlewares": ["lan"]},
					{"name": "static", "match": "Host(`app.test`) && (PathPrefix(`/static/`) || PathPrefix(`/assets/`))", "to": to},
					{"name": "api", "match": "Host(`app.test`) && PathPrefix(`/api/`) && !ClientIP(`192.0.2.0/24`)", "to": to, "middlewares": ["sec", "strip"]},
					{"name": "site", "match": "Host(`app.test`)", "to": to},
				],
				"middlewares": {
					"lan": {"ip_allow": {"source_range": ["10.0.0.0/8"]}},
					"sec": {"headers": {
						"request": {"set": {"X-A": "1"}, "remove": ["X-B"]},
						"response": {"set": {"X-Served-By": "rproxy"}},
						"hsts": {"max_age": 31536000},
						"frame_deny": true,
					}},
					"strip": {"strip_prefix": {"prefixes": ["/api"]}},
				},
			},
		}),
	)
	.await;
	port
}

fn l7_http1(c: &mut Criterion) {
	let rt = runtime();
	let (_h, mut sender) = rt.block_on(async {
		let h = harness().await;
		let port = http_rule(&h, http_backend().await).await;
		let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
		tcp.set_nodelay(true).unwrap();
		let (sender, conn) = hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(tcp)).await.unwrap();
		tokio::spawn(conn);
		(h, sender)
	});
	let mut g = c.benchmark_group("l7_http1");
	g.throughput(Throughput::Elements(1));
	// keep-alive requests one after another on one connection
	g.bench_function("request", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					sender.ready().await.unwrap();
					let req = hyper::Request::get("/api/v1/items?page=2").header("host", "app.test").body(Empty::<Bytes>::new()).unwrap();
					let resp = sender.send_request(req).await.unwrap();
					assert_eq!(resp.status(), StatusCode::OK);
					assert_eq!(resp.headers()["x-served-by"], "rproxy");
					resp.into_body().collect().await.unwrap();
				}
				start.elapsed()
			})
		})
	});
	g.finish();
}

fn l7_http2(c: &mut Criterion) {
	let rt = runtime();
	let (_h, sender) = rt.block_on(async {
		let h = harness().await;
		let port = http_rule(&h, http_backend().await).await;
		// HTTP/2 with prior knowledge (h2c); the backend side stays HTTP/1.1
		let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
		tcp.set_nodelay(true).unwrap();
		let (sender, conn) = hyper::client::conn::http2::handshake::<_, _, Empty<Bytes>>(TokioExecutor::new(), TokioIo::new(tcp)).await.unwrap();
		tokio::spawn(conn);
		(h, sender)
	});
	let request = |mut sender: hyper::client::conn::http2::SendRequest<Empty<Bytes>>| async move {
		let req = hyper::Request::get("http://app.test/api/v1/items?page=2").body(Empty::<Bytes>::new()).unwrap();
		let resp = sender.send_request(req).await.unwrap();
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(resp.headers()["x-served-by"], "rproxy");
		resp.into_body().collect().await.unwrap();
	};
	let mut g = c.benchmark_group("l7_http2");

	g.throughput(Throughput::Elements(1));
	g.bench_function("request", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					request(sender.clone()).await;
				}
				start.elapsed()
			})
		})
	});

	// 32 streams at once on one connection
	const STREAMS: usize = 32;
	g.throughput(Throughput::Elements(STREAMS as u64));
	g.bench_function("concurrent_32", |b| {
		b.iter_custom(|iters| {
			rt.block_on(async {
				let start = Instant::now();
				for _ in 0..iters {
					futures_util::future::join_all((0..STREAMS).map(|_| request(sender.clone()))).await;
				}
				start.elapsed()
			})
		})
	});
	g.finish();
}

fn config() -> Criterion {
	Criterion::default().sample_size(20).warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(3))
}

criterion_group! {
	name = benches;
	config = config();
	targets = l4_tcp, l4_udp, tls_terminate, l7_http1, l7_http2
}
criterion_main!(benches);
