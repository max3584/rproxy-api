//! The L4 TCP relay (`l4::relay`, #185): an idle connection holds no buffer, a
//! busy one does, and an end (FIN, close_notify) is passed on as a half-close in
//! either direction, on plain TCP and through TLS termination.
//!
//! One test function: the buffer count is process-wide, so nothing else may run
//! relays at the same time in this binary.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use rproxy_api::l4::relay::buffers_in_use;
use rustls::pki_types::ServerName;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::pki::Pki;
use common::*;

async fn plain(port: u16) -> TcpStream {
	TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

/// Waits until `cond` holds on the number of lent relay buffers.
async fn buffers_become(what: &str, cond: impl Fn(usize) -> bool) {
	let deadline = Instant::now() + Duration::from_secs(5);
	while !cond(buffers_in_use()) {
		assert!(Instant::now() < deadline, "{what}: {} relay buffers in use", buffers_in_use());
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

async fn echo<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, msg: &[u8]) {
	s.write_all(msg).await.unwrap();
	s.flush().await.unwrap();
	let mut buf = vec![0u8; msg.len() + 16];
	let mut got = 0;
	while got < msg.len() + 1 {
		let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf[got..])).await.unwrap().unwrap();
		assert!(n > 0, "closed early");
		got += n;
	}
	assert_eq!(&buf[1..got], msg);
}

/// A backend that ends its side first: it sends `hello` and a FIN, then reads
/// what the client sends until the client's end, and answers how much that was
/// on the channel.
async fn ends_first() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<usize>) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			let tx = tx.clone();
			tokio::spawn(async move {
				s.write_all(b"hello").await.unwrap();
				s.shutdown().await.unwrap();
				let mut got = vec![];
				s.read_to_end(&mut got).await.unwrap();
				let _ = tx.send(got.len());
			});
		}
	});
	(addr, rx)
}

/// The backend ended first: the client reads `hello` and the end, then still sends.
async fn client_after_backend_end<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, rx: &mut tokio::sync::mpsc::UnboundedReceiver<usize>) {
	let mut got = vec![];
	tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut got)).await.unwrap().unwrap();
	assert_eq!(got, b"hello");
	let data = vec![7u8; 200_000];
	s.write_all(&data).await.unwrap();
	s.shutdown().await.unwrap();
	let n = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
	assert_eq!(n, data.len(), "what the client sent after the backend's end arrives whole");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_buffers_and_half_closes() {
	let h = harness().await;
	let pki = Pki::new("relay-buffers");
	let front = pki.server("front", &["a.test"]);
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}]});
	let connector = pki.connector(None);
	let name = || ServerName::try_from("a.test").unwrap();

	// idle connections, plain and TLS, hold no buffer once their data has passed
	let backend = tcp_backend(">").await;
	let plain_port = free_port();
	assert_eq!(h.post(rule("tcp", plain_port, backend)).await.0, StatusCode::CREATED);
	let mut tls_rule = rule("tcp", free_port(), backend);
	tls_rule["tls"] = tls.clone();
	let tls_port = tls_rule["listen_port"].as_u64().unwrap() as u16;
	assert_eq!(h.post(tls_rule).await.0, StatusCode::CREATED);
	let mut plain_conns = vec![];
	for i in 0..50 {
		let mut c = plain(plain_port).await;
		echo(&mut c, format!("plain {i}").as_bytes()).await;
		plain_conns.push(c);
	}
	let mut tls_conns = vec![];
	for i in 0..20 {
		let mut c = connector.connect(name(), plain(tls_port).await).await.unwrap();
		echo(&mut c, format!("tls {i}").as_bytes()).await;
		tls_conns.push(c);
	}
	buffers_become("70 idle connections", |n| n == 0).await;
	// and they still work afterwards
	echo(&mut plain_conns[3], b"again").await;
	echo(&mut tls_conns[3], b"again").await;
	buffers_become("idle again", |n| n == 0).await;
	drop((plain_conns, tls_conns));

	// a busy connection (the backend does not read) holds a buffer until it ends
	let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let stalled_addr = stalled.local_addr().unwrap();
	let port = free_port();
	assert_eq!(h.post(rule("tcp", port, stalled_addr)).await.0, StatusCode::CREATED);
	let mut c = plain(port).await;
	let (backend_side, _) = stalled.accept().await.unwrap();
	let writer = tokio::spawn(async move {
		let _ = c.write_all(&vec![1u8; 16 << 20]).await;
		c
	});
	buffers_become("a connection with data in flight", |n| n >= 1).await;
	drop(backend_side);
	let c = writer.await.unwrap();
	drop(c);
	buffers_become("after the busy connection ended", |n| n == 0).await;

	// half-close, the backend ending first: plain, then through TLS termination
	let (b, mut rx) = ends_first().await;
	let port = free_port();
	assert_eq!(h.post(rule("tcp", port, b)).await.0, StatusCode::CREATED);
	client_after_backend_end(plain(port).await, &mut rx).await;
	let mut r = rule("tcp", free_port(), b);
	r["tls"] = tls.clone();
	let port = r["listen_port"].as_u64().unwrap() as u16;
	assert_eq!(h.post(r).await.0, StatusCode::CREATED);
	client_after_backend_end(connector.connect(name(), plain(port).await).await.unwrap(), &mut rx).await;

	// half-close, the client ending first, through TLS termination (plain is in tests/integrity.rs)
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let b = listener.local_addr().unwrap();
	tokio::spawn(async move {
		let (mut s, _) = listener.accept().await.unwrap();
		let mut got = vec![];
		s.read_to_end(&mut got).await.unwrap();
		s.write_all(format!("got {}", got.len()).as_bytes()).await.unwrap();
		s.shutdown().await.unwrap();
	});
	let mut r = rule("tcp", free_port(), b);
	r["tls"] = tls;
	let port = r["listen_port"].as_u64().unwrap() as u16;
	assert_eq!(h.post(r).await.0, StatusCode::CREATED);
	let mut c = connector.connect(name(), plain(port).await).await.unwrap();
	c.write_all(&vec![9u8; 300_000]).await.unwrap();
	c.shutdown().await.unwrap();
	let mut got = vec![];
	tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut got)).await.unwrap().unwrap();
	assert_eq!(got, b"got 300000");

	buffers_become("everything closed", |n| n == 0).await;
}
