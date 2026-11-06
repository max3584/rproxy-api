//! Deadlines of the L4 TCP relay (#353): the rule's `idle_timeout` ends a connection that
//! moves nothing either way (also one whose peer does not read), on plain TCP (the
//! user-space copy and, after a bulk transfer, splice: `l4::splice`) and through TLS
//! termination (`tcp.rs` `finish`), with both sides reset and `conn.close` `reason:
//! idle_timeout`; a connection that keeps moving is not ended. `half_close_timeout` after a
//! side has finished sending. The shape: both on tcp rules only.
//!
//! The splice counter is process-wide: the tests that may splice take `SPLICING` in turn.

mod common;

use std::time::{Duration, Instant};

use common::pki::Pki;
use common::*;
use reqwest::StatusCode;
use rustls::pki_types::ServerName;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Held by the tests whose connections may splice, so `spliced_bytes` moves for one only.
static SPLICING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A backend that answers nothing and hands each accepted connection to the test.
async fn silent_backend() -> (std::net::SocketAddr, mpsc::UnboundedReceiver<TcpStream>) {
	let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = l.local_addr().unwrap();
	let (tx, rx) = mpsc::unbounded_channel();
	tokio::spawn(async move {
		while let Ok((s, _)) = l.accept().await {
			let _ = tx.send(s);
		}
	});
	(addr, rx)
}

/// A backend that reads and counts everything until the end, then sends the count.
async fn sink_backend() -> std::net::SocketAddr {
	let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = l.local_addr().unwrap();
	tokio::spawn(async move {
		while let Ok((mut s, _)) = l.accept().await {
			tokio::spawn(async move {
				let mut buf = vec![0u8; 1 << 16];
				let mut n = 0u64;
				while let Ok(m) = s.read(&mut buf).await {
					if m == 0 {
						let _ = s.write_all(n.to_string().as_bytes()).await;
						return;
					}
					n += m as u64;
				}
			});
		}
	});
	addr
}

/// Reads until an error, which must be a reset.
async fn reset<S: AsyncRead + Unpin>(s: &mut S, within: Duration) {
	let mut buf = [0u8; 4096];
	loop {
		match tokio::time::timeout(within, s.read(&mut buf)).await.expect("not ended") {
			Ok(0) => panic!("closed cleanly, not reset"),
			Ok(_) => {}
			Err(e) => {
				assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}");
				return;
			}
		}
	}
}

async fn close_reason(port: u16, reason: &str) {
	let key = format!("tcp/127.0.0.1:{port}");
	logs::wait_for(reason, |v| v["event"] == "conn.close" && v["rule"] == key.as_str() && v["reason"] == reason).await;
}

async fn plain(port: u16) -> TcpStream {
	TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

/// Waits for the end of `s` (reset or EOF) and returns how long it took.
async fn ended<S: AsyncRead + Unpin>(s: &mut S, within: Duration) -> Duration {
	let t0 = Instant::now();
	let mut buf = [0u8; 64];
	loop {
		match tokio::time::timeout(within, s.read(&mut buf)).await.expect("the connection was not ended") {
			Ok(0) | Err(_) => return t0.elapsed(),
			Ok(_) => {}
		}
	}
}

async fn echo<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, msg: &str) {
	s.write_all(msg.as_bytes()).await.unwrap();
	s.flush().await.unwrap();
	let mut buf = [0u8; 256];
	let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.unwrap().unwrap();
	assert_eq!(String::from_utf8_lossy(&buf[..n]), format!(">{msg}"));
}

#[tokio::test]
async fn idle_timeout_ends_quiet_and_stalled_connections() {
	let _splicing = SPLICING.lock().await;
	logs::capture();
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["tcp_idle_timeout"], true);
	// the UI writes connect_timeout to its database only when told it is restored (#379, UI #184)
	assert_eq!(caps["features"]["db_connect_timeout"], true);
	let backend = tcp_backend(">").await;

	// plain TCP (the splice relay): ended after 1s of nothing, reset
	let port = free_port();
	let mut r = rule("tcp", port, backend);
	r["idle_timeout"] = json!("1s");
	let (status, v) = h.post(r).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["idle_timeout"], "1s", "{v}");
	let mut c = plain(port).await;
	echo(&mut c, "hello").await;
	let took = ended(&mut c, Duration::from_secs(5)).await;
	assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(3), "ended after {took:?}");
	close_reason(port, "idle_timeout").await;

	// both sides are reset, not closed as if complete
	let (quiet, mut accepted) = silent_backend().await;
	let qport = free_port();
	let mut r = rule("tcp", qport, quiet);
	r["idle_timeout"] = json!("1s");
	assert_eq!(h.post(r).await.0, StatusCode::CREATED);
	let mut c = plain(qport).await;
	c.write_all(b"hi").await.unwrap();
	let mut b = accepted.recv().await.unwrap();
	let mut got = [0u8; 2];
	b.read_exact(&mut got).await.unwrap();
	tokio::join!(reset(&mut c, Duration::from_secs(5)), reset(&mut b, Duration::from_secs(5)));
	close_reason(qport, "idle_timeout").await;

	// a connection that keeps moving is not ended
	let mut c = plain(port).await;
	let t0 = Instant::now();
	while t0.elapsed() < Duration::from_millis(2500) {
		echo(&mut c, "tick").await;
		tokio::time::sleep(Duration::from_millis(300)).await;
	}
	echo(&mut c, "still there").await;
	drop(c);

	// a backend that does not read: the client's writes stall, and the deadline ends it
	let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = free_port();
	let mut r = rule("tcp", port, stalled.local_addr().unwrap());
	r["idle_timeout"] = json!("1s");
	assert_eq!(h.post(r).await.0, StatusCode::CREATED);
	let mut c = plain(port).await;
	let (_backend_side, _) = stalled.accept().await.unwrap();
	let t0 = Instant::now();
	let w = tokio::time::timeout(Duration::from_secs(10), async {
		loop {
			if c.write_all(&[7u8; 64 * 1024]).await.is_err() {
				return;
			}
		}
	})
	.await;
	assert!(w.is_ok(), "the stalled connection was not ended");
	assert!(t0.elapsed() >= Duration::from_millis(900), "{:?}", t0.elapsed());

	// through TLS termination (the user-space relay)
	let pki = Pki::new("tcp-deadlines");
	let front = pki.server("front", &["a.test"]);
	let port = free_port();
	let mut r = rule("tcp", port, backend);
	r["idle_timeout"] = json!("1s");
	r["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}]});
	let (status, v) = h.post(r).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut c = pki.connector(None).connect(ServerName::try_from("a.test").unwrap(), plain(port).await).await.unwrap();
	echo(&mut c, "over tls").await;
	let took = ended(&mut c, Duration::from_secs(5)).await;
	assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(3), "ended after {took:?}");

	// left out: 1h (not shown); 0s: no limit
	let port = free_port();
	let (status, v) = h.post(rule("tcp", port, backend)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(v.get("idle_timeout").is_none(), "{v}");
	let path = format!("tcp/127.0.0.1/{port}");
	let (status, v) = h.patch(&path, json!({"remote_addr": "127.0.0.1", "remote_port": backend.port(), "idle_timeout": "0s"})).await;
	assert_eq!((status, v["idle_timeout"].as_str()), (StatusCode::OK, Some("0s")), "{v}");
	let (status, v) = h.patch(&path, json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()})).await;
	assert_eq!((status, v["idle_timeout"].as_str()), (StatusCode::OK, Some("0s")), "left out keeps it: {v}");
	let (status, v) = h.patch(&path, json!({"remote_addr": "127.0.0.1", "remote_port": backend.port(), "idle_timeout": "1s"})).await;
	assert_eq!((status, v["idle_timeout"].as_str()), (StatusCode::OK, Some("1s")), "{v}");
	// from the next connection
	let mut c = plain(port).await;
	echo(&mut c, "patched").await;
	ended(&mut c, Duration::from_secs(5)).await;

	// tcp rules without http only, and at least 1s
	let h = &h;
	let refused = |body: serde_json::Value| async move {
		let (status, v) = h.post(body).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
		v.to_string()
	};
	let mut udp = rule("udp", free_udp_port(), backend);
	udp["idle_timeout"] = json!("10s");
	assert!(refused(udp).await.contains("udp"));
	let mut short = rule("tcp", free_port(), backend);
	short["idle_timeout"] = json!("500ms");
	assert!(refused(short).await.contains("1s"));
	let mut bad = rule("tcp", free_port(), backend);
	bad["idle_timeout"] = json!("soon");
	assert!(refused(bad).await.contains("duration"));
	let http = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "idle_timeout": "10s",
		"http": {"routes": [{"name": "a", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:1"}]}});
	assert!(refused(http).await.contains("global.http.timeouts"));
}

/// The splice path (`l4::splice`): a bulk transfer moves on to splice, then a quiet
/// connection is still ended, and one that keeps moving through splice is not.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn idle_timeout_on_the_splice_path() {
	let _splicing = SPLICING.lock().await;
	logs::capture();
	let h = harness().await;
	let sink = sink_backend().await;
	let port = free_port();
	let mut r = rule("tcp", port, sink);
	r["idle_timeout"] = json!("1s");
	assert_eq!(h.post(r).await.0, StatusCode::CREATED);

	// past the handover (4 full 32 KiB reads in a row), then quiet: cut
	let before = rproxy_api::l4::splice::spliced_bytes();
	let mut c = plain(port).await;
	c.write_all(&vec![5u8; 8 << 20]).await.unwrap();
	let deadline = Instant::now() + Duration::from_secs(5);
	while rproxy_api::l4::splice::spliced_bytes() < before + (4 << 20) {
		assert!(Instant::now() < deadline, "the bulk transfer was not spliced");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	reset(&mut c, Duration::from_secs(5)).await;
	close_reason(port, "idle_timeout").await;

	// moving through splice for longer than idle_timeout: not cut
	let before = rproxy_api::l4::splice::spliced_bytes();
	let mut c = plain(port).await;
	let t0 = Instant::now();
	let mut sent = 0u64;
	while t0.elapsed() < Duration::from_millis(2500) {
		c.write_all(&vec![6u8; 1 << 20]).await.unwrap();
		sent += 1 << 20;
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	c.shutdown().await.unwrap();
	let mut answer = String::new();
	tokio::time::timeout(Duration::from_secs(5), c.read_to_string(&mut answer)).await.unwrap().unwrap();
	assert_eq!(answer, sent.to_string(), "every byte arrived");
	assert!(rproxy_api::l4::splice::spliced_bytes() > before, "not spliced");
}

/// `half_close_timeout`: once the client has finished sending, a backend that stays silent
/// is cut after it (`reason: half_close_timeout`); `0s` leaves only `idle_timeout`.
#[tokio::test]
async fn half_close_timeout_after_the_client_finished_sending() {
	let _splicing = SPLICING.lock().await;
	logs::capture();
	let h = harness().await;
	let (quiet, mut accepted) = silent_backend().await;
	let port = free_port();
	let mut r = rule("tcp", port, quiet);
	r["half_close_timeout"] = json!("1s");
	let (status, v) = h.post(r).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["half_close_timeout"], "1s", "{v}");
	let mut c = plain(port).await;
	c.write_all(b"request").await.unwrap();
	let mut b = accepted.recv().await.unwrap();
	let mut got = [0u8; 7];
	b.read_exact(&mut got).await.unwrap();
	// the FIN comes while the relay is running (not with its first read): the limit must
	// start from it, not from the next look at idle_timeout (1h: a minute apart)
	tokio::time::sleep(Duration::from_millis(200)).await;
	c.shutdown().await.unwrap();
	let t0 = Instant::now();
	let mut rest = Vec::new();
	b.read_to_end(&mut rest).await.unwrap();
	assert!(rest.is_empty(), "the half-close was passed on");
	reset(&mut c, Duration::from_secs(5)).await;
	let took = t0.elapsed();
	assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(3), "{took:?}");
	close_reason(port, "half_close_timeout").await;

	// `0s`: a backend that takes long to answer after the half-close (an RPC or backup tool,
	// `nc -N`) is waited for until idle_timeout
	let port = free_port();
	let mut r = rule("tcp", port, quiet);
	r["half_close_timeout"] = json!("0s");
	r["idle_timeout"] = json!("3s");
	assert_eq!(h.post(r).await.0, StatusCode::CREATED);
	let mut c = plain(port).await;
	c.write_all(b"slow").await.unwrap();
	c.shutdown().await.unwrap();
	let mut b = accepted.recv().await.unwrap();
	let mut got = Vec::new();
	b.read_to_end(&mut got).await.unwrap();
	tokio::time::sleep(Duration::from_millis(1800)).await;
	b.write_all(b"answer").await.unwrap();
	b.shutdown().await.unwrap();
	let mut answer = Vec::new();
	tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut answer)).await.unwrap().unwrap();
	assert_eq!(answer, b"answer");

	// tcp rules without http only
	let mut udp = rule("udp", free_udp_port(), quiet);
	udp["half_close_timeout"] = json!("10s");
	let (status, v) = h.post(udp).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	let mut short = rule("tcp", free_port(), quiet);
	short["half_close_timeout"] = json!("10ms");
	let (status, v) = h.post(short).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
}
