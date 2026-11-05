//! Deadlines of the L4 TCP relay (#353): the rule's `idle_timeout` ends a connection that
//! moves nothing either way (also one whose peer does not read), on plain TCP (splice,
//! `l4::splice`) and through TLS termination (`tcp.rs` `finish`), with both sides reset; a
//! connection that keeps moving is not ended. The shape: `idle_timeout` on tcp rules only.

mod common;

use std::time::{Duration, Instant};

use common::pki::Pki;
use common::*;
use reqwest::StatusCode;
use rustls::pki_types::ServerName;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["tcp_idle_timeout"], true);
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
