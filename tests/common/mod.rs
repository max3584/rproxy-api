//! Shared test harness: a real control API on loopback plus echo backends.
#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use rproxy_api::api::{router, AppState};
use rproxy_api::auth::Tokens;
use rproxy_api::registry::{Config, Registry};
use rproxy_api::resolve::Lookup;

/// Name → addresses served by the fake resolver (several entries = several A records).
pub type Names = Arc<Mutex<HashMap<String, Vec<SocketAddr>>>>;

pub struct Harness {
	pub base: String,
	pub http: reqwest::Client,
	pub registry: Arc<Registry>,
	pub names: Names,
}

/// Resolves IP literals directly and other hosts from `names`; unknown names fail like a DNS outage.
pub fn fake_lookup(names: Names) -> Lookup {
	Arc::new(move |target: String| {
		let names = names.clone();
		Box::pin(async move {
			if let Ok(addr) = target.parse::<SocketAddr>() {
				return Ok(vec![addr]);
			}
			let host = target.rsplit_once(':').map(|(h, _)| h).unwrap_or(&target);
			names
				.lock()
				.unwrap()
				.get(host)
				.cloned()
				.ok_or_else(|| io::Error::other("no such host"))
		})
	})
}

pub async fn harness_with(tokens: Tokens) -> Harness {
	let names: Names = Arc::default();
	let registry = Registry::new(Config {
		dns_interval: Duration::from_millis(100),
		lookup: fake_lookup(names.clone()),
		transparent: false,
	});
	let app = router(Arc::new(AppState { registry: registry.clone(), tokens: Arc::new(tokens) }));
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	Harness { base, http: reqwest::Client::new(), registry, names }
}

pub async fn harness() -> Harness {
	harness_with(Tokens::disabled()).await
}

pub fn free_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub fn free_udp_port() -> u16 {
	std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// TCP backend that answers every read with `tag` + the bytes read.
pub async fn tcp_backend(tag: &'static str) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			tokio::spawn(async move {
				let mut buf = [0u8; 1024];
				while let Ok(n) = s.read(&mut buf).await {
					if n == 0 {
						break;
					}
					let mut out = tag.as_bytes().to_vec();
					out.extend_from_slice(&buf[..n]);
					if s.write_all(&out).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

/// UDP backend that answers every datagram with `tag` + the datagram.
pub async fn udp_backend(tag: &'static str) -> SocketAddr {
	let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let addr = sock.local_addr().unwrap();
	tokio::spawn(async move {
		let mut buf = [0u8; 1024];
		loop {
			let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
			let mut out = tag.as_bytes().to_vec();
			out.extend_from_slice(&buf[..n]);
			let _ = sock.send_to(&out, peer).await;
		}
	});
	addr
}

pub fn rule(protocol: &str, port: u16, target: SocketAddr) -> Value {
	json!({
		"protocol": protocol,
		"listen_addr": "127.0.0.1",
		"listen_port": port,
		"remote_addr": target.ip().to_string(),
		"remote_port": target.port(),
	})
}

impl Harness {
	pub async fn post(&self, body: Value) -> (StatusCode, Value) {
		let r = self.http.post(format!("{}/rules", self.base)).json(&body).send().await.unwrap();
		let status = r.status();
		(status, r.json().await.unwrap_or(Value::Null))
	}

	pub async fn patch(&self, path: &str, body: Value) -> (StatusCode, Value) {
		let r = self.http.patch(format!("{}/rules/{path}", self.base)).json(&body).send().await.unwrap();
		let status = r.status();
		(status, r.json().await.unwrap_or(Value::Null))
	}

	pub async fn delete(&self, path: &str) -> StatusCode {
		self.http.delete(format!("{}/rules/{path}", self.base)).send().await.unwrap().status()
	}

	pub async fn get(&self, path: &str) -> (StatusCode, Value) {
		let r = self.http.get(format!("{}{path}", self.base)).send().await.unwrap();
		let status = r.status();
		(status, r.json().await.unwrap_or(Value::Null))
	}
}

pub async fn roundtrip(stream: &mut TcpStream, msg: &str) -> String {
	stream.write_all(msg.as_bytes()).await.unwrap();
	let mut buf = [0u8; 1024];
	let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await.unwrap().unwrap();
	String::from_utf8_lossy(&buf[..n]).into_owned()
}

pub async fn udp_roundtrip(sock: &UdpSocket, msg: &str) -> String {
	sock.send(msg.as_bytes()).await.unwrap();
	let mut buf = [0u8; 1024];
	let n = tokio::time::timeout(Duration::from_secs(2), sock.recv(&mut buf)).await.unwrap().unwrap();
	String::from_utf8_lossy(&buf[..n]).into_owned()
}

pub async fn wait_for<F: Fn(&Value) -> bool>(h: &Harness, path: &str, cond: F) -> Value {
	let deadline = Instant::now() + Duration::from_secs(3);
	loop {
		let (_, v) = h.get(path).await;
		if cond(&v) {
			return v;
		}
		assert!(Instant::now() < deadline, "condition not met, last: {v}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

