use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::cidr::{self, Cidr};
use crate::rule::{Key, SourceIp};
use crate::tlsconf::{name_matches, TlsRuntime, Unmatched};

#[derive(Default)]
pub struct Stats {
	/// Open connections (TCP) or sessions (UDP).
	pub active: AtomicU64,
	pub total: AtomicU64,
	/// Bytes from clients to the backend.
	pub rx_bytes: AtomicU64,
	/// Bytes from the backend to clients.
	pub tx_bytes: AtomicU64,
	/// TLS / DTLS handshakes (or STARTTLS dialogues) that failed.
	pub tls_failures: AtomicU64,
	/// Refused by allow_from or `unmatched: reject`.
	pub denied: AtomicU64,
}

impl Stats {
	pub fn opened(&self) {
		self.active.fetch_add(1, Ordering::Relaxed);
		self.total.fetch_add(1, Ordering::Relaxed);
	}

	pub fn closed(&self) {
		self.active.fetch_sub(1, Ordering::Relaxed);
	}

	/// Bytes are counted as they flow, so dashboards see long-lived
	/// connections and UDP sessions before they end.
	pub fn add_rx(&self, n: u64) {
		self.rx_bytes.fetch_add(n, Ordering::Relaxed);
	}

	pub fn add_tx(&self, n: u64) {
		self.tx_bytes.fetch_add(n, Ordering::Relaxed);
	}

	pub fn denied(&self) {
		self.denied.fetch_add(1, Ordering::Relaxed);
	}

	pub fn tls_failed(&self) {
		self.tls_failures.fetch_add(1, Ordering::Relaxed);
	}
}

/// A backend chosen by server name (TLS `sni` / `terminate` routes).
pub struct RouteTarget {
	pub pattern: String,
	pub host: String,
	pub target: watch::Receiver<Vec<SocketAddr>>,
}

/// Where one connection goes.
pub struct Target {
	pub addrs: Vec<SocketAddr>,
	/// Host name as configured, for verifying the backend's certificate.
	pub host: String,
}

/// Everything a listener and its connections need at run time.
pub struct Runtime {
	pub key: Key,
	pub source_ip: SourceIp,
	/// Current backend addresses; the first one is used for new connections.
	pub target: watch::Receiver<Vec<SocketAddr>>,
	pub remote_host: RwLock<String>,
	pub routes: RwLock<Arc<Vec<RouteTarget>>>,
	pub tls: RwLock<Arc<TlsRuntime>>,
	pub allow_from: RwLock<Arc<Vec<Cidr>>>,
	/// The rule's `crowdsec`: refuse clients blocked by the CrowdSec decisions.
	pub crowdsec: std::sync::atomic::AtomicBool,
	/// L7 routing of an `http` rule; replaced as a whole on changes.
	pub http: RwLock<Option<Arc<crate::http::server::Router>>>,
	/// `global` settings of `http` rules (trusted proxies, access log).
	pub global: Arc<crate::http::access::HttpGlobal>,
	/// Requests of an `http` rule by route.
	pub http_stats: crate::http::access::HttpStats,
	/// HTTP/3 of an `http` rule with `http3` (QUIC over UDP on the same address and port).
	pub h3: crate::http::h3::H3State,
	pub udp_idle: watch::Receiver<Duration>,
	pub stats: Stats,
	/// Stops accepting new connections.
	pub stop: CancellationToken,
	/// Closes established connections. `stop` is its child, so this stops everything.
	pub kill: CancellationToken,
	pub tracker: TaskTracker,
}

/// `addr` moved up by `offset` ports (port ranges map one to one).
pub fn shifted(addr: SocketAddr, offset: u16) -> SocketAddr {
	SocketAddr::new(addr.ip(), addr.port().wrapping_add(offset))
}

impl Runtime {
	pub fn bind_as(&self, client: SocketAddr) -> Option<SocketAddr> {
		(self.source_ip == SourceIp::Transparent).then_some(client)
	}

	pub fn http_router(&self) -> Option<Arc<crate::http::server::Router>> {
		self.http.read().unwrap().clone()
	}

	pub fn tls(&self) -> Arc<TlsRuntime> {
		self.tls.read().unwrap().clone()
	}

	/// Whether `allow_from` lets this client in.
	pub fn allowed(&self, client: std::net::IpAddr) -> bool {
		cidr::allows(&self.allow_from.read().unwrap(), client)
	}

	/// Whether the CrowdSec decisions refuse this client (rules with `crowdsec`).
	/// Until the LAPI has answered once, clients pass.
	pub fn crowdsec_blocks(&self, client: std::net::IpAddr) -> bool {
		self.crowdsec.load(Ordering::Relaxed)
			&& self.global.crowdsec().is_some_and(|b| b.check_ip(client) == crate::http::crowdsec::Verdict::Block)
	}

	/// The backend for a connection, by server name when routes are configured.
	/// None when the name matches no route and the rule rejects unmatched names.
	pub fn select(&self, server_name: Option<&str>, offset: u16) -> Option<Target> {
		let routes = self.routes.read().unwrap().clone();
		if let Some(name) = server_name {
			if let Some(route) = routes.iter().find(|r| name_matches(&r.pattern, name)) {
				return Some(Target {
					addrs: route.target.borrow().iter().map(|a| shifted(*a, offset)).collect(),
					host: route.host.clone(),
				});
			}
		}
		if !routes.is_empty() && self.tls().spec.unmatched == Unmatched::Reject {
			return None;
		}
		Some(Target {
			addrs: self.target.borrow().iter().map(|a| shifted(*a, offset)).collect(),
			host: self.remote_host.read().unwrap().clone(),
		})
	}
}

/// Counts bytes read through a stream into this connection's total and a
/// rule-wide counter. Writes pass through untouched.
pub struct Counted<'a, S: ?Sized> {
	inner: &'a mut S,
	pub count: u64,
	global: &'a AtomicU64,
}

impl<'a, S: ?Sized> Counted<'a, S> {
	pub fn new(inner: &'a mut S, global: &'a AtomicU64) -> Self {
		Counted { inner, count: 0, global }
	}
}

impl<S: tokio::io::AsyncRead + Unpin + ?Sized> tokio::io::AsyncRead for Counted<'_, S> {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		let this = self.get_mut();
		let before = buf.filled().len();
		let poll = std::pin::Pin::new(&mut *this.inner).poll_read(cx, buf);
		let n = (buf.filled().len() - before) as u64;
		if n > 0 {
			this.count += n;
			this.global.fetch_add(n, Ordering::Relaxed);
		}
		poll
	}
}

impl<S: tokio::io::AsyncWrite + Unpin + ?Sized> tokio::io::AsyncWrite for Counted<'_, S> {
	fn poll_write(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<std::io::Result<usize>> {
		std::pin::Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
	}

	fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
	}
}
