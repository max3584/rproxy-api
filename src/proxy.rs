use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::rule::{Key, SourceIp};
use crate::tlsconf::{name_matches, TlsRuntime};

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
}

impl Stats {
	pub fn opened(&self) {
		self.active.fetch_add(1, Ordering::Relaxed);
		self.total.fetch_add(1, Ordering::Relaxed);
	}

	pub fn closed(&self, rx: u64, tx: u64) {
		self.active.fetch_sub(1, Ordering::Relaxed);
		self.rx_bytes.fetch_add(rx, Ordering::Relaxed);
		self.tx_bytes.fetch_add(tx, Ordering::Relaxed);
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

	pub fn tls(&self) -> Arc<TlsRuntime> {
		self.tls.read().unwrap().clone()
	}

	/// The backend for a connection, by server name when routes are configured.
	pub fn select(&self, server_name: Option<&str>, offset: u16) -> Target {
		if let Some(name) = server_name {
			let routes = self.routes.read().unwrap().clone();
			if let Some(route) = routes.iter().find(|r| name_matches(&r.pattern, name)) {
				return Target {
					addrs: route.target.borrow().iter().map(|a| shifted(*a, offset)).collect(),
					host: route.host.clone(),
				};
			}
		}
		Target {
			addrs: self.target.borrow().iter().map(|a| shifted(*a, offset)).collect(),
			host: self.remote_host.read().unwrap().clone(),
		}
	}
}
