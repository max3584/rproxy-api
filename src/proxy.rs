use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::rule::{Key, SourceIp};

#[derive(Default)]
pub struct Stats {
	/// Open connections (TCP) or sessions (UDP).
	pub active: AtomicU64,
	pub total: AtomicU64,
	/// Bytes from clients to the backend.
	pub rx_bytes: AtomicU64,
	/// Bytes from the backend to clients.
	pub tx_bytes: AtomicU64,
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
}

/// Everything a listener and its connections need at run time.
pub struct Runtime {
	pub key: Key,
	pub source_ip: SourceIp,
	/// Current backend addresses; the first one is used for new connections.
	pub target: watch::Receiver<Vec<SocketAddr>>,
	pub udp_idle: watch::Receiver<Duration>,
	pub stats: Stats,
	/// Stops accepting new connections.
	pub stop: CancellationToken,
	/// Closes established connections. `stop` is its child, so this stops everything.
	pub kill: CancellationToken,
	pub tracker: TaskTracker,
}

impl Runtime {
	pub fn bind_as(&self, client: SocketAddr) -> Option<SocketAddr> {
		(self.source_ip == SourceIp::Transparent).then_some(client)
	}
}
