use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::rule::Key;

const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send>>;

/// Name lookup, swappable so tests can simulate a DNS outage.
pub type Lookup = Arc<dyn Fn(String) -> LookupFuture + Send + Sync>;

pub fn system_lookup() -> Lookup {
	Arc::new(|target: String| {
		Box::pin(async move { Ok(tokio::net::lookup_host(target).await?.collect()) })
	})
}

pub fn is_ip_literal(host: &str) -> bool {
	host.parse::<IpAddr>().is_ok()
}

/// Resolves `host:port` into a sorted, de-duplicated address list.
pub async fn resolve(lookup: &Lookup, target: &str) -> Result<Vec<SocketAddr>, ApiError> {
	let result = tokio::time::timeout(LOOKUP_TIMEOUT, lookup(target.to_string()))
		.await
		.map_err(|_| ApiError::resolve_failed(format!("{target}: lookup timed out")))?;
	let mut addrs = result.map_err(|e| ApiError::resolve_failed(format!("{target}: {e}")))?;
	addrs.sort();
	addrs.dedup();
	if addrs.is_empty() {
		return Err(ApiError::resolve_failed(format!("{target}: no addresses")));
	}
	Ok(addrs)
}

/// Re-resolves `target` every `interval` and publishes changes on `tx`.
/// When a lookup fails, the last good answer stays in `tx` (the cache).
pub fn spawn_refresh(
	key: Key,
	target: String,
	lookup: Lookup,
	interval: Duration,
	tx: Arc<watch::Sender<Vec<SocketAddr>>>,
	cancel: CancellationToken,
) -> JoinHandle<()> {
	tokio::spawn(async move {
		loop {
			tokio::select! {
				_ = cancel.cancelled() => break,
				_ = tokio::time::sleep(interval) => {}
			}
			match resolve(&lookup, &target).await {
				Ok(addrs) => {
					if *tx.borrow() != addrs {
						info!(event = "dns.change", rule = %key, target = %target, resolved = ?addrs);
						tx.send_replace(addrs);
					}
				}
				Err(e) => {
					warn!(event = "dns.stale", rule = %key, target = %target, error = %e.message, cached = ?*tx.borrow());
				}
			}
		}
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::rule::Protocol;
	use std::sync::atomic::{AtomicBool, Ordering};

	fn key() -> Key {
		Key { protocol: Protocol::Tcp, listen: "127.0.0.1:1".parse().unwrap() }
	}

	#[tokio::test]
	async fn keeps_cached_answer_while_dns_is_down() {
		let down = Arc::new(AtomicBool::new(false));
		let flag = down.clone();
		let lookup: Lookup = Arc::new(move |_| {
			let down = flag.load(Ordering::SeqCst);
			Box::pin(async move {
				if down {
					Err(io::Error::other("dns down"))
				} else {
					Ok(vec!["10.0.0.2:80".parse().unwrap(), "10.0.0.1:80".parse().unwrap()])
				}
			})
		});

		let first = resolve(&lookup, "svc:80").await.unwrap();
		assert_eq!(first[0], "10.0.0.1:80".parse().unwrap(), "answers are sorted");

		let (tx, rx) = watch::channel(first.clone());
		let tx = Arc::new(tx);
		down.store(true, Ordering::SeqCst);
		let cancel = CancellationToken::new();
		let task = spawn_refresh(key(), "svc:80".into(), lookup, Duration::from_millis(10), tx, cancel.clone());
		tokio::time::sleep(Duration::from_millis(60)).await;
		assert_eq!(*rx.borrow(), first);
		cancel.cancel();
		task.await.unwrap();
	}

	#[tokio::test]
	async fn empty_answer_is_an_error() {
		let lookup: Lookup = Arc::new(|_| Box::pin(async { Ok(vec![]) }));
		assert_eq!(resolve(&lookup, "svc:80").await.unwrap_err().code, "resolve_failed");
	}
}
