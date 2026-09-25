// The per-client session model descends from the original rproxy project by
// glacierx and has been rewritten around cancellation tokens for rproxy-api.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::sleep_until;
use tracing::{debug, info, warn};

use crate::proxy::Runtime;
use crate::source;

const MAX_DATAGRAM: usize = 65_535;
const SESSION_QUEUE: usize = 1024;

type Sessions = Arc<Mutex<HashMap<SocketAddr, (u64, mpsc::Sender<Vec<u8>>)>>>;

pub async fn serve(socket: UdpSocket, rt: Arc<Runtime>) {
	let socket = Arc::new(socket);
	let sessions: Sessions = Arc::default();
	let next_id = AtomicU64::new(0);
	let mut buf = vec![0u8; MAX_DATAGRAM];

	loop {
		tokio::select! {
			biased;
			_ = rt.stop.cancelled() => break,
			received = socket.recv_from(&mut buf) => match received {
				Ok((n, client)) => {
					let tx = {
						let mut map = sessions.lock().unwrap();
						match map.get(&client) {
							Some((_, tx)) if !tx.is_closed() => tx.clone(),
							_ => {
								let id = next_id.fetch_add(1, Ordering::Relaxed);
								let (tx, rx) = mpsc::channel(SESSION_QUEUE);
								map.insert(client, (id, tx.clone()));
								rt.tracker.spawn(session(id, client, rx, socket.clone(), rt.clone(), sessions.clone()));
								tx
							}
						}
					};
					if tx.try_send(buf[..n].to_vec()).is_err() {
						debug!(event = "udp.drop", rule = %rt.key, client = %client);
					}
				}
				Err(e) => {
					warn!(event = "recv.error", rule = %rt.key, error = %e);
					tokio::time::sleep(Duration::from_millis(10)).await;
				}
			}
		}
	}
}

async fn session(
	id: u64,
	client: SocketAddr,
	mut from_client: mpsc::Receiver<Vec<u8>>,
	listener: Arc<UdpSocket>,
	rt: Arc<Runtime>,
	sessions: Sessions,
) {
	let started = Instant::now();
	let mut target_rx = rt.target.clone();
	let mut idle_rx = rt.udp_idle.clone();
	let mut target = target_rx.borrow_and_update().first().copied();
	let mut idle = *idle_rx.borrow_and_update();

	let upstream = match target {
		Some(t) => source::udp_upstream(t, rt.bind_as(client)).await,
		None => Err(std::io::Error::other("no resolved target")),
	};
	let upstream = match upstream {
		Ok(s) => s,
		Err(e) => {
			warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e);
			remove(&sessions, client, id);
			return;
		}
	};

	rt.stats.opened();
	info!(event = "conn.open", rule = %rt.key, client = %client, target = %addr_or_empty(target));

	let (mut rx_bytes, mut tx_bytes) = (0u64, 0u64);
	let mut buf = vec![0u8; MAX_DATAGRAM];
	let mut deadline = tokio::time::Instant::now() + idle;
	let reason = loop {
		tokio::select! {
			_ = rt.kill.cancelled() => break "stopped",
			_ = sleep_until(deadline) => break "idle",
			datagram = from_client.recv() => match datagram {
				Some(data) => {
					if let Err(e) = upstream.send(&data).await {
						debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
					}
					rx_bytes += data.len() as u64;
					deadline = tokio::time::Instant::now() + idle;
				}
				None => break "closed",
			},
			received = upstream.recv(&mut buf) => match received {
				Ok(n) => {
					if let Err(e) = listener.send_to(&buf[..n], client).await {
						debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
					}
					tx_bytes += n as u64;
					deadline = tokio::time::Instant::now() + idle;
				}
				// ICMP unreachable from the backend surfaces here on a connected socket
				Err(e) => debug!(event = "udp.recv_error", rule = %rt.key, client = %client, error = %e),
			},
			changed = target_rx.changed() => {
				if changed.is_err() {
					break "stopped";
				}
				let next = target_rx.borrow_and_update().first().copied();
				if let Some(next) = next.filter(|n| Some(*n) != target) {
					match upstream.connect(next).await {
						Ok(()) => {
							info!(event = "conn.retarget", rule = %rt.key, client = %client, from = %addr_or_empty(target), to = %next);
							target = Some(next);
						}
						Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e),
					}
				}
			},
			changed = idle_rx.changed() => {
				if changed.is_err() {
					break "stopped";
				}
				idle = *idle_rx.borrow_and_update();
				deadline = tokio::time::Instant::now() + idle;
			},
		}
	};

	remove(&sessions, client, id);
	rt.stats.closed(rx_bytes, tx_bytes);
	info!(event = "conn.close", rule = %rt.key, client = %client, target = %addr_or_empty(target),
		rx_bytes, tx_bytes, duration_ms = started.elapsed().as_millis() as u64, reason);
}

fn addr_or_empty(target: Option<SocketAddr>) -> String {
	target.map(|t| t.to_string()).unwrap_or_default()
}

fn remove(sessions: &Sessions, client: SocketAddr, id: u64) {
	let mut map = sessions.lock().unwrap();
	if map.get(&client).is_some_and(|(current, _)| *current == id) {
		map.remove(&client);
	}
}
