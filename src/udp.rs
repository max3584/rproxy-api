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

use webrtc_dtls::conn::DTLSConn;
use webrtc_util::conn::Conn;

use crate::dtls::SessionConn;
use crate::proxy::{shifted, Runtime};
use crate::rule::SourceIp;
use crate::source;
use crate::tlsconf::{TlsMode, TlsRuntime};

const MAX_DATAGRAM: usize = 65_535;
const SESSION_QUEUE: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

type Sessions = Arc<Mutex<HashMap<SocketAddr, (u64, mpsc::Sender<Vec<u8>>)>>>;

/// Serves one port of the rule; `offset` is its place in a range.
pub async fn serve(socket: UdpSocket, rt: Arc<Runtime>, offset: u16) {
	let socket = Arc::new(socket);
	let sessions: Sessions = Arc::default();
	let next_id = AtomicU64::new(0);
	let mut buf = vec![0u8; MAX_DATAGRAM];

	loop {
		tokio::select! {
			biased;
			_ = rt.stop.cancelled() => break,
			received = socket.recv_from(&mut buf) => match received {
				Ok((_, client)) if !rt.allowed(client.ip()) => {
					rt.stats.denied();
					debug!(event = "conn.denied", rule = %rt.key, client = %client, reason = "allow_from");
				}
				Ok((n, client)) => {
					let tx = {
						let mut map = sessions.lock().unwrap();
						match map.get(&client) {
							Some((_, tx)) if !tx.is_closed() => tx.clone(),
							_ => {
								let id = next_id.fetch_add(1, Ordering::Relaxed);
								let (tx, rx) = mpsc::channel(SESSION_QUEUE);
								map.insert(client, (id, tx.clone()));
								rt.tracker.spawn(session(id, client, rx, socket.clone(), rt.clone(), sessions.clone(), offset));
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
	offset: u16,
) {
	let tls = rt.tls();
	if tls.mode() == TlsMode::Terminate {
		return dtls_session(id, client, from_client, listener, rt, sessions, offset, tls).await;
	}
	let started = Instant::now();
	let mut target_rx = rt.target.clone();
	let mut idle_rx = rt.udp_idle.clone();
	let mut target = target_rx.borrow_and_update().first().map(|a| shifted(*a, offset));
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
	let header = proxy_header(&rt, client, &listener);

	let (mut rx_bytes, mut tx_bytes) = (0u64, 0u64);
	let mut buf = vec![0u8; MAX_DATAGRAM];
	let mut deadline = tokio::time::Instant::now() + idle;
	let reason = loop {
		tokio::select! {
			_ = rt.kill.cancelled() => break "stopped",
			_ = sleep_until(deadline) => break "idle",
			datagram = from_client.recv() => match datagram {
				Some(data) => {
					if let Err(e) = upstream.send(&with_header(&header, &data)).await {
						debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
					}
					rx_bytes += data.len() as u64;
					rt.stats.add_rx(data.len() as u64);
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
					rt.stats.add_tx(n as u64);
					deadline = tokio::time::Instant::now() + idle;
				}
				// ICMP unreachable from the backend surfaces here on a connected socket
				Err(e) => debug!(event = "udp.recv_error", rule = %rt.key, client = %client, error = %e),
			},
			changed = target_rx.changed() => {
				if changed.is_err() {
					break "stopped";
				}
				let next = target_rx.borrow_and_update().first().map(|a| shifted(*a, offset));
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
	rt.stats.closed();
	info!(event = "conn.close", rule = %rt.key, client = %client, target = %addr_or_empty(target),
		rx_bytes, tx_bytes, duration_ms = started.elapsed().as_millis() as u64, reason);
}

/// `source_ip: proxy_v2`: the PROXY v2 (DGRAM) header sent in front of every
/// datagram to the backend. The destination is the listening socket's address
/// (0.0.0.0 / :: for a wildcard listener).
fn proxy_header(rt: &Runtime, client: SocketAddr, listener: &UdpSocket) -> Option<Vec<u8>> {
	(rt.source_ip == SourceIp::ProxyV2).then(|| {
		let local = listener.local_addr().unwrap_or_else(|_| SocketAddr::new(client.ip(), 0));
		source::proxy_v2_dgram_header(client, local)
	})
}

fn with_header<'a>(header: &Option<Vec<u8>>, data: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
	match header {
		Some(h) => [h.as_slice(), data].concat().into(),
		None => data.into(),
	}
}

/// The backend side of a DTLS session: plain UDP, or DTLS again.
enum Upstream {
	Plain(Arc<UdpSocket>),
	Dtls(Box<DTLSConn>),
}

impl Upstream {
	async fn send(&self, data: &[u8]) -> Result<(), String> {
		match self {
			Upstream::Plain(s) => s.send(data).await.map(|_| ()).map_err(|e| e.to_string()),
			Upstream::Dtls(c) => c.write(data, None).await.map(|_| ()).map_err(|e| e.to_string()),
		}
	}

	async fn recv(&self, buf: &mut [u8]) -> Result<usize, String> {
		match self {
			Upstream::Plain(s) => s.recv(buf).await.map_err(|e| e.to_string()),
			Upstream::Dtls(c) => c.read(buf, None).await.map_err(|e| e.to_string()),
		}
	}
}

/// A UDP session whose client speaks DTLS to rproxy.
#[allow(clippy::too_many_arguments)]
async fn dtls_session(
	id: u64,
	client: SocketAddr,
	from_client: mpsc::Receiver<Vec<u8>>,
	listener: Arc<UdpSocket>,
	rt: Arc<Runtime>,
	sessions: Sessions,
	offset: u16,
	tls: Arc<TlsRuntime>,
) {
	let started = Instant::now();
	// before `listener` moves into the DTLS connection
	let header = proxy_header(&rt, client, &listener);
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(SessionConn::new(from_client, listener, client));
	let handshake = tokio::select! {
		_ = rt.kill.cancelled() => { remove(&sessions, client, id); return; }
		r = tokio::time::timeout(HANDSHAKE_TIMEOUT, DTLSConn::new(conn, tls.dtls_server_config(), false, None)) => r,
	};
	let dtls = match handshake {
		Ok(Ok(c)) => c,
		failed => {
			let error = match failed {
				Ok(Err(e)) => e.to_string(),
				_ => "DTLS handshake timed out".to_string(),
			};
			rt.stats.tls_failed();
			warn!(event = "tls.error", rule = %rt.key, client = %client, error = %error, dtls = true);
			remove(&sessions, client, id);
			return;
		}
	};
	let state = dtls.connection_state().await;
	if let Err(e) = tls.verify_dtls_client(&state.peer_certificates) {
		rt.stats.tls_failed();
		warn!(event = "tls.error", rule = %rt.key, client = %client, error = %e, dtls = true);
		let _ = dtls.close().await;
		remove(&sessions, client, id);
		return;
	}
	let client_cn = state.peer_certificates.first().and_then(|c| crate::tlsconf::common_name(c));

	let Some(target) = rt.select(None, offset) else {
		let _ = dtls.close().await;
		remove(&sessions, client, id);
		return;
	};
	let upstream = async {
		let addr = *target.addrs.first().ok_or("no resolved target")?;
		let socket = Arc::new(source::udp_upstream(addr, rt.bind_as(client)).await.map_err(|e| e.to_string())?);
		if !tls.spec.upstream.tls {
			return Ok::<_, String>((addr, Upstream::Plain(socket)));
		}
		let conn: Arc<dyn Conn + Send + Sync> = socket;
		let up = tokio::time::timeout(HANDSHAKE_TIMEOUT, DTLSConn::new(conn, tls.dtls_client_config(&target.host), true, None))
			.await
			.map_err(|_| "backend DTLS handshake timed out".to_string())?
			.map_err(|e| e.to_string())?;
		Ok((addr, Upstream::Dtls(Box::new(up))))
	}
	.await;
	let (addr, upstream) = match upstream {
		Ok(u) => u,
		Err(e) => {
			warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e, dtls = true);
			let _ = dtls.close().await;
			remove(&sessions, client, id);
			return;
		}
	};

	rt.stats.opened();
	info!(event = "conn.open", rule = %rt.key, client = %client, target = %addr, dtls = true,
		client_cn = client_cn.as_deref().unwrap_or(""), upstream_dtls = tls.spec.upstream.tls);

	let mut idle_rx = rt.udp_idle.clone();
	let mut idle = *idle_rx.borrow_and_update();
	let (mut rx_bytes, mut tx_bytes) = (0u64, 0u64);
	let (mut buf, mut ubuf) = (vec![0u8; MAX_DATAGRAM], vec![0u8; MAX_DATAGRAM]);
	let mut deadline = tokio::time::Instant::now() + idle;
	let reason = loop {
		tokio::select! {
			_ = rt.kill.cancelled() => break "stopped",
			_ = sleep_until(deadline) => break "idle",
			read = dtls.read(&mut buf, None) => match read {
				Ok(n) => {
					if let Err(e) = upstream.send(&with_header(&header, &buf[..n])).await {
						debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
					}
					rx_bytes += n as u64;
					rt.stats.add_rx(n as u64);
					deadline = tokio::time::Instant::now() + idle;
				}
				Err(_) => break "closed",
			},
			received = upstream.recv(&mut ubuf) => match received {
				Ok(n) => {
					if let Err(e) = dtls.write(&ubuf[..n], None).await {
						debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
					}
					tx_bytes += n as u64;
					rt.stats.add_tx(n as u64);
					deadline = tokio::time::Instant::now() + idle;
				}
				Err(e) => debug!(event = "udp.recv_error", rule = %rt.key, client = %client, error = %e),
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
	let _ = dtls.close().await;
	if let Upstream::Dtls(up) = &upstream {
		let _ = up.close().await;
	}
	remove(&sessions, client, id);
	rt.stats.closed();
	info!(event = "conn.close", rule = %rt.key, client = %client, target = %addr, dtls = true,
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
