// The per-client session model descends from the original rproxy project by
// glacierx and has been rewritten around cancellation tokens for rproxy-api.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep_until;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use dtls::conn::DTLSConn;
use webrtc_util::conn::Conn;

use crate::core::balance::{Lease, Member};
use crate::tls::dtls::SessionConn;
use crate::core::proxy::{shifted, Runtime};
use crate::core::rule::SourceIp;
use crate::net::source;
use crate::tls::config::{TlsMode, TlsRuntime};
use crate::net::udpsock::{Listener, Local, RecvBuf};

const SESSION_QUEUE: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// `tls.mode: sni`: how long, and how many datagrams / bytes, a new session's
/// first datagrams are held while the server name is read (DTLS / QUIC).
const SNI_WAIT: Duration = Duration::from_secs(3);
const SNI_MAX_DATAGRAMS: usize = 16;
const SNI_MAX_BYTES: usize = 64 * 1024;
/// Sessions of one port reading their server name at the same time; beyond
/// this, first datagrams of new clients are dropped (they retransmit).
const SNI_MAX_PENDING: usize = 4096;

/// A session is one client (address and port) talking to one local address:
/// on a wildcard socket the same client may reach the rule at several addresses
/// (IPv4 and IPv6, or several IPv6 addresses), and each is answered from its own.
type Peer = (SocketAddr, Option<Local>);
type Sessions = Arc<Mutex<HashMap<Peer, (u64, mpsc::Sender<Vec<u8>>)>>>;

/// Serves one port of the rule; `offset` is its place in a range.
/// `stop` ends it: the rule's `stop`, or the address being taken off the rule.
pub async fn serve(socket: UdpSocket, rt: Arc<Runtime>, offset: u16, stop: CancellationToken) {
	let socket = Arc::new(Listener::new(socket));
	let sessions: Sessions = Arc::default();
	let sniffing: Arc<AtomicUsize> = Arc::default();
	let next_id = AtomicU64::new(0);
	let mut buf = RecvBuf::new();

	loop {
		tokio::select! {
			biased;
			_ = stop.cancelled() => break,
			received = socket.recv(&mut buf) => match received {
				Ok((_, client, _)) if !rt.allowed(client.ip()) => {
					rt.stats.denied();
					debug!(event = "conn.denied", rule = %rt.key, client = %client, reason = "allow_from");
				}
				// also datagrams of sessions that were open before the ban
				Ok((_, client, _)) if rt.crowdsec_blocks(client.ip()) => {
					rt.stats.denied();
					debug!(event = "conn.denied", rule = %rt.key, client = %client, reason = "crowdsec");
				}
				Ok((n, client, local)) => {
					let tx = {
						let mut map = sessions.lock().unwrap();
						match map.get(&(client, local)) {
							Some((_, tx)) if !tx.is_closed() => tx.clone(),
							_ => {
								let id = next_id.fetch_add(1, Ordering::Relaxed);
								let (tx, rx) = mpsc::channel(SESSION_QUEUE);
								map.insert((client, local), (id, tx.clone()));
								rt.tracker.spawn(run_session(id, (client, local), rx, socket.clone(), rt.clone(), sessions.clone(), offset, sniffing.clone()));
								tx
							}
						}
					};
					if tx.try_send(buf[..n].to_vec()).is_err() {
						rt.stats.dropped();
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

/// One client's session. With `tls.mode: sni`, a new QUIC connection from the
/// same client socket to another server name starts it over with the new name.
#[allow(clippy::too_many_arguments)]
async fn run_session(
	id: u64,
	peer: Peer,
	mut from_client: mpsc::Receiver<Vec<u8>>,
	listener: Arc<Listener>,
	rt: Arc<Runtime>,
	sessions: Sessions,
	offset: u16,
	sniffing: Arc<AtomicUsize>,
) {
	let tls = rt.tls();
	if tls.mode() == TlsMode::Terminate {
		return dtls_session(id, peer, from_client, listener, rt, sessions, offset, tls).await;
	}
	let mut carry = vec![];
	while let Some(next) = session(id, peer, &mut from_client, &listener, &rt, &sessions, offset, &sniffing, carry).await {
		carry = next;
	}
}

/// A plain (not DTLS-terminating) UDP session. `carry`: datagrams already read
/// that start it (a new QUIC connection that ended the previous session).
/// Returns them when a new QUIC connection to another name should start over.
#[allow(clippy::too_many_arguments)]
async fn session(
	id: u64,
	peer: Peer,
	from_client: &mut mpsc::Receiver<Vec<u8>>,
	listener: &Arc<Listener>,
	rt: &Arc<Runtime>,
	sessions: &Sessions,
	offset: u16,
	sniffing: &AtomicUsize,
	carry: Vec<Vec<u8>>,
) -> Option<Vec<Vec<u8>>> {
	let (client, local) = peer;
	let tls = rt.tls();
	let started = Instant::now();
	let mut events = rt.pool_events.subscribe();
	let mut idle_rx = rt.udp_idle.clone();
	let mut idle = *idle_rx.borrow_and_update();
	let bind_as = rt.bind_as(client);
	// `tls.mode: sni` (#130): hold the first datagrams until the server name is read
	let by_name = tls.mode() == TlsMode::Sni;
	let (sni, first) = if by_name {
		let Some(sniffed) = sniff(rt, from_client, sniffing, carry).await else {
			remove(sessions, peer, id);
			return None;
		};
		sniffed
	} else {
		(None, carry)
	};
	let picked = if by_name {
		match rt.select(sni.as_deref(), offset) {
			None => {
				rt.stats.denied();
				info!(event = "conn.denied", rule = %rt.key, client = %client, reason = "unmatched", sni = sni.as_deref().unwrap_or(""));
				// swallow the rest of this client's datagrams until it goes quiet,
				// rather than reading every one of them again as a new session
				drain(rt, from_client, idle).await;
				remove(sessions, peer, id);
				return None;
			}
			// a `tls.routes` backend: its addresses as resolved now
			Some(t) if t.pool.is_none() => t
				.candidates
				.iter()
				.flat_map(|c| c.addrs.iter())
				.copied()
				.find(|a| source::usable(*a, bind_as))
				.map(|addr| Picked { lease: None, addrs: None, addr }),
			Some(_) => pick(rt, offset, bind_as),
		}
	} else {
		pick(rt, offset, bind_as)
	};
	let Some(Picked { mut lease, addrs: mut target_rx, addr }) = picked else {
		warn!(event = "conn.error", rule = %rt.key, client = %client, error = "no resolved target", sni = sni.as_deref().unwrap_or(""));
		remove(sessions, peer, id);
		return None;
	};
	let mut target = Some(addr);

	let upstream = match source::udp_upstream(addr, rt.bind_as(client)).await {
		Ok(s) => s,
		Err(e) => {
			warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e);
			remove(sessions, peer, id);
			return None;
		}
	};

	rt.stats.opened();
	info!(event = "conn.open", rule = %rt.key, listen = %listener.local_for(local), client = %client, target = %addr_or_empty(target),
		sni = sni.as_deref().unwrap_or(""));
	let header = proxy_header(rt, client, listener.local_for(local));
	// sni: the QUIC connection this session was routed for, and a new one being read
	let mut quic_dcid = first.iter().find_map(|d| crate::tls::udp_sni::quic::initial_dcid(d));
	let mut probe: Option<Probe> = None;
	let mut restart = None;

	let (mut rx_bytes, mut tx_bytes) = (0u64, 0u64);
	// the datagrams held while reading the server name, in order
	for data in &first {
		if let Err(e) = upstream.send(&with_header(&header, data)).await {
			rt.stats.dropped();
			debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
		}
		rx_bytes += data.len() as u64;
		rt.stats.add_rx(data.len() as u64);
	}
	let mut buf = RecvBuf::new();
	let mut deadline = tokio::time::Instant::now() + idle;
	let reason = loop {
		tokio::select! {
			_ = rt.kill.cancelled() => break "stopped",
			_ = sleep_until(deadline) => break "idle",
			// a new QUIC connection that did not show its name in time: treat it as ours
			_ = async { match &probe { Some(p) => sleep_until(p.until).await, None => std::future::pending().await } } => {
				for data in probe.take().map(|p| p.held).unwrap_or_default() {
					if let Err(e) = upstream.send(&with_header(&header, &data)).await {
						rt.stats.dropped();
						debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
					}
					rx_bytes += data.len() as u64;
					rt.stats.add_rx(data.len() as u64);
				}
			},
			datagram = from_client.recv() => match datagram {
				Some(data) => {
					deadline = tokio::time::Instant::now() + idle;
					let forward = if by_name {
						match renamed(&mut probe, &mut quic_dcid, sni.as_deref(), data) {
							Step::Forward(d) => d,
							Step::Hold => continue,
							Step::Restart(held) => {
								restart = Some(held);
								break "new connection";
							}
						}
					} else {
						vec![data]
					};
					for data in forward {
						if let Err(e) = upstream.send(&with_header(&header, &data)).await {
							rt.stats.dropped();
							debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
						}
						rx_bytes += data.len() as u64;
						rt.stats.add_rx(data.len() as u64);
					}
				}
				None => break "closed",
			},
			received = upstream.recv(&mut buf) => match received {
				Ok(n) => {
					if let Err(e) = listener.send_to(&buf[..n], client, local).await {
						rt.stats.dropped();
						debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
					}
					tx_bytes += n as u64;
					rt.stats.add_tx(n as u64);
					deadline = tokio::time::Instant::now() + idle;
				}
				// ICMP unreachable from the backend surfaces here on a connected socket
				Err(e) => {
					debug!(event = "udp.recv_error", rule = %rt.key, client = %client, error = %e);
					if let (std::io::ErrorKind::ConnectionRefused, Some(lease)) = (e.kind(), &lease) {
						let pool = rt.pool();
						if pool.contains(lease.member()) {
							pool.mark_failed(&rt.key, lease.member(), &e.to_string());
						}
					}
				}
			},
			// a target went down (or the targets changed): move off it
			changed = events.changed() => {
				if changed.is_err() {
					break "stopped";
				}
				// a `tls.routes` backend (sni) is not in the pool
				let Some(member) = lease.as_ref().map(|l| l.member().clone()) else { continue };
				if rt.pool().contains(&member) && member.is_up() {
					continue;
				}
				let Some(next) = pick(rt, offset, bind_as).filter(|p| !p.lease.as_ref().is_some_and(|l| Arc::ptr_eq(l.member(), &member))) else { continue };
				match upstream.connect(next.addr).await {
					Ok(()) => {
						info!(event = "conn.retarget", rule = %rt.key, client = %client, from = %addr_or_empty(target), to = %next.addr,
							reason = "target down");
						target = Some(next.addr);
						target_rx = next.addrs;
						lease = next.lease;
					}
					Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e),
				}
			},
			changed = async { match target_rx.as_mut() { Some(rx) => rx.changed().await, None => std::future::pending().await } } => {
				if changed.is_err() {
					break "stopped";
				}
				let Some(rx) = target_rx.as_mut() else { continue };
				let next = rx.borrow_and_update().iter().map(|a| shifted(*a, offset)).find(|a| source::usable(*a, bind_as));
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

	if restart.is_none() {
		remove(sessions, peer, id);
	}
	drop(lease);
	rt.stats.closed();
	info!(event = "conn.close", rule = %rt.key, client = %client, target = %addr_or_empty(target),
		rx_bytes, tx_bytes, duration_ms = started.elapsed().as_millis() as u64, reason);
	restart
}

/// `tls.mode: sni`: a new QUIC connection (an Initial with another Destination
/// Connection ID) from a client socket that already has a session, while its
/// server name is being read. Its datagrams are held meanwhile.
struct Probe {
	dcid: Vec<u8>,
	sniffer: crate::tls::udp_sni::Sniffer,
	held: Vec<Vec<u8>>,
	until: tokio::time::Instant,
}

enum Step {
	/// Send these on to the session's backend.
	Forward(Vec<Vec<u8>>),
	/// Held while a new connection's name is read.
	Hold,
	/// A new connection to another name: start the session over with these.
	Restart(Vec<Vec<u8>>),
}

/// Sessions are kept per client address and port, but a QUIC client (quinn, for
/// one) may open its next connection from the same socket, to another name. A
/// new connection to the same name (or one after a Retry, or whose name cannot
/// be read) stays on this session's backend.
fn renamed(probe: &mut Option<Probe>, quic_dcid: &mut Option<Vec<u8>>, name: Option<&str>, data: Vec<u8>) -> Step {
	use crate::tls::udp_sni::Sniff;
	if probe.is_none() {
		match crate::tls::udp_sni::quic::initial_dcid(&data) {
			Some(dcid) if quic_dcid.as_deref() != Some(dcid.as_slice()) => {
				*probe = Some(Probe {
					dcid,
					sniffer: crate::tls::udp_sni::Sniffer::default(),
					held: vec![],
					until: tokio::time::Instant::now() + SNI_WAIT,
				});
			}
			_ => return Step::Forward(vec![data]),
		}
	}
	let Some(p) = probe.as_mut() else { return Step::Forward(vec![data]) };
	let seen = p.sniffer.push(&data);
	p.held.push(data);
	let new_name = match seen {
		Sniff::NeedMore if p.held.len() < SNI_MAX_DATAGRAMS => return Step::Hold,
		Sniff::Done(n) => n,
		_ => None,
	};
	let Some(p) = probe.take() else { return Step::Hold };
	match new_name {
		Some(n) if Some(n.as_str()) != name => Step::Restart(p.held),
		_ => {
			*quic_dcid = Some(p.dcid);
			Step::Forward(p.held)
		}
	}
}

/// The target of a session and its addresses (None for a `tls.routes` backend,
/// which is not one of the rule's targets).
struct Picked {
	lease: Option<Lease>,
	addrs: Option<watch::Receiver<Vec<SocketAddr>>>,
	addr: SocketAddr,
}

/// The target for a new session, or for one whose target went down: the best
/// one (by `balance`) that has addresses.
/// The best target for a new session; with `transparent` (`bind_as`), only one
/// of the client's address family.
fn pick(rt: &Runtime, offset: u16, bind_as: Option<SocketAddr>) -> Option<Picked> {
	rt.pool().order().into_iter().find_map(|m: Arc<Member>| {
		let addr = m.addrs(offset).into_iter().find(|a| source::usable(*a, bind_as))?;
		let mut addrs = m.addrs.clone();
		addrs.borrow_and_update();
		Some(Picked { lease: Some(Lease::new(m)), addrs: Some(addrs), addr })
	})
}

/// Holds a new session's first datagrams until its server name is read (DTLS /
/// QUIC, `udp_sni`), for at most `SNI_WAIT` and `SNI_MAX_*`. The name (None when
/// there is none or it cannot be read) and the datagrams, which must still be
/// sent on. None: the rule stopped, or too many sessions are reading their name.
async fn sniff(
	rt: &Runtime,
	from_client: &mut mpsc::Receiver<Vec<u8>>,
	sniffing: &AtomicUsize,
	carry: Vec<Vec<u8>>,
) -> Option<(Option<String>, Vec<Vec<u8>>)> {
	use crate::tls::udp_sni::{Sniff, Sniffer};
	struct Pending<'a>(&'a AtomicUsize);
	impl Drop for Pending<'_> {
		fn drop(&mut self) {
			self.0.fetch_sub(1, Ordering::Relaxed);
		}
	}
	if sniffing.fetch_add(1, Ordering::Relaxed) >= SNI_MAX_PENDING {
		sniffing.fetch_sub(1, Ordering::Relaxed);
		rt.stats.dropped();
		debug!(event = "udp.drop", rule = %rt.key, reason = "too many sessions reading their server name");
		return None;
	}
	let _pending = Pending(sniffing);
	let mut sniffer = Sniffer::default();
	let (mut first, mut bytes) = (Vec::new(), 0usize);
	let deadline = tokio::time::Instant::now() + SNI_WAIT;
	let mut carry = carry.into_iter();
	loop {
		let datagram = match carry.next() {
			Some(d) => d,
			None => tokio::select! {
				_ = rt.kill.cancelled() => return None,
				_ = sleep_until(deadline) => return Some((None, first)),
				d = from_client.recv() => d?,
			},
		};
		let seen = sniffer.push(&datagram);
		bytes += datagram.len();
		first.push(datagram);
		match seen {
			Sniff::Done(name) => return Some((name, first)),
			Sniff::Unknown => return Some((None, first)),
			Sniff::NeedMore if first.len() >= SNI_MAX_DATAGRAMS || bytes >= SNI_MAX_BYTES => return Some((None, first)),
			Sniff::NeedMore => {}
		}
	}
}

/// Drops a refused client's datagrams until it is idle for `idle`.
async fn drain(rt: &Runtime, from_client: &mut mpsc::Receiver<Vec<u8>>, idle: Duration) {
	loop {
		tokio::select! {
			_ = rt.kill.cancelled() => return,
			_ = tokio::time::sleep(idle) => return,
			d = from_client.recv() => if d.is_none() { return },
		}
	}
}

/// `source_ip: proxy_v2`: the PROXY v2 (DGRAM) header sent in front of every
/// datagram to the backend. The destination is the address the client sent to
/// (learnt on a wildcard listener).
fn proxy_header(rt: &Runtime, client: SocketAddr, local: SocketAddr) -> Option<Vec<u8>> {
	(rt.source_ip == SourceIp::ProxyV2).then(|| source::proxy_v2_dgram_header(client, local))
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
	peer: Peer,
	from_client: mpsc::Receiver<Vec<u8>>,
	listener: Arc<Listener>,
	rt: Arc<Runtime>,
	sessions: Sessions,
	offset: u16,
	tls: Arc<TlsRuntime>,
) {
	let (client, local) = peer;
	let started = Instant::now();
	// before `listener` moves into the DTLS connection
	let listen = listener.local_for(local);
	let header = proxy_header(&rt, client, listen);
	let conn: Arc<dyn Conn + Send + Sync> = Arc::new(SessionConn::new(from_client, listener, client, local));
	let handshake = tokio::select! {
		_ = rt.kill.cancelled() => { remove(&sessions, peer, id); return; }
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
			remove(&sessions, peer, id);
			return;
		}
	};
	let state = dtls.connection_state().await;
	if let Err(e) = tls.verify_dtls_client(&state.peer_certificates) {
		rt.stats.tls_failed();
		warn!(event = "tls.error", rule = %rt.key, client = %client, error = %e, dtls = true);
		let _ = dtls.close().await;
		remove(&sessions, peer, id);
		return;
	}
	let client_cn = state.peer_certificates.first().and_then(|c| crate::tls::config::common_name(c));

	let Some(target) = rt.select(None, offset) else {
		let _ = dtls.close().await;
		remove(&sessions, peer, id);
		return;
	};
	let Some(chosen) = target.candidates.iter().find(|c| !c.addrs.is_empty()) else {
		warn!(event = "conn.error", rule = %rt.key, client = %client, error = "no resolved target", dtls = true);
		let _ = dtls.close().await;
		remove(&sessions, peer, id);
		return;
	};
	let _lease = chosen.lease();
	let upstream = async {
		let addr = chosen.addrs[0];
		let socket = Arc::new(source::udp_upstream(addr, rt.bind_as(client)).await.map_err(|e| e.to_string())?);
		if !tls.spec.upstream.tls {
			return Ok::<_, String>((addr, Upstream::Plain(socket)));
		}
		let conn: Arc<dyn Conn + Send + Sync> = socket;
		let up = tokio::time::timeout(HANDSHAKE_TIMEOUT, DTLSConn::new(conn, tls.dtls_client_config(&chosen.host), true, None))
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
			remove(&sessions, peer, id);
			return;
		}
	};

	rt.stats.opened();
	info!(event = "conn.open", rule = %rt.key, listen = %listen, client = %client, target = %addr, dtls = true,
		client_cn = client_cn.as_deref().unwrap_or(""), upstream_dtls = tls.spec.upstream.tls);

	let mut idle_rx = rt.udp_idle.clone();
	let mut idle = *idle_rx.borrow_and_update();
	let (mut rx_bytes, mut tx_bytes) = (0u64, 0u64);
	let (mut buf, mut ubuf) = (RecvBuf::new(), RecvBuf::new());
	let mut deadline = tokio::time::Instant::now() + idle;
	let reason = loop {
		tokio::select! {
			_ = rt.kill.cancelled() => break "stopped",
			_ = sleep_until(deadline) => break "idle",
			read = dtls.read(&mut buf, None) => match read {
				Ok(n) => {
					if let Err(e) = upstream.send(&with_header(&header, &buf[..n])).await {
						rt.stats.dropped();
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
						rt.stats.dropped();
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
	remove(&sessions, peer, id);
	rt.stats.closed();
	info!(event = "conn.close", rule = %rt.key, client = %client, target = %addr, dtls = true,
		rx_bytes, tx_bytes, duration_ms = started.elapsed().as_millis() as u64, reason);
}

fn addr_or_empty(target: Option<SocketAddr>) -> String {
	target.map(|t| t.to_string()).unwrap_or_default()
}

fn remove(sessions: &Sessions, peer: Peer, id: u64) {
	let mut map = sessions.lock().unwrap();
	if map.get(&peer).is_some_and(|(current, _)| *current == id) {
		map.remove(&peer);
	}
}
