// The per-client session model descends from the original rproxy project by
// glacierx and has been rewritten around cancellation tokens for rproxy-api.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep_until;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use dtls::conn::DTLSConn;
use webrtc_util::conn::Conn;

use crate::core::balance::{Lease, Member};
use crate::core::bandwidth::{Bandwidth, Dir, Gate};
use crate::core::budget::Ticket;
use crate::core::limits::{self, Limiter, Permit, Reason};
use crate::tls::dtls::SessionConn;
use crate::core::proxy::{shifted, Runtime};
use crate::core::rule::SourceIp;
use crate::net::proxy_in::{self, peer_field};
use crate::net::source;
use crate::logging::{clip, throttled, udp_errors};
use crate::tls::config::{TlsMode, TlsRuntime};
use crate::net::udpsock::{Batch, Listener, Local, Meta, RecvBuf, BATCH};

const SESSION_QUEUE: usize = 1024;
/// The bytes of datagrams one session's queue is sized for (#354): a datagram waits only
/// while the queue holds fewer than this many bytes' worth of datagrams of its size, so
/// large datagrams queue less deep. The datagram at place k of the queue is then smaller
/// than this / k, so the queue holds at most about 4.5 times this (9 MiB; the count of
/// 1024 alone allowed 64 MiB), with no count of bytes kept on the way of each datagram.
const SESSION_QUEUE_BYTES: usize = 2 << 20;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A session that has not seen a reply from its backend (DTLS terminate: has not finished
/// its handshake) ends after this without datagrams (conntrack's unreplied, #354): a spoofed
/// source sends one datagram and is never heard from again. `udp_idle` once replied.
pub const UNREPLIED_TIMEOUT: Duration = Duration::from_secs(5);
/// `tls.mode: sni`: how long, and how many datagrams / bytes, a new session's
/// first datagrams are held while the server name is read (DTLS / QUIC).
const SNI_WAIT: Duration = Duration::from_secs(3);
const SNI_MAX_DATAGRAMS: usize = 16;
const SNI_MAX_BYTES: usize = 64 * 1024;
/// Sessions of one port reading their server name over more than one datagram
/// at the same time (`SniSlots`); beyond this the oldest is given up.
const SNI_MAX_PENDING: usize = 4096;
/// ... of them from one source prefix (`SOURCE_PREFIX_V4` / `_V6`, also the prefixes of
/// `Unreplied`); beyond this, the prefix's own oldest is given up for the new one,
/// whatever the others do (#332).
const SNI_MAX_PENDING_PER_PREFIX: usize = 64;
const SOURCE_PREFIX_V4: u8 = 24;
const SOURCE_PREFIX_V6: u8 = 48;
/// Sessions of a rule without `limits.max_connections` (#332 L3): a flood from
/// spoofed sources could otherwise open a backend socket per source until `udp_idle`.
/// `RPROXY_UDP_MAX_SESSIONS` (`set_max_sessions`), 0 for none.
pub const DEFAULT_MAX_SESSIONS: u64 = 16_384;
static MAX_SESSIONS: AtomicU64 = AtomicU64::new(DEFAULT_MAX_SESSIONS);

/// The sessions a udp rule without `limits.max_connections` may have (0: no limit).
/// Read for each new session, so it can be set at any time (startup).
pub fn set_max_sessions(max: u64) {
	MAX_SESSIONS.store(max, Ordering::Relaxed);
}

pub fn max_sessions() -> u64 {
	MAX_SESSIONS.load(Ordering::Relaxed)
}

/// A session is one client (address and port) talking to one local address:
/// on a wildcard socket the same client may reach the rule at several addresses
/// (IPv4 and IPv6, or several IPv6 addresses), and each is answered from its own.
/// With `proxy_protocol` (#312), datagrams from a front end in `from` carry the
/// client in a PROXY v2 header: the session is (front end's address and port, local
/// address, the header's client), and replies go back to the front end's address and
/// port, without a header. A header naming another client from the same front end
/// port is another session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peer {
	/// Where the datagrams come from, and replies go.
	from: SocketAddr,
	local: Option<Local>,
	/// The client named by a PROXY header; None: `from` is the client.
	named: Option<SocketAddr>,
}

impl Peer {
	/// The client: who `allow_from`, `limits`, the logs and the backend see.
	fn client(&self) -> SocketAddr {
		self.named.unwrap_or(self.from)
	}

	/// The front end that sent the PROXY header (`proxy_peer` of the logs).
	fn via(&self) -> Option<SocketAddr> {
		self.named.map(|_| self.from)
	}
}

// Without a header the key hashes as the (address, local) pair it was before #312:
// nothing more is hashed for every datagram of a rule without `proxy_protocol`.
impl std::hash::Hash for Peer {
	fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
		self.from.hash(state);
		self.local.hash(state);
		if let Some(named) = self.named {
			named.hash(state);
		}
	}
}

/// A shard's sessions: the id of each (a newer session of the same peer replaces it) and its queue.
type Table = HashMap<Peer, (u64, mpsc::Sender<Vec<u8>>)>;
type Sessions = Arc<Mutex<Table>>;

/// The table of a shard, whatever a panic left it in: a session's entry is put in and
/// taken out whole under the lock, so a poisoned table is still consistent (#354).
fn lock(sessions: &Sessions) -> std::sync::MutexGuard<'_, Table> {
	sessions.lock().unwrap_or_else(|e| e.into_inner())
}

/// Queues a client's datagram for its session; false when the queue is full: 1024
/// datagrams, or `SESSION_QUEUE_BYTES` worth of datagrams of its own size waiting ahead
/// of it. One atomic load (`capacity`).
fn enqueue(tx: &mpsc::Sender<Vec<u8>>, data: &[u8]) -> bool {
	let waiting = SESSION_QUEUE - tx.capacity();
	waiting < (SESSION_QUEUE_BYTES / data.len().max(1)).min(SESSION_QUEUE) && tx.try_send(data.to_vec()).is_ok()
}

/// What the sessions of one socket share.
struct Shard {
	listener: Arc<Listener>,
	sessions: Sessions,
	sniffing: Arc<SniSlots>,
	/// The port's place in a range.
	offset: u16,
	/// Ends the shard's sessions: the rule's `kill`, or its address taken off the rule
	/// (`extra_listen_addrs`), which ends `serve` but not the rule.
	ended: CancellationToken,
}

/// Takes a session out of its shard's table when it ends, however it ends (a panic too).
struct Registered {
	sessions: Sessions,
	peer: Peer,
	id: u64,
}

impl Drop for Registered {
	fn drop(&mut self) {
		let mut map = lock(&self.sessions);
		if map.get(&self.peer).is_some_and(|(current, _)| *current == self.id) {
			map.remove(&self.peer);
		}
	}
}

/// A rule's UDP sessions that have not seen a reply from their backend yet (DTLS terminate:
/// not through the handshake), oldest first (#354). When the rule's default cap
/// (`MAX_SESSIONS`) or the process's descriptors (`core::budget`) are taken, one of them
/// makes room for the new session instead of the new one being refused: a flood from
/// spoofed sources then pushes out only its own kind, and sessions that are answered stay.
/// They are also kept by source prefix (IPv4 /24, IPv6 /48, as `SniSlots`, #366), so that a
/// flood from one network pushes out its own: a prefix holds at most `per_prefix` of the
/// rule's (past that, its own oldest goes for the new one), and at a cap the new session's
/// prefix gives up its own oldest unless the oldest of all is of a prefix that holds more.
#[derive(Default)]
pub struct Unreplied {
	/// Which of a session's counts (`Waiting::live`) is of this queue: 0 the rule's, 1 the process's.
	slot: usize,
	table: Mutex<UnrepliedTable>,
}

#[derive(Default)]
struct UnrepliedTable {
	/// Oldest first; done ones are skipped when evicting, and cleared out now and then.
	order: VecDeque<Arc<Waiting>>,
	by_prefix: HashMap<IpAddr, PrefixQueue>,
	/// The prefix that held the most when it last took one (a hint: its count may have gone down since).
	heaviest: Option<(IpAddr, Arc<AtomicUsize>)>,
}

/// The sessions of one source prefix in one `Unreplied`.
#[derive(Default)]
struct PrefixQueue {
	/// Those not done yet: counted down by the session itself (`Waiting::finish`), no lock taken.
	live: Arc<AtomicUsize>,
	/// Oldest first, done ones among them as in `order`.
	order: VecDeque<Arc<Waiting>>,
}

struct Waiting {
	/// Replied, ended or evicted: no longer one to evict.
	done: AtomicBool,
	evicted: AtomicBool,
	/// The session's own stop (a child of its shard's `ended`).
	stop: CancellationToken,
	/// Its prefix's `PrefixQueue::live` in its rule's queue and in the process's.
	live: [Arc<AtomicUsize>; 2],
}

impl Waiting {
	/// Done (replied, ended or evicted); false when it was already.
	fn finish(&self) -> bool {
		if self.done.swap(true, Ordering::Relaxed) {
			return false;
		}
		for live in &self.live {
			live.fetch_sub(1, Ordering::Relaxed);
		}
		true
	}

	fn is_done(&self) -> bool {
		self.done.load(Ordering::Relaxed)
	}

	fn evict(&self) -> bool {
		if !self.finish() {
			return false;
		}
		self.evicted.store(true, Ordering::Relaxed);
		self.stop.cancel();
		true
	}
}

/// Every rule's sessions not replied to yet, oldest first: the process's descriptors
/// (`core::budget`) are shared by all rules, so one of all makes room there.
static ALL_UNREPLIED: std::sync::LazyLock<Unreplied> = std::sync::LazyLock::new(|| Unreplied { slot: 1, table: Mutex::default() });

/// One source prefix holds at most this share of a rule's sessions not replied to (of
/// `MAX_SESSIONS`, or of the process's descriptors when that is 0), and at least
/// `UNREPLIED_PER_PREFIX_MIN` (#366).
const UNREPLIED_PER_PREFIX_SHARE: u64 = 16;
const UNREPLIED_PER_PREFIX_MIN: u64 = 64;

fn unreplied_per_prefix() -> usize {
	let cap = match MAX_SESSIONS.load(Ordering::Relaxed) {
		0 => crate::core::budget::limit(),
		max => max,
	};
	usize::try_from((cap / UNREPLIED_PER_PREFIX_SHARE).max(UNREPLIED_PER_PREFIX_MIN)).unwrap_or(usize::MAX)
}

impl UnrepliedTable {
	/// `prefix`'s count of sessions not done, made if it has none.
	fn live(&mut self, prefix: IpAddr) -> Arc<AtomicUsize> {
		// prefixes with none left are cleared out now and then (amortised)
		if !self.by_prefix.contains_key(&prefix) && self.by_prefix.len() >= 64 && self.by_prefix.len().is_power_of_two() {
			self.by_prefix.retain(|_, q| q.live.load(Ordering::Relaxed) > 0);
		}
		self.by_prefix.entry(prefix).or_default().live.clone()
	}

	/// `state` of `prefix`, counted in `live` already.
	fn push(&mut self, prefix: IpAddr, live: &Arc<AtomicUsize>, state: Arc<Waiting>) {
		let held = live.load(Ordering::Relaxed);
		if self.heaviest.as_ref().is_none_or(|(p, most)| *p == prefix || most.load(Ordering::Relaxed) < held) {
			self.heaviest = Some((prefix, live.clone()));
		}
		if self.order.len() >= 64 && self.order.len().is_power_of_two() {
			self.order.retain(|w| !w.is_done());
		}
		self.order.push_back(state.clone());
		let queue = self.by_prefix.entry(prefix).or_default();
		while queue.order.front().is_some_and(|w| w.is_done()) {
			queue.order.pop_front();
		}
		if queue.order.len() >= 64 && queue.order.len().is_power_of_two() {
			queue.order.retain(|w| !w.is_done());
		}
		queue.order.push_back(state);
	}

	/// The oldest of all not done yet.
	fn oldest(&mut self) -> Option<&Arc<Waiting>> {
		while self.order.front().is_some_and(|w| w.is_done()) {
			self.order.pop_front();
		}
		self.order.front()
	}

	/// Ends the oldest session of `prefix` not done yet; false when it has none.
	fn evict_in(&mut self, prefix: IpAddr) -> bool {
		let Some(queue) = self.by_prefix.get_mut(&prefix) else { return false };
		while let Some(w) = queue.order.pop_front() {
			if w.evict() {
				return true;
			}
		}
		false
	}
}

impl Unreplied {
	fn lock(&self) -> std::sync::MutexGuard<'_, UnrepliedTable> {
		self.table.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// A new session of `client`, in its rule's queue and in the process's (`ALL_UNREPLIED`).
	/// When its prefix already holds `unreplied_per_prefix` of the rule's, the oldest of them goes.
	fn track(&self, client: IpAddr, stop: CancellationToken) -> Mark {
		self.track_in(client, stop, true)
	}

	/// A new session of `client` that holds no descriptor (the DPDK path, #366): in its rule's
	/// queue only. It ends when it is evicted (`Mark::evicted`) or its `Mark` is dropped.
	#[cfg_attr(not(feature = "dpdk"), allow(dead_code))]
	pub(crate) fn track_without_descriptor(&self, client: IpAddr) -> Mark {
		self.track_in(client, CancellationToken::new(), false)
	}

	fn track_in(&self, client: IpAddr, stop: CancellationToken, descriptor: bool) -> Mark {
		let prefix = limits::source_key(client, SOURCE_PREFIX_V4, SOURCE_PREFIX_V6);
		let mut rule = self.lock();
		let mut all = descriptor.then(|| ALL_UNREPLIED.lock());
		let live = [rule.live(prefix), all.as_mut().map_or_else(Arc::default, |all| all.live(prefix))];
		if live[0].load(Ordering::Relaxed) >= unreplied_per_prefix() {
			rule.evict_in(prefix);
		}
		for live in &live {
			live.fetch_add(1, Ordering::Relaxed);
		}
		let state = Arc::new(Waiting { done: AtomicBool::new(false), evicted: AtomicBool::new(false), stop, live });
		rule.push(prefix, &state.live[0], state.clone());
		if let Some(all) = all.as_mut() {
			all.push(prefix, &state.live[1], state.clone());
		}
		Mark(state)
	}

	/// Whether there may be one to evict (a quick look before spending a source's `limits`).
	pub(crate) fn any(&self) -> bool {
		self.lock().oldest().is_some()
	}

	/// Ends a session not replied to, to make room for a new one of `client`; false when there
	/// is none. Of the new one's own prefix, the one that held the most (`heaviest`) and the
	/// prefix of the oldest of all, the one holding the most gives up its oldest (the new one's
	/// own first, then the oldest of all, when they hold as many): a flood from one network evicts its own, and a client
	/// of another network makes room at the flood's cost, not at that of the others. Three
	/// counts read, no walk over the prefixes.
	pub(crate) fn evict_for(&self, client: IpAddr) -> bool {
		let prefix = limits::source_key(client, SOURCE_PREFIX_V4, SOURCE_PREFIX_V6);
		let mut t = self.lock();
		let Some(oldest) = t.oldest().cloned() else { return false };
		let own = t.by_prefix.get(&prefix).map_or(0, |q| q.live.load(Ordering::Relaxed));
		let (heaviest, most) = t.heaviest.as_ref().map_or((prefix, 0), |(p, live)| (*p, live.load(Ordering::Relaxed)));
		let first = oldest.live[self.slot].load(Ordering::Relaxed);
		let evicted = if own > 0 && own >= most && own >= first {
			t.evict_in(prefix)
		} else {
			most > first && t.evict_in(heaviest)
		};
		evicted || oldest.evict()
	}

	#[cfg(test)]
	fn waiting(&self) -> usize {
		self.lock().order.iter().filter(|w| !w.is_done()).count()
	}
}

/// A session's place in its rule's `Unreplied`, and its stop.
pub(crate) struct Mark(Arc<Waiting>);

impl Mark {
	/// The backend answered (DTLS: the handshake is through): not one to evict any more.
	pub(crate) fn replied(&self) {
		self.0.finish();
	}

	fn is_replied(&self) -> bool {
		self.0.is_done()
	}

	fn stop(&self) -> &CancellationToken {
		&self.0.stop
	}

	/// Evicted to make room for a new session (`Unreplied::evict_for`).
	#[cfg_attr(not(feature = "dpdk"), allow(dead_code))]
	pub(crate) fn evicted(&self) -> bool {
		self.0.evicted.load(Ordering::Relaxed)
	}

	/// Why a stopped session ended.
	fn stopped(&self) -> &'static str {
		if self.0.evicted.load(Ordering::Relaxed) { "evicted" } else { "stopped" }
	}
}

impl Drop for Mark {
	fn drop(&mut self) {
		self.0.finish();
	}
}

/// What the shards of one port share: the sessions reading their server name
/// (`SNI_MAX_PENDING` is for the port, not for each shard), and the size of each
/// shard's receive batch.
pub struct Port {
	sniffing: Arc<SniSlots>,
	batch: usize,
}

impl Port {
	/// A port of a rule with `ports` ports: a range gets smaller batches (down to
	/// one datagram), as each slot can hold up to 64 KiB once a large datagram
	/// came through it (10 000 ports of 32 slots would take GBs).
	pub fn new(ports: u16) -> Self {
		Port {
			sniffing: Arc::new(SniSlots::new(SNI_MAX_PENDING, SNI_MAX_PENDING_PER_PREFIX)),
			batch: (64 / usize::from(ports.max(1))).clamp(1, BATCH),
		}
	}
}

/// The slots of the sessions of one port that hold their first datagrams while their
/// server name comes in more than one datagram (`sniff`; a ClientHello in one datagram,
/// the usual case, takes none). Sources can be spoofed (#332): one prefix (IPv4 /24,
/// IPv6 /48) holds at most `per_prefix` of them, so a flood from one network cannot
/// take the slots of the others. Past that, the prefix's own oldest slot is given up
/// for the new one, and when all are taken (a flood from everywhere) the oldest of all:
/// a new session is never refused, so a client (of the flooded network too) still gets
/// its next datagram in, unless the flood takes that many slots in the meantime.
struct SniSlots {
	max: usize,
	per_prefix: usize,
	table: Mutex<SniTable>,
}

#[derive(Default)]
struct SniTable {
	taken: usize,
	/// The live slots of each prefix, oldest first (at most `per_prefix`).
	by_prefix: HashMap<IpAddr, VecDeque<Arc<SlotState>>>,
	/// Slots in the order they were taken; given back ones are skipped (and cleared out now and then).
	order: VecDeque<Arc<SlotState>>,
}

struct SlotState {
	prefix: IpAddr,
	/// Given back or given up (under the table's lock).
	done: AtomicBool,
	/// Cancelled when it is given up for a newer one.
	given_up: CancellationToken,
}

/// A session's slot while it reads its server name; given back on drop.
struct SniSlot {
	slots: Arc<SniSlots>,
	state: Arc<SlotState>,
}

impl SniTable {
	fn give_back(&mut self, state: &SlotState) {
		if state.done.swap(true, Ordering::Relaxed) {
			return;
		}
		self.taken -= 1;
		if let Some(slots) = self.by_prefix.get_mut(&state.prefix) {
			slots.retain(|s| !std::ptr::eq(Arc::as_ptr(s), state));
			if slots.is_empty() {
				self.by_prefix.remove(&state.prefix);
			}
		}
	}

	/// Gives `state` up for a newer slot: its session ends.
	fn give_up(&mut self, state: &SlotState) {
		if !state.done.load(Ordering::Relaxed) {
			self.give_back(state);
			state.given_up.cancel();
		}
	}
}

impl SniSlots {
	fn new(max: usize, per_prefix: usize) -> Self {
		SniSlots { max: max.max(1), per_prefix, table: Mutex::default() }
	}

	/// A slot for a session of `client`, giving up the oldest of its prefix (or of all) when full.
	fn take(self: &Arc<Self>, client: IpAddr) -> SniSlot {
		let prefix = limits::source_key(client, SOURCE_PREFIX_V4, SOURCE_PREFIX_V6);
		let mut t = self.table.lock().unwrap_or_else(|e| e.into_inner());
		while t.by_prefix.get(&prefix).is_some_and(|slots| slots.len() >= self.per_prefix.max(1)) {
			let Some(oldest) = t.by_prefix.get_mut(&prefix).and_then(VecDeque::pop_front) else { break };
			t.give_up(&oldest);
		}
		while t.taken >= self.max {
			let Some(oldest) = t.order.pop_front() else { break };
			t.give_up(&oldest);
		}
		if t.order.len() >= 2 * self.max {
			t.order.retain(|s| !s.done.load(Ordering::Relaxed));
		}
		let state = Arc::new(SlotState { prefix, done: AtomicBool::new(false), given_up: CancellationToken::new() });
		t.order.push_back(state.clone());
		t.taken += 1;
		t.by_prefix.entry(prefix).or_default().push_back(state.clone());
		SniSlot { slots: self.clone(), state }
	}
}

impl Drop for SniSlot {
	fn drop(&mut self) {
		self.slots.table.lock().unwrap_or_else(|e| e.into_inner()).give_back(&self.state);
	}
}

/// A session counted in its rule's `stats.udp_sessions` (the default cap, `MAX_SESSIONS`), in
/// its `limits` (`Permit`) and in the process's descriptors (`core::budget`, its backend
/// socket), until it ends; and its place among the sessions not replied to yet.
struct Admitted {
	_permit: Option<Permit>,
	_counted: Counted,
	_ticket: Ticket,
	mark: Mark,
}

pub(crate) struct Counted(Arc<Runtime>);

impl Drop for Counted {
	fn drop(&mut self) {
		self.0.stats.udp_sessions.fetch_sub(1, Ordering::Relaxed);
	}
}

/// Counts a new session of the rule, and whether it is over the default cap
/// (`MAX_SESSIONS`), which a rule's own `limits.max_connections` replaces.
pub(crate) fn count_session(rt: &Arc<Runtime>, limiter: Option<&Limiter>) -> (Counted, bool) {
	let before = rt.stats.udp_sessions.fetch_add(1, Ordering::Relaxed);
	let counted = Counted(rt.clone());
	let max = MAX_SESSIONS.load(Ordering::Relaxed);
	(counted, !(max == 0 || before < max || limiter.is_some_and(|l| l.max_connections().is_some())))
}

/// The descriptor of a new session's backend socket from the process's budget; when it is
/// all taken, the oldest session of any rule not replied to gives its up (`Ticket::force`:
/// counted over until that session has ended, a moment later, within half the budget's
/// reserve). None: none to give.
fn session_ticket(client: IpAddr) -> Option<Ticket> {
	Ticket::take(1).or_else(|| if ALL_UNREPLIED.evict_for(client) { Ticket::force(1) } else { None })
}

/// Serves one socket of one port of the rule; `offset` is the port's place in a
/// range. A port has one socket per shard (`SO_REUSEPORT`, #194), each with its
/// own sessions: the kernel sends a client's datagrams to the same socket, so
/// the shards share no table and take no lock of each other.
/// `stop` ends it: the rule's `stop`, or the address being taken off the rule, which
/// also ends the address's sessions (#354).
/// In a graceful shutdown (`core::shutdown::draining`), `stop` only ends new
/// sessions: the open ones go on (their datagrams come in here) until the
/// rule's `kill`.
pub async fn serve(socket: UdpSocket, port: Arc<Port>, rt: Arc<Runtime>, offset: u16, stop: CancellationToken) {
	let shard = Arc::new(Shard {
		listener: Arc::new(Listener::new(socket)),
		sessions: Arc::default(),
		sniffing: port.sniffing.clone(),
		offset,
		ended: rt.kill.child_token(),
	});
	let socket = shard.listener.clone();
	let next_id = AtomicU64::new(0);
	let mut batch = Batch::new(port.batch);
	let mut draining = false;

	loop {
		tokio::select! {
			biased;
			_ = stop.cancelled(), if !draining => {
				if !crate::core::shutdown::draining() {
					break;
				}
				draining = true;
			}
			_ = rt.kill.cancelled(), if draining => break,
			received = socket.recv_batch(&mut batch) => match received {
				Ok(_) => {
					// `limits` (#165) and `proxy_protocol` (#312): None after one relaxed load when the rule has none
					let limiter = rt.limits.get();
					let pp = rt.proxy_protocol.get();
					let mut map = lock(&shard.sessions);
					let mut one = |peer: Peer, data: &[u8]| {
						let client = peer.client();
						if !rt.allowed(client.ip()) {
							denied(&rt, client, "allow_from");
							return;
						}
						// also datagrams of sessions that were open before the rule's geoip changed
						if let Err(info) = rt.geoip_check(client.ip()) {
							rt.geoip_denied(client, &info, None, true);
							return;
						}
						// also datagrams of sessions that were open before the ban
						if rt.crowdsec_blocks(client.ip()) {
							denied(&rt, client, "crowdsec");
							return;
						}
						if limiter.as_ref().is_some_and(|l| !l.packet(client.ip())) {
							limits::refused(&rt, client, Reason::Packets, "udp");
							return;
						}
						let tx = match map.get(&peer) {
							Some((_, tx)) if !tx.is_closed() => tx.clone(),
							_ if draining => {
								// shutting down: no new sessions
								rt.stats.dropped();
								return;
							}
							_ => {
								let Some(tx) = open(&rt, &shard, &mut map, &next_id, peer, data, limiter.as_deref()) else { return };
								tx
							}
						};
						if !enqueue(&tx, data) {
							rt.stats.dropped();
							debug!(event = "udp.drop", rule = %rt.key, client = %client);
						}
					};
					for (data, Meta { from, local, .. }) in batch.iter() {
						let Some(pp) = pp.as_deref() else {
							one(Peer { from, local, named: None }, data);
							continue;
						};
						// the PROXY header is read and stripped; the checks and logs are of the client it names
						match proxy_in::datagram(pp, from.ip(), data) {
							Ok((None, skip)) => one(Peer { from, local, named: None }, &data[skip..]),
							Ok((named, skip)) => {
								let peer = Peer { from, local, named };
								proxy_in::sync_with_peer(peer.via(), || one(peer, &data[skip..]));
							}
							Err(refusal) => header_denied(&rt, from, refusal),
						}
					}
				}
				Err(e) => {
					warn!(event = "recv.error", rule = %rt.key, error = %e);
					tokio::time::sleep(Duration::from_millis(10)).await;
				}
			}
		}
	}
	// the address was taken off the rule (the rule itself goes on): its sessions end with it
	if !rt.stop.is_cancelled() {
		shard.ended.cancel();
	}
}

/// A new session for the first datagram of `peer`: within the limits, or the datagram is
/// dropped (None).
#[allow(clippy::too_many_arguments)]
fn open(
	rt: &Arc<Runtime>,
	shard: &Arc<Shard>,
	map: &mut Table,
	next_id: &AtomicU64,
	peer: Peer,
	data: &[u8],
	limiter: Option<&Limiter>,
) -> Option<mpsc::Sender<Vec<u8>>> {
	let client = peer.client();
	// every target full (#341): no session (with `tls.routes`, the route's
	// targets are looked at once the name is read)
	if rt.pool().all_full() && rt.routes.read().unwrap_or_else(|e| e.into_inner()).is_empty() {
		limits::refused(rt, client, Reason::TargetFull, "udp");
		return None;
	}
	// DTLS terminate (#354): only a ClientHello starts a session, so stray or spoofed records
	// of other kinds take nothing
	if rt.tls().mode() == TlsMode::Terminate && !crate::tls::dtls::opens_handshake(data) {
		rt.stats.dropped();
		debug!(event = "udp.drop", rule = %rt.key, client = %client, reason = "not a DTLS ClientHello");
		return None;
	}
	// the default cap first: a datagram refused there spends nothing of the source's `limits`;
	// at the cap, room is made only when there is a session to evict
	let (counted, over) = count_session(rt, limiter);
	if over && !rt.udp_unreplied.any() {
		limits::refused(rt, client, Reason::MaxConnections, "udp");
		return None;
	}
	let permit = match limiter.map(|l| l.admit(client.ip())) {
		None => None,
		Some(Ok(p)) => Some(p),
		Some(Err(reason)) => {
			limits::refused(rt, client, reason, "udp");
			return None;
		}
	};
	// within the source's own limits: only now does an older session make room (#354)
	if over && !rt.udp_unreplied.evict_for(client.ip()) {
		limits::refused(rt, client, Reason::MaxConnections, "udp");
		return None;
	}
	let Some(ticket) = session_ticket(client.ip()) else {
		limits::refused(rt, client, Reason::FdBudget, "udp");
		return None;
	};
	let mark = rt.udp_unreplied.track(client.ip(), shard.ended.child_token());
	let admitted = Admitted { _permit: permit, _counted: counted, _ticket: ticket, mark };
	let id = next_id.fetch_add(1, Ordering::Relaxed);
	let (tx, rx) = mpsc::channel(SESSION_QUEUE);
	map.insert(peer, (id, tx.clone()));
	let registered = Registered { sessions: shard.sessions.clone(), peer, id };
	let session = run_session(peer, rx, shard.clone(), rt.clone(), admitted, registered);
	rt.tracker.spawn(proxy_in::with_peer(peer.via(), session));
	Some(tx)
}

/// A refused datagram: counted always, logged like TCP's refusals but at most
/// `Throttle`'s rate per client (`suppressed`: lines left out before this one).
fn denied(rt: &Runtime, client: SocketAddr, reason: &'static str) {
	rt.stats.denied();
	match rt.denied_log.check(&client.ip()) {
		Some(suppressed) => info!(event = "conn.denied", rule = %rt.key, client = %client, reason, sni = "", suppressed, proxy_peer = peer_field()),
		None => debug!(event = "conn.denied", rule = %rt.key, client = %client, reason, throttled = true),
	}
}

/// A datagram refused for its PROXY header (`proxy_protocol`, #312): from a front end
/// in `from`, none while `required` or a bad one; from outside `from`, one at all.
/// Counted and logged as TCP's refusals, at most `Throttle`'s rate per peer.
fn header_denied(rt: &Runtime, peer: SocketAddr, refusal: proxy_in::Refusal) {
	rt.stats.denied();
	let (reason, version) = (refusal.reason, refusal.version.map(|v| v.as_str()));
	match rt.denied_log.check(&peer.ip()) {
		Some(suppressed) => warn!(event = "conn.denied", rule = %rt.key, client = %peer, reason, error = refusal.why, version, sni = "", suppressed),
		None => debug!(event = "conn.denied", rule = %rt.key, client = %peer, reason, error = refusal.why, throttled = true),
	}
}

/// One client's session. With `tls.mode: sni`, a new QUIC connection from the
/// same client socket to another server name starts it over with the new name.
/// `admitted` counts the session in the rule's `limits` and default cap until it ends;
/// `registered` takes it out of the shard's table then.
async fn run_session(
	peer: Peer,
	mut from_client: mpsc::Receiver<Vec<u8>>,
	shard: Arc<Shard>,
	rt: Arc<Runtime>,
	admitted: Admitted,
	registered: Registered,
) {
	let _registered = registered;
	let tls = rt.tls();
	if tls.mode() == TlsMode::Terminate {
		return dtls_session(peer, from_client, &shard, rt, tls, admitted).await;
	}
	let mut carry = vec![];
	while let Some(next) = session(peer, &mut from_client, &shard, &rt, &admitted.mark, carry).await {
		carry = next;
	}
}

/// When a plain session ends without datagrams (#354). It is established once the backend
/// has replied and the client has sent more than one datagram: a spoofed source sends one
/// and never hears the reply, however readily the backend (DNS, a game server, QUIC)
/// answers it. Until then it ends `UNREPLIED_TIMEOUT` after the client's last datagram,
/// the backend's datagrams do not keep it, and it stays one to evict at the caps
/// (`Unreplied`). Established, `udp_idle` after the last datagram either way.
struct Quiet {
	idle: Duration,
	/// The backend has replied.
	answered: bool,
	/// Datagrams from the client.
	from_client: u64,
	last: tokio::time::Instant,
}

impl Quiet {
	/// A session's clock, established already when an earlier run of it was (`Mark::is_replied`).
	fn new(idle: Duration, mark: &Mark, first: usize) -> Self {
		let established = mark.is_replied();
		Quiet { idle, answered: established, from_client: if established { first.max(2) } else { first } as u64, last: tokio::time::Instant::now() }
	}

	fn established(&self) -> bool {
		self.answered && self.from_client > 1
	}

	fn deadline(&self) -> tokio::time::Instant {
		self.last + if self.established() { self.idle } else { self.idle.min(UNREPLIED_TIMEOUT) }
	}

	fn client(&mut self, datagrams: usize, mark: &Mark) {
		self.from_client += datagrams as u64;
		self.last = tokio::time::Instant::now();
		self.settle(mark);
	}

	fn backend(&mut self, mark: &Mark) {
		self.answered = true;
		if self.established() {
			self.last = tokio::time::Instant::now();
		}
		self.settle(mark);
	}

	fn settle(&self, mark: &Mark) {
		if self.established() {
			mark.replied();
		}
	}
}

/// A plain (not DTLS-terminating) UDP session. `carry`: datagrams already read
/// that start it (a new QUIC connection that ended the previous session).
/// Returns them when a new QUIC connection to another name should start over.
async fn session(
	peer: Peer,
	from_client: &mut mpsc::Receiver<Vec<u8>>,
	shard: &Shard,
	rt: &Arc<Runtime>,
	mark: &Mark,
	carry: Vec<Vec<u8>>,
) -> Option<Vec<Vec<u8>>> {
	let (listener, offset, stop) = (&shard.listener, shard.offset, mark.stop());
	let (client, reply_to, local) = (peer.client(), peer.from, peer.local);
	let tls = rt.tls();
	let started = Instant::now();
	let mut events = rt.pool_events.subscribe();
	let mut idle_rx = rt.udp_idle.clone();
	let idle = *idle_rx.borrow_and_update();
	let mut bind_as = rt.bind_as(client);
	// the rule's, or the `tls.routes` route's own (#297)
	let mut source_ip = rt.source_ip;
	// `tls.mode: sni` (#130): hold the first datagrams until the server name is read
	let by_name = tls.mode() == TlsMode::Sni;
	let (sni, first) = if by_name {
		sniff(rt, stop, from_client, &shard.sniffing, client.ip(), carry).await?
	} else {
		(None, carry)
	};
	let picked = if by_name {
		match rt.select(sni.as_deref(), offset) {
			None => {
				rt.stats.denied();
				throttled!(rt.denied_log, client.ip(), info, event = "conn.denied", rule = %rt.key, client = %client, reason = "unmatched",
					sni = %clip(sni.as_deref().unwrap_or("")), proxy_peer = peer_field());
				// swallow the rest of this client's datagrams until it goes quiet,
				// rather than reading every one of them again as a new session
				drain(stop, from_client, idle.min(UNREPLIED_TIMEOUT)).await;
				return None;
			}
			// a `tls.routes` backend: its addresses as resolved now, counted on the route's
			// target (`max_connections`, #341) but not moved when it goes down
			Some(t) if t.from_route => {
				source_ip = rt.source_ip_for(&t);
				bind_as = rt.bind_as_for(&t, client);
				let mut miss = Miss::NoTarget;
				t.candidates
					.iter()
					.find_map(|c| {
						let addr = c.addrs.iter().copied().find(|a| source::usable(*a, bind_as))?;
						match c.lease() {
							Ok(lease) => Some(Picked { lease, addrs: None, addr, routed: true }),
							Err(_) => {
								miss = Miss::Full;
								None
							}
						}
					})
					.ok_or(miss)
			}
			Some(_) => pick(rt, offset, bind_as),
		}
	} else {
		pick(rt, offset, bind_as)
	};
	let Picked { mut lease, addrs: mut target_rx, addr, routed } = match picked {
		Ok(p) => p,
		Err(Miss::Full) => {
			// the datagrams are dropped; the client's next one tries again
			limits::refused(rt, client, Reason::TargetFull, "udp");
			return None;
		}
		Err(Miss::NoTarget) => {
			throttled!(udp_errors(), client.ip(), warn, event = "conn.error", rule = %rt.key, client = %client, error = "no resolved target",
				sni = %clip(sni.as_deref().unwrap_or("")),
				proxy_peer = peer_field());
			return None;
		}
	};
	let mut target = Some(addr);

	let upstream = match source::udp_upstream(addr, bind_as).await {
		Ok(s) => s,
		Err(e) => {
			throttled!(udp_errors(), client.ip(), warn, event = "conn.error", rule = %rt.key, client = %client, error = %e, proxy_peer = peer_field());
			return None;
		}
	};

	rt.stats.opened();
	let geo = rt.geo_for_log(client.ip(), None);
	info!(event = "conn.open", rule = %rt.key, listen = %listener.local_for(local), client = %client, target = %addr_or_empty(target),
		sni = %clip(sni.as_deref().unwrap_or("")), country = geo.as_ref().and_then(|g| g.country_str()), asn = geo.and_then(|g| g.asn), proxy_peer = peer_field());
	// `bandwidth` (#166): datagrams over the rate are dropped
	let (mut up, mut down) = (Gate::new(client.ip(), Dir::Up), Gate::new(client.ip(), Dir::Down));
	let header = proxy_header(source_ip, client, listener.local_for(local));
	// sni: the QUIC connection this session was routed for, and a new one being read
	let mut quic_dcid = first.iter().find_map(|d| crate::tls::udp_sni::quic::initial_dcid(d));
	let mut probe: Option<Probe> = None;
	let mut restart = None;

	let (mut rx_bytes, mut tx_bytes) = (0u64, 0u64);
	// the datagrams held while reading the server name, in order
	let mut first = first;
	let mut quiet = Quiet::new(idle, mark, first.len());
	// ECONNREFUSED from the backend: an ICMP port unreachable, seen on a send or a read
	let mut refused: Option<std::io::Error> = None;
	rx_bytes += forward(rt, &upstream, &header, client, &mut first, &mut up, &mut refused).await;
	drop(first);
	// datagrams taken from the queue at once, sent on with one `sendmmsg`
	let (mut inbox, mut out) = (Vec::new(), Vec::new());
	let reason = loop {
		if let Some(e) = refused.take() {
			target_refused(rt, lease.as_ref(), &e);
		}
		tokio::select! {
			_ = stop.cancelled() => break mark.stopped(),
			_ = sleep_until(quiet.deadline()) => break "idle",
			// a new QUIC connection that did not show its name in time: treat it as ours
			_ = async { match &probe { Some(p) => sleep_until(p.until).await, None => std::future::pending().await } } => {
				let mut held = probe.take().map(|p| p.held).unwrap_or_default();
				rx_bytes += forward(rt, &upstream, &header, client, &mut held, &mut up, &mut refused).await;
			},
			received = from_client.recv_many(&mut inbox, BATCH) => {
				if received == 0 {
					break "closed";
				}
				quiet.client(received, mark);
				if !by_name {
					rx_bytes += forward(rt, &upstream, &header, client, &mut inbox, &mut up, &mut refused).await;
					inbox.clear();
					continue;
				}
				let mut datagrams = inbox.drain(..);
				for data in datagrams.by_ref() {
					match renamed(&mut probe, &mut quic_dcid, sni.as_deref(), data) {
						Step::Forward(d) => out.extend(d),
						Step::Hold => {}
						Step::Restart(held) => {
							// the new session starts with these, then what is still queued
							restart = Some(held);
							break;
						}
					}
				}
				if let Some(held) = restart.as_mut() {
					held.extend(datagrams);
				} else {
					drop(datagrams);
				}
				rx_bytes += forward(rt, &upstream, &header, client, &mut out, &mut up, &mut refused).await;
				out.clear();
				if restart.is_some() {
					break "new connection";
				}
			},
			// the backend's replies are read into the worker's buffer and sent on at once (#268)
			ready = upstream.ready(Interest::READABLE | Interest::ERROR) => {
				if let Err(e) = ready {
					debug!(event = "udp.recv_error", rule = %rt.key, client = %client, error = %e);
					continue;
				}
				for _ in 0..BATCH {
					let n = match reply(&upstream, listener, reply_to, local, &mut down, &rt.bandwidth) {
						Reply::Empty => break,
						Reply::OverBandwidth => {
							rt.stats.bandwidth_dropped();
							quiet.backend(mark);
							continue;
						}
						Reply::Sent(n) => n,
						Reply::SendFailed(n, e) => {
							rt.stats.dropped();
							debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
							n
						}
						// the client side's send buffer is full: wait with a copy, not the shared buffer
						Reply::Blocked(data) => {
							if let Err(e) = listener.send_to(&data, reply_to, local).await {
								rt.stats.dropped();
								debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
							}
							data.len()
						}
						// ICMP unreachable from the backend surfaces here on a connected socket
						Reply::RecvFailed(e) => {
							debug!(event = "udp.recv_error", rule = %rt.key, client = %client, error = %e);
							if e.kind() == std::io::ErrorKind::ConnectionRefused {
								target_refused(rt, lease.as_ref(), &e);
							}
							break;
						}
					};
					tx_bytes += n as u64;
					rt.stats.add_tx(n as u64);
					quiet.backend(mark);
				}
			},
			// a target went down (or the targets changed): move off it
			changed = events.changed() => {
				if changed.is_err() {
					break "stopped";
				}
				// a `tls.routes` backend (sni) is not in the pool
				let Some(member) = lease.as_ref().filter(|_| !routed).map(|l| l.member().clone()) else { continue };
				let pool = rt.pool();
				if pool.contains(&member) && member.is_up() {
					continue;
				}
				// the targets were replaced and this one is still there (its count went on, #341): stay
				if let Some((l, same)) = lease.as_mut().and_then(|l| l.carried_to(&pool).map(|m| (l, m))) {
					// not marked seen: a different address there moves the session below
					target_rx = Some(same.addrs.clone());
					l.move_to(same);
					continue;
				}
				drop(pool);
				// none (every other target full, too): it stays where it is
				let Some(next) = pick(rt, offset, bind_as).ok().filter(|p| !p.lease.as_ref().is_some_and(|l| Arc::ptr_eq(l.member(), &member))) else { continue };
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
				quiet.idle = *idle_rx.borrow_and_update();
			},
		}
	};

	drop(lease);
	rt.stats.closed();
	info!(event = "conn.close", rule = %rt.key, client = %client, target = %addr_or_empty(target),
		rx_bytes, tx_bytes, duration_ms = started.elapsed().as_millis() as u64, reason, proxy_peer = peer_field());
	restart
}

/// `tls.mode: sni`: a new QUIC connection (an Initial with another Destination
/// Connection ID) from a client socket that already has a session, while its
/// server name is being read. Its datagrams are held meanwhile.
struct Probe {
	dcid: Vec<u8>,
	sniffer: crate::tls::udp_sni::Sniffer,
	held: Vec<Vec<u8>>,
	/// Bytes in `held` (at most about `SNI_MAX_BYTES`, as `sniff`).
	held_bytes: usize,
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
			// a new connection's first flight; not a later Initial of this one with the server's connection ID,
			// which would be held until SNI_WAIT and stall the handshake
			Some(dcid) if quic_dcid.as_deref() != Some(dcid.as_slice()) && crate::tls::udp_sni::quic::opens_with_own_id(&data) => {
				*probe = Some(Probe {
					dcid,
					sniffer: crate::tls::udp_sni::Sniffer::default(),
					held: vec![],
					held_bytes: 0,
					until: tokio::time::Instant::now() + SNI_WAIT,
				});
			}
			_ => return Step::Forward(vec![data]),
		}
	}
	let Some(p) = probe.as_mut() else { return Step::Forward(vec![data]) };
	let seen = p.sniffer.push(&data);
	p.held_bytes += data.len();
	p.held.push(data);
	let new_name = match seen {
		Sniff::NeedMore if p.held.len() < SNI_MAX_DATAGRAMS && p.held_bytes < SNI_MAX_BYTES => return Step::Hold,
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
	/// A `tls.routes` backend: not moved to the rule's targets when it goes down.
	routed: bool,
}

/// Why a session got no target.
#[derive(Clone, Copy)]
enum Miss {
	/// None with an address (of the client's family with `transparent`).
	NoTarget,
	/// Each one with an address was at its `max_connections` (#341).
	Full,
}

/// The target for a new session, or for one whose target went down: the best
/// one (by `balance`) that has addresses and room (`max_connections`, #341);
/// with `transparent` (`bind_as`), only one of the client's address family.
fn pick(rt: &Runtime, offset: u16, bind_as: Option<SocketAddr>) -> Result<Picked, Miss> {
	let mut miss = Miss::NoTarget;
	rt.pool()
		.order()
		.into_iter()
		.find_map(|m: Arc<Member>| {
			let addr = m.addrs(offset).into_iter().find(|a| source::usable(*a, bind_as))?;
			let mut addrs = m.addrs.clone();
			let Some(lease) = Lease::take(m) else {
				miss = Miss::Full;
				return None;
			};
			addrs.borrow_and_update();
			Some(Picked { lease: Some(lease), addrs: Some(addrs), addr, routed: false })
		})
		.ok_or(miss)
}

/// Holds a new session's first datagrams until its server name is read (DTLS /
/// QUIC, `udp_sni`), for at most `SNI_WAIT` and `SNI_MAX_*`. The name (None when
/// there is none or it cannot be read) and the datagrams, which must still be
/// sent on. None: the rule stopped, or the session's slot of the port's `SniSlots`
/// (taken once one datagram is not enough) was given up for a newer one.
async fn sniff(
	rt: &Runtime,
	stop: &CancellationToken,
	from_client: &mut mpsc::Receiver<Vec<u8>>,
	slots: &Arc<SniSlots>,
	client: IpAddr,
	carry: Vec<Vec<u8>>,
) -> Option<(Option<String>, Vec<Vec<u8>>)> {
	use crate::tls::udp_sni::{Sniff, Sniffer};
	let mut sniffer = Sniffer::default();
	let (mut first, mut bytes) = (Vec::new(), 0usize);
	let deadline = tokio::time::Instant::now() + SNI_WAIT;
	let mut carry = carry.into_iter();
	let mut slot: Option<SniSlot> = None;
	loop {
		let datagram = match carry.next() {
			Some(d) => d,
			None => tokio::select! {
				_ = stop.cancelled() => return None,
				_ = sleep_until(deadline) => return Some((None, first)),
				_ = async { match &slot { Some(s) => s.state.given_up.cancelled().await, None => std::future::pending().await } } => {
					rt.stats.dropped();
					debug!(event = "udp.drop", rule = %rt.key, reason = "given up for a newer session reading its server name");
					return None;
				}
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
			Sniff::NeedMore if slot.is_none() => slot = Some(slots.take(client)),
			Sniff::NeedMore => {}
		}
	}
}

/// Drops a refused client's datagrams until it is idle for `idle`.
async fn drain(stop: &CancellationToken, from_client: &mut mpsc::Receiver<Vec<u8>>, idle: Duration) {
	loop {
		tokio::select! {
			_ = stop.cancelled() => return,
			_ = tokio::time::sleep(idle) => return,
			d = from_client.recv() => if d.is_none() { return },
		}
	}
}

/// `source_ip: proxy_v2` (the rule's, or a route's own, #297): the PROXY v2 (DGRAM) header sent in front of every
/// datagram to the backend. The destination is the address the client sent to
/// (learnt on a wildcard listener).
fn proxy_header(source_ip: SourceIp, client: SocketAddr, local: SocketAddr) -> Option<Vec<u8>> {
	(source_ip == SourceIp::ProxyV2).then(|| source::proxy_v2_dgram_header(client, local))
}

/// The session's target answered with ICMP port unreachable (ECONNREFUSED, on a read or a
/// send): it is failed (`outlier_detection`) when it is still one of the rule's targets.
fn target_refused(rt: &Runtime, lease: Option<&Lease>, e: &std::io::Error) {
	if let Some(lease) = lease {
		let pool = rt.pool();
		if pool.contains(lease.member()) {
			pool.failed(&rt.key, lease.member(), "refused", &e.to_string());
		}
	}
}

/// Sends a client's datagrams on to its backend (those over the `bandwidth`
/// limit, `up`, are dropped); their bytes. A send refused by the backend (ICMP port
/// unreachable of an earlier datagram) is kept in `refused`.
async fn forward(
	rt: &Runtime,
	upstream: &UdpSocket,
	header: &Option<Vec<u8>>,
	client: SocketAddr,
	datagrams: &mut Vec<Vec<u8>>,
	up: &mut Gate,
	refused: &mut Option<std::io::Error>,
) -> u64 {
	if rt.bandwidth.is_on() {
		datagrams.retain(|d| {
			let pass = up.admit(&rt.bandwidth, d.len());
			if !pass {
				rt.stats.bandwidth_dropped();
			}
			pass
		});
	}
	if datagrams.is_empty() {
		return 0;
	}
	crate::net::udpsock::send_connected(upstream, header.as_deref(), datagrams, |e| {
		rt.stats.dropped();
		debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
		if e.kind() == std::io::ErrorKind::ConnectionRefused {
			*refused = Some(std::io::Error::from(e.kind()));
		}
	})
	.await;
	let bytes = datagrams.iter().map(|d| d.len() as u64).sum();
	rt.stats.add_rx(bytes);
	bytes
}

fn with_header<'a>(header: &Option<Vec<u8>>, data: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
	match header {
		Some(h) => [h.as_slice(), data].concat().into(),
		None => data.into(),
	}
}

thread_local! {
	/// One receive buffer per worker thread for the plain sessions' backend replies (#268): a buffer per session cost
	/// 64 KiB each, resident, for as long as the session lived (`udp_idle`). It is borrowed only between a readiness and
	/// the send without waiting, never across an `.await`.
	static REPLY_BUF: std::cell::RefCell<RecvBuf> = std::cell::RefCell::new(RecvBuf::new());
}

/// What one read of the backend's socket came to.
#[derive(Debug)]
enum Reply {
	/// nothing more to read
	Empty,
	OverBandwidth,
	Sent(usize),
	SendFailed(usize, std::io::Error),
	/// not sent yet: the client side would block
	Blocked(Vec<u8>),
	RecvFailed(std::io::Error),
}

/// Reads one datagram from the backend into the worker's buffer and sends it on to `client` without waiting.
fn reply(upstream: &UdpSocket, listener: &Listener, client: SocketAddr, local: Option<Local>, down: &mut Gate, bandwidth: &Bandwidth) -> Reply {
	REPLY_BUF.with_borrow_mut(|buf| {
		// `try_recv` reads only when readable: an ICMP error alone (readiness ERROR) is read on its own, or it would stay
		// pending and wake the session again and again (`try_io` takes one interest at a time)
		let read = match upstream.try_recv(buf) {
			Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => upstream.try_io(Interest::ERROR, || {
				use std::os::fd::AsRawFd;
				// SAFETY: `buf` is valid for writes of its length for the duration of the call
				let n = unsafe { libc::recv(upstream.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
				if n < 0 {
					Err(std::io::Error::last_os_error())
				} else {
					Ok(n as usize)
				}
			}),
			read => read,
		};
		let n = match read {
			Ok(n) => n,
			Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Reply::Empty,
			Err(e) => return Reply::RecvFailed(e),
		};
		if !down.admit(bandwidth, n) {
			return Reply::OverBandwidth;
		}
		match listener.try_send_to(&buf[..n], client, local) {
			Ok(_) => Reply::Sent(n),
			Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Reply::Blocked(buf[..n].to_vec()),
			Err(e) => Reply::SendFailed(n, e),
		}
	})
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

	/// Err: the error, and whether it is a plain backend's ICMP port unreachable.
	async fn recv(&self, buf: &mut [u8]) -> Result<usize, (String, Option<std::io::Error>)> {
		match self {
			Upstream::Plain(s) => s.recv(buf).await.map_err(|e| (e.to_string(), (e.kind() == std::io::ErrorKind::ConnectionRefused).then_some(e))),
			Upstream::Dtls(c) => c.read(buf, None).await.map_err(|e| (e.to_string(), None)),
		}
	}
}

/// A UDP session whose client speaks DTLS to rproxy. Until the handshake is through it
/// is a session not replied to (`Unreplied`, evicted first at the cap), takes one of the
/// port's slots of sessions that wait for more datagrams (`SniSlots`: at most 64 per source
/// prefix, the prefix's oldest given up past that, #354), and ends unless a ClientHello with
/// the cookie of the crate's HelloVerifyRequest comes back within `UNREPLIED_TIMEOUT`
/// (`SessionConn::verified`: a spoofed source never sees the cookie).
async fn dtls_session(peer: Peer, from_client: mpsc::Receiver<Vec<u8>>, shard: &Shard, rt: Arc<Runtime>, tls: Arc<TlsRuntime>, admitted: Admitted) {
	let (client, local) = (peer.client(), peer.local);
	let (offset, mark) = (shard.offset, &admitted.mark);
	let stop = mark.stop();
	let started = Instant::now();
	let listen = shard.listener.local_for(local);
	let header = proxy_header(rt.source_ip, client, listen);
	let session_conn = Arc::new(SessionConn::new(from_client, shard.listener.clone(), peer.from, local));
	let conn: Arc<dyn Conn + Send + Sync> = session_conn.clone();
	let slot = shard.sniffing.take(client.ip());
	let unanswered = async {
		tokio::time::sleep(UNREPLIED_TIMEOUT).await;
		if session_conn.verified() {
			std::future::pending::<()>().await;
		}
	};
	let handshake = tokio::select! {
		_ = stop.cancelled() => return,
		_ = slot.state.given_up.cancelled() => {
			rt.stats.dropped();
			debug!(event = "udp.drop", rule = %rt.key, client = %client, reason = "given up for a newer DTLS handshake of its network");
			return;
		}
		_ = unanswered => {
			rt.stats.dropped();
			debug!(event = "udp.drop", rule = %rt.key, client = %client, reason = "no ClientHello with the cookie of the HelloVerifyRequest");
			return;
		}
		r = tokio::time::timeout(HANDSHAKE_TIMEOUT, DTLSConn::new(conn, tls.dtls_server_config(), false, None)) => r,
	};
	drop(slot);
	let dtls = match handshake {
		Ok(Ok(c)) => c,
		failed => {
			let error = match failed {
				Ok(Err(e)) => e.to_string(),
				_ => "DTLS handshake timed out".to_string(),
			};
			rt.stats.tls_failed();
			throttled!(udp_errors(), client.ip(), warn, event = "tls.error", rule = %rt.key, client = %client, error = %error, dtls = true);
			return;
		}
	};
	mark.replied();
	let state = dtls.connection_state().await;
	if let Err(e) = tls.verify_dtls_client(&state.peer_certificates) {
		rt.stats.tls_failed();
		throttled!(udp_errors(), client.ip(), warn, event = "tls.error", rule = %rt.key, client = %client, error = %e, dtls = true);
		let _ = dtls.close().await;
		return;
	}
	let client_cn = state.peer_certificates.first().and_then(|c| crate::tls::config::common_name(c));
	let chain: Vec<rustls::pki_types::CertificateDer<'_>> = state.peer_certificates.iter().map(|c| rustls::pki_types::CertificateDer::from(c.as_slice())).collect();
	let client_verify = source::TlsInfo::default().with_client(&chain, tls.client_verified(&chain)).client_verify();

	let Some(target) = rt.select(None, offset) else {
		let _ = dtls.close().await;
		return;
	};
	// the first with addresses and room (`max_connections`, #341)
	let mut full = false;
	let chosen = target.candidates.iter().filter(|c| !c.addrs.is_empty()).find_map(|c| match c.lease() {
		Ok(lease) => Some((c, lease)),
		Err(_) => {
			full = true;
			None
		}
	});
	let Some((chosen, lease)) = chosen else {
		if full {
			limits::refused(&rt, client, Reason::TargetFull, "udp");
		} else {
			throttled!(udp_errors(), client.ip(), warn, event = "conn.error", rule = %rt.key, client = %client, error = "no resolved target",
				dtls = true);
		}
		let _ = dtls.close().await;
		return;
	};
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
			throttled!(udp_errors(), client.ip(), warn, event = "conn.error", rule = %rt.key, client = %client, error = %e, dtls = true);
			let _ = dtls.close().await;
			return;
		}
	};

	rt.stats.opened();
	info!(event = "conn.open", rule = %rt.key, listen = %listen, client = %client, target = %addr, dtls = true,
		client_cn = client_cn.as_deref().unwrap_or(""), client_verify, upstream_dtls = tls.spec.upstream.tls, proxy_peer = peer_field());

	let mut idle_rx = rt.udp_idle.clone();
	let mut idle = *idle_rx.borrow_and_update();
	let (mut rx_bytes, mut tx_bytes) = (0u64, 0u64);
	let (mut buf, mut ubuf) = (RecvBuf::new(), RecvBuf::new());
	let (mut up, mut down) = (Gate::new(client.ip(), Dir::Up), Gate::new(client.ip(), Dir::Down));
	let mut deadline = tokio::time::Instant::now() + idle;
	let reason = loop {
		tokio::select! {
			_ = stop.cancelled() => break mark.stopped(),
			_ = sleep_until(deadline) => break "idle",
			read = dtls.read(&mut buf, None) => match read {
				Ok(n) if !up.admit(&rt.bandwidth, n) => {
					rt.stats.bandwidth_dropped();
					deadline = tokio::time::Instant::now() + idle;
				}
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
				Ok(n) if !down.admit(&rt.bandwidth, n) => {
					rt.stats.bandwidth_dropped();
					deadline = tokio::time::Instant::now() + idle;
				}
				Ok(n) => {
					if let Err(e) = dtls.write(&ubuf[..n], None).await {
						rt.stats.dropped();
						debug!(event = "udp.send_error", rule = %rt.key, client = %client, error = %e);
					}
					tx_bytes += n as u64;
					rt.stats.add_tx(n as u64);
					deadline = tokio::time::Instant::now() + idle;
				}
				// a plain backend's ICMP port unreachable comes once; a DTLS backend that closed
				// (or failed) fails every read from now on: the session ends (#354)
				Err((e, refused)) => {
					debug!(event = "udp.recv_error", rule = %rt.key, client = %client, error = %e);
					if matches!(upstream, Upstream::Dtls(_)) {
						break "backend closed";
					}
					if let Some(refused) = refused {
						target_refused(&rt, lease.as_ref(), &refused);
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
	let _ = dtls.close().await;
	if let Upstream::Dtls(up) = &upstream {
		let _ = up.close().await;
	}
	rt.stats.closed();
	info!(event = "conn.close", rule = %rt.key, client = %client, target = %addr, dtls = true,
		rx_bytes, tx_bytes, duration_ms = started.elapsed().as_millis() as u64, reason, proxy_peer = peer_field());
}

fn addr_or_empty(target: Option<SocketAddr>) -> String {
	target.map(|t| t.to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	fn taken(slots: &SniSlots) -> (usize, usize) {
		let t = slots.table.lock().unwrap();
		(t.taken, t.by_prefix.len())
	}

	fn given_up(s: &SniSlot) -> bool {
		s.state.given_up.is_cancelled()
	}

	// #332: spoofed sources of one network hold at most their share of the slots, never those of another network;
	// past it they give up their own oldest, so a client of the flooded network still gets a slot too
	#[test]
	fn sni_slots_are_bounded_per_source_prefix() {
		let slots = Arc::new(SniSlots::new(8, 3));
		let flood: Vec<SniSlot> = (1..=3).map(|i| slots.take(ip(&format!("192.0.2.{i}")))).collect();
		// another /24 and an IPv6 /48 take theirs
		let other = slots.take(ip("198.51.100.1"));
		let v6: Vec<SniSlot> = (1..=3).map(|i| slots.take(ip(&format!("2001:db8:1:{i}::1")))).collect();
		assert_eq!(taken(&slots), (7, 3));
		// a fourth of 192.0.2.0/24 (any address in it, IPv4-mapped too) gives up that network's oldest
		let newer = slots.take(ip("::ffff:192.0.2.200"));
		assert!(given_up(&flood[0]) && !given_up(&flood[1]) && !given_up(&flood[2]) && !given_up(&newer));
		assert!(!given_up(&other) && v6.iter().all(|s| !given_up(s)), "nothing of the other networks");
		assert_eq!(taken(&slots), (7, 3));
		let newest = slots.take(ip("192.0.2.9"));
		assert!(given_up(&flood[1]) && !given_up(&newest));
		// one /48
		let v6_more = slots.take(ip("2001:db8:1:ffff::1"));
		assert!(given_up(&v6[0]) && !given_up(&v6_more) && !given_up(&other));
		assert_eq!(taken(&slots), (7, 3));
		// given up and then dropped counts nothing twice; given back frees the place
		drop(flood);
		assert_eq!(taken(&slots), (6, 3));
		drop((other, v6, v6_more, newer, newest));
		assert_eq!(taken(&slots), (0, 0));
		assert!(slots.table.lock().unwrap().by_prefix.is_empty());
	}

	#[test]
	fn sni_slots_give_up_the_oldest_when_all_are_taken() {
		let slots = Arc::new(SniSlots::new(4, 4));
		// a flood from everywhere: each source its own prefix
		let flood: Vec<SniSlot> = (1..=4).map(|i| slots.take(ip(&format!("10.0.{i}.1")))).collect();
		let legit = slots.take(ip("203.0.113.5"));
		assert!(flood[0].state.given_up.is_cancelled(), "the oldest was given up");
		assert!(flood[1..].iter().all(|s| !s.state.given_up.is_cancelled()));
		assert!(!legit.state.given_up.is_cancelled());
		assert_eq!(taken(&slots).0, 4);
		// a given-up slot dropped later counts nothing twice
		drop(flood);
		assert_eq!(taken(&slots), (1, 1));
		// many turns: the queue of slots stays bounded
		for i in 0..10_000u32 {
			let _ = slots.take(IpAddr::from(i.to_be_bytes()));
		}
		let t = slots.table.lock().unwrap();
		assert!(t.order.len() <= 2 * 4 + 1, "{}", t.order.len());
		assert_eq!(t.taken, 1, "the one still held");
		drop(t);
		drop(legit);
	}

	// #354: at the caps, the oldest session that never saw a reply goes; replied and ended ones are not evicted
	#[test]
	fn the_oldest_unreplied_session_is_evicted() {
		let unreplied = Unreplied::default();
		let marks: Vec<Mark> = (0..3).map(|_| unreplied.track(ip("192.0.2.1"), CancellationToken::new())).collect();
		marks[0].replied();
		assert_eq!(unreplied.waiting(), 2);
		assert!(unreplied.evict_for(ip("192.0.2.1")));
		assert!(!marks[0].stop().is_cancelled() && marks[1].stop().is_cancelled() && !marks[2].stop().is_cancelled());
		assert_eq!((marks[1].stopped(), marks[2].stopped()), ("evicted", "stopped"));
		drop(marks);
		assert!(!unreplied.evict_for(ip("192.0.2.1")), "ended sessions are not evicted");
		// many sessions answered at once: the queue is cleared out as it goes
		for _ in 0..10_000 {
			unreplied.track(ip("192.0.2.1"), CancellationToken::new()).replied();
		}
		assert!(unreplied.lock().order.len() <= 2 * 64 + 1);
		let last = unreplied.track(ip("192.0.2.1"), CancellationToken::new());
		assert!(unreplied.evict_for(ip("192.0.2.1")) && last.stop().is_cancelled());
	}

	fn v4(n: u32) -> IpAddr {
		IpAddr::from(n.to_be_bytes())
	}

	// #366: a flood from one prefix pushes out its own unreplied sessions, not those of other prefixes
	#[test]
	fn a_flooding_prefix_evicts_its_own() {
		let unreplied = Unreplied::default();
		// a client of another network, waiting for its reply since before the flood
		let legit = unreplied.track(v4(0x0a00_0001), CancellationToken::new());
		let flood: Vec<Mark> = (0..10).map(|i| unreplied.track(v4(0xc000_0200 + i), CancellationToken::new())).collect();
		// at the cap, a new session of the flood's /24 evicts the flood's oldest
		assert!(unreplied.evict_for(v4(0xc000_02ff)));
		assert!(flood[0].stop().is_cancelled() && !legit.stop().is_cancelled());
		// a new client of a third network evicts the flood's oldest too: its prefix holds the most
		assert!(unreplied.evict_for(v4(0x0b00_0001)));
		assert!(flood[1].stop().is_cancelled() && !legit.stop().is_cancelled());
		// IPv6: a /48
		let v6 = |s: &str| s.parse::<IpAddr>().unwrap();
		let six: Vec<Mark> = (0..20).map(|i| unreplied.track(v6(&format!("2001:db8:1:{i:x}::1")), CancellationToken::new())).collect();
		assert!(unreplied.evict_for(v6("2001:db8:2::1")));
		assert!(six[0].stop().is_cancelled() && !flood[2].stop().is_cancelled() && !legit.stop().is_cancelled());
		// the prefixes as many as each other: the oldest of all goes
		drop((flood, six));
		let other = unreplied.track(v4(0x0c00_0001), CancellationToken::new());
		assert!(unreplied.evict_for(v4(0x0d00_0001)));
		assert!(legit.stop().is_cancelled() && !other.stop().is_cancelled());
		assert_eq!(unreplied.waiting(), 1);
	}

	// #366: one prefix holds at most `unreplied_per_prefix` of a rule's unreplied sessions; past that its own oldest goes
	#[test]
	fn a_prefix_holds_at_most_its_share() {
		let unreplied = Unreplied::default();
		let share = unreplied_per_prefix();
		assert_eq!(share, (DEFAULT_MAX_SESSIONS / UNREPLIED_PER_PREFIX_SHARE) as usize);
		let legit = unreplied.track(v4(0x0a00_0001), CancellationToken::new());
		let flood = |i: usize| v4(0xc000_0200 + (i % 256) as u32);
		let marks: Vec<Mark> = (0..share + 3).map(|i| unreplied.track(flood(i), CancellationToken::new())).collect();
		assert_eq!(marks.iter().filter(|m| m.stop().is_cancelled()).count(), 3);
		assert!(marks[..3].iter().all(|m| m.stopped() == "evicted"));
		assert!(!legit.stop().is_cancelled());
		assert_eq!(unreplied.waiting(), share + 1);
		// answered ones count no more: room again without evicting
		marks[share].replied();
		let next = unreplied.track(v4(0xc000_0201), CancellationToken::new());
		assert!(!marks[3].stop().is_cancelled() && !next.stop().is_cancelled());
		// many prefixes coming and going: the table of prefixes stays bounded
		drop((marks, next));
		for i in 0..10_000u32 {
			unreplied.track(v4(i << 8), CancellationToken::new());
		}
		let t = unreplied.lock();
		assert!(t.by_prefix.len() <= 2 * 64 + 1, "{}", t.by_prefix.len());
		assert!(t.order.len() <= 2 * 64 + 1);
		drop(t);
		drop(legit);
	}

	// #366: a session of the DPDK path (no descriptor) is evicted at the rule's cap like the others
	#[test]
	fn sessions_without_descriptors_are_evicted_too() {
		let unreplied = Unreplied::default();
		let mark = unreplied.track_without_descriptor(v4(0xc000_0201));
		assert!(!mark.evicted());
		assert!(unreplied.evict_for(v4(0xc000_0202)));
		assert!(mark.evicted() && mark.stop().is_cancelled());
		let established = unreplied.track_without_descriptor(v4(0xc000_0201));
		established.replied();
		assert!(!unreplied.evict_for(v4(0xc000_0202)));
		assert!(!established.evicted());
	}

	// #354: large datagrams queue less deep than small ones
	#[test]
	fn the_queue_is_bounded_in_bytes() {
		let (tx, _rx) = mpsc::channel(SESSION_QUEUE);
		let large = vec![0u8; 65_000];
		let taken = (0..SESSION_QUEUE).take_while(|_| enqueue(&tx, &large)).count();
		assert_eq!(taken, SESSION_QUEUE_BYTES / large.len());
		// small datagrams still go behind them, up to the count
		let small = [0u8; 100];
		assert_eq!((0..SESSION_QUEUE).filter(|_| enqueue(&tx, &small)).count(), SESSION_QUEUE - taken);
		assert!(!enqueue(&tx, &small));
	}

	// #354: until established (a reply, and more than one datagram from the client) a session ends UNREPLIED_TIMEOUT
	// after the client's last datagram, the backend's datagrams do not keep it and it stays one to evict; established,
	// udp_idle after the last datagram either way
	#[tokio::test(start_paused = true)]
	async fn quiet_sessions_end() {
		let idle = Duration::from_secs(30);
		let unreplied = Unreplied::default();
		let mark = unreplied.track(ip("192.0.2.1"), CancellationToken::new());
		let start = tokio::time::Instant::now();
		let mut quiet = Quiet::new(idle, &mark, 1);
		assert_eq!(quiet.deadline(), start + UNREPLIED_TIMEOUT);
		tokio::time::advance(Duration::from_secs(2)).await;
		// a reply to a single datagram (a spoofed query a backend answers): still unreplied, however much it sends
		quiet.backend(&mark);
		tokio::time::advance(Duration::from_secs(2)).await;
		quiet.backend(&mark);
		assert_eq!(quiet.deadline(), start + UNREPLIED_TIMEOUT);
		assert_eq!(unreplied.waiting(), 1, "still one to evict");
		// the client's second datagram: established, both ways from now on
		quiet.client(1, &mark);
		let now = tokio::time::Instant::now();
		assert_eq!(quiet.deadline(), now + idle);
		assert_eq!(unreplied.waiting(), 0, "established: not one to evict");
		tokio::time::advance(Duration::from_secs(20)).await;
		quiet.backend(&mark);
		assert_eq!(quiet.deadline(), tokio::time::Instant::now() + idle);
		// a later run of the same session (a new QUIC connection) starts established
		assert!(Quiet::new(idle, &mark, 1).established());
		// two datagrams before any reply: established with the first reply
		let other = unreplied.track(ip("192.0.2.1"), CancellationToken::new());
		let mut quiet = Quiet::new(idle, &other, 2);
		assert!(!quiet.established());
		quiet.backend(&other);
		assert!(quiet.established() && unreplied.waiting() == 0);
		// a short udp_idle stays as short unreplied
		let third = unreplied.track(ip("192.0.2.1"), CancellationToken::new());
		let quiet = Quiet::new(Duration::from_secs(1), &third, 1);
		assert_eq!(quiet.deadline(), tokio::time::Instant::now() + Duration::from_secs(1));
	}

	// #354: what a new QUIC connection from the same socket holds while its name is read is bounded in bytes too
	#[tokio::test]
	async fn a_renamed_probe_holds_at_most_sni_max_bytes() {
		use crate::tls::udp_sni::quic::Version;
		use crate::tls::udp_sni::tests::{crypto_frame, initial, tls_hello};
		let hello = tls_hello("other.example", &["h3"]);
		// the first bytes of a ClientHello, padded to 15 000 bytes: the name never comes
		let mut frames = crypto_frame(0, &hello[..10]);
		frames.resize(15_000, 0);
		let (mut probe, mut dcid) = (None, Some(vec![1u8; 8]));
		for pn in 0..4 {
			let step = renamed(&mut probe, &mut dcid, Some("first.example"), initial(Version::V1, &[2u8; 8], pn, &frames, b""));
			assert!(matches!(step, Step::Hold), "datagram {pn} held");
		}
		match renamed(&mut probe, &mut dcid, Some("first.example"), initial(Version::V1, &[2u8; 8], 4, &frames, b"")) {
			Step::Forward(held) => assert_eq!(held.len(), 5, "past SNI_MAX_BYTES: given up and sent on"),
			_ => panic!("still held past SNI_MAX_BYTES"),
		}
		assert!(probe.is_none());
	}

	#[tokio::test]
	async fn backend_replies_go_through_the_worker_buffer() {
		let listener = Listener::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
		let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		upstream.connect(backend.local_addr().unwrap()).await.unwrap();
		let (bandwidth, mut down) = (Bandwidth::default(), Gate::new(client.local_addr().unwrap().ip(), Dir::Down));

		// sizes up to the largest datagram, one after another through the same buffer
		for len in [1usize, 1400, 9000, RecvBuf::LEN - 28] {
			let data: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
			backend.send_to(&data, upstream.local_addr().unwrap()).await.unwrap();
			upstream.ready(Interest::READABLE | Interest::ERROR).await.unwrap();
			match reply(&upstream, &listener, client.local_addr().unwrap(), None, &mut down, &bandwidth) {
				Reply::Sent(n) => assert_eq!(n, len),
				r => panic!("not sent: {r:?}"),
			}
			let mut got = vec![0u8; RecvBuf::LEN];
			let (n, from) = client.recv_from(&mut got).await.unwrap();
			assert_eq!((&got[..n], from), (&data[..], listener.local_addr().unwrap()));
		}
		assert!(matches!(reply(&upstream, &listener, client.local_addr().unwrap(), None, &mut down, &bandwidth), Reply::Empty));
	}

	// ICMP port unreachable wakes the session (an error, not a readable datagram) and fails the target
	#[tokio::test]
	async fn a_refusing_backend_is_seen() {
		let listener = Listener::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
		let closed = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
		let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		upstream.connect(closed).await.unwrap();
		let (bandwidth, mut down) = (Bandwidth::default(), Gate::new(closed.ip(), Dir::Down));
		upstream.send(b"x").await.unwrap();
		tokio::time::timeout(Duration::from_secs(5), upstream.ready(Interest::READABLE | Interest::ERROR)).await.unwrap().unwrap();
		match reply(&upstream, &listener, closed, None, &mut down, &bandwidth) {
			Reply::RecvFailed(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused),
			r => panic!("no refusal: {r:?}"),
		}
		// read once: the session is not woken again for it
		assert!(matches!(reply(&upstream, &listener, closed, None, &mut down, &bandwidth), Reply::Empty));
		assert!(tokio::time::timeout(Duration::from_millis(200), upstream.ready(Interest::READABLE | Interest::ERROR)).await.is_err());
	}
}
