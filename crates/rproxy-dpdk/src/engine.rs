//! The UDP forwarding of the DPDK path (#261): frames in, frames out, no
//! kernel. A rule listens on an address of a DPDK port; each client gets a
//! session with a port of its own on the source address (NAT, like the
//! kernel path's connected upstream socket), and the backend's answers to that
//! port go back to the client from the rule's address.
//!
//! Pure Rust and generic over the rules (`Rule`), so the same code runs in the
//! lcores, in the startup check (`selftest`) and in the unit tests without
//! DPDK. The I/O around it (`ffi`, `io`) only moves frames.
//!
//! Sharing between lcores: the rule table is copied into each lcore
//! (`Worker`) and refreshed when its version changes (one relaxed load per
//! burst); sessions live in one slot per NAT port (a Mutex each, uncontended
//! unless two lcores see the same session), found from the client side
//! through a sharded map.
//!
//! Sources can be spoofed (#354, #366): a session is established once its
//! backend has replied and its client has sent more than one datagram, as on
//! the kernel's path. Until then it ends `UNREPLIED_TIMEOUT` after the client's
//! last datagram (the backend's datagrams do not keep it), and it is one the
//! rule may end at its cap (`Rule::evicted`). One client prefix (/24) holds at
//! most `1 / NAT_PREFIX_SHARE` of an address's NAT ports while half of them are
//! taken: past that, its own oldest session not established gives up its port.

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::packet::{self, Frame, Mac, Udp4};

/// The source ports of sessions on each address (the Linux default
/// `ip_local_port_range`). Ports of rules on the address are skipped.
pub const NAT_LO: u16 = 32768;
pub const NAT_HI: u16 = 60999;
/// Slots tried for a new session before giving up (the datagram is dropped).
const NAT_TRIES: usize = 256;
const SHARDS: usize = 64;
/// ARP requests for one address at most this often.
const ARP_RETRY: Duration = Duration::from_secs(1);
/// A session not established ends this long after its client's last datagram
/// (the rule's idle time if shorter): the kernel path's `udp::UNREPLIED_TIMEOUT`.
pub const UNREPLIED_TIMEOUT: Duration = Duration::from_secs(5);
/// One client prefix (`NAT_PREFIX` bits) holds at most this share of the NAT
/// ports of an address (at least `NAT_PREFIX_MIN`) once half of them are taken.
pub const NAT_PREFIX_SHARE: usize = 16;
const NAT_PREFIX_MIN: usize = 64;
const NAT_PREFIX: u32 = 24;

/// What a rule tells the forwarder. Implemented over the rule's runtime by
/// rproxy-api (the same checks as the kernel path) and by the startup check.
pub trait Rule: Send + Sync + 'static {
	/// Per-session state of the rule (target lease, limits permit, counters).
	type Session: Send;
	fn phase(&self) -> Phase;
	/// Every datagram from a client: `allow_from`, `geoip`, `crowdsec`, packet
	/// limits. Counts and logs refusals itself.
	fn admit(&self, client: SocketAddrV4) -> bool;
	/// A new session: session limits, then the target (IPv4 only). None drops
	/// the datagram (counted and logged by the rule). Nothing is given up for
	/// it yet: that waits for `start`, once it has a port.
	fn open(&self, client: SocketAddrV4, listen: SocketAddrV4, offset: u16) -> Option<(SocketAddrV4, Self::Session)>;
	/// The new session has its port: the rule may now end another of its
	/// sessions to make room at its cap (#366; a session refused for want of a
	/// port must not have cost another network its session). False drops the
	/// session (counted and logged by the rule; `close` is not called).
	/// Sessions dropped before this (no route, no port) go through `close`.
	fn start(&self, _s: &mut Self::Session, _client: SocketAddrV4, _listen: SocketAddrV4, _target: SocketAddrV4) -> bool {
		true
	}
	/// `len` payload bytes from the client to the target; false drops them (bandwidth).
	fn up(&self, s: &mut Self::Session, len: usize) -> bool;
	/// `len` payload bytes from the target to the client.
	fn down(&self, s: &mut Self::Session, len: usize) -> bool;
	/// A datagram the forwarder could not pass on.
	fn dropped(&self);
	fn idle(&self) -> Duration;
	/// Checked once a second: a new target when the current one went down or
	/// changed its address.
	fn retarget(&self, s: &mut Self::Session, offset: u16, current: SocketAddrV4) -> Option<SocketAddrV4>;
	fn close(&self, s: Self::Session, client: SocketAddrV4, target: SocketAddrV4, reason: &'static str);
	/// The session is established (its backend replied and its client sent more
	/// than one datagram): no longer one to end at the caps. Once per session.
	fn established(&self, _s: &mut Self::Session) {}
	/// Whether the rule ended the session to make room for a new one (at its
	/// cap): its datagrams are dropped and the forwarder ends it (`evicted`).
	/// Asked only of sessions not established.
	fn evicted(&self, _s: &Self::Session) -> bool {
		false
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
	/// Takes new sessions.
	Open,
	/// Graceful shutdown: open sessions go on, no new ones.
	Draining,
	/// Stopped: its sessions end at the next sweep, their datagrams are dropped.
	Closed,
}

/// One DPDK port as the forwarder sees it.
#[derive(Clone, Debug)]
pub struct PortCfg {
	pub mac: Mac,
	/// Its addresses with their prefix lengths; the first is the source of
	/// sessions to backends reached through this port by rules on other ports.
	pub addrs: Vec<(Ipv4Addr, u8)>,
	pub gateway: Option<Ipv4Addr>,
}

fn on_link(addr: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
	let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) };
	u32::from(addr) & mask == u32::from(net) & mask
}

/// What to do with a frame after `Engine::process`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
	Drop,
	/// Send it (rewritten in place, same length) on this port.
	Send(usize),
}

/// Counters of frames the forwarder did not pass on and that belong to no rule.
#[derive(Default, Debug)]
pub struct Counters {
	pub not_ours: AtomicU64,
	pub fragments: AtomicU64,
	pub malformed: AtomicU64,
	pub no_neighbor: AtomicU64,
	pub nat_full: AtomicU64,
	/// New sessions refused because their prefix held its share of the NAT ports (#366).
	pub nat_prefix_full: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FwdKey {
	/// The rule's address and port as the client sent to.
	listen: SocketAddrV4,
	client: SocketAddrV4,
}

struct Session<R: Rule> {
	key: FwdKey,
	rule: Arc<R>,
	offset: u16,
	state: R::Session,
	target: SocketAddrV4,
	/// Where frames to the target go out, and the next hop's MAC once known.
	egress: usize,
	hop: Ipv4Addr,
	hop_mac: Option<Mac>,
	arp_sent: Option<Instant>,
	/// Answers go back to the MAC and port the client's frames came from.
	client_mac: Mac,
	client_port: usize,
	/// The client's last datagram; once established, the last datagram either way.
	last: Instant,
	/// Tells this session from a later one in the same slot (`PrefixPorts::waiting`).
	id: u64,
	/// The backend has replied.
	answered: bool,
	/// The client has sent more than one datagram.
	again: bool,
	established: bool,
}

impl<R: Rule> Session<R> {
	/// Marks it established once the backend has replied and the client has sent again.
	fn settle(&mut self) {
		if !self.established && self.answered && self.again {
			self.established = true;
			self.rule.established(&mut self.state);
		}
	}

	/// Not established and ended by its rule to make room.
	fn evicted(&self) -> bool {
		!self.established && self.rule.evicted(&self.state)
	}

	/// Why the sweep ends it at `now`, if it does.
	fn ends(&self, now: Instant) -> Option<&'static str> {
		if self.rule.phase() == Phase::Closed {
			return Some("stopped");
		}
		if self.evicted() {
			return Some("evicted");
		}
		let idle = self.rule.idle();
		let idle = if self.established { idle } else { idle.min(UNREPLIED_TIMEOUT) };
		(now.duration_since(self.last) >= idle).then_some("idle")
	}
}

/// The sessions of one client prefix on one source address.
#[derive(Default)]
struct PrefixPorts {
	held: usize,
	/// The slots and ids of its latest sessions not established when they
	/// opened, oldest first (at most its share and twice `held`; ended and
	/// established ones are skipped when one is looked for).
	waiting: VecDeque<(u16, u64)>,
}

/// One source address of sessions: a slot per NAT port.
struct Local<R: Rule> {
	ip: Ipv4Addr,
	port: usize,
	slots: Box<[Mutex<Option<Session<R>>>]>,
	cursor: AtomicUsize,
	/// Slots taken, and by client prefix (taken after a slot's lock, never before).
	held: AtomicUsize,
	prefixes: Mutex<HashMap<u32, PrefixPorts>>,
	/// The NAT ports one prefix may hold while half of them are taken.
	share: usize,
}

impl<R: Rule> Local<R> {
	fn share(&self) -> usize {
		self.share
	}
}

fn share_of(slots: usize, min: usize) -> usize {
	(slots / NAT_PREFIX_SHARE).max(min).min(slots)
}

fn prefix_of(ip: Ipv4Addr) -> u32 {
	u32::from(ip) & (u32::MAX << (32 - NAT_PREFIX))
}

type Table<R> = HashMap<SocketAddrV4, (Arc<R>, u16)>;
/// A client-side shard: each session's source address (by index) and NAT port.
type Fwd = HashMap<FwdKey, (usize, u16)>;

pub struct Engine<R: Rule> {
	ports: Vec<PortCfg>,
	/// The NAT ports (`NAT_LO..=NAT_HI` unless `with_nat_ports`).
	nat_lo: u16,
	nat_hi: u16,
	locals: Vec<Local<R>>,
	rules: Mutex<Arc<Table<R>>>,
	version: AtomicU64,
	fwd: Vec<Mutex<Fwd>>,
	/// Client-side entries of sessions ended while another shard was held (`open`), for the next `open`
	/// (before it takes a shard) or the sweep to clear: a couple per `open` in flight at most.
	/// With the id of the ended session: a row the slot's new session of the same client holds is kept.
	stale: Mutex<Vec<(FwdKey, usize, u16, u64)>>,
	/// Rows in `stale` (an empty one takes no lock).
	stale_len: AtomicUsize,
	next_id: AtomicU64,
	neighbors: Mutex<HashMap<Ipv4Addr, Mac>>,
	arp_pending: Mutex<HashMap<Ipv4Addr, Instant>>,
	pub counters: Counters,
}

/// An lcore's view: its copy of the rule table.
pub struct Worker<R: Rule> {
	rules: Arc<Table<R>>,
	version: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
	// a panic elsewhere must not stop the data plane
	m.lock().unwrap_or_else(|e| e.into_inner())
}

impl<R: Rule> Engine<R> {
	pub fn new(ports: Vec<PortCfg>) -> Self {
		Self::with_nat_ports(ports, NAT_LO, NAT_HI)
	}

	/// With the sessions' source ports from `lo..=hi` (a small range for the fuzz target).
	pub fn with_nat_ports(ports: Vec<PortCfg>, lo: u16, hi: u16) -> Self {
		let (lo, hi) = (lo.max(1), hi.max(lo.max(1)));
		let slots = usize::from(hi - lo) + 1;
		let mut locals = vec![];
		for (i, p) in ports.iter().enumerate() {
			for (ip, _) in &p.addrs {
				locals.push(Local {
					ip: *ip,
					port: i,
					slots: (0..slots).map(|_| Mutex::new(None)).collect(),
					cursor: AtomicUsize::new(0),
					held: AtomicUsize::new(0),
					prefixes: Mutex::default(),
					share: share_of(slots, NAT_PREFIX_MIN),
				});
			}
		}
		Engine {
			ports,
			nat_lo: lo,
			nat_hi: hi,
			locals,
			rules: Mutex::new(Arc::default()),
			version: AtomicU64::new(1),
			fwd: (0..SHARDS).map(|_| Mutex::default()).collect(),
			stale: Mutex::default(),
			stale_len: AtomicUsize::new(0),
			next_id: AtomicU64::new(0),
			neighbors: Mutex::default(),
			arp_pending: Mutex::default(),
			counters: Counters::default(),
		}
	}

	/// With a smaller least share of the NAT ports for one prefix than
	/// `NAT_PREFIX_MIN` (the fuzz target's small range: the share binds there too).
	#[doc(hidden)]
	pub fn with_prefix_min(mut self, min: usize) -> Self {
		for l in &mut self.locals {
			l.share = share_of(l.slots.len(), min.max(1));
		}
		self
	}

	pub fn ports(&self) -> &[PortCfg] {
		&self.ports
	}

	/// Whether `ip` is an address of a DPDK port.
	pub fn owns(&self, ip: Ipv4Addr) -> bool {
		self.local(ip).is_some()
	}

	fn local(&self, ip: Ipv4Addr) -> Option<usize> {
		self.locals.iter().position(|l| l.ip == ip)
	}

	/// Takes `count` ports from `port` on `ip` for `rule` (offsets 0..count).
	pub fn register(&self, ip: Ipv4Addr, port: u16, count: u16, rule: Arc<R>) -> Result<(), String> {
		if !self.owns(ip) {
			return Err(format!("{ip} is not an address of a DPDK port"));
		}
		let mut cur = lock(&self.rules);
		let mut next: Table<R> = (**cur).clone();
		for offset in 0..count {
			let at = SocketAddrV4::new(ip, port.checked_add(offset).ok_or("port range overflows")?);
			if next.contains_key(&at) {
				return Err(format!("{at} is taken by another rule"));
			}
			next.insert(at, (rule.clone(), offset));
		}
		*cur = Arc::new(next);
		self.version.fetch_add(1, Ordering::Release);
		Ok(())
	}

	/// Gives back the ports `register` took for `rule`.
	pub fn unregister(&self, ip: Ipv4Addr, port: u16, count: u16, rule: &Arc<R>) {
		let mut cur = lock(&self.rules);
		let mut next: Table<R> = (**cur).clone();
		for offset in 0..count {
			let at = SocketAddrV4::new(ip, port.saturating_add(offset));
			if next.get(&at).is_some_and(|(r, _)| Arc::ptr_eq(r, rule)) {
				next.remove(&at);
			}
		}
		*cur = Arc::new(next);
		self.version.fetch_add(1, Ordering::Release);
	}

	pub fn worker(&self) -> Worker<R> {
		Worker { rules: lock(&self.rules).clone(), version: self.version.load(Ordering::Acquire) }
	}

	/// Once per burst: picks up rule changes.
	pub fn refresh(&self, w: &mut Worker<R>) {
		let v = self.version.load(Ordering::Acquire);
		if v != w.version {
			w.rules = lock(&self.rules).clone();
			w.version = v;
		}
	}

	/// The port and next hop for `dst`: a port it is on the link of, else the
	/// first port with a gateway.
	fn route(&self, dst: Ipv4Addr, prefer: usize) -> Option<(usize, Ipv4Addr)> {
		let link = |i: usize| self.ports[i].addrs.iter().any(|(a, p)| on_link(dst, *a, *p));
		if link(prefer) {
			return Some((prefer, dst));
		}
		if let Some(i) = (0..self.ports.len()).find(|&i| link(i)) {
			return Some((i, dst));
		}
		if let Some(gw) = self.ports[prefer].gateway {
			return Some((prefer, gw));
		}
		self.ports.iter().enumerate().find_map(|(i, p)| p.gateway.map(|g| (i, g)))
	}

	fn neighbor(&self, ip: Ipv4Addr) -> Option<Mac> {
		lock(&self.neighbors).get(&ip).copied()
	}

	/// Sends an ARP request for `hop` out of `port` unless one went out lately.
	fn ask(&self, port: usize, hop: Ipv4Addr, now: Instant, out: &mut dyn FnMut(usize, &[u8])) {
		{
			let mut pending = lock(&self.arp_pending);
			if pending.get(&hop).is_some_and(|t| now.duration_since(*t) < ARP_RETRY) {
				return;
			}
			pending.insert(hop, now);
		}
		let p = &self.ports[port];
		let src = p.addrs.iter().find(|(a, pl)| on_link(hop, *a, *pl)).or(p.addrs.first()).map(|(a, _)| *a);
		let Some(src) = src else { return };
		let mut f = [0u8; packet::ARP_FRAME];
		packet::arp_frame(&mut f, packet::ARP_REQUEST, p.mac, src, [0; 6], hop);
		out(port, &f);
	}

	/// Handles one frame received on `port`. Frames the forwarder answers or
	/// passes on are rewritten in place (`Verdict::Send`); new frames (ARP
	/// requests) go through `out`.
	pub fn process(&self, w: &Worker<R>, port: usize, f: &mut [u8], now: Instant, out: &mut dyn FnMut(usize, &[u8])) -> Verdict {
		match packet::parse(f) {
			Frame::Udp(u) => self.udp(w, port, f, &u, now, out),
			Frame::Arp(a) => self.arp(port, f, &a),
			Frame::Echo { src, dst, l3 } if self.ports[port].addrs.iter().any(|(ip, _)| *ip == dst) => {
				packet::echo_reply_in_place(f, l3, src, dst, self.ports[port].mac);
				Verdict::Send(port)
			}
			Frame::Fragment => {
				self.counters.fragments.fetch_add(1, Ordering::Relaxed);
				Verdict::Drop
			}
			Frame::Malformed => {
				self.counters.malformed.fetch_add(1, Ordering::Relaxed);
				Verdict::Drop
			}
			Frame::Echo { .. } | Frame::Other => {
				self.counters.not_ours.fetch_add(1, Ordering::Relaxed);
				Verdict::Drop
			}
		}
	}

	fn arp(&self, port: usize, f: &mut [u8], a: &packet::Arp) -> Verdict {
		let p = &self.ports[port];
		// learn neighbors on our links (requests and replies alike)
		if a.sender_ip != Ipv4Addr::UNSPECIFIED && p.addrs.iter().any(|(ip, pl)| on_link(a.sender_ip, *ip, *pl)) {
			lock(&self.neighbors).insert(a.sender_ip, a.sender_mac);
		}
		if a.op == packet::ARP_REQUEST && p.addrs.iter().any(|(ip, _)| *ip == a.target_ip) {
			packet::arp_reply_in_place(f, a, p.mac);
			return Verdict::Send(port);
		}
		Verdict::Drop
	}

	fn udp(&self, w: &Worker<R>, port: usize, f: &mut [u8], u: &Udp4, now: Instant, out: &mut dyn FnMut(usize, &[u8])) -> Verdict {
		let Some(li) = self.local(*u.dst.ip()) else {
			self.counters.not_ours.fetch_add(1, Ordering::Relaxed);
			return Verdict::Drop;
		};
		// an answer from a backend to a session's port
		let p = u.dst.port();
		if (self.nat_lo..=self.nat_hi).contains(&p) {
			let mut slot = lock(&self.locals[li].slots[usize::from(p - self.nat_lo)]);
			if let Some(s) = slot.as_mut().filter(|s| s.target == u.src) {
				return self.answer(s, f, u, now);
			}
		}
		match w.rules.get(&u.dst) {
			Some((rule, offset)) => self.client_datagram(port, li, rule, *offset, f, u, now, out),
			None => {
				self.counters.not_ours.fetch_add(1, Ordering::Relaxed);
				Verdict::Drop
			}
		}
	}

	fn answer(&self, s: &mut Session<R>, f: &mut [u8], u: &Udp4, now: Instant) -> Verdict {
		if s.rule.phase() == Phase::Closed || s.evicted() || !s.rule.down(&mut s.state, u.payload) {
			s.rule.dropped();
			return Verdict::Drop;
		}
		// the backend's datagrams keep only an established session
		if s.established {
			s.last = now;
		} else {
			s.answered = true;
			s.settle();
		}
		packet::rewrite_udp(f, u, self.ports[s.client_port].mac, s.client_mac, s.key.listen, s.key.client);
		Verdict::Send(s.client_port)
	}

	#[allow(clippy::too_many_arguments)]
	fn client_datagram(&self, port: usize, li: usize, rule: &Arc<R>, offset: u16, f: &mut [u8], u: &Udp4, now: Instant, out: &mut dyn FnMut(usize, &[u8])) -> Verdict {
		if rule.phase() == Phase::Closed {
			rule.dropped();
			return Verdict::Drop;
		}
		if !rule.admit(u.src) {
			return Verdict::Drop;
		}
		let key = FwdKey { listen: u.dst, client: u.src };
		let shard = &self.fwd[shard_of(&key)];
		let found = lock(shard).get(&key).copied();
		let (src_li, nat) = match found {
			Some(at) => at,
			None => {
				if rule.phase() != Phase::Open {
					rule.dropped();
					return Verdict::Drop;
				}
				match self.open(port, li, rule, offset, u, now, shard) {
					Some(at) => at,
					None => return Verdict::Drop,
				}
			}
		};
		let mut slot = lock(&self.locals[src_li].slots[usize::from(nat - self.nat_lo)]);
		let Some(s) = slot.as_mut().filter(|s| s.key == key) else {
			drop(slot);
			// ended meanwhile (the sweep, or its port given up in `open`): the next datagram opens a new one
			let mut map = lock(shard);
			if map.get(&key) == Some(&(src_li, nat)) {
				map.remove(&key);
			}
			rule.dropped();
			return Verdict::Drop;
		};
		if s.evicted() || !s.rule.up(&mut s.state, u.payload) {
			s.rule.dropped();
			return Verdict::Drop;
		}
		s.last = now;
		if !s.established {
			s.again |= found.is_some();
			s.settle();
		}
		s.client_mac = u.src_mac;
		s.client_port = port;
		let hop_mac = match s.hop_mac.or_else(|| self.neighbor(s.hop)) {
			Some(m) => m,
			None => {
				if s.arp_sent.is_none_or(|t| now.duration_since(t) >= ARP_RETRY) {
					s.arp_sent = Some(now);
					self.ask(s.egress, s.hop, now, out);
				}
				self.counters.no_neighbor.fetch_add(1, Ordering::Relaxed);
				s.rule.dropped();
				return Verdict::Drop;
			}
		};
		s.hop_mac = Some(hop_mac);
		let src = SocketAddrV4::new(self.locals[src_li].ip, nat);
		packet::rewrite_udp(f, u, self.ports[s.egress].mac, hop_mac, src, s.target);
		Verdict::Send(s.egress)
	}

	/// A new session for `u`: the rule picks the target, then a free port on
	/// the source address. Holds the client-side shard while it does, so two
	/// lcores cannot open the same session twice.
	#[allow(clippy::too_many_arguments)]
	fn open(&self, port: usize, li: usize, rule: &Arc<R>, offset: u16, u: &Udp4, now: Instant, shard: &Mutex<Fwd>) -> Option<(usize, u16)> {
		let key = FwdKey { listen: u.dst, client: u.src };
		// what earlier opens left (one entry each at most), before this one holds a shard
		if self.stale_len.load(Ordering::Relaxed) > 0 {
			self.clear_stale();
		}
		let mut map = lock(shard);
		if let Some(at) = map.get(&key) {
			return Some(*at);
		}
		let (target, state) = rule.open(u.src, u.dst, offset)?;
		let Some((egress, hop)) = self.route(*target.ip(), self.locals[li].port) else {
			self.counters.no_neighbor.fetch_add(1, Ordering::Relaxed);
			rule.dropped();
			rule.close(state, u.src, target, "no route");
			return None;
		};
		// the rule's address when it is on the egress port, else that port's first address
		let src_li = if self.locals[li].port == egress {
			li
		} else {
			let first = self.ports[egress].addrs.first().map(|(a, _)| *a);
			first.and_then(|a| self.local(a)).unwrap_or(li)
		};
		let prefix = prefix_of(*u.src.ip());
		let held = shard_of(&key);
		let Ok(freed) = self.prefix_room(src_li, prefix, held, &mut map) else {
			self.counters.nat_prefix_full.fetch_add(1, Ordering::Relaxed);
			rule.dropped();
			rule.close(state, u.src, target, "no free port");
			return None;
		};
		let rules = lock(&self.rules).clone();
		let local = &self.locals[src_li];
		let start = local.cursor.fetch_add(1, Ordering::Relaxed);
		// the port its prefix just gave up first, then ports from the cursor
		let probes = freed.into_iter().chain((0..NAT_TRIES).map(|i| (start.wrapping_mul(7919).wrapping_add(i)) % local.slots.len()));
		let mut state = state;
		for n in probes {
			let nat = self.nat_lo + n as u16;
			if rules.contains_key(&SocketAddrV4::new(local.ip, nat)) {
				continue;
			}
			let Ok(mut slot) = local.slots[n].try_lock() else { continue };
			// a session its rule ended to make room gives its port up now, not at the sweep
			if slot.as_ref().is_some_and(Session::evicted) {
				self.end(src_li, n, &mut slot, "evicted", Some((held, &mut map)));
			}
			if slot.is_some() {
				continue;
			}
			// the port is ours: only now may the rule make room for it
			if !rule.start(&mut state, u.src, u.dst, target) {
				return None;
			}
			let id = self.next_id.fetch_add(1, Ordering::Relaxed);
			*slot = Some(Session {
				key,
				rule: rule.clone(),
				offset,
				state,
				target,
				egress,
				hop,
				hop_mac: None,
				arp_sent: None,
				client_mac: u.src_mac,
				client_port: port,
				last: now,
				id,
				answered: false,
				again: false,
				established: false,
			});
			local.held.fetch_add(1, Ordering::Relaxed);
			{
				let mut prefixes = lock(&local.prefixes);
				let ports = prefixes.entry(prefix).or_default();
				ports.held += 1;
				// ended and established ones are skipped when one is looked for; keep it near what the prefix holds
				while ports.waiting.len() >= local.share().min(2 * ports.held) {
					ports.waiting.pop_front();
				}
				ports.waiting.push_back((n as u16, id));
			}
			map.insert(key, (src_li, nat));
			return Some((src_li, nat));
		}
		self.counters.nat_full.fetch_add(1, Ordering::Relaxed);
		rule.dropped();
		rule.close(state, u.src, target, "no free port");
		None
	}

	/// Whether a new session of `prefix` may take a port of `li`: below its
	/// share, or fewer than half the ports taken; else its oldest session not
	/// established gives its port up (Ok with that slot; `map`: the client-side
	/// shard `open` holds). Err: none to give up.
	fn prefix_room(&self, li: usize, prefix: u32, shard: usize, map: &mut Fwd) -> Result<Option<usize>, ()> {
		let local = &self.locals[li];
		loop {
			let (n, id) = {
				let mut prefixes = lock(&local.prefixes);
				let Some(ports) = prefixes.get_mut(&prefix) else { return Ok(None) };
				if ports.held < local.share() || local.held.load(Ordering::Relaxed) < local.slots.len() / 2 {
					return Ok(None);
				}
				ports.waiting.pop_front().ok_or(())?
			};
			let n = usize::from(n);
			let mut slot = lock(&local.slots[n]);
			if slot.as_ref().is_some_and(|s| s.id == id && !s.established) {
				self.end(li, n, &mut slot, "evicted", Some((shard, map)));
				return Ok(Some(n));
			}
		}
	}

	/// Clears the client-side entries `end` left for later (`stale`), holding no shard.
	fn clear_stale(&self) {
		let stale = {
			let mut stale = lock(&self.stale);
			self.stale_len.store(0, Ordering::Relaxed);
			std::mem::take(&mut *stale)
		};
		for (key, li, nat, id) in stale {
			let mut map = lock(&self.fwd[shard_of(&key)]);
			if map.get(&key) != Some(&(li, nat)) {
				continue;
			}
			// the same client may have its session again in the same slot since: that row is its own
			let n = usize::from(nat - self.nat_lo);
			if lock(&self.locals[li].slots[n]).as_ref().is_some_and(|s| s.key == key && s.id != id) {
				continue;
			}
			map.remove(&key);
		}
	}

	/// Whether the counts agree with the slots (`held`, and its sum over the
	/// prefixes): for the fuzz target and tests, while nothing else runs.
	#[doc(hidden)]
	pub fn check_counts(&self) -> Result<(), String> {
		for local in &self.locals {
			let taken = local.slots.iter().filter(|s| lock(s).is_some()).count();
			let held = local.held.load(Ordering::Relaxed);
			let by_prefix: usize = lock(&local.prefixes).values().map(|p| p.held).sum();
			if taken != held || held != by_prefix {
				return Err(format!("{}: {taken} slots taken, held {held}, by prefix {by_prefix}", local.ip));
			}
			if lock(&local.prefixes).values().any(|p| p.held == 0 || p.waiting.len() > 2 * p.held) {
				return Err(format!("{}: a prefix holds none, or waits on more than twice what it holds", local.ip));
			}
		}
		// every client-side row points at a slot of the same client, or waits in `stale` to be cleared
		let stale: Vec<(FwdKey, usize, u16)> = lock(&self.stale).iter().map(|&(k, li, nat, _)| (k, li, nat)).collect();
		for shard in &self.fwd {
			for (key, &(li, nat)) in lock(shard).iter() {
				let n = usize::from(nat - self.nat_lo);
				let ok = lock(&self.locals[li].slots[n]).as_ref().is_some_and(|s| s.key == *key);
				if !ok && !stale.contains(&(*key, li, nat)) {
					return Err(format!("{}: a row for {} at {li}:{nat} without its session", key.listen, key.client));
				}
			}
		}
		Ok(())
	}

	/// Ends the session in slot `n` of `li` and gives its port back. `held`: the
	/// client-side shard the caller holds (its index and map), if any; an entry
	/// in another shard is left for the next `open` or the sweep to clear
	/// (`stale`), so that no two shards are held at once.
	fn end(&self, li: usize, n: usize, slot: &mut Option<Session<R>>, reason: &'static str, held: Option<(usize, &mut Fwd)>) {
		let Some(s) = slot.take() else { return };
		let at = (li, self.nat_lo + n as u16);
		match held {
			Some((shard, map)) if shard == shard_of(&s.key) => {
				if map.get(&s.key) == Some(&at) {
					map.remove(&s.key);
				}
			}
			Some(_) => {
				let mut stale = lock(&self.stale);
				stale.push((s.key, at.0, at.1, s.id));
				self.stale_len.store(stale.len(), Ordering::Relaxed);
			}
			None => {
				let mut map = lock(&self.fwd[shard_of(&s.key)]);
				if map.get(&s.key) == Some(&at) {
					map.remove(&s.key);
				}
			}
		}
		let local = &self.locals[li];
		local.held.fetch_sub(1, Ordering::Relaxed);
		{
			let mut prefixes = lock(&local.prefixes);
			let prefix = prefix_of(*s.key.client.ip());
			if let Some(ports) = prefixes.get_mut(&prefix) {
				ports.held -= 1;
				if ports.held == 0 {
					prefixes.remove(&prefix);
				} else {
					// bounded by what it holds: the oldest go first (most likely ended)
					while ports.waiting.len() > 2 * ports.held {
						ports.waiting.pop_front();
					}
				}
			}
		}
		s.rule.close(s.state, s.key.client, s.target, reason);
	}

	/// Once a second (one lcore): ends idle sessions (sooner when not
	/// established), those of stopped rules and those their rule evicted, moves
	/// sessions off targets that went down, and picks up neighbors' new MACs.
	/// Returns the sessions still open.
	pub fn sweep(&self, now: Instant) -> usize {
		self.clear_stale();
		let mut open = 0;
		for (li, local) in self.locals.iter().enumerate() {
			for (n, slot) in local.slots.iter().enumerate() {
				let mut guard = lock(slot);
				let Some(s) = guard.as_mut() else { continue };
				if let Some(reason) = s.ends(now) {
					let mut s = guard.take();
					drop(guard);
					self.end(li, n, &mut s, reason, None);
					continue;
				}
				open += 1;
				if let Some(next) = s.rule.retarget(&mut s.state, s.offset, s.target) {
					if let Some((egress, hop)) = self.route(*next.ip(), s.egress) {
						s.target = next;
						s.egress = egress;
						s.hop = hop;
						s.hop_mac = None;
					}
				}
				if let Some(m) = self.neighbor(s.hop) {
					s.hop_mac = Some(m);
				}
			}
		}
		open
	}
}

fn shard_of(k: &FwdKey) -> usize {
	let (a, b) = (u32::from(*k.client.ip()), u32::from(*k.listen.ip()));
	let h = (u64::from(a) << 16 | u64::from(k.client.port())) ^ (u64::from(b) << 20) ^ u64::from(k.listen.port());
	(h.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 58) as usize % SHARDS
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;
	use std::sync::atomic::AtomicBool;

	/// A rule with one target; counts what the forwarder tells it.
	pub struct TestRule {
		pub target: Mutex<SocketAddrV4>,
		pub phase: Mutex<Phase>,
		pub deny: AtomicBool,
		pub opened: AtomicU64,
		pub closed: Mutex<Vec<&'static str>>,
		pub dropped: AtomicU64,
		pub idle: Duration,
		/// Every session not established counts as evicted (`Rule::evicted`).
		pub evict: AtomicBool,
		pub established: AtomicU64,
		/// Sessions that got their port (`Rule::start`).
		pub started: AtomicU64,
	}

	impl TestRule {
		pub fn new(target: &str) -> Arc<Self> {
			Arc::new(TestRule {
				target: Mutex::new(target.parse().unwrap()),
				phase: Mutex::new(Phase::Open),
				deny: AtomicBool::new(false),
				opened: AtomicU64::new(0),
				closed: Mutex::default(),
				dropped: AtomicU64::new(0),
				idle: Duration::from_secs(30),
				evict: AtomicBool::new(false),
				established: AtomicU64::new(0),
				started: AtomicU64::new(0),
			})
		}
	}

	impl Rule for TestRule {
		type Session = (u64, u64);
		fn phase(&self) -> Phase {
			*self.phase.lock().unwrap()
		}
		fn admit(&self, _: SocketAddrV4) -> bool {
			!self.deny.load(Ordering::Relaxed)
		}
		fn open(&self, _: SocketAddrV4, _: SocketAddrV4, offset: u16) -> Option<(SocketAddrV4, (u64, u64))> {
			self.opened.fetch_add(1, Ordering::Relaxed);
			let t = *self.target.lock().unwrap();
			Some((SocketAddrV4::new(*t.ip(), t.port() + offset), (0, 0)))
		}
		fn up(&self, s: &mut (u64, u64), len: usize) -> bool {
			s.0 += len as u64;
			true
		}
		fn down(&self, s: &mut (u64, u64), len: usize) -> bool {
			s.1 += len as u64;
			true
		}
		fn dropped(&self) {
			self.dropped.fetch_add(1, Ordering::Relaxed);
		}
		fn idle(&self) -> Duration {
			self.idle
		}
		fn retarget(&self, _: &mut (u64, u64), offset: u16, current: SocketAddrV4) -> Option<SocketAddrV4> {
			let t = *self.target.lock().unwrap();
			let t = SocketAddrV4::new(*t.ip(), t.port() + offset);
			(t != current).then_some(t)
		}
		fn close(&self, _: (u64, u64), _: SocketAddrV4, _: SocketAddrV4, reason: &'static str) {
			self.closed.lock().unwrap().push(reason);
		}
		fn established(&self, _: &mut (u64, u64)) {
			self.established.fetch_add(1, Ordering::Relaxed);
		}
		fn start(&self, _: &mut (u64, u64), _: SocketAddrV4, _: SocketAddrV4, _: SocketAddrV4) -> bool {
			self.started.fetch_add(1, Ordering::Relaxed);
			true
		}
		fn evicted(&self, _: &(u64, u64)) -> bool {
			self.evict.load(Ordering::Relaxed)
		}
	}

	pub const OURS: Mac = [2, 0, 0, 0, 0, 0xaa];
	pub const CLIENT_MAC: Mac = [2, 0, 0, 0, 0, 3];
	pub const BACKEND_MAC: Mac = [2, 0, 0, 0, 0, 2];
	pub const GW_MAC: Mac = [2, 0, 0, 0, 0, 1];

	fn sa(s: &str) -> SocketAddrV4 {
		s.parse().unwrap()
	}

	fn engine() -> Engine<TestRule> {
		Engine::new(vec![PortCfg { mac: OURS, addrs: vec![("10.0.0.10".parse().unwrap(), 24)], gateway: Some("10.0.0.1".parse().unwrap()) }])
	}

	fn run(e: &Engine<TestRule>, f: &mut [u8], now: Instant) -> (Verdict, Vec<Vec<u8>>) {
		let mut w = e.worker();
		e.refresh(&mut w);
		let mut sent = vec![];
		let v = e.process(&w, 0, f, now, &mut |_, b| sent.push(b.to_vec()));
		(v, sent)
	}

	fn arp_reply(from_mac: Mac, from_ip: &str) -> Vec<u8> {
		let mut f = vec![0u8; packet::ARP_FRAME];
		packet::arp_frame(&mut f, packet::ARP_REPLY, from_mac, from_ip.parse().unwrap(), OURS, "10.0.0.10".parse().unwrap());
		f
	}

	#[test]
	fn forwards_both_ways_with_arp_and_nat() {
		let e = engine();
		let rule = TestRule::new("10.0.0.20:6000");
		e.register("10.0.0.10".parse().unwrap(), 5000, 2, rule.clone()).unwrap();
		let now = Instant::now();
		let mut f = packet::udp_frame(CLIENT_MAC, OURS, sa("10.0.0.30:40000"), sa("10.0.0.10:5001"), b"hello", true);
		// the backend's MAC is not known yet: an ARP request goes out, the datagram is dropped
		let (v, sent) = run(&e, &mut f.clone(), now);
		assert_eq!(v, Verdict::Drop);
		assert_eq!(sent.len(), 1);
		let Frame::Arp(a) = packet::parse(&sent[0]) else { panic!() };
		assert_eq!((a.op, a.target_ip), (packet::ARP_REQUEST, "10.0.0.20".parse().unwrap()));
		// not asked again within a second
		assert!(run(&e, &mut f.clone(), now).1.is_empty());
		assert_eq!(run(&e, &mut arp_reply(BACKEND_MAC, "10.0.0.20"), now).0, Verdict::Drop);

		let (v, _) = run(&e, &mut f, now);
		assert_eq!(v, Verdict::Send(0));
		let Frame::Udp(u) = packet::parse(&f) else { panic!() };
		assert_eq!(*u.src.ip(), "10.0.0.10".parse::<Ipv4Addr>().unwrap());
		assert!((NAT_LO..=NAT_HI).contains(&u.src.port()));
		assert_eq!(u.dst, sa("10.0.0.20:6001"), "port range: the offset carries over");
		assert_eq!((&f[0..6], &f[6..12]), (&BACKEND_MAC[..], &OURS[..]));
		assert!(packet::checksums_ok(&f, &u));
		assert_eq!(packet::payload(&f, &u), b"hello");
		let nat = u.src;

		// the answer goes back from the rule's address and port
		let mut r = packet::udp_frame(BACKEND_MAC, OURS, sa("10.0.0.20:6001"), nat, b"world!", true);
		assert_eq!(run(&e, &mut r, now).0, Verdict::Send(0));
		let Frame::Udp(u) = packet::parse(&r) else { panic!() };
		assert_eq!((u.src, u.dst), (sa("10.0.0.10:5001"), sa("10.0.0.30:40000")));
		assert_eq!(&r[0..6], &CLIENT_MAC);
		assert!(packet::checksums_ok(&r, &u));
		assert_eq!(packet::payload(&r, &u), b"world!");

		// from another address to the session's port: not the backend, dropped
		let mut spoof = packet::udp_frame(BACKEND_MAC, OURS, sa("10.0.0.21:6001"), nat, b"x", true);
		assert_eq!(run(&e, &mut spoof, now).0, Verdict::Drop);
		assert_eq!(rule.opened.load(Ordering::Relaxed), 1, "one session");

		// idle: the sweep ends it
		assert_eq!(e.sweep(now + Duration::from_secs(1)), 1);
		assert_eq!(e.sweep(now + Duration::from_secs(31)), 0);
		assert_eq!(*rule.closed.lock().unwrap(), ["idle"]);
		let mut late = packet::udp_frame(BACKEND_MAC, OURS, sa("10.0.0.20:6001"), nat, b"late", true);
		assert_eq!(run(&e, &mut late, now).0, Verdict::Drop);
	}

	#[test]
	fn off_link_backends_go_through_the_gateway_and_retarget() {
		let e = engine();
		let rule = TestRule::new("192.0.2.5:53");
		e.register("10.0.0.10".parse().unwrap(), 53, 1, rule.clone()).unwrap();
		let now = Instant::now();
		run(&e, &mut arp_reply(GW_MAC, "10.0.0.1"), now);
		let mut f = packet::udp_frame(CLIENT_MAC, OURS, sa("10.0.0.30:1000"), sa("10.0.0.10:53"), b"q", false);
		assert_eq!(run(&e, &mut f, now).0, Verdict::Send(0));
		assert_eq!(&f[0..6], &GW_MAC);
		let Frame::Udp(u) = packet::parse(&f) else { panic!() };
		assert!(packet::checksums_ok(&f, &u));
		// the target changes: open sessions move at the next sweep
		*rule.target.lock().unwrap() = sa("192.0.2.6:53");
		e.sweep(now);
		let mut f = packet::udp_frame(CLIENT_MAC, OURS, sa("10.0.0.30:1000"), sa("10.0.0.10:53"), b"q", false);
		assert_eq!(run(&e, &mut f, now).0, Verdict::Send(0));
		let Frame::Udp(u) = packet::parse(&f) else { panic!() };
		assert_eq!(u.dst, sa("192.0.2.6:53"));
	}

	#[test]
	fn refused_draining_stopped_and_unknown() {
		let e = engine();
		let rule = TestRule::new("10.0.0.20:6000");
		e.register("10.0.0.10".parse().unwrap(), 5000, 1, rule.clone()).unwrap();
		let now = Instant::now();
		run(&e, &mut arp_reply(BACKEND_MAC, "10.0.0.20"), now);
		let frame = |c: &str| packet::udp_frame(CLIENT_MAC, OURS, sa(c), sa("10.0.0.10:5000"), b"x", true);
		rule.deny.store(true, Ordering::Relaxed);
		assert_eq!(run(&e, &mut frame("10.0.0.30:1"), now).0, Verdict::Drop);
		rule.deny.store(false, Ordering::Relaxed);
		assert_eq!(run(&e, &mut frame("10.0.0.30:1"), now).0, Verdict::Send(0));
		*rule.phase.lock().unwrap() = Phase::Draining;
		assert_eq!(run(&e, &mut frame("10.0.0.30:1"), now).0, Verdict::Send(0), "open sessions go on");
		assert_eq!(run(&e, &mut frame("10.0.0.30:2"), now).0, Verdict::Drop, "no new ones");
		*rule.phase.lock().unwrap() = Phase::Closed;
		assert_eq!(run(&e, &mut frame("10.0.0.30:1"), now).0, Verdict::Drop);
		e.sweep(now);
		assert_eq!(*rule.closed.lock().unwrap(), ["stopped"]);
		// other ports, other addresses
		let mut other = packet::udp_frame(CLIENT_MAC, OURS, sa("10.0.0.30:1"), sa("10.0.0.10:5999"), b"x", true);
		assert_eq!(run(&e, &mut other, now).0, Verdict::Drop);
		let mut far = packet::udp_frame(CLIENT_MAC, OURS, sa("10.0.0.30:1"), sa("10.0.0.11:5000"), b"x", true);
		assert_eq!(run(&e, &mut far, now).0, Verdict::Drop);
		e.unregister("10.0.0.10".parse().unwrap(), 5000, 1, &rule);
		assert!(e.register("10.0.0.10".parse().unwrap(), 5000, 1, TestRule::new("10.0.0.20:1")).is_ok());
		assert!(e.register("10.0.0.10".parse().unwrap(), 5000, 1, TestRule::new("10.0.0.20:1")).is_err(), "taken");
		assert!(e.register("10.9.9.9".parse().unwrap(), 5000, 1, TestRule::new("10.0.0.20:1")).is_err(), "not ours");
	}

	#[test]
	fn answers_arp_and_ping_for_its_addresses_only() {
		let e = engine();
		let now = Instant::now();
		let mut req = vec![0u8; packet::ARP_FRAME];
		packet::arp_frame(&mut req, packet::ARP_REQUEST, CLIENT_MAC, "10.0.0.30".parse().unwrap(), [0; 6], "10.0.0.10".parse().unwrap());
		assert_eq!(run(&e, &mut req, now).0, Verdict::Send(0));
		let Frame::Arp(a) = packet::parse(&req) else { panic!() };
		assert_eq!((a.op, a.sender_mac), (packet::ARP_REPLY, OURS));
		assert_eq!(e.neighbor("10.0.0.30".parse().unwrap()), Some(CLIENT_MAC), "learned from the request");
		let mut other = vec![0u8; packet::ARP_FRAME];
		packet::arp_frame(&mut other, packet::ARP_REQUEST, CLIENT_MAC, "10.0.0.30".parse().unwrap(), [0; 6], "10.0.0.99".parse().unwrap());
		assert_eq!(run(&e, &mut other, now).0, Verdict::Drop);
	}

	#[test]
	fn many_clients_get_distinct_ports() {
		let e = engine();
		let rule = TestRule::new("10.0.0.20:6000");
		e.register("10.0.0.10".parse().unwrap(), 5000, 1, rule.clone()).unwrap();
		let now = Instant::now();
		run(&e, &mut arp_reply(BACKEND_MAC, "10.0.0.20"), now);
		let mut ports = std::collections::HashSet::new();
		for i in 0..2000u16 {
			let mut f = packet::udp_frame(CLIENT_MAC, OURS, SocketAddrV4::new("10.0.0.30".parse().unwrap(), 1000 + i), sa("10.0.0.10:5000"), b"x", true);
			assert_eq!(run(&e, &mut f, now).0, Verdict::Send(0));
			let Frame::Udp(u) = packet::parse(&f) else { panic!() };
			assert!(ports.insert(u.src.port()));
		}
		assert_eq!(e.sweep(now), 2000);
	}

	fn from(client: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
		packet::udp_frame(CLIENT_MAC, OURS, client, sa("10.0.0.10:5000"), payload, true)
	}

	/// The NAT port a client's datagram went out from.
	fn nat_of(e: &Engine<TestRule>, client: SocketAddrV4, now: Instant) -> SocketAddrV4 {
		let mut f = from(client, b"x");
		assert_eq!(run(e, &mut f, now).0, Verdict::Send(0));
		let Frame::Udp(u) = packet::parse(&f) else { panic!() };
		u.src
	}

	fn answer(e: &Engine<TestRule>, nat: SocketAddrV4, now: Instant) -> Verdict {
		run(e, &mut packet::udp_frame(BACKEND_MAC, OURS, sa("10.0.0.20:6000"), nat, b"r", true), now).0
	}

	// #366: as on the kernel's path, a session not established (a backend reply and a second datagram from the
	// client) ends UNREPLIED_TIMEOUT after the client's last datagram, the backend's do not keep it; established, idle
	#[test]
	fn sessions_not_established_end_after_five_seconds() {
		let e = engine();
		let rule = TestRule::new("10.0.0.20:6000");
		e.register("10.0.0.10".parse().unwrap(), 5000, 1, rule.clone()).unwrap();
		let now = Instant::now();
		run(&e, &mut arp_reply(BACKEND_MAC, "10.0.0.20"), now);
		// a spoofed source: one datagram, which the backend answers again and again
		let spoofed = nat_of(&e, sa("192.0.2.7:1000"), now);
		// a client: two datagrams and an answer
		let client = sa("198.51.100.7:1000");
		let nat = nat_of(&e, client, now);
		assert_eq!(nat_of(&e, client, now), nat);
		assert_eq!(answer(&e, nat, now), Verdict::Send(0));
		assert_eq!(rule.established.load(Ordering::Relaxed), 1);
		for t in 1..5 {
			assert_eq!(answer(&e, spoofed, now + Duration::from_secs(t)), Verdict::Send(0));
		}
		assert_eq!(e.sweep(now + Duration::from_secs(4)), 2);
		assert_eq!(e.sweep(now + Duration::from_secs(5)), 1, "the backend's datagrams did not keep it");
		assert_eq!(*rule.closed.lock().unwrap(), ["idle"]);
		assert_eq!(e.sweep(now + Duration::from_secs(29)), 1);
		assert_eq!(e.sweep(now + Duration::from_secs(30)), 0);
		assert_eq!(rule.established.load(Ordering::Relaxed), 1);
	}

	// #366: a session its rule evicted (at the cap) passes nothing more and gives its port up at once to a new
	// session that finds it, or at the sweep; established sessions are not asked
	#[test]
	fn evicted_sessions_end() {
		let e = Engine::with_nat_ports(vec![PortCfg { mac: OURS, addrs: vec![("10.0.0.10".parse().unwrap(), 24)], gateway: None }], 40000, 40001);
		let rule = TestRule::new("10.0.0.20:6000");
		e.register("10.0.0.10".parse().unwrap(), 5000, 1, rule.clone()).unwrap();
		let now = Instant::now();
		run(&e, &mut arp_reply(BACKEND_MAC, "10.0.0.20"), now);
		// three networks: none over its share of the ports
		let (a, b, c) = (sa("192.0.2.1:1"), sa("198.51.100.2:1"), sa("203.0.113.3:1"));
		let nat_a = nat_of(&e, a, now);
		nat_of(&e, a, now);
		assert_eq!(answer(&e, nat_a, now), Verdict::Send(0), "a is established");
		nat_of(&e, b, now);
		// both ports taken: no room for c, and the rule is not asked to make room at its cap (#366)
		assert_eq!(rule.started.load(Ordering::Relaxed), 2);
		assert_eq!(run(&e, &mut from(c, b"x"), now).0, Verdict::Drop);
		assert_eq!(rule.started.load(Ordering::Relaxed), 2);
		rule.evict.store(true, Ordering::Relaxed);
		assert_eq!(nat_of(&e, a, now), nat_a, "established: not evicted");
		// b's port goes to c (the rule evicted b)
		let mut f = from(c, b"x");
		assert_eq!(run(&e, &mut f, now).0, Verdict::Drop, "c's own session is not established either");
		assert_eq!(*rule.closed.lock().unwrap(), ["no free port", "evicted"]);
		// the sweep ends c (in b's port, evicted too); a stays
		assert_eq!(e.sweep(now), 1);
		assert_eq!(*rule.closed.lock().unwrap(), ["no free port", "evicted", "evicted"]);
		// b's next datagram opens a new session
		rule.evict.store(false, Ordering::Relaxed);
		assert_eq!(run(&e, &mut from(b, b"x"), now).0, Verdict::Send(0));
	}

	// #366: one /24 holds at most its share of an address's NAT ports once half of them are taken; past that,
	// its own oldest session not established gives its port up, and with none the new session is refused
	#[test]
	fn a_prefix_holds_at_most_its_share_of_the_ports() {
		let e = Engine::with_nat_ports(vec![PortCfg { mac: OURS, addrs: vec![("10.0.0.10".parse().unwrap(), 24)], gateway: None }], 40000, 40255);
		let rule = TestRule::new("10.0.0.20:6000");
		e.register("10.0.0.10".parse().unwrap(), 5000, 1, rule.clone()).unwrap();
		let now = Instant::now();
		run(&e, &mut arp_reply(BACKEND_MAC, "10.0.0.20"), now);
		let share = e.locals[0].share();
		assert_eq!(share, NAT_PREFIX_MIN);
		let flood = |i: u16| SocketAddrV4::new("192.0.2.0".parse().unwrap(), 1000 + i);
		// below half the ports: a prefix may hold more than its share
		for i in 0..100 {
			nat_of(&e, flood(i), now);
		}
		// another network fills up to half
		let other = |i: u16| SocketAddrV4::new(Ipv4Addr::from(0xc633_6400 + u32::from(i)), 1);
		for i in 0..28 {
			nat_of(&e, other(i), now);
		}
		assert_eq!(e.locals[0].held.load(Ordering::Relaxed), 128);
		// the flood's next session takes the port of its own oldest
		nat_of(&e, flood(100), now);
		assert_eq!(*rule.closed.lock().unwrap(), ["evicted"]);
		assert_eq!(e.locals[0].held.load(Ordering::Relaxed), 128);
		// the other network is below its share: no eviction
		nat_of(&e, other(28), now);
		assert_eq!(rule.closed.lock().unwrap().len(), 1);
		assert_eq!(e.sweep(now), 129);
		// established, the flood's sessions are not given up: refused
		let established = Engine::with_nat_ports(vec![PortCfg { mac: OURS, addrs: vec![("10.0.0.10".parse().unwrap(), 24)], gateway: None }], 40000, 40255);
		let rule = TestRule::new("10.0.0.20:6000");
		established.register("10.0.0.10".parse().unwrap(), 5000, 1, rule.clone()).unwrap();
		run(&established, &mut arp_reply(BACKEND_MAC, "10.0.0.20"), now);
		for i in 0..128 {
			let nat = nat_of(&established, flood(i), now);
			nat_of(&established, flood(i), now);
			assert_eq!(answer(&established, nat, now), Verdict::Send(0));
		}
		let started = rule.started.load(Ordering::Relaxed);
		assert_eq!(run(&established, &mut from(flood(500), b"x"), now).0, Verdict::Drop);
		assert_eq!(established.counters.nat_prefix_full.load(Ordering::Relaxed), 1);
		assert_eq!(rule.started.load(Ordering::Relaxed), started, "refused for its prefix: the rule made no room for it");
		assert_eq!(*rule.closed.lock().unwrap(), ["no free port"]);
		assert_eq!(run(&established, &mut from(other(0), b"x"), now).0, Verdict::Send(0), "other networks still get ports");
		established.check_counts().unwrap();
		e.check_counts().unwrap();
		// the prefixes' table empties as their sessions end
		established.sweep(now + Duration::from_secs(60));
		established.check_counts().unwrap();
		assert!(lock(&established.locals[0].prefixes).is_empty());
	}

	// #366: a rule that refuses in `start` (nothing to evict at its cap) leaves no session and no count behind
	#[test]
	fn a_session_refused_at_start_takes_no_port() {
		struct Refusing(Arc<TestRule>);
		impl Rule for Refusing {
			type Session = (u64, u64);
			fn phase(&self) -> Phase {
				Phase::Open
			}
			fn admit(&self, c: SocketAddrV4) -> bool {
				self.0.admit(c)
			}
			fn open(&self, c: SocketAddrV4, l: SocketAddrV4, o: u16) -> Option<(SocketAddrV4, (u64, u64))> {
				self.0.open(c, l, o)
			}
			fn start(&self, _: &mut (u64, u64), _: SocketAddrV4, _: SocketAddrV4, _: SocketAddrV4) -> bool {
				false
			}
			fn up(&self, s: &mut (u64, u64), len: usize) -> bool {
				self.0.up(s, len)
			}
			fn down(&self, s: &mut (u64, u64), len: usize) -> bool {
				self.0.down(s, len)
			}
			fn dropped(&self) {}
			fn idle(&self) -> Duration {
				self.0.idle
			}
			fn retarget(&self, _: &mut (u64, u64), _: u16, _: SocketAddrV4) -> Option<SocketAddrV4> {
				None
			}
			fn close(&self, s: (u64, u64), c: SocketAddrV4, t: SocketAddrV4, reason: &'static str) {
				self.0.close(s, c, t, reason)
			}
		}
		let e: Engine<Refusing> = Engine::new(vec![PortCfg { mac: OURS, addrs: vec![("10.0.0.10".parse().unwrap(), 24)], gateway: None }]);
		let inner = TestRule::new("10.0.0.20:6000");
		e.register("10.0.0.10".parse().unwrap(), 5000, 1, Arc::new(Refusing(inner.clone()))).unwrap();
		let now = Instant::now();
		let mut w = e.worker();
		e.refresh(&mut w);
		let mut f = packet::udp_frame(CLIENT_MAC, OURS, sa("192.0.2.1:1"), sa("10.0.0.10:5000"), b"x", true);
		assert_eq!(e.process(&w, 0, &mut f, now, &mut |_, _| {}), Verdict::Drop);
		assert!(inner.closed.lock().unwrap().is_empty(), "refused by the rule itself: no close");
		e.check_counts().unwrap();
		assert_eq!(e.sweep(now), 0);
		assert!(lock(&e.fwd[0]).is_empty() && e.fwd.iter().all(|m| lock(m).is_empty()));
	}
}
