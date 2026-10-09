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

use std::collections::HashMap;
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
	/// the datagram (counted and logged by the rule).
	fn open(&self, client: SocketAddrV4, listen: SocketAddrV4, offset: u16) -> Option<(SocketAddrV4, Self::Session)>;
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
	last: Instant,
}

/// One source address of sessions: a slot per NAT port.
struct Local<R: Rule> {
	ip: Ipv4Addr,
	port: usize,
	slots: Box<[Mutex<Option<Session<R>>>]>,
	cursor: AtomicUsize,
}

type Table<R> = HashMap<SocketAddrV4, (Arc<R>, u16)>;

pub struct Engine<R: Rule> {
	ports: Vec<PortCfg>,
	/// The NAT ports (`NAT_LO..=NAT_HI` unless `with_nat_ports`).
	nat_lo: u16,
	nat_hi: u16,
	locals: Vec<Local<R>>,
	rules: Mutex<Arc<Table<R>>>,
	version: AtomicU64,
	fwd: Vec<Mutex<HashMap<FwdKey, (usize, u16)>>>,
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
			neighbors: Mutex::default(),
			arp_pending: Mutex::default(),
			counters: Counters::default(),
		}
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
		if s.rule.phase() == Phase::Closed || !s.rule.down(&mut s.state, u.payload) {
			s.rule.dropped();
			return Verdict::Drop;
		}
		s.last = now;
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
			// ended by the sweep meanwhile; the next datagram opens a new one
			rule.dropped();
			return Verdict::Drop;
		};
		if !s.rule.up(&mut s.state, u.payload) {
			s.rule.dropped();
			return Verdict::Drop;
		}
		s.last = now;
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
	fn open(&self, port: usize, li: usize, rule: &Arc<R>, offset: u16, u: &Udp4, now: Instant, shard: &Mutex<HashMap<FwdKey, (usize, u16)>>) -> Option<(usize, u16)> {
		let key = FwdKey { listen: u.dst, client: u.src };
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
		let rules = lock(&self.rules).clone();
		let local = &self.locals[src_li];
		let start = local.cursor.fetch_add(1, Ordering::Relaxed);
		let mut state = Some(state);
		for i in 0..NAT_TRIES {
			let n = (start.wrapping_mul(7919).wrapping_add(i)) % local.slots.len();
			let nat = self.nat_lo + n as u16;
			if rules.contains_key(&SocketAddrV4::new(local.ip, nat)) {
				continue;
			}
			let Ok(mut slot) = local.slots[n].try_lock() else { continue };
			if slot.is_some() {
				continue;
			}
			*slot = Some(Session {
				key,
				rule: rule.clone(),
				offset,
				state: state.take()?,
				target,
				egress,
				hop,
				hop_mac: None,
				arp_sent: None,
				client_mac: u.src_mac,
				client_port: port,
				last: now,
			});
			map.insert(key, (src_li, nat));
			return Some((src_li, nat));
		}
		self.counters.nat_full.fetch_add(1, Ordering::Relaxed);
		rule.dropped();
		if let Some(state) = state {
			rule.close(state, u.src, target, "no free port");
		}
		None
	}

	/// Once a second (one lcore): ends idle sessions and those of stopped
	/// rules, moves sessions off targets that went down, and picks up
	/// neighbors' new MACs. Returns the sessions still open.
	pub fn sweep(&self, now: Instant) -> usize {
		let mut open = 0;
		for (li, local) in self.locals.iter().enumerate() {
			for (n, slot) in local.slots.iter().enumerate() {
				let mut guard = lock(slot);
				let Some(s) = guard.as_mut() else { continue };
				let reason = if s.rule.phase() == Phase::Closed {
					Some("stopped")
				} else if now.duration_since(s.last) >= s.rule.idle() {
					Some("idle")
				} else {
					None
				};
				if let Some(reason) = reason {
					let s = guard.take().expect("checked above");
					drop(guard);
					let mut map = lock(&self.fwd[shard_of(&s.key)]);
					if map.get(&s.key) == Some(&(li, self.nat_lo + n as u16)) {
						map.remove(&s.key);
					}
					drop(map);
					s.rule.close(s.state, s.key.client, s.target, reason);
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
}
