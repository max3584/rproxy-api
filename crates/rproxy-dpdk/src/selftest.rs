//! The startup check of the DPDK path (#261; the owner's rule in #260: push
//! test data through the fast path and compare it before enabling it).
//!
//! `scenario` drives the forwarder with a rule of its own on documentation
//! addresses (RFC 5737): ARP both ways, then a burst of datagrams of several
//! sizes from a client to the rule and the backend's answers, and checks every
//! frame that comes out (addresses, ports, MACs, checksums, payload). The
//! frames travel through a `Wire`: in the unit tests a direct call, at startup
//! real mbufs through a loopback `net_ring` port (`io::RingWire`), so the
//! mempool, the burst functions and the rewriting on mbuf memory are what is
//! checked.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::engine::{Engine, Phase, PortCfg, Rule, Verdict};
use crate::packet::{self, Frame, Mac};

const OUR_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LISTEN: SocketAddrV4 = SocketAddrV4::new(OUR_IP, 5000);
const BACKEND: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 6000);
const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 3), 40000);
const BACKEND_MAC: Mac = [2, 0x52, 0x50, 0, 0, 2];
const CLIENT_MAC: Mac = [2, 0x52, 0x50, 0, 0, 3];
/// Payload sizes sent in one burst (up to the burst size): empty, odd, small,
/// and the largest that fits a 1500-byte MTU.
pub const SIZES: [usize; 8] = [0, 1, 17, 64, 255, 512, 1024, 1472];

/// The forwarder's handling of one frame: rewrites it in place (the verdict)
/// and sends new frames through the callback.
pub type Handle<'a> = dyn FnMut(&mut [u8], &mut dyn FnMut(usize, &[u8])) -> Verdict + 'a;

/// Moves frames through the path under test.
pub trait Wire {
	/// Sends `frames` into the port, runs the forwarder (`f`) over what the
	/// port received, sends what the forwarder sent back through the port and
	/// returns what came out, in order.
	fn forward(&mut self, frames: Vec<Vec<u8>>, f: &mut Handle) -> Result<Vec<Vec<u8>>, String>;
}

/// The check's own rule: one target, nothing refused.
pub struct CheckRule {
	opened: AtomicU64,
	closed: Mutex<Vec<&'static str>>,
}

impl Rule for CheckRule {
	type Session = ();
	fn phase(&self) -> Phase {
		Phase::Open
	}
	fn admit(&self, _: SocketAddrV4) -> bool {
		true
	}
	fn open(&self, _: SocketAddrV4, _: SocketAddrV4, _: u16) -> Option<(SocketAddrV4, ())> {
		self.opened.fetch_add(1, Ordering::Relaxed);
		Some((BACKEND, ()))
	}
	fn up(&self, _: &mut (), _: usize) -> bool {
		true
	}
	fn down(&self, _: &mut (), _: usize) -> bool {
		true
	}
	fn dropped(&self) {}
	fn idle(&self) -> Duration {
		Duration::from_secs(60)
	}
	fn retarget(&self, _: &mut (), _: u16, _: SocketAddrV4) -> Option<SocketAddrV4> {
		None
	}
	fn close(&self, _: (), _: SocketAddrV4, _: SocketAddrV4, reason: &'static str) {
		self.closed.lock().unwrap_or_else(|e| e.into_inner()).push(reason);
	}
}

fn payload_of(size: usize, seed: u8) -> Vec<u8> {
	(0..size).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// Runs the check over `wire` for a port whose MAC is `mac`, sending at most
/// `burst` frames at once. Ok when every frame came out as expected; else what
/// did not match.
pub fn scenario(wire: &mut dyn Wire, mac: Mac, burst: usize) -> Result<(), String> {
	let engine: Engine<CheckRule> = Engine::new(vec![PortCfg { mac, addrs: vec![(OUR_IP, 24)], gateway: None }]);
	let rule = Arc::new(CheckRule { opened: AtomicU64::new(0), closed: Mutex::default() });
	engine.register(OUR_IP, LISTEN.port(), 1, rule.clone())?;
	let mut w = engine.worker();
	engine.refresh(&mut w);
	let now = Instant::now();
	let mut step = |frames: Vec<Vec<u8>>| -> Result<Vec<Vec<u8>>, String> { wire.forward(frames, &mut |f, out| engine.process(&w, 0, f, now, out)) };

	// 1. the client asks for our MAC
	let mut req = vec![0u8; packet::ARP_FRAME];
	packet::arp_frame(&mut req, packet::ARP_REQUEST, CLIENT_MAC, *CLIENT.ip(), [0; 6], OUR_IP);
	let out = step(vec![req])?;
	match out.as_slice() {
		[f] if matches!(packet::parse(f), Frame::Arp(a) if a.op == packet::ARP_REPLY && a.sender_mac == mac && a.sender_ip == OUR_IP && a.target_ip == *CLIENT.ip())
			&& f[0..6] == CLIENT_MAC => {}
		other => return Err(format!("ARP: expected our reply to the client, got {} frame(s)", other.len())),
	}

	// 2. the first datagram: the backend's MAC is unknown, so we ask for it
	let first = packet::udp_frame(CLIENT_MAC, mac, CLIENT, LISTEN, b"rproxy-dpdk-check", true);
	let out = step(vec![first])?;
	match out.as_slice() {
		[f] if matches!(packet::parse(f), Frame::Arp(a) if a.op == packet::ARP_REQUEST && a.target_ip == *BACKEND.ip() && a.sender_mac == mac) => {}
		other => return Err(format!("ARP: expected a request for the backend, got {} frame(s)", other.len())),
	}
	let mut reply = vec![0u8; packet::ARP_FRAME];
	packet::arp_frame(&mut reply, packet::ARP_REPLY, BACKEND_MAC, *BACKEND.ip(), mac, OUR_IP);
	if !step(vec![reply])?.is_empty() {
		return Err("ARP: a reply to us was answered".into());
	}

	// 3. a burst of datagrams of several sizes to the rule
	let sizes: Vec<usize> = SIZES.iter().copied().cycle().take(burst.max(1)).collect();
	let sent: Vec<Vec<u8>> = sizes.iter().enumerate().map(|(i, s)| payload_of(*s, i as u8)).collect();
	let frames = sent.iter().enumerate().map(|(i, p)| packet::udp_frame(CLIENT_MAC, mac, CLIENT, LISTEN, p, i % 3 != 2)).collect();
	let out = step(frames)?;
	if out.len() != sent.len() {
		return Err(format!("client to backend: sent {} datagrams, {} came out", sent.len(), out.len()));
	}
	let mut nat = None;
	for (i, (f, p)) in out.iter().zip(&sent).enumerate() {
		let Frame::Udp(u) = packet::parse(f) else { return Err(format!("client to backend #{i}: not a UDP datagram")) };
		if *u.src.ip() != OUR_IP || u.dst != BACKEND || f[0..6] != BACKEND_MAC || f[6..12] != mac {
			return Err(format!("client to backend #{i}: addressed {} -> {}", u.src, u.dst));
		}
		if *nat.get_or_insert(u.src) != u.src {
			return Err(format!("client to backend #{i}: the session's port changed"));
		}
		if !packet::checksums_ok(f, &u) {
			return Err(format!("client to backend #{i}: bad checksum"));
		}
		if packet::payload(f, &u) != p.as_slice() {
			return Err(format!("client to backend #{i}: payload of {} bytes differs", p.len()));
		}
	}
	let nat = nat.ok_or("no datagram")?;

	// 4. the backend answers
	let answers: Vec<Vec<u8>> = sizes.iter().enumerate().map(|(i, s)| payload_of(*s, 100 + i as u8)).collect();
	let frames = answers.iter().enumerate().map(|(i, p)| packet::udp_frame(BACKEND_MAC, mac, BACKEND, nat, p, i % 4 != 3)).collect();
	let out = step(frames)?;
	if out.len() != answers.len() {
		return Err(format!("backend to client: sent {} datagrams, {} came out", answers.len(), out.len()));
	}
	for (i, (f, p)) in out.iter().zip(&answers).enumerate() {
		let Frame::Udp(u) = packet::parse(f) else { return Err(format!("backend to client #{i}: not a UDP datagram")) };
		if u.src != LISTEN || u.dst != CLIENT || f[0..6] != CLIENT_MAC {
			return Err(format!("backend to client #{i}: addressed {} -> {}", u.src, u.dst));
		}
		if !packet::checksums_ok(f, &u) || packet::payload(f, &u) != p.as_slice() {
			return Err(format!("backend to client #{i}: checksum or payload differs"));
		}
	}
	if rule.opened.load(Ordering::Relaxed) != 1 {
		return Err(format!("{} sessions opened for one client", rule.opened.load(Ordering::Relaxed)));
	}
	// 5. the session ends when idle
	engine.sweep(now + Duration::from_secs(61));
	if *rule.closed.lock().unwrap_or_else(|e| e.into_inner()) != ["idle"] {
		return Err("the idle session was not closed".into());
	}
	Ok(())
}

/// A wire without one: frames go straight to the forwarder (unit tests).
pub struct Direct;

impl Wire for Direct {
	fn forward(&mut self, frames: Vec<Vec<u8>>, f: &mut Handle) -> Result<Vec<Vec<u8>>, String> {
		let mut out = vec![];
		for mut frame in frames {
			let mut extra = vec![];
			if let Verdict::Send(_) = f(&mut frame, &mut |_, b| extra.push(b.to_vec())) {
				out.push(frame);
			}
			out.extend(extra);
		}
		Ok(out)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_check_passes_on_a_direct_wire() {
		for burst in [1, 8, 32, 64] {
			scenario(&mut Direct, [2, 0, 0, 0, 0, 9], burst).unwrap();
		}
	}

	/// A wire that breaks things: the check must notice.
	struct Corrupt(usize);
	impl Wire for Corrupt {
		fn forward(&mut self, frames: Vec<Vec<u8>>, f: &mut Handle) -> Result<Vec<Vec<u8>>, String> {
			let mut out = Direct.forward(frames, f)?;
			self.0 += 1;
			// the third step is the burst: flip a payload byte of the last datagram
			if self.0 == 4 {
				if let Some(last) = out.last_mut() {
					let n = last.len() - 1;
					last[n] ^= 0xff;
				}
			}
			Ok(out)
		}
	}

	#[test]
	fn the_check_notices_corruption() {
		let err = scenario(&mut Corrupt(0), [2, 0, 0, 0, 0, 9], 8).unwrap_err();
		assert!(err.contains("client to backend"), "{err}");
	}
}
