//! Frames received by the DPDK path (#261, `rproxy_dpdk::packet` and the
//! forwarder `rproxy_dpdk::engine`): Ethernet, ARP, IPv4, UDP, ICMP echo.
//!
//! Input: frames, each prefixed with its length (16 bits, big-endian), all
//! received on the one port of a forwarder with a UDP rule. Besides not
//! panicking: every UDP datagram with right checksums that is passed on keeps
//! them right (the incremental update of the UDP checksum) and its payload.
#![no_main]

use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use rproxy_dpdk::engine::{Engine, Phase, PortCfg, Rule, Verdict};
use rproxy_dpdk::packet::{self, Frame};

const MAX_FRAMES: usize = 64;

struct Fuzz;

impl Rule for Fuzz {
	type Session = ();
	fn phase(&self) -> Phase {
		Phase::Open
	}
	fn admit(&self, c: SocketAddrV4) -> bool {
		c.port() != 1
	}
	fn open(&self, _: SocketAddrV4, _: SocketAddrV4, offset: u16) -> Option<(SocketAddrV4, ())> {
		Some((SocketAddrV4::new([10, 0, 0, 20].into(), 6000 + offset), ()))
	}
	fn up(&self, _: &mut (), _: usize) -> bool {
		true
	}
	fn down(&self, _: &mut (), _: usize) -> bool {
		true
	}
	fn dropped(&self) {}
	fn idle(&self) -> Duration {
		Duration::from_secs(1)
	}
	fn retarget(&self, _: &mut (), _: u16, _: SocketAddrV4) -> Option<SocketAddrV4> {
		None
	}
	fn close(&self, _: (), _: SocketAddrV4, _: SocketAddrV4, _: &'static str) {}
}

fn frames(mut data: &[u8]) -> Vec<&[u8]> {
	let mut out = vec![];
	while data.len() >= 2 && out.len() < MAX_FRAMES {
		let n = usize::from(u16::from_be_bytes([data[0], data[1]])).min(data.len() - 2);
		out.push(&data[2..2 + n]);
		data = &data[2 + n..];
	}
	out
}

fuzz_target!(|data: &[u8]| {
	// a small NAT range: a new engine per input stays cheap, and running out of ports gets exercised
	let engine = Engine::with_nat_ports(vec![PortCfg {
		mac: [2, 0, 0, 0, 0, 0xaa],
		addrs: vec![([10, 0, 0, 10].into(), 24), ([192, 0, 2, 1].into(), 32)],
		gateway: Some([10, 0, 0, 1].into()),
	}], 32768, 32799);
	engine.register([10, 0, 0, 10].into(), 5000, 4, std::sync::Arc::new(Fuzz)).unwrap();
	let mut w = engine.worker();
	engine.refresh(&mut w);
	let now = Instant::now();
	for (i, f) in frames(data).into_iter().enumerate() {
		let mut f = f.to_vec();
		let before = match packet::parse(&f) {
			Frame::Udp(u) if packet::checksums_ok(&f, &u) => Some(packet::payload(&f, &u).to_vec()),
			_ => None,
		};
		let mut extra = vec![];
		let verdict = engine.process(&w, 0, &mut f, now + Duration::from_millis(i as u64 * 300), &mut |_, b| extra.push(b.to_vec()));
		if let (Verdict::Send(_), Some(payload)) = (verdict, before) {
			let Frame::Udp(u) = packet::parse(&f) else { panic!("a passed-on datagram no longer parses") };
			assert!(packet::checksums_ok(&f, &u), "checksums broken by the rewrite");
			assert_eq!(packet::payload(&f, &u), payload.as_slice());
		}
		for e in &extra {
			assert!(matches!(packet::parse(e), Frame::Arp(_)), "only ARP requests are made");
		}
		if i % 8 == 7 {
			engine.sweep(now + Duration::from_millis(i as u64 * 300));
		}
	}
});
