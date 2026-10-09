//! The DPDK path on real DPDK ports, with the EAL on plain memory
//! (`--no-huge`): needs DPDK, not root. The dpdk.yml workflow runs it;
//! `RPROXY_DPDK_TEST_EAL` adds EAL arguments (e.g. `-d` for the PMD plugins of
//! a DPDK outside the system paths).
//!
//! The EAL starts once per process, so this is one test in steps:
//! 1. the startup check through a loopback `net_ring` port;
//! 2. the lcore loop (`io::run`) on one end of a `net_memif` pair, driven
//!    from the other end as the wire: client datagrams in, forwarded frames
//!    out, the backend's answers back to the client.
#![cfg(feature = "ffi")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rproxy_dpdk::engine::{Engine, Phase, PortCfg, Rule};
use rproxy_dpdk::ffi::{self, Mbuf, Pool, Port};
use rproxy_dpdk::io::{self, IoStats, Job, RingWire};
use rproxy_dpdk::packet::{self, Frame};
use rproxy_dpdk::selftest;

struct OneTarget(SocketAddrV4);

impl Rule for OneTarget {
	type Session = ();
	fn phase(&self) -> Phase {
		Phase::Open
	}
	fn admit(&self, _: SocketAddrV4) -> bool {
		true
	}
	fn open(&self, _: SocketAddrV4, _: SocketAddrV4, _: u16) -> Option<(SocketAddrV4, ())> {
		Some((self.0, ()))
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
	fn close(&self, _: (), _: SocketAddrV4, _: SocketAddrV4, _: &'static str) {}
}

fn send(port: Port, pool: Pool, frames: &[Vec<u8>]) {
	let mut ms: Vec<*mut Mbuf> = frames.iter().map(|f| pool.copy(f).expect("mbuf")).collect();
	let mut at = 0;
	let deadline = Instant::now() + Duration::from_secs(5);
	while at < ms.len() {
		at += port.tx(0, &mut ms[at..]);
		assert!(Instant::now() < deadline, "the wire took {at} of {} frames", ms.len());
	}
}

fn receive(port: Port, want: usize) -> Vec<Vec<u8>> {
	let mut out = vec![];
	let mut bufs = [std::ptr::null_mut(); 64];
	let deadline = Instant::now() + Duration::from_secs(5);
	while out.len() < want && Instant::now() < deadline {
		let n = port.rx(0, &mut bufs);
		for &m in &bufs[..n] {
			out.push(unsafe { ffi::data(m) }.expect("one segment").to_vec());
			unsafe { ffi::free(m) };
		}
	}
	out
}

#[test]
fn the_dpdk_path_on_real_ports() {
	let sock = format!("/rproxy-dpdk-test-{}.sock", std::process::id());
	let mut args: Vec<String> = ["rproxy-dpdk-test", "--no-huge", "-m", "512", "--no-pci", "--no-shconf", "--no-telemetry", "-l", "0-1"]
		.map(String::from)
		.to_vec();
	for v in ["net_ring_rpchk".to_string(), format!("net_memif_a,role=server,id=7,socket={sock}"), format!("net_memif_b,role=client,id=7,socket={sock}")] {
		args.push("--vdev".into());
		args.push(v);
	}
	if let Ok(extra) = std::env::var("RPROXY_DPDK_TEST_EAL") {
		args.extend(extra.split_whitespace().map(String::from));
	}
	ffi::eal_init(&args).unwrap();
	println!("{}", ffi::version());
	let pool = Pool::create("rproxy_test", 8191, 64).unwrap();

	// 1. the startup check
	let ring = Port::by_name("net_ring_rpchk").unwrap();
	ring.setup(pool, 1, 1, 256, 256).unwrap();
	let mac = ring.mac().unwrap();
	for burst in [1, 32, 64] {
		selftest::scenario(&mut RingWire { port: ring, pool }, mac, burst).unwrap();
	}
	ring.stop();

	// 2. forwarding on an lcore, between the two ends of a memif pair
	let (a, b) = (Port::by_name("net_memif_a").unwrap(), Port::by_name("net_memif_b").unwrap());
	a.setup(pool, 1, 1, 1024, 1024).unwrap();
	b.setup(pool, 1, 1, 1024, 1024).unwrap();
	let deadline = Instant::now() + Duration::from_secs(10);
	while !(a.link().unwrap().0 && b.link().unwrap().0) {
		assert!(Instant::now() < deadline, "memif did not connect");
		std::thread::sleep(Duration::from_millis(20));
	}
	let ours: Ipv4Addr = "10.9.0.10".parse().unwrap();
	let (mac_a, wire_mac) = (a.mac().unwrap(), [2, 0, 0, 0, 0x77, 1]);
	let engine = Arc::new(Engine::new(vec![PortCfg { mac: mac_a, addrs: vec![(ours, 24)], gateway: None }]));
	let backend: SocketAddrV4 = "10.9.0.20:7000".parse().unwrap();
	engine.register(ours, 5300, 1, Arc::new(OneTarget(backend))).unwrap();
	let stop = Arc::new(AtomicBool::new(false));
	let stats = Arc::new(IoStats::default());
	let lcore = *ffi::workers().first().expect("a worker lcore");
	let job = Job { engine: engine.clone(), pool, ports: vec![a], rx: vec![(0, 0)], txq: 0, burst: 32, sweeper: true, stop: stop.clone(), stats: stats.clone() };
	ffi::launch(lcore, Box::new(move || io::run(job))).unwrap();

	// the backend's MAC, then datagrams from a client
	let mut arp = vec![0u8; packet::ARP_FRAME];
	packet::arp_frame(&mut arp, packet::ARP_REPLY, wire_mac, *backend.ip(), mac_a, ours);
	send(b, pool, &[arp]);
	std::thread::sleep(Duration::from_millis(50));
	let client: SocketAddrV4 = "10.9.0.30:41000".parse().unwrap();
	let listen = SocketAddrV4::new(ours, 5300);
	let n = 500;
	let payloads: Vec<Vec<u8>> = (0..n).map(|i| (0..(i * 3) % 1473).map(|j| (i + j) as u8).collect()).collect();
	let mut forwarded = vec![];
	for chunk in payloads.chunks(50) {
		let frames: Vec<Vec<u8>> = chunk.iter().map(|p| packet::udp_frame(wire_mac, mac_a, client, listen, p, true)).collect();
		send(b, pool, &frames);
		forwarded.extend(receive(b, chunk.len()));
	}
	assert_eq!(forwarded.len(), n, "every datagram forwarded");
	let mut nat = None;
	for (f, p) in forwarded.iter().zip(&payloads) {
		let Frame::Udp(u) = packet::parse(f) else { panic!("not UDP") };
		assert_eq!((u.dst, *u.src.ip()), (backend, ours));
		assert_eq!(*nat.get_or_insert(u.src), u.src);
		assert!(packet::checksums_ok(f, &u));
		assert_eq!(packet::payload(f, &u), p.as_slice());
	}
	let nat = nat.unwrap();
	let answers: Vec<Vec<u8>> = payloads.iter().map(|p| packet::udp_frame(wire_mac, mac_a, backend, nat, p, true)).collect();
	let mut back = vec![];
	for chunk in answers.chunks(50) {
		send(b, pool, chunk);
		back.extend(receive(b, chunk.len()));
	}
	assert_eq!(back.len(), n, "every answer returned");
	for (f, p) in back.iter().zip(&payloads) {
		let Frame::Udp(u) = packet::parse(f) else { panic!("not UDP") };
		assert_eq!((u.src, u.dst), (listen, client));
		assert!(packet::checksums_ok(f, &u));
		assert_eq!(packet::payload(f, &u), p.as_slice());
	}
	stop.store(true, Ordering::Relaxed);
	assert_eq!(ffi::wait(lcore), 0);
	println!("lcore loop: {stats:?}");
	a.stop();
	b.stop();
}
