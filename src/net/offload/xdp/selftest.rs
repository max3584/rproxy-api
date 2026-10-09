//! The AF_XDP startup self-test (#260, owner's decision: push test data
//! through the fast path and compare, rather than trusting kernel versions).
//!
//! It runs on its own thread, in a private network namespace (`unshare`
//! applies to that thread only, so the host's interfaces are never touched):
//! a veth pair `rpx0` (10.200.0.1/30) <-> `rpx1` (10.200.0.2/30), the XDP
//! program on `rpx1` in generic mode steering one UDP port to an AF_XDP
//! socket. A normal UDP socket on `rpx0` sends datagrams to that port; the
//! test reads each one from the XSK, checks it, answers through the XSK with
//! a reflected frame (`build_reply`), and checks what the UDP socket gets back.
//! The namespace (and the veth pair) goes away when the thread ends.
//!
//! Zero-copy is tried first and copy mode second (veth supports only copy).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use super::netlink::Rtnl;
use super::{build_reply, parse, AttachMode, Steer, Xsk, XskConfig};
use crate::net::offload::probe::{Outcome, Test};

const A: &str = "rpx0";
const B: &str = "rpx1";
const ADDR_A: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
const ADDR_B: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const PORT: u16 = 9;

/// What the cases send; the reply is `ack:` + the payload, so a reply that is
/// merely the request bounced back by the stack does not pass.
fn cases() -> Vec<(&'static str, Vec<u8>)> {
	let big: Vec<u8> = (0..1400u32).map(|i| (i % 251) as u8).collect();
	vec![("small", b"rproxy".to_vec()), ("1400 bytes", big)]
}

/// Runs the test on its own thread and returns the outcome.
pub fn run(ring_size: u32, frame_size: u32) -> Outcome {
	let handle = std::thread::Builder::new().name("rproxy-xdp-probe".into()).spawn(move || in_namespace(ring_size, frame_size));
	match handle.map(|h| h.join()) {
		Ok(Ok(o)) => o,
		Ok(Err(_)) => Outcome::unusable("the AF_XDP self-test panicked", vec![]),
		Err(e) => Outcome::unusable(format!("could not start the self-test thread: {e}"), vec![]),
	}
}

fn step(tests: &mut Vec<Test>, name: &str, r: Result<(), String>) -> bool {
	let ok = r.is_ok();
	tests.push(Test { name: name.to_string(), ok, detail: r.err().unwrap_or_default() });
	ok
}

fn in_namespace(ring_size: u32, frame_size: u32) -> Outcome {
	let mut tests = vec![];
	// SAFETY: unshare(2) on this thread only (CLONE_NEWNET is per task)
	if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
		let e = std::io::Error::last_os_error();
		step(&mut tests, "netns", Err(e.to_string()));
		return Outcome::unusable(format!("cannot make a private network namespace for the test: {e}"), tests);
	}
	let setup = (|| -> std::io::Result<()> {
		let mut nl = Rtnl::open()?;
		nl.add_veth(A, B)?;
		nl.add_addr(A, ADDR_A, 30)?;
		nl.add_addr(B, ADDR_B, 30)?;
		nl.set_up("lo")?;
		nl.set_up(A)?;
		nl.set_up(B)
	})();
	if !step(&mut tests, "veth", setup.map_err(|e| e.to_string())) {
		return Outcome::unusable("cannot set up the veth pair for the test", tests);
	}
	let mut steer = match Steer::attach(B, AttachMode::Generic) {
		Ok(s) => s,
		Err(e) => {
			step(&mut tests, "attach", Err(e.to_string()));
			return Outcome::unusable(format!("cannot attach the XDP program: {e}"), tests);
		}
	};
	step(&mut tests, "attach", Ok(()));
	if let Err(e) = steer.add_port(PORT) {
		step(&mut tests, "ports map", Err(e.to_string()));
		return Outcome::unusable(format!("cannot fill the ports map: {e}"), tests);
	}
	// zero-copy first, then copy
	let mut chosen = None;
	for zero_copy in [true, false] {
		let cfg = XskConfig { queue: 0, ring_size, frame_size, zero_copy, busy_poll: false };
		match Xsk::bind(B, cfg) {
			Ok(x) => {
				chosen = Some((x, zero_copy));
				break;
			}
			Err(e) => tests.push(Test { name: format!("bind {}", if zero_copy { "zero-copy" } else { "copy" }), ok: false, detail: e.to_string() }),
		}
	}
	let Some((mut xsk, zero_copy)) = chosen else {
		return Outcome::unusable("cannot bind an AF_XDP socket", tests);
	};
	step(&mut tests, if zero_copy { "bind zero-copy" } else { "bind copy" }, Ok(()));
	if let Err(e) = steer.set_xsk(0, xsk.fd()) {
		step(&mut tests, "xsk map", Err(e.to_string()));
		return Outcome::unusable(format!("cannot point the program at the socket: {e}"), tests);
	}
	let client = match UdpSocket::bind(SocketAddr::new(ADDR_A.into(), 0)).and_then(|s| {
		s.connect(SocketAddr::new(ADDR_B.into(), PORT))?;
		s.set_read_timeout(Some(Duration::from_secs(2)))?;
		Ok(s)
	}) {
		Ok(s) => s,
		Err(e) => {
			step(&mut tests, "client socket", Err(e.to_string()));
			return Outcome::unusable(format!("cannot open the test client: {e}"), tests);
		}
	};
	let mut all_ok = true;
	for (name, payload) in cases() {
		all_ok &= step(&mut tests, name, round_trip(&client, &mut xsk, &payload));
	}
	if all_ok {
		let mode = if zero_copy { "generic, zero-copy" } else { "generic, copy" };
		Outcome { usable: true, detail: format!("udp round trips over veth ({mode})"), tests }
	} else {
		Outcome::unusable("a test datagram did not come through intact", tests)
	}
}

/// Sends `payload` from the client, reads it from the XSK, answers through the
/// XSK, and checks the answer the client gets.
fn round_trip(client: &UdpSocket, xsk: &mut Xsk, payload: &[u8]) -> Result<(), String> {
	client.send(payload).map_err(|e| format!("send: {e}"))?;
	let deadline = Instant::now() + Duration::from_secs(2);
	let mut got: Option<Vec<u8>> = None;
	while got.is_none() && Instant::now() < deadline {
		xsk.recv(|frame| {
			// ARP and other traffic are passed to the stack by the program; only
			// our port should come here, but check
			if got.is_none() && parse(frame).is_some_and(|p| p.dst.port() == PORT) {
				got = Some(frame.to_vec());
			}
		})
		.map_err(|e| format!("recv: {e}"))?;
		if got.is_none() {
			xsk.wait(50);
		}
	}
	let frame = got.ok_or("no frame on the AF_XDP socket within 2 s")?;
	let p = parse(&frame).ok_or("frame not parsed")?;
	if &frame[p.payload..] != payload {
		return Err(format!("payload changed on the way in ({} bytes, expected {})", frame.len() - p.payload, payload.len()));
	}
	let mut answer = b"ack:".to_vec();
	answer.extend_from_slice(payload);
	let mut out = Vec::with_capacity(frame.len() + 8);
	let n = build_reply(&p, &frame, &answer, &mut out).ok_or("reply frame not built")?;
	out.truncate(n);
	if !xsk.send(&out).map_err(|e| format!("send on the XSK: {e}"))? {
		return Err("no free TX frame".into());
	}
	let mut buf = vec![0u8; 2048];
	let n = client.recv(&mut buf).map_err(|e| format!("client recv: {e}"))?;
	if buf[..n] != answer[..] {
		return Err(format!("reply changed ({n} bytes, expected {})", answer.len()));
	}
	Ok(())
}
