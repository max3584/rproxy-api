//! The AF_XDP startup self-test (#260, owner's decision: push test data
//! through the fast path and compare, rather than trusting kernel versions).
//!
//! Two threads, each in its own private network namespace (`unshare` applies
//! to the calling thread only, so the host's interfaces are never touched):
//!
//! - the server (`rpx1`, 10.200.0.2/30): the XDP program in generic mode
//!   steers one UDP port to an AF_XDP socket; it answers every datagram
//!   through the socket with `ack:` + the payload in a reflected frame
//!   (`build_reply`);
//! - the client (`rpx0`, 10.200.0.1/30, the veth peer moved into its
//!   namespace): a normal UDP socket sends the test datagrams and checks the
//!   answers byte for byte.
//!
//! The two ends must be in different namespaces: in one namespace the kernel
//! delivers 10.200.0.1 -> 10.200.0.2 through the local route and the veth (and
//! XDP) never sees it. The namespaces and the veth pair go away with the
//! threads. Zero-copy is tried first and copy mode second (veth: copy only).

use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::netlink::Rtnl;
use super::{build_reply, parse, AttachMode, Steer, Xsk, XskConfig};
use crate::net::offload::probe::{Outcome, Test};

const CLIENT_IF: &str = "rpx0";
const SERVER_IF: &str = "rpx1";
const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
const SERVER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 2);
const PORT: u16 = 9;
const TIMEOUT: Duration = Duration::from_secs(2);

/// What the client sends; the answer must be `ack:` + the payload, so the
/// request bounced back by the stack does not pass.
fn cases() -> Vec<(&'static str, Vec<u8>)> {
	let big: Vec<u8> = (0..1400u32).map(|i| (i % 251) as u8).collect();
	vec![("small", b"rproxy".to_vec()), ("1400 bytes", big)]
}

/// Runs the test and returns the outcome.
pub fn run(ring_size: u32, frame_size: u32) -> Outcome {
	let handle = std::thread::Builder::new().name("rproxy-xdp-probe".into()).spawn(move || server(ring_size, frame_size));
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

/// A private network namespace for this thread, and an open handle to it.
fn private_netns() -> std::io::Result<File> {
	// SAFETY: unshare(2) on this thread only (CLONE_NEWNET is per task)
	if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
		return Err(std::io::Error::last_os_error());
	}
	File::open("/proc/thread-self/ns/net")
}

/// The client's side: its namespace (handed to the server, which creates the
/// veth peer in it), then, once the veth exists, the address and the
/// datagrams. Reports one result per case.
fn client(ns_tx: mpsc::Sender<std::io::Result<File>>, go: mpsc::Receiver<bool>) -> Vec<(String, Result<(), String>)> {
	let ns = private_netns();
	let ok = ns.is_ok();
	let _ = ns_tx.send(ns);
	if !ok || go.recv() != Ok(true) {
		return vec![];
	}
	let setup = (|| -> std::io::Result<UdpSocket> {
		let mut nl = Rtnl::open()?;
		nl.add_addr(CLIENT_IF, CLIENT_ADDR, 30)?;
		nl.set_up("lo")?;
		nl.set_up(CLIENT_IF)?;
		let s = UdpSocket::bind(SocketAddr::new(CLIENT_ADDR.into(), 0))?;
		s.connect(SocketAddr::new(SERVER_ADDR.into(), PORT))?;
		s.set_read_timeout(Some(TIMEOUT))?;
		Ok(s)
	})();
	let sock = match setup {
		Ok(s) => s,
		Err(e) => return vec![("client".into(), Err(e.to_string()))],
	};
	let mut out = vec![];
	for (name, payload) in cases() {
		let r = (|| -> Result<(), String> {
			sock.send(&payload).map_err(|e| format!("send: {e}"))?;
			let mut buf = vec![0u8; 2048];
			let n = sock.recv(&mut buf).map_err(|e| format!("no answer: {e}"))?;
			let mut want = b"ack:".to_vec();
			want.extend_from_slice(&payload);
			if buf[..n] != want[..] {
				return Err(format!("answer changed ({n} bytes, expected {})", want.len()));
			}
			Ok(())
		})();
		out.push((name.to_string(), r));
	}
	out
}

/// The server's side (this thread's namespace): the veth, the program, the
/// AF_XDP socket, and the answers.
fn server(ring_size: u32, frame_size: u32) -> Outcome {
	let mut tests = vec![];
	if let Err(e) = private_netns() {
		step(&mut tests, "netns", Err(e.to_string()));
		return Outcome::unusable(format!("cannot make a private network namespace for the test: {e}"), tests);
	}
	let (ns_tx, ns_rx) = mpsc::channel();
	let (go_tx, go_rx) = mpsc::channel();
	let peer = std::thread::Builder::new().name("rproxy-xdp-client".into()).spawn(move || client(ns_tx, go_rx));
	let Ok(peer) = peer else {
		return Outcome::unusable("could not start the self-test client", tests);
	};
	// let the client finish (and its namespace go) whatever happens below
	let finish = |go: bool, peer: std::thread::JoinHandle<_>| {
		let _ = go_tx.send(go);
		peer.join().unwrap_or_default()
	};
	let client_ns = match ns_rx.recv() {
		Ok(Ok(f)) => f,
		Ok(Err(e)) => {
			let _ = finish(false, peer);
			step(&mut tests, "netns", Err(e.to_string()));
			return Outcome::unusable(format!("cannot make a private network namespace for the test: {e}"), tests);
		}
		Err(_) => {
			let _ = finish(false, peer);
			return Outcome::unusable("the self-test client stopped", tests);
		}
	};
	let setup = (|| -> std::io::Result<()> {
		let mut nl = Rtnl::open()?;
		nl.add_veth(SERVER_IF, CLIENT_IF, client_ns.as_fd())?;
		nl.add_addr(SERVER_IF, SERVER_ADDR, 30)?;
		nl.set_up("lo")?;
		nl.set_up(SERVER_IF)
	})();
	if !step(&mut tests, "veth", setup.map_err(|e| e.to_string())) {
		let _ = finish(false, peer);
		return Outcome::unusable("cannot set up the veth pair for the test", tests);
	}
	let prepared = prepare(&mut tests, ring_size, frame_size);
	let Some((steer, mut xsk, zero_copy)) = prepared else {
		let _ = finish(false, peer);
		let why = tests.iter().rev().find(|t| !t.ok).map(|t| format!("{}: {}", t.name, t.detail)).unwrap_or_default();
		return Outcome::unusable(format!("cannot set up AF_XDP ({why})"), tests);
	};
	let _ = go_tx.send(true);
	// answer until the client is done (or the time is up)
	let deadline = Instant::now() + TIMEOUT * (cases().len() as u32 + 2);
	let mut answered = 0usize;
	let mut bad = vec![];
	while !peer.is_finished() && Instant::now() < deadline {
		let mut frames = vec![];
		if let Err(e) = xsk.recv(|f| frames.push(f.to_vec())) {
			bad.push(format!("recv: {e}"));
			break;
		}
		for frame in frames {
			match answer(&mut xsk, &frame) {
				Ok(()) => answered += 1,
				Err(e) => bad.push(e),
			}
		}
		xsk.wait(20);
	}
	let results = peer.join().unwrap_or_default();
	let mut all_ok = !results.is_empty() && bad.is_empty();
	for (name, r) in results {
		all_ok &= step(&mut tests, &name, r);
	}
	if !bad.is_empty() {
		step(&mut tests, "server", Err(bad.join("; ")));
	}
	if all_ok {
		let mode = if zero_copy { "generic, zero-copy" } else { "generic, copy" };
		Outcome { usable: true, detail: format!("udp round trips over veth ({mode}, {answered} answered)"), tests }
	} else {
		// where it stopped: the program's counters and the socket's statistics
		let prog = steer.stats().map(|[seen, port, fail]| format!("program: udp seen {seen}, port matched {port}, redirect failed {fail}"));
		let sock = xsk.statistics().map(|s| {
			format!("socket: rx_dropped {} rx_invalid {} rx_ring_full {} fill_ring_empty {} tx_invalid {} tx_ring_empty {}", s[0], s[1], s[3], s[4], s[2], s[5])
		});
		let detail = [prog, sock].into_iter().flatten().collect::<Vec<_>>().join("; ");
		step(&mut tests, "diagnosis", Err(format!("{detail}; answered {answered}")));
		Outcome::unusable("a test datagram did not come through intact", tests)
	}
}

/// Attaches the program, binds the socket (zero-copy, then copy) and points
/// the program at it.
fn prepare(tests: &mut Vec<Test>, ring_size: u32, frame_size: u32) -> Option<(Steer, Xsk, bool)> {
	let mut steer = match Steer::attach(SERVER_IF, AttachMode::Generic) {
		Ok(s) => s,
		Err(e) => {
			step(tests, "attach", Err(e.to_string()));
			return None;
		}
	};
	step(tests, "attach", Ok(()));
	if let Err(e) = steer.add_port(PORT) {
		step(tests, "ports map", Err(e.to_string()));
		return None;
	}
	let mut chosen = None;
	for zero_copy in [true, false] {
		let cfg = XskConfig { queue: 0, ring_size, frame_size, zero_copy, busy_poll: false };
		match Xsk::bind(SERVER_IF, cfg) {
			Ok(x) => {
				chosen = Some((x, zero_copy));
				break;
			}
			Err(e) => tests.push(Test { name: format!("bind {}", if zero_copy { "zero-copy" } else { "copy" }), ok: false, detail: e.to_string() }),
		}
	}
	let (xsk, zero_copy) = chosen?;
	step(tests, if zero_copy { "bind zero-copy" } else { "bind copy" }, Ok(()));
	if let Err(e) = steer.set_xsk(0, xsk.fd()) {
		step(tests, "xsk map", Err(e.to_string()));
		return None;
	}
	Some((steer, xsk, zero_copy))
}

/// Answers one frame from the AF_XDP socket with `ack:` + its payload.
fn answer(xsk: &mut Xsk, frame: &[u8]) -> Result<(), String> {
	let p = parse(frame).ok_or("frame not parsed")?;
	if p.dst.port() != PORT {
		return Err(format!("frame for port {} on the socket", p.dst.port()));
	}
	let mut reply = b"ack:".to_vec();
	reply.extend_from_slice(&frame[p.payload..]);
	let mut out = Vec::with_capacity(frame.len() + 8);
	let n = build_reply(&p, frame, &reply, &mut out).ok_or("reply frame not built")?;
	out.truncate(n);
	if !xsk.send(&out).map_err(|e| format!("send on the socket: {e}"))? {
		return Err("no free TX frame".into());
	}
	Ok(())
}
