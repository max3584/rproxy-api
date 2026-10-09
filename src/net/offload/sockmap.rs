//! eBPF sockmap relay for plain L4 TCP (#260, stage 1 of the ebpf fast path).
//!
//! rproxy still accepts the client and dials the backend itself (handshake,
//! PROXY protocol, `source_ip`, the `allow_from` / `crowdsec` / `limits`
//! admission checks all stay in user space). Once both TCP sockets are
//! established it puts them in a per-connection SOCKMAP(2) and attaches a tiny
//! stream-verdict program that redirects each socket's bytes to the other, so
//! the kernel moves the data with no system calls or copies (like splice, but
//! without the pipe round trip).
//!
//! The program redirects by `skb->local_port`: the client-side socket's local
//! port is the rule's listen port (baked into the program), so its bytes go to
//! key 1 (the backend socket) and everything else to key 0 (the client).
//!
//! This build has no byte/bandwidth BPF counters yet, so sockmap is used only
//! for rules without `bandwidth` (continuous shaping cannot be done in the
//! kernel here); `limits` admission already happened in user space. Byte totals
//! are read from `TCP_INFO` when the connection ends.
//!
//! The mechanism is proved per host at startup by `probe` (loopback pairs, data
//! of several sizes including >64 KiB and split writes, SHA-256 compared, FIN
//! propagation); only then is it used.

#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};

use super::bpf::{Attached, Insn, Map, Prog, BPF_SK_SKB_STREAM_VERDICT};

/// `BPF_PSEUDO_MAP_FD` in the src field of an `ld_imm64` loading a map.
const BPF_PSEUDO_MAP_FD: u8 = 1;
/// `bpf_sk_redirect_map` helper id.
const BPF_FUNC_SK_REDIRECT_MAP: i32 = 52;
/// `struct __sk_buff` byte offset of `local_port` (host byte order).
const SK_BUFF_LOCAL_PORT: i16 = 136;

/// The stream-verdict program: redirect to key 1 when the socket's local port
/// is `client_lport` (the client side), else to key 0. `map_fd` is embedded.
fn verdict_insns(client_lport: u16, map_fd: i32) -> [Insn; 9] {
	// opcodes
	const LDX_W: u8 = 0x61; // r0 = *(u32*)(r1 + off)
	const MOV64_IMM: u8 = 0xb7;
	const JEQ_K: u8 = 0x15;
	const LD_IMM64: u8 = 0x18;
	const CALL: u8 = 0x85;
	const EXIT: u8 = 0x95;
	[
		Insn::new(LDX_W, 0, 1, SK_BUFF_LOCAL_PORT, 0), // r0 = skb->local_port (r1 = skb)
		Insn::new(MOV64_IMM, 3, 0, 0, 1),              // r3 = 1 (assume client -> backend)
		Insn::new(JEQ_K, 0, 0, 1, client_lport as i32), // if r0 == client_lport skip next
		Insn::new(MOV64_IMM, 3, 0, 0, 0),              // r3 = 0 (not the client socket -> client)
		Insn::new(LD_IMM64, 2, BPF_PSEUDO_MAP_FD, 0, map_fd), // r2 = map (lo)
		Insn::new(0, 0, 0, 0, 0),                      //          (hi)
		Insn::new(MOV64_IMM, 4, 0, 0, 0),              // r4 = 0 flags (egress of target)
		Insn::new(CALL, 0, 0, 0, BPF_FUNC_SK_REDIRECT_MAP), // r0 = bpf_sk_redirect_map(r1,r2,r3,r4)
		Insn::new(EXIT, 0, 0, 0, 0),                   // return r0
	]
}

/// A per-connection sockmap relay. Dropping it detaches the program, closes the
/// map and program, and removes the sockets from the map (the kernel then
/// relays nothing more; the sockets go back to ordinary I/O).
pub struct Relay {
	// order matters: the attachment is dropped (detached) before the map/prog
	_attached: Attached,
	_prog: Prog,
	_map: Map,
}

impl Relay {
	/// Puts `client` and `backend` (both established TCP sockets) in a fresh
	/// SOCKMAP and starts the kernel relay. `client_lport` is the client
	/// socket's local port (the rule's listen port).
	pub fn start(client: BorrowedFd<'_>, backend: BorrowedFd<'_>, client_lport: u16) -> io::Result<Relay> {
		let map = Map::sockmap(2)?;
		let insns = verdict_insns(client_lport, map.fd().as_raw_fd());
		let prog = Prog::load_sk_skb(&insns, "rproxy_vdct", BPF_SK_SKB_STREAM_VERDICT)?;
		// the guard holds raw ids; `Relay`'s field order drops it before the map/prog
		let attached = prog.attach(map.fd(), BPF_SK_SKB_STREAM_VERDICT)?;
		// sockets go in after the verdict program is attached
		map.put_socket(0, client)?;
		map.put_socket(1, backend)?;
		Ok(Relay { _attached: attached, _prog: prog, _map: map })
	}
}

use super::probe::{Outcome, Test};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::time::Duration;

/// Pushes test data through a sockmap relay on loopback and checks it arrives
/// byte for byte, that it works in both directions and at sizes above 64 KiB
/// and split across writes, and that a half-close (FIN) is passed on. Returns
/// whether sockmap is usable here, with the reason when it is not. This is the
/// owner-mandated gate: sockmap is used only after this passes.
pub fn prove() -> Outcome {
	let mut tests = vec![];
	match prove_inner(&mut tests) {
		Ok(()) => Outcome { usable: true, detail: "stream verdict, loopback".into(), tests },
		Err(e) => Outcome::unusable(super::bpf::explain(&e), tests),
	}
}

fn prove_inner(tests: &mut Vec<Test>) -> io::Result<()> {
	let la = TcpListener::bind("127.0.0.1:0")?;
	let lb = TcpListener::bind("127.0.0.1:0")?;
	let (ca, cb) = (la.local_addr()?, lb.local_addr()?);
	let mut outer_a = TcpStream::connect(ca)?;
	let (inner_a, _) = la.accept()?;
	let mut outer_b = TcpStream::connect(cb)?;
	let (inner_b, _) = lb.accept()?;
	for s in [&outer_a, &inner_a, &outer_b, &inner_b] {
		s.set_nodelay(true)?;
		s.set_read_timeout(Some(Duration::from_secs(5)))?;
		s.set_write_timeout(Some(Duration::from_secs(5)))?;
	}
	let client_lport = inner_a.local_addr()?.port();
	// the map and verdict program load and attach: the main thing a host must allow
	let relay = Relay::start(inner_a.as_fd(), inner_b.as_fd(), client_lport)?;
	tests.push(Test { name: "load+attach".into(), ok: true, detail: String::new() });

	// client -> backend, several sizes, the big one split across writes
	for (name, size, split) in [("small", 100usize, false), ("over_64k", (64 << 10) + 13, true), ("large", 256 << 10, true)] {
		let data = pattern(size);
		let got = transfer(&mut outer_a, &outer_b, &data, split)?;
		let ok = sha256(&got) == sha256(&data) && got.len() == data.len();
		tests.push(Test { name: format!("c2b_{name}"), ok, detail: if ok { String::new() } else { "data differs".into() } });
		if !ok {
			return mismatch();
		}
	}
	// backend -> client (the other direction / key 0)
	let data = pattern(4096);
	let got = transfer(&mut outer_b, &outer_a, &data, false)?;
	let ok = sha256(&got) == sha256(&data);
	tests.push(Test { name: "b2c".into(), ok, detail: if ok { String::new() } else { "data differs".into() } });
	if !ok {
		return mismatch();
	}
	// FIN: half-close the client write. The backend must see EOF (the FIN is
	// forwarded), and a user-space read on the sockmap'd client socket must
	// return 0 too (how the data plane learns the connection ended).
	outer_a.shutdown(Shutdown::Write)?;
	let mut buf = [0u8; 16];
	let fwd = matches!(outer_b.read(&mut buf), Ok(0));
	tests.push(Test { name: "fin".into(), ok: fwd, detail: if fwd { String::new() } else { "FIN not forwarded to the backend".into() } });
	inner_a.set_read_timeout(Some(Duration::from_secs(5)))?;
	let eof = matches!((&inner_a).read(&mut buf), Ok(0));
	tests.push(Test { name: "fin_eof".into(), ok: eof, detail: if eof { String::new() } else { "no EOF on the sockmap socket".into() } });
	drop(relay);
	if fwd && eof {
		Ok(())
	} else {
		Err(io::Error::other("FIN was not passed on"))
	}
}

fn mismatch() -> io::Result<()> {
	Err(io::Error::new(io::ErrorKind::InvalidData, "relayed data did not match"))
}

/// Writes `data` to `send` (in chunks when `split`) while a thread reads
/// `data.len()` bytes from `recv`; returns what was read.
fn transfer(send: &mut TcpStream, recv: &TcpStream, data: &[u8], split: bool) -> io::Result<Vec<u8>> {
	let want = data.len();
	let mut reader = recv.try_clone()?;
	let handle = std::thread::spawn(move || -> io::Result<Vec<u8>> {
		let mut got = Vec::with_capacity(want);
		let mut buf = [0u8; 32 << 10];
		while got.len() < want {
			let n = reader.read(&mut buf)?;
			if n == 0 {
				break;
			}
			got.extend_from_slice(&buf[..n]);
		}
		Ok(got)
	});
	if split {
		for chunk in data.chunks(13 << 10) {
			send.write_all(chunk)?;
		}
	} else {
		send.write_all(data)?;
	}
	send.flush()?;
	handle.join().map_err(|_| io::Error::other("reader thread panicked"))?
}

fn pattern(n: usize) -> Vec<u8> {
	(0..n).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
	use sha2::{Digest, Sha256};
	Sha256::digest(data).into()
}

/// `TCP_INFO` bytes received on `sock` (what the kernel delivered to it while
/// it was in the sockmap), for the stats after the relay. Best effort.
pub fn bytes_received(sock: BorrowedFd<'_>) -> Option<u64> {
	// SAFETY: a zeroed tcp_info is valid; getsockopt fills up to len
	let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
	let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
	let r = unsafe {
		libc::getsockopt(sock.as_raw_fd(), libc::IPPROTO_TCP, libc::TCP_INFO, &mut info as *mut _ as *mut libc::c_void, &mut len)
	};
	(r == 0).then_some(info.tcpi_bytes_received)
}
