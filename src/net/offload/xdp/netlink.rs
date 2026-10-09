//! The few rtnetlink requests the AF_XDP self-test needs inside its private
//! network namespace: a veth pair, IPv4 addresses, links up. Raw
//! `NETLINK_ROUTE` messages (no dependency); every request asks for an ACK and
//! the error in it is returned.

use std::ffi::CString;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_ADDRESS: u16 = 1;
const NLA_F_NESTED: u16 = 0x8000;
const IFF_UP: u32 = 0x1;

/// A `NETLINK_ROUTE` socket.
pub struct Rtnl {
	fd: OwnedFd,
	seq: u32,
}

fn align4(n: usize) -> usize {
	(n + 3) & !3
}

/// Appends a netlink attribute (`rtattr`) with `payload`.
fn attr(buf: &mut Vec<u8>, kind: u16, payload: &[u8]) {
	let len = 4 + payload.len();
	buf.extend_from_slice(&(len as u16).to_ne_bytes());
	buf.extend_from_slice(&kind.to_ne_bytes());
	buf.extend_from_slice(payload);
	buf.resize(align4(buf.len()), 0);
}

/// Appends a nested attribute whose body `f` writes.
fn nested(buf: &mut Vec<u8>, kind: u16, f: impl FnOnce(&mut Vec<u8>)) {
	let start = buf.len();
	buf.extend_from_slice(&[0u8; 4]);
	f(buf);
	let len = (buf.len() - start) as u16;
	buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
	buf[start + 2..start + 4].copy_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
}

fn cstr(name: &str) -> Vec<u8> {
	let mut v = name.as_bytes().to_vec();
	v.push(0);
	v
}

/// `struct ifinfomsg` (16 bytes).
fn ifinfomsg(index: i32, flags: u32, change: u32) -> Vec<u8> {
	let mut v = Vec::with_capacity(16);
	v.push(libc::AF_UNSPEC as u8);
	v.push(0);
	v.extend_from_slice(&0u16.to_ne_bytes()); // type
	v.extend_from_slice(&index.to_ne_bytes());
	v.extend_from_slice(&flags.to_ne_bytes());
	v.extend_from_slice(&change.to_ne_bytes());
	v
}

impl Rtnl {
	pub fn open() -> io::Result<Rtnl> {
		// SAFETY: plain socket(2); the descriptor is owned below
		let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
		if fd < 0 {
			return Err(io::Error::last_os_error());
		}
		// SAFETY: a fresh descriptor we own
		Ok(Rtnl { fd: unsafe { OwnedFd::from_raw_fd(fd) }, seq: 1 })
	}

	/// Sends one request (`body` after the `nlmsghdr`) and waits for its ACK.
	fn request(&mut self, kind: u16, flags: u16, body: &[u8]) -> io::Result<()> {
		self.seq += 1;
		let mut msg = Vec::with_capacity(16 + body.len());
		msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
		msg.extend_from_slice(&kind.to_ne_bytes());
		msg.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
		msg.extend_from_slice(&self.seq.to_ne_bytes());
		msg.extend_from_slice(&0u32.to_ne_bytes());
		msg.extend_from_slice(body);
		// SAFETY: sending our buffer on our socket (the kernel is the default peer)
		let n = unsafe { libc::send(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
		if n < 0 {
			return Err(io::Error::last_os_error());
		}
		let mut buf = [0u8; 4096];
		loop {
			// SAFETY: receiving into our buffer
			let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
			if n < 0 {
				return Err(io::Error::last_os_error());
			}
			let mut off = 0usize;
			let n = n as usize;
			while off + 16 <= n {
				let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap_or_default()) as usize;
				let ty = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().unwrap_or_default());
				let seq = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap_or_default());
				if ty == NLMSG_ERROR && seq == self.seq && off + 20 <= n {
					let errno = i32::from_ne_bytes(buf[off + 16..off + 20].try_into().unwrap_or_default());
					return if errno == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(-errno)) };
				}
				if len < 16 {
					break;
				}
				off += align4(len);
			}
		}
	}

	/// Creates the veth pair `a` <-> `b` with one TX and one RX queue on each
	/// end (veth defaults to one queue per CPU, and a datagram then lands on
	/// whichever RX queue matches the sender's CPU — not only queue 0).
	pub fn add_veth(&mut self, a: &str, b: &str) -> io::Result<()> {
		let mut body = ifinfomsg(0, 0, 0);
		attr(&mut body, IFLA_IFNAME, &cstr(a));
		attr(&mut body, IFLA_NUM_TX_QUEUES, &1u32.to_ne_bytes());
		attr(&mut body, IFLA_NUM_RX_QUEUES, &1u32.to_ne_bytes());
		nested(&mut body, IFLA_LINKINFO, |li| {
			attr(li, IFLA_INFO_KIND, b"veth");
			nested(li, IFLA_INFO_DATA, |data| {
				nested(data, VETH_INFO_PEER, |peer| {
					peer.extend_from_slice(&ifinfomsg(0, 0, 0));
					attr(peer, IFLA_IFNAME, &cstr(b));
					attr(peer, IFLA_NUM_TX_QUEUES, &1u32.to_ne_bytes());
					attr(peer, IFLA_NUM_RX_QUEUES, &1u32.to_ne_bytes());
				});
			});
		});
		self.request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &body)
	}

	/// Sets link `name` up.
	pub fn set_up(&mut self, name: &str) -> io::Result<()> {
		let body = ifinfomsg(index(name)? as i32, IFF_UP, IFF_UP);
		self.request(RTM_NEWLINK, 0, &body)
	}

	/// Adds `addr/prefix` to link `name`.
	pub fn add_addr(&mut self, name: &str, addr: Ipv4Addr, prefix: u8) -> io::Result<()> {
		let mut body = Vec::with_capacity(24);
		body.push(libc::AF_INET as u8);
		body.push(prefix);
		body.push(0); // flags
		body.push(0); // scope: universe
		body.extend_from_slice(&index(name)?.to_ne_bytes());
		attr(&mut body, IFA_LOCAL, &addr.octets());
		attr(&mut body, IFA_ADDRESS, &addr.octets());
		self.request(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &body)
	}
}

/// The index of link `name`.
pub fn index(name: &str) -> io::Result<u32> {
	let c = CString::new(name).map_err(io::Error::other)?;
	// SAFETY: a valid NUL-terminated string
	let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
	if i == 0 {
		return Err(io::Error::last_os_error());
	}
	Ok(i)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn nested_attributes_have_their_length_and_flag() {
		let mut b = vec![];
		nested(&mut b, IFLA_LINKINFO, |li| attr(li, IFLA_INFO_KIND, b"veth"));
		// outer header: len = 4 + inner (4 + 4 "veth") = 12
		assert_eq!(u16::from_ne_bytes([b[0], b[1]]), 12);
		assert_eq!(u16::from_ne_bytes([b[2], b[3]]), IFLA_LINKINFO | NLA_F_NESTED);
		assert_eq!(u16::from_ne_bytes([b[4], b[5]]), 8);
		assert_eq!(&b[8..12], b"veth");
	}
}
