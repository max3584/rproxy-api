//! A rule's listening UDP socket. On a wildcard address (`0.0.0.0` / `::`) the
//! kernel would pick the source of a reply by the route back to the client,
//! which on a host with several addresses can differ from the address the
//! client sent to; clients that match replies by address (IKE, WebRTC, QUIC,
//! DTLS over a connected socket) then drop them (#137). Such sockets learn each
//! datagram's destination with `IP_PKTINFO` / `IPV6_RECVPKTINFO` and send replies
//! from it with the same control message.

use std::io;
use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;

/// The local end a datagram arrived at (wildcard sockets only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Local {
	/// As the kernel reports it: IPv4 through a dual-stack `::` socket is IPv4-mapped.
	pub ip: IpAddr,
	/// Interface index; used when sending from a link-local IPv6 address.
	pub ifindex: u32,
}

impl Local {
	/// The address without IPv4 mapping, for logs and PROXY headers.
	pub fn canonical(&self) -> IpAddr {
		self.ip.to_canonical()
	}
}

pub struct Listener {
	socket: UdpSocket,
	/// Whether destinations are learnt and replies sent from them (a wildcard bind).
	pktinfo: bool,
}

impl Listener {
	/// Wraps a bound socket; on a wildcard address turns on packet info (Linux).
	pub fn new(socket: UdpSocket) -> Self {
		let wildcard = socket.local_addr().is_ok_and(|a| a.ip().is_unspecified());
		let pktinfo = wildcard && sys::enable(&socket).is_ok();
		Listener { socket, pktinfo }
	}

	pub fn local_addr(&self) -> io::Result<SocketAddr> {
		self.socket.local_addr()
	}

	/// The listening address a datagram was sent to: the learnt destination on a
	/// wildcard socket, else the socket's own address.
	pub fn local_for(&self, local: Option<Local>) -> SocketAddr {
		let own = self.socket.local_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
		match local {
			Some(l) => SocketAddr::new(l.canonical(), own.port()),
			None => own,
		}
	}

	/// Receives a datagram: its length, the client, and (wildcard sockets) where it was sent to.
	pub async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<Local>)> {
		if !self.pktinfo {
			let (n, from) = self.socket.recv_from(buf).await?;
			return Ok((n, from, None));
		}
		self.socket.async_io(tokio::io::Interest::READABLE, || sys::recv(&self.socket, buf)).await
	}

	/// Sends to `client`, from `local` when known (the address the client sent to).
	pub async fn send_to(&self, data: &[u8], client: SocketAddr, local: Option<Local>) -> io::Result<usize> {
		if let (true, Some(local)) = (self.pktinfo, local) {
			match self.socket.async_io(tokio::io::Interest::WRITABLE, || sys::send(&self.socket, data, client, local)).await {
				// the address is gone from the host: let the kernel choose rather than lose the reply
				Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::EADDRNOTAVAIL)) => {}
				other => return other,
			}
		}
		self.socket.send_to(data, client).await
	}
}

#[cfg(target_os = "linux")]
mod sys {
	use std::io;
	use std::mem;
	use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
	use std::os::fd::AsRawFd;

	use tokio::net::UdpSocket;

	use super::Local;

	/// Room for one pktinfo control message (and a second, if the kernel sends both).
	type Control = [u64; 16];

	fn setsockopt(socket: &UdpSocket, level: libc::c_int, name: libc::c_int) -> io::Result<()> {
		let one: libc::c_int = 1;
		// SAFETY: a valid fd and a c_int option value of the right size
		let r = unsafe {
			libc::setsockopt(socket.as_raw_fd(), level, name, (&one as *const libc::c_int).cast(), mem::size_of::<libc::c_int>() as libc::socklen_t)
		};
		if r == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
	}

	pub fn enable(socket: &UdpSocket) -> io::Result<()> {
		if socket.local_addr()?.is_ipv6() {
			// IPv4 through a dual-stack socket also comes as IPV6_PKTINFO (v4-mapped)
			setsockopt(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)?;
			let _ = setsockopt(socket, libc::IPPROTO_IP, libc::IP_PKTINFO);
			Ok(())
		} else {
			setsockopt(socket, libc::IPPROTO_IP, libc::IP_PKTINFO)
		}
	}

	pub fn recv(socket: &UdpSocket, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<Local>)> {
		// SAFETY: plain C structs, all-zero is a valid value
		let mut name: libc::sockaddr_storage = unsafe { mem::zeroed() };
		let mut control: Control = [0; 16];
		let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
		// SAFETY: as above
		let mut msg: libc::msghdr = unsafe { mem::zeroed() };
		msg.msg_name = (&mut name as *mut libc::sockaddr_storage).cast();
		msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
		msg.msg_iov = &mut iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.as_mut_ptr().cast();
		msg.msg_controllen = mem::size_of::<Control>() as _;
		// SAFETY: msg points at live buffers of the stated sizes
		let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
		if n < 0 {
			return Err(io::Error::last_os_error());
		}
		let from = from_sockaddr(&name).ok_or_else(|| io::Error::other("recvmsg: unknown address family"))?;
		Ok((n as usize, from, local_of(&msg)))
	}

	/// The destination from the control messages of a received datagram.
	fn local_of(msg: &libc::msghdr) -> Option<Local> {
		let mut v4 = None;
		// SAFETY: walking the control buffer the kernel filled, with its own macros;
		// the payloads are read unaligned
		unsafe {
			let mut cmsg = libc::CMSG_FIRSTHDR(msg);
			while !cmsg.is_null() {
				let (level, kind) = ((*cmsg).cmsg_level, (*cmsg).cmsg_type);
				let data = libc::CMSG_DATA(cmsg);
				if level == libc::IPPROTO_IPV6 && kind == libc::IPV6_PKTINFO {
					let info: libc::in6_pktinfo = std::ptr::read_unaligned(data.cast());
					return Some(Local { ip: IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)), ifindex: info.ipi6_ifindex });
				}
				if level == libc::IPPROTO_IP && kind == libc::IP_PKTINFO {
					let info: libc::in_pktinfo = std::ptr::read_unaligned(data.cast());
					v4 = Some(Local {
						ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(info.ipi_addr.s_addr))),
						ifindex: info.ipi_ifindex as u32,
					});
				}
				cmsg = libc::CMSG_NXTHDR(msg, cmsg);
			}
		}
		v4
	}

	pub fn send(socket: &UdpSocket, data: &[u8], to: SocketAddr, local: Local) -> io::Result<usize> {
		let v6_socket = socket.local_addr()?.is_ipv6();
		// a dual-stack socket addresses IPv4 clients as v4-mapped
		let to = match (v6_socket, to) {
			(true, SocketAddr::V4(a)) => SocketAddr::V6(SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0)),
			_ => to,
		};
		let (name, name_len) = to_sockaddr(to);
		let mut control: Control = [0; 16];
		let control_len = if v6_socket { build_v6(&mut control, local) } else { build_v4(&mut control, local)? };
		let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut libc::c_void, iov_len: data.len() };
		// SAFETY: plain C struct, all-zero is valid
		let mut msg: libc::msghdr = unsafe { mem::zeroed() };
		msg.msg_name = (&name as *const libc::sockaddr_storage) as *mut libc::c_void;
		msg.msg_namelen = name_len;
		msg.msg_iov = &mut iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.as_mut_ptr().cast();
		msg.msg_controllen = control_len as _;
		// SAFETY: msg points at live buffers of the stated sizes
		let n = unsafe { libc::sendmsg(socket.as_raw_fd(), &msg, 0) };
		if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
	}

	/// IPV6_PKTINFO for an IPv6 (possibly dual-stack) socket; a v4-mapped source
	/// is accepted by Linux for IPv4 destinations.
	pub(super) fn build_v6(control: &mut Control, local: Local) -> usize {
		let addr = match local.ip {
			IpAddr::V6(a) => a,
			IpAddr::V4(a) => a.to_ipv6_mapped(),
		};
		// only a link-local source needs the interface; otherwise let routing choose it
		let ifindex = if addr.is_unicast_link_local() { local.ifindex } else { 0 };
		let info = libc::in6_pktinfo { ipi6_addr: libc::in6_addr { s6_addr: addr.octets() }, ipi6_ifindex: ifindex };
		// SAFETY: the buffer holds CMSG_SPACE(in6_pktinfo) (checked by the tests)
		unsafe { put(control, libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, info) }
	}

	/// IP_PKTINFO (ipi_spec_dst = the source) for an IPv4 socket.
	pub(super) fn build_v4(control: &mut Control, local: Local) -> io::Result<usize> {
		let IpAddr::V4(addr) = local.ip.to_canonical() else {
			return Err(io::Error::from_raw_os_error(libc::EINVAL));
		};
		let info = libc::in_pktinfo {
			ipi_ifindex: 0,
			ipi_spec_dst: libc::in_addr { s_addr: u32::from(addr).to_be() },
			ipi_addr: libc::in_addr { s_addr: 0 },
		};
		// SAFETY: as in build_v6
		Ok(unsafe { put(control, libc::IPPROTO_IP, libc::IP_PKTINFO, info) })
	}

	/// Writes one control message at the start of `control`; its space.
	unsafe fn put<T>(control: &mut Control, level: libc::c_int, kind: libc::c_int, value: T) -> usize {
		let space = libc::CMSG_SPACE(mem::size_of::<T>() as u32) as usize;
		assert!(space <= mem::size_of::<Control>());
		// SAFETY: a msghdr describing `control` lets the libc macros place the header
		let mut msg: libc::msghdr = mem::zeroed();
		msg.msg_control = control.as_mut_ptr().cast();
		msg.msg_controllen = space as _;
		let cmsg = libc::CMSG_FIRSTHDR(&msg);
		(*cmsg).cmsg_level = level;
		(*cmsg).cmsg_type = kind;
		(*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<T>() as u32) as _;
		std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<T>(), value);
		space
	}

	fn from_sockaddr(s: &libc::sockaddr_storage) -> Option<SocketAddr> {
		match s.ss_family as libc::c_int {
			libc::AF_INET => {
				// SAFETY: the family says it is a sockaddr_in
				let a: libc::sockaddr_in = unsafe { std::ptr::read_unaligned((s as *const libc::sockaddr_storage).cast()) };
				Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)), u16::from_be(a.sin_port))))
			}
			libc::AF_INET6 => {
				// SAFETY: the family says it is a sockaddr_in6
				let a: libc::sockaddr_in6 = unsafe { std::ptr::read_unaligned((s as *const libc::sockaddr_storage).cast()) };
				Some(SocketAddr::V6(SocketAddrV6::new(
					Ipv6Addr::from(a.sin6_addr.s6_addr),
					u16::from_be(a.sin6_port),
					a.sin6_flowinfo,
					a.sin6_scope_id,
				)))
			}
			_ => None,
		}
	}

	fn to_sockaddr(to: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
		// SAFETY: all-zero is valid; the right struct is written over its start
		let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
		match to {
			SocketAddr::V4(a) => {
				let sin = libc::sockaddr_in {
					sin_family: libc::AF_INET as libc::sa_family_t,
					sin_port: a.port().to_be(),
					sin_addr: libc::in_addr { s_addr: u32::from(*a.ip()).to_be() },
					sin_zero: [0; 8],
				};
				// SAFETY: sockaddr_storage is larger than sockaddr_in
				unsafe { std::ptr::write_unaligned((&mut storage as *mut libc::sockaddr_storage).cast(), sin) };
				(storage, mem::size_of::<libc::sockaddr_in>() as libc::socklen_t)
			}
			SocketAddr::V6(a) => {
				let sin6 = libc::sockaddr_in6 {
					sin6_family: libc::AF_INET6 as libc::sa_family_t,
					sin6_port: a.port().to_be(),
					sin6_flowinfo: a.flowinfo(),
					sin6_addr: libc::in6_addr { s6_addr: a.ip().octets() },
					sin6_scope_id: a.scope_id(),
				};
				// SAFETY: sockaddr_storage is larger than sockaddr_in6
				unsafe { std::ptr::write_unaligned((&mut storage as *mut libc::sockaddr_storage).cast(), sin6) };
				(storage, mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t)
			}
		}
	}

	#[cfg(test)]
	mod tests {
		use super::*;

		fn parse(control: &mut Control, len: usize) -> Option<Local> {
			// SAFETY: all-zero is valid
			let mut msg: libc::msghdr = unsafe { mem::zeroed() };
			msg.msg_control = control.as_mut_ptr().cast();
			msg.msg_controllen = len as _;
			local_of(&msg)
		}

		#[test]
		fn control_messages_round_trip() {
			let mut c: Control = [0; 16];
			let v6 = Local { ip: "2001:db8:2::1".parse().unwrap(), ifindex: 7 };
			let len = build_v6(&mut c, v6);
			// a global address is sent without the interface
			assert_eq!(parse(&mut c, len), Some(Local { ifindex: 0, ..v6 }));
			let ll = Local { ip: "fe80::1".parse().unwrap(), ifindex: 7 };
			let len = build_v6(&mut c, ll);
			assert_eq!(parse(&mut c, len), Some(ll), "a link-local source keeps its interface");
			// IPv4 on a dual-stack socket goes as v4-mapped
			let len = build_v6(&mut c, Local { ip: "192.0.2.1".parse().unwrap(), ifindex: 0 });
			assert_eq!(parse(&mut c, len).map(|l| l.canonical()), Some("192.0.2.1".parse().unwrap()));

			let mut c: Control = [0; 16];
			let len = build_v4(&mut c, Local { ip: "198.51.100.1".parse().unwrap(), ifindex: 3 }).unwrap();
			// build_v4 writes ipi_spec_dst; parsing reads ipi_addr, so check the raw struct
			// SAFETY: the message was just written
			let spec = unsafe {
				let mut msg: libc::msghdr = mem::zeroed();
				msg.msg_control = c.as_mut_ptr().cast();
				msg.msg_controllen = len as _;
				let cmsg = libc::CMSG_FIRSTHDR(&msg);
				assert_eq!(((*cmsg).cmsg_level, (*cmsg).cmsg_type), (libc::IPPROTO_IP, libc::IP_PKTINFO));
				let info: libc::in_pktinfo = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast());
				Ipv4Addr::from(u32::from_be(info.ipi_spec_dst.s_addr))
			};
			assert_eq!(spec, Ipv4Addr::new(198, 51, 100, 1));
			assert!(build_v4(&mut c, Local { ip: "2001:db8::1".parse().unwrap(), ifindex: 0 }).is_err());
		}

		#[test]
		fn socket_addresses_round_trip() {
			for a in ["192.0.2.1:500", "[2001:db8::1]:4500", "[::ffff:192.0.2.1]:53"] {
				let a: SocketAddr = a.parse().unwrap();
				let (s, _) = to_sockaddr(a);
				assert_eq!(from_sockaddr(&s), Some(a));
			}
		}
	}
}

#[cfg(not(target_os = "linux"))]
mod sys {
	use std::io;
	use std::net::SocketAddr;

	use tokio::net::UdpSocket;

	use super::Local;

	pub fn enable(_: &UdpSocket) -> io::Result<()> {
		Err(io::Error::from(io::ErrorKind::Unsupported))
	}

	pub fn recv(_: &UdpSocket, _: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<Local>)> {
		Err(io::Error::from(io::ErrorKind::Unsupported))
	}

	pub fn send(_: &UdpSocket, _: &[u8], _: SocketAddr, _: Local) -> io::Result<usize> {
		Err(io::Error::from(io::ErrorKind::Unsupported))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A reply to 127.0.0.1 from a wildcard socket would leave from 127.0.0.1 (the
	/// route to it); with packet info it leaves from 127.0.0.2, where it was sent.
	#[tokio::test]
	async fn wildcard_replies_leave_from_the_address_sent_to() {
		for wild in ["0.0.0.0:0", "[::]:0"] {
			let Ok(std) = std::net::UdpSocket::bind(wild) else { continue };
			std.set_nonblocking(true).unwrap();
			let listener = Listener::new(UdpSocket::from_std(std).unwrap());
			let port = listener.local_addr().unwrap().port();
			let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
			client.send_to(b"ping", ("127.0.0.2", port)).await.unwrap();
			let mut buf = [0u8; 16];
			let (n, from, local) = listener.recv(&mut buf).await.unwrap();
			assert_eq!(&buf[..n], b"ping");
			let local = local.unwrap_or_else(|| panic!("{wild}: no destination learnt"));
			assert_eq!(local.canonical(), "127.0.0.2".parse::<IpAddr>().unwrap(), "{wild}");
			assert_eq!(listener.local_for(Some(local)), SocketAddr::from(([127, 0, 0, 2], port)));
			listener.send_to(b"pong", from, Some(local)).await.unwrap();
			let (n, source) = client.recv_from(&mut buf).await.unwrap();
			assert_eq!((&buf[..n], source), (&b"pong"[..], SocketAddr::from(([127, 0, 0, 2], port))), "{wild}");
		}
	}

	#[tokio::test]
	async fn specific_addresses_keep_the_plain_path() {
		let listener = Listener::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
		assert!(!listener.pktinfo);
		let port = listener.local_addr().unwrap().port();
		let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		client.send_to(b"x", ("127.0.0.1", port)).await.unwrap();
		let mut buf = [0u8; 4];
		let (_, _, local) = listener.recv(&mut buf).await.unwrap();
		assert_eq!(local, None);
	}
}
