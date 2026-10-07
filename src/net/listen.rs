//! Opening a rule's listening sockets, and whether two listening addresses clash.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};

use socket2::{Domain, Socket, Type};

fn socket(addr: SocketAddr, kind: Type, v6only: bool) -> io::Result<Socket> {
	let sock = Socket::new(Domain::for_address(addr), kind, None)?;
	if addr.is_ipv6() && v6only {
		sock.set_only_v6(true)?;
	}
	busy_poll(&sock);
	Ok(sock)
}

/// `global.performance.busy_poll_usecs` (#194): SO_BUSY_POLL of the listening
/// sockets (accepted connections take it over). 0: off.
static BUSY_POLL_USECS: AtomicU32 = AtomicU32::new(0);

/// Sets SO_BUSY_POLL for the sockets opened from now on (at startup).
pub fn set_busy_poll(usecs: u32) {
	BUSY_POLL_USECS.store(usecs, Ordering::Relaxed);
}

fn busy_poll(sock: &Socket) {
	let usecs = BUSY_POLL_USECS.load(Ordering::Relaxed);
	if usecs == 0 {
		return;
	}
	#[cfg(target_os = "linux")]
	{
		use std::os::fd::AsRawFd;
		let v = usecs as libc::c_int;
		// SAFETY: setsockopt reads an int from a local
		let r = unsafe {
			libc::setsockopt(
				sock.as_raw_fd(),
				libc::SOL_SOCKET,
				libc::SO_BUSY_POLL,
				(&v as *const libc::c_int).cast(),
				std::mem::size_of::<libc::c_int>() as libc::socklen_t,
			)
		};
		if r != 0 {
			static ONCE: std::sync::Once = std::sync::Once::new();
			let e = io::Error::last_os_error();
			// above net.core.busy_read needs CAP_NET_ADMIN; the socket works without it
			ONCE.call_once(|| tracing::warn!(event = "degraded", part = "global.performance.busy_poll_usecs", error = %e,
				"SO_BUSY_POLL could not be set; sockets wait as usual"));
		}
	}
}

/// A socket handed over by the old process in a live upgrade (#174), as a
/// non-blocking socket.
fn inherited<T: Into<std::os::fd::OwnedFd> + From<std::os::fd::OwnedFd>>(sock: T) -> io::Result<T> {
	let sock = Socket::from(sock.into());
	sock.set_nonblocking(true)?;
	Ok(T::from(sock.into()))
}

/// A TCP listener. `v6only` makes an IPv6 socket take IPv6 only, so `::` and
/// `0.0.0.0` can listen on the same port.
pub fn tcp(addr: SocketAddr, v6only: bool) -> io::Result<std::net::TcpListener> {
	if let Some(l) = crate::control::upgrade::inherit::take_tcp(addr) {
		return inherited(l);
	}
	let sock = socket(addr, Type::STREAM, v6only)?;
	// lets a stopped rule's port be reused while old connections sit in TIME_WAIT
	sock.set_reuse_address(true)?;
	sock.set_nonblocking(true)?;
	sock.bind(&addr.into())?;
	sock.listen(1024)?;
	Ok(sock.into())
}

/// A UDP socket (non-blocking), with `v6only` as for [`tcp`].
pub fn udp(addr: SocketAddr, v6only: bool) -> io::Result<std::net::UdpSocket> {
	let mut old = crate::control::upgrade::inherit::take_udp(addr);
	if let Some(s) = old.pop() {
		return inherited(s);
	}
	let sock = socket(addr, Type::DGRAM, v6only)?;
	sock.set_nonblocking(true)?;
	sock.bind(&addr.into())?;
	Ok(sock.into())
}

/// Bytes asked for as `SO_RCVBUF` of UDP listening sockets (the kernel caps it at
/// `net.core.rmem_max`). The default (`net.core.rmem_default`, about 208 KiB)
/// holds only a few hundred small datagrams: a 64-byte datagram takes several
/// hundred bytes of buffer (its skb), so bursts were dropped by the kernel.
/// `RPROXY_UDP_RCVBUF` overrides it (0 keeps the kernel's default; an
/// experiment's tunable, #194).
const UDP_RCVBUF: usize = 4 << 20;

fn udp_rcvbuf() -> usize {
	static V: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
	*V.get_or_init(|| std::env::var("RPROXY_UDP_RCVBUF").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(UDP_RCVBUF))
}

/// UDP listening sockets of one address and port: `shards` of them in one
/// `SO_REUSEPORT` group (#194), so that several tasks can read the port at once.
/// The kernel hands each datagram to one of them by a hash of its addresses and
/// ports, so a client keeps reaching the same socket while the group stays the
/// same (it changes only when the rule's sockets are opened again).
///
/// Before the group, the port is bound once without `SO_REUSEPORT` and closed
/// again: a group would otherwise join another process's group on the same
/// port (of the same user) silently, where a single socket fails with
/// "address in use" as it always did.
pub fn udp_shards(addr: SocketAddr, v6only: bool, shards: usize) -> io::Result<Vec<std::net::UdpSocket>> {
	let shards = shards.max(1);
	// a live upgrade (#174): the old process's group as it was (its size decides
	// where the kernel sends clients)
	let old = crate::control::upgrade::inherit::take_udp(addr);
	if !old.is_empty() {
		if old.len() != shards {
			tracing::info!(event = "handoff.sockets", addr = %addr, inherited = old.len(), udp_shards = shards,
				"keeping the inherited UDP sockets; udp_shards applies when the rule's sockets are opened again");
		}
		return old.into_iter().map(inherited).collect();
	}
	let rcvbuf = udp_rcvbuf();
	let open = |reuse: bool, addr: SocketAddr| -> io::Result<Socket> {
		let sock = socket(addr, Type::DGRAM, v6only)?;
		#[cfg(target_os = "linux")]
		if reuse {
			sock.set_reuse_port(true)?;
		}
		#[cfg(not(target_os = "linux"))]
		let _ = reuse;
		if rcvbuf > 0 {
			// best effort: the kernel's cap applies, and a smaller buffer still works
			let _ = sock.set_recv_buffer_size(rcvbuf);
		}
		sock.set_nonblocking(true)?;
		sock.bind(&addr.into())?;
		Ok(sock)
	};
	if shards == 1 || !cfg!(target_os = "linux") {
		return Ok(vec![open(false, addr)?.into()]);
	}
	// port 0: the group shares the port the first socket was given
	let addr = {
		let probe = open(false, addr)?;
		let bound = probe.local_addr()?.as_socket().unwrap_or(addr);
		drop(probe);
		bound
	};
	(0..shards).map(|_| open(true, addr).map(Into::into)).collect()
}

/// Whether sockets on `a` and `b` (same protocol and port) would clash: the same
/// address, or a wildcard that covers the other. A `::` without `IPV6_V6ONLY`
/// also takes IPv4, as Linux does by default.
pub fn clash(a: IpAddr, a_v6only: bool, b: IpAddr, b_v6only: bool) -> bool {
	fn covers(wild: IpAddr, wild_v6only: bool, other: IpAddr) -> bool {
		match wild {
			IpAddr::V4(w) if w.is_unspecified() => other.is_ipv4(),
			IpAddr::V6(w) if w.is_unspecified() => !wild_v6only || other.is_ipv6(),
			_ => false,
		}
	}
	a == b || covers(a, a_v6only, b) || covers(b, b_v6only, a)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	#[test]
	fn clashes() {
		// v4 wildcard and v4 addresses
		assert!(clash(ip("0.0.0.0"), false, ip("10.0.0.1"), false));
		assert!(!clash(ip("0.0.0.0"), false, ip("2001:db8::1"), false));
		// a dual-stack :: takes everything; an IPv6-only one only IPv6
		assert!(clash(ip("::"), false, ip("10.0.0.1"), false));
		assert!(clash(ip("::"), false, ip("0.0.0.0"), false));
		assert!(!clash(ip("::"), true, ip("0.0.0.0"), false));
		assert!(!clash(ip("::"), true, ip("10.0.0.1"), false));
		assert!(clash(ip("::"), true, ip("2001:db8::1"), false));
		// 0.0.0.0 against a dual-stack :: (either order)
		assert!(clash(ip("0.0.0.0"), false, ip("::"), false));
		assert!(!clash(ip("0.0.0.0"), false, ip("::"), true));
		assert!(!clash(ip("10.0.0.1"), false, ip("10.0.0.2"), false));
		assert!(clash(ip("2001:db8::1"), true, ip("2001:db8::1"), false));
	}

	#[test]
	fn v4_and_v6_wildcards_listen_side_by_side() {
		let v4 = tcp("0.0.0.0:0".parse().unwrap(), false).unwrap();
		let port = v4.local_addr().unwrap().port();
		// no IPv6 on this host: nothing to check
		let Ok(v6) = tcp(SocketAddr::new(ip("::"), port), true) else { return };
		assert_eq!(v6.local_addr().unwrap().port(), port);
		let u4 = udp("0.0.0.0:0".parse().unwrap(), false).unwrap();
		let uport = u4.local_addr().unwrap().port();
		if let Ok(u6) = udp(SocketAddr::new(ip("::"), uport), true) {
			assert_eq!(u6.local_addr().unwrap().port(), uport);
		}
	}
}
