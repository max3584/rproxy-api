//! Opening a rule's listening sockets, and whether two listening addresses clash.

use std::io;
use std::net::{IpAddr, SocketAddr};

use socket2::{Domain, Socket, Type};

fn socket(addr: SocketAddr, kind: Type, v6only: bool) -> io::Result<Socket> {
	let sock = Socket::new(Domain::for_address(addr), kind, None)?;
	if addr.is_ipv6() && v6only {
		sock.set_only_v6(true)?;
	}
	Ok(sock)
}

/// A TCP listener. `v6only` makes an IPv6 socket take IPv6 only, so `::` and
/// `0.0.0.0` can listen on the same port.
pub fn tcp(addr: SocketAddr, v6only: bool) -> io::Result<std::net::TcpListener> {
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
	let sock = socket(addr, Type::DGRAM, v6only)?;
	sock.set_nonblocking(true)?;
	sock.bind(&addr.into())?;
	Ok(sock.into())
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
