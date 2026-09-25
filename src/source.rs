//! Passing the client's address on to the backend: PROXY protocol headers and
//! IP_TRANSPARENT sockets.

use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

const V2_SIGNATURE: [u8; 12] = [0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a];

fn to_v6(ip: IpAddr) -> Ipv6Addr {
	match ip {
		IpAddr::V4(v4) => v4.to_ipv6_mapped(),
		IpAddr::V6(v6) => v6,
	}
}

/// PROXY protocol v1 (text) header for a TCP connection.
pub fn proxy_v1_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
	match (src.ip(), dst.ip()) {
		(IpAddr::V4(s), IpAddr::V4(d)) => {
			format!("PROXY TCP4 {s} {d} {} {}\r\n", src.port(), dst.port()).into_bytes()
		}
		(s, d) => {
			format!("PROXY TCP6 {} {} {} {}\r\n", to_v6(s), to_v6(d), src.port(), dst.port()).into_bytes()
		}
	}
}

/// PROXY protocol v2 (binary) header for a TCP connection.
pub fn proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
	let mut out = V2_SIGNATURE.to_vec();
	out.push(0x21); // version 2, PROXY command
	match (src.ip(), dst.ip()) {
		(IpAddr::V4(s), IpAddr::V4(d)) => {
			out.push(0x11); // AF_INET, STREAM
			out.extend_from_slice(&12u16.to_be_bytes());
			out.extend_from_slice(&s.octets());
			out.extend_from_slice(&d.octets());
		}
		(s, d) => {
			out.push(0x21); // AF_INET6, STREAM
			out.extend_from_slice(&36u16.to_be_bytes());
			out.extend_from_slice(&to_v6(s).octets());
			out.extend_from_slice(&to_v6(d).octets());
		}
	}
	out.extend_from_slice(&src.port().to_be_bytes());
	out.extend_from_slice(&dst.port().to_be_bytes());
	out
}

#[cfg(target_os = "linux")]
fn transparent_socket(domain: Domain, ty: Type, protocol: Protocol, bind_as: SocketAddr) -> io::Result<Socket> {
	let sock = Socket::new(domain, ty, Some(protocol))?;
	sock.set_ip_transparent(true)?;
	sock.set_reuse_address(true)?;
	sock.set_nonblocking(true)?;
	sock.bind(&bind_as.into())?;
	Ok(sock)
}

#[cfg(not(target_os = "linux"))]
fn transparent_socket(_: Domain, _: Type, _: Protocol, _: SocketAddr) -> io::Result<Socket> {
	Err(io::Error::new(io::ErrorKind::Unsupported, "IP_TRANSPARENT is Linux only"))
}

/// Whether this process may use IP_TRANSPARENT (Linux with CAP_NET_ADMIN).
pub fn transparent_available() -> bool {
	#[cfg(target_os = "linux")]
	{
		Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
			.and_then(|s| s.set_ip_transparent(true))
			.is_ok()
	}
	#[cfg(not(target_os = "linux"))]
	{
		false
	}
}

/// Connects to `target`, optionally presenting `bind_as` (the client) as the source address.
pub async fn connect_tcp(target: SocketAddr, bind_as: Option<SocketAddr>) -> io::Result<TcpStream> {
	match bind_as {
		None => TcpStream::connect(target).await,
		Some(src) => {
			let sock = transparent_socket(Domain::for_address(target), Type::STREAM, Protocol::TCP, src)?;
			TcpSocket::from_std_stream(sock.into()).connect(target).await
		}
	}
}

/// Opens the upstream socket of a UDP session, optionally sending as `bind_as` (the client).
pub async fn udp_upstream(target: SocketAddr, bind_as: Option<SocketAddr>) -> io::Result<UdpSocket> {
	let sock = match bind_as {
		None => {
			let any: SocketAddr = match target {
				SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
				SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
			};
			UdpSocket::bind(any).await?
		}
		Some(src) => {
			let sock = transparent_socket(Domain::for_address(target), Type::DGRAM, Protocol::UDP, src)?;
			UdpSocket::from_std(sock.into())?
		}
	};
	sock.connect(target).await?;
	Ok(sock)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn v1_header() {
		let h = proxy_v1_header("192.0.2.1:5000".parse().unwrap(), "198.51.100.1:80".parse().unwrap());
		assert_eq!(h, b"PROXY TCP4 192.0.2.1 198.51.100.1 5000 80\r\n");
		let h = proxy_v1_header("[2001:db8::1]:5000".parse().unwrap(), "192.0.2.9:80".parse().unwrap());
		assert_eq!(h, b"PROXY TCP6 2001:db8::1 ::ffff:192.0.2.9 5000 80\r\n");
	}

	#[test]
	fn v2_header_ipv4() {
		let h = proxy_v2_header("192.0.2.1:5000".parse().unwrap(), "198.51.100.1:80".parse().unwrap());
		assert_eq!(&h[..12], &V2_SIGNATURE);
		assert_eq!(&h[12..16], &[0x21, 0x11, 0x00, 0x0c]);
		assert_eq!(&h[16..20], &[192, 0, 2, 1]);
		assert_eq!(&h[20..24], &[198, 51, 100, 1]);
		assert_eq!(&h[24..], &[0x13, 0x88, 0x00, 0x50]);
	}

	#[test]
	fn v2_header_ipv6_length() {
		let h = proxy_v2_header("[2001:db8::1]:1".parse().unwrap(), "[2001:db8::2]:2".parse().unwrap());
		assert_eq!(h.len(), 16 + 36);
		assert_eq!(h[13], 0x21);
	}
}
