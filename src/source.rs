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

/// What a terminated TLS session tells the backend (PROXY v2 TLVs).
#[derive(Clone, Debug, Default)]
pub struct TlsInfo {
	pub server_name: Option<String>,
	pub alpn: Option<String>,
	pub version: Option<String>,
	/// Common name of a verified client certificate.
	pub client_cn: Option<String>,
	/// The client sent a certificate (it was verified, or the handshake would have failed).
	pub client_cert: bool,
}

const PP2_TYPE_ALPN: u8 = 0x01;
const PP2_TYPE_AUTHORITY: u8 = 0x02;
const PP2_TYPE_SSL: u8 = 0x20;
const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21;
const PP2_SUBTYPE_SSL_CN: u8 = 0x22;
const PP2_CLIENT_SSL: u8 = 0x01;
const PP2_CLIENT_CERT_CONN: u8 = 0x02;

fn tlv(out: &mut Vec<u8>, kind: u8, value: &[u8]) {
	out.push(kind);
	out.extend_from_slice(&(value.len() as u16).to_be_bytes());
	out.extend_from_slice(value);
}

fn tls_tlvs(info: &TlsInfo) -> Vec<u8> {
	let mut out = vec![];
	if let Some(alpn) = &info.alpn {
		tlv(&mut out, PP2_TYPE_ALPN, alpn.as_bytes());
	}
	if let Some(name) = &info.server_name {
		tlv(&mut out, PP2_TYPE_AUTHORITY, name.as_bytes());
	}
	let mut ssl = vec![PP2_CLIENT_SSL | if info.client_cert { PP2_CLIENT_CERT_CONN } else { 0 }];
	ssl.extend_from_slice(&0u32.to_be_bytes()); // verify: 0 = verified (or no certificate)
	if let Some(version) = &info.version {
		tlv(&mut ssl, PP2_SUBTYPE_SSL_VERSION, version.as_bytes());
	}
	if let Some(cn) = &info.client_cn {
		tlv(&mut ssl, PP2_SUBTYPE_SSL_CN, cn.as_bytes());
	}
	tlv(&mut out, PP2_TYPE_SSL, &ssl);
	out
}

/// PROXY protocol v2 (binary) header for a TCP connection.
pub fn proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
	proxy_v2_header_with(src, dst, None)
}

/// PROXY protocol v2 header, carrying TLS details when rproxy terminated TLS.
pub fn proxy_v2_header_with(src: SocketAddr, dst: SocketAddr, tls: Option<&TlsInfo>) -> Vec<u8> {
	let tlvs = tls.map(tls_tlvs).unwrap_or_default();
	let mut out = V2_SIGNATURE.to_vec();
	out.push(0x21); // version 2, PROXY command
	let (family, addrs) = match (src.ip(), dst.ip()) {
		(IpAddr::V4(s), IpAddr::V4(d)) => (0x11, [s.octets().to_vec(), d.octets().to_vec()].concat()),
		(s, d) => (0x21, [to_v6(s).octets().to_vec(), to_v6(d).octets().to_vec()].concat()),
	};
	out.push(family); // AF_INET or AF_INET6, STREAM
	out.extend_from_slice(&((addrs.len() + 4 + tlvs.len()) as u16).to_be_bytes());
	out.extend_from_slice(&addrs);
	out.extend_from_slice(&src.port().to_be_bytes());
	out.extend_from_slice(&dst.port().to_be_bytes());
	out.extend_from_slice(&tlvs);
	out
}

/// The client address as the source for a connection to `target`: an
/// IPv4-mapped client (a dual-stack listener) becomes plain IPv4 for an IPv4
/// target. The client and the target must end up in the same family.
fn source_for(target: SocketAddr, client: SocketAddr) -> io::Result<SocketAddr> {
	let ip = match (target.ip(), client.ip()) {
		(IpAddr::V4(_), IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
			Some(v4) => IpAddr::V4(v4),
			None => client.ip(),
		},
		_ => client.ip(),
	};
	if ip.is_ipv4() != target.is_ipv4() {
		return Err(io::Error::new(
			io::ErrorKind::Unsupported,
			format!("transparent: client {client} and target {target} are in different address families"),
		));
	}
	Ok(SocketAddr::new(ip, client.port()))
}

#[cfg(target_os = "linux")]
fn transparent_socket(domain: Domain, ty: Type, protocol: Protocol, bind_as: SocketAddr) -> io::Result<Socket> {
	let sock = Socket::new(domain, ty, Some(protocol))?;
	if domain == Domain::IPV6 {
		sock.set_ip_transparent_v6(true)?;
	} else {
		sock.set_ip_transparent_v4(true)?;
	}
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
			.and_then(|s| s.set_ip_transparent_v4(true))
			.is_ok()
	}
	#[cfg(not(target_os = "linux"))]
	{
		false
	}
}

/// Whether this process may use IPV6_TRANSPARENT (and the host has IPv6).
pub fn transparent_v6_available() -> bool {
	#[cfg(target_os = "linux")]
	{
		Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))
			.and_then(|s| s.set_ip_transparent_v6(true))
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
		Some(client) => {
			let src = source_for(target, client)?;
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
		Some(client) => {
			let src = source_for(target, client)?;
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
	fn transparent_source_matches_the_target_family() {
		let v4: SocketAddr = "192.0.2.10:80".parse().unwrap();
		let v6: SocketAddr = "[fd00:2::2]:80".parse().unwrap();
		let mapped: SocketAddr = "[::ffff:198.51.100.7]:5000".parse().unwrap();
		let gua: SocketAddr = "[2001:db8:1::2]:5000".parse().unwrap();
		assert_eq!(source_for(v4, mapped).unwrap(), "198.51.100.7:5000".parse().unwrap());
		assert_eq!(source_for(v6, gua).unwrap(), gua);
		assert!(source_for(v4, gua).is_err(), "IPv6 client to an IPv4 target");
		assert!(source_for(v6, "198.51.100.7:1".parse().unwrap()).is_err(), "IPv4 client to an IPv6 target");
	}

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
	fn v2_header_carries_tls_tlvs() {
		let info = TlsInfo {
			server_name: Some("mail.example".into()),
			alpn: None,
			version: Some("TLSv1_3".into()),
			client_cn: Some("alice".into()),
			client_cert: true,
		};
		let h = proxy_v2_header_with("192.0.2.1:1".parse().unwrap(), "192.0.2.2:2".parse().unwrap(), Some(&info));
		let len = u16::from_be_bytes([h[14], h[15]]) as usize;
		assert_eq!(h.len(), 16 + len);
		let tlvs = &h[28..];
		assert_eq!(tlvs[0], PP2_TYPE_AUTHORITY);
		assert_eq!(&tlvs[3..15], b"mail.example");
		assert_eq!(tlvs[15], PP2_TYPE_SSL);
		assert_eq!(tlvs[18], PP2_CLIENT_SSL | PP2_CLIENT_CERT_CONN);
		assert!(h.windows(5).any(|w| w == b"alice"));
	}

	#[test]
	fn v2_header_ipv6_length() {
		let h = proxy_v2_header("[2001:db8::1]:1".parse().unwrap(), "[2001:db8::2]:2".parse().unwrap());
		assert_eq!(h.len(), 16 + 36);
		assert_eq!(h[13], 0x21);
	}
}
