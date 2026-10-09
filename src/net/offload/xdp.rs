//! AF_XDP for L4 UDP (#260, stage 1), opt-in and experimental (cargo feature
//! `kernel-offload`). The XDP program (`bpf/xdp-redirect`, loaded by `aya`)
//! steers the UDP packets of rproxy's rule ports to an AF_XDP socket on the
//! right RX queue; everything else goes up the normal stack. rproxy reads and
//! answers the client side through the XSK (UMEM + the four rings, via
//! `xdpilone`) instead of `recvmmsg` / `sendmmsg`, with no per-packet system
//! call. The backend side stays an ordinary UDP socket.
//!
//! What stays in user space: sessions, PROXY protocol, `source_ip`, and the
//! `allow_from` / `crowdsec` / `limits` / `bandwidth` checks — the XSK only
//! moves the client-facing datagrams.
//!
//! The reply to a client is built by reflecting the received frame (swap the
//! Ethernet, IP and UDP addresses, new payload, fixed lengths and checksums),
//! so no neighbour lookup is needed. The frame parsing and crafting are pure
//! functions with unit tests; the ring handling is checked in CI
//! (`offload` job) on veth with generic XDP, never on this machine (no BPF).

#![cfg(all(feature = "kernel-offload", target_os = "linux"))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const ETH_HLEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_UDP: u8 = 17;
const UDP_HLEN: usize = 8;

/// A UDP datagram read from the wire through AF_XDP: the payload plus the
/// addresses, kept so the reply can reflect the frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
	pub eth_src: [u8; 6],
	pub eth_dst: [u8; 6],
	pub src: SocketAddr,
	pub dst: SocketAddr,
	/// Byte offset of the UDP payload within the frame.
	pub payload: usize,
	/// IP header start and length (for rebuilding the reply).
	ip_off: usize,
	v4: bool,
}

/// Reads the Ethernet/IP/UDP headers of `frame` (one full L2 frame). `None`
/// when it is not a plain UDP packet this path handles (the XDP program only
/// steers those, but a frame is still checked here).
pub fn parse(frame: &[u8]) -> Option<Parsed> {
	let eth_type = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
	let mut eth_dst = [0u8; 6];
	let mut eth_src = [0u8; 6];
	eth_dst.copy_from_slice(frame.get(0..6)?);
	eth_src.copy_from_slice(frame.get(6..12)?);
	let ip_off = ETH_HLEN;
	let (udp_off, src_ip, dst_ip, v4) = match eth_type {
		ETH_P_IP => {
			let vihl = *frame.get(ip_off)?;
			if vihl >> 4 != 4 {
				return None;
			}
			let ihl = usize::from(vihl & 0x0f) * 4;
			if ihl < 20 || *frame.get(ip_off + 9)? != IPPROTO_UDP {
				return None;
			}
			let s = Ipv4Addr::new(*frame.get(ip_off + 12)?, *frame.get(ip_off + 13)?, *frame.get(ip_off + 14)?, *frame.get(ip_off + 15)?);
			let d = Ipv4Addr::new(*frame.get(ip_off + 16)?, *frame.get(ip_off + 17)?, *frame.get(ip_off + 18)?, *frame.get(ip_off + 19)?);
			(ip_off + ihl, IpAddr::V4(s), IpAddr::V4(d), true)
		}
		ETH_P_IPV6 => {
			if *frame.get(ip_off)? >> 4 != 6 || *frame.get(ip_off + 6)? != IPPROTO_UDP {
				return None;
			}
			let s = ipv6_at(frame, ip_off + 8)?;
			let d = ipv6_at(frame, ip_off + 24)?;
			(ip_off + 40, IpAddr::V6(s), IpAddr::V6(d), false)
		}
		_ => return None,
	};
	let src_port = u16::from_be_bytes([*frame.get(udp_off)?, *frame.get(udp_off + 1)?]);
	let dst_port = u16::from_be_bytes([*frame.get(udp_off + 2)?, *frame.get(udp_off + 3)?]);
	let payload = udp_off + UDP_HLEN;
	if payload > frame.len() {
		return None;
	}
	Some(Parsed { eth_src, eth_dst, src: SocketAddr::new(src_ip, src_port), dst: SocketAddr::new(dst_ip, dst_port), payload, ip_off, v4 })
}

fn ipv6_at(frame: &[u8], off: usize) -> Option<Ipv6Addr> {
	let b: [u8; 16] = frame.get(off..off + 16)?.try_into().ok()?;
	Some(Ipv6Addr::from(b))
}

/// Builds the reply frame into `out` (cleared first): the headers of `req`
/// reflected (Ethernet and IP addresses and UDP ports swapped), carrying
/// `payload`, with the IP and UDP lengths and checksums fixed. Returns the
/// frame length, or `None` if it would not fit in `out`.
pub fn build_reply(req: &Parsed, orig: &[u8], payload: &[u8], out: &mut Vec<u8>) -> Option<usize> {
	let total = req.payload + payload.len();
	if total > out.capacity().max(orig.len()) && total > 65_535 {
		return None;
	}
	out.clear();
	out.extend_from_slice(orig.get(..req.payload)?);
	out.extend_from_slice(payload);
	// Ethernet: swap src/dst
	out[0..6].copy_from_slice(&req.eth_src);
	out[6..12].copy_from_slice(&req.eth_dst);
	let udp_off = req.payload - UDP_HLEN;
	let udp_len = (UDP_HLEN + payload.len()) as u16;
	if req.v4 {
		let ip = req.ip_off;
		// swap IP src/dst (12..16 <-> 16..20)
		let (s, d): ([u8; 4], [u8; 4]) = (out[ip + 12..ip + 16].try_into().ok()?, out[ip + 16..ip + 20].try_into().ok()?);
		out[ip + 12..ip + 16].copy_from_slice(&d);
		out[ip + 16..ip + 20].copy_from_slice(&s);
		let ihl = usize::from(out[ip] & 0x0f) * 4;
		let ip_total = (ihl + UDP_HLEN + payload.len()) as u16;
		out[ip + 2..ip + 4].copy_from_slice(&ip_total.to_be_bytes());
		// IPv4 header checksum
		out[ip + 10] = 0;
		out[ip + 11] = 0;
		let csum = ones_complement(&out[ip..ip + ihl]);
		out[ip + 10..ip + 12].copy_from_slice(&csum.to_be_bytes());
		out[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
		udp_checksum_v4(out, ip, udp_off);
	} else {
		let ip = req.ip_off;
		let (s, d): ([u8; 16], [u8; 16]) = (out[ip + 8..ip + 24].try_into().ok()?, out[ip + 24..ip + 40].try_into().ok()?);
		out[ip + 8..ip + 24].copy_from_slice(&d);
		out[ip + 24..ip + 40].copy_from_slice(&s);
		out[ip + 4..ip + 6].copy_from_slice(&udp_len.to_be_bytes());
		out[udp_off + 4..udp_off + 6].copy_from_slice(&udp_len.to_be_bytes());
		udp_checksum_v6(out, ip, udp_off);
	}
	// swap UDP src/dst ports
	let (sp, dp): ([u8; 2], [u8; 2]) = (out[udp_off..udp_off + 2].try_into().ok()?, out[udp_off + 2..udp_off + 4].try_into().ok()?);
	out[udp_off..udp_off + 2].copy_from_slice(&dp);
	out[udp_off + 2..udp_off + 4].copy_from_slice(&sp);
	Some(total)
}

/// The 16-bit one's-complement sum (IP/UDP checksum) of `data`.
fn ones_complement(data: &[u8]) -> u16 {
	ones_complement_with(data, 0)
}

fn ones_complement_with(data: &[u8], start: u32) -> u16 {
	let mut sum = start;
	let (pairs, rest) = data.as_chunks::<2>();
	for c in pairs {
		sum += u32::from(u16::from_be_bytes(*c));
	}
	if let [last] = rest {
		sum += u32::from(u16::from_be_bytes([*last, 0]));
	}
	while sum >> 16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	!(sum as u16)
}

/// UDP checksum over the IPv4 pseudo-header + UDP header + payload.
fn udp_checksum_v4(frame: &mut [u8], ip: usize, udp_off: usize) {
	frame[udp_off + 6] = 0;
	frame[udp_off + 7] = 0;
	let len = frame.len() - udp_off;
	let mut sum: u32 = 0;
	for pair in [&frame[ip + 12..ip + 14], &frame[ip + 14..ip + 16], &frame[ip + 16..ip + 18], &frame[ip + 18..ip + 20]] {
		sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
	}
	sum += u32::from(IPPROTO_UDP as u16);
	sum += len as u32;
	let mut csum = ones_complement_with(&frame[udp_off..udp_off + len], sum);
	if csum == 0 {
		csum = 0xffff; // 0 means "no checksum" in IPv4 UDP
	}
	frame[udp_off + 6..udp_off + 8].copy_from_slice(&csum.to_be_bytes());
}

/// UDP checksum over the IPv6 pseudo-header + UDP header + payload.
fn udp_checksum_v6(frame: &mut [u8], ip: usize, udp_off: usize) {
	frame[udp_off + 6] = 0;
	frame[udp_off + 7] = 0;
	let len = (frame.len() - udp_off) as u32;
	let mut sum: u32 = 0;
	for i in (0..32).step_by(2) {
		sum += u32::from(u16::from_be_bytes([frame[ip + 8 + i], frame[ip + 8 + i + 1]]));
	}
	sum += len;
	sum += u32::from(IPPROTO_UDP as u16);
	let csum = ones_complement_with(&frame[udp_off..udp_off + len as usize], sum);
	frame[udp_off + 6..udp_off + 8].copy_from_slice(&csum.to_be_bytes());
}

mod rings;
pub use rings::{Config as XskConfig, Xsk};
mod loader;
pub use loader::{Mode as AttachMode, Steer};
mod netlink;
pub mod selftest;

#[cfg(test)]
mod tests {
	use super::*;

	fn udp_v4(src: (&str, u16), dst: (&str, u16), payload: &[u8]) -> Vec<u8> {
		let mut f = vec![0u8; ETH_HLEN + 20 + UDP_HLEN + payload.len()];
		f[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xaa]); // dst mac
		f[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xbb]); // src mac
		f[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
		let ip = ETH_HLEN;
		f[ip] = 0x45;
		f[ip + 9] = IPPROTO_UDP;
		f[ip + 12..ip + 16].copy_from_slice(&src.0.parse::<Ipv4Addr>().unwrap().octets());
		f[ip + 16..ip + 20].copy_from_slice(&dst.0.parse::<Ipv4Addr>().unwrap().octets());
		let udp = ip + 20;
		f[udp..udp + 2].copy_from_slice(&src.1.to_be_bytes());
		f[udp + 2..udp + 4].copy_from_slice(&dst.1.to_be_bytes());
		f[udp + 4..udp + 6].copy_from_slice(&((UDP_HLEN + payload.len()) as u16).to_be_bytes());
		f[udp + UDP_HLEN..].copy_from_slice(payload);
		f
	}

	#[test]
	fn parses_and_reflects_ipv4() {
		let frame = udp_v4(("10.0.0.2", 55000), ("10.0.0.1", 9000), b"ping");
		let p = parse(&frame).unwrap();
		assert_eq!(p.src, "10.0.0.2:55000".parse::<SocketAddr>().unwrap());
		assert_eq!(p.dst, "10.0.0.1:9000".parse::<SocketAddr>().unwrap());
		assert_eq!(&frame[p.payload..], b"ping");
		let mut out = Vec::with_capacity(1500);
		let n = build_reply(&p, &frame, b"pong!", &mut out).unwrap();
		out.truncate(n);
		let r = parse(&out).unwrap();
		// addresses reflected: the reply goes back to the client
		assert_eq!(r.src, "10.0.0.1:9000".parse::<SocketAddr>().unwrap());
		assert_eq!(r.dst, "10.0.0.2:55000".parse::<SocketAddr>().unwrap());
		assert_eq!(r.eth_dst, [0x02, 0, 0, 0, 0, 0xbb]);
		assert_eq!(&out[r.payload..], b"pong!");
		// checksums valid: the whole IP header and UDP (with pseudo-header) sum to 0
		let ip = ETH_HLEN;
		assert_eq!(ones_complement(&out[ip..ip + 20]), 0, "IPv4 header checksum");
	}

	#[test]
	fn ipv6_udp_checksum_is_mandatory_and_valid() {
		let payload = b"hello world";
		let mut f = vec![0u8; ETH_HLEN + 40 + UDP_HLEN + payload.len()];
		f[12..14].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
		let ip = ETH_HLEN;
		f[ip] = 0x60;
		f[ip + 6] = IPPROTO_UDP;
		f[ip + 8..ip + 24].copy_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
		f[ip + 24..ip + 40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
		let udp = ip + 40;
		f[udp..udp + 2].copy_from_slice(&40000u16.to_be_bytes());
		f[udp + 2..udp + 4].copy_from_slice(&9000u16.to_be_bytes());
		f[udp + UDP_HLEN..].copy_from_slice(payload);
		let p = parse(&f).unwrap();
		let mut out = Vec::with_capacity(1500);
		let n = build_reply(&p, &f, payload, &mut out).unwrap();
		out.truncate(n);
		// a valid UDP checksum means the receiver's sum over pseudo-header+udp is 0
		let ipr = ETH_HLEN;
		let udpr = ipr + 40;
		let mut sum: u32 = 0;
		for i in (0..32).step_by(2) {
			sum += u32::from(u16::from_be_bytes([out[ipr + 8 + i], out[ipr + 8 + i + 1]]));
		}
		sum += (out.len() - udpr) as u32 + u32::from(IPPROTO_UDP as u16);
		assert_eq!(ones_complement_with(&out[udpr..], sum), 0, "IPv6 UDP checksum");
	}

	#[test]
	fn non_udp_is_ignored() {
		let mut f = udp_v4(("10.0.0.2", 1), ("10.0.0.1", 2), b"x");
		f[ETH_HLEN + 9] = 6; // TCP
		assert!(parse(&f).is_none());
		assert!(parse(&[0u8; 8]).is_none());
	}
}
