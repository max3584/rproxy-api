//! Ethernet / ARP / IPv4 / UDP / ICMP echo: parsing and in-place rewriting of
//! the frames the DPDK path handles (#261). Pure Rust, no allocation; every
//! offset is checked against the frame (the input comes from the network, see
//! the `dpdk_packet` fuzz target).

use std::net::{Ipv4Addr, SocketAddrV4};

pub type Mac = [u8; 6];

pub const ETH_HDR: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_LEN: usize = 28;
/// The TTL of the packets this path sends (it ends one UDP flow and starts another, like a socket).
pub const TTL: u8 = 64;
pub const BROADCAST: Mac = [0xff; 6];

/// What a frame is, as far as this path cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Frame {
	Arp(Arp),
	Udp(Udp4),
	/// An ICMP echo request; `l3` is the IPv4 header's offset.
	Echo { src: Ipv4Addr, dst: Ipv4Addr, l3: usize },
	/// A fragment of an IPv4 datagram (not reassembled: dropped).
	Fragment,
	/// Anything else (IPv6, VLAN tags, other protocols, ...).
	Other,
	/// Too short or inconsistent lengths / checksum.
	Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arp {
	pub op: u16,
	pub sender_mac: Mac,
	pub sender_ip: Ipv4Addr,
	pub target_ip: Ipv4Addr,
}

pub const ARP_REQUEST: u16 = 1;
pub const ARP_REPLY: u16 = 2;

/// A UDP datagram over IPv4 (not fragmented).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Udp4 {
	pub src_mac: Mac,
	pub src: SocketAddrV4,
	pub dst: SocketAddrV4,
	/// Offset of the IPv4 header.
	pub l3: usize,
	/// Offset of the UDP header.
	pub l4: usize,
	/// UDP payload bytes.
	pub payload: usize,
}

fn be16(b: &[u8], at: usize) -> u16 {
	u16::from_be_bytes([b[at], b[at + 1]])
}

fn ip_at(b: &[u8], at: usize) -> Ipv4Addr {
	Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

fn mac_at(b: &[u8], at: usize) -> Mac {
	let mut m = [0; 6];
	m.copy_from_slice(&b[at..at + 6]);
	m
}

/// Reads a frame. Never panics (fuzzed).
pub fn parse(f: &[u8]) -> Frame {
	if f.len() < ETH_HDR {
		return Frame::Malformed;
	}
	match be16(f, 12) {
		ETHERTYPE_ARP => parse_arp(f),
		ETHERTYPE_IPV4 => parse_ipv4(f),
		_ => Frame::Other,
	}
}

fn parse_arp(f: &[u8]) -> Frame {
	let a = ETH_HDR;
	if f.len() < a + ARP_LEN {
		return Frame::Malformed;
	}
	// Ethernet, IPv4, 6-byte and 4-byte addresses
	if be16(f, a) != 1 || be16(f, a + 2) != ETHERTYPE_IPV4 || f[a + 4] != 6 || f[a + 5] != 4 {
		return Frame::Other;
	}
	Frame::Arp(Arp { op: be16(f, a + 6), sender_mac: mac_at(f, a + 8), sender_ip: ip_at(f, a + 14), target_ip: ip_at(f, a + 24) })
}

fn parse_ipv4(f: &[u8]) -> Frame {
	let l3 = ETH_HDR;
	if f.len() < l3 + 20 {
		return Frame::Malformed;
	}
	let (version, ihl) = (f[l3] >> 4, usize::from(f[l3] & 0x0f) * 4);
	let total = usize::from(be16(f, l3 + 2));
	// frames may carry Ethernet padding after the datagram (total < what is left)
	if version != 4 || ihl < 20 || total < ihl || l3 + total > f.len() {
		return Frame::Malformed;
	}
	if checksum(&f[l3..l3 + ihl]) != 0 {
		return Frame::Malformed;
	}
	let frag = be16(f, l3 + 6);
	if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
		return Frame::Fragment;
	}
	let (src, dst) = (ip_at(f, l3 + 12), ip_at(f, l3 + 16));
	let l4 = l3 + ihl;
	match f[l3 + 9] {
		17 => {
			if total < ihl + 8 {
				return Frame::Malformed;
			}
			let len = usize::from(be16(f, l4 + 4));
			if len < 8 || len > total - ihl {
				return Frame::Malformed;
			}
			Frame::Udp(Udp4 {
				src_mac: mac_at(f, 6),
				src: SocketAddrV4::new(src, be16(f, l4)),
				dst: SocketAddrV4::new(dst, be16(f, l4 + 2)),
				l3,
				l4,
				payload: len - 8,
			})
		}
		1 if total >= ihl + 8 && f[l4] == 8 && f[l4 + 1] == 0 => Frame::Echo { src, dst, l3 },
		_ => Frame::Other,
	}
}

/// The ones' complement of the ones' complement sum of `data` (16-bit words,
/// an odd last byte padded with zero): 0 over a header with a valid checksum.
pub fn checksum(data: &[u8]) -> u16 {
	!fold(sum(data, 0))
}

fn sum(data: &[u8], mut acc: u32) -> u32 {
	let (words, rest) = data.as_chunks::<2>();
	for w in words {
		acc += u32::from(u16::from_be_bytes(*w));
	}
	if let [last] = rest {
		acc += u32::from(*last) << 8;
	}
	acc
}

fn fold(mut acc: u32) -> u16 {
	while acc > 0xffff {
		acc = (acc & 0xffff) + (acc >> 16);
	}
	acc as u16
}

/// RFC 1624 eqn. 3: the checksum `hc` after the 16-bit words `old` became `new`.
fn adjust(hc: u16, old: &[u8], new: &[u8]) -> u16 {
	let mut acc = u32::from(!hc);
	for w in old.as_chunks::<2>().0 {
		acc += u32::from(!u16::from_be_bytes(*w));
	}
	for w in new.as_chunks::<2>().0 {
		acc += u32::from(u16::from_be_bytes(*w));
	}
	!fold(acc)
}

/// The UDP checksum of the datagram at `u` from scratch (pseudo-header
/// included); 0 means "no checksum" on the wire, so a computed 0 is sent as 0xffff.
pub fn udp_checksum(f: &[u8], u: &Udp4) -> u16 {
	let len = u.payload + 8;
	let mut acc = sum(&f[u.l3 + 12..u.l3 + 20], 0);
	acc += 17 + len as u32;
	// the datagram with its checksum field taken as zero
	acc = sum(&f[u.l4..u.l4 + 6], acc);
	acc = sum(&f[u.l4 + 8..u.l4 + len], acc);
	match !fold(acc) {
		0 => 0xffff,
		c => c,
	}
}

/// Whether the IPv4 header and the UDP checksum (if any) of `u` are right.
pub fn checksums_ok(f: &[u8], u: &Udp4) -> bool {
	let ihl = u.l4 - u.l3;
	if checksum(&f[u.l3..u.l3 + ihl]) != 0 {
		return false;
	}
	let sent = be16(f, u.l4 + 6);
	sent == 0 || sent == udp_checksum(f, u)
}

fn set_ip_header(f: &mut [u8], l3: usize, ihl: usize, src: Ipv4Addr, dst: Ipv4Addr) {
	f[l3 + 8] = TTL;
	f[l3 + 12..l3 + 16].copy_from_slice(&src.octets());
	f[l3 + 16..l3 + 20].copy_from_slice(&dst.octets());
	f[l3 + 10..l3 + 12].copy_from_slice(&[0, 0]);
	let c = checksum(&f[l3..l3 + ihl]);
	f[l3 + 10..l3 + 12].copy_from_slice(&c.to_be_bytes());
}

/// Rewrites the datagram `u` (as parsed from `f`) in place to go from `src` to
/// `dst` in a frame from `src_mac` to `dst_mac`: addresses, ports, TTL, the
/// IPv4 header checksum, and the UDP checksum updated for the new addresses
/// and ports (RFC 1624; a datagram sent without one stays without one).
pub fn rewrite_udp(f: &mut [u8], u: &Udp4, src_mac: Mac, dst_mac: Mac, src: SocketAddrV4, dst: SocketAddrV4) {
	f[0..6].copy_from_slice(&dst_mac);
	f[6..12].copy_from_slice(&src_mac);
	let ihl = u.l4 - u.l3;
	let mut old = [0u8; 12];
	old[..8].copy_from_slice(&f[u.l3 + 12..u.l3 + 20]);
	old[8..].copy_from_slice(&f[u.l4..u.l4 + 4]);
	set_ip_header(f, u.l3, ihl, *src.ip(), *dst.ip());
	f[u.l4..u.l4 + 2].copy_from_slice(&src.port().to_be_bytes());
	f[u.l4 + 2..u.l4 + 4].copy_from_slice(&dst.port().to_be_bytes());
	let hc = be16(f, u.l4 + 6);
	if hc != 0 {
		let mut new = [0u8; 12];
		new[..8].copy_from_slice(&f[u.l3 + 12..u.l3 + 20]);
		new[8..].copy_from_slice(&f[u.l4..u.l4 + 4]);
		let c = match adjust(hc, &old, &new) {
			0 => 0xffff,
			c => c,
		};
		f[u.l4 + 6..u.l4 + 8].copy_from_slice(&c.to_be_bytes());
	}
}

/// Turns the ARP request in `f` into the reply from `mac` (in place).
pub fn arp_reply_in_place(f: &mut [u8], a: &Arp, mac: Mac) {
	let o = ETH_HDR;
	f[0..6].copy_from_slice(&a.sender_mac);
	f[6..12].copy_from_slice(&mac);
	f[o + 6..o + 8].copy_from_slice(&ARP_REPLY.to_be_bytes());
	f[o + 8..o + 14].copy_from_slice(&mac);
	f[o + 14..o + 18].copy_from_slice(&a.target_ip.octets());
	f[o + 18..o + 24].copy_from_slice(&a.sender_mac);
	f[o + 24..o + 28].copy_from_slice(&a.sender_ip.octets());
}

/// The length of the ARP frames `arp_frame` writes (padded to the Ethernet minimum).
pub const ARP_FRAME: usize = 60;

/// Writes an ARP frame (`op`) from `mac`/`ip` to `to_mac`/`to_ip` into `f`
/// (at least `ARP_FRAME` bytes); a request goes to the broadcast address.
pub fn arp_frame(f: &mut [u8], op: u16, mac: Mac, ip: Ipv4Addr, to_mac: Mac, to_ip: Ipv4Addr) {
	let f = &mut f[..ARP_FRAME];
	f.fill(0);
	f[0..6].copy_from_slice(if op == ARP_REQUEST { &BROADCAST } else { &to_mac });
	f[6..12].copy_from_slice(&mac);
	f[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
	let o = ETH_HDR;
	f[o..o + 2].copy_from_slice(&1u16.to_be_bytes());
	f[o + 2..o + 4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
	f[o + 4] = 6;
	f[o + 5] = 4;
	f[o + 6..o + 8].copy_from_slice(&op.to_be_bytes());
	f[o + 8..o + 14].copy_from_slice(&mac);
	f[o + 14..o + 18].copy_from_slice(&ip.octets());
	if op != ARP_REQUEST {
		f[o + 18..o + 24].copy_from_slice(&to_mac);
	}
	f[o + 24..o + 28].copy_from_slice(&to_ip.octets());
}

/// Turns the ICMP echo request at `l3` into its reply from `mac` (in place).
pub fn echo_reply_in_place(f: &mut [u8], l3: usize, src: Ipv4Addr, dst: Ipv4Addr, mac: Mac) {
	let peer = mac_at(f, 6);
	f[0..6].copy_from_slice(&peer);
	f[6..12].copy_from_slice(&mac);
	let ihl = usize::from(f[l3] & 0x0f) * 4;
	set_ip_header(f, l3, ihl, dst, src);
	let l4 = l3 + ihl;
	let hc = be16(f, l4 + 2);
	f[l4] = 0;
	let c = adjust(hc, &[8, 0], &[0, 0]);
	f[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
}

/// Builds an Ethernet + IPv4 + UDP frame (tests, the startup check).
pub fn udp_frame(src_mac: Mac, dst_mac: Mac, src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8], with_checksum: bool) -> Vec<u8> {
	let total = 20 + 8 + payload.len();
	let mut f = vec![0u8; ETH_HDR + total];
	f[0..6].copy_from_slice(&dst_mac);
	f[6..12].copy_from_slice(&src_mac);
	f[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
	let l3 = ETH_HDR;
	f[l3] = 0x45;
	f[l3 + 2..l3 + 4].copy_from_slice(&(total as u16).to_be_bytes());
	f[l3 + 6] = 0x40; // DF
	f[l3 + 9] = 17;
	set_ip_header(&mut f, l3, 20, *src.ip(), *dst.ip());
	let l4 = l3 + 20;
	f[l4..l4 + 2].copy_from_slice(&src.port().to_be_bytes());
	f[l4 + 2..l4 + 4].copy_from_slice(&dst.port().to_be_bytes());
	f[l4 + 4..l4 + 6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
	f[l4 + 8..].copy_from_slice(payload);
	if with_checksum {
		let u = Udp4 { src_mac, src, dst, l3, l4, payload: payload.len() };
		let c = udp_checksum(&f, &u);
		f[l4 + 6..l4 + 8].copy_from_slice(&c.to_be_bytes());
	}
	f
}

/// The payload of the datagram `u` in `f`.
pub fn payload<'a>(f: &'a [u8], u: &Udp4) -> &'a [u8] {
	&f[u.l4 + 8..u.l4 + 8 + u.payload]
}

#[cfg(test)]
mod tests {
	use super::*;

	const A: Mac = [2, 0, 0, 0, 0, 1];
	const B: Mac = [2, 0, 0, 0, 0, 2];

	fn sa(s: &str) -> SocketAddrV4 {
		s.parse().unwrap()
	}

	#[test]
	fn udp_round_trip_and_rewrite_keep_checksums_right() {
		for len in [0usize, 1, 2, 17, 64, 1472] {
			let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
			for with in [true, false] {
				let mut f = udp_frame(A, B, sa("10.0.0.1:40000"), sa("10.0.0.2:53"), &data, with);
				let Frame::Udp(u) = parse(&f) else { panic!("{:?}", parse(&f)) };
				assert_eq!((u.src, u.dst, u.payload, u.src_mac), (sa("10.0.0.1:40000"), sa("10.0.0.2:53"), len, A));
				assert!(checksums_ok(&f, &u));
				rewrite_udp(&mut f, &u, B, A, sa("10.0.0.2:33000"), sa("192.168.7.9:5353"));
				let Frame::Udp(v) = parse(&f) else { panic!() };
				assert_eq!((v.src, v.dst, v.src_mac), (sa("10.0.0.2:33000"), sa("192.168.7.9:5353"), B));
				assert_eq!(&f[0..6], &A);
				assert_eq!(payload(&f, &v), &data[..]);
				assert!(checksums_ok(&f, &v), "len {len} with {with}");
				let sent = be16(&f, v.l4 + 6);
				assert_eq!(sent == 0, !with, "a datagram without a checksum stays without one");
				if with {
					assert_eq!(sent, udp_checksum(&f, &v), "incremental = from scratch");
				}
			}
		}
	}

	#[test]
	fn fragments_padding_and_bad_headers() {
		let mut f = udp_frame(A, B, sa("10.0.0.1:1"), sa("10.0.0.2:2"), b"hi", true);
		// Ethernet padding after the datagram is fine
		let mut padded = f.clone();
		padded.resize(60, 0);
		assert!(matches!(parse(&padded), Frame::Udp(u) if u.payload == 2));
		// a broken header checksum
		f[ETH_HDR + 8] ^= 1;
		assert_eq!(parse(&f), Frame::Malformed);
		f[ETH_HDR + 8] ^= 1;
		// more fragments / an offset
		let mut frag = f.clone();
		frag[ETH_HDR + 6] = 0x20;
		set_ip_header(&mut frag, ETH_HDR, 20, "10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
		assert_eq!(parse(&frag), Frame::Fragment);
		// truncated
		assert_eq!(parse(&f[..f.len() - 1]), Frame::Malformed);
		assert_eq!(parse(&f[..10]), Frame::Malformed);
		// a UDP length beyond the datagram
		let mut long = f.clone();
		long[ETH_HDR + 20 + 4] = 0xff;
		assert_eq!(parse(&long), Frame::Malformed);
		// IPv6 and VLAN tags are not handled
		let mut v6 = f.clone();
		v6[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
		assert_eq!(parse(&v6), Frame::Other);
	}

	#[test]
	fn arp_and_echo_replies() {
		let mut f = [0u8; ARP_FRAME];
		arp_frame(&mut f, ARP_REQUEST, A, "10.0.0.1".parse().unwrap(), [0; 6], "10.0.0.2".parse().unwrap());
		let Frame::Arp(a) = parse(&f) else { panic!() };
		assert_eq!((a.op, a.sender_mac, a.target_ip), (ARP_REQUEST, A, "10.0.0.2".parse().unwrap()));
		assert_eq!(&f[0..6], &BROADCAST);
		arp_reply_in_place(&mut f, &a, B);
		let Frame::Arp(r) = parse(&f) else { panic!() };
		assert_eq!((r.op, r.sender_mac, r.sender_ip, r.target_ip), (ARP_REPLY, B, a.target_ip, a.sender_ip));
		assert_eq!(&f[0..6], &A);

		// an echo request: built from a UDP frame with the protocol and ICMP header changed
		let mut e = udp_frame(A, B, sa("10.0.0.1:0"), sa("10.0.0.2:0"), b"pingdata", false);
		e[ETH_HDR + 9] = 1;
		let l4 = ETH_HDR + 20;
		e[l4..l4 + 8].copy_from_slice(&[8, 0, 0, 0, 0, 1, 0, 1]);
		let c = checksum(&e[l4..]);
		e[l4 + 2..l4 + 4].copy_from_slice(&c.to_be_bytes());
		set_ip_header(&mut e, ETH_HDR, 20, "10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap());
		let Frame::Echo { src, dst, l3 } = parse(&e) else { panic!("{:?}", parse(&e)) };
		echo_reply_in_place(&mut e, l3, src, dst, B);
		assert_eq!(e[l4], 0);
		assert_eq!(checksum(&e[l4..]), 0, "ICMP checksum");
		assert_eq!(checksum(&e[ETH_HDR..l4]), 0, "IPv4 checksum");
		assert_eq!(ip_at(&e, ETH_HDR + 12), dst);
		assert_eq!((&e[0..6], &e[6..12]), (&A[..], &B[..]));
	}
}
