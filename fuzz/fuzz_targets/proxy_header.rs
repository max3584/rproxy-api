//! PROXY protocol v1 / v2 headers (`net::source`). rproxy only writes them (it
//! never reads PROXY headers from its clients), so this target checks the
//! writer: for any addresses and TLS details, the header is well formed and
//! reads back to what was put in (decoded here independently, after the spec at
//! haproxy.org/download/2.9/doc/proxy-protocol.txt).
#![no_main]

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use libfuzzer_sys::arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use rproxy_api::net::source::{proxy_v1_header, proxy_v2_dgram_header, proxy_v2_header, proxy_v2_header_with, TlsInfo};

const SIGNATURE: [u8; 12] = [0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a];

/// A string of at most `max` bytes, or none.
fn text(u: &mut Unstructured, max: usize) -> Result<Option<String>> {
	let s: Option<String> = u.arbitrary()?;
	Ok(s.map(|s| {
		let mut end = s.len().min(max);
		while !s.is_char_boundary(end) {
			end -= 1;
		}
		s[..end].to_string()
	}))
}

fn to_v6(ip: IpAddr) -> Ipv6Addr {
	match ip {
		IpAddr::V4(v4) => v4.to_ipv6_mapped(),
		IpAddr::V6(v6) => v6,
	}
}

fn check_v1(h: &[u8], src: SocketAddr, dst: SocketAddr) {
	assert!(h.len() <= 107, "a v1 header is at most 107 bytes");
	let line = std::str::from_utf8(h).expect("v1 is text");
	let line = line.strip_suffix("\r\n").expect("ends with CRLF");
	let f: Vec<&str> = line.split(' ').collect();
	assert_eq!(f.len(), 6);
	assert_eq!(f[0], "PROXY");
	let (s, d): (IpAddr, IpAddr) = (f[2].parse().unwrap(), f[3].parse().unwrap());
	match (src.ip(), dst.ip()) {
		(IpAddr::V4(_), IpAddr::V4(_)) => {
			assert_eq!(f[1], "TCP4");
			assert_eq!((s, d), (src.ip(), dst.ip()));
		}
		_ => {
			assert_eq!(f[1], "TCP6");
			assert_eq!((s, d), (IpAddr::V6(to_v6(src.ip())), IpAddr::V6(to_v6(dst.ip()))));
		}
	}
	assert_eq!(f[4].parse::<u16>().unwrap(), src.port());
	assert_eq!(f[5].parse::<u16>().unwrap(), dst.port());
}

/// Type-length-value entries; every byte must belong to one.
fn tlvs(mut p: &[u8]) -> Vec<(u8, &[u8])> {
	let mut out = vec![];
	while !p.is_empty() {
		assert!(p.len() >= 3, "a TLV header is cut short");
		let n = usize::from(u16::from_be_bytes([p[1], p[2]]));
		assert!(p.len() >= 3 + n, "a TLV runs past the header");
		out.push((p[0], &p[3..3 + n]));
		p = &p[3 + n..];
	}
	out
}

fn check_v2(h: &[u8], src: SocketAddr, dst: SocketAddr, tls: Option<&TlsInfo>, dgram: bool) {
	assert!(h.len() >= 16);
	assert_eq!(h[..12], SIGNATURE);
	assert_eq!(h[12], 0x21, "version 2, PROXY");
	assert_eq!(h[13] & 0x0f, if dgram { 0x02 } else { 0x01 });
	let len = usize::from(u16::from_be_bytes([h[14], h[15]]));
	assert_eq!(h.len(), 16 + len, "the length field covers the rest");
	let body = &h[16..];
	let rest = match (src.ip(), dst.ip()) {
		(IpAddr::V4(s), IpAddr::V4(d)) => {
			assert_eq!(h[13] >> 4, 1, "AF_INET");
			assert_eq!(body[..4], s.octets());
			assert_eq!(body[4..8], d.octets());
			assert_eq!(body[8..10], src.port().to_be_bytes());
			assert_eq!(body[10..12], dst.port().to_be_bytes());
			&body[12..]
		}
		_ => {
			assert_eq!(h[13] >> 4, 2, "AF_INET6");
			assert_eq!(body[..16], to_v6(src.ip()).octets());
			assert_eq!(body[16..32], to_v6(dst.ip()).octets());
			assert_eq!(body[32..34], src.port().to_be_bytes());
			assert_eq!(body[34..36], dst.port().to_be_bytes());
			&body[36..]
		}
	};
	let entries = tlvs(rest);
	let Some(info) = tls else {
		assert!(entries.is_empty(), "no TLVs without TLS");
		return;
	};
	let find = |kind: u8| entries.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v);
	assert_eq!(find(0x01), info.alpn.as_deref().map(str::as_bytes), "PP2_TYPE_ALPN");
	assert_eq!(find(0x02), info.server_name.as_deref().map(str::as_bytes), "PP2_TYPE_AUTHORITY");
	let ssl = find(0x20).expect("PP2_TYPE_SSL");
	assert!(ssl.len() >= 5);
	assert_eq!(ssl[0], 0x01 | if info.client_cert { 0x02 } else { 0 }, "PP2_CLIENT_SSL / CERT_CONN");
	// 1 only for a certificate that did not verify (client_auth optional_no_verify, #238)
	let verify = u32::from(info.client_cert && !info.client_verified);
	assert_eq!(ssl[1..5], verify.to_be_bytes(), "verify");
	let sub = tlvs(&ssl[5..]);
	let find = |kind: u8| sub.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v);
	assert_eq!(find(0x21), info.version.as_deref().map(str::as_bytes), "PP2_SUBTYPE_SSL_VERSION");
	assert_eq!(find(0x22), info.client_cn.as_deref().map(str::as_bytes), "PP2_SUBTYPE_SSL_CN");
}

fn run(u: &mut Unstructured) -> Result<()> {
	let src: SocketAddr = u.arbitrary()?;
	let dst: SocketAddr = u.arbitrary()?;
	// as long as they can be: a DNS name, ALPN protocol ids, a TLS version name,
	// and a certificate's common name (RFC 5280: 64 characters, 4 bytes each)
	let info = TlsInfo {
		server_name: text(u, 255)?,
		alpn: text(u, 255)?,
		version: text(u, 32)?,
		cipher: text(u, 64)?,
		client_cn: text(u, 256)?,
		client_cert: u.arbitrary()?,
		client_verified: u.arbitrary()?,
		..Default::default()
	};
	check_v1(&proxy_v1_header(src, dst), src, dst);
	check_v2(&proxy_v2_header(src, dst), src, dst, None, false);
	check_v2(&proxy_v2_header_with(src, dst, Some(&info)), src, dst, Some(&info), false);
	check_v2(&proxy_v2_dgram_header(src, dst), src, dst, None, true);
	Ok(())
}

fuzz_target!(|data: &[u8]| {
	let _ = run(&mut Unstructured::new(data));
});
