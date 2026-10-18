//! Receiving PROXY protocol v1 / v2 headers (#296): a load balancer (or another
//! rproxy, or a Kubernetes Gateway) in front puts the client's address in front of
//! the connection, and rproxy uses it as the client's from then on.
//!
//! Only peers listed in the rule's `proxy_protocol.from` (the TCP peer, the hop
//! right in front) are believed. From them a header is read before anything else
//! (with `required`, the default, a connection without one is refused); from any
//! other peer nothing is read, and a connection that starts like a header is
//! refused (`untrusted_start`), so a front end missing from `from` shows up in the
//! logs instead of its header reaching the backend as data.
//!
//! The parser (`parse`) follows haproxy.org/download/2.9/doc/proxy-protocol.txt and
//! reads at most `V1_MAX` bytes of a v1 header and `V2_MAX` of a v2 one (TLVs
//! included); TLVs are skipped (towards a backend rproxy writes what it saw itself).
//! The header must arrive within `HEADER_TIMEOUT`.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::core::rule::Protocol;
use crate::error::ApiError;
use crate::net::cidr::{Cidr, MAX_ALLOW_FROM};

const V2_SIGNATURE: [u8; 12] = [0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a];
const V1_PREFIX: &[u8; 6] = b"PROXY ";

/// The longest v1 header, CRLF included (the spec's limit).
pub const V1_MAX: usize = 107;
/// The longest address block of a v2 header, TLVs included (its 16-bit length field
/// could say 65535). Addresses take at most 216 bytes (AF_UNIX); what front ends add
/// as TLVs (AWS's VPC endpoint id, GCP's PSC id, HAProxy's SSL details, a unique id)
/// is far below this.
pub const V2_MAX_PAYLOAD: usize = 4096;
/// The longest v2 header: the 16 fixed bytes and `V2_MAX_PAYLOAD`.
pub const V2_MAX: usize = 16 + V2_MAX_PAYLOAD;
/// How long a peer in `from` may take to send the whole header, from the moment the
/// connection is accepted (a slow sender does not get to hold a connection open).
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// `proxy_protocol` of a rule as given (API, settings file, database). `{}` means
/// none (how PATCH removes it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyProtocolSpec {
	/// The peers whose headers are believed (CIDR or single IP); required, not empty.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub from: Option<Vec<String>>,
	/// Refuse a connection from `from` without a header (default true).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub required: Option<bool>,
}

impl ProxyProtocolSpec {
	pub fn is_empty(&self) -> bool {
		self.from.is_none() && self.required.is_none()
	}
}

/// A validated `proxy_protocol`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyProtocol {
	pub from: Vec<Cidr>,
	pub required: bool,
}

impl ProxyProtocol {
	/// Whether headers from this peer (the TCP peer address) are believed.
	pub fn trusts(&self, peer: IpAddr) -> bool {
		self.from.iter().any(|c| c.contains(peer))
	}

	/// As the rule view (and `rproxy_rules`) shows it.
	pub fn view(&self) -> ProxyProtocolSpec {
		ProxyProtocolSpec { from: Some(self.from.iter().map(|c| c.to_string()).collect()), required: Some(self.required) }
	}
}

/// `proxy_protocol` of a rule: tcp only (PROXY v2 over UDP is for later), `from`
/// not empty and no `/0` (rproxy never believes headers from just anyone).
pub fn validate(spec: Option<ProxyProtocolSpec>, protocol: Protocol) -> Result<Option<ProxyProtocol>, ApiError> {
	let Some(spec) = spec.filter(|s| !s.is_empty()) else { return Ok(None) };
	if protocol != Protocol::Tcp {
		return Err(ApiError::unsupported("proxy_protocol is for tcp rules (PROXY headers over udp are not read)"));
	}
	let list = spec.from.unwrap_or_default();
	if list.is_empty() {
		return Err(ApiError::invalid(
			"proxy_protocol.from must list the front ends whose headers are believed (rproxy does not believe headers from everyone)",
		));
	}
	if list.len() > MAX_ALLOW_FROM {
		return Err(ApiError::invalid(format!("proxy_protocol.from may hold at most {MAX_ALLOW_FROM} entries")));
	}
	let mut from = Vec::with_capacity(list.len());
	for s in &list {
		let c: Cidr = s.parse().map_err(|_| ApiError::invalid(format!("proxy_protocol.from: not an address or CIDR: {s}")))?;
		if c.prefix() == 0 {
			return Err(ApiError::invalid(format!(
				"proxy_protocol.from: {s} would believe headers from everyone; list the front ends' addresses"
			)));
		}
		from.push(c);
	}
	Ok(Some(ProxyProtocol { from, required: spec.required.unwrap_or(true) }))
}

/// Which version a connection's first bytes are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
	V1,
	V2,
}

impl Version {
	pub fn as_str(self) -> &'static str {
		match self {
			Version::V1 => "v1",
			Version::V2 => "v2",
		}
	}
}

/// What the first bytes of a connection look like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
	/// Too few bytes to tell (all of them could still begin a header).
	More,
	/// Not a PROXY header.
	Plain,
	/// The v2 signature or `PROXY ` (the header itself may still be incomplete or wrong).
	Header(Version),
}

/// Tells a PROXY header from anything else by its first bytes: the 12-byte v2
/// signature or `PROXY `.
pub fn classify(buf: &[u8]) -> Start {
	if buf.is_empty() {
		return Start::More;
	}
	let n = buf.len().min(V2_SIGNATURE.len());
	if buf[..n] == V2_SIGNATURE[..n] {
		return if n == V2_SIGNATURE.len() { Start::Header(Version::V2) } else { Start::More };
	}
	let n = buf.len().min(V1_PREFIX.len());
	if buf[..n] == V1_PREFIX[..n] {
		return if n == V1_PREFIX.len() { Start::Header(Version::V1) } else { Start::More };
	}
	Start::Plain
}

/// A complete header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
	pub version: Version,
	/// Its length in bytes (what to consume from the connection).
	pub len: usize,
	/// The client's address and the address it connected to; none for a v2 LOCAL
	/// command (the front end's own health check), `UNKNOWN` (v1), and the UNSPEC and
	/// AF_UNIX families: the peer's address stands.
	pub addrs: Option<(SocketAddr, SocketAddr)>,
}

/// What `parse` found at the start of a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parsed {
	/// The header is not complete yet.
	More,
	/// The bytes do not start with a PROXY header.
	NotHeader,
	Header(Header),
	/// It starts like a header but is not a valid one (or is too long).
	Invalid(&'static str),
}

/// Reads a PROXY header (v1 or v2) at the start of `buf`. Bytes after the header are
/// not looked at.
pub fn parse(buf: &[u8]) -> Parsed {
	match classify(buf) {
		Start::More => Parsed::More,
		Start::Plain => Parsed::NotHeader,
		Start::Header(Version::V1) => parse_v1(buf),
		Start::Header(Version::V2) => parse_v2(buf),
	}
}

fn parse_v1(buf: &[u8]) -> Parsed {
	let window = &buf[..buf.len().min(V1_MAX)];
	let Some(end) = window.windows(2).position(|w| w == b"\r\n") else {
		return if buf.len() >= V1_MAX { Parsed::Invalid("v1 header longer than 107 bytes") } else { Parsed::More };
	};
	let len = end + 2;
	let Ok(line) = std::str::from_utf8(&buf[..end]) else { return Parsed::Invalid("v1 header is not text") };
	let mut fields = line.split(' ');
	let _proxy = fields.next();
	let header = |addrs| Parsed::Header(Header { version: Version::V1, len, addrs });
	match fields.next() {
		// the spec: whatever follows UNKNOWN is ignored
		Some("UNKNOWN") => header(None),
		Some(proto @ ("TCP4" | "TCP6")) => {
			let f: Vec<&str> = fields.collect();
			let [src, dst, sport, dport] = f.as_slice() else { return Parsed::Invalid("v1 header needs 2 addresses and 2 ports") };
			let (Some(sport), Some(dport)) = (port(sport), port(dport)) else { return Parsed::Invalid("v1 header has a bad port") };
			let ips = if proto == "TCP4" {
				src.parse::<Ipv4Addr>().ok().zip(dst.parse::<Ipv4Addr>().ok()).map(|(s, d)| (IpAddr::V4(s), IpAddr::V4(d)))
			} else {
				src.parse::<Ipv6Addr>().ok().zip(dst.parse::<Ipv6Addr>().ok()).map(|(s, d)| (IpAddr::V6(s), IpAddr::V6(d)))
			};
			match ips {
				Some((s, d)) => header(Some((SocketAddr::new(s, sport), SocketAddr::new(d, dport)))),
				None => Parsed::Invalid("v1 header has a bad address"),
			}
		}
		_ => Parsed::Invalid("v1 header has an unknown protocol (TCP4, TCP6 or UNKNOWN)"),
	}
}

/// A v1 port: 0-65535 in decimal, digits only, no leading zero.
fn port(s: &str) -> Option<u16> {
	if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
		return None;
	}
	s.parse().ok()
}

fn parse_v2(buf: &[u8]) -> Parsed {
	if buf.len() < 16 {
		return Parsed::More;
	}
	if buf[12] >> 4 != 2 {
		return Parsed::Invalid("v2 header has an unknown version");
	}
	let local = match buf[12] & 0x0f {
		0x0 => true,
		0x1 => false,
		_ => return Parsed::Invalid("v2 header has an unknown command"),
	};
	let (family, transport) = (buf[13] >> 4, buf[13] & 0x0f);
	let payload = usize::from(u16::from_be_bytes([buf[14], buf[15]]));
	if payload > V2_MAX_PAYLOAD {
		return Parsed::Invalid("v2 header longer than 4096 bytes after the fixed part");
	}
	let len = 16 + payload;
	if buf.len() < len {
		return Parsed::More;
	}
	let body = &buf[16..len];
	let header = |addrs| Parsed::Header(Header { version: Version::V2, len, addrs });
	if family > 3 || transport > 2 {
		return Parsed::Invalid("v2 header has an unknown address family or transport");
	}
	// LOCAL: the front end's own connection (a health check); the addresses are ignored
	if local {
		return header(None);
	}
	if transport == 2 {
		return Parsed::Invalid("v2 header of a datagram (UDP) on a TCP connection");
	}
	match family {
		// AF_UNSPEC, AF_UNIX, or an unspecified transport: nothing rproxy can use
		_ if transport == 0 => header(None),
		0 | 3 => header(None),
		1 => {
			if body.len() < 12 {
				return Parsed::Invalid("v2 header too short for IPv4 addresses");
			}
			let ip = |o: usize| IpAddr::V4(Ipv4Addr::new(body[o], body[o + 1], body[o + 2], body[o + 3]));
			let port = |o: usize| u16::from_be_bytes([body[o], body[o + 1]]);
			header(Some((SocketAddr::new(ip(0), port(8)), SocketAddr::new(ip(4), port(10)))))
		}
		_ => {
			if body.len() < 36 {
				return Parsed::Invalid("v2 header too short for IPv6 addresses");
			}
			let ip = |o: usize| {
				let mut b = [0u8; 16];
				b.copy_from_slice(&body[o..o + 16]);
				IpAddr::V6(Ipv6Addr::from(b))
			};
			let port = |o: usize| u16::from_be_bytes([body[o], body[o + 1]]);
			header(Some((SocketAddr::new(ip(0), port(32)), SocketAddr::new(ip(16), port(34)))))
		}
	}
}

fn refused(kind: io::ErrorKind, why: impl Into<String>) -> io::Error {
	io::Error::new(kind, why.into())
}

/// Waits until `decide` can tell from the bytes waiting on `stream` (looked at, not
/// consumed), or the peer closes. A header split over several segments is looked at
/// again as more arrives.
async fn peek_until<T>(stream: &TcpStream, buf: &mut [u8], decide: impl Fn(&[u8]) -> Option<T>) -> io::Result<(T, usize)> {
	let mut seen = 0;
	let mut pause = Duration::from_millis(1);
	loop {
		let n = stream.peek(buf).await?;
		if n == 0 {
			return Err(refused(io::ErrorKind::UnexpectedEof, "closed before sending a PROXY header"));
		}
		if let Some(t) = decide(&buf[..n]) {
			return Ok((t, n));
		}
		// the same bytes as last time: wait for more instead of spinning on them
		if n == seen {
			tokio::time::sleep(pause).await;
			pause = (pause * 2).min(Duration::from_millis(50));
		} else {
			seen = n;
			pause = Duration::from_millis(1);
		}
	}
}

/// Reads the PROXY header of a connection from a peer in `from`, consuming exactly
/// the header. Ok(Some(client)) with the client's address; Ok(None) when the peer's
/// address stands (LOCAL, UNKNOWN / UNSPEC, or no header while `required` is off).
/// Errors are reasons to refuse the connection.
pub async fn read(stream: &mut TcpStream, required: bool) -> io::Result<Option<SocketAddr>> {
	read_within(stream, required, HEADER_TIMEOUT).await
}

async fn read_within(stream: &mut TcpStream, required: bool, limit: Duration) -> io::Result<Option<SocketAddr>> {
	let mut buf = vec![0u8; V2_MAX];
	let got_any = std::sync::atomic::AtomicBool::new(false);
	let peeked = tokio::time::timeout(limit, async {
		peek_until(stream, &mut buf, |b| {
			got_any.store(true, std::sync::atomic::Ordering::Relaxed);
			match parse(b) {
				Parsed::More => None,
				other => Some(other),
			}
		})
		.await
	})
	.await;
	let parsed = match peeked {
		Ok(r) => r?.0,
		// a peer that sends nothing first (a server-first protocol) without `required`
		Err(_) if !required && !got_any.load(std::sync::atomic::Ordering::Relaxed) => return Ok(None),
		Err(_) => return Err(refused(io::ErrorKind::TimedOut, format!("no complete PROXY header within {limit:?}"))),
	};
	match parsed {
		Parsed::Header(h) => {
			stream.read_exact(&mut buf[..h.len]).await?;
			Ok(h.addrs.map(|(src, _)| src))
		}
		Parsed::NotHeader if !required => Ok(None),
		Parsed::NotHeader => Err(refused(io::ErrorKind::InvalidData, "no PROXY header (proxy_protocol.required)")),
		Parsed::Invalid(why) => Err(refused(io::ErrorKind::InvalidData, why)),
		Parsed::More => Err(refused(io::ErrorKind::InvalidData, "incomplete PROXY header")),
	}
}

/// Whether a connection from a peer outside `from` starts like a PROXY header (it is
/// then refused). With `wait` (protocols where the client speaks first) the first
/// bytes are waited for, up to `HEADER_TIMEOUT`; without it (plain TCP and STARTTLS,
/// where the server may speak first) only bytes that have already arrived are looked at.
pub async fn untrusted_start(stream: &TcpStream, wait: bool) -> Option<Version> {
	let mut buf = [0u8; V2_SIGNATURE.len()];
	let start = if wait {
		let peeked =
			tokio::time::timeout(HEADER_TIMEOUT, peek_until(stream, &mut buf, |b| Some(classify(b)).filter(|s| *s != Start::More)));
		match peeked.await {
			Ok(Ok((s, _))) => s,
			_ => return None,
		}
	} else {
		let mut rb = tokio::io::ReadBuf::new(&mut buf);
		let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
		match stream.poll_peek(&mut cx, &mut rb) {
			std::task::Poll::Ready(Ok(_)) => classify(rb.filled()),
			_ => return None,
		}
	};
	match start {
		Start::Header(v) => Some(v),
		_ => None,
	}
}

tokio::task_local! {
	/// The peer that sent the PROXY header of the connection being handled (the front
	/// end), for the `proxy_peer` field of its log lines. Set by `l4::tcp`.
	static PROXY_PEER: Option<SocketAddr>;
}

/// Runs a connection's handling with `peer` as the `proxy_peer` of its log lines.
pub fn with_peer<F: std::future::Future>(peer: Option<SocketAddr>, f: F) -> impl std::future::Future<Output = F::Output> {
	PROXY_PEER.scope(peer, f)
}

/// The front end that sent the current connection's PROXY header, if any.
pub fn current_peer() -> Option<SocketAddr> {
	PROXY_PEER.try_with(|p| *p).ok().flatten()
}

/// `proxy_peer` for a log line: left out when the connection came without a header.
pub fn peer_field() -> Option<tracing::field::DisplayValue<SocketAddr>> {
	current_peer().map(tracing::field::display)
}

/// Shared form kept in `Runtime` (PATCH replaces it for the next connection).
pub type Shared = Option<Arc<ProxyProtocol>>;

#[cfg(test)]
mod tests {
	use super::*;
	use crate::net::source::{proxy_v1_header, proxy_v2_header, proxy_v2_header_with, TlsInfo};

	fn sa(s: &str) -> SocketAddr {
		s.parse().unwrap()
	}

	fn header(buf: &[u8]) -> Header {
		match parse(buf) {
			Parsed::Header(h) => h,
			other => panic!("{other:?}"),
		}
	}

	#[test]
	fn reads_back_what_rproxy_writes() {
		for (src, dst) in [("192.0.2.1:5000", "198.51.100.1:80"), ("[2001:db8::1]:1", "[2001:db8::2]:65535")] {
			let (src, dst) = (sa(src), sa(dst));
			let v1 = proxy_v1_header(src, dst);
			let h = header(&[v1.as_slice(), b"GET / HTTP/1.1\r\n"].concat());
			assert_eq!((h.version, h.len, h.addrs), (Version::V1, v1.len(), Some((src, dst))));
			let v2 = proxy_v2_header(src, dst);
			let h = header(&[v2.as_slice(), b"\x16\x03\x01"].concat());
			assert_eq!((h.version, h.len, h.addrs), (Version::V2, v2.len(), Some((src, dst))));
		}
		// TLVs are skipped
		let info = TlsInfo { server_name: Some("mail.example".into()), version: Some("TLSv1_3".into()), ..Default::default() };
		let v2 = proxy_v2_header_with(sa("192.0.2.1:1"), sa("192.0.2.2:2"), Some(&info));
		assert!(v2.len() > 28);
		assert_eq!(header(&v2).len, v2.len());
		assert_eq!(header(&v2).addrs.unwrap().0, sa("192.0.2.1:1"));
	}

	#[test]
	fn every_prefix_asks_for_more() {
		let v1 = proxy_v1_header(sa("192.0.2.1:5000"), sa("198.51.100.1:80"));
		let v2 = proxy_v2_header(sa("[2001:db8::1]:1"), sa("[2001:db8::2]:2"));
		for full in [v1, v2] {
			for n in 0..full.len() {
				assert_eq!(parse(&full[..n]), Parsed::More, "{n} of {} bytes", full.len());
			}
		}
	}

	#[test]
	fn other_protocols_are_not_headers() {
		for start in [&b"GET / HTTP/1.1\r\n"[..], b"\x16\x03\x01\x02\x00", b"SSH-2.0-x\r\n", b"PROXZ", b"\r\n\r\n\0\r\nQUIZ", b"proxy "] {
			assert_eq!(parse(start), Parsed::NotHeader, "{start:?}");
			assert_eq!(classify(start), Start::Plain);
		}
		assert_eq!(classify(b"PRO"), Start::More);
		assert_eq!(classify(b"PROXY TCP4"), Start::Header(Version::V1));
		assert_eq!(classify(&V2_SIGNATURE), Start::Header(Version::V2));
	}

	#[test]
	fn v1_unknown_and_bad_lines() {
		let h = header(b"PROXY UNKNOWN ffff::1 ffff::2 1 2\r\nrest");
		assert_eq!((h.len, h.addrs), (35, None));
		assert_eq!(header(b"PROXY UNKNOWN\r\n").addrs, None);
		for bad in [
			&b"PROXY TCP4 192.0.2.1 192.0.2.2 1\r\n"[..],
			b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2 3\r\n",
			b"PROXY TCP4 2001:db8::1 192.0.2.2 1 2\r\n",
			b"PROXY TCP6 192.0.2.1 2001:db8::2 1 2\r\n",
			b"PROXY TCP4 192.0.2.1 192.0.2.2 65536 2\r\n",
			b"PROXY TCP4 192.0.2.1 192.0.2.2 +1 2\r\n",
			b"PROXY TCP4 192.0.2.1 192.0.2.2 01 2\r\n",
			b"PROXY TCP4 192.0.2.1  192.0.2.2 1 2\r\n",
			b"PROXY UDP4 192.0.2.1 192.0.2.2 1 2\r\n",
			b"PROXY TCP4 192.0.2.1 192.0.2.2 1 2\n\r\n",
			b"PROXY \xff\r\n",
		] {
			assert!(matches!(parse(bad), Parsed::Invalid(_)), "{:?}: {:?}", String::from_utf8_lossy(bad), parse(bad));
		}
		// no CRLF within 107 bytes
		let long = [b"PROXY TCP6 ".as_slice(), &[b'f'; 120]].concat();
		assert!(matches!(parse(&long), Parsed::Invalid(_)));
		assert_eq!(parse(&long[..106]), Parsed::More);
		// the longest valid line is 107 bytes
		let max = format!("PROXY UNKNOWN {0} {0} 65535 65535\r\n", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
		assert_eq!(max.len(), V1_MAX);
		assert_eq!(header(max.as_bytes()).len, V1_MAX);
	}

	fn v2(cmd: u8, fam: u8, body: &[u8]) -> Vec<u8> {
		let mut out = V2_SIGNATURE.to_vec();
		out.extend_from_slice(&[cmd, fam]);
		out.extend_from_slice(&(body.len() as u16).to_be_bytes());
		out.extend_from_slice(body);
		out
	}

	#[test]
	fn v2_local_unspec_and_limits() {
		// LOCAL (a health check): the addresses are ignored
		assert_eq!(header(&v2(0x20, 0x11, &[0; 12])).addrs, None);
		assert_eq!(header(&v2(0x20, 0x00, &[])).addrs, None);
		// UNSPEC family, AF_UNIX, unspecified transport
		assert_eq!(header(&v2(0x21, 0x00, &[])).addrs, None);
		assert_eq!(header(&v2(0x21, 0x31, &[0; 216])).addrs, None);
		assert_eq!(header(&v2(0x21, 0x10, &[0; 12])).addrs, None);
		// TLVs after the addresses are skipped
		let mut body = vec![192, 0, 2, 7, 192, 0, 2, 8, 0x13, 0x88, 0, 80];
		body.extend_from_slice(&[0x01, 0, 2, b'h', b'2', 0x05, 0, 3, 1, 2, 3]);
		let h = header(&v2(0x21, 0x11, &body));
		assert_eq!(h.addrs, Some((sa("192.0.2.7:5000"), sa("192.0.2.8:80"))));
		assert_eq!(h.len, 16 + body.len());
		for (bad, why) in [
			(v2(0x11, 0x11, &[0; 12]), "version 1"),
			(v2(0x22, 0x11, &[0; 12]), "command 2"),
			(v2(0x21, 0x41, &[0; 12]), "family 4"),
			(v2(0x21, 0x13, &[0; 12]), "transport 3"),
			(v2(0x21, 0x12, &[0; 12]), "DGRAM over TCP"),
			(v2(0x21, 0x11, &[0; 11]), "short IPv4"),
			(v2(0x21, 0x21, &[0; 35]), "short IPv6"),
		] {
			assert!(matches!(parse(&bad), Parsed::Invalid(_)), "{why}");
		}
		// the length is capped (TLVs included)
		assert!(header(&v2(0x21, 0x11, &[0; V2_MAX_PAYLOAD])).len == V2_MAX);
		let mut long = v2(0x21, 0x11, &[0; 12]);
		long[14..16].copy_from_slice(&((V2_MAX_PAYLOAD + 1) as u16).to_be_bytes());
		assert!(matches!(parse(&long), Parsed::Invalid(_)), "decided before the bytes arrive");
	}

	#[test]
	fn validation() {
		let spec = |v: serde_json::Value| serde_json::from_value::<ProxyProtocolSpec>(v).unwrap();
		let ok = validate(Some(spec(serde_json::json!({"from": ["10.2.0.0/16", "172.16.10.19/32"]}))), Protocol::Tcp).unwrap().unwrap();
		assert!(ok.required, "required by default");
		assert!(ok.trusts("10.2.3.4".parse().unwrap()) && ok.trusts("::ffff:172.16.10.19".parse().unwrap()));
		assert!(!ok.trusts("172.16.10.20".parse().unwrap()));
		assert_eq!(ok.view(), spec(serde_json::json!({"from": ["10.2.0.0/16", "172.16.10.19/32"], "required": true})));
		assert_eq!(validate(Some(spec(serde_json::json!({}))), Protocol::Tcp).unwrap(), None, "{{}} is none");
		assert_eq!(validate(None, Protocol::Udp).unwrap(), None);
		for (v, code) in [
			(serde_json::json!({"from": []}), "invalid"),
			(serde_json::json!({"required": false}), "invalid"),
			(serde_json::json!({"from": ["nope"]}), "invalid"),
			(serde_json::json!({"from": ["0.0.0.0/0"]}), "invalid"),
			(serde_json::json!({"from": ["::/0"]}), "invalid"),
		] {
			assert_eq!(validate(Some(spec(v.clone())), Protocol::Tcp).unwrap_err().code, code, "{v}");
		}
		assert_eq!(validate(Some(spec(serde_json::json!({"from": ["10.0.0.1"]}))), Protocol::Udp).unwrap_err().code, "unsupported");
		assert!(serde_json::from_value::<ProxyProtocolSpec>(serde_json::json!({"from": ["10.0.0.1"], "trust": true})).is_err());
	}

	async fn pair() -> (TcpStream, TcpStream) {
		let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
		let (s, _) = l.accept().await.unwrap();
		(c, s)
	}

	#[tokio::test]
	async fn read_consumes_just_the_header() {
		use tokio::io::AsyncWriteExt;
		let (mut c, mut s) = pair().await;
		let v2 = proxy_v2_header(sa("192.0.2.9:4000"), sa("192.0.2.1:443"));
		// split over two writes
		c.write_all(&v2[..10]).await.unwrap();
		let writer = tokio::spawn(async move {
			tokio::time::sleep(Duration::from_millis(30)).await;
			c.write_all(&v2[10..]).await.unwrap();
			c.write_all(b"hello").await.unwrap();
			c
		});
		assert_eq!(read(&mut s, true).await.unwrap(), Some(sa("192.0.2.9:4000")));
		let _c = writer.await.unwrap();
		let mut rest = [0u8; 5];
		s.read_exact(&mut rest).await.unwrap();
		assert_eq!(&rest, b"hello");
	}

	#[tokio::test]
	async fn read_without_a_header() {
		use tokio::io::AsyncWriteExt;
		let (mut c, mut s) = pair().await;
		c.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
		assert_eq!(read(&mut s, false).await.unwrap(), None, "not required: the peer's address");
		let mut first = [0u8; 3];
		s.read_exact(&mut first).await.unwrap();
		assert_eq!(&first, b"GET", "nothing consumed");
		let (mut c, mut s) = pair().await;
		c.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
		assert_eq!(read(&mut s, true).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
		let (mut c, mut s) = pair().await;
		c.write_all(b"PROXY TCP4 1.2.3.4\r\n").await.unwrap();
		assert_eq!(read(&mut s, false).await.unwrap_err().kind(), io::ErrorKind::InvalidData, "a broken header is refused");
	}

	#[tokio::test]
	async fn read_gives_up_on_a_slow_header() {
		use tokio::io::AsyncWriteExt;
		let limit = Duration::from_millis(200);
		let (mut c, mut s) = pair().await;
		c.write_all(b"PROXY TCP4 ").await.unwrap();
		assert_eq!(read_within(&mut s, true, limit).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
		let (mut c, mut s) = pair().await;
		c.write_all(b"PROXY TCP4 ").await.unwrap();
		assert_eq!(read_within(&mut s, false, limit).await.unwrap_err().kind(), io::ErrorKind::TimedOut, "a header begun is finished");
		// nothing at all, not required (a server-first protocol): the peer's address
		let (_c, mut s) = pair().await;
		assert_eq!(read_within(&mut s, false, limit).await.unwrap(), None);
		let (_c, mut s) = pair().await;
		assert_eq!(read_within(&mut s, true, limit).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
	}

	#[tokio::test]
	async fn untrusted_headers_are_seen() {
		use tokio::io::AsyncWriteExt;
		let (mut c, s) = pair().await;
		c.write_all(&proxy_v2_header(sa("192.0.2.9:4000"), sa("192.0.2.1:443"))).await.unwrap();
		assert_eq!(untrusted_start(&s, true).await, Some(Version::V2));
		let (mut c, s) = pair().await;
		c.write_all(b"PROXY TCP4 192.0.2.9 192.0.2.1 1 2\r\n").await.unwrap();
		assert_eq!(untrusted_start(&s, true).await, Some(Version::V1));
		tokio::time::sleep(Duration::from_millis(20)).await;
		assert_eq!(untrusted_start(&s, false).await, Some(Version::V1), "already arrived");
		let (mut c, s) = pair().await;
		c.write_all(b"\x16\x03\x01").await.unwrap();
		assert_eq!(untrusted_start(&s, true).await, None);
		let (_c, s) = pair().await;
		assert_eq!(untrusted_start(&s, false).await, None, "nothing has arrived: not waited for");
	}
}
