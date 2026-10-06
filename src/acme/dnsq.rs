//! A small DNS client for DNS-01 (#208): follows the CNAME of
//! `_acme-challenge.<name>` to where the TXT record is written, finds the zone
//! of a name (SOA), and checks whether a TXT record is visible yet. Queries go
//! over UDP to the configured name servers (`global.acme.dns_servers`, or
//! /etc/resolv.conf). The answers come from the network, so `parse_response`
//! is fuzzed (fuzz/fuzz_targets/dns_response.rs).

use std::net::SocketAddr;
use std::time::Duration;

pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_TXT: u16 = 16;

const TIMEOUT: Duration = Duration::from_secs(3);
/// CNAMEs followed at most (a loop ends here).
const MAX_CNAMES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
	Cname(String),
	Soa,
	Txt(Vec<u8>),
	Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
	/// Owner name, lower case, without the final dot.
	pub name: String,
	pub rtype: u16,
	pub data: Data,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Response {
	pub id: u16,
	pub rcode: u8,
	pub truncated: bool,
	pub answers: Vec<Record>,
	pub authority: Vec<Record>,
}

/// The name servers of /etc/resolv.conf (127.0.0.1:53 without any).
pub fn system_servers() -> Vec<SocketAddr> {
	let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
	let mut out: Vec<SocketAddr> = text
		.lines()
		.filter_map(|l| l.trim().strip_prefix("nameserver"))
		.filter_map(|v| v.trim().split('%').next()?.parse::<std::net::IpAddr>().ok())
		.map(|ip| SocketAddr::new(ip, 53))
		.collect();
	if out.is_empty() {
		out.push(SocketAddr::from(([127, 0, 0, 1], 53)));
	}
	out
}

/// A query for `name` / `qtype` with recursion desired.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
	let mut q = Vec::with_capacity(32 + name.len());
	q.extend_from_slice(&id.to_be_bytes());
	q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
	for label in name.trim_end_matches('.').split('.') {
		if label.is_empty() || label.len() > 63 {
			return Err(format!("{name:?} is not a DNS name"));
		}
		q.push(label.len() as u8);
		q.extend_from_slice(label.as_bytes());
	}
	q.push(0);
	q.extend_from_slice(&qtype.to_be_bytes());
	q.extend_from_slice(&1u16.to_be_bytes());
	Ok(q)
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
	Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Reads a (possibly compressed) name at `at`; returns it and the offset after it.
fn read_name(b: &[u8], mut at: usize) -> Option<(String, usize)> {
	let mut name = String::new();
	let mut end = None;
	let mut jumps = 0;
	loop {
		let len = *b.get(at)? as usize;
		match len & 0xc0 {
			0x00 if len == 0 => {
				return Some((name.to_ascii_lowercase(), end.unwrap_or(at + 1)));
			}
			0x00 => {
				let label = b.get(at + 1..at + 1 + len)?;
				if !name.is_empty() {
					name.push('.');
				}
				name.extend(label.iter().map(|&c| if c.is_ascii_graphic() { c as char } else { '?' }));
				if name.len() > 255 {
					return None;
				}
				at += 1 + len;
			}
			0xc0 => {
				jumps += 1;
				if jumps > 32 {
					return None;
				}
				let target = (u16_at(b, at)? & 0x3fff) as usize;
				end.get_or_insert(at + 2);
				at = target;
			}
			_ => return None,
		}
	}
}

fn read_records(b: &[u8], mut at: usize, count: u16) -> Option<(Vec<Record>, usize)> {
	let mut out = Vec::new();
	for _ in 0..count {
		let (name, next) = read_name(b, at)?;
		let rtype = u16_at(b, next)?;
		let rdlen = u16_at(b, next + 8)? as usize;
		let rdata_at = next + 10;
		let rdata = b.get(rdata_at..rdata_at + rdlen)?;
		let data = match rtype {
			TYPE_CNAME => Data::Cname(read_name(b, rdata_at)?.0),
			TYPE_SOA => Data::Soa,
			TYPE_TXT => {
				// character-strings, joined
				let mut txt = Vec::new();
				let mut i = 0;
				while i < rdata.len() {
					let l = rdata[i] as usize;
					txt.extend_from_slice(rdata.get(i + 1..i + 1 + l)?);
					i += 1 + l;
				}
				Data::Txt(txt)
			}
			_ => Data::Other,
		};
		out.push(Record { name, rtype, data });
		at = rdata_at + rdlen;
	}
	Some((out, at))
}

/// Parses a DNS response (answer and authority sections).
pub fn parse_response(b: &[u8]) -> Option<Response> {
	let id = u16_at(b, 0)?;
	let flags = u16_at(b, 2)?;
	if flags & 0x8000 == 0 {
		return None; // not a response
	}
	let (qd, an, ns) = (u16_at(b, 4)?, u16_at(b, 6)?, u16_at(b, 8)?);
	let mut at = 12;
	for _ in 0..qd {
		at = read_name(b, at)?.1 + 4;
	}
	let (answers, at) = read_records(b, at, an)?;
	let (authority, _) = read_records(b, at, ns)?;
	Some(Response { id, rcode: (flags & 0x0f) as u8, truncated: flags & 0x0200 != 0, answers, authority })
}

/// Asks the servers in turn until one answers.
pub async fn query(servers: &[SocketAddr], name: &str, qtype: u16) -> Result<Response, String> {
	let mut last = "no name servers".to_string();
	for server in servers {
		let id: u16 = rand_id();
		let q = build_query(id, name, qtype)?;
		let bind: SocketAddr = if server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() };
		let attempt = async {
			let sock = tokio::net::UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
			sock.connect(server).await.map_err(|e| e.to_string())?;
			sock.send(&q).await.map_err(|e| e.to_string())?;
			let mut buf = vec![0u8; 4096];
			loop {
				let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
				match parse_response(&buf[..n]) {
					Some(r) if r.id == id => return Ok::<Response, String>(r),
					_ => continue, // not ours: keep waiting
				}
			}
		};
		match tokio::time::timeout(TIMEOUT, attempt).await {
			Ok(Ok(r)) if r.rcode == 0 || r.rcode == 3 => return Ok(r),
			Ok(Ok(r)) => last = format!("{server}: rcode {}", r.rcode),
			Ok(Err(e)) => last = format!("{server}: {e}"),
			Err(_) => last = format!("{server}: timed out"),
		}
	}
	Err(format!("DNS query for {name}: {last}"))
}

fn rand_id() -> u16 {
	let mut b = [0u8; 2];
	let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
	u16::from_be_bytes(b)
}

/// Where `name`'s records really live: follows CNAMEs (delegation of
/// `_acme-challenge` to another zone).
pub async fn follow_cname(servers: &[SocketAddr], name: &str) -> Result<String, String> {
	let mut current = name.to_ascii_lowercase();
	for _ in 0..MAX_CNAMES {
		let r = query(servers, &current, TYPE_CNAME).await?;
		let next = r.answers.iter().find_map(|a| match &a.data {
			Data::Cname(target) if a.name == current => Some(target.clone()),
			_ => None,
		});
		match next {
			Some(target) => current = target,
			None => return Ok(current),
		}
	}
	Err(format!("{name}: more than {MAX_CNAMES} CNAMEs"))
}

/// The zone `name` is in: the owner of the SOA record in the answer (an apex)
/// or in the authority section (a name below it, or one that does not exist).
pub async fn find_zone(servers: &[SocketAddr], name: &str) -> Result<String, String> {
	let r = query(servers, name, TYPE_SOA).await?;
	r.answers
		.iter()
		.chain(&r.authority)
		.find(|rec| rec.rtype == TYPE_SOA && (name == rec.name || name.ends_with(&format!(".{}", rec.name))))
		.map(|rec| rec.name.clone())
		.ok_or_else(|| format!("{name}: no SOA record found (give the provider's zones)"))
}

/// The TXT values of `name`.
pub async fn txt(servers: &[SocketAddr], name: &str) -> Result<Vec<String>, String> {
	let r = query(servers, name, TYPE_TXT).await?;
	Ok(r.answers
		.iter()
		.filter_map(|a| match &a.data {
			Data::Txt(t) if a.name == name => Some(String::from_utf8_lossy(t).into_owned()),
			_ => None,
		})
		.collect())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn name(out: &mut Vec<u8>, n: &str) {
		for l in n.split('.') {
			out.push(l.len() as u8);
			out.extend_from_slice(l.as_bytes());
		}
		out.push(0);
	}

	fn rr(out: &mut Vec<u8>, owner: &[u8], rtype: u16, rdata: &[u8]) {
		out.extend_from_slice(owner);
		out.extend_from_slice(&rtype.to_be_bytes());
		out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
		out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
		out.extend_from_slice(rdata);
	}

	#[test]
	fn reads_cname_txt_and_soa_with_compression() {
		let mut q = build_query(0x1234, "_acme-challenge.www.example.com.", TYPE_TXT).unwrap();
		// turn it into a response with 2 answers, 1 authority record
		q[2] = 0x81;
		q[3] = 0x80;
		q[7] = 2;
		q[9] = 1;
		let mut cname = vec![];
		name(&mut cname, "www.acme.example.net");
		rr(&mut q, &[0xc0, 12], TYPE_CNAME, &cname);
		let target_at = q.len() - cname.len();
		rr(&mut q, &[0xc0, target_at as u8], TYPE_TXT, b"\x05hello\x03 me");
		let mut zone = vec![];
		name(&mut zone, "acme.example.net");
		let mut soa = vec![0xc0, 12, 0xc0, 12];
		soa.extend_from_slice(&[0; 20]);
		rr(&mut q, &zone, TYPE_SOA, &soa);
		let r = parse_response(&q).unwrap();
		assert_eq!(r.id, 0x1234);
		assert_eq!(r.answers[0], Record { name: "_acme-challenge.www.example.com".into(), rtype: TYPE_CNAME, data: Data::Cname("www.acme.example.net".into()) });
		assert_eq!(r.answers[1].name, "www.acme.example.net");
		assert_eq!(r.answers[1].data, Data::Txt(b"hello me".to_vec()));
		assert_eq!(r.authority[0].name, "acme.example.net");
		assert_eq!(r.authority[0].data, Data::Soa);
	}

	#[test]
	fn refuses_broken_answers() {
		let q = build_query(1, "a.example", TYPE_TXT).unwrap();
		assert!(parse_response(&q).is_none(), "a query is not a response");
		let mut loop_ = q.clone();
		loop_[2] = 0x81;
		loop_[7] = 1;
		loop_.extend_from_slice(&[0xc0, (loop_.len()) as u8]); // a pointer to itself
		assert!(parse_response(&loop_).is_none());
		for cut in 0..q.len() {
			let mut r = q[..cut].to_vec();
			if r.len() > 2 {
				r[2] |= 0x80;
			}
			let _ = parse_response(&r);
		}
		assert!(build_query(1, "a..b", TYPE_TXT).is_err());
	}
}
