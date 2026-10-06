//! DNS UPDATE (RFC 2136) signed with TSIG (RFC 8945), for the `rfc2136` DNS
//! provider: adds and deletes the TXT records of DNS-01 on a primary server
//! (BIND, Knot, PowerDNS, ...). HMAC-SHA256 / HMAC-SHA512 through ring.

use std::net::SocketAddr;
use std::time::Duration;

use ring::hmac;

const TYPE_SOA: u16 = 6;
const TYPE_TXT: u16 = 16;
const TYPE_TSIG: u16 = 250;
const CLASS_IN: u16 = 1;
const CLASS_NONE: u16 = 254;
const CLASS_ANY: u16 = 255;
const OPCODE_UPDATE: u16 = 5 << 11;
const FUDGE: u16 = 300;
const TIMEOUT: Duration = Duration::from_secs(5);

/// A TSIG key: name, algorithm and secret.
pub struct TsigKey {
	pub name: String,
	pub algorithm: Algorithm,
	pub secret: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
	HmacSha256,
	HmacSha512,
}

impl Algorithm {
	pub fn parse(s: &str) -> Option<Algorithm> {
		match s.trim_end_matches('.') {
			"hmac-sha256" => Some(Algorithm::HmacSha256),
			"hmac-sha512" => Some(Algorithm::HmacSha512),
			_ => None,
		}
	}

	fn name(self) -> &'static str {
		match self {
			Algorithm::HmacSha256 => "hmac-sha256",
			Algorithm::HmacSha512 => "hmac-sha512",
		}
	}

	fn ring(self) -> hmac::Algorithm {
		match self {
			Algorithm::HmacSha256 => hmac::HMAC_SHA256,
			Algorithm::HmacSha512 => hmac::HMAC_SHA512,
		}
	}
}

/// A name in wire format (lower case, uncompressed: also the canonical form TSIG signs).
fn wire_name(name: &str) -> Result<Vec<u8>, String> {
	let mut out = vec![];
	for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
		if label.len() > 63 {
			return Err(format!("{name:?}: a label is longer than 63"));
		}
		out.push(label.len() as u8);
		out.extend(label.to_ascii_lowercase().bytes());
	}
	out.push(0);
	Ok(out)
}

fn txt_rdata(value: &str) -> Result<Vec<u8>, String> {
	if value.len() > 255 {
		return Err("a TXT value longer than 255".into());
	}
	let mut r = vec![value.len() as u8];
	r.extend_from_slice(value.as_bytes());
	Ok(r)
}

/// What one UPDATE does to the TXT records of `name`.
pub enum Change<'a> {
	Add { name: &'a str, value: &'a str, ttl: u32 },
	Delete { name: &'a str, value: &'a str },
}

/// A signed UPDATE message for `zone`.
pub fn build(id: u16, zone: &str, changes: &[Change<'_>], key: &TsigKey, time: u64) -> Result<Vec<u8>, String> {
	let mut m = vec![];
	m.extend_from_slice(&id.to_be_bytes());
	m.extend_from_slice(&OPCODE_UPDATE.to_be_bytes());
	m.extend_from_slice(&1u16.to_be_bytes()); // zone
	m.extend_from_slice(&0u16.to_be_bytes()); // prerequisites
	m.extend_from_slice(&(changes.len() as u16).to_be_bytes());
	m.extend_from_slice(&0u16.to_be_bytes()); // additional (TSIG added below)
	m.extend(wire_name(zone)?);
	m.extend_from_slice(&TYPE_SOA.to_be_bytes());
	m.extend_from_slice(&CLASS_IN.to_be_bytes());
	for c in changes {
		let (name, value, class, ttl) = match c {
			Change::Add { name, value, ttl } => (name, value, CLASS_IN, *ttl),
			Change::Delete { name, value } => (name, value, CLASS_NONE, 0),
		};
		let rdata = txt_rdata(value)?;
		m.extend(wire_name(name)?);
		m.extend_from_slice(&TYPE_TXT.to_be_bytes());
		m.extend_from_slice(&class.to_be_bytes());
		m.extend_from_slice(&ttl.to_be_bytes());
		m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
		m.extend(rdata);
	}
	sign(m, key, time)
}

/// Appends the TSIG record (RFC 8945 4.): the MAC covers the message, then the TSIG variables.
fn sign(mut m: Vec<u8>, key: &TsigKey, time: u64) -> Result<Vec<u8>, String> {
	let key_name = wire_name(&key.name)?;
	let alg_name = wire_name(key.algorithm.name())?;
	let time48 = &time.to_be_bytes()[2..];
	let mut signed = m.clone();
	signed.extend(&key_name);
	signed.extend_from_slice(&CLASS_ANY.to_be_bytes());
	signed.extend_from_slice(&0u32.to_be_bytes());
	signed.extend(&alg_name);
	signed.extend_from_slice(time48);
	signed.extend_from_slice(&FUDGE.to_be_bytes());
	signed.extend_from_slice(&0u16.to_be_bytes()); // error
	signed.extend_from_slice(&0u16.to_be_bytes()); // other length
	let mac = hmac::sign(&hmac::Key::new(key.algorithm.ring(), &key.secret), &signed);
	let mac = mac.as_ref();
	let mut rdata = alg_name;
	rdata.extend_from_slice(time48);
	rdata.extend_from_slice(&FUDGE.to_be_bytes());
	rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
	rdata.extend_from_slice(mac);
	rdata.extend_from_slice(&m[0..2]); // original id
	rdata.extend_from_slice(&0u16.to_be_bytes());
	rdata.extend_from_slice(&0u16.to_be_bytes());
	m.extend(key_name);
	m.extend_from_slice(&TYPE_TSIG.to_be_bytes());
	m.extend_from_slice(&CLASS_ANY.to_be_bytes());
	m.extend_from_slice(&0u32.to_be_bytes());
	m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
	m.extend(rdata);
	let ar = u16::from_be_bytes([m[10], m[11]]) + 1;
	m[10..12].copy_from_slice(&ar.to_be_bytes());
	Ok(m)
}

fn rcode_text(rcode: u16) -> String {
	match rcode {
		1 => "FORMERR".into(),
		2 => "SERVFAIL".into(),
		5 => "REFUSED".into(),
		8 => "NXRRSET".into(),
		9 => "NOTAUTH (the key or the zone is not accepted)".into(),
		10 => "NOTZONE".into(),
		n => format!("rcode {n}"),
	}
}

/// Sends a signed UPDATE (UDP, TCP when the answer is truncated) and checks the answer's rcode.
pub async fn send(server: SocketAddr, zone: &str, changes: &[Change<'_>], key: &TsigKey) -> Result<(), String> {
	let mut id = [0u8; 2];
	let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id);
	let id = u16::from_be_bytes(id);
	let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
	let msg = build(id, zone, changes, key, time)?;
	let answer = async {
		let bind: SocketAddr = if server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { (std::net::Ipv6Addr::UNSPECIFIED, 0).into() };
		let sock = tokio::net::UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
		sock.connect(server).await.map_err(|e| e.to_string())?;
		sock.send(&msg).await.map_err(|e| e.to_string())?;
		let mut buf = vec![0u8; 4096];
		loop {
			let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
			if n >= 12 && buf[0..2] == id.to_be_bytes() {
				buf.truncate(n);
				break;
			}
		}
		if buf[2] & 0x02 != 0 {
			use tokio::io::{AsyncReadExt, AsyncWriteExt};
			let mut tcp = tokio::net::TcpStream::connect(server).await.map_err(|e| e.to_string())?;
			tcp.write_all(&(msg.len() as u16).to_be_bytes()).await.map_err(|e| e.to_string())?;
			tcp.write_all(&msg).await.map_err(|e| e.to_string())?;
			let mut len = [0u8; 2];
			tcp.read_exact(&mut len).await.map_err(|e| e.to_string())?;
			buf = vec![0u8; u16::from_be_bytes(len) as usize];
			tcp.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
		}
		Ok::<_, String>(buf)
	};
	let answer = tokio::time::timeout(TIMEOUT, answer).await.map_err(|_| format!("{server}: timed out"))??;
	let rcode = u16::from_be_bytes([answer.get(2).copied().unwrap_or(0), answer.get(3).copied().unwrap_or(0)]) & 0x0f;
	if rcode != 0 {
		return Err(format!("{server}: the update was refused: {}", rcode_text(rcode)));
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_signed_update() {
		let key = TsigKey { name: "rproxy.".into(), algorithm: Algorithm::HmacSha256, secret: b"0123456789abcdef".to_vec() };
		let m = build(
			0x1234,
			"example.com",
			&[
				Change::Add { name: "_acme-challenge.example.com", value: "abc", ttl: 60 },
				Change::Delete { name: "_acme-challenge.example.com", value: "old" },
			],
			&key,
			1_700_000_000,
		)
		.unwrap();
		assert_eq!(&m[0..4], &[0x12, 0x34, 0x28, 0x00], "UPDATE");
		assert_eq!(&m[4..12], &[0, 1, 0, 0, 0, 2, 0, 1], "1 zone, 2 updates, 1 TSIG");
		// the MAC checks out over the message without the TSIG record, then the variables
		let tsig_at = m.windows(8).position(|w| w == b"\x06rproxy\x00").unwrap();
		let mut unsigned = m[..tsig_at].to_vec();
		unsigned[11] = 0;
		let rdata = &m[tsig_at + 8 + 10..];
		let alg = wire_name("hmac-sha256").unwrap();
		assert!(rdata.starts_with(&alg));
		let after_alg = &rdata[alg.len()..];
		let mac_len = u16::from_be_bytes([after_alg[8], after_alg[9]]) as usize;
		assert_eq!(mac_len, 32);
		let mac = &after_alg[10..10 + mac_len];
		let mut vars = unsigned.clone();
		vars.extend(wire_name("rproxy").unwrap());
		vars.extend_from_slice(&[0, 255, 0, 0, 0, 0]);
		vars.extend(alg);
		vars.extend_from_slice(&after_alg[0..8]);
		vars.extend_from_slice(&[0, 0, 0, 0]);
		hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, b"0123456789abcdef"), &vars, mac).unwrap();
		assert_eq!(&after_alg[10 + mac_len..10 + mac_len + 2], &[0x12, 0x34], "original id");
		assert!(Algorithm::parse("hmac-sha512.").is_some() && Algorithm::parse("hmac-md5").is_none());
		assert!(build(1, "a", &[Change::Add { name: "a", value: &"x".repeat(256), ttl: 1 }], &key, 0).is_err());
	}
}
