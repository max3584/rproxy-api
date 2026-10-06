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

/// A signed UPDATE message for `zone`, and its MAC (the answer's MAC covers it).
pub fn build(id: u16, zone: &str, changes: &[Change<'_>], key: &TsigKey, time: u64) -> Result<(Vec<u8>, Vec<u8>), String> {
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
	sign(m, key, time, None, 0)
}

/// The TSIG variables (RFC 8945 4.3.3) after the message.
fn variables(key_name: &[u8], alg_name: &[u8], time48: &[u8], fudge: u16, error: u16, other: &[u8]) -> Vec<u8> {
	let mut v = key_name.to_vec();
	v.extend_from_slice(&CLASS_ANY.to_be_bytes());
	v.extend_from_slice(&0u32.to_be_bytes());
	v.extend_from_slice(alg_name);
	v.extend_from_slice(time48);
	v.extend_from_slice(&fudge.to_be_bytes());
	v.extend_from_slice(&error.to_be_bytes());
	v.extend_from_slice(&(other.len() as u16).to_be_bytes());
	v.extend_from_slice(other);
	v
}

/// Appends the TSIG record (RFC 8945 4.): the MAC covers the request's MAC (in
/// an answer, `prior`), the message, then the TSIG variables. Returns the
/// message and the MAC.
pub fn sign(mut m: Vec<u8>, key: &TsigKey, time: u64, prior: Option<&[u8]>, error: u16) -> Result<(Vec<u8>, Vec<u8>), String> {
	let key_name = wire_name(&key.name)?;
	let alg_name = wire_name(key.algorithm.name())?;
	let time48 = &time.to_be_bytes()[2..];
	let mut signed = vec![];
	if let Some(prior) = prior {
		signed.extend_from_slice(&(prior.len() as u16).to_be_bytes());
		signed.extend_from_slice(prior);
	}
	signed.extend_from_slice(&m);
	signed.extend(variables(&key_name, &alg_name, time48, FUDGE, error, &[]));
	let mac = hmac::sign(&hmac::Key::new(key.algorithm.ring(), &key.secret), &signed).as_ref().to_vec();
	let mut rdata = alg_name;
	rdata.extend_from_slice(time48);
	rdata.extend_from_slice(&FUDGE.to_be_bytes());
	rdata.extend_from_slice(&(mac.len() as u16).to_be_bytes());
	rdata.extend_from_slice(&mac);
	rdata.extend_from_slice(&m[0..2]); // original id
	rdata.extend_from_slice(&error.to_be_bytes());
	rdata.extend_from_slice(&0u16.to_be_bytes());
	m.extend(key_name);
	m.extend_from_slice(&TYPE_TSIG.to_be_bytes());
	m.extend_from_slice(&CLASS_ANY.to_be_bytes());
	m.extend_from_slice(&0u32.to_be_bytes());
	m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
	m.extend(rdata);
	let ar = u16::from_be_bytes([m[10], m[11]]) + 1;
	m[10..12].copy_from_slice(&ar.to_be_bytes());
	Ok((m, mac))
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

fn tsig_error_text(error: u16) -> String {
	match error {
		16 => "BADSIG (the server does not accept the signature: a wrong secret?)".into(),
		17 => "BADKEY (the server does not know the key or its algorithm)".into(),
		18 => "BADTIME (the clocks differ by more than the fudge)".into(),
		22 => "BADTRUNC".into(),
		n => format!("TSIG error {n}"),
	}
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
	Ok(u16::from_be_bytes([*b.get(at).ok_or("a short answer")?, *b.get(at + 1).ok_or("a short answer")?]))
}

/// A (possibly compressed) name at `at`: lower case, and the offset after it.
fn read_name(b: &[u8], mut at: usize) -> Result<(String, usize), String> {
	let mut name = String::new();
	let mut end = None;
	for _ in 0..128 {
		let len = *b.get(at).ok_or("a short answer")? as usize;
		if len == 0 {
			return Ok((name, end.unwrap_or(at + 1)));
		}
		if len & 0xc0 == 0xc0 {
			end.get_or_insert(at + 2);
			at = (u16_at(b, at)? & 0x3fff) as usize;
			continue;
		}
		let label = b.get(at + 1..at + 1 + len).ok_or("a short answer")?;
		if !name.is_empty() {
			name.push('.');
		}
		name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
		at += 1 + len;
	}
	Err("a name that does not end".into())
}

/// Checks the TSIG record of an answer (RFC 8945 5.3): signed with `key`,
/// MAC over the request's MAC and the answer, time within the fudge, no TSIG
/// error; then the answer's rcode.
pub fn verify_answer(answer: &[u8], request_mac: &[u8], key: &TsigKey, now: u64) -> Result<(), String> {
	let rcode = u16_at(answer, 2)? & 0x0f;
	let (qd, an, ns, ar) = (u16_at(answer, 4)?, u16_at(answer, 6)?, u16_at(answer, 8)?, u16_at(answer, 10)?);
	if ar == 0 {
		return Err(match rcode {
			0 => "the answer is not signed (TSIG): it cannot be trusted".into(),
			r => format!("the update was refused: {} (the answer is not signed)", rcode_text(r)),
		});
	}
	let mut at = 12;
	for _ in 0..qd {
		at = read_name(answer, at)?.1 + 4;
	}
	for _ in 0..(u32::from(an) + u32::from(ns) + u32::from(ar) - 1) {
		at = read_name(answer, at)?.1;
		at += 10 + u16_at(answer, at + 8)? as usize;
	}
	let tsig_at = at;
	let (name, after) = read_name(answer, at)?;
	if u16_at(answer, after)? != TYPE_TSIG {
		return Err("the answer is not signed (TSIG): it cannot be trusted".into());
	}
	let rdlen = u16_at(answer, after + 8)? as usize;
	let rdata_at = after + 10;
	let rdata = answer.get(rdata_at..rdata_at + rdlen).ok_or("a short answer")?;
	if rdata_at + rdlen != answer.len() {
		return Err("data after the TSIG record".into());
	}
	let (alg, p) = read_name(answer, rdata_at)?;
	let p = p - rdata_at;
	let time48 = rdata.get(p..p + 6).ok_or("a short TSIG record")?;
	let time = time48.iter().fold(0u64, |t, b| t << 8 | u64::from(*b));
	let fudge = u16_at(rdata, p + 6)?;
	let mac_len = u16_at(rdata, p + 8)? as usize;
	let mac = rdata.get(p + 10..p + 10 + mac_len).ok_or("a short TSIG record")?;
	let q = p + 10 + mac_len;
	let original_id = rdata.get(q..q + 2).ok_or("a short TSIG record")?;
	let error = u16_at(rdata, q + 2)?;
	let other_len = u16_at(rdata, q + 4)? as usize;
	let other = rdata.get(q + 6..q + 6 + other_len).ok_or("a short TSIG record")?;
	if name != key.name.trim_end_matches('.').to_ascii_lowercase() || alg != key.algorithm.name() {
		return Err(format!("the answer is signed with another key ({name}, {alg})"));
	}
	if error != 0 && mac_len == 0 {
		return Err(format!("the update was refused: {}", tsig_error_text(error)));
	}
	if mac_len != key.algorithm.ring().digest_algorithm().output_len() {
		return Err("the answer's MAC is truncated or empty".into());
	}
	let mut unsigned = answer[..tsig_at].to_vec();
	unsigned[0..2].copy_from_slice(original_id);
	unsigned[10..12].copy_from_slice(&(ar - 1).to_be_bytes());
	let mut signed = (request_mac.len() as u16).to_be_bytes().to_vec();
	signed.extend_from_slice(request_mac);
	signed.extend(unsigned);
	signed.extend(variables(&wire_name(&key.name)?, &wire_name(key.algorithm.name())?, time48, fudge, error, other));
	hmac::verify(&hmac::Key::new(key.algorithm.ring(), &key.secret), &signed, mac)
		.map_err(|_| "the answer's TSIG signature does not verify (BADSIG): it cannot be trusted".to_string())?;
	if error != 0 {
		return Err(format!("the update was refused: {}", tsig_error_text(error)));
	}
	if now.abs_diff(time) > u64::from(fudge) {
		return Err(format!("BADTIME: the answer was signed at {time}, {}s from this clock (fudge {fudge}s)", now.abs_diff(time)));
	}
	if rcode != 0 {
		return Err(format!("the update was refused: {}", rcode_text(rcode)));
	}
	Ok(())
}

/// Sends a signed UPDATE (UDP, TCP when the answer is truncated) and checks the
/// answer: its TSIG signature, then its rcode.
pub async fn send(server: SocketAddr, zone: &str, changes: &[Change<'_>], key: &TsigKey) -> Result<(), String> {
	let mut id = [0u8; 2];
	let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut id);
	let id = u16::from_be_bytes(id);
	let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
	let (msg, mac) = build(id, zone, changes, key, now())?;
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
	verify_answer(&answer, &mac, key, now()).map_err(|e| format!("{server}: {e}"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_signed_update() {
		let key = TsigKey { name: "rproxy.".into(), algorithm: Algorithm::HmacSha256, secret: b"0123456789abcdef".to_vec() };
		let (m, _) = build(
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

	/// An answer as a server would send it: the request's header with QR and `rcode`.
	fn answer(request: &[u8], rcode: u8) -> Vec<u8> {
		// the request without its TSIG record: header + zone section
		let mut a = request[..12].to_vec();
		a[2] |= 0x80;
		a[3] = rcode;
		a[4..12].copy_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
		a.extend(wire_name("example.com").unwrap());
		a.extend_from_slice(&[0, 6, 0, 1]);
		a
	}

	#[test]
	fn answers_must_be_signed_with_the_key() {
		let key = TsigKey { name: "rproxy".into(), algorithm: Algorithm::HmacSha512, secret: b"the-right-secret".to_vec() };
		let wrong = TsigKey { secret: b"another-secret".to_vec(), ..TsigKey { name: "rproxy".into(), algorithm: Algorithm::HmacSha512, secret: vec![] } };
		let now = 1_700_000_000;
		let (req, req_mac) = build(7, "example.com", &[Change::Add { name: "_acme-challenge.example.com", value: "v", ttl: 60 }], &key, now).unwrap();
		let sign_answer = |rcode: u8, k: &TsigKey, prior: &[u8], time: u64, error: u16| sign(answer(&req, rcode), k, time, Some(prior), error).unwrap().0;

		verify_answer(&sign_answer(0, &key, &req_mac, now + 2, 0), &req_mac, &key, now).unwrap();
		// unsigned, forged, signed for another request, altered after signing
		let e = verify_answer(&answer(&req, 0), &req_mac, &key, now).unwrap_err();
		assert!(e.contains("not signed"), "{e}");
		let e = verify_answer(&sign_answer(0, &wrong, &req_mac, now, 0), &req_mac, &key, now).unwrap_err();
		assert!(e.contains("does not verify"), "{e}");
		let e = verify_answer(&sign_answer(0, &key, &[0; 64], now, 0), &req_mac, &key, now).unwrap_err();
		assert!(e.contains("does not verify"), "the MAC covers the request's MAC: {e}");
		let mut altered = sign_answer(0, &key, &req_mac, now, 0);
		altered[3] = 5;
		assert!(verify_answer(&altered, &req_mac, &key, now).unwrap_err().contains("does not verify"));
		// the clock, the server's errors
		let e = verify_answer(&sign_answer(0, &key, &req_mac, now - 1000, 0), &req_mac, &key, now).unwrap_err();
		assert!(e.contains("BADTIME"), "{e}");
		let e = verify_answer(&sign_answer(9, &key, &req_mac, now, 18), &req_mac, &key, now).unwrap_err();
		assert!(e.contains("BADTIME") && e.contains("refused"), "{e}");
		let e = verify_answer(&sign_answer(5, &key, &req_mac, now, 0), &req_mac, &key, now).unwrap_err();
		assert!(e.contains("REFUSED"), "{e}");
		// BADKEY / BADSIG come unsigned (the server cannot sign with a key it does not know)
		let mut badkey = answer(&req, 9);
		let (signed, _) = sign(badkey.clone(), &key, now, Some(&req_mac), 17).unwrap();
		let mac_len = 64usize;
		// strip the MAC: rebuild the TSIG record with an empty MAC
		let tsig_at = badkey.len();
		let mut rdata = signed[tsig_at + wire_name("rproxy").unwrap().len() + 10..].to_vec();
		let alg_len = wire_name("hmac-sha512").unwrap().len();
		rdata.drain(alg_len + 10..alg_len + 10 + mac_len);
		rdata[alg_len + 8..alg_len + 10].copy_from_slice(&[0, 0]);
		badkey.extend(wire_name("rproxy").unwrap());
		badkey.extend_from_slice(&[0, 250, 0, 255, 0, 0, 0, 0]);
		badkey.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
		badkey.extend(rdata);
		badkey[11] = 1;
		let e = verify_answer(&badkey, &req_mac, &key, now).unwrap_err();
		assert!(e.contains("BADKEY"), "{e}");
		// a cut answer is an error, not a panic
		let good = sign_answer(0, &key, &req_mac, now, 0);
		for cut in 0..good.len() {
			let _ = verify_answer(&good[..cut], &req_mac, &key, now);
		}
	}
}
