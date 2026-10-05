//! The server name of a UDP session (`tls.mode: sni` on a udp rule), read from
//! its first datagrams without terminating anything (#130):
//!
//! - DTLS 1.2 / 1.3: the ClientHello is plain text; its handshake fragments may
//!   be spread over several records and datagrams (RFC 6347 §4.2.2, RFC 9147 §5.5).
//! - QUIC v1 (RFC 9000 / 9001) and v2 (RFC 9369): Initial packets are protected
//!   with keys anyone can derive from the Destination Connection ID the client
//!   chose (RFC 9001 §5.2), so the CRYPTO frames can be read and the ClientHello
//!   rebuilt, even when it spans several Initial packets (large key shares).
//!
//! The same ClientHello walk as TCP `sni` is used (`sni::hello_server_name`).
//! Nothing here keeps state beyond one session's first datagrams, and every
//! length read from the wire is checked, so garbage only ends in "no name".

use std::collections::BTreeMap;

use ring::{aead, hkdf};

use crate::tls::sni;

/// ClientHellos larger than this are not assembled (post-quantum key shares make
/// them ~2 KiB today).
const MAX_HELLO: usize = 32 * 1024;

/// What the datagrams seen so far tell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sniff {
	/// A DTLS or QUIC handshake has started but the ClientHello is not complete yet.
	NeedMore,
	/// The whole ClientHello; its server name if it has one.
	Done(Option<String>),
	/// Not DTLS or QUIC (or not something a server name can be read from).
	Unknown,
}

enum State {
	Start,
	Dtls(dtls::Assembler),
	Quic(quic::Assembler),
	Finished(Sniff),
}

/// Reads the first datagrams of one client until the server name is known.
pub struct Sniffer {
	state: State,
}

impl Default for Sniffer {
	fn default() -> Self {
		Sniffer { state: State::Start }
	}
}

impl Sniffer {
	/// Feeds the next datagram from the client.
	pub fn push(&mut self, datagram: &[u8]) -> Sniff {
		if let State::Start = self.state {
			self.state = if dtls::looks_like(datagram) {
				State::Dtls(dtls::Assembler::default())
			} else if quic::looks_like(datagram) {
				State::Quic(quic::Assembler::default())
			} else {
				State::Finished(Sniff::Unknown)
			};
		}
		let result = match &mut self.state {
			State::Dtls(a) => a.push(datagram),
			State::Quic(a) => a.push(datagram),
			State::Finished(s) => return s.clone(),
			State::Start => unreachable!("set above"),
		};
		if result != Sniff::NeedMore {
			self.state = State::Finished(result.clone());
		}
		result
	}
}

/// Byte ranges received of a message whose total length is known: fragments may
/// arrive in any order and overlap.
#[derive(Default)]
struct Reassembly {
	data: Vec<u8>,
	filled: Vec<bool>,
}

impl Reassembly {
	/// Copies `bytes` to `offset`. False when it would go past `MAX_HELLO`.
	fn insert(&mut self, offset: usize, bytes: &[u8]) -> bool {
		let Some(end) = offset.checked_add(bytes.len()).filter(|e| *e <= MAX_HELLO) else {
			return false;
		};
		if self.data.len() < end {
			self.data.resize(end, 0);
			self.filled.resize(end, false);
		}
		self.data[offset..end].copy_from_slice(bytes);
		self.filled[offset..end].iter_mut().for_each(|f| *f = true);
		true
	}

	/// Length of the contiguous bytes from the start.
	fn prefix(&self) -> usize {
		self.filled.iter().position(|f| !f).unwrap_or(self.filled.len())
	}
}

pub mod dtls {
	use super::*;

	const HANDSHAKE: u8 = 22;
	const CLIENT_HELLO: u8 = 1;
	/// ClientHello messages tracked at once (by message_seq).
	const MAX_MESSAGES: usize = 4;

	/// A DTLS handshake record (DTLS 1.0 0xfeff, 1.2 0xfefd, 1.3 uses 0xfefd too).
	pub fn looks_like(d: &[u8]) -> bool {
		d.len() >= 13 && d[0] == HANDSHAKE && d[1] == 0xfe && matches!(d[2], 0xff | 0xfd | 0xfc)
	}

	#[derive(Default)]
	pub struct Assembler {
		/// ClientHello fragments by message_seq: total length and bytes so far.
		messages: BTreeMap<u16, (usize, Reassembly)>,
	}

	impl Assembler {
		pub fn push(&mut self, datagram: &[u8]) -> Sniff {
			let mut p = datagram;
			// records: type(1) version(2) epoch(2) sequence(6) length(2) fragment
			while p.len() >= 13 {
				let (kind, epoch, len) = (p[0], u16::from_be_bytes([p[3], p[4]]), u16::from_be_bytes([p[11], p[12]]) as usize);
				if p.len() < 13 + len {
					break;
				}
				let fragment = &p[13..13 + len];
				p = &p[13 + len..];
				if kind != HANDSHAKE || epoch != 0 {
					continue;
				}
				if let Some(done) = self.fragments(fragment) {
					return done;
				}
			}
			Sniff::NeedMore
		}

		/// Handshake fragments of one record:
		/// type(1) length(3) message_seq(2) fragment_offset(3) fragment_length(3) body
		fn fragments(&mut self, mut f: &[u8]) -> Option<Sniff> {
			while f.len() >= 12 {
				let kind = f[0];
				let total = u24(&f[1..4]);
				let seq = u16::from_be_bytes([f[4], f[5]]);
				let (offset, len) = (u24(&f[6..9]), u24(&f[9..12]));
				if f.len() < 12 + len {
					return None;
				}
				let body = &f[12..12 + len];
				f = &f[12 + len..];
				if kind != CLIENT_HELLO {
					continue;
				}
				if total > MAX_HELLO || offset + len > total {
					return Some(Sniff::Done(None));
				}
				if !self.messages.contains_key(&seq) && self.messages.len() >= MAX_MESSAGES {
					continue;
				}
				let (known, message) = self.messages.entry(seq).or_insert_with(|| (total, Reassembly::default()));
				if *known != total {
					return Some(Sniff::Done(None));
				}
				message.insert(offset, body);
				if message.prefix() >= total {
					return Some(Sniff::Done(sni::hello_server_name(&message.data[..total], true)));
				}
			}
			None
		}
	}
}

pub mod quic {
	use super::*;

	pub const V1: u32 = 0x0000_0001;
	pub const V2: u32 = 0x6b33_43cf;
	/// RFC 9001 §5.2
	const SALT_V1: [u8; 20] = hex20("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");
	/// RFC 9369 §3.3.1
	const SALT_V2: [u8; 20] = hex20("0dede3def700a6db819381be6e269dcbf9bd2ed9");
	/// Datagrams' packets examined for one session (coalesced packets count each).
	const MAX_PACKETS: usize = 64;

	#[derive(Clone, Copy, Debug, PartialEq, Eq)]
	pub enum Version {
		V1,
		V2,
	}

	impl Version {
		fn of(v: u32) -> Option<Version> {
			match v {
				V1 => Some(Version::V1),
				V2 => Some(Version::V2),
				_ => None,
			}
		}

		/// The long-header packet type bits of an Initial packet.
		fn initial_type(self) -> u8 {
			match self {
				Version::V1 => 0b00,
				Version::V2 => 0b01,
			}
		}

		fn retry_type(self) -> u8 {
			match self {
				Version::V1 => 0b11,
				Version::V2 => 0b00,
			}
		}
	}

	/// A long-header Initial packet of QUIC v1 or v2.
	pub fn looks_like(d: &[u8]) -> bool {
		if d.len() < 7 || d[0] & 0xc0 != 0xc0 {
			return false;
		}
		let Some(v) = Version::of(u32::from_be_bytes([d[1], d[2], d[3], d[4]])) else { return false };
		(d[0] >> 4) & 0b11 == v.initial_type()
	}

	/// The Destination Connection ID of a datagram that starts with an Initial
	/// packet: a client starting a (new) QUIC connection.
	pub fn initial_dcid(d: &[u8]) -> Option<Vec<u8>> {
		if !looks_like(d) {
			return None;
		}
		let len = usize::from(d[5]);
		if len > 20 {
			return None;
		}
		d.get(6..6 + len).map(<[u8]>::to_vec)
	}

	/// Client Initial packet protection keys (RFC 9001 §5.2, RFC 9369 §3.3).
	#[derive(Debug, PartialEq, Eq)]
	pub struct Keys {
		pub key: [u8; 16],
		pub iv: [u8; 12],
		pub hp: [u8; 16],
	}

	struct Len(usize);

	impl hkdf::KeyType for Len {
		fn len(&self) -> usize {
			self.0
		}
	}

	/// HKDF-Expand-Label (RFC 8446 §7.1) with an empty context.
	fn expand_label(prk: &hkdf::Prk, label: &str, out: &mut [u8]) {
		let full = format!("tls13 {label}");
		let mut info = Vec::with_capacity(4 + full.len());
		info.extend_from_slice(&(out.len() as u16).to_be_bytes());
		info.push(full.len() as u8);
		info.extend_from_slice(full.as_bytes());
		info.push(0);
		prk.expand(&[&info], Len(out.len()))
			.and_then(|okm| okm.fill(out))
			.expect("HKDF-Expand of at most 32 bytes from SHA-256 cannot fail");
	}

	pub fn client_initial_keys(version: Version, dcid: &[u8]) -> Keys {
		let salt = match version {
			Version::V1 => &SALT_V1,
			Version::V2 => &SALT_V2,
		};
		let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
		let mut secret = [0u8; 32];
		expand_label(&initial, "client in", &mut secret);
		let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &secret);
		let prefix = match version {
			Version::V1 => "quic",
			Version::V2 => "quicv2",
		};
		let mut keys = Keys { key: [0; 16], iv: [0; 12], hp: [0; 16] };
		expand_label(&client, &format!("{prefix} key"), &mut keys.key);
		expand_label(&client, &format!("{prefix} iv"), &mut keys.iv);
		expand_label(&client, &format!("{prefix} hp"), &mut keys.hp);
		keys
	}

	/// The five-byte header protection mask for `sample` (RFC 9001 §5.4.3).
	pub fn header_mask(hp: &[u8; 16], sample: &[u8]) -> Option<[u8; 5]> {
		let key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, hp).ok()?;
		key.new_mask(sample).ok()
	}

	/// QUIC variable-length integer (RFC 9000 §16).
	pub fn varint(p: &mut &[u8]) -> Option<u64> {
		let first = *p.first()?;
		let len = 1usize << (first >> 6);
		if p.len() < len {
			return None;
		}
		let mut v = u64::from(first & 0x3f);
		for b in &p[1..len] {
			v = (v << 8) | u64::from(*b);
		}
		*p = &p[len..];
		Some(v)
	}

	fn take<'a>(p: &mut &'a [u8], n: u64) -> Option<&'a [u8]> {
		let n = usize::try_from(n).ok()?;
		if p.len() < n {
			return None;
		}
		let (head, rest) = p.split_at(n);
		*p = rest;
		Some(head)
	}

	/// Removes header and packet protection from one Initial packet (`packet`
	/// ends where its Length field says; `pn_offset` is where the packet number
	/// starts). The frames, or None when it does not decrypt.
	pub fn unprotect(version: Version, dcid: &[u8], packet: &[u8], pn_offset: usize) -> Option<Vec<u8>> {
		let keys = client_initial_keys(version, dcid);
		let sample = packet.get(pn_offset + 4..pn_offset + 4 + 16)?;
		let mask = header_mask(&keys.hp, sample)?;
		let first = packet[0] ^ (mask[0] & 0x0f);
		let pn_len = usize::from(first & 0x03) + 1;
		let mut header = packet.get(..pn_offset + pn_len)?.to_vec();
		header[0] = first;
		let mut pn = 0u64;
		for i in 0..pn_len {
			header[pn_offset + i] ^= mask[1 + i];
			pn = (pn << 8) | u64::from(header[pn_offset + i]);
		}
		let mut nonce = keys.iv;
		for (i, b) in pn.to_be_bytes().iter().enumerate() {
			nonce[4 + i] ^= b;
		}
		let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &keys.key).ok()?);
		let mut payload = packet[pn_offset + pn_len..].to_vec();
		let plain = key
			.open_in_place(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(&header), &mut payload)
			.ok()?;
		Some(plain.to_vec())
	}

	#[derive(Default)]
	pub struct Assembler {
		crypto: Reassembly,
		packets: usize,
	}

	impl Assembler {
		pub fn push(&mut self, datagram: &[u8]) -> Sniff {
			let mut p = datagram;
			// coalesced packets (RFC 9000 §12.2): long headers until a short one
			while !p.is_empty() && p[0] & 0x80 != 0 {
				self.packets += 1;
				if self.packets > MAX_PACKETS {
					return Sniff::Done(None);
				}
				match self.packet(&mut p) {
					Some(Some(done)) => return done,
					Some(None) => {}
					None => break,
				}
			}
			Sniff::NeedMore
		}

		/// One long-header packet from the front of `p`. None: cannot tell where
		/// it ends (the rest of the datagram is skipped); Some(Some(_)): decided.
		fn packet(&mut self, p: &mut &[u8]) -> Option<Option<Sniff>> {
			let start = *p;
			let mut r = *p;
			let first = *take(&mut r, 1)?.first()?;
			let raw = take(&mut r, 4)?;
			let version = Version::of(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))?;
			let ptype = (first >> 4) & 0b11;
			if ptype == version.retry_type() {
				return None;
			}
			let dcid_len = *take(&mut r, 1)?.first()?;
			if dcid_len > 20 {
				return None;
			}
			let dcid = take(&mut r, u64::from(dcid_len))?;
			let scid_len = *take(&mut r, 1)?.first()?;
			if scid_len > 20 {
				return None;
			}
			take(&mut r, u64::from(scid_len))?;
			let initial = ptype == version.initial_type();
			if initial {
				let token = varint(&mut r)?;
				take(&mut r, token)?;
			}
			let length = varint(&mut r)?;
			let pn_offset = start.len() - r.len();
			take(&mut r, length)?;
			let packet = &start[..start.len() - r.len()];
			*p = r;
			if !initial {
				return Some(None);
			}
			let Some(frames) = unprotect(version, dcid, packet, pn_offset) else { return Some(None) };
			Some(self.frames(&frames))
		}

		/// Frames of an Initial packet (RFC 9000 §17.2.2: PADDING, PING, ACK,
		/// CRYPTO and CONNECTION_CLOSE only).
		fn frames(&mut self, mut f: &[u8]) -> Option<Sniff> {
			while !f.is_empty() {
				let Some(kind) = varint(&mut f) else { return Some(Sniff::Done(None)) };
				let ok = match kind {
					0x00 | 0x01 => Some(()),
					0x02 | 0x03 => (|| {
						varint(&mut f)?; // largest acknowledged
						varint(&mut f)?; // delay
						let ranges = varint(&mut f)?;
						varint(&mut f)?; // first range
						for _ in 0..ranges.min(4096) {
							varint(&mut f)?;
							varint(&mut f)?;
						}
						if kind == 0x03 {
							for _ in 0..3 {
								varint(&mut f)?;
							}
						}
						Some(())
					})(),
					0x06 => (|| {
						let offset = usize::try_from(varint(&mut f)?).ok()?;
						let len = varint(&mut f)?;
						let data = take(&mut f, len)?;
						// past MAX_HELLO: the ClientHello cannot be assembled
						self.crypto.insert(offset, data).then_some(())
					})(),
					0x1c => (|| {
						varint(&mut f)?;
						varint(&mut f)?;
						let reason = varint(&mut f)?;
						take(&mut f, reason).map(|_| ())
					})(),
					_ => None,
				};
				if ok.is_none() {
					return Some(Sniff::Done(None));
				}
			}
			let have = self.crypto.prefix();
			match sni::parse_handshake(&self.crypto.data[..have]) {
				sni::Parse::Incomplete if have >= MAX_HELLO => Some(Sniff::Done(None)),
				sni::Parse::Incomplete => None,
				sni::Parse::NotTls => Some(Sniff::Done(None)),
				sni::Parse::Done(name) => Some(Sniff::Done(name)),
			}
		}
	}

	const fn hex20(s: &str) -> [u8; 20] {
		let b = s.as_bytes();
		let mut out = [0u8; 20];
		let mut i = 0;
		while i < 20 {
			out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
			i += 1;
		}
		out
	}

	const fn nibble(c: u8) -> u8 {
		match c {
			b'0'..=b'9' => c - b'0',
			b'a'..=b'f' => c - b'a' + 10,
			_ => panic!("not hex"),
		}
	}
}

fn u24(b: &[u8]) -> usize {
	(usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2])
}

#[cfg(test)]
mod tests {
	use super::quic::{client_initial_keys, header_mask, unprotect, varint, Version, V1, V2};
	use super::*;

	fn hex(s: &str) -> Vec<u8> {
		let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
		(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
	}

	const DCID: &str = "8394c8f03e515708";

	/// The ClientHello (a handshake message, no record layer) that rustls sends for `name`.
	fn tls_hello(name: &str, alpn: &[&str]) -> Vec<u8> {
		let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_root_certificates(rustls::RootCertStore::empty())
			.with_no_client_auth();
		config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
		let mut conn =
			rustls::ClientConnection::new(std::sync::Arc::new(config), name.to_string().try_into().unwrap()).unwrap();
		let mut out = vec![];
		conn.write_tls(&mut out).unwrap();
		// strip the TLS record headers
		let mut hs = vec![];
		let mut p = &out[..];
		while p.len() >= 5 {
			let len = u16::from_be_bytes([p[3], p[4]]) as usize;
			hs.extend_from_slice(&p[5..5 + len]);
			p = &p[5 + len..];
		}
		hs
	}

	// ---- QUIC: the RFC's sample packets ----

	#[test]
	fn rfc9001_initial_keys() {
		let k = client_initial_keys(Version::V1, &hex(DCID));
		assert_eq!(k.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
		assert_eq!(k.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
		assert_eq!(k.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
		// header protection (A.2)
		let mask = header_mask(&k.hp, &hex("d1b1c98dd7689fb8ec11d242b123dc9b")).unwrap();
		assert_eq!(mask.to_vec(), hex("437b9aec36"));
	}

	#[test]
	fn rfc9369_initial_keys() {
		let k = client_initial_keys(Version::V2, &hex(DCID));
		assert_eq!(k.key.to_vec(), hex("8b1a0bc121284290a29e0971b5cd045d"));
		assert_eq!(k.iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
		assert_eq!(k.hp.to_vec(), hex("45b95e15235d6f45a6b19cbcb0294ba9"));
		let mask = header_mask(&k.hp, &hex("ffe67b6abcdb4298b485dd04de806071")).unwrap();
		assert_eq!(mask.to_vec(), hex("94a0c95e80"));
	}

	/// The start of the CRYPTO frame in the RFC's sample client Initial (both
	/// versions): type 06, offset 0, length 0xf1, then the ClientHello header.
	const RFC_CRYPTO_START: &str = "060040f1010000ed";

	#[test]
	fn rfc9001_client_initial_decrypts_to_example_com() {
		let packet = hex(include_str!("../../tests/fixtures/quic/rfc9001-client-initial.hex"));
		assert_eq!(packet.len(), 1200);
		// header c0 00000001 08 <dcid> 00 00 449e: packet number at 18
		let frames = unprotect(Version::V1, &hex(DCID), &packet, 18).expect("decrypts with the RFC's keys");
		assert_eq!(frames.len(), 1162, "1182 minus the packet number and the tag");
		assert_eq!(&frames[..8], &hex(RFC_CRYPTO_START)[..]);
		assert!(frames[4 + 0xf1..].iter().all(|b| *b == 0), "the rest is PADDING");
		let mut s = Sniffer::default();
		assert_eq!(s.push(&packet), Sniff::Done(Some("example.com".into())));
	}

	#[test]
	fn rfc9369_client_initial_decrypts_to_example_com() {
		let packet = hex(include_str!("../../tests/fixtures/quic/rfc9369-client-initial.hex"));
		assert!(quic::looks_like(&packet));
		assert_eq!(Sniffer::default().push(&packet), Sniff::Done(Some("example.com".into())));
		// the v1 keys do not open it
		assert!(unprotect(Version::V1, &hex(DCID), &packet, 18).is_none());
	}

	#[test]
	fn a_corrupted_rfc_packet_gives_no_name() {
		let mut packet = hex(include_str!("../../tests/fixtures/quic/rfc9001-client-initial.hex"));
		packet[600] ^= 1; // fails the AEAD tag
		let mut s = Sniffer::default();
		assert_eq!(s.push(&packet), Sniff::NeedMore, "an Initial that does not decrypt is skipped");
		// a later, good one still works
		let good = hex(include_str!("../../tests/fixtures/quic/rfc9001-client-initial.hex"));
		assert_eq!(s.push(&good), Sniff::Done(Some("example.com".into())));
	}

	// ---- QUIC: packets built here (the inverse of `unprotect`) ----

	fn put_varint(out: &mut Vec<u8>, v: u64) {
		match v {
			0..=63 => out.push(v as u8),
			64..=16383 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
			_ => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
		}
	}

	fn crypto_frame(offset: usize, data: &[u8]) -> Vec<u8> {
		let mut f = vec![0x06];
		put_varint(&mut f, offset as u64);
		put_varint(&mut f, data.len() as u64);
		f.extend_from_slice(data);
		f
	}

	/// A protected client Initial carrying `frames` (padded to at least 1200 bytes).
	fn initial(version: Version, dcid: &[u8], pn: u32, frames: &[u8], token: &[u8]) -> Vec<u8> {
		let keys = client_initial_keys(version, dcid);
		let mut payload = frames.to_vec();
		// enough for the header protection sample, and the 1200-byte minimum
		let min = 1200usize.saturating_sub(64).max(20);
		if payload.len() < min {
			payload.resize(min, 0);
		}
		let ptype = match version {
			Version::V1 => 0b00,
			Version::V2 => 0b01,
		};
		let vnum = match version {
			Version::V1 => V1,
			Version::V2 => V2,
		};
		let mut header = vec![0xc0 | (ptype << 4) | 0x03];
		header.extend_from_slice(&vnum.to_be_bytes());
		header.push(dcid.len() as u8);
		header.extend_from_slice(dcid);
		header.push(0); // no source connection id
		put_varint(&mut header, token.len() as u64);
		header.extend_from_slice(token);
		let length = 4 + payload.len() + 16;
		header.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
		let pn_offset = header.len();
		header.extend_from_slice(&pn.to_be_bytes());
		let mut nonce = keys.iv;
		for (i, b) in u64::from(pn).to_be_bytes().iter().enumerate() {
			nonce[4 + i] ^= b;
		}
		let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &keys.key).unwrap());
		key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(&header), &mut payload).unwrap();
		let mut packet = header;
		packet.extend_from_slice(&payload);
		let mask = header_mask(&keys.hp, &packet[pn_offset + 4..pn_offset + 20]).unwrap();
		packet[0] ^= mask[0] & 0x0f;
		for i in 0..4 {
			packet[pn_offset + i] ^= mask[1 + i];
		}
		packet
	}

	#[test]
	fn builder_matches_the_rfc_packet() {
		// the same frames, packet number and keys give the RFC's bytes
		let rfc = hex(include_str!("../../tests/fixtures/quic/rfc9001-client-initial.hex"));
		let frames = unprotect(Version::V1, &hex(DCID), &rfc, 18).unwrap();
		let built = initial(Version::V1, &hex(DCID), 2, &frames, b"");
		assert_eq!(built, rfc);
	}

	#[test]
	fn quic_hello_split_over_two_initials_in_any_order() {
		let hello = tls_hello("big.example", &["x".repeat(200).as_str(); 12]);
		assert!(hello.len() > 2000, "{}", hello.len());
		let dcid = [7u8; 8];
		let (a, b) = hello.split_at(1100);
		let p0 = initial(Version::V1, &dcid, 0, &crypto_frame(0, a), b"");
		let p1 = initial(Version::V1, &dcid, 1, &crypto_frame(a.len(), b), b"");
		let mut s = Sniffer::default();
		assert_eq!(s.push(&p0), Sniff::NeedMore);
		assert_eq!(s.push(&p1), Sniff::Done(Some("big.example".into())));
		// the second part first
		let mut s = Sniffer::default();
		assert_eq!(s.push(&p1), Sniff::NeedMore);
		assert_eq!(s.push(&p0), Sniff::Done(Some("big.example".into())));
	}

	#[test]
	fn quic_frames_mixed_overlapping_and_coalesced() {
		let hello = tls_hello("mixed.example", &["h3"]);
		let dcid = [1u8, 2, 3, 4, 5];
		// PING, ACK, CRYPTO parts out of order with an overlap, PADDING in between
		let mut frames = vec![0x01];
		frames.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00]);
		frames.extend_from_slice(&crypto_frame(40, &hello[40..]));
		frames.push(0x00);
		frames.extend_from_slice(&crypto_frame(0, &hello[..60]));
		let p = initial(Version::V2, &dcid, 5, &frames, b"token-from-a-retry");
		assert_eq!(Sniffer::default().push(&p), Sniff::Done(Some("mixed.example".into())));
		// two Initials coalesced in one datagram, then a short-header packet (ignored)
		let (a, b) = hello.split_at(30);
		let mut datagram = initial(Version::V1, &dcid, 0, &crypto_frame(0, a), b"");
		datagram.extend_from_slice(&initial(Version::V1, &dcid, 1, &crypto_frame(30, b), b""));
		datagram.extend_from_slice(&[0x40, 1, 2, 3, 4]);
		assert_eq!(Sniffer::default().push(&datagram), Sniff::Done(Some("mixed.example".into())));
	}

	#[test]
	fn quic_without_server_name_or_with_a_gap() {
		let dcid = [9u8; 8];
		let hello = tls_hello("gap.example", &[]);
		// a gap at the start is never filled: still waiting
		let p = initial(Version::V1, &dcid, 0, &crypto_frame(10, &hello[10..]), b"");
		let mut s = Sniffer::default();
		assert_eq!(s.push(&p), Sniff::NeedMore);
		// an IP literal is not sent as SNI by rustls: done, no name
		let no_sni = tls_hello("192.0.2.1", &[]);
		let p = initial(Version::V1, &dcid, 0, &crypto_frame(0, &no_sni), b"");
		assert_eq!(Sniffer::default().push(&p), Sniff::Done(None));
		// CRYPTO that is not a ClientHello
		let p = initial(Version::V1, &dcid, 0, &crypto_frame(0, &[0x02, 0, 0, 4, 1, 2, 3, 4]), b"");
		assert_eq!(Sniffer::default().push(&p), Sniff::Done(None));
		// a frame not allowed in Initial packets (STREAM)
		let p = initial(Version::V1, &dcid, 0, &[0x08, 0x00, 0x01, 0x61], b"");
		assert_eq!(Sniffer::default().push(&p), Sniff::Done(None));
		// CRYPTO beyond the size limit
		let p = initial(Version::V1, &dcid, 0, &crypto_frame(1 << 20, b"x"), b"");
		assert_eq!(Sniffer::default().push(&p), Sniff::Done(None));
	}

	#[test]
	fn quic_non_initial_first_packets() {
		let dcid = [3u8; 8];
		let hello = tls_hello("later.example", &[]);
		let good = initial(Version::V1, &dcid, 0, &crypto_frame(0, &hello), b"");
		// a Handshake-type (0b10) long header (no token field) first: not recognised as an Initial start
		let mut handshake = good.clone();
		handshake[0] = (handshake[0] & 0xcf) | (0b10 << 4);
		handshake.remove(1 + 4 + 1 + dcid.len() + 1); // the (empty) token's length
		assert_eq!(Sniffer::default().push(&handshake), Sniff::Unknown);
		// but after an Initial, other long-header packets in a datagram are skipped over
		let mut s = Sniffer::default();
		let (a, b) = hello.split_at(50);
		assert_eq!(s.push(&initial(Version::V1, &dcid, 0, &crypto_frame(0, a), b"")), Sniff::NeedMore);
		let mut dg = handshake.clone();
		dg.extend_from_slice(&initial(Version::V1, &dcid, 1, &crypto_frame(50, b), b""));
		assert_eq!(s.push(&dg), Sniff::Done(Some("later.example".into())));
		// short header / version negotiation / unknown version first: not QUIC we can read
		assert_eq!(Sniffer::default().push(&[0x40, 1, 2, 3, 4, 5, 6, 7]), Sniff::Unknown);
		assert_eq!(Sniffer::default().push(&[0xc0, 0, 0, 0, 0, 0, 0, 0]), Sniff::Unknown);
		assert_eq!(Sniffer::default().push(&[0xc0, 0xff, 0, 0, 0x1d, 0, 0, 0]), Sniff::Unknown);
	}

	#[test]
	fn varints() {
		for (bytes, v) in [(&[0x25][..], 37u64), (&[0x7b, 0xbd], 15293), (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
			(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c], 151_288_809_941_952_652)]
		{
			let mut p = bytes;
			assert_eq!(varint(&mut p), Some(v));
			assert!(p.is_empty());
		}
		let mut short: &[u8] = &[0x7b];
		assert_eq!(varint(&mut short), None);
	}

	// ---- DTLS ----

	/// A DTLS ClientHello body (after the handshake header) for `name`.
	fn dtls_hello_body(name: Option<&str>, cookie: &[u8], version: [u8; 2]) -> Vec<u8> {
		let mut b = version.to_vec();
		b.extend_from_slice(&[0x11; 32]); // random
		b.push(0); // session id
		b.push(cookie.len() as u8);
		b.extend_from_slice(cookie);
		b.extend_from_slice(&[0, 2, 0xc0, 0x2b]); // cipher suites
		b.extend_from_slice(&[1, 0]); // compression
		let mut exts = vec![];
		if let Some(n) = name {
			let mut sn = vec![0];
			sn.extend_from_slice(&(n.len() as u16).to_be_bytes());
			sn.extend_from_slice(n.as_bytes());
			let mut list = (sn.len() as u16).to_be_bytes().to_vec();
			list.extend_from_slice(&sn);
			exts.extend_from_slice(&[0, 0]);
			exts.extend_from_slice(&(list.len() as u16).to_be_bytes());
			exts.extend_from_slice(&list);
		}
		// supported_versions with DTLS 1.3 (0xfefc) — ignored, just present
		exts.extend_from_slice(&[0, 43, 0, 3, 2, 0xfe, 0xfc]);
		b.extend_from_slice(&(exts.len() as u16).to_be_bytes());
		b.extend_from_slice(&exts);
		b
	}

	/// Handshake fragments of a ClientHello body, each in its own record.
	fn dtls_records(body: &[u8], seq: u16, cuts: &[usize], record_version: [u8; 2]) -> Vec<Vec<u8>> {
		let mut bounds = vec![0];
		bounds.extend_from_slice(cuts);
		bounds.push(body.len());
		bounds
			.windows(2)
			.map(|w| {
				let frag = &body[w[0]..w[1]];
				let mut hs = vec![1];
				hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
				hs.extend_from_slice(&seq.to_be_bytes());
				hs.extend_from_slice(&(w[0] as u32).to_be_bytes()[1..]);
				hs.extend_from_slice(&(frag.len() as u32).to_be_bytes()[1..]);
				hs.extend_from_slice(frag);
				let mut rec = vec![22, record_version[0], record_version[1], 0, 0, 0, 0, 0, 0, 0, seq as u8];
				rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
				rec.extend_from_slice(&hs);
				rec
			})
			.collect()
	}

	#[test]
	fn dtls_single_record_12_and_13() {
		for version in [[0xfe, 0xfd], [0xfe, 0xff]] {
			let body = dtls_hello_body(Some("Turn.Example"), b"", version);
			let recs = dtls_records(&body, 0, &[], version);
			assert!(dtls::looks_like(&recs[0]));
			assert_eq!(Sniffer::default().push(&recs[0]), Sniff::Done(Some("turn.example".into())));
		}
	}

	#[test]
	fn dtls_fragments_out_of_order_across_datagrams() {
		let body = dtls_hello_body(Some("frag.example"), b"", [0xfe, 0xfd]);
		let recs = dtls_records(&body, 0, &[20, 45], [0xfe, 0xfd]);
		let mut s = Sniffer::default();
		assert_eq!(s.push(&recs[2]), Sniff::NeedMore);
		assert_eq!(s.push(&recs[0]), Sniff::NeedMore);
		assert_eq!(s.push(&recs[1]), Sniff::Done(Some("frag.example".into())));
		// all three records in one datagram
		let one: Vec<u8> = recs.concat();
		assert_eq!(Sniffer::default().push(&one), Sniff::Done(Some("frag.example".into())));
		// overlapping fragments
		let mut s = Sniffer::default();
		let overlap = dtls_records(&body, 0, &[30], [0xfe, 0xfd]);
		let again = dtls_records(&body, 0, &[10, 50], [0xfe, 0xfd]);
		assert_eq!(s.push(&again[1]), Sniff::NeedMore);
		assert_eq!(s.push(&overlap[0]), Sniff::NeedMore);
		assert_eq!(s.push(&overlap[1]), Sniff::Done(Some("frag.example".into())));
	}

	#[test]
	fn dtls_hello_verify_retry_and_no_name() {
		// the second ClientHello (after HelloVerifyRequest) carries a cookie
		let body = dtls_hello_body(Some("cookie.example"), &[0xab; 20], [0xfe, 0xfd]);
		let recs = dtls_records(&body, 1, &[], [0xfe, 0xfd]);
		assert_eq!(Sniffer::default().push(&recs[0]), Sniff::Done(Some("cookie.example".into())));
		let body = dtls_hello_body(None, b"", [0xfe, 0xfd]);
		let recs = dtls_records(&body, 0, &[], [0xfe, 0xfd]);
		assert_eq!(Sniffer::default().push(&recs[0]), Sniff::Done(None));
	}

	#[test]
	fn dtls_bad_lengths_and_other_records() {
		let body = dtls_hello_body(Some("x.example"), b"", [0xfe, 0xfd]);
		let mut rec = dtls_records(&body, 0, &[], [0xfe, 0xfd]).remove(0);
		// fragment beyond its declared total
		let mut bad = rec.clone();
		bad[13 + 9..13 + 12].copy_from_slice(&[0xff, 0xff, 0xff]);
		assert_eq!(Sniffer::default().push(&bad), Sniff::NeedMore, "truncated fragment is ignored");
		let mut huge = rec.clone();
		huge[13 + 1..13 + 4].copy_from_slice(&[0x10, 0x00, 0x00]);
		assert_eq!(Sniffer::default().push(&huge), Sniff::Done(None), "a 1 MiB ClientHello is not assembled");
		// an epoch-1 record (encrypted) and a ChangeCipherSpec are skipped
		let mut epoch1 = rec.clone();
		epoch1[4] = 1;
		assert_eq!(Sniffer::default().push(&epoch1), Sniff::NeedMore);
		// record length longer than the datagram
		rec.truncate(20);
		assert_eq!(Sniffer::default().push(&rec), Sniff::NeedMore);
	}

	// ---- anything else ----

	#[test]
	fn other_protocols_are_unknown() {
		for d in [&b""[..], b"\x00", b"GET / HTTP/1.1\r\n", &[0x16, 0x03, 0x01, 0, 5, 1, 0, 0, 1, 0], &[0x80; 40], &[0x00; 12]] {
			assert_eq!(Sniffer::default().push(d), Sniff::Unknown, "{d:?}");
		}
		// once decided, later datagrams do not change it
		let mut s = Sniffer::default();
		assert_eq!(s.push(b"hello"), Sniff::Unknown);
		assert_eq!(s.push(&hex(include_str!("../../tests/fixtures/quic/rfc9001-client-initial.hex"))), Sniff::Unknown);
	}

	/// Random and mutated input never panics and always ends in one of the three answers.
	#[test]
	fn garbage_never_panics() {
		let mut seed = 0x2545_f491_4f6c_dd1du64;
		let mut next = move || {
			seed ^= seed << 13;
			seed ^= seed >> 7;
			seed ^= seed << 17;
			seed
		};
		let rfc = hex(include_str!("../../tests/fixtures/quic/rfc9001-client-initial.hex"));
		let body = dtls_hello_body(Some("fuzz.example"), b"", [0xfe, 0xfd]);
		let dtls_rec = dtls_records(&body, 0, &[], [0xfe, 0xfd]).remove(0);
		for i in 0..20_000 {
			let base: &[u8] = match i % 3 {
				0 => &rfc,
				1 => &dtls_rec,
				_ => &[],
			};
			let len = if base.is_empty() { (next() % 1500) as usize } else { base.len() };
			let mut d: Vec<u8> = if base.is_empty() { (0..len).map(|_| next() as u8).collect() } else { base.to_vec() };
			// flip a few bytes, maybe truncate
			for _ in 0..(next() % 4) {
				if !d.is_empty() {
					let at = (next() as usize) % d.len();
					d[at] = next() as u8;
				}
			}
			if next() % 4 == 0 && !d.is_empty() {
				d.truncate((next() as usize) % d.len());
			}
			let mut s = Sniffer::default();
			let _ = s.push(&d);
			let _ = s.push(&d);
		}
	}
}
