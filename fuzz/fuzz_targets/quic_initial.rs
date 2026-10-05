//! QUIC v1 / v2 Initial packets (`tls::udp_sni`) with valid protection: the fuzzer
//! chooses the frames, this target encrypts them with the client Initial keys
//! (RFC 9001 §5, RFC 9369 §3.3), so the frame parser and the CRYPTO reassembly
//! behind the AEAD are reached (random bytes almost never decrypt).
//!
//! Input: flags (bit 0: v2), DCID length (% 21), DCID, then packets: packet
//! number (1 byte), frames length (16 bits), frames.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ring::aead;
use rproxy_api::tls::udp_sni::quic::{client_initial_keys, header_mask, Version, V1, V2};
use rproxy_api::tls::udp_sni::{Sniff, Sniffer};

const MAX_PACKETS: usize = 16;
/// The Length field is written in two bytes.
const MAX_FRAMES: usize = 16000;

fn put_varint(out: &mut Vec<u8>, v: u64) {
	match v {
		0..=63 => out.push(v as u8),
		64..=16383 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
		_ => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
	}
}

/// A protected client Initial carrying `frames` (the builder of the unit tests in
/// src/tls/udp_sni.rs).
fn initial(version: Version, dcid: &[u8], pn: u32, frames: &[u8]) -> Vec<u8> {
	let keys = client_initial_keys(version, dcid);
	let mut payload = frames.to_vec();
	// room for the header protection sample, and the 1200-byte minimum
	if payload.len() < 1136 {
		payload.resize(1136, 0);
	}
	let (ptype, vnum) = match version {
		Version::V1 => (0b00, V1),
		Version::V2 => (0b01, V2),
	};
	let mut header = vec![0xc0 | (ptype << 4) | 0x03];
	header.extend_from_slice(&vnum.to_be_bytes());
	header.push(dcid.len() as u8);
	header.extend_from_slice(dcid);
	header.push(0); // no source connection id
	put_varint(&mut header, 0); // no token
	let length = 4 + payload.len() + 16;
	header.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
	let pn_offset = header.len();
	header.extend_from_slice(&pn.to_be_bytes());
	let mut nonce = keys.iv;
	for (i, b) in u64::from(pn).to_be_bytes().iter().enumerate() {
		nonce[4 + i] ^= b;
	}
	let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &keys.key).unwrap());
	key.seal_in_place_append_tag(aead::Nonce::assume_unique_for_key(nonce), aead::Aad::from(&header), &mut payload)
		.unwrap();
	let mut packet = header;
	packet.extend_from_slice(&payload);
	let mask = header_mask(&keys.hp, &packet[pn_offset + 4..pn_offset + 20]).unwrap();
	packet[0] ^= mask[0] & 0x0f;
	for i in 0..4 {
		packet[pn_offset + i] ^= mask[1 + i];
	}
	packet
}

fuzz_target!(|data: &[u8]| {
	let [flags, dcid_len, rest @ ..] = data else { return };
	let version = if flags & 1 == 1 { Version::V2 } else { Version::V1 };
	let dcid_len = usize::from(*dcid_len % 21).min(rest.len());
	let (dcid, mut rest) = rest.split_at(dcid_len);
	let mut sniffer = Sniffer::default();
	let mut decided: Option<Sniff> = None;
	let mut packets = 0;
	while rest.len() >= 3 && packets < MAX_PACKETS {
		packets += 1;
		let pn = u32::from(rest[0]);
		let n = usize::from(u16::from_be_bytes([rest[1], rest[2]])).min(rest.len() - 3).min(MAX_FRAMES);
		let frames = &rest[3..3 + n];
		rest = &rest[3 + n..];
		let got = sniffer.push(&initial(version, dcid, pn, frames));
		match &decided {
			Some(first) => assert_eq!(&got, first),
			None if got != Sniff::NeedMore => decided = Some(got),
			None => {}
		}
	}
});
