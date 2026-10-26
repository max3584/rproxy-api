//! The first datagrams of a UDP session (`tls::udp_sni`, `tls.mode: sni` on udp):
//! DTLS ClientHello fragments and QUIC v1 / v2 Initial packets.
//!
//! Input: datagrams, each prefixed with its length (16 bits, big-endian). The same
//! bytes are also read as fragments (offset, length) of a real DTLS ClientHello, to
//! drive the reassembly (#332): in any order, overlapping, empty, sent again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rproxy_api::tls::udp_sni::{dtls, quic, Sniff, Sniffer};

const MAX_DATAGRAMS: usize = 64;

fn datagrams(mut data: &[u8]) -> Vec<&[u8]> {
	let mut out = vec![];
	while data.len() >= 2 && out.len() < MAX_DATAGRAMS {
		let n = usize::from(u16::from_be_bytes([data[0], data[1]])).min(data.len() - 2);
		out.push(&data[2..2 + n]);
		data = &data[2 + n..];
	}
	out
}

/// A DTLS 1.2 ClientHello body for `name`.
fn hello_body(name: &str) -> Vec<u8> {
	let mut b = vec![0xfe, 0xfd];
	b.extend_from_slice(&[0x11; 32]); // random
	b.extend_from_slice(&[0, 0]); // session id, cookie
	b.extend_from_slice(&[0, 2, 0xc0, 0x2b, 1, 0]); // cipher suites, compression
	let mut sn = vec![0];
	sn.extend_from_slice(&(name.len() as u16).to_be_bytes());
	sn.extend_from_slice(name.as_bytes());
	let mut ext = vec![0, 0];
	ext.extend_from_slice(&(sn.len() as u16 + 2).to_be_bytes());
	ext.extend_from_slice(&(sn.len() as u16).to_be_bytes());
	ext.extend_from_slice(&sn);
	// padding so that the message has room for many fragments
	ext.extend_from_slice(&[0, 21, 0x01, 0x00]);
	ext.extend_from_slice(&[0; 256]);
	b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
	b.extend_from_slice(&ext);
	b
}

/// A DTLS record carrying the handshake fragment `body[from..to]` of a ClientHello.
fn record(body: &[u8], from: usize, to: usize) -> Vec<u8> {
	let mut hs = vec![1];
	hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
	hs.extend_from_slice(&[0, 0]);
	hs.extend_from_slice(&(from as u32).to_be_bytes()[1..]);
	hs.extend_from_slice(&((to - from) as u32).to_be_bytes()[1..]);
	hs.extend_from_slice(&body[from..to]);
	let mut rec = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0];
	rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
	rec.extend_from_slice(&hs);
	rec
}

/// Fragments (3 bytes each: offset, length, how many records go in the datagram) of a
/// real ClientHello: the name comes exactly when they cover it, never before; with at
/// most 64 fragments no cap of the reassembly is reached.
fn fragments(data: &[u8]) {
	const NAME: &str = "fuzz.example";
	let body = hello_body(NAME);
	let mut covered = vec![false; body.len()];
	let mut a = dtls::Assembler::default();
	let mut gram = vec![];
	for f in data.chunks_exact(3).take(64) {
		let from = usize::from(f[0]) * body.len() / 256;
		let to = (from + usize::from(f[1])).min(body.len());
		gram.extend_from_slice(&record(&body, from, to));
		covered[from..to].iter_mut().for_each(|c| *c = true);
		// several records in one datagram now and then
		if f[2] & 3 != 0 {
			continue;
		}
		let got = a.push(&gram);
		gram.clear();
		if covered.iter().all(|c| *c) {
			assert_eq!(got, Sniff::Done(Some(NAME.into())));
			return;
		}
		assert_eq!(got, Sniff::NeedMore);
	}
}

fuzz_target!(|data: &[u8]| {
	fragments(data);
	let grams = datagrams(data);
	let mut sniffer = Sniffer::default();
	let mut decided: Option<Sniff> = None;
	for d in &grams {
		let _ = quic::initial_dcid(d);
		let got = sniffer.push(d);
		match &decided {
			// once decided, the answer never changes
			Some(first) => assert_eq!(&got, first),
			None if got != Sniff::NeedMore => decided = Some(got),
			None => {}
		}
	}
	// the assemblers on their own, without the first-datagram check
	let mut d = dtls::Assembler::default();
	let mut q = quic::Assembler::default();
	for g in &grams {
		let _ = d.push(g);
		let _ = q.push(g);
	}
	// the whole input as one datagram
	let _ = Sniffer::default().push(data);
});
