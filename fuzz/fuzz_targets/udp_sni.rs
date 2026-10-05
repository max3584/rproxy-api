//! The first datagrams of a UDP session (`tls::udp_sni`, `tls.mode: sni` on udp):
//! DTLS ClientHello fragments and QUIC v1 / v2 Initial packets.
//!
//! Input: datagrams, each prefixed with its length (16 bits, big-endian).
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

fuzz_target!(|data: &[u8]| {
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
