//! Reading PROXY protocol v1 / v2 headers (`net::proxy_in`, #296): what a front end
//! in a rule's `proxy_protocol.from` sends before anything else. Any bytes: no panic,
//! a header never longer than the limits (107 bytes for v1, 16 + 4096 for v2) or than
//! the input, the same answer from the header's own bytes, `More` for every shorter
//! prefix, agreement with `classify`, and the addresses of a header written back by
//! rproxy's own writer (`net::source`) read back the same.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rproxy_api::net::proxy_in::{classify, parse, Parsed, Start, Version, V1_MAX, V2_MAX};
use rproxy_api::net::source::{proxy_v1_header, proxy_v2_header};

fuzz_target!(|data: &[u8]| {
	let parsed = parse(data);
	let start = classify(data);
	match parsed {
		Parsed::NotHeader => assert_eq!(start, Start::Plain),
		Parsed::More => {
			assert!(data.len() < V2_MAX, "a decision is made within the longest header");
			assert!(start == Start::More || matches!(start, Start::Header(_)));
		}
		Parsed::Invalid(_) => assert!(matches!(start, Start::Header(_))),
		Parsed::Header(h) => {
			assert_eq!(start, Start::Header(h.version));
			assert!(h.len <= data.len());
			match h.version {
				Version::V1 => assert!(h.len <= V1_MAX),
				Version::V2 => assert!((16..=V2_MAX).contains(&h.len)),
			}
			// the header alone says the same, and every prefix of it asks for more
			assert_eq!(parse(&data[..h.len]), parsed);
			assert_eq!(parse(&data[..h.len - 1]), Parsed::More);
			if let Some((src, dst)) = h.addrs {
				assert_eq!(src.is_ipv4(), dst.is_ipv4(), "one family");
				for written in [proxy_v1_header(src, dst), proxy_v2_header(src, dst)] {
					match parse(&written) {
						Parsed::Header(back) => {
							assert_eq!(back.len, written.len());
							assert_eq!(back.addrs, Some((src, dst)));
						}
						other => panic!("rproxy's own header for {src} -> {dst} reads as {other:?}"),
					}
				}
			}
		}
	}
});
