//! DNS responses (`acme::dnsq`): what the name servers answer while DNS-01
//! follows the CNAME of `_acme-challenge`, looks for the zone, and waits for
//! the TXT record. Names may be compressed (pointers, which can loop); nothing
//! may panic or read past the message, and the names that come out are
//! bounded.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rproxy_api::acme::dnsq::{parse_response, Data};

fuzz_target!(|data: &[u8]| {
	if let Some(r) = parse_response(data) {
		for rec in r.answers.iter().chain(&r.authority) {
			assert!(rec.name.len() <= 255 + 64, "{}", rec.name.len());
			if let Data::Cname(target) = &rec.data {
				assert!(target.len() <= 255 + 64);
			}
			if let Data::Txt(t) = &rec.data {
				assert!(t.len() <= data.len());
			}
		}
		assert_eq!(parse_response(data), Some(r), "the same bytes, the same answer");
	}
});
