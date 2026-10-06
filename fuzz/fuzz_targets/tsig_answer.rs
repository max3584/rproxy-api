//! Answers to RFC 2136 updates (`acme::rfc2136::verify_answer`): the TSIG
//! record is found and checked in whatever a DNS server (or an attacker on the
//! path) sends. Nothing may panic, and nothing unsigned may pass.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rproxy_api::acme::rfc2136::{verify_answer, Algorithm, TsigKey};

fuzz_target!(|data: &[u8]| {
	let key = TsigKey { name: "rproxy".into(), algorithm: Algorithm::HmacSha256, secret: b"fuzz-secret".to_vec() };
	// the fuzzer cannot forge an HMAC-SHA256 under a secret it does not know
	assert!(verify_answer(data, &[7; 32], &key, 1_700_000_000).is_err());
});
