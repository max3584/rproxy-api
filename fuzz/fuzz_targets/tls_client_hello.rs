//! TLS ClientHello (`tls::sni`): the records a TCP client sends first, read before
//! anything is decrypted (`tls.mode: sni`, `passthrough` routes of `terminate`).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rproxy_api::tls::sni::{hello_server_name, parse_client_hello, parse_handshake, Parse};

fn check_name(name: &Option<String>) {
	if let Some(n) = name {
		assert_eq!(n, &n.to_ascii_lowercase(), "server names are lower-cased");
	}
}

fuzz_target!(|data: &[u8]| {
	let whole = parse_client_hello(data);
	if let Parse::Done(name) = &whole {
		check_name(name);
		// more bytes after a complete ClientHello do not change the answer
		let mut more = data.to_vec();
		more.extend_from_slice(b"\x17\x03\x03\x00\x01x");
		assert_eq!(parse_client_hello(&more), whole);
	}
	if let Parse::Done(name) = parse_handshake(data) {
		check_name(&name);
	}
	check_name(&hello_server_name(data, false));
	check_name(&hello_server_name(data, true));
});
