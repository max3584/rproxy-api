//! The http(s) URLs rproxy connects to (`net::url::parse`, #324): from settings,
//! the API and the internet (an OIDC provider's discovery document, an ACME
//! directory). Whatever is accepted names a host and a port between 1 and 65535
//! that `http::Uri` reads the same way, and reads the same again.
//!
//! Input: the URL as bytes (UTF-8).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rproxy_api::net::url::parse;

fuzz_target!(|data: &[u8]| {
	let Ok(text) = std::str::from_utf8(data) else { return };
	let Ok(u) = parse(text) else { return };
	assert!(u.port > 0 && !u.host.is_empty(), "{text:?}");
	assert!(!u.host.contains('%') && !text.contains('@') && !text.contains('\\'), "{text:?}");
	let authority = u.uri.authority().expect("an authority");
	assert_eq!(authority.port_u16().unwrap_or(if u.https { 443 } else { 80 }), u.port, "{text:?}");
	assert_eq!(authority.host().trim_matches(|c| c == '[' || c == ']'), u.host, "{text:?}");
	let again = parse(&u.uri.to_string()).expect("reads again");
	assert_eq!((again.https, again.host, again.port), (u.https, u.host, u.port), "{text:?}");
});
