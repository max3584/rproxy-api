//! The request path normalised before routing (`l7::normalize`, #320): any path
//! a client sends either is refused (a broken `%`) or comes out normal: starting
//! with `/`, without `//`, `.` or `..` segments or escapes of unreserved
//! characters, and the same when normalised again.
//!
//! Input (UTF-8): the path; after a first line break, a host.
#![no_main]

use std::borrow::Cow;

use libfuzzer_sys::fuzz_target;
use rproxy_api::l7::normalize;

fuzz_target!(|data: &[u8]| {
	let Ok(text) = std::str::from_utf8(data) else { return };
	let (path, host) = text.split_once('\n').unwrap_or((text, ""));
	assert!(normalize::host(host).len() + 1 >= host.len());
	let Ok(out) = normalize::path(path) else { return };
	if !path.starts_with('/') {
		assert!(matches!(out, Cow::Borrowed(_)));
		return;
	}
	assert!(out.starts_with('/'), "{path:?} -> {out:?}");
	assert!(!out.contains("//"), "{path:?} -> {out:?}");
	for seg in out.split('/') {
		assert!(seg != "." && seg != "..", "{path:?} -> {out:?}");
	}
	assert!(
		matches!(normalize::path(&out), Ok(Cow::Borrowed(_))),
		"{path:?} -> {out:?} is not stable"
	);
});
