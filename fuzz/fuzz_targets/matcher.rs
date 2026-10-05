//! The `match` expressions of L7 routes (`l7::matcher`), parsed from settings
//! files and the API, and evaluated against a request.
//!
//! Input (UTF-8): the expression, then one per line: host, path, query, method,
//! a header (`name: value`) and the client IP.
//!
//! Parsed and evaluated on a thread with tokio's 2 MiB stack, where the API
//! handlers and the request handling run (libFuzzer's own thread has 8 MiB).
#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use rproxy_api::l7::matcher::{Matcher, RequestInfo};

fuzz_target!(|data: &[u8]| {
	let Ok(text) = std::str::from_utf8(data) else { return };
	let text = text.to_string();
	std::thread::Builder::new()
		.stack_size(2 * 1024 * 1024)
		.spawn(move || run(&text))
		.unwrap()
		.join()
		.unwrap();
});

fn run(text: &str) {
	let mut lines = text.split('\n');
	let expr = lines.next().unwrap_or("");
	let mut field = || lines.next().unwrap_or("");
	let (host, path, query, method) = (field(), field(), field(), field());
	let headers: Vec<(String, String)> = field()
		.split_once(':')
		.map(|(n, v)| vec![(n.trim().to_ascii_lowercase(), v.trim().to_string())])
		.unwrap_or_default();
	let client = field().parse::<IpAddr>().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
	let _ = Matcher::default_priority(expr);
	if let Ok(m) = Matcher::parse(expr) {
		let request = RequestInfo { host, path, query, method, headers: &headers, client };
		let _ = m.matches(&request);
	}
}
