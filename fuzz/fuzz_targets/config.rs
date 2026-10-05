//! Settings files (`config`): YAML or JSON parsed into a `ConfigDoc` and checked,
//! then every rule validated as at startup (`RuleRequest::validate`), with this
//! build's features and with all of them. Nothing here opens files or sockets.
//!
//! Input: 0 (even) = YAML, 1 (odd) = JSON, then the document (UTF-8).
#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;
use rproxy_api::config::ConfigDoc;
use rproxy_api::core::rule::{Caps, Features};

fuzz_target!(|data: &[u8]| {
	let [kind, text @ ..] = data else { return };
	let Ok(text) = std::str::from_utf8(text) else { return };
	let path = Path::new(if kind & 1 == 0 { "fuzz.yaml" } else { "fuzz.json" });
	let Ok(doc) = ConfigDoc::parse(path, text) else { return };
	let _ = doc.unsupported_globals();
	assert!(doc.restart_needed(&doc).is_empty());
	let all = Caps { transparent: true, transparent_ipv6: true, features: Features::ALL, ..Caps::default() };
	for (_, rule) in doc.labeled_rules() {
		let _ = rule.clone().validate(&Caps::default());
		let _ = rule.validate(&all);
	}
});
