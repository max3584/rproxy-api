//! Converts a Traefik configuration into an rproxy-api settings file (`RPROXY_CONFIG`):
//! the `rproxy-traefik-convert` command (docs/MIGRATING-FROM-TRAEFIK.md). It replaces
//! `contrib/traefik2rproxy.py` and writes the same output.
//!
//! Reads the Traefik static configuration (entry points, trusted IPs, access log,
//! certificate resolvers), the dynamic configuration (file provider: routers,
//! services, middlewares, TLS) and optionally `docker inspect` output (labels), and
//! writes one rproxy settings document (`version: 1`, `global`, `rules`). Settings
//! that have no rproxy equivalent are listed as notes (comments at the top of the
//! output and on stderr).
//!
//! # For other converters (rproxy-gateway: Traefik's CRDs)
//!
//! - [`translate_http_rule`]`(rule, where_, notes) -> Option<String>`: a router rule
//!   (v2 or v3) → rproxy's `match`; `None` when it has a matcher rproxy lacks.
//! - [`host_names`]`(rule) -> Vec<String>`: the `Host(...)` names of a rule.
//! - [`sni_regexp_pattern`]`(regex) -> Option<String>`: a `HostSNIRegexp` → `*.suffix` /
//!   `**.suffix`.
//! - [`convert_middleware`]`(name, spec, where_, env) -> Converted`: one Traefik
//!   middleware (`{type: settings}`) → an rproxy middleware, a chain to expand, or
//!   nothing. Where the middleware comes from answers through [`MiddlewareEnv`]
//!   (basicAuth users, the errors service, CrowdSec's global settings).
//! - [`duration`], [`tls_version`], [`cipher_suite`], [`client_auth_mode`]: the small
//!   mappings.
//! - [`Value`] is the value all of them take; `From<&serde_json::Value>` and back.
//!
//! Notes go to a [`NoteSink`] as `(where, text)`; [`Notes`] collects them like the
//! command does (`where: text`, each once).

pub mod cli;
pub mod convert;
pub mod emit;
pub mod load;
pub mod middleware;
pub mod rule;
pub mod value;

pub use convert::{check_capabilities, cipher_suite, client_auth_mode, convert, tls_version, used_features, Certs, Options};
pub use load::InputError;
pub use middleware::{convert_middleware, duration, ChainRef, Converted, MiddlewareEnv, KNOWN_MIDDLEWARES, KNOWN_SERVICE_OPTIONS};
pub use rule::{host_names, sni_regexp_pattern, translate_http_rule, v2_template, HTTP_MATCHERS};
pub use value::{Map, Value};

/// Where notes (what did not convert, what to check) go.
pub trait NoteSink {
	/// A note about `where_` (`router app`, `middleware auth`, …; empty for none).
	fn note(&mut self, where_: &str, text: &str);
}

/// Notes as the command lists them: `where: text`, each once, in order.
#[derive(Clone, Debug, Default)]
pub struct Notes {
	pub items: Vec<String>,
}

impl NoteSink for Notes {
	fn note(&mut self, where_: &str, text: &str) {
		let line = if where_.is_empty() { text.to_string() } else { format!("{where_}: {text}") };
		if !self.items.contains(&line) {
			self.items.push(line);
		}
	}
}
