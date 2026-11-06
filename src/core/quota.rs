//! How much the control API may make (#358): rules, listening sockets and rule sets of
//! the process, rules and rule sets of one token, and who may ask for `listen_freebind`. The rules of the settings file and those
//! restored from the database or a live upgrade are counted but never refused: the limits
//! are for what tokens ask for.

use std::sync::atomic::{AtomicUsize, Ordering};

use crate::core::rule::RuleSpec;
use crate::error::ApiError;

/// `RPROXY_MAX_RULES`: rules of the process.
pub const DEFAULT_MAX_RULES: usize = 10_000;
/// `RPROXY_MAX_RULESETS`: rule sets of the process.
pub const DEFAULT_MAX_RULESETS: usize = 1_000;
/// File descriptors kept out of `RPROXY_MAX_LISTENERS`'s automatic value for everything
/// else besides the connections (the control API, the database, DNS, files).
pub const RESERVED_FDS: u64 = 1_024;
/// `RPROXY_MAX_LISTENERS` when the file limit is not known.
const FALLBACK_LISTENERS: usize = 16_384;
/// The automatic value is at least this.
const MIN_LISTENERS: usize = 256;

static MAX_RULES: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_RULES);
static MAX_LISTENERS: AtomicUsize = AtomicUsize::new(FALLBACK_LISTENERS);
static MAX_RULESETS: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_RULESETS);

/// `RPROXY_MAX_LISTENERS`'s automatic value (`0`): half of what the file limit leaves after
/// `RESERVED_FDS` (the other half for connections), at least `MIN_LISTENERS`.
pub fn auto_listeners(nofile: Option<u64>) -> usize {
	match nofile {
		Some(n) => usize::try_from(n.saturating_sub(RESERVED_FDS) / 2).unwrap_or(usize::MAX).max(MIN_LISTENERS),
		None => FALLBACK_LISTENERS,
	}
}

/// The limits of the process (at startup). `0` in any of them: no limit (`listeners`: the
/// automatic value from `nofile`).
pub fn set(rules: usize, listeners: usize, rulesets: usize, nofile: Option<u64>) {
	let none = |n: usize| if n == 0 { usize::MAX } else { n };
	MAX_RULES.store(none(rules), Ordering::Relaxed);
	MAX_LISTENERS.store(if listeners == 0 { auto_listeners(nofile) } else { listeners }, Ordering::Relaxed);
	MAX_RULESETS.store(none(rulesets), Ordering::Relaxed);
}

pub fn max_rules() -> usize {
	MAX_RULES.load(Ordering::Relaxed)
}

pub fn max_listeners() -> usize {
	MAX_LISTENERS.load(Ordering::Relaxed)
}

pub fn max_rulesets() -> usize {
	MAX_RULESETS.load(Ordering::Relaxed)
}

/// The listening sockets a rule opens: one per address and port, and the UDP ones of HTTP/3.
pub fn sockets(spec: &RuleSpec) -> usize {
	let h3 = spec.http.as_ref().is_some_and(|h| h.http3);
	spec.listen_ips().len() * usize::from(spec.port_count.max(1)) * if h3 { 2 } else { 1 }
}

fn reached(message: String) -> ApiError {
	ApiError::limit(message)
}

/// Refuses a change that would take the process past `RPROXY_MAX_RULES` or
/// `RPROXY_MAX_LISTENERS` (`rules` and `sockets`: the totals after it). A change that
/// does not add any (`added_*` 0) always goes through, so a process over a lowered
/// limit can still be changed and cleaned up.
pub fn check_process(rules: usize, added_rules: usize, sockets: usize, added_sockets: usize) -> Result<(), ApiError> {
	if added_rules > 0 && rules > max_rules() {
		return Err(reached(format!("the process may have at most {} rules (RPROXY_MAX_RULES)", max_rules())));
	}
	if added_sockets > 0 && sockets > max_listeners() {
		return Err(reached(format!(
			"the rules may open at most {} listening sockets together (RPROXY_MAX_LISTENERS; one per address and port, two with http3); this change would make {sockets}",
			max_listeners()
		)));
	}
	Ok(())
}

/// Refuses a new rule set past `RPROXY_MAX_RULESETS` (`sets`: the number with it).
pub fn check_rulesets(sets: usize) -> Result<(), ApiError> {
	if sets > max_rulesets() {
		return Err(reached(format!("the process may have at most {} rule sets (RPROXY_MAX_RULESETS)", max_rulesets())));
	}
	Ok(())
}

/// `listen_freebind` (binding addresses that are not on the host) for a token that may not
/// ask for it (`allowed`: `admin`, `allow_freebind: true` of the token file, or a rule set's
/// `PUT` by a token limited by `allow_rulesets`, such as rproxy-gateway's).
pub fn check_freebind(listen_freebind: bool, allowed: bool) -> Result<(), ApiError> {
	if listen_freebind && !allowed {
		return Err(ApiError::forbidden(
			"listen_freebind needs a token with the admin scope or allow_freebind: true (a rule set's PUT also by a token with allow_rulesets)",
		));
	}
	Ok(())
}

/// A token's own limit (`max_rules` / `max_rulesets` of the token file): `have` after the change.
pub fn check_token(what: &str, have: usize, added: usize, max: Option<usize>) -> Result<(), ApiError> {
	match max {
		Some(max) if added > 0 && have > max => {
			Err(reached(format!("this token may have at most {max} {what} (max_{what} of the token file)")))
		}
		_ => Ok(()),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn listeners_follow_the_file_limit() {
		assert_eq!(auto_listeners(Some(65_536)), 32_256);
		assert_eq!(auto_listeners(Some(1_024)), MIN_LISTENERS);
		assert_eq!(auto_listeners(None), FALLBACK_LISTENERS);
	}

	#[test]
	fn only_additions_are_refused() {
		assert!(check_token("rules", 3, 1, Some(2)).is_err());
		assert!(check_token("rules", 3, 0, Some(2)).is_ok());
		assert!(check_token("rules", 2, 1, Some(2)).is_ok());
		assert!(check_token("rules", 9, 1, None).is_ok());
		assert!(check_process(usize::MAX, 0, usize::MAX, 0).is_ok());
		assert_eq!(check_process(usize::MAX, 1, 0, 0).unwrap_err().code, "limit");
	}

	#[test]
	fn freebind_needs_permission() {
		assert!(check_freebind(true, false).is_err());
		assert!(check_freebind(true, true).is_ok());
		assert!(check_freebind(false, false).is_ok());
	}
}
