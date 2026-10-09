//! `offload-verify` (#260, owner's decision): an always-on cross-check of the
//! kernel fast paths, for TESTING only. It is a cargo feature that release
//! builds leave out, so production keeps zero overhead; the default build has
//! none of this code. The CI `offload` job and the integrity / soak / load
//! correctness runs of fast-path branches turn it on.
//!
//! This module is the part every fast path shares: recording a mismatch
//! (`fail`: an `error` line `event = "offload.verify"` with the detail, and
//! `rproxy_offload_verify_failures_total` on /metrics in this build only), the
//! count the tests assert is zero (`failures`), and the stall threshold
//! (`stall_after`). Each fast path adds its own checks next to its data path
//! (bytes/packets moved against what the peer acknowledged or received, stalls
//! with data waiting, FIN/RST propagation); end-to-end content is compared by
//! the tests themselves (tests/integrity.rs SHA-256s every stream).
//!
//! It was written for the eBPF sockmap experiment, where it found the four
//! kernel quirks and the backlog stall that decided against sockmap
//! (docs/PERFORMANCE.md).

#![cfg(all(feature = "offload-verify", target_os = "linux"))]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::error;

static FAILURES: AtomicU64 = AtomicU64::new(0);

/// Mismatches found so far in this process.
pub fn failures() -> u64 {
	FAILURES.load(Ordering::Relaxed)
}

/// Records a mismatch: an `error` line with the detail, and the counter.
pub fn fail(fast_path: &'static str, check: &'static str, rule: &str, detail: String) {
	FAILURES.fetch_add(1, Ordering::Relaxed);
	error!(event = "offload.verify", fast_path, check, rule = %rule, detail = %detail, "kernel fast path verification failed");
	// also on stderr, so a failing test shows it whatever the log setup
	eprintln!("offload.verify: {fast_path} {check} {rule}: {detail}");
}

/// How long data may wait without progress before it is a stall
/// (`RPROXY_OFFLOAD_VERIFY_STALL_SECS`, default 5 s).
pub fn stall_after() -> Duration {
	let secs = std::env::var("RPROXY_OFFLOAD_VERIFY_STALL_SECS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(5);
	Duration::from_secs(secs)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_counter_counts() {
		let before = failures();
		fail("test", "counter", "udp/127.0.0.1:1", "a test of the counter".into());
		assert_eq!(failures(), before + 1);
	}
}
