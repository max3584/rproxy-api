//! `offload-verify` (#260, owner's decision): an always-on cross-check of the
//! kernel fast paths, for TESTING only. It is a cargo feature that release
//! builds leave out, so production keeps zero overhead; the default build has
//! none of this code. The CI `offload` job and the integrity / soak / load
//! correctness runs of fast-path branches turn it on.
//!
//! Per sockmap connection it watches, while the relay runs, that bytes keep
//! moving (a stall is data waiting — redirected but not in the other socket's
//! send queue, or queued but not acknowledged — with no progress for
//! `RPROXY_OFFLOAD_VERIFY_STALL_SECS`, default 5 s), and at the end that the
//! bytes each side received all reached the other side, that each half-close
//! was passed on (the other socket sent its FIN) and that a reset was not taken
//! for a clean close. End-to-end data integrity is compared by the tests
//! themselves (tests/integrity.rs SHA-256s every stream).
//!
//! A mismatch is logged at `error` (`event = "offload.verify"`, with the
//! numbers) and counted (`failures`, `rproxy_offload_verify_failures_total` on
//! /metrics in this build only); the tests fail when it is not zero.

#![cfg(all(feature = "offload-verify", target_os = "linux"))]

use std::io;
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tracing::error;

use super::sockmap;

static FAILURES: AtomicU64 = AtomicU64::new(0);

/// Mismatches found so far in this process.
pub fn failures() -> u64 {
	FAILURES.load(Ordering::Relaxed)
}

/// Records a mismatch: an `error` line with the detail, and the counter.
pub fn fail(fast_path: &'static str, check: &'static str, rule: &str, detail: String) {
	FAILURES.fetch_add(1, Ordering::Relaxed);
	error!(event = "offload.verify", fast_path, check, rule = %rule, detail = %detail, "kernel fast path verification failed");
}

/// How long data may wait without progress before it is a stall.
pub fn stall_after() -> Duration {
	let secs = std::env::var("RPROXY_OFFLOAD_VERIFY_STALL_SECS").ok().and_then(|v| v.trim().parse().ok()).unwrap_or(5);
	Duration::from_secs(secs)
}

// linux/tcp_states.h
const ESTABLISHED: u8 = 1;
const FIN_WAIT1: u8 = 4;
const FIN_WAIT2: u8 = 5;
const TIME_WAIT: u8 = 6;
const CLOSE: u8 = 7;
const CLOSE_WAIT: u8 = 8;
const LAST_ACK: u8 = 9;
const CLOSING: u8 = 11;

/// The socket has received its peer's FIN.
fn got_fin(state: u8) -> bool {
	matches!(state, CLOSE_WAIT | LAST_ACK | CLOSING | TIME_WAIT | CLOSE)
}

/// The socket has sent its FIN.
fn sent_fin(state: u8) -> bool {
	matches!(state, FIN_WAIT1 | FIN_WAIT2 | CLOSING | TIME_WAIT | LAST_ACK | CLOSE)
}

/// One direction of a sockmap relay: what `src` receives is redirected to `dst`.
#[derive(Clone, Copy, Debug)]
pub struct Dir {
	pub name: &'static str,
	pub src: RawFd,
	pub rx0: u64,
	pub dst: RawFd,
	pub w0: u64,
	pub acked0: u64,
}

/// Data counts of one direction since the relay started, FINs left out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Snap {
	/// received by `src` (redirected)
	moved: u64,
	/// put in `dst`'s send queue
	written: u64,
	/// acknowledged by `dst`'s peer
	acked: u64,
	src_state: u8,
	dst_state: u8,
}

impl Dir {
	/// Baselines of `src` -> `dst` before the relay starts.
	pub fn start(name: &'static str, src: BorrowedFd<'_>, dst: BorrowedFd<'_>) -> io::Result<Dir> {
		use std::os::fd::AsRawFd;
		Ok(Dir {
			name,
			src: src.as_raw_fd(),
			rx0: sockmap::bytes_received(src)?,
			dst: dst.as_raw_fd(),
			w0: sockmap::bytes_written(dst)?,
			acked0: sockmap::bytes_acked(dst)?,
		})
	}

	fn snap(&self) -> io::Result<Snap> {
		// SAFETY: the relay borrows both sockets for as long as it is checked
		let (src, dst) = unsafe { (BorrowedFd::borrow_raw(self.src), BorrowedFd::borrow_raw(self.dst)) };
		let (src_state, dst_state) = (sockmap::tcp_state(src)?, sockmap::tcp_state(dst)?);
		let src_fin = u64::from(got_fin(src_state));
		let dst_fin = u64::from(sent_fin(dst_state));
		Ok(Snap {
			moved: sockmap::bytes_received(src)?.saturating_sub(self.rx0).saturating_sub(src_fin),
			written: sockmap::bytes_written(dst)?.saturating_sub(self.w0).saturating_sub(dst_fin),
			acked: sockmap::bytes_acked(dst)?.saturating_sub(self.acked0).saturating_sub(dst_fin),
			src_state,
			dst_state,
		})
	}
}

/// Runs beside a sockmap relay and reports a stall of either direction (once
/// per direction). Never returns; the relay's end drops it.
pub async fn watch_sockmap(rule: String, dirs: [Dir; 2]) -> std::convert::Infallible {
	let stall = stall_after();
	let mut last: [Option<(Snap, Instant)>; 2] = [None, None];
	let mut reported = [false; 2];
	loop {
		tokio::time::sleep(Duration::from_millis(250)).await;
		for (i, d) in dirs.iter().enumerate() {
			let Ok(now) = d.snap() else { continue };
			let waiting = now.moved > now.written || now.written > now.acked;
			let progress = match &last[i] {
				Some((prev, _)) => prev.written != now.written || prev.acked != now.acked,
				None => true,
			};
			if progress || !waiting {
				last[i] = Some((now, Instant::now()));
				continue;
			}
			if let Some((_, since)) = last[i] {
				if !reported[i] && since.elapsed() >= stall {
					reported[i] = true;
					fail(
						"sockmap",
						"stall",
						&rule,
						format!("{}: no progress for {:?} with data waiting: {now:?}", d.name, since.elapsed()),
					);
				}
			}
		}
	}
}

/// After a sockmap relay: each side's bytes all reached the other side, each
/// half-close was passed on, and no reset hid behind a clean close.
pub fn check_sockmap_end(rule: &str, dirs: [Dir; 2], clean: bool) {
	for d in dirs {
		let now = match d.snap() {
			Ok(s) => s,
			Err(e) => {
				fail("sockmap", "counters", rule, format!("{}: TCP_INFO failed: {e}", d.name));
				continue;
			}
		};
		if !clean {
			continue;
		}
		if now.written != now.moved {
			fail("sockmap", "bytes", rule, format!("{}: received {} but put {} in the other socket: {now:?}", d.name, now.moved, now.written));
		}
		if now.dst_state == ESTABLISHED || now.dst_state == CLOSE_WAIT {
			fail("sockmap", "fin", rule, format!("{}: the half-close was not passed on: {now:?}", d.name));
		}
		// SAFETY: as in `snap`
		let errs = unsafe { (sockmap::so_error(BorrowedFd::borrow_raw(d.src)), sockmap::so_error(BorrowedFd::borrow_raw(d.dst))) };
		if errs != (0, 0) {
			fail("sockmap", "rst", rule, format!("{}: a socket error behind a clean close (src {}, dst {})", d.name, errs.0, errs.1));
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn states_and_the_counter() {
		assert!(got_fin(CLOSE_WAIT) && got_fin(LAST_ACK) && !got_fin(ESTABLISHED) && !got_fin(FIN_WAIT2));
		assert!(sent_fin(FIN_WAIT1) && sent_fin(LAST_ACK) && !sent_fin(CLOSE_WAIT) && !sent_fin(ESTABLISHED));
		let before = failures();
		fail("sockmap", "test", "tcp/127.0.0.1:1", "a test of the counter".into());
		assert_eq!(failures(), before + 1);
	}
}
