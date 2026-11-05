//! The process-wide budget of file descriptors for connections and sessions (#354).
//!
//! Each UDP session opens a backend socket and each TCP connection two sockets; without a
//! cap for the whole process, a flood (of spoofed UDP sources, for one) could take every
//! descriptor and leave none for the control API, the database, name resolution or the
//! certificate files. The budget is `RLIMIT_NOFILE` (soft, after `main` lifts it to the hard
//! limit) less `RESERVE`, read the first time it is used. A `Ticket` holds its descriptors
//! until it is dropped.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Descriptors kept out of the budget: the control API, DB, DNS, files, listeners.
pub const RESERVE: u64 = 1024;
/// The budget when the limit cannot be read, or leaves less than this beyond `RESERVE`.
const FLOOR: u64 = 256;

static LIMIT: OnceLock<u64> = OnceLock::new();
static IN_USE: AtomicU64 = AtomicU64::new(0);

/// Descriptors the data plane may hold at once.
pub fn limit() -> u64 {
	*LIMIT.get_or_init(|| from_nofile(nofile()))
}

/// Descriptors held now.
pub fn in_use() -> u64 {
	IN_USE.load(Ordering::Relaxed)
}

fn from_nofile(nofile: Option<u64>) -> u64 {
	match nofile {
		// unlimited: no cap of ours
		Some(u64::MAX) => u64::MAX,
		Some(n) => n.saturating_sub(RESERVE).max(FLOOR),
		None => FLOOR,
	}
}

#[cfg(unix)]
fn nofile() -> Option<u64> {
	let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
	// SAFETY: getrlimit fills a local struct
	if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
		return None;
	}
	if lim.rlim_cur == libc::RLIM_INFINITY {
		return Some(u64::MAX);
	}
	#[allow(clippy::unnecessary_cast)] // rlim_t is not u64 everywhere
	Some(lim.rlim_cur as u64)
}

#[cfg(not(unix))]
fn nofile() -> Option<u64> {
	None
}

/// `n` descriptors of the budget, given back on drop.
#[derive(Debug)]
pub struct Ticket {
	n: u64,
}

impl Ticket {
	/// `n` descriptors, or None when the budget has no room for them.
	pub fn take(n: u64) -> Option<Ticket> {
		take_within(n, limit())
	}

	/// `n` descriptors over the budget: for one that is being given back (a session evicted
	/// for this one ends a moment later).
	pub fn force(n: u64) -> Ticket {
		IN_USE.fetch_add(n, Ordering::Relaxed);
		Ticket { n }
	}
}

fn take_within(n: u64, limit: u64) -> Option<Ticket> {
	let mut used = IN_USE.load(Ordering::Relaxed);
	loop {
		let next = used.checked_add(n).filter(|&next| next <= limit)?;
		match IN_USE.compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed) {
			Ok(_) => return Some(Ticket { n }),
			Err(now) => used = now,
		}
	}
}

impl Drop for Ticket {
	fn drop(&mut self) {
		IN_USE.fetch_sub(self.n, Ordering::Relaxed);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_budget_leaves_the_reserve() {
		assert_eq!(from_nofile(Some(1_048_576)), 1_048_576 - RESERVE);
		assert_eq!(from_nofile(Some(1024)), FLOOR);
		assert_eq!(from_nofile(None), FLOOR);
		assert_eq!(from_nofile(Some(u64::MAX)), u64::MAX);
	}

	#[test]
	fn tickets_are_bounded_and_given_back() {
		// the counter is the process's: measure against what is held now
		let base = in_use();
		let a = take_within(3, base + 4).unwrap();
		assert!(take_within(2, base + 4).is_none(), "no room for 2 more");
		let b = take_within(1, base + 4).unwrap();
		drop(a);
		let c = take_within(3, base + 4).unwrap();
		drop((b, c));
		assert!(in_use() <= base + 4);
	}
}
