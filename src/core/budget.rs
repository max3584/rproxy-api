//! The process-wide budget of file descriptors for connections and sessions (#354).
//!
//! Each UDP session opens a backend socket, each TCP relay two sockets (and, while it
//! splices, a pipe of two more), an `http` connection its own socket and each connection
//! to a server one more (#373); without a
//! cap for the whole process, a flood (of spoofed UDP sources, for one) could take every
//! descriptor and leave none for the control API, the database, name resolution or the
//! certificate files. The budget is `RLIMIT_NOFILE` (soft, after `main` lifts it to the hard
//! limit) less `RESERVE` and less the listening sockets the rules may open
//! (`RPROXY_MAX_LISTENERS`, #370), so that the two caps together leave `RESERVE`. `main`
//! sets it once at startup (`init`); otherwise it is worked out the first time it is used.
//! A `Ticket` holds its descriptors until it is dropped. Taking one is a single CAS (`take`),
//! giving it back one `fetch_sub`: what a connection pays for the budget (#369). HTTP/3
//! takes none: its connections share the rule's one UDP socket.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Descriptors kept out of the budget and of `RPROXY_MAX_LISTENERS`: the control API, DB,
/// DNS, files.
pub const RESERVE: u64 = 1024;
/// The budget when the limit cannot be read, or leaves less than this beyond `RESERVE`.
const FLOOR: u64 = 256;

static LIMIT: OnceLock<u64> = OnceLock::new();
static IN_USE: AtomicU64 = AtomicU64::new(0);

/// Descriptors the data plane may hold at once.
pub fn limit() -> u64 {
	*LIMIT.get_or_init(|| from_nofile(nofile(), crate::core::quota::max_listeners() as u64))
}

/// Sets the budget to `limit` descriptors, once, as `init` does: for tests that need a small
/// budget in their own process (`tests/fd_budget.rs`). Returns the budget in force.
#[doc(hidden)]
pub fn init_exact(limit: u64) -> u64 {
	*LIMIT.get_or_init(|| limit)
}

/// Sets the budget from the file limit `main` read and the listener cap
/// (`core::quota::max_listeners`), once, before the data plane starts. Returns the budget.
pub fn init(nofile: Option<u64>, listeners: u64) -> u64 {
	*LIMIT.get_or_init(|| from_nofile(nofile, listeners))
}

/// How far the budget and the listener cap together go past `RLIMIT_NOFILE` less `RESERVE`
/// (None when they fit, or the file limit is unknown or unlimited). They go past it only when
/// `RPROXY_MAX_LISTENERS` is set that high, or the file limit is so low that the floors of
/// both decide.
pub fn overcommit(nofile: Option<u64>, listeners: u64, budget: u64) -> Option<u64> {
	match nofile {
		None | Some(u64::MAX) => None,
		Some(n) => listeners.saturating_add(budget).checked_sub(n.saturating_sub(RESERVE)).filter(|&over| over > 0),
	}
}

/// Descriptors held now.
pub fn in_use() -> u64 {
	IN_USE.load(Ordering::Relaxed)
}

fn from_nofile(nofile: Option<u64>, listeners: u64) -> u64 {
	match nofile {
		// unlimited: no cap of ours
		Some(u64::MAX) => u64::MAX,
		Some(n) => n.saturating_sub(RESERVE).saturating_sub(listeners).max(FLOOR),
		None => FLOOR,
	}
}

/// Lifts the soft file limit to the hard one (`main` at startup, and the test harness so that
/// tests get the budget the service would); returns the soft limit then in force.
#[cfg(unix)]
pub fn raise_nofile_limit() -> Option<u64> {
	let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
	// SAFETY: plain syscalls on a local struct
	unsafe {
		if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
			return None;
		}
		if lim.rlim_cur < lim.rlim_max {
			lim.rlim_cur = lim.rlim_max;
			libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
			libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
		}
	}
	#[allow(clippy::unnecessary_cast)] // rlim_t is not u64 everywhere
	Some(lim.rlim_cur as u64)
}

#[cfg(not(unix))]
pub fn raise_nofile_limit() -> Option<u64> {
	None
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

	/// `n` descriptors over the budget, for ones being given back (a session evicted for
	/// this one ends a moment later), but never into more than half of `RESERVE`: what
	/// is in flight at once stays bounded. None past that.
	pub fn force(n: u64) -> Option<Ticket> {
		take_within(n, limit().saturating_add(RESERVE / 2))
	}

	/// Gives back what the ticket holds beyond `n` (an `http` connection keeps one of the
	/// two a TCP connection takes when accepted; its servers' connections take their own).
	pub fn keep(&mut self, n: u64) {
		if n < self.n {
			IN_USE.fetch_sub(self.n - n, Ordering::Relaxed);
			self.n = n;
		}
	}
}

fn take_within(n: u64, limit: u64) -> Option<Ticket> {
	// not `then_some`: a Ticket made and dropped would give back what it never took
	if reserve(&IN_USE, n, limit) { Some(Ticket { n }) } else { None }
}

/// Adds `n` to `counter` if that stays within `limit` (one CAS when uncontended).
fn reserve(counter: &AtomicU64, n: u64, limit: u64) -> bool {
	let mut used = counter.load(Ordering::Relaxed);
	loop {
		let Some(next) = used.checked_add(n).filter(|&next| next <= limit) else { return false };
		match counter.compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed) {
			Ok(_) => return true,
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
		assert_eq!(from_nofile(Some(1_048_576), 0), 1_048_576 - RESERVE);
		assert_eq!(from_nofile(Some(1024), 0), FLOOR);
		assert_eq!(from_nofile(None, 0), FLOOR);
		assert_eq!(from_nofile(Some(u64::MAX), 0), u64::MAX);
		assert_eq!(from_nofile(Some(u64::MAX), 1_000), u64::MAX);
	}

	/// #370: with both caps automatic, listeners and connections share what the file limit
	/// leaves after `RESERVE` and never go past it together.
	#[test]
	fn the_automatic_caps_add_up_to_the_file_limit_less_the_reserve() {
		for n in [1_536u64, 2_048, 4_096, 65_536, 65_537, 1_048_576] {
			let listeners = crate::core::quota::auto_listeners(Some(n)) as u64;
			let budget = from_nofile(Some(n), listeners);
			assert_eq!(listeners + budget, n - RESERVE, "nofile {n}");
			assert!(budget >= listeners, "nofile {n}: connections get at least half");
			assert_eq!(overcommit(Some(n), listeners, budget), None, "nofile {n}");
		}
		// the unit's LimitNOFILE=65536
		assert_eq!(crate::core::quota::auto_listeners(Some(65_536)), 32_256);
		assert_eq!(from_nofile(Some(65_536), 32_256), 32_256);
	}

	#[test]
	fn an_explicit_listener_cap_comes_out_of_the_budget() {
		assert_eq!(from_nofile(Some(65_536), 1_000), 65_536 - RESERVE - 1_000);
		assert_eq!(overcommit(Some(65_536), 1_000, 65_536 - RESERVE - 1_000), None);
		// a cap that leaves less than the floor: the floor, and the warning says by how much
		assert_eq!(from_nofile(Some(65_536), 65_000), FLOOR);
		assert_eq!(overcommit(Some(65_536), 65_000, FLOOR), Some(65_000 + FLOOR - (65_536 - RESERVE)));
		// a file limit too low for both floors
		assert_eq!(overcommit(Some(1_024), 256, FLOOR), Some(512));
		// unknown or unlimited: nothing to go past
		assert_eq!(overcommit(None, 16_384, FLOOR), None);
		assert_eq!(overcommit(Some(u64::MAX), u64::MAX / 2, u64::MAX), None);
	}

	#[test]
	fn tickets_are_bounded_and_given_back() {
		// a counter of its own: other tests (UDP sessions, splice pipes) take from the process's
		let counter = AtomicU64::new(0);
		assert!(reserve(&counter, 3, 4));
		assert!(!reserve(&counter, 2, 4), "no room for 2 more");
		assert!(reserve(&counter, 1, 4));
		assert_eq!(counter.load(Ordering::Relaxed), 4);
		counter.fetch_sub(3, Ordering::Relaxed);
		assert!(reserve(&counter, 3, 4));
		assert!(!reserve(&counter, 1, 4));
		// `force` is bounded the same way, at half the reserve past the limit
		assert!(!reserve(&counter, RESERVE, RESERVE / 2));
		assert!(!reserve(&AtomicU64::new(u64::MAX), 1, u64::MAX), "never wraps");
	}

	/// #373: an `http` connection keeps one of the two it took when accepted.
	#[test]
	fn a_ticket_keeps_part_of_what_it_took() {
		// other tests take tickets too: look at the ticket, not at the process's counter
		let mut t = take_within(2, u64::MAX).unwrap();
		t.keep(1);
		assert_eq!(t.n, 1);
		t.keep(5);
		assert_eq!(t.n, 1, "keeping more takes nothing more");
		t.keep(0);
		assert_eq!(t.n, 0);
	}
}
