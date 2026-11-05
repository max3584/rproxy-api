//! Deadlines of a relayed TCP connection (#353): the rule's `idle_timeout` (no
//! byte moved either way for that long; default 1 h, `0s` none) and, once one
//! side has ended its sending (a half-close), its `half_close_timeout` (default
//! 1 min, `0s` none: then only `idle_timeout`) of no progress for the other. A
//! writer that takes nothing (the peer does not read) makes no progress either,
//! so a stalled connection ends by the same deadline. Only bytes of the
//! connection count: TCP keepalive probes are not seen here.
//!
//! The relay marks what it moves in a `Progress` (a plain store per read or write
//! that moved bytes, no timer touched); `expired` wakes now and then and compares,
//! so a busy connection costs no timer resets. The deadline is met within
//! `tick` of it.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// The rule's `idle_timeout` when it has none.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
/// The rule's `half_close_timeout` when it has none: after one side has half-closed,
/// the other may go this long without progress.
pub const DEFAULT_HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(60);

/// The deadlines of one connection (`None`: no limit), read from the rule when it starts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deadlines {
	pub idle: Option<Duration>,
	pub half_close: Option<Duration>,
}

impl Deadlines {
	/// The limit in force, and which one it is.
	fn limit(&self, half_closed: bool) -> Option<(Duration, Expired)> {
		let idle = self.idle.map(|d| (d, Expired::Idle));
		if !half_closed {
			return idle;
		}
		match (idle, self.half_close) {
			(Some((i, _)), Some(h)) if i <= h => idle,
			(_, Some(h)) => Some((h, Expired::HalfClose)),
			(idle, None) => idle,
		}
	}
}

/// What a relay moved, for `expired`.
#[derive(Debug, Default)]
pub struct Progress {
	/// Changes whenever bytes move (or a side ends); only compared.
	moved: AtomicU64,
	/// One side ended its sending (EOF read).
	half_closed: AtomicBool,
}

impl Progress {
	/// Bytes moved. Every change is made by the task of the connection, so a load
	/// and a store (no read-modify-write) is enough.
	#[inline]
	pub fn moved(&self) {
		self.moved.store(self.moved.load(Ordering::Relaxed).wrapping_add(1), Ordering::Relaxed);
	}

	/// A side ended its sending; counts as progress (the other side gets the whole
	/// `half_close_timeout` from here).
	pub fn half_closed(&self) {
		self.half_closed.store(true, Ordering::Relaxed);
		self.moved();
	}

	fn seen(&self) -> u64 {
		self.moved.load(Ordering::Relaxed)
	}

	fn is_half_closed(&self) -> bool {
		self.half_closed.load(Ordering::Relaxed)
	}
}

/// Which deadline ended a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expired {
	Idle,
	HalfClose,
}

impl Expired {
	/// The `reason` of `conn.close`.
	pub fn reason(self) -> &'static str {
		match self {
			Expired::Idle => "idle_timeout",
			Expired::HalfClose => "half_close_timeout",
		}
	}
}

/// How often `expired` looks at a deadline of `limit`.
fn tick(limit: Duration) -> Duration {
	(limit / 8).clamp(Duration::from_millis(10), Duration::from_secs(60))
}

/// Returns when nothing has moved for the limit in force (`Deadlines::limit`: the
/// idle one, or once a side has half-closed the shorter of both). Never returns while
/// progress is made, nor without a limit.
pub async fn expired(progress: &Progress, deadlines: Deadlines) -> Expired {
	let mut seen = progress.seen();
	let mut since = Instant::now();
	loop {
		let (sleep, due) = match deadlines.limit(progress.is_half_closed()) {
			Some((limit, which)) => {
				let left = (since + limit).saturating_duration_since(Instant::now());
				if left.is_zero() {
					return which;
				}
				(left.min(tick(limit)), true)
			}
			// no limit until a half-close: look now and then whether one came
			None => (deadlines.half_close.map_or(Duration::from_secs(60), tick), false),
		};
		tokio::time::sleep(sleep).await;
		let current = progress.seen();
		if current != seen || !due {
			seen = current;
			// moved somewhere in the last tick: counted from now, at most a tick late
			since = Instant::now();
		}
	}
}

/// Runs `relay` until it ends, or until `expired` (none without any limit).
pub async fn within<T>(deadlines: Deadlines, progress: &Progress, relay: impl std::future::Future<Output = T>) -> Result<T, Expired> {
	if deadlines == Deadlines::default() {
		return Ok(relay.await);
	}
	tokio::select! {
		biased;
		r = relay => Ok(r),
		e = expired(progress, deadlines) => Err(e),
	}
}

/// A stream whose reads and writes that move bytes, and whose end of reading,
/// are marked in a `Progress`.
pub struct Tracked<'a, S: ?Sized> {
	inner: &'a mut S,
	progress: &'a Progress,
}

impl<'a, S: ?Sized> Tracked<'a, S> {
	pub fn new(inner: &'a mut S, progress: &'a Progress) -> Self {
		Tracked { inner, progress }
	}
}

impl<S: AsyncRead + Unpin + ?Sized> AsyncRead for Tracked<'_, S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		let (before, room) = (buf.filled().len(), buf.remaining());
		let poll = Pin::new(&mut *this.inner).poll_read(cx, buf);
		if let Poll::Ready(Ok(())) = poll {
			if buf.filled().len() > before {
				this.progress.moved();
			} else if room > 0 {
				this.progress.half_closed();
			}
		}
		poll
	}
}

impl<S: AsyncWrite + Unpin + ?Sized> AsyncWrite for Tracked<'_, S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		let poll = Pin::new(&mut *this.inner).poll_write(cx, buf);
		if let Poll::Ready(Ok(n)) = poll {
			if n > 0 {
				this.progress.moved();
			}
		}
		poll
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test(start_paused = true)]
	async fn idle_ends_only_without_progress() {
		let p = Progress::default();
		let start = Instant::now();
		let watch = expired(&p, Deadlines { idle: Some(Duration::from_secs(80)), half_close: Some(DEFAULT_HALF_CLOSE_TIMEOUT) });
		tokio::pin!(watch);
		// progress every 30 s keeps it going
		for _ in 0..10 {
			tokio::select! {
				_ = &mut watch => panic!("ended while progressing"),
				_ = tokio::time::sleep(Duration::from_secs(30)) => p.moved(),
			}
		}
		assert_eq!(watch.await, Expired::Idle);
		let quiet = start.elapsed() - Duration::from_secs(300);
		assert!(quiet >= Duration::from_secs(80) && quiet <= Duration::from_secs(80) + tick(Duration::from_secs(80)), "{quiet:?}");
	}

	#[tokio::test(start_paused = true)]
	async fn a_half_close_shortens_it() {
		let p = Progress::default();
		let start = Instant::now();
		let watch = expired(&p, Deadlines { idle: Some(DEFAULT_IDLE_TIMEOUT), half_close: Some(DEFAULT_HALF_CLOSE_TIMEOUT) });
		tokio::pin!(watch);
		tokio::select! {
			_ = &mut watch => panic!("ended too soon"),
			_ = tokio::time::sleep(Duration::from_secs(600)) => p.half_closed(),
		}
		assert_eq!(watch.await, Expired::HalfClose);
		let after = start.elapsed() - Duration::from_secs(600);
		assert!(after >= DEFAULT_HALF_CLOSE_TIMEOUT && after <= DEFAULT_HALF_CLOSE_TIMEOUT + Duration::from_secs(60), "{after:?}");
	}

	#[tokio::test(start_paused = true)]
	async fn each_limit_alone() {
		// half_close_timeout 0s: after a half-close only idle_timeout applies
		let p = Progress::default();
		let start = Instant::now();
		p.half_closed();
		let d = Deadlines { idle: Some(Duration::from_secs(600)), half_close: None };
		assert_eq!(expired(&p, d).await, Expired::Idle);
		assert!(start.elapsed() >= Duration::from_secs(600));
		// idle_timeout 0s: no limit until a half-close, then half_close_timeout
		let p = Progress::default();
		let d = Deadlines { idle: None, half_close: Some(Duration::from_secs(30)) };
		let start = Instant::now();
		let watch = expired(&p, d);
		tokio::pin!(watch);
		tokio::select! {
			_ = &mut watch => panic!("ended without a half-close"),
			_ = tokio::time::sleep(Duration::from_secs(7200)) => p.half_closed(),
		}
		assert_eq!(watch.await, Expired::HalfClose);
		let after = start.elapsed() - Duration::from_secs(7200);
		assert!(after >= Duration::from_secs(30) && after <= Duration::from_secs(60) + tick(Duration::from_secs(30)), "{after:?}");
		// an idle_timeout shorter than half_close_timeout stays in force after a half-close
		let d = Deadlines { idle: Some(Duration::from_secs(5)), half_close: Some(Duration::from_secs(60)) };
		assert_eq!(d.limit(true), Some((Duration::from_secs(5), Expired::Idle)));
	}

	#[tokio::test]
	async fn tracked_marks_reads_writes_and_the_end() {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};
		let p = Progress::default();
		let (mut a, mut b) = tokio::io::duplex(64);
		let mut t = Tracked::new(&mut a, &p);
		t.write_all(b"hi").await.unwrap();
		assert_eq!(p.seen(), 1);
		b.write_all(b"yo").await.unwrap();
		drop(b);
		let mut got = vec![];
		t.read_to_end(&mut got).await.unwrap();
		assert_eq!(got, b"yo");
		assert!(p.is_half_closed());
	}
}
