//! Deadlines of a relayed TCP connection (#353): the rule's `idle_timeout` (no
//! byte moved either way for that long; default 1 h, `0s` none) and, once one
//! side has ended its sending (a half-close), `HALF_CLOSE_TIMEOUT` of no progress
//! for the other. A writer that takes nothing (the peer does not read) makes no
//! progress either, so a stalled connection ends by the same deadline.
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
/// After one side has half-closed: the other may go this long without progress.
pub const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(60);

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
	/// `HALF_CLOSE_TIMEOUT` from here).
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

/// Returns when nothing has moved for `idle` (or for `HALF_CLOSE_TIMEOUT`, if
/// shorter, once a side has half-closed). Never returns while progress is made.
pub async fn expired(progress: &Progress, idle: Duration) -> Expired {
	let half = HALF_CLOSE_TIMEOUT.min(idle);
	let mut seen = progress.seen();
	let mut since = Instant::now();
	loop {
		let (limit, which) = if progress.is_half_closed() { (half, Expired::HalfClose) } else { (idle, Expired::Idle) };
		let now = Instant::now();
		let left = (since + limit).saturating_duration_since(now);
		if left.is_zero() {
			return which;
		}
		tokio::time::sleep(left.min(tick(limit))).await;
		let current = progress.seen();
		if current != seen {
			seen = current;
			// moved somewhere in the last tick: counted from now, at most a tick late
			since = Instant::now();
		}
	}
}

/// Runs `relay` until it ends, or until `expired` (with `idle`; `None`: no deadline).
pub async fn within<T>(idle: Option<Duration>, progress: &Progress, relay: impl std::future::Future<Output = T>) -> Result<T, Expired> {
	match idle {
		None => Ok(relay.await),
		Some(idle) => tokio::select! {
			biased;
			r = relay => Ok(r),
			e = expired(progress, idle) => Err(e),
		},
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
		let watch = expired(&p, Duration::from_secs(80));
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
		let watch = expired(&p, DEFAULT_IDLE_TIMEOUT);
		tokio::pin!(watch);
		tokio::select! {
			_ = &mut watch => panic!("ended too soon"),
			_ = tokio::time::sleep(Duration::from_secs(600)) => p.half_closed(),
		}
		assert_eq!(watch.await, Expired::HalfClose);
		let after = start.elapsed() - Duration::from_secs(600);
		assert!(after >= HALF_CLOSE_TIMEOUT && after <= HALF_CLOSE_TIMEOUT + Duration::from_secs(60), "{after:?}");
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
