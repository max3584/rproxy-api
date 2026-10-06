//! Copying between two streams in both directions (#185): the TCP relay of L4
//! rules and upgraded HTTP connections (WebSocket).
//!
//! Like `tokio::io::copy_bidirectional` (same half-close, flush and error
//! behaviour), but a connection does not keep buffers of its own: each direction
//! borrows one from a per-thread pool only while it has data in flight, and gives
//! it back as soon as everything read has been written and the reader has
//! nothing more (`Pending`), or the direction ends. An idle connection holds no
//! buffer; a busy one holds a larger one than tokio's 8 KiB, so fewer reads and
//! writes move the same data.
//!
//! The reader is polled with a borrowed buffer and the buffer handed back when it
//! returns `Pending`: a `Pending` read leaves the buffer untouched, so this is
//! correct for any stream, including TLS (a rustls stream may have decrypted data
//! without the socket being readable; its `poll_read` returns that) and the
//! prefixed streams of SNI / STARTTLS.

use std::cell::RefCell;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Size of a relay buffer.
pub const BUFFER_SIZE: usize = 32 * 1024;

/// How much is read from a TLS stream at a time. A TLS stream gives at most one
/// record (16 KiB) per read anyway, and reading it into more than 8 KiB cost
/// about 15 % more CPU per byte in the load test (#185), so data read from TLS
/// moves in 8 KiB pieces as with tokio's `copy_bidirectional`.
pub const TLS_READ_SIZE: usize = 8 * 1024;

/// Free buffers kept per thread; more given back than this are freed.
const POOL_PER_THREAD: usize = 32;

/// Buffers lent out right now (for tests and diagnostics).
static IN_USE: AtomicUsize = AtomicUsize::new(0);

thread_local! {
	static POOL: RefCell<Vec<Box<[u8]>>> = const { RefCell::new(Vec::new()) };
}

/// Buffers that relays hold right now, over all connections. An idle
/// connection holds none.
pub fn buffers_in_use() -> usize {
	IN_USE.load(Ordering::Relaxed)
}

fn take() -> Box<[u8]> {
	IN_USE.fetch_add(1, Ordering::Relaxed);
	POOL.try_with(|p| p.borrow_mut().pop())
		.ok()
		.flatten()
		.unwrap_or_else(|| vec![0; BUFFER_SIZE].into_boxed_slice())
}

fn give_back(buf: Box<[u8]>) {
	IN_USE.fetch_sub(1, Ordering::Relaxed);
	let _ = POOL.try_with(|p| {
		let mut p = p.borrow_mut();
		if p.len() < POOL_PER_THREAD {
			p.push(buf);
		}
	});
}

/// When a direction may hand over to another way of copying (splice for plain
/// TCP, `l4::splice`): after `full_reads` reads in a row that filled the
/// buffer, and at least `after` bytes.
#[derive(Clone, Copy)]
pub struct Handover {
	pub full_reads: u32,
	pub after: u64,
}

/// What `Copy::poll_copy` ended with.
pub enum Step {
	/// The reader ended (and the writer was flushed); the bytes copied.
	Done(u64),
	/// Everything read was written and the buffer given back, and the
	/// `Handover` condition holds; the bytes copied so far.
	Handover(u64),
}

/// One direction: what was read and not yet written.
pub struct Copy {
	buf: Option<Box<[u8]>>,
	pos: usize,
	cap: usize,
	read_done: bool,
	need_flush: bool,
	amt: u64,
	/// The most this direction reads into its buffer.
	limit: usize,
	handover: Option<Handover>,
	/// Reads in a row that filled the buffer.
	full_streak: u32,
}

impl Drop for Copy {
	fn drop(&mut self) {
		if let Some(buf) = self.buf.take() {
			give_back(buf);
		}
	}
}

impl Copy {
	pub fn new(limit: usize) -> Self {
		Copy {
			buf: None,
			pos: 0,
			cap: 0,
			read_done: false,
			need_flush: false,
			amt: 0,
			limit: limit.clamp(1, BUFFER_SIZE),
			handover: None,
			full_streak: 0,
		}
	}

	/// Makes `poll_copy` return `Step::Handover` once `h` holds.
	pub fn with_handover(mut self, h: Option<Handover>) -> Self {
		self.handover = h;
		self
	}

	/// Gives the buffer back once everything in it has been written.
	fn release_if_empty(&mut self) {
		if self.pos == self.cap {
			self.pos = 0;
			self.cap = 0;
			if let Some(buf) = self.buf.take() {
				give_back(buf);
			}
		}
	}

	fn poll_fill<R: AsyncRead + ?Sized>(&mut self, cx: &mut Context<'_>, reader: Pin<&mut R>) -> Poll<io::Result<()>> {
		let buf = self.buf.get_or_insert_with(take);
		let mut rb = ReadBuf::new(&mut buf[..self.limit]);
		rb.set_filled(self.cap);
		let res = reader.poll_read(cx, &mut rb);
		if let Poll::Ready(Ok(())) = res {
			let filled = rb.filled().len();
			self.read_done = filled == self.cap;
			if filled > self.cap {
				self.full_streak = if filled == self.limit { self.full_streak.saturating_add(1) } else { 0 };
			}
			self.cap = filled;
		}
		res
	}

	pub fn poll_copy<R, W>(&mut self, cx: &mut Context<'_>, mut reader: Pin<&mut R>, mut writer: Pin<&mut W>) -> Poll<io::Result<Step>>
	where
		R: AsyncRead + ?Sized,
		W: AsyncWrite + ?Sized,
	{
		let coop = ready!(tokio::task::coop::poll_proceed(cx));
		loop {
			// read more while there is room, for larger writes
			if !self.read_done && self.cap < self.limit {
				match self.poll_fill(cx, reader.as_mut()) {
					Poll::Ready(Ok(())) => coop.made_progress(),
					Poll::Ready(Err(e)) => {
						coop.made_progress();
						return Poll::Ready(Err(e));
					}
					Poll::Pending => {
						if self.pos == self.cap {
							// nothing in flight: the buffer goes back while the reader waits
							self.release_if_empty();
							// flush when there is nothing more to read, so a writer that
							// buffers (TLS) does not keep the last records (#187)
							if self.need_flush {
								ready!(writer.as_mut().poll_flush(cx))?;
								coop.made_progress();
								self.need_flush = false;
							}
							return Poll::Pending;
						}
					}
				}
			}

			while self.pos < self.cap {
				let buf = self.buf.as_ref().expect("data in flight is in a buffer");
				match writer.as_mut().poll_write(cx, &buf[self.pos..self.cap]) {
					Poll::Pending => {
						// top up the buffer while the writer is full, for a larger write
						if !self.read_done && self.cap < self.limit {
							ready!(self.poll_fill(cx, reader.as_mut()))?;
						}
						return Poll::Pending;
					}
					Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
					Poll::Ready(Ok(0)) => {
						return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero byte into writer")));
					}
					Poll::Ready(Ok(n)) => {
						coop.made_progress();
						self.pos += n;
						self.amt += n as u64;
						self.need_flush = true;
					}
				}
			}
			debug_assert!(self.pos <= self.cap, "writer returned length larger than input slice");
			// all written: keep the buffer for the next read in this round
			self.pos = 0;
			self.cap = 0;

			if self.read_done {
				self.release_if_empty();
				ready!(writer.as_mut().poll_flush(cx))?;
				coop.made_progress();
				return Poll::Ready(Ok(Step::Done(self.amt)));
			}
			if let Some(h) = self.handover {
				if self.full_streak >= h.full_reads && self.amt >= h.after {
					self.release_if_empty();
					ready!(writer.as_mut().poll_flush(cx))?;
					self.need_flush = false;
					return Poll::Ready(Ok(Step::Handover(self.amt)));
				}
			}
		}
	}
}

enum State {
	Running(Copy),
	ShuttingDown(u64),
	Done(u64),
}

fn transfer<A, B>(cx: &mut Context<'_>, state: &mut State, r: &mut A, w: &mut B) -> Poll<io::Result<u64>>
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let mut r = Pin::new(r);
	let mut w = Pin::new(w);
	loop {
		match state {
			State::Running(copy) => {
				// no handover is set here, so the copy runs until the reader ends
				let (Step::Done(count) | Step::Handover(count)) = ready!(copy.poll_copy(cx, r.as_mut(), w.as_mut()))?;
				// the reader ended (FIN, or close_notify on TLS): pass it on as a half-close
				*state = State::ShuttingDown(count);
			}
			State::ShuttingDown(count) => {
				ready!(w.as_mut().poll_shutdown(cx))?;
				*state = State::Done(*count);
			}
			State::Done(count) => return Poll::Ready(Ok(*count)),
		}
	}
}

/// Copies `a` to `b` and `b` to `a` until both have ended, like
/// `tokio::io::copy_bidirectional`: the end of one side's reading is passed on as
/// a shutdown of the other's writing (a half-close) and the other direction goes
/// on; the first error ends both and is returned. Returns the bytes copied
/// from `a` to `b` and from `b` to `a`.
pub async fn bidirectional<A, B>(a: &mut A, b: &mut B) -> io::Result<(u64, u64)>
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	bidirectional_reading(a, b, BUFFER_SIZE, BUFFER_SIZE).await
}

/// `bidirectional`, reading at most `a_read` bytes at a time from `a` and
/// `b_read` from `b` (`TLS_READ_SIZE` for a TLS stream).
pub async fn bidirectional_reading<A, B>(a: &mut A, b: &mut B, a_read: usize, b_read: usize) -> io::Result<(u64, u64)>
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let mut a_to_b = State::Running(Copy::new(a_read));
	let mut b_to_a = State::Running(Copy::new(b_read));
	poll_fn(|cx| {
		let a_to_b = transfer(cx, &mut a_to_b, a, b)?;
		let b_to_a = transfer(cx, &mut b_to_a, b, a)?;
		let a_to_b = ready!(a_to_b);
		let b_to_a = ready!(b_to_a);
		Poll::Ready(Ok((a_to_b, b_to_a)))
	})
	.await
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	#[tokio::test]
	async fn copies_both_ways_and_passes_on_half_closes() {
		let (mut a, a_peer) = tokio::io::duplex(1024);
		let (mut b, b_peer) = tokio::io::duplex(1024);
		let relay = tokio::spawn(async move { bidirectional(&mut a, &mut b).await });

		let up: Vec<u8> = (0..300_000u32).map(|i| (i * 7) as u8).collect();
		let down: Vec<u8> = (0..200_000u32).map(|i| (i * 13) as u8).collect();
		let (up2, down2) = (up.clone(), down.clone());
		let (mut ar, mut aw) = tokio::io::split(a_peer);
		let (mut br, mut bw) = tokio::io::split(b_peer);
		let w1 = tokio::spawn(async move {
			aw.write_all(&up2).await.unwrap();
			aw.shutdown().await.unwrap();
		});
		let w2 = tokio::spawn(async move {
			let mut got = vec![];
			br.read_to_end(&mut got).await.unwrap();
			// the client's end arrived; the backend still answers after it
			bw.write_all(&down2).await.unwrap();
			bw.shutdown().await.unwrap();
			got
		});
		let mut got_down = vec![];
		ar.read_to_end(&mut got_down).await.unwrap();
		w1.await.unwrap();
		assert_eq!(w2.await.unwrap(), up);
		assert_eq!(got_down, down);
		assert_eq!(relay.await.unwrap().unwrap(), (up.len() as u64, down.len() as u64));
	}
}
