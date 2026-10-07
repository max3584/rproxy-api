//! Experiment (#184): relays a plain TCP connection (no TLS terminated, no
//! STARTTLS) with splice(2) through a pipe per direction, so the data does not
//! pass through user space. Bytes already read (the ClientHello of `sni`) and
//! the PROXY header are written before, the normal way.
//!
//! Set by `global.performance.splice` (`config::performance`, #194) or, without
//! it, by environment variables, read once:
//! - `RPROXY_SPLICE=0` turns it off (only the user-space copy of `l4::relay`)
//! - `RPROXY_SPLICE_AFTER=<bytes>`: a direction is relayed in user space until it
//!   has carried this many bytes, then with splice (small exchanges never pay
//!   for the pipe). 0 does not wait.
//! - `RPROXY_SPLICE_FULL_READS=<n>` (default 4): also wait until n user-space
//!   reads in a row have filled the whole `relay` buffer (32 KiB: a bulk transfer,
//!   not request / response; like HAProxy's `splice-auto`). With both 0, splice
//!   from the first byte.
//! - `RPROXY_SPLICE_PIPE_SIZE=<bytes>`: F_SETPIPE_SZ for new pipes (0: the kernel's, 64 KiB)
//!
//! A pipe is taken when a direction has data to splice and given back, empty, to
//! a small shared pool when the direction waits for more (so an idle connection
//! holds no pipe, as HAProxy does); a pipe with data left is closed. The pool
//! is emptied when no direction is splicing any more. A side that cannot be
//! spliced (EINVAL / ENOSYS) or a pipe that cannot be made (EMFILE) goes back to
//! the user-space copy for the rest of that direction.

use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use std::future::poll_fn;
use std::pin::Pin;

use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use crate::core::proxy::Counted;
use crate::l4::relay::{self, Copy, Handover, Step};

const DEFAULT_ENABLED: bool = true;
const DEFAULT_AFTER: u64 = 0;
const DEFAULT_FULL_READS: u32 = 4;
/// Empty pipes kept for the next bursts (shared by all threads; 2 FDs each).
const POOL_MAX: usize = 8;
/// The most asked of one splice into the pipe (the pipe's room limits it anyway).
const SPLICE_LEN: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
	pub enabled: bool,
	pub after: u64,
	pub full_reads: u32,
	pub pipe_size: usize,
}

static SETTINGS: OnceLock<Settings> = OnceLock::new();

impl Default for Settings {
	fn default() -> Settings {
		Settings { enabled: DEFAULT_ENABLED, after: DEFAULT_AFTER, full_reads: DEFAULT_FULL_READS, pipe_size: 0 }
	}
}

impl Settings {
	/// From `RPROXY_SPLICE*`, or the defaults.
	pub fn from_env() -> Settings {
		let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
		Settings {
			enabled: var("RPROXY_SPLICE").map(|v| !matches!(v.trim(), "0" | "false" | "off")).unwrap_or(DEFAULT_ENABLED),
			after: var("RPROXY_SPLICE_AFTER").and_then(|v| v.trim().parse().ok()).unwrap_or(DEFAULT_AFTER),
			full_reads: var("RPROXY_SPLICE_FULL_READS").and_then(|v| v.trim().parse().ok()).unwrap_or(DEFAULT_FULL_READS),
			pipe_size: var("RPROXY_SPLICE_PIPE_SIZE").and_then(|v| v.trim().parse().ok()).unwrap_or(0),
		}
	}
}

/// The settings in use: `global.performance.splice` (`configure`, at startup),
/// else `RPROXY_SPLICE*`, else the defaults. Fixed once read.
pub fn settings() -> &'static Settings {
	SETTINGS.get_or_init(Settings::from_env)
}

/// Sets the settings before the first connection (`config::performance`);
/// false when they were already read.
pub fn configure(s: Settings) -> bool {
	SETTINGS.set(s).is_ok()
}

struct PipeFds {
	read: OwnedFd,
	write: OwnedFd,
}

static POOL: Mutex<Vec<PipeFds>> = Mutex::new(Vec::new());
/// Directions that have started splicing and not ended. When the last one ends,
/// the pool is emptied, so no pipe outlives the connections that used them.
static SPLICING: AtomicUsize = AtomicUsize::new(0);

/// Counts one direction in `SPLICING` while it lives.
struct Splicing;

impl Splicing {
	fn start() -> Splicing {
		SPLICING.fetch_add(1, Ordering::AcqRel);
		Splicing
	}
}

impl Drop for Splicing {
	fn drop(&mut self) {
		if SPLICING.fetch_sub(1, Ordering::AcqRel) == 1 {
			if let Ok(mut pool) = POOL.lock() {
				// another direction may have started meanwhile; it makes new pipes
				if SPLICING.load(Ordering::Acquire) == 0 {
					pool.clear();
				}
			}
		}
	}
}

/// Bytes moved by splice so far, over all connections (for tests and diagnostics).
static SPLICED_BYTES: AtomicU64 = AtomicU64::new(0);

pub fn spliced_bytes() -> u64 {
	SPLICED_BYTES.load(Ordering::Relaxed)
}

/// Pipes kept in the pool (2 FDs each), for tests and the load test.
pub fn pooled() -> usize {
	POOL.lock().map_or(0, |p| p.len())
}

/// Pipes held by directions right now (not counting the pool).
static PIPES_IN_USE: AtomicUsize = AtomicUsize::new(0);

/// Pipes that relays hold right now, over all connections. An idle connection
/// holds none.
pub fn pipes_in_use() -> usize {
	PIPES_IN_USE.load(Ordering::Relaxed)
}

/// A pipe in use by one direction; `pending` bytes are in it.
struct Pipe {
	fds: Option<PipeFds>,
	pending: usize,
}

impl Pipe {
	fn take() -> io::Result<Pipe> {
		let pipe = Pipe::open()?;
		PIPES_IN_USE.fetch_add(1, Ordering::Relaxed);
		Ok(pipe)
	}

	fn open() -> io::Result<Pipe> {
		if let Some(fds) = POOL.lock().ok().and_then(|mut p| p.pop()) {
			return Ok(Pipe { fds: Some(fds), pending: 0 });
		}
		let mut fds = [0 as libc::c_int; 2];
		// SAFETY: fds has room for the two descriptors pipe2 writes
		if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
			return Err(io::Error::last_os_error());
		}
		// SAFETY: pipe2 succeeded, so both are new descriptors owned by nobody else
		let fds = unsafe { PipeFds { read: OwnedFd::from_raw_fd(fds[0]), write: OwnedFd::from_raw_fd(fds[1]) } };
		let size = settings().pipe_size;
		if size > 0 {
			// a failure (above pipe-max-size, or the user's pipe pages) keeps the default size
			// SAFETY: fcntl on a descriptor we own
			let _ = unsafe { libc::fcntl(fds.write.as_raw_fd(), libc::F_SETPIPE_SZ, size as libc::c_int) };
		}
		Ok(Pipe { fds: Some(fds), pending: 0 })
	}

	fn read_fd(&self) -> RawFd {
		self.fds.as_ref().map_or(-1, |f| f.read.as_raw_fd())
	}

	fn write_fd(&self) -> RawFd {
		self.fds.as_ref().map_or(-1, |f| f.write.as_raw_fd())
	}
}

impl Drop for Pipe {
	fn drop(&mut self) {
		PIPES_IN_USE.fetch_sub(1, Ordering::Relaxed);
		// a pipe with data left (the relay was cut off) is closed, never reused
		if let (Some(fds), 0) = (self.fds.take(), self.pending) {
			if let Ok(mut pool) = POOL.lock() {
				if pool.len() < POOL_MAX {
					pool.push(fds);
				}
			}
		}
	}
}

fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
	// SAFETY: plain descriptors, no offsets
	let n = unsafe {
		libc::splice(from, std::ptr::null_mut(), to, std::ptr::null_mut(), len, libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK)
	};
	if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
}

/// Relays `a` (the client) and `b` (the backend) until both sides close, with
/// the semantics of `relay::bidirectional`: a clean close (FIN) of one side is
/// passed on as a half-close, an error of either direction ends both. Each
/// direction starts with the user-space copy of `relay` (pooled buffers) and,
/// once it carries a bulk transfer (`Settings::full_reads`, `Settings::after`),
/// moves on to splice. Bytes read from `a` are counted in `rx` and `rx_total`,
/// from `b` in `tx` and `tx_total`, as they move.
pub async fn relay(
	a: &mut TcpStream,
	b: &mut TcpStream,
	rx: &AtomicU64,
	tx: &AtomicU64,
	rx_total: &AtomicU64,
	tx_total: &AtomicU64,
) -> io::Result<()> {
	let (mut ar, mut aw) = a.split();
	let (mut br, mut bw) = b.split();
	tokio::try_join!(direction(&mut ar, &mut bw, rx, rx_total), direction(&mut br, &mut aw, tx, tx_total))?;
	Ok(())
}

async fn direction(r: &mut ReadHalf<'_>, w: &mut WriteHalf<'_>, count: &AtomicU64, total: &AtomicU64) -> io::Result<()> {
	let Settings { after, full_reads, .. } = *settings();
	let mut handover = Some(Handover { full_reads, after });
	loop {
		// user space, until the reader ends or the transfer is a bulk one
		let mut reader = Counted::new(&mut *r, total);
		let mut copy = Copy::new(relay::BUFFER_SIZE).with_handover(handover);
		let step = poll_fn(|cx| copy.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut *w))).await;
		count.fetch_add(reader.count, Ordering::Relaxed);
		drop(copy);
		match step? {
			Step::Done(_) => return w.shutdown().await,
			Step::Handover(_) => {}
		}
		match spliced(r.as_ref(), w.as_ref(), count, total).await? {
			Spliced::Ended => return Ok(()),
			// this pair cannot be spliced: the user-space copy to the end
			Spliced::Unsupported => handover = None,
		}
	}
}

enum Spliced {
	Ended,
	Unsupported,
}

/// Moves `src` to `dst` through a pipe until `src` ends, then passes the FIN on.
async fn spliced(src: &TcpStream, dst: &TcpStream, count: &AtomicU64, total: &AtomicU64) -> io::Result<Spliced> {
	let (src_fd, dst_fd) = (src.as_raw_fd(), dst.as_raw_fd());
	// declared before `pipe` so the pipe is given back before this ends (and may empty the pool)
	let _splicing = Splicing::start();
	let mut pipe: Option<Pipe> = None;
	loop {
		// wait without a pipe; take one only when there is something to move
		src.readable().await?;
		let p = match pipe.as_mut() {
			Some(p) => p,
			None => match Pipe::take() {
				Ok(p) => pipe.insert(p),
				Err(_) => return Ok(Spliced::Unsupported),
			},
		};
		// the pipe is empty, so EAGAIN is the socket's and clears its readiness
		let n = match src.try_io(Interest::READABLE, || splice(src_fd, p.write_fd(), SPLICE_LEN)) {
			Ok(0) => break,
			Ok(n) => n,
			Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
				// nothing to read and the pipe empty: give it back while waiting
				// (an idle connection holds no pipe)
				pipe = None;
				continue;
			}
			Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) => return Ok(Spliced::Unsupported),
			Err(e) => return Err(e),
		};
		p.pending += n;
		count.fetch_add(n as u64, Ordering::Relaxed);
		total.fetch_add(n as u64, Ordering::Relaxed);
		while p.pending > 0 {
			dst.writable().await?;
			// data is in the pipe, so EAGAIN is the socket's
			match dst.try_io(Interest::WRITABLE, || splice(p.read_fd(), dst_fd, p.pending)) {
				Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
				Ok(m) => {
					p.pending -= m;
					SPLICED_BYTES.fetch_add(m as u64, Ordering::Relaxed);
				}
				Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
				Err(e) => return Err(e),
			}
		}
	}
	// the end of this direction: pass the FIN on (what poll_shutdown of a TcpStream does)
	socket2::SockRef::from(dst).shutdown(Shutdown::Write)?;
	Ok(Spliced::Ended)
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;

	async fn pair() -> (TcpStream, TcpStream) {
		let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let c = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
		let (s, _) = l.accept().await.unwrap();
		(c, s)
	}

	#[tokio::test]
	async fn relays_every_byte_with_half_close_and_leaves_no_pipe() {
		// client <-> (a | relay | b) <-> backend
		let (mut client, mut a) = pair().await;
		let (mut b, mut backend) = pair().await;
		let spliced_before = spliced_bytes();
		let (rx, tx, rt, tt) = (AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0));
		let data: Vec<u8> = (0..4u32 << 20).map(|i| (i * 7 + i / 251) as u8).collect();
		let sent = data.clone();
		let relay = relay(&mut a, &mut b, &rx, &tx, &rt, &tt);
		let peers = async {
			let up = async {
				client.write_all(&sent).await.unwrap();
				client.shutdown().await.unwrap();
				let mut back = Vec::new();
				client.read_to_end(&mut back).await.unwrap();
				back
			};
			let down = async {
				let mut got = Vec::new();
				backend.read_to_end(&mut got).await.unwrap();
				// answer after the client's FIN (half-close)
				backend.write_all(&got[..100_000]).await.unwrap();
				backend.shutdown().await.unwrap();
				got
			};
			tokio::join!(up, down)
		};
		let (r, (back, got)) = tokio::join!(relay, peers);
		r.unwrap();
		assert!(got == data, "upload changed");
		assert!(back[..] == data[..100_000], "download changed");
		assert_eq!(rx.into_inner(), data.len() as u64);
		assert_eq!(tx.into_inner(), 100_000);
		assert!(spliced_bytes() > spliced_before, "the bulk upload was not spliced");
		assert_eq!(pooled(), 0, "pipes kept after the last splicing connection");
	}
}
