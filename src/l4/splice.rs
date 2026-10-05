//! Experiment (#184): relays a plain TCP connection (no TLS terminated, no
//! STARTTLS) with splice(2) through a pipe per direction, so the data does not
//! pass through user space. Bytes already read (the ClientHello of `sni`) and
//! the PROXY header are written before, the normal way.
//!
//! Switched by environment variables, read once (internal, for the load test):
//! - `RPROXY_SPLICE=0` turns it off (the relay of `copy_bidirectional` as before)
//! - `RPROXY_SPLICE_AFTER=<bytes>`: a direction is relayed in user space until it
//!   has carried this many bytes, then with splice (like HAProxy's `splice-auto`:
//!   small exchanges never pay for the pipe). 0 splices from the first byte.
//! - `RPROXY_SPLICE_FULL_READS=<n>`: also wait until n user-space reads in a row
//!   have filled the whole buffer (a bulk transfer, not request / response; the
//!   heuristic of HAProxy's `splice-auto`). 0 does not wait.
//! - `RPROXY_SPLICE_PIPE_SIZE=<bytes>`: F_SETPIPE_SZ for new pipes (0: the kernel's, 64 KiB)
//!
//! A pipe is taken when a direction has data to splice and given back, empty, to
//! a small shared pool when the direction waits for more (so an idle connection
//! holds no pipe, as HAProxy does); a pipe with data left is closed. A side that cannot be spliced (EINVAL / ENOSYS) or a pipe that
//! cannot be made (EMFILE) falls back to the user-space copy for that direction.

use std::io;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use tokio::io::Interest;
use tokio::net::TcpStream;

const DEFAULT_ENABLED: bool = true;
const DEFAULT_AFTER: u64 = 0;
const DEFAULT_FULL_READS: u32 = 4;
/// User-space buffer before splicing starts or when it cannot be used (as `copy_bidirectional`).
const BUF_SIZE: usize = 8 * 1024;
/// Empty pipes kept for the next bursts (shared by all threads; 2 FDs each).
const POOL_MAX: usize = 8;
/// The most asked of one splice into the pipe (the pipe's room limits it anyway).
const SPLICE_LEN: usize = 1 << 20;

#[derive(Clone, Copy)]
pub struct Settings {
	pub enabled: bool,
	pub after: u64,
	pub full_reads: u32,
	pub pipe_size: usize,
}

pub fn settings() -> &'static Settings {
	static SETTINGS: OnceLock<Settings> = OnceLock::new();
	SETTINGS.get_or_init(|| {
		let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
		Settings {
			enabled: var("RPROXY_SPLICE").map(|v| !matches!(v.trim(), "0" | "false" | "off")).unwrap_or(DEFAULT_ENABLED),
			after: var("RPROXY_SPLICE_AFTER").and_then(|v| v.trim().parse().ok()).unwrap_or(DEFAULT_AFTER),
			full_reads: var("RPROXY_SPLICE_FULL_READS").and_then(|v| v.trim().parse().ok()).unwrap_or(DEFAULT_FULL_READS),
			pipe_size: var("RPROXY_SPLICE_PIPE_SIZE").and_then(|v| v.trim().parse().ok()).unwrap_or(0),
		}
	})
}

struct PipeFds {
	read: OwnedFd,
	write: OwnedFd,
}

static POOL: Mutex<Vec<PipeFds>> = Mutex::new(Vec::new());

/// A pipe in use by one direction; `pending` bytes are in it.
struct Pipe {
	fds: Option<PipeFds>,
	pending: usize,
}

impl Pipe {
	fn take() -> io::Result<Pipe> {
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

/// Relays `a` (the client) and `b` (the backend) until both sides close, like
/// `copy_bidirectional`: a clean close (FIN) of one side is passed on as a
/// half-close, an error of either direction ends both. Bytes read from `a` are
/// counted in `rx` and `rx_total`, from `b` in `tx` and `tx_total`, as they move.
pub async fn relay(
	a: &TcpStream,
	b: &TcpStream,
	rx: &AtomicU64,
	tx: &AtomicU64,
	rx_total: &AtomicU64,
	tx_total: &AtomicU64,
) -> io::Result<()> {
	tokio::try_join!(direction(a, b, rx, rx_total), direction(b, a, tx, tx_total))?;
	Ok(())
}

async fn direction(src: &TcpStream, dst: &TcpStream, count: &AtomicU64, total: &AtomicU64) -> io::Result<()> {
	let Settings { after, full_reads, .. } = *settings();
	let (src_fd, dst_fd) = (src.as_raw_fd(), dst.as_raw_fd());
	// user-space reads in a row that filled the buffer
	let mut streak = 0u32;
	let mut pipe: Option<Pipe> = None;
	let mut buf: Option<Box<[u8]>> = None;
	let mut user_space = false;
	// splicing once started goes on (the pipe itself is given back while idle)
	let mut spliced = false;
	loop {
		if !user_space && (spliced || (count.load(Ordering::Relaxed) >= after && streak >= full_reads)) {
			spliced = true;
			// the user-space buffer is empty here (each read is written out in full)
			buf = None;
			// wait without a pipe; take one only when there is something to move
			src.readable().await?;
			let p = match pipe.as_mut() {
				Some(p) => p,
				None => match Pipe::take() {
					Ok(p) => pipe.insert(p),
					Err(_) => {
						user_space = true;
						continue;
					}
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
				Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS)) => {
					user_space = true;
					continue;
				}
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
					Ok(m) => p.pending -= m,
					Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
					Err(e) => return Err(e),
				}
			}
		} else {
			let b = buf.get_or_insert_with(|| vec![0; BUF_SIZE].into_boxed_slice());
			src.readable().await?;
			let n = match src.try_read(b) {
				Ok(0) => break,
				Ok(n) => n,
				Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
				Err(e) => return Err(e),
			};
			streak = if n == b.len() { streak.saturating_add(1) } else { 0 };
			count.fetch_add(n as u64, Ordering::Relaxed);
			total.fetch_add(n as u64, Ordering::Relaxed);
			let mut off = 0;
			while off < n {
				dst.writable().await?;
				match dst.try_write(&b[off..n]) {
					Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
					Ok(m) => off += m,
					Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
					Err(e) => return Err(e),
				}
			}
		}
	}
	// end of this direction: pass the FIN on (what poll_shutdown of a TcpStream does)
	socket2::SockRef::from(dst).shutdown(Shutdown::Write)
}
