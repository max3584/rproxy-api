//! The AF_XDP socket: a UMEM and the four rings on one `(interface, queue)`,
//! via `xdpilone` (pure Rust, no libbpf). UMEM frames are split in two: the
//! lower half seeds the fill ring for RX, the upper half is a free list for TX,
//! reclaimed from the completion ring. Correctness is checked in CI on veth.

use std::io;
use std::num::NonZeroU32;
use std::os::fd::{BorrowedFd, RawFd};
use std::ptr::NonNull;

use xdpilone::xdp::XdpDesc;
use xdpilone::{BufIdx, DeviceQueue, IfInfo, RingRx, RingTx, Socket, SocketConfig, Umem, UmemConfig};

/// A UMEM region mmap'd anonymously; unmapped on drop.
struct Area {
	ptr: NonNull<u8>,
	len: usize,
}

impl Area {
	fn new(len: usize) -> io::Result<Area> {
		// SAFETY: a fresh anonymous mapping of `len` bytes
		let p = unsafe {
			libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE, -1, 0)
		};
		if p == libc::MAP_FAILED {
			return Err(io::Error::last_os_error());
		}
		Ok(Area { ptr: NonNull::new(p as *mut u8).unwrap(), len })
	}

	fn as_non_null_slice(&self) -> NonNull<[u8]> {
		NonNull::slice_from_raw_parts(self.ptr, self.len)
	}
}

impl Drop for Area {
	fn drop(&mut self) {
		// SAFETY: mapping we created, not used after this
		unsafe { libc::munmap(self.ptr.as_ptr() as *mut libc::c_void, self.len) };
	}
}

/// Parameters of an [`Xsk`].
#[derive(Clone, Copy, Debug)]
pub struct Config {
	pub queue: u32,
	pub ring_size: u32,
	pub frame_size: u32,
	pub zero_copy: bool,
	pub busy_poll: bool,
}

/// One AF_XDP socket bound to a queue of an interface.
pub struct Xsk {
	umem: Umem,
	device: DeviceQueue,
	rx: RingRx,
	tx: RingTx,
	frame_size: u64,
	/// Frames [0, rx_frames) seed the fill ring; [rx_frames, frames) are TX.
	rx_frames: u32,
	frames: u32,
	/// TX frames not in flight (addresses), reclaimed from the completion ring.
	tx_free: Vec<u64>,
	/// The UMEM's memory. Last field: dropped (unmapped) after the rings and
	/// the `Umem` that point into it.
	_area: Area,
}

fn err(e: impl std::fmt::Display) -> io::Error {
	io::Error::other(e.to_string())
}

impl Xsk {
	/// Creates and binds an XSK on `iface`'s `cfg.queue`. The fill ring is
	/// seeded; the program still has to point its XSKMAP at `fd()`.
	pub fn bind(iface: &str, cfg: Config) -> io::Result<Xsk> {
		let ring = cfg.ring_size.max(64).next_power_of_two();
		let frame_size = u64::from(cfg.frame_size);
		let frames = ring * 2;
		let area = Area::new(frames as usize * frame_size as usize)?;
		let umem_cfg = UmemConfig { fill_size: ring, complete_size: ring, frame_size: cfg.frame_size, headroom: 0, flags: 0 };
		// SAFETY: the area is page-aligned (mmap) and outlives the Umem: it is the
		// last field of `Xsk`, so it is unmapped after the Umem and the rings
		let umem = unsafe { Umem::new(umem_cfg, area.as_non_null_slice()) }.map_err(err)?;
		let mut info = IfInfo::invalid();
		let c = std::ffi::CString::new(iface).map_err(err)?;
		info.from_name(&c).map_err(err)?;
		info.set_queue(cfg.queue);
		let sock = Socket::with_shared(&info, &umem).map_err(err)?;
		let device = umem.fq_cq(&sock).map_err(err)?;
		let mut bind_flags = SocketConfig::XDP_BIND_NEED_WAKEUP;
		if cfg.zero_copy {
			bind_flags |= SocketConfig::XDP_BIND_ZEROCOPY;
		}
		let rxtx = umem
			.rx_tx(&sock, &SocketConfig { rx_size: NonZeroU32::new(ring), tx_size: NonZeroU32::new(ring), bind_flags })
			.map_err(err)?;
		let rx = rxtx.map_rx().map_err(err)?;
		let tx = rxtx.map_tx().map_err(err)?;
		umem.bind(&rxtx).map_err(err)?;
		let mut xsk = Xsk { umem, device, rx, tx, frame_size, rx_frames: ring, frames, tx_free: Vec::with_capacity(ring as usize), _area: area };
		xsk.seed_fill()?;
		for i in ring..frames {
			xsk.tx_free.push(u64::from(i) * frame_size);
		}
		Ok(xsk)
	}

	/// Puts the RX frames in the fill ring so the kernel can deliver into them.
	fn seed_fill(&mut self) -> io::Result<()> {
		let addrs = (0..self.rx_frames).map(|i| u64::from(i) * self.frame_size);
		let mut fill = self.device.fill(self.rx_frames);
		let put = fill.insert(addrs);
		fill.commit();
		if put < self.rx_frames {
			return Err(io::Error::other("could not seed the fill ring"));
		}
		Ok(())
	}

	/// The AF_XDP socket descriptor (the program's XSKMAP points at it).
	pub fn fd(&self) -> BorrowedFd<'_> {
		// SAFETY: the fd lives as long as the RingRx (and so `self`)
		unsafe { BorrowedFd::borrow_raw(self.raw_fd()) }
	}

	fn raw_fd(&self) -> RawFd {
		self.rx.as_raw_fd()
	}

	/// Calls `f` with each received frame, then returns the frames to the fill
	/// ring. Returns how many were handled (0 means nothing was waiting).
	pub fn recv(&mut self, mut f: impl FnMut(&[u8])) -> io::Result<usize> {
		let want = self.rx_frames;
		let frame_size = self.frame_size;
		// collect the descriptors first, so `self` is free while `f` runs
		let mut descs = vec![];
		{
			let mut reader = self.rx.receive(want);
			while let Some(desc) = reader.read() {
				descs.push(desc);
			}
			reader.release();
		}
		let mut refill = Vec::with_capacity(descs.len());
		for desc in &descs {
			// SAFETY: the kernel wrote `len` bytes at `addr` within a frame we own
			let bytes = unsafe { self.frame_bytes(desc.addr, desc.len as usize) };
			f(bytes);
			refill.push((desc.addr / frame_size) * frame_size);
		}
		let done = refill.len() as u32;
		if done > 0 {
			let mut fill = self.device.fill(done);
			fill.insert(refill.into_iter());
			fill.commit();
		}
		Ok(done as usize)
	}

	/// Sends one frame (a full L2 frame already built). Drops it (and returns
	/// `false`) when no TX frame is free. Reclaims completed frames first.
	pub fn send(&mut self, frame: &[u8]) -> io::Result<bool> {
		self.reclaim();
		let Some(addr) = self.tx_free.pop() else {
			return Ok(false);
		};
		if frame.len() as u64 > self.frame_size {
			self.tx_free.push(addr);
			return Err(io::Error::other("frame larger than the UMEM frame"));
		}
		// SAFETY: writing into a TX frame we own, within its size
		unsafe {
			let dst = self.umem_ptr(addr);
			std::ptr::copy_nonoverlapping(frame.as_ptr(), dst, frame.len());
		}
		let desc = XdpDesc { addr, len: frame.len() as u32, options: 0 };
		let put = {
			let mut writer = self.tx.transmit(1);
			let n = writer.insert(std::iter::once(desc));
			writer.commit();
			n
		};
		if put == 0 {
			self.tx_free.push(addr);
			return Ok(false);
		}
		if self.tx.needs_wakeup() {
			self.tx.wake();
		}
		Ok(true)
	}

	/// Waits up to `timeout_ms` for received frames, kicking the kernel first
	/// when the fill ring needs a wakeup (`XDP_BIND_NEED_WAKEUP`).
	pub fn wait(&mut self, timeout_ms: i32) {
		if self.device.needs_wakeup() {
			self.device.wake();
		}
		let mut p = libc::pollfd { fd: self.raw_fd(), events: libc::POLLIN, revents: 0 };
		// SAFETY: one pollfd on our socket
		unsafe { libc::poll(&mut p, 1, timeout_ms) };
	}

	/// Returns completed TX frames to the free list.
	fn reclaim(&mut self) {
		let mut reader = self.device.complete(self.frames);
		while let Some(addr) = reader.read() {
			let base = (addr / self.frame_size) * self.frame_size;
			self.tx_free.push(base);
		}
		reader.release();
	}

	/// Pointer to byte `addr` of the UMEM.
	unsafe fn umem_ptr(&self, addr: u64) -> *mut u8 {
		let idx = addr / self.frame_size;
		let chunk = self.umem.frame(BufIdx(idx as u32)).expect("addr within the UMEM");
		chunk.addr.as_ptr().cast::<u8>().add((addr % self.frame_size) as usize)
	}

	unsafe fn frame_bytes(&self, addr: u64, len: usize) -> &[u8] {
		std::slice::from_raw_parts(self.umem_ptr(addr), len)
	}
}
