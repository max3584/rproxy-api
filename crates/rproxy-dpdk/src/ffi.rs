//! The DPDK calls (through src/shim.c) and thin safe wrappers. Only what the
//! forwarder needs: EAL, one mbuf pool, ports, bursts, lcore launch.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr, CString};

/// An `rte_mbuf` (opaque).
#[repr(C)]
pub struct Mbuf {
	_private: [u8; 0],
}

/// An `rte_mempool` (opaque).
#[repr(C)]
pub struct RawPool {
	_private: [u8; 0],
}

extern "C" {
	fn rp_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
	fn rp_eal_cleanup() -> c_int;
	fn rp_strerror(e: c_int) -> *const c_char;
	fn rp_version() -> *const c_char;
	fn rp_pool_create(name: *const c_char, n: c_uint, cache: c_uint, err: *mut c_int) -> *mut RawPool;
	fn rp_port_by_name(name: *const c_char, port: *mut u16) -> c_int;
	fn rp_port_driver(port: u16, buf: *mut c_char, len: usize) -> c_int;
	fn rp_port_setup(port: u16, pool: *mut RawPool, rxq: u16, txq: u16, rxd: u16, txd: u16, err: *mut c_char, errlen: usize) -> c_int;
	fn rp_port_mac(port: u16, mac: *mut u8) -> c_int;
	fn rp_port_link(port: u16, speed: *mut u32) -> c_int;
	fn rp_port_stop(port: u16) -> c_int;
	fn rp_rx(port: u16, q: u16, pkts: *mut *mut Mbuf, n: u16) -> u16;
	fn rp_tx(port: u16, q: u16, pkts: *mut *mut Mbuf, n: u16) -> u16;
	fn rp_data(m: *mut Mbuf, len: *mut u16) -> *mut u8;
	fn rp_copy(pool: *mut RawPool, data: *const u8, len: u16) -> *mut Mbuf;
	fn rp_free(m: *mut Mbuf);
	fn rp_free_bulk(m: *mut *mut Mbuf, n: c_uint);
	fn rp_lcore_id() -> c_uint;
	fn rp_main_lcore() -> c_uint;
	fn rp_next_worker(prev: c_uint) -> c_uint;
	fn rp_max_lcore() -> c_uint;
	fn rp_launch(f: extern "C" fn(*mut c_void) -> c_int, arg: *mut c_void, lcore: c_uint) -> c_int;
	fn rp_wait(lcore: c_uint) -> c_int;
}

fn strerror(e: c_int) -> String {
	// SAFETY: rte_strerror returns a static (or thread-local) NUL-terminated string
	unsafe { CStr::from_ptr(rp_strerror(e.abs())) }.to_string_lossy().into_owned()
}

/// The DPDK version string (e.g. "DPDK 24.11.4").
pub fn version() -> String {
	// SAFETY: a static string
	unsafe { CStr::from_ptr(rp_version()) }.to_string_lossy().into_owned()
}

/// Initialises the EAL with `args` (the program name first). Once per
/// process: the calling thread becomes the main lcore (pinned to its CPU), so
/// call it from a thread of its own, not from one whose affinity others inherit.
pub fn eal_init(args: &[String]) -> Result<(), String> {
	let owned: Vec<CString> = args.iter().map(|a| CString::new(a.as_str()).map_err(|_| format!("NUL in EAL argument {a:?}"))).collect::<Result<_, _>>()?;
	// EAL may reorder argv; it keeps the pointers, so they must outlive the process: leak them
	let mut argv: Vec<*mut c_char> = owned.into_iter().map(CString::into_raw).collect();
	argv.push(std::ptr::null_mut());
	let argc = (argv.len() - 1) as c_int;
	let argv = Box::leak(argv.into_boxed_slice());
	// SAFETY: argv is a NULL-terminated array of NUL-terminated strings, kept forever
	let r = unsafe { rp_eal_init(argc, argv.as_mut_ptr()) };
	if r < 0 {
		return Err(format!("rte_eal_init: {}", strerror(r)));
	}
	Ok(())
}

/// Releases the EAL's resources (hugepages, devices) at exit.
pub fn eal_cleanup() {
	// SAFETY: after every lcore has returned
	unsafe { rp_eal_cleanup() };
}

/// The mbuf pool (shared by every port and lcore).
#[derive(Clone, Copy)]
pub struct Pool(*mut RawPool);

// SAFETY: rte_mempool is thread safe (per-lcore caches, a lock-free ring)
unsafe impl Send for Pool {}
unsafe impl Sync for Pool {}

impl Pool {
	pub fn create(name: &str, mbufs: u32, cache: u32) -> Result<Pool, String> {
		let name = CString::new(name).map_err(|_| "bad pool name")?;
		let mut err = 0;
		// SAFETY: valid name; err is written on failure
		let p = unsafe { rp_pool_create(name.as_ptr(), mbufs, cache, &mut err) };
		if p.is_null() {
			return Err(format!("rte_pktmbuf_pool_create({mbufs} mbufs, cache {cache}): {}", strerror(err)));
		}
		Ok(Pool(p))
	}

	/// A new mbuf with a copy of `data`; None when the pool is empty.
	pub fn copy(&self, data: &[u8]) -> Option<*mut Mbuf> {
		let len = u16::try_from(data.len()).ok()?;
		// SAFETY: the pool is valid for the process; data is len bytes
		let m = unsafe { rp_copy(self.0, data.as_ptr(), len) };
		(!m.is_null()).then_some(m)
	}
}

/// A port (ethdev) by its id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Port(pub u16);

impl Port {
	/// The port DPDK made for a PCI address or vdev name (as given to the EAL).
	pub fn by_name(name: &str) -> Result<Port, String> {
		let c = CString::new(name).map_err(|_| "bad port name")?;
		let mut id = 0u16;
		// SAFETY: valid name, id is written on success
		match unsafe { rp_port_by_name(c.as_ptr(), &mut id) } {
			0 => Ok(Port(id)),
			e => Err(format!("{name}: no such DPDK port ({}; is it bound to vfio-pci / given to the EAL?)", strerror(e))),
		}
	}

	pub fn driver(&self) -> String {
		let mut buf = [0 as c_char; 64];
		// SAFETY: buf is 64 bytes, NUL-terminated by snprintf
		if unsafe { rp_port_driver(self.0, buf.as_mut_ptr(), buf.len()) } != 0 {
			return String::new();
		}
		unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
	}

	pub fn setup(&self, pool: Pool, rxq: u16, txq: u16, rxd: u16, txd: u16) -> Result<(), String> {
		let mut err = [0 as c_char; 256];
		// SAFETY: a valid pool; err is 256 bytes
		match unsafe { rp_port_setup(self.0, pool.0, rxq, txq, rxd, txd, err.as_mut_ptr(), err.len()) } {
			0 => Ok(()),
			_ => Err(unsafe { CStr::from_ptr(err.as_ptr()) }.to_string_lossy().into_owned()),
		}
	}

	pub fn mac(&self) -> Result<[u8; 6], String> {
		let mut mac = [0u8; 6];
		// SAFETY: mac is 6 bytes
		match unsafe { rp_port_mac(self.0, mac.as_mut_ptr()) } {
			0 => Ok(mac),
			e => Err(format!("rte_eth_macaddr_get: {}", strerror(e))),
		}
	}

	/// Whether the link is up, and its speed in Mbit/s.
	pub fn link(&self) -> Result<(bool, u32), String> {
		let mut speed = 0;
		// SAFETY: speed is written
		match unsafe { rp_port_link(self.0, &mut speed) } {
			r if r < 0 => Err(format!("rte_eth_link_get_nowait: {}", strerror(r))),
			r => Ok((r == 1, speed)),
		}
	}

	pub fn stop(&self) {
		// SAFETY: no lcore uses the port any more
		unsafe { rp_port_stop(self.0) };
	}

	/// Receives up to `bufs.len()` frames into `bufs`; returns how many.
	#[inline]
	pub fn rx(&self, q: u16, bufs: &mut [*mut Mbuf]) -> usize {
		let n = u16::try_from(bufs.len()).unwrap_or(u16::MAX);
		// SAFETY: bufs has room for n pointers; one lcore per queue
		usize::from(unsafe { rp_rx(self.0, q, bufs.as_mut_ptr(), n) })
	}

	/// Sends `bufs`; returns how many the port took (the rest still belong to the caller).
	#[inline]
	pub fn tx(&self, q: u16, bufs: &mut [*mut Mbuf]) -> usize {
		let n = u16::try_from(bufs.len()).unwrap_or(u16::MAX);
		// SAFETY: valid mbufs; one lcore per queue
		usize::from(unsafe { rp_tx(self.0, q, bufs.as_mut_ptr(), n) })
	}
}

/// The bytes of a one-segment mbuf; None for chained mbufs.
///
/// # Safety
/// `m` must be a valid mbuf owned by the caller, not used elsewhere while the slice lives.
#[inline]
pub unsafe fn data<'a>(m: *mut Mbuf) -> Option<&'a mut [u8]> {
	let mut len = 0u16;
	let p = rp_data(m, &mut len);
	(!p.is_null()).then(|| std::slice::from_raw_parts_mut(p, usize::from(len)))
}

/// # Safety
/// `m` must be a valid mbuf owned by the caller.
#[inline]
pub unsafe fn free(m: *mut Mbuf) {
	rp_free(m)
}

/// # Safety
/// The mbufs must be valid and owned by the caller.
#[inline]
pub unsafe fn free_all(ms: &mut [*mut Mbuf]) {
	if !ms.is_empty() {
		rp_free_bulk(ms.as_mut_ptr(), ms.len() as c_uint)
	}
}

pub fn lcore_id() -> u32 {
	// SAFETY: no arguments
	unsafe { rp_lcore_id() }
}

pub fn main_lcore() -> u32 {
	unsafe { rp_main_lcore() }
}

/// The worker lcores (all but the main one), in order.
pub fn workers() -> Vec<u32> {
	let max = unsafe { rp_max_lcore() };
	let mut out = vec![];
	let mut prev = u32::MAX;
	loop {
		// rte_get_next_lcore takes the previous id; u32::MAX (-1) starts at 0
		let next = unsafe { rp_next_worker(prev) };
		if next >= max {
			return out;
		}
		out.push(next);
		prev = next;
	}
}

/// Runs `f` on the worker lcore `lcore` (it must be idle).
pub fn launch(lcore: u32, f: Box<dyn FnOnce() + Send>) -> Result<(), String> {
	extern "C" fn trampoline(arg: *mut c_void) -> c_int {
		// SAFETY: made from Box::into_raw below, run once
		let f = unsafe { Box::from_raw(arg as *mut Box<dyn FnOnce() + Send>) };
		match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
			Ok(()) => 0,
			Err(_) => -1,
		}
	}
	let arg = Box::into_raw(Box::new(f)) as *mut c_void;
	// SAFETY: trampoline takes the box back exactly once
	match unsafe { rp_launch(trampoline, arg, lcore) } {
		0 => Ok(()),
		e => {
			drop(unsafe { Box::from_raw(arg as *mut Box<dyn FnOnce() + Send>) });
			Err(format!("rte_eal_remote_launch(lcore {lcore}): {}", strerror(e)))
		}
	}
}

/// Waits for the function launched on `lcore` to return.
pub fn wait(lcore: u32) -> i32 {
	unsafe { rp_wait(lcore) }
}
