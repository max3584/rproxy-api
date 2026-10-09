//! The bpf(2) calls the fast paths share (#260). Kept to what rproxy uses;
//! the programs themselves come with the fast paths.

use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

#[cfg(target_os = "linux")]
const BPF_MAP_CREATE: libc::c_long = 0;
#[cfg(target_os = "linux")]
const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
#[cfg(target_os = "linux")]
const BPF_PROG_LOAD: libc::c_long = 5;
#[cfg(target_os = "linux")]
const BPF_PROG_ATTACH: libc::c_long = 8;
#[cfg(target_os = "linux")]
const BPF_PROG_DETACH: libc::c_long = 9;

#[cfg(target_os = "linux")]
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
#[cfg(target_os = "linux")]
pub const BPF_MAP_TYPE_SOCKMAP: u32 = 15;

#[cfg(target_os = "linux")]
const BPF_PROG_TYPE_SK_SKB: u32 = 14;
/// Attach type of the stream verdict program on a sockmap.
#[cfg(target_os = "linux")]
pub const BPF_SK_SKB_STREAM_VERDICT: u32 = 5;

/// A BPF map; closed on drop.
#[derive(Debug)]
pub struct Map {
	#[cfg(target_os = "linux")]
	fd: OwnedFd,
}

/// `union bpf_attr` for BPF_MAP_CREATE (the fields rproxy sets; the rest
/// must be zero).
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct MapCreate {
	map_type: u32,
	key_size: u32,
	value_size: u32,
	max_entries: u32,
	map_flags: u32,
	inner_map_fd: u32,
	numa_node: u32,
	map_name: [u8; 16],
	map_ifindex: u32,
	btf_fd: u32,
	btf_key_type_id: u32,
	btf_value_type_id: u32,
	btf_vmlinux_value_type_id: u32,
	map_extra: u64,
}

/// bpf(2).
#[cfg(target_os = "linux")]
fn sys_bpf<T>(cmd: libc::c_long, attr: &mut T) -> io::Result<libc::c_long> {
	// SAFETY: attr is a valid, fully initialised bpf_attr prefix of its size
	let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr as *mut T, std::mem::size_of::<T>() as libc::c_uint) };
	if r < 0 {
		Err(io::Error::last_os_error())
	} else {
		Ok(r)
	}
}

impl Map {
	/// A map of `map_type`; `name` up to 15 bytes.
	#[cfg(target_os = "linux")]
	pub fn create(map_type: u32, key_size: u32, value_size: u32, max_entries: u32, name: &str) -> io::Result<Map> {
		let mut attr = MapCreate { map_type, key_size, value_size, max_entries, ..Default::default() };
		for (dst, src) in attr.map_name.iter_mut().zip(name.bytes().take(15)) {
			*dst = src;
		}
		let fd = sys_bpf(BPF_MAP_CREATE, &mut attr)?;
		// SAFETY: the kernel returned a new descriptor we own
		Ok(Map { fd: unsafe { OwnedFd::from_raw_fd(fd as i32) } })
	}

	/// An array map of `entries` values of `value_size` bytes.
	pub fn array(value_size: u32, entries: u32) -> io::Result<Map> {
		#[cfg(target_os = "linux")]
		{
			Map::create(BPF_MAP_TYPE_ARRAY, 4, value_size, entries, "rproxy_probe")
		}
		#[cfg(not(target_os = "linux"))]
		{
			let _ = (value_size, entries);
			Err(io::Error::new(io::ErrorKind::Unsupported, "BPF needs Linux"))
		}
	}

	#[cfg(target_os = "linux")]
	pub fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
		use std::os::fd::AsFd;
		self.fd.as_fd()
	}

	/// A sockmap with `entries` slots (key u32, value a socket fd).
	#[cfg(target_os = "linux")]
	pub fn sockmap(entries: u32) -> io::Result<Map> {
		Map::create(BPF_MAP_TYPE_SOCKMAP, 4, 4, entries, "rproxy_sk")
	}

	/// Puts socket `sock` at `key` (sockmap update: the value is the fd).
	#[cfg(target_os = "linux")]
	pub fn put_socket(&self, key: u32, sock: BorrowedFd<'_>) -> io::Result<()> {
		let fd_val: u32 = sock.as_raw_fd() as u32;
		let mut attr = MapChange {
			map_fd: self.fd.as_raw_fd() as u32,
			_pad: 0,
			key: (&key as *const u32) as u64,
			value: (&fd_val as *const u32) as u64,
			flags: 0,
		};
		sys_bpf(BPF_MAP_UPDATE_ELEM, &mut attr).map(drop)
	}
}

/// `union bpf_attr` for BPF_MAP_UPDATE_ELEM / DELETE_ELEM.
#[cfg(target_os = "linux")]
#[repr(C)]
struct MapChange {
	map_fd: u32,
	_pad: u32,
	key: u64,
	value: u64,
	flags: u64,
}

/// `union bpf_attr` for BPF_PROG_LOAD (the fields rproxy sets).
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct ProgLoad {
	prog_type: u32,
	insn_cnt: u32,
	insns: u64,
	license: u64,
	log_level: u32,
	log_size: u32,
	log_buf: u64,
	kern_version: u32,
	prog_flags: u32,
	prog_name: [u8; 16],
	prog_ifindex: u32,
	expected_attach_type: u32,
}

/// `union bpf_attr` for BPF_PROG_ATTACH / DETACH.
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default)]
struct ProgAttach {
	target_fd: u32,
	attach_bpf_fd: u32,
	attach_type: u32,
	attach_flags: u32,
	replace_bpf_fd: u32,
}

/// A loaded BPF program; closed (and so unloaded) on drop.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Prog {
	fd: OwnedFd,
}

/// One BPF instruction (`struct bpf_insn`, 8 bytes).
#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Insn {
	code: u8,
	regs: u8,
	off: i16,
	imm: i32,
}

#[cfg(target_os = "linux")]
impl Insn {
	pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
		Insn { code, regs: (src << 4) | (dst & 0xf), off, imm }
	}
}

#[cfg(target_os = "linux")]
impl Prog {
	/// Loads an SK_SKB program (`insns`) with `expected_attach_type`; `log`
	/// receives the verifier log on failure. License "GPL" (the redirect
	/// helpers are GPL-only).
	pub fn load_sk_skb(insns: &[Insn], name: &str, expected_attach_type: u32) -> io::Result<Prog> {
		let license = b"GPL\0";
		let mut log = vec![0u8; 16 << 10];
		let mut attr = ProgLoad {
			prog_type: BPF_PROG_TYPE_SK_SKB,
			insn_cnt: insns.len() as u32,
			insns: insns.as_ptr() as u64,
			license: license.as_ptr() as u64,
			log_level: 1,
			log_size: log.len() as u32,
			log_buf: log.as_mut_ptr() as u64,
			expected_attach_type,
			..Default::default()
		};
		for (dst, src) in attr.prog_name.iter_mut().zip(name.bytes().take(15)) {
			*dst = src;
		}
		match sys_bpf(BPF_PROG_LOAD, &mut attr) {
			Ok(fd) => Ok(Prog { fd: unsafe { OwnedFd::from_raw_fd(fd as i32) } }),
			Err(e) => {
				let end = log.iter().position(|&b| b == 0).unwrap_or(0);
				let msg = String::from_utf8_lossy(&log[..end]);
				let msg = msg.trim();
				if msg.is_empty() {
					Err(e)
				} else {
					Err(io::Error::new(e.kind(), format!("{e}: {msg}")))
				}
			}
		}
	}

	/// Attaches this program to `map` with `attach_type`. The returned guard
	/// detaches on drop; keep the map and program alive until then (drop them
	/// after the guard).
	pub fn attach(&self, map: BorrowedFd<'_>, attach_type: u32) -> io::Result<Attached> {
		let mut attr = ProgAttach {
			target_fd: map.as_raw_fd() as u32,
			attach_bpf_fd: self.fd.as_raw_fd() as u32,
			attach_type,
			..Default::default()
		};
		sys_bpf(BPF_PROG_ATTACH, &mut attr)?;
		Ok(Attached { prog: self.fd.as_raw_fd() as u32, map: map.as_raw_fd() as u32, attach_type })
	}
}

/// Detaches a program from a map when dropped (by the raw ids of the program
/// and map, which the holder must keep open until this is dropped).
#[cfg(target_os = "linux")]
pub struct Attached {
	prog: u32,
	map: u32,
	attach_type: u32,
}

#[cfg(target_os = "linux")]
impl Drop for Attached {
	fn drop(&mut self) {
		let mut attr = ProgAttach { target_fd: self.map, attach_bpf_fd: self.prog, attach_type: self.attach_type, ..Default::default() };
		let _ = sys_bpf(BPF_PROG_DETACH, &mut attr);
	}
}

/// A bpf(2) error with what usually causes it.
pub fn explain(e: &io::Error) -> String {
	match e.raw_os_error() {
		Some(libc::EPERM) => format!("{e} (missing CAP_BPF / CAP_SYS_ADMIN, kernel.unprivileged_bpf_disabled or lockdown; before 5.11 also RLIMIT_MEMLOCK)"),
		Some(libc::ENOSYS) => format!("{e} (the kernel has no bpf(2), or seccomp blocks it)"),
		Some(libc::EINVAL) => format!("{e} (this kernel does not know the request)"),
		_ => e.to_string(),
	}
}
