//! The bpf(2) calls the fast paths share (#260). Kept to what rproxy uses;
//! the programs themselves come with the fast paths.

use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd};

#[cfg(target_os = "linux")]
const BPF_MAP_CREATE: libc::c_long = 0;
#[cfg(target_os = "linux")]
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;

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
