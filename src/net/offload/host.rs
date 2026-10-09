//! What the host allows (#260): capabilities, RLIMIT_MEMLOCK, BTF, lockdown,
//! `kernel.unprivileged_bpf_disabled`, and whether bpf(2) works at all. Only
//! for the reasons and the `--check-kernel` table: whether a fast path is used
//! is decided by pushing test data through it (`probe`), not by these.

use serde::Serialize;

/// Capability numbers (linux/capability.h).
pub const CAP_NET_ADMIN: u32 = 12;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_PERFMON: u32 = 38;
pub const CAP_BPF: u32 = 39;

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Host {
	/// uname -r
	pub kernel: String,
	/// CapEff of this process (bit n = capability n).
	#[serde(skip)]
	pub cap_eff: u64,
	/// The capabilities that matter here, by name, that this process has.
	pub capabilities: Vec<&'static str>,
	/// RLIMIT_MEMLOCK (soft) in bytes; None = unlimited. Kernels before 5.11
	/// charge BPF maps to it.
	pub memlock: Option<u64>,
	/// /sys/kernel/btf/vmlinux exists.
	pub btf: bool,
	/// The active mode of /sys/kernel/security/lockdown (none, integrity,
	/// confidentiality); None when there is no lockdown LSM.
	pub lockdown: Option<String>,
	/// kernel.unprivileged_bpf_disabled (0, 1, 2); None when unreadable.
	pub unprivileged_bpf_disabled: Option<u32>,
	/// Why a tiny BPF array map could not be created; None when it could.
	pub bpf_error: Option<String>,
}

impl Host {
	pub fn has(&self, cap: u32) -> bool {
		cap < 64 && self.cap_eff & (1u64 << cap) != 0
	}

	/// CAP_BPF, or CAP_SYS_ADMIN (kernels before 5.8 have only that).
	pub fn may_bpf(&self) -> bool {
		self.has(CAP_BPF) || self.has(CAP_SYS_ADMIN)
	}

	/// The first missing privilege for loading BPF programs that attach to
	/// network objects (sockmap, XDP, TC): CAP_BPF (or CAP_SYS_ADMIN) and
	/// CAP_NET_ADMIN.
	pub fn missing_for_net_bpf(&self) -> Option<&'static str> {
		if !self.may_bpf() {
			Some("missing CAP_BPF (or CAP_SYS_ADMIN)")
		} else if !self.has(CAP_NET_ADMIN) && !self.has(CAP_SYS_ADMIN) {
			Some("missing CAP_NET_ADMIN")
		} else {
			None
		}
	}

	/// Looks at this process and kernel. Creates (and closes) one tiny BPF map.
	pub fn inspect() -> Host {
		let cap_eff = cap_eff();
		let names = [
			(CAP_BPF, "CAP_BPF"),
			(CAP_NET_ADMIN, "CAP_NET_ADMIN"),
			(CAP_NET_RAW, "CAP_NET_RAW"),
			(CAP_PERFMON, "CAP_PERFMON"),
			(CAP_SYS_ADMIN, "CAP_SYS_ADMIN"),
		];
		let capabilities = names.iter().filter(|(n, _)| cap_eff & (1u64 << n) != 0).map(|(_, s)| *s).collect();
		Host {
			kernel: kernel_release(),
			cap_eff,
			capabilities,
			memlock: memlock(),
			btf: std::path::Path::new("/sys/kernel/btf/vmlinux").exists(),
			lockdown: std::fs::read_to_string("/sys/kernel/security/lockdown").ok().and_then(|s| lockdown_mode(&s)),
			unprivileged_bpf_disabled: std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
				.ok()
				.and_then(|s| s.trim().parse().ok()),
			bpf_error: super::bpf::Map::array(4, 1).err().map(|e| super::bpf::explain(&e)),
		}
	}
}

/// `none [integrity] confidentiality` → `integrity`.
pub fn lockdown_mode(text: &str) -> Option<String> {
	let start = text.find('[')?;
	let end = text[start..].find(']')? + start;
	Some(text[start + 1..end].to_string())
}

/// CapEff of /proc/self/status.
fn cap_eff() -> u64 {
	std::fs::read_to_string("/proc/self/status")
		.ok()
		.and_then(|s| s.lines().find_map(|l| l.strip_prefix("CapEff:")).and_then(|v| u64::from_str_radix(v.trim(), 16).ok()))
		.unwrap_or(0)
}

fn kernel_release() -> String {
	#[cfg(unix)]
	{
		// SAFETY: utsname is plain data; uname fills it
		let mut u: libc::utsname = unsafe { std::mem::zeroed() };
		if unsafe { libc::uname(&mut u) } == 0 {
			// SAFETY: uname NUL-terminates release
			return unsafe { std::ffi::CStr::from_ptr(u.release.as_ptr()) }.to_string_lossy().into_owned();
		}
	}
	String::new()
}

fn memlock() -> Option<u64> {
	#[cfg(target_os = "linux")]
	{
		// SAFETY: getrlimit fills the struct
		let mut r: libc::rlimit = unsafe { std::mem::zeroed() };
		if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) } == 0 {
			return (r.rlim_cur != libc::RLIM_INFINITY).then_some(r.rlim_cur as u64);
		}
	}
	Some(0)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn lockdown_and_capabilities() {
		assert_eq!(lockdown_mode("[none] integrity confidentiality\n").as_deref(), Some("none"));
		assert_eq!(lockdown_mode("none [integrity] confidentiality").as_deref(), Some("integrity"));
		assert_eq!(lockdown_mode("garbage"), None);
		let h = Host { cap_eff: 1 << CAP_NET_ADMIN, ..Default::default() };
		assert_eq!(h.missing_for_net_bpf(), Some("missing CAP_BPF (or CAP_SYS_ADMIN)"));
		let h = Host { cap_eff: 1 << CAP_BPF, ..Default::default() };
		assert_eq!(h.missing_for_net_bpf(), Some("missing CAP_NET_ADMIN"));
		let h = Host { cap_eff: 1 << CAP_SYS_ADMIN, ..Default::default() };
		assert_eq!(h.missing_for_net_bpf(), None);
		// whatever this machine allows, inspecting it works
		let h = Host::inspect();
		assert!(!h.kernel.is_empty() || cfg!(not(unix)));
	}
}
