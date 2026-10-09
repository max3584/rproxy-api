//! `global.performance` (#194, #184, docs/DESIGN-v0.4.md 12.): worker threads,
//! UDP sockets per port, CPU pinning, busy polling and splice(2). Each key falls
//! back to its environment variable (`RPROXY_WORKERS`, `RPROXY_UDP_SHARDS`,
//! `RPROXY_CPU_AFFINITY`, `RPROXY_BUSY_POLL_USECS`, `RPROXY_SPLICE*`), then to the
//! default. All take effect at startup only.
//!
//! `features.performance` lists the keys this build applies from the settings
//! file (all of them). The environment variables (`RPROXY_UDP_SHARDS`,
//! `RPROXY_SPLICE*` and the flags' `RPROXY_WORKERS`, `RPROXY_CPU_AFFINITY`,
//! `RPROXY_BUSY_POLL_USECS`) keep working where the file says nothing.
//!
//! `main` reads the settings file before it builds the tokio runtime
//! (`resolve`, `runtime`), and applies the rest (`apply`) before any rule opens
//! a socket.

use serde::{Deserialize, Serialize};

const MAX_WORKERS: u32 = 1024;
const MAX_UDP_SHARDS: u32 = 64;
const MAX_BUSY_POLL_USECS: u32 = 1000;
const MAX_FULL_READS: u32 = 64;
const MIN_PIPE: u64 = 4 << 10;
const MAX_PIPE: u64 = 16 << 20;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformanceSpec {
	/// tokio worker threads (default: the number of CPUs).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub workers: Option<u32>,
	/// SO_REUSEPORT sockets per UDP port: a number or `auto` (= workers). Default 1.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub udp_shards: Option<Shards>,
	/// `none`, `auto` (one worker per CPU) or a CPU list such as `"0-3,6"`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cpu_affinity: Option<String>,
	/// SO_BUSY_POLL of data-plane sockets in microseconds; 0 = off (default).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub busy_poll_usecs: Option<u32>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub splice: Option<SpliceSpec>,
	/// Kernel offload of plain L4 TCP (#260): `tcp: off | sockmap | nat`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ebpf: Option<super::offload::EbpfSpec>,
	/// XDP / AF_XDP for L4 UDP (#260).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub xdp: Option<super::offload::XdpSpec>,
	/// The DPDK data plane for L4 UDP (#261): builds with the `dpdk` feature only.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub dpdk: Option<DpdkSpec>,
}

/// `udp_shards`: a count or `auto`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Shards {
	Count(u32),
	Auto(AutoWord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoWord {
	Auto,
}

/// A size: bytes, or a string such as `"64KiB"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Size {
	Bytes(u64),
	Text(String),
}

impl Size {
	pub fn bytes(&self) -> Result<u64, String> {
		match self {
			Size::Bytes(n) => Ok(*n),
			Size::Text(s) => crate::core::bandwidth::parse_size(s),
		}
	}
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpliceSpec {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub enabled: Option<bool>,
	/// Bytes relayed in user space before switching to splice.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub after: Option<Size>,
	/// Full 32 KiB reads in a row before switching (0-64).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub full_reads: Option<u32>,
	/// F_SETPIPE_SZ of new pipes (0: the kernel's; 4KiB-16MiB).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub pipe_size: Option<Size>,
}

/// `global.performance.dpdk` (#261, docs/PERFORMANCE.md): UDP rules on the
/// addresses of these ports are forwarded by DPDK lcores instead of the kernel.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkSpec {
	/// Off by default.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub enabled: Option<bool>,
	/// Passed to the EAL as they are (after the ones rproxy makes: -l, -a / --no-pci, --vdev).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub eal_args: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub ports: Vec<DpdkPortSpec>,
	/// The CPUs of the forwarding lcores (`"2-5"`); required when enabled.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub lcores: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mempool: Option<DpdkMempool>,
	/// Checked before the EAL starts (the host sets them up).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub hugepages: Option<DpdkHugepages>,
	/// Frames received / sent at once (1-512, default 32).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub burst: Option<u32>,
	/// When DPDK cannot be used: true (default) goes on with the kernel path, false stops the start.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub fallback: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkPortSpec {
	/// A PCI address bound to vfio-pci (`"0000:3b:00.0"`) ...
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub pci: Option<String>,
	/// ... or a virtual device (`"net_tap0,iface=dtap0"`, `"net_af_packet0,iface=eth1"`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub vdev: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rx_queues: Option<u16>,
	/// At least one per lcore (each lcore sends on its own queue).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tx_queues: Option<u16>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub rx_desc: Option<u16>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tx_desc: Option<u16>,
	/// The port's IPv4 addresses with prefix (`"198.51.100.2/24"`); rules listen on them.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub addresses: Vec<String>,
	/// The next hop for backends off the port's links.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub gateway: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkMempool {
	/// mbufs in the pool (default 65535; 2^n - 1 is best).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mbufs: Option<u32>,
	/// Per-lcore cache (default 256, at most 512).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub cache: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpdkHugepages {
	/// `2MB` (default) or `1GB`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub size: Option<String>,
}

pub const DPDK_MAX_QUEUES: u16 = 64;
pub const DPDK_MAX_BURST: u32 = 512;
/// The pre-check's loopback port (`net_ring`), added to the EAL by rproxy.
pub const DPDK_CHECK_PORT: &str = "net_ring_rpchk";

impl DpdkPortSpec {
	/// The name DPDK gives the port: the PCI address, or the vdev's name.
	pub fn name(&self) -> String {
		match (&self.pci, &self.vdev) {
			(Some(pci), _) => pci.trim().to_string(),
			(None, Some(v)) => v.split(',').next().unwrap_or_default().trim().to_string(),
			(None, None) => String::new(),
		}
	}

	pub fn queues(&self) -> (u16, u16, u16, u16) {
		(self.rx_queues.unwrap_or(1), self.tx_queues.unwrap_or(1), self.rx_desc.unwrap_or(1024), self.tx_desc.unwrap_or(1024))
	}
}

/// `"a.b.c.d/len"`.
pub fn parse_ipv4_cidr(s: &str) -> Result<(std::net::Ipv4Addr, u8), String> {
	let bad = || format!("{s:?} is not an IPv4 address with a prefix length (e.g. 198.51.100.2/24)");
	let (ip, len) = s.trim().split_once('/').ok_or_else(bad)?;
	let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| bad())?;
	let len: u8 = len.parse().map_err(|_| bad())?;
	if len == 0 || len > 32 || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
		return Err(bad());
	}
	Ok((ip, len))
}

/// The hugepage size in KiB (`2MB` / `1GB`).
pub fn hugepage_kib(size: Option<&str>) -> Result<u64, String> {
	match size.map(|s| s.trim().to_ascii_uppercase()).as_deref() {
		None | Some("2MB") | Some("2MIB") | Some("2M") => Ok(2048),
		Some("1GB") | Some("1GIB") | Some("1G") => Ok(1 << 20),
		Some(other) => Err(format!("{other:?} is not a hugepage size (2MB or 1GB)")),
	}
}

impl DpdkSpec {
	pub fn enabled(&self) -> bool {
		self.enabled.unwrap_or(false)
	}

	pub fn fallback(&self) -> bool {
		self.fallback.unwrap_or(true)
	}

	pub fn burst(&self) -> usize {
		self.burst.unwrap_or(32) as usize
	}

	pub fn mempool(&self) -> (u32, u32) {
		let m = self.mempool.clone().unwrap_or_default();
		(m.mbufs.unwrap_or(65535), m.cache.unwrap_or(256))
	}

	pub fn check(&self) -> Result<(), String> {
		let p = "global.performance.dpdk";
		let lcores = match &self.lcores {
			Some(l) => Some(parse_cpu_list(l).map_err(|e| format!("{p}.lcores: {e}"))?),
			None if self.enabled() => return Err(format!("{p}.lcores is required: the CPUs the forwarding lcores take (e.g. \"2-5\")")),
			None => None,
		};
		if self.enabled() && self.ports.is_empty() {
			return Err(format!("{p}.ports: give at least one port"));
		}
		for a in &self.eal_args {
			let flag = a.split('=').next().unwrap_or_default();
			if ["-l", "-c", "--lcores", "--main-lcore", "-a", "--allow", "--vdev"].contains(&flag) {
				return Err(format!("{p}.eal_args: {flag} comes from lcores / ports; give it there"));
			}
		}
		let mut seen = vec![];
		for (i, port) in self.ports.iter().enumerate() {
			let at = format!("{p}.ports[{i}]");
			match (&port.pci, &port.vdev) {
				(Some(_), Some(_)) | (None, None) => return Err(format!("{at}: give pci or vdev (one of them)")),
				(Some(pci), None) if pci.trim().is_empty() || pci.contains(char::is_whitespace) => return Err(format!("{at}.pci {pci:?} is not a PCI address")),
				(None, Some(v)) if !v.starts_with("net_") || v.contains(char::is_whitespace) => {
					return Err(format!("{at}.vdev {v:?} is not a DPDK virtual device (net_tap0,iface=..., net_af_packet0,iface=..., net_memif0,...)"))
				}
				_ => {}
			}
			if port.name() == DPDK_CHECK_PORT {
				return Err(format!("{at}: {DPDK_CHECK_PORT} is rproxy's own check port"));
			}
			let (rxq, txq, rxd, txd) = port.queues();
			for (key, n) in [("rx_queues", rxq), ("tx_queues", txq)] {
				if n == 0 || n > DPDK_MAX_QUEUES {
					return Err(format!("{at}.{key} must be 1-{DPDK_MAX_QUEUES}"));
				}
			}
			for (key, n) in [("rx_desc", rxd), ("tx_desc", txd)] {
				if !(64..=16384).contains(&n) {
					return Err(format!("{at}.{key} must be 64-16384"));
				}
			}
			if let Some(l) = &lcores {
				if usize::from(txq) < l.len() {
					return Err(format!("{at}.tx_queues ({txq}) must be at least the number of lcores ({}): each lcore sends on its own queue", l.len()));
				}
			}
			if self.enabled() && port.addresses.is_empty() {
				return Err(format!("{at}.addresses: give the port's IPv4 address(es), e.g. [\"198.51.100.2/24\"]"));
			}
			let mut nets = vec![];
			for a in &port.addresses {
				let (ip, len) = parse_ipv4_cidr(a).map_err(|e| format!("{at}.addresses: {e}"))?;
				if seen.contains(&ip) {
					return Err(format!("{at}.addresses: {ip} is given twice"));
				}
				seen.push(ip);
				nets.push((ip, len));
			}
			if let Some(gw) = &port.gateway {
				let gw: std::net::Ipv4Addr = gw.trim().parse().map_err(|_| format!("{at}.gateway {gw:?} is not an IPv4 address"))?;
				let on_link = nets.iter().any(|(ip, len)| {
					let mask = u32::MAX << (32 - u32::from(*len));
					u32::from(gw) & mask == u32::from(*ip) & mask
				});
				if !on_link {
					return Err(format!("{at}.gateway {gw} is on none of the port's networks"));
				}
			}
		}
		let names: Vec<String> = self.ports.iter().map(|p| p.name()).collect();
		if let Some(dup) = names.iter().enumerate().find_map(|(i, n)| names[..i].contains(n).then_some(n)) {
			return Err(format!("{p}.ports: {dup} is given twice"));
		}
		let (mbufs, cache) = self.mempool();
		if !(1023..=(16 << 20)).contains(&mbufs) {
			return Err(format!("{p}.mempool.mbufs must be 1023-16777216"));
		}
		if cache > 512 || cache as f64 > f64::from(mbufs) / 1.5 {
			return Err(format!("{p}.mempool.cache must be at most 512 and mbufs / 1.5"));
		}
		if let Some(h) = &self.hugepages {
			hugepage_kib(h.size.as_deref()).map_err(|e| format!("{p}.hugepages.size: {e}"))?;
		}
		if self.burst.is_some_and(|b| b == 0 || b > DPDK_MAX_BURST) {
			return Err(format!("{p}.burst must be 1-{DPDK_MAX_BURST}"));
		}
		Ok(())
	}
}

/// Parses a CPU list: `"0-3,6"`.
pub fn parse_cpu_list(s: &str) -> Result<Vec<usize>, String> {
	let bad = || format!("{s:?} is not a CPU list (e.g. 0-3,6)");
	let mut cpus = vec![];
	for part in s.split(',') {
		let part = part.trim();
		let (lo, hi) = part.split_once('-').unwrap_or((part, part));
		let (lo, hi): (usize, usize) = (lo.trim().parse().map_err(|_| bad())?, hi.trim().parse().map_err(|_| bad())?);
		if lo > hi || hi >= 4096 {
			return Err(bad());
		}
		for cpu in lo..=hi {
			if !cpus.contains(&cpu) {
				cpus.push(cpu);
			}
		}
	}
	Ok(cpus)
}

impl PerformanceSpec {
	pub fn check(&self) -> Result<(), String> {
		let p = "global.performance";
		if self.workers.is_some_and(|n| n == 0 || n > MAX_WORKERS) {
			return Err(format!("{p}.workers must be 1-{MAX_WORKERS}"));
		}
		if let Some(Shards::Count(n)) = self.udp_shards {
			if n == 0 || n > MAX_UDP_SHARDS {
				return Err(format!("{p}.udp_shards must be 1-{MAX_UDP_SHARDS} or auto"));
			}
		}
		match self.cpu_affinity.as_deref() {
			None | Some("none") | Some("auto") => {}
			Some(list) => {
				let cpus = parse_cpu_list(list).map_err(|e| format!("{p}.cpu_affinity: {e} (or none / auto)"))?;
				if let Some(w) = self.workers {
					if cpus.len() < w as usize {
						return Err(format!("{p}.cpu_affinity lists {} CPU(s) for {w} workers", cpus.len()));
					}
				}
			}
		}
		if self.busy_poll_usecs.is_some_and(|n| n > MAX_BUSY_POLL_USECS) {
			return Err(format!("{p}.busy_poll_usecs must be 0-{MAX_BUSY_POLL_USECS}"));
		}
		if let Some(d) = &self.dpdk {
			d.check()?;
			// the lcores spin on their CPUs: the workers must not be pinned there
			if let (Some(l), Some(list)) = (&d.lcores, self.cpu_affinity.as_deref()) {
				if let (Ok(lcores), Ok(cpus)) = (parse_cpu_list(l), parse_cpu_list(list)) {
					if let Some(c) = cpus.iter().find(|c| lcores.contains(c)) {
						return Err(format!("{p}.cpu_affinity includes CPU {c} of dpdk.lcores (the lcores take their CPUs for themselves)"));
					}
				}
			}
		}
		if let Some(s) = &self.splice {
			if let Some(a) = &s.after {
				a.bytes().map_err(|e| format!("{p}.splice.after: {e}"))?;
			}
			if s.full_reads.is_some_and(|n| n > MAX_FULL_READS) {
				return Err(format!("{p}.splice.full_reads must be 0-{MAX_FULL_READS}"));
			}
			if let Some(size) = &s.pipe_size {
				let n = size.bytes().map_err(|e| format!("{p}.splice.pipe_size: {e}"))?;
				if n != 0 && !(MIN_PIPE..=MAX_PIPE).contains(&n) {
					return Err(format!("{p}.splice.pipe_size must be 0 or 4KiB-16MiB"));
				}
			}
		}
		if let Some(x) = &self.xdp {
			x.check(&format!("{p}.xdp"))?;
		}
		Ok(())
	}

	/// The keys that are set, as `global.performance.<key>`.
	pub fn keys(&self) -> Vec<&'static str> {
		let mut out = vec![];
		for (key, set) in [
			("workers", self.workers.is_some()),
			("udp_shards", self.udp_shards.is_some()),
			("cpu_affinity", self.cpu_affinity.is_some()),
			("busy_poll_usecs", self.busy_poll_usecs.is_some()),
			("splice", self.splice.is_some()),
			("ebpf", self.ebpf.is_some()),
			("xdp", self.xdp.is_some()),
			("dpdk", self.dpdk.is_some()),
		] {
			if set {
				out.push(key);
			}
		}
		out
	}
}

/// `cpu_affinity` as resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Affinity {
	None,
	/// Worker i on the i-th CPU the process may use.
	Auto,
	/// Worker i on `cpus[i % len]`; other threads on any of them.
	List(Vec<usize>),
}

/// Where a value came from (for the `performance` log line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
	File,
	Env,
	Default,
}

impl Source {
	pub fn as_str(self) -> &'static str {
		match self {
			Source::File => "file",
			Source::Env => "env",
			Source::Default => "default",
		}
	}
}

/// The flags and environment variables (`RPROXY_*`), the fallback of each key.
#[derive(Clone, Debug, Default)]
pub struct EnvKnobs {
	pub workers: Option<u32>,
	pub cpu_affinity: Option<String>,
	pub busy_poll_usecs: Option<u32>,
	/// `RPROXY_UDP_SHARDS`: a number or `auto`.
	pub udp_shards: Option<String>,
	/// `RPROXY_SPLICE*` (with the defaults where unset).
	pub splice: crate::l4::splice::Settings,
	/// `RPROXY_EBPF_*` / `RPROXY_XDP_*` (mistakes are reported by `check_env`).
	pub offload: (super::offload::EbpfSpec, super::offload::XdpSpec),
}

impl EnvKnobs {
	/// The flags given, and the environment for the rest.
	pub fn from_env(workers: Option<u32>, cpu_affinity: Option<String>, busy_poll_usecs: Option<u32>) -> EnvKnobs {
		EnvKnobs {
			workers,
			cpu_affinity,
			busy_poll_usecs,
			udp_shards: std::env::var("RPROXY_UDP_SHARDS").ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()),
			splice: crate::l4::splice::Settings::from_env(),
			offload: super::offload::from_env().unwrap_or_default(),
		}
	}

	/// Mistakes in the environment variables read here that have a shape
	/// (`RPROXY_EBPF_*`, `RPROXY_XDP_*`): startup stops on them.
	pub fn check_env() -> Result<(), String> {
		super::offload::from_env().map(|_| ())
	}
}

/// The performance settings in effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effective {
	pub workers: usize,
	pub udp_shards: usize,
	pub cpu_affinity: Affinity,
	pub busy_poll_usecs: u32,
	pub splice: crate::l4::splice::Settings,
	/// Kernel offload requested (#260); used only after the probe passed.
	pub ebpf: super::offload::Ebpf,
	pub xdp: super::offload::Xdp,
	/// Where each key came from: (key, source).
	pub sources: Vec<(&'static str, Source)>,
	/// CPUs of `cpu_affinity` this process may not use (left out, `degraded`).
	pub missing_cpus: Vec<usize>,
	/// `dpdk` from the settings file (no environment variable), started by `l4::dpdk::start`.
	pub dpdk: Option<DpdkSpec>,
}

/// The CPUs this process may run on (sched_getaffinity), in order.
pub fn allowed_cpus() -> Vec<usize> {
	#[cfg(target_os = "linux")]
	{
		// SAFETY: a zeroed cpu_set_t is empty; sched_getaffinity fills it
		let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
		if unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) } == 0 {
			let cpus: Vec<usize> = (0..libc::CPU_SETSIZE as usize).filter(|&c| unsafe { libc::CPU_ISSET(c, &set) }).collect();
			if !cpus.is_empty() {
				return cpus;
			}
		}
	}
	(0..std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)).collect()
}

/// What tokio would take by default: the CPUs available to the process,
/// cgroup quotas included.
pub fn parallelism() -> usize {
	std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Each key from the settings file, else the flag / environment variable, else
/// the default. `allowed` is `allowed_cpus()`, `parallelism` is `parallelism()`.
pub fn resolve(spec: Option<&PerformanceSpec>, env: &EnvKnobs, allowed: &[usize], parallelism: usize) -> Effective {
	let empty = PerformanceSpec::default();
	let spec = spec.unwrap_or(&empty);
	let mut sources = vec![];
	let mut pick = |key: &'static str, file: bool, env: bool| {
		let from = if file {
			Source::File
		} else if env {
			Source::Env
		} else {
			Source::Default
		};
		sources.push((key, from));
		from
	};

	let affinity_text = match pick("cpu_affinity", spec.cpu_affinity.is_some(), env.cpu_affinity.is_some()) {
		Source::File => spec.cpu_affinity.clone(),
		Source::Env => env.cpu_affinity.clone(),
		Source::Default => None,
	};
	let mut missing_cpus = vec![];
	let cpu_affinity = match affinity_text.as_deref().map(str::trim) {
		None | Some("none") => Affinity::None,
		Some("auto") => Affinity::Auto,
		Some(list) => match parse_cpu_list(list) {
			Ok(cpus) => {
				let (ok, missing): (Vec<usize>, Vec<usize>) = cpus.into_iter().partition(|c| allowed.contains(c));
				missing_cpus = missing;
				if ok.is_empty() {
					Affinity::None
				} else {
					Affinity::List(ok)
				}
			}
			// checked at startup already
			Err(_) => Affinity::None,
		},
	};

	let workers = match pick("workers", spec.workers.is_some(), env.workers.is_some()) {
		Source::File => spec.workers.unwrap_or(1) as usize,
		Source::Env => env.workers.unwrap_or(1) as usize,
		// one per CPU: the listed ones, or as tokio would (the CPUs and the cgroup's quota)
		Source::Default => match &cpu_affinity {
			Affinity::List(cpus) => cpus.len(),
			_ => parallelism,
		},
	}
	.clamp(1, MAX_WORKERS as usize);

	let shards_text = match pick("udp_shards", spec.udp_shards.is_some(), env.udp_shards.is_some()) {
		Source::File => match &spec.udp_shards {
			Some(Shards::Count(n)) => Some(n.to_string()),
			_ => Some("auto".into()),
		},
		Source::Env => env.udp_shards.clone(),
		Source::Default => None,
	};
	let udp_shards = match shards_text.as_deref() {
		None => 1,
		Some("auto") => workers,
		Some(n) => n.parse().unwrap_or(1),
	}
	.clamp(1, MAX_UDP_SHARDS as usize);

	let busy_poll_usecs = match pick("busy_poll_usecs", spec.busy_poll_usecs.is_some(), env.busy_poll_usecs.is_some()) {
		Source::File => spec.busy_poll_usecs.unwrap_or(0),
		Source::Env => env.busy_poll_usecs.unwrap_or(0),
		Source::Default => 0,
	}
	.min(MAX_BUSY_POLL_USECS);

	// splice: each key from the file over RPROXY_SPLICE* (which has the defaults)
	let mut splice = env.splice;
	let file_splice = spec.splice.clone().unwrap_or_default();
	pick("splice", spec.splice.is_some(), false);
	if let Some(v) = file_splice.enabled {
		splice.enabled = v;
	}
	if let Some(v) = file_splice.after.as_ref().and_then(|s| s.bytes().ok()) {
		splice.after = v;
	}
	if let Some(v) = file_splice.full_reads {
		splice.full_reads = v;
	}
	if let Some(v) = file_splice.pipe_size.as_ref().and_then(|s| s.bytes().ok()) {
		splice.pipe_size = v as usize;
	}

	let (ee, ex) = &env.offload;
	pick("ebpf", spec.ebpf.is_some(), ee != &Default::default());
	pick("xdp", spec.xdp.is_some(), ex != &Default::default());
	let (ebpf, xdp) = super::offload::resolve(spec.ebpf.as_ref(), spec.xdp.as_ref(), &env.offload);

	Effective { workers, udp_shards, cpu_affinity, busy_poll_usecs, splice, ebpf, xdp, sources, missing_cpus, dpdk: spec.dpdk.clone() }
}

/// Name of the i-th worker thread; `pin_current_thread` reads it back.
const WORKER_PREFIX: &str = "rproxy-wrk-";

/// The tokio runtime of `e`: `workers` threads, named `rproxy-wrk-<i>` (the
/// others `rproxy-blocking`), pinned to CPUs by `cpu_affinity`.
pub fn runtime(e: &Effective) -> std::io::Result<tokio::runtime::Runtime> {
	use std::sync::atomic::{AtomicUsize, Ordering};
	let workers = e.workers;
	let started = std::sync::Arc::new(AtomicUsize::new(0));
	let affinity = e.cpu_affinity.clone();
	let allowed = allowed_cpus();
	tokio::runtime::Builder::new_multi_thread()
		.worker_threads(workers)
		.enable_all()
		// tokio starts its workers first, when the runtime is built
		.thread_name_fn(move || {
			let i = started.fetch_add(1, Ordering::Relaxed);
			if i < workers {
				format!("{WORKER_PREFIX}{i}")
			} else {
				"rproxy-blocking".to_string()
			}
		})
		.on_thread_start(move || pin_current_thread(&affinity, &allowed))
		.build()
}

/// Pins the calling runtime thread: worker i to its CPU, the others to the
/// listed CPUs (`auto` leaves them free). Best effort.
fn pin_current_thread(affinity: &Affinity, allowed: &[usize]) {
	let index = std::thread::current().name().and_then(|n| n.strip_prefix(WORKER_PREFIX)).and_then(|i| i.parse::<usize>().ok());
	let cpus: Vec<usize> = match (affinity, index) {
		(Affinity::None, _) => return,
		(Affinity::Auto, Some(i)) if !allowed.is_empty() => vec![allowed[i % allowed.len()]],
		(Affinity::Auto, _) => return,
		(Affinity::List(list), Some(i)) => vec![list[i % list.len()]],
		(Affinity::List(list), None) => list.clone(),
	};
	#[cfg(target_os = "linux")]
	{
		// SAFETY: a zeroed cpu_set_t is empty; CPU_SET stays within CPU_SETSIZE
		let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
		for c in cpus.into_iter().filter(|&c| c < libc::CPU_SETSIZE as usize) {
			unsafe { libc::CPU_SET(c, &mut set) };
		}
		// thread 0: the calling thread
		unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
	}
	#[cfg(not(target_os = "linux"))]
	let _ = cpus;
}

/// Applies what the data plane reads (before any rule opens a socket): UDP
/// sockets per port, SO_BUSY_POLL and splice.
pub fn apply(e: &Effective) {
	crate::core::registry::force_udp_shards(e.udp_shards);
	crate::net::listen::set_busy_poll(e.busy_poll_usecs);
	crate::l4::splice::configure(e.splice);
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(yaml: &str) -> PerformanceSpec {
		crate::config::from_yaml(yaml).unwrap()
	}

	#[test]
	fn shape_and_validation() {
		let ok = parse("{workers: 4, udp_shards: auto, cpu_affinity: '0-3,6', busy_poll_usecs: 50, splice: {enabled: true, after: 64KiB, full_reads: 4, pipe_size: 1MiB}, ebpf: {tcp: sockmap}, xdp: {mode: af_xdp}}");
		ok.check().unwrap();
		assert_eq!(ok.udp_shards, Some(Shards::Auto(AutoWord::Auto)));
		assert_eq!(ok.keys(), ["workers", "udp_shards", "cpu_affinity", "busy_poll_usecs", "splice", "ebpf", "xdp"]);
		assert_eq!(parse("{udp_shards: 8}").udp_shards, Some(Shards::Count(8)));
		for bad in [
			"{workers: 0}",
			"{udp_shards: 65}",
			"{cpu_affinity: '3-1'}",
			"{workers: 4, cpu_affinity: '0-1'}",
			"{busy_poll_usecs: 5000}",
			"{splice: {full_reads: 100}}",
			"{splice: {pipe_size: 100}}",
			"{splice: {after: lots}}",
			"{xdp: {ring_size: 100}}",
		] {
			assert!(parse(bad).check().is_err(), "{bad}");
		}
		assert!(crate::config::from_yaml::<PerformanceSpec>("{udp_shards: many}").is_err());
		assert!(crate::config::from_yaml::<PerformanceSpec>("{threads: 4}").is_err(), "unknown keys");
		assert_eq!(parse_cpu_list("0-2,1,5").unwrap(), [0, 1, 2, 5]);
	}

	#[test]
	fn dpdk_shape_and_validation() {
		let ok = parse(
			"{cpu_affinity: '0-1', dpdk: {enabled: true, lcores: '2-3', eal_args: ['--in-memory'], mempool: {mbufs: 65535, cache: 256}, hugepages: {size: 2MB}, burst: 64, fallback: false,
			  ports: [{pci: '0000:3b:00.0', rx_queues: 4, tx_queues: 2, rx_desc: 1024, tx_desc: 1024, addresses: ['198.51.100.2/24', '198.51.100.3/24'], gateway: 198.51.100.1},
			          {vdev: 'net_tap0,iface=dtap0', tx_queues: 2, addresses: ['203.0.113.2/24']}]}}",
		);
		ok.check().unwrap();
		assert_eq!(ok.keys(), ["cpu_affinity", "dpdk"]);
		let d = ok.dpdk.as_ref().unwrap();
		assert_eq!((d.enabled(), d.fallback(), d.burst(), d.mempool()), (true, false, 64, (65535, 256)));
		assert_eq!(d.ports[1].name(), "net_tap0");
		assert_eq!(d.ports[1].queues(), (1, 2, 1024, 1024));
		// off: only the shape is checked
		parse("{dpdk: {enabled: false}}").check().unwrap();
		assert!(!parse("{dpdk: {}}").dpdk.unwrap().enabled());
		let port = "ports: [{vdev: net_tap0, tx_queues: 2, addresses: ['10.0.0.2/24']}]";
		for bad in [
			"{dpdk: {enabled: true, ports: [{vdev: net_tap0, addresses: ['10.0.0.2/24']}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3'}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: net_tap0, tx_queues: 1, addresses: ['10.0.0.2/24']}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: net_tap0, tx_queues: 2}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{pci: '0000:01:00.0', vdev: net_tap0, tx_queues: 2, addresses: ['10.0.0.2/24']}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: tap0, tx_queues: 2, addresses: ['10.0.0.2/24']}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: net_tap0, tx_queues: 2, addresses: ['10.0.0.2']}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: net_tap0, tx_queues: 2, addresses: ['10.0.0.2/24'], gateway: 10.1.0.1}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: net_tap0, tx_queues: 2, rx_queues: 65, addresses: ['10.0.0.2/24']}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: net_tap0, tx_queues: 2, rx_desc: 32, addresses: ['10.0.0.2/24']}]}}".to_string(),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: net_ring_rpchk, tx_queues: 2, addresses: ['10.0.0.2/24']}]}}".to_string(),
			format!("{{dpdk: {{enabled: true, lcores: '2-3', {port}, eal_args: ['-l', '4']}}}}"),
			format!("{{dpdk: {{enabled: true, lcores: '2-3', {port}, burst: 0}}}}"),
			format!("{{dpdk: {{enabled: true, lcores: '2-3', {port}, mempool: {{mbufs: 100}}}}}}"),
			format!("{{dpdk: {{enabled: true, lcores: '2-3', {port}, mempool: {{mbufs: 2047, cache: 2000}}}}}}"),
			format!("{{dpdk: {{enabled: true, lcores: '2-3', {port}, hugepages: {{size: 4MB}}}}}}"),
			format!("{{cpu_affinity: '1-2', dpdk: {{enabled: true, lcores: '2-3', {port}}}}}"),
			"{dpdk: {enabled: true, lcores: '2-3', ports: [{vdev: net_tap0, tx_queues: 2, addresses: ['10.0.0.2/24']}, {vdev: net_tap1, tx_queues: 2, addresses: ['10.0.0.2/24']}]}}".to_string(),
		] {
			assert!(parse(&bad).check().is_err(), "{bad}");
		}
		assert!(crate::config::from_yaml::<PerformanceSpec>("{dpdk: {ports: [{pci: x, mtu: 9000}]}}").is_err(), "unknown keys");
		assert_eq!(hugepage_kib(Some("1GB")), Ok(1 << 20));
	}

	fn env() -> EnvKnobs {
		EnvKnobs {
			splice: crate::l4::splice::Settings { enabled: true, after: 0, full_reads: 4, pipe_size: 0 },
			..Default::default()
		}
	}

	#[test]
	fn the_file_wins_over_the_environment_then_the_defaults() {
		let cpus = [0, 1, 2, 3];
		let d = resolve(None, &env(), &cpus, 4);
		assert_eq!((d.workers, d.udp_shards, d.busy_poll_usecs), (4, 1, 0));
		assert_eq!(d.cpu_affinity, Affinity::None);
		assert!(d.sources.iter().all(|(_, f)| *f == Source::Default), "{:?}", d.sources);

		let mut e = env();
		e.workers = Some(2);
		e.udp_shards = Some("auto".into());
		e.busy_poll_usecs = Some(50);
		e.splice.enabled = false;
		e.splice.pipe_size = 65536;
		let from_env = resolve(None, &e, &cpus, 4);
		assert_eq!((from_env.workers, from_env.udp_shards, from_env.busy_poll_usecs, from_env.splice.enabled), (2, 2, 50, false));

		let file = parse("{workers: 3, udp_shards: 5, busy_poll_usecs: 0, splice: {enabled: true, full_reads: 0}}");
		let f = resolve(Some(&file), &e, &cpus, 4);
		assert_eq!((f.workers, f.udp_shards, f.busy_poll_usecs), (3, 5, 0));
		// splice: keys from the file, the rest from RPROXY_SPLICE*
		assert_eq!(f.splice, crate::l4::splice::Settings { enabled: true, after: 0, full_reads: 0, pipe_size: 65536 });
		assert!(f.sources.contains(&("workers", Source::File)) && f.sources.contains(&("cpu_affinity", Source::Default)));

		// auto shards follow the workers of the file
		let auto = resolve(Some(&parse("{workers: 6, udp_shards: auto}")), &env(), &cpus, 4);
		assert_eq!(auto.udp_shards, 6);
	}

	#[test]
	fn cpu_lists_drop_missing_cpus_and_size_the_workers() {
		let cpus = [0, 1, 2, 3];
		let list = resolve(Some(&parse("{cpu_affinity: '1,3,9'}")), &env(), &cpus, 4);
		assert_eq!(list.cpu_affinity, Affinity::List(vec![1, 3]));
		assert_eq!(list.missing_cpus, [9]);
		assert_eq!(list.workers, 2, "one worker per usable listed CPU");
		let none = resolve(Some(&parse("{cpu_affinity: '8-9'}")), &env(), &cpus, 4);
		assert_eq!(none.cpu_affinity, Affinity::None);
		let auto = resolve(Some(&parse("{cpu_affinity: auto, workers: 2}")), &env(), &cpus, 4);
		assert_eq!((auto.cpu_affinity, auto.workers), (Affinity::Auto, 2));
	}
}
