//! `global.performance` (#194, #184, docs/DESIGN-v0.4.md 12.): worker threads,
//! UDP sockets per port, CPU pinning, busy polling and splice(2). Each key falls
//! back to its environment variable (`RPROXY_WORKERS`, `RPROXY_UDP_SHARDS`,
//! `RPROXY_CPU_AFFINITY`, `RPROXY_BUSY_POLL_USECS`, `RPROXY_SPLICE*`), then to the
//! default. All take effect at startup only.
//!
//! v0.4.0 settles the shape; `features.performance` lists the keys this build
//! applies from the settings file. The environment variables that already
//! exist (`RPROXY_UDP_SHARDS`, `RPROXY_SPLICE*`) keep working either way.

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
		] {
			if set {
				out.push(key);
			}
		}
		out
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn parse(yaml: &str) -> PerformanceSpec {
		crate::config::from_yaml(yaml).unwrap()
	}

	#[test]
	fn shape_and_validation() {
		let ok = parse("{workers: 4, udp_shards: auto, cpu_affinity: '0-3,6', busy_poll_usecs: 50, splice: {enabled: true, after: 64KiB, full_reads: 4, pipe_size: 1MiB}}");
		ok.check().unwrap();
		assert_eq!(ok.udp_shards, Some(Shards::Auto(AutoWord::Auto)));
		assert_eq!(ok.keys(), ["workers", "udp_shards", "cpu_affinity", "busy_poll_usecs", "splice"]);
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
		] {
			assert!(parse(bad).check().is_err(), "{bad}");
		}
		assert!(crate::config::from_yaml::<PerformanceSpec>("{udp_shards: many}").is_err());
		assert!(crate::config::from_yaml::<PerformanceSpec>("{threads: 4}").is_err(), "unknown keys");
		assert_eq!(parse_cpu_list("0-2,1,5").unwrap(), [0, 1, 2, 5]);
	}
}
