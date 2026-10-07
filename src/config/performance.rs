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
		}
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
	/// Where each key came from: (key, source).
	pub sources: Vec<(&'static str, Source)>,
	/// CPUs of `cpu_affinity` this process may not use (left out, `degraded`).
	pub missing_cpus: Vec<usize>,
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

	Effective { workers, udp_shards, cpu_affinity, busy_poll_usecs, splice, sources, missing_cpus }
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
