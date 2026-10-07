//! `global.performance` (#194, #184, docs/DESIGN-v0.4.md 12.) with the real
//! binary: the settings file wins over the flags and environment variables,
//! which win over the defaults; the effect is visible from outside (worker
//! threads, CPU pinning, UDP sockets per port).

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use common::*;

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-perf-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

struct Rproxy {
	child: Child,
	log: PathBuf,
}

impl Drop for Rproxy {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

impl Rproxy {
	fn start(dir: &Path, env: &[(&str, String)]) -> Rproxy {
		let log = dir.join("out.log");
		let out = fs::File::create(&log).unwrap();
		let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(dir)
			.env_clear()
			.env("RPROXY_API_PORT", free_port().to_string())
			.envs(env.iter().map(|(k, v)| (*k, v.as_str())))
			.stdout(out.try_clone().unwrap())
			.stderr(out)
			.stdin(Stdio::null())
			.spawn()
			.unwrap();
		Rproxy { child, log }
	}

	/// The `performance` log line (the process has set itself up by then).
	async fn performance(&self) -> Value {
		let deadline = Instant::now() + Duration::from_secs(20);
		loop {
			let text = fs::read_to_string(&self.log).unwrap_or_default();
			if let Some(v) = text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).find(|v| v["event"] == "performance") {
				return v;
			}
			assert!(Instant::now() < deadline, "no performance line:\n{text}");
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}

	async fn wait_log(&self, event: &str) {
		let deadline = Instant::now() + Duration::from_secs(20);
		while !fs::read_to_string(&self.log).unwrap_or_default().contains(&format!("\"event\":\"{event}\"")) {
			assert!(Instant::now() < deadline, "no {event}:\n{}", fs::read_to_string(&self.log).unwrap_or_default());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}

	/// (name, Cpus_allowed_list) of each thread.
	fn threads(&self) -> Vec<(String, String)> {
		let pid = self.child.id();
		fs::read_dir(format!("/proc/{pid}/task"))
			.unwrap()
			.flatten()
			.map(|t| {
				let comm = fs::read_to_string(t.path().join("comm")).unwrap_or_default().trim().to_string();
				let status = fs::read_to_string(t.path().join("status")).unwrap_or_default();
				let cpus = status.lines().find_map(|l| l.strip_prefix("Cpus_allowed_list:")).unwrap_or("").trim().to_string();
				(comm, cpus)
			})
			.collect()
	}

	fn workers(&self) -> Vec<(String, String)> {
		self.threads().into_iter().filter(|(n, _)| n.starts_with("rproxy-wrk-")).collect()
	}
}

/// UDP sockets bound to 127.0.0.1:`port` (by inode; see tests/udp_shards.rs).
fn udp_sockets_on(port: u16) -> usize {
	let want = format!("{:08X}:{port:04X}", u32::from_le_bytes([127, 0, 0, 1]));
	let read = || {
		fs::read_to_string("/proc/net/udp")
			.unwrap()
			.lines()
			.skip(1)
			.filter_map(|l| {
				let f: Vec<&str> = l.split_whitespace().collect();
				(f.get(1) == Some(&want.as_str())).then(|| f[9].to_string())
			})
			.collect::<std::collections::BTreeSet<_>>()
	};
	let mut last = read();
	for _ in 0..50 {
		let next = read();
		if next == last {
			return next.len();
		}
		last = next;
	}
	panic!("/proc/net/udp kept changing");
}

fn sources(perf: &Value) -> String {
	perf["sources"].as_str().unwrap_or("").to_string()
}

#[tokio::test]
async fn the_settings_file_sets_workers_shards_and_pinning() {
	let dir = workdir("file");
	let port = free_udp_port();
	fs::write(
		dir.join("rproxy.yaml"),
		format!(
			"version: 1\nglobal:\n  performance: {{workers: 3, udp_shards: auto, cpu_affinity: '0-2', busy_poll_usecs: 0, splice: {{enabled: false, full_reads: 2}}}}\nrules:\n  - {{protocol: udp, listen_addr: 127.0.0.1, listen_port: {port}, remote_addr: 127.0.0.1, remote_port: 9}}\n"
		),
	)
	.unwrap();
	// the environment says otherwise; the file wins
	let rp = Rproxy::start(
		&dir,
		&[
			("RPROXY_CONFIG", dir.join("rproxy.yaml").display().to_string()),
			("RPROXY_WORKERS", "5".into()),
			("RPROXY_UDP_SHARDS", "2".into()),
			("RPROXY_SPLICE", "1".into()),
		],
	);
	let perf = rp.performance().await;
	assert_eq!((&perf["workers"], &perf["udp_shards"]), (&3.into(), &3.into()), "{perf}");
	// CPUs this machine lacks are left out (CI runners have at least two)
	let listed: Vec<String> = perf["cpu_affinity"].as_str().unwrap().split(',').map(String::from).collect();
	assert!(!listed.is_empty() && listed.iter().all(|c| ["0", "1", "2"].contains(&c.as_str())), "{perf}");
	assert_eq!((&perf["splice"], &perf["splice_full_reads"]), (&false.into(), &2.into()), "{perf}");
	assert!(sources(&perf).contains("workers=file") && sources(&perf).contains("udp_shards=file"), "{perf}");
	rp.wait_log("static.loaded").await;

	let workers = rp.workers();
	assert_eq!(workers.len(), 3, "{:?}", rp.threads());
	// worker i on the i-th listed CPU (round and round)
	for (name, cpus) in &workers {
		let i: usize = name.trim_start_matches("rproxy-wrk-").parse().unwrap();
		assert_eq!(cpus, &listed[i % listed.len()], "{workers:?}");
	}
	// udp_shards: auto = the workers
	assert_eq!(udp_sockets_on(port), 3);
	drop(rp);
	let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_environment_applies_without_the_file() {
	let dir = workdir("env");
	let port = free_udp_port();
	// a settings file without global.performance
	fs::write(
		dir.join("rproxy.yaml"),
		format!("version: 1\nrules:\n  - {{protocol: udp, listen_addr: 127.0.0.1, listen_port: {port}, remote_addr: 127.0.0.1, remote_port: 9}}\n"),
	)
	.unwrap();
	let rp = Rproxy::start(
		&dir,
		&[
			("RPROXY_CONFIG", dir.join("rproxy.yaml").display().to_string()),
			("RPROXY_WORKERS", "2".into()),
			("RPROXY_UDP_SHARDS", "auto".into()),
			("RPROXY_SPLICE", "0".into()),
		],
	);
	let perf = rp.performance().await;
	assert_eq!((&perf["workers"], &perf["udp_shards"], &perf["splice"]), (&2.into(), &2.into(), &false.into()), "{perf}");
	assert!(sources(&perf).contains("workers=env") && sources(&perf).contains("cpu_affinity=default"), "{perf}");
	rp.wait_log("static.loaded").await;
	assert_eq!(rp.workers().len(), 2, "{:?}", rp.threads());
	assert_eq!(udp_sockets_on(port), 2);
	drop(rp);

	// nothing set: one UDP socket, a worker per CPU, no pinning
	let rp = Rproxy::start(&dir, &[("RPROXY_CONFIG", dir.join("rproxy.yaml").display().to_string())]);
	let perf = rp.performance().await;
	assert_eq!((&perf["udp_shards"], &perf["cpu_affinity"], &perf["splice"]), (&1.into(), &"none".into(), &true.into()), "{perf}");
	rp.wait_log("static.loaded").await;
	assert_eq!(udp_sockets_on(port), 1);
	assert_eq!(rp.workers().len() as u64, perf["workers"].as_u64().unwrap());
	drop(rp);
	let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn cpus_that_do_not_exist_are_left_out() {
	let dir = workdir("cpus");
	fs::write(dir.join("rproxy.yaml"), "version: 1\nglobal:\n  performance: {cpu_affinity: '0,4000'}\n").unwrap();
	let rp = Rproxy::start(&dir, &[("RPROXY_CONFIG", dir.join("rproxy.yaml").display().to_string())]);
	let perf = rp.performance().await;
	// one listed CPU can be used: one worker on it
	assert_eq!((&perf["workers"], &perf["cpu_affinity"]), (&1.into(), &"0".into()), "{perf}");
	let log = fs::read_to_string(&rp.log).unwrap();
	assert!(log.contains("global.performance.cpu_affinity") && log.contains("4000"), "{log}");
	drop(rp);
	let _ = fs::remove_dir_all(dir);
}
