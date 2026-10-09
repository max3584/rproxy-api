//! Kernel offload (#260) with the real binary: the startup probe of
//! `global.performance.xdp` (`performance.probe`, `degraded`,
//! `GET /capabilities` `performance`), `fallback: false`, and
//! `rproxy-api --check-kernel`. Whether a fast path is usable depends on the
//! machine (privileges, kernel); the tests check that the outcome is reported
//! consistently either way.

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

use common::*;

fn workdir(tag: &str) -> PathBuf {
	rproxy_api::net::files::private_umask();
	let dir = std::env::temp_dir().join(format!("rproxy-offload-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn command(dir: &Path, env: &[(&str, String)]) -> Command {
	let mut c = Command::new(env!("CARGO_BIN_EXE_rproxy-api"));
	c.current_dir(dir).env_clear().envs(env.iter().map(|(k, v)| (*k, v.as_str())));
	c
}

struct Rproxy {
	child: Child,
	log: PathBuf,
	port: u16,
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
		let port = free_port();
		let child = command(dir, env)
			.env("RPROXY_API_PORT", port.to_string())
			.stdout(out.try_clone().unwrap())
			.stderr(out)
			.stdin(Stdio::null())
			.spawn()
			.unwrap();
		Rproxy { child, log, port }
	}

	fn text(&self) -> String {
		fs::read_to_string(&self.log).unwrap_or_default()
	}

	fn lines(&self, event: &str) -> Vec<Value> {
		self.text().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|v| v["event"] == event).collect()
	}

	async fn capabilities(&self) -> Value {
		let deadline = Instant::now() + Duration::from_secs(20);
		loop {
			if let Ok(r) = reqwest::get(format!("http://127.0.0.1:{}/capabilities", self.port)).await {
				return r.json().await.unwrap();
			}
			assert!(Instant::now() < deadline, "no API:\n{}", self.text());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}

	fn exited(mut self) -> (bool, String) {
		let deadline = Instant::now() + Duration::from_secs(20);
		loop {
			if let Some(status) = self.child.try_wait().unwrap() {
				return (status.success(), self.text());
			}
			assert!(Instant::now() < deadline, "still running:\n{}", self.text());
			std::thread::sleep(Duration::from_millis(50));
		}
	}
}

#[tokio::test]
async fn nothing_requested_probes_nothing() {
	let dir = workdir("off");
	let rp = Rproxy::start(&dir, &[]);
	let caps = rp.capabilities().await;
	assert_eq!(caps["performance"]["xdp"], serde_json::json!({"requested": "off", "active": false, "mode": null, "reason": null}), "{caps}");
	assert!(caps["performance"].get("ebpf_tcp").is_none(), "sockmap was not adopted: {caps}");
	assert_eq!(caps["performance"]["xdp"]["requested"], "off", "{caps}");
	assert!(rp.lines("performance.probe").is_empty(), "{}", rp.text());
	assert!(!rp.text().contains("global.performance.xdp"), "{}", rp.text());
	drop(rp);
	let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn requested_fast_paths_are_probed_and_fall_back_with_a_reason() {
	let dir = workdir("probe");
	let rp = Rproxy::start(&dir, &[("RPROXY_XDP_MODE", "af_xdp".into())]);
	let caps = rp.capabilities().await;
	let probes = rp.lines("performance.probe");
	assert_eq!(probes.len(), 1, "{}", rp.text());
	{
		let (name, requested, part) = ("xdp", "af_xdp", "global.performance.xdp.mode");
		let c = &caps["performance"][name];
		assert_eq!(c["requested"], requested, "{caps}");
		let line = probes.iter().find(|l| l["feature"] == name).unwrap();
		assert_eq!((&line["requested"], &line["active"]), (&c["requested"], &c["active"]), "{line} {caps}");
		let degraded = rp.lines("degraded").into_iter().any(|l| l["part"] == part);
		if c["active"] == true {
			assert!(c["mode"].is_string() && c["reason"].is_null() && !degraded, "{caps}");
		} else {
			assert!(c["reason"].as_str().is_some_and(|r| !r.is_empty()), "{caps}");
			assert!(degraded, "falls back with degraded:\n{}", rp.text());
		}
	}
	drop(rp);
	let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn fallback_false_stops_startup_when_the_fast_path_is_not_usable() {
	let dir = workdir("nofallback");
	let cfg = dir.join("rproxy.yaml");
	// stage 2 of #260 (XDP forwarding by itself) is not built in
	fs::write(&cfg, "version: 1\nglobal:\n  performance:\n    xdp: {mode: native, fallback: false}\n").unwrap();
	let (ok, out) = Rproxy::start(&dir, &[("RPROXY_CONFIG", cfg.display().to_string())]).exited();
	assert!(!ok && out.contains("global.performance.xdp.mode = native") && out.contains("fallback: false"), "{out}");
	let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn mistakes_in_the_settings_stop_startup_and_the_check() {
	let dir = workdir("mistakes");
	let (ok, out) = Rproxy::start(&dir, &[("RPROXY_XDP_RING_SIZE", "1000".into())]).exited();
	assert!(!ok && out.contains("RPROXY_XDP_RING_SIZE"), "{out}");
	let out = command(&dir, &[("RPROXY_XDP_MODE", "fast".into())]).arg("--check-kernel").output().unwrap();
	assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("RPROXY_XDP_MODE"), "{out:?}");
	// the sockmap experiment's key is gone (not adopted): a mistake in the file
	let cfg = dir.join("ebpf.yaml");
	fs::write(&cfg, "version: 1\nglobal:\n  performance:\n    ebpf: {tcp: sockmap}\n").unwrap();
	let out = command(&dir, &[("RPROXY_CONFIG", cfg.display().to_string())]).arg("--check-kernel").output().unwrap();
	assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("ebpf"), "{out:?}");
	let cfg = dir.join("rproxy.yaml");
	fs::write(&cfg, "version: 1\nglobal:\n  performance:\n    xdp: {frame_size: 1024}\n").unwrap();
	let out = command(&dir, &[("RPROXY_CONFIG", cfg.display().to_string())]).arg("--check-kernel").output().unwrap();
	assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("frame_size"), "{out:?}");
	let _ = fs::remove_dir_all(dir);
}

#[test]
fn check_kernel_tests_every_fast_path_and_prints_a_table() {
	let dir = workdir("check");
	// nothing requested: every fast path is tested, and the check passes
	let out = command(&dir, &[]).arg("--check-kernel").output().unwrap();
	let text = String::from_utf8_lossy(&out.stdout).to_string();
	assert!(out.status.success(), "{out:?}");
	for row in ["xdp.mode=af_xdp", "xdp.mode=native", "kernel:", "capabilities:"] {
		assert!(text.contains(row), "{row}:\n{text}");
	}

	// requested: the exit status says whether it works; JSON has the same report
	let out = command(&dir, &[("RPROXY_XDP_MODE", "af_xdp".into())]).args(["--check-kernel", "--check-kernel-format", "json"]).output().unwrap();
	let report: Value = serde_json::from_slice(&out.stdout).unwrap();
	let paths = report["paths"].as_array().unwrap();
	let af_xdp = paths.iter().find(|p| p["key"] == "xdp.mode" && p["mode"] == "af_xdp").unwrap();
	assert_eq!(af_xdp["requested"], true, "{report}");
	assert_eq!(out.status.success(), af_xdp["usable"] == true, "{report}");
	assert_eq!(paths.iter().filter(|p| p["requested"] == true).count(), 1, "{report}");
	assert!(report["host"]["kernel"].is_string(), "{report}");
	let _ = fs::remove_dir_all(dir);
}
