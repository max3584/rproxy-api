//! Kernel offload (#260) with the real binary: the startup probe of
//! `global.performance.ebpf` / `xdp` (`performance.probe`, `degraded`,
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
	assert_eq!(caps["performance"]["ebpf_tcp"], serde_json::json!({"requested": "off", "active": false, "mode": null, "reason": null}), "{caps}");
	assert_eq!(caps["performance"]["xdp"]["requested"], "off", "{caps}");
	assert!(rp.lines("performance.probe").is_empty(), "{}", rp.text());
	assert!(!rp.text().contains("global.performance.ebpf"), "{}", rp.text());
	drop(rp);
	let _ = fs::remove_dir_all(dir);
}

#[tokio::test]
async fn requested_fast_paths_are_probed_and_fall_back_with_a_reason() {
	let dir = workdir("probe");
	let rp = Rproxy::start(&dir, &[("RPROXY_EBPF_TCP", "sockmap".into()), ("RPROXY_XDP_MODE", "af_xdp".into())]);
	let caps = rp.capabilities().await;
	let probes = rp.lines("performance.probe");
	assert_eq!(probes.len(), 2, "{}", rp.text());
	for (name, requested, part) in [("ebpf_tcp", "sockmap", "global.performance.ebpf.tcp"), ("xdp", "af_xdp", "global.performance.xdp.mode")] {
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
	let out = command(&dir, &[("RPROXY_EBPF_TCP", "fast".into())]).arg("--check-kernel").output().unwrap();
	assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("RPROXY_EBPF_TCP"), "{out:?}");
	let cfg = dir.join("rproxy.yaml");
	fs::write(&cfg, "version: 1\nglobal:\n  performance:\n    xdp: {frame_size: 1024}\n").unwrap();
	let out = command(&dir, &[("RPROXY_CONFIG", cfg.display().to_string())]).arg("--check-kernel").output().unwrap();
	assert!(!out.status.success() && String::from_utf8_lossy(&out.stderr).contains("frame_size"), "{out:?}");
	let _ = fs::remove_dir_all(dir);
}

/// On a host that allows BPF (the CI root job sets `RPROXY_TEST_REQUIRE_SOCKMAP`)
/// sockmap must actually relay the probe's test data; elsewhere this only
/// checks the outcome is reported consistently.
#[test]
fn sockmap_relays_test_data_when_the_kernel_allows() {
	let dir = workdir("sockmap");
	let out = command(&dir, &[("RPROXY_EBPF_TCP", "sockmap".into())]).args(["--check-kernel", "--check-kernel-format", "json"]).output().unwrap();
	let report: Value = serde_json::from_slice(&out.stdout).unwrap();
	let sockmap = report["paths"].as_array().unwrap().iter().find(|p| p["key"] == "ebpf.tcp" && p["mode"] == "sockmap").unwrap().clone();
	let required = std::env::var("RPROXY_TEST_REQUIRE_SOCKMAP").is_ok();
	if required {
		assert_eq!(sockmap["usable"], true, "sockmap must work on this host: {report}");
	}
	if sockmap["usable"] == true {
		// every sub-test (load+attach, both directions, >64 KiB, split, FIN) passed
		for t in sockmap["tests"].as_array().unwrap() {
			assert_eq!(t["ok"], true, "sub-test {}: {report}", t["name"]);
		}
		assert!(out.status.success(), "exit 0 when the requested path works: {report}");
		assert!(sockmap["tests"].as_array().unwrap().iter().any(|t| t["name"] == "fin"), "FIN is checked: {report}");
	} else {
		assert!(sockmap["detail"].as_str().is_some_and(|d| !d.is_empty()), "a reason when not usable: {report}");
	}
	let _ = fs::remove_dir_all(dir);
}

/// End to end: a real rproxy with a plain TCP rule and `RPROXY_EBPF_TCP=sockmap`
/// relays a stream (including >64 KiB) and a half-close through the kernel. On a
/// host that allows BPF (the CI root job) this must use sockmap and match byte
/// for byte; elsewhere sockmap is not active and the test skips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_rproxy_relays_plain_tcp_through_sockmap() {
	use std::io::{Read, Write};
	use std::net::{Shutdown, TcpListener, TcpStream};
	let dir = workdir("relay");
	// an echo backend
	let backend = TcpListener::bind("127.0.0.1:0").unwrap();
	let bport = backend.local_addr().unwrap().port();
	std::thread::spawn(move || {
		for s in backend.incoming().flatten() {
			std::thread::spawn(move || {
				let mut r = s.try_clone().unwrap();
				let mut w = s;
				let _ = std::io::copy(&mut r, &mut w);
			});
		}
	});
	let lport = free_port();
	let cfg = dir.join("rproxy.yaml");
	fs::write(
		&cfg,
		format!("version: 1\nrules:\n  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {lport}, remote_addr: 127.0.0.1, remote_port: {bport}}}\n"),
	)
	.unwrap();
	let rp = Rproxy::start(&dir, &[("RPROXY_CONFIG", cfg.display().to_string()), ("RPROXY_EBPF_TCP", "sockmap".into())]);
	let caps = rp.capabilities().await;
	let active = caps["performance"]["ebpf_tcp"]["active"] == true;
	let required = std::env::var("RPROXY_TEST_REQUIRE_SOCKMAP").is_ok();
	if required {
		assert!(active, "sockmap must be active on this host: {caps}");
	}
	if !active {
		drop(rp);
		let _ = fs::remove_dir_all(dir);
		return;
	}

	let data: Vec<u8> = (0..(256usize << 10)).map(|i| (i.wrapping_mul(2654435761) >> 11) as u8).collect();
	let got = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
		let deadline = Instant::now() + Duration::from_secs(10);
		let mut conn = loop {
			match TcpStream::connect(("127.0.0.1", lport)) {
				Ok(c) => break c,
				Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
				Err(e) => return Err(e),
			}
		};
		conn.set_read_timeout(Some(Duration::from_secs(10)))?;
		let want = data.len();
		let mut reader = conn.try_clone()?;
		let send = std::thread::spawn(move || -> std::io::Result<()> {
			for chunk in data.chunks(13 << 10) {
				conn.write_all(chunk)?;
			}
			conn.flush()?;
			conn.shutdown(Shutdown::Write)?; // half-close: the echo must still drain back
			Ok(())
		});
		let mut got = Vec::with_capacity(want);
		let mut buf = [0u8; 32 << 10];
		loop {
			let n = reader.read(&mut buf)?;
			if n == 0 {
				break;
			}
			got.extend_from_slice(&buf[..n]);
		}
		send.join().unwrap()?;
		Ok(got)
	})
	.await
	.unwrap()
	.unwrap();

	let expect: Vec<u8> = (0..(256usize << 10)).map(|i| (i.wrapping_mul(2654435761) >> 11) as u8).collect();
	assert_eq!(got.len(), expect.len(), "echoed length");
	assert!(got == expect, "echoed bytes differ");
	drop(rp);
	let _ = fs::remove_dir_all(dir);
}

#[test]
fn check_kernel_tests_every_fast_path_and_prints_a_table() {
	let dir = workdir("check");
	// nothing requested: every fast path is tested, and the check passes
	let out = command(&dir, &[]).arg("--check-kernel").output().unwrap();
	let text = String::from_utf8_lossy(&out.stdout).to_string();
	assert!(out.status.success(), "{out:?}");
	for row in ["ebpf.tcp=sockmap", "ebpf.tcp=nat", "xdp.mode=af_xdp", "xdp.mode=native", "kernel:", "capabilities:"] {
		assert!(text.contains(row), "{row}:\n{text}");
	}

	// requested: the exit status says whether it works; JSON has the same report
	let out = command(&dir, &[("RPROXY_EBPF_TCP", "sockmap".into())]).args(["--check-kernel", "--check-kernel-format", "json"]).output().unwrap();
	let report: Value = serde_json::from_slice(&out.stdout).unwrap();
	let paths = report["paths"].as_array().unwrap();
	let sockmap = paths.iter().find(|p| p["key"] == "ebpf.tcp" && p["mode"] == "sockmap").unwrap();
	assert_eq!(sockmap["requested"], true, "{report}");
	assert_eq!(out.status.success(), sockmap["usable"] == true, "{report}");
	assert_eq!(paths.iter().filter(|p| p["requested"] == true).count(), 1, "{report}");
	assert!(report["host"]["kernel"].is_string(), "{report}");
	let _ = fs::remove_dir_all(dir);
}
