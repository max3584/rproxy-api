//! The self-update (#174, docs/DESIGN-v0.4.md 10.2) with the real binary and a
//! release mirror over HTTPS: a newer signed patch is fetched, verified and
//! swapped in with a live upgrade; a bad signature is refused; `rproxy-api
//! launch` runs the newest patch, follows live upgrades and rolls a version on
//! trial back. The "newer" release is this very binary published under the
//! next patch number (the version the cache and the manifest give it).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::fs;
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use serde_json::{json, Value};

use common::pki::Pki;
use common::*;
use rproxy_api::control::upgrade::minisign::testing;
use rproxy_api::control::upgrade::update::{asset_name, Version};

const KEY_ID: [u8; 8] = [0x52, 0x50, 0x52, 0x58, 0x59, 0x54, 0x53, 0x54];

fn workdir(tag: &str) -> PathBuf {
	// keys and secrets written here must pass the owner check (net::files)
	rproxy_api::net::files::private_umask();
	let dir = std::env::temp_dir().join(format!("rproxy-update-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

type Files = Arc<Mutex<HashMap<String, Bytes>>>;

/// An HTTPS mirror of the release paths. Binaries are answered with a redirect
/// to `/objects/...`, as GitHub does.
async fn mirror(pki: &Pki) -> (u16, Files) {
	let issued = pki.server("mirror", &["localhost"]);
	let acceptor = pki.acceptor(&issued);
	let files: Files = Arc::default();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	let served = files.clone();
	tokio::spawn(async move {
		loop {
			let Ok((tcp, _)) = listener.accept().await else { continue };
			let (acceptor, files) = (acceptor.clone(), served.clone());
			tokio::spawn(async move {
				let Ok(tls) = acceptor.accept(tcp).await else { return };
				let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
					let files = files.clone();
					async move {
						let path = req.uri().path().to_string();
						let resp = if let Some(rest) = path.strip_prefix("/releases/download/").filter(|p| p.contains("/rproxy-api-v") && !p.ends_with(".minisig")) {
							Response::builder().status(StatusCode::FOUND).header("location", format!("/objects/{rest}")).body(Full::new(Bytes::new()))
						} else {
							let key = path.replacen("/objects/", "/releases/download/", 1);
							match files.lock().unwrap().get(&key) {
								Some(b) => Response::builder().body(Full::new(b.clone())),
								None => Response::builder().status(StatusCode::NOT_FOUND).body(Full::new(Bytes::new())),
							}
						};
						Ok::<_, Infallible>(resp.unwrap())
					}
				});
				let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(tls), service).await;
			});
		}
	});
	(port, files)
}

fn sha256(b: &[u8]) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

/// Publishes `binary` as release `v`, signed (or with the binary's signature
/// made over other bytes when `forged`).
fn publish(files: &Files, pair: &ring::signature::Ed25519KeyPair, v: Version, binary: &[u8], forged: bool) {
	let name = asset_name(v);
	let manifest = serde_json::to_vec(&json!({"version": v.to_string(), "handoff": true, "files": {name.clone(): sha256(binary)}})).unwrap();
	let signed: &[u8] = if forged { b"something else" } else { binary };
	let mut f = files.lock().unwrap();
	let base = format!("/releases/download/v{v}");
	f.insert(format!("{base}/manifest.json.minisig"), testing::sign(pair, KEY_ID, &manifest, "manifest").into());
	f.insert(format!("{base}/manifest.json"), manifest.into());
	f.insert(format!("{base}/{name}.minisig"), testing::sign(pair, KEY_ID, signed, &format!("file:{name}")).into());
	f.insert(format!("{base}/{name}"), Bytes::copy_from_slice(binary));
	drop(f);
	list(files, pair, v);
}

/// Adds `v` to the signed release index (`releases.json` of the latest release),
/// as the release workflow does with every release.
fn list(files: &Files, pair: &ring::signature::Ed25519KeyPair, v: Version) {
	let mut f = files.lock().unwrap();
	let key = "/releases/latest/download/releases.json".to_string();
	let mut index: Value = f.get(&key).map(|b| serde_json::from_slice(b).unwrap()).unwrap_or(json!({"releases": []}));
	index["releases"].as_array_mut().unwrap().push(json!({"version": v.to_string()}));
	// newer with each release, as the release workflow writes it (security review L4)
	let n = index["releases"].as_array().unwrap().len() as u64;
	index["generated_at"] = json!(1_700_000_000 + n);
	let body = serde_json::to_vec(&index).unwrap();
	f.insert(format!("{key}.minisig"), testing::sign(pair, KEY_ID, &body, "index").into());
	f.insert(key, body.into());
}

struct Procs {
	first: Child,
	pids: Vec<i32>,
	log: PathBuf,
}

impl Drop for Procs {
	fn drop(&mut self) {
		for pid in &self.pids {
			signal(*pid, libc::SIGKILL);
		}
		let _ = self.first.kill();
		let _ = self.first.wait();
	}
}

fn signal(pid: i32, sig: libc::c_int) {
	// SAFETY: a signal to a process this test started
	unsafe { libc::kill(pid, sig) };
}

fn alive(pid: i32) -> bool {
	fs::read_to_string(format!("/proc/{pid}/stat")).map(|s| s.rsplit(')').next().is_some_and(|r| !r.trim_start().starts_with('Z'))).unwrap_or(false)
}

fn start(dir: &Path, args: &[&str], env: &[(&str, String)]) -> Procs {
	let log = dir.join("out.log");
	let out = fs::File::create(&log).unwrap();
	let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.current_dir(dir)
		.env_clear()
		.args(args)
		.envs(env.iter().map(|(k, v)| (*k, v.as_str())))
		.stdout(out.try_clone().unwrap())
		.stderr(out)
		.stdin(Stdio::null())
		// a group of its own: `kill_group` stops everything, like the end of a container
		.process_group(0)
		.spawn()
		.unwrap();
	let pid = child.id() as i32;
	Procs { first: child, pids: vec![pid], log }
}

/// SIGKILL to the launcher and everything it started (a container killed or out of memory).
fn kill_group(procs: &mut Procs) {
	// SAFETY: the process group this test started
	unsafe { libc::killpg(procs.pids[0], libc::SIGKILL) };
	let _ = procs.first.wait();
	let deadline = Instant::now() + Duration::from_secs(10);
	while fs::read_dir("/proc").unwrap().flatten().any(|e| {
		let stat = fs::read_to_string(e.path().join("stat")).unwrap_or_default();
		let rest: Vec<&str> = stat.rsplit_once(')').map(|(_, r)| r.split_whitespace().collect()).unwrap_or_default();
		rest.first() != Some(&"Z") && rest.get(2).and_then(|g| g.parse::<i32>().ok()) == Some(procs.pids[0])
	}) {
		assert!(Instant::now() < deadline, "the process group did not stop");
		std::thread::sleep(Duration::from_millis(20));
	}
}

/// The server the launcher runs now (its child), once there is one.
async fn server_of(launcher: i32, not: &[i32], log: &Path) -> i32 {
	let mut server = 0;
	wait_until("the server", log, || {
		server = children_of(launcher).into_iter().find(|p| !not.contains(p)).unwrap_or(0);
		server != 0
	})
	.await;
	server
}

fn lines(log: &Path) -> Vec<Value> {
	fs::read_to_string(log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

async fn wait_event(log: &Path, event: &str, n: usize) -> Value {
	let deadline = Instant::now() + Duration::from_secs(40);
	loop {
		let found: Vec<Value> = lines(log).into_iter().filter(|l| l["event"] == event).collect();
		if found.len() >= n {
			return found[n - 1].clone();
		}
		assert!(Instant::now() < deadline, "no {event} #{n}; log:\n{}", fs::read_to_string(log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

async fn wait_until(what: &str, log: &Path, mut f: impl FnMut() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(40);
	while !f() {
		assert!(Instant::now() < deadline, "timed out waiting for {what}; log:\n{}", fs::read_to_string(log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

fn exe_of(pid: i32) -> PathBuf {
	fs::read_link(format!("/proc/{pid}/exe")).unwrap_or_default()
}

fn children_of(pid: i32) -> Vec<i32> {
	fs::read_dir("/proc")
		.unwrap()
		.flatten()
		.filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()))
		.filter(|p| {
			fs::read_to_string(format!("/proc/{p}/status"))
				.ok()
				.and_then(|s| s.lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|v| v.trim().parse::<i32>().ok()))
				== Some(pid)
		})
		.filter(|p| alive(*p))
		.collect()
}

fn state(cache: &Path) -> Value {
	fs::read(cache.join("state.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
}

async fn api(port: u16, method: reqwest::Method, path: &str) -> Option<(u16, Value)> {
	let r = reqwest::Client::new().request(method, format!("http://127.0.0.1:{port}{path}")).timeout(Duration::from_secs(5)).send().await.ok()?;
	let status = r.status().as_u16();
	Some((status, r.json().await.unwrap_or(Value::Null)))
}

struct Setup {
	dir: PathBuf,
	cache: PathBuf,
	files: Files,
	pair: ring::signature::Ed25519KeyPair,
	env: Vec<(&'static str, String)>,
	_pki: Pki,
}

async fn setup(tag: &str) -> Setup {
	let dir = workdir(tag);
	let pki = Pki::new(&format!("update-{tag}"));
	let (port, files) = mirror(&pki).await;
	let (pub_text, pair) = testing::key_pair([42; 32], KEY_ID);
	fs::write(dir.join("release.pub"), pub_text).unwrap();
	let cache = dir.join("cache");
	let env = vec![
		("RPROXY_UPDATE", "auto".to_string()),
		("RPROXY_UPDATE_SOURCE", format!("https://localhost:{port}/releases")),
		("RPROXY_UPDATE_CACHE", cache.display().to_string()),
		("RPROXY_UPDATE_PUBKEY", dir.join("release.pub").display().to_string()),
		("RPROXY_UPDATE_CA_FILE", pki.ca_file.clone()),
		("RPROXY_UPDATE_INTERVAL", "0s".into()),
		("RPROXY_UPDATE_HEALTHY", "2s".into()),
		("RPROXY_HANDOFF_SOCKET", dir.join("handoff.sock").display().to_string()),
		("RPROXY_HANDOFF_DRAIN", "5s".into()),
		("RPROXY_API_RELOAD_UNIX_ONLY", "false".into()),
	];
	Setup { dir, cache, files, pair, env, _pki: pki }
}

fn next(v: Version, n: u64) -> Version {
	Version(v.0, v.1, v.2 + n)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_patch_is_swapped_in_and_a_forged_one_refused() {
	let s = setup("server").await;
	let binary = fs::read(env!("CARGO_BIN_EXE_rproxy-api")).unwrap();
	// patch numbers have gaps (only the repository whose code changed is
	// released): the next patch is +2; another minor in the index is ignored
	let v1 = next(Version::own(), 2);
	publish(&s.files, &s.pair, v1, &binary, false);
	let own = Version::own();
	list(&s.files, &s.pair, Version(own.0, own.1 + 1, 0));
	let port = free_port();
	let mut env = s.env.clone();
	env.push(("RPROXY_API_PORT", port.to_string()));
	let mut procs = start(&s.dir, &[], &env);
	let log = procs.log.clone();
	let deadline = Instant::now() + Duration::from_secs(20);
	while api(port, reqwest::Method::GET, "/capabilities").await.is_none() {
		assert!(Instant::now() < deadline, "API down:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let (_, st) = api(port, reqwest::Method::GET, "/admin/update").await.unwrap();
	assert_eq!((&st["mode"], &st["current"]["version"], &st["available"]), (&json!("auto"), &json!(Version::own().to_string()), &Value::Null), "{st}");

	// a check finds v1, verifies it and hands over to it
	let (status, _) = api(port, reqwest::Method::POST, "/admin/update").await.unwrap();
	assert_eq!(status, 202);
	let ready = wait_event(&log, "handoff.ready", 1).await;
	let new = ready["pid"].as_i64().unwrap() as i32;
	procs.pids.push(new);
	assert_eq!(exe_of(new), s.cache.join(v1.to_string()).join("rproxy-api"));
	let deadline = Instant::now() + Duration::from_secs(20);
	loop {
		if let Some((200, st)) = api(port, reqwest::Method::GET, "/admin/update").await {
			if st["current"]["version"] == json!(v1.to_string()) {
				break;
			}
		}
		assert!(Instant::now() < deadline, "the new process did not answer");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	// it keeps running RPROXY_UPDATE_HEALTHY: the good version now
	wait_event(&log, "update.healthy", 1).await;
	let st = state(&s.cache);
	assert_eq!((&st["good"], &st["trial"]), (&json!(v1.to_string()), &Value::Null), "{st}");

	// v2's binary is not what was signed: refused, nothing swapped
	let v2 = next(Version::own(), 5);
	publish(&s.files, &s.pair, v2, &binary, true);
	let (status, _) = api(port, reqwest::Method::POST, "/admin/update").await.unwrap();
	assert_eq!(status, 202);
	let deadline = Instant::now() + Duration::from_secs(60);
	let st = loop {
		if let Some((_, st)) = api(port, reqwest::Method::GET, "/admin/update").await {
			if !st["error"].is_null() {
				break st;
			}
		}
		assert!(Instant::now() < deadline, "no error reported");
		tokio::time::sleep(Duration::from_millis(100)).await;
	};
	assert!(st["error"].as_str().unwrap().contains("does not match"), "{st}");
	assert_eq!(st["current"]["version"], json!(v1.to_string()));
	assert!(!s.cache.join(v2.to_string()).exists(), "never stored");
	assert_eq!(lines(&log).iter().filter(|l| l["event"] == "handoff.ready").count(), 1);

	signal(new, libc::SIGTERM);
	wait_until("the new process to stop", &log, || !alive(new)).await;
	drop(procs);
	let _ = fs::remove_dir_all(&s.dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn launch_runs_the_newest_patch_follows_upgrades_and_rolls_back() {
	let s = setup("launch").await;
	let binary = fs::read(env!("CARGO_BIN_EXE_rproxy-api")).unwrap();
	let v1 = next(Version::own(), 1);
	publish(&s.files, &s.pair, v1, &binary, false);
	let port = free_port();
	let mut env = s.env.clone();
	env.push(("RPROXY_API_PORT", port.to_string()));
	// long enough to roll back before it is good
	env.retain(|(k, _)| *k != "RPROXY_UPDATE_HEALTHY");
	env.push(("RPROXY_UPDATE_HEALTHY", "10m".into()));
	let mut procs = start(&s.dir, &["launch"], &env);
	let log = procs.log.clone();
	let launcher = procs.pids[0];

	// the launcher fetched v1 and runs it, on trial
	let started = wait_event(&log, "launch.start", 1).await;
	assert_eq!(started["version"], json!(v1.to_string()), "{started}");
	let mut main = 0;
	wait_until("the server process", &log, || {
		main = children_of(launcher).first().copied().unwrap_or(0);
		main != 0 && exe_of(main) == s.cache.join(v1.to_string()).join("rproxy-api")
	})
	.await;
	procs.pids.push(main);
	assert_eq!(state(&s.cache)["trial"]["version"], json!(v1.to_string()));
	let deadline = Instant::now() + Duration::from_secs(20);
	while api(port, reqwest::Method::GET, "/capabilities").await.is_none() {
		assert!(Instant::now() < deadline, "API down:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}

	// SIGUSR2 to the launcher: the server hands over, the launcher follows
	signal(launcher, libc::SIGUSR2);
	let ready = wait_event(&log, "handoff.ready", 1).await;
	let second = ready["pid"].as_i64().unwrap() as i32;
	procs.pids.push(second);
	let followed = wait_event(&log, "launch.mainpid", 1).await;
	assert_eq!((followed["old"].as_i64(), followed["new"].as_i64()), (Some(main as i64), Some(second as i64)), "{followed}");
	wait_until("the first server to end", &log, || !alive(main)).await;

	// v1 dies while on trial (a crash of its own: SIGKILL counts as an interruption,
	// `a_trial_killed_three_times_is_bad`): marked bad, the image's version runs instead
	signal(second, libc::SIGABRT);
	let rolled = wait_event(&log, "update.rollback", 1).await;
	assert_eq!(rolled["version"], json!(v1.to_string()), "{rolled}");
	let mut third = 0;
	wait_until("the rolled back server", &log, || {
		third = children_of(launcher).into_iter().find(|p| *p != second).unwrap_or(0);
		third != 0 && exe_of(third) == Path::new(env!("CARGO_BIN_EXE_rproxy-api"))
	})
	.await;
	procs.pids.push(third);
	assert!(state(&s.cache)["bad"].as_array().unwrap().contains(&json!(v1.to_string())));

	// SIGTERM to the launcher stops the server, then the launcher
	let deadline = Instant::now() + Duration::from_secs(20);
	while api(port, reqwest::Method::GET, "/capabilities").await.is_none() {
		assert!(Instant::now() < deadline, "API down after the rollback:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	signal(launcher, libc::SIGTERM);
	let deadline = Instant::now() + Duration::from_secs(20);
	let status = loop {
		if let Some(st) = procs.first.try_wait().unwrap() {
			break st;
		}
		assert!(Instant::now() < deadline, "the launcher did not stop:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	};
	assert!(status.success(), "{status:?}\n{}", fs::read_to_string(&log).unwrap_or_default());
	assert!(!alive(third));
	drop(procs);
	let _ = fs::remove_dir_all(&s.dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trial_stopped_by_a_signal_is_not_bad_and_bad_marks_can_be_cleared() {
	// security review M1: docker stop / a rolling restart during the trial says nothing about the version
	let s = setup("launch-stop").await;
	let binary = fs::read(env!("CARGO_BIN_EXE_rproxy-api")).unwrap();
	let v1 = next(Version::own(), 1);
	publish(&s.files, &s.pair, v1, &binary, false);
	let port = free_port();
	let mut env = s.env.clone();
	env.push(("RPROXY_API_PORT", port.to_string()));
	env.retain(|(k, _)| *k != "RPROXY_UPDATE_HEALTHY");
	env.push(("RPROXY_UPDATE_HEALTHY", "10m".into()));
	let mut procs = start(&s.dir, &["launch"], &env);
	let log = procs.log.clone();
	let launcher = procs.pids[0];
	wait_event(&log, "launch.start", 1).await;
	assert_eq!(state(&s.cache)["trial"]["version"], json!(v1.to_string()));
	let deadline = Instant::now() + Duration::from_secs(20);
	while api(port, reqwest::Method::GET, "/capabilities").await.is_none() {
		assert!(Instant::now() < deadline, "API down:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	signal(launcher, libc::SIGTERM);
	let deadline = Instant::now() + Duration::from_secs(20);
	while procs.first.try_wait().unwrap().is_none() {
		assert!(Instant::now() < deadline, "the launcher did not stop");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	let st = state(&s.cache);
	assert!(st["trial"].is_null(), "{st}");
	assert!(!st["bad"].as_array().is_some_and(|b| b.contains(&json!(v1.to_string()))), "{st}");
	drop(procs);

	// a mark can be taken off again from the command line (or DELETE /admin/update/bad)
	let mut st = st;
	st["bad"] = json!([v1.to_string()]);
	fs::write(s.cache.join("state.json"), st.to_string()).unwrap();
	let out = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.env_clear()
		.args(["update-clear-bad", "--version", &v1.to_string()])
		.env("RPROXY_UPDATE_CACHE", s.cache.display().to_string())
		.output()
		.unwrap();
	assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
	assert_eq!(serde_json::from_slice::<Value>(&out.stdout).unwrap()["cleared"], json!([v1.to_string()]));
	assert_eq!(state(&s.cache)["bad"], json!([]));
	let _ = fs::remove_dir_all(&s.dir);
}

/// A version on trial cut short by SIGKILL, abnormal ends the launcher cannot
/// tell from the version's fault (security review M1): the whole container
/// killed (the launcher with it), or only the server killed (the OOM killer of
/// the container's memory limit takes the largest process, the server). Each
/// counts as `update.interrupted`; the third makes the version bad and the
/// image's version runs instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trial_killed_three_times_is_bad() {
	let s = setup("launch-kill").await;
	let binary = fs::read(env!("CARGO_BIN_EXE_rproxy-api")).unwrap();
	let v1 = next(Version::own(), 1);
	publish(&s.files, &s.pair, v1, &binary, false);
	let port = free_port();
	let mut env = s.env.clone();
	env.push(("RPROXY_API_PORT", port.to_string()));
	env.retain(|(k, _)| *k != "RPROXY_UPDATE_HEALTHY");
	env.push(("RPROXY_UPDATE_HEALTHY", "10m".into()));
	let trial = |cache: &Path| state(cache)["trial"].clone();

	// 1. the container is killed while v1 is on trial
	let mut procs = start(&s.dir, &["launch"], &env);
	let log = procs.log.clone();
	assert_eq!(wait_event(&log, "launch.start", 1).await["version"], json!(v1.to_string()));
	server_of(procs.pids[0], &[], &log).await;
	assert_eq!(trial(&s.cache)["version"], json!(v1.to_string()));
	kill_group(&mut procs);
	drop(procs);

	// 2. the next start counts it and tries v1 again
	let mut procs = start(&s.dir, &["launch"], &env);
	let log = procs.log.clone();
	let launcher = procs.pids[0];
	assert_eq!(wait_event(&log, "update.interrupted", 1).await["times"], json!(1));
	assert_eq!(wait_event(&log, "launch.start", 1).await["version"], json!(v1.to_string()));
	assert_eq!(trial(&s.cache)["interrupted"], json!(1), "{}", trial(&s.cache));
	let server = server_of(launcher, &[], &log).await;

	// 3. only the server is killed: counted the same, not bad at once
	signal(server, libc::SIGKILL);
	assert_eq!(wait_event(&log, "update.interrupted", 2).await["times"], json!(2));
	assert_eq!(wait_event(&log, "launch.start", 2).await["version"], json!(v1.to_string()));
	let st = state(&s.cache);
	assert_eq!((&st["trial"]["interrupted"], st["bad"].as_array().map_or(0, |b| b.len())), (&json!(2), 0), "{st}");
	assert!(lines(&log).iter().all(|l| l["event"] != "update.rollback"), "not rolled back");
	let second = server_of(launcher, &[server], &log).await;

	// 4. the third time: bad, and the image's version runs
	signal(second, libc::SIGKILL);
	assert_eq!(wait_event(&log, "launch.start", 3).await["version"], json!(Version::own().to_string()));
	let st = state(&s.cache);
	assert_eq!((&st["bad"], &st["trial"]), (&json!([v1.to_string()]), &Value::Null), "{st}");
	let deadline = Instant::now() + Duration::from_secs(20);
	while api(port, reqwest::Method::GET, "/capabilities").await.is_none() {
		assert!(Instant::now() < deadline, "API down:\n{}", fs::read_to_string(&log).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	signal(launcher, libc::SIGTERM);
	let deadline = Instant::now() + Duration::from_secs(20);
	while procs.first.try_wait().unwrap().is_none() {
		assert!(Instant::now() < deadline, "the launcher did not stop");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	drop(procs);
	let _ = fs::remove_dir_all(&s.dir);
}

/// Signatures made by minisign itself verify (CI installs it:
/// `RPROXY_TEST_REQUIRE_MINISIGN=1`; skipped elsewhere when it is missing).
#[test]
fn signatures_of_the_minisign_tool_verify() {
	use rproxy_api::control::upgrade::minisign;
	let have = Command::new("minisign").arg("-v").output().is_ok();
	if !have {
		assert!(std::env::var_os("RPROXY_TEST_REQUIRE_MINISIGN").is_none(), "minisign is required");
		eprintln!("minisign not installed; skipped");
		return;
	}
	let dir = workdir("minisign");
	let (pk, sk, file) = (dir.join("m.pub"), dir.join("m.key"), dir.join("payload"));
	fs::write(&file, vec![7u8; 300_000]).unwrap();
	let gen = Command::new("minisign").args(["-G", "-W", "-p"]).arg(&pk).arg("-s").arg(&sk).output().unwrap();
	assert!(gen.status.success(), "{gen:?}");
	let sign = Command::new("minisign").args(["-S", "-s"]).arg(&sk).arg("-m").arg(&file).args(["-t", "rproxy test"]).output().unwrap();
	assert!(sign.status.success(), "{sign:?}");
	let key = minisign::PublicKey::parse(&fs::read_to_string(&pk).unwrap()).unwrap();
	let sig = fs::read_to_string(dir.join("payload.minisig")).unwrap();
	assert_eq!(minisign::verify(&key, &sig, &fs::read(&file).unwrap()).unwrap(), "rproxy test");
	assert!(minisign::verify(&key, &sig, b"other").is_err());
	// the legacy (not prehashed) signatures too
	let legacy = Command::new("minisign").args(["-S", "-l", "-s"]).arg(&sk).arg("-m").arg(&file).output().unwrap();
	if legacy.status.success() {
		let sig = fs::read_to_string(dir.join("payload.minisig")).unwrap();
		minisign::verify(&key, &sig, &fs::read(&file).unwrap()).unwrap();
	}
	let _ = fs::remove_dir_all(dir);
}
