//! Starting the real binary: configuration mistakes stop it, problems in the
//! environment (permissions, a busy port) leave it running in a restricted
//! mode that recovers once the problem is gone.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

use common::pki::Pki;
use common::*;

struct Rproxy {
	child: Child,
	out: PathBuf,
}

impl Drop for Rproxy {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

impl Rproxy {
	fn start(dir: &Path, api_port: u16, env: &[(&str, &str)]) -> Rproxy {
		let out = dir.join("stdout.log");
		let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(dir) // no .env from the repository
			.env_clear()
			.env("RPROXY_API_PORT", api_port.to_string())
			.env("RPROXY_API_RETRY_SECS", "1")
			.envs(env.iter().copied())
			.stdout(fs::File::create(&out).unwrap())
			.stderr(Stdio::piped())
			.spawn()
			.unwrap();
		Rproxy { child, out }
	}

	fn log(&self) -> String {
		fs::read_to_string(&self.out).unwrap_or_default()
	}

	/// Waits for the process to exit and returns (success, stderr + stdout).
	fn exited(mut self) -> (bool, String) {
		let deadline = Instant::now() + Duration::from_secs(10);
		loop {
			if let Some(status) = self.child.try_wait().unwrap() {
				let mut err = String::new();
				use std::io::Read;
				self.child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
				return (status.success(), err + &self.log());
			}
			assert!(Instant::now() < deadline, "still running:\n{}", self.log());
			std::thread::sleep(Duration::from_millis(50));
		}
	}

	fn hup(&self) {
		// SAFETY: sending a signal to our own child
		unsafe { libc::kill(self.child.id() as i32, libc::SIGHUP) };
	}
}

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-startup-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn chmod(path: &Path, mode: u32) {
	fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Permission tests mean nothing as root.
fn as_root() -> bool {
	// SAFETY: plain syscall
	unsafe { libc::geteuid() == 0 }
}

/// GET /rules status, or None while nothing listens.
async fn api_status(port: u16, token: Option<&str>) -> Option<u16> {
	let mut req = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/rules"));
	if let Some(t) = token {
		req = req.bearer_auth(t);
	}
	req.timeout(Duration::from_secs(2)).send().await.ok().map(|r| r.status().as_u16())
}

async fn wait_for<F, Fut>(what: &str, rp: &Rproxy, mut check: F)
where
	F: FnMut() -> Fut,
	Fut: std::future::Future<Output = bool>,
{
	let deadline = Instant::now() + Duration::from_secs(15);
	while !check().await {
		assert!(Instant::now() < deadline, "timed out waiting for {what}; log:\n{}", rp.log());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

#[tokio::test]
async fn configuration_mistakes_stop_the_startup() {
	let dir = workdir("config");
	// (what, environment, expected in the error)
	type Case<'a> = (&'a str, Vec<(&'a str, String)>, &'a str);
	let cases: Vec<Case> = vec![
		("log level", vec![("RPROXY_LOG_LEVEL", "no-such=level=x".into())], "log level"),
		("log directory", vec![("RPROXY_LOG_FILE", dir.join("missing/rproxy.log").display().to_string())], "does not exist"),
		("token file path", vec![("RPROXY_TOKEN_FILE", dir.join("missing-tokens").display().to_string())], "token file"),
		("static rules path", vec![("RPROXY_STATIC_RULES", dir.join("missing.json").display().to_string())], "static rules"),
	];
	for (name, env, expect) in cases {
		let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
		let (ok, out) = Rproxy::start(&dir, free_port(), &env).exited();
		assert!(!ok, "{name}: started anyway");
		assert!(out.contains(expect), "{name}: {out}");
	}

	// a token file without tokens and a static file that is not JSON are mistakes too
	let empty = dir.join("empty-tokens");
	fs::write(&empty, "# nothing\n").unwrap();
	let bad = dir.join("bad.json");
	fs::write(&bad, "{not json").unwrap();
	for (key, path) in [("RPROXY_TOKEN_FILE", &empty), ("RPROXY_STATIC_RULES", &bad)] {
		let (ok, out) = Rproxy::start(&dir, free_port(), &[(key, path.to_str().unwrap())]).exited();
		assert!(!ok, "{key}: started anyway: {out}");
	}
}

#[tokio::test]
async fn an_unwritable_log_directory_falls_back_to_stdout() {
	if as_root() {
		return;
	}
	let dir = workdir("log");
	let logs = dir.join("logs");
	fs::create_dir(&logs).unwrap();
	chmod(&logs, 0o555);
	let port = free_port();
	let log_file = logs.join("rproxy.log");
	let rp = Rproxy::start(&dir, port, &[("RPROXY_LOG_FILE", log_file.to_str().unwrap())]);
	wait_for("the API", &rp, || async { api_status(port, None).await == Some(200) }).await;
	assert!(rp.log().contains(r#""part":"log""#), "{}", rp.log());
	chmod(&logs, 0o755);
}

#[tokio::test]
async fn an_unreadable_token_file_locks_the_api_until_sighup() {
	if as_root() {
		return;
	}
	let dir = workdir("tokens");
	let tokens = dir.join("tokens");
	fs::write(&tokens, "secret-token\n").unwrap();
	chmod(&tokens, 0o000);
	let port = free_port();
	let rp = Rproxy::start(&dir, port, &[("RPROXY_TOKEN_FILE", tokens.to_str().unwrap())]);
	wait_for("the locked API", &rp, || async { api_status(port, Some("secret-token")).await == Some(401) }).await;
	assert!(rp.log().contains(r#""part":"tokens""#), "{}", rp.log());

	chmod(&tokens, 0o600);
	rp.hup();
	wait_for("the token after SIGHUP", &rp, || async { api_status(port, Some("secret-token")).await == Some(200) }).await;
	assert_eq!(api_status(port, Some("wrong")).await, Some(401));
}

#[tokio::test]
async fn unreadable_static_rules_are_skipped() {
	if as_root() {
		return;
	}
	let dir = workdir("static");
	let rules = dir.join("rules.json");
	fs::write(&rules, "[]").unwrap();
	chmod(&rules, 0o000);
	let port = free_port();
	let rp = Rproxy::start(&dir, port, &[("RPROXY_STATIC_RULES", rules.to_str().unwrap())]);
	wait_for("the API", &rp, || async { api_status(port, None).await == Some(200) }).await;
	assert!(rp.log().contains(r#""part":"static_rules""#), "{}", rp.log());
}

#[tokio::test]
async fn a_busy_api_port_keeps_the_rules_running_and_is_retried() {
	let dir = workdir("busy");
	let port = free_port();
	let blocker = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
	let backend = tcp_backend("S:").await;
	let listen = free_port();
	let rules = dir.join("rules.json");
	fs::write(&rules, json!([{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": listen,
		"remote_addr": "127.0.0.1", "remote_port": backend.port()}]).to_string()).unwrap();
	let mut rp = Rproxy::start(&dir, port, &[("RPROXY_STATIC_RULES", rules.to_str().unwrap())]);

	wait_for("the static rule", &rp, || async {
		tokio::net::TcpStream::connect(("127.0.0.1", listen)).await.is_ok()
	})
	.await;
	assert!(rp.log().contains(r#""part":"api""#), "{}", rp.log());
	assert!(rp.child.try_wait().unwrap().is_none(), "exited: {}", rp.log());

	drop(blocker);
	wait_for("the API after the port is freed", &rp, || async { api_status(port, None).await == Some(200) }).await;
	let (_, v) = get_json(port, &format!("/rules/tcp/127.0.0.1/{listen}")).await;
	assert_eq!(v["state"], "running");
}

#[tokio::test]
async fn an_unreadable_api_certificate_is_retried() {
	if as_root() {
		return;
	}
	let dir = workdir("apitls");
	let pki = Pki::new("startup-api");
	let cert = pki.server("api", &["localhost"]);
	chmod(Path::new(&cert.key_file), 0o000);
	let port = free_port();
	let rp = Rproxy::start(&dir, port, &[("RPROXY_TLS_CERT", &cert.cert_file), ("RPROXY_TLS_KEY", &cert.key_file)]);
	wait_for("the degraded log line", &rp, || async { rp.log().contains(r#""part":"api_tls""#) }).await;
	assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err(), "listening without its certificate");

	chmod(Path::new(&cert.key_file), 0o600);
	wait_for("the TLS listener", &rp, || async { tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() }).await;

	// a file that is not a key is a mistake
	let not_pem = dir.join("key.pem");
	fs::write(&not_pem, "not a key").unwrap();
	let (ok, out) = Rproxy::start(&dir, free_port(), &[("RPROXY_TLS_CERT", &cert.cert_file), ("RPROXY_TLS_KEY", not_pem.to_str().unwrap())])
		.exited();
	assert!(!ok && out.contains("TLS"), "{out}");
}

async fn get_json(port: u16, path: &str) -> (u16, serde_json::Value) {
	let r = reqwest::get(format!("http://127.0.0.1:{port}{path}")).await.unwrap();
	(r.status().as_u16(), r.json().await.unwrap_or_default())
}
