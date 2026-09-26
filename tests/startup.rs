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
		("static rules path", vec![("RPROXY_STATIC_RULES", dir.join("missing.json").display().to_string())], "settings file"),
		("config path", vec![("RPROXY_CONFIG", dir.join("missing.yaml").display().to_string())], "settings file"),
		(
			"config and static rules together",
			vec![("RPROXY_CONFIG", "/a.yaml".into()), ("RPROXY_STATIC_RULES", "/b.json".into())],
			"not both",
		),
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
	wait_for("the degraded log line", &rp, || async { rp.log().contains(r#""part":"log""#) }).await;
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
	wait_for("the degraded log line", &rp, || async { rp.log().contains(r#""part":"tokens""#) }).await;

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
	wait_for("the degraded log line", &rp, || async { rp.log().contains(r#""part":"static_rules""#) }).await;
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
	// the rules start before the API; the log is written asynchronously
	wait_for("the degraded log line", &rp, || async { rp.log().contains(r#""part":"api""#) }).await;
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

/// GET over TLS to the control API: (status, DER of the certificate the server presented).
async fn https_get(pki: &Pki, port: u16, path: &str, token: &str) -> Option<(u16, Vec<u8>)> {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
	let mut tls = pki.connector(None).connect("localhost".try_into().unwrap(), tcp).await.ok()?;
	let served = tls.get_ref().1.peer_certificates()?.first()?.as_ref().to_vec();
	let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n");
	tls.write_all(req.as_bytes()).await.ok()?;
	let mut resp = Vec::new();
	let _ = tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut resp)).await;
	let status = String::from_utf8_lossy(&resp).split_whitespace().nth(1)?.parse().ok()?;
	Some((status, served))
}

#[tokio::test]
async fn sighup_reloads_tokens_and_the_api_certificate_and_keeps_them_on_bad_files() {
	let dir = workdir("reload");
	let pki = Pki::new("startup-reload");
	let (first, second) = (pki.server("api-1", &["localhost"]), pki.server("api-2", &["localhost"]));
	let (cert, key, tokens) = (dir.join("api.pem"), dir.join("api.key"), dir.join("tokens"));
	fs::copy(&first.cert_file, &cert).unwrap();
	fs::copy(&first.key_file, &key).unwrap();
	fs::write(&tokens, "old-token\n").unwrap();
	let port = free_port();
	let rp = Rproxy::start(
		&dir,
		port,
		&[
			("RPROXY_TLS_CERT", cert.to_str().unwrap()),
			("RPROXY_TLS_KEY", key.to_str().unwrap()),
			("RPROXY_TOKEN_FILE", tokens.to_str().unwrap()),
		],
	);
	let first_der = first.der().as_ref().to_vec();
	let second_der = second.der().as_ref().to_vec();

	// HTTPS with the first certificate and the old token
	wait_for("the HTTPS API", &rp, || async { https_get(&pki, port, "/rules", "old-token").await.map(|r| r.0) == Some(200) }).await;
	assert_eq!(https_get(&pki, port, "/rules", "old-token").await, Some((200, first_der.clone())));
	assert_eq!(https_get(&pki, port, "/rules", "new-token").await.map(|r| r.0), Some(401));

	// rotate the token and renew the certificate in place, then SIGHUP
	fs::write(&tokens, "new-token\n").unwrap();
	fs::copy(&second.cert_file, &cert).unwrap();
	fs::copy(&second.key_file, &key).unwrap();
	rp.hup();
	wait_for("the new token and certificate", &rp, || async {
		https_get(&pki, port, "/rules", "new-token").await == Some((200, second_der.clone()))
	})
	.await;
	assert_eq!(https_get(&pki, port, "/rules", "old-token").await.map(|r| r.0), Some(401), "the old token is gone");

	// broken files: the current token and certificate stay in effect
	fs::write(&tokens, "# no tokens\n").unwrap();
	fs::write(&cert, "not a certificate").unwrap();
	rp.hup();
	wait_for("the reload warnings", &rp, || async {
		let log = rp.log();
		log.contains(r#""event":"reload.tokens""#) && log.contains("keeping current tokens")
			&& log.contains(r#""event":"reload.tls""#) && log.contains("keeping current certificate")
	})
	.await;
	assert_eq!(https_get(&pki, port, "/rules", "new-token").await, Some((200, second_der)));
}

#[tokio::test]
async fn a_yaml_settings_file_starts_and_marks_unavailable_features_failed() {
	let dir = workdir("yaml");
	let backend = tcp_backend("Y:").await;
	let (plain, l7) = (free_port(), free_port());
	let cfg = dir.join("rproxy.yaml");
	fs::write(
		&cfg,
		format!(
			r#"
# comments are fine in YAML
version: 1
global:
  trusted_proxies: [10.0.0.0/8]
rules:
  - protocol: tcp
    listen_addr: 127.0.0.1
    listen_port: {plain}
    remote_addr: 127.0.0.1
    remote_port: {bp}
  - protocol: tcp
    listen_addr: 127.0.0.1
    listen_port: {l7}
    http:
      routes:
        - name: all
          match: PathPrefix(`/`)
          to: http://127.0.0.1:{bp}
          middlewares: [cs]
      middlewares:
        cs: {{crowdsec: {{}}}}
"#,
			bp = backend.port()
		),
	)
	.unwrap();
	let port = free_port();
	let rp = Rproxy::start(&dir, port, &[("RPROXY_CONFIG", cfg.to_str().unwrap())]);
	wait_for("the API", &rp, || async { api_status(port, None).await == Some(200) }).await;
	let (_, v) = get_json(port, &format!("/rules/tcp/127.0.0.1/{plain}")).await;
	assert_eq!((v["state"].as_str(), v["origin"].as_str()), (Some("running"), Some("static")), "{v}");
	let (_, v) = get_json(port, &format!("/rules/tcp/127.0.0.1/{l7}")).await;
	assert_eq!(v["state"], "failed", "{v}");
	assert!(v["error"].as_str().unwrap().contains("crowdsec"), "{v}");
	assert_eq!(v["http"]["routes"][0]["name"], "all", "the settings are kept and shown: {v}");
	wait_for("the ignored global setting", &rp, || async { rp.log().contains(r#""part":"global.trusted_proxies""#) }).await;
	let (_, caps) = get_json(port, "/capabilities").await;
	let kinds = caps["features"]["middlewares"].as_array().unwrap();
	assert!(kinds.contains(&serde_json::json!("respond")) && !kinds.contains(&serde_json::json!("crowdsec")), "{caps}");

	// an unknown version is a mistake
	fs::write(&cfg, "version: 9\n").unwrap();
	let (ok, out) = Rproxy::start(&dir, free_port(), &[("RPROXY_CONFIG", cfg.to_str().unwrap())]).exited();
	assert!(!ok && out.contains("version 9"), "{out}");
}

/// One HTTP/1.1 request over a Unix socket; returns the whole response.
async fn unix_get(socket: &Path, path: &str, token: Option<&str>) -> Option<String> {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let mut s = tokio::net::UnixStream::connect(socket).await.ok()?;
	let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
	s.write_all(format!("GET {path} HTTP/1.1\r\nHost: rproxy\r\n{auth}Connection: close\r\n\r\n").as_bytes()).await.ok()?;
	let mut out = String::new();
	s.read_to_string(&mut out).await.ok()?;
	Some(out)
}

#[tokio::test]
async fn the_api_on_a_unix_socket() {
	let dir = workdir("socket");
	let socket = dir.join("api.sock");
	fs::write(dir.join("tokens"), "sock-secret\n").unwrap();
	// a stale socket from an earlier run is replaced
	drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
	let rp = Rproxy::start(
		&dir,
		0,
		&[
			("RPROXY_API_SOCKET", socket.to_str().unwrap()),
			("RPROXY_API_SOCKET_MODE", "600"),
			("RPROXY_TOKEN_FILE", dir.join("tokens").to_str().unwrap()),
		],
	);
	wait_for("the socket", &rp, || async { unix_get(&socket, "/healthz", None).await.is_some_and(|r| r.ends_with("ok")) }).await;
	assert_eq!(fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
	let r = unix_get(&socket, "/rules", None).await.unwrap();
	assert!(r.starts_with("HTTP/1.1 401"), "tokens apply on the socket too: {r}");
	let r = unix_get(&socket, "/rules", Some("sock-secret")).await.unwrap();
	assert!(r.starts_with("HTTP/1.1 200") && r.ends_with("[]"), "{r}");
	assert!(!rp.log().contains(r#""event":"api.listening","addr""#), "--api-port 0 means no TCP listener:\n{}", rp.log());

	// SIGTERM removes the socket file
	// SAFETY: signalling our own child
	unsafe { libc::kill(rp.child.id() as i32, libc::SIGTERM) };
	let (ok, log) = rp.exited();
	assert!(ok, "{log}");
	assert!(!socket.exists(), "{log}");
}

#[tokio::test]
async fn unix_socket_mistakes_stop_the_startup() {
	let dir = workdir("socket-bad");
	fs::write(dir.join("plain"), "").unwrap();
	let plain = dir.join("plain");
	let missing = dir.join("nope/api.sock");
	for (env, want) in [
		(vec![], "give --api-socket"),
		(vec![("RPROXY_API_SOCKET", plain.to_str().unwrap())], "not a socket"),
		(vec![("RPROXY_API_SOCKET", missing.to_str().unwrap())], "does not exist"),
		(vec![("RPROXY_API_SOCKET", "s.sock"), ("RPROXY_API_SOCKET_MODE", "999")], "octal"),
		(vec![("RPROXY_API_SOCKET", "s.sock"), ("RPROXY_API_SOCKET_GROUP", "no-such-group-rproxy")], "no such group"),
	] {
		let (ok, log) = Rproxy::start(&dir, 0, &env).exited();
		assert!(!ok && log.contains(want), "{env:?}: {log}");
	}
}
