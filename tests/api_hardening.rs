//! Control API hardening (#167, docs/API.md): client certificates (mTLS) with
//! tokens bound to them, token expiry warnings, and locking out sources that
//! keep failing authentication (not over the Unix socket).

mod common;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rproxy_api::control::api::{router, AppState, Transport};
use rproxy_api::control::auth::Tokens;
use rproxy_api::control::hardening::{ApiTlsFiles, ClientAuth, ClientCertAcceptor, LockoutConfig, TokenExpiry};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::pki::{Issued, Pki};
use common::*;

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-hardening-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn sha(s: &str) -> String {
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Status of a raw HTTP/1.1 response; None when there is none.
fn status(resp: &[u8]) -> Option<u16> {
	let text = String::from_utf8_lossy(resp);
	text.starts_with("HTTP/1.1 ").then(|| text.split_whitespace().nth(1)?.parse().ok())?
}

/// GET over TLS, presenting `client` (if any): the status, or None when the
/// handshake or the request failed.
async fn https_get(pki: &Pki, addr: SocketAddr, client: Option<&Issued>, path: &str, token: Option<&str>) -> Option<u16> {
	let tcp = tokio::net::TcpStream::connect(addr).await.ok()?;
	let mut tls = pki.connector(client).connect("localhost".try_into().unwrap(), tcp).await.ok()?;
	let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
	let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Connection: close\r\n\r\n");
	tls.write_all(req.as_bytes()).await.ok()?;
	let mut resp = Vec::new();
	let _ = tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut resp)).await;
	status(&resp)
}

/// The control API over TLS with `files`, as main.rs serves it.
async fn serve_tls(tokens: Tokens, files: &ApiTlsFiles) -> SocketAddr {
	let h = harness().await;
	let app = router(Arc::new(AppState { registry: h.registry.clone(), tokens: Arc::new(tokens), reloader: None, reload_unix_only: true }));
	let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	listener.set_nonblocking(true).unwrap();
	let addr = listener.local_addr().unwrap();
	let server = axum_server::from_tcp(listener).unwrap().acceptor(ClientCertAcceptor::new(files.rustls().unwrap()));
	tokio::spawn(server.serve(app.into_make_service_with_connect_info::<SocketAddr>()));
	addr
}

fn mtls_tokens(dir: &Path) -> PathBuf {
	let file = dir.join("tokens.yaml");
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: ui, client_cert: ui.rproxy.internal, scopes: [rules:read]}}\n  - {{name: ctl, sha256: {}, client_cert: ctl.rproxy.internal, scopes: [admin]}}\n  - {{name: ci, sha256: {}, scopes: [rules:read]}}\n",
			sha("ctl-secret"),
			sha("ci-secret")
		),
	)
	.unwrap();
	file
}

#[tokio::test]
async fn client_certificates_authenticate_alone_or_bound_to_a_token() {
	let dir = workdir("mtls");
	let pki = Pki::new("hardening-mtls");
	let server = pki.server("api", &["localhost"]);
	let ui = pki.client_with_names("ui", "someone", &["ui.rproxy.internal"]);
	let ctl = pki.client("ctl", "ctl.rproxy.internal"); // no SAN: the CN is its name
	let stranger = pki.client("stranger", "stranger.example");
	let other_ca = Pki::new("hardening-mtls-other");
	let forged = other_ca.client_with_names("forged", "ui", &["ui.rproxy.internal"]);
	let file = mtls_tokens(&dir);

	// optional: certificates are checked when presented, tokens work without
	let optional = ApiTlsFiles {
		cert: server.cert_file.clone().into(),
		key: server.key_file.clone().into(),
		client_ca: Some(pki.ca_file.clone().into()),
		client_auth: ClientAuth::Optional,
	};
	let tokens = Tokens::from_file(file.clone()).unwrap().with_client_auth(ClientAuth::Optional).unwrap();
	let addr = serve_tls(tokens, &optional).await;
	assert_eq!(https_get(&pki, addr, Some(&ui), "/rules", None).await, Some(200), "the certificate alone");
	assert_eq!(https_get(&pki, addr, Some(&ui), "/metrics", None).await, Some(403), "with the token's scopes");
	assert_eq!(https_get(&pki, addr, Some(&stranger), "/rules", None).await, Some(401), "a name no token has");
	assert_eq!(https_get(&pki, addr, None, "/rules", None).await, Some(401));
	assert_eq!(https_get(&pki, addr, None, "/rules", Some("ci-secret")).await, Some(200), "a plain token without a certificate");
	assert_eq!(https_get(&pki, addr, Some(&ctl), "/metrics", Some("ctl-secret")).await, Some(200), "token + certificate");
	assert_eq!(https_get(&pki, addr, None, "/rules", Some("ctl-secret")).await, Some(401), "the bound token needs its certificate");
	assert_eq!(https_get(&pki, addr, Some(&ui), "/rules", Some("ctl-secret")).await, Some(401), "and not another one");
	assert_eq!(https_get(&pki, addr, Some(&forged), "/rules", None).await, None, "a certificate from another CA fails the handshake");

	// required: no certificate, no connection
	let required = ApiTlsFiles { client_auth: ClientAuth::Required, ..optional.clone() };
	let tokens = Tokens::from_file(file).unwrap().with_client_auth(ClientAuth::Required).unwrap();
	let addr = serve_tls(tokens, &required).await;
	assert_eq!(https_get(&pki, addr, None, "/rules", Some("ci-secret")).await, None);
	assert_eq!(https_get(&pki, addr, Some(&stranger), "/rules", Some("ci-secret")).await, Some(200));
	assert_eq!(https_get(&pki, addr, Some(&ui), "/rules", None).await, Some(200));
	fs::remove_dir_all(dir).unwrap();
}

/// Plain HTTP over the Unix socket (as rproxy serves it): the status.
async fn unix_get(socket: &Path, path: &str, token: &str) -> u16 {
	let mut s = tokio::net::UnixStream::connect(socket).await.unwrap();
	let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n");
	s.write_all(req.as_bytes()).await.unwrap();
	let mut resp = Vec::new();
	s.read_to_end(&mut resp).await.unwrap();
	status(&resp).unwrap()
}

#[tokio::test]
async fn failing_sources_are_locked_out_over_tcp_but_not_the_unix_socket() {
	let dir = workdir("lockout");
	let file = dir.join("tokens.yaml");
	fs::write(&file, format!("tokens:\n  - {{name: admin, sha256: {}, scopes: [admin]}}\n", sha("good"))).unwrap();
	let config = LockoutConfig { failures: 3, window: Duration::from_secs(60), duration: Duration::from_secs(2) };
	let tokens = Arc::new(Tokens::from_file(file).unwrap().with_lockout(config));
	let h = harness().await;
	let state = Arc::new(AppState { registry: h.registry.clone(), tokens: tokens.clone(), reloader: None, reload_unix_only: true });
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	let app = router(state.clone());
	tokio::spawn(async move { axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap() });
	let socket = dir.join("api.sock");
	let unix = tokio::net::UnixListener::bind(&socket).unwrap();
	let unix_app = router(state).layer(axum::Extension(Transport::UnixSocket));
	tokio::spawn(async move { axum::serve(unix, unix_app).await.unwrap() });

	let http = reqwest::Client::new();
	let get = |token: &'static str| http.get(format!("{base}/rules")).bearer_auth(token).send();
	// failures over the Unix socket are not counted
	for _ in 0..5 {
		assert_eq!(unix_get(&socket, "/rules", "bad").await, 401);
	}
	assert_eq!(get("good").await.unwrap().status(), 200);
	for _ in 0..3 {
		assert_eq!(get("bad").await.unwrap().status(), 401);
	}
	// locked out: refused before the token is looked at
	let r = get("good").await.unwrap();
	assert_eq!(r.status(), 429);
	let retry: u64 = r.headers()["retry-after"].to_str().unwrap().parse().unwrap();
	assert!((1..=2).contains(&retry), "{retry}");
	let body: serde_json::Value = r.json().await.unwrap();
	assert_eq!(body["code"], "locked_out", "{body}");
	// the Unix socket still works
	assert_eq!(unix_get(&socket, "/rules", "good").await, 200);
	let metrics = {
		let mut s = tokio::net::UnixStream::connect(&socket).await.unwrap();
		s.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer good\r\nConnection: close\r\n\r\n").await.unwrap();
		let mut resp = Vec::new();
		s.read_to_end(&mut resp).await.unwrap();
		String::from_utf8_lossy(&resp).into_owned()
	};
	assert!(metrics.contains("rproxy_api_lockouts_total 1\n"), "{metrics}");
	assert!(metrics.contains("rproxy_api_locked_sources 1\n"), "{metrics}");
	// /healthz is never locked
	assert_eq!(http.get(format!("{base}/healthz")).send().await.unwrap().status(), 200);
	// the time is up
	tokio::time::sleep(Duration::from_millis(2100)).await;
	assert_eq!(get("good").await.unwrap().status(), 200);
	assert_eq!(tokens.lockout().locked_sources(), 0);
	fs::remove_dir_all(dir).unwrap();
}

/// Owner's decision: on by default, 20 failures within a minute.
#[tokio::test]
async fn lockout_is_on_by_default() {
	let dir = workdir("default");
	let file = dir.join("tokens");
	fs::write(&file, "good\n").unwrap();
	let h = harness_with(Tokens::from_file(file).unwrap()).await;
	let get = |token: &'static str| h.http.get(format!("{}/rules", h.base)).bearer_auth(token).send();
	for _ in 0..19 {
		assert_eq!(get("bad").await.unwrap().status(), 401);
	}
	assert_eq!(get("good").await.unwrap().status(), 200);
	assert_eq!(get("bad").await.unwrap().status(), 401);
	assert_eq!(get("good").await.unwrap().status(), 429);
	fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn expiring_tokens_are_reported_and_exported() {
	logs::capture();
	let dir = workdir("expiry");
	let today = time::OffsetDateTime::now_utc().date();
	let soon = today + time::Duration::days(3);
	let later = today + time::Duration::days(300);
	let past = today - time::Duration::days(1);
	let file = dir.join("tokens.yaml");
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: hardening-soon, sha256: {}, scopes: [metrics:read], expires: {soon}}}\n  - {{name: hardening-later, sha256: {}, scopes: [admin], expires: {later}}}\n  - {{name: hardening-past, sha256: {}, scopes: [admin], expires: {past}}}\n",
			sha("soon"),
			sha("later"),
			sha("past")
		),
	)
	.unwrap();
	let tokens = Tokens::from_file(file).unwrap();
	let watch = TokenExpiry::new(14);
	assert_eq!(watch.check(&tokens.expiries()).len(), 2);
	let expiring = logs::wait_for("token.expiring", |v| v["event"] == "token.expiring" && v["token"] == "hardening-soon").await;
	assert_eq!((expiring["days_left"].as_i64(), expiring["level"].as_str()), (Some(3), Some("WARN")), "{expiring}");
	assert_eq!(expiring["expires"], soon.to_string());
	logs::wait_for("token.expired", |v| v["event"] == "token.expired" && v["token"] == "hardening-past").await;
	assert!(logs::lines(|v| v["token"] == "hardening-later").is_empty());
	assert!(watch.check(&tokens.expiries()).is_empty(), "once per change");

	let h = harness_with(tokens).await;
	let text = h.http.get(format!("{}/metrics", h.base)).bearer_auth("soon").send().await.unwrap().text().await.unwrap();
	let end_of_soon = (soon + time::Duration::days(1)).midnight().assume_utc().unix_timestamp();
	assert!(text.contains(&format!("rproxy_token_expiry_timestamp_seconds{{token=\"hardening-soon\"}} {end_of_soon}\n")), "{text}");
	assert!(text.contains("rproxy_api_lockouts_total 0\n"), "{text}");
	fs::remove_dir_all(dir).unwrap();
}

/// The real binary: a `client_cert` token needs client certificates turned
/// on, and with them the API answers to the certificate (main.rs's TLS).
#[tokio::test]
async fn the_binary_serves_client_certificates() {
	let dir = workdir("binary");
	let pki = Pki::new("hardening-binary");
	let server = pki.server("api", &["localhost"]);
	let ui = pki.client_with_names("ui", "ui", &["ui.rproxy.internal"]);
	let tokens = mtls_tokens(&dir);
	let base_env = [
		("RPROXY_TOKEN_FILE", tokens.to_str().unwrap().to_string()),
		("RPROXY_TLS_CERT", server.cert_file.clone()),
		("RPROXY_TLS_KEY", server.key_file.clone()),
	];
	let start = |extra: &[(&str, String)], port: u16| -> (Child, PathBuf) {
		let out = dir.join(format!("out-{port}.log"));
		let file = fs::File::create(&out).unwrap();
		let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(&dir)
			.env_clear()
			.env("RPROXY_API_PORT", port.to_string())
			.envs(base_env.iter().map(|(k, v)| (*k, v.as_str())))
			.envs(extra.iter().map(|(k, v)| (*k, v.as_str())))
			.stdout(file.try_clone().unwrap())
			.stderr(file)
			.spawn()
			.unwrap();
		(child, out)
	};

	// client_cert without --tls-client-auth: a mistake that stops the startup
	let (mut child, out) = start(&[], free_port());
	let deadline = Instant::now() + Duration::from_secs(10);
	let code = loop {
		if let Some(status) = child.try_wait().unwrap() {
			break status;
		}
		assert!(Instant::now() < deadline, "still running");
		tokio::time::sleep(Duration::from_millis(50)).await;
	};
	let log = fs::read_to_string(&out).unwrap_or_default();
	assert!(!code.success() && log.contains("token ui: client_cert needs --tls-client-auth"), "{log}");

	// with client certificates required
	let port = free_port();
	let (mut child, out) = start(
		&[("RPROXY_TLS_CLIENT_AUTH", "required".into()), ("RPROXY_TLS_CLIENT_CA", pki.ca_file.clone())],
		port,
	);
	let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
	let deadline = Instant::now() + Duration::from_secs(15);
	while https_get(&pki, addr, Some(&ui), "/rules", None).await != Some(200) {
		assert!(Instant::now() < deadline, "{}", fs::read_to_string(&out).unwrap_or_default());
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
	assert_eq!(https_get(&pki, addr, None, "/rules", Some("ci-secret")).await, None, "no certificate, no connection");
	let _ = child.kill();
	let _ = child.wait();
	fs::remove_dir_all(dir).unwrap();
}
