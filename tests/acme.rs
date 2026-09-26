//! ACME end to end against Pebble (Let's Encrypt's test CA): rproxy answers
//! tls-alpn-01 on its TLS listener and http-01 on an `http` rule, installs the
//! certificates, stores them, and loads them again after a restart.
//!
//! Needs the `pebble` and `pebble-challtestsrv` binaries
//! (<https://github.com/letsencrypt/pebble/releases>) named by
//! `RPROXY_TEST_PEBBLE` and `RPROXY_TEST_CHALLTESTSRV`; skipped without them.
//! CI runs it in the `acme` job.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::pki::Pki;
use common::*;

struct Process(Child);

impl Drop for Process {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

fn spawn(cmd: &mut Command, log: &Path) -> Process {
	Process(cmd.stdout(fs::File::create(log).unwrap()).stderr(Stdio::from(fs::File::create(log.with_extension("err")).unwrap())).spawn().unwrap())
}

async fn wait_until<F, Fut>(what: &str, secs: u64, logs: &[&Path], mut check: F)
where
	F: FnMut() -> Fut,
	Fut: std::future::Future<Output = bool>,
{
	let deadline = Instant::now() + Duration::from_secs(secs);
	while !check().await {
		if Instant::now() > deadline {
			let text: String = logs.iter().map(|p| fs::read_to_string(p).unwrap_or_default()).collect::<Vec<_>>().join("\n----\n");
			panic!("timed out waiting for {what}; logs:\n{text}");
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

async fn get_json(port: u16, path: &str) -> Option<Value> {
	let r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}{path}")).timeout(Duration::from_secs(2)).send().await.ok()?;
	r.json().await.ok()
}

/// The certificate rproxy presents for `name` on `port`, without verifying it.
async fn served_certificate(port: u16, name: &str) -> Vec<u8> {
	let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_safe_default_protocol_versions()
		.unwrap()
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(AcceptAll))
		.with_no_client_auth();
	config.alpn_protocols = vec![];
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
		.connect(ServerName::try_from(name.to_string()).unwrap(), tcp)
		.await
		.unwrap();
	let (_, conn) = tls.get_ref();
	conn.peer_certificates().unwrap()[0].as_ref().to_vec()
}

fn issuer_and_names(der: &[u8]) -> (String, Vec<String>) {
	let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
	let names = rproxy_api::tlsconf::cert_names(&rustls::pki_types::CertificateDer::from(der.to_vec()));
	(cert.issuer().to_string(), names)
}

#[derive(Debug)]
struct AcceptAll;

impl rustls::client::danger::ServerCertVerifier for AcceptAll {
	fn verify_server_cert(
		&self,
		_: &rustls::pki_types::CertificateDer<'_>,
		_: &[rustls::pki_types::CertificateDer<'_>],
		_: &ServerName<'_>,
		_: &[u8],
		_: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		_: &[u8],
		_: &rustls::pki_types::CertificateDer<'_>,
		_: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}

	fn verify_tls13_signature(
		&self,
		_: &[u8],
		_: &rustls::pki_types::CertificateDer<'_>,
		_: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
	}
}

fn start_rproxy(dir: &Path, api_port: u16, cfg: &Path, tag: &str) -> (Process, PathBuf) {
	let log = dir.join(format!("rproxy-{tag}.log"));
	let p = spawn(
		Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(dir)
			.env_clear()
			.env("RPROXY_API_PORT", api_port.to_string())
			.env("RPROXY_LOG_LEVEL", "info,rproxy_api=debug")
			.env("RPROXY_CONFIG", cfg),
		&log,
	);
	(p, log)
}

#[tokio::test]
async fn certificates_from_pebble_by_tls_alpn_01_and_http_01() {
	let (Ok(pebble), Ok(challtestsrv)) = (std::env::var("RPROXY_TEST_PEBBLE"), std::env::var("RPROXY_TEST_CHALLTESTSRV")) else {
		eprintln!("skipped: set RPROXY_TEST_PEBBLE and RPROXY_TEST_CHALLTESTSRV to run the ACME test");
		return;
	};
	let dir = std::env::temp_dir().join(format!("rproxy-acme-e2e-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();

	// Pebble's own HTTPS certificate, from a CA rproxy is told about (ca_file)
	let pki = Pki::new("pebble");
	let server = pki.server("pebble", &["127.0.0.1", "localhost"]);
	let (dir_port, mgmt_port, dns_port, cts_mgmt) = (free_port(), free_port(), free_port(), free_port());
	let (tls_port, http_port, api_port) = (free_port(), free_port(), free_port());
	let backend = tcp_backend("B:").await;
	let pebble_cfg = dir.join("pebble.json");
	fs::write(
		&pebble_cfg,
		serde_json::json!({"pebble": {
			"listenAddress": format!("127.0.0.1:{dir_port}"),
			"managementListenAddress": format!("127.0.0.1:{mgmt_port}"),
			"certificate": server.cert_file, "privateKey": server.key_file,
			"httpPort": http_port, "tlsPort": tls_port,
			"ocspResponderURL": "", "externalAccountBindingRequired": false,
		}})
		.to_string(),
	)
	.unwrap();
	let _dns = spawn(
		Command::new(&challtestsrv).args([
			"-defaultIPv4", "127.0.0.1", "-defaultIPv6", "",
			"-dnsserver", &format!("127.0.0.1:{dns_port}"),
			"-management", &format!("127.0.0.1:{cts_mgmt}"),
			"-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "",
		]),
		&dir.join("challtestsrv.log"),
	);
	let pebble_log = dir.join("pebble.log");
	let _pebble = spawn(
		Command::new(&pebble)
			.args(["-config", pebble_cfg.to_str().unwrap(), "-dnsserver", &format!("127.0.0.1:{dns_port}")])
			.env("PEBBLE_VA_NOSLEEP", "1")
			.env("PEBBLE_WFE_NONCEREJECT", "0")
			.env("PEBBLE_AUTHZREUSE", "0"),
		&pebble_log,
	);
	wait_until("pebble", 20, &[&pebble_log], || async move { TcpStream::connect(("127.0.0.1", dir_port)).await.is_ok() }).await;

	let storage = dir.join("acme");
	let cfg = dir.join("rproxy.yaml");
	fs::write(
		&cfg,
		format!(
			r#"
version: 1
global:
  acme:
    storage: {storage}
    resolvers:
      alpn: {{email: admin@example.com, directory: "https://127.0.0.1:{dir_port}/dir", challenge: tls-alpn-01, ca_file: {ca}}}
      web: {{email: admin@example.com, directory: "https://127.0.0.1:{dir_port}/dir", challenge: http-01, ca_file: {ca}}}
rules:
  # TLS on the port Pebble validates tls-alpn-01 on; L4 to a backend
  - protocol: tcp
    listen_addr: 127.0.0.1
    listen_port: {tls_port}
    remote_addr: 127.0.0.1
    remote_port: {bp}
    tls:
      mode: terminate
      certificates:
        - {{acme: alpn, domains: [alpn.rproxy.test]}}
        - {{acme: web, domains: [web.rproxy.test, www.web.rproxy.test]}}
  # plain HTTP on the port Pebble validates http-01 on; everything else goes to HTTPS
  - protocol: tcp
    listen_addr: 127.0.0.1
    listen_port: {http_port}
    http:
      routes:
        - {{name: to-https, match: "PathPrefix(`/`)", middlewares: [https]}}
      middlewares:
        https: {{redirect_scheme: {{scheme: https, permanent: true}}}}
"#,
			storage = storage.display(),
			ca = pki.ca_file,
			bp = backend.port(),
		),
	)
	.unwrap();

	let (rp, log) = start_rproxy(&dir, api_port, &cfg, "first");
	let logs = [log.as_path(), pebble_log.as_path()];
	let rule = format!("/rules/tcp/127.0.0.1/{tls_port}");
	wait_until("both certificates", 90, &logs, || {
		let rule = rule.clone();
		async move {
			get_json(api_port, &rule).await.is_some_and(|v| {
				let acme = v["acme"].as_array().cloned().unwrap_or_default();
				acme.len() == 2 && acme.iter().all(|c| c["state"] == "valid")
			})
		}
	})
	.await;
	let v = get_json(api_port, &rule).await.unwrap();
	assert_eq!(v["state"], "running", "{v}");
	assert!(v["acme"][0]["not_after"].as_u64().unwrap() > 0, "{v}");

	// the listener serves what Pebble issued, chosen by SNI
	let (issuer, names) = issuer_and_names(&served_certificate(tls_port, "alpn.rproxy.test").await);
	assert!(issuer.contains("Pebble"), "{issuer}");
	assert_eq!(names, ["alpn.rproxy.test"]);
	let (issuer, names) = issuer_and_names(&served_certificate(tls_port, "www.web.rproxy.test").await);
	assert!(issuer.contains("Pebble"), "{issuer}");
	assert_eq!(names.len(), 2, "{names:?}");
	// and still forwards: TLS → backend
	let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_safe_default_protocol_versions()
		.unwrap()
		.dangerous()
		.with_custom_certificate_verifier(Arc::new(AcceptAll))
		.with_no_client_auth();
	config.alpn_protocols = vec![];
	let tcp = TcpStream::connect(("127.0.0.1", tls_port)).await.unwrap();
	let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
		.connect(ServerName::try_from("alpn.rproxy.test").unwrap(), tcp)
		.await
		.unwrap();
	tls.write_all(b"ping").await.unwrap();
	let mut buf = [0u8; 6];
	tls.read_exact(&mut buf).await.unwrap();
	assert_eq!(&buf, b"B:ping");

	// the redirect still applies to everything but the challenges
	let r = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap()
		.get(format!("http://127.0.0.1:{http_port}/x"))
		.header("host", "web.rproxy.test")
		.send()
		.await
		.unwrap();
	assert_eq!(r.status(), 301);

	// stored for rproxy only, and used again after a restart without asking the CA
	let text = fs::read_to_string(&log).unwrap();
	assert!(text.contains(r#""event":"acme.issue""#), "{text}");
	let mut stored = 0;
	for entry in walk(&storage) {
		let mode = fs::metadata(&entry).unwrap().permissions().mode() & 0o777;
		if entry.is_dir() {
			assert_eq!(mode, 0o700, "{}", entry.display());
		} else {
			assert_eq!(mode, 0o600, "{}", entry.display());
			stored += 1;
		}
	}
	assert_eq!(stored, 2 + 2 * 2, "two accounts, two certificates with keys");
	drop(rp);
	let (_rp, log) = start_rproxy(&dir, api_port, &cfg, "second");
	wait_until("the stored certificates", 20, &[log.as_path()], || {
		let rule = rule.clone();
		async move {
			get_json(api_port, &rule).await.is_some_and(|v| v["acme"].as_array().is_some_and(|a| a.iter().all(|c| c["state"] == "valid")))
		}
	})
	.await;
	let text = fs::read_to_string(&log).unwrap();
	assert!(text.contains(r#""event":"acme.load""#) && !text.contains(r#""event":"acme.issue""#), "{text}");
	let _ = fs::remove_dir_all(&dir);
}

fn walk(dir: &Path) -> Vec<PathBuf> {
	let mut out = vec![];
	for e in fs::read_dir(dir).unwrap() {
		let p = e.unwrap().path();
		if p.is_dir() {
			out.extend(walk(&p));
		}
		out.push(p);
	}
	out
}
