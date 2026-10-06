//! ACME (#208). The API's guards run everywhere: `acme:write`, the names'
//! allowlists, no secret in any answer, the challenge answers of `http` and
//! `terminate` rules. Obtaining certificates for real needs Pebble (the ACME
//! test CA) and PowerDNS: `issues_certificates_from_pebble` runs when
//! RPROXY_TEST_PEBBLE, RPROXY_TEST_PDNS, RPROXY_TEST_PDNS_SCHEMA and
//! RPROXY_TEST_SQLITE3 name them (CI: the `acme` job; docs/TESTING.md), and
//! fails without them when RPROXY_TEST_REQUIRE_ACME=1.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use common::*;
use rproxy_api::control::auth::Tokens;

const PDNS_KEY: &str = "pdns-api-key-SECRET-1d9f";
const RELAY_SECRET: &str = "relay-token-SECRET-77ab";

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-acme-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn hex(t: &str) -> String {
	Sha256::digest(t.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Accepts any server certificate and keeps the leaf.
#[derive(Debug, Default)]
struct Capture(Mutex<Option<Vec<u8>>>);

impl ServerCertVerifier for Capture {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		_: &[CertificateDer<'_>],
		_: &ServerName<'_>,
		_: &[u8],
		_: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		*self.0.lock().unwrap() = Some(end_entity.to_vec());
		Ok(ServerCertVerified::assertion())
	}
	fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
		Ok(HandshakeSignatureValid::assertion())
	}
	fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
		Ok(HandshakeSignatureValid::assertion())
	}
	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
	}
}

/// The leaf certificate a TLS server on `port` sends for `name` (and the ALPN agreed).
async fn served_cert(port: u16, name: &str, alpn: &[&str]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
	let capture = Arc::new(Capture::default());
	let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_safe_default_protocol_versions()
		.unwrap()
		.dangerous()
		.with_custom_certificate_verifier(capture.clone())
		.with_no_client_auth();
	config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
	let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
	let tls = tokio_rustls::TlsConnector::from(Arc::new(config));
	let stream = tokio::time::timeout(Duration::from_secs(5), tls.connect(ServerName::try_from(name.to_string()).unwrap(), tcp)).await.ok()?.ok()?;
	let alpn = stream.get_ref().1.alpn_protocol().map(|a| a.to_vec());
	let leaf = capture.0.lock().unwrap().clone()?;
	Some((leaf, alpn))
}

fn issuer_cn(der: &[u8]) -> String {
	let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
	cert.issuer().to_string()
}

/// `global.acme` (without the `acme:` line, not indented); `extra` is added at the end.
fn acme_settings(dir: &Path, directory: &str, extra: &str) -> String {
	fs::write(dir.join("pdns.key"), format!("{PDNS_KEY}\n")).unwrap();
	fs::write(dir.join("relay.token"), format!("{RELAY_SECRET}\n")).unwrap();
	format!(
		r#"storage: {storage}
accounts:
  test:
    directory: '{directory}'
    contact: ['mailto:admin@example.test']
    allowed_names: ['**.example.test', example.test]
dns_providers:
  pdns:
    type: powerdns
    api_url: 'http://127.0.0.1:1'
    api_key_file: {dir}/pdns.key
    allowed_names: ['**.example.test', example.test]
  relay:
    type: http
    add: {{url: 'http://127.0.0.1:1/present', headers: {{Authorization: 'Bearer {{secret}}'}}, body: '{{"fqdn":"{{fqdn}}","zone":"{{zone}}","value":"{{value}}"}}'}}
    remove: {{url: 'http://127.0.0.1:1/cleanup', headers: {{Authorization: 'Bearer {{secret}}'}}, body: '{{"fqdn":"{{fqdn}}","zone":"{{zone}}","value":"{{value}}"}}'}}
    secret_file: {dir}/relay.token
    allowed_names: [rest.example.test]
resolvers:
  http: {{account: test, challenge: http-01}}
  alpn: {{account: test, challenge: tls-alpn-01}}
  dns: {{account: test, challenge: dns-01, dns_provider: pdns}}
  rest: {{account: test, challenge: dns-01, dns_provider: relay}}
{extra}"#,
		storage = dir.join("acme").display(),
		dir = dir.display(),
	)
}

/// The API's guards, in process (no CA is reached).
#[tokio::test]
async fn the_api_guards_acme() {
	let dir = workdir("api");
	let tokens_file = dir.join("tokens.yaml");
	fs::write(
		&tokens_file,
		format!(
			"tokens:\n  - {{name: plain, sha256: {}, scopes: [rules:read, rules:write]}}\n  - {{name: acme, sha256: {}, scopes: [rules:read, rules:write, acme:write]}}\n",
			hex("plain-token"),
			hex("acme-token")
		),
	)
	.unwrap();
	let h = harness_with(Tokens::from_file(tokens_file).unwrap()).await;
	let yaml = acme_settings(&dir, "https://127.0.0.1:1/directory", "");
	let global: rproxy_api::acme::config::AcmeGlobal = rproxy_api::config::from_yaml(&yaml).unwrap();
	let acme = rproxy_api::acme::Acme::new(&global).unwrap();
	h.registry.set_acme(acme.clone());

	let post = |token: &'static str, body: Value| {
		let (http, base) = (h.http.clone(), h.base.clone());
		async move {
			let r = http.post(format!("{base}/rules")).bearer_auth(token).json(&body).send().await.unwrap();
			let status = r.status();
			(status, r.json::<Value>().await.unwrap_or(Value::Null))
		}
	};
	let backend = tcp_backend("b:").await;
	let port = free_port();
	let mut rule = rule("tcp", port, backend);
	rule["tls"] = json!({"mode": "terminate", "certificates": [{"acme": "alpn", "domains": ["www.example.test"]}]});

	// acme:write is needed besides rules:write
	let (status, v) = post("plain-token", rule.clone()).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("acme:write"), "{v}");

	// names outside the allowlists, wildcards without dns-01, unknown resolvers, udp
	for (certs, want) in [
		(json!([{"acme": "alpn", "domains": ["www.evil.example"]}]), "not in allowed_names of account"),
		(json!([{"acme": "rest", "domains": ["other.example.test"]}]), "not in allowed_names of dns provider"),
		(json!([{"acme": "alpn", "domains": ["*.example.test"]}]), "needs a resolver with challenge dns-01"),
		(json!([{"acme": "nope", "domains": ["www.example.test"]}]), "not defined"),
		(json!([{"acme": "alpn", "domains": []}]), "domain"),
	] {
		let mut r = rule.clone();
		r["tls"]["certificates"] = certs.clone();
		let (status, v) = post("acme-token", r).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{certs}: {v}");
		assert!(v["error"].as_str().unwrap().contains(want), "{certs}: {v}");
	}
	let mut udp = rule.clone();
	udp["protocol"] = json!("udp");
	let (status, v) = post("acme-token", udp).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");

	// a valid rule serves a self-signed stand-in until the certificate is issued
	let (status, v) = post("acme-token", rule.clone()).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["acme"][0]["state"], "pending", "{v}");
	assert_eq!(v["tls"]["certificates"][0], json!({"acme": "alpn", "domains": ["www.example.test"]}));
	let (leaf, _) = served_cert(port, "www.example.test", &[]).await.unwrap();
	assert!(issuer_cn(&leaf).contains("rproxy ACME placeholder"), "{}", issuer_cn(&leaf));

	// TLS-ALPN-01: a ClientHello offering only acme-tls/1 for a name being validated
	// gets the challenge certificate (RFC 8737), with the acmeIdentifier extension
	let mut answers = rproxy_api::acme::challenge::Answers::default();
	answers.add_tls_alpn("www.example.test", &[7; 32]).unwrap();
	let (leaf, alpn) = served_cert(port, "www.example.test", &["acme-tls/1"]).await.unwrap();
	assert_eq!(alpn.as_deref(), Some(&b"acme-tls/1"[..]));
	let (_, cert) = x509_parser::parse_x509_certificate(&leaf).unwrap();
	let ext = cert.extensions().iter().find(|e| e.oid.to_id_string() == "1.3.6.1.5.5.7.1.31").expect("acmeIdentifier");
	assert!(ext.critical && ext.value.ends_with(&[7; 32]));
	let (leaf, _) = served_cert(port, "www.example.test", &["h2", "acme-tls/1"]).await.unwrap();
	assert!(issuer_cn(&leaf).contains("placeholder"), "other clients get the rule's certificate");
	drop(answers);
	let (leaf, _) = served_cert(port, "www.example.test", &["acme-tls/1"]).await.unwrap();
	assert!(issuer_cn(&leaf).contains("placeholder"), "after the order the answer is gone");

	// HTTP-01: http rules answer before routes and middlewares (here a redirect to HTTPS)
	let http_port = free_port();
	let http_rule = json!({
		"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": http_port,
		"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "middlewares": ["https"]}],
			"middlewares": {"https": {"redirect_scheme": {"scheme": "https"}}}}
	});
	let (status, v) = post("plain-token", http_rule).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let mut answers = rproxy_api::acme::challenge::Answers::default();
	answers.add_http("tok-api-test", "tok-api-test.thumbprint");
	let get = |path: &str| {
		let url = format!("http://127.0.0.1:{http_port}{path}");
		async move {
			let r = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap().get(url).send().await.unwrap();
			(r.status(), r.text().await.unwrap())
		}
	};
	assert_eq!(get("/.well-known/acme-challenge/tok-api-test").await, (StatusCode::OK, "tok-api-test.thumbprint".to_string()));
	assert_eq!(get("/.well-known/acme-challenge/other").await.0, StatusCode::FOUND, "unknown tokens go through the routes");
	drop(answers);
	assert_eq!(get("/.well-known/acme-challenge/tok-api-test").await.0, StatusCode::FOUND);

	// GET /acme: names and states, never a secret or where it is kept
	let r = h.http.get(format!("{}/acme", h.base)).bearer_auth("plain-token").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let text = r.text().await.unwrap();
	let v: Value = serde_json::from_str(&text).unwrap();
	assert_eq!(v["certificates"][0]["domains"], json!(["www.example.test"]));
	assert_eq!(v["dns_providers"].as_array().unwrap().len(), 2);
	for secret in [PDNS_KEY, RELAY_SECRET, "pdns.key", "relay.token", "key_file", "secret_file"] {
		assert!(!text.contains(secret), "{secret} in GET /acme: {text}");
	}
	let rules = h.http.get(format!("{}/rules", h.base)).bearer_auth("plain-token").send().await.unwrap().text().await.unwrap();
	assert!(!rules.contains(PDNS_KEY) && !rules.contains(RELAY_SECRET), "{rules}");

	// the strong operations: acme:write, and only over the Unix socket by default
	let renew = json!({"resolver": "alpn", "domains": ["www.example.test"]});
	for (token, want) in [("plain-token", "acme:write"), ("acme-token", "Unix socket")] {
		let r = h.http.post(format!("{}/acme/renew", h.base)).bearer_auth(token).json(&renew).send().await.unwrap();
		assert_eq!(r.status(), StatusCode::FORBIDDEN);
		assert!(r.text().await.unwrap().contains(want));
		let r = h.http.post(format!("{}/acme/accounts/test/deactivate", h.base)).bearer_auth(token).send().await.unwrap();
		assert_eq!(r.status(), StatusCode::FORBIDDEN);
	}
	h.delete(&format!("tcp/127.0.0.1/{port}")).await;
	let _ = fs::remove_dir_all(&dir);
}

// ---- Pebble and PowerDNS ----

struct Proc(Child, PathBuf);

impl Drop for Proc {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

impl Proc {
	fn log(&self) -> String {
		fs::read_to_string(&self.1).unwrap_or_default()
	}
}

fn spawn(name: &'static str, dir: &Path, cmd: &str, args: &[&str], env: &[(&str, &str)]) -> Proc {
	let out = dir.join(format!("{name}.log"));
	let child = Command::new(cmd)
		.args(args)
		.envs(env.iter().copied())
		.current_dir(dir)
		.stdout(fs::File::create(&out).unwrap())
		.stderr(fs::File::create(dir.join(format!("{name}.err"))).unwrap())
		.spawn()
		.unwrap_or_else(|e| panic!("{cmd}: {e}"));
	Proc(child, out)
}

async fn wait_until<F, Fut>(what: &str, secs: u64, logs: &dyn Fn() -> String, mut check: F)
where
	F: FnMut() -> Fut,
	Fut: std::future::Future<Output = bool>,
{
	let deadline = Instant::now() + Duration::from_secs(secs);
	while !check().await {
		assert!(Instant::now() < deadline, "timed out waiting for {what}\n{}", logs());
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
}

struct Pdns {
	_proc: Proc,
	api: String,
	dns: u16,
}

impl Pdns {
	async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (StatusCode, String) {
		let mut req = reqwest::Client::new().request(method, format!("{}/api/v1/servers/localhost{path}", self.api)).header("X-API-Key", PDNS_KEY);
		if let Some(b) = body {
			req = req.json(&b);
		}
		let r = req.send().await.unwrap();
		(r.status(), r.text().await.unwrap())
	}

	/// TXT records of a zone, as "name value".
	async fn txt(&self, zone: &str) -> Vec<String> {
		let (_, body) = self.call(reqwest::Method::GET, &format!("/zones/{zone}."), None).await;
		let v: Value = serde_json::from_str(&body).unwrap_or_default();
		let mut out = vec![];
		for rr in v["rrsets"].as_array().into_iter().flatten().filter(|r| r["type"] == "TXT") {
			for rec in rr["records"].as_array().into_iter().flatten() {
				out.push(format!("{} {}", rr["name"].as_str().unwrap_or(""), rec["content"].as_str().unwrap_or("")));
			}
		}
		out
	}
}

async fn start_pdns(dir: &Path, pdns: &str, schema: &str, sqlite3: &str) -> Pdns {
	let db = dir.join("pdns.sqlite3");
	let sql = fs::read(schema).unwrap();
	let mut child = Command::new(sqlite3).arg(&db).stdin(Stdio::piped()).spawn().unwrap();
	std::io::Write::write_all(child.stdin.as_mut().unwrap(), &sql).unwrap();
	drop(child.stdin.take());
	assert!(child.wait().unwrap().success());
	let dns = free_udp_port();
	let web = free_port();
	let conf = format!(
		"launch=gsqlite3\ngsqlite3-database={}\nlocal-address=127.0.0.1\nlocal-port={dns}\napi=yes\napi-key={PDNS_KEY}\nwebserver=yes\nwebserver-address=127.0.0.1\nwebserver-port={web}\nwebserver-allow-from=127.0.0.0/8\nsocket-dir={}\nguardian=no\ndaemon=no\ndisable-syslog=yes\nloglevel=5\nzone-cache-refresh-interval=0\n",
		db.display(),
		dir.display()
	);
	fs::write(dir.join("pdns.conf"), conf).unwrap();
	let config_dir = format!("--config-dir={}", dir.display());
	let proc = spawn("pdns", dir, pdns, &[&config_dir], &[]);
	let p = Pdns { _proc: proc, api: format!("http://127.0.0.1:{web}"), dns };
	let log = || fs::read_to_string(dir.join("pdns.err")).unwrap_or_default();
	wait_until("PowerDNS", 20, &log, || async {
		reqwest::Client::new().get(format!("{}/api/v1/servers", p.api)).header("X-API-Key", PDNS_KEY).send().await.is_ok_and(|r| r.status().is_success())
	})
	.await;
	let a = |name: &str| json!({"name": name, "type": "A", "ttl": 60, "changetype": "REPLACE", "records": [{"content": "127.0.0.1", "disabled": false}]});
	let zone = |name: &str, rrsets: Vec<Value>| json!({"name": name, "kind": "Native", "nameservers": [format!("ns.{name}")], "rrsets": rrsets});
	let cname = json!({"name": "_acme-challenge.deleg.example.test.", "type": "CNAME", "ttl": 60, "records": [{"content": "deleg.challenges.test.", "disabled": false}]});
	for z in [zone("example.test.", vec![a("example.test."), a("*.example.test."), cname]), zone("challenges.test.", vec![])] {
		let (status, body) = p.call(reqwest::Method::POST, "/zones", Some(z)).await;
		assert!(status.is_success(), "PowerDNS zone: {status} {body}");
	}
	p
}

/// A REST relay for the `http` DNS provider: checks the token, keeps calls,
/// and writes the TXT record through PowerDNS's API.
async fn start_relay(pdns_api: String) -> (u16, Arc<Mutex<Vec<String>>>) {
	let calls: Arc<Mutex<Vec<String>>> = Arc::default();
	let values: Arc<Mutex<std::collections::HashMap<String, Vec<String>>>> = Arc::default();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	let state = (calls.clone(), values, pdns_api);
	let app = axum::Router::new().route(
		"/{op}",
		axum::routing::post(move |axum::extract::Path(op): axum::extract::Path<String>, headers: axum::http::HeaderMap, body: String| {
			let (calls, values, api) = state.clone();
			async move {
				if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {RELAY_SECRET}")) {
					return axum::http::StatusCode::UNAUTHORIZED;
				}
				let v: Value = serde_json::from_str(&body).unwrap_or_default();
				let (fqdn, value) = (v["fqdn"].as_str().unwrap_or("").to_string(), v["value"].as_str().unwrap_or("").to_string());
				calls.lock().unwrap().push(format!("{op} {fqdn} {value}"));
				let records: Vec<String> = {
					let mut all = values.lock().unwrap();
					let list = all.entry(fqdn.clone()).or_default();
					if op == "present" {
						list.push(value);
					} else {
						list.retain(|x| *x != value);
					}
					list.clone()
				};
				let zone = v["zone"].as_str().unwrap_or("").to_string();
				let rrset = if records.is_empty() {
					json!({"name": format!("{fqdn}."), "type": "TXT", "changetype": "DELETE"})
				} else {
					json!({"name": format!("{fqdn}."), "type": "TXT", "ttl": 60, "changetype": "REPLACE",
						"records": records.iter().map(|r| json!({"content": format!("\"{r}\""), "disabled": false})).collect::<Vec<_>>()})
				};
				let r = reqwest::Client::new()
					.patch(format!("{api}/api/v1/servers/localhost/zones/{zone}."))
					.header("X-API-Key", PDNS_KEY)
					.json(&json!({"rrsets": [rrset]}))
					.send()
					.await;
				match r {
					Ok(r) if r.status().is_success() => axum::http::StatusCode::NO_CONTENT,
					_ => axum::http::StatusCode::BAD_GATEWAY,
				}
			}
		}),
	);
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(port, calls)
}

/// Pebble with its own HTTPS certificate (the package ships none).
fn start_pebble(dir: &Path, pebble: &str, dns: u16, http_port: u16, tls_port: u16) -> (Proc, String, PathBuf) {
	let ca = rcgen::KeyPair::generate().unwrap();
	let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
	ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
	ca_params.distinguished_name.push(rcgen::DnType::CommonName, "pebble WFE test CA");
	let ca_cert = ca_params.self_signed(&ca).unwrap();
	let key = rcgen::KeyPair::generate().unwrap();
	let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
	let cert = params.signed_by(&key, &rcgen::Issuer::from_ca_cert_der(ca_cert.der(), &ca).unwrap()).unwrap();
	fs::write(dir.join("wfe.pem"), cert.pem()).unwrap();
	fs::write(dir.join("wfe.key"), key.serialize_pem()).unwrap();
	let ca_file = dir.join("wfe-ca.pem");
	fs::write(&ca_file, ca_cert.pem()).unwrap();
	let wfe = free_port();
	let mgmt = free_port();
	let config = json!({"pebble": {
		"listenAddress": format!("127.0.0.1:{wfe}"),
		"managementListenAddress": format!("127.0.0.1:{mgmt}"),
		"certificate": dir.join("wfe.pem"),
		"privateKey": dir.join("wfe.key"),
		"httpPort": http_port,
		"tlsPort": tls_port,
		"ocspResponderURL": "",
		"externalAccountBindingRequired": false,
		"retryAfter": {"authz": 1, "order": 1},
	}});
	fs::write(dir.join("pebble.json"), config.to_string()).unwrap();
	let dns = format!("127.0.0.1:{dns}");
	let config_path = dir.join("pebble.json").display().to_string();
	let proc = spawn(
		"pebble",
		dir,
		pebble,
		&["-config", &config_path, "-dnsserver", &dns, "-strict=false"],
		&[("PEBBLE_VA_NOSLEEP", "1"), ("PEBBLE_WFE_NONCEREJECT", "0"), ("PEBBLE_AUTHZREUSE", "0")],
	);
	(proc, format!("https://127.0.0.1:{wfe}/dir"), ca_file)
}

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
	fn start(dir: &Path, api_port: u16, config: &Path, socket: &Path) -> Rproxy {
		let out = dir.join(format!("rproxy-{api_port}.log"));
		let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(dir)
			.env_clear()
			.env("RPROXY_API_PORT", api_port.to_string())
			.env("RPROXY_CONFIG", config)
			.env("RPROXY_API_SOCKET", socket)
			.env("RPROXY_TOKEN_FILE", dir.join("tokens"))
			.env("RPROXY_LOG_LEVEL", "info,rproxy_api=debug")
			.env("RPROXY_CERT_CHECK_SECS", "1")
			.stdout(fs::File::create(&out).unwrap())
			.stderr(Stdio::null())
			.spawn()
			.unwrap();
		Rproxy { child, out }
	}

	fn log(&self) -> String {
		fs::read_to_string(&self.out).unwrap_or_default()
	}
}

async fn unix_post(socket: &Path, path: &str, body: &str) -> String {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	let mut s = tokio::net::UnixStream::connect(socket).await.unwrap();
	let req = format!(
		"POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer e2e-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
		body.len()
	);
	s.write_all(req.as_bytes()).await.unwrap();
	let mut out = String::new();
	s.read_to_string(&mut out).await.unwrap();
	out
}

fn env(name: &str) -> Option<String> {
	std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
async fn issues_certificates_from_pebble() {
	let (Some(pebble), Some(pdns_bin), Some(schema), Some(sqlite3)) =
		(env("RPROXY_TEST_PEBBLE"), env("RPROXY_TEST_PDNS"), env("RPROXY_TEST_PDNS_SCHEMA"), env("RPROXY_TEST_SQLITE3"))
	else {
		assert!(env("RPROXY_TEST_REQUIRE_ACME").is_none(), "RPROXY_TEST_REQUIRE_ACME=1 needs Pebble and PowerDNS");
		eprintln!("skipped: set RPROXY_TEST_PEBBLE, RPROXY_TEST_PDNS, RPROXY_TEST_PDNS_SCHEMA and RPROXY_TEST_SQLITE3");
		return;
	};
	let dir = workdir("pebble");
	let pdns = start_pdns(&dir, &pdns_bin, &schema, &sqlite3).await;
	let (relay_port, relay_calls) = start_relay(pdns.api.clone()).await;
	let http01 = free_port();
	let alpn_port = free_port();
	let (pebble_proc, directory, ca_file) = start_pebble(&dir, &pebble, pdns.dns, http01, alpn_port);
	let pebble_log = || format!("{}\n{}", pebble_proc.log(), fs::read_to_string(dir.join("pebble.err")).unwrap_or_default());
	wait_until("Pebble", 20, &pebble_log, || async { std::net::TcpStream::connect(directory.trim_start_matches("https://").trim_end_matches("/dir")).is_ok() }).await;

	// a TXT record a crash left behind (in the journal): removed after the start
	pdns.call(
		reqwest::Method::PATCH,
		"/zones/example.test.",
		Some(json!({"rrsets": [{"name": "_acme-challenge.stale.example.test.", "type": "TXT", "ttl": 60, "changetype": "REPLACE", "records": [{"content": "\"stale\"", "disabled": false}]}]})),
	)
	.await;
	fs::create_dir_all(dir.join("acme")).unwrap();
	fs::write(
		dir.join("acme/dns-pending.json"),
		json!([{"provider": "pdns", "fqdn": "_acme-challenge.stale.example.test", "zone": "example.test", "value": "stale"}]).to_string(),
	)
	.unwrap();

	// the settings: every challenge, CNAME delegation, the generic REST provider
	let extra = format!(
		"  deleg: {{account: test, challenge: dns-01, dns_provider: pdns-deleg}}\ndns_servers: ['127.0.0.1:{dns}']\ndns_propagation_timeout: 20s\nhttp01_listen: ['127.0.0.1:{http01}']\nrate_limit: {{orders: 50, period: 1h}}\n",
		dns = pdns.dns
	);
	let mut settings = acme_settings(&dir, &directory, &extra);
	for (from, to) in [
		("'http://127.0.0.1:1'".to_string(), format!("'{}'", pdns.api)),

		(
			"    allowed_names: ['**.example.test', example.test]\ndns_providers:".to_string(),
			format!("    allowed_names: ['**.example.test', example.test]\n    ca_file: {}\ndns_providers:", ca_file.display()),
		),
		(
			"  relay:\n".to_string(),
			format!(
				"  pdns-deleg:\n    type: powerdns\n    api_url: '{}'\n    api_key_file: {}/pdns.key\n    zones: [challenges.test]\n    allowed_names: [deleg.example.test]\n  relay:\n",
				pdns.api,
				dir.display()
			),
		),
	] {
		assert!(settings.contains(&from), "{from}");
		settings = settings.replacen(&from, &to, 1);
	}
	settings = settings.replace("http://127.0.0.1:1/", &format!("http://127.0.0.1:{relay_port}/"));
	let global: String = settings.lines().map(|l| format!("    {l}\n")).collect();
	let backend = tcp_backend("app:").await;
	let (p_http, p_dns, p_deleg, p_rest) = (free_port(), free_port(), free_port(), free_port());
	let rule = |port: u16, resolver: &str, domains: &[&str]| {
		format!(
			"  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {port}, remote_addr: 127.0.0.1, remote_port: {}, tls: {{mode: terminate, certificates: [{{acme: {resolver}, domains: {domains:?}}}]}}}}\n",
			backend.port()
		)
	};
	let config = format!(
		"version: 1\nglobal:\n  acme:\n{global}rules:\n{}{}{}{}{}",
		rule(alpn_port, "alpn", &["alpn.example.test"]),
		rule(p_http, "http", &["http.example.test", "www.http.example.test"]),
		rule(p_dns, "dns", &["*.wild.example.test", "wild.example.test"]),
		rule(p_deleg, "deleg", &["deleg.example.test"]),
		rule(p_rest, "rest", &["rest.example.test"]),
	);
	let config_file = dir.join("rproxy.yaml");
	fs::write(&config_file, &config).unwrap();
	fs::write(dir.join("tokens"), "e2e-token\n").unwrap();

	// --check-config reads the same settings
	let check = Command::new(env!("CARGO_BIN_EXE_rproxy-api")).arg("--check-config").arg(&config_file).env_clear().output().unwrap();
	assert!(check.status.success(), "{}{}", String::from_utf8_lossy(&check.stdout), String::from_utf8_lossy(&check.stderr));

	let api = free_port();
	let socket = dir.join("api.sock");
	let rp = Rproxy::start(&dir, api, &config_file, &socket);
	let logs = || format!("{}\n--- pebble ---\n{}", rp.log(), pebble_log());
	let client = reqwest::Client::new();
	let get = |path: String| {
		let client = client.clone();
		async move {
			let r = client.get(format!("http://127.0.0.1:{api}{path}")).bearer_auth("e2e-token").send().await.ok()?;
			Some(r.json::<Value>().await.unwrap_or_default())
		}
	};
	for (port, name) in [(alpn_port, "alpn.example.test"), (p_http, "www.http.example.test"), (p_dns, "x.wild.example.test"), (p_deleg, "deleg.example.test"), (p_rest, "rest.example.test")] {
		wait_until(name, 90, &logs, || async {
			get(format!("/rules/tcp/127.0.0.1/{port}")).await.is_some_and(|v| v["acme"][0]["state"] == "valid")
		})
		.await;
		// the issued certificate is served (swapped in like a renewed file)
		wait_until(&format!("{name}: the issued certificate"), 15, &logs, || async {
			served_cert(port, name, &[]).await.is_some_and(|(leaf, _)| issuer_cn(&leaf).to_ascii_lowercase().contains("pebble"))
		})
		.await;
	}
	let log = rp.log();
	for want in [r#""event":"acme.issue""#, r#""event":"acme.account""#, r#""challenge":"tls-alpn-01""#, r#""challenge":"http-01""#] {
		assert!(log.contains(want), "{want}:\n{}", logs());
	}

	// DNS-01: the CNAME was followed to the delegated zone, and every TXT record is gone
	assert!(log.contains(r#""fqdn":"deleg.challenges.test""#), "{}", logs());
	assert!(log.contains(r#""reason":"left over""#), "the journal's record was removed: {}", logs());
	assert!(pdns.txt("example.test").await.is_empty(), "{:?}", pdns.txt("example.test").await);
	assert!(pdns.txt("challenges.test").await.is_empty(), "{:?}", pdns.txt("challenges.test").await);
	assert!(!dir.join("acme/dns-pending.json").exists());
	let calls = relay_calls.lock().unwrap().clone();
	assert!(calls.iter().any(|c| c.starts_with("present _acme-challenge.rest.example.test ")), "{calls:?}");
	assert!(calls.iter().any(|c| c.starts_with("cleanup _acme-challenge.rest.example.test ")), "{calls:?}");

	// files: 0600 keys, and no secret in any answer or the log
	use std::os::unix::fs::PermissionsExt;
	let key = dir.join("acme/accounts/test.key");
	assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
	let acme = client.get(format!("http://127.0.0.1:{api}/acme")).bearer_auth("e2e-token").send().await.unwrap().text().await.unwrap();
	let rules = client.get(format!("http://127.0.0.1:{api}/rules")).bearer_auth("e2e-token").send().await.unwrap().text().await.unwrap();
	let account_key = fs::read_to_string(&key).unwrap();
	let key_body = account_key.lines().nth(1).unwrap();
	for text in [&acme, &rules, &rp.log()] {
		for secret in [PDNS_KEY, RELAY_SECRET, key_body] {
			assert!(!text.contains(secret), "a secret leaked: {secret}");
		}
	}

	// force a renewal: only over the Unix socket
	let body = r#"{"resolver": "alpn", "domains": ["alpn.example.test"]}"#;
	let r = client.post(format!("http://127.0.0.1:{api}/acme/renew")).bearer_auth("e2e-token").body(body).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::FORBIDDEN);
	let before = served_cert(alpn_port, "alpn.example.test", &[]).await.unwrap().0;
	let r = unix_post(&socket, "/acme/renew", body).await;
	assert!(r.starts_with("HTTP/1.1 202"), "{r}");
	wait_until("the renewal", 60, &logs, || async { rp.log().contains(r#""event":"acme.renew""#) }).await;
	wait_until("the renewed certificate", 15, &logs, || async {
		served_cert(alpn_port, "alpn.example.test", &[]).await.is_some_and(|(leaf, _)| leaf != before)
	})
	.await;
	assert!(rp.log().contains(r#""action":"acme.renew""#), "audited: {}", logs());

	// ARI (RFC 9773): Pebble offers renewal windows; renew_at falls in the window
	wait_until("the renewal window", 20, &logs, || async {
		get("/acme".into()).await.is_some_and(|v| v["certificates"].as_array().unwrap().iter().all(|c| c["ari"]["start"].is_string()))
	})
	.await;
	let v = get("/acme".into()).await.unwrap();
	for c in v["certificates"].as_array().unwrap() {
		let (start, end, at) = (c["ari"]["start"].as_str().unwrap(), c["ari"]["end"].as_str().unwrap(), c["renew_at"].as_str().unwrap());
		assert!(start <= at && at <= end, "{c}");
	}
	assert!(rp.log().contains(r#""event":"acme.ari""#), "{}", logs());

	// revoke: over TCP refused; over the socket the certificate is revoked and replaced
	let body = r#"{"resolver": "dns", "domains": ["*.wild.example.test", "wild.example.test"], "reason": "superseded"}"#;
	let r = client.post(format!("http://127.0.0.1:{api}/acme/revoke")).bearer_auth("e2e-token").body(body).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::FORBIDDEN);
	let bad = unix_post(&socket, "/acme/revoke", r#"{"resolver": "dns", "domains": ["wild.example.test"], "reason": "nope"}"#).await;
	assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
	let before = served_cert(p_dns, "x.wild.example.test", &[]).await.unwrap().0;
	let r = unix_post(&socket, "/acme/revoke", body).await;
	assert!(r.starts_with("HTTP/1.1 200"), "{r}");
	assert!(rp.log().contains(r#""event":"acme.revoke""#) && rp.log().contains(r#""action":"acme.revoke""#), "{}", logs());
	wait_until("the replacement of the revoked certificate", 60, &logs, || async {
		served_cert(p_dns, "x.wild.example.test", &[]).await.is_some_and(|(leaf, _)| leaf != before)
	})
	.await;

	// after a restart the stored certificates are used at once (no new order)
	drop(rp);
	let rp = Rproxy::start(&dir, api, &config_file, &socket);
	let logs = || rp.log();
	wait_until("the restart", 20, &logs, || async {
		get(format!("/rules/tcp/127.0.0.1/{p_rest}")).await.is_some_and(|v| v["acme"][0]["state"] == "valid")
	})
	.await;
	let (leaf, _) = served_cert(p_rest, "rest.example.test", &[]).await.unwrap();
	assert!(issuer_cn(&leaf).to_ascii_lowercase().contains("pebble"));
	tokio::time::sleep(Duration::from_secs(1)).await;
	assert!(!rp.log().contains(r#""event":"acme.order""#), "{}", rp.log());
	drop(rp);
	drop(pebble_proc);
	let _ = fs::remove_dir_all(&dir);
}
