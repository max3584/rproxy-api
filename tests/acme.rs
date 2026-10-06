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
/// TSIG secrets (base64) of the RFC 2136 providers.
const TSIG_256: &str = "c2VjcmV0LXRzaWctMjU2LWtleS1mb3ItcnByb3h5LXRlc3Q=";
const TSIG_512: &str = "c2VjcmV0LXRzaWctNTEyLWtleS1mb3ItcnByb3h5LXRlc3QtYWJjZGVmZ2hpams=";
/// The password the acme-dns mock hands out.
const ADNS_PASSWORD: &str = "acme-dns-password-SECRET-5c1e";

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

/// The helper refuses peers it does not know, names outside the allowlist,
/// values that are not DNS-01 values, and records it would not write there.
#[tokio::test]
async fn the_helper_checks_what_it_is_asked() {
	use rproxy_api::acme::dns::Written;
	use rproxy_api::acme::helper::{call, Helper, Request};
	let dir = workdir("helper");
	fs::write(dir.join("pdns.key"), "k\n").unwrap();
	let yaml = format!(
		"accounts: {{a: {{allowed_names: ['**.example.test']}}}}\ndns_providers:\n  pdns: {{type: powerdns, api_url: 'http://127.0.0.1:1', api_key_file: {}/pdns.key, zones: [example.test], allowed_names: ['*.example.test']}}\ndns_servers: ['127.0.0.1:1']\n",
		dir.display()
	);
	let global: rproxy_api::acme::config::AcmeGlobal = rproxy_api::config::from_yaml(&yaml).unwrap();
	// SAFETY: plain syscall
	let me = unsafe { libc::getuid() };
	let start = |allow: Vec<u32>, name: &str| {
		let path = dir.join(name);
		let listener = tokio::net::UnixListener::bind(&path).unwrap();
		let helper = Arc::new(Helper::new(&global, allow).unwrap());
		tokio::spawn(helper.serve(listener, tokio_util::sync::CancellationToken::new()));
		path
	};
	let value = "qYdUfkaTCkVSY0mW0UjdUs7f-1xYODPyuo3uF0ktZnc".to_string();
	let locate = |domain: &str, value: &str| Request::Locate { provider: "pdns".into(), domain: domain.into(), value: value.into() };
	let other = start(vec![me + 1], "other.sock");
	let e = call(&other, &locate("a.example.test", &value)).await.unwrap_err();
	assert!(e.contains("may not use the helper"), "{e}");

	let ours = start(vec![me], "ours.sock");
	let rec = call(&ours, &locate("a.example.test", &value)).await.unwrap().record.unwrap();
	assert_eq!((rec.fqdn.as_str(), rec.zone.as_str()), ("_acme-challenge.a.example.test", "example.test"));
	for (domain, v, want) in [
		("evil.example.org", value.as_str(), "not in allowed_names"),
		("a.b.example.test", value.as_str(), "not in allowed_names"),
		("a.example.test", "x\"},{\"y", "not a DNS-01 value"),
		("*.example.test", value.as_str(), "not a name"),
	] {
		let e = call(&ours, &locate(domain, v)).await.unwrap_err();
		assert!(e.contains(want), "{domain} {v}: {e}");
	}
	// a record somewhere else than where the helper puts it is refused before any call
	let moved = Written { fqdn: "www.example.test".into(), ..rec.clone() };
	let e = call(&ours, &Request::Present { provider: "pdns".into(), records: vec![moved] }).await.unwrap_err();
	assert!(e.contains("would go to"), "{e}");
	let e = call(&ours, &Request::Cleanup { provider: "nope".into(), records: vec![rec] }).await.unwrap_err();
	assert!(e.contains("not configured"), "{e}");
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
		"launch=gsqlite3\ngsqlite3-database={}\nlocal-address=127.0.0.1\nlocal-port={dns}\napi=yes\napi-key={PDNS_KEY}\nwebserver=yes\nwebserver-address=127.0.0.1\nwebserver-port={web}\nwebserver-allow-from=127.0.0.0/8\nsocket-dir={}\nguardian=no\ndaemon=no\ndisable-syslog=yes\nloglevel=5\nzone-cache-refresh-interval=0\ndnsupdate=yes\nallow-dnsupdate-from=127.0.0.0/8\n",
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
	let cname = |from: &str, to: &str| json!({"name": from, "type": "CNAME", "ttl": 60, "records": [{"content": to, "disabled": false}]});
	let deleg = cname("_acme-challenge.deleg.example.test.", "deleg.challenges.test.");
	let rfc512 = cname("_acme-challenge.rfc512.example.test.", "rfc512.challenges.test.");
	for z in [zone("example.test.", vec![a("example.test."), a("*.example.test."), deleg, rfc512]), zone("challenges.test.", vec![])] {
		let (status, body) = p.call(reqwest::Method::POST, "/zones", Some(z)).await;
		assert!(status.is_success(), "PowerDNS zone: {status} {body}");
	}
	// DNS UPDATE (RFC 2136) with TSIG: one key per zone
	for (key, alg, secret, zone) in [("rproxy-256", "hmac-sha256", TSIG_256, "example.test."), ("rproxy-512", "hmac-sha512", TSIG_512, "challenges.test.")] {
		let (status, body) = p.call(reqwest::Method::POST, "/tsigkeys", Some(json!({"name": key, "algorithm": alg, "key": secret}))).await;
		assert!(status.is_success(), "PowerDNS TSIG key: {status} {body}");
		let (status, body) = p.call(reqwest::Method::PUT, &format!("/zones/{zone}/metadata/TSIG-ALLOW-DNSUPDATE"), Some(json!({"metadata": [key]}))).await;
		assert!(status.is_success(), "PowerDNS metadata: {status} {body}");
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

/// An acme-dns server: `/register` hands out an account, `/update` (with its
/// credentials) sets the TXT record of the account's name (the latest two)
/// through PowerDNS's API.
async fn start_acme_dns(pdns_api: String) -> u16 {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let port = listener.local_addr().unwrap().port();
	let values: Arc<Mutex<Vec<String>>> = Arc::default();
	let app = axum::Router::new()
		.route(
			"/register",
			axum::routing::post(|| async {
				(
					axum::http::StatusCode::CREATED,
					axum::Json(json!({"username": "adns-user", "password": ADNS_PASSWORD, "fulldomain": "b7f4.challenges.test", "subdomain": "b7f4", "allowfrom": []})),
				)
			}),
		)
		.route(
			"/update",
			axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
				let (values, api) = (values.clone(), pdns_api.clone());
				async move {
					let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
					if h("x-api-user") != "adns-user" || h("x-api-key") != ADNS_PASSWORD {
						return axum::http::StatusCode::UNAUTHORIZED;
					}
					let v: Value = serde_json::from_str(&body).unwrap_or_default();
					if v["subdomain"] != "b7f4" {
						return axum::http::StatusCode::BAD_REQUEST;
					}
					let records = {
						let mut all = values.lock().unwrap();
						all.push(v["txt"].as_str().unwrap_or("").to_string());
						let n = all.len();
						all[n.saturating_sub(2)..].to_vec()
					};
					let rrset = json!({"name": "b7f4.challenges.test.", "type": "TXT", "ttl": 60, "changetype": "REPLACE",
						"records": records.iter().map(|r| json!({"content": format!("\"{r}\""), "disabled": false})).collect::<Vec<_>>()});
					let r = reqwest::Client::new()
						.patch(format!("{api}/api/v1/servers/localhost/zones/challenges.test."))
						.header("X-API-Key", PDNS_KEY)
						.json(&json!({"rrsets": [rrset]}))
						.send()
						.await;
					match r {
						Ok(r) if r.status().is_success() => axum::http::StatusCode::OK,
						_ => axum::http::StatusCode::BAD_GATEWAY,
					}
				}
			}),
		);
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	port
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
	let adns_port = start_acme_dns(pdns.api.clone()).await;
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
		"  deleg: {{account: test, challenge: dns-01, dns_provider: pdns-deleg}}\n  rfc256: {{account: test, challenge: dns-01, dns_provider: rfc256}}\n  rfc512: {{account: test, challenge: dns-01, dns_provider: rfc512}}\n  adns: {{account: test, challenge: dns-01, dns_provider: adns}}\ndns_servers: ['127.0.0.1:{dns}']\ndns_propagation_timeout: 20s\nhttp01_listen: ['127.0.0.1:{http01}']\nrate_limit: {{orders: 50, period: 1h}}\n",
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
				"  pdns-deleg:\n    type: powerdns\n    api_url: '{}'\n    api_key_file: {d}/pdns.key\n    zones: [challenges.test]\n    allowed_names: [deleg.example.test]\n  rfc256: {{type: rfc2136, server: '127.0.0.1:{dns}', tsig_key_name: rproxy-256, tsig_secret_file: {d}/tsig-256.key, allowed_names: [rfc.example.test]}}\n  rfc512: {{type: rfc2136, server: '127.0.0.1:{dns}', tsig_key_name: rproxy-512, tsig_algorithm: hmac-sha512, tsig_secret_file: {d}/tsig-512.key, zones: [challenges.test], allowed_names: [rfc512.example.test]}}\n  adns: {{type: acme_dns, api_url: 'http://127.0.0.1:{adns_port}', credentials_file: {d}/acme-dns.json, allowed_names: [adns.example.test]}}\n  relay:\n",
				pdns.api,
				d = dir.display(),
				dns = pdns.dns,
			),
		),
	] {
		assert!(settings.contains(&from), "{from}");
		settings = settings.replacen(&from, &to, 1);
	}
	settings = settings.replace("http://127.0.0.1:1/", &format!("http://127.0.0.1:{relay_port}/"));
	let global: String = settings.lines().map(|l| format!("    {l}\n")).collect();
	fs::write(dir.join("tsig-256.key"), format!("{TSIG_256}\n")).unwrap();
	fs::write(dir.join("tsig-512.key"), format!("{TSIG_512}\n")).unwrap();
	let backend = tcp_backend("app:").await;
	let (p_http, p_dns, p_deleg, p_rest) = (free_port(), free_port(), free_port(), free_port());
	let (p_rfc, p_rfc512, p_adns) = (free_port(), free_port(), free_port());
	let rule = |port: u16, resolver: &str, domains: &[&str]| {
		format!(
			"  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {port}, remote_addr: 127.0.0.1, remote_port: {}, tls: {{mode: terminate, certificates: [{{acme: {resolver}, domains: {domains:?}}}]}}}}\n",
			backend.port()
		)
	};
	let config = format!(
		"version: 1\nglobal:\n  acme:\n{global}rules:\n{}{}{}{}{}{}{}{}",
		rule(alpn_port, "alpn", &["alpn.example.test"]),
		rule(p_http, "http", &["http.example.test", "www.http.example.test"]),
		rule(p_dns, "dns", &["*.wild.example.test", "wild.example.test"]),
		rule(p_deleg, "deleg", &["deleg.example.test"]),
		rule(p_rest, "rest", &["rest.example.test"]),
		rule(p_rfc, "rfc256", &["rfc.example.test"]),
		rule(p_rfc512, "rfc512", &["rfc512.example.test"]),
		rule(p_adns, "adns", &["adns.example.test"]),
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
	for (port, name) in [(alpn_port, "alpn.example.test"), (p_http, "www.http.example.test"), (p_dns, "x.wild.example.test"), (p_deleg, "deleg.example.test"), (p_rest, "rest.example.test"), (p_rfc, "rfc.example.test"), (p_rfc512, "rfc512.example.test")] {
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
	// RFC 2136: HMAC-SHA256 into example.test, HMAC-SHA512 through the CNAME into challenges.test
	// (send() takes only answers PowerDNS signed with the same key, so these were checked too)
	assert!(log.contains(r#""provider":"rfc256","fqdn":"_acme-challenge.rfc.example.test","zone":"example.test""#), "{}", logs());
	assert!(log.contains(r#""provider":"rfc512","fqdn":"rfc512.challenges.test","zone":"challenges.test""#), "{}", logs());

	// a wrong TSIG key is refused by the server
	use rproxy_api::acme::rfc2136;
	let wrong = rfc2136::TsigKey { name: "rproxy-256".into(), algorithm: rfc2136::Algorithm::HmacSha256, secret: b"not-the-key".to_vec() };
	let server: std::net::SocketAddr = format!("127.0.0.1:{}", pdns.dns).parse().unwrap();
	let e = rfc2136::send(server, "example.test", &[rfc2136::Change::Add { name: "_acme-challenge.x.example.test", value: "x", ttl: 60 }], &wrong)
		.await
		.unwrap_err();
	// PowerDNS answers a wrong key with an unsigned REFUSED (BIND: NOTAUTH with BADSIG)
	assert!(e.contains("refused"), "{e}");
	assert!(pdns.txt("example.test").await.is_empty());

	// acme-dns: the first order registers the name (kept 0600) and asks for the CNAME
	let adns_file = dir.join("acme-dns.json");
	wait_until("the acme-dns registration", 30, &logs, || async { adns_file.exists() && rp.log().contains("create the CNAME record _acme-challenge.adns.example.test") }).await;
	use std::os::unix::fs::PermissionsExt;
	assert_eq!(fs::metadata(&adns_file).unwrap().permissions().mode() & 0o777, 0o600);
	let creds: Value = serde_json::from_slice(&fs::read(&adns_file).unwrap()).unwrap();
	assert_eq!(creds["adns.example.test"]["fulldomain"], "b7f4.challenges.test");
	pdns.call(
		reqwest::Method::PATCH,
		"/zones/example.test.",
		Some(json!({"rrsets": [{"name": "_acme-challenge.adns.example.test.", "type": "CNAME", "ttl": 60, "changetype": "REPLACE", "records": [{"content": "b7f4.challenges.test.", "disabled": false}]}]})),
	)
	.await;
	let r = unix_post(&socket, "/acme/renew", r#"{"resolver": "adns", "domains": ["adns.example.test"]}"#).await;
	assert!(r.starts_with("HTTP/1.1 202"), "{r}");
	wait_until("adns.example.test", 60, &logs, || async {
		get(format!("/rules/tcp/127.0.0.1/{p_adns}")).await.is_some_and(|v| v["acme"][0]["state"] == "valid")
	})
	.await;
	let log = rp.log();
	for secret in [ADNS_PASSWORD, TSIG_256, TSIG_512] {
		assert!(!log.contains(secret), "a secret in the log");
	}

	// files: 0600 keys, and no secret in any answer or the log
	let key = dir.join("acme/accounts/test.key");
	assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
	let acme = client.get(format!("http://127.0.0.1:{api}/acme")).bearer_auth("e2e-token").send().await.unwrap().text().await.unwrap();
	let rules = client.get(format!("http://127.0.0.1:{api}/rules")).bearer_auth("e2e-token").send().await.unwrap().text().await.unwrap();
	let account_key = fs::read_to_string(&key).unwrap();
	let key_body = account_key.lines().nth(1).unwrap();
	for text in [&acme, &rules, &rp.log()] {
		for secret in [PDNS_KEY, RELAY_SECRET, key_body, ADNS_PASSWORD, TSIG_256, TSIG_512] {
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

	// the helper (global.acme.helper): it holds the DNS secrets; this rproxy's
	// settings name files that do not exist, so it cannot have read them
	let helper_socket = dir.join("helper.sock");
	// SAFETY: plain syscall
	let uid = unsafe { libc::getuid() }.to_string();
	let helper = spawn(
		"helper",
		&dir,
		env!("CARGO_BIN_EXE_rproxy-api"),
		&["acme-helper", "--config", config_file.to_str().unwrap(), "--socket", helper_socket.to_str().unwrap(), "--socket-mode", "600", "--allow-user", &uid],
		&[],
	);
	let helper_log = || fs::read_to_string(dir.join("helper.log")).unwrap_or_default();
	wait_until("the helper", 20, &helper_log, || async { helper_socket.exists() }).await;
	let mut global_b = global.replace(&format!("storage: {}", dir.join("acme").display()), &format!("storage: {}", dir.join("acme-b").display()));
	for f in ["pdns.key", "tsig-256.key", "tsig-512.key", "relay.token", "acme-dns.json"] {
		global_b = global_b.replace(&format!("{}/{f}", dir.display()), &format!("/nonexistent/{f}"));
	}
	global_b.push_str(&format!("    helper: {{socket: {}}}\n", helper_socket.display()));
	let p_helper = free_port();
	let config_b = dir.join("rproxy-b.yaml");
	fs::write(&config_b, format!("version: 1\nglobal:\n  acme:\n{global_b}rules:\n{}", rule(p_helper, "dns", &["helper.example.test"]))).unwrap();
	let check = Command::new(env!("CARGO_BIN_EXE_rproxy-api")).arg("--check-config").arg(&config_b).env_clear().output().unwrap();
	assert!(check.status.success(), "{}{}", String::from_utf8_lossy(&check.stdout), String::from_utf8_lossy(&check.stderr));
	let api_b = free_port();
	let rp = Rproxy::start(&dir, api_b, &config_b, &dir.join("api-b.sock"));
	let logs = || format!("{}\n--- helper ---\n{}", rp.log(), helper_log());
	wait_until("helper.example.test through the helper", 60, &logs, || async {
		let r = client.get(format!("http://127.0.0.1:{api_b}/rules/tcp/127.0.0.1/{p_helper}")).bearer_auth("e2e-token").send().await;
		match r {
			Ok(r) => r.json::<Value>().await.unwrap_or_default()["acme"][0]["state"] == "valid",
			Err(_) => false,
		}
	})
	.await;
	let hl = helper_log();
	assert!(hl.contains(r#""action":"add""#) && hl.contains(r#""action":"remove""#) && hl.contains(r#""fqdn":"_acme-challenge.helper.example.test""#), "{hl}");
	assert!(pdns.txt("example.test").await.is_empty());
	let acme_b = client.get(format!("http://127.0.0.1:{api_b}/acme")).bearer_auth("e2e-token").send().await.unwrap().json::<Value>().await.unwrap();
	assert_eq!(acme_b["helper"], true, "{acme_b}");
	for text in [hl.as_str(), &rp.log()] {
		for secret in [PDNS_KEY, TSIG_256, ADNS_PASSWORD] {
			assert!(!text.contains(secret), "a secret in a log");
		}
	}
	drop(rp);
	drop(helper);
	drop(pebble_proc);
	let _ = fs::remove_dir_all(&dir);
}
