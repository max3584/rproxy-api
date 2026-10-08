//! Stored certificates (#240, v0.4.2, docs/DESIGN-v0.4.x.md 3.): `PUT /certs/{name}`
//! with the PEM, rules naming it with `{"cert": "<name>"}`, replacing it
//! without cutting connections, the scopes and `allow_certs`, the files'
//! modes, and audit lines without keys.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::Digest;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use common::logs;
use common::pki::{Issued, Pki};
use common::*;
use rproxy_api::control::auth::Tokens;

/// The store of this test binary (one per process: the store's directory is process-wide).
fn store() -> PathBuf {
	static DIR: OnceLock<PathBuf> = OnceLock::new();
	DIR.get_or_init(|| {
		rproxy_api::net::files::private_umask();
		let dir = std::env::temp_dir().join(format!("rproxy-certs-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		rproxy_api::tls::named::set_dir(dir.clone());
		rproxy_api::tls::named::prepare().unwrap();
		dir
	})
	.clone()
}

fn body(issued: &Issued) -> Value {
	json!({"cert": issued.cert.pem(), "key": issued.key.serialize_pem()})
}

async fn put(h: &Harness, name: &str, body: &Value) -> (StatusCode, Value, Option<String>) {
	let r = h.http.put(format!("{}/certs/{name}", h.base)).json(body).send().await.unwrap();
	let etag = r.headers().get("etag").map(|v| v.to_str().unwrap().to_string());
	(r.status(), r.json().await.unwrap_or(Value::Null), etag)
}

fn sha(der: &[u8]) -> String {
	sha2::Sha256::digest(der).iter().map(|b| format!("{b:02x}")).collect()
}

/// The fingerprint of the certificate a TLS rule serves for `name`, and the connection.
async fn served(pki: &Pki, port: u16, name: &str) -> (String, tokio_rustls::client::TlsStream<TcpStream>) {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let s = pki.connector(None).connect(name.to_string().try_into().unwrap(), tcp).await.unwrap();
	let leaf = s.get_ref().1.peer_certificates().unwrap()[0].clone();
	(sha(leaf.as_ref()), s)
}

async fn echo(s: &mut tokio_rustls::client::TlsStream<TcpStream>, msg: &str) -> String {
	s.write_all(msg.as_bytes()).await.unwrap();
	let mut buf = [0u8; 256];
	let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.unwrap().unwrap();
	String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn tls_rule(port: u16, backend: std::net::SocketAddr, cert: &str) -> Value {
	let mut r = rule("tcp", port, backend);
	r["tls"] = json!({"mode": "terminate", "certificates": [{"cert": cert}]});
	r
}

#[tokio::test]
async fn store_use_replace_and_delete() {
	let dir = store();
	logs::capture();
	let h = harness().await;
	let pki = Pki::new("certs-main");
	let first = pki.server("a.pem", &["a.test"]);

	let caps = h.get("/capabilities").await.1;
	assert_eq!(caps["features"]["cert_store"], json!(true), "{caps}");

	// stored: 201, the view, the files 0600 under 0700 directories
	let (status, view, etag) = put(&h, "site-a", &body(&first)).await;
	assert_eq!(status, StatusCode::CREATED, "{view}");
	assert_eq!(view["sans"], json!(["a.test"]), "{view}");
	assert_eq!(view["fingerprint_sha256"], json!(sha(first.der().as_ref())));
	assert_eq!(etag.as_deref(), Some(format!("\"{}\"", sha(first.der().as_ref())).as_str()));
	assert!(view.get("key").is_none() && !view.to_string().contains("PRIVATE KEY"), "{view}");
	let current = fs::canonicalize(dir.join("site-a/current")).unwrap();
	for f in ["tls.crt", "tls.key"] {
		assert_eq!(fs::metadata(current.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
	}
	assert_eq!(fs::metadata(&current).unwrap().permissions().mode() & 0o777, 0o700);
	assert_eq!(fs::metadata(dir.join("site-a")).unwrap().permissions().mode() & 0o777, 0o700);

	// a rule names it (the owner check accepts rproxy's own files)
	let backend = tcp_backend("B:").await;
	let port = free_port();
	let (status, v) = h.post(tls_rule(port, backend, "site-a")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (print, mut conn) = served(&pki, port, "a.test").await;
	assert_eq!(print, sha(first.der().as_ref()));
	assert_eq!(echo(&mut conn, "x").await, "B:x");
	let (_, one) = h.get("/certs/site-a").await;
	assert_eq!(one["used_by"], json!([format!("tcp/127.0.0.1:{port}")]), "{one}");
	let (_, all) = h.get("/certs").await;
	assert!(all.as_array().unwrap().iter().any(|c| c["name"] == "site-a"), "{all}");

	// replaced: 200; the open connection goes on, a new one gets the new certificate
	let second = pki.server("a2.pem", &["a.test", "www.a.test"]);
	let stale = json!("\"0000\"");
	let r = h.http.put(format!("{}/certs/site-a", h.base)).header("If-Match", stale.as_str().unwrap()).json(&body(&second)).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::PRECONDITION_FAILED);
	let r = h.http.put(format!("{}/certs/site-a", h.base)).header("If-Match", etag.unwrap()).json(&body(&second)).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(echo(&mut conn, "y").await, "B:y");
	let (print, _) = served(&pki, port, "www.a.test").await;
	assert_eq!(print, sha(second.der().as_ref()));
	// the old version is gone
	let versions: Vec<_> = fs::read_dir(dir.join("site-a")).unwrap().flatten().filter(|e| e.file_type().unwrap().is_dir()).collect();
	assert_eq!(versions.len(), 1);

	// in use: 409 with the rules; free: 204
	let r = h.http.delete(format!("{}/certs/site-a", h.base)).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::CONFLICT);
	let v: Value = r.json().await.unwrap();
	assert_eq!((v["code"].as_str(), &v["used_by"]), (Some("in_use"), &json!([format!("tcp/127.0.0.1:{port}")])), "{v}");
	drop(conn);
	assert_eq!(h.delete(&format!("tcp/127.0.0.1/{port}")).await, StatusCode::NO_CONTENT);
	assert_eq!(h.http.delete(format!("{}/certs/site-a", h.base)).send().await.unwrap().status(), StatusCode::NO_CONTENT);
	assert_eq!(h.get("/certs/site-a").await.0, StatusCode::NOT_FOUND);
	assert!(!dir.join("site-a").exists());

	// audit: the name and the fingerprint, never the key
	let audit = logs::lines(|l| l["event"] == "audit" && l["cert"] == "site-a");
	let actions: Vec<&str> = audit.iter().filter_map(|l| l["action"].as_str()).collect();
	assert!(actions.contains(&"cert.put") && actions.contains(&"cert.delete"), "{audit:?}");
	assert!(audit.iter().any(|l| l["fingerprint_sha256"] == json!(sha(second.der().as_ref()))), "{audit:?}");
	assert!(!format!("{audit:?}").contains("PRIVATE KEY"));
}

#[tokio::test]
async fn bad_certificates_and_names_are_refused() {
	store();
	let h = harness().await;
	let pki = Pki::new("certs-bad");
	let good = pki.server("g.pem", &["g.test"]);
	let other = pki.server("o.pem", &["o.test"]);
	let past = pki.server_until("old.pem", &["old.test"], rproxy_api::tls::config::unix_now() - 86_400);
	let soon = pki.server_until("soon.pem", &["soon.test"], rproxy_api::tls::config::unix_now() + 3 * 86_400);
	let cases = [
		("junk", json!({"cert": "junk", "key": good.key.serialize_pem()}), "invalid"),
		("mismatch", json!({"cert": good.cert.pem(), "key": other.key.serialize_pem()}), "invalid"),
		("expired", body(&past), "invalid"),
		("no-key", json!({"cert": good.cert.pem(), "key": ""}), "invalid"),
		("extra", json!({"cert": good.cert.pem(), "key": good.key.serialize_pem(), "password": "x"}), "invalid"),
		("Bad_Name", body(&good), "invalid"),
		("-dash", body(&good), "invalid"),
	];
	for (name, b, code) in cases {
		let (status, v, _) = put(&h, name, &b).await;
		assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some(code)), "{name}: {v}");
		assert!(!v.to_string().contains("PRIVATE KEY"), "{name}: {v}");
	}
	// too big
	let big = json!({"cert": "x".repeat(2 << 20), "key": ""});
	assert_eq!(put(&h, "big", &big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
	// expiring soon: stored, with a warning
	let (status, v, _) = put(&h, "soon", &body(&soon)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(v["warnings"][0].as_str().unwrap().contains("expires"), "{v}");
	// a rule naming a certificate that is not stored
	let (status, v) = h.post(tls_rule(free_port(), tcp_backend("B:").await, "nothing-here")).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("not in the certificate store"), "{v}");
	// cert with cert_file is one too many
	let mut r = rule("tcp", free_port(), tcp_backend("B:").await);
	r["tls"] = json!({"mode": "terminate", "certificates": [{"cert": "soon", "cert_file": good.cert_file, "key_file": good.key_file}]});
	assert_eq!(h.post(r).await.1["code"], "tls_config");
}

#[tokio::test]
async fn a_failed_rule_starts_once_its_certificate_is_stored() {
	store();
	let h = harness().await;
	let pki = Pki::new("certs-later");
	let backend = tcp_backend("L:").await;
	let port = free_port();
	let spec: rproxy_api::core::rule::RuleRequest = serde_json::from_value(tls_rule(port, backend, "later")).unwrap();
	h.registry.load_static(vec![spec]).await.unwrap();
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!(v["state"], "failed", "{v}");
	assert!(v["error"].as_str().unwrap().contains("not in the certificate store"), "{v}");

	let issued = pki.server("l.pem", &["later.test"]);
	assert_eq!(put(&h, "later", &body(&issued)).await.0, StatusCode::CREATED);
	let v = wait_for(&h, &format!("/rules/tcp/127.0.0.1/{port}"), |v| v["state"] == "running").await;
	assert_eq!(v["tls"]["certificates"], json!([{"cert": "later"}]), "{v}");
	let (print, mut conn) = served(&pki, port, "later.test").await;
	assert_eq!(print, sha(issued.der().as_ref()));
	assert_eq!(echo(&mut conn, "z").await, "L:z");
}

fn token_sha(s: &str) -> String {
	sha(s.as_bytes())
}

#[tokio::test]
async fn scopes_and_allow_certs() {
	store();
	let dir = std::env::temp_dir().join(format!("rproxy-certs-tokens-{}", std::process::id()));
	fs::create_dir_all(&dir).unwrap();
	let file = dir.join("tokens.yaml");
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: team-a, sha256: {}, scopes: [rules:write, rules:read, certs:write, certs:read], allow_certs: [team-a-]}}\n  - {{name: reader, sha256: {}, scopes: [certs:read]}}\n  - {{name: rules-only, sha256: {}, scopes: [rules:read, rules:write]}}\n",
			token_sha("a"),
			token_sha("r"),
			token_sha("o")
		),
	)
	.unwrap();
	let h = harness_with(Tokens::from_file(file).unwrap()).await;
	let pki = Pki::new("certs-scopes");
	let issued = pki.server("s.pem", &["s.test"]);
	let send = |method: reqwest::Method, path: &str, token: &str, b: Option<Value>| {
		let mut r = h.http.request(method, format!("{}{path}", h.base)).bearer_auth(token);
		if let Some(b) = b {
			r = r.json(&b);
		}
		r.send()
	};
	use reqwest::Method;
	assert_eq!(send(Method::PUT, "/certs/team-a-web", "a", Some(body(&issued))).await.unwrap().status(), StatusCode::CREATED);
	assert_eq!(send(Method::PUT, "/certs/team-b-web", "a", Some(body(&issued))).await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(send(Method::PUT, "/certs/team-x", "r", Some(body(&issued))).await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(send(Method::GET, "/certs", "o", None).await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(send(Method::GET, "/certs/team-a-web", "r", None).await.unwrap().status(), StatusCode::OK);
	// the admin-less writer sees only its own names
	assert_eq!(send(Method::PUT, "/certs/other-web", "r", Some(body(&issued))).await.unwrap().status(), StatusCode::FORBIDDEN);
	let listed: Value = send(Method::GET, "/certs", "a", None).await.unwrap().json().await.unwrap();
	assert!(listed.as_array().unwrap().iter().all(|c| c["name"].as_str().unwrap().starts_with("team-a-")), "{listed}");

	// rules may name only certificates within allow_certs
	let backend = tcp_backend("S:").await;
	let r = send(Method::POST, "/rules", "a", Some(tls_rule(free_port(), backend, "team-a-web"))).await.unwrap();
	assert_eq!(r.status(), StatusCode::CREATED);
	let r = send(Method::POST, "/rules", "a", Some(tls_rule(free_port(), backend, "team-b-web"))).await.unwrap();
	assert_eq!(r.status(), StatusCode::FORBIDDEN);
	// a token without allow_certs may name any
	let r = send(Method::POST, "/rules", "o", Some(tls_rule(free_port(), backend, "team-a-web"))).await.unwrap();
	assert_eq!(r.status(), StatusCode::CREATED);
	fs::remove_dir_all(dir).unwrap();
}
