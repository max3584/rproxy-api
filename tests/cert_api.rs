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

/// A removal left half done (a kill or a failed delete) is finished at the next write,
/// not only at the next start.
#[tokio::test]
async fn leftovers_of_a_removal_are_cleaned_at_the_next_write() {
	let store = store();
	let h = harness().await;
	let pki = Pki::new("certs-clean");
	let leftover = store.join(".removing-gone-1");
	fs::create_dir_all(leftover.join("0123456789abcdef")).unwrap();
	fs::write(leftover.join("0123456789abcdef").join("tls.key"), "half").unwrap();
	let (status, _, _) = put(&h, "site-clean", &body(&pki.server("clean.pem", &["clean.test"]))).await;
	assert_eq!(status, StatusCode::CREATED);
	assert!(!leftover.exists(), "the leftover is still there");
	assert_eq!(h.http.delete(format!("{}/certs/site-clean", h.base)).send().await.unwrap().status(), StatusCode::NO_CONTENT);
	let rest: Vec<_> = fs::read_dir(&store).unwrap().flatten().map(|e| e.file_name()).filter(|n| n.to_string_lossy().starts_with(".removing-")).collect();
	assert!(rest.is_empty(), "{rest:?}");
}

/// #319: rules from the API may not name files of the certificate store (nor reach
/// them through a symbolic link or `..`), nor secrets of the options; a token
/// limited by `allow_certs` names no file at all; rules of the settings file may.
#[tokio::test]
async fn rule_files_may_not_reach_the_store() {
	let dir = store();
	let work = std::env::temp_dir().join(format!("rproxy-certs-files-{}", std::process::id()));
	let _ = fs::remove_dir_all(&work);
	fs::create_dir_all(&work).unwrap();
	let tokens = work.join("tokens.yaml");
	fs::write(
		&tokens,
		format!(
			"tokens:\n  - {{name: team-a, sha256: {}, scopes: [rules:write, rules:read], allow_certs: [team-a-]}}\n  - {{name: admin, sha256: {}, scopes: [admin]}}\n",
			token_sha("limited"),
			token_sha("admin")
		),
	)
	.unwrap();
	// the token file is a secret of the options
	rproxy_api::net::protected::set_process(rproxy_api::net::protected::process_entries(Some(&tokens), None, None));
	let h = harness_with(Tokens::from_file(tokens.clone()).unwrap()).await;
	let pki = Pki::new("certs-files");
	let issued = pki.server("f.pem", &["f.test"]);
	let send = |method: reqwest::Method, path: String, token: &'static str, b: Value| {
		let req = h.http.request(method, format!("{}{path}", h.base)).bearer_auth(token).json(&b);
		async move {
			let r = req.send().await.unwrap();
			let status = r.status();
			(status, r.json::<Value>().await.unwrap_or(Value::Null))
		}
	};
	use reqwest::Method;
	let caps: Value = h.http.get(format!("{}/capabilities", h.base)).bearer_auth("admin").send().await.unwrap().json().await.unwrap();
	assert_eq!(caps["features"]["protected_files"], true, "{caps}");
	assert_eq!(send(Method::PUT, "/certs/team-a-files".into(), "admin", body(&issued)).await.0, StatusCode::CREATED);
	let stored = dir.join("team-a-files/current");
	let (crt, key) = (stored.join("tls.crt"), stored.join("tls.key"));
	let s = |p: &std::path::Path| p.to_string_lossy().into_owned();
	let backend = tcp_backend("F:").await;
	let files_rule = |port: u16, cert: &str, key: &str| {
		let mut r = rule("tcp", port, backend);
		r["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert, "key_file": key}]});
		r
	};
	let refused = |(status, v): (StatusCode, Value), code: &str, what: &str| {
		assert_eq!((status, v["code"].as_str()), (StatusCode::FORBIDDEN, Some(code)), "{what}: {v}");
	};

	// the stored files themselves, through a symbolic link, through `..`, and one not stored yet
	std::os::unix::fs::symlink(&key, work.join("link.key")).unwrap();
	let outside = pki.write("outside.crt", &issued.cert.pem());
	for (cert, key_file, what) in [
		(s(&crt), s(&key), "the stored files"),
		(outside.clone(), s(&work.join("link.key")), "a link into the store"),
		(outside.clone(), format!("{}/../{}/team-a-files/current/tls.key", work.display(), dir.file_name().unwrap().to_string_lossy()), "`..`"),
		(outside.clone(), s(&dir.join("team-a-later/current/tls.key")), "a certificate stored later"),
	] {
		let (status, v) = send(Method::POST, "/rules".into(), "admin", files_rule(free_port(), &cert, &key_file)).await;
		refused((status, v.clone()), "protected_file", what);
		assert!(v["error"].as_str().unwrap().contains("certificate store"), "{what}: {v}");
	}
	// dry runs, PATCH, a rule set's PUT, and the services' TLS files
	let port = free_port();
	refused(send(Method::POST, "/rules?dry_run=true".into(), "admin", files_rule(port, &s(&crt), &s(&key))).await, "protected_file", "dry run");
	let (status, v) = send(Method::POST, "/rules".into(), "admin", rule("tcp", port, backend)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let tls = json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port(),
		"tls": {"mode": "terminate", "certificates": [{"cert_file": s(&crt), "key_file": s(&key)}]}});
	refused(send(Method::PATCH, format!("/rules/tcp/127.0.0.1/{port}"), "admin", tls.clone()).await, "protected_file", "PATCH");
	refused(send(Method::PATCH, format!("/rules/tcp/127.0.0.1/{port}?dry_run=true"), "admin", tls).await, "protected_file", "PATCH dry run");
	let set = json!({"generation": 1, "rules": [files_rule(free_port(), &s(&crt), &s(&key))]});
	let (status, v) = send(Method::PUT, "/rulesets/files".into(), "admin", set).await;
	refused((status, v.clone()), "protected_file", "rule set");
	assert!(v["error"].as_str().unwrap().starts_with("rules[0]: tls.certificates[0]"), "{v}");
	let http = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
		"routes": [{"name": "a", "match": "PathPrefix(`/`)", "service": "s"}],
		"services": {"s": {"servers": [{"url": format!("https://{backend}")}], "tls": {"ca_file": s(&crt)}}}}});
	refused(send(Method::POST, "/rules".into(), "admin", http).await, "protected_file", "a service's ca_file");
	// the token file is a secret of the options
	let users = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
		"routes": [{"name": "a", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["auth"]}],
		"middlewares": {"auth": {"basic_auth": {"users_file": s(&tokens)}}}}});
	let (status, v) = send(Method::POST, "/rules".into(), "admin", users).await;
	refused((status, v.clone()), "protected_file", "the token file");
	assert!(v["error"].as_str().unwrap().contains("RPROXY_TOKEN_FILE"), "{v}");

	// files elsewhere are fine
	let own_key = pki.write("own.key", &issued.key.serialize_pem());
	let (status, v) = send(Method::POST, "/rules".into(), "admin", files_rule(free_port(), &outside, &own_key)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	// a token limited by allow_certs names stored certificates only, no file
	let (status, v) = send(Method::POST, "/rules".into(), "limited", files_rule(free_port(), &outside, &own_key)).await;
	refused((status, v.clone()), "file_not_allowed", "allow_certs");
	assert!(v["error"].as_str().unwrap().contains("allow_certs"), "{v}");
	let (status, v) = send(Method::POST, "/rules".into(), "limited", tls_rule(free_port(), backend, "team-a-files")).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	// a rule an earlier version accepted (restored from the database) runs, said with
	// rule.protected_file (the field, not the path); a PATCH of only its targets is refused
	logs::capture();
	let legacy = free_port();
	let spec: rproxy_api::core::rule::RuleRequest = serde_json::from_value(files_rule(legacy, &s(&crt), &s(&key))).unwrap();
	h.registry.restore(vec![spec]).await;
	let line = logs::wait_for("rule.protected_file", |l| l["event"] == "rule.protected_file" && l["rule"] == format!("tcp/127.0.0.1:{legacy}")).await;
	assert!(line["field"].as_str().unwrap().starts_with("tls.certificates[0]."), "{line}");
	assert!(!line.to_string().contains(&s(&crt)), "{line}");
	let (print, _conn) = served(&pki, legacy, "f.test").await;
	assert_eq!(print, sha(issued.der().as_ref()));
	let only_targets = json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port()});
	refused(send(Method::PATCH, format!("/rules/tcp/127.0.0.1/{legacy}"), "admin", only_targets).await, "protected_file", "PATCH of the targets");

	// refusals of PUT /rulesets are audited like those of /rules
	let set = json!({"generation": 1, "rules": [files_rule(free_port(), &s(&crt), &s(&key))]});
	refused(send(Method::PUT, "/rulesets/audited".into(), "admin", set).await, "protected_file", "rule set");
	let audit = logs::wait_for("audit", |l| l["event"] == "audit" && l["ruleset"] == "audited").await;
	assert_eq!((audit["outcome"].as_str(), audit["code"].as_str()), (Some("forbidden"), Some("protected_file")), "{audit}");

	// rules of the settings file are the administrator's: they may
	let port = free_port();
	let spec: rproxy_api::core::rule::RuleRequest = serde_json::from_value(files_rule(port, &s(&crt), &s(&key))).unwrap();
	h.registry.load_static(vec![spec]).await.unwrap();
	let (print, mut conn) = served(&pki, port, "f.test").await;
	assert_eq!(print, sha(issued.der().as_ref()));
	assert_eq!(echo(&mut conn, "s").await, "F:s");
	rproxy_api::net::protected::set_process(vec![]);
	fs::remove_dir_all(work).unwrap();
}

/// #319: a change whose names take long to resolve holds up no other change (the
/// files' check holds no lock over the change), and the files of a change under way
/// still count for the checks made meanwhile.
#[tokio::test]
async fn a_slow_change_holds_up_no_other() {
	let h = harness().await;
	let pki = Pki::new("certs-slow");
	let issued = pki.server("slow.pem", &["slow.test"]);
	let cert = pki.write("slow.crt", &issued.cert.pem());
	let key = pki.write("slow.key", &issued.key.serialize_pem());
	let slow = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(),
		"targets": (0..3).map(|i| json!({"addr": format!("t{i}.slow.test"), "port": 9})).collect::<Vec<_>>(),
		"tls": {"mode": "terminate", "certificates": [{"cert_file": cert, "key_file": key}]}});
	let (http, base) = (h.http.clone(), h.base.clone());
	let pending = tokio::spawn(async move { http.post(format!("{base}/rules")).json(&slow).send().await.unwrap().status() });
	tokio::time::sleep(Duration::from_millis(300)).await;
	let started = std::time::Instant::now();
	let backend = tcp_backend("Q:").await;
	// without files, and with other files
	let (status, v) = h.post(rule("tcp", free_port(), backend)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let other_key = pki.write("other.key", &issued.key.serialize_pem());
	let mut with_files = rule("tcp", free_port(), backend);
	with_files["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": pki.write("other.crt", &issued.cert.pem()), "key_file": other_key}]});
	let (status, v) = h.post(with_files).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	// the key of the change under way may not become another rule's OIDC client secret
	let cookie = pki.write("cookie", "a-long-cookie-secret-for-tests\n");
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
			"routes": [{"name": "a", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["sso"]}],
			"middlewares": {"sso": {"oidc": {"issuer": "https://idp.evil.example", "client_id": "x",
				"client_secret_file": key, "cookie_secret_file": cookie}}}}}))
		.await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("secret_reuse")), "{v}");
	assert!(started.elapsed() < Duration::from_secs(5), "held up for {:?}", started.elapsed());
	assert!(!pending.is_finished(), "the slow change is still resolving");
	pending.abort();
}

/// #323: a token may not name a key or secret file a rule of another owner names (a
/// rule of another token, of another token's rule set, of the settings file, or one
/// restored without a known creator), by the same inode however it is reached
/// (`409 file_in_use`, without saying whose); `admin` may. Certificates are public;
/// a PATCH or a set's PUT may keep the files it names already; restored rules that
/// share one already run, said by `rule.shared_file`.
#[tokio::test]
async fn key_files_keep_to_their_owner() {
	let work = std::env::temp_dir().join(format!("rproxy-certs-owners-{}", std::process::id()));
	let _ = fs::remove_dir_all(&work);
	fs::create_dir_all(&work).unwrap();
	let tokens = work.join("tokens.yaml");
	fs::write(
		&tokens,
		format!(
			"tokens:\n  - {{name: team-a, sha256: {}, scopes: [rules:write, rules:read]}}\n  - {{name: team-b, sha256: {}, scopes: [rules:write, rules:read]}}\n  - {{name: admin, sha256: {}, scopes: [admin]}}\n",
			token_sha("a"),
			token_sha("b"),
			token_sha("admin")
		),
	)
	.unwrap();
	let h = harness_with(Tokens::from_file(tokens).unwrap()).await;
	let pki = Pki::new("certs-owners");
	let issued = pki.server("o.pem", &["o.test"]);
	let cert = pki.write("o.crt", &issued.cert.pem());
	let key = pki.write("o.key", &issued.key.serialize_pem());
	let backend = tcp_backend("O:").await;
	let send = |method: reqwest::Method, path: String, token: &'static str, b: Value| {
		let req = h.http.request(method, format!("{}{path}", h.base)).bearer_auth(token).json(&b);
		async move {
			let r = req.send().await.unwrap();
			let status = r.status();
			(status, r.json::<Value>().await.unwrap_or(Value::Null))
		}
	};
	use reqwest::Method;
	let files_rule = |port: u16, key: &str| {
		let mut r = rule("tcp", port, backend);
		r["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert, "key_file": key}]});
		r
	};
	let in_use = |(status, v): (StatusCode, Value), what: &str| {
		assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("file_in_use")), "{what}: {v}");
		v
	};
	let created = |(status, v): (StatusCode, Value), what: &str| assert_eq!(status, StatusCode::CREATED, "{what}: {v}");
	let caps: Value = h.http.get(format!("{}/capabilities", h.base)).bearer_auth("admin").send().await.unwrap().json().await.unwrap();
	assert_eq!(caps["features"]["file_owners"], true, "{caps}");

	let a_port = free_port();
	created(send(Method::POST, "/rules".into(), "a", files_rule(a_port, &key)).await, "team-a's rule");
	// another token: the key itself, a hard link, a symbolic link, `..`, a dry run
	fs::hard_link(&key, work.join("hard.key")).unwrap();
	std::os::unix::fs::symlink(&key, work.join("soft.key")).unwrap();
	let s = |p: PathBuf| p.to_string_lossy().into_owned();
	let dotted = format!("{}/../{}/hard.key", work.display(), work.file_name().unwrap().to_string_lossy());
	for (k, what) in [(key.clone(), "the key"), (s(work.join("hard.key")), "a hard link"), (s(work.join("soft.key")), "a symbolic link"), (dotted, "`..`")] {
		let v = in_use(send(Method::POST, "/rules".into(), "b", files_rule(free_port(), &k)).await, what);
		let error = v["error"].as_str().unwrap();
		assert!(error.starts_with("tls.certificates[0].key_file: "), "{what}: {v}");
		assert!(!error.contains("team-a") && !error.contains(&a_port.to_string()), "says whose: {v}");
	}
	in_use(send(Method::POST, "/rules?dry_run=true".into(), "b", files_rule(free_port(), &key)).await, "dry run");
	// the certificate is public, and a copy of the key is another file
	let copy = pki.write("copy.key", &issued.key.serialize_pem());
	created(send(Method::POST, "/rules".into(), "b", files_rule(free_port(), &copy)).await, "the same certificate with a key of its own");
	// the same token, and admin, may
	created(send(Method::POST, "/rules".into(), "a", files_rule(free_port(), &key)).await, "team-a again");
	created(send(Method::POST, "/rules".into(), "admin", files_rule(free_port(), &key)).await, "admin");

	// PATCH: adding the key to a rule of its own is refused; a PATCH of team-a's rule (its
	// ports are team-b's too) that keeps the key it names is not
	let b_port = free_port();
	created(send(Method::POST, "/rules".into(), "b", rule("tcp", b_port, backend)).await, "team-b's rule");
	let with_key = json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port(),
		"tls": {"mode": "terminate", "certificates": [{"cert_file": cert, "key_file": key}]}});
	in_use(send(Method::PATCH, format!("/rules/tcp/127.0.0.1/{b_port}"), "b", with_key.clone()).await, "PATCH adding the key");
	in_use(send(Method::PATCH, format!("/rules/tcp/127.0.0.1/{b_port}?dry_run=true"), "b", with_key).await, "PATCH dry run");
	let (status, v) = send(Method::PATCH, format!("/rules/tcp/127.0.0.1/{a_port}"), "b", json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port(), "udp_idle_secs": 40})).await;
	assert_eq!(status, StatusCode::OK, "a PATCH that keeps the rule's files: {v}");

	// rule sets: another token's set may not, its owner's PUT keeps its files
	let v = in_use(send(Method::PUT, "/rulesets/b-set".into(), "b", json!({"generation": 1, "rules": [files_rule(free_port(), &key)]})).await, "team-b's set");
	assert!(v["error"].as_str().unwrap().starts_with("rules[0]: tls.certificates[0].key_file"), "{v}");
	let set_key = pki.write("set.key", &issued.key.serialize_pem());
	let set_port = free_port();
	let (status, v) = send(Method::PUT, "/rulesets/a-set".into(), "a", json!({"generation": 1, "rules": [files_rule(set_port, &set_key)]})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	in_use(send(Method::POST, "/rules".into(), "b", files_rule(free_port(), &set_key)).await, "the key of team-a's set");
	created(send(Method::POST, "/rules".into(), "a", files_rule(free_port(), &set_key)).await, "the key of its own set");
	let (status, v) = send(Method::PUT, "/rulesets/a-set".into(), "a", json!({"generation": 2, "rules": [files_rule(set_port, &set_key)]})).await;
	assert_eq!(status, StatusCode::OK, "the set's PUT keeps its file: {v}");

	// the settings file's rules, and rules restored without a known creator, are no token's
	let static_key = pki.write("static.key", &issued.key.serialize_pem());
	let spec: rproxy_api::core::rule::RuleRequest = serde_json::from_value(files_rule(free_port(), &static_key)).unwrap();
	h.registry.load_static(vec![spec]).await.unwrap();
	in_use(send(Method::POST, "/rules".into(), "a", files_rule(free_port(), &static_key)).await, "a static rule's key");
	created(send(Method::POST, "/rules".into(), "admin", files_rule(free_port(), &static_key)).await, "admin and a static rule's key");
	let restored_key = pki.write("restored.key", &issued.key.serialize_pem());
	let spec: rproxy_api::core::rule::RuleRequest = serde_json::from_value(files_rule(free_port(), &restored_key)).unwrap();
	h.registry.restore(vec![spec]).await;
	in_use(send(Method::POST, "/rules".into(), "a", files_rule(free_port(), &restored_key)).await, "a restored rule's key");

	// restored rules that share a key with another owner's run, said once (rule and field, not the path)
	logs::capture();
	let shared = free_port();
	let spec: rproxy_api::core::rule::RuleRequest = serde_json::from_value(files_rule(shared, &key)).unwrap();
	h.registry.restore(vec![spec]).await;
	let line = logs::wait_for("rule.shared_file", |l| {
		l["event"] == "rule.shared_file" && (l["rule"] == format!("tcp/127.0.0.1:{shared}") || l["other_rule"] == format!("tcp/127.0.0.1:{shared}"))
	})
	.await;
	assert!(line["field"].as_str().unwrap().ends_with("key_file"), "{line}");
	assert!(!line.to_string().contains(&key), "{line}");
	let (print, _conn) = served(&pki, shared, "o.test").await;
	assert_eq!(print, sha(issued.der().as_ref()));
	fs::remove_dir_all(work).unwrap();
}
