//! Storing rules created through the API (#144): rules of `persist: true`
//! tokens are `origin: "api"` and written to `rproxy_rules`; the table is
//! restored at startup after the UI's `forward_rules`. The database test runs
//! only when RPROXY_TEST_DATABASE_URL points at a scratch database (CI starts
//! one); it recreates `forward_rules` and `rproxy_rules`.

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{json, Value};

use rproxy_api::config::persist::Store;
use rproxy_api::control::auth::Tokens;

use common::*;

fn workdir(tag: &str) -> PathBuf {
	// keys and secrets written here must pass the owner check (net::files)
	rproxy_api::net::files::private_umask();
	let dir = std::env::temp_dir().join(format!("rproxy-persist-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn sha(s: &str) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// `ci` stores its rules, `ui` does not.
fn token_file(dir: &std::path::Path) -> PathBuf {
	let file = dir.join("tokens.yaml");
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: ci, sha256: {}, scopes: [rules:read, rules:write], persist: true}}\n  - {{name: ui, sha256: {}, scopes: [rules:read, rules:write]}}\n",
			sha("ci"),
			sha("ui")
		),
	)
	.unwrap();
	file
}

async fn call(h: &Harness, method: reqwest::Method, path: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
	let mut req = h.http.request(method, format!("{}{path}", h.base)).bearer_auth(token);
	if let Some(b) = body {
		req = req.json(&b);
	}
	let r = req.send().await.unwrap();
	let status = r.status();
	(status, r.json().await.unwrap_or(Value::Null))
}

#[tokio::test]
async fn persist_tokens_store_their_rules() {
	use reqwest::Method;
	let dir = workdir("api");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	let (_, caps) = call(&h, Method::GET, "/capabilities", "ui", None).await;
	assert_eq!(caps["features"]["persistence"], true, "{caps}");
	let backend = tcp_backend("S:").await;
	let (stored, plain) = (free_port(), free_port());

	// a dry run stores nothing
	let r = call(&h, Method::POST, "/rules?dry_run=true", "ci", Some(rule("tcp", stored, backend))).await;
	assert_eq!(r.0, StatusCode::OK);
	assert!(store.memory_rows().is_empty());

	let r = call(&h, Method::POST, "/rules", "ci", Some(rule("tcp", stored, backend))).await;
	assert_eq!(r.0, StatusCode::CREATED, "{}", r.1);
	assert_eq!((&r.1["origin"], &r.1["persisted"], &r.1["created_by"]), (&json!("api"), &json!(true), &json!("ci")), "{}", r.1);
	assert!(r.1["created_at"].as_u64().unwrap() > 1_700_000_000);
	let rows = store.memory_rows();
	assert_eq!(rows.len(), 1);
	assert_eq!((rows[0].node.as_str(), rows[0].spec.listen_port, rows[0].created_by.as_str()), ("node-a", stored, "ci"));
	assert_eq!(rows[0].spec.remote_port, backend.port());

	let r = call(&h, Method::POST, "/rules", "ui", Some(rule("tcp", plain, backend))).await;
	assert_eq!((&r.1["origin"], r.1.get("persisted")), (&json!("dynamic"), None), "not a persist token: {}", r.1);
	assert_eq!(store.memory_rows().len(), 1);

	// a change is written whichever token makes it; the creator stays
	let path = format!("/rules/tcp/127.0.0.1/{stored}");
	let r = call(&h, Method::PATCH, &path, "ui", Some(json!({"remote_addr": "127.0.0.1", "remote_port": backend.port(), "allow_from": ["127.0.0.0/8"]}))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	let rows = store.memory_rows();
	assert_eq!((rows[0].spec.allow_from.clone(), rows[0].created_by.as_str(), rows[0].updated_by.as_str()), (vec!["127.0.0.0/8".to_string()], "ci", "ui"));
	// a persist token changing a rule that is not its kind does not store it
	let r = call(&h, Method::PATCH, &format!("/rules/tcp/127.0.0.1/{plain}"), "ci", Some(json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()}))).await;
	assert_eq!((r.0, &r.1["origin"]), (StatusCode::OK, &json!("dynamic")));
	assert_eq!(store.memory_rows().len(), 1);

	// the database is out: the rule changes and runs, persisted: false
	store.fail_writes(true);
	let r = call(&h, Method::PATCH, &path, "ci", Some(json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()}))).await;
	assert_eq!((r.0, &r.1["persisted"], &r.1["state"]), (StatusCode::OK, &json!(false), &json!("running")), "{}", r.1);
	let (_, list) = call(&h, Method::GET, "/rules", "ui", None).await;
	let listed = list.as_array().unwrap().iter().find(|v| v["listen_port"] == stored).unwrap();
	assert_eq!((&listed["persisted"], &listed["created_by"]), (&json!(false), &json!("ci")));
	store.fail_writes(false);

	// deleted with the rule
	assert_eq!(call(&h, Method::DELETE, &path, "ci", None).await.0, StatusCode::NO_CONTENT);
	assert!(store.memory_rows().is_empty());
	fs::remove_dir_all(dir).unwrap();
}

/// A client that goes away before the answer (or a front's timeout) does not
/// cut a change short: the row is still written, and the periodic check never
/// takes the rule for one without a row meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_whose_client_went_away_is_still_written() {
	let dir = workdir("gone");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("n1"));
	h.registry.set_persist(store.clone());
	let backend = tcp_backend("G:").await;
	let port = free_port();
	store.delay_writes(Duration::from_millis(800));
	let sent = h
		.http
		.post(format!("{}/rules", h.base))
		.bearer_auth("ci")
		.json(&rule("tcp", port, backend))
		.timeout(Duration::from_millis(300))
		.send()
		.await;
	assert!(sent.is_err(), "the answer came before the write: {sent:?}");
	// the write is on its way: the check leaves the rule alone
	let r = store.reconcile(&h.registry).await.unwrap();
	assert_eq!(r.deleted, 0, "{r:?}");
	let deadline = Instant::now() + Duration::from_secs(5);
	while store.memory_rows().is_empty() {
		assert!(Instant::now() < deadline, "the row was not written");
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	let (_, v) = call(&h, reqwest::Method::GET, &format!("/rules/tcp/127.0.0.1/{port}"), "ci", None).await;
	assert_eq!((&v["origin"], &v["persisted"], &v["state"]), (&json!("api"), &json!(true), &json!("running")), "{v}");
	store.delay_writes(Duration::ZERO);
	let r = store.reconcile(&h.registry).await.unwrap();
	assert_eq!((r.deleted, r.replaced, r.created), (0, 0, 0), "{r:?}");
	fs::remove_dir_all(dir).unwrap();
}

/// `DELETE ?drain_secs` while a `POST` makes a new rule with the same key: the
/// old rule's row is deleted before the new one is written, so the new rule
/// keeps its row (and `persisted: true`); the drain does not hold up the `POST`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delete_with_drain_spares_a_new_rule_with_the_key() {
	let dir = workdir("drain");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("n1"));
	h.registry.set_persist(store.clone());
	let backend = tcp_backend("D:").await;
	let port = free_port();
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let (status, v) = call(&h, reqwest::Method::POST, "/rules", "ci", Some(rule("tcp", port, backend))).await;
	assert_eq!((status, &v["persisted"]), (StatusCode::CREATED, &json!(true)), "{v}");
	// a connection the old rule drains
	let mut held = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	tokio::io::AsyncWriteExt::write_all(&mut held, b"x").await.unwrap();
	let mut buf = [0u8; 8];
	let _ = tokio::io::AsyncReadExt::read(&mut held, &mut buf).await;
	let delete = tokio::spawn({
		let (http, url) = (h.http.clone(), format!("{}{path}?drain_secs=20", h.base));
		async move { http.delete(url).bearer_auth("ci").send().await.unwrap().status() }
	});
	let deadline = Instant::now() + Duration::from_secs(5);
	while call(&h, reqwest::Method::GET, &path, "ci", None).await.0 != StatusCode::NOT_FOUND {
		assert!(Instant::now() < deadline, "the rule is not taken out");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	// the new rule, while the old one drains (its listener closes right away)
	let mut body = rule("tcp", port, backend);
	body["udp_idle_secs"] = json!(4242);
	let started = Instant::now();
	let created = loop {
		let (status, v) = call(&h, reqwest::Method::POST, "/rules", "ci", Some(body.clone())).await;
		if status == StatusCode::CREATED {
			break v;
		}
		assert!(Instant::now() < deadline, "{status}: {v}");
		tokio::time::sleep(Duration::from_millis(50)).await;
	};
	assert!(started.elapsed() < Duration::from_secs(3), "the POST waited for the drain: {:?}", started.elapsed());
	assert_eq!(created["persisted"], true, "{created}");
	assert!(!delete.is_finished(), "the drain is over already");
	drop(held);
	assert_eq!(delete.await.unwrap(), StatusCode::NO_CONTENT);
	let rows = store.memory_rows();
	assert_eq!(rows.iter().map(|r| r.spec.udp_idle_secs).collect::<Vec<_>>(), [Some(4242)], "the new rule's row stays");
	let (_, v) = call(&h, reqwest::Method::GET, &path, "ci", None).await;
	assert_eq!((&v["persisted"], &v["udp_idle_secs"]), (&json!(true), &json!(4242)), "{v}");
	fs::remove_dir_all(dir).unwrap();
}

/// A live upgrade's old process lets go of the node's lock while a deletion
/// still drains (it used to wait for the drain, so the new process could not
/// write and said it was a duplicate node).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_does_not_wait_for_a_drain() {
	let dir = workdir("release");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("n1"));
	h.registry.set_persist(store.clone());
	let backend = tcp_backend("R:").await;
	let port = free_port();
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	assert_eq!(call(&h, reqwest::Method::POST, "/rules", "ci", Some(rule("tcp", port, backend))).await.0, StatusCode::CREATED);
	let mut held = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	tokio::io::AsyncWriteExt::write_all(&mut held, b"x").await.unwrap();
	let mut buf = [0u8; 8];
	let _ = tokio::io::AsyncReadExt::read(&mut held, &mut buf).await;
	let delete = tokio::spawn({
		let (http, url) = (h.http.clone(), format!("{}{path}?drain_secs=30", h.base));
		async move { http.delete(url).bearer_auth("ci").send().await.unwrap().status() }
	});
	let deadline = Instant::now() + Duration::from_secs(5);
	while call(&h, reqwest::Method::GET, &path, "ci", None).await.0 != StatusCode::NOT_FOUND {
		assert!(Instant::now() < deadline, "the rule is not taken out");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	let started = Instant::now();
	tokio::time::timeout(Duration::from_secs(3), store.release()).await.expect("release waited for the drain");
	assert!(started.elapsed() < Duration::from_secs(3));
	// the row was deleted before the drain
	assert!(store.memory_rows().is_empty());
	drop(held);
	assert_eq!(delete.await.unwrap(), StatusCode::NO_CONTENT);
	fs::remove_dir_all(dir).unwrap();
}

/// Without RPROXY_DATABASE_URL a persist token's rules are `api` but not stored.
#[tokio::test]
async fn without_a_database_nothing_is_stored() {
	let dir = workdir("nodb");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	h.registry.set_persist(Arc::new(Store::new("n".into(), None).unwrap()));
	let r = call(&h, reqwest::Method::POST, "/rules", "ci", Some(rule("tcp", free_port(), tcp_backend("N:").await))).await;
	assert_eq!((r.0, &r.1["origin"], &r.1["persisted"]), (StatusCode::CREATED, &json!("api"), &json!(false)), "{}", r.1);
	fs::remove_dir_all(dir).unwrap();
}

/// Restoring: the rows of this node come back as `api` rules; the UI's row
/// wins on the same key (`restore.conflict`).
#[tokio::test]
async fn restored_rows_are_api_rules() {
	let h = harness().await;
	let backend = tcp_backend("B:").await;
	let (mine, conflict) = (free_port(), free_port());
	let row = |port: u16, node: &str| rproxy_api::config::persist::StoredRule {
		node: node.into(),
		spec: serde_json::from_value(rule("tcp", port, backend)).unwrap(),
		spec_version: 1,
		created_by: "ci".into(),
		created_at: 1_790_000_000,
		updated_by: "ci".into(),
		updated_at: 1_790_000_000,
	};
	let store = Arc::new(Store::memory("n1"));
	h.registry.set_persist(store.clone());
	let ui = vec![serde_json::from_value(rule("tcp", conflict, backend)).unwrap()];
	let kept = rproxy_api::config::persist::without_conflicts(&ui, vec![row(mine, "n1"), row(conflict, "n1")]);
	assert_eq!(kept.len(), 1);
	h.registry.restore(ui).await;
	store.restored(&kept);
	h.registry.restore_as(kept.into_iter().map(|r| r.spec).collect(), rproxy_api::core::rule::Origin::Api).await;
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{mine}")).await;
	assert_eq!((&v["origin"], &v["persisted"], &v["created_at"]), (&json!("api"), &json!(true), &json!(1_790_000_000)), "{v}");
	let (_, v) = h.get(&format!("/rules/tcp/127.0.0.1/{conflict}")).await;
	assert_eq!(v["origin"], "dynamic");
}

/// #327: restored rules that do not validate are failed rules of `GET /rules` (the
/// reason, the body as stored, who stored it) holding their key; a PATCH that fixes
/// one starts it and writes its row, `DELETE` removes it and its row; the periodic
/// check tries a row again once it changed and forgets one that is gone.
#[tokio::test]
async fn rows_that_do_not_validate_are_failed_rules() {
	use reqwest::Method;
	use rproxy_api::config::persist::StoredRule;
	use rproxy_api::core::rule::{Key, Origin, Protocol};
	let dir = workdir("invalid");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("n1"));
	h.registry.set_persist(store.clone());
	let backend = tcp_backend("I:").await;
	let (fixed, deleted, ui) = (free_port(), free_port(), free_port());
	let bad = |port: u16| {
		let mut r = rule("tcp", port, backend);
		r["allow_from"] = json!(["not-an-address"]);
		r
	};
	let row = |spec: Value| StoredRule {
		node: "n1".into(),
		spec: serde_json::from_value(spec).unwrap(),
		spec_version: 1,
		created_by: "ci".into(),
		created_at: 1_790_000_000,
		updated_by: "ci".into(),
		updated_at: 1_790_000_000,
	};
	let rows = vec![row(bad(fixed)), row(bad(deleted))];
	for r in &rows {
		store.memory_put_row(r.clone());
	}
	h.registry.restore(vec![serde_json::from_value(bad(ui)).unwrap()]).await;
	store.restored(&rows);
	h.registry.restore_as(rows.into_iter().map(|r| r.spec).collect(), Origin::Api).await;

	// failed with the reason, the body as stored and who stored it
	let (status, list) = call(&h, Method::GET, "/rules", "ui", None).await;
	assert_eq!(status, StatusCode::OK);
	let find = |list: &Value, port: u16| list.as_array().unwrap().iter().find(|v| v["listen_port"] == port).cloned();
	let v = find(&list, fixed).expect("listed");
	assert_eq!(
		(&v["state"], &v["origin"], &v["created_by"], &v["persisted"], &v["allow_from"]),
		(&json!("failed"), &json!("api"), &json!("ci"), &json!(true), &json!(["not-an-address"])),
		"{v}"
	);
	assert!(v["error"].as_str().unwrap().contains("not-an-address"), "{v}");
	let accepted = v["conditions"].as_array().unwrap().iter().find(|c| c["type"] == "Accepted").cloned().unwrap();
	assert_eq!((&accepted["status"], &accepted["reason"]), (&json!("False"), &json!("Invalid")), "{v}");
	assert_eq!(find(&list, ui).expect("the UI's rule")["origin"], "dynamic");
	let (status, v) = call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{ui}"), "ui", None).await;
	assert_eq!((status, &v["state"]), (StatusCode::OK, &json!("failed")), "{v}");

	// it holds its key
	let (status, v) = call(&h, Method::POST, "/rules", "ci", Some(rule("tcp", fixed, backend))).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")), "{v}");
	// a PATCH that leaves it invalid changes nothing; one that fixes it starts it and writes its row
	let targets = json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port()});
	let (status, v) = call(&h, Method::PATCH, &format!("/rules/tcp/127.0.0.1/{fixed}"), "ci", Some(targets.clone())).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	let mut fix = targets.clone();
	fix["allow_from"] = json!(["127.0.0.1/32"]);
	let (status, v) = call(&h, Method::PATCH, &format!("/rules/tcp/127.0.0.1/{fixed}?dry_run=true"), "ci", Some(fix.clone())).await;
	assert_eq!((status, &v["action"]), (StatusCode::OK, &json!("update")), "{v}");
	let (status, v) = call(&h, Method::PATCH, &format!("/rules/tcp/127.0.0.1/{fixed}"), "ci", Some(fix)).await;
	assert_eq!(
		(status, &v["state"], &v["origin"], &v["persisted"], &v["created_by"]),
		(StatusCode::OK, &json!("running"), &json!("api"), &json!(true), &json!("ci")),
		"{v}"
	);
	let stored = store.memory_rows().into_iter().find(|r| r.spec.listen_port == fixed).unwrap();
	assert_eq!(stored.spec.allow_from, vec!["127.0.0.1/32".to_string()]);
	let mut conn = tokio::net::TcpStream::connect(("127.0.0.1", fixed)).await.unwrap();
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	conn.write_all(b"x").await.unwrap();
	let mut buf = [0u8; 8];
	let n = tokio::time::timeout(Duration::from_secs(3), conn.read(&mut buf)).await.unwrap().unwrap();
	assert_eq!(&buf[..n], b"I:x");

	// DELETE removes it, and its row
	let (status, _) = call(&h, Method::DELETE, &format!("/rules/tcp/127.0.0.1/{deleted}?dry_run=true"), "ci", None).await;
	assert_eq!(status, StatusCode::OK);
	let (status, v) = call(&h, Method::DELETE, &format!("/rules/tcp/127.0.0.1/{deleted}"), "ci", None).await;
	assert_eq!(status, StatusCode::NO_CONTENT, "{v}");
	assert_eq!(call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{deleted}"), "ci", None).await.0, StatusCode::NOT_FOUND);
	assert!(!store.memory_rows().iter().any(|r| r.spec.listen_port == deleted), "the row stays");
	assert_eq!(call(&h, Method::DELETE, &format!("/rules/tcp/127.0.0.1/{ui}"), "ui", None).await.0, StatusCode::NO_CONTENT);

	// the periodic check: a new row that does not validate is shown, tried again once it
	// changed (it validates now: it starts), and one whose row is gone is forgotten
	let (later, gone) = (free_port(), free_port());
	store.memory_put_row(row(bad(later)));
	store.memory_put_row(row(bad(gone)));
	store.reconcile(&h.registry).await.unwrap();
	for port in [later, gone] {
		let (status, v) = call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{port}"), "ci", None).await;
		assert_eq!((status, &v["state"]), (StatusCode::OK, &json!("failed")), "{v}");
	}
	store.reconcile(&h.registry).await.unwrap();
	store.memory_put_row(row(rule("tcp", later, backend)));
	store.memory_remove_row(&Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{gone}").parse().unwrap() });
	store.reconcile(&h.registry).await.unwrap();
	let (status, v) = call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{later}"), "ci", None).await;
	assert_eq!((status, &v["state"]), (StatusCode::OK, &json!("running")), "{v}");
	assert_eq!(call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{gone}"), "ci", None).await.0, StatusCode::NOT_FOUND);
	fs::remove_dir_all(dir).unwrap();
}

/// #327 / #323 review: the files of a restored rule that did not validate are its
/// owner's (another token may not name its key; its owner's fixing PATCH keeps it);
/// deleting it forgets who made it and lets the same row be looked at again; it counts
/// in `/metrics`; a restored rule set wins over it at startup.
#[tokio::test]
async fn invalid_rules_keep_their_files_and_count() {
	use reqwest::Method;
	use rproxy_api::config::persist::{StoredRule, StoredSet};
	use rproxy_api::core::rule::{Key, Origin, Protocol};
	let dir = workdir("invalid-files");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("n1"));
	h.registry.set_persist(store.clone());
	let pki = common::pki::Pki::new("persist-invalid");
	let issued = pki.server("i.pem", &["i.test"]);
	let cert = pki.write("i.crt", &issued.cert.pem());
	let key_file = pki.write("i.key", &issued.key.serialize_pem());
	let backend = tcp_backend("K:").await;
	let with_key = |port: u16| {
		let mut r = rule("tcp", port, backend);
		r["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert, "key_file": key_file}]});
		r
	};
	let row = |spec: Value| StoredRule {
		node: "n1".into(),
		spec: serde_json::from_value(spec).unwrap(),
		spec_version: 1,
		created_by: "ci".into(),
		created_at: 1_790_000_000,
		updated_by: "ci".into(),
		updated_at: 1_790_000_000,
	};
	let (mine, shared, set_port, kept_port, put_port) = (free_port(), free_port(), free_port(), free_port(), free_port());
	let mut bad = with_key(mine);
	bad["allow_from"] = json!(["not-an-address"]);
	let mut bad_set_key = rule("tcp", set_port, backend);
	bad_set_key["allow_from"] = json!(["not-an-address"]);
	let invalid_at = |port: u16| {
		let mut r = rule("tcp", port, backend);
		r["allow_from"] = json!(["not-an-address"]);
		r
	};
	let rows = vec![row(bad.clone()), row(bad_set_key), row(invalid_at(kept_port)), row(invalid_at(put_port))];
	for r in &rows {
		store.memory_put_row(r.clone());
	}
	store.restored(&rows);
	h.registry.restore_as(rows.into_iter().map(|r| r.spec).collect(), Origin::Api).await;
	// a rule set restored after them wins over the one with its key
	let set = StoredSet {
		name: "ci/set".into(),
		generation: 1,
		etag: String::new(),
		owner: "ci".into(),
		rules: vec![serde_json::from_value(rule("tcp", set_port, backend)).unwrap()],
		spec_version: 1,
		updated_by: "ci".into(),
		updated_at: 1_790_000_000,
	};
	// a set whose rule with the key of another one is left out (it does not validate here either)
	let leaves_out = StoredSet {
		name: "ci/leaves-out".into(),
		generation: 1,
		etag: String::new(),
		owner: "ci".into(),
		rules: vec![serde_json::from_value(invalid_at(kept_port)).unwrap(), serde_json::from_value(rule("tcp", free_port(), backend)).unwrap()],
		spec_version: 1,
		updated_by: "ci".into(),
		updated_at: 1_790_000_000,
	};
	assert_eq!(h.registry.restore_rulesets(vec![set, leaves_out]).await, 2);
	let (status, v) = call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{set_port}"), "ci", None).await;
	assert_eq!((status, &v["state"], &v["ruleset"]), (StatusCode::OK, &json!("running"), &json!("ci/set")), "{v}");
	let set_key = Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{set_port}").parse().unwrap() };
	assert_eq!(store.created_by(&set_key), None, "the row's created_by is forgotten once the set took the key");
	let (status, v) = call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{kept_port}"), "ci", None).await;
	assert_eq!((status, &v["state"], &v["origin"], &v["created_by"]), (StatusCode::OK, &json!("failed"), &json!("api"), &json!("ci")), "kept: {v}");
	// a PUT of a set with its key: refused up front as for any rule outside the set
	let (status, v) = call(&h, Method::PUT, "/rulesets/ci/other", "ci", Some(json!({"generation": 1, "rules": [rule("tcp", put_port, backend)]}))).await;
	assert_eq!((status, v["errors"][0]["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")), "{v}");
	assert!(v["errors"][0]["message"].as_str().unwrap().contains("does not belong to this rule set"), "{v}");

	// counted in /metrics
	let text = h.registry.metrics().await;
	assert!(text.contains(&format!("rproxy_rule_up{{protocol=\"tcp\",listen=\"127.0.0.1:{mine}\"}} 0")), "{text}");
	assert!(text.contains("rproxy_rules{state=\"failed\"} 3"), "{text}");

	// another token may not name its key
	let (status, v) = call(&h, Method::POST, "/rules", "ui", Some(with_key(free_port()))).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("file_in_use")), "{v}");
	// a restored rule of no known creator shares it (from before); the owner's fix keeps the key
	h.registry.restore(vec![serde_json::from_value(with_key(shared)).unwrap()]).await;
	let fix = json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port(), "allow_from": []});
	let (status, v) = call(&h, Method::PATCH, &format!("/rules/tcp/127.0.0.1/{mine}"), "ci", Some(fix)).await;
	assert_eq!((status, &v["state"]), (StatusCode::OK, &json!("running")), "{v}");

	// deleted: who made it is forgotten, and the same row coming back is shown again
	let again = free_port();
	let mut bad = rule("tcp", again, backend);
	bad["allow_from"] = json!(["not-an-address"]);
	store.memory_put_row(row(bad.clone()));
	store.reconcile(&h.registry).await.unwrap();
	assert_eq!(call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{again}"), "ci", None).await.1["state"], "failed");
	let key = Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{again}").parse().unwrap() };
	// as a live upgrade hands it over
	h.registry.set_owner(key, "ui");
	assert_eq!(call(&h, Method::DELETE, &format!("/rules/tcp/127.0.0.1/{again}"), "ci", None).await.0, StatusCode::NO_CONTENT);
	assert!(!h.registry.owners().iter().any(|(k, _)| *k == key));
	store.memory_put_row(row(bad));
	store.reconcile(&h.registry).await.unwrap();
	let (status, v) = call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{again}"), "ci", None).await;
	assert_eq!((status, &v["state"]), (StatusCode::OK, &json!("failed")), "the same row again: {v}");
	fs::remove_dir_all(dir).unwrap();
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
	fn start(dir: &std::path::Path, port: u16, url: &str, tag: &str) -> Rproxy {
		let out = dir.join(format!("{tag}.log"));
		let child = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(dir)
			.env_clear()
			.env("RPROXY_API_PORT", port.to_string())
			.env("RPROXY_DATABASE_URL", url)
			.env("RPROXY_NODE_NAME", "node-a")
			.env("RPROXY_TOKEN_FILE", dir.join("tokens.yaml"))
			.stdout(fs::File::create(&out).unwrap())
			.stderr(Stdio::null())
			.spawn()
			.unwrap();
		Rproxy { child, out }
	}

	fn log(&self) -> String {
		fs::read_to_string(&self.out).unwrap_or_default()
	}

	/// Until the log has `needle`: rproxy writes its log from another thread (tracing's non_blocking), so a
	/// line can land after the API has answered.
	async fn wait_log(&self, needle: &str) {
		let deadline = Instant::now() + Duration::from_secs(10);
		while !self.log().contains(needle) {
			assert!(Instant::now() < deadline, "no {needle} in the log:\n{}", self.log());
			tokio::time::sleep(Duration::from_millis(50)).await;
		}
	}

	async fn wait(&self, port: u16) {
		let deadline = Instant::now() + Duration::from_secs(20);
		loop {
			let r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/rules")).bearer_auth("ci").send().await;
			if r.is_ok_and(|r| r.status() == StatusCode::OK) && self.log().contains("restore.done") {
				return;
			}
			assert!(Instant::now() < deadline, "did not start:\n{}", self.log());
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
}

/// The DDL in docs/API.md (the UI repository's db/ migration creates it).
const RPROXY_RULES: &str = "CREATE TABLE rproxy_rules (
	node         VARCHAR(255) NOT NULL,
	protocol     VARCHAR(3)   NOT NULL,
	listen_addr  VARCHAR(45)  NOT NULL,
	listen_port  INT UNSIGNED NOT NULL,
	spec         JSON         NOT NULL,
	spec_version INT UNSIGNED NOT NULL DEFAULT 1,
	created_by   VARCHAR(255) NOT NULL,
	created_at   DATETIME(3)  NOT NULL,
	updated_by   VARCHAR(255) NOT NULL,
	updated_at   DATETIME(3)  NOT NULL,
	PRIMARY KEY (node, protocol, listen_addr, listen_port)
)";

const FORWARD_RULES: &str = "CREATE TABLE forward_rules (
	id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
	auth_id VARCHAR(255) NOT NULL,
	protocol VARCHAR(3) NOT NULL,
	src_addr VARCHAR(45) NOT NULL,
	src_port INT NOT NULL,
	src_port_end INT NULL,
	dist_addr VARCHAR(253) NOT NULL,
	dist_port INT NOT NULL,
	source_ip VARCHAR(16) NOT NULL DEFAULT 'proxy',
	udp_idle_secs INT NOT NULL DEFAULT 30,
	options JSON NULL
)";

/// The database tests recreate the same tables: one at a time.
static DB: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The real binary with MariaDB: a rule made by a persist token survives a
/// restart; the UI's row wins on the same key; other nodes' rows stay out.
#[tokio::test]
async fn rules_survive_a_restart_with_mariadb() {
	use sqlx::Executor;
	let Ok(url) = std::env::var("RPROXY_TEST_DATABASE_URL") else {
		eprintln!("skipping: RPROXY_TEST_DATABASE_URL is not set");
		return;
	};
	let _db = DB.lock().await;
	let pool = sqlx::mysql::MySqlPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
	pool.execute("DROP TABLE IF EXISTS forward_rules").await.unwrap();
	pool.execute("DROP TABLE IF EXISTS rproxy_rules").await.unwrap();
	pool.execute(FORWARD_RULES).await.unwrap();
	pool.execute(RPROXY_RULES).await.unwrap();

	let dir = workdir("db");
	token_file(&dir);
	let backend = tcp_backend("M:").await;
	let (api_port, stored, conflict, elsewhere) = (free_port(), free_port(), free_port(), free_port());
	// another node's row, and the UI's rule on a key rproxy_rules also has
	let spec = |port: u16| rule("tcp", port, backend).to_string();
	sqlx::query(
		"INSERT INTO rproxy_rules (node, protocol, listen_addr, listen_port, spec, spec_version, created_by, created_at, updated_by, updated_at)
		 VALUES ('node-b', 'tcp', '127.0.0.1', ?, ?, 1, 'x', NOW(3), 'x', NOW(3)),
		        ('node-a', 'tcp', '127.0.0.1', ?, ?, 1, 'x', NOW(3), 'x', NOW(3))",
	)
	.bind(u32::from(elsewhere))
	.bind(spec(elsewhere))
	.bind(u32::from(conflict))
	.bind(spec(conflict))
	.execute(&pool)
	.await
	.unwrap();
	sqlx::query("INSERT INTO forward_rules (auth_id, protocol, src_addr, src_port, dist_addr, dist_port) VALUES ('u', 'tcp', '127.0.0.1', ?, ?, ?)")
		.bind(i32::from(conflict))
		.bind(backend.ip().to_string())
		.bind(i32::from(backend.port()))
		.execute(&pool)
		.await
		.unwrap();

	let client = reqwest::Client::new();
	let base = format!("http://127.0.0.1:{api_port}");
	{
		let rp = Rproxy::start(&dir, api_port, &url, "first");
		rp.wait(api_port).await;
		rp.wait_log("restore.conflict").await;
		let r = client.post(format!("{base}/rules")).bearer_auth("ci").json(&rule("tcp", stored, backend)).send().await.unwrap();
		assert_eq!(r.status(), StatusCode::CREATED);
		let v: Value = r.json().await.unwrap();
		assert_eq!((&v["origin"], &v["persisted"]), (&json!("api"), &json!(true)), "{v}\n{}", rp.log());
		let r = client
			.patch(format!("{base}/rules/tcp/127.0.0.1/{stored}"))
			.bearer_auth("ci")
			.json(&json!({"remote_addr": "127.0.0.1", "remote_port": backend.port(), "udp_idle_secs": 77}))
			.send()
			.await
			.unwrap();
		assert_eq!(r.status(), StatusCode::OK);
	}
	let row: (String, String, i64) = sqlx::query_as(
		"SELECT CAST(spec AS CHAR), created_by, CAST(spec_version AS SIGNED) FROM rproxy_rules WHERE node = 'node-a' AND listen_port = ?",
	)
	.bind(u32::from(stored))
	.fetch_one(&pool)
	.await
	.unwrap();
	let spec: Value = serde_json::from_str(&row.0).unwrap();
	assert_eq!((&spec["udp_idle_secs"], row.1.as_str(), row.2), (&json!(77), "ci", 1), "{spec}");

	{
		let rp = Rproxy::start(&dir, api_port, &url, "second");
		rp.wait(api_port).await;
		let get = |port: u16| client.get(format!("{base}/rules/tcp/127.0.0.1/{port}")).bearer_auth("ci").send();
		let v: Value = get(stored).await.unwrap().json().await.unwrap();
		assert_eq!((&v["origin"], &v["persisted"], &v["created_by"], &v["udp_idle_secs"]), (&json!("api"), &json!(true), &json!("ci"), &json!(77)), "{v}");
		let v: Value = get(conflict).await.unwrap().json().await.unwrap();
		assert_eq!(v["origin"], "dynamic", "the UI's rule: {v}");
		assert_eq!(get(elsewhere).await.unwrap().status(), StatusCode::NOT_FOUND, "another node's row");

		let r = client.delete(format!("{base}/rules/tcp/127.0.0.1/{stored}")).bearer_auth("ci").send().await.unwrap();
		assert_eq!(r.status(), StatusCode::NO_CONTENT);
	}
	let left: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM rproxy_rules WHERE node = 'node-a' AND listen_port = ?")
		.bind(u32::from(stored))
		.fetch_one(&pool)
		.await
		.unwrap();
	assert_eq!(left.0, 0);
	pool.execute("DROP TABLE rproxy_rules").await.unwrap();
	pool.execute("DROP TABLE forward_rules").await.unwrap();
	fs::remove_dir_all(dir).unwrap();
}

/// The DDL of `rproxy_global` in docs/API.md (#342; the UI repository's migration 013).
const RPROXY_GLOBAL: &str = "CREATE TABLE rproxy_global (
	node         VARCHAR(255) NOT NULL,
	spec         JSON         NOT NULL,
	spec_version INT UNSIGNED NOT NULL DEFAULT 1,
	updated_by   VARCHAR(255) NOT NULL,
	updated_at   DATETIME(3)  NOT NULL,
	PRIMARY KEY (node)
)";

/// #342 with the real binary and MariaDB: `PATCH /config/global` writes the row of
/// `rproxy_global` before the answer (without the table: `persisted: false`, in force
/// anyway); a restart reads it back before the rules.
#[tokio::test]
async fn global_values_survive_a_restart_with_mariadb() {
	use sqlx::Executor;
	let Ok(url) = std::env::var("RPROXY_TEST_DATABASE_URL") else {
		eprintln!("skipping: RPROXY_TEST_DATABASE_URL is not set");
		return;
	};
	let _db = DB.lock().await;
	let pool = sqlx::mysql::MySqlPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
	for drop in ["DROP TABLE IF EXISTS forward_rules", "DROP TABLE IF EXISTS rproxy_rules", "DROP TABLE IF EXISTS rproxy_global"] {
		pool.execute(drop).await.unwrap();
	}
	pool.execute(FORWARD_RULES).await.unwrap();
	pool.execute(RPROXY_RULES).await.unwrap();
	let dir = workdir("db-global");
	fs::write(
		dir.join("tokens.yaml"),
		format!("tokens:\n  - {{name: ci, sha256: {}, scopes: [admin, rules:read, rules:write], persist: true}}\n", sha("ci")),
	)
	.unwrap();
	let api_port = free_port();
	let client = reqwest::Client::new();
	let base = format!("http://127.0.0.1:{api_port}");
	let patch = |body: Value| client.patch(format!("{base}/config/global")).bearer_auth("ci").json(&body).send();
	{
		let rp = Rproxy::start(&dir, api_port, &url, "first");
		rp.wait(api_port).await;
		// before migration 013: in force, not stored
		let r = patch(json!({"trusted_proxies": ["192.0.2.0/24"]})).await.unwrap();
		assert_eq!(r.status(), StatusCode::OK);
		let v: Value = r.json().await.unwrap();
		assert_eq!((&v["persisted"], &v["storage"], &v["items"]["trusted_proxies"]["source"]), (&json!(false), &json!("database"), &json!("api")), "{v}");
		pool.execute(RPROXY_GLOBAL).await.unwrap();
		let r = patch(json!({"http": {"timeouts": {"idle": "42s"}}})).await.unwrap();
		let v: Value = r.json().await.unwrap();
		assert_eq!(v["persisted"], true, "{v}\n{}", rp.log());
	}
	let row: (String, String, i64) =
		sqlx::query_as("SELECT CAST(spec AS CHAR), updated_by, CAST(spec_version AS SIGNED) FROM rproxy_global WHERE node = 'node-a'")
			.fetch_one(&pool)
			.await
			.unwrap();
	let spec: Value = serde_json::from_str(&row.0).unwrap();
	assert_eq!((&spec, row.1.as_str(), row.2), (&json!({"trusted_proxies": ["192.0.2.0/24"], "http": {"timeouts": {"idle": "42s"}}}), "ci", 1));
	{
		let rp = Rproxy::start(&dir, api_port, &url, "second");
		rp.wait(api_port).await;
		rp.wait_log("restore.global").await;
		let v: Value = client.get(format!("{base}/config/global")).bearer_auth("ci").send().await.unwrap().json().await.unwrap();
		assert_eq!(
			(&v["items"]["trusted_proxies"]["value"], &v["items"]["http.timeouts"]["source"], &v["persisted"], &v["updated_by"]),
			(&json!(["192.0.2.0/24"]), &json!("api"), &json!(true), &json!("ci")),
			"{v}"
		);
	}
	for drop in ["DROP TABLE IF EXISTS forward_rules", "DROP TABLE IF EXISTS rproxy_rules", "DROP TABLE IF EXISTS rproxy_global"] {
		pool.execute(drop).await.unwrap();
	}
	fs::remove_dir_all(dir).unwrap();
}

/// #327 with the real binary and MariaDB: a row of `rproxy_rules` and one of
/// `forward_rules` that do not validate are failed rules of `GET /rules`; a PATCH
/// fixes the first and writes its row (it runs after a restart), `DELETE` removes the
/// second until the next start (rproxy does not write `forward_rules`).
#[tokio::test]
async fn rows_that_do_not_validate_with_mariadb() {
	use sqlx::Executor;
	let Ok(url) = std::env::var("RPROXY_TEST_DATABASE_URL") else {
		eprintln!("skipping: RPROXY_TEST_DATABASE_URL is not set");
		return;
	};
	let _db = DB.lock().await;
	let pool = sqlx::mysql::MySqlPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
	pool.execute("DROP TABLE IF EXISTS forward_rules").await.unwrap();
	pool.execute("DROP TABLE IF EXISTS rproxy_rules").await.unwrap();
	pool.execute(FORWARD_RULES).await.unwrap();
	pool.execute(RPROXY_RULES).await.unwrap();

	let dir = workdir("db-invalid");
	token_file(&dir);
	let backend = tcp_backend("V:").await;
	let (api_port, stored, ui) = (free_port(), free_port(), free_port());
	let mut bad = rule("tcp", stored, backend);
	bad["allow_from"] = json!(["not-an-address"]);
	sqlx::query(
		"INSERT INTO rproxy_rules (node, protocol, listen_addr, listen_port, spec, spec_version, created_by, created_at, updated_by, updated_at)
		 VALUES ('node-a', 'tcp', '127.0.0.1', ?, ?, 1, 'ci', NOW(3), 'ci', NOW(3))",
	)
	.bind(u32::from(stored))
	.bind(bad.to_string())
	.execute(&pool)
	.await
	.unwrap();
	// remote_port 0
	sqlx::query("INSERT INTO forward_rules (auth_id, protocol, src_addr, src_port, dist_addr, dist_port) VALUES ('u', 'tcp', '127.0.0.1', ?, ?, 0)")
		.bind(i32::from(ui))
		.bind(backend.ip().to_string())
		.execute(&pool)
		.await
		.unwrap();

	let client = reqwest::Client::new();
	let base = format!("http://127.0.0.1:{api_port}");
	let get = |port: u16| client.get(format!("{base}/rules/tcp/127.0.0.1/{port}")).bearer_auth("ci").send();
	{
		let rp = Rproxy::start(&dir, api_port, &url, "first");
		rp.wait(api_port).await;
		let v: Value = get(stored).await.unwrap().json().await.unwrap();
		assert_eq!((&v["state"], &v["origin"], &v["created_by"]), (&json!("failed"), &json!("api"), &json!("ci")), "{v}\n{}", rp.log());
		assert!(v["error"].as_str().unwrap().contains("not-an-address"), "{v}");
		let v: Value = get(ui).await.unwrap().json().await.unwrap();
		assert_eq!((&v["state"], &v["origin"]), (&json!("failed"), &json!("dynamic")), "{v}");
		assert!(v["error"].as_str().unwrap().contains("remote_port"), "{v}");
		let r = client
			.patch(format!("{base}/rules/tcp/127.0.0.1/{stored}"))
			.bearer_auth("ci")
			.json(&json!({"remote_addr": "127.0.0.1", "remote_port": backend.port(), "allow_from": ["127.0.0.0/8"]}))
			.send()
			.await
			.unwrap();
		assert_eq!(r.status(), StatusCode::OK);
		let v: Value = r.json().await.unwrap();
		assert_eq!((&v["state"], &v["persisted"]), (&json!("running"), &json!(true)), "{v}");
		let r = client.delete(format!("{base}/rules/tcp/127.0.0.1/{ui}")).bearer_auth("ui").send().await.unwrap();
		assert_eq!(r.status(), StatusCode::NO_CONTENT);
		assert_eq!(get(ui).await.unwrap().status(), StatusCode::NOT_FOUND);
	}
	let row: (String, String) = sqlx::query_as("SELECT CAST(spec AS CHAR), created_by FROM rproxy_rules WHERE node = 'node-a' AND listen_port = ?")
		.bind(u32::from(stored))
		.fetch_one(&pool)
		.await
		.unwrap();
	let spec: Value = serde_json::from_str(&row.0).unwrap();
	assert_eq!((&spec["allow_from"], row.1.as_str()), (&json!(["127.0.0.0/8"]), "ci"), "{spec}");
	{
		let rp = Rproxy::start(&dir, api_port, &url, "second");
		rp.wait(api_port).await;
		let v: Value = get(stored).await.unwrap().json().await.unwrap();
		assert_eq!((&v["state"], &v["origin"]), (&json!("running"), &json!("api")), "{v}");
		let v: Value = get(ui).await.unwrap().json().await.unwrap();
		assert_eq!(v["state"], "failed", "the UI's row comes back: {v}");
	}
	pool.execute("DROP TABLE rproxy_rules").await.unwrap();
	pool.execute("DROP TABLE forward_rules").await.unwrap();
	fs::remove_dir_all(dir).unwrap();
}

/// `--node-name` is checked at startup.
#[test]
fn a_blank_node_name_stops_the_startup() {
	let dir = workdir("node");
	let out = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.current_dir(&dir)
		.env_clear()
		.env("RPROXY_API_PORT", "0")
		.env("RPROXY_API_SOCKET", dir.join("api.sock"))
		.env("RPROXY_NODE_NAME", "  ")
		.output()
		.unwrap();
	let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
	assert!(!out.status.success() && text.contains("--node-name"), "{text}");
	fs::remove_dir_all(dir).unwrap();
}
