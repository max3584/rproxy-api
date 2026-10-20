//! Storing rule sets (#241, v0.4.2, docs/DESIGN-v0.4.x.md 4.): a set PUT by a
//! `persist: true` token is written to `rproxy_rule_sets` (one row, the rules
//! as JSON) and restored at startup before `/readyz` turns ready. The database
//! test runs only when RPROXY_TEST_DATABASE_URL points at a scratch database
//! (CI starts one); it recreates the tables.

mod common;

use std::fs;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

use rproxy_api::config::persist::{Store, StoredSet};
use rproxy_api::control::auth::Tokens;

use common::*;

fn workdir(tag: &str) -> PathBuf {
	rproxy_api::net::files::private_umask();
	let dir = std::env::temp_dir().join(format!("rproxy-setstore-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn sha(s: &str) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// `ci` stores its sets; `ctl` (a controller) does not; `root` is an admin without persist.
fn token_file(dir: &std::path::Path) -> PathBuf {
	let file = dir.join("tokens.yaml");
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: ci, sha256: {}, scopes: [rules:read, rules:write], persist: true}}\n  - {{name: ctl, sha256: {}, scopes: [rules:read, rules:write]}}\n  - {{name: root, sha256: {}, scopes: [admin]}}\n",
			sha("ci"),
			sha("ctl"),
			sha("root")
		),
	)
	.unwrap();
	file
}

async fn call(h: &Harness, method: Method, path: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
	let mut req = h.http.request(method, format!("{}{path}", h.base)).bearer_auth(token);
	if let Some(b) = body {
		req = req.json(&b);
	}
	let r = req.send().await.unwrap();
	let status = r.status();
	(status, r.json().await.unwrap_or(Value::Null))
}

fn set(generation: u64, rules: Vec<Value>) -> Value {
	json!({"generation": generation, "rules": rules})
}

/// `DELETE /rulesets/a?drain_secs` drains: a `PUT` of another set meanwhile
/// is neither held up by the drain nor holds up a live upgrade's `release`, and
/// its row is written (it used to wait for the drain holding the changes'
/// shared lock, so `release` gave up and the change was written nowhere).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_set_draining_holds_up_neither_other_sets_nor_the_release() {
	let dir = workdir("drain");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	let backend = tcp_backend("D:").await;
	let (a, b) = (free_port(), free_port());
	let r = call(&h, Method::PUT, "/rulesets/ci/a", "ci", Some(set(1, vec![rule("tcp", a, backend)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	// a connection the set's rule drains
	let mut held = tokio::net::TcpStream::connect(("127.0.0.1", a)).await.unwrap();
	tokio::io::AsyncWriteExt::write_all(&mut held, b"x").await.unwrap();
	let mut buf = [0u8; 8];
	let _ = tokio::io::AsyncReadExt::read(&mut held, &mut buf).await;
	let delete = tokio::spawn({
		let (http, url) = (h.http.clone(), format!("{}/rulesets/ci/a?drain_secs=60", h.base));
		async move { http.delete(url).bearer_auth("ci").send().await.unwrap().status() }
	});
	let deadline = Instant::now() + Duration::from_secs(5);
	while call(&h, Method::GET, "/rulesets/ci/a", "ci", None).await.0 != StatusCode::NOT_FOUND {
		assert!(Instant::now() < deadline, "the set is not taken out");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	let started = Instant::now();
	let r = call(&h, Method::PUT, "/rulesets/ci/b", "ci", Some(set(1, vec![rule("tcp", b, backend)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	assert!(started.elapsed() < Duration::from_secs(3), "the PUT waited for the drain: {:?}", started.elapsed());
	tokio::time::timeout(Duration::from_secs(3), store.release()).await.expect("release waited for the drain");
	assert!(!delete.is_finished(), "the drain is over already");
	let names: Vec<String> = store.memory_sets().into_iter().map(|s| s.name).collect();
	assert_eq!(names, ["ci/b"], "a's row is gone, b's written");
	drop(held);
	assert_eq!(delete.await.unwrap(), StatusCode::NO_CONTENT);
	fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn persist_tokens_store_their_sets() {
	let dir = workdir("api");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	let (_, caps) = call(&h, Method::GET, "/capabilities", "ci", None).await;
	assert_eq!(caps["features"]["ruleset_persistence"], true, "{caps}");
	let backend = tcp_backend("S:").await;
	let (a, b, c) = (free_port(), free_port(), free_port());

	// a dry run writes nothing
	let r = call(&h, Method::PUT, "/rulesets/ci/web?dry_run=true", "ci", Some(set(1, vec![rule("tcp", a, backend)]))).await;
	assert_eq!(r.0, StatusCode::OK, "{}", r.1);
	assert!(store.memory_sets().is_empty());

	let r = call(&h, Method::PUT, "/rulesets/ci/web", "ci", Some(set(3, vec![rule("tcp", a, backend), rule("tcp", b, backend)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	let etag = r.1["etag"].as_str().unwrap().to_string();
	let rows = store.memory_sets();
	assert_eq!(rows.len(), 1);
	let row = &rows[0];
	assert_eq!((row.name.as_str(), row.generation, row.etag.as_str(), row.owner.as_str(), row.updated_by.as_str()), ("ci/web", 3, etag.as_str(), "ci", "ci"));
	assert_eq!(row.rules.iter().map(|r| r.listen_port).collect::<Vec<_>>(), [a, b]);
	let (_, view) = call(&h, Method::GET, "/rulesets/ci/web", "ci", None).await;
	assert_eq!(view["persisted"], true, "{view}");
	let (_, list) = call(&h, Method::GET, "/rulesets", "ci", None).await;
	assert_eq!(list[0]["persisted"], true, "{list}");

	// a controller's set (no persist) stays in memory only
	let r = call(&h, Method::PUT, "/rulesets/k8s/gw", "ctl", Some(set(1, vec![rule("tcp", c, backend)]))).await;
	assert_eq!(r.0, StatusCode::OK, "{}", r.1);
	assert!(r.1.get("persisted").is_none(), "{}", r.1);
	assert_eq!(store.memory_sets().len(), 1);
	let (_, view) = call(&h, Method::GET, "/rulesets/k8s/gw", "ctl", None).await;
	assert!(view.get("persisted").is_none(), "{view}");

	// an admin without persist changes the stored set: the row follows
	let r = call(&h, Method::PUT, "/rulesets/ci/web", "root", Some(set(4, vec![rule("tcp", a, backend)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	let row = store.memory_sets().pop().unwrap();
	assert_eq!((row.generation, row.owner.as_str(), row.updated_by.as_str(), row.rules.len()), (4, "ci", "root", 1));

	// the database is out: the set changes and runs, persisted: false
	store.fail_writes(true);
	let r = call(&h, Method::PUT, "/rulesets/ci/web", "ci", Some(set(5, vec![rule("tcp", a, backend), rule("tcp", b, backend)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(false)), "{}", r.1);
	assert_eq!(call(&h, Method::GET, "/rulesets/ci/web", "ci", None).await.1["persisted"], false);
	store.fail_writes(false);

	// deleted with the set
	assert_eq!(call(&h, Method::DELETE, "/rulesets/ci/web", "ci", None).await.0, StatusCode::NO_CONTENT);
	assert!(store.memory_sets().is_empty());
	fs::remove_dir_all(dir).unwrap();
}

/// Restoring: a stored set comes back with its generation, etag and owner; a
/// rule whose key is taken already is left out, the rest of the set applies.
#[tokio::test]
async fn stored_sets_are_restored() {
	let dir = workdir("restore");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let backend = tcp_backend("R:").await;
	let (a, b, taken) = (free_port(), free_port(), free_port());

	// the etag a PUT gives these rules, from a first registry
	let first = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let r = call(&first, Method::PUT, "/rulesets/ci/app", "ci", Some(set(7, vec![rule("tcp", a, backend), rule("tcp", b, backend)]))).await;
	let etag = r.1["etag"].as_str().unwrap().to_string();
	assert_eq!(call(&first, Method::DELETE, "/rulesets/ci/app", "ci", None).await.0, StatusCode::NO_CONTENT);

	let req = |port: u16| serde_json::from_value(rule("tcp", port, backend)).unwrap();
	let store = Arc::new(Store::memory("node-a"));
	store.memory_put_set(StoredSet {
		name: "ci/app".into(),
		generation: 7,
		etag: etag.clone(),
		owner: "ci".into(),
		rules: vec![req(a), req(b)],
		spec_version: 1,
		updated_by: "ci".into(),
		updated_at: 1,
	});
	store.memory_put_set(StoredSet {
		name: "ci/clash".into(),
		generation: 2,
		etag: "g2-0".into(),
		owner: "ci".into(),
		rules: vec![req(taken), req(free_port())],
		spec_version: 1,
		updated_by: "ci".into(),
		updated_at: 1,
	});
	h.registry.set_persist(store.clone());
	// restored before: the UI's rule on `taken`
	h.registry.restore(vec![req(taken)]).await;
	let restored = h.registry.restore_rulesets(store.load_sets().await.unwrap()).await;
	assert_eq!(restored, 2);

	let (_, v) = call(&h, Method::GET, "/rulesets/ci/app", "ci", None).await;
	assert_eq!((&v["generation"], &v["etag"], &v["owner"]), (&json!(7), &json!(etag), &json!("ci")), "{v}");
	assert_eq!(v["rules"].as_array().unwrap().len(), 2);
	let (_, v) = call(&h, Method::GET, "/rulesets/ci/clash", "ci", None).await;
	assert_eq!(v["rules"].as_array().unwrap().len(), 1, "the taken key is left out: {v}");
	let (_, r) = call(&h, Method::GET, &format!("/rules/tcp/127.0.0.1/{taken}"), "ci", None).await;
	assert!(r.get("ruleset").is_none(), "the earlier rule keeps its key: {r}");
	// the owner is restored: another non-admin token may not change it
	let r = call(&h, Method::PUT, "/rulesets/ci/app", "ctl", Some(set(8, vec![]))).await;
	assert_eq!(r.0, StatusCode::FORBIDDEN, "{}", r.1);
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

	/// Until `/readyz` is 200 (the restore is done).
	async fn ready(&self, port: u16) {
		let deadline = Instant::now() + Duration::from_secs(20);
		loop {
			let r = reqwest::Client::new().get(format!("http://127.0.0.1:{port}/readyz")).send().await;
			if r.is_ok_and(|r| r.status() == StatusCode::OK) {
				return;
			}
			assert!(Instant::now() < deadline, "not ready:\n{}", self.log());
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
}

/// The DDL in docs/API.md (the UI repository's migration 012 creates it).
const RPROXY_RULE_SETS: &str = "CREATE TABLE rproxy_rule_sets (
	node         VARCHAR(255) NOT NULL,
	name         VARCHAR(253) NOT NULL,
	generation   BIGINT UNSIGNED NOT NULL,
	etag         VARCHAR(64)  NOT NULL,
	owner        VARCHAR(255) NOT NULL,
	rules        JSON         NOT NULL,
	spec_version INT UNSIGNED NOT NULL DEFAULT 1,
	updated_by   VARCHAR(255) NOT NULL,
	updated_at   DATETIME(3)  NOT NULL,
	PRIMARY KEY (node, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

/// A rule that sends `port` to 127.0.0.1:`remote` (the remote tells the versions of a set apart).
fn to(port: u16, remote: u16) -> Value {
	rule("tcp", port, std::net::SocketAddr::from(([127, 0, 0, 1], remote)))
}

/// Waits until the set's row has the running set's rules and the set says
/// `persisted: true` (and fails if it never does).
async fn row_follows_the_set(h: &Harness, store: &Store, name: &str) {
	let deadline = Instant::now() + Duration::from_secs(5);
	loop {
		let (_, view) = call(h, Method::GET, &format!("/rulesets/{name}"), "ci", None).await;
		let running: Vec<u64> = view["rules"].as_array().unwrap().iter().map(|r| r["remote_port"].as_u64().unwrap()).collect();
		let row: Option<Vec<u64>> =
			store.memory_sets().into_iter().find(|s| s.name == name).map(|s| s.rules.iter().map(|r| u64::from(r.remote_port)).collect());
		if row.as_ref() == Some(&running) && view["persisted"] == true {
			return;
		}
		assert!(
			Instant::now() < deadline,
			"the row {row:?} and the running set {running:?} (persisted: {}) do not agree",
			view["persisted"]
		);
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
}

/// Two `PUT`s of the same generation at once (#306): the one that read the set
/// first queues its row last. The row is read with the queueing (under the
/// store's order), so the row ends up as the set that runs, and `persisted`
/// says so (it used to keep the older rules while saying `persisted: true`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_puts_of_the_same_generation_leave_the_row_of_the_set_that_runs() {
	let dir = workdir("same-gen");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	let a = free_port();
	let r = call(&h, Method::PUT, "/rulesets/ci/a", "ci", Some(set(1, vec![to(a, 1001)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	// the first PUT has changed the set and waits before it writes the row
	let (arrived, go) = store.pause_next_set_write();
	let first = tokio::spawn({
		let (base, http) = (h.base.clone(), h.http.clone());
		async move {
			let r = http.put(format!("{base}/rulesets/ci/a")).bearer_auth("ci").json(&set(1, vec![to(a, 1002)])).send().await.unwrap();
			(r.status(), r.json::<Value>().await.unwrap())
		}
	});
	arrived.acquire().await.unwrap().forget();
	// the second, of the same generation, runs to its end meanwhile
	let r = call(&h, Method::PUT, "/rulesets/ci/a", "ci", Some(set(1, vec![to(a, 1003)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	go.add_permits(1);
	let r = first.await.unwrap();
	assert_eq!(r.0, StatusCode::OK, "{}", r.1);
	row_follows_the_set(&h, &store, "ci/a").await;
	let (_, view) = call(&h, Method::GET, "/rulesets/ci/a", "ci", None).await;
	assert_eq!(view["rules"][0]["remote_port"], 1003, "{view}");
	fs::remove_dir_all(dir).unwrap();
}

/// The periodic check writes again a set whose row did not go through while a
/// `PUT` of the same generation changes it (#306): the check reads the set
/// when it queues the row, so it never writes the older rules over the
/// `PUT`'s.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_check_writing_a_set_again_does_not_undo_a_put() {
	let dir = workdir("check-put");
	let h = harness_with(Tokens::from_file(token_file(&dir)).unwrap()).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	let a = free_port();
	let r = call(&h, Method::PUT, "/rulesets/ci/a", "ci", Some(set(1, vec![to(a, 1001)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	store.fail_writes(true);
	let r = call(&h, Method::PUT, "/rulesets/ci/a", "ci", Some(set(1, vec![to(a, 1002)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(false)), "{}", r.1);
	store.fail_writes(false);
	// the check writes the set again, and waits before it reads it
	let (arrived, go) = store.pause_next_set_write();
	let check = tokio::spawn({
		let (store, registry) = (store.clone(), h.registry.clone());
		async move { store.reconcile(&registry).await }
	});
	arrived.acquire().await.unwrap().forget();
	let r = call(&h, Method::PUT, "/rulesets/ci/a", "ci", Some(set(1, vec![to(a, 1003)]))).await;
	assert_eq!((r.0, &r.1["persisted"]), (StatusCode::OK, &json!(true)), "{}", r.1);
	go.add_permits(1);
	check.await.unwrap().unwrap();
	row_follows_the_set(&h, &store, "ci/a").await;
	let (_, view) = call(&h, Method::GET, "/rulesets/ci/a", "ci", None).await;
	assert_eq!(view["rules"][0]["remote_port"], 1003, "{view}");
	fs::remove_dir_all(dir).unwrap();
}

/// The real binary with MariaDB: a set PUT by a persist token survives a
/// restart (generation, etag, owner); a row with a newer generation is not
/// overwritten; other nodes' rows stay out; DELETE removes the row. Without
/// the table nothing fails.
#[tokio::test]
async fn sets_survive_a_restart_with_mariadb() {
	use sqlx::Executor;
	let Ok(url) = std::env::var("RPROXY_TEST_DATABASE_URL") else {
		eprintln!("skipping: RPROXY_TEST_DATABASE_URL is not set");
		return;
	};
	let pool = sqlx::mysql::MySqlPoolOptions::new().max_connections(1).connect(&url).await.unwrap();
	pool.execute("DROP TABLE IF EXISTS rproxy_rule_sets").await.unwrap();

	let dir = workdir("db");
	token_file(&dir);
	let backend = tcp_backend("M:").await;
	let (api_port, a, b, elsewhere) = (free_port(), free_port(), free_port(), free_port());
	let client = reqwest::Client::new();
	let base = format!("http://127.0.0.1:{api_port}");
	let put = |gen: u64, rules: Vec<Value>| client.put(format!("{base}/rulesets/ci/db")).bearer_auth("ci").json(&set(gen, rules)).send();

	// before migration 012: the startup is fine, a PUT runs with persisted: false
	{
		let rp = Rproxy::start(&dir, api_port, &url, "no-table");
		rp.ready(api_port).await;
		let r = put(1, vec![rule("tcp", a, backend)]).await.unwrap();
		let v: Value = r.json().await.unwrap();
		assert_eq!(v["persisted"], false, "{v}\n{}", rp.log());
		rp.wait_log("rproxy_rule_sets").await;
	}

	pool.execute(RPROXY_RULE_SETS).await.unwrap();
	sqlx::query(
		"INSERT INTO rproxy_rule_sets (node, name, generation, etag, owner, rules, updated_by, updated_at)
		 VALUES ('node-b', 'ci/other', 1, 'g1-x', 'ci', ?, 'ci', NOW(3))",
	)
	.bind(json!([rule("tcp", elsewhere, backend)]).to_string())
	.execute(&pool)
	.await
	.unwrap();
	let etag;
	{
		let rp = Rproxy::start(&dir, api_port, &url, "first");
		rp.ready(api_port).await;
		let r = put(5, vec![rule("tcp", a, backend), rule("tcp", b, backend)]).await.unwrap();
		let v: Value = r.json().await.unwrap();
		assert_eq!(v["persisted"], true, "{v}\n{}", rp.log());
		etag = v["etag"].as_str().unwrap().to_string();
	}
	let row: (i64, String, String, String) =
		sqlx::query_as("SELECT CAST(generation AS SIGNED), etag, owner, CAST(rules AS CHAR) FROM rproxy_rule_sets WHERE node = 'node-a' AND name = 'ci/db'")
			.fetch_one(&pool)
			.await
			.unwrap();
	let rules: Value = serde_json::from_str(&row.3).unwrap();
	assert_eq!((row.0, row.1.as_str(), row.2.as_str(), rules.as_array().unwrap().len()), (5, etag.as_str(), "ci", 2), "{rules}");

	{
		let rp = Rproxy::start(&dir, api_port, &url, "second");
		rp.ready(api_port).await;
		let v: Value = client.get(format!("{base}/rulesets/ci/db")).bearer_auth("ci").send().await.unwrap().json().await.unwrap();
		assert_eq!((&v["generation"], &v["etag"], &v["owner"], &v["persisted"]), (&json!(5), &json!(etag), &json!("ci"), &json!(true)), "{v}\n{}", rp.log());
		let r = client.get(format!("{base}/rulesets/ci/other")).bearer_auth("ci").send().await.unwrap();
		assert_eq!(r.status(), StatusCode::NOT_FOUND, "another node's row");
		let r = client.get(format!("{base}/rules/tcp/127.0.0.1/{a}")).bearer_auth("ci").send().await.unwrap();
		assert_eq!(r.status(), StatusCode::OK);

		// a newer row (another writer) is not overwritten by an older generation
		sqlx::query("UPDATE rproxy_rule_sets SET generation = 9, etag = 'g9-newer' WHERE node = 'node-a' AND name = 'ci/db'").execute(&pool).await.unwrap();
		let v: Value = put(6, vec![rule("tcp", a, backend)]).await.unwrap().json().await.unwrap();
		assert_eq!(v["persisted"], true, "{v}");
		let kept: (i64, String) = sqlx::query_as("SELECT CAST(generation AS SIGNED), etag FROM rproxy_rule_sets WHERE node = 'node-a' AND name = 'ci/db'")
			.fetch_one(&pool)
			.await
			.unwrap();
		assert_eq!((kept.0, kept.1.as_str()), (9, "g9-newer"));

		let r = client.delete(format!("{base}/rulesets/ci/db")).bearer_auth("ci").send().await.unwrap();
		assert_eq!(r.status(), StatusCode::NO_CONTENT);
	}
	let left: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM rproxy_rule_sets WHERE node = 'node-a'").fetch_one(&pool).await.unwrap();
	assert_eq!(left.0, 0);
	pool.execute("DROP TABLE rproxy_rule_sets").await.unwrap();
	fs::remove_dir_all(dir).unwrap();
}
