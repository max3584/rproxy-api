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
		assert!(rp.log().contains("rproxy_rule_sets"), "{}", rp.log());
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
