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

/// The real binary with MariaDB: a rule made by a persist token survives a
/// restart; the UI's row wins on the same key; other nodes' rows stay out.
#[tokio::test]
async fn rules_survive_a_restart_with_mariadb() {
	use sqlx::Executor;
	let Ok(url) = std::env::var("RPROXY_TEST_DATABASE_URL") else {
		eprintln!("skipping: RPROXY_TEST_DATABASE_URL is not set");
		return;
	};
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
		assert!(rp.log().contains("restore.conflict"), "{}", rp.log());
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
