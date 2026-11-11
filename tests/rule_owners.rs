//! Tokens change and delete only what they made (#401, `features.rule_owners`): a token
//! without `admin` may `PATCH` / `DELETE` (also `dry_run`) only its own rules, change or
//! remove only its own overlays, and rules whose creator is not known (restored from the
//! UI's `forward_rules`, rows without `created_by`) only with `allow_restored`. Refusals are
//! `403 not_owner`; `admin` may do anything. The owner is the token's name, so a token
//! rotated under the same name keeps its rules.

mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use common::*;
use rproxy_api::config::persist::{Store, StoredRule};
use rproxy_api::control::auth::Tokens;
use rproxy_api::core::rule::{Key, Origin, Protocol, RuleRequest, UpdateRequest};
use rproxy_api::error::ApiError;
use rproxy_api::net::protected::Owner;

fn sha(s: &str) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-it-owners-{tag}-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	dir
}

/// `a` and `b` are service accounts on the same ports, `ui` is the UI's token
/// (`allow_restored`), `root` is `admin`. `a`'s secret is `a_secret`.
fn write_tokens(file: &Path, a_secret: &str) {
	std::fs::write(
		file,
		format!(
			"tokens:\n  - {{name: a, sha256: {}, scopes: [rules:read, rules:write]}}\n  - {{name: b, sha256: {}, scopes: [rules:read, rules:write]}}\n  - {{name: ui, sha256: {}, scopes: [rules:read, rules:write], allow_restored: true}}\n  - {{name: root, sha256: {}, scopes: [admin]}}\n",
			sha(a_secret),
			sha("b"),
			sha("ui"),
			sha("root")
		),
	)
	.unwrap();
}

async fn with_tokens(tag: &str) -> (Harness, PathBuf) {
	let dir = workdir(tag);
	let file = dir.join("tokens.yaml");
	write_tokens(&file, "a");
	(harness_with(Tokens::from_file(file).unwrap()).await, dir)
}

async fn call(h: &Harness, method: Method, path: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
	let mut r = h.http.request(method, format!("{}{path}", h.base)).bearer_auth(token);
	if let Some(b) = body {
		r = r.json(&b);
	}
	let r = r.send().await.unwrap();
	let status = r.status();
	(status, r.json().await.unwrap_or(Value::Null))
}

fn not_owner((status, v): (StatusCode, Value), what: &str) {
	assert_eq!((status, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("not_owner")), "{what}: {v}");
}

fn rule_path(port: u16) -> String {
	format!("/rules/tcp/127.0.0.1/{port}")
}

fn targets(backend: SocketAddr) -> Value {
	json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port()})
}

#[tokio::test]
async fn tokens_change_and_delete_only_their_own_rules() {
	let (h, dir) = with_tokens("rules").await;
	let backend = tcp_backend("O:").await;
	let port = free_port();
	let (status, v) = call(&h, Method::POST, "/rules", "a", Some(rule("tcp", port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let path = rule_path(port);

	// another token, with the scope and the ports: refused, also the dry runs, and nothing changes
	not_owner(call(&h, Method::PATCH, &path, "b", Some(targets(backend))).await, "PATCH");
	not_owner(call(&h, Method::PATCH, &format!("{path}?dry_run=true"), "b", Some(targets(backend))).await, "PATCH dry run");
	not_owner(call(&h, Method::DELETE, &path, "b", None).await, "DELETE");
	not_owner(call(&h, Method::DELETE, &format!("{path}?dry_run=true"), "b", None).await, "DELETE dry run");
	// the UI's token is not every token's: allow_restored is for rules of no known creator
	not_owner(call(&h, Method::PATCH, &path, "ui", Some(targets(backend))).await, "allow_restored");
	let (status, v) = call(&h, Method::GET, &path, "b", None).await;
	assert_eq!((status, &v["state"]), (StatusCode::OK, &json!("running")), "reading is as before: {v}");

	// its creator may, and admin may
	let (status, v) = call(&h, Method::PATCH, &format!("{path}?dry_run=true"), "a", Some(targets(backend))).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let (status, v) = call(&h, Method::PATCH, &path, "a", Some(targets(backend))).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let (status, v) = call(&h, Method::PATCH, &path, "root", Some(targets(backend))).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	// an admin's change does not make it admin's
	let (status, v) = call(&h, Method::PATCH, &path, "a", Some(targets(backend))).await;
	assert_eq!(status, StatusCode::OK, "still a's: {v}");
	let (status, _) = call(&h, Method::DELETE, &format!("{path}?dry_run=true"), "a", None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(call(&h, Method::DELETE, &path, "a", None).await.0, StatusCode::NO_CONTENT);
	// a key without a rule is 404 as before
	assert_eq!(call(&h, Method::DELETE, &path, "b", None).await.0, StatusCode::NOT_FOUND);

	// admin deletes another token's rule
	let (status, v) = call(&h, Method::POST, "/rules", "b", Some(rule("tcp", port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(call(&h, Method::DELETE, &path, "root", None).await.0, StatusCode::NO_CONTENT);
	std::fs::remove_dir_all(dir).unwrap();
}

/// Rules restored from the UI's `forward_rules` (no known creator, also those that do not
/// validate) and `rproxy_rules` rows without `created_by`: `admin` and `allow_restored` only.
#[tokio::test]
async fn rules_of_no_known_creator_need_allow_restored_or_admin() {
	let (h, dir) = with_tokens("restored").await;
	let store = Arc::new(Store::memory("n1"));
	h.registry.set_persist(store.clone());
	let backend = tcp_backend("R:").await;
	let (restored, invalid, row_port) = (free_port(), free_port(), free_port());
	let mut bad = rule("tcp", invalid, backend);
	bad["allow_from"] = json!(["not-an-address"]);
	let reqs: Vec<RuleRequest> = [rule("tcp", restored, backend), bad].into_iter().map(|v| serde_json::from_value(v).unwrap()).collect();
	h.registry.restore(reqs).await;
	// an older version's row without its creator
	let row = StoredRule {
		node: "n1".into(),
		spec: serde_json::from_value(rule("tcp", row_port, backend)).unwrap(),
		spec_version: 1,
		created_by: String::new(),
		created_at: 1_790_000_000,
		updated_by: String::new(),
		updated_at: 1_790_000_000,
	};
	store.memory_put_row(row.clone());
	store.restored(std::slice::from_ref(&row));
	h.registry.restore_as(vec![row.spec], Origin::Api).await;

	let mut fix = targets(backend);
	fix["allow_from"] = json!([]);
	for port in [restored, invalid, row_port] {
		let path = rule_path(port);
		not_owner(call(&h, Method::PATCH, &path, "a", Some(fix.clone())).await, "PATCH");
		not_owner(call(&h, Method::DELETE, &format!("{path}?dry_run=true"), "a", None).await, "DELETE dry run");
		not_owner(call(&h, Method::DELETE, &path, "b", None).await, "DELETE");
		let (status, v) = call(&h, Method::PATCH, &format!("{path}?dry_run=true"), "ui", Some(fix.clone())).await;
		assert_eq!(status, StatusCode::OK, "{port}: {v}");
	}
	// the UI's token edits the UI's rule and fixes the one that did not validate; it stays no
	// token's (another allow_restored token or admin may still change it)
	let (status, v) = call(&h, Method::PATCH, &rule_path(restored), "ui", Some(targets(backend))).await;
	assert_eq!((status, &v["origin"]), (StatusCode::OK, &json!("dynamic")), "{v}");
	not_owner(call(&h, Method::PATCH, &rule_path(restored), "a", Some(targets(backend))).await, "after the UI's change");
	let (status, v) = call(&h, Method::PATCH, &rule_path(invalid), "ui", Some(fix)).await;
	assert_eq!((status, &v["state"]), (StatusCode::OK, &json!("running")), "{v}");
	assert_eq!(call(&h, Method::DELETE, &rule_path(restored), "ui", None).await.0, StatusCode::NO_CONTENT);
	assert_eq!(call(&h, Method::DELETE, &rule_path(invalid), "root", None).await.0, StatusCode::NO_CONTENT);
	assert_eq!(call(&h, Method::DELETE, &rule_path(row_port), "root", None).await.0, StatusCode::NO_CONTENT);
	std::fs::remove_dir_all(dir).unwrap();
}

/// Says its name.
async fn http_backend(name: &'static str) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let app = axum::Router::new().fallback(move || async move { name });
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

/// Overlays: anyone with the ports makes one where there is none; then only its creator and
/// admin change or remove it.
#[tokio::test]
async fn overlays_are_changed_by_their_creator() {
	let (h, dir) = with_tokens("overlay").await;
	let (a, b) = (http_backend("A").await, http_backend("B").await);
	let port = free_port();
	let file = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "app", "match": "PathPrefix(`/app`)", "service": "a"}],
		"services": {"a": {"servers": [{"url": format!("http://{a}")}]}}
	}});
	let reqs = vec![("rule #0".to_string(), serde_json::from_value::<RuleRequest>(file).unwrap())];
	h.registry.load_static_labeled(reqs).await.unwrap();
	let overlay = |prio: u32| {
		json!({"http": {
			"routes": [{"name": "extra", "match": "PathPrefix(`/`)", "priority": prio, "service": "b"}],
			"services": {"b": {"servers": [{"url": format!("http://{b}")}]}}
		}})
	};
	let path = format!("/rules/tcp/127.0.0.1/{port}/overlay");
	let (status, v) = call(&h, Method::PUT, &path, "a", Some(overlay(1))).await;
	assert_eq!((status, &v["created_by"]), (StatusCode::CREATED, &json!("a")), "{v}");
	not_owner(call(&h, Method::PUT, &path, "b", Some(overlay(2))).await, "PUT");
	// a create that lost the race is 412 first (#399), whoever made the overlay
	let r = h.http.put(format!("{}{path}", h.base)).bearer_auth("b").header("if-none-match", "*").json(&overlay(2)).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::PRECONDITION_FAILED);
	not_owner(call(&h, Method::PUT, &format!("{path}?dry_run=true"), "b", Some(overlay(2))).await, "PUT dry run");
	not_owner(call(&h, Method::DELETE, &path, "b", None).await, "DELETE");
	not_owner(call(&h, Method::DELETE, &format!("{path}?dry_run=true"), "ui", None).await, "DELETE dry run");
	let (status, v) = call(&h, Method::PUT, &path, "a", Some(overlay(3))).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let (status, v) = call(&h, Method::PUT, &path, "root", Some(overlay(4))).await;
	assert_eq!((status, &v["created_by"], &v["updated_by"]), (StatusCode::OK, &json!("a"), &json!("root")), "{v}");
	assert_eq!(call(&h, Method::DELETE, &path, "root", None).await.0, StatusCode::NO_CONTENT);
	// none now: b may make one, and it is b's
	let (status, v) = call(&h, Method::PUT, &path, "b", Some(overlay(5))).await;
	assert_eq!((status, &v["created_by"]), (StatusCode::CREATED, &json!("b")), "{v}");
	not_owner(call(&h, Method::DELETE, &path, "a", None).await, "a after b made it");
	assert_eq!(call(&h, Method::DELETE, &path, "b", None).await.0, StatusCode::NO_CONTENT);
	std::fs::remove_dir_all(dir).unwrap();
}

/// Rule sets were their owner's already (security review M3); the refusal says `not_owner`
/// as rules do.
#[tokio::test]
async fn rule_sets_answer_not_owner_too() {
	let (h, dir) = with_tokens("sets").await;
	let backend = tcp_backend("S:").await;
	let body = |g: u64| json!({"generation": g, "rules": [rule("tcp", 0, backend)]});
	let port = free_port();
	let mut first = body(1);
	first["rules"][0]["listen_port"] = json!(port);
	let (status, v) = call(&h, Method::PUT, "/rulesets/team-a", "a", Some(first.clone())).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let mut next = first.clone();
	next["generation"] = json!(2);
	not_owner(call(&h, Method::PUT, "/rulesets/team-a", "b", Some(next.clone())).await, "PUT");
	not_owner(call(&h, Method::DELETE, "/rulesets/team-a", "b", None).await, "DELETE");
	// its rules are refused individually as before (409 owned), whoever asks
	let (status, v) = call(&h, Method::PATCH, &rule_path(port), "b", Some(targets(backend))).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("owned")), "{v}");
	assert_eq!(call(&h, Method::DELETE, "/rulesets/team-a", "root", None).await.0, StatusCode::NO_CONTENT);
	std::fs::remove_dir_all(dir).unwrap();
}

/// The owner is the token's name: a new secret under the same name keeps its rules; a token of
/// another name (a renamed one) does not get them.
#[tokio::test]
async fn a_rotated_token_keeps_its_rules() {
	let dir = workdir("rotate");
	let file = dir.join("tokens.yaml");
	write_tokens(&file, "a");
	let h = harness_with(Tokens::from_file(file.clone()).unwrap()).await;
	let backend = tcp_backend("T:").await;
	let port = free_port();
	let (status, v) = call(&h, Method::POST, "/rules", "a", Some(rule("tcp", port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	write_tokens(&file, "a-new");
	h.tokens.reload().unwrap();
	assert_eq!(call(&h, Method::GET, "/rules", "a", None).await.0, StatusCode::UNAUTHORIZED, "the old secret is gone");
	let (status, v) = call(&h, Method::PATCH, &rule_path(port), "a-new", Some(targets(backend))).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	// renamed: another token's rule now
	std::fs::write(&file, format!("tokens:\n  - {{name: a2, sha256: {}, scopes: [rules:read, rules:write]}}\n", sha("a-new"))).unwrap();
	h.tokens.reload().unwrap();
	not_owner(call(&h, Method::DELETE, &rule_path(port), "a-new", None).await, "renamed");
	std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn the_feature_is_announced() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["rule_owners"], true, "{caps}");
}

/// The check `a`'s change makes under the rules lock (#401): only `a`'s rules.
fn as_a(owner: &Owner) -> Result<(), ApiError> {
	if owner.is("a") { Ok(()) } else { Err(ApiError::not_owner("not a's")) }
}

/// The owner is checked again where the change takes the rules lock: a rule another token made
/// on the key after the API's first check (a `DELETE` of a free key racing another token's
/// `POST`, a `PATCH` racing a delete and re-create) is not changed nor deleted. Deterministic:
/// the registry is called as the handler calls it after its first check passed.
#[tokio::test]
async fn the_owner_is_checked_again_under_the_rules_lock() {
	let (h, dir) = with_tokens("lock").await;
	let backend = tcp_backend("L:").await;
	let port = free_port();
	let key = Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{port}").parse().unwrap() };
	// a's check passed while the key was free; b's rule took it meanwhile
	let (status, v) = call(&h, Method::POST, "/rules", "b", Some(rule("tcp", port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let e = h.registry.take_as(&key, Some(&as_a)).await.err().expect("refused");
	assert_eq!(e.code, "not_owner");
	let req: UpdateRequest = serde_json::from_value(json!({"remote_addr": "127.0.0.1", "remote_port": 9})).unwrap();
	let e = h.registry.update_as(&key, req.clone(), Some(&as_a)).await.expect_err("refused");
	assert_eq!(e.code, "not_owner");
	let (status, v) = call(&h, Method::GET, &rule_path(port), "b", None).await;
	assert_eq!(
		(status, &v["state"], &v["remote_port"]),
		(StatusCode::OK, &json!("running"), &json!(backend.port())),
		"b's rule as it was: {v}"
	);
	// a's own rule passes the same check
	assert_eq!(call(&h, Method::DELETE, &rule_path(port), "b", None).await.0, StatusCode::NO_CONTENT);
	let (status, v) = call(&h, Method::POST, "/rules", "a", Some(rule("tcp", port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	h.registry.update_as(&key, req, Some(&as_a)).await.unwrap();
	h.registry.stop_taken(h.registry.take_as(&key, Some(&as_a)).await.unwrap(), None).await;

	// a restored rule that did not validate: neither fixed nor deleted, and not made failed
	let mut bad = rule("tcp", port, backend);
	bad["allow_from"] = json!(["not-an-address"]);
	h.registry.restore(vec![serde_json::from_value(bad).unwrap()]).await;
	let fix: UpdateRequest = serde_json::from_value(json!({"remote_addr": "127.0.0.1", "remote_port": 9, "allow_from": []})).unwrap();
	assert_eq!(h.registry.update_as(&key, fix, Some(&as_a)).await.expect_err("refused").code, "not_owner");
	assert_eq!(h.registry.take_as(&key, Some(&as_a)).await.err().expect("refused").code, "not_owner");
	let (status, v) = call(&h, Method::GET, &rule_path(port), "root", None).await;
	assert_eq!((status, &v["state"], &v["allow_from"]), (StatusCode::OK, &json!("failed"), &json!(["not-an-address"])), "{v}");
	assert_eq!(call(&h, Method::DELETE, &rule_path(port), "root", None).await.0, StatusCode::NO_CONTENT);
	std::fs::remove_dir_all(dir).unwrap();
}
