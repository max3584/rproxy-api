//! The old process of a live upgrade stops its API changes before it takes
//! the snapshot the new process starts from (#305, `handoff::prepare`,
//! `persist::Store::freeze`): a change under way is waited for (it is in the
//! snapshot, its row written or handed over), a change that gets its turn
//! after that is refused with `503 upgrading` (never made in the old process
//! only), and a change that does not end in time stops the handoff instead of
//! being lost. In-process, with a memory store; the new process is another
//! registry started from the snapshot on the same rows.
//!
//! A handoff in progress is process-wide (`handoff::active`), so the cases
//! here run one at a time, in a test binary of their own.

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tokio::task::JoinHandle;

use rproxy_api::config::persist::Store;
use rproxy_api::control::auth::Tokens;
use rproxy_api::control::upgrade::handoff;
use rproxy_api::core::rule::{Key, Protocol};

use common::*;

/// One case at a time: `handoff::set_active` is process-wide.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn workdir(tag: &str) -> PathBuf {
	rproxy_api::net::files::private_umask();
	let dir = std::env::temp_dir().join(format!("rproxy-freeze-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn sha(s: &str) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// `ci` stores its rules and sets.
fn tokens(dir: &std::path::Path) -> Tokens {
	let file = dir.join("tokens.yaml");
	fs::write(&file, format!("tokens:\n  - {{name: ci, sha256: {}, scopes: [rules:read, rules:write], persist: true}}\n", sha("ci")))
		.unwrap();
	Tokens::from_file(file).unwrap()
}

async fn call(h: &Harness, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
	let mut req = h.http.request(method, format!("{}{path}", h.base)).bearer_auth("ci");
	if let Some(b) = body {
		req = req.json(&b);
	}
	let r = req.send().await.unwrap();
	let status = r.status();
	(status, r.json().await.unwrap_or(Value::Null))
}

fn key(port: u16) -> Key {
	Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{port}").parse().unwrap() }
}

/// A `PATCH` of the rule on `port` that sets `udp_idle_secs` (which tells the
/// changes apart), sent in the background.
fn patch(h: &Harness, port: u16, idle: u64) -> JoinHandle<(StatusCode, Value)> {
	let req = h
		.http
		.patch(format!("{}/rules/tcp/127.0.0.1/{port}", h.base))
		.bearer_auth("ci")
		.json(&json!({"remote_addr": "127.0.0.1", "remote_port": 9, "udp_idle_secs": idle}));
	tokio::spawn(async move {
		let r = req.send().await.unwrap();
		let status = r.status();
		(status, r.json().await.unwrap_or(Value::Null))
	})
}

async fn idle_of(h: &Harness, port: u16) -> Option<u64> {
	let (status, v) = call(h, Method::GET, &format!("/rules/tcp/127.0.0.1/{port}"), None).await;
	(status == StatusCode::OK).then(|| v["udp_idle_secs"].as_u64()).flatten()
}

fn row_idle(store: &Store, port: u16) -> Option<u64> {
	store.memory_rows().into_iter().find(|r| r.spec.listen_port == port).and_then(|r| r.spec.udp_idle_secs)
}

/// Waits until `cond` holds (and fails with `what` if it never does).
async fn until(what: &str, mut cond: impl AsyncFnMut() -> bool) {
	let deadline = Instant::now() + Duration::from_secs(10);
	while !cond().await {
		assert!(Instant::now() < deadline, "{what}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

/// A rule of `ci` on a free port, stored.
async fn stored_rule(h: &Harness) -> u16 {
	let port = free_port();
	let mut body = rule("tcp", port, "127.0.0.1:9".parse().unwrap());
	body["udp_idle_secs"] = json!(100);
	let (status, v) = call(h, Method::POST, "/rules", Some(body)).await;
	assert_eq!((status, &v["persisted"]), (StatusCode::CREATED, &json!(true)), "{v}");
	port
}

/// A change to a rule whose write is on its way when the live upgrade starts,
/// and more changes to the same rule right around the snapshot and after it:
/// the snapshot waits for the change under way, the later ones are made
/// before the snapshot or refused (`503 upgrading`), and the new process runs
/// the last change that was answered, with its row (it used to take the
/// snapshot at once: a change after it was made in the old process only, and
/// the new process wrote the older rule over its row).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn changes_around_the_snapshot_are_in_it_or_refused() {
	let _one = ONE_AT_A_TIME.lock().await;
	let dir = workdir("around");
	let old = harness_with(tokens(&dir)).await;
	let old_store = Arc::new(Store::memory("node-a"));
	old.registry.set_persist(old_store.clone());
	let port = stored_rule(&old).await;
	let set_port = free_port();
	let set = json!({"generation": 1, "rules": [rule("tcp", set_port, "127.0.0.1:9".parse().unwrap())]});
	assert_eq!(call(&old, Method::PUT, "/rulesets/ci/a", Some(set)).await.0, StatusCode::OK);

	old_store.delay_writes(Duration::from_millis(600));
	let first = patch(&old, port, 111);
	until("the first change's write is not on its way", async || old_store.is_unwritten(&key(port))).await;
	// the live upgrade starts (SIGUSR2: `Upgrader::start` marks it, `run` prepares)
	handoff::set_active(true);
	let prepare = tokio::spawn({
		let registry = old.registry.clone();
		async move { handoff::prepare(&registry, Duration::from_secs(10)).await }
	});
	// right around the snapshot
	let second = patch(&old, port, 222);
	let state = prepare.await.unwrap().expect("the snapshot is taken once the change under way is done");
	// after the snapshot: a rule and a rule set
	let third = patch(&old, port, 333);
	let set_after = tokio::spawn({
		let req = old.http.put(format!("{}/rulesets/ci/a", old.base)).bearer_auth("ci").json(&json!({"generation": 2, "rules": []}));
		async move { req.send().await.unwrap().status() }
	});
	tokio::time::sleep(Duration::from_millis(300)).await;
	let snapshot_idle = idle_of(&old, port).await;

	// the new process starts from the snapshot, on the same rows; the old lets go
	let new = harness_with(tokens(&dir)).await;
	let new_store = Arc::new(old_store.memory_after_upgrade());
	new.registry.set_persist(new_store.clone());
	state.restore_rules(&new.registry).await;
	old_store.release().await;

	// every change answered while the handoff is still marked (they are woken together)
	let (first, second, third) = (first.await.unwrap(), second.await.unwrap(), third.await.unwrap());
	let set_after = set_after.await.unwrap();
	handoff::set_active(false);
	assert_eq!((first.0, &first.1["persisted"]), (StatusCode::OK, &json!(true)), "the change under way: {}", first.1);
	let mut answered = Some(111);
	for (idle, (status, v)) in [(222, &second), (333, &third)] {
		match *status {
			StatusCode::OK => {
				assert_eq!(v["persisted"], true, "{v}");
				answered = Some(idle);
			}
			StatusCode::SERVICE_UNAVAILABLE => assert_eq!(v["code"], "upgrading", "{v}"),
			other => panic!("{other}: {v}"),
		}
	}
	assert_eq!(third.0, StatusCode::SERVICE_UNAVAILABLE, "a change after the snapshot was made in the old process: {}", third.1);
	assert_eq!(set_after, StatusCode::SERVICE_UNAVAILABLE, "a rule set changed after the snapshot");
	// the old process did not change after the snapshot
	assert_eq!(snapshot_idle, answered);
	assert_eq!(idle_of(&old, port).await, answered, "the old process changed after the snapshot");
	// the new process runs the last answered change, and its row says so
	assert_eq!(idle_of(&new, port).await, answered, "the new process runs another version");
	until("the row of the new process's rule does not follow it", async || {
		let _ = new_store.reconcile(&new.registry).await;
		let (_, v) = call(&new, Method::GET, &format!("/rules/tcp/127.0.0.1/{port}"), None).await;
		row_idle(&new_store, port) == answered && v["persisted"] == true
	})
	.await;
	assert_eq!(idle_of(&new, port).await, answered, "the new process's check undid the change");
	let (_, set) = call(&new, Method::GET, "/rulesets/ci/a", None).await;
	assert_eq!(set["generation"], 1, "{set}");
	fs::remove_dir_all(dir).unwrap();
}

/// A change under way that does not end within the wait (its write is slow):
/// the handoff does not happen, and the change is made and written in the old
/// process, which keeps running (`release` used to give up on it after
/// `RELEASE_WAIT`: the change was then in the old process only, its write
/// failed, and the new process never knew of it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_change_that_does_not_end_in_time_stops_the_handoff() {
	let _one = ONE_AT_A_TIME.lock().await;
	let dir = workdir("long");
	let h = harness_with(tokens(&dir)).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	let port = stored_rule(&h).await;
	store.delay_writes(Duration::from_millis(1500));
	let change = patch(&h, port, 111);
	until("the change's write is not on its way", async || store.is_unwritten(&key(port))).await;
	handoff::set_active(true);
	let started = Instant::now();
	let prepared = handoff::prepare(&h.registry, Duration::from_millis(300)).await;
	assert!(prepared.is_err(), "the snapshot was taken while a change was under way");
	assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
	// as `Upgrader` does when the handoff does not happen
	handoff::set_active(false);
	let (status, v) = change.await.unwrap();
	assert_eq!((status, &v["persisted"], &v["udp_idle_secs"]), (StatusCode::OK, &json!(true), &json!(111)), "{v}");
	assert_eq!(row_idle(&store, port), Some(111));
	store.delay_writes(Duration::ZERO);
	let (status, v) = patch(&h, port, 222).await.unwrap();
	assert_eq!((status, &v["persisted"]), (StatusCode::OK, &json!(true)), "{v}");
	fs::remove_dir_all(dir).unwrap();
}

/// A handoff that failed after the snapshot: the changes that waited
/// meanwhile go on (they are not refused), and the store writes again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_failed_handoff_the_waiting_changes_go_on() {
	let _one = ONE_AT_A_TIME.lock().await;
	let dir = workdir("failed");
	let h = harness_with(tokens(&dir)).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	let port = stored_rule(&h).await;
	handoff::set_active(true);
	let _state = handoff::prepare(&h.registry, Duration::from_secs(5)).await.unwrap();
	let waiting = patch(&h, port, 111);
	tokio::time::sleep(Duration::from_millis(300)).await;
	assert!(!waiting.is_finished(), "a change ran while the store was frozen");
	assert_eq!(idle_of(&h, port).await, Some(100));
	// as `Upgrader::failed` does
	handoff::set_active(false);
	store.thaw();
	let (status, v) = waiting.await.unwrap();
	assert_eq!((status, &v["persisted"], &v["udp_idle_secs"]), (StatusCode::OK, &json!(true), &json!(111)), "{v}");
	assert_eq!(row_idle(&store, port), Some(111));
	fs::remove_dir_all(dir).unwrap();
}

/// A handoff whose task ends without handing over, here by a panic after the
/// snapshot: the changes that waited go on (neither left waiting for ever nor
/// refused), and the self-update is told the handoff to that binary did not
/// happen (`Upgrader::set_on_abort`: it takes back its trial).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handoff_that_panics_lets_the_changes_go_on() {
	let _one = ONE_AT_A_TIME.lock().await;
	let dir = workdir("panic");
	let h = harness_with(tokens(&dir)).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	let port = stored_rule(&h).await;
	let config = handoff::Config { socket: dir.join("handoff.sock"), timeout: Duration::from_secs(1), drain: Duration::from_secs(1) };
	let upgrader = handoff::Upgrader::new(config, h.registry.clone());
	let aborted: Arc<std::sync::Mutex<Vec<PathBuf>>> = Arc::default();
	upgrader.set_on_abort(Box::new({
		let aborted = aborted.clone();
		move |exe, _| aborted.lock().unwrap().push(exe.to_path_buf())
	}));
	handoff::set_active(true);
	let (frozen, is_frozen) = tokio::sync::oneshot::channel();
	let (go, panic_now) = tokio::sync::oneshot::channel::<()>();
	let task = tokio::spawn({
		let (upgrader, registry) = (upgrader.clone(), h.registry.clone());
		async move {
			let _running = handoff::Running::new(upgrader, Some(PathBuf::from("/opt/rproxy/rproxy-api-v99.0.0")));
			let _state = handoff::prepare(&registry, Duration::from_secs(5)).await.unwrap();
			let _ = frozen.send(());
			let _ = panic_now.await;
			panic!("the handoff task panicked (test)");
		}
	});
	is_frozen.await.unwrap();
	let waiting = patch(&h, port, 111);
	tokio::time::sleep(Duration::from_millis(200)).await;
	go.send(()).unwrap();
	assert!(task.await.is_err(), "the task panicked");
	assert!(!handoff::active(), "the handoff stays marked");
	let (status, v) = tokio::time::timeout(Duration::from_secs(5), waiting).await.expect("the waiting change hangs").unwrap();
	assert_eq!((status, &v["persisted"], &v["udp_idle_secs"]), (StatusCode::OK, &json!(true), &json!(111)), "{v}");
	assert_eq!(*aborted.lock().unwrap(), [PathBuf::from("/opt/rproxy/rproxy-api-v99.0.0")]);
	fs::remove_dir_all(dir).unwrap();
}

/// #327 / #323: the rules restored that did not validate go over a live upgrade as
/// stored (still failed there, with who stored them), not as the rules to start; and
/// who made each rule through the API goes with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_rules_and_owners_carry_over() {
	let _one = ONE_AT_A_TIME.lock().await;
	let dir = workdir("invalid");
	let old = harness_with(tokens(&dir)).await;
	let old_store = Arc::new(Store::memory("node-a"));
	old.registry.set_persist(old_store.clone());
	let made = stored_rule(&old).await;
	let (api, dynamic) = (free_port(), free_port());
	let bad = |port: u16| {
		let mut r = rule("tcp", port, "127.0.0.1:9".parse().unwrap());
		r["allow_from"] = json!(["not-an-address"]);
		r
	};
	let row = rproxy_api::config::persist::StoredRule {
		node: "node-a".into(),
		spec: serde_json::from_value(bad(api)).unwrap(),
		spec_version: 1,
		created_by: "someone".into(),
		created_at: 1_790_000_000,
		updated_by: "someone".into(),
		updated_at: 1_790_000_000,
	};
	old_store.memory_put_row(row.clone());
	old_store.restored(std::slice::from_ref(&row));
	old.registry.restore_as(vec![row.spec.clone()], rproxy_api::core::rule::Origin::Api).await;
	old.registry.restore(vec![serde_json::from_value(bad(dynamic)).unwrap()]).await;

	let state = handoff::prepare(&old.registry, Duration::from_secs(5)).await.unwrap();
	assert!(state.rules.iter().all(|r| r["listen_port"] != api && r["listen_port"] != dynamic), "not as rules to start");
	// as it goes over the socket
	let state: handoff::State = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
	let new = harness_with(tokens(&dir)).await;
	let new_store = Arc::new(old_store.memory_after_upgrade());
	new.registry.set_persist(new_store.clone());
	state.restore_rules(&new.registry).await;
	old_store.release().await;

	let (status, v) = call(&new, Method::GET, &format!("/rules/tcp/127.0.0.1/{api}"), None).await;
	assert_eq!(
		(status, &v["state"], &v["origin"], &v["created_by"], &v["persisted"], &v["allow_from"]),
		(StatusCode::OK, &json!("failed"), &json!("api"), &json!("someone"), &json!(true), &json!(["not-an-address"])),
		"{v}"
	);
	let (status, v) = call(&new, Method::GET, &format!("/rules/tcp/127.0.0.1/{dynamic}"), None).await;
	assert_eq!((status, &v["state"], &v["origin"]), (StatusCode::OK, &json!("failed"), &json!("dynamic")), "{v}");
	assert!(new.registry.owners().contains(&(key(made), "ci".to_string())), "{:?}", new.registry.owners());
	// fixed in the new process
	let (status, v) = call(&new, Method::PATCH, &format!("/rules/tcp/127.0.0.1/{api}"), Some(json!({"remote_addr": "127.0.0.1", "remote_port": 9, "allow_from": []}))).await;
	assert_eq!((status, &v["state"], &v["persisted"]), (StatusCode::OK, &json!("running"), &json!(true)), "{v}");
	fs::remove_dir_all(dir).unwrap();
}
