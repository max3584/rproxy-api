//! `global` through the control API (#342): `GET` / `PATCH /config/global`. Items
//! the settings file (or the environment) sets are the file's (`409 static`), the
//! start-only ones are not changed (`409 restart_only`), the live ones are in force
//! for the next request, connection or UDP session, stored in `rproxy_global` and
//! restored before the rules, handed over by a live upgrade, and a reload that
//! brings an item into the file shadows the API's value.

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use rproxy_api::config::ConfigDoc;
use rproxy_api::config::check::CheckInput;
use rproxy_api::config::global::Values;
use rproxy_api::config::persist::Store;
use rproxy_api::config::reload::{ConfigReloader, Outcome};
use rproxy_api::control::api::{AppState, router};
use rproxy_api::control::auth::Tokens;
use rproxy_api::control::upgrade::handoff;

use common::*;

fn workdir(tag: &str) -> PathBuf {
	rproxy_api::net::files::private_umask();
	let dir = std::env::temp_dir().join(format!("rproxy-global-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn sha(s: &str) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// `admin` (persist: true) and `reader` (rules:read).
fn tokens(dir: &std::path::Path) -> Tokens {
	let file = dir.join("tokens.yaml");
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: admin, sha256: {}, scopes: [admin, rules:read, rules:write], persist: true}}\n  - {{name: reader, sha256: {}, scopes: [rules:read]}}\n",
			sha("admin"),
			sha("reader")
		),
	)
	.unwrap();
	Tokens::from_file(file).unwrap()
}

/// Another control API on the same registry; `unix_only: false` stands for the Unix socket.
async fn api(h: &Harness, dir: &std::path::Path, unix_only: bool) -> String {
	let app = router(Arc::new(AppState {
		registry: h.registry.clone(),
		tokens: Arc::new(tokens(dir)),
		reloader: None,
		reload_unix_only: unix_only,
	}));
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move { axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap() });
	base
}

async fn call(base: &str, token: &str, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
	let mut req = reqwest::Client::new().request(method, format!("{base}{path}")).bearer_auth(token);
	if let Some(b) = body {
		req = req.json(&b);
	}
	let r = req.send().await.unwrap();
	let status = r.status();
	(status, r.json().await.unwrap_or(Value::Null))
}

async fn patch(base: &str, path: &str, body: Value) -> (StatusCode, Value) {
	call(base, "admin", Method::PATCH, path, Some(body)).await
}

/// An HTTP backend answering the client address it was told about (`X-Real-IP`).
async fn echo_backend() -> std::net::SocketAddr {
	let app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
		let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		axum::Json(json!({"real": h("x-real-ip"), "xff": h("x-forwarded-for")}))
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

async fn real_ip(port: u16) -> String {
	let r = reqwest::Client::new()
		.get(format!("http://127.0.0.1:{port}/"))
		.header("X-Forwarded-For", "203.0.113.9")
		.timeout(Duration::from_secs(10))
		.send()
		.await
		.unwrap();
	let v: Value = r.json().await.unwrap();
	v["real"].as_str().unwrap_or_default().to_string()
}

fn http_rule(port: u16, backend: std::net::SocketAddr) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
		"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}")}]}})
}

/// The file's `global` as `main` gives it to the settings at the start.
fn init_with_file(h: &Harness, text: &str, database: bool) -> ConfigDoc {
	let doc = ConfigDoc::parse(std::path::Path::new("rproxy.yaml"), text).unwrap();
	h.registry.global().init(Some((&doc.global, &doc.global_raw)), Values::default(), Default::default(), 1, database);
	doc
}

#[tokio::test]
async fn the_api_sets_what_the_file_leaves_out_and_the_next_request_takes_it() {
	let dir = workdir("patch");
	let h = harness_with(tokens(&dir)).await;
	init_with_file(&h, "version: 1\nglobal: {http: {timeouts: {idle: 5m}}}\n", false);
	let base = api(&h, &dir, true).await;

	assert_eq!(call(&base, "reader", Method::GET, "/config/global", None).await.0, StatusCode::FORBIDDEN, "admin only");
	let (status, v) = call(&base, "admin", Method::GET, "/config/global", None).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!((&v["items"]["http.timeouts"]["source"], &v["items"]["http.timeouts"]["settable"]), (&json!("file"), &json!(false)), "{v}");
	assert_eq!(v["items"]["http.timeouts"]["value"]["idle"], "5m");
	assert_eq!((&v["items"]["performance"]["apply"], &v["items"]["crowdsec"]["unix_only"]), (&json!("restart"), &json!(true)));
	assert_eq!(v["storage"], "memory", "no database: the values live in this process");

	// the file's item, a start-only item, a secret over TCP, mistakes
	let (status, e) = patch(&base, "/config/global", json!({"http": {"timeouts": {"idle": "1s"}}, "access_log": null})).await;
	assert_eq!((status, &e["code"], &e["items"]), (StatusCode::CONFLICT, &json!("static"), &json!(["http.timeouts"])), "{e}");
	let (status, e) = patch(&base, "/config/global", json!({"performance": {"workers": 2}})).await;
	assert_eq!((status, &e["code"], &e["items"]), (StatusCode::CONFLICT, &json!("restart_only"), &json!(["performance"])), "{e}");
	let (status, e) = patch(&base, "/config/global", json!({"crowdsec": null})).await;
	assert_eq!((status, &e["code"]), (StatusCode::FORBIDDEN, &json!("forbidden")), "{e}");
	for body in [
		json!({"trusted_proxies": ["nope"]}),
		json!({"nope": 1}),
		json!({}),
		json!([1]),
		json!({"access_log": "/nonexistent-rproxy/a.log"}),
	] {
		let (status, e) = patch(&base, "/config/global", body.clone()).await;
		assert_eq!((status, &e["code"]), (StatusCode::BAD_REQUEST, &json!("invalid")), "{body}: {e}");
	}
	let (status, e) = patch(&base, "/config/global", json!({"access_log": "/proc/self/a.log"})).await;
	assert_eq!((status, &e["code"]), (StatusCode::FORBIDDEN, &json!("protected_file")), "{e}");

	// trusted_proxies: the next request believes the proxy's X-Forwarded-For
	let backend = echo_backend().await;
	let port = free_port();
	let (status, v) = call(&base, "admin", Method::POST, "/rules", Some(http_rule(port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(real_ip(port).await, "127.0.0.1");
	let (status, plan) = patch(&base, "/config/global?dry_run=true", json!({"trusted_proxies": ["127.0.0.0/8"]})).await;
	assert_eq!((status, &plan["dry_run"], &plan["applied"]), (StatusCode::OK, &json!(true), &json!(["trusted_proxies"])), "{plan}");
	assert_eq!(real_ip(port).await, "127.0.0.1", "a dry run changes nothing");
	let (status, v) = patch(&base, "/config/global", json!({"trusted_proxies": ["127.0.0.0/8"]})).await;
	assert_eq!((status, &v["applied"]), (StatusCode::OK, &json!(["trusted_proxies"])), "{v}");
	assert_eq!((&v["items"]["trusted_proxies"]["source"], &v["persisted"]), (&json!("api"), &Value::Null), "{v}");
	assert_eq!(v["changes"][0]["before"], json!([]));
	assert_eq!(real_ip(port).await, "203.0.113.9", "the next request takes it");

	// access_log: the next lines go to the file
	let log = dir.join("access.log");
	let (status, v) = patch(&base, "/config/global", json!({"access_log": log})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	real_ip(port).await;
	let deadline = Instant::now() + Duration::from_secs(5);
	loop {
		let lines: String = fs::read_dir(&dir)
			.unwrap()
			.flatten()
			.filter(|e| e.file_name().to_string_lossy().starts_with("access"))
			.map(|e| fs::read_to_string(e.path()).unwrap_or_default())
			.collect();
		if lines.contains("\"http.access\"") && lines.contains("203.0.113.9") {
			break;
		}
		assert!(Instant::now() < deadline, "no access line in {}: {lines}", dir.display());
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	// cleared: back to the default
	let (status, v) = patch(&base, "/config/global", json!({"trusted_proxies": null, "access_log": null})).await;
	assert_eq!((status, &v["items"]["trusted_proxies"]["source"]), (StatusCode::OK, &json!("default")), "{v}");
	assert!(v["items"]["trusted_proxies"].get("api_value").is_none(), "{v}");
	assert_eq!(real_ip(port).await, "127.0.0.1");
	fs::remove_dir_all(dir).unwrap();
}

/// The only case that changes the UDP default cap (process-wide).
#[tokio::test]
async fn udp_sessions_and_http_timeouts_change_for_the_next_session_and_connection() {
	let dir = workdir("live");
	let h = harness_with(tokens(&dir)).await;
	init_with_file(&h, "version: 1\n", false);
	let base = api(&h, &dir, true).await;

	// the default cap of UDP sessions: the next new session is refused over it
	let backend = udp_backend("U:").await;
	let port = free_udp_port();
	let (status, v) = call(&base, "admin", Method::POST, "/rules", Some(rule("udp", port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v) = patch(&base, "/config/global", json!({"udp_max_sessions": 1})).await;
	assert_eq!((status, &v["items"]["udp_max_sessions"]["value"]), (StatusCode::OK, &json!(1)), "{v}");
	let client = |_: ()| async move {
		let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		s.connect(("127.0.0.1", port)).await.unwrap();
		s
	};
	let a = client(()).await;
	assert_eq!(udp_roundtrip(&a, "1").await, "U:1");
	let b = client(()).await;
	b.send(b"2").await.unwrap();
	let mut buf = [0u8; 64];
	assert!(tokio::time::timeout(Duration::from_millis(500), b.recv(&mut buf)).await.is_err(), "over the cap");
	patch(&base, "/config/global", json!({"udp_max_sessions": null})).await;
	assert_eq!(udp_roundtrip(&b, "3").await, "U:3", "back to the default cap");

	// http.timeouts: a new connection that sends nothing is closed after first_byte
	let http = echo_backend().await;
	let port = free_port();
	assert_eq!(call(&base, "admin", Method::POST, "/rules", Some(http_rule(port, http))).await.0, StatusCode::CREATED);
	let (status, v) = patch(&base, "/config/global", json!({"http": {"timeouts": {"first_byte": "1s"}}})).await;
	assert_eq!((status, &v["items"]["http.timeouts"]["source"]), (StatusCode::OK, &json!("api")), "{v}");
	let mut idle = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let started = Instant::now();
	let n = tokio::time::timeout(Duration::from_secs(5), idle.read(&mut buf)).await.expect("closed within the new limit");
	assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
	assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
	// the default (10s) again for the next connection
	patch(&base, "/config/global", json!({"http": null})).await;
	let mut next = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert!(tokio::time::timeout(Duration::from_millis(1500), next.read(&mut buf)).await.is_err(), "still open after 1.5 s");
	next.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
	assert!(next.read(&mut buf).await.unwrap() > 0);
	fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn crowdsec_through_the_unix_socket_and_the_rules_that_need_it() {
	let dir = workdir("crowdsec");
	let h = harness_with(tokens(&dir)).await;
	init_with_file(&h, "version: 1\n", false);
	let unix = api(&h, &dir, false).await;
	let key = dir.join("crowdsec.key");
	fs::write(&key, "secret\n").unwrap();
	let backend = echo_backend().await;
	let port = free_port();
	let mut r = http_rule(port, backend);
	r["http"]["routes"][0]["middlewares"] = json!(["cs"]);
	r["http"]["middlewares"] = json!({"cs": {"crowdsec": {}}});
	let (status, e) = call(&unix, "admin", Method::POST, "/rules", Some(r.clone())).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "needs global.crowdsec: {e}");

	let cs = json!({"crowdsec": {"lapi_url": "http://127.0.0.1:9", "api_key_file": key}});
	let (status, v) = patch(&unix, "/config/global", cs).await;
	assert_eq!((status, &v["items"]["crowdsec"]["source"]), (StatusCode::OK, &json!("api")), "{v}");
	assert!(h.registry.http_global().crowdsec().is_some());
	let (status, v) = call(&unix, "admin", Method::POST, "/rules", Some(r)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	// rules use it: not taken away
	let (status, e) = patch(&unix, "/config/global", json!({"crowdsec": null})).await;
	assert_eq!((status, &e["code"]), (StatusCode::CONFLICT, &json!("in_use")), "{e}");
	// the API may not name rproxy's own secrets: the key file is protected from rules now
	let mut leak = http_rule(free_port(), backend);
	leak["http"]["middlewares"] = json!({"a": {"basic_auth": {"users_file": key}}});
	leak["http"]["routes"][0]["middlewares"] = json!(["a"]);
	let (status, e) = call(&unix, "admin", Method::POST, "/rules", Some(leak)).await;
	assert_eq!((status, &e["code"]), (StatusCode::FORBIDDEN, &json!("protected_file")), "{e}");
	assert_eq!(call(&unix, "admin", Method::DELETE, &format!("/rules/tcp/127.0.0.1/{port}"), None).await.0, StatusCode::NO_CONTENT);
	let (status, v) = patch(&unix, "/config/global", json!({"crowdsec": null})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert!(h.registry.http_global().crowdsec().is_none());
	fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn stored_restored_and_written_again() {
	let dir = workdir("persist");
	let h = harness_with(tokens(&dir)).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	init_with_file(&h, "version: 1\n", true);
	let base = api(&h, &dir, true).await;
	let (status, v) =
		patch(&base, "/config/global", json!({"trusted_proxies": ["192.0.2.0/24"], "http": {"timeouts": {"idle": "8s"}}})).await;
	assert_eq!((status, &v["persisted"], &v["storage"]), (StatusCode::OK, &json!(true), &json!("database")), "{v}");
	let row = store.memory_global().expect("written before the answer");
	assert_eq!(row.spec, json!({"trusted_proxies": ["192.0.2.0/24"], "http": {"timeouts": {"idle": "8s"}}}));
	assert_eq!(row.updated_by, "admin");

	// a write that does not go through: persisted false, written again by the check
	store.fail_writes(true);
	let (status, v) = patch(&base, "/config/global", json!({"http": null})).await;
	assert_eq!((status, &v["persisted"]), (StatusCode::OK, &json!(false)), "in force anyway: {v}");
	assert_eq!(store.memory_global().unwrap().spec["http"]["timeouts"]["idle"], "8s");
	assert!(store.pending().global.is_some(), "handed over by a live upgrade");
	store.fail_writes(false);
	let done = store.reconcile(&h.registry).await.unwrap();
	assert!(done.written >= 1, "{done:?}");
	assert_eq!(store.memory_global().unwrap().spec, json!({"trusted_proxies": ["192.0.2.0/24"]}));
	assert_eq!(h.registry.global().persisted(), Some(true));

	// a restart: the row, read before the rules (as main does), in force again;
	// an item the file now sets stays shadowed
	// what main builds from the file at the start
	let again = harness_with_global(tokens(&dir), rproxy_api::l7::access::HttpGlobal::without_file(&["10.0.0.0/8".to_string()])).await;
	again.registry.set_persist(Arc::new(Store::memory("node-a")));
	init_with_file(&again, "version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}\n", true);
	let mut stored = store.memory_global().unwrap();
	stored.spec = json!({"trusted_proxies": ["192.0.2.0/24"], "http": {"timeouts": {"idle": "9s"}}});
	let values: Values = serde_json::from_value(stored.spec.clone()).unwrap();
	let http = again.registry.http_global();
	again.registry.global().restore(&http, values, Some(stored.updated_by.clone()), Some(stored.updated_at), Some(true), "database").await;
	assert_eq!(http.timeouts().idle, Some(Duration::from_secs(9)));
	assert!(http.trusts("10.0.0.1".parse().unwrap()) && !http.trusts("192.0.2.1".parse().unwrap()), "the file wins");
	let base = api(&again, &dir, true).await;
	let (_, v) = call(&base, "admin", Method::GET, "/config/global", None).await;
	assert_eq!(
		(&v["items"]["http.timeouts"]["source"], &v["updated_by"], &v["persisted"]),
		(&json!("api"), &json!("admin"), &json!(true)),
		"{v}"
	);
	assert_eq!(
		(&v["items"]["trusted_proxies"]["source"], &v["items"]["trusted_proxies"]["shadowed"]),
		(&json!("file"), &json!(true)),
		"{v}"
	);
	assert_eq!(v["warnings"][0]["code"], "config.global_shadowed", "{v}");
	fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_live_upgrade_hands_the_values_over() {
	let dir = workdir("handoff");
	let old = harness_with(tokens(&dir)).await;
	let old_store = Arc::new(Store::memory("node-a"));
	old.registry.set_persist(old_store.clone());
	init_with_file(&old, "version: 1\n", true);
	let base = api(&old, &dir, true).await;
	let (status, v) =
		patch(&base, "/config/global", json!({"trusted_proxies": ["198.51.100.0/24"], "http": {"timeouts": {"idle": "11s"}}})).await;
	assert_eq!(status, StatusCode::OK, "{v}");

	let state = handoff::prepare(&old.registry, Duration::from_secs(5)).await.unwrap();
	let state: handoff::State = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
	assert!(state.global.is_some());
	let new = harness_with(tokens(&dir)).await;
	new.registry.set_persist(Arc::new(old_store.memory_after_upgrade()));
	init_with_file(&new, "version: 1\n", true);
	state.restore_rules(&new.registry).await;
	old_store.release().await;

	let http = new.registry.http_global();
	assert!(http.trusts("198.51.100.1".parse().unwrap()));
	assert_eq!(http.timeouts().idle, Some(Duration::from_secs(11)));
	let base = api(&new, &dir, true).await;
	let (_, v) = call(&base, "admin", Method::GET, "/config/global", None).await;
	assert_eq!(
		(&v["items"]["trusted_proxies"]["source"], &v["persisted"], &v["updated_by"]),
		(&json!("api"), &json!(true), &json!("admin")),
		"{v}"
	);
	fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_reload_that_brings_the_item_into_the_file_wins() {
	let dir = workdir("reload");
	let h = harness_with(tokens(&dir)).await;
	let file = dir.join("rproxy.yaml");
	fs::write(&file, "version: 1\n").unwrap();
	let doc = ConfigDoc::load(&file).unwrap();
	h.registry.global().init(Some((&doc.global, &doc.global_raw)), Values::default(), Default::default(), 1, false);
	let input = CheckInput { path: file.clone(), reserved: vec![], max_range_ports: 100, warn_days: 14 };
	let reloader = ConfigReloader::new(doc, h.registry.clone(), input);
	let base = api(&h, &dir, true).await;
	let (status, _) = patch(&base, "/config/global", json!({"trusted_proxies": ["192.0.2.0/24"]})).await;
	assert_eq!(status, StatusCode::OK);
	let http = h.registry.http_global();
	assert!(http.trusts("192.0.2.1".parse().unwrap()));

	fs::write(&file, "version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}\n").unwrap();
	let Outcome::Applied(applied) = reloader.reload(true).await else { panic!("not applied") };
	assert!(applied.restart_needed.is_empty(), "a live item: {applied:?}");
	assert!(http.trusts("10.0.0.1".parse().unwrap()) && !http.trusts("192.0.2.1".parse().unwrap()), "the file wins");
	let (_, v) = call(&base, "admin", Method::GET, "/config/global", None).await;
	assert_eq!(
		(&v["items"]["trusted_proxies"]["shadowed"], &v["items"]["trusted_proxies"]["api_value"]),
		(&json!(true), &json!(["192.0.2.0/24"])),
		"{v}"
	);
	assert_eq!(
		(&v["warnings"][0]["code"], &v["warnings"][0]["item"]),
		(&json!("config.global_shadowed"), &json!("trusted_proxies")),
		"{v}"
	);
	let (status, e) = patch(&base, "/config/global", json!({"trusted_proxies": null})).await;
	assert_eq!((status, &e["code"]), (StatusCode::CONFLICT, &json!("static")), "the file's now: {e}");

	// a mistake in the file's live item refuses the reload, nothing changes
	fs::write(&file, "version: 1\nglobal: {access_log: /nonexistent-rproxy/a.log}\n").unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Failed(e) if e.contains("does not exist")));
	assert!(http.trusts("10.0.0.1".parse().unwrap()));

	// the file leaves it out again: the API's value is in force again
	fs::write(&file, "version: 1\n").unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Applied(_)));
	assert!(http.trusts("192.0.2.1".parse().unwrap()) && !http.trusts("10.0.0.1".parse().unwrap()));
	let (_, v) = call(&base, "admin", Method::GET, "/config/global", None).await;
	assert_eq!((&v["items"]["trusted_proxies"]["source"], &v["warnings"]), (&json!("api"), &json!([])), "{v}");
	fs::remove_dir_all(dir).unwrap();
}
