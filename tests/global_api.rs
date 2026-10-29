//! `global` through the control API (#342): `GET` / `PATCH /config/global`. Items
//! the settings file (or the environment) sets are the file's (`409 static`), the
//! start-only ones are not changed (`409 restart_only`), the live ones are in force
//! for the next request, connection or UDP session, stored in `rproxy_global` and
//! restored before the rules, handed over by a live upgrade, and a reload that
//! brings an item into the file shadows the API's value.

#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use rproxy_api::config::ConfigDoc;
use rproxy_api::config::check::CheckInput;
use rproxy_api::config::global::{Options, Values};
use rproxy_api::config::persist::{Store, StoredGlobal};
use rproxy_api::config::reload::{ConfigReloader, Outcome};
use rproxy_api::control::api::{AppState, router};
use rproxy_api::control::auth::Tokens;
use rproxy_api::control::upgrade::handoff;
use rproxy_api::core::rule::Origin;
use rproxy_api::l7::middleware::crowdsec::Verdict;

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
fn tokens(dir: &Path) -> Tokens {
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

/// A control API on the registry; `unix: true` stands for the Unix socket (the
/// secret-related items are accepted), `false` for TCP.
async fn api(h: &Harness, dir: &Path, unix: bool) -> String {
	let app =
		router(Arc::new(AppState { registry: h.registry.clone(), tokens: Arc::new(tokens(dir)), reloader: None, reload_unix_only: !unix }));
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move { axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap() });
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

async fn view(base: &str) -> Value {
	call(base, "admin", Method::GET, "/config/global", None).await.1
}

/// An HTTP backend answering the client address it was told about (`X-Real-IP`).
async fn echo_backend() -> SocketAddr {
	let app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
		let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		axum::Json(json!({"real": h("x-real-ip"), "xff": h("x-forwarded-for")}))
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

/// A CrowdSec LAPI with one decision (192.0.2.66 banned) for the key `lapi-key`.
async fn fake_lapi() -> SocketAddr {
	let app = axum::Router::new().route(
		"/v1/decisions/stream",
		axum::routing::get(|headers: axum::http::HeaderMap| async move {
			if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some("lapi-key") {
				return (axum::http::StatusCode::FORBIDDEN, axum::Json(json!({"message": "access forbidden"})));
			}
			let ban = json!({"id": 1, "scope": "Ip", "value": "192.0.2.66", "type": "ban", "duration": "4h", "origin": "crowdsec", "scenario": "test"});
			(axum::http::StatusCode::OK, axum::Json(json!({"new": [ban], "deleted": null})))
		}),
	);
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

/// A port nothing answers on.
fn dead_port() -> u16 {
	std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn crowdsec(lapi: &str, key: &Path, appsec: Option<&str>) -> Value {
	let mut c = json!({"lapi_url": lapi, "api_key_file": key, "update_interval": "1s"});
	if let Some(a) = appsec {
		c["appsec_url"] = json!(a);
	}
	c
}

fn banned(h: &Harness) -> bool {
	h.registry.http_global().crowdsec().is_some_and(|b| b.check_ip("192.0.2.66".parse().unwrap()) == Verdict::Block)
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

fn http_rule(port: u16, backend: SocketAddr) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
		"http": {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}")}]}})
}

fn crowdsec_rule(port: u16, backend: SocketAddr, appsec: bool) -> Value {
	let mut r = http_rule(port, backend);
	r["http"]["routes"][0]["middlewares"] = json!(["cs"]);
	r["http"]["middlewares"] = json!({"cs": {"crowdsec": {"appsec": appsec}}});
	r
}

fn options(dir: &Path, database: bool) -> Options {
	Options { keep_files: 1, access_log_dir: Some(dir.to_path_buf()), database, sync_wait: Duration::from_secs(2), ..Default::default() }
}

/// The file's `global` as `main` gives it to the settings at the start.
fn init_with_file(h: &Harness, dir: &Path, text: &str, database: bool) -> ConfigDoc {
	let doc = ConfigDoc::parse(Path::new("rproxy.yaml"), text).unwrap();
	h.registry.global().init(Some((&doc.global, &doc.global_raw)), Values::default(), Default::default(), options(dir, database));
	doc
}

#[tokio::test]
async fn the_api_sets_what_the_file_leaves_out_and_the_next_request_takes_it() {
	let dir = workdir("patch");
	let h = harness_with(tokens(&dir)).await;
	init_with_file(&h, &dir, "version: 1\nglobal: {http: {timeouts: {idle: 5m}}}\n", false);
	let tcp = api(&h, &dir, false).await;
	let unix = api(&h, &dir, true).await;

	assert_eq!(call(&tcp, "reader", Method::GET, "/config/global", None).await.0, StatusCode::FORBIDDEN, "admin only");
	let v = view(&tcp).await;
	assert_eq!((&v["items"]["http.timeouts"]["source"], &v["items"]["http.timeouts"]["settable"]), (&json!("file"), &json!(false)), "{v}");
	assert_eq!(v["items"]["http.timeouts"]["value"]["idle"], "5m");
	assert_eq!((&v["items"]["performance"]["apply"], &v["items"]["crowdsec"]["unix_only"]), (&json!("restart"), &json!(true)));
	assert_eq!((&v["items"]["trusted_proxies"]["unix_only"], &v["items"]["udp_max_sessions"]["unix_only"]), (&json!(true), &json!(false)));
	assert_eq!((&v["storage"], &v["loaded"]), (&json!("memory"), &json!(true)), "no database: the values live in this process");

	// the file's item, a start-only item, secret-related items over TCP, mistakes
	let (status, e) = patch(&unix, "/config/global", json!({"http": {"timeouts": {"idle": "1s"}}, "access_log": null})).await;
	assert_eq!((status, &e["code"], &e["items"]), (StatusCode::CONFLICT, &json!("static"), &json!(["http.timeouts"])), "{e}");
	let (status, e) = patch(&unix, "/config/global", json!({"performance": {"workers": 2}})).await;
	assert_eq!((status, &e["code"], &e["items"]), (StatusCode::CONFLICT, &json!("restart_only"), &json!(["performance"])), "{e}");
	for body in [json!({"crowdsec": null}), json!({"trusted_proxies": ["0.0.0.0/0"]}), json!({"access_log": dir.join("a.log")})] {
		let (status, e) = patch(&tcp, "/config/global?dry_run=true", body.clone()).await;
		assert_eq!((status, &e["code"]), (StatusCode::FORBIDDEN, &json!("forbidden")), "{body}: {e}");
		let text = e["error"].as_str().unwrap_or_default();
		assert!(text.contains("only over the Unix socket") && !text.contains("RPROXY_API_RELOAD_UNIX_ONLY"), "{text}");
	}
	for body in [json!({"trusted_proxies": ["nope"]}), json!({"nope": 1}), json!({}), json!([1]), json!({"udp_max_sessions": -1})] {
		let (status, e) = patch(&unix, "/config/global", body.clone()).await;
		assert_eq!((status, &e["code"]), (StatusCode::BAD_REQUEST, &json!("invalid")), "{body}: {e}");
	}
	// access logs stay in their directory (no file anywhere else is written or rotated away)
	for p in ["/etc/profile.d/rproxy.sh", "/proc/self/a.log"] {
		let (status, e) = patch(&unix, "/config/global", json!({"access_log": p})).await;
		assert_eq!((status, &e["code"]), (StatusCode::FORBIDDEN, &json!("protected_file")), "{p}: {e}");
	}

	// trusted_proxies: the next request believes the proxy's X-Forwarded-For
	let backend = echo_backend().await;
	let port = free_port();
	let (status, v) = call(&tcp, "admin", Method::POST, "/rules", Some(http_rule(port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(real_ip(port).await, "127.0.0.1");
	let (status, plan) = patch(&unix, "/config/global?dry_run=true", json!({"trusted_proxies": ["127.0.0.0/8"]})).await;
	assert_eq!((status, &plan["dry_run"], &plan["applied"]), (StatusCode::OK, &json!(true), &json!(["trusted_proxies"])), "{plan}");
	assert_eq!(real_ip(port).await, "127.0.0.1", "a dry run changes nothing");
	let (status, v) = patch(&unix, "/config/global", json!({"trusted_proxies": ["127.0.0.0/8"]})).await;
	assert_eq!((status, &v["applied"]), (StatusCode::OK, &json!(["trusted_proxies"])), "{v}");
	assert_eq!((&v["items"]["trusted_proxies"]["source"], &v["persisted"]), (&json!("api"), &Value::Null), "{v}");
	assert_eq!(v["changes"][0]["before"], json!([]));
	assert_eq!(real_ip(port).await, "203.0.113.9", "the next request takes it");
	// [] is a value (no proxy trusted, set through the API); null clears it (the default)
	let (_, v) = patch(&unix, "/config/global", json!({"trusted_proxies": []})).await;
	assert_eq!((&v["items"]["trusted_proxies"]["source"], &v["items"]["trusted_proxies"]["api_value"]), (&json!("api"), &json!([])), "{v}");
	assert_eq!(real_ip(port).await, "127.0.0.1");

	// access_log: the next lines go to the file
	let (status, v) = patch(&unix, "/config/global", json!({"access_log": dir.join("access.log")})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	patch(&unix, "/config/global", json!({"trusted_proxies": ["127.0.0.0/8"]})).await;
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
	let (status, v) = patch(&unix, "/config/global", json!({"trusted_proxies": null, "access_log": null})).await;
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
	init_with_file(&h, &dir, "version: 1\n", false);
	let base = api(&h, &dir, false).await;

	let backend = udp_backend("U:").await;
	let port = free_udp_port();
	let (status, v) = call(&base, "admin", Method::POST, "/rules", Some(rule("udp", port, backend))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v) = patch(&base, "/config/global", json!({"udp_max_sessions": 1})).await;
	assert_eq!((status, &v["items"]["udp_max_sessions"]["value"]), (StatusCode::OK, &json!(1)), "over TCP: {v}");
	let client = || async move {
		let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		s.connect(("127.0.0.1", port)).await.unwrap();
		s
	};
	let a = client().await;
	assert_eq!(udp_roundtrip(&a, "1").await, "U:1");
	let b = client().await;
	b.send(b"2").await.unwrap();
	let mut buf = [0u8; 64];
	assert!(tokio::time::timeout(Duration::from_millis(500), b.recv(&mut buf)).await.is_err(), "over the cap");
	patch(&base, "/config/global", json!({"udp_max_sessions": null})).await;
	assert_eq!(udp_roundtrip(&b, "3").await, "U:3", "back to the default cap");

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
	patch(&base, "/config/global", json!({"http": null})).await;
	let mut next = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	assert!(tokio::time::timeout(Duration::from_millis(1500), next.read(&mut buf)).await.is_err(), "still open after 1.5 s");
	next.write_all(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").await.unwrap();
	assert!(next.read(&mut buf).await.unwrap() > 0);
	fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn crowdsec_through_the_unix_socket_swaps_only_a_synced_bouncer() {
	let dir = workdir("crowdsec");
	let h = harness_with(tokens(&dir)).await;
	init_with_file(&h, &dir, "version: 1\n", false);
	let unix = api(&h, &dir, true).await;
	let key = dir.join("crowdsec.key");
	fs::write(&key, "lapi-key\n").unwrap();
	let lapi = format!("http://{}", fake_lapi().await);
	let backend = echo_backend().await;
	let port = free_port();
	let (status, e) = call(&unix, "admin", Method::POST, "/rules", Some(crowdsec_rule(port, backend, false))).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "needs global.crowdsec: {e}");

	let (status, v) = patch(&unix, "/config/global", json!({"crowdsec": crowdsec(&lapi, &key, None)})).await;
	assert_eq!((status, &v["items"]["crowdsec"]["source"]), (StatusCode::OK, &json!("api")), "{v}");
	assert!(banned(&h), "in force only once it has the LAPI's decisions");
	let (status, v) = call(&unix, "admin", Method::POST, "/rules", Some(crowdsec_rule(port, backend, false))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	// a LAPI that does not answer: refused, the synced bouncer stays (never a gap that lets clients in)
	let dead = format!("http://127.0.0.1:{}", dead_port());
	let started = Instant::now();
	let (status, e) = patch(&unix, "/config/global", json!({"crowdsec": crowdsec(&dead, &key, None)})).await;
	assert_eq!((status, &e["code"]), (StatusCode::BAD_GATEWAY, &json!("crowdsec_unavailable")), "{e}");
	assert!(started.elapsed() >= Duration::from_secs(2), "waited for the first pull");
	assert!(banned(&h), "the bouncer in force stays");
	assert_eq!(view(&unix).await["items"]["crowdsec"]["value"]["lapi_url"], json!(lapi));

	// rules use it: not taken away, nor its appsec
	let (status, e) = patch(&unix, "/config/global", json!({"crowdsec": null})).await;
	assert_eq!((status, &e["code"]), (StatusCode::CONFLICT, &json!("in_use")), "{e}");
	// the key file set through the API is protected from rules
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

/// A PATCH clearing `crowdsec` and rules using it created at the same time: the
/// rules lock orders them, so a rule using crowdsec never runs without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clearing_crowdsec_never_crosses_a_rule_that_needs_it() {
	let dir = workdir("race");
	let h = harness_with(tokens(&dir)).await;
	init_with_file(&h, &dir, "version: 1\n", false);
	let unix = api(&h, &dir, true).await;
	let key = dir.join("crowdsec.key");
	fs::write(&key, "lapi-key\n").unwrap();
	let lapi = format!("http://{}", fake_lapi().await);
	let backend = echo_backend().await;
	for round in 0..10 {
		let (status, _) = patch(&unix, "/config/global", json!({"crowdsec": crowdsec(&lapi, &key, None)})).await;
		assert_eq!(status, StatusCode::OK);
		let ports: Vec<u16> = (0..4).map(|_| free_port()).collect();
		let creates: Vec<_> = ports
			.iter()
			.map(|p| {
				let (unix, body) = (unix.clone(), crowdsec_rule(*p, backend, false));
				tokio::spawn(async move { call(&unix, "admin", Method::POST, "/rules", Some(body)).await.0 })
			})
			.collect();
		let clear = {
			let unix = unix.clone();
			tokio::spawn(async move { patch(&unix, "/config/global", json!({"crowdsec": null})).await.0 })
		};
		let created: Vec<StatusCode> = futures_join(creates).await;
		let cleared = clear.await.unwrap();
		let present = h.registry.http_global().crowdsec().is_some();
		let running = created.iter().filter(|s| **s == StatusCode::CREATED).count();
		assert!(present || running == 0, "round {round}: {running} rules use crowdsec, which is gone (PATCH {cleared})");
		assert_eq!(present, cleared != StatusCode::OK, "round {round}");
		for p in ports {
			call(&unix, "admin", Method::DELETE, &format!("/rules/tcp/127.0.0.1/{p}"), None).await;
		}
	}
	fs::remove_dir_all(dir).unwrap();
}

async fn futures_join(tasks: Vec<tokio::task::JoinHandle<StatusCode>>) -> Vec<StatusCode> {
	let mut out = vec![];
	for t in tasks {
		out.push(t.await.unwrap());
	}
	out
}

#[tokio::test]
async fn stored_restored_and_written_again() {
	let dir = workdir("persist");
	let h = harness_with(tokens(&dir)).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	init_with_file(&h, &dir, "version: 1\n", true);
	let base = api(&h, &dir, true).await;
	// what a newer version stored: kept and written back
	store.memory_put_global(StoredGlobal { spec: json!({"later": {"x": 1}}), spec_version: 2, updated_by: "new".into(), updated_at: 1 });
	let row = store.memory_global().unwrap();
	h.registry.global().restore(&h.registry, &row.spec, Some(row.updated_by), Some(row.updated_at), Some(true), None, "database").await;
	let (status, v) =
		patch(&base, "/config/global", json!({"http": {"timeouts": {"idle": "8s"}}, "trusted_proxies": ["192.0.2.0/24"]})).await;
	assert_eq!((status, &v["persisted"], &v["storage"]), (StatusCode::OK, &json!(true), &json!("database")), "{v}");
	let row = store.memory_global().expect("written before the answer");
	assert_eq!(row.spec, json!({"later": {"x": 1}, "http": {"timeouts": {"idle": "8s"}}, "trusted_proxies": ["192.0.2.0/24"]}));
	assert_eq!((row.updated_by.as_str(), row.spec_version), ("admin", 1));
	patch(&base, "/config/global", json!({"trusted_proxies": null})).await;

	// a write that does not go through: persisted false, written again by the check
	store.fail_writes(true);
	let (status, v) = patch(&base, "/config/global", json!({"http": null})).await;
	assert_eq!((status, &v["persisted"]), (StatusCode::OK, &json!(false)), "in force anyway: {v}");
	assert!(store.pending().global.is_some(), "handed over by a live upgrade");
	store.fail_writes(false);
	let done = store.reconcile(&h.registry).await.unwrap();
	assert!(done.written >= 1, "{done:?}");
	assert_eq!(store.memory_global().unwrap().spec, json!({"later": {"x": 1}}));
	assert_eq!(h.registry.global().persisted(), Some(true));

	// a restart: the row, read before the rules (as main does), in force again; an
	// item the file now sets stays shadowed
	let again = harness_with_global(tokens(&dir), rproxy_api::l7::access::HttpGlobal::without_file(&["10.0.0.0/8".to_string()])).await;
	again.registry.set_persist(Arc::new(Store::memory("node-a")));
	init_with_file(&again, &dir, "version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}\n", true);
	let spec = json!({"trusted_proxies": ["192.0.2.0/24"], "http": {"timeouts": {"idle": "9s"}}});
	again.registry.global().restore(&again.registry, &spec, Some("admin".into()), Some(1), Some(true), None, "database").await;
	let http = again.registry.http_global();
	assert_eq!(http.timeouts().idle, Some(Duration::from_secs(9)));
	assert!(http.trusts("10.0.0.1".parse().unwrap()) && !http.trusts("192.0.2.1".parse().unwrap()), "the file wins");
	let v = view(&api(&again, &dir, false).await).await;
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

/// The stored values could not be read at the start: a PATCH would overwrite them,
/// so it waits (503) until the periodic check has read them.
#[tokio::test]
async fn a_change_waits_for_the_stored_values() {
	let dir = workdir("unread");
	let h = harness_with(tokens(&dir)).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	init_with_file(&h, &dir, "version: 1\n", true);
	store.memory_put_global(StoredGlobal {
		spec: json!({"trusted_proxies": ["192.0.2.0/24"], "http": {"timeouts": {"idle": "6s"}}}),
		spec_version: 1,
		updated_by: "ui".into(),
		updated_at: 1,
	});
	// as main does when load_global fails
	h.registry.global().set_not_loaded();
	let base = api(&h, &dir, false).await;
	let (status, e) = patch(&base, "/config/global", json!({"http": {"timeouts": {"idle": "7s"}}})).await;
	assert_eq!((status, &e["code"]), (StatusCode::SERVICE_UNAVAILABLE, &json!("not_loaded")), "{e}");
	assert_eq!(view(&base).await["loaded"], false);
	assert!(!store.save_global(&h.registry, "x").await, "nothing written over the row");
	store.reconcile(&h.registry).await.unwrap();
	assert_eq!(view(&base).await["items"]["http.timeouts"]["value"]["idle"], "6s");
	let (status, v) = patch(&base, "/config/global", json!({"http": {"timeouts": {"idle": "7s"}}})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(
		store.memory_global().unwrap().spec,
		json!({"trusted_proxies": ["192.0.2.0/24"], "http": {"timeouts": {"idle": "7s"}}}),
		"the other item kept"
	);
	fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn a_live_upgrade_hands_the_values_over() {
	let dir = workdir("handoff");
	let old = harness_with(tokens(&dir)).await;
	let old_store = Arc::new(Store::memory("node-a"));
	old.registry.set_persist(old_store.clone());
	init_with_file(&old, &dir, "version: 1\n", true);
	let base = api(&old, &dir, true).await;
	let (status, v) =
		patch(&base, "/config/global", json!({"trusted_proxies": ["198.51.100.0/24"], "http": {"timeouts": {"idle": "11s"}}})).await;
	assert_eq!(status, StatusCode::OK, "{v}");

	let state = handoff::prepare(&old.registry, Duration::from_secs(5)).await.unwrap();
	let state: handoff::State = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
	assert!(state.global.is_some());
	let new = harness_with(tokens(&dir)).await;
	new.registry.set_persist(Arc::new(old_store.memory_after_upgrade()));
	init_with_file(&new, &dir, "version: 1\n", true);
	state.restore_rules(&new.registry).await;
	old_store.release().await;

	let http = new.registry.http_global();
	assert!(http.trusts("198.51.100.1".parse().unwrap()));
	assert_eq!(http.timeouts().idle, Some(Duration::from_secs(11)));
	let v = view(&api(&new, &dir, false).await).await;
	assert_eq!(
		(&v["items"]["trusted_proxies"]["source"], &v["persisted"], &v["updated_by"]),
		(&json!("api"), &json!(true), &json!("admin")),
		"{v}"
	);
	fs::remove_dir_all(dir).unwrap();
}

fn reloader(h: &Harness, file: &Path) -> ConfigReloader {
	let doc = ConfigDoc::load(file).unwrap();
	let dir = file.parent().unwrap();
	h.registry.global().init(Some((&doc.global, &doc.global_raw)), Values::default(), Default::default(), options(dir, false));
	let input = CheckInput { path: file.to_path_buf(), reserved: vec![], max_range_ports: 100, warn_days: 14 };
	ConfigReloader::new(doc, h.registry.clone(), input)
}

#[tokio::test]
async fn a_reload_that_brings_the_item_into_the_file_wins() {
	let dir = workdir("reload");
	let h = harness_with(tokens(&dir)).await;
	let file = dir.join("rproxy.yaml");
	fs::write(&file, "version: 1\n").unwrap();
	let reloader = reloader(&h, &file);
	let base = api(&h, &dir, true).await;
	let (status, _) = patch(&base, "/config/global", json!({"trusted_proxies": ["192.0.2.0/24"]})).await;
	assert_eq!(status, StatusCode::OK);
	let http = h.registry.http_global();
	assert!(http.trusts("192.0.2.1".parse().unwrap()));

	fs::write(&file, "version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}\n").unwrap();
	let Outcome::Applied(applied) = reloader.reload(true).await else { panic!("not applied") };
	assert!(applied.restart_needed.is_empty(), "a live item: {applied:?}");
	assert!(http.trusts("10.0.0.1".parse().unwrap()) && !http.trusts("192.0.2.1".parse().unwrap()), "the file wins");
	let v = view(&base).await;
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

	// a mistake in a live item refuses the reload, nothing changes
	fs::write(&file, "version: 1\nglobal: {trusted_proxies: [172.16.0.0/12], access_log: /nonexistent-rproxy/a.log}\n").unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Failed(e) if e.contains("does not exist")));
	assert!(http.trusts("10.0.0.1".parse().unwrap()) && !http.trusts("172.16.0.1".parse().unwrap()));
	// a rule that does not validate refuses it too: the global items stay as they were
	fs::write(
		&file,
		format!(
			"version: 1\nglobal: {{trusted_proxies: [172.16.0.0/12]}}\nrules: [{{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {}, remote_addr: 127.0.0.1, remote_port: 1, allow_from: [nope]}}]\n",
			free_port()
		),
	)
	.unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Failed(_)));
	assert!(http.trusts("10.0.0.1".parse().unwrap()) && !http.trusts("172.16.0.1".parse().unwrap()), "nothing changed");

	// the file leaves it out again: the API's value is in force again
	fs::write(&file, "version: 1\n").unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Applied(_)));
	assert!(http.trusts("192.0.2.1".parse().unwrap()) && !http.trusts("10.0.0.1".parse().unwrap()));
	let v = view(&base).await;
	assert_eq!((&v["items"]["trusted_proxies"]["source"], &v["warnings"]), (&json!("api"), &json!([])), "{v}");
	fs::remove_dir_all(dir).unwrap();
}

/// A reload does not take away (or break the appsec of) a CrowdSec that rules use,
/// nor swap in a bouncer whose LAPI does not answer: the one in force stays (kept),
/// also over unrelated changes and a live upgrade.
#[tokio::test]
async fn a_reload_keeps_the_crowdsec_rules_need() {
	let dir = workdir("reload-cs");
	let h = harness_with(tokens(&dir)).await;
	let key = dir.join("crowdsec.key");
	fs::write(&key, "lapi-key\n").unwrap();
	let lapi = format!("http://{}", fake_lapi().await);
	let appsec = format!("http://127.0.0.1:{}", dead_port());
	let file = dir.join("rproxy.yaml");
	let with = |c: Value| format!("version: 1\nglobal: {{crowdsec: {c}}}\n");
	fs::write(&file, "version: 1\n").unwrap();
	let reloader = reloader(&h, &file);
	let unix = api(&h, &dir, true).await;
	fs::write(&file, with(crowdsec(&lapi, &key, Some(&appsec)))).unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Applied(_)));
	assert!(banned(&h), "synced before it was put in force");
	let backend = echo_backend().await;
	let port = free_port();
	assert_eq!(call(&unix, "admin", Method::POST, "/rules", Some(crowdsec_rule(port, backend, true))).await.0, StatusCode::CREATED);

	// a LAPI that does not answer: the bouncer in force stays
	let dead = format!("http://127.0.0.1:{}", dead_port());
	fs::write(&file, with(crowdsec(&dead, &key, Some(&appsec)))).unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Applied(_)));
	assert!(banned(&h));
	assert_eq!(view(&unix).await["items"]["crowdsec"]["value"]["lapi_url"], json!(lapi));
	// without appsec_url (the rule uses appsec): kept
	fs::write(&file, with(crowdsec(&lapi, &key, None))).unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Applied(_)));
	assert!(h.registry.http_global().crowdsec().is_some_and(|b| b.has_appsec()));
	// taken out of the file: kept while the rule uses it, shown, over an unrelated PATCH too
	fs::write(&file, "version: 1\n").unwrap();
	assert!(matches!(reloader.reload(true).await, Outcome::Applied(_)));
	assert!(banned(&h));
	assert_eq!(patch(&unix, "/config/global", json!({"http": {"timeouts": {"idle": "9s"}}})).await.0, StatusCode::OK);
	assert!(banned(&h), "an unrelated change keeps it");
	let v = view(&unix).await;
	assert_eq!((&v["items"]["crowdsec"]["kept"], &v["items"]["crowdsec"]["source"]), (&json!(true), &json!("file")), "{v}");
	let handed = h.registry.global().handoff();
	assert!(handed.kept_crowdsec.is_some(), "handed over");
	// the rule is gone: the next reload lets it go
	assert_eq!(call(&unix, "admin", Method::DELETE, &format!("/rules/tcp/127.0.0.1/{port}"), None).await.0, StatusCode::NO_CONTENT);
	assert!(matches!(reloader.reload(true).await, Outcome::Applied(_)));
	assert!(h.registry.http_global().crowdsec().is_none());
	assert!(view(&unix).await["items"]["crowdsec"].get("kept").is_none());
	fs::remove_dir_all(dir).unwrap();
}

/// `RPROXY_CONFIG` as a directory: `global` in a file that is not the first is the file's.
#[tokio::test]
async fn global_in_a_later_file_of_a_directory_is_the_file_s() {
	let dir = workdir("confd");
	let conf = dir.join("conf.d");
	fs::create_dir_all(&conf).unwrap();
	let backend = tcp_backend("D:").await;
	fs::write(conf.join("10-rules.yaml"), format!("version: 1\nrules: [{}]\n", rule("tcp", free_port(), backend))).unwrap();
	fs::write(conf.join("20-global.yaml"), "version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}\n").unwrap();
	let h = harness_with(tokens(&dir)).await;
	let doc = ConfigDoc::load(&conf).unwrap();
	h.registry.global().init(Some((&doc.global, &doc.global_raw)), Values::default(), Default::default(), options(&dir, false));
	let unix = api(&h, &dir, true).await;
	assert_eq!(view(&unix).await["items"]["trusted_proxies"]["source"], "file");
	let (status, e) = patch(&unix, "/config/global", json!({"trusted_proxies": []})).await;
	assert_eq!((status, &e["code"]), (StatusCode::CONFLICT, &json!("static")), "{e}");
	fs::remove_dir_all(dir).unwrap();
}

/// A PATCH while a reload waits for a new LAPI: it takes its turn after the reload,
/// so the reload does not undo it (what is in force and what GET shows agree).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_patch_during_a_reload_is_not_undone() {
	let dir = workdir("reload-race");
	let h = harness_with(tokens(&dir)).await;
	let key = dir.join("crowdsec.key");
	fs::write(&key, "lapi-key\n").unwrap();
	let file = dir.join("rproxy.yaml");
	fs::write(&file, "version: 1\n").unwrap();
	let reloader = Arc::new(reloader(&h, &file));
	let unix = api(&h, &dir, true).await;
	// a LAPI that does not answer: the reload waits for it (2 s here) holding its turn
	let dead = format!("http://127.0.0.1:{}", dead_port());
	fs::write(&file, format!("version: 1\nglobal: {{crowdsec: {}}}\n", crowdsec(&dead, &key, None))).unwrap();
	let reload = {
		let r = reloader.clone();
		tokio::spawn(async move { r.reload(true).await })
	};
	tokio::time::sleep(Duration::from_millis(300)).await;
	let (status, _) = patch(&unix, "/config/global", json!({"http": {"timeouts": {"idle": "7s"}}})).await;
	assert_eq!(status, StatusCode::OK);
	assert!(matches!(reload.await.unwrap(), Outcome::Applied(_)));
	assert_eq!(h.registry.http_global().timeouts().idle, Some(Duration::from_secs(7)));
	let v = view(&unix).await;
	assert_eq!(
		(&v["items"]["http.timeouts"]["value"]["idle"], &v["items"]["http.timeouts"]["source"]),
		(&json!("7s"), &json!("api")),
		"{v}"
	);
	assert!(h.registry.http_global().crowdsec().is_none(), "the LAPI never answered");
	fs::remove_dir_all(dir).unwrap();
}

/// The stored values read late (the database was down at the start): rules that
/// could not start without their `crowdsec` start once it is in force.
#[tokio::test]
async fn rules_waiting_for_crowdsec_start_once_it_is_read() {
	let dir = workdir("late");
	let h = harness_with(tokens(&dir)).await;
	let store = Arc::new(Store::memory("node-a"));
	h.registry.set_persist(store.clone());
	init_with_file(&h, &dir, "version: 1\n", true);
	let key = dir.join("crowdsec.key");
	fs::write(&key, "lapi-key\n").unwrap();
	let lapi = format!("http://{}", fake_lapi().await);
	store.memory_put_global(StoredGlobal {
		spec: json!({"crowdsec": crowdsec(&lapi, &key, None)}),
		spec_version: 1,
		updated_by: "ui".into(),
		updated_at: 1,
	});
	// as main does when load_global fails, then the rules
	h.registry.global().set_not_loaded();
	let backend = echo_backend().await;
	let port = free_port();
	h.registry.restore_as(vec![serde_json::from_value(crowdsec_rule(port, backend, false)).unwrap()], Origin::Dynamic).await;
	let unix = api(&h, &dir, true).await;
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let (_, v) = call(&unix, "admin", Method::GET, &path, None).await;
	assert_eq!(v["state"], "failed", "{v}");
	store.reconcile(&h.registry).await.unwrap();
	assert!(banned(&h));
	let (_, v) = call(&unix, "admin", Method::GET, &path, None).await;
	assert_eq!(v["state"], "running", "{v}");
	fs::remove_dir_all(dir).unwrap();
}

/// A PATCH that brings `crowdsec` (with its `appsec_url`) starts the rules waiting
/// for it: the rule's own `crowdsec`, the middleware, the middleware's `appsec`
/// (#347: matched by the reason of the error, after the change is done).
#[tokio::test]
async fn a_patch_starts_the_rules_waiting_for_crowdsec() {
	let dir = workdir("patch-waiting");
	let h = harness_with(tokens(&dir)).await;
	init_with_file(&h, &dir, "version: 1\n", false);
	let key = dir.join("crowdsec.key");
	fs::write(&key, "lapi-key\n").unwrap();
	let lapi = format!("http://{}", fake_lapi().await);
	let appsec = format!("http://127.0.0.1:{}", dead_port());
	let backend = echo_backend().await;
	let ports = [free_port(), free_port(), free_port()];
	let mut l4 = rule("tcp", ports[2], backend);
	l4["crowdsec"] = json!(true);
	let rules = [crowdsec_rule(ports[0], backend, false), crowdsec_rule(ports[1], backend, true), l4];
	h.registry.restore_as(rules.into_iter().map(|r| serde_json::from_value(r).unwrap()).collect(), Origin::Dynamic).await;
	let unix = api(&h, &dir, true).await;
	let states = || async {
		let mut out = vec![];
		for port in ports {
			out.push(call(&unix, "admin", Method::GET, &format!("/rules/tcp/127.0.0.1/{port}"), None).await.1["state"].clone());
		}
		out
	};
	assert_eq!(states().await, vec![json!("failed"); 3]);
	let (status, v) = patch(&unix, "/config/global", json!({"crowdsec": crowdsec(&lapi, &key, Some(&appsec))})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(states().await, vec![json!("running"); 3]);
	fs::remove_dir_all(dir).unwrap();
}
