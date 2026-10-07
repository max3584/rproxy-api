//! Diff before change (#169): `dry_run` on the rule endpoints, `POST
//! /config/reload?dry_run`, `POST /config/plan` and `--check-config --diff`.
//! A dry run validates like the change itself and changes nothing.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

use rproxy_api::config::check::CheckInput;
use rproxy_api::config::reload::ConfigReloader;
use rproxy_api::config::ConfigDoc;
use rproxy_api::control::api::{router, AppState};
use rproxy_api::control::auth::Tokens;

use common::*;

async fn send(h: &Harness, method: Method, path: &str, body: Option<Value>) -> (StatusCode, Value) {
	let mut req = h.http.request(method, format!("{}{path}", h.base));
	if let Some(b) = body {
		req = req.json(&b);
	}
	let r = req.send().await.unwrap();
	let status = r.status();
	(status, r.json().await.unwrap_or(Value::Null))
}

fn paths(plan: &Value) -> Vec<&str> {
	plan["diff"].as_array().unwrap().iter().map(|d| d["path"].as_str().unwrap()).collect()
}

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-plan-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

#[tokio::test]
async fn capabilities_say_dry_run() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["dry_run"], true, "{caps}");
}

#[tokio::test]
async fn dry_runs_of_the_rule_endpoints_change_nothing() {
	let h = harness().await;
	let backend = tcp_backend("D:").await;
	let port = free_port();
	let rule_name = format!("tcp/127.0.0.1:{port}");

	// create
	let r = send(&h, Method::POST, "/rules?dry_run=true", Some(rule("tcp", port, backend))).await;
	assert_eq!(r.0, StatusCode::OK, "{}", r.1);
	assert_eq!((r.1["dry_run"].as_bool(), r.1["action"].as_str(), r.1["change"].as_str()), (Some(true), Some("create"), Some("none")));
	assert_eq!(r.1["rule"], rule_name);
	assert!(r.1["before"].is_null());
	assert_eq!(r.1["after"]["remote_port"], backend.port());
	assert!(r.1["after"].get("stats").is_none(), "the shape of a rule, not its view: {}", r.1);
	assert!(paths(&r.1).contains(&"remote_port"));
	let (_, rules) = h.get("/rules").await;
	assert_eq!(rules, json!([]), "a dry run creates nothing");
	assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_ok(), "and binds nothing");

	// refused like the change itself
	let mut bad = rule("tcp", port, backend);
	bad["remote_port"] = json!(0);
	assert_eq!(send(&h, Method::POST, "/rules?dry_run=true", Some(bad)).await.1["code"], "invalid");
	assert_eq!(send(&h, Method::POST, "/rules?dry_run=perhaps", Some(rule("tcp", port, backend))).await.1["code"], "invalid");
	let mut tls = rule("tcp", port, backend);
	tls["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": "/nonexistent.pem", "key_file": "/nonexistent.key"}]});
	let r = send(&h, Method::POST, "/rules?dry_run=true", Some(tls)).await;
	assert_eq!(r.1["code"], "tls_config", "certificates are read: {}", r.1);
	// names are not resolved by a dry run
	let mut named = rule("tcp", port, backend);
	named["remote_addr"] = json!("not-resolvable.invalid");
	assert_eq!(send(&h, Method::POST, "/rules?dry_run=true", Some(named)).await.0, StatusCode::OK);

	assert_eq!(h.post(rule("tcp", port, backend)).await.0, StatusCode::CREATED);
	let r = send(&h, Method::POST, "/rules?dry_run=true", Some(rule("tcp", port, backend))).await;
	assert_eq!((r.0, r.1["code"].as_str()), (StatusCode::CONFLICT, Some("already_exists")));

	// update
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let same = json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()});
	let r = send(&h, Method::PATCH, &format!("{path}?dry_run=1"), Some(same)).await;
	assert_eq!((r.0, r.1["action"].as_str(), r.1["change"].as_str()), (StatusCode::OK, Some("none"), Some("none")), "{}", r.1);
	assert!(r.1["diff"].as_array().unwrap().is_empty());
	let moved = json!({"remote_addr": "127.0.0.1", "remote_port": backend.port() + 1, "allow_from": ["10.0.0.0/8"]});
	let r = send(&h, Method::PATCH, &format!("{path}?dry_run=true"), Some(moved)).await;
	assert_eq!((r.1["action"].as_str(), r.1["change"].as_str()), (Some("update"), Some("in_place")), "{}", r.1);
	assert_eq!(paths(&r.1), ["allow_from", "remote_port"]);
	assert_eq!(r.1["before"]["state"], "running", "before is the rule's view");
	assert_eq!(r.1["diff"][1]["before"], backend.port());
	let r = send(&h, Method::PATCH, &format!("{path}?dry_run=true"), Some(json!({"remote_addr": "127.0.0.1", "remote_port": 1, "source_ip": "proxy_v2"}))).await;
	assert_eq!(r.1["code"], "unsupported", "{}", r.1);
	let (_, view) = h.get(&path).await;
	assert_eq!(view["remote_port"], backend.port(), "unchanged");
	assert_eq!(view["allow_from"], json!([]));

	// delete
	let r = send(&h, Method::DELETE, &format!("{path}?dry_run=true"), None).await;
	assert_eq!((r.1["action"].as_str(), r.1["change"].as_str()), (Some("delete"), Some("none")), "{}", r.1);
	assert!(r.1["after"].is_null());
	assert_eq!(h.get(&path).await.0, StatusCode::OK, "still there");
	let r = send(&h, Method::DELETE, &format!("/rules/tcp/127.0.0.1/{}?dry_run=true", free_port()), None).await;
	assert_eq!(r.0, StatusCode::NOT_FOUND);

	// static rules stay refused
	let static_port = free_port();
	h.registry.load_static(vec![serde_json::from_value(rule("tcp", static_port, backend)).unwrap()]).await.unwrap();
	let r = send(&h, Method::DELETE, &format!("/rules/tcp/127.0.0.1/{static_port}?dry_run=true"), None).await;
	assert_eq!((r.0, r.1["code"].as_str()), (StatusCode::CONFLICT, Some("static")));
	let r = send(&h, Method::PATCH, &format!("/rules/tcp/127.0.0.1/{static_port}?dry_run=true"), Some(json!({"remote_addr": "127.0.0.1", "remote_port": 1}))).await;
	assert_eq!(r.1["code"], "static");
}

/// `PUT /rulesets/{name}?dry_run=true` (#28): the set's checks, then what
/// would happen to each rule, through the same plan engine; nothing changes.
#[tokio::test]
async fn rule_set_dry_runs_change_nothing() {
	let h = harness().await;
	let backend = tcp_backend("U:").await;
	let (keep, moved, proto, dropped, added) = (free_port(), free_port(), free_port(), free_port(), free_port());
	let set = json!({"generation": 1, "rules": [rule("tcp", keep, backend), rule("tcp", moved, backend), rule("tcp", proto, backend), rule("tcp", dropped, backend)]});
	let r = send(&h, Method::PUT, "/rulesets/k8s/plan", Some(set)).await;
	assert_eq!(r.0, StatusCode::OK, "{}", r.1);
	let etag = r.1["etag"].clone();

	let mut changed = rule("tcp", moved, backend);
	changed["remote_port"] = json!(backend.port() + 1);
	let mut v2 = rule("tcp", proto, backend);
	v2["source_ip"] = json!("proxy_v2");
	let body = json!({"generation": 2, "rules": [rule("tcp", keep, backend), changed, v2, rule("tcp", added, backend)]});
	let r = send(&h, Method::PUT, "/rulesets/k8s/plan?dry_run=true", Some(body)).await;
	assert_eq!((r.0, r.1["dry_run"].as_bool()), (StatusCode::OK, Some(true)), "{}", r.1);
	assert_ne!(r.1["etag"], etag, "the etag the set would have");
	let result = |port: u16| {
		r.1["results"].as_array().unwrap().iter().find(|x| x["rule"] == format!("tcp/127.0.0.1:{port}")).unwrap_or_else(|| panic!("{port}: {}", r.1)).clone()
	};
	let pair = |v: &Value| (v["action"].as_str().unwrap().to_string(), v["change"].as_str().unwrap().to_string());
	assert_eq!(pair(&result(keep)), ("none".into(), "none".into()));
	assert_eq!(pair(&result(moved)), ("update".into(), "in_place".into()));
	assert_eq!(result(moved)["diff"], json!([{"path": "remote_port", "before": backend.port(), "after": backend.port() + 1}]));
	assert_eq!(pair(&result(proto)), ("update".into(), "recreate".into()), "source_ip cannot change in place");
	assert_eq!(pair(&result(dropped)), ("delete".into(), "none".into()));
	assert_eq!(pair(&result(added)), ("create".into(), "none".into()));
	// a rule of the set is changed only through it, dry runs included
	let r = send(&h, Method::DELETE, &format!("/rules/tcp/127.0.0.1/{keep}?dry_run=true"), None).await;
	assert_eq!(r.1["code"], "owned", "{}", r.1);

	let (_, now) = h.get("/rulesets/k8s/plan").await;
	assert_eq!((&now["generation"], &now["etag"]), (&json!(1), &etag), "nothing changed: {now}");
	assert_eq!(h.get(&format!("/rules/tcp/127.0.0.1/{dropped}")).await.0, StatusCode::OK);
	assert_eq!(h.get(&format!("/rules/tcp/127.0.0.1/{moved}")).await.1["remote_port"], backend.port());
	assert!(std::net::TcpListener::bind(("127.0.0.1", added)).is_ok(), "nothing bound");
	// refused like the PUT itself
	let r = send(&h, Method::PUT, "/rulesets/k8s/plan?dry_run=true", Some(json!({"generation": 0, "rules": []}))).await;
	assert_eq!(r.1["code"], "stale_generation", "{}", r.1);
}

/// A token's allow_listen_ports applies to dry runs too.
#[tokio::test]
async fn dry_runs_need_the_same_permissions() {
	let dir = workdir("scopes");
	let file = dir.join("tokens.yaml");
	let sha = |s: &str| {
		use sha2::Digest;
		sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>()
	};
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: narrow, sha256: {}, scopes: [rules:write], allow_listen_ports: 1-2}}\n  - {{name: reader, sha256: {}, scopes: [rules:read]}}\n",
			sha("narrow"),
			sha("reader")
		),
	)
	.unwrap();
	let h = harness_with(Tokens::from_file(file).unwrap()).await;
	let body = rule("tcp", free_port(), "127.0.0.1:9".parse().unwrap());
	let post = |token: &'static str| h.http.post(format!("{}/rules?dry_run=true", h.base)).bearer_auth(token).json(&body).send();
	assert_eq!(post("narrow").await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(post("reader").await.unwrap().status(), StatusCode::FORBIDDEN);
	fs::remove_dir_all(dir).unwrap();
}

/// A control API that takes POST /config/reload and /config/plan over TCP.
async fn admin_api(h: &Harness, reloader: Option<Arc<ConfigReloader>>) -> String {
	let app = router(Arc::new(AppState {
		registry: h.registry.clone(),
		tokens: Arc::new(Tokens::disabled()),
		reloader,
		reload_unix_only: false,
	}));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move { axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap() });
	base
}

async fn post(h: &Harness, url: String, body: Option<Value>) -> (StatusCode, Value) {
	let mut req = h.http.post(url);
	if let Some(b) = body {
		req = req.json(&b);
	}
	let r = req.send().await.unwrap();
	let status = r.status();
	(status, r.json::<Value>().await.unwrap_or(Value::Null))
}

fn change<'a>(plan: &'a Value, rule: &str) -> &'a Value {
	plan["changes"].as_array().unwrap().iter().find(|c| c["rule"] == rule).unwrap_or_else(|| panic!("{rule}: {plan}"))
}

#[tokio::test]
async fn config_plan_compares_with_the_static_rules() {
	let h = harness().await;
	let backend = tcp_backend("P:").await;
	let (keep, change_it, recreate, drop_it, add, api) = (free_port(), free_port(), free_port(), free_port(), free_port(), free_port());
	let static_rule = |port: u16| rule("tcp", port, backend);
	let reqs = [keep, change_it, recreate, drop_it].map(|p| serde_json::from_value(static_rule(p)).unwrap()).to_vec();
	h.registry.load_static(reqs).await.unwrap();
	assert_eq!(h.post(rule("tcp", api, backend)).await.0, StatusCode::CREATED);
	let base = admin_api(&h, None).await;

	let mut changed = static_rule(change_it);
	changed["remote_port"] = json!(backend.port() + 1);
	let mut recreated = static_rule(recreate);
	recreated["source_ip"] = json!("proxy_v2");
	let doc = json!({"version": 1, "global": {"trusted_proxies": ["10.0.0.0/8"]},
		"rules": [static_rule(keep), changed, recreated, static_rule(add), static_rule(api)]});
	let (status, plan) = post(&h, format!("{base}/config/plan"), Some(doc)).await;
	assert_eq!(status, StatusCode::OK, "{plan}");
	assert_eq!(plan["dry_run"], true);
	assert_eq!(
		(&plan["added"], &plan["removed"], &plan["changed"], &plan["unchanged"], &plan["failed"]),
		(&json!(2), &json!(1), &json!(2), &json!(1), &json!(1)),
		"{plan}"
	);
	assert_eq!(plan["restart_needed"], json!(["global.trusted_proxies"]));
	let c = change(&plan, &format!("tcp/127.0.0.1:{change_it}"));
	assert_eq!((c["action"].as_str(), c["change"].as_str()), (Some("update"), Some("in_place")));
	assert_eq!(c["diff"][0]["path"], "remote_port");
	let c = change(&plan, &format!("tcp/127.0.0.1:{recreate}"));
	assert_eq!(c["change"], "recreate", "source_ip cannot change in place");
	assert_eq!(change(&plan, &format!("tcp/127.0.0.1:{drop_it}"))["action"], "delete");
	assert_eq!(change(&plan, &format!("tcp/127.0.0.1:{add}"))["action"], "create");
	// the address an API rule holds: would be registered as failed
	assert_eq!(change(&plan, &format!("tcp/127.0.0.1:{api}"))["action"], "create");
	assert!(plan["warnings"].to_string().contains("holds this address"), "{plan}");
	assert!(plan["changes"].as_array().unwrap().iter().all(|c| c["rule"] != format!("tcp/127.0.0.1:{keep}")), "unchanged rules are not listed");

	// nothing changed
	let (_, view) = h.get(&format!("/rules/tcp/127.0.0.1/{change_it}")).await;
	assert_eq!(view["remote_port"], backend.port());
	assert_eq!(h.get(&format!("/rules/tcp/127.0.0.1/{drop_it}")).await.0, StatusCode::OK);

	// mistakes: 400 with every finding
	let doc = json!({"version": 1, "rules": [static_rule(keep), {"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": add, "remote_addr": "a", "remote_port": 0}]});
	let (status, body) = post(&h, format!("{base}/config/plan"), Some(doc)).await;
	assert_eq!((status, body["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{body}");
	assert!(body["errors"][0]["rule"].as_str().unwrap().contains("rule #2"), "{body}");
	let (status, _) = post(&h, format!("{base}/config/plan"), Some(json!({"version": 2}))).await;
	assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn config_reload_dry_run_reads_the_file_and_applies_nothing() {
	let h = harness().await;
	let backend = tcp_backend("R:").await;
	let dir = workdir("reload");
	let file = dir.join("rproxy.yaml");
	let (a, b) = (free_port(), free_port());
	let text = |port: u16, remote: u16| {
		format!("version: 1\nrules:\n  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {port}, remote_addr: 127.0.0.1, remote_port: {remote}}}\n")
	};
	fs::write(&file, text(a, backend.port())).unwrap();
	let doc = ConfigDoc::load(&file).unwrap();
	h.registry.load_static_labeled(doc.labeled_rules()).await.unwrap();
	let input = || CheckInput { path: file.clone(), reserved: vec![], max_range_ports: 100, warn_days: 14 };
	let reloader = Arc::new(ConfigReloader::new(doc, h.registry.clone(), input()));
	let base = admin_api(&h, Some(reloader)).await;

	fs::write(&file, text(b, backend.port())).unwrap();
	let (status, plan) = post(&h, format!("{base}/config/reload?dry_run=true"), None).await;
	assert_eq!(status, StatusCode::OK, "{plan}");
	assert_eq!((&plan["added"], &plan["removed"]), (&json!(1), &json!(1)), "{plan}");
	assert_eq!(h.get(&format!("/rules/tcp/127.0.0.1/{a}")).await.0, StatusCode::OK, "nothing applied");
	assert_eq!(h.get(&format!("/rules/tcp/127.0.0.1/{b}")).await.0, StatusCode::NOT_FOUND);

	fs::write(&file, "version: 1\nrules: [{protocol: tcp}]\n").unwrap();
	let (status, body) = post(&h, format!("{base}/config/reload?dry_run=true"), None).await;
	assert_eq!((status, body["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{body}");
	assert!(!body["errors"].as_array().unwrap().is_empty());

	// the real reload still applies
	fs::write(&file, text(b, backend.port())).unwrap();
	let (status, applied) = post(&h, format!("{base}/config/reload"), None).await;
	assert_eq!((status, &applied["added"]), (StatusCode::OK, &json!(1)), "{applied}");
	assert_eq!(h.get(&format!("/rules/tcp/127.0.0.1/{b}")).await.0, StatusCode::OK);
	fs::remove_dir_all(dir).unwrap();
}

struct Rproxy(Child);

impl Drop for Rproxy {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

/// Runs `--check-config` in `dir` without the repository's .env; (exit code, output).
fn check(dir: &Path, args: &[&str]) -> (i32, String) {
	let out = Command::new(env!("CARGO_BIN_EXE_rproxy-api")).current_dir(dir).env_clear().args(args).output().unwrap();
	let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
	(out.status.code().unwrap_or(-1), text)
}

/// `--check-config --diff` asks a running rproxy over its Unix socket.
#[test]
fn check_config_diff_asks_the_running_rproxy() {
	let dir = workdir("diff");
	let socket = dir.join("api.sock");
	let (port, other) = (free_port(), free_port());
	let running = dir.join("running.yaml");
	let rule = |port: u16, remote: u16| {
		format!("  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {port}, remote_addr: 127.0.0.1, remote_port: {remote}}}\n")
	};
	fs::write(&running, format!("version: 1\nrules:\n{}", rule(port, 9))).unwrap();
	fs::write(dir.join("tokens"), "secret-token\n").unwrap();
	fs::write(dir.join("token"), "secret-token\n").unwrap();
	let _rp = Rproxy(
		Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
			.current_dir(&dir)
			.env_clear()
			.env("RPROXY_API_PORT", "0")
			.env("RPROXY_API_SOCKET", &socket)
			.env("RPROXY_CONFIG", &running)
			.env("RPROXY_TOKEN_FILE", dir.join("tokens"))
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.spawn()
			.unwrap(),
	);
	let deadline = Instant::now() + Duration::from_secs(15);
	while std::os::unix::net::UnixStream::connect(&socket).is_err() {
		assert!(Instant::now() < deadline, "the rproxy did not start");
		std::thread::sleep(Duration::from_millis(100));
	}

	let next = dir.join("next.yaml");
	fs::write(&next, format!("version: 1\nrules:\n{}{}", rule(port, 10), rule(other, 9))).unwrap();
	let api = format!("unix:{}", socket.display());
	let token = dir.join("token");
	let args = ["--check-config", next.to_str().unwrap(), "--diff", "--diff-api", &api, "--diff-token-file", token.to_str().unwrap()];
	let (exit, out) = check(&dir, &args);
	assert_eq!(exit, 0, "{out}");
	assert!(out.contains(&format!("~ tcp/127.0.0.1:{port} (update, in_place): remote_port")), "{out}");
	assert!(out.contains(&format!("+ tcp/127.0.0.1:{other} (create, none)")), "{out}");
	assert!(out.contains("1 to add, 1 to change, 0 to remove"), "{out}");

	let mut json_args = args.to_vec();
	json_args.extend(["--check-config-format", "json"]);
	let (exit, out) = check(&dir, &json_args);
	let v: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
	assert_eq!((exit, &v["ok"], &v["plan"]["added"]), (0, &json!(true), &json!(1)), "{v}");

	// the default is RPROXY_API_SOCKET
	let (exit, out) = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.current_dir(&dir)
		.env_clear()
		.env("RPROXY_API_SOCKET", &socket)
		.env("RPROXY_DIFF_TOKEN_FILE", &token)
		.args(["--check-config", next.to_str().unwrap(), "--diff"])
		.output()
		.map(|o| (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned()))
		.unwrap();
	assert!(exit == 0 && out.contains("1 to add"), "{out}");

	// without the token: refused, so no difference (1)
	let (exit, out) = check(&dir, &["--check-config", next.to_str().unwrap(), "--diff", "--diff-api", &api]);
	assert!(exit == 1 && out.contains("could not get the difference") && out.contains("401"), "{out}");
	// nothing listening
	let gone = format!("unix:{}", dir.join("nothing.sock").display());
	let (exit, out) = check(&dir, &["--check-config", next.to_str().unwrap(), "--diff", "--diff-api", &gone]);
	assert!(exit == 1 && out.contains("could not get the difference"), "{out}");
	let (exit, out) = check(&dir, &["--check-config", next.to_str().unwrap(), "--diff", "--diff-api", "ftp://x"]);
	assert!(exit == 1 && out.contains("--diff-api"), "{out}");
	// a mistake in the file: the check fails, nothing is asked
	fs::write(&next, "version: 1\nrules: [{protocol: tcp}]\n").unwrap();
	let (exit, out) = check(&dir, &args);
	assert!(exit == 1 && !out.contains("to add"), "{out}");
	fs::remove_dir_all(dir).unwrap();
}
