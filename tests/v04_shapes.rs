//! v0.4 settings (docs/DESIGN-v0.4.md): the shapes are validated, and what
//! this build cannot run yet is refused with `unsupported` (API), registered as
//! failed or warned about (settings file), or ignored with `degraded` (global
//! settings and flags). One test per item: an item's implementation replaces
//! its test with one that shows it working (and turns its `features` flag on).

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

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

fn code(r: &(StatusCode, Value)) -> (StatusCode, Option<&str>) {
	(r.0, r.1["code"].as_str())
}

const UNSUPPORTED: (StatusCode, Option<&str>) = (StatusCode::BAD_REQUEST, Some("unsupported"));
const INVALID: (StatusCode, Option<&str>) = (StatusCode::BAD_REQUEST, Some("invalid"));

/// POST with `key: good` is `unsupported`, with `key: bad` is `invalid`; a
/// running rule PATCHed with `key: good` is `unsupported`, with `{}` is fine.
async fn rule_setting(h: &Harness, protocol: &str, key: &str, good: Value, bad: Value) {
	let backend = if protocol == "udp" { udp_backend("V:").await } else { tcp_backend("V:").await };
	let port = if protocol == "udp" { free_udp_port() } else { free_port() };
	let mut body = rule(protocol, port, backend);
	body[key] = good.clone();
	let r = h.post(body.clone()).await;
	assert_eq!(code(&r), UNSUPPORTED, "{key}: {}", r.1);
	assert!(r.1["error"].as_str().unwrap().contains(key), "{}", r.1);
	body[key] = bad;
	let r = h.post(body.clone()).await;
	assert_eq!(code(&r), INVALID, "{key}: {}", r.1);

	let plain = rule(protocol, port, backend);
	assert_eq!(h.post(plain).await.0, StatusCode::CREATED);
	let path = format!("{protocol}/127.0.0.1/{port}");
	let target = json!({"remote_addr": backend.ip().to_string(), "remote_port": backend.port()});
	let mut patch = target.clone();
	patch[key] = good;
	assert_eq!(code(&h.patch(&path, patch).await), UNSUPPORTED, "PATCH {key}");
	let mut clear = target;
	clear[key] = json!({});
	let r = h.patch(&path, clear).await;
	assert_eq!(r.0, StatusCode::OK, "PATCH {key}: {{}} removes it: {}", r.1);
	assert!(r.1.get(key).is_none(), "{}", r.1);
}

#[tokio::test]
async fn capabilities_list_the_v0_4_features_as_off() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	let f = &caps["features"];
	for flag in [
		"rulesets", "labels", "conditions", "readyz", "geoip", "outlier_detection", "dry_run",
		"persistence", "client_cert_auth", "token_expiry", "api_lockout", "handoff", "self_update",
	] {
		assert_eq!(f[flag], false, "{flag}: {caps}");
	}
	assert_eq!(f["performance"], json!([]), "{caps}");
	assert!(!f["middlewares"].as_array().unwrap().contains(&json!("geoip")));
	assert!(!f["services"].as_array().unwrap().contains(&json!("outlier_detection")));
}

/// #28 labels
#[tokio::test]
async fn labels_are_checked_then_unsupported() {
	let h = harness().await;
	rule_setting(&h, "tcp", "labels", json!({"tenant": "act"}), json!({"bad key": "x"})).await;
}

/// #168, L4 and the middleware
#[tokio::test]
async fn geoip_is_checked_then_unsupported() {
	let h = harness().await;
	rule_setting(&h, "udp", "geoip", json!({"allow_countries": ["JP"]}), json!({"allow_countries": ["japan"]})).await;

	let mut body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
		"routes": [{"name": "a", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:9", "middlewares": ["geo"]}],
		"middlewares": {"geo": {"geoip": {"deny_asns": [64496]}}}
	}});
	let r = h.post(body.clone()).await;
	assert_eq!(code(&r), UNSUPPORTED, "{}", r.1);
	assert!(r.1["error"].as_str().unwrap().contains("geoip"), "{}", r.1);
	body["http"]["middlewares"]["geo"] = json!({"geoip": {"deny_asns": [0]}});
	assert_eq!(code(&h.post(body).await), INVALID);
}

/// #170, L4 and services
#[tokio::test]
async fn outlier_detection_is_checked_then_unsupported() {
	let h = harness().await;
	let good = json!({"consecutive_failures": 3, "ejection_time": "10s", "max_ejection_time": "5m", "max_ejected_percent": 50});
	rule_setting(&h, "tcp", "outlier_detection", good, json!({"ejection_time": "1m", "max_ejection_time": "10s"})).await;

	let mut body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
		"routes": [{"name": "a", "match": "PathPrefix(`/`)", "service": "s"}],
		"services": {"s": {"servers": [{"url": "http://127.0.0.1:9"}], "outlier_detection": {"consecutive_5xx": 5}}}
	}});
	let r = h.post(body.clone()).await;
	assert_eq!(code(&r), UNSUPPORTED, "{}", r.1);
	assert!(r.1["error"].as_str().unwrap().contains("outlier_detection"), "{}", r.1);
	body["http"]["services"]["s"]["outlier_detection"] = json!({"failure_percent": 0});
	assert_eq!(code(&h.post(body.clone()).await), INVALID);
	// a rule's outlier_detection is for L4 only
	body["http"]["services"]["s"]["outlier_detection"] = Value::Null;
	body["outlier_detection"] = json!({"consecutive_failures": 2});
	let r = h.post(body).await;
	assert_eq!(code(&r), INVALID, "{}", r.1);
}

/// #28 rule sets and readiness
#[tokio::test]
async fn rulesets_and_readyz_are_checked_then_unsupported() {
	let h = harness().await;
	let backend = tcp_backend("R:").await;
	let set = json!({"generation": 1, "rules": [rule("tcp", free_port(), backend)]});
	let r = send(&h, Method::PUT, "/rulesets/k8s/default/web", Some(set.clone())).await;
	assert_eq!(code(&r), UNSUPPORTED, "{}", r.1);
	let r = send(&h, Method::PUT, "/rulesets/Bad%20Name", Some(set.clone())).await;
	assert_eq!(code(&r), INVALID, "{}", r.1);
	let r = send(&h, Method::PUT, "/rulesets/k8s/web", Some(json!({"rules": []}))).await;
	assert_eq!(code(&r), INVALID, "generation is required: {}", r.1);
	let mut twice = set.clone();
	twice["rules"] = json!([set["rules"][0], set["rules"][0]]);
	assert_eq!(code(&send(&h, Method::PUT, "/rulesets/k8s/web", Some(twice)).await), INVALID);
	let mut wrong = set.clone();
	wrong["rules"][0]["remote_port"] = json!(0);
	let r = send(&h, Method::PUT, "/rulesets/k8s/web", Some(wrong)).await;
	assert_eq!(code(&r), INVALID);
	assert!(r.1["error"].as_str().unwrap().starts_with("rules[0]"), "{}", r.1);
	assert_eq!(code(&send(&h, Method::PUT, "/rulesets/k8s/web?dry_run=maybe", Some(set)).await), INVALID);
	assert_eq!(code(&send(&h, Method::GET, "/rulesets", None).await), UNSUPPORTED);
	assert_eq!(code(&send(&h, Method::GET, "/rulesets/k8s/web", None).await), UNSUPPORTED);
	assert_eq!(code(&send(&h, Method::DELETE, "/rulesets/k8s/web", None).await), UNSUPPORTED);
	// no token needed, like /healthz
	assert_eq!(code(&send(&h, Method::GET, "/readyz", None).await), UNSUPPORTED);
}

/// #169
#[tokio::test]
async fn dry_run_is_checked_then_unsupported() {
	let h = harness().await;
	let backend = tcp_backend("D:").await;
	let port = free_port();
	let r = send(&h, Method::POST, "/rules?dry_run=true", Some(rule("tcp", port, backend))).await;
	assert_eq!(code(&r), UNSUPPORTED, "{}", r.1);
	assert!(r.1["error"].as_str().unwrap().contains("dry_run"), "{}", r.1);
	let mut bad = rule("tcp", port, backend);
	bad["remote_port"] = json!(0);
	assert_eq!(code(&send(&h, Method::POST, "/rules?dry_run=true", Some(bad)).await), INVALID);
	assert_eq!(code(&send(&h, Method::POST, "/rules?dry_run=perhaps", Some(rule("tcp", port, backend))).await), INVALID);
	let (_, rules) = h.get("/rules").await;
	assert_eq!(rules, json!([]), "a dry run creates nothing");

	assert_eq!(h.post(rule("tcp", port, backend)).await.0, StatusCode::CREATED);
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let patch = json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()});
	assert_eq!(code(&send(&h, Method::PATCH, &format!("{path}?dry_run=1"), Some(patch)).await), UNSUPPORTED);
	assert_eq!(code(&send(&h, Method::DELETE, &format!("{path}?dry_run=true"), None).await), UNSUPPORTED);
	assert_eq!(h.get(&path).await.0, StatusCode::OK, "still there");
	// POST /config/plan and POST /config/reload are only over the Unix socket by default
	let r = send(&h, Method::POST, "/config/plan", Some(json!({"version": 1, "rules": []}))).await;
	assert_eq!(r.0, StatusCode::FORBIDDEN, "{}", r.1);
}

/// #169: `POST /config/plan` checks the document like a settings file.
#[tokio::test]
async fn config_plan_checks_the_document_then_unsupported() {
	use rproxy_api::control::api::{router, AppState};
	let h = harness().await;
	let app = router(std::sync::Arc::new(AppState {
		registry: h.registry.clone(),
		tokens: std::sync::Arc::new(rproxy_api::control::auth::Tokens::disabled()),
		reloader: None,
		reload_unix_only: false,
	}));
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
	let base = format!("http://{}", listener.local_addr().unwrap());
	tokio::spawn(async move {
		axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap()
	});
	let post = |body: Value| {
		let (client, base) = (h.http.clone(), base.clone());
		async move {
			let r = client.post(format!("{base}/config/plan")).json(&body).send().await.unwrap();
			let status = r.status();
			(status, r.json::<Value>().await.unwrap_or(Value::Null))
		}
	};
	let r = post(json!({"version": 1, "global": {"performance": {"workers": 2}}, "rules": []})).await;
	assert_eq!(code(&r), UNSUPPORTED, "{}", r.1);
	let r = post(json!({"version": 1, "global": {"performance": {"workers": 0}}})).await;
	assert_eq!(code(&r), INVALID, "{}", r.1);
	let r = post(json!({"version": 1, "rules": [{"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 1,
		"remote_addr": "a", "remote_port": 1, "geoip": {"allow_countries": ["JP"]}}]}))
	.await;
	assert_eq!(code(&r), INVALID, "country lists need global.geoip: {}", r.1);
}

/// #174
#[tokio::test]
async fn upgrade_and_update_endpoints_are_unsupported() {
	let h = harness().await;
	// strong operations: only over the Unix socket by default
	assert_eq!(send(&h, Method::POST, "/admin/upgrade", None).await.0, StatusCode::FORBIDDEN);
	assert_eq!(send(&h, Method::POST, "/admin/update", None).await.0, StatusCode::FORBIDDEN);
	assert_eq!(code(&send(&h, Method::GET, "/admin/update", None).await), UNSUPPORTED);
}

/// Scopes of the new endpoints.
#[tokio::test]
async fn new_endpoints_need_their_scopes() {
	let dir = std::env::temp_dir().join(format!("rproxy-v04-scopes-{}", std::process::id()));
	fs::create_dir_all(&dir).unwrap();
	let file = dir.join("tokens.yaml");
	let sha = |s: &str| {
		use sha2::Digest;
		sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>()
	};
	fs::write(&file, format!("tokens:\n  - {{name: reader, sha256: {}, scopes: [rules:read]}}\n", sha("reader"))).unwrap();
	let h = harness_with(rproxy_api::control::auth::Tokens::from_file(file).unwrap()).await;
	let as_reader = |method: Method, path: &str| {
		h.http.request(method, format!("{}{path}", h.base)).bearer_auth("reader").json(&json!({"generation": 1, "rules": []})).send()
	};
	assert_eq!(as_reader(Method::GET, "/rulesets").await.unwrap().status(), StatusCode::BAD_REQUEST, "rules:read may list");
	assert_eq!(as_reader(Method::PUT, "/rulesets/a").await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(as_reader(Method::GET, "/admin/update").await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(as_reader(Method::POST, "/config/plan").await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(h.http.get(format!("{}/readyz", h.base)).send().await.unwrap().status(), StatusCode::BAD_REQUEST, "no token");
	fs::remove_dir_all(dir).unwrap();
}

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-v04-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

/// Runs the binary in `dir` without the repository's .env; (exit code, output).
fn run(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
	let out = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.current_dir(dir)
		.env_clear()
		.envs(env.iter().copied())
		.args(args)
		.output()
		.unwrap();
	let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
	(out.status.code().unwrap_or(-1), text)
}

/// The settings file: v0.4 shapes are checked by `--check-config`; rules using
/// them would be registered as failed and global settings ignored (warnings).
#[test]
fn check_config_validates_the_v0_4_shapes() {
	let dir = workdir("check");
	let file = dir.join("rproxy.yaml");
	fs::write(
		&file,
		r#"version: 1
global:
  geoip: {country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb}
  performance: {workers: 2, udp_shards: auto, splice: {enabled: false}}
rules:
  - protocol: udp
    listen_addr: 127.0.0.1
    listen_port: 1
    remote_addr: 127.0.0.1
    remote_port: 9
    labels: {tenant: act}
    limits: {per_source: {packets: {average: 100}}}
    bandwidth: {download: 10Mbps}
    geoip: {allow_countries: [JP]}
  - protocol: tcp
    listen_addr: 127.0.0.1
    listen_port: 2
    http:
      routes: [{name: a, match: 'PathPrefix(`/`)', service: s, middlewares: [geo]}]
      services: {s: {servers: [{url: 'http://127.0.0.1:9'}], outlier_detection: {consecutive_5xx: 3}}}
      middlewares: {geo: {geoip: {deny_countries: [ZZ]}}}
"#,
	)
	.unwrap();
	let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap(), "--check-config-format", "json"], &[]);
	let v: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
	assert_eq!((exit, &v["ok"]), (0, &json!(true)), "warnings only: {v}");
	let warnings = v["warnings"].to_string();
	for want in ["global.geoip", "global.performance.workers", "global.performance.udp_shards", "global.performance.splice", "rule #1", "rule #2"] {
		assert!(warnings.contains(want), "{want}: {warnings}");
	}

	// mistakes in the shapes are errors
	for (text, want) in [
		("version: 1\nglobal: {performance: {busy_poll_usecs: 5000}}\n", "busy_poll_usecs"),
		("version: 1\nglobal: {geoip: {}}\n", "country_db or asn_db"),
		("version: 1\nglobal: {performance: {threads: 2}}\n", "unknown field"),
		(
			"version: 1\nrules: [{protocol: tcp, listen_addr: 127.0.0.1, listen_port: 1, remote_addr: a, remote_port: 1, geoip: {deny_asns: [64496]}}]\n",
			"asn_db",
		),
		(
			"version: 1\nrules: [{protocol: tcp, listen_addr: 127.0.0.1, listen_port: 1, remote_addr: a, remote_port: 1, limits: {max_connections: 0}}]\n",
			"max_connections",
		),
	] {
		fs::write(&file, text).unwrap();
		let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap()], &[]);
		assert!(exit == 1 && out.contains(want), "{text}: {out}");
	}

	// --diff (#169) is not available yet
	fs::write(&file, "version: 1\n").unwrap();
	let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap(), "--diff"], &[]);
	assert!(exit == 1 && out.contains("--diff is not available"), "{out}");
	let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap(), "--diff", "--diff-api", "ftp://x"], &[]);
	assert!(exit == 1 && out.contains("--diff-api"), "{out}");
	fs::remove_dir_all(dir).unwrap();
}

/// A 0.3 settings file still passes as before.
#[test]
fn a_0_3_settings_file_still_passes() {
	let dir = workdir("v03");
	let file = dir.join("rproxy.yaml");
	fs::write(
		&file,
		"version: 1\nglobal: {trusted_proxies: [10.0.0.0/8]}\nrules:\n  - {protocol: tcp, listen_addr: 127.0.0.1, listen_port: 1, remote_addr: 127.0.0.1, remote_port: 9, allow_from: [10.0.0.0/8], crowdsec: false}\n",
	)
	.unwrap();
	let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap(), "--check-config-format", "json"], &[]);
	let v: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
	assert_eq!((exit, &v["errors"], &v["warnings"]), (0, &json!([]), &json!([])), "{v}");
	fs::remove_dir_all(dir).unwrap();
}

/// #167, #174, #144, performance flags: mistakes stop the startup, client
/// certificates (which would weaken the control API if ignored) too.
#[test]
fn v0_4_flags_are_checked_at_startup() {
	let dir = workdir("flags");
	for (env, want) in [
		(vec![("RPROXY_TLS_CLIENT_AUTH", "required"), ("RPROXY_TLS_CLIENT_CA", "/ca.pem")], "not available"),
		(vec![("RPROXY_TLS_CLIENT_AUTH", "sometimes")], "sometimes"),
		(vec![("RPROXY_API_LOCKOUT_WINDOW", "soon")], "--api-lockout-window"),
		(vec![("RPROXY_UPDATE_PIN", "99.0.0")], "RPROXY_UPDATE_PIN"),
		(vec![("RPROXY_UPDATE_SOURCE", "http://mirror")], "https://"),
		(vec![("RPROXY_HANDOFF_TIMEOUT", "1h")], "--handoff-timeout"),
		(vec![("RPROXY_WORKERS", "0")], "--workers"),
		(vec![("RPROXY_CPU_AFFINITY", "3-1")], "--cpu-affinity"),
	] {
		let mut env = env;
		env.push(("RPROXY_API_PORT", "0"));
		env.push(("RPROXY_API_SOCKET", "/nonexistent/api.sock"));
		let (exit, out) = run(&dir, &[], &env);
		assert!(exit != 0 && out.contains(want), "{env:?}: {out}");
	}
	fs::remove_dir_all(dir).unwrap();
}
