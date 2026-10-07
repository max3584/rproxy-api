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
		"limits", "bandwidth",
	] {
		assert_eq!(f[flag], false, "{flag}: {caps}");
	}
	// implemented (tests/api_hardening.rs, rulesets.rs, geoip.rs, outlier.rs, plan.rs, persist.rs; #174 and performance below)
	for flag in ["client_cert_auth", "token_expiry", "api_lockout", "rulesets", "labels", "conditions", "readyz", "geoip", "outlier_detection", "dry_run", "persistence", "handoff", "self_update"] {
		assert_eq!(f[flag], true, "{flag}: {caps}");
	}
	assert!(f["middlewares"].as_array().unwrap().contains(&json!("geoip")));
	assert!(f["services"].as_array().unwrap().contains(&json!("outlier_detection")));
}

/// #165
#[tokio::test]
async fn limits_are_checked_then_unsupported() {
	let h = harness().await;
	let good = json!({"max_connections": 100, "per_source": {"max_connections": 4, "new_connections": {"average": 10}}});
	rule_setting(&h, "tcp", "limits", good, json!({"per_source": {"packets": {"average": 5}}})).await;
	let good = json!({"per_source": {"packets": {"average": 1000, "period": "1s", "burst": 2000}}});
	rule_setting(&h, "udp", "limits", good, json!({"max_connections": 0})).await;
}

/// #166
#[tokio::test]
async fn bandwidth_is_checked_then_unsupported() {
	let h = harness().await;
	let good = json!({"upload": "10Mbps", "download": "100Mbps", "per_source": {"download": "5Mbps"}});
	rule_setting(&h, "tcp", "bandwidth", good, json!({"upload": "10MB/s"})).await;
}

// #168 GeoIP and #170 outlier detection are implemented: tests/geoip.rs and tests/outlier.rs.

// #169 (dry runs) and #144 (persistence) work: tests/plan.rs and tests/persist.rs

/// #174 (implemented): tests/handoff.rs and tests/self_update.rs run the real
/// binary; here the endpoints of a router without a server process.
#[tokio::test]
async fn upgrade_and_update_endpoints_answer() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!((&caps["features"]["handoff"], &caps["features"]["self_update"]), (&json!(true), &json!(true)), "{caps}");
	assert_eq!(caps["build"]["version"], caps["version"], "{caps}");
	// strong operations: only over the Unix socket by default
	assert_eq!(send(&h, Method::POST, "/admin/upgrade", None).await.0, StatusCode::FORBIDDEN);
	assert_eq!(send(&h, Method::POST, "/admin/update", None).await.0, StatusCode::FORBIDDEN);
	let r = send(&h, Method::GET, "/admin/update", None).await;
	assert_eq!((r.0, &r.1["mode"], &r.1["available"]), (StatusCode::OK, &json!("off"), &Value::Null), "{}", r.1);
}

/// #194, #184 (implemented): tests/performance.rs runs the real binary.
#[tokio::test]
async fn performance_keys_are_all_applied() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["performance"], json!(["workers", "udp_shards", "cpu_affinity", "busy_poll_usecs", "splice"]), "{caps}");
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
	assert_eq!(as_reader(Method::GET, "/admin/update").await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(as_reader(Method::POST, "/config/plan").await.unwrap().status(), StatusCode::FORBIDDEN);
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
  - protocol: tcp
    listen_addr: 127.0.0.1
    listen_port: 2
    limits: {max_connections: 100}
    http:
      routes: [{name: a, match: 'PathPrefix(`/`)', service: s}]
      services: {s: {servers: [{url: 'http://127.0.0.1:9'}], outlier_detection: {consecutive_5xx: 3}}}
"#,
	)
	.unwrap();
	let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap(), "--check-config-format", "json"], &[]);
	let v: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
	assert_eq!((exit, &v["ok"]), (0, &json!(true)), "warnings only: {v}");
	let warnings = v["warnings"].to_string();
	for want in ["rule #1", "rule #2"] {
		assert!(warnings.contains(want), "{want}: {warnings}");
	}
	assert!(!warnings.contains("global.performance"), "applied now: {warnings}");

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

/// #167, #174, performance flags: mistakes stop the startup.
#[test]
fn v0_4_flags_are_checked_at_startup() {
	let dir = workdir("flags");
	for (env, want) in [
		(vec![("RPROXY_TLS_CLIENT_AUTH", "required"), ("RPROXY_TLS_CLIENT_CA", "/ca.pem")], "needs --tls-cert"),
		(vec![("RPROXY_TLS_CLIENT_AUTH", "optional")], "needs --tls-client-ca"),
		(vec![("RPROXY_TOKEN_WARN_DAYS", "0")], "--token-warn-days"),
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
