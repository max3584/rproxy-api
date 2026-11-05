//! The control plane's limits (#358): names of routes and middlewares, the size of the
//! files rules name, what only `admin` tokens may ask for, the tokens' `max_rules` and
//! `max_rulesets`, and the counts of routes an `http` rule no longer has.

mod common;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

use common::*;

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-limits-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

fn sha(s: &str) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn http_rule(port: u16, http: Value) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})
}

fn answering(route: &str, middleware: &str) -> Value {
	json!({
		"routes": [{"name": route, "match": "PathPrefix(`/`)", "middlewares": [middleware]}],
		"middlewares": {middleware: {"respond": {"status": 204}}},
	})
}

async fn metrics(h: &Harness) -> String {
	h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap()
}

/// Names are labels of `GET /metrics`: a line feed or a quote cannot be in one, while
/// rproxy-gateway's names and letters of other scripts are fine.
#[tokio::test]
async fn route_and_middleware_names_are_checked() {
	let h = harness().await;
	for (route, middleware) in [("a\"} 1\nrproxy_fake 1", "m"), ("a", "m\n"), ("a b", "m"), ("a", ""), ("a", "m\\")] {
		let (status, v) = h.post(http_rule(free_port(), answering(route, middleware))).await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{route:?} {middleware:?}: {v}");
		assert_eq!(v["code"], "invalid", "{v}");
	}
	let long = "r".repeat(rproxy_api::l7::MAX_NAME + 1);
	assert_eq!(h.post(http_rule(free_port(), answering(&long, "m"))).await.0, StatusCode::BAD_REQUEST);

	let port = free_port();
	let route = "grpc:default/my-route.v1/r0/b1/f2.3";
	let (status, v) = h.post(http_rule(port, answering(route, "rproxy-gateway/500"))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(h.post(http_rule(free_port(), answering("経路@file", "認証+1"))).await.0, StatusCode::CREATED);
	let r = reqwest::get(format!("http://127.0.0.1:{port}/")).await.unwrap();
	assert_eq!(r.status(), StatusCode::NO_CONTENT);
	let mut text = String::new();
	for _ in 0..50 {
		text = metrics(&h).await;
		if text.contains(route) {
			break;
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert!(text.contains(&format!("listen=\"127.0.0.1:{port}\",route=\"{route}\",code=\"2xx\"}} 1")), "{text}");
}

/// The counts of routes and middlewares a PATCH takes away are forgotten.
#[tokio::test]
async fn counts_of_removed_routes_are_forgotten() {
	let h = harness().await;
	let port = free_port();
	let (status, v) = h.post(http_rule(port, answering("old", "m"))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(reqwest::get(format!("http://127.0.0.1:{port}/")).await.unwrap().status(), StatusCode::NO_CONTENT);
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let mut stats = Value::Null;
	for _ in 0..50 {
		stats = h.get(&path).await.1["stats"]["http"]["routes"].clone();
		if stats["old"]["requests"] == 1 {
			break;
		}
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert_eq!(stats["old"]["requests"], 1, "{stats}");
	let (status, v) = h.patch(&format!("tcp/127.0.0.1/{port}"), json!({"http": answering("new", "m")})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let stats = h.get(&path).await.1["stats"]["http"]["routes"].clone();
	assert!(stats.get("old").is_none(), "{stats}");
	assert!(!metrics(&h).await.contains("route=\"old\""));
}

/// A file a rule names is read up to a size (`users_file`: 16 MiB, others 4 MiB).
#[tokio::test]
async fn files_larger_than_the_limit_are_refused() {
	let dir = workdir("size");
	let users = dir.join("users");
	let line = format!("alice:{}\n", bcrypt::hash("wonderland", 4).unwrap());
	let big = line.repeat((rproxy_api::net::files::MAX_USERS_FILE as usize / line.len()) + 1);
	fs::write(&users, &big).unwrap();
	let h = harness().await;
	let body = |file: &PathBuf| {
		http_rule(
			free_port(),
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "middlewares": ["auth", "ok"]}],
				"middlewares": {"auth": {"basic_auth": {"users_file": file}}, "ok": {"respond": {"status": 204}}},
			}),
		)
	};
	let (status, v) = h.post(body(&users)).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("cannot be used"), "{v}");
	fs::write(&users, &line).unwrap();
	assert_eq!(h.post(body(&users)).await.0, StatusCode::CREATED);
	fs::remove_dir_all(dir).unwrap();
}

/// `listen_freebind` and large ranges need `admin`; a token's `max_rules` and
/// `max_rulesets` count its rules (its sets' too) and its sets.
#[tokio::test]
async fn tokens_are_held_to_their_limits() {
	let dir = workdir("tokens");
	let file = dir.join("tokens.yaml");
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: admin, sha256: {}, scopes: [admin]}}\n  - {{name: ctl, sha256: {}, scopes: [rules:write, rules:read], max_rules: 2, max_rulesets: 1}}\n",
			sha("admin"),
			sha("ctl")
		),
	)
	.unwrap();
	let h = harness_with(rproxy_api::control::auth::Tokens::from_file(file).unwrap()).await;
	let call = |token: &'static str, method: Method, path: String, body: Value| {
		h.http.request(method, format!("{}{path}", h.base)).bearer_auth(token).json(&body).send()
	};
	let a = tcp_backend("A:").await;

	let mut freebind = rule("tcp", free_port(), a);
	freebind["listen_freebind"] = json!(true);
	let r = call("ctl", Method::POST, "/rules".into(), freebind).await.unwrap();
	assert_eq!(r.status(), StatusCode::FORBIDDEN);
	assert!(r.text().await.unwrap().contains("admin"));
	let base = free_tcp_block(1);
	let mut range = rule("tcp", base, a);
	range["listen_port_end"] = json!(base + rproxy_api::core::quota::DEFAULT_NON_ADMIN_RANGE_PORTS as u16);
	range["remote_port"] = json!(1000);
	let r = call("ctl", Method::POST, "/rules".into(), range.clone()).await.unwrap();
	assert_eq!(r.status(), StatusCode::FORBIDDEN);
	// the same set of rules through a rule set
	let r = call("ctl", Method::PUT, "/rulesets/wide".into(), json!({"generation": 1, "rules": [range]})).await.unwrap();
	assert_eq!(r.status(), StatusCode::FORBIDDEN);

	// max_rules: 2, one of them in a set
	let r = call("ctl", Method::POST, "/rules".into(), rule("tcp", free_port(), a)).await.unwrap();
	assert_eq!(r.status(), StatusCode::CREATED);
	let set = |port: u16| json!({"generation": 1, "rules": [rule("tcp", port, a)]});
	let r = call("ctl", Method::PUT, "/rulesets/one".into(), set(free_port())).await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let r = call("ctl", Method::POST, "/rules".into(), rule("tcp", free_port(), a)).await.unwrap();
	assert_eq!(r.status(), StatusCode::CONFLICT);
	let v: Value = r.json().await.unwrap();
	assert_eq!(v["code"], "limit", "{v}");
	// a set changed in place keeps its count
	let r =
		call("ctl", Method::PUT, "/rulesets/one".into(), json!({"generation": 2, "rules": [rule("tcp", free_port(), a)]})).await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	// max_rulesets: 1
	let r = call("ctl", Method::PUT, "/rulesets/two".into(), json!({"generation": 1, "rules": []})).await.unwrap();
	assert_eq!(r.status(), StatusCode::CONFLICT);
	// admin has no limit of its own
	let r = call("admin", Method::POST, "/rules".into(), rule("tcp", free_port(), a)).await.unwrap();
	assert_eq!(r.status(), StatusCode::CREATED);
	fs::remove_dir_all(dir).unwrap();
}
