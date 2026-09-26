//! The `crowdsec` middleware against a fake LAPI and AppSec (src/http/crowdsec.rs).

mod common;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode as AxStatus};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use common::*;
use rproxy_api::auth::Tokens;
use rproxy_api::config::CrowdsecGlobal;
use rproxy_api::http::access::HttpGlobal;
use rproxy_api::http::crowdsec::Bouncer;

#[derive(Default)]
struct Lapi {
	key: String,
	/// Answer to `startup=true`.
	all: Vec<Value>,
	/// Answers to the following pulls, in order; then nothing new.
	deltas: VecDeque<Value>,
	pulls: usize,
}

type Shared = Arc<Mutex<Lapi>>;
/// What AppSec received: headers and body of each request.
type Seen = Arc<Mutex<Vec<(HeaderMap, String)>>>;

async fn serve(app: axum::Router) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

async fn fake_lapi(state: Shared) -> SocketAddr {
	let app = axum::Router::new()
		.route(
			"/v1/decisions/stream",
			axum::routing::get(
				|State(s): State<Shared>, Query(q): Query<std::collections::HashMap<String, String>>, headers: HeaderMap| async move {
					let mut s = s.lock().unwrap();
					if headers.get("x-api-key").and_then(|v| v.to_str().ok()) != Some(s.key.as_str()) {
						return (AxStatus::FORBIDDEN, axum::Json(json!({"message": "access forbidden"})));
					}
					s.pulls += 1;
					let body = if q.get("startup").map(String::as_str) == Some("true") {
						json!({"new": s.all.clone(), "deleted": null})
					} else {
						s.deltas.pop_front().unwrap_or(json!({"new": null, "deleted": null}))
					};
					(AxStatus::OK, axum::Json(body))
				},
			),
		)
		.with_state(state);
	serve(app).await
}

/// AppSec: refuses `/attack` and bodies containing `evil`; records what it saw.
async fn fake_appsec(seen: Seen) -> SocketAddr {
	let app = axum::Router::new()
		.fallback(|State(seen): State<Seen>, headers: HeaderMap, body: String| async move {
			let uri = headers.get("x-crowdsec-appsec-uri").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
			let key_ok = headers.get("x-crowdsec-appsec-api-key").and_then(|v| v.to_str().ok()) == Some("appsec-key");
			seen.lock().unwrap().push((headers, body.clone()));
			if !key_ok {
				return AxStatus::UNAUTHORIZED;
			}
			if uri.starts_with("/attack") || body.contains("evil") {
				AxStatus::FORBIDDEN
			} else {
				AxStatus::OK
			}
		})
		.with_state(seen);
	serve(app).await
}

/// A backend answering with the body it received.
async fn body_backend() -> SocketAddr {
	let app = axum::Router::new().fallback(|body: String| async move { format!("got:{body}") });
	serve(app).await
}

fn key_file(tag: &str, key: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-cs-it-{tag}-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let file = dir.join("key");
	std::fs::write(&file, key).unwrap();
	file
}

fn bouncer(lapi: &str, key: &Path, appsec: Option<String>) -> Arc<Bouncer> {
	let b = Bouncer::new(&CrowdsecGlobal {
		lapi_url: lapi.to_string(),
		api_key_file: key.to_str().unwrap().to_string(),
		appsec_url: appsec,
		update_interval: Some("1s".into()),
	})
	.unwrap();
	b.spawn();
	b
}

/// The test client connects from 127.0.0.1, which is a trusted proxy here, so
/// `X-Forwarded-For` names the client.
async fn harness_for(b: &Arc<Bouncer>) -> Harness {
	let global = HttpGlobal::without_file(&["127.0.0.0/8".to_string()]).with_crowdsec(Some(b.clone()));
	harness_with_global(Tokens::disabled(), global).await
}

fn http_rule(port: u16, http: Value) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})
}

async fn send(port: u16, method: reqwest::Method, path: &str, client: &str, body: &str) -> (StatusCode, String) {
	let r = reqwest::Client::new()
		.request(method, format!("http://127.0.0.1:{port}{path}"))
		.header("X-Forwarded-For", client)
		.header("User-Agent", "cs-test")
		.body(body.to_string())
		.timeout(Duration::from_secs(10))
		.send()
		.await
		.unwrap();
	let status = r.status();
	(status, r.text().await.unwrap())
}

async fn get(port: u16, client: &str) -> StatusCode {
	send(port, reqwest::Method::GET, "/", client, "").await.0
}

async fn eventually<F, Fut>(what: &str, mut check: F)
where
	F: FnMut() -> Fut,
	Fut: std::future::Future<Output = bool>,
{
	let deadline = Instant::now() + Duration::from_secs(15);
	while !check().await {
		assert!(Instant::now() < deadline, "timed out waiting for {what}");
		tokio::time::sleep(Duration::from_millis(100)).await;
	}
}

fn decision(id: i64, scope: &str, value: &str, kind: &str) -> Value {
	json!({"id": id, "scope": scope, "value": value, "type": kind, "duration": "4h", "origin": "crowdsec", "scenario": "test"})
}

#[tokio::test]
async fn lapi_decisions_block_and_expire() {
	let lapi = Shared::default();
	{
		let mut l = lapi.lock().unwrap();
		l.key = "lapi-key".into();
		l.all = vec![
			decision(1, "Ip", "192.0.2.1", "ban"),
			decision(2, "Range", "198.51.100.0/24", "ban"),
			decision(3, "Ip", "2001:db8::7", "captcha"),
		];
	}
	let lapi_addr = fake_lapi(lapi.clone()).await;
	let key = key_file("expire", "lapi-key\n");
	let b = bouncer(&format!("http://{lapi_addr}"), &key, None);
	let h = harness_for(&b).await;
	let backend = body_backend().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["cs"]}],
				"middlewares": {"cs": {"crowdsec": {}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	eventually("the first pull", || async { b.synced() }).await;

	assert_eq!(get(port, "192.0.2.1").await, StatusCode::FORBIDDEN);
	assert_eq!(get(port, "198.51.100.77").await, StatusCode::FORBIDDEN, "range");
	assert_eq!(get(port, "2001:db8::7").await, StatusCode::FORBIDDEN, "IPv6, captcha as ban");
	assert_eq!(get(port, "192.0.2.2").await, StatusCode::OK);
	assert_eq!(b.decision_count(), 3);

	// the ban expires: the next pull deletes it; a new one arrives
	lapi.lock().unwrap().deltas.push_back(json!({
		"new": [decision(4, "Ip", "192.0.2.2", "ban")],
		"deleted": [decision(1, "Ip", "192.0.2.1", "ban")],
	}));
	eventually("the delta", || async { get(port, "192.0.2.1").await == StatusCode::OK }).await;
	assert_eq!(get(port, "192.0.2.2").await, StatusCode::FORBIDDEN);

	let (_, rule) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert!(rule["stats"]["http"]["blocked"].as_u64().unwrap() >= 4, "{rule}");
	assert!(rule["stats"]["http"]["routes"]["all"]["blocked"]["cs"].as_u64().unwrap() >= 4, "{rule}");
	let metrics = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	assert!(metrics.contains("rproxy_http_blocked_total{protocol=\"tcp\""), "{metrics}");
	assert!(metrics.contains("rproxy_crowdsec_decisions 3"), "{metrics}");
	assert!(metrics.contains("rproxy_crowdsec_synced 1"), "{metrics}");
	b.stop();
}

#[tokio::test]
async fn on_error_decides_until_the_lapi_answers() {
	// nothing listens on the LAPI's port
	let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
	let key = key_file("onerror", "k");
	let b = bouncer(&format!("http://{closed}"), &key, None);
	let h = harness_for(&b).await;
	let backend = body_backend().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [
					{"name": "open", "match": "Path(`/open`)", "to": format!("http://{backend}"), "middlewares": ["lenient"]},
					{"name": "closed", "match": "Path(`/closed`)", "to": format!("http://{backend}"), "middlewares": ["strict"]},
				],
				"middlewares": {
					"lenient": {"crowdsec": {"on_error": "allow"}},
					"strict": {"crowdsec": {"on_error": "block"}},
				},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(send(port, reqwest::Method::GET, "/open", "192.0.2.1", "").await.0, StatusCode::OK);
	assert_eq!(send(port, reqwest::Method::GET, "/closed", "192.0.2.1", "").await.0, StatusCode::FORBIDDEN);
	assert!(!b.synced());
	b.stop();
}

#[tokio::test]
async fn appsec_checks_requests() {
	let lapi = Shared::default();
	lapi.lock().unwrap().key = "appsec-key".into();
	let lapi_addr = fake_lapi(lapi.clone()).await;
	let seen = Seen::default();
	let appsec = fake_appsec(seen.clone()).await;
	let key = key_file("appsec", "appsec-key");
	let b = bouncer(&format!("http://{lapi_addr}"), &key, Some(format!("http://{appsec}")));
	let h = harness_for(&b).await;
	let backend = body_backend().await;
	let port = free_port();
	let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["waf"]}],
				"middlewares": {"waf": {"crowdsec": {"appsec": true, "on_error": "block"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	eventually("the first pull", || async { b.synced() }).await;

	let (status, body) = send(port, reqwest::Method::POST, "/form?x=1", "192.0.2.5", "hello").await;
	assert_eq!((status, body.as_str()), (StatusCode::OK, "got:hello"), "the body still reaches the backend");
	assert_eq!(send(port, reqwest::Method::GET, "/attack?id=1", "192.0.2.5", "").await.0, StatusCode::FORBIDDEN);
	assert_eq!(send(port, reqwest::Method::POST, "/form", "192.0.2.5", "some evil payload").await.0, StatusCode::FORBIDDEN);
	{
		let seen = seen.lock().unwrap();
		let (headers, body) = &seen[0];
		let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		assert_eq!(h("x-crowdsec-appsec-ip"), "192.0.2.5");
		assert_eq!(h("x-crowdsec-appsec-uri"), "/form?x=1");
		assert_eq!(h("x-crowdsec-appsec-verb"), "POST");
		assert_eq!(h("x-crowdsec-appsec-host"), "127.0.0.1");
		assert_eq!(h("x-crowdsec-appsec-user-agent"), "cs-test");
		assert_eq!(body, "hello");
	}

	// a rule whose AppSec cannot be reached: on_error block
	let b2 = bouncer(&format!("http://{lapi_addr}"), &key, Some(format!("http://{closed}")));
	let h2 = harness_for(&b2).await;
	let port2 = free_port();
	let (status, v) = h2
		.post(http_rule(
			port2,
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["waf"]}],
				"middlewares": {"waf": {"crowdsec": {"appsec": true, "on_error": "block"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	eventually("the first pull", || async { b2.synced() }).await;
	assert_eq!(get(port2, "192.0.2.5").await, StatusCode::FORBIDDEN);
	b.stop();
	b2.stop();
}

#[tokio::test]
async fn the_key_file_is_read_again() {
	let lapi = Shared::default();
	{
		let mut l = lapi.lock().unwrap();
		l.key = "new-key".into();
		l.all = vec![decision(1, "Ip", "192.0.2.9", "ban")];
	}
	let lapi_addr = fake_lapi(lapi.clone()).await;
	let key = key_file("reload", "old-key");
	let b = bouncer(&format!("http://{lapi_addr}"), &key, None);
	tokio::time::sleep(Duration::from_millis(300)).await;
	assert!(!b.synced(), "the LAPI refuses the old key");
	std::fs::write(&key, "new-key\n").unwrap();
	b.reload_key().unwrap();
	eventually("a pull with the new key", || async { b.synced() }).await;
	assert_eq!(b.decision_count(), 1);
	b.stop();
}

#[tokio::test]
async fn crowdsec_needs_its_global_settings() {
	let h = harness().await;
	let (status, v) = h
		.post(http_rule(
			free_port(),
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:9", "middlewares": ["cs"]}],
				"middlewares": {"cs": {"crowdsec": {}}},
			}),
		))
		.await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("global.crowdsec"), "{v}");

	let key = key_file("needs", "k");
	let b = bouncer("http://127.0.0.1:9", &key, None);
	let h = harness_for(&b).await;
	let (status, v) = h
		.post(http_rule(
			free_port(),
			json!({
				"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:9", "middlewares": ["cs"]}],
				"middlewares": {"cs": {"crowdsec": {"appsec": true}}},
			}),
		))
		.await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("appsec_url"), "{v}");
	b.stop();
}
