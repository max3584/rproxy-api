//! Overlays on static rules (#397, docs/DESIGN-v0.4.x.md 26.): routes, services and
//! middlewares of `http` and `tls.routes` added through the API on a static rule's listener.
//! The file's routes are tried first, names the file has are the file's, and an overlay the
//! file's rule cannot take any more is kept and reported `not_applied`.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::pki::{Issued, Pki};
use common::*;
use rproxy_api::config::persist::Store;
use rproxy_api::control::auth::Tokens;
use rproxy_api::core::rule::RuleRequest;

/// Says its name.
async fn backend(name: &'static str) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let app = axum::Router::new().fallback(move || async move { name });
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

fn requests(v: Value) -> Vec<(String, RuleRequest)> {
	v.as_array().unwrap().iter().enumerate().map(|(i, r)| (format!("rule #{i}"), serde_json::from_value(r.clone()).unwrap())).collect()
}

/// The file's http rule: `/app` behind an `ip_allow` loopback does not pass (the file's
/// "authentication"), anything else 404 (no default).
fn file_rule(port: u16, a: SocketAddr) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "app", "match": "PathPrefix(`/app`)", "service": "a", "middlewares": ["only-lan"]}],
		"services": {"a": {"servers": [{"url": format!("http://{a}")}]}},
		"middlewares": {"only-lan": {"ip_allow": {"source_range": ["10.0.0.0/8"]}}}
	}})
}

fn overlay(b: SocketAddr) -> Value {
	json!({"http": {
		"routes": [
			{"name": "extra", "match": "PathPrefix(`/`)", "priority": 100000, "service": "b"},
			{"name": "reuse", "match": "PathPrefix(`/reuse`)", "priority": 200000, "service": "a"}
		],
		"services": {"b": {"servers": [{"url": format!("http://{b}")}]}}
	}})
}

async fn call(
	h: &Harness,
	method: Method,
	path: &str,
	body: Option<Value>,
	headers: &[(&str, &str)],
) -> (StatusCode, Value, Option<String>) {
	let mut r = h.http.request(method, format!("{}{path}", h.base));
	for (k, v) in headers {
		r = r.header(*k, *v);
	}
	if let Some(b) = body {
		r = r.json(&b);
	}
	let r = r.send().await.unwrap();
	let status = r.status();
	let etag = r.headers().get("etag").and_then(|v| v.to_str().ok()).map(str::to_string);
	(status, r.json().await.unwrap_or(Value::Null), etag)
}

/// Status and body of `GET http://127.0.0.1:{port}{path}`.
async fn fetch(port: u16, path: &str) -> (u16, String) {
	let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
	let r = client.get(format!("http://127.0.0.1:{port}{path}")).send().await.unwrap();
	(r.status().as_u16(), r.text().await.unwrap_or_default())
}

fn path(port: u16) -> String {
	format!("/rules/tcp/127.0.0.1/{port}/overlay")
}

#[tokio::test]
async fn overlay_routes_come_after_the_files_and_cannot_skip_its_authentication() {
	let h = harness().await;
	let (a, b) = (backend("A").await, backend("B").await);
	let port = free_port();
	h.registry.load_static_labeled(requests(json!([file_rule(port, a)]))).await.unwrap();
	assert_eq!(fetch(port, "/x").await.0, 404);

	let (status, v, etag) = call(&h, Method::PUT, &path(port), Some(overlay(b)), &[]).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!((v["state"].as_str(), v["created_by"].as_str()), (Some("applied"), Some("")), "{v}");
	assert_eq!(etag.as_deref(), v["etag"].as_str());
	// the file's route first, whatever the overlay's priority: its ip_allow still refuses
	assert_eq!(fetch(port, "/app/secret").await.0, 403);
	assert_eq!(fetch(port, "/x").await, (200, "B".into()));
	assert_eq!(fetch(port, "/reuse").await, (200, "A".into()), "an overlay route may use the file's service");

	// the rule's view stays the file's, with a summary of the overlay
	let (_, rule) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!(rule["origin"], "static");
	assert_eq!(rule["http"]["routes"].as_array().unwrap().len(), 1, "{rule}");
	assert_eq!(rule["overlay"], json!({"state": "applied", "routes": 2, "tls_routes": 0}), "{rule}");
	assert!(rule["stats"]["http"]["routes"]["extra"]["requests"].as_u64().unwrap() >= 1, "{rule}");
	let (_, metrics) = (StatusCode::OK, h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap());
	assert!(
		metrics.contains(&format!("rproxy_rule_overlay{{protocol=\"tcp\",listen=\"127.0.0.1:{port}\",state=\"applied\"}} 1")),
		"{metrics}"
	);

	// names the file has are refused
	let mut clash = overlay(b);
	clash["http"]["routes"][0]["name"] = json!("app");
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(clash), &[]).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("overlay_conflict")), "{v}");
	let mut clash = overlay(b);
	clash["http"]["services"] =
		json!({"a": {"servers": [{"url": format!("http://{b}")}]}, "b": {"servers": [{"url": format!("http://{b}")}]}});
	assert_eq!(call(&h, Method::PUT, &path(port), Some(clash), &[]).await.0, StatusCode::CONFLICT);
	// the file's part cannot be set through it
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(json!({"http": {"default": {"status": 200}}})), &[]).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	// a merge that does not validate changes nothing
	let (status, v, _) = call(
		&h,
		Method::PUT,
		&path(port),
		Some(json!({"http": {"routes": [{"name": "y", "match": "Path(`/y`)", "service": "nope"}]}})),
		&[],
	)
	.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert_eq!(fetch(port, "/x").await, (200, "B".into()));

	// If-Match and dry runs
	let mut changed = overlay(b);
	changed["http"]["routes"][0]["match"] = json!("PathPrefix(`/z`)");
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(changed.clone()), &[("If-Match", "\"o-0000\"")]).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::PRECONDITION_FAILED, Some("precondition_failed")), "{v}");
	let (status, v, _) = call(&h, Method::PUT, &format!("{}?dry_run=true", path(port)), Some(changed.clone()), &[]).await;
	assert_eq!((status, v["action"].as_str()), (StatusCode::OK, Some("update")), "{v}");
	assert!(!v["diff"].as_array().unwrap().is_empty(), "{v}");
	assert_eq!(fetch(port, "/x").await, (200, "B".into()), "a dry run changes nothing");
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(changed), &[("If-Match", etag.as_deref().unwrap())]).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(fetch(port, "/x").await.0, 404);
	assert_eq!(fetch(port, "/z").await, (200, "B".into()));

	let (status, v, _) = call(&h, Method::DELETE, &format!("{}?dry_run=true", path(port)), None, &[]).await;
	assert_eq!((status, v["action"].as_str()), (StatusCode::OK, Some("delete")), "{v}");
	assert_eq!(call(&h, Method::DELETE, &path(port), None, &[]).await.0, StatusCode::NO_CONTENT);
	assert_eq!(fetch(port, "/z").await.0, 404);
	assert_eq!(call(&h, Method::GET, &path(port), None, &[]).await.0, StatusCode::NOT_FOUND);
	let (_, rule) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert!(rule.get("overlay").is_none(), "{rule}");
}

#[tokio::test]
async fn only_static_rules_take_an_overlay() {
	let h = harness().await;
	let b = backend("B").await;
	let port = free_port();
	assert_eq!(call(&h, Method::PUT, &path(port), Some(overlay(b)), &[]).await.0, StatusCode::NOT_FOUND);
	let (status, v) = h.post(file_rule(port, b)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(overlay(b)), &[]).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("not_static")), "{v}");
	// a static rule without http takes no routes
	let plain = free_port();
	let rule =
		json!([{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": plain, "remote_addr": "127.0.0.1", "remote_port": b.port()}]);
	h.registry.load_static_labeled(requests(rule)).await.unwrap();
	let (status, v, _) = call(&h, Method::PUT, &path(plain), Some(overlay(b)), &[]).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
}

/// A reload that adds a name, drops http, removes the rule and brings it back: the overlay is
/// kept throughout and applies again.
#[tokio::test]
async fn reloads_keep_the_overlay_and_report_whether_it_applies() {
	let h = harness().await;
	let (a, b) = (backend("A").await, backend("B").await);
	let port = free_port();
	h.registry.load_static_labeled(requests(json!([file_rule(port, a)]))).await.unwrap();
	assert_eq!(call(&h, Method::PUT, &path(port), Some(overlay(b)), &[]).await.0, StatusCode::CREATED);

	// the file defines `extra` now: the file's wins, the overlay's is shadowed
	let mut file = file_rule(port, a);
	file["http"]["routes"].as_array_mut().unwrap().push(json!({"name": "extra", "match": "PathPrefix(`/x`)", "service": "a"}));
	h.registry.reload_static(requests(json!([file]))).await.unwrap();
	let (_, v, _) = call(&h, Method::GET, &path(port), None, &[]).await;
	assert_eq!(v["state"], "applied", "{v}");
	assert_eq!(v["shadowed"], json!([{"kind": "route", "name": "extra", "reason": "the settings file defines it"}]), "{v}");
	assert_eq!(fetch(port, "/x").await, (200, "A".into()));
	assert_eq!(fetch(port, "/reuse").await, (200, "A".into()));
	assert_eq!(fetch(port, "/elsewhere").await.0, 404, "the shadowed catch-all is gone");

	// no http any more: kept, not applied
	let plain =
		json!([{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "remote_addr": "127.0.0.1", "remote_port": b.port()}]);
	h.registry.reload_static(requests(plain)).await.unwrap();
	let (_, v, _) = call(&h, Method::GET, &path(port), None, &[]).await;
	assert_eq!((v["state"].as_str(), v["reason"].as_str()), (Some("not_applied"), Some("shape")), "{v}");
	let (_, rule) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!(rule["state"], "running", "the file's rule runs alone: {rule}");

	// the rule goes away: kept
	h.registry.reload_static(vec![]).await.unwrap();
	let (status, v, _) = call(&h, Method::GET, &path(port), None, &[]).await;
	assert_eq!((status, v["reason"].as_str()), (StatusCode::OK, Some("no_static_rule")), "{v}");

	// and comes back: applies again
	h.registry.reload_static(requests(json!([file_rule(port, a)]))).await.unwrap();
	let (_, v, _) = call(&h, Method::GET, &path(port), None, &[]).await;
	assert_eq!(v["state"], "applied", "{v}");
	assert_eq!(fetch(port, "/x").await, (200, "B".into()));
	assert_eq!(fetch(port, "/app").await.0, 403);
}

/// An overlay oidc's callback path never answers a request a file route matched.
#[tokio::test]
async fn an_overlay_oidc_does_not_take_a_file_routes_path() {
	let h = harness().await;
	let (a, b) = (backend("A").await, backend("B").await);
	let dir = std::env::temp_dir().join(format!("rproxy-it-overlay-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let (secret, cookie) = (dir.join("client.secret"), dir.join("cookie.secret"));
	std::fs::write(&secret, "s3cret").unwrap();
	std::fs::write(&cookie, "0123456789abcdef0123456789abcdef").unwrap();
	let port = free_port();
	let file = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "cb", "match": "PathPrefix(`/cb`)", "service": "a"}],
		"services": {"a": {"servers": [{"url": format!("http://{a}")}]}}
	}});
	h.registry.load_static_labeled(requests(json!([file]))).await.unwrap();
	let ov = json!({"http": {
		"routes": [{"name": "o", "match": "PathPrefix(`/o`)", "service": "b", "middlewares": ["sso"]}],
		"services": {"b": {"servers": [{"url": format!("http://{b}")}]}},
		"middlewares": {"sso": {"oidc": {"issuer": "https://id.example", "client_id": "x", "client_secret_file": secret,
			"cookie_secret_file": cookie, "callback_path": "/cb", "logout_path": "/bye"}}}
	}});
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(ov), &[]).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(fetch(port, "/cb").await, (200, "A".into()), "the file's route keeps its path");
	assert_ne!(fetch(port, "/bye").await, (404, String::new()), "the overlay's logout path is answered where no file route matches");
	std::fs::remove_dir_all(dir).unwrap();
}

async fn tls_backend(pki: &Pki, cert: &Issued, tag: &'static str) -> SocketAddr {
	let acceptor = pki.acceptor(cert);
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move {
		loop {
			let (s, _) = listener.accept().await.unwrap();
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				let Ok(mut s) = acceptor.accept(s).await else { return };
				let mut buf = [0u8; 256];
				while let Ok(n) = s.read(&mut buf).await {
					if n == 0 || s.write_all(&[tag.as_bytes(), &buf[..n]].concat()).await.is_err() {
						break;
					}
				}
			});
		}
	});
	addr
}

async fn tls_roundtrip(pki: &Pki, port: u16, name: &str, msg: &str) -> std::io::Result<String> {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
	let mut s = pki.connector(None).connect(name.to_string().try_into().unwrap(), tcp).await?;
	s.write_all(msg.as_bytes()).await?;
	let mut buf = [0u8; 256];
	let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await??;
	Ok(String::from_utf8_lossy(&buf[..n]).into_owned())
}

/// `tls.routes` of an `sni` rule: names no file route matches go to the overlay's.
#[tokio::test]
async fn sni_names_are_added_where_the_file_has_none() {
	let pki = Pki::new("overlay-sni");
	let cert = pki.server("backend", &["a.test", "b.test", "c.test", "x.wild.test"]);
	let (a, b, d) = (tls_backend(&pki, &cert, "A:").await, tls_backend(&pki, &cert, "B:").await, tls_backend(&pki, &cert, "D:").await);
	let h = harness().await;
	let port = free_port();
	let file = json!([{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "remote_addr": "127.0.0.1", "remote_port": d.port(),
	"tls": {"mode": "sni", "routes": [
		{"server_name": "a.test", "remote_addr": "127.0.0.1", "remote_port": a.port()},
		{"server_name": "*.wild.test", "remote_addr": "127.0.0.1", "remote_port": a.port()}
	]}}]);
	h.registry.load_static_labeled(requests(file)).await.unwrap();
	assert_eq!(tls_roundtrip(&pki, port, "b.test", "1").await.unwrap(), "D:1");
	let ov = json!({"tls": {"routes": [
		{"server_names": ["b.test", "x.wild.test"], "remote_addr": "127.0.0.1", "remote_port": b.port()}
	]}});
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(ov), &[]).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(tls_roundtrip(&pki, port, "b.test", "2").await.unwrap(), "B:2");
	assert_eq!(tls_roundtrip(&pki, port, "x.wild.test", "3").await.unwrap(), "A:3", "the file's wildcard comes first");
	assert_eq!(tls_roundtrip(&pki, port, "c.test", "4").await.unwrap(), "D:4");
	assert_eq!(tls_roundtrip(&pki, port, "a.test", "5").await.unwrap(), "A:5");
	// the same name as the file's is refused
	let same = json!({"tls": {"routes": [{"server_name": "A.test", "remote_addr": "127.0.0.1", "remote_port": b.port()}]}});
	assert_eq!(call(&h, Method::PUT, &path(port), Some(same), &[]).await.0, StatusCode::CONFLICT);
	let up = json!({"tls": {"routes": [{"server_name": "c.test", "remote_addr": "127.0.0.1", "remote_port": b.port(), "upstream": {"tls": true}}]}});
	assert_eq!(call(&h, Method::PUT, &path(port), Some(up), &[]).await.0, StatusCode::BAD_REQUEST);
}

fn sha(s: &str) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn scopes_and_ports_apply() {
	let dir = std::env::temp_dir().join(format!("rproxy-it-overlay-tokens-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let file = dir.join("tokens.yaml");
	let (a, b) = (backend("A").await, backend("B").await);
	let (port, other) = (free_port(), free_port());
	std::fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: reader, sha256: {}, scopes: [rules:read]}}\n  - {{name: deploy, sha256: {}, scopes: [rules:write], allow_listen_ports: '{other}'}}\n  - {{name: ops, sha256: {}, scopes: [rules:read, rules:write], allow_listen_ports: '{port}'}}\n",
			sha("r"),
			sha("d"),
			sha("o")
		),
	)
	.unwrap();
	let h = harness_with(Tokens::from_file(file).unwrap()).await;
	h.registry.load_static_labeled(requests(json!([file_rule(port, a)]))).await.unwrap();
	let auth = |t: &'static str| format!("Bearer {t}");
	let (r, d, o) = (auth("r"), auth("d"), auth("o"));
	assert_eq!(
		call(&h, Method::PUT, &path(port), Some(overlay(b)), &[("authorization", &r)]).await.0,
		StatusCode::FORBIDDEN,
		"rules:read only"
	);
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(overlay(b)), &[("authorization", &d)]).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")), "outside allow_listen_ports: {v}");
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(overlay(b)), &[("authorization", &o)]).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["created_by"], "ops");
	let (status, v, _) = call(&h, Method::GET, &path(port), None, &[("authorization", &r)]).await;
	assert_eq!((status, v["updated_by"].as_str()), (StatusCode::OK, Some("ops")), "{v}");
	assert_eq!(call(&h, Method::DELETE, &path(port), None, &[("authorization", &d)]).await.0, StatusCode::FORBIDDEN);
	assert_eq!(call(&h, Method::DELETE, &path(port), None, &[("authorization", &o)]).await.0, StatusCode::NO_CONTENT);
	std::fs::remove_dir_all(dir).unwrap();
}

/// Stored in `rproxy_rule_overlays` (a memory store here) when a `persist: true` token makes it
/// (a `persist: false` token's stays in memory) and put back on the static rule after a
/// restart; handed over in a live upgrade.
#[tokio::test]
async fn overlays_survive_a_restart_and_a_live_upgrade() {
	let (a, b) = (backend("A").await, backend("B").await);
	let port = free_port();
	let dir = std::env::temp_dir().join(format!("rproxy-it-overlay-persist-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let file = dir.join("tokens.yaml");
	std::fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: ci, sha256: {}, scopes: [rules:read, rules:write], persist: true}}\n  - {{name: ui, sha256: {}, scopes: [rules:read, rules:write]}}\n",
			sha("ci"),
			sha("ui")
		),
	)
	.unwrap();
	let old = harness_with(Tokens::from_file(file).unwrap()).await;
	let store = Arc::new(Store::memory("node-o"));
	old.registry.set_persist(store.clone());
	old.registry.load_static_labeled(requests(json!([file_rule(port, a)]))).await.unwrap();
	let (ci, ui) = ("Bearer ci".to_string(), "Bearer ui".to_string());
	// a token without persist: in force, in memory only (as its rules)
	let (status, v, _) = call(&old, Method::PUT, &path(port), Some(overlay(b)), &[("authorization", &ui)]).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(v.get("persisted").is_none(), "not stored: {v}");
	assert!(store.memory_overlays().is_empty());
	assert_eq!(fetch(port, "/x").await, (200, "B".into()));
	assert_eq!(call(&old, Method::DELETE, &path(port), None, &[("authorization", &ui)]).await.0, StatusCode::NO_CONTENT);
	// a persist token's is stored, and a later change by any token is written too
	let (status, v, _) = call(&old, Method::PUT, &path(port), Some(overlay(b)), &[("authorization", &ci)]).await;
	assert_eq!((status, &v["persisted"]), (StatusCode::CREATED, &json!(true)), "{v}");
	let mut changed = overlay(b);
	changed["http"]["routes"][1]["priority"] = json!(300000);
	let (status, v, _) = call(&old, Method::PUT, &path(port), Some(changed), &[("authorization", &ui)]).await;
	assert_eq!((status, &v["persisted"], &v["updated_by"]), (StatusCode::OK, &json!(true), &json!("ui")), "{v}");
	let rows = store.memory_overlays();
	assert_eq!(rows.len(), 1);
	assert_eq!((rows[0].spec.http.as_ref().unwrap().routes[1].priority, rows[0].updated_by.as_str()), (Some(300000), "ui"));
	std::fs::remove_dir_all(dir).unwrap();

	// a live upgrade: the state, as JSON, to a new registry that read the settings file
	let state = rproxy_api::control::upgrade::handoff::prepare(&old.registry, Duration::from_secs(5)).await.unwrap();
	let state: rproxy_api::control::upgrade::handoff::State = serde_json::from_value(serde_json::to_value(&state).unwrap()).unwrap();
	assert_eq!(state.overlays.len(), 1);
	store.thaw();
	// ports: the old registry lets go of the listener first (a restart would too)
	old.registry.shutdown().await;
	let new = harness().await;
	new.registry.load_static_labeled(requests(json!([file_rule(port, a)]))).await.unwrap();
	state.restore_rules(&new.registry).await;
	let (_, v, _) = call(&new, Method::GET, &path(port), None, &[]).await;
	assert_eq!(v["state"], "applied", "{v}");
	assert_eq!(fetch(port, "/x").await, (200, "B".into()));
	new.registry.shutdown().await;

	// a restart: read back from the table
	let again = harness().await;
	let store = Arc::new(store.memory_after_upgrade());
	again.registry.set_persist(store.clone());
	again.registry.load_static_labeled(requests(json!([file_rule(port, a)]))).await.unwrap();
	let rows = store.load_overlays().await.unwrap();
	again.registry.restore_overlays(rows.into_iter().map(|r| r.into_overlay()).collect(), "database").await;
	assert_eq!(fetch(port, "/x").await, (200, "B".into()));
	assert_eq!(call(&again, Method::DELETE, &path(port), None, &[]).await.0, StatusCode::NO_CONTENT);
	assert!(store.memory_overlays().is_empty(), "the row goes with it");
	assert_eq!(fetch(port, "/x").await.0, 404);
}

#[tokio::test]
async fn the_feature_is_announced() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["static_overlay"], true, "{caps}");
}
