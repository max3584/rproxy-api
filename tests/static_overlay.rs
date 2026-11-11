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

	// If-None-Match: * creates only (#399): a dry run, then the creation
	let (status, v, _) = call(&h, Method::PUT, &format!("{}?dry_run=true", path(port)), Some(overlay(b)), &[("If-None-Match", "*")]).await;
	assert_eq!((status, v["action"].as_str()), (StatusCode::OK, Some("create")), "{v}");
	let (status, v, etag) = call(&h, Method::PUT, &path(port), Some(overlay(b)), &[("If-None-Match", "*")]).await;
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
	// an overlay is there: If-None-Match: * (or its ETag) fails, in a dry run too; another ETag passes
	for (query, value) in [("", "*"), ("?dry_run=true", "*"), ("", etag.as_deref().unwrap())] {
		let (status, v, _) = call(&h, Method::PUT, &format!("{}{query}", path(port)), Some(changed.clone()), &[("If-None-Match", value)]).await;
		assert_eq!((status, v["code"].as_str()), (StatusCode::PRECONDITION_FAILED, Some("precondition_failed")), "{query} {value}: {v}");
	}
	let (status, v, _) =
		call(&h, Method::PUT, &format!("{}?dry_run=true", path(port)), Some(changed.clone()), &[("If-None-Match", "\"o-0000\"")]).await;
	assert_eq!((status, v["action"].as_str()), (StatusCode::OK, Some("update")), "{v}");
	// both at once is refused
	let both = [("If-Match", etag.as_deref().unwrap()), ("If-None-Match", "*")];
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(changed.clone()), &both).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
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

	// two creations at once with If-None-Match: *: one makes it, the other is 412
	let (target, only_new) = (path(port), [("If-None-Match", "*")]);
	let ((one, v1, _), (two, v2, _)) = tokio::join!(
		call(&h, Method::PUT, &target, Some(overlay(b)), &only_new),
		call(&h, Method::PUT, &target, Some(overlay(b)), &only_new)
	);
	let mut statuses = [one, two];
	statuses.sort();
	assert_eq!(statuses, [StatusCode::CREATED, StatusCode::PRECONDITION_FAILED], "{v1} {v2}");
	assert_eq!(fetch(port, "/x").await, (200, "B".into()));
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
	for f in [&secret, &cookie] {
		std::fs::set_permissions(f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	}
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
	// a name under the file's wildcard could never be reached: refused
	let covered =
		json!({"tls": {"routes": [{"server_names": ["b.test", "x.wild.test"], "remote_addr": "127.0.0.1", "remote_port": b.port()}]}});
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(covered), &[]).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("overlay_conflict")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("*.wild.test"), "{v}");
	let ov = json!({"tls": {"routes": [{"server_name": "b.test", "remote_addr": "127.0.0.1", "remote_port": b.port()}]}});
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

/// Echoes the header `x-auth-user` it received.
async fn echo_user() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
		req.headers().get("x-auth-user").and_then(|v| v.to_str().ok()).unwrap_or("-").to_string()
	});
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

async fn fetch_with(port: u16, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
	let client = reqwest::Client::builder().timeout(Duration::from_secs(5)).build().unwrap();
	let mut r = client.get(format!("http://127.0.0.1:{port}{path}"));
	for (k, v) in headers {
		r = r.header(*k, *v);
	}
	let r = r.send().await.unwrap();
	(r.status().as_u16(), r.text().await.unwrap_or_default())
}

/// Review M1: what says where a request came from is never an identity header. Behind
/// `trusted_proxies`, an overlay `forward_auth` naming X-Forwarded-For is refused, and a file's
/// (only warned) does not remove the proxy's X-Forwarded-For before `client_ip`, so the file's
/// `ip_allow` still sees the client. An overlay's own identity header is removed only from the
/// requests no file route took.
#[tokio::test]
async fn forwarding_headers_are_no_identity_and_overlay_identities_stay_off_file_routes() {
	let h = harness_with_global(Tokens::disabled(), rproxy_api::l7::access::HttpGlobal::without_file(&["127.0.0.0/8".to_string()])).await;
	let echo = echo_user().await;
	let port = free_port();
	let file = json!([{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "app", "match": "PathPrefix(`/app`)", "service": "e", "middlewares": ["inside"]}],
		"services": {"e": {"servers": [{"url": format!("http://{echo}")}]}},
		"middlewares": {
			"inside": {"ip_allow": {"source_range": ["127.0.0.0/8"]}},
			"unused": {"forward_auth": {"address": "http://127.0.0.1:9/", "response_headers": ["X-Forwarded-For"]}}
		}
	}}]);
	h.registry.load_static_labeled(requests(file)).await.unwrap();
	let xff = [("x-forwarded-for", "203.0.113.5")];
	assert_eq!(fetch_with(port, "/app", &xff).await.0, 403, "the client behind the trusted proxy is outside ip_allow");
	assert_eq!(fetch_with(port, "/app", &[]).await.0, 200);

	let bad = json!({"http": {"middlewares": {"fa": {"forward_auth": {"address": "http://127.0.0.1:9/", "response_headers": ["x-forwarded-for"]}}}}});
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(bad), &[]).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("x-forwarded-for"), "{v}");
	let bad = json!({"http": {"middlewares": {"ba": {"basic_auth": {"users_file": "/nonexistent", "user_header": "X_Real_IP"}}}}});
	assert_eq!(call(&h, Method::PUT, &path(port), Some(bad), &[]).await.0, StatusCode::BAD_REQUEST);

	// an overlay's identity header: not removed from the file's route's requests
	let ov = json!({"http": {
		"routes": [{"name": "o", "match": "PathPrefix(`/o`)", "service": "e", "middlewares": ["fa"]}],
		"middlewares": {"fa": {"forward_auth": {"address": "http://127.0.0.1:9/", "response_headers": ["x-auth-user"]}}}
	}});
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(ov), &[]).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(fetch_with(port, "/app", &[("x-auth-user", "alice")]).await, (200, "alice".into()));
	assert_eq!(fetch_with(port, "/app", &xff).await.0, 403);
}

/// Review M2: the secrets of the file's services and middlewares an overlay reaches are the
/// file's: `409 file_in_use` for a token without `admin`, allowed with it. #319: an overlay may
/// not name a protected file.
#[tokio::test]
async fn an_overlay_reaching_the_files_secrets_needs_admin() {
	let dir = std::env::temp_dir().join(format!("rproxy-it-overlay-files-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let users = dir.join("users");
	// a secret file passes the owner check only when no one else may read it
	rproxy_api::net::files::private_umask();
	std::fs::write(&users, "alice:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=\n").unwrap();
	std::fs::set_permissions(&users, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	let tokens = dir.join("tokens.yaml");
	std::fs::write(
		&tokens,
		format!(
			"tokens:\n  - {{name: ops, sha256: {}, scopes: [rules:read, rules:write]}}\n  - {{name: root, sha256: {}, scopes: [admin]}}\n",
			sha("o"),
			sha("a")
		),
	)
	.unwrap();
	let h = harness_with(Tokens::from_file(tokens.clone()).unwrap()).await;
	let a = backend("A").await;
	let port = free_port();
	let mut file = file_rule(port, a);
	file["http"]["middlewares"]["login"] = json!({"basic_auth": {"users_file": users}});
	file["http"]["middlewares"]["chain"] = json!({"headers": {"request": {"set": {"x-a": "1"}}}});
	h.registry.load_static_labeled(requests(json!([file]))).await.unwrap();
	let (ops, root) = ("Bearer o".to_string(), "Bearer a".to_string());
	// the file's service and a middleware without files: fine
	let plain = json!({"http": {"routes": [{"name": "x", "match": "PathPrefix(`/x`)", "service": "a", "middlewares": ["chain"]}]}});
	let (status, v, _) = call(&h, Method::PUT, &format!("{}?dry_run=true", path(port)), Some(plain), &[("authorization", &ops)]).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	// the file's basic_auth reads a secret file of the file's
	let login = json!({"http": {"routes": [{"name": "x", "match": "PathPrefix(`/x`)", "service": "a", "middlewares": ["login"]}]}});
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(login.clone()), &[("authorization", &ops)]).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::CONFLICT, Some("file_in_use")), "{v}");
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(login), &[("authorization", &root)]).await;
	assert_eq!(status, StatusCode::CREATED, "admin may: {v}");
	// #319: the token file is protected
	rproxy_api::net::protected::set_process(rproxy_api::net::protected::process_entries(Some(&tokens), None, None));
	let protected = json!({"http": {"middlewares": {"b": {"basic_auth": {"users_file": tokens}}},
		"routes": [{"name": "y", "match": "PathPrefix(`/y`)", "service": "a", "middlewares": ["b"]}]}});
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(protected), &[("authorization", &root)]).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("protected_file")), "{v}");
	rproxy_api::net::protected::set_process(vec![]);
	std::fs::remove_dir_all(dir).unwrap();
}

/// `tls.routes` on a `terminate` rule without http and client_auth (relayed per name after
/// the rule's TLS); a port range: the token must have every port.
#[tokio::test]
async fn terminate_rules_and_port_ranges() {
	let pki = Pki::new("overlay-term");
	let front = pki.server("front", &["a.test", "b.test"]);
	let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let b = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (a_addr, b_addr) = (a.local_addr().unwrap(), b.local_addr().unwrap());
	for (l, tag) in [(a, "A:"), (b, "B:")] {
		tokio::spawn(async move {
			loop {
				let (mut s, _) = l.accept().await.unwrap();
				tokio::spawn(async move {
					let mut buf = [0u8; 64];
					while let Ok(n) = s.read(&mut buf).await {
						if n == 0 || s.write_all(&[tag.as_bytes(), &buf[..n]].concat()).await.is_err() {
							break;
						}
					}
				});
			}
		});
	}
	let dir = std::env::temp_dir().join(format!("rproxy-it-overlay-range-{}", std::process::id()));
	std::fs::create_dir_all(&dir).unwrap();
	let tokens = dir.join("tokens.yaml");
	let port = free_tcp_block(2);
	std::fs::write(
		&tokens,
		format!(
			"tokens:\n  - {{name: one, sha256: {}, scopes: [rules:read, rules:write], allow_listen_ports: '{port}'}}\n  - {{name: both, sha256: {}, scopes: [rules:read, rules:write], allow_listen_ports: '{port}-{}'}}\n",
			sha("1"),
			sha("2"),
			port + 1
		),
	)
	.unwrap();
	let h = harness_with(Tokens::from_file(tokens).unwrap()).await;
	let file = json!([{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "listen_port_end": port + 1,
		"remote_addr": "127.0.0.1", "remote_port": a_addr.port(),
		"tls": {"mode": "terminate", "certificates": [{"cert_file": front.cert_file, "key_file": front.key_file}]}}]);
	h.registry.load_static_labeled(requests(file)).await.unwrap();
	let ov = json!({"tls": {"routes": [{"server_name": "b.test", "remote_addr": "127.0.0.1", "remote_port": b_addr.port()}]}});
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(ov.clone()), &[("authorization", "Bearer 1")]).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::FORBIDDEN, Some("forbidden")), "the range's second port: {v}");
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(ov), &[("authorization", "Bearer 2")]).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let talk = |name: &'static str| {
		let connector = pki.connector(None);
		async move {
			let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
			let mut s = connector.connect(name.try_into().unwrap(), tcp).await.unwrap();
			s.write_all(b"x").await.unwrap();
			let mut buf = [0u8; 16];
			let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut buf)).await.unwrap().unwrap();
			String::from_utf8_lossy(&buf[..n]).into_owned()
		}
	};
	assert_eq!(talk("b.test").await, "B:x", "terminated, then the overlay's target");
	assert_eq!(talk("a.test").await, "A:x", "the rule's own target");
	std::fs::remove_dir_all(dir).unwrap();
}

/// Review SHOULD 2: an overlay change takes over the file's middlewares' state: a
/// `rate_limit` guarding the file's route is not started afresh by PUTs.
#[tokio::test]
async fn an_overlay_change_keeps_the_files_rate_limit() {
	let h = harness().await;
	let (a, b) = (backend("A").await, backend("B").await);
	let port = free_port();
	let file = json!([{"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "app", "match": "PathPrefix(`/app`)", "service": "a", "middlewares": ["slow"]}],
		"services": {"a": {"servers": [{"url": format!("http://{a}")}]}},
		"middlewares": {"slow": {"rate_limit": {"average": 1, "period": "1h", "burst": 2}}}
	}}]);
	h.registry.load_static_labeled(requests(file)).await.unwrap();
	assert_eq!(fetch(port, "/app").await.0, 200);
	assert_eq!(fetch(port, "/app").await.0, 200);
	assert_eq!(fetch(port, "/app").await.0, 429);
	for i in 0..3 {
		let mut ov = overlay(b);
		ov["http"]["routes"].as_array_mut().unwrap().truncate(1);
		ov["http"]["routes"][0]["priority"] = json!(i);
		assert!(call(&h, Method::PUT, &path(port), Some(ov), &[]).await.0.is_success());
		assert_eq!(fetch(port, "/app").await.0, 429, "change {i} did not reset the bucket");
	}
	assert_eq!(call(&h, Method::DELETE, &path(port), None, &[]).await.0, StatusCode::NO_CONTENT);
	assert_eq!(fetch(port, "/app").await.0, 429);
}

/// Review S1: only a stored overlay has a row. A stored overlay removed while the database is
/// down, then a `persist: false` token's PUT on the key, then the periodic check: the row goes
/// and the memory-only overlay is not written.
#[tokio::test]
async fn the_periodic_check_writes_no_memory_only_overlay() {
	let dir = std::env::temp_dir().join(format!("rproxy-it-overlay-s1-{}", std::process::id()));
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
	let h = harness_with(Tokens::from_file(file).unwrap()).await;
	let store = Arc::new(Store::memory("node-s1"));
	h.registry.set_persist(store.clone());
	let (a, b) = (backend("A").await, backend("B").await);
	let port = free_port();
	h.registry.load_static_labeled(requests(json!([file_rule(port, a)]))).await.unwrap();
	let (ci, ui) = ("Bearer ci".to_string(), "Bearer ui".to_string());
	assert_eq!(call(&h, Method::PUT, &path(port), Some(overlay(b)), &[("authorization", &ci)]).await.0, StatusCode::CREATED);
	assert_eq!(store.memory_overlays().len(), 1);
	// the database is down: the removal is not written
	store.fail_writes(true);
	assert_eq!(call(&h, Method::DELETE, &path(port), None, &[("authorization", &ci)]).await.0, StatusCode::NO_CONTENT);
	assert_eq!(store.memory_overlays().len(), 1, "the row stays until the database is back");
	// a token without persist puts one in memory on the same key
	let mut mine = overlay(b);
	mine["http"]["routes"].as_array_mut().unwrap().truncate(1);
	let (status, v, _) = call(&h, Method::PUT, &path(port), Some(mine), &[("authorization", &ui)]).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert!(v.get("persisted").is_none(), "{v}");
	// back: the periodic check writes the removal, not the memory-only overlay
	store.fail_writes(false);
	store.reconcile(&h.registry).await.unwrap();
	assert!(store.memory_overlays().is_empty(), "rows: {:?}", store.memory_overlays());
	assert_eq!(fetch(port, "/x").await, (200, "B".into()), "the memory-only overlay is in force");
	std::fs::remove_dir_all(dir).unwrap();
}
