//! `http.pre_routing` (#386, the Gateway API's listener filters, GEP-5224): middlewares every
//! request passes, in order, before the routes are matched; the routes see what they changed.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use common::*;

async fn serve(app: axum::Router) -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

/// Says who it is, with what it received.
async fn backend(name: &'static str) -> SocketAddr {
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| async move {
		let (host, tier, step, path) = {
			let h = |n: &str| req.headers().get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
			(h("host"), h("x-tier"), h("x-step"), req.uri().path().to_string())
		};
		let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
		axum::Json(json!({
			"name": name, "host": host, "tier": tier, "step": step, "path": path, "body": String::from_utf8_lossy(&body),
		}))
	});
	serve(app).await
}

/// An auth server: `X-Token: gold` / `silver` pass with that `X-Tier`, `slow` after 1.5 s and
/// `slowish` after 200 ms as silver; a body `let me in` passes as gold; anything else gets 401.
async fn auth_server() -> SocketAddr {
	let app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
		let token = req.headers().get("x-token").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		let body = axum::body::to_bytes(req.into_body(), 1 << 20).await.unwrap();
		let tier = match token.as_str() {
			"gold" | "silver" => token.clone(),
			"slow" => {
				tokio::time::sleep(Duration::from_millis(1500)).await;
				"silver".into()
			}
			"slowish" => {
				tokio::time::sleep(Duration::from_millis(200)).await;
				"silver".into()
			}
			_ if &body[..] == b"let me in" => "gold".into(),
			_ => {
				return axum::response::Response::builder()
					.status(401)
					.header("x-reason", "no token")
					.body(axum::body::Body::from("denied"))
					.unwrap();
			}
		};
		axum::response::Response::builder().status(200).header("x-tier", tier).body(axum::body::Body::empty()).unwrap()
	});
	serve(app).await
}

fn http_rule(port: u16, http: Value) -> Value {
	json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})
}

fn client() -> reqwest::Client {
	reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build().unwrap()
}

async fn json_of(r: reqwest::Response) -> Value {
	let text = r.text().await.unwrap();
	serde_json::from_str(&text).unwrap_or(Value::String(text))
}

/// `X-Tier: gold` → `gold`; `/new/` (written by a pre-routing middleware) → `moved` (the gold
/// backend); Host `evil.test` → `evil` (the gold backend); other `/app` paths → `other`; the rest: 404.
fn routes(gold: SocketAddr, other: SocketAddr) -> Value {
	json!([
		{"name": "gold", "match": "Header(`X-Tier`, `gold`)", "to": format!("http://{gold}")},
		{"name": "moved", "match": "PathPrefix(`/new/`)", "to": format!("http://{gold}")},
		{"name": "evil", "match": "Host(`evil.test`)", "to": format!("http://{gold}")},
		{"name": "other", "match": "PathPrefix(`/app`)", "to": format!("http://{other}")},
	])
}

#[tokio::test]
async fn pre_routing_runs_before_matching_in_order() {
	let auth = auth_server().await;
	let (gold, other) = (backend("gold").await, backend("other").await);
	let h = harness().await;
	let port = free_port();
	let middlewares = json!({
		"fa": {"forward_auth": {"address": format!("http://{auth}/check"), "response_headers": ["X-Tier"], "forward_body": {"max_size": 1024}}},
		"token": {"headers": {"request": {"set": {"X-Token": "gold"}}}},
		"step": {"headers": {"request": {"set": {"X-Step": "pre"}}, "response": {"set": {"X-Pre": "yes"}}}},
		"move": {"replace_path_regex": {"regex": "^/old/(.*)", "replacement": "/new/$1"}},
		"host": {"headers": {"request": {"set": {"Host": "evil.test"}}}},
	});
	let (status, v) = h
		.post(http_rule(
			port,
			json!({"pre_routing": ["host", "move", "step", "fa"], "routes": routes(gold, other), "middlewares": middlewares}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = |p: &str| format!("http://127.0.0.1:{port}{p}");

	// the auth server's X-Tier picks the route: matched after forward_auth
	let r = client().get(url("/app/x")).header("X-Token", "gold").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(r.headers()["x-pre"], "yes", "the response side of a pre-routing middleware");
	let v = json_of(r).await;
	assert_eq!((v["name"].as_str(), v["tier"].as_str(), v["step"].as_str()), (Some("gold"), Some("gold"), Some("pre")), "{v}");
	// a client's own X-Tier is an identity header of forward_auth: dropped before routing
	let r = client().get(url("/app/x")).header("X-Token", "silver").header("X-Tier", "gold").send().await.unwrap();
	let v = json_of(r).await;
	assert_eq!((v["name"].as_str(), v["tier"].as_str()), (Some("other"), Some("silver")), "{v}");
	// the body goes to the auth server (forward_body) and on to the backend
	let r = client().post(url("/app/x")).body("let me in").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let v = json_of(r).await;
	assert_eq!((v["name"].as_str(), v["body"].as_str()), (Some("gold"), Some("let me in")), "{v}");

	// refused before matching, also where no route matches (not 404) and with a route that would
	let r = client().get(url("/nowhere")).send().await.unwrap();
	assert_eq!((r.status(), r.headers()["x-reason"].to_str().unwrap()), (StatusCode::UNAUTHORIZED, "no token"));
	assert_eq!(r.headers()["x-pre"], "yes");
	assert_eq!(r.text().await.unwrap(), "denied");
	let r = client().get(url("/app/x")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
	// passed, but no route: the default (404)
	let r = client().get(url("/nowhere")).header("X-Token", "silver").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::NOT_FOUND);

	// a path rewritten before routing is matched (once) as rewritten
	let r = client().get(url("/old/doc")).header("X-Token", "silver").send().await.unwrap();
	let v = json_of(r).await;
	assert_eq!((v["name"].as_str(), v["path"].as_str()), (Some("gold"), Some("/new/doc")), "{v}");

	// Host stays the client's: not `evil.test` for routing, nor for the backend
	let r = client().get(url("/app/x")).header("X-Token", "silver").header("Host", "app.test").send().await.unwrap();
	let v = json_of(r).await;
	assert_eq!((v["name"].as_str(), v["host"].as_str()), (Some("other"), Some("app.test")), "{v}");

	// in the order written: the token is set after forward_auth has asked (401), then before (200)
	let (status, v) = h
		.patch(
			&format!("tcp/127.0.0.1/{port}"),
			json!({"http": {"pre_routing": ["fa", "token"], "routes": routes(gold, other), "middlewares": middlewares}}),
		)
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let r = client().get(url("/app/x")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
	let (status, v) = h
		.patch(
			&format!("tcp/127.0.0.1/{port}"),
			json!({"http": {"pre_routing": ["token", "fa"], "routes": routes(gold, other), "middlewares": middlewares}}),
		)
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	let r = client().get(url("/app/x")).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(json_of(r).await["name"], "gold");
}

#[tokio::test]
async fn pre_routing_runs_before_the_default_service() {
	let auth = auth_server().await;
	let fallback = backend("fallback").await;
	let h = harness().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"pre_routing": ["fa"],
				"routes": [],
				"services": {"fallback": {"servers": [{"url": format!("http://{fallback}")}]}},
				"default": {"service": "fallback"},
				"middlewares": {"fa": {"forward_auth": {"address": format!("http://{auth}/check")}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = format!("http://127.0.0.1:{port}/x");
	assert_eq!(client().get(&url).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
	let r = client().get(&url).header("X-Token", "gold").send().await.unwrap();
	assert_eq!(json_of(r).await["name"], "fallback");
}

#[tokio::test]
async fn route_request_timeout_counts_from_before_pre_routing() {
	let auth = auth_server().await;
	let other = backend("other").await;
	let h = harness().await;
	let port = free_port();
	let http = |timeout: &str| {
		json!({
			"pre_routing": ["fa"],
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": format!("http://{other}"), "timeouts": {"request": timeout}}],
			"middlewares": {"fa": {"forward_auth": {"address": format!("http://{auth}/check"), "timeout": "5s"}}},
		})
	};
	let (status, v) = h.post(http_rule(port, http("1s"))).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = format!("http://127.0.0.1:{port}/x");
	// the auth server took 1.5 s of the route's 1 s
	let began = Instant::now();
	let r = client().get(&url).header("X-Token", "slow").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::GATEWAY_TIMEOUT);
	assert!(began.elapsed() < Duration::from_secs(4), "{:?}", began.elapsed());
	assert_eq!(client().get(&url).header("X-Token", "gold").send().await.unwrap().status(), StatusCode::OK);
	let (status, v) = h.patch(&format!("tcp/127.0.0.1/{port}"), json!({"http": http("3s")})).await;
	assert_eq!(status, StatusCode::OK, "{v}");
	assert_eq!(client().get(&url).header("X-Token", "slow").send().await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn pre_routing_takes_only_kinds_that_run_before_routing() {
	let h = harness().await;
	let base = |pre: Value, m: Value| {
		http_rule(
			free_port(),
			json!({"pre_routing": pre, "routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:9"}], "middlewares": m}),
		)
	};
	for (kind, spec) in [
		("retry", json!({"retry": {"attempts": 2}})),
		("cache", json!({"cache": {"ttl": "1s"}})),
		("replace_host", json!({"replace_host": {"host": "x.test"}})),
		("mirror", json!({"mirror": {"service": "copy"}})),
	] {
		let mut rule = base(json!(["m"]), json!({ "m": spec }));
		rule["http"]["services"] = json!({"copy": {"servers": [{"url": "http://127.0.0.1:9"}]}});
		let (status, v) = h.post(rule).await;
		assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{kind}: {v}");
		assert!(v["error"].as_str().unwrap().contains("cannot run before routing"), "{kind}: {v}");
	}
	let (status, v) = h.post(base(json!(["nope"]), json!({}))).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	// a middleware runs at most once per request: not twice in pre_routing
	let (status, v) = h.post(base(json!(["h", "h"]), json!({"h": {"headers": {"request": {"set": {"X-A": "1"}}}}}))).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("listed twice"), "{v}");
	// a sign-in before routing makes every route's cache need share_after_auth (#340)
	let cached = |share: bool| {
		http_rule(
			free_port(),
			json!({
				"pre_routing": ["fa"],
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:9", "middlewares": ["c"]}],
				"middlewares": {
					"fa": {"forward_auth": {"address": "http://127.0.0.1:9/"}},
					"c": {"cache": {"ttl": "1s", "share_after_auth": share}},
				},
			}),
		)
	};
	let (status, v) = h.post(cached(false)).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("share_after_auth"), "{v}");
	let (status, v) = h.post(cached(true)).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	let (_, caps) = h.get("/capabilities").await;
	assert!(caps["features"]["http_options"].as_array().unwrap().contains(&json!("pre_routing")), "{caps}");
	let kinds = caps["features"]["pre_routing_kinds"].as_array().unwrap();
	assert!(kinds.contains(&json!("forward_auth")) && kinds.contains(&json!("headers")), "{caps}");
	assert!(!kinds.contains(&json!("retry")), "{caps}");
}

#[tokio::test]
async fn a_pre_routing_circuit_breaker_counts_the_routes_answers_once() {
	let failing = serve(axum::Router::new().fallback(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "down") })).await;
	let h = harness().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"pre_routing": ["cb"],
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": format!("http://{failing}")}],
				"middlewares": {"cb": {"circuit_breaker": {"failure_percent": 50, "window": "10s", "recovery": "10s"}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = format!("http://127.0.0.1:{port}/x");
	// MIN_REQUESTS (10) failures open it: each request is counted once, not skipped
	for n in 0..10 {
		assert_eq!(client().get(&url).send().await.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR, "request {n}");
	}
	assert_eq!(client().get(&url).send().await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
	// also for requests no route would take
	assert_eq!(client().get(format!("http://127.0.0.1:{port}/other")).send().await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// Counts the requests it gets; `GET /flip` turns failing (500) on and off.
async fn counting_backend() -> (SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>, std::sync::Arc<std::sync::atomic::AtomicBool>) {
	use std::sync::atomic::Ordering;
	let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
	let failing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
	let (s, f) = (seen.clone(), failing.clone());
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
		let (s, f) = (s.clone(), f.clone());
		async move {
			s.fetch_add(1, Ordering::SeqCst);
			if req.uri().path() == "/slow" {
				tokio::time::sleep(Duration::from_millis(300)).await;
			}
			if f.load(Ordering::SeqCst) {
				(axum::http::StatusCode::INTERNAL_SERVER_ERROR, "down")
			} else {
				(axum::http::StatusCode::OK, "up")
			}
		}
	});
	(serve(app).await, seen, failing)
}

/// The same middleware in pre_routing and in a route runs once (#386): stateful kinds work.
#[tokio::test]
async fn a_middleware_in_pre_routing_and_a_route_runs_once() {
	use std::sync::atomic::Ordering;
	let (backend, _, failing) = counting_backend().await;
	let dir = std::env::temp_dir().join(format!("rproxy-pre-routing-{}", std::process::id()));
	rproxy_api::net::files::private_umask();
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let users = dir.join("users");
	std::fs::write(&users, format!("alice:{}\n", bcrypt::hash("wonderland", 4).unwrap())).unwrap();
	let h = harness().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"pre_routing": ["cb", "one", "auth"],
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["auth", "one", "cb"]}],
				"middlewares": {
					"cb": {"circuit_breaker": {"failure_percent": 50, "window": "10s", "recovery": "300ms"}},
					"one": {"in_flight": {"amount": 1}},
					"auth": {"basic_auth": {"users_file": users}},
				},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = format!("http://127.0.0.1:{port}/x");
	let get = || client().get(&url).basic_auth("alice", Some("wonderland")).send();
	// basic_auth: Authorization is not gone for a second check; in_flight (1): not 429 against itself
	for _ in 0..3 {
		assert_eq!(get().await.unwrap().status(), StatusCode::OK);
	}
	assert_eq!(client().get(&url).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
	// circuit_breaker: opens, and closes again after a probe that passes
	failing.store(true, Ordering::SeqCst);
	let mut opened = false;
	for _ in 0..20 {
		match get().await.unwrap().status() {
			StatusCode::INTERNAL_SERVER_ERROR => {}
			StatusCode::SERVICE_UNAVAILABLE => {
				opened = true;
				break;
			}
			other => panic!("{other}"),
		}
	}
	assert!(opened, "the breaker opens");
	failing.store(false, Ordering::SeqCst);
	tokio::time::sleep(Duration::from_millis(400)).await;
	for n in 0..3 {
		assert_eq!(get().await.unwrap().status(), StatusCode::OK, "after recovery, request {n}");
	}
	std::fs::remove_dir_all(dir).unwrap();
}

/// A path rewritten before routing is normalised (and checked) again (#320, #386).
#[tokio::test]
async fn a_path_rewritten_before_routing_is_normalised_again() {
	let other = backend("other").await;
	let h = harness().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"pre_routing": ["strip", "broken"],
				"routes": [
					{"name": "admin", "match": "PathPrefix(`/admin`)", "to": format!("http://{other}"), "middlewares": ["deny"]},
					{"name": "rest", "match": "PathPrefix(`/`)", "to": format!("http://{other}")},
				],
				"middlewares": {
					"strip": {"strip_prefix": {"prefixes": ["/x"]}},
					"broken": {"replace_path_regex": {"regex": "^/bad$", "replacement": "/%zz"}},
					"deny": {"ip_allow": {"source_range": ["192.0.2.0/24"]}},
				},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = |p: &str| format!("http://127.0.0.1:{port}{p}");
	// /x../admin is normal; without /x it is /../admin, which is /admin
	assert_eq!(client().get(url("/x../admin")).send().await.unwrap().status(), StatusCode::FORBIDDEN);
	let r = client().get(url("/x../doc")).send().await.unwrap();
	assert_eq!(json_of(r).await["path"], "/doc");
	// a broken percent-encoding written before routing is a bad path
	assert_eq!(client().get(url("/bad")).send().await.unwrap().status(), StatusCode::BAD_REQUEST);
}

/// The time of a route's timeouts.request that pre_routing used up: 504 at once, nothing to the
/// backend, and not a backend failure for a circuit_breaker before.
#[tokio::test]
async fn a_deadline_spent_before_routing_is_answered_at_once() {
	use std::sync::atomic::Ordering;
	let auth = auth_server().await;
	let (backend, seen, _) = counting_backend().await;
	let h = harness().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"pre_routing": ["cb", "fa"],
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "timeouts": {"request": "100ms"}}],
				"middlewares": {
					"cb": {"circuit_breaker": {"failure_percent": 50, "window": "30s", "recovery": "30s"}},
					"fa": {"forward_auth": {"address": format!("http://{auth}/check"), "timeout": "5s"}},
				},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let url = format!("http://127.0.0.1:{port}/x");
	let c = client();
	let r = c.get(&url).header("X-Token", "gold").send().await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(r.text().await.unwrap(), "up");
	let before = seen.load(Ordering::SeqCst);
	// more than MIN_REQUESTS (10): as backend failures they would open the breaker
	for n in 0..11 {
		let r = c.get(&url).header("X-Token", "slowish").send().await.unwrap();
		assert_eq!(r.status(), StatusCode::GATEWAY_TIMEOUT, "request {n}");
	}
	tokio::time::sleep(Duration::from_millis(200)).await;
	assert_eq!(seen.load(Ordering::SeqCst), before, "nothing went to the backend after the deadline");
	assert_eq!(c.get(&url).header("X-Token", "gold").send().await.unwrap().status(), StatusCode::OK, "the breaker stays closed");
}

/// HTTP/2: `:authority` as the client sent it, whatever pre_routing does to Host (#386).
#[tokio::test]
async fn http2_authority_is_kept() {
	use http_body_util::{BodyExt, Empty};
	let (gold, other) = (backend("gold").await, backend("other").await);
	let h = harness().await;
	let port = free_port();
	let (status, v) = h
		.post(http_rule(
			port,
			json!({
				"pre_routing": ["host"],
				"routes": routes(gold, other),
				"middlewares": {"host": {"headers": {"request": {"set": {"Host": "evil.test"}}}}},
			}),
		))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let (mut sender, conn) = hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
		.handshake(hyper_util::rt::TokioIo::new(tcp))
		.await
		.unwrap();
	tokio::spawn(conn);
	let req = hyper::Request::get("http://app.test/app/x").body(Empty::<bytes::Bytes>::new()).unwrap();
	let resp = sender.send_request(req).await.unwrap();
	assert_eq!(resp.status(), hyper::StatusCode::OK);
	let body = resp.into_body().collect().await.unwrap().to_bytes();
	let v: Value = serde_json::from_slice(&body).unwrap();
	assert_eq!((v["name"].as_str(), v["host"].as_str()), (Some("other"), Some("app.test")), "{v}");
}
