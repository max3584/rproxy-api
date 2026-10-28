//! The `cache` middleware (#340) through real sockets: one backend request per key and
//! `ttl` however many clients ask at once, the answer when the backend fails
//! (`stale_on_error`), what is never kept, the route's checks, and the statistics.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode as AxStatus};
use axum::response::IntoResponse;
use reqwest::StatusCode;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use common::*;

/// A backend that counts requests, answers with the count and can be slowed down or broken.
struct Backend {
	hits: AtomicU64,
	status: AtomicU16,
	delay_ms: AtomicU64,
	addr: std::net::SocketAddr,
}

async fn backend() -> Arc<Backend> {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let b = Arc::new(Backend {
		hits: AtomicU64::new(0),
		status: AtomicU16::new(200),
		delay_ms: AtomicU64::new(0),
		addr: listener.local_addr().unwrap(),
	});
	fn count(b: &Backend) -> u64 {
		b.hits.fetch_add(1, Ordering::SeqCst) + 1
	}
	let app = axum::Router::new()
		.route(
			"/data",
			axum::routing::get(|State(b): State<Arc<Backend>>, headers: HeaderMap| async move {
				let n = count(&b);
				let delay = b.delay_ms.load(Ordering::SeqCst);
				if delay > 0 {
					tokio::time::sleep(Duration::from_millis(delay)).await;
				}
				let status = AxStatus::from_u16(b.status.load(Ordering::SeqCst)).unwrap();
				let user = headers.get("x-forwarded-user").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
				(status, [("content-type", "application/json")], axum::Json(json!({"n": n, "user": user}))).into_response()
			}),
		)
		.route(
			"/cookie",
			axum::routing::get(|State(b): State<Arc<Backend>>| async move { ([("set-cookie", "s=1")], count(&b).to_string()) }),
		)
		.route(
			"/private",
			axum::routing::get(|State(b): State<Arc<Backend>>| async move { ([("cache-control", "private")], count(&b).to_string()) }),
		)
		.route("/big", axum::routing::get(|State(b): State<Arc<Backend>>| async move { format!("{}{}", count(&b), "x".repeat(4096)) }))
		.fallback(|State(b): State<Arc<Backend>>| async move { count(&b).to_string() })
		.with_state(b.clone());
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	b
}

fn client() -> reqwest::Client {
	reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap()
}

/// A rule with one route through `middlewares` to `b`.
async fn rule(h: &Harness, b: &Backend, cache: Value) -> u16 {
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"routes": [{"name": "api", "match": "PathPrefix(`/`)", "to": format!("http://{}", b.addr), "middlewares": ["micro"]}],
				"middlewares": {"micro": {"cache": cache}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	port
}

async fn get(port: u16, path: &str, headers: &[(&str, &str)]) -> reqwest::Response {
	let mut r = client().get(format!("http://127.0.0.1:{port}{path}"));
	for (k, v) in headers {
		r = r.header(*k, *v);
	}
	r.send().await.unwrap()
}

fn x_cache(r: &reqwest::Response) -> String {
	r.headers().get("x-cache").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default()
}

#[tokio::test]
async fn many_clients_one_backend_request_per_ttl() {
	let h = harness().await;
	let b = backend().await;
	let port = rule(&h, &b, json!({"ttl": "1s"})).await;
	// the backend is slow: all of these come while the first is on its way
	b.delay_ms.store(300, Ordering::SeqCst);
	let answers = futures_util::future::join_all((0..40).map(|_| async move {
		let r = get(port, "/data", &[]).await;
		assert_eq!(r.status(), StatusCode::OK);
		let x = x_cache(&r);
		(x, r.json::<Value>().await.unwrap()["n"].clone())
	}))
	.await;
	assert_eq!(b.hits.load(Ordering::SeqCst), 1, "one request to the backend: {answers:?}");
	assert!(answers.iter().all(|(_, n)| *n == 1), "{answers:?}");
	assert_eq!(answers.iter().filter(|(x, _)| x == "MISS").count(), 1, "{answers:?}");
	b.delay_ms.store(0, Ordering::SeqCst);
	// fresh for ttl, with Age
	let r = get(port, "/data", &[]).await;
	assert_eq!((x_cache(&r).as_str(), r.headers().contains_key("age")), ("HIT", true));
	// another query is another key
	assert_eq!(get(port, "/data?page=2", &[]).await.json::<Value>().await.unwrap()["n"], 2);
	// a new answer once ttl has passed
	tokio::time::sleep(Duration::from_millis(1100)).await;
	let r = get(port, "/data", &[]).await;
	assert_eq!(x_cache(&r), "MISS");
	assert_eq!(r.json::<Value>().await.unwrap()["n"], 3);
	// HEAD is answered from GET's answer
	let r = client().head(format!("http://127.0.0.1:{port}/data")).send().await.unwrap();
	assert_eq!((r.status(), x_cache(&r).as_str()), (StatusCode::OK, "HIT"));
	assert!(r.headers()["content-length"].to_str().unwrap().parse::<u64>().unwrap() > 0);
	assert_eq!(b.hits.load(Ordering::SeqCst), 3);

	// counted in stats.http and /metrics
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let v = wait_for(&h, &path, |v| v["stats"]["http"]["cache"]["hit"].as_u64() >= Some(41)).await;
	let stats = &v["stats"]["http"];
	assert_eq!(stats["cache"]["miss"], 3, "{stats}");
	assert_eq!(stats["routes"]["api"]["cache"]["micro"]["miss"], 3, "{stats}");
	let text = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	let labels = format!("protocol=\"tcp\",listen=\"127.0.0.1:{port}\"");
	assert!(text.contains(&format!("rproxy_http_cache_total{{{labels},route=\"api\",middleware=\"micro\",result=\"miss\"}} 3")), "{text}");
	// ?page=2 went out of date for good and was dropped when /data came again
	assert!(text.contains(&format!("rproxy_http_cache_entries{{{labels},middleware=\"micro\"}} 1")), "{text}");
	let (_, caps) = h.get("/capabilities").await;
	assert!(caps["features"]["middlewares"].as_array().unwrap().contains(&json!("cache")), "{caps}");
}

#[tokio::test]
async fn the_last_answer_while_the_backend_fails() {
	let h = harness().await;
	let b = backend().await;
	let port = rule(&h, &b, json!({"ttl": "200ms", "stale_on_error": "1s"})).await;
	assert_eq!(get(port, "/data", &[]).await.json::<Value>().await.unwrap()["n"], 1);
	b.status.store(503, Ordering::SeqCst);
	tokio::time::sleep(Duration::from_millis(250)).await;
	let r = get(port, "/data", &[]).await;
	assert_eq!((r.status(), x_cache(&r).as_str()), (StatusCode::OK, "STALE"));
	assert_eq!(r.json::<Value>().await.unwrap()["n"], 1);
	// a backend nobody listens on is a failure too
	let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
	let path = format!("tcp/127.0.0.1/{port}");
	let (status, v) = h
		.patch(
			&path,
			json!({"http": {
				"routes": [{"name": "api", "match": "PathPrefix(`/`)", "to": format!("http://{dead}"), "middlewares": ["micro"]}],
				"middlewares": {"micro": {"cache": {"ttl": "200ms", "stale_on_error": "1s"}}},
			}}),
		)
		.await;
	assert_eq!(status, StatusCode::OK, "{v}");
	// a changed rule starts with nothing kept: the error goes through
	assert_eq!(get(port, "/data", &[]).await.status(), StatusCode::BAD_GATEWAY);
	// past stale_on_error the error goes through as well
	let port = rule(&h, &b, json!({"ttl": "100ms", "stale_on_error": "100ms"})).await;
	b.status.store(200, Ordering::SeqCst);
	assert_eq!(get(port, "/data", &[]).await.status(), StatusCode::OK);
	b.status.store(500, Ordering::SeqCst);
	tokio::time::sleep(Duration::from_millis(250)).await;
	let r = get(port, "/data", &[]).await;
	assert_eq!((r.status(), x_cache(&r).as_str()), (StatusCode::INTERNAL_SERVER_ERROR, "MISS"));
}

#[tokio::test]
async fn what_is_never_kept() {
	let h = harness().await;
	let b = backend().await;
	let port = rule(&h, &b, json!({"ttl": "10s", "max_body": 1024})).await;
	let b = &b;
	let twice = |path: &'static str, headers: &'static [(&'static str, &'static str)]| async move {
		let before = b.hits.load(Ordering::SeqCst);
		let first = get(port, path, headers).await;
		let x = x_cache(&first);
		first.bytes().await.unwrap();
		get(port, path, headers).await.bytes().await.unwrap();
		(b.hits.load(Ordering::SeqCst) - before, x)
	};
	assert_eq!(twice("/cookie", &[]).await, (2, "MISS".into()), "Set-Cookie");
	assert_eq!(twice("/private", &[]).await, (2, "MISS".into()), "Cache-Control: private");
	assert_eq!(twice("/big", &[]).await, (2, "MISS".into()), "over max_body");
	assert_eq!(twice("/data", &[("authorization", "Bearer t")]).await, (2, "BYPASS".into()), "Authorization");
	assert_eq!(twice("/data", &[("cookie", "s=1")]).await, (2, "BYPASS".into()), "Cookie");
	let before = b.hits.load(Ordering::SeqCst);
	for _ in 0..2 {
		client().post(format!("http://127.0.0.1:{port}/other")).send().await.unwrap();
	}
	assert_eq!(b.hits.load(Ordering::SeqCst) - before, 2, "POST");
	// the big body arrives whole
	let body = get(port, "/big", &[]).await.text().await.unwrap();
	assert_eq!(body.len(), 4096 + body.find('x').unwrap());
}

#[tokio::test]
async fn routes_keep_the_cache_away_from_authentication() {
	let h = harness().await;
	let b = backend().await;
	let post = |middlewares: Vec<&'static str>, defs: Value| {
		let h = &h;
		let to = format!("http://{}", b.addr);
		async move {
			h.post(json!({
				"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(),
				"http": {
					"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": to, "middlewares": middlewares}],
					"middlewares": defs,
				},
			}))
			.await
		}
	};
	let auth = json!({"forward_auth": {"address": "http://127.0.0.1:9/auth"}});
	let (status, v) =
		post(vec!["c", "lan"], json!({"c": {"cache": {"ttl": "1s"}}, "lan": {"ip_allow": {"source_range": ["127.0.0.0/8"]}}})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("before the cache"), "{v}");
	let (status, v) = post(vec!["a", "c"], json!({"c": {"cache": {"ttl": "1s"}}, "a": auth.clone()})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("share_after_auth"), "{v}");
	let (status, v) = post(vec!["a", "c"], json!({"c": {"cache": {"ttl": "1s", "share_after_auth": true}}, "a": auth})).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let (status, v) = post(vec!["c", "c2"], json!({"c": {"cache": {"ttl": "1s"}}, "c2": {"cache": {"ttl": "2s"}}})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	let (status, v) = post(vec!["c"], json!({"c": {"cache": {"ttl": "10ms"}}})).await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	// a server's forward_auth would be skipped too
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"services": {"s": {"servers": [{"url": format!("http://{}", b.addr), "middlewares": ["a"]}]}},
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "s", "middlewares": ["c"]}],
				"middlewares": {"c": {"cache": {"ttl": "1s"}}, "a": {"forward_auth": {"address": "http://127.0.0.1:9/auth"}}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("forward_auth"), "{v}");
}
