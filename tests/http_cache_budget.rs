//! The memory of all `cache` middlewares together (#349, `RPROXY_CACHE_MAX_MEMORY`) through
//! real sockets: two rules' caches share the process's budget, an answer that does not fit
//! drops the oldest of its own cache or is not kept, and `/metrics` shows the total. A test
//! binary of its own: the budget is process-wide.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::json;
use tokio::net::TcpListener;

use common::*;
use rproxy_api::l7::middleware::cache;

/// A backend that counts requests and answers with 1000 bytes.
async fn backend() -> (Arc<AtomicU64>, std::net::SocketAddr) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let hits = Arc::new(AtomicU64::new(0));
	let counted = hits.clone();
	let app = axum::Router::new().fallback(move || {
		let hits = counted.clone();
		async move {
			hits.fetch_add(1, Ordering::SeqCst);
			"x".repeat(1000)
		}
	});
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(hits, addr)
}

async fn rule(h: &Harness, to: std::net::SocketAddr) -> u16 {
	let port = free_port();
	let (status, v) = h
		.post(json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"http": {
				"routes": [{"name": "api", "match": "PathPrefix(`/`)", "to": format!("http://{to}"), "middlewares": ["micro"]}],
				"middlewares": {"micro": {"cache": {"ttl": "1m"}}},
			},
		}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	port
}

async fn x_cache(port: u16, path: &str) -> String {
	let r = reqwest::get(format!("http://127.0.0.1:{port}{path}")).await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let x = r.headers().get("x-cache").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
	assert_eq!(r.text().await.unwrap().len(), 1000, "the answer is given whether kept or not");
	x
}

async fn metrics(h: &Harness) -> String {
	h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap()
}

fn gauge(text: &str, name: &str) -> u64 {
	let line = text.lines().find(|l| l.starts_with(&format!("{name} "))).unwrap_or_else(|| panic!("no {name}: {text}"));
	line.rsplit(' ').next().unwrap().parse().unwrap()
}

#[tokio::test]
async fn caches_share_the_process_budget() {
	let h = harness().await;
	let (hits, to) = backend().await;
	let a = rule(&h, to).await;
	let b = rule(&h, to).await;

	// the default budget: kept
	assert_eq!(cache::memory().0, cache::DEFAULT_PROCESS_MAX_MEMORY);
	assert_eq!(x_cache(a, "/1").await, "MISS");
	assert_eq!(x_cache(a, "/1").await, "HIT");
	let text = metrics(&h).await;
	let one = gauge(&text, "rproxy_http_cache_memory_bytes");
	assert!(one > 1000, "{text}");
	assert_eq!(gauge(&text, "rproxy_http_cache_memory_limit_bytes"), cache::DEFAULT_PROCESS_MAX_MEMORY);

	// room for one answer and a half: b's is given but not kept while a holds its own
	let limit = one + one / 2;
	cache::set_max_memory(limit);
	assert_eq!(x_cache(b, "/1").await, "MISS");
	assert_eq!(x_cache(b, "/1").await, "MISS", "not kept");
	assert_eq!(x_cache(a, "/1").await, "HIT", "a keeps its own");
	// a's next answer drops a's oldest
	assert_eq!(x_cache(a, "/2").await, "MISS");
	assert_eq!(x_cache(a, "/2").await, "HIT");
	assert_eq!(x_cache(a, "/1").await, "MISS", "the oldest went");
	let text = metrics(&h).await;
	let used = gauge(&text, "rproxy_http_cache_memory_bytes");
	assert!(used > 1000 && used <= limit, "{used} {limit}: {text}");
	assert_eq!(gauge(&text, "rproxy_http_cache_memory_limit_bytes"), limit);
	assert_eq!(hits.load(Ordering::SeqCst), 5);

	// a rule that goes gives its memory back; then b keeps its answers
	let status = h.delete(&format!("tcp/127.0.0.1/{a}")).await;
	assert!(status.is_success(), "{status}");
	tokio::time::sleep(Duration::from_millis(100)).await;
	assert_eq!(gauge(&metrics(&h).await, "rproxy_http_cache_memory_bytes"), 0);
	assert_eq!(x_cache(b, "/1").await, "MISS");
	assert_eq!(x_cache(b, "/1").await, "HIT");

	// 0: no limit of the process
	cache::set_max_memory(0);
	assert_eq!(x_cache(b, "/2").await, "MISS");
	assert_eq!(x_cache(b, "/2").await, "HIT");
	let text = metrics(&h).await;
	assert!(gauge(&text, "rproxy_http_cache_memory_bytes") > limit, "{text}");
	assert_eq!(gauge(&text, "rproxy_http_cache_memory_limit_bytes"), 0);
	let (_, caps) = h.get("/capabilities").await;
	assert_eq!(caps["features"]["cache_process_memory"], true, "{caps}");
}
