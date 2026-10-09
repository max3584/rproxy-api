//! L7 features for the Gateway API (#224, #226-#232, #235) through real sockets:
//! `headers` `add`, redirect `status`, route `timeouts`, `replace_host`, per-server
//! middlewares, `cors`, `retry` on status, `mirror` and `status` servers.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::*;

/// Requests a backend received: (path, headers as name -> values).
type Seen = Arc<Mutex<Vec<(String, HashMap<String, Vec<String>>)>>>;

/// A backend answering what it received as JSON, with a few special paths:
/// `/delay/<ms>` answers after that long, `/stream` sends its body over about 1.5 s,
/// `/fail/<key>/<n>/<code>` answers `code` to the first `n` requests of `key`.
async fn backend(tag: &'static str) -> (SocketAddr, Seen) {
	let seen: Seen = Arc::default();
	let failures: Arc<Mutex<HashMap<String, u32>>> = Arc::default();
	let s = seen.clone();
	let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
		let (seen, failures) = (s.clone(), failures.clone());
		async move {
			let path = req.uri().path().to_string();
			let mut headers: HashMap<String, Vec<String>> = HashMap::new();
			for (k, v) in req.headers() {
				headers.entry(k.as_str().to_string()).or_default().push(String::from_utf8_lossy(v.as_bytes()).into_owned());
			}
			seen.lock().unwrap().push((path.clone(), headers.clone()));
			let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
			match parts.as_slice() {
				["delay", ms, ..] => tokio::time::sleep(Duration::from_millis(ms.parse().unwrap_or(0))).await,
				["stream", ..] => {
					let chunks = futures_util::stream::unfold(0u32, |i| async move {
						if i == 5 {
							return None;
						}
						tokio::time::sleep(Duration::from_millis(300)).await;
						Some((Ok::<_, std::io::Error>(Bytes::from(format!("c{i};"))), i + 1))
					});
					return axum::response::Response::new(axum::body::Body::from_stream(chunks));
				}
				["fail", key, n, code] => {
					let mut f = failures.lock().unwrap();
					let count = f.entry(key.to_string()).or_default();
					*count += 1;
					if *count <= n.parse::<u32>().unwrap() {
						return axum::response::Response::builder().status(code.parse::<u16>().unwrap()).body(axum::body::Body::from("failed")).unwrap();
					}
				}
				_ => {}
			}
			let body = json!({"tag": tag, "path": path, "uri": req.uri().to_string(), "headers": headers});
			axum::response::Response::builder()
				.header("content-type", "application/json")
				.header("x-resp-add", "from-backend")
				.body(axum::body::Body::from(body.to_string()))
				.unwrap()
		}
	});
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	(addr, seen)
}

async fn rule(h: &Harness, http: Value) -> u16 {
	let port = free_port();
	let (status, v) = h.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": http})).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	port
}

fn client() -> reqwest::Client {
	reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(10)).build().unwrap()
}

async fn send(req: reqwest::RequestBuilder) -> (StatusCode, reqwest::header::HeaderMap, Value) {
	let r = req.send().await.unwrap();
	let (status, headers) = (r.status(), r.headers().clone());
	let text = r.text().await.unwrap_or_default();
	(status, headers, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

fn header<'a>(v: &'a Value, name: &str) -> Vec<&'a str> {
	v["headers"][name].as_array().map(|a| a.iter().filter_map(|s| s.as_str()).collect()).unwrap_or_default()
}

#[tokio::test]
async fn headers_add_appends_to_existing_values() {
	let h = harness().await;
	let (b, _) = backend("b").await;
	let port = rule(
		&h,
		json!({
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": format!("http://{b}"), "middlewares": ["hdr"]}],
			"middlewares": {"hdr": {"headers": {
				"request": {"set": {"X-Header-Set": "set-overwrites-values"}, "add": {"X-Header-Add": "header-val-1", "X-Header-Add-Append": "header-val-2"}, "remove": ["X-Header-Remove"]},
				"response": {"add": {"X-Resp-Add": "by-rproxy", "X-New": "n"}},
			}}},
		}),
	)
	.await;
	let url = format!("http://127.0.0.1:{port}/x");
	let (status, headers, v) = send(
		client()
			.get(&url)
			.header("x-header-set", "some-other-value")
			.header("x-header-add-append", "append-val-1")
			.header("x-header-remove", "val"),
	)
	.await;
	assert_eq!(status, 200);
	assert_eq!(header(&v, "x-header-set"), ["set-overwrites-values"]);
	assert_eq!(header(&v, "x-header-add"), ["header-val-1"], "added when absent");
	assert_eq!(header(&v, "x-header-add-append"), ["append-val-1,header-val-2"], "appended after the existing value");
	assert!(header(&v, "x-header-remove").is_empty());
	assert_eq!(headers["x-resp-add"], "from-backend,by-rproxy");
	assert_eq!(headers["x-new"], "n");
	// several fields of the name become one
	let (_, _, v) = send(client().get(&url).header("x-header-add", "a").header("X-HEADER-ADD", "b")).await;
	assert_eq!(header(&v, "x-header-add"), ["a,b,header-val-1"]);
}

#[tokio::test]
async fn redirects_answer_with_the_status_given() {
	let h = harness().await;
	let mut middlewares = serde_json::Map::new();
	let mut routes = vec![];
	for code in [301, 302, 303, 307, 308] {
		middlewares.insert(
			format!("r{code}"),
			json!({"redirect_regex": {"regex": "^http://[^/]+/(.*)$", "replacement": "http://example.org/$1", "status": code}}),
		);
		routes.push(json!({"name": format!("r{code}"), "match": format!("PathPrefix(`/s{code}/`)"), "middlewares": [format!("r{code}")]}));
	}
	middlewares.insert("scheme".into(), json!({"redirect_scheme": {"scheme": "https", "status": 303}}));
	routes.push(json!({"name": "scheme", "match": "PathPrefix(`/scheme`)", "middlewares": ["scheme"]}));
	let port = rule(&h, json!({"routes": routes, "middlewares": middlewares})).await;
	for code in [301, 302, 303, 307, 308] {
		for method in [reqwest::Method::GET, reqwest::Method::POST] {
			let (status, headers, _) = send(client().request(method.clone(), format!("http://127.0.0.1:{port}/s{code}/p?q=1"))).await;
			assert_eq!(status.as_u16(), code, "{method}");
			assert_eq!(headers["location"], format!("http://example.org/s{code}/p?q=1"));
		}
	}
	let (status, headers, _) = send(client().post(format!("http://127.0.0.1:{port}/scheme")).header("host", "a.test")).await;
	assert_eq!((status.as_u16(), headers["location"].to_str().unwrap()), (303, "https://a.test/scheme"));

	// other statuses are refused
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "middlewares": ["m"]}],
			"middlewares": {"m": {"redirect_scheme": {"status": 300}}}}}))
		.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("301, 302, 303, 307 or 308"), "{v}");
}

#[tokio::test]
async fn route_timeouts_limit_the_request_and_each_attempt() {
	let h = harness().await;
	let (b, seen) = backend("b").await;
	let svc = json!({"servers": [{"url": format!("http://{b}")}]});
	let port = rule(
		&h,
		json!({
			"routes": [
				{"name": "req", "match": "PathPrefix(`/req/`)", "service": "s", "middlewares": ["strip"], "timeouts": {"request": "500ms"}},
				{"name": "off", "match": "PathPrefix(`/off/`)", "service": "s", "middlewares": ["strip"], "timeouts": {"request": "0s", "backend_request": "0s"}},
				{"name": "per", "match": "PathPrefix(`/per/`)", "service": "s", "middlewares": ["strip", "again"], "timeouts": {"backend_request": "500ms"}},
			],
			"services": {"s": svc},
			"middlewares": {"strip": {"strip_prefix": {"prefixes": ["/req", "/off", "/per"]}}, "again": {"retry": {"attempts": 2, "initial_interval": "10ms"}}},
		}),
	)
	.await;
	let base = format!("http://127.0.0.1:{port}");
	assert_eq!(send(client().get(format!("{base}/req/delay/10"))).await.0, 200);
	let started = Instant::now();
	assert_eq!(send(client().get(format!("{base}/req/delay/1500"))).await.0, StatusCode::GATEWAY_TIMEOUT);
	assert!(started.elapsed() < Duration::from_millis(1200), "{:?}", started.elapsed());
	assert_eq!(send(client().get(format!("{base}/off/delay/1000"))).await.0, 200, "0s is no limit");

	// backend_request is per attempt: two attempts, then 504
	seen.lock().unwrap().clear();
	assert_eq!(send(client().get(format!("{base}/per/delay/1000"))).await.0, StatusCode::GATEWAY_TIMEOUT);
	assert_eq!(seen.lock().unwrap().len(), 2, "retried once after the attempt timed out");

	// after the headers, a body that runs past the deadline is cut off, not ended cleanly
	let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	s.write_all(b"GET /req/stream HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n").await.unwrap();
	let mut out = vec![];
	let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
	let text = String::from_utf8_lossy(&out);
	assert!(text.starts_with("HTTP/1.1 200"), "{text}");
	assert!(!text.ends_with("0\r\n\r\n"), "the chunked body must not get its last chunk: {text}");
	assert!(!text.contains("c4;"), "{text}");

	// shapes
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:1", "timeouts": {"request": "soon"}}]}}))
		.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn replace_host_and_per_server_middlewares() {
	let h = harness().await;
	let (v1, _) = backend("v1").await;
	let (v2, _) = backend("v2").await;
	let port = rule(
		&h,
		json!({
			"routes": [
				{"name": "host", "match": "PathPrefix(`/one`)", "service": "single", "middlewares": ["host"]},
				{"name": "weights", "match": "PathPrefix(`/w`)", "service": "pair"},
			],
			"services": {
				"single": {"servers": [{"url": format!("http://{v1}")}]},
				"pair": {"servers": [
					{"url": format!("http://{v1}"), "weight": 1, "middlewares": ["b1", "path1"]},
					{"url": format!("http://{v2}"), "weight": 1, "middlewares": ["b2"]},
				]},
			},
			"middlewares": {
				"host": {"replace_host": {"host": "one.example.org"}},
				"b1": {"headers": {"request": {"set": {"Backend": "infra-backend-v1"}}, "response": {"set": {"X-Served-By": "v1"}}}},
				"b2": {"headers": {"request": {"set": {"Backend": "infra-backend-v2"}}}},
				"path1": {"add_prefix": {"prefix": "/v1"}},
			},
		}),
	)
	.await;
	let (status, _, v) = send(client().get(format!("http://127.0.0.1:{port}/one")).header("host", "rewrite.example")).await;
	assert_eq!(status, 200);
	assert_eq!(header(&v, "host"), ["one.example.org"]);
	assert_eq!(header(&v, "x-forwarded-host"), ["rewrite.example"], "X-Forwarded-Host keeps the client's");

	let mut by = HashMap::new();
	for _ in 0..20 {
		let (status, headers, v) = send(client().get(format!("http://127.0.0.1:{port}/w"))).await;
		assert_eq!(status, 200);
		let tag = v["tag"].as_str().unwrap().to_string();
		let backend_header = header(&v, "backend")[0].to_string();
		assert_eq!(backend_header, format!("infra-backend-{tag}"), "each server gets its own headers");
		if tag == "v1" {
			assert_eq!(v["path"], "/v1/w", "per-server path rewrite");
			assert_eq!(headers["x-served-by"], "v1");
		} else {
			assert_eq!(v["path"], "/w");
			assert!(!headers.contains_key("x-served-by"));
		}
		*by.entry(tag).or_insert(0) += 1;
	}
	assert_eq!((by["v1"], by["v2"]), (10, 10));

	// only rewriting kinds run per server
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "s"}],
			"services": {"s": {"servers": [{"url": "http://127.0.0.1:1", "middlewares": ["rl"]}]}},
			"middlewares": {"rl": {"rate_limit": {"average": 1}}}}}))
		.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("cannot run per server"), "{v}");
}

#[tokio::test]
async fn cors_answers_preflights_and_marks_responses() {
	let h = harness().await;
	let (b, seen) = backend("b").await;
	let port = rule(
		&h,
		json!({
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": format!("http://{b}"), "middlewares": ["cors"]}],
			"middlewares": {"cors": {"cors": {
				"allow_origins": ["https://www.foo.com", "https://*.bar.com"], "allow_methods": ["GET", "OPTIONS"],
				"allow_headers": ["x-header-1", "x-header-2"], "expose_headers": ["x-header-3", "x-header-4"],
				"allow_credentials": true, "max_age": 3600,
			}}},
		}),
	)
	.await;
	let url = format!("http://127.0.0.1:{port}/cors-1");
	let preflight = |origin: &'static str| {
		client()
			.request(reqwest::Method::OPTIONS, &url)
			.header("origin", origin)
			.header("access-control-request-method", "GET")
			.header("access-control-request-headers", "x-header-1, x-header-2")
	};
	let (status, headers, _) = send(preflight("https://xpto.www.bar.com")).await;
	assert_eq!(status, 204);
	assert_eq!(headers["access-control-allow-origin"], "https://xpto.www.bar.com");
	assert_eq!(headers["access-control-allow-methods"], "GET, OPTIONS");
	assert_eq!(headers["access-control-allow-headers"], "x-header-1, x-header-2");
	assert_eq!(headers["access-control-expose-headers"], "x-header-3, x-header-4");
	assert_eq!(headers["access-control-max-age"], "3600");
	assert_eq!(headers["access-control-allow-credentials"], "true");
	assert!(seen.lock().unwrap().is_empty(), "answered by rproxy");

	let (status, headers, _) = send(preflight("https://foobar.com")).await;
	assert_eq!(status, 204, "a preflight of another origin is answered by rproxy (#238)");
	assert!(!headers.contains_key("access-control-allow-origin"));
	assert!(seen.lock().unwrap().is_empty(), "and never reaches the backend");

	let (status, headers, _) = send(client().get(&url).header("origin", "https://www.foo.com")).await;
	assert_eq!(status, 200);
	assert_eq!(headers["access-control-allow-origin"], "https://www.foo.com");
	assert_eq!(headers["access-control-allow-credentials"], "true");
	assert_eq!(headers["access-control-expose-headers"], "x-header-3, x-header-4");
	let (_, headers, _) = send(client().get(&url).header("origin", "https://foobar.com")).await;
	assert!(!headers.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn retry_on_the_statuses_given() {
	let h = harness().await;
	let (b, seen) = backend("b").await;
	let port = rule(
		&h,
		json!({
			"routes": [
				{"name": "three", "match": "PathPrefix(`/r3/`)", "service": "s", "middlewares": ["strip", "r3"]},
				{"name": "conn", "match": "PathPrefix(`/plain/`)", "service": "s", "middlewares": ["strip", "plain"]},
			],
			"services": {"s": {"servers": [{"url": format!("http://{b}")}]}},
			"middlewares": {
				"strip": {"strip_prefix": {"prefixes": ["/r3", "/plain"]}},
				"r3": {"retry": {"attempts": 3, "status": ["500", "502-504"], "initial_interval": "10ms"}},
				"plain": {"retry": {"attempts": 3, "initial_interval": "10ms"}},
			},
		}),
	)
	.await;
	let base = format!("http://127.0.0.1:{port}");
	assert_eq!(send(client().get(format!("{base}/r3/fail/a/2/500"))).await.0, 200, "succeeds on the third attempt, sent to the only server again (#238)");
	assert_eq!(send(client().get(format!("{base}/r3/fail/b/3/503"))).await.0, 503, "the last attempt's answer");
	assert_eq!(send(client().get(format!("{base}/r3/fail/c/1/501"))).await.0, 501, "501 is not retried");
	assert_eq!(send(client().get(format!("{base}/plain/fail/d/1/500"))).await.0, 500, "without status, 5xx answers are not retried");
	assert_eq!(send(client().post(format!("{base}/r3/fail/e/1/500"))).await.0, 500, "POST is not sent again");
	let count = |key: &str| seen.lock().unwrap().iter().filter(|(p, _)| p.starts_with(&format!("/fail/{key}/"))).count();
	assert_eq!((count("a"), count("b"), count("c"), count("d"), count("e")), (3, 3, 1, 1, 1));
}

#[tokio::test]
async fn mirror_copies_a_share_without_touching_the_response() {
	let h = harness().await;
	let (b, main) = backend("main").await;
	let (m, mirrored) = backend("mirror").await;
	let port = rule(
		&h,
		json!({
			"routes": [
				{"name": "all", "match": "PathPrefix(`/all`)", "service": "s", "middlewares": ["hdr", "copy"]},
				{"name": "part", "match": "PathPrefix(`/part`)", "service": "s", "middlewares": ["copy20"]},
				{"name": "frac", "match": "PathPrefix(`/frac`)", "service": "s", "middlewares": ["half"]},
				{"name": "down", "match": "PathPrefix(`/down`)", "service": "s", "middlewares": ["dead"]},
				{"name": "buf", "match": "PathPrefix(`/buf`)", "service": "s", "middlewares": ["buffer", "copy"]},
			],
			"services": {
				"s": {"servers": [{"url": format!("http://{b}")}]},
				"shadow": {"servers": [{"url": format!("http://{m}")}]},
				"gone": {"servers": [{"url": "http://127.0.0.1:1"}]},
			},
			"middlewares": {
				"hdr": {"headers": {"request": {"set": {"X-Header-Set": "v"}}}},
				"copy": {"mirror": {"service": "shadow"}},
				"copy20": {"mirror": {"service": "shadow", "percent": 20}},
				"half": {"mirror": {"service": "shadow", "fraction": {"numerator": 25, "denominator": 50}}},
				"dead": {"mirror": {"service": "gone"}},
				"buffer": {"buffering": {"max_request_body": 1000}},
			},
		}),
	)
	.await;
	let base = format!("http://127.0.0.1:{port}");
	// with a body, copied as it streams
	let (status, _, v) = send(client().post(format!("{base}/all")).body("hello mirror")).await;
	assert_eq!((status.as_u16(), v["tag"].as_str()), (200, Some("main")));
	let deadline = Instant::now() + Duration::from_secs(3);
	while mirrored.lock().unwrap().is_empty() {
		assert!(Instant::now() < deadline, "the mirror got nothing");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	{
		let got = mirrored.lock().unwrap();
		assert_eq!(got[0].0, "/all");
		assert_eq!(got[0].1["x-header-set"], ["v"], "the copy is taken after the middlewares before it");
	}
	for _ in 0..100 {
		assert_eq!(send(client().get(format!("{base}/part"))).await.0, 200);
	}
	for _ in 0..100 {
		assert_eq!(send(client().get(format!("{base}/frac"))).await.0, 200);
	}
	tokio::time::sleep(Duration::from_millis(300)).await;
	let count = |p: &str| mirrored.lock().unwrap().iter().filter(|(path, _)| path == p).count();
	assert!((15..=25).contains(&count("/part")), "{}", count("/part"));
	assert!((45..=55).contains(&count("/frac")), "{}", count("/frac"));
	assert_eq!(main.lock().unwrap().iter().filter(|(p, _)| p == "/part").count(), 100);
	// a mirror that cannot be reached changes nothing for the client
	assert_eq!(send(client().get(format!("{base}/down"))).await.0, 200);
	// a body read by buffering reaches the mirror too
	assert_eq!(send(client().put(format!("{base}/buf")).body("buffered")).await.0, 200);
	let deadline = Instant::now() + Duration::from_secs(3);
	while count("/buf") == 0 {
		assert!(Instant::now() < deadline, "the buffered request was not mirrored");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	assert_eq!(mirrored.lock().unwrap().iter().find(|(p, _)| p == "/buf").unwrap().1["content-length"], ["8"]);

	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "to": "http://127.0.0.1:1", "middlewares": ["m"]}],
			"middlewares": {"m": {"mirror": {"service": "nope"}}}}}))
		.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn status_servers_answer_their_share() {
	let h = harness().await;
	let (b, _) = backend("b").await;
	let port = rule(
		&h,
		json!({
			"routes": [
				{"name": "mixed", "match": "PathPrefix(`/m`)", "service": "mixed"},
				{"name": "none", "match": "PathPrefix(`/n`)", "service": "none"},
			],
			"services": {
				"mixed": {"servers": [{"url": format!("http://{b}"), "weight": 1}, {"status": 500, "weight": 1}]},
				"none": {"servers": [{"status": 500}]},
			},
		}),
	)
	.await;
	let mut codes = HashMap::new();
	for _ in 0..20 {
		*codes.entry(send(client().get(format!("http://127.0.0.1:{port}/m"))).await.0.as_u16()).or_insert(0) += 1;
	}
	assert_eq!((codes[&200], codes[&500]), (10, 10), "{codes:?}");
	assert_eq!(send(client().get(format!("http://127.0.0.1:{port}/n"))).await.0, 500);

	for bad in [json!({"url": "http://127.0.0.1:1", "status": 500}), json!({}), json!({"status": 99})] {
		let (status, v) = h
			.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "s"}], "services": {"s": {"servers": [bad]}}}}))
			.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	}
}

#[tokio::test]
async fn capabilities_list_the_gateway_features() {
	let h = harness().await;
	let (_, v) = h.get("/capabilities").await;
	let f = &v["features"];
	for m in ["cors", "mirror", "replace_host"] {
		assert!(f["middlewares"].as_array().unwrap().iter().any(|x| x == m), "{m}: {f}");
	}
	for s in ["protocol", "tls"] {
		assert!(f["services"].as_array().unwrap().iter().any(|x| x == s), "{s}: {f}");
	}
	assert_eq!(
		f["http_options"],
		json!(["headers_add", "redirect_status", "route_timeouts", "server_middlewares", "server_status", "retry_status", "misdirected"])
	);
	assert_eq!(f["tls_route_targets"], true);
}

/// An HTTPS request (HTTP/1.1) with an optional client certificate; the backend's JSON.
async fn tls_get(pki: &common::pki::Pki, port: u16, client: Option<&common::pki::Issued>, extra: &str) -> Value {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut s = pki.connector_alpn(client, &["http/1.1"]).connect("a.test".to_string().try_into().unwrap(), tcp).await.unwrap();
	s.write_all(format!("GET /x HTTP/1.1\r\nHost: a.test\r\n{extra}Connection: close\r\n\r\n").as_bytes()).await.unwrap();
	let mut out = vec![];
	let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
	let text = String::from_utf8_lossy(&out);
	let body = &text[text.find('{').expect(&text)..=text.rfind('}').unwrap()];
	serde_json::from_str(body).unwrap()
}

#[tokio::test]
async fn client_certificates_are_told_to_the_backend() {
	// #238: optional_no_verify (AllowInsecureFallback) lets everyone in and says what it saw
	let pki = common::pki::Pki::new("gw-xfcc");
	let cert = pki.server("front", &["a.test"]);
	let alice = pki.client("alice", "alice");
	let other = common::pki::Pki::new("gw-xfcc-other");
	let mallory = other.client("mallory", "mallory");
	let h = harness().await;
	let (b, _) = backend("b").await;
	let (auth, auth_seen) = backend("auth").await;
	let (shadow, shadow_seen) = backend("shadow").await;
	let port = free_port();
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"tls": {"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}],
				"client_auth": {"mode": "optional_no_verify", "ca_file": pki.ca_file}},
			"http": {
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "b", "middlewares": ["fa", "copy"]}],
				"services": {"b": {"servers": [{"url": format!("http://{b}")}]}, "shadow": {"servers": [{"url": format!("http://{shadow}")}]}},
				"middlewares": {"fa": {"forward_auth": {"address": format!("http://{auth}/check")}}, "copy": {"mirror": {"service": "shadow"}}},
			}}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	let v = tls_get(&pki, port, Some(&alice), "X-Client-Verify: SUCCESS\r\nX-Forwarded-Client-Cert: Hash=forged\r\n").await;
	assert_eq!(header(&v, "x-client-verify"), ["SUCCESS"]);
	let xfcc = header(&v, "x-forwarded-client-cert");
	assert_eq!(xfcc.len(), 1);
	assert!(xfcc[0].starts_with("Hash=") && xfcc[0].contains("Subject=\"CN=alice\"") && !xfcc[0].contains("forged"), "{xfcc:?}");
	// the auth server and the mirror see what rproxy saw, never the client's claim
	let auth_got = auth_seen.lock().unwrap().last().unwrap().1.clone();
	assert_eq!(auth_got["x-client-verify"], ["SUCCESS"]);
	assert!(!auth_got["x-forwarded-client-cert"][0].contains("forged"));
	let deadline = Instant::now() + Duration::from_secs(3);
	while shadow_seen.lock().unwrap().is_empty() {
		assert!(Instant::now() < deadline, "no mirror copy");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	let copy = shadow_seen.lock().unwrap()[0].1.clone();
	assert_eq!((copy["x-client-verify"].clone(), copy["x-forwarded-for"].clone()), (vec!["SUCCESS".to_string()], vec!["127.0.0.1".to_string()]));
	assert_eq!(copy["x-forwarded-client-cert"], xfcc.iter().map(|s| s.to_string()).collect::<Vec<_>>());
	let v = tls_get(&pki, port, Some(&mallory), "").await;
	assert_eq!(header(&v, "x-client-verify"), ["FAILED"], "another CA's certificate gets in, marked");
	let xfcc = header(&v, "x-forwarded-client-cert");
	assert!(xfcc[0].starts_with("Hash=") && !xfcc[0].contains("mallory"), "no subject of a certificate that did not verify: {xfcc:?}");
	let v = tls_get(&pki, port, None, "X-Client-Verify: SUCCESS\r\n").await;
	assert_eq!(header(&v, "x-client-verify"), ["NONE"], "a forged header is replaced");
	assert!(header(&v, "x-forwarded-client-cert").is_empty());
}

#[tokio::test]
async fn client_certificate_headers_cannot_be_forged_where_no_client_auth_applies() {
	// security review H1 / M5: plain HTTP rules, forward_auth, mirror and upgrades drop them too
	let h = harness().await;
	let (b, main_seen) = backend("b").await;
	let (auth, auth_seen) = backend("auth").await;
	let (shadow, shadow_seen) = backend("shadow").await;
	let port = rule(
		&h,
		json!({
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "b", "middlewares": ["fa", "copy"]}],
			"services": {"b": {"servers": [{"url": format!("http://{b}")}]}, "shadow": {"servers": [{"url": format!("http://{shadow}")}]}},
			"middlewares": {"fa": {"forward_auth": {"address": format!("http://{auth}/check")}}, "copy": {"mirror": {"service": "shadow"}}},
		}),
	)
	.await;
	let forged = "X-Client-Verify: SUCCESS\r\nX-Forwarded-Client-Cert: Hash=00;Subject=\"CN=admin\"\r\nX-Forwarded-For: 6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\n";
	for upgrade in ["", "Connection: Upgrade\r\nUpgrade: websocket\r\n"] {
		let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
		s.write_all(format!("GET /x HTTP/1.1\r\nHost: a.test\r\n{forged}{upgrade}Connection: close\r\n\r\n").as_bytes()).await.unwrap();
		let mut out = vec![];
		let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
	}
	let deadline = Instant::now() + Duration::from_secs(3);
	while shadow_seen.lock().unwrap().len() < 2 {
		assert!(Instant::now() < deadline, "mirror copies missing");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	for (who, seen) in [("backend", &main_seen), ("forward_auth", &auth_seen), ("mirror", &shadow_seen)] {
		let seen = seen.lock().unwrap();
		assert_eq!(seen.len(), 2, "{who}");
		for (_, headers) in seen.iter() {
			assert!(!headers.contains_key("x-client-verify") && !headers.contains_key("x-forwarded-client-cert"), "{who}: {headers:?}");
			if who != "forward_auth" {
				assert_eq!(headers["x-forwarded-for"], ["127.0.0.1"], "{who}: the forged chain is replaced");
				assert_eq!(headers["x-real-ip"], ["127.0.0.1"], "{who}");
			}
		}
	}
}

/// Statuses of requests for `hosts` sent on one HTTP/2 connection made for `sni`
/// (connection coalescing, as browsers do for names of one certificate).
async fn h2_statuses(pki: &common::pki::Pki, port: u16, sni: &str, hosts: &[&str]) -> Vec<u16> {
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let tls = pki.connector_alpn(None, &["h2"]).connect(sni.to_string().try_into().unwrap(), tcp).await.unwrap();
	let (mut send, conn) =
		hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), hyper_util::rt::TokioIo::new(tls)).await.unwrap();
	tokio::spawn(conn);
	let mut out = vec![];
	for host in hosts {
		let req = hyper::Request::get(format!("https://{host}/x")).body(http_body_util::Empty::<Bytes>::new()).unwrap();
		out.push(send.send_request(req).await.unwrap().status().as_u16());
	}
	out
}

#[tokio::test]
async fn misdirected_requests_get_421() {
	// tls.misdirected (v0.4.3): the Gateway API's HTTPS listeners on one port; a request on a
	// connection made for another listener's name gets 421 (HTTPRouteHTTPSListenerDetectMisdirectedRequests)
	let pki = common::pki::Pki::new("gw-421");
	let cert = pki.server("front", &["a.test", "b.test", "*.w.test", "x.w.test", "c.test"]);
	let h = harness().await;
	let (b, _) = backend("b").await;
	let port = free_port();
	let tls = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}],
		"misdirected": {"groups": [["*"], ["b.test"], ["**.w.test"], ["x.w.test"]]}});
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "tls": tls,
			"http": {
				"routes": [{"name": "r", "match": "!Host(`c.test`)", "service": "b"}],
				"services": {"b": {"servers": [{"url": format!("http://{b}")}]}},
			}}))
		.await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	// the catch-all listener: its own names and unknown ones are routed (c.test: no route, 404)
	assert_eq!(h2_statuses(&pki, port, "a.test", &["a.test", "b.test", "c.test", "y.w.test"]).await, [200, 421, 404, 421]);
	assert_eq!(h2_statuses(&pki, port, "b.test", &["b.test", "a.test", "c.test"]).await, [200, 421, 421]);
	assert_eq!(h2_statuses(&pki, port, "y.w.test", &["y.w.test", "z.w.test", "x.w.test", "b.test"]).await, [200, 200, 421, 421]);
	assert_eq!(h2_statuses(&pki, port, "x.w.test", &["x.w.test", "y.w.test"]).await, [200, 421]);
	// HTTP/1.1 on a connection for a.test asking for b.test, too
	let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut s = pki.connector_alpn(None, &["http/1.1"]).connect("a.test".to_string().try_into().unwrap(), tcp).await.unwrap();
	s.write_all(b"GET /x HTTP/1.1\r\nHost: b.test\r\nConnection: close\r\n\r\n").await.unwrap();
	let mut out = vec![];
	let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
	assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 421"), "{}", String::from_utf8_lossy(&out));
	// the rule's view keeps the setting; it needs http and terminate
	let (_, view) = h.get(&format!("/rules/tcp/127.0.0.1/{port}")).await;
	assert_eq!(view["tls"]["misdirected"]["groups"][1], json!(["b.test"]), "{view}");
	let (status, v) = h
		.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "remote_addr": "127.0.0.1", "remote_port": 1,
			"tls": tls}))
		.await;
	assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
	assert!(v["error"].as_str().unwrap().contains("needs http"), "{v}");
}

#[tokio::test]
async fn per_server_cors_redirects_and_mirrors() {
	// v0.4.3: the Gateway API's CORS, RequestRedirect and RequestMirror filters on a backendRef
	let h = harness().await;
	let (v1, seen1) = backend("v1").await;
	let (v2, seen2) = backend("v2").await;
	let (m, mirrored) = backend("mirror").await;
	let port = rule(
		&h,
		json!({
			"routes": [{"name": "w", "match": "PathPrefix(`/`)", "service": "pair"}],
			"services": {
				"pair": {"servers": [
					{"url": format!("http://{v1}"), "middlewares": ["cors", "copy", "b1"]},
					{"url": format!("http://{v2}"), "middlewares": ["redir"]},
				]},
				"shadow": {"servers": [{"url": format!("http://{m}")}]},
			},
			"middlewares": {
				"cors": {"cors": {"allow_origins": ["https://www.foo.com"], "allow_methods": ["GET"]}},
				"copy": {"mirror": {"service": "shadow"}},
				"b1": {"headers": {"request": {"set": {"Backend": "v1"}}}},
				"redir": {"redirect_regex": {"regex": "^http://([^/:]+)(:\\d+)?/(.*)$", "replacement": "https://$1/$3", "status": 302}},
			},
		}),
	)
	.await;
	let base = format!("http://127.0.0.1:{port}");
	let (mut statuses, mut cors, mut redirects) = (vec![], 0, 0);
	for i in 0..10 {
		let (status, headers, v) =
			send(client().post(format!("{base}/p{i}")).header("origin", "https://www.foo.com").header("host", "app.example").body("hello")).await;
		statuses.push(status.as_u16());
		if status == 200 {
			assert_eq!(v["tag"], "v1");
			assert_eq!(headers["access-control-allow-origin"], "https://www.foo.com", "the server's cors marks its responses");
			cors += 1;
		} else {
			assert_eq!(status, 302);
			assert_eq!(headers["location"], format!("https://app.example/p{i}"), "the other server's redirect");
			assert!(!headers.contains_key("access-control-allow-origin"));
			redirects += 1;
		}
	}
	assert_eq!((cors, redirects), (5, 5), "{statuses:?}");
	assert!(seen2.lock().unwrap().is_empty(), "the redirecting server gets nothing");
	// copies of the requests sent to v1 only, with the headers up to the copy, sent once
	let deadline = Instant::now() + Duration::from_secs(3);
	while mirrored.lock().unwrap().len() < 5 {
		assert!(Instant::now() < deadline, "the mirror got {}", mirrored.lock().unwrap().len());
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
	tokio::time::sleep(Duration::from_millis(200)).await;
	{
		let got = mirrored.lock().unwrap();
		assert_eq!(got.len(), 5);
		let sent: Vec<String> = seen1.lock().unwrap().iter().map(|(p, _)| p.clone()).collect();
		for (path, headers) in got.iter() {
			assert!(sent.contains(path), "{path} was copied but not sent to v1: {sent:?}");
			assert_eq!(headers["host"], ["app.example"]);
			assert_eq!(headers["x-forwarded-for"], ["127.0.0.1"], "X-Forwarded-For once");
			assert_eq!(headers["content-length"], ["5"]);
			assert!(!headers.contains_key("backend"), "the copy is taken before the later middlewares");
		}
	}
	// a preflight that reaches the cors server is answered there
	let before = seen1.lock().unwrap().len();
	let mut answered = 0;
	for _ in 0..4 {
		let (status, headers, _) = send(
			client()
				.request(reqwest::Method::OPTIONS, format!("{base}/pre"))
				.header("origin", "https://www.foo.com")
				.header("access-control-request-method", "GET"),
		)
		.await;
		if status == 204 {
			assert_eq!(headers["access-control-allow-methods"], "GET");
			answered += 1;
		}
	}
	assert_eq!(answered, 2, "half of the preflights go to the cors server");
	assert_eq!(seen1.lock().unwrap().len(), before, "answered without the backend");

	// a server may not copy to a service whose servers copy again; other kinds stay refused
	for (mws, services, want) in [
		(
			json!({"copy": {"mirror": {"service": "shadow"}}, "again": {"mirror": {"service": "s"}}}),
			json!({"s": {"servers": [{"url": "http://127.0.0.1:1", "middlewares": ["copy"]}]},
				"shadow": {"servers": [{"url": "http://127.0.0.1:2", "middlewares": ["again"]}]}}),
			"copy requests themselves",
		),
		(
			json!({"rl": {"rate_limit": {"average": 1}}}),
			json!({"s": {"servers": [{"url": "http://127.0.0.1:1", "middlewares": ["rl"]}]}}),
			"cannot run per server",
		),
	] {
		let (status, v) = h
			.post(json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
				"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "s"}], "services": services, "middlewares": mws}}))
			.await;
		assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
		assert!(v["error"].as_str().unwrap().contains(want), "{v}");
	}
	let (_, caps) = h.get("/capabilities").await;
	for k in ["cors", "redirect_regex", "redirect_scheme", "mirror", "headers"] {
		assert!(caps["features"]["server_middleware_kinds"].as_array().unwrap().iter().any(|x| x == k), "{k}: {caps}");
	}
}
