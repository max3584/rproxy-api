//! Rule sets, labels, conditions and readiness for a Kubernetes controller
//! (#28, docs/DESIGN-v0.4.md 3.): `PUT /rulesets/{name}` applies a whole set
//! (validated first, changed in place where possible), its rules are owned by
//! the set, and `GET /readyz` answers without a token.

mod common;

use std::fs;

use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use tokio::net::TcpStream;

use common::*;

async fn send(h: &Harness, method: Method, path: &str, body: Option<Value>, if_match: Option<&str>) -> (StatusCode, Value, Option<String>) {
	let mut req = h.http.request(method, format!("{}{path}", h.base));
	if let Some(b) = body {
		req = req.json(&b);
	}
	if let Some(etag) = if_match {
		req = req.header("If-Match", etag);
	}
	let r = req.send().await.unwrap();
	let status = r.status();
	let etag = r.headers().get("etag").map(|v| v.to_str().unwrap().to_string());
	(status, r.json().await.unwrap_or(Value::Null), etag)
}

async fn put(h: &Harness, name: &str, body: Value) -> (StatusCode, Value, Option<String>) {
	send(h, Method::PUT, &format!("/rulesets/{name}"), Some(body), None).await
}

fn actions(applied: &Value) -> Vec<(String, String, String)> {
	applied["results"]
		.as_array()
		.unwrap()
		.iter()
		.map(|r| (r["rule"].as_str().unwrap().to_string(), r["action"].as_str().unwrap().to_string(), r["change"].as_str().unwrap().to_string()))
		.collect()
}

fn condition<'a>(rule: &'a Value, kind: &str) -> &'a Value {
	rule["conditions"].as_array().unwrap().iter().find(|c| c["type"] == kind).unwrap_or_else(|| panic!("{kind}: {rule}"))
}

#[tokio::test]
async fn capabilities_turn_the_controller_features_on() {
	let h = harness().await;
	let (_, caps) = h.get("/capabilities").await;
	for flag in ["rulesets", "labels", "conditions", "readyz"] {
		assert_eq!(caps["features"][flag], true, "{flag}: {caps}");
	}
}

/// A set is created, re-applied unchanged, changed in place (connections
/// kept), changed in a way that re-creates a listener, shrunk, and deleted.
#[tokio::test]
async fn a_set_is_applied_as_a_whole_with_minimal_disruption() {
	let h = harness().await;
	let (a, b) = (tcp_backend("A:").await, tcp_backend("B:").await);
	let (p1, p2, p3) = (free_port(), free_port(), free_port());
	let name = "k8s/default/web-gateway";
	let mut r1 = rule("tcp", p1, a);
	r1["labels"] = json!({"gateway.networking.k8s.io/gateway-name": "web"});
	let set = json!({"generation": 1, "rules": [r1, rule("tcp", p2, a)]});

	let (status, applied, etag) = put(&h, name, set.clone()).await;
	assert_eq!(status, StatusCode::OK, "{applied}");
	assert_eq!((applied["name"].as_str(), applied["generation"].as_u64(), applied["dry_run"].as_bool()), (Some(name), Some(1), Some(false)));
	let tag = applied["etag"].as_str().unwrap().to_string();
	assert!(tag.starts_with("g1-") && tag.len() == 3 + 16, "{tag}");
	assert_eq!(etag.as_deref(), Some(format!("\"{tag}\"").as_str()), "ETag header");
	assert_eq!(
		actions(&applied),
		[(format!("tcp/127.0.0.1:{p1}"), "create".into(), "none".into()), (format!("tcp/127.0.0.1:{p2}"), "create".into(), "none".into())]
	);
	assert!(applied["results"].as_array().unwrap().iter().all(|r| r["state"] == "running"), "{applied}");

	// the rules carry the set, their labels and conditions
	let (_, rules) = h.get("/rules").await;
	let first = rules.as_array().unwrap().iter().find(|r| r["listen_port"] == p1).unwrap();
	assert_eq!(first["ruleset"], name);
	assert_eq!(first["labels"]["gateway.networking.k8s.io/gateway-name"], "web");
	for kind in ["Accepted", "Programmed", "ResolvedRefs", "BackendsHealthy"] {
		assert_eq!(condition(first, kind)["status"], "True", "{kind}: {first}");
	}
	assert_eq!(condition(first, "Programmed")["reason"], "Listening");
	let (_, list) = h.get("/rulesets").await;
	assert_eq!(list[0]["name"], name);
	assert_eq!((list[0]["rules"].as_u64(), list[0]["generation"].as_u64()), (Some(2), Some(1)));
	assert_eq!(list[0]["etag"], tag.as_str());
	assert_eq!(list[0]["updated_by"], "", "the token's name (none without a token file)");
	let (status, one, header) = send(&h, Method::GET, &format!("/rulesets/{name}"), None, None).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!((one["etag"].as_str(), one["rules"].as_array().unwrap().len()), (Some(tag.as_str()), 2));
	assert_eq!(header.as_deref(), Some(format!("\"{tag}\"").as_str()));
	let mut conn = TcpStream::connect(("127.0.0.1", p1)).await.unwrap();
	assert_eq!(roundtrip(&mut conn, "x").await, "A:x");

	// the same set again changes nothing (and keeps the etag)
	let (status, again, _) = put(&h, name, set.clone()).await;
	assert_eq!(status, StatusCode::OK);
	assert!(actions(&again).iter().all(|(_, a, c)| a == "none" && c == "none"), "{again}");
	assert_eq!(again["etag"], tag.as_str());

	// a new target is changed in place: the open connection stays
	let mut changed = set.clone();
	changed["generation"] = json!(2);
	changed["rules"][0]["remote_port"] = json!(b.port());
	let (status, applied, _) = send(&h, Method::PUT, &format!("/rulesets/{name}"), Some(changed.clone()), Some(&tag)).await;
	assert_eq!(status, StatusCode::OK, "{applied}");
	assert_eq!(actions(&applied)[0], (format!("tcp/127.0.0.1:{p1}"), "update".into(), "in_place".into()));
	assert_eq!(actions(&applied)[1].1, "none");
	assert_eq!(roundtrip(&mut conn, "y").await, "A:y", "the connection made before the change is kept");
	let mut fresh = TcpStream::connect(("127.0.0.1", p1)).await.unwrap();
	assert_eq!(roundtrip(&mut fresh, "z").await, "B:z", "new connections use the new target");
	assert_ne!(applied["etag"], tag.as_str());

	// source_ip cannot change in place: the listener is re-created
	let mut proxied = changed.clone();
	proxied["generation"] = json!(3);
	proxied["rules"][1]["source_ip"] = json!("proxy_v2");
	let (status, applied, _) = put(&h, name, proxied.clone()).await;
	assert_eq!(status, StatusCode::OK, "{applied}");
	assert_eq!(actions(&applied)[1], (format!("tcp/127.0.0.1:{p2}"), "update".into(), "recreate".into()));
	assert_eq!(applied["results"][1]["state"], "running");

	// a rule left out is deleted; a new one created
	let shrunk = json!({"generation": 4, "rules": [proxied["rules"][0], rule("tcp", p3, a)]});
	let (status, applied, _) = put(&h, name, shrunk).await;
	assert_eq!(status, StatusCode::OK, "{applied}");
	let got = actions(&applied);
	assert!(got.contains(&(format!("tcp/127.0.0.1:{p2}"), "delete".into(), "none".into())), "{applied}");
	assert!(got.contains(&(format!("tcp/127.0.0.1:{p3}"), "create".into(), "none".into())), "{applied}");
	assert_eq!(h.get(&format!("/rules/tcp/127.0.0.1/{p2}")).await.0, StatusCode::NOT_FOUND);
	assert_eq!(roundtrip(&mut conn, "w").await, "A:w", "the rule changed in place earlier was not touched");

	// DELETE stops every rule of the set
	let (status, _, _) = send(&h, Method::DELETE, &format!("/rulesets/{name}?drain_secs=0"), None, None).await;
	assert_eq!(status, StatusCode::NO_CONTENT);
	assert_eq!(h.get("/rules").await.1, json!([]));
	assert_eq!(h.get(&format!("/rulesets/{name}")).await.0, StatusCode::NOT_FOUND);
	assert_eq!(h.get("/rulesets").await.1, json!([]));
	assert_eq!(send(&h, Method::DELETE, &format!("/rulesets/{name}"), None, None).await.0, StatusCode::NOT_FOUND);
}

/// If-Match, generations, ownership and conflicts.
#[tokio::test]
async fn sets_refuse_stale_writes_and_do_not_take_other_rules() {
	let h = harness().await;
	let a = tcp_backend("A:").await;
	let (p1, p2, p3) = (free_port(), free_port(), free_port());
	let set = json!({"generation": 5, "rules": [rule("tcp", p1, a)]});
	let (status, applied, _) = put(&h, "team-a", set.clone()).await;
	assert_eq!(status, StatusCode::OK, "{applied}");
	let tag = applied["etag"].as_str().unwrap().to_string();

	// a wrong etag, a set that does not exist yet, an older generation
	let code = |r: &(StatusCode, Value, Option<String>)| (r.0, r.1["code"].as_str().map(str::to_string));
	let r = send(&h, Method::PUT, "/rulesets/team-a", Some(set.clone()), Some("\"g5-0000000000000000\"")).await;
	assert_eq!(code(&r), (StatusCode::PRECONDITION_FAILED, Some("precondition_failed".into())), "{}", r.1);
	let r = send(&h, Method::PUT, "/rulesets/new-set", Some(json!({"generation": 1, "rules": []})), Some("*")).await;
	assert_eq!(code(&r), (StatusCode::PRECONDITION_FAILED, Some("precondition_failed".into())));
	let mut old = set.clone();
	old["generation"] = json!(4);
	let r = put(&h, "team-a", old).await;
	assert_eq!(code(&r), (StatusCode::CONFLICT, Some("stale_generation".into())), "{}", r.1);
	// the etag in the body works unquoted, a list and W/ too
	let r = send(&h, Method::PUT, "/rulesets/team-a", Some(set.clone()), Some(&format!("\"x\", W/\"{tag}\""))).await;
	assert_eq!(r.0, StatusCode::OK, "{}", r.1);
	assert_eq!(send(&h, Method::PUT, "/rulesets/team-a", Some(set.clone()), Some(&tag)).await.0, StatusCode::OK);

	// a rule of the set cannot be changed alone
	let path = format!("tcp/127.0.0.1/{p1}");
	let r = h.patch(&path, json!({"remote_addr": "127.0.0.1", "remote_port": a.port()})).await;
	assert_eq!((r.0, r.1["code"].as_str()), (StatusCode::CONFLICT, Some("owned")), "{}", r.1);
	assert!(r.1["error"].as_str().unwrap().contains("team-a"), "{}", r.1);
	let r = h.http.delete(format!("{}/rules/{path}", h.base)).send().await.unwrap();
	assert_eq!(r.status(), StatusCode::CONFLICT);
	assert_eq!(r.json::<Value>().await.unwrap()["code"], "owned");

	// another set may not take it, nor a rule made by POST
	let r = put(&h, "team-b", json!({"generation": 1, "rules": [rule("tcp", p1, a)]})).await;
	assert_eq!(code(&r), (StatusCode::CONFLICT, Some("owned".into())), "{}", r.1);
	assert_eq!(r.1["errors"][0]["index"], 0);
	assert_eq!(h.post(rule("tcp", p2, a)).await.0, StatusCode::CREATED);
	let r = put(&h, "team-b", json!({"generation": 1, "rules": [rule("tcp", p3, a), rule("tcp", p2, a)]})).await;
	assert_eq!(code(&r), (StatusCode::CONFLICT, Some("already_exists".into())), "{}", r.1);
	assert!(r.1["error"].as_str().unwrap().starts_with("rules[1]"), "{}", r.1);
	assert_eq!(h.get(&format!("/rules/tcp/127.0.0.1/{p3}")).await.0, StatusCode::NOT_FOUND, "nothing of the refused set was started");
	assert_eq!(h.get("/rulesets/team-b").await.0, StatusCode::NOT_FOUND);
	// a rule POSTed at a key of the set is refused
	assert_eq!(h.post(rule("tcp", p1, a)).await.1["code"], "already_exists");

	// an invalid rule changes nothing, and every problem is listed
	let mut wrong = rule("tcp", p3, a);
	wrong["remote_port"] = json!(0);
	let mut unsupported = rule("tcp", free_port(), a);
	unsupported["limits"] = json!({"max_connections": 10});
	let r = put(&h, "team-a", json!({"generation": 6, "rules": [rule("tcp", p1, tcp_backend("C:").await), wrong, unsupported]})).await;
	assert_eq!(code(&r), (StatusCode::BAD_REQUEST, Some("invalid".into())), "{}", r.1);
	assert!(r.1["error"].as_str().unwrap().starts_with("rules[1]: "), "{}", r.1);
	let errors: Vec<(u64, &str)> = r.1["errors"].as_array().unwrap().iter().map(|e| (e["index"].as_u64().unwrap(), e["code"].as_str().unwrap())).collect();
	assert_eq!(errors, [(1, "invalid"), (2, "unsupported")], "{}", r.1);
	let (_, now) = h.get("/rulesets/team-a").await;
	assert_eq!((now["generation"].as_u64(), now["rules"][0]["remote_port"].as_u64()), (Some(5), Some(u64::from(a.port()))), "{now}");
	// overlapping rules within the set
	let mut range = rule("tcp", p3, a);
	range["listen_port_end"] = json!(p3 + 1);
	let r = put(&h, "team-c", json!({"generation": 1, "rules": [range, rule("tcp", p3 + 1, a)]})).await;
	assert_eq!(code(&r), (StatusCode::BAD_REQUEST, Some("invalid".into())), "{}", r.1);

	// DELETE with a wrong If-Match
	let r = send(&h, Method::DELETE, "/rulesets/team-a", None, Some("\"nope\"")).await;
	assert_eq!(r.0, StatusCode::PRECONDITION_FAILED);
	// a dry run (#169; more in tests/plan.rs) answers what would go and changes nothing
	let r = put(&h, "team-a?dry_run=true", json!({"generation": 9, "rules": []})).await;
	assert_eq!((r.0, r.1["dry_run"].as_bool()), (StatusCode::OK, Some(true)), "{}", r.1);
	assert!(actions(&r.1).iter().all(|(_, action, change)| action == "delete" && change == "none"), "{}", r.1);
	assert_eq!(h.get("/rulesets/team-a").await.1["generation"], 5);
	assert_eq!(code(&put(&h, "team-a?dry_run=maybe", set).await).1.as_deref(), Some("invalid"));
	// names
	for bad in ["Bad%20Name", "a/", "-a"] {
		let r = put(&h, bad, json!({"generation": 1, "rules": []})).await;
		assert_eq!(code(&r), (StatusCode::BAD_REQUEST, Some("invalid".into())), "{bad}");
	}
	let r = put(&h, "k8s/web", json!({"rules": []})).await;
	assert_eq!(code(&r).1.as_deref(), Some("invalid"), "generation is required");
}

/// A rule that cannot bind is registered as failed with its conditions; the
/// rest of the set is applied. Once the port is free, PUT starts it.
#[tokio::test]
async fn a_rule_that_cannot_bind_fails_alone() {
	let h = harness().await;
	let a = tcp_backend("A:").await;
	let (p1, p2) = (free_port(), free_port());
	let taken = std::net::TcpListener::bind(("127.0.0.1", p2)).unwrap();
	let set = json!({"generation": 1, "rules": [rule("tcp", p1, a), rule("tcp", p2, a)]});
	let (status, applied, _) = put(&h, "s", set.clone()).await;
	assert_eq!(status, StatusCode::OK, "{applied}");
	assert_eq!(applied["results"][0]["state"], "running");
	assert_eq!(applied["results"][1]["state"], "failed");
	assert!(applied["results"][1]["error"].as_str().unwrap().contains(&p2.to_string()), "{applied}");
	let (_, failed) = h.get(&format!("/rules/tcp/127.0.0.1/{p2}")).await;
	assert_eq!(failed["ruleset"], "s");
	let programmed = condition(&failed, "Programmed");
	assert_eq!((programmed["status"].as_str(), programmed["reason"].as_str()), (Some("False"), Some("BindFailed")), "{failed}");
	assert_eq!(condition(&failed, "Accepted")["status"], "True");
	assert_eq!(condition(&failed, "BackendsHealthy")["status"], "Unknown");
	let since = programmed["last_transition"].as_u64().unwrap();
	assert!(since > 1_700_000_000);
	// read again: the time of the last change stays
	let (_, again) = h.get(&format!("/rules/tcp/127.0.0.1/{p2}")).await;
	assert_eq!(condition(&again, "Programmed")["last_transition"].as_u64(), Some(since));

	drop(taken);
	let (status, applied, _) = put(&h, "s", set).await;
	assert_eq!(status, StatusCode::OK);
	assert_eq!(actions(&applied)[1].1, "update", "a failed rule is started again: {applied}");
	assert_eq!(applied["results"][1]["state"], "running");
	assert_eq!(actions(&applied)[0].1, "none");
}

/// conditions of a rule whose targets are all down.
#[tokio::test]
async fn conditions_report_targets_that_are_down() {
	let h = harness().await;
	let port = free_port();
	let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
	let mut r = rule("tcp", port, dead);
	r["health_check"] = json!({"interval": "100ms", "timeout": "200ms"});
	assert_eq!(h.post(r).await.0, StatusCode::CREATED, "conditions are on rules made by POST too");
	let v = wait_for(&h, &format!("/rules/tcp/127.0.0.1/{port}"), |v| v["all_targets_down"] == true).await;
	let c = condition(&v, "BackendsHealthy");
	assert_eq!((c["status"].as_str(), c["reason"].as_str()), (Some("False"), Some("AllTargetsDown")), "{v}");
	assert!(v.get("ruleset").is_none());
}

/// labels: PATCH replaces them, `{}` removes them, /metrics shows them.
#[tokio::test]
async fn labels_are_kept_replaced_and_exported() {
	let h = harness().await;
	let a = tcp_backend("A:").await;
	let port = free_port();
	let mut body = rule("tcp", port, a);
	body["labels"] = json!({"tenant": "act", "app.kubernetes.io/name": "game"});
	let (status, created) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{created}");
	assert_eq!(created["labels"]["tenant"], "act");
	let metrics = h.http.get(format!("{}/metrics", h.base)).send().await.unwrap().text().await.unwrap();
	let line = format!("rproxy_rule_labels{{rule=\"tcp/127.0.0.1:{port}\",label_app_kubernetes_io_name=\"game\",label_tenant=\"act\"}} 1");
	assert!(metrics.contains(&line), "{metrics}");

	let path = format!("tcp/127.0.0.1/{port}");
	let target = json!({"remote_addr": "127.0.0.1", "remote_port": a.port()});
	let mut patch = target.clone();
	patch["labels"] = json!({"tenant": "other"});
	let (_, v) = h.patch(&path, patch).await;
	assert_eq!(v["labels"], json!({"tenant": "other"}), "replaced as a whole");
	let (_, v) = h.patch(&path, target.clone()).await;
	assert_eq!(v["labels"], json!({"tenant": "other"}), "left out: kept");
	let mut clear = target;
	clear["labels"] = json!({});
	let (_, v) = h.patch(&path, clear).await;
	assert!(v.get("labels").is_none(), "{v}");
	let mut bad = rule("tcp", free_port(), a);
	bad["labels"] = json!({"bad key": "x"});
	assert_eq!(h.post(bad).await.1["code"], "invalid");
}

/// `GET /readyz` needs no token: starting until the restore is done, then
/// ready, draining when the process stops.
#[tokio::test]
async fn readyz_follows_the_startup_and_the_shutdown() {
	let dir = std::env::temp_dir().join(format!("rproxy-readyz-{}", std::process::id()));
	fs::create_dir_all(&dir).unwrap();
	let file = dir.join("tokens.txt");
	fs::write(&file, "secret\n").unwrap();
	let h = harness_with(rproxy_api::control::auth::Tokens::from_file(file).unwrap()).await;
	let readyz = || async { h.http.get(format!("{}/readyz", h.base)).send().await.unwrap() };
	let r = readyz().await;
	assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(r.json::<Value>().await.unwrap(), json!({"ready": false, "reason": "starting"}));
	h.registry.readiness().set_ready();
	let r = readyz().await;
	assert_eq!(r.status(), StatusCode::OK);
	assert_eq!(r.json::<Value>().await.unwrap(), json!({"ready": true}));
	h.registry.readiness().set_draining();
	h.registry.readiness().set_ready();
	let r = readyz().await;
	assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
	assert_eq!(r.json::<Value>().await.unwrap()["reason"], "draining");
	// the rest of the API still needs the token
	assert_eq!(h.http.get(format!("{}/rulesets", h.base)).send().await.unwrap().status(), StatusCode::UNAUTHORIZED);
	fs::remove_dir_all(dir).unwrap();
}

/// Scopes and allow_listen_ports apply to sets.
#[tokio::test]
async fn sets_need_rules_write_within_the_allowed_ports() {
	let dir = std::env::temp_dir().join(format!("rproxy-ruleset-scopes-{}", std::process::id()));
	fs::create_dir_all(&dir).unwrap();
	let file = dir.join("tokens.yaml");
	let sha = |s: &str| {
		use sha2::Digest;
		sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect::<String>()
	};
	let a = tcp_backend("A:").await;
	let port = free_port();
	fs::write(
		&file,
		format!(
			"tokens:\n  - {{name: reader, sha256: {}, scopes: [rules:read]}}\n  - {{name: ctl, sha256: {}, scopes: [rules:write, rules:read], allow_listen_ports: {port}-{port}}}\n",
			sha("reader"),
			sha("ctl")
		),
	)
	.unwrap();
	let h = harness_with(rproxy_api::control::auth::Tokens::from_file(file).unwrap()).await;
	let call = |token: &'static str, method: Method, path: &str, body: Value| {
		h.http.request(method, format!("{}{path}", h.base)).bearer_auth(token).json(&body).send()
	};
	let set = json!({"generation": 1, "rules": [rule("tcp", port, a)]});
	assert_eq!(call("reader", Method::PUT, "/rulesets/a", set.clone()).await.unwrap().status(), StatusCode::FORBIDDEN);
	let r = call("ctl", Method::PUT, "/rulesets/a", set.clone()).await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let mut outside = set.clone();
	outside["rules"][0]["listen_port"] = json!(port - 1);
	let r = call("ctl", Method::PUT, "/rulesets/b", outside).await.unwrap();
	assert_eq!(r.status(), StatusCode::FORBIDDEN);
	let r = call("reader", Method::GET, "/rulesets", json!(null)).await.unwrap();
	assert_eq!(r.status(), StatusCode::OK);
	let list: Value = r.json().await.unwrap();
	assert_eq!((list[0]["name"].as_str(), list[0]["updated_by"].as_str()), (Some("a"), Some("ctl")));
	assert_eq!(call("reader", Method::DELETE, "/rulesets/a", json!(null)).await.unwrap().status(), StatusCode::FORBIDDEN);
	assert_eq!(call("ctl", Method::DELETE, "/rulesets/a", json!(null)).await.unwrap().status(), StatusCode::NO_CONTENT);
	fs::remove_dir_all(dir).unwrap();
}
