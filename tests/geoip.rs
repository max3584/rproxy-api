//! GeoIP (#168): the country / ASN lists of a rule (L4, TCP and UDP) and of
//! the `geoip` middleware (L7), with small mmdb files made by the test
//! (`common::mmdb`; no MaxMind database is used or committed). Loopback
//! clients: 127.0.0.1 is "JP", 127.0.0.2 is "US" in AS64496, 127.0.0.3 is
//! not in the databases.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use reqwest::StatusCode;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

use common::*;
use rproxy_api::l7::access::HttpGlobal;
use rproxy_api::net::geoip::{Geoip, GeoipGlobal};

fn country_db() -> Vec<u8> {
	mmdb::build("GeoLite2-Country", &[("127.0.0.1", mmdb::country("JP")), ("127.0.0.2", mmdb::country("US")), ("192.0.2.0/24", mmdb::country("FR"))])
}

fn asn_db() -> Vec<u8> {
	mmdb::build("GeoLite2-ASN", &[("127.0.0.2", mmdb::asn(64496, "Example Net"))])
}

fn geoip(log_country: bool) -> Arc<Geoip> {
	let spec = GeoipGlobal {
		country_db: Some("country.mmdb".into()),
		asn_db: Some("asn.mmdb".into()),
		check_interval: Some("0s".into()),
		log_country,
	};
	Geoip::from_bytes(spec, Some(country_db()), Some(asn_db())).unwrap()
}

async fn harness_geo(global: HttpGlobal) -> Harness {
	harness_with_global(rproxy_api::control::auth::Tokens::disabled(), global).await
}

/// A TCP connection to `port` from `from` (127.0.0.x).
async fn connect_from(from: &str, port: u16) -> TcpStream {
	let socket = TcpSocket::new_v4().unwrap();
	socket.bind(format!("{from}:0").parse().unwrap()).unwrap();
	socket.connect(SocketAddr::from(([127, 0, 0, 1], port))).await.unwrap()
}

/// Whether a connection from `from` is relayed (the echo answers) or closed at once.
async fn relayed(from: &str, port: u16) -> bool {
	let mut s = connect_from(from, port).await;
	if s.write_all(b"x").await.is_err() {
		return false;
	}
	let mut buf = [0u8; 64];
	matches!(tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await, Ok(Ok(n)) if n > 0)
}

#[tokio::test]
async fn tcp_rules_refuse_by_country_and_asn() {
	logs::capture();
	let h = harness_geo(HttpGlobal::default().with_geoip(Some(geoip(true)))).await;
	let backend = tcp_backend("G:").await;
	let port = free_port();
	let mut body = rule("tcp", port, backend);
	body["geoip"] = json!({"allow_countries": ["JP"]});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	assert_eq!(v["geoip"], json!({"allow_countries": ["JP"]}));

	assert!(relayed("127.0.0.1", port).await, "JP is allowed");
	let open = logs::wait_for("conn.open with the country", |l| {
		l["event"] == "conn.open" && l["rule"] == format!("tcp/127.0.0.1:{port}")
	})
	.await;
	assert_eq!(open["country"], "JP", "log_country: {open}");
	assert!(!relayed("127.0.0.2", port).await, "US is not");
	assert!(relayed("127.0.0.3", port).await, "unknown: allowed by default");
	let denied = logs::wait_for("conn.denied", |l| l["event"] == "conn.denied" && l["rule"] == format!("tcp/127.0.0.1:{port}")).await;
	assert_eq!((&denied["reason"], &denied["country"], &denied["asn"]), (&json!("geoip"), &json!("US"), &json!(64496)), "{denied}");
	let path = format!("/rules/tcp/127.0.0.1/{port}");
	let v = wait_for(&h, &path, |v| v["stats"]["denied"] == 1).await;
	assert_eq!(v["stats"]["denied"], 1);

	// PATCH replaces the lists without closing anything; {} removes them
	let target = json!({"remote_addr": "127.0.0.1", "remote_port": backend.port()});
	let mut patch = target.clone();
	patch["geoip"] = json!({"deny_asns": [64496]});
	assert_eq!(h.patch(&format!("tcp/127.0.0.1/{port}"), patch.clone()).await.0, StatusCode::OK);
	assert!(!relayed("127.0.0.2", port).await, "AS64496 is refused");
	assert!(relayed("127.0.0.1", port).await, "no ASN known: unknown, allowed by default");
	patch["geoip"]["unknown"] = json!("deny");
	assert_eq!(h.patch(&format!("tcp/127.0.0.1/{port}"), patch).await.0, StatusCode::OK);
	assert!(!relayed("127.0.0.1", port).await, "unknown: deny");
	let mut clear = target;
	clear["geoip"] = json!({});
	let (status, v) = h.patch(&format!("tcp/127.0.0.1/{port}"), clear).await;
	assert_eq!(status, StatusCode::OK);
	assert!(v.get("geoip").is_none(), "{v}");
	assert!(relayed("127.0.0.2", port).await);
}

#[tokio::test]
async fn udp_rules_drop_datagrams_by_country() {
	let h = harness_geo(HttpGlobal::default().with_geoip(Some(geoip(false)))).await;
	let backend = udp_backend("U:").await;
	let port = free_udp_port();
	let mut body = rule("udp", port, backend);
	body["geoip"] = json!({"deny_countries": ["US"]});
	assert_eq!(h.post(body).await.0, StatusCode::CREATED);

	let jp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
	jp.connect(("127.0.0.1", port)).await.unwrap();
	assert_eq!(udp_roundtrip(&jp, "hi").await, "U:hi");
	let us = UdpSocket::bind("127.0.0.2:0").await.unwrap();
	us.connect(("127.0.0.1", port)).await.unwrap();
	us.send(b"hi").await.unwrap();
	let mut buf = [0u8; 64];
	assert!(tokio::time::timeout(Duration::from_millis(500), us.recv(&mut buf)).await.is_err(), "dropped");
	let v = wait_for(&h, &format!("/rules/udp/127.0.0.1/{port}"), |v| v["stats"]["denied"] == 1).await;
	assert_eq!(v["stats"]["total_connections"], 1, "no session for the refused client");
}

#[tokio::test]
async fn lists_need_the_databases() {
	let h = harness().await;
	let backend = tcp_backend("N:").await;
	let mut body = rule("tcp", free_port(), backend);
	body["geoip"] = json!({"allow_countries": ["JP"]});
	let (status, v) = h.post(body.clone()).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("invalid")), "{v}");
	assert!(v["error"].as_str().unwrap().contains("country_db"), "{v}");
	body["geoip"] = json!({"allow_countries": ["japan"]});
	assert_eq!(h.post(body).await.1["code"], "invalid");

	// only a country database: ASN lists are refused
	let spec = GeoipGlobal { country_db: Some("c.mmdb".into()), ..Default::default() };
	let only_country = Geoip::from_bytes(spec, Some(country_db()), None).unwrap();
	let h = harness_geo(HttpGlobal::default().with_geoip(Some(only_country))).await;
	let mut body = rule("tcp", free_port(), backend);
	body["geoip"] = json!({"deny_asns": [64496]});
	let (_, v) = h.post(body).await;
	assert!(v["error"].as_str().unwrap_or("").contains("asn_db"), "{v}");
	let mw = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": free_port(), "http": {
		"routes": [{"name": "a", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["geo"]}],
		"middlewares": {"geo": {"geoip": {"allow_asns": [64496]}}}
	}});
	let (_, v) = h.post(mw).await;
	assert!(v["error"].as_str().unwrap_or("").contains("asn_db"), "{v}");
}

/// An HTTP backend that answers 200 "ok".
async fn http_backend() -> SocketAddr {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let app = axum::Router::new().fallback(|| async { "ok" });
	tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
	addr
}

async fn get_from(from: &str, port: u16, xff: Option<&str>) -> StatusCode {
	let client = reqwest::Client::builder().local_address(from.parse::<std::net::IpAddr>().unwrap()).build().unwrap();
	let mut req = client.get(format!("http://127.0.0.1:{port}/"));
	if let Some(x) = xff {
		req = req.header("x-forwarded-for", x);
	}
	req.send().await.unwrap().status()
}

#[tokio::test]
async fn the_middleware_answers_403_for_the_client_trusted_proxies_name() {
	logs::capture();
	let global = HttpGlobal::new(&["127.0.0.3/32".to_string()], None, 1).unwrap().with_geoip(Some(geoip(true)));
	let h = harness_geo(global).await;
	let backend = http_backend().await;
	let port = free_port();
	let body = json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port, "http": {
		"routes": [{"name": "web", "match": "PathPrefix(`/`)", "to": format!("http://{backend}"), "middlewares": ["geo"]}],
		"middlewares": {"geo": {"geoip": {"deny_countries": ["US", "FR"]}}}
	}});
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");

	assert_eq!(get_from("127.0.0.1", port, None).await, StatusCode::OK);
	assert_eq!(get_from("127.0.0.2", port, None).await, StatusCode::FORBIDDEN);
	// behind a trusted proxy, the client it names counts (192.0.2.1 is FR)
	assert_eq!(get_from("127.0.0.3", port, Some("192.0.2.1")).await, StatusCode::FORBIDDEN);
	assert_eq!(get_from("127.0.0.3", port, None).await, StatusCode::OK, "the proxy itself is unknown: allowed");
	// an untrusted peer's X-Forwarded-For is not believed
	assert_eq!(get_from("127.0.0.1", port, Some("192.0.2.1")).await, StatusCode::OK);

	let rule = format!("tcp/127.0.0.1:{port}");
	let refused = logs::wait_for("http.access refused by geoip", |l| {
		l["event"] == "http.access" && l["rule"] == rule && l["refused_by"] == "geoip" && l["client"] == "127.0.0.2"
	})
	.await;
	assert_eq!((&refused["status"], &refused["middleware"], &refused["country"], &refused["asn"]),
		(&json!(403), &json!("geo"), &json!("US"), &json!(64496)), "{refused}");
	let passed = logs::wait_for("http.access with the country", |l| {
		l["event"] == "http.access" && l["rule"] == rule && l["client"] == "127.0.0.1"
	})
	.await;
	assert_eq!(passed["country"], "JP", "log_country: {passed}");
}

/// Runs the binary in `dir` without the repository's .env; (exit code, output).
fn run(dir: &Path, args: &[&str]) -> (i32, String) {
	let out = Command::new(env!("CARGO_BIN_EXE_rproxy-api")).current_dir(dir).env_clear().args(args).output().unwrap();
	let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
	(out.status.code().unwrap_or(-1), text)
}

/// The settings file: the databases are read by `--check-config` as at startup.
#[test]
fn check_config_reads_the_databases() {
	let dir = std::env::temp_dir().join(format!("rproxy-geoip-check-{}", std::process::id()));
	let _ = std::fs::remove_dir_all(&dir);
	std::fs::create_dir_all(&dir).unwrap();
	let country = dir.join("country.mmdb");
	std::fs::write(&country, country_db()).unwrap();
	let file = dir.join("rproxy.yaml");
	let doc = |db: &Path| {
		format!(
			"version: 1\nglobal:\n  geoip: {{country_db: {}, log_country: true}}\nrules:\n  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: 1, remote_addr: 127.0.0.1, remote_port: 9, geoip: {{allow_countries: [JP]}}}}\n",
			db.display()
		)
	};
	std::fs::write(&file, doc(&country)).unwrap();
	let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap(), "--check-config-format", "json"]);
	let v: Value = serde_json::from_str(&out).unwrap_or_else(|e| panic!("{e}: {out}"));
	assert_eq!((exit, &v["errors"]), (0, &json!([])), "{v}");
	assert!(!v["warnings"].to_string().contains("global.geoip"), "geoip is applied: {v}");

	std::fs::write(&file, doc(&dir.join("missing.mmdb"))).unwrap();
	let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap()]);
	assert!(exit == 1 && out.contains("missing.mmdb"), "{out}");
	let garbage = dir.join("garbage.mmdb");
	std::fs::write(&garbage, b"no").unwrap();
	std::fs::write(&file, doc(&garbage)).unwrap();
	let (exit, out) = run(&dir, &["--check-config", file.to_str().unwrap()]);
	assert!(exit == 1 && out.contains("not a MaxMind database"), "{out}");
	std::fs::remove_dir_all(dir).unwrap();
}
