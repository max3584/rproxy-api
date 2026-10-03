//! `rproxy-api --check-config` (#140): validates the settings file the way
//! startup and reloads do, opens nothing, and reports through its exit code,
//! text and JSON.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use common::pki::Pki;
use common::*;

fn workdir(tag: &str) -> PathBuf {
	let dir = std::env::temp_dir().join(format!("rproxy-check-{tag}-{}", std::process::id()));
	let _ = fs::remove_dir_all(&dir);
	fs::create_dir_all(&dir).unwrap();
	dir
}

/// Runs the check in `dir` (no .env from the repository); (exit code, stdout).
fn check(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String) {
	let out = Command::new(env!("CARGO_BIN_EXE_rproxy-api"))
		.current_dir(dir)
		.env_clear()
		.envs(env.iter().copied())
		.arg("--check-config")
		.args(args)
		.output()
		.unwrap();
	let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
	(out.status.code().unwrap_or(-1), text)
}

fn check_json(dir: &Path, path: &Path) -> (i32, Value) {
	let (code, text) = check(dir, &[path.to_str().unwrap(), "--check-config-format", "json"], &[]);
	(code, serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}")))
}

fn messages(v: &Value, kind: &str) -> String {
	v[kind].as_array().unwrap().iter().map(|f| format!("{} | {}\n", f["rule"].as_str().unwrap_or(""), f["message"])).collect()
}

fn rule(port: u16) -> String {
	format!("  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {port}, remote_addr: 127.0.0.1, remote_port: 9}}\n")
}

#[test]
fn a_good_file_passes_without_opening_its_ports() {
	let dir = workdir("good");
	let pki = Pki::new("check-good");
	let cert = pki.server("front", &["a.test"]);
	// the port is taken: the check must not try to listen on it
	let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
	let port = busy.local_addr().unwrap().port();
	let file = dir.join("rproxy.yaml");
	fs::write(
		&file,
		format!(
			"version: 1\nglobal: {{trusted_proxies: [10.0.0.0/8]}}\nrules:\n{}  - protocol: tcp\n    listen_addr: 127.0.0.1\n    listen_port: {}\n    remote_addr: 127.0.0.1\n    remote_port: 9\n    tls: {{mode: terminate, certificates: [{{cert_file: {}, key_file: {}}}]}}\n",
			rule(port),
			free_port(),
			cert.cert_file,
			cert.key_file
		),
	)
	.unwrap();
	let (code, text) = check(&dir, &[file.to_str().unwrap()], &[]);
	assert_eq!(code, 0, "{text}");
	assert!(text.contains("2 rule(s), 0 error(s)") && text.contains("OK"), "{text}");

	// RPROXY_CONFIG is used when no path is given
	let (code, text) = check(&dir, &[], &[("RPROXY_CONFIG", file.to_str().unwrap())]);
	assert_eq!(code, 0, "{text}");

	let (code, v) = check_json(&dir, &file);
	assert_eq!(code, 0);
	assert_eq!((v["ok"].as_bool(), v["rules"].as_u64()), (Some(true), Some(2)), "{v}");
	assert_eq!(v["errors"], serde_json::json!([]));
	drop(busy);
}

#[test]
fn nothing_configured_is_nothing_to_check() {
	let dir = workdir("none");
	let (code, text) = check(&dir, &[], &[]);
	assert_eq!(code, 0, "{text}");
	assert!(text.contains("nothing to check"), "{text}");
}

#[test]
fn mistakes_are_all_reported() {
	let dir = workdir("bad");
	let pki = Pki::new("check-bad");
	let a = pki.server("a", &["a.test"]);
	let b = pki.server("b", &["b.test"]);
	let expired = pki.server_until("old", &["old.test"], 1_600_000_000);
	let (p1, p2, p3, p4) = (free_port(), free_port(), free_port(), free_port());
	let file = dir.join("rproxy.yaml");
	let tls = |cert: &str, key: &str| format!("{{mode: terminate, certificates: [{{cert_file: {cert}, key_file: {key}}}]}}");
	fs::write(
		&file,
		format!(
			"version: 1\nrules:\n\
			   - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {p1}, remote_addr: x, remote_port: 1, tls: {}}}\n\
			   - {{protocol: tcp, listen_addr: 0.0.0.0, listen_port: {p1}, remote_addr: x, remote_port: 1}}\n\
			   - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {p2}, remote_addr: x, remote_port: 1, tls: {}}}\n\
			   - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {p3}, remote_addr: x, remote_port: 1, tls: {}}}\n\
			   - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {p4}, remote_addr: x, remote_port: 0}}\n\
			   - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: 8080, remote_addr: x, remote_port: 1}}\n",
			tls("/nope/cert.pem", "/nope/key.pem"),
			tls(&a.cert_file, &b.key_file),
			tls(&expired.cert_file, &expired.key_file),
		),
	)
	.unwrap();
	let (code, v) = check_json(&dir, &file);
	assert_eq!(code, 1, "{v}");
	assert_eq!(v["ok"], false);
	let errors = messages(&v, "errors");
	for (rule, want) in [
		("rule #1", "/nope/cert.pem"),
		("rule #2", "overlaps with"),
		("rule #3", "key"),
		("rule #4", "expired"),
		("rule #5", "remote_port"),
		("rule #6", "control API"),
	] {
		assert!(errors.lines().any(|l| l.contains(rule) && l.contains(want)), "{rule} / {want}:\n{errors}");
	}
	assert_eq!(v["errors"].as_array().unwrap().len(), 6, "{errors}");

	// the same in text, for people
	let (code, text) = check(&dir, &[file.to_str().unwrap()], &[]);
	assert_eq!(code, 1);
	assert!(text.contains("error: rproxy.yaml rule #2:") && text.contains("6 error(s)") && text.contains("NG"), "{text}");
}

#[test]
fn a_certificate_close_to_expiry_is_a_warning() {
	let dir = workdir("expiring");
	let pki = Pki::new("check-expiring");
	let soon = pki.server_until("soon", &["soon.test"], rproxy_api::tls::config::unix_now() + 3 * 86_400);
	let file = dir.join("rproxy.yaml");
	fs::write(
		&file,
		format!(
			"version: 1\nrules:\n  - {{protocol: tcp, listen_addr: 127.0.0.1, listen_port: {}, remote_addr: x, remote_port: 1, tls: {{mode: terminate, certificates: [{{cert_file: {}, key_file: {}}}]}}}}\n",
			free_port(),
			soon.cert_file,
			soon.key_file
		),
	)
	.unwrap();
	let (code, v) = check_json(&dir, &file);
	assert_eq!(code, 0, "{v}");
	assert!(messages(&v, "warnings").contains("expires at"), "{v}");
}

#[test]
fn a_directory_with_the_same_rule_twice_and_a_broken_file() {
	let dir = workdir("dir");
	let conf = dir.join("rproxy.d");
	fs::create_dir_all(&conf).unwrap();
	let port = free_port();
	fs::write(conf.join("10-a.yaml"), format!("version: 1\nrules:\n{}", rule(port))).unwrap();
	fs::write(conf.join("20-b.yaml"), format!("version: 1\nrules:\n{}", rule(port))).unwrap();
	let (code, v) = check_json(&dir, &conf);
	assert_eq!(code, 1, "{v}");
	let errors = messages(&v, "errors");
	assert!(errors.contains("10-a.yaml rule #1") && errors.contains("20-b.yaml rule #1"), "{errors}");

	fs::write(conf.join("20-b.yaml"), "version: 1\nrules: [{protocol: tcp, listen_port: oops}]\n").unwrap();
	let (code, v) = check_json(&dir, &conf);
	assert_eq!(code, 1);
	assert!(messages(&v, "errors").contains("20-b.yaml"), "{v}");

	fs::write(conf.join("20-b.yaml"), format!("version: 1\nrules:\n{}", rule(free_port()))).unwrap();
	let (code, v) = check_json(&dir, &conf);
	assert_eq!((code, v["rules"].as_u64(), v["files"].as_array().unwrap().len()), (0, Some(2), 2), "{v}");
}

#[test]
fn missing_files_of_global_settings_and_middlewares() {
	let dir = workdir("global");
	let file = dir.join("rproxy.yaml");
	fs::write(
		&file,
		format!(
			"version: 1\nglobal:\n  access_log: /nope/dir/access.log\n  crowdsec: {{lapi_url: http://127.0.0.1:8080, api_key_file: /nope/key}}\nrules:\n  - protocol: tcp\n    listen_addr: 127.0.0.1\n    listen_port: {}\n    http:\n      routes: [{{name: all, match: 'PathPrefix(`/`)', to: 'http://127.0.0.1:9', middlewares: [auth]}}]\n      middlewares: {{auth: {{basic_auth: {{users_file: /nope/htpasswd}}}}}}\n",
			free_port()
		),
	)
	.unwrap();
	let (code, v) = check_json(&dir, &file);
	assert_eq!(code, 1, "{v}");
	let errors = messages(&v, "errors");
	for want in ["access log directory /nope/dir", "/nope/key", "/nope/htpasswd"] {
		assert!(errors.contains(want), "{want}:\n{errors}");
	}
}

#[test]
fn a_file_that_cannot_be_read_or_parsed() {
	let dir = workdir("unread");
	let (code, text) = check(&dir, &["/nope/rproxy.yaml"], &[]);
	assert_eq!(code, 1);
	assert!(text.contains("/nope/rproxy.yaml"), "{text}");
	let file = dir.join("rproxy.yaml");
	fs::write(&file, "version: 9\nrules: []\n").unwrap();
	let (code, text) = check(&dir, &[file.to_str().unwrap()], &[]);
	assert_eq!(code, 1);
	assert!(text.contains("version 9"), "{text}");
}
