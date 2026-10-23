//! Files rules from the API may not name (#319, security review A / M2 / M3):
//! the certificate store (`RPROXY_CERT_STORE`), the ACME storage
//! (`global.acme.storage`) and the secrets of the settings and the options
//! (CrowdSec's key, ACME's DNS credentials, EAB and account keys, the token
//! file, the control API's TLS key).
//!
//! A token that may write rules could otherwise make rproxy serve a stored key
//! without `allow_certs` or `acme:write`, or send a secret to an issuer of its
//! own (`oidc.client_secret_file`). Rules of the settings file are the
//! administrator's: they are not refused, `--check-config` warns.
//!
//! A path is judged where it really leads: the file is opened (`O_PATH`: no
//! read permission needed, a FIFO does not block) and the real path of the fd
//! (`/proc/self/fd`, as `net::files`) and its device and inode are compared, so
//! symbolic links and `..` do not get around it. A path that does not exist
//! (yet) is judged by its longest existing parent, so a key stored later under
//! the store is refused now too.
//!
//! Secret files are also kept to one use (M2): a file read as an OIDC client
//! secret, which rproxy sends to the issuer, may be used elsewhere only as the
//! client secret of the same issuer and client.

use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;

use serde_json::Value;

/// One protected file or directory tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
	/// What it is, for the error (`the certificate store (RPROXY_CERT_STORE)`).
	pub what: String,
	pub path: PathBuf,
	/// A directory: everything under it.
	pub tree: bool,
}

impl Entry {
	pub fn tree(what: impl Into<String>, path: impl Into<PathBuf>) -> Entry {
		Entry {
			what: what.into(),
			path: path.into(),
			tree: true,
		}
	}

	pub fn file(what: impl Into<String>, path: impl Into<PathBuf>) -> Entry {
		Entry {
			what: what.into(),
			path: path.into(),
			tree: false,
		}
	}
}

/// The options' secrets (the token file, the control API's TLS key), set at startup.
static PROCESS: RwLock<Vec<Entry>> = RwLock::new(Vec::new());

/// Sets the options' secrets (startup, `--check-config`; tests).
pub fn set_process(entries: Vec<Entry>) {
	*PROCESS.write().unwrap_or_else(|e| e.into_inner()) = entries;
}

/// The options' secrets: `RPROXY_TOKEN_FILE` and `RPROXY_TLS_KEY`.
pub fn process_entries(token_file: Option<&Path>, tls_key: Option<&Path>) -> Vec<Entry> {
	let mut out = vec![];
	out.extend(token_file.map(|p| Entry::file("the token file (RPROXY_TOKEN_FILE)", p)));
	out.extend(tls_key.map(|p| Entry::file("the control API's TLS key (RPROXY_TLS_KEY)", p)));
	out
}

/// Everything protected now: the certificate store, the options' secrets, and
/// the given `global` parts (ACME, CrowdSec's key).
pub fn current(acme: Option<&crate::acme::Acme>, crowdsec_key: Option<&Path>) -> Vec<Entry> {
	let mut out = vec![Entry::tree(
		"under the certificate store (RPROXY_CERT_STORE; name a stored certificate with {\"cert\": \"<name>\"})",
		crate::tls::named::dir(),
	)];
	out.extend(PROCESS.read().unwrap_or_else(|e| e.into_inner()).iter().cloned());
	if let Some(a) = acme {
		out.push(Entry::tree(
			"under the ACME storage (global.acme.storage; use {\"acme\": ...} with the acme:write scope)",
			a.storage(),
		));
		out.extend(
			a.protected_files()
				.into_iter()
				.map(|(what, f)| Entry::file(format!("a secret of global.acme ({what})"), f)),
		);
	}
	out.extend(crowdsec_key.map(|p| Entry::file("the CrowdSec key (global.crowdsec.api_key_file)", p)));
	out
}

/// Where a path leads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
	/// The real path (of the opened fd; else the longest existing parent's real path and the rest).
	pub real: PathBuf,
	/// Device and inode, when it could be opened.
	pub id: Option<(u64, u64)>,
}

impl Resolved {
	/// The same file: the same inode, or (not opened) the same path.
	fn same(&self, other: &Resolved) -> bool {
		match (self.id, other.id) {
			(Some(a), Some(b)) => a == b,
			_ => self.real == other.real,
		}
	}
}

/// Opens `path` without reading it and finds its real path, device and inode.
pub fn resolve(path: &Path) -> Resolved {
	if let Some(r) = open_real(path) {
		return r;
	}
	Resolved {
		real: best_effort(path),
		id: None,
	}
}

#[cfg(target_os = "linux")]
fn open_real(path: &Path) -> Option<Resolved> {
	use std::os::fd::AsRawFd;
	use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
	let file = std::fs::OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_PATH | libc::O_CLOEXEC)
		.open(path)
		.ok()?;
	let meta = file.metadata().ok()?;
	let real = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()?;
	Some(Resolved {
		real,
		id: Some((meta.dev(), meta.ino())),
	})
}

#[cfg(not(target_os = "linux"))]
fn open_real(path: &Path) -> Option<Resolved> {
	use std::os::unix::fs::MetadataExt;
	let meta = std::fs::metadata(path).ok()?;
	Some(Resolved {
		real: std::fs::canonicalize(path).ok()?,
		id: Some((meta.dev(), meta.ino())),
	})
}

/// The longest existing parent's real path, then the rest without `.` and `..`.
fn best_effort(path: &Path) -> PathBuf {
	let abs = if path.is_absolute() {
		path.to_path_buf()
	} else {
		std::env::current_dir().unwrap_or_default().join(path)
	};
	let mut base = abs.as_path();
	let mut rest = vec![];
	loop {
		if let Ok(real) = std::fs::canonicalize(base) {
			let mut out = real;
			for c in rest.iter().rev() {
				match c {
					Component::ParentDir => {
						out.pop();
					}
					Component::Normal(s) => out.push(s),
					_ => {}
				}
			}
			return out;
		}
		match (base.parent(), base.components().next_back()) {
			(Some(parent), Some(last)) => {
				rest.push(last);
				base = parent;
			}
			_ => return abs,
		}
	}
}

/// The entry protecting `path`, if one does.
pub fn protecting<'a>(path: &str, entries: &'a [Entry]) -> Option<&'a Entry> {
	if path.is_empty() {
		return None;
	}
	let r = resolve(Path::new(path));
	entries.iter().find(|e| {
		let p = resolve(&e.path);
		if e.tree {
			r.real.starts_with(&p.real)
		} else {
			r.same(&p)
		}
	})
}

/// A file a rule names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRef {
	/// Where in the rule (`tls.certificates[0].key_file`).
	pub field: String,
	pub path: String,
	/// For an `oidc` `client_secret_file`: the issuer (without a trailing `/`) and the client.
	pub client: Option<(String, String)>,
}

impl FileRef {
	fn is_client_secret(&self) -> bool {
		self.field.ends_with("client_secret_file")
	}
}

/// Every file a rule names: each `*_file` field of `tls` and `http` (certificates,
/// keys, chains and CAs anywhere, the services' TLS, `users_file`, the OIDC secrets).
pub fn refs(tls: Option<&crate::tls::config::TlsSpec>, http: Option<&crate::l7::HttpSpec>) -> Vec<FileRef> {
	let mut out = vec![];
	if let Some(v) = tls.and_then(|t| serde_json::to_value(t).ok()) {
		walk(&v, "tls", &mut out);
	}
	if let Some(v) = http.and_then(|h| serde_json::to_value(h).ok()) {
		walk(&v, "http", &mut out);
	}
	out
}

fn walk(v: &Value, at: &str, out: &mut Vec<FileRef>) {
	match v {
		Value::Object(map) => {
			for (k, child) in map {
				let here = format!("{at}.{k}");
				match child {
					Value::String(path) if k.ends_with("_file") && !path.is_empty() => {
						let client = (k == "client_secret_file").then(|| {
							let s = |key: &str| map.get(key).and_then(Value::as_str).unwrap_or_default().to_string();
							(s("issuer").trim_end_matches('/').to_string(), s("client_id"))
						});
						out.push(FileRef {
							field: here,
							path: path.clone(),
							client,
						});
					}
					_ => walk(child, &here, out),
				}
			}
		}
		Value::Array(items) => {
			for (i, child) in items.iter().enumerate() {
				walk(child, &format!("{at}[{i}]"), out);
			}
		}
		_ => {}
	}
}

/// A rule's files with where they come from.
pub struct Use<'a> {
	/// The rule (`tcp/0.0.0.0:443`, `rules[1]`, `file rule #2`).
	pub rule: String,
	pub file: &'a FileRef,
	/// Part of the change being judged (conflicts among the others alone are not its fault).
	pub new: bool,
}

/// Secret files used twice in ways that let one rule read another's secret (M2): a
/// client secret file used other than as the client secret of the same issuer and
/// client (e.g. as a cookie secret, or for another issuer). One message per conflict.
pub fn secret_conflicts(uses: &[Use<'_>]) -> Vec<String> {
	let resolved: Vec<Resolved> = uses.iter().map(|u| resolve(Path::new(&u.file.path))).collect();
	let mut out = vec![];
	for (i, a) in uses.iter().enumerate() {
		if !a.file.is_client_secret() {
			continue;
		}
		for (j, b) in uses.iter().enumerate() {
			if i == j || !(a.new || b.new) || !resolved[i].same(&resolved[j]) {
				continue;
			}
			if b.file.is_client_secret() && b.file.client == a.file.client {
				continue;
			}
			// a pair of client secrets is reported once
			if b.file.is_client_secret() && j < i {
				continue;
			}
			out.push(format!(
				"{} {} ({}) is also {} {}: a file read as an OIDC client secret (sent to the issuer) may be used elsewhere only as the client secret of the same issuer and client_id",
				a.rule, a.file.field, a.file.path, b.rule, b.file.field
			));
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	fn dir(tag: &str) -> PathBuf {
		let d = std::env::temp_dir().join(format!("rproxy-protected-{tag}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&d);
		std::fs::create_dir_all(&d).unwrap();
		d
	}

	#[test]
	fn trees_files_links_and_missing_paths() {
		let d = dir("paths");
		let store = d.join("store");
		std::fs::create_dir_all(store.join("a")).unwrap();
		std::fs::write(store.join("a/tls.key"), b"k").unwrap();
		std::fs::write(d.join("token"), b"t").unwrap();
		std::fs::write(d.join("mine.key"), b"k").unwrap();
		std::os::unix::fs::symlink(store.join("a/tls.key"), d.join("link.key")).unwrap();
		std::fs::hard_link(d.join("token"), d.join("token2")).unwrap();
		let entries = vec![Entry::tree("store", &store), Entry::file("token", d.join("token"))];
		let s = |p: PathBuf| p.to_string_lossy().into_owned();
		assert_eq!(protecting(&s(store.join("a/tls.key")), &entries).unwrap().what, "store");
		assert_eq!(
			protecting(&s(d.join("link.key")), &entries).unwrap().what,
			"store",
			"a link into the store"
		);
		assert_eq!(
			protecting(&s(d.join("other/../store/a/tls.key")), &entries).unwrap().what,
			"store",
			"`..` does not get around it"
		);
		assert_eq!(
			protecting(&s(store.join("later/current/tls.key")), &entries).unwrap().what,
			"store",
			"not stored yet"
		);
		assert_eq!(protecting(&s(d.join("nothing/../store/b.key")), &entries).unwrap().what, "store");
		assert_eq!(protecting(&s(d.join("token")), &entries).unwrap().what, "token");
		assert_eq!(
			protecting(&s(d.join("token2")), &entries).unwrap().what,
			"token",
			"a hard link is the same inode"
		);
		assert!(protecting(&s(d.join("mine.key")), &entries).is_none());
		assert!(protecting(&s(d.join("store2.key")), &entries).is_none());
		assert!(protecting("", &entries).is_none());
		std::fs::remove_dir_all(d).unwrap();
	}

	#[test]
	fn every_file_field_is_found() {
		let tls: crate::tls::config::TlsSpec = serde_json::from_value(serde_json::json!({
			"mode": "terminate",
			"certificates": [{"cert_file": "/c", "key_file": "/k", "chain_file": "/ch"}],
			"client_auth": {"mode": "required", "ca_file": "/ca"},
		}))
		.unwrap();
		let http: crate::l7::HttpSpec = serde_json::from_value(serde_json::json!({
			"routes": [{"name": "r", "match": "PathPrefix(`/`)", "service": "s", "middlewares": ["o", "b"]}],
			"services": {"s": {"servers": [{"url": "https://127.0.0.1:1"}], "tls": {"ca_file": "/sca", "cert_file": "/sc", "key_file": "/sk"}}},
			"middlewares": {
				"o": {"oidc": {"issuer": "https://idp.example/", "client_id": "x", "client_secret_file": "/cs", "cookie_secret_file": "/ck"}},
				"b": {"basic_auth": {"users_file": "/u"}},
			},
		}))
		.unwrap();
		let mut found: Vec<(String, String)> = refs(Some(&tls), Some(&http)).into_iter().map(|r| (r.field, r.path)).collect();
		found.sort();
		let want = [
			("http.middlewares.b.basic_auth.users_file", "/u"),
			("http.middlewares.o.oidc.client_secret_file", "/cs"),
			("http.middlewares.o.oidc.cookie_secret_file", "/ck"),
			("http.services.s.tls.ca_file", "/sca"),
			("http.services.s.tls.cert_file", "/sc"),
			("http.services.s.tls.key_file", "/sk"),
			("tls.certificates[0].cert_file", "/c"),
			("tls.certificates[0].chain_file", "/ch"),
			("tls.certificates[0].key_file", "/k"),
			("tls.client_auth.ca_file", "/ca"),
		];
		assert_eq!(found, want.map(|(a, b)| (a.to_string(), b.to_string())));
		let cs = refs(None, Some(&http)).into_iter().find(|r| r.is_client_secret()).unwrap();
		assert_eq!(cs.client, Some(("https://idp.example".into(), "x".into())));
	}

	#[test]
	fn client_secrets_keep_to_one_use() {
		let d = dir("uses");
		let f = d.join("secret").to_string_lossy().into_owned();
		std::fs::write(&f, b"s").unwrap();
		let client = |iss: &str, id: &str| FileRef {
			field: "http.middlewares.o.oidc.client_secret_file".into(),
			path: f.clone(),
			client: Some((iss.into(), id.into())),
		};
		let cookie = FileRef {
			field: "http.middlewares.o.oidc.cookie_secret_file".into(),
			path: f.clone(),
			client: None,
		};
		let (a, b, c) = (client("https://a", "x"), client("https://evil", "x"), client("https://a", "x"));
		let use_ = |rule: &str, file, new| Use {
			rule: rule.into(),
			file,
			new,
		};
		assert_eq!(
			secret_conflicts(&[use_("r1", &a, false), use_("r2", &c, true)]).len(),
			0,
			"the same client"
		);
		assert_eq!(
			secret_conflicts(&[use_("r1", &a, false), use_("r2", &b, true)]).len(),
			1,
			"another issuer"
		);
		assert_eq!(
			secret_conflicts(&[use_("r1", &cookie, false), use_("r2", &b, true)]).len(),
			1,
			"a cookie secret as a client secret"
		);
		assert_eq!(
			secret_conflicts(&[use_("r1", &a, true), use_("r2", &cookie, false)]).len(),
			1,
			"a client secret as a cookie secret"
		);
		assert_eq!(
			secret_conflicts(&[use_("r1", &a, false), use_("r2", &cookie, false)]).len(),
			0,
			"old conflicts are not the change's"
		);
		std::fs::remove_dir_all(d).unwrap();
	}
}
