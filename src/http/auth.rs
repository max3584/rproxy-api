//! Authentication middlewares (#59): `basic_auth` (htpasswd file) and the
//! request / response handling of `forward_auth` (the server sends the request
//! to the auth server). `oidc` is in `oidc.rs`. Secret files are read when the
//! rule is compiled, again when they change (checked at most every few seconds
//! while requests come in) and on SIGHUP.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::request::Parts;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::error::ApiError;

/// How often a secret file is looked at for changes while requests come in.
const RECHECK: Duration = Duration::from_secs(5);
/// Verified user:password pairs remembered (bcrypt is slow on purpose).
const CACHE_MAX: usize = 1024;
pub const DEFAULT_REALM: &str = "rproxy";
pub const DEFAULT_FORWARD_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

fn fingerprint(path: &Path) -> u64 {
	crate::tlsconf::fingerprint([path.to_str().unwrap_or("")])
}

/// A file with a secret (users, client secret, cookie key), parsed into `T`.
/// Missing or malformed at compile time is a configuration error; unreadable
/// (permissions) leaves it empty, and the middleware answers 503 until it can be read.
pub struct SecretFile<T> {
	path: PathBuf,
	parse: fn(&str) -> Result<T, String>,
	state: RwLock<Loaded<T>>,
}

struct Loaded<T> {
	value: Option<Arc<T>>,
	print: u64,
	checked: Instant,
	/// The version of the file whose problem was logged (once per version).
	reported: Option<u64>,
}

impl<T> SecretFile<T> {
	pub fn open(path: &str, what: &str, parse: fn(&str) -> Result<T, String>) -> Result<SecretFile<T>, ApiError> {
		let path = PathBuf::from(path);
		let print = fingerprint(&path);
		let value = match std::fs::read_to_string(&path) {
			Ok(text) => Some(Arc::new(parse(&text).map_err(|e| ApiError::invalid(format!("{what}: {}: {e}", path.display())))?)),
			Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::InvalidData) => {
				return Err(ApiError::invalid(format!("{what}: {}: {e}", path.display())));
			}
			Err(e) => {
				warn!(event = "degraded", part = "http.auth", file = %path.display(), error = %e,
					"requests through this middleware get 503 until the file can be read");
				None
			}
		};
		Ok(SecretFile { path, parse, state: RwLock::new(Loaded { value, print, checked: Instant::now(), reported: None }) })
	}

	/// The current value, re-reading the file when it changed.
	pub fn get(&self) -> Option<Arc<T>> {
		{
			let s = self.state.read().unwrap();
			if s.checked.elapsed() < RECHECK {
				return s.value.clone();
			}
		}
		self.reload(false);
		self.state.read().unwrap().value.clone()
	}

	/// Re-reads the file if it changed (or always with `force`, for SIGHUP).
	/// A file that no longer reads or parses keeps the current value.
	pub fn reload(&self, force: bool) {
		let print = fingerprint(&self.path);
		let mut s = self.state.write().unwrap();
		s.checked = Instant::now();
		if !force && print == s.print && s.value.is_some() {
			return;
		}
		let result = std::fs::read_to_string(&self.path).map_err(|e| e.to_string()).and_then(|t| (self.parse)(&t));
		match result {
			Ok(v) => {
				if s.value.is_some() && print != s.print {
					info!(event = "reload.secret", file = %self.path.display());
				}
				s.value = Some(Arc::new(v));
				s.print = print;
				s.reported = None;
			}
			Err(e) => {
				if s.reported != Some(print) {
					warn!(event = "reload.secret", file = %self.path.display(), error = %e, "keeping the current contents");
					s.reported = Some(print);
				}
			}
		}
	}
}

impl<T> std::fmt::Debug for SecretFile<T> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SecretFile").field("path", &self.path).finish_non_exhaustive()
	}
}

/// The first line of a file, trimmed (client secrets, keys); empty is an error.
pub fn one_line(text: &str) -> Result<String, String> {
	let line = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or("");
	if line.is_empty() {
		return Err("the file is empty".into());
	}
	Ok(line.to_string())
}

/// A password hash of an htpasswd file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hash {
	/// `$2y$` / `$2b$` / `$2a$` (htpasswd -B)
	Bcrypt(String),
	/// `{SHA}` + base64 of SHA-1 (htpasswd -s; weak, for old files)
	Sha1([u8; 20]),
	/// `$apr1$salt$hash` (htpasswd -m, its default; MD5-based, for old files)
	Apr1 { salt: String, hash: String },
}

/// `user:hash` lines: bcrypt, APR1 and {SHA} (what htpasswd writes, as in
/// Traefik). Other schemes (crypt, plain text) are refused so that a file never
/// silently lets nobody in.
pub fn parse_htpasswd(text: &str) -> Result<HashMap<String, Hash>, String> {
	let mut users = HashMap::new();
	for (i, line) in text.lines().enumerate() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		let (user, hash) = line.split_once(':').ok_or_else(|| format!("line {}: expected user:hash", i + 1))?;
		let hash = if hash.starts_with("$2y$") || hash.starts_with("$2b$") || hash.starts_with("$2a$") {
			hash.parse::<bcrypt::HashParts>().map_err(|e| format!("line {}: {e}", i + 1))?;
			Hash::Bcrypt(hash.to_string())
		} else if let Some(rest) = hash.strip_prefix("$apr1$") {
			let (salt, h) = rest.split_once('$').ok_or_else(|| format!("line {}: malformed $apr1$ hash", i + 1))?;
			if salt.is_empty() || salt.len() > 8 || h.len() != 22 {
				return Err(format!("line {}: malformed $apr1$ hash", i + 1));
			}
			Hash::Apr1 { salt: salt.to_string(), hash: h.to_string() }
		} else if let Some(b64) = hash.strip_prefix("{SHA}") {
			let raw = base64::engine::general_purpose::STANDARD.decode(b64).map_err(|e| format!("line {}: {e}", i + 1))?;
			Hash::Sha1(raw.try_into().map_err(|_| format!("line {}: {{SHA}} must be 20 bytes", i + 1))?)
		} else {
			return Err(format!("line {}: user {user}: only bcrypt ($2y$, htpasswd -B), $apr1$ and {{SHA}} hashes are supported", i + 1));
		};
		if users.insert(user.to_string(), hash).is_some() {
			return Err(format!("line {}: user {user} appears twice", i + 1));
		}
	}
	if users.is_empty() {
		return Err("no users".into());
	}
	Ok(users)
}

/// The hash part of Apache's `$apr1$` (MD5-crypt with the `$apr1$` magic).
fn apr1(password: &[u8], salt: &[u8]) -> String {
	use md5::{Digest as _, Md5};
	const MAGIC: &[u8] = b"$apr1$";
	let alt = Md5::new().chain_update(password).chain_update(salt).chain_update(password).finalize();
	let mut ctx = Md5::new();
	ctx.update(password);
	ctx.update(MAGIC);
	ctx.update(salt);
	let mut n = password.len();
	while n > 0 {
		ctx.update(&alt[..n.min(16)]);
		n = n.saturating_sub(16);
	}
	let mut n = password.len();
	while n > 0 {
		ctx.update(if n & 1 == 1 { &[0u8][..] } else { &password[..1] });
		n >>= 1;
	}
	let mut sum = ctx.finalize();
	for i in 0..1000 {
		let mut c = Md5::new();
		if i & 1 == 1 {
			c.update(password);
		} else {
			c.update(sum);
		}
		if i % 3 != 0 {
			c.update(salt);
		}
		if i % 7 != 0 {
			c.update(password);
		}
		if i & 1 == 1 {
			c.update(sum);
		} else {
			c.update(password);
		}
		sum = c.finalize();
	}
	const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	let mut out = String::with_capacity(22);
	let mut put = |v: u32, n: usize| {
		let mut v = v;
		for _ in 0..n {
			out.push(ITOA64[(v & 0x3f) as usize] as char);
			v >>= 6;
		}
	};
	let b = |i: usize| u32::from(sum[i]);
	for (x, y, z) in [(0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)] {
		put((b(x) << 16) | (b(y) << 8) | b(z), 4);
	}
	put(b(11), 2);
	out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
	a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `basic_auth`.
#[derive(Debug)]
pub struct BasicAuth {
	pub name: String,
	pub users: SecretFile<HashMap<String, Hash>>,
	pub realm: String,
	/// Pass `Authorization` on to the backend.
	pub keep_authorization: bool,
	/// Header that tells the backend who signed in.
	pub user_header: Option<HeaderName>,
	/// sha256(user:password) of recent successes, for the current users file.
	cache: Mutex<(usize, HashMap<[u8; 32], String>)>,
}

/// What `basic_auth` decided.
pub enum BasicVerdict {
	Allow(String),
	Deny,
	/// The users file could not be read.
	Unavailable,
}

impl BasicAuth {
	pub fn new(name: &str, users_file: &str, realm: Option<&str>, keep_authorization: bool, user_header: Option<&str>) -> Result<BasicAuth, ApiError> {
		let what = format!("middleware {name}: users_file");
		let user_header = match user_header {
			Some(h) => Some(HeaderName::from_bytes(h.as_bytes()).map_err(|_| ApiError::invalid(format!("middleware {name}: user_header {h:?}")))?),
			None => None,
		};
		let realm = realm.unwrap_or(DEFAULT_REALM);
		if realm.contains('"') || HeaderValue::from_str(realm).is_err() {
			return Err(ApiError::invalid(format!("middleware {name}: realm {realm:?}")));
		}
		Ok(BasicAuth {
			name: name.to_string(),
			users: SecretFile::open(users_file, &what, parse_htpasswd)?,
			realm: realm.to_string(),
			keep_authorization,
			user_header,
			cache: Mutex::default(),
		})
	}

	/// Checks `Authorization: Basic`. bcrypt runs on the blocking pool.
	pub async fn check(&self, headers: &HeaderMap) -> BasicVerdict {
		let Some(users) = self.users.get() else { return BasicVerdict::Unavailable };
		let Some((user, password)) = basic_credentials(headers) else { return BasicVerdict::Deny };
		let key: [u8; 32] = Sha256::digest(format!("{user}:{password}").as_bytes()).into();
		let generation = Arc::as_ptr(&users) as usize;
		{
			let c = self.cache.lock().unwrap();
			if c.0 == generation && c.1.get(&key).is_some_and(|u| *u == user) {
				return BasicVerdict::Allow(user);
			}
		}
		let Some(hash) = users.get(&user).cloned() else { return BasicVerdict::Deny };
		let ok = match hash {
			Hash::Sha1(expected) => constant_time_eq(&Sha1::digest(password.as_bytes()), &expected),
			Hash::Apr1 { salt, hash } => constant_time_eq(apr1(password.as_bytes(), salt.as_bytes()).as_bytes(), hash.as_bytes()),
			Hash::Bcrypt(h) => tokio::task::spawn_blocking(move || bcrypt::verify(password, &h).unwrap_or(false)).await.unwrap_or(false),
		};
		if !ok {
			return BasicVerdict::Deny;
		}
		let mut c = self.cache.lock().unwrap();
		if c.0 != generation || c.1.len() >= CACHE_MAX {
			*c = (generation, HashMap::new());
		}
		c.1.insert(key, user.clone());
		BasicVerdict::Allow(user)
	}

	pub fn challenge(&self) -> HeaderValue {
		HeaderValue::from_str(&format!("Basic realm=\"{}\"", self.realm)).unwrap_or(HeaderValue::from_static("Basic"))
	}
}

fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
	let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
	let (scheme, rest) = value.split_once(' ')?;
	if !scheme.eq_ignore_ascii_case("basic") {
		return None;
	}
	let decoded = base64::engine::general_purpose::STANDARD.decode(rest.trim()).ok()?;
	let text = String::from_utf8(decoded).ok()?;
	let (user, password) = text.split_once(':')?;
	Some((user.to_string(), password.to_string()))
}

/// `forward_auth`: what to ask and what to take from the answer.
#[derive(Debug)]
pub struct ForwardAuth {
	pub name: String,
	pub service: Arc<super::backend::Service>,
	/// Path and query of `address`.
	pub path: String,
	/// Headers of the auth server's 2xx answer copied to the request for the backend.
	pub response_headers: Vec<HeaderName>,
	/// Headers of the client's request sent to the auth server; empty = all.
	pub request_headers: Vec<HeaderName>,
	pub trust_forward_header: bool,
}

const FORWARDED: [&str; 6] =
	["x-forwarded-method", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-uri", "x-forwarded-for", "x-forwarded-port"];

impl ForwardAuth {
	/// Headers for the auth server: the client's (all, or `request_headers`),
	/// without hop-by-hop ones, and X-Forwarded-Method / Proto / Host / Uri / For.
	pub fn request_headers(&self, parts: &Parts, client: IpAddr, https: bool, host: &str) -> HeaderMap {
		let mut out = HeaderMap::new();
		for (name, value) in &parts.headers {
			let wanted = self.request_headers.is_empty() || self.request_headers.contains(name);
			if wanted && !is_hop_by_hop(name) && name != header::HOST && name != header::CONTENT_LENGTH {
				out.append(name.clone(), value.clone());
			}
		}
		if !self.trust_forward_header {
			for h in FORWARDED {
				out.remove(h);
			}
		}
		let trust = self.trust_forward_header;
		let set = |out: &mut HeaderMap, name: &'static str, value: &str| {
			let name = HeaderName::from_static(name);
			if trust && out.contains_key(&name) {
				return;
			}
			if let Ok(v) = HeaderValue::from_str(value) {
				out.insert(name, v);
			}
		};
		set(&mut out, "x-forwarded-method", parts.method.as_str());
		set(&mut out, "x-forwarded-proto", if https { "https" } else { "http" });
		set(&mut out, "x-forwarded-host", host);
		set(&mut out, "x-forwarded-uri", parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
		if trust {
			if let Some(v) = parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
				if let Ok(v) = HeaderValue::from_str(&format!("{v}, {client}")) {
					out.insert("x-forwarded-for", v);
				}
			}
		}
		set(&mut out, "x-forwarded-for", &client.to_string());
		out
	}

	/// After a 2xx: the named headers of the answer replace those of the request.
	pub fn copy_answer(&self, answer: &HeaderMap, parts: &mut Parts) {
		for name in &self.response_headers {
			parts.headers.remove(name);
			for v in answer.get_all(name) {
				parts.headers.append(name.clone(), v.clone());
			}
		}
	}
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
	matches!(
		name.as_str(),
		"connection" | "keep-alive" | "proxy-connection" | "proxy-authenticate" | "proxy-authorization" | "te" | "trailer" | "transfer-encoding" | "upgrade"
	)
}

pub fn header_names(names: &[String], what: &str) -> Result<Vec<HeaderName>, ApiError> {
	names
		.iter()
		.map(|n| HeaderName::from_bytes(n.as_bytes()).map_err(|_| ApiError::invalid(format!("{what}: {n:?} is not a header name"))))
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn basic(user: &str, password: &str) -> HeaderMap {
		let mut h = HeaderMap::new();
		let v = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
		h.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Basic {v}")).unwrap());
		h
	}

	fn tempfile(name: &str, text: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("rproxy-auth-mw-{}-{name}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let p = dir.join("file");
		std::fs::write(&p, text).unwrap();
		p
	}

	#[test]
	fn htpasswd_lines() {
		let bc = bcrypt::hash("pw", 4).unwrap();
		let sha = format!("{{SHA}}{}", base64::engine::general_purpose::STANDARD.encode(Sha1::digest(b"pw")));
		let users = parse_htpasswd(&format!("# c\nalice:{bc}\nbob:{sha}\n")).unwrap();
		assert!(matches!(users["alice"], Hash::Bcrypt(_)));
		assert!(matches!(users["bob"], Hash::Sha1(_)));
		// htpasswd -mb /dev/stdout user pw (Apache's own test vector style)
		let apr = parse_htpasswd("dave:$apr1$r31.....$ARC3pREO82RIm0aQ2zszC0\n").unwrap();
		assert!(matches!(&apr["dave"], Hash::Apr1 { .. }));
		for (bad, want) in [
			("carol:$apr1$abc$def", "malformed"),
			("carol:plain", "only bcrypt"),
			("nocolon", "user:hash"),
			("", "no users"),
			("{SHA}", "user:hash"),
		] {
			let e = parse_htpasswd(bad).unwrap_err();
			assert!(e.contains(want), "{bad}: {e}");
		}
		assert!(parse_htpasswd(&format!("a:{bc}\na:{bc}")).unwrap_err().contains("twice"));
	}

	#[test]
	fn apr1_matches_htpasswd() {
		// `openssl passwd -apr1 -salt r31..... password`
		assert_eq!(apr1(b"password", b"r31....."), "ARC3pREO82RIm0aQ2zszC0");
		assert_ne!(apr1(b"Password", b"r31....."), "ARC3pREO82RIm0aQ2zszC0");
	}

	#[tokio::test]
	async fn basic_auth_checks_and_reloads() {
		let file = tempfile("basic", &format!("alice:{}\n", bcrypt::hash("secret", 4).unwrap()));
		let b = BasicAuth::new("auth", file.to_str().unwrap(), None, false, Some("X-User")).unwrap();
		assert!(matches!(b.check(&basic("alice", "secret")).await, BasicVerdict::Allow(u) if u == "alice"));
		assert!(matches!(b.check(&basic("alice", "secret")).await, BasicVerdict::Allow(_)), "cached");
		assert!(matches!(b.check(&basic("alice", "wrong")).await, BasicVerdict::Deny));
		assert!(matches!(b.check(&basic("mallory", "secret")).await, BasicVerdict::Deny));
		assert!(matches!(b.check(&HeaderMap::new()).await, BasicVerdict::Deny));
		assert_eq!(b.challenge(), "Basic realm=\"rproxy\"");

		// a new file takes over (SIGHUP forces the check); the cache does not outlive it
		std::fs::write(&file, format!("alice:{}\n", bcrypt::hash("new", 4).unwrap())).unwrap();
		b.users.reload(true);
		assert!(matches!(b.check(&basic("alice", "secret")).await, BasicVerdict::Deny));
		assert!(matches!(b.check(&basic("alice", "new")).await, BasicVerdict::Allow(_)));
		// a broken file keeps the current users
		std::fs::write(&file, "garbage").unwrap();
		b.users.reload(true);
		assert!(matches!(b.check(&basic("alice", "new")).await, BasicVerdict::Allow(_)));
		std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
	}

	#[test]
	fn missing_or_bad_files_are_configuration_errors() {
		let e = BasicAuth::new("a", "/nonexistent/rproxy/users", None, false, None).unwrap_err();
		assert!(e.message.contains("users_file"), "{}", e.message);
		let file = tempfile("bad", "alice:plain\n");
		assert!(BasicAuth::new("a", file.to_str().unwrap(), None, false, None).unwrap_err().message.contains("only bcrypt"));
		assert!(BasicAuth::new("a", file.to_str().unwrap(), Some("a\"b"), false, None).is_err());
		std::fs::remove_dir_all(file.parent().unwrap()).unwrap();
	}

	#[test]
	fn forward_auth_headers() {
		let service = Arc::new(super::super::backend::Service::single("http://127.0.0.1:1/auth").unwrap());
		let mut fa = ForwardAuth {
			name: "fa".into(),
			service,
			path: "/auth".into(),
			response_headers: vec![HeaderName::from_static("x-user")],
			request_headers: vec![],
			trust_forward_header: false,
		};
		let req = hyper::Request::post("/app/x?y=1")
			.header("cookie", "a=b")
			.header("x-forwarded-for", "6.6.6.6")
			.header("x-forwarded-host", "evil")
			.header("connection", "keep-alive")
			.body(())
			.unwrap();
		let (parts, _) = req.into_parts();
		let client: IpAddr = "10.0.0.9".parse().unwrap();
		let h = fa.request_headers(&parts, client, true, "a.example");
		assert_eq!(h["x-forwarded-method"], "POST");
		assert_eq!(h["x-forwarded-proto"], "https");
		assert_eq!(h["x-forwarded-host"], "a.example");
		assert_eq!(h["x-forwarded-uri"], "/app/x?y=1");
		assert_eq!(h["x-forwarded-for"], "10.0.0.9");
		assert_eq!(h["cookie"], "a=b");
		assert!(!h.contains_key("connection"));

		fa.trust_forward_header = true;
		let h = fa.request_headers(&parts, client, true, "a.example");
		assert_eq!(h["x-forwarded-host"], "evil");
		assert_eq!(h["x-forwarded-for"], "6.6.6.6, 10.0.0.9");

		fa.request_headers = vec![HeaderName::from_static("x-none")];
		assert!(!fa.request_headers(&parts, client, true, "a").contains_key("cookie"));

		let mut answer = HeaderMap::new();
		answer.insert("x-user", HeaderValue::from_static("alice"));
		answer.insert("x-other", HeaderValue::from_static("1"));
		let (mut parts, _) = hyper::Request::get("/").header("x-user", "forged").body(()).unwrap().into_parts();
		fa.copy_answer(&answer, &mut parts);
		assert_eq!(parts.headers["x-user"], "alice");
		assert!(!parts.headers.contains_key("x-other"));
	}
}
