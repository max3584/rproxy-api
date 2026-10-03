//! CrowdSec bouncer (#55): the decisions of the Local API (LAPI), pulled in
//! stream mode by one task for the whole process (`global.crowdsec`), and the
//! AppSec component asked per request by the `crowdsec` middleware.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::server::Body;
use super::{HttpSpec, MiddlewareSpec};
use crate::cidr::Cidr;
use crate::config::CrowdsecGlobal;
use crate::error::ApiError;

/// Default of `update_interval`, as in the CrowdSec bouncers.
const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
/// Longest wait between attempts while the LAPI cannot be reached.
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const LAPI_TIMEOUT: Duration = Duration::from_secs(10);
const APPSEC_TIMEOUT: Duration = Duration::from_secs(3);
/// Request bodies up to this size (by Content-Length) are sent to AppSec;
/// larger ones, and those without a length, are checked by their headers only.
pub const APPSEC_MAX_BODY: u64 = 1024 * 1024;

/// Why the bouncer cannot be set up.
#[derive(Debug)]
pub enum CrowdsecError {
	/// A mistake in the settings (bad URL, missing or empty key file): stop the startup.
	Config(String),
}

/// One decision of the stream.
#[derive(Debug, Deserialize)]
struct Decision {
	#[serde(default)]
	id: Option<i64>,
	#[serde(default)]
	scope: String,
	#[serde(default)]
	value: String,
	#[serde(default, rename = "type")]
	kind: String,
}

#[derive(Debug, Default, Deserialize)]
struct Stream {
	#[serde(default)]
	new: Option<Vec<Decision>>,
	#[serde(default)]
	deleted: Option<Vec<Decision>>,
}

/// What a decision blocks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Target {
	Ip(IpAddr),
	Range(Cidr),
}

fn canonical(ip: IpAddr) -> IpAddr {
	super::access::canonical(ip)
}

impl Target {
	/// Scopes `Ip` and `Range`; others (Country, AS, …) are not handled.
	fn of(d: &Decision) -> Option<Target> {
		let value = d.value.trim();
		match d.scope.to_ascii_lowercase().as_str() {
			"ip" => value.parse().ok().map(|ip| Target::Ip(canonical(ip))),
			"range" => value.parse().ok().map(Target::Range),
			_ => None,
		}
	}
}

/// Blocking decisions: `ban`, and `captcha`, which rproxy cannot serve, is treated as a ban.
fn blocks(d: &Decision) -> bool {
	matches!(d.kind.to_ascii_lowercase().as_str(), "ban" | "captcha")
}

/// The decisions in force: each target with the ids of the decisions on it, so
/// that one expiring does not lift another on the same address.
#[derive(Debug, Default)]
pub struct Decisions {
	ips: HashMap<IpAddr, HashSet<i64>>,
	ranges: HashMap<Cidr, HashSet<i64>>,
}

impl Decisions {
	fn ids(&mut self, t: &Target) -> &mut HashSet<i64> {
		match t {
			Target::Ip(ip) => self.ips.entry(*ip).or_default(),
			Target::Range(c) => self.ranges.entry(*c).or_default(),
		}
	}

	fn add(&mut self, d: &Decision) {
		if !blocks(d) {
			return;
		}
		if let Some(t) = Target::of(d) {
			// decisions without an id count as one
			self.ids(&t).insert(d.id.unwrap_or(0));
		}
	}

	fn remove(&mut self, d: &Decision) {
		let Some(t) = Target::of(d) else { return };
		let empty = {
			let ids = self.ids(&t);
			match d.id {
				Some(id) => {
					ids.remove(&id);
				}
				None => ids.clear(),
			}
			ids.is_empty()
		};
		if empty {
			match t {
				Target::Ip(ip) => self.ips.remove(&ip),
				Target::Range(c) => self.ranges.remove(&c),
			};
		}
	}

	pub fn blocked(&self, ip: IpAddr) -> bool {
		let ip = canonical(ip);
		self.ips.contains_key(&ip) || self.ranges.keys().any(|c| c.contains(ip))
	}

	/// Targets (addresses and ranges) blocked.
	pub fn len(&self) -> usize {
		self.ips.len() + self.ranges.len()
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}
}

/// What the `crowdsec` middleware decided.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
	Allow,
	Block,
	/// The LAPI has never answered, or AppSec could not be asked: `on_error` decides.
	Error(String),
}

/// The process-wide bouncer.
pub struct Bouncer {
	lapi: Uri,
	appsec: Option<Uri>,
	key_file: PathBuf,
	key: RwLock<String>,
	interval: Duration,
	decisions: RwLock<Decisions>,
	synced: AtomicBool,
	/// Successful pulls, for tests and logs.
	pulls: AtomicU64,
	tls: tokio_rustls::TlsConnector,
	stop: CancellationToken,
}

impl std::fmt::Debug for Bouncer {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Bouncer").field("lapi", &self.lapi).field("appsec", &self.appsec).finish_non_exhaustive()
	}
}

fn parse_url(url: &str, what: &str) -> Result<Uri, CrowdsecError> {
	let uri: Uri = url.trim().parse().map_err(|e| CrowdsecError::Config(format!("{what}: {url:?}: {e}")))?;
	match (uri.scheme_str(), uri.authority()) {
		(Some("http" | "https"), Some(_)) => Ok(uri),
		_ => Err(CrowdsecError::Config(format!("{what}: {url:?} must be an http:// or https:// URL"))),
	}
}

/// Reads the API key; a missing or empty file is a configuration error.
fn read_key(path: &PathBuf) -> Result<String, std::io::Error> {
	let key = std::fs::read_to_string(path)?.trim().to_string();
	if key.is_empty() {
		return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the key file is empty"));
	}
	Ok(key)
}

impl Bouncer {
	/// Sets up the bouncer. An unreadable key file (permissions) is not fatal:
	/// the bouncer waits for SIGHUP and `on_error` decides meanwhile.
	pub fn new(g: &CrowdsecGlobal) -> Result<Arc<Bouncer>, CrowdsecError> {
		let lapi = parse_url(&g.lapi_url, "global.crowdsec.lapi_url")?;
		let appsec = g.appsec_url.as_deref().map(|u| parse_url(u, "global.crowdsec.appsec_url")).transpose()?;
		let interval = match &g.update_interval {
			Some(i) => super::parse_duration(i).map_err(|e| CrowdsecError::Config(format!("global.crowdsec.update_interval: {e}")))?,
			None => DEFAULT_INTERVAL,
		}
		.max(Duration::from_secs(1));
		let key_file = PathBuf::from(&g.api_key_file);
		let key = match read_key(&key_file) {
			Ok(k) => k,
			Err(e) if e.kind() == std::io::ErrorKind::NotFound || e.kind() == std::io::ErrorKind::InvalidData => {
				return Err(CrowdsecError::Config(format!("global.crowdsec.api_key_file {}: {e}", key_file.display())));
			}
			Err(e) => {
				warn!(event = "degraded", part = "global.crowdsec", error = %format!("{}: {e}", key_file.display()),
					"CrowdSec is not asked until the key file can be read (SIGHUP)");
				String::new()
			}
		};
		let tls = crate::tlsconf::client_config(&Default::default())
			.map_err(|e| CrowdsecError::Config(format!("global.crowdsec: {}", e.message)))?;
		Ok(Arc::new(Bouncer {
			lapi,
			appsec,
			key_file,
			key: RwLock::new(key),
			interval,
			decisions: RwLock::default(),
			synced: AtomicBool::new(false),
			pulls: AtomicU64::new(0),
			tls: tokio_rustls::TlsConnector::from(tls),
			stop: CancellationToken::new(),
		}))
	}

	pub fn has_appsec(&self) -> bool {
		self.appsec.is_some()
	}

	/// Re-reads the API key (SIGHUP); on error the current key stays.
	pub fn reload_key(&self) -> Result<(), String> {
		let key = read_key(&self.key_file).map_err(|e| format!("{}: {e}", self.key_file.display()))?;
		*self.key.write().unwrap() = key;
		Ok(())
	}

	fn key(&self) -> String {
		self.key.read().unwrap().clone()
	}

	/// Number of blocked addresses and ranges (`rproxy_crowdsec_decisions`).
	pub fn decision_count(&self) -> usize {
		self.decisions.read().unwrap().len()
	}

	pub fn synced(&self) -> bool {
		self.synced.load(Ordering::Relaxed)
	}

	pub fn pulls(&self) -> u64 {
		self.pulls.load(Ordering::Relaxed)
	}

	/// Starts pulling decisions until `stop`.
	pub fn spawn(self: &Arc<Self>) {
		let me = self.clone();
		tokio::spawn(async move { me.run().await });
	}

	pub fn stop(&self) {
		self.stop.cancel();
	}

	async fn run(self: Arc<Self>) {
		let mut startup = true;
		let mut failures: u32 = 0;
		loop {
			let wait = match self.pull(startup).await {
				Ok((added, deleted)) => {
					if startup || added > 0 || deleted > 0 {
						info!(event = "crowdsec.sync", startup, added, deleted, decisions = self.decision_count());
					}
					startup = false;
					failures = 0;
					self.interval
				}
				Err(e) => {
					failures = failures.saturating_add(1);
					// what the LAPI took from a failed pull is unknown: start over with a full list
					startup = true;
					let wait = self.interval.saturating_mul(2u32.saturating_pow(failures.min(16))).min(MAX_BACKOFF);
					warn!(event = "crowdsec.error", error = %e, failures, retry_secs = wait.as_secs(),
						synced = self.synced(), "keeping the current decisions");
					wait
				}
			};
			tokio::select! {
				_ = self.stop.cancelled() => return,
				_ = tokio::time::sleep(wait) => {}
			}
		}
	}

	/// One pull of the stream; returns the numbers of new and deleted decisions.
	async fn pull(&self, startup: bool) -> Result<(usize, usize), String> {
		let key = self.key();
		if key.is_empty() {
			return Err(format!("no API key ({} could not be read)", self.key_file.display()));
		}
		let base = self.lapi.to_string();
		let url = format!("{}/v1/decisions/stream?startup={startup}", base.trim_end_matches('/'));
		let mut headers = HeaderMap::new();
		headers.insert(HeaderName::from_static("x-api-key"), HeaderValue::from_str(&key).map_err(|e| e.to_string())?);
		let (status, body) = call(&self.tls, Method::GET, &url, headers, Bytes::new(), LAPI_TIMEOUT).await?;
		if status != StatusCode::OK {
			return Err(format!("LAPI answered {status}"));
		}
		let stream: Stream = serde_json::from_slice(&body).map_err(|e| format!("LAPI answer: {e}"))?;
		let (new, deleted) = (stream.new.unwrap_or_default(), stream.deleted.unwrap_or_default());
		let mut d = self.decisions.write().unwrap();
		if startup {
			*d = Decisions::default();
		}
		for x in &deleted {
			d.remove(x);
		}
		for x in &new {
			d.add(x);
		}
		drop(d);
		self.synced.store(true, Ordering::Relaxed);
		self.pulls.fetch_add(1, Ordering::Relaxed);
		Ok((new.len(), deleted.len()))
	}

	/// Whether the LAPI's decisions block `client`.
	pub fn check_ip(&self, client: IpAddr) -> Verdict {
		if !self.synced() {
			return Verdict::Error("no decisions from the LAPI yet".into());
		}
		if self.decisions.read().unwrap().blocked(client) {
			Verdict::Block
		} else {
			Verdict::Allow
		}
	}

	/// Asks AppSec about a request. The body is read (and put back) when it has
	/// a Content-Length of at most `APPSEC_MAX_BODY`.
	pub async fn check_appsec(&self, parts: &Parts, body: &mut Body, client: IpAddr, host: &str) -> Verdict {
		let Some(appsec) = &self.appsec else { return Verdict::Error("no global.crowdsec.appsec_url".into()) };
		let key = self.key();
		if key.is_empty() {
			return Verdict::Error(format!("no API key ({} could not be read)", self.key_file.display()));
		}
		let length: Option<u64> = parts.headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
		let mut sent = Bytes::new();
		if let Some(n) = length.filter(|n| *n > 0 && *n <= APPSEC_MAX_BODY) {
			let taken = std::mem::replace(body, empty());
			match taken.collect().await {
				Ok(collected) => {
					sent = collected.to_bytes();
					*body = Full::new(sent.clone()).map_err(|never| match never {}).boxed();
				}
				Err(e) => return Verdict::Error(format!("reading the request body ({n} bytes): {e}")),
			}
		}
		let mut headers = HeaderMap::new();
		for (name, value) in parts.headers.iter() {
			if name != header::CONTENT_LENGTH && name != header::TRANSFER_ENCODING && name != header::CONNECTION && name != header::HOST {
				headers.append(name.clone(), value.clone());
			}
		}
		let mut set = |name: &'static str, value: &str| {
			if let Ok(v) = HeaderValue::from_str(value) {
				headers.insert(HeaderName::from_static(name), v);
			}
		};
		set("x-crowdsec-appsec-ip", &canonical(client).to_string());
		set("x-crowdsec-appsec-uri", parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
		set("x-crowdsec-appsec-host", host);
		set("x-crowdsec-appsec-verb", parts.method.as_str());
		set("x-crowdsec-appsec-api-key", &key);
		let ua = parts.headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		set("x-crowdsec-appsec-user-agent", &ua);
		let version = match parts.version {
			hyper::Version::HTTP_10 => "10",
			hyper::Version::HTTP_2 => "20",
			hyper::Version::HTTP_3 => "30",
			_ => "11",
		};
		set("x-crowdsec-appsec-http-version", version);
		let method = if sent.is_empty() { Method::GET } else { Method::POST };
		match call(&self.tls, method, &appsec.to_string(), headers, sent, APPSEC_TIMEOUT).await {
			Ok((StatusCode::OK, _)) => Verdict::Allow,
			Ok((StatusCode::FORBIDDEN, _)) => Verdict::Block,
			Ok((status, _)) => Verdict::Error(format!("AppSec answered {status}")),
			Err(e) => Verdict::Error(e),
		}
	}
}

/// The `crowdsec` middlewares of a rule need `global.crowdsec` (and its
/// `appsec_url` for `appsec: true`).
pub fn check_refs(spec: &HttpSpec, bouncer: Option<&Arc<Bouncer>>) -> Result<(), ApiError> {
	for (name, m) in &spec.middlewares {
		let MiddlewareSpec::Crowdsec { appsec, .. } = m else { continue };
		match bouncer {
			None => {
				return Err(ApiError::invalid(format!(
					"middleware {name}: crowdsec needs global.crowdsec in the settings file (RPROXY_CONFIG)"
				)))
			}
			Some(b) if *appsec && !b.has_appsec() => {
				return Err(ApiError::invalid(format!("middleware {name}: appsec needs global.crowdsec.appsec_url")))
			}
			_ => {}
		}
	}
	Ok(())
}

fn empty() -> Body {
	Full::new(Bytes::new()).map_err(|never| match never {}).boxed()
}

trait Stream2: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream2 for T {}

/// One HTTP/1.1 request to the LAPI or AppSec (and the OIDC provider); returns the status and body.
pub(super) async fn call(
	tls: &tokio_rustls::TlsConnector,
	method: Method,
	url: &str,
	headers: HeaderMap,
	body: Bytes,
	timeout: Duration,
) -> Result<(StatusCode, Bytes), String> {
	let uri: Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
	let authority = uri.authority().ok_or_else(|| format!("{url}: no host"))?.clone();
	let https = uri.scheme_str() == Some("https");
	let host = authority.host().trim_matches(|c| c == '[' || c == ']').to_string();
	let port = authority.port_u16().unwrap_or(if https { 443 } else { 80 });
	let work = async {
		let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| format!("{authority}: {e}"))?;
		let _ = tcp.set_nodelay(true);
		let stream: Box<dyn Stream2> = if https {
			let name = ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
			Box::new(tls.connect(name, tcp).await.map_err(|e| format!("{authority}: TLS: {e}"))?)
		} else {
			Box::new(tcp)
		};
		let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream))
			.await
			.map_err(|e| e.to_string())?;
		tokio::spawn(conn);
		let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
		let mut req = Request::builder().method(method).uri(path);
		let h = req.headers_mut().expect("builder without errors");
		*h = headers;
		h.insert(header::HOST, HeaderValue::from_str(authority.as_str()).map_err(|e| e.to_string())?);
		h.insert(header::USER_AGENT, HeaderValue::from_static(concat!("rproxy-api/", env!("CARGO_PKG_VERSION"))));
		let req = req.body(Full::new(body)).map_err(|e| e.to_string())?;
		let resp = sender.send_request(req).await.map_err(|e| e.to_string())?;
		let status = resp.status();
		let bytes = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
		Ok::<_, String>((status, bytes))
	};
	tokio::time::timeout(timeout, work).await.map_err(|_| format!("{authority}: timed out"))?
}

#[cfg(test)]
mod tests {
	use super::*;

	fn d(id: i64, scope: &str, value: &str, kind: &str) -> Decision {
		Decision { id: Some(id), scope: scope.into(), value: value.into(), kind: kind.into() }
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	#[test]
	fn decisions_by_address_and_range() {
		let mut set = Decisions::default();
		set.add(&d(1, "Ip", "192.0.2.1", "ban"));
		set.add(&d(2, "Range", "198.51.100.0/24", "ban"));
		set.add(&d(3, "ip", "2001:db8::7", "captcha"));
		set.add(&d(4, "Country", "JP", "ban"));
		set.add(&d(5, "Ip", "192.0.2.9", "throttle"));
		assert!(set.blocked(ip("192.0.2.1")));
		assert!(set.blocked(ip("::ffff:192.0.2.1")), "IPv4-mapped");
		assert!(set.blocked(ip("198.51.100.200")));
		assert!(set.blocked(ip("2001:db8::7")), "captcha counts as a ban");
		assert!(!set.blocked(ip("192.0.2.9")), "other types are ignored");
		assert!(!set.blocked(ip("192.0.2.2")));
		assert_eq!(set.len(), 3);
	}

	#[test]
	fn one_decision_expiring_does_not_lift_another() {
		let mut set = Decisions::default();
		set.add(&d(1, "Ip", "192.0.2.1", "ban"));
		set.add(&d(2, "Ip", "192.0.2.1", "ban"));
		set.remove(&d(1, "Ip", "192.0.2.1", "ban"));
		assert!(set.blocked(ip("192.0.2.1")));
		set.remove(&d(2, "Ip", "192.0.2.1", "ban"));
		assert!(!set.blocked(ip("192.0.2.1")));
		assert!(set.is_empty());
		// deletions without an id lift every decision on the target
		set.add(&d(3, "Range", "10.0.0.0/8", "ban"));
		set.add(&d(4, "Range", "10.0.0.0/8", "ban"));
		set.remove(&Decision { id: None, scope: "Range".into(), value: "10.0.0.0/8".into(), kind: "ban".into() });
		assert!(set.is_empty());
	}

	#[test]
	fn settings() {
		let g = |lapi: &str, key: &str| CrowdsecGlobal {
			lapi_url: lapi.into(),
			api_key_file: key.into(),
			appsec_url: None,
			update_interval: None,
		};
		let e = |r: Result<Arc<Bouncer>, CrowdsecError>| match r {
			Err(CrowdsecError::Config(e)) => e,
			Ok(_) => panic!("accepted"),
		};
		assert!(e(Bouncer::new(&g("ftp://x", "/nonexistent"))).contains("http://"));
		assert!(e(Bouncer::new(&g("http://127.0.0.1:8080", "/nonexistent/key"))).contains("api_key_file"));
		let dir = std::env::temp_dir().join(format!("rproxy-cs-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let key = dir.join("key");
		std::fs::write(&key, "\n").unwrap();
		assert!(e(Bouncer::new(&g("http://127.0.0.1:8080", key.to_str().unwrap()))).contains("empty"));
		std::fs::write(&key, "secret\n").unwrap();
		let b = Bouncer::new(&g("http://127.0.0.1:8080/", key.to_str().unwrap())).unwrap();
		assert_eq!(b.key(), "secret");
		assert_eq!(b.check_ip(ip("192.0.2.1")), Verdict::Error("no decisions from the LAPI yet".into()));
		std::fs::write(&key, "other").unwrap();
		b.reload_key().unwrap();
		assert_eq!(b.key(), "other");
		std::fs::remove_dir_all(dir).unwrap();
	}
}
