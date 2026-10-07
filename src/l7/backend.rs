//! Services of `http` rules (#61): servers chosen by weighted round robin,
//! active health checks, sticky sessions by cookie, and HTTP/1.1 connections to
//! the servers kept for reuse.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::server::Body;
use super::{parse_duration, ServiceSpec};
use crate::error::ApiError;
use crate::core::resolve::{self, Lookup};

const DEFAULT_CONNECT: Duration = Duration::from_secs(5);
const DEFAULT_RESPONSE: Duration = Duration::from_secs(60);
const DEFAULT_HEALTH_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(3);
/// Idle connections kept per server. About as many as requests in progress at
/// once: with fewer, a busy server gets a new connection for most requests (the
/// HTTP/2 clients of a rule each have up to `max_concurrent_streams` requests going,
/// and each of those needs a connection of its own to an HTTP/1.1 backend; #195).
const MAX_IDLE: usize = 1024;
/// Idle connections unused for longer are closed (by `start_idle_sweep`, and when the
/// pool is next used). Short, like HAProxy's `pool-purge-delay` (5 s): connections in
/// steady use are reused long before, and after a burst the surplus (each with its
/// buffers and a task) goes soon. Also shorter than common backends' keep-alive
/// timeouts (Node.js 5 s, nginx 75 s), so a kept connection is rarely closed under us.
const IDLE_TIMEOUT: Duration = Duration::from_secs(4);
/// How often `start_idle_sweep` looks.
const IDLE_SWEEP: Duration = Duration::from_secs(1);

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// One backend of a service.
#[derive(Debug)]
pub struct Server {
	pub url: String,
	pub https: bool,
	pub host: String,
	pub port: u16,
	/// `host[:port]` as written, for the Host header when `pass_host_header` is false.
	pub authority: String,
	/// Path of the URL without the trailing slash; prepended to request paths.
	pub prefix: String,
	pub weight: u64,
	/// Value of the sticky cookie that selects this server (from the URL, so it
	/// survives restarts and changes of the other servers).
	pub id: String,
	up: AtomicBool,
	/// Requests in progress on this server (for `balance: least_conn`).
	pub inflight: Arc<AtomicU64>,
	/// Last used at the end: taken from the end (the warmest), expired from the front.
	idle: Mutex<Vec<(SendRequest<Body>, Instant)>>,
}

impl Server {
	fn parse(url: &str, weight: u32) -> Result<Server, ApiError> {
		let uri: Uri = url.parse().map_err(|e| ApiError::invalid(format!("{url:?}: {e}")))?;
		let https = uri.scheme_str() == Some("https");
		let authority = uri.authority().ok_or_else(|| ApiError::invalid(format!("{url:?} has no host")))?;
		let host = authority.host().trim_matches(|c| c == '[' || c == ']').to_string();
		let id = Sha256::digest(url.as_bytes())[..8].iter().map(|b| format!("{b:02x}")).collect();
		Ok(Server {
			url: url.to_string(),
			https,
			port: authority.port_u16().unwrap_or(if https { 443 } else { 80 }),
			host,
			authority: authority.as_str().to_string(),
			prefix: uri.path().trim_end_matches('/').to_string(),
			weight: u64::from(weight.max(1)),
			id,
			up: AtomicBool::new(true),
			inflight: Arc::default(),
			idle: Mutex::new(vec![]),
		})
	}

	pub fn is_up(&self) -> bool {
		self.up.load(Ordering::Relaxed)
	}

	pub fn addr(&self) -> String {
		format!("{}:{}", self.host, self.port)
	}

	/// An idle connection that can take a request now.
	pub fn checkout(&self) -> Option<SendRequest<Body>> {
		let mut idle = self.idle.lock().unwrap();
		let now = Instant::now();
		// the newest first; one handed back before its connection has finished the last
		// response is not ready yet, and stays for a later request
		for i in (0..idle.len()).rev() {
			let (s, since) = &idle[i];
			if s.is_closed() || now.duration_since(*since) >= IDLE_TIMEOUT {
				idle.remove(i);
			} else if s.is_ready() {
				return Some(idle.remove(i).0);
			}
		}
		None
	}

	/// Keeps a connection whose response has been read for the next request.
	pub fn checkin(&self, sender: SendRequest<Body>) {
		if sender.is_closed() {
			return;
		}
		let now = Instant::now();
		let mut idle = self.idle.lock().unwrap();
		// the oldest are at the front
		let expired = idle.iter().take_while(|(_, since)| now.duration_since(*since) >= IDLE_TIMEOUT).count();
		idle.drain(..expired);
		if idle.len() >= MAX_IDLE {
			idle.retain(|(s, _)| !s.is_closed());
		}
		if idle.len() < MAX_IDLE {
			idle.push((sender, now));
		}
	}

	/// Closes the idle connections unused for `IDLE_TIMEOUT`, and those the server closed.
	fn prune_idle(&self) {
		let now = Instant::now();
		self.idle.lock().unwrap().retain(|(s, since)| !s.is_closed() && now.duration_since(*since) < IDLE_TIMEOUT);
	}
}

/// Closes idle backend connections of `services` once unused for `IDLE_TIMEOUT`, until `stop`.
pub fn start_idle_sweep(services: Vec<Arc<Service>>, stop: CancellationToken) {
	if services.is_empty() || tokio::runtime::Handle::try_current().is_err() {
		return;
	}
	tokio::spawn(async move {
		loop {
			tokio::select! {
				_ = stop.cancelled() => return,
				_ = tokio::time::sleep(IDLE_SWEEP) => {}
			}
			for server in services.iter().flat_map(|s| s.servers.iter()) {
				server.prune_idle();
			}
		}
	});
}

#[derive(Debug)]
pub struct HealthCheck {
	path: String,
	interval: Duration,
	timeout: Duration,
}

/// A service: weighted round robin over its servers that are up.
#[derive(Debug)]
pub struct Service {
	pub name: String,
	pub servers: Vec<Server>,
	total_weight: u64,
	next: AtomicU64,
	pub pass_host: bool,
	pub connect: Duration,
	pub response: Duration,
	pub health: Option<HealthCheck>,
	/// Name of the sticky cookie.
	pub sticky: Option<String>,
	pub balance: crate::core::balance::Balance,
}

fn duration(d: Option<&String>, default: Duration) -> Result<Duration, ApiError> {
	match d {
		Some(d) => parse_duration(d).map_err(ApiError::invalid),
		None => Ok(default),
	}
}

impl Service {
	pub fn compile(name: &str, spec: &ServiceSpec) -> Result<Service, ApiError> {
		let servers = spec
			.servers
			.iter()
			.map(|s| Server::parse(&s.url, s.weight.unwrap_or(1)))
			.collect::<Result<Vec<_>, _>>()?;
		if servers.is_empty() {
			return Err(ApiError::invalid(format!("service {name}: servers is empty")));
		}
		let timeouts = spec.timeouts.as_ref();
		let health = match &spec.health_check {
			Some(h) => Some(HealthCheck {
				path: h.path.clone(),
				interval: duration(h.interval.as_ref(), DEFAULT_HEALTH_INTERVAL)?.max(Duration::from_millis(100)),
				timeout: duration(h.timeout.as_ref(), DEFAULT_HEALTH_TIMEOUT)?.max(Duration::from_millis(10)),
			}),
			None => None,
		};
		let sticky = match &spec.sticky {
			Some(s) if s.cookie.is_empty() || !s.cookie.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) => {
				return Err(ApiError::invalid(format!("service {name}: sticky.cookie {:?} is not a cookie name", s.cookie)));
			}
			Some(s) => Some(s.cookie.clone()),
			None => None,
		};
		Ok(Service {
			name: name.to_string(),
			total_weight: servers.iter().map(|s| s.weight).sum(),
			servers,
			next: AtomicU64::new(0),
			pass_host: spec.pass_host_header.unwrap_or(true),
			connect: duration(timeouts.and_then(|t| t.connect.as_ref()), DEFAULT_CONNECT)?,
			response: duration(timeouts.and_then(|t| t.response.as_ref()), DEFAULT_RESPONSE)?,
			health,
			sticky,
			balance: spec.balance,
		})
	}

	pub fn single(url: &str) -> Result<Service, ApiError> {
		let spec = ServiceSpec {
			servers: vec![super::ServerSpec { url: url.to_string(), weight: None }],
			health_check: None,
			sticky: None,
			pass_host_header: None,
			timeouts: None,
			balance: Default::default(),
			outlier_detection: None,
		};
		Service::compile(url, &spec)
	}

	/// The server for a request: the one its sticky cookie names while that is
	/// up, otherwise the one `balance` picks among those up (weighted round
	/// robin, fewest requests in progress, or the first in order). None when
	/// every server is down.
	pub fn pick(&self, sticky: Option<&str>) -> Option<usize> {
		if let Some(id) = sticky {
			if let Some(i) = self.servers.iter().position(|s| s.id == id && s.is_up()) {
				return Some(i);
			}
		}
		match self.balance {
			crate::core::balance::Balance::Failover => return self.servers.iter().position(Server::is_up),
			crate::core::balance::Balance::LeastConn => {
				let up: Vec<usize> = (0..self.servers.len()).filter(|&i| self.servers[i].is_up()).collect();
				if up.is_empty() {
					return None;
				}
				// ties go round, so idle servers share requests evenly
				let start = self.next.fetch_add(1, Ordering::Relaxed) as usize % up.len();
				return up[start..].iter().chain(&up[..start]).copied().min_by(|&a, &b| {
					let (sa, sb) = (&self.servers[a], &self.servers[b]);
					let la = u128::from(sa.inflight.load(Ordering::Relaxed)) * u128::from(sb.weight);
					let lb = u128::from(sb.inflight.load(Ordering::Relaxed)) * u128::from(sa.weight);
					la.cmp(&lb)
				});
			}
			crate::core::balance::Balance::RoundRobin => {}
		}
		// a few draws; with most servers down, fall back to scanning
		for _ in 0..self.servers.len() * 4 {
			let mut n = self.next.fetch_add(1, Ordering::Relaxed) % self.total_weight;
			for (i, s) in self.servers.iter().enumerate() {
				if n < s.weight {
					if s.is_up() {
						return Some(i);
					}
					break;
				}
				n -= s.weight;
			}
		}
		self.servers.iter().position(Server::is_up)
	}

	/// The sticky cookie's value in a request, if this service is sticky.
	pub fn sticky_value(&self, headers: &HeaderMap) -> Option<String> {
		let name = self.sticky.as_deref()?;
		cookie(headers, name)
	}

	/// `Set-Cookie` that pins the client to a server.
	pub fn sticky_cookie(&self, server: &Server, https: bool) -> Option<HeaderValue> {
		let name = self.sticky.as_deref()?;
		let secure = if https { "; Secure" } else { "" };
		HeaderValue::from_str(&format!("{name}={}; Path=/; HttpOnly; SameSite=Lax{secure}", server.id)).ok()
	}
}

/// The value of cookie `name` in the Cookie headers.
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
	headers
		.get_all(header::COOKIE)
		.iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|v| v.split(';'))
		.filter_map(|pair| pair.trim().split_once('='))
		.find(|(k, _)| *k == name)
		.map(|(_, v)| v.trim().to_string())
}

/// What connecting to servers needs, shared by requests and health checks.
#[derive(Clone)]
pub struct Dialer {
	pub lookup: Lookup,
	/// For https:// servers: `tls.upstream` of the rule, or the Mozilla roots.
	pub tls: tokio_rustls::TlsConnector,
	pub server_name: Option<String>,
}

impl Dialer {
	/// A TCP (and TLS for https://) connection to `server`, from `bind` when
	/// the rule uses `source_ip: transparent`.
	pub async fn dial(&self, server: &Server, bind: Option<SocketAddr>) -> Result<Box<dyn Stream>, String> {
		let addrs = match server.host.parse::<IpAddr>() {
			Ok(ip) => vec![SocketAddr::new(ip, server.port)],
			Err(_) => resolve::resolve(&self.lookup, &server.addr()).await.map_err(|e| e.message)?,
		};
		let mut last = String::from("no addresses");
		let mut tcp = None;
		for addr in addrs {
			match crate::net::source::connect_tcp(addr, bind).await {
				Ok(s) => {
					tcp = Some(s);
					break;
				}
				Err(e) => last = format!("{addr}: {e}"),
			}
		}
		let tcp = tcp.ok_or(last)?; // TCP_NODELAY is set by connect_tcp
		if !server.https {
			return Ok(Box::new(tcp));
		}
		let name = self.server_name.clone().unwrap_or_else(|| server.host.clone());
		let name = ServerName::try_from(name).map_err(|e| e.to_string())?;
		Ok(Box::new(self.tls.connect(name, tcp).await.map_err(|e| format!("TLS: {e}"))?))
	}
}

/// Starts HTTP/1.1 on a connection; the connection itself runs until `stop` or its end.
pub async fn handshake(stream: Box<dyn Stream>, stop: CancellationToken, spawn: impl FnOnce(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>)) -> io::Result<SendRequest<Body>> {
	let (sender, conn) = hyper::client::conn::http1::Builder::new()
		.handshake::<_, Body>(TokioIo::new(stream))
		.await
		.map_err(io::Error::other)?;
	spawn(Box::pin(async move {
		tokio::select! {
			_ = stop.cancelled() => {}
			_ = conn.with_upgrades() => {}
		}
	}));
	Ok(sender)
}

/// Health of the servers of a service with `health_check` (rule view and metrics).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ServerHealth {
	pub url: String,
	pub up: bool,
}

pub fn health_view<'a>(services: impl Iterator<Item = &'a Arc<Service>>) -> BTreeMap<String, Vec<ServerHealth>> {
	services
		.filter(|s| s.health.is_some())
		.map(|s| (s.name.clone(), s.servers.iter().map(|v| ServerHealth { url: v.url.clone(), up: v.is_up() }).collect()))
		.collect()
}

/// Probes the servers of `service` every `interval` until `stop`; a server is up
/// while `GET path` answers 2xx / 3xx within `timeout`.
pub fn start_health_checks(service: Arc<Service>, dialer: Dialer, stop: CancellationToken) {
	let Some(h) = service.health.as_ref() else { return };
	if tokio::runtime::Handle::try_current().is_err() {
		return;
	}
	let interval = h.interval;
	tokio::spawn(async move {
		loop {
			let probes = service.servers.iter().map(|s| probe(&service, s, &dialer, &stop));
			let results = futures_util::future::join_all(probes).await;
			for (server, (up, why)) in service.servers.iter().zip(results) {
				if server.up.swap(up, Ordering::Relaxed) != up {
					if up {
						info!(event = "http.health", service = %service.name, server = %server.url, up);
					} else {
						warn!(event = "http.health", service = %service.name, server = %server.url, up, error = %why);
					}
				}
			}
			tokio::select! {
				_ = stop.cancelled() => return,
				_ = tokio::time::sleep(interval) => {}
			}
		}
	});
}

async fn probe(service: &Service, server: &Server, dialer: &Dialer, stop: &CancellationToken) -> (bool, String) {
	let Some(h) = service.health.as_ref() else { return (true, String::new()) };
	let check = async {
		let stream = dialer.dial(server, None).await?;
		let conn_stop = stop.child_token();
		let mut sender = handshake(stream, conn_stop.clone(), |f| {
			tokio::spawn(f);
		})
		.await
		.map_err(|e| e.to_string())?;
		let req = Request::get(format!("{}{}", server.prefix, h.path))
			.header(header::HOST, &server.authority)
			.header(header::USER_AGENT, "rproxy-health-check")
			.body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
			.map_err(|e| e.to_string())?;
		let resp = sender.send_request(req).await.map_err(|e| e.to_string());
		conn_stop.cancel();
		let status = resp?.status();
		if status.is_success() || status.is_redirection() {
			Ok(())
		} else {
			Err(format!("status {status}"))
		}
	};
	match tokio::time::timeout(h.timeout, check).await {
		Ok(Ok(())) => (true, String::new()),
		Ok(Err(e)) => (false, e),
		Err(_) => (false, "timed out".into()),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn service(yaml: &str) -> Service {
		let spec: ServiceSpec = serde_json::from_value(serde_yaml_ng::from_str::<serde_json::Value>(yaml).unwrap()).unwrap();
		Service::compile("s", &spec).unwrap()
	}

	#[test]
	fn weighted_round_robin_skips_servers_that_are_down() {
		let s = service("servers: [{url: 'http://10.0.0.1', weight: 3}, {url: 'https://b.example:8443/base/', weight: 1}]");
		let picks: Vec<usize> = (0..8).map(|_| s.pick(None).unwrap()).collect();
		assert_eq!(picks.iter().filter(|i| **i == 0).count(), 6);
		let b = &s.servers[1];
		assert_eq!((b.https, b.port, b.prefix.as_str(), b.authority.as_str()), (true, 8443, "/base", "b.example:8443"));
		assert_eq!((s.servers[0].port, s.servers[0].prefix.as_str()), (80, ""));

		s.servers[0].up.store(false, Ordering::Relaxed);
		assert!((0..8).all(|_| s.pick(None) == Some(1)));
		s.servers[1].up.store(false, Ordering::Relaxed);
		assert_eq!(s.pick(None), None, "every server is down");
	}

	#[test]
	fn least_conn_and_failover() {
		let s = service("servers: [{url: 'http://10.0.0.1'}, {url: 'http://10.0.0.2'}, {url: 'http://10.0.0.3'}]\nbalance: least_conn");
		s.servers[0].inflight.store(3, Ordering::Relaxed);
		s.servers[1].inflight.store(1, Ordering::Relaxed);
		s.servers[2].inflight.store(2, Ordering::Relaxed);
		assert!((0..4).all(|_| s.pick(None) == Some(1)));
		s.servers[1].up.store(false, Ordering::Relaxed);
		assert_eq!(s.pick(None), Some(2));

		let f = service("servers: [{url: 'http://10.0.0.1'}, {url: 'http://10.0.0.2'}]\nbalance: failover");
		assert!((0..4).all(|_| f.pick(None) == Some(0)));
		f.servers[0].up.store(false, Ordering::Relaxed);
		assert_eq!(f.pick(None), Some(1));
		f.servers[0].up.store(true, Ordering::Relaxed);
		assert_eq!(f.pick(None), Some(0), "back to the first once it is up");
	}

	#[test]
	fn sticky_cookie_pins_a_server_while_it_is_up() {
		let s = service("servers: [{url: 'http://10.0.0.1'}, {url: 'http://10.0.0.2'}]\nsticky: {cookie: lb}");
		let id = s.servers[1].id.clone();
		assert_eq!(id.len(), 16);
		let mut h = HeaderMap::new();
		h.insert(header::COOKIE, HeaderValue::from_str(&format!("a=1; lb={id}; b=2")).unwrap());
		assert_eq!(s.sticky_value(&h).as_deref(), Some(id.as_str()));
		assert!((0..6).all(|_| s.pick(Some(&id)) == Some(1)));
		s.servers[1].up.store(false, Ordering::Relaxed);
		assert_eq!(s.pick(Some(&id)), Some(0), "re-picked when the pinned server is down");
		assert_eq!(s.pick(Some("unknown")), Some(0));
		let set = s.sticky_cookie(&s.servers[0], true).unwrap();
		assert_eq!(set.to_str().unwrap(), format!("lb={}; Path=/; HttpOnly; SameSite=Lax; Secure", s.servers[0].id));
		assert!(Service::compile("s", &serde_json::from_value(serde_json::json!({"servers": [{"url": "http://a"}], "sticky": {"cookie": "a b"}})).unwrap()).is_err());
	}
}
