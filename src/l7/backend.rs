//! Services of `http` rules (#61): servers chosen by weighted round robin,
//! active health checks, sticky sessions by cookie, and HTTP/1.1 connections to
//! the servers kept for reuse. HTTP/2 servers (`protocol`, #233) get one
//! multiplexed connection each; `status` entries (#235) answer themselves.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::client::conn::http1::SendRequest;
use hyper::client::conn::http2;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::middleware::Middleware;
use super::server::Body;
use super::{parse_duration, MiddlewareSpec, ServiceSpec, UpstreamProtocol};
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
	/// Ejected by the service's `outlier_detection` (#170).
	pub ejection: Arc<crate::core::outlier::Ejection>,
	/// Requests in progress on this server (for `balance: least_conn`).
	pub inflight: Arc<AtomicU64>,
	/// Last used at the end: taken from the end (the warmest), expired from the front.
	idle: Mutex<Vec<(SendRequest<Body>, Instant)>>,
	/// `status` entry (#235): rproxy answers with this instead of forwarding.
	pub status: Option<StatusCode>,
	/// `middlewares` of this server (#229), run after the route's.
	pub middlewares: Vec<Arc<Middleware>>,
	/// The HTTP/2 connections (#233): another is opened when every one carries
	/// `H2_STREAMS_PER_CONN` requests, up to `H2_MAX_CONNS` (security review M6).
	h2: Mutex<Vec<H2Conn>>,
	/// Held while an HTTP/2 connection is being opened: requests that need a new one
	/// wait for it (one opening at a time); those with room on a kept one do not.
	pub h2_opening: tokio::sync::Mutex<()>,
	/// `protocol: auto`: what the server picked by ALPN (0 not known yet, 1 HTTP/1.1, 2 HTTP/2).
	alpn: std::sync::atomic::AtomicU8,
}

impl Server {
	/// A `status` entry (#235).
	fn fixed(status: u16, weight: u32) -> Result<Server, ApiError> {
		let status = StatusCode::from_u16(status).map_err(|e| ApiError::invalid(format!("status {status}: {e}")))?;
		let mut server = Server::parse(&format!("http://status-{}.invalid", status.as_u16()), weight)?;
		server.url = format!("status:{}", status.as_u16());
		server.status = Some(status);
		Ok(server)
	}

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
			ejection: Arc::default(),
			inflight: Arc::default(),
			idle: Mutex::new(vec![]),
			status: None,
			middlewares: vec![],
			h2: Mutex::new(vec![]),
			h2_opening: tokio::sync::Mutex::new(()),
			alpn: Default::default(),
		})
	}

	/// A kept HTTP/2 connection with room for one more request, counted while the
	/// returned hold lives. None: open another (`h2_add`) or wait.
	pub fn h2_take(&self) -> H2Pick {
		let mut conns = self.h2.lock().unwrap_or_else(|e| e.into_inner());
		conns.retain(|c| !c.sender.is_closed());
		if let Some(c) = conns.iter().min_by_key(|c| c.streams.load(Ordering::Relaxed)).filter(|c| c.streams.load(Ordering::Relaxed) < H2_STREAMS_PER_CONN) {
			return H2Pick::Use(c.sender.clone(), crate::l7::middleware::limit::Hold::counting(c.streams.clone()));
		}
		if conns.len() < H2_MAX_CONNS {
			H2Pick::Open
		} else {
			// all full: the least busy one; the request waits for a stream (bounded by the caller)
			match conns.iter().min_by_key(|c| c.streams.load(Ordering::Relaxed)) {
				Some(c) => H2Pick::Use(c.sender.clone(), crate::l7::middleware::limit::Hold::counting(c.streams.clone())),
				None => H2Pick::Open,
			}
		}
	}

	/// Keeps a new HTTP/2 connection; the hold counts the request that opened it.
	pub fn h2_add(&self, sender: http2::SendRequest<Body>) -> crate::l7::middleware::limit::Hold {
		let streams: Arc<AtomicU64> = Arc::default();
		let hold = crate::l7::middleware::limit::Hold::counting(streams.clone());
		self.h2.lock().unwrap_or_else(|e| e.into_inner()).push(H2Conn { sender, streams });
		hold
	}

	/// Open HTTP/2 connections (tests).
	pub fn h2_conns(&self) -> usize {
		self.h2.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|c| !c.sender.is_closed()).count()
	}

	/// `protocol: auto`: the server picked HTTP/2 by ALPN on the last connection.
	pub fn picked_h2(&self) -> bool {
		self.alpn.load(Ordering::Relaxed) == 2
	}

	pub fn set_picked(&self, h2: bool) {
		self.alpn.store(if h2 { 2 } else { 1 }, Ordering::Relaxed);
	}

	/// Up by the health check and not ejected by `outlier_detection`.
	pub fn is_up(&self) -> bool {
		self.up.load(Ordering::Relaxed) && !self.ejection.is_ejected()
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
	/// Passive health checks (#170): servers failing in real traffic are ejected for a while.
	pub outlier: Option<crate::core::outlier::HttpOutlier>,
	/// HTTP version towards the servers (#233).
	pub protocol: UpstreamProtocol,
	/// TLS of this service (its `tls`, #236, or ALPN other than http/1.1); None uses the router's.
	pub tls: Option<ServiceTls>,
}

/// The TLS client of one service.
#[derive(Clone)]
pub struct ServiceTls {
	pub connector: tokio_rustls::TlsConnector,
	pub server_name: Option<String>,
}

impl std::fmt::Debug for ServiceTls {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ServiceTls").field("server_name", &self.server_name).finish_non_exhaustive()
	}
}

/// ALPN offered for `protocol`.
pub fn alpn(protocol: UpstreamProtocol) -> Vec<Vec<u8>> {
	match protocol {
		UpstreamProtocol::H2 => vec![b"h2".to_vec()],
		UpstreamProtocol::Auto => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
		UpstreamProtocol::Http1 | UpstreamProtocol::H2c => vec![b"http/1.1".to_vec()],
	}
}

impl ServiceTls {
	pub fn new(mut config: rustls::ClientConfig, protocol: UpstreamProtocol, server_name: Option<String>) -> ServiceTls {
		config.alpn_protocols = alpn(protocol);
		ServiceTls { connector: tokio_rustls::TlsConnector::from(Arc::new(config)), server_name }
	}
}

fn duration(d: Option<&String>, default: Duration) -> Result<Duration, ApiError> {
	match d {
		Some(d) => parse_duration(d).map_err(ApiError::invalid),
		None => Ok(default),
	}
}

impl Service {
	/// `middlewares` are the rule's, for the servers' own (#229).
	pub fn compile(name: &str, spec: &ServiceSpec, middlewares: &BTreeMap<String, MiddlewareSpec>) -> Result<Service, ApiError> {
		Service::compile_with(name, spec, middlewares, &Default::default())
	}

	/// `services`: those compiled already, for the servers' `mirror` (v0.4.3).
	pub fn compile_with(
		name: &str,
		spec: &ServiceSpec,
		middlewares: &BTreeMap<String, MiddlewareSpec>,
		services: &std::collections::HashMap<String, Arc<Service>>,
	) -> Result<Service, ApiError> {
		let mut servers = vec![];
		for (i, s) in spec.servers.iter().enumerate() {
			let weight = s.weight.unwrap_or(1);
			let mut server = match s.status {
				Some(status) => Server::fixed(status, weight)?,
				None => Server::parse(&s.url, weight)?,
			};
			for m in &s.middlewares {
				let what = format!("service {name}: servers[{i}]: middleware {m}");
				let spec = middlewares.get(m).ok_or_else(|| ApiError::invalid(format!("{what} is not defined")))?;
				if !super::SERVER_MIDDLEWARES.contains(&spec.kind()) {
					return Err(ApiError::invalid(format!("{what}: {} cannot run per server", spec.kind())));
				}
				server.middlewares.push(Arc::new(Middleware::errors(m, spec, services)?));
			}
			servers.push(server);
		}
		let tls = match &spec.tls {
			Some(t) => {
				t.validate(&format!("service {name}: tls"))?;
				Some(ServiceTls::new(t.client_config()?, spec.protocol, t.server_name.clone()))
			}
			None => None,
		};
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
			outlier: spec.outlier_detection.as_ref().map(crate::core::outlier::HttpOutlier::new),
			protocol: spec.protocol,
			tls,
		})
	}

	pub fn single(url: &str) -> Result<Service, ApiError> {
		let spec = ServiceSpec {
			servers: vec![super::ServerSpec { url: url.to_string(), ..Default::default() }],
			health_check: None,
			sticky: None,
			pass_host_header: None,
			timeouts: None,
			balance: Default::default(),
			outlier_detection: None,
			protocol: Default::default(),
			tls: None,
		};
		Service::compile(url, &spec, &BTreeMap::new())
	}

	/// Whether requests to server `index` go over HTTP/2.
	pub fn speaks_h2(&self, index: usize) -> bool {
		match self.protocol {
			UpstreamProtocol::H2 | UpstreamProtocol::H2c => true,
			UpstreamProtocol::Auto => self.servers.get(index).is_some_and(|s| s.https && s.picked_h2()),
			UpstreamProtocol::Http1 => false,
		}
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
		self.draw().or_else(|| {
			// every server that is up by its health checks is ejected (max_ejected_percent: 100):
			// still try one rather than refuse
			self.servers.iter().position(|s| s.up.load(Ordering::Relaxed))
		})
	}

	fn draw(&self) -> Option<usize> {
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
	/// the rule uses `source_ip: transparent`. `tls` is the service's own (#236);
	/// the second value tells that the server picked HTTP/2 by ALPN.
	pub async fn dial(&self, server: &Server, bind: Option<SocketAddr>, tls: Option<&ServiceTls>) -> Result<(Box<dyn Stream>, bool), String> {
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
			return Ok((Box::new(tcp), false));
		}
		let (connector, name) = match tls {
			Some(t) => (&t.connector, t.server_name.clone()),
			None => (&self.tls, self.server_name.clone()),
		};
		let name = name.unwrap_or_else(|| server.host.clone());
		let name = ServerName::try_from(name).map_err(|e| e.to_string())?;
		let stream = connector.connect(name, tcp).await.map_err(|e| format!("TLS: {e}"))?;
		let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
		Ok((Box::new(stream), h2))
	}
}

/// Marks a request whose client asked for trailers (`TE: trailers`), for HTTP/2 servers (#233).
#[derive(Clone, Copy, Debug)]
pub struct WantsTrailers;

/// A connection to a server, ready for requests.
pub enum Sender {
	Http1(SendRequest<Body>),
	Http2(http2::SendRequest<Body>),
}

/// Starts HTTP/1.1 (or HTTP/2 with `h2`) on a connection; the connection itself
/// runs until `stop` or its end.
pub async fn handshake(
	stream: Box<dyn Stream>,
	h2: bool,
	stop: CancellationToken,
	spawn: impl FnOnce(std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>),
) -> io::Result<Sender> {
	if h2 {
		let (sender, conn) = http2::Builder::new(TokioExecutor::new())
			.timer(TokioTimer::new())
			.keep_alive_interval(Some(H2_KEEPALIVE))
			.keep_alive_timeout(H2_KEEPALIVE_TIMEOUT)
			.max_header_list_size(super::server::MAX_HEADER_SECTION)
			.handshake::<_, Body>(TokioIo::new(stream))
			.await
			.map_err(io::Error::other)?;
		spawn(Box::pin(async move {
			tokio::select! {
				_ = stop.cancelled() => {}
				_ = conn => {}
			}
		}));
		return Ok(Sender::Http2(sender));
	}
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
	Ok(Sender::Http1(sender))
}

/// Requests on one HTTP/2 connection before another is opened (below the usual
/// SETTINGS_MAX_CONCURRENT_STREAMS of 100-250).
pub const H2_STREAMS_PER_CONN: u64 = 100;
/// HTTP/2 connections per server at most.
pub const H2_MAX_CONNS: usize = 8;

/// One kept HTTP/2 connection and the requests it carries now.
#[derive(Debug)]
struct H2Conn {
	sender: http2::SendRequest<Body>,
	streams: Arc<AtomicU64>,
}

/// What `Server::h2_take` found.
pub enum H2Pick {
	Use(http2::SendRequest<Body>, crate::l7::middleware::limit::Hold),
	Open,
}

/// Pings on an idle HTTP/2 connection, so one the server or a middlebox dropped is noticed.
const H2_KEEPALIVE: Duration = Duration::from_secs(30);
const H2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// A request in the form HTTP/2 needs (#233): an absolute URI whose authority is
/// the Host (no Host field), and `te: trailers` when the client asked for trailers.
pub fn to_h2<B>(mut req: Request<B>, https: bool, trailers: bool) -> Request<B> {
	let authority = req.headers_mut().remove(header::HOST).and_then(|h| h.to_str().ok().map(str::to_string));
	let pq = req.uri().path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into());
	let mut b = Uri::builder().scheme(if https { "https" } else { "http" }).path_and_query(pq);
	if let Some(a) = authority.as_deref().filter(|a| !a.is_empty()) {
		b = b.authority(a);
	}
	if let Ok(uri) = b.build() {
		*req.uri_mut() = uri;
	}
	*req.version_mut() = hyper::Version::HTTP_2;
	if trailers {
		req.headers_mut().insert(header::TE, HeaderValue::from_static("trailers"));
	}
	req
}

/// Health of the servers of a service with `health_check` or `outlier_detection` (rule view and metrics).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ServerHealth {
	pub url: String,
	pub up: bool,
	/// Ejected by `outlier_detection` (#170); `up` is false meanwhile.
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub ejected: bool,
}

pub fn health_view<'a>(services: impl Iterator<Item = &'a Arc<Service>>) -> BTreeMap<String, Vec<ServerHealth>> {
	services
		.filter(|s| s.health.is_some() || s.outlier.is_some())
		.map(|s| {
			let servers = s.servers.iter().filter(|v| v.status.is_none()).map(|v| ServerHealth { url: v.url.clone(), up: v.is_up(), ejected: v.ejection.is_ejected() });
			(s.name.clone(), servers.collect())
		})
		.collect()
}

impl Service {
	/// What a request to server `index` came to, for `outlier_detection`: the
	/// server is ejected when a threshold is reached, unless that would eject more
	/// than `max_ejected_percent` of the servers. `rule` is for the logs.
	pub fn observe(self: &Arc<Self>, index: usize, outcome: crate::core::outlier::HttpOutcome, rule: crate::core::rule::Key) {
		let (Some(cfg), Some(server)) = (&self.outlier, self.servers.get(index)) else { return };
		if server.status.is_some() {
			return;
		}
		// a request to an ejected server (every other one is out) neither extends nor counts
		if server.ejection.is_ejected() {
			return;
		}
		let Some(cause) = server.ejection.record_http(cfg, outcome) else { return };
		let ejected = self.servers.iter().filter(|s| s.ejection.is_ejected()).count();
		if !cfg.ejecting.allows(ejected, self.servers.len()) {
			tracing::debug!(event = "target.eject_skipped", rule = %rule, service = %self.name, server = %server.url, ejected,
				max_ejected_percent = cfg.ejecting.max_percent);
			return;
		}
		let (length, until) = server.ejection.eject(&cfg.ejecting);
		warn!(event = "target.down", rule = %rule, service = %self.name, server = %server.url, reason = "outlier", cause,
			ejection_secs = length.as_secs_f64(), ejections = server.ejection.ejections());
		let (service, url) = (Arc::downgrade(self), server.url.clone());
		crate::core::outlier::after(&server.ejection, until, length, move || {
			let Some(service) = service.upgrade() else { return };
			info!(event = "target.up", rule = %rule, service = %service.name, server = %url, reason = "outlier");
		});
	}
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
	if server.status.is_some() {
		return (true, String::new());
	}
	let check = async {
		let (stream, picked_h2) = dialer.dial(server, None, service.tls.as_ref()).await?;
		let h2 = match service.protocol {
			UpstreamProtocol::H2 | UpstreamProtocol::H2c => true,
			UpstreamProtocol::Auto => picked_h2,
			UpstreamProtocol::Http1 => false,
		};
		if service.protocol == UpstreamProtocol::H2 && !picked_h2 {
			return Err("the server did not pick h2 (ALPN)".to_string());
		}
		let conn_stop = stop.child_token();
		let sender = handshake(stream, h2, conn_stop.clone(), |f| {
			tokio::spawn(f);
		})
		.await
		.map_err(|e| e.to_string())?;
		let req = Request::get(format!("{}{}", server.prefix, h.path))
			.header(header::HOST, &server.authority)
			.header(header::USER_AGENT, "rproxy-health-check")
			.body(Empty::<Bytes>::new().map_err(|never| match never {}).boxed())
			.map_err(|e| e.to_string())?;
		let resp = match sender {
			Sender::Http1(mut s) => s.send_request(req).await.map_err(|e| e.to_string()),
			Sender::Http2(mut s) => s.send_request(to_h2(req, server.https, false)).await.map_err(|e| e.to_string()),
		};
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
		Service::compile("s", &spec, &BTreeMap::new()).unwrap()
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
		assert!(Service::compile("s", &serde_json::from_value(serde_json::json!({"servers": [{"url": "http://a"}], "sticky": {"cookie": "a b"}})).unwrap(), &BTreeMap::new()).is_err());
	}
}
