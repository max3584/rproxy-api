//! Serving `http` rules: HTTP/1.1 and HTTP/2 from clients (after TLS
//! termination, or plain), routed by `match` to services of HTTP/1.1 backends.

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::warn;

use super::access::{AccessEntry, NO_ROUTE};
use super::limit::Hold;
use super::middleware::{Ctx, Limited, Middleware};
use super::{parse_duration, HttpSpec, Matcher, ServiceSpec};
use crate::error::ApiError;
use crate::http::matcher::RequestInfo;
use crate::proxy::Runtime;
use crate::resolve::{self, Lookup};
use crate::source::TlsInfo;
use crate::tlsconf::Upstream;

pub type Body = BoxBody<Bytes, hyper::Error>;

const DEFAULT_CONNECT: Duration = Duration::from_secs(5);
const DEFAULT_RESPONSE: Duration = Duration::from_secs(60);

/// One backend of a service.
#[derive(Debug)]
struct Server {
	https: bool,
	host: String,
	port: u16,
	/// `host[:port]` as written, for the Host header when `pass_host_header` is false.
	authority: String,
	/// Path of the URL without the trailing slash; prepended to request paths.
	prefix: String,
	weight: u64,
}

impl Server {
	fn parse(url: &str, weight: u32) -> Result<Server, ApiError> {
		let uri: Uri = url.parse().map_err(|e| ApiError::invalid(format!("{url:?}: {e}")))?;
		let https = uri.scheme_str() == Some("https");
		let authority = uri.authority().ok_or_else(|| ApiError::invalid(format!("{url:?} has no host")))?;
		let host = authority.host().trim_matches(|c| c == '[' || c == ']').to_string();
		Ok(Server {
			https,
			port: authority.port_u16().unwrap_or(if https { 443 } else { 80 }),
			host,
			authority: authority.as_str().to_string(),
			prefix: uri.path().trim_end_matches('/').to_string(),
			weight: u64::from(weight.max(1)),
		})
	}
}

/// A service: weighted round robin over its servers.
#[derive(Debug)]
struct Service {
	name: String,
	servers: Vec<Server>,
	total_weight: u64,
	next: AtomicU64,
	pass_host: bool,
	connect: Duration,
	response: Duration,
}

impl Service {
	fn compile(name: &str, spec: &ServiceSpec) -> Result<Service, ApiError> {
		let servers = spec
			.servers
			.iter()
			.map(|s| Server::parse(&s.url, s.weight.unwrap_or(1)))
			.collect::<Result<Vec<_>, _>>()?;
		let duration = |d: Option<&String>, default| match d {
			Some(d) => parse_duration(d).map_err(ApiError::invalid),
			None => Ok(default),
		};
		let timeouts = spec.timeouts.as_ref();
		Ok(Service {
			name: name.to_string(),
			total_weight: servers.iter().map(|s| s.weight).sum(),
			servers,
			next: AtomicU64::new(0),
			pass_host: spec.pass_host_header.unwrap_or(true),
			connect: duration(timeouts.and_then(|t| t.connect.as_ref()), DEFAULT_CONNECT)?,
			response: duration(timeouts.and_then(|t| t.response.as_ref()), DEFAULT_RESPONSE)?,
		})
	}

	fn single(url: &str) -> Result<Service, ApiError> {
		let spec = ServiceSpec {
			servers: vec![super::ServerSpec { url: url.to_string(), weight: None }],
			health_check: None,
			sticky: None,
			pass_host_header: None,
			timeouts: None,
		};
		Service::compile(url, &spec)
	}

	fn pick(&self) -> &Server {
		let mut n = self.next.fetch_add(1, Ordering::Relaxed) % self.total_weight;
		for s in &self.servers {
			if n < s.weight {
				return s;
			}
			n -= s.weight;
		}
		&self.servers[0]
	}
}

#[derive(Debug)]
struct Route {
	name: String,
	matcher: Matcher,
	service: Option<Arc<Service>>,
	middlewares: Vec<Arc<Middleware>>,
}

/// The compiled `http` of a rule. Replaced as a whole when the rule changes,
/// so requests always see one consistent version.
pub struct Router {
	routes: Vec<Route>,
	default_status: StatusCode,
	default_service: Option<Arc<Service>>,
	lookup: Lookup,
	/// For https:// backends: `tls.upstream` of the rule, or the Mozilla roots.
	backend_tls: tokio_rustls::TlsConnector,
	backend_server_name: Option<String>,
}

impl std::fmt::Debug for Router {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Router").field("routes", &self.routes).finish_non_exhaustive()
	}
}

impl Router {
	pub fn compile(spec: &HttpSpec, upstream: &Upstream, lookup: Lookup) -> Result<Router, ApiError> {
		let mut services = std::collections::HashMap::new();
		for (name, s) in &spec.services {
			services.insert(name.clone(), Arc::new(Service::compile(name, s)?));
		}
		let mut middlewares = std::collections::HashMap::new();
		for (name, m) in &spec.middlewares {
			middlewares.insert(name.clone(), Arc::new(Middleware::compile(name, m)?));
		}
		let mut routes = vec![];
		for (i, r) in spec.routes.iter().enumerate() {
			let chain = r
				.middlewares
				.iter()
				.map(|m| middlewares.get(m).cloned().ok_or_else(|| ApiError::invalid(format!("middleware {m:?} is not defined"))))
				.collect::<Result<Vec<_>, _>>()?;
			let matcher = Matcher::parse(&r.rule).map_err(|e| ApiError::invalid(format!("route {}: match: {e}", r.name)))?;
			let service = match (&r.service, &r.to) {
				(Some(s), _) => Some(services.get(s).cloned().ok_or_else(|| ApiError::invalid(format!("service {s:?} is not defined")))?),
				(None, Some(to)) => Some(Arc::new(Service::single(to)?)),
				(None, None) => None,
			};
			let priority = r.priority.unwrap_or_else(|| Matcher::default_priority(&r.rule));
			routes.push((priority, i, Route { name: r.name.clone(), matcher, service, middlewares: chain }));
		}
		// higher priority first; the order in the settings breaks ties
		routes.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
		let default = spec.default.as_ref();
		let default_service = match default.and_then(|d| d.service.as_ref()) {
			Some(s) => Some(services.get(s).cloned().ok_or_else(|| ApiError::invalid(format!("service {s:?} is not defined")))?),
			None => None,
		};
		let default_status = StatusCode::from_u16(default.map(|d| d.status).unwrap_or(404))
			.map_err(|e| ApiError::invalid(format!("default: {e}")))?;
		let mut config: ClientConfig = (*crate::tlsconf::client_config(upstream)?).clone();
		config.alpn_protocols = vec![b"http/1.1".to_vec()];
		Ok(Router {
			routes: routes.into_iter().map(|(_, _, r)| r).collect(),
			default_status,
			default_service,
			lookup,
			backend_tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
			backend_server_name: upstream.server_name.clone(),
		})
	}

	fn route(&self, info: &RequestInfo) -> Option<&Route> {
		self.routes.iter().find(|r| r.matcher.matches(info))
	}
}

/// Counts bytes of one client connection into the rule's statistics.
pub struct Metered<S> {
	inner: S,
	rt: Arc<Runtime>,
	/// This connection's bytes from and to the client.
	rx: Arc<AtomicU64>,
	tx: Arc<AtomicU64>,
}

impl<S> Metered<S> {
	pub fn new(inner: S, rt: Arc<Runtime>, rx: Arc<AtomicU64>, tx: Arc<AtomicU64>) -> Self {
		Metered { inner, rt, rx, tx }
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		let before = buf.filled().len();
		let poll = Pin::new(&mut this.inner).poll_read(cx, buf);
		let n = (buf.filled().len() - before) as u64;
		if n > 0 {
			this.rx.fetch_add(n, Ordering::Relaxed);
			this.rt.stats.add_rx(n);
		}
		poll
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
		if let Poll::Ready(Ok(n)) = poll {
			this.tx.fetch_add(n as u64, Ordering::Relaxed);
			this.rt.stats.add_tx(n as u64);
		}
		poll
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}
}

/// One client connection.
struct Conn {
	rt: Arc<Runtime>,
	client: SocketAddr,
	local: SocketAddr,
	https: bool,
	/// The terminated TLS session (for the access log).
	tls: Option<TlsInfo>,
}

/// Serves HTTP/1.1 and HTTP/2 (by preface) on an accepted, possibly decrypted, connection.
/// `tls` is the terminated session; None for plain HTTP.
pub async fn serve<S>(stream: S, client: SocketAddr, local: SocketAddr, rt: Arc<Runtime>, tls: Option<TlsInfo>) -> io::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let conn = Arc::new(Conn { rt, client, local, https: tls.is_some(), tls });
	let service = hyper::service::service_fn(move |req| {
		let conn = conn.clone();
		async move { Ok::<_, Infallible>(conn.handle(req).await) }
	});
	let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
	builder.http1().timer(TokioTimer::new());
	builder.http2().timer(TokioTimer::new());
	builder.serve_connection_with_upgrades(TokioIo::new(stream), service).await.map_err(io::Error::other)
}

fn full(status: StatusCode, text: &str) -> Response<Body> {
	let mut resp = Response::new(Full::new(Bytes::from(format!("{text}\n"))).map_err(|never| match never {}).boxed());
	*resp.status_mut() = status;
	resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
	resp
}

fn error_response(status: StatusCode) -> Response<Body> {
	full(status, &status.to_string())
}

/// Host of the request without the port (Host header, or :authority for HTTP/2).
fn request_host<B>(req: &Request<B>) -> Option<String> {
	let raw = match req.headers().get(header::HOST).and_then(|h| h.to_str().ok()) {
		Some(h) => h.to_string(),
		None => req.uri().authority()?.as_str().to_string(),
	};
	Some(strip_port(&raw).to_ascii_lowercase())
}

fn strip_port(host: &str) -> &str {
	if let Some(rest) = host.strip_prefix('[') {
		return rest.split(']').next().unwrap_or(rest);
	}
	match host.rsplit_once(':') {
		Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
		_ => host,
	}
}

const HOP_BY_HOP: [HeaderName; 8] = [
	header::CONNECTION,
	HeaderName::from_static("keep-alive"),
	HeaderName::from_static("proxy-connection"),
	header::PROXY_AUTHENTICATE,
	header::PROXY_AUTHORIZATION,
	header::TE,
	header::TRAILER,
	header::TRANSFER_ENCODING,
];

/// Removes hop-by-hop headers (and those listed in Connection). `Upgrade` goes too;
/// the caller puts it back for an upgrade it passes through.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
	let listed: Vec<HeaderName> = headers
		.get_all(header::CONNECTION)
		.iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|v| v.split(','))
		.filter_map(|n| HeaderName::from_bytes(n.trim().as_bytes()).ok())
		.collect();
	for name in listed.iter().chain(HOP_BY_HOP.iter()) {
		headers.remove(name);
	}
	headers.remove(header::UPGRADE);
}

/// The protocol a client asks to switch to (`Connection: upgrade` + `Upgrade`).
fn upgrade_of(headers: &HeaderMap) -> Option<HeaderValue> {
	let wants = headers
		.get_all(header::CONNECTION)
		.iter()
		.filter_map(|v| v.to_str().ok())
		.flat_map(|v| v.split(','))
		.any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
	if wants {
		headers.get(header::UPGRADE).cloned()
	} else {
		None
	}
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

enum Failure {
	/// Could not connect (502) or timed out (504).
	Status(StatusCode, String),
}

impl Conn {
	async fn handle(&self, req: Request<Incoming>) -> Response<Body> {
		let Some(router) = self.rt.http_router() else {
			return error_response(StatusCode::SERVICE_UNAVAILABLE);
		};
		let started = Instant::now();
		let host = request_host(&req).unwrap_or_default();
		// the client: the peer, or what a trusted proxy in front says (global.trusted_proxies)
		let peer = canonical(self.client.ip());
		let global = &self.rt.global;
		let client_ip = global.client_ip(peer, req.headers().get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()));
		let headers: Vec<(String, String)> = req
			.headers()
			.iter()
			.map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
			.collect();
		let info = RequestInfo {
			host: &host,
			path: req.uri().path(),
			query: req.uri().query().unwrap_or(""),
			method: req.method().as_str(),
			headers: &headers,
			client: client_ip,
		};
		let (route_name, service, chain) = match router.route(&info) {
			Some(r) => (r.name.as_str(), r.service.clone(), r.middlewares.as_slice()),
			None => ("", router.default_service.clone(), &[][..]),
		};
		let header_text = |name: header::HeaderName| req.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
		let mut entry = AccessEntry {
			rule: self.rt.key.to_string(),
			route: if route_name.is_empty() { NO_ROUTE.to_string() } else { route_name.to_string() },
			client: client_ip.to_string(),
			method: req.method().to_string(),
			host: host.clone(),
			path: req.uri().path().to_string(),
			protocol: format!("{:?}", req.version()),
			bytes_in: header_text(header::CONTENT_LENGTH).parse().unwrap_or(0),
			user_agent: header_text(header::USER_AGENT),
			sni: self.tls.as_ref().and_then(|t| t.server_name.clone()).unwrap_or_default(),
			tls_version: self.tls.as_ref().and_then(|t| t.version.clone()).unwrap_or_default(),
			..Default::default()
		};
		let ctx = Ctx {
			client: client_ip,
			https: self.https,
			host: host.clone(),
			origin: req.headers().get(header::ORIGIN).cloned(),
			holds: Default::default(),
		};
		// request side in the route's order, until one answers
		let (mut parts, body) = req.into_parts();
		let mut ran = 0;
		let mut answer = None;
		for m in chain {
			ran += 1;
			if let Some(resp) = m.on_request(&mut parts, &ctx) {
				answer = Some(resp);
				break;
			}
		}
		let req = Request::from_parts(parts, body);
		if let Some(limited) = answer.as_ref().and_then(|r| r.extensions().get::<Limited>()) {
			self.rt.http_stats.limited(route_name, &limited.0);
		}
		let mut holds = std::mem::take(&mut *ctx.holds.lock().unwrap());
		let mut resp = match (answer, service) {
			(Some(resp), _) => resp,
			(None, Some(service)) => {
				entry.service = service.name.clone();
				self.forward(&router, &service, route_name, req, &host, client_ip, &mut entry.backend, &mut holds).await
			}
			(None, None) if route_name.is_empty() => error_response(router.default_status),
			// validation makes such a route end in an answering middleware
			(None, None) => error_response(StatusCode::NOT_FOUND),
		};
		// response side in reverse, also for answers of the middlewares
		for m in chain[..ran].iter().rev() {
			m.on_response(resp.headers_mut(), &ctx);
		}
		entry.status = resp.status().as_u16();
		// logged and counted when the response body ends
		let rt = self.rt.clone();
		resp.map(|body| Logged { inner: body, bytes: 0, entry, rt, started, _holds: holds }.boxed())
	}

	#[allow(clippy::too_many_arguments)]
	async fn forward(
		&self,
		router: &Router,
		service: &Service,
		route: &str,
		mut req: Request<Incoming>,
		host: &str,
		client_ip: IpAddr,
		backend: &mut String,
		holds: &mut Vec<Hold>,
	) -> Response<Body> {
		let server = service.pick();
		*backend = format!("{}:{}", server.host, server.port);
		let path_and_query = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
		let uri: Uri = match format!("{}{}", server.prefix, path_and_query).parse() {
			Ok(u) => u,
			Err(_) => return error_response(StatusCode::BAD_REQUEST),
		};
		let upgrade = if req.version() == Version::HTTP_11 { upgrade_of(req.headers()) } else { None };
		let client_upgrade = upgrade.is_some().then(|| hyper::upgrade::on(&mut req));
		let original_host = req.headers().get(header::HOST).cloned().or_else(|| {
			req.uri().authority().and_then(|a| HeaderValue::from_str(a.as_str()).ok())
		});

		let (mut parts, body) = req.into_parts();
		strip_hop_by_hop(&mut parts.headers);
		if let Some(u) = &upgrade {
			parts.headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
			parts.headers.insert(header::UPGRADE, u.clone());
		}
		let host_value = match (&original_host, service.pass_host) {
			(Some(h), true) => h.clone(),
			_ => HeaderValue::from_str(&server.authority).unwrap_or(HeaderValue::from_static("localhost")),
		};
		parts.headers.insert(header::HOST, host_value);
		// X-Forwarded-* from the client are believed only from trusted proxies (global.trusted_proxies):
		// then the chain is extended and their Proto / Host / Port are kept
		let peer = canonical(self.client.ip());
		let trusted = self.rt.global.trusts(peer);
		let set = |headers: &mut HeaderMap, name: &'static str, value: &str| {
			let name = HeaderName::from_static(name);
			if trusted && headers.contains_key(&name) {
				return;
			}
			if let Ok(v) = HeaderValue::from_str(value) {
				headers.insert(name, v);
			}
		};
		let chain: Vec<&str> = if trusted {
			parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect()
		} else {
			vec![]
		};
		let forwarded_for = chain.iter().copied().chain([peer.to_string().as_str()]).collect::<Vec<_>>().join(", ");
		if let Ok(v) = HeaderValue::from_str(&forwarded_for) {
			parts.headers.insert(HeaderName::from_static("x-forwarded-for"), v);
		}
		if let Ok(v) = HeaderValue::from_str(&client_ip.to_string()) {
			parts.headers.insert(HeaderName::from_static("x-real-ip"), v);
		}
		set(&mut parts.headers, "x-forwarded-proto", if self.https { "https" } else { "http" });
		set(&mut parts.headers, "x-forwarded-port", &self.local.port().to_string());
		if let Some(h) = original_host.as_ref().and_then(|h| h.to_str().ok()) {
			set(&mut parts.headers, "x-forwarded-host", h);
		} else if !host.is_empty() {
			set(&mut parts.headers, "x-forwarded-host", host);
		}
		parts.uri = uri;
		parts.version = Version::HTTP_11;
		let req = Request::from_parts(parts, body);

		let result = async {
			let mut sender = self.connect(router, service, server).await?;
			tokio::time::timeout(service.response, sender.send_request(req))
				.await
				.map_err(|_| Failure::Status(StatusCode::GATEWAY_TIMEOUT, "response timed out".into()))?
				.map_err(|e| Failure::Status(StatusCode::BAD_GATEWAY, e.to_string()))
		}
		.await;
		let mut resp = match result {
			Ok(resp) => resp,
			Err(Failure::Status(status, error)) => {
				warn!(event = "http.error", rule = %self.rt.key, route, service = %service.name,
					backend = %format!("{}:{}", server.host, server.port), status = status.as_u16(), error = %error);
				return error_response(status);
			}
		};

		if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
			if let Some(client_upgrade) = client_upgrade {
				let backend_upgrade = hyper::upgrade::on(&mut resp);
				let rt = self.rt.clone();
				// an upgraded connection keeps its in_flight places until it ends
				let holds = std::mem::take(holds);
				self.rt.tracker.spawn(async move {
					let _holds = holds;
					let relay = async {
						let (client, backend) = tokio::try_join!(client_upgrade, backend_upgrade).ok()?;
						let (mut client, mut backend) = (TokioIo::new(client), TokioIo::new(backend));
						tokio::io::copy_bidirectional(&mut client, &mut backend).await.ok()
					};
					tokio::select! {
						_ = rt.kill.cancelled() => {}
						_ = relay => {}
					}
				});
				return resp.map(|b| b.boxed());
			}
		}
		strip_hop_by_hop(resp.headers_mut());
		resp.map(|b| b.boxed())
	}

	async fn connect(
		&self,
		router: &Router,
		service: &Service,
		server: &Server,
	) -> Result<hyper::client::conn::http1::SendRequest<Incoming>, Failure> {
		let bad = |e: String| Failure::Status(StatusCode::BAD_GATEWAY, e);
		let connecting = async {
			let addrs = match server.host.parse::<IpAddr>() {
				Ok(ip) => vec![SocketAddr::new(ip, server.port)],
				Err(_) => resolve::resolve(&router.lookup, &format!("{}:{}", server.host, server.port))
					.await
					.map_err(|e| bad(e.message))?,
			};
			let mut last = String::from("no addresses");
			let mut tcp = None;
			for addr in addrs {
				match crate::source::connect_tcp(addr, self.rt.bind_as(self.client)).await {
					Ok(s) => {
						tcp = Some(s);
						break;
					}
					Err(e) => last = format!("{addr}: {e}"),
				}
			}
			let tcp = tcp.ok_or_else(|| bad(last))?;
			let _ = tcp.set_nodelay(true);
			let stream: Box<dyn Stream> = if server.https {
				let name = router.backend_server_name.clone().unwrap_or_else(|| server.host.clone());
				let name = ServerName::try_from(name).map_err(|e| bad(e.to_string()))?;
				Box::new(router.backend_tls.connect(name, tcp).await.map_err(|e| bad(format!("TLS: {e}")))?)
			} else {
				Box::new(tcp)
			};
			Ok(stream)
		};
		let stream = tokio::time::timeout(service.connect, connecting)
			.await
			.map_err(|_| Failure::Status(StatusCode::GATEWAY_TIMEOUT, "connect timed out".into()))??;
		let (sender, conn) = hyper::client::conn::http1::Builder::new()
			.handshake::<_, Incoming>(TokioIo::new(stream))
			.await
			.map_err(|e| bad(e.to_string()))?;
		let kill = self.rt.kill.clone();
		self.rt.tracker.spawn(async move {
			tokio::select! {
				_ = kill.cancelled() => {}
				_ = conn.with_upgrades() => {}
			}
		});
		Ok(sender)
	}
}

/// A response body that writes the access log line and counts the request once
/// it has been sent completely (or the client went away).
struct Logged {
	inner: Body,
	bytes: u64,
	entry: AccessEntry,
	rt: Arc<Runtime>,
	started: Instant,
	/// `in_flight` places, freed with the response.
	_holds: Vec<Hold>,
}

impl hyper::body::Body for Logged {
	type Data = Bytes;
	type Error = hyper::Error;

	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
		let poll = Pin::new(&mut self.inner).poll_frame(cx);
		if let Poll::Ready(Some(Ok(frame))) = &poll {
			if let Some(data) = frame.data_ref() {
				self.bytes += data.len() as u64;
			}
		}
		poll
	}

	fn is_end_stream(&self) -> bool {
		self.inner.is_end_stream()
	}

	fn size_hint(&self) -> hyper::body::SizeHint {
		self.inner.size_hint()
	}
}

impl Drop for Logged {
	fn drop(&mut self) {
		let elapsed = self.started.elapsed();
		self.entry.duration_ms = elapsed.as_millis() as u64;
		self.entry.bytes_out = self.bytes;
		self.rt.http_stats.record(&self.entry.route, self.entry.status, elapsed);
		self.rt.global.log(&self.entry);
	}
}

/// IPv4-mapped IPv6 clients as IPv4, like `allow_from`.
fn canonical(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
		v4 => v4,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn router(yaml: &str) -> Router {
		let spec: HttpSpec = serde_json::from_value(serde_yaml_ng::from_str::<serde_json::Value>(yaml).unwrap()).unwrap();
		spec.validate().unwrap();
		Router::compile(&spec, &Upstream::default(), resolve::system_lookup()).unwrap()
	}

	fn route<'a>(r: &'a Router, host: &str, path: &str) -> &'a str {
		let info = RequestInfo { host, path, query: "", method: "GET", headers: &[], client: "10.0.0.1".parse().unwrap() };
		r.route(&info).map(|r| r.name.as_str()).unwrap_or("")
	}

	#[test]
	fn longer_matches_win_unless_a_priority_is_given() {
		let r = router(
			"routes:\n- {name: all, match: 'Host(`a.example`)', to: 'http://127.0.0.1:1'}\n- {name: api, match: 'Host(`a.example`) && PathPrefix(`/api/`)', to: 'http://127.0.0.1:1'}\n- {name: forced, match: 'Path(`/x`)', priority: 1000, to: 'http://127.0.0.1:1'}\n",
		);
		assert_eq!(route(&r, "a.example", "/"), "all");
		assert_eq!(route(&r, "a.example", "/api/v4"), "api");
		assert_eq!(route(&r, "a.example", "/x"), "forced");
		assert_eq!(route(&r, "b.example", "/"), "");
	}

	#[test]
	fn weighted_round_robin() {
		let r = router("routes: []\nservices:\n  s: {servers: [{url: 'http://10.0.0.1', weight: 3}, {url: 'https://b.example:8443/base/', weight: 1}]}\ndefault: {service: s}\n");
		let s = r.default_service.as_ref().unwrap();
		let picks: Vec<&str> = (0..8).map(|_| s.pick().host.as_str()).collect();
		assert_eq!(picks.iter().filter(|h| **h == "10.0.0.1").count(), 6);
		let b = &s.servers[1];
		assert_eq!((b.https, b.port, b.prefix.as_str(), b.authority.as_str()), (true, 8443, "/base", "b.example:8443"));
		assert_eq!((s.servers[0].port, s.servers[0].prefix.as_str()), (80, ""));
	}

	#[test]
	fn hosts_and_hop_by_hop_headers() {
		assert_eq!(strip_port("a.example:8080"), "a.example");
		assert_eq!(strip_port("[2001:db8::1]:443"), "2001:db8::1");
		assert_eq!(strip_port("a.example"), "a.example");
		let mut h = HeaderMap::new();
		h.insert(header::CONNECTION, HeaderValue::from_static("keep-alive, x-secret"));
		h.insert("x-secret", HeaderValue::from_static("1"));
		h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
		h.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
		h.insert("x-kept", HeaderValue::from_static("1"));
		assert!(upgrade_of(&h).is_none(), "Connection does not ask for an upgrade");
		strip_hop_by_hop(&mut h);
		assert_eq!(h.keys().map(|k| k.as_str()).collect::<Vec<_>>(), ["x-kept"]);
	}
}
