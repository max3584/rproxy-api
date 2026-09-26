//! Serving `http` rules: HTTP/1.1 and HTTP/2 from clients (after TLS
//! termination, or plain), routed by `match` to services of HTTP/1.1 backends.

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as _, Incoming};
use hyper::client::conn::http1::SendRequest;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use super::access::{AccessEntry, NO_ROUTE};
use super::auth::{BasicVerdict, ForwardAuth};
use super::oidc::{self, Oidc};
use super::backend::{self, Dialer, ServerHealth, Service};
use super::compress;
use super::crowdsec::Verdict;
use super::limit::Hold;
use super::middleware::{self, Blocked, Ctx, Limited, Middleware};
use super::resilience::{self, RetryPolicy, Ticket};
use super::{HttpSpec, Matcher};
use crate::error::ApiError;
use crate::http::matcher::RequestInfo;
use crate::proxy::Runtime;
use crate::resolve::Lookup;
use crate::source::TlsInfo;
use crate::tlsconf::Upstream;

/// An error of a request or response body: hyper's (HTTP/1.1, HTTP/2) or h3's
/// (HTTP/3). A struct rather than `Box<dyn Error>` itself, which trips the
/// compiler's `Send` checks of the handler's future.
#[derive(Debug)]
pub struct BoxError(Box<dyn std::error::Error + Send + Sync>);

impl BoxError {
	pub fn new(e: impl std::error::Error + Send + Sync + 'static) -> Self {
		BoxError(Box::new(e))
	}
}

impl std::fmt::Display for BoxError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.0.fmt(f)
	}
}

impl std::error::Error for BoxError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		self.0.source()
	}
}

pub type Body = BoxBody<Bytes, BoxError>;

fn boxed_error(e: hyper::Error) -> BoxError {
	BoxError::new(e)
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
	/// Every service, for health reports.
	services: Vec<Arc<Service>>,
	dialer: Dialer,
	/// Stops the health checks when this version of the settings is dropped.
	health_stop: CancellationToken,
	/// `oidc` middlewares: their callback and logout paths are answered before routing.
	oidc: Vec<Arc<Oidc>>,
	/// Middlewares with secret files, re-read on SIGHUP.
	secrets: Vec<Arc<Middleware>>,
}

impl Drop for Router {
	fn drop(&mut self) {
		self.health_stop.cancel();
	}
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
			middlewares.insert(name.clone(), Arc::new(Middleware::errors(name, m, &services)?));
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
		let dialer = Dialer {
			lookup,
			tls: tokio_rustls::TlsConnector::from(Arc::new(config)),
			server_name: upstream.server_name.clone(),
		};
		let routes: Vec<Route> = routes.into_iter().map(|(_, _, r)| r).collect();
		// services named in settings, plus the single ones of `to`
		let mut all: Vec<Arc<Service>> = services.into_values().collect();
		all.sort_by(|a, b| a.name.cmp(&b.name));
		let health_stop = CancellationToken::new();
		for s in &all {
			backend::start_health_checks(s.clone(), dialer.clone(), health_stop.clone());
		}
		let oidc = middlewares.values().filter_map(|m| if let Middleware::Oidc(o) = m.as_ref() { Some(o.clone()) } else { None }).collect();
		let secrets = middlewares.values().filter(|m| matches!(m.as_ref(), Middleware::BasicAuth(_) | Middleware::Oidc(_))).cloned().collect();
		Ok(Router { routes, default_status, default_service, services: all, dialer, health_stop, oidc, secrets })
	}

	/// SIGHUP: read the secret files of the authentication middlewares again.
	pub fn reload_secrets(&self) {
		for m in &self.secrets {
			match m.as_ref() {
				Middleware::BasicAuth(b) => b.users.reload(true),
				Middleware::Oidc(o) => o.reload(),
				_ => {}
			}
		}
	}

	/// Health of the servers of services with `health_check`.
	pub fn health(&self) -> std::collections::BTreeMap<String, Vec<ServerHealth>> {
		backend::health_view(self.services.iter())
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
pub(super) struct Conn {
	rt: Arc<Runtime>,
	client: SocketAddr,
	local: SocketAddr,
	https: bool,
	/// The terminated TLS session (for the access log).
	tls: Option<TlsInfo>,
	/// Over QUIC (HTTP/3); others get `Alt-Svc` when the rule answers HTTP/3.
	h3: bool,
}

impl Conn {
	pub(super) fn new(rt: Arc<Runtime>, client: SocketAddr, local: SocketAddr, tls: Option<TlsInfo>, h3: bool) -> Self {
		Conn { rt, client, local, https: tls.is_some(), tls, h3 }
	}
}

/// Serves HTTP/1.1 and HTTP/2 (by preface) on an accepted, possibly decrypted, connection.
/// `tls` is the terminated session; None for plain HTTP.
pub async fn serve<S>(stream: S, client: SocketAddr, local: SocketAddr, rt: Arc<Runtime>, tls: Option<TlsInfo>) -> io::Result<()>
where
	S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
	let conn = Arc::new(Conn::new(rt, client, local, tls, false));
	let service = hyper::service::service_fn(move |req: Request<Incoming>| {
		let conn = conn.clone();
		async move { Ok::<_, Infallible>(conn.handle(req.map(|b| b.map_err(boxed_error).boxed())).await) }
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

/// An answer of the `oidc` middleware (sign-in redirect, callback, logout, errors).
fn oidc_response(outcome: oidc::Outcome) -> Response<Body> {
	match outcome {
		oidc::Outcome::Respond { status, headers, body } => {
			let mut resp = full(status, body.trim_end());
			if body.is_empty() {
				*resp.body_mut() = empty_body();
				resp.headers_mut().remove(header::CONTENT_TYPE);
			}
			for (k, v) in headers {
				resp.headers_mut().append(k, v);
			}
			resp
		}
		// a signed-in request goes on; only reached for callback / logout paths, which always answer
		oidc::Outcome::Pass { .. } => error_response(StatusCode::NOT_FOUND),
	}
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

enum Failure {
	/// Could not connect (502) or timed out (504).
	Status(StatusCode, String),
}

/// What the response side of the chain needs to know about the request.
struct Sent {
	accept_encoding: String,
	head: bool,
	host: HeaderValue,
	/// Admissions through circuit breakers, by position in the chain.
	tickets: Vec<(usize, Ticket)>,
}

impl Conn {
	pub(super) async fn handle(&self, req: Request<Body>) -> Response<Body> {
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
		let mut sent = Sent {
			accept_encoding: header_text(header::ACCEPT_ENCODING),
			head: req.method() == hyper::Method::HEAD,
			host: req
				.headers()
				.get(header::HOST)
				.cloned()
				.unwrap_or_else(|| HeaderValue::from_str(&host).unwrap_or(HeaderValue::from_static("localhost"))),
			tickets: vec![],
		};
		// request side in the route's order, until one answers
		let (mut parts, mut body) = req.into_parts();
		let mut ran = 0;
		let mut answer = None;
		let mut replay: Option<Bytes> = None;
		let mut retry: Option<RetryPolicy> = None;
		// cookies of the authentication middlewares for the response
		let mut set_cookies: Vec<HeaderValue> = vec![];
		let authority = parts
			.headers
			.get(header::HOST)
			.and_then(|h| h.to_str().ok())
			.map(str::to_string)
			.or_else(|| parts.uri.authority().map(|a| a.to_string()))
			.unwrap_or_else(|| host.clone());
		// sign-in callbacks and logout of `oidc`, whichever route matched
		if let Some(o) = router.oidc.iter().find(|o| o.owns(parts.uri.path())) {
			answer = Some(oidc_response(o.handle(&parts, self.https, &authority).await));
		}
		for (i, m) in chain.iter().enumerate() {
			if answer.is_some() {
				break;
			}
			ran += 1;
			let resp = match m.as_ref() {
				Middleware::BasicAuth(b) => match b.check(&parts.headers).await {
					BasicVerdict::Allow(user) => {
						if !b.keep_authorization {
							parts.headers.remove(header::AUTHORIZATION);
						}
						if let Some(h) = &b.user_header {
							parts.headers.remove(h);
							if let Ok(v) = HeaderValue::from_str(&user) {
								parts.headers.insert(h.clone(), v);
							}
						}
						None
					}
					BasicVerdict::Deny => {
						let mut resp = error_response(StatusCode::UNAUTHORIZED);
						resp.headers_mut().insert(header::WWW_AUTHENTICATE, b.challenge());
						Some(resp)
					}
					BasicVerdict::Unavailable => Some(error_response(StatusCode::SERVICE_UNAVAILABLE)),
				},
				Middleware::ForwardAuth(fa) => self.forward_auth(&router, fa, &mut parts, client_ip, &host).await,
				Middleware::Oidc(o) => match o.handle(&parts, self.https, &authority).await {
					oidc::Outcome::Pass { session, set_cookie } => {
						o.pass_identity(&mut parts.headers, &session);
						set_cookies.extend(set_cookie);
						None
					}
					answer => Some(oidc_response(answer)),
				},
				Middleware::Crowdsec { name, appsec, block_on_error } => {
					self.crowdsec(name, *appsec, *block_on_error, &parts, &mut body, client_ip, &host).await
				}
				Middleware::Buffering { max } => {
					let taken = std::mem::replace(&mut body, empty_body());
					match resilience::buffer(&parts.headers, taken, *max).await {
						Ok(bytes) => {
							body = full_body(bytes.clone());
							replay = Some(bytes);
							None
						}
						Err(true) => Some(error_response(StatusCode::PAYLOAD_TOO_LARGE)),
						Err(false) => Some(error_response(StatusCode::BAD_REQUEST)),
					}
				}
				Middleware::Retry(policy) => {
					retry = Some(*policy);
					None
				}
				Middleware::CircuitBreaker(breaker) => match breaker.admit() {
					Some(ticket) => {
						sent.tickets.push((i, ticket));
						None
					}
					None => Some(error_response(StatusCode::SERVICE_UNAVAILABLE)),
				},
				m => m.on_request(&mut parts, &ctx),
			};
			if let Some(resp) = resp {
				answer = Some(resp);
				break;
			}
		}
		let req = Request::from_parts(parts, body);
		if let Some(limited) = answer.as_ref().and_then(|r| r.extensions().get::<Limited>()) {
			self.rt.http_stats.limited(route_name, &limited.0);
		}
		if let Some(blocked) = answer.as_ref().and_then(|r| r.extensions().get::<Blocked>()) {
			self.rt.http_stats.blocked(route_name, &blocked.0);
		}
		let mut holds = std::mem::take(&mut *ctx.holds.lock().unwrap());
		let mut resp = match (answer, service) {
			(Some(resp), _) => resp,
			(None, Some(service)) => {
				entry.service = service.name.clone();
				let target = Target { router: &router, service: &service, route: route_name, host: &host, client_ip };
				self.forward(target, req, replay, retry, &mut entry.backend, &mut holds).await
			}
			(None, None) if route_name.is_empty() => error_response(router.default_status),
			// validation makes such a route end in an answering middleware
			(None, None) => error_response(StatusCode::NOT_FOUND),
		};
		for c in set_cookies {
			resp.headers_mut().append(header::SET_COOKIE, c);
		}
		// response side in reverse, also for answers of the middlewares
		for (i, m) in chain[..ran].iter().enumerate().rev() {
			resp = self.on_response(&router, m, i, resp, &ctx, &mut sent).await;
		}
		entry.status = resp.status().as_u16();
		// tell HTTP/1.1 and HTTP/2 clients that HTTP/3 is answered on the same port
		if !self.h3 && self.https && !resp.headers().contains_key(header::ALT_SVC) {
			if let Some(port) = self.rt.h3.port() {
				if let Ok(v) = HeaderValue::from_str(&format!("h3=\":{port}\"; ma=86400")) {
					resp.headers_mut().insert(header::ALT_SVC, v);
				}
			}
		}
		// logged and counted when the response body ends
		let rt = self.rt.clone();
		resp.map(|body| Logged { inner: body, bytes: 0, entry, rt, started, _holds: holds }.boxed())
	}

	/// The response side of one middleware.
	async fn on_response(
		&self,
		router: &Router,
		m: &Middleware,
		i: usize,
		mut resp: Response<Body>,
		ctx: &Ctx,
		sent: &mut Sent,
	) -> Response<Body> {
		match m {
			Middleware::CircuitBreaker(_) => {
				if let Some(pos) = sent.tickets.iter().position(|(at, _)| *at == i) {
					let (_, ticket) = sent.tickets.swap_remove(pos);
					ticket.record(resp.status().is_server_error());
				}
				resp
			}
			Middleware::Errors { ranges, service, path } => {
				let status = resp.status().as_u16();
				if resp.status() == StatusCode::SWITCHING_PROTOCOLS || !ranges.iter().any(|(a, b)| (*a..=*b).contains(&status)) {
					return resp;
				}
				match self.error_page(router, service, &path.replace("{status}", &status.to_string()), &sent.host).await {
					Some(page) => {
						let (mut parts, body) = page.into_parts();
						parts.status = resp.status();
						Response::from_parts(parts, body)
					}
					None => resp,
				}
			}
			Middleware::Compress { encodings, min_size } => {
				if !compress::compressible(resp.status(), resp.headers(), *min_size, sent.head) {
					return resp;
				}
				match compress::negotiate(&sent.accept_encoding, encodings) {
					Some(e) => compress::compress(resp, e),
					None => resp,
				}
			}
			m => {
				m.on_response(resp.headers_mut(), ctx);
				resp
			}
		}
	}

	/// The page of an `errors` middleware; None keeps the original response.
	async fn error_page(&self, router: &Router, service: &Arc<Service>, path: &str, host: &HeaderValue) -> Option<Response<Body>> {
		let index = service.pick(None)?;
		let server = &service.servers[index];
		let host = if service.pass_host { host.clone() } else { HeaderValue::from_str(&server.authority).ok()? };
		let req = Request::get(format!("{}{path}", server.prefix)).header(header::HOST, host).body(empty_body()).ok()?;
		match self.send(router, service, index, req).await {
			Ok(resp) => {
				let mut resp = resp;
				strip_hop_by_hop(resp.headers_mut());
				Some(resp)
			}
			Err(Failure::Status(_, error)) => {
				warn!(event = "http.error", rule = %self.rt.key, service = %service.name, backend = %server.addr(), error = %error,
					"error page not available; the original response is sent");
				None
			}
		}
	}

	/// `forward_auth`: asks the auth server; `Some` is its refusal (or an error) for the client.
	async fn forward_auth(
		&self,
		router: &Router,
		fa: &ForwardAuth,
		parts: &mut hyper::http::request::Parts,
		client: IpAddr,
		host: &str,
	) -> Option<Response<Body>> {
		let server = &fa.service.servers[0];
		let mut req = Request::get(fa.path.as_str()).body(empty_body()).ok()?;
		*req.headers_mut() = fa.request_headers(parts, client, self.https, host);
		req.headers_mut().insert(header::HOST, HeaderValue::from_str(&server.authority).ok()?);
		match self.send(router, &fa.service, 0, req).await {
			Ok(resp) if resp.status().is_success() => {
				let (answer, body) = resp.into_parts();
				// read the rest so the connection can be used again
				let _ = body.collect().await;
				fa.copy_answer(&answer.headers, parts);
				None
			}
			Ok(mut resp) => {
				strip_hop_by_hop(resp.headers_mut());
				Some(resp)
			}
			Err(Failure::Status(status, error)) => {
				warn!(event = "http.error", rule = %self.rt.key, middleware = %fa.name, backend = %server.addr(), error = %error,
					"the auth server did not answer");
				Some(error_response(if status == StatusCode::GATEWAY_TIMEOUT { status } else { StatusCode::BAD_GATEWAY }))
			}
		}
	}

	/// The `crowdsec` middleware: the LAPI's decisions, then AppSec. `Some` refuses the request.
	#[allow(clippy::too_many_arguments)]
	async fn crowdsec(
		&self,
		name: &str,
		appsec: bool,
		block_on_error: bool,
		parts: &hyper::http::request::Parts,
		body: &mut Body,
		client: IpAddr,
		host: &str,
	) -> Option<Response<Body>> {
		let Some(bouncer) = self.rt.global.crowdsec() else {
			// validation requires global.crowdsec; a rule restored without it fails closed or open as asked
			return block_on_error.then(|| middleware::blocked(name));
		};
		let fail = || block_on_error.then(|| middleware::blocked(name));
		match bouncer.check_ip(client) {
			Verdict::Block => return Some(middleware::blocked(name)),
			// the LAPI has not answered yet; the pulling task logs why
			Verdict::Error(_) => return fail(),
			Verdict::Allow => {}
		}
		if !appsec {
			return None;
		}
		match bouncer.check_appsec(parts, body, client, host).await {
			Verdict::Allow => None,
			Verdict::Block => Some(middleware::blocked(name)),
			Verdict::Error(e) => {
				warn!(event = "crowdsec.error", rule = %self.rt.key, middleware = name, client = %client, error = %e,
					action = if block_on_error { "block" } else { "allow" });
				fail()
			}
		}
	}

	/// Sends the request to a server of the service: again on another server
	/// (as `retry` allows) when a backend cannot be reached or does not answer.
	async fn forward(
		&self,
		target: Target<'_>,
		mut req: Request<Body>,
		replay: Option<Bytes>,
		retry: Option<RetryPolicy>,
		backend: &mut String,
		holds: &mut Vec<Hold>,
	) -> Response<Body> {
		let Target { router, service, route, host, client_ip } = target;
		let upgrade = if req.version() == Version::HTTP_11 { upgrade_of(req.headers()) } else { None };
		let client_upgrade = upgrade.is_some().then(|| hyper::upgrade::on(&mut req));
		let original_host = req.headers().get(header::HOST).cloned().or_else(|| {
			req.uri().authority().and_then(|a| HeaderValue::from_str(a.as_str()).ok())
		});
		let sticky = service.sticky_value(req.headers());
		// a body can be sent again when it was buffered or there is none
		let replayable = replay.is_some() || req.body().is_end_stream();
		let attempts = match retry {
			Some(p) if upgrade.is_none() && replayable && resilience::idempotent(req.method()) => p.attempts,
			_ => 1,
		};

		let (mut parts, body) = req.into_parts();
		strip_hop_by_hop(&mut parts.headers);
		if let Some(u) = &upgrade {
			parts.headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
			parts.headers.insert(header::UPGRADE, u.clone());
		}
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
		let path_and_query = parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/").to_string();
		let method = parts.method.clone();
		let headers = parts.headers.clone();
		let mut first = Some((parts, body));

		let mut attempt = 0;
		let (mut resp, index) = loop {
			attempt += 1;
			let Some(index) = service.pick(sticky.as_deref()) else {
				warn!(event = "http.error", rule = %self.rt.key, route, service = %service.name, status = 503, error = "no server is up");
				return error_response(StatusCode::SERVICE_UNAVAILABLE);
			};
			let server = &service.servers[index];
			*backend = server.addr();
			let uri: Uri = match format!("{}{}", server.prefix, path_and_query).parse() {
				Ok(u) => u,
				Err(_) => return error_response(StatusCode::BAD_REQUEST),
			};
			let host_value = match (&original_host, service.pass_host) {
				(Some(h), true) => h.clone(),
				_ => HeaderValue::from_str(&server.authority).unwrap_or(HeaderValue::from_static("localhost")),
			};
			let req = match first.take() {
				Some((mut parts, body)) => {
					parts.uri = uri;
					parts.version = Version::HTTP_11;
					parts.headers.insert(header::HOST, host_value);
					let body = match &replay {
						Some(bytes) => full_body(bytes.clone()),
						None => body,
					};
					Request::from_parts(parts, body)
				}
				None => {
					let mut req = Request::new(replay.clone().map(full_body).unwrap_or_else(empty_body));
					*req.method_mut() = method.clone();
					*req.uri_mut() = uri;
					*req.headers_mut() = headers.clone();
					req.headers_mut().insert(header::HOST, host_value);
					req
				}
			};
			match self.send(router, service, index, req).await {
				Ok(resp) => break (resp, index),
				Err(Failure::Status(status, error)) => {
					warn!(event = "http.error", rule = %self.rt.key, route, service = %service.name, backend = %server.addr(),
						status = status.as_u16(), error = %error, attempt, attempts);
					if attempt >= attempts {
						return error_response(status);
					}
					if let Some(p) = retry {
						tokio::time::sleep(p.wait(attempt + 1)).await;
					}
				}
			}
		};
		let server = &service.servers[index];
		if sticky.as_deref() != Some(server.id.as_str()) {
			if let Some(cookie) = service.sticky_cookie(server, self.https) {
				resp.headers_mut().append(header::SET_COOKIE, cookie);
			}
		}

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
				return resp;
			}
		}
		strip_hop_by_hop(resp.headers_mut());
		resp
	}

	/// One request to one server, on a kept connection when there is one. The
	/// connection goes back to the server's pool once the response body has been read.
	async fn send(&self, router: &Router, service: &Arc<Service>, index: usize, req: Request<Body>) -> Result<Response<Body>, Failure> {
		let server = &service.servers[index];
		// connections from the client's address (transparent) are not shared
		let pooled = self.rt.bind_as(self.client).is_none();
		let keep = pooled && !req.headers().contains_key(header::UPGRADE);
		let mut req = req;
		if let Some(mut sender) = pooled.then(|| server.checkout()).flatten() {
			match tokio::time::timeout(service.response, sender.try_send_request(req)).await {
				Err(_) => return Err(Failure::Status(StatusCode::GATEWAY_TIMEOUT, "response timed out".into())),
				Ok(Ok(resp)) => return Ok(self.returning(resp, sender, service, index, keep)),
				// the kept connection closed before the request went out: use a new one
				Ok(Err(mut e)) => match e.take_message() {
					Some(r) => req = r,
					None => return Err(Failure::Status(StatusCode::BAD_GATEWAY, e.into_error().to_string())),
				},
			}
		}
		let mut sender = self.connect(router, service, index).await?;
		let resp = tokio::time::timeout(service.response, sender.send_request(req))
			.await
			.map_err(|_| Failure::Status(StatusCode::GATEWAY_TIMEOUT, "response timed out".into()))?
			.map_err(|e| Failure::Status(StatusCode::BAD_GATEWAY, e.to_string()))?;
		Ok(self.returning(resp, sender, service, index, keep))
	}

	fn returning(&self, resp: Response<Incoming>, sender: SendRequest<Body>, service: &Arc<Service>, index: usize, keep: bool) -> Response<Body> {
		if !keep || resp.status() == StatusCode::SWITCHING_PROTOCOLS {
			return resp.map(|b| b.map_err(boxed_error).boxed());
		}
		let service = service.clone();
		resp.map(|inner| Pooled { inner, back: Some((sender, service, index)) }.boxed())
	}

	async fn connect(&self, router: &Router, service: &Service, index: usize) -> Result<SendRequest<Body>, Failure> {
		let server = &service.servers[index];
		let stream = tokio::time::timeout(service.connect, router.dialer.dial(server, self.rt.bind_as(self.client)))
			.await
			.map_err(|_| Failure::Status(StatusCode::GATEWAY_TIMEOUT, "connect timed out".into()))?
			.map_err(|e| Failure::Status(StatusCode::BAD_GATEWAY, e))?;
		let tracker = self.rt.tracker.clone();
		backend::handshake(stream, self.rt.kill.clone(), move |f| {
			tracker.spawn(f);
		})
		.await
		.map_err(|e| Failure::Status(StatusCode::BAD_GATEWAY, e.to_string()))
	}
}

/// Where `forward` sends a request.
struct Target<'a> {
	router: &'a Router,
	service: &'a Arc<Service>,
	route: &'a str,
	host: &'a str,
	client_ip: IpAddr,
}

fn empty_body() -> Body {
	http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

fn full_body(bytes: Bytes) -> Body {
	Full::new(bytes).map_err(|never| match never {}).boxed()
}

/// A backend's response body; its connection is kept for the next request once
/// the body has been read to the end.
struct Pooled {
	inner: Incoming,
	back: Option<(SendRequest<Body>, Arc<Service>, usize)>,
}

impl hyper::body::Body for Pooled {
	type Data = Bytes;
	type Error = BoxError;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
		let poll = Pin::new(&mut self.inner).poll_frame(cx).map_err(boxed_error);
		if matches!(poll, Poll::Ready(None)) || self.inner.is_end_stream() {
			if let Some((sender, service, index)) = self.back.take() {
				service.servers[index].checkin(sender);
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
	type Error = BoxError;

	fn poll_frame(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Option<Result<hyper::body::Frame<Bytes>, BoxError>>> {
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
		Router::compile(&spec, &Upstream::default(), crate::resolve::system_lookup()).unwrap()
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
	fn default_service_and_health_report() {
		let r = router("routes: []\nservices:\n  s: {servers: [{url: 'http://10.0.0.1'}], health_check: {path: /health}}\n  t: {servers: [{url: 'http://10.0.0.2'}]}\ndefault: {service: s}\n");
		assert_eq!(r.default_service.as_ref().unwrap().name, "s");
		let health = r.health();
		assert_eq!(health.keys().collect::<Vec<_>>(), ["s"], "only services with health_check");
		assert_eq!(health["s"], [ServerHealth { url: "http://10.0.0.1".into(), up: true }], "up until a check fails");
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
