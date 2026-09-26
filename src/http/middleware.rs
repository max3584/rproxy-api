//! Middlewares: redirects, fixed answers, client address checks, headers and
//! path rewriting (#53, #60, #62), and the limits of `limit.rs` (#54). The
//! request side runs in the route's order; the response side in reverse, as in
//! Traefik.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, Response, StatusCode, Uri};
use regex::Regex;

use super::backend::Service;
use super::compress::{self, Encoding};
use super::limit::{Hold, InFlight, RateLimiter, Source};
use super::resilience::{Breaker, RetryPolicy, DEFAULT_RETRY_INTERVAL};
use super::server::Body;
use super::{parse_duration, parse_status_range, CorsSpec, HeaderOps, HstsSpec, MiddlewareSpec};
use crate::cidr::{self, Cidr};
use crate::error::ApiError;

/// What a middleware sees of the request besides its parts.
pub struct Ctx {
	/// The client (TCP peer), IPv4-mapped addresses as IPv4.
	pub client: IpAddr,
	/// The client talks TLS to rproxy.
	pub https: bool,
	/// Host without the port.
	pub host: String,
	/// `Origin` of the request as received (CORS).
	pub origin: Option<HeaderValue>,
	/// Places taken by `in_flight`; kept until the response has been sent.
	pub holds: Mutex<Vec<Hold>>,
}

/// Marks a response refused by `rate_limit` / `in_flight`, with the middleware's name (metrics).
#[derive(Clone, Debug)]
pub struct Limited(pub String);

/// Marks a response refused by `crowdsec`, with the middleware's name (metrics).
#[derive(Clone, Debug)]
pub struct Blocked(pub String);

#[derive(Debug)]
pub struct Headers {
	request: HeaderOps,
	response: HeaderOps,
	hsts: Option<HstsSpec>,
	/// Security headers set on every response.
	fixed: Vec<(HeaderName, HeaderValue)>,
	cors: Option<CorsSpec>,
}

/// A compiled middleware.
#[derive(Debug)]
pub enum Middleware {
	RedirectScheme { scheme: String, port: Option<u16>, permanent: bool },
	RedirectRegex { regex: Regex, replacement: String, permanent: bool },
	Respond { status: StatusCode, body: String, content_type: HeaderValue },
	IpAllow(Vec<Cidr>),
	Headers(Box<Headers>),
	StripPrefix(Vec<String>),
	AddPrefix(String),
	ReplacePath(String),
	ReplacePathRegex { regex: Regex, replacement: String },
	RateLimit { name: String, limiter: RateLimiter },
	InFlight { name: String, limiter: Arc<InFlight> },
	/// Asked asynchronously by the server (`crowdsec.rs`); `on_request` passes it by.
	Crowdsec { name: String, appsec: bool, block_on_error: bool },
	/// The ones below are run by the server (they need the body, the response
	/// or the backend); `on_request` / `on_response` pass them by.
	Compress { encodings: Vec<Encoding>, min_size: u64 },
	Buffering { max: u64 },
	Retry(RetryPolicy),
	CircuitBreaker(Arc<Breaker>),
	Errors { ranges: Vec<(u16, u16)>, service: Arc<Service>, path: String },
}

fn value(v: &str, what: &str) -> Result<HeaderValue, ApiError> {
	HeaderValue::from_str(v).map_err(|_| ApiError::invalid(format!("{what}: {v:?} is not a valid header value")))
}

fn name(n: &str, what: &str) -> Result<HeaderName, ApiError> {
	HeaderName::from_bytes(n.as_bytes()).map_err(|_| ApiError::invalid(format!("{what}: {n:?} is not a valid header name")))
}

fn check_ops(ops: &HeaderOps, what: &str) -> Result<(), ApiError> {
	for (n, v) in &ops.set {
		name(n, what)?;
		value(v, what)?;
	}
	for n in &ops.remove {
		name(n, what)?;
	}
	Ok(())
}

impl Middleware {
	/// Compiles a middleware of a kind in `Features::CURRENT.middlewares`.
	pub fn compile(label: &str, spec: &MiddlewareSpec) -> Result<Middleware, ApiError> {
		let regex = |r: &str| Regex::new(r).map_err(|e| ApiError::invalid(format!("middleware {label}: {e}")));
		let what = format!("middleware {label}");
		Ok(match spec {
			MiddlewareSpec::RedirectScheme { scheme, port, permanent } => {
				Middleware::RedirectScheme { scheme: scheme.clone(), port: *port, permanent: *permanent }
			}
			MiddlewareSpec::RedirectRegex { regex: r, replacement, permanent } => {
				Middleware::RedirectRegex { regex: regex(r)?, replacement: replacement.clone(), permanent: *permanent }
			}
			MiddlewareSpec::Respond { status, body, content_type } => Middleware::Respond {
				status: StatusCode::from_u16(*status).map_err(|e| ApiError::invalid(format!("{what}: {e}")))?,
				body: body.clone().unwrap_or_default(),
				content_type: value(content_type.as_deref().unwrap_or("text/plain; charset=utf-8"), &what)?,
			},
			MiddlewareSpec::IpAllow { source_range } => Middleware::IpAllow(cidr::parse_list(source_range)?),
			MiddlewareSpec::Headers {
				request,
				response,
				hsts,
				frame_deny,
				content_type_nosniff,
				referrer_policy,
				csp,
				cors,
			} => {
				let (request, response) = (request.clone().unwrap_or_default(), response.clone().unwrap_or_default());
				check_ops(&request, &what)?;
				check_ops(&response, &what)?;
				let mut fixed = vec![];
				if *frame_deny {
					fixed.push((header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")));
				}
				if *content_type_nosniff {
					fixed.push((header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")));
				}
				if let Some(p) = referrer_policy {
					fixed.push((header::REFERRER_POLICY, value(p, &what)?));
				}
				if let Some(p) = csp {
					fixed.push((header::CONTENT_SECURITY_POLICY, value(p, &what)?));
				}
				if let Some(c) = cors {
					for v in c.allow_origins.iter().chain(&c.allow_methods).chain(&c.allow_headers) {
						value(v, &what)?;
					}
				}
				Middleware::Headers(Box::new(Headers { request, response, hsts: hsts.clone(), fixed, cors: cors.clone() }))
			}
			MiddlewareSpec::StripPrefix { prefixes } => Middleware::StripPrefix(prefixes.clone()),
			MiddlewareSpec::AddPrefix { prefix } => Middleware::AddPrefix(prefix.trim_end_matches('/').to_string()),
			MiddlewareSpec::ReplacePath { path } => Middleware::ReplacePath(path.clone()),
			MiddlewareSpec::ReplacePathRegex { regex: r, replacement } => {
				Middleware::ReplacePathRegex { regex: regex(r)?, replacement: replacement.clone() }
			}
			MiddlewareSpec::RateLimit { average, period, burst, source } => Middleware::RateLimit {
				name: label.to_string(),
				limiter: RateLimiter::new(
					*average,
					parse_duration(period).map_err(|e| ApiError::invalid(format!("{what}: period: {e}")))?,
					*burst,
					Source::parse(source).map_err(|e| ApiError::invalid(format!("{what}: {}", e.message)))?,
				),
			},
			MiddlewareSpec::InFlight { amount } => Middleware::InFlight { name: label.to_string(), limiter: InFlight::new(*amount) },
			MiddlewareSpec::Crowdsec { appsec, on_error } => {
				Middleware::Crowdsec { name: label.to_string(), appsec: *appsec, block_on_error: on_error == "block" }
			}
			MiddlewareSpec::Compress { encodings, min_size } => Middleware::Compress {
				encodings: compress::encodings(encodings).map_err(|e| ApiError::invalid(format!("{what}: {e}")))?,
				min_size: min_size.unwrap_or(compress::DEFAULT_MIN_SIZE),
			},
			MiddlewareSpec::Buffering { max_request_body } => Middleware::Buffering { max: *max_request_body },
			MiddlewareSpec::Retry { attempts, initial_interval } => Middleware::Retry(RetryPolicy {
				attempts: (*attempts).max(1),
				interval: match initial_interval {
					Some(d) => parse_duration(d).map_err(|e| ApiError::invalid(format!("{what}: {e}")))?,
					None => DEFAULT_RETRY_INTERVAL,
				},
			}),
			MiddlewareSpec::CircuitBreaker { failure_percent, window, recovery } => {
				let d = |s: &str| parse_duration(s).map_err(|e| ApiError::invalid(format!("{what}: {e}")));
				Middleware::CircuitBreaker(Breaker::new(label, *failure_percent, d(window)?, d(recovery)?))
			}
			other => return Err(ApiError::unsupported(format!("{what}: {} is not available in this version", other.kind()))),
		})
	}

	/// `errors`: pages from `service`, which must be compiled already.
	pub fn errors(label: &str, spec: &MiddlewareSpec, services: &std::collections::HashMap<String, Arc<Service>>) -> Result<Middleware, ApiError> {
		let MiddlewareSpec::Errors { status, service, path } = spec else {
			return Middleware::compile(label, spec);
		};
		let what = format!("middleware {label}");
		let ranges = status
			.iter()
			.map(|s| parse_status_range(s).map_err(|e| ApiError::invalid(format!("{what}: {e}"))))
			.collect::<Result<Vec<_>, _>>()?;
		let service = services.get(service).cloned().ok_or_else(|| ApiError::invalid(format!("{what}: service {service:?} is not defined")))?;
		if !path.starts_with('/') {
			return Err(ApiError::invalid(format!("{what}: path {path:?} must start with /")));
		}
		Ok(Middleware::Errors { ranges, service, path: path.clone() })
	}

	/// Runs the request side. `Some` answers the request without going further.
	pub fn on_request(&self, parts: &mut Parts, ctx: &Ctx) -> Option<Response<Body>> {
		match self {
			Middleware::RedirectScheme { scheme, port, permanent } => {
				let https = scheme == "https";
				if https == ctx.https {
					return None;
				}
				let default = if https { 443 } else { 80 };
				let port = port.filter(|p| *p != default).map(|p| format!(":{p}")).unwrap_or_default();
				let host = if ctx.host.contains(':') { format!("[{}]", ctx.host) } else { ctx.host.clone() };
				Some(redirect(&format!("{scheme}://{host}{port}{}", path_and_query(&parts.uri)), *permanent, &parts.method))
			}
			Middleware::RedirectRegex { regex, replacement, permanent } => {
				let url = request_url(parts, ctx);
				if !regex.is_match(&url) {
					return None;
				}
				let to = regex.replace(&url, replacement.as_str());
				Some(redirect(&to, *permanent, &parts.method))
			}
			Middleware::Respond { status, body, content_type } => {
				let mut resp = Response::new(full(body.clone()));
				*resp.status_mut() = *status;
				resp.headers_mut().insert(header::CONTENT_TYPE, content_type.clone());
				Some(resp)
			}
			Middleware::RateLimit { name, limiter } => {
				let wait = limiter.check(&limiter.source.key(&parts.headers, ctx.client)).err()?;
				let mut resp = limited(name);
				insert(resp.headers_mut(), header::RETRY_AFTER, &wait.as_secs_f64().ceil().max(1.0).to_string());
				Some(resp)
			}
			Middleware::InFlight { name, limiter } => match limiter.acquire(&ctx.client.to_string()) {
				Some(hold) => {
					ctx.holds.lock().unwrap().push(hold);
					None
				}
				None => Some(limited(name)),
			},
			Middleware::IpAllow(list) => {
				(!cidr::allows(list, ctx.client)).then(|| text(StatusCode::FORBIDDEN, "403 Forbidden"))
			}
			Middleware::Headers(h) => {
				apply(&mut parts.headers, &h.request);
				let cors = h.cors.as_ref()?;
				// a preflight from an allowed origin is answered here
				let preflight = parts.method == Method::OPTIONS && parts.headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);
				if !preflight || allowed_origin(cors, ctx.origin.as_ref()).is_none() {
					return None;
				}
				let mut resp = Response::new(full(String::new()));
				*resp.status_mut() = StatusCode::NO_CONTENT;
				let headers = resp.headers_mut();
				if !cors.allow_methods.is_empty() {
					insert(headers, header::ACCESS_CONTROL_ALLOW_METHODS, &cors.allow_methods.join(", "));
				}
				if !cors.allow_headers.is_empty() {
					insert(headers, header::ACCESS_CONTROL_ALLOW_HEADERS, &cors.allow_headers.join(", "));
				}
				if let Some(age) = cors.max_age {
					insert(headers, header::ACCESS_CONTROL_MAX_AGE, &age.to_string());
				}
				// the response side of this middleware adds Allow-Origin and Credentials
				Some(resp)
			}
			Middleware::StripPrefix(prefixes) => {
				let path = parts.uri.path().to_string();
				let prefix = prefixes.iter().find(|p| path.starts_with(p.as_str()))?;
				let rest = &path[prefix.len()..];
				let new = if rest.starts_with('/') { rest.to_string() } else { format!("/{rest}") };
				set_path(parts, &new);
				insert(&mut parts.headers, HeaderName::from_static("x-forwarded-prefix"), prefix.trim_end_matches('/'));
				None
			}
			Middleware::AddPrefix(prefix) => {
				let new = format!("{prefix}{}", parts.uri.path());
				set_path(parts, &new);
				None
			}
			Middleware::ReplacePath(path) => {
				let old = parts.uri.path().to_string();
				set_path(parts, path);
				insert(&mut parts.headers, HeaderName::from_static("x-replaced-path"), &old);
				None
			}
			Middleware::ReplacePathRegex { regex, replacement } => {
				let old = parts.uri.path().to_string();
				if regex.is_match(&old) {
					let new = regex.replace(&old, replacement.as_str()).into_owned();
					set_path(parts, &new);
					insert(&mut parts.headers, HeaderName::from_static("x-replaced-path"), &old);
				}
				None
			}
			Middleware::Crowdsec { .. }
			| Middleware::Compress { .. }
			| Middleware::Buffering { .. }
			| Middleware::Retry(_)
			| Middleware::CircuitBreaker(_)
			| Middleware::Errors { .. } => None,
		}
	}

	/// Runs the response side (also on answers of later middlewares).
	pub fn on_response(&self, headers: &mut HeaderMap, ctx: &Ctx) {
		let Middleware::Headers(h) = self else { return };
		apply(headers, &h.response);
		for (n, v) in &h.fixed {
			headers.insert(n.clone(), v.clone());
		}
		if let (Some(hsts), true) = (&h.hsts, ctx.https) {
			let mut v = format!("max-age={}", hsts.max_age);
			if hsts.include_subdomains {
				v.push_str("; includeSubDomains");
			}
			if hsts.preload {
				v.push_str("; preload");
			}
			insert(headers, header::STRICT_TRANSPORT_SECURITY, &v);
		}
		if let Some(cors) = &h.cors {
			if let Some(origin) = allowed_origin(cors, ctx.origin.as_ref()) {
				headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
				if cors.allow_credentials {
					headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
				}
				headers.append(header::VARY, HeaderValue::from_static("Origin"));
			}
		}
	}
}

/// The Allow-Origin value for this request's Origin, if the origin is allowed.
/// `*` is echoed as the origin when credentials are allowed (browsers refuse `*` then).
fn allowed_origin(cors: &CorsSpec, origin: Option<&HeaderValue>) -> Option<HeaderValue> {
	let origin = origin?;
	let o = origin.to_str().ok()?;
	if cors.allow_origins.iter().any(|a| a == "*") {
		return Some(if cors.allow_credentials { origin.clone() } else { HeaderValue::from_static("*") });
	}
	cors.allow_origins.iter().any(|a| a.eq_ignore_ascii_case(o)).then(|| origin.clone())
}

/// `set` with an empty value removes the header, as in Traefik.
fn apply(headers: &mut HeaderMap, ops: &HeaderOps) {
	for n in &ops.remove {
		if let Ok(n) = HeaderName::from_bytes(n.as_bytes()) {
			headers.remove(n);
		}
	}
	for (n, v) in &ops.set {
		let Ok(n) = HeaderName::from_bytes(n.as_bytes()) else { continue };
		if v.is_empty() {
			headers.remove(n);
		} else if let Ok(v) = HeaderValue::from_str(v) {
			headers.insert(n, v);
		}
	}
}

fn insert(headers: &mut HeaderMap, name: HeaderName, v: &str) {
	if let Ok(v) = HeaderValue::from_str(v) {
		headers.insert(name, v);
	}
}

fn path_and_query(uri: &Uri) -> String {
	uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_else(|| "/".into())
}

/// The full URL of the request, for `redirect_regex`.
fn request_url(parts: &Parts, ctx: &Ctx) -> String {
	let authority = parts
		.headers
		.get(header::HOST)
		.and_then(|h| h.to_str().ok())
		.map(str::to_string)
		.or_else(|| parts.uri.authority().map(|a| a.as_str().to_string()))
		.unwrap_or_else(|| ctx.host.clone());
	format!("{}://{authority}{}", if ctx.https { "https" } else { "http" }, path_and_query(&parts.uri))
}

/// Replaces the path, keeping the query.
fn set_path(parts: &mut Parts, path: &str) {
	let pq = match parts.uri.query() {
		Some(q) => format!("{path}?{q}"),
		None => path.to_string(),
	};
	let mut builder = Uri::builder();
	if let Some(s) = parts.uri.scheme() {
		builder = builder.scheme(s.clone());
	}
	if let Some(a) = parts.uri.authority() {
		builder = builder.authority(a.clone());
	}
	if let Ok(uri) = builder.path_and_query(pq).build() {
		parts.uri = uri;
	}
}

fn full(body: String) -> Body {
	Full::new(Bytes::from(body)).map_err(|never| match never {}).boxed()
}

fn text(status: StatusCode, body: &str) -> Response<Body> {
	let mut resp = Response::new(full(format!("{body}\n")));
	*resp.status_mut() = status;
	resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
	resp
}

/// 403 from `crowdsec`.
pub fn blocked(name: &str) -> Response<Body> {
	let mut resp = text(StatusCode::FORBIDDEN, "403 Forbidden");
	resp.extensions_mut().insert(Blocked(name.to_string()));
	resp
}

/// 429 from a limit middleware.
fn limited(name: &str) -> Response<Body> {
	let mut resp = text(StatusCode::TOO_MANY_REQUESTS, "429 Too Many Requests");
	resp.extensions_mut().insert(Limited(name.to_string()));
	resp
}

/// 301/302 for GET and HEAD; 308/307 keep the method and body of others.
fn redirect(location: &str, permanent: bool, method: &Method) -> Response<Body> {
	let simple = method == Method::GET || method == Method::HEAD;
	let status = match (permanent, simple) {
		(true, true) => StatusCode::MOVED_PERMANENTLY,
		(true, false) => StatusCode::PERMANENT_REDIRECT,
		(false, true) => StatusCode::FOUND,
		(false, false) => StatusCode::TEMPORARY_REDIRECT,
	};
	let mut resp = text(status, status.canonical_reason().unwrap_or(""));
	*resp.status_mut() = status;
	match HeaderValue::from_str(location) {
		Ok(v) => {
			resp.headers_mut().insert(header::LOCATION, v);
			resp
		}
		Err(_) => text(StatusCode::BAD_REQUEST, "400 Bad Request"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn mw(yaml: &str) -> Middleware {
		let spec: MiddlewareSpec = serde_json::from_value(serde_yaml_ng::from_str::<serde_json::Value>(yaml).unwrap()).unwrap();
		Middleware::compile("t", &spec).unwrap()
	}

	fn parts(method: &str, uri: &str, headers: &[(&str, &str)]) -> Parts {
		let mut b = hyper::Request::builder().method(method).uri(uri);
		for (k, v) in headers {
			b = b.header(*k, *v);
		}
		b.body(()).unwrap().into_parts().0
	}

	fn ctx(https: bool) -> Ctx {
		Ctx { client: "10.0.0.5".parse().unwrap(), https, host: "a.example".into(), origin: None, holds: Default::default() }
	}

	fn location(r: &Response<Body>) -> &str {
		r.headers()[header::LOCATION].to_str().unwrap()
	}

	#[test]
	fn redirects() {
		let m = mw("redirect_scheme: {scheme: https, permanent: true}");
		let r = m.on_request(&mut parts("GET", "/x?y=1", &[("host", "a.example:8080")]), &ctx(false)).unwrap();
		assert_eq!((r.status(), location(&r)), (StatusCode::MOVED_PERMANENTLY, "https://a.example/x?y=1"));
		assert!(m.on_request(&mut parts("GET", "/", &[]), &ctx(true)).is_none(), "already https");
		let r = m.on_request(&mut parts("POST", "/", &[]), &ctx(false)).unwrap();
		assert_eq!(r.status(), StatusCode::PERMANENT_REDIRECT);
		let m = mw("redirect_scheme: {scheme: https, port: 8443}");
		let r = m.on_request(&mut parts("GET", "/", &[]), &ctx(false)).unwrap();
		assert_eq!((r.status(), location(&r)), (StatusCode::FOUND, "https://a.example:8443/"));

		let m = mw("redirect_regex: {regex: '^https?://www\\.(.+)$', replacement: 'https://$1', permanent: true}");
		let r = m.on_request(&mut parts("GET", "/p", &[("host", "www.a.example")]), &ctx(false)).unwrap();
		assert_eq!(location(&r), "https://a.example/p");
		assert!(m.on_request(&mut parts("GET", "/p", &[("host", "a.example")]), &ctx(false)).is_none());
	}

	#[test]
	fn paths() {
		let m = mw("strip_prefix: {prefixes: [/api/, /v1]}");
		let mut p = parts("GET", "/api/users?x=1", &[]);
		assert!(m.on_request(&mut p, &ctx(false)).is_none());
		assert_eq!(p.uri.to_string(), "/users?x=1");
		assert_eq!(p.headers["x-forwarded-prefix"], "/api");
		let mut p = parts("GET", "/v1", &[]);
		m.on_request(&mut p, &ctx(false));
		assert_eq!(p.uri.path(), "/");
		let mut p = parts("GET", "/other", &[]);
		m.on_request(&mut p, &ctx(false));
		assert_eq!((p.uri.path(), p.headers.contains_key("x-forwarded-prefix")), ("/other", false));

		let mut p = parts("GET", "/x?q", &[]);
		mw("add_prefix: {prefix: /base/}").on_request(&mut p, &ctx(false));
		assert_eq!(p.uri.to_string(), "/base/x?q");
		let mut p = parts("GET", "/x", &[]);
		mw("replace_path: {path: /y}").on_request(&mut p, &ctx(false));
		assert_eq!((p.uri.path(), p.headers["x-replaced-path"].to_str().unwrap()), ("/y", "/x"));
		let mut p = parts("GET", "/files/a/b", &[]);
		mw("replace_path_regex: {regex: '^/files/(.*)', replacement: '/data/$1'}").on_request(&mut p, &ctx(false));
		assert_eq!((p.uri.path(), p.headers["x-replaced-path"].to_str().unwrap()), ("/data/a/b", "/files/a/b"));
	}

	#[test]
	fn ip_allow_and_respond() {
		let m = mw("ip_allow: {source_range: [10.0.0.0/8]}");
		assert!(m.on_request(&mut parts("GET", "/", &[]), &ctx(false)).is_none());
		let mut c = ctx(false);
		c.client = "192.0.2.1".parse().unwrap();
		assert_eq!(m.on_request(&mut parts("GET", "/", &[]), &c).unwrap().status(), StatusCode::FORBIDDEN);
		let r = mw("respond: {status: 403, body: nope, content_type: text/html}").on_request(&mut parts("GET", "/", &[]), &c).unwrap();
		assert_eq!((r.status(), r.headers()[header::CONTENT_TYPE].to_str().unwrap()), (StatusCode::FORBIDDEN, "text/html"));
	}

	#[test]
	fn headers_and_cors() {
		let m = mw(
			"headers: {request: {set: {X-A: '1', X-Drop: ''}, remove: [X-B]}, response: {set: {X-C: '2'}, remove: [Server]}, hsts: {max_age: 60, include_subdomains: true}, frame_deny: true, content_type_nosniff: true, cors: {allow_origins: ['https://app.example'], allow_methods: [GET, PUT], allow_credentials: true, max_age: 600}}",
		);
		let mut p = parts("GET", "/", &[("x-b", "1"), ("x-drop", "1")]);
		assert!(m.on_request(&mut p, &ctx(false)).is_none());
		assert_eq!(p.headers["x-a"], "1");
		assert!(!p.headers.contains_key("x-b") && !p.headers.contains_key("x-drop"));

		let mut h = HeaderMap::new();
		h.insert("server", HeaderValue::from_static("x"));
		m.on_response(&mut h, &ctx(false));
		assert_eq!((h["x-c"].to_str().unwrap(), h["x-frame-options"].to_str().unwrap()), ("2", "DENY"));
		assert!(!h.contains_key("server") && !h.contains_key("strict-transport-security"), "HSTS only over https");
		assert!(!h.contains_key("access-control-allow-origin"), "no Origin, no CORS headers");
		let mut c = ctx(true);
		c.origin = Some(HeaderValue::from_static("https://app.example"));
		let mut h = HeaderMap::new();
		m.on_response(&mut h, &c);
		assert_eq!(h["strict-transport-security"], "max-age=60; includeSubDomains");
		assert_eq!(h["access-control-allow-origin"], "https://app.example");
		assert_eq!(h["access-control-allow-credentials"], "true");

		let mut p = parts("OPTIONS", "/", &[("origin", "https://app.example"), ("access-control-request-method", "PUT")]);
		let r = m.on_request(&mut p, &c).unwrap();
		assert_eq!(r.status(), StatusCode::NO_CONTENT);
		assert_eq!(r.headers()["access-control-allow-methods"], "GET, PUT");
		assert_eq!(r.headers()["access-control-max-age"], "600");
		c.origin = Some(HeaderValue::from_static("https://evil.example"));
		assert!(m.on_request(&mut p, &c).is_none(), "preflights of other origins go to the backend");
	}
}
