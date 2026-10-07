//! `cors` (#230): CORS as the Gateway API's HTTPCORSFilter. Preflights from an
//! allowed origin are answered here; other requests get the CORS headers on
//! their response. Origins may be exact, `*`, or have `*` in the host
//! (`https://*.bar.com`, where `*` matches one or more of any characters).

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::http::request::Parts;
use hyper::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::l7::server::Body;

/// Settings of the `cors` middleware.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsFilterSpec {
	pub allow_origins: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allow_methods: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allow_headers: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub expose_headers: Vec<String>,
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub allow_credentials: bool,
	/// Seconds a preflight may be cached (`Access-Control-Max-Age`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_age: Option<u64>,
}

impl CorsFilterSpec {
	pub fn validate(&self, what: &str) -> Result<(), ApiError> {
		let bad = |m: String| Err(ApiError::invalid(format!("{what}: {m}")));
		if self.allow_origins.is_empty() {
			return bad("allow_origins is empty".into());
		}
		for o in &self.allow_origins {
			if o != "*" && !(o.starts_with("http://") || o.starts_with("https://")) {
				return bad(format!("allow_origins: {o:?} must be * or start with http:// or https://"));
			}
		}
		for v in self.allow_origins.iter().chain(&self.allow_methods).chain(&self.allow_headers).chain(&self.expose_headers) {
			if HeaderValue::from_str(v).is_err() || v.contains(',') {
				return bad(format!("{v:?} is not a valid header value"));
			}
		}
		Ok(())
	}
}

#[derive(Debug)]
pub struct Cors {
	spec: CorsFilterSpec,
	any_origin: bool,
	any_method: bool,
	any_header: bool,
}

impl Cors {
	pub fn new(spec: &CorsFilterSpec, what: &str) -> Result<Cors, ApiError> {
		spec.validate(what)?;
		Ok(Cors {
			any_origin: spec.allow_origins.iter().any(|o| o == "*"),
			any_method: spec.allow_methods.iter().any(|m| m == "*"),
			any_header: spec.allow_headers.iter().any(|h| h == "*"),
			spec: spec.clone(),
		})
	}

	/// The `Access-Control-Allow-Origin` for this `Origin`; None when not allowed.
	fn allow_origin(&self, origin: Option<&HeaderValue>) -> Option<HeaderValue> {
		let origin = origin?;
		let o = origin.to_str().ok()?;
		if self.any_origin {
			return Some(if self.spec.allow_credentials { origin.clone() } else { HeaderValue::from_static("*") });
		}
		self.spec.allow_origins.iter().any(|p| origin_matches(p, o)).then(|| origin.clone())
	}

	fn common(&self, headers: &mut HeaderMap, allow: HeaderValue) {
		headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
		if self.spec.allow_credentials {
			headers.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
		} else {
			headers.remove(header::ACCESS_CONTROL_ALLOW_CREDENTIALS);
		}
		if !self.spec.expose_headers.is_empty() {
			insert(headers, header::ACCESS_CONTROL_EXPOSE_HEADERS, &self.spec.expose_headers.join(", "));
		}
		if !headers.get_all(header::VARY).iter().any(|v| v.to_str().is_ok_and(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("origin")))) {
			headers.append(header::VARY, HeaderValue::from_static("Origin"));
		}
	}

	/// A preflight from an allowed origin gets its answer here.
	pub fn on_request(&self, parts: &Parts, origin: Option<&HeaderValue>) -> Option<Response<Body>> {
		if parts.method != Method::OPTIONS {
			return None;
		}
		let requested = parts.headers.get(header::ACCESS_CONTROL_REQUEST_METHOD)?;
		let allow = self.allow_origin(origin)?;
		let mut resp = Response::new(Full::new(Bytes::new()).map_err(|never| match never {}).boxed());
		*resp.status_mut() = StatusCode::NO_CONTENT;
		let h = resp.headers_mut();
		self.common(h, allow);
		if self.any_method {
			h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, if self.spec.allow_credentials { requested.clone() } else { HeaderValue::from_static("*") });
		} else if !self.spec.allow_methods.is_empty() {
			insert(h, header::ACCESS_CONTROL_ALLOW_METHODS, &self.spec.allow_methods.join(", "));
		}
		if self.any_header {
			match (self.spec.allow_credentials, parts.headers.get(header::ACCESS_CONTROL_REQUEST_HEADERS)) {
				(true, Some(v)) => {
					h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, v.clone());
				}
				(true, None) => {}
				(false, _) => {
					h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("*"));
				}
			}
		} else if !self.spec.allow_headers.is_empty() {
			insert(h, header::ACCESS_CONTROL_ALLOW_HEADERS, &self.spec.allow_headers.join(", "));
		}
		if let Some(age) = self.spec.max_age {
			insert(h, header::ACCESS_CONTROL_MAX_AGE, &age.to_string());
		}
		Some(resp)
	}

	/// Other requests from an allowed origin: the CORS headers on the response.
	pub fn on_response(&self, headers: &mut HeaderMap, origin: Option<&HeaderValue>) {
		// a preflight answered above has them already
		if headers.contains_key(header::ACCESS_CONTROL_ALLOW_METHODS) && headers.contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN) {
			return;
		}
		if let Some(allow) = self.allow_origin(origin) {
			self.common(headers, allow);
		}
	}
}

fn insert(headers: &mut HeaderMap, name: header::HeaderName, v: &str) {
	if let Ok(v) = HeaderValue::from_str(v) {
		headers.insert(name, v);
	}
}

/// `https://*.bar.com` style patterns: `*` matches one or more of any characters.
fn origin_matches(pattern: &str, origin: &str) -> bool {
	let (p, o) = (pattern.to_ascii_lowercase(), origin.to_ascii_lowercase());
	match p.split_once('*') {
		None => p == o,
		Some((prefix, suffix)) => o.len() > prefix.len() + suffix.len() && o.starts_with(prefix) && o.ends_with(suffix),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cors(v: serde_json::Value) -> Cors {
		Cors::new(&serde_json::from_value(v).unwrap(), "t").unwrap()
	}

	fn preflight(origin: &str, method: &str, headers: Option<&str>) -> Parts {
		let mut b = hyper::Request::builder().method("OPTIONS").uri("/").header("origin", origin).header("access-control-request-method", method);
		if let Some(h) = headers {
			b = b.header("access-control-request-headers", h);
		}
		b.body(()).unwrap().into_parts().0
	}

	fn hv(s: &str) -> HeaderValue {
		HeaderValue::from_str(s).unwrap()
	}

	#[test]
	fn origins() {
		assert!(origin_matches("https://*.bar.com", "https://www.bar.com"));
		assert!(origin_matches("https://*.bar.com", "https://xpto.www.bar.com"));
		assert!(!origin_matches("https://*.bar.com", "https://bar.com"));
		assert!(!origin_matches("https://*.bar.com", "http://www.bar.com"));
		assert!(origin_matches("https://www.foo.com", "HTTPS://WWW.FOO.COM"));
		assert!(!origin_matches("https://www.foo.com", "https://foobar.com"));
	}

	#[test]
	fn preflights_like_the_conformance_tests() {
		let c = cors(serde_json::json!({"allow_origins": ["https://www.foo.com", "https://*.bar.com"], "allow_methods": ["GET", "OPTIONS"],
			"allow_headers": ["x-header-1", "x-header-2"], "expose_headers": ["x-header-3", "x-header-4"], "allow_credentials": true, "max_age": 3600}));
		let p = preflight("https://www.bar.com", "GET", Some("x-header-1, x-header-2"));
		let r = c.on_request(&p, p.headers.get("origin")).unwrap();
		let h = r.headers();
		assert_eq!(r.status(), 204);
		assert_eq!(h["access-control-allow-origin"], "https://www.bar.com");
		assert_eq!(h["access-control-allow-methods"], "GET, OPTIONS");
		assert_eq!(h["access-control-allow-headers"], "x-header-1, x-header-2");
		assert_eq!(h["access-control-expose-headers"], "x-header-3, x-header-4");
		assert_eq!(h["access-control-max-age"], "3600");
		assert_eq!(h["access-control-allow-credentials"], "true");
		let p = preflight("https://foobar.com", "GET", None);
		assert!(c.on_request(&p, p.headers.get("origin")).is_none(), "not allowed: to the backend");
		let mut resp = HeaderMap::new();
		c.on_response(&mut resp, Some(&hv("https://foobar.com")));
		assert!(resp.is_empty());
		c.on_response(&mut resp, Some(&hv("https://www.foo.com")));
		assert_eq!(resp["access-control-allow-origin"], "https://www.foo.com");
		assert_eq!(resp["vary"], "Origin");

		// wildcards with and without credentials
		let star = |cred: bool| cors(serde_json::json!({"allow_origins": ["*"], "allow_methods": ["*"], "allow_headers": ["*"], "allow_credentials": cred}));
		let p = preflight("https://other.foo.com", "PUT", Some("x-header-1, x-header-2"));
		let r = star(true).on_request(&p, p.headers.get("origin")).unwrap();
		assert_eq!(r.headers()["access-control-allow-origin"], "https://other.foo.com");
		assert_eq!(r.headers()["access-control-allow-methods"], "PUT");
		assert_eq!(r.headers()["access-control-allow-headers"], "x-header-1, x-header-2");
		let r = star(false).on_request(&p, p.headers.get("origin")).unwrap();
		assert_eq!(r.headers()["access-control-allow-origin"], "*");
		assert_eq!(r.headers()["access-control-allow-methods"], "*");
		assert!(!r.headers().contains_key("access-control-allow-credentials"));
		let mut resp = HeaderMap::new();
		resp.insert("access-control-allow-credentials", hv("true"));
		star(false).on_response(&mut resp, Some(&hv("https://foobar.com:12345")));
		assert_eq!(resp["access-control-allow-origin"], "*");
		assert!(!resp.contains_key("access-control-allow-credentials"), "the backend's is replaced");
	}

	#[test]
	fn validation() {
		let v = |j: serde_json::Value| serde_json::from_value::<CorsFilterSpec>(j).unwrap().validate("t");
		assert!(v(serde_json::json!({"allow_origins": []})).is_err());
		assert!(v(serde_json::json!({"allow_origins": ["www.foo.com"]})).is_err());
		assert!(v(serde_json::json!({"allow_origins": ["*"], "allow_methods": ["GET,PUT"]})).is_err());
	}
}
