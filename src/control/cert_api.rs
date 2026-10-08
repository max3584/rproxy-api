//! The certificate API (#240, v0.4.2, docs/DESIGN-v0.4.x.md 3.): `GET /certs`,
//! `GET` / `PUT` / `DELETE /certs/{name}`. The files are in `tls::named`;
//! rules name a stored certificate with `{"cert": "<name>"}`.
//!
//! Keys travel in `PUT`, so over TCP it is accepted only with TLS (plain
//! loopback and the Unix socket are fine). Audit lines carry the name and the
//! fingerprint only.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use tracing::info;

use crate::control::api::{AppState, Client, Transport};
use crate::control::auth::Principal;
use crate::control::hardening::ClientCert;
use crate::error::ApiError;
use crate::tls::named::{self, CertView, PutRequest};

/// Whether a request may carry a private key: the Unix socket, TLS, or plain
/// TCP from loopback.
pub fn secure_transport(unix: bool, tls: bool, peer: Option<SocketAddr>) -> bool {
	unix || tls || peer.is_some_and(|p| crate::l7::access::canonical(p.ip()).is_loopback())
}

fn etag(view: &CertView) -> [(header::HeaderName, HeaderValue); 1] {
	[(header::ETAG, HeaderValue::from_str(&format!("\"{}\"", view.fingerprint_sha256)).unwrap_or(HeaderValue::from_static("\"\"")))]
}

fn if_match(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
	headers
		.get(header::IF_MATCH)
		.map(|v| v.to_str().map(str::to_string).map_err(|_| ApiError::invalid("If-Match is not text")))
		.transpose()
}

fn audit(principal: &Principal, client: &Client, action: &str, name: &str, fingerprint: &str, result: Result<(), &'static str>) {
	let (outcome, code) = match result {
		Ok(()) => ("ok", ""),
		Err("forbidden") => ("forbidden", "forbidden"),
		Err(code) => ("error", code),
	};
	info!(event = "audit", token = %principal.name, auth = principal.auth, client = %client.0, action, cert = name,
		fingerprint_sha256 = fingerprint, outcome, code);
}

/// Runs the store's file work off the async threads.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, ApiError> + Send + 'static) -> Result<T, ApiError> {
	tokio::task::spawn_blocking(f).await.map_err(|e| ApiError::internal(e.to_string()))?
}

pub async fn list(State(state): State<Arc<AppState>>, Extension(principal): Extension<Principal>) -> Json<Vec<CertView>> {
	let mut certs = blocking(|| Ok(named::list())).await.unwrap_or_default();
	certs.retain(|c| principal.may_use_cert(&c.name).is_ok());
	for c in &mut certs {
		c.used_by = state.registry.rules_using_cert(&c.name).await;
	}
	Json(certs)
}

pub async fn get(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Path(name): Path<String>,
) -> Result<Response, ApiError> {
	named::validate_name(&name)?;
	principal.may_use_cert(&name)?;
	let n = name.clone();
	let mut view = blocking(move || named::read(&n)).await?;
	view.used_by = state.registry.rules_using_cert(&name).await;
	Ok((etag(&view), Json(view)).into_response())
}

#[allow(clippy::too_many_arguments)]
pub async fn put(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	transport: Option<Extension<Transport>>,
	tls: Option<Extension<ClientCert>>,
	peer: Option<Extension<ConnectInfo<SocketAddr>>>,
	Path(name): Path<String>,
	headers: HeaderMap,
	body: Bytes,
) -> Result<Response, ApiError> {
	let result = async {
		if !secure_transport(transport.is_some(), tls.is_some(), peer.map(|Extension(ConnectInfo(p))| p)) {
			return Err(ApiError {
				status: StatusCode::FORBIDDEN,
				code: "tls_required",
				message: "PUT /certs carries a private key: use the control API over TLS, the Unix socket, or loopback".into(),
			});
		}
		named::validate_name(&name)?;
		principal.may_use_cert(&name)?;
		let req: PutRequest = serde_json::from_slice(&body).map_err(|e| ApiError::invalid(format!("invalid body: {e}")))?;
		let (n, by, warn, im) = (name.clone(), principal.name.clone(), state.registry.certs().warn_secs(), if_match(&headers)?);
		blocking(move || named::put(&n, &req, &by, im.as_deref(), warn)).await
	}
	.await;
	let print = result.as_ref().map(|s| s.view.fingerprint_sha256.clone()).unwrap_or_default();
	audit(&principal, &client, "cert.put", &name, &print, result.as_ref().map(|_| ()).map_err(|e| e.code));
	let mut stored = result?;
	// rules using it take it now; failed rules waiting for it start
	state.registry.cert_stored(&name).await;
	stored.view.used_by = state.registry.rules_using_cert(&name).await;
	let status = if stored.created { StatusCode::CREATED } else { StatusCode::OK };
	let mut body = serde_json::to_value(&stored.view).unwrap_or_default();
	if !stored.warnings.is_empty() {
		body["warnings"] = json!(stored.warnings);
	}
	Ok((status, etag(&stored.view), Json(body)).into_response())
}

pub async fn delete(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	Path(name): Path<String>,
	headers: HeaderMap,
) -> Response {
	let result = async {
		named::validate_name(&name).map_err(|e| (e, vec![]))?;
		principal.may_use_cert(&name).map_err(|e| (e, vec![]))?;
		let used_by = state.registry.rules_using_cert(&name).await;
		if !used_by.is_empty() {
			return Err((
				ApiError {
					status: StatusCode::CONFLICT,
					code: "in_use",
					message: format!("certificate {name:?} is used by {}", used_by.join(", ")),
				},
				used_by,
			));
		}
		let (n, im) = (name.clone(), if_match(&headers).map_err(|e| (e, vec![]))?);
		blocking(move || named::remove(&n, im.as_deref())).await.map_err(|e| (e, vec![]))
	}
	.await;
	let print = result.as_ref().map(|v| v.fingerprint_sha256.clone()).unwrap_or_default();
	audit(&principal, &client, "cert.delete", &name, &print, result.as_ref().map(|_| ()).map_err(|(e, _)| e.code));
	match result {
		Ok(_) => StatusCode::NO_CONTENT.into_response(),
		Err((e, used_by)) if !used_by.is_empty() => {
			(e.status, Json(json!({"error": e.message, "code": e.code, "used_by": used_by}))).into_response()
		}
		Err((e, _)) => e.into_response(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn keys_travel_only_over_a_secure_transport() {
		let at = |s: &str| Some(s.parse::<SocketAddr>().unwrap());
		assert!(secure_transport(true, false, None));
		assert!(secure_transport(false, true, at("192.0.2.1:5")));
		assert!(secure_transport(false, false, at("127.0.0.1:5")));
		assert!(secure_transport(false, false, at("[::1]:5")));
		assert!(secure_transport(false, false, at("[::ffff:127.0.0.1]:5")));
		assert!(!secure_transport(false, false, at("192.0.2.1:5")));
		assert!(!secure_transport(false, false, None));
	}
}
