//! The ACME part of the control API (#208): `GET /acme` (names and states,
//! never a secret or a secret's file) and the strong operations (create or
//! deactivate an account at the CA, renew a certificate now), which need the
//! `acme:write` scope and, by default, the Unix socket
//! (`RPROXY_API_RELOAD_UNIX_ONLY`, as `POST /config/reload`).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use tracing::info;

use super::api::{AppState, Client, Transport};
use super::auth::{Principal, Scope};
use crate::core::rule::{RuleRequest, UpdateRequest};
use crate::error::ApiError;

/// `event = "audit"` for ACME operations (no secret in it).
fn audit(principal: &Principal, client: &Client, action: &str, target: &str, result: &Result<(), ApiError>) {
	let (outcome, code) = match result {
		Ok(()) => ("ok", ""),
		Err(e) if e.code == "forbidden" => ("forbidden", e.code),
		Err(e) => ("error", e.code),
	};
	info!(event = "audit", token = %principal.name, client = %client.0, action, rule = "", target, outcome, code);
}

/// Whether a rule (in a POST or PATCH body) has an ACME certificate.
pub fn uses_acme(tls: Option<&crate::tls::config::TlsSpec>) -> bool {
	tls.is_some_and(|t| t.certificates.iter().any(|c| c.acme.is_some()))
}

/// Rules with ACME certificates need `acme:write` besides `rules:write`.
pub fn check_rule_scope(principal: &Principal, create: Option<&RuleRequest>, update: Option<&UpdateRequest>) -> Result<(), ApiError> {
	let acme = uses_acme(create.and_then(|r| r.tls.as_ref())) || uses_acme(update.and_then(|r| r.tls.as_ref()));
	if acme && !principal.has(Scope::AcmeWrite) {
		return Err(ApiError::forbidden("rules with acme certificates need the acme:write scope"));
	}
	Ok(())
}

fn acme(state: &AppState) -> Result<&Arc<crate::acme::Acme>, ApiError> {
	state.registry.acme().ok_or_else(|| ApiError::not_found("global.acme is not configured in the settings file (RPROXY_CONFIG)"))
}

/// The strong operations: the scope, then the Unix socket.
fn check_strong(state: &AppState, principal: &Principal, transport: Option<Extension<Transport>>, action: &str) -> Result<(), ApiError> {
	if !principal.has(Scope::AcmeWrite) {
		return Err(ApiError::forbidden("this token lacks the acme:write scope"));
	}
	if state.reload_unix_only && transport.is_none() {
		return Err(ApiError::forbidden(format!(
			"{action} is accepted only over the Unix socket (RPROXY_API_SOCKET); set RPROXY_API_RELOAD_UNIX_ONLY=false to allow it over TCP"
		)));
	}
	Ok(())
}

pub async fn view(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, ApiError> {
	Ok(Json(acme(&state)?.view()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewRequest {
	resolver: String,
	domains: Vec<String>,
}

pub async fn renew(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	transport: Option<Extension<Transport>>,
	body: Bytes,
) -> Response {
	let mut target = String::new();
	let result = (|| {
		check_strong(&state, &principal, transport, "POST /acme/renew")?;
		let req: RenewRequest = serde_json::from_slice(&body).map_err(|e| ApiError::invalid(format!("invalid body: {e}")))?;
		let acme = acme(&state)?;
		let id = acme.check(&req.resolver, &req.domains)?;
		target = format!("{}:{}", id.resolver, id.domains.join(","));
		acme.renew(&id)
	})();
	audit(&principal, &client, "acme.renew", &target, &result);
	match result {
		Ok(()) => (StatusCode::ACCEPTED, Json(json!({}))).into_response(),
		Err(e) => e.into_response(),
	}
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeRequest {
	resolver: String,
	domains: Vec<String>,
	/// RFC 5280 reason: unspecified, key_compromise, affiliation_changed,
	/// superseded, cessation_of_operation (left out: none given).
	reason: Option<String>,
}

fn revocation_reason(s: &str) -> Result<instant_acme::RevocationReason, ApiError> {
	use instant_acme::RevocationReason as R;
	Ok(match s {
		"unspecified" => R::Unspecified,
		"key_compromise" => R::KeyCompromise,
		"affiliation_changed" => R::AffiliationChanged,
		"superseded" => R::Superseded,
		"cessation_of_operation" => R::CessationOfOperation,
		_ => {
			return Err(ApiError::invalid(format!(
				"reason {s:?}: unspecified, key_compromise, affiliation_changed, superseded or cessation_of_operation"
			)))
		}
	})
}

pub async fn revoke(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	transport: Option<Extension<Transport>>,
	body: Bytes,
) -> Response {
	let mut target = String::new();
	let result = async {
		check_strong(&state, &principal, transport, "POST /acme/revoke")?;
		let req: RevokeRequest = serde_json::from_slice(&body).map_err(|e| ApiError::invalid(format!("invalid body: {e}")))?;
		let reason = req.reason.as_deref().map(revocation_reason).transpose()?;
		let acme = acme(&state)?;
		let id = acme.check(&req.resolver, &req.domains)?;
		target = format!("{}:{}", id.resolver, id.domains.join(","));
		acme.revoke(&id, reason).await
	}
	.await;
	audit(&principal, &client, "acme.revoke", &target, &result);
	match result {
		Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
		Err(e) => e.into_response(),
	}
}

pub async fn register(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	transport: Option<Extension<Transport>>,
	Path(name): Path<String>,
) -> Response {
	let result = async {
		check_strong(&state, &principal, transport, "POST /acme/accounts/{name}/register")?;
		acme(&state)?.register(&name).await
	}
	.await;
	audit(&principal, &client, "acme.account.register", &name, &result);
	match result {
		Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
		Err(e) => e.into_response(),
	}
}

pub async fn deactivate(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	transport: Option<Extension<Transport>>,
	Path(name): Path<String>,
) -> Response {
	let result = async {
		check_strong(&state, &principal, transport, "POST /acme/accounts/{name}/deactivate")?;
		acme(&state)?.deactivate(&name).await
	}
	.await;
	audit(&principal, &client, "acme.account.deactivate", &name, &result);
	match result {
		Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
		Err(e) => e.into_response(),
	}
}
