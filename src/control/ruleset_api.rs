//! The control API for a Kubernetes controller (#28, docs/DESIGN-v0.4.md 3.):
//! rule sets (`GET /rulesets`, `GET` / `PUT` / `DELETE /rulesets/{name}`) and
//! `GET /readyz`. The work is in `core::ruleset`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use tracing::info;

use crate::control::api::{AppState, Client};
use crate::control::auth::Principal;
use crate::core::ruleset::{self, PutOptions, RulesetRequest, SetError};
use crate::error::ApiError;

/// `GET /readyz`: no authentication, like `/healthz`. 200 once the startup
/// restore is done; 503 while starting or draining.
pub async fn readyz(State(state): State<Arc<AppState>>) -> Response {
	match state.registry.readiness().check() {
		Ok(()) => Json(json!({"ready": true})).into_response(),
		Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ready": false, "reason": reason}))).into_response(),
	}
}

pub async fn list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	Json(state.registry.list_rulesets().await)
}

/// The etag as an `ETag` header (a quoted string).
fn etag_header(etag: &str) -> [(header::HeaderName, HeaderValue); 1] {
	[(header::ETAG, HeaderValue::from_str(&format!("\"{etag}\"")).unwrap_or(HeaderValue::from_static("\"\"")))]
}

fn if_match(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
	headers
		.get(header::IF_MATCH)
		.map(|v| v.to_str().map_err(|_| ApiError::invalid("If-Match is not text")))
		.transpose()
}

pub async fn get(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> Result<Response, ApiError> {
	let set = state.registry.get_ruleset(&name).await?;
	Ok((etag_header(&set.etag), Json(set)).into_response())
}

/// `event = "audit"` for a change to a rule set.
fn audit(principal: &Principal, client: &Client, action: &str, name: &str, outcome: Result<(), &'static str>) {
	let (outcome, code) = match outcome {
		Ok(()) => ("ok", ""),
		Err("forbidden") => ("forbidden", "forbidden"),
		Err(code) => ("error", code),
	};
	info!(event = "audit", token = %principal.name, client = %client.0, action, rule = "", ruleset = name, outcome, code);
}

pub async fn put(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	Path(name): Path<String>,
	Query(query): Query<HashMap<String, String>>,
	headers: HeaderMap,
	body: Bytes,
) -> Result<Response, SetError> {
	ruleset::validate_name(&name)?;
	let dry_run = crate::config::plan::dry_run(&query)?;
	let req: RulesetRequest = serde_json::from_slice(&body).map_err(|e| ApiError::invalid(format!("invalid body: {e}")))?;
	req.validate_shape()?;
	for (i, r) in req.rules.iter().enumerate() {
		super::acme_api::check_rule_scope(&principal, Some(r), None)
			.map_err(|e| ApiError { message: format!("rules[{i}]: {}", e.message), ..e })?;
	}
	principal.may_use_ruleset(&name)?;
	let if_match = if_match(&headers)?.map(str::to_owned);
	// a change runs to its end even if the client goes away (#144)
	super::api::to_the_end(async move {
		let may_use_ports = |first: u16, last: u16| principal.may_use_ports(first, last);
		let admin = principal.has(crate::control::auth::Scope::Admin);
		let opts =
			PutOptions { if_match: if_match.as_deref(), dry_run, by: &principal.name, admin, owner: None, may_use_ports: &may_use_ports };
		// the periodic check of the stored rules and sets waits for none of the changes (persist::Store::reconcile)
		let _change = match state.registry.persist().filter(|_| !dry_run) {
			Some(store) => Some(store.changing().await),
			None => None,
		};
		let result = state.registry.put_ruleset(&name, req, opts).await;
		if !dry_run {
			audit(&principal, &client, "ruleset.put", &name, result.as_ref().map(|_| ()).map_err(|e| e.error.code));
		}
		let mut applied = result?;
		if !dry_run {
			applied.persisted = persist_set(&state, &principal, &name).await;
		}
		Ok((etag_header(&applied.etag), Json(applied)).into_response())
	})
	.await
}

/// The store for a change to rule set `name` (#241): a `persist: true` token's
/// sets, and every change to a set that is stored already.
fn set_store(state: &AppState, principal: &Principal, name: &str) -> Option<Arc<crate::config::persist::Store>> {
	state
		.registry
		.persist()
		.filter(|s| state.registry.caps().features.ruleset_persistence && (principal.persist || s.knows_set(name)))
		.cloned()
}

/// Writes the set's row after a `PUT`; `persisted` of the answer.
async fn persist_set(state: &AppState, principal: &Principal, name: &str) -> Option<bool> {
	let store = set_store(state, principal, name)?;
	let (generation, etag, owner, rules) = state.registry.ruleset_row(name).await?;
	let row = crate::config::persist::SetRow { name, generation, etag: &etag, owner: &owner, rules, by: &principal.name };
	Some(store.save_set(row).await)
}

pub async fn delete(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	Path(name): Path<String>,
	Query(query): Query<HashMap<String, String>>,
	headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
	let drain = match query.get("drain_secs") {
		Some(s) => {
			let secs: u64 = s.parse().map_err(|_| ApiError::invalid(format!("invalid drain_secs: {s}")))?;
			(secs > 0).then(|| Duration::from_secs(secs))
		}
		None => None,
	};
	principal.may_use_ruleset(&name)?;
	let if_match = if_match(&headers)?.map(str::to_owned);
	// a change runs to its end even if the client goes away (#144)
	super::api::to_the_end(async move {
		let may_use_ports = |first: u16, last: u16| principal.may_use_ports(first, last);
		let admin = principal.has(crate::control::auth::Scope::Admin);
		let store = set_store(&state, &principal, &name);
		let change = match state.registry.persist() {
			Some(store) => Some(store.changing().await),
			None => None,
		};
		let result = state.registry.take_ruleset(&name, if_match.as_deref(), &may_use_ports, (&principal.name, admin)).await;
		audit(&principal, &client, "ruleset.delete", &name, result.as_ref().map(|_| ()).map_err(|e| e.code));
		let taken = result?;
		// the row's deletion is queued now; the drain holds up no other change (nor the end of a live upgrade)
		let queued = match &store {
			Some(store) => store.begin_remove_set(&state.registry, &name, &principal.name).await,
			None => None,
		};
		drop(change);
		state.registry.stop_ruleset(taken, drain).await;
		if let (Some(store), Some(queued)) = (store, queued) {
			store.finish_remove_set(queued).await;
		}
		Ok(StatusCode::NO_CONTENT)
	})
	.await
}
