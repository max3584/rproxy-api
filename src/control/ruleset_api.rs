//! The control API for a Kubernetes controller (#28, docs/DESIGN-v0.4.md 3.):
//! rule sets (`GET /rulesets`, `GET` / `PUT` / `DELETE /rulesets/{name}`) and
//! `GET /readyz`. The work is in `core::ruleset`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
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

/// Bodies of `PUT /rulesets/{name}` read and parsed at a time (#358): each may be
/// `ruleset::MAX_BODY`, and the changes run one at a time anyway.
static PUT_BODIES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
/// How long a `PUT` waits for its turn to send the body (`503 busy` after).
const PUT_WAIT: Duration = Duration::from_secs(30);
/// How long the body may take to arrive (`408 timeout` after): a slow client does not
/// keep the others waiting.
const BODY_TIME: Duration = Duration::from_secs(60);

/// The body of a `PUT`, at most `ruleset::MAX_BODY` bytes, within `BODY_TIME`.
async fn read_body(body: Body) -> Result<Bytes, ApiError> {
	match tokio::time::timeout(BODY_TIME, axum::body::to_bytes(body, ruleset::MAX_BODY)).await {
		Ok(Ok(bytes)) => Ok(bytes),
		Ok(Err(e)) => {
			let e = e.into_inner();
			let mut cause: Option<&(dyn std::error::Error + 'static)> = Some(e.as_ref());
			while let Some(c) = cause {
				if c.is::<http_body_util::LengthLimitError>() {
					return Err(ApiError::too_large(format!("the body is larger than {} bytes", ruleset::MAX_BODY)));
				}
				cause = c.source();
			}
			Err(ApiError::invalid(format!("the body could not be read: {e}")))
		}
		Err(_) => Err(ApiError::timeout(format!("the body did not arrive within {} s", BODY_TIME.as_secs()))),
	}
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
		// the token's scopes and limits, a protected file (#319)
		Err(code @ ("forbidden" | "protected_file" | "file_not_allowed")) => ("forbidden", code),
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
	body: Body,
) -> Result<Response, SetError> {
	ruleset::validate_name(&name)?;
	let dry_run = crate::config::plan::dry_run(&query)?;
	// at most `PUT_BODIES` bodies (up to `ruleset::MAX_BODY` each) are read and parsed at a time (#358)
	let permit = match tokio::time::timeout(PUT_WAIT, PUT_BODIES.acquire()).await {
		Ok(Ok(permit)) => permit,
		_ => return Err(ApiError::busy("other rule sets are being sent; try again in a moment").into()),
	};
	let body = read_body(body).await?;
	let req: RulesetRequest = serde_json::from_slice(&body).map_err(|e| ApiError::invalid(format!("invalid body: {e}")))?;
	drop((body, permit));
	req.validate_shape()?;
	// refusals of the token are audited as those of PUT /rules (#319)
	let refused = |e: ApiError| {
		if !dry_run {
			audit(&principal, &client, "ruleset.put", &name, Err(e.code));
		}
		e
	};
	for (i, r) in req.rules.iter().enumerate() {
		// names only for what the API is sent (#358): restored sets keep theirs
		if let Some(h) = &r.http {
			h.check_names().map_err(|e| ApiError { message: format!("rules[{i}]: {}", e.message), ..e }).map_err(refused)?;
		}
		super::acme_api::check_rule_scope(&principal, Some(r), None)
			.map_err(|e| ApiError { message: format!("rules[{i}]: {}", e.message), ..e })
			.map_err(refused)?;
	}
	principal.may_use_ruleset(&name).map_err(refused)?;
	let if_match = if_match(&headers)?.map(str::to_owned);
	// a change runs to its end even if the client goes away (#144)
	super::api::to_the_end(async move {
		let may_use_ports = |first: u16, last: u16| principal.may_use_ports(first, last);
		let admin = principal.has(crate::control::auth::Scope::Admin);
		let limits = Some(ruleset::SetLimits {
			max_rules: principal.max_rules,
			max_rulesets: principal.max_rulesets,
			freebind: principal.may_freebind(true),
		});
		let opts = PutOptions {
			if_match: if_match.as_deref(),
			dry_run,
			by: &principal.name,
			admin,
			owner: None,
			may_use_ports: &may_use_ports,
			limits,
		};
		// the periodic check of the stored rules and sets waits for none of the changes (persist::Store::reconcile)
		// refused if a live upgrade started meanwhile (#305)
		let _change = if dry_run { None } else { super::api::changing(&state).await? };
		// the files are counted by other checks until the change is made (#319)
		let files = match super::rule_files::check_ruleset(&state.registry, &principal, &name, &req.rules).await {
			Ok(intent) => intent,
			Err(e) => {
				if !dry_run {
					audit(&principal, &client, "ruleset.put", &name, Err(e.code));
				}
				return Err(e.into());
			}
		};
		let result = state.registry.put_ruleset(&name, req, opts).await;
		drop(files);
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
	// the set is read as it runs when its row is queued (#306)
	set_store(state, principal, name)?.save_set(&state.registry, name, &principal.name).await
}

pub async fn delete(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	Path(name): Path<String>,
	Query(query): Query<HashMap<String, String>>,
	headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
	let drain = super::api::drain_query(&query)?;
	principal.may_use_ruleset(&name)?;
	let if_match = if_match(&headers)?.map(str::to_owned);
	// a change runs to its end even if the client goes away (#144)
	super::api::to_the_end(async move {
		let may_use_ports = |first: u16, last: u16| principal.may_use_ports(first, last);
		let admin = principal.has(crate::control::auth::Scope::Admin);
		let store = set_store(&state, &principal, &name);
		// refused if a live upgrade started meanwhile (#305)
		let change = super::api::changing(&state).await?;
		if let Some(store) = &store {
			store.check_backlog(principal.has(crate::control::auth::Scope::Admin))?;
		}
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
