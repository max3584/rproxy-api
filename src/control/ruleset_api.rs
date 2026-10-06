//! The control API for a Kubernetes controller (#28, docs/DESIGN-v0.4.md 3.):
//! rule sets (`GET /rulesets`, `GET` / `PUT` / `DELETE /rulesets/{name}`) and
//! `GET /readyz`. Until `features.rulesets` / `features.readyz` are true, the
//! requests are checked and answered `400 unsupported`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::response::IntoResponse;

use crate::control::api::AppState;
use crate::control::auth::Principal;
use crate::core::ruleset::{self, RulesetRequest};
use crate::error::ApiError;

fn unavailable(what: &str) -> ApiError {
	ApiError::unsupported(format!("{what} is not available in this version (see GET /capabilities features)"))
}

/// `GET /readyz`: no authentication, like `/healthz`.
pub async fn readyz() -> ApiError {
	unavailable("GET /readyz")
}

pub async fn list() -> ApiError {
	unavailable("rule sets")
}

pub async fn get(Path(name): Path<String>) -> ApiError {
	if let Err(e) = ruleset::validate_name(&name) {
		return e;
	}
	unavailable("rule sets")
}

pub async fn put(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Path(name): Path<String>,
	Query(query): Query<HashMap<String, String>>,
	body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
	ruleset::validate_name(&name)?;
	let _dry_run = crate::config::plan::dry_run(&query)?;
	let req: RulesetRequest = serde_json::from_slice(&body).map_err(|e| ApiError::invalid(format!("invalid body: {e}")))?;
	req.validate_shape()?;
	let caps = state.registry.caps();
	// the shape of every rule, as if everything were available
	let everything = crate::core::rule::Caps {
		transparent: true,
		transparent_ipv6: true,
		features: crate::core::rule::Features::ALL,
		..caps
	};
	for (i, r) in req.rules.iter().enumerate() {
		if !principal.may_use_ports(r.listen_port, r.listen_port_end.unwrap_or(r.listen_port).max(r.listen_port)) {
			return Err(ApiError::forbidden(format!("rules[{i}]: this token may not use listen port {}", r.listen_port)));
		}
		r.clone().validate(&everything).map_err(|e| ApiError { message: format!("rules[{i}]: {}", e.message), ..e })?;
	}
	Err::<(), _>(unavailable("rule sets"))
}

pub async fn delete(Path(name): Path<String>) -> ApiError {
	if let Err(e) = ruleset::validate_name(&name) {
		return e;
	}
	unavailable("rule sets")
}
