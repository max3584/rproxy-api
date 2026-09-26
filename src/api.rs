use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde_json::json;
use tracing::info;

use crate::auth::{Principal, Scope, Tokens};
use crate::error::ApiError;
use crate::registry::Registry;
use crate::rule::{parse_listen, Key, RuleRequest, SourceIp, UpdateRequest};

pub struct AppState {
	pub registry: Arc<Registry>,
	pub tokens: Arc<Tokens>,
}

type AppResult<T> = Result<T, ApiError>;

pub fn router(state: Arc<AppState>) -> Router {
	let protected = Router::new()
		.route("/capabilities", get(capabilities))
		.route("/openapi.json", get(openapi))
		.route("/config", get(config_status))
		.route("/interfaces", get(interfaces))
		.route("/rules", get(list).post(create))
		.route("/rules/{protocol}/{listen_addr}/{listen_port}", get(get_rule).patch(update).delete(delete))
		.route("/metrics", get(metrics))
		.route_layer(middleware::from_fn_with_state(state.clone(), require_token));

	Router::new()
		.route("/healthz", get(|| async { "ok" }))
		.merge(protected)
		.fallback(|| async { ApiError::not_found("no such endpoint") })
		.with_state(state)
}

/// The scope an endpoint needs; `None` for those any accepted token may use.
fn required_scope(method: &Method, path: &str) -> Option<Scope> {
	match path {
		"/capabilities" | "/openapi.json" => None,
		"/metrics" => Some(Scope::MetricsRead),
		_ if method == Method::GET => Some(Scope::RulesRead),
		_ => Some(Scope::RulesWrite),
	}
}

async fn require_token(State(state): State<Arc<AppState>>, mut req: Request, next: Next) -> Response {
	let header = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
	let Some(principal) = state.tokens.authenticate(header) else {
		return ApiError::unauthorized().into_response();
	};
	if let Some(scope) = required_scope(req.method(), req.uri().path()) {
		if !principal.has(scope) {
			info!(event = "audit", token = %principal.name, method = %req.method(), path = %req.uri().path(),
				outcome = "forbidden", scope = scope.as_str());
			return ApiError::forbidden(format!("this token lacks the {} scope", scope.as_str())).into_response();
		}
	}
	req.extensions_mut().insert(principal);
	next.run(req).await
}

/// Refuses a change to rules outside the token's `allow_listen_ports`.
fn check_ports(principal: &Principal, first: u16, last: Option<u16>) -> AppResult<()> {
	let last = last.unwrap_or(first).max(first);
	if principal.may_use_ports(first, last) {
		return Ok(());
	}
	Err(ApiError::forbidden(format!("this token may not use listen port {first}-{last}")))
}

/// `event = "audit"`: who changed which rule, and how it went.
fn audit<T>(principal: &Principal, action: &str, rule: &str, result: &AppResult<T>) {
	let (outcome, code) = match result {
		Ok(_) => ("ok", ""),
		Err(e) => ("error", e.code),
	};
	info!(event = "audit", token = %principal.name, action, rule, outcome, code);
}

/// Parses a JSON body, reporting failures in the API's own error format.
fn parse_body<T: DeserializeOwned>(body: &Bytes) -> AppResult<T> {
	serde_json::from_slice(body).map_err(|e| ApiError::invalid(format!("invalid body: {e}")))
}

fn parse_key(protocol: &str, listen_addr: &str, listen_port: &str) -> AppResult<Key> {
	let port: u16 = listen_port.parse().map_err(|_| ApiError::invalid(format!("invalid port: {listen_port}")))?;
	Ok(Key { protocol: protocol.parse()?, listen: parse_listen(listen_addr, port)? })
}

async fn capabilities(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	let transparent = state.registry.transparent_available();
	let mut source_ip = vec![SourceIp::Proxy, SourceIp::ProxyV1, SourceIp::ProxyV2];
	if transparent {
		source_ip.push(SourceIp::Transparent);
	}
	let names: Vec<&str> = source_ip.iter().map(SourceIp::as_str).collect();
	Json(json!({
		"source_ip": names,
		"transparent": transparent,
		"transparent_ipv6": state.registry.transparent_ipv6_available(),
		"tls_modes": ["passthrough", "sni", "terminate"],
		"dtls": true,
		"starttls": ["smtp", "imap", "pop3"],
		"max_range_ports": state.registry.caps().max_range_ports,
		// v0.3 settings this build can run (docs/DESIGN-v0.3.md)
		"features": state.registry.caps().features,
	}))
}

/// The OpenAPI definition of this API (docs/openapi.json).
const OPENAPI: &str = include_str!("../docs/openapi.json");

async fn openapi() -> impl IntoResponse {
	([(header::CONTENT_TYPE, "application/json")], OPENAPI)
}

/// How the settings file (`RPROXY_CONFIG`) was last read.
async fn config_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	match state.registry.config_status() {
		Some(status) => {
			let mut v = serde_json::to_value(status).unwrap_or_default();
			v["configured"] = json!(true);
			Json(v)
		}
		None => Json(json!({"configured": false})),
	}
}

/// Addresses of this host that rules can listen on, and the ones rproxy keeps for itself.
async fn interfaces(State(state): State<Arc<AppState>>) -> AppResult<impl IntoResponse> {
	let mut list: Vec<serde_json::Value> = if_addrs::get_if_addrs()
		.map_err(|e| ApiError::internal(format!("cannot list interfaces: {e}")))?
		.into_iter()
		.filter(|i| i.is_oper_up())
		.map(|i| {
			let ip = i.ip();
			json!({
				"name": i.name,
				"addr": ip.to_string(),
				"family": if ip.is_ipv4() { "ipv4" } else { "ipv6" },
				"loopback": i.is_loopback(),
				"link_local": i.is_link_local(),
			})
		})
		.collect();
	list.sort_by_key(|v| (v["loopback"].as_bool(), v["family"] != "ipv4", v["name"].as_str().map(String::from)));
	let reserved: Vec<serde_json::Value> = state
		.registry
		.reserved()
		.iter()
		.map(|a| json!({"protocol": "tcp", "addr": a.ip().to_string(), "port": a.port(), "purpose": "control API"}))
		.collect();
	Ok(Json(json!({ "interfaces": list, "reserved": reserved })))
}

async fn list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	Json(state.registry.list().await)
}

async fn get_rule(
	State(state): State<Arc<AppState>>,
	Path((protocol, addr, port)): Path<(String, String, String)>,
) -> AppResult<impl IntoResponse> {
	let key = parse_key(&protocol, &addr, &port)?;
	Ok(Json(state.registry.get(&key).await?))
}

async fn create(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	body: Bytes,
) -> AppResult<impl IntoResponse> {
	let req: RuleRequest = parse_body(&body)?;
	let rule = parse_listen(&req.listen_addr, req.listen_port).map_or_else(|_| req.listen_addr.clone(), |a| a.to_string());
	let rule = format!("{}/{rule}", req.protocol);
	let result = async {
		check_ports(&principal, req.listen_port, req.listen_port_end)?;
		state.registry.create(req).await
	}
	.await;
	audit(&principal, "create", &rule, &result);
	Ok((StatusCode::CREATED, Json(result?)))
}

/// Checks a change to an existing rule against the token's ports (the whole range).
async fn check_rule_ports(state: &AppState, principal: &Principal, key: &Key) -> AppResult<()> {
	if principal.may_use_ports(1, 65535) {
		return Ok(());
	}
	let view = state.registry.get(key).await?;
	check_ports(principal, view.listen_port, view.listen_port_end)
}

async fn update(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Path((protocol, addr, port)): Path<(String, String, String)>,
	body: Bytes,
) -> AppResult<impl IntoResponse> {
	let key = parse_key(&protocol, &addr, &port)?;
	let req: UpdateRequest = parse_body(&body)?;
	let result = async {
		check_rule_ports(&state, &principal, &key).await?;
		state.registry.update(&key, req).await
	}
	.await;
	audit(&principal, "update", &key.to_string(), &result);
	Ok(Json(result?))
}

async fn delete(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Path((protocol, addr, port)): Path<(String, String, String)>,
	Query(query): Query<HashMap<String, String>>,
) -> AppResult<impl IntoResponse> {
	let key = parse_key(&protocol, &addr, &port)?;
	let drain = match query.get("drain_secs") {
		Some(s) => {
			let secs: u64 = s.parse().map_err(|_| ApiError::invalid(format!("invalid drain_secs: {s}")))?;
			(secs > 0).then(|| Duration::from_secs(secs))
		}
		None => None,
	};
	let result = async {
		check_rule_ports(&state, &principal, &key).await?;
		state.registry.delete(&key, drain).await
	}
	.await;
	audit(&principal, "delete", &key.to_string(), &result);
	result?;
	Ok(StatusCode::NO_CONTENT)
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	(
		[(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
		state.registry.metrics().await,
	)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Every route of the router, with its methods, is in docs/openapi.json and
	/// the document lists nothing else.
	#[test]
	fn openapi_covers_every_route() {
		let doc: serde_json::Value = serde_json::from_str(OPENAPI).unwrap();
		let mut documented: Vec<String> = vec![];
		for (path, item) in doc["paths"].as_object().unwrap() {
			for method in ["get", "post", "patch", "delete", "put"] {
				if item.get(method).is_some() {
					documented.push(format!("{method} {path}"));
				}
			}
		}
		let source = include_str!("api.rs");
		let mut routed: Vec<String> = vec![];
		for line in source.lines().map(str::trim).filter(|l| l.starts_with(".route(\"")) {
			let path = line.split('"').nth(1).unwrap();
			for method in ["get", "post", "patch", "delete", "put"] {
				if line.contains(&format!("{method}(")) {
					routed.push(format!("{method} {path}"));
				}
			}
		}
		documented.sort();
		routed.sort();
		assert!(!routed.is_empty());
		assert_eq!(documented, routed);
		// every $ref points to a schema that exists
		let schemas = doc["components"]["schemas"].as_object().unwrap();
		for r in OPENAPI.split("\"$ref\": \"#/components/schemas/").skip(1) {
			let name = r.split('"').next().unwrap();
			assert!(schemas.contains_key(name), "missing schema {name}");
		}
	}
}
