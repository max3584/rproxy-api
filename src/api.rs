use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::auth::Tokens;
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

async fn require_token(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
	let header = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
	if !state.tokens.allows(header) {
		return ApiError::unauthorized().into_response();
	}
	next.run(req).await
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
		"tls_modes": ["passthrough", "sni", "terminate"],
		"dtls": true,
		"starttls": ["smtp", "imap", "pop3"],
		"max_range_ports": state.registry.caps().max_range_ports,
	}))
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

async fn create(State(state): State<Arc<AppState>>, body: Bytes) -> AppResult<impl IntoResponse> {
	let req: RuleRequest = parse_body(&body)?;
	let view = state.registry.create(req).await?;
	Ok((StatusCode::CREATED, Json(view)))
}

async fn update(
	State(state): State<Arc<AppState>>,
	Path((protocol, addr, port)): Path<(String, String, String)>,
	body: Bytes,
) -> AppResult<impl IntoResponse> {
	let key = parse_key(&protocol, &addr, &port)?;
	let req: UpdateRequest = parse_body(&body)?;
	Ok(Json(state.registry.update(&key, req).await?))
}

async fn delete(
	State(state): State<Arc<AppState>>,
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
	state.registry.delete(&key, drain).await?;
	Ok(StatusCode::NO_CONTENT)
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	(
		[(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
		state.registry.metrics().await,
	)
}
