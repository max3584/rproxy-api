use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Extension, Path, Query, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde_json::json;
use tracing::info;

use crate::control::auth::{Principal, Scope, Tokens};
use crate::config::check::Finding;
use crate::config::reload::{ConfigReloader, Outcome};
use crate::error::ApiError;
use crate::logging::Throttle;
use crate::core::registry::Registry;
use crate::core::rule::{parse_listen, Features, Key, Origin, RuleRequest, RuleView, SourceIp, UpdateRequest};

pub struct AppState {
	pub registry: Arc<Registry>,
	pub tokens: Arc<Tokens>,
	/// The settings file (`RPROXY_CONFIG`), for `POST /config/reload`; None when there is none.
	pub reloader: Option<Arc<ConfigReloader>>,
	/// `POST /config/reload` only over the Unix socket (`RPROXY_API_RELOAD_UNIX_ONLY`).
	pub reload_unix_only: bool,
}

/// How a request reached the control API. The Unix socket's router carries
/// `Transport::UnixSocket` as an extension; TCP requests have none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
	UnixSocket,
}

type AppResult<T> = Result<T, ApiError>;

/// Who sent a request, for the audit log: the peer's IP address (TCP; the server
/// must give `ConnectInfo<SocketAddr>`), `unix` (the Unix socket) or `unknown`.
#[derive(Clone, Debug)]
pub struct Client(pub String);

impl Client {
	fn of(req: &Request) -> Client {
		if req.extensions().get::<Transport>().is_some() {
			return Client("unix".into());
		}
		match req.extensions().get::<ConnectInfo<SocketAddr>>() {
			Some(ConnectInfo(addr)) => Client(crate::l7::access::canonical(addr.ip()).to_string()),
			None => Client("unknown".into()),
		}
	}
}

/// State of the token check: the app, and the refusals logged per client.
type Guard = (Arc<AppState>, Arc<Throttle<String>>);

pub fn router(state: Arc<AppState>) -> Router {
	let protected = Router::new()
		.route("/capabilities", get(capabilities))
		.route("/openapi.json", get(openapi))
		.route("/config", get(config_status))
		.route("/config/reload", post(config_reload))
		.route("/interfaces", get(interfaces))
		.route("/rules", get(list).post(create))
		.route("/rules/{protocol}/{listen_addr}/{listen_port}", get(get_rule).patch(update).delete(delete))
		.route("/metrics", get(metrics))
		.route("/acme", get(super::acme_api::view))
		.route("/acme/renew", post(super::acme_api::renew))
		.route("/acme/revoke", post(super::acme_api::revoke))
		.route("/acme/accounts/{name}/register", post(super::acme_api::register))
		.route("/acme/accounts/{name}/deactivate", post(super::acme_api::deactivate))
		// v0.4 (docs/DESIGN-v0.4.md): rule sets (#28), plan (#169), upgrade / update (#174)
		.route("/rulesets", get(super::ruleset_api::list))
		.route("/rulesets/{*name}", get(super::ruleset_api::get).put(super::ruleset_api::put).delete(super::ruleset_api::delete).layer(axum::extract::DefaultBodyLimit::max(crate::core::ruleset::MAX_BODY)))
		.route("/config/plan", post(config_plan))
		.route("/admin/upgrade", post(super::upgrade::upgrade))
		.route("/admin/update", get(super::upgrade::update_status).post(super::upgrade::update_now))
		.route_layer(middleware::from_fn_with_state((state.clone(), Arc::new(Throttle::default())), require_token));

	Router::new()
		.route("/healthz", get(|| async { "ok" }))
		.route("/readyz", get(super::ruleset_api::readyz))
		.merge(protected)
		.fallback(|| async { ApiError::not_found("no such endpoint") })
		.with_state(state)
}

/// The scope an endpoint needs; `None` for those any accepted token may use.
fn required_scope(method: &Method, path: &str) -> Option<Scope> {
	match path {
		"/capabilities" | "/openapi.json" => None,
		"/metrics" => Some(Scope::MetricsRead),
		// re-reads files on the host: only for administrators
		"/config/reload" | "/config/plan" => Some(Scope::Admin),
		_ if path.starts_with("/admin/") => Some(Scope::Admin),
		// the handlers check acme:write (and the Unix socket) themselves, to answer why
		_ if path.starts_with("/acme/") && method == Method::POST => None,
		_ if method == Method::GET => Some(Scope::RulesRead),
		_ => Some(Scope::RulesWrite),
	}
}

/// Checks the bearer token or client certificate, and the scope. Refusals are
/// logged as `event = "audit"` with the client (never the token), at most
/// `Throttle`'s rate per client. Over TCP, sources that keep failing are locked
/// out for a while (#167; never over the Unix socket).
async fn require_token(State((state, refusals)): State<Guard>, mut req: Request, next: Next) -> Response {
	let client = Client::of(&req);
	// the source counted by the lockout: TCP only
	let source = match req.extensions().get::<Transport>() {
		Some(_) => None,
		None => req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(a)| a.ip()),
	};
	if let Some(left) = source.filter(|_| state.tokens.enabled()).and_then(|ip| state.tokens.lockout().locked(ip)) {
		if let Some(suppressed) = refusals.check(&client.0) {
			info!(event = "audit", client = %client.0, method = %req.method(), path = %req.uri().path(),
				outcome = "locked_out", suppressed);
		}
		let secs = left.as_secs() + u64::from(left.subsec_nanos() > 0);
		let mut res =
			ApiError::locked_out("too many failed authentications from this address; try again later").into_response();
		res.headers_mut().insert(header::RETRY_AFTER, header::HeaderValue::from(secs.max(1)));
		return res;
	}
	let header = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok());
	let cert = req.extensions().get::<crate::control::hardening::ClientCert>().cloned().unwrap_or_default();
	let principal = match state.tokens.check_with(header, cert.names()) {
		Ok(p) => p,
		Err(reason) => {
			if let Some(suppressed) = refusals.check(&client.0) {
				info!(event = "audit", client = %client.0, method = %req.method(), path = %req.uri().path(),
					outcome = "unauthorized", reason, suppressed);
			}
			if let Some(ip) = source {
				state.tokens.lockout().failed(ip);
			}
			return ApiError::unauthorized().into_response();
		}
	};
	if let Some(scope) = required_scope(req.method(), req.uri().path()) {
		if !principal.has(scope) {
			if let Some(suppressed) = refusals.check(&client.0) {
				info!(event = "audit", token = %principal.name, auth = principal.auth, client = %client.0, method = %req.method(),
					path = %req.uri().path(), outcome = "forbidden", scope = scope.as_str(), suppressed);
			}
			return ApiError::forbidden(format!("this token lacks the {} scope", scope.as_str())).into_response();
		}
	}
	req.extensions_mut().insert(principal);
	req.extensions_mut().insert(client);
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
fn audit<T>(principal: &Principal, client: &Client, action: &str, rule: &str, result: &AppResult<T>) {
	let (outcome, code) = match result {
		Ok(_) => ("ok", ""),
		// refused by the token's allow_listen_ports
		Err(e) if e.code == "forbidden" => ("forbidden", e.code),
		Err(e) => ("error", e.code),
	};
	info!(event = "audit", token = %principal.name, auth = principal.auth, client = %client.0, action, rule, outcome, code);
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
		// the release of this build (Cargo.toml); the UI compares it with the
		// oldest rproxy-api it supports (docs/RELEASING.md)
		"version": env!("CARGO_PKG_VERSION"),
		"source_ip": names,
		"transparent": transparent,
		"transparent_ipv6": state.registry.transparent_ipv6_available(),
		"tls_modes": ["passthrough", "sni", "terminate"],
		"dtls": true,
		"starttls": ["smtp", "imap", "pop3"],
		"max_range_ports": state.registry.caps().max_range_ports,
		// v0.3 / v0.4 settings this build can run (docs/DESIGN-v0.3.md, docs/DESIGN-v0.4.md)
		"features": state.registry.caps().features,
		// the running binary (#174)
		"build": super::upgrade::build_view(),
	}))
}

/// The OpenAPI definition of this API (docs/openapi.json).
const OPENAPI: &str = include_str!("../../docs/openapi.json");

async fn openapi() -> impl IntoResponse {
	([(header::CONTENT_TYPE, "application/json")], OPENAPI)
}

/// How the settings file (`RPROXY_CONFIG`) was last read.
async fn config_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	let mut v = match state.registry.config_status() {
		Some(status) => {
			let mut v = serde_json::to_value(status).unwrap_or_default();
			v["configured"] = json!(true);
			v
		}
		None => json!({"configured": false}),
	};
	// global.crowdsec: whether the LAPI answers now (#115)
	if let Some(b) = state.registry.http_global().crowdsec() {
		v["crowdsec"] = serde_json::to_value(b.status()).unwrap_or_default();
	}
	Json(v)
}

/// Applies the settings file again now and answers what happened (the same as
/// the file watcher and SIGHUP do, but the caller learns the result).
async fn config_reload(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	transport: Option<Extension<Transport>>,
	Query(query): Query<HashMap<String, String>>,
) -> Response {
	let audit = |outcome: &str, code: &str| {
		info!(event = "audit", token = %principal.name, auth = principal.auth, client = %client.0, action = "config.reload", rule = "", outcome, code);
	};
	if state.reload_unix_only && transport.is_none() {
		audit("forbidden", "unix_only");
		return ApiError::forbidden(
			"POST /config/reload is accepted only over the Unix socket (RPROXY_API_SOCKET); set RPROXY_API_RELOAD_UNIX_ONLY=false to allow it over TCP",
		)
		.into_response();
	}
	let Some(reloader) = &state.reloader else {
		audit("error", "no_config");
		return (StatusCode::CONFLICT, Json(json!({"code": "no_config", "error": "no settings file (RPROXY_CONFIG) is configured"})))
			.into_response();
	};
	match crate::config::plan::dry_run(&query) {
		Ok(false) => {}
		Ok(true) => {
			let doc = match crate::config::ConfigDoc::load(reloader.path()) {
				Ok(doc) => doc,
				Err(e) => {
					let (errors, warnings) = reloader.findings().await;
					let error = e.to_string();
					let errors = if errors.is_empty() { vec![Finding { rule: String::new(), message: error.clone() }] } else { errors };
					return plan_failed(crate::config::plan::PlanError { error, errors, warnings });
				}
			};
			return config_plan_answer(&state, reloader.base(), &doc).await;
		}
		Err(e) => return e.into_response(),
	}
	match reloader.reload(true).await {
		Outcome::Applied(applied) => {
			audit("ok", "");
			let (errors, warnings) = reloader.findings().await;
			// applied anyway (e.g. a rule registered as failed): report them as warnings
			let warnings: Vec<_> = errors.into_iter().chain(warnings).collect();
			let mut v = serde_json::to_value(&applied).unwrap_or_default();
			v["warnings"] = json!(warnings);
			(StatusCode::OK, Json(v)).into_response()
		}
		Outcome::Failed(error) => {
			audit("error", "invalid");
			let (errors, warnings) = reloader.findings().await;
			let errors = if errors.is_empty() { vec![Finding { rule: String::new(), message: error.clone() }] } else { errors };
			(StatusCode::BAD_REQUEST, Json(json!({"code": "invalid", "error": error, "errors": errors, "warnings": warnings})))
				.into_response()
		}
		// forced reloads always read the files
		Outcome::Unchanged => (StatusCode::OK, Json(json!({}))).into_response(),
	}
}

/// Refuses a strong operation that did not come over the Unix socket while
/// `RPROXY_API_RELOAD_UNIX_ONLY` is on.
pub(crate) fn unix_only(state: &AppState, over_unix: bool, what: &str) -> AppResult<()> {
	if state.reload_unix_only && !over_unix {
		return Err(ApiError::forbidden(format!(
			"{what} is accepted only over the Unix socket (RPROXY_API_SOCKET); set RPROXY_API_RELOAD_UNIX_ONLY=false to allow it over TCP"
		)));
	}
	Ok(())
}

/// `400 invalid` for settings that would not apply, with what `--check-config` finds.
fn plan_failed(e: crate::config::plan::PlanError) -> Response {
	(StatusCode::BAD_REQUEST, Json(json!({"code": "invalid", "error": e.error, "errors": e.errors, "warnings": e.warnings})))
		.into_response()
}

async fn config_plan_answer(state: &AppState, base: &crate::config::ConfigDoc, doc: &crate::config::ConfigDoc) -> Response {
	match crate::config::plan::plan_config(&state.registry, base, doc).await {
		Ok(plan) => (StatusCode::OK, Json(plan)).into_response(),
		Err(e) => plan_failed(e),
	}
}

/// `POST /config/plan` (#169): the settings in the body against what runs.
async fn config_plan(
	State(state): State<Arc<AppState>>,
	transport: Option<Extension<Transport>>,
	body: Bytes,
) -> AppResult<Response> {
	unix_only(&state, transport.is_some(), "POST /config/plan")?;
	let doc: serde_json::Value = parse_body(&body)?;
	let doc = crate::config::ConfigDoc::from_value(doc).map_err(ApiError::invalid)?;
	let none = crate::config::ConfigDoc::default();
	let base = state.reloader.as_ref().map(|r| r.base()).unwrap_or(&none);
	Ok(config_plan_answer(&state, base, &doc).await)
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
	Extension(client): Extension<Client>,
	Query(query): Query<HashMap<String, String>>,
	body: Bytes,
) -> AppResult<impl IntoResponse> {
	let req: RuleRequest = parse_body(&body)?;
	if crate::config::plan::dry_run(&query)? {
		check_ports(&principal, req.listen_port, req.listen_port_end)?;
		super::acme_api::check_rule_scope(&principal, Some(&req), None)?;
		return Ok((StatusCode::OK, Json(crate::config::plan::plan_create(&state.registry, req).await?)).into_response());
	}
	let rule = parse_listen(&req.listen_addr, req.listen_port).map_or_else(|_| req.listen_addr.clone(), |a| a.to_string());
	let rule = format!("{}/{rule}", req.protocol);
	// #144: rules of a persist: true token are stored in rproxy_rules
	let store = state.registry.persist().filter(|_| principal.persist && Features::CURRENT.persistence).cloned();
	let origin = if store.is_some() { Origin::Api } else { Origin::Dynamic };
	let result = async {
		check_ports(&principal, req.listen_port, req.listen_port_end)?;
		super::acme_api::check_rule_scope(&principal, Some(&req), None)?;
		state.registry.create_as(req, origin).await
	}
	.await;
	audit(&principal, &client, "create", &rule, &result);
	let view = persisted(&state, store.as_deref(), result?, &principal).await;
	Ok((StatusCode::CREATED, Json(view)).into_response())
}

/// Writes an `api` rule's row after a change and answers its view with `persisted`.
async fn persisted(state: &AppState, store: Option<&crate::config::persist::Store>, view: RuleView, principal: &Principal) -> RuleView {
	let Some(store) = store.filter(|_| view.origin == Origin::Api) else { return view };
	let Ok(listen) = parse_listen(&view.listen_addr, view.listen_port) else { return view };
	let key = Key { protocol: view.protocol, listen };
	store.save(&state.registry, &key, &principal.name).await;
	state.registry.get(&key).await.unwrap_or(view)
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
	Extension(client): Extension<Client>,
	Path((protocol, addr, port)): Path<(String, String, String)>,
	Query(query): Query<HashMap<String, String>>,
	body: Bytes,
) -> AppResult<impl IntoResponse> {
	let key = parse_key(&protocol, &addr, &port)?;
	let req: UpdateRequest = parse_body(&body)?;
	if crate::config::plan::dry_run(&query)? {
		check_rule_ports(&state, &principal, &key).await?;
		super::acme_api::check_rule_scope(&principal, None, Some(&req))?;
		return Ok(Json(crate::config::plan::plan_update(&state.registry, &key, req).await?).into_response());
	}
	let result = async {
		check_rule_ports(&state, &principal, &key).await?;
		super::acme_api::check_rule_scope(&principal, None, Some(&req))?;
		state.registry.update(&key, req).await
	}
	.await;
	audit(&principal, &client, "update", &key.to_string(), &result);
	let store = state.registry.persist().filter(|_| Features::CURRENT.persistence).cloned();
	Ok(Json(persisted(&state, store.as_deref(), result?, &principal).await).into_response())
}

async fn delete(
	State(state): State<Arc<AppState>>,
	Extension(principal): Extension<Principal>,
	Extension(client): Extension<Client>,
	Path((protocol, addr, port)): Path<(String, String, String)>,
	Query(query): Query<HashMap<String, String>>,
) -> AppResult<impl IntoResponse> {
	let key = parse_key(&protocol, &addr, &port)?;
	if crate::config::plan::dry_run(&query)? {
		check_rule_ports(&state, &principal, &key).await?;
		return Ok(Json(crate::config::plan::plan_delete(&state.registry, &key).await?).into_response());
	}
	let drain = match query.get("drain_secs") {
		Some(s) => {
			let secs: u64 = s.parse().map_err(|_| ApiError::invalid(format!("invalid drain_secs: {s}")))?;
			(secs > 0).then(|| Duration::from_secs(secs))
		}
		None => None,
	};
	// #144: the row of an api rule goes with it
	let stored = match state.registry.persist() {
		Some(store) if state.registry.get(&key).await.is_ok_and(|v| v.origin == Origin::Api) => Some(store.clone()),
		_ => None,
	};
	let result = async {
		check_rule_ports(&state, &principal, &key).await?;
		state.registry.delete(&key, drain).await
	}
	.await;
	audit(&principal, &client, "delete", &key.to_string(), &result);
	result?;
	if let Some(store) = stored {
		store.remove(&key, &principal.name).await;
	}
	Ok(StatusCode::NO_CONTENT.into_response())
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
	let mut text = state.registry.metrics().await;
	text.push_str(&crate::control::hardening::metrics(&state.tokens));
	text.push_str(&super::upgrade::metrics());
	([(header::CONTENT_TYPE, "text/plain; version=0.0.4")], text)
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
			// a wildcard segment ({*name}) is documented as {name}
			let path = line.split('"').nth(1).unwrap().replace("{*", "{");
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
