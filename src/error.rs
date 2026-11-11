use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// An error reported to API clients as `{"error": ..., "code": ...}`.
#[derive(Debug, Clone)]
pub struct ApiError {
	pub status: StatusCode,
	pub code: &'static str,
	pub message: String,
	/// Why, for rproxy itself (not in the response): a rule that failed for it is
	/// started again when it goes away (#347).
	pub reason: Option<Reason>,
}

/// What a rule that could not start waits for (#347).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
	/// `global.crowdsec` (or its `appsec_url`) is not in force.
	NeedsCrowdsec,
	/// `global.geoip` (or the database its lists need) is not in force (#345).
	NeedsGeoip,
	/// `global.acme` (or the resolver and names a certificate needs) is not in force (#345).
	NeedsAcme,
}

impl ApiError {
	fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
		ApiError { status, code, message: message.into(), reason: None }
	}

	pub fn unauthorized() -> Self {
		Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "missing or invalid bearer token")
	}

	pub fn forbidden(message: impl Into<String>) -> Self {
		Self::new(StatusCode::FORBIDDEN, "forbidden", message)
	}

	/// A token other than `admin` changes or deletes a rule, an overlay or a rule set another
	/// token made, or a rule whose creator is not known (#401).
	pub fn not_owner(message: impl Into<String>) -> Self {
		Self::new(StatusCode::FORBIDDEN, "not_owner", message)
	}

	/// A rule from the API names a file of the certificate store, the ACME storage or a
	/// secret of the settings (#319).
	pub fn protected_file(message: impl Into<String>) -> Self {
		Self::new(StatusCode::FORBIDDEN, "protected_file", message)
	}

	/// A token limited by `allow_certs` names a file in a rule (#319).
	pub fn file_not_allowed(message: impl Into<String>) -> Self {
		Self::new(StatusCode::FORBIDDEN, "file_not_allowed", message)
	}

	/// An OIDC client secret file used for something else too (#319).
	pub fn secret_reuse(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "secret_reuse", message)
	}

	/// A key or secret file another owner's rule names (#323).
	pub fn file_in_use(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "file_in_use", message)
	}

	pub fn invalid(message: impl Into<String>) -> Self {
		Self::new(StatusCode::BAD_REQUEST, "invalid", message)
	}

	/// `invalid` for a rule that uses `crowdsec` (or its `appsec`) without
	/// `global.crowdsec` (or its `appsec_url`) in force (#342, #347).
	pub fn needs_crowdsec(message: impl Into<String>) -> Self {
		ApiError { reason: Some(Reason::NeedsCrowdsec), ..Self::invalid(message) }
	}

	/// `400 invalid` for a rule whose `geoip` lists need a database of `global.geoip`
	/// that is not in force: started again once it is (#345).
	pub fn needs_geoip(message: impl Into<String>) -> Self {
		ApiError { reason: Some(Reason::NeedsGeoip), ..Self::invalid(message) }
	}

	/// `400 invalid` for a rule whose ACME certificate needs a `global.acme` (resolver,
	/// names) that is not in force: started again once one is (#345).
	pub fn needs_acme(message: impl Into<String>) -> Self {
		ApiError { reason: Some(Reason::NeedsAcme), ..Self::invalid(message) }
	}

	pub fn unsupported(message: impl Into<String>) -> Self {
		Self::new(StatusCode::BAD_REQUEST, "unsupported", message)
	}

	pub fn tls_config(message: impl Into<String>) -> Self {
		Self::new(StatusCode::BAD_REQUEST, "tls_config", message)
	}

	pub fn not_found(message: impl Into<String>) -> Self {
		Self::new(StatusCode::NOT_FOUND, "not_found", message)
	}

	/// A limit of the process or of the token (#358: rules, listening sockets, rule sets).
	pub fn limit(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "limit", message)
	}

	/// The control API is busy with other requests of the kind (#358): try again.
	pub fn busy(message: impl Into<String>) -> Self {
		Self::new(StatusCode::SERVICE_UNAVAILABLE, "busy", message)
	}

	/// A body larger than the endpoint takes.
	pub fn too_large(message: impl Into<String>) -> Self {
		Self::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", message)
	}

	/// A body that did not arrive in time.
	pub fn timeout(message: impl Into<String>) -> Self {
		Self::new(StatusCode::REQUEST_TIMEOUT, "timeout", message)
	}

	pub fn already_exists(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "already_exists", message)
	}

	/// An overlay (#397) on a rule that is not from the settings file.
	pub fn not_static(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "not_static", message)
	}

	/// An overlay (#397) naming what the settings file has.
	pub fn overlay_conflict(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "overlay_conflict", message)
	}

	pub fn static_rule(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "static", message)
	}

	pub fn reserved(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "reserved", message)
	}

	pub fn bind_failed(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "bind_failed", message)
	}

	pub fn resolve_failed(message: impl Into<String>) -> Self {
		Self::new(StatusCode::BAD_GATEWAY, "resolve_failed", message)
	}

	/// v0.4 (#28): the rule belongs to a rule set and cannot be changed alone.
	pub fn owned(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "owned", message)
	}

	/// v0.4 (#28): `If-Match` differs from the rule set's etag.
	pub fn precondition_failed(message: impl Into<String>) -> Self {
		Self::new(StatusCode::PRECONDITION_FAILED, "precondition_failed", message)
	}

	/// v0.4 (#28): the rule set's generation is older than the current one.
	pub fn stale_generation(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "stale_generation", message)
	}

	/// v0.4 (#167): the source is locked out after repeated authentication failures.
	pub fn locked_out(message: impl Into<String>) -> Self {
		Self::new(StatusCode::TOO_MANY_REQUESTS, "locked_out", message)
	}

	pub fn internal(message: impl Into<String>) -> Self {
		Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
	}
}

impl std::fmt::Display for ApiError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}: {}", self.code, self.message)
	}
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
	fn into_response(self) -> Response {
		(self.status, Json(json!({ "error": self.message, "code": self.code }))).into_response()
	}
}
