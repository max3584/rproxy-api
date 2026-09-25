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
}

impl ApiError {
	fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
		ApiError { status, code, message: message.into() }
	}

	pub fn unauthorized() -> Self {
		Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "missing or invalid bearer token")
	}

	pub fn invalid(message: impl Into<String>) -> Self {
		Self::new(StatusCode::BAD_REQUEST, "invalid", message)
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

	pub fn already_exists(message: impl Into<String>) -> Self {
		Self::new(StatusCode::CONFLICT, "already_exists", message)
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
