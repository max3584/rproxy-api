//! Live upgrade and container self-update (#174, docs/DESIGN-v0.4.md 10.):
//! handing the listening sockets over to a new binary of the same minor
//! (SIGUSR2 / `POST /admin/upgrade`), and the launcher that follows the newest
//! signed patch of the image's X.Y (`RPROXY_UPDATE*`, `GET` / `POST /admin/update`).
//!
//! - `handoff`: the live upgrade (both sides), `inherit`: the sockets the new
//!   process received, `fdpass`: the channel (SCM_RIGHTS), `notify`: sd_notify
//! - `update`: fetching and verifying releases, the cache, `minisign`: signatures,
//!   `launch`: `rproxy-api launch` (the container's entry point)

pub mod fdpass;
pub mod handoff;
pub mod inherit;
pub mod launch;
pub mod minisign;
pub mod notify;
pub mod update;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde_json::json;

use crate::control::api::{AppState, Transport};
use crate::core::rule::Features;
use crate::error::ApiError;

/// `RPROXY_UPDATE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum UpdateMode {
	/// No self-update (default; apt manages VMs).
	#[default]
	Off,
	/// Fetch and verify new patches; only report them.
	Check,
	/// Swap verified patches in with a handoff.
	Auto,
}

pub const DEFAULT_HANDOFF_SOCKET: &str = "/run/rproxy/handoff.sock";
pub const DEFAULT_HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_HANDOFF_DRAIN: Duration = Duration::from_secs(300);
pub const DEFAULT_UPDATE_SOURCE: &str = "https://github.com/max3584/rproxy-api/releases";
pub const DEFAULT_UPDATE_CACHE: &str = "/var/cache/rproxy/update";
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(6 * 3600);
pub const DEFAULT_UPDATE_HEALTHY: Duration = Duration::from_secs(60);

/// The handoff and update options as given (None: left out).
#[derive(Clone, Debug, Default)]
pub struct UpgradeOptions {
	pub handoff_socket: Option<std::path::PathBuf>,
	pub handoff_timeout: Option<String>,
	pub handoff_drain: Option<String>,
	pub update: Option<UpdateMode>,
	pub update_pin: Option<String>,
	pub update_source: Option<String>,
	pub update_cache: Option<std::path::PathBuf>,
	pub update_interval: Option<String>,
	pub update_pubkey: Option<std::path::PathBuf>,
	pub update_healthy: Option<String>,
}

/// Errors stop the startup; `ignored` options are logged as `degraded`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
	pub errors: Vec<String>,
	pub ignored: Vec<&'static str>,
}

fn duration(what: &str, v: &Option<String>, min: Duration, max: Duration, errors: &mut Vec<String>) {
	let Some(v) = v else { return };
	match crate::l7::parse_duration(v) {
		Ok(d) if d >= min && d <= max => {}
		Ok(_) => errors.push(format!("{what}: {v} is out of range")),
		Err(e) => errors.push(format!("{what}: {e}")),
	}
}

/// The release this build belongs to, as (major, minor).
pub(crate) fn own_minor() -> (u64, u64) {
	let mut it = env!("CARGO_PKG_VERSION").split('.').map(|p| p.parse().unwrap_or(0));
	(it.next().unwrap_or(0), it.next().unwrap_or(0))
}

/// `RPROXY_UPDATE_PIN`: `X.Y.Z` within this build's X.Y.
pub fn check_pin(pin: &str) -> Result<(), String> {
	let parts: Vec<&str> = pin.trim().split('.').collect();
	let nums: Option<Vec<u64>> = parts.iter().map(|p| p.parse().ok()).collect();
	match nums.as_deref() {
		Some([major, minor, _]) if (*major, *minor) == own_minor() => Ok(()),
		Some([_, _, _]) => {
			let (a, b) = own_minor();
			Err(format!("RPROXY_UPDATE_PIN {pin} is outside {a}.{b} (handoffs stay within one minor)"))
		}
		_ => Err(format!("RPROXY_UPDATE_PIN {pin:?} is not a version like 0.4.3")),
	}
}

impl UpgradeOptions {
	pub fn check(&self, features: &Features) -> Verdict {
		let mut v = Verdict::default();
		let hour = Duration::from_secs(3600);
		duration("--handoff-timeout", &self.handoff_timeout, Duration::from_secs(1), Duration::from_secs(600), &mut v.errors);
		duration("--handoff-drain", &self.handoff_drain, Duration::ZERO, 24 * hour, &mut v.errors);
		duration("RPROXY_UPDATE_INTERVAL", &self.update_interval, Duration::ZERO, 7 * 24 * hour, &mut v.errors);
		duration("RPROXY_UPDATE_HEALTHY", &self.update_healthy, Duration::from_secs(1), hour, &mut v.errors);
		if let Some(pin) = &self.update_pin {
			if let Err(e) = check_pin(pin) {
				v.errors.push(e);
			}
		}
		if let Some(src) = &self.update_source {
			if !src.starts_with("https://") {
				v.errors.push(format!("RPROXY_UPDATE_SOURCE must be an https:// URL: {src}"));
			}
		}
		let handoff_set = self.handoff_socket.is_some() || self.handoff_timeout.is_some() || self.handoff_drain.is_some();
		if !features.handoff && handoff_set {
			v.ignored.push("--handoff-*");
		}
		let update_set = self.update.is_some_and(|m| m != UpdateMode::Off)
			|| self.update_pin.is_some()
			|| self.update_source.is_some()
			|| self.update_cache.is_some()
			|| self.update_interval.is_some()
			|| self.update_pubkey.is_some()
			|| self.update_healthy.is_some();
		if !features.self_update && update_set {
			v.ignored.push("RPROXY_UPDATE*");
		}
		v
	}
}

impl UpgradeOptions {
	/// The handoff settings with their defaults (after `check`).
	pub fn handoff_config(&self) -> handoff::Config {
		let d = |v: &Option<String>, default: Duration| v.as_deref().and_then(|v| crate::l7::parse_duration(v).ok()).unwrap_or(default);
		handoff::Config {
			socket: self.handoff_socket.clone().unwrap_or_else(|| DEFAULT_HANDOFF_SOCKET.into()),
			timeout: d(&self.handoff_timeout, DEFAULT_HANDOFF_TIMEOUT),
			drain: d(&self.handoff_drain, DEFAULT_HANDOFF_DRAIN),
		}
	}

	/// The self-update settings with their defaults (after `check`).
	pub fn update_config(&self) -> update::UpdateConfig {
		let d = |v: &Option<String>, default: Duration| v.as_deref().and_then(|v| crate::l7::parse_duration(v).ok()).unwrap_or(default);
		update::UpdateConfig {
			mode: self.update.unwrap_or_default(),
			pin: self.update_pin.as_deref().and_then(update::Version::parse),
			source: self.update_source.clone().unwrap_or_else(|| DEFAULT_UPDATE_SOURCE.into()),
			cache: self.update_cache.clone().unwrap_or_else(|| DEFAULT_UPDATE_CACHE.into()),
			interval: d(&self.update_interval, DEFAULT_UPDATE_INTERVAL),
			pubkey: self.update_pubkey.clone(),
			healthy: d(&self.update_healthy, DEFAULT_UPDATE_HEALTHY),
			ca_file: std::env::var("RPROXY_UPDATE_CA_FILE").ok().filter(|v| !v.is_empty()),
		}
	}
}

/// The live upgrade and the self-update of this process (set by `main`; the
/// router has none in tests that build it as a library).
pub struct Upgrade {
	pub upgrader: Arc<handoff::Upgrader>,
	pub updater: Arc<update::Updater>,
}

static UPGRADE: OnceLock<Upgrade> = OnceLock::new();

pub fn install(u: Upgrade) {
	let _ = UPGRADE.set(u);
}

pub fn installed() -> Option<&'static Upgrade> {
	UPGRADE.get()
}

/// When this process (or the first one before live upgrades) started.
static PROCESS_START: OnceLock<f64> = OnceLock::new();

/// `rproxy_process_start_time_seconds`: kept over live upgrades.
pub fn process_start_time() -> f64 {
	*PROCESS_START.get_or_init(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0))
}

/// Takes the start time over from the old process (a live upgrade).
pub fn set_process_start_time(t: f64) {
	let _ = PROCESS_START.set(t);
}

static BUILD_SHA256: OnceLock<String> = OnceLock::new();

/// SHA-256 of the running binary (None until `hash_binary` has read it).
pub fn build_sha256() -> Option<String> {
	BUILD_SHA256.get().cloned()
}

/// Reads the running binary once for `build_sha256` (in the background).
pub fn hash_binary() {
	std::thread::spawn(|| {
		use sha2::Digest;
		use std::io::Read;
		let Ok(mut f) = std::fs::File::open("/proc/self/exe") else { return };
		let mut h = sha2::Sha256::new();
		let mut buf = vec![0u8; 1 << 16];
		loop {
			match f.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => h.update(&buf[..n]),
				Err(_) => return,
			}
		}
		let _ = BUILD_SHA256.set(h.finalize().iter().map(|b| format!("{b:02x}")).collect());
	});
}

/// `build` of `GET /capabilities`.
pub fn build_view() -> serde_json::Value {
	json!({"version": env!("CARGO_PKG_VERSION"), "sha256": build_sha256()})
}

/// `rproxy_build_info`, `rproxy_handoffs_total`, `rproxy_process_start_time_seconds`.
pub fn metrics() -> String {
	use std::fmt::Write as _;
	use std::sync::atomic::Ordering;
	let mut out = String::new();
	let _ = writeln!(out, "# HELP rproxy_build_info The running binary (version, SHA-256).");
	let _ = writeln!(out, "# TYPE rproxy_build_info gauge");
	let _ = writeln!(out, "rproxy_build_info{{version=\"{}\",sha256=\"{}\"}} 1", env!("CARGO_PKG_VERSION"), build_sha256().unwrap_or_default());
	let _ = writeln!(out, "# HELP rproxy_handoffs_total Live upgrades this process started, by outcome.");
	let _ = writeln!(out, "# TYPE rproxy_handoffs_total counter");
	let o = &handoff::OUTCOMES;
	for (outcome, n) in [("done", &o.done), ("failed", &o.failed), ("refused", &o.refused)] {
		let _ = writeln!(out, "rproxy_handoffs_total{{outcome=\"{outcome}\"}} {}", n.load(Ordering::Relaxed));
	}
	let _ = writeln!(out, "# HELP rproxy_process_start_time_seconds When rproxy started (kept over live upgrades), Unix seconds.");
	let _ = writeln!(out, "# TYPE rproxy_process_start_time_seconds gauge");
	let _ = writeln!(out, "rproxy_process_start_time_seconds {}", process_start_time());
	out
}

/// While a live upgrade runs (and after it, in the old process), requests that
/// change something get `503 upgrading`: the old process's state has been
/// handed over, and a change it made now would be lost.
pub async fn guard(req: Request, next: Next) -> Response {
	let reads = matches!(*req.method(), Method::GET | Method::HEAD);
	if handoff::active() && !reads && !req.uri().path().starts_with("/admin/") {
		return upgrading("a live upgrade is in progress; send the request again in a moment").into_response();
	}
	next.run(req).await
}

fn upgrading(message: &str) -> ApiError {
	ApiError { status: StatusCode::SERVICE_UNAVAILABLE, code: "upgrading", message: message.into() }
}

/// `POST /admin/upgrade`: a handoff to the binary now on disk (`admin`, by
/// default only over the Unix socket).
pub async fn upgrade(State(state): State<Arc<AppState>>, transport: Option<Extension<Transport>>) -> Response {
	if let Err(e) = crate::control::api::unix_only(&state, transport.is_some(), "POST /admin/upgrade") {
		return e.into_response();
	}
	let Some(u) = installed() else {
		return ApiError::unsupported("live upgrades are run by the rproxy-api server process only").into_response();
	};
	match u.upgrader.start(None, "api") {
		Ok(()) => (StatusCode::ACCEPTED, Json(json!({"status": "started"}))).into_response(),
		Err(e) => ApiError { status: StatusCode::CONFLICT, code: "upgrading", message: e }.into_response(),
	}
}

/// `GET /admin/update`: the self-update state (`admin`).
pub async fn update_status() -> Response {
	match installed() {
		Some(u) => Json(u.updater.status()).into_response(),
		None => Json(json!({
			"mode": "off",
			"current": {"version": env!("CARGO_PKG_VERSION"), "sha256": build_sha256()},
			"available": null,
			"last_check": null,
			"error": null,
			"bad_versions": [],
		}))
		.into_response(),
	}
}

/// `POST /admin/update`: check for a new patch now (`admin`, by default only over the Unix socket).
pub async fn update_now(State(state): State<Arc<AppState>>, transport: Option<Extension<Transport>>) -> Response {
	if let Err(e) = crate::control::api::unix_only(&state, transport.is_some(), "POST /admin/update") {
		return e.into_response();
	}
	let Some(u) = installed() else {
		return ApiError::unsupported("the self-update runs in the rproxy-api server process only").into_response();
	};
	if u.updater.config().mode == UpdateMode::Off {
		return ApiError::unsupported("the self-update is off (RPROXY_UPDATE=check or auto)").into_response();
	}
	let updater = u.updater.clone();
	tokio::spawn(async move {
		if let Err(e) = updater.check_now().await {
			tracing::warn!(event = "update.error", error = %e);
		}
	});
	(StatusCode::ACCEPTED, Json(json!({"status": "checking"}))).into_response()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn options_are_checked_and_ignored_until_available() {
		let none = Features { handoff: false, self_update: false, ..Features::CURRENT };
		assert_eq!(UpgradeOptions::default().check(&none), Verdict::default());
		let (a, b) = own_minor();
		let auto = UpgradeOptions {
			update: Some(UpdateMode::Auto),
			update_pin: Some(format!("{a}.{b}.7")),
			update_interval: Some("6h".into()),
			handoff_drain: Some("5m".into()),
			..Default::default()
		};
		let v = auto.check(&none);
		assert!(v.errors.is_empty(), "{v:?}");
		assert_eq!(v.ignored, ["--handoff-*", "RPROXY_UPDATE*"]);
		assert!(auto.check(&Features::ALL).ignored.is_empty());
		let bad = UpgradeOptions {
			update_pin: Some(format!("{}.{}.0", a + 1, b)),
			update_source: Some("http://mirror".into()),
			handoff_timeout: Some("0s".into()),
			..Default::default()
		};
		assert_eq!(bad.check(&Features::ALL).errors.len(), 3, "{:?}", bad.check(&Features::ALL));
		assert!(check_pin("latest").is_err());
	}
}
