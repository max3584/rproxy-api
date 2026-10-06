//! Live upgrade and container self-update (#174, docs/DESIGN-v0.4.md 10.):
//! handing the listening sockets over to a new binary of the same minor
//! (SIGUSR2 / `POST /admin/upgrade`), and the launcher that follows the newest
//! signed patch of the image's X.Y (`RPROXY_UPDATE*`, `GET` / `POST /admin/update`).
//!
//! v0.4.0 settles the shape; `features.handoff` and `features.self_update` say
//! whether this build does it.

use std::time::Duration;

use crate::core::rule::Features;

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
fn own_minor() -> (u64, u64) {
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

/// `POST /admin/upgrade`: a handoff to the binary now on disk (`admin`, by
/// default only over the Unix socket).
pub async fn upgrade(
	axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::control::api::AppState>>,
	transport: Option<axum::extract::Extension<crate::control::api::Transport>>,
) -> crate::error::ApiError {
	if let Err(e) = crate::control::api::unix_only(&state, transport.is_some(), "POST /admin/upgrade") {
		return e;
	}
	unavailable("live upgrade (handoff)")
}

/// `GET /admin/update`: the self-update state (`admin`).
pub async fn update_status() -> crate::error::ApiError {
	unavailable("self-update")
}

/// `POST /admin/update`: check for a new patch now (`admin`, by default only over the Unix socket).
pub async fn update_now(
	axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::control::api::AppState>>,
	transport: Option<axum::extract::Extension<crate::control::api::Transport>>,
) -> crate::error::ApiError {
	if let Err(e) = crate::control::api::unix_only(&state, transport.is_some(), "POST /admin/update") {
		return e;
	}
	unavailable("self-update")
}

fn unavailable(what: &str) -> crate::error::ApiError {
	crate::error::ApiError::unsupported(format!("{what} is not available in this version (see GET /capabilities features)"))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn options_are_checked_and_ignored_until_available() {
		let none = Features::CURRENT;
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
