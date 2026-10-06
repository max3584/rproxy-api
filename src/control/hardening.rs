//! Control API hardening (#167, docs/DESIGN-v0.4.md 6.): client certificates
//! (mTLS) for the control API's TLS, token expiry warnings, and locking out
//! sources that keep failing authentication.
//!
//! v0.4.0 settles the shape; `features.client_cert_auth`, `features.token_expiry`
//! and `features.api_lockout` say whether this build applies it.

use std::time::Duration;

use crate::core::rule::Features;

/// `--tls-client-auth` / `RPROXY_TLS_CLIENT_AUTH`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ClientAuth {
	/// No client certificates (default).
	#[default]
	None,
	/// Verified when presented.
	Optional,
	/// Connections without a valid certificate fail the TLS handshake.
	Required,
}

pub const DEFAULT_TOKEN_WARN_DAYS: u64 = 14;
pub const DEFAULT_LOCKOUT_FAILURES: u32 = 20;
pub const DEFAULT_LOCKOUT_WINDOW: Duration = Duration::from_secs(60);
pub const DEFAULT_LOCKOUT_DURATION: Duration = Duration::from_secs(300);
/// Most sources remembered by the lockout.
pub const LOCKOUT_SOURCES: usize = 4096;

/// The hardening options as given (None: left out, so the default applies).
#[derive(Clone, Debug, Default)]
pub struct HardeningOptions {
	pub tls_client_ca: Option<std::path::PathBuf>,
	pub tls_client_auth: Option<ClientAuth>,
	pub has_tls_cert: bool,
	pub token_warn_days: Option<u64>,
	pub lockout_failures: Option<u32>,
	pub lockout_window: Option<String>,
	pub lockout_duration: Option<String>,
}

/// What the options mean for this build: errors stop the startup, warnings
/// are logged as `degraded` and the option is ignored.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
	pub errors: Vec<String>,
	/// Options this build cannot apply yet (`--flag` names).
	pub ignored: Vec<&'static str>,
}

fn lockout_duration(what: &str, v: &Option<String>) -> Result<(), String> {
	if let Some(v) = v {
		let d = crate::l7::parse_duration(v).map_err(|e| format!("{what}: {e}"))?;
		if d < Duration::from_secs(1) || d > Duration::from_secs(86_400) {
			return Err(format!("{what} must be 1s-24h"));
		}
	}
	Ok(())
}

impl HardeningOptions {
	pub fn check(&self, features: &Features) -> Verdict {
		let mut v = Verdict::default();
		let auth = self.tls_client_auth.unwrap_or_default();
		if auth != ClientAuth::None && self.tls_client_ca.is_none() {
			v.errors.push("--tls-client-auth optional / required needs --tls-client-ca (RPROXY_TLS_CLIENT_CA)".into());
		}
		if self.tls_client_ca.is_some() && !self.has_tls_cert {
			v.errors.push("--tls-client-ca needs --tls-cert / --tls-key (client certificates are part of TLS)".into());
		}
		// ignoring these would leave the control API weaker than asked for
		if !features.client_cert_auth && (auth != ClientAuth::None || self.tls_client_ca.is_some()) {
			v.errors.push(
				"client certificates for the control API (--tls-client-auth, --tls-client-ca) are not available in this version (see GET /capabilities features)".into(),
			);
		}
		if self.token_warn_days.is_some_and(|d| d == 0 || d > 3650) {
			v.errors.push("--token-warn-days must be 1-3650".into());
		}
		if self.lockout_failures.is_some_and(|n| n > 1_000_000) {
			v.errors.push("--api-lockout-failures must be 0-1000000".into());
		}
		for (what, value) in [("--api-lockout-window", &self.lockout_window), ("--api-lockout-duration", &self.lockout_duration)] {
			if let Err(e) = lockout_duration(what, value) {
				v.errors.push(e);
			}
		}
		if !features.token_expiry && self.token_warn_days.is_some() {
			v.ignored.push("--token-warn-days");
		}
		if !features.api_lockout && (self.lockout_failures.is_some() || self.lockout_window.is_some() || self.lockout_duration.is_some()) {
			v.ignored.push("--api-lockout-*");
		}
		v
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn options_are_checked_and_client_certificates_refused_until_available() {
		let none = Features::CURRENT;
		assert_eq!(HardeningOptions::default().check(&none), Verdict::default());
		let mtls = HardeningOptions {
			tls_client_ca: Some("/ca.pem".into()),
			tls_client_auth: Some(ClientAuth::Required),
			has_tls_cert: true,
			..Default::default()
		};
		let v = mtls.check(&none);
		assert!(v.errors.iter().any(|e| e.contains("not available")), "{v:?}");
		assert!(mtls.check(&Features::ALL).errors.is_empty());
		let no_ca = HardeningOptions { tls_client_auth: Some(ClientAuth::Optional), has_tls_cert: true, ..Default::default() };
		assert!(no_ca.check(&Features::ALL).errors[0].contains("needs --tls-client-ca"));
		let lockout = HardeningOptions { lockout_failures: Some(5), lockout_window: Some("30s".into()), ..Default::default() };
		assert_eq!(lockout.check(&none).ignored, ["--api-lockout-*"]);
		assert!(lockout.check(&Features::ALL).ignored.is_empty());
		let bad = HardeningOptions { lockout_duration: Some("2d".into()), token_warn_days: Some(0), ..Default::default() };
		assert_eq!(bad.check(&Features::ALL).errors.len(), 2);
	}
}
