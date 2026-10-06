//! `rproxy-api --check-config`: validates the settings file (`RPROXY_CONFIG`) the
//! way startup and reloads do, without opening sockets, the database or the
//! control API, and without touching a running rproxy (#140).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::config::{ConfigDoc, LoadError};
use crate::l7::access::{access_log_dir, HttpGlobal};
use crate::l7::middleware::crowdsec::{Bouncer, CrowdsecError};
use crate::l7::MiddlewareSpec;
use crate::core::registry::{Config, Registry};

/// What to check, from the same options the service starts with.
pub struct CheckInput {
	/// `RPROXY_CONFIG`: a file or a directory.
	pub path: PathBuf,
	/// The control API's listen addresses; rules may not take them.
	pub reserved: Vec<SocketAddr>,
	pub max_range_ports: u16,
	pub warn_days: u64,
}

/// One problem: where (a file, a rule) and what.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
	/// The rule (`file rule #n`), or empty for the file as a whole / `global`.
	#[serde(skip_serializing_if = "String::is_empty")]
	pub rule: String,
	pub message: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
	pub ok: bool,
	/// The settings file or directory.
	pub path: String,
	/// The files read, in order.
	pub files: Vec<String>,
	/// Rules in the files.
	pub rules: usize,
	pub errors: Vec<Finding>,
	pub warnings: Vec<Finding>,
}

impl Report {
	fn error(&mut self, rule: impl Into<String>, message: impl Into<String>) {
		self.errors.push(Finding { rule: rule.into(), message: message.into() });
	}

	fn warning(&mut self, rule: impl Into<String>, message: impl Into<String>) {
		self.warnings.push(Finding { rule: rule.into(), message: message.into() });
	}

	/// For people: one line per finding, then a summary.
	pub fn to_text(&self) -> String {
		let mut out = String::new();
		for e in &self.errors {
			out.push_str(&line("error", e));
		}
		for w in &self.warnings {
			out.push_str(&line("warning", w));
		}
		out.push_str(&format!(
			"{}: {} file(s), {} rule(s), {} error(s), {} warning(s) — {}\n",
			self.path,
			self.files.len(),
			self.rules,
			self.errors.len(),
			self.warnings.len(),
			if self.ok { "OK" } else { "NG" }
		));
		out
	}
}

fn line(kind: &str, f: &Finding) -> String {
	if f.rule.is_empty() {
		format!("{kind}: {}\n", f.message)
	} else {
		format!("{kind}: {}: {}\n", f.rule, f.message)
	}
}

/// Checks the settings. Needs a tokio runtime (compiling `http` rules may start
/// timers); opens no sockets and does not resolve names.
pub async fn check(input: &CheckInput) -> Report {
	let mut report = Report { path: input.path.display().to_string(), ..Default::default() };
	let doc = match ConfigDoc::load(&input.path) {
		Ok(doc) => doc,
		Err(LoadError::Read(file, e)) => {
			report.error("", format!("{}: {e}", file.display()));
			return report;
		}
		Err(LoadError::Invalid(e)) => {
			report.error("", e);
			return report;
		}
	};
	report.files = doc.files.iter().map(|f| f.display().to_string()).collect();
	report.rules = doc.rules.len();

	// global: what startup builds, without starting anything
	let mut secrets: Vec<String> = vec![];
	if let Some(log) = &doc.global.access_log {
		match access_log_dir(Path::new(log)) {
			Ok(dir) => warn_unreadable(&mut report, dir, "global.access_log", true),
			Err(e) => report.error("", format!("global.access_log: {}", access_error(e))),
		}
	}
	let bouncer = match &doc.global.crowdsec {
		Some(c) => match Bouncer::new(c) {
			Ok(b) => {
				secrets.push(c.api_key_file.clone());
				Some(b)
			}
			Err(CrowdsecError::Config(e)) => {
				report.error("", e);
				None
			}
		},
		None => None,
	};
	let http = HttpGlobal::without_file(&doc.global.trusted_proxies).with_crowdsec(bouncer);
	// global.acme: built as at startup (nothing is started, nothing is written)
	let acme = match &doc.global.acme {
		Some(a) => match crate::acme::Acme::new(a) {
			Ok(acme) => {
				secrets.extend(acme.secret_files());
				if acme.storage().exists() {
					warn_unreadable(&mut report, acme.storage(), "global.acme.storage", true);
				}
				Some(acme)
			}
			Err(e) => {
				report.error("", e);
				None
			}
		},
		None => None,
	};
	let mut reserved = input.reserved.clone();
	reserved.extend(acme.iter().flat_map(|a| a.http01_listen().to_vec()));

	let registry = Registry::new(Config {
		dns_interval: Duration::from_secs(30),
		lookup: crate::core::resolve::system_lookup(),
		transparent: crate::net::source::transparent_available(),
		transparent_ipv6: crate::net::source::transparent_v6_available(),
		max_range_ports: input.max_range_ports.max(1),
		reserved,
		http: Arc::new(http),
	});
	registry.certs().set_warn_days(input.warn_days);
	if let Some(a) = acme {
		registry.set_acme(a);
	}
	let checked = registry.check_rules(doc.labeled_rules());
	for (rule, message) in checked.errors {
		report.error(rule, message);
	}
	for (rule, message) in checked.warnings {
		report.warning(rule, message);
	}

	// files rproxy reads while running: they must be readable by its user too
	for r in &doc.rules {
		for m in r.http.iter().flat_map(|h| h.middlewares.values()) {
			match m {
				MiddlewareSpec::BasicAuth { users_file, .. } => secrets.push(users_file.clone()),
				MiddlewareSpec::Oidc { client_secret_file, cookie_secret_file, ca_file, .. } => {
					secrets.extend([client_secret_file.clone(), cookie_secret_file.clone()]);
					secrets.extend(ca_file.clone());
				}
				_ => {}
			}
		}
	}
	let mut files: Vec<String> = report.files.clone();
	files.extend(checked.files);
	files.extend(secrets);
	files.sort();
	files.dedup();
	for f in &files {
		warn_unreadable(&mut report, Path::new(f), f, false);
	}

	report.ok = report.errors.is_empty();
	report
}

fn access_error(e: crate::l7::access::AccessLogError) -> String {
	match e {
		crate::l7::access::AccessLogError::Config(m) | crate::l7::access::AccessLogError::Unavailable(m) => m,
	}
}

/// The service runs as this user (debian/rproxy-api.service).
const SERVICE_USER: &str = "rproxy";

/// Warns when the `rproxy` user (if it exists and is not the one checking) may
/// not read `path` (or write it, for a directory), judged from its owner and
/// mode only (supplementary groups and ACLs are not looked at).
fn warn_unreadable(report: &mut Report, path: &Path, what: &str, write: bool) {
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		let Some((uid, gid)) = service_user() else { return };
		// SAFETY: plain syscall
		if unsafe { libc::geteuid() } == uid {
			return; // the real reads above already ran as that user
		}
		let Ok(meta) = std::fs::metadata(path) else { return };
		let mode = meta.mode();
		let (r, w) = if meta.uid() == uid {
			(mode & 0o400 != 0, mode & 0o200 != 0)
		} else if meta.gid() == gid {
			(mode & 0o040 != 0, mode & 0o020 != 0)
		} else {
			(mode & 0o004 != 0, mode & 0o002 != 0)
		};
		if !r || (write && !w) {
			let need = if write { "write to" } else { "read" };
			report.warning(
				"",
				format!(
					"{what}: rproxy runs as user {SERVICE_USER}, which may not be able to {need} {} (owner {}:{}, mode {:o})",
					path.display(),
					meta.uid(),
					meta.gid(),
					mode & 0o7777
				),
			);
		}
	}
	#[cfg(not(unix))]
	let _ = (report, path, what, write);
}

#[cfg(unix)]
fn service_user() -> Option<(u32, u32)> {
	let name = std::ffi::CString::new(SERVICE_USER).ok()?;
	// SAFETY: getpwnam returns a pointer into static storage or null; copied at once
	unsafe {
		let pw = libc::getpwnam(name.as_ptr());
		if pw.is_null() {
			return None;
		}
		Some(((*pw).pw_uid, (*pw).pw_gid))
	}
}
