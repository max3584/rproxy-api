use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use axum_server::tls_rustls::RustlsConfig;
/// Handle of a control API listener on TCP (axum-server 0.8 is generic over the address).
type Handle = axum_server::Handle<SocketAddr>;
use tokio::sync::{Notify, OnceCell};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use rproxy_api::control::api::{self, AppState};
use rproxy_api::control::auth::Tokens;
use rproxy_api::control::hardening::{ApiTlsError, ApiTlsFiles, ClientCertAcceptor, TokenExpiry};
use rproxy_api::l7::access::{AccessLogError, HttpGlobal};
use rproxy_api::l7::middleware::crowdsec::{Bouncer, CrowdsecError};
use rproxy_api::config::{ConfigDoc, LoadError};
use rproxy_api::config::reload::ConfigReloader;
use rproxy_api::core::registry::{Config, ConfigStatus, Registry};
use rproxy_api::tls::config::CertRole;
use rproxy_api::{config::db, core::resolve, logging, net::source};

/// mimalloc instead of the libc's malloc (`alloc-mimalloc`, off by default. #185): musl's malloc takes a
/// global lock, and the data plane (hyper, h2, rustls, tokio) allocates small objects from every worker thread.
/// It is faster for L7 but uses more memory, so the default stays the libc's malloc.
#[cfg(feature = "alloc-mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// TCP/UDP forwarder controlled over an HTTP API.
///
/// Every option can also be set with the environment variable shown, and a
/// `.env` file in the working directory is loaded first. Flags win over both.
#[derive(Parser)]
#[command(version)]
struct Options {
	/// Addresses for the control API, comma-separated or repeated
	#[arg(long, env = "RPROXY_API_ADDR", value_delimiter = ',', default_value = "127.0.0.1")]
	api_addr: Vec<IpAddr>,
	/// Port for the control API (0: no TCP listener, only --api-socket)
	#[arg(long, env = "RPROXY_API_PORT", default_value_t = 8080)]
	api_port: u16,
	/// Unix socket for the control API, in addition to TCP (e.g. /run/rproxy/api.sock)
	#[arg(long, env = "RPROXY_API_SOCKET")]
	api_socket: Option<PathBuf>,
	/// Mode of the socket file (octal)
	#[arg(long, env = "RPROXY_API_SOCKET_MODE", default_value = "660")]
	api_socket_mode: String,
	/// Group of the socket file (name or id), e.g. the UI's user group
	#[arg(long, env = "RPROXY_API_SOCKET_GROUP")]
	api_socket_group: Option<String>,
	/// Accept POST /config/reload and the strong ACME operations (POST /acme/...) only over the Unix socket (true / false)
	#[arg(long, env = "RPROXY_API_RELOAD_UNIX_ONLY", default_value_t = true, action = clap::ArgAction::Set)]
	api_reload_unix_only: bool,
	/// File of bearer tokens (one per line, or YAML with scopes); re-read on SIGHUP
	#[arg(long, env = "RPROXY_TOKEN_FILE")]
	token_file: Option<PathBuf>,
	/// TLS certificate chain (PEM) for the control API; re-read on SIGHUP
	#[arg(long, env = "RPROXY_TLS_CERT")]
	tls_cert: Option<PathBuf>,
	/// TLS private key (PEM) for the control API
	#[arg(long, env = "RPROXY_TLS_KEY")]
	tls_key: Option<PathBuf>,
	/// Seconds between checks for changed certificate files (renewed by certbot,
	/// cert-manager, ...), which are then re-read; 0 turns the checks off
	#[arg(long, env = "RPROXY_CERT_CHECK_SECS", default_value_t = 60)]
	cert_check_secs: u64,
	/// Seconds between checks for certificates that have expired (a rule drops
	/// an expired certificate, and stops when all of its certificates have
	/// expired); certificates are also checked whenever they are loaded; 0 turns
	/// the periodic check off
	#[arg(long, env = "RPROXY_CERT_EXPIRY_CHECK_SECS", default_value_t = 86_400)]
	cert_expiry_check_secs: u64,
	/// Days before expiry from which a certificate is reported as expiring
	#[arg(long, env = "RPROXY_CERT_WARN_DAYS", default_value_t = rproxy_api::tls::certstore::DEFAULT_WARN_DAYS)]
	cert_warn_days: u64,
	/// Log file, rotated daily as <stem>.<date>.<ext> (default: stdout)
	#[arg(long, env = "RPROXY_LOG_FILE")]
	log_file: Option<PathBuf>,
	/// Number of rotated log files to keep
	#[arg(long, env = "RPROXY_LOG_KEEP", default_value_t = 14)]
	log_keep: usize,
	/// Log filter, e.g. info or debug
	#[arg(long, env = "RPROXY_LOG_LEVEL", default_value = "info")]
	log_level: String,
	/// Settings file (YAML or JSON) or a directory of them: `version`, `global` and
	/// `rules` started before the database ones; the API cannot change those rules
	#[arg(long, env = "RPROXY_CONFIG")]
	config: Option<PathBuf>,
	/// Seconds between checks of the settings file for changes, which are then
	/// applied without a restart; 0: only on SIGHUP
	#[arg(long, env = "RPROXY_CONFIG_CHECK_SECS", default_value_t = 10)]
	config_check_secs: u64,
	/// The same as --config (the 0.2 name; a plain array of rules also works)
	#[arg(long, env = "RPROXY_STATIC_RULES")]
	static_rules: Option<PathBuf>,
	/// mysql://user:pass@host:port/db to restore rules from at startup
	#[arg(long, env = "RPROXY_DATABASE_URL", hide_env_values = true)]
	database_url: Option<String>,
	/// Seconds between DNS re-resolutions of rule targets
	#[arg(long, env = "RPROXY_DNS_INTERVAL", default_value_t = 30)]
	dns_interval: u64,
	/// Largest port range (listen_port..listen_port_end) one rule may open
	#[arg(long, env = "RPROXY_MAX_RANGE_PORTS", default_value_t = rproxy_api::core::rule::DEFAULT_MAX_RANGE_PORTS)]
	max_range_ports: u16,
	/// Seconds between attempts to open a control API listener that could not start
	#[arg(long, env = "RPROXY_API_RETRY_SECS", default_value_t = 10, hide = true)]
	api_retry_secs: u64,
	/// Check the settings file (PATH, or --config / RPROXY_CONFIG) as startup and
	/// reloads would, then exit: 0 when it is fine, 1 otherwise. Opens no sockets
	/// and does not touch a running rproxy
	#[arg(long, value_name = "PATH", num_args = 0..=1)]
	check_config: Option<Option<PathBuf>>,
	/// Output of --check-config: text or json
	#[arg(long, value_name = "FORMAT", default_value = "text", value_parser = ["text", "json"])]
	check_config_format: String,
	/// With --check-config: also ask the running rproxy what would change (v0.4, #169)
	#[arg(long, requires = "check_config")]
	diff: bool,
	/// Where --diff asks: unix:/path or http(s)://host:port (default: RPROXY_API_SOCKET, else the control API)
	#[arg(long, env = "RPROXY_DIFF_API")]
	diff_api: Option<String>,
	/// File with the token (one plain line) --diff asks with
	#[arg(long, env = "RPROXY_DIFF_TOKEN_FILE")]
	diff_token_file: Option<PathBuf>,
	/// CA (PEM) that verifies client certificates of the control API; re-read on SIGHUP (v0.4, #167)
	#[arg(long, env = "RPROXY_TLS_CLIENT_CA")]
	tls_client_ca: Option<PathBuf>,
	/// Client certificates for the control API: none (default), optional or required (v0.4, #167)
	#[arg(long, env = "RPROXY_TLS_CLIENT_AUTH", value_enum)]
	tls_client_auth: Option<rproxy_api::control::hardening::ClientAuth>,
	/// Report tokens whose expires is closer than this many days [default: 14] (v0.4, #167)
	#[arg(long, env = "RPROXY_TOKEN_WARN_DAYS")]
	token_warn_days: Option<u64>,
	/// Lock out a source after this many failed authentications within the window; 0: never [default: 20] (v0.4, #167)
	#[arg(long, env = "RPROXY_API_LOCKOUT_FAILURES")]
	api_lockout_failures: Option<u32>,
	/// Window of --api-lockout-failures [default: 1m]
	#[arg(long, env = "RPROXY_API_LOCKOUT_WINDOW")]
	api_lockout_window: Option<String>,
	/// How long a source stays locked out [default: 5m]
	#[arg(long, env = "RPROXY_API_LOCKOUT_DURATION")]
	api_lockout_duration: Option<String>,
	/// This rproxy's name in rproxy_rules (default: the host name) (v0.4, #144)
	#[arg(long, env = "RPROXY_NODE_NAME")]
	node_name: Option<String>,
	/// Unix socket for live upgrades [default: /run/rproxy/handoff.sock] (v0.4, #174)
	#[arg(long, env = "RPROXY_HANDOFF_SOCKET")]
	handoff_socket: Option<PathBuf>,
	/// How long a live upgrade waits for the new process [default: 30s]
	#[arg(long, env = "RPROXY_HANDOFF_TIMEOUT")]
	handoff_timeout: Option<String>,
	/// Longest the old process waits for its connections after a live upgrade [default: 5m]
	#[arg(long, env = "RPROXY_HANDOFF_DRAIN")]
	handoff_drain: Option<String>,
	/// Self-update: off (default), check or auto (v0.4, #174)
	#[arg(long, env = "RPROXY_UPDATE", value_enum)]
	update: Option<rproxy_api::control::upgrade::UpdateMode>,
	/// Pin the self-update to this version (X.Y.Z within this build's X.Y)
	#[arg(long, env = "RPROXY_UPDATE_PIN")]
	update_pin: Option<String>,
	/// Where releases are fetched from (https://) [default: https://github.com/max3584/rproxy-api/releases]
	#[arg(long, env = "RPROXY_UPDATE_SOURCE")]
	update_source: Option<String>,
	/// Cache of fetched releases [default: /var/cache/rproxy/update]
	#[arg(long, env = "RPROXY_UPDATE_CACHE")]
	update_cache: Option<PathBuf>,
	/// How often to look for a new patch; 0s: at start and through the API only [default: 6h]
	#[arg(long, env = "RPROXY_UPDATE_INTERVAL")]
	update_interval: Option<String>,
	/// minisign public key that verifies releases (default: the release key built in)
	#[arg(long, env = "RPROXY_UPDATE_PUBKEY")]
	update_pubkey: Option<PathBuf>,
	/// A new version that runs this long is kept [default: 60s]
	#[arg(long, env = "RPROXY_UPDATE_HEALTHY")]
	update_healthy: Option<String>,
	/// tokio worker threads (default: the number of CPUs); global.performance.workers wins (v0.4, #194)
	#[arg(long, env = "RPROXY_WORKERS")]
	workers: Option<u32>,
	/// Pin the workers to CPUs: none, auto or a list such as 0-3,6; global.performance.cpu_affinity wins
	#[arg(long, env = "RPROXY_CPU_AFFINITY")]
	cpu_affinity: Option<String>,
	/// SO_BUSY_POLL of data-plane sockets in microseconds, 0 = off; global.performance.busy_poll_usecs wins
	#[arg(long, env = "RPROXY_BUSY_POLL_USECS")]
	busy_poll_usecs: Option<u32>,
	#[command(subcommand)]
	command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
	/// The container image's entry point (v0.4, #174): runs the newest verified
	/// patch of this major.minor (RPROXY_UPDATE=auto) or this binary, and stays
	/// as the container's init (signals, live upgrades, rollback). The other
	/// options and RPROXY_* go to the server
	Launch {
		/// Ignored; the server gets the same arguments without `launch`
		#[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
		rest: Vec<std::ffi::OsString>,
	},
	/// The ACME helper (global.acme.helper): holds the DNS providers' secrets and
	/// writes DNS-01 records for rproxy-api over a Unix socket. Run it as
	/// another user (docs/ACME.md, docs/PERMISSIONS.md)
	AcmeHelper {
		/// The settings file (or directory) with global.acme
		#[arg(long, env = "RPROXY_ACME_HELPER_CONFIG")]
		config: PathBuf,
		/// The socket to listen on (global.acme.helper.socket)
		#[arg(long, env = "RPROXY_ACME_HELPER_SOCKET")]
		socket: PathBuf,
		/// Mode of the socket file (octal)
		#[arg(long, env = "RPROXY_ACME_HELPER_SOCKET_MODE", default_value = "660")]
		socket_mode: String,
		/// Group of the socket file (name or id): rproxy-api's group
		#[arg(long, env = "RPROXY_ACME_HELPER_SOCKET_GROUP")]
		socket_group: Option<String>,
		/// Users (name or uid) allowed to use the helper, checked with SO_PEERCRED;
		/// comma-separated or repeated (default: whoever the socket's mode lets in)
		#[arg(long, env = "RPROXY_ACME_HELPER_ALLOW_USER", value_delimiter = ',')]
		allow_user: Vec<String>,
	},
}

/// A user name or uid.
fn user_id(name: &str) -> Result<u32, String> {
	if let Ok(uid) = name.parse() {
		return Ok(uid);
	}
	let c = std::ffi::CString::new(name).map_err(|_| format!("invalid user name: {name:?}"))?;
	// SAFETY: getpwnam returns a pointer to static storage or null; the uid is copied at once
	unsafe {
		let pw = libc::getpwnam(c.as_ptr());
		if pw.is_null() {
			return Err(format!("no such user: {name}"));
		}
		Ok((*pw).pw_uid)
	}
}

/// `rproxy-api acme-helper` (logs to stdout, JSON Lines).
fn acme_helper(opts: &Options) -> ExitCode {
	let Some(Command::AcmeHelper { config, socket, socket_mode, socket_group, allow_user }) = &opts.command else {
		return ExitCode::FAILURE;
	};
	let _guard = match logging::init(&opts.log_level, None, opts.log_keep) {
		Ok((guard, _)) => guard,
		Err(e) => {
			eprintln!("rproxy-api: {e}");
			return ExitCode::FAILURE;
		}
	};
	let setup = || -> Result<rproxy_api::acme::helper::HelperOptions, String> {
		Ok(rproxy_api::acme::helper::HelperOptions {
			config: config.clone(),
			socket: rproxy_api::control::unix_api::SocketOptions {
				path: socket.clone(),
				mode: rproxy_api::control::unix_api::parse_mode(socket_mode)?,
				group: socket_group.clone(),
			},
			allow_uids: allow_user.iter().map(|u| user_id(u)).collect::<Result<_, _>>()?,
		})
	};
	let result = setup().and_then(|helper| {
		let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
		runtime.block_on(rproxy_api::acme::helper::run(helper))
	});
	match result {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			error!(event = "fatal", part = "acme-helper", error = %e);
			ExitCode::FAILURE
		}
	}
}

/// Port ranges open one socket per port; lift the soft file limit to the hard one.
#[cfg(unix)]
fn raise_nofile_limit() -> Option<u64> {
	let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
	// SAFETY: plain syscalls on a local struct
	unsafe {
		if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
			return None;
		}
		if lim.rlim_cur < lim.rlim_max {
			lim.rlim_cur = lim.rlim_max;
			libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
			libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim);
		}
	}
	#[allow(clippy::unnecessary_cast)] // rlim_t is not u64 everywhere
	Some(lim.rlim_cur as u64)
}

#[cfg(not(unix))]
fn raise_nofile_limit() -> Option<u64> {
	None
}

/// The v0.4 options (docs/DESIGN-v0.4.md): mistakes and settings that would
/// weaken the control API if ignored are errors; options this build cannot
/// apply yet are returned to be logged as `degraded`.
fn check_v04_options(opts: &Options) -> Result<Vec<&'static str>, String> {
	let features = rproxy_api::core::rule::Features::CURRENT;
	let hardening = hardening_options(opts).check(&features);
	let upgrade = upgrade_options(opts).check(&features);
	let mut errors: Vec<String> = hardening.errors.into_iter().chain(upgrade.errors).collect();
	let perf = rproxy_api::config::performance::PerformanceSpec {
		workers: opts.workers,
		udp_shards: None,
		cpu_affinity: opts.cpu_affinity.clone(),
		busy_poll_usecs: opts.busy_poll_usecs,
		splice: None,
	};
	if let Err(e) = perf.check() {
		errors.push(e.replace("global.performance.", "--").replace('_', "-"));
	}
	if opts.node_name.as_deref().is_some_and(|n| n.trim().is_empty() || n.len() > 255) {
		errors.push("--node-name must be 1-255 characters".into());
	}
	if !errors.is_empty() {
		return Err(errors.join("; "));
	}
	let mut ignored: Vec<&'static str> = hardening.ignored.into_iter().chain(upgrade.ignored).collect();
	if opts.node_name.is_some() && !features.persistence {
		ignored.push("--node-name");
	}
	for (flag, key, set) in [
		("--workers", "workers", opts.workers.is_some()),
		("--cpu-affinity", "cpu_affinity", opts.cpu_affinity.is_some()),
		("--busy-poll-usecs", "busy_poll_usecs", opts.busy_poll_usecs.is_some()),
	] {
		if set && !features.performance.contains(&key) {
			ignored.push(flag);
		}
	}
	Ok(ignored)
}

/// The live upgrade and self-update options (#174).
fn upgrade_options(opts: &Options) -> rproxy_api::control::upgrade::UpgradeOptions {
	rproxy_api::control::upgrade::UpgradeOptions {
		handoff_socket: opts.handoff_socket.clone(),
		handoff_timeout: opts.handoff_timeout.clone(),
		handoff_drain: opts.handoff_drain.clone(),
		update: opts.update,
		update_pin: opts.update_pin.clone(),
		update_source: opts.update_source.clone(),
		update_cache: opts.update_cache.clone(),
		update_interval: opts.update_interval.clone(),
		update_pubkey: opts.update_pubkey.clone(),
		update_healthy: opts.update_healthy.clone(),
	}
}

/// `rproxy-api launch` (#174): the container's entry point.
fn launch(opts: &Options) -> ExitCode {
	let _guard = match logging::init(&opts.log_level, None, opts.log_keep) {
		Ok((guard, _)) => guard,
		Err(e) => {
			eprintln!("rproxy-api: {e}");
			return ExitCode::FAILURE;
		}
	};
	let upgrade = upgrade_options(opts);
	let verdict = upgrade.check(&rproxy_api::core::rule::Features::CURRENT);
	if !verdict.errors.is_empty() {
		error!(event = "fatal", part = "launch", error = %verdict.errors.join("; "));
		return ExitCode::FAILURE;
	}
	// the server gets the same arguments, without `launch`
	let mut args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
	if let Some(i) = args.iter().position(|a| a == "launch") {
		args.remove(i);
	}
	rproxy_api::control::upgrade::launch::run(upgrade.update_config(), args)
}

/// The control API hardening options (#167).
fn hardening_options(opts: &Options) -> rproxy_api::control::hardening::HardeningOptions {
	rproxy_api::control::hardening::HardeningOptions {
		tls_client_ca: opts.tls_client_ca.clone(),
		tls_client_auth: opts.tls_client_auth,
		has_tls_cert: opts.tls_cert.is_some(),
		token_warn_days: opts.token_warn_days,
		lockout_failures: opts.api_lockout_failures,
		lockout_window: opts.api_lockout_window.clone(),
		lockout_duration: opts.api_lockout_duration.clone(),
	}
}

/// The control API's TLS files (certificate, key, client CA), when it serves TLS.
fn api_tls_files(opts: &Options) -> Option<ApiTlsFiles> {
	let (cert, key) = opts.tls_cert.clone().zip(opts.tls_key.clone())?;
	Some(ApiTlsFiles { cert, key, client_ca: opts.tls_client_ca.clone(), client_auth: opts.tls_client_auth.unwrap_or_default() })
}

/// `--check-config --diff` (#169): what the running rproxy would change with
/// these settings (`POST /config/plan`). Only asked when the check passed
/// (`checked`); None then.
async fn diff(opts: &Options, path: &std::path::Path, checked: bool) -> Result<Option<serde_json::Value>, String> {
	use rproxy_api::config::plan::{self, Api};
	let api: Api = match &opts.diff_api {
		Some(api) => api.parse()?,
		None => match &opts.api_socket {
			Some(socket) => Api::Unix(socket.clone()),
			None if opts.api_port != 0 => {
				let ip = match opts.api_addr.first().copied() {
					Some(ip) if !ip.is_unspecified() => ip,
					Some(IpAddr::V6(_)) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
					_ => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
				};
				let scheme = if opts.tls_cert.is_some() { "https" } else { "http" };
				Api::Url(format!("{scheme}://{}", SocketAddr::new(ip, opts.api_port)))
			}
			None => return Err("--diff: no control API to ask (give --diff-api)".into()),
		},
	};
	let token = match &opts.diff_token_file {
		Some(file) => Some(
			std::fs::read_to_string(file)
				.map_err(|e| format!("--diff-token-file {}: {e}", file.display()))?
				.trim()
				.to_string(),
		),
		None => None,
	};
	if !checked {
		return Ok(None);
	}
	let doc = plan::document_json(path)?;
	let ca = opts.tls_cert.as_ref().map(|p| p.display().to_string());
	plan::ask(&api, token.as_deref(), &doc, ca.as_deref())
		.await
		.map(Some)
		.map_err(|e| format!("--diff: could not get the difference from the running rproxy: {e}"))
}

fn check_exposure(opts: &Options, addrs: &[IpAddr]) -> Result<(), String> {
	let exposed: Vec<String> = addrs.iter().filter(|a| !a.is_loopback()).map(|a| a.to_string()).collect();
	if exposed.is_empty() {
		return Ok(());
	}
	let mut missing = vec![];
	if opts.token_file.is_none() {
		missing.push("--token-file");
	}
	if opts.tls_cert.is_none() || opts.tls_key.is_none() {
		missing.push("--tls-cert/--tls-key");
	}
	if missing.is_empty() {
		Ok(())
	} else {
		Err(format!("listening on {} requires {}", exposed.join(", "), missing.join(" and ")))
	}
}

fn main() -> ExitCode {
	// a missing .env is fine; a malformed one is reported
	if let Err(e) = dotenvy::dotenv() {
		if !e.not_found() {
			eprintln!("rproxy-api: .env: {e}");
			return ExitCode::FAILURE;
		}
	}
	// `RPROXY_DATABASE_URL=` and the like mean "not set", not an empty value.
	// Done before the runtime starts so no other thread reads the environment.
	for (key, value) in std::env::vars_os() {
		if value.is_empty() && key.to_string_lossy().starts_with("RPROXY_") {
			std::env::remove_var(key);
		}
	}
	// a live upgrade (#174): the old process's handoff socket, for this process only
	let handoff_from = std::env::var_os(rproxy_api::control::upgrade::handoff::ENV_FROM).map(PathBuf::from);
	std::env::remove_var(rproxy_api::control::upgrade::handoff::ENV_FROM);
	let opts = Options::parse();
	if let Some(Command::Launch { .. }) = &opts.command {
		return launch(&opts);
	}
	if opts.command.is_some() {
		return acme_helper(&opts);
	}
	if let Some(path) = &opts.check_config {
		return check_config(&opts, path.clone());
	}

	let _log_guard = match logging::init(&opts.log_level, opts.log_file.as_deref(), opts.log_keep) {
		Ok((guard, fallback)) => {
			if let Some(why) = fallback {
				warn!(event = "degraded", part = "log", error = %why);
			}
			guard
		}
		Err(e) => {
			eprintln!("rproxy-api: {e}");
			return ExitCode::FAILURE;
		}
	};
	// global.performance (#194): the workers are fixed when the runtime is built,
	// so the settings file is read for it first (its mistakes are reported by `run`)
	let perf = performance_settings(&opts);
	let runtime = match rproxy_api::config::performance::runtime(&perf) {
		Ok(rt) => rt,
		Err(e) => {
			error!(event = "fatal", error = %e);
			return ExitCode::FAILURE;
		}
	};
	match runtime.block_on(run(opts, perf, handoff_from)) {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			error!(event = "fatal", error = %e);
			ExitCode::FAILURE
		}
	}
}

/// `global.performance` of the settings file over the flags and environment
/// variables (docs/DESIGN-v0.4.md 12.).
fn performance_settings(opts: &Options) -> rproxy_api::config::performance::Effective {
	use rproxy_api::config::performance::{allowed_cpus, parallelism, resolve, EnvKnobs};
	let spec = opts
		.config
		.as_ref()
		.or(opts.static_rules.as_ref())
		.and_then(|path| ConfigDoc::load(path).ok())
		.and_then(|doc| doc.global.performance);
	let env = EnvKnobs::from_env(opts.workers, opts.cpu_affinity.clone(), opts.busy_poll_usecs);
	resolve(spec.as_ref(), &env, &allowed_cpus(), parallelism())
}

/// `--check-config`: validates the settings file and prints the result. No log
/// is set up (the report is the output), nothing listens.
fn check_config(opts: &Options, path: Option<PathBuf>) -> ExitCode {
	let json = opts.check_config_format == "json";
	let fail = |message: String| {
		if json {
			let report = rproxy_api::config::check::Report {
				errors: vec![rproxy_api::config::check::Finding { rule: String::new(), message }],
				..Default::default()
			};
			println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
		} else {
			eprintln!("rproxy-api: {message}");
		}
		ExitCode::FAILURE
	};
	if opts.config.is_some() && opts.static_rules.is_some() {
		return fail("give --config (RPROXY_CONFIG) or --static-rules (RPROXY_STATIC_RULES), not both".into());
	}
	let Some(path) = path.or_else(|| opts.config.clone()).or_else(|| opts.static_rules.clone()) else {
		// no settings file configured: nothing can be wrong (so `systemctl reload`
		// with the check in ExecReload works on hosts without one)
		let message = "no settings file (RPROXY_CONFIG) is configured; nothing to check";
		if json {
			let report = rproxy_api::config::check::Report { ok: true, ..Default::default() };
			println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
		} else {
			println!("{message}");
		}
		return ExitCode::SUCCESS;
	};
	let api_addrs = if opts.api_port == 0 { vec![] } else { opts.api_addr.clone() };
	let input = rproxy_api::config::check::CheckInput {
		path,
		reserved: api_addrs.iter().map(|ip| SocketAddr::new(*ip, opts.api_port)).collect(),
		max_range_ports: opts.max_range_ports,
		warn_days: opts.cert_warn_days,
	};
	let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
		Ok(rt) => rt,
		Err(e) => return fail(e.to_string()),
	};
	let mut report = runtime.block_on(rproxy_api::config::check::check(&input));
	if opts.diff {
		// v0.4 (#169): asks the running rproxy with POST /config/plan
		match runtime.block_on(diff(opts, &input.path, report.ok)) {
			Ok(plan) => report.plan = plan,
			Err(message) => {
				report.errors.push(rproxy_api::config::check::Finding { rule: String::new(), message });
				report.ok = false;
			}
		}
	}
	if json {
		println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
	} else {
		print!("{}", report.to_text());
		if let Some(plan) = &report.plan {
			print!("{}", rproxy_api::config::plan::plan_text(plan));
		}
	}
	if report.ok {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

async fn run(opts: Options, perf: rproxy_api::config::performance::Effective, handoff_from: Option<PathBuf>) -> Result<(), String> {
	use rproxy_api::control::upgrade::{self as upgrade, handoff};
	let addrs = if opts.api_port == 0 { vec![] } else { opts.api_addr.clone() };
	if addrs.is_empty() && opts.api_socket.is_none() {
		return Err("--api-port 0 turns TCP off; give --api-socket (RPROXY_API_SOCKET) for the control API".into());
	}
	check_exposure(&opts, &addrs)?;
	for flag in check_v04_options(&opts)? {
		warn!(event = "degraded", part = flag, "not available in this version yet; ignored (see GET /capabilities features)");
	}
	rproxy_api::config::performance::apply(&perf);
	log_performance(&perf);
	let upgrade_opts = upgrade_options(&opts);
	upgrade::hash_binary();
	// a live upgrade (#174): take the old process's sockets and state before
	// anything listens
	let received = match &handoff_from {
		Some(path) => {
			raise_nofile_limit();
			let timeout = upgrade_opts.handoff_config().timeout;
			let mut r = tokio::task::block_in_place(|| handoff::receive(path, timeout))?;
			let fds = r.take_fds();
			let received = fds.len();
			let kept = upgrade::inherit::adopt(fds);
			if let Ok(t) = r.state.process_start_time.parse() {
				upgrade::set_process_start_time(t);
			}
			info!(event = "handoff.received", from_version = %r.state.version, sockets = kept, received, rules = r.state.rules.len());
			Some(r)
		}
		None => None,
	};
	#[cfg(unix)]
	let socket = match &opts.api_socket {
		Some(path) => Some(rproxy_api::control::unix_api::SocketOptions {
			path: path.clone(),
			mode: rproxy_api::control::unix_api::parse_mode(&opts.api_socket_mode)?,
			group: opts.api_socket_group.clone(),
		}),
		None => None,
	};
	#[cfg(not(unix))]
	if opts.api_socket.is_some() {
		return Err("--api-socket needs a Unix system".into());
	}
	if opts.tls_cert.is_some() != opts.tls_key.is_some() {
		return Err("--tls-cert and --tls-key must be given together".into());
	}

	let hardening = hardening_options(&opts);
	let tokens = match &opts.token_file {
		None => Tokens::disabled(),
		Some(path) => match Tokens::from_file(path.clone()) {
			Ok(tokens) => tokens,
			// a wrong path or a file without tokens is a configuration error
			Err(e) if config_error(&e) => return Err(format!("token file {}: {e}", path.display())),
			// unreadable (permissions): keep the API closed until SIGHUP reads it
			Err(e) => {
				warn!(event = "degraded", part = "tokens", error = %format!("{}: {e}", path.display()),
					"control API refuses every request until the token file can be read (SIGHUP)");
				Tokens::locked(path.clone())
			}
		},
	};
	// client_cert entries while the API asks for no certificates are a mistake
	let tokens = Arc::new(tokens.with_client_auth(hardening.client_auth()).map_err(|e| e.to_string())?.with_lockout(hardening.lockout()));
	let token_expiry = Arc::new(TokenExpiry::new(hardening.token_warn_days()));
	token_expiry.check(&tokens.expiries());

	if !rproxy_api::core::rule::Features::CURRENT.persistence {
		for name in tokens.persisting() {
			warn!(event = "degraded", part = "tokens", token = %name,
				"persist is not available in this version yet; the token's rules are not stored (see GET /capabilities features)");
		}
	}

	// the control API certificate; loaded later by the listener task when it cannot be read yet
	let tls: Arc<OnceCell<RustlsConfig>> = Arc::default();
	let tls_files = api_tls_files(&opts);
	if let Some(files) = &tls_files {
		let _ = rustls::crypto::ring::default_provider().install_default();
		match files.rustls() {
			Ok(config) => {
				let _ = tls.set(config);
			}
			Err(ApiTlsError::Config(e)) => return Err(e),
			Err(ApiTlsError::Unreadable(e)) => {
				warn!(event = "degraded", part = "api_tls", error = %e, "control API waits for its certificate");
			}
		}
	}

	// the settings file: its `global` shapes the registry, its rules start below
	if opts.config.is_some() && opts.static_rules.is_some() {
		return Err("give --config (RPROXY_CONFIG) or --static-rules (RPROXY_STATIC_RULES), not both".into());
	}
	let config_path = opts.config.as_ref().or(opts.static_rules.as_ref()).cloned();
	let mut doc = None;
	let mut config_unread = None;
	if let Some(path) = &config_path {
		match ConfigDoc::load(path) {
			Ok(parsed) => {
				doc = Some((path.clone(), parsed));
			}
			Err(LoadError::Invalid(e)) => return Err(e),
			Err(LoadError::Read(file, e)) if config_error(&e) => return Err(format!("settings file {}: {e}", file.display())),
			Err(e) => {
				error!(event = "degraded", part = "static_rules", error = %e,
					"running without the rules of the settings file until it can be read");
				config_unread = Some(e.to_string());
			}
		}
	}
	if let Some((_, d)) = &doc {
		for part in d.global.unsupported(&rproxy_api::core::rule::Features::CURRENT) {
			warn!(event = "degraded", part = %part, "not available in this version yet; ignored (see GET /capabilities features)");
		}
	}
	let http_global = match &doc {
		None => HttpGlobal::default(),
		Some((path, d)) => {
			let access_log = d.global.access_log.as_deref().map(Path::new);
			match HttpGlobal::new(&d.global.trusted_proxies, access_log, opts.log_keep) {
				Ok(g) => g,
				Err(AccessLogError::Config(e)) => return Err(format!("{}: global.access_log: {e}", path.display())),
				Err(AccessLogError::Unavailable(e)) => {
					warn!(event = "degraded", part = "global.access_log", error = %e, "access log lines go to the main log");
					HttpGlobal::without_file(&d.global.trusted_proxies)
				}
			}
		}
	};
	// global.crowdsec: one bouncer for the process, pulling the LAPI's decisions
	let crowdsec = match doc.as_ref().and_then(|(path, d)| d.global.crowdsec.as_ref().map(|c| (path, c))) {
		Some((path, c)) => match Bouncer::new(c) {
			Ok(b) => Some(b),
			Err(CrowdsecError::Config(e)) => return Err(format!("{}: {e}", path.display())),
		},
		None => None,
	};
	if let Some(b) = &crowdsec {
		b.spawn();
	}
	// global.geoip: the databases of the geoip lists, looked at again every check_interval (#168)
	let geoip = match doc.as_ref().and_then(|(path, d)| d.global.geoip.as_ref().map(|g| (path, g))) {
		Some((path, g)) if rproxy_api::core::rule::Features::CURRENT.geoip => match rproxy_api::net::geoip::Geoip::open(g) {
			Ok(geoip) => Some(geoip),
			Err(rproxy_api::net::geoip::GeoipError::Config(e)) => return Err(format!("{}: {e}", path.display())),
		},
		_ => None,
	};
	if let Some(g) = &geoip {
		g.spawn();
	}
	let http_global = http_global.with_crowdsec(crowdsec.clone()).with_geoip(geoip.clone());
	// global.acme: certificates of `tls.certificates[].acme`, obtained and renewed in the background
	let acme = match doc.as_ref().and_then(|(path, d)| d.global.acme.as_ref().map(|a| (path, a))) {
		Some((path, a)) => Some(rproxy_api::acme::Acme::new(a).map_err(|e| format!("{}: {e}", path.display()))?),
		None => None,
	};
	if let Some(e) = acme.as_ref().and_then(|a| a.storage_problem()) {
		warn!(event = "degraded", part = "global.acme.storage", error = %e,
			"certificates cannot be stored; rules with acme certificates serve a self-signed one until this is fixed");
	}
	let mut reserved: Vec<SocketAddr> = addrs.iter().map(|ip| SocketAddr::new(*ip, opts.api_port)).collect();
	reserved.extend(acme.iter().flat_map(|a| a.http01_listen().to_vec()));

	let transparent = source::transparent_available();
	let transparent_ipv6 = source::transparent_v6_available();
	let registry = Registry::new(Config {
		dns_interval: Duration::from_secs(opts.dns_interval.max(1)),
		lookup: resolve::system_lookup(),
		transparent,
		transparent_ipv6,
		max_range_ports: opts.max_range_ports.max(1),
		reserved,
		http: Arc::new(http_global),
	});
	registry.certs().set_warn_days(opts.cert_warn_days);
	if let Some(a) = &acme {
		registry.set_acme(a.clone());
	}
	if let Some(cert) = &opts.tls_cert {
		note_api_cert(&registry, cert);
	}
	let nofile = raise_nofile_limit();
	info!(event = "start", version = env!("CARGO_PKG_VERSION"), transparent, transparent_ipv6, auth = tokens.enabled(),
		tls = opts.tls_cert.is_some(), max_range_ports = opts.max_range_ports, nofile_limit = nofile.unwrap_or(0));

	if let Some((path, d)) = &doc {
		let rules = registry.load_static_labeled(d.labeled_rules()).await.map_err(|e| format!("{}: {e}", path.display()))?;
		registry.set_config_status(ConfigStatus {
			path: path.display().to_string(),
			files: d.files.iter().map(|f| f.display().to_string()).collect(),
			loaded_at: Some(unix_now()),
			rules,
			..Default::default()
		});
	}
	if let (Some(path), Some(error)) = (&config_path, config_unread) {
		registry.set_config_status(ConfigStatus { path: path.display().to_string(), error: Some(error), ..Default::default() });
	}
	if let Some(a) = &acme {
		for (addr, e) in a.spawn().await {
			warn!(event = "degraded", part = "global.acme.http01_listen", addr = %addr, error = %e,
				"HTTP-01 is answered only by http rules on this address");
		}
	}

	// #144: rules of persist: true tokens, in rproxy_rules
	if rproxy_api::core::rule::Features::CURRENT.persistence {
		let node = opts.node_name.clone().unwrap_or_else(rproxy_api::config::persist::host_name);
		match rproxy_api::config::persist::Store::new(node, opts.database_url.as_deref()) {
			Ok(store) => registry.set_persist(Arc::new(store)),
			Err(e) => error!(event = "degraded", part = "db", error = %e, "rules made through the API are not stored"),
		}
	}
	if let Some(r) = &received {
		// the old process's rules, as they were (not the database's, read at its start)
		r.restore_rules(&registry).await;
	} else if let Some(url) = &opts.database_url {
		let ui = match db::load_rules(url).await {
			Ok(rules) => rules,
			// keep serving the API so the UI can still add rules
			Err(e) => {
				error!(event = "restore.error", error = %e);
				vec![]
			}
		};
		let stored = match registry.persist() {
			Some(store) => match store.load().await {
				Ok(rows) => rproxy_api::config::persist::without_conflicts(&ui, rows),
				Err(e) => {
					error!(event = "degraded", part = "db", table = rproxy_api::config::persist::TABLE, error = %e,
						"rules stored by the API are not restored");
					vec![]
				}
			},
			None => vec![],
		};
		info!(event = "restore.start", rules = ui.len(), api_rules = stored.len(),
			node = registry.persist().map(|s| s.node()).unwrap_or(""));
		registry.restore(ui).await;
		if let Some(store) = registry.persist().filter(|_| !stored.is_empty()) {
			store.restored(&stored);
			registry.restore_as(stored.into_iter().map(|r| r.spec).collect(), rproxy_api::core::rule::Origin::Api).await;
		}
	}

	// GET /readyz (#28): the restore is done
	registry.readiness().set_ready();

	// the settings file: applied again when it changes, on SIGHUP or by POST /config/reload
	let reloader = config_path.clone().map(|path| {
		Arc::new(ConfigReloader::new(
			doc.map(|(_, d)| d).unwrap_or_default(),
			registry.clone(),
			rproxy_api::config::check::CheckInput {
				path,
				reserved: addrs.iter().map(|ip| SocketAddr::new(*ip, opts.api_port)).collect(),
				max_range_ports: opts.max_range_ports,
				warn_days: opts.cert_warn_days,
			},
		))
	});
	let upgrader = handoff::Upgrader::new(upgrade_opts.handoff_config(), registry.clone());
	let updater = upgrade::update::Updater::new(upgrade_opts.update_config());
	upgrade::install(upgrade::Upgrade { upgrader: upgrader.clone(), updater: updater.clone() });
	let app = api::router(Arc::new(AppState {
		registry: registry.clone(),
		tokens: tokens.clone(),
		reloader: reloader.clone(),
		reload_unix_only: opts.api_reload_unix_only,
	}))
	.layer(axum::middleware::from_fn(upgrade::guard));
	let handles: Arc<Mutex<Vec<Handle>>> = Arc::default();
	let stop = CancellationToken::new();
	let retry = Duration::from_secs(opts.api_retry_secs.max(1));
	for ip in addrs {
		let addr = SocketAddr::new(ip, opts.api_port);
		let listener = ApiListener {
			addr,
			app: app.clone(),
			tls: tls.clone(),
			files: tls_files.clone(),
			handles: handles.clone(),
		};
		// the rules keep running while a listener that cannot start is retried
		if let Err(e) = listener.start().await {
			error!(event = "degraded", part = "api", addr = %addr, error = %e, retry_secs = retry.as_secs(),
				"control API is not listening here yet; retrying");
			tokio::spawn(listener.retry(retry, stop.clone()));
		}
	}

	#[cfg(unix)]
	let unix_server = match &socket {
		Some(socket) => match rproxy_api::control::unix_api::bind(socket).await {
			Ok(listener) => {
				info!(event = "api.listening", socket = %socket.path.display());
				let unix_app = app.clone().layer(axum::Extension(api::Transport::UnixSocket));
				let serve = axum::serve(listener, unix_app).with_graceful_shutdown(stop.clone().cancelled_owned());
				Some(tokio::spawn(async move { serve.await }))
			}
			Err(rproxy_api::control::unix_api::SocketError::Config(e)) => return Err(e),
			Err(rproxy_api::control::unix_api::SocketError::Unavailable(e)) => {
				error!(event = "degraded", part = "api_socket", error = %e, "control API is not on the Unix socket");
				None
			}
		},
		None => None,
	};

	if opts.cert_check_secs > 0 || opts.cert_expiry_check_secs > 0 {
		let every = |secs: u64| (secs > 0).then(|| Duration::from_secs(secs));
		tokio::spawn(watch_certificates(
			every(opts.cert_check_secs),
			every(opts.cert_expiry_check_secs),
			registry.clone(),
			tls.clone(),
			tls_files.clone(),
			stop.clone(),
		));
	}
	tokio::spawn(watch_tokens(tokens.clone(), token_expiry.clone(), stop.clone()));

	let config_hup = Arc::new(Notify::new());
	if let Some(reloader) = reloader {
		let every = (opts.config_check_secs > 0).then(|| Duration::from_secs(opts.config_check_secs));
		tokio::spawn(watch_config(every, reloader, config_hup.clone(), stop.clone()));
	}

	// the startup is done: a new process of a live upgrade takes over now
	if let Some(r) = received {
		let left = upgrade::inherit::close_rest();
		if !left.is_empty() {
			info!(event = "handoff.sockets", unused = left.len(), "closed inherited sockets no rule or listener took");
		}
		let adopted = r.ready(&registry).await?;
		tokio::spawn(adopted.follow(registry.clone()));
	}
	updater.spawn(Some(upgrader.clone()));
	upgrade::notify::notify("READY=1");

	let handed = wait_for_shutdown(&tokens, &token_expiry, &tls, tls_files.as_ref(), &registry, &config_hup, &upgrader).await?;

	// GET /readyz: draining (#28), here and after a handoff
	registry.readiness().set_draining();
	match &handed {
		Some(h) => {
			handoff::set_draining();
			info!(event = "handoff.drain", pid = h.pid, drain_secs = upgrader.config().drain.as_secs());
		}
		None => info!(event = "shutdown"),
	}
	stop.cancel();
	for handle in handles.lock().unwrap().iter() {
		handle.graceful_shutdown(Some(Duration::from_secs(5)));
	}
	if let Some(b) = &crowdsec {
		b.stop();
	}
	if let Some(g) = &geoip {
		g.stop();
	}
	if let Some(a) = &acme {
		a.shutdown();
	}
	// after a handoff the rules stop accepting at once and drain meanwhile
	let runtimes = if handed.is_some() { registry.runtimes().await } else { vec![] };
	let drain = upgrader.config().drain;
	let draining = async {
		if handed.is_none() {
			return;
		}
		// SIGTERM (systemctl stop) cuts the drain short
		let until = async move {
			#[cfg(unix)]
			if let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
				tokio::select! {
					_ = tokio::time::sleep(drain) => {}
					_ = term.recv() => {}
					_ = tokio::signal::ctrl_c() => {}
				}
				return;
			}
			tokio::time::sleep(drain).await;
		};
		registry.drain_all(until).await;
	};
	let api_down = async {
		#[cfg(unix)]
		if let (Some(server), Some(socket)) = (unix_server, &socket) {
			let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
			// after a handoff the socket file is the new process's
			if handed.is_none() {
				let _ = std::fs::remove_file(&socket.path);
			}
		}
	};
	tokio::join!(draining, api_down);
	match handed {
		Some(h) => upgrader.finish(h, runtimes).await,
		None => registry.shutdown().await,
	}
	Ok(())
}

/// `event = "performance"`: the settings in effect and where each came from.
fn log_performance(p: &rproxy_api::config::performance::Effective) {
	use rproxy_api::config::performance::Affinity;
	let affinity = match &p.cpu_affinity {
		Affinity::None => "none".to_string(),
		Affinity::Auto => "auto".to_string(),
		Affinity::List(cpus) => cpus.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
	};
	let sources: Vec<String> = p.sources.iter().map(|(k, f)| format!("{k}={}", f.as_str())).collect();
	info!(event = "performance", workers = p.workers, udp_shards = p.udp_shards, cpu_affinity = %affinity,
		busy_poll_usecs = p.busy_poll_usecs, splice = p.splice.enabled, splice_after = p.splice.after,
		splice_full_reads = p.splice.full_reads, splice_pipe_size = p.splice.pipe_size, sources = %sources.join(" "));
	if !p.missing_cpus.is_empty() {
		let missing: Vec<String> = p.missing_cpus.iter().map(|c| c.to_string()).collect();
		warn!(event = "degraded", part = "global.performance.cpu_affinity", cpus = %missing.join(","),
			"these CPUs do not exist or this process may not use them; left out");
	}
}

/// Records the control API's certificate expiry (it is not in the certificate
/// store, but goes through the same check, logs and metrics).
fn note_api_cert(registry: &Registry, cert: &Path) {
	let file = cert.to_string_lossy();
	match rproxy_api::tls::config::file_expiry(&file) {
		Ok(not_after) => registry.certs().note_external(CertRole::Api, &file, not_after, rproxy_api::tls::config::unix_now()),
		Err(e) => warn!(event = "cert.check", part = "api", error = %e.message),
	}
}

/// Watches certificates: files that changed are re-read (`files`, #90), once
/// per certificate in the store, and expiry is checked (`expiry`, daily by
/// default), for the rules' certificates and the control API's.
async fn watch_certificates(
	files: Option<Duration>,
	expiry: Option<Duration>,
	registry: Arc<Registry>,
	api_tls: Arc<OnceCell<RustlsConfig>>,
	api_files: Option<ApiTlsFiles>,
	stop: CancellationToken,
) {
	use rproxy_api::tls::config::fingerprint;
	let api_print = |f: &ApiTlsFiles| fingerprint(f.paths().into_iter().map(|p| p.to_str().unwrap_or("")));
	let mut api_seen = api_files.as_ref().map(api_print);
	let ticker = |every: Option<Duration>| {
		every.map(|e| {
			let mut t = tokio::time::interval_at(tokio::time::Instant::now() + e, e);
			t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
			t
		})
	};
	let (mut file_ticks, mut expiry_ticks) = (ticker(files), ticker(expiry));
	async fn tick(t: &mut Option<tokio::time::Interval>) {
		match t {
			Some(t) => {
				t.tick().await;
			}
			None => std::future::pending().await,
		}
	}
	loop {
		tokio::select! {
			_ = stop.cancelled() => return,
			_ = tick(&mut file_ticks) => {
				registry.reload_changed_tls().await;
				if let (Some(files), Some(config)) = (&api_files, api_tls.get()) {
					let now = api_print(files);
					if api_seen != Some(now) {
						match files.reload(config) {
							Ok(()) => {
								info!(event = "reload.tls", part = "api", reason = "files changed");
								api_seen = Some(now);
								note_api_cert(&registry, &files.cert);
							}
							Err(e) => warn!(event = "reload.tls", part = "api", error = %e, "keeping current certificate"),
						}
					}
				}
			}
			_ = tick(&mut expiry_ticks) => {
				let changed = registry.check_certificate_expiry().await;
				info!(event = "cert.check", rules_updated = changed);
				if let Some(files) = &api_files {
					note_api_cert(&registry, &files.cert);
				}
			}
		}
	}
}

fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Applies the settings file again when it changes (checked every `every`) or on
/// SIGHUP (`hup`). A version with a mistake, or one that cannot be read, changes
/// nothing: the rules of the last good version keep running. The work is done by
/// the shared `ConfigReloader`, which `POST /config/reload` also uses.
async fn watch_config(every: Option<Duration>, reloader: Arc<ConfigReloader>, hup: Arc<Notify>, stop: CancellationToken) {
	let mut ticks = every.map(|every| {
		let mut t = tokio::time::interval(every);
		t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
		t
	});
	loop {
		let forced = tokio::select! {
			_ = stop.cancelled() => return,
			_ = hup.notified() => true,
			_ = async { match ticks.as_mut() { Some(t) => { t.tick().await; } None => std::future::pending().await } } => false,
		};
		reloader.reload(forced).await;
	}
}

/// Checks token expiry once a day and unlocks locked-out sources whose time
/// is up (#167).
async fn watch_tokens(tokens: Arc<Tokens>, expiry: Arc<TokenExpiry>, stop: CancellationToken) {
	let start = tokio::time::Instant::now();
	let mut day = tokio::time::interval_at(start + Duration::from_secs(86_400), Duration::from_secs(86_400));
	let mut sweep = tokio::time::interval_at(start + Duration::from_secs(5), Duration::from_secs(5));
	loop {
		tokio::select! {
			_ = stop.cancelled() => return,
			_ = day.tick() => {
				expiry.check(&tokens.expiries());
			}
			_ = sweep.tick() => tokens.lockout().sweep(),
		}
	}
}

/// Serves SIGHUP (reload tokens and certificate) until SIGINT or SIGTERM.
#[cfg(unix)]
async fn wait_for_shutdown(
	tokens: &Tokens,
	token_expiry: &TokenExpiry,
	tls: &OnceCell<RustlsConfig>,
	tls_files: Option<&ApiTlsFiles>,
	registry: &Arc<Registry>,
	config_hup: &Notify,
	upgrader: &Arc<rproxy_api::control::upgrade::handoff::Upgrader>,
) -> Result<Option<rproxy_api::control::upgrade::handoff::HandedOff>, String> {
	use tokio::signal::unix::{signal, SignalKind};

	let mut hup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
	let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
	// a live upgrade to the binary on disk (#174)
	let mut usr2 = signal(SignalKind::user_defined2()).map_err(|e| e.to_string())?;
	loop {
		tokio::select! {
			_ = usr2.recv() => {
				if let Err(e) = upgrader.start(None, "SIGUSR2") {
					warn!(event = "handoff.busy", error = %e);
				}
			}
			h = upgrader.handed_off() => return Ok(Some(h)),
			_ = hup.recv() => {
				match tokens.reload() {
					Ok(n) => info!(event = "reload.tokens", tokens = n),
					Err(e) => warn!(event = "reload.tokens", error = %e, "keeping current tokens"),
				}
				token_expiry.check(&tokens.expiries());
				if let (Some(tls), Some(files)) = (tls.get(), tls_files) {
					match files.reload(tls) {
						Ok(()) => {
							info!(event = "reload.tls");
							note_api_cert(registry, &files.cert);
						}
						Err(e) => warn!(event = "reload.tls", error = %e, "keeping current certificate"),
					}
				}
				config_hup.notify_one();
				let (ok, failed) = registry.reload_tls().await;
				info!(event = "reload.rules_tls", reloaded = ok, failed);
				if let Some(b) = registry.http_global().crowdsec() {
					match b.reload_key() {
						Ok(()) => info!(event = "reload.crowdsec"),
						Err(e) => warn!(event = "reload.crowdsec", error = %e, "keeping the current CrowdSec key"),
					}
				}
				if let Some(g) = registry.http_global().geoip().cloned() {
					let _ = tokio::task::spawn_blocking(move || g.refresh(true)).await;
				}
			}
			_ = term.recv() => return Ok(None),
			_ = tokio::signal::ctrl_c() => return Ok(None),
		}
	}
}

#[cfg(not(unix))]
async fn wait_for_shutdown(
	_: &Tokens,
	_: &TokenExpiry,
	_: &OnceCell<RustlsConfig>,
	_: Option<&ApiTlsFiles>,
	_: &Arc<Registry>,
	_: &Notify,
	_: &Arc<rproxy_api::control::upgrade::handoff::Upgrader>,
) -> Result<Option<rproxy_api::control::upgrade::handoff::HandedOff>, String> {
	tokio::signal::ctrl_c().await.map_err(|e| e.to_string())?;
	Ok(None)
}

/// A missing file or unusable content is a mistake in the configuration;
/// anything else (permissions, ...) is the environment, which rproxy-api runs
/// around in a restricted mode.
fn config_error(e: &io::Error) -> bool {
	matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput)
}

/// One address of the control API.
struct ApiListener {
	addr: SocketAddr,
	app: axum::Router,
	tls: Arc<OnceCell<RustlsConfig>>,
	/// the TLS files when the API is served over TLS
	files: Option<ApiTlsFiles>,
	handles: Arc<Mutex<Vec<Handle>>>,
}

impl ApiListener {
	async fn start(&self) -> Result<(), String> {
		let tls = match &self.files {
			None => None,
			Some(files) => match self.tls.get() {
				Some(config) => Some(config.clone()),
				None => {
					let config = files.rustls().map_err(|e| e.to_string())?;
					let _ = self.tls.set(config);
					self.tls.get().cloned()
				}
			},
		};
		// Bind here so a busy port fails right away. Waiting on `Handle::listening()` for a bind
		// error can hang: axum-server notifies only the waiters present at that moment.
		// a live upgrade (#174): the old process's socket
		let listener = match rproxy_api::control::upgrade::inherit::take_tcp(self.addr) {
			Some(l) => l,
			None => std::net::TcpListener::bind(self.addr).map_err(|e| e.to_string())?,
		};
		listener.set_nonblocking(true).map_err(|e| e.to_string())?;
		// the peer's address for the audit log (api::Client)
		let app = self.app.clone().into_make_service_with_connect_info::<SocketAddr>();
		let handle = Handle::new();
		let addr = self.addr;
		match tls {
			Some(tls) => {
				// requests carry the client certificate's names (#167)
				let server = axum_server::from_tcp(listener)
					.map_err(|e| e.to_string())?
					.acceptor(ClientCertAcceptor::new(tls))
					.handle(handle.clone());
				tokio::spawn(async move {
					if let Err(e) = server.serve(app).await {
						error!(event = "api.stopped", addr = %addr, error = %e);
					}
				});
			}
			None => {
				let server = axum_server::from_tcp(listener).map_err(|e| e.to_string())?.handle(handle.clone());
				tokio::spawn(async move {
					if let Err(e) = server.serve(app).await {
						error!(event = "api.stopped", addr = %addr, error = %e);
					}
				});
			}
		}
		info!(event = "api.listening", addr = %self.addr, tls = self.files.is_some());
		self.handles.lock().unwrap().push(handle);
		Ok(())
	}

	/// Tries again after `first`, then doubles the wait up to five minutes, so
	/// a port that stays taken does not fill the log.
	async fn retry(self, first: Duration, stop: CancellationToken) {
		let mut wait = first;
		loop {
			tokio::select! {
				_ = stop.cancelled() => return,
				_ = tokio::time::sleep(wait) => {}
			}
			match self.start().await {
				Ok(()) => return,
				Err(e) => {
					wait = next_retry(wait, first);
					warn!(event = "api.retry", addr = %self.addr, error = %e, next_retry_secs = wait.as_secs());
				}
			}
		}
	}
}

const MAX_API_RETRY: Duration = Duration::from_secs(300);

/// The next wait between attempts: doubled, at most five minutes (or `first` if that is longer).
fn next_retry(wait: Duration, first: Duration) -> Duration {
	(wait * 2).min(MAX_API_RETRY.max(first))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn api_retries_back_off_to_five_minutes() {
		let first = Duration::from_secs(10);
		let mut wait = first;
		let mut waits = vec![];
		for _ in 0..8 {
			wait = next_retry(wait, first);
			waits.push(wait.as_secs());
		}
		assert_eq!(waits, [20, 40, 80, 160, 300, 300, 300, 300]);
	}
}
