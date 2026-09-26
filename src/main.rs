use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use rproxy_api::api::{self, AppState};
use rproxy_api::auth::Tokens;
use rproxy_api::registry::{Config, Registry};
use rproxy_api::{db, logging, resolve, source};

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
	/// File of bearer tokens (one per line, or YAML with scopes); re-read on SIGHUP
	#[arg(long, env = "RPROXY_TOKEN_FILE")]
	token_file: Option<PathBuf>,
	/// TLS certificate chain (PEM) for the control API; re-read on SIGHUP
	#[arg(long, env = "RPROXY_TLS_CERT")]
	tls_cert: Option<PathBuf>,
	/// TLS private key (PEM) for the control API
	#[arg(long, env = "RPROXY_TLS_KEY")]
	tls_key: Option<PathBuf>,
	/// Log file, rotated daily as <stem>.<date>.<ext> (default: stdout)
	#[arg(long, env = "RPROXY_LOG_FILE")]
	log_file: Option<PathBuf>,
	/// Number of rotated log files to keep
	#[arg(long, env = "RPROXY_LOG_KEEP", default_value_t = 14)]
	log_keep: usize,
	/// Log filter, e.g. info or debug
	#[arg(long, env = "RPROXY_LOG_LEVEL", default_value = "info")]
	log_level: String,
	/// Settings file (YAML or JSON): `version`, `global` and `rules` started before
	/// the database ones; the API cannot change those rules
	#[arg(long, env = "RPROXY_CONFIG")]
	config: Option<PathBuf>,
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
	#[arg(long, env = "RPROXY_MAX_RANGE_PORTS", default_value_t = rproxy_api::rule::DEFAULT_MAX_RANGE_PORTS)]
	max_range_ports: u16,
	/// Seconds between attempts to open a control API listener that could not start
	#[arg(long, env = "RPROXY_API_RETRY_SECS", default_value_t = 10, hide = true)]
	api_retry_secs: u64,
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
	let opts = Options::parse();

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
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(rt) => rt,
		Err(e) => {
			error!(event = "fatal", error = %e);
			return ExitCode::FAILURE;
		}
	};
	match runtime.block_on(run(opts)) {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			error!(event = "fatal", error = %e);
			ExitCode::FAILURE
		}
	}
}

async fn run(opts: Options) -> Result<(), String> {
	let addrs = if opts.api_port == 0 { vec![] } else { opts.api_addr.clone() };
	if addrs.is_empty() && opts.api_socket.is_none() {
		return Err("--api-port 0 turns TCP off; give --api-socket (RPROXY_API_SOCKET) for the control API".into());
	}
	check_exposure(&opts, &addrs)?;
	#[cfg(unix)]
	let socket = match &opts.api_socket {
		Some(path) => Some(rproxy_api::unix_api::SocketOptions {
			path: path.clone(),
			mode: rproxy_api::unix_api::parse_mode(&opts.api_socket_mode)?,
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

	let tokens = Arc::new(match &opts.token_file {
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
	});

	// the control API certificate; loaded later by the listener task when it cannot be read yet
	let tls: Arc<OnceCell<RustlsConfig>> = Arc::default();
	if let (Some(cert), Some(key)) = (&opts.tls_cert, &opts.tls_key) {
		let _ = rustls::crypto::ring::default_provider().install_default();
		match load_api_tls(cert, key).await {
			Ok(config) => {
				let _ = tls.set(config);
			}
			Err(ApiTlsError::Config(e)) => return Err(e),
			Err(ApiTlsError::Unreadable(e)) => {
				warn!(event = "degraded", part = "api_tls", error = %e, "control API waits for its certificate");
			}
		}
	}

	let transparent = source::transparent_available();
	let transparent_ipv6 = source::transparent_v6_available();
	let registry = Registry::new(Config {
		dns_interval: Duration::from_secs(opts.dns_interval.max(1)),
		lookup: resolve::system_lookup(),
		transparent,
		transparent_ipv6,
		max_range_ports: opts.max_range_ports.max(1),
		reserved: addrs.iter().map(|ip| SocketAddr::new(*ip, opts.api_port)).collect(),
	});
	let nofile = raise_nofile_limit();
	info!(event = "start", version = env!("CARGO_PKG_VERSION"), transparent, transparent_ipv6, auth = tokens.enabled(),
		tls = opts.tls_cert.is_some(), max_range_ports = opts.max_range_ports, nofile_limit = nofile.unwrap_or(0));

	if opts.config.is_some() && opts.static_rules.is_some() {
		return Err("give --config (RPROXY_CONFIG) or --static-rules (RPROXY_STATIC_RULES), not both".into());
	}
	if let Some(path) = opts.config.as_ref().or(opts.static_rules.as_ref()) {
		match std::fs::read_to_string(path) {
			Ok(text) => {
				let doc = rproxy_api::config::ConfigDoc::parse(path, &text).map_err(|e| format!("{}: {e}", path.display()))?;
				for part in doc.unsupported_globals() {
					warn!(event = "degraded", part = %format!("global.{part}"),
						"not available in this version yet; ignored (see GET /capabilities features)");
				}
				registry.load_static(doc.rules).await.map_err(|e| format!("{}: {e}", path.display()))?;
			}
			Err(e) if config_error(&e) => return Err(format!("settings file {}: {e}", path.display())),
			Err(e) => error!(event = "degraded", part = "static_rules", error = %format!("{}: {e}", path.display()),
				"running without the rules of the settings file"),
		}
	}

	if let Some(url) = &opts.database_url {
		match db::load_rules(url).await {
			Ok(rules) => {
				info!(event = "restore.start", rules = rules.len());
				registry.restore(rules).await;
			}
			// keep serving the API so the UI can still add rules
			Err(e) => error!(event = "restore.error", error = %e),
		}
	}

	let app = api::router(Arc::new(AppState { registry: registry.clone(), tokens: tokens.clone() }));
	let handles: Arc<Mutex<Vec<Handle>>> = Arc::default();
	let stop = CancellationToken::new();
	let retry = Duration::from_secs(opts.api_retry_secs.max(1));
	for ip in addrs {
		let addr = SocketAddr::new(ip, opts.api_port);
		let listener = ApiListener {
			addr,
			app: app.clone(),
			tls: tls.clone(),
			files: opts.tls_cert.clone().zip(opts.tls_key.clone()),
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
		Some(socket) => match rproxy_api::unix_api::bind(socket).await {
			Ok(listener) => {
				info!(event = "api.listening", socket = %socket.path.display());
				let serve = axum::serve(listener, app.clone()).with_graceful_shutdown(stop.clone().cancelled_owned());
				Some(tokio::spawn(async move { serve.await }))
			}
			Err(rproxy_api::unix_api::SocketError::Config(e)) => return Err(e),
			Err(rproxy_api::unix_api::SocketError::Unavailable(e)) => {
				error!(event = "degraded", part = "api_socket", error = %e, "control API is not on the Unix socket");
				None
			}
		},
		None => None,
	};

	wait_for_shutdown(&tokens, &tls, &opts, &registry).await?;

	info!(event = "shutdown");
	stop.cancel();
	for handle in handles.lock().unwrap().iter() {
		handle.graceful_shutdown(Some(Duration::from_secs(5)));
	}
	#[cfg(unix)]
	if let (Some(server), Some(socket)) = (unix_server, &socket) {
		let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
		let _ = std::fs::remove_file(&socket.path);
	}
	registry.shutdown().await;
	Ok(())
}

/// Serves SIGHUP (reload tokens and certificate) until SIGINT or SIGTERM.
#[cfg(unix)]
async fn wait_for_shutdown(
	tokens: &Tokens,
	tls: &OnceCell<RustlsConfig>,
	opts: &Options,
	registry: &Registry,
) -> Result<(), String> {
	use tokio::signal::unix::{signal, SignalKind};

	let mut hup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
	let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
	loop {
		tokio::select! {
			_ = hup.recv() => {
				match tokens.reload() {
					Ok(n) => info!(event = "reload.tokens", tokens = n),
					Err(e) => warn!(event = "reload.tokens", error = %e, "keeping current tokens"),
				}
				if let (Some(tls), Some(cert), Some(key)) = (tls.get(), &opts.tls_cert, &opts.tls_key) {
					match tls.reload_from_pem_file(cert, key).await {
						Ok(()) => info!(event = "reload.tls"),
						Err(e) => warn!(event = "reload.tls", error = %e, "keeping current certificate"),
					}
				}
				let (ok, failed) = registry.reload_tls().await;
				info!(event = "reload.rules_tls", reloaded = ok, failed);
			}
			_ = term.recv() => return Ok(()),
			_ = tokio::signal::ctrl_c() => return Ok(()),
		}
	}
}

#[cfg(not(unix))]
async fn wait_for_shutdown(_: &Tokens, _: &OnceCell<RustlsConfig>, _: &Options, _: &Registry) -> Result<(), String> {
	tokio::signal::ctrl_c().await.map_err(|e| e.to_string())
}

/// A missing file or unusable content is a mistake in the configuration;
/// anything else (permissions, ...) is the environment, which rproxy-api runs
/// around in a restricted mode.
fn config_error(e: &io::Error) -> bool {
	matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput)
}

enum ApiTlsError {
	/// Wrong path or not a certificate / key: stop the startup.
	Config(String),
	/// Exists but cannot be read now: retry.
	Unreadable(String),
}

async fn load_api_tls(cert: &Path, key: &Path) -> Result<RustlsConfig, ApiTlsError> {
	let read = |path: &Path| {
		std::fs::read(path).map_err(|e| {
			let msg = format!("TLS {}: {e}", path.display());
			if config_error(&e) {
				ApiTlsError::Config(msg)
			} else {
				ApiTlsError::Unreadable(msg)
			}
		})
	};
	let (cert_pem, key_pem) = (read(cert)?, read(key)?);
	RustlsConfig::from_pem(cert_pem, key_pem).await.map_err(|e| ApiTlsError::Config(format!("TLS: {e}")))
}

/// One address of the control API.
struct ApiListener {
	addr: SocketAddr,
	app: axum::Router,
	tls: Arc<OnceCell<RustlsConfig>>,
	/// (cert, key) when the API is served over TLS
	files: Option<(PathBuf, PathBuf)>,
	handles: Arc<Mutex<Vec<Handle>>>,
}

impl ApiListener {
	async fn start(&self) -> Result<(), String> {
		let tls = match &self.files {
			None => None,
			Some((cert, key)) => match self.tls.get() {
				Some(config) => Some(config.clone()),
				None => {
					let config = load_api_tls(cert, key).await.map_err(|e| match e {
						ApiTlsError::Config(e) | ApiTlsError::Unreadable(e) => e,
					})?;
					let _ = self.tls.set(config);
					self.tls.get().cloned()
				}
			},
		};
		// Bind here so a busy port fails right away. Waiting on `Handle::listening()` for a bind
		// error can hang: axum-server notifies only the waiters present at that moment.
		let listener = std::net::TcpListener::bind(self.addr).map_err(|e| e.to_string())?;
		listener.set_nonblocking(true).map_err(|e| e.to_string())?;
		let app = self.app.clone().into_make_service();
		let handle = Handle::new();
		let addr = self.addr;
		match tls {
			Some(tls) => {
				let server = axum_server::from_tcp_rustls(listener, tls).handle(handle.clone());
				tokio::spawn(async move {
					if let Err(e) = server.serve(app).await {
						error!(event = "api.stopped", addr = %addr, error = %e);
					}
				});
			}
			None => {
				let server = axum_server::from_tcp(listener).handle(handle.clone());
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
