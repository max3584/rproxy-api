use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use tokio::sync::{Notify, OnceCell};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use rproxy_api::api::{self, AppState};
use rproxy_api::auth::Tokens;
use rproxy_api::http::access::{AccessLogError, HttpGlobal};
use rproxy_api::http::crowdsec::{Bouncer, CrowdsecError};
use rproxy_api::config::{ConfigDoc, LoadError};
use rproxy_api::registry::{Config, ConfigStatus, Registry};
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
	/// Seconds between checks for changed certificate files (renewed by certbot,
	/// cert-manager, ...), which are then re-read; 0 turns the checks off
	#[arg(long, env = "RPROXY_CERT_CHECK_SECS", default_value_t = 60)]
	cert_check_secs: u64,
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
				for part in parsed.unsupported_globals() {
					warn!(event = "degraded", part = %format!("global.{part}"),
						"not available in this version yet; ignored (see GET /capabilities features)");
				}
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
	let http_global = http_global.with_crowdsec(crowdsec.clone());

	let transparent = source::transparent_available();
	let transparent_ipv6 = source::transparent_v6_available();
	let registry = Registry::new(Config {
		dns_interval: Duration::from_secs(opts.dns_interval.max(1)),
		lookup: resolve::system_lookup(),
		transparent,
		transparent_ipv6,
		max_range_ports: opts.max_range_ports.max(1),
		reserved: addrs.iter().map(|ip| SocketAddr::new(*ip, opts.api_port)).collect(),
		http: Arc::new(http_global),
	});
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

	if opts.cert_check_secs > 0 {
		let every = Duration::from_secs(opts.cert_check_secs);
		tokio::spawn(watch_certificates(every, registry.clone(), tls.clone(), opts.tls_cert.clone().zip(opts.tls_key.clone()), stop.clone()));
	}

	// the settings file: applied again when it changes, or on SIGHUP
	let config_hup = Arc::new(Notify::new());
	if let Some(path) = config_path {
		let every = (opts.config_check_secs > 0).then(|| Duration::from_secs(opts.config_check_secs));
		let base = doc.map(|(_, d)| d).unwrap_or_default();
		tokio::spawn(watch_config(path, every, registry.clone(), base, config_hup.clone(), stop.clone()));
	}

	wait_for_shutdown(&tokens, &tls, &opts, &registry, &config_hup).await?;

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
	if let Some(b) = &crowdsec {
		b.stop();
	}
	registry.shutdown().await;
	Ok(())
}

/// Re-reads certificate files that changed: the rules' and the control API's.
async fn watch_certificates(
	every: Duration,
	registry: Arc<Registry>,
	api_tls: Arc<OnceCell<RustlsConfig>>,
	api_files: Option<(PathBuf, PathBuf)>,
	stop: CancellationToken,
) {
	use rproxy_api::tlsconf::fingerprint;
	let mut seen = std::collections::HashMap::new();
	let api_print = |(c, k): &(PathBuf, PathBuf)| fingerprint([c.to_str().unwrap_or(""), k.to_str().unwrap_or("")]);
	let mut api_seen = api_files.as_ref().map(api_print);
	let mut ticks = tokio::time::interval(every);
	ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	loop {
		tokio::select! {
			_ = stop.cancelled() => return,
			_ = ticks.tick() => {}
		}
		registry.reload_changed_tls(&mut seen).await;
		if let (Some(files), Some(config)) = (&api_files, api_tls.get()) {
			let now = api_print(files);
			if api_seen != Some(now) {
				match config.reload_from_pem_file(&files.0, &files.1).await {
					Ok(()) => {
						info!(event = "reload.tls", part = "api", reason = "files changed");
						api_seen = Some(now);
					}
					Err(e) => warn!(event = "reload.tls", part = "api", error = %e, "keeping current certificate"),
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
/// nothing: the rules of the last good version keep running. `base` is the
/// version the process started with; `global` changes against it need a restart.
async fn watch_config(
	path: PathBuf,
	every: Option<Duration>,
	registry: Arc<Registry>,
	base: ConfigDoc,
	hup: Arc<Notify>,
	stop: CancellationToken,
) {
	let started_ok = registry.config_status().is_some_and(|s| s.error.is_none());
	// what was last applied (or found broken); None: try again on every check
	let mut seen = started_ok.then(|| rproxy_api::config::fingerprint(&path));
	let mut last_error: Option<String> = None;
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
		let now = rproxy_api::config::fingerprint(&path);
		if !forced && seen == Some(now) {
			continue;
		}
		let mut status = registry.config_status().unwrap_or_default();
		status.path = path.display().to_string();
		let result = match ConfigDoc::load(&path) {
			Ok(doc) => {
				let restart: Vec<String> = doc.restart_needed(&base).into_iter().map(String::from).collect();
				let files: Vec<String> = doc.files.iter().map(|f| f.display().to_string()).collect();
				let rules = doc.rules.len();
				match registry.reload_static(doc.labeled_rules()).await {
					Ok(counts) => {
						info!(event = "config.reload", added = counts.added, removed = counts.removed, changed = counts.changed,
							unchanged = counts.unchanged, failed = counts.failed, files = files.len());
						if !restart.is_empty() {
							warn!(event = "config.reload", restart_needed = ?restart, "these settings take effect after a restart");
						}
						status = ConfigStatus {
							path: status.path,
							files,
							loaded_at: Some(unix_now()),
							rules,
							last_reload: Some(counts),
							error: None,
							restart_needed: restart,
						};
						seen = Some(now);
						last_error = None;
						Ok(())
					}
					Err(e) => Err((format!("{}: {e}", path.display()), true)),
				}
			}
			Err(LoadError::Invalid(e)) => Err((e, true)),
			// e.g. permissions: the fingerprint may not change when fixed, so keep trying
			Err(e @ LoadError::Read(..)) => Err((e.to_string(), false)),
		};
		if let Err((error, settled)) = result {
			if last_error.as_deref() != Some(error.as_str()) {
				error!(event = "config.error", error = %error, "keeping the rules of the last good settings");
			}
			if settled {
				seen = Some(now);
			}
			status.error = Some(error.clone());
			last_error = Some(error);
		}
		registry.set_config_status(status);
	}
}

/// Serves SIGHUP (reload tokens and certificate) until SIGINT or SIGTERM.
#[cfg(unix)]
async fn wait_for_shutdown(
	tokens: &Tokens,
	tls: &OnceCell<RustlsConfig>,
	opts: &Options,
	registry: &Registry,
	config_hup: &Notify,
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
				config_hup.notify_one();
				let (ok, failed) = registry.reload_tls().await;
				info!(event = "reload.rules_tls", reloaded = ok, failed);
				if let Some(b) = registry.http_global().crowdsec() {
					match b.reload_key() {
						Ok(()) => info!(event = "reload.crowdsec"),
						Err(e) => warn!(event = "reload.crowdsec", error = %e, "keeping the current CrowdSec key"),
					}
				}
			}
			_ = term.recv() => return Ok(()),
			_ = tokio::signal::ctrl_c() => return Ok(()),
		}
	}
}

#[cfg(not(unix))]
async fn wait_for_shutdown(_: &Tokens, _: &OnceCell<RustlsConfig>, _: &Options, _: &Registry, _: &Notify) -> Result<(), String> {
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
