use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
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
	/// Port for the control API
	#[arg(long, env = "RPROXY_API_PORT", default_value_t = 8080)]
	api_port: u16,
	/// File of bearer tokens, one per line; re-read on SIGHUP
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
	/// mysql://user:pass@host:port/db to restore rules from at startup
	#[arg(long, env = "RPROXY_DATABASE_URL", hide_env_values = true)]
	database_url: Option<String>,
	/// Seconds between DNS re-resolutions of rule targets
	#[arg(long, env = "RPROXY_DNS_INTERVAL", default_value_t = 30)]
	dns_interval: u64,
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

#[tokio::main]
async fn main() -> ExitCode {
	// a missing .env is fine; a malformed one is reported
	if let Err(e) = dotenvy::dotenv() {
		if !e.not_found() {
			eprintln!("rproxy-api: .env: {e}");
			return ExitCode::FAILURE;
		}
	}
	let opts = Options::parse();

	let _log_guard = match logging::init(&opts.log_level, opts.log_file.as_deref(), opts.log_keep) {
		Ok(guard) => guard,
		Err(e) => {
			eprintln!("rproxy-api: {e}");
			return ExitCode::FAILURE;
		}
	};
	match run(opts).await {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			error!(event = "fatal", error = %e);
			ExitCode::FAILURE
		}
	}
}

async fn run(opts: Options) -> Result<(), String> {
	let addrs = opts.api_addr.clone();
	check_exposure(&opts, &addrs)?;
	if opts.tls_cert.is_some() != opts.tls_key.is_some() {
		return Err("--tls-cert and --tls-key must be given together".into());
	}

	let tokens = Arc::new(match &opts.token_file {
		Some(path) => Tokens::from_file(path.clone()).map_err(|e| format!("token file: {e}"))?,
		None => Tokens::disabled(),
	});

	let tls = match (&opts.tls_cert, &opts.tls_key) {
		(Some(cert), Some(key)) => {
			let _ = rustls::crypto::ring::default_provider().install_default();
			Some(RustlsConfig::from_pem_file(cert, key).await.map_err(|e| format!("TLS: {e}"))?)
		}
		_ => None,
	};

	let transparent = source::transparent_available();
	let registry = Registry::new(Config {
		dns_interval: Duration::from_secs(opts.dns_interval.max(1)),
		lookup: resolve::system_lookup(),
		transparent,
	});
	info!(event = "start", version = env!("CARGO_PKG_VERSION"), transparent, auth = tokens.enabled(), tls = tls.is_some());

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
	let mut handles = vec![];
	for ip in addrs {
		let addr = SocketAddr::new(ip, opts.api_port);
		let app = app.clone().into_make_service();
		let handle = Handle::new();
		let server = match &tls {
			Some(tls) => tokio::spawn(axum_server::bind_rustls(addr, tls.clone()).handle(handle.clone()).serve(app)),
			None => tokio::spawn(axum_server::bind(addr).handle(handle.clone()).serve(app)),
		};
		// a bind error makes `listening()` return None
		if handle.listening().await.is_none() {
			let reason = match server.await {
				Ok(Err(e)) => e.to_string(),
				_ => "server stopped".into(),
			};
			return Err(format!("control API on {addr}: {reason}"));
		}
		handles.push(handle);
	}
	info!(event = "api.listening", port = opts.api_port, tls = tls.is_some());

	wait_for_shutdown(&tokens, tls.as_ref(), &opts).await?;

	info!(event = "shutdown");
	for handle in &handles {
		handle.graceful_shutdown(Some(Duration::from_secs(5)));
	}
	registry.shutdown().await;
	Ok(())
}

/// Serves SIGHUP (reload tokens and certificate) until SIGINT or SIGTERM.
#[cfg(unix)]
async fn wait_for_shutdown(tokens: &Tokens, tls: Option<&RustlsConfig>, opts: &Options) -> Result<(), String> {
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
				if let (Some(tls), Some(cert), Some(key)) = (tls, &opts.tls_cert, &opts.tls_key) {
					match tls.reload_from_pem_file(cert, key).await {
						Ok(()) => info!(event = "reload.tls"),
						Err(e) => warn!(event = "reload.tls", error = %e, "keeping current certificate"),
					}
				}
			}
			_ = term.recv() => return Ok(()),
			_ = tokio::signal::ctrl_c() => return Ok(()),
		}
	}
}

#[cfg(not(unix))]
async fn wait_for_shutdown(_: &Tokens, _: Option<&RustlsConfig>, _: &Options) -> Result<(), String> {
	tokio::signal::ctrl_c().await.map_err(|e| e.to_string())
}
