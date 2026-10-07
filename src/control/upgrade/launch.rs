//! `rproxy-api launch`: the entry point of the container image (#174,
//! docs/DESIGN-v0.4.md 10.2).
//!
//! It picks the binary to run (the newest verified patch of the image's
//! major.minor in the cache or at the release source, unless `RPROXY_UPDATE` is
//! not `auto`), runs it as its child and stays as the container's init:
//! - signals (TERM, INT, HUP, USR2) go to the current server process;
//! - a live upgrade (SIGUSR2, `POST /admin/update`) makes the server start its
//!   successor and say `MAINPID=<new>` on `$NOTIFY_SOCKET`, which points here;
//!   the old process drains and exits, and the successor is followed instead
//!   (orphans come to this process: `PR_SET_CHILD_SUBREAPER`);
//! - when the server exits, so does the launcher, with its status. A version on
//!   trial (swapped in, not `RPROXY_UPDATE_HEALTHY` yet) that exits on its own is
//!   marked bad and the previous good version is started instead (rollback). One
//!   stopped by a signal to the launcher (docker stop, a rolling restart) is not:
//!   its trial ends, and it is tried again on the next start. A trial cut short
//!   without the launcher seeing it (SIGKILL, OOM of the container) counts against
//!   the version only `MAX_INTERRUPTED` times in a row (security review M1).

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tracing::{error, info, warn};

use super::update::{mark_bad, Fetcher, Trial, UpdateConfig, Version, MAX_INTERRUPTED};
use super::UpdateMode;

/// The binary the launcher starts, and whether it is on trial.
struct Choice {
	exe: PathBuf,
	version: Version,
}

/// The image's own binary.
fn image() -> Result<Choice, String> {
	let exe = super::handoff::binary_on_disk().map_err(|e| format!("cannot find the binary: {e}"))?;
	Ok(Choice { exe, version: Version::own() })
}

/// Picks the binary: the pin, else the newest good one (image, cache, source).
async fn choose(cfg: &UpdateConfig) -> Result<Choice, String> {
	let image = image()?;
	if cfg.mode != UpdateMode::Auto {
		return Ok(image);
	}
	let key = match cfg.key() {
		Ok(k) => k,
		Err(e) => {
			warn!(event = "update.error", error = %e, "running the image's version");
			return Ok(image);
		}
	};
	let _ = std::fs::create_dir_all(&cfg.cache);
	// a version still on trial: the container stopped without the launcher seeing it
	// (SIGKILL, OOM); counted, and bad only when it keeps happening
	let mut interrupted = 0;
	if let Some(t) = cfg.load_state().trial {
		if let Some(v) = Version::parse(&t.version) {
			interrupted = t.interrupted + 1;
			if interrupted >= MAX_INTERRUPTED {
				mark_bad(cfg, v, &format!("stopped {interrupted} times before RPROXY_UPDATE_HEALTHY"));
				interrupted = 0;
			} else {
				warn!(event = "update.interrupted", version = %v, times = interrupted, "the trial of this version was cut short; trying it again");
			}
		}
	}
	let bad = cfg.load_state().bad;
	let is_bad = |v: &Version| bad.iter().any(|b| Version::parse(b) == Some(*v));
	// fetch what is new (a closed network or an outage falls back to the cache)
	match Fetcher::new(cfg.clone()) {
		Ok(f) => match tokio::time::timeout(Duration::from_secs(60), f.newest(image.version, &bad)).await {
			Ok(Ok(_)) => {}
			Ok(Err(e)) => warn!(event = "update.error", error = %e, "using the cached releases"),
			Err(_) => warn!(event = "update.error", error = "timed out", "using the cached releases"),
		},
		Err(e) => warn!(event = "update.error", error = %e),
	}
	let wanted = |v: &Version| match cfg.pin {
		Some(pin) => *v == pin,
		None => *v > image.version && v.0 == image.version.0 && v.1 == image.version.1,
	};
	for v in cfg.cached_versions().into_iter().filter(|v| wanted(v) && !is_bad(v)) {
		match cfg.verify_cached(&key, v) {
			Ok(exe) => {
				// not known to be good yet: on trial until RPROXY_UPDATE_HEALTHY
				if cfg.load_state().good.as_deref().and_then(Version::parse) != Some(v) {
					let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
					let _ = cfg.update_state(|s| {
						// the count goes on for the same version only
						let count = if s.trial.as_ref().is_some_and(|t| t.version == v.to_string()) { interrupted } else { 0 };
						s.trial = Some(Trial { version: v.to_string(), started_at: now, interrupted: count });
					});
				} else {
					let _ = cfg.update_state(|s| s.trial = None);
				}
				return Ok(Choice { exe, version: v });
			}
			Err(e) => warn!(event = "update.error", version = %v, error = %e, "not running this cached release"),
		}
	}
	if let Some(pin) = cfg.pin.filter(|p| *p != image.version) {
		warn!(event = "update.error", version = %pin, "the pinned version is not available; running the image's version");
	}
	let _ = cfg.update_state(|s| s.trial = None);
	Ok(image)
}

/// Whether `pid` descends from this process (a server or its successor).
fn descends_from_me(pid: i32) -> bool {
	let me = std::process::id() as i32;
	let mut p = pid;
	for _ in 0..16 {
		if p == me {
			return true;
		}
		if p <= 1 {
			return false;
		}
		let Ok(status) = std::fs::read_to_string(format!("/proc/{p}/status")) else { return false };
		let Some(ppid) = status.lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|v| v.trim().parse().ok()) else {
			return false;
		};
		p = ppid;
	}
	false
}

fn spawn(choice: &Choice, args: &[OsString], notify: &str) -> Result<i32, String> {
	info!(event = "launch.start", version = %choice.version, exe = %choice.exe.display());
	let child = std::process::Command::new(&choice.exe)
		.args(args)
		.env("NOTIFY_SOCKET", notify)
		.spawn()
		.map_err(|e| format!("starting {}: {e}", choice.exe.display()))?;
	Ok(child.id() as i32)
}

fn exit_code(status: libc::c_int) -> u8 {
	if libc::WIFEXITED(status) {
		libc::WEXITSTATUS(status) as u8
	} else if libc::WIFSIGNALED(status) {
		(128 + libc::WTERMSIG(status)) as u8
	} else {
		1
	}
}

/// Runs the launcher; `args` go to the server.
pub fn run(cfg: UpdateConfig, args: Vec<OsString>) -> ExitCode {
	// orphans (the old server after a handoff, its successor) come here
	// SAFETY: prctl with integer arguments
	unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
	let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
		Ok(rt) => rt,
		Err(e) => {
			error!(event = "fatal", part = "launch", error = %e);
			return ExitCode::FAILURE;
		}
	};
	match runtime.block_on(supervise(cfg, args)) {
		Ok(code) => ExitCode::from(code),
		Err(e) => {
			error!(event = "fatal", part = "launch", error = %e);
			ExitCode::FAILURE
		}
	}
}

async fn supervise(cfg: UpdateConfig, args: Vec<OsString>) -> Result<u8, String> {
	use std::os::linux::net::SocketAddrExt;
	use tokio::signal::unix::{signal, SignalKind};

	let name = format!("rproxy-launch-{}-{:x}", std::process::id(), rand_suffix());
	let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).map_err(|e| e.to_string())?;
	let std_sock = std::os::unix::net::UnixDatagram::bind_addr(&addr).map_err(|e| format!("notify socket: {e}"))?;
	std_sock.set_nonblocking(true).map_err(|e| e.to_string())?;
	let sock = tokio::net::UnixDatagram::from_std(std_sock).map_err(|e| e.to_string())?;
	let notify = format!("@{name}");

	let mut choice = choose(&cfg).await?;
	let mut main = spawn(&choice, &args, &notify)?;
	let mut former: Vec<i32> = vec![];
	let mut stopping = false;

	let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
	let mut int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;
	let mut hup = signal(SignalKind::hangup()).map_err(|e| e.to_string())?;
	let mut usr2 = signal(SignalKind::user_defined2()).map_err(|e| e.to_string())?;
	let mut chld = signal(SignalKind::child()).map_err(|e| e.to_string())?;
	let mut buf = [0u8; 4096];
	let send = |pid: i32, sig: libc::c_int| {
		// SAFETY: kill with a pid we started (or that descends from us)
		unsafe { libc::kill(pid, sig) };
	};
	loop {
		tokio::select! {
			_ = term.recv() => { stopping = true; send(main, libc::SIGTERM); for p in &former { send(*p, libc::SIGTERM); } }
			_ = int.recv() => { stopping = true; send(main, libc::SIGINT); for p in &former { send(*p, libc::SIGINT); } }
			_ = hup.recv() => send(main, libc::SIGHUP),
			_ = usr2.recv() => send(main, libc::SIGUSR2),
			r = sock.recv(&mut buf) => {
				let Ok(n) = r else { continue };
				let text = String::from_utf8_lossy(&buf[..n]);
				for line in text.lines() {
					if let Some(pid) = line.strip_prefix("MAINPID=").and_then(|p| p.trim().parse::<i32>().ok()) {
						if pid != main && descends_from_me(pid) {
							info!(event = "launch.mainpid", old = main, new = pid);
							former.push(main);
							main = pid;
							choice.version = running_version_of(&cfg, pid).unwrap_or(choice.version);
						}
					}
				}
			}
			_ = chld.recv() => {
				// reap every child that ended (we are the subreaper)
				loop {
					let mut status: libc::c_int = 0;
					// SAFETY: waitpid on any child, without blocking
					let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
					if pid <= 0 {
						break;
					}
					former.retain(|p| *p != pid);
					if pid != main {
						continue;
					}
					let code = exit_code(status);
					if stopping {
						// stopped by us (docker stop, a rolling restart): proves nothing about
						// the version; its trial ends and it is tried again next time
						let _ = cfg.update_state(|s| s.trial = None);
						return Ok(code);
					}
					// a version on trial that stops is rolled back
					let trial = cfg.load_state().trial.and_then(|t| Version::parse(&t.version));
					if cfg.mode == UpdateMode::Auto && trial.is_some() {
						let v = trial.unwrap_or(choice.version);
						mark_bad(&cfg, v, &format!("exited with status {code} before RPROXY_UPDATE_HEALTHY"));
						choice = choose(&cfg).await?;
						warn!(event = "update.rollback", started = %choice.version);
						main = spawn(&choice, &args, &notify)?;
						continue;
					}
					info!(event = "launch.exit", code);
					return Ok(code);
				}
			}
		}
	}
}

/// The version a server process runs, from its binary's path.
fn running_version_of(cfg: &UpdateConfig, pid: i32) -> Option<Version> {
	let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
	cfg.cached_version_of(&exe).or(Some(Version::own()))
}

fn rand_suffix() -> u64 {
	let mut b = [0u8; 8];
	let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
	u64::from_le_bytes(b)
}
