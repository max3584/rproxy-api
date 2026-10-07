//! A live upgrade (#174, docs/DESIGN-v0.4.md 10.1): the running process starts
//! the binary on disk as its child and hands its listening sockets over.
//!
//! 1. The old process listens on the handoff socket (`--handoff-socket`, 0600)
//!    and starts the new binary with the same arguments and
//!    `RPROXY_HANDOFF_FROM=<socket>`. Only that child (by its pid) may connect.
//! 2. The child says its version (`H`). Another major.minor is refused (`R`):
//!    the shape of what is handed over may change between minors.
//! 3. The old process sends every listening socket it has (`F`, SCM_RIGHTS, in
//!    batches): the rules' TCP and UDP sockets, HTTP/3's UDP sockets, the
//!    control API on TCP and the Unix socket, `http01_listen`. Then its state
//!    (`S`… `E`): the rules made through the API and every rule's counters.
//! 4. The child starts as usual, but takes the inherited socket wherever it
//!    would open one (`inherit`), restores the API's rules from the state
//!    instead of the database, adds the counters, and says it is ready (`Y`).
//! 5. The old process tells systemd / `rproxy-api launch` the new main pid,
//!    stops accepting, lets its connections finish (`--handoff-drain`), closes
//!    the rest, sends its final counters (`C`… `Z`, so nothing counted while it
//!    drained is lost) and exits.
//!
//! If the child does not get ready within `--handoff-timeout` (or exits), the
//! old process stops it and goes on as before (`handoff.failed`).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use tracing::{error, info, warn};

use super::fdpass::{Channel, Listener, MAX_FDS};
use crate::core::proxy::Runtime;
use crate::core::registry::Registry;
use crate::core::rule::{Key, Origin, RuleRequest};

/// Set in the new process's environment: the old process's handoff socket.
pub const ENV_FROM: &str = "RPROXY_HANDOFF_FROM";

const HELLO: u8 = b'H';
const REFUSE: u8 = b'R';
const FDS: u8 = b'F';
const STATE: u8 = b'S';
const STATE_END: u8 = b'E';
const READY: u8 = b'Y';
const FAILED: u8 = b'X';
const FINAL: u8 = b'C';
const FINAL_END: u8 = b'Z';

/// A rule's counters, by its key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
	pub protocol: String,
	pub listen_addr: String,
	pub listen_port: u16,
	pub total: u64,
	pub rx_bytes: u64,
	pub tx_bytes: u64,
	pub tls_failures: u64,
	pub denied: u64,
	pub dropped: u64,
}

impl Counters {
	fn of(key: &Key, rt: &Runtime) -> Counters {
		let s = &rt.stats;
		Counters {
			protocol: key.protocol.to_string(),
			listen_addr: key.listen.ip().to_string(),
			listen_port: key.listen.port(),
			total: s.total.load(Ordering::Relaxed),
			rx_bytes: s.rx_bytes.load(Ordering::Relaxed),
			tx_bytes: s.tx_bytes.load(Ordering::Relaxed),
			tls_failures: s.tls_failures.load(Ordering::Relaxed),
			denied: s.denied.load(Ordering::Relaxed),
			dropped: s.dropped.load(Ordering::Relaxed),
		}
	}

	fn key(&self) -> Option<Key> {
		Some(Key {
			protocol: self.protocol.parse().ok()?,
			listen: crate::core::rule::parse_listen(&self.listen_addr, self.listen_port).ok()?,
		})
	}

	/// `self - before`, never below zero.
	fn since(&self, before: &Counters) -> Counters {
		Counters {
			total: self.total.saturating_sub(before.total),
			rx_bytes: self.rx_bytes.saturating_sub(before.rx_bytes),
			tx_bytes: self.tx_bytes.saturating_sub(before.tx_bytes),
			tls_failures: self.tls_failures.saturating_sub(before.tls_failures),
			denied: self.denied.saturating_sub(before.denied),
			dropped: self.dropped.saturating_sub(before.dropped),
			..self.clone()
		}
	}

	fn add_to(&self, rt: &Runtime) {
		let s = &rt.stats;
		s.total.fetch_add(self.total, Ordering::Relaxed);
		s.rx_bytes.fetch_add(self.rx_bytes, Ordering::Relaxed);
		s.tx_bytes.fetch_add(self.tx_bytes, Ordering::Relaxed);
		s.tls_failures.fetch_add(self.tls_failures, Ordering::Relaxed);
		s.denied.fetch_add(self.denied, Ordering::Relaxed);
		s.dropped.fetch_add(self.dropped, Ordering::Relaxed);
	}
}

/// What the old process hands over besides the sockets.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
	/// The old process's version.
	pub version: String,
	/// `rproxy_process_start_time_seconds` of the first process, as text (a
	/// float through JSON can lose its last digit).
	pub process_start_time: String,
	/// Rules that are not from the settings file, as `GET /rules` shows them.
	pub rules: Vec<serde_json::Value>,
	/// Every rule's counters.
	pub counters: Vec<Counters>,
	/// Rule sets (#28) with their rules, applied again as they were.
	#[serde(default)]
	pub rulesets: Vec<SetSnapshot>,
}

/// A rule set (`PUT /rulesets/{name}`, #28) as handed over.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SetSnapshot {
	pub name: String,
	pub generation: u64,
	pub updated_by: String,
	pub rules: Vec<serde_json::Value>,
}

/// A rule as `GET /rules` shows it, as a body that creates it again.
fn request_value(v: &crate::core::rule::RuleView) -> Option<serde_json::Value> {
	let mut v = serde_json::to_value(v).ok()?;
	// with `targets`, remote_addr / remote_port only repeat the first one
	if v["targets"].as_array().is_some_and(|t| !t.is_empty()) {
		v["remote_addr"] = "".into();
		v["remote_port"] = 0.into();
	}
	Some(v)
}

#[derive(Serialize, Deserialize)]
struct Hello {
	version: String,
	pid: u32,
}

/// Whether `version` has this build's major.minor.
pub fn same_minor(version: &str) -> bool {
	let mut it = version.trim().trim_start_matches('v').split('.').map(|p| p.parse::<u64>().ok());
	match (it.next().flatten(), it.next().flatten()) {
		(Some(a), Some(b)) => (a, b) == super::own_minor(),
		_ => false,
	}
}

/// The binary on disk: where `/proc/self/exe` pointed (a package upgrade
/// replaced the file, so the link reads `... (deleted)`).
pub fn binary_on_disk() -> std::io::Result<PathBuf> {
	let exe = std::env::current_exe()?;
	let text = exe.to_string_lossy();
	Ok(match text.strip_suffix(" (deleted)") {
		Some(path) => PathBuf::from(path),
		None => exe,
	})
}

/// The settings of a live upgrade.
#[derive(Clone, Debug)]
pub struct Config {
	pub socket: PathBuf,
	pub timeout: Duration,
	pub drain: Duration,
}

/// How handoffs ended (`rproxy_handoffs_total{outcome}`).
#[derive(Default)]
pub struct Outcomes {
	pub done: AtomicU64,
	pub failed: AtomicU64,
	pub refused: AtomicU64,
}

pub static OUTCOMES: Outcomes = Outcomes { done: AtomicU64::new(0), failed: AtomicU64::new(0), refused: AtomicU64::new(0) };

/// A handoff in progress or done (mutating API requests wait: `guard`).
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// The old process is draining after a handoff (`/readyz`: `draining`).
static DRAINING: AtomicBool = AtomicBool::new(false);

pub fn active() -> bool {
	ACTIVE.load(Ordering::Relaxed)
}

pub fn draining() -> bool {
	DRAINING.load(Ordering::Relaxed)
}

/// The new process took over; the old one drains with this.
pub struct HandedOff {
	channel: Channel,
	pub pid: u32,
}

/// Why a handoff did not happen.
enum Failure {
	Refused(String),
	Failed(String),
}

impl From<std::io::Error> for Failure {
	fn from(e: std::io::Error) -> Self {
		Failure::Failed(e.to_string())
	}
}

impl From<serde_json::Error> for Failure {
	fn from(e: serde_json::Error) -> Self {
		Failure::Failed(e.to_string())
	}
}

impl From<String> for Failure {
	fn from(e: String) -> Self {
		Failure::Failed(e)
	}
}

/// Called with the binary and the error when a handoff to a binary other than
/// the one on disk failed.
pub type OnFailure = Box<dyn Fn(&Path, &str) + Send + Sync>;

/// The old process's side: starts handoffs (SIGUSR2, `POST /admin/upgrade`,
/// the self-update) one at a time.
pub struct Upgrader {
	cfg: Config,
	registry: Arc<Registry>,
	handed: Mutex<Option<HandedOff>>,
	wake: Notify,
	/// The self-update marks a release that failed as bad.
	on_failure: Mutex<Option<OnFailure>>,
}

impl Upgrader {
	pub fn new(cfg: Config, registry: Arc<Registry>) -> Arc<Upgrader> {
		Arc::new(Upgrader { cfg, registry, handed: Mutex::default(), wake: Notify::new(), on_failure: Mutex::default() })
	}

	pub fn config(&self) -> &Config {
		&self.cfg
	}

	pub fn set_on_failure(&self, f: OnFailure) {
		*self.on_failure.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
	}

	/// Starts a handoff to `exe` (default: the binary on disk) in the background.
	/// Err when one is already running.
	pub fn start(self: &Arc<Self>, exe: Option<PathBuf>, reason: &'static str) -> Result<(), String> {
		if ACTIVE.swap(true, Ordering::AcqRel) {
			return Err("a live upgrade is already in progress".into());
		}
		let me = self.clone();
		tokio::spawn(async move { me.run(exe, reason).await });
		Ok(())
	}

	async fn run(self: Arc<Self>, exe: Option<PathBuf>, reason: &'static str) {
		let explicit = exe.is_some();
		let exe = match exe.map(Ok).unwrap_or_else(binary_on_disk) {
			Ok(exe) => exe,
			Err(e) => {
				self.failed(None, format!("cannot find the binary: {e}"));
				return;
			}
		};
		info!(event = "handoff.start", exe = %exe.display(), reason, socket = %self.cfg.socket.display());
		let state = snapshot(&self.registry).await;
		let cfg = self.cfg.clone();
		let exe2 = exe.clone();
		let result = tokio::task::spawn_blocking(move || hand_over(&cfg, &exe2, &state))
			.await
			.unwrap_or_else(|e| Err(Failure::Failed(format!("handoff task: {e}"))));
		match result {
			Ok(handed) => {
				info!(event = "handoff.ready", pid = handed.pid, exe = %exe.display());
				// systemd (Type=notify, NotifyAccess=all) and `rproxy-api launch` follow the new process
				super::notify::notify(&format!("MAINPID={}", handed.pid));
				*self.handed.lock().unwrap_or_else(|e| e.into_inner()) = Some(handed);
				self.wake.notify_one();
			}
			Err(Failure::Refused(why)) => {
				OUTCOMES.refused.fetch_add(1, Ordering::Relaxed);
				warn!(event = "handoff.refused", reason = "version", error = %why, "restart rproxy-api to change the minor version");
				ACTIVE.store(false, Ordering::Release);
			}
			Err(Failure::Failed(why)) => self.failed(explicit.then_some(exe.as_path()), why),
		}
	}

	fn failed(&self, exe: Option<&Path>, why: String) {
		OUTCOMES.failed.fetch_add(1, Ordering::Relaxed);
		error!(event = "handoff.failed", error = %why, "the current process keeps running");
		if let (Some(exe), Some(f)) = (exe, self.on_failure.lock().unwrap_or_else(|e| e.into_inner()).as_ref()) {
			f(exe, &why);
		}
		ACTIVE.store(false, Ordering::Release);
	}

	/// Waits until a handoff has succeeded.
	pub async fn handed_off(&self) -> HandedOff {
		loop {
			if let Some(h) = self.handed.lock().unwrap_or_else(|e| e.into_inner()).take() {
				return h;
			}
			self.wake.notified().await;
		}
	}

	/// After the drain: the final counters to the new process, then done.
	pub async fn finish(&self, handed: HandedOff, runtimes: Vec<(Key, Arc<Runtime>)>) {
		let counters: Vec<Counters> = runtimes.iter().map(|(k, rt)| Counters::of(k, rt)).collect();
		let pid = handed.pid;
		let sent = tokio::task::spawn_blocking(move || {
			let body = serde_json::to_vec(&counters).unwrap_or_default();
			handed.channel.send_chunked(FINAL, FINAL_END, &body)
		})
		.await;
		if let Ok(Err(e)) = sent {
			warn!(event = "handoff.counters", error = %e, "the final counters did not reach the new process");
		}
		OUTCOMES.done.fetch_add(1, Ordering::Relaxed);
		info!(event = "handoff.done", pid);
	}
}

/// Marks this process as draining (after `handed_off`).
pub fn set_draining() {
	DRAINING.store(true, Ordering::Release);
}

/// The rules made through the API (and from the database) and the counters.
async fn snapshot(registry: &Registry) -> State {
	// the rules of rule sets go with their set
	let rules = registry
		.list()
		.await
		.iter()
		.filter(|v| v.origin != Origin::Static && v.ruleset.is_none())
		.filter_map(request_value)
		.collect();
	let mut rulesets = vec![];
	for summary in registry.list_rulesets().await {
		if let Ok(set) = registry.get_ruleset(&summary.name).await {
			rulesets.push(SetSnapshot {
				name: set.name,
				generation: set.generation,
				updated_by: set.updated_by,
				rules: set.rules.iter().filter_map(request_value).collect(),
			});
		}
	}
	let counters = registry.runtimes().await.iter().map(|(k, rt)| Counters::of(k, rt)).collect();
	State { version: env!("CARGO_PKG_VERSION").into(), process_start_time: super::process_start_time().to_string(), rules, counters, rulesets }
}

/// Every listening socket of this process, duplicated (so a socket closed
/// meanwhile cannot turn into another descriptor), except `skip`.
fn listening_sockets(skip: &[i32]) -> Vec<std::os::fd::OwnedFd> {
	use std::os::fd::{FromRawFd, OwnedFd};
	let Ok(dir) = std::fs::read_dir("/proc/self/fd") else { return vec![] };
	let mut out = vec![];
	for entry in dir.flatten() {
		let Some(fd) = entry.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
		if skip.contains(&fd) || super::inherit::classify(fd).is_none() {
			continue;
		}
		// SAFETY: F_DUPFD_CLOEXEC makes a new descriptor we own (or fails if fd is gone)
		let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
		if dup >= 0 && super::inherit::classify(dup).is_some() {
			out.push(unsafe { OwnedFd::from_raw_fd(dup) });
		} else if dup >= 0 {
			// SAFETY: closing the duplicate we just made
			unsafe { libc::close(dup) };
		}
	}
	out
}

/// The old process's side, blocking.
fn hand_over(cfg: &Config, exe: &Path, state: &State) -> Result<HandedOff, Failure> {
	use std::os::fd::AsRawFd;
	let listener = Listener::bind(&cfg.socket).map_err(|e| format!("handoff socket {}: {e}", cfg.socket.display()))?;
	let deadline = Instant::now() + cfg.timeout;
	let left = || deadline.saturating_duration_since(Instant::now());
	let mut child = Command::new(exe)
		.args(std::env::args_os().skip(1))
		.env(ENV_FROM, &cfg.socket)
		.stdin(Stdio::null())
		.spawn()
		.map_err(|e| format!("starting {}: {e}", exe.display()))?;
	let child_pid = child.id();
	let result = (|| -> Result<HandedOff, Failure> {
		// only the child we started may take the sockets
		let channel = loop {
			let (ch, pid) = listener.accept(left())?;
			if pid as u32 == child_pid {
				break ch;
			}
			warn!(event = "handoff.refused", reason = "peer", pid, "a process other than the new rproxy-api connected; ignored");
		};
		let (tag, data, _) = channel.recv(left())?;
		if tag != HELLO {
			return Err(Failure::Failed("the new process did not introduce itself".into()));
		}
		let hello: Hello = serde_json::from_slice(&data)?;
		if !same_minor(&hello.version) {
			let why = format!("the new binary is {} and this is {}; a live upgrade stays within one minor", hello.version, env!("CARGO_PKG_VERSION"));
			let _ = channel.send(REFUSE, why.as_bytes(), &[]);
			return Err(Failure::Refused(why));
		}
		let sockets = listening_sockets(&[listener.raw_fd(), channel.raw_fd()]);
		let raw: Vec<i32> = sockets.iter().map(|s| s.as_raw_fd()).collect();
		for batch in raw.chunks(MAX_FDS) {
			channel.send(FDS, b"", batch)?;
		}
		drop(sockets);
		let body = serde_json::to_vec(state)?;
		channel.send_chunked(STATE, STATE_END, &body)?;
		info!(event = "handoff.sent", sockets = raw.len(), rules = state.rules.len(), pid = child_pid);
		match channel.recv(left()) {
			Ok((READY, _, _)) => Ok(HandedOff { channel, pid: child_pid }),
			Ok((FAILED, why, _)) => Err(Failure::Failed(format!("the new process failed: {}", String::from_utf8_lossy(&why)))),
			Ok((tag, _, _)) => Err(Failure::Failed(format!("unexpected message {:?}", tag as char))),
			Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
				Err(Failure::Failed(format!("the new process was not ready within {}s", cfg.timeout.as_secs())))
			}
			Err(e) => Err(Failure::Failed(format!("the new process stopped before it was ready: {e}"))),
		}
	})();
	drop(listener);
	let _ = std::fs::remove_file(&cfg.socket);
	if result.is_err() {
		let _ = child.kill();
		let _ = child.wait();
	}
	result
}

/// The new process's side: what came from the old process.
pub struct Received {
	channel: Channel,
	pub fds: Vec<std::os::fd::OwnedFd>,
	pub state: State,
}

/// Connects to the old process and takes its sockets and state (blocking; at
/// the very start, before anything listens).
pub fn receive(socket: &Path, timeout: Duration) -> Result<Received, String> {
	let channel = Channel::connect(socket).map_err(|e| format!("handoff socket: {e}"))?;
	let hello = serde_json::to_vec(&Hello { version: env!("CARGO_PKG_VERSION").into(), pid: std::process::id() }).unwrap_or_default();
	channel.send(HELLO, &hello, &[]).map_err(|e| format!("handoff: {e}"))?;
	let mut fds = vec![];
	let mut body = vec![];
	loop {
		let (tag, data, got) = channel.recv(timeout).map_err(|e| format!("handoff: {e}"))?;
		match tag {
			REFUSE => return Err(format!("handoff refused: {}", String::from_utf8_lossy(&data))),
			FDS => fds.extend(got),
			STATE => body.extend(data),
			STATE_END => break,
			other => return Err(format!("handoff: unexpected message {:?}", other as char)),
		}
	}
	let state: State = serde_json::from_slice(&body).map_err(|e| format!("handoff state: {e}"))?;
	Ok(Received { channel, fds, state })
}

/// The new process after its startup: rules, counters, ready.
pub struct Adopted {
	channel: Channel,
	snapshot: Vec<Counters>,
}

impl Received {
	/// The rules made through the API, to be started like restored ones.
	pub fn rules(&self) -> Vec<RuleRequest> {
		self.state
			.rules
			.iter()
			.filter_map(|v| match serde_json::from_value::<RuleRequest>(v.clone()) {
				Ok(r) => Some(r),
				Err(e) => {
					warn!(event = "handoff.rule", error = %e, rule = %v, "a rule from the old process could not be read; dropped");
					None
				}
			})
			.collect()
	}

	/// Applies the rule sets of the old process again (#28), as they were.
	pub async fn restore_rulesets(&self, registry: &Arc<Registry>) {
		for set in &self.state.rulesets {
			let rules: Result<Vec<RuleRequest>, _> = set.rules.iter().map(|v| serde_json::from_value(v.clone())).collect();
			let rules = match rules {
				Ok(r) => r,
				Err(e) => {
					warn!(event = "handoff.ruleset", ruleset = %set.name, error = %e, "a rule set from the old process could not be read; dropped");
					continue;
				}
			};
			let req = crate::core::ruleset::RulesetRequest { generation: set.generation, rules };
			let opts = crate::core::ruleset::PutOptions { if_match: None, dry_run: false, by: &set.updated_by, may_use_ports: &|_, _| true };
			if let Err(e) = registry.put_ruleset(&set.name, req, opts).await {
				warn!(event = "handoff.ruleset", ruleset = %set.name, error = %e.error.message, "a rule set from the old process could not be applied");
			}
		}
	}

	/// Adds the old counters to the rules now running and tells the old process
	/// this one is ready.
	pub async fn ready(self, registry: &Registry) -> Result<Adopted, String> {
		add_counters(registry, &self.state.counters, |c| c.clone()).await;
		let channel = self.channel;
		let channel = tokio::task::spawn_blocking(move || channel.send(READY, b"", &[]).map(|_| channel))
			.await
			.map_err(|e| e.to_string())?
			.map_err(|e| format!("handoff: {e}"))?;
		Ok(Adopted { channel, snapshot: self.state.counters })
	}

	/// The sockets, for `inherit::adopt`.
	pub fn take_fds(&mut self) -> Vec<std::os::fd::OwnedFd> {
		std::mem::take(&mut self.fds)
	}
}

async fn add_counters(registry: &Registry, counters: &[Counters], f: impl Fn(&Counters) -> Counters) {
	let runtimes = registry.runtimes().await;
	for c in counters {
		let Some(key) = c.key() else { continue };
		if let Some((_, rt)) = runtimes.iter().find(|(k, _)| *k == key) {
			f(c).add_to(rt);
		}
	}
}

impl Adopted {
	/// Waits for the old process's final counters (it sends them after its
	/// drain) and adds what it counted after the snapshot.
	pub async fn follow(self, registry: Arc<Registry>) {
		let channel = self.channel;
		let finals = tokio::task::spawn_blocking(move || -> Option<Vec<Counters>> {
			let mut body = vec![];
			loop {
				// the old process drains for up to --handoff-drain (and is killed after)
				match channel.recv(Duration::from_secs(25 * 3600)) {
					Ok((FINAL, data, _)) => body.extend(data),
					Ok((FINAL_END, _, _)) => return serde_json::from_slice(&body).ok(),
					_ => return None,
				}
			}
		})
		.await
		.ok()
		.flatten();
		let Some(finals) = finals else {
			info!(event = "handoff.counters", "the old process ended without its final counters");
			return;
		};
		let before = self.snapshot;
		add_counters(&registry, &finals, |f| match before.iter().find(|b| b.key() == f.key()) {
			Some(b) => f.since(b),
			None => f.clone(),
		})
		.await;
		info!(event = "handoff.counters", rules = finals.len(), "counted the old process's last connections");
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn versions_within_the_minor() {
		let (a, b) = super::super::own_minor();
		assert!(same_minor(&format!("{a}.{b}.99")));
		assert!(same_minor(&format!("v{a}.{b}.0")));
		assert!(!same_minor(&format!("{a}.{}.0", b + 1)));
		assert!(!same_minor(&format!("{}.{b}.0", a + 1)));
		assert!(!same_minor("garbage"));
	}

	#[test]
	fn counters_add_what_came_after_the_snapshot() {
		let before = Counters { protocol: "tcp".into(), listen_addr: "127.0.0.1".into(), listen_port: 80, total: 5, rx_bytes: 100, ..Default::default() };
		let after = Counters { total: 7, rx_bytes: 90, tx_bytes: 3, ..before.clone() };
		let d = after.since(&before);
		assert_eq!((d.total, d.rx_bytes, d.tx_bytes), (2, 0, 3));
		assert_eq!(before.key().unwrap().to_string(), "tcp/127.0.0.1:80");
	}
}
