//! The single owner of every running listener.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use socket2::{Domain, Socket, Type};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

use crate::error::ApiError;
use crate::proxy::{Runtime, Stats};
use crate::resolve::{self, Lookup};
use crate::rule::{
	validate_remote, validate_udp_idle, Key, Protocol, RuleRequest, RuleSpec, RuleView, State, UpdateRequest,
};
use crate::{tcp, udp};

pub struct Config {
	pub dns_interval: Duration,
	pub lookup: Lookup,
	/// Whether `source_ip: transparent` may be used.
	pub transparent: bool,
}

struct Running {
	generation: u64,
	spec: RuleSpec,
	rt: Arc<Runtime>,
	target_tx: Arc<watch::Sender<Vec<SocketAddr>>>,
	idle_tx: watch::Sender<Duration>,
	resolver: Option<(CancellationToken, JoinHandle<()>)>,
	supervisor: JoinHandle<()>,
}

impl Running {
	fn stop_resolver(&mut self) -> Option<JoinHandle<()>> {
		self.resolver.take().map(|(cancel, task)| {
			cancel.cancel();
			task
		})
	}
}

struct Failed {
	generation: u64,
	spec: RuleSpec,
	error: String,
	retry: Option<JoinHandle<()>>,
}

enum Entry {
	Running(Running),
	Failed(Failed),
}

impl Entry {
	fn view(&self) -> RuleView {
		match self {
			Entry::Running(r) => RuleView::new(
				&r.spec,
				State::Running,
				None,
				&r.rt.target.borrow(),
				r.rt.stats.active.load(Ordering::Relaxed),
			),
			Entry::Failed(f) => RuleView::new(&f.spec, State::Failed, Some(f.error.clone()), &[], 0),
		}
	}
}

pub struct Registry {
	cfg: Config,
	rules: Mutex<HashMap<Key, Entry>>,
	next_generation: AtomicU64,
}

fn bind_error(key: &Key, e: std::io::Error) -> ApiError {
	ApiError::bind_failed(format!("{}: {e}", key.listen))
}

fn bind_tcp(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
	let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
	// lets a stopped rule's port be reused while old connections sit in TIME_WAIT
	sock.set_reuse_address(true)?;
	sock.set_nonblocking(true)?;
	sock.bind(&addr.into())?;
	sock.listen(1024)?;
	tokio::net::TcpListener::from_std(sock.into())
}

fn bind_udp(addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
	let sock = std::net::UdpSocket::bind(addr)?;
	sock.set_nonblocking(true)?;
	tokio::net::UdpSocket::from_std(sock)
}

fn panic_message(e: tokio::task::JoinError) -> String {
	if !e.is_panic() {
		return e.to_string();
	}
	let payload = e.into_panic();
	payload
		.downcast_ref::<&str>()
		.map(|s| s.to_string())
		.or_else(|| payload.downcast_ref::<String>().cloned())
		.unwrap_or_else(|| "unknown panic".into())
}

impl Registry {
	pub fn new(cfg: Config) -> Arc<Self> {
		Arc::new(Registry { cfg, rules: Mutex::default(), next_generation: AtomicU64::new(1) })
	}

	pub fn transparent_available(&self) -> bool {
		self.cfg.transparent
	}

	fn generation(&self) -> u64 {
		self.next_generation.fetch_add(1, Ordering::Relaxed)
	}

	pub async fn list(&self) -> Vec<RuleView> {
		let rules = self.rules.lock().await;
		let mut keys: Vec<&Key> = rules.keys().collect();
		keys.sort_by_key(|k| (k.protocol == Protocol::Udp, k.listen));
		keys.into_iter().map(|k| rules[k].view()).collect()
	}

	pub async fn get(&self, key: &Key) -> Result<RuleView, ApiError> {
		self.rules.lock().await.get(key).map(Entry::view).ok_or_else(|| ApiError::not_found(key.to_string()))
	}

	fn spawn_resolver(
		&self,
		spec: &RuleSpec,
		tx: &Arc<watch::Sender<Vec<SocketAddr>>>,
	) -> Option<(CancellationToken, JoinHandle<()>)> {
		if resolve::is_ip_literal(&spec.remote_host) {
			return None;
		}
		let cancel = CancellationToken::new();
		let task = resolve::spawn_refresh(
			spec.key,
			spec.remote(),
			self.cfg.lookup.clone(),
			self.cfg.dns_interval,
			tx.clone(),
			cancel.clone(),
		);
		Some((cancel, task))
	}

	/// Binds the listener and starts serving. Called with the rules lock held.
	fn start(self: &Arc<Self>, spec: RuleSpec, addrs: Vec<SocketAddr>) -> Result<Running, ApiError> {
		let key = spec.key;
		let (target_tx, target_rx) = watch::channel(addrs);
		let target_tx = Arc::new(target_tx);
		let (idle_tx, idle_rx) = watch::channel(spec.udp_idle);
		let kill = CancellationToken::new();
		let rt = Arc::new(Runtime {
			key,
			source_ip: spec.source_ip,
			target: target_rx,
			udp_idle: idle_rx,
			stats: Stats::default(),
			stop: kill.child_token(),
			kill,
			tracker: TaskTracker::new(),
		});

		let serve = match key.protocol {
			Protocol::Tcp => {
				let listener = bind_tcp(key.listen).map_err(|e| bind_error(&key, e))?;
				tokio::spawn(tcp::serve(listener, rt.clone()))
			}
			Protocol::Udp => {
				let socket = bind_udp(key.listen).map_err(|e| bind_error(&key, e))?;
				tokio::spawn(udp::serve(socket, rt.clone()))
			}
		};

		let generation = self.generation();
		let supervisor = tokio::spawn(supervise(Arc::downgrade(self), key, generation, rt.clone(), serve));
		let resolver = self.spawn_resolver(&spec, &target_tx);
		Ok(Running { generation, spec, rt, target_tx, idle_tx, resolver, supervisor })
	}

	async fn create_spec(self: &Arc<Self>, spec: RuleSpec) -> Result<RuleView, ApiError> {
		let addrs = resolve::resolve(&self.cfg.lookup, &spec.remote()).await?;
		let mut rules = self.rules.lock().await;
		if rules.contains_key(&spec.key) {
			return Err(ApiError::already_exists(spec.key.to_string()));
		}
		let key = spec.key;
		let entry = Entry::Running(self.start(spec, addrs)?);
		let view = entry.view();
		rules.insert(key, entry);
		info!(event = "rule.create", rule = %key, target = %format!("{}:{}", view.remote_addr, view.remote_port),
			source_ip = view.source_ip, resolved = ?view.resolved);
		Ok(view)
	}

	pub async fn create(self: &Arc<Self>, req: RuleRequest) -> Result<RuleView, ApiError> {
		let spec = req.validate(self.cfg.transparent)?;
		self.create_spec(spec).await
	}

	pub async fn update(self: &Arc<Self>, key: &Key, req: UpdateRequest) -> Result<RuleView, ApiError> {
		let remote_host = validate_remote(&req.remote_addr, req.remote_port)?;
		let udp_idle = match req.udp_idle_secs {
			Some(secs) => Some(validate_udp_idle(Some(secs))?),
			None => None,
		};

		let mut spec = {
			let rules = self.rules.lock().await;
			match rules.get(key) {
				Some(Entry::Running(r)) => r.spec.clone(),
				Some(Entry::Failed(f)) => f.spec.clone(),
				None => return Err(ApiError::not_found(key.to_string())),
			}
		};
		if req.source_ip.is_some_and(|s| s != spec.source_ip) {
			return Err(ApiError::unsupported("source_ip cannot be changed; delete and re-create the rule"));
		}
		spec.remote_host = remote_host;
		spec.remote_port = req.remote_port;
		if let Some(idle) = udp_idle {
			spec.udp_idle = idle;
		}
		let addrs = resolve::resolve(&self.cfg.lookup, &spec.remote()).await?;

		let mut rules = self.rules.lock().await;
		let entry = rules.get_mut(key).ok_or_else(|| ApiError::not_found(key.to_string()))?;
		match entry {
			Entry::Running(r) => {
				let host_changed = r.spec.remote_host != spec.remote_host || r.spec.remote_port != spec.remote_port;
				r.target_tx.send_replace(addrs);
				r.idle_tx.send_replace(spec.udp_idle);
				if host_changed {
					r.stop_resolver();
					r.resolver = self.spawn_resolver(&spec, &r.target_tx);
				}
				r.spec = spec;
			}
			Entry::Failed(f) => {
				if let Some(retry) = f.retry.take() {
					retry.abort();
				}
				f.spec = spec.clone();
				match self.start(spec, addrs) {
					Ok(running) => *entry = Entry::Running(running),
					Err(e) => {
						f.error = e.message.clone();
						return Err(e);
					}
				}
			}
		}
		let view = entry.view();
		info!(event = "rule.update", rule = %key, target = %format!("{}:{}", view.remote_addr, view.remote_port),
			udp_idle_secs = view.udp_idle_secs, resolved = ?view.resolved);
		Ok(view)
	}

	/// Stops a rule. Returns once the listener is closed and every connection has ended.
	pub async fn delete(&self, key: &Key, drain: Option<Duration>) -> Result<(), ApiError> {
		let entry = self.rules.lock().await.remove(key).ok_or_else(|| ApiError::not_found(key.to_string()))?;
		match entry {
			Entry::Failed(f) => {
				if let Some(retry) = f.retry {
					retry.abort();
				}
			}
			Entry::Running(mut r) => {
				r.rt.stop.cancel();
				r.rt.tracker.close();
				if let Some(drain) = drain {
					let _ = tokio::time::timeout(drain, r.rt.tracker.wait()).await;
				}
				r.rt.kill.cancel();
				r.rt.tracker.wait().await;
				if let Some(task) = r.stop_resolver() {
					let _ = task.await;
				}
				let _ = r.supervisor.await;
			}
		}
		info!(event = "rule.delete", rule = %key, drain_secs = drain.map(|d| d.as_secs()));
		Ok(())
	}

	/// Starts rules loaded at boot. Rules whose target cannot be resolved yet are
	/// kept as failed and retried until resolution succeeds.
	pub async fn restore(self: &Arc<Self>, reqs: Vec<RuleRequest>) {
		let (mut started, mut failed) = (0, 0);
		for req in reqs {
			let spec = match req.clone().validate(self.cfg.transparent) {
				Ok(spec) => spec,
				Err(e) => {
					failed += 1;
					error!(event = "rule.failed", rule = %format!("{}/{}:{}", req.protocol, req.listen_addr, req.listen_port),
						error = %e.message, phase = "restore");
					continue;
				}
			};
			let key = spec.key;
			match self.create_spec(spec.clone()).await {
				Ok(_) => started += 1,
				Err(e) if e.code == "already_exists" => {
					warn!(event = "rule.duplicate", rule = %key, phase = "restore");
				}
				Err(e) => {
					failed += 1;
					error!(event = "rule.failed", rule = %key, error = %e.message, phase = "restore");
					self.insert_failed(spec, e.message, e.code == "resolve_failed").await;
				}
			}
		}
		info!(event = "restore.done", started, failed);
	}

	async fn insert_failed(self: &Arc<Self>, spec: RuleSpec, error: String, retry: bool) {
		let generation = self.generation();
		let key = spec.key;
		let retry = retry.then(|| tokio::spawn(retry_start(Arc::downgrade(self), spec.clone(), generation)));
		self.rules.lock().await.insert(key, Entry::Failed(Failed { generation, spec, error, retry }));
	}

	pub async fn shutdown(&self) {
		let keys: Vec<Key> = self.rules.lock().await.keys().copied().collect();
		for key in keys {
			let _ = self.delete(&key, None).await;
		}
	}

	pub async fn metrics(&self) -> String {
		let rules = self.rules.lock().await;
		let mut out = String::new();
		let running = rules.values().filter(|e| matches!(e, Entry::Running(_))).count();
		let _ = writeln!(out, "# HELP rproxy_rules Number of rules by state.");
		let _ = writeln!(out, "# TYPE rproxy_rules gauge");
		let _ = writeln!(out, "rproxy_rules{{state=\"running\"}} {running}");
		let _ = writeln!(out, "rproxy_rules{{state=\"failed\"}} {}", rules.len() - running);

		let mut lines: [(&str, &str, &str, Vec<String>); 4] = [
			("rproxy_rule_up", "gauge", "1 if the rule is running.", vec![]),
			("rproxy_connections", "gauge", "Open TCP connections or UDP sessions.", vec![]),
			("rproxy_connections_total", "counter", "TCP connections or UDP sessions handled.", vec![]),
			("rproxy_bytes_total", "counter", "Bytes forwarded; rx is client to backend.", vec![]),
		];
		for (key, entry) in rules.iter() {
			let labels = format!("protocol=\"{}\",listen=\"{}\"", key.protocol, key.listen);
			match entry {
				Entry::Running(r) => {
					let s = &r.rt.stats;
					lines[0].3.push(format!("{{{labels}}} 1"));
					lines[1].3.push(format!("{{{labels}}} {}", s.active.load(Ordering::Relaxed)));
					lines[2].3.push(format!("{{{labels}}} {}", s.total.load(Ordering::Relaxed)));
					lines[3].3.push(format!("{{{labels},direction=\"rx\"}} {}", s.rx_bytes.load(Ordering::Relaxed)));
					lines[3].3.push(format!("{{{labels},direction=\"tx\"}} {}", s.tx_bytes.load(Ordering::Relaxed)));
				}
				Entry::Failed(_) => lines[0].3.push(format!("{{{labels}}} 0")),
			}
		}
		for (name, kind, help, samples) in lines.iter_mut() {
			samples.sort();
			let _ = writeln!(out, "# HELP {name} {help}");
			let _ = writeln!(out, "# TYPE {name} {kind}");
			for sample in samples.iter() {
				let _ = writeln!(out, "{name}{sample}");
			}
		}
		out
	}
}

/// Watches a listener task and marks the rule failed if it dies on its own.
async fn supervise(registry: Weak<Registry>, key: Key, generation: u64, rt: Arc<Runtime>, serve: JoinHandle<()>) {
	let outcome = serve.await;
	if rt.stop.is_cancelled() && outcome.is_ok() {
		return;
	}
	let error = match outcome {
		Ok(()) => "listener stopped unexpectedly".to_string(),
		Err(e) => format!("listener task failed: {}", panic_message(e)),
	};
	rt.kill.cancel();
	error!(event = "rule.failed", rule = %key, error = %error);

	let Some(registry) = registry.upgrade() else { return };
	let mut rules = registry.rules.lock().await;
	if let Some(Entry::Running(r)) = rules.get_mut(&key) {
		if r.generation == generation {
			r.stop_resolver();
			let spec = r.spec.clone();
			rules.insert(key, Entry::Failed(Failed { generation, spec, error, retry: None }));
		}
	}
}

async fn retry_start(registry: Weak<Registry>, spec: RuleSpec, generation: u64) {
	loop {
		let Some(interval) = registry.upgrade().map(|r| r.cfg.dns_interval) else { return };
		tokio::time::sleep(interval).await;
		let Some(registry) = registry.upgrade() else { return };
		let Ok(addrs) = resolve::resolve(&registry.cfg.lookup, &spec.remote()).await else { continue };

		let mut rules = registry.rules.lock().await;
		let current = matches!(rules.get(&spec.key), Some(Entry::Failed(f)) if f.generation == generation);
		if !current {
			return;
		}
		match registry.start(spec.clone(), addrs) {
			Ok(running) => {
				info!(event = "rule.create", rule = %spec.key, phase = "retry");
				rules.insert(spec.key, Entry::Running(running));
			}
			Err(e) => {
				error!(event = "rule.failed", rule = %spec.key, error = %e.message, phase = "retry");
				if let Some(Entry::Failed(f)) = rules.get_mut(&spec.key) {
					f.error = e.message;
					f.retry = None;
				}
			}
		}
		return;
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::rule::RuleRequest;

	fn registry() -> Arc<Registry> {
		Registry::new(Config {
			dns_interval: Duration::from_secs(30),
			lookup: resolve::system_lookup(),
			transparent: false,
		})
	}

	fn tcp_rule(port: u16) -> RuleRequest {
		serde_json::from_value(serde_json::json!({
			"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"remote_addr": "127.0.0.1", "remote_port": 9,
		}))
		.unwrap()
	}

	fn free_port() -> u16 {
		std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
	}

	#[tokio::test]
	async fn a_panicking_listener_marks_only_its_rule_failed() {
		let reg = registry();
		let (a, b) = (free_port(), free_port());
		reg.create(tcp_rule(a)).await.unwrap();
		reg.create(tcp_rule(b)).await.unwrap();
		let key_a = Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{a}").parse().unwrap() };

		let (generation, rt) = match reg.rules.lock().await.get(&key_a) {
			Some(Entry::Running(r)) => (r.generation, r.rt.clone()),
			_ => panic!("rule a should be running"),
		};
		let serve = tokio::spawn(async { panic!("boom") });
		supervise(Arc::downgrade(&reg), key_a, generation, rt.clone(), serve).await;

		let view = reg.get(&key_a).await.unwrap();
		assert_eq!(view.state, State::Failed);
		assert!(view.error.unwrap().contains("boom"));
		assert!(rt.kill.is_cancelled(), "connections of the failed rule are closed");

		let key_b = Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{b}").parse().unwrap() };
		assert_eq!(reg.get(&key_b).await.unwrap().state, State::Running, "the other rule keeps running");
		reg.shutdown().await;
	}

	#[tokio::test]
	async fn a_stale_supervisor_does_not_touch_a_recreated_rule() {
		let reg = registry();
		let port = free_port();
		reg.create(tcp_rule(port)).await.unwrap();
		let key = Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{port}").parse().unwrap() };
		let rt = match reg.rules.lock().await.get(&key) {
			Some(Entry::Running(r)) => r.rt.clone(),
			_ => unreachable!(),
		};

		// a supervisor from an older generation reports a failure
		supervise(Arc::downgrade(&reg), key, 0, rt, tokio::spawn(async { panic!("old") })).await;
		assert_eq!(reg.get(&key).await.unwrap().state, State::Running);
		reg.shutdown().await;
	}
}
