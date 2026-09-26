//! The single owner of every running listener.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use socket2::{Domain, Socket, Type};
use tokio::sync::{watch, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

use crate::error::ApiError;
use crate::proxy::{RouteTarget, Runtime, Stats};
use crate::resolve::{self, Lookup};
use crate::rule::{
	validate_target, validate_udp_idle, Caps, Key, Origin, Protocol, RuleRequest, RuleSpec, RuleStats, RuleView,
	State, UpdateRequest,
};
use crate::tlsconf::{self, Route, TlsMode, TlsRuntime};
use crate::{tcp, udp};

pub struct Config {
	pub dns_interval: Duration,
	pub lookup: Lookup,
	/// Whether `source_ip: transparent` may be used.
	pub transparent: bool,
	/// Whether it may be used with IPv6 clients (IPV6_TRANSPARENT).
	pub transparent_ipv6: bool,
	/// Largest port range one rule may open.
	pub max_range_ports: u16,
	/// Addresses rproxy itself listens on (the control API); rules may not take them.
	pub reserved: Vec<SocketAddr>,
	/// `global` settings of `http` rules (trusted proxies, access log).
	pub http: Arc<crate::http::access::HttpGlobal>,
}

type Resolver = (CancellationToken, JoinHandle<()>);

struct Running {
	generation: u64,
	started_at: u64,
	spec: RuleSpec,
	rt: Arc<Runtime>,
	target_tx: Arc<watch::Sender<Vec<SocketAddr>>>,
	idle_tx: watch::Sender<Duration>,
	resolver: Option<Resolver>,
	route_resolvers: Vec<Resolver>,
	supervisor: JoinHandle<()>,
}

impl Running {
	fn stop_resolver(&mut self) -> Option<JoinHandle<()>> {
		self.resolver.take().map(|(cancel, task)| {
			cancel.cancel();
			task
		})
	}

	fn stop_route_resolvers(&mut self) {
		for (cancel, _) in self.route_resolvers.drain(..) {
			cancel.cancel();
		}
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
	fn spec(&self) -> &RuleSpec {
		match self {
			Entry::Running(r) => &r.spec,
			Entry::Failed(f) => &f.spec,
		}
	}

	fn view(&self) -> RuleView {
		match self {
			Entry::Running(r) => {
				let s = &r.rt.stats;
				let mut view = RuleView::new(
					&r.spec,
					State::Running,
					None,
					&r.rt.target.borrow(),
					s.active.load(Ordering::Relaxed),
				);
				view.stats = RuleStats {
					total_connections: s.total.load(Ordering::Relaxed),
					rx_bytes: s.rx_bytes.load(Ordering::Relaxed),
					tx_bytes: s.tx_bytes.load(Ordering::Relaxed),
					tls_failures: s.tls_failures.load(Ordering::Relaxed),
					denied: s.denied.load(Ordering::Relaxed),
					http: r.spec.http.is_some().then(|| crate::http::access::HttpStatsView::from_stats(&r.rt.http_stats)),
				};
				view.started_at = Some(r.started_at);
				view
			}
			Entry::Failed(f) => RuleView::new(&f.spec, State::Failed, Some(f.error.clone()), &[], 0),
		}
	}
}

/// What a rule needs before it can listen: resolved targets and TLS settings.
struct Prepared {
	addrs: Vec<SocketAddr>,
	routes: Vec<(Route, Vec<SocketAddr>)>,
	tls: Arc<TlsRuntime>,
	http: Option<Arc<crate::http::server::Router>>,
}

/// What `Registry::reload_changed_tls` last saw of a rule's certificate files.
#[derive(Debug, Clone, Copy)]
pub struct FileState {
	loaded: u64,
	failed: Option<u64>,
}

pub struct Registry {
	cfg: Config,
	rules: Mutex<HashMap<Key, Entry>>,
	next_generation: AtomicU64,
}

fn bind_error(addr: SocketAddr, e: std::io::Error) -> ApiError {
	if e.kind() == std::io::ErrorKind::PermissionDenied && addr.port() < 1024 {
		return ApiError::bind_failed(format!(
			"{addr}: {e}; ports below 1024 need CAP_NET_BIND_SERVICE (setcap cap_net_bind_service=+ep on the binary, or AmbientCapabilities in systemd)"
		));
	}
	ApiError::bind_failed(format!("{addr}: {e}"))
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

/// Two rules clash when they share a protocol, ports and an address (or a wildcard).
fn overlaps(a: &RuleSpec, b: &RuleSpec) -> bool {
	let (ai, bi): (IpAddr, IpAddr) = (a.key.listen.ip(), b.key.listen.ip());
	let same_ip = ai == bi || ai.is_unspecified() || bi.is_unspecified();
	let (a0, b0) = (u32::from(a.key.listen.port()), u32::from(b.key.listen.port()));
	let (a1, b1) = (a0 + u32::from(a.port_count) - 1, b0 + u32::from(b.port_count) - 1);
	a.key.protocol == b.key.protocol && same_ip && a0 <= b1 && b0 <= a1
}

fn route_spec(route: &Route) -> String {
	match route.remote_addr.parse::<IpAddr>() {
		Ok(IpAddr::V6(ip)) => SocketAddr::new(IpAddr::V6(ip), route.remote_port).to_string(),
		_ => format!("{}:{}", route.remote_addr, route.remote_port),
	}
}

impl Registry {
	pub fn new(cfg: Config) -> Arc<Self> {
		Arc::new(Registry { cfg, rules: Mutex::default(), next_generation: AtomicU64::new(1) })
	}

	pub fn reserved(&self) -> &[SocketAddr] {
		&self.cfg.reserved
	}

	/// The control API's own address, if the rule would take it.
	fn reserved_clash(&self, spec: &RuleSpec) -> Option<SocketAddr> {
		if spec.key.protocol != Protocol::Tcp {
			return None;
		}
		let (ip, start) = (spec.key.listen.ip(), u32::from(spec.key.listen.port()));
		let end = start + u32::from(spec.port_count) - 1;
		self.cfg.reserved.iter().copied().find(|r| {
			let same_ip = r.ip() == ip || r.ip().is_unspecified() || ip.is_unspecified();
			same_ip && (start..=end).contains(&u32::from(r.port()))
		})
	}

	pub fn caps(&self) -> Caps {
		Caps {
			transparent: self.cfg.transparent,
			transparent_ipv6: self.cfg.transparent_ipv6,
			max_range_ports: self.cfg.max_range_ports,
			features: crate::rule::Features::CURRENT,
		}
	}

	/// Validates a rule loaded at startup (DB or static file). A rule that is
	/// well-formed but needs something this process lacks (transparent without
	/// CAP_NET_ADMIN, a v0.3 feature this build cannot run yet) comes back with
	/// the reason, to be registered as failed instead of being dropped or
	/// stopping the startup.
	fn validate_at_startup(&self, req: RuleRequest) -> Result<(RuleSpec, Option<String>), ApiError> {
		let caps = self.caps();
		match req.clone().validate(&caps) {
			Ok(spec) => Ok((spec, None)),
			Err(e) if e.code == "unsupported" => {
				let everything =
					Caps { transparent: true, transparent_ipv6: true, features: crate::rule::Features::ALL, ..caps };
				// still unsupported with everything available: a real mistake (e.g. proxy_v1 on udp)
				let spec = req.validate(&everything)?;
				Ok((spec, Some(e.message)))
			}
			Err(e) => Err(e),
		}
	}

	pub fn transparent_available(&self) -> bool {
		self.cfg.transparent
	}

	pub fn transparent_ipv6_available(&self) -> bool {
		self.cfg.transparent_ipv6
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
		key: Key,
		host: &str,
		target: String,
		tx: &Arc<watch::Sender<Vec<SocketAddr>>>,
	) -> Option<Resolver> {
		// http rules have no remote_addr; their backends are resolved per request
		if host.is_empty() || resolve::is_ip_literal(host) {
			return None;
		}
		let cancel = CancellationToken::new();
		let task = resolve::spawn_refresh(key, target, self.cfg.lookup.clone(), self.cfg.dns_interval, tx.clone(), cancel.clone());
		Some((cancel, task))
	}

	/// Resolves targets and reads certificates, without holding the rules lock.
	async fn prepare(&self, spec: &RuleSpec) -> Result<Prepared, ApiError> {
		let tls = Arc::new(TlsRuntime::build(spec.key.protocol, &spec.runtime_tls(), spec.starttls, spec.starttls_required)?);
		let http = match &spec.http {
			Some(h) => {
				crate::http::crowdsec::check_refs(h, self.cfg.http.crowdsec())?;
				Some(Arc::new(crate::http::server::Router::compile(h, &spec.tls.upstream, self.cfg.lookup.clone())?))
			}
			None => None,
		};
		let addrs = if http.is_some() { vec![] } else { resolve::resolve(&self.cfg.lookup, &spec.remote()).await? };
		let mut routes = vec![];
		for route in &spec.tls.routes {
			routes.push((route.clone(), resolve::resolve(&self.cfg.lookup, &route_spec(route)).await?));
		}
		Ok(Prepared { addrs, routes, tls, http })
	}

	fn install_routes(&self, key: Key, routes: Vec<(Route, Vec<SocketAddr>)>) -> (Arc<Vec<RouteTarget>>, Vec<Resolver>) {
		let mut targets = vec![];
		let mut resolvers = vec![];
		for (route, addrs) in routes {
			let (tx, rx) = watch::channel(addrs);
			// the resolver task keeps the sender; without one the last value stays readable
			resolvers.extend(self.spawn_resolver(key, &route.remote_addr, route_spec(&route), &Arc::new(tx)));
			targets.push(RouteTarget { pattern: route.server_name.clone(), host: route.remote_addr.clone(), target: rx });
		}
		(Arc::new(targets), resolvers)
	}

	/// Binds every port of the rule and starts serving. Called with the rules lock held.
	fn start(self: &Arc<Self>, spec: RuleSpec, prepared: Prepared) -> Result<Running, ApiError> {
		let key = spec.key;
		let (target_tx, target_rx) = watch::channel(prepared.addrs);
		let target_tx = Arc::new(target_tx);
		let (idle_tx, idle_rx) = watch::channel(spec.udp_idle);
		let (routes, route_resolvers) = self.install_routes(key, prepared.routes);
		let kill = CancellationToken::new();
		let rt = Arc::new(Runtime {
			key,
			source_ip: spec.source_ip,
			target: target_rx,
			remote_host: RwLock::new(spec.remote_host.clone()),
			routes: RwLock::new(routes),
			tls: RwLock::new(prepared.tls),
			allow_from: RwLock::new(Arc::new(spec.allow_from.clone())),
			http: RwLock::new(prepared.http),
			global: self.cfg.http.clone(),
			http_stats: Default::default(),
			udp_idle: idle_rx,
			stats: Stats::default(),
			stop: kill.child_token(),
			kill,
			tracker: TaskTracker::new(),
		});

		// bind everything first so a failure leaves nothing half-open
		let mut set = JoinSet::new();
		match key.protocol {
			Protocol::Tcp => {
				let mut listeners = vec![];
				for offset in 0..spec.port_count {
					let addr = crate::proxy::shifted(key.listen, offset);
					listeners.push(bind_tcp(addr).map_err(|e| bind_error(addr, e))?);
				}
				for (offset, l) in listeners.into_iter().enumerate() {
					set.spawn(tcp::serve(l, rt.clone(), offset as u16));
				}
			}
			Protocol::Udp => {
				let mut sockets = vec![];
				for offset in 0..spec.port_count {
					let addr = crate::proxy::shifted(key.listen, offset);
					sockets.push(bind_udp(addr).map_err(|e| bind_error(addr, e))?);
				}
				for (offset, s) in sockets.into_iter().enumerate() {
					set.spawn(udp::serve(s, rt.clone(), offset as u16));
				}
			}
		}
		let stop = rt.stop.clone();
		let serve = tokio::spawn(async move {
			while let Some(done) = set.join_next().await {
				match done {
					Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
					// one listener ending on its own fails the whole rule
					_ if !stop.is_cancelled() => return,
					_ => {}
				}
			}
		});

		let generation = self.generation();
		let supervisor = tokio::spawn(supervise(Arc::downgrade(self), key, generation, rt.clone(), serve));
		let resolver = self.spawn_resolver(key, &spec.remote_host, spec.remote(), &target_tx);
		let started_at = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		Ok(Running { generation, started_at, spec, rt, target_tx, idle_tx, resolver, route_resolvers, supervisor })
	}

	async fn create_spec(self: &Arc<Self>, spec: RuleSpec) -> Result<RuleView, ApiError> {
		if let Some(api) = self.reserved_clash(&spec) {
			return Err(ApiError::reserved(format!("{} would take rproxy's control API ({api})", spec.key)));
		}
		let prepared = self.prepare(&spec).await?;
		let mut rules = self.rules.lock().await;
		if rules.contains_key(&spec.key) {
			return Err(ApiError::already_exists(spec.key.to_string()));
		}
		if let Some((other, _)) = rules.iter().find(|(_, e)| overlaps(e.spec(), &spec)) {
			return Err(ApiError::already_exists(format!("{} overlaps with {other}", spec.key)));
		}
		let key = spec.key;
		let entry = Entry::Running(self.start(spec, prepared)?);
		let view = entry.view();
		rules.insert(key, entry);
		info!(event = "rule.create", rule = %key, target = %format!("{}:{}", view.remote_addr, view.remote_port),
			ports = view.listen_port_end.map(|e| e - view.listen_port + 1).unwrap_or(1),
			source_ip = view.source_ip, tls = ?view.tls.mode, starttls = view.starttls.map(|s| s.as_str()).unwrap_or(""),
			resolved = ?view.resolved);
		Ok(view)
	}

	/// The `global` settings of `http` rules.
	pub fn http_global(&self) -> Arc<crate::http::access::HttpGlobal> {
		self.cfg.http.clone()
	}

	pub async fn create(self: &Arc<Self>, req: RuleRequest) -> Result<RuleView, ApiError> {
		let spec = req.validate(&self.caps())?;
		self.create_spec(spec).await
	}

	pub async fn update(self: &Arc<Self>, key: &Key, req: UpdateRequest) -> Result<RuleView, ApiError> {
		let udp_idle = match req.udp_idle_secs {
			Some(secs) => Some(validate_udp_idle(Some(secs))?),
			None => None,
		};

		let mut spec = {
			let rules = self.rules.lock().await;
			rules.get(key).map(|e| e.spec().clone()).ok_or_else(|| ApiError::not_found(key.to_string()))?
		};
		if spec.origin == Origin::Static {
			return Err(ApiError::static_rule(format!("{key} is a static rule; edit the static rules file and restart rproxy")));
		}
		if let Some(list) = &req.allow_from {
			spec.allow_from = crate::cidr::parse_list(list)?;
		}
		if req.source_ip.is_some_and(|s| s != spec.source_ip) {
			return Err(ApiError::unsupported("source_ip cannot be changed; delete and re-create the rule"));
		}
		if let Some(end) = req.listen_port_end {
			if end != key.listen.port() + spec.port_count - 1 {
				return Err(ApiError::unsupported("the port range cannot be changed; delete and re-create the rule"));
			}
		}
		let remote_host = validate_target(&req.remote_addr, req.remote_port, req.http.is_some() || spec.http.is_some())?;
		if u32::from(req.remote_port) + u32::from(spec.port_count) - 1 > 65_535 {
			return Err(ApiError::invalid("remote_port + range length exceeds 65535"));
		}
		spec.remote_host = remote_host;
		spec.remote_port = req.remote_port;
		if let Some(idle) = udp_idle {
			spec.udp_idle = idle;
		}
		let tls_changed = req.tls.is_some();
		if let Some(tls) = req.tls {
			tlsconf::validate_range(key.protocol, &tls, req.starttls, spec.port_count)?;
			if req.starttls.is_none() && req.starttls_required == Some(false) {
				return Err(ApiError::invalid("starttls_required needs starttls"));
			}
			spec.tls = tls;
			spec.starttls = req.starttls;
			spec.starttls_required = req.starttls != Some(crate::tlsconf::StartTls::Smtp) || req.starttls_required.unwrap_or(true);
		}
		let http_changed = req.http.is_some();
		if let Some(http) = req.http {
			if spec.http.is_none() {
				return Err(ApiError::unsupported("a rule cannot be turned into an http rule; delete and re-create it"));
			}
			if key.protocol != crate::rule::Protocol::Tcp || spec.tls.mode == crate::tlsconf::TlsMode::Sni || spec.starttls.is_some() {
				return Err(ApiError::invalid("http needs protocol tcp with tls mode terminate (or no TLS) and no starttls"));
			}
			http.validate()?;
			spec.http = Some(http);
		}
		if spec.http.is_some() {
			crate::rule::check_http_tls(&spec.tls, spec.source_ip)?;
		}
		// whatever was replaced, the rule must stay within what this build can run
		self.caps().features.check(&spec.tls, spec.http.as_ref())?;
		let prepared = self.prepare(&spec).await?;

		let mut rules = self.rules.lock().await;
		let entry = rules.get_mut(key).ok_or_else(|| ApiError::not_found(key.to_string()))?;
		match entry {
			Entry::Running(r) => {
				let host_changed = r.spec.remote_host != spec.remote_host || r.spec.remote_port != spec.remote_port;
				r.target_tx.send_replace(prepared.addrs);
				r.idle_tx.send_replace(spec.udp_idle);
				*r.rt.remote_host.write().unwrap() = spec.remote_host.clone();
				*r.rt.allow_from.write().unwrap() = Arc::new(spec.allow_from.clone());
				if host_changed {
					r.stop_resolver();
					r.resolver = self.spawn_resolver(*key, &spec.remote_host, spec.remote(), &r.target_tx);
				}
				if http_changed {
					*r.rt.http.write().unwrap() = prepared.http;
				}
				if tls_changed {
					*r.rt.tls.write().unwrap() = prepared.tls;
					r.stop_route_resolvers();
					let (routes, resolvers) = self.install_routes(*key, prepared.routes);
					*r.rt.routes.write().unwrap() = routes;
					r.route_resolvers = resolvers;
				}
				r.spec = spec;
			}
			Entry::Failed(f) => {
				if let Some(retry) = f.retry.take() {
					retry.abort();
				}
				f.spec = spec.clone();
				match self.start(spec, prepared) {
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
			udp_idle_secs = view.udp_idle_secs, tls = ?view.tls.mode, resolved = ?view.resolved);
		Ok(view)
	}

	/// Re-reads certificate files for every rule that uses them (SIGHUP).
	/// A rule whose files are now broken keeps its current certificates.
	pub async fn reload_tls(&self) -> (usize, usize) {
		let rules = self.rules.lock().await;
		let (mut ok, mut failed) = (0, 0);
		for (key, entry) in rules.iter() {
			let Entry::Running(r) = entry else { continue };
			if r.spec.tls.mode != TlsMode::Terminate {
				continue;
			}
			match TlsRuntime::build(key.protocol, &r.spec.runtime_tls(), r.spec.starttls, r.spec.starttls_required) {
				Ok(tls) => {
					*r.rt.tls.write().unwrap() = Arc::new(tls);
					ok += 1;
				}
				Err(e) => {
					failed += 1;
					warn!(event = "reload.tls", rule = %key, error = %e.message, "keeping current certificates");
				}
			}
		}
		(ok, failed)
	}

	/// Re-reads the certificate files of rules whose files changed since the last
	/// call (renewed by certbot, cert-manager, ...). `seen` holds each rule's
	/// fingerprint between calls; a rule seen for the first time is only recorded.
	/// Files that do not load (a half-written renewal) keep the current
	/// certificates and are tried again on the next call.
	pub async fn reload_changed_tls(&self, seen: &mut HashMap<Key, FileState>) -> (usize, usize) {
		let rules = self.rules.lock().await;
		seen.retain(|k, _| matches!(rules.get(k), Some(Entry::Running(_))));
		let (mut ok, mut failed) = (0, 0);
		for (key, entry) in rules.iter() {
			let Entry::Running(r) = entry else { continue };
			let tls = r.spec.runtime_tls();
			let files = tls.files();
			if files.is_empty() {
				seen.remove(key);
				continue;
			}
			let now = tlsconf::fingerprint(files.iter().copied());
			let state = match seen.get_mut(key) {
				None => {
					seen.insert(*key, FileState { loaded: now, failed: None });
					continue;
				}
				Some(s) if s.loaded == now => continue,
				Some(s) => s,
			};
			match TlsRuntime::build(key.protocol, &tls, r.spec.starttls, r.spec.starttls_required) {
				Ok(built) => {
					*r.rt.tls.write().unwrap() = Arc::new(built);
					*state = FileState { loaded: now, failed: None };
					ok += 1;
					info!(event = "reload.tls", rule = %key, reason = "files changed");
				}
				Err(e) => {
					failed += 1;
					// once per version of the files, not on every check
					if state.failed != Some(now) {
						warn!(event = "reload.tls", rule = %key, error = %e.message, "keeping current certificates");
						state.failed = Some(now);
					}
				}
			}
		}
		(ok, failed)
	}

	/// Stops a rule. Returns once the listener is closed and every connection has ended.
	pub async fn delete(&self, key: &Key, drain: Option<Duration>) -> Result<(), ApiError> {
		let entry = {
			let mut rules = self.rules.lock().await;
			match rules.get(key) {
				None => return Err(ApiError::not_found(key.to_string())),
				Some(e) if e.spec().origin == Origin::Static => {
					return Err(ApiError::static_rule(format!("{key} is a static rule; edit the static rules file and restart rproxy")));
				}
				Some(_) => rules.remove(key).expect("checked above"),
			}
		};
		self.stop_entry(key, entry, drain).await;
		info!(event = "rule.delete", rule = %key, drain_secs = drain.map(|d| d.as_secs()));
		Ok(())
	}

	/// Stops a rule already taken out of the table.
	async fn stop_entry(&self, _key: &Key, entry: Entry, drain: Option<Duration>) {
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
				r.stop_route_resolvers();
				let _ = r.supervisor.await;
			}
		}
	}

	/// Starts rules loaded at boot. Rules whose target cannot be resolved yet are
	/// kept as failed and retried until resolution succeeds.
	pub async fn restore(self: &Arc<Self>, reqs: Vec<RuleRequest>) {
		let (mut started, mut failed) = (0, 0);
		for req in reqs {
			let spec = match self.validate_at_startup(req.clone()) {
				Ok((spec, None)) => spec,
				Ok((spec, Some(missing))) => {
					failed += 1;
					error!(event = "rule.failed", rule = %spec.key, error = %missing, phase = "restore");
					self.insert_failed(spec, missing, false).await;
					continue;
				}
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
		let entries: Vec<(Key, Entry)> = self.rules.lock().await.drain().collect();
		for (key, entry) in entries {
			self.stop_entry(&key, entry, None).await;
		}
	}

	/// Starts the rules from the static rules file. Every rule is validated
	/// first so a broken file stops startup instead of half applying.
	pub async fn load_static(self: &Arc<Self>, reqs: Vec<RuleRequest>) -> Result<usize, String> {
		// (spec, reason it cannot run here); only mistakes in the file stop the startup
		let mut specs: Vec<(RuleSpec, Option<String>)> = vec![];
		for (i, req) in reqs.into_iter().enumerate() {
			let (mut spec, missing) =
				self.validate_at_startup(req).map_err(|e| format!("static rule #{}: {}", i + 1, e.message))?;
			spec.origin = Origin::Static;
			if let Some((other, _)) = specs.iter().find(|(s, _)| overlaps(s, &spec)) {
				return Err(format!("static rule #{}: {} overlaps with {}", i + 1, spec.key, other.key));
			}
			if let Some(api) = self.reserved_clash(&spec) {
				return Err(format!("static rule #{}: {} would take the control API ({api})", i + 1, spec.key));
			}
			specs.push((spec, missing));
		}
		let count = specs.len();
		for (spec, missing) in specs {
			let key = spec.key;
			if let Some(missing) = missing {
				error!(event = "rule.failed", rule = %key, error = %missing, phase = "static");
				self.insert_failed(spec, missing, false).await;
				continue;
			}
			if let Err(e) = self.create_spec(spec.clone()).await {
				error!(event = "rule.failed", rule = %key, error = %e.message, phase = "static");
				self.insert_failed(spec, e.message, e.code == "resolve_failed").await;
			}
		}
		info!(event = "static.loaded", rules = count);
		Ok(count)
	}

	pub async fn metrics(&self) -> String {
		let rules = self.rules.lock().await;
		let mut out = String::new();
		let running = rules.values().filter(|e| matches!(e, Entry::Running(_))).count();
		let _ = writeln!(out, "# HELP rproxy_rules Number of rules by state.");
		let _ = writeln!(out, "# TYPE rproxy_rules gauge");
		let _ = writeln!(out, "rproxy_rules{{state=\"running\"}} {running}");
		let _ = writeln!(out, "rproxy_rules{{state=\"failed\"}} {}", rules.len() - running);

		let mut lines: [(&str, &str, &str, Vec<String>); 5] = [
			("rproxy_rule_up", "gauge", "1 if the rule is running.", vec![]),
			("rproxy_connections", "gauge", "Open TCP connections or UDP sessions.", vec![]),
			("rproxy_connections_total", "counter", "TCP connections or UDP sessions handled.", vec![]),
			("rproxy_bytes_total", "counter", "Bytes forwarded; rx is client to backend.", vec![]),
			("rproxy_tls_failures_total", "counter", "Failed TLS / DTLS handshakes and STARTTLS dialogues.", vec![]),
		];
		for (key, entry) in rules.iter() {
			let labels = format!("protocol=\"{}\",listen=\"{}\"", key.protocol, key.listen);
			match entry {
				Entry::Running(r) => {
					let s = &r.rt.stats;
					lines[4].3.push(format!("{{{labels}}} {}", s.tls_failures.load(Ordering::Relaxed)));
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
		http_metrics(&mut out, &rules);
		if let Some(b) = self.cfg.http.crowdsec() {
			let _ = writeln!(out, "# HELP rproxy_crowdsec_decisions Addresses and ranges blocked by the CrowdSec LAPI decisions.");
			let _ = writeln!(out, "# TYPE rproxy_crowdsec_decisions gauge");
			let _ = writeln!(out, "rproxy_crowdsec_decisions {}", b.decision_count());
			let _ = writeln!(out, "# HELP rproxy_crowdsec_synced Whether the decisions have been pulled from the LAPI at least once.");
			let _ = writeln!(out, "# TYPE rproxy_crowdsec_synced gauge");
			let _ = writeln!(out, "rproxy_crowdsec_synced {}", u8::from(b.synced()));
		}
		out
	}
}

/// Requests of `http` rules: a counter by route and status class, and a duration
/// histogram by route. Routes are named in the settings, so the labels stay few.
fn http_metrics(out: &mut String, rules: &HashMap<Key, Entry>) {
	use crate::http::access::{BUCKETS, CLASSES};
	let mut requests = vec![];
	let mut durations = vec![];
	let mut limited = vec![];
	let mut blocked = vec![];
	let mut keys: Vec<&Key> = rules.keys().collect();
	keys.sort_by_key(|k| (k.protocol.to_string(), k.listen));
	for key in keys {
		let Some(Entry::Running(r)) = rules.get(key) else { continue };
		if r.spec.http.is_none() {
			continue;
		}
		for (route, c) in r.rt.http_stats.snapshot() {
			let route = route.replace('\\', "\\\\").replace('"', "\\\"");
			let labels = format!("protocol=\"{}\",listen=\"{}\",route=\"{route}\"", key.protocol, key.listen);
			for (class, n) in CLASSES.iter().zip(c.by_class) {
				if n > 0 {
					requests.push(format!("rproxy_http_requests_total{{{labels},code=\"{class}\"}} {n}"));
				}
			}
			for (bound, n) in BUCKETS.iter().zip(c.buckets) {
				durations.push(format!("rproxy_http_request_duration_seconds_bucket{{{labels},le=\"{bound}\"}} {n}"));
			}
			let total = c.requests();
			durations.push(format!("rproxy_http_request_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {total}"));
			durations.push(format!("rproxy_http_request_duration_seconds_sum{{{labels}}} {}", c.duration_sum));
			durations.push(format!("rproxy_http_request_duration_seconds_count{{{labels}}} {total}"));
		}
		let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
		for ((route, middleware), n) in r.rt.http_stats.limited_snapshot() {
			limited.push(format!(
				"rproxy_http_limited_total{{protocol=\"{}\",listen=\"{}\",route=\"{}\",middleware=\"{}\"}} {n}",
				key.protocol,
				key.listen,
				esc(&route),
				esc(&middleware)
			));
		}
		for ((route, middleware), n) in r.rt.http_stats.blocked_snapshot() {
			blocked.push(format!(
				"rproxy_http_blocked_total{{protocol=\"{}\",listen=\"{}\",route=\"{}\",middleware=\"{}\"}} {n}",
				key.protocol,
				key.listen,
				esc(&route),
				esc(&middleware)
			));
		}
	}
	let _ = writeln!(out, "# HELP rproxy_http_requests_total HTTP requests of http rules by route and status class.");
	let _ = writeln!(out, "# TYPE rproxy_http_requests_total counter");
	for line in requests {
		let _ = writeln!(out, "{line}");
	}
	let _ = writeln!(out, "# HELP rproxy_http_limited_total HTTP requests of http rules refused by rate_limit / in_flight.");
	let _ = writeln!(out, "# TYPE rproxy_http_limited_total counter");
	for line in limited {
		let _ = writeln!(out, "{line}");
	}
	let _ = writeln!(out, "# HELP rproxy_http_blocked_total HTTP requests of http rules refused by crowdsec.");
	let _ = writeln!(out, "# TYPE rproxy_http_blocked_total counter");
	for line in blocked {
		let _ = writeln!(out, "{line}");
	}
	let _ = writeln!(out, "# HELP rproxy_http_request_duration_seconds Time until the response of http rules ended, by route.");
	let _ = writeln!(out, "# TYPE rproxy_http_request_duration_seconds histogram");
	for line in durations {
		let _ = writeln!(out, "{line}");
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
			r.stop_route_resolvers();
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
		let prepared = match registry.prepare(&spec).await {
			Ok(p) => p,
			Err(e) if e.code == "resolve_failed" => continue,
			Err(e) => {
				error!(event = "rule.failed", rule = %spec.key, error = %e.message, phase = "retry");
				if let Some(Entry::Failed(f)) = registry.rules.lock().await.get_mut(&spec.key) {
					f.error = e.message;
					f.retry = None;
				}
				return;
			}
		};

		let mut rules = registry.rules.lock().await;
		let current = matches!(rules.get(&spec.key), Some(Entry::Failed(f)) if f.generation == generation);
		if !current {
			return;
		}
		match registry.start(spec.clone(), prepared) {
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
			transparent_ipv6: false,
			max_range_ports: crate::rule::DEFAULT_MAX_RANGE_PORTS,
			reserved: vec![],
			http: Default::default(),
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
