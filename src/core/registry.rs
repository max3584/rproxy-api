//! The single owner of every running listener.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::Duration;

use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info, warn};

use crate::core::balance::{self, Member, Pool, TargetSpec};
use crate::tls::certstore::{self, CertStore, Source};
use crate::error::ApiError;
use crate::core::proxy::{RouteTarget, Runtime, Stats};
use crate::core::resolve::{self, Lookup};
use crate::core::rule::{
	check_transparent_families, validate_backends, validate_extra_listen, validate_udp_idle, Caps, Key, Origin, Protocol,
	RuleRequest, RuleSpec, RuleStats, RuleView, SourceIp, State, UpdateRequest,
};
use crate::tls::config::{self as tlsconf, Route, TlsMode, TlsRuntime};
use crate::l4::{tcp, udp};

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
	pub http: Arc<crate::l7::access::HttpGlobal>,
}

type Resolver = (CancellationToken, JoinHandle<()>);

/// One listening socket's task; true when it stopped because its address was
/// taken off the rule (or the rule stopped), false when it ended on its own.
type ListenerTask = std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>;

/// The sockets of one listening address, one per port of the rule (UDP: one
/// group of `SO_REUSEPORT` shards per port).
enum Bound {
	Tcp(Vec<tokio::net::TcpListener>),
	Udp(Vec<Vec<tokio::net::UdpSocket>>),
}

/// Sockets per UDP port of a rule (#194). One by default: batching
/// (`recvmmsg` / `sendmmsg`) gave most of the gain, while more sockets cost CPU
/// and only moved the bottleneck to the sessions in the load test. More are
/// opt-in through `RPROXY_UDP_SHARDS` (an experiment's tunable; the setting's
/// shape is for v0.4.0). A range of ports gets fewer, to keep the sockets of
/// one address within `UDP_SHARD_SOCKETS`.
/// Decided when the sockets are opened only: a group that changes size makes
/// the kernel send clients to other sockets, where their sessions are not.
fn udp_shards(ports: u16) -> usize {
	const UDP_SHARD_SOCKETS: usize = 64;
	static FROM_ENV: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
	let forced = match FORCED_UDP_SHARDS.load(Ordering::Relaxed) {
		0 => *FROM_ENV.get_or_init(|| std::env::var("RPROXY_UDP_SHARDS").ok().and_then(|v| v.trim().parse().ok())),
		n => Some(n),
	};
	forced.unwrap_or(1).min(UDP_SHARD_SOCKETS / usize::from(ports.max(1))).clamp(1, UDP_SHARD_SOCKETS)
}

static FORCED_UDP_SHARDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Sets the number of UDP shards for rules created from now on, over
/// `RPROXY_UDP_SHARDS` (tests; 0 goes back to the environment).
#[doc(hidden)]
pub fn force_udp_shards(n: usize) {
	FORCED_UDP_SHARDS.store(n, Ordering::Relaxed);
}

struct Running {
	generation: u64,
	started_at: u64,
	spec: RuleSpec,
	rt: Arc<Runtime>,
	/// Stops the listeners of each address (`listen_addr` and `extra_listen_addrs`).
	listeners: HashMap<IpAddr, CancellationToken>,
	/// Hands listeners of addresses added later to the task that watches them all.
	add_listeners: mpsc::UnboundedSender<ListenerTask>,
	idle_tx: watch::Sender<Duration>,
	/// Name resolution of the targets, and their health checks.
	backends: Backends,
	route_resolvers: Vec<Resolver>,
	supervisor: JoinHandle<()>,
}

/// Background tasks of a rule's targets; replaced with the targets.
#[derive(Default)]
struct Backends {
	resolvers: Vec<Resolver>,
	health: Option<CancellationToken>,
}

impl Backends {
	fn stop(&mut self) -> Vec<JoinHandle<()>> {
		if let Some(h) = self.health.take() {
			h.cancel();
		}
		self.resolvers
			.drain(..)
			.map(|(cancel, task)| {
				cancel.cancel();
				task
			})
			.collect()
	}
}

impl Running {
	fn stop_resolver(&mut self) -> Vec<JoinHandle<()>> {
		self.backends.stop()
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
				let pool = r.rt.pool();
				let resolved: Vec<SocketAddr> = pool.members.iter().flat_map(|m| m.addrs.borrow().clone()).collect();
				let mut view = RuleView::new(&r.spec, State::Running, None, &resolved, s.active.load(Ordering::Relaxed));
				view.stats = RuleStats {
					total_connections: s.total.load(Ordering::Relaxed),
					rx_bytes: s.rx_bytes.load(Ordering::Relaxed),
					tx_bytes: s.tx_bytes.load(Ordering::Relaxed),
					tls_failures: s.tls_failures.load(Ordering::Relaxed),
					denied: s.denied.load(Ordering::Relaxed),
					dropped: s.dropped.load(Ordering::Relaxed),
					limited: None,
					counters_since: None,
					http: r.spec.http.is_some().then(|| {
						let mut v = crate::l7::access::HttpStatsView::from_stats(&r.rt.http_stats);
						v.services = r.rt.http_router().map(|router| router.health()).unwrap_or_default();
						v.http3 = r.spec.http.as_ref().is_some_and(|h| h.http3).then(|| r.rt.h3.view());
						v
					}),
					targets: if pool.reported { pool.status() } else { vec![] },
				};
				view.all_targets_down = pool.all_down();
				if let Some(http) = &view.stats.http {
					view.down_services = down_services(&http.services);
				}
				view.started_at = Some(r.started_at);
				view
			}
			Entry::Failed(f) => RuleView::new(&f.spec, State::Failed, Some(f.error.clone()), &[], 0),
		}
	}
}

/// Services with health checks that have no server up.
fn down_services(health: &std::collections::BTreeMap<String, Vec<crate::l7::backend::ServerHealth>>) -> Vec<String> {
	health.iter().filter(|(_, servers)| !servers.iter().any(|s| s.up)).map(|(name, _)| name.clone()).collect()
}

/// What a rule needs before it can listen: resolved targets and TLS settings.
struct Prepared {
	/// The targets with their addresses (empty for one that could not be resolved yet).
	members: Vec<(TargetSpec, Vec<SocketAddr>)>,
	routes: Vec<(Route, Vec<SocketAddr>)>,
	tls: Arc<TlsRuntime>,
	http: Option<Arc<crate::l7::server::Router>>,
}

/// What `Registry::check_rules` found: (label, message) per problem.
#[derive(Debug, Default)]
pub struct RulesCheck {
	/// Rules that would start.
	pub ok: usize,
	pub errors: Vec<(String, String)>,
	pub warnings: Vec<(String, String)>,
	/// Certificate, chain, key and CA files the rules use.
	pub files: Vec<String>,
}

/// What a reload of the settings file did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ReloadCounts {
	pub added: usize,
	pub removed: usize,
	pub changed: usize,
	pub unchanged: usize,
	/// Of the added and changed rules: those registered as failed.
	pub failed: usize,
}

/// The settings file as last read (`GET /config`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ConfigStatus {
	/// The file or directory.
	pub path: String,
	/// Files read, in order.
	pub files: Vec<String>,
	/// Unix seconds of the last successful read.
	pub loaded_at: Option<u64>,
	pub rules: usize,
	pub last_reload: Option<ReloadCounts>,
	/// Why the latest version could not be applied (the previous one stays in effect).
	pub error: Option<String>,
	/// `global` settings changed in the file that take effect only after a restart.
	pub restart_needed: Vec<String>,
}

pub struct Registry {
	cfg: Config,
	rules: Mutex<HashMap<Key, Entry>>,
	next_generation: AtomicU64,
	config_status: RwLock<Option<ConfigStatus>>,
	/// Every certificate the rules use, loaded once and shared.
	certs: CertStore,
	/// `global.acme`: certificates of `tls.certificates[].acme` (set once at startup).
	acme: std::sync::OnceLock<Arc<crate::acme::Acme>>,
}

/// What `Registry::apply_certs` does with one rule.
enum CertAction {
	Nothing,
	/// Its certificates could not be reloaded; the current ones stay.
	Failed,
	/// New TLS settings were installed.
	Rebuilt,
	/// Every server certificate has expired: take the rule out of service.
	Expired(String),
	/// Stopped for expired certificates, and a certificate it uses changed.
	Restart(Box<RuleSpec>, u64),
}

fn bind_error(addr: SocketAddr, e: std::io::Error) -> ApiError {
	if e.kind() == std::io::ErrorKind::PermissionDenied && addr.port() < 1024 {
		return ApiError::bind_failed(format!(
			"{addr}: {e}; ports below 1024 need CAP_NET_BIND_SERVICE (setcap cap_net_bind_service=+ep on the binary, or AmbientCapabilities in systemd)"
		));
	}
	ApiError::bind_failed(format!("{addr}: {e}"))
}

/// Binds every port of the rule on one address; all or nothing.
fn bind_all(spec: &RuleSpec, ip: IpAddr) -> Result<Bound, ApiError> {
	let v6only = spec.v6only();
	let addrs = (0..spec.port_count).map(|offset| SocketAddr::new(ip, spec.key.listen.port() + offset));
	let bound = match spec.key.protocol {
		Protocol::Tcp => Bound::Tcp(
			addrs
				.map(|addr| crate::net::listen::tcp(addr, v6only).and_then(tokio::net::TcpListener::from_std).map_err(|e| bind_error(addr, e)))
				.collect::<Result<_, _>>()?,
		),
		Protocol::Udp => {
			let shards = udp_shards(spec.port_count);
			Bound::Udp(
				addrs
					.map(|addr| {
						crate::net::listen::udp_shards(addr, v6only, shards)
							.and_then(|group| group.into_iter().map(tokio::net::UdpSocket::from_std).collect())
							.map_err(|e| bind_error(addr, e))
					})
					.collect::<Result<_, _>>()?,
			)
		}
	};
	Ok(bound)
}

/// The serving tasks of one address's sockets, stopped by `stop`.
fn listener_tasks(bound: Bound, rt: &Arc<Runtime>, stop: &CancellationToken) -> Vec<ListenerTask> {
	let mut tasks: Vec<ListenerTask> = vec![];
	match bound {
		Bound::Tcp(listeners) => {
			for (offset, l) in listeners.into_iter().enumerate() {
				let (rt, stop) = (rt.clone(), stop.clone());
				tasks.push(Box::pin(async move {
					tcp::serve(l, rt, offset as u16, stop.clone()).await;
					stop.is_cancelled()
				}));
			}
		}
		Bound::Udp(sockets) => {
			let ports = u16::try_from(sockets.len()).unwrap_or(u16::MAX);
			for (offset, group) in sockets.into_iter().enumerate() {
				let port = Arc::new(udp::Port::new(ports));
				for s in group {
					let (rt, stop, port) = (rt.clone(), stop.clone(), port.clone());
					tasks.push(Box::pin(async move {
						udp::serve(s, port, rt, offset as u16, stop.clone()).await;
						stop.is_cancelled()
					}));
				}
			}
		}
	}
	tasks
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

/// Two rules clash when they share a protocol and ports on an address of either
/// (`listen_addr` or `extra_listen_addrs`), or on a wildcard that covers it.
fn overlaps(a: &RuleSpec, b: &RuleSpec) -> bool {
	let (a0, b0) = (u32::from(a.key.listen.port()), u32::from(b.key.listen.port()));
	let (a1, b1) = (a0 + u32::from(a.port_count) - 1, b0 + u32::from(b.port_count) - 1);
	if a.key.protocol != b.key.protocol || a0 > b1 || b0 > a1 {
		return false;
	}
	let (bs, av, bv) = (b.listen_ips(), a.v6only(), b.v6only());
	a.listen_ips().into_iter().any(|x| bs.iter().any(|y| crate::net::listen::clash(x, av, *y, bv)))
}

/// A rule on `::`, whose socket takes IPv4 too unless it has extra addresses.
fn is_dual_stack_wildcard(key: &Key) -> bool {
	key.listen.is_ipv6() && key.listen.ip().is_unspecified()
}

fn route_spec(route: &Route) -> String {
	match route.remote_addr.parse::<IpAddr>() {
		Ok(IpAddr::V6(ip)) => SocketAddr::new(IpAddr::V6(ip), route.remote_port).to_string(),
		_ => format!("{}:{}", route.remote_addr, route.remote_port),
	}
}

impl Registry {
	pub fn new(cfg: Config) -> Arc<Self> {
		Arc::new(Registry {
			cfg,
			rules: Mutex::default(),
			next_generation: AtomicU64::new(1),
			config_status: RwLock::default(),
			certs: CertStore::default(),
			acme: std::sync::OnceLock::new(),
		})
	}

	/// Sets `global.acme` (before rules are loaded). A certificate written by
	/// ACME is swapped in like a certificate file that changed.
	pub fn set_acme(self: &Arc<Self>, acme: Arc<crate::acme::Acme>) {
		let weak = Arc::downgrade(self);
		acme.set_on_change(Box::new(move || {
			if let Some(registry) = weak.upgrade() {
				tokio::spawn(async move {
					let (ok, failed) = registry.reload_changed_tls().await;
					info!(event = "reload.tls", part = "acme", reloaded = ok, failed);
				});
			}
		}));
		let _ = self.acme.set(acme);
	}

	pub fn acme(&self) -> Option<&Arc<crate::acme::Acme>> {
		self.acme.get()
	}

	/// The certificate files a rule's TLS settings use (ACME ones included).
	fn sources(&self, tls: &tlsconf::TlsSpec) -> Vec<(tlsconf::CertRole, Source)> {
		certstore::sources_with(tls, self.acme().map(|a| a.as_ref()))
	}

	/// Checks the ACME certificates of a rule: `global.acme` is set, the
	/// resolver exists, the names are allowed, and the rule is TCP.
	fn check_acme(&self, spec: &RuleSpec) -> Result<(), ApiError> {
		for c in &spec.tls.certificates {
			let Some(resolver) = &c.acme else { continue };
			let acme = self.acme().ok_or_else(|| {
				ApiError::invalid(format!("acme resolver {resolver:?}: global.acme is not configured in the settings file (RPROXY_CONFIG)"))
			})?;
			if spec.key.protocol != Protocol::Tcp {
				return Err(ApiError::tls_config("acme certificates are for tcp rules (DTLS takes cert_file / key_file)"));
			}
			acme.check(resolver, &c.domains)?;
		}
		Ok(())
	}

	/// The certificate store (#115).
	pub fn certs(&self) -> &CertStore {
		&self.certs
	}

	/// A rule's view with the expiry of its certificates.
	fn view_of(&self, entry: &Entry) -> RuleView {
		let mut view = entry.view();
		let now = tlsconf::unix_now();
		let warn = self.certs.warn_secs();
		let sources = self.sources(&entry.spec().tls);
		view.acme = sources
			.iter()
			.filter_map(|(_, s)| match s {
				Source::Acme { id, .. } => self.acme()?.status(id),
				_ => None,
			})
			.collect();
		view.cert_status = sources
			.into_iter()
			.filter_map(|(role, source)| {
				let not_after = self.certs.not_after(&source)?;
				Some(certstore::CertStatusView::new(role, source.file(), not_after, now, warn))
			})
			.collect();
		view
	}

	/// The rule's TLS settings, with its certificates from the store.
	fn build_tls(&self, spec: &RuleSpec) -> Result<TlsRuntime, ApiError> {
		let tls = spec.runtime_tls();
		self.check_acme(spec)?;
		let loaded = self.certs.rule_certs_with(&tls, self.acme().map(|a| a.as_ref()))?;
		TlsRuntime::build(spec.key.protocol, &tls, spec.starttls, spec.starttls_required, &loaded)
	}

	/// Forgets certificates no rule uses any more, and tells ACME which
	/// certificates the rules use now.
	async fn gc_certs(&self) {
		let used: HashSet<Source> =
			self.rules.lock().await.values().flat_map(|e| self.sources(&e.spec().tls)).map(|(_, s)| s).collect();
		if let Some(acme) = self.acme() {
			acme.set_wanted(
				used.iter()
					.filter_map(|s| match s {
						Source::Acme { id, .. } => Some(id.clone()),
						_ => None,
					})
					.collect(),
			);
		}
		self.certs.retain(&used);
	}

	pub fn reserved(&self) -> &[SocketAddr] {
		&self.cfg.reserved
	}

	/// The control API's own address, if the rule would take it.
	fn reserved_clash(&self, spec: &RuleSpec) -> Option<SocketAddr> {
		if spec.key.protocol != Protocol::Tcp {
			return None;
		}
		let start = u32::from(spec.key.listen.port());
		let end = start + u32::from(spec.port_count) - 1;
		let ips = spec.listen_ips();
		// the control API's own sockets may be dual-stack
		self.cfg.reserved.iter().copied().find(|r| {
			(start..=end).contains(&u32::from(r.port())) && ips.iter().any(|ip| crate::net::listen::clash(*ip, spec.v6only(), r.ip(), false))
		})
	}

	pub fn caps(&self) -> Caps {
		Caps {
			transparent: self.cfg.transparent,
			transparent_ipv6: self.cfg.transparent_ipv6,
			max_range_ports: self.cfg.max_range_ports,
			features: crate::core::rule::Features::CURRENT,
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
					Caps { transparent: true, transparent_ipv6: true, features: crate::core::rule::Features::ALL, ..caps };
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
		keys.into_iter().map(|k| self.view_of(&rules[k])).collect()
	}

	pub async fn get(&self, key: &Key) -> Result<RuleView, ApiError> {
		self.rules.lock().await.get(key).map(|e| self.view_of(e)).ok_or_else(|| ApiError::not_found(key.to_string()))
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
	/// What a rule needs besides sockets and name resolution: its TLS settings
	/// with the certificates from the store, and its compiled `http` (secret files
	/// read). Shared by starting a rule and by `--check-config` (`check_rules`).
	fn build_parts(&self, spec: &RuleSpec) -> Result<(Arc<TlsRuntime>, Option<Arc<crate::l7::server::Router>>), ApiError> {
		let tls = Arc::new(self.build_tls(spec)?);
		if spec.crowdsec && self.cfg.http.crowdsec().is_none() {
			return Err(ApiError::invalid("crowdsec needs global.crowdsec in the settings file"));
		}
		let http = match &spec.http {
			Some(h) => {
				crate::l7::middleware::crowdsec::check_refs(h, self.cfg.http.crowdsec())?;
				Some(Arc::new(crate::l7::server::Router::compile(h, &spec.tls.upstream, self.cfg.lookup.clone())?))
			}
			None => None,
		};
		Ok((tls, http))
	}

	async fn prepare(&self, spec: &RuleSpec) -> Result<Prepared, ApiError> {
		let (tls, http) = self.build_parts(spec)?;
		// with several targets, one that cannot be resolved yet is retried in the
		// background; the rule fails only when none can be
		let wanted = spec.members();
		let mut members = vec![];
		let mut first_error = None;
		for t in wanted.iter() {
			match resolve::resolve(&self.cfg.lookup, &t.remote()).await {
				Ok(addrs) => members.push((t.clone(), addrs)),
				Err(e) => {
					warn!(event = "dns.stale", rule = %spec.key, target = %t.remote(), error = %e.message);
					first_error.get_or_insert(e);
					members.push((t.clone(), vec![]));
				}
			}
		}
		if let Some(e) = first_error.filter(|_| members.iter().all(|(_, a)| a.is_empty())) {
			return Err(e);
		}
		let mut routes = vec![];
		for route in &spec.tls.routes {
			routes.push((route.clone(), resolve::resolve(&self.cfg.lookup, &route_spec(route)).await?));
		}
		Ok(Prepared { members, routes, tls, http })
	}

	/// The run-time targets of a rule, with their name resolution and health checks.
	fn install_pool(&self, spec: &RuleSpec, members: Vec<(TargetSpec, Vec<SocketAddr>)>, events: &Arc<watch::Sender<u64>>, kill: &CancellationToken) -> (Arc<Pool>, Backends) {
		let mut backends = Backends::default();
		let mut pool_members = vec![];
		for (t, addrs) in members {
			let tx = Arc::new(watch::channel(addrs).0);
			backends.resolvers.extend(self.spawn_resolver(spec.key, &t.addr, t.remote(), &tx));
			pool_members.push(Arc::new(Member::new(t, tx)));
		}
		let reported = pool_members.len() > 1 || spec.health_check.is_some();
		let pool = Arc::new(Pool::new(pool_members, spec.balance, events.clone(), reported));
		if let Some(check) = spec.health_check.clone().filter(|_| !pool.members.is_empty()) {
			let stop = kill.child_token();
			balance::spawn_health_checks(spec.key, pool.clone(), check, stop.clone());
			backends.health = Some(stop);
		}
		(pool, backends)
	}

	fn install_routes(&self, key: Key, routes: Vec<(Route, Vec<SocketAddr>)>) -> (Arc<Vec<RouteTarget>>, Vec<Resolver>) {
		let mut targets = vec![];
		let mut resolvers = vec![];
		for (route, addrs) in routes {
			let (tx, rx) = watch::channel(addrs);
			// the resolver task keeps the sender; without one the last value stays readable
			resolvers.extend(self.spawn_resolver(key, &route.remote_addr, route_spec(&route), &Arc::new(tx)));
			targets.push(RouteTarget {
				patterns: route.patterns(),
				passthrough: route.passthrough,
				host: route.remote_addr.clone(),
				target: rx,
			});
		}
		(Arc::new(targets), resolvers)
	}

	/// Binds every port of the rule and starts serving. Called with the rules lock held.
	fn start(self: &Arc<Self>, spec: RuleSpec, prepared: Prepared) -> Result<Running, ApiError> {
		let key = spec.key;
		let (idle_tx, idle_rx) = watch::channel(spec.udp_idle);
		let (routes, route_resolvers) = self.install_routes(key, prepared.routes);
		let kill = CancellationToken::new();
		let events = Arc::new(watch::channel(0).0);
		let (pool, backends) = self.install_pool(&spec, prepared.members, &events, &kill);
		let rt = Arc::new(Runtime {
			key,
			source_ip: spec.source_ip,
			pool: RwLock::new(pool),
			pool_events: events,
			routes: RwLock::new(routes),
			tls: RwLock::new(prepared.tls),
			allow_from: RwLock::new(Arc::new(spec.allow_from.clone())),
			crowdsec: spec.crowdsec.into(),
			http: RwLock::new(prepared.http),
			global: self.cfg.http.clone(),
			http_stats: Default::default(),
			h3: Default::default(),
			listen: RwLock::new(spec.listen_ips()),
			udp_idle: idle_rx,
			stats: Stats::default(),
			denied_log: Default::default(),
			stop: kill.child_token(),
			kill,
			tracker: TaskTracker::new(),
		});

		// bind everything first so a failure leaves nothing half-open
		let bound = spec.listen_ips().into_iter().map(|ip| Ok((ip, bind_all(&spec, ip)?))).collect::<Result<Vec<_>, ApiError>>()?;
		let mut set = JoinSet::new();
		let mut listeners = HashMap::new();
		for (ip, sockets) in bound {
			let token = rt.stop.child_token();
			for task in listener_tasks(sockets, &rt, &token) {
				set.spawn(task);
			}
			listeners.insert(ip, token);
		}
		if spec.http.as_ref().is_some_and(|h| h.http3) {
			crate::l7::h3::start(&rt);
		}
		let stop = rt.stop.clone();
		let (add_listeners, mut added) = mpsc::unbounded_channel::<ListenerTask>();
		let serve = tokio::spawn(async move {
			let mut adding = true;
			loop {
				tokio::select! {
					done = set.join_next(), if !set.is_empty() => match done {
						Some(Err(e)) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
						// the listener's address was taken off the rule
						Some(Ok(true)) => {}
						// one listener ending on its own fails the whole rule
						_ if !stop.is_cancelled() => return,
						_ => {}
					},
					task = added.recv(), if adding => match task {
						Some(task) => {
							set.spawn(task);
						}
						None => adding = false,
					},
					else => return,
				}
				if stop.is_cancelled() && set.is_empty() {
					return;
				}
			}
		});

		let generation = self.generation();
		let supervisor = tokio::spawn(supervise(Arc::downgrade(self), key, generation, rt.clone(), serve));
		let started_at = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		Ok(Running { generation, started_at, spec, rt, listeners, add_listeners, idle_tx, backends, route_resolvers, supervisor })
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
		let view = self.view_of(&entry);
		rules.insert(key, entry);
		drop(rules);
		// ACME learns about new certificates (their state is in the view)
		self.gc_certs().await;
		let view = self.get(&key).await.unwrap_or(view);
		info!(event = "rule.create", rule = %key, target = %format!("{}:{}", view.remote_addr, view.remote_port),
			ports = view.listen_port_end.map(|e| e - view.listen_port + 1).unwrap_or(1),
			source_ip = view.source_ip, tls = ?view.tls.mode, starttls = view.starttls.map(|s| s.as_str()).unwrap_or(""),
			resolved = ?view.resolved);
		Ok(view)
	}

	/// The `global` settings of `http` rules.
	pub fn http_global(&self) -> Arc<crate::l7::access::HttpGlobal> {
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
			return Err(ApiError::static_rule(format!("{key} is a static rule; edit the settings file (RPROXY_CONFIG), which is re-read when it changes")));
		}
		if let Some(list) = &req.allow_from {
			spec.allow_from = crate::net::cidr::parse_list(list)?;
		}
		if let Some(on) = req.crowdsec {
			spec.crowdsec = on;
		}
		if let Some(list) = &req.extra_listen_addrs {
			spec.extra_listen = validate_extra_listen(key.listen.ip(), list)?;
		}
		if req.source_ip.is_some_and(|s| s != spec.source_ip) {
			return Err(ApiError::unsupported("source_ip cannot be changed; delete and re-create the rule"));
		}
		if let Some(end) = req.listen_port_end {
			if end != key.listen.port() + spec.port_count - 1 {
				return Err(ApiError::unsupported("the port range cannot be changed; delete and re-create the rule"));
			}
		}
		let is_http = req.http.is_some() || spec.http.is_some();
		let mut targets = req.targets;
		if targets.is_empty() && u32::from(req.remote_port) + u32::from(spec.port_count) - 1 > 65_535 {
			return Err(ApiError::invalid("remote_port + range length exceeds 65535"));
		}
		let (remote_host, remote_port) = validate_backends(&req.remote_addr, req.remote_port, &mut targets, is_http, spec.port_count)?;
		spec.remote_host = remote_host;
		spec.remote_port = remote_port;
		// the backends are replaced as a whole: left out means the default
		spec.targets = targets;
		spec.balance = req.balance.unwrap_or_default();
		spec.health_check = req.health_check;
		if let Some(c) = &spec.health_check {
			if is_http {
				return Err(ApiError::invalid("health_check of a rule is not used with http; use http.services.<name>.health_check"));
			}
			c.validate(key.protocol)?;
		}
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
			spec.starttls_required = req.starttls != Some(crate::tls::config::StartTls::Smtp) || req.starttls_required.unwrap_or(true);
		}
		let http_changed = req.http.is_some();
		if let Some(http) = req.http {
			if spec.http.is_none() {
				return Err(ApiError::unsupported("a rule cannot be turned into an http rule; delete and re-create it"));
			}
			if key.protocol != crate::core::rule::Protocol::Tcp || spec.tls.mode == crate::tls::config::TlsMode::Sni || spec.starttls.is_some() {
				return Err(ApiError::invalid("http needs protocol tcp with tls mode terminate (or no TLS) and no starttls"));
			}
			http.validate()?;
			spec.http = Some(http);
		}
		if let Some(h) = &spec.http {
			crate::core::rule::check_http_tls(&spec.tls, spec.source_ip, h)?;
		}
		// v0.4: each replaces the current value when present (`{}` removes it)
		if let Some(labels) = req.labels {
			spec.labels = labels;
		}
		let v04 = crate::core::rule::V04Settings {
			limits: req.limits.or_else(|| spec.limits.take()),
			bandwidth: req.bandwidth.or_else(|| spec.bandwidth.take()),
			geoip: req.geoip.or_else(|| spec.geoip.take()),
			outlier_detection: req.outlier_detection.or_else(|| spec.outlier_detection.take()),
		}
		.validate(key.protocol, spec.http.is_some(), &spec.labels)?;
		spec.limits = v04.limits;
		spec.bandwidth = v04.bandwidth;
		spec.geoip = v04.geoip;
		spec.outlier_detection = v04.outlier_detection;
		// whatever was replaced, the rule must stay within what this build can run
		self.caps().features.check(&spec.tls, spec.http.as_ref())?;
		self.caps().features.check_v04(&spec)?;
		if spec.source_ip == SourceIp::Transparent {
			check_transparent_families(&spec.extra_listen, &spec.members(), &self.caps())?;
		}
		self.apply(key, spec, tls_changed, http_changed).await
	}

	/// Puts a changed spec into effect on an existing rule, keeping its
	/// connections (the fields PATCH can change: target, timeouts, TLS, allow_from, http).
	async fn apply(self: &Arc<Self>, key: &Key, spec: RuleSpec, tls_changed: bool, http_changed: bool) -> Result<RuleView, ApiError> {
		if let Some(api) = self.reserved_clash(&spec) {
			return Err(ApiError::reserved(format!("{key} would take rproxy's control API ({api})")));
		}
		let prepared = self.prepare(&spec).await?;

		let mut rules = self.rules.lock().await;
		if let Some((other, _)) = rules.iter().find(|(k, e)| *k != key && overlaps(e.spec(), &spec)) {
			return Err(ApiError::already_exists(format!("{key} overlaps with {other}")));
		}
		let entry = rules.get_mut(key).ok_or_else(|| ApiError::not_found(key.to_string()))?;
		match entry {
			Entry::Running(r) => {
				// open the added addresses first: a failure changes nothing
				let listen_changed = r.spec.extra_listen != spec.extra_listen;
				if listen_changed && is_dual_stack_wildcard(key) && r.spec.v6only() != spec.v6only() {
					return Err(ApiError::unsupported(
						"a rule on :: listens dual-stack alone and IPv6-only with extra_listen_addrs; delete and re-create it to switch",
					));
				}
				let old_ips = r.spec.listen_ips();
				let added = spec
					.listen_ips()
					.into_iter()
					.filter(|ip| !old_ips.contains(ip))
					.map(|ip| Ok((ip, bind_all(&spec, ip)?)))
					.collect::<Result<Vec<_>, ApiError>>()?;
				if listen_changed {
					let new_ips = spec.listen_ips();
					r.listeners.retain(|ip, token| {
						let keep = new_ips.contains(ip);
						if !keep {
							token.cancel();
						}
						keep
					});
					for (ip, sockets) in added {
						let token = r.rt.stop.child_token();
						for task in listener_tasks(sockets, &r.rt, &token) {
							// the watching task ends only with the rule
							let _ = r.add_listeners.send(task);
						}
						r.listeners.insert(ip, token);
					}
					*r.rt.listen.write().unwrap() = new_ips;
					info!(event = "rule.listen", rule = %key, addrs = ?r.rt.listen.read().unwrap());
				}
				let backends_changed = r.spec.members() != spec.members()
					|| r.spec.balance != spec.balance
					|| r.spec.health_check != spec.health_check;
				r.idle_tx.send_replace(spec.udp_idle);
				*r.rt.allow_from.write().unwrap() = Arc::new(spec.allow_from.clone());
				r.rt.crowdsec.store(spec.crowdsec, Ordering::Relaxed);
				if backends_changed {
					// new connections use the new targets; UDP sessions move when theirs is gone
					r.backends.stop();
					let (pool, backends) = self.install_pool(&spec, prepared.members, &r.rt.pool_events, &r.rt.kill);
					*r.rt.pool.write().unwrap() = pool;
					r.backends = backends;
					r.rt.pool().notify();
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
				// HTTP/3 turned on or off (new certificates are picked up per QUIC connection)
				let h3_was = r.spec.http.as_ref().is_some_and(|h| h.http3);
				let h3_now = spec.http.as_ref().is_some_and(|h| h.http3);
				if h3_now && (!h3_was || r.rt.h3.port().is_none() || listen_changed) {
					crate::l7::h3::start(&r.rt);
				} else if h3_was && !h3_now {
					crate::l7::h3::stop(&r.rt);
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
		let view = self.view_of(entry);
		info!(event = "rule.update", rule = %key, target = %format!("{}:{}", view.remote_addr, view.remote_port),
			udp_idle_secs = view.udp_idle_secs, tls = ?view.tls.mode, resolved = ?view.resolved);
		Ok(view)
	}

	/// SIGHUP: reloads every certificate of the store (and the secret files of
	/// authentication middlewares), then rebuilds the TLS settings of every TLS
	/// rule. Returns (rules updated, rules whose certificates could not be reloaded,
	/// which keep their current ones).
	pub async fn reload_tls(self: &Arc<Self>) -> (usize, usize) {
		let changes = self.certs.reload_all();
		self.apply_certs(&changes, true).await
	}

	/// Re-reads the certificates whose files changed since they were loaded
	/// (renewed by certbot, cert-manager, ...; #90), once per certificate, and
	/// updates the rules that use them. A version that does not load (half
	/// written) keeps the current certificate and is tried again on the next call.
	pub async fn reload_changed_tls(self: &Arc<Self>) -> (usize, usize) {
		let changes = self.certs.refresh();
		self.apply_certs(&changes, false).await
	}

	/// The daily expiry check: rules drop server certificates that have expired
	/// since the last check, and stop when none is left. Returns the rules updated.
	pub async fn check_certificate_expiry(self: &Arc<Self>) -> usize {
		let expired = self.certs.newly_expired(tlsconf::unix_now());
		let changes = certstore::Changes { changed: expired, failed: HashSet::new() };
		self.apply_certs(&changes, false).await.0
	}

	/// Applies certificate changes of the store to the rules that use them
	/// (`all`: every rule, SIGHUP): new TLS settings (an expired server
	/// certificate is left out); a rule whose server certificates have all
	/// expired is taken out of service (failed, listeners closed); a rule
	/// stopped for that starts again once a renewed certificate loads.
	async fn apply_certs(self: &Arc<Self>, changes: &certstore::Changes, all: bool) -> (usize, usize) {
		let uses = |spec: &RuleSpec, set: &HashSet<Source>| self.sources(&spec.tls).iter().any(|(_, s)| set.contains(s));
		let (mut ok, mut failed) = (0, 0);
		let mut stopped = vec![];
		let mut restart = vec![];
		{
			let mut rules = self.rules.lock().await;
			let keys: Vec<Key> = rules.keys().copied().collect();
			for key in keys {
				let action = match &rules[&key] {
					Entry::Running(r) => {
						if all {
							if let Some(router) = r.rt.http_router() {
								router.reload_secrets();
							}
						}
						if uses(&r.spec, &changes.failed) {
							CertAction::Failed
						} else if r.spec.tls.mode != TlsMode::Terminate || !(all || uses(&r.spec, &changes.changed)) {
							CertAction::Nothing
						} else {
							match self.build_tls(&r.spec) {
								Ok(tls) => {
									*r.rt.tls.write().unwrap() = Arc::new(tls);
									CertAction::Rebuilt
								}
								Err(e) if tlsconf::is_cert_expired(&e) => CertAction::Expired(e.message),
								Err(e) => {
									warn!(event = "reload.tls", rule = %key, error = %e.message, "keeping current certificates");
									CertAction::Failed
								}
							}
						}
					}
					Entry::Failed(f) if tlsconf::is_cert_expired_text(&f.error) && (all || uses(&f.spec, &changes.changed)) => {
						CertAction::Restart(Box::new(f.spec.clone()), f.generation)
					}
					Entry::Failed(_) => CertAction::Nothing,
				};
				match action {
					CertAction::Nothing => {}
					CertAction::Failed => failed += 1,
					CertAction::Rebuilt => {
						ok += 1;
						info!(event = "reload.tls", rule = %key, reason = if all { "sighup" } else { "certificates changed" });
					}
					CertAction::Expired(error) => {
						error!(event = "rule.failed", rule = %key, error = %error, phase = "certificates");
						if let Some(Entry::Running(r)) = rules.remove(&key) {
							let generation = self.generation();
							rules.insert(key, Entry::Failed(Failed { generation, spec: r.spec.clone(), error, retry: None }));
							stopped.push((key, r));
						}
					}
					CertAction::Restart(spec, generation) => restart.push((spec, generation)),
				}
			}
		}
		for (key, r) in stopped {
			self.stop_entry(&key, Entry::Running(r), None).await;
		}
		for (spec, generation) in restart {
			let spec = *spec;
			let key = spec.key;
			let still_failed = |rules: &HashMap<Key, Entry>| matches!(rules.get(&key), Some(Entry::Failed(f)) if f.generation == generation);
			let prepared = match self.prepare(&spec).await {
				Ok(p) => p,
				Err(e) => {
					let mut rules = self.rules.lock().await;
					if still_failed(&rules) {
						if let Some(Entry::Failed(f)) = rules.get_mut(&key) {
							f.error = e.message;
						}
					}
					continue;
				}
			};
			let mut rules = self.rules.lock().await;
			if !still_failed(&rules) {
				continue;
			}
			match self.start(spec, prepared) {
				Ok(running) => {
					info!(event = "rule.create", rule = %key, phase = "certificates renewed");
					rules.insert(key, Entry::Running(running));
					ok += 1;
				}
				Err(e) => {
					error!(event = "rule.failed", rule = %key, error = %e.message, phase = "certificates");
					if let Some(Entry::Failed(f)) = rules.get_mut(&key) {
						f.error = e.message;
					}
				}
			}
		}
		self.gc_certs().await;
		(ok, failed)
	}

	/// Stops a rule. Returns once the listener is closed and every connection has ended.
	pub async fn delete(&self, key: &Key, drain: Option<Duration>) -> Result<(), ApiError> {
		let entry = {
			let mut rules = self.rules.lock().await;
			match rules.get(key) {
				None => return Err(ApiError::not_found(key.to_string())),
				Some(e) if e.spec().origin == Origin::Static => {
					return Err(ApiError::static_rule(format!("{key} is a static rule; edit the settings file (RPROXY_CONFIG), which is re-read when it changes")));
				}
				Some(_) => rules.remove(key).expect("checked above"),
			}
		};
		self.stop_entry(key, entry, drain).await;
		self.gc_certs().await;
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
				for task in r.stop_resolver() {
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

	/// The running rules' runtimes (a live upgrade reads and adds counters, #174).
	pub async fn runtimes(&self) -> Vec<(Key, Arc<Runtime>)> {
		self.rules
			.lock()
			.await
			.iter()
			.filter_map(|(k, e)| match e {
				Entry::Running(r) => Some((*k, r.rt.clone())),
				Entry::Failed(_) => None,
			})
			.collect()
	}

	/// Stops accepting on every rule at once, lets the connections end until
	/// `until` is done, then closes the rest (after a live upgrade, #174).
	pub async fn drain_all(&self, until: impl std::future::Future<Output = ()>) {
		let entries: Vec<(Key, Entry)> = self.rules.lock().await.drain().collect();
		let mut trackers = vec![];
		for (_, entry) in &entries {
			if let Entry::Running(r) = entry {
				r.rt.stop.cancel();
				r.rt.tracker.close();
				trackers.push(r.rt.tracker.clone());
			}
		}
		tokio::select! {
			_ = futures_util::future::join_all(trackers.iter().map(|t| t.wait())) => {}
			_ = until => {}
		}
		for (key, entry) in entries {
			self.stop_entry(&key, entry, None).await;
		}
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
		let labeled = reqs.into_iter().enumerate().map(|(i, r)| (format!("static rule #{}", i + 1), r)).collect();
		self.load_static_labeled(labeled).await
	}

	/// `load_static` with a label per rule for messages (file and position).
	pub async fn load_static_labeled(self: &Arc<Self>, reqs: Vec<(String, RuleRequest)>) -> Result<usize, String> {
		let specs = self.validate_static(reqs)?;
		let count = specs.len();
		for (spec, missing) in specs {
			self.start_static(spec, missing, "static").await;
		}
		self.gc_certs().await;
		info!(event = "static.loaded", rules = count);
		Ok(count)
	}

	/// Validates the rules of the settings file as a whole: (spec, reason it
	/// cannot run here). Only mistakes in the file are errors.
	fn validate_static(&self, reqs: Vec<(String, RuleRequest)>) -> Result<Vec<(RuleSpec, Option<String>)>, String> {
		let mut specs: Vec<(RuleSpec, Option<String>, String)> = vec![];
		for (label, req) in reqs {
			let (mut spec, missing) = self.validate_at_startup(req).map_err(|e| format!("{label}: {}", e.message))?;
			spec.origin = Origin::Static;
			if let Some((other, _, other_label)) = specs.iter().find(|(s, _, _)| overlaps(s, &spec)) {
				return Err(format!("{label}: {} overlaps with {} ({other_label})", spec.key, other.key));
			}
			if let Some(api) = self.reserved_clash(&spec) {
				return Err(format!("{label}: {} would take the control API ({api})", spec.key));
			}
			specs.push((spec, missing, label));
		}
		Ok(specs.into_iter().map(|(s, m, _)| (s, m)).collect())
	}

	/// Checks the rules of a settings file without starting anything (`rproxy-api
	/// --check-config`): the same validation as `validate_static`, then what
	/// `prepare` does short of name resolution (certificates, `http`, secret
	/// files). Unlike `validate_static` it goes on after a mistake, so every
	/// problem is reported.
	pub fn check_rules(&self, reqs: Vec<(String, RuleRequest)>) -> RulesCheck {
		let mut out = RulesCheck::default();
		let mut specs: Vec<(RuleSpec, String)> = vec![];
		for (label, req) in reqs {
			let (spec, missing) = match self.validate_at_startup(req) {
				Ok(v) => v,
				Err(e) => {
					out.errors.push((label, e.message));
					continue;
				}
			};
			if let Some((other, other_label)) = specs.iter().find(|(s, _)| overlaps(s, &spec)) {
				out.errors.push((label, format!("{} overlaps with {} ({other_label})", spec.key, other.key)));
				continue;
			}
			if let Some(api) = self.reserved_clash(&spec) {
				out.errors.push((label, format!("{} would take the control API ({api})", spec.key)));
				continue;
			}
			let missing_reported = missing.is_some();
			if let Some(missing) = missing {
				out.warnings.push((
					label.clone(),
					format!("cannot run with this build or these permissions (it would be registered as failed): {missing}"),
				));
			}
			match self.build_parts(&spec) {
				Ok(_) => out.ok += 1,
				// the part this build cannot run is the warning above
				Err(e) if missing_reported && e.code == "unsupported" => {}
				Err(e) => out.errors.push((label.clone(), e.message)),
			}
			specs.push((spec, label));
		}
		// expiry of every certificate the rules use; a rule whose server
		// certificates have all expired is already an error from build_tls
		let now = tlsconf::unix_now();
		let warn = self.certs.warn_secs();
		let mut seen = HashSet::new();
		for (spec, label) in &specs {
			for (role, source) in self.sources(&spec.tls) {
				if !seen.insert(source.clone()) {
					continue;
				}
				out.files.extend(source.files().into_iter().map(str::to_string));
				let Some(not_after) = self.certs.not_after(&source) else { continue };
				let file = source.file().to_string();
				let when = certstore::rfc3339(not_after);
				let server = role == tlsconf::CertRole::Certificate;
				let role = serde_json::to_value(role).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
				match certstore::CertState::of(not_after, now, warn) {
					// a server certificate that has expired is not used (#115): a mistake to fix
					certstore::CertState::Expired if server => {
						let msg = format!("{file} ({role}) expired at {when}");
						if !out.errors.iter().any(|(l, m)| l == label && m.contains(&file)) {
							out.errors.push((label.clone(), msg));
						}
					}
					// CA and client certificates towards backends only warn when running
					certstore::CertState::Expired => out.warnings.push((label.clone(), format!("{file} ({role}) expired at {when}"))),
					certstore::CertState::Expiring => out.warnings.push((label.clone(), format!("{file} ({role}) expires at {when}"))),
					certstore::CertState::Ok => {}
				}
			}
		}
		out
	}

	/// Starts one rule of the settings file; false if it ended up failed.
	async fn start_static(self: &Arc<Self>, spec: RuleSpec, missing: Option<String>, phase: &'static str) -> bool {
		let key = spec.key;
		if let Some(missing) = missing {
			error!(event = "rule.failed", rule = %key, error = %missing, phase);
			self.insert_failed(spec, missing, false).await;
			return false;
		}
		match self.create_spec(spec.clone()).await {
			Ok(_) => true,
			Err(e) => {
				error!(event = "rule.failed", rule = %key, error = %e.message, phase);
				// a rule made through the API already holds the key: leave it alone
				if e.code != "already_exists" {
					self.insert_failed(spec, e.message, e.code == "resolve_failed").await;
				}
				false
			}
		}
	}

	/// Applies a changed settings file: validates all of its rules first (a
	/// mistake changes nothing), then stops removed rules, starts new ones,
	/// changes the rest in place where PATCH could (keeping connections) or
	/// re-creates them, and leaves unchanged rules alone.
	pub async fn reload_static(self: &Arc<Self>, reqs: Vec<(String, RuleRequest)>) -> Result<ReloadCounts, String> {
		let specs = self.validate_static(reqs)?;
		let current: HashMap<Key, (RuleSpec, bool)> = self
			.rules
			.lock()
			.await
			.iter()
			.filter(|(_, e)| e.spec().origin == Origin::Static)
			.map(|(k, e)| (*k, (e.spec().clone(), matches!(e, Entry::Running(_)))))
			.collect();
		let mut counts = ReloadCounts::default();

		// removed first, so a rule that moved to another key or range does not overlap itself
		let wanted: std::collections::HashSet<Key> = specs.iter().map(|(s, _)| s.key).collect();
		for key in current.keys().filter(|k| !wanted.contains(k)) {
			let entry = self.rules.lock().await.remove(key);
			if let Some(entry) = entry {
				self.stop_entry(key, entry, None).await;
				info!(event = "rule.delete", rule = %key, phase = "reload");
				counts.removed += 1;
			}
		}
		for (spec, missing) in specs {
			let key = spec.key;
			match current.get(&key) {
				None => {
					counts.added += 1;
					if !self.start_static(spec, missing, "reload").await {
						counts.failed += 1;
					}
				}
				Some((old, _)) if *old == spec => counts.unchanged += 1,
				Some((old, running)) => {
					counts.changed += 1;
					let in_place = *running
						&& missing.is_none()
						&& old.port_count == spec.port_count
						&& old.source_ip == spec.source_ip
						&& old.http.is_some() == spec.http.is_some()
						&& !(is_dual_stack_wildcard(&key) && old.v6only() != spec.v6only());
					if in_place {
						let tls_changed =
							old.tls != spec.tls || old.starttls != spec.starttls || old.starttls_required != spec.starttls_required;
						let http_changed = old.http != spec.http;
						match self.apply(&key, spec.clone(), tls_changed, http_changed).await {
							Ok(_) => continue,
							Err(e) => warn!(event = "rule.update", rule = %key, error = %e.message, phase = "reload",
								"could not change in place; re-creating"),
						}
					}
					let entry = self.rules.lock().await.remove(&key);
					if let Some(entry) = entry {
						self.stop_entry(&key, entry, None).await;
					}
					if !self.start_static(spec, missing, "reload").await {
						counts.failed += 1;
					}
				}
			}
		}
		self.gc_certs().await;
		Ok(counts)
	}

	/// Remembers how the settings file was last read, for `GET /config`.
	pub fn set_config_status(&self, status: ConfigStatus) {
		*self.config_status.write().unwrap() = Some(status);
	}

	pub fn config_status(&self) -> Option<ConfigStatus> {
		self.config_status.read().unwrap().clone()
	}

	pub async fn metrics(&self) -> String {
		let rules = self.rules.lock().await;
		let mut out = String::new();
		let running = rules.values().filter(|e| matches!(e, Entry::Running(_))).count();
		let _ = writeln!(out, "# HELP rproxy_rules Number of rules by state.");
		let _ = writeln!(out, "# TYPE rproxy_rules gauge");
		let _ = writeln!(out, "rproxy_rules{{state=\"running\"}} {running}");
		let _ = writeln!(out, "rproxy_rules{{state=\"failed\"}} {}", rules.len() - running);

		let mut lines: [(&str, &str, &str, Vec<String>); 6] = [
			("rproxy_rule_up", "gauge", "1 if the rule is running.", vec![]),
			("rproxy_connections", "gauge", "Open TCP connections or UDP sessions.", vec![]),
			("rproxy_connections_total", "counter", "TCP connections or UDP sessions handled.", vec![]),
			("rproxy_bytes_total", "counter", "Bytes forwarded; rx is client to backend.", vec![]),
			("rproxy_tls_failures_total", "counter", "Failed TLS / DTLS handshakes and STARTTLS dialogues.", vec![]),
			("rproxy_udp_dropped_total", "counter", "UDP datagrams rproxy could not pass on (a session queue full, or sending failed).", vec![]),
		];
		for (key, entry) in rules.iter() {
			let labels = format!("protocol=\"{}\",listen=\"{}\"", key.protocol, key.listen);
			match entry {
				Entry::Running(r) => {
					let s = &r.rt.stats;
					lines[4].3.push(format!("{{{labels}}} {}", s.tls_failures.load(Ordering::Relaxed)));
					if key.protocol == Protocol::Udp {
						lines[5].3.push(format!("{{{labels}}} {}", s.dropped.load(Ordering::Relaxed)));
					}
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
		target_metrics(&mut out, &rules);
		http_metrics(&mut out, &rules);
		self.cert_metrics(&mut out, &rules);
		if let Some(b) = self.cfg.http.crowdsec() {
			let _ = writeln!(out, "# HELP rproxy_crowdsec_decisions Addresses and ranges blocked by the CrowdSec LAPI decisions.");
			let _ = writeln!(out, "# TYPE rproxy_crowdsec_decisions gauge");
			let _ = writeln!(out, "rproxy_crowdsec_decisions {}", b.decision_count());
			let _ = writeln!(out, "# HELP rproxy_crowdsec_synced Whether the decisions have been pulled from the LAPI at least once.");
			let _ = writeln!(out, "# TYPE rproxy_crowdsec_synced gauge");
			let _ = writeln!(out, "rproxy_crowdsec_synced {}", u8::from(b.synced()));
			let status = b.status();
			let _ = writeln!(out, "# HELP rproxy_crowdsec_connected Whether the last pull of the decisions from the LAPI succeeded.");
			let _ = writeln!(out, "# TYPE rproxy_crowdsec_connected gauge");
			let _ = writeln!(out, "rproxy_crowdsec_connected {}", u8::from(status.connected));
			if let Some(at) = status.last_success {
				let _ = writeln!(out, "# HELP rproxy_crowdsec_last_success_timestamp_seconds Unix time of the last successful pull from the LAPI.");
				let _ = writeln!(out, "# TYPE rproxy_crowdsec_last_success_timestamp_seconds gauge");
				let _ = writeln!(out, "rproxy_crowdsec_last_success_timestamp_seconds {at}");
			}
		}
		let _ = writeln!(out, "# HELP rproxy_log_suppressed_total Log lines left out so that refusals under attack do not flood the log (UDP conn.denied, control API audit).");
		let _ = writeln!(out, "# TYPE rproxy_log_suppressed_total counter");
		let _ = writeln!(out, "rproxy_log_suppressed_total {}", crate::logging::suppressed_total());
		out
	}
}

impl Registry {
	/// Seconds until each certificate a rule uses expires (negative once
	/// expired), and the control API's.
	fn cert_metrics(&self, out: &mut String, rules: &HashMap<Key, Entry>) {
		let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
		let now = tlsconf::unix_now();
		let mut samples = vec![];
		for (key, entry) in rules {
			for (role, source) in self.sources(&entry.spec().tls) {
				if let Some(not_after) = self.certs.not_after(&source) {
					samples.push(format!(
						"{{protocol=\"{}\",listen=\"{}\",role=\"{}\",file=\"{}\"}} {}",
						key.protocol,
						key.listen,
						role.as_str(),
						esc(source.file()),
						not_after - now
					));
				}
			}
		}
		for (role, file, not_after) in self.certs.external() {
			samples.push(format!("{{role=\"{}\",file=\"{}\"}} {}", role.as_str(), esc(&file), not_after - now));
		}
		if samples.is_empty() {
			return;
		}
		samples.sort();
		let _ = writeln!(out, "# HELP rproxy_cert_expiry_seconds Seconds until the certificate expires (negative once expired).");
		let _ = writeln!(out, "# TYPE rproxy_cert_expiry_seconds gauge");
		for sample in samples {
			let _ = writeln!(out, "rproxy_cert_expiry_seconds{sample}");
		}
	}
}

/// Targets of L4 rules with several targets or a health check.
fn target_metrics(out: &mut String, rules: &HashMap<Key, Entry>) {
	let mut up = vec![];
	let mut conns = vec![];
	let mut all_down = vec![];
	let mut keys: Vec<&Key> = rules.keys().collect();
	keys.sort_by_key(|k| (k.protocol.to_string(), k.listen));
	for key in keys {
		let Some(Entry::Running(r)) = rules.get(key) else { continue };
		let pool = r.rt.pool();
		if !pool.reported {
			continue;
		}
		all_down.push(format!("rproxy_rule_all_targets_down{{protocol=\"{}\",listen=\"{}\"}} {}", key.protocol, key.listen, u8::from(pool.all_down())));
		for t in pool.status() {
			let target = crate::core::balance::TargetSpec { addr: t.addr.clone(), port: t.port, weight: None, backup: false }.remote();
			let labels = format!("protocol=\"{}\",listen=\"{}\",target=\"{}\"", key.protocol, key.listen, target.replace('"', "\\\""));
			up.push(format!("rproxy_target_up{{{labels}}} {}", u8::from(t.up)));
			conns.push(format!("rproxy_target_connections{{{labels}}} {}", t.connections));
		}
	}
	let _ = writeln!(out, "# HELP rproxy_target_up Targets of rules with several targets or a health check: 1 up, 0 down.");
	let _ = writeln!(out, "# TYPE rproxy_target_up gauge");
	for line in up {
		let _ = writeln!(out, "{line}");
	}
	let _ = writeln!(out, "# HELP rproxy_rule_all_targets_down Rules with several targets or a health check: 1 when every target is down.");
	let _ = writeln!(out, "# TYPE rproxy_rule_all_targets_down gauge");
	for line in all_down {
		let _ = writeln!(out, "{line}");
	}
	let _ = writeln!(out, "# HELP rproxy_target_connections Open TCP connections or UDP sessions per target.");
	let _ = writeln!(out, "# TYPE rproxy_target_connections gauge");
	for line in conns {
		let _ = writeln!(out, "{line}");
	}
}

/// Requests of `http` rules: a counter by route and status class, and a duration
/// histogram by route. Routes are named in the settings, so the labels stay few.
fn http_metrics(out: &mut String, rules: &HashMap<Key, Entry>) {
	use crate::l7::access::{BUCKETS, CLASSES};
	let mut requests = vec![];
	let mut durations = vec![];
	let mut limited = vec![];
	let mut blocked = vec![];
	let mut up = vec![];
	let mut service_down = vec![];
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
		if let Some(router) = r.rt.http_router() {
			for (service, servers) in router.health() {
				service_down.push(format!(
					"rproxy_http_service_down{{protocol=\"{}\",listen=\"{}\",service=\"{}\"}} {}",
					key.protocol,
					key.listen,
					esc(&service),
					u8::from(!servers.iter().any(|s| s.up))
				));
				for s in servers {
					up.push(format!(
						"rproxy_http_server_up{{protocol=\"{}\",listen=\"{}\",service=\"{}\",server=\"{}\"}} {}",
						key.protocol,
						key.listen,
						esc(&service),
						esc(&s.url),
						u8::from(s.up)
					));
				}
			}
		}
	}
	let _ = writeln!(out, "# HELP rproxy_http_server_up Servers of http services with health_check: 1 up, 0 down.");
	let _ = writeln!(out, "# TYPE rproxy_http_server_up gauge");
	for line in up {
		let _ = writeln!(out, "{line}");
	}
	let _ = writeln!(out, "# HELP rproxy_http_service_down Services of http rules with health_check: 1 when no server is up.");
	let _ = writeln!(out, "# TYPE rproxy_http_service_down gauge");
	for line in service_down {
		let _ = writeln!(out, "{line}");
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
	use crate::core::rule::RuleRequest;

	/// One socket per UDP port unless asked for more (#194); a range is capped.
	#[test]
	fn udp_shards_default_to_one() {
		if std::env::var_os("RPROXY_UDP_SHARDS").is_none() {
			assert_eq!(udp_shards(1), 1);
		}
		force_udp_shards(8);
		assert_eq!((udp_shards(1), udp_shards(16), udp_shards(10_000)), (8, 4, 1));
		force_udp_shards(0);
	}

	fn registry() -> Arc<Registry> {
		Registry::new(Config {
			dns_interval: Duration::from_secs(30),
			lookup: resolve::system_lookup(),
			transparent: false,
			transparent_ipv6: false,
			max_range_ports: crate::core::rule::DEFAULT_MAX_RANGE_PORTS,
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
