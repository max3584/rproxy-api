//! Several destinations for one L4 rule (#98): `targets`, `balance`
//! (round robin, least connections, failover) and TCP `health_check`.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::core::outlier::{self, Ejection, L4Outlier};
use crate::core::rule::{validate_remote, Key, Protocol};
use crate::error::ApiError;

/// Targets one rule may have.
pub const MAX_TARGETS: usize = 64;
/// How long a target that refused a connection is skipped (without `health_check`,
/// or until the next check says otherwise): the default `outlier_detection.ejection_time`.
pub const FAIL_COOLDOWN: Duration = Duration::from_secs(10);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// How new connections (TCP) or sessions (UDP) are spread over the targets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
	/// In turn, in proportion to `weight`.
	#[default]
	RoundRobin,
	/// The target with the fewest open connections for its `weight`.
	LeastConn,
	/// The first target (in order) that is up.
	Failover,
}

impl Balance {
	pub fn is_default(&self) -> bool {
		*self == Balance::RoundRobin
	}

	pub fn as_str(&self) -> &'static str {
		match self {
			Balance::RoundRobin => "round_robin",
			Balance::LeastConn => "least_conn",
			Balance::Failover => "failover",
		}
	}
}

/// One destination of a rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSpec {
	pub addr: String,
	pub port: u16,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub weight: Option<u32>,
	/// Used only while every other target is down.
	#[serde(default, skip_serializing_if = "std::ops::Not::not")]
	pub backup: bool,
	/// Connections (TCP) or sessions (UDP) the target takes at once (#341): a full
	/// target is skipped like one that is down; when all are full, new ones are refused.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub max_connections: Option<u32>,
}

impl TargetSpec {
	pub fn weight(&self) -> u64 {
		u64::from(self.weight.unwrap_or(1).max(1))
	}

	/// `host:port` for name resolution (IPv6 in brackets).
	pub fn remote(&self) -> String {
		match self.addr.parse::<IpAddr>() {
			Ok(IpAddr::V6(ip)) => SocketAddr::new(IpAddr::V6(ip), self.port).to_string(),
			_ => format!("{}:{}", self.addr, self.port),
		}
	}
}

/// `health_check` of an L4 rule: a TCP connection must succeed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckSpec {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub interval: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub timeout: Option<String>,
	/// Port to connect to instead of each target's own (required for udp rules).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub port: Option<u16>,
}

impl HealthCheckSpec {
	fn duration(value: Option<&String>, default: Duration, what: &str) -> Result<Duration, ApiError> {
		match value {
			Some(v) => crate::l7::parse_duration(v).map_err(|e| ApiError::invalid(format!("health_check.{what}: {e}"))),
			None => Ok(default),
		}
	}

	pub fn interval(&self) -> Duration {
		Self::duration(self.interval.as_ref(), DEFAULT_INTERVAL, "interval").unwrap_or(DEFAULT_INTERVAL).max(Duration::from_millis(100))
	}

	pub fn timeout(&self) -> Duration {
		Self::duration(self.timeout.as_ref(), DEFAULT_TIMEOUT, "timeout").unwrap_or(DEFAULT_TIMEOUT).max(Duration::from_millis(10))
	}

	pub fn validate(&self, protocol: Protocol) -> Result<(), ApiError> {
		Self::duration(self.interval.as_ref(), DEFAULT_INTERVAL, "interval")?;
		Self::duration(self.timeout.as_ref(), DEFAULT_TIMEOUT, "timeout")?;
		if self.port == Some(0) {
			return Err(ApiError::invalid("health_check.port must be 1-65535"));
		}
		if protocol == Protocol::Udp && self.port.is_none() {
			return Err(ApiError::invalid("health_check on a udp rule needs port (a TCP port on the targets to connect to)"));
		}
		Ok(())
	}
}

/// Checks `targets` and normalizes their addresses; `port_count` is the length
/// of the rule's port range (each target's port moves up with it).
pub fn validate_targets(targets: &mut [TargetSpec], port_count: u16) -> Result<(), ApiError> {
	if targets.len() > MAX_TARGETS {
		return Err(ApiError::invalid(format!("a rule may have at most {MAX_TARGETS} targets")));
	}
	for (i, t) in targets.iter_mut().enumerate() {
		t.addr = validate_remote(&t.addr, t.port).map_err(|e| ApiError::invalid(format!("targets[{i}]: {}", e.message)))?;
		if t.weight == Some(0) {
			return Err(ApiError::invalid(format!("targets[{i}]: weight must be at least 1")));
		}
		if t.max_connections == Some(0) {
			return Err(ApiError::invalid(format!("targets[{i}]: max_connections must be at least 1")));
		}
		if u32::from(t.port) + u32::from(port_count) - 1 > 65_535 {
			return Err(ApiError::invalid(format!("targets[{i}]: port + range length exceeds 65535")));
		}
	}
	if !targets.is_empty() && targets.iter().all(|t| t.backup) {
		return Err(ApiError::invalid("at least one target must not be a backup"));
	}
	Ok(())
}

/// A target at run time.
pub struct Member {
	pub spec: TargetSpec,
	/// Resolved addresses (re-resolved in the background for host names).
	pub addrs: watch::Receiver<Vec<SocketAddr>>,
	/// Kept so `addrs` stays open for IP literals, which have no resolver task.
	_addrs_tx: Arc<watch::Sender<Vec<SocketAddr>>>,
	/// Open connections (TCP) or sessions (UDP) on this target. Shared with the target of
	/// the same address in the pool this one replaced (`Member::new`), so the connections
	/// still open there count against `max_connections` too.
	pub active: Arc<AtomicU64>,
	/// `max_connections` (0: none).
	max: u64,
	pub total: AtomicU64,
	/// What the last health check said (true without checks).
	healthy: AtomicBool,
	/// Skipped while ejected by `outlier_detection` (by default after one refused connection).
	pub ejection: Arc<Ejection>,
}

impl Member {
	/// A target; `active` is the count of the same target in the pool replaced, if any
	/// (`Pool::counter_for`), so it goes on.
	pub fn new(spec: TargetSpec, addrs_tx: Arc<watch::Sender<Vec<SocketAddr>>>, active: Option<Arc<AtomicU64>>) -> Member {
		Member {
			max: spec.max_connections.map_or(0, u64::from),
			spec,
			addrs: addrs_tx.subscribe(),
			_addrs_tx: addrs_tx,
			active: active.unwrap_or_default(),
			total: AtomicU64::new(0),
			healthy: AtomicBool::new(true),
			ejection: Arc::default(),
		}
	}

	pub fn is_up(&self) -> bool {
		self.healthy.load(Ordering::Relaxed) && !self.ejection.is_ejected()
	}

	pub fn healthy(&self) -> bool {
		self.healthy.load(Ordering::Relaxed)
	}

	/// At its `max_connections` now (never without one).
	pub fn is_full(&self) -> bool {
		self.max != 0 && self.active.load(Ordering::Relaxed) >= self.max
	}

	/// The addresses to connect to on port `offset` of a range.
	pub fn addrs(&self, offset: u16) -> Vec<SocketAddr> {
		self.addrs.borrow().iter().map(|a| crate::core::proxy::shifted(*a, offset)).collect()
	}
}

/// The targets of a rule and how to choose among them. Replaced as a whole
/// when the rule's targets change.
pub struct Pool {
	pub members: Vec<Arc<Member>>,
	pub balance: Balance,
	next: AtomicU64,
	/// Bumped when a target goes up or down, or the pool is replaced (UDP
	/// sessions then move off targets that are down).
	events: Arc<watch::Sender<u64>>,
	/// Whether target states are worth reporting (several targets or a health check).
	pub reported: bool,
	/// Some target has `max_connections` (#341); without, `order` looks at no count.
	capped: bool,
	/// `outlier_detection` (the defaults without it); PATCH changes it in place.
	outlier: RwLock<L4Outlier>,
}

impl Pool {
	pub fn new(members: Vec<Arc<Member>>, balance: Balance, events: Arc<watch::Sender<u64>>, reported: bool) -> Pool {
		let capped = members.iter().any(|m| m.max != 0);
		Pool { members, balance, next: AtomicU64::new(0), events, reported, capped, outlier: RwLock::new(L4Outlier::default()) }
	}

	/// The count of open connections to hand on to the target `spec` of a pool that
	/// replaces this one: that of the first target of the same address and port not yet
	/// handed on (`taken`), so what is still open here counts against the new pool's caps.
	pub fn counter_for(&self, spec: &TargetSpec, taken: &mut Vec<usize>) -> Option<Arc<AtomicU64>> {
		let remote = spec.remote();
		let i = (0..self.members.len()).find(|i| !taken.contains(i) && self.members[*i].spec.remote() == remote)?;
		taken.push(i);
		Some(self.members[i].active.clone())
	}

	/// Some target has `max_connections`.
	pub fn capped(&self) -> bool {
		self.capped
	}

	/// Every target is at its `max_connections` (false without caps): new connections are refused.
	pub fn all_full(&self) -> bool {
		self.capped && self.members.iter().all(|m| m.is_full())
	}

	pub fn with_outlier(self, outlier: L4Outlier) -> Pool {
		self.set_outlier(outlier);
		self
	}

	/// New settings for the next connections; the targets' counts and ejections stay.
	pub fn set_outlier(&self, outlier: L4Outlier) {
		*self.outlier.write().unwrap_or_else(|e| e.into_inner()) = outlier;
	}

	pub fn outlier(&self) -> L4Outlier {
		*self.outlier.read().unwrap_or_else(|e| e.into_inner())
	}

	pub fn notify(&self) {
		self.events.send_modify(|n| *n = n.wrapping_add(1));
	}

	/// A connection to `member` was made (or, with `short_lived`, lasted long
	/// enough or was ended by the client): its run of failures ends.
	pub fn succeeded(&self, member: &Member) {
		member.ejection.record_l4(&self.outlier(), false);
	}

	/// A connection to `member` failed (`cause`: `connect`, `refused` for UDP's
	/// ICMP, `short_lived`): after `consecutive_failures` in a row it is ejected,
	/// unless that would eject more than `max_ejected_percent` of the targets.
	/// A target failing while ejected (tried because every target is out) has
	/// its ejection started over.
	pub fn failed(&self, key: &Key, member: &Arc<Member>, cause: &'static str, error: &str) {
		let cfg = self.outlier();
		let ejection = &member.ejection;
		let again = ejection.is_ejected();
		if !again {
			if !ejection.record_l4(&cfg, true) {
				return;
			}
			let ejected = self.members.iter().filter(|m| m.ejection.is_ejected()).count();
			if !cfg.ejecting.allows(ejected, self.members.len()) {
				tracing::debug!(event = "target.eject_skipped", rule = %key, target = %member.spec.remote(), cause, ejected,
					max_ejected_percent = cfg.ejecting.max_percent);
				return;
			}
		}
		let was_up = member.is_up();
		let (length, until) = ejection.eject(&cfg.ejecting);
		if was_up {
			if self.reported {
				warn!(event = "target.down", rule = %key, target = %member.spec.remote(), reason = "outlier", cause, error = %error,
					ejection_secs = length.as_secs_f64(), ejections = ejection.ejections());
			}
			self.notify();
		}
		let (weak, events, key, reported) = (Arc::downgrade(member), self.events.clone(), *key, self.reported);
		outlier::after(ejection, until, length, move || {
			let Some(member) = weak.upgrade() else { return };
			if member.healthy() {
				if reported {
					info!(event = "target.up", rule = %key, target = %member.spec.remote(), reason = "outlier");
				}
				events.send_modify(|n| *n = n.wrapping_add(1));
			}
		});
	}

	/// A relayed TCP connection to `member` ended after `lived`; `backend_first`:
	/// the backend ended it. With `short_lived`, that is a failure when sooner.
	pub fn ended(&self, key: &Key, member: &Arc<Member>, lived: Duration, backend_first: bool) {
		let short = self.outlier().short_lived;
		if short.is_zero() {
			return;
		}
		if backend_first && lived < short {
			self.failed(key, member, "short_lived", &format!("closed by the target after {} ms", lived.as_millis()));
		} else {
			self.succeeded(member);
		}
	}

	/// The targets to try for a new connection, best first: the one `balance`
	/// picks among those up, the other targets that are up, backups that are up,
	/// then everything else (so a connection is never refused just because every
	/// target is marked down). A target at its `max_connections` (#341) is skipped
	/// like one that is down, and comes last of all: `Lease::take` refuses it unless
	/// a connection has ended in the meantime (with `failover`, targets fill up in
	/// order, and backups take what the full primaries cannot).
	pub fn order(&self) -> Vec<Arc<Member>> {
		let n = self.members.len();
		if n > 64 {
			return self.order_slow();
		}
		// each target looked at once: the sets as bits (at most `MAX_TARGETS`), one allocation (the result)
		let (mut open, mut up, mut backup) = (0u64, 0u64, 0u64);
		for (i, m) in self.members.iter().enumerate() {
			let bit = 1u64 << i;
			// one branch per target without caps
			if !self.capped || !m.is_full() {
				open |= bit;
				if m.is_up() {
					up |= bit;
				}
			}
			if m.spec.backup {
				backup |= bit;
			}
		}
		let (primary, backups) = (up & !backup, up & backup);
		let mut eligible = [0usize; 64];
		let mut k = 0;
		for i in bits(if primary != 0 { primary } else { backups }) {
			eligible[k] = i;
			k += 1;
		}
		let eligible = &eligible[..k];
		let mut out = Vec::with_capacity(n);
		let mut placed = 0u64;
		let mut push = |i: usize| {
			if placed & (1u64 << i) == 0 {
				placed |= 1u64 << i;
				out.push(self.members[i].clone());
			}
		};
		if let Some(first) = self.choose(eligible) {
			// the rest of the eligible ones, continuing after the chosen one
			let at = eligible.iter().position(|&i| i == first).unwrap_or(0);
			for &i in eligible[at..].iter().chain(&eligible[..at]) {
				push(i);
			}
		}
		let all = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
		for i in bits(primary).chain(bits(backups)).chain(bits(open)) {
			push(i);
		}
		if self.capped {
			for i in bits(all) {
				push(i);
			}
		}
		out
	}

	/// `order` for more targets than a u64 has bits (not reached: `MAX_TARGETS`).
	fn order_slow(&self) -> Vec<Arc<Member>> {
		let open = |i: usize| !self.capped || !self.members[i].is_full();
		let up: Vec<usize> = (0..self.members.len()).filter(|&i| self.members[i].is_up() && open(i)).collect();
		let primary: Vec<usize> = up.iter().copied().filter(|&i| !self.members[i].spec.backup).collect();
		let backup: Vec<usize> = up.iter().copied().filter(|&i| self.members[i].spec.backup).collect();
		let eligible = if primary.is_empty() { &backup } else { &primary };
		let mut order: Vec<usize> = vec![];
		if let Some(first) = self.choose(eligible) {
			order.push(first);
			let at = eligible.iter().position(|&i| i == first).unwrap_or(0);
			order.extend(eligible[at + 1..].iter().chain(&eligible[..at]).copied());
		}
		for i in primary.iter().chain(&backup).copied().chain(0..self.members.len()) {
			if !order.contains(&i) && open(i) {
				order.push(i);
			}
		}
		if self.capped {
			for i in 0..self.members.len() {
				if !order.contains(&i) {
					order.push(i);
				}
			}
		}
		order.into_iter().map(|i| self.members[i].clone()).collect()
	}

	fn choose(&self, eligible: &[usize]) -> Option<usize> {
		if eligible.is_empty() {
			return None;
		}
		match self.balance {
			Balance::Failover => eligible.first().copied(),
			Balance::RoundRobin => {
				let total: u64 = eligible.iter().map(|&i| self.members[i].spec.weight()).sum();
				let mut n = self.next.fetch_add(1, Ordering::Relaxed) % total;
				for &i in eligible {
					let w = self.members[i].spec.weight();
					if n < w {
						return Some(i);
					}
					n -= w;
				}
				eligible.first().copied()
			}
			Balance::LeastConn => {
				// ties go round, so idle targets share new connections evenly
				let start = self.next.fetch_add(1, Ordering::Relaxed) as usize % eligible.len();
				let rotated = eligible[start..].iter().chain(&eligible[..start]);
				rotated
					.min_by(|&&a, &&b| {
						let (ma, mb) = (&self.members[a], &self.members[b]);
						// active / weight, compared without division
						let la = u128::from(ma.active.load(Ordering::Relaxed)) * u128::from(mb.spec.weight());
						let lb = u128::from(mb.active.load(Ordering::Relaxed)) * u128::from(ma.spec.weight());
						la.cmp(&lb)
					})
					.copied()
			}
		}
	}

	/// Whether `member` belongs to this pool.
	pub fn contains(&self, member: &Arc<Member>) -> bool {
		self.members.iter().any(|m| Arc::ptr_eq(m, member))
	}

	/// Every target is down (only meaningful when `reported`).
	pub fn all_down(&self) -> bool {
		self.reported && !self.members.is_empty() && !self.members.iter().any(|m| m.is_up())
	}

	pub fn status(&self) -> Vec<TargetStatus> {
		self.members
			.iter()
			.map(|m| TargetStatus {
				addr: m.spec.addr.clone(),
				port: m.spec.port,
				backup: m.spec.backup,
				up: m.is_up(),
				connections: m.active.load(Ordering::Relaxed),
				max_connections: m.spec.max_connections,
				full: m.is_full(),
				total_connections: m.total.load(Ordering::Relaxed),
				resolved: m.addrs.borrow().iter().map(|a| a.to_string()).collect(),
				ejected_until: m.ejection.ejected_until(),
				ejections: m.ejection.ejections(),
			})
			.collect()
	}
}

/// The places of the bits set in `mask`, lowest first.
fn bits(mut mask: u64) -> impl Iterator<Item = usize> {
	std::iter::from_fn(move || {
		if mask == 0 {
			return None;
		}
		let i = mask.trailing_zeros() as usize;
		mask &= mask - 1;
		Some(i)
	})
}

/// State of one target (`stats.targets` of the rule view).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TargetStatus {
	pub addr: String,
	pub port: u16,
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	pub backup: bool,
	pub up: bool,
	pub connections: u64,
	/// The target's `max_connections` (#341); `connections` counts against it.
	#[serde(skip_serializing_if = "Option::is_none")]
	pub max_connections: Option<u32>,
	/// At `max_connections` now: skipped for new connections (#341).
	pub full: bool,
	pub total_connections: u64,
	pub resolved: Vec<String>,
	/// Ejected by `outlier_detection` until then, in Unix seconds; null when not (#170).
	pub ejected_until: Option<u64>,
	/// Times `outlier_detection` ejected the target (#170).
	pub ejections: u64,
}

/// Every target that could take a connection is at its `max_connections` (#341):
/// the connection is refused (`limits::Reason::TargetFull`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetFull;

impl std::fmt::Display for TargetFull {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("every target is at its max_connections")
	}
}

impl std::error::Error for TargetFull {}

impl TargetFull {
	/// As an I/O error, for the TCP connect path (`is`).
	pub fn io() -> std::io::Error {
		std::io::Error::other(TargetFull)
	}

	pub fn is(e: &std::io::Error) -> bool {
		e.get_ref().is_some_and(|inner| inner.is::<TargetFull>())
	}
}

/// A connection or session counted on a target while it lasts: whichever way it
/// ends (closed, failed, the rule stopped, a UDP session gone idle or moved to
/// another target), dropping the lease gives its place back.
pub struct Lease(Arc<Member>);

impl Lease {
	/// Counts a connection on `member`; None when it is at its `max_connections` (#341).
	/// The count and the check are one atomic step, so a target never takes more.
	pub fn take(member: Arc<Member>) -> Option<Lease> {
		if member.max == 0 {
			member.active.fetch_add(1, Ordering::Relaxed);
		} else {
			let mut n = member.active.load(Ordering::Relaxed);
			loop {
				if n >= member.max {
					return None;
				}
				match member.active.compare_exchange_weak(n, n + 1, Ordering::Relaxed, Ordering::Relaxed) {
					Ok(_) => break,
					Err(now) => n = now,
				}
			}
		}
		member.total.fetch_add(1, Ordering::Relaxed);
		Some(Lease(member))
	}

	pub fn member(&self) -> &Arc<Member> {
		&self.0
	}

	/// The target in `pool` (one that replaced this lease's) that took this one's count
	/// on (`Pool::counter_for`) and is up: the connection stays there, counted as it is.
	pub fn carried_to(&self, pool: &Pool) -> Option<Arc<Member>> {
		pool.members.iter().find(|m| Arc::ptr_eq(&m.active, &self.0.active) && m.is_up()).cloned()
	}

	/// Moves the lease to `to`, which shares its count (`carried_to`).
	pub fn move_to(&mut self, to: Arc<Member>) {
		debug_assert!(Arc::ptr_eq(&to.active, &self.0.active));
		if Arc::ptr_eq(&to.active, &self.0.active) {
			self.0 = to;
		}
	}
}

impl Drop for Lease {
	fn drop(&mut self) {
		self.0.active.fetch_sub(1, Ordering::Relaxed);
	}
}

/// Probes every target of `pool` until `stop`: a target is up while a TCP
/// connection to it (or to `health_check.port`) succeeds within the timeout.
pub fn spawn_health_checks(key: Key, pool: Arc<Pool>, check: HealthCheckSpec, stop: CancellationToken) {
	let (interval, timeout) = (check.interval(), check.timeout());
	tokio::spawn(async move {
		loop {
			let probes = pool.members.iter().map(|m| probe(m, check.port, timeout));
			let results = futures_util::future::join_all(probes).await;
			let mut changed = false;
			for (m, (up, why)) in pool.members.iter().zip(results) {
				if m.healthy.swap(up, Ordering::Relaxed) != up {
					changed = true;
					if up {
						// a recovered target is used again at once
						m.ejection.clear();
						info!(event = "target.up", rule = %key, target = %m.spec.remote(), reason = "health_check");
					} else {
						warn!(event = "target.down", rule = %key, target = %m.spec.remote(), error = %why, reason = "health_check");
					}
				}
			}
			if changed {
				pool.notify();
			}
			tokio::select! {
				_ = stop.cancelled() => return,
				_ = tokio::time::sleep(interval) => {}
			}
		}
	});
}

async fn probe(member: &Member, port: Option<u16>, timeout: Duration) -> (bool, String) {
	let addrs: Vec<SocketAddr> = member.addrs.borrow().clone();
	if addrs.is_empty() {
		return (false, "not resolved".into());
	}
	let mut last = String::new();
	for addr in addrs {
		let addr = SocketAddr::new(addr.ip(), port.unwrap_or(addr.port()));
		match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
			Ok(Ok(_)) => return (true, String::new()),
			Ok(Err(e)) => last = format!("{addr}: {e}"),
			Err(_) => last = format!("{addr}: timed out"),
		}
	}
	(false, last)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pool(balance: Balance, targets: &[(u16, u32, bool)]) -> Pool {
		capped(balance, &targets.iter().map(|&(port, weight, backup)| (port, weight, backup, None)).collect::<Vec<_>>(), None)
	}

	/// Targets with `max_connections`; `before`: the pool this one replaces.
	fn capped(balance: Balance, targets: &[(u16, u32, bool, Option<u32>)], before: Option<&Pool>) -> Pool {
		let mut taken = vec![];
		let members = targets
			.iter()
			.map(|&(port, weight, backup, max_connections)| {
				let spec = TargetSpec { addr: "127.0.0.1".into(), port, weight: Some(weight), backup, max_connections };
				let (tx, _) = watch::channel(vec![SocketAddr::from(([127, 0, 0, 1], port))]);
				let active = before.and_then(|p| p.counter_for(&spec, &mut taken));
				Arc::new(Member::new(spec, Arc::new(tx), active))
			})
			.collect();
		Pool::new(members, balance, Arc::new(watch::channel(0).0), true)
	}

	/// What a connection gets: the first target of `order` that `Lease::take` lets in.
	fn connect(p: &Pool) -> Option<Lease> {
		p.order().into_iter().find_map(Lease::take)
	}

	fn ports(leases: &[Lease]) -> Vec<u16> {
		leases.iter().map(|l| l.member().spec.port).collect()
	}

	fn first(p: &Pool) -> u16 {
		p.order()[0].spec.port
	}

	fn key() -> Key {
		Key { protocol: Protocol::Tcp, listen: "127.0.0.1:1".parse().unwrap() }
	}

	#[test]
	fn round_robin_follows_the_weights() {
		let p = pool(Balance::RoundRobin, &[(1, 3, false), (2, 1, false)]);
		let picks: Vec<u16> = (0..8).map(|_| first(&p)).collect();
		assert_eq!(picks.iter().filter(|&&x| x == 1).count(), 6, "{picks:?}");
		// the others follow as fallbacks
		assert_eq!(p.order().len(), 2);
	}

	#[test]
	fn least_conn_takes_the_emptiest_target_for_its_weight() {
		let p = pool(Balance::LeastConn, &[(1, 1, false), (2, 1, false), (3, 2, false)]);
		let _a = Lease::take(p.members[0].clone()).unwrap();
		let _b = Lease::take(p.members[1].clone()).unwrap();
		let _c = Lease::take(p.members[2].clone()).unwrap();
		// 1/1, 1/1, 1/2: the weighted one is emptiest
		assert_eq!(first(&p), 3);
		drop(_a);
		assert_eq!(first(&p), 1);
		assert_eq!(p.members[0].total.load(Ordering::Relaxed), 1);
	}

	#[test]
	fn failover_uses_the_first_target_that_is_up() {
		let p = pool(Balance::Failover, &[(1, 1, false), (2, 1, false), (3, 1, true)]);
		assert!((0..4).all(|_| first(&p) == 1));
		p.failed(&key(), &p.members[0], "connect", "refused");
		assert_eq!(first(&p), 2);
		p.members[1].healthy.store(false, Ordering::Relaxed);
		assert_eq!(first(&p), 3, "the backup when every other target is down");
		p.members[2].healthy.store(false, Ordering::Relaxed);
		let order: Vec<u16> = p.order().iter().map(|m| m.spec.port).collect();
		assert_eq!(order, vec![1, 2, 3], "all down: still tried in order");
		p.members[0].ejection.clear();
		assert_eq!(first(&p), 1, "back to the first once it is up again");
	}

	#[test]
	fn outlier_detection_counts_failures_and_keeps_some_targets() {
		let p = pool(Balance::RoundRobin, &[(1, 1, false), (2, 1, false), (3, 1, false), (4, 1, false)]).with_outlier(L4Outlier::new(Some(
			&crate::core::outlier::L4OutlierSpec { consecutive_failures: Some(2), max_ejected_percent: Some(50), ..Default::default() },
		)));
		p.failed(&key(), &p.members[0], "connect", "refused");
		assert!(p.members[0].is_up(), "one failure is not enough");
		p.succeeded(&p.members[0]);
		p.failed(&key(), &p.members[0], "connect", "refused");
		assert!(p.members[0].is_up(), "the run started over");
		p.failed(&key(), &p.members[0], "connect", "refused");
		assert!(!p.members[0].is_up());
		let status = p.status();
		assert_eq!((status[0].ejections, status[0].ejected_until.is_some()), (1, true));
		assert_eq!((status[1].ejections, status[1].ejected_until), (0, None));
		for m in &p.members[1..] {
			p.failed(&key(), m, "connect", "refused");
			p.failed(&key(), m, "connect", "refused");
		}
		let up = p.members.iter().filter(|m| m.is_up()).count();
		assert_eq!(up, 2, "max_ejected_percent: at most half of them");

		// short_lived: a connection the target ended too soon
		let p = pool(Balance::RoundRobin, &[(1, 1, false), (2, 1, false)])
			.with_outlier(L4Outlier::new(Some(&crate::core::outlier::L4OutlierSpec { short_lived: Some("1s".into()), ..Default::default() })));
		p.ended(&key(), &p.members[0], Duration::from_millis(10), false);
		assert!(p.members[0].is_up(), "ended by the client");
		p.ended(&key(), &p.members[0], Duration::from_secs(2), true);
		assert!(p.members[0].is_up(), "long enough");
		p.ended(&key(), &p.members[0], Duration::from_millis(10), true);
		assert!(!p.members[0].is_up());
	}

	#[test]
	fn failover_with_caps_fills_the_targets_in_order() {
		let p = capped(Balance::Failover, &[(1, 1, false, Some(2)), (2, 1, false, Some(1)), (3, 1, true, Some(1))], None);
		let mut held: Vec<Lease> = (0..4).map_while(|_| connect(&p)).collect();
		assert_eq!(ports(&held), [1, 1, 2, 3], "spillover: the first until full, then the next, the backup last");
		assert!(connect(&p).is_none(), "every target full: refused");
		assert!(p.all_full());
		let status = p.status();
		assert_eq!((status[0].connections, status[0].max_connections, status[0].full), (2, Some(2), true));
		// a connection to the first ends: the next one goes there again
		held.remove(0);
		assert!(!p.all_full());
		assert_eq!(connect(&p).map(|l| l.member().spec.port), Some(1));
	}

	#[test]
	fn round_robin_and_least_conn_skip_full_targets() {
		let p = capped(Balance::RoundRobin, &[(1, 1, false, Some(1)), (2, 1, false, None)], None);
		let held: Vec<Lease> = (0..6).map_while(|_| connect(&p)).collect();
		assert_eq!(ports(&held).iter().filter(|&&x| x == 1).count(), 1, "{:?}", ports(&held));
		assert_eq!(held.len(), 6, "the target without a cap takes the rest");

		let p = capped(Balance::LeastConn, &[(1, 1, false, Some(3)), (2, 1, false, Some(3))], None);
		let held: Vec<Lease> = (0..7).map_while(|_| connect(&p)).collect();
		assert_eq!(held.len(), 6);
		assert_eq!(ports(&held).iter().filter(|&&x| x == 2).count(), 3, "{:?}", ports(&held));
		drop(held);
		assert!(p.members.iter().all(|m| m.active.load(Ordering::Relaxed) == 0), "every place given back");
	}

	#[test]
	fn a_full_target_is_skipped_even_when_others_are_down() {
		let p = capped(Balance::RoundRobin, &[(1, 1, false, Some(1)), (2, 1, false, None)], None);
		p.members[1].healthy.store(false, Ordering::Relaxed);
		let first = connect(&p).unwrap();
		assert_eq!(first.member().spec.port, 1);
		let order: Vec<u16> = p.order().iter().map(|m| m.spec.port).collect();
		assert_eq!(order, [2, 1], "the down target is tried before the full one");
		assert_eq!(connect(&p).map(|l| l.member().spec.port), Some(2));
	}

	#[test]
	fn the_count_goes_on_in_a_pool_that_replaces_it() {
		let old = capped(Balance::RoundRobin, &[(1, 1, false, Some(2)), (2, 1, false, None)], None);
		let a = Lease::take(old.members[0].clone()).unwrap();
		let _b = Lease::take(old.members[0].clone()).unwrap();
		// PATCH: another target in front, the same one with the same cap
		let new = capped(Balance::Failover, &[(3, 1, false, Some(1)), (1, 1, false, Some(2))], Some(&old));
		assert_eq!(new.members[1].active.load(Ordering::Relaxed), 2, "the old pool's connections count");
		let c = connect(&new).unwrap();
		assert_eq!(c.member().spec.port, 3);
		assert!(connect(&new).is_none(), "target 1 is still full with the old pool's connections");
		drop(a);
		assert_eq!(connect(&new).map(|l| l.member().spec.port), Some(1), "one of them ended");
	}

	#[test]
	fn leases_never_go_over_the_cap_from_many_threads() {
		let p = Arc::new(capped(Balance::LeastConn, &[(1, 1, false, Some(5)), (2, 1, false, Some(3))], None));
		let peak = Arc::new(AtomicU64::new(0));
		let threads: Vec<_> = (0..8)
			.map(|_| {
				let (p, peak) = (p.clone(), peak.clone());
				std::thread::spawn(move || {
					for _ in 0..2_000 {
						let lease = connect(&p);
						let now: u64 = p.members.iter().map(|m| m.active.load(Ordering::Relaxed)).sum();
						peak.fetch_max(now, Ordering::Relaxed);
						assert!(p.members[0].active.load(Ordering::Relaxed) <= 5 && p.members[1].active.load(Ordering::Relaxed) <= 3);
						drop(lease);
					}
				})
			})
			.collect();
		for t in threads {
			t.join().unwrap();
		}
		assert!(peak.load(Ordering::Relaxed) <= 8);
		assert!(p.members.iter().all(|m| m.active.load(Ordering::Relaxed) == 0));
	}

	#[test]
	fn order_gives_what_the_plain_version_gives() {
		// the bit sets of `order` against `order_slow` (the version with lists), over many states
		let mut seed = 0x9e37_79b9_7f4a_7c15u64;
		let mut next = || {
			seed ^= seed << 13;
			seed ^= seed >> 7;
			seed ^= seed << 17;
			seed
		};
		for round in 0..500 {
			let n = 1 + (next() % 9) as usize;
			let balance = [Balance::RoundRobin, Balance::LeastConn, Balance::Failover][round % 3];
			let targets: Vec<(u16, u32, bool, Option<u32>)> =
				(0..n).map(|i| (i as u16 + 1, 1 + (next() % 3) as u32, next() % 4 == 0, (next() % 3 == 0).then_some(1))).collect();
			if targets.iter().all(|t| t.2) {
				continue;
			}
			let (a, b) = (capped(balance, &targets, None), capped(balance, &targets, None));
			let mut held = vec![];
			for i in 0..n {
				let (down, busy) = (next() % 3 == 0, next() % 2 == 0);
				for p in [&a, &b] {
					p.members[i].healthy.store(!down, Ordering::Relaxed);
					if busy {
						held.extend(Lease::take(p.members[i].clone()));
					}
				}
			}
			for _ in 0..3 {
				let ports = |v: Vec<Arc<Member>>| v.iter().map(|m| m.spec.port).collect::<Vec<_>>();
				assert_eq!(ports(a.order()), ports(b.order_slow()), "{targets:?}");
			}
		}
	}

	#[test]
	fn backups_are_skipped_while_a_primary_is_up() {
		let p = pool(Balance::RoundRobin, &[(1, 1, false), (2, 1, true)]);
		assert!((0..4).all(|_| first(&p) == 1));
	}

	#[test]
	fn targets_are_validated() {
		let t = |addr: &str, port, weight, backup| TargetSpec { addr: addr.into(), port, weight, backup, max_connections: None };
		let mut ok = vec![t(" [::1] ", 80, Some(2), false), t("db.internal", 5432, None, true)];
		validate_targets(&mut ok, 1).unwrap();
		assert_eq!(ok[0].addr, "::1");
		assert_eq!(ok[0].remote(), "[::1]:80");
		for (mut bad, want) in [
			(vec![t("a", 0, None, false)], "remote_port"),
			(vec![t("a", 1, Some(0), false)], "weight"),
			(vec![t("a", 1, None, true)], "backup"),
			(vec![t("a b", 1, None, false)], "remote_addr"),
			(vec![t("a", 65_535, None, false)], "range"),
			(vec![TargetSpec { max_connections: Some(0), ..t("a", 1, None, false) }], "max_connections"),
		] {
			let e = validate_targets(&mut bad, 2).unwrap_err();
			assert!(e.message.contains(want), "{want}: {}", e.message);
		}
		let hc = HealthCheckSpec { port: None, ..Default::default() };
		assert!(hc.validate(Protocol::Tcp).is_ok());
		assert!(hc.validate(Protocol::Udp).unwrap_err().message.contains("port"));
		let hc = HealthCheckSpec { interval: Some("soon".into()), ..Default::default() };
		assert!(hc.validate(Protocol::Tcp).is_err());
	}
}
