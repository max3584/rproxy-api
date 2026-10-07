//! Several destinations for one L4 rule (#98): `targets`, `balance`
//! (round robin, least connections, failover) and TCP `health_check`.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::core::rule::{validate_remote, Key, Protocol};

/// Targets one rule may have.
pub const MAX_TARGETS: usize = 64;
/// How long a target that refused a connection is skipped (without `health_check`,
/// or until the next check says otherwise).
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
	/// Open connections (TCP) or sessions (UDP) on this target.
	pub active: AtomicU64,
	pub total: AtomicU64,
	/// What the last health check said (true without checks).
	healthy: AtomicBool,
	/// Skipped until then after refusing a connection.
	failed_until: Mutex<Option<Instant>>,
}

impl Member {
	pub fn new(spec: TargetSpec, addrs_tx: Arc<watch::Sender<Vec<SocketAddr>>>) -> Member {
		Member {
			spec,
			addrs: addrs_tx.subscribe(),
			_addrs_tx: addrs_tx,
			active: AtomicU64::new(0),
			total: AtomicU64::new(0),
			healthy: AtomicBool::new(true),
			failed_until: Mutex::new(None),
		}
	}

	pub fn is_up(&self) -> bool {
		self.healthy.load(Ordering::Relaxed) && self.failed_until.lock().unwrap().is_none_or(|t| Instant::now() >= t)
	}

	pub fn healthy(&self) -> bool {
		self.healthy.load(Ordering::Relaxed)
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
}

impl Pool {
	pub fn new(members: Vec<Arc<Member>>, balance: Balance, events: Arc<watch::Sender<u64>>, reported: bool) -> Pool {
		Pool { members, balance, next: AtomicU64::new(0), events, reported }
	}

	pub fn notify(&self) {
		self.events.send_modify(|n| *n = n.wrapping_add(1));
	}

	/// A target refused a connection: skip it for a while.
	pub fn mark_failed(&self, key: &Key, member: &Member, error: &str) {
		let was_up = member.is_up();
		*member.failed_until.lock().unwrap() = Some(Instant::now() + FAIL_COOLDOWN);
		if was_up && self.members.len() > 1 {
			warn!(event = "target.down", rule = %key, target = %member.spec.remote(), error = %error, reason = "connect");
			self.notify();
		}
	}

	/// The targets to try for a new connection, best first: the one `balance`
	/// picks among those up, the other targets that are up, backups that are up,
	/// then everything else (so a connection is never refused just because every
	/// target is marked down).
	pub fn order(&self) -> Vec<Arc<Member>> {
		let up: Vec<usize> = (0..self.members.len()).filter(|&i| self.members[i].is_up()).collect();
		let primary: Vec<usize> = up.iter().copied().filter(|&i| !self.members[i].spec.backup).collect();
		let backup: Vec<usize> = up.iter().copied().filter(|&i| self.members[i].spec.backup).collect();
		let eligible = if primary.is_empty() { &backup } else { &primary };
		let mut order: Vec<usize> = vec![];
		if let Some(first) = self.choose(eligible) {
			order.push(first);
			// the rest of the eligible ones, continuing after the chosen one
			let at = eligible.iter().position(|&i| i == first).unwrap_or(0);
			order.extend(eligible[at + 1..].iter().chain(&eligible[..at]).copied());
		}
		for i in primary.iter().chain(&backup).copied().chain(0..self.members.len()) {
			if !order.contains(&i) {
				order.push(i);
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
				total_connections: m.total.load(Ordering::Relaxed),
				resolved: m.addrs.borrow().iter().map(|a| a.to_string()).collect(),
				ejected_until: None,
				ejections: None,
			})
			.collect()
	}
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
	pub total_connections: u64,
	pub resolved: Vec<String>,
	/// Ejected by `outlier_detection` until then, in Unix seconds (#170, v0.4).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub ejected_until: Option<u64>,
	/// Times `outlier_detection` ejected the target (#170, v0.4).
	#[serde(skip_serializing_if = "Option::is_none")]
	pub ejections: Option<u64>,
}

/// A connection or session counted on a target while it lasts.
pub struct Lease(Arc<Member>);

impl Lease {
	pub fn new(member: Arc<Member>) -> Lease {
		member.active.fetch_add(1, Ordering::Relaxed);
		member.total.fetch_add(1, Ordering::Relaxed);
		Lease(member)
	}

	pub fn member(&self) -> &Arc<Member> {
		&self.0
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
						*m.failed_until.lock().unwrap() = None;
						info!(event = "target.up", rule = %key, target = %m.spec.remote());
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
		let members = targets
			.iter()
			.map(|&(port, weight, backup)| {
				let spec = TargetSpec { addr: "127.0.0.1".into(), port, weight: Some(weight), backup };
				let (tx, _) = watch::channel(vec![SocketAddr::from(([127, 0, 0, 1], port))]);
				Arc::new(Member::new(spec, Arc::new(tx)))
			})
			.collect();
		Pool::new(members, balance, Arc::new(watch::channel(0).0), true)
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
		let _a = Lease::new(p.members[0].clone());
		let _b = Lease::new(p.members[1].clone());
		let _c = Lease::new(p.members[2].clone());
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
		p.mark_failed(&key(), &p.members[0], "refused");
		assert_eq!(first(&p), 2);
		p.members[1].healthy.store(false, Ordering::Relaxed);
		assert_eq!(first(&p), 3, "the backup when every other target is down");
		p.members[2].healthy.store(false, Ordering::Relaxed);
		let order: Vec<u16> = p.order().iter().map(|m| m.spec.port).collect();
		assert_eq!(order, vec![1, 2, 3], "all down: still tried in order");
		*p.members[0].failed_until.lock().unwrap() = None;
		assert_eq!(first(&p), 1, "back to the first once it is up again");
	}

	#[test]
	fn backups_are_skipped_while_a_primary_is_up() {
		let p = pool(Balance::RoundRobin, &[(1, 1, false), (2, 1, true)]);
		assert!((0..4).all(|_| first(&p) == 1));
	}

	#[test]
	fn targets_are_validated() {
		let t = |addr: &str, port, weight, backup| TargetSpec { addr: addr.into(), port, weight, backup };
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
