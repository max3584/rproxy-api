//! Storing rules created through the API (#144, docs/DESIGN-v0.4.md 11.):
//! rproxy writes only its own table, `rproxy_rules` (the UI's `forward_rules`
//! is never touched), for tokens marked `persist: true`, and restores its own
//! node's rows at startup after the UI's (the UI's win on the same key).
//!
//! A rule created by a `persist: true` token has `origin: "api"`; its row is
//! written on every change to it (whichever token makes it) and deleted with
//! it, before the answer. A write that fails leaves the rule running
//! (`persisted: false`, `event = "degraded"`, `part = "db"`), and the periodic
//! check (`reconcile`) writes it again.
//!
//! Every database job goes through one queue (`queue`) to one worker that owns
//! the one connection. A process killed while a write is on its way leaves
//! that statement to MariaDB, which carries it out (and may commit it) after
//! the client is gone. So that a restart reads the rows only after it is done:
//! - every write is one transaction, and the connection's session ends any
//!   statement within `STATEMENT_SECS` (`max_statement_time`,
//!   `innodb_lock_wait_timeout`): a write left behind is committed or rolled
//!   back within `WRITE_BOUND`;
//! - the connection holds this node's lock (`GET_LOCK`), which MariaDB lets go
//!   only once it has finished with the connection; the startup waits for it
//!   up to `STARTUP_WAIT` and reads the rows anyway after that
//!   (`restore.wait`), then checks again once it has the lock;
//! - the session's `wait_timeout` (`IDLE_SECS`; the connection is pinged well
//!   within it) lets MariaDB drop the connection of a host that went away
//!   without closing it.
//!
//! Another live process with the same node name keeps the lock: writes then
//! fail (`persisted: false`) instead of racing it, and after `DUPLICATE_AFTER`
//! `persist.duplicate_node` (error) says so.

pub mod queue;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use serde::Deserialize;
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Row;
use tracing::{debug, error, info, warn};

use crate::core::registry::Registry;
use crate::core::rule::{parse_listen, Key, Origin, RuleRequest, RuleView};
use queue::{Done, Holder, Job, JobError, JobFuture, JobResult, LocalQueue, PersistQueue, RuleRow, SetRecord, Worker};

/// rproxy's own table (definition and GRANT: the UI repository's `db/` migrations;
/// the DDL is in docs/API.md).
pub const TABLE: &str = "rproxy_rules";

/// How `spec` is written; bumped when its reading changes.
pub const SPEC_VERSION: u32 = 1;

/// Rule sets of `persist: true` tokens (#241, v0.4.2): one row per set (the
/// UI repository's migration 012; the DDL is in docs/API.md).
pub const SETS_TABLE: &str = "rproxy_rule_sets";

/// Longest one statement of the write connection runs in MariaDB (the
/// session's `max_statement_time` and `innodb_lock_wait_timeout`).
pub const STATEMENT_SECS: u64 = 3;

/// Longest a write (its statement and the `COMMIT`) runs in MariaDB, also when
/// the process that sent it is gone.
pub const WRITE_BOUND: Duration = Duration::from_secs(2 * STATEMENT_SECS);

/// Longest a caller waits for a write (MariaDB is done a little before).
const WRITE_TIMEOUT: Duration = Duration::from_secs(WRITE_BOUND.as_secs() + 1);

/// How long the startup waits for this node's lock: a write an earlier process
/// left behind is done by then.
pub const STARTUP_WAIT: Duration = Duration::from_secs(WRITE_BOUND.as_secs() + 2);

/// The write connection's `wait_timeout`: MariaDB drops it after this long
/// without a statement (a host that went away), and so lets go of the lock.
pub const IDLE_SECS: u64 = 30;

/// How often an idle write connection is pinged (well within `IDLE_SECS`).
const PING: Duration = Duration::from_secs(IDLE_SECS / 3);

/// How often the lock is tried while another connection holds it.
const RETRY: Duration = Duration::from_secs(5);

/// Held by another connection for this long, the lock is not a dead
/// process's (MariaDB would have dropped that connection): `persist.duplicate_node`.
pub const DUPLICATE_AFTER: Duration = Duration::from_secs(IDLE_SECS + 2 * STATEMENT_SECS + 10);

/// Jobs that may wait in the queue; more are refused at once (`persisted: false`).
const QUEUE_CAPACITY: usize = 256;

/// One row of `rproxy_rule_sets`.
#[derive(Clone, Debug)]
pub struct StoredSet {
	pub name: String,
	pub generation: u64,
	pub etag: String,
	/// The token that owns the set (security review M3).
	pub owner: String,
	/// The set's rules as in the body of `PUT /rulesets/{name}`.
	pub rules: Vec<RuleRequest>,
	pub spec_version: u32,
	pub updated_by: String,
	/// Unix seconds.
	pub updated_at: u64,
}

/// One row of `rproxy_rules`.
#[derive(Clone, Debug, Deserialize)]
pub struct StoredRule {
	/// `RPROXY_NODE_NAME` (default: the host name); only this node's rows are restored.
	pub node: String,
	/// The rule as in the body of `POST /rules`.
	pub spec: RuleRequest,
	pub spec_version: u32,
	/// The token that created it, and when (Unix seconds).
	pub created_by: String,
	pub created_at: u64,
	pub updated_by: String,
	pub updated_at: u64,
}

impl StoredRule {
	pub fn key(&self) -> Option<Key> {
		Some(Key { protocol: self.spec.protocol, listen: parse_listen(&self.spec.listen_addr, self.spec.listen_port).ok()? })
	}
}

/// What the rule view shows of a stored rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
	pub created_by: String,
	pub created_at: u64,
	/// Whether the row in `rproxy_rules` is up to date.
	pub persisted: bool,
}

/// The rows of a memory store (tests).
#[derive(Default)]
struct Memory {
	rows: Mutex<HashMap<Key, StoredRule>>,
	sets: Mutex<HashMap<String, StoredSet>>,
	/// Makes the writes fail.
	fail: AtomicBool,
}

/// Whether this process holds the node's lock, and since when not.
#[derive(Default)]
struct LockWatch {
	held: bool,
	/// Since when another connection holds it (attempts failed).
	busy_since: Option<Instant>,
	/// `persist.duplicate_node` said for this episode.
	reported: bool,
}

/// Writes that did not go through, written again by `reconcile`: by whom.
#[derive(Default)]
struct Unwritten {
	rules: HashMap<Key, String>,
	removed_rules: HashMap<Key, String>,
	sets: HashMap<String, String>,
	removed_sets: HashMap<String, String>,
}

/// What a `reconcile` did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
	/// Did not run: the queue or an API change was busy, or the lock is held by another connection.
	pub skipped: Option<&'static str>,
	/// Rows written again (rules and sets) and rows deleted again.
	pub written: usize,
	/// Rules created, replaced and deleted to match this node's rows.
	pub created: usize,
	pub replaced: usize,
	pub deleted: usize,
}

pub struct Store {
	node: String,
	/// None: no `RPROXY_DATABASE_URL`, nothing is stored.
	queue: Option<Arc<dyn PersistQueue>>,
	memory: Option<Arc<Memory>>,
	meta: Mutex<HashMap<Key, Meta>>,
	/// Rule sets with a row (or that should have one): whether it is up to date (#241).
	sets: Mutex<HashMap<String, bool>>,
	unwritten: Mutex<Unwritten>,
	/// API changes to stored rules and sets hold it shared while they change the
	/// registry and write the row; `reconcile` holds it alone, so it compares a
	/// state that no change is half way through.
	changes: Arc<tokio::sync::RwLock<()>>,
	lock: Mutex<LockWatch>,
	/// Keys `restore.conflict` was said for by `reconcile` (once each).
	conflicts: Mutex<std::collections::HashSet<Key>>,
	/// Reading a rule and queueing its row happen together, so rows are queued
	/// in the order of the changes.
	order: tokio::sync::Mutex<()>,
}

/// The host name (`RPROXY_NODE_NAME`'s default).
pub fn host_name() -> String {
	#[cfg(unix)]
	{
		let mut buf = [0u8; 256];
		// SAFETY: the buffer is valid for its length; gethostname writes at most that much
		if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } == 0 {
			let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
			let name = String::from_utf8_lossy(&buf[..end]).trim().to_string();
			if !name.is_empty() {
				return name;
			}
		}
	}
	"localhost".into()
}

fn unix_millis() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// The name of a node's lock (`GET_LOCK` names are at most 64 characters;
/// node names up to 255).
fn lock_name(node: &str) -> String {
	use sha2::Digest;
	let hash = sha2::Sha256::digest(node.as_bytes());
	format!("rproxy-node-{}", hash.iter().take(16).map(|b| format!("{b:02x}")).collect::<String>())
}

impl Store {
	fn with(node: String, queue: Option<Arc<dyn PersistQueue>>, memory: Option<Arc<Memory>>) -> Store {
		Store {
			node,
			queue,
			memory,
			meta: Default::default(),
			sets: Default::default(),
			unwritten: Default::default(),
			changes: Default::default(),
			lock: Default::default(),
			conflicts: Default::default(),
			order: Default::default(),
		}
	}

	/// `url`: `RPROXY_DATABASE_URL`; the connection opens when first used. Starts
	/// the queue's worker (in the current tokio runtime).
	pub fn new(node: String, url: Option<&str>) -> Result<Store, String> {
		let Some(url) = url else { return Ok(Store::with(node, None, None)) };
		let statement_limit = Arc::new(AtomicBool::new(false));
		let limit = statement_limit.clone();
		// one connection: it holds this node's lock and runs every job; kept open
		// (pinged, `spawn_background`) so that it keeps the lock
		let pool = MySqlPoolOptions::new()
			.max_connections(1)
			.acquire_timeout(Duration::from_secs(2))
			.idle_timeout(None)
			.max_lifetime(None)
			.after_connect(move |conn, _| {
				let limit = limit.clone();
				Box::pin(async move {
					use sqlx::Executor;
					conn.execute(sqlx::AssertSqlSafe(format!(
						"SET SESSION innodb_lock_wait_timeout = {STATEMENT_SECS}, wait_timeout = {IDLE_SECS}"
					)))
					.await?;
					// MariaDB's; MySQL has no such limit for writes
					match conn.execute(sqlx::AssertSqlSafe(format!("SET SESSION max_statement_time = {STATEMENT_SECS}"))).await {
						Ok(_) => limit.store(true, Ordering::Relaxed),
						Err(e) => warn!(event = "degraded", part = "db", error = %e, "writes to rproxy_rules are bounded only by the lock wait"),
					}
					Ok(())
				})
			})
			.connect_lazy(url)
			.map_err(|e| format!("database: {e}"))?;
		let worker = DbWorker { pool, node: node.clone(), lock: lock_name(&node), statement_limit };
		Ok(Store::with(node, Some(Arc::new(LocalQueue::start(QUEUE_CAPACITY, worker))), None))
	}

	/// A store that keeps its rows in memory (tests). Starts the queue's worker.
	#[doc(hidden)]
	pub fn memory(node: &str) -> Store {
		let memory = Arc::new(Memory::default());
		let worker = MemoryWorker { node: node.into(), memory: memory.clone() };
		Store::with(node.into(), Some(Arc::new(LocalQueue::start(QUEUE_CAPACITY, worker))), Some(memory))
	}

	/// Makes the writes of a memory store fail (tests).
	#[doc(hidden)]
	pub fn fail_writes(&self, fail: bool) {
		if let Some(m) = &self.memory {
			m.fail.store(fail, Ordering::Relaxed);
		}
	}

	/// The rows of a memory store (tests).
	#[doc(hidden)]
	pub fn memory_rows(&self) -> Vec<StoredRule> {
		self.memory.as_ref().map(|m| m.rows.lock().unwrap().values().cloned().collect()).unwrap_or_default()
	}

	/// The set rows of a memory store (tests).
	#[doc(hidden)]
	pub fn memory_sets(&self) -> Vec<StoredSet> {
		self.memory.as_ref().map(|m| m.sets.lock().unwrap().values().cloned().collect()).unwrap_or_default()
	}

	/// Puts a set row into a memory store as if another process wrote it (tests).
	#[doc(hidden)]
	pub fn memory_put_set(&self, set: StoredSet) {
		if let Some(m) = &self.memory {
			m.sets.lock().unwrap().insert(set.name.clone(), set);
		}
	}

	pub fn node(&self) -> &str {
		&self.node
	}

	/// Whether rows can be written at all (`RPROXY_DATABASE_URL` is set).
	pub fn enabled(&self) -> bool {
		self.queue.is_some()
	}

	/// Held by an API change to stored rules or sets, from before it changes the
	/// registry until its row is written (`reconcile` waits for none of them).
	pub async fn changing(&self) -> tokio::sync::OwnedRwLockReadGuard<()> {
		self.changes.clone().read_owned().await
	}

	/// Queues `job` now (the order of the queue is the order of the calls); its
	/// result once done.
	fn enqueue(&self, job: Job) -> JobFuture<'static> {
		let Some(q) = &self.queue else {
			return Box::pin(async { Err(JobError::Failed("no database (RPROXY_DATABASE_URL) is configured".into())) });
		};
		let deadline = match &job {
			Job::Lock { wait } => *wait + WRITE_TIMEOUT,
			_ => WRITE_TIMEOUT,
		};
		q.submit(job, deadline)
	}

	async fn submit(&self, job: Job) -> JobResult {
		let result = self.enqueue(job).await;
		self.note_lock(&result);
		result
	}

	/// Follows who holds the node's lock from the jobs' results.
	fn note_lock(&self, result: &JobResult) {
		let mut w = self.lock.lock().unwrap_or_else(|e| e.into_inner());
		match result {
			Ok(Done::Locked) => {
				if w.reported {
					info!(event = "persist.lock", node = %self.node, "this process holds the node's lock again");
				}
				*w = LockWatch { held: true, busy_since: None, reported: false };
			}
			Err(JobError::Busy(holder)) => {
				w.held = false;
				let since = *w.busy_since.get_or_insert_with(Instant::now);
				if since.elapsed() >= DUPLICATE_AFTER && !w.reported {
					w.reported = true;
					error!(event = "persist.duplicate_node", node = %self.node, lock = %lock_name(&self.node),
						connection = holder.connection.map(|c| c.to_string()).unwrap_or_default(), host = holder.host.as_deref().unwrap_or(""), held_secs = since.elapsed().as_secs(),
						"another live connection holds this node's lock: probably another process with the same node name (RPROXY_NODE_NAME, default the host name); rules are not stored until it is gone");
				}
			}
			// a connection that broke lost the lock with it
			Err(JobError::Failed(_)) => w.held = false,
			_ => {}
		}
	}

	/// Whether this process holds the node's lock (as far as the last jobs showed).
	pub fn holds_lock(&self) -> bool {
		self.lock.lock().unwrap_or_else(|e| e.into_inner()).held
	}

	/// Fills in `persisted`, `created_by` and `created_at` of an `api` rule's view.
	pub fn decorate(&self, key: &Key, view: &mut RuleView) {
		let meta = self.meta.lock().unwrap();
		match meta.get(key) {
			Some(m) => {
				view.persisted = Some(m.persisted);
				view.created_by = Some(m.created_by.clone());
				view.created_at = Some(m.created_at);
			}
			None => view.persisted = Some(false),
		}
	}

	/// Startup (not after a live upgrade): takes this node's lock, waiting up to
	/// `STARTUP_WAIT` for an earlier process's connection to let go of it: MariaDB
	/// does that only after it has finished the statements that connection sent
	/// (each within `WRITE_BOUND`), so the rows read afterwards include a write
	/// sent just before that process was killed. Still held after that (a host
	/// that went away, until MariaDB drops its connection; another process with
	/// this node's name): `restore.wait`, the rows are read anyway, and the
	/// periodic check compares them again once it has the lock.
	pub async fn wait_for_earlier_writes(&self) {
		match self.submit(Job::Lock { wait: STARTUP_WAIT }).await {
			Err(JobError::Busy(h)) => {
				warn!(event = "restore.wait", node = %self.node, lock = %lock_name(&self.node), connection = h.connection.map(|c| c.to_string()).unwrap_or_default(),
					host = h.host.as_deref().unwrap_or(""), waited_secs = STARTUP_WAIT.as_secs(),
					"another connection still holds this node's lock; the stored rules are read anyway and checked again once the lock is free");
			}
			// the database is not there: the reads say so
			Err(e) => debug!(event = "persist.lock", error = %e),
			Ok(_) => {}
		}
	}

	/// This node's rows (startup). Rows written by a newer rproxy (`spec_version`)
	/// or that do not read are skipped with `restore.skip`.
	pub async fn load(&self) -> Result<Vec<StoredRule>, String> {
		if self.queue.is_none() {
			return Ok(vec![]);
		}
		match self.submit(Job::ReadRules).await {
			Ok(Done::Rules(rows)) => Ok(rows),
			Ok(other) => Err(format!("unexpected answer {other:?}")),
			Err(e) => Err(e.to_string()),
		}
	}

	/// Takes over what the old process knew of an `api` rule (a live upgrade, #174).
	pub fn adopt(&self, key: Key, meta: Meta) {
		self.meta.lock().unwrap_or_else(|e| e.into_inner()).insert(key, meta);
	}

	/// Remembers the rules restored from the table (as stored).
	pub fn restored(&self, rules: &[StoredRule]) {
		let mut meta = self.meta.lock().unwrap();
		for r in rules {
			if let Some(key) = r.key() {
				meta.insert(key, Meta { created_by: r.created_by.clone(), created_at: r.created_at, persisted: true });
			}
		}
	}

	/// Writes the current version of an `api` rule (after it was created or
	/// changed by `by`); does nothing for other rules. Returns whether the row is
	/// up to date.
	pub async fn save(&self, registry: &Registry, key: &Key, by: &str) -> bool {
		// the rule as it is now goes into the queue before any later change's row
		let (pending, created_by, created_at) = {
			let _order = self.order.lock().await;
			let Some((spec, _, _)) = registry.current(key).await else { return false };
			if spec.origin != Origin::Api || spec.ruleset.is_some() {
				return false;
			}
			let now = unix_millis();
			let (created_by, created_at) = {
				let meta = self.meta.lock().unwrap();
				meta.get(key).map(|m| (m.created_by.clone(), m.created_at)).unwrap_or_else(|| (by.to_string(), now / 1000))
			};
			let spec = crate::config::plan::shape(&spec);
			let row = RuleRow { key: *key, spec, created_by: created_by.clone(), created_at, by: by.into(), now };
			(self.enqueue(Job::SaveRule(row)), created_by, created_at)
		};
		let result = pending.await;
		self.note_lock(&result);
		let persisted = result.is_ok();
		{
			let mut u = self.unwritten.lock().unwrap();
			u.removed_rules.remove(key);
			if persisted {
				u.rules.remove(key);
			} else {
				u.rules.insert(*key, by.into());
			}
		}
		match result {
			Ok(_) => info!(event = "rule.persist", rule = %key, action = "save", token = by),
			// without a database nothing is stored, as documented; not a degradation
			Err(_) if !self.enabled() => {}
			Err(e) => warn!(event = "degraded", part = "db", rule = %key, error = %e,
				"the rule runs but is not stored in rproxy_rules yet (it is written again by the next check; until then it is lost on restart)"),
		}
		let mut meta = self.meta.lock().unwrap();
		meta.insert(*key, Meta { created_by, created_at, persisted });
		persisted
	}

	/// Deletes the row of a deleted `api` rule.
	pub async fn remove(&self, key: &Key, by: &str) -> bool {
		self.meta.lock().unwrap().remove(key);
		if self.queue.is_none() {
			return false;
		}
		let pending = {
			let _order = self.order.lock().await;
			self.enqueue(Job::RemoveRule(*key))
		};
		let result = pending.await;
		self.note_lock(&result);
		{
			let mut u = self.unwritten.lock().unwrap();
			u.rules.remove(key);
			if result.is_ok() {
				u.removed_rules.remove(key);
			} else {
				u.removed_rules.insert(*key, by.into());
			}
		}
		match result {
			Ok(_) => {
				info!(event = "rule.persist", rule = %key, action = "delete", token = by);
				true
			}
			Err(e) => {
				warn!(event = "degraded", part = "db", rule = %key, error = %e,
					"the row of the deleted rule stays in rproxy_rules for now (it is deleted again by the next check; until then the rule comes back on restart)");
				false
			}
		}
	}

	/// The old process after a live upgrade handed over: the changes under way
	/// and the queued jobs finish, then the connection closes and lets go of
	/// this node's lock for the new process. Nothing is written after that.
	pub async fn release(&self) {
		let _all = self.changes.clone().write_owned().await;
		if self.queue.is_some() {
			let _ = self.submit(Job::Release).await;
		}
	}

	/// The background of a store with a database: pings the idle connection
	/// (`PING`), tries the lock again every `RETRY` while another connection
	/// holds it, and checks this node's rows against the running rules every
	/// `every` (`reconcile`; None: only while the lock is not held).
	pub fn spawn_background(self: &Arc<Self>, registry: &Arc<Registry>, every: Option<Duration>) {
		let Some(q) = self.queue.clone() else { return };
		let me = Arc::downgrade(self);
		tokio::spawn(async move {
			loop {
				tokio::time::sleep(PING).await;
				if Weak::strong_count(&me) == 0 {
					return;
				}
				if q.idle() && matches!(q.submit(Job::Ping, WRITE_TIMEOUT).await, Err(JobError::Closed)) {
					return;
				}
			}
		});
		let me = Arc::downgrade(self);
		let registry = Arc::downgrade(registry);
		tokio::spawn(async move {
			let mut last = Instant::now();
			loop {
				tokio::time::sleep(RETRY).await;
				let (Some(store), Some(registry)) = (me.upgrade(), registry.upgrade()) else { return };
				let due = every.is_some_and(|e| last.elapsed() >= e);
				if store.holds_lock() && !due {
					continue;
				}
				match store.reconcile(&registry).await {
					Ok(r) if r.skipped == Some("released") => return,
					Ok(r) => {
						if r.skipped.is_none() {
							last = Instant::now();
						}
						if r != Reconciled::default() && r.skipped.is_none() {
							info!(event = "persist.reconcile", written = r.written, created = r.created, replaced = r.replaced,
								deleted = r.deleted);
						}
					}
					Err(e) => debug!(event = "persist.reconcile", error = %e),
				}
			}
		});
	}

	/// Compares this node's rows with the running `api` rules, under the node's
	/// lock and with no API change half way through: first writes again what did
	/// not go through (rules and sets with `persisted: false`, deleted ones whose
	/// row stayed), then makes the running `api` rules what the rows say (rows
	/// win: they are what a restart would run). Only `api` rules (not of a rule
	/// set) are touched; a row whose key another rule has is left alone
	/// (`restore.conflict`, once). Skipped when the queue is not idle, an API
	/// change is under way or another connection holds the lock.
	pub async fn reconcile(&self, registry: &Arc<Registry>) -> Result<Reconciled, String> {
		let skip = |why| Ok(Reconciled { skipped: Some(why), ..Default::default() });
		let Some(q) = &self.queue else { return skip("off") };
		if !q.idle() {
			return skip("queue");
		}
		let Ok(_alone) = self.changes.clone().try_write_owned() else { return skip("changes") };
		match self.submit(Job::Lock { wait: Duration::ZERO }).await {
			Ok(_) => {}
			Err(JobError::Busy(_)) => return skip("lock"),
			Err(JobError::Closed) => return skip("released"),
			Err(e) => return Err(e.to_string()),
		}
		let mut out = Reconciled::default();
		let unwritten = std::mem::take(&mut *self.unwritten.lock().unwrap());
		let api_rules = |specs: Vec<(crate::core::rule::RuleSpec, bool)>| -> HashMap<Key, crate::core::rule::RuleSpec> {
			specs.into_iter().filter(|(s, _)| s.origin == Origin::Api && s.ruleset.is_none()).map(|(s, _)| (s.key, s)).collect()
		};
		let running = api_rules(registry.specs().await);
		// 1. what did not go through
		for (key, by) in unwritten.rules {
			if running.contains_key(&key) && self.save(registry, &key, &by).await {
				out.written += 1;
			}
		}
		for (key, by) in unwritten.removed_rules {
			if !running.contains_key(&key) && self.remove(&key, &by).await {
				out.written += 1;
			}
		}
		for (name, by) in unwritten.sets {
			if let Some((generation, etag, owner, rules)) = registry.ruleset_row(&name).await {
				if self.save_set(SetRow { name: &name, generation, etag: &etag, owner: &owner, rules, by: &by }).await {
					out.written += 1;
				}
			}
		}
		for (name, by) in unwritten.removed_sets {
			if registry.ruleset_row(&name).await.is_none() && self.remove_set(&name, &by).await {
				out.written += 1;
			}
		}
		// 2. the rows win over the running api rules that are stored
		let rows = self.load().await?;
		let still_unwritten: std::collections::HashSet<Key> = {
			let u = self.unwritten.lock().unwrap();
			u.rules.keys().chain(u.removed_rules.keys()).copied().collect()
		};
		let mut by_key: HashMap<Key, StoredRule> = HashMap::new();
		for row in rows {
			if let Some(key) = row.key() {
				by_key.insert(key, row);
			}
		}
		for (key, spec) in &running {
			if still_unwritten.contains(key) {
				continue;
			}
			match by_key.get(key) {
				None => {
					if registry.delete(key, None).await.is_ok() {
						self.meta.lock().unwrap().remove(key);
						info!(event = "persist.reconcile", rule = %key, action = "delete", "the rule's row is gone from rproxy_rules");
						out.deleted += 1;
					}
				}
				Some(row) => {
					let want = registry.validate_at_startup(row.spec.clone()).map(|(s, _)| crate::config::plan::shape(&s));
					if want.as_ref().is_ok_and(|w| *w != crate::config::plan::shape(spec)) {
						let _ = registry.delete(key, None).await;
						registry.restore_as(vec![row.spec.clone()], Origin::Api).await;
						self.restored(std::slice::from_ref(row));
						info!(event = "persist.reconcile", rule = %key, action = "replace", "the rule is replaced by its row");
						out.replaced += 1;
					}
				}
			}
		}
		for (key, row) in by_key {
			if running.contains_key(&key) || still_unwritten.contains(&key) {
				continue;
			}
			if registry.get(&key).await.is_ok() {
				if self.conflicts.lock().unwrap().insert(key) {
					warn!(event = "restore.conflict", rule = %key, created_by = %row.created_by,
						"a row of rproxy_rules has the key of another rule (not made through the API); that rule is kept");
				}
				continue;
			}
			registry.restore_as(vec![row.spec.clone()], Origin::Api).await;
			self.restored(std::slice::from_ref(&row));
			info!(event = "persist.reconcile", rule = %key, action = "create", "the rule of a row in rproxy_rules was not running");
			out.created += 1;
		}
		Ok(out)
	}
}

/// Whether a database error says the table is missing (before migration 012).
fn missing_table(e: &sqlx::Error) -> bool {
	e.as_database_error().is_some_and(|d| d.code().as_deref() == Some("42S02") || d.message().contains("doesn't exist"))
}

/// What a `PUT /rulesets/{name}` left, to be written as one row.
pub struct SetRow<'a> {
	pub name: &'a str,
	pub generation: u64,
	pub etag: &'a str,
	pub owner: &'a str,
	/// The set's rules, each as `config::plan::shape`.
	pub rules: serde_json::Value,
	pub by: &'a str,
}

/// Rule sets (#241, v0.4.2): a set changed by a `persist: true` token gets a
/// row in `rproxy_rule_sets`; from then on every change to it is written,
/// whichever token makes it, and its deletion deletes the row. `reconcile`
/// writes again what did not go through; it does not change running sets.
impl Store {
	/// Whether the set has a row (or should have one).
	pub fn knows_set(&self, name: &str) -> bool {
		self.sets.lock().unwrap_or_else(|e| e.into_inner()).contains_key(name)
	}

	/// `persisted` in the views of a set: None for sets that are not stored.
	pub fn set_persisted(&self, name: &str) -> Option<bool> {
		self.sets.lock().unwrap_or_else(|e| e.into_inner()).get(name).copied()
	}

	/// Remembers sets that have rows (startup, a live upgrade).
	pub fn sets_restored(&self, names: impl IntoIterator<Item = String>) {
		let mut sets = self.sets.lock().unwrap_or_else(|e| e.into_inner());
		for n in names {
			sets.insert(n, true);
		}
	}

	/// This node's set rows (startup). Without the table (before migration 012)
	/// there are none; rows written by a newer rproxy or that do not read are
	/// skipped with `restore.skip`.
	pub async fn load_sets(&self) -> Result<Vec<StoredSet>, String> {
		if self.queue.is_none() {
			return Ok(vec![]);
		}
		match self.submit(Job::ReadSets).await {
			Ok(Done::Sets(sets)) => Ok(sets),
			Ok(other) => Err(format!("unexpected answer {other:?}")),
			Err(e) => Err(e.to_string()),
		}
	}

	/// Writes a set's row after a `PUT` (a row with a newer `generation` is
	/// kept). Returns whether the row is up to date.
	pub async fn save_set(&self, row: SetRow<'_>) -> bool {
		let record = SetRecord {
			name: row.name.into(),
			generation: row.generation,
			etag: row.etag.into(),
			owner: row.owner.into(),
			rules: row.rules,
			by: row.by.into(),
			now: unix_millis(),
		};
		let result = self.submit(Job::SaveSet(record)).await;
		let persisted = result.is_ok();
		{
			let mut u = self.unwritten.lock().unwrap();
			u.removed_sets.remove(row.name);
			if persisted {
				u.sets.remove(row.name);
			} else {
				u.sets.insert(row.name.into(), row.by.into());
			}
		}
		match result {
			Ok(_) => info!(event = "ruleset.persist", ruleset = row.name, generation = row.generation, action = "save", token = row.by),
			Err(_) if !self.enabled() => {}
			Err(e) => warn!(event = "degraded", part = "db", table = SETS_TABLE, ruleset = row.name, error = %e,
				"the rule set runs but is not stored in rproxy_rule_sets yet (it is written again by the next check)"),
		}
		self.sets.lock().unwrap_or_else(|e| e.into_inner()).insert(row.name.to_string(), persisted);
		persisted
	}

	/// Deletes the row of a deleted set.
	pub async fn remove_set(&self, name: &str, by: &str) -> bool {
		self.sets.lock().unwrap_or_else(|e| e.into_inner()).remove(name);
		if self.queue.is_none() {
			return false;
		}
		let result = self.submit(Job::RemoveSet(name.into())).await;
		{
			let mut u = self.unwritten.lock().unwrap();
			u.sets.remove(name);
			if result.is_ok() {
				u.removed_sets.remove(name);
			} else {
				u.removed_sets.insert(name.into(), by.into());
			}
		}
		match result {
			Ok(_) => {
				info!(event = "ruleset.persist", ruleset = name, action = "delete", token = by);
				true
			}
			Err(e) => {
				warn!(event = "degraded", part = "db", table = SETS_TABLE, ruleset = name, error = %e,
					"the row of the deleted rule set stays in rproxy_rule_sets for now (it is deleted again by the next check)");
				false
			}
		}
	}
}

/// The queue's worker with a database: owns the one connection (the pool of
/// one) and this node's lock on it.
struct DbWorker {
	pool: MySqlPool,
	node: String,
	lock: String,
	/// Whether the session has `max_statement_time` (MariaDB).
	statement_limit: Arc<AtomicBool>,
}

fn failed(e: sqlx::Error) -> JobError {
	JobError::Failed(e.to_string())
}

impl DbWorker {
	async fn conn(&self) -> Result<sqlx::pool::PoolConnection<sqlx::MySql>, JobError> {
		self.pool.acquire().await.map_err(failed)
	}

	/// Who holds the lock (nothing known when it cannot be read).
	async fn holder(&self, conn: &mut sqlx::MySqlConnection) -> Holder {
		let row: Result<Option<(Option<i64>, Option<String>)>, _> = sqlx::query_as(
			"SELECT CAST(IS_USED_LOCK(?) AS SIGNED), (SELECT HOST FROM information_schema.PROCESSLIST WHERE ID = IS_USED_LOCK(?))",
		)
		.bind(&self.lock)
		.bind(&self.lock)
		.fetch_optional(&mut *conn)
		.await;
		match row {
			Ok(Some((connection, host))) => Holder { connection, host },
			_ => Holder::default(),
		}
	}

	/// Takes the lock on `conn` if it does not hold it, waiting up to `wait`.
	async fn take_lock(&self, conn: &mut sqlx::MySqlConnection, wait: Duration) -> Result<(), JobError> {
		// the wait is not a statement to cut short
		let sql = if !wait.is_zero() && self.statement_limit.load(Ordering::Relaxed) {
			"SET STATEMENT max_statement_time = 0 FOR SELECT IF(IS_USED_LOCK(?) <=> CONNECTION_ID(), 1, GET_LOCK(?, ?))"
		} else {
			"SELECT IF(IS_USED_LOCK(?) <=> CONNECTION_ID(), 1, GET_LOCK(?, ?))"
		};
		let got: Option<i64> =
			sqlx::query_scalar(sql).bind(&self.lock).bind(&self.lock).bind(wait.as_secs()).fetch_one(&mut *conn).await.map_err(failed)?;
		if got == Some(1) {
			return Ok(());
		}
		Err(JobError::Busy(self.holder(conn).await))
	}

	/// One write as one transaction, under the lock.
	async fn write(&self, query: sqlx::query::Query<'_, sqlx::MySql, sqlx::mysql::MySqlArguments>) -> JobResult {
		use sqlx::Connection;
		let mut conn = self.conn().await?;
		self.take_lock(&mut conn, Duration::ZERO).await?;
		let mut tx = conn.begin().await.map_err(failed)?;
		query.execute(&mut *tx).await.map_err(failed)?;
		tx.commit().await.map_err(failed)?;
		Ok(Done::Ok)
	}

	async fn read_rules(&self) -> JobResult {
		let mut conn = self.conn().await?;
		let rows = sqlx::query(
			"SELECT CAST(spec AS CHAR) AS spec, CAST(spec_version AS SIGNED) AS spec_version, created_by, \
			 CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created_at, updated_by, \
			 CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at \
			 FROM rproxy_rules WHERE node = ? ORDER BY protocol, listen_addr, listen_port",
		)
		.bind(&self.node)
		.fetch_all(&mut *conn)
		.await
		.map_err(failed)?;
		let mut out = vec![];
		for row in rows {
			match read_row(&self.node, &row) {
				Ok(rule) => out.push(rule),
				Err(e) => warn!(event = "restore.skip", table = TABLE, error = %e),
			}
		}
		Ok(Done::Rules(out))
	}

	async fn read_sets(&self) -> JobResult {
		let mut conn = self.conn().await?;
		let query = sqlx::query(
			"SELECT name, CAST(generation AS SIGNED) AS generation, etag, owner, CAST(rules AS CHAR) AS rules, \
			 CAST(spec_version AS SIGNED) AS spec_version, updated_by, \
			 CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at \
			 FROM rproxy_rule_sets WHERE node = ? ORDER BY name",
		)
		.bind(&self.node);
		let rows = match query.fetch_all(&mut *conn).await {
			Ok(rows) => rows,
			Err(e) if missing_table(&e) => return Ok(Done::Sets(vec![])),
			Err(e) => return Err(failed(e)),
		};
		let mut out = vec![];
		for row in rows {
			let get_str = |c: &str| row.try_get::<String, _>(c).map_err(|e| format!("{c}: {e}"));
			let get_int = |c: &str| row.try_get::<i64, _>(c).map_err(|e| format!("{c}: {e}"));
			let read = || -> Result<StoredSet, String> {
				let spec_version = u32::try_from(get_int("spec_version")?).unwrap_or(u32::MAX);
				if spec_version > SPEC_VERSION {
					return Err(format!("spec_version {spec_version} is newer than this build reads ({SPEC_VERSION})"));
				}
				Ok(StoredSet {
					name: get_str("name")?,
					generation: get_int("generation")?.max(0) as u64,
					etag: get_str("etag")?,
					owner: get_str("owner")?,
					rules: serde_json::from_str(&get_str("rules")?).map_err(|e| format!("rules: {e}"))?,
					spec_version,
					updated_by: get_str("updated_by")?,
					updated_at: get_int("updated_at")?.max(0) as u64,
				})
			};
			match read() {
				Ok(set) => out.push(set),
				Err(e) => warn!(event = "restore.skip", table = SETS_TABLE, name = %get_str("name").unwrap_or_default(), error = %e),
			}
		}
		Ok(Done::Sets(out))
	}

	async fn job(&mut self, job: Job) -> JobResult {
		match job {
			Job::Lock { wait } => {
				let mut conn = self.conn().await?;
				self.take_lock(&mut conn, wait).await.map(|()| Done::Locked)
			}
			Job::ReadRules => self.read_rules().await,
			Job::ReadSets => self.read_sets().await,
			Job::SaveRule(r) => {
				let query = sqlx::query(
					"INSERT INTO rproxy_rules (node, protocol, listen_addr, listen_port, spec, spec_version, \
					 created_by, created_at, updated_by, updated_at) \
					 VALUES (?, ?, ?, ?, ?, ?, ?, FROM_UNIXTIME(? / 1000), ?, FROM_UNIXTIME(? / 1000)) \
					 ON DUPLICATE KEY UPDATE spec = VALUES(spec), spec_version = VALUES(spec_version), \
					 updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
				)
				.bind(&self.node)
				.bind(r.key.protocol.to_string())
				.bind(r.key.listen.ip().to_string())
				.bind(u32::from(r.key.listen.port()))
				.bind(r.spec.to_string())
				.bind(SPEC_VERSION)
				.bind(r.created_by)
				.bind(r.created_at.saturating_mul(1000))
				.bind(r.by)
				.bind(r.now);
				self.write(query).await
			}
			Job::RemoveRule(key) => {
				let query = sqlx::query("DELETE FROM rproxy_rules WHERE node = ? AND protocol = ? AND listen_addr = ? AND listen_port = ?")
					.bind(&self.node)
					.bind(key.protocol.to_string())
					.bind(key.listen.ip().to_string())
					.bind(u32::from(key.listen.port()));
				self.write(query).await
			}
			Job::SaveSet(s) => {
				// generation last: the IFs before it compare with the stored one
				let query = sqlx::query(
					"INSERT INTO rproxy_rule_sets (node, name, generation, etag, owner, rules, spec_version, updated_by, updated_at) \
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?, FROM_UNIXTIME(? / 1000)) \
					 ON DUPLICATE KEY UPDATE \
					 etag = IF(VALUES(generation) >= generation, VALUES(etag), etag), \
					 owner = IF(VALUES(generation) >= generation, VALUES(owner), owner), \
					 rules = IF(VALUES(generation) >= generation, VALUES(rules), rules), \
					 spec_version = IF(VALUES(generation) >= generation, VALUES(spec_version), spec_version), \
					 updated_by = IF(VALUES(generation) >= generation, VALUES(updated_by), updated_by), \
					 updated_at = IF(VALUES(generation) >= generation, VALUES(updated_at), updated_at), \
					 generation = GREATEST(generation, VALUES(generation))",
				)
				.bind(&self.node)
				.bind(s.name)
				.bind(s.generation)
				.bind(s.etag)
				.bind(s.owner)
				.bind(s.rules.to_string())
				.bind(SPEC_VERSION)
				.bind(s.by)
				.bind(s.now);
				self.write(query).await
			}
			Job::RemoveSet(name) => {
				let query = sqlx::query("DELETE FROM rproxy_rule_sets WHERE node = ? AND name = ?").bind(&self.node).bind(name);
				self.write(query).await
			}
			Job::Ping => {
				// only an open connection (a database that is down is not dialled every time)
				if self.pool.num_idle() > 0 {
					use sqlx::Connection;
					self.conn().await?.ping().await.map_err(failed)?;
				}
				Ok(Done::Ok)
			}
			Job::Release => {
				self.pool.close().await;
				Ok(Done::Ok)
			}
		}
	}
}

impl Worker for DbWorker {
	fn run(&mut self, job: Job) -> JobFuture<'_> {
		Box::pin(async move {
			let deadline = match &job {
				Job::Lock { wait } => *wait + WRITE_TIMEOUT,
				_ => WRITE_TIMEOUT,
			};
			match tokio::time::timeout(deadline, self.job(job)).await {
				Ok(r) => r,
				Err(_) => Err(JobError::TimedOut),
			}
		})
	}
}

fn read_row(node: &str, row: &sqlx::mysql::MySqlRow) -> Result<StoredRule, String> {
	let get_str = |c: &str| row.try_get::<String, _>(c).map_err(|e| format!("{c}: {e}"));
	let get_int = |c: &str| row.try_get::<i64, _>(c).map_err(|e| format!("{c}: {e}"));
	let spec_version = u32::try_from(get_int("spec_version")?).unwrap_or(u32::MAX);
	if spec_version > SPEC_VERSION {
		return Err(format!("spec_version {spec_version} is newer than this build reads ({SPEC_VERSION})"));
	}
	let spec: RuleRequest = serde_json::from_str(&get_str("spec")?).map_err(|e| format!("spec: {e}"))?;
	Ok(StoredRule {
		node: node.into(),
		spec,
		spec_version,
		created_by: get_str("created_by")?,
		created_at: get_int("created_at")?.max(0) as u64,
		updated_by: get_str("updated_by")?,
		updated_at: get_int("updated_at")?.max(0) as u64,
	})
}

/// The queue's worker of a memory store (tests): the lock is always held.
struct MemoryWorker {
	node: String,
	memory: Arc<Memory>,
}

impl MemoryWorker {
	fn job(&self, job: Job) -> JobResult {
		let m = &self.memory;
		let writing = matches!(job, Job::SaveRule(_) | Job::RemoveRule(_) | Job::SaveSet(_) | Job::RemoveSet(_));
		if writing && m.fail.load(Ordering::Relaxed) {
			return Err(JobError::Failed("writes fail (test)".into()));
		}
		match job {
			Job::Lock { .. } => Ok(Done::Locked),
			Job::ReadRules => Ok(Done::Rules(m.rows.lock().unwrap().values().filter(|r| r.node == self.node).cloned().collect())),
			Job::ReadSets => Ok(Done::Sets(m.sets.lock().unwrap().values().cloned().collect())),
			Job::SaveRule(r) => {
				let spec = serde_json::from_value::<RuleRequest>(r.spec).map_err(|e| JobError::Failed(e.to_string()))?;
				let row = StoredRule {
					node: self.node.clone(),
					spec,
					spec_version: SPEC_VERSION,
					created_by: r.created_by,
					created_at: r.created_at,
					updated_by: r.by,
					updated_at: r.now / 1000,
				};
				m.rows.lock().unwrap().insert(r.key, row);
				Ok(Done::Ok)
			}
			Job::RemoveRule(key) => {
				m.rows.lock().unwrap().remove(&key);
				Ok(Done::Ok)
			}
			Job::SaveSet(s) => {
				let rules = serde_json::from_value::<Vec<RuleRequest>>(s.rules).map_err(|e| JobError::Failed(e.to_string()))?;
				let mut sets = m.sets.lock().unwrap();
				if sets.get(&s.name).is_none_or(|old| old.generation <= s.generation) {
					let set = StoredSet {
						name: s.name.clone(),
						generation: s.generation,
						etag: s.etag,
						owner: s.owner,
						rules,
						spec_version: SPEC_VERSION,
						updated_by: s.by,
						updated_at: s.now / 1000,
					};
					sets.insert(s.name, set);
				}
				Ok(Done::Ok)
			}
			Job::RemoveSet(name) => {
				m.sets.lock().unwrap().remove(&name);
				Ok(Done::Ok)
			}
			Job::Ping | Job::Release => Ok(Done::Ok),
		}
	}
}

impl Worker for MemoryWorker {
	fn run(&mut self, job: Job) -> JobFuture<'_> {
		let result = self.job(job);
		Box::pin(async move { result })
	}
}

/// Rows of `rproxy_rules` without the keys the UI's `forward_rules` has
/// (the UI's rule is used; `restore.conflict`).
pub fn without_conflicts(ui: &[RuleRequest], stored: Vec<StoredRule>) -> Vec<StoredRule> {
	let taken: std::collections::HashSet<Key> = ui
		.iter()
		.filter_map(|r| Some(Key { protocol: r.protocol, listen: parse_listen(&r.listen_addr, r.listen_port).ok()? }))
		.collect();
	stored
		.into_iter()
		.filter(|r| match r.key() {
			Some(key) if taken.contains(&key) => {
				warn!(event = "restore.conflict", rule = %key, created_by = %r.created_by,
					"the same rule is in forward_rules (the UI's) and rproxy_rules; the UI's is used");
				false
			}
			_ => true,
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn req(port: u16) -> RuleRequest {
		serde_json::from_value(serde_json::json!({"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": port,
			"remote_addr": "10.0.0.1", "remote_port": 80}))
		.unwrap()
	}

	fn stored(port: u16) -> StoredRule {
		StoredRule {
			node: "n1".into(),
			spec: req(port),
			spec_version: 1,
			created_by: "ci".into(),
			created_at: 1,
			updated_by: "ci".into(),
			updated_at: 1,
		}
	}

	#[test]
	fn the_ui_wins_on_the_same_key() {
		let kept = without_conflicts(&[req(80), req(443)], vec![stored(443), stored(8443)]);
		assert_eq!(kept.iter().map(|r| r.spec.listen_port).collect::<Vec<_>>(), [8443]);
	}

	#[test]
	fn host_name_is_never_empty() {
		assert!(!host_name().is_empty());
	}
}
