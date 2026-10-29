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
//! Node names must be unique. At startup (not after a live upgrade, where the
//! new process knows the old one holds the lock until it lets go) a lock still
//! held by a live connection after `DUPLICATE_STARTUP_WAIT` (longer than a dead
//! one's write and `IDLE_SECS`) is another process with the same node name:
//! the startup stops with `persist.duplicate_node` (`wait_for_earlier_writes`).
//! A process that started while the database was down and finds the lock held
//! later does not take it: writes then fail (`persisted: false`) instead of
//! racing the other, and after `DUPLICATE_AFTER` `persist.duplicate_node`
//! (error) says so.
//!
//! What a write is about to change is recorded (`Unwritten`) before it is
//! queued and cleared once it went through, so `reconcile` never takes a row
//! for the truth while a write of it is on its way or failed: rows win only
//! over running rules whose row is known to be up to date.

pub mod queue;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Row;
use tracing::{debug, error, info, warn};

use crate::core::registry::Registry;
use crate::core::rule::{parse_listen, Key, Origin, Protocol, RuleRequest, RuleView};
use queue::{Done, GlobalRecord, Holder, Job, JobError, JobFuture, JobResult, Liveness, LocalQueue, PersistQueue, RuleRow, SetRecord, Worker};

/// rproxy's own table (definition and GRANT: the UI repository's `db/` migrations;
/// the DDL is in docs/API.md).
pub const TABLE: &str = "rproxy_rules";

/// How `spec` is written; bumped when its reading changes.
pub const SPEC_VERSION: u32 = 1;

/// Rule sets of `persist: true` tokens (#241, v0.4.2): one row per set (the
/// UI repository's migration 012; the DDL is in docs/API.md).
pub const SETS_TABLE: &str = "rproxy_rule_sets";

/// The `global` values set through the API (#342): one row per node (the UI
/// repository's migration 013; the DDL is in docs/API.md).
pub const GLOBAL_TABLE: &str = "rproxy_global";

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

/// How long the startup waits in all for this node's lock while another
/// connection holds it: a dead process's connection is gone by then (its write
/// within `WRITE_BOUND`, an idle one within `IDLE_SECS`), so a holder still
/// there that runs statements is a live process with the same node name.
pub const DUPLICATE_STARTUP_WAIT: Duration = Duration::from_secs(IDLE_SECS + 10);

/// A live rproxy runs a statement on its connection at least every `PING`
/// (from the moment it has the lock, also while it restores, #307): a holder
/// idle for longer than this is not one.
pub const LIVE_IDLE: Duration = Duration::from_secs(IDLE_SECS / 3 + 5);

/// How long the startup waits for a third look at the holder of this node's
/// lock when the second could not tell (`Liveness::Unsure`, #307): a live
/// rproxy pings in that time, a dead one's connection stays idle (or MariaDB
/// drops it and the lock comes free).
pub const DUPLICATE_LOOK_AGAIN: Duration = Duration::from_secs(LIVE_IDLE.as_secs() + 5);

/// What the startup does after its looks at the holder of this node's lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Startup {
	/// Another live process has the node name: the startup stops.
	Refuse,
	/// The holder does not look live: the rows are read anyway (`restore.wait`).
	Proceed,
	/// Wait this long more for the lock, then look again.
	LookAgain(Duration),
}

/// The startup's next step after `looks` at the holder of this node's lock
/// (each with when it was taken, from the start of the wait): see
/// `Store::wait_for_earlier_writes`.
pub fn after_looks(looks: &[(Holder, Duration)]) -> Startup {
	match looks {
		[] => Startup::Proceed,
		[(first, _)] if first.idle().is_some_and(|i| i >= LIVE_IDLE) => Startup::Proceed,
		[_] => Startup::LookAgain(DUPLICATE_STARTUP_WAIT.saturating_sub(STARTUP_WAIT)),
		[.., (earlier, then), (last, now)] => match last.liveness_since(earlier, now.saturating_sub(*then)) {
			Liveness::Live => Startup::Refuse,
			Liveness::NotLive => Startup::Proceed,
			Liveness::Unsure if looks.len() == 2 => Startup::LookAgain(DUPLICATE_LOOK_AGAIN),
			// still unsure: a duplicate is not proven, and one would not take the
			// lock from the other (its writes fail and `persist.duplicate_node` says so)
			Liveness::Unsure => Startup::Proceed,
		},
	}
}

/// How long a live upgrade waits for the API changes under way before it
/// takes its snapshot (`freeze`; each writes within `WRITE_TIMEOUT`): longer,
/// and the handoff does not happen (the old process keeps running, nothing is
/// lost), #305.
pub const FREEZE_WAIT: Duration = Duration::from_secs(WRITE_TIMEOUT.as_secs() + 3);

/// How long `release` waits for the changes under way when the store was not
/// frozen (it always is after a handoff) before it lets go of the lock anyway.
pub const RELEASE_WAIT: Duration = FREEZE_WAIT;

/// Writes `reconcile` tries again per round (the rest waits for the next).
const RETRIES_PER_ROUND: usize = 32;

/// Rules `reconcile` creates, replaces or deletes per round.
const APPLIED_PER_ROUND: usize = 64;

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

/// The row of `rproxy_global` (#342).
#[derive(Clone, Debug)]
pub struct StoredGlobal {
	/// `config::global::Values` as JSON.
	pub spec: serde_json::Value,
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
	global: Mutex<Option<StoredGlobal>>,
	/// Makes the writes fail.
	fail: AtomicBool,
	/// Another connection holds the lock: the lock and the writes answer `Busy`.
	busy: AtomicBool,
	/// How long each write takes (milliseconds).
	delay_ms: AtomicU64,
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

/// Writes that are on their way or did not go through (written again by
/// `reconcile`): by whom. Recorded before the write is queued, cleared once it
/// went through (by the last write queued for the key: `latest`).
#[derive(Default)]
struct Unwritten {
	rules: HashMap<Key, String>,
	removed_rules: HashMap<Key, String>,
	sets: HashMap<String, String>,
	removed_sets: HashMap<String, String>,
	/// The last write queued for a rule or set (`Store::seq`).
	latest: HashMap<Key, u64>,
	latest_sets: HashMap<String, u64>,
	/// The `global` row (#342): by whom, and the last write queued for it.
	global: Option<String>,
	latest_global: u64,
}

/// What a live upgrade hands over of the writes that are not done (#174): the
/// new process writes them again.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
	/// Rules whose row is not up to date.
	#[serde(default)]
	pub rules: Vec<PendingRule>,
	/// Deleted rules whose row stayed.
	#[serde(default)]
	pub removed_rules: Vec<PendingRule>,
	/// Rule sets whose row is not up to date.
	#[serde(default)]
	pub sets: Vec<PendingSet>,
	/// Deleted rule sets whose row stayed.
	#[serde(default)]
	pub removed_sets: Vec<PendingSet>,
	/// The `global` row is not up to date (#342): by whom.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub global: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRule {
	pub protocol: Protocol,
	pub listen: std::net::SocketAddr,
	pub by: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSet {
	pub name: String,
	pub by: String,
}

/// A write queued with its intent recorded; `Store::finish_remove` waits for it.
pub struct Queued {
	key: Key,
	by: String,
	seq: u64,
	job: JobFuture<'static>,
}

/// A rule set's removal queued; `Store::finish_remove_set` waits for it.
pub struct QueuedSet {
	name: String,
	by: String,
	seq: u64,
	job: JobFuture<'static>,
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
	/// Rows `reconcile` could not start a rule from, as they were (said once each).
	invalid: Mutex<HashMap<Key, String>>,
	/// Reading a rule and queueing its row happen together, so rows are queued
	/// in the order of the changes.
	order: tokio::sync::Mutex<()>,
	/// Writes queued so far (under `order`): `reconcile` compares the rows it
	/// read only if no write was queued after the read.
	seq: AtomicU64,
	/// `changes` held alone from a live upgrade's snapshot until `release` (or
	/// `thaw`, when the handoff did not happen): no change runs in between.
	frozen: Mutex<Option<tokio::sync::OwnedRwLockWriteGuard<()>>>,
	/// Makes the next `save_set` wait before it reads the set (tests).
	set_pause: Mutex<Option<(Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>)>>,
	/// The keepalive (`PING`) runs.
	keepalive: AtomicBool,
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
			invalid: Default::default(),
			order: Default::default(),
			seq: AtomicU64::new(0),
			frozen: Default::default(),
			set_pause: Default::default(),
			keepalive: AtomicBool::new(false),
		}
	}

	/// `url`: `RPROXY_DATABASE_URL`; the connection opens when first used. Starts
	/// the queue's worker (in the current tokio runtime).
	pub fn new(node: String, url: Option<&str>) -> Result<Store, String> {
		let Some(url) = url else { return Ok(Store::with(node, None, None)) };
		let statement_limit = Arc::new(AtomicBool::new(false));
		let limit = statement_limit.clone();
		let lock = lock_name(&node);
		let lock_on_connect = lock.clone();
		// one connection: it holds this node's lock and runs every job; kept open
		// (pinged, `spawn_background`) so that it keeps the lock
		let pool = MySqlPoolOptions::new()
			.max_connections(1)
			.acquire_timeout(Duration::from_secs(2))
			.idle_timeout(None)
			.max_lifetime(None)
			.after_connect(move |conn, _| {
				let limit = limit.clone();
				let lock = lock_on_connect.clone();
				Box::pin(async move {
					use sqlx::Executor;
					// row locks (InnoDB) and metadata locks (DDL of the table) are waited
					// for STATEMENT_SECS at most, on MariaDB and MySQL
					conn.execute(sqlx::AssertSqlSafe(format!(
						"SET SESSION innodb_lock_wait_timeout = {STATEMENT_SECS}, lock_wait_timeout = {STATEMENT_SECS}, \
						 wait_timeout = {IDLE_SECS}"
					)))
					.await?;
					// MariaDB's; MySQL has no such limit for writes (max_execution_time is for SELECT only)
					match conn.execute(sqlx::AssertSqlSafe(format!("SET SESSION max_statement_time = {STATEMENT_SECS}"))).await {
						Ok(_) => limit.store(true, Ordering::Relaxed),
						Err(e) => warn!(event = "degraded", part = "db", error = %e,
							"writes to rproxy_rules are bounded only by the lock waits (MySQL): a write of a killed process may still run after the restart has read the rows"),
					}
					// a new connection (also after the old one broke) takes the lock at once
					// if it is free, so the lock is held all the time
					let _ = sqlx::query("SELECT GET_LOCK(?, 0)").bind(&lock).execute(&mut *conn).await;
					Ok(())
				})
			})
			.connect_lazy(url)
			.map_err(|e| format!("database: {e}"))?;
		let worker = DbWorker { pool, node: node.clone(), lock, statement_limit };
		Ok(Store::with(node, Some(Arc::new(LocalQueue::start(QUEUE_CAPACITY, worker))), None))
	}

	/// A store that keeps its rows in memory (tests). Starts the queue's worker.
	#[doc(hidden)]
	pub fn memory(node: &str) -> Store {
		let memory = Arc::new(Memory::default());
		let worker = MemoryWorker { node: node.into(), memory: memory.clone() };
		Store::with(node.into(), Some(Arc::new(LocalQueue::start(QUEUE_CAPACITY, worker))), Some(memory))
	}

	/// Another memory store on the same rows (tests): the new process of a live
	/// upgrade.
	#[doc(hidden)]
	pub fn memory_after_upgrade(&self) -> Store {
		let memory = self.memory.clone().expect("a memory store");
		let worker = MemoryWorker { node: self.node.clone(), memory: memory.clone() };
		Store::with(self.node.clone(), Some(Arc::new(LocalQueue::start(QUEUE_CAPACITY, worker))), Some(memory))
	}

	/// Makes the writes of a memory store fail (tests).
	#[doc(hidden)]
	pub fn fail_writes(&self, fail: bool) {
		if let Some(m) = &self.memory {
			m.fail.store(fail, Ordering::Relaxed);
		}
	}

	/// Makes a memory store's lock held by another connection (tests).
	#[doc(hidden)]
	pub fn memory_busy(&self, busy: bool) {
		if let Some(m) = &self.memory {
			m.busy.store(busy, Ordering::Relaxed);
		}
	}

	/// Makes each write of a memory store take this long (tests).
	#[doc(hidden)]
	pub fn delay_writes(&self, delay: Duration) {
		if let Some(m) = &self.memory {
			m.delay_ms.store(delay.as_millis() as u64, Ordering::Relaxed);
		}
	}

	/// Puts a rule row into a memory store as if another writer did (tests).
	#[doc(hidden)]
	pub fn memory_put_row(&self, row: StoredRule) {
		if let (Some(m), Some(key)) = (&self.memory, row.key()) {
			m.rows.lock().unwrap().insert(key, row);
		}
	}

	/// Takes a row out of a memory store behind rproxy's back (tests).
	#[doc(hidden)]
	pub fn memory_remove_row(&self, key: &Key) {
		if let Some(m) = &self.memory {
			m.rows.lock().unwrap().remove(key);
		}
	}

	/// Whether `reconcile` would write the rule's row again or leaves it alone (tests).
	#[doc(hidden)]
	pub fn is_unwritten(&self, key: &Key) -> bool {
		let u = self.unwritten.lock().unwrap();
		u.rules.contains_key(key) || u.removed_rules.contains_key(key)
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

	/// Makes the next `save_set` wait before it reads the set (tests): it adds a
	/// permit to the first semaphore once there, then waits for one of the second.
	#[doc(hidden)]
	pub fn pause_next_set_write(&self) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
		let pause = (Arc::new(tokio::sync::Semaphore::new(0)), Arc::new(tokio::sync::Semaphore::new(0)));
		*self.set_pause.lock().unwrap() = Some(pause.clone());
		pause
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
		let writes = job.writes();
		let result = self.enqueue(job).await;
		self.note_lock(&result, writes);
		result
	}

	/// Records what a write is about to change (under `order`, before it is
	/// queued); its number in the order of the writes.
	fn intend(&self, record: impl FnOnce(&mut Unwritten, u64)) -> u64 {
		let seq = self.seq.fetch_add(1, Ordering::AcqRel) + 1;
		if self.queue.is_some() {
			record(&mut self.unwritten.lock().unwrap_or_else(|e| e.into_inner()), seq);
		}
		seq
	}

	/// Follows who holds the node's lock from the jobs' results (`wrote`: the
	/// job was a write, which goes through only under the lock).
	fn note_lock(&self, result: &JobResult, wrote: bool) {
		let mut w = self.lock.lock().unwrap_or_else(|e| e.into_inner());
		if matches!(result, Ok(Done::Locked)) || (wrote && result.is_ok()) {
			if w.reported {
				info!(event = "persist.lock", node = %self.node, "this process holds the node's lock again");
			}
			*w = LockWatch { held: true, busy_since: None, reported: false };
			return;
		}
		match result {
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

	/// The token that created an `api` rule (#323).
	pub fn created_by(&self, key: &Key) -> Option<String> {
		self.meta.lock().unwrap_or_else(|e| e.into_inner()).get(key).map(|m| m.created_by.clone())
	}

	/// What the view shows of a stored rule (`created_by`, ...) is forgotten: the key is
	/// another rule's now (a restored rule set took it, #327).
	pub fn forget_meta(&self, key: &Key) {
		self.meta.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
	}

	/// A row known not to make a rule is looked at again.
	pub fn forget_invalid_row(&self, key: &Key) {
		self.invalid.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
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
	/// sent just before that process was killed.
	///
	/// Still held after that (`after_looks`): a holder idle for longer than a
	/// live rproxy ever is (`LIVE_IDLE`) is a connection left behind
	/// (`restore.wait`, the rows are read anyway, and the periodic check compares
	/// them again once it has the lock). Otherwise the wait goes on up to
	/// `DUPLICATE_STARTUP_WAIT` (a host that went away without closing its
	/// connection: MariaDB drops it within `IDLE_SECS`). A holder that is still
	/// there and ran statements meanwhile (its idle time started again: it
	/// pings, from the moment it took the lock, `spawn_keepalive`) is a live
	/// process with the same node name: `persist.duplicate_node` and an error,
	/// which stops the startup. When the second look cannot tell (the statement
	/// of the first ended in between, `Liveness::Unsure`: a dead host's long
	/// write on MySQL looks so, #307) a third look after `DUPLICATE_LOOK_AGAIN`
	/// does; still unsure, the startup goes on with `restore.wait`.
	pub async fn wait_for_earlier_writes(&self) -> Result<(), String> {
		let started = Instant::now();
		let mut looks: Vec<(Holder, Duration)> = vec![];
		let mut wait = STARTUP_WAIT;
		loop {
			match self.submit(Job::Lock { wait }).await {
				Ok(_) => return Ok(()),
				Err(JobError::Busy(h)) => looks.push((h, started.elapsed())),
				// the database is not there: the reads say so
				Err(e) => {
					debug!(event = "persist.lock", error = %e);
					return Ok(());
				}
			}
			match after_looks(&looks) {
				Startup::LookAgain(more) => wait = more,
				Startup::Proceed => break,
				Startup::Refuse => {
					let holder = &looks[looks.len() - 1].0;
					let connection = holder.connection.map(|c| c.to_string()).unwrap_or_else(|| "?".into());
					let host = holder.host.clone().unwrap_or_else(|| "?".into());
					error!(event = "persist.duplicate_node", phase = "startup", node = %self.node, lock = %lock_name(&self.node),
						connection = %connection, host = %host, waited_secs = started.elapsed().as_secs(),
						"another live process with the same node name holds this node's lock: node names must be unique; give this process a name of its own with --node-name or RPROXY_NODE_NAME (default the host name)");
					return Err(format!(
						"another live process uses the node name {:?} (its database connection {connection} from {host} holds the node's lock): \
						 node names must be unique; set --node-name or RPROXY_NODE_NAME (default the host name) to a name of its own",
						self.node
					));
				}
			}
		}
		let holder = &looks[looks.len() - 1].0;
		warn!(event = "restore.wait", node = %self.node, lock = %lock_name(&self.node), connection = holder.connection.map(|c| c.to_string()).unwrap_or_default(),
			host = holder.host.as_deref().unwrap_or(""), idle_secs = holder.idle_secs.unwrap_or(0), waited_secs = started.elapsed().as_secs(), looks = looks.len(),
			"a connection that does not look live still holds this node's lock; the stored rules are read anyway and checked again once the lock is free");
		Ok(())
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

	/// Takes over what the old process knew of an `api` rule (a live upgrade,
	/// #174): a row that was not up to date there is written again here.
	pub fn adopt(&self, key: Key, meta: Meta) {
		if !meta.persisted && self.enabled() {
			self.unwritten.lock().unwrap_or_else(|e| e.into_inner()).rules.entry(key).or_insert_with(|| meta.created_by.clone());
		}
		self.meta.lock().unwrap_or_else(|e| e.into_inner()).insert(key, meta);
	}

	/// The writes that are on their way or did not go through, for the new
	/// process of a live upgrade (#174).
	pub fn pending(&self) -> Pending {
		let u = self.unwritten.lock().unwrap_or_else(|e| e.into_inner());
		let rules = |m: &HashMap<Key, String>| -> Vec<PendingRule> {
			m.iter().map(|(k, by)| PendingRule { protocol: k.protocol, listen: k.listen, by: by.clone() }).collect()
		};
		let sets = |m: &HashMap<String, String>| -> Vec<PendingSet> {
			m.iter().map(|(name, by)| PendingSet { name: name.clone(), by: by.clone() }).collect()
		};
		Pending {
			rules: rules(&u.rules),
			removed_rules: rules(&u.removed_rules),
			sets: sets(&u.sets),
			removed_sets: sets(&u.removed_sets),
			global: u.global.clone(),
		}
	}

	/// Takes over the old process's writes that are not done (a live upgrade,
	/// #174): the periodic check writes them, and rows never win over them.
	pub fn adopt_pending(&self, pending: Pending) {
		if !self.enabled() {
			return;
		}
		let mut u = self.unwritten.lock().unwrap_or_else(|e| e.into_inner());
		for r in pending.rules {
			u.rules.insert(Key { protocol: r.protocol, listen: r.listen }, r.by);
		}
		for r in pending.removed_rules {
			u.removed_rules.insert(Key { protocol: r.protocol, listen: r.listen }, r.by);
		}
		let mut sets = self.sets.lock().unwrap_or_else(|e| e.into_inner());
		for s in pending.sets {
			sets.insert(s.name.clone(), false);
			u.sets.insert(s.name, s.by);
		}
		for s in pending.removed_sets {
			u.removed_sets.insert(s.name, s.by);
		}
		if pending.global.is_some() {
			u.global = pending.global;
		}
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
		self.save_rule(registry, key, by).await == Some(true)
	}

	/// `save`; None: not an `api` rule (nothing to write).
	async fn save_rule(&self, registry: &Registry, key: &Key, by: &str) -> Option<bool> {
		// the rule as it is now goes into the queue before any later change's row
		let (seq, pending, created_by, created_at) = {
			let _order = self.order.lock().await;
			let spec = match registry.current(key).await {
				Some((spec, _, _)) if spec.origin == Origin::Api && spec.ruleset.is_none() => spec,
				_ => {
					// gone, or not stored any more: nothing to write again
					self.unwritten.lock().unwrap().rules.remove(key);
					return None;
				}
			};
			let now = unix_millis();
			let (created_by, created_at) = {
				let meta = self.meta.lock().unwrap();
				meta.get(key).map(|m| (m.created_by.clone(), m.created_at)).unwrap_or_else(|| (by.to_string(), now / 1000))
			};
			let spec = crate::config::plan::shape(&spec);
			let row = RuleRow { key: *key, spec, created_by: created_by.clone(), created_at, by: by.into(), now };
			let seq = self.intend(|u, seq| {
				u.rules.insert(*key, by.into());
				u.removed_rules.remove(key);
				u.latest.insert(*key, seq);
			});
			(seq, self.enqueue(Job::SaveRule(row)), created_by, created_at)
		};
		let result = pending.await;
		self.note_lock(&result, true);
		let persisted = result.is_ok();
		match result {
			Ok(_) => info!(event = "rule.persist", rule = %key, action = "save", token = by),
			// without a database nothing is stored, as documented; not a degradation
			Err(_) if !self.enabled() => {}
			Err(e) => warn!(event = "degraded", part = "db", rule = %key, error = %e,
				"the rule runs but is not stored in rproxy_rules yet (it is written again by the next check; until then it is lost on restart)"),
		}
		// the last write queued for the rule says whether its row is up to date
		let latest = {
			let mut u = self.unwritten.lock().unwrap();
			let latest = u.latest.get(key) == Some(&seq);
			if latest && persisted {
				u.rules.remove(key);
				u.latest.remove(key);
			}
			latest || !self.enabled()
		};
		if latest {
			self.meta.lock().unwrap().insert(*key, Meta { created_by, created_at, persisted });
		}
		Some(persisted)
	}

	/// Deletes the row of a deleted `api` rule (`begin_remove`, then waits for it).
	pub async fn remove(&self, registry: &Registry, key: &Key, by: &str) -> bool {
		match self.begin_remove(registry, key, by).await {
			Some(queued) => self.finish_remove(queued).await,
			None => false,
		}
	}

	/// Queues the deletion of the row of an `api` rule that is out of the
	/// registry now (with the change under `changing`). None: nothing to delete
	/// (no database; or a newer `api` rule has the key, and its own change writes
	/// its row: deleting would lose it).
	pub async fn begin_remove(&self, registry: &Registry, key: &Key, by: &str) -> Option<Queued> {
		if self.queue.is_none() {
			self.meta.lock().unwrap().remove(key);
			return None;
		}
		let _order = self.order.lock().await;
		if let Some((spec, _, _)) = registry.current(key).await {
			if spec.origin == Origin::Api && spec.ruleset.is_none() {
				self.unwritten.lock().unwrap().removed_rules.remove(key);
				return None;
			}
		}
		self.meta.lock().unwrap().remove(key);
		let seq = self.intend(|u, seq| {
			u.removed_rules.insert(*key, by.into());
			u.rules.remove(key);
			u.latest.insert(*key, seq);
		});
		Some(Queued { key: *key, by: by.into(), seq, job: self.enqueue(Job::RemoveRule(*key)) })
	}

	/// Waits for a deletion `begin_remove` queued; whether the row is gone.
	pub async fn finish_remove(&self, queued: Queued) -> bool {
		let Queued { key, by, seq, job } = queued;
		let result = job.await;
		self.note_lock(&result, true);
		if result.is_ok() {
			let mut u = self.unwritten.lock().unwrap();
			if u.latest.get(&key) == Some(&seq) {
				u.removed_rules.remove(&key);
				u.latest.remove(&key);
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

	/// A live upgrade's snapshot is about to be taken (#305): waits up to `wait`
	/// for the API changes under way (and a `reconcile` applying rows) to end,
	/// then holds `changes` alone until `release` (the handoff happened) or
	/// `thaw` (it did not). So the snapshot is the last state of this process:
	/// no change runs between the snapshot and `release`, and one that waits
	/// for `changing` meanwhile is refused once it gets it (`503 upgrading`,
	/// `control::api`), never made here only. False: changes were still under
	/// way after `wait` (the handoff must not happen).
	pub async fn freeze(&self, wait: Duration) -> bool {
		match tokio::time::timeout(wait, self.changes.clone().write_owned()).await {
			Ok(alone) => {
				*self.frozen.lock().unwrap_or_else(|e| e.into_inner()) = Some(alone);
				true
			}
			Err(_) => false,
		}
	}

	/// The handoff did not happen after `freeze`: changes run again.
	pub fn thaw(&self) {
		drop(self.frozen.lock().unwrap_or_else(|e| e.into_inner()).take());
	}

	/// The old process after a live upgrade handed over: the queued jobs finish
	/// (writes queued before the snapshot, also those whose rows are in its
	/// `pending`), then the connection closes and lets go of this node's lock
	/// for the new process. No change ran since the snapshot (`freeze`), and
	/// nothing is written after this; the changes that waited meanwhile go on
	/// once it returns and are refused (`503 upgrading`).
	pub async fn release(&self) {
		self.release_within(RELEASE_WAIT).await
	}

	/// `release`, waiting up to `wait` for the changes under way when the store
	/// is not frozen (tests).
	#[doc(hidden)]
	pub async fn release_within(&self, wait: Duration) {
		let frozen = self.frozen.lock().unwrap_or_else(|e| e.into_inner()).take();
		let _alone = match frozen {
			Some(alone) => Some(alone),
			None => {
				let all = tokio::time::timeout(wait, self.changes.clone().write_owned()).await.ok();
				if all.is_none() {
					warn!(event = "persist.release", node = %self.node, waited_secs = wait.as_secs(),
						"changes are still under way; this process lets go of the node's lock anyway (what they write after that fails, persisted: false)");
				}
				all
			}
		};
		if self.queue.is_some() {
			let _ = self.submit(Job::Release).await;
		}
	}

	/// Keeps the connection open and the node's lock held: a statement every
	/// `PING` while the queue is idle (a connection opened again takes the lock
	/// again). The startup starts it as soon as it has the lock, before the
	/// restore (which may take long): so the process looks live to another
	/// process with the same node name from then on (#307). Once only.
	pub fn spawn_keepalive(self: &Arc<Self>) {
		if self.queue.is_none() || self.keepalive.swap(true, Ordering::AcqRel) {
			return;
		}
		let me = Arc::downgrade(self);
		tokio::spawn(async move {
			loop {
				tokio::time::sleep(PING).await;
				let Some(store) = me.upgrade() else { return };
				if !store.queue.as_ref().is_some_and(|q| q.idle()) {
					continue;
				}
				if matches!(store.submit(Job::Ping).await, Err(JobError::Closed)) {
					return;
				}
			}
		});
	}

	/// The background of a store with a database: keeps the connection open and
	/// the node's lock held (`PING`: a connection opened again takes it again),
	/// tries the lock again every `RETRY` while it is not held, and checks this
	/// node's rows against the running rules every `every` (`reconcile`; None:
	/// only while the lock is not held).
	pub fn spawn_background(self: &Arc<Self>, registry: &Arc<Registry>, every: Option<Duration>) {
		if self.queue.is_none() {
			return;
		}
		self.spawn_keepalive();
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
						if r.written + r.created + r.replaced + r.deleted > 0 {
							info!(event = "persist.reconcile", written = r.written, created = r.created, replaced = r.replaced,
								deleted = r.deleted, skipped = r.skipped.unwrap_or(""));
						}
					}
					Err(e) => debug!(event = "persist.reconcile", error = %e),
				}
			}
		});
	}

	/// Compares this node's rows with the running `api` rules, under the node's
	/// lock: first writes again what did not go through (rules and sets with
	/// `persisted: false`, deleted ones whose row stayed; like API changes, at
	/// most `RETRIES_PER_ROUND`, holding no change up), then reads the rows and,
	/// with no API change half way through and no write queued since the read,
	/// makes the running `api` rules what the rows say (rows win: they are what a
	/// restart would run; at most `APPLIED_PER_ROUND`). Rules whose row is not
	/// known to be up to date (a write on its way or failed, `persisted: false`)
	/// are left alone, and so are rules not of the API or of a rule set; a row
	/// whose key another rule has is left alone (`restore.conflict`, once), and
	/// so is a row that does not make a rule (`restore.skip`, once until it
	/// changes). Skipped when the queue is not idle, an API change is under way
	/// or another connection holds the lock.
	pub async fn reconcile(&self, registry: &Arc<Registry>) -> Result<Reconciled, String> {
		let skip = |why| Ok(Reconciled { skipped: Some(why), ..Default::default() });
		let Some(q) = &self.queue else { return skip("off") };
		if !q.idle() {
			return skip("queue");
		}
		match self.submit(Job::Lock { wait: Duration::ZERO }).await {
			Ok(_) => {}
			Err(JobError::Busy(_)) => return skip("lock"),
			Err(JobError::Closed) => return skip("released"),
			Err(e) => return Err(e.to_string()),
		}
		let mut out = Reconciled::default();
		// 1. what did not go through, written again (the first failure ends it: the database is in trouble)
		let (rules, removed_rules, sets, removed_sets, global) = {
			let u = self.unwritten.lock().unwrap();
			let take = |m: &HashMap<Key, String>| m.iter().map(|(k, by)| (*k, by.clone())).collect::<Vec<_>>();
			let take_sets = |m: &HashMap<String, String>| m.iter().map(|(n, by)| (n.clone(), by.clone())).collect::<Vec<_>>();
			(take(&u.rules), take(&u.removed_rules), take_sets(&u.sets), take_sets(&u.removed_sets), u.global.clone())
		};
		let mut budget = RETRIES_PER_ROUND;
		'retry: {
			// the global values (#342): read first if they could not be at the start (a
			// change waits for them), then only written again: the row never wins over them
			if !registry.global().loaded() {
				match self.load_global().await {
					Ok(row) => {
						let (spec, by, at) = match row {
							Some(r) => (r.spec, Some(r.updated_by), Some(r.updated_at)),
							None => (serde_json::json!({}), None, None),
						};
						registry.global().restore(registry, &spec, by, at, Some(true), None, "reconcile").await;
					}
					Err(_) => break 'retry,
				}
			}
			if let Some(by) = global {
				budget -= 1;
				if !self.save_global(registry, &by).await {
					break 'retry;
				}
				out.written += 1;
			}
			for (key, by) in rules {
				if budget == 0 {
					break 'retry;
				}
				budget -= 1;
				match self.save_rule(registry, &key, &by).await {
					Some(true) => out.written += 1,
					Some(false) => break 'retry,
					None => {}
				}
			}
			for (key, by) in removed_rules {
				if budget == 0 {
					break 'retry;
				}
				budget -= 1;
				if let Some(queued) = self.begin_remove(registry, &key, &by).await {
					if !self.finish_remove(queued).await {
						break 'retry;
					}
					out.written += 1;
				}
			}
			for (name, by) in sets {
				if budget == 0 {
					break 'retry;
				}
				budget -= 1;
				// read as it runs when its row is queued (gone: nothing to write again)
				match self.save_set(registry, &name, &by).await {
					Some(true) => out.written += 1,
					Some(false) => break 'retry,
					None => {}
				}
			}
			for (name, by) in removed_sets {
				if budget == 0 {
					break 'retry;
				}
				budget -= 1;
				if let Some(queued) = self.begin_remove_set(registry, &name, &by).await {
					if !self.finish_remove_set(queued).await {
						break 'retry;
					}
					out.written += 1;
				}
			}
		}
		// 2. the rows, after every write queued so far (the count and the read taken
		// together under `order`, where writes are counted and queued)
		let (queued_before, read) = {
			let _order = self.order.lock().await;
			(self.seq.load(Ordering::Acquire), self.enqueue(Job::ReadRules))
		};
		let result = read.await;
		self.note_lock(&result, false);
		let rows = match result {
			Ok(Done::Rules(rows)) => rows,
			Ok(other) => return Err(format!("unexpected answer {other:?}")),
			Err(e) => return Err(e.to_string()),
		};
		// 3. compared and applied alone: no change is half way through, and none
		// queued a write after the read (the rows would not show it)
		let Ok(_alone) = self.changes.clone().try_write_owned() else { return Ok(Reconciled { skipped: Some("changes"), ..out }) };
		if self.seq.load(Ordering::Acquire) != queued_before {
			return Ok(Reconciled { skipped: Some("changes"), ..out });
		}
		let mut leave: std::collections::HashSet<Key> = {
			let u = self.unwritten.lock().unwrap();
			u.rules.keys().chain(u.removed_rules.keys()).copied().collect()
		};
		leave.extend(self.meta.lock().unwrap().iter().filter(|(_, m)| !m.persisted).map(|(k, _)| *k));
		let running: HashMap<Key, crate::core::rule::RuleSpec> = registry
			.specs()
			.await
			.into_iter()
			.filter(|(s, _)| s.origin == Origin::Api && s.ruleset.is_none())
			.map(|(s, _)| (s.key, s))
			.collect();
		let mut by_key: HashMap<Key, StoredRule> = HashMap::new();
		for row in rows {
			if let Some(key) = row.key() {
				by_key.insert(key, row);
			}
		}
		let mut budget = APPLIED_PER_ROUND;
		for (key, spec) in &running {
			if leave.contains(key) {
				continue;
			}
			if budget == 0 {
				return Ok(out);
			}
			match by_key.get(key) {
				None => {
					budget -= 1;
					if registry.delete(key, None).await.is_ok() {
						self.meta.lock().unwrap().remove(key);
						info!(event = "persist.reconcile", rule = %key, action = "delete", "the rule's row is gone from rproxy_rules");
						out.deleted += 1;
					}
				}
				Some(row) => match registry.validate_at_startup(row.spec.clone()) {
					Ok((want, _)) if crate::config::plan::shape(&want) != crate::config::plan::shape(spec) => {
						budget -= 1;
						let _ = registry.delete(key, None).await;
						registry.restore_as(vec![row.spec.clone()], Origin::Api).await;
						self.restored(std::slice::from_ref(row));
						info!(event = "persist.reconcile", rule = %key, action = "replace", "the rule is replaced by its row");
						out.replaced += 1;
					}
					Ok(_) => {}
					// the running rule stays
					Err(e) => self.invalid_row(key, row, &e.message),
				},
			}
		}
		// rules of rows that did not validate (#327): left alone while the row is the same,
		// tried again once it changed, forgotten when it is gone
		let invalid: HashMap<Key, String> = registry
			.invalid_rules()
			.into_iter()
			.filter(|(_, _, origin)| *origin == Origin::Api)
			.map(|(k, req, _)| (k, format!("{req:?}")))
			.collect();
		for key in invalid.keys().filter(|k| !by_key.contains_key(k) && !leave.contains(k)) {
			if registry.drop_invalid(key).is_some() {
				self.meta.lock().unwrap().remove(key);
				info!(event = "persist.reconcile", rule = %key, action = "delete", "the row of a rule that did not validate is gone from rproxy_rules");
				out.deleted += 1;
			}
		}
		for (key, row) in by_key {
			if running.contains_key(&key) || leave.contains(&key) {
				continue;
			}
			if let Some(seen) = invalid.get(&key) {
				if *seen == format!("{:?}", row.spec) {
					continue;
				}
				registry.drop_invalid(&key);
			}
			if registry.get(&key).await.is_ok() {
				if self.conflicts.lock().unwrap().insert(key) {
					warn!(event = "restore.conflict", rule = %key, created_by = %row.created_by,
						"a row of rproxy_rules has the key of another rule (not made through the API); that rule is kept");
				}
				continue;
			}
			// a row that did not make a rule is tried again once it changed
			if self.invalid.lock().unwrap().get(&key) == Some(&format!("{:?}", row.spec)) {
				continue;
			}
			if budget == 0 {
				return Ok(out);
			}
			budget -= 1;
			if let Err(e) = registry.validate_at_startup(row.spec.clone()) {
				// shown as failed (#327), said by `rule.failed`
				self.invalid.lock().unwrap().insert(key, format!("{:?}", row.spec));
				self.restored(std::slice::from_ref(&row));
				registry.note_invalid(row.spec.clone(), Origin::Api, &e, "reconcile").await;
				continue;
			}
			registry.restore_as(vec![row.spec.clone()], Origin::Api).await;
			if registry.get(&key).await.is_err() {
				self.invalid_row(&key, &row, "it could not be started (rule.failed says why)");
				continue;
			}
			self.invalid.lock().unwrap().remove(&key);
			self.restored(std::slice::from_ref(&row));
			info!(event = "persist.reconcile", rule = %key, action = "create", "the rule of a row in rproxy_rules was not running");
			out.created += 1;
		}
		Ok(out)
	}

	/// A row that does not make a rule: said once until the row changes.
	fn invalid_row(&self, key: &Key, row: &StoredRule, error: &str) {
		let seen = format!("{:?}", row.spec);
		if self.invalid.lock().unwrap().insert(*key, seen.clone()).as_ref() != Some(&seen) {
			warn!(event = "restore.skip", table = TABLE, rule = %key, error = %error,
				"a row of rproxy_rules does not make a rule; it is left alone until it changes");
		}
	}
}

/// The `global` values set through the API (#342): one row per node in
/// `rproxy_global`, written on every `PATCH /config/global` (before the answer)
/// and read at the start before the rules. `reconcile` writes it again when a
/// write did not go through; the row never wins over the running values (only
/// this process writes it).
impl Store {
	/// This node's row (None: no row, or no table yet).
	pub async fn load_global(&self) -> Result<Option<StoredGlobal>, String> {
		match self.submit(Job::ReadGlobal).await {
			Ok(Done::Global(row)) => Ok(row),
			Ok(other) => Err(format!("unexpected answer {other:?}")),
			Err(e) => Err(e.to_string()),
		}
	}

	/// Writes the API values as they are now (after a change by `by`, or again by
	/// `reconcile`); read under `order`, where the row is queued, so the last
	/// queued is the latest. Returns whether the row is up to date (false
	/// without a database).
	pub async fn save_global(&self, registry: &Registry, by: &str) -> bool {
		debug_assert!(!self.enabled() || registry.global().persisted().is_some(), "a database stores the values, but the settings do not know");
		let (seq, job) = {
			let _order = self.order.lock().await;
			// not read yet: writing now would lose what is stored
			let Some((spec, _)) = registry.global().stored() else { return false };
			let record = GlobalRecord { spec, by: by.into(), now: unix_millis() };
			let seq = self.intend(|u, seq| {
				u.global = Some(by.into());
				u.latest_global = seq;
			});
			(seq, self.enqueue(Job::SaveGlobal(record)))
		};
		let result = job.await;
		self.note_lock(&result, true);
		let persisted = result.is_ok();
		let latest = {
			let mut u = self.unwritten.lock().unwrap();
			let latest = u.latest_global == seq;
			if latest && persisted {
				u.global = None;
			}
			latest || !self.enabled()
		};
		match result {
			Ok(_) => info!(event = "config.global.persist", token = by),
			Err(_) if !self.enabled() => {}
			Err(e) => warn!(event = "degraded", part = "db", table = GLOBAL_TABLE, error = %e,
				"the global values are in force but not stored in rproxy_global yet (written again by the next check)"),
		}
		if latest {
			registry.global().set_persisted(persisted);
		}
		persisted
	}

	/// The row of a memory store (tests).
	pub fn memory_global(&self) -> Option<StoredGlobal> {
		self.memory.as_ref().and_then(|m| m.global.lock().unwrap().clone())
	}

	/// Puts a row in a memory store (tests).
	pub fn memory_put_global(&self, row: StoredGlobal) {
		if let Some(m) = &self.memory {
			*m.global.lock().unwrap() = Some(row);
		}
	}
}

/// Whether a database error says the table is missing (before migration 012).
fn missing_table(e: &sqlx::Error) -> bool {
	e.as_database_error().is_some_and(|d| d.code().as_deref() == Some("42S02") || d.message().contains("doesn't exist"))
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

	/// Remembers sets that have rows (startup, a live upgrade; a set the old
	/// process could not write stays `persisted: false`).
	pub fn sets_restored(&self, names: impl IntoIterator<Item = String>) {
		let mut sets = self.sets.lock().unwrap_or_else(|e| e.into_inner());
		for n in names {
			sets.entry(n).or_insert(true);
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

	/// Writes the row of a set as it runs now (after a `PUT`, or again by
	/// `reconcile`; a row with a newer `generation` is kept). The set is read
	/// under `order`, where its row is queued (#306): of two changes, the one
	/// queued last read the set last, so an older version never lands after a
	/// newer one (the same `generation` overwrites the row). None: the set is
	/// gone (nothing to write); otherwise whether the row is up to date.
	pub async fn save_set(&self, registry: &Registry, name: &str, by: &str) -> Option<bool> {
		self.paused_set_write().await;
		let (seq, generation, job) = {
			let _order = self.order.lock().await;
			let Some((generation, etag, owner, rules)) = registry.ruleset_row(name).await else {
				self.unwritten.lock().unwrap().sets.remove(name);
				return None;
			};
			let record = SetRecord { name: name.into(), generation, etag, owner, rules, by: by.into(), now: unix_millis() };
			let seq = self.intend(|u, seq| {
				u.sets.insert(name.into(), by.into());
				u.removed_sets.remove(name);
				u.latest_sets.insert(name.into(), seq);
			});
			(seq, generation, self.enqueue(Job::SaveSet(record)))
		};
		let result = job.await;
		self.note_lock(&result, true);
		let persisted = result.is_ok();
		let latest = {
			let mut u = self.unwritten.lock().unwrap();
			let latest = u.latest_sets.get(name) == Some(&seq);
			if latest && persisted {
				u.sets.remove(name);
				u.latest_sets.remove(name);
			}
			latest || !self.enabled()
		};
		match result {
			Ok(_) => info!(event = "ruleset.persist", ruleset = name, generation, action = "save", token = by),
			Err(_) if !self.enabled() => {}
			Err(e) => warn!(event = "degraded", part = "db", table = SETS_TABLE, ruleset = name, error = %e,
				"the rule set runs but is not stored in rproxy_rule_sets yet (it is written again by the next check)"),
		}
		if latest {
			self.sets.lock().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), persisted);
		}
		Some(persisted)
	}

	/// `pause_next_set_write` (tests).
	async fn paused_set_write(&self) {
		let pause = self.set_pause.lock().unwrap_or_else(|e| e.into_inner()).take();
		if let Some((arrived, go)) = pause {
			arrived.add_permits(1);
			if let Ok(permit) = go.acquire().await {
				permit.forget();
			}
		}
	}

	/// Deletes the row of a deleted set (`begin_remove_set`, then waits for it).
	pub async fn remove_set(&self, registry: &Registry, name: &str, by: &str) -> bool {
		match self.begin_remove_set(registry, name, by).await {
			Some(queued) => self.finish_remove_set(queued).await,
			None => false,
		}
	}

	/// Queues the deletion of the row of a set that is out of the registry now.
	/// None: nothing to delete (no database; a newer set has the name).
	pub async fn begin_remove_set(&self, registry: &Registry, name: &str, by: &str) -> Option<QueuedSet> {
		if self.queue.is_none() {
			self.sets.lock().unwrap_or_else(|e| e.into_inner()).remove(name);
			return None;
		}
		let _order = self.order.lock().await;
		if registry.ruleset_row(name).await.is_some() {
			self.unwritten.lock().unwrap().removed_sets.remove(name);
			return None;
		}
		self.sets.lock().unwrap_or_else(|e| e.into_inner()).remove(name);
		let seq = self.intend(|u, seq| {
			u.removed_sets.insert(name.into(), by.into());
			u.sets.remove(name);
			u.latest_sets.insert(name.into(), seq);
		});
		Some(QueuedSet { name: name.into(), by: by.into(), seq, job: self.enqueue(Job::RemoveSet(name.into())) })
	}

	/// Waits for a deletion `begin_remove_set` queued; whether the row is gone.
	pub async fn finish_remove_set(&self, queued: QueuedSet) -> bool {
		let QueuedSet { name, by, seq, job } = queued;
		let result = job.await;
		self.note_lock(&result, true);
		if result.is_ok() {
			let mut u = self.unwritten.lock().unwrap();
			if u.latest_sets.get(&name) == Some(&seq) {
				u.removed_sets.remove(&name);
				u.latest_sets.remove(&name);
			}
		}
		match result {
			Ok(_) => {
				info!(event = "ruleset.persist", ruleset = %name, action = "delete", token = %by);
				true
			}
			Err(e) => {
				warn!(event = "degraded", part = "db", table = SETS_TABLE, ruleset = %name, error = %e,
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

	/// Who holds the lock, and what its connection does (nothing known when it
	/// cannot be read; a user sees only its own connections).
	async fn holder(&self, conn: &mut sqlx::MySqlConnection) -> Holder {
		type Row = (Option<i64>, Option<String>, Option<String>, Option<i64>);
		let row: Result<Option<Row>, _> = sqlx::query_as(
			"SELECT CAST(h.id AS SIGNED), p.HOST, p.COMMAND, CAST(p.TIME AS SIGNED) \
			 FROM (SELECT IS_USED_LOCK(?) AS id) h LEFT JOIN information_schema.PROCESSLIST p ON p.ID = h.id",
		)
		.bind(&self.lock)
		.fetch_optional(&mut *conn)
		.await;
		match row {
			Ok(Some((connection, host, command, time))) => {
				Holder { connection, host, command, idle_secs: time.map(|t| t.max(0) as u64) }
			}
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

	async fn read_global(&self) -> JobResult {
		let mut conn = self.conn().await?;
		let query = sqlx::query(
			"SELECT CAST(spec AS CHAR) AS spec, CAST(spec_version AS SIGNED) AS spec_version, updated_by, \
			 CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at FROM rproxy_global WHERE node = ?",
		)
		.bind(&self.node);
		let row = match query.fetch_optional(&mut *conn).await {
			Ok(row) => row,
			Err(e) if missing_table(&e) => return Ok(Done::Global(None)),
			Err(e) => return Err(failed(e)),
		};
		let Some(row) = row else { return Ok(Done::Global(None)) };
		let get_str = |c: &str| row.try_get::<String, _>(c).map_err(|e| format!("{c}: {e}"));
		let get_int = |c: &str| row.try_get::<i64, _>(c).map_err(|e| format!("{c}: {e}"));
		let read = || -> Result<StoredGlobal, String> {
			let spec_version = u32::try_from(get_int("spec_version")?).unwrap_or(u32::MAX);
			// read item by item (`config::global::Values::read_stored`): what this build
			// does not know is kept as stored
			if spec_version > crate::config::global::GLOBAL_SPEC_VERSION {
				warn!(event = "restore.global", spec_version, "rproxy_global was written by a newer version; reading the items this one knows");
			}
			let spec: serde_json::Value = serde_json::from_str(&get_str("spec")?).map_err(|e| format!("spec: {e}"))?;
			if !spec.is_object() {
				return Err("spec: not an object".into());
			}
			Ok(StoredGlobal {
				spec,
				spec_version,
				updated_by: get_str("updated_by")?,
				updated_at: get_int("updated_at")?.max(0) as u64,
			})
		};
		// a row that does not read is not "no row": a change would overwrite it
		read().map(|g| Done::Global(Some(g))).map_err(|e| JobError::Failed(format!("{GLOBAL_TABLE}: {e}")))
	}

	async fn job(&mut self, job: Job) -> JobResult {
		match job {
			Job::ReadGlobal => self.read_global().await,
			Job::SaveGlobal(g) => {
				let query = sqlx::query(
					"INSERT INTO rproxy_global (node, spec, spec_version, updated_by, updated_at) \
					 VALUES (?, ?, ?, ?, FROM_UNIXTIME(? / 1000)) \
					 ON DUPLICATE KEY UPDATE spec = VALUES(spec), spec_version = VALUES(spec_version), \
					 updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)",
				)
				.bind(&self.node)
				.bind(g.spec.to_string())
				.bind(crate::config::global::GLOBAL_SPEC_VERSION)
				.bind(g.by)
				.bind(g.now);
				self.write(query).await
			}
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
				// only an open connection (a database that is down is not dialled every
				// time; the lock is tried again by `reconcile` meanwhile)
				if self.pool.size() == 0 {
					return Err(JobError::Failed("no open connection".into()));
				}
				// a statement, which keeps the connection open and shows it live (its
				// idle time starts again); a connection opened again meanwhile (the
				// old one broke) takes the lock again here
				let mut conn = self.conn().await?;
				self.take_lock(&mut conn, Duration::ZERO).await.map(|()| Done::Locked)
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
		if m.busy.load(Ordering::Relaxed) && (job.writes() || matches!(job, Job::Lock { .. } | Job::Ping)) {
			return Err(JobError::Busy(Holder { connection: Some(1), host: Some("other:1".into()), ..Default::default() }));
		}
		if job.writes() && m.fail.load(Ordering::Relaxed) {
			return Err(JobError::Failed("writes fail (test)".into()));
		}
		match job {
			Job::Lock { .. } | Job::Ping => Ok(Done::Locked),
			Job::ReadRules => Ok(Done::Rules(m.rows.lock().unwrap().values().filter(|r| r.node == self.node).cloned().collect())),
			Job::ReadSets => Ok(Done::Sets(m.sets.lock().unwrap().values().cloned().collect())),
			Job::ReadGlobal => Ok(Done::Global(m.global.lock().unwrap().clone())),
			Job::SaveGlobal(g) => {
				*m.global.lock().unwrap() =
					Some(StoredGlobal { spec: g.spec, spec_version: crate::config::global::GLOBAL_SPEC_VERSION, updated_by: g.by, updated_at: g.now / 1000 });
				Ok(Done::Ok)
			}
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
			Job::Release => Ok(Done::Ok),
		}
	}
}

impl Worker for MemoryWorker {
	fn run(&mut self, job: Job) -> JobFuture<'_> {
		let delay = Duration::from_millis(self.memory.delay_ms.load(Ordering::Relaxed));
		let wait = job.writes() && !delay.is_zero();
		Box::pin(async move {
			if wait {
				tokio::time::sleep(delay).await;
			}
			self.job(job)
		})
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

	fn registry(store: &Arc<Store>) -> Arc<Registry> {
		let r = Registry::new(crate::core::registry::Config {
			dns_interval: Duration::from_secs(30),
			lookup: crate::core::resolve::system_lookup(),
			transparent: false,
			transparent_ipv6: false,
			max_range_ports: crate::core::rule::DEFAULT_MAX_RANGE_PORTS,
			reserved: vec![],
			http: Default::default(),
		});
		r.set_persist(store.clone());
		r
	}

	fn free_port() -> u16 {
		free_ports::<1>()[0]
	}

	/// `N` different free ports: the listeners are held until all are picked, or the kernel may hand out the
	/// same port twice (a test then failed with `409 already_exists` on its own second rule).
	fn free_ports<const N: usize>() -> [u16; N] {
		let held: Vec<std::net::TcpListener> = (0..N).map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap()).collect();
		std::array::from_fn(|i| held[i].local_addr().unwrap().port())
	}

	fn local(port: u16, remote_port: u16) -> RuleRequest {
		serde_json::from_value(serde_json::json!({"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": port,
			"remote_addr": "127.0.0.1", "remote_port": remote_port}))
		.unwrap()
	}

	fn key(port: u16) -> Key {
		Key { protocol: Protocol::Tcp, listen: format!("127.0.0.1:{port}").parse().unwrap() }
	}

	fn row(port: u16, remote_port: u16) -> StoredRule {
		StoredRule { spec: local(port, remote_port), ..stored(port) }
	}

	async fn remote_port(registry: &Registry, port: u16) -> Option<u16> {
		registry.get(&key(port)).await.ok().map(|v| v.remote_port)
	}

	/// A rule whose row was not up to date in the old process of a live upgrade
	/// (`persisted: false`, adopted with no row or an older one) is written again
	/// by the check, never deleted or put back to the row; a deletion the old
	/// process could not write never brings the rule back.
	#[tokio::test]
	async fn reconcile_leaves_rules_whose_row_is_not_up_to_date() {
		let store = Arc::new(Store::memory("n1"));
		let registry = registry(&store);
		let [gone, stale, removed] = free_ports();
		// what the old process ran: `gone` has no row, `stale` an older one; `removed` was deleted, its row stayed
		for port in [gone, stale] {
			registry.create_as(local(port, 81), Origin::Api).await.unwrap();
			store.adopt(key(port), Meta { created_by: "ci".into(), created_at: 1, persisted: false });
		}
		store.memory_put_row(row(stale, 80));
		store.memory_put_row(row(removed, 80));
		store.adopt_pending(Pending {
			removed_rules: vec![PendingRule { protocol: Protocol::Tcp, listen: key(removed).listen, by: "ci".into() }],
			..Default::default()
		});
		// the database is out: nothing is written, and nothing is undone
		store.fail_writes(true);
		let r = store.reconcile(&registry).await.unwrap();
		assert_eq!((r.created, r.replaced, r.deleted, r.written), (0, 0, 0, 0), "{r:?}");
		assert_eq!((remote_port(&registry, gone).await, remote_port(&registry, stale).await), (Some(81), Some(81)));
		assert_eq!(remote_port(&registry, removed).await, None);
		// back: the rows follow the running rules
		store.fail_writes(false);
		let r = store.reconcile(&registry).await.unwrap();
		assert_eq!((r.created, r.replaced, r.deleted, r.written), (0, 0, 0, 3), "{r:?}");
		let mut rows: Vec<(u16, u16)> = store.memory_rows().iter().map(|r| (r.spec.listen_port, r.spec.remote_port)).collect();
		rows.sort();
		let mut want = vec![(gone, 81), (stale, 81)];
		want.sort();
		assert_eq!(rows, want);
		assert_eq!(registry.get(&key(gone)).await.unwrap().persisted, Some(true));
		// and from now on the rows win
		store.memory_put_row(row(stale, 82));
		let r = store.reconcile(&registry).await.unwrap();
		assert_eq!(r.replaced, 1, "{r:?}");
		assert_eq!(remote_port(&registry, stale).await, Some(82));
	}

	/// The check writes again what did not go through without holding up the
	/// API's changes meanwhile.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn reconcile_does_not_hold_up_changes_while_it_writes_again() {
		let store = Arc::new(Store::memory("n1"));
		let registry = registry(&store);
		store.fail_writes(true);
		let ports = free_ports::<3>();
		for &port in &ports {
			registry.create_as(local(port, 81), Origin::Api).await.unwrap();
			assert!(!store.save(&registry, &key(port), "ci").await);
		}
		store.fail_writes(false);
		store.delay_writes(Duration::from_millis(400));
		let check = tokio::spawn({
			let (store, registry) = (store.clone(), registry.clone());
			async move { store.reconcile(&registry).await }
		});
		tokio::time::sleep(Duration::from_millis(100)).await;
		let started = Instant::now();
		let change = store.changing().await;
		assert!(started.elapsed() < Duration::from_millis(100), "a change waited {:?}", started.elapsed());
		drop(change);
		let r = check.await.unwrap().unwrap();
		assert_eq!(r.written, 3, "{r:?}");
		assert_eq!(store.memory_rows().len(), 3);
	}

	/// A row that does not make a rule is said once and not counted as created
	/// again every round; it is a failed rule of the list (#327).
	#[tokio::test]
	async fn reconcile_counts_an_invalid_row_once() {
		let store = Arc::new(Store::memory("n1"));
		let registry = registry(&store);
		let port = free_port();
		store.memory_put_row(row(port, 0));
		for _ in 0..3 {
			let r = store.reconcile(&registry).await.unwrap();
			assert_eq!((r.created, r.skipped), (0, None), "{r:?}");
		}
		let view = registry.get(&key(port)).await.unwrap();
		assert_eq!((view.state, view.origin), (crate::core::rule::State::Failed, Origin::Api));
		// once the row is right, the rule starts
		store.memory_put_row(row(port, 80));
		assert_eq!(store.reconcile(&registry).await.unwrap().created, 1);
		assert_eq!(remote_port(&registry, port).await, Some(80));
	}

	/// The deletion of an older rule's row (a drain, then the write) does not
	/// delete the row of the newer rule with the same key, nor its `persisted`.
	#[tokio::test]
	async fn a_late_removal_spares_a_newer_rule_with_the_key() {
		let store = Arc::new(Store::memory("n1"));
		let registry = registry(&store);
		let port = free_port();
		registry.create_as(local(port, 81), Origin::Api).await.unwrap();
		assert!(store.save(&registry, &key(port), "ci").await);
		let taken = registry.take(&key(port)).await.unwrap();
		registry.stop_taken(taken, None).await;
		registry.create_as(local(port, 82), Origin::Api).await.unwrap();
		assert!(store.save(&registry, &key(port), "ci").await);
		// the removal of the first rule, late
		assert!(!store.remove(&registry, &key(port), "ci").await);
		assert_eq!(store.memory_rows().iter().map(|r| r.spec.remote_port).collect::<Vec<_>>(), [82]);
		assert_eq!(registry.get(&key(port)).await.unwrap().persisted, Some(true));
		// without the newer rule the row goes
		registry.delete(&key(port), None).await.unwrap();
		assert!(store.remove(&registry, &key(port), "ci").await);
		assert!(store.memory_rows().is_empty());
	}

	/// A write that is on its way is never taken for missing: the check leaves
	/// its rule alone until it is done.
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn a_write_on_its_way_is_not_undone() {
		let store = Arc::new(Store::memory("n1"));
		let registry = registry(&store);
		let port = free_port();
		registry.create_as(local(port, 81), Origin::Api).await.unwrap();
		store.delay_writes(Duration::from_millis(500));
		let save = tokio::spawn({
			let (store, registry) = (store.clone(), registry.clone());
			async move { store.save(&registry, &key(port), "ci").await }
		});
		tokio::time::sleep(Duration::from_millis(100)).await;
		assert!(store.is_unwritten(&key(port)));
		let r = store.reconcile(&registry).await.unwrap();
		assert_eq!(r.deleted, 0, "{r:?}");
		assert!(save.await.unwrap());
		assert!(!store.is_unwritten(&key(port)));
		assert_eq!(remote_port(&registry, port).await, Some(81));
	}

	/// Lock tracking: a write that went through shows the lock held and ends a
	/// busy episode (a later one starts its own `DUPLICATE_AFTER`).
	#[tokio::test]
	async fn a_write_that_went_through_ends_a_busy_episode() {
		let store = Arc::new(Store::memory("n1"));
		let registry = registry(&store);
		let port = free_port();
		registry.create_as(local(port, 81), Origin::Api).await.unwrap();
		store.memory_busy(true);
		assert!(!store.save(&registry, &key(port), "ci").await);
		assert!(!store.holds_lock());
		assert!(store.lock.lock().unwrap().busy_since.is_some());
		store.memory_busy(false);
		assert!(store.save(&registry, &key(port), "ci").await);
		assert!(store.holds_lock());
		assert!(store.lock.lock().unwrap().busy_since.is_none());
	}

	/// `release` waits for a change under way only so long.
	#[tokio::test]
	async fn release_does_not_wait_for_ever() {
		let store = Arc::new(Store::memory("n1"));
		let _change = store.changing().await;
		let started = Instant::now();
		store.release_within(Duration::from_millis(200)).await;
		assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
		assert_eq!(store.reconcile(&registry(&store)).await.unwrap().skipped, Some("released"));
	}

	fn looked(command: &str, idle_secs: u64, at_secs: u64) -> (Holder, Duration) {
		let h = Holder { connection: Some(7), host: Some("h:1".into()), command: Some(command.into()), idle_secs: Some(idle_secs) };
		(h, Duration::from_secs(at_secs))
	}

	/// The startup's steps while another connection holds this node's lock
	/// (#307): a holder that pings is refused, also one that took the lock just
	/// before and restores for long (it pings from the lock on); on MySQL a long
	/// statement that ended between the looks is not taken for a live one
	/// (unsure: a third look), and a holder still unsure after it is not
	/// refused.
	#[test]
	fn the_startup_refuses_only_a_holder_shown_live() {
		let second = DUPLICATE_STARTUP_WAIT.saturating_sub(STARTUP_WAIT);
		let first_at = STARTUP_WAIT.as_secs();
		let second_at = DUPLICATE_STARTUP_WAIT.as_secs();
		// idle for longer than a live rproxy at the first look: left behind
		assert_eq!(after_looks(&[looked("Sleep", LIVE_IDLE.as_secs(), first_at)]), Startup::Proceed);
		assert_eq!(after_looks(&[looked("Sleep", 3, first_at)]), Startup::LookAgain(second));
		assert_eq!(after_looks(&[looked("Query", 3, first_at)]), Startup::LookAgain(second));
		// it pinged in between (a live process, restoring or not)
		assert_eq!(after_looks(&[looked("Sleep", 3, first_at), looked("Sleep", 5, second_at)]), Startup::Refuse);
		// idle all along
		assert_eq!(after_looks(&[looked("Sleep", 3, first_at), looked("Sleep", 35, second_at)]), Startup::Proceed);
		// MySQL, a dead host's long write that ended in between: look again
		let ended = [looked("Query", 20, first_at), looked("Sleep", 3, second_at)];
		assert_eq!(after_looks(&ended), Startup::LookAgain(DUPLICATE_LOOK_AGAIN));
		let third_at = second_at + DUPLICATE_LOOK_AGAIN.as_secs();
		// stayed idle: not live, the startup goes on
		assert_eq!(after_looks(&[ended[0].clone(), ended[1].clone(), looked("Sleep", 3 + DUPLICATE_LOOK_AGAIN.as_secs(), third_at)]), Startup::Proceed);
		// pinged meanwhile: live
		assert_eq!(after_looks(&[ended[0].clone(), ended[1].clone(), looked("Sleep", 4, third_at)]), Startup::Refuse);
		// still unsure at the third look: not refused
		assert_eq!(after_looks(&[ended[0].clone(), ended[1].clone(), looked("Query", 30, third_at), looked("Sleep", 1, third_at + 20)]), Startup::Proceed);
	}

	/// What a live upgrade hands over reads back.
	#[test]
	fn pending_writes_read_back() {
		let p = Pending {
			rules: vec![PendingRule { protocol: Protocol::Udp, listen: "[::]:53".parse().unwrap(), by: "ci".into() }],
			removed_sets: vec![PendingSet { name: "a/b".into(), by: "ui".into() }],
			..Default::default()
		};
		assert_eq!(serde_json::from_value::<Pending>(serde_json::to_value(&p).unwrap()).unwrap(), p);
		assert_eq!(serde_json::from_str::<Pending>("{}").unwrap(), Pending::default());
	}
}
