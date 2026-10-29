//! The persistence queue (#144, #241): every database job of a node — the
//! writes of rules and rule sets, the reads of the startup and of the periodic
//! check, the node's lock — goes through one queue, in order, to one worker
//! that owns the connection. So a read sees every write queued before it, and
//! there is one writer per process.
//!
//! The store talks to a `PersistQueue`. The in-process queue (`LocalQueue`: a
//! bounded channel and one task) is the only one now; another backend (an
//! external queue) can take its place without changing the callers.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use super::{StoredGlobal, StoredRule, StoredSet};
use crate::core::rule::Key;

/// One job for the database of this node.
#[derive(Debug)]
pub enum Job {
	/// Takes this node's lock, waiting up to `wait` for another connection to let go of it.
	Lock {
		wait: Duration,
	},
	/// This node's rows of `rproxy_rules`.
	ReadRules,
	/// This node's rows of `rproxy_rule_sets`.
	ReadSets,
	SaveRule(RuleRow),
	RemoveRule(Key),
	SaveSet(SetRecord),
	RemoveSet(String),
	/// This node's row of `rproxy_global` (#342).
	ReadGlobal,
	SaveGlobal(GlobalRecord),
	/// Keeps the connection open (it holds the lock), when one is open.
	Ping,
	/// The last job (the old process after a live upgrade): the connection closes
	/// and lets go of the lock; later jobs fail.
	Release,
}

impl Job {
	/// Whether the job writes a row (and so goes through only under the lock).
	pub fn writes(&self) -> bool {
		matches!(self, Job::SaveRule(_) | Job::RemoveRule(_) | Job::SaveSet(_) | Job::RemoveSet(_) | Job::SaveGlobal(_))
	}
}

/// A row of `rproxy_rules` to write.
#[derive(Clone, Debug)]
pub struct RuleRow {
	pub key: Key,
	/// `config::plan::shape` of the rule.
	pub spec: serde_json::Value,
	pub created_by: String,
	/// Unix seconds.
	pub created_at: u64,
	pub by: String,
	/// Unix milliseconds.
	pub now: u64,
}

/// A row of `rproxy_rule_sets` to write.
#[derive(Clone, Debug)]
pub struct SetRecord {
	pub name: String,
	pub generation: u64,
	pub etag: String,
	pub owner: String,
	pub rules: serde_json::Value,
	pub by: String,
	/// Unix milliseconds.
	pub now: u64,
}

/// The row of `rproxy_global` to write (#342).
#[derive(Clone, Debug)]
pub struct GlobalRecord {
	/// `config::global::Values` as JSON.
	pub spec: serde_json::Value,
	pub by: String,
	/// Unix milliseconds.
	pub now: u64,
}

/// What a job did.
#[derive(Debug)]
pub enum Done {
	Ok,
	/// `Lock`: held by this connection now.
	Locked,
	Rules(Vec<StoredRule>),
	Sets(Vec<StoredSet>),
	/// `ReadGlobal`: None when there is no row (or no table).
	Global(Option<StoredGlobal>),
}

/// Which connection holds this node's lock (what MariaDB shows of it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Holder {
	pub connection: Option<i64>,
	/// `information_schema.PROCESSLIST.HOST` (a user sees its own connections).
	pub host: Option<String>,
	/// `PROCESSLIST.COMMAND`: `Sleep` between statements.
	pub command: Option<String>,
	/// `PROCESSLIST.TIME`: seconds in that command (idle, for `Sleep`).
	pub idle_secs: Option<u64>,
}

/// Seconds the idle times of two looks at a connection may differ by beyond
/// the time between them (they are whole seconds).
const SLACK: Duration = Duration::from_secs(2);

/// What two looks at the holder of a lock say of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liveness {
	/// It sent a statement in between (or cannot be seen, or another connection holds the lock now).
	Live,
	/// Idle all the time, or running one statement all the time.
	NotLive,
	/// The statement of the earlier look ended in between and it has been idle
	/// since, for less than `LIVE_IDLE`: a live client's statement, or a dead
	/// one's long statement that MariaDB finished on its own (MySQL has no
	/// limit for statements, #307). Only a later look tells.
	Unsure,
}

impl Holder {
	/// How long the connection has been idle (None: running a statement, or not seen).
	pub fn idle(&self) -> Option<Duration> {
		(self.command.as_deref() == Some("Sleep")).then(|| Duration::from_secs(self.idle_secs.unwrap_or(0)))
	}

	/// Whether the holder is live, from this look `elapsed` after `earlier`.
	/// `PROCESSLIST.TIME` starts again when a statement starts and when it ends:
	/// - another connection took the lock meanwhile, or it cannot be seen
	///   (another user's: a dead connection would have been dropped by then):
	///   live;
	/// - the same command at both looks (idle, or running a statement): live
	///   if its time started again in between (a statement was sent: only a
	///   live client sends one), otherwise not live (idle all the time, or one
	///   statement all the time);
	/// - idle, then running a statement: a statement was sent, live;
	/// - running a statement, then idle: the statement ended, which a dead
	///   client's statement also does (on MySQL it may run long, #307). Idle
	///   for `LIVE_IDLE` or longer it is not live (a live rproxy runs a
	///   statement more often); otherwise unsure, and a later look tells.
	pub fn liveness_since(&self, earlier: &Holder, elapsed: Duration) -> Liveness {
		let (Some(now), true) = (self.command.as_deref(), self.connection == earlier.connection) else {
			return Liveness::Live;
		};
		let Some(before) = earlier.command.as_deref() else { return Liveness::Unsure };
		let secs = |h: &Holder| Duration::from_secs(h.idle_secs.unwrap_or(0));
		if before == now {
			return if secs(self) + SLACK < secs(earlier) + elapsed { Liveness::Live } else { Liveness::NotLive };
		}
		match (before == "Sleep", now == "Sleep") {
			(true, _) => Liveness::Live,
			(false, true) if secs(self) >= super::LIVE_IDLE => Liveness::NotLive,
			_ => Liveness::Unsure,
		}
	}
}

#[derive(Debug)]
pub enum JobError {
	/// Another connection holds this node's lock: a write would not be fenced.
	Busy(Holder),
	/// The queue is full (`QUEUE_CAPACITY`).
	Full,
	/// The queue is closed (`Release`).
	Closed,
	/// No answer within the job's time (`Job::deadline`); the job may still run.
	TimedOut,
	Failed(String),
}

impl fmt::Display for JobError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			JobError::Busy(h) => write!(
				f,
				"another connection (id {}, host {}) holds this node's lock: another process with the same node name?",
				h.connection.map_or_else(|| "?".to_string(), |c| c.to_string()),
				h.host.as_deref().unwrap_or("?")
			),
			JobError::Full => f.write_str("the write queue is full"),
			JobError::Closed => f.write_str("no more writes in this process (after the live upgrade)"),
			JobError::TimedOut => f.write_str("timed out"),
			JobError::Failed(e) => f.write_str(e),
		}
	}
}

pub type JobResult = Result<Done, JobError>;
pub type JobFuture<'a> = Pin<Box<dyn Future<Output = JobResult> + Send + 'a>>;

/// Where the store sends its jobs.
pub trait PersistQueue: Send + Sync {
	/// Queues `job` (before it returns: jobs run in the order of the calls) and
	/// waits for its result, at most `deadline`. Never waits for room: a full
	/// queue answers `Full` at once.
	fn submit(&self, job: Job, deadline: Duration) -> JobFuture<'static>;
	/// Whether no job is queued or running.
	fn idle(&self) -> bool;
}

/// What runs the jobs of a `LocalQueue`, one at a time.
pub trait Worker: Send + 'static {
	fn run(&mut self, job: Job) -> JobFuture<'_>;
}

type Item = (Job, oneshot::Sender<JobResult>);

/// The in-process queue: a bounded channel, consumed by one task that runs the
/// jobs in order on its `Worker`.
pub struct LocalQueue {
	tx: mpsc::Sender<Item>,
	pending: Arc<AtomicUsize>,
}

impl LocalQueue {
	/// Starts the worker task (in the current tokio runtime).
	pub fn start(capacity: usize, mut worker: impl Worker) -> LocalQueue {
		let (tx, mut rx) = mpsc::channel::<Item>(capacity);
		let pending = Arc::new(AtomicUsize::new(0));
		let done = pending.clone();
		tokio::spawn(async move {
			while let Some((job, reply)) = rx.recv().await {
				let last = matches!(job, Job::Release);
				let result = worker.run(job).await;
				done.fetch_sub(1, Ordering::AcqRel);
				let _ = reply.send(result);
				if last {
					rx.close();
					while let Ok((_, reply)) = rx.try_recv() {
						done.fetch_sub(1, Ordering::AcqRel);
						let _ = reply.send(Err(JobError::Closed));
					}
					return;
				}
			}
		});
		LocalQueue { tx, pending }
	}
}

impl PersistQueue for LocalQueue {
	fn submit(&self, job: Job, deadline: Duration) -> JobFuture<'static> {
		let (reply, answer) = oneshot::channel();
		self.pending.fetch_add(1, Ordering::AcqRel);
		let sent = self.tx.try_send((job, reply));
		if sent.is_err() {
			self.pending.fetch_sub(1, Ordering::AcqRel);
		}
		Box::pin(async move {
			match sent {
				Ok(()) => {}
				Err(mpsc::error::TrySendError::Full(_)) => return Err(JobError::Full),
				Err(mpsc::error::TrySendError::Closed(_)) => return Err(JobError::Closed),
			}
			match tokio::time::timeout(deadline, answer).await {
				Ok(Ok(result)) => result,
				Ok(Err(_)) => Err(JobError::Closed),
				Err(_) => Err(JobError::TimedOut),
			}
		})
	}

	fn idle(&self) -> bool {
		self.pending.load(Ordering::Acquire) == 0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Waits until the test lets it go, for every job.
	struct Gate(Arc<tokio::sync::Semaphore>);

	impl Worker for Gate {
		fn run(&mut self, _job: Job) -> JobFuture<'_> {
			let gate = self.0.clone();
			Box::pin(async move {
				gate.acquire().await.unwrap().forget();
				Ok(Done::Ok)
			})
		}
	}

	#[tokio::test]
	async fn a_full_queue_answers_at_once_and_jobs_run_in_order() {
		let gate = Arc::new(tokio::sync::Semaphore::new(0));
		let q = LocalQueue::start(2, Gate(gate.clone()));
		assert!(q.idle());
		// one running (held at the gate), two queued: the next one is refused at once
		let mut jobs = vec![q.submit(Job::Ping, Duration::from_secs(10))];
		tokio::time::sleep(Duration::from_millis(50)).await;
		jobs.extend((0..2).map(|_| q.submit(Job::Ping, Duration::from_secs(10))));
		let started = std::time::Instant::now();
		assert!(matches!(q.submit(Job::Ping, Duration::from_secs(10)).await, Err(JobError::Full)));
		assert!(started.elapsed() < Duration::from_millis(100));
		assert!(!q.idle());
		gate.add_permits(3);
		for j in jobs {
			assert!(matches!(j.await, Ok(Done::Ok)));
		}
		assert!(q.idle());
	}

	#[tokio::test]
	async fn an_answer_that_takes_too_long_times_out() {
		let gate = Arc::new(tokio::sync::Semaphore::new(0));
		let q = LocalQueue::start(4, Gate(gate.clone()));
		assert!(matches!(q.submit(Job::Ping, Duration::from_millis(50)).await, Err(JobError::TimedOut)));
		gate.add_permits(1);
	}

	fn holder(connection: i64, command: &str, idle_secs: u64) -> Holder {
		Holder { connection: Some(connection), host: Some("h:1".into()), command: Some(command.into()), idle_secs: Some(idle_secs) }
	}

	/// Two looks at the holder of a lock, 32 seconds apart.
	#[test]
	fn a_holder_is_live_when_it_ran_statements_in_between() {
		use Liveness::*;
		let apart = Duration::from_secs(32);
		// pinged in between: its idle time started again
		assert_eq!(holder(7, "Sleep", 4).liveness_since(&holder(7, "Sleep", 8), apart), Live);
		// idle all along (a connection left behind)
		assert_eq!(holder(7, "Sleep", 40).liveness_since(&holder(7, "Sleep", 8), apart), NotLive);
		assert_eq!(holder(7, "Sleep", 39).liveness_since(&holder(7, "Sleep", 8), apart), NotLive);
		// one statement all along (not ours)
		assert_eq!(holder(7, "Query", 40).liveness_since(&holder(7, "Query", 8), apart), NotLive);
		// a statement started in between (only a live client sends one)
		assert_eq!(holder(7, "Query", 1).liveness_since(&holder(7, "Sleep", 8), apart), Live);
		assert_eq!(holder(7, "Query", 1).liveness_since(&holder(7, "Query", 8), apart), Live);
		// another connection took the lock meanwhile, or the holder cannot be seen
		assert_eq!(holder(9, "Sleep", 30).liveness_since(&holder(7, "Sleep", 8), apart), Live);
		let unseen = Holder { connection: Some(7), ..Default::default() };
		assert_eq!(unseen.liveness_since(&unseen, apart), Live);
		assert_eq!(holder(7, "Sleep", 20).idle(), Some(Duration::from_secs(20)));
		assert_eq!(holder(7, "Query", 20).idle(), None);
	}

	/// MySQL (no limit for statements), a host that went away during a long
	/// write (#307): the first look sees the statement, the second the
	/// connection idle since it ended. That is no proof of a live client
	/// (it used to refuse the startup): unsure, and a third look tells (a live
	/// rproxy has pinged meanwhile, a dead one's connection stayed idle).
	#[test]
	fn a_statement_that_ended_in_between_is_no_proof_of_life() {
		use Liveness::*;
		let apart = Duration::from_secs(32);
		assert_eq!(holder(7, "Sleep", 3).liveness_since(&holder(7, "Query", 20), apart), Unsure);
		// idle for longer than a live rproxy ever is
		assert_eq!(holder(7, "Sleep", 16).liveness_since(&holder(7, "Query", 20), apart), NotLive);
		// the third look, 20 seconds later
		let later = Duration::from_secs(20);
		assert_eq!(holder(7, "Sleep", 23).liveness_since(&holder(7, "Sleep", 3), later), NotLive);
		assert_eq!(holder(7, "Sleep", 6).liveness_since(&holder(7, "Sleep", 3), later), Live);
		// not seen at the first look
		let unseen = Holder { connection: Some(7), host: Some("h:1".into()), ..Default::default() };
		assert_eq!(holder(7, "Sleep", 3).liveness_since(&unseen, apart), Unsure);
	}

	#[tokio::test]
	async fn nothing_runs_after_release() {
		let gate = Arc::new(tokio::sync::Semaphore::new(10));
		let q = LocalQueue::start(4, Gate(gate));
		assert!(matches!(q.submit(Job::Release, Duration::from_secs(1)).await, Ok(Done::Ok)));
		tokio::time::sleep(Duration::from_millis(20)).await;
		assert!(matches!(q.submit(Job::Ping, Duration::from_secs(1)).await, Err(JobError::Closed)));
	}
}
