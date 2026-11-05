//! Background tasks that must not end by a panic (#358): the persist worker, the file
//! watchers, ACME, GeoIP. A panic is logged (`event = "degraded"`, `part`) and the task is
//! started again after a pause (1 s, doubled up to a minute); a task that returns ends.

use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures_util::FutureExt;
use tokio::task::JoinHandle;
use tracing::error;

const MAX_PAUSE: Duration = Duration::from_secs(60);

/// A task that ran this long before it panicked starts again after the first pause.
const STABLE: Duration = Duration::from_secs(300);

/// Restarts by `part` (`rproxy_task_restarts_total`).
static RESTARTS: std::sync::Mutex<std::collections::BTreeMap<&'static str, u64>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Counts a restart of `part` (a supervised task, or a database job that panicked).
pub fn count_restart(part: &'static str) {
	*RESTARTS.lock().unwrap_or_else(|e| e.into_inner()).entry(part).or_default() += 1;
}

/// The `GET /metrics` lines.
pub fn metrics() -> String {
	use std::fmt::Write as _;
	let restarts = RESTARTS.lock().unwrap_or_else(|e| e.into_inner()).clone();
	let mut out = String::new();
	let _ = writeln!(out, "# HELP rproxy_task_restarts_total Background tasks started again after a panic, by part.");
	let _ = writeln!(out, "# TYPE rproxy_task_restarts_total counter");
	for (part, n) in restarts {
		let _ = writeln!(out, "rproxy_task_restarts_total{{part=\"{}\"}} {n}", crate::core::prom::label(part));
	}
	out
}

/// What a panic said.
pub fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
	match (p.downcast_ref::<&str>(), p.downcast_ref::<String>()) {
		(Some(s), _) => (*s).to_string(),
		(_, Some(s)) => s.clone(),
		_ => "(not text)".to_string(),
	}
}

/// Spawns `make()`'s task, and again after it panics. Aborting the handle ends it.
pub fn spawn<F, Fut>(part: &'static str, make: F) -> JoinHandle<()>
where
	F: FnMut() -> Fut + Send + 'static,
	Fut: Future<Output = ()> + Send + 'static,
{
	tokio::spawn(run(part, make, Duration::from_secs(1)))
}

async fn run<F, Fut>(part: &'static str, mut make: F, first: Duration)
where
	F: FnMut() -> Fut,
	Fut: Future<Output = ()>,
{
	let mut pause = first;
	loop {
		let started = tokio::time::Instant::now();
		match AssertUnwindSafe(make()).catch_unwind().await {
			Ok(()) => return,
			Err(p) => {
				count_restart(part);
				if started.elapsed() >= STABLE {
					pause = first;
				}
				error!(event = "degraded", part, error = %panic_message(p.as_ref()), restart_secs = pause.as_secs_f64(),
					"a background task panicked; it is started again");
				tokio::time::sleep(pause).await;
				pause = (pause * 2).min(MAX_PAUSE);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Arc;
	use std::sync::atomic::{AtomicUsize, Ordering};

	#[tokio::test]
	async fn a_panicking_task_is_started_again() {
		let runs = Arc::new(AtomicUsize::new(0));
		let r = runs.clone();
		run(
			"test",
			move || {
				let n = r.fetch_add(1, Ordering::SeqCst);
				async move {
					if n < 2 {
						panic!("run {n}");
					}
				}
			},
			Duration::from_millis(1),
		)
		.await;
		assert_eq!(runs.load(Ordering::SeqCst), 3);
		assert!(metrics().contains("rproxy_task_restarts_total{part=\"test\"} 2"), "{}", metrics());
	}
}
