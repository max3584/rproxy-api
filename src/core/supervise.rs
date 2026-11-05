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
		match AssertUnwindSafe(make()).catch_unwind().await {
			Ok(()) => return,
			Err(p) => {
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
	}
}
