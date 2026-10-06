//! The log lines of this test binary, as the real binary writes them (JSON with
//! `event`). Tests run in parallel and share them: pick lines by rule or port.

use std::io;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;

static LINES: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		self.0.lock().unwrap().extend_from_slice(buf);
		Ok(buf.len())
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
	type Writer = Sink;

	fn make_writer(&'a self) -> Sink {
		self.clone()
	}
}

/// Starts collecting `info` and above (call before the events of interest).
pub fn capture() {
	LINES.get_or_init(|| {
		let buf: Arc<Mutex<Vec<u8>>> = Arc::default();
		tracing_subscriber::fmt()
			.json()
			.flatten_event(true)
			.with_current_span(false)
			.with_span_list(false)
			.with_target(false)
			.with_env_filter("info")
			.with_writer(Sink(buf.clone()))
			.init();
		buf
	});
}

/// Lines so far that `pick` accepts.
pub fn lines(pick: impl Fn(&Value) -> bool) -> Vec<Value> {
	let Some(buf) = LINES.get() else { return vec![] };
	let text = String::from_utf8_lossy(&buf.lock().unwrap()).into_owned();
	text.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|v| pick(v)).collect()
}

/// Waits up to three seconds for a line that `pick` accepts.
pub async fn wait_for(what: &str, pick: impl Fn(&Value) -> bool) -> Value {
	let deadline = Instant::now() + Duration::from_secs(3);
	loop {
		if let Some(v) = lines(&pick).pop() {
			return v;
		}
		assert!(Instant::now() < deadline, "no log line for {what}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}
