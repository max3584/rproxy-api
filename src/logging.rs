use std::path::Path;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::EnvFilter;

/// Writes one JSON object per line, to a daily-rotated file or to stdout.
/// Keep the returned guard alive until exit so buffered lines are flushed.
pub fn init(level: &str, file: Option<&Path>, keep_files: usize) -> Result<WorkerGuard, String> {
	let filter = EnvFilter::try_new(level).map_err(|e| format!("invalid log level {level:?}: {e}"))?;

	let (writer, guard) = match file {
		Some(path) => {
			let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
			let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("rproxy");
			let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");
			let appender = RollingFileAppender::builder()
				.rotation(Rotation::DAILY)
				.filename_prefix(stem)
				.filename_suffix(ext)
				.max_log_files(keep_files)
				.build(dir)
				.map_err(|e| format!("cannot open log file in {}: {e}", dir.display()))?;
			tracing_appender::non_blocking(appender)
		}
		None => tracing_appender::non_blocking(std::io::stdout()),
	};

	tracing_subscriber::fmt()
		.json()
		.flatten_event(true)
		.with_current_span(false)
		.with_span_list(false)
		.with_target(false)
		.with_env_filter(filter)
		.with_writer(writer)
		.try_init()
		.map_err(|e| e.to_string())?;
	Ok(guard)
}
