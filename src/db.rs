//! Reads the rules table maintained by the UI so rules survive a restart.

use std::time::Duration;

use sqlx::mysql::MySqlPoolOptions;
use sqlx::Row;
use tracing::warn;

use crate::rule::{RuleRequest, SourceIp};

const QUERY: &str = "SELECT protocol, src_addr, CAST(src_port AS SIGNED) AS src_port, dist_addr, \
	CAST(dist_port AS SIGNED) AS dist_port, source_ip, CAST(udp_idle_secs AS SIGNED) AS udp_idle_secs \
	FROM forward_rules";

/// For databases created before `source_ip` and `udp_idle_secs` existed.
const LEGACY_QUERY: &str = "SELECT protocol, src_addr, CAST(src_port AS SIGNED) AS src_port, dist_addr, \
	CAST(dist_port AS SIGNED) AS dist_port FROM forward_rules";

const UNKNOWN_COLUMN: &str = "42S22";

fn port(value: i64, column: &str) -> Result<u16, String> {
	u16::try_from(value).map_err(|_| format!("{column} out of range: {value}"))
}

fn to_request(row: &sqlx::mysql::MySqlRow, legacy: bool) -> Result<RuleRequest, String> {
	let get_str = |c: &str| row.try_get::<String, _>(c).map_err(|e| format!("{c}: {e}"));
	let get_int = |c: &str| row.try_get::<i64, _>(c).map_err(|e| format!("{c}: {e}"));
	let source_ip = if legacy {
		SourceIp::Proxy
	} else {
		get_str("source_ip")?.parse().map_err(|e: crate::error::ApiError| e.message)?
	};
	let udp_idle_secs = if legacy { None } else { Some(get_int("udp_idle_secs")?.max(0) as u64) };
	Ok(RuleRequest {
		protocol: get_str("protocol")?.parse().map_err(|e: crate::error::ApiError| e.message)?,
		listen_addr: get_str("src_addr")?,
		listen_port: port(get_int("src_port")?, "src_port")?,
		remote_addr: get_str("dist_addr")?,
		remote_port: port(get_int("dist_port")?, "dist_port")?,
		source_ip,
		udp_idle_secs,
	})
}

pub async fn load_rules(url: &str) -> Result<Vec<RuleRequest>, sqlx::Error> {
	let pool = MySqlPoolOptions::new()
		.max_connections(1)
		.acquire_timeout(Duration::from_secs(10))
		.connect(url)
		.await?;

	let (rows, legacy) = match sqlx::query(QUERY).fetch_all(&pool).await {
		Ok(rows) => (rows, false),
		Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some(UNKNOWN_COLUMN) => {
			warn!(event = "restore.legacy_schema", error = %e, "source_ip / udp_idle_secs missing; using defaults");
			(sqlx::query(LEGACY_QUERY).fetch_all(&pool).await?, true)
		}
		Err(e) => return Err(e),
	};
	pool.close().await;

	Ok(rows
		.iter()
		.filter_map(|row| match to_request(row, legacy) {
			Ok(req) => Some(req),
			Err(e) => {
				warn!(event = "restore.skip", error = %e);
				None
			}
		})
		.collect())
}
