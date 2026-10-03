//! Reads the rules table maintained by the UI so rules survive a restart.

use std::time::Duration;

use serde::Deserialize;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::Row;
use tracing::{info, warn};

use crate::core::rule::{RuleRequest, SourceIp};
use crate::tls::config::{StartTls, TlsSpec};

const BASE: &str = "protocol, src_addr, CAST(src_port AS SIGNED) AS src_port, dist_addr, CAST(dist_port AS SIGNED) AS dist_port";

/// Newest schema first; older databases lack the later columns (see the UI's db/migrations).
const QUERIES: [(&str, Schema); 3] = [
	(
		"SELECT {BASE}, source_ip, CAST(udp_idle_secs AS SIGNED) AS udp_idle_secs, CAST(src_port_end AS SIGNED) AS src_port_end, CAST(options AS CHAR) AS options FROM forward_rules",
		Schema::WithOptions,
	),
	(
		"SELECT {BASE}, source_ip, CAST(udp_idle_secs AS SIGNED) AS udp_idle_secs FROM forward_rules",
		Schema::WithSourceIp,
	),
	("SELECT {BASE} FROM forward_rules", Schema::Legacy),
];

const UNKNOWN_COLUMN: &str = "42S22";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Schema {
	Legacy,
	WithSourceIp,
	WithOptions,
}

/// The `options` column: TLS / STARTTLS settings as JSON.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
	tls: Option<TlsSpec>,
	starttls: Option<StartTls>,
	starttls_required: Option<bool>,
	#[serde(default)]
	allow_from: Vec<String>,
	/// L7 routing (v0.3)
	http: Option<crate::l7::HttpSpec>,
	#[serde(default)]
	crowdsec: bool,
	/// Several backends (#98); dist_addr / dist_port are then ignored.
	#[serde(default)]
	targets: Vec<crate::core::balance::TargetSpec>,
	#[serde(default)]
	balance: crate::core::balance::Balance,
	health_check: Option<crate::core::balance::HealthCheckSpec>,
	/// More listen addresses (#99).
	#[serde(default)]
	extra_listen_addrs: Vec<String>,
	/// `false`: paused in the UI; kept in the table but not started (#116).
	enabled: Option<bool>,
}

fn port(value: i64, column: &str) -> Result<u16, String> {
	u16::try_from(value).map_err(|_| format!("{column} out of range: {value}"))
}

/// The rule of a row, or `None` for a rule paused in the UI (`options.enabled: false`).
fn to_request(row: &sqlx::mysql::MySqlRow, schema: Schema) -> Result<Option<RuleRequest>, String> {
	let get_str = |c: &str| row.try_get::<String, _>(c).map_err(|e| format!("{c}: {e}"));
	let get_int = |c: &str| row.try_get::<i64, _>(c).map_err(|e| format!("{c}: {e}"));
	let parse_err = |e: crate::error::ApiError| e.message;
	let mut req = RuleRequest {
		protocol: get_str("protocol")?.parse().map_err(parse_err)?,
		listen_addr: get_str("src_addr")?,
		listen_port: port(get_int("src_port")?, "src_port")?,
		listen_port_end: None,
		extra_listen_addrs: vec![],
		remote_addr: get_str("dist_addr")?,
		remote_port: port(get_int("dist_port")?, "dist_port")?,
		targets: vec![],
		balance: Default::default(),
		health_check: None,
		source_ip: SourceIp::Proxy,
		udp_idle_secs: None,
		tls: None,
		starttls: None,
		starttls_required: None,
		allow_from: vec![],
		http: None,
		crowdsec: false,
	};
	if schema != Schema::Legacy {
		req.source_ip = get_str("source_ip")?.parse().map_err(parse_err)?;
		req.udp_idle_secs = Some(get_int("udp_idle_secs")?.max(0) as u64);
	}
	if schema == Schema::WithOptions {
		req.listen_port_end = match row.try_get::<Option<i64>, _>("src_port_end").map_err(|e| e.to_string())? {
			Some(end) => Some(port(end, "src_port_end")?),
			None => None,
		};
		let options = row.try_get::<Option<String>, _>("options").map_err(|e| e.to_string())?;
		let options: Options = match options.as_deref().map(str::trim) {
			None | Some("") | Some("null") => Options::default(),
			Some(json) => serde_json::from_str(json).map_err(|e| format!("options: {e}"))?,
		};
		if options.enabled == Some(false) {
			return Ok(None);
		}
		req.tls = options.tls;
		req.starttls = options.starttls;
		req.starttls_required = options.starttls_required;
		req.allow_from = options.allow_from;
		req.http = options.http;
		req.crowdsec = options.crowdsec;
		if !options.targets.is_empty() {
			req.remote_addr = String::new();
			req.remote_port = 0;
			req.targets = options.targets;
		}
		req.balance = options.balance;
		req.health_check = options.health_check;
		req.extra_listen_addrs = options.extra_listen_addrs;
	}
	Ok(Some(req))
}

pub async fn load_rules(url: &str) -> Result<Vec<RuleRequest>, sqlx::Error> {
	let pool = MySqlPoolOptions::new()
		.max_connections(1)
		.acquire_timeout(Duration::from_secs(10))
		.connect(url)
		.await?;

	let mut loaded = None;
	for (i, (sql, schema)) in QUERIES.iter().enumerate() {
		// built only from the constants above (no input), so it is safe to run as is
		let sql = sqlx::AssertSqlSafe(sql.replace("{BASE}", BASE));
		match sqlx::query(sql).fetch_all(&pool).await {
			Ok(rows) => {
				if i > 0 {
					warn!(event = "restore.legacy_schema", schema = ?schema, "newer columns missing; using defaults");
				}
				loaded = Some((rows, *schema));
				break;
			}
			Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some(UNKNOWN_COLUMN) && i + 1 < QUERIES.len() => {}
			Err(e) => {
				pool.close().await;
				return Err(e);
			}
		}
	}
	pool.close().await;
	let (rows, schema) = loaded.expect("the last query either succeeds or returns");

	let mut paused = 0;
	let rules = rows
		.iter()
		.filter_map(|row| match to_request(row, schema) {
			Ok(Some(req)) => Some(req),
			Ok(None) => {
				paused += 1;
				None
			}
			Err(e) => {
				warn!(event = "restore.skip", error = %e);
				None
			}
		})
		.collect();
	if paused > 0 {
		info!(event = "restore.paused", rules = paused, "rules paused in the UI are not started");
	}
	Ok(rules)
}
