//! Settings shared by every `http` rule (`global.trusted_proxies`,
//! `global.access_log`), the access log and the per-route request metrics.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tracing::info;
use tracing_appender::non_blocking::{NonBlocking, WorkerGuard};
use tracing_appender::rolling::{RollingFileAppender, Rotation};

use super::crowdsec::Bouncer;
use crate::cidr::{self, Cidr};

/// Route label for requests that matched no route.
pub const NO_ROUTE: &str = "(none)";

/// Upper bounds (seconds) of the request duration histogram.
pub const BUCKETS: [f64; 11] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

enum Sink {
	/// `event = "http.access"` in the main log.
	Log,
	/// JSON lines in a file of their own, rotated daily.
	File { writer: Mutex<NonBlocking>, _guard: WorkerGuard },
}

/// The `global` settings of the L7 data plane.
pub struct HttpGlobal {
	trusted_proxies: Vec<Cidr>,
	sink: Sink,
	/// `global.crowdsec`: the bouncer the `crowdsec` middleware asks.
	crowdsec: Option<Arc<Bouncer>>,
}

impl Default for HttpGlobal {
	fn default() -> Self {
		HttpGlobal { trusted_proxies: vec![], sink: Sink::Log, crowdsec: None }
	}
}

/// Why the access log file cannot be used.
#[derive(Debug)]
pub enum AccessLogError {
	/// The directory does not exist: a configuration error.
	Config(String),
	/// It cannot be written (permissions): lines go to the main log instead.
	Unavailable(String),
}

impl HttpGlobal {
	/// `trusted_proxies` must already be validated (ConfigDoc::check).
	pub fn new(trusted_proxies: &[String], access_log: Option<&Path>, keep_files: usize) -> Result<Self, AccessLogError> {
		let trusted_proxies = cidr::parse_list(trusted_proxies).map_err(|e| AccessLogError::Config(e.message))?;
		let Some(path) = access_log else {
			return Ok(HttpGlobal { trusted_proxies, sink: Sink::Log, crowdsec: None });
		};
		let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
		if !dir.is_dir() {
			return Err(AccessLogError::Config(format!("access log directory {} does not exist", dir.display())));
		}
		let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("access");
		let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");
		let appender = RollingFileAppender::builder()
			.rotation(Rotation::DAILY)
			.filename_prefix(stem)
			.filename_suffix(ext)
			.max_log_files(keep_files.max(1))
			.build(dir)
			.map_err(|e| AccessLogError::Unavailable(format!("cannot write the access log in {}: {e}", dir.display())))?;
		let (writer, guard) = tracing_appender::non_blocking(appender);
		Ok(HttpGlobal { trusted_proxies, sink: Sink::File { writer: Mutex::new(writer), _guard: guard }, crowdsec: None })
	}

	/// Same as `new` without an access log file, for when it cannot be written.
	pub fn without_file(trusted_proxies: &[String]) -> Self {
		HttpGlobal { trusted_proxies: cidr::parse_list(trusted_proxies).unwrap_or_default(), sink: Sink::Log, crowdsec: None }
	}

	/// Attaches the CrowdSec bouncer of `global.crowdsec`.
	pub fn with_crowdsec(mut self, bouncer: Option<Arc<Bouncer>>) -> Self {
		self.crowdsec = bouncer;
		self
	}

	pub fn crowdsec(&self) -> Option<&Arc<Bouncer>> {
		self.crowdsec.as_ref()
	}

	pub fn trusts(&self, peer: IpAddr) -> bool {
		!self.trusted_proxies.is_empty() && cidr::allows(&self.trusted_proxies, peer)
	}

	/// The client of a request: the TCP peer, or, when the peer is a trusted proxy,
	/// the rightmost address of `X-Forwarded-For` that is not a trusted proxy.
	pub fn client_ip<'a>(&self, peer: IpAddr, forwarded_for: impl Iterator<Item = &'a str>) -> IpAddr {
		let peer = canonical(peer);
		if !self.trusts(peer) {
			return peer;
		}
		let chain: Vec<&str> = forwarded_for.flat_map(|v| v.split(',')).map(str::trim).filter(|s| !s.is_empty()).collect();
		let mut client = peer;
		for hop in chain.iter().rev() {
			let Some(ip) = parse_hop(hop) else { break };
			client = canonical(ip);
			if !self.trusts(client) {
				break;
			}
		}
		client
	}

	pub fn log(&self, entry: &AccessEntry) {
		match &self.sink {
			Sink::Log => info!(event = "http.access", rule = %entry.rule, route = %entry.route, service = %entry.service,
				backend = %entry.backend, client = %entry.client, method = %entry.method, host = %entry.host,
				path = %entry.path, protocol = %entry.protocol, status = entry.status, duration_ms = entry.duration_ms,
				bytes_in = entry.bytes_in, bytes_out = entry.bytes_out, user_agent = %entry.user_agent,
				sni = %entry.sni, tls_version = %entry.tls_version),
			Sink::File { writer, .. } => {
				let mut line = serde_json::to_vec(&FileLine { timestamp: now(), event: "http.access", entry }).unwrap_or_default();
				line.push(b'\n');
				let _ = writer.lock().unwrap().write_all(&line);
			}
		}
	}
}

fn now() -> String {
	time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

/// `1.2.3.4`, `1.2.3.4:5`, `2001:db8::1` or `[2001:db8::1]:5`.
fn parse_hop(hop: &str) -> Option<IpAddr> {
	if let Ok(ip) = hop.parse() {
		return Some(ip);
	}
	if let Some(rest) = hop.strip_prefix('[') {
		return rest.split(']').next()?.parse().ok();
	}
	hop.rsplit_once(':')?.0.parse().ok()
}

/// IPv4-mapped IPv6 addresses as IPv4, like `allow_from`.
pub fn canonical(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
		v4 => v4,
	}
}

/// One line of the access log.
#[derive(Clone, Debug, Default, Serialize)]
pub struct AccessEntry {
	pub rule: String,
	pub route: String,
	pub service: String,
	pub backend: String,
	pub client: String,
	pub method: String,
	pub host: String,
	/// Without the query string.
	pub path: String,
	pub protocol: String,
	pub status: u16,
	pub duration_ms: u64,
	pub bytes_in: u64,
	pub bytes_out: u64,
	pub user_agent: String,
	pub sni: String,
	pub tls_version: String,
}

#[derive(Serialize)]
struct FileLine<'a> {
	timestamp: String,
	event: &'static str,
	#[serde(flatten)]
	entry: &'a AccessEntry,
}

/// Requests of one route.
#[derive(Clone, Debug, Default)]
pub struct RouteCounters {
	/// By status class: 1xx … 5xx.
	pub by_class: [u64; 5],
	/// Cumulative counts per `BUCKETS` bound.
	pub buckets: [u64; BUCKETS.len()],
	pub duration_sum: f64,
}

impl RouteCounters {
	pub fn requests(&self) -> u64 {
		self.by_class.iter().sum()
	}

	fn record(&mut self, status: u16, duration: Duration) {
		let class = usize::from((status / 100).clamp(1, 5)) - 1;
		self.by_class[class] += 1;
		let secs = duration.as_secs_f64();
		self.duration_sum += secs;
		for (bound, count) in BUCKETS.iter().zip(self.buckets.iter_mut()) {
			if secs <= *bound {
				*count += 1;
			}
		}
	}
}

/// Requests of an `http` rule by route. Kept across changes of the rule; the
/// number of routes bounds it.
#[derive(Default)]
pub struct HttpStats {
	routes: Mutex<BTreeMap<String, RouteCounters>>,
	/// Requests refused by `rate_limit` / `in_flight`, by (route, middleware).
	limited: Mutex<BTreeMap<(String, String), u64>>,
	/// Requests refused by `crowdsec`, by (route, middleware).
	blocked: Mutex<BTreeMap<(String, String), u64>>,
}

impl HttpStats {
	pub fn record(&self, route: &str, status: u16, duration: Duration) {
		let route = if route.is_empty() { NO_ROUTE } else { route };
		let mut routes = self.routes.lock().unwrap();
		match routes.get_mut(route) {
			Some(c) => c.record(status, duration),
			None => routes.entry(route.to_string()).or_default().record(status, duration),
		}
	}

	pub fn snapshot(&self) -> BTreeMap<String, RouteCounters> {
		self.routes.lock().unwrap().clone()
	}

	pub fn limited(&self, route: &str, middleware: &str) {
		let route = if route.is_empty() { NO_ROUTE } else { route };
		*self.limited.lock().unwrap().entry((route.to_string(), middleware.to_string())).or_default() += 1;
	}

	pub fn limited_snapshot(&self) -> BTreeMap<(String, String), u64> {
		self.limited.lock().unwrap().clone()
	}

	pub fn blocked(&self, route: &str, middleware: &str) {
		let route = if route.is_empty() { NO_ROUTE } else { route };
		*self.blocked.lock().unwrap().entry((route.to_string(), middleware.to_string())).or_default() += 1;
	}

	pub fn blocked_snapshot(&self) -> BTreeMap<(String, String), u64> {
		self.blocked.lock().unwrap().clone()
	}
}

/// `stats.http` of a rule in the API.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct HttpStatsView {
	pub requests: u64,
	pub by_status: BTreeMap<&'static str, u64>,
	/// Refused by `rate_limit` / `in_flight` (also counted in `by_status` as 4xx).
	#[serde(skip_serializing_if = "is_zero")]
	pub limited: u64,
	/// Refused by `crowdsec` (also counted in `by_status` as 4xx).
	#[serde(skip_serializing_if = "is_zero")]
	pub blocked: u64,
	pub routes: BTreeMap<String, RouteStatsView>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct RouteStatsView {
	pub requests: u64,
	pub by_status: BTreeMap<&'static str, u64>,
	/// Refused by each limit middleware of the route.
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	pub limited: BTreeMap<String, u64>,
	/// Refused by each `crowdsec` middleware of the route.
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	pub blocked: BTreeMap<String, u64>,
}

fn is_zero(n: &u64) -> bool {
	*n == 0
}

pub const CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

fn by_status(counts: &[u64; 5]) -> BTreeMap<&'static str, u64> {
	CLASSES.iter().zip(counts).filter(|(_, n)| **n > 0).map(|(c, n)| (*c, *n)).collect()
}

impl HttpStatsView {
	pub fn from_stats(stats: &HttpStats) -> Self {
		let mut view = HttpStatsView::default();
		let mut total = [0u64; 5];
		for (name, c) in stats.snapshot() {
			for (t, n) in total.iter_mut().zip(c.by_class) {
				*t += n;
			}
			view.routes.insert(name, RouteStatsView { requests: c.requests(), by_status: by_status(&c.by_class), ..Default::default() });
		}
		for ((route, middleware), n) in stats.limited_snapshot() {
			view.limited += n;
			view.routes.entry(route).or_default().limited.insert(middleware, n);
		}
		for ((route, middleware), n) in stats.blocked_snapshot() {
			view.blocked += n;
			view.routes.entry(route).or_default().blocked.insert(middleware, n);
		}
		view.requests = total.iter().sum();
		view.by_status = by_status(&total);
		view
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn global(trusted: &[&str]) -> HttpGlobal {
		HttpGlobal::without_file(&trusted.iter().map(|s| s.to_string()).collect::<Vec<_>>())
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	#[test]
	fn forwarded_for_is_believed_only_from_trusted_proxies() {
		let none = global(&[]);
		assert_eq!(none.client_ip(ip("10.0.0.1"), ["203.0.113.9"].into_iter()), ip("10.0.0.1"));

		let g = global(&["10.0.0.0/8", "fd00::/8"]);
		assert_eq!(g.client_ip(ip("192.0.2.1"), ["203.0.113.9"].into_iter()), ip("192.0.2.1"), "untrusted peer");
		assert_eq!(g.client_ip(ip("10.0.0.1"), ["203.0.113.9"].into_iter()), ip("203.0.113.9"));
		// a client cannot forge its way past the rightmost untrusted hop
		assert_eq!(g.client_ip(ip("10.0.0.1"), ["1.1.1.1, 203.0.113.9, 10.0.0.2"].into_iter()), ip("203.0.113.9"));
		assert_eq!(g.client_ip(ip("10.0.0.1"), ["1.1.1.1", "203.0.113.9:4711"].into_iter()), ip("203.0.113.9"));
		assert_eq!(g.client_ip(ip("::ffff:10.0.0.1"), ["[2001:db8::5]:1"].into_iter()), ip("2001:db8::5"));
		assert_eq!(g.client_ip(ip("10.0.0.1"), [].into_iter()), ip("10.0.0.1"), "no header");
		assert_eq!(g.client_ip(ip("10.0.0.1"), ["garbage"].into_iter()), ip("10.0.0.1"));
		assert_eq!(g.client_ip(ip("10.0.0.1"), ["10.0.0.3, 10.0.0.2"].into_iter()), ip("10.0.0.3"), "only proxies");
	}

	#[test]
	fn counts_by_route_and_status_class() {
		let s = HttpStats::default();
		s.record("api", 200, Duration::from_millis(3));
		s.record("api", 204, Duration::from_millis(30));
		s.record("api", 502, Duration::from_secs(20));
		s.record("", 404, Duration::from_millis(1));
		let snap = s.snapshot();
		let api = &snap["api"];
		assert_eq!((api.requests(), api.by_class), (3, [0, 2, 0, 0, 1]));
		assert_eq!(api.buckets[0], 1, "3ms <= 5ms");
		assert_eq!(api.buckets[BUCKETS.len() - 1], 2, "20s is above every bound");
		let view = HttpStatsView::from_stats(&s);
		assert_eq!(view.requests, 4);
		assert_eq!(view.by_status, BTreeMap::from([("2xx", 2), ("4xx", 1), ("5xx", 1)]));
		assert_eq!(view.routes[NO_ROUTE].by_status, BTreeMap::from([("4xx", 1)]));
	}

	#[test]
	fn access_log_file_lines() {
		let dir = std::env::temp_dir().join(format!("rproxy-access-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let g = HttpGlobal::new(&[], Some(&dir.join("access.log")), 3).unwrap();
		g.log(&AccessEntry { rule: "tcp/0.0.0.0:80".into(), status: 200, path: "/x".into(), ..Default::default() });
		drop(g); // flushes
		let file = std::fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
		let line: serde_json::Value = serde_json::from_str(std::fs::read_to_string(file).unwrap().trim()).unwrap();
		assert_eq!((line["event"].as_str(), line["status"].as_u64(), line["path"].as_str()), (Some("http.access"), Some(200), Some("/x")));
		assert!(line["timestamp"].as_str().unwrap().contains('T'));
		std::fs::remove_dir_all(dir).unwrap();

		assert!(matches!(HttpGlobal::new(&[], Some(Path::new("/nonexistent-rproxy/a.log")), 3), Err(AccessLogError::Config(_))));
	}
}
