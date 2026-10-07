//! GeoIP (#168, docs/DESIGN-v0.4.md 7.): MaxMind databases (mmdb) given in
//! `global.geoip`, and allow / deny lists of countries and ASNs for a rule (L4,
//! right after accepting) and for the `geoip` middleware (L7).
//!
//! The databases are read into memory (no mmap: a file replaced under a map
//! would change under the readers) and looked at again every `check_interval`
//! and on SIGHUP; a version that does not load keeps the current one
//! (`event = "degraded"`, `part: "geoip"`). Nothing is bundled: GeoLite2 needs
//! a MaxMind account (or another provider's mmdb with the same fields).

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::error::ApiError;

/// Default of `global.geoip.check_interval`.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// `global.geoip`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoipGlobal {
	/// A Country or City database (mmdb); needed by `*_countries`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub country_db: Option<String>,
	/// An ASN database (mmdb); needed by `*_asns`.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub asn_db: Option<String>,
	/// How often to check the files for changes (default 1m; 0s: never).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub check_interval: Option<String>,
	/// Add the country (and ASN) to conn.open, conn.denied and http.access.
	#[serde(default)]
	pub log_country: bool,
}

impl GeoipGlobal {
	pub fn check(&self) -> Result<(), String> {
		if self.country_db.is_none() && self.asn_db.is_none() {
			return Err("global.geoip needs country_db or asn_db".into());
		}
		for (what, path) in [("country_db", &self.country_db), ("asn_db", &self.asn_db)] {
			if path.as_ref().is_some_and(|p| p.trim().is_empty()) {
				return Err(format!("global.geoip.{what} must not be empty"));
			}
		}
		if let Some(i) = &self.check_interval {
			if i != "0s" {
				crate::l7::parse_duration(i).map_err(|e| format!("global.geoip.check_interval: {e}"))?;
			}
		}
		Ok(())
	}

	/// How often the files are looked at; None: never (`0s`).
	pub fn interval(&self) -> Option<Duration> {
		match self.check_interval.as_deref() {
			None => Some(DEFAULT_CHECK_INTERVAL),
			Some(i) => crate::l7::parse_duration(i).ok().filter(|d| !d.is_zero()),
		}
	}
}

/// What to do with clients the databases do not know (or private addresses).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unknown {
	#[default]
	Allow,
	Deny,
}

/// `geoip` of a rule, and of the `geoip` middleware.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoipSpec {
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allow_countries: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub deny_countries: Vec<String>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub allow_asns: Vec<u32>,
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub deny_asns: Vec<u32>,
	#[serde(default, skip_serializing_if = "is_allow")]
	pub unknown: Unknown,
}

fn is_allow(u: &Unknown) -> bool {
	*u == Unknown::Allow
}

impl GeoipSpec {
	/// `{}`: no lists (how PATCH removes them).
	pub fn is_empty(&self) -> bool {
		*self == GeoipSpec::default()
	}

	pub fn uses_countries(&self) -> bool {
		!self.allow_countries.is_empty() || !self.deny_countries.is_empty()
	}

	pub fn uses_asns(&self) -> bool {
		!self.allow_asns.is_empty() || !self.deny_asns.is_empty()
	}

	pub fn validate(&self, what: &str) -> Result<(), ApiError> {
		if !self.uses_countries() && !self.uses_asns() {
			return Err(ApiError::invalid(format!("{what} needs a list (allow_countries, deny_countries, allow_asns or deny_asns)")));
		}
		for c in self.allow_countries.iter().chain(&self.deny_countries) {
			if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
				return Err(ApiError::invalid(format!("{what}: {c:?} is not a country code (ISO 3166-1 alpha-2, e.g. JP)")));
			}
		}
		if let Some(c) = self.allow_countries.iter().find(|c| self.deny_countries.contains(c)) {
			return Err(ApiError::invalid(format!("{what}: {c} is in both allow_countries and deny_countries")));
		}
		if self.allow_asns.iter().chain(&self.deny_asns).any(|a| *a == 0) {
			return Err(ApiError::invalid(format!("{what}: ASNs are 1-4294967295")));
		}
		if let Some(a) = self.allow_asns.iter().find(|a| self.deny_asns.contains(a)) {
			return Err(ApiError::invalid(format!("{what}: AS{a} is in both allow_asns and deny_asns")));
		}
		Ok(())
	}

	/// The databases the lists need, against `global.geoip` (settings file).
	pub fn check_databases(&self, what: &str, global: Option<&GeoipGlobal>) -> Result<(), String> {
		let has = |f: fn(&GeoipGlobal) -> bool| global.is_some_and(f);
		if self.uses_countries() && !has(|g| g.country_db.is_some()) {
			return Err(format!("{what}: country lists need global.geoip.country_db"));
		}
		if self.uses_asns() && !has(|g| g.asn_db.is_some()) {
			return Err(format!("{what}: ASN lists need global.geoip.asn_db"));
		}
		Ok(())
	}
}

/// A country code as in the databases (`JP`, also regions like `EU`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Country([u8; 2]);

impl Country {
	pub fn parse(code: &str) -> Option<Country> {
		match code.as_bytes() {
			[a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => Some(Country([a.to_ascii_uppercase(), b.to_ascii_uppercase()])),
			_ => None,
		}
	}

	pub fn as_str(&self) -> &str {
		std::str::from_utf8(&self.0).unwrap_or("")
	}
}

impl std::fmt::Display for Country {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(self.as_str())
	}
}

/// What the databases say about an address (None: not known, or no database).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
	pub country: Option<Country>,
	pub asn: Option<u32>,
}

impl Info {
	/// For log fields: `country` is left out when not known.
	pub fn country_str(&self) -> Option<&str> {
		self.country.as_ref().map(Country::as_str)
	}
}

/// A compiled `geoip` of a rule or of the middleware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
	allow_countries: Vec<Country>,
	deny_countries: Vec<Country>,
	allow_asns: Vec<u32>,
	deny_asns: Vec<u32>,
	unknown: Unknown,
}

impl Policy {
	/// `spec` must be validated (`GeoipSpec::validate`).
	pub fn new(spec: &GeoipSpec) -> Policy {
		let codes = |list: &[String]| list.iter().filter_map(|c| Country::parse(c)).collect();
		Policy {
			allow_countries: codes(&spec.allow_countries),
			deny_countries: codes(&spec.deny_countries),
			allow_asns: spec.allow_asns.clone(),
			deny_asns: spec.deny_asns.clone(),
			unknown: spec.unknown,
		}
	}

	/// Whether a client the databases describe as `info` may pass: a `deny_*`
	/// hit refuses; with `allow_*` lists, only a hit passes; what the lists
	/// cannot decide (the country or ASN they need is not known) is `unknown`.
	pub fn allows(&self, info: &Info) -> bool {
		let hit_c = |list: &[Country]| info.country.is_some_and(|c| list.contains(&c));
		let hit_a = |list: &[u32]| info.asn.is_some_and(|a| list.contains(&a));
		if hit_c(&self.deny_countries) || hit_a(&self.deny_asns) {
			return false;
		}
		let (allow_c, allow_a) = (!self.allow_countries.is_empty(), !self.allow_asns.is_empty());
		if allow_c || allow_a {
			if hit_c(&self.allow_countries) || hit_a(&self.allow_asns) {
				return true;
			}
			// what is known misses its allow list: refused, even if the other one is not
			// known (an unknown ASN must not let a refused country in; security review L18)
			let known_miss = (allow_c && info.country.is_some()) || (allow_a && info.asn.is_some());
			if known_miss {
				return false;
			}
			return self.unknown == Unknown::Allow;
		}
		let needs_c = !self.deny_countries.is_empty();
		let needs_a = !self.deny_asns.is_empty();
		let known = (!needs_c || info.country.is_some()) && (!needs_a || info.asn.is_some());
		known || self.unknown == Unknown::Allow
	}
}

/// Why `global.geoip` cannot be used at startup.
#[derive(Debug)]
pub enum GeoipError {
	/// A file is missing or is not an mmdb: a configuration error.
	Config(String),
}

/// File identity, to see a replaced database.
type Stamp = (Option<SystemTime>, u64);

struct Db {
	what: &'static str,
	path: PathBuf,
	reader: RwLock<Option<Arc<Reader<Vec<u8>>>>>,
	/// The version last tried (loaded or not), and the last problem logged.
	seen: Mutex<(Option<Stamp>, Option<String>)>,
}

impl Db {
	fn new(what: &'static str, path: &str) -> Db {
		Db { what, path: PathBuf::from(path), reader: RwLock::new(None), seen: Mutex::new((None, None)) }
	}

	fn get(&self) -> Option<Arc<Reader<Vec<u8>>>> {
		self.reader.read().unwrap_or_else(|e| e.into_inner()).clone()
	}

	/// Loads the file when it changed (or `force`). Ok(true): a new version is in use.
	fn refresh(&self, force: bool) -> Result<bool, (std::io::ErrorKind, String)> {
		let meta = std::fs::metadata(&self.path).map_err(|e| (e.kind(), format!("{}: {e}", self.path.display())))?;
		let stamp = (meta.modified().ok(), meta.len());
		{
			let seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
			if !force && seen.0 == Some(stamp) {
				return Ok(false);
			}
		}
		let loaded = load(&self.path);
		self.seen.lock().unwrap_or_else(|e| e.into_inner()).0 = Some(stamp);
		let reader = loaded?;
		*self.reader.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(reader));
		Ok(true)
	}

	/// `refresh` with the logs: `geoip.reload` for a new version, `degraded`
	/// once per problem (the current version stays in use).
	fn refresh_logged(&self, force: bool) {
		match self.refresh(force) {
			Ok(changed) => {
				let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
				if changed {
					let epoch = self.get().map(|r| r.metadata().build_epoch).unwrap_or(0);
					info!(event = "geoip.reload", db = self.what, path = %self.path.display(), build_epoch = epoch);
				}
				seen.1 = None;
			}
			Err((_, e)) => {
				let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
				if seen.1.as_deref() != Some(e.as_str()) {
					let using = if self.get().is_some() { "the version read before" } else { "no database (unknown)" };
					warn!(event = "degraded", part = "geoip", db = self.what, error = %e, using);
					seen.1 = Some(e);
				}
			}
		}
	}
}

/// The largest database read (GeoLite2/GeoIP2 City are about 100 MiB).
const MAX_DB: u64 = 1 << 30;

fn load(path: &Path) -> Result<Reader<Vec<u8>>, (std::io::ErrorKind, String)> {
	let size = std::fs::metadata(path).map_err(|e| (e.kind(), format!("{}: {e}", path.display())))?.len();
	if size > MAX_DB {
		return Err((std::io::ErrorKind::InvalidData, format!("{}: larger than {} MiB", path.display(), MAX_DB >> 20)));
	}
	let bytes = std::fs::read(path).map_err(|e| (e.kind(), format!("{}: {e}", path.display())))?;
	Reader::from_source(bytes).map_err(|e| (std::io::ErrorKind::InvalidData, format!("{}: not a MaxMind database: {e}", path.display())))
}

#[derive(Deserialize)]
struct CountryRecord<'a> {
	#[serde(borrow, default)]
	country: Option<IsoCode<'a>>,
	#[serde(borrow, default)]
	registered_country: Option<IsoCode<'a>>,
}

#[derive(Deserialize)]
struct IsoCode<'a> {
	#[serde(borrow, default)]
	iso_code: Option<&'a str>,
}

#[derive(Deserialize)]
struct AsnRecord {
	#[serde(default)]
	autonomous_system_number: Option<u32>,
}

/// The databases of `global.geoip`, shared by every rule (`HttpGlobal::geoip`).
pub struct Geoip {
	spec: GeoipGlobal,
	country: Option<Db>,
	asn: Option<Db>,
	stop: CancellationToken,
}

impl std::fmt::Debug for Geoip {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Geoip").field("spec", &self.spec).finish_non_exhaustive()
	}
}

impl Geoip {
	/// Reads the databases. A missing file or one that is not an mmdb stops the
	/// startup (`GeoipError::Config`); one that cannot be read (permissions) is
	/// logged as `degraded` and tried again every `check_interval` (until then
	/// its lists see every client as unknown).
	pub fn open(spec: &GeoipGlobal) -> Result<Arc<Geoip>, GeoipError> {
		let geoip = Geoip {
			spec: spec.clone(),
			country: spec.country_db.as_deref().map(|p| Db::new("country", p)),
			asn: spec.asn_db.as_deref().map(|p| Db::new("asn", p)),
			stop: CancellationToken::new(),
		};
		for db in geoip.dbs() {
			match db.refresh(true) {
				Ok(_) => {
					let epoch = db.get().map(|r| r.metadata().build_epoch).unwrap_or(0);
					info!(event = "geoip.reload", db = db.what, path = %db.path.display(), build_epoch = epoch, phase = "startup");
				}
				Err((std::io::ErrorKind::NotFound | std::io::ErrorKind::InvalidData, e)) => {
					return Err(GeoipError::Config(format!("global.geoip.{}_db: {e}", db.what)))
				}
				Err((_, e)) => {
					warn!(event = "degraded", part = "geoip", db = db.what, error = %e,
						"clients are unknown to this database until it can be read");
					db.seen.lock().unwrap_or_else(|e| e.into_inner()).1 = Some(e);
				}
			}
		}
		Ok(Arc::new(geoip))
	}

	/// A `Geoip` from database bytes already in memory (tests).
	pub fn from_bytes(spec: GeoipGlobal, country: Option<Vec<u8>>, asn: Option<Vec<u8>>) -> Result<Arc<Geoip>, String> {
		let db = |what, bytes: Option<Vec<u8>>| -> Result<Option<Db>, String> {
			let Some(bytes) = bytes else { return Ok(None) };
			let reader = Reader::from_source(bytes).map_err(|e| e.to_string())?;
			let db = Db::new(what, "");
			*db.reader.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(reader));
			Ok(Some(db))
		};
		Ok(Arc::new(Geoip { country: db("country", country)?, asn: db("asn", asn)?, spec, stop: CancellationToken::new() }))
	}

	fn dbs(&self) -> impl Iterator<Item = &Db> {
		self.country.iter().chain(self.asn.iter())
	}

	pub fn spec(&self) -> &GeoipGlobal {
		&self.spec
	}

	/// `log_country`: conn.open, conn.denied and http.access carry the country (and ASN).
	pub fn log_country(&self) -> bool {
		self.spec.log_country
	}

	/// Looks the files at again every `check_interval` until `stop`.
	pub fn spawn(self: &Arc<Self>) {
		let Some(interval) = self.spec.interval() else { return };
		let geoip = Arc::downgrade(self);
		let stop = self.stop.clone();
		tokio::spawn(async move {
			loop {
				tokio::select! {
					_ = stop.cancelled() => return,
					_ = tokio::time::sleep(interval) => {}
				}
				let Some(g) = geoip.upgrade() else { return };
				// reading a database of tens of MB is blocking work
				let _ = tokio::task::spawn_blocking(move || g.refresh(false)).await;
			}
		});
	}

	pub fn stop(&self) {
		self.stop.cancel();
	}

	/// Re-reads the files that changed (`force`: every file, SIGHUP).
	pub fn refresh(&self, force: bool) {
		for db in self.dbs() {
			if !db.path.as_os_str().is_empty() {
				db.refresh_logged(force);
			}
		}
	}

	/// The country and ASN of `ip` (IPv4-mapped IPv6 as IPv4).
	pub fn lookup(&self, ip: IpAddr) -> Info {
		let ip = match ip {
			IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
			v4 => v4,
		};
		let mut info = Info::default();
		if let Some(reader) = self.country.as_ref().and_then(Db::get) {
			if let Ok(Some(rec)) = reader.lookup(ip).and_then(|r| r.decode::<CountryRecord>()) {
				let code = rec.country.and_then(|c| c.iso_code).or(rec.registered_country.and_then(|c| c.iso_code));
				info.country = code.and_then(Country::parse);
			}
		}
		if let Some(reader) = self.asn.as_ref().and_then(Db::get) {
			if let Ok(Some(rec)) = reader.lookup(ip).and_then(|r| r.decode::<AsnRecord>()) {
				info.asn = rec.autonomous_system_number.filter(|n| *n != 0);
			}
		}
		info
	}
}

impl Drop for Geoip {
	fn drop(&mut self) {
		self.stop.cancel();
	}
}

/// A rule's `geoip` or the middleware against the databases: Ok when the
/// client may pass, Err with what is known of it when refused. Without
/// `global.geoip` (a rule restored without it), every client is unknown.
pub fn check(policy: &Policy, geoip: Option<&Geoip>, ip: IpAddr) -> Result<Info, Info> {
	let info = geoip.map(|g| g.lookup(ip)).unwrap_or_default();
	if policy.allows(&info) {
		Ok(info)
	} else {
		Err(info)
	}
}

#[cfg(test)]
#[path = "../../tests/common/mmdb.rs"]
mod mmdb;

#[cfg(test)]
mod tests {
	use super::*;

	fn info(country: Option<&str>, asn: Option<u32>) -> Info {
		Info { country: country.and_then(Country::parse), asn }
	}

	fn policy(v: serde_json::Value) -> Policy {
		let spec: GeoipSpec = serde_json::from_value(v).unwrap();
		spec.validate("geoip").unwrap();
		Policy::new(&spec)
	}

	#[test]
	fn deny_wins_then_allow_lists_then_unknown() {
		let p = policy(serde_json::json!({"allow_countries": ["JP", "US"], "deny_asns": [64496]}));
		assert!(p.allows(&info(Some("JP"), None)));
		assert!(p.allows(&info(Some("US"), Some(64511))));
		assert!(!p.allows(&info(Some("JP"), Some(64496))), "deny first");
		assert!(!p.allows(&info(Some("DE"), None)), "known and not allowed");
		assert!(p.allows(&info(None, None)), "unknown: allow by default");
		let strict = policy(serde_json::json!({"allow_countries": ["JP"], "unknown": "deny"}));
		assert!(!strict.allows(&info(None, Some(1))));
		assert!(strict.allows(&info(Some("JP"), None)));

		// deny lists only: everything else passes, the unknown as `unknown` says
		let deny = policy(serde_json::json!({"deny_countries": ["CN"], "unknown": "deny"}));
		assert!(deny.allows(&info(Some("JP"), None)));
		assert!(!deny.allows(&info(Some("CN"), None)));
		assert!(!deny.allows(&info(None, Some(64496))));

		// either allow list lets a client in
		let either = policy(serde_json::json!({"allow_countries": ["JP"], "allow_asns": [64500]}));
		assert!(either.allows(&info(Some("US"), Some(64500))));
		assert!(!either.allows(&info(Some("US"), Some(64501))));
		assert!(!either.allows(&info(Some("US"), None)), "a known country outside the list decides, not the unknown ASN (security review L18)");
		assert!(either.allows(&info(None, None)), "nothing known: unknown");
	}

	fn write(dir: &Path, name: &str, bytes: &[u8]) -> String {
		let path = dir.join(name);
		std::fs::write(&path, bytes).unwrap();
		path.to_str().unwrap().to_string()
	}

	#[test]
	fn databases_are_read_looked_up_and_reloaded() {
		let dir = std::env::temp_dir().join(format!("rproxy-geoip-unit-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let country = mmdb::build(
			"GeoLite2-Country",
			&[
				("192.0.2.0/24", mmdb::country("JP")),
				("198.51.100.7", mmdb::registered_country("US")),
				("2001:db8::/32", mmdb::country("DE")),
			],
		);
		let asn = mmdb::build("GeoLite2-ASN", &[("192.0.2.0/25", mmdb::asn(64496, "Example"))]);
		let spec = GeoipGlobal {
			country_db: Some(write(&dir, "country.mmdb", &country)),
			asn_db: Some(write(&dir, "asn.mmdb", &asn)),
			check_interval: Some("0s".into()),
			log_country: true,
		};
		let g = Geoip::open(&spec).unwrap();
		assert_eq!(spec.interval(), None);
		let ip = |s: &str| s.parse::<IpAddr>().unwrap();
		assert_eq!(g.lookup(ip("192.0.2.1")), info(Some("JP"), Some(64496)));
		assert_eq!(g.lookup(ip("192.0.2.200")), info(Some("JP"), None));
		assert_eq!(g.lookup(ip("::ffff:192.0.2.1")), info(Some("JP"), Some(64496)), "IPv4-mapped");
		assert_eq!(g.lookup(ip("198.51.100.7")).country_str(), Some("US"), "registered_country without country");
		assert_eq!(g.lookup(ip("2001:db8::1")).country_str(), Some("DE"));
		assert_eq!(g.lookup(ip("10.0.0.1")), Info::default(), "private: unknown");

		// a broken new version keeps the current one; a good one replaces it
		std::thread::sleep(Duration::from_millis(20));
		write(&dir, "country.mmdb", b"not a database at all");
		g.refresh(false);
		assert_eq!(g.lookup(ip("192.0.2.1")).country_str(), Some("JP"));
		std::thread::sleep(Duration::from_millis(20));
		write(&dir, "country.mmdb", &mmdb::build("GeoLite2-Country", &[("192.0.2.0/24", mmdb::country("FR"))]));
		g.refresh(false);
		assert_eq!(g.lookup(ip("192.0.2.1")).country_str(), Some("FR"));

		// at startup: a missing file or one that is not an mmdb is a configuration error
		let missing = GeoipGlobal { country_db: Some(dir.join("none.mmdb").to_str().unwrap().into()), ..Default::default() };
		assert!(matches!(Geoip::open(&missing), Err(GeoipError::Config(e)) if e.contains("country_db")));
		let garbage = GeoipGlobal { asn_db: Some(write(&dir, "garbage.mmdb", b"garbage")), ..Default::default() };
		assert!(matches!(Geoip::open(&garbage), Err(GeoipError::Config(e)) if e.contains("not a MaxMind database")));
		std::fs::remove_dir_all(dir).unwrap();
	}

	fn parse(v: serde_json::Value) -> GeoipSpec {
		serde_json::from_value(v).unwrap()
	}

	#[test]
	fn shape_and_validation() {
		let ok = parse(serde_json::json!({"allow_countries": ["JP", "US"], "deny_asns": [64496], "unknown": "deny"}));
		ok.validate("geoip").unwrap();
		assert_eq!(ok.unknown, Unknown::Deny);
		for bad in [
			serde_json::json!({}),
			serde_json::json!({"allow_countries": ["jp"]}),
			serde_json::json!({"allow_countries": ["JPN"]}),
			serde_json::json!({"allow_countries": ["JP"], "deny_countries": ["JP"]}),
			serde_json::json!({"deny_asns": [0]}),
			serde_json::json!({"allow_asns": [1], "deny_asns": [1]}),
		] {
			assert_eq!(parse(bad.clone()).validate("geoip").unwrap_err().code, "invalid", "{bad}");
		}
		assert!(serde_json::from_value::<GeoipSpec>(serde_json::json!({"unknown": "maybe"})).is_err());
	}

	#[test]
	fn lists_need_their_databases() {
		let spec = parse(serde_json::json!({"allow_countries": ["JP"], "deny_asns": [64496]}));
		assert!(spec.check_databases("rule", None).unwrap_err().contains("country_db"));
		let country = GeoipGlobal { country_db: Some("/c.mmdb".into()), ..Default::default() };
		assert!(spec.check_databases("rule", Some(&country)).unwrap_err().contains("asn_db"));
		let both = GeoipGlobal { asn_db: Some("/a.mmdb".into()), ..country };
		spec.check_databases("rule", Some(&both)).unwrap();
		both.check().unwrap();
		assert!(GeoipGlobal::default().check().is_err());
		assert!(GeoipGlobal { check_interval: Some("soon".into()), ..both }.check().is_err());
	}
}
