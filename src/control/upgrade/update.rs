//! The container self-update (#174, docs/DESIGN-v0.4.md 10.2): follows the
//! newest signed patch of this build's major.minor.
//!
//! Releases are read from `RPROXY_UPDATE_SOURCE` (GitHub's releases, or a
//! mirror with the same paths): `<source>/download/v<X.Y.Z>/manifest.json`,
//! its `.minisig`, the binary `rproxy-api-v<X.Y.Z>-<target>` and its `.minisig`.
//! Which releases exist comes from the signed index
//! `<source>/latest/download/releases.json` (every release of every minor,
//! written by the release workflow with each release: patch numbers have gaps,
//! since only the repository whose code changed is released). The manifest (version, whether a handoff is allowed,
//! SHA-256 of each file) and the binary must both be signed by the release key
//! (`RPROXY_UPDATE_PUBKEY`, or the key built in), and the binary's hash must
//! match the manifest; nothing else is run.
//!
//! The cache (`RPROXY_UPDATE_CACHE`) keeps verified releases as
//! `<cache>/<version>/` and `state.json`: the good version, the one before it
//! (to go back to), the bad versions (never chosen again) and the version on
//! trial (swapped in, not yet `RPROXY_UPDATE_HEALTHY`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::minisign::{self, PublicKey};
use super::UpdateMode;

/// A release version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u64, pub u64, pub u64);

impl Version {
	pub fn parse(s: &str) -> Option<Version> {
		let mut it = s.trim().trim_start_matches('v').split('.').map(|p| p.parse::<u64>().ok());
		let v = Version(it.next()??, it.next()??, it.next()??);
		it.next().is_none().then_some(v)
	}

	/// This build's version.
	pub fn own() -> Version {
		Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Version(0, 0, 0))
	}

	fn same_minor(&self, other: &Version) -> bool {
		(self.0, self.1) == (other.0, other.1)
	}
}

impl std::fmt::Display for Version {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}.{}.{}", self.0, self.1, self.2)
	}
}

/// The target triple of this build, as in the release's file names.
pub fn target() -> &'static str {
	macro_rules! triple {
		($arch:literal) => {
			if cfg!(target_env = "musl") {
				concat!($arch, "-unknown-linux-musl")
			} else {
				concat!($arch, "-unknown-linux-gnu")
			}
		};
	}
	if cfg!(target_arch = "x86_64") {
		triple!("x86_64")
	} else if cfg!(target_arch = "aarch64") {
		triple!("aarch64")
	} else if cfg!(target_arch = "arm") {
		if cfg!(target_env = "musl") {
			"armv7-unknown-linux-musleabihf"
		} else {
			"armv7-unknown-linux-gnueabihf"
		}
	} else {
		"unknown"
	}
}

/// The release's binary for this target.
pub fn asset_name(v: Version) -> String {
	format!("rproxy-api-v{v}-{}", target())
}

const BINARY: &str = "rproxy-api";
/// The largest binary fetched (release binaries are a few tens of MiB; written
/// to the cache as it arrives, not held in memory).
const MAX_BINARY: u64 = 1 << 30;
const MAX_SMALL: usize = 1 << 20;
/// The release index: `<source>/latest/download/releases.json` (and `.minisig`).
pub const INDEX: &str = "releases.json";

/// The release key built in (`RPROXY_RELEASE_PUBKEY` when the release was
/// built: the base64 line of minisign.pub). None in builds without one.
pub const RELEASE_PUBKEY: Option<&str> = option_env!("RPROXY_RELEASE_PUBKEY");

/// `manifest.json` of a release.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
	pub version: String,
	/// False for a patch that cannot be swapped in without a restart.
	#[serde(default = "yes")]
	pub handoff: bool,
	/// File name → SHA-256 (hex).
	#[serde(default)]
	pub files: BTreeMap<String, String>,
}

fn yes() -> bool {
	true
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trial {
	pub version: String,
	pub started_at: u64,
	/// Times the container stopped abruptly (SIGKILL, OOM) while this version was on trial;
	/// at `MAX_INTERRUPTED` it counts as bad (security review M1).
	#[serde(default, skip_serializing_if = "is_zero")]
	pub interrupted: u32,
}

fn is_zero(n: &u32) -> bool {
	*n == 0
}

/// Abrupt stops on trial before a version counts as bad: one could be anyone's
/// `docker kill`, three in a row look like the version.
pub const MAX_INTERRUPTED: u32 = 3;

/// Takes versions off the bad list (`DELETE /admin/update/bad`, `rproxy-api update-clear-bad`):
/// all of them, or `version`. Returns the ones taken off.
pub fn clear_bad(cfg: &UpdateConfig, version: Option<Version>) -> Result<Vec<String>, String> {
	cfg.update_state(|s| {
		let (gone, kept): (Vec<String>, Vec<String>) =
			s.bad.drain(..).partition(|b| version.is_none_or(|v| Version::parse(b) == Some(v)));
		s.bad = kept;
		gone
	})
}

/// `<cache>/state.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheState {
	#[serde(default)]
	pub good: Option<String>,
	#[serde(default)]
	pub previous: Option<String>,
	#[serde(default)]
	pub bad: Vec<String>,
	#[serde(default)]
	pub trial: Option<Trial>,
}

/// The self-update settings, resolved.
#[derive(Clone, Debug)]
pub struct UpdateConfig {
	pub mode: UpdateMode,
	pub pin: Option<Version>,
	pub source: String,
	pub cache: PathBuf,
	pub interval: Duration,
	pub pubkey: Option<PathBuf>,
	pub healthy: Duration,
	/// CA of a mirror with a private CA (`RPROXY_UPDATE_CA_FILE`, hidden).
	pub ca_file: Option<String>,
}

impl UpdateConfig {
	/// The release key: `RPROXY_UPDATE_PUBKEY`, or the one built in.
	pub fn key(&self) -> Result<PublicKey, String> {
		match &self.pubkey {
			Some(path) => {
				let text = std::fs::read_to_string(path).map_err(|e| format!("RPROXY_UPDATE_PUBKEY {}: {e}", path.display()))?;
				PublicKey::parse(&text).map_err(|e| format!("RPROXY_UPDATE_PUBKEY {}: {e}", path.display()))
			}
			None => match RELEASE_PUBKEY.filter(|t| !t.trim().is_empty()) {
				Some(text) => PublicKey::parse(text),
				None => Err("no release key is built into this binary; set RPROXY_UPDATE_PUBKEY (minisign public key file)".into()),
			},
		}
	}

	fn url(&self, v: Version, file: &str) -> String {
		format!("{}/download/v{v}/{file}", self.source.trim_end_matches('/'))
	}

	fn dir(&self, v: Version) -> PathBuf {
		self.cache.join(v.to_string())
	}

	pub fn binary(&self, v: Version) -> PathBuf {
		self.dir(v).join(BINARY)
	}

	fn state_file(&self) -> PathBuf {
		self.cache.join("state.json")
	}

	pub fn load_state(&self) -> CacheState {
		std::fs::read(self.state_file()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
	}

	pub fn save_state(&self, state: &CacheState) -> Result<(), String> {
		let path = self.state_file();
		let tmp = self.cache.join(".state.json.tmp");
		let body = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
		std::fs::write(&tmp, body).and_then(|_| std::fs::rename(&tmp, &path)).map_err(|e| format!("{}: {e}", path.display()))
	}

	/// Changes the state file under a lock file (the launcher and the server
	/// both write it).
	pub fn update_state<T>(&self, f: impl FnOnce(&mut CacheState) -> T) -> Result<T, String> {
		let _ = std::fs::create_dir_all(&self.cache);
		let lock = std::fs::OpenOptions::new()
			.create(true)
			.truncate(false)
			.write(true)
			.open(self.cache.join(".lock"))
			.map_err(|e| format!("{}: {e}", self.cache.display()))?;
		use std::os::fd::AsRawFd;
		// SAFETY: flock on a file we hold open; released when it is closed
		unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) };
		let mut state = self.load_state();
		let out = f(&mut state);
		self.save_state(&state)?;
		Ok(out)
	}

	/// The version of a binary in the cache (`<cache>/<version>/rproxy-api`).
	pub fn cached_version_of(&self, exe: &Path) -> Option<Version> {
		let dir = exe.parent()?;
		if dir.parent()? != self.cache.as_path() {
			return None;
		}
		Version::parse(dir.file_name()?.to_str()?)
	}

	/// Versions in the cache, newest first.
	pub fn cached_versions(&self) -> Vec<Version> {
		let mut out: Vec<Version> = std::fs::read_dir(&self.cache)
			.into_iter()
			.flatten()
			.flatten()
			.filter_map(|e| e.file_name().to_str().and_then(Version::parse))
			.collect();
		out.sort_unstable_by(|a, b| b.cmp(a));
		out
	}

	/// Checks a cached release again (before it runs): both signatures and the hash.
	pub fn verify_cached(&self, key: &PublicKey, v: Version) -> Result<PathBuf, String> {
		let dir = self.dir(v);
		let read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| format!("{}: {e}", dir.join(name).display()));
		let manifest_bytes = read("manifest.json")?;
		let manifest_sig = String::from_utf8_lossy(&read("manifest.json.minisig")?).into_owned();
		let manifest = check_manifest(key, v, &manifest_bytes, &manifest_sig)?;
		let sig = String::from_utf8_lossy(&read(&format!("{BINARY}.minisig"))?).into_owned();
		check_binary(key, v, &manifest, &dir.join(BINARY), &sig)?;
		Ok(dir.join(BINARY))
	}

	/// Keeps only `keep` in the cache.
	pub fn prune(&self, keep: &[Version]) {
		for v in self.cached_versions() {
			if !keep.contains(&v) {
				let _ = std::fs::remove_dir_all(self.dir(v));
			}
		}
	}
}

#[cfg(test)]
fn sha256_hex(data: &[u8]) -> String {
	use sha2::Digest;
	sha2::Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of a file, read in pieces.
fn sha256_file(path: &Path) -> Result<String, String> {
	use sha2::Digest;
	use std::io::Read;
	let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
	let mut h = sha2::Sha256::new();
	let mut buf = vec![0u8; 1 << 16];
	loop {
		match f.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => h.update(&buf[..n]),
			Err(e) => return Err(format!("{}: {e}", path.display())),
		}
	}
	Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn check_manifest(key: &PublicKey, v: Version, bytes: &[u8], sig: &str) -> Result<Manifest, String> {
	minisign::verify(key, sig, bytes).map_err(|e| format!("v{v} manifest.json: {e}"))?;
	let manifest: Manifest = serde_json::from_slice(bytes).map_err(|e| format!("v{v} manifest.json: {e}"))?;
	if Version::parse(&manifest.version) != Some(v) {
		return Err(format!("v{v} manifest.json is for {}", manifest.version));
	}
	Ok(manifest)
}

/// The binary at `path` is release `v`'s: its signature and the manifest's SHA-256.
/// `releases.json`: `{"releases": [{"version": "0.4.3"}, ...]}`, signed.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Index {
	pub releases: Vec<IndexEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct IndexEntry {
	pub version: String,
}

fn parse_index(key: &PublicKey, bytes: &[u8], sig: &str) -> Result<Vec<Version>, String> {
	minisign::verify(key, sig, bytes).map_err(|e| format!("{INDEX}: {e}"))?;
	let index: Index = serde_json::from_slice(bytes).map_err(|e| format!("{INDEX}: {e}"))?;
	Ok(index.releases.iter().filter_map(|r| Version::parse(&r.version)).collect())
}

fn check_binary(key: &PublicKey, v: Version, manifest: &Manifest, path: &Path, sig: &str) -> Result<String, String> {
	let name = asset_name(v);
	let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
	minisign::verify_reader(key, sig, std::io::BufReader::new(file)).map_err(|e| format!("{name}: {e}"))?;
	let sha = sha256_file(path)?;
	match manifest.files.get(&name) {
		Some(want) if want.eq_ignore_ascii_case(&sha) => Ok(sha),
		Some(_) => Err(format!("{name}: SHA-256 differs from manifest.json")),
		None => Err(format!("{name} is not in the v{v} manifest.json")),
	}
}

/// What one check found.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VersionView {
	pub version: String,
	pub sha256: Option<String>,
}

/// `GET /admin/update`.
#[derive(Clone, Debug, Serialize)]
pub struct Status {
	pub mode: &'static str,
	pub current: VersionView,
	pub available: Option<VersionView>,
	pub last_check: Option<u64>,
	pub error: Option<String>,
	pub bad_versions: Vec<String>,
}

pub fn mode_name(m: UpdateMode) -> &'static str {
	match m {
		UpdateMode::Off => "off",
		UpdateMode::Check => "check",
		UpdateMode::Auto => "auto",
	}
}

#[derive(Default)]
struct Found {
	available: Option<VersionView>,
	last_check: Option<u64>,
	error: Option<String>,
}

/// A verified release in the cache, newer than what runs.
#[derive(Clone, Debug)]
pub struct Fetched {
	pub version: Version,
	pub path: PathBuf,
	pub sha256: String,
	pub handoff: bool,
}

/// Fetches and verifies releases.
pub struct Fetcher {
	cfg: UpdateConfig,
	tls: tokio_rustls::TlsConnector,
}

impl Fetcher {
	pub fn new(cfg: UpdateConfig) -> Result<Fetcher, String> {
		let tls = crate::acme::http::connector(cfg.ca_file.as_deref())?;
		Ok(Fetcher { cfg, tls })
	}

	pub fn config(&self) -> &UpdateConfig {
		&self.cfg
	}

	/// GET over https, following redirects (to https only); None for 404.
	/// One HTTP/1.1 connection per request.
	async fn open(&self, url: &str) -> Result<Option<hyper::Response<hyper::body::Incoming>>, String> {
		use http_body_util::Empty;
		use hyper_util::rt::TokioIo;
		const STEP: Duration = Duration::from_secs(30);
		let mut url = url.to_string();
		for _ in 0..6 {
			if !url.starts_with("https://") {
				return Err(format!("{url}: only https:// is fetched"));
			}
			let uri: hyper::Uri = url.parse().map_err(|e| format!("{url}: {e}"))?;
			let authority = uri.authority().ok_or(format!("{url}: no host"))?.clone();
			let host = authority.host().trim_matches(|c| c == '[' || c == ']').to_string();
			let port = authority.port_u16().unwrap_or(443);
			let tcp = tokio::time::timeout(STEP, tokio::net::TcpStream::connect((host.as_str(), port)))
				.await
				.map_err(|_| format!("{authority}: timed out"))?
				.map_err(|e| format!("{authority}: {e}"))?;
			crate::net::source::nodelay(&tcp);
			let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
			let tls = tokio::time::timeout(STEP, self.tls.connect(name, tcp))
				.await
				.map_err(|_| format!("{authority}: timed out"))?
				.map_err(|e| format!("{authority}: TLS: {e}"))?;
			let (mut sender, conn) =
				hyper::client::conn::http1::handshake::<_, Empty<Bytes>>(TokioIo::new(tls)).await.map_err(|e| e.to_string())?;
			tokio::spawn(conn);
			let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
			let req = hyper::Request::get(path)
				.header(hyper::header::HOST, authority.as_str())
				.header(hyper::header::USER_AGENT, concat!("rproxy-api/", env!("CARGO_PKG_VERSION")))
				.body(Empty::new())
				.map_err(|e| format!("{url}: {e}"))?;
			let resp = tokio::time::timeout(STEP, sender.send_request(req))
				.await
				.map_err(|_| format!("{authority}: timed out"))?
				.map_err(|e| format!("{url}: {e}"))?;
			let status = resp.status();
			if status.is_redirection() {
				let next = resp.headers().get(hyper::header::LOCATION).and_then(|v| v.to_str().ok()).ok_or(format!("{url}: redirect without Location"))?;
				url = if next.starts_with('/') { format!("https://{authority}{next}") } else { next.to_string() };
				continue;
			}
			if status == hyper::StatusCode::NOT_FOUND {
				return Ok(None);
			}
			if !status.is_success() {
				return Err(format!("{url}: HTTP {status}"));
			}
			return Ok(Some(resp));
		}
		Err(format!("{url}: too many redirects"))
	}

	/// A small file (manifests, signatures) into memory.
	async fn get(&self, url: &str, max: usize) -> Result<Option<Bytes>, String> {
		use http_body_util::BodyExt;
		let Some(resp) = self.open(url).await? else { return Ok(None) };
		let body = http_body_util::Limited::new(resp.into_body(), max);
		let bytes = tokio::time::timeout(Duration::from_secs(60), body.collect())
			.await
			.map_err(|_| format!("{url}: timed out"))?
			.map_err(|e| format!("{url}: {e}"))?;
		Ok(Some(bytes.to_bytes()))
	}

	/// A binary into a file, without holding it in memory (at most `max` bytes).
	async fn get_to_file(&self, url: &str, path: &Path, max: u64) -> Result<Option<()>, String> {
		use http_body_util::BodyExt;
		use std::io::Write;
		let Some(resp) = self.open(url).await? else { return Ok(None) };
		let mut file = std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
		let mut body = resp.into_body();
		let mut written: u64 = 0;
		let copy = async {
			while let Some(frame) = body.frame().await {
				let frame = frame.map_err(|e| format!("{url}: {e}"))?;
				if let Ok(data) = frame.into_data() {
					written += data.len() as u64;
					if written > max {
						return Err(format!("{url}: larger than {max} bytes"));
					}
					file.write_all(&data).map_err(|e| format!("{}: {e}", path.display()))?;
				}
			}
			file.sync_all().map_err(|e| format!("{}: {e}", path.display()))
		};
		tokio::time::timeout(Duration::from_secs(600), copy).await.map_err(|_| format!("{url}: timed out"))??;
		Ok(Some(()))
	}

	async fn get_text(&self, url: &str) -> Result<Option<String>, String> {
		Ok(self.get(url, MAX_SMALL).await?.map(|b| String::from_utf8_lossy(&b).into_owned()))
	}

	/// Every release version in the signed index (`releases.json`, written by
	/// the release workflow with each release: all releases, every minor, so
	/// numbers that were skipped do not matter).
	async fn index(&self, key: &PublicKey) -> Result<Vec<Version>, String> {
		let base = self.cfg.source.trim_end_matches('/');
		let url = format!("{base}/latest/download/{INDEX}");
		let bytes = self.get(&url, MAX_SMALL).await?.ok_or(format!("{url} is missing"))?;
		let sig = self.get_text(&format!("{url}.minisig")).await?.ok_or(format!("{url}.minisig is missing"))?;
		parse_index(key, &bytes, &sig)
	}

	/// The signed manifest of `v`; None when there is no such release.
	async fn manifest(&self, key: &PublicKey, v: Version) -> Result<Option<(Manifest, Bytes, String)>, String> {
		let Some(bytes) = self.get(&self.cfg.url(v, "manifest.json"), MAX_SMALL).await? else { return Ok(None) };
		let sig = self.get_text(&self.cfg.url(v, "manifest.json.minisig")).await?.ok_or(format!("v{v}: manifest.json.minisig is missing"))?;
		let manifest = check_manifest(key, v, &bytes, &sig)?;
		Ok(Some((manifest, bytes, sig)))
	}

	/// The newest release after `current` within its minor (or the pin), not
	/// in `bad`, downloaded and verified into the cache. None when there is none.
	pub async fn newest(&self, current: Version, bad: &[String]) -> Result<Option<Fetched>, String> {
		let key = self.cfg.key()?;
		let is_bad = |v: &Version| bad.iter().any(|b| Version::parse(b) == Some(*v));
		let mut candidates: Vec<Version> = match self.cfg.pin {
			Some(pin) if pin != current && pin.same_minor(&current) => vec![pin],
			Some(_) => vec![],
			None => self.index(&key).await?.into_iter().filter(|v| v.same_minor(&current) && *v > current).collect(),
		};
		candidates.retain(|v| !is_bad(v));
		candidates.sort_unstable_by(|a, b| b.cmp(a));
		// the newest one whose signed manifest checks out
		let mut best = None;
		for v in candidates {
			match self.manifest(&key, v).await {
				Ok(Some(found)) => {
					best = Some((v, found));
					break;
				}
				Ok(None) => warn!(event = "update.error", version = %v, error = "listed in releases.json but its manifest.json is missing"),
				Err(e) => warn!(event = "update.error", version = %v, error = %e, "trying an older release"),
			}
		}
		let Some((v, (manifest, manifest_bytes, manifest_sig))) = best else { return Ok(None) };
		// already here and still good
		// (hashing a binary is slow work: off the runtime's threads)
		let (cfg, k) = (self.cfg.clone(), key.clone());
		let cached = tokio::task::spawn_blocking(move || {
			cfg.verify_cached(&k, v).map(|path| {
				let sha = sha256_file(&path).unwrap_or_default();
				(path, sha)
			})
		})
		.await
		.map_err(|e| e.to_string())?;
		if let Ok((path, sha)) = cached {
			return Ok(Some(Fetched { version: v, path, sha256: sha, handoff: manifest.handoff }));
		}
		let name = asset_name(v);
		let sig = self.get_text(&self.cfg.url(v, &format!("{name}.minisig"))).await?.ok_or(format!("v{v}: {name}.minisig is missing"))?;
		// into a directory of its own, moved into place once verified
		let tmp = self.cfg.cache.join(format!(".tmp-{v}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&tmp);
		std::fs::create_dir_all(&tmp).map_err(|e| format!("cache {}: {e}", self.cfg.cache.display()))?;
		let result = async {
			self.get_to_file(&self.cfg.url(v, &name), &tmp.join(BINARY), MAX_BINARY).await?.ok_or(format!("v{v}: {name} is missing"))?;
			let (k, m, file, sg) = (key.clone(), manifest.clone(), tmp.join(BINARY), sig.clone());
			let sha = tokio::task::spawn_blocking(move || check_binary(&k, v, &m, &file, &sg)).await.map_err(|e| e.to_string())??;
			let path = self.store(v, &tmp, &sig, &manifest_bytes, &manifest_sig)?;
			Ok::<_, String>((sha, path))
		}
		.await;
		let _ = std::fs::remove_dir_all(&tmp);
		let (sha, path) = result?;
		info!(event = "update.fetched", version = %v, sha256 = %sha);
		Ok(Some(Fetched { version: v, path, sha256: sha, handoff: manifest.handoff }))
	}

	/// Moves a verified release (`tmp` holds the binary) into the cache.
	fn store(&self, v: Version, tmp: &Path, sig: &str, manifest: &[u8], manifest_sig: &str) -> Result<PathBuf, String> {
		use std::os::unix::fs::PermissionsExt;
		let dir = self.cfg.dir(v);
		let write = || -> std::io::Result<()> {
			std::fs::set_permissions(tmp.join(BINARY), std::fs::Permissions::from_mode(0o755))?;
			std::fs::write(tmp.join(format!("{BINARY}.minisig")), sig)?;
			std::fs::write(tmp.join("manifest.json"), manifest)?;
			std::fs::write(tmp.join("manifest.json.minisig"), manifest_sig)?;
			let _ = std::fs::remove_dir_all(&dir);
			std::fs::rename(tmp, &dir)
		};
		write().map_err(|e| format!("cache {}: {e}", self.cfg.cache.display()))?;
		Ok(dir.join(BINARY))
	}
}

/// The version of this running process: its cache directory's, or the build's.
pub fn running_version(cfg: &UpdateConfig) -> Version {
	super::handoff::binary_on_disk().ok().and_then(|exe| cfg.cached_version_of(&exe)).unwrap_or_else(Version::own)
}

fn unix_now() -> u64 {
	std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The server's side: periodic checks, `GET` / `POST /admin/update`, and
/// keeping a version that ran `RPROXY_UPDATE_HEALTHY`.
pub struct Updater {
	fetcher: Option<Fetcher>,
	cfg: UpdateConfig,
	found: Mutex<Found>,
	checking: tokio::sync::Mutex<()>,
	upgrader: std::sync::OnceLock<Arc<super::handoff::Upgrader>>,
}

impl Updater {
	pub fn new(cfg: UpdateConfig) -> Arc<Updater> {
		let mut found = Found::default();
		let fetcher = match Fetcher::new(cfg.clone()) {
			Ok(f) => Some(f),
			Err(e) => {
				found.error = Some(e);
				None
			}
		};
		if cfg.mode != UpdateMode::Off {
			if let Err(e) = cfg.key() {
				found.error = Some(e);
			}
		}
		Arc::new(Updater { fetcher, cfg, found: Mutex::new(found), checking: tokio::sync::Mutex::new(()), upgrader: Default::default() })
	}

	pub fn config(&self) -> &UpdateConfig {
		&self.cfg
	}

	pub fn status(&self) -> Status {
		let found = self.found.lock().unwrap_or_else(|e| e.into_inner());
		let state = self.cfg.load_state();
		Status {
			mode: mode_name(self.cfg.mode),
			current: VersionView { version: running_version(&self.cfg).to_string(), sha256: super::build_sha256() },
			available: found.available.clone(),
			last_check: found.last_check,
			error: found.error.clone(),
			bad_versions: state.bad,
		}
	}

	/// Starts the periodic checks and the health timer (modes check and auto).
	pub fn spawn(self: &Arc<Self>, upgrader: Option<Arc<super::handoff::Upgrader>>) {
		if let Some(u) = upgrader {
			let cfg = self.cfg.clone();
			u.set_on_failure(Box::new(move |exe, why| {
				if let Some(v) = cfg.cached_version_of(exe) {
					mark_bad(&cfg, v, why);
				}
			}));
			let _ = self.upgrader.set(u);
		}
		if self.cfg.mode == UpdateMode::Off {
			return;
		}
		if let Err(e) = std::fs::create_dir_all(&self.cfg.cache) {
			warn!(event = "degraded", part = "update.cache", error = %format!("{}: {e}", self.cfg.cache.display()),
				"releases cannot be cached; the self-update fails until this is fixed");
		}
		// a version on trial that keeps running is good
		let cfg = self.cfg.clone();
		tokio::spawn(async move {
			tokio::time::sleep(cfg.healthy).await;
			promote(&cfg);
		});
		if self.cfg.interval > Duration::ZERO {
			let me = self.clone();
			tokio::spawn(async move {
				loop {
					tokio::time::sleep(me.cfg.interval).await;
					if let Err(e) = me.check_now().await {
						warn!(event = "update.error", error = %e);
					}
				}
			});
		}
	}

	/// Looks for a newer patch now; in `auto`, swaps it in with a handoff.
	pub async fn check_now(self: &Arc<Self>) -> Result<Option<Fetched>, String> {
		let _one = self.checking.lock().await;
		let Some(fetcher) = &self.fetcher else {
			return Err(self.found.lock().unwrap_or_else(|e| e.into_inner()).error.clone().unwrap_or_default());
		};
		let current = running_version(&self.cfg);
		let bad = self.cfg.load_state().bad;
		let result = fetcher.newest(current, &bad).await;
		{
			let mut found = self.found.lock().unwrap_or_else(|e| e.into_inner());
			found.last_check = Some(unix_now());
			match &result {
				Ok(f) => {
					found.error = None;
					found.available = f.as_ref().map(|f| VersionView { version: f.version.to_string(), sha256: Some(f.sha256.clone()) });
				}
				Err(e) => found.error = Some(e.clone()),
			}
		}
		let fetched = result?;
		let Some(f) = &fetched else {
			info!(event = "update.check", current = %current, available = "none");
			return Ok(None);
		};
		info!(event = "update.available", current = %current, version = %f.version, mode = mode_name(self.cfg.mode));
		if self.cfg.mode != UpdateMode::Auto {
			return Ok(fetched);
		}
		if !f.handoff {
			warn!(event = "update.restart_needed", version = %f.version, "this patch cannot be swapped in live; it runs after the next restart");
			return Ok(fetched);
		}
		let Some(upgrader) = self.upgrader.get() else { return Ok(fetched) };
		let v = f.version;
		self.cfg.update_state(|s| s.trial = Some(Trial { version: v.to_string(), started_at: unix_now(), interrupted: 0 }))?;
		if let Err(e) = upgrader.start(Some(f.path.clone()), "self-update") {
			self.cfg.update_state(|s| s.trial = None)?;
			return Err(e);
		}
		Ok(fetched)
	}
}

/// Marks `v` as bad (it failed to start or did not stay up).
pub fn mark_bad(cfg: &UpdateConfig, v: Version, why: &str) {
	warn!(event = "update.rollback", version = %v, error = %why, "this version is not used again");
	let _ = cfg.update_state(|s| {
		let v = v.to_string();
		if !s.bad.contains(&v) {
			s.bad.push(v.clone());
		}
		if s.trial.as_ref().is_some_and(|t| t.version == v) {
			s.trial = None;
		}
	});
}

/// The running version has stayed up `RPROXY_UPDATE_HEALTHY`: it becomes the
/// good one, the old good one is kept to go back to, the rest is removed.
pub fn promote(cfg: &UpdateConfig) {
	// a process that handed over (or is handing over) is no longer the one to judge
	if super::handoff::active() {
		return;
	}
	let running = running_version(cfg);
	let r = cfg.update_state(|s| {
		let trial = s.trial.as_ref().and_then(|t| Version::parse(&t.version));
		// another version is on trial: leave it to that one
		if trial.is_some_and(|t| t != running) {
			return None;
		}
		let promoted = trial == Some(running);
		if promoted {
			s.trial = None;
		}
		if s.good.as_deref().and_then(Version::parse) != Some(running) {
			s.previous = s.good.take();
			s.good = Some(running.to_string());
		}
		Some(promoted)
	});
	if let Ok(Some(promoted)) = r {
		let state = cfg.load_state();
		let keep: Vec<Version> = [state.good.as_deref(), state.previous.as_deref(), state.trial.as_ref().map(|t| t.version.as_str())]
			.into_iter()
			.flatten()
			.filter_map(Version::parse)
			.collect();
		cfg.prune(&keep);
		if promoted {
			info!(event = "update.healthy", version = %running);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cfg(dir: &Path) -> UpdateConfig {
		UpdateConfig {
			mode: UpdateMode::Auto,
			pin: None,
			source: "https://example.invalid/releases".into(),
			cache: dir.to_path_buf(),
			interval: Duration::ZERO,
			pubkey: None,
			healthy: Duration::from_secs(1),
			ca_file: None,
		}
	}

	#[test]
	fn versions_and_names() {
		assert_eq!(Version::parse("v0.4.12"), Some(Version(0, 4, 12)));
		assert!(Version::parse("0.4").is_none() && Version::parse("0.4.1.2").is_none() && Version::parse("x").is_none());
		assert!(Version(0, 4, 10) > Version(0, 4, 9));
		assert!(asset_name(Version(0, 4, 1)).starts_with("rproxy-api-v0.4.1-"));
		let c = cfg(Path::new("/var/cache/rproxy/update"));
		assert_eq!(c.url(Version(0, 4, 1), "manifest.json"), "https://example.invalid/releases/download/v0.4.1/manifest.json");
		assert_eq!(c.cached_version_of(Path::new("/var/cache/rproxy/update/0.4.2/rproxy-api")), Some(Version(0, 4, 2)));
		assert_eq!(c.cached_version_of(Path::new("/usr/bin/rproxy-api")), None);
	}

	#[test]
	fn the_index_is_signed() {
		let id = [3; 8];
		let (pub_text, pair) = minisign::testing::key_pair([6; 32], id);
		let key = PublicKey::parse(&pub_text).unwrap();
		let body = br#"{"releases":[{"version":"0.4.0"},{"version":"0.4.7"},{"version":"0.5.0"},{"version":"junk"}]}"#;
		let sig = minisign::testing::sign(&pair, id, body, "index");
		assert_eq!(parse_index(&key, body, &sig).unwrap(), [Version(0, 4, 0), Version(0, 4, 7), Version(0, 5, 0)]);
		assert!(parse_index(&key, br#"{"releases":[{"version":"0.4.9"}]}"#, &sig).unwrap_err().contains("does not match"));
	}

	#[test]
	fn cached_releases_are_verified_again() {
		let dir = std::env::temp_dir().join(format!("rproxy-update-unit-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let id = [7; 8];
		let (pub_text, pair) = minisign::testing::key_pair([5; 32], id);
		std::fs::write(dir.join("key.pub"), &pub_text).unwrap();
		let mut c = cfg(&dir);
		c.pubkey = Some(dir.join("key.pub"));
		let key = c.key().unwrap();
		let v = Version(0, 4, 9);
		let binary = b"#!/bin/true\n".to_vec();
		let name = asset_name(v);
		let manifest = serde_json::to_vec(&Manifest {
			version: v.to_string(),
			handoff: true,
			files: [(name.clone(), sha256_hex(&binary))].into_iter().collect(),
		})
		.unwrap();
		let f = Fetcher::new(c.clone()).unwrap();
		let tmp = dir.join(".tmp-test");
		std::fs::create_dir_all(&tmp).unwrap();
		std::fs::write(tmp.join(BINARY), &binary).unwrap();
		let path = f
			.store(v, &tmp, &minisign::testing::sign(&pair, id, &binary, "t"), &manifest, &minisign::testing::sign(&pair, id, &manifest, "m"))
			.unwrap();
		assert_eq!(c.verify_cached(&key, v).unwrap(), path);
		assert_eq!(c.cached_versions(), [v]);
		// tampered with in the cache
		std::fs::write(&path, b"#!/bin/false\n").unwrap();
		assert!(c.verify_cached(&key, v).unwrap_err().contains("does not match"));

		// state: bad versions and promotion
		mark_bad(&c, v, "test");
		assert_eq!(c.load_state().bad, ["0.4.9"]);
		// marks can be taken off (security review M1)
		mark_bad(&c, Version::parse("0.4.8").unwrap(), "test");
		assert_eq!(clear_bad(&c, Version::parse("0.4.8")).unwrap(), ["0.4.8"]);
		assert_eq!(c.load_state().bad, ["0.4.9"]);
		assert_eq!(clear_bad(&c, None).unwrap(), ["0.4.9"]);
		assert!(c.load_state().bad.is_empty());
		mark_bad(&c, v, "test");
		c.update_state(|s| s.trial = Some(Trial { version: Version::own().to_string(), started_at: 1, interrupted: 0 })).unwrap();
		promote(&c);
		let s = c.load_state();
		assert_eq!((s.trial, s.good), (None, Some(Version::own().to_string())));
		assert!(c.cached_versions().is_empty(), "pruned: 0.4.9 is neither good nor previous");
		let _ = std::fs::remove_dir_all(dir);
	}
}
