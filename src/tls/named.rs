//! Certificates stored through the control API (#240, v0.4.2,
//! docs/DESIGN-v0.4.x.md 3.): `PUT /certs/{name}` writes a certificate and its
//! key under `RPROXY_CERT_STORE`, and rules name it with `{"cert": "<name>"}`
//! in `tls.certificates[]`.
//!
//! Layout: `<dir>/<name>/<first 16 hex digits of the fingerprint>/{tls.crt,tls.key}`
//! (`tls.crt` holds the chain after the certificate), with the symbolic link
//! `<dir>/<name>/current` swapped to the newest version, so the certificate
//! store (`certstore`) reads them like any other files and notices a swap.
//! rproxy writes them itself: directories 0700, files 0600 (the UI of the
//! .deb shares the `rproxy` group), which the owner check (`net::files`)
//! accepts. Keys never go to the DB, the logs or an answer.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::tls::certstore::rfc3339;
use crate::tls::config::{self as tlsconf, KeyedCert};

/// `RPROXY_CERT_STORE`'s default (the .deb's `StateDirectory`).
pub const DEFAULT_DIR: &str = "/var/lib/rproxy/certs";

const MISSING: &str = " is not in the certificate store";

/// The error of a rule naming a certificate that is not stored.
pub fn missing(name: &str) -> ApiError {
	ApiError::tls_config(format!("certificate {name:?}{MISSING} (PUT /certs/{name})"))
}

/// Whether a failed rule waits for a certificate to be stored (it starts once
/// the certificate is `PUT`).
pub fn is_missing(error: &str) -> bool {
	error.contains(MISSING)
}

/// Largest `PUT /certs/{name}` body.
pub const MAX_BODY: usize = 1 << 20;

const CERT: &str = "tls.crt";
const KEY: &str = "tls.key";
const META: &str = "meta.json";
const CURRENT: &str = "current";

static DIR: RwLock<Option<PathBuf>> = RwLock::new(None);
/// One change at a time.
static WRITES: Mutex<()> = Mutex::new(());

/// Sets the store's directory (startup; tests).
pub fn set_dir(dir: PathBuf) {
	*DIR.write().unwrap_or_else(|e| e.into_inner()) = Some(dir);
}

/// The store's directory.
pub fn dir() -> PathBuf {
	DIR.read().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}

/// `[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?`: usable in a path and a URL as is.
pub fn validate_name(name: &str) -> Result<(), ApiError> {
	let b = name.as_bytes();
	let inner = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-');
	let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
	let ok = !b.is_empty()
		&& b.len() <= 63
		&& b.first().is_some_and(edge)
		&& b.last().is_some_and(edge)
		&& b.iter().all(inner)
		&& !name.contains("..");
	match ok {
		true => Ok(()),
		false => Err(ApiError::invalid(format!(
			"certificate name {name:?}: use 1-63 of a-z, 0-9, '.', '_', '-', starting and ending with a letter or digit"
		))),
	}
}

/// The files a rule naming `name` reads: (certificate with chain, key).
pub fn files(name: &str) -> (String, String) {
	let current = dir().join(name).join(CURRENT);
	(current.join(CERT).display().to_string(), current.join(KEY).display().to_string())
}

/// The body of `PUT /certs/{name}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutRequest {
	/// PEM certificate (may hold its chain after it, leaf first).
	pub cert: String,
	/// PEM private key (PKCS#8, PKCS#1 or SEC1).
	pub key: String,
	/// PEM intermediate CA certificates.
	#[serde(default)]
	pub chain: Option<String>,
}

/// One stored certificate (never its key).
#[derive(Clone, Debug, Serialize)]
pub struct CertView {
	pub name: String,
	/// DNS names it is valid for (subjectAltName, else the common name).
	pub sans: Vec<String>,
	/// RFC 3339 (UTC).
	pub not_before: String,
	pub not_after: String,
	/// SHA-256 of the certificate (DER), hex; `If-Match` takes it.
	pub fingerprint_sha256: String,
	pub issuer: String,
	/// Rules that name it (`protocol/addr:port`).
	pub used_by: Vec<String>,
	pub updated_at: String,
	pub updated_by: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Meta {
	updated_by: String,
	/// Unix seconds.
	updated_at: i64,
}

/// What a `PUT` did.
pub struct Stored {
	pub view: CertView,
	/// The name was new.
	pub created: bool,
	pub warnings: Vec<String>,
}

fn store_error(e: impl std::fmt::Display) -> ApiError {
	ApiError {
		status: axum::http::StatusCode::SERVICE_UNAVAILABLE,
		code: "cert_store_unavailable",
		message: format!("certificate store {}: {e}", dir().display()),
	}
}

/// Creates the store's directory (0700) if missing and checks rproxy can write
/// there. At startup: an error is logged (`degraded`) and `PUT` answers
/// `503 cert_store_unavailable` until it works.
pub fn prepare() -> io::Result<()> {
	let dir = dir();
	fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
	let probe = dir.join(format!(".probe-{}", std::process::id()));
	fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&probe)?;
	fs::remove_file(&probe)
}

fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fingerprint(der: &[u8]) -> String {
	hex(&Sha256::digest(der))
}

fn parse_chain(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>, ApiError> {
	let certs: Vec<_> = CertificateDer::pem_slice_iter(pem.as_bytes())
		.collect::<Result<_, _>>()
		.map_err(|e| ApiError::invalid(format!("{what}: {e}")))?;
	if certs.is_empty() {
		return Err(ApiError::invalid(format!("{what}: no CERTIFICATE block")));
	}
	Ok(certs)
}

/// The view of a certificate chain (leaf first) and its metadata.
fn view_of(name: &str, chain: &[CertificateDer<'_>], meta: &Meta) -> CertView {
	let leaf = chain[0].as_ref();
	let (not_before, not_after, issuer) = match x509_parser::parse_x509_certificate(leaf) {
		Ok((_, c)) => (c.validity().not_before.timestamp(), c.validity().not_after.timestamp(), c.issuer().to_string()),
		Err(_) => (0, 0, String::new()),
	};
	CertView {
		name: name.to_string(),
		sans: tlsconf::cert_names(&chain[0]),
		not_before: rfc3339(not_before),
		not_after: rfc3339(not_after),
		fingerprint_sha256: fingerprint(leaf),
		issuer,
		used_by: vec![],
		updated_at: rfc3339(meta.updated_at),
		updated_by: meta.updated_by.clone(),
	}
}

/// Reads one stored certificate (`404 not_found` if there is none).
pub fn read(name: &str) -> Result<CertView, ApiError> {
	validate_name(name)?;
	let base = dir().join(name);
	let pem = match fs::read_to_string(base.join(CURRENT).join(CERT)) {
		Ok(p) => p,
		Err(e) if e.kind() == io::ErrorKind::NotFound => {
			return Err(ApiError::not_found(format!("no certificate {name:?} in the certificate store")))
		}
		Err(e) => return Err(store_error(e)),
	};
	let chain = parse_chain(&pem, name).map_err(|e| store_error(e.message))?;
	let meta: Meta = fs::read(base.join(META)).ok().and_then(|m| serde_json::from_slice(&m).ok()).unwrap_or_default();
	Ok(view_of(name, &chain, &meta))
}

/// Every stored certificate, by name (unreadable entries are left out).
pub fn list() -> Vec<CertView> {
	let mut names: Vec<String> = fs::read_dir(dir())
		.into_iter()
		.flatten()
		.flatten()
		.filter_map(|e| e.file_name().into_string().ok())
		.filter(|n| validate_name(n).is_ok())
		.collect();
	names.sort();
	names.iter().filter_map(|n| read(n).ok()).collect()
}

/// The `If-Match` header against the current fingerprint (quotes and `W/`
/// allowed; `*`: it exists).
fn if_match(header: &str, current: Option<&str>) -> bool {
	header.split(',').map(|v| v.trim().trim_start_matches("W/").trim_matches('"')).any(|v| match current {
		Some(c) => v == "*" || v.eq_ignore_ascii_case(c),
		None => false,
	})
}

fn write_file(path: &Path, data: &[u8]) -> io::Result<()> {
	let tmp = path.with_extension("tmp");
	let _ = fs::remove_file(&tmp);
	let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
	f.write_all(data)?;
	f.sync_all()?;
	fs::rename(&tmp, path)
}

fn sync_dir(path: &Path) -> io::Result<()> {
	fs::File::open(path)?.sync_all()
}

/// Checks and stores a certificate (`PUT /certs/{name}`): the PEM parses, the
/// key matches, it has not expired. `warn_secs`: warn when it expires sooner.
pub fn put(name: &str, req: &PutRequest, by: &str, if_match_header: Option<&str>, warn_secs: i64) -> Result<Stored, ApiError> {
	validate_name(name)?;
	let mut chain = parse_chain(&req.cert, "cert")?;
	if let Some(extra) = &req.chain {
		for c in parse_chain(extra, "chain")? {
			if !chain.contains(&c) {
				chain.push(c);
			}
		}
	}
	let key = PrivateKeyDer::from_pem_slice(req.key.as_bytes()).map_err(|e| match e {
		rustls::pki_types::pem::Error::NoItemsFound => ApiError::invalid("key: no private key block"),
		e => ApiError::invalid(format!("key: {e}")),
	})?;
	let keyed = KeyedCert::from_parts(chain.clone(), key.clone_key(), "cert", "key").map_err(|e| ApiError::invalid(e.message))?;
	tlsconf::check_chain_order(&chain, "cert").map_err(|e| ApiError::invalid(e.message))?;
	let now = tlsconf::unix_now();
	if keyed.expired(now) {
		return Err(ApiError::invalid(format!("the certificate expired on {}", rfc3339(keyed.not_after))));
	}
	let mut warnings = vec![];
	if keyed.not_after - now <= warn_secs {
		warnings.push(format!("the certificate expires on {} ({} days left)", rfc3339(keyed.not_after), (keyed.not_after - now) / 86_400));
	}

	let _one = WRITES.lock().unwrap_or_else(|e| e.into_inner());
	let current = read(name).ok();
	if let Some(h) = if_match_header {
		if !if_match(h, current.as_ref().map(|c| c.fingerprint_sha256.as_str())) {
			return Err(ApiError {
				status: axum::http::StatusCode::PRECONDITION_FAILED,
				code: "precondition_failed",
				message: format!("If-Match {h:?} does not match the certificate {name:?}"),
			});
		}
	}
	let print = fingerprint(chain[0].as_ref());
	let base = dir().join(name);
	let version = &print[..16];
	let vdir = base.join(version);
	let mut pem = String::new();
	for c in &chain {
		pem.push_str(&pem_block("CERTIFICATE", c.as_ref()));
	}
	let key_pem = match &key {
		PrivateKeyDer::Pkcs8(k) => pem_block("PRIVATE KEY", k.secret_pkcs8_der()),
		PrivateKeyDer::Pkcs1(k) => pem_block("RSA PRIVATE KEY", k.secret_pkcs1_der()),
		PrivateKeyDer::Sec1(k) => pem_block("EC PRIVATE KEY", k.secret_sec1_der()),
		_ => return Err(ApiError::invalid("key: unsupported key type")),
	};
	let write = || -> io::Result<()> {
		let mut builder = fs::DirBuilder::new();
		builder.recursive(true).mode(0o700);
		builder.create(&vdir)?;
		write_file(&vdir.join(CERT), pem.as_bytes())?;
		write_file(&vdir.join(KEY), key_pem.as_bytes())?;
		sync_dir(&vdir)?;
		let meta = Meta { updated_by: by.to_string(), updated_at: now };
		write_file(&base.join(META), &serde_json::to_vec(&meta).unwrap_or_default())?;
		// swap `current` in one rename
		let link = base.join("current.tmp");
		let _ = fs::remove_file(&link);
		std::os::unix::fs::symlink(version, &link)?;
		fs::rename(&link, base.join(CURRENT))?;
		sync_dir(&base)?;
		// older versions
		for e in fs::read_dir(&base)?.flatten() {
			let n = e.file_name();
			if n != version && e.file_type().is_ok_and(|t| t.is_dir()) {
				let _ = fs::remove_dir_all(e.path());
			}
		}
		Ok(())
	};
	write().map_err(store_error)?;
	let meta = Meta { updated_by: by.to_string(), updated_at: now };
	Ok(Stored { view: view_of(name, &chain, &meta), created: current.is_none(), warnings })
}

/// Removes a stored certificate (`404 not_found` if there is none). The
/// caller has checked no rule uses it.
pub fn remove(name: &str, if_match_header: Option<&str>) -> Result<CertView, ApiError> {
	validate_name(name)?;
	let _one = WRITES.lock().unwrap_or_else(|e| e.into_inner());
	let current = read(name)?;
	if let Some(h) = if_match_header {
		if !if_match(h, Some(&current.fingerprint_sha256)) {
			return Err(ApiError {
				status: axum::http::StatusCode::PRECONDITION_FAILED,
				code: "precondition_failed",
				message: format!("If-Match {h:?} does not match the certificate {name:?}"),
			});
		}
	}
	fs::remove_dir_all(dir().join(name)).map_err(store_error)?;
	let _ = sync_dir(&dir());
	Ok(current)
}

fn pem_block(label: &str, der: &[u8]) -> String {
	use base64::Engine;
	let b64 = base64::engine::general_purpose::STANDARD.encode(der);
	let mut out = format!("-----BEGIN {label}-----\n");
	for line in b64.as_bytes().chunks(64) {
		out.push_str(std::str::from_utf8(line).unwrap_or_default());
		out.push('\n');
	}
	out.push_str(&format!("-----END {label}-----\n"));
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn names() {
		for ok in ["a", "example.com", "web-1", "a_b.c-d", "0"] {
			assert!(validate_name(ok).is_ok(), "{ok}");
		}
		for bad in ["", "-a", "a-", "A", "a/b", "a..b", ".", "..", "a b", &"a".repeat(64), "café"] {
			assert!(validate_name(bad).is_err(), "{bad}");
		}
	}

	#[test]
	fn if_match_forms() {
		assert!(if_match("\"abc\"", Some("abc")));
		assert!(if_match("W/\"x\", abc", Some("ABC")));
		assert!(if_match("*", Some("abc")));
		assert!(!if_match("*", None));
		assert!(!if_match("abd", Some("abc")));
	}
}
