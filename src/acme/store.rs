//! Files under `global.acme.storage`: account keys, issued certificates and the
//! DNS-01 journal. Everything is written atomically, 0600, in 0700 directories.
//!
//! ```text
//! <storage>/accounts/<account>.key        PKCS#8 PEM (unless key_file says otherwise)
//! <storage>/accounts/<account>.json       the account URL at the CA (no secret)
//! <storage>/certs/<resolver>/<first name>-<hash>/cert.pem, key.pem
//! <storage>/dns-pending.json              TXT records not removed yet
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use sha2::{Digest, Sha256};

/// The directory of one certificate: the first name plus a hash of all of them,
/// so a changed list of names is a different certificate.
pub fn cert_dir(storage: &Path, resolver: &str, domains: &[String]) -> PathBuf {
	let first: String = domains
		.first()
		.map(|d| d.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect())
		.unwrap_or_default();
	let hash = Sha256::digest(domains.join(",").as_bytes());
	let hex: String = hash.iter().take(6).map(|b| format!("{b:02x}")).collect();
	storage.join("certs").join(resolver).join(format!("{first}-{hex}"))
}

/// (certificate chain, key) files of a certificate.
pub fn cert_files(storage: &Path, resolver: &str, domains: &[String]) -> (String, String) {
	let dir = cert_dir(storage, resolver, domains);
	(dir.join("cert.pem").to_string_lossy().into_owned(), dir.join("key.pem").to_string_lossy().into_owned())
}

/// Creates `path` and its missing parents with mode 0700.
pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
	#[cfg(unix)]
	{
		use std::os::unix::fs::DirBuilderExt;
		std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path)
	}
	#[cfg(not(unix))]
	std::fs::create_dir_all(path)
}

/// Writes a file only rproxy can read (0600), replacing it atomically.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
	if let Some(parent) = path.parent() {
		create_private_dir(parent)?;
	}
	let mut name = path.file_name().unwrap_or_default().to_os_string();
	name.push(".tmp");
	let tmp = path.with_file_name(name);
	let mut options = std::fs::OpenOptions::new();
	options.write(true).create(true).truncate(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	let mut f = options.open(&tmp)?;
	f.write_all(data)?;
	f.sync_all()?;
	drop(f);
	std::fs::rename(&tmp, path)?;
	// the rename itself survives a power cut
	if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
		std::fs::File::open(parent)?.sync_all()?;
	}
	Ok(())
}

/// PEM text of one DER object.
pub fn pem(label: &str, der: &[u8]) -> String {
	let b64 = base64::engine::general_purpose::STANDARD.encode(der);
	let mut out = format!("-----BEGIN {label}-----\n");
	for chunk in b64.as_bytes().chunks(64) {
		out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
		out.push('\n');
	}
	out.push_str(&format!("-----END {label}-----\n"));
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn paths_and_private_files() {
		let a = cert_dir(Path::new("/s"), "le", &["a.example".into(), "b.example".into()]);
		let b = cert_dir(Path::new("/s"), "le", &["a.example".into()]);
		assert!(a.starts_with("/s/certs/le/") && a != b, "{a:?}");
		assert!(cert_dir(Path::new("/s"), "le", &["*.example".into()]).to_string_lossy().contains("/_.example-"));

		let dir = std::env::temp_dir().join(format!("rproxy-acme-store-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		let file = dir.join("x/y.key");
		write_private(&file, b"secret").unwrap();
		write_private(&file, b"secret2").unwrap();
		assert_eq!(std::fs::read(&file).unwrap(), b"secret2");
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
			assert_eq!(std::fs::metadata(dir.join("x")).unwrap().permissions().mode() & 0o777, 0o700);
		}
		std::fs::remove_dir_all(&dir).unwrap();
		assert_eq!(pem("X", &[0; 3]), "-----BEGIN X-----\nAAAA\n-----END X-----\n");
	}
}
