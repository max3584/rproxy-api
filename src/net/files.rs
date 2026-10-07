//! Files referenced by rules and the settings (certificates, keys, CA bundles,
//! htpasswd, OIDC and CrowdSec secrets, ACME credentials): rproxy reads only
//! files owned by the user it runs as (owner's decision, security review). A
//! token that may write rules must not be able to make rproxy load (and so use,
//! or probe for) a file that belongs to someone else — another service's key,
//! a root-owned file.
//!
//! `strict` (the default, `global.files.owner_check`):
//! - the file (after symbolic links) is owned by rproxy's effective uid;
//! - it is not writable by the group or others;
//! - a private key or secret is not readable by others (group read is fine: the
//!   UI user `rproxy-ui` is a member of group `rproxy`);
//! - a symbolic link as the last component is owned by rproxy's uid or root
//!   (`/etc/letsencrypt/live/...` style links point into a tree rproxy owns).
//!
//! The checks are made on the opened file (fstat), so what is checked is what is read.
//! `off` turns them off (certbot's root-owned files in place; documented risk).

use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// What a file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
	/// Certificates, chains, CA bundles: others may read them.
	Public,
	/// Private keys and secrets: not readable by others.
	Secret,
}

/// `global.files.owner_check`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerCheck {
	#[default]
	Strict,
	Off,
}

/// `global.files` of the settings file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesGlobal {
	#[serde(default)]
	pub owner_check: OwnerCheck,
}

static OFF: AtomicBool = AtomicBool::new(false);

/// Sets the policy for the process (at startup, from `global.files`).
pub fn set_owner_check(check: OwnerCheck) {
	OFF.store(check == OwnerCheck::Off, Ordering::Relaxed);
}

pub fn owner_check() -> OwnerCheck {
	if OFF.load(Ordering::Relaxed) {
		OwnerCheck::Off
	} else {
		OwnerCheck::Strict
	}
}

fn euid() -> u32 {
	// SAFETY: geteuid has no preconditions
	unsafe { libc::geteuid() }
}

/// Why `meta` (of a file at `path`) may not be used; None when it may.
pub fn problem(path: &Path, link: Option<&std::fs::Metadata>, meta: &std::fs::Metadata, kind: Kind, uid: u32) -> Option<String> {
	let p = path.display();
	if let Some(link) = link.filter(|l| l.file_type().is_symlink()) {
		if link.uid() != uid && link.uid() != 0 {
			return Some(format!("{p} is a symbolic link owned by uid {}, not rproxy's (uid {uid}) or root", link.uid()));
		}
	}
	if !meta.is_file() {
		return Some(format!("{p} is not a regular file"));
	}
	if meta.uid() != uid {
		return Some(format!(
			"{p} is owned by uid {}, not by the user rproxy runs as (uid {uid}): give the file to that user (chown) or set global.files.owner_check: off",
			meta.uid()
		));
	}
	let mode = meta.mode();
	if mode & 0o022 != 0 {
		return Some(format!("{p} may be written by the group or others (mode {:o}): chmod g-w,o-w", mode & 0o7777));
	}
	if kind == Kind::Secret && mode & 0o004 != 0 {
		return Some(format!("{p} holds a key or secret and may be read by anyone (mode {:o}): chmod o-r (0600 or 0640)", mode & 0o7777));
	}
	None
}

/// Reads a file, after the checks of `owner_check`.
pub fn read(path: impl AsRef<Path>, kind: Kind) -> io::Result<Vec<u8>> {
	let path = path.as_ref();
	let mut file = std::fs::File::open(path)?;
	if owner_check() == OwnerCheck::Strict {
		let meta = file.metadata()?;
		let link = std::fs::symlink_metadata(path).ok();
		if let Some(why) = problem(path, link.as_ref(), &meta, kind, euid()) {
			return Err(io::Error::new(io::ErrorKind::PermissionDenied, Refused(why)));
		}
	}
	let mut out = vec![];
	file.read_to_end(&mut out)?;
	Ok(out)
}

/// The error of a file the owner check refused (not a permission problem of the environment).
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for Refused {}

/// Whether `e` is the owner check's refusal.
pub fn is_refused(e: &io::Error) -> bool {
	e.get_ref().is_some_and(|inner| inner.is::<Refused>())
}

/// Files created from here on are for this user only (umask 077): tests that
/// write keys and secrets, which the owner check refuses when others may read them.
#[doc(hidden)]
pub fn private_umask() {
	// SAFETY: umask has no preconditions
	unsafe { libc::umask(0o077) };
}

/// `read` as text.
pub fn read_to_string(path: impl AsRef<Path>, kind: Kind) -> io::Result<String> {
	String::from_utf8(read(path, kind)?).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::os::unix::fs::PermissionsExt;

	#[test]
	fn owner_and_modes_are_checked() {
		let dir = std::env::temp_dir().join(format!("rproxy-files-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();
		let f = dir.join("key.pem");
		std::fs::write(&f, b"k").unwrap();
		let set = |mode| std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
		set(0o600);
		assert_eq!(read(&f, Kind::Secret).unwrap(), b"k");
		set(0o640);
		assert!(read(&f, Kind::Secret).is_ok(), "group read is fine");
		set(0o644);
		assert!(read(&f, Kind::Secret).unwrap_err().to_string().contains("read by anyone"));
		assert!(read(&f, Kind::Public).is_ok(), "a certificate may be world-readable");
		set(0o664);
		assert!(read(&f, Kind::Public).unwrap_err().to_string().contains("written by the group"));
		set(0o600);
		let meta = std::fs::metadata(&f).unwrap();
		assert!(problem(&f, None, &meta, Kind::Secret, meta.uid() + 1).unwrap().contains("not by the user rproxy runs as"));
		// a symbolic link: the target is checked, and the link's owner
		let link = dir.join("link.pem");
		std::os::unix::fs::symlink(&f, &link).unwrap();
		assert!(read(&link, Kind::Secret).is_ok());
		let lmeta = std::fs::symlink_metadata(&link).unwrap();
		assert!(problem(&link, Some(&lmeta), &meta, Kind::Secret, meta.uid()).is_none());
		assert!(problem(&dir, None, &std::fs::metadata(&dir).unwrap(), Kind::Public, meta.uid()).unwrap().contains("not a regular file"));
		std::fs::remove_dir_all(dir).unwrap();
	}
}
