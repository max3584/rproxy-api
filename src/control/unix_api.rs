//! The control API on a Unix socket (`RPROXY_API_SOCKET`). Access is limited by
//! the socket file's mode and group; bearer tokens apply as on TCP.

use std::ffi::CString;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

pub struct SocketOptions {
	pub path: PathBuf,
	pub mode: u32,
	pub group: Option<String>,
}

/// Why the socket could not be opened.
#[derive(Debug)]
pub enum SocketError {
	/// A mistake in the settings: stop the startup.
	Config(String),
	/// The environment (permissions, another process on the socket): run without it.
	Unavailable(String),
}

/// `RPROXY_API_SOCKET_MODE`: octal, at most 0777.
pub fn parse_mode(s: &str) -> Result<u32, String> {
	match u32::from_str_radix(s.trim().trim_start_matches("0o"), 8) {
		Ok(mode) if mode <= 0o777 => Ok(mode),
		_ => Err(format!("socket mode must be octal like 660: {s}")),
	}
}

fn group_id(name: &str) -> Result<u32, String> {
	if let Ok(gid) = name.parse() {
		return Ok(gid);
	}
	let c = CString::new(name).map_err(|_| format!("invalid group name: {name:?}"))?;
	// SAFETY: getgrnam returns a pointer to static storage or null; we copy the id out at once
	let gid = unsafe {
		let entry = libc::getgrnam(c.as_ptr());
		if entry.is_null() {
			return Err(format!("no such group: {name}"));
		}
		(*entry).gr_gid
	};
	Ok(gid)
}

async fn remove_stale(path: &Path) -> Result<(), SocketError> {
	let meta = match std::fs::symlink_metadata(path) {
		Ok(meta) => meta,
		Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
		Err(e) => return Err(SocketError::Unavailable(format!("{}: {e}", path.display()))),
	};
	if !meta.file_type().is_socket() {
		return Err(SocketError::Config(format!("{} exists and is not a socket", path.display())));
	}
	if UnixStream::connect(path).await.is_ok() {
		return Err(SocketError::Unavailable(format!("{} is in use by another process", path.display())));
	}
	std::fs::remove_file(path).map_err(|e| SocketError::Unavailable(format!("{}: {e}", path.display())))
}

/// Opens the socket, replacing a stale one left by a previous run.
pub async fn bind(opts: &SocketOptions) -> Result<UnixListener, SocketError> {
	let path = &opts.path;
	let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
	if !parent.is_dir() {
		return Err(SocketError::Config(format!("{}: directory {} does not exist", path.display(), parent.display())));
	}
	let gid = match &opts.group {
		Some(g) => Some(group_id(g).map_err(|e| SocketError::Config(format!("{}: {e}", path.display())))?),
		None => None,
	};
	remove_stale(path).await?;
	let listener = UnixListener::bind(path).map_err(|e| SocketError::Unavailable(format!("{}: {e}", path.display())))?;
	let set = || -> io::Result<()> {
		if let Some(gid) = gid {
			std::os::unix::fs::chown(path, None, Some(gid))?;
		}
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(opts.mode))
	};
	if let Err(e) = set() {
		// never leave a socket open with the wrong owner or mode
		let _ = std::fs::remove_file(path);
		return Err(SocketError::Unavailable(format!("{}: setting group and mode: {e}", path.display())));
	}
	Ok(listener)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn modes() {
		assert_eq!(parse_mode("660"), Ok(0o660));
		assert_eq!(parse_mode("0600"), Ok(0o600));
		assert_eq!(parse_mode("0o770"), Ok(0o770));
		assert!(parse_mode("888").is_err());
		assert!(parse_mode("1777").is_err());
		assert!(parse_mode("rw").is_err());
	}

	#[test]
	fn groups() {
		assert_eq!(group_id("0"), Ok(0));
		assert!(group_id("no-such-group-rproxy").unwrap_err().contains("no such group"));
	}
}
