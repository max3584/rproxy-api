//! sd_notify(3) without libsystemd: `READY=1` when the startup is done, and
//! `MAINPID=<new>` when a live upgrade hands the service over (#174). systemd
//! (`Type=notify`, `NotifyAccess=all`) and `rproxy-api launch` listen on
//! `$NOTIFY_SOCKET`; without it nothing is sent.

use std::os::unix::net::UnixDatagram;

/// Sends `state` (lines like `READY=1`) to `$NOTIFY_SOCKET`; false when there
/// is none or it failed.
pub fn notify(state: &str) -> bool {
	let Some(path) = std::env::var_os("NOTIFY_SOCKET") else { return false };
	let Ok(sock) = UnixDatagram::unbound() else { return false };
	send(&sock, &path, state.as_bytes()).is_ok()
}

fn send(sock: &UnixDatagram, path: &std::ffi::OsStr, msg: &[u8]) -> std::io::Result<usize> {
	use std::os::unix::ffi::OsStrExt;
	let bytes = path.as_bytes();
	// `@name`: the abstract namespace
	if let Some(name) = bytes.strip_prefix(b"@") {
		#[cfg(target_os = "linux")]
		{
			use std::os::linux::net::SocketAddrExt;
			let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
			return sock.send_to_addr(msg, &addr);
		}
		#[cfg(not(target_os = "linux"))]
		return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, format!("abstract socket {name:?}")));
	}
	sock.send_to(msg, std::path::Path::new(path))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn messages_reach_path_and_abstract_sockets() {
		let dir = std::env::temp_dir().join(format!("rproxy-notify-{}", std::process::id()));
		let _ = std::fs::create_dir_all(&dir);
		let path = dir.join("n.sock");
		let _ = std::fs::remove_file(&path);
		let rx = UnixDatagram::bind(&path).unwrap();
		let tx = UnixDatagram::unbound().unwrap();
		send(&tx, path.as_os_str(), b"READY=1").unwrap();
		let mut buf = [0u8; 64];
		let n = rx.recv(&mut buf).unwrap();
		assert_eq!(&buf[..n], b"READY=1");
		#[cfg(target_os = "linux")]
		{
			use std::os::linux::net::SocketAddrExt;
			let name = format!("rproxy-notify-test-{}", std::process::id());
			let rx = UnixDatagram::bind_addr(&std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap()).unwrap();
			send(&tx, std::ffi::OsStr::new(&format!("@{name}")), b"MAINPID=7").unwrap();
			let n = rx.recv(&mut buf).unwrap();
			assert_eq!(&buf[..n], b"MAINPID=7");
		}
		let _ = std::fs::remove_dir_all(dir);
	}
}
