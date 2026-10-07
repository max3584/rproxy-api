//! Listening sockets received from the old process in a live upgrade (#174).
//!
//! The new process puts every socket it received here before it starts. Each
//! place that opens a listening socket (`net::listen`, the control API on TCP
//! and on the Unix socket, `global.acme.http01_listen`) asks for an inherited
//! one with the same address first, so it serves the very socket the old process
//! listened on: no connection is refused while the two processes overlap. What is
//! left after the startup is closed (`close_rest`).
//!
//! Sockets are recognised by what the kernel says about them (type, listening,
//! local address), never by what the old process claims.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
	/// A listening TCP socket.
	Tcp(SocketAddr),
	/// A bound, unconnected UDP socket.
	Udp(SocketAddr),
	/// A listening Unix stream socket with a path.
	Unix(PathBuf),
}

struct Entry {
	kind: Kind,
	fd: OwnedFd,
}

/// None outside a live upgrade (the common case: nothing to look up).
static POOL: Mutex<Option<Vec<Entry>>> = Mutex::new(None);

fn sockopt(fd: i32, level: i32, name: i32) -> Option<i32> {
	let mut v: libc::c_int = 0;
	let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
	// SAFETY: getsockopt writes at most `len` bytes into `v`
	let r = unsafe { libc::getsockopt(fd, level, name, (&mut v as *mut libc::c_int).cast(), &mut len) };
	(r == 0).then_some(v)
}

fn storage_addr(storage: &libc::sockaddr_storage) -> Option<SocketAddr> {
	match storage.ss_family as i32 {
		libc::AF_INET => {
			// SAFETY: the family says it is a sockaddr_in
			let a = unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>() };
			Some(SocketAddr::new(std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)).into(), u16::from_be(a.sin_port)))
		}
		libc::AF_INET6 => {
			// SAFETY: the family says it is a sockaddr_in6
			let a = unsafe { &*(storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>() };
			let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
			Some(SocketAddr::V6(std::net::SocketAddrV6::new(ip, u16::from_be(a.sin6_port), a.sin6_flowinfo, a.sin6_scope_id)))
		}
		_ => None,
	}
}

fn local_addr(fd: i32) -> Option<SocketAddr> {
	// SAFETY: zeroed sockaddr_storage is valid; getsockname writes at most `len` bytes
	let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
	let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
	let r = unsafe { libc::getsockname(fd, (&mut storage as *mut libc::sockaddr_storage).cast(), &mut len) };
	if r != 0 {
		return None;
	}
	storage_addr(&storage)
}

fn connected(fd: i32) -> bool {
	// SAFETY: as in local_addr
	let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
	let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
	unsafe { libc::getpeername(fd, (&mut storage as *mut libc::sockaddr_storage).cast(), &mut len) == 0 }
}

fn unix_path(fd: i32) -> Option<PathBuf> {
	use std::os::unix::ffi::OsStrExt;
	// SAFETY: zeroed sockaddr_un is valid; getsockname writes at most `len` bytes
	let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
	let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
	let r = unsafe { libc::getsockname(fd, (&mut addr as *mut libc::sockaddr_un).cast(), &mut len) };
	if r != 0 || addr.sun_family as i32 != libc::AF_UNIX {
		return None;
	}
	let path: Vec<u8> = addr.sun_path.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
	(!path.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(&path)))
}

/// What a socket is, from the kernel: a listening TCP or Unix stream socket, or
/// an unconnected bound UDP socket. Anything else is not handed over.
pub fn classify(fd: i32) -> Option<Kind> {
	let domain = sockopt(fd, libc::SOL_SOCKET, libc::SO_DOMAIN)?;
	let kind = sockopt(fd, libc::SOL_SOCKET, libc::SO_TYPE)?;
	let listening = sockopt(fd, libc::SOL_SOCKET, libc::SO_ACCEPTCONN).unwrap_or(0) != 0;
	match (domain, kind) {
		(libc::AF_INET | libc::AF_INET6, libc::SOCK_STREAM) if listening => local_addr(fd).map(Kind::Tcp),
		(libc::AF_INET | libc::AF_INET6, libc::SOCK_DGRAM) if !connected(fd) => {
			local_addr(fd).filter(|a| a.port() != 0).map(Kind::Udp)
		}
		(libc::AF_UNIX, libc::SOCK_STREAM) if listening => unix_path(fd).map(Kind::Unix),
		_ => None,
	}
}

/// Puts the received sockets in the pool (the new process, before it starts).
/// Returns how many were kept; the others are closed.
pub fn adopt(fds: Vec<OwnedFd>) -> usize {
	let entries: Vec<Entry> = fds.into_iter().filter_map(|fd| classify(fd.as_raw_fd()).map(|kind| Entry { kind, fd })).collect();
	let n = entries.len();
	*POOL.lock().unwrap_or_else(|e| e.into_inner()) = Some(entries);
	n
}

fn take_where(mut want: impl FnMut(&Kind) -> bool, all: bool) -> Vec<OwnedFd> {
	let mut pool = POOL.lock().unwrap_or_else(|e| e.into_inner());
	let Some(entries) = pool.as_mut() else { return vec![] };
	let mut out = vec![];
	let mut i = 0;
	while i < entries.len() {
		if want(&entries[i].kind) && (all || out.is_empty()) {
			out.push(entries.remove(i).fd);
		} else {
			i += 1;
		}
	}
	out
}

/// The inherited listening TCP socket on `addr`.
pub fn take_tcp(addr: SocketAddr) -> Option<std::net::TcpListener> {
	take_where(|k| *k == Kind::Tcp(addr), false).pop().map(Into::into)
}

/// Every inherited UDP socket on `addr` (a `SO_REUSEPORT` group has several).
pub fn take_udp(addr: SocketAddr) -> Vec<std::net::UdpSocket> {
	take_where(|k| *k == Kind::Udp(addr), true).into_iter().map(Into::into).collect()
}

/// The inherited listening Unix socket at `path`.
pub fn take_unix(path: &std::path::Path) -> Option<std::os::unix::net::UnixListener> {
	take_where(|k| matches!(k, Kind::Unix(p) if p == path), false).pop().map(Into::into)
}

/// Closes the inherited sockets nobody took (e.g. a rule that is no longer in
/// the settings file); returns what they were.
pub fn close_rest() -> Vec<Kind> {
	let rest = POOL.lock().unwrap_or_else(|e| e.into_inner()).take().unwrap_or_default();
	rest.into_iter().map(|e| e.kind).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sockets_are_recognised_by_the_kernel() {
		let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let tcp_addr = tcp.local_addr().unwrap();
		let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
		let udp_addr = udp.local_addr().unwrap();
		let connected_udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
		connected_udp.connect(udp_addr).unwrap();
		let dir = std::env::temp_dir().join(format!("rproxy-inherit-{}", std::process::id()));
		let _ = std::fs::create_dir_all(&dir);
		let path = dir.join("api.sock");
		let _ = std::fs::remove_file(&path);
		let unix = std::os::unix::net::UnixListener::bind(&path).unwrap();
		let stream = std::net::TcpStream::connect(tcp_addr).unwrap();

		assert_eq!(classify(tcp.as_raw_fd()), Some(Kind::Tcp(tcp_addr)));
		assert_eq!(classify(udp.as_raw_fd()), Some(Kind::Udp(udp_addr)));
		assert_eq!(classify(connected_udp.as_raw_fd()), None, "a session's socket");
		assert_eq!(classify(stream.as_raw_fd()), None, "a connection");
		assert_eq!(classify(unix.as_raw_fd()), Some(Kind::Unix(path.clone())));

		let fds: Vec<OwnedFd> = vec![tcp.into(), udp.into(), connected_udp.into(), unix.into(), stream.into()];
		assert_eq!(adopt(fds), 3);
		assert!(take_tcp("127.0.0.1:1".parse().unwrap()).is_none());
		let l = take_tcp(tcp_addr).expect("the same socket back");
		assert_eq!(l.local_addr().unwrap(), tcp_addr);
		assert!(take_tcp(tcp_addr).is_none(), "taken once");
		assert_eq!(take_udp(udp_addr).len(), 1);
		assert_eq!(close_rest(), [Kind::Unix(path.clone())]);
		assert!(take_unix(&path).is_none(), "the pool is gone");
		let _ = std::fs::remove_dir_all(dir);
	}
}
