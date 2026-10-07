//! Messages with file descriptors (SCM_RIGHTS) over a Unix SOCK_SEQPACKET
//! socket: the channel of a live upgrade (#174). Blocking, with timeouts.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

/// The most descriptors sent in one message (the kernel's limit is 253).
pub const MAX_FDS: usize = 200;
/// The largest message.
pub const MAX_MSG: usize = 64 << 10;

fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
	if r < 0 {
		Err(io::Error::last_os_error())
	} else {
		Ok(r)
	}
}

fn seqpacket() -> io::Result<OwnedFd> {
	// SAFETY: a new socket; we own the descriptor
	let fd = cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) })?;
	Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn sockaddr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
	use std::os::unix::ffi::OsStrExt;
	// SAFETY: a zeroed sockaddr_un is valid
	let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
	addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
	let bytes = path.as_os_str().as_bytes();
	if bytes.len() >= addr.sun_path.len() {
		return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{}: path too long for a socket", path.display())));
	}
	for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
		*d = *s as libc::c_char;
	}
	let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
	Ok((addr, len as libc::socklen_t))
}

/// One end of the channel.
pub struct Channel {
	fd: OwnedFd,
}

/// The listening side (the old process), at a path with mode 0600.
pub struct Listener {
	fd: OwnedFd,
}

impl Listener {
	pub fn bind(path: &Path) -> io::Result<Listener> {
		use std::os::unix::fs::{FileTypeExt, PermissionsExt};
		match std::fs::symlink_metadata(path) {
			Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
			Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} exists and is not a socket", path.display()))),
			Err(_) => {}
		}
		let fd = seqpacket()?;
		let (addr, len) = sockaddr(path)?;
		// SAFETY: bind with a valid sockaddr_un
		cvt(unsafe { libc::bind(fd.as_raw_fd(), (&addr as *const libc::sockaddr_un).cast(), len) })
			.map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
		// only rproxy's user (and the peer must be the process we started: `accept`'s pid)
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
		// SAFETY: listen on our socket
		cvt(unsafe { libc::listen(fd.as_raw_fd(), 4) })?;
		Ok(Listener { fd })
	}

	/// Waits up to `timeout` for a connection; (channel, peer's pid).
	pub fn accept(&self, timeout: Duration) -> io::Result<(Channel, i32)> {
		if !poll_in(self.fd.as_raw_fd(), timeout)? {
			return Err(io::Error::new(io::ErrorKind::TimedOut, "the new process did not connect in time"));
		}
		// SAFETY: accept4 on our listening socket; we own the new descriptor
		let fd = cvt(unsafe { libc::accept4(self.fd.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) })?;
		let ch = Channel { fd: unsafe { OwnedFd::from_raw_fd(fd) } };
		let pid = ch.peer_pid()?;
		Ok((ch, pid))
	}

	pub fn raw_fd(&self) -> RawFd {
		self.fd.as_raw_fd()
	}
}

fn poll_in(fd: RawFd, timeout: Duration) -> io::Result<bool> {
	let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
	let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
	loop {
		// SAFETY: one pollfd on the stack
		match unsafe { libc::poll(&mut p, 1, ms) } {
			-1 if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
			-1 => return Err(io::Error::last_os_error()),
			0 => return Ok(false),
			_ => return Ok(true),
		}
	}
}

impl Channel {
	pub fn connect(path: &Path) -> io::Result<Channel> {
		let fd = seqpacket()?;
		let (addr, len) = sockaddr(path)?;
		// SAFETY: connect with a valid sockaddr_un
		cvt(unsafe { libc::connect(fd.as_raw_fd(), (&addr as *const libc::sockaddr_un).cast(), len) })
			.map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
		Ok(Channel { fd })
	}

	pub fn raw_fd(&self) -> RawFd {
		self.fd.as_raw_fd()
	}

	fn peer_pid(&self) -> io::Result<i32> {
		Ok(self.peer_cred()?.pid)
	}

	/// The peer's pid, uid and gid (SO_PEERCRED).
	pub fn peer_cred(&self) -> io::Result<libc::ucred> {
		let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
		let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
		// SAFETY: getsockopt writes a ucred into a local
		cvt(unsafe {
			libc::getsockopt(self.fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len)
		})?;
		Ok(cred)
	}

	/// Sends one message: `tag`, then `data`, with `fds` attached.
	pub fn send(&self, tag: u8, data: &[u8], fds: &[RawFd]) -> io::Result<()> {
		let mut payload = Vec::with_capacity(1 + data.len());
		payload.push(tag);
		payload.extend_from_slice(data);
		let mut iov = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: payload.len() };
		let fd_bytes = std::mem::size_of_val(fds);
		// SAFETY: CMSG_SPACE only computes a size
		let space = if fds.is_empty() { 0 } else { (unsafe { libc::CMSG_SPACE(fd_bytes as u32) }) as usize };
		let mut control = vec![0u8; space];
		// SAFETY: a zeroed msghdr; every pointer set below outlives the call
		let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
		msg.msg_iov = &mut iov;
		msg.msg_iovlen = 1;
		if !fds.is_empty() {
			msg.msg_control = control.as_mut_ptr().cast();
			msg.msg_controllen = space as _;
			// SAFETY: the control buffer has room for one cmsg with the descriptors
			unsafe {
				let cmsg = libc::CMSG_FIRSTHDR(&msg);
				(*cmsg).cmsg_level = libc::SOL_SOCKET;
				(*cmsg).cmsg_type = libc::SCM_RIGHTS;
				(*cmsg).cmsg_len = libc::CMSG_LEN(fd_bytes as u32) as _;
				std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast::<RawFd>(), fds.len());
			}
		}
		loop {
			// SAFETY: msg points at live buffers
			let r = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
			if r >= 0 {
				return Ok(());
			}
			let e = io::Error::last_os_error();
			if e.kind() != io::ErrorKind::Interrupted {
				return Err(e);
			}
		}
	}

	/// Receives one message within `timeout`: (tag, data, descriptors). A closed
	/// channel is `UnexpectedEof`.
	pub fn recv(&self, timeout: Duration) -> io::Result<(u8, Vec<u8>, Vec<OwnedFd>)> {
		if !poll_in(self.fd.as_raw_fd(), timeout)? {
			return Err(io::Error::new(io::ErrorKind::TimedOut, "no message in time"));
		}
		let mut buf = vec![0u8; MAX_MSG + 1];
		let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
		// SAFETY: CMSG_SPACE only computes a size
		let space = unsafe { libc::CMSG_SPACE((std::mem::size_of::<RawFd>() * 253) as u32) } as usize;
		let mut control = vec![0u8; space];
		// SAFETY: as in send
		let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
		msg.msg_iov = &mut iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.as_mut_ptr().cast();
		msg.msg_controllen = space as _;
		let n = loop {
			// SAFETY: msg points at live buffers
			let r = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
			if r >= 0 {
				break r as usize;
			}
			let e = io::Error::last_os_error();
			if e.kind() != io::ErrorKind::Interrupted {
				return Err(e);
			}
		};
		let mut fds = vec![];
		// SAFETY: walking the control messages the kernel wrote
		unsafe {
			let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
			while !cmsg.is_null() {
				if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
					let data = libc::CMSG_DATA(cmsg).cast::<RawFd>();
					let count = ((*cmsg).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / std::mem::size_of::<RawFd>();
					for i in 0..count {
						fds.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
					}
				}
				cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
			}
		}
		if n == 0 {
			return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the other process closed the channel"));
		}
		if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
			return Err(io::Error::new(io::ErrorKind::InvalidData, "a message was cut short"));
		}
		buf.truncate(n);
		let tag = buf.remove(0);
		Ok((tag, buf, fds))
	}

	/// Sends a large payload as several `tag` messages and one `end`.
	pub fn send_chunked(&self, tag: u8, end: u8, data: &[u8]) -> io::Result<()> {
		for chunk in data.chunks(MAX_MSG - 1) {
			self.send(tag, chunk, &[])?;
		}
		self.send(end, &[], &[])
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn messages_carry_descriptors() {
		let dir = std::env::temp_dir().join(format!("rproxy-fdpass-{}", std::process::id()));
		let _ = std::fs::create_dir_all(&dir);
		let path = dir.join("h.sock");
		let listener = Listener::bind(&path).unwrap();
		use std::os::unix::fs::PermissionsExt;
		assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
		let client = Channel::connect(&path).unwrap();
		let (server, pid) = listener.accept(Duration::from_secs(5)).unwrap();
		assert_eq!(pid, std::process::id() as i32);

		let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = tcp.local_addr().unwrap();
		server.send(b'F', b"", &[tcp.as_raw_fd()]).unwrap();
		let (tag, data, fds) = client.recv(Duration::from_secs(5)).unwrap();
		assert_eq!((tag, data.len(), fds.len()), (b'F', 0, 1));
		let got = std::net::TcpListener::from(fds.into_iter().next().unwrap());
		assert_eq!(got.local_addr().unwrap(), addr, "the same socket");

		let big = vec![7u8; MAX_MSG * 2 + 5];
		server.send_chunked(b'S', b'E', &big).unwrap();
		let mut back = vec![];
		loop {
			let (tag, data, _) = client.recv(Duration::from_secs(5)).unwrap();
			if tag == b'E' {
				break;
			}
			back.extend(data);
		}
		assert_eq!(back, big);
		drop(server);
		assert_eq!(client.recv(Duration::from_secs(5)).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
		assert_eq!(listener.accept(Duration::from_millis(50)).err().map(|e| e.kind()), Some(io::ErrorKind::TimedOut));
		let _ = std::fs::remove_dir_all(dir);
	}
}
