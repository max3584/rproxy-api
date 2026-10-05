//! Kernel TLS (kTLS) for TCP rules that terminate TLS without `http` (#184, experiment).
//!
//! The handshake stays in rustls (certificates by SNI, client certificates, ALPN, versions and
//! cipher suites are unchanged). Once it is done, the record keys are handed to the kernel
//! (`TCP_ULP` "tls", `TLS_TX` / `TLS_RX`) and the relay reads and writes plain text on the
//! socket: the kernel encrypts and decrypts, rustls is out of the data path.
//!
//! - The handshake reads the client's records one whole record at a time ([`Records`]), so
//!   nothing after the client's last handshake message is left half-read in rustls when the
//!   keys move to the kernel. A record already read (application data that came with the
//!   client's Finished) is decrypted by rustls and passed on first.
//! - TLS 1.3 session tickets are sent by rustls before the switch (tokio-rustls flushes them at
//!   the end of the handshake).
//! - Records other than application data reach the relay through `recvmsg` with
//!   `TLS_GET_RECORD_TYPE`: close_notify is the end of the stream, user_canceled is skipped,
//!   other alerts and handshake messages (a TLS 1.3 KeyUpdate: rustls's buffered connection
//!   cannot give the next keys) end the connection with an error, which resets it (#134).
//! - Shutting down the write side sends close_notify (`TLS_SET_RECORD_TYPE`) before the FIN, as
//!   rustls does. A FIN without close_notify is an error (cut off), as with rustls.
//! - AES-GCM's confidentiality limit: the kernel cannot update keys, so a connection that would
//!   send more records than the cipher suite allows is ended with an error (a reset).
//! - What the kernel supports (the `tls` module, cipher suites per version) is tried once on a
//!   loopback connection; a connection whose version or cipher suite it lacks stays on rustls.
//!   `RPROXY_KTLS=off` turns it off.

use std::io::{self, Read};
use std::mem::{size_of, MaybeUninit};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::task::{ready, Context, Poll};

use rustls::{CipherSuite, ConnectionTrafficSecrets, ProtocolVersion, ServerConnection, SupportedCipherSuite};
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;
use tracing::info;

const SOL_TLS: libc::c_int = 282;
const TCP_ULP: libc::c_int = 31;
const TLS_TX: libc::c_int = 1;
const TLS_RX: libc::c_int = 2;
const TLS_SET_RECORD_TYPE: libc::c_int = 1;
const TLS_GET_RECORD_TYPE: libc::c_int = 2;

const TLS_1_2_VERSION: u16 = 0x0303;
const TLS_1_3_VERSION: u16 = 0x0304;
const TLS_CIPHER_AES_GCM_128: u16 = 51;
const TLS_CIPHER_AES_GCM_256: u16 = 52;
const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
const CONTENT_APPLICATION_DATA: u8 = 23;
const ALERT_CLOSE_NOTIFY: u8 = 0;
const ALERT_USER_CANCELED: u8 = 90;
const HANDSHAKE_KEY_UPDATE: u8 = 24;
/// Most plain text in one record.
const MAX_FRAGMENT: u64 = 1 << 14;

/// Connections switched to kTLS since the start (for the tests).
pub static CONNECTIONS: AtomicU64 = AtomicU64::new(0);

#[repr(C)]
struct CryptoInfo {
	version: u16,
	cipher_type: u16,
}

#[repr(C)]
struct AesGcm128 {
	info: CryptoInfo,
	iv: [u8; 8],
	key: [u8; 16],
	salt: [u8; 4],
	rec_seq: [u8; 8],
}

#[repr(C)]
struct AesGcm256 {
	info: CryptoInfo,
	iv: [u8; 8],
	key: [u8; 32],
	salt: [u8; 4],
	rec_seq: [u8; 8],
}

#[repr(C)]
struct Chacha20Poly1305 {
	info: CryptoInfo,
	iv: [u8; 12],
	key: [u8; 32],
	rec_seq: [u8; 8],
}

/// Key material for `TLS_TX` / `TLS_RX`, as the kernel takes it.
enum Crypto {
	Aes128(AesGcm128),
	Aes256(AesGcm256),
	Chacha(Chacha20Poly1305),
}

impl Crypto {
	fn new(version: u16, seq: u64, secrets: &ConnectionTrafficSecrets) -> io::Result<Crypto> {
		let rec_seq = seq.to_be_bytes();
		let bad = || io::Error::other("unexpected key length");
		Ok(match secrets {
			ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
				let iv = iv.as_ref();
				Crypto::Aes128(AesGcm128 {
					info: CryptoInfo { version, cipher_type: TLS_CIPHER_AES_GCM_128 },
					iv: iv[4..].try_into().map_err(|_| bad())?,
					key: key.as_ref().try_into().map_err(|_| bad())?,
					salt: iv[..4].try_into().map_err(|_| bad())?,
					rec_seq,
				})
			}
			ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
				let iv = iv.as_ref();
				Crypto::Aes256(AesGcm256 {
					info: CryptoInfo { version, cipher_type: TLS_CIPHER_AES_GCM_256 },
					iv: iv[4..].try_into().map_err(|_| bad())?,
					key: key.as_ref().try_into().map_err(|_| bad())?,
					salt: iv[..4].try_into().map_err(|_| bad())?,
					rec_seq,
				})
			}
			ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => Crypto::Chacha(Chacha20Poly1305 {
				info: CryptoInfo { version, cipher_type: TLS_CIPHER_CHACHA20_POLY1305 },
				iv: iv.as_ref().try_into().map_err(|_| bad())?,
				key: key.as_ref().try_into().map_err(|_| bad())?,
				rec_seq,
			}),
			_ => return Err(io::Error::other("cipher not supported by kTLS")),
		})
	}

	/// Zero keys of one kind, to try what the kernel supports.
	fn zero(version: u16, cipher: u16) -> Crypto {
		let info = CryptoInfo { version, cipher_type: cipher };
		match cipher {
			TLS_CIPHER_AES_GCM_128 => Crypto::Aes128(AesGcm128 { info, iv: [0; 8], key: [0; 16], salt: [0; 4], rec_seq: [0; 8] }),
			TLS_CIPHER_AES_GCM_256 => Crypto::Aes256(AesGcm256 { info, iv: [0; 8], key: [0; 32], salt: [0; 4], rec_seq: [0; 8] }),
			_ => Crypto::Chacha(Chacha20Poly1305 { info, iv: [0; 12], key: [0; 32], rec_seq: [0; 8] }),
		}
	}

	fn set(&self, fd: RawFd, direction: libc::c_int) -> io::Result<()> {
		let (ptr, len) = match self {
			Crypto::Aes128(c) => (c as *const _ as *const libc::c_void, size_of::<AesGcm128>()),
			Crypto::Aes256(c) => (c as *const _ as *const libc::c_void, size_of::<AesGcm256>()),
			Crypto::Chacha(c) => (c as *const _ as *const libc::c_void, size_of::<Chacha20Poly1305>()),
		};
		// SAFETY: `ptr` points at a live #[repr(C)] struct of `len` bytes
		let rc = unsafe { libc::setsockopt(fd, SOL_TLS, direction, ptr, len as libc::socklen_t) };
		if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
	}
}

impl Drop for Crypto {
	fn drop(&mut self) {
		// do not leave the keys in freed memory
		let bytes: &mut [u8] = match self {
			Crypto::Aes128(c) => &mut c.key,
			Crypto::Aes256(c) => &mut c.key,
			Crypto::Chacha(c) => &mut c.key,
		};
		for b in bytes.iter_mut() {
			// SAFETY: a valid &mut u8
			unsafe { std::ptr::write_volatile(b, 0) };
		}
	}
}

fn attach_ulp(fd: RawFd) -> io::Result<()> {
	let name = b"tls";
	// SAFETY: `name` is valid for its length
	let rc = unsafe { libc::setsockopt(fd, libc::IPPROTO_TCP, TCP_ULP, name.as_ptr().cast(), name.len() as libc::socklen_t) };
	if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// What the kernel can do: (TLS version, cipher) pairs.
struct Support {
	pairs: Vec<(u16, u16)>,
}

fn support() -> &'static Support {
	static SUPPORT: OnceLock<Support> = OnceLock::new();
	SUPPORT.get_or_init(|| {
		let off = std::env::var("RPROXY_KTLS").is_ok_and(|v| matches!(v.to_ascii_lowercase().as_str(), "0" | "off" | "false" | "no"));
		let mut pairs = Vec::new();
		let mut error = String::new();
		if !off {
			for version in [TLS_1_2_VERSION, TLS_1_3_VERSION] {
				for cipher in [TLS_CIPHER_AES_GCM_128, TLS_CIPHER_AES_GCM_256, TLS_CIPHER_CHACHA20_POLY1305] {
					match probe(version, cipher) {
						Ok(()) => pairs.push((version, cipher)),
						Err(e) => error = e.to_string(),
					}
				}
			}
		}
		info!(event = "ktls.support", disabled = off, pairs = ?pairs, error = %error);
		Support { pairs }
	})
}

/// Tries `TLS_TX` and `TLS_RX` with zero keys on a loopback connection.
fn probe(version: u16, cipher: u16) -> io::Result<()> {
	let listener =
		std::net::TcpListener::bind(("127.0.0.1", 0)).or_else(|_| std::net::TcpListener::bind(("::1", 0)))?;
	let client = std::net::TcpStream::connect(listener.local_addr()?)?;
	let (_server, _) = listener.accept()?;
	let fd = client.as_raw_fd();
	attach_ulp(fd)?;
	let zero = Crypto::zero(version, cipher);
	zero.set(fd, TLS_TX)?;
	zero.set(fd, TLS_RX)
}

/// Whether kTLS is used for new connections at all (`RPROXY_KTLS` and the kernel).
pub fn enabled() -> bool {
	!support().pairs.is_empty()
}

fn kernel_ids(version: Option<ProtocolVersion>, suite: Option<SupportedCipherSuite>) -> Option<(u16, u16)> {
	let version = match version? {
		ProtocolVersion::TLSv1_2 => TLS_1_2_VERSION,
		ProtocolVersion::TLSv1_3 => TLS_1_3_VERSION,
		_ => return None,
	};
	let cipher = match suite?.suite() {
		CipherSuite::TLS13_AES_128_GCM_SHA256
		| CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		| CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => TLS_CIPHER_AES_GCM_128,
		CipherSuite::TLS13_AES_256_GCM_SHA384
		| CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		| CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => TLS_CIPHER_AES_GCM_256,
		CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
		| CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		| CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => TLS_CIPHER_CHACHA20_POLY1305,
		_ => return None,
	};
	Some((version, cipher))
}

/// Whether this finished handshake can move to the kernel, and if so the socket now has the
/// `tls` ULP attached (nothing changes on it until the keys are set).
pub fn prepare(conn: &ServerConnection, fd: RawFd) -> bool {
	if conn.is_handshaking() || conn.wants_write() {
		return false;
	}
	let Some(ids) = kernel_ids(conn.protocol_version(), conn.negotiated_cipher_suite()) else {
		return false;
	};
	support().pairs.contains(&ids) && attach_ulp(fd).is_ok()
}

/// Moves a finished handshake to the kernel. `rest` is the rest of a record the handshake had
/// started to read (completed). Returns the stream and the plain text rustls had already
/// decrypted, which goes to the backend first. After [`prepare`]; an error here leaves the
/// connection unusable (it is reset).
pub fn switch(sock: &mut TcpStream, mut conn: ServerConnection, rest: Vec<u8>) -> io::Result<(Stream<'_>, Vec<u8>)> {
	let mut input = &rest[..];
	while !input.is_empty() {
		if conn.read_tls(&mut input)? == 0 {
			break;
		}
		conn.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
	}
	let mut early = Vec::new();
	let mut read_closed = false;
	let mut chunk = [0u8; 4096];
	loop {
		match conn.reader().read(&mut chunk) {
			Ok(0) => {
				read_closed = true;
				break;
			}
			Ok(n) => early.extend_from_slice(&chunk[..n]),
			Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
			Err(e) => return Err(e),
		}
	}
	let version = if conn.protocol_version() == Some(ProtocolVersion::TLSv1_3) { TLS_1_3_VERSION } else { TLS_1_2_VERSION };
	let limit = match conn.negotiated_cipher_suite() {
		Some(SupportedCipherSuite::Tls13(s)) => s.common.confidentiality_limit,
		Some(SupportedCipherSuite::Tls12(s)) => s.common.confidentiality_limit,
		None => 0,
	};
	let secrets = conn.dangerous_extract_secrets().map_err(io::Error::other)?;
	let fd = sock.as_raw_fd();
	Crypto::new(version, secrets.tx.0, &secrets.tx.1)?.set(fd, TLS_TX)?;
	Crypto::new(version, secrets.rx.0, &secrets.rx.1)?.set(fd, TLS_RX)?;
	CONNECTIONS.fetch_add(1, Ordering::Relaxed);
	// leave room for close_notify and a margin
	let tx_limit = limit.saturating_sub(secrets.tx.0).saturating_sub(1024);
	Ok((Stream { sock, read_closed, write_closed: false, tx_records: 0, tx_limit }, early))
}

/// The client's side of a connection after [`switch`]: plain text in and out, the kernel does
/// the records.
pub struct Stream<'a> {
	sock: &'a mut TcpStream,
	/// close_notify received: the end of the stream
	read_closed: bool,
	/// close_notify sent
	write_closed: bool,
	/// most records sent so far (each write is at most `len / 16 KiB + 1` records)
	tx_records: u64,
	tx_limit: u64,
}

/// One `recvmsg`: the bytes and the record type (none: the end of the stream).
fn recv_record(fd: RawFd, buf: &mut [MaybeUninit<u8>]) -> io::Result<(usize, Option<u8>)> {
	let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
	let mut control = [0u64; 8];
	// SAFETY: an all-zero msghdr is valid; the pointers set below outlive the call
	let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
	msg.msg_iov = &mut iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.as_mut_ptr().cast();
	msg.msg_controllen = size_of::<[u64; 8]>() as _;
	// SAFETY: `msg` describes valid buffers
	let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
	if n < 0 {
		return Err(io::Error::last_os_error());
	}
	let mut kind = None;
	// SAFETY: walking the control messages the kernel wrote into `control`
	unsafe {
		let mut c = libc::CMSG_FIRSTHDR(&msg);
		while !c.is_null() {
			if (*c).cmsg_level == SOL_TLS && (*c).cmsg_type == TLS_GET_RECORD_TYPE {
				kind = Some(*libc::CMSG_DATA(c));
			}
			c = libc::CMSG_NXTHDR(&msg, c);
		}
	}
	if n > 0 && kind.is_none() {
		kind = Some(CONTENT_APPLICATION_DATA);
	}
	Ok((n as usize, kind))
}

/// Sends one alert record (`TLS_SET_RECORD_TYPE`).
fn send_alert(fd: RawFd, level: u8, description: u8) -> io::Result<()> {
	let mut body = [level, description];
	let mut iov = libc::iovec { iov_base: body.as_mut_ptr().cast(), iov_len: body.len() };
	let mut control = [0u64; 8];
	// SAFETY: as in `recv_record`; the control message is written inside `control`
	unsafe {
		let mut msg: libc::msghdr = std::mem::zeroed();
		msg.msg_iov = &mut iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control.as_mut_ptr().cast();
		msg.msg_controllen = libc::CMSG_SPACE(1) as _;
		let c = libc::CMSG_FIRSTHDR(&msg);
		(*c).cmsg_level = SOL_TLS;
		(*c).cmsg_type = TLS_SET_RECORD_TYPE;
		(*c).cmsg_len = libc::CMSG_LEN(1) as _;
		*libc::CMSG_DATA(c) = CONTENT_ALERT;
		let n = libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL);
		if n < 0 {
			return Err(io::Error::last_os_error());
		}
	}
	Ok(())
}

impl AsyncRead for Stream<'_> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		if this.read_closed || buf.remaining() == 0 {
			return Poll::Ready(Ok(()));
		}
		let fd = this.sock.as_raw_fd();
		loop {
			ready!(this.sock.poll_read_ready(cx))?;
			// SAFETY: recvmsg only writes into the unfilled part; we mark as filled what it wrote
			let unfilled = unsafe { buf.unfilled_mut() };
			match this.sock.try_io(Interest::READABLE, || recv_record(fd, unfilled)) {
				Ok((0, None)) => {
					return Poll::Ready(Err(io::Error::new(
						io::ErrorKind::UnexpectedEof,
						"peer closed connection without sending TLS close_notify",
					)));
				}
				Ok((n, Some(CONTENT_APPLICATION_DATA))) => {
					// SAFETY: the kernel wrote `n` bytes
					unsafe { buf.assume_init(n) };
					buf.advance(n);
					return Poll::Ready(Ok(()));
				}
				Ok((n, Some(CONTENT_ALERT))) => {
					// SAFETY: the kernel wrote `n` bytes at the start of `unfilled`
					let body: Vec<u8> = unfilled[..n].iter().map(|b| unsafe { b.assume_init() }).collect();
					match body.get(1).copied() {
						Some(ALERT_CLOSE_NOTIFY) => {
							this.read_closed = true;
							return Poll::Ready(Ok(()));
						}
						Some(ALERT_USER_CANCELED) => continue,
						d => {
							return Poll::Ready(Err(io::Error::new(
								io::ErrorKind::ConnectionAborted,
								format!("received TLS alert {}", d.map(|d| d.to_string()).unwrap_or_default()),
							)));
						}
					}
				}
				Ok((n, Some(CONTENT_HANDSHAKE))) => {
					// SAFETY: as above
					let first = (n > 0).then(|| unsafe { unfilled[0].assume_init() });
					let what = if first == Some(HANDSHAKE_KEY_UPDATE) { "a TLS KeyUpdate (not supported with kTLS)" } else { "a TLS handshake message" };
					return Poll::Ready(Err(io::Error::new(io::ErrorKind::Unsupported, format!("received {what}"))));
				}
				Ok((_, kind)) => {
					return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, format!("unexpected TLS record type {kind:?}"))));
				}
				Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
				Err(e) => return Poll::Ready(Err(e)),
			}
		}
	}
}

impl AsyncWrite for Stream<'_> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		let records = (buf.len() as u64).div_ceil(MAX_FRAGMENT).max(1);
		if this.tx_records + records >= this.tx_limit {
			return Poll::Ready(Err(io::Error::other("the TLS cipher suite's limit of records is reached (kTLS cannot update keys)")));
		}
		let n = ready!(Pin::new(&mut *this.sock).poll_write(cx, buf))?;
		this.tx_records += (n as u64).div_ceil(MAX_FRAGMENT).max(1);
		Poll::Ready(Ok(n))
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		while !this.write_closed {
			ready!(this.sock.poll_write_ready(cx))?;
			let fd = this.sock.as_raw_fd();
			match this.sock.try_io(Interest::WRITABLE, || send_alert(fd, 1, ALERT_CLOSE_NOTIFY)) {
				Ok(()) => this.write_closed = true,
				Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
				Err(e) => return Poll::Ready(Err(e)),
			}
		}
		Pin::new(&mut *this.sock).poll_shutdown(cx)
	}
}

/// Reads TLS records one whole record at a time while `bounded`, so that what the handshake
/// reads ends at a record boundary: a record is handed on only once all of it has arrived, and
/// nothing after it is read from `inner`. Not bounded, it passes reads through.
pub struct Records<S> {
	inner: S,
	bounded: bool,
	/// the current record, read so far
	buf: Vec<u8>,
	/// how much of `buf` has been handed on
	pos: usize,
}

impl<S> Records<S> {
	pub fn new(inner: S, bounded: bool) -> Self {
		Records { inner, bounded, buf: Vec::new(), pos: 0 }
	}

	pub fn get_ref(&self) -> &S {
		&self.inner
	}

	/// Stops reading record by record (staying on rustls).
	pub fn unbound(&mut self) {
		self.bounded = false;
	}

	/// Bytes still needed to complete the record in `buf` (0: complete).
	fn missing(&self) -> usize {
		if self.buf.len() < 5 {
			5 - self.buf.len()
		} else {
			5 + u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize - self.buf.len()
		}
	}
}

impl<S: AsyncRead + Unpin> Records<S> {
	/// Reads until the record in `buf` is complete (or `inner` ends). Ready(Ok(true)) when it is.
	fn poll_complete(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
		loop {
			let missing = self.missing();
			if missing == 0 {
				return Poll::Ready(Ok(true));
			}
			let old = self.buf.len();
			self.buf.resize(old + missing, 0);
			let mut rb = ReadBuf::new(&mut self.buf[old..]);
			let polled = Pin::new(&mut self.inner).poll_read(cx, &mut rb);
			let n = rb.filled().len();
			self.buf.truncate(old + n);
			match polled {
				Poll::Ready(Ok(())) if n == 0 => return Poll::Ready(Ok(false)),
				Poll::Ready(Ok(())) => {}
				Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
				Poll::Pending => return Poll::Pending,
			}
		}
	}

	/// The rest of the record the handshake had started to read, read to its end (empty if it
	/// had not started one).
	pub async fn rest(&mut self) -> io::Result<Vec<u8>> {
		if self.buf.is_empty() {
			return Ok(Vec::new());
		}
		std::future::poll_fn(|cx| self.poll_complete(cx)).await?;
		let rest = self.buf.split_off(self.pos);
		self.buf.clear();
		self.pos = 0;
		Ok(rest)
	}

	pub fn into_inner(self) -> S {
		self.inner
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for Records<S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		if this.bounded && this.pos == 0 {
			// a record is handed on only once complete (an end of stream hands on what there is)
			ready!(this.poll_complete(cx))?;
		}
		if this.pos < this.buf.len() {
			let n = (this.buf.len() - this.pos).min(buf.remaining());
			buf.put_slice(&this.buf[this.pos..this.pos + n]);
			this.pos += n;
			if this.pos == this.buf.len() {
				this.buf.clear();
				this.pos = 0;
			}
			return Poll::Ready(Ok(()));
		}
		if this.bounded {
			// end of stream
			return Poll::Ready(Ok(()));
		}
		Pin::new(&mut this.inner).poll_read(cx, buf)
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Records<S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}

	fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
	}

	fn is_write_vectored(&self) -> bool {
		self.inner.is_write_vectored()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::AsyncReadExt;

	#[tokio::test]
	async fn records_are_handed_on_whole_and_nothing_after_is_read() {
		let (mut w, r) = tokio::io::duplex(64);
		let mut rec = Records::new(r, true);
		// one record of 3 bytes, then the start of another
		tokio::io::AsyncWriteExt::write_all(&mut w, &[23, 3, 3, 0, 3, 1, 2]).await.unwrap();
		let mut out = [0u8; 64];
		let read = tokio::time::timeout(std::time::Duration::from_millis(50), rec.read(&mut out)).await;
		assert!(read.is_err(), "an incomplete record is not handed on");
		tokio::io::AsyncWriteExt::write_all(&mut w, &[3, 23, 3, 3, 0, 2, 9]).await.unwrap();
		let n = rec.read(&mut out).await.unwrap();
		assert_eq!(&out[..n], &[23, 3, 3, 0, 3, 1, 2, 3]);
		// the second record: header and 1 of its 2 bytes so far
		let read = tokio::time::timeout(std::time::Duration::from_millis(50), rec.read(&mut out)).await;
		assert!(read.is_err());
		let rest = tokio::time::timeout(std::time::Duration::from_millis(50), rec.rest()).await;
		assert!(rest.is_err(), "rest waits for the end of the record");
		tokio::io::AsyncWriteExt::write_all(&mut w, &[8, 99]).await.unwrap();
		assert_eq!(rec.rest().await.unwrap(), vec![23, 3, 3, 0, 2, 9, 8]);
		let mut inner = rec.into_inner();
		let n = inner.read(&mut out).await.unwrap();
		assert_eq!(&out[..n], &[99]);
	}
}
