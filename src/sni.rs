//! Reading the server name from a TLS ClientHello without decrypting anything,
//! so the connection can be routed and the bytes replayed to the backend.

use std::io;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// ClientHellos larger than this are refused (post-quantum key shares make
/// them ~2 KiB today; 16 KiB leaves plenty of room).
const MAX_HELLO: usize = 16 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, PartialEq, Eq)]
pub enum Parse {
	/// Need more bytes.
	Incomplete,
	/// A complete ClientHello; the server name if it carried one.
	Done(Option<String>),
	/// Not a TLS ClientHello.
	NotTls,
}

/// Parses the handshake message carried by one or more TLS records in `buf`.
pub fn parse_client_hello(buf: &[u8]) -> Parse {
	// collect the handshake bytes from consecutive handshake records
	let mut hs = Vec::new();
	let mut pos = 0;
	loop {
		if buf.len() < pos + 5 {
			return if pos == 0 && !buf.is_empty() && buf[0] != 0x16 { Parse::NotTls } else { Parse::Incomplete };
		}
		if buf[pos] != 0x16 || buf[pos + 1] != 0x03 {
			return Parse::NotTls;
		}
		let len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
		if buf.len() < pos + 5 + len {
			return Parse::Incomplete;
		}
		hs.extend_from_slice(&buf[pos + 5..pos + 5 + len]);
		pos += 5 + len;
		if hs.len() >= 4 {
			if hs[0] != 0x01 {
				return Parse::NotTls;
			}
			let body = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
			if hs.len() >= 4 + body {
				return Parse::Done(server_name(&hs[4..4 + body]));
			}
		}
	}
}

/// Walks a ClientHello body to the server_name extension.
fn server_name(body: &[u8]) -> Option<String> {
	let mut r = Reader(body);
	r.skip(2 + 32)?; // version, random
	let sid = r.u8()? as usize;
	r.skip(sid)?;
	let suites = r.u16()? as usize;
	r.skip(suites)?;
	let comp = r.u8()? as usize;
	r.skip(comp)?;
	let mut exts = Reader(r.vec16()?);
	while !exts.0.is_empty() {
		let kind = exts.u16()?;
		let data = exts.vec16()?;
		if kind != 0 {
			continue;
		}
		let mut list = Reader(data);
		let mut names = Reader(list.vec16()?);
		while !names.0.is_empty() {
			let name_type = names.u8()?;
			let name = names.vec16()?;
			if name_type == 0 {
				return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase());
			}
		}
	}
	None
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
	fn take(&mut self, n: usize) -> Option<&'a [u8]> {
		if self.0.len() < n {
			return None;
		}
		let (head, rest) = self.0.split_at(n);
		self.0 = rest;
		Some(head)
	}
	fn skip(&mut self, n: usize) -> Option<()> {
		self.take(n).map(|_| ())
	}
	fn u8(&mut self) -> Option<u8> {
		self.take(1).map(|b| b[0])
	}
	fn u16(&mut self) -> Option<u16> {
		self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
	}
	/// A block prefixed with its 16-bit length.
	fn vec16(&mut self) -> Option<&'a [u8]> {
		let n = self.u16()? as usize;
		self.take(n)
	}
}

/// Reads from `stream` until a whole ClientHello has arrived. Returns the
/// server name and every byte read, which must be sent on to the backend.
pub async fn read_client_hello(stream: &mut TcpStream) -> io::Result<(Option<String>, Vec<u8>)> {
	let mut buf = Vec::with_capacity(1024);
	let mut chunk = [0u8; 4096];
	tokio::time::timeout(READ_TIMEOUT, async {
		loop {
			match parse_client_hello(&buf) {
				Parse::Done(name) => return Ok(name),
				Parse::NotTls => return Err(io::Error::new(io::ErrorKind::InvalidData, "not a TLS ClientHello")),
				Parse::Incomplete if buf.len() >= MAX_HELLO => {
					return Err(io::Error::new(io::ErrorKind::InvalidData, "ClientHello too large"));
				}
				Parse::Incomplete => {}
			}
			let n = stream.read(&mut chunk).await?;
			if n == 0 {
				return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed before ClientHello"));
			}
			buf.extend_from_slice(&chunk[..n]);
		}
	})
	.await
	.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no ClientHello within 10s"))?
	.map(|name| (name, buf))
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A ClientHello produced by rustls for `mail.example.com`.
	fn hello(name: &str) -> Vec<u8> {
		let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
			.with_safe_default_protocol_versions()
			.unwrap()
			.with_root_certificates(rustls::RootCertStore::empty())
			.with_no_client_auth();
		let mut conn =
			rustls::ClientConnection::new(std::sync::Arc::new(config), name.to_string().try_into().unwrap()).unwrap();
		let mut out = vec![];
		conn.write_tls(&mut out).unwrap();
		out
	}

	#[test]
	fn reads_server_name() {
		let bytes = hello("Mail.Example.com");
		assert_eq!(parse_client_hello(&bytes), Parse::Done(Some("mail.example.com".into())));
	}

	#[test]
	fn needs_the_whole_record() {
		let bytes = hello("a.example");
		assert_eq!(parse_client_hello(&bytes[..3]), Parse::Incomplete);
		assert_eq!(parse_client_hello(&bytes[..bytes.len() - 1]), Parse::Incomplete);
	}

	#[test]
	fn handles_a_hello_split_across_records() {
		let bytes = hello("split.example");
		let body = &bytes[5..];
		let (a, b) = body.split_at(40);
		let mut split = vec![0x16, 0x03, 0x01];
		split.extend_from_slice(&(a.len() as u16).to_be_bytes());
		split.extend_from_slice(a);
		split.extend_from_slice(&[0x16, 0x03, 0x01]);
		split.extend_from_slice(&(b.len() as u16).to_be_bytes());
		split.extend_from_slice(b);
		assert_eq!(parse_client_hello(&split), Parse::Done(Some("split.example".into())));
	}

	#[test]
	fn rejects_plain_text() {
		assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\n"), Parse::NotTls);
		assert_eq!(parse_client_hello(b"EHLO x\r\n"), Parse::NotTls);
	}
}
