//! Feeding one client's datagrams from the shared UDP listener into a DTLS
//! server connection.

use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex};
use webrtc_util::conn::Conn;

use crate::net::udpsock::{Listener, Local};

/// A per-client view of the listener: reads come from the session's queue,
/// writes go out of the listener to that client, from the address it sent to.
pub struct SessionConn {
	from_client: Mutex<mpsc::Receiver<Vec<u8>>>,
	listener: Arc<Listener>,
	client: SocketAddr,
	local: Option<Local>,
	/// The cookie of the HelloVerifyRequest the `dtls` crate sent (#354).
	cookie: std::sync::Mutex<Option<Vec<u8>>>,
	/// A ClientHello came back with that cookie: the client is at its address.
	verified: AtomicBool,
}

impl SessionConn {
	pub fn new(from_client: mpsc::Receiver<Vec<u8>>, listener: Arc<Listener>, client: SocketAddr, local: Option<Local>) -> Self {
		SessionConn {
			from_client: Mutex::new(from_client),
			listener,
			client,
			local,
			cookie: std::sync::Mutex::new(None),
			verified: AtomicBool::new(false),
		}
	}

	/// Whether the client answered the HelloVerifyRequest with its cookie (return routability:
	/// a spoofed source never sees the cookie).
	pub fn verified(&self) -> bool {
		self.verified.load(Ordering::Relaxed)
	}
}

fn closed() -> webrtc_util::Error {
	webrtc_util::Error::from(io::Error::new(io::ErrorKind::ConnectionAborted, "session closed"))
}

#[async_trait]
impl Conn for SessionConn {
	async fn connect(&self, _: SocketAddr) -> webrtc_util::Result<()> {
		Ok(())
	}

	async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
		let mut from_client = self.from_client.lock().await;
		let datagram = loop {
			let d = from_client.recv().await.ok_or_else(closed)?;
			if !self.verified() {
				let cookie = self.cookie.lock().unwrap_or_else(|e| e.into_inner());
				if cookie.as_deref().is_some_and(|c| handshake(&d, CLIENT_HELLO).and_then(hello_cookie) == Some(c)) {
					self.verified.store(true, Ordering::Relaxed);
				}
			}
			if hellos_are_safe(&d) {
				break d;
			}
			tracing::debug!(event = "udp.drop", client = %self.client, reason = "a ClientHello the DTLS library cannot read safely");
		};
		let n = datagram.len().min(buf.len());
		buf[..n].copy_from_slice(&datagram[..n]);
		Ok(n)
	}

	async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
		Ok((self.recv(buf).await?, self.client))
	}

	async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
		if !self.verified() {
			if let Some(cookie) = handshake(buf, HELLO_VERIFY_REQUEST).and_then(verify_request_cookie) {
				*self.cookie.lock().unwrap_or_else(|e| e.into_inner()) = Some(cookie.to_vec());
			}
		}
		Ok(self.listener.send_to(buf, self.client, self.local).await?)
	}

	async fn send_to(&self, buf: &[u8], _: SocketAddr) -> webrtc_util::Result<usize> {
		self.send(buf).await
	}

	fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
		Ok(self.listener.local_for(self.local))
	}

	fn remote_addr(&self) -> Option<SocketAddr> {
		Some(self.client)
	}

	async fn close(&self) -> webrtc_util::Result<()> {
		self.from_client.lock().await.close();
		Ok(())
	}

	fn as_any(&self) -> &(dyn Any + Send + Sync) {
		self
	}
}

const HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const HELLO_VERIFY_REQUEST: u8 = 3;

/// The body of the first handshake message of type `kind` in an epoch 0 record of `d`, whole.
fn handshake(mut d: &[u8], kind: u8) -> Option<&[u8]> {
	while d.len() >= 13 {
		let len = u16::from_be_bytes([d[11], d[12]]) as usize;
		let record = d.get(13..13 + len)?;
		if d[0] == HANDSHAKE && d[3..5] == [0, 0] {
			let mut m = record;
			while m.len() >= 12 {
				let length = u32::from_be_bytes([0, m[1], m[2], m[3]]) as usize;
				let body = m.get(12..12 + length)?;
				if m[0] == kind {
					return Some(body);
				}
				m = &m[12 + length..];
			}
		}
		d = &d[13 + len..];
	}
	None
}

/// The cookie of a HelloVerifyRequest body: version(2), cookie<0..255>.
fn verify_request_cookie(b: &[u8]) -> Option<&[u8]> {
	let len = *b.get(2)? as usize;
	b.get(3..3 + len).filter(|c| !c.is_empty())
}

/// The cookie of a ClientHello body: version(2), random(32), session_id<0..32>, cookie<0..255>.
fn hello_cookie(b: &[u8]) -> Option<&[u8]> {
	let sid = *b.get(34)? as usize;
	let at = 35 + sid;
	let len = *b.get(at)? as usize;
	b.get(at + 1..at + 1 + len)
}

/// Whether a datagram may start a DTLS session (terminate, #354): its first record is a
/// handshake record of epoch 0 holding a ClientHello, which the `dtls` crate can read
/// safely (`hellos_are_safe`). Anything else from an address without a session (an
/// application record, an alert, garbage, a stray record from a spoofed source) is dropped
/// without a session, a backend socket or a DTLS connection being made for it.
pub fn opens_handshake(d: &[u8]) -> bool {
	// record header (13), then the handshake header (12)
	d.len() >= 13 + 12 && d[0] == HANDSHAKE && d[1] == 0xfe && d[3..5] == [0, 0] && d[13] == CLIENT_HELLO && hellos_are_safe(d)
}

/// Whether the ClientHellos in this datagram are safe to hand to the `dtls`
/// crate. Its ClientHello parser (0.17.2) indexes into the extensions without
/// checking that 4 bytes are left, and panics on a truncated one (#287). So a
/// ClientHello (epoch 0) must come whole in one record, and its extensions are
/// walked the way the crate walks them. Anything else passes: what the crate
/// cannot parse it refuses with an error.
pub fn hellos_are_safe(mut d: &[u8]) -> bool {
	// records: type(1) version(2) epoch(2) sequence(6) length(2) fragment
	while d.len() >= 13 {
		let len = u16::from_be_bytes([d[11], d[12]]) as usize;
		let end = (13 + len).min(d.len());
		let (record, rest) = (&d[13..end], &d[end..]);
		if d[0] == HANDSHAKE && d[3..5] == [0, 0] {
			// handshake messages: type(1) length(3) message_seq(2) fragment_offset(3) fragment_length(3) body
			let mut m = record;
			while m.len() >= 12 {
				let length = u32::from_be_bytes([0, m[1], m[2], m[3]]) as usize;
				let offset = u32::from_be_bytes([0, m[6], m[7], m[8]]) as usize;
				let fragment = u32::from_be_bytes([0, m[9], m[10], m[11]]) as usize;
				let end = (12 + length).min(m.len());
				if m[0] == CLIENT_HELLO && (offset != 0 || fragment != length || end - 12 != length || !extensions_walk(&m[12..end])) {
					return false;
				}
				m = &m[end..];
			}
		}
		d = rest;
	}
	true
}

/// Walks a ClientHello body as the `dtls` crate reads it (it skips one byte for
/// the session ID, whatever its length) and checks that each extension it would
/// look at has its 4-byte header. A body too short for the crate is an error
/// there, so it counts as safe here.
fn extensions_walk(b: &[u8]) -> bool {
	fn skip(b: &mut &[u8], n: usize) -> Option<()> {
		*b = b.get(n..)?;
		Some(())
	}
	fn u8_(b: &mut &[u8]) -> Option<usize> {
		let v = *b.first()?;
		skip(b, 1)?;
		Some(v as usize)
	}
	fn u16_(b: &mut &[u8]) -> Option<usize> {
		let v = u16::from_be_bytes([*b.first()?, *b.get(1)?]);
		skip(b, 2)?;
		Some(v as usize)
	}
	let extensions = (|| {
		let mut b = b;
		// version, random, the session ID's length byte
		skip(&mut b, 2 + 32 + 1)?;
		let cookie = u8_(&mut b)?;
		skip(&mut b, cookie)?;
		let suites = u16_(&mut b)? / 2;
		skip(&mut b, suites * 2)?;
		let compression = u8_(&mut b)?;
		skip(&mut b, compression)?;
		let len = u16_(&mut b)?;
		b.get(..len)
	})();
	let Some(ext) = extensions else { return true };
	let mut offset = 0;
	while offset < ext.len() {
		let Some(header) = ext.get(offset..offset + 4) else { return false };
		offset += 4 + u16::from_be_bytes([header[2], header[3]]) as usize;
	}
	true
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A DTLS 1.2 record with one whole ClientHello carrying `extensions`.
	fn record(extensions: &[u8]) -> Vec<u8> {
		let mut body = vec![0xfe, 0xfd];
		body.extend([7u8; 32]); // random
		body.push(0); // session ID
		body.push(0); // cookie
		body.extend([0, 2, 0xc0, 0x2b]); // one cipher suite
		body.extend([1, 0]); // null compression
		body.extend((extensions.len() as u16).to_be_bytes());
		body.extend(extensions);
		let mut hs = vec![1];
		hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
		hs.extend([0, 0, 0, 0, 0]);
		hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
		hs.extend(body);
		let mut r = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0];
		r.extend((hs.len() as u16).to_be_bytes());
		r.extend(hs);
		r
	}

	#[test]
	fn whole_hellos_with_sound_extensions_pass() {
		assert!(hellos_are_safe(&record(&[])));
		// extended_master_secret (empty), then supported_groups
		assert!(hellos_are_safe(&record(&[0, 0x17, 0, 0, 0, 0x0a, 0, 4, 0, 2, 0, 0x17])));
		// two records in one datagram
		let mut two = record(&[0, 0x17, 0, 0]);
		two.extend(record(&[]));
		assert!(hellos_are_safe(&two));
	}

	#[test]
	fn a_truncated_extension_header_is_refused() {
		// 1 to 3 bytes left where the crate reads a 4-byte extension header
		for tail in [&[0u8][..], &[0, 0x17], &[0, 0x17, 0]] {
			assert!(!hellos_are_safe(&record(tail)), "{tail:?}");
			let mut ext = vec![0, 0x17, 0, 0];
			ext.extend(tail);
			assert!(!hellos_are_safe(&record(&ext)), "{ext:?}");
		}
		// a length that jumps past the end ends the walk, as in the crate
		assert!(hellos_are_safe(&record(&[0, 0x0a, 0xff, 0xff])));
	}

	#[test]
	fn fragmented_hellos_are_refused() {
		let mut r = record(&[]);
		// fragment_length one short of the message length
		r[13 + 11] -= 1;
		assert!(!hellos_are_safe(&r));
		let mut r = record(&[]);
		// a fragment that does not start at 0
		r[13 + 8] = 1;
		assert!(!hellos_are_safe(&r));
		// the record cut short
		let r = record(&[0, 0x17, 0, 0]);
		assert!(!hellos_are_safe(&r[..r.len() - 2]));
	}

	/// The walk agrees with the crate: every body it refuses makes the crate's
	/// parser panic, and none it lets through does.
	#[test]
	fn the_walk_matches_the_crate() {
		use dtls::handshake::handshake_message_client_hello::HandshakeMessageClientHello;
		let hook = std::panic::take_hook();
		std::panic::set_hook(Box::new(|_| {}));
		let mut seed = 0x2545_f491_4f6c_dd1du64;
		let mut next = move || {
			seed ^= seed << 13;
			seed ^= seed >> 7;
			seed ^= seed << 17;
			seed
		};
		let (mut refused, mut passed) = (0, 0);
		for _ in 0..4000 {
			// extensions of random sizes, some cut short
			let mut ext = vec![];
			for _ in 0..next() % 4 {
				let len = (next() % 6) as u16;
				ext.extend([0, (next() % 0x30) as u8]);
				ext.extend(len.to_be_bytes());
				ext.extend((0..len).map(|_| next() as u8));
			}
			ext.truncate(ext.len().saturating_sub((next() % 4) as usize));
			let r = record(&ext);
			let body = r[25..].to_vec();
			let panics = std::panic::catch_unwind(|| {
				let _ = HandshakeMessageClientHello::unmarshal(&mut &body[..]);
			})
			.is_err();
			let safe = hellos_are_safe(&r);
			assert_eq!(safe, !panics, "{ext:?}");
			if safe {
				passed += 1;
			} else {
				refused += 1;
			}
		}
		std::panic::set_hook(hook);
		assert!(refused > 100 && passed > 100, "{refused} refused, {passed} passed");
	}

	// #354: in a real handshake with the dtls crate on both sides, the cookie of the server's HelloVerifyRequest
	// is caught on the way out and the client's second ClientHello brings it back
	#[tokio::test]
	async fn a_real_client_is_verified_by_its_cookie() {
		use dtls::config::{Config, ExtendedMasterSecretType};
		use dtls::conn::DTLSConn;
		let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
		std_sock.set_nonblocking(true).unwrap();
		let reader = tokio::net::UdpSocket::from_std(std_sock.try_clone().unwrap()).unwrap();
		let listener = Arc::new(Listener::new(tokio::net::UdpSocket::from_std(std_sock).unwrap()));
		let server_addr = listener.local_addr().unwrap();
		let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
		client_sock.connect(server_addr).await.unwrap();
		let client_addr = client_sock.local_addr().unwrap();
		// the shared listener's datagrams into the session's queue, as `serve` does
		let (tx, rx) = mpsc::channel(64);
		tokio::spawn(async move {
			let mut buf = vec![0u8; 2048];
			while let Ok((n, _)) = reader.recv_from(&mut buf).await {
				if tx.send(buf[..n].to_vec()).await.is_err() {
					break;
				}
			}
		});
		let session = Arc::new(SessionConn::new(rx, listener, client_addr, None));
		let cert = dtls::crypto::Certificate::generate_self_signed(vec!["localhost".to_owned()]).unwrap();
		let server_config =
			Config { certificates: vec![cert], extended_master_secret: ExtendedMasterSecretType::Require, ..Default::default() };
		let client_config = Config {
			insecure_skip_verify: true,
			server_name: "localhost".into(),
			extended_master_secret: ExtendedMasterSecretType::Require,
			..Default::default()
		};
		assert!(!session.verified());
		let server_conn: Arc<dyn Conn + Send + Sync> = session.clone();
		let client_conn: Arc<dyn Conn + Send + Sync> = Arc::new(client_sock);
		let (server, client) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
			tokio::join!(DTLSConn::new(server_conn, server_config, false, None), DTLSConn::new(client_conn, client_config, true, None))
		})
		.await
		.unwrap();
		let (server, client) = (server.unwrap(), client.unwrap());
		assert!(session.verified(), "the second ClientHello carried the HelloVerifyRequest's cookie");
		let _ = client.close().await;
		let _ = server.close().await;
	}

	#[test]
	fn cookies_are_read() {
		// a ClientHello with a cookie: the test record's cookie length byte is at body offset 35
		let mut r = record(&[]);
		assert_eq!(handshake(&r, CLIENT_HELLO).and_then(hello_cookie), Some(&[][..]));
		let body_at = 13 + 12;
		r[body_at + 35] = 2;
		r.splice(body_at + 36..body_at + 36, [7u8, 8]);
		// lengths: the record's, the message's and the fragment's
		for at in [11usize, 13 + 1, 13 + 9] {
			let (hi, lo) = if at == 11 { (at, at + 1) } else { (at + 1, at + 2) };
			let v = u16::from_be_bytes([r[hi], r[lo]]) + 2;
			r[hi..=lo].copy_from_slice(&v.to_be_bytes());
		}
		assert_eq!(handshake(&r, CLIENT_HELLO).and_then(hello_cookie), Some(&[7u8, 8][..]));
		assert!(hellos_are_safe(&r));
		// a HelloVerifyRequest: version, cookie
		let mut hvr = vec![22, 0xfe, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12 + 6, 3, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 6];
		hvr.extend([0xfe, 0xff, 3, 1, 2, 3]);
		assert_eq!(handshake(&hvr, HELLO_VERIFY_REQUEST).and_then(verify_request_cookie), Some(&[1u8, 2, 3][..]));
		assert_eq!(handshake(&hvr, CLIENT_HELLO), None);
		// cut short: nothing
		assert_eq!(handshake(&hvr[..hvr.len() - 1], HELLO_VERIFY_REQUEST), None);
		// epoch 1: not read
		hvr[4] = 1;
		assert_eq!(handshake(&hvr, HELLO_VERIFY_REQUEST), None);
	}

	#[test]
	fn only_a_client_hello_opens() {
		assert!(opens_handshake(&record(&[])));
		assert!(opens_handshake(&record(&[0, 0x17, 0, 0])));
		// a truncated extension the crate would panic on
		assert!(!opens_handshake(&record(&[0, 0x17, 0])));
		// epoch 1, an application record, an alert, too short, not DTLS
		let mut r = record(&[]);
		r[4] = 1;
		assert!(!opens_handshake(&r));
		assert!(!opens_handshake(&[23, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 9, 9]));
		assert!(!opens_handshake(&[21, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 40]));
		assert!(!opens_handshake(&record(&[])[..20]));
		let mut r = record(&[]);
		r[1] = 0x03;
		assert!(!opens_handshake(&r));
		// another handshake message (a Finished in the clear)
		let mut r = record(&[]);
		r[13] = 20;
		assert!(!opens_handshake(&r));
	}

	#[test]
	fn other_records_pass() {
		assert!(hellos_are_safe(&[]));
		assert!(hellos_are_safe(&[23, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 1, 0, 2, 9, 9]));
		// a handshake record of epoch 1 (encrypted)
		let mut r = record(&[0]);
		r[4] = 1;
		assert!(hellos_are_safe(&r));
		// garbage shorter than a record header
		assert!(hellos_are_safe(&[22, 0xfe]));
	}
}
