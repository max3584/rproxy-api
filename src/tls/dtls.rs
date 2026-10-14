//! Feeding one client's datagrams from the shared UDP listener into a DTLS
//! server connection.

use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

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
}

impl SessionConn {
	pub fn new(from_client: mpsc::Receiver<Vec<u8>>, listener: Arc<Listener>, client: SocketAddr, local: Option<Local>) -> Self {
		SessionConn { from_client: Mutex::new(from_client), listener, client, local }
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

/// Whether the ClientHellos in this datagram are safe to hand to the `dtls`
/// crate. Its ClientHello parser (0.17.2) indexes into the extensions without
/// checking that 4 bytes are left, and panics on a truncated one (#287). So a
/// ClientHello (epoch 0) must come whole in one record, and its extensions are
/// walked the way the crate walks them. Anything else passes: what the crate
/// cannot parse it refuses with an error.
pub fn hellos_are_safe(mut d: &[u8]) -> bool {
	const HANDSHAKE: u8 = 22;
	const CLIENT_HELLO: u8 = 1;
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
