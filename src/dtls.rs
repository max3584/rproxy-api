//! Feeding one client's datagrams from the shared UDP listener into a DTLS
//! server connection.

use std::any::Any;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use webrtc_util::conn::Conn;

/// A per-client view of the listener: reads come from the session's queue,
/// writes go out of the listener to that client.
pub struct SessionConn {
	from_client: Mutex<mpsc::Receiver<Vec<u8>>>,
	listener: Arc<UdpSocket>,
	client: SocketAddr,
}

impl SessionConn {
	pub fn new(from_client: mpsc::Receiver<Vec<u8>>, listener: Arc<UdpSocket>, client: SocketAddr) -> Self {
		SessionConn { from_client: Mutex::new(from_client), listener, client }
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
		let datagram = self.from_client.lock().await.recv().await.ok_or_else(closed)?;
		let n = datagram.len().min(buf.len());
		buf[..n].copy_from_slice(&datagram[..n]);
		Ok(n)
	}

	async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
		Ok((self.recv(buf).await?, self.client))
	}

	async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
		Ok(self.listener.send_to(buf, self.client).await?)
	}

	async fn send_to(&self, buf: &[u8], _: SocketAddr) -> webrtc_util::Result<usize> {
		self.send(buf).await
	}

	fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
		Ok(self.listener.local_addr()?)
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
