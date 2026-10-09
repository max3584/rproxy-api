//! HTTP/3 for `http` rules with `http3: true` (#56): QUIC on the rule's address
//! and port over UDP, with the certificates of the rule's TLS settings. Requests
//! go through the same router, middlewares and backends as HTTP/1.1 and HTTP/2.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use hyper::body::Frame;
use hyper::{Request, Response};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::server::{Body, BoxError, Conn};
use crate::core::proxy::Runtime;
use crate::net::source::TlsInfo;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The QUIC side of a rule: whether it listens, and why not.
#[derive(Default)]
pub struct H3State {
	/// The UDP port HTTP/3 is answered on (for `Alt-Svc`); 0 while it is not.
	port: AtomicU16,
	error: RwLock<Option<String>>,
	/// Stops the endpoint (when `http3` is turned off, or the rule stops).
	stop: Mutex<Option<CancellationToken>>,
}

/// `stats.http.http3` of a rule view.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct H3View {
	pub listening: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

impl H3State {
	/// The UDP port to advertise in `Alt-Svc`, while HTTP/3 is answered.
	pub fn port(&self) -> Option<u16> {
		Some(self.port.load(Ordering::Relaxed)).filter(|p| *p != 0)
	}

	pub fn view(&self) -> H3View {
		H3View { listening: self.port().is_some(), error: self.error.read().unwrap().clone() }
	}
}

/// Starts answering HTTP/3 over UDP on the rule's addresses (`listen_addr` and
/// `extra_listen_addrs`). A port that cannot be bound or TLS settings QUIC cannot
/// use leave the rule running over TCP only (on that address); the reason is in
/// the rule view and the log (`event = "degraded"`, `part = "http3"`).
pub fn start(rt: &Arc<Runtime>) {
	stop(rt);
	let port = rt.key.listen.port();
	let ips = rt.listen.read().unwrap().clone();
	let opts = crate::net::listen::Opts { v6only: ips.len() > 1, freebind: rt.listen_freebind };
	let server = (|| {
		let tls = rt.tls();
		let config = match &tls.quic_config {
			Some(Ok(c)) => c.clone(),
			Some(Err(e)) => return Err(e.clone()),
			None => return Err("HTTP/3 needs tls.mode terminate".to_string()),
		};
		quinn_config(config)
	})();
	let mut endpoints = vec![];
	let mut errors = vec![];
	match server {
		Ok(server) => {
			for ip in ips {
				let addr = SocketAddr::new(ip, port);
				let endpoint = crate::net::listen::udp(addr, opts).map_err(|e| format!("udp {addr}: {e}")).and_then(|socket| {
					quinn::Endpoint::new(quinn::EndpointConfig::default(), Some(server.clone()), socket, Arc::new(quinn::TokioRuntime))
						.map_err(|e| format!("udp {addr}: {e}"))
				});
				match endpoint {
					Ok(e) => endpoints.push((addr, e)),
					Err(e) => errors.push(e),
				}
			}
		}
		Err(e) => errors.push(e),
	}
	let error = (!errors.is_empty()).then(|| errors.join("; "));
	if let Some(e) = &error {
		warn!(event = "degraded", part = "http3", rule = %rt.key, error = %e, "answering over TCP only there");
	}
	*rt.h3.error.write().unwrap() = error;
	if endpoints.is_empty() {
		return;
	}
	let token = rt.stop.child_token();
	*rt.h3.stop.lock().unwrap() = Some(token.clone());
	rt.h3.port.store(port, Ordering::Relaxed);
	for (addr, endpoint) in endpoints {
		info!(event = "http3.listening", rule = %rt.key, addr = %addr);
		rt.tracker.spawn(serve(endpoint, rt.clone(), token.clone()));
	}
}

/// Stops answering HTTP/3 (`http3` turned off); open QUIC connections are closed.
pub fn stop(rt: &Runtime) {
	rt.h3.port.store(0, Ordering::Relaxed);
	*rt.h3.error.write().unwrap() = None;
	if let Some(token) = rt.h3.stop.lock().unwrap().take() {
		token.cancel();
	}
}

fn quinn_config(tls: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig, String> {
	let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| format!("QUIC: {e}"))?;
	Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// IPv4-mapped IPv6 clients as IPv4, like `allow_from`.
fn canonical(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
		v4 => v4,
	}
}

fn denied(rt: &Runtime, client: SocketAddr, why: &str) {
	rt.stats.denied();
	info!(event = "conn.denied", rule = %rt.key, client = %client, reason = why, transport = "quic");
}

async fn serve(endpoint: quinn::Endpoint, rt: Arc<Runtime>, token: CancellationToken) {
	// the QUIC settings of the certificates in use; renewed ones are picked up per connection
	let mut current: Option<(Arc<rustls::ServerConfig>, Arc<quinn::ServerConfig>)> = None;
	let local = endpoint.local_addr().unwrap_or(rt.key.listen);
	loop {
		let incoming = tokio::select! {
			biased;
			_ = token.cancelled() => break,
			i = endpoint.accept() => match i {
				Some(i) => i,
				None => break,
			},
		};
		let client = incoming.remote_address();
		let ip = canonical(client.ip());
		if !rt.allowed(ip) {
			denied(&rt, client, "allow_from");
			incoming.refuse();
			continue;
		}
		if let Err(info) = rt.geoip_check(ip) {
			rt.geoip_denied(client, &info, Some("quic"), false);
			incoming.refuse();
			continue;
		}
		if rt.crowdsec_blocks(ip) {
			denied(&rt, client, "crowdsec");
			incoming.refuse();
			continue;
		}
		let tls = rt.tls();
		let Some(Ok(config)) = tls.quic_config.clone() else {
			incoming.refuse();
			continue;
		};
		let server = match &current {
			Some((tls, server)) if Arc::ptr_eq(tls, &config) => server.clone(),
			_ => match quinn_config(config.clone()) {
				Ok(server) => {
					let server = Arc::new(server);
					current = Some((config, server.clone()));
					server
				}
				Err(e) => {
					warn!(event = "http3.error", rule = %rt.key, error = %e, "keeping the previous certificates");
					match &current {
						Some((_, server)) => server.clone(),
						None => {
							incoming.refuse();
							continue;
						}
					}
				}
			},
		};
		match incoming.accept_with(server) {
			Ok(connecting) => {
				rt.tracker.spawn(connection(connecting, client, local, rt.clone()));
			}
			Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e, transport = "quic"),
		}
	}
	endpoint.set_server_config(None);
	if rt.stop.is_cancelled() {
		// the rule is stopping: open connections may finish until they are killed
		tokio::select! {
			_ = rt.kill.cancelled() => {}
			_ = endpoint.wait_idle() => {}
		}
	}
	endpoint.close(0u32.into(), b"closing");
	let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
}

async fn connection(connecting: quinn::Connecting, client: SocketAddr, local: SocketAddr, rt: Arc<Runtime>) {
	let started = Instant::now();
	rt.stats.opened();
	let result = tokio::select! {
		_ = rt.kill.cancelled() => Ok("stopped"),
		r = run(connecting, client, local, &rt) => r,
	};
	rt.stats.closed();
	let duration_ms = started.elapsed().as_millis() as u64;
	match result {
		Ok(reason) => info!(event = "conn.close", rule = %rt.key, client = %client, transport = "quic", duration_ms, reason),
		Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, transport = "quic", duration_ms, error = %e),
	}
}

async fn run(connecting: quinn::Connecting, client: SocketAddr, local: SocketAddr, rt: &Arc<Runtime>) -> Result<&'static str, String> {
	let conn = match tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting).await {
		Ok(Ok(c)) => c,
		Ok(Err(e)) => {
			rt.stats.tls_failed();
			return Err(format!("QUIC handshake: {e}"));
		}
		Err(_) => {
			rt.stats.tls_failed();
			return Err("QUIC handshake timed out".into());
		}
	};
	let handshake = conn.handshake_data().and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok());
	let chain = conn
		.peer_identity()
		.and_then(|p| p.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok())
		.map(|c| *c)
		.unwrap_or_default();
	let tls = TlsInfo {
		server_name: handshake.as_ref().and_then(|h| h.server_name.clone()),
		alpn: Some("h3".into()),
		version: Some("TLSv1_3".into()),
		..Default::default()
	}
	.with_client(&chain, rt.tls().client_verified(&chain));
	info!(event = "conn.open", rule = %rt.key, client = %client, transport = "quic",
		sni = tls.server_name.as_deref().unwrap_or(""), client_cn = tls.client_cn.as_deref().unwrap_or(""));
	// names of `passthrough` routes are served by their own backend over TCP, never here
	if rt.select(tls.server_name.as_deref(), 0).is_some_and(|t| t.passthrough) {
		conn.close(quinn::VarInt::from_u32(0x0100), b"passthrough name");
		return Ok("passthrough");
	}
	let handler = Arc::new(Conn::new(rt.clone(), client, local, Some(tls), true));
	let mut h3 = h3::server::builder()
		.max_field_section_size(u64::from(super::server::MAX_HEADER_SECTION))
		.build::<_, Bytes>(h3_quinn::Connection::new(conn))
		.await
		.map_err(|e| format!("HTTP/3: {e}"))?;
	loop {
		match h3.accept().await {
			Ok(Some(resolver)) => {
				let handler = handler.clone();
				let rt2 = rt.clone();
				rt.tracker.spawn(async move {
					match resolver.resolve_request().await {
						Ok((req, stream)) => request(handler, req, stream, rt2).await,
						Err(e) => warn!(event = "http.error", rule = %rt2.key, error = %e, transport = "quic", "bad request"),
					}
				});
			}
			Ok(None) => return Ok("closed"),
			Err(e) if e.is_h3_no_error() => return Ok("closed"),
			Err(e) => return Err(format!("HTTP/3: {e}")),
		}
	}
}

type Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn request(handler: Arc<Conn>, req: Request<()>, stream: Stream, rt: Arc<Runtime>) {
	let (mut send, recv) = stream.split();
	let resp = handler.handle(req.map(|_| request_body(recv, rt.clone()))).await;
	if let Err(e) = respond(&mut send, resp, &rt).await {
		warn!(event = "http.error", rule = %rt.key, error = %e, transport = "quic", "response cut short");
		// reset the stream: dropping it would finish it (quinn), and the client would
		// take a response cut short for a complete one
		send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
	}
}

/// The request body, read from the QUIC stream by a task as the backend takes it
/// (one frame ahead).
fn request_body(mut recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>, rt: Arc<Runtime>) -> Body {
	let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(1);
	let kill = rt.kill.clone();
	let tracker = rt.tracker.clone();
	tracker.spawn(async move {
		let read = async {
			loop {
				let frame = match recv.recv_data().await {
					Ok(Some(mut data)) => {
						let bytes = data.copy_to_bytes(data.remaining());
						rt.stats.add_rx(bytes.len() as u64);
						Ok(Frame::data(bytes))
					}
					Ok(None) => {
						match recv.recv_trailers().await {
							Ok(Some(trailers)) => {
								let _ = tx.send(Ok(Frame::trailers(trailers))).await;
							}
							Ok(None) => {}
							Err(e) => {
								let _ = tx.send(Err(BoxError::new(e))).await;
							}
						}
						return;
					}
					Err(e) => Err(BoxError::new(e)),
				};
				let failed = frame.is_err();
				// the handler dropped the body (answered without reading it)
				if tx.send(frame).await.is_err() || failed {
					return;
				}
			}
		};
		tokio::select! {
			// the rule stopped: the body did not end, so do not let it look complete
			_ = kill.cancelled() => {
				let _ = tx.try_send(Err(BoxError::new(std::io::Error::other("rule stopped"))));
			}
			_ = read => {}
		}
	});
	BodyExt::boxed(ChannelBody(rx))
}

struct ChannelBody(tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, BoxError>>);

impl hyper::body::Body for ChannelBody {
	type Data = Bytes;
	type Error = BoxError;

	fn poll_frame(
		mut self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<Option<Result<Frame<Bytes>, BoxError>>> {
		self.0.poll_recv(cx)
	}
}

async fn respond(
	send: &mut h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
	resp: Response<Body>,
	rt: &Runtime,
) -> Result<(), BoxError> {
	let (mut parts, mut body) = resp.into_parts();
	// connection-specific headers are not allowed in HTTP/3 (RFC 9114 4.2)
	for name in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"] {
		parts.headers.remove(name);
	}
	send.send_response(Response::from_parts(parts, ())).await.map_err(BoxError::new)?;
	while let Some(frame) = body.frame().await {
		let frame = frame?;
		match frame.into_data() {
			Ok(data) => {
				rt.stats.add_tx(data.len() as u64);
				send.send_data(data).await.map_err(BoxError::new)?;
			}
			Err(frame) => {
				if let Ok(trailers) = frame.into_trailers() {
					send.send_trailers(trailers).await.map_err(BoxError::new)?;
				}
			}
		}
	}
	send.finish().await.map_err(BoxError::new)
}
