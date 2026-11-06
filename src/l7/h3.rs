//! HTTP/3 for `http` rules with `http3: true` (#56): QUIC on the rule's address
//! and port over UDP, with the certificates of the rule's TLS settings. Requests
//! go through the same router, middlewares and backends as HTTP/1.1 and HTTP/2.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
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
use crate::core::bandwidth::{Dir, Gate};
use crate::core::proxy::Runtime;
use crate::net::source::TlsInfo;

/// The QUIC side of a rule: whether it listens, and why not.
#[derive(Default)]
pub struct H3State {
	/// The UDP port HTTP/3 is answered on (for `Alt-Svc`); 0 while it is not.
	port: AtomicU16,
	error: RwLock<Option<String>>,
	/// Stops the endpoint (when `http3` is turned off, or the rule stops).
	stop: Mutex<Option<CancellationToken>>,
	/// QUIC handshakes in progress on all the rule's addresses (`MAX_HANDSHAKES`).
	handshakes: AtomicUsize,
}

/// What one QUIC connection may make the proxy buffer of what the client sends (#355; quinn's
/// default is no limit for the connection, 1.25 MB for each of 100 streams).
const CONNECTION_RECEIVE_WINDOW: u32 = 4 << 20;
const STREAM_RECEIVE_WINDOW: u32 = 1 << 20;
/// HTTP/3 needs 3 unidirectional streams of the client (control, QPACK encoder and decoder);
/// a few more for streams of extensions it does not know, which are read and dropped.
const MAX_UNI_STREAMS: u32 = 8;
/// QUIC's own idle timeout (a connection without any packet: the peer is gone) follows
/// `global.http.timeouts.idle`, from `MIN_QUIC_IDLE` to `MAX_QUIC_IDLE` (also when `idle` is
/// unlimited: a client that wants more keeps the connection with PINGs, and `idle` still
/// closes it without requests). A short `idle` must not cut a request whose backend is slow:
/// `idle` only counts time without requests, QUIC's counts time without packets.
const MIN_QUIC_IDLE: Duration = Duration::from_secs(30);
const MAX_QUIC_IDLE: Duration = Duration::from_secs(600);
/// The proxy PINGs a connection that has been quiet this long (at most half of QUIC's idle
/// timeout), so a request waiting on a slow backend keeps it, also with a client whose own
/// idle timeout is shorter. A peer that is gone does not answer, and the idle timeout ends it.
const MAX_KEEP_ALIVE: Duration = Duration::from_secs(15);
/// QUIC handshakes of one rule in progress at a time; more are refused (#355). Only clients
/// whose address is validated (Retry) get this far.
const MAX_HANDSHAKES: usize = 512;
/// How long a request body that has all of its Content-Length waits for the end of its
/// stream after the handler is done with it, before the client is told to stop sending.
const BODY_END_GRACE: Duration = Duration::from_secs(5);
/// Connection attempts quinn holds before the rule's task looks at them.
const MAX_INCOMING: usize = 4096;
const INCOMING_BUFFER_TOTAL: u64 = 16 << 20;

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
		base_config(config)
	})();
	let mut endpoints = vec![];
	let mut errors = vec![];
	match &server {
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
		Err(e) => errors.push(e.clone()),
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
	let Ok(base) = server else { return };
	let base = Arc::new(base);
	for (addr, endpoint) in endpoints {
		info!(event = "http3.listening", rule = %rt.key, addr = %addr);
		rt.tracker.spawn(serve(endpoint, base.clone(), rt.clone(), token.clone()));
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

/// The endpoint's QUIC settings: the key of its Retry tokens, and how many connection
/// attempts it holds. The settings of each connection are made from it (`quinn_config`).
fn base_config(tls: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig, String> {
	let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| format!("QUIC: {e}"))?;
	let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
	server.max_incoming(MAX_INCOMING).incoming_buffer_size_total(INCOMING_BUFFER_TOTAL);
	server.transport_config(transport(None));
	Ok(server)
}

/// The settings of a new connection: the certificates in use and `global.http.timeouts.idle`,
/// with the Retry token key of the endpoint (a token it gave stays good for the connection).
fn quinn_config(base: &quinn::ServerConfig, tls: Arc<rustls::ServerConfig>, idle: Option<Duration>) -> Result<quinn::ServerConfig, String> {
	let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| format!("QUIC: {e}"))?;
	let mut server = base.clone();
	server.crypto = Arc::new(crypto);
	server.transport_config(transport(idle));
	Ok(server)
}

/// Flow control and limits of a QUIC connection (#355).
fn transport(idle: Option<Duration>) -> Arc<quinn::TransportConfig> {
	let mut t = quinn::TransportConfig::default();
	t.receive_window(quinn::VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
		.stream_receive_window(quinn::VarInt::from_u32(STREAM_RECEIVE_WINDOW))
		.max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_UNI_STREAMS))
		.max_idle_timeout(quinn::IdleTimeout::try_from(quic_idle(idle)).ok())
		.keep_alive_interval(Some((quic_idle(idle) / 2).min(MAX_KEEP_ALIVE)));
	Arc::new(t)
}

/// QUIC's idle timeout for `global.http.timeouts.idle` (`MIN_QUIC_IDLE`, `MAX_QUIC_IDLE`).
fn quic_idle(idle: Option<Duration>) -> Duration {
	idle.map_or(MAX_QUIC_IDLE, |i| i.clamp(MIN_QUIC_IDLE, MAX_QUIC_IDLE))
}

/// A QUIC handshake counted in `H3State.handshakes` until it ends.
struct Handshake(Arc<Runtime>);

impl Handshake {
	fn begin(rt: &Arc<Runtime>) -> Option<Handshake> {
		if rt.h3.handshakes.fetch_add(1, Ordering::Relaxed) >= MAX_HANDSHAKES {
			rt.h3.handshakes.fetch_sub(1, Ordering::Relaxed);
			return None;
		}
		Some(Handshake(rt.clone()))
	}
}

impl Drop for Handshake {
	fn drop(&mut self) {
		self.0.h3.handshakes.fetch_sub(1, Ordering::Relaxed);
	}
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

async fn serve(endpoint: quinn::Endpoint, base: Arc<quinn::ServerConfig>, rt: Arc<Runtime>, token: CancellationToken) {
	// the QUIC settings of the certificates and `idle` in use; renewed ones are picked up per connection
	type Current = (Arc<rustls::ServerConfig>, Option<Duration>, Arc<quinn::ServerConfig>);
	let mut current: Option<Current> = None;
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
		// an address not validated yet gets a Retry first (#355): a spoofed source never gets
		// further, so it cannot use up `limits` or the handshakes, make the proxy send much, or
		// show up in the `denied` counts and logs
		if !incoming.remote_address_validated() {
			if let Err(e) = incoming.retry() {
				e.into_incoming().refuse();
			}
			continue;
		}
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
		let Some(handshake) = Handshake::begin(&rt) else {
			busy(&rt, client);
			incoming.refuse();
			continue;
		};
		// `limits` (#165): one QUIC connection counts as one connection, held until it ends
		let permit = match rt.limits.get().map(|l| l.admit(client.ip())) {
			None => None,
			Some(Ok(permit)) => Some(permit),
			Some(Err(reason)) => {
				crate::core::limits::refused(&rt, client, reason, "quic");
				incoming.refuse();
				continue;
			}
		};
		let tls = rt.tls();
		let Some(Ok(config)) = tls.quic_config.clone() else {
			incoming.refuse();
			continue;
		};
		let idle = rt.global.timeouts().idle;
		let server = match &current {
			Some((tls, i, server)) if Arc::ptr_eq(tls, &config) && *i == idle => server.clone(),
			_ => match quinn_config(&base, config.clone(), idle) {
				Ok(server) => {
					let server = Arc::new(server);
					current = Some((config, idle, server.clone()));
					server
				}
				Err(e) => {
					warn!(event = "http3.error", rule = %rt.key, error = %e, "keeping the previous certificates");
					match &current {
						Some((_, _, server)) => server.clone(),
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
				rt.tracker.spawn(connection(connecting, client, local, rt.clone(), handshake, permit));
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

/// Too many QUIC handshakes in progress: refused, counted as a failed handshake.
fn busy(rt: &Runtime, client: SocketAddr) {
	rt.stats.tls_failed();
	if let Some(suppressed) = rt.limited_log.check(&client.ip()) {
		info!(event = "conn.limited", rule = %rt.key, client = %client, reason = "quic_handshakes", transport = "quic", suppressed);
	}
}

async fn connection(
	connecting: quinn::Connecting,
	client: SocketAddr,
	local: SocketAddr,
	rt: Arc<Runtime>,
	handshake: Handshake,
	_permit: Option<crate::core::limits::Permit>,
) {
	let started = Instant::now();
	rt.stats.opened();
	let result = tokio::select! {
		_ = rt.kill.cancelled() => Ok("stopped"),
		r = run(connecting, handshake, client, local, &rt) => r,
	};
	rt.stats.closed();
	let duration_ms = started.elapsed().as_millis() as u64;
	match result {
		Ok(reason) => info!(event = "conn.close", rule = %rt.key, client = %client, transport = "quic", duration_ms, reason),
		Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, transport = "quic", duration_ms, error = %e),
	}
}

async fn run(
	connecting: quinn::Connecting,
	handshake: Handshake,
	client: SocketAddr,
	local: SocketAddr,
	rt: &Arc<Runtime>,
) -> Result<&'static str, String> {
	// global.http.timeouts (#320)
	let limits = rt.global.timeouts();
	let done = match limits.tls_handshake {
		Some(limit) => tokio::time::timeout(limit, connecting).await.ok(),
		None => Some(connecting.await),
	};
	drop(handshake);
	let conn = match done {
		Some(Ok(c)) => c,
		Some(Err(e)) => {
			rt.stats.tls_failed();
			return Err(format!("QUIC handshake: {e}"));
		}
		None => {
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
	// requests in progress: a connection without any for `idle` is closed (#320; QUIC's own
	// idle timeout does not see a client that keeps the connection with PINGs)
	let activity = super::timeouts::Activity::new();
	loop {
		let accepted = match limits.idle {
			// waiting in accept() keeps its state in the connection: safe to give up
			Some(idle) => tokio::select! {
				a = h3.accept() => a,
				_ = activity.idle(idle) => {
					conn_close(&mut h3).await;
					return Ok("idle");
				}
			},
			None => h3.accept().await,
		};
		match accepted {
			Ok(Some(resolver)) => {
				let handler = handler.clone();
				let rt2 = rt.clone();
				let busy = activity.begin();
				rt.tracker.spawn(async move {
					let _busy = busy;
					// the request's headers (request_headers)
					let resolved = match limits.request_headers {
						Some(limit) => tokio::time::timeout(limit, resolver.resolve_request()).await.ok(),
						None => Some(resolver.resolve_request().await),
					};
					match resolved {
						Some(Ok((req, stream))) => request(handler, req, stream, rt2, client.ip(), limits.request_body_idle).await,
						Some(Err(e)) => warn!(event = "http.error", rule = %rt2.key, error = %e, transport = "quic", "bad request"),
						None => warn!(event = "http.error", rule = %rt2.key, error = "request headers timed out", transport = "quic", "bad request"),
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

/// Closes an idle HTTP/3 connection: GOAWAY, then the QUIC connection.
async fn conn_close(h3: &mut h3::server::Connection<h3_quinn::Connection, Bytes>) {
	let _ = tokio::time::timeout(Duration::from_secs(1), h3.shutdown(0)).await;
}

async fn request(handler: Arc<Conn>, req: Request<()>, stream: Stream, rt: Arc<Runtime>, client: IpAddr, body_idle: Option<Duration>) {
	let (mut send, mut recv) = stream.split();
	// h3 does not compare the DATA with Content-Length (RFC 9114 4.1.2): the body reader does
	let Ok(length) = content_length(req.headers()) else {
		warn!(event = "http.error", rule = %rt.key, client = %client, error = "invalid content-length", transport = "quic", status = 400u16, "bad request");
		recv.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
		let resp = Response::builder().status(hyper::StatusCode::BAD_REQUEST).body(()).expect("a 400");
		if send.send_response(resp).await.is_err() || send.finish().await.is_err() {
			send.stop_stream(h3::error::Code::H3_MESSAGE_ERROR);
		}
		return;
	};
	// request_body_idle: not for gRPC, and only until the response head goes out (#320)
	let body_idle = body_idle.filter(|_| !super::timeouts::is_grpc(req.headers()));
	let responded = super::timeouts::Responded::default();
	let body = request_body(recv, rt.clone(), client, length, body_idle, responded.clone());
	let resp = handler.handle(req.map(|_| body)).await;
	responded.set();
	if let Err(e) = respond(&mut send, resp, &rt, client).await {
		warn!(event = "http.error", rule = %rt.key, error = %e, transport = "quic", "response cut short");
		// reset the stream: dropping it would finish it (quinn), and the client would
		// take a response cut short for a complete one
		send.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
	}
}

/// The request's Content-Length: none, or the one value of all its fields (an error when
/// they cannot be read or do not agree).
fn content_length(headers: &hyper::HeaderMap) -> Result<Option<u64>, ()> {
	let mut length = None;
	for v in headers.get_all(hyper::header::CONTENT_LENGTH) {
		let n = v
			.to_str()
			.ok()
			.filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
			.and_then(|s| s.parse::<u64>().ok())
			.ok_or(())?;
		if length.is_some_and(|l| l != n) {
			return Err(());
		}
		length = Some(n);
	}
	Ok(length)
}

/// A request body that does not match its Content-Length (RFC 9114 4.1.2: malformed).
fn length_mismatch(what: &str) -> BoxError {
	BoxError::new(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("request body {what} than its content-length")))
}

/// The request body, read from the QUIC stream by a task as the backend takes it
/// (one frame ahead). A client silent for `idle` while it is read ends it with an error,
/// and so does a body longer or shorter than `length` (its Content-Length). The rule's
/// `bandwidth` paces the reads (the client's flow control window then fills).
fn request_body(
	mut recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
	rt: Arc<Runtime>,
	client: IpAddr,
	length: Option<u64>,
	idle: Option<Duration>,
	responded: super::timeouts::Responded,
) -> Body {
	let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(1);
	let kill = rt.kill.clone();
	let tracker = rt.tracker.clone();
	tracker.spawn(async move {
		let mut gate = Gate::new(client, Dir::Up);
		let mut left = length;
		// a read of the stream in progress: one given up keeps the stream inside h3-quinn,
		// whose stop_sending then panics; dropping the stream stops it (code 0) instead
		let reading = std::sync::atomic::AtomicBool::new(false);
		// all of Content-Length has come: only the end of the stream (or trailers) is left
		let complete = std::sync::atomic::AtomicBool::new(length == Some(0));
		// why reading stopped before the end of the stream, to tell the client
		let stop = {
			let read = async {
				loop {
					std::future::poll_fn(|cx| gate.poll_allow(&rt.bandwidth, cx)).await;
					reading.store(true, Ordering::Relaxed);
					let data = match idle.filter(|_| !responded.get()) {
						Some(limit) => {
							let read = recv.recv_data();
							tokio::pin!(read);
							tokio::select! {
								d = &mut read => Some(d),
								// once the response is under way the exchange may be bidirectional: keep waiting
								_ = tokio::time::sleep(limit) => if responded.get() { Some(read.await) } else { None },
							}
						}
						None => Some(recv.recv_data().await),
					};
					if data.is_some() {
						reading.store(false, Ordering::Relaxed);
					}
					let Some(data) = data else {
						let _ = tx.send(Err(super::timeouts::body_timed_out())).await;
						return Some(h3::error::Code::H3_REQUEST_CANCELLED);
					};
					let frame = match data {
						Ok(Some(mut data)) => {
							let bytes = data.copy_to_bytes(data.remaining());
							let n = bytes.len() as u64;
							rt.stats.add_rx(n);
							gate.spend(&rt.bandwidth, bytes.len());
							if let Some(l) = left {
								if n > l {
									// nothing of a body longer than it said goes on
									let _ = tx.send(Err(length_mismatch("longer"))).await;
									return Some(h3::error::Code::H3_MESSAGE_ERROR);
								}
								left = Some(l - n);
								if l == n {
									complete.store(true, Ordering::Relaxed);
								}
							}
							Ok(Frame::data(bytes))
						}
						Ok(None) => {
							if left.is_some_and(|l| l > 0) {
								let _ = tx.send(Err(length_mismatch("shorter"))).await;
								return None;
							}
							reading.store(true, Ordering::Relaxed);
							let trailers = recv.recv_trailers().await;
							reading.store(false, Ordering::Relaxed);
							match trailers {
								Ok(Some(trailers)) => {
									let _ = tx.send(Ok(Frame::trailers(trailers))).await;
								}
								Ok(None) => {}
								Err(e) => {
									let _ = tx.send(Err(BoxError::new(e))).await;
								}
							}
							return None;
						}
						Err(e) => Err(BoxError::new(e)),
					};
					let failed = frame.is_err();
					// the handler dropped the body (answered without reading it)
					if tx.send(frame).await.is_err() {
						return Some(h3::error::Code::H3_NO_ERROR);
					}
					if failed {
						return None;
					}
				}
			};
			tokio::pin!(read);
			tokio::select! {
				// the end of the stream first: a body read to its end is not stopped
				biased;
				stop = &mut read => stop,
				// the rule stopped: the body did not end, so do not let it look complete
				_ = kill.cancelled() => {
					let _ = tx.try_send(Err(BoxError::new(std::io::Error::other("rule stopped"))));
					None
				}
				// the handler dropped the body before its end (answered without reading it, or the
				// request ended otherwise): the client need not send the rest (RFC 9114 4.1). Told
				// with H3_NO_ERROR, or code 0 when the stream is dropped in the middle of a read.
				// A body with all of its Content-Length is not stopped: its end may still be on the
				// way (a lost packet, a busy client), and a client told to stop would see its
				// request fail although the response is complete
				_ = tx.closed() => if complete.load(Ordering::Relaxed) {
					tokio::select! {
						biased;
						stop = &mut read => stop,
						_ = kill.cancelled() => None,
						_ = tokio::time::sleep(BODY_END_GRACE) => Some(h3::error::Code::H3_NO_ERROR),
					}
				} else {
					Some(h3::error::Code::H3_NO_ERROR)
				},
			}
		};
		if let Some(code) = stop.filter(|_| !reading.load(Ordering::Relaxed)) {
			recv.stop_sending(code);
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

	/// The reader has seen the end of the stream (and sent everything before it): a GET whose
	/// stream ended with its headers (#340: the cache need not look for a body).
	fn is_end_stream(&self) -> bool {
		self.0.is_closed() && self.0.is_empty()
	}
}

async fn respond(
	send: &mut h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
	resp: Response<Body>,
	rt: &Runtime,
	client: IpAddr,
) -> Result<(), BoxError> {
	// the rule's `bandwidth` paces the response body (the headers are not counted)
	let mut gate = Gate::new(client, Dir::Down);
	let (mut parts, mut body) = resp.into_parts();
	// connection-specific headers are not allowed in HTTP/3 (RFC 9114 4.2)
	for name in ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"] {
		parts.headers.remove(name);
	}
	send.send_response(Response::from_parts(parts, ())).await.map_err(BoxError::new)?;
	while let Some(frame) = body.frame().await {
		let frame = frame?;
		match frame.into_data() {
			Ok(mut data) => {
				while !data.is_empty() {
					let allow = std::future::poll_fn(|cx| gate.poll_allow(&rt.bandwidth, cx)).await;
					let part = data.split_to(allow.map_or(data.len(), |a| a.min(data.len())));
					rt.stats.add_tx(part.len() as u64);
					gate.spend(&rt.bandwidth, part.len());
					send.send_data(part).await.map_err(BoxError::new)?;
				}
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn content_length_is_one_number() {
		let headers = |values: &[&str]| {
			let mut h = hyper::HeaderMap::new();
			for v in values {
				h.append(hyper::header::CONTENT_LENGTH, v.parse().unwrap());
			}
			h
		};
		assert_eq!(content_length(&headers(&[])), Ok(None));
		assert_eq!(content_length(&headers(&["12"])), Ok(Some(12)));
		assert_eq!(content_length(&headers(&["12", "12"])), Ok(Some(12)));
		for bad in [&["12", "13"][..], &["-1"], &["+1"], &["1 "], &["0x10"], &[""], &["99999999999999999999999"]] {
			assert_eq!(content_length(&headers(bad)), Err(()), "{bad:?}");
		}
	}

	#[test]
	fn quic_idle_follows_the_idle_timeout() {
		assert_eq!(quic_idle(Some(Duration::from_secs(180))), Duration::from_secs(180));
		assert_eq!(quic_idle(Some(Duration::from_secs(5))), MIN_QUIC_IDLE, "a short idle does not cut slow requests");
		assert_eq!(quic_idle(Some(Duration::from_secs(86_400))), MAX_QUIC_IDLE);
		assert_eq!(quic_idle(None), MAX_QUIC_IDLE, "idle unlimited: a peer that is gone is still let go");
	}
}
