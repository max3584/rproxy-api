// The forwarding loop descends from the original rproxy project by glacierx and
// has been rewritten around cancellation tokens for rproxy-api.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::balance::Lease;
use crate::http::server::{self as http, Metered};
use crate::proxy::{Counted, Runtime, Target};
use crate::rule::SourceIp;
use crate::source::{self, TlsInfo};
use crate::starttls::{self, Outcome};
use crate::tlsconf::{StartTls, TlsMode, TlsRuntime};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// With other targets to fall back on, a target that does not answer is given up after this.
const FAILOVER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Accepts connections on one port of the rule; `offset` is its place in a range.
/// `stop` ends it: the rule's `stop`, or the address being taken off the rule.
pub async fn serve(listener: TcpListener, rt: Arc<Runtime>, offset: u16, stop: CancellationToken) {
	loop {
		tokio::select! {
			biased;
			_ = stop.cancelled() => break,
			accepted = listener.accept() => match accepted {
				Ok((inbound, peer)) => {
					rt.tracker.spawn(handle(inbound, peer, rt.clone(), offset));
				}
				Err(e) => {
					// e.g. EMFILE: back off instead of spinning
					warn!(event = "accept.error", rule = %rt.key, error = %e);
					tokio::time::sleep(Duration::from_millis(100)).await;
				}
			}
		}
	}
}

/// A connection to one of the rule's backends.
struct Connected {
	stream: TcpStream,
	addr: SocketAddr,
	/// Host name as configured, for verifying the backend's certificate.
	host: String,
	/// Counts the connection on its target while it lasts.
	lease: Option<Lease>,
}

/// Connects to the first backend that answers, in the order `balance` gave;
/// a target that refuses is marked down for a while and the next one is tried.
async fn connect(rt: &Runtime, client: SocketAddr, target: &Target) -> io::Result<Connected> {
	let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no resolved target");
	let bind_as = rt.bind_as(client);
	// transparent: only backends of the client's address family (an IPv6 client
	// of a rule that also listens on IPv4 goes to an IPv6 target)
	let usable = |c: &&crate::proxy::Candidate| c.addrs.iter().any(|a| source::usable(*a, bind_as));
	let fallback = target.candidates.iter().filter(usable).count() > 1;
	for c in target.candidates.iter().filter(usable) {
		let lease = c.lease();
		for addr in c.addrs.iter().filter(|a| source::usable(**a, bind_as)) {
			let attempt = source::connect_tcp(*addr, rt.bind_as(client));
			let result = if fallback {
				tokio::time::timeout(FAILOVER_CONNECT_TIMEOUT, attempt)
					.await
					.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")))
			} else {
				attempt.await
			};
			match result {
				Ok(stream) => return Ok(Connected { stream, addr: *addr, host: c.host.clone(), lease }),
				Err(e) => last_err = io::Error::new(e.kind(), format!("{addr}: {e}")),
			}
		}
		if let (Some(pool), Some(member)) = (&target.pool, &c.member) {
			pool.mark_failed(&rt.key, member, &last_err.to_string());
		}
	}
	Err(last_err)
}

async fn send_proxy_header(
	rt: &Runtime,
	out: &mut TcpStream,
	client: SocketAddr,
	local: SocketAddr,
	tls: Option<&TlsInfo>,
) -> io::Result<()> {
	match rt.source_ip {
		SourceIp::ProxyV1 => out.write_all(&source::proxy_v1_header(client, local)).await,
		SourceIp::ProxyV2 => out.write_all(&source::proxy_v2_header_with(client, local, tls)).await,
		SourceIp::Proxy | SourceIp::Transparent => Ok(()),
	}
}

/// Fields for the connection log.
#[derive(Default)]
struct Detail {
	target: Option<SocketAddr>,
	/// Counts the connection on the chosen target until it ends.
	lease: Option<Lease>,
	tls: Option<TlsInfo>,
	rx: u64,
	tx: u64,
	reason: &'static str,
}

/// Refusal that is not an error: allow_from or `unmatched: reject`.
fn denied(rt: &Runtime, client: SocketAddr, why: &str, sni: Option<&str>) -> io::Error {
	rt.stats.denied();
	info!(event = "conn.denied", rule = %rt.key, client = %client, reason = why, sni = sni.unwrap_or(""));
	io::Error::new(io::ErrorKind::PermissionDenied, "denied")
}

fn is_denied(e: &io::Error) -> bool {
	e.kind() == io::ErrorKind::PermissionDenied && e.to_string() == "denied"
}

async fn handle(mut inbound: TcpStream, client: SocketAddr, rt: Arc<Runtime>, offset: u16) {
	if !rt.allowed(client.ip()) {
		denied(&rt, client, "allow_from", None);
		return;
	}
	if rt.crowdsec_blocks(client.ip()) {
		denied(&rt, client, "crowdsec", None);
		return;
	}
	let tls = rt.tls();
	// a `terminate` rule with passthrough routes reads the ClientHello first:
	// passthrough names are relayed as they are, the others are terminated
	// from the bytes already read
	let mut prefix = Vec::new();
	let mut pass = None;
	if tls.mode() == TlsMode::Terminate && tls.starttls.is_none() && rt.has_passthrough() {
		match crate::sni::read_client_hello(&mut inbound).await {
			Ok((name, hello)) => match rt.select(name.as_deref(), offset) {
				Some(target) if target.passthrough => pass = Some((name, hello, target)),
				// no match with `unmatched: reject` is refused by the TLS handshake below
				_ => prefix = hello,
			},
			Err(e) => {
				rt.stats.tls_failed();
				warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e, "reading the ClientHello");
				return;
			}
		}
	}
	if pass.is_none() && rt.http_router().is_some() {
		return handle_http(inbound, prefix, client, rt, offset).await;
	}
	let started = Instant::now();
	rt.stats.opened();
	let mut detail = Detail::default();

	let serving = async {
		match pass {
			Some((name, hello, target)) => {
				let local = inbound.local_addr()?;
				relay_hello(&mut inbound, client, local, &rt, &target, name, hello, true, &mut detail).await
			}
			None => run(&mut inbound, prefix, client, &rt, offset, &tls, &mut detail).await,
		}
	};
	let result = tokio::select! {
		_ = rt.kill.cancelled() => { detail.reason = "stopped"; Ok(()) }
		r = serving => r,
	};

	rt.stats.closed();
	let elapsed_ms = started.elapsed().as_millis() as u64;
	let info = detail.tls.unwrap_or_default();
	let target = detail.target.map(|t| t.to_string()).unwrap_or_default();
	match result {
		Err(e) if is_denied(&e) => {}
		Ok(()) => info!(event = "conn.close", rule = %rt.key, client = %client, target = %target,
			rx_bytes = detail.rx, tx_bytes = detail.tx, duration_ms = elapsed_ms, reason = detail.reason,
			sni = info.server_name.as_deref().unwrap_or(""), client_cn = info.client_cn.as_deref().unwrap_or("")),
		Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, target = %target,
			error = %e, duration_ms = elapsed_ms, sni = info.server_name.as_deref().unwrap_or("")),
	}
}

async fn run(
	inbound: &mut TcpStream,
	prefix: Vec<u8>,
	client: SocketAddr,
	rt: &Runtime,
	offset: u16,
	tls: &TlsRuntime,
	detail: &mut Detail,
) -> io::Result<()> {
	let local = inbound.local_addr()?;
	match tls.mode() {
		TlsMode::Passthrough => {
			let target = rt.select(None, offset).ok_or_else(|| denied(rt, client, "unmatched", None))?;
			let Connected { stream: mut out, addr, lease, .. } = connect(rt, client, &target).await?;
			detail.target = Some(addr);
			detail.lease = lease;
			info!(event = "conn.open", rule = %rt.key, listen = %local, client = %client, target = %addr);
			send_proxy_header(rt, &mut out, client, local, None).await?;
			finish(rt, inbound, &mut out, detail).await
		}
		TlsMode::Sni => {
			let (name, hello) = crate::sni::read_client_hello(inbound).await.inspect_err(|_| rt.stats.tls_failed())?;
			let target = rt.select(name.as_deref(), offset).ok_or_else(|| denied(rt, client, "unmatched", name.as_deref()))?;
			relay_hello(inbound, client, local, rt, &target, name, hello, false, detail).await
		}
		TlsMode::Terminate => terminate(inbound, prefix, client, local, rt, offset, tls, detail).await,
	}
}

/// Relays a connection without terminating TLS: the ClientHello already read,
/// then everything else (mode `sni`, and `passthrough` routes of `terminate`).
#[allow(clippy::too_many_arguments)]
async fn relay_hello(
	inbound: &mut TcpStream,
	client: SocketAddr,
	local: SocketAddr,
	rt: &Runtime,
	target: &Target,
	name: Option<String>,
	hello: Vec<u8>,
	passthrough: bool,
	detail: &mut Detail,
) -> io::Result<()> {
	let Connected { stream: mut out, addr, lease, .. } = connect(rt, client, target).await?;
	detail.target = Some(addr);
	detail.lease = lease;
	detail.tls = Some(TlsInfo { server_name: name.clone(), ..Default::default() });
	info!(event = "conn.open", rule = %rt.key, listen = %local, client = %client, target = %addr, sni = name.as_deref().unwrap_or(""), passthrough);
	send_proxy_header(rt, &mut out, client, local, None).await?;
	out.write_all(&hello).await?;
	detail.rx += hello.len() as u64;
	rt.stats.add_rx(hello.len() as u64);
	finish(rt, inbound, &mut out, detail).await
}

/// A stream that first yields bytes already read from it (the ClientHello read
/// to look at the server name), then the rest.
struct Prefixed<S> {
	prefix: Vec<u8>,
	pos: usize,
	inner: S,
}

impl<S> Prefixed<S> {
	fn new(prefix: Vec<u8>, inner: S) -> Self {
		Prefixed { prefix, pos: 0, inner }
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<io::Result<()>> {
		let this = self.get_mut();
		if this.pos < this.prefix.len() {
			let n = (this.prefix.len() - this.pos).min(buf.remaining());
			buf.put_slice(&this.prefix[this.pos..this.pos + n]);
			this.pos += n;
			return std::task::Poll::Ready(Ok(()));
		}
		std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
	fn poll_write(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<io::Result<usize>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
	}

	fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}
}

/// Relays until both sides close. `a` is the client side, `b` the backend.
async fn finish<A: AsyncRead + AsyncWrite + Unpin + ?Sized, B: AsyncRead + AsyncWrite + Unpin + ?Sized>(
	rt: &Runtime,
	a: &mut A,
	b: &mut B,
	detail: &mut Detail,
) -> io::Result<()> {
	let mut client = Counted::new(a, &rt.stats.rx_bytes);
	let mut backend = Counted::new(b, &rt.stats.tx_bytes);
	let result = tokio::io::copy_bidirectional(&mut client, &mut backend).await;
	detail.rx += client.count;
	detail.tx += backend.count;
	result?;
	detail.reason = "closed";
	Ok(())
}

/// TLS handshake of a `terminate` rule. The ClientHello is read first so
/// unmatched names are refused before any certificate is sent.
async fn accept_tls<S: AsyncRead + AsyncWrite + Unpin>(
	stream: S,
	client: SocketAddr,
	rt: &Runtime,
	offset: u16,
	config: Arc<rustls::ServerConfig>,
) -> io::Result<(tokio_rustls::server::TlsStream<S>, TlsInfo)> {
	let session = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
		let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
		let name = start.client_hello().server_name().map(str::to_string);
		if rt.select(name.as_deref(), offset).is_none() {
			return Err(denied(rt, client, "unmatched", name.as_deref()));
		}
		start.into_stream(config).await
	})
	.await
	.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))
	.and_then(|r| r)
	.inspect_err(|e| {
		if !is_denied(e) {
			rt.stats.tls_failed()
		}
	})?;

	let (_, conn) = session.get_ref();
	let peer_cert = conn.peer_certificates().and_then(|c| c.first()).map(|c| c.as_ref().to_vec());
	let info = TlsInfo {
		server_name: conn.server_name().map(str::to_string),
		alpn: conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
		version: conn.protocol_version().map(|v| format!("{v:?}")),
		cipher: conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())),
		client_cn: peer_cert.as_deref().and_then(crate::tlsconf::common_name),
		client_cert: peer_cert.is_some(),
	};
	Ok((session, info))
}

/// A connection of an `http` rule: TLS (for `terminate`), then HTTP requests
/// routed one by one (src/http/server.rs).
async fn handle_http(inbound: TcpStream, prefix: Vec<u8>, client: SocketAddr, rt: Arc<Runtime>, offset: u16) {
	let started = Instant::now();
	rt.stats.opened();
	let tls = rt.tls();
	let local = inbound.local_addr().unwrap_or(rt.key.listen);
	let (rx, tx) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
	let mut info = None;
	let serving = async {
		match (tls.mode(), tls.server_config.clone()) {
			(TlsMode::Terminate, Some(config)) => {
				let (session, i) = accept_tls(Prefixed::new(prefix, inbound), client, &rt, offset, config).await?;
				info = Some(i.clone());
				let stream = Metered::new(session, rt.clone(), rx.clone(), tx.clone());
				http::serve(stream, client, local, rt.clone(), Some(i)).await
			}
			(TlsMode::Terminate, None) => Err(io::Error::other("TLS is not configured")),
			_ => {
				let stream = Metered::new(inbound, rt.clone(), rx.clone(), tx.clone());
				http::serve(stream, client, local, rt.clone(), None).await
			}
		}
	};
	let result = tokio::select! {
		_ = rt.kill.cancelled() => Ok("stopped"),
		r = serving => r.map(|()| "closed"),
	};
	rt.stats.closed();
	let elapsed_ms = started.elapsed().as_millis() as u64;
	let info = info.unwrap_or_default();
	match result {
		Err(e) if is_denied(&e) => {}
		Ok(reason) => info!(event = "conn.close", rule = %rt.key, client = %client, target = "http",
			rx_bytes = rx.load(Ordering::Relaxed), tx_bytes = tx.load(Ordering::Relaxed), duration_ms = elapsed_ms, reason,
			sni = info.server_name.as_deref().unwrap_or(""), client_cn = info.client_cn.as_deref().unwrap_or("")),
		Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, target = "http",
			error = %e, duration_ms = elapsed_ms, sni = info.server_name.as_deref().unwrap_or("")),
	}
}

#[allow(clippy::too_many_arguments)]
async fn terminate(
	inbound: &mut TcpStream,
	prefix: Vec<u8>,
	client: SocketAddr,
	local: SocketAddr,
	rt: &Runtime,
	offset: u16,
	tls: &TlsRuntime,
	detail: &mut Detail,
) -> io::Result<()> {
	let config = tls.server_config.clone().ok_or_else(|| io::Error::other("TLS is not configured"))?;

	if let Some(proto) = tls.starttls {
		let outcome = starttls::serve_client(proto, inbound, &tls.greeting_name, tls.starttls_required)
			.await
			.inspect_err(|_| rt.stats.tls_failed())?;
		match outcome {
			Outcome::Upgrade => {}
			Outcome::Closed => {
				detail.reason = "quit";
				return Ok(());
			}
			Outcome::Plain { ehlo, pending } => return plain_smtp(inbound, client, local, rt, offset, ehlo, pending, detail).await,
		}
	}

	let (mut session, info) = accept_tls(Prefixed::new(prefix, &mut *inbound), client, rt, offset, config).await?;
	let target = rt
		.select(info.server_name.as_deref(), offset)
		.ok_or_else(|| denied(rt, client, "unmatched", info.server_name.as_deref()))?;
	let Connected { stream: mut out, addr, host, lease } = connect(rt, client, &target).await?;
	detail.target = Some(addr);
	detail.lease = lease;
	info!(event = "conn.open", rule = %rt.key, listen = %local, client = %client, target = %addr,
		sni = info.server_name.as_deref().unwrap_or(""), alpn = info.alpn.as_deref().unwrap_or(""),
		tls_version = info.version.as_deref().unwrap_or(""), tls_cipher = info.cipher.as_deref().unwrap_or(""),
		client_cn = info.client_cn.as_deref().unwrap_or(""), starttls = tls.starttls.map(|p| p.as_str()).unwrap_or(""));
	send_proxy_header(rt, &mut out, client, local, Some(&info)).await?;
	detail.tls = Some(info);

	let mut upstream: Box<dyn Stream> = match &tls.connector {
		Some(connector) => {
			let name = tls.upstream_name(&host).map_err(|e| io::Error::other(e.message))?;
			Box::new(
				tokio::time::timeout(HANDSHAKE_TIMEOUT, connector.connect(name, out))
					.await
					.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "backend TLS handshake timed out"))??,
			)
		}
		None => Box::new(out),
	};

	if let Some(proto) = tls.starttls {
		let extra = starttls::skip_greeting(proto, &mut upstream).await?;
		session.write_all(&extra).await?;
		if proto == StartTls::Smtp {
			let (to_server, to_client) = starttls::relay_first_ehlo(&mut session, &mut upstream).await?;
			upstream.write_all(&to_server).await?;
			session.write_all(&to_client).await?;
		}
	}
	finish(rt, &mut session, &mut upstream, detail).await
}

/// SMTP client that carried on without STARTTLS (`starttls_required: false`).
#[allow(clippy::too_many_arguments)]
async fn plain_smtp(
	inbound: &mut TcpStream,
	client: SocketAddr,
	local: SocketAddr,
	rt: &Runtime,
	offset: u16,
	ehlo: Option<String>,
	pending: Vec<u8>,
	detail: &mut Detail,
) -> io::Result<()> {
	let target = rt.select(None, offset).ok_or_else(|| denied(rt, client, "unmatched", None))?;
	let Connected { stream: mut out, addr, lease, .. } = connect(rt, client, &target).await?;
	detail.target = Some(addr);
	detail.lease = lease;
	info!(event = "conn.open", rule = %rt.key, listen = %local, client = %client, target = %addr, starttls = "smtp", tls = "none");
	send_proxy_header(rt, &mut out, client, local, None).await?;
	let extra = starttls::skip_greeting(StartTls::Smtp, &mut out).await?;
	let after = starttls::replay_plain(&mut out, ehlo.as_deref(), &pending).await?;
	inbound.write_all(&extra).await?;
	inbound.write_all(&after).await?;
	finish(rt, inbound, &mut out, detail).await
}
