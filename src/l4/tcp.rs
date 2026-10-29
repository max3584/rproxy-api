// The forwarding loop descends from the original rproxy project by glacierx and
// has been rewritten around cancellation tokens for rproxy-api.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::core::balance::{Lease, TargetFull};
use crate::l7::server::{self as http, Metered};
use crate::core::proxy::{Counted, Runtime, Target};
use crate::core::rule::SourceIp;
use crate::net::proxy_in::{self, peer_field};
use crate::net::source::{self, TlsInfo};
use crate::l4::relay;
use crate::l4::starttls::{self, Outcome};
use crate::tls::config::{StartTls, TlsMode, TlsRuntime};

/// Read sizes for a relay between two plain TCP streams.
const PLAIN: (usize, usize) = (relay::BUFFER_SIZE, relay::BUFFER_SIZE);
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
					source::nodelay(&inbound);
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
/// A target at its `max_connections` is passed over (#341): `TargetFull` when no
/// target could be tried for that.
async fn connect(rt: &Runtime, client: SocketAddr, target: &Target) -> io::Result<Connected> {
	let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no resolved target");
	let (mut full, mut tried) = (false, false);
	let bind_as = rt.bind_as_for(target, client);
	// transparent: only backends of the client's address family (an IPv6 client
	// of a rule that also listens on IPv4 goes to an IPv6 target)
	let usable = |c: &&crate::core::proxy::Candidate| c.addrs.iter().any(|a| source::usable(*a, bind_as));
	// a full target (#341) is not one to fall back on
	let fallback = target.candidates.iter().filter(usable).filter(|c| !c.member.as_ref().is_some_and(|m| m.is_full())).count() > 1;
	for c in target.candidates.iter().filter(usable) {
		let Ok(lease) = c.lease() else {
			full = true;
			continue;
		};
		tried = true;
		for addr in c.addrs.iter().filter(|a| source::usable(**a, bind_as)) {
			let attempt = source::connect_tcp(*addr, bind_as);
			// the rule's connect_timeout (v0.4.3); without it, 5 s when another target can be tried
			let limit = rt.connect_timeout().or(fallback.then_some(FAILOVER_CONNECT_TIMEOUT));
			let result = if let Some(limit) = limit {
				tokio::time::timeout(limit, attempt)
					.await
					.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")))
			} else {
				attempt.await
			};
			match result {
				Ok(stream) => {
					// with `short_lived`, the connection is judged when it ends (`Pool::ended`)
					if let (Some(pool), Some(member)) = (&target.pool, &c.member) {
						if pool.outlier().short_lived.is_zero() {
							pool.succeeded(member);
						}
					}
					return Ok(Connected { stream, addr: *addr, host: c.host.clone(), lease });
				}
				Err(e) => last_err = io::Error::new(e.kind(), format!("{addr}: {e}")),
			}
		}
		if let (Some(pool), Some(member)) = (&target.pool, &c.member) {
			pool.failed(&rt.key, member, "connect", &last_err.to_string());
		}
	}
	if full && !tried {
		return Err(crate::core::balance::TargetFull::io());
	}
	Err(last_err)
}

/// The PROXY header (if any) in front of what goes to the backend. `source_ip` is
/// the rule's, or a route's own (#297, `Runtime::source_ip_for`).
async fn send_proxy_header(
	source_ip: SourceIp,
	out: &mut TcpStream,
	client: SocketAddr,
	local: SocketAddr,
	tls: Option<&TlsInfo>,
) -> io::Result<()> {
	match source_ip {
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
	/// The client's country and ASN for `conn.open` (`global.geoip.log_country`).
	geo: Option<crate::net::geoip::Info>,
	/// When the backend connection was made (`outlier_detection.short_lived`).
	connected: Option<Instant>,
	/// Which side ended first; only with `outlier_detection.short_lived`.
	first: Option<Arc<crate::core::outlier::FirstEnd>>,
	/// From a peer outside `proxy_protocol.from` on a rule with `proxy_protocol`, where the
	/// server may speak first: looked at again for a PROXY header once the backend answers.
	untrusted: bool,
}

impl Detail {
	fn country(&self) -> Option<&str> {
		self.geo.as_ref().and_then(|g| g.country_str())
	}

	fn asn(&self) -> Option<u32> {
		self.geo.and_then(|g| g.asn)
	}
}

/// Refusal that is not an error: allow_from or `unmatched: reject`.
fn denied(rt: &Runtime, client: SocketAddr, why: &str, sni: Option<&str>) -> io::Error {
	rt.stats.denied();
	info!(event = "conn.denied", rule = %rt.key, client = %client, reason = why, sni = sni.unwrap_or(""), proxy_peer = peer_field());
	io::Error::new(io::ErrorKind::PermissionDenied, "denied")
}

/// A connection from a front end in `proxy_protocol.from` without a usable PROXY header
/// (none while `required`, a broken or too long one, or too slow).
fn header_refused(rt: &Runtime, peer: SocketAddr, why: &io::Error) {
	rt.stats.denied();
	warn!(event = "conn.denied", rule = %rt.key, client = %peer, reason = "proxy_protocol", error = %why);
}

/// A connection from outside `proxy_protocol.from` that starts like a PROXY header: a
/// front end missing from `from`, or someone claiming another address.
fn untrusted_header(rt: &Runtime, client: SocketAddr, version: proxy_in::Version) -> io::Error {
	rt.stats.denied();
	warn!(event = "conn.denied", rule = %rt.key, client = %client, reason = "proxy_protocol_untrusted", version = version.as_str(),
		"a PROXY header from a peer outside proxy_protocol.from");
	io::Error::new(io::ErrorKind::PermissionDenied, "denied")
}

/// Whether the client sends first on this rule (TLS, HTTP), so its first bytes can be
/// waited for; plain TCP and STARTTLS may have the server speak first.
fn client_speaks_first(rt: &Runtime, tls: &TlsRuntime) -> bool {
	rt.http_router().is_some()
		|| match tls.mode() {
			TlsMode::Sni => true,
			TlsMode::Terminate => tls.starttls.is_none(),
			TlsMode::Passthrough => false,
		}
}

fn is_denied(e: &io::Error) -> bool {
	e.kind() == io::ErrorKind::PermissionDenied && e.to_string() == "denied"
}

/// A connection as accepted from `peer`. With `proxy_protocol` (#296), a front end in
/// `from` sends a PROXY header first and the client is who it names: everything after
/// this (allow_from, geoip, crowdsec, limits, bandwidth, logs, the address passed on to
/// the backend) uses that client, and the front end is the logs' `proxy_peer`.
async fn handle(mut inbound: TcpStream, peer: SocketAddr, rt: Arc<Runtime>, offset: u16) {
	let (client, via, untrusted) = match rt.proxy_protocol() {
		None => (peer, None, false),
		Some(pp) if pp.trusts(peer.ip()) => match tokio::select! {
			_ = rt.kill.cancelled() => return,
			r = proxy_in::read(&mut inbound, pp.required) => r,
		} {
			Ok(Some(client)) => (client, Some(peer), false),
			// LOCAL (the front end's health check), UNKNOWN, or no header while not required
			Ok(None) => (peer, None, false),
			Err(e) => {
				header_refused(&rt, peer, &e);
				return;
			}
		},
		Some(_) => (peer, None, true),
	};
	proxy_in::with_peer(via, handle_client(inbound, client, rt, offset, untrusted)).await
}

async fn handle_client(mut inbound: TcpStream, client: SocketAddr, rt: Arc<Runtime>, offset: u16, untrusted: bool) {
	if !rt.allowed(client.ip()) {
		denied(&rt, client, "allow_from", None);
		return;
	}
	let geo = match rt.geoip_check(client.ip()) {
		Ok(info) => info,
		Err(info) => {
			rt.geoip_denied(client, &info, None, false);
			return;
		}
	};
	if rt.crowdsec_blocks(client.ip()) {
		denied(&rt, client, "crowdsec", None);
		return;
	}
	// every target full (#341): refused before it counts as a connection or spends anything of
	// `limits`; with `tls.routes`, the route's targets are looked at when connecting
	if rt.pool().all_full() && rt.routes.read().unwrap().is_empty() {
		crate::core::limits::refused(&rt, client, crate::core::limits::Reason::TargetFull, "tcp");
		return;
	}
	// `limits` (#165): held until the connection ends (also through `handle_http`)
	let _permit = match rt.limits.get().map(|l| l.admit(client.ip())) {
		None => None,
		Some(Ok(permit)) => Some(permit),
		Some(Err(reason)) => {
			// closed at once, nothing sent
			crate::core::limits::refused(&rt, client, reason, "tcp");
			return;
		}
	};
	let tls = rt.tls();
	// `proxy_protocol`: a peer outside `from` must not send a header (#296)
	let speaks_first = client_speaks_first(&rt, &tls);
	if untrusted {
		let start = tokio::select! {
			_ = rt.kill.cancelled() => return,
			s = proxy_in::untrusted_start(&inbound, speaks_first) => s,
		};
		if let Some(version) = start {
			untrusted_header(&rt, client, version);
			return;
		}
	}
	// a `terminate` rule with passthrough routes reads the ClientHello first:
	// passthrough names are relayed as they are, the others are terminated
	// from the bytes already read
	let mut prefix = Vec::new();
	let mut pass = None;
	if tls.mode() == TlsMode::Terminate && tls.starttls.is_none() && rt.has_passthrough() {
		match crate::tls::sni::read_client_hello(&mut inbound).await {
			Ok((name, hello)) => match rt.select(name.as_deref(), offset) {
				Some(target) if target.passthrough => pass = Some((name, hello, target)),
				// no match with `unmatched: reject` is refused by the TLS handshake below
				_ => prefix = hello,
			},
			Err(e) => {
				rt.stats.tls_failed();
				warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e, proxy_peer = peer_field(), "reading the ClientHello");
				return;
			}
		}
	}
	if pass.is_none() && rt.http_router().is_some() {
		return handle_http(inbound, prefix, client, rt, offset).await;
	}
	let started = Instant::now();
	rt.stats.opened();
	let short_lived = !rt.pool().outlier().short_lived.is_zero();
	let mut detail = Detail {
		geo: rt.geo_for_log(client.ip(), geo),
		first: short_lived.then(Arc::default),
		untrusted: untrusted && !speaks_first,
		..Default::default()
	};

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
	// `outlier_detection.short_lived`: a connection the target ended too soon is a failure
	if let (Some(lease), Some(at), Some(first)) = (&detail.lease, detail.connected, &detail.first) {
		let pool = rt.pool();
		if pool.contains(lease.member()) {
			pool.ended(&rt.key, lease.member(), at.elapsed(), first.backend());
		}
	}
	let elapsed_ms = started.elapsed().as_millis() as u64;
	let info = detail.tls.unwrap_or_default();
	let target = detail.target.map(|t| t.to_string()).unwrap_or_default();
	if matches!(&result, Err(e) if !is_denied(e) && !TargetFull::is(e)) {
		// the relay failed (a side reset, or could not be written): end the client's
		// connection with a reset too, not a clean close it would take for a complete one
		reset_on_close(&inbound);
	}
	match result {
		Err(e) if is_denied(&e) => {}
		// closed with nothing sent to it, as `limits` refuses; not a connection (as when refused before `opened`)
		Err(e) if TargetFull::is(&e) => {
			rt.stats.total.fetch_sub(1, Ordering::Relaxed);
			crate::core::limits::refused(&rt, client, crate::core::limits::Reason::TargetFull, "tcp");
		}
		Ok(()) => info!(event = "conn.close", rule = %rt.key, client = %client, target = %target,
			rx_bytes = detail.rx, tx_bytes = detail.tx, duration_ms = elapsed_ms, reason = detail.reason,
			sni = info.server_name.as_deref().unwrap_or(""), client_cn = info.client_cn.as_deref().unwrap_or(""), proxy_peer = peer_field()),
		Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, target = %target,
			error = %e, duration_ms = elapsed_ms, sni = info.server_name.as_deref().unwrap_or(""), proxy_peer = peer_field()),
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
			// by now (a round trip to the backend) a front end's header would have arrived
			if detail.untrusted {
				if let Some(version) = proxy_in::untrusted_start(inbound, false).await {
					return Err(untrusted_header(rt, client, version));
				}
			}
			detail.target = Some(addr);
			detail.lease = lease;
			detail.connected = Some(Instant::now());
			info!(event = "conn.open", rule = %rt.key, listen = %local, client = %client, target = %addr, country = detail.country(), asn = detail.asn(),
				proxy_peer = peer_field());
			send_proxy_header(rt.source_ip, &mut out, client, local, None).await?;
			finish_plain(rt, client, inbound, &mut out, detail).await
		}
		TlsMode::Sni => {
			let (name, hello) = crate::tls::sni::read_client_hello(inbound).await.inspect_err(|_| rt.stats.tls_failed())?;
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
	detail.connected = Some(Instant::now());
	detail.tls = Some(TlsInfo { server_name: name.clone(), ..Default::default() });
	info!(event = "conn.open", rule = %rt.key, listen = %local, client = %client, target = %addr, sni = name.as_deref().unwrap_or(""), passthrough,
		country = detail.country(), asn = detail.asn(), proxy_peer = peer_field());
	send_proxy_header(rt.source_ip_for(target), &mut out, client, local, None).await?;
	out.write_all(&hello).await?;
	detail.rx += hello.len() as u64;
	rt.stats.add_rx(hello.len() as u64);
	finish_plain(rt, client, inbound, &mut out, detail).await
}

/// `finish` for two plain TCP sockets (nothing terminated in between): a
/// direction that carries a bulk transfer moves on to splice(2) (#184,
/// `l4::splice`) while the rule has no `bandwidth` limit.
async fn finish_plain(rt: &Runtime, client: SocketAddr, a: &mut TcpStream, b: &mut TcpStream, detail: &mut Detail) -> io::Result<()> {
	#[cfg(target_os = "linux")]
	if crate::l4::splice::settings().enabled {
		let (rx, tx) = (AtomicU64::new(0), AtomicU64::new(0));
		let totals = crate::l4::splice::Totals { rx: &rx, tx: &tx, rx_total: &rt.stats.rx_bytes, tx_total: &rt.stats.tx_bytes };
		let first = detail.first.clone();
		let result = crate::l4::splice::relay(a, b, totals, &rt.bandwidth, client.ip(), first.as_deref()).await;
		detail.rx += rx.into_inner();
		detail.tx += tx.into_inner();
		if result.is_err() {
			reset_on_close(b);
		}
		result?;
		detail.reason = "closed";
		return Ok(());
	}
	let backend = b.as_raw_fd();
	finish(rt, client, a, b, backend, PLAIN, detail).await
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

/// Relays until both sides close. `a` is the client side, `b` the backend, whose
/// socket is `b_fd`. A clean close (FIN) of one side is passed on as a half-close;
/// when the relay fails (a side reset, or could not be written), the backend's
/// connection is reset (RST) rather than closed cleanly, so it does not take a
/// cut-off stream for a complete one (the client's is reset by `handle`).
/// `reads` is how much is read at a time from `a` and from `b`
/// (`relay::TLS_READ_SIZE` for TLS streams). Reads wait for the rule's
/// `bandwidth` (`Shaped`; nothing but a relaxed load per read without one).
async fn finish<A: AsyncRead + AsyncWrite + Unpin + ?Sized, B: AsyncRead + AsyncWrite + Unpin + ?Sized>(
	rt: &Runtime,
	client_addr: SocketAddr,
	a: &mut A,
	b: &mut B,
	b_fd: RawFd,
	reads: (usize, usize),
	detail: &mut Detail,
) -> io::Result<()> {
	use crate::core::bandwidth::{Dir, Gate, Shaped};
	let ip = client_addr.ip();
	let first = detail.first.clone();
	let mut a = crate::core::outlier::Watched::new(a, first.as_deref(), false);
	let mut b = crate::core::outlier::Watched::new(b, first.as_deref(), true);
	let mut client = Shaped::new(Counted::new(&mut a, &rt.stats.rx_bytes), &rt.bandwidth, Gate::new(ip, Dir::Up));
	let mut backend = Shaped::new(Counted::new(&mut b, &rt.stats.tx_bytes), &rt.bandwidth, Gate::new(ip, Dir::Down));
	let result = relay::bidirectional_reading(&mut client, &mut backend, reads.0, reads.1).await;
	detail.rx += client.into_inner().count;
	detail.tx += backend.into_inner().count;
	if result.is_err() {
		// SAFETY: `b` (which owns `b_fd`) is borrowed for this whole call, so the fd is open
		reset_on_close(&unsafe { BorrowedFd::borrow_raw(b_fd) });
	}
	result?;
	detail.reason = "closed";
	Ok(())
}

/// Makes closing the socket reset the connection (RST, SO_LINGER 0) instead of
/// closing it cleanly (FIN).
fn reset_on_close(socket: &impl AsFd) {
	let _ = socket2::SockRef::from(socket).set_linger(Some(Duration::ZERO));
}

/// TLS handshake of a `terminate` rule. The ClientHello is read first so
/// unmatched names are refused before any certificate is sent.
async fn accept_tls<S: AsyncRead + AsyncWrite + Unpin>(
	stream: S,
	client: SocketAddr,
	rt: &Runtime,
	offset: u16,
	config: Arc<rustls::ServerConfig>,
	limit: Option<Duration>,
) -> io::Result<(tokio_rustls::server::TlsStream<S>, TlsInfo)> {
	let handshake = async {
		let start = tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream).await?;
		let name = start.client_hello().server_name().map(str::to_string);
		// an ACME CA validating TLS-ALPN-01 (global.acme): answer with the challenge certificate, then close
		if let Some(acme) = crate::acme::challenge::tls_alpn_config(&start.client_hello()) {
			let mut session = start.into_stream(acme).await?;
			let _ = tokio::io::AsyncWriteExt::shutdown(&mut session).await;
			info!(event = "acme.answer", challenge = "tls-alpn-01", rule = %rt.key, client = %client, sni = name.as_deref().unwrap_or(""),
				proxy_peer = peer_field());
			return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
		}
		if rt.select(name.as_deref(), offset).is_none() {
			return Err(denied(rt, client, "unmatched", name.as_deref()));
		}
		start.into_stream(config).await
	};
	// `http` rules: global.http.timeouts.tls_handshake (#320, 0s is no limit)
	let session = match limit {
		Some(limit) => tokio::time::timeout(limit, handshake).await.unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))),
		None => handshake.await,
	}
	.inspect_err(|e| {
		if !is_denied(e) {
			rt.stats.tls_failed()
		}
	})?;

	let (_, conn) = session.get_ref();
	let chain = conn.peer_certificates().unwrap_or(&[]);
	let info = TlsInfo {
		server_name: conn.server_name().map(str::to_string),
		alpn: conn.alpn_protocol().map(|p| String::from_utf8_lossy(p).into_owned()),
		version: conn.protocol_version().map(|v| format!("{v:?}")),
		cipher: conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())),
		..Default::default()
	}
	.with_client(chain, rt.tls().client_verified(chain));
	Ok((session, info))
}

/// A connection of an `http` rule: TLS (for `terminate`), then HTTP requests
/// routed one by one (src/l7/server.rs).
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
				let limit = rt.global.timeouts().tls_handshake;
				let (session, i) = accept_tls(Prefixed::new(prefix, inbound), client, &rt, offset, config, limit).await?;
				info = Some(i.clone());
				let stream = Metered::new(session, rt.clone(), client.ip(), rx.clone(), tx.clone());
				http::serve(stream, client, local, rt.clone(), Some(i), rx.clone()).await
			}
			(TlsMode::Terminate, None) => Err(io::Error::other("TLS is not configured")),
			_ => {
				let stream = Metered::new(inbound, rt.clone(), client.ip(), rx.clone(), tx.clone());
				http::serve(stream, client, local, rt.clone(), None, rx.clone()).await
			}
		}
	};
	let result = tokio::select! {
		_ = rt.kill.cancelled() => Ok("stopped"),
		r = serving => r,
	};
	rt.stats.closed();
	let elapsed_ms = started.elapsed().as_millis() as u64;
	let info = info.unwrap_or_default();
	match result {
		Err(e) if is_denied(&e) => {}
		Ok(reason) => info!(event = "conn.close", rule = %rt.key, client = %client, target = "http",
			rx_bytes = rx.load(Ordering::Relaxed), tx_bytes = tx.load(Ordering::Relaxed), duration_ms = elapsed_ms, reason,
			sni = info.server_name.as_deref().unwrap_or(""), client_cn = info.client_cn.as_deref().unwrap_or(""), proxy_peer = peer_field()),
		Err(e) => warn!(event = "conn.error", rule = %rt.key, client = %client, target = "http",
			error = %e, duration_ms = elapsed_ms, sni = info.server_name.as_deref().unwrap_or(""), proxy_peer = peer_field()),
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

	let (mut session, info) = accept_tls(Prefixed::new(prefix, &mut *inbound), client, rt, offset, config, Some(HANDSHAKE_TIMEOUT)).await?;
	let target = rt
		.select(info.server_name.as_deref(), offset)
		.ok_or_else(|| denied(rt, client, "unmatched", info.server_name.as_deref()))?;
	let Connected { stream: mut out, addr, host, lease } = connect(rt, client, &target).await?;
	detail.target = Some(addr);
	detail.lease = lease;
	detail.connected = Some(Instant::now());
	info!(event = "conn.open", rule = %rt.key, listen = %local, client = %client, target = %addr,
		sni = info.server_name.as_deref().unwrap_or(""), alpn = info.alpn.as_deref().unwrap_or(""),
		tls_version = info.version.as_deref().unwrap_or(""), tls_cipher = info.cipher.as_deref().unwrap_or(""),
		client_cn = info.client_cn.as_deref().unwrap_or(""), client_verify = info.client_verify(), starttls = tls.starttls.map(|p| p.as_str()).unwrap_or(""),
		country = detail.country(), asn = detail.asn(), proxy_peer = peer_field());
	send_proxy_header(rt.source_ip, &mut out, client, local, Some(&info)).await?;
	detail.tls = Some(info);

	let backend = out.as_raw_fd();
	// the route's own upstream (tls.routes[].upstream), else the rule's
	let reach = tls.upstream_for(target.route, &host).map_err(|e| io::Error::other(e.message))?;
	let encrypted = reach.is_some();
	let mut upstream: Box<dyn Stream> = match reach {
		Some((connector, name)) => {
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
	let upstream_read = if encrypted { relay::TLS_READ_SIZE } else { relay::BUFFER_SIZE };
	finish(rt, client, &mut session, &mut upstream, backend, (relay::TLS_READ_SIZE, upstream_read), detail).await
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
	detail.connected = Some(Instant::now());
	info!(event = "conn.open", rule = %rt.key, listen = %local, client = %client, target = %addr, starttls = "smtp", tls = "none",
		country = detail.country(), asn = detail.asn(), proxy_peer = peer_field());
	send_proxy_header(rt.source_ip, &mut out, client, local, None).await?;
	let extra = starttls::skip_greeting(StartTls::Smtp, &mut out).await?;
	let after = starttls::replay_plain(&mut out, ehlo.as_deref(), &pending).await?;
	inbound.write_all(&extra).await?;
	inbound.write_all(&after).await?;
	let backend = out.as_raw_fd();
	finish(rt, client, inbound, &mut out, backend, PLAIN, detail).await
}
