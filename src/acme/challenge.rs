//! Answers to HTTP-01 and TLS-ALPN-01 challenges while an order is open,
//! shared by every listener of the process: `http` rules answer
//! `/.well-known/acme-challenge/<token>` before routing (src/l7/server.rs),
//! `terminate` rules answer a ClientHello that offers only `acme-tls/1`
//! (src/l4/tcp.rs), and `global.acme.http01_listen` is a responder for HTTP-01
//! alone.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// The ALPN protocol of TLS-ALPN-01 (RFC 8737).
pub const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
pub const HTTP_PREFIX: &str = "/.well-known/acme-challenge/";

#[derive(Default)]
struct Pending {
	/// tls-alpn-01: server name → certificate with the acmeIdentifier extension.
	tls_alpn: HashMap<String, Arc<CertifiedKey>>,
	/// http-01: token → key authorization.
	http: HashMap<String, String>,
}

fn pending() -> &'static RwLock<Pending> {
	static PENDING: OnceLock<RwLock<Pending>> = OnceLock::new();
	PENDING.get_or_init(Default::default)
}

/// The HTTP-01 answer for a request path, while that challenge is open.
pub fn http_answer(path: &str) -> Option<String> {
	let token = path.strip_prefix(HTTP_PREFIX)?;
	pending().read().ok()?.http.get(token).cloned()
}

/// An HTTP-01 answer as a response (200, text/plain).
pub fn http_response<B: From<Bytes>>(answer: String) -> Response<B> {
	let mut resp = Response::new(B::from(Bytes::from(answer)));
	resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/plain"));
	resp
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
	fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
		Some(self.0.clone())
	}
}

/// The TLS settings that answer an open TLS-ALPN-01 challenge, when the
/// ClientHello offers only `acme-tls/1` (RFC 8737 3.) for a name being validated.
pub fn tls_alpn_config(hello: &rustls::server::ClientHello<'_>) -> Option<Arc<rustls::ServerConfig>> {
	let mut alpn = hello.alpn()?;
	if alpn.next() != Some(ACME_TLS_ALPN) || alpn.next().is_some() {
		return None;
	}
	let name = hello.server_name()?.to_ascii_lowercase();
	let key = pending().read().ok()?.tls_alpn.get(&name).cloned()?;
	let provider = Arc::new(rustls::crypto::ring::default_provider());
	let mut config = rustls::ServerConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
		.ok()?
		.with_no_client_auth()
		.with_cert_resolver(Arc::new(Fixed(key)));
	config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
	Some(Arc::new(config))
}

/// A self-signed certificate for `names`, with the acmeIdentifier extension
/// for TLS-ALPN-01, or as the stand-in a rule serves until its certificate is issued.
pub fn self_signed(names: &[String], acme_digest: Option<&[u8]>) -> Result<(Vec<u8>, Vec<u8>), String> {
	let mut params = rcgen::CertificateParams::new(names.to_vec()).map_err(|e| e.to_string())?;
	let mut dn = rcgen::DistinguishedName::new();
	dn.push(rcgen::DnType::CommonName, "rproxy ACME placeholder");
	params.distinguished_name = dn;
	if let Some(digest) = acme_digest {
		params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest)];
	}
	let key = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
	let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
	Ok((cert.der().to_vec(), key.serialize_der()))
}

fn certified(cert: Vec<u8>, key: Vec<u8>) -> Result<Arc<CertifiedKey>, String> {
	let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key));
	let signing = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| e.to_string())?;
	Ok(Arc::new(CertifiedKey::new(vec![CertificateDer::from(cert)], signing)))
}

/// Answers of one order; withdrawn when it is dropped, however the order ends.
#[derive(Default)]
pub struct Answers {
	tls_alpn: Vec<String>,
	http: Vec<String>,
}

impl Answers {
	pub fn add_http(&mut self, token: &str, key_authorization: &str) {
		if let Ok(mut p) = pending().write() {
			p.http.insert(token.to_string(), key_authorization.to_string());
			self.http.push(token.to_string());
		}
	}

	pub fn add_tls_alpn(&mut self, name: &str, digest: &[u8]) -> Result<(), String> {
		let (cert, key) = self_signed(&[name.to_string()], Some(digest))?;
		let key = certified(cert, key)?;
		let name = name.to_ascii_lowercase();
		if let Ok(mut p) = pending().write() {
			p.tls_alpn.insert(name.clone(), key);
			self.tls_alpn.push(name);
		}
		Ok(())
	}
}

impl Drop for Answers {
	fn drop(&mut self) {
		if let Ok(mut p) = pending().write() {
			for n in &self.tls_alpn {
				p.tls_alpn.remove(n);
			}
			for t in &self.http {
				p.http.remove(t);
			}
		}
	}
}

/// The `global.acme.http01_listen` responders of the process, by address (#345): one
/// set whatever `Acme` is in force, so that a change of `global.acme` keeps the
/// listeners it still names (answers are shared by every listener anyway).
fn http01_serving() -> &'static Mutex<HashMap<SocketAddr, CancellationToken>> {
	static SERVING: OnceLock<Mutex<HashMap<SocketAddr, CancellationToken>>> = OnceLock::new();
	SERVING.get_or_init(Default::default)
}

/// The addresses HTTP-01 is answered on now.
pub fn http01_addrs() -> Vec<SocketAddr> {
	let mut out: Vec<SocketAddr> = http01_serving().lock().unwrap_or_else(|e| e.into_inner()).keys().copied().collect();
	out.sort();
	out
}

/// Listeners bound for a change of `http01_listen`, not serving yet (closed when dropped).
#[derive(Default)]
pub struct Bound(Vec<(SocketAddr, tokio::net::TcpListener)>);

/// Binds the addresses of `addrs` that are not served yet (a live upgrade hands the old
/// process's socket over, #174). Returns them and the addresses that could not be bound.
pub async fn bind_http01(addrs: &[SocketAddr]) -> (Bound, Vec<(SocketAddr, String)>) {
	let serving = http01_addrs();
	let mut bound = Bound::default();
	let mut failed = vec![];
	for addr in addrs.iter().filter(|a| !serving.contains(a)) {
		let listener = match crate::control::upgrade::inherit::take_tcp(*addr) {
			Some(l) => l.set_nonblocking(true).and_then(|()| tokio::net::TcpListener::from_std(l)),
			None => tokio::net::TcpListener::bind(addr).await,
		};
		match listener {
			Ok(l) => bound.0.push((*addr, l)),
			Err(e) => failed.push((*addr, e.to_string())),
		}
	}
	(bound, failed)
}

/// Makes `addrs` the responders: those no longer named stop, the ones of `bound` start,
/// the others go on as they are.
pub fn install_http01(addrs: &[SocketAddr], bound: Bound) {
	let mut serving = http01_serving().lock().unwrap_or_else(|e| e.into_inner());
	serving.retain(|addr, stop| {
		let keep = addrs.contains(addr);
		if !keep {
			stop.cancel();
			info!(event = "acme.listening", addr = %addr, action = "stop");
		}
		keep
	});
	for (addr, listener) in bound.0 {
		let stop = CancellationToken::new();
		if let Some(old) = serving.insert(addr, stop.clone()) {
			old.cancel();
		}
		info!(event = "acme.listening", addr = %addr);
		tokio::spawn(serve_http01(listener, stop));
	}
}

/// `bind_http01` and `install_http01`: returns the addresses that could not be bound.
pub async fn set_http01(addrs: &[SocketAddr]) -> Vec<(SocketAddr, String)> {
	let (bound, failed) = bind_http01(addrs).await;
	install_http01(addrs, bound);
	failed
}

/// `global.acme.http01_listen`: answers HTTP-01 challenges, 404 for anything else.
async fn serve_http01(listener: tokio::net::TcpListener, stop: CancellationToken) {
	loop {
		let (stream, client) = tokio::select! {
			_ = stop.cancelled() => return,
			r = listener.accept() => match r {
				Ok(v) => v,
				Err(e) => {
					warn!(event = "acme.error", part = "http01_listen", error = %e);
					tokio::time::sleep(std::time::Duration::from_millis(100)).await;
					continue;
				}
			},
		};
		crate::net::source::nodelay(&stream);
		let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| async move {
			let resp = match http_answer(req.uri().path()) {
				Some(answer) => {
					debug!(event = "acme.answer", challenge = "http-01", client = %client, path = req.uri().path());
					http_response::<Full<Bytes>>(answer)
				}
				None => {
					let mut r = Response::new(Full::new(Bytes::new()));
					*r.status_mut() = StatusCode::NOT_FOUND;
					r
				}
			};
			Ok::<_, std::convert::Infallible>(resp)
		});
		tokio::spawn(async move {
			let conn = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), service);
			let _ = tokio::time::timeout(std::time::Duration::from_secs(30), conn).await;
		});
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn answers_are_withdrawn_when_the_order_ends() {
		let mut a = Answers::default();
		a.add_http("tok-unit-1", "tok-unit-1.thumb");
		a.add_tls_alpn("Alpn-Unit.example", &[0; 32]).unwrap();
		assert_eq!(http_answer("/.well-known/acme-challenge/tok-unit-1").as_deref(), Some("tok-unit-1.thumb"));
		assert!(http_answer("/tok-unit-1").is_none());
		assert!(pending().read().unwrap().tls_alpn.contains_key("alpn-unit.example"));
		drop(a);
		assert!(http_answer("/.well-known/acme-challenge/tok-unit-1").is_none());
		assert!(!pending().read().unwrap().tls_alpn.contains_key("alpn-unit.example"));
	}
}
