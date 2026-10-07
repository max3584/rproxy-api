//! HTTP for ACME: the client instant-acme talks to the CA through, and calls to
//! DNS provider APIs. One HTTP/1.1 connection per request, rustls with ring,
//! the web PKI roots or a `ca_file` (no platform verifier, no extra TLS stack).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use rustls::pki_types::ServerName;

const TIMEOUT: Duration = Duration::from_secs(30);
/// Responses larger than this are refused (certificate chains are a few KiB).
const MAX_BODY: usize = 1 << 20;

trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}

/// TLS settings towards a CA or DNS API: the web PKI roots, or `ca_file`.
pub fn connector(ca_file: Option<&str>) -> Result<tokio_rustls::TlsConnector, String> {
	let up = crate::tls::config::Upstream { ca_file: ca_file.map(str::to_string), ..Default::default() };
	let config = crate::tls::config::client_config(&up).map_err(|e| e.message)?;
	let mut config = (*config).clone();
	config.alpn_protocols = vec![b"http/1.1".to_vec()];
	Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// Sends one request; the URI must be absolute.
pub async fn send(tls: &tokio_rustls::TlsConnector, req: Request<Bytes>) -> Result<Response<Bytes>, String> {
	let (mut parts, body) = req.into_parts();
	let uri = parts.uri.clone();
	let authority = uri.authority().ok_or_else(|| format!("{uri}: no host"))?.clone();
	let https = match uri.scheme_str() {
		Some("https") => true,
		Some("http") => false,
		_ => return Err(format!("{uri}: not an http(s) URL")),
	};
	let host = authority.host().trim_matches(|c| c == '[' || c == ']').to_string();
	let port = authority.port_u16().unwrap_or(if https { 443 } else { 80 });
	let work = async {
		let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| format!("{authority}: {e}"))?;
		crate::net::source::nodelay(&tcp);
		let stream: Box<dyn Stream> = if https {
			let name = ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
			Box::new(tls.connect(name, tcp).await.map_err(|e| format!("{authority}: TLS: {e}"))?)
		} else {
			Box::new(tcp)
		};
		let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream))
			.await
			.map_err(|e| e.to_string())?;
		tokio::spawn(conn);
		parts.uri = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/").parse::<Uri>().map_err(|e| e.to_string())?;
		parts.headers.insert(header::HOST, HeaderValue::from_str(authority.as_str()).map_err(|e| e.to_string())?);
		parts
			.headers
			.entry(header::USER_AGENT)
			.or_insert(HeaderValue::from_static(concat!("rproxy-api/", env!("CARGO_PKG_VERSION"))));
		let resp = sender.send_request(Request::from_parts(parts, Full::new(body))).await.map_err(|e| e.to_string())?;
		let (parts, body) = resp.into_parts();
		let limited = http_body_util::Limited::new(body, MAX_BODY);
		let bytes = limited.collect().await.map_err(|e| e.to_string())?.to_bytes();
		Ok::<_, String>(Response::from_parts(parts, bytes))
	};
	tokio::time::timeout(TIMEOUT, work).await.map_err(|_| format!("{authority}: timed out"))?
}

/// The HTTP client instant-acme uses.
pub struct AcmeHttp {
	tls: tokio_rustls::TlsConnector,
}

impl AcmeHttp {
	pub fn new(ca_file: Option<&str>) -> Result<AcmeHttp, String> {
		Ok(AcmeHttp { tls: connector(ca_file)? })
	}
}

#[derive(Debug)]
struct Failed(String);

impl std::fmt::Display for Failed {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for Failed {}

impl HttpClient for AcmeHttp {
	fn request(
		&self,
		req: Request<BodyWrapper<Bytes>>,
	) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
		let tls = self.tls.clone();
		Box::pin(async move {
			let (parts, body) = req.into_parts();
			let body = match body.collect().await {
				Ok(b) => b.to_bytes(),
				Err(never) => match never {},
			};
			let resp = send(&tls, Request::from_parts(parts, body)).await.map_err(|e| instant_acme::Error::Other(Box::new(Failed(e))))?;
			let (parts, body) = resp.into_parts();
			Ok(BytesResponse::from(Response::from_parts(parts, Full::new(body))))
		})
	}
}
