//! Time limits of client connections of `http` rules (#320 M1, `global.http.timeouts`):
//! the TLS handshake, the first byte, the first request's headers, connections
//! without requests (HTTP/2, HTTP/3; HTTP/1.1 waits for the next request with
//! `request_headers`), HTTP/2 PING, and the time between two reads of a request body.
//! A long upload or download is never cut for its length, only for silence.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use serde::{Deserialize, Serialize};
use tokio::time::{Instant, Sleep};

use super::server::BoxError;

/// `global.http` (v0.4.17).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpGlobalSpec {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub timeouts: Option<HttpTimeoutsSpec>,
}

/// `global.http.timeouts`: durations like `10s`; `0s` is no limit. Left out, the default.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpTimeoutsSpec {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub tls_handshake: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub first_byte: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub request_headers: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub idle: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub request_body_idle: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub http2_ping_interval: Option<String>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub http2_ping_timeout: Option<String>,
}

/// The limits in force; `None` is no limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpTimeouts {
	/// TLS handshake of `terminate` (and QUIC's).
	pub tls_handshake: Option<Duration>,
	/// From the connection (after TLS) to the first byte of a request.
	pub first_byte: Option<Duration>,
	/// From the connection to the first request's complete headers; on HTTP/1.1 also each
	/// later request's headers, counted from the end of the response before (keep-alive).
	pub request_headers: Option<Duration>,
	/// A connection with no request in progress (HTTP/2, HTTP/3) is closed after this.
	pub idle: Option<Duration>,
	/// Silence between two reads of a request body (not the whole upload).
	pub request_body_idle: Option<Duration>,
	/// HTTP/2 PING every this much without reads, and how long its answer may take.
	pub http2_ping_interval: Option<Duration>,
	pub http2_ping_timeout: Duration,
}

impl Default for HttpTimeouts {
	fn default() -> Self {
		HttpTimeouts {
			tls_handshake: Some(Duration::from_secs(10)),
			first_byte: Some(Duration::from_secs(10)),
			request_headers: Some(Duration::from_secs(30)),
			idle: Some(Duration::from_secs(180)),
			request_body_idle: Some(Duration::from_secs(60)),
			http2_ping_interval: Some(Duration::from_secs(60)),
			http2_ping_timeout: Duration::from_secs(20),
		}
	}
}

impl HttpTimeoutsSpec {
	fn fields(&self) -> [(&'static str, &Option<String>); 7] {
		[
			("tls_handshake", &self.tls_handshake),
			("first_byte", &self.first_byte),
			("request_headers", &self.request_headers),
			("idle", &self.idle),
			("request_body_idle", &self.request_body_idle),
			("http2_ping_interval", &self.http2_ping_interval),
			("http2_ping_timeout", &self.http2_ping_timeout),
		]
	}

	/// The values are durations; `http2_ping_timeout` is not `0s`.
	pub fn check(&self) -> Result<(), String> {
		for (name, v) in self.fields() {
			if let Some(v) = v {
				let d = super::parse_duration(v).map_err(|e| format!("global.http.timeouts.{name}: {e}"))?;
				if name == "http2_ping_timeout" && d.is_zero() {
					return Err("global.http.timeouts.http2_ping_timeout: 0s is not a time to wait".into());
				}
			}
		}
		Ok(())
	}

	/// The limits, with the defaults for what is left out (`check` has passed).
	pub fn resolve(&self) -> HttpTimeouts {
		let d = HttpTimeouts::default();
		let get = |v: &Option<String>, default: Option<Duration>| match v {
			Some(v) => super::parse_duration(v).ok().filter(|d| !d.is_zero()),
			None => default,
		};
		HttpTimeouts {
			tls_handshake: get(&self.tls_handshake, d.tls_handshake),
			first_byte: get(&self.first_byte, d.first_byte),
			request_headers: get(&self.request_headers, d.request_headers),
			idle: get(&self.idle, d.idle),
			request_body_idle: get(&self.request_body_idle, d.request_body_idle),
			http2_ping_interval: get(&self.http2_ping_interval, d.http2_ping_interval),
			http2_ping_timeout: get(&self.http2_ping_timeout, Some(d.http2_ping_timeout)).unwrap_or(d.http2_ping_timeout),
		}
	}
}

impl HttpGlobalSpec {
	pub fn check(&self) -> Result<(), String> {
		self.timeouts.as_ref().map_or(Ok(()), HttpTimeoutsSpec::check)
	}

	pub fn timeouts(&self) -> HttpTimeouts {
		self.timeouts.as_ref().map(HttpTimeoutsSpec::resolve).unwrap_or_default()
	}
}

/// Requests of one client connection: how many began, how many are in progress, and
/// when the last one ended (for `idle`).
pub struct Activity {
	started: Instant,
	begun: AtomicU64,
	in_progress: AtomicUsize,
	/// Milliseconds from `started` to the end of the last request.
	quiet_from: AtomicU64,
}

impl Activity {
	pub fn new() -> Arc<Activity> {
		Arc::new(Activity {
			started: Instant::now(),
			begun: AtomicU64::new(0),
			in_progress: AtomicUsize::new(0),
			quiet_from: AtomicU64::new(0),
		})
	}

	/// A request began (its headers are in); it is in progress until the guard drops
	/// (with the response body).
	pub fn begin(self: &Arc<Self>) -> Busy {
		self.begun.fetch_add(1, Ordering::Relaxed);
		self.in_progress.fetch_add(1, Ordering::AcqRel);
		Busy(self.clone())
	}

	fn begun(&self) -> u64 {
		self.begun.load(Ordering::Relaxed)
	}

	/// Whether a request is in progress.
	pub fn in_progress(&self) -> bool {
		self.in_progress.load(Ordering::Acquire) != 0
	}

	/// Since when nothing is in progress; None while a request is.
	fn quiet_since(&self) -> Option<Instant> {
		if self.in_progress.load(Ordering::Acquire) != 0 {
			return None;
		}
		Some(self.started + Duration::from_millis(self.quiet_from.load(Ordering::Relaxed)))
	}

	/// Returns when the connection is to be closed, with the reason (`conn.close`):
	/// `first_byte_timeout` (`rx` still 0), `request_headers_timeout` (no request
	/// yet) or `idle`. Never returns when every limit is off.
	pub async fn expired(&self, rx: &AtomicU64, t: &HttpTimeouts) -> &'static str {
		loop {
			let now = Instant::now();
			let first = self.begun() == 0;
			let mut next: Option<Instant> = None;
			let mut wake = |at: Instant| next = Some(next.map_or(at, |n| n.min(at)));
			if first {
				if let Some(d) = t.first_byte.filter(|_| rx.load(Ordering::Relaxed) == 0) {
					if now >= self.started + d {
						return "first_byte_timeout";
					}
					wake(self.started + d);
				}
				if let Some(d) = t.request_headers {
					if now >= self.started + d {
						return "request_headers_timeout";
					}
					wake(self.started + d);
				}
			}
			if let Some(idle) = t.idle {
				match self.quiet_since() {
					Some(since) if now >= since + idle => return "idle",
					Some(since) => wake(since + idle),
					None => wake(now + idle),
				}
			}
			match next {
				Some(at) => tokio::time::sleep_until(at).await,
				None => return std::future::pending().await,
			}
		}
	}

	/// For HTTP/3: when no request has been in progress for `idle`.
	pub async fn idle(&self, idle: Duration) {
		loop {
			match self.quiet_since() {
				Some(since) if Instant::now() >= since + idle => return,
				Some(since) => tokio::time::sleep_until(since + idle).await,
				None => tokio::time::sleep(idle).await,
			}
		}
	}
}

/// A request in progress (see `Activity::begin`).
pub struct Busy(Arc<Activity>);

impl Drop for Busy {
	fn drop(&mut self) {
		let a = &self.0;
		a.quiet_from.store(a.started.elapsed().as_millis() as u64, Ordering::Relaxed);
		a.in_progress.fetch_sub(1, Ordering::AcqRel);
	}
}

/// A response body that keeps its request in progress until it ends or is dropped.
pub struct Tracked<B> {
	inner: B,
	_busy: Busy,
}

impl<B> Tracked<B> {
	pub fn new(inner: B, busy: Busy) -> Self {
		Tracked { inner, _busy: busy }
	}
}

impl<B: Body + Unpin> Body for Tracked<B> {
	type Data = B::Data;
	type Error = B::Error;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<B::Data>, B::Error>>> {
		Pin::new(&mut self.inner).poll_frame(cx)
	}

	fn is_end_stream(&self) -> bool {
		self.inner.is_end_stream()
	}

	fn size_hint(&self) -> SizeHint {
		self.inner.size_hint()
	}
}

#[derive(Debug)]
struct BodyTimedOut;

impl std::fmt::Display for BodyTimedOut {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("request body timed out (request_body_idle)")
	}
}

impl std::error::Error for BodyTimedOut {}

/// The error of a request body the client went silent on.
pub fn body_timed_out() -> BoxError {
	BoxError::new(BodyTimedOut)
}

/// A gRPC request (`content-type: application/grpc…`): its streams may stay quiet for
/// as long as they like (etcd Watch, xDS), so `request_body_idle` does not apply.
pub fn is_grpc(headers: &hyper::HeaderMap) -> bool {
	headers
		.get(hyper::header::CONTENT_TYPE)
		.is_some_and(|v| v.as_bytes().len() >= 16 && v.as_bytes()[..16].eq_ignore_ascii_case(b"application/grpc"))
}

/// Set when the response head of a request goes out: from then on its body may be one
/// direction of a bidirectional exchange, and `request_body_idle` no longer applies.
#[derive(Clone, Default)]
pub struct Responded(Arc<std::sync::atomic::AtomicBool>);

impl Responded {
	pub fn set(&self) {
		self.0.store(true, Ordering::Release);
	}

	pub fn get(&self) -> bool {
		self.0.load(Ordering::Acquire)
	}
}

/// A request body that ends with an error when the client sends nothing for `limit`
/// while it is being read, until the response head has gone out (`responded`). The
/// timer is made only when a read has to wait.
pub struct IdleBody<B> {
	inner: B,
	limit: Option<Duration>,
	responded: Option<Responded>,
	timer: Option<Pin<Box<Sleep>>>,
	/// The timer runs for the read in progress.
	armed: bool,
	failed: bool,
}

impl<B> IdleBody<B> {
	/// Without `responded` there is no limit.
	pub fn new(inner: B, limit: Option<Duration>, responded: Option<Responded>) -> Self {
		IdleBody {
			inner,
			limit: limit.filter(|_| responded.is_some()),
			responded,
			timer: None,
			armed: false,
			failed: false,
		}
	}
}

impl<B> Body for IdleBody<B>
where
	B: Body<Data = Bytes> + Unpin,
	B::Error: std::error::Error + Send + Sync + 'static,
{
	type Data = Bytes;
	type Error = BoxError;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
		let this = &mut *self;
		if this.failed {
			return Poll::Ready(None);
		}
		match Pin::new(&mut this.inner).poll_frame(cx) {
			Poll::Ready(frame) => {
				this.armed = false;
				Poll::Ready(frame.map(|f| f.map_err(BoxError::new)))
			}
			Poll::Pending => {
				let Some(limit) = this.limit else { return Poll::Pending };
				if !this.armed {
					let at = Instant::now() + limit;
					match &mut this.timer {
						Some(t) => t.as_mut().reset(at),
						None => this.timer = Some(Box::pin(tokio::time::sleep_until(at))),
					}
					this.armed = true;
				}
				match this.timer.as_mut().map(|t| t.as_mut().poll(cx)) {
					// the response is under way: the exchange is bidirectional, wait as long as it takes
					Some(Poll::Ready(())) if this.responded.as_ref().is_some_and(Responded::get) => {
						this.limit = None;
						this.timer = None;
						Poll::Pending
					}
					Some(Poll::Ready(())) => {
						this.failed = true;
						Poll::Ready(Some(Err(body_timed_out())))
					}
					_ => Poll::Pending,
				}
			}
		}
	}

	fn is_end_stream(&self) -> bool {
		!self.failed && self.inner.is_end_stream()
	}

	fn size_hint(&self) -> SizeHint {
		self.inner.size_hint()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use http_body_util::BodyExt;

	#[test]
	fn defaults_and_settings() {
		assert_eq!(HttpGlobalSpec::default().timeouts(), HttpTimeouts::default());
		let spec = HttpTimeoutsSpec {
			idle: Some("0s".into()),
			request_body_idle: Some("5m".into()),
			..Default::default()
		};
		spec.check().unwrap();
		let t = spec.resolve();
		assert_eq!(t.idle, None);
		assert_eq!(t.request_body_idle, Some(Duration::from_secs(300)));
		assert_eq!(t.first_byte, Some(Duration::from_secs(10)));
		assert!(HttpTimeoutsSpec {
			first_byte: Some("soon".into()),
			..Default::default()
		}
		.check()
		.is_err());
		assert!(HttpTimeoutsSpec {
			http2_ping_timeout: Some("0s".into()),
			..Default::default()
		}
		.check()
		.is_err());
	}

	const MS: fn(u64) -> Duration = Duration::from_millis;

	#[tokio::test]
	async fn a_silent_body_times_out_but_a_slow_one_does_not() {
		let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(1);
		let inner = http_body_util::StreamBody::new(futures_util::stream::unfold(rx, |mut rx| async move {
			rx.recv().await.map(|f| (f, rx))
		}));
		let mut body = IdleBody::new(Box::pin(inner), Some(MS(300)), Some(Responded::default()));
		for _ in 0..4 {
			let tx = tx.clone();
			tokio::spawn(async move {
				tokio::time::sleep(MS(150)).await;
				let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"x")))).await;
			});
			assert!(body.frame().await.unwrap().is_ok());
		}
		let err = body.frame().await.unwrap().unwrap_err();
		assert!(err.to_string().contains("request_body_idle"));
		assert!(body.frame().await.is_none());
	}

	#[tokio::test]
	async fn no_limit_once_the_response_is_under_way() {
		let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(1);
		let inner = http_body_util::StreamBody::new(futures_util::stream::unfold(rx, |mut rx| async move {
			rx.recv().await.map(|f| (f, rx))
		}));
		let responded = Responded::default();
		let mut body = IdleBody::new(Box::pin(inner), Some(MS(100)), Some(responded.clone()));
		responded.set();
		tokio::spawn(async move {
			tokio::time::sleep(MS(400)).await;
			let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"x")))).await;
		});
		assert!(body.frame().await.unwrap().is_ok());
		let mut grpc = hyper::HeaderMap::new();
		grpc.insert(
			hyper::header::CONTENT_TYPE,
			hyper::header::HeaderValue::from_static("application/grpc+proto"),
		);
		assert!(is_grpc(&grpc));
		grpc.insert(
			hyper::header::CONTENT_TYPE,
			hyper::header::HeaderValue::from_static("application/json"),
		);
		assert!(!is_grpc(&grpc));
	}

	#[tokio::test]
	async fn idle_counts_from_the_end_of_the_last_request() {
		let a = Activity::new();
		let rx = AtomicU64::new(1);
		let t = HttpTimeouts {
			first_byte: None,
			request_headers: None,
			idle: Some(MS(100)),
			..HttpTimeouts::default()
		};
		let busy = a.begin();
		let watch = a.expired(&rx, &t);
		tokio::pin!(watch);
		assert!(tokio::time::timeout(MS(300), watch.as_mut()).await.is_err());
		drop(busy);
		let started = std::time::Instant::now();
		assert_eq!(watch.await, "idle");
		assert!(started.elapsed() >= MS(90));
	}

	#[tokio::test]
	async fn first_byte_and_headers() {
		let t = HttpTimeouts {
			first_byte: Some(MS(50)),
			request_headers: Some(MS(100)),
			..HttpTimeouts::default()
		};
		let a = Activity::new();
		assert_eq!(a.expired(&AtomicU64::new(0), &t).await, "first_byte_timeout");
		let a = Activity::new();
		assert_eq!(a.expired(&AtomicU64::new(3), &t).await, "request_headers_timeout");
		// a request began in time: only `idle` is left
		let a = Activity::new();
		let busy = a.begin();
		assert!(tokio::time::timeout(MS(300), a.expired(&AtomicU64::new(3), &t)).await.is_err());
		drop(busy);
	}
}
