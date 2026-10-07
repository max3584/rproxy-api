//! Time limits of a route (#227, the Gateway API's `timeouts.request` and
//! `backendRequest`): a response body that has not ended by the deadline ends
//! with an error, so the client sees it cut off (HTTP/1.1 closes the
//! connection, HTTP/2 RST_STREAM, HTTP/3 a reset), never as complete.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame};
use tokio::time::{Instant, Sleep};

use super::server::{Body, BoxError};

/// A duration of a route's `timeouts`; `0s` is no limit.
pub fn limit(d: Option<&String>) -> Option<Duration> {
	d.and_then(|d| super::parse_duration(d).ok()).filter(|d| !d.is_zero())
}

#[derive(Debug)]
struct TimedOut(&'static str);

impl std::fmt::Display for TimedOut {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(self.0)
	}
}

impl std::error::Error for TimedOut {}

/// `body`, cut off with an error at `at`.
pub fn until(body: Body, at: Instant, what: &'static str) -> Body {
	if body.is_end_stream() {
		return body;
	}
	Deadline { inner: body, sleep: Box::pin(tokio::time::sleep_until(at)), what, done: false }.boxed()
}

struct Deadline {
	inner: Body,
	sleep: Pin<Box<Sleep>>,
	what: &'static str,
	done: bool,
}

impl hyper::body::Body for Deadline {
	type Data = Bytes;
	type Error = BoxError;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
		if self.done {
			return Poll::Ready(None);
		}
		if let Poll::Ready(frame) = Pin::new(&mut self.inner).poll_frame(cx) {
			return Poll::Ready(frame);
		}
		match self.sleep.as_mut().poll(cx) {
			Poll::Ready(()) => {
				self.done = true;
				Poll::Ready(Some(Err(BoxError::new(TimedOut(self.what)))))
			}
			Poll::Pending => Poll::Pending,
		}
	}

	fn is_end_stream(&self) -> bool {
		!self.done && self.inner.is_end_stream()
	}

	fn size_hint(&self) -> hyper::body::SizeHint {
		self.inner.size_hint()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn a_late_body_ends_with_an_error() {
		let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, BoxError>>(1);
		let body = http_body_util::StreamBody::new(tokio_stream_from(rx)).boxed();
		tx.try_send(Ok(Frame::data(Bytes::from_static(b"a")))).unwrap();
		let mut b = until(body, Instant::now() + Duration::from_millis(50), "request timed out");
		let first = b.frame().await.unwrap().unwrap();
		assert_eq!(first.into_data().unwrap(), "a");
		let err = b.frame().await.unwrap().unwrap_err();
		assert_eq!(err.to_string(), "request timed out");
		assert!(b.frame().await.is_none());
		drop(tx);
		assert_eq!(limit(Some(&"0s".to_string())), None);
		assert_eq!(limit(Some(&"2s".to_string())), Some(Duration::from_secs(2)));
	}

	fn tokio_stream_from(
		mut rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
	) -> impl futures_util::Stream<Item = Result<Frame<Bytes>, BoxError>> {
		futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))
	}
}
