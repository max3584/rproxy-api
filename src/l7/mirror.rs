//! Request mirroring (#232, the Gateway API's RequestMirror): the request body is
//! copied as it streams to the mirrors (`tee`). A mirror that falls behind is cut
//! off (its body ends with an error); the request to the backend never waits.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body as _, Frame};
use hyper::header::HeaderMap;
use hyper::{Method, Uri};
use tokio::sync::mpsc;

use super::backend::Service;
use super::server::{Body, BoxError};

/// Frames a mirror may be behind before it is cut off.
pub const QUEUE: usize = 64;

/// A copy to send: the request as it was at the `mirror` middleware.
pub struct Copy {
	pub name: String,
	pub service: Arc<Service>,
	pub method: Method,
	pub uri: Uri,
	pub headers: HeaderMap,
}

enum Item {
	Frame(Frame<Bytes>),
	End,
}

/// `body` for the backend, and one body per mirror that gets the same frames.
pub fn tee(body: Body, mirrors: usize) -> (Body, Vec<Body>) {
	if body.is_end_stream() {
		return (body, (0..mirrors).map(|_| empty()).collect());
	}
	let mut txs = vec![];
	let mut bodies = vec![];
	for _ in 0..mirrors {
		let (tx, rx) = mpsc::channel(QUEUE);
		txs.push(Some(tx));
		bodies.push(Copied { rx, done: false }.boxed());
	}
	(Tee { inner: body, txs }.boxed(), bodies)
}

fn empty() -> Body {
	http_body_util::Empty::<Bytes>::new().map_err(|never| match never {}).boxed()
}

struct Tee {
	inner: Body,
	txs: Vec<Option<mpsc::Sender<Item>>>,
}

impl Tee {
	fn send(&mut self, item: impl Fn() -> Item) {
		for slot in &mut self.txs {
			if let Some(tx) = slot {
				// full or gone: that mirror is cut off (its body sees the channel close without End)
				if tx.try_send(item()).is_err() {
					*slot = None;
				}
			}
		}
	}
}

impl hyper::body::Body for Tee {
	type Data = Bytes;
	type Error = BoxError;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
		let poll = Pin::new(&mut self.inner).poll_frame(cx);
		match &poll {
			Poll::Ready(Some(Ok(frame))) => {
				if let Some(data) = frame.data_ref() {
					let data = data.clone();
					self.send(|| Item::Frame(Frame::data(data.clone())));
				} else if let Some(trailers) = frame.trailers_ref() {
					let trailers = trailers.clone();
					self.send(|| Item::Frame(Frame::trailers(trailers.clone())));
				}
				if self.inner.is_end_stream() {
					self.send(|| Item::End);
					self.txs.clear();
				}
			}
			Poll::Ready(None) => {
				self.send(|| Item::End);
				self.txs.clear();
			}
			// the client's body broke off: the mirrors' break off too
			Poll::Ready(Some(Err(_))) => self.txs.clear(),
			Poll::Pending => {}
		}
		poll
	}

	fn is_end_stream(&self) -> bool {
		self.inner.is_end_stream()
	}

	fn size_hint(&self) -> hyper::body::SizeHint {
		self.inner.size_hint()
	}
}

#[derive(Debug)]
struct Behind;

impl std::fmt::Display for Behind {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("the mirror fell behind or the request body broke off")
	}
}

impl std::error::Error for Behind {}

struct Copied {
	rx: mpsc::Receiver<Item>,
	done: bool,
}

impl hyper::body::Body for Copied {
	type Data = Bytes;
	type Error = BoxError;

	fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
		if self.done {
			return Poll::Ready(None);
		}
		match self.rx.poll_recv(cx) {
			Poll::Ready(Some(Item::Frame(f))) => Poll::Ready(Some(Ok(f))),
			Poll::Ready(Some(Item::End)) => {
				self.done = true;
				Poll::Ready(None)
			}
			Poll::Ready(None) => {
				self.done = true;
				Poll::Ready(Some(Err(BoxError::new(Behind))))
			}
			Poll::Pending => Poll::Pending,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use http_body_util::{Full, StreamBody};

	#[tokio::test]
	async fn copies_and_falls_behind() {
		let body = Full::new(Bytes::from_static(b"hello")).map_err(|never| match never {}).boxed();
		let (main, mut copies) = tee(body, 2);
		assert_eq!(main.collect().await.unwrap().to_bytes(), "hello");
		for c in copies.drain(..) {
			assert_eq!(c.collect().await.unwrap().to_bytes(), "hello");
		}

		// a streamed body larger than the queue, with a mirror nobody reads until the end
		let chunks: Vec<Result<Frame<Bytes>, BoxError>> = (0..QUEUE + 10).map(|_| Ok(Frame::data(Bytes::from_static(b"x")))).collect();
		let body = StreamBody::new(futures_util::stream::iter(chunks)).boxed();
		let (main, copies) = tee(body, 1);
		assert_eq!(main.collect().await.unwrap().to_bytes().len(), QUEUE + 10, "the backend's body never waits");
		let err = copies.into_iter().next().unwrap().collect().await.unwrap_err();
		assert!(err.to_string().contains("fell behind"));
	}
}
