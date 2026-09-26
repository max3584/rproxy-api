//! The `compress` middleware (#63): responses compressed with br, zstd or gzip as
//! the client accepts, while they stream (each chunk is flushed, so server-sent
//! and long responses are not held back).

use std::io::{self, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Frame;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};
use tracing::warn;

use super::server::Body;

/// Responses smaller than this (by Content-Length) are sent as they are.
pub const DEFAULT_MIN_SIZE: u64 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
	Br,
	Zstd,
	Gzip,
}

impl Encoding {
	pub fn parse(s: &str) -> Option<Encoding> {
		match s.trim().to_ascii_lowercase().as_str() {
			"br" => Some(Encoding::Br),
			"zstd" => Some(Encoding::Zstd),
			"gzip" => Some(Encoding::Gzip),
			_ => None,
		}
	}

	fn as_str(self) -> &'static str {
		match self {
			Encoding::Br => "br",
			Encoding::Zstd => "zstd",
			Encoding::Gzip => "gzip",
		}
	}
}

/// The encodings a `compress` middleware offers, in the order it prefers them
/// (default br, zstd, gzip).
pub fn encodings(list: &[String]) -> Result<Vec<Encoding>, String> {
	if list.is_empty() {
		return Ok(vec![Encoding::Br, Encoding::Zstd, Encoding::Gzip]);
	}
	list.iter().map(|e| Encoding::parse(e).ok_or_else(|| format!("encoding {e:?} must be br, zstd or gzip"))).collect()
}

/// The encoding to use for a request's `Accept-Encoding`: the highest q value
/// the client gives among `offered`, ties by the order of `offered`.
pub fn negotiate(accept: &str, offered: &[Encoding]) -> Option<Encoding> {
	let mut best: Option<(f32, usize)> = None;
	let mut wildcard: Option<f32> = None;
	let mut named = vec![];
	for item in accept.split(',') {
		let mut parts = item.split(';');
		let name = parts.next().unwrap_or("").trim().to_ascii_lowercase();
		let q = parts
			.filter_map(|p| p.trim().strip_prefix("q=").and_then(|v| v.trim().parse::<f32>().ok()))
			.next()
			.unwrap_or(1.0);
		if name == "*" {
			wildcard = Some(q);
		} else if let Some(e) = Encoding::parse(&name) {
			named.push((e, q));
		}
	}
	for (i, e) in offered.iter().enumerate() {
		let q = named.iter().find(|(n, _)| n == e).map(|(_, q)| *q).or(wildcard).unwrap_or(0.0);
		if q > 0.0 && best.is_none_or(|(bq, _)| q > bq) {
			best = Some((q, i));
		}
	}
	best.map(|(_, i)| offered[i])
}

/// Content types that are already compressed or must not be buffered.
fn incompressible(content_type: &str) -> bool {
	let t = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
	(t.starts_with("image/") && t != "image/svg+xml")
		|| t.starts_with("video/")
		|| t.starts_with("audio/")
		|| t.starts_with("font/woff")
		|| t.starts_with("application/grpc")
		|| matches!(
			t.as_str(),
			"application/zip"
				| "application/gzip"
				| "application/x-gzip"
				| "application/zstd"
				| "application/x-bzip2"
				| "application/x-xz"
				| "application/x-7z-compressed"
				| "application/x-rar-compressed"
				| "application/pdf"
				| "text/event-stream"
		)
}

/// Whether a response may be compressed.
pub fn compressible(status: StatusCode, headers: &HeaderMap, min_size: u64, head: bool) -> bool {
	if head || status.is_informational() || matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED | StatusCode::PARTIAL_CONTENT) {
		return false;
	}
	if headers.contains_key(header::CONTENT_ENCODING) || headers.contains_key(header::CONTENT_RANGE) {
		return false;
	}
	let text = |n: header::HeaderName| headers.get(n).and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
	if text(header::CACHE_CONTROL).contains("no-transform") || incompressible(&text(header::CONTENT_TYPE)) {
		return false;
	}
	match text(header::CONTENT_LENGTH).parse::<u64>() {
		Ok(len) => len >= min_size,
		// unknown length (streamed): compress
		Err(_) => true,
	}
}

/// Compresses the body of `resp` with `encoding` and fixes its headers.
pub fn compress(resp: Response<Body>, encoding: Encoding) -> Response<Body> {
	let (mut parts, body) = resp.into_parts();
	let h = &mut parts.headers;
	h.remove(header::CONTENT_LENGTH);
	h.insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding.as_str()));
	h.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
	// the bytes differ now; a strong validator would lie
	if let Some(etag) = h.get(header::ETAG).and_then(|v| v.to_str().ok()).filter(|e| !e.starts_with("W/")) {
		if let Ok(weak) = HeaderValue::from_str(&format!("W/{etag}")) {
			h.insert(header::ETAG, weak);
		}
	}
	let encoder = Encoder::new(encoding);
	Response::from_parts(parts, Compressed { inner: body, encoder: Some(encoder), trailers: None }.boxed())
}

enum Encoder {
	Gzip(flate2::write::GzEncoder<Vec<u8>>),
	Br(Box<brotli::CompressorWriter<Vec<u8>>>),
	Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

impl Encoder {
	fn new(e: Encoding) -> Encoder {
		match e {
			Encoding::Gzip => Encoder::Gzip(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(5))),
			Encoding::Br => Encoder::Br(Box::new(brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22))),
			// level 3 is zstd's default; creating the context only fails without memory
			Encoding::Zstd => match zstd::stream::write::Encoder::new(Vec::new(), 3) {
				Ok(z) => Encoder::Zstd(z),
				Err(_) => Encoder::Gzip(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(5))),
			},
		}
	}

	/// Compresses `data` and returns what is ready to send (flushed).
	fn write(&mut self, data: &[u8]) -> io::Result<Bytes> {
		let out = match self {
			Encoder::Gzip(w) => {
				w.write_all(data)?;
				w.flush()?;
				w.get_mut()
			}
			Encoder::Br(w) => {
				w.write_all(data)?;
				w.flush()?;
				w.get_mut()
			}
			Encoder::Zstd(w) => {
				w.write_all(data)?;
				w.flush()?;
				w.get_mut()
			}
		};
		Ok(Bytes::from(std::mem::take(out)))
	}

	fn finish(self) -> io::Result<Bytes> {
		Ok(Bytes::from(match self {
			Encoder::Gzip(w) => w.finish()?,
			Encoder::Br(w) => w.into_inner(),
			Encoder::Zstd(w) => w.finish()?,
		}))
	}
}

struct Compressed {
	inner: Body,
	/// None once the stream has ended.
	encoder: Option<Encoder>,
	/// Trailers of the original body, sent after the last compressed bytes.
	trailers: Option<HeaderMap>,
}

impl hyper::body::Body for Compressed {
	type Data = Bytes;
	type Error = super::server::BoxError;

	fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, super::server::BoxError>>> {
		let this = self.get_mut();
		loop {
			let Some(encoder) = this.encoder.as_mut() else {
				return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
			};
			let frame = match Pin::new(&mut this.inner).poll_frame(cx) {
				Poll::Pending => return Poll::Pending,
				Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
				Poll::Ready(Some(Ok(frame))) => frame,
				Poll::Ready(None) => {
					let done = this.encoder.take().map(Encoder::finish);
					return match done {
						Some(Ok(rest)) if !rest.is_empty() => Poll::Ready(Some(Ok(Frame::data(rest)))),
						Some(Err(e)) => {
							warn!(event = "http.error", error = %e, "compression failed; response cut short");
							Poll::Ready(None)
						}
						_ => Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t)))),
					};
				}
			};
			match frame.into_data() {
				Ok(data) => match encoder.write(&data) {
					Ok(out) if out.is_empty() => continue,
					Ok(out) => return Poll::Ready(Some(Ok(Frame::data(out)))),
					Err(e) => {
						warn!(event = "http.error", error = %e, "compression failed; response cut short");
						this.encoder = None;
						return Poll::Ready(None);
					}
				},
				Err(frame) => {
					if let Ok(t) = frame.into_trailers() {
						this.trailers = Some(t);
					}
				}
			}
		}
	}

	fn is_end_stream(&self) -> bool {
		self.encoder.is_none() && self.trailers.is_none()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io::Read;

	#[test]
	fn negotiation_follows_q_values_then_our_order() {
		let all = encodings(&[]).unwrap();
		assert_eq!(negotiate("gzip, deflate, br, zstd", &all), Some(Encoding::Br));
		assert_eq!(negotiate("gzip;q=1.0, br;q=0.5", &all), Some(Encoding::Gzip));
		assert_eq!(negotiate("identity", &all), None);
		assert_eq!(negotiate("*;q=0.1", &all), Some(Encoding::Br));
		assert_eq!(negotiate("br;q=0, gzip", &all), Some(Encoding::Gzip));
		assert_eq!(negotiate("GZIP", &[Encoding::Zstd]), None);
		assert_eq!(encodings(&["gzip".into(), "deflate".into()]).unwrap_err(), "encoding \"deflate\" must be br, zstd or gzip");
	}

	#[test]
	fn what_is_left_alone() {
		let h = |pairs: &[(&str, &str)]| {
			let mut m = HeaderMap::new();
			for (k, v) in pairs {
				m.insert(header::HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
			}
			m
		};
		let ok = StatusCode::OK;
		assert!(compressible(ok, &h(&[("content-type", "text/html"), ("content-length", "5000")]), 1024, false));
		assert!(compressible(ok, &h(&[("content-type", "application/json")]), 1024, false), "streamed");
		assert!(!compressible(ok, &h(&[("content-type", "text/html"), ("content-length", "100")]), 1024, false), "small");
		assert!(!compressible(ok, &h(&[("content-type", "image/png")]), 0, false));
		assert!(compressible(ok, &h(&[("content-type", "image/svg+xml")]), 0, false));
		assert!(!compressible(ok, &h(&[("content-encoding", "gzip")]), 0, false));
		assert!(!compressible(ok, &h(&[("cache-control", "public, no-transform")]), 0, false));
		assert!(!compressible(ok, &h(&[("content-type", "text/event-stream")]), 0, false));
		assert!(!compressible(StatusCode::NOT_MODIFIED, &h(&[]), 0, false));
		assert!(!compressible(ok, &h(&[]), 0, true), "HEAD");
	}

	#[test]
	fn each_encoder_round_trips_in_chunks() {
		let text = "rproxy compresses this line. ".repeat(200);
		for e in [Encoding::Gzip, Encoding::Br, Encoding::Zstd] {
			let mut enc = Encoder::new(e);
			let mut out = vec![];
			for chunk in text.as_bytes().chunks(700) {
				let part = enc.write(chunk).unwrap();
				assert!(!part.is_empty(), "{e:?}: every chunk is flushed");
				out.extend_from_slice(&part);
			}
			out.extend_from_slice(&enc.finish().unwrap());
			assert!(out.len() < text.len() / 4, "{e:?}: {} bytes", out.len());
			let mut back = String::new();
			match e {
				Encoding::Gzip => flate2::read::GzDecoder::new(&out[..]).read_to_string(&mut back).unwrap(),
				Encoding::Br => brotli::Decompressor::new(&out[..], 4096).read_to_string(&mut back).unwrap(),
				Encoding::Zstd => zstd::stream::read::Decoder::new(&out[..]).unwrap().read_to_string(&mut back).unwrap(),
			};
			assert_eq!(back, text, "{e:?}");
		}
	}
}
