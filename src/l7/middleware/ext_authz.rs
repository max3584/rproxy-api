//! Envoy's ext_authz v3 gRPC protocol for `forward_auth` with `protocol: grpc`
//! (v0.4.3, the Gateway API's `ExternalAuth` filter with `protocol: GRPC`):
//! `envoy.service.auth.v3.Authorization/Check`. Only the messages and fields
//! rproxy sends and reads are encoded here, by hand (no protobuf code generator):
//!
//! - `CheckRequest.attributes` (`AttributeContext`): `source` / `destination`
//!   (`Peer.address.socket_address`), `request.time`, `request.http`
//!   (`id`, `method`, `headers`, `path` with the query, `host`, `scheme`, `size`,
//!   `protocol`, `body` / `raw_body`).
//! - `CheckResponse`: `status.code`, `denied_response` (`status.code`, `headers`,
//!   `body`), `ok_response` (`headers`, `headers_to_remove`, `response_headers_to_add`).
//!
//! Unknown fields of the response are skipped, as protobuf requires.

use std::net::SocketAddr;

use bytes::{BufMut, Bytes, BytesMut};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};

/// The method path of the Check call.
pub const CHECK_PATH: &str = "/envoy.service.auth.v3.Authorization/Check";

/// Largest Check response read (a denied response carries a body).
pub const MAX_RESPONSE: usize = 1024 * 1024;

fn varint(out: &mut BytesMut, mut v: u64) {
	while v >= 0x80 {
		out.put_u8((v as u8) | 0x80);
		v >>= 7;
	}
	out.put_u8(v as u8);
}

fn key(out: &mut BytesMut, field: u32, wire: u8) {
	varint(out, (u64::from(field) << 3) | u64::from(wire));
}

fn bytes_field(out: &mut BytesMut, field: u32, data: &[u8]) {
	key(out, field, 2);
	varint(out, data.len() as u64);
	out.put_slice(data);
}

fn string_field(out: &mut BytesMut, field: u32, s: &str) {
	if !s.is_empty() {
		bytes_field(out, field, s.as_bytes());
	}
}

fn uint_field(out: &mut BytesMut, field: u32, v: u64) {
	if v != 0 {
		key(out, field, 0);
		varint(out, v);
	}
}

fn message(out: &mut BytesMut, field: u32, build: impl FnOnce(&mut BytesMut)) {
	let mut inner = BytesMut::new();
	build(&mut inner);
	bytes_field(out, field, &inner);
}

/// `Peer { address: Address { socket_address: SocketAddress { address, port_value } } }`
fn peer(out: &mut BytesMut, field: u32, addr: SocketAddr) {
	message(out, field, |p| {
		message(p, 1, |a| {
			message(a, 1, |s| {
				string_field(s, 2, &addr.ip().to_string());
				uint_field(s, 3, u64::from(addr.port()));
			})
		})
	});
}

/// What the Check request says of the client's request.
pub struct Attributes<'a> {
	pub source: SocketAddr,
	pub destination: SocketAddr,
	pub id: &'a str,
	pub method: &'a str,
	/// Lower-case names; values of a name repeated are joined with `,` (as Envoy does).
	pub headers: &'a [(String, String)],
	/// Path and query.
	pub path: &'a str,
	pub host: &'a str,
	pub scheme: &'a str,
	/// `HTTP/1.1`, `HTTP/2` or `HTTP/3`.
	pub protocol: &'a str,
	/// The body forwarded (`forward_body`), if any.
	pub body: Option<&'a [u8]>,
	/// The body's size: its length when known, -1 otherwise.
	pub size: i64,
	pub time: std::time::SystemTime,
}

/// A `CheckRequest`, framed for gRPC (no compression).
pub fn check_request(a: &Attributes) -> Bytes {
	let mut msg = BytesMut::new();
	message(&mut msg, 1, |ctx| {
		peer(ctx, 1, a.source);
		peer(ctx, 2, a.destination);
		message(ctx, 4, |req| {
			let since = a.time.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
			message(req, 1, |t| {
				uint_field(t, 1, since.as_secs());
				uint_field(t, 2, u64::from(since.subsec_nanos()));
			});
			message(req, 2, |http| {
				string_field(http, 1, a.id);
				string_field(http, 2, a.method);
				for (k, v) in a.headers {
					message(http, 3, |e| {
						string_field(e, 1, k);
						string_field(e, 2, v);
					});
				}
				string_field(http, 4, a.path);
				string_field(http, 5, a.host);
				string_field(http, 6, a.scheme);
				// int64: -1 is ten bytes of varint
				key(http, 9, 0);
				varint(http, a.size as u64);
				string_field(http, 10, a.protocol);
				if let Some(body) = a.body {
					match std::str::from_utf8(body) {
						Ok(text) => string_field(http, 11, text),
						Err(_) => bytes_field(http, 12, body),
					}
				}
			});
		});
	});
	let mut framed = BytesMut::with_capacity(msg.len() + 5);
	framed.put_u8(0);
	framed.put_u32(msg.len() as u32);
	framed.put_slice(&msg);
	framed.freeze()
}

/// A header to set on the request (or response) from the auth server's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderOption {
	pub name: HeaderName,
	pub value: HeaderValue,
	pub action: Action,
}

/// What to do with a header of `HeaderValueOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
	/// Add another field (`append: true`, `APPEND_IF_EXISTS_OR_ADD`).
	Append,
	/// Only when there is none (`ADD_IF_ABSENT`).
	AddIfAbsent,
	/// Replace (`append: false` and, in these messages, an unset `append`; `OVERWRITE_IF_EXISTS_OR_ADD`).
	Overwrite,
	/// Replace only an existing one (`OVERWRITE_IF_EXISTS`).
	OverwriteIfExists,
}

impl HeaderOption {
	pub fn apply(&self, headers: &mut HeaderMap) {
		match self.action {
			Action::Append => {
				headers.append(self.name.clone(), self.value.clone());
			}
			Action::AddIfAbsent => {
				if !headers.contains_key(&self.name) {
					headers.insert(self.name.clone(), self.value.clone());
				}
			}
			Action::Overwrite => {
				headers.insert(self.name.clone(), self.value.clone());
			}
			Action::OverwriteIfExists => {
				if headers.contains_key(&self.name) {
					headers.insert(self.name.clone(), self.value.clone());
				}
			}
		}
	}
}

/// The auth server's answer.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CheckResponse {
	/// `status.code` (google.rpc.Code; 0 is OK).
	pub code: i32,
	/// `denied_response.status.code` (an HTTP status; 0 when not given).
	pub denied_status: u16,
	pub denied_headers: Vec<HeaderOption>,
	pub denied_body: Bytes,
	pub ok_headers: Vec<HeaderOption>,
	pub ok_remove: Vec<HeaderName>,
	pub ok_response_headers: Vec<HeaderOption>,
}

struct Reader<'a> {
	data: &'a [u8],
}

enum Value<'a> {
	Varint(u64),
	Len(&'a [u8]),
	Other,
}

impl<'a> Reader<'a> {
	fn varint(&mut self) -> Result<u64, String> {
		let mut v = 0u64;
		for i in 0..10 {
			let (&b, rest) = self.data.split_first().ok_or("truncated varint")?;
			self.data = rest;
			v |= u64::from(b & 0x7f) << (7 * i);
			if b & 0x80 == 0 {
				return Ok(v);
			}
		}
		Err("varint too long".into())
	}

	fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
		if self.data.len() < n {
			return Err("truncated field".into());
		}
		let (head, rest) = self.data.split_at(n);
		self.data = rest;
		Ok(head)
	}

	/// The next field: (number, value); None at the end.
	fn next(&mut self) -> Result<Option<(u32, Value<'a>)>, String> {
		if self.data.is_empty() {
			return Ok(None);
		}
		let k = self.varint()?;
		let field = u32::try_from(k >> 3).map_err(|_| "bad field number")?;
		let value = match k & 7 {
			0 => Value::Varint(self.varint()?),
			1 => {
				self.take(8)?;
				Value::Other
			}
			2 => {
				let n = usize::try_from(self.varint()?).map_err(|_| "bad length")?;
				Value::Len(self.take(n)?)
			}
			5 => {
				self.take(4)?;
				Value::Other
			}
			w => return Err(format!("unsupported wire type {w}")),
		};
		Ok(Some((field, value)))
	}
}

fn fields(data: &[u8], mut each: impl FnMut(u32, Value) -> Result<(), String>) -> Result<(), String> {
	let mut r = Reader { data };
	while let Some((f, v)) = r.next()? {
		each(f, v)?;
	}
	Ok(())
}

/// `HeaderValueOption { header: HeaderValue { key, value, raw_value }, append: BoolValue, append_action }`.
/// None for a header that is not a valid HTTP header (skipped, as Envoy does).
fn header_option(data: &[u8]) -> Result<Option<HeaderOption>, String> {
	let (mut name, mut value, mut append, mut action) = (Vec::new(), Vec::new(), None, 0u64);
	fields(data, |f, v| {
		match (f, v) {
			(1, Value::Len(h)) => fields(h, |f, v| {
				match (f, v) {
					(1, Value::Len(k)) => name = k.to_vec(),
					(2, Value::Len(x)) | (3, Value::Len(x)) => value = x.to_vec(),
					_ => {}
				}
				Ok(())
			})?,
			(2, Value::Len(b)) => {
				let mut set = false;
				fields(b, |f, v| {
					if let (1, Value::Varint(x)) = (f, v) {
						set = x != 0;
					}
					Ok(())
				})?;
				append = Some(set);
			}
			(3, Value::Varint(a)) => action = a,
			_ => {}
		}
		Ok(())
	})?;
	let action = match (append, action) {
		(Some(true), _) => Action::Append,
		(Some(false), _) => Action::Overwrite,
		(None, 1) => Action::AddIfAbsent,
		(None, 3) => Action::OverwriteIfExists,
		// unset `append` in ext_authz's ok / denied responses means replace
		(None, _) => Action::Overwrite,
	};
	match (HeaderName::from_bytes(&name), HeaderValue::from_bytes(&value)) {
		(Ok(name), Ok(value)) => Ok(Some(HeaderOption { name, value, action })),
		_ => Ok(None),
	}
}

/// Decodes one gRPC message of the Check call's response body.
pub fn check_response(body: &[u8]) -> Result<CheckResponse, String> {
	if body.len() < 5 {
		return Err("no gRPC message in the response".into());
	}
	if body[0] != 0 {
		return Err("a compressed gRPC message".into());
	}
	let n = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
	let msg = body.get(5..5 + n).ok_or("a truncated gRPC message")?;
	let mut out = CheckResponse::default();
	fields(msg, |f, v| {
		match (f, v) {
			(1, Value::Len(status)) => fields(status, |f, v| {
				if let (1, Value::Varint(c)) = (f, v) {
					out.code = c as i32;
				}
				Ok(())
			})?,
			(2, Value::Len(denied)) => fields(denied, |f, v| {
				match (f, v) {
					(1, Value::Len(st)) => fields(st, |f, v| {
						if let (1, Value::Varint(c)) = (f, v) {
							out.denied_status = u16::try_from(c).unwrap_or(0);
						}
						Ok(())
					})?,
					(2, Value::Len(h)) => out.denied_headers.extend(header_option(h)?),
					(3, Value::Len(b)) => out.denied_body = Bytes::copy_from_slice(b),
					_ => {}
				}
				Ok(())
			})?,
			(3, Value::Len(ok)) => fields(ok, |f, v| {
				match (f, v) {
					(2, Value::Len(h)) => out.ok_headers.extend(header_option(h)?),
					(5, Value::Len(n)) => {
						if let Ok(n) = HeaderName::from_bytes(n) {
							out.ok_remove.push(n);
						}
					}
					(6, Value::Len(h)) => out.ok_response_headers.extend(header_option(h)?),
					_ => {}
				}
				Ok(())
			})?,
			_ => {}
		}
		Ok(())
	})?;
	Ok(out)
}

/// Builders of Check responses for tests (an auth server in Rust without protobuf code).
pub mod encode {
	use super::*;

	pub fn header(name: &str, value: &str, append: Option<bool>) -> Vec<u8> {
		let mut out = BytesMut::new();
		message(&mut out, 1, |h| {
			string_field(h, 1, name);
			string_field(h, 2, value);
		});
		if let Some(a) = append {
			message(&mut out, 2, |b| uint_field(b, 1, u64::from(a)));
		}
		out.to_vec()
	}

	/// An OK answer with headers for the request (`ok_response.headers`), headers to remove
	/// and headers for the client's response.
	pub fn ok(headers: &[Vec<u8>], remove: &[&str], response: &[Vec<u8>]) -> Bytes {
		let mut msg = BytesMut::new();
		message(&mut msg, 1, |_| {});
		message(&mut msg, 3, |ok| {
			for h in headers {
				bytes_field(ok, 2, h);
			}
			for r in remove {
				string_field(ok, 5, r);
			}
			for h in response {
				bytes_field(ok, 6, h);
			}
		});
		frame(&msg)
	}

	/// A denial (`status.code` 7, PERMISSION_DENIED) with an HTTP status, headers and a body.
	pub fn denied(status: u16, headers: &[Vec<u8>], body: &str) -> Bytes {
		let mut msg = BytesMut::new();
		message(&mut msg, 1, |s| uint_field(s, 1, 7));
		message(&mut msg, 2, |d| {
			if status != 0 {
				message(d, 1, |st| uint_field(st, 1, u64::from(status)));
			}
			for h in headers {
				bytes_field(d, 2, h);
			}
			string_field(d, 3, body);
		});
		frame(&msg)
	}

	fn frame(msg: &[u8]) -> Bytes {
		let mut framed = BytesMut::new();
		framed.put_u8(0);
		framed.put_u32(msg.len() as u32);
		framed.put_slice(msg);
		framed.freeze()
	}

	/// What a Check request says (for tests).
	#[derive(Clone, Debug, Default)]
	pub struct Seen {
		pub method: String,
		pub path: String,
		pub host: String,
		pub headers: Vec<(String, String)>,
		pub body: Vec<u8>,
	}

	pub fn read_request(body: &[u8]) -> Result<Seen, String> {
		let msg = body.get(5..).ok_or("short")?;
		let (mut method, mut path, mut host, mut headers, mut data) = (String::new(), String::new(), String::new(), vec![], vec![]);
		let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
		fields(msg, |f, v| {
			if let (1, Value::Len(ctx)) = (f, v) {
				fields(ctx, |f, v| {
					if let (4, Value::Len(req)) = (f, v) {
						fields(req, |f, v| {
							if let (2, Value::Len(http)) = (f, v) {
								fields(http, |f, v| {
									match (f, v) {
										(2, Value::Len(x)) => method = text(x),
										(3, Value::Len(e)) => {
											let (mut k, mut val) = (String::new(), String::new());
											fields(e, |f, v| {
												match (f, v) {
													(1, Value::Len(x)) => k = text(x),
													(2, Value::Len(x)) => val = text(x),
													_ => {}
												}
												Ok(())
											})?;
											headers.push((k, val));
										}
										(4, Value::Len(x)) => path = text(x),
										(5, Value::Len(x)) => host = text(x),
										(11, Value::Len(x)) | (12, Value::Len(x)) => data = x.to_vec(),
										_ => {}
									}
									Ok(())
								})?;
							}
							Ok(())
						})?;
					}
					Ok(())
				})?;
			}
			Ok(())
		})?;
		Ok(Seen { method, path, host, headers, body: data })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn requests_and_responses_round_trip() {
		let headers = vec![("authorization".to_string(), "Bearer x".to_string()), ("x-a".to_string(), "1,2".to_string())];
		let a = Attributes {
			source: "10.0.0.1:5555".parse().unwrap(),
			destination: "10.0.0.2:443".parse().unwrap(),
			id: "abc",
			method: "POST",
			headers: &headers,
			path: "/p?q=1",
			host: "app.example",
			scheme: "https",
			protocol: "HTTP/2",
			body: Some(b"hello"),
			size: 5,
			time: std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
		};
		let req = check_request(&a);
		assert_eq!(req[0], 0);
		assert_eq!(u32::from_be_bytes([req[1], req[2], req[3], req[4]]) as usize, req.len() - 5);
		let seen = encode::read_request(&req).unwrap();
		assert_eq!((seen.method.as_str(), seen.path.as_str(), seen.host.as_str(), seen.body.as_slice()), ("POST", "/p?q=1", "app.example", &b"hello"[..]));
		assert_eq!(seen.headers, headers);
		// a body that is not UTF-8 goes as raw_body
		let raw = check_request(&Attributes { body: Some(&[0xff, 0x00]), size: -1, ..a });
		assert_eq!(encode::read_request(&raw).unwrap().body, [0xff, 0x00]);

		let ok = encode::ok(&[encode::header("x-user", "alice", None), encode::header("x-add", "2", Some(true))], &["x-drop"], &[
			encode::header("x-resp", "r", None),
		]);
		let r = check_response(&ok).unwrap();
		assert_eq!(r.code, 0);
		assert_eq!(r.ok_headers.len(), 2);
		assert_eq!((r.ok_headers[0].action, r.ok_headers[1].action), (Action::Overwrite, Action::Append));
		assert_eq!(r.ok_remove, [HeaderName::from_static("x-drop")]);
		assert_eq!(r.ok_response_headers[0].value, "r");
		let mut h = HeaderMap::new();
		h.insert("x-user", HeaderValue::from_static("forged"));
		h.insert("x-add", HeaderValue::from_static("1"));
		for o in &r.ok_headers {
			o.apply(&mut h);
		}
		assert_eq!(h["x-user"], "alice");
		assert_eq!(h.get_all("x-add").iter().collect::<Vec<_>>(), ["1", "2"]);

		let denied = check_response(&encode::denied(401, &[encode::header("www-authenticate", "Bearer", None)], "go away")).unwrap();
		assert_eq!((denied.code, denied.denied_status, &denied.denied_body[..]), (7, 401, &b"go away"[..]));
		assert_eq!(denied.denied_headers[0].name, "www-authenticate");
		assert!(check_response(&[0, 0, 0, 0, 9, 1]).is_err(), "truncated");
		assert!(check_response(&[1, 0, 0, 0, 0]).is_err(), "compressed");
		assert_eq!(check_response(&[0, 0, 0, 0, 0]).unwrap(), CheckResponse::default(), "empty: OK without changes");
	}
}
