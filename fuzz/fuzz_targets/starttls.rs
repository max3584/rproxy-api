//! The plain-text part of SMTP / IMAP / POP3 before STARTTLS (`l4::starttls`):
//! rproxy's side of the dialogue with the client, the mail server's greeting and
//! EHLO reply after TLS, and the replay for SMTP without TLS. Both peers are
//! played by the input, read in pieces of a size the input chooses.
//!
//! Input: a mode byte (bits 0-1: protocol, bit 2: STARTTLS required, bits 3-7:
//! bytes per read - 1), then what the client sends, a NUL byte, and what the
//! mail server sends (without a NUL, both send the same).
#![no_main]

use std::io;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use libfuzzer_sys::fuzz_target;
use rproxy_api::l4::starttls::{relay_first_ehlo, replay_plain, serve_client, skip_greeting, Outcome};
use rproxy_api::tls::config::StartTls;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A peer that sends `input` (at most `chunk` bytes per read, then EOF) and
/// takes everything written to it.
struct Peer<'a> {
	input: &'a [u8],
	chunk: usize,
	written: usize,
}

impl<'a> Peer<'a> {
	fn new(input: &'a [u8], chunk: usize) -> Self {
		Peer { input, chunk, written: 0 }
	}
}

impl AsyncRead for Peer<'_> {
	fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let n = self.chunk.min(buf.remaining()).min(self.input.len());
		buf.put_slice(&self.input[..n]);
		self.input = &self.input[n..];
		Poll::Ready(Ok(()))
	}
}

impl AsyncWrite for Peer<'_> {
	fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		self.written += buf.len();
		Poll::Ready(Ok(buf.len()))
	}
	fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}
	fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}
}

fn runtime() -> &'static tokio::runtime::Runtime {
	static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
	RT.get_or_init(|| tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap())
}

fuzz_target!(|data: &[u8]| {
	let [mode, input @ ..] = data else { return };
	let proto = match mode & 0x03 {
		0 | 3 => StartTls::Smtp,
		1 => StartTls::Imap,
		_ => StartTls::Pop3,
	};
	let required = mode & 0x04 != 0;
	let chunk = usize::from(mode >> 3) + 1;
	let (input, server_input) = match input.iter().position(|b| *b == 0) {
		Some(i) => (&input[..i], &input[i + 1..]),
		None => (input, input),
	};
	runtime().block_on(async {
		let mut client = Peer::new(input, chunk);
		let outcome = serve_client(proto, &mut client, "mail.example", required).await;
		if let Ok(Outcome::Plain { ehlo, pending }) = &outcome {
			assert_eq!(proto, StartTls::Smtp, "only SMTP continues without TLS");
			assert!(!required, "only when STARTTLS is not required");
			let mut server = Peer::new(server_input, chunk);
			let _ = replay_plain(&mut server, ehlo.as_deref(), pending).await;
		}
		let _ = skip_greeting(proto, &mut Peer::new(server_input, chunk)).await;
		let _ = relay_first_ehlo(&mut Peer::new(input, chunk), &mut Peer::new(server_input, chunk)).await;
	});
});
