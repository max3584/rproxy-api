//! The plain-text part of SMTP / IMAP / POP3 before STARTTLS, answered by
//! rproxy itself so it can terminate TLS in front of the mail server.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tlsconf::StartTls;

const MAX_LINE: usize = 4096;
const MAX_PLAIN_COMMANDS: usize = 32;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Reads CRLF-terminated lines and keeps whatever follows the last line.
#[derive(Default)]
pub struct Lines {
	buf: Vec<u8>,
}

impl Lines {
	pub async fn next<R: AsyncRead + Unpin>(&mut self, r: &mut R) -> io::Result<Option<String>> {
		loop {
			if let Some(i) = self.buf.iter().position(|&b| b == b'\n') {
				let line: Vec<u8> = self.buf.drain(..=i).collect();
				let text = String::from_utf8_lossy(&line);
				return Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()));
			}
			if self.buf.len() > MAX_LINE {
				return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
			}
			let mut chunk = [0u8; 1024];
			let n = r.read(&mut chunk).await?;
			if n == 0 {
				return Ok(None);
			}
			self.buf.extend_from_slice(&chunk[..n]);
		}
	}

	pub fn into_rest(self) -> Vec<u8> {
		self.buf
	}

	pub fn is_empty(&self) -> bool {
		self.buf.is_empty()
	}
}

/// How the plain-text dialogue with the client ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
	/// The client asked for STARTTLS; start the TLS handshake now.
	Upgrade,
	/// The client continued without TLS (SMTP with `starttls_required: false`).
	/// `ehlo` is the greeting it already sent; `pending` must reach the server next.
	Plain { ehlo: Option<String>, pending: Vec<u8> },
	/// The client quit or went away.
	Closed,
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, text: &str) -> io::Result<()> {
	w.write_all(text.as_bytes()).await?;
	w.flush().await
}

fn verb(line: &str) -> String {
	line.split_whitespace().next().unwrap_or("").to_ascii_uppercase()
}

/// Talks to the client until it asks for STARTTLS.
pub async fn serve_client<S: AsyncRead + AsyncWrite + Unpin>(
	proto: StartTls,
	client: &mut S,
	hostname: &str,
	required: bool,
) -> io::Result<Outcome> {
	let mut lines = Lines::default();
	let greeting = match proto {
		StartTls::Smtp => format!("220 {hostname} ESMTP rproxy\r\n"),
		StartTls::Imap => "* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] rproxy ready\r\n".to_string(),
		StartTls::Pop3 => "+OK rproxy ready\r\n".to_string(),
	};
	send(client, &greeting).await?;

	let mut ehlo = None;
	for _ in 0..MAX_PLAIN_COMMANDS {
		let Some(line) = tokio::time::timeout(COMMAND_TIMEOUT, lines.next(client))
			.await
			.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no command before STARTTLS"))??
		else {
			return Ok(Outcome::Closed);
		};
		let upgrade = match proto {
			StartTls::Smtp => match verb(&line).as_str() {
				"EHLO" => {
					send(client, &format!("250-{hostname}\r\n250 STARTTLS\r\n")).await?;
					ehlo = Some(line);
					false
				}
				"HELO" => {
					send(client, &format!("250 {hostname}\r\n")).await?;
					ehlo = Some(line);
					false
				}
				"STARTTLS" => {
					send(client, "220 2.0.0 Ready to start TLS\r\n").await?;
					true
				}
				"NOOP" | "RSET" => {
					send(client, "250 2.0.0 OK\r\n").await?;
					false
				}
				"QUIT" => {
					send(client, "221 2.0.0 Bye\r\n").await?;
					return Ok(Outcome::Closed);
				}
				_ if !required => {
					let mut pending = format!("{line}\r\n").into_bytes();
					pending.extend(lines.into_rest());
					return Ok(Outcome::Plain { ehlo, pending });
				}
				_ => {
					send(client, "530 5.7.0 Must issue a STARTTLS command first\r\n").await?;
					false
				}
			},
			StartTls::Imap => {
				let (tag, rest) = line.split_once(' ').unwrap_or((line.as_str(), ""));
				match verb(rest).as_str() {
					"CAPABILITY" => {
						send(client, &format!("* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\n{tag} OK CAPABILITY completed\r\n"))
							.await?;
						false
					}
					"NOOP" => {
						send(client, &format!("{tag} OK NOOP completed\r\n")).await?;
						false
					}
					"LOGOUT" => {
						send(client, &format!("* BYE rproxy logging out\r\n{tag} OK LOGOUT completed\r\n")).await?;
						return Ok(Outcome::Closed);
					}
					"STARTTLS" => {
						send(client, &format!("{tag} OK Begin TLS negotiation now\r\n")).await?;
						true
					}
					"LOGIN" | "AUTHENTICATE" => {
						send(client, &format!("{tag} NO [PRIVACYREQUIRED] Use STARTTLS first\r\n")).await?;
						false
					}
					_ => {
						send(client, &format!("{tag} BAD STARTTLS required\r\n")).await?;
						false
					}
				}
			}
			StartTls::Pop3 => match verb(&line).as_str() {
				"CAPA" => {
					send(client, "+OK Capability list follows\r\nSTLS\r\n.\r\n").await?;
					false
				}
				"STLS" => {
					send(client, "+OK Begin TLS negotiation\r\n").await?;
					true
				}
				"QUIT" => {
					send(client, "+OK Bye\r\n").await?;
					return Ok(Outcome::Closed);
				}
				_ => {
					send(client, "-ERR STLS required\r\n").await?;
					false
				}
			},
		};
		if upgrade {
			// Bytes sent before our reply would be read as if they came over TLS
			// (command injection, CVE-2011-0411); refuse them.
			if !lines.is_empty() {
				return Err(io::Error::new(io::ErrorKind::InvalidData, "data sent before the TLS handshake"));
			}
			return Ok(Outcome::Upgrade);
		}
	}
	Err(io::Error::new(io::ErrorKind::InvalidData, "too many commands before STARTTLS"))
}

/// Reads one complete reply from the server (SMTP multi-line replies end with "NNN ").
async fn read_reply<R: AsyncRead + Unpin>(proto: StartTls, lines: &mut Lines, r: &mut R) -> io::Result<Vec<String>> {
	let mut reply = vec![];
	loop {
		let line = lines
			.next(r)
			.await?
			.ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "server closed during greeting"))?;
		let last = match proto {
			StartTls::Smtp => line.as_bytes().get(3) != Some(&b'-'),
			StartTls::Imap | StartTls::Pop3 => true,
		};
		reply.push(line);
		if last {
			return Ok(reply);
		}
	}
}

fn check_ok(proto: StartTls, reply: &[String]) -> io::Result<()> {
	let first = reply.first().map(String::as_str).unwrap_or("");
	let ok = match proto {
		StartTls::Smtp => first.starts_with('2'),
		StartTls::Imap => first.starts_with("* OK") || first.starts_with("* PREAUTH"),
		StartTls::Pop3 => first.starts_with("+OK"),
	};
	if ok {
		Ok(())
	} else {
		Err(io::Error::other(format!("server refused: {first}")))
	}
}

/// Consumes the server's greeting, which the client never sees: it already
/// got rproxy's greeting before STARTTLS. Returns bytes read past the greeting.
pub async fn skip_greeting<S: AsyncRead + Unpin>(proto: StartTls, upstream: &mut S) -> io::Result<Vec<u8>> {
	let mut lines = Lines::default();
	let reply = tokio::time::timeout(UPSTREAM_TIMEOUT, read_reply(proto, &mut lines, upstream))
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no greeting from the mail server"))??;
	check_ok(proto, &reply)?;
	Ok(lines.into_rest())
}

/// SMTP after TLS: relays the client's first EHLO and removes STARTTLS from
/// the server's answer, since the session is already encrypted.
pub async fn relay_first_ehlo<C, U>(client: &mut C, upstream: &mut U) -> io::Result<(Vec<u8>, Vec<u8>)>
where
	C: AsyncRead + AsyncWrite + Unpin,
	U: AsyncRead + AsyncWrite + Unpin,
{
	let mut from_client = Lines::default();
	let Some(line) = tokio::time::timeout(COMMAND_TIMEOUT, from_client.next(client))
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no EHLO after STARTTLS"))??
	else {
		return Ok((vec![], vec![]));
	};
	upstream.write_all(format!("{line}\r\n").as_bytes()).await?;
	let is_ehlo = verb(&line) == "EHLO";
	if !is_ehlo {
		return Ok((from_client.into_rest(), vec![]));
	}
	let mut from_server = Lines::default();
	let reply = tokio::time::timeout(UPSTREAM_TIMEOUT, read_reply(StartTls::Smtp, &mut from_server, upstream))
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no EHLO reply from the mail server"))??;
	let mut kept: Vec<&String> = reply.iter().filter(|l| !l[4.min(l.len())..].eq_ignore_ascii_case("STARTTLS")).collect();
	if kept.is_empty() {
		kept = reply.iter().collect();
	}
	let mut out = String::new();
	for (i, l) in kept.iter().enumerate() {
		let sep = if i + 1 == kept.len() { ' ' } else { '-' };
		let (code, text) = (l.get(..3).unwrap_or("250"), l.get(4..).unwrap_or(""));
		out.push_str(&format!("{code}{sep}{text}\r\n"));
	}
	client.write_all(out.as_bytes()).await?;
	client.flush().await?;
	Ok((from_client.into_rest(), from_server.into_rest()))
}

/// SMTP without TLS (`starttls_required: false`): replays the client's EHLO to
/// the server, drops the answer (the client already got one) and sends `pending`.
pub async fn replay_plain<U: AsyncRead + AsyncWrite + Unpin>(
	upstream: &mut U,
	ehlo: Option<&str>,
	pending: &[u8],
) -> io::Result<Vec<u8>> {
	let mut lines = Lines::default();
	if let Some(ehlo) = ehlo {
		upstream.write_all(format!("{ehlo}\r\n").as_bytes()).await?;
		let reply = tokio::time::timeout(UPSTREAM_TIMEOUT, read_reply(StartTls::Smtp, &mut lines, upstream))
			.await
			.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no EHLO reply from the mail server"))??;
		check_ok(StartTls::Smtp, &reply)?;
	}
	upstream.write_all(pending).await?;
	Ok(lines.into_rest())
}

#[cfg(test)]
mod tests {
	use super::*;
	use tokio::io::duplex;

	async fn dialogue(proto: StartTls, required: bool, input: &str) -> (Outcome, String) {
		let (mut ours, mut theirs) = duplex(8192);
		theirs.write_all(input.as_bytes()).await.unwrap();
		let outcome = serve_client(proto, &mut ours, "mx.example", required).await;
		drop(ours);
		let mut out = String::new();
		theirs.read_to_string(&mut out).await.unwrap();
		(outcome.unwrap_or(Outcome::Closed), out)
	}

	#[tokio::test]
	async fn smtp_ehlo_then_starttls() {
		let (outcome, out) = dialogue(StartTls::Smtp, true, "EHLO client\r\nMAIL FROM:<a@b>\r\nSTARTTLS\r\n").await;
		assert_eq!(outcome, Outcome::Upgrade);
		assert!(out.starts_with("220 mx.example ESMTP"));
		assert!(out.contains("250 STARTTLS\r\n"));
		assert!(out.contains("530 5.7.0"), "mail before TLS is refused");
		assert!(out.ends_with("220 2.0.0 Ready to start TLS\r\n"));
	}

	#[tokio::test]
	async fn smtp_optional_tls_hands_over_plain_commands() {
		let (outcome, _) = dialogue(StartTls::Smtp, false, "EHLO c\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n").await;
		assert_eq!(
			outcome,
			Outcome::Plain { ehlo: Some("EHLO c".into()), pending: b"MAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n".to_vec() }
		);
	}

	#[tokio::test]
	async fn data_before_the_handshake_is_refused() {
		let (mut ours, mut theirs) = duplex(8192);
		theirs.write_all(b"EHLO c\r\nSTARTTLS\r\nMAIL FROM:<evil>\r\n").await.unwrap();
		let err = serve_client(StartTls::Smtp, &mut ours, "mx", true).await.unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	#[tokio::test]
	async fn imap_capability_and_starttls() {
		let (outcome, out) = dialogue(StartTls::Imap, true, "a1 CAPABILITY\r\na2 LOGIN u p\r\na3 STARTTLS\r\n").await;
		assert_eq!(outcome, Outcome::Upgrade);
		assert!(out.contains("a1 OK CAPABILITY completed"));
		assert!(out.contains("a2 NO [PRIVACYREQUIRED]"));
		assert!(out.ends_with("a3 OK Begin TLS negotiation now\r\n"));
	}

	#[tokio::test]
	async fn pop3_capa_and_stls() {
		let (outcome, out) = dialogue(StartTls::Pop3, true, "CAPA\r\nUSER x\r\nSTLS\r\n").await;
		assert_eq!(outcome, Outcome::Upgrade);
		assert!(out.contains("STLS\r\n.\r\n"));
		assert!(out.contains("-ERR STLS required"));
		assert!(out.ends_with("+OK Begin TLS negotiation\r\n"));
	}

	#[tokio::test]
	async fn quit_closes() {
		let (outcome, out) = dialogue(StartTls::Pop3, true, "QUIT\r\n").await;
		assert_eq!(outcome, Outcome::Closed);
		assert!(out.ends_with("+OK Bye\r\n"));
	}

	#[tokio::test]
	async fn ehlo_reply_loses_starttls() {
		let (mut client_side, mut client) = duplex(8192);
		let (mut up_side, mut server) = duplex(8192);
		client.write_all(b"EHLO c\r\n").await.unwrap();
		server.write_all(b"250-mail.example\r\n250-PIPELINING\r\n250 STARTTLS\r\n").await.unwrap();
		relay_first_ehlo(&mut client_side, &mut up_side).await.unwrap();
		drop(client_side);
		let mut out = String::new();
		client.read_to_string(&mut out).await.unwrap();
		assert_eq!(out, "250-mail.example\r\n250 PIPELINING\r\n");
		let mut sent = vec![0u8; 8];
		server.read_exact(&mut sent).await.unwrap();
		assert_eq!(&sent, b"EHLO c\r\n");
	}
}
