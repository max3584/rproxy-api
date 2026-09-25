//! STARTTLS termination for SMTP, IMAP and POP3 in front of plain mail servers.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use reqwest::StatusCode;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use common::pki::Pki;
use common::*;
use rproxy_api::starttls::Lines;

type Seen = Arc<Mutex<Vec<String>>>;

/// A plain mail server: sends `greeting`, answers each line with `reply(line)`,
/// and records every command it receives.
async fn mail_server(greeting: &'static str, reply: fn(&str) -> String) -> (SocketAddr, Seen) {
	let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr = listener.local_addr().unwrap();
	let seen: Seen = Arc::default();
	let log = seen.clone();
	tokio::spawn(async move {
		loop {
			let (mut s, _) = listener.accept().await.unwrap();
			let log = log.clone();
			tokio::spawn(async move {
				s.write_all(greeting.as_bytes()).await.unwrap();
				let mut lines = Lines::default();
				while let Ok(Some(line)) = lines.next(&mut s).await {
					log.lock().unwrap().push(line.clone());
					if s.write_all(reply(&line).as_bytes()).await.is_err() {
						break;
					}
				}
			});
		}
	});
	(addr, seen)
}

fn smtp_reply(line: &str) -> String {
	match line.split_whitespace().next().unwrap_or("").to_ascii_uppercase().as_str() {
		"EHLO" => "250-mail.backend\r\n250-PIPELINING\r\n250 STARTTLS\r\n".into(),
		"MAIL" => "250 2.1.0 Ok\r\n".into(),
		_ => "250 OK\r\n".into(),
	}
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, line: &str) {
	s.write_all(format!("{line}\r\n").as_bytes()).await.unwrap();
}

/// Reads one reply; SMTP replies continue while the 4th byte is '-'.
async fn reply<S: AsyncRead + Unpin>(lines: &mut Lines, s: &mut S, smtp: bool) -> Vec<String> {
	let mut out = vec![];
	loop {
		let line = lines.next(s).await.unwrap().expect("connection closed");
		let more = smtp && line.as_bytes().get(3) == Some(&b'-');
		out.push(line);
		if !more {
			return out;
		}
	}
}

async fn mail_rule(h: &Harness, pki: &Pki, backend: SocketAddr, proto: &str, required: bool) -> u16 {
	let cert = pki.server(&format!("mx-{proto}"), &["mx.test"]);
	let port = free_port();
	let mut body = rule("tcp", port, backend);
	body["tls"] = json!({"mode": "terminate", "certificates": [{"cert_file": cert.cert_file, "key_file": cert.key_file}]});
	body["starttls"] = json!(proto);
	body["starttls_required"] = json!(required);
	let (status, v) = h.post(body).await;
	assert_eq!(status, StatusCode::CREATED, "{v}");
	port
}

#[tokio::test]
async fn smtp_starttls_is_terminated_by_rproxy() {
	let pki = Pki::new("smtp");
	let (backend, seen) = mail_server("220 mail.backend ESMTP\r\n", smtp_reply).await;
	let h = harness().await;
	let port = mail_rule(&h, &pki, backend, "smtp", true).await;

	let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut lines = Lines::default();
	assert!(reply(&mut lines, &mut tcp, true).await[0].starts_with("220 mx.test ESMTP rproxy"));
	send(&mut tcp, "EHLO client.test").await;
	assert_eq!(reply(&mut lines, &mut tcp, true).await.last().unwrap(), "250 STARTTLS");
	send(&mut tcp, "MAIL FROM:<a@b>").await;
	assert!(reply(&mut lines, &mut tcp, true).await[0].starts_with("530"), "no mail before TLS");
	send(&mut tcp, "STARTTLS").await;
	assert!(reply(&mut lines, &mut tcp, true).await[0].starts_with("220 2.0.0"));

	let mut tls = pki.connector(None).connect("mx.test".try_into().unwrap(), tcp).await.unwrap();
	let mut lines = Lines::default();
	send(&mut tls, "EHLO client.test").await;
	assert_eq!(
		reply(&mut lines, &mut tls, true).await,
		vec!["250-mail.backend", "250 PIPELINING"],
		"the server's EHLO answer, without STARTTLS"
	);
	send(&mut tls, "MAIL FROM:<a@b>").await;
	assert_eq!(reply(&mut lines, &mut tls, true).await, vec!["250 2.1.0 Ok"]);
	assert_eq!(*seen.lock().unwrap(), vec!["EHLO client.test", "MAIL FROM:<a@b>"], "plain-text commands never reach the server");
}

#[tokio::test]
async fn smtp_without_tls_is_allowed_when_not_required() {
	let pki = Pki::new("smtp-opt");
	let (backend, seen) = mail_server("220 mail.backend ESMTP\r\n", smtp_reply).await;
	let h = harness().await;
	let port = mail_rule(&h, &pki, backend, "smtp", false).await;

	let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut lines = Lines::default();
	reply(&mut lines, &mut tcp, true).await;
	send(&mut tcp, "EHLO mta.test").await;
	reply(&mut lines, &mut tcp, true).await;
	send(&mut tcp, "MAIL FROM:<x@y>").await;
	assert_eq!(reply(&mut lines, &mut tcp, true).await, vec!["250 2.1.0 Ok"]);
	assert_eq!(*seen.lock().unwrap(), vec!["EHLO mta.test", "MAIL FROM:<x@y>"], "EHLO is replayed to the server");
}

#[tokio::test]
async fn imap_starttls_is_terminated_by_rproxy() {
	let pki = Pki::new("imap");
	let (backend, seen) = mail_server("* OK backend ready\r\n", |line| {
		let tag = line.split(' ').next().unwrap_or("*");
		format!("{tag} OK done\r\n")
	})
	.await;
	let h = harness().await;
	let port = mail_rule(&h, &pki, backend, "imap", true).await;

	let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut lines = Lines::default();
	assert!(reply(&mut lines, &mut tcp, false).await[0].contains("STARTTLS"));
	send(&mut tcp, "a1 LOGIN user pass").await;
	assert!(reply(&mut lines, &mut tcp, false).await[0].starts_with("a1 NO [PRIVACYREQUIRED]"));
	send(&mut tcp, "a2 STARTTLS").await;
	assert!(reply(&mut lines, &mut tcp, false).await[0].starts_with("a2 OK"));

	let mut tls = pki.connector(None).connect("mx.test".try_into().unwrap(), tcp).await.unwrap();
	let mut lines = Lines::default();
	send(&mut tls, "a3 LOGIN user pass").await;
	assert_eq!(reply(&mut lines, &mut tls, false).await, vec!["a3 OK done"]);
	assert_eq!(*seen.lock().unwrap(), vec!["a3 LOGIN user pass"], "the password only travels over TLS");
}

#[tokio::test]
async fn pop3_stls_is_terminated_by_rproxy() {
	let pki = Pki::new("pop3");
	let (backend, seen) = mail_server("+OK backend ready\r\n", |_| "+OK\r\n".into()).await;
	let h = harness().await;
	let port = mail_rule(&h, &pki, backend, "pop3", true).await;

	let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
	let mut lines = Lines::default();
	assert!(reply(&mut lines, &mut tcp, false).await[0].starts_with("+OK"));
	send(&mut tcp, "USER bob").await;
	assert!(reply(&mut lines, &mut tcp, false).await[0].starts_with("-ERR"));
	send(&mut tcp, "STLS").await;
	assert!(reply(&mut lines, &mut tcp, false).await[0].starts_with("+OK Begin TLS"));

	let mut tls = pki.connector(None).connect("mx.test".try_into().unwrap(), tcp).await.unwrap();
	let mut lines = Lines::default();
	send(&mut tls, "USER bob").await;
	assert_eq!(reply(&mut lines, &mut tls, false).await, vec!["+OK"]);
	assert_eq!(*seen.lock().unwrap(), vec!["USER bob"]);
}

#[tokio::test]
async fn starttls_needs_terminate() {
	let h = harness().await;
	let mut body = rule("tcp", free_port(), tcp_backend("A:").await);
	body["starttls"] = json!("smtp");
	let (status, v) = h.post(body).await;
	assert_eq!((status, v["code"].as_str()), (StatusCode::BAD_REQUEST, Some("tls_config")), "{v}");
}
