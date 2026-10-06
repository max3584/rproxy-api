//! The ACME helper (#208 point 7): `rproxy-api acme-helper` holds the DNS
//! providers' secrets and writes the TXT records of DNS-01 for the main
//! process, which then never reads those secrets (`global.acme.helper`). It
//! runs as another user and answers on a Unix socket, one JSON line per
//! request and per answer:
//!
//! ```text
//! {"op":"locate","provider":"pdns","domain":"www.example.com","value":"<dns-01 value>"}
//!   -> {"ok":true,"record":{"provider","domain","fqdn","zone","value"}}
//! {"op":"present","provider":"pdns","records":[...]}  -> {"ok":true}
//! {"op":"cleanup","provider":"pdns","records":[...]}  -> {"ok":true}
//! ```
//!
//! The helper trusts nothing it is sent: the name must be in the provider's
//! `allowed_names`, the value must look like a DNS-01 value, and a record to
//! write or remove must be where the helper itself finds `_acme-challenge` of
//! that name (CNAMEs followed, the provider's `zones`). So whoever can reach the
//! socket can write only `_acme-challenge` TXT records for allowed names.
//! `--allow-uid` limits the peers further (SO_PEERCRED).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tracing::{info, warn};

use super::config::{allowed_by, normalize_name, valid_name, AcmeGlobal};
use super::dns::{Provider, Written};

/// How long one request may take (DNS lookups, the provider's API).
const TIMEOUT: Duration = Duration::from_secs(60);
const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
	Locate { provider: String, domain: String, value: String },
	Present { provider: String, records: Vec<Written> },
	Cleanup { provider: String, records: Vec<Written> },
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Answer {
	pub ok: bool,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub record: Option<Written>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

/// Sends one request to the helper at `socket`.
pub async fn call(socket: &Path, req: &Request) -> Result<Answer, String> {
	let work = async {
		let stream = tokio::net::UnixStream::connect(socket).await.map_err(|e| format!("acme helper {}: {e}", socket.display()))?;
		let (read, mut write) = stream.into_split();
		let mut line = serde_json::to_vec(req).map_err(|e| e.to_string())?;
		line.push(b'\n');
		write.write_all(&line).await.map_err(|e| format!("acme helper: {e}"))?;
		let mut answer = String::new();
		BufReader::new(read).take(MAX_LINE as u64).read_line(&mut answer).await.map_err(|e| format!("acme helper: {e}"))?;
		let answer: Answer = serde_json::from_str(&answer).map_err(|e| format!("acme helper: a broken answer: {e}"))?;
		match answer.ok {
			true => Ok(answer),
			false => Err(format!("acme helper: {}", answer.error.unwrap_or_default())),
		}
	};
	tokio::time::timeout(TIMEOUT, work).await.map_err(|_| "acme helper: timed out".to_string())?
}


/// What the helper serves.
pub struct Helper {
	providers: BTreeMap<String, Provider>,
	servers: Vec<SocketAddr>,
	/// Peers allowed by uid (SO_PEERCRED); empty: whoever the socket's mode lets in.
	allow_uids: Vec<u32>,
}

/// A DNS-01 value: base64url of a SHA-256 (43 characters).
fn valid_value(v: &str) -> bool {
	(16..=128).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Helper {
	/// The providers of `global.acme` (their secrets are read when used).
	pub fn new(global: &AcmeGlobal, allow_uids: Vec<u32>) -> Result<Helper, String> {
		global.check()?;
		let mut providers = BTreeMap::new();
		for (name, p) in &global.dns_providers {
			for f in Provider::required_files(p) {
				if let Err(e) = std::fs::metadata(&f) {
					if e.kind() == std::io::ErrorKind::NotFound {
						return Err(format!("global.acme.dns_providers.{name}: {f} does not exist"));
					}
				}
			}
			providers.insert(name.clone(), Provider::new(name, p).map_err(|e| format!("global.acme.dns_providers.{name}: {e}"))?);
		}
		let servers = if global.dns_servers.is_empty() {
			super::dnsq::system_servers()
		} else {
			global.dns_servers.iter().map(|s| super::config::parse_dns_server(s)).collect::<Result<_, _>>()?
		};
		Ok(Helper { providers, servers, allow_uids })
	}

	fn provider(&self, name: &str) -> Result<&Provider, String> {
		self.providers.get(name).ok_or_else(|| format!("dns provider {name:?} is not configured in the helper"))
	}

	fn check_domain(p: &Provider, domain: &str) -> Result<(), String> {
		let d = normalize_name(domain);
		if d != domain || !valid_name(&d) || d.starts_with("*.") {
			return Err(format!("{domain:?} is not a name"));
		}
		if !allowed_by(p.allowed_names(), &d) {
			return Err(format!("{domain} is not in allowed_names of dns provider {:?}", p.name));
		}
		Ok(())
	}

	/// A record to write or remove must be where this helper finds it.
	async fn verify(&self, p: &Provider, records: &[Written]) -> Result<(), String> {
		for r in records {
			Self::check_domain(p, &r.domain)?;
			if r.provider != p.name || !valid_value(&r.value) {
				return Err("a record that does not belong to this request".into());
			}
			let found = p.locate(&r.domain, &r.value, &self.servers).await?;
			if found.fqdn != r.fqdn || found.zone != r.zone {
				return Err(format!("{}: the record would go to {} (zone {}), not {} (zone {})", r.domain, found.fqdn, found.zone, r.fqdn, r.zone));
			}
		}
		Ok(())
	}

	async fn handle(&self, req: Request) -> Result<Answer, String> {
		match req {
			Request::Locate { provider, domain, value } => {
				let p = self.provider(&provider)?;
				Self::check_domain(p, &domain)?;
				if !valid_value(&value) {
					return Err("the value is not a DNS-01 value".into());
				}
				let record = p.locate(&domain, &value, &self.servers).await?;
				Ok(Answer { ok: true, record: Some(record), error: None })
			}
			Request::Present { provider, records } => {
				let p = self.provider(&provider)?;
				self.verify(p, &records).await?;
				p.present(&records).await?;
				for r in &records {
					info!(event = "acme.dns", action = "add", provider = %p.name, fqdn = %r.fqdn, zone = %r.zone, part = "helper", outcome = "ok");
				}
				Ok(Answer { ok: true, ..Default::default() })
			}
			Request::Cleanup { provider, records } => {
				let p = self.provider(&provider)?;
				self.verify(p, &records).await?;
				p.cleanup(&records).await?;
				for r in &records {
					info!(event = "acme.dns", action = "remove", provider = %p.name, fqdn = %r.fqdn, zone = %r.zone, part = "helper", outcome = "ok");
				}
				Ok(Answer { ok: true, ..Default::default() })
			}
		}
	}

	async fn connection(self: Arc<Self>, stream: tokio::net::UnixStream) {
		let peer = stream.peer_cred().ok().map(|c| c.uid());
		let (read, mut write) = stream.into_split();
		let answer = if !self.allow_uids.is_empty() && !peer.is_some_and(|uid| self.allow_uids.contains(&uid)) {
			warn!(event = "acme.helper", outcome = "refused", uid = peer.map(i64::from).unwrap_or(-1), "this peer is not in --allow-uid");
			Answer { ok: false, error: Some("this peer may not use the helper".into()), ..Default::default() }
		} else {
			let mut line = String::new();
			let read = BufReader::new(read).take(MAX_LINE as u64).read_line(&mut line).await;
			let result = match read {
				Ok(_) => match serde_json::from_str::<Request>(&line) {
					Ok(req) => tokio::time::timeout(TIMEOUT, self.handle(req)).await.unwrap_or_else(|_| Err("timed out".into())),
					Err(e) => Err(format!("a broken request: {e}")),
				},
				Err(e) => Err(e.to_string()),
			};
			result.unwrap_or_else(|e| {
				warn!(event = "acme.helper", outcome = "error", uid = peer.map(i64::from).unwrap_or(-1), error = %e);
				Answer { ok: false, error: Some(e), ..Default::default() }
			})
		};
		let mut out = serde_json::to_vec(&answer).unwrap_or_default();
		out.push(b'\n');
		let _ = write.write_all(&out).await;
	}

	/// Serves requests on `listener` until `stop`.
	pub async fn serve(self: Arc<Self>, listener: tokio::net::UnixListener, stop: tokio_util::sync::CancellationToken) {
		loop {
			let stream = tokio::select! {
				_ = stop.cancelled() => return,
				r = listener.accept() => match r {
					Ok((s, _)) => s,
					Err(e) => {
						warn!(event = "acme.helper", error = %e);
						tokio::time::sleep(Duration::from_millis(100)).await;
						continue;
					}
				},
			};
			tokio::spawn(self.clone().connection(stream));
		}
	}
}

/// `rproxy-api acme-helper`: reads `global.acme` from the settings file and
/// serves its DNS providers on `socket`.
pub struct HelperOptions {
	pub config: PathBuf,
	pub socket: crate::control::unix_api::SocketOptions,
	pub allow_uids: Vec<u32>,
}

pub async fn run(opts: HelperOptions) -> Result<(), String> {
	let doc = crate::config::ConfigDoc::load(&opts.config).map_err(|e| e.to_string())?;
	let global = doc.global.acme.ok_or_else(|| format!("{}: no global.acme", opts.config.display()))?;
	let helper = Arc::new(Helper::new(&global, opts.allow_uids)?);
	let listener = crate::control::unix_api::bind(&opts.socket).await.map_err(|e| match e {
		crate::control::unix_api::SocketError::Config(e) | crate::control::unix_api::SocketError::Unavailable(e) => e,
	})?;
	info!(event = "acme.helper", outcome = "listening", socket = %opts.socket.path.display(), providers = helper.providers.len());
	let stop = tokio_util::sync::CancellationToken::new();
	let serve = tokio::spawn(helper.serve(listener, stop.clone()));
	let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
	tokio::select! {
		_ = term.recv() => {}
		_ = tokio::signal::ctrl_c() => {}
	}
	stop.cancel();
	let _ = serve.await;
	let _ = std::fs::remove_file(&opts.socket.path);
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn values_and_requests() {
		assert!(valid_value("qYdUfkaTCkVSY0mW0UjdUs7f-1xYODPyuo3uF0ktZnc"));
		assert!(!valid_value("a\"},{\"x"));
		assert!(!valid_value("short"));
		let r: Request = serde_json::from_str(r#"{"op":"locate","provider":"p","domain":"a.example.com","value":"v"}"#).unwrap();
		assert!(matches!(r, Request::Locate { .. }));
		assert!(serde_json::from_str::<Request>(r#"{"op":"order"}"#).is_err());
	}
}
