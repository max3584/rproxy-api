// The forwarding loop descends from the original rproxy project by glacierx and
// has been rewritten around cancellation tokens for rproxy-api.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::proxy::Runtime;
use crate::rule::SourceIp;
use crate::source;

pub async fn serve(listener: TcpListener, rt: Arc<Runtime>) {
	loop {
		tokio::select! {
			biased;
			_ = rt.stop.cancelled() => break,
			accepted = listener.accept() => match accepted {
				Ok((inbound, peer)) => {
					rt.tracker.spawn(handle(inbound, peer, rt.clone()));
				}
				Err(e) => {
					// e.g. EMFILE: back off instead of spinning
					warn!(event = "accept.error", rule = %rt.key, error = %e);
					tokio::time::sleep(Duration::from_millis(100)).await;
				}
			}
		}
	}
}

async fn connect(rt: &Runtime, client: SocketAddr) -> io::Result<(TcpStream, SocketAddr)> {
	let targets = rt.target.borrow().clone();
	let mut last_err = io::Error::new(io::ErrorKind::NotFound, "no resolved target");
	for target in targets {
		match source::connect_tcp(target, rt.bind_as(client)).await {
			Ok(stream) => return Ok((stream, target)),
			Err(e) => last_err = e,
		}
	}
	Err(last_err)
}

async fn handle(mut inbound: TcpStream, client: SocketAddr, rt: Arc<Runtime>) {
	let started = Instant::now();
	rt.stats.opened();

	let result: io::Result<(SocketAddr, u64, u64, &str)> = async {
		let (mut outbound, target) = tokio::select! {
			_ = rt.kill.cancelled() => return Err(io::Error::other("stopped before connect")),
			r = connect(&rt, client) => r?,
		};
		info!(event = "conn.open", rule = %rt.key, client = %client, target = %target);

		let local = inbound.local_addr()?;
		match rt.source_ip {
			SourceIp::ProxyV1 => outbound.write_all(&source::proxy_v1_header(client, local)).await?,
			SourceIp::ProxyV2 => outbound.write_all(&source::proxy_v2_header(client, local)).await?,
			SourceIp::Proxy | SourceIp::Transparent => {}
		}

		tokio::select! {
			_ = rt.kill.cancelled() => Ok((target, 0, 0, "stopped")),
			r = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {
				let (rx, tx) = r?;
				Ok((target, rx, tx, "closed"))
			}
		}
	}
	.await;

	let elapsed_ms = started.elapsed().as_millis() as u64;
	match result {
		Ok((target, rx, tx, reason)) => {
			rt.stats.closed(rx, tx);
			info!(event = "conn.close", rule = %rt.key, client = %client, target = %target,
				rx_bytes = rx, tx_bytes = tx, duration_ms = elapsed_ms, reason);
		}
		Err(e) => {
			rt.stats.closed(0, 0);
			warn!(event = "conn.error", rule = %rt.key, client = %client, error = %e, duration_ms = elapsed_ms);
		}
	}
}
