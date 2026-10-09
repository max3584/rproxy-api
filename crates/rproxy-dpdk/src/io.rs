//! Moving frames between DPDK ports and the forwarder: the lcore loop, and the
//! startup check's wire through a loopback port.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::engine::{Engine, Rule, Verdict};
use crate::ffi::{self, Mbuf, Pool, Port};
use crate::selftest::{Handle, Wire};

/// How often an lcore that sweeps ends idle sessions.
const SWEEP_EVERY: Duration = Duration::from_secs(1);

/// What one lcore does.
pub struct Job<R: Rule> {
	pub engine: Arc<Engine<R>>,
	pub pool: Pool,
	/// Every port, by the forwarder's port index.
	pub ports: Vec<Port>,
	/// The (port index, RX queue) pairs this lcore polls.
	pub rx: Vec<(usize, u16)>,
	/// Its own TX queue on every port.
	pub txq: u16,
	pub burst: usize,
	/// One lcore ends idle sessions (`Engine::sweep`).
	pub sweeper: bool,
	pub stop: Arc<AtomicBool>,
	pub stats: Arc<IoStats>,
}

/// Frames the ports did not take (TX queue full) or the pool could not hold.
#[derive(Default, Debug)]
pub struct IoStats {
	pub rx: AtomicU64,
	pub tx: AtomicU64,
	pub tx_full: AtomicU64,
	pub chained: AtomicU64,
	pub no_mbuf: AtomicU64,
}

/// Polls the job's queues until `stop`: each burst through the forwarder, then
/// out on the ports' TX queues. Anomalies are counted, and logged at `debug`
/// (dropping frames is what a full queue does; nothing watches the counts).
pub fn run<R: Rule>(job: Job<R>) {
	let Job { engine, pool, ports, rx, txq, burst, sweeper, stop, stats } = job;
	let burst = burst.clamp(1, 512);
	let mut w = engine.worker();
	let mut bufs: Vec<*mut Mbuf> = vec![std::ptr::null_mut(); burst];
	let mut out: Vec<Vec<*mut Mbuf>> = ports.iter().map(|_| Vec::with_capacity(burst * 2)).collect();
	let mut last_sweep = Instant::now();
	let (mut rx_n, mut tx_n) = (0u64, 0u64);
	while !stop.load(Ordering::Relaxed) {
		engine.refresh(&mut w);
		let now = Instant::now();
		for &(pi, q) in &rx {
			let n = ports[pi].rx(q, &mut bufs);
			rx_n += n as u64;
			for &m in &bufs[..n] {
				// SAFETY: the mbuf is ours until it is sent or freed
				let Some(frame) = (unsafe { ffi::data(m) }) else {
					stats.chained.fetch_add(1, Ordering::Relaxed);
					unsafe { ffi::free(m) };
					continue;
				};
				let verdict = engine.process(&w, pi, frame, now, &mut |port, bytes| match pool.copy(bytes) {
					Some(c) => out[port].push(c),
					None => {
						stats.no_mbuf.fetch_add(1, Ordering::Relaxed);
					}
				});
				match verdict {
					Verdict::Send(port) => out[port].push(m),
					Verdict::Drop => unsafe { ffi::free(m) },
				}
			}
		}
		for (pi, q) in out.iter_mut().enumerate() {
			if q.is_empty() {
				continue;
			}
			let sent = ports[pi].tx(txq, q);
			tx_n += sent as u64;
			if sent < q.len() {
				let lost = q.len() - sent;
				stats.tx_full.fetch_add(lost as u64, Ordering::Relaxed);
				tracing::debug!(event = "dpdk.tx_full", port = pi, queue = txq, dropped = lost);
				// SAFETY: the port did not take these
				unsafe { ffi::free_all(&mut q[sent..]) };
			}
			q.clear();
		}
		if now.duration_since(last_sweep) >= SWEEP_EVERY {
			last_sweep = now;
			// the totals, once a second rather than per burst (shared cache lines)
			stats.rx.fetch_add(std::mem::take(&mut rx_n), Ordering::Relaxed);
			stats.tx.fetch_add(std::mem::take(&mut tx_n), Ordering::Relaxed);
			if sweeper {
				engine.sweep(now);
			}
		}
	}
	stats.rx.fetch_add(rx_n, Ordering::Relaxed);
	stats.tx.fetch_add(tx_n, Ordering::Relaxed);
}

/// The startup check's wire: a loopback port (`net_ring`, whose TX ring is its
/// RX ring) with one queue. Frames go in as mbufs from the real pool, the
/// forwarder rewrites them in mbuf memory, and they come back out of the port.
pub struct RingWire {
	pub port: Port,
	pub pool: Pool,
}

impl RingWire {
	fn send(&self, frames: impl IntoIterator<Item = *mut Mbuf>) -> Result<(), String> {
		let mut q: Vec<*mut Mbuf> = frames.into_iter().collect();
		let mut at = 0;
		let deadline = Instant::now() + Duration::from_secs(1);
		while at < q.len() {
			at += self.port.tx(0, &mut q[at..]);
			if at < q.len() && Instant::now() > deadline {
				unsafe { ffi::free_all(&mut q[at..]) };
				return Err(format!("the check port took {at} of {} frames", q.len()));
			}
		}
		Ok(())
	}

	fn receive(&self, want: usize) -> Vec<*mut Mbuf> {
		let mut got = vec![];
		let mut bufs = [std::ptr::null_mut(); 64];
		let deadline = Instant::now() + Duration::from_millis(500);
		while got.len() < want && Instant::now() < deadline {
			let n = self.port.rx(0, &mut bufs);
			got.extend_from_slice(&bufs[..n]);
		}
		// anything beyond what was sent would be a fault: take it too, so the check sees it
		loop {
			let n = self.port.rx(0, &mut bufs);
			if n == 0 {
				break;
			}
			got.extend_from_slice(&bufs[..n]);
		}
		got
	}

	fn copies(&self, frames: &[Vec<u8>]) -> Result<Vec<*mut Mbuf>, String> {
		let mut out = vec![];
		for f in frames {
			match self.pool.copy(f) {
				Some(m) => out.push(m),
				None => {
					unsafe { ffi::free_all(&mut out) };
					return Err("the mbuf pool is empty".into());
				}
			}
		}
		Ok(out)
	}
}

impl Wire for RingWire {
	fn forward(&mut self, frames: Vec<Vec<u8>>, f: &mut Handle) -> Result<Vec<Vec<u8>>, String> {
		let n = frames.len();
		self.send(self.copies(&frames)?)?;
		let mut received = self.receive(n);
		if received.len() != n {
			let got = received.len();
			unsafe { ffi::free_all(&mut received) };
			return Err(format!("sent {n} frames into the check port, {got} came out"));
		}
		let mut outgoing = vec![];
		let mut extra: Vec<Vec<u8>> = vec![];
		for m in received {
			// SAFETY: ours until sent or freed
			let Some(frame) = (unsafe { ffi::data(m) }) else {
				unsafe { ffi::free(m) };
				return Err("a chained mbuf".into());
			};
			match f(frame, &mut |_, b| extra.push(b.to_vec())) {
				Verdict::Send(_) => outgoing.push(m),
				Verdict::Drop => unsafe { ffi::free(m) },
			}
			// frames the forwarder made go out after the one that caused them
			if !extra.is_empty() {
				match self.copies(&extra) {
					Ok(ms) => outgoing.extend(ms),
					Err(e) => {
						unsafe { ffi::free_all(&mut outgoing) };
						return Err(e);
					}
				}
				extra.clear();
			}
		}
		let want = outgoing.len();
		self.send(outgoing)?;
		let mut back = self.receive(want);
		let mut result = vec![];
		for &m in &back {
			match unsafe { ffi::data(m) } {
				Some(d) => result.push(d.to_vec()),
				None => result.push(vec![]),
			}
		}
		unsafe { ffi::free_all(&mut back) };
		Ok(result)
	}
}
