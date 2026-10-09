//! The DPDK data plane for L4 UDP (#261, experimental; builds with the `dpdk`
//! feature only). `global.performance.dpdk` gives DPDK ports with IPv4
//! addresses; UDP rules listening on those addresses are forwarded by DPDK
//! lcores (`rproxy_dpdk::engine`) instead of kernel sockets. TCP, L7 and the
//! control API stay on the kernel.
//!
//! At startup (`start`): the hugepages are checked, the EAL is initialised on
//! a thread of its own (it becomes the main lcore, so the rest of the process
//! keeps its CPU affinity), the ports are set up, and test datagrams go
//! through the forwarder over rproxy's loopback port (`net_ring_rpchk`) and
//! are compared (`rproxy_dpdk::selftest`) before anything is enabled. The
//! result (`Status`) goes to the log (`performance.probe`), `degraded`, and
//! `GET /capabilities` (`performance.dpdk`). If any step fails, the kernel
//! path is used (`fallback: true`) or the start stops (`fallback: false`).
//! Nothing watches the data plane while it runs; anomalies are logged as
//! they are handled.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rproxy_dpdk::engine::{Engine, Phase, PortCfg, Rule};
use rproxy_dpdk::ffi::{self, Pool, Port};
use rproxy_dpdk::io::{self, IoStats, Job, RingWire};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::performance::{hugepage_kib, parse_cpu_list, parse_ipv4_cidr, DpdkSpec, DPDK_CHECK_PORT};
use crate::core::balance::{Lease, Member};
use crate::core::bandwidth::{Dir, Gate};
use crate::core::limits::{self, Permit, Reason};
use crate::core::proxy::Runtime;
use crate::core::rule::{RuleSpec, SourceIp};
use crate::error::ApiError;
use crate::net::offload::probe::{Outcome, Test};
use crate::tls::config::TlsMode;

/// How long the EAL, the ports and the check may take at startup.
const START_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a port's link may take to come up before it is reported down.
const LINK_WAIT: Duration = Duration::from_secs(5);
/// Bytes of hugepage memory per mbuf (data room, headers, the pool's own).
const MBUF_FOOTPRINT: u64 = 2560;

/// The startup check passed and the data plane runs: the engine and how to stop it.
struct Dataplane {
	engine: Arc<Engine<RtRule>>,
	stop: Arc<AtomicBool>,
	main: Mutex<Option<std::thread::JoinHandle<()>>>,
}

static DATAPLANE: OnceLock<Dataplane> = OnceLock::new();
static IO_STATS: OnceLock<Arc<IoStats>> = OnceLock::new();
/// Set by `main` before the startup probe: a passing test leaves the data
/// plane running. Unset (`--check-kernel`), the test releases everything.
static KEEP: AtomicBool = AtomicBool::new(false);

pub fn keep_running() {
	KEEP.store(true, Ordering::Relaxed);
}

fn mac_text(m: [u8; 6]) -> String {
	m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

fn step(tests: &mut Vec<Test>, name: impl Into<String>, result: Result<String, String>) -> Result<String, String> {
	let (ok, detail) = match &result {
		Ok(d) => (true, d.clone()),
		Err(e) => (false, e.clone()),
	};
	tests.push(Test { name: name.into(), ok, detail });
	result
}

/// The probe of `global.performance.dpdk` (`net::offload::probe`): hugepages,
/// EAL, mempool, test datagrams through the forwarder over the loopback check
/// port, then the configured ports. At startup (`keep_running`) a pass leaves
/// the lcores forwarding; otherwise everything is released.
pub fn test(spec: Option<&DpdkSpec>) -> Outcome {
	let Some(spec) = spec.filter(|s| s.enabled()) else {
		return Outcome::unusable("not enabled (global.performance.dpdk.enabled)", vec![]);
	};
	if DATAPLANE.get().is_some() {
		return Outcome::unusable("the EAL is already in use by this process", vec![]);
	}
	let mut tests = vec![];
	if let Err(e) = step(&mut tests, "hugepages", check_hugepages(spec)) {
		return Outcome::unusable(e, tests);
	}
	let keep = KEEP.load(Ordering::Relaxed);
	let (tx, rx) = std::sync::mpsc::channel();
	let spec = spec.clone();
	let stop = Arc::new(AtomicBool::new(false));
	let stop_main = stop.clone();
	let main = std::thread::Builder::new().name("rproxy-dpdk".into()).spawn(move || {
		// this thread becomes the main lcore (pinned to the first lcore's CPU)
		let mut tests = vec![];
		let (detail, (engine, mut jobs, ports)) = match bring_up(&spec, &stop_main, &mut tests) {
			Ok(ok) => ok,
			Err(e) => {
				let _ = tx.send(Err((e, tests)));
				return;
			}
		};
		if !keep {
			for p in ports {
				p.stop();
			}
			ffi::eal_cleanup();
			let _ = tx.send(Ok((detail, tests, engine)));
			return;
		}
		let _ = tx.send(Ok((detail, tests, engine)));
		let own = jobs.remove(0);
		let mut launched = vec![];
		for (lcore, job) in jobs {
			match ffi::launch(lcore, Box::new(move || io::run(job))) {
				Ok(()) => launched.push(lcore),
				Err(e) => warn!(event = "degraded", part = "global.performance.dpdk", error = %e, "an lcore did not start; its queues are not polled"),
			}
		}
		io::run(own.1);
		for lcore in launched {
			if ffi::wait(lcore) != 0 {
				warn!(event = "dpdk.lcore", lcore, "the lcore's loop panicked");
			}
		}
		for p in ports {
			p.stop();
		}
		ffi::eal_cleanup();
	});
	let main = match main {
		Ok(m) => m,
		Err(e) => return Outcome::unusable(format!("cannot start the DPDK thread: {e}"), tests),
	};
	match rx.recv_timeout(START_TIMEOUT) {
		Ok(Ok((detail, more, engine))) => {
			tests.extend(more);
			if keep {
				let _ = DATAPLANE.set(Dataplane { engine, stop, main: Mutex::new(Some(main)) });
			} else {
				let _ = main.join();
			}
			Outcome { usable: true, detail, tests }
		}
		Ok(Err((e, more))) => {
			tests.extend(more);
			let _ = main.join();
			Outcome::unusable(e, tests)
		}
		Err(_) => Outcome::unusable(format!("the EAL and the ports did not come up within {}s", START_TIMEOUT.as_secs()), tests),
	}
}

/// Hugepages free for the pool (unless the EAL runs without them).
fn check_hugepages(spec: &DpdkSpec) -> Result<String, String> {
	if spec.eal_args.iter().any(|a| a == "--no-huge") {
		return Ok("not used (--no-huge)".into());
	}
	let kib = hugepage_kib(spec.hugepages.as_ref().and_then(|h| h.size.as_deref()))?;
	let label = if kib >= 1 << 20 { "1GB" } else { "2MB" };
	let dir = format!("/sys/kernel/mm/hugepages/hugepages-{kib}kB");
	let free: u64 = std::fs::read_to_string(format!("{dir}/free_hugepages"))
		.map_err(|e| format!("{label} hugepages are not available ({dir}: {e})"))?
		.trim()
		.parse()
		.unwrap_or(0);
	let (mbufs, _) = spec.mempool();
	let need = u64::from(mbufs) * MBUF_FOOTPRINT;
	let have = free * kib * 1024;
	if have < need {
		return Err(format!("{free} free {label} hugepages ({} MiB); the mempool of {mbufs} mbufs needs about {} MiB (vm.nr_hugepages)", have >> 20, need >> 20));
	}
	Ok(format!("{free} free {label} pages ({} MiB)", have >> 20))
}

/// The EAL's arguments: the program name, the lcores, the devices, rproxy's
/// check port, then `eal_args`.
pub fn eal_args(spec: &DpdkSpec) -> Vec<String> {
	let mut args = vec!["rproxy-api".to_string()];
	if let Some(l) = &spec.lcores {
		args.extend(["-l".into(), l.trim().to_string()]);
	}
	let pci: Vec<&String> = spec.ports.iter().filter_map(|p| p.pci.as_ref()).collect();
	if pci.is_empty() {
		args.push("--no-pci".into());
	}
	for p in pci {
		args.extend(["-a".into(), p.trim().to_string()]);
	}
	for v in spec.ports.iter().filter_map(|p| p.vdev.as_ref()) {
		args.extend(["--vdev".into(), v.trim().to_string()]);
	}
	args.extend(["--vdev".into(), DPDK_CHECK_PORT.into()]);
	args.extend(spec.eal_args.iter().cloned());
	args
}

type Jobs = (Arc<Engine<RtRule>>, Vec<(u32, Job<RtRule>)>, Vec<Port>);

/// EAL, pool, the check, the ports; then the lcores' jobs (the first is the
/// main lcore's). Each step goes to `tests`.
fn bring_up(spec: &DpdkSpec, stop: &Arc<AtomicBool>, tests: &mut Vec<Test>) -> Result<(String, Jobs), String> {
	step(tests, "eal", ffi::eal_init(&eal_args(spec)).map(|()| ffi::version()))?;
	let fail = |e: String| {
		ffi::eal_cleanup();
		e
	};
	let (mbufs, cache) = spec.mempool();
	let pool = Pool::create("rproxy_mbufs", mbufs, cache);
	step(tests, "mempool", pool.as_ref().map(|_| format!("{mbufs} mbufs, cache {cache}")).map_err(Clone::clone)).map_err(fail)?;
	let pool = pool.map_err(fail)?;
	let burst = spec.burst();

	// the check first, on rproxy's own loopback port, before any real port starts
	let checked = (|| {
		let check = Port::by_name(DPDK_CHECK_PORT)?;
		check.setup(pool, 1, 1, 1024, 1024).map_err(|e| format!("{DPDK_CHECK_PORT}: {e}"))?;
		let mac = check.mac()?;
		let r = rproxy_dpdk::selftest::scenario(&mut RingWire { port: check, pool }, mac, burst);
		check.stop();
		r.map(|()| format!("ARP and UDP both ways, {burst} datagrams of {} sizes, checksums and payload compared", rproxy_dpdk::selftest::SIZES.len()))
	})();
	step(tests, "test datagrams", checked).map_err(|e| fail(format!("startup check (test datagrams through the DPDK path): {e}")))?;

	let mut ports = vec![];
	let mut cfgs = vec![];
	let mut summary = vec![];
	for p in &spec.ports {
		let name = p.name();
		let (rxq, txq, rxd, txd) = p.queues();
		let set_up = (|| {
			let port = Port::by_name(&name)?;
			port.setup(pool, rxq, txq, rxd, txd)?;
			let mac = port.mac()?;
			let deadline = Instant::now() + LINK_WAIT;
			let (mut up, mut speed) = port.link().unwrap_or((false, 0));
			while !up && Instant::now() < deadline {
				std::thread::sleep(Duration::from_millis(100));
				(up, speed) = port.link().unwrap_or((false, 0));
			}
			Ok::<_, String>((port, mac, up, speed))
		})();
		let (port, mac, up, speed) = match set_up {
			Ok(ok) => ok,
			Err(e) => {
				step(tests, format!("port {name}"), Err(e.clone())).ok();
				for p in &ports {
					Port::stop(p);
				}
				return Err(fail(format!("port {name}: {e}")));
			}
		};
		let driver = port.driver();
		let link = if up { format!("link up {speed} Mbit/s") } else { "link down".to_string() };
		step(tests, format!("port {name}"), Ok(format!("{driver} {} {link}, {rxq} RX / {txq} TX queues", mac_text(mac)))).ok();
		if !up {
			warn!(event = "degraded", part = "global.performance.dpdk", port = %name, "the port's link is down");
		}
		summary.push(format!("{name} {}", if up { "up" } else { "down" }));
		let addrs: Vec<(Ipv4Addr, u8)> = p.addresses.iter().filter_map(|a| parse_ipv4_cidr(a).ok()).collect();
		cfgs.push(PortCfg { mac, addrs, gateway: p.gateway.as_deref().and_then(|g| g.trim().parse().ok()) });
		ports.push(port);
	}
	let engine = Arc::new(Engine::new(cfgs));
	let mut lcores = vec![ffi::main_lcore()];
	lcores.extend(ffi::workers());
	let expected = spec.lcores.as_deref().and_then(|l| parse_cpu_list(l).ok()).map(|l| l.len()).unwrap_or(1);
	if lcores.len() != expected {
		debug!(event = "dpdk.lcores", expected, got = lcores.len());
	}
	let stats = Arc::new(IoStats::default());
	let _ = IO_STATS.set(stats.clone());
	let jobs: Vec<(u32, Job<RtRule>)> = lcores
		.iter()
		.enumerate()
		.map(|(i, &lcore)| {
			let mut rx = vec![];
			for (pi, p) in spec.ports.iter().enumerate() {
				for q in 0..p.queues().0 {
					if usize::from(q) % lcores.len() == i {
						rx.push((pi, q));
					}
				}
			}
			let job = Job {
				engine: engine.clone(),
				pool,
				ports: ports.clone(),
				rx,
				txq: i as u16,
				burst,
				sweeper: i == 0,
				stop: stop.clone(),
				stats: stats.clone(),
			};
			(lcore, job)
		})
		.collect();
	let detail = format!(
		"{}; lcores {}; {}",
		ffi::version(),
		lcores.iter().map(|l| l.to_string()).collect::<Vec<_>>().join(","),
		summary.join(", ")
	);
	Ok((detail, (engine, jobs, ports)))
}

/// Stops the lcores and releases the EAL (at exit).
pub fn shutdown() {
	let Some(d) = DATAPLANE.get() else { return };
	d.stop.store(true, Ordering::Relaxed);
	let main = d.main.lock().unwrap_or_else(|e| e.into_inner()).take();
	if let Some(main) = main {
		let _ = main.join();
	}
	// what the lcores counted, once at the end (nothing watches them while they run)
	let (c, io) = (&d.engine.counters, IO_STATS.get().cloned().unwrap_or_default());
	let n = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed);
	info!(event = "dpdk.stop", rx = n(&io.rx), tx = n(&io.tx), tx_full = n(&io.tx_full), chained = n(&io.chained), no_mbuf = n(&io.no_mbuf),
		not_ours = n(&c.not_ours), fragments = n(&c.fragments), malformed = n(&c.malformed), no_neighbor = n(&c.no_neighbor), nat_full = n(&c.nat_full));
}

/// A UDP rule's address taken by the DPDK path (`Registry`'s binding step).
pub struct Claim {
	ip: Ipv4Addr,
	port: u16,
	count: u16,
}

/// Whether the UDP rule `spec` listening on `ip` belongs to the DPDK path:
/// None when DPDK is not active or `ip` is not a DPDK port's address. Rules
/// on a DPDK address that use what the DPDK path cannot do are refused (the
/// kernel has no such address to bind).
pub fn claim(spec: &RuleSpec, ip: IpAddr) -> Option<Result<Claim, ApiError>> {
	let d = DATAPLANE.get()?;
	let IpAddr::V4(v4) = ip else { return None };
	if !d.engine.owns(v4) {
		return None;
	}
	let at = SocketAddr::new(ip, spec.key.listen.port());
	let unsupported = if spec.source_ip != SourceIp::Proxy {
		Some(format!("source_ip: {}", spec.source_ip.as_str()))
	} else if spec.runtime_tls().mode != TlsMode::Passthrough {
		Some("tls (DTLS / sni)".to_string())
	} else if spec.http.is_some() {
		Some("http".to_string())
	} else {
		None
	};
	if let Some(what) = unsupported {
		return Some(Err(ApiError::bind_failed(format!(
			"{at}: the address belongs to a DPDK port (global.performance.dpdk), whose UDP path does not support {what}"
		))));
	}
	Some(Ok(Claim { ip: v4, port: spec.key.listen.port(), count: spec.port_count }))
}

/// The serving task of a claimed address: registers the rule with the
/// forwarder until `stop` (in a graceful shutdown, open sessions go on until
/// the rule's `kill`, as on the kernel path). True when stopped on purpose.
pub async fn serve(claim: Claim, rt: Arc<Runtime>, stop: CancellationToken) -> bool {
	let Some(d) = DATAPLANE.get() else { return false };
	let rule = Arc::new(RtRule { rt: rt.clone(), phase: AtomicU8::new(OPEN) });
	if let Err(e) = d.engine.register(claim.ip, claim.port, claim.count, rule.clone()) {
		warn!(event = "dpdk.rule", rule = %rt.key, error = %e);
		return false;
	}
	info!(event = "dpdk.rule", rule = %rt.key, listen = %claim.ip, ports = claim.count, "forwarded by DPDK");
	stop.cancelled().await;
	if crate::core::shutdown::draining() {
		rule.phase.store(DRAINING, Ordering::Relaxed);
		rt.kill.cancelled().await;
	}
	rule.phase.store(CLOSED, Ordering::Relaxed);
	d.engine.unregister(claim.ip, claim.port, claim.count, &rule);
	true
}

const OPEN: u8 = 0;
const DRAINING: u8 = 1;
const CLOSED: u8 = 2;

/// A rule as the forwarder sees it: the same checks, counters and logs as
/// the kernel path (`l4::udp`).
pub struct RtRule {
	rt: Arc<Runtime>,
	phase: AtomicU8,
}

pub struct RtSession {
	lease: Option<Lease>,
	_permit: Option<Permit>,
	up: Gate,
	down: Gate,
	rx: u64,
	tx: u64,
	started: Instant,
}

fn v4(a: SocketAddr) -> Option<SocketAddrV4> {
	match a {
		SocketAddr::V4(a) => Some(a),
		SocketAddr::V6(a) => a.ip().to_ipv4_mapped().map(|ip| SocketAddrV4::new(ip, a.port())),
	}
}

impl RtRule {
	fn denied(&self, client: SocketAddrV4, reason: &'static str) {
		let rt = &self.rt;
		rt.stats.denied();
		let client = SocketAddr::V4(client);
		match rt.denied_log.check(&client.ip()) {
			Some(suppressed) => info!(event = "conn.denied", rule = %rt.key, client = %client, reason, sni = "", suppressed),
			None => debug!(event = "conn.denied", rule = %rt.key, client = %client, reason, throttled = true),
		}
	}

	/// The best target with an IPv4 address (by `balance`).
	fn pick(&self, offset: u16, skip: Option<&Arc<Member>>) -> Option<(SocketAddrV4, Lease)> {
		self.rt.pool().order().into_iter().filter(|m| !skip.is_some_and(|s| Arc::ptr_eq(s, m))).find_map(|m: Arc<Member>| {
			let addr = m.addrs(offset).into_iter().find_map(v4)?;
			Some((addr, Lease::new(m)))
		})
	}
}

impl Rule for RtRule {
	type Session = RtSession;

	fn phase(&self) -> Phase {
		match self.phase.load(Ordering::Relaxed) {
			OPEN => Phase::Open,
			DRAINING => Phase::Draining,
			_ => Phase::Closed,
		}
	}

	fn admit(&self, client: SocketAddrV4) -> bool {
		let rt = &self.rt;
		let ip = IpAddr::V4(*client.ip());
		if !rt.allowed(ip) {
			self.denied(client, "allow_from");
			return false;
		}
		if let Err(info) = rt.geoip_check(ip) {
			rt.geoip_denied(SocketAddr::V4(client), &info, None, true);
			return false;
		}
		if rt.crowdsec_blocks(ip) {
			self.denied(client, "crowdsec");
			return false;
		}
		if rt.limits.get().is_some_and(|l| !l.packet(ip)) {
			limits::refused(rt, SocketAddr::V4(client), Reason::Packets, "udp");
			return false;
		}
		true
	}

	fn open(&self, client: SocketAddrV4, listen: SocketAddrV4, offset: u16) -> Option<(SocketAddrV4, RtSession)> {
		let rt = &self.rt;
		let ip = IpAddr::V4(*client.ip());
		// PATCH may have changed tls in place; the DPDK path only passes datagrams on
		if rt.tls().mode() != TlsMode::Passthrough {
			rt.stats.dropped();
			warn!(event = "conn.error", rule = %rt.key, client = %client, error = "tls is not supported on the DPDK path");
			return None;
		}
		let permit = match rt.limits.get().map(|l| l.admit(ip)) {
			None => None,
			Some(Ok(p)) => Some(p),
			Some(Err(reason)) => {
				limits::refused(rt, SocketAddr::V4(client), reason, "udp");
				return None;
			}
		};
		let Some((target, lease)) = self.pick(offset, None) else {
			rt.stats.dropped();
			warn!(event = "conn.error", rule = %rt.key, client = %client, error = "no resolved IPv4 target (the DPDK path is IPv4 only)");
			return None;
		};
		rt.stats.opened();
		let geo = rt.geo_for_log(ip, None);
		info!(event = "conn.open", rule = %rt.key, listen = %listen, client = %client, target = %target, sni = "",
			country = geo.as_ref().and_then(|g| g.country_str()), asn = geo.and_then(|g| g.asn), path = "dpdk");
		Some((
			target,
			RtSession { lease: Some(lease), _permit: permit, up: Gate::new(ip, Dir::Up), down: Gate::new(ip, Dir::Down), rx: 0, tx: 0, started: Instant::now() },
		))
	}

	fn up(&self, s: &mut RtSession, len: usize) -> bool {
		if !s.up.admit(&self.rt.bandwidth, len) {
			self.rt.stats.bandwidth_dropped();
			return false;
		}
		s.rx += len as u64;
		self.rt.stats.add_rx(len as u64);
		true
	}

	fn down(&self, s: &mut RtSession, len: usize) -> bool {
		if !s.down.admit(&self.rt.bandwidth, len) {
			self.rt.stats.bandwidth_dropped();
			return false;
		}
		s.tx += len as u64;
		self.rt.stats.add_tx(len as u64);
		true
	}

	fn dropped(&self) {
		self.rt.stats.dropped();
	}

	fn idle(&self) -> Duration {
		*self.rt.udp_idle.borrow()
	}

	fn retarget(&self, s: &mut RtSession, offset: u16, current: SocketAddrV4) -> Option<SocketAddrV4> {
		let member = s.lease.as_ref().map(|l| l.member().clone())?;
		let next = if self.rt.pool().contains(&member) && member.is_up() {
			// the same target; its address may have changed (name resolution)
			let addr = member.addrs(offset).into_iter().find_map(v4)?;
			(addr != current).then_some((addr, None))
		} else {
			self.pick(offset, Some(&member)).map(|(a, l)| (a, Some(l)))
		};
		let (addr, lease) = next?;
		info!(event = "conn.retarget", rule = %self.rt.key, from = %current, to = %addr, path = "dpdk");
		if let Some(lease) = lease {
			s.lease = Some(lease);
		}
		Some(addr)
	}

	fn close(&self, s: RtSession, client: SocketAddrV4, target: SocketAddrV4, reason: &'static str) {
		self.rt.stats.closed();
		info!(event = "conn.close", rule = %self.rt.key, client = %client, target = %target, rx_bytes = s.rx, tx_bytes = s.tx,
			duration_ms = s.started.elapsed().as_millis() as u64, reason, path = "dpdk");
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn eal_arguments() {
		let spec: DpdkSpec = crate::config::from_yaml(
			"{enabled: true, lcores: '2-3', eal_args: ['--in-memory'], ports: [{pci: '0000:3b:00.0', tx_queues: 2, addresses: ['10.0.0.2/24']}, {vdev: 'net_tap0,iface=x', tx_queues: 2, addresses: ['10.1.0.2/24']}]}",
		)
		.unwrap();
		spec.check().unwrap();
		assert_eq!(
			eal_args(&spec),
			["rproxy-api", "-l", "2-3", "-a", "0000:3b:00.0", "--vdev", "net_tap0,iface=x", "--vdev", DPDK_CHECK_PORT, "--in-memory"]
		);
	}
}
