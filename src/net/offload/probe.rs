//! The startup probe of the kernel fast paths (#260, owner's decision): before
//! a fast path is used, test data is pushed through it and compared (not
//! version checks: distributions backport and disable features). What does not
//! pass falls back to the current path with the reason.
//!
//! - At startup (`run(.., Scope::Requested)`) only the fast paths the settings
//!   ask for are tested; nothing runs when none is asked for. `main` logs one
//!   `performance.probe` line per requested feature, `degraded` when it falls
//!   back (or stops when its `fallback` is false), and `publish`es the result
//!   for `GET /capabilities` (`performance`).
//! - `rproxy-api --check-kernel` (`Scope::All`) runs every test and prints
//!   `to_text` (or the JSON of the report).
//!
//! Each fast path is one `PathSpec`: its setting (`key` = `mode`), whether
//! the settings ask for it, and its test. A fast path that is not built in
//! reports why.

use std::sync::OnceLock;

use serde::Serialize;

use super::host::Host;
use crate::config::offload::{TcpOffload, XdpMode};
use crate::config::performance::Effective;

/// Which fast paths `run` tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
	/// Those the settings ask for (startup).
	Requested,
	/// All of them (`--check-kernel`).
	All,
}

/// One step of a test and how it went.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Test {
	pub name: String,
	pub ok: bool,
	#[serde(skip_serializing_if = "String::is_empty")]
	pub detail: String,
}

/// The result of one fast path's test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
	pub usable: bool,
	/// When usable: how it runs (e.g. `generic, copy`); else why not.
	pub detail: String,
	pub tests: Vec<Test>,
}

impl Outcome {
	pub fn unusable(reason: impl Into<String>, tests: Vec<Test>) -> Outcome {
		Outcome { usable: false, detail: reason.into(), tests }
	}
}

/// A fast path: `key` = `mode` in the settings.
pub struct PathSpec {
	/// `ebpf.tcp`, `xdp.mode`
	pub key: &'static str,
	pub mode: &'static str,
	/// The feature it belongs to (`Feature::name`).
	pub feature: &'static str,
	pub requested: fn(&Effective) -> bool,
	pub test: fn(&Host, &Effective) -> Outcome,
}

/// The fast paths this build knows, in the order of the table.
pub const PATHS: &[PathSpec] = &[
	PathSpec { key: "ebpf.tcp", mode: "sockmap", feature: "ebpf_tcp", requested: |e| e.ebpf.tcp == TcpOffload::Sockmap, test: test_sockmap },
	PathSpec { key: "ebpf.tcp", mode: "nat", feature: "ebpf_tcp", requested: |e| e.ebpf.tcp == TcpOffload::Nat, test: test_tcp_nat },
	PathSpec { key: "xdp.mode", mode: "af_xdp", feature: "xdp", requested: |e| e.xdp.mode == XdpMode::AfXdp, test: test_af_xdp },
	PathSpec { key: "xdp.mode", mode: "native", feature: "xdp", requested: |e| e.xdp.mode == XdpMode::Native, test: test_xdp_native },
	// the DPDK data plane for L4 UDP (#261): not the kernel's, but probed the same way (builds with `dpdk`)
	#[cfg(feature = "dpdk")]
	PathSpec { key: "dpdk.enabled", mode: "true", feature: "dpdk", requested: |e| e.dpdk.as_ref().is_some_and(|d| d.enabled()), test: test_dpdk },
];

/// DPDK: hugepages, EAL, ports, and test datagrams through the forwarder (`l4::dpdk::test`).
#[cfg(feature = "dpdk")]
fn test_dpdk(_: &Host, perf: &Effective) -> Outcome {
	crate::l4::dpdk::test(perf.dpdk.as_ref())
}

/// One fast path in the report.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PathResult {
	#[serde(skip)]
	pub feature: &'static str,
	pub key: &'static str,
	pub mode: &'static str,
	pub requested: bool,
	pub usable: bool,
	pub detail: String,
	pub tests: Vec<Test>,
}

/// One feature of `GET /capabilities` `performance` and the
/// `performance.probe` line.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Feature {
	/// `ebpf_tcp`, `xdp`
	pub name: &'static str,
	/// The setting asked for (`off` when none).
	pub requested: &'static str,
	/// The fast path is in use.
	pub active: bool,
	/// How it runs when active.
	pub mode: Option<String>,
	/// Why it is not in use, when requested.
	pub reason: Option<String>,
	/// `global.performance.<key>` (the `part` of `degraded`).
	#[serde(skip)]
	pub part: &'static str,
	/// Use the current path when not usable (else startup stops).
	#[serde(skip)]
	pub fallback: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Report {
	pub host: Host,
	pub paths: Vec<PathResult>,
	pub features: Vec<Feature>,
}

impl Report {
	/// Every requested fast path passed.
	pub fn ok(&self) -> bool {
		self.paths.iter().all(|p| !p.requested || p.usable)
	}
}

/// The features, all off (before `run`, or when nothing is requested).
fn features_of(perf: &Effective, paths: &[PathResult]) -> Vec<Feature> {
	let mut out = vec![];
	#[allow(unused_mut)]
	let mut features = vec![
		("ebpf_tcp", "global.performance.ebpf.tcp", perf.ebpf.tcp.as_str(), perf.ebpf.fallback),
		("xdp", "global.performance.xdp.mode", perf.xdp.mode.as_str(), perf.xdp.fallback),
	];
	#[cfg(feature = "dpdk")]
	{
		let d = perf.dpdk.as_ref().filter(|d| d.enabled());
		features.push(("dpdk", "global.performance.dpdk", if d.is_some() { "on" } else { "off" }, d.is_none_or(|d| d.fallback())));
	}
	for (name, part, requested, fallback) in features {
		let path = paths.iter().find(|p| p.requested && p.feature == name);
		let (active, mode, reason) = match path {
			Some(p) if p.usable => (true, Some(p.detail.clone()), None),
			Some(p) => (false, None, Some(p.detail.clone())),
			None => (false, None, None),
		};
		out.push(Feature { name, requested, active, mode, reason, part, fallback });
	}
	out
}

/// Tests the fast paths of `scope`. Blocking (it may create sockets,
/// namespaces and BPF objects and wait for test data).
pub fn run(perf: &Effective, scope: Scope) -> Report {
	let wanted: Vec<&PathSpec> = PATHS.iter().filter(|s| scope == Scope::All || (s.requested)(perf)).collect();
	if wanted.is_empty() {
		return Report { host: Host::default(), paths: vec![], features: features_of(perf, &[]) };
	}
	let host = Host::inspect();
	let paths: Vec<PathResult> = wanted
		.into_iter()
		.map(|s| {
			let o = (s.test)(&host, perf);
			PathResult { feature: s.feature, key: s.key, mode: s.mode, requested: (s.requested)(perf), usable: o.usable, detail: o.detail, tests: o.tests }
		})
		.collect();
	let features = features_of(perf, &paths);
	Report { host, paths, features }
}

static PUBLISHED: OnceLock<Vec<Feature>> = OnceLock::new();

/// Keeps the startup result for `GET /capabilities`; once.
pub fn publish(features: Vec<Feature>) {
	let _ = PUBLISHED.set(features);
}

/// `GET /capabilities` `performance`: `{feature: {requested, active, mode, reason}}`.
pub fn capabilities() -> serde_json::Value {
	let features = match PUBLISHED.get() {
		Some(f) => f.clone(),
		None => features_of(&crate::config::performance::resolve(None, &Default::default(), &[0], 1), &[]),
	};
	let mut out = serde_json::Map::new();
	for f in features {
		out.insert(f.name.to_string(), serde_json::json!({"requested": f.requested, "active": f.active, "mode": f.mode, "reason": f.reason}));
	}
	serde_json::Value::Object(out)
}

/// The `--check-kernel` table.
pub fn to_text(r: &Report) -> String {
	let h = &r.host;
	let mut out = String::new();
	let memlock = match h.memlock {
		None => "unlimited".to_string(),
		Some(n) => format!("{} KiB", n / 1024),
	};
	let caps = if h.capabilities.is_empty() { "none".to_string() } else { h.capabilities.join(" ") };
	out.push_str(&format!("kernel:        {}\n", h.kernel));
	out.push_str(&format!("capabilities:  {caps}\n"));
	out.push_str(&format!("memlock:       {memlock}\n"));
	out.push_str(&format!("BTF:           {}\n", if h.btf { "yes" } else { "no" }));
	out.push_str(&format!("lockdown:      {}\n", h.lockdown.as_deref().unwrap_or("-")));
	out.push_str(&format!(
		"unprivileged_bpf_disabled: {}\n",
		h.unprivileged_bpf_disabled.map(|n| n.to_string()).unwrap_or_else(|| "-".into())
	));
	out.push_str(&format!("bpf(2):        {}\n\n", h.bpf_error.as_deref().unwrap_or("ok")));
	let rows: Vec<[String; 4]> = r
		.paths
		.iter()
		.map(|p| {
			[
				format!("{}={}", p.key, p.mode),
				if p.requested { "yes" } else { "no" }.to_string(),
				if p.usable { "usable" } else { "unavailable" }.to_string(),
				p.detail.clone(),
			]
		})
		.collect();
	let head = ["fast path".to_string(), "requested".into(), "result".into(), "detail".into()];
	let width = |i: usize| rows.iter().chain(std::iter::once(&head)).map(|r| r[i].len()).max().unwrap_or(0);
	let (w0, w1, w2) = (width(0), width(1), width(2));
	for row in std::iter::once(&head).chain(rows.iter()) {
		out.push_str(format!("{:<w0$}  {:<w1$}  {:<w2$}  {}", row[0], row[1], row[2], row[3]).trim_end());
		out.push('\n');
	}
	for p in &r.paths {
		for t in p.tests.iter().filter(|t| !t.ok || !t.detail.is_empty()) {
			out.push_str(&format!("  {}={} {}: {}{}\n", p.key, p.mode, t.name, if t.ok { "ok" } else { "failed" }, if t.detail.is_empty() { String::new() } else { format!(" ({})", t.detail) }));
		}
	}
	out
}

/// The fast paths not built in yet report this (after the privileges).
const NOT_BUILT: &str = "not in this build yet (#260)";

fn not_built(host: &Host, needs_net_bpf: bool) -> Outcome {
	if needs_net_bpf {
		if let Some(why) = host.missing_for_net_bpf() {
			return Outcome::unusable(why, vec![]);
		}
		if let Some(e) = &host.bpf_error {
			return Outcome::unusable(format!("bpf(2) failed: {e}"), vec![]);
		}
	}
	Outcome::unusable(NOT_BUILT, vec![])
}

/// sockmap: loopback TCP pairs spliced in the kernel, data compared.
fn test_sockmap(host: &Host, _perf: &Effective) -> Outcome {
	not_built(host, true)
}

/// TC / XDP NAT: packets through a temporary namespace and veth pair.
fn test_tcp_nat(host: &Host, _perf: &Effective) -> Outcome {
	not_built(host, true)
}

/// AF_XDP: UDP round trips over a veth pair (zero-copy, then copy).
fn test_af_xdp(host: &Host, _perf: &Effective) -> Outcome {
	not_built(host, true)
}

/// XDP forwarding by the program alone (stage 2).
fn test_xdp_native(host: &Host, _perf: &Effective) -> Outcome {
	not_built(host, true)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::performance::{resolve, EnvKnobs, PerformanceSpec};

	fn perf(yaml: &str) -> Effective {
		let spec: PerformanceSpec = crate::config::from_yaml(yaml).unwrap();
		resolve(Some(&spec), &EnvKnobs::default(), &[0], 1)
	}

	#[test]
	fn nothing_requested_runs_nothing() {
		let r = run(&perf("{}"), Scope::Requested);
		assert!(r.paths.is_empty() && r.ok());
		assert_eq!(r.host, Host::default(), "the host is not even inspected");
		assert_eq!(r.features.iter().map(|f| (f.name, f.requested, f.active)).collect::<Vec<_>>(), [("ebpf_tcp", "off", false), ("xdp", "off", false)]);
		let caps = capabilities();
		assert_eq!(caps["ebpf_tcp"], serde_json::json!({"requested": "off", "active": false, "mode": null, "reason": null}));
		assert_eq!(caps["xdp"]["requested"], "off");
	}

	#[test]
	fn requested_paths_fall_back_with_a_reason() {
		let p = perf("{ebpf: {tcp: sockmap}, xdp: {mode: af_xdp, fallback: false}}");
		let r = run(&p, Scope::Requested);
		assert_eq!(r.paths.iter().map(|p| (p.key, p.mode, p.requested)).collect::<Vec<_>>(), [("ebpf.tcp", "sockmap", true), ("xdp.mode", "af_xdp", true)]);
		assert!(!r.ok(), "no fast path is built in yet");
		let tcp = &r.features[0];
		assert_eq!((tcp.name, tcp.requested, tcp.active, tcp.fallback, tcp.part), ("ebpf_tcp", "sockmap", false, true, "global.performance.ebpf.tcp"));
		assert!(tcp.reason.as_deref().is_some_and(|r| !r.is_empty()), "{tcp:?}");
		assert!(!r.features[1].fallback);

		let all = run(&p, Scope::All);
		assert_eq!(all.paths.len(), PATHS.len());
		assert_eq!(all.paths.iter().filter(|p| p.requested).count(), 2);
		let text = to_text(&all);
		assert!(text.contains("ebpf.tcp=sockmap") && text.contains("xdp.mode=native") && text.contains("kernel:"), "{text}");
	}

	#[test]
	fn reasons_name_the_missing_privilege_first() {
		let h = Host::default();
		assert_eq!(not_built(&h, true).detail, "missing CAP_BPF (or CAP_SYS_ADMIN)");
		let h = Host { cap_eff: 1 << super::super::host::CAP_SYS_ADMIN, ..Default::default() };
		assert_eq!(not_built(&h, true).detail, NOT_BUILT);
		let h = Host { cap_eff: 1 << super::super::host::CAP_SYS_ADMIN, bpf_error: Some("EPERM".into()), ..Default::default() };
		assert_eq!(not_built(&h, true).detail, "bpf(2) failed: EPERM");
	}
}
