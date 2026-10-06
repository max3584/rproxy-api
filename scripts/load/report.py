#!/usr/bin/env python3
"""Markdown tables of the load test results (scripts/load/load.py), with deltas
against an earlier run.

    scripts/load/report.py results.json [previous.json] > summary.md
"""

import json
import sys

# key: (column label, format, +1 when higher is better / -1 when lower is better / 0 neutral)
METRICS = {
	"gbps": ("Gbit/s", "{:.2f}", 1),
	"gbps_min": ("min Gbit/s", "{:.2f}", 1),
	"req_s": ("req/s", "{:,.0f}", 1),
	"rps": ("round trips/s", "{:,.0f}", 1),
	"conns_per_s": ("conns/s", "{:,.0f}", 1),
	"handshakes_s": ("handshakes/s", "{:,.0f}", 1),
	"pps_sent": ("sent pps", "{:,.0f}", 0),
	"pps": ("delivered pps", "{:,.0f}", 1),
	"loss_pct": ("loss %", "{:.3f}", -1),
	"jitter_ms": ("jitter ms", "{:.3f}", -1),
	"dropped": ("rproxy dropped", "{:,}", -1),
	"kernel_drops_middle": ("kernel drops (proxy ns)", "{:,}", -1),
	"kernel_drops_backend": ("kernel drops (backend)", "{:,}", -1),
	"p50_us": ("p50 µs", "{:,}", -1),
	"p99_us": ("p99 µs", "{:,}", -1),
	"max_us": ("max µs", "{:,}", -1),
	"retransmits": ("retransmits", "{:,}", -1),
	"failed": ("failed", "{:,}", -1),
	"verified_gib": ("verified GiB", "{:.1f}", 0),
	"proxy_cpu_s": ("proxy CPU s", "{:.2f}", -1),
	"proxy_cores": ("proxy cores", "{:.2f}", -1),
	"gib_per_proxy_cpu_s": ("GiB / proxy CPU-s", "{:.2f}", 1),
	"req_per_proxy_cpu_s": ("req / proxy CPU-s", "{:,.0f}", 1),
	"rtt_per_proxy_cpu_s": ("round trips / proxy CPU-s", "{:,.0f}", 1),
	"conns_per_proxy_cpu_s": ("conns / proxy CPU-s", "{:,.0f}", 1),
	"handshakes_per_proxy_cpu_s": ("handshakes / proxy CPU-s", "{:,.0f}", 1),
	"datagrams_per_proxy_cpu_s": ("datagrams / proxy CPU-s", "{:,.0f}", 1),
	"sys_cpu_s": ("system CPU s", "{:.2f}", -1),
	"gib_per_sys_cpu_s": ("GiB / system CPU-s", "{:.2f}", 1),
	"rss_peak_mib": ("peak RSS MiB", "{:.1f}", -1),
	"conns": ("conns", "{:,}", 0),
	"sessions": ("sessions", "{:,}", 0),
	"rss_mib": ("RSS MiB", "{:.1f}", -1),
	"fds": ("FDs", "{:,}", -1),
	"kib_per_rule": ("KiB / rule", "{:.1f}", -1),
	"kib_per_conn": ("KiB / conn", "{:.1f}", -1),
	"fds_per_conn": ("FDs / conn", "{:.2f}", -1),
	"kib_per_session": ("KiB / session", "{:.2f}", -1),
	"fds_per_session": ("FDs / session", "{:.2f}", -1),
	"rss_start_mib": ("RSS start MiB", "{:.1f}", -1),
	"rss_end_mib": ("RSS end MiB", "{:.1f}", -1),
	"rss_growth": ("RSS last/first quarter", "{:.2f}", -1),
	"fds_start": ("FDs start", "{:,}", 0),
	"fds_peak": ("FDs peak", "{:,}", 0),
	"fds_end": ("FDs end", "{:,}", -1),
	"bulk_gib": ("bulk GiB", "{:.1f}", 0),
}
# the metric that the "vs direct" column compares, first one present
MAIN = ["gbps", "req_s", "pps", "conns_per_s", "rps"]
TITLES = {
	"tcp": "L4 TCP throughput (iperf3)",
	"verify": "L4 TCP large transfers, every byte verified",
	"tls": "TLS termination",
	"http": "L7 HTTP",
	"udp": "UDP",
	"latency": "Latency (L4 TCP)",
	"churn": "New connections",
	"memory": "Memory (fresh processes)",
	"soak": "Soak",
}
# kept in results.json, left out of the tables to keep them readable
HIDDEN = {"proxy_cpu_s", "sys_cpu_s"}
WORSE = 10.0  # % in the bad direction that gets bold


def fmt(key, v):
	if v is None:
		return "–"
	try:
		return METRICS.get(key, (key, "{}", 0))[1].format(v)
	except (ValueError, TypeError):
		return str(v)


def delta(key, cur, prev):
	if not isinstance(cur, (int, float)) or not isinstance(prev, (int, float)) or prev == 0:
		return ""
	d = (cur - prev) / abs(prev) * 100
	better = METRICS.get(key, ("", "", 0))[2]
	if abs(d) < 1 or not better:
		return ""
	s = f" ({d:+.0f}%)"
	if better and d * better < -WORSE:
		s = f" **({d:+.0f}%)**"
	return s


def compare_builds(data):
	"""One table per scenario with a column per build (git ref) and the change against the first."""
	builds = data.get("meta", {}).get("builds", [])
	names = [b["target"] for b in builds]
	results = data.get("results", [])
	out = ["## Builds compared", "",
		   "Every scenario ran the builds in turn on the same runner (A, B, A, B, ...); the first is the baseline, "
		   f"(+x%) is the change against it, bold is more than {WORSE:.0f}% worse.", ""]
	out += [f"- `{b['target']}`: {b['ref']} `{(b.get('commit') or '')[:10]}` {b.get('version') or ''} · "
			f"{b.get('libc', '?')} · {b.get('allocator', '?')}" for b in builds]
	if len({(b.get("libc"), b.get("allocator")) for b in builds}) > 1:
		out += ["", "**The builds differ in libc or allocator**: part of any difference comes from that."]
	out.append("")
	by = {(r["scenario"], r["case"], r["target"]): r for r in results}
	scenarios = []
	for r in results:
		if r["target"] in names and r["scenario"] not in scenarios:
			scenarios.append(r["scenario"])
	for sc in scenarios:
		cases = []
		for r in results:
			if r["scenario"] == sc and r["target"] in names and r["case"] not in cases:
				cases.append(r["case"])
		out += [f"### {TITLES.get(sc, sc)}", "", "| case | metric | " + " | ".join(f"`{b['ref']}`" for b in builds) + " |",
				"|" + "---|" * (2 + len(builds))]
		for case in cases:
			rows = [by.get((sc, case, n)) for n in names]
			keys = []
			for r in rows:
				for k in (r or {}).get("metrics", {}):
					if k not in keys and k not in HIDDEN and METRICS.get(k, ("", "", 0))[2]:
						keys.append(k)
			keys.sort(key=lambda k: list(METRICS).index(k) if k in METRICS else 999)
			for k in keys:
				base = (rows[0] or {}).get("metrics", {}).get(k)
				cells = []
				for i, r in enumerate(rows):
					v = (r or {}).get("metrics", {}).get(k)
					failed = "" if r is None or r.get("ok", True) else " (FAILED)"
					cells.append(fmt(k, v) + (delta(k, v, base) if i else "") + failed)
				out.append(f"| {case} | {METRICS.get(k, (k,))[0]} | " + " | ".join(cells) + " |")
		out.append("")
	return out


def render(data, prev=None):
	m = data.get("meta", {})
	p = m.get("params", {})
	out = ["# rproxy load test", ""]
	out.append(f"- {m.get('date', '')} · commit `{(m.get('commit') or '')[:10]}` {m.get('ref', '')} · {m.get('rproxy') or ''}")
	for b in m.get("builds", []):
		out.append(f"- {b['target']}: {b.get('ref') or '(local build)'} `{(b.get('commit') or '')[:10]}` · {b.get('version') or ''} · "
				   f"libc {b.get('libc', '?')} · allocator {b.get('allocator', '?')}")
	out.append(f"- {m.get('cpu', '')} · {m.get('nproc', '')} CPUs · {m.get('mem_gib', '')} GiB · kernel {m.get('kernel', '')}")
	out.append(f"- netem: {m.get('netem') or 'none'} · size {p.get('size_mib')} MiB x {p.get('repeat')} · {p.get('duration')} s per run · "
			   f"{p.get('conns')} conns · {p.get('udp_sessions')} UDP sessions · soak {p.get('soak_secs')} s · rproxy log level {p.get('log_level')}")
	if p.get("profile"):
		out.append("- **profiled** (perf record, frame pointers, symbols): the numbers are not comparable with ordinary runs; "
				   "flame graphs in `profile/` of the artifact")
	if prev:
		pm = prev.get("meta", {})
		out.append(f"- compared with {pm.get('date', '?')} (commit `{(pm.get('commit') or '')[:10]}`): (+x%) is the change; "
				   f"bold is more than {WORSE:.0f}% worse. The runners vary, so look for changes that repeat")
	else:
		out.append("- no earlier run to compare with")
	checks = data.get("checks", [])
	failed = [c for c in checks if not c["ok"]]
	out += ["", f"**Checks: {len(checks) - len(failed)} of {len(checks)} passed**", ""]
	for c in failed:
		out.append(f"- FAIL {c['name']}: {c.get('detail', '')}")
	if failed:
		out.append("")
	for s in data.get("skipped", []):
		out.append(f"- skipped: {s}")
	if data.get("skipped"):
		out.append("")

	if len(data.get("meta", {}).get("builds", [])) > 1:
		out += compare_builds(data)
		out += ["# All results", ""]
	old = {}
	if prev:
		for r in prev.get("results", []):
			old[(r["scenario"], r["case"], r["target"])] = r.get("metrics", {})
	results = data.get("results", [])
	direct = {(r["scenario"], r["case"]): r["metrics"] for r in results if r["target"] == "direct"}
	scenarios = []
	for r in results:
		if r["scenario"] not in scenarios:
			scenarios.append(r["scenario"])
	for s in scenarios:
		rows = [r for r in results if r["scenario"] == s]
		keys = []
		for r in rows:
			for k in r["metrics"]:
				if k not in keys and k not in HIDDEN:
					keys.append(k)
		keys.sort(key=lambda k: list(METRICS).index(k) if k in METRICS else 999)
		has_direct = any((s, r["case"]) in direct for r in rows if r["target"] != "direct")
		head = ["case", "target"] + (["vs direct"] if has_direct else []) + [METRICS.get(k, (k,))[0] for k in keys]
		out += [f"## {TITLES.get(s, s)}", "", "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
		for r in rows:
			mt = r["metrics"]
			prevm = old.get((s, r["case"], r["target"]), {})
			cells = [r["case"], r["target"] + ("" if r["ok"] else " (FAILED)")]
			if has_direct:
				d = direct.get((s, r["case"]), {})
				main = next((k for k in MAIN if k in mt and d.get(k)), None)
				cells.append(f"{mt[main] / d[main] * 100:.0f}%" if main and r["target"] != "direct" else "")
			for k in keys:
				cells.append(fmt(k, mt.get(k)) + (delta(k, mt.get(k), prevm.get(k)) if k in mt else ""))
			out.append("| " + " | ".join(cells) + " |")
		notes = [f"{r['target']} / {r['case']}: {r['note']}" for r in rows if r.get("note")]
		out += [""] + [f"- {n}" for n in notes] + ([""] if notes else [])
	out += ["GiB / proxy CPU-s: bytes moved per CPU-second of the proxy process (user + system, all threads). "
			"GiB / system CPU-s: the same over the whole machine (client, backend, kernel forwarding and the proxy), "
			"so it compares with direct. vs direct: the main rate against the same case without a proxy.", ""]
	return "\n".join(out)


if __name__ == "__main__":
	with open(sys.argv[1]) as f:
		cur = json.load(f)
	before = None
	if len(sys.argv) > 2:
		try:
			with open(sys.argv[2]) as f:
				before = json.load(f)
		except OSError:
			pass
	print(render(cur, before))
