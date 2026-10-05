#!/usr/bin/env python3
"""Load and soak tests that measure transfer efficiency (issue #183).

Started by scripts/load/run.sh inside a network namespace (the "rproxy" namespace)
with two more namespaces for the client and the backend:

    client 10.71.1.2 --- 10.71.1.1 [rproxy / HAProxy / router] 10.71.2.1 --- 10.71.2.2 backend

"direct" goes through the same namespace, forwarded by the kernel (no proxy), so
it is the baseline for the same links and netem settings. rproxy and HAProxy run
in the middle namespace; their CPU time, RSS and FD count are read from /proc.

Writes OUT/results.json and OUT/summary.md (scripts/load/report.py, compared with
PREVIOUS when given). The exit code is 1 when a check fails (a corrupted transfer,
a failed scenario, memory or FDs that keep growing in the soak); slower numbers
are only shown as deltas, never a failure.

Settings (environment variables; docs/TESTING.md):
  OUT=load-results  SCENARIOS=tcp,verify,tls,http,udp,latency,churn,memory,soak
  SIZE_MIB=1024 REPEAT=3 DURATION=10 CONNS=2000 UDP_SESSIONS=1000 RULES=100,1000
  UDP_BW=1G UDP_PPS=50000 H2_REQS=200000 H2_CONNS=64 SOAK_SECS=0 HAPROXY=auto
  LOG_LEVEL=warn PREVIOUS=<results.json of an earlier run>
  BINS=label=path,label=path   several rproxy builds (git refs) side by side; the first is the baseline
"""

import datetime
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
import traceback
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report  # noqa: E402

E = os.environ
NS_C, NS_B = E["LOAD_NS_CLIENT"], E["LOAD_NS_BACKEND"]
LOADGEN = E["LOADGEN"]
# the rproxy builds to compare: BINS="label=path,label=path" (one per git ref; the first is the baseline), else BIN
BINS = [tuple(x.split("=", 1)) for x in E.get("BINS", "").split(",") if "=" in x] or [("", E["BIN"])]
BIN = BINS[0][1]
# target names: "rproxy" with one build, "rproxy@<label>" with several
COMMITS = dict(x.split("=", 1) for x in E.get("REF_COMMITS", "").split(",") if "=" in x)
RP_NAMES = ["rproxy"] if len(BINS) == 1 else [f"rproxy@{label}" for label, _ in BINS]
WORK = E["WORK"]
OUT = os.path.abspath(E.get("OUT", "load-results"))
CLIENT, RP_C, RP_B, BACKEND = "10.71.1.2", "10.71.1.1", "10.71.2.1", "10.71.2.2"
# each rproxy build listens on its own address (run.sh adds 10.71.1.11-19), HAProxy on RP_C


def rp_ip(idx):
	return f"10.71.1.{11 + idx}"
API = 18080

ALL = ["tcp", "verify", "tls", "http", "udp", "latency", "churn", "memory", "soak"]
SCENARIOS = [s.strip() for s in E.get("SCENARIOS", ",".join(ALL)).split(",") if s.strip()]
# memory and soak start fresh processes after the shared ones stop, so they run last
SCENARIOS = [s for s in SCENARIOS if s not in ("memory", "soak")] + [s for s in SCENARIOS if s in ("memory", "soak")]
MIB = 1 << 20
SIZE = int(float(E.get("SIZE_MIB", "1024")) * MIB)
REPEAT = int(E.get("REPEAT", "3"))
DURATION = int(E.get("DURATION", "10"))
CONNS = int(E.get("CONNS", "2000"))
UDP_SESSIONS = int(E.get("UDP_SESSIONS", "1000"))
RULES = [int(x) for x in E.get("RULES", "100,1000").split(",") if x.strip()]
UDP_BW = E.get("UDP_BW", "1G")
UDP_PPS = int(E.get("UDP_PPS", "50000"))
H2_REQS = int(E.get("H2_REQS", "200000"))
H2_CONNS = int(E.get("H2_CONNS", "64"))
SOAK_SECS = int(E.get("SOAK_SECS", "0"))
SOAK_BW = E.get("SOAK_BW", "1G")
LOG_LEVEL = E.get("LOG_LEVEL", "warn")
CLK = os.sysconf("SC_CLK_TCK")
NPROC = os.cpu_count() or 1

# backend services (in the backend namespace) and the ports the proxies listen on
SERVICES = {
	# name: (kind, backend port, proxy port offset → rproxy 1xxxx, HAProxy 2xxxx)
	"echo": ("tcp", 9000, 9000),
	"sink": ("tcp", 9001, 9001),
	"http": ("http", 9002, 9002),
	"iperf": ("tcp", 5201, 5201),
	"iperf_udp": ("udp", 5201, 5201),
	"uecho": ("udp", 9003, 9003),
	"usink": ("udp", 9004, 9004),
	"tls_sink": ("tls", 9001, 9443),
	"tls_echo": ("tls", 9000, 9444),
	"https": ("https", 9002, 9445),
}

results = []
checks = []
skipped = []


def log(msg):
	print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def check(name, ok, detail=""):
	checks.append({"name": name, "ok": bool(ok), "detail": detail})
	log(("PASS " if ok else "FAIL ") + name + (f": {detail}" if detail else ""))


def skip(msg):
	skipped.append(msg)
	log(f"skipped: {msg}")


def record(scenario, case, target, metrics, ok=True, note=""):
	m = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in metrics.items() if v is not None}
	results.append({"scenario": scenario, "case": case, "target": target, "metrics": m, "ok": ok, "note": note})
	log(f"{scenario}/{case}/{target}: {json.dumps(m)}{' ' + note if note else ''}")


def ns(which, args):
	return ["nsenter", "-n", "-t", which] + args


def run(args, timeout=None, check_rc=True):
	p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
	if check_rc and p.returncode != 0:
		raise RuntimeError(f"{' '.join(args[:6])}... exited {p.returncode}: {p.stderr.strip()[-800:]}")
	return p


def last_json(text):
	for line in reversed(text.strip().splitlines()):
		line = line.strip()
		if line.startswith("{"):
			return json.loads(line)
	raise RuntimeError(f"no JSON in output: {text[-500:]}")


def have(tool):
	return shutil.which(tool) is not None


# ---------------------------------------------------------------- /proc

def cpu_s(pid):
	with open(f"/proc/{pid}/stat") as f:
		fields = f.read().rsplit(")", 1)[1].split()
	return (int(fields[11]) + int(fields[12])) / CLK


def rss_kib(pid):
	with open(f"/proc/{pid}/status") as f:
		for line in f:
			if line.startswith("VmRSS:"):
				return int(line.split()[1])
	return 0


def fd_count(pid):
	return len(os.listdir(f"/proc/{pid}/fd"))


def sys_busy():
	with open("/proc/stat") as f:
		v = [int(x) for x in f.readline().split()[1:]]
	return (sum(v[:8]) - v[3] - v[4]) / CLK  # everything but idle and iowait


def snmp(which=None):
	"""UDP counters of a namespace (InErrors, RcvbufErrors)."""
	text = run(ns(which, ["cat", "/proc/net/snmp"]) if which else ["cat", "/proc/net/snmp"]).stdout
	lines = [line.split() for line in text.splitlines() if line.startswith("Udp:")]
	d = dict(zip(lines[0][1:], (int(x) for x in lines[1][1:])))
	return d.get("RcvbufErrors", 0) + d.get("SndbufErrors", 0)


class Meter:
	"""CPU time (the proxy's and the whole machine's), wall time and peak RSS over a block.
	Reused for several blocks, it adds them up (repeated runs interleaved with other targets)."""

	def __init__(self, proxy):
		self.pid = proxy.pid
		self.wall = self.sys_cpu = 0.0
		self.proxy_cpu = 0.0 if self.pid else None
		self.peak = 0

	def __enter__(self):
		self.t0, self.sys0 = time.monotonic(), sys_busy()
		self.cpu0 = cpu_s(self.pid) if self.pid else 0
		self.stop = threading.Event()
		if self.pid:
			threading.Thread(target=self.sample, args=(self.stop,), daemon=True).start()
		return self

	def sample(self, stop):
		while not stop.is_set():
			try:
				self.peak = max(self.peak, rss_kib(self.pid))
			except OSError:
				return
			stop.wait(0.2)

	def __exit__(self, *exc):
		self.stop.set()
		self.wall += time.monotonic() - self.t0
		self.sys_cpu += sys_busy() - self.sys0
		if self.pid:
			self.proxy_cpu += cpu_s(self.pid) - self.cpu0
		return False

	def metrics(self, nbytes=None, units=None, unit_name=None):
		m = {"sys_cpu_s": self.sys_cpu}
		if self.pid:
			m["proxy_cpu_s"] = self.proxy_cpu
			m["proxy_cores"] = self.proxy_cpu / self.wall if self.wall else None
			m["rss_peak_mib"] = self.peak / 1024
		if nbytes:
			m["gib_per_sys_cpu_s"] = nbytes / (1 << 30) / self.sys_cpu if self.sys_cpu else None
			if self.pid and self.proxy_cpu:
				m["gib_per_proxy_cpu_s"] = nbytes / (1 << 30) / self.proxy_cpu
		if units and unit_name and self.pid and self.proxy_cpu:
			m[f"{unit_name}_per_proxy_cpu_s"] = units / self.proxy_cpu
		return m


# ---------------------------------------------------------------- targets

class Direct:
	name = "direct"
	pid = None

	def addr(self, service):
		kind, port, _ = SERVICES[service]
		if kind in ("tls", "https"):
			return None
		return BACKEND, port

	def url(self, service):
		a = self.addr(service)
		return a and f"http://{a[0]}:{a[1]}"

	def stop(self):
		pass


class Rproxy:
	def __init__(self, label, services=(), udp_idle=30, idx=0):
		self.label, self.udp_idle, self.idx = label, udp_idle, idx
		self.name, self.ip, self.api_port = RP_NAMES[idx], rp_ip(idx), API + idx
		self.log = open(os.path.join(WORK, f"rproxy-{label}-{idx}.log"), "w")
		env = dict(E, RPROXY_API_PORT=str(self.api_port), RPROXY_LOG_LEVEL=LOG_LEVEL)
		for k in list(env):
			if k.startswith("RPROXY_") and k not in ("RPROXY_API_PORT", "RPROXY_LOG_LEVEL"):
				del env[k]
		self.proc = subprocess.Popen([BINS[idx][1]], cwd=WORK, env=env, stdout=self.log, stderr=subprocess.STDOUT)
		self.pid = self.proc.pid
		for _ in range(100):
			try:
				self.api("GET", "/healthz")
				break
			except OSError:
				time.sleep(0.1)
		else:
			raise RuntimeError(f"rproxy did not start: {open(self.log.name).read()[-2000:]}")
		for s in services:
			self.add(s)

	def api(self, method, path, body=None):
		req = urllib.request.Request(f"http://127.0.0.1:{self.api_port}{path}", method=method,
									 data=json.dumps(body).encode() if body is not None else None,
									 headers={"Content-Type": "application/json"})
		with urllib.request.urlopen(req, timeout=30) as r:
			data = r.read()
			return json.loads(data) if data and data[:1] in b"[{" else data

	def port(self, service):
		return 10000 + SERVICES[service][2]

	def add(self, service, port=None, backend_port=None):
		kind, bport, _ = SERVICES[service]
		port = port or self.port(service)
		body = {"protocol": "udp" if kind == "udp" else "tcp", "listen_addr": self.ip, "listen_port": port}
		if kind == "udp":
			body["udp_idle_secs"] = self.udp_idle
		if kind in ("http", "https"):
			body["http"] = {"routes": [{"name": "all", "match": "PathPrefix(`/`)", "to": f"http://{BACKEND}:{bport}"}]}
		else:
			body.update(remote_addr=BACKEND, remote_port=backend_port or bport)
		if kind in ("tls", "https"):
			body["tls"] = {"mode": "terminate", "certificates": [{"cert_file": CERT, "key_file": KEY}]}
		self.api("POST", "/rules", body)

	def addr(self, service):
		return self.ip, self.port(service)

	def url(self, service):
		scheme = "https" if SERVICES[service][0] == "https" else "http"
		return f"{scheme}://{self.ip}:{self.port(service)}"

	def rule_stats(self, service):
		port = self.port(service)
		proto = "udp" if SERVICES[service][0] == "udp" else "tcp"
		rules = self.api("GET", "/rules")
		rules = rules.get("rules", rules) if isinstance(rules, dict) else rules
		for r in rules:
			if r.get("listen_port") == port and r.get("protocol") == proto:
				return r
		return {}

	def connections(self):
		rules = self.api("GET", "/rules")
		rules = rules.get("rules", rules) if isinstance(rules, dict) else rules
		return sum(r.get("connections", 0) for r in rules)

	def stop(self):
		if self.proc.poll() is None:
			self.proc.terminate()
			try:
				self.proc.wait(timeout=20)
			except subprocess.TimeoutExpired:
				self.proc.kill()
				self.proc.wait()
		self.log.close()


class Haproxy:
	name = "haproxy"

	def __init__(self, label):
		cfg = os.path.join(WORK, f"haproxy-{label}.cfg")
		lines = ["global", "  maxconn 400000", "defaults", "  timeout connect 5s", "  timeout client 1h",
				 "  timeout server 1h", "  timeout tunnel 1h", "  maxconn 400000"]
		for s, (kind, bport, off) in SERVICES.items():
			if kind == "udp":
				continue
			port = 20000 + off
			ssl = f" ssl crt {HAPEM} alpn h2,http/1.1" if kind in ("tls", "https") else ""
			mode = "http" if kind in ("http", "https") else "tcp"
			lines += [f"listen {s}", f"  mode {mode}", f"  bind {RP_C}:{port}{ssl}", f"  server b {BACKEND}:{bport}"]
		with open(cfg, "w") as f:
			f.write("\n".join(lines) + "\n")
		self.log = open(os.path.join(WORK, f"haproxy-{label}.log"), "w")
		self.proc = subprocess.Popen(["haproxy", "-db", "-f", cfg], stdout=self.log, stderr=subprocess.STDOUT)
		self.pid = self.proc.pid
		time.sleep(1)
		if self.proc.poll() is not None:
			raise RuntimeError(f"haproxy did not start: {open(self.log.name).read()[-2000:]}")

	def addr(self, service):
		kind, _, off = SERVICES[service]
		return None if kind == "udp" else (RP_C, 20000 + off)

	def url(self, service):
		a = self.addr(service)
		scheme = "https" if SERVICES[service][0] == "https" else "http"
		return a and f"{scheme}://{a[0]}:{a[1]}"

	def stop(self):
		self.proc.terminate()
		try:
			self.proc.wait(timeout=20)
		except subprocess.TimeoutExpired:
			self.proc.kill()
		self.log.close()


def use_haproxy():
	h = E.get("HAPROXY", "auto")
	return h != "0" and have("haproxy")


def hostport(a):
	return f"{a[0]}:{a[1]}"


# ---------------------------------------------------------------- scenarios

def iperf3(a, args):
	"""iperf3 -J; the server takes one test at a time and may still be finishing the last one: retry a few times."""
	for attempt in range(4):
		p = run(ns(NS_C, ["iperf3", "-c", a[0], "-p", str(a[1]), "-J"] + args), timeout=DURATION + 60, check_rc=False)
		if p.returncode == 0:
			return p
		time.sleep(2 + attempt * 2)
	raise RuntimeError(f"iperf3 exited {p.returncode}: {(p.stdout + p.stderr).strip()[-300:]}")


def sc_tcp(targets):
	"""Raw TCP throughput with iperf3 (upload with 1 and 8 streams, download with 1)."""
	if not have("iperf3"):
		skip("tcp: iperf3 is not installed")
		return
	for case, extra in (("upload 1 stream", ["-P", "1"]), ("upload 8 streams", ["-P", "8"]), ("download 1 stream", ["-P", "1", "-R"])):
		for t in targets:
			a = t.addr("iperf")
			try:
				with Meter(t) as m:
					p = iperf3(a, ["-t", str(DURATION)] + extra)
				j = json.loads(p.stdout)
				recv = j["end"]["sum_received"]
				met = {"gbps": recv["bits_per_second"] / 1e9, "retransmits": j["end"]["sum_sent"].get("retransmits")}
				met.update(m.metrics(nbytes=recv["bytes"]))
				record("tcp", case, t.name, met)
			except Exception as e:  # noqa: BLE001
				record("tcp", case, t.name, {}, ok=False, note=str(e)[:300])
				check(f"tcp {case} via {t.name}", False, str(e)[:300])


def repeated(scenario, case, targets, one):
	"""one(t, i) -> (bytes, Gbit/s, error or None), REPEAT times for every target, interleaved
	(A, B, C, A, B, C, ...) so that the runner's ups and downs hit every target alike."""
	st = {t.name: {"m": Meter(t), "total": 0, "gbps": [], "bad": []} for t in targets}
	for i in range(REPEAT):
		for t in targets:
			x = st[t.name]
			try:
				with x["m"]:
					nbytes, gbps, err = one(t, i)
				x["total"] += nbytes
				x["gbps"].append(gbps)
				if err:
					x["bad"].append(err)
			except Exception as e:  # noqa: BLE001
				x["bad"].append(str(e)[:300])
	for t in targets:
		x = st[t.name]
		g, bad = x["gbps"], "; ".join(x["bad"])[:300]
		met = {"gbps": sum(g) / len(g) if g else None, "gbps_min": min(g) if g else None, "verified_gib": x["total"] / (1 << 30)}
		met.update(x["m"].metrics(nbytes=x["total"]))
		record(scenario, f"{case} x{REPEAT} ({SIZE // MIB} MiB)", t.name, met, ok=not x["bad"], note=bad)
		check(f"{scenario} {case} via {t.name}: every byte arrived unchanged", not x["bad"], bad)


def sc_verify(targets):
	"""Large transfers whose every byte the backend checks (SIZE x REPEAT, 1 and 4 streams)."""
	for case, streams in (("1 stream", 1), ("4 streams", 4)):
		def one(t, i, streams=streams):
			p = run(ns(NS_C, [LOADGEN, "send", "--connect", hostport(t.addr("sink")), "--bytes", str(SIZE // streams),
							  "--streams", str(streams), "--seed", str(1000 * i + 1)]), timeout=3600, check_rc=False)
			r = last_json(p.stdout)
			return r["bytes"], r["gbps"], None if r["ok"] else r.get("error", "failed")
		repeated("verify", case, targets, one)


class Sink:
	"""The backend's TCP sink; its JSON lines (one per connection) are collected."""

	def __init__(self, proc):
		self.proc, self.lines, self.lock = proc, [], threading.Lock()
		threading.Thread(target=self.read, daemon=True).start()

	def read(self):
		for line in self.proc.stdout:
			if line.startswith("{"):
				with self.lock:
					self.lines.append(json.loads(line))

	def take(self, n, timeout=60):
		end = time.monotonic() + timeout
		while time.monotonic() < end:
			with self.lock:
				if len(self.lines) >= n:
					got, self.lines = self.lines[:n], self.lines[n:]
					return got
			time.sleep(0.05)
		raise RuntimeError("the sink did not report")


def sc_tls(targets):
	"""TLS termination: verified uploads through socat (the backend's timing) and full handshakes per second."""
	tls_targets = [t for t in targets if t.addr("tls_sink")]
	if have("socat"):
		with SINK.lock:
			SINK.lines.clear()

		def one(t, i):
			a = t.addr("tls_sink")
			cmd = (f"{LOADGEN} gen --header 1 --bytes {SIZE} --seed {5000 + i} | "
				   f"socat -u -T 30 - OPENSSL:{a[0]}:{a[1]},verify=0")
			run(ns(NS_C, ["bash", "-o", "pipefail", "-c", cmd]), timeout=3600)
			r = SINK.take(1)[0]
			return r.get("bytes", 0), r.get("gbps", 0), None if r.get("ok") else json.dumps(r)
		repeated("tls", "upload", tls_targets, one)
	else:
		skip("tls uploads: socat is not installed")
	for t in tls_targets:
		a = t.addr("tls_echo")
		try:
			with Meter(t) as m:
				# OpenSSL 3.0's s_time exits 1 after a "-new" only run even when it worked: read the output instead
				p = run(ns(NS_C, ["openssl", "s_time", "-connect", hostport(a), "-new", "-time", str(DURATION)]), timeout=DURATION + 60,
						check_rc=False)
			n = secs = None
			for line in p.stdout.splitlines():
				w = line.split()
				if "real seconds" in line and len(w) > 4:
					n, secs = int(w[0]), float(w[3])
			if not n:
				raise RuntimeError(f"no result (exit {p.returncode}): {(p.stdout + p.stderr)[-300:]}")
			met = {"handshakes_s": n / secs}
			met.update(m.metrics(units=n, unit_name="handshakes"))
			record("tls", "new handshakes (openssl s_time)", t.name, met)
		except Exception as e:  # noqa: BLE001
			record("tls", "new handshakes (openssl s_time)", t.name, {}, ok=False, note=str(e)[:300])
			check(f"tls handshakes via {t.name}", False, str(e)[:300])


def h2load(t, case, url, args):
	logf = os.path.join(WORK, "h2load.log")
	threads = str(min(4, NPROC))
	with Meter(t) as m:
		p = run(ns(NS_C, ["h2load", "-n", str(H2_REQS), "-c", str(H2_CONNS), "-t", threads, "--log-file", logf] + args + [url + "/small"]),
				timeout=1800, check_rc=False)
	out = p.stdout
	req_s = done = failed = None
	for line in out.splitlines():
		if line.startswith("finished in"):
			req_s = float(line.split(",")[1].split()[0])
		if line.startswith("requests:"):
			w = line.replace(",", "").split()
			done, failed = int(w[7]), int(w[9])
	lat = []
	with open(logf) as f:
		for line in f:
			c = line.split()
			if len(c) >= 3 and c[1].startswith("2"):
				lat.append(int(c[2]))
	lat.sort()
	met = {"req_s": req_s, "p50_us": lat[len(lat) // 2] if lat else None, "p99_us": lat[int(len(lat) * 0.99)] if lat else None,
		   "failed": failed}
	met.update(m.metrics(units=done, unit_name="req"))
	ok = req_s is not None and not failed
	record("http", case, t.name, met, ok=ok, note="" if ok else out[-300:])
	if not ok:
		check(f"http {case} via {t.name}", False, out[-300:])


def sc_http(targets):
	"""L7: small requests with h2load (HTTP/1.1, h2c, h2 over TLS) and verified large downloads with curl."""
	if have("h2load"):
		for t in targets:
			if t.url("http"):
				h2load(t, "HTTP/1.1 small", t.url("http"), ["--h1"])
				if t.name != "direct":  # the backend speaks HTTP/1.1 only
					h2load(t, "HTTP/2 h2c small", t.url("http"), ["-m", "10"])
			if t.url("https"):
				h2load(t, "HTTP/2 TLS small", t.url("https"), ["-m", "10"])
	else:
		skip("http request rates: h2load is not installed")
	variants = [("HTTP/1.1 download", "http", ["--http1.1"]), ("HTTP/2 h2c download", "http", ["--http2-prior-knowledge"]),
				("HTTP/2 TLS download", "https", ["-k", "--http2"])]
	for case, svc, flags in variants:
		def one(t, i, svc=svc, flags=flags):
			seed = 7000 + i
			cmd = (f"curl -sS {' '.join(flags)} -o - {t.url(svc)}/stream/{SIZE}/{seed} | "
				   f"{LOADGEN} verify --bytes {SIZE} --seed {seed}")
			p = run(ns(NS_C, ["bash", "-o", "pipefail", "-c", cmd]), timeout=3600, check_rc=False)
			r = last_json(p.stdout)
			err = None if r["ok"] and not p.returncode else f"{r} {p.stderr.strip()[-200:]}"
			return r["bytes"], r["gbps"], err
		these = [t for t in targets if t.url(svc) and not (t.name == "direct" and "HTTP/2" in case)]
		repeated("http", case, these, one)


def sc_udp(targets):
	"""UDP: iperf3 at UDP_BW with 1400-byte datagrams, and 64-byte datagrams (max rate and UDP_PPS) from 16 sources."""
	udp_targets = [t for t in targets if t.addr("usink")]
	if have("iperf3"):
		for t in udp_targets:
			a = t.addr("iperf_udp")
			try:
				with Meter(t) as m:
					p = iperf3(a, ["-u", "-b", UDP_BW, "-l", "1400", "-t", str(DURATION)])
				j = json.loads(p.stdout)["end"]
				s = j.get("sum_received") or j["sum"]
				met = {"gbps": s["bits_per_second"] / 1e9, "loss_pct": j["sum"].get("lost_percent"), "jitter_ms": j["sum"].get("jitter_ms")}
				met.update(m.metrics(nbytes=s.get("bytes")))
				record("udp", f"iperf3 {UDP_BW}bit/s 1400 B", t.name, met)
			except Exception as e:  # noqa: BLE001
				record("udp", f"iperf3 {UDP_BW}bit/s 1400 B", t.name, {}, ok=False, note=str(e)[:300])
				check(f"udp iperf3 via {t.name}", False, str(e)[:300])
	for case, pps in (("64 B max rate, 16 sources", 0), (f"64 B at {UDP_PPS} pps, 16 sources", UDP_PPS)):
		for t in udp_targets:
			a = t.addr("usink")
			try:
				sink = subprocess.Popen(ns(NS_B, [LOADGEN, "udp-sink", "--listen", f"{BACKEND}:9004", "--idle", "2",
												  "--max-secs", str(DURATION + 60)]), stdout=subprocess.PIPE, text=True)
				sink.stdout.readline()  # ready
				drop0 = t.rule_stats("usink").get("stats", {}).get("dropped", 0) if isinstance(t, Rproxy) else 0
				k_mid, k_back = snmp(), snmp(NS_B)
				with Meter(t) as m:
					p = run(ns(NS_C, [LOADGEN, "udp-flood", "--connect", hostport(a), "--sources", "16", "--secs", str(DURATION),
									  "--size", "64", "--pps", str(pps), "--threads", "2"]), timeout=DURATION + 60)
				sent = last_json(p.stdout)
				got = last_json(sink.communicate(timeout=120)[0])
				drop = (t.rule_stats("usink").get("stats", {}).get("dropped", 0) - drop0) if isinstance(t, Rproxy) else None
				met = {"pps_sent": sent["pps"], "pps": got["received"] / sent["secs"] if sent["secs"] else None,
					   "loss_pct": 100.0 * (1 - got["received"] / sent["sent"]) if sent["sent"] else None,
					   "dropped": drop, "kernel_drops_middle": snmp() - k_mid, "kernel_drops_backend": snmp(NS_B) - k_back}
				met.update(m.metrics(nbytes=got["bytes"], units=got["received"], unit_name="datagrams"))
				record("udp", case, t.name, met)
			except Exception as e:  # noqa: BLE001
				record("udp", case, t.name, {}, ok=False, note=str(e)[:300])
				check(f"udp {case} via {t.name}", False, str(e)[:300])


def sc_latency(targets):
	"""Round trips of 64 bytes on 1 and 64 connections (p50 / p99)."""
	for conns in (1, 64):
		for t in targets:
			a = t.addr("echo")
			try:
				with Meter(t) as m:
					p = run(ns(NS_C, [LOADGEN, "rtt", "--connect", hostport(a), "--conns", str(conns), "--secs", str(DURATION)]),
							timeout=DURATION + 120)
				r = last_json(p.stdout)
				met = {"rps": r["rps"], "p50_us": r["p50_us"], "p99_us": r["p99_us"], "max_us": r["max_us"]}
				met.update(m.metrics(units=r["count"], unit_name="rtt"))
				record("latency", f"64 B ping-pong, {conns} conn", t.name, met, ok=r["ok"])
				if not r["ok"]:
					check(f"latency via {t.name}: echoes intact", False, json.dumps(r))
			except Exception as e:  # noqa: BLE001
				record("latency", f"64 B ping-pong, {conns} conn", t.name, {}, ok=False, note=str(e)[:300])
				check(f"latency {conns} via {t.name}", False, str(e)[:300])


def sc_churn(targets):
	"""New connections per second: connect, echo 1 KiB, close (32 workers)."""
	for t in targets:
		a = t.addr("echo")
		try:
			with Meter(t) as m:
				p = run(ns(NS_C, [LOADGEN, "churn", "--connect", hostport(a), "--workers", "32", "--secs", str(DURATION)]),
						timeout=DURATION + 120)
			r = last_json(p.stdout)
			met = {"conns_per_s": r["conns_per_s"], "p50_us": r["p50_us"], "p99_us": r["p99_us"], "failed": r["failed"]}
			met.update(m.metrics(units=r["count"], unit_name="conns"))
			bad = r["failed"] > max(10, r["count"] // 1000)
			record("churn", "connect + 1 KiB echo + close, 32 workers", t.name, met, ok=not bad, note=r.get("error", ""))
			if bad:
				check(f"churn via {t.name}: failures <= 0.1%", False, json.dumps(r))
		except Exception as e:  # noqa: BLE001
			record("churn", "connect + 1 KiB echo + close, 32 workers", t.name, {}, ok=False, note=str(e)[:300])
			check(f"churn via {t.name}", False, str(e)[:300])


def settle(pid, secs=2.0):
	time.sleep(secs)
	return rss_kib(pid), fd_count(pid)


def hold_conns(t, n):
	"""RSS / FDs of a fresh proxy with n idle connections, then with n busy ones (4 KiB ping-pong)."""
	rss0, fd0 = settle(t.pid)
	p = subprocess.Popen(ns(NS_C, [LOADGEN, "hold", "--connect", hostport(t.addr("echo")), "--conns", str(n), "--size", "4096"]),
						 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
	try:
		ready = json.loads(p.stdout.readline())
		rss1, fd1 = settle(t.pid)
		up = ready["conns"]
		record("memory", f"{n} idle TCP conns", t.name, {
			"conns": up, "rss_mib": rss1 / 1024, "kib_per_conn": (rss1 - rss0) / up if up else None,
			"fds_per_conn": (fd1 - fd0) / up if up else None}, ok=up == n, note=ready.get("error", ""))
		check(f"memory via {t.name}: {n} connections established", up == n, json.dumps(ready))
		p.stdin.write("active\n")
		p.stdin.flush()
		act = json.loads(p.stdout.readline())
		with Meter(t) as m:
			time.sleep(max(3, DURATION // 2))
		rss2 = max(m.peak, rss_kib(t.pid))
		met = {"conns": act["conns"], "rss_mib": rss2 / 1024, "kib_per_conn": (rss2 - rss0) / up if up else None}
		met.update(m.metrics())
		record("memory", f"{n} busy TCP conns (4 KiB ping-pong)", t.name, met)
		p.stdin.write("idle\n")
		p.stdin.flush()
		p.stdout.readline()
		p.stdin.write("quit\n")
		p.stdin.flush()
		p.communicate(timeout=120)
	finally:
		if p.poll() is None:
			p.kill()
	# connections closed: the FDs come back
	end = time.monotonic() + 30
	while fd_count(t.pid) > fd0 + 5 and time.monotonic() < end:
		time.sleep(0.5)
	fd3 = fd_count(t.pid)
	check(f"memory via {t.name}: FDs return after {n} connections close", fd3 <= fd0 + 5, f"before {fd0}, after {fd3}")


def mem_rules(idx):
	rp = Rproxy("memory-rules", idx=idx)
	try:
		rss0, fd0 = settle(rp.pid)
		record("memory", "idle, 0 rules", rp.name, {"rss_mib": rss0 / 1024, "fds": fd0})
		made = 0
		for count in sorted(RULES):
			while made < count:
				rp.add("echo", port=30000 + made)
				made += 1
			rss, fds = settle(rp.pid)
			record("memory", f"idle, {count} TCP rules", rp.name, {"rss_mib": rss / 1024, "fds": fds,
																   "kib_per_rule": (rss - rss0) / count})
	finally:
		rp.stop()


def mem_udp(idx):
	rp = Rproxy("memory-udp", ["uecho"], udp_idle=600, idx=idx)
	try:
		rss0, fd0 = settle(rp.pid)
		p = subprocess.Popen(ns(NS_C, [LOADGEN, "udp-hold", "--connect", hostport(rp.addr("uecho")), "--sources", str(UDP_SESSIONS)]),
							 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
		ready = json.loads(p.stdout.readline())
		rss1, fd1 = settle(rp.pid)
		n = ready["sessions"]
		record("memory", f"{UDP_SESSIONS} UDP sessions", rp.name, {
			"sessions": n, "rss_mib": rss1 / 1024, "kib_per_session": (rss1 - rss0) / n if n else None,
			"fds_per_session": (fd1 - fd0) / n if n else None}, ok=n == UDP_SESSIONS)
		check(f"memory via {rp.name}: {UDP_SESSIONS} UDP sessions established", n == UDP_SESSIONS, json.dumps(ready))
		p.communicate("quit\n", timeout=60)
	finally:
		rp.stop()


def sc_memory(targets):
	"""Memory of fresh processes: idle, per rule (0/100/1000), per idle / busy connection, per UDP session.
	With several builds, each step runs for every build in turn."""
	for idx in range(len(BINS)):
		mem_rules(idx)
	for idx in range(len(BINS)):
		rp = Rproxy("memory-conns", ["echo"], idx=idx)
		try:
			hold_conns(rp, CONNS)
		finally:
			rp.stop()
	if any(isinstance(t, Haproxy) for t in targets):
		h = Haproxy("memory")
		try:
			hold_conns(h, CONNS)
		finally:
			h.stop()
	for idx in range(len(BINS)):
		mem_udp(idx)


def sc_soak(_targets):
	"""SOAK_SECS for every build in turn."""
	if SOAK_SECS > 0:
		for idx in range(len(BINS)):
			soak_one(idx)


def soak_one(idx):
	"""SOAK_SECS of mixed load (iperf3 at SOAK_BW, connection churn, rotating UDP sources); RSS and FDs must not keep growing."""
	idle = 5
	rp = Rproxy("soak", ["echo", "iperf", "usink"], udp_idle=idle, idx=idx)
	procs, files = {}, {}
	samples = []

	def start(key, args):
		# output to files, not pipes: iperf3 -J writes its whole report at the end, more than a pipe holds,
		# and would block forever while nobody reads it before every process has ended
		files[key] = open(os.path.join(WORK, f"soak-{idx}-{key}.out"), "w+")
		procs[key] = subprocess.Popen(ns(NS_C, args), stdout=files[key], stderr=subprocess.STDOUT, text=True)
	try:
		rss0, fd0 = settle(rp.pid)
		sink = subprocess.Popen(ns(NS_B, [LOADGEN, "udp-sink", "--listen", f"{BACKEND}:9004", "--idle", "30",
										  "--max-secs", str(SOAK_SECS + 120)]), stdout=subprocess.PIPE, text=True)
		sink.stdout.readline()
		start("iperf3", ["iperf3", "-c", rp.ip, "-p", str(rp.port("iperf")), "-t", str(SOAK_SECS), "-b", SOAK_BW, "-J"])
		start("churn", [LOADGEN, "churn", "--connect", hostport(rp.addr("echo")), "--workers", "16", "--secs", str(SOAK_SECS)])
		start("udp", [LOADGEN, "udp-flood", "--connect", hostport(rp.addr("usink")), "--sources", "64", "--secs", str(SOAK_SECS),
					  "--pps", "20000", "--rotate", "10"])
		deadline = time.monotonic() + SOAK_SECS + 300
		t0 = time.monotonic()
		cpu0 = cpu_s(rp.pid)
		step = max(2, min(30, SOAK_SECS // 60))
		while any(p.poll() is None for p in procs.values()) and time.monotonic() < deadline:
			try:
				samples.append({"t": round(time.monotonic() - t0, 1), "rss_kib": rss_kib(rp.pid), "fds": fd_count(rp.pid),
								"cpu_s": round(cpu_s(rp.pid) - cpu0, 2), "conns": rp.connections()})
			except Exception:  # noqa: BLE001
				pass
			time.sleep(step)
		outs = {}
		for k, p in procs.items():
			if p.poll() is None:
				p.kill()
				check(f"soak via {rp.name}: {k} ended on time", False, "killed")
			p.wait()
			files[k].seek(0)
			outs[k] = files[k].read()
		sink.terminate()
		time.sleep(idle + 5)
		rss_end, fd_end = rss_kib(rp.pid), fd_count(rp.pid)
		churn = last_json(outs["churn"])
		try:
			ip = json.loads(outs["iperf3"])["end"]["sum_received"]
			bulk = ip["bytes"]
		except Exception:  # noqa: BLE001
			bulk = 0
			check(f"soak via {rp.name}: iperf3 ran to the end", False, outs["iperf3"][-300:])
		rss = [s["rss_kib"] for s in samples]
		body = rss[len(rss) // 10:]
		q = max(1, len(body) // 4)
		early, late = sum(body[:q]) / q, sum(body[-q:]) / q
		growth = late / early if early else 0
		cpu = cpu_s(rp.pid) - cpu0
		record("soak", f"{SOAK_SECS} s mixed load", rp.name, {
			"rss_start_mib": rss0 / 1024, "rss_peak_mib": max(rss) / 1024 if rss else None, "rss_end_mib": rss_end / 1024,
			"rss_growth": growth, "fds_start": fd0, "fds_peak": max(s["fds"] for s in samples) if samples else None, "fds_end": fd_end,
			"proxy_cpu_s": cpu, "bulk_gib": bulk / (1 << 30), "conns_per_s": churn["conns_per_s"], "failed": churn["failed"]})
		check(f"soak via {rp.name}: FDs return to the start (+20) after the load", fd_end <= fd0 + 20, f"start {fd0}, end {fd_end}")
		check(f"soak via {rp.name}: RSS does not keep growing (last quarter <= 1.5x the first)", growth <= 1.5,
			  f"first quarter {early / 1024:.1f} MiB, last quarter {late / 1024:.1f} MiB")
		check(f"soak via {rp.name}: connection failures <= 0.1%", churn["failed"] <= max(10, churn["count"] // 1000),
			  f"{churn['failed']} of {churn['count']}")
		suffix = "" if len(BINS) == 1 else "-" + BINS[idx][0].replace("/", "_")
		with open(os.path.join(OUT, f"soak{suffix}.csv"), "w") as f:
			f.write("t,rss_kib,fds,cpu_s,conns\n")
			for s in samples:
				f.write(f"{s['t']},{s['rss_kib']},{s['fds']},{s['cpu_s']},{s['conns']}\n")
	finally:
		for p in procs.values():
			if p.poll() is None:
				p.kill()
		for f in files.values():
			f.close()
		rp.stop()


# ---------------------------------------------------------------- main

def tool_version(args):
	try:
		p = subprocess.run(args, capture_output=True, text=True, timeout=10)
		return (p.stdout + p.stderr).strip().splitlines()[0][:80]
	except Exception:  # noqa: BLE001
		return None


def build_info(path):
	"""The libc and the allocator of a binary: musl's malloc is slower than glibc's, so runs compare only when these match."""
	try:
		with open(path, "rb") as f:
			data = f.read()
	except OSError:
		return {}
	interp = ""
	if data[:4] == b"\x7fELF" and data[4] == 2:  # 64-bit ELF: look for PT_INTERP
		import struct
		phoff, = struct.unpack_from("<Q", data, 0x20)
		phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
		for i in range(phnum):
			ptype, = struct.unpack_from("<I", data, phoff + i * phentsize)
			if ptype == 3:
				off, = struct.unpack_from("<Q", data, phoff + i * phentsize + 8)
				size, = struct.unpack_from("<Q", data, phoff + i * phentsize + 32)
				interp = data[off:off + size].rstrip(b"\0").decode(errors="replace")
	if "musl" in interp:
		libc = "musl (dynamic)"
	elif interp:
		libc = "glibc (dynamic)"
	else:
		libc = "glibc (static)" if b"GNU C Library" in data or b"GLIBC_" in data else "musl (static)"
	if b"mimalloc" in data:
		alloc = "mimalloc"
	elif b"jemalloc" in data or b"_rjem_" in data:
		alloc = "jemalloc"
	elif b"snmalloc" in data:
		alloc = "snmalloc"
	else:
		alloc = "libc malloc"
	return {"libc": libc, "allocator": alloc}


def meta():
	cpu = ""
	try:
		with open("/proc/cpuinfo") as f:
			cpu = next((line.split(":", 1)[1].strip() for line in f if line.startswith("model name")), "")
	except OSError:
		pass
	return {
		"date": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
		"commit": E.get("GITHUB_SHA") or E.get("COMMIT", ""),
		"ref": E.get("GITHUB_REF_NAME", ""),
		"rproxy": tool_version([BIN, "--version"]),
		"builds": [dict({"target": RP_NAMES[i], "ref": label, "commit": COMMITS.get(label, ""),
						 "version": tool_version([path, "--version"])}, **build_info(path)) for i, (label, path) in enumerate(BINS)],
		"kernel": platform.release(), "cpu": cpu, "nproc": NPROC,
		"mem_gib": round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / (1 << 30), 1),
		"netem": E.get("NETEM", ""),
		"params": {"scenarios": SCENARIOS, "size_mib": SIZE // MIB, "repeat": REPEAT, "duration": DURATION, "conns": CONNS,
				   "udp_sessions": UDP_SESSIONS, "rules": RULES, "udp_bw": UDP_BW, "udp_pps": UDP_PPS, "h2_reqs": H2_REQS,
				   "h2_conns": H2_CONNS, "soak_secs": SOAK_SECS, "log_level": LOG_LEVEL},
		"tools": {t: tool_version(a) for t, a in {"iperf3": ["iperf3", "--version"], "h2load": ["h2load", "--version"],
												  "curl": ["curl", "--version"], "socat": ["socat", "-V"], "openssl": ["openssl", "version"],
												  "haproxy": ["haproxy", "-v"]}.items() if have(a[0])},
	}


def main():
	global CERT, KEY, HAPEM, SINK
	os.makedirs(OUT, exist_ok=True)
	CERT, KEY, HAPEM = (os.path.join(WORK, x) for x in ("cert.pem", "key.pem", "haproxy.pem"))
	run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", KEY, "-out", CERT,
		 "-days", "2", "-subj", "/CN=load.test", "-addext", "subjectAltName=DNS:load.test"])
	with open(HAPEM, "w") as f:
		f.write(open(CERT).read() + open(KEY).read())
	log(f"scenarios: {', '.join(SCENARIOS)}; size {SIZE // MIB} MiB x {REPEAT}; {DURATION} s per run; netem: {E.get('NETEM') or 'none'}")

	servers = [
		subprocess.Popen(ns(NS_B, [LOADGEN, "echo", "--listen", f"{BACKEND}:9000"]), stderr=subprocess.DEVNULL),
		subprocess.Popen(ns(NS_B, [LOADGEN, "http-server", "--listen", f"{BACKEND}:9002"]), stderr=subprocess.DEVNULL),
		subprocess.Popen(ns(NS_B, [LOADGEN, "udp-echo", "--listen", f"{BACKEND}:9003"]), stderr=subprocess.DEVNULL),
	]
	sink = subprocess.Popen(ns(NS_B, [LOADGEN, "sink", "--listen", f"{BACKEND}:9001"]), stdout=subprocess.PIPE,
							stderr=subprocess.DEVNULL, text=True)
	servers.append(sink)
	SINK = Sink(sink)
	if have("iperf3"):
		servers.append(subprocess.Popen(ns(NS_B, ["iperf3", "-s", "-B", BACKEND, "-p", "5201"]), stdout=subprocess.DEVNULL,
										stderr=subprocess.DEVNULL))
	time.sleep(0.5)

	targets = [Direct()]
	try:
		for idx in range(len(BINS)):
			targets.append(Rproxy("main", list(SERVICES), idx=idx))
	except Exception as e:  # noqa: BLE001
		check("rproxy starts with every rule", False, str(e)[:500])
		raise
	if use_haproxy():
		try:
			targets.append(Haproxy("main"))
		except Exception as e:  # noqa: BLE001
			log(f"HAProxy left out: {e}")

	fns = {"tcp": sc_tcp, "verify": sc_verify, "tls": sc_tls, "http": sc_http, "udp": sc_udp, "latency": sc_latency,
		   "churn": sc_churn, "memory": sc_memory, "soak": sc_soak}
	shared_running = True
	try:
		for s in SCENARIOS:
			if s not in fns:
				check(f"known scenario {s}", False)
				continue
			if s in ("memory", "soak") and shared_running:
				# these start fresh processes of their own; the shared ones must not compete
				for t in targets:
					t.stop()
				shared_running = False
			log(f"== {s}")
			try:
				fns[s](targets)
			except Exception as e:  # noqa: BLE001
				traceback.print_exc()
				check(f"scenario {s} ran", False, str(e)[:300])
	finally:
		if shared_running:
			for t in targets:
				t.stop()
		for p in servers:
			p.kill()
	if not use_haproxy():
		skip("HAProxy comparison: haproxy is not installed (or HAPROXY=0)")
	data = {"meta": meta(), "results": results, "checks": checks, "skipped": skipped}
	with open(os.path.join(OUT, "results.json"), "w") as f:
		json.dump(data, f, indent=1)
	if len(BINS) > 1:
		# one file per build too (with direct and HAProxy), named after the ref
		for i, (label, _) in enumerate(BINS):
			mine = [r for r in results if not r["target"].startswith("rproxy@") or r["target"] == RP_NAMES[i]]
			with open(os.path.join(OUT, f"results-{label.replace('/', '_')}.json"), "w") as f:
				json.dump(dict(data, results=mine, build=data["meta"]["builds"][i]), f, indent=1)
	prev = None
	if E.get("PREVIOUS") and os.path.exists(E["PREVIOUS"]):
		try:
			with open(E["PREVIOUS"]) as f:
				prev = json.load(f)
		except Exception as e:  # noqa: BLE001
			log(f"previous results unreadable: {e}")
	with open(os.path.join(OUT, "summary.md"), "w") as f:
		f.write(report.render(data, prev))
	failed = [c for c in checks if not c["ok"]]
	log(f"{len(checks) - len(failed)} of {len(checks)} checks passed; results in {OUT}")
	return 1 if failed else 0


if __name__ == "__main__":
	sys.exit(main())
