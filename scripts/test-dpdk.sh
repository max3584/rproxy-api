#!/bin/bash
# The DPDK path (#261) end to end, against the kernel's own UDP stack:
#
#   kernel: dtap0 10.99.0.1/24 ---- DPDK port 0 (net_tap0)       10.99.0.2/24
#   kernel: veth-k 10.98.0.1/24 --- DPDK port 1 (net_af_packet0 on veth-d) 10.98.0.2/24
#
# rproxy runs with global.performance.dpdk and three UDP rules on the DPDK
# addresses; echo servers and clients are ordinary kernel sockets:
#   - 10.99.0.2:5300 -> 10.99.0.1:7000 (both on port 0)
#   - 10.98.0.2:5300 -> 10.99.0.1:7001 (client on port 1, backend on port 0: the
#     source towards the backend is port 0's address)
#   - 10.99.0.2:5400-5401 -> 10.99.0.1:7100-7101 (a port range)
# Clients send datagrams of many sizes (0-1472 bytes) from many sockets and
# compare every answer (SHA-256 of the payload and the sequence number). Then
# GET /capabilities must show performance.dpdk active; a run with a port that
# does not exist must fall back (degraded, active false), and with
# fallback: false must not start.
#
# Needs root (net_tap, hugepages) and DPDK's PMD plugins (Ubuntu: libdpdk-dev).
# Correctness only: the numbers of a GitHub runner say nothing about DPDK's speed.
# Usage: cargo build --features dpdk && sudo scripts/test-dpdk.sh
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug/rproxy-api}
WORK=$(mktemp -d)
LCORES=${LCORES:-1-2}
API=18260
RP=
FAIL=
cleanup() {
  [ -n "$RP" ] && kill "$RP" 2>/dev/null && wait "$RP" 2>/dev/null
  # shellcheck disable=SC2046
  kill $(jobs -p) 2>/dev/null || true
  ip link del veth-k 2>/dev/null || true
}
trap cleanup EXIT

ip link add veth-k type veth peer name veth-d
ip addr add 10.98.0.1/24 dev veth-k
ip link set veth-k up
ip link set veth-d up
# the kernel must not answer on veth-d itself (DPDK owns it)
sysctl -qw net.ipv6.conf.veth-d.disable_ipv6=1 || true

config() {
  # $1: the extra port's vdev, $2: fallback
  cat > "$WORK/rproxy.yaml" <<EOF
version: 1
global:
  performance:
    dpdk:
      enabled: true
      lcores: "$LCORES"
      eal_args: ["--in-memory", "--no-telemetry"]
      mempool: { mbufs: 8191, cache: 128 }
      burst: 32
      fallback: $2
      ports:
        - vdev: "net_tap0,iface=dtap0"
          rx_queues: 2
          tx_queues: 2
          addresses: ["10.99.0.2/24"]
        - vdev: "$1"
          rx_queues: 1
          tx_queues: 2
          addresses: ["10.98.0.2/24"]
rules:
  - { protocol: udp, listen_addr: 10.99.0.2, listen_port: 5300, remote_addr: 10.99.0.1, remote_port: 7000 }
  - { protocol: udp, listen_addr: 10.98.0.2, listen_port: 5300, remote_addr: 10.99.0.1, remote_port: 7001 }
  - { protocol: udp, listen_addr: 10.99.0.2, listen_port: 5400, port_count: 2, remote_addr: 10.99.0.1, remote_port: 7100 }
EOF
}

start() {
  (cd "$WORK" && RPROXY_API_PORT=$API RPROXY_CONFIG="$WORK/rproxy.yaml" exec "$BIN" > "$WORK/rproxy.out" 2>&1) & RP=$!
  for _ in $(seq 1 150); do
    curl -sf localhost:$API/healthz >/dev/null && return 0
    kill -0 "$RP" 2>/dev/null || return 1
    sleep 0.2
  done
  return 1
}

stop() {
  kill "$RP" 2>/dev/null || true
  wait "$RP" 2>/dev/null || true
  RP=
}

logs() {
  tail -80 "$WORK/rproxy.out"
}

# --- 1. forwarding ---
config "net_af_packet0,iface=veth-d,qpairs=2" true
start || { echo "rproxy did not start"; logs; exit 1; }
for _ in $(seq 1 50); do ip link show dtap0 >/dev/null 2>&1 && break; sleep 0.1; done
ip addr add 10.99.0.1/24 dev dtap0
ip link set dtap0 up
sysctl -qw net.ipv6.conf.dtap0.disable_ipv6=1 || true

caps=$(curl -sf localhost:$API/capabilities)
echo "capabilities.performance: $(echo "$caps" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("performance")))')"
echo "$caps" | python3 -c '
import json, sys
c = json.load(sys.stdin)
d = c["performance"]["dpdk"]
assert d["requested"] == "on" and d["active"], d
assert "dpdk" in c["features"]["performance"], c["features"]["performance"]
assert "net_tap0 up" in d["mode"] and "net_af_packet0 up" in d["mode"], d["mode"]
' || { echo "capabilities do not show DPDK active"; logs; FAIL=1; }

# echo servers on the kernel side: "<port>:" + the datagram
python3 -c '
import selectors, socket
sel = selectors.DefaultSelector()
for port in (7000, 7001, 7100, 7101):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    s.bind(("10.99.0.1", port))
    sel.register(s, selectors.EVENT_READ, port)
while True:
    for key, _ in sel.select():
        d, a = key.fileobj.recvfrom(65535)
        key.fileobj.sendto(str(key.data).encode() + b":" + d, a)
' & sleep 0.5

check() {
  # $1 listen address, $2 port, $3 expected backend port, $4 client source address
  python3 - "$1" "$2" "$3" "$4" <<'EOF'
import hashlib, os, socket, sys
to, port, backend, src = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
sizes = [0, 1, 2, 17, 64, 100, 255, 256, 511, 512, 1000, 1024, 1400, 1460]
socks = []
for _ in range(20):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0)); s.settimeout(2); s.connect((to, port))
    socks.append(s)
ok = sent = 0
for rnd in range(5):
    for i, s in enumerate(socks):
        for size in sizes:
            body = os.urandom(size)
            seq = f"{rnd}-{i}-{size}".encode()
            msg = seq + b"|" + body
            msg = msg[:1472]
            sent += 1
            s.send(msg)
            want = backend.encode() + b":" + msg
            for _ in range(3):
                try:
                    got = s.recv(65535)
                except socket.timeout:
                    s.send(msg)  # UDP: the first datagram of a session may wait for ARP
                    continue
                if got == want:
                    ok += 1
                    break
                print("mismatch", seq, len(got), len(want), hashlib.sha256(got).hexdigest()[:12], file=sys.stderr)
                break
            else:
                print("no answer", seq, file=sys.stderr)
print(f"{to}:{port} -> :{backend}: {ok}/{sent} answers intact")
sys.exit(0 if ok == sent else 1)
EOF
}

check 10.99.0.2 5300 7000 10.99.0.1 || FAIL=1
check 10.98.0.2 5300 7001 10.98.0.1 || FAIL=1
check 10.99.0.2 5400 7100 10.99.0.1 || FAIL=1
check 10.99.0.2 5401 7101 10.99.0.1 || FAIL=1

# the kernel answered ARP for nothing on DPDK's ports, and DPDK answers ping on its addresses
ping -c 2 -W 2 10.99.0.2 >/dev/null || { echo "no ping answer from 10.99.0.2"; FAIL=1; }

stats=$(curl -sf localhost:$API/rules)
echo "$stats" | python3 -c '
import json, sys
rules = json.load(sys.stdin)
rules = rules.get("rules", rules) if isinstance(rules, dict) else rules
for r in rules:
    s = r.get("stats", {})
    print(r["protocol"], r["listen_addr"], r["listen_port"], r.get("status"), "rx", s.get("rx_bytes"), "tx", s.get("tx_bytes"), "total", s.get("total"), "dropped", s.get("dropped"))
'
grep -h '"event":"performance.probe"' "$WORK/rproxy.out" | head -1
grep -qh '"path":"dpdk"' "$WORK/rproxy.out" || { echo "no conn.open with path=dpdk in the log"; FAIL=1; }
stop

# --- the same probe without starting: --check-kernel ---
"$BIN" --check-kernel --config "$WORK/rproxy.yaml" > "$WORK/check.txt" 2>&1 || true
grep -E '^dpdk|^  dpdk' "$WORK/check.txt"
grep -qE '^dpdk\.enabled=true +yes +usable' "$WORK/check.txt" || { echo "--check-kernel: DPDK not usable"; cat "$WORK/check.txt"; FAIL=1; }

# --- 2. a port that does not exist: fallback ---
ip link set dtap0 down 2>/dev/null || true
config "net_af_packet0,iface=no-such-if" true
start || { echo "rproxy did not start with fallback: true"; logs; exit 1; }
caps=$(curl -sf localhost:$API/capabilities)
echo "$caps" | python3 -c '
import json, sys
d = json.load(sys.stdin)["performance"]["dpdk"]
assert d["requested"] == "on" and not d["active"] and d["reason"], d
print("fallback:", d["reason"])
' || { echo "fallback not reported"; logs; FAIL=1; }
grep -qh '"part":"global.performance.dpdk"' "$WORK/rproxy.out" || { echo "no degraded line"; FAIL=1; }
stop

# --- 3. fallback: false stops the start ---
config "net_af_packet0,iface=no-such-if" false
if start; then echo "rproxy started although DPDK failed with fallback: false"; FAIL=1; fi
stop

if [ -n "$FAIL" ]; then
  echo "FAILED"; logs; exit 1
fi
echo "ok"
