#!/bin/bash
# Load and soak tests that measure transfer efficiency (issue #183; docs/TESTING.md).
# Builds three network namespaces and runs scripts/load/load.py in the middle one:
#
#   client 10.71.1.2 --- 10.71.1.1 [rproxy / HAProxy / router] 10.71.2.1 --- 10.71.2.2 backend
#
# "direct" (the baseline) is forwarded by the kernel of the middle namespace, so it
# crosses the same links. NETEM="delay 5ms loss 0.1%" adds tc netem on the client
# link, in both directions.
#
# Usage:
#   cargo build --release
#   cargo build --release --locked --manifest-path scripts/load/loadgen/Cargo.toml --target-dir target/loadgen
#   [sudo] [SIZE_MIB=256 REPEAT=1 DURATION=5 ...] scripts/load/run.sh
# Without root it uses a user namespace (unshare -r); with sudo the limits (open
# files, socket buffers) can be raised further. Results: $OUT (default load-results)/
# results.json, summary.md. Settings: the top of scripts/load/load.py.
# Needs: unshare / nsenter / ip / tc (util-linux, iproute2), python3, openssl, curl;
# optional: iperf3, h2load (nghttp2-client), socat, haproxy (left out when missing).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
export BIN=${BIN:-$ROOT/target/release/rproxy-api}
export LOADGEN=${LOADGEN:-$ROOT/target/loadgen/release/rproxy-loadgen}
export OUT=${OUT:-$PWD/load-results}

if [ -z "${RPROXY_LOAD_NETNS:-}" ]; then
  [ -x "$BIN" ] || { echo "no $BIN: run cargo build --release first (or set BIN)"; exit 2; }
  if [ ! -x "$LOADGEN" ]; then
    if [ "$(id -u)" = 0 ]; then echo "no $LOADGEN: build it first (see the top of this file)"; exit 2; fi
    cargo build --release --locked --manifest-path "$ROOT/scripts/load/loadgen/Cargo.toml" --target-dir "$ROOT/target/loadgen"
  fi
  mkdir -p "$OUT"
  if [ "$(id -u)" = 0 ]; then
    exec env RPROXY_LOAD_NETNS=1 unshare -n bash "$0" "$@"
  fi
  exec env RPROXY_LOAD_NETNS=1 unshare -rn bash "$0" "$@"
fi

WORK=$(mktemp -d)
export WORK
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  if [ -n "${SUDO_UID:-}" ]; then chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

# many connections: one FD each in the client and the backend, two in a proxy
ulimit -n 1048576 2>/dev/null || ulimit -n "$(ulimit -Hn)"
echo "open files: $(ulimit -n)"

ip link set lo up
unshare -n sleep 86400 & C=$!
unshare -n sleep 86400 & B=$!
PIDS+=("$C" "$B")
sleep 0.3
ns() { nsenter -n -t "$1" -- "${@:2}"; }

ip link add pc type veth peer name vc
ip link add pb type veth peer name vb
ip link set vc netns "$C"
ip link set vb netns "$B"
ip addr add 10.71.1.1/24 dev pc && ip link set pc up
ip addr add 10.71.2.1/24 dev pb && ip link set pb up
ns "$C" ip link set lo up
ns "$C" ip addr add 10.71.1.2/24 dev vc
ns "$C" ip link set vc up
ns "$C" ip route add default via 10.71.1.1
ns "$B" ip link set lo up
ns "$B" ip addr add 10.71.2.2/24 dev vb
ns "$B" ip link set vb up
ns "$B" ip route add default via 10.71.2.1

# sysctl without the sysctl binary: setsys <namespace pid | self> <key> <value>
setsys() {
  local f="/proc/sys/${2//.//}"
  if [ "$1" = self ]; then echo "$3" > "$f"; else nsenter -n -t "$1" -- sh -c "echo '$3' > $f"; fi
}
# the middle namespace routes the direct (baseline) traffic
setsys self net.ipv4.ip_forward 1
# thousands of short connections: ports and TIME_WAIT reuse; deeper accept queues
for n in self "$C" "$B"; do
  setsys "$n" net.ipv4.ip_local_port_range "1024 65000" || true
  setsys "$n" net.ipv4.tcp_tw_reuse 1 || true
  setsys "$n" net.core.somaxconn 65535 2>/dev/null || true
  setsys "$n" net.ipv4.tcp_max_syn_backlog 65535 || true
done
# larger socket buffers (global settings: only with real root)
setsys self net.core.rmem_max 16777216 2>/dev/null || true
setsys self net.core.wmem_max 16777216 2>/dev/null || true

if [ -n "${NETEM:-}" ]; then
  # shellcheck disable=SC2086
  if ns "$C" tc qdisc add dev vc root netem $NETEM && tc qdisc add dev pc root netem $NETEM; then
    echo "netem on the client link (each direction): $NETEM"
  else
    echo "netem is not available (sch_netem); stopping"
    exit 2
  fi
fi

export LOAD_NS_CLIENT=$C LOAD_NS_BACKEND=$B
python3 "$ROOT/scripts/load/load.py" "$@"
