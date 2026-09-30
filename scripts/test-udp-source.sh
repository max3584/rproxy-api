#!/bin/bash
# UDP の返信が、クライアントが送った宛先のアドレスから出ることを確かめる（#137）。
# root 不要: ユーザー名前空間とネットワーク名前空間の中で、次の構成を作る。
#
#   client（203.0.113.10 / 2001:db8:3::10）--- rproxy（1 つのインターフェースに
#     192.0.2.1 と 198.51.100.1、2001:db8:1::1 と 2001:db8:2::1）
#
# rproxy 側の client への経路は src に 2 つ目のアドレス（198.51.100.1 / 2001:db8:2::1）を付けてあるので、
# カーネルに返信の送信元を任せると、1 つ目のアドレスに送った client には 2 つ目のアドレスから返る
# （アドレスが複数のホストで IKE の応答が届かなかった実例と同じ形）。
# rproxy は 0.0.0.0 と ::（dual-stack）の UDP のルールで待ち受け、client は接続した（宛先以外からは受けない）
# ソケットで 4 つのアドレスそれぞれに送って、返信が届くこと（送信元が宛先と同じこと）を確かめる。
#
# 使い方: cargo build && scripts/test-udp-source.sh
# 必要なもの: unshare / nsenter / ip（util-linux, iproute2）, python3, curl
if [ "$(id -u)" != 0 ] || [ -z "$RPROXY_NETNS" ]; then
  exec env RPROXY_NETNS=1 unshare -rn bash "$0" "$@"
fi
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug/rproxy-api}
WORK=$(mktemp -d)
FAIL=

ip link set lo up
unshare -n sleep 600 & C=$!
sleep 0.3
ns() { nsenter -n -t "$1" -- "${@:2}"; }

ip link add pc type veth peer name vc
ip link set vc netns $C
ip addr add 192.0.2.1/24 dev pc
ip addr add 198.51.100.1/24 dev pc
ip -6 addr add 2001:db8:1::1/64 dev pc nodad
ip -6 addr add 2001:db8:2::1/64 dev pc nodad
ip link set pc up
# the way back to the client prefers the second address
ip route add 203.0.113.0/24 dev pc src 198.51.100.1
ip -6 route add 2001:db8:3::/64 dev pc src 2001:db8:2::1

ns $C ip link set lo up
ns $C ip addr add 203.0.113.10/24 dev vc
ns $C ip -6 addr add 2001:db8:3::10/64 dev vc nodad
ns $C ip link set vc up
for net in 192.0.2.0/24 198.51.100.0/24; do ns $C ip route add $net dev vc; done
for net in 2001:db8:1::/64 2001:db8:2::/64; do ns $C ip -6 route add $net dev vc; done

python3 -c '
import socket
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 9002))
while True:
    d, a = u.recvfrom(100); u.sendto(b"echo:" + d, a)
' & BE=$!
sleep 0.3

(cd "$WORK" && RPROXY_API_PORT=18210 exec "$BIN" > "$WORK/rproxy.log" 2>&1) & RP=$!
for _ in $(seq 1 50); do curl -sf localhost:18210/healthz >/dev/null && break; sleep 0.2; done
if ! curl -sf localhost:18210/healthz >/dev/null; then
  echo "rproxy did not start; log:"; cat "$WORK/rproxy.log"; exit 1
fi

# 0.0.0.0 (an IPv4 socket) and :: (dual-stack: IPv6, and IPv4 as v4-mapped)
create() {
  local code
  code=$(curl -s -o "$WORK/resp" -w '%{http_code}' -X POST localhost:18210/rules \
    -d "{\"protocol\":\"udp\",\"listen_addr\":\"$1\",\"listen_port\":$2,\"remote_addr\":\"127.0.0.1\",\"remote_port\":9002}")
  if [ "$code" != 201 ]; then echo "create udp $1:$2 failed: $code $(cat "$WORK/resp")"; FAIL=1; fi
}
create 0.0.0.0 7500
create :: 7600

check() {
  local to=$1 port=$2
  local out
  out=$(ns $C python3 -c "
import socket
to, port = '$to', $port
fam = socket.AF_INET6 if ':' in to else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM); s.settimeout(3)
s.connect((to, port)); s.send(b'hi')
try:
    print(s.recv(100).decode())
except socket.timeout:
    print('no reply from the address sent to')
" 2>&1)
  echo "udp -> [$to]:$port: $out"
  if [ "$out" != "echo:hi" ]; then FAIL=1; fi
}
for to in 192.0.2.1 198.51.100.1; do check $to 7500; check $to 7600; done
for to in 2001:db8:1::1 2001:db8:2::1; do check $to 7600; done

kill $RP $BE $C 2>/dev/null; wait 2>/dev/null
if [ -z "$FAIL" ]; then
  echo "OK: UDP replies leave from the address the client sent to (0.0.0.0 and ::, IPv4 and IPv6)"
  rm -rf "$WORK"
else
  echo "NG; rproxy log:"; cat "$WORK/rproxy.log"
  exit 1
fi
