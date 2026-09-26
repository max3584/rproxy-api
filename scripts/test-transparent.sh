#!/bin/bash
# source_ip の proxy / transparent を、TCP と UDP の両方で実際の経路を使って確かめる。
# root 不要: ユーザー名前空間とネットワーク名前空間の中で、次の構成を作る。
#
#   client 10.0.1.2 --- 10.0.1.1 rproxy 10.0.2.1 --- 10.0.2.2 backend
#
# backend のデフォルトゲートウェイは rproxy。rproxy 側では「backend から届いた
# client 宛てのパケット」をローカル扱いにする（table 100）ので、transparent の
# 戻りパケットが rproxy のソケットに届く。本番のポリシールーティングと同じ考え方。
#
# 戻りパケットの受け取り方は ROUTING で選ぶ（README の「送信元 IP の引き渡し」）:
#   iif       転送先側のインターフェースから届いた client 宛てをローカル扱い（既定。ip rule iif）
#   iptables  rproxy の transparent ソケット宛てのパケットに印（-m socket --transparent）を付けてローカル扱い
#   nft       同じことを nftables で行う
#
# 使い方: cargo build && [ROUTING=iptables] scripts/test-transparent.sh
# 必要なもの: unshare / nsenter / ip（util-linux, iproute2）, python3, curl。iptables / nft はそれぞれの方法で
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
unshare -n sleep 600 & B=$!
sleep 0.3
ns() { nsenter -n -t "$1" -- "${@:2}"; }

ip link add pc type veth peer name vc
ip link add pb type veth peer name vb
ip link set vc netns $C
ip link set vb netns $B
ip addr add 10.0.1.1/24 dev pc && ip link set pc up
ip addr add 10.0.2.1/24 dev pb && ip link set pb up
ns $C ip link set lo up; ns $C ip addr add 10.0.1.2/24 dev vc; ns $C ip link set vc up; ns $C ip route add default via 10.0.1.1
ns $B ip link set lo up; ns $B ip addr add 10.0.2.2/24 dev vb; ns $B ip link set vb up; ns $B ip route add default via 10.0.2.1

ROUTING=${ROUTING:-iif}
echo "routing: $ROUTING"
case $ROUTING in
  iif)
    ip route add local 10.0.1.0/24 dev lo table 100
    ip rule add iif pb lookup 100
    ;;
  iptables)
    iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j MARK --set-mark 1
    iptables -t mangle -A PREROUTING -p udp -m socket --transparent -j MARK --set-mark 1
    ip rule add fwmark 1 lookup 100
    ip route add local 0.0.0.0/0 dev lo table 100
    ;;
  nft)
    nft add table ip rproxy
    nft add chain ip rproxy prerouting '{ type filter hook prerouting priority mangle; }'
    nft add rule ip rproxy prerouting socket transparent 1 meta mark set 1
    ip rule add fwmark 1 lookup 100
    ip route add local 0.0.0.0/0 dev lo table 100
    ;;
  *) echo "unknown ROUTING=$ROUTING"; exit 2 ;;
esac

# backend: TCP and UDP echo that answer with the peer address they saw
nsenter -n -t $B python3 -c '
import socket, threading
def tcp():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("10.0.2.2", 9001)); s.listen()
    while True:
        c, a = s.accept(); c.recv(100); c.sendall(("tcp peer=%s:%d" % a).encode()); c.close()
def udp():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("10.0.2.2", 9002))
    while True:
        d, a = u.recvfrom(100); u.sendto(("udp peer=%s:%d" % a).encode(), a)
threading.Thread(target=tcp, daemon=True).start(); udp()
' & BE=$!

(cd "$WORK" && RPROXY_API_PORT=18200 exec "$BIN" > "$WORK/rproxy.log" 2>&1) & RP=$!
for _ in $(seq 1 50); do curl -sf localhost:18200/healthz >/dev/null && break; sleep 0.2; done
if ! curl -sf localhost:18200/healthz >/dev/null; then
  echo "rproxy did not start; log:"; cat "$WORK/rproxy.log"; exit 1
fi
echo "capabilities: $(curl -s localhost:18200/capabilities)"
for proto in tcp udp; do
  if [ "$proto" = tcp ]; then port=9001; else port=9002; fi
  for mode in proxy transparent; do
    if [ "$mode" = proxy ]; then lport="7${port:1}"; else lport="8${port:1}"; fi
    code=$(curl -s -o "$WORK/resp" -w '%{http_code}' -X POST localhost:18200/rules \
      -d "{\"protocol\":\"$proto\",\"listen_addr\":\"10.0.1.1\",\"listen_port\":$lport,\"remote_addr\":\"10.0.2.2\",\"remote_port\":$port,\"source_ip\":\"$mode\"}")
    [ "$code" = 201 ] || { echo "create $proto/$mode failed: $code $(cat "$WORK/resp")"; continue; }
    out=$(ns $C python3 -c "
import socket, sys
if '$proto' == 'tcp':
    s = socket.create_connection(('10.0.1.1', $lport), timeout=3)
    me = s.getsockname(); s.sendall(b'hi'); r = s.recv(100)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3); s.connect(('10.0.1.1', $lport))
    me = s.getsockname(); s.send(b'hi'); r = s.recv(100)
print('client=%s:%d backend-saw %s' % (me[0], me[1], r.decode()))
" 2>&1)
    echo "$proto $mode: $out"
    # transparent must show the client's own address to the backend; proxy must not
    client=${out#client=}; client=${client%% *}; saw=${out##*peer=}
    if [ $mode = transparent ] && [ "$client" != "$saw" ]; then FAIL=1; echo "  NG: backend saw $saw"; fi
    if [ $mode = proxy ] && [ "$client" = "$saw" ]; then FAIL=1; echo "  NG: address leaked"; fi
  done
done
kill $RP $BE $C $B 2>/dev/null; wait 2>/dev/null
if [ -z "$FAIL" ]; then
  echo "OK ($ROUTING): transparent passes the client address, proxy does not"
else
  echo "rproxy log: $WORK/rproxy.log"; exit 1
fi
