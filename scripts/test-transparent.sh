#!/bin/bash
# source_ip の proxy / transparent を、TCP と UDP の両方で実際の経路を使って確かめる。
# root 不要: ユーザー名前空間とネットワーク名前空間の中で、次の構成を作る。
#
#   client --- rproxy --- backend [--- egress]
#
#   FAMILY=4（既定）  client 10.0.1.2        rproxy 10.0.1.1 / 10.0.2.1   backend 10.0.2.2
#   FAMILY=6          client 2001:db8:1::2   rproxy 2001:db8:1::1 / fd00:2::1（ULA）   backend fd00:2::2（ULA）
#                     （入口は GUA、内部は ULA の構成。proxy では backend に rproxy の ULA が、transparent では client の GUA が見える）
#
# 戻りパケットの受け取り方は ROUTING で選ぶ（README の「送信元 IP の引き渡し」）:
#   iif       転送先側のインターフェースから届いた client 宛てをローカル扱い（既定。ip rule iif）
#   iptables  rproxy の transparent ソケット宛てのパケットに印（-m socket --transparent）を付けてローカル扱い
#   nft       同じことを nftables で行う
#
# backend の戻りの経路は RETURN で選ぶ:
#   rproxy    backend のデフォルトゲートウェイが rproxy（既定）
#   gateway   backend のデフォルトゲートウェイは別の出口（egress。代表 IP で外に出る構成）。
#             backend 側で「rproxy から届いた接続の応答だけ rproxy に返す」設定（connmark + fwmark。docs/TRANSPARENT.md）を入れる
#
# 使い方: cargo build && [FAMILY=6] [ROUTING=nft] [RETURN=gateway] scripts/test-transparent.sh
# 必要なもの: unshare / nsenter / ip（util-linux, iproute2）, python3, curl。iptables / ip6tables / nft はそれぞれの方法で
if [ "$(id -u)" != 0 ] || [ -z "$RPROXY_NETNS" ]; then
  exec env RPROXY_NETNS=1 unshare -rn bash "$0" "$@"
fi
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug/rproxy-api}
WORK=$(mktemp -d)
FAIL=
FAMILY=${FAMILY:-4}
ROUTING=${ROUTING:-iif}
RETURN=${RETURN:-rproxy}
echo "family: IPv$FAMILY, routing: $ROUTING, return: $RETURN"

if [ "$FAMILY" = 6 ]; then
  F=-6; PLEN=64; ANY=::/0
  CLIENT=2001:db8:1::2; RP_C=2001:db8:1::1; CLIENTS=2001:db8:1::/64
  RP_B=fd00:2::1; BACKEND=fd00:2::2
  EG_E=fd00:3::1; EG_B=fd00:3::2
  NODAD=nodad
else
  F=-4; PLEN=24; ANY=0.0.0.0/0
  CLIENT=10.0.1.2; RP_C=10.0.1.1; CLIENTS=10.0.1.0/24
  RP_B=10.0.2.1; BACKEND=10.0.2.2
  EG_E=10.0.3.1; EG_B=10.0.3.2
  NODAD=
fi

ip link set lo up
unshare -n sleep 600 & C=$!
unshare -n sleep 600 & B=$!
unshare -n sleep 600 & E=$!
sleep 0.3
ns() { nsenter -n -t "$1" -- "${@:2}"; }

ip link add pc type veth peer name vc
ip link add pb type veth peer name vb
ip link set vc netns $C
ip link set vb netns $B
# shellcheck disable=SC2086
ip $F addr add $RP_C/$PLEN dev pc $NODAD && ip link set pc up
# shellcheck disable=SC2086
ip $F addr add $RP_B/$PLEN dev pb $NODAD && ip link set pb up
# shellcheck disable=SC2086
{ ns $C ip link set lo up; ns $C ip $F addr add $CLIENT/$PLEN dev vc $NODAD; ns $C ip link set vc up; ns $C ip $F route add default via $RP_C; }
# shellcheck disable=SC2086
{ ns $B ip link set lo up; ns $B ip $F addr add $BACKEND/$PLEN dev vb $NODAD; ns $B ip link set vb up; }

if [ "$RETURN" = gateway ]; then
  # the backend's way out is another router (egress); it drops what it gets
  ip link add ve type veth peer name ee
  ip link set ve netns $B
  ip link set ee netns $E
  # shellcheck disable=SC2086
  { ns $E ip link set lo up; ns $E ip $F addr add $EG_E/$PLEN dev ee $NODAD; ns $E ip link set ee up; }
  # shellcheck disable=SC2086
  { ns $B ip $F addr add $EG_B/$PLEN dev ve $NODAD; ns $B ip link set ve up; ns $B ip $F route add default via $EG_E; }
  # replies to connections that came in from rproxy go back to rproxy (docs/TRANSPARENT.md)
  ns $B nft -f - <<EOF
table inet rproxy_return {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "vb" ct mark set 0x52
  }
  chain output {
    type route hook output priority mangle; policy accept;
    ct mark 0x52 meta mark set 0x52
  }
}
EOF
  ns $B ip $F rule add fwmark 0x52 lookup 200
  ns $B ip $F route add default via $RP_B table 200
else
  ns $B ip $F route add default via $RP_B
fi

case $ROUTING in
  iif)
    ip $F route add local $CLIENTS dev lo table 100
    ip $F rule add iif pb lookup 100
    ;;
  iptables)
    if [ "$FAMILY" = 6 ]; then IPT=ip6tables; else IPT=iptables; fi
    $IPT -t mangle -A PREROUTING -p tcp -m socket --transparent -j MARK --set-mark 1
    $IPT -t mangle -A PREROUTING -p udp -m socket --transparent -j MARK --set-mark 1
    ip $F rule add fwmark 1 lookup 100
    ip $F route add local $ANY dev lo table 100
    ;;
  nft)
    nft add table inet rproxy
    nft add chain inet rproxy prerouting '{ type filter hook prerouting priority mangle; }'
    nft add rule inet rproxy prerouting socket transparent 1 meta mark set 1
    ip $F rule add fwmark 1 lookup 100
    ip $F route add local $ANY dev lo table 100
    ;;
  *) echo "unknown ROUTING=$ROUTING"; exit 2 ;;
esac

# backend: TCP and UDP echo that answer with the peer address they saw
nsenter -n -t $B python3 -c '
import socket, sys, threading
host = sys.argv[1]
fam = socket.AF_INET6 if ":" in host else socket.AF_INET
def tcp():
    s = socket.socket(fam); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((host, 9001)); s.listen()
    while True:
        c, a = s.accept(); c.recv(100); c.sendall(("tcp peer=%s:%d" % a[:2]).encode()); c.close()
def udp():
    u = socket.socket(fam, socket.SOCK_DGRAM); u.bind((host, 9002))
    while True:
        d, a = u.recvfrom(100); u.sendto(("udp peer=%s:%d" % a[:2]).encode(), a)
threading.Thread(target=tcp, daemon=True).start(); udp()
' "$BACKEND" & BE=$!
sleep 0.3

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
      -d "{\"protocol\":\"$proto\",\"listen_addr\":\"$RP_C\",\"listen_port\":$lport,\"remote_addr\":\"$BACKEND\",\"remote_port\":$port,\"source_ip\":\"$mode\"}")
    [ "$code" = 201 ] || { echo "create $proto/$mode failed: $code $(cat "$WORK/resp")"; FAIL=1; continue; }
    out=$(ns $C python3 -c "
import socket
host = '$RP_C'
fam = socket.AF_INET6 if ':' in host else socket.AF_INET
if '$proto' == 'tcp':
    s = socket.create_connection((host, $lport), timeout=3)
    me = s.getsockname(); s.sendall(b'hi'); r = s.recv(100)
else:
    s = socket.socket(fam, socket.SOCK_DGRAM); s.settimeout(3); s.connect((host, $lport))
    me = s.getsockname(); s.send(b'hi'); r = s.recv(100)
print('client=%s:%d backend-saw %s' % (me[0], me[1], r.decode()))
" 2>&1)
    echo "$proto $mode: $out"
    # transparent must show the client's own address to the backend; proxy must show rproxy's
    client=${out#client=}; client=${client%% *}; saw=${out##*peer=}
    if [ $mode = transparent ] && [ "$client" != "$saw" ]; then FAIL=1; echo "  NG: backend saw $saw"; fi
    if [ $mode = proxy ] && [ "${saw%:*}" != "$RP_B" ]; then FAIL=1; echo "  NG: backend saw $saw, not rproxy's $RP_B"; fi
  done
done
kill $RP $BE $C $B $E 2>/dev/null; wait 2>/dev/null
if [ -z "$FAIL" ]; then
  echo "OK (IPv$FAMILY, $ROUTING, return via $RETURN): transparent passes the client address, proxy does not"
else
  echo "rproxy log: $WORK/rproxy.log"; cat "$WORK/rproxy.log"; exit 1
fi
