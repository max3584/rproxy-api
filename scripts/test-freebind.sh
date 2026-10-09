#!/bin/bash
# listen_freebind（v0.4.3）の実経路テスト。root 不要: ユーザー名前空間とネットワーク名前空間の中で、
# まだホストにない VIP（192.0.2.10・192.0.2.11・2001:db8:1::10）で TCP と UDP のルールを作り、
# 後から VIP をインターフェースに足すと、その VIP に来たものだけがそれぞれの転送先に届くことを確かめる
# （Kubernetes の fleet で VIP を持つ Pod が入れ替わる形。rproxy-gateway の docs/DESIGN-v0.4.x.md 7.）。
#
#   client（203.0.113.10 / 2001:db8:3::10）--- rproxy（pc。VIP は後から /32・/128 で足す）
#
# 確かめること：
# - VIP がないうちから、listen_freebind のルールは running（listen_freebind なしでは bind に失敗する）
# - 同じポート 443 の 2 つの VIP が別々のルール（別々のルールの組）として並ぶ
# - 0.0.0.0:443 のルールは 409 already_exists（ワイルドカードはどのアドレスのポートも取る）
# - VIP を足すと TCP・UDP とも VIP ごとの転送先に届き、UDP の返信は VIP から出る
# - VIP を外して足し直しても（持ち主が戻る）そのまま届く
#
# 使い方: cargo build && scripts/test-freebind.sh
# 必要なもの: unshare / nsenter / ip（util-linux, iproute2）, python3, curl
if [ "$(id -u)" != 0 ] || [ -z "$RPROXY_NETNS" ]; then
  exec env RPROXY_NETNS=1 unshare -rn bash "$0" "$@"
fi
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug/rproxy-api}
WORK=$(mktemp -d)
FAIL=
API=localhost:18220

ip link set lo up
unshare -n sleep 600 & C=$!
sleep 0.3
ns() { nsenter -n -t "$1" -- "${@:2}"; }

ip link add pc type veth peer name vc
ip link set vc netns $C
ip addr add 192.0.2.1/24 dev pc
ip -6 addr add 2001:db8:1::1/64 dev pc nodad
ip link set pc up
ip route add 203.0.113.0/24 dev pc
ip -6 route add 2001:db8:3::/64 dev pc

ns $C ip link set lo up
ns $C ip addr add 203.0.113.10/24 dev vc
ns $C ip -6 addr add 2001:db8:3::10/64 dev vc nodad
ns $C ip link set vc up
ns $C ip route add 192.0.2.0/24 dev vc
ns $C ip -6 route add 2001:db8:1::/64 dev vc

# backends: TCP and UDP, answering "<tag>:<data>"
for spec in A:9101 B:9102; do
  python3 -c '
import socket, sys, threading
tag, port = sys.argv[1], int(sys.argv[2])
def udp():
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", port))
    while True:
        d, a = u.recvfrom(100); u.sendto(tag.encode() + b":" + d, a)
threading.Thread(target=udp, daemon=True).start()
t = socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("127.0.0.1", port)); t.listen(16)
while True:
    c, _ = t.accept(); d = c.recv(100); c.sendall(tag.encode() + b":" + d); c.close()
' "${spec%%:*}" "${spec##*:}" &
done
sleep 0.3

(cd "$WORK" && RPROXY_API_PORT=18220 exec "$BIN" > "$WORK/rproxy.log" 2>&1) & RP=$!
for _ in $(seq 1 50); do curl -sf $API/healthz > /dev/null && break; sleep 0.2; done
if ! curl -sf $API/healthz > /dev/null; then
  echo "rproxy did not start; log:"; cat "$WORK/rproxy.log"; exit 1
fi

# put_set <name> <vip> <backend port>: one rule set with a TCP and a UDP rule on <vip>:443
put_set() {
  local code
  code=$(curl -s -o "$WORK/resp" -w '%{http_code}' -X PUT "$API/rulesets/$1" -d "{\"generation\":1,\"rules\":[
    {\"protocol\":\"tcp\",\"listen_addr\":\"$2\",\"listen_port\":443,\"listen_freebind\":true,\"remote_addr\":\"127.0.0.1\",\"remote_port\":$3},
    {\"protocol\":\"udp\",\"listen_addr\":\"$2\",\"listen_port\":443,\"listen_freebind\":true,\"remote_addr\":\"127.0.0.1\",\"remote_port\":$3}]}")
  if [ "$code" != 200 ] || grep -q '"state":"failed"' "$WORK/resp"; then
    echo "NG: rule set $1 on $2: $code $(cat "$WORK/resp")"; FAIL=1
  else
    echo "rule set $1 on $2:443 (tcp, udp): running before the address is on the host"
  fi
}
put_set k8s/a/one 192.0.2.10 9101
put_set k8s/b/two 192.0.2.11 9102
put_set k8s/c/six 2001:db8:1::10 9102

# without listen_freebind an address not on the host does not bind
code=$(curl -s -o "$WORK/resp" -w '%{http_code}' -X POST $API/rules \
  -d '{"protocol":"tcp","listen_addr":"192.0.2.12","listen_port":443,"remote_addr":"127.0.0.1","remote_port":9101}')
if [ "$code" = 201 ]; then echo "NG: 192.0.2.12:443 bound without listen_freebind"; FAIL=1; else echo "without listen_freebind: $code (bind fails)"; fi
# a wildcard on the same port overlaps every address
code=$(curl -s -o "$WORK/resp" -w '%{http_code}' -X POST $API/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":443,"remote_addr":"127.0.0.1","remote_port":9101}')
if [ "$code" != 409 ] || ! grep -q 'rule set k8s/' "$WORK/resp"; then
  echo "NG: 0.0.0.0:443 next to the VIPs: $code $(cat "$WORK/resp")"; FAIL=1
else
  echo "0.0.0.0:443: 409 $(sed 's/.*"error":"\([^"]*\)".*/\1/' "$WORK/resp")"
fi

# check <proto> <to> <want>
check() {
  local out
  out=$(ns $C python3 -c "
import socket, sys
proto, to = '$1', '$2'
fam = socket.AF_INET6 if ':' in to else socket.AF_INET
s = socket.socket(fam, socket.SOCK_STREAM if proto == 'tcp' else socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.connect((to, 443)); s.send(b'hi'); print(s.recv(100).decode())
except Exception as e:
    print('error: %s' % e)
" 2>&1)
  echo "$1 -> [$2]:443: $out"
  if [ "$out" != "$3" ]; then FAIL=1; fi
}
vips_up() {
  ip addr add 192.0.2.10/32 dev pc
  ip addr add 192.0.2.11/32 dev pc
  ip -6 addr add 2001:db8:1::10/128 dev pc nodad
}
vips_up
for p in tcp udp; do
  check $p 192.0.2.10 A:hi
  check $p 192.0.2.11 B:hi
  check $p 2001:db8:1::10 B:hi
done
# the VIPs move away and back (another node held them for a while)
ip addr del 192.0.2.10/32 dev pc
ip addr del 192.0.2.11/32 dev pc
ip -6 addr del 2001:db8:1::10/128 dev pc
vips_up
for p in tcp udp; do check $p 192.0.2.10 A:hi; check $p 192.0.2.11 B:hi; done

kill $RP $C 2> /dev/null
pkill -P $$ python3 2> /dev/null || true
wait 2> /dev/null || true
if [ -z "$FAIL" ]; then
  echo "OK: listen_freebind rules listen on VIPs before they are on the host; the same port on two VIPs; 0.0.0.0 refused"
  rm -rf "$WORK"
else
  echo "NG; rproxy log:"; cat "$WORK/rproxy.log"
  exit 1
fi
