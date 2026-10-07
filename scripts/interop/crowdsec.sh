#!/usr/bin/env bash
# 実際の CrowdSec（LAPI・エージェント・AppSec）を動かし、rproxy のログから検知 → ban → rproxy で止める、
# までを一周確かめる（issue #129）。CI の CrowdSec の公式のイメージ（crowdsecurity/crowdsec、Alpine）のコンテナ用
# （特権つき、root で動かす。ネットワーク名前空間を作る。足りないものはワークフローが apk で入れる：bash coreutils curl
# python3 iproute2）。systemd はないので、CrowdSec はこのスクリプトが設定して起動する。
#
#   cargo build && scripts/interop/crowdsec.sh
#
# クライアントの「global な」アドレスには文書用のアドレスを使う：IPv4 は RFC 5737（192.0.2.0/24・198.51.100.0/24・
# 203.0.113.0/24）、IPv6 は RFC 3849（2001:db8::/32）。インターネットでは経路がないので名前空間の中なら安全で、
# CrowdSec の既定の whitelist（crowdsecurity/whitelists：RFC 1918・ループバックなど）にも入らない。
# 比べるために私用アドレス（10.99.0.10）のクライアントも用意し、同じことをしても ban されないことを確かめる。
# 使い捨てのコンテナの外（rproxy-api や CrowdSec を本番で動かしている機械）では実行しない。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${BIN:-$ROOT/target/debug/rproxy-api}
WORK=$(mktemp -d)
chmod 755 "$WORK"
API=http://127.0.0.1:18400
NS=rpcs
PIDS=()

# clients (in the namespace $NS) and the address rproxy is reached at (on the host side of the veth)
GLOBAL_A=192.0.2.10      # HTTP probing -> banned
GLOBAL_B=198.51.100.10   # does nothing wrong -> always let through
GLOBAL_C=203.0.113.10    # AppSec
GLOBAL_F=192.0.2.20      # L4: refused by allow_from repeatedly -> banned
GLOBAL_V6=2001:db8::10   # HTTP probing over IPv6 -> banned
PRIVATE=10.99.0.10       # the same probing from a private address -> whitelisted by CrowdSec
HOST4=192.0.2.1
HOST6=2001:db8::1

dump() {
	echo "---- rproxy" >&2
	tail -n 80 "$WORK"/logs/*.log >&2 || true
	echo "---- crowdsec" >&2
	tail -n 80 /var/log/crowdsec.log /var/log/crowdsec.out >&2 || true
	cscli alerts list >&2 || true
	cscli decisions list >&2 || true
	cscli metrics show acquisition parsers scenarios >&2 || true
}
fail() { echo "FAIL: $*" >&2; dump; exit 1; }
cleanup() {
	kill "${PIDS[@]}" 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	ip link del rpcs-host 2>/dev/null || true
}
trap cleanup EXIT
[ "$(id -u)" = 0 ] || { echo "run as root (in a throwaway container)" >&2; exit 1; }
command -v cscli >/dev/null || { echo "no cscli: run this in the crowdsecurity/crowdsec image" >&2; exit 1; }

# the LAPI and the agent in one process, logging to /var/log/crowdsec.log
CROWDSEC=
start_crowdsec() {
	crowdsec -c /etc/crowdsec/config.yaml >> /var/log/crowdsec.out 2>&1 &
	CROWDSEC=$!
	PIDS+=("$CROWDSEC")
}
restart_crowdsec() {
	kill "$CROWDSEC" 2>/dev/null || true
	wait "$CROWDSEC" 2>/dev/null || true
	start_crowdsec
}

echo "== CrowdSec"
# what the image's entrypoint (docker_start.sh) would do: the configuration and data from /staging,
# and the local agent's credentials
mkdir -p /etc/crowdsec /var/lib/crowdsec/data
cp -a /staging/etc/crowdsec/. /etc/crowdsec/
cp -a /staging/var/lib/crowdsec/data/. /var/lib/crowdsec/data/
sed -i 's/^\(  *log_media:\).*/\1 file/' /etc/crowdsec/config.yaml
cscli machines add localhost --auto --force >/dev/null
cscli hub update >/dev/null
cscli collections install crowdsecurity/base-http-scenarios crowdsecurity/http-cve \
	crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules >/dev/null
cscli parsers install crowdsecurity/http-logs crowdsecurity/whitelists >/dev/null 2>&1 || true
install -m 644 "$ROOT/contrib/crowdsec/parsers/s01-parse/rproxy-logs.yaml" /etc/crowdsec/parsers/s01-parse/
install -m 644 "$ROOT"/contrib/crowdsec/scenarios/*.yaml /etc/crowdsec/scenarios/
mkdir -p /etc/crowdsec/acquis.d
install -m 644 "$ROOT/contrib/crowdsec/acquis.d/appsec.yaml" /etc/crowdsec/acquis.d/appsec.yaml
sed "s#/var/log/rproxy/\*\.log#$WORK/logs/*.log#" "$ROOT/contrib/crowdsec/acquis.d/rproxy.yaml" \
	> /etc/crowdsec/acquis.d/rproxy.yaml
cscli version 2>&1 | head -3
start_crowdsec

echo "== parser (cscli explain on sample lines)"
explain=$(cscli explain --file "$ROOT/scripts/interop/crowdsec-samples.log" --type rproxy 2>&1) || fail "cscli explain: $explain"
echo "$explain"
parsed=$(grep -c '🟢 max3584/rproxy-logs' <<<"$explain" || true)
[ "$parsed" = 7 ] || fail "our parser handled $parsed of 7 sample lines"
grep -q '🟢 crowdsecurity/http-logs' <<<"$explain" || fail "http.access lines did not reach crowdsecurity/http-logs"
grep -q '🟢 crowdsecurity/http-sensitive-files' <<<"$explain" || fail "http scenarios did not see GET /.env"
grep -q 'max3584/rproxy-conn-denied' <<<"$explain" || fail "conn.denied did not reach max3584/rproxy-conn-denied"
grep -q 'max3584/rproxy-conn-limited' <<<"$explain" || fail "conn.limited did not reach max3584/rproxy-conn-limited"

echo "== network: clients with documentation (global) and private addresses"
ip netns add "$NS"
ip link add rpcs-host type veth peer name rpcs-cli
ip link set rpcs-cli netns "$NS"
for a in "$HOST4/24" 198.51.100.1/24 203.0.113.1/24 10.99.0.1/24; do ip addr add "$a" dev rpcs-host; done
ip -6 addr add "$HOST6/64" dev rpcs-host nodad
ip link set rpcs-host up
for a in "$GLOBAL_A/24" "$GLOBAL_F/24" "$GLOBAL_B/24" "$GLOBAL_C/24" "$PRIVATE/24"; do
	ip netns exec "$NS" ip addr add "$a" dev rpcs-cli
done
ip netns exec "$NS" ip -6 addr add "$GLOBAL_V6/64" dev rpcs-cli nodad
ip netns exec "$NS" ip link set rpcs-cli up
ip netns exec "$NS" ip link set lo up

echo "== backend and rproxy"
mkdir -p "$WORK/www" "$WORK/logs"
echo ok > "$WORK/www/index.html"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$WORK/www" > "$WORK/backend.out" 2>&1 &
PIDS+=($!)
for _ in $(seq 60); do cscli lapi status >/dev/null 2>&1 && break; sleep 1; done
cscli lapi status >/dev/null 2>&1 || fail "the CrowdSec LAPI is not up"
key=$(cscli bouncers add rproxy-ci -o raw)
printf '%s\n' "$key" > "$WORK/bouncer.key"
cat > "$WORK/rproxy.yaml" <<EOF
version: 1
global:
  crowdsec:
    lapi_url: http://127.0.0.1:8080
    api_key_file: $WORK/bouncer.key
    appsec_url: http://127.0.0.1:7422
    update_interval: 2s
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    extra_listen_addrs: ["::"]
    listen_port: 8088
    http:
      routes:
        - {name: appsec, match: "Host(\`appsec.test\`)", to: "http://127.0.0.1:8081", middlewares: [cs-appsec]}
        - {name: site, match: "PathPrefix(\`/\`)", to: "http://127.0.0.1:8081", middlewares: [cs]}
      middlewares:
        cs: {crowdsec: {}}
        cs-appsec: {crowdsec: {appsec: true}}
  # L4 with the CrowdSec decisions: banned clients are cut before anything is relayed
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8089
    remote_addr: 127.0.0.1
    remote_port: 8081
    crowdsec: true
  # L4 that refuses everyone outside 127.0.0.0/8 (conn.denied -> max3584/rproxy-conn-denied)
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8090
    remote_addr: 127.0.0.1
    remote_port: 8081
    allow_from: ["127.0.0.0/8"]
EOF
(cd "$WORK" && RPROXY_API_PORT=18400 RPROXY_CONFIG="$WORK/rproxy.yaml" RPROXY_LOG_FILE="$WORK/logs/rproxy.log" \
	exec "$BIN" > "$WORK/rproxy.out" 2>&1) &
PIDS+=($!)
for _ in $(seq 50); do curl -sf "$API/healthz" >/dev/null && break; sleep 0.2; done
curl -sf "$API/healthz" >/dev/null || fail "rproxy did not start: $(cat "$WORK/rproxy.out")"

# reload CrowdSec now that the log directory exists, with our parser, scenarios and acquisitions
restart_crowdsec
for _ in $(seq 60); do cscli lapi status >/dev/null 2>&1 && break; sleep 1; done
for _ in $(seq 60); do curl -s -o /dev/null http://127.0.0.1:7422/ && break; sleep 1; done
curl -s -o /dev/null http://127.0.0.1:7422/ || fail "the AppSec component is not listening"
for _ in $(seq 30); do curl -s "$API/metrics" | grep -q '^rproxy_crowdsec_synced 1' && break; sleep 1; done
curl -s "$API/metrics" | grep -q '^rproxy_crowdsec_synced 1' || fail "rproxy never got the decisions stream from the LAPI"

# req <source address> <url> [curl args...] -> HTTP status (000 when the connection fails)
req() {
	local src=$1 url=$2
	shift 2
	ip netns exec "$NS" curl -g -s -o /dev/null -m 5 -w '%{http_code}' --interface "$src" "$@" "$url" || true
}
banned() { cscli decisions list -i "$1" -o json 2>/dev/null | grep -q '"value"'; }
wait_banned() {
	for _ in $(seq 60); do banned "$1" && return 0; sleep 2; done
	fail "CrowdSec did not ban $1"
}
wait_code() { # wait_code <source> <url> <expected> [curl args...]
	local src=$1 url=$2 want=$3 got=
	shift 3
	for _ in $(seq 30); do
		got=$(req "$src" "$url" "$@")
		[ "$got" = "$want" ] && return 0
		sleep 1
	done
	fail "$src $url: wanted $want, got $got"
}
probe() { # probe <source> <base url>: paths that do not exist, as a scanner would
	local i
	for i in $(seq 40); do req "$1" "$2/wp-admin-$i/backup-$i" >/dev/null; done
}
SITE4=http://$HOST4:8088
SITE6=http://[$HOST6]:8088

echo "== everyone gets through at first"
for src in "$GLOBAL_A" "$GLOBAL_B" "$PRIVATE" "$GLOBAL_V6"; do
	url=$SITE4/
	[ "$src" = "$GLOBAL_V6" ] && url=$SITE6/
	[ "$(req "$src" "$url")" = 200 ] || fail "$src could not reach $url"
done
[ "$(req "$GLOBAL_F" "http://$HOST4:8089/")" = 200 ] || fail "$GLOBAL_F could not reach the L4 rule"

echo "== the private client probes (must not be banned)"
probe "$PRIVATE" "$SITE4"

echo "== HTTP detection: $GLOBAL_A probes -> banned by CrowdSec -> 403 from rproxy"
probe "$GLOBAL_A" "$SITE4"
wait_banned "$GLOBAL_A"
wait_code "$GLOBAL_A" "$SITE4/" 403
[ "$(req "$GLOBAL_B" "$SITE4/")" = 200 ] || fail "$GLOBAL_B was blocked too"
echo "banned and blocked: $GLOBAL_A"

echo "== the same over IPv6: $GLOBAL_V6"
probe "$GLOBAL_V6" "$SITE6"
wait_banned "$GLOBAL_V6"
wait_code "$GLOBAL_V6" "$SITE6/" 403
echo "banned and blocked: $GLOBAL_V6"

echo "== L4: $GLOBAL_F refused by allow_from again and again -> banned -> cut by the crowdsec: true rule"
for _ in $(seq 20); do req "$GLOBAL_F" "http://$HOST4:8090/" >/dev/null; done
wait_banned "$GLOBAL_F"
wait_code "$GLOBAL_F" "http://$HOST4:8089/" 000
[ "$(req "$GLOBAL_B" "http://$HOST4:8089/")" = 200 ] || fail "$GLOBAL_B was cut by the L4 rule too"
echo "banned and cut before relaying: $GLOBAL_F"

echo "== AppSec: $GLOBAL_C"
[ "$(req "$GLOBAL_C" "$SITE4/" -H 'Host: appsec.test')" = 200 ] || fail "a normal request through AppSec was refused"
code=$(req "$GLOBAL_C" "$SITE4/.env" -H 'Host: appsec.test')
[ "$code" = 403 ] || fail "AppSec did not block GET /.env (crowdsecurity/vpatch-env-access): $code"
[ "$(req "$GLOBAL_C" "$SITE4/index.html" -H 'Host: appsec.test')" = 200 ] || fail "a normal request after the AppSec block was refused"
echo "AppSec blocked /.env and let normal requests through"

echo "== unbanning lets the client in again"
cscli decisions delete -i "$GLOBAL_A" >/dev/null
wait_code "$GLOBAL_A" "$SITE4/" 200
echo "unbanned: $GLOBAL_A"

echo "== the private client was never banned (CrowdSec whitelist)"
banned "$PRIVATE" && fail "$PRIVATE (RFC 1918) was banned"
[ "$(req "$PRIVATE" "$SITE4/")" = 200 ] || fail "$PRIVATE was blocked"
echo "== what CrowdSec saw"
cscli alerts list 2>/dev/null || true
cscli metrics show acquisition parsers 2>/dev/null | grep -i rproxy || true
echo "ok"
