#!/usr/bin/env bash
# ブラウザ（ヘッドレスの Chromium）の WebRTC が、rproxy 越しに映像を受け取れることを確かめる（issue #44）。
# CI の Alpine のコンテナ用（root で動かす。パッケージはワークフローが apk で入れる：bash coreutils curl tar
# iproute2 coturn chromium nodejs。MediaMTX はここで落とす）。
#
#   cargo build && scripts/interop/webrtc.sh
#
# 127.0.0.2 を「公開のアドレス」に見立てる（ループバックの /8 はどれも自分のアドレス）。サーバは 127.0.0.1 で
# 待ち、外へは 127.0.0.2 を告知し、127.0.0.2 に来たものを rproxy が 127.0.0.1 のサーバへ通す：
#
#   - 直接：MediaMTX の WebRTC（WHIP / WHEP）。メディアの UDP は 127.0.0.2:18189 を告知し、rproxy の範囲ルール
#     （passthrough）で MediaMTX の 127.0.0.1:18189 へ。シグナリングの HTTP も rproxy（127.0.0.2:28889）越し。
#   - TURN：受け取る側を iceTransportPolicy: relay にして、rproxy 越しの coturn（127.0.0.1:23478）だけでつなぐ。
#     coturn の relay のアドレスは 127.0.0.2 として告知し、rproxy の範囲ルールで coturn へ。
#
# 確かめること：受け取ったフレームが 30 以上、直接は選ばれた候補の相手が 127.0.0.2:18189（rproxy）で範囲ルールに
# バイトが流れた、TURN は受け取った映像のバイト数以上が rproxy の TURN のルールを（coturn からブラウザへ）通った。
# 使い捨てのコンテナの外では実行しない。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${BIN:-$ROOT/target/debug/rproxy-api}
WORK=$(mktemp -d)
API=http://127.0.0.1:18400
MEDIAMTX_VERSION=${MEDIAMTX_VERSION:-v1.21.1}
CHROMIUM=${CHROMIUM:-$(command -v chromium-browser || command -v chromium)}
PIDS=()

fail() { echo "FAIL: $*" >&2; tail -n 40 "$WORK"/*.log >&2 || true; ss -lnup >&2 || true; exit 1; }
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "run as root (in a throwaway container)" >&2; exit 1; }
[ -n "$CHROMIUM" ] || { echo "no chromium" >&2; exit 1; }

echo "== MediaMTX"
curl -fsSL "https://github.com/bluenviron/mediamtx/releases/download/$MEDIAMTX_VERSION/mediamtx_${MEDIAMTX_VERSION}_linux_amd64.tar.gz" \
	| tar -xz -C "$WORK" mediamtx mediamtx.yml
(cd "$WORK" && MTX_RTSP=no MTX_RTMP=no MTX_HLS=no MTX_SRT=no MTX_API=no MTX_METRICS=no MTX_PPROF=no MTX_PLAYBACK=no \
	MTX_WEBRTC=yes MTX_WEBRTCADDRESS=127.0.0.1:18889 MTX_WEBRTCLOCALUDPADDRESS=127.0.0.1:18189 \
	MTX_WEBRTCIPSFROMINTERFACES=no MTX_WEBRTCADDITIONALHOSTS=127.0.0.2 exec ./mediamtx > "$WORK/mediamtx.log" 2>&1) &
PIDS+=($!)
for _ in $(seq 50); do grep -q 'WebRTC\] started with listeners' "$WORK/mediamtx.log" && break; sleep 0.2; done
grep -q 'WebRTC\] started with listeners' "$WORK/mediamtx.log" || fail "MediaMTX did not start"

echo "== TURN (coturn)"
cat > "$WORK/turnserver.conf" <<EOF
listening-ip=127.0.0.1
listening-port=13478
relay-ip=127.0.0.1
external-ip=127.0.0.2/127.0.0.1
min-port=49200
max-port=49299
no-tls
no-dtls
lt-cred-mech
user=interop:interop-pass
realm=interop.test
fingerprint
allow-loopback-peers
no-cli
no-multicast-peers
log-file=stdout
EOF
turnserver -c "$WORK/turnserver.conf" > "$WORK/coturn.log" 2>&1 &
PIDS+=($!)

echo "== rproxy"
(cd "$WORK" && RPROXY_API_PORT=18400 exec "$BIN" > "$WORK/rproxy.log" 2>&1) &
PIDS+=($!)
for _ in $(seq 50); do curl -sf "$API/healthz" >/dev/null && break; sleep 0.2; done
curl -sf "$API/healthz" >/dev/null || fail "rproxy did not start"
rule() { # rule <json>
	local code
	code=$(curl -s -o "$WORK/resp" -w '%{http_code}' -X POST "$API/rules" -d "$1")
	[ "$code" = 201 ] || fail "rule $1: $code $(cat "$WORK/resp")"
}
# MediaMTX: the signaling (HTTP) and the media (UDP, a range rule as for a media server's port range)
rule '{"protocol":"tcp","listen_addr":"127.0.0.2","listen_port":28889,"remote_addr":"127.0.0.1","remote_port":18889}'
rule '{"protocol":"udp","listen_addr":"127.0.0.2","listen_port":18180,"listen_port_end":18199,"remote_addr":"127.0.0.1","remote_port":18180}'
# coturn: the TURN port, and its relayed addresses advertised as 127.0.0.2
rule '{"protocol":"udp","listen_addr":"127.0.0.1","listen_port":23478,"remote_addr":"127.0.0.1","remote_port":13478}'
rule '{"protocol":"udp","listen_addr":"127.0.0.2","listen_port":49200,"listen_port_end":49299,"remote_addr":"127.0.0.1","remote_port":49200}'

echo "== Chromium"
"$CHROMIUM" --version
# host candidates as addresses, not mDNS names (MediaMTX would have to resolve them)
"$CHROMIUM" --headless=new --no-sandbox --disable-gpu --disable-dev-shm-usage --no-first-run \
	--disable-features=WebRtcHideLocalIpsWithMdns --remote-debugging-address=127.0.0.1 --remote-debugging-port=19222 \
	--user-data-dir="$WORK/chromium" about:blank > "$WORK/chromium.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do curl -sf http://127.0.0.1:19222/json/version >/dev/null && break; sleep 0.2; done
curl -sf http://127.0.0.1:19222/json/version >/dev/null || fail "Chromium did not start"

field() { node -e "const v=JSON.parse(process.argv[1]); console.log(String(process.argv[2].split('.').reduce((o,k)=>o?.[k], v) ?? ''))" "$1" "$2"; }
stat() { # stat <listen addr> <port> [rx_bytes | tx_bytes] -> that count of the udp rule
	field "$(curl -s "$API/rules/udp/$1/$2")" "stats.${3:-rx_bytes}"
}
page=http://127.0.0.2:28889/
check() { # check <name> <mode> [turn url] -> JSON of what getStats saw
	local out
	out=$(timeout 90 node "$ROOT/scripts/interop/webrtc-cdp.mjs" 19222 "$page" "$2" "${3:-}" 2> "$WORK/cdp-$1.log") || fail "$1: $(cat "$WORK/cdp-$1.log")"
	echo "$1: $out" >&2
	echo "$out"
}
echo "== direct: media through rproxy's range rule"
media_before=$(stat 127.0.0.2 18180)
out=$(check direct direct)
[ "$(field "$out" framesDecoded)" -ge 30 ] || fail "direct: too few frames decoded: $out"
[ "$(field "$out" remote.address)" = 127.0.0.2 ] && [ "$(field "$out" remote.port)" = 18189 ] \
	|| fail "direct: the media did not go to rproxy's address (127.0.0.2:18189): $out"
media_after=$(stat 127.0.0.2 18180)
echo "range rule 127.0.0.2:18180-18199: rx_bytes $media_before -> $media_after"
[ "$media_after" -gt "$media_before" ] || fail "direct: no bytes through rproxy's range rule"

echo "== TURN: the reader only through coturn behind rproxy (iceTransportPolicy: relay)"
# with iceTransportPolicy: relay the browser has no other way than TURN; Chromium may still name the
# selected local candidate prflx (learned from the binding response through the relay), so what
# counts is that the video it received came down through rproxy's TURN rule
turn_before=$(stat 127.0.0.1 23478 tx_bytes)
out=$(check relay relay 'turn:127.0.0.1:23478?transport=udp')
[ "$(field "$out" framesDecoded)" -ge 30 ] || fail "relay: too few frames decoded: $out"
received=$(field "$out" bytesReceived)
turn_after=$(stat 127.0.0.1 23478 tx_bytes)
echo "TURN rule 127.0.0.1:23478: tx_bytes $turn_before -> $turn_after (the browser received $received bytes of video)"
[ $((turn_after - turn_before)) -ge "$received" ] || fail "relay: the video did not come through rproxy's TURN rule: $out"
echo "OK"
