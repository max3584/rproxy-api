#!/usr/bin/env bash
# 実際の coturn（TURN）と MediaMTX（RTSP）を rproxy の後ろに置いて通し、10000 ポートの範囲ルールの
# 起動時間・メモリ・ファイル数を測る（issue #16）。GitHub の Ubuntu ランナー用（sudo でパッケージを入れる）。
#
#   cargo build && scripts/interop/media.sh
#
# ポートは root のいらない番号にしている（23478 = TURN 3478、25349 = TURNS / DTLS 5349、28554 = RTSP 554、
# 28322 = RTSPS 322）。rproxy-api を本番で動かしている機械では実行しない。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${BIN:-$ROOT/target/debug/rproxy-api}
WORK=$(mktemp -d)
API=http://127.0.0.1:18400
MEDIAMTX_VERSION=${MEDIAMTX_VERSION:-v1.21.1}
PIDS=()

fail() { echo "FAIL: $*" >&2; tail -n 30 "$WORK"/*.log >&2 || true; ss -ltnup >&2 || true; exit 1; }
cleanup() { kill "${PIDS[@]}" 2>/dev/null || true; }
trap cleanup EXIT

echo "== packages"
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q coturn ffmpeg openssl >/dev/null
sudo systemctl stop coturn 2>/dev/null || true
curl -fsSL "https://github.com/bluenviron/mediamtx/releases/download/$MEDIAMTX_VERSION/mediamtx_${MEDIAMTX_VERSION}_linux_amd64.tar.gz" \
	| tar -xz -C "$WORK" mediamtx mediamtx.yml

echo "== test CA and the media.test certificate"
grep -q ' media.test$' /etc/hosts || echo '127.0.0.1 media.test' | sudo tee -a /etc/hosts >/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=interop-ca \
	-keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=media.test \
	-keyout "$WORK/media.key" -out "$WORK/media.csr" 2>/dev/null
printf 'subjectAltName=DNS:media.test\n' > "$WORK/san.ext"
openssl x509 -req -in "$WORK/media.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial -days 2 \
	-extfile "$WORK/san.ext" -out "$WORK/media.pem" 2>/dev/null

echo "== rproxy"
(cd "$WORK" && RPROXY_API_PORT=18400 exec "$BIN" > "$WORK/rproxy.log" 2>&1) &
PIDS+=($!)
RP=${PIDS[-1]}
for _ in $(seq 50); do curl -sf "$API/healthz" >/dev/null && break; sleep 0.2; done
tls="{\"mode\":\"terminate\",\"certificates\":[{\"cert_file\":\"$WORK/media.pem\",\"key_file\":\"$WORK/media.key\"}]}"
rule() { # rule <json>
	local code
	code=$(curl -s -o "$WORK/resp" -w '%{http_code}' -X POST "$API/rules" -d "$1")
	[ "$code" = 201 ] || fail "rule $1: $code $(cat "$WORK/resp")"
}

echo "== TURN (coturn)"
# relayed addresses are advertised as 127.0.0.2 and reach coturn through a range rule, as a public IP would
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
turnutils_peer -p 13480 -L 127.0.0.1 > "$WORK/peer.log" 2>&1 &
PIDS+=($!)
sleep 1
rule '{"protocol":"udp","listen_addr":"127.0.0.1","listen_port":23478,"remote_addr":"127.0.0.1","remote_port":13478}'
rule '{"protocol":"tcp","listen_addr":"127.0.0.1","listen_port":23478,"remote_addr":"127.0.0.1","remote_port":13478}'
rule "{\"protocol\":\"tcp\",\"listen_addr\":\"127.0.0.1\",\"listen_port\":25349,\"remote_addr\":\"127.0.0.1\",\"remote_port\":13478,\"tls\":$tls}"
rule "{\"protocol\":\"udp\",\"listen_addr\":\"127.0.0.1\",\"listen_port\":25349,\"remote_addr\":\"127.0.0.1\",\"remote_port\":13478,\"tls\":$tls}"
rule '{"protocol":"udp","listen_addr":"127.0.0.2","listen_port":49200,"listen_port_end":49299,"remote_addr":"127.0.0.1","remote_port":49200}'

turn() { # turn <name> <port> [uclient flags]
	local name=$1 port=$2
	shift 2
	# 10 messages from 1 client to the peer through the relayed address (-e / -r)
	if ! timeout 60 turnutils_uclient -u interop -w interop-pass -p "$port" -e 127.0.0.1 -r 13480 -n 10 -m 1 -l 64 "$@" 127.0.0.1 \
		> "$WORK/uclient-$name.log" 2>&1; then
		fail "turn $name: turnutils_uclient failed"
	fi
	local sent recv lost
	sent=$(sed -n 's/.*tot_send_msgs=\([0-9]*\).*/\1/p' "$WORK/uclient-$name.log" | tail -n1)
	recv=$(sed -n 's/.*tot_recv_msgs=\([0-9]*\).*/\1/p' "$WORK/uclient-$name.log" | tail -n1)
	lost=$(sed -n 's/.*Total lost packets \([0-9]*\).*/\1/p' "$WORK/uclient-$name.log" | tail -n1)
	echo "turn $name: sent=${sent:-?} received=${recv:-?} lost=${lost:-?}"
	if [ -z "$sent" ] || [ "$sent" = 0 ] || [ "$sent" != "$recv" ]; then
		cat "$WORK/uclient-$name.log" >&2
		fail "turn $name: messages did not come back"
	fi
}
turn udp 23478
turn tcp 23478 -t
turn tls 25349 -t -S
turn dtls 25349 -S

echo "== RTSP (MediaMTX)"
(cd "$WORK" && MTX_RTSPADDRESS=127.0.0.1:18554 MTX_RTSPTRANSPORTS=tcp MTX_RTMP=no MTX_HLS=no MTX_WEBRTC=no MTX_SRT=no \
	MTX_API=no MTX_METRICS=no MTX_PPROF=no MTX_PLAYBACK=no exec ./mediamtx > "$WORK/mediamtx.log" 2>&1) &
PIDS+=($!)
for _ in $(seq 50); do grep -q 'RTSP\] started' "$WORK/mediamtx.log" && break; sleep 0.2; done
grep -q 'RTSP\] started' "$WORK/mediamtx.log" || fail "MediaMTX did not start"
rule '{"protocol":"tcp","listen_addr":"127.0.0.1","listen_port":28554,"remote_addr":"127.0.0.1","remote_port":18554}'
rule "{\"protocol\":\"tcp\",\"listen_addr\":\"127.0.0.1\",\"listen_port\":28322,\"remote_addr\":\"127.0.0.1\",\"remote_port\":18554,\"tls\":$tls}"

# publish through rproxy (TCP interleaved)
ffmpeg -nostdin -loglevel error -re -f lavfi -i testsrc=size=320x240:rate=15 -t 40 -c:v libx264 -preset ultrafast \
	-tune zerolatency -f rtsp -rtsp_transport tcp rtsp://127.0.0.1:28554/interop > "$WORK/publish.log" 2>&1 &
PIDS+=($!)
probe() { # probe <url>
	timeout 20 ffprobe -v error -rtsp_transport tcp -show_entries stream=codec_name,width,height -of csv=p=0 "$1" 2>&1
}
for _ in $(seq 30); do out=$(probe rtsp://127.0.0.1:28554/interop || true); [[ $out == h264,320,240* ]] && break; sleep 1; done
echo "rtsp: $out"
[[ $out == h264,320,240* ]] || fail "rtsp: no stream through rproxy"
out=$(probe rtsps://media.test:28322/interop || true)
echo "rtsps: $out"
[[ $out == h264,320,240* ]] || fail "rtsps: no stream through rproxy's TLS termination"

echo "== a 10000-port range rule"
fds() { sudo ls "/proc/$RP/fd" | wc -l; }
rss() { awk '/VmRSS/ {print $2}' "/proc/$RP/status"; }
before_fds=$(fds)
before_rss=$(rss)
start=$(date +%s%N)
rule '{"protocol":"udp","listen_addr":"127.0.0.1","listen_port":30000,"listen_port_end":39999,"remote_addr":"127.0.0.1","remote_port":30000}'
ms=$(( ($(date +%s%N) - start) / 1000000 ))
during_fds=$(fds)
during_rss=$(rss)
curl -s -o /dev/null -X DELETE "$API/rules/udp/127.0.0.1/30000"
sleep 1
after_fds=$(fds)
echo "range 10000 ports: created in ${ms} ms; fds ${before_fds} -> ${during_fds} -> ${after_fds}; RSS ${before_rss} -> ${during_rss} kB"
[ $((during_fds - before_fds)) -ge 10000 ] || fail "the range did not open 10000 sockets"
[ $((after_fds - before_fds)) -lt 50 ] || fail "sockets were not released after DELETE"
[ "$ms" -lt 30000 ] || fail "creating the range took ${ms} ms"
[ $((during_rss - before_rss)) -lt 262144 ] || fail "the range took more than 256 MiB"
echo "OK"
