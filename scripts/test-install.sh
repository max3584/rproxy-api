#!/usr/bin/env bash
# scripts/install.sh をこの機械で実際に動かして確かめる（root と systemd が要る。GitHub の Ubuntu ランナー用）。
#
#   sudo scripts/test-install.sh target/release/rproxy-api
#
# rproxy-api を本番で動かしている機械では実行しない。
set -euo pipefail

bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
install=$here/install.sh

fail() { echo "FAIL: $*" >&2; journalctl -u rproxy-api --no-pager -n 30 >&2 || true; exit 1; }
env_of() { sed -n "s/^$1=//p" /etc/rproxy/rproxy.env | tail -n1; }
api() { curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(cat /etc/rproxy/tokens)" "http://127.0.0.1:$1/rules"; }
log_lines() { cat /var/log/rproxy/rproxy.*.log 2>/dev/null | wc -l; }

echo "== binary: fresh install while 8080 is taken"
python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &
blocker=$!
trap 'kill $blocker 2>/dev/null || true' EXIT
sleep 0.5
"$install" --method binary --binary "$bin"
[ "$(env_of RPROXY_API_PORT)" = 8081 ] || fail "did not move off the busy port 8080"
systemctl is-active --quiet rproxy-api || fail "not running"
systemctl is-enabled --quiet rproxy-api || fail "not enabled"
[ "$(ps -o user= -C rproxy-api | tr -d ' ')" = rproxy ] || fail "not running as rproxy"
[ "$(stat -c '%a %U:%G' /etc/rproxy/tokens)" = "640 root:rproxy" ] || fail "tokens mode/owner"
[ "$(stat -c '%a %U:%G' /etc/rproxy/rproxy.env)" = "640 root:root" ] || fail "env mode/owner"
grep -Eqx '[0-9a-f]{64}' /etc/rproxy/tokens || fail "token format"
[ "$(api 8081)" = 200 ] || fail "API with the token"
[ "$(env_of RPROXY_LOG_FILE)" = /var/log/rproxy/rproxy.log ] || fail "log file is not the default"
[ "$(log_lines)" -gt 0 ] || fail "nothing in /var/log/rproxy"
head -n1 /var/log/rproxy/rproxy.*.log | grep -q '"event"' || fail "log is not JSON Lines"
token=$(cat /etc/rproxy/tokens)

echo "== binary: rerun changes only what is given"
"$install" --method binary --binary "$bin" --api-port 18090 --api-addr 127.0.0.1
[ "$(cat /etc/rproxy/tokens)" = "$token" ] || fail "rerun replaced the token"
[ "$(api 18090)" = 200 ] || fail "API did not move to 18090"
kill $blocker

echo "== binary: static rules must be readable by the service"
echo '[]' > /root/rules.json
! "$install" --method binary --binary "$bin" --static-rules /root/rules.json 2>/dev/null || fail "accepted a file under /root"
install -o root -g rproxy -m 0640 /dev/stdin /etc/rproxy/static-rules.json <<< '[]'
"$install" --method binary --binary "$bin" --static-rules /etc/rproxy/static-rules.json
[ "$(env_of RPROXY_STATIC_RULES)" = /etc/rproxy/static-rules.json ] || fail "static rules not set"

echo "== binary: log to journald with --log-file -"
"$install" --method binary --binary "$bin" --log-file -
grep -q '^# RPROXY_LOG_FILE=' /etc/rproxy/rproxy.env || fail "log file line not commented out"

echo "== binary: uninstall keeps the configuration, purge removes it"
"$install" --uninstall
! systemctl is-active --quiet rproxy-api || fail "still running"
[ ! -e /usr/local/bin/rproxy-api ] || fail "binary left behind"
[ -e /etc/rproxy/tokens ] || fail "uninstall removed the token"
"$install" --uninstall --purge
[ ! -e /etc/rproxy ] && [ ! -e /var/log/rproxy ] || fail "purge left files behind"

echo "== apt: install the published package"
"$install" --method apt
dpkg-query -W -f='${Status}' rproxy-api | grep -q 'install ok installed' || fail "package not installed"
systemctl is-active --quiet rproxy-api || fail "not running"
[ "$(api "$(env_of RPROXY_API_PORT)")" = 200 ] || fail "API with the token"
[ "$(log_lines)" -gt 0 ] || fail "nothing in /var/log/rproxy"
"$install" --uninstall --purge
! dpkg-query -W rproxy-api >/dev/null 2>&1 || dpkg-query -W -f='${Status}' rproxy-api | grep -q 'not-installed' || fail "package still installed"
[ ! -e /etc/apt/sources.list.d/rproxy-api.list ] || fail "apt source left behind"
echo "OK"
