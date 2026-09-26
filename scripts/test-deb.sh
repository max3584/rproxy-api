#!/usr/bin/env bash
# Installs the .deb on this machine and checks what the package promises:
# user, token, unit, API, upgrade from a signed apt repository, and purge.
#
#   scripts/test-deb.sh target/debian/rproxy-api_<version>_amd64.deb
#
# Needs root through sudo and systemd (the GitHub Ubuntu runners have both).
# Do not run it on a machine where rproxy-api is installed for real.
set -euo pipefail

deb=$(realpath "$1")
work=$(mktemp -d)
trap 'kill "$http" 2>/dev/null || true; rm -rf "$work"' EXIT

fail() { echo "FAIL: $*" >&2; sudo journalctl -u rproxy-api --no-pager -n 50 >&2 || true; exit 1; }
api() { curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(sudo cat /etc/rproxy/tokens)" "http://127.0.0.1:8080$1"; }
wait_api() {
	for _ in $(seq 50); do
		[ "$(api /rules)" = 200 ] && return 0
		sleep 0.2
	done
	fail "API did not answer with the generated token"
}

echo "== install from the file"
sudo apt-get install -y "$deb"
getent passwd rproxy >/dev/null || fail "no rproxy user"
[ "$(sudo stat -c '%a %U:%G' /etc/rproxy/tokens)" = "640 root:rproxy" ] || fail "tokens file mode/owner"
[ "$(sudo stat -c '%a %U:%G' /etc/rproxy)" = "750 root:rproxy" ] || fail "/etc/rproxy mode/owner"
# read through sudo: the file is not readable by the runner user
[ "$(sudo cat /etc/rproxy/tokens | wc -l)" = 1 ] || fail "expected one token line"
sudo grep -Eqx '[0-9a-f]{64}' /etc/rproxy/tokens || fail "token is not 64 hex characters"
! systemctl is-active --quiet rproxy-api || fail "started before it was configured"
! systemctl is-enabled --quiet rproxy-api || fail "enabled before it was configured"
token=$(sudo cat /etc/rproxy/tokens)

echo "== start"
sudo systemctl enable --now rproxy-api
wait_api
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/rules)" = 401 ] || fail "API answered without a token"
# the unit's capability lets it listen below 1024 as the rproxy user
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
	-d '{"protocol":"tcp","listen_addr":"127.0.0.1","listen_port":25,"remote_addr":"127.0.0.1","remote_port":2525}' \
	http://127.0.0.1:8080/rules)
[ "$code" = 201 ] || fail "could not open port 25 (HTTP $code)"
[ "$(ps -o user= -C rproxy-api | tr -d ' ')" = rproxy ] || fail "not running as rproxy"
# the default configuration logs to /var/log/rproxy (JSON Lines, rotated by rproxy itself)
sudo sh -c 'head -n1 /var/log/rproxy/rproxy.*.log' | grep -q '"event"' || fail "no JSON log in /var/log/rproxy"
sudo systemctl reload rproxy-api
sleep 0.5
systemctl is-active --quiet rproxy-api || fail "reload stopped the service"

echo "== upgrade from a signed apt repository"
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase '' --quick-gen-key 'rproxy-api CI <ci@example.invalid>' ed25519 sign never
"$(dirname "$0")/apt-repo.sh" "$work/repo" "$deb"
python3 -m http.server 18765 -d "$work/repo" >/dev/null 2>&1 &
http=$!
sudo install -m 644 "$work/repo/rproxy-archive-keyring.gpg" /usr/share/keyrings/rproxy-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/rproxy-archive-keyring.gpg] http://127.0.0.1:18765 stable main" |
	sudo tee /etc/apt/sources.list.d/rproxy-api.list >/dev/null
sleep 0.5
sudo apt-get update -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/rproxy-api.list -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
apt-cache policy rproxy-api | grep -q 'http://127.0.0.1:18765 stable/main' || fail "apt does not see the repository"
sudo apt-get install -y --reinstall rproxy-api
[ "$(sudo cat /etc/rproxy/tokens)" = "$token" ] || fail "reinstall replaced the token"
wait_api
systemctl is-enabled --quiet rproxy-api || fail "reinstall disabled the service"

echo "== purge"
sudo apt-get purge -y rproxy-api
! systemctl is-active --quiet rproxy-api || fail "still running after purge"
[ ! -e /etc/rproxy ] || fail "/etc/rproxy left behind after purge"
[ ! -e /var/log/rproxy ] || fail "/var/log/rproxy left behind after purge"
sudo rm -f /etc/apt/sources.list.d/rproxy-api.list /usr/share/keyrings/rproxy-archive-keyring.gpg
echo "OK"
