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
PORT=8080 # read from rproxy.env after the install
api() { curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(sudo cat /etc/rproxy/tokens)" "http://127.0.0.1:$PORT$1"; }
wait_api() {
	for _ in $(seq 50); do
		[ "$(api /rules)" = 200 ] && return 0
		sleep 0.2
	done
	fail "API did not answer with the generated token"
}

echo "== install from the file, with 8080 taken (as by CrowdSec's local API)"
python3 -m http.server 8080 --bind 127.0.0.1 >/dev/null 2>&1 &
blocker=$!
sleep 0.5
sudo apt-get install -y "$deb"
kill $blocker
PORT=$(sudo sed -n 's/^RPROXY_API_PORT=//p' /etc/rproxy/rproxy.env)
[ "$PORT" = 8081 ] || fail "the control API did not move off the busy port 8080 (RPROXY_API_PORT=$PORT)"
getent passwd rproxy-api >/dev/null || fail "no rproxy-api user"
[ "$(id -gn rproxy-api)" = rproxy ] || fail "rproxy-api's primary group is not rproxy"
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
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/rules")" = 401 ] || fail "API answered without a token"
# the unit's capability lets it listen below 1024 as the rproxy-api user
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
	-d '{"protocol":"tcp","listen_addr":"127.0.0.1","listen_port":25,"remote_addr":"127.0.0.1","remote_port":2525}' \
	"http://127.0.0.1:$PORT/rules")
[ "$code" = 201 ] || fail "could not open port 25 (HTTP $code)"
[ "$(ps -o uid= -C rproxy-api | tr -d ' ')" = "$(id -u rproxy-api)" ] || fail "not running as rproxy-api"
# StateDirectory: where global.acme keeps account keys and certificates (docs/ACME.md)
[ "$(stat -c %U /var/lib/rproxy)" = rproxy-api ] || fail "/var/lib/rproxy is not the rproxy-api user's"
# the ACME helper: its user and unit are installed, not enabled (docs/ACME.md)
getent passwd rproxy-acme >/dev/null || fail "no rproxy-acme user"
[ -f /lib/systemd/system/rproxy-acme-helper.service ] || [ -f /usr/lib/systemd/system/rproxy-acme-helper.service ] || fail "no rproxy-acme-helper.service"
! systemctl is-enabled --quiet rproxy-acme-helper || fail "the ACME helper is enabled by default"
# the default configuration logs to /var/log/rproxy (JSON Lines, rotated by rproxy itself)
sudo sh -c 'head -n1 /var/log/rproxy/rproxy.*.log' | grep -q '"event"' || fail "no JSON log in /var/log/rproxy"
curl -s -H "Authorization: Bearer $token" "http://127.0.0.1:$PORT/capabilities" | grep -q '"transparent":true' ||
	fail "source_ip transparent is not available (CAP_NET_ADMIN)"
sudo systemctl reload rproxy-api
sleep 0.5
systemctl is-active --quiet rproxy-api || fail "reload stopped the service"
# the unit checks the settings file before signalling (--check-config): a mistake
# fails the reload and leaves the service running
printf 'version: 9\nrules: []\n' | sudo tee /etc/rproxy/broken.yaml >/dev/null
sudo cp /etc/rproxy/rproxy.env "$work/rproxy.env.saved"
echo 'RPROXY_CONFIG=/etc/rproxy/broken.yaml' | sudo tee -a /etc/rproxy/rproxy.env >/dev/null
if sudo systemctl reload rproxy-api; then
	fail "reload went through with a broken settings file"
fi
systemctl is-active --quiet rproxy-api || fail "a failed reload stopped the service"
sudo -u rproxy-api /usr/bin/rproxy-api --check-config /etc/rproxy/broken.yaml >/dev/null 2>&1 && fail "--check-config accepted version 9"
sudo cp "$work/rproxy.env.saved" /etc/rproxy/rproxy.env
sudo rm /etc/rproxy/broken.yaml
sudo systemctl reload rproxy-api || fail "reload failed after the settings file was fixed"

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
# the same major.minor: the package hands the running service over to the new
# binary without a restart (#174); the rule made through the API stays
pid=$(systemctl show -p MainPID --value rproxy-api)
sudo apt-get install -y --reinstall rproxy-api | tee "$work/reinstall.log"
[ "$(sudo cat /etc/rproxy/tokens)" = "$token" ] || fail "reinstall replaced the token"
wait_api
systemctl is-enabled --quiet rproxy-api || fail "reinstall disabled the service"
grep -q 'without a restart' "$work/reinstall.log" || fail "the upgrade did not hand over (see the apt output)"
now=$(systemctl show -p MainPID --value rproxy-api)
[ "$now" != "$pid" ] || fail "the main process did not change"
systemctl is-active --quiet rproxy-api || fail "not active after the live upgrade"
curl -s -H "Authorization: Bearer $token" "http://127.0.0.1:$PORT/rules" | grep -q '"listen_port":25' ||
	fail "the rule made through the API did not survive the live upgrade"
# the glob is expanded by root (the log directory is not readable by the runner user)
for _ in $(seq 50); do
	sudo sh -c 'grep -qh "\"event\":\"handoff.done\"" /var/log/rproxy/rproxy.*.log' && break
	sleep 0.2
done
sudo sh -c 'grep -qh "\"event\":\"handoff.done\"" /var/log/rproxy/rproxy.*.log' || fail "no handoff.done in the log"

echo "== purge"
sudo apt-get purge -y rproxy-api
! systemctl is-active --quiet rproxy-api || fail "still running after purge"
[ ! -e /etc/rproxy ] || fail "/etc/rproxy left behind after purge"
[ ! -e /var/log/rproxy ] || fail "/var/log/rproxy left behind after purge"
[ ! -e /var/lib/rproxy ] || fail "/var/lib/rproxy (ACME storage) left behind after purge"
sudo rm -f /etc/apt/sources.list.d/rproxy-api.list /usr/share/keyrings/rproxy-archive-keyring.gpg

echo "== upgrade from v0.3.21: the user rproxy becomes rproxy-api with the same uid"
# a host as v0.3 left it: no rproxy-api user and no shared rproxy group yet (v0.3.21's postinst fails when the group exists without the user)
sudo userdel rproxy-api 2>/dev/null || true
sudo groupdel rproxy 2>/dev/null || true
arch=$(dpkg --print-architecture)
curl -fsSL -o "$work/old.deb" "https://github.com/max3584/rproxy-api/releases/download/v0.3.21/rproxy-api_0.3.21-1_${arch}.deb"
sudo apt-get install -y "$work/old.deb"
getent passwd rproxy >/dev/null || fail "v0.3.21 did not make the rproxy user"
old_uid=$(id -u rproxy)
# a key of the service's, as an operator gives it (the owner check of v0.4 needs this)
sudo install -o rproxy -g rproxy -m 0640 /dev/null /etc/rproxy/service.key
sudo systemctl enable --now rproxy-api
PORT=$(sudo sed -n 's/^RPROXY_API_PORT=//p' /etc/rproxy/rproxy.env)
wait_api
sudo apt-get install -y "$deb" | tee "$work/upgrade.log"
! getent passwd rproxy >/dev/null || fail "the rproxy user is still there"
[ "$(id -u rproxy-api)" = "$old_uid" ] || fail "rproxy-api does not have rproxy's uid"
[ "$(id -gn rproxy-api)" = rproxy ] || fail "rproxy-api's primary group is not rproxy"
[ "$(sudo stat -c '%U:%G' /etc/rproxy/service.key)" = rproxy-api:rproxy ] || fail "the service's files changed owner"
wait_api
systemctl is-active --quiet rproxy-api || fail "not running after the upgrade"
[ "$(ps -o uid= -C rproxy-api | tr -d ' ')" = "$old_uid" ] || fail "not running as rproxy-api after the upgrade"
sudo apt-get purge -y rproxy-api
echo "OK"
