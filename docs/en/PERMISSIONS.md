日本語: [PERMISSIONS.md](../PERMISSIONS.md)

# Permissions

rproxy-api is designed on the assumption that it runs on hosts with root or strong network privileges.
Host configuration (package installation, policy routing) is done as root. rproxy-api itself runs as the `rproxy` user and receives only the capabilities it needs from systemd.

## Permissions of the rproxy-api process

| Capability | Feature that uses it | If removed |
|---|---|---|
| `CAP_NET_BIND_SERVICE` | Listening on ports below 1024 (25, 443, etc.) | Only rules below 1024 become unusable. Creation via the API returns `bind_failed` (with the reason and the required permission); rules restored at startup and static rules remain as `failed` |
| `CAP_NET_ADMIN` | `source_ip: transparent` (connecting while claiming the client's IP using `IP_TRANSPARENT`) | `transparent` in `GET /capabilities` becomes false and the option disappears from the UI (the reason is shown). Creation via the API returns `unsupported`. Transparent rules restored from the DB and static rules remain as `failed` (`needs Linux and CAP_NET_ADMIN`). Also used to set `global.performance.busy_poll_usecs` above `net.core.busy_read` (without it: `degraded`, no busy polling) |

rproxy-api starts even if either permission is removed, and the other rules keep working (the CI `install.sh` job verifies this with both removed via a drop-in). A static rules file only stops startup on writing errors (invalid addresses, overlapping rules, etc.), not on rules that merely lack permissions.

- Both are granted by `AmbientCapabilities` and `CapabilityBoundingSet` in the unit (`/usr/lib/systemd/system/rproxy-api.service`, or `/etc/systemd/system/` for the install.sh binary). No other capabilities are held.
- Permissions you do not use can be removed with `systemctl edit rproxy-api`. Rerunning install.sh does not restore removed permissions.
  ```ini
  [Service]
  # Do not use transparent
  AmbientCapabilities=
  AmbientCapabilities=CAP_NET_BIND_SERVICE
  CapabilityBoundingSet=~CAP_NET_ADMIN
  ```
- The unit has `NoNewPrivileges=yes`, so capabilities set on the binary with `setcap` have no effect. Grant permissions in the unit.
- When starting manually (without systemd), run as root or apply `setcap cap_net_bind_service,cap_net_admin+ep` to the binary.

### systemd sandbox

| Setting | Effect |
|---|---|
| `ProtectSystem=strict` | `/usr`, `/etc`, etc. are read-only. Only `/var/log/rproxy` (`LogsDirectory`) and `/var/lib/rproxy` (`StateDirectory`; ACME storage) are writable |
| `ProtectHome=yes` | `/home` and `/root` are not visible. Certificates, keys and static rules files placed there cannot be read |
| `PrivateTmp=yes` | `/tmp` is private to the service. Files in the host's `/tmp` are not visible |
| `LimitNOFILE=65536` | Port range rules use one socket per port (the limit is raised to the maximum at startup) |
| `Type=notify`, `NotifyAccess=all`, `RuntimeDirectory=rproxy` | Live upgrades (#174, docs/en/UPGRADE.md): the old process passes its sockets over `/run/rproxy/handoff.sock` (0600; only the pid of the child it started is accepted) and makes the new process the main one with `MAINPID=`. The new process runs in the same unit with the same (ambient) capabilities |

### The ACME helper (`rproxy-acme-helper.service`, optional)

With `global.acme.helper` (docs/en/ACME.md, "Helper process"). Only this process reads the DNS providers' secrets.

| Item | Value |
|---|---|
| User | `rproxy-acme` (created by the .deb's postinst), with the supplementary group `rproxy` (to read the settings file and own the socket's group) |
| Capabilities | None (`CapabilityBoundingSet=` empty) |
| Socket | `/run/rproxy-acme/helper.sock` (`rproxy-acme:rproxy` 660; `RuntimeDirectory=rproxy-acme`). `--allow-user rproxy` checks the peer's user too |
| Secret files | e.g. `/etc/rproxy/acme-helper/` (`root:rproxy-acme` 750, files 640); not readable by the rproxy user |
| What it writes | `/var/lib/rproxy-acme/` (`StateDirectory`, 700): acme-dns's `credentials_file` |

## Host configuration (root)

| Task | How |
|---|---|
| Install / uninstall | `apt`, or `scripts/install.sh` (run as root) |
| Policy routing for transparent return packets | `install.sh --transparent-clients <CIDR> --transparent-iface <IF>`. `rproxy-transparent-routing.service` sets up `ip rule` / `ip route` (table 100) at boot. The configuration is in `/etc/rproxy/transparent-routing.conf` |
| Return route from upstreams | Set the upstream's default gateway to the rproxy host (or point the route to clients at rproxy on the upstream). This is work on the upstream side, so it is outside the scope of install.sh |

## Files

| Path | Owner / mode | Contents and notes |
|---|---|---|
| `/etc/rproxy/` | `root:rproxy` 750 | Location of configuration. The rproxy user only reads it |
| `/etc/rproxy/rproxy.env` | `root:root` 640 | Configuration. May contain the DB password. systemd (root) reads it and passes it as environment variables, so the rproxy user does not need to be able to read it |
| `/etc/rproxy/tokens` | `root:rproxy` 640 | Control API tokens (one per line, or YAML with scopes). After changing, run `systemctl reload rproxy-api` |
| Certificates and private keys (`cert_file` / `key_file` / `ca_file` / `chain_file` in `tls`) | e.g. `root:rproxy` 640 | Must be readable by the rproxy user. Place them outside `/home`, `/root` and `/tmp` (e.g. `/etc/rproxy/tls/`) |
| CrowdSec API key (`global.crowdsec.api_key_file`, e.g. `/etc/rproxy/crowdsec.key`) | `root:rproxy` 640 | Key created with `cscli bouncers add rproxy`. Must be readable by the rproxy user. After changing, run `systemctl reload rproxy-api` |
| Secrets for authentication middlewares (`users_file` of `basic_auth`, `client_secret_file` / `cookie_secret_file` of `oidc`; e.g. `/etc/rproxy/auth/`) | `root:rproxy` 640 (directory 750) | Must be readable by the rproxy user. Do not let other users read them (a leaked `cookie_secret_file` allows forging session cookies; `client_secret_file` is the provider's client secret). If unreadable, that middleware returns 503. Changes are reloaded within a few seconds (immediately on SIGHUP). Changing `cookie_secret_file` signs everyone out |
| Static rules (`RPROXY_STATIC_RULES`) | e.g. `root:rproxy` 640 | Same as above. install.sh checks that the rproxy user can read it |
| `/run/rproxy/api.sock` (`RPROXY_API_SOCKET`) | `rproxy:<RPROXY_API_SOCKET_GROUP>` 660 (default) | Unix socket for the control API. Only the owner and group can connect. The unit's `RuntimeDirectory=rproxy` creates `/run/rproxy` (create it yourself when not using systemd) |
| `/etc/rproxy/transparent-routing.conf` | `root:root` 644 | Policy routing configuration for transparent |
| `/var/lib/rproxy/` (default `global.acme.storage` is `/var/lib/rproxy/acme`) | `rproxy:rproxy` 750 (below `acme/`: directories 700, files 600) | ACME account keys (`accounts/<name>.key`), certificates obtained and their keys (`certs/`), DNS-01 TXT records not removed yet (`dns-pending.json`). Created by the unit's `StateDirectory=rproxy`. A leaked account key lets someone order and revoke certificates with that account. Removed on purge (docs/en/ACME.md) |
| Secrets of ACME DNS providers (`api_key_file` / `secret_file` / `tsig_secret_file` / `credentials_file` (acme-dns; written by rproxy) of `global.acme.dns_providers`, EAB `hmac_key_file`; e.g. `/etc/rproxy/acme/`) | `root:rproxy` 640 (directory 750) | Must be readable by the rproxy user; do not let other users read them (they can change DNS records; delegating `_acme-challenge` to a zone of its own and using a key limited to that zone narrows the damage). Not readable through the API |
| `/var/log/rproxy/` | `rproxy:rproxy` 750 | Logs. They contain client IPs, SNI and client certificate CNs, so restrict who can view them |

## Control API

- Using the Unix socket (`RPROXY_API_SOCKET`) lets you restrict which users can connect via the file mode and group (loopback TCP can be reached by anyone on the same host). TCP can be closed with `RPROXY_API_PORT=0`.
- The default listen address is `127.0.0.1`. Listening on anything other than loopback requires both a token file and a TLS certificate (it will not start if either is missing).
- Tokens written one per line have full permissions. With the YAML format, each token can be given scopes (`rules:read` / `rules:write` / `metrics:read` / `admin`), the listen ports it may change, and an expiry date, and only the SHA-256 is stored in the file (docs/API.md). Changes are recorded in the `event: "audit"` log.
- Multiple tokens can be active at the same time, so tokens can be rotated without downtime: add a new token and reload, switch the UI over, then remove the old token.

## DB (MariaDB)

| User | Privileges | Purpose |
|---|---|---|
| For rproxy-api (e.g. `rproxy`) | `SELECT ON forward_rules` | Restores rules at startup (does not write) |
| For the UI (e.g. `rproxy_ui`) | `SELECT, INSERT, UPDATE, DELETE ON forward_rules`, `SELECT, INSERT ON forward_rules_log` | Rule management and change history |

GRANT examples are in `db/README.md` in the UI repository.

## UI (TCP-UDP-rproxy-ui)

- Only users signed in via Keycloak can use it. Rules are owned per user (Keycloak `sub`), and other users' rules are not visible. Static rules are visible to anyone who is signed in (they cannot be changed).
- Role-based permission separation (read-only, etc.) is under consideration in UI #4.
- The UI server holds `RPROXY_API_TOKEN` (the rproxy token) and the DB password. Set `.env.local` to 600.

## GitHub (development and distribution)

| Item | Location | Notes |
|---|---|---|
| apt repository signing key | Actions Secrets (`APT_GPG_PRIVATE_KEY` / `APT_GPG_KEY_ID`) | No passphrase. A backup is kept offline (docs/APT.md) |
| main / master | Ruleset | Can only be changed via PRs, and cannot be merged until required CI checks pass. Force pushes and deletion are prohibited |
| `v*` tags | Ruleset | Deletion and re-pointing are prohibited (the contents of a published version must not change) |
