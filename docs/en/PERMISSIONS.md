日本語: [PERMISSIONS.md](../PERMISSIONS.md)

# Permissions

rproxy-api is designed on the assumption that it runs on hosts with root or strong network privileges.
Host configuration (package installation, policy routing) is done as root. rproxy-api itself runs as the `rproxy-api` user (primary group `rproxy`) and receives only the capabilities it needs from systemd. The v0.3 user `rproxy` is renamed to `rproxy-api` by the v0.4 .deb and install.sh with its uid unchanged (file ownership stays). Putting the UI user `rproxy-ui` into group `rproxy` lets the two share files by group read.

## Permissions of the rproxy-api process

| Capability | Feature that uses it | If removed |
|---|---|---|
| `CAP_NET_BIND_SERVICE` | Listening on ports below 1024 (25, 443, etc.) | Only rules below 1024 become unusable. Creation via the API returns `bind_failed` (with the reason and the required permission); rules restored at startup and static rules remain as `failed` |
| `CAP_NET_ADMIN` | `source_ip: transparent` (connecting while claiming the client's IP using `IP_TRANSPARENT`) | `transparent` in `GET /capabilities` becomes false and the option disappears from the UI (the reason is shown). Creation via the API returns `unsupported`. Transparent rules restored from the DB and static rules remain as `failed` (`needs Linux and CAP_NET_ADMIN`). Also used to set `global.performance.busy_poll_usecs` above `net.core.busy_read` (without it: `degraded`, no busy polling) |

Kernel offload (`global.performance.xdp`, #260; off by default) additionally needs `CAP_BPF` (`CAP_SYS_ADMIN` on kernels before 5.8) and `CAP_NET_ADMIN`, and AF_XDP `CAP_NET_RAW`. The unit does not grant these by default; add them to `AmbientCapabilities` and `CapabilityBoundingSet` with `systemctl edit rproxy-api` when using it. Without them the startup test fails, `degraded` is logged (`reason: missing CAP_BPF ...`) and the current path runs. `rproxy-api --check-kernel` checks this beforehand.

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
| User | `rproxy-acme` (created by the .deb's postinst), with the supplementary group `rproxy` (to read the settings file and own the socket's group; the primary group of `rproxy-api`) |
| Capabilities | None (`CapabilityBoundingSet=` empty) |
| Socket | `/run/rproxy-acme/helper.sock` (`rproxy-acme:rproxy` 660; `RuntimeDirectory=rproxy-acme`). `--allow-user rproxy-api` checks the peer's user too |
| Secret files | e.g. `/etc/rproxy/acme-helper/` (`root:rproxy-acme` 750, files 640); not readable by the rproxy-api user |
| What it writes | `/var/lib/rproxy-acme/` (`StateDirectory`, 700): acme-dns's `credentials_file` |

### Owner of the files rules name (v0.4, owner's decision)

Files that rules (API, rule sets, settings file) and `global` name (certificates, keys, CAs, chains, a service's `tls`, `client_auth.ca_file`, `users_file` of `basic_auth`, `oidc` secrets, `global.crowdsec.api_key_file`, ACME secrets) are used only when (`global.files.owner_check: strict`, the default) — so a `rules:write` token cannot make rproxy read (use, or probe for) another service's key or a root-owned file:

- the owner is the user rproxy runs as (`rproxy-api`); a symbolic link is checked at its target, and the link itself is owned by rproxy-api or root;
- the group and others cannot write it (`g-w,o-w`);
- keys and secrets are not readable by others (600 or 640; group `rproxy` read is fine, for sharing with the UI); certificates and CAs up to 644.
- Otherwise the API answers `400 tls_config` / `invalid` (with the reason) and a settings file has a configuration error (startup and reload stop). `--check-config` run as the service user reports errors; run as another user (root) it warns about the rproxy-api user. The opened file is checked (fstat), so what is checked is what is read.
- When certbot and the like write root-owned files, copy them in a deploy hook (`install -o rproxy-api -g rproxy -m 0640 privkey.pem /etc/rproxy/tls/a.key`). To use root-owned files in place, set `global.files.owner_check: off` (whoever holds a `rules:write` token can then use any file rproxy can read as a certificate or key; logged as `degraded` at startup).
- Trusted directories (`global.files.trusted_dirs`, else the environment variable `RPROXY_FILES_TRUSTED_DIRS`; absolute paths separated by `:` or `,`; none by default): a file whose real path (of the opened file, after every symbolic link; `..` cannot escape) is under one of them may be owned by root too. This is for Kubernetes Secret volumes (owned by root, group fsGroup, 0440, behind root-owned `..data` links); rproxy-gateway passes `RPROXY_FILES_TRUSTED_DIRS=/var/run/rproxy-gateway/certs`. The other checks stay (no group/other write, keys not readable by others (0440 passes), links owned by rproxy or root); files of users other than root are refused there too. Logged as `files.trusted_dirs` at startup; `--check-config` uses the same. Whatever root puts there can be used as a key by `rules:write` tokens, so keep other files out of it.
- The control API's certificate and token files (`RPROXY_TLS_*`, `RPROXY_TOKEN_FILE`) and GeoIP databases are not checked (rules cannot name them).

### Rule destinations

A `rules:write` token (and `PUT /rulesets`) can point rule destinations (`remote_addr`, `targets`, service `url`s, `forward_auth`'s `address`, the service a `mirror` copies to) anywhere. rproxy does not restrict destinations: to keep them off internal networks (metadata IPs, management services), give such tokens to fewer people and filter the rproxy host's egress.

## Host configuration (root)

| Task | How |
|---|---|
| Install / uninstall | `apt`, or `scripts/install.sh` (run as root) |
| Policy routing for transparent return packets | `install.sh --transparent-clients <CIDR> --transparent-iface <IF>`. `rproxy-transparent-routing.service` sets up `ip rule` / `ip route` (table 100) at boot. The configuration is in `/etc/rproxy/transparent-routing.conf` |
| Return route from upstreams | Set the upstream's default gateway to the rproxy host (or point the route to clients at rproxy on the upstream). This is work on the upstream side, so it is outside the scope of install.sh |

## Files

| Path | Owner / mode | Contents and notes |
|---|---|---|
| `/etc/rproxy/` | `root:rproxy` 750 | Location of configuration. The rproxy-api user only reads it |
| `/etc/rproxy/rproxy.env` | `root:root` 640 | Configuration. May contain the DB password. systemd (root) reads it and passes it as environment variables, so the rproxy-api user does not need to be able to read it |
| `/etc/rproxy/tokens` | `root:rproxy` 640 | Control API tokens (one per line, or YAML with scopes). After changing, run `systemctl reload rproxy-api` |
| Certificates and private keys (`cert_file` / `key_file` / `ca_file` / `chain_file` in `tls`, a service's `tls`) | `rproxy-api:rproxy`, keys 600 or 640, certificates up to 644 | **Only files of the rproxy-api user are used** ("Owner of the files rules name" below). Place them outside `/home`, `/root` and `/tmp` (e.g. `/etc/rproxy/tls/`) |
| CrowdSec API key (`global.crowdsec.api_key_file`, e.g. `/etc/rproxy/crowdsec.key`) | `rproxy-api:rproxy` 640 | Key created with `cscli bouncers add rproxy`. The rproxy-api user's (owner check). After changing, run `systemctl reload rproxy-api` |
| Secrets for authentication middlewares (`users_file` of `basic_auth`, `client_secret_file` / `cookie_secret_file` of `oidc`; e.g. `/etc/rproxy/auth/`) | `rproxy-api:rproxy` 640 (directory 750) | The rproxy-api user's (owner check). Do not let other users read them (a leaked `cookie_secret_file` allows forging session cookies; `client_secret_file` is the provider's client secret). If unreadable, that middleware returns 503. Changes are reloaded within a few seconds (immediately on SIGHUP). Changing `cookie_secret_file` signs everyone out |
| Static rules (`RPROXY_STATIC_RULES`) | e.g. `root:rproxy` 640 | Same as above. install.sh checks that the rproxy-api user can read it |
| `/run/rproxy/api.sock` (`RPROXY_API_SOCKET`) | `rproxy-api:<RPROXY_API_SOCKET_GROUP>` 660 (default) | Unix socket for the control API. Only the owner and group can connect. The unit's `RuntimeDirectory=rproxy` creates `/run/rproxy` (create it yourself when not using systemd) |
| `/run/rproxy/handoff.sock` (`--handoff-socket` / `RPROXY_HANDOFF_SOCKET`, #174) | `rproxy-api` 600 (SEQPACKET) | The handoff socket, present only during a live upgrade. Only the child the old process started (checked by pid) may connect, and the child checks too that the other end is its parent of the same user and that other users cannot write the socket's directory. Without its parent directory (`/run/rproxy`) the handoff ends in `handoff.failed` and the old process keeps running (docs/en/UPGRADE.md) |
| Client CA of the control API (`--tls-client-ca` / `RPROXY_TLS_CLIENT_CA`, #167) | e.g. `root:rproxy` 640 | The CA (PEM) that verifies client certificates (mTLS). Not secret, but whoever can rewrite it can pass certificate authentication, so the rproxy-api user must not be able to write it. Re-read on SIGHUP and when the file changes, like the control API's certificate and key (`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`) |
| GeoIP databases (`country_db` / `asn_db` of `global.geoip`, #168) | e.g. `root:rproxy` 640 | Must be readable by the rproxy-api user (otherwise rproxy starts `degraded` and countries/ASNs are "unknown" until it can read them). Updaters (`geoipupdate` etc.) should replace the file (rename). Re-read every `check_interval` and on SIGHUP |
| `/etc/rproxy/transparent-routing.conf` | `root:root` 644 | Policy routing configuration for transparent |
| `/var/lib/rproxy/` (default `global.acme.storage` is `/var/lib/rproxy/acme`) | `rproxy-api:rproxy` 750 (below `acme/`: directories 700, files 600) | ACME account keys (`accounts/<name>.key`), certificates obtained and their keys (`certs/`), DNS-01 TXT records not removed yet (`dns-pending.json`). Created by the unit's `StateDirectory=rproxy`. A leaked account key lets someone order and revoke certificates with that account. Removed on purge (docs/en/ACME.md) |
| `/var/lib/rproxy/certs/` (default `RPROXY_CERT_STORE`, v0.4.2) | owned by `rproxy-api`; directories 700, files 600 | Certificates and keys received by `PUT /certs/{name}` (#240; written by rproxy itself) |
| Secrets of ACME DNS providers (`api_key_file` / `secret_file` / `tsig_secret_file` / `credentials_file` (acme-dns; written by rproxy) of `global.acme.dns_providers`, EAB `hmac_key_file`; e.g. `/etc/rproxy/acme/`) | `rproxy-api:rproxy` 640 (directory 750) | The rproxy-api user's (owner check; `rproxy-acme`'s with the helper). Must be readable by the rproxy-api user; do not let other users read them (they can change DNS records; delegating `_acme-challenge` to a zone of its own and using a key limited to that zone narrows the damage). Not readable through the API |
| `/var/log/rproxy/` | `rproxy-api:rproxy` 750 | Logs. They contain client IPs, SNI and client certificate CNs, so restrict who can view them |
| Self-update cache (`RPROXY_UPDATE_CACHE`, default `/var/cache/rproxy/update`, #174; only `rproxy-api launch` in containers) | The server user's, 700 (rproxy creates it so) | Fetched release binaries, signatures and manifests (`<version>/`) and `state.json` (good, previous, bad and trial versions). Signatures are verified again before every run, but whoever can write it can tamper with the bad-version marks and rollbacks, so no other user may write it. Put it on a writable volume (the root filesystem may be read-only). Not used on VMs installed with apt (`RPROXY_UPDATE` stays off) |

## Control API

- Using the Unix socket (`RPROXY_API_SOCKET`) lets you restrict which users can connect via the file mode and group (loopback TCP can be reached by anyone on the same host). TCP can be closed with `RPROXY_API_PORT=0`.
- The default listen address is `127.0.0.1`. Listening on anything other than loopback requires both a token file and a TLS certificate (it will not start if either is missing).
- Tokens written one per line have full permissions. With the YAML format, each token can be given scopes (`rules:read` / `rules:write` / `metrics:read` / `acme:write` / `admin`), the listen ports it may change, an expiry date, a bound client certificate (`client_cert`) and whether the rules it creates are stored in the DB (`persist`), and only the SHA-256 is stored in the file (docs/en/API.md). Changes are recorded in the `event: "audit"` log.
- v0.4 (#167): the TCP control API can also check client certificates (mTLS, `--tls-client-auth optional|required` with `--tls-client-ca`). Tokens close to expiry are reported with `token.expiring` / `token.expired`. Sources (IPv6 by /64) with repeated 401s are locked out by default (20 in 1 minute locks for 5 minutes, `429 locked_out`); the Unix socket is not counted ("Control API hardening" in docs/en/API.md).
- Strong operations (`POST /config/reload`, `/admin/upgrade`, `/admin/update`, ACME renew/revoke) are accepted only over the Unix socket by default (`RPROXY_API_RELOAD_UNIX_ONLY`).
- Multiple tokens can be active at the same time, so tokens can be rotated without downtime: add a new token and reload, switch the UI over, then remove the old token.

## DB (MariaDB)

| User | Privileges | Purpose |
|---|---|---|
| For rproxy-api (e.g. `rproxy`; a DB user, not the OS user) | `SELECT ON forward_rules`; to store API-created rules (#144, tokens with `persist: true`) also `SELECT, INSERT, UPDATE, DELETE ON rproxy_rules` | Restores rules at startup (never writes `forward_rules`). Writes only its own `node`'s rows in `rproxy_rules`; without the grant it logs `degraded` (`part: db`) and the rule keeps running with `persisted: false` |
| For the UI (e.g. `rproxy_ui`) | `SELECT, INSERT, UPDATE, DELETE ON forward_rules`, `SELECT, INSERT ON forward_rules_log` | Rule management and change history |

GRANT examples are in `db/README.md` in the UI repository. The definition and GRANT of `rproxy_rules` are in "Storing API-created rules" in docs/en/API.md.

## UI (TCP-UDP-rproxy-ui)

- Only users signed in via Keycloak can use it. Rules are owned per user (Keycloak `sub`), and other users' rules are not visible. Static rules are visible to anyone who is signed in (they cannot be changed).
- Role-based permission separation (read-only, etc.) is under consideration in UI #4.
- The UI server holds `RPROXY_API_TOKEN` (the rproxy token) and the DB password. Set `.env.local` to 600.

## GitHub (development and distribution)

| Item | Location | Notes |
|---|---|---|
| apt repository signing key | Actions Secrets (`APT_GPG_PRIVATE_KEY` / `APT_GPG_KEY_ID`) | No passphrase. A backup is kept offline (docs/APT.md) |
| Release signing key (minisign, #174) | Actions Secret `MINISIGN_SECRET_KEY` (secret key), variable `MINISIGN_PUBLIC_KEY` (public key, built into the binary) | Separate from the apt key. No password. A backup is kept offline. If it leaks, arbitrary binaries can be pushed through the self-update (docs/en/RELEASING.md) |
| main / master | Ruleset | Can only be changed via PRs, and cannot be merged until required CI checks pass. Force pushes and deletion are prohibited |
| `v*` tags | Ruleset | Deletion and re-pointing are prohibited (the contents of a published version must not change) |
