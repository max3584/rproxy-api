# rproxy-api

[![CI](https://github.com/max3584/rproxy-api/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/max3584/rproxy-api/actions/workflows/ci.yml)
[![Interop](https://github.com/max3584/rproxy-api/actions/workflows/interop.yml/badge.svg?branch=master)](https://github.com/max3584/rproxy-api/actions/workflows/interop.yml)
[![cargo-deny](https://github.com/max3584/rproxy-api/actions/workflows/deny.yml/badge.svg?branch=master)](https://github.com/max3584/rproxy-api/actions/workflows/deny.yml)
[![Release](https://img.shields.io/github/v/release/max3584/rproxy-api)](https://github.com/max3584/rproxy-api/releases/latest)
[![apt](https://img.shields.io/badge/apt-max3584.github.io%2Frproxy--api-blue)](https://max3584.github.io/rproxy-api/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen?logo=renovatebot)](https://github.com/max3584/rproxy-api/issues?q=is%3Aissue+is%3Aopen+%22Dependency+Dashboard%22)

日本語: [README.md](README.md)

An L4 forwarder that lets you add, change, delete, and query TCP/UDP forwarding while it is running.
It is controlled through an HTTP API; the management UI is [TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui).

Architecture diagrams (overall, modules, connection flow, rule states) are in [docs/en/architecture.md](docs/en/architecture.md).

## Installation

### install.sh (for VMs)

Run as root on a Linux system running systemd. On Debian / Ubuntu it installs from the apt repository; elsewhere it installs the statically linked binary from the GitHub Release (x86_64 / aarch64 / armv7), then creates the user, configuration, and unit, and starts the service.

```shell
curl -fsSL https://raw.githubusercontent.com/max3584/rproxy-api/master/scripts/install.sh | bash -s -- \
  --api-addr 127.0.0.1 --database-url 'mysql://rproxy:password@db.example:3306/rproxy'
```

- At the end it shows how to obtain `RPROXY_API_URL` and `RPROXY_API_TOKEN` to set in the UI's `.env.local`
- If the control API's default port 8080 is in use, it picks a free port from 8081-8099 (first install only)
- Logs go to `/var/log/rproxy/rproxy.<date>.log` (rproxy splits them by day and removes old ones, so logrotate is not needed). Use `--log-file -` to send them to journald
- Running it again upgrades (configuration and tokens are kept; only the options you specify are rewritten)
- The permission for `source_ip: transparent` (`CAP_NET_ADMIN`) is granted by the unit. Policy routing for return packets is installed with `--transparent-clients <CIDR> --transparent-iface <IF>` (see "Passing the source IP" below)
- `--uninstall` (`--purge` also removes configuration, tokens, and logs). For the list of options, see `install.sh --help`. Required permissions are in [docs/en/PERMISSIONS.md](docs/en/PERMISSIONS.md)

### apt (Debian / Ubuntu)

Can be installed from the apt repository (amd64 / arm64 / armhf). The same repository also has the management UI `rproxy-ui` (`sudo apt install rproxy-api rproxy-ui`. The UI requires Node.js 20.9 or later. See the [TCP-UDP-rproxy-ui README](https://github.com/max3584/TCP-UDP-rproxy-ui)).

```shell
sudo curl -fsSLo /usr/share/keyrings/rproxy-archive-keyring.gpg https://max3584.github.io/rproxy-api/rproxy-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/rproxy-archive-keyring.gpg] https://max3584.github.io/rproxy-api stable main" \
  | sudo tee /etc/apt/sources.list.d/rproxy-api.list
sudo apt update && sudo apt install rproxy-api
```

Installing does not start the service. Edit `/etc/rproxy/rproxy.env`, then start it with `sudo systemctl enable --now rproxy-api`.
An API token is generated in `/etc/rproxy/tokens` at install time (set it as the UI's `RPROXY_API_TOKEN`).
The package contents and how the repository is published are described in [docs/en/APT.md](docs/en/APT.md).

Backup and restore (what to back up, how to take the database and configuration, restore order and checks, moving to a new host, running without the database) is in [docs/en/BACKUP.md](docs/en/BACKUP.md).

The performance work log (what was adopted, what was not and why, measurement caveats) is in [docs/en/PERFORMANCE.md](docs/en/PERFORMANCE.md).

## Running

Configuration is done with environment variables. If there is a `.env` in the working directory, it is loaded (see [.env.example](.env.example) for an example).
If the same setting is also given as a command-line argument (such as `--api-port`), the argument takes precedence.

```shell
cargo build --locked --release
cp .env.example .env   # edit the values to match your environment
./target/release/rproxy-api
```

Memory is allocated with the libc's malloc by default (musl's malloc in the release binaries; it uses the least memory). To spend less CPU on L7 (HTTP/2, HTTP with many small requests), build with mimalloc: `cargo build --locked --release --features alloc-mimalloc` (built with the C compiler). In our measurements HTTP/2 and small HTTP requests were 20-30% faster and the work per CPU-second rose by 25-170%, while memory grew by about 6 MiB at idle and 15-40 MiB at peak under load.

When running under systemd, you can pass the same content with `EnvironmentFile=/etc/rproxy/rproxy.env`.

| Environment variable | Argument | Default | Description |
|---|---|---|---|
| `RPROXY_API_ADDR` | `--api-addr` | `127.0.0.1` | Listen address of the control API. Multiple addresses can be given, comma-separated |
| `RPROXY_API_PORT` | `--api-port` | `8080` | Port of the control API. `0` disables listening on TCP (`RPROXY_API_SOCKET` is then required) |
| `RPROXY_API_SOCKET` | `--api-socket` | none | Unix socket for the control API (e.g. `/run/rproxy/api.sock`). Can be used together with TCP. A token is required just as with TCP. Startup fails if the parent directory does not exist. A socket left over from a previous run is replaced |
| `RPROXY_API_SOCKET_MODE` | `--api-socket-mode` | `660` | Mode of the socket file (octal) |
| `RPROXY_API_SOCKET_GROUP` | `--api-socket-group` | none | Group of the socket file (name or ID). Use a group that the user running the UI belongs to |
| `RPROXY_TOKEN_FILE` | `--token-file` | none | Bearer token file (one token per line, or YAML with name, SHA-256, and scopes; see docs/API.md). When set, authentication is required. Reloaded on SIGHUP |
| `RPROXY_TLS_CERT` / `RPROXY_TLS_KEY` | `--tls-cert` / `--tls-key` | none | TLS certificate and private key (PEM) for the control API. Reloaded on SIGHUP |
| `RPROXY_CERT_CHECK_SECS` | `--cert-check-secs` | `60` | Interval (seconds) for checking whether certificate files (rules' `tls` and the control API) have changed. Only changed ones are reloaded (certbot and cert-manager renewals are picked up as-is). `0` disables it |
| `RPROXY_CERT_STORE` | `--cert-store` | `/var/lib/rproxy/certs` | Where certificates and keys received by `PUT /certs/{name}` are stored (v0.4.2, #240; directories 0700, files 0600; rules use `{"cert": "<name>"}`; "Certificate API" in docs/en/API.md). Cannot be under `trusted_dirs` |
| `RPROXY_CERT_EXPIRY_CHECK_SECS` | `--cert-expiry-check-secs` | `86400` | Interval (seconds) for checking certificate expiry (also checked on load). Expired server certificates are removed, and a rule whose certificates have all expired is stopped ("Certificate expiry" in docs/API.md). `0` disables it |
| `RPROXY_CERT_WARN_DAYS` | `--cert-warn-days` | `14` | How many days before expiry a certificate becomes `expiring` (warning) |
| `RPROXY_LOG_FILE` | `--log-file` | stdout | JSON Lines log. Rotated daily to `<name>.<date>.<extension>` |
| `RPROXY_LOG_KEEP` | `--log-keep` | `14` | Number of log files to keep |
| `RPROXY_LOG_LEVEL` | `--log-level` | `info` | Filter such as `debug` |
| `RPROXY_CONFIG` | `--config` | none | Configuration file (YAML / JSON with `version`, `global`, `rules`) or a directory of them. The rules start as static rules, and when the file changes the difference is applied without a restart ("Configuration file" in docs/API.md). If the content is invalid at startup, rproxy does not start |
| `RPROXY_CONFIG_CHECK_SECS` | `--config-check-secs` | `10` | Interval (seconds) for checking whether the configuration file has changed. `0` reloads only on SIGHUP |
| `RPROXY_API_RELOAD_UNIX_ONLY` | `--api-reload-unix-only` | `true` | Accept `POST /config/reload` (reload the configuration file on the spot and return the result) and the strong ACME operations (`POST /acme/...`; docs/en/ACME.md) only from the Unix socket. `false` also accepts them on the TCP control API (an `admin` / `acme:write` token is required) |
| — | `--check-config [PATH]` | — | Check the configuration file (PATH, or `RPROXY_CONFIG` if omitted) and exit. Exits 0 if there are no problems, 1 if there are errors. `--check-config-format json` for JSON (see "Checking the configuration" below) |
| `RPROXY_STATIC_RULES` | `--static-rules` | none | The 0.2 name of `RPROXY_CONFIG` (a JSON array of rules can also be read). Both cannot be specified |
| `RPROXY_DATABASE_URL` | `--database-url` | none | MariaDB/MySQL from which rules are restored at startup (`mysql://user:pass@host:port/db`) |
| `RPROXY_MAX_RANGE_PORTS` | `--max-range-ports` | `20000` | Maximum size of the port range one rule can open |
| `RPROXY_DNS_INTERVAL` | `--dns-interval` | `30` | Interval (seconds) for re-resolving target host names. If resolution fails, the previous result continues to be used |

Added in v0.4 (all of them work; settings of rules and `global` are in "v0.4 settings" of docs/en/API.md, control API hardening in "Control API hardening", live upgrades and the self-update in docs/en/UPGRADE.md):

| Environment variable | Flag | Default | Description |
|---|---|---|---|
| `RPROXY_TLS_CLIENT_CA` | `--tls-client-ca` | none | CA (PEM) verifying control API client certificates; re-read on SIGHUP (#167) |
| `RPROXY_TLS_CLIENT_AUTH` | `--tls-client-auth` | `none` | Control API client certificates: `none`, `optional` (verified when presented), `required` (connections without one fail the handshake). A token file's `client_cert` uses them for authentication (#167) |
| `RPROXY_TOKEN_WARN_DAYS` | `--token-warn-days` | `14` | Days before a token's expiry from which `token.expiring` is logged (#167) |
| `RPROXY_API_LOCKOUT_FAILURES` / `_WINDOW` / `_DURATION` | `--api-lockout-failures` / `-window` / `-duration` | `20` / `1m` / `5m` | Lock out sources that keep failing authentication (401) on the TCP control API with `429 locked_out` (on by default; `0`: never; not the Unix socket) (#167) |
| `RPROXY_API_LOCKOUT_EXEMPT` | `--api-lockout-exempt` | none | Sources never locked out (comma-separated CIDRs). Connections with a verified client certificate (mTLS) are not locked out either (v0.4) |
| `RPROXY_FILES_TRUSTED_DIRS` | `--files-trusted-dirs` | none | Directories whose files rules may name even when root owns them (absolute paths separated by `:` or `,`; Kubernetes Secret volumes). `global.files.trusted_dirs` of the settings file wins (v0.4, docs/en/PERMISSIONS.md) |
| `RPROXY_NODE_NAME` | `--node-name` | host name | Name in `rproxy_rules`; only rows with this name are restored at startup (#144, "Storing API-created rules" in docs/en/API.md) |
| `RPROXY_HANDOFF_SOCKET` / `_TIMEOUT` / `_DRAIN` | `--handoff-socket` / `-timeout` / `-drain` | `/run/rproxy/handoff.sock` / `30s` / `5m` | Live upgrade (#174): SIGUSR2 or `POST /admin/upgrade` hands the listening sockets to the binary on disk. The handoff socket, how long to wait for the new process, how long the old one waits for its connections. docs/en/UPGRADE.md |
| `RPROXY_SHUTDOWN_DELAY` / `RPROXY_SHUTDOWN_DRAIN` | `--shutdown-delay` / `--shutdown-drain` | `0s` / `0s` | How SIGTERM stops rproxy (v0.4.1). By default it stops at once (as before). During `DELAY` it keeps accepting while `/readyz` answers 503 `draining` (waiting for a load balancer in front to drop it), then it closes the listeners and waits up to `DRAIN` for current connections to end. Meanwhile the control API answers reads and refuses changes with `503 shutting_down`. A second SIGTERM stops at once. Each is at most one hour. Recommended values under systemd: "Shutting down on SIGTERM" below |
| `RPROXY_UPDATE` | `--update` | `off` | Self-update (containers, #174): `off`, `check`, `auto`; also `RPROXY_UPDATE_PIN`, `_SOURCE`, `_CACHE`, `_INTERVAL`, `_PUBKEY`, `_HEALTHY`. The image's entry point is `rproxy-api launch`. docs/en/UPGRADE.md |
| `RPROXY_WORKERS` / `RPROXY_CPU_AFFINITY` / `RPROXY_BUSY_POLL_USECS` | `--workers` / `--cpu-affinity` / `--busy-poll-usecs` | number of CPUs / `none` / `0` | Performance (#194; `global.performance` in the settings file wins). Also `RPROXY_UDP_SHARDS` (a number or `auto`) and `RPROXY_SPLICE*`. "Performance" in docs/en/API.md |
| `RPROXY_DIFF_API` / `RPROXY_DIFF_TOKEN_FILE` | `--diff` / `--diff-api` / `--diff-token-file` | `RPROXY_API_SOCKET`, else the control API / none | `--check-config --diff`: the difference from the running rproxy, asked with `POST /config/plan` (#169, "Diff before change" in docs/en/API.md) |

If `RPROXY_API_ADDR` includes a non-loopback address, a token file and a TLS certificate are required. If any of them is missing, rproxy does not start.

### When some parts cannot start

Configuration errors (wrong values, nonexistent paths, invalid file contents) prevent startup.
For other environment problems, only the unusable part is stopped and startup continues (logged with `"event":"degraded"` and `part`).

| Situation | Behavior |
|---|---|
| The log directory is not writable | Logs go to stdout (`part: log`) |
| The token file cannot be read (permissions) | The control API rejects all requests with 401. Cleared by making it readable and sending SIGHUP (`part: tokens`) |
| The control API's TLS certificate/key cannot be read (permissions), or the port is in use | Rule forwarding keeps running, and only that control API address is retried (starting after 10 seconds, doubling the interval up to a maximum of 5 minutes) (`part: api_tls` / `part: api`) |
| The control API's Unix socket cannot be created (permissions, used by another process) | Starts without the socket (`part: api_socket`) |
| The UDP port of an `http.http3` rule cannot be used (in use, permissions) | That rule runs on TCP only (HTTP/1.1, HTTP/2). The reason appears in `stats.http.http3` (`part: http3`) |
| The static rules file cannot be read (permissions) | Starts without static rules (`part: static_rules`) |
| The `global.access_log` directory is not writable | Access logs go to the main log (`part: global.access_log`) |
| Cannot connect to the DB | Starts without the DB rules (`restore.error`) |
| `rproxy_rules` cannot be read or written (missing table, permissions, DB down) | At startup only the UI's rules are restored. API rules keep running with `persisted: false` (`part: db`, #144) |
| The `global.geoip` database cannot be read (permissions), or a new version is corrupt | Until it can be read, country and ASN are unknown (handled as `unknown`); a reload keeps using the current one (`part: geoip`) |
| `global.performance` `busy_poll_usecs` cannot be set, or `cpu_affinity` names CPUs that do not exist | Runs without `SO_BUSY_POLL` / leaves those CPUs out (`part: global.performance.*`) |
| The self-update cache directory cannot be created | Forwarding keeps running; the self-update fails until it is fixed (`part: update.cache`) |
| A rule lacks the required permissions (capabilities) | Only that rule becomes `failed`, with a reason ([docs/en/PERMISSIONS.md](docs/en/PERMISSIONS.md)) |


### Shutting down on SIGTERM (v0.4.1)

By default, SIGTERM (`systemctl stop`) stops all forwarding at once (cutting current connections). With a load balancer or VIP in front, or to let current connections finish first, set `RPROXY_SHUTDOWN_DELAY` and `RPROXY_SHUTDOWN_DRAIN` in `/etc/rproxy/rproxy.env`:

1. On SIGTERM, `/readyz` answers 503 `draining` and rproxy keeps accepting as before for `DELAY` (waiting for health checks to drop it).
2. It closes the listeners (no new connections or UDP sessions) and waits up to `DRAIN` for current connections to end. HTTP requests in flight get `Connection: close` (HTTP/2 GOAWAY) and idle connections close at once. Current UDP sessions go on.
3. It cuts what is left and exits. A second SIGTERM or Ctrl-C stops at once.

Meanwhile the control API answers reads (`GET`, `/metrics`) and refuses changes with `503 shutting_down`.

| In front of rproxy | `RPROXY_SHUTDOWN_DELAY` | `RPROXY_SHUTDOWN_DRAIN` |
|---|---|---|
| Nothing (clients connect directly) | `0s` | `10s` |
| A load balancer health-checking `/readyz` | interval × failures to drop + 1 second (e.g. `5s`) | `10s`–`25s` |
| A VIP such as keepalived | time for the VIP to move (e.g. `3s`) | `10s` |

Keep systemd's `TimeoutStopSec` (default 90 seconds) above `DELAY + DRAIN + 5 seconds`. `systemctl restart` gets slower by the same amount, so update the binary with a live upgrade (SIGUSR2, [docs/en/UPGRADE.md](docs/en/UPGRADE.md)). In Kubernetes, rproxy-gateway passes `5s` / `25s`.

## Usage

For API details, see [docs/en/API.md](docs/en/API.md).

```bash
TOKEN=$(head -1 /etc/rproxy/tokens)

# Add a forwarding rule
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":8888,"remote_addr":"192.168.1.2","remote_port":8080}'

# List
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules

# Change the target (takes effect immediately for new connections)
curl -H "Authorization: Bearer $TOKEN" -X PATCH http://127.0.0.1:8080/rules/tcp/0.0.0.0/8888 \
  -d '{"remote_addr":"192.168.1.3","remote_port":8081}'

# Multiple targets (balance: round_robin / least_conn / failover; health_check checks liveness)
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":5432,
       "targets":[{"addr":"10.0.0.11","port":5432},{"addr":"10.0.0.12","port":5432},{"addr":"10.0.0.13","port":5432,"backup":true}],
       "balance":"least_conn","health_check":{"interval":"10s"}}'

# Listen on IPv4 and IPv6 with one rule (extra_listen_addrs; 0.0.0.0 and :: can also be listed together)
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"203.0.113.5","extra_listen_addrs":["2001:db8::5"],"listen_port":443,
       "remote_addr":"10.0.0.20","remote_port":443}'

# Stop (existing connections are also closed; ?drain_secs=30 waits for them to finish)
curl -H "Authorization: Bearer $TOKEN" -X DELETE http://127.0.0.1:8080/rules/tcp/0.0.0.0/8888
```

## Static rules and publishing the dashboard

If you set `RPROXY_CONFIG` to a configuration file (YAML or JSON) or a directory of them, its rules are started at startup (before restoring from the DB). When you edit the file, only the difference is applied without a restart (connections of unchanged rules are not closed; if there is an error, nothing is applied and you are notified through `GET /config` and the log). These rules cannot be changed or deleted from the API or the UI, so they are well suited for a rule that publishes the Web UI through rproxy (you cannot accidentally delete it and lock yourself out of the UI).

Example ([contrib/rproxy.example.yaml](contrib/rproxy.example.yaml)): accept only `dashboard.proxy.home`, on 443, from the internal network.

- `tls.routes` and `tls.unmatched: reject`: connections for other names or without SNI are closed before a certificate is returned (equivalent to Traefik's `Host(...)` rule)
- `allow_from`: sources outside the range are closed before TLS
- The Web UI (rproxy-ui package) listens only on `127.0.0.1:3000` by default. Set `NEXTAUTH_URL` to `https://dashboard.proxy.home`

Clients can claim any SNI or server name. Routing by name alone is not access control, so combine it with `allow_from`, mTLS (`client_auth`), and the Web UI login.

When migrating from Traefik, `rproxy-traefik-convert` ([contrib/traefik2rproxy.py](contrib/traefik2rproxy.py), included in the .deb) can convert Traefik configuration (static and dynamic configuration, Docker labels) into this configuration file. Settings that could not be converted are listed at the top of the output and on stderr ([docs/en/MIGRATING-FROM-TRAEFIK.md](docs/en/MIGRATING-FROM-TRAEFIK.md)).

An example for running under systemd is in [contrib/rproxy-api.service](contrib/rproxy-api.service) (it adds `CAP_NET_BIND_SERVICE` for ports such as 80 / 443).

### Checking the configuration

After editing the configuration file, you can check it with `rproxy-api --check-config` before applying it (equivalent to nginx's `nginx -t`). It performs the same validation as startup and reload (format, rule values, overlapping listeners, overlap with the control API, certificate/key/CA files and expiry, `global` and secret files for authentication, etc.) and exits 0 if there are no problems, 1 if there are errors. It does not open listeners or the DB, and does not touch a running rproxy.

```bash
rproxy-api --check-config                            # the file in RPROXY_CONFIG (/etc/rproxy/rproxy.env, etc.)
rproxy-api --check-config /etc/rproxy/conf.d         # specify a file or directory
rproxy-api --check-config /etc/rproxy/rproxy.yaml --check-config-format json   # for scripts
rproxy-api --check-config /etc/rproxy/rproxy.yaml && systemctl reload rproxy-api
rproxy-api --check-config /etc/rproxy/rproxy.yaml --diff --diff-token-file /etc/rproxy/admin.token   # also show the difference from the running rproxy
```

- Errors: reasons are reported per file and per rule (such as `rproxy.yaml rule #2`). It does not stop at the first one; all are reported
- Warnings: certificates close to expiry (`RPROXY_CERT_WARN_DAYS`), settings that cannot run with this version or these permissions (they become `failed` at startup), files the `rproxy` user may not be able to read (judged from owner and mode)
- JSON: `{"ok": false, "path": "...", "files": [...], "rules": 3, "errors": [{"rule": "rproxy.yaml rule #2", "message": "..."}], "warnings": [...]}`
- No name resolution is done (whether target names resolve is found out at startup)
- If no configuration file is specified, there is nothing to check, so it exits 0
- `--diff`: once the check passes, it asks the running rproxy with `POST /config/plan` and prints, one per line, the rules applying it would create, change or remove (`+` / `~` / `-`; `global` changes that need a restart as `!`). It asks `RPROXY_API_SOCKET` by default, else the control API (`--diff-api` to choose). The token needs the `admin` scope (`--diff-token-file`). "Diff before change" in docs/en/API.md

The systemd unit of the package (and install.sh) runs this check first on `systemctl reload rproxy-api`. If there are errors, the reload fails (the reason is in `journalctl -u rproxy-api`) and nothing is sent to rproxy. In that case tokens and certificates are not reloaded either, so fix the configuration file and then reload.

### Applying on the spot and getting the result

`systemctl reload` only sends a signal, so the command's result does not tell you whether the change was applied. When a script needs the result, use the control API's `POST /config/reload`. It reloads and applies the configuration, and returns the number of additions, changes, and deletions (if there is an error, nothing is changed and it returns `400` with the reason).

```bash
curl --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $ADMIN_TOKEN" -X POST http://localhost/config/reload
# {"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0,"restart_needed":[],"files":["/etc/rproxy/rproxy.yaml"],"rules":5,"warnings":[]}
```

- Only tokens with the `admin` scope can use it (the UI's `rules:read` / `rules:write` cannot)
- By default it is accepted only from the Unix socket (`RPROXY_API_SOCKET`). To use it from the TCP control API, set `RPROXY_API_RELOAD_UNIX_ONLY=false`
- `POST /config/reload?dry_run=true` applies nothing and returns what applying would change (`changes`: each rule's `diff` and whether it can change without closing connections, `change`: `in_place` / `recreate`). Rule `POST` / `PATCH` / `DELETE` and `PUT /rulesets/{name}` also take `?dry_run=true`
- It uses the same processing as file change detection and SIGHUP, and they do not run concurrently

## TLS, DTLS, STARTTLS, port ranges

For each rule you can choose how the content is handled (details in [docs/en/API.md](docs/en/API.md), configuration examples by use case in [docs/en/PROFILES.md](docs/en/PROFILES.md)).

| Setting | Behavior |
|---|---|
| `tls.mode: passthrough` (default) | Passes traffic through still encrypted |
| `tls.mode: sni` | Routes to targets by the server name in the ClientHello (no decryption; TLS for tcp, DTLS and QUIC (HTTP/3, etc.) for udp; see "Routing UDP by server name" in docs/API.md) |
| `tls.mode: terminate` | rproxy terminates TLS (tcp) / DTLS (udp). Supports certificate selection by SNI, mTLS (`client_auth`), ALPN, and re-encryption to the target (`upstream`). Only names with `passthrough: true` in `tls.routes` can be passed through without termination (even on the same port as an L7 rule) |
| `starttls: smtp / imap / pop3` | rproxy answers the plaintext exchange before STARTTLS and terminates TLS |
| `listen_port_end` | Forwards a whole port range (RTP, TURN relays, WebRTC media, FTP passive mode) |

Certificates are specified as files, or obtained by rproxy itself through ACME (Let's Encrypt and others; HTTP-01, TLS-ALPN-01 and DNS-01 (PowerDNS, RFC 2136, acme-dns, generic REST)): `{acme: <resolver>, domains: [...]}`, see [docs/en/ACME.md](docs/en/ACME.md). They can also be handed over with `PUT /certs/{name}` of the control API and used by rules as `{cert: <name>}` (v0.4.2, "Certificate API" in docs/en/API.md). When a file changes it is reloaded automatically (`RPROXY_CERT_CHECK_SECS`), so certificates renewed by certbot or cert-manager are used as-is (you can also reload immediately with SIGHUP). Certificates obtained through ACME are renewed before they expire and swapped in the same way. DNS-01 secrets can be held only by a helper process running as another user, `rproxy-api acme-helper` (`rproxy-acme-helper.service`). Combined with `source_ip: proxy_v2`, the SNI, ALPN, and client certificate CN are passed to the target in PROXY v2 TLVs.

## CrowdSec

Besides blocking based on CrowdSec decisions (the L7 `crowdsec` middleware, `crowdsec: true` on L4 rules, AppSec), you can also have the CrowdSec agent read rproxy's logs so that it detects attacks in traffic passing through rproxy and bans them. Parsers, scenarios, and acquis are in `contrib/crowdsec/` (`/usr/share/rproxy-api/crowdsec/` in the .deb); the procedure is in [docs/en/CROWDSEC.md](docs/en/CROWDSEC.md). The full round trip with real CrowdSec (detection -> ban -> blocked by rproxy) is verified in CI (the interop `crowdsec` job).

## Passing the source IP

Choose with `source_ip` per rule. What PROXY protocol is, which option to choose, and configuration examples for targets (Postfix, Dovecot, nginx, ingress-nginx, etc.) are in [docs/en/SOURCE-IP.md](docs/en/SOURCE-IP.md).

| Value | Behavior | Requirements |
|---|---|---|
| `proxy` (default) | The target sees rproxy's IP | None |
| `proxy_v1` / `proxy_v2` | Adds a PROXY protocol header at the start of the connection for TCP, and to each datagram for UDP (`proxy_v2` only) | The target supports PROXY protocol. For UDP, as with dnsdist, PowerDNS, and Unbound, the header is added to every datagram and not to responses |
| `transparent` | Connects using the client's IP (`IP_TRANSPARENT` / `IPV6_TRANSPARENT`) | Linux, `CAP_NET_ADMIN`. IPv4 and IPv6. Return packets from the target must pass through the rproxy host ([docs/en/TRANSPARENT.md](docs/en/TRANSPARENT.md)) |

To use `transparent`, give rproxy `CAP_NET_ADMIN` and set up policy routing so that the rproxy host itself receives the return packets from the target.
If installed with apt or install.sh, the unit grants `CAP_NET_ADMIN`, so no permission setup is needed. The policy routing (1 below) can be installed in one go with install.sh (it creates `rproxy-transparent-routing.service`, which sets it up on every boot).

```bash
install.sh --transparent-clients 10.0.1.0/24 --transparent-iface eth1
rproxy-transparent-routing status   # show the installed ip rule / ip route
```

When starting manually (without systemd), run as root or grant the capabilities to the binary. The list of permissions is in [docs/en/PERMISSIONS.md](docs/en/PERMISSIONS.md).

```bash
setcap cap_net_bind_service,cap_net_admin+ep ./target/release/rproxy-api
```

There are two ways to receive return packets.

1. **When the client address range is known** (verified with `scripts/test-transparent.sh`).
   Treat packets addressed to clients that arrive from the target-side interface as local.

   ```bash
   ip route add local 10.0.1.0/24 dev lo table 100   # client address range
   ip rule add iif <target-side interface> lookup 100
   ```

2. **When the client address range is not known** (verified with `scripts/test-transparent.sh` using `ROUTING=iptables` / `ROUTING=nft`).
   Mark only packets addressed to rproxy's transparent sockets and treat them as local.

   ```bash
   # iptables
   iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j MARK --set-mark 1
   iptables -t mangle -A PREROUTING -p udp -m socket --transparent -j MARK --set-mark 1
   # or nftables
   nft add table ip rproxy
   nft add chain ip rproxy prerouting '{ type filter hook prerouting priority mangle; }'
   nft add rule ip rproxy prerouting socket transparent 1 meta mark set 1

   ip rule add fwmark 1 lookup 100
   ip route add local 0.0.0.0/0 dev lo table 100
   ```

   To persist across reboots, put the nftables rules in `/etc/nftables.conf`, and set up `ip rule` / `ip route` at boot in the same way as `rproxy-transparent-routing`.

In either case, the target's default gateway must be the rproxy host (or the target must route traffic to clients via rproxy).
You can check availability with `GET /capabilities`.

`scripts/test-transparent.sh` builds a "client, rproxy, target" setup inside a user namespace and network namespaces without root privileges. It then checks, for both `proxy` and `transparent`, the source address the target sees over TCP and UDP (run it after `cargo build`).

## Logs

One JSON event per line. Common fields are `timestamp`, `level`, `event`, and `rule` (in the form `tcp/0.0.0.0:8888`). These appear with the default `RPROXY_LOG_LEVEL=info` (the last row is `debug` only). For a SIEM or CrowdSec, start with `audit`, `conn.denied`, `http.access`, `tls.error`, `target.down`, `cert.*` and `crowdsec.error`. Fields are in docs/API.md.

| `event` | Content |
|---|---|
| `rule.create` / `rule.update` / `rule.delete` / `rule.failed` | Rule creation, change, deletion, abnormal stop (with `labels`, and `ruleset` for rules of a set) |
| `ruleset.apply` / `ruleset.delete` | A rule set (v0.4, #28) was applied (`ruleset`, `generation`, `etag`, counts created / updated / deleted / unchanged / failed, `by`) / deleted |
| `config.reload` / `config.error` | Application of the configuration file (counts, `global` changes that need a restart) and the reason it could not be applied |
| `start` / `shutdown` / `fatal` | Startup (`version`, whether transparent, authentication and TLS are on, …) / exit / a configuration mistake that stops the startup |
| `shutdown.start` / `shutdown.drain` / `shutdown.now` / `shutdown.done` | SIGTERM with `RPROXY_SHUTDOWN_DELAY` / `_DRAIN`: began (`delay_secs`, `drain_secs`) / listeners closed (connections and sessions left, `connections`) / a second SIGTERM stops at once / stopped (connections and sessions cut, `cut`) |
| `degraded` | Part of rproxy was left out because of the environment and the rest runs (`part`: `api`, `api_tls`, `tokens`, `log`, `global.*`, …) |
| `api.listening` / `api.retry` / `api.stopped` | The control API started listening / cannot listen and retries / stopped |
| `audit` | Changes through the control API (token name, `client`, operation, rule, result) and refused requests: a missing or wrong token (`outcome: unauthorized`, `reason`), insufficient permissions (`outcome: forbidden`), a locked-out source (`outcome: locked_out`). How the caller authenticated (`auth`: `token`, `cert`, `token+cert`). Lines of refused requests are thinned out per sender (`suppressed`) |
| `token.expiring` / `token.expired` | A control API token is close to expiry (closer than `RPROXY_TOKEN_WARN_DAYS`) / has expired (`token`, `expires`, `days_left`). At startup, on SIGHUP and daily, once per change of state |
| `api.lockout` / `api.unlock` | A source that kept failing authentication (`client`; IPv6 by /64) was locked out (`failures`, `until`) / unlocked |
| `reload.tokens` / `reload.tls` / `reload.rules_tls` / `reload.crowdsec` | SIGHUP re-read the tokens, the control API's certificate, the rules' certificates, the CrowdSec key (the current ones stay if a file cannot be read) |
| `geoip.reload` | A `global.geoip` database was read or read again (`db`: `country` / `asn`, `path`, `build_epoch`). One that cannot be read logs `degraded` (`part: geoip`) and the current one stays |
| `static.loaded` / `rule.listen` / `rule.duplicate` | Static rules were loaded / a rule's listen addresses changed / a rule with the same key was skipped |
| `conn.open` / `conn.close` | Start and end of a connection (session for UDP). `client`, `target`, `rx_bytes`, `tx_bytes`, `duration_ms`, `reason`. When TLS is terminated, `tls_version`, `tls_cipher`, etc. HTTP/3 QUIC connections have `transport: quic`. With `global.geoip.log_country`, `country` and `asn` |
| `conn.denied` | A refused connection (for UDP, datagram): `reason` is `allow_from`, `geoip` (`country`, `asn`), `crowdsec` or `unmatched`; `client` (`IP:port`), `sni`. For UDP thinned out per source (`suppressed`: lines left out before it). HTTP/3 has `transport: quic` |
| `conn.limited` | A connection (for UDP, datagram) refused by the rule's `limits` (#165): `reason` is `max_connections`, `source_connections`, `new_connections` or `packets`; `transport` is `tcp` or `udp`; `client`. Thinned out per source (`suppressed`) |
| `conn.error` / `tls.error` / `accept.error` / `recv.error` | A failed connection (the target cannot be reached, the ClientHello cannot be read, …) / a failed TLS or DTLS handshake / accepting or receiving failed |
| `http3.listening` / `http3.error` | An `http.http3` rule started accepting HTTP/3 over UDP / the QUIC certificates cannot be rebuilt |
| `http.error` | An `http` rule could not connect to the target, timed out (route `timeouts` included) or retries on a `status` of `retry` (`route`, `service`, `backend`, `status`, and `attempt` for `retry`). Requests of `http` rules go to `http.access` (access log; a separate file if `global.access_log` is set; fields are in docs/API.md) |
| `http.access` | A request of an `http` rule (access log), with the middleware that refused it (`refused_by`, `middleware`) and `basic_auth`'s user (`user`) or why it refused (`auth_error`), and on rules with `tls.client_auth` the client certificate's `client_cn` and `client_verify` (`SUCCESS` / `FAILED` / `NONE`). `country` and `asn` with `global.geoip.log_country` (and when the `geoip` middleware refused) |
| `oidc.login` / `oidc.refresh` / `oidc.error` / `oidc.cookie` | Sign-in through the `oidc` middleware (`user`), refresh failure, failure communicating with the provider, a session too large to keep the refresh token |
| `reload.secret` | A secret file of an authentication middleware (htpasswd, OIDC secret) was reloaded, or could not be reloaded and the current content continues to be used |
| `http.health` / `http.breaker` | A target became down / up in a health check (`service`, `server`, `up`); a `circuit_breaker` opened / closed (`middleware`, `state`) |
| `http.mirror` | What a copy of the `mirror` middleware came to (debug; `middleware`, `service`, `backend`, `status`, `error` on failure). It does not affect the client's response |
| `crowdsec.sync` / `crowdsec.error` | Decisions were fetched from the CrowdSec LAPI (`added`, `deleted`, `decisions`) / could not be fetched or AppSec could not be queried (the previous decisions continue to be used) |
| `conn.retarget` | The target of a UDP session was switched (name resolution changed, or the target went down: `reason: target down`) |
| `target.down` / `target.up` | In a rule with multiple targets (`targets`) or `health_check`, a target went down / up (`reason: health_check` / `outlier`; `outlier` is an ejection by failures in real traffic and its end: `cause`, `ejection_secs`). Also for the `outlier_detection` of `http` services (`service`, `server`) |
| `dns.change` / `dns.stale` | The name resolution result of a target changed / resolution failed (the previous result continues to be used) |
| `restore.*` | Restoration from the DB at startup (`restore.paused` is the number of rules not created because they are paused in the UI; `restore.conflict`: `rproxy_rules` and the UI's `forward_rules` have the same key and the UI's row was used, #144) |
| `rule.persist` | An API rule of a `persist: true` token (`origin: "api"`) was written to or deleted from `rproxy_rules` (`action: save` / `delete`, `token`; #144) |
| `acme.order` / `acme.issue` / `acme.renew` / `acme.revoke` / `acme.ari` / `acme.error` / `acme.rate_limited` | An ACME order started / a certificate was obtained / renewed / an order failed (`retry_at`) / the issuance limit held an order back (docs/en/ACME.md) |
| `acme.account` / `acme.dns` / `acme.challenge` / `acme.answer` / `acme.listening` | An ACME account was created or deactivated / a DNS-01 TXT record was written or removed / a challenge was set up or answered / `http01_listen` started listening. No secret is logged |
| `acme.helper` | The ACME helper (`rproxy-api acme-helper`) started listening / refused a peer it does not allow / failed (`outcome`: `listening` / `refused` / `error`) |
| `cert.expiring` / `cert.expired` / `cert.ok` | A certificate is close to expiry (within `RPROXY_CERT_WARN_DAYS`) / expired / was renewed (`file`, `not_after`, `days_left`). Emitted only once when the state changes |
| `cert.check` | Periodic expiry check (`rules_updated`: number of rules from which expired certificates were removed or that were stopped) |
| `performance` | The `global.performance` values at startup and where each came from (`sources`). `SO_BUSY_POLL` that cannot be set and CPUs that do not exist log `degraded` (`part: global.performance.busy_poll_usecs` / `global.performance.cpu_affinity`) |
| `handoff.start` / `handoff.sent` / `handoff.ready` / `handoff.drain` / `handoff.done` / `handoff.failed` / `handoff.refused` / `handoff.busy` / `handoff.received` / `handoff.sockets` / `handoff.counters` / `handoff.rule` / `handoff.ruleset` | Live upgrade: started / sockets and state sent / the new process (`pid`) is ready / the old process waits for its connections / done / failed (the old process keeps running) / refused for another minor or because another process connected / one is already running / what the new process received / inherited sockets taken, or closed unused / the old process's last counts added (warn if they did not arrive) / an inherited API rule or rule set could not be read or applied (warn) (docs/en/UPGRADE.md) |
| `update.check` / `update.available` / `update.fetched` / `update.restart_needed` / `update.healthy` / `update.rollback` / `update.interrupted` / `update.clear_bad` / `update.error` / `launch.start` / `launch.mainpid` / `launch.notify_refused` / `launch.exit` | Self-update: looked, no new patch / a new patch exists / verified and cached / the patch cannot be swapped in live and runs after the next restart / became the good version / rolled back as bad / a version on trial stopped with the launcher (bad after 3) / bad marks taken off / failed (a signature that does not match, ...) / the launcher (`rproxy-api launch`) started the server / the main process changed with a handoff / a `MAINPID=` from a process that is not ours was refused / the server exited (`code`). A cache that cannot be created logs `degraded` (`part: update.cache`) |
| (`debug` only) `udp.drop` / `udp.send_error` / `udp.recv_error` / `tcp.nodelay` / `target.eject_skipped` | A UDP datagram was dropped (counted in `stats.dropped`) / sending or receiving failed / TCP_NODELAY could not be set / a failing target was not ejected because of `max_ejected_percent` |

## Development

```bash
cargo test     # unit tests (src/) and integration tests that use real sockets (tests/; listed in docs/en/TESTING.md)
cargo clippy --all-targets
```

## Origin and license

rproxy-api started from glacierx's [rproxy](https://github.com/glacierx/rproxy) (MIT License).
It is now an independent project whose code has been entirely rewritten, including the control API, TLS, DTLS, STARTTLS, and source IP passing, and it is developed separately from the original project.
The design of the bidirectional TCP forwarding loop and the per-client UDP sessions comes from the original project (noted at the top of `src/l4/tcp.rs` and `src/l4/udp.rs`).

MIT License. See [LICENSE](LICENSE), which includes the original project's copyright notice.
