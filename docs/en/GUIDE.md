日本語: [GUIDE.md](../GUIDE.md)

# Configuration and operations guide

This guide is for people new to rproxy-api. It is organised by task. It walks through writing the settings file (`RPROXY_CONFIG`, YAML) and using the control API, step by step, with examples. The second half covers day-to-day operations: upgrades, backups, monitoring and so on.

- [API.md](API.md) is the reference for what each field means and exactly how it behaves. Where a topic is long, this guide links to the API.md section.
- The examples can be pasted as they are. Change the addresses, names and paths to fit your setup.
- The example addresses are documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) and private ranges (`10.0.0.0/8` and so on).

## Contents

Configuration

1. [Install and start](#1-install-and-start)
2. [The first rule](#2-the-first-rule)
3. [L4 forwarding (UDP, port ranges, several targets)](#3-l4-forwarding-udp-port-ranges-several-targets)
4. [TLS](#4-tls)
5. [L7 (`http` rules)](#5-l7-http-rules)
6. [Source IP](#6-source-ip)
7. [Security (tokens, CrowdSec, GeoIP, files)](#7-security-tokens-crowdsec-geoip-files)
8. [`global` settings](#8-global-settings)
9. [Changing things while running](#9-changing-things-while-running)
10. [Persistence, rule sets and dry run](#10-persistence-rule-sets-and-dry-run)
11. [Observing (logs, `/metrics`, stats)](#11-observing-logs-metrics-stats)

Operations

12. [Upgrades and going back](#12-upgrades-and-going-back)
13. [Backup and restore](#13-backup-and-restore)
14. [Monitoring and alerts](#14-monitoring-and-alerts)
15. [Handling logs](#15-handling-logs)
16. [Capacity limits](#16-capacity-limits)
17. [Recipes](#17-recipes)
18. [Troubleshooting](#18-troubleshooting)

## 1. Install and start

### apt (Debian / Ubuntu)

```shell
sudo curl -fsSLo /usr/share/keyrings/rproxy-archive-keyring.gpg https://max3584.github.io/rproxy-api/rproxy-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/rproxy-archive-keyring.gpg] https://max3584.github.io/rproxy-api stable main" \
  | sudo tee /etc/apt/sources.list.d/rproxy-api.list
sudo apt update && sudo apt install rproxy-api
```

Installing does not start it. Edit `/etc/rproxy/rproxy.env` first, then start it.

```shell
sudoedit /etc/rproxy/rproxy.env
sudo systemctl enable --now rproxy-api
```

### install.sh (Linux with systemd, for VMs)

It installs from apt on Debian / Ubuntu and the release binary elsewhere, creates the user, the settings and the unit, and starts the service.

```shell
curl -fsSL https://raw.githubusercontent.com/max3584/rproxy-api/master/scripts/install.sh | sudo bash -s -- --api-addr 127.0.0.1
```

Running it again upgrades (the settings and tokens are kept). Options: `install.sh --help`.

### Main environment variables

Settings come from environment variables (`/etc/rproxy/rproxy.env`). Only the common ones are listed here. Every item is in the table under [Running in the README](../../README.en.md#running).

| Variable | Default | What it sets |
|---|---|---|
| `RPROXY_API_ADDR` / `RPROXY_API_PORT` | `127.0.0.1` / `8080` | Where the control API listens. Outside loopback, tokens and TLS are required |
| `RPROXY_API_SOCKET` | none | The control API's Unix socket (e.g. `/run/rproxy/api.sock`). Strong operations such as `POST /config/reload` are accepted only here by default |
| `RPROXY_TOKEN_FILE` | none (the package uses `/etc/rproxy/tokens`) | Control API tokens. Setting it makes authentication required |
| `RPROXY_CONFIG` | none | The settings file (YAML / JSON) or its directory. Its rules are static rules |
| `RPROXY_DATABASE_URL` | none | MariaDB to restore the UI's rules and stored API rules from |
| `RPROXY_LOG_FILE` / `RPROXY_LOG_LEVEL` | stdout / `info` | Logs (JSON Lines, split by day) |
| `RPROXY_NODE_NAME` | host name | The node's name in the DB. Give each node a different name |

### Check that it runs

```shell
systemctl status rproxy-api
TOKEN=$(head -1 /etc/rproxy/tokens)          # the one-line token the package created (all permissions)
curl -s http://127.0.0.1:8080/healthz          # ok (no authentication)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/capabilities | jq '{version, features: (.features | keys | length)}'
```

If it does not start, read `journalctl -u rproxy-api`. A configuration mistake (a value, a path, a file's contents) stops the start. An environment problem (permissions, a port in use, the DB) stops only the part that cannot work; the rest starts, and the log has `"event":"degraded"` with a `part` ([When some parts cannot start in the README](../../README.en.md#when-some-parts-cannot-start)).

## 2. The first rule

As an example, forward TCP on `0.0.0.0:8888` to `192.168.1.2:8080`.

### In the settings file

```yaml
# /etc/rproxy/rproxy.yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8888
    remote_addr: 192.168.1.2
    remote_port: 8080
```

Add `RPROXY_CONFIG=/etc/rproxy/rproxy.yaml` to `/etc/rproxy/rproxy.env` (adding `RPROXY_CONFIG` is the only time a restart is needed).

```shell
sudo -u rproxy-api rproxy-api --check-config /etc/rproxy/rproxy.yaml   # 0: fine, 1: a mistake
sudo systemctl restart rproxy-api
```

`--check-config` runs the same checks as start-up and reload, and opens no listeners and no DB. Run it every time you edit the file (it is like `nginx -t`). After the first time, no restart is needed: rproxy checks the file every `RPROXY_CONFIG_CHECK_SECS` (default 10 seconds) and applies only the difference. To apply at once, use `systemctl reload rproxy-api` (it runs `--check-config` first and sends nothing if there is a mistake).

How to check:

```shell
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules \
  | jq '.[] | {protocol, listen_addr, listen_port, origin, state, error}'
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/config | jq '{files, rules, last_reload, error}'
```

`state: running` means it works. With `failed`, the reason is in `error` and `conditions`.

- YAML is read as 1.2. `yes` and `on` are strings. A number such as `010` stays a number; quote it to make it a string.
- With a directory, the `*.yaml` / `*.yml` / `*.json` files in it are read in name order as one settings file. Only one file may have `global` ([Config file in API.md](API.md#config-file-fixed-rules)).

### Through the control API

Create the same rule through the API. The body has the same shape as one item of `rules` in the settings file.

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":8889,"remote_addr":"192.168.1.2","remote_port":8080}'

# change the target (new connections use it)
curl -s -H "Authorization: Bearer $TOKEN" -X PATCH http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889 \
  -d '{"remote_addr":"192.168.1.3","remote_port":8080}'

# delete (current connections are cut; ?drain_secs=30 waits up to 30 seconds for them to end)
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889
```

A rule's key is `(protocol, listen_addr, listen_port)`. URL-encode an IPv6 address in the path (`::` is `%3A%3A`).

### Settings file versus API

| | Settings file | API |
|---|---|---|
| `origin` in the view | `static` | `dynamic` (`api` with a `persist: true` token) |
| How to change | Edit the file (applied automatically) | `PATCH` / `DELETE`. A static rule gives `409 static` |
| After a restart | Rebuilt from the file | `dynamic` is gone. UI rules come back from the DB, `api` rules from `rproxy_rules` |
| Good for | Rules that must not disappear (such as the one publishing the UI) | Rules the UI, CI or a controller changes |

- A key belongs to one of them. Creating a file's key through the API gives `409 static`; writing an API rule's key into the file makes the file's rule `rule.failed`.
- To **add** http routes or `tls.routes` names to a static rule's listener from the API, use an overlay (v0.4.23, #397). The file's rule itself does not change.

  ```shell
  curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H 'If-None-Match: *' \
    http://127.0.0.1:8080/rules/tcp/0.0.0.0/443/overlay \
    -d '{"http":{"routes":[{"name":"wiki","match":"Host(`wiki.example.com`)","service":"wiki"}],
         "services":{"wiki":{"servers":[{"url":"http://10.0.0.5:8080"}]}}}}'
  ```

  An overlay's routes see only the requests no file route matches. A name that clashes with the file gives `409 overlay_conflict` ([Overlays in API.md](API.md#overlays-on-a-static-rules-listener-v0423-397-featuresstatic_overlay)).

## 3. L4 forwarding (UDP, port ranges, several targets)

The examples from here on go under `rules:` in the settings file. For the API, send the same shape as JSON to `POST /rules`.

### UDP

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 53
    remote_addr: 10.0.0.53
    remote_port: 53
    udp_idle_secs: 30        # seconds before a quiet session is dropped (default 30)
```

- Even when listening on `0.0.0.0` / `::`, replies come from the address the client sent to.
- A session ends after 5 seconds until it has both a reply from the target and a second datagram from the client (a guard against spoofed sources; [Against spoofed UDP sources in API.md](API.md#against-spoofed-udp-sources-v0420-354)). A client that sends once and then only receives should keep sending something.
- The default cap of sessions per rule is `RPROXY_UDP_MAX_SESSIONS` (16384). For many clients, set the rule's `limits.max_connections` or raise it.

### Port ranges

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 10000
    listen_port_end: 10100     # 10000-10100
    remote_addr: 10.0.0.40
    remote_port: 20000         # go to 20000-20100, shifted by the same amount
```

One rule may have up to `RPROXY_MAX_RANGE_PORTS` (default 20000) ports. Each port uses one socket (chapter 16).

### Several listen addresses

```yaml
  - protocol: tcp
    listen_addr: 203.0.113.5
    extra_listen_addrs: ['2001:db8::5']   # IPv4 and IPv6 in one rule
    listen_port: 443
    remote_addr: 10.0.0.20
    remote_port: 443
```

Up to 16. The key stays `listen_addr`, and the stats are combined.

### Several targets (balancing and failover)

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 5432
    targets:
      - {addr: 10.0.0.11, port: 5432, weight: 2, max_connections: 200}
      - {addr: 10.0.0.12, port: 5432, max_connections: 200}
      - {addr: db-backup.internal, port: 5432, backup: true}
    balance: least_conn        # round_robin (default) / least_conn / failover
    health_check: {interval: 10s, timeout: 3s}
    connect_timeout: 3s
```

- `failover` uses only the first live target, top down. `backup: true` is used only when all others are down.
- `health_check` checks with a TCP connection (`port` is required on UDP rules). Even without it, a target that cannot be reached is skipped for 10 seconds (tunable with `outlier_detection`).
- `max_connections` (per target, v0.4.19): a full target is skipped; when all are full, the connection is refused (`conn.limited` with `reason: target_full`).
- `connect_timeout`: when omitted, 5 seconds if there are other targets, otherwise 30 seconds. `tcp` rules only.

How to check: `stats.targets` (per target `up` and `connections`) in `GET /rules/tcp/0.0.0.0/5432`, and `rproxy_target_up` in `/metrics`.

### Connection limits for the whole rule

```yaml
    limits:
      max_connections: 2000          # the whole rule (UDP: sessions)
      per_source:
        max_connections: 50          # one source (by default per IPv4 /32 and IPv6 /64)
        new_connections: {average: 10, period: 1s, burst: 20}
```

Refusals are counted in `stats.limited`, in `rproxy_rule_limited_total{reason}` in `/metrics`, and logged as `conn.limited` ([L4 limits and bandwidth in API.md](API.md#how-l4-limits-and-bandwidth-165-166-behave)). Bandwidth can be limited with `bandwidth` (`upload`, `download`, e.g. `"10Mbps"`).

### Connections that stay quiet for long

`tcp` rules cut a connection where nothing flows either way for `idle_timeout` (default `1h`). Lengthen it for long-quiet connections such as DB pools (`0s`: no limit).

```yaml
    idle_timeout: 8h
    half_close_timeout: 1m           # after one side has closed (default 1m)
```

## 4. TLS

A rule's `tls.mode` decides how the content is handled. [PROFILES.md](PROFILES.md) has examples by use.

| `tls.mode` | Behaviour | Certificate |
|---|---|---|
| `passthrough` (default) | Passes it on encrypted | Target |
| `sni` | Picks the target by the name in the ClientHello (no decryption; TLS on tcp, DTLS and QUIC on udp) | Target |
| `terminate` | rproxy terminates TLS (tcp) / DTLS (udp) | rproxy |

### Routing by name (`sni`)

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 10.0.0.10           # when no name matches
    remote_port: 443
    tls:
      mode: sni
      routes:
        - {server_name: git.example.com, remote_addr: 10.0.0.11, remote_port: 443}
        - {server_names: ['*.apps.example.com', 'apps.example.com'], remote_addr: 10.0.0.12, remote_port: 8443}
      unmatched: reject              # cut unmatched names and connections without SNI
```

Names are exact, `*.` (one level) or `**.` (any depth). Routing by name is not access control (a client can claim any name). Combine it with `allow_from` or mTLS.

### Terminating (`terminate`)

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8443
    remote_addr: 10.0.0.30
    remote_port: 8080                # plain text to the target
    allow_from: [10.0.0.0/8]         # outside the range, cut before TLS
    tls:
      mode: terminate
      certificates:
        - cert_file: /etc/rproxy/tls/site.pem
          chain_file: /etc/rproxy/tls/intermediates.pem
          key_file: /etc/rproxy/tls/site.key
      options: {min_version: '1.2'}
```

- Certificates and keys must belong to the `rproxy-api` user, keys 600 or 640 ([PERMISSIONS.md](PERMISSIONS.md)). If certbot or similar writes root-owned files, copy them in a deploy hook.
- When a file changes it is re-read within `RPROXY_CERT_CHECK_SECS` (default 60 seconds), without cutting connections.
- A certificate close to expiry shows as the `cert.expiring` log and `rproxy_cert_expiry_seconds` in `/metrics`.

### TLS to the target too (re-encryption, mTLS)

```yaml
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/site.pem, key_file: /etc/rproxy/tls/site.key}
      upstream:
        tls: true
        server_name: backend.internal
        ca_file: /etc/rproxy/tls/internal-ca.pem
        cert_file: /etc/rproxy/tls/client.pem        # client certificate towards the target (mTLS)
        key_file: /etc/rproxy/tls/client.key
```

To ask clients for a certificate, use `client_auth`: `{mode: required, ca_file: /etc/rproxy/tls/clients-ca.pem}`.

### DTLS

`protocol: udp` with `mode: terminate` terminates DTLS. The key must be PKCS#8 (`-----BEGIN PRIVATE KEY-----`). WebRTC media cannot be terminated; pass it through.

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 5684
    remote_addr: 10.0.0.60
    remote_port: 5683
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/coap.pem, key_file: /etc/rproxy/tls/coap.key}
```

### STARTTLS (mail)

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 587
    remote_addr: 10.0.0.20
    remote_port: 587
    source_ip: proxy_v2              # pass the source IP and TLS details to the target
    starttls: smtp                   # smtp / imap / pop3
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/mail.pem, key_file: /etc/rproxy/tls/mail.key}
```

On port 25 between MTAs, some peers do not use TLS, so set `starttls_required: false`.

### Automatic certificates (ACME)

Write an account and a resolver in `global.acme`, and make the rule's certificate `{acme: <resolver>, domains: [...]}`.

```yaml
version: 1
global:
  acme:
    accounts:
      letsencrypt:
        contact: ['mailto:admin@example.com']
        allowed_names: [example.com, '*.example.com']    # required: the names it may get
    resolvers:
      le-alpn: {account: letsencrypt, challenge: tls-alpn-01}
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 10.0.0.30
    remote_port: 8080
    tls:
      mode: terminate
      certificates:
        - acme: le-alpn
          domains: [example.com, www.example.com]
```

- Until the certificate arrives, a self-signed placeholder is served. When `state` under `acme` in the rule's view is `valid`, it has arrived. See `GET /acme` for the status.
- `tls-alpn-01` is answered by a `terminate` rule on 443, `http-01` by an `http` rule on 80 (or `http01_listen`). Wildcards need `dns-01`.
- For trying things out, Let's Encrypt staging (`directory: https://acme-staging-v02.api.letsencrypt.org/directory`) avoids the rate limits.
- Creating a rule that uses an ACME certificate through the API needs the `acme:write` scope. DNS-01 providers, the helper process and changes while running are in [ACME.md](ACME.md).

## 5. L7 (`http` rules)

A `tcp` rule with `http` parses HTTP and routes requests. TLS is `terminate` (HTTPS) or none (plain HTTP). Do not write `remote_addr` / `remote_port` (the targets are `http.services`).

### Routes, services and middlewares

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/site.pem, key_file: /etc/rproxy/tls/site.key}
    http:
      http3: true                    # HTTP/3 on UDP on the same port too
      pre_routing: [secure-headers]  # applied to every request before a route is chosen
      routes:
        - name: app
          match: Host(`app.example.com`)
          service: app
          middlewares: [compress, cache]
        - name: admin
          match: Host(`app.example.com`) && PathPrefix(`/admin`)
          service: app
          middlewares: [office-only, login]
        - name: api
          match: Host(`api.example.com`)
          service: api
          middlewares: [per-ip]
      default: {status: 404}
      services:
        app:
          servers:
            - {url: 'http://10.0.0.10:3000'}
            - {url: 'http://10.0.0.11:3000'}
          health_check: {path: /healthz, interval: 10s}
          timeouts: {connect: 5s, response: 60s}
        api:
          servers:
            - {url: 'http://10.0.0.12:8080', max_connections: 500}
      middlewares:
        secure-headers:
          headers:
            hsts: {max_age: 31536000, include_subdomains: true}
            frame_deny: true
            content_type_nosniff: true
        compress: {compress: {}}
        cache: {cache: {ttl: 60s}}
        office-only: {ip_allow: {source_range: [10.0.0.0/8, '2001:db8:10::/48']}}
        login: {basic_auth: {users_file: /etc/rproxy/auth/htpasswd, realm: admin}}
        per-ip: {rate_limit: {average: 50, period: 1s, burst: 100}}
```

- Routes are tried by `priority`, highest first (when omitted, the length of `match`). Above, the longer `admin` comes before `app`. When none matches, `default` answers.
- `match` uses Traefik's syntax: `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`, `Method`, `Header`, `Query`, `ClientIP` and others, combined with `&&`, `||` and `!`.
- Middlewares act on the request in the order written, and on the response in reverse.
- To send to one URL without a service, write `to: 'http://10.0.0.10:3000'` on the route.
- The path and Host are normalised before matching (`/%61dmin` or `/x/../admin` do not slip past `PathPrefix(`/admin`)`).

### Common middlewares

```yaml
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
        old-docs: {redirect_regex: {regex: '^https://old\.example\.com/(.*)', replacement: 'https://docs.example.com/$1'}}
        sso:
          forward_auth:
            address: 'http://127.0.0.1:9091/api/verify'
            response_headers: [Remote-User, Remote-Groups]
        no-index: {headers: {response: {set: {X-Robots-Tag: noindex}}}}
        api-cache: {cache: {ttl: 30s, stale_on_error: 5m, vary: [Accept-Language]}}
        maintenance: {respond: {status: 503, body: 'maintenance'}}
```

| Kind | What it does |
|---|---|
| `basic_auth` | Lets through only the users in an htpasswd file (bcrypt from `htpasswd -B` is recommended). `user_header` passes the name on |
| `forward_auth` | Asks an auth server (Authelia, oauth2-proxy and so on) and lets 2xx through |
| `oidc` | OpenID Connect sign-in (Keycloak and so on, without oauth2-proxy) |
| `headers` | `set`, `add`, `remove` request and response headers; `hsts`, `frame_deny`, `csp` and more |
| `redirect_scheme` / `redirect_regex` | Redirect to HTTPS or to another URL |
| `rate_limit` / `in_flight` | Rate and concurrency per source. Over it: 429 |
| `cache` | Keeps GET responses in memory for `ttl`. Behind an auth middleware it needs `share_after_auth` |
| `compress` | Compresses with br, zstd or gzip |
| `ip_allow` | 403 outside the source ranges |

The other kinds (`crowdsec`, `geoip`, `cors`, `mirror`, `retry`, `circuit_breaker`, `errors`, path rewrites and so on) and the details are in [HTTP forwarding semantics in API.md](API.md#http-forwarding-semantics) and "L7 and TLS for the Gateway API".

### From port 80 to HTTPS

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - {name: to-https, match: 'PathPrefix(`/`)', middlewares: [to-https]}
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
```

ACME `http-01` answers come before the routes, so this rule works together with it.

### HTTP/3

`http.http3: true` also accepts HTTP/3 on UDP on the same address and port (with `terminate` only). Open the UDP port in the firewall too. If it cannot listen, the rule runs on TCP only and `stats.http.http3` in `GET /rules` says why.

### Time limits (`global.http.timeouts`)

Limits on client connections to `http` rules live in `global`, not in the rule. They apply to new connections.

```yaml
global:
  http:
    timeouts:
      idle: 5m                 # a connection with no request in progress (default 180s)
      request_body_idle: 2m    # silence while sending a body (default 60s)
      upgraded_idle: 4h        # nothing flowing on WebSocket and similar (default 1h)
```

The items and defaults are under `global.http.timeouts` in [HTTP forwarding semantics in API.md](API.md#http-forwarding-semantics). Time limits towards targets are the service's `timeouts` (`connect`, `response`).

## 6. Source IP

Targets normally see rproxy's IP. To pass on the client's IP, choose the rule's `source_ip`. How to choose and how to set up targets: [SOURCE-IP.md](SOURCE-IP.md).

| `source_ip` | Behaviour | Target needs |
|---|---|---|
| `proxy` (default) | Does not pass it | Nothing |
| `proxy_v2` / `proxy_v1` | Puts a PROXY protocol header at the start of the connection (UDP: v2 only, on each datagram) | To accept PROXY protocol |
| `transparent` | Connects using the client's IP | A return route ([TRANSPARENT.md](TRANSPARENT.md)) |

- On `http` rules the IP goes in `X-Forwarded-For` and `X-Real-IP` (`source_ip` is `proxy` or `transparent`).
- `source_ip` cannot change after creation (recreate the rule).

### Accepting PROXY protocol from a front proxy

When a load balancer in front of rproxy adds PROXY protocol, read it with the rule's `proxy_protocol`.

```yaml
    proxy_protocol:
      from: [10.2.0.0/16]          # only the front proxies whose header is trusted (required, no /0)
      required: true               # refuse connections from `from` without a header (default)
```

From then on, `allow_from`, `limits`, the logs and `source_ip` use the client in the header. The front proxy's address is in the log as `proxy_peer`.

### Front proxies whose `X-Forwarded-For` is trusted

With a CDN or load balancer in front of `http` rules, write its range in `global.trusted_proxies`. Connections from there have their `X-Forwarded-For` trusted, and `ClientIP`, `ip_allow`, `rate_limit` and the logs use the real client.

```yaml
global:
  trusted_proxies: [10.2.0.0/16]
```

## 7. Security (tokens, CrowdSec, GeoIP, files)

### Tokens

The token file (`RPROXY_TOKEN_FILE`) has two forms. A token written one per line has all permissions (`admin`). In YAML, name, SHA-256 and scopes are separate, and the token itself is not in the file.

```shell
TOKEN=$(openssl rand -hex 32)
printf %s "$TOKEN" | sha256sum      # write this value as sha256
```

```yaml
# /etc/rproxy/tokens (root:rproxy 640)
tokens:
  - name: ui
    sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    scopes: [admin]                     # make the UI's token admin (v0.4.23)
  - name: ci-deploy
    sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    scopes: [rules:read, rules:write]
    allow_listen_ports: 20000-29999     # listen ports it may create, change or delete
    max_rules: 200
    expires: 2027-03-31
  - name: k8s-controller
    sha256: fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
    scopes: [rules:read, rules:write]
    allow_rulesets: [k8s/]              # name prefixes of the rule sets it may PUT / DELETE
  - name: monitoring
    sha256: baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096
    scopes: [metrics:read]
```

- Scopes: `rules:read`, `rules:write`, `metrics:read`, `acme:write`, `certs:read`, `certs:write`, `admin`. A missing scope gives `403 forbidden`.
- **Only the owner changes or deletes** (v0.4.23, #401): a token that is not `admin` may change or delete only the rules, overlays and rule sets it created itself. Others give `403 not_owner`. The owner is the token's **name** (replacing `sha256` under the same name keeps ownership).
- `allow_restored: true`: may also change rules whose creating token is unknown (UI rules restored from the DB and so on). Put it only on the UI's token, when that token is not `admin`. Remove it before going back to v0.4.22 or older (older versions then refuse the whole file).
- After a change, `systemctl reload rproxy-api`. Without SIGHUP the file is re-read within `RPROXY_TOKENS_CHECK_SECS` (default 10 seconds). To replace a token: add the new one, switch the clients, remove the old one.
- A source with 20 authentication failures within a minute is blocked for 5 minutes (`429 locked_out`; the Unix socket is exempt).
- Opening the control API outside loopback requires tokens and TLS (`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`). A UI on the same host is safest over the Unix socket. Client certificates (mTLS): [Control API hardening in API.md](API.md#control-api-hardening-v04-167).

### CrowdSec

Blocks IPs in the LAPI's decisions (bans). L7 uses the `crowdsec` middleware, L4 the rule's `crowdsec: true`.

```shell
sudo cscli bouncers add rproxy -o raw | sudo tee /etc/rproxy/crowdsec.key >/dev/null
sudo chown rproxy-api:rproxy /etc/rproxy/crowdsec.key && sudo chmod 640 /etc/rproxy/crowdsec.key
```

```yaml
global:
  crowdsec:
    lapi_url: 'http://127.0.0.1:8081'     # not the control API's port
    api_key_file: /etc/rproxy/crowdsec.key
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 25
    remote_addr: 10.0.0.30
    remote_port: 25
    crowdsec: true                        # banned IPs are cut before TLS
```

`crowdsec` in `GET /config` (`connected`, `decisions`) shows whether the LAPI is reachable. The other direction, CrowdSec reading rproxy's logs to find attacks, is in [CROWDSEC.md](CROWDSEC.md).

### GeoIP

Decide by country or ASN. Point `global.geoip` at an mmdb such as GeoLite2.

```yaml
global:
  geoip:
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 22
    remote_addr: 10.0.0.70
    remote_port: 22
    geoip: {allow_countries: [JP], unknown: deny}
```

The order of checks is `allow_from`, then `geoip`, then `crowdsec` ([GeoIP in API.md](API.md#geoip-168)).

### Files that rules point to

- Certificates, keys and secret files must belong to the `rproxy-api` user and must not be writable by group or others (`global.files.owner_check: strict`, the default). Put Kubernetes Secret volumes in `global.files.trusted_dirs`.
- API rules may not point into the certificate store, the ACME storage, rproxy's secrets (the token file and so on), `/proc` and similar (`403 protected_file`).
- A token that is not `admin` may not point to keys or secret files used by another owner's rules (`409 file_in_use`).
- The API answer does not give the reason; the `config.file` log does ([PERMISSIONS.md](PERMISSIONS.md)).

## 8. `global` settings

`global` is process-wide. Write it in the settings file's `global`, or, for items not in the file, change them with `PATCH /config/global` (`admin`). **Items in the file (and environment) win** (the API gets `409 static`).

| Item | How it changes | Source |
|---|---|---|
| `trusted_proxies`, `access_log`, `crowdsec`, `geoip`, `acme` | While running (Unix socket only) | File / API |
| `http.timeouts` | While running (new connections) | File / API |
| `udp_max_sessions`, `cache_max_memory` | While running | Environment / API |
| `performance`, `files` | Needs a restart | File / environment |

```shell
SOCK=/run/rproxy/api.sock
curl -s --unix-socket $SOCK -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost/config/global | jq '.items | map_values({value, source, apply})'

curl -s --unix-socket $SOCK -H "Authorization: Bearer $ADMIN_TOKEN" -X PATCH 'http://localhost/config/global?dry_run=true' \
  -d '{"http":{"timeouts":{"idle":"5m"}},"udp_max_sessions":32768}'
# if it looks right, send it again without ?dry_run=true; null removes the item's API value
```

- Each item named is replaced whole (inside `http.timeouts` too).
- With a DB, the values are stored in `rproxy_global` and come back after a restart. Without one they live only in the process.
- Changing a start-up-only item in the settings file shows in `restart_needed` in `GET /config` ([The global settings API in API.md](API.md#the-global-settings-api-v0419-342-featuresglobal_api)).

## 9. Changing things while running

### Re-reading the settings file

After an edit, the 10-second check applies only the difference. To get the result on the spot, use `POST /config/reload` (`admin`, Unix socket only by default).

```shell
curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $ADMIN_TOKEN" -X POST 'http://localhost/config/reload?dry_run=true' | jq
curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $ADMIN_TOKEN" -X POST http://localhost/config/reload
# {"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0,"restart_needed":[],...}
```

With a mistake it changes nothing, returns `400` with the reasons, and keeps running the previous settings. `--check-config --diff` also shows the difference from the running rproxy.

### Changes that keep connections (`in_place`) and changes that cut them (`recreate`)

| What changes | Effect |
|---|---|
| Targets (`remote_*`, `targets`, `balance`, `health_check`), `tls`, `starttls`, `allow_from`, `http`, `extra_listen_addrs`, timeouts, `limits`, `bandwidth`, `geoip`, `labels` and so on | `in_place`: current connections stay. TCP uses it from new connections; UDP moves current sessions too |
| `listen_port_end` (port range), `source_ip`, whether there is `http` | `recreate`: the listener is rebuilt and current connections are cut. A `PATCH` through the API gives `400 unsupported` (recreate the rule) |

The `change` field of a `?dry_run=true` answer tells you which it will be in advance.

### Waiting when stopping (drain)

- Deleting a rule: `DELETE /rules/...?drain_secs=30` (up to 3600 seconds).
- Stopping the process: `RPROXY_SHUTDOWN_DELAY` (waits with `/readyz` at 503) and `RPROXY_SHUTDOWN_DRAIN` (waits for current connections to end). Values for a load balancer in front: [Shutting down on SIGTERM in the README](../../README.en.md#shutting-down-on-sigterm-v041).

### Replacing the binary (no restart)

Patches within the same minor (X.Y) can be swapped in without cutting TCP and HTTP connections.

```shell
sudo systemctl kill -s USR2 --kill-whom=main rproxy-api    # hand over to the binary on disk
journalctl -u rproxy-api | grep -E '"handoff\.(done|failed|refused)"'
```

UDP sessions are re-created in the new process. `systemctl restart` cuts current connections, so use the handoff for upgrades (chapter 12, [UPGRADE.md](UPGRADE.md)).

## 10. Persistence, rule sets and dry run

### Keeping API-created rules

Rules created with a token that does not persist (`origin: dynamic`) live only in rproxy's memory and disappear on restart. There are three ways to keep them.

1. Write them in the settings file.
2. Create them in the UI (they go into the UI's DB and come back at start-up).
3. Create them through the API with a `persist: true` token (`origin: api`, written to `rproxy_rules` in `RPROXY_DATABASE_URL`).

```yaml
tokens:
  - name: ci-deploy
    sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    scopes: [rules:read, rules:write]
    persist: true
```

`persisted: true` in the answer means the DB committed it. If the DB is unreachable, the rule keeps running with `persisted: false` and the periodic reconciliation writes it again. The table is in [Storing API-created rules in API.md](API.md#storing-api-created-rules-144). Do not set it on the UI's token (the UI writes its own DB, so it would be stored twice).

### Rule sets (for automation)

A controller or CI sends `PUT` with the whole of a rule set every time. rproxy applies the difference.

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PUT http://127.0.0.1:8080/rulesets/ci/preview-42 -d '{
  "generation": 1,
  "rules": [
    {"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":20042,"remote_addr":"10.0.5.42","remote_port":8080}
  ]}' | jq '.results'
```

- If any rule fails the checks, nothing changes. A `generation` smaller than before gives `409 stale_generation`. With `If-Match` set to the `etag`, you do not overwrite someone else's change.
- `PATCH` / `DELETE` on a single rule of a set gives `409 owned`.
- Rule sets live in memory only (stored in `rproxy_rule_sets` with a `persist: true` token). After a restart, PUT them again once `GET /readyz` returns 200 ([Rule sets in API.md](API.md#rule-sets-conditions-and-readiness-for-the-kubernetes-controller-28)).

### Dry run

`POST` / `PATCH` / `DELETE /rules`, `PUT /rulesets/{name}`, `POST /config/reload`, `PATCH /config/global` and overlay `PUT` / `DELETE` accept `?dry_run=true`. They run the same checks and return the difference without changing anything.

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PATCH 'http://127.0.0.1:8080/rules/tcp/0.0.0.0/5432?dry_run=true' \
  -d '{"remote_addr":"10.0.0.13","remote_port":5432}' | jq '{action, change, diff}'
```

## 11. Observing (logs, `/metrics`, stats)

### Logs

One JSON event per line, told apart by `event` (the list is under [Logs in the README](../../README.en.md#logs)).

```shell
# when logging to a file (the package default)
tail -F /var/log/rproxy/rproxy.$(date +%F).log | jq -c 'select(.event == "degraded" or .event == "rule.failed" or .event == "audit")'
# when logging to journald
journalctl -u rproxy-api -o cat | jq -c 'select(.event == "conn.denied" or .event == "degraded")'
```

Look at these first: `degraded` (part stopped because of the environment), `rule.failed`, `config.error`, `audit` (API changes), `conn.denied` and `conn.limited`, `tls.error`, `target.down`, `cert.expiring`.

### `/metrics`

Prometheus format. It needs a `metrics:read` (or `admin`) token.

```shell
curl -s -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:8080/metrics | grep -E '^rproxy_(rules|rule_up|connections) '
```

### A rule's stats

Look at `stats` (`connections`, `rx_bytes`, `tx_bytes`, `denied`, `limited`, `targets`, `http` and so on) and `conditions` in `GET /rules/{protocol}/{addr}/{port}`. The counts are only in memory and start from 0 after a restart (a handoff does not lower them).

## 12. Upgrades and going back

### apt

```shell
sudo apt update && sudo apt install rproxy-api
journalctl -u rproxy-api -n 50 | grep -E '"handoff\.|"start"'
```

If the major.minor is the same as before, the package hands over with SIGUSR2 (connections stay); otherwise it restarts. A patch whose release notes say "restart required" restarts.

### Self-update (containers)

Make the image's entrypoint `rproxy-api launch` and pass `RPROXY_UPDATE=auto` (or `check` to only report). It verifies the signature of newer patches in the same X.Y and swaps them in by handoff. A version that dies before `RPROXY_UPDATE_HEALTHY` (default 60 seconds) is marked bad and rolled back. Keep it `off` on apt VMs and in Kubernetes ([Self-update in UPGRADE.md](UPGRADE.md#self-update-containers)).

```shell
curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $ADMIN_TOKEN" http://localhost/admin/update | jq
```

### Handing over by hand

Replace the binary, then `systemctl kill -s USR2 --kill-whom=main rproxy-api`, or `POST /admin/upgrade` (`admin`, from the Unix socket). It is done when `handoff.done` appears. If the new process is not ready within 30 seconds, the old one keeps running (`handoff.failed`).

### Going back to an earlier version

```shell
apt-cache policy rproxy-api                 # versions you can install (the repository keeps old ones)
sudo apt install rproxy-api=<a version listed above>   # within the same minor, going back also hands over
```

Before going back:

- **Remove settings that the newer version added first.** Older versions treat unknown items as mistakes. For example, going back to v0.4.22 with `allow_restored` (v0.4.23) still in the token file makes it refuse the whole token file, and no token works. The "Added" part of the release notes says which version each item needs.
- The same goes for new items in the settings file. Run `--check-config` with the older binary before going back.
- Values set with `PATCH /config/global` (from v0.4.19) are not handed over to older versions (the DB row stays).
- Going back across minors is a restart (no handoff).

## 13. Backup and restore

What to back up and the order of restoring are in [BACKUP.md](BACKUP.md). The essentials:

| What | Where |
|---|---|
| Environment file and tokens | `/etc/rproxy/rproxy.env`, `/etc/rproxy/tokens` |
| Settings file (static rules exist only here) | `RPROXY_CONFIG` |
| Certificates, keys and secret files | Paths in the settings and rules, `/var/lib/rproxy/certs/` (`PUT /certs`), `/var/lib/rproxy/acme/` (ACME) |
| DB | `forward_rules` (UI rules); `rproxy_rules`, `rproxy_rule_sets`, `rproxy_global`, `rproxy_rule_overlays` (written by rproxy) |

Order of restoring: install the packages (do not start) → restore `/etc/rproxy` and the keys → restore the DB → `--check-config` → start rproxy-api → start the UI → check. Rules created through the API with a token that does not persist are not in the DB; to keep them, save a copy of `GET /rules`.

## 14. Monitoring and alerts

### Collecting

```yaml
# prometheus.yml
scrape_configs:
  - job_name: rproxy
    authorization:
      credentials_file: /etc/prometheus/rproxy.token     # a metrics:read token (plain text)
    static_configs:
      - targets: ['10.0.0.2:8080']
```

If the control API listens on loopback only, collect on the same host (for example through the node exporter's textfile), or add the monitoring network's address to `RPROXY_API_ADDR` (tokens and TLS are then required; use `scheme: https`).

### What to watch

| To see | Value |
|---|---|
| Rules not running | `rproxy_rules{state="failed"}`, `rproxy_rule_up == 0` |
| All targets down | `rproxy_rule_all_targets_down`, `rproxy_http_service_down`, `rproxy_target_up` |
| Refused by limits | `rproxy_rule_limited_total{reason}` (`max_connections`, `source_connections`, `new_connections`, `packets`, `target_full`, `fd_budget`), `rproxy_http_limited_total` |
| Descriptor budget | `rproxy_session_budget_in_use` / `rproxy_session_budget_limit` |
| Certificate expiry | `rproxy_cert_expiry_seconds` |
| CrowdSec | `rproxy_crowdsec_connected` |
| Background tasks crashing | `rproxy_task_restarts_total{part}` |
| Lost log lines | `rproxy_log_dropped_total` |
| Handoffs | `rproxy_handoffs_total{outcome}`, `rproxy_build_info` |

### Example alerts

```yaml
# rproxy-alerts.yml
groups:
  - name: rproxy
    rules:
      - alert: RproxyRuleFailed
        expr: rproxy_rules{state="failed"} > 0
        for: 5m
        annotations: {summary: 'A rule is not running (state and error in GET /rules)'}
      - alert: RproxyAllTargetsDown
        expr: rproxy_rule_all_targets_down == 1 or rproxy_http_service_down == 1
        for: 2m
      - alert: RproxyLimited
        expr: sum by (protocol, listen, reason) (rate(rproxy_rule_limited_total{reason!="fd_budget"}[5m])) > 1
        for: 10m
        annotations: {summary: '{{ $labels.listen }} keeps refusing by {{ $labels.reason }}'}
      - alert: RproxyFdBudgetRefusing
        expr: sum(rate(rproxy_rule_limited_total{reason="fd_budget"}[5m])) > 0
        annotations: {summary: 'The descriptor budget is full and connections or sessions are refused (raise LimitNOFILE)'}
      - alert: RproxyFdBudgetHigh
        expr: rproxy_session_budget_limit > 0 and rproxy_session_budget_in_use / rproxy_session_budget_limit > 0.8
        for: 10m
      - alert: RproxyCertExpiring
        expr: rproxy_cert_expiry_seconds < 7 * 86400
      - alert: RproxyCrowdsecDisconnected
        expr: rproxy_crowdsec_connected == 0
        for: 5m
      - alert: RproxyTaskRestarted
        expr: increase(rproxy_task_restarts_total[15m]) > 0
        annotations: {summary: 'A background task crashed and was restarted (part in the degraded log)'}
      - alert: RproxyLogDropped
        expr: increase(rproxy_log_dropped_total[5m]) > 0
```

### Catching `degraded`

`degraded` (part stopped because of the environment) has no value in `/metrics`; it is only in the log. Pick it up with your log pipeline.

```shell
journalctl -u rproxy-api --since -1h -o cat | jq -c 'select(.event == "degraded") | {timestamp, part, error}'
```

With Loki, a query such as `{unit="rproxy-api.service"} | json | event="degraded"` can drive an alert.

## 15. Handling logs

- **Where**: the package default is `/var/log/rproxy/rproxy.<date>.log` (`RPROXY_LOG_FILE`). rproxy splits it by day and deletes files beyond `RPROXY_LOG_KEEP` (default 14), so logrotate is not needed. Remove the `RPROXY_LOG_FILE` line to log to stdout, which systemd puts in journald.
- **Access log**: requests to `http` rules are `http.access`. `global.access_log: /var/log/rproxy/access.log` moves them to their own file. Set through the API, it must be under `RPROXY_API_ACCESS_LOG_DIR` (keep that directory for rproxy's access logs only).
- **Volume**: so that attacks do not flood the log, `conn.denied`, `conn.limited`, `tls.error` and others are thinned per source (the number left out is in `suppressed` on the next line). Long fields chosen by the client are cut at 2,048 bytes.
- **Secrets**: query parameters such as `token`, `code` and `password` become `REDACTED`. The log contains client IPs, SNI and certificate CNs, so limit who can read it (`/var/log/rproxy` is 750).
- **CrowdSec**: the bundled parser and scenarios let CrowdSec read rproxy's logs ([CROWDSEC.md](CROWDSEC.md)). Write the file name in `acquis` as a glob (`/var/log/rproxy/*.log`).

## 16. Capacity limits

Sockets use file descriptors. At start-up rproxy raises its file limit (`RLIMIT_NOFILE`) to the hard limit. The package's unit has `LimitNOFILE=65536`.

| Limit | Default | What it counts |
|---|---|---|
| `LimitNOFILE` (unit) | `65536` | All of the process's file descriptors |
| `RPROXY_MAX_LISTENERS` | `0` (automatic: half of (limit − 1024); 32256 with 65536) | Listening sockets the control API may open (addresses × ports, twice for `http3`) |
| Connection and session budget | limit − 1024 − `RPROXY_MAX_LISTENERS` (32256 with 65536) | A TCP connection takes 2 (the accepted socket and the target), an `http` connection 1 plus 1 per connection to a target, a UDP session 1, a splice pipe 2 |
| `RPROXY_MAX_RANGE_PORTS` | `20000` | Ports in one rule |
| `RPROXY_MAX_RULES` / `RPROXY_MAX_RULESETS` | `10000` / `1000` | Rules and rule sets the API may create |
| `RPROXY_UDP_MAX_SESSIONS` | `16384` | Sessions of one UDP rule (the rule's `limits.max_connections` instead, if set) |

- When the budget is full, new connections are closed at once, and UDP sessions are refused or the oldest unestablished one is ended. It shows as `conn.limited` with `reason: fd_budget` and `rproxy_rule_limited_total{reason="fd_budget"}`. With 65536, that is about 16000 concurrent TCP relays. If it is not enough, raise `LimitNOFILE`:

  ```shell
  sudo systemctl edit rproxy-api
  # [Service]
  # LimitNOFILE=262144
  sudo systemctl restart rproxy-api
  ```

- The start-up `start` line shows `session_budget`, `max_listeners` and `fd_reserve`. Current use is `rproxy_session_budget_in_use`.
- Rules from the settings file and those restored from the DB count towards the limits but are never refused (only API changes that add give `409 limit`).
- **Source ports towards targets** (an OS rule): each TCP connection and UDP session from rproxy to a target uses one ephemeral port on the rproxy host. With the Linux default (`net.ipv4.ip_local_port_range`, 32768–60999), that is about 28000 per pair of source address and one target (address and port). To connect to one target more than that, widen the range or spread the load over several `targets`. With `source_ip: transparent` connections leave from the client's address, so these pairs are separate.

## 17. Recipes

All are settings-file examples. Change the certificate paths and addresses, and run `--check-config` before using them.

### A web app over HTTPS (ACME)

```yaml
version: 1
global:
  acme:
    accounts:
      letsencrypt:
        contact: ['mailto:admin@example.com']
        allowed_names: [app.example.com]
    resolvers:
      le-http: {account: letsencrypt, challenge: http-01}
rules:
  - protocol: tcp                  # 80: answers ACME http-01, sends the rest to HTTPS
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - {name: to-https, match: 'PathPrefix(`/`)', middlewares: [to-https]}
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
  - protocol: tcp                  # 443: terminates and forwards to the web app
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - acme: le-http
          domains: [app.example.com]
    http:
      http3: true
      routes:
        - name: app
          match: Host(`app.example.com`)
          service: app
          middlewares: [secure, compress]
      services:
        app:
          servers: [{url: 'http://127.0.0.1:3000'}]
          health_check: {path: /, interval: 10s}
      middlewares:
        secure: {headers: {hsts: {max_age: 31536000}, content_type_nosniff: true}}
        compress: {compress: {}}
```

Open TCP 80 and 443 and UDP 443 (HTTP/3). The certificate's status is in `GET /acme`.

### A TCP proxy for a database (long-idle connections)

```yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 10.0.0.2
    listen_port: 5432
    targets:
      - {addr: 10.0.1.11, port: 5432}
      - {addr: 10.0.1.12, port: 5432}
    balance: failover              # send to the primary, the next one if it fails
    health_check: {interval: 5s, timeout: 2s}
    connect_timeout: 3s
    idle_timeout: 12h              # do not cut pooled connections after 1h
    allow_from: [10.0.0.0/16]
    limits: {max_connections: 1000}
```

### A UDP game server

```yaml
version: 1
rules:
  - protocol: udp
    listen_addr: 0.0.0.0
    extra_listen_addrs: ['::']
    listen_port: 27015
    remote_addr: 10.0.0.80
    remote_port: 27015
    udp_idle_secs: 120             # do not drop quiet players after 30 seconds
    limits:
      max_connections: 4000        # this rule's sessions (instead of the default 16384)
      per_source:
        max_connections: 4
        packets: {average: 200, period: 1s, burst: 400}
```

### Splitting one 443 by name

```yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/example.pem, key_file: /etc/rproxy/tls/example.key}
      routes:
        - server_names: ['**.k8s.example.com']    # straight to Kubernetes (it holds the certificates)
          passthrough: true
          remote_addr: 10.2.255.131
          remote_port: 443
          source_ip: proxy_v2
    http:
      routes:
        - {name: wiki, match: Host(`wiki.example.com`), to: 'http://10.0.0.5:8080'}
        - {name: git, match: Host(`git.example.com`), to: 'http://10.0.0.6:3000'}
      default: {status: 404}
```

Names rproxy terminates (`wiki`, `git`) and names it passes through (`**.k8s.example.com`) share one port. If the targets hold every certificate, use the `tls.mode: sni` example (chapter 4).

## 18. Troubleshooting

### API errors

Answers have the form `{"error": "...", "code": "..."}`. All codes: [Errors in API.md](API.md#errors).

| `code` (HTTP) | Meaning | What to do |
|---|---|---|
| `static` (409) | A settings-file rule (for `PATCH /config/global`: an item set in the file or environment) | Edit the file. To add from the API, use an overlay |
| `already_exists` (409) | A rule with the same key or an overlapping listener exists | Find it with `GET /rules`. Change the address or port |
| `reserved` (409) | Overlaps the control API's (or `http01_listen`'s) address and port | Use another port. See `reserved` in `GET /interfaces` |
| `bind_failed` (409) | Cannot open the port (another process has it, permissions) | Find the user with `ss -lntup`. Below 1024 needs `CAP_NET_BIND_SERVICE` |
| `not_owner` (403) | A non-`admin` token tried to change or delete something another token created | Use the creating token or `admin`. Make the UI's token `admin` (or `allow_restored`) |
| `forbidden` (403) | Missing scope, outside `allow_listen_ports`, or a Unix-socket-only operation over TCP | Check the token. Send strong operations through `RPROXY_API_SOCKET` |
| `file_in_use` (409) | Pointed to a key or secret file used by another owner's rule | Provide your own file (or use `admin`) |
| `protected_file` (403) | Pointed into the certificate store, the ACME storage, rproxy's secrets and so on | Put the file elsewhere |
| `file_not_allowed` (403) | An `allow_certs` token wrote a file path | Use `{cert: <name>}` (a stored certificate) |
| `tls_config` / `invalid` (400) | A shape mistake or an unreadable file | The reason is in the `config.file` log. Check with `--check-config` |
| `unsupported` (400) | Not available in this version or environment, or not changeable by `PATCH` | See `features` in `GET /capabilities`. Recreate the rule |
| `limit` (409) | Over `RPROXY_MAX_*` or the token's `max_rules` / `max_rulesets` | Delete unused ones or raise the limit (chapter 16) |
| `owned` (409) | Tried to change a single rule of a rule set | `PUT` the rule set |
| `stale_generation` (409) / `precondition_failed` (412) | An old `generation`, or `If-Match` did not match | Read again, then send |
| `resolve_failed` (502) | The target's name does not resolve | Check DNS. The rule starts by itself once it resolves |
| `locked_out` (429) | Too many authentication failures from this source | Wait for `Retry-After`. Fix the token |
| `upgrading` / `shutting_down` (503) | In a handoff or a shutdown | Wait a little and send again |
| `no_config` (409) | `POST /config/reload` without a settings file | Set `RPROXY_CONFIG` |
| `restart_only` (409) / `in_use` (409) | A `global` item that needs a restart / removing something a rule uses | Change it in the file and restart / fix the rule first |

### A rule is `failed` or does not work

- Read `error` and `conditions` (`BindFailed`, `ResolveFailed`, `CertificateUnreadable` and so on) in `GET /rules`.
- Read the `rule.failed`, `config.error` and `config.file` logs.
- For the settings file, run `--check-config`; the result of applying it is `error` in `GET /config`.
- `persisted: false`: the DB was not reached. Look for `degraded` with `part: db`.

### Connections are refused

| Log | Reason | What to do |
|---|---|---|
| `conn.denied` (`allow_from`, `geoip`, `crowdsec`, `unmatched`) | Refused by access control | Check the ranges, countries and bans. `unmatched` means the `tls.routes` names |
| `conn.denied` (`proxy_protocol*`) | No PROXY protocol header, or the front proxy is outside `from` | Add the front proxy's address to `from` |
| `conn.limited` (`max_connections` and others) | The rule's `limits` | Raise the limits |
| `conn.limited` (`target_full`) | Every target is at `max_connections` | Add targets or raise the limit |
| `conn.limited` (`fd_budget`) | The process's descriptor budget is full | Raise `LimitNOFILE` (chapter 16) |
| `tls.error` | A TLS handshake failed | Certificate, name, `min_version`, client support |
| `target.down` | The target failed its liveness check | The target, `health_check`'s `port` |
