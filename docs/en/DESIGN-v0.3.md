日本語: [DESIGN-v0.3.md](../DESIGN-v0.3.md)

# v0.3 design: the shape of the configuration and API

v0.3.0 decides, all at once, the **shape of the configuration and API** for the features to be added (#72). The functionality itself becomes usable step by step in v0.3.x patch releases (docs/RELEASING.md).
Once this document is settled, its contents are copied into docs/API.md as the official shape, and this document remains as a record of how the design came about.

The goal is to make the configuration currently running on Traefik (per-path routes, rate limits and CrowdSec for gitlab, allowed paths for cdn, metrics, HTTP→HTTPS) expressible with rproxy alone (#29).

## 1. Policy

| Item | Decision |
|---|---|
| Files written by humans | YAML (`.yaml` / `.yml`). `.json` in the same shape is also read (#27) |
| Control API | JSON. Same shape as the rules in the file |
| DB `options` column | JSON. Rule fields such as `http` are added |
| Availability | Announced via `features` in `GET /capabilities`. A rule that specifies a feature not yet implemented is rejected with `unsupported` (and not saved) |
| Compatibility | The 0.2 shapes (JSON array of rules, current API fields, current token file) are still read as-is |
| Reuse | Middlewares and services are written inside the rule (easier to handle in the API, DB and UI). In files, they can be reused with YAML anchors (`&name` / `*name`) |

## 2. Configuration file (#27)

Set `RPROXY_CONFIG` to a file or a directory (`*.yaml` files are read in name order). When it is changed, the difference is applied without a restart. `RPROXY_STATIC_RULES` remains as an alias for it (its content may be an array of rules or the shape below).

> Implemented in v0.3.2: a directory reads `*.yaml` / `*.yml` / `*.json` (excluding names starting with `.`), and `global` may appear in only one file. The check interval is `RPROXY_CONFIG_CHECK_SECS` (default 10 seconds) plus SIGHUP. A version with errors is not applied and is reported in `error` of `GET /config`. Changes to `global` do not take effect until restart (`restart_needed`).

```yaml
# /etc/rproxy/rproxy.yaml
version: 1

# Process-wide settings (no precedence over the RPROXY_* environment variables; write each in only one place)
global:
  trusted_proxies: [10.0.0.0/8]          # #67. Trust X-Forwarded-For from this range (→ as implemented, PROXY headers are not read; see 3.)
  access_log: /var/log/rproxy/access.log # #57. Log of L7 requests (JSON Lines)
  acme:                                  # #17, #208 (reshaped in v0.4.0; docs/en/ACME.md)
    storage: /var/lib/rproxy/acme
    accounts:
      le: {contact: ['mailto:admin@example.com'], allowed_names: ['**.example.com']}
    dns_providers:                       # for dns-01; secrets are named by files
      pdns: {type: powerdns, api_url: 'http://127.0.0.1:8081', api_key_file: /etc/rproxy/acme/pdns.key, allowed_names: ['*.example.com']}
    resolvers:
      letsencrypt: {account: le, challenge: tls-alpn-01}   # http-01 / tls-alpn-01 / dns-01 (dns_provider)
  crowdsec:                              # #55
    lapi_url: http://127.0.0.1:8080
    api_key_file: /etc/rproxy/crowdsec.key
    appsec_url: http://127.0.0.1:7422
    update_interval: 10s

rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls: {...}          # Same as now (ACME and options are added in section 4 below)
    http: {...}         # L7 from section 3
```

## 3. L7 (the rule's `http`)

A rule with `http` routes each request as HTTP, either after terminating TLS (`tls.mode: terminate`) or in plaintext. `http` can be attached to `protocol: tcp` rules where `tls.mode` is `terminate` or there is no TLS (plaintext HTTP, treated as `passthrough`).

```yaml
http:
  http3: true                  # #56. Also accept QUIC on the same UDP port. Adds Alt-Svc
  routes:                      # #52. Tried in order of highest priority, then longest match
    - name: gitlab-login
      match: Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)
      priority: 100
      service: gitlab
      middlewares: [crowdsec, rate-limit-login]
  default:                     # When no route matches (404 if omitted)
    status: 404
  services:                    # #61
    gitlab:
      servers:
        - url: http://10.0.0.20:80
          weight: 1
      health_check: {path: /-/readiness, interval: 10s, timeout: 3s}
      sticky: {cookie: rproxy_gitlab}
      pass_host_header: true
      timeouts: {connect: 5s, response: 60s}   # #64
  middlewares:                 # name → exactly one type
    rate-limit-login: {rate_limit: {average: 5, period: 1m, burst: 10}}
    crowdsec: {crowdsec: {appsec: true}}
```

- Do not write `remote_addr` / `remote_port` in an `http` rule (all upstreams go in `services`; writing them is `invalid`).
- The upstream is specified with `service` (a name) or `to: http://host:port` (a shorthand for a single service).
- `X-Forwarded-For` / `-Proto` / `-Host` / `X-Real-IP` are always added (values from `global.trusted_proxies` are carried over. The client IP is the first untrusted address when reading X-Forwarded-For from the right. PROXY headers are not read). WebSocket is passed through as-is.
- Redirect-only routes (such as HTTP→HTTPS on port 80) have no `service`; the middleware returns the response.
- (Decided in v0.3.1) `source_ip` is only `proxy` / `transparent` (PROXY headers do not fit per-request forwarding, so the client is conveyed via `X-Forwarded-For`). `tls.routes` is not used; routing is done with `Host(...)`. Verification of `https://` upstreams uses `ca_file` etc. in `tls.upstream`, not `tls.upstream.tls`. Connections to upstreams are first created per request; reuse will be added later (→ reused since v0.3.2; see 9.). Detailed behavior is in "Behavior of `http` rules" in docs/API.md.

### Writing match (same as Traefik)

| Condition | Example |
|---|---|
| `Host` / `HostRegexp` | ``Host(`gitlab.example.com`)``, ``HostRegexp(`^.+\.example\.com$`)`` |
| `Path` / `PathPrefix` / `PathRegexp` | ``PathPrefix(`/api/`)`` |
| `Method` | ``Method(`POST`)`` |
| `Header` / `HeaderRegexp` | ``Header(`X-Requested-With`, `XMLHttpRequest`)`` |
| `Query` / `QueryRegexp` | ``Query(`preview`, `1`)`` |
| `ClientIP` | ``ClientIP(`10.0.0.0/8`, `fd00::/8`)`` |

Combine with `&&`, `||`, `!` and parentheses.

### Middleware types

| Type | Settings | Issue |
|---|---|---|
| `redirect_scheme` | `scheme` (default https), `port`, `permanent` | #53 |
| `redirect_regex` | `regex`, `replacement`, `permanent` | #53 |
| `rate_limit` | `average`, `period`, `burst`, `source` (`ip` / `header: X-Real-IP`) | #54 |
| `in_flight` | `amount` (number of requests processed concurrently) | #54 |
| `crowdsec` | `appsec` (true / false), `on_error` (`allow` / `block`) | #55 |
| `ip_allow` | `source_range` (list of CIDRs) | v0.3.1, together with #53 |
| `headers` | `set` / `remove` for `request` / `response`, `hsts`, `frame_deny`, `content_type_nosniff`, `referrer_policy`, `csp`, `cors` | #60 |
| `forward_auth` | `address`, `response_headers`, `trust_forward_header` (`request_headers` and `timeout` added in v0.3.2) | #59 |
| `oidc` | `issuer`, `client_id`, `client_secret_file`, `scopes`, `cookie_secret_file` (`ca_file`, `callback_path`, `logout_path`, `cookie_name`, `groups_claim` added in v0.3.2) | #59 |
| `basic_auth` | `users_file` (htpasswd: bcrypt, APR1, {SHA}) (`realm`, `keep_authorization`, `user_header` added in v0.3.2) | #59 |
| `strip_prefix` / `add_prefix` / `replace_path` / `replace_path_regex` | `prefixes` / `prefix` / `path` / `regex`, `replacement` | #62 |
| `compress` | `encodings` (gzip, br, zstd), `min_size` | #63 |
| `buffering` | `max_request_body` (413) | #64 |
| `retry` | `attempts`, `initial_interval` (idempotent methods only) | #64 |
| `circuit_breaker` | `failure_percent` (1–100), `window`, `recovery` | #64 |
| `errors` | `status` (e.g. `500-599`), `service`, `path` | #65 |
| `respond` | `status`, `body`, `content_type` (maintenance pages or rejection) | #65 |

## 4. TLS additions (#17, #66)

> ACME (#17) was first left out in v0.3.2, then built in from v0.4.0 (#208; docs/en/ACME.md). The rule side (`acme` and `domains`) keeps the v0.3.0 shape. `global.acme` splits v0.3.0's per-resolver `email`, `directory` and `dns` into `accounts` (CA, contact, account key, allowed names) and `dns_providers` (named providers, secrets in files, allowed names), and `resolvers` combine them by name (rules made through the API only name a resolver; secrets and what may be obtained stay in the fixed settings). The v0.3 `global.acme` never ran (`unsupported`), so there is no compatibility. Files obtained with certbot / cert-manager and the like still work.

```yaml
tls:
  mode: terminate
  certificates:
    - acme: letsencrypt                    # Certificate obtained via ACME (instead of files). → Not available (see the note above; unsupported)
      domains: [gitlab.example.com, cdn.example.com]
    - cert_file: /etc/rproxy/tls/other.pem # Files can still be used as before
      key_file: /etc/rproxy/tls/other.key
  options:                                 # #66
    min_version: "1.2"
    cipher_suites: [TLS13_AES_128_GCM_SHA256, ...]
    alpn: [h2, http/1.1]                   # The current alpn location is also allowed here
```

## 5. Control API

- Add `http` and `tls`'s `acme` / `options` to the bodies of `POST /rules` and `PATCH /rules/...` (same shape as the file).
- `GET /capabilities` returns the features usable in this version.

```json
{"features": {"http": true, "http3": true, "acme": true, "tls_options": true,
              "middlewares": ["redirect_scheme", "redirect_regex", "ip_allow", "headers"],
              "services": ["health_check"]}}
```

- Add L7 statistics (request counts per route, by status code) to `GET /rules/...` (#57).

## 6. Token permissions (#30) and Unix socket (#3)

In addition to the current "one per line" format (full permissions), the token file is also read as YAML.

```yaml
# /etc/rproxy/tokens.yaml
tokens:
  - name: ui
    sha256: 9f86d0...          # Do not store the token itself (generate with sha256sum)
    scopes: [rules:read, rules:write]
  - name: ci-deploy
    sha256: 2c26b4...
    scopes: [rules:write]
    allow_listen_ports: 20000-29999
    expires: 2027-03-31
```

- Scopes: `rules:read`, `rules:write`, `metrics:read`, `admin` (everything)
- Audit log of changes: `event: "audit"`, token name, operation, rule
- `GET /openapi.json` returns the API definition (v0.3.2. A hand-written `docs/openapi.json`; mismatches with the router are caught by tests)
- No CLI (`rproxyctl`) will be built. `curl` and clients generated from the OpenAPI definition are sufficient (no extra binaries)
- The relationship between rules from the API, the configuration file and the UI (DB) is described in "Relationship between the API, config file and UI (DB)" in docs/API.md

Unix socket: `RPROXY_API_SOCKET=/run/rproxy/api.sock` (`RPROXY_API_SOCKET_MODE`, `RPROXY_API_SOCKET_GROUP`). Can be used together with the TCP listener. The UI uses `RPROXY_API_URL=unix:/run/rproxy/api.sock`.

## 7. Example: rewriting the current Traefik configuration

```yaml
version: 1
rules:
  # 80: HTTP→HTTPS (also normalizes www)
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - name: redirect
          match: HostRegexp(`^.+$`)
          middlewares: [to-https]
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}

  # 443: gitlab and cdn
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - acme: letsencrypt                # → not available (the note in 4.); in practice, cert_file / key_file of files made by certbot etc.
          domains: [gitlab.example.com, cdn.example.com]
    http:
      http3: true
      routes:
        - name: gitlab-login
          match: Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)
          service: gitlab
          middlewares: [crowdsec, rate-limit-login]
        - name: gitlab-api
          match: Host(`gitlab.example.com`) && PathPrefix(`/api/`)
          service: gitlab
          middlewares: [crowdsec]
        - name: gitlab-assets
          match: Host(`gitlab.example.com`) && (PathPrefix(`/assets/`) || PathPrefix(`/uploads/`))
          service: gitlab
          middlewares: [crowdsec, rate-limit-assets]
        - name: gitlab-internal
          match: Host(`gitlab.example.com`) && ClientIP(`10.0.0.0/8`)
          service: gitlab
        - name: gitlab
          match: Host(`gitlab.example.com`)
          service: gitlab
          middlewares: [crowdsec]
        - name: cdn-allowed
          match: Host(`cdn.example.com`) && (PathPrefix(`/file/`) || PathPrefix(`/images/`) || PathPrefix(`/iso/`))
          service: cdn
          middlewares: [crowdsec]
        - name: cdn-block
          match: Host(`cdn.example.com`)
          middlewares: [forbidden]
        - name: metrics
          match: PathPrefix(`/metrics`)
          service: metrics
          middlewares: [internal-only]
      services:
        gitlab: {servers: [{url: http://10.0.0.20:80}]}
        cdn: {servers: [{url: http://10.0.0.30:80}]}
        metrics: {servers: [{url: http://10.0.0.40:9100}]}
      middlewares:
        crowdsec: {crowdsec: {appsec: true}}
        rate-limit-login: {rate_limit: {average: 5, period: 1m, burst: 10}}
        rate-limit-assets: {rate_limit: {average: 100, period: 1s, burst: 200}}
        internal-only: {ip_allow: {source_range: [10.0.0.0/8]}}
        forbidden: {respond: {status: 403}}
```

### CrowdSec (#55, v0.3.1)

- LAPI decisions are fetched in bulk via the stream (`/v1/decisions/stream`) by a single task and shared by all rules. Decisions are tracked by ID, and an address stays blocked as long as another decision for the same address remains.
- Captchas cannot be shown, so they are treated the same as bans. Only the `Ip` and `Range` scopes are supported.
- Only bodies with a `Content-Length` of 1 MiB or less are sent to AppSec (reading a body without a length to the end before forwarding would delay streaming and uploads).
- Cutting connections before TLS in L4 (rules without `http`) was added in v0.3.2 as the rule's `crowdsec: true` ("Rules" in docs/API.md).

## 8. Undecided items (to be worked out during implementation)

- Granularity of statistics for `http` rules (planned: down to route × status code, not down to path)
- Whether to send to upstreams over HTTP/2 (HTTP/1.1 first; add h2c if gRPC is needed)
- Kubernetes CRDs (#28) will use this rule shape as-is for `spec` (`apiVersion: rproxy.max3584.net/v1alpha1`, `kind: RproxyRule`)
- Renaming source_ip (#49) is on hold. If the shape is to change, v0.3.0 is the opportunity

## 9. Decided in v0.3.2 (load balancing, fault tolerance, compression, error pages)

- A "failure" for `circuit_breaker` is a 5xx (including the 502 / 504 returned by rproxy itself). It only evaluates when there are 10 or more entries in `window`, and once open, lets exactly one request through every `recovery` to probe (the equivalent of Traefik's `ResponseCodeRatio(500, 600, 0, 600) > failure_percent/100`, made usable without writing an expression)
- `retry` only applies when the connection fails or there is no response (502 / 504). A 5xx returned by the upstream is not retried (same as Traefik). Requests with a body are only retried when they were fully read by `buffering`
- `{status}` in the `path` of `errors` is replaced with the status code (same as Traefik's `query`)
- `compress` compresses and sends data as it streams in (prioritizing not stalling long-running responses over compression ratio)
- The `sticky` cookie value is derived from the upstream URL (it does not change across restarts or when upstreams are added)
- HTTP/1.1 connections to upstreams are reused (except with `source_ip: transparent`)
