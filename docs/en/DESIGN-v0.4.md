日本語: [DESIGN-v0.4.md](../DESIGN-v0.4.md)

# v0.4 design: the shape of the configuration and API

> **Implemented (v0.4.0)**: every item of this document is on master and ships in v0.4.0 (shape in #216, implementation in #218-#223). Every v0.4 item of `features` in `GET /capabilities` is true. The authoritative shape is the "v0.4 settings" section of docs/en/API.md; this document stays as the design history. Where the implementation departs from the design is in "15. Deviations in the implementation". The Kubernetes controller (#28) continues in the separate repository `max3584/rproxy-gateway`.

v0.4.0 decides, all at once, the **shape of the configuration and API** for the features to be added (#215). The process follows v0.3.0 (docs/en/DESIGN-v0.3.md): first the shape (types, validation, `features` set to false, openapi.json, the "v0.4 settings" section of docs/API.md, `unsupported` tests) goes into master; then one implementation PR per item is built on top of it, and each item's `features` flag becomes true once implemented.

> **v0.4.0 is released once, with everything implemented** (owner's decision). Unlike v0.3, there is no shape-only v0.4.0 followed by v0.4.x patches filling it in. The shape PR and the implementation PRs land on master one after another, but the release waits until every item is `true`. Until then, items not done yet are `unsupported` on master.

Once this document is settled, it is copied into the "v0.4 settings" section of docs/en/API.md as the authoritative shape; this document stays as the design history.

## 1. Principles

| Topic | Decision |
|---|---|
| Where settings live | Settings of a rule go in the rule (same shape in the API, the settings file and the DB `options`). Process-wide settings go in the settings file's `global`. Things needed before the settings file is read (control API, startup, updates) stay CLI flags and `RPROXY_*` environment variables, as today |
| Availability | A flag per item in `features` of `GET /capabilities` (all start false). List-shaped ones (`middlewares`, `services`, `performance`) list the names that can run |
| Settings that cannot run yet | Rules: the shape is validated, then the API answers `400 unsupported` (nothing is stored). Rules at startup / reload are registered as `failed` with the reason (as in v0.3). `global`, CLI flags, environment variables: an `event = "degraded"` line and the setting is ignored (as in v0.3). Exception: settings whose being ignored **would weaken protection** (client certificates for the control API) are configuration errors that stop the startup |
| Endpoints that cannot run yet | After authentication and the scope check, `400 unsupported` (the HTTP status of `unsupported` stays 400) |
| Compatibility | 0.3 settings files, API bodies, DB rows and token files still load. Everything added is optional, and leaving it out behaves as 0.3 |
| Item boundaries | One module per item (table below). Implementation PRs touch that module and the data plane; the shared places (`rule.rs`, `config/mod.rs`, `api.rs`, openapi.json) get everything up front in the shape PR |
| Units | Durations are strings as before (`10s`, `500ms`, `5m`, `1h`). Rates (bandwidth) are strings like `"10Mbps"` (bits per second, steps of 1000: `bps`, `kbps`, `Mbps`, `Gbps`). Sizes are like `"256KiB"` (`B`, `KiB`, `MiB`, `GiB`, steps of 1024) |

### Items, modules and `features`

| Issue | Item | Where the shape lives (module) | `features` | Implemented in |
|---|---|---|---|---|
| #28 | Kubernetes hooks (rule sets, labels, conditions, readiness) | `src/core/ruleset.rs`, `src/control/ruleset_api.rs` | `rulesets`, `labels`, `conditions`, `readyz` | #220 |
| #165 | L4 per-source limits | `src/core/limits.rs` | `limits` | #219 |
| #166 | Bandwidth limits and accounting | `src/core/bandwidth.rs` | `bandwidth` | #219 |
| #167 | Control API hardening | `src/control/hardening.rs` | `client_cert_auth`, `token_expiry`, `api_lockout` | #218 |
| #168 | GeoIP | `src/net/geoip.rs` | `geoip`, `geoip` in `middlewares` | #221 |
| #169 | Diff before change | `src/config/plan.rs` | `dry_run` | #222 |
| #170 | Passive health checks | `src/core/outlier.rs` | `outlier_detection`, `outlier_detection` in `services` | #221 |
| #174 | Live upgrade, self-update | `src/control/upgrade.rs` | `handoff`, `self_update` | #223 |
| #144 | Storing API-created rules | `src/config/persist.rs` | `persistence` | #222 |
| #194, #184 | Performance settings | `src/config/performance.rs` | `performance` (names of the keys that take effect) | #223 |

## 2. Combined example

```yaml
version: 1
global:
  geoip:                                   # #168
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb
    check_interval: 1m
    log_country: true
  performance:                             # #194, #184
    workers: 8
    udp_shards: auto
    cpu_affinity: auto
    busy_poll_usecs: 0
    splice: {enabled: true, after: 0, full_reads: 4, pipe_size: 0}

rules:
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 27015
    targets: [{addr: 10.0.0.10, port: 27015}, {addr: 10.0.0.11, port: 27015}]
    labels: {tenant: act, service: game}   # #28, #166
    limits:                                # #165
      max_connections: 20000
      per_source:
        max_connections: 8
        new_connections: {average: 10, period: 1s, burst: 20}
        packets: {average: 2000, period: 1s, burst: 4000}
    bandwidth:                             # #166
      download: 500Mbps
      per_source: {upload: 2Mbps, download: 10Mbps}
    geoip: {allow_countries: [JP]}         # #168
    outlier_detection:                     # #170
      consecutive_failures: 3
      ejection_time: 10s
      max_ejection_time: 5m
      max_ejected_percent: 50
```

## 3. #28 Kubernetes (Gateway API)

### 3.1 Approach

- **The controller is not built into rproxy; it is a separate process** that creates rules through the control API (rproxy knows nothing of the Kubernetes API).
- **It lives in a separate repository, `max3584/rproxy-gateway`** (not a `controller/` directory here). Reasons: keep kube-rs, k8s-openapi and friends out of rproxy-api's `Cargo.lock`, `cargo deny` and cross builds; the release units differ (container image, Helm chart, CRD versions); Gateway API conformance tests run in their own CI. The proposed language is Rust (kube-rs), which keeps this repository's types and validation style. rproxy and the controller meet only at the control API (`docs/openapi.json`).
- Gateway API is the main target. Ingress and Traefik CRDs are for migration (read only, never written back).

### 3.2 What rproxy adds

**Rule sets**: the controller hands over "all the rules it owns" in one call and rproxy applies the difference (declarative; no sequences of POST / PATCH / DELETE; if the controller dies half way, the next sync converges).

| Method and path | Body | Success | Description |
|---|---|---|---|
| `GET /rulesets` | | 200 | The sets: `[{"name","generation","etag","rules":<count>,"updated_at","updated_by"}]`. `rules:read` |
| `GET /rulesets/{name}` | | 200 | `{"name","generation","etag","rules":[<rule>...]}`; the `ETag` header has the same value. `rules:read` |
| `PUT /rulesets/{name}?dry_run=true` | `{"generation": 42, "rules": [<rule>...]}` | 200 | Makes the set's rules equal to the body: rules in the body and not running are created, rules in both that differ are changed along the PATCH path (in place where possible), running rules missing from the body are deleted. With `If-Match: <etag>`, a different current etag is `412 precondition_failed`. `generation` is the caller's generation (e.g. Kubernetes `metadata.generation`), stored and echoed (a lower generation is `409 stale_generation`). Answer: `{"name","generation","etag","dry_run","results":[{"rule":"tcp/0.0.0.0:443","action":"create\|update\|delete\|none","change":"none\|in_place\|recreate","state","error"}]}`. Every rule's shape is validated first; if any is `invalid`, nothing changes (`400`, `errors` carry the index in the set). A bind or resolve failure marks only that rule `failed`; the rest is applied. `rules:write`; every rule must be within the token's `allow_listen_ports` |
| `DELETE /rulesets/{name}?drain_secs=N` | | 204 | Deletes all rules of the set |

- Set names: `[a-z0-9]([a-z0-9._/-]{0,251}[a-z0-9])?` (e.g. `k8s/default/web-gateway`).
- Rules of a set also appear in `GET /rules`, with `ruleset: "<name>"`. Changing such a rule with a single `PATCH` / `DELETE` is `409 owned` (so nobody fights the set's owner; PUT the set instead). A key taken by a settings-file rule is `409 static`; a key taken by a dynamic rule outside any set is `409 already_exists` (never taken over silently).
- Sets live in rproxy's memory and are not written to the DB (nor stored by #144). After a restart the controller PUTs them again (once `GET /readyz` is ready).
- Etag: a string made from the normalized JSON of the set's rules and the generation (`"g42-<first 16 hex digits of sha256>"`).

**Labels**: a rule's `labels` (`{key: value}`). They mark what a controller owns (e.g. `gateway.networking.k8s.io/gateway-name` verbatim) and the owner (tenant) for #166 accounting.

- Keys `[a-z0-9A-Z]([a-z0-9A-Z._/-]{0,61}[a-z0-9A-Z])?`, values 0-253 characters (no control characters), at most 16 per rule.
- They change no behaviour (only shown in logs and `/metrics`). `/metrics` gets `rproxy_rule_labels{rule="...",label_<key's alphanumerics and _>="value"} 1` (an info metric; few series).
- `PATCH` with `labels` replaces them all (`{}` removes them).

**Conditions**: the rule view gets `conditions`, shaped to be copied into Gateway API status.

```json
"conditions": [
  {"type": "Accepted",     "status": "True",  "reason": "Accepted",      "message": "", "last_transition": 1790000000},
  {"type": "Programmed",   "status": "True",  "reason": "Listening",     "message": "", "last_transition": 1790000000},
  {"type": "ResolvedRefs", "status": "False", "reason": "ResolveFailed", "message": "backend.local: no address", "last_transition": 1790000123},
  {"type": "BackendsHealthy", "status": "True", "reason": "Healthy", "message": "", "last_transition": 1790000000}
]
```

| type | True when | reasons for False |
|---|---|---|
| `Accepted` | The shape is valid and this build can run it | `Invalid`, `Unsupported` |
| `Programmed` | Listening (`state: running`) | `BindFailed`, `Failed`, `Pending` |
| `ResolvedRefs` | Backend names, certificates and secret files are all there | `ResolveFailed`, `CertificateExpired`, `CertificateUnreadable` |
| `BackendsHealthy` | Some backend is up | `AllTargetsDown`, `ServiceDown` |

`last_transition` is in Unix seconds. The existing `state`, `error`, `all_targets_down` and `down_services` stay (the UI uses them).

**Readiness**: `GET /readyz` (no authentication, like `/healthz`).

- `200 {"ready": true}`: the startup restore (settings file, DB) is done and requests are accepted.
- `503 {"ready": false, "reason": "starting" | "draining"}`: during the restore, or in the old process after it stopped accepting during a #174 handoff.
- Failed rules do not affect readiness (one bad rule must not take the whole pod out; rule state is in `conditions`).
- `/healthz` stays liveness only.

### 3.3 The controller (rproxy-gateway)

- `GatewayClass` `spec.controllerName: rproxy.max3584.net/gateway-controller`.
- Supported resources (mainly the Gateway API v1.x standard channel; TCP, UDP and TLS routes are in the experimental channel):

| Resource | rproxy rule |
|---|---|
| `Gateway` listeners (`HTTP`, `HTTPS`, `TLS`, `TCP`, `UDP`) | One (protocol, address, port) is one rule. Several listeners on one port (different hostnames) merge into one rule |
| `HTTPRoute` | `http.routes`. `matches` (path, headers, queryParams, method) → the `match` expression; `backendRefs` weights → `servers` `weight`; `filters`: `RequestHeaderModifier` / `ResponseHeaderModifier` → `headers`, `RequestRedirect` → `redirect_scheme` / `redirect_regex`, `URLRewrite` → `replace_path` / `strip_prefix`, `ExtensionRef` (`RproxyMiddleware`) → that middleware |
| `TLSRoute` | `tls.mode: sni` (`tls.routes`); on the port of an HTTPS listener, a passthrough route of the `http` rule |
| `TCPRoute`, `UDPRoute` | L4 rules (`targets`) |
| `GRPCRoute` | Not yet (no HTTP/2 towards backends; `Accepted: False`, reason `UnsupportedValue`) |
| `ReferenceGrant` | Checked for Services and Secrets in other namespaces |
| `BackendTLSPolicy` | `ca_file` of `https://` backends (the Secret / ConfigMap written to a file on the rproxy host) |

- Backends are **the pod IPs from EndpointSlices** (not the Service's ClusterIP) in `targets` / `servers`, so rproxy's balancing and passive health checks work. When EndpointSlices change, the set is PUT again (a change of backends only does not drop connections).
- Certificates (`certificateRefs` Secrets) are written to files on the rproxy host (a volume shared with the DaemonSet) and referenced with `cert_file` / `key_file` (key material is never sent over the control API).
- Settings Gateway API lacks (`rate_limit`, `crowdsec`, `geoip`, `limits`, `bandwidth`, `outlier_detection`, ...) come from rproxy CRDs:
  - `RproxyMiddleware` (`rproxy.max3584.net/v1alpha1`): `spec` has the shape of `http.middlewares.<name>`. Used through HTTPRoute `ExtensionRef`.
  - `RproxyPolicy`: `spec.targetRefs` (Gateway, listener, Service) plus the rule's `limits`, `bandwidth`, `geoip`, `outlier_detection`, `allow_from`, `crowdsec` (policy attachment, GEP-713).
  - `RproxyRule`: the rule's shape verbatim in `spec`, an escape hatch (the idea in docs/en/DESIGN-v0.3.md 8.) for what Gateway API cannot express.
- Status: Gateway `status.listeners[].conditions` (`Programmed`, `Accepted`) and Route `status.parents[].conditions` (`Accepted`, `ResolvedRefs`) are written from the rules' `conditions`. `observedGeneration` is the set's `generation`.
- Set names are `k8s/<Gateway namespace>/<Gateway name>`: one Gateway, one set.
- Deploying rproxy: a DaemonSet with `hostNetwork: true` (L4 and UDP work plainly), or a Deployment behind a `LoadBalancer` Service. The controller PUTs the same set to every rproxy pod's control API (mTLS #167 and a token).
- Migration (optional, enabled by a flag): `Ingress` (`ingressClassName: rproxy`) → `http` rules. Traefik `IngressRoute`, `IngressRouteTCP`, `IngressRouteUDP`, `Middleware` (`traefik.io/v1alpha1`) → the same mapping as `contrib/traefik2rproxy.py` (docs/en/MIGRATING-FROM-TRAEFIK.md).
- Deliverables: container image (GHCR), CRDs, Helm chart, DaemonSet manifests.

### 3.4 Compatibility and security

- 0.3 rules without `labels`, `ruleset` or `conditions` stay as they are.
- PUT of a set needs `rules:write`. Narrow the controller's token with `allow_listen_ports`.

## 4. #165 L4 per-source limits

A rule's `limits` (TCP and UDP; on `http` rules they apply to the TCP connections).

```yaml
limits:
  max_connections: 20000          # concurrent connections of the whole rule (UDP: sessions)
  per_source:
    prefix_v4: 32                 # how sources are grouped (default 32 and 64)
    prefix_v6: 64
    max_connections: 8            # concurrent connections of one source (UDP: sessions)
    new_connections: {average: 10, period: 1s, burst: 20}   # rate of new connections (UDP: new sessions)
    packets: {average: 2000, period: 1s, burst: 4000}       # rate of UDP datagrams (UDP only)
    max_sources: 65536            # most sources remembered (default 65536)
```

| Key | Validation |
|---|---|
| `max_connections` | 1-10,000,000 |
| `per_source.prefix_v4` / `prefix_v6` | 1-32 / 1-128 |
| `per_source.max_connections` | 1-1,000,000 |
| `new_connections` / `packets` | `average` at least 1, `period` 1ms-1h (default 1s), `burst` at least `average` (default `average`). The same shape as the L7 `rate_limit` |
| `packets` | `protocol: udp` only (`invalid` on tcp) |
| `max_sources` | 1-1,000,000 (lowered from 10,000,000 by security review L8) |
| Overall | At least one limit (`{}` means "no limits" and is how PATCH removes them) |

- Checked right after accepting, after `allow_from`, GeoIP and CrowdSec, before TLS and the PROXY header.
- Over a limit: TCP closes the accepted connection at once (sends nothing); UDP drops the datagram (no new session). Counted in `stats.limited` and logged as `conn.limited`: `{"event":"conn.limited","rule","client","reason":"max_connections\|source_connections\|new_connections\|packets","transport":"tcp\|udp"}` (thinned per source by `Throttle`; field names usable by the CrowdSec parser). `/metrics`: `rproxy_rule_limited_total{rule,reason}`.
- When more than `max_sources` sources are remembered, the oldest are forgotten (memory stays bounded).
- `PATCH` with `limits` replaces them as a whole (from the next connection / datagram; the counting state is kept). `{}` removes them.
- Left out: no limits, as today.

## 5. #166 Bandwidth limits and accounting

### 5.1 Bandwidth limits (a rule's `bandwidth`)

```yaml
bandwidth:
  upload: 100Mbps        # client → backend, whole rule
  download: 500Mbps      # backend → client, whole rule
  burst: 1MiB            # what may pass at once (default: 100 ms worth)
  per_source:
    upload: 2Mbps
    download: 10Mbps
    prefix_v4: 32
    prefix_v6: 64
    max_sources: 65536
```

- TCP (including `http` rules) is shaped by waiting (reads are delayed; nothing is dropped). UDP drops datagrams over the rate (`stats.dropped` and `rproxy_rule_bandwidth_dropped_total`).
- Rates are `"<number><bps|kbps|Mbps|Gbps>"` (8kbps-100Gbps); `burst` is `"<number><B|KiB|MiB|GiB>"` (1KiB-1GiB). At least one rate is required (`{}` is for PATCH to remove them).
- No per-route bandwidth in L7 yet (a middleware can add it later).
- `PATCH` replaces it as a whole (effective from the next read).

### 5.2 Counters for accounting

`stats` is lost on restart, so the UI polls and stores it in its DB. rproxy keeps it easy to take differences:

- A rule's `stats.rx_bytes`, `tx_bytes` and `total_connections` stay monotonic.
- New `stats.counters_since` (Unix seconds): when this count started. It changes when the rule is recreated and not on a #174 handoff (so the UI can tell a reset).
- `stats.limited` (#165) is added.
- `/metrics` gets `rproxy_process_start_time_seconds` (carried over from the old process on a handoff).
- rproxy does not know owners (tenants); `labels` mark them and the UI aggregates (traffic per rule, node and owner per hour, day and month is on the UI side together with UI #98).

## 6. #167 Control API hardening

These are control API settings, so they are CLI flags and environment variables as before.

| Flag / environment variable | Default | Meaning |
|---|---|---|
| `--tls-client-ca` / `RPROXY_TLS_CLIENT_CA` | none | CA (PEM) to verify client certificates; re-read on SIGHUP. Needs `--tls-cert` |
| `--tls-client-auth` / `RPROXY_TLS_CLIENT_AUTH` | `none` | `none`, `optional` (verified when presented), `required` (connections without a valid certificate fail the TLS handshake). `optional` / `required` need `--tls-client-ca` |
| `--token-warn-days` / `RPROXY_TOKEN_WARN_DAYS` | 14 | Report tokens whose `expires` is closer than this |
| `--api-lockout-failures` / `RPROXY_API_LOCKOUT_FAILURES` | 20 | Lock a source out once it fails authentication this many times within `window`; 0 turns it off |
| `--api-lockout-window` / `RPROXY_API_LOCKOUT_WINDOW` | `1m` | Counting period |
| `--api-lockout-duration` / `RPROXY_API_LOCKOUT_DURATION` | `5m` | How long a source stays locked out |

**Client certificates (mTLS)**: token file (YAML) entries get `client_cert`.

```yaml
tokens:
  - name: ui
    client_cert: ui.rproxy.internal      # the certificate's name (a DNS or URI SAN; the CN without SANs), exact match
    scopes: [rules:read, rules:write]
  - name: gateway-controller
    sha256: 9f86d0...
    client_cert: spiffe://cluster.local/ns/rproxy/sa/controller
    scopes: [rules:read, rules:write]
```

- One of `sha256` and `client_cert` is required. **With both, both are required** (the token and the certificate must both match). With `client_cert` only, the certificate alone is enough (no `Authorization` needed).
- A token file with `client_cert` while `--tls-client-auth` is `none` is a configuration error that stops the startup (unusable entries are not silently ignored).
- While `client_cert_auth` cannot run in this build, `--tls-client-auth optional / required` is a configuration error that stops the startup (ignoring it would leave the control API weaker than intended).
- The Unix socket is out of scope (protected by the socket file's permissions).
- The audit log (`event = "audit"`) gets `auth: "token" | "cert" | "token+cert"`.

**Token expiry**:

- At startup, on SIGHUP and once a day, tokens expiring within `--token-warn-days` are reported as `token.expiring` (`token`, `expires`, `days_left`) and expired ones as `token.expired` (warn), once per change of state.
- `/metrics`: `rproxy_token_expiry_timestamp_seconds{token}`.
- The rotation procedure (enable old and new together, SIGHUP, switch, remove the old one) is documented in docs/API.md.

**Locking out failing sources**:

- On the TCP control API, `401`s are counted per source IP (IPv6 grouped by /64); a source reaching `failures` within `window` is answered `429 locked_out` (with `Retry-After`) for `duration`, without looking at its token.
- `api.lockout` (`client`, `failures`, `until`) when locked, `api.unlock` when released. Refusals while locked are `event = "audit"`, `outcome = "locked_out"` (thinned by `Throttle`). `/metrics`: `rproxy_api_lockouts_total`, `rproxy_api_locked_sources`.
- At most 4096 sources are remembered (oldest forgotten first). The Unix socket is out of scope.

## 7. #168 GeoIP

```yaml
global:
  geoip:
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb   # a Country or City mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb           # optional
    check_interval: 1m     # how often to check the files for changes (default 1m; 0s: never; SIGHUP also re-reads)
    log_country: true      # add country (and asn) to conn.open, conn.denied and http.access (default false)
```

A rule's `geoip` (L4) and the `geoip` middleware (L7) have the same shape:

```yaml
geoip:
  allow_countries: [JP, US]
  deny_countries: []
  allow_asns: []
  deny_asns: [64496]
  unknown: allow           # not in the database, or private addresses (allow / deny, default allow)
```

- Decision: a match in any `deny_*` refuses. If any `allow_*` is given, only clients matching some `allow_*` pass. Clients matching neither, or unknown, get `unknown`.
- Countries are ISO 3166-1 alpha-2, two upper-case letters (region codes such as `EU` work if the database has them). ASNs are 1-4294967295. The same value in allow and deny is `invalid`. At least one list is required.
- `*_countries` needs `global.geoip.country_db`, `*_asns` needs `global.geoip.asn_db` (settings-file validation; `400 invalid` in the API).
- L4: checked right after accepting, after `allow_from`. UDP drops datagrams. Refusals count in `stats.denied`, and `conn.denied` carries `reason: "geoip"` and `country` (and `asn`).
- L7: checked against the client IP decided with `global.trusted_proxies`; refusals are `403` (as `ip_allow`).
- No database is bundled (people fetch GeoLite2 with their MaxMind account). Missing or broken files: at startup a configuration error (no such file) or `degraded` (permissions); while running, the previous database stays in use (`event = "degraded"`, `part: "geoip"`).

## 8. #169 Diff before change (plan / dry-run)

**Control API**:

- `POST /rules?dry_run=true`, `PATCH /rules/...?dry_run=true`, `DELETE /rules/...?dry_run=true`, `PUT /rulesets/{name}?dry_run=true`: validate and return the difference without changing anything (no bind, no name resolution; certificates and secret files are read to check them). Success is `200`:

```json
{
  "dry_run": true,
  "action": "update",
  "change": "in_place",
  "rule": "tcp/0.0.0.0:443",
  "before": {<rule view>},
  "after": {<rule shape>},
  "diff": [{"path": "targets", "before": [...], "after": [...]}],
  "warnings": []
}
```

  - `action`: `create`, `update`, `delete`, `none` (identical).
  - `change`: `none`, `in_place` (changed without dropping connections), `recreate` (listeners are rebuilt; current connections are dropped).
  - `diff`: JSON paths (joined with `.`; arrays as a whole) of what changed, with old and new values. Secrets are not part of the shape, so they never appear.
  - What validation refuses gets the same `400` (`invalid` etc.) as the real operation.
- `POST /config/reload?dry_run=true`: reads the settings file and answers what applying it would change (`{"dry_run": true, "added", "removed", "changed", "unchanged", "failed", "restart_needed", "changes": [{"rule", "action", "change", "diff"}], "warnings"}`). Scope and Unix-socket rules as `POST /config/reload`.
- `POST /config/plan`: compares the settings in the body (JSON in the settings file's shape: `version`, `global`, `rules`) with what is running (no file is read; used by `--check-config --diff`). Same answer shape. `admin`; by default only over the Unix socket (`RPROXY_API_RELOAD_UNIX_ONLY`).

**Settings file**: `rproxy-api --check-config [PATH] --diff`

| Flag / environment variable | Default | Meaning |
|---|---|---|
| `--diff` | | After validation passes, ask the running rproxy with `POST /config/plan` and print the difference |
| `--diff-api` / `RPROXY_DIFF_API` | `RPROXY_API_SOCKET` if set, else `http://<first RPROXY_API_ADDR>:<RPROXY_API_PORT>` (https with TLS) | Where to ask (`unix:/run/rproxy/api.sock` or a URL) |
| `--diff-token-file` / `RPROXY_DIFF_TOKEN_FILE` | none | File with the token (one plain line) to ask with |

- Output follows `--check-config-format` (`text`: one change per line; `json`: the `Report` plus `plan`).
- Exit code: 1 for validation errors or a failed query; 0 on success whether or not there are differences.
- When the running rproxy cannot be reached, the validation result and "no difference could be computed" are printed, with exit code 1.

## 9. #170 Passive health checks (outlier detection)

**L4** (a rule's `outlier_detection`; rules with several targets or a `health_check`):

```yaml
outlier_detection:
  consecutive_failures: 3     # connection failures in a row (default 1)
  short_lived: 0s             # connections the backend closes sooner than this also count as failures (default 0s: not counted)
  ejection_time: 10s          # first ejection (default 10s)
  max_ejection_time: 5m       # doubled on each ejection up to this (default = ejection_time: no doubling)
  max_ejected_percent: 100    # share of targets that may be ejected at once (default 100)
```

- The defaults reproduce today's behaviour (one connection failure skips the target for `FAIL_COOLDOWN`, 10 seconds). Today's `FAIL_COOLDOWN` becomes that default.
- `consecutive_failures` 1-1000, durations 1s-1h (`short_lived` 0s-1m), `max_ejection_time` ≥ `ejection_time`, `max_ejected_percent` 0-100.
- Ejection and return use the existing `target.down` / `target.up` with `reason: "outlier"` (health checks get `reason: "health_check"`). `stats.targets[]` gets `ejected_until` (Unix seconds, null when not ejected) and `ejections` (count).

**L7** (`http.services.<name>.outlier_detection`):

```yaml
outlier_detection:
  consecutive_5xx: 5               # 5xx answers in a row (0: ignored; default 5)
  consecutive_gateway_failures: 3  # 502, 503, 504, connection failures and timeouts in a row (default 3)
  failure_percent: 50              # share of failures in window (1-100; left out: ignored)
  min_requests: 20                 # fewest requests before the share counts (default 20)
  window: 30s
  ejection_time: 30s
  max_ejection_time: 5m
  max_ejected_percent: 50          # default 50: never all of them
```

- Separate from `circuit_breaker` (which stops the whole service): servers are ejected one by one. An ejected server shows `ejected` in the server state of `stats.http`.
- Logged as `target.down` / `target.up` (`reason: "outlier"`, `service`, `server`).

## 10. #174 Live upgrade and container self-update

### 10.1 Handoff

- Within one minor (X.Y), handing over to a new binary while running is guaranteed. Across minors or majors the handoff is refused (`handoff.refused`, reason `version`) and a restart is needed.
- Triggers: `SIGUSR2` to the old process, or `POST /admin/upgrade` (`admin`, by default only over the Unix socket). The old process starts the binary now on disk (the path `/proc/self/exe` pointed to) as a child and passes the listening sockets (rules' TCP and UDP, the control API's TCP and Unix sockets, HTTP/3 UDP) and state over the handoff Unix socket (`SCM_RIGHTS`).
- The new process builds its rules on the received sockets and tells the old one when ready (`/readyz` ready). The old process stops accepting (`/readyz` `draining`), waits for current connections to finish (`stop → drain → kill`) and exits. systemd is told the new main process with `sd_notify` `MAINPID=` (the unit needs `Type=notify`, `NotifyAccess=all`).
- State passed on: the rules' counter bases (`counters_since`, `rx_bytes`, ...; counters never go down), `rproxy_process_start_time_seconds`, the rule sets (#28) with their generations. ACME state is re-read from its files.
- UDP may blink (agreed with the owner): the listening sockets are passed on, but current sessions end with the old process. TCP and HTTP stay with the old process until they finish, so they are not cut.
- If the new process is not ready within `handoff_timeout`, the old process stops the child and keeps running (`handoff.failed`).

| Flag / environment variable | Default | Meaning |
|---|---|---|
| `--handoff-socket` / `RPROXY_HANDOFF_SOCKET` | `/run/rproxy/handoff.sock` | Handoff Unix socket (0600, rproxy's user only) |
| `--handoff-timeout` / `RPROXY_HANDOFF_TIMEOUT` | `30s` | How long to wait for the new process |
| `--handoff-drain` / `RPROXY_HANDOFF_DRAIN` | `5m` | Longest the old process waits for current connections (then cuts them) |

- Logs: `handoff.start`, `handoff.ready`, `handoff.done`, `handoff.failed`, `handoff.refused`. `/metrics`: `rproxy_build_info{version,sha256}`, `rproxy_handoffs_total{outcome}`.
- systemd: `systemctl reload` stays SIGHUP (re-reading settings and certificates), and the handoff is a separate SIGUSR2 (decided in 14.). The .deb `postinst` uses `systemctl kill -s USR2` when major.minor matches the previous version and restarts otherwise.
- Exceptional patches (fixes that cannot be handed over) are announced with `"handoff": false` in the release's `manifest.json` and in the release notes.

### 10.2 Container self-update

- The image's entry point is `rproxy-api launch` (the launcher). From a cache volume and the GitHub releases (a mirror can replace them) it picks the newest patch of the image's X.Y, **verifies its signature**, then execs it. When nothing can be fetched: the newest cached version, else the image's own.
- While running: every `RPROXY_UPDATE_INTERVAL`, or on `POST /admin/update`, a new patch is fetched, verified and swapped in with the handoff of 10.1.
- If the new version does not start or dies within `RPROXY_UPDATE_HEALTHY`, the previous one is restored (one previous version is kept in the cache) and the failed version is remembered as bad and never picked again.

| Environment variable (flags are the matching `--update-*`) | Default | Meaning |
|---|---|---|
| `RPROXY_UPDATE` | `off` (`auto` in the image) | `off`, `check` (fetch and verify; only report in logs and the API), `auto` (swap in). Stays off on VMs installed with apt (no double management with apt) |
| `RPROXY_UPDATE_PIN` | none | Pin a version (`0.4.3`); nothing outside X.Y |
| `RPROXY_UPDATE_SOURCE` | `https://github.com/max3584/rproxy-api/releases` | Where releases come from (a mirror; `https://` only) |
| `RPROXY_UPDATE_CACHE` | `/var/cache/rproxy/update` | Cache (a writable volume; the root file system may be read-only) |
| `RPROXY_UPDATE_INTERVAL` | `6h` | Check interval (`0s`: only at start and through the API) |
| `RPROXY_UPDATE_PUBKEY` | the release key built into the binary | minisign public key (a file) to verify with, for mirrors that re-sign |
| `RPROXY_UPDATE_HEALTHY` | `60s` | A new version that survives this long is marked good |

- Signatures are **minisign** (Ed25519; verification is a small pure-Rust implementation and needs no outside service, unlike cosign). The release workflow attaches a `.minisig` per binary `.tar.gz` (per bare binary in the implementation; 15.), plus `SHA256SUMS` and `manifest.json` (version, whether a handoff is possible, each file's hash) with their signatures. Nothing unverified is executed.
- API: `GET /admin/update` (`admin`) `{"mode","current":{"version","sha256"},"available":{"version","sha256"}|null,"last_check","error","bad_versions":[...]}`, `POST /admin/update` (`admin`, by default only over the Unix socket; checks now and swaps in under `auto`). The running binary's version and hash are also in `build` of `GET /capabilities` (`{"version","sha256"}`) and `rproxy_build_info`.
- On Kubernetes, updates replace replicas, so set `RPROXY_UPDATE=off` (the Helm chart's default).

## 11. #144 Storing API-created rules in the DB

- rproxy **writes only its own table, `rproxy_rules`**. The UI's tables (`forward_rules` / `forward_rules_log`) are never touched. The table definition and GRANT go into the UI repository's `db/` migrations (below is the proposal from the design; the implemented definition is in "Storing API-created rules" of docs/en/API.md):

```sql
CREATE TABLE rproxy_rules (
  node        VARCHAR(255) NOT NULL,   -- which rproxy the rule belongs to (RPROXY_NODE_NAME, default the host name)
  protocol    VARCHAR(3)   NOT NULL,
  listen_addr VARCHAR(45)  NOT NULL,
  listen_port INT UNSIGNED NOT NULL,
  spec        JSON         NOT NULL,   -- the shape of the POST /rules body (RuleRequest)
  spec_version INT UNSIGNED NOT NULL DEFAULT 1,
  created_by  VARCHAR(255) NOT NULL,   -- token name
  created_at  DATETIME(3)  NOT NULL,
  updated_by  VARCHAR(255) NOT NULL,
  updated_at  DATETIME(3)  NOT NULL,
  PRIMARY KEY (node, protocol, listen_addr, listen_port)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON rproxy.rproxy_rules TO 'rproxy'@'%';
```

- The rule is kept as JSON in `spec`, not split into columns (new settings need no new columns; `spec_version` says how to read it).
- Stored are the rules created, changed or deleted through the API with a token marked `persist: true`. **The default is not to store** (as in 0.3; only tokens that should store are marked, so the UI's token never stores twice). Tokens of the one-per-line format never store. Rules of sets (#28) are never stored.

```yaml
tokens:
  - name: ci-deploy
    sha256: 2c26b4...
    scopes: [rules:write]
    persist: true
```

- Written on every create, change and delete (before answering). If writing fails, the rule keeps running, the answer says `persisted: false`, and the log gets `event = "degraded"`, `part: "db"`. Without `RPROXY_DATABASE_URL` nothing is stored (`persisted: false`).
- At startup, rules are restored from both the UI's table and rproxy's (only rows of its own `node`). The same key in both: the UI's wins and `restore.conflict` is logged at warn.
- Display: stored rules have `origin: "api"`, `created_by`, `created_at`, `persisted`. Rules from the UI's DB and unstored API rules stay `origin: "dynamic"`. The UI treats unknown `origin` values like `dynamic` (UI issue).
- Flag / environment variable: `--node-name` / `RPROXY_NODE_NAME` (default the host name).

## 12. Performance settings (#194, #184)

Knobs that today are internal environment variables for experiments (`RPROXY_UDP_SHARDS`, `RPROXY_SPLICE*`) become `global.performance` in the settings file. **The settings file wins; without it, today's environment variables; without both, the defaults** (the environment variables stay). All of them take effect only after a restart (`restart_needed`).

```yaml
global:
  performance:
    workers: 8              # tokio worker threads (default: number of CPUs). Env RPROXY_WORKERS
    udp_shards: 1           # SO_REUSEPORT sockets per UDP port: 1-64 or auto (= workers). Default 1. RPROXY_UDP_SHARDS
    cpu_affinity: none      # none, auto (one worker per CPU), "0-3,6" (CPUs to use). RPROXY_CPU_AFFINITY
    busy_poll_usecs: 0      # SO_BUSY_POLL on data-plane sockets (microseconds); 0 = off (default); 0-1000. RPROXY_BUSY_POLL_USECS
    splice:                 # splice(2) for plain L4 TCP (#184)
      enabled: true         # RPROXY_SPLICE
      after: 0              # bytes relayed before switching to splice (number or "64KiB"). RPROXY_SPLICE_AFTER
      full_reads: 4         # switch after this many full 32 KiB reads in a row (0-64). RPROXY_SPLICE_FULL_READS
      pipe_size: 0          # pipe size (0: the kernel's; 4KiB-16MiB). RPROXY_SPLICE_PIPE_SIZE
```

- `features.performance` lists the keys that take effect from the settings file (empty in the shape PR). Keys not in the list are ignored with a `degraded` line (the environment variables keep working).
- `cpu_affinity` must list at least `workers` CPUs; CPUs that do not exist are `degraded` at startup (just not used).
- Adaptive behaviour (#194 comment: leave busy poll and add workers depending on queue depth) waits until load tests settle the thresholds; if those need settings, the next minor adds them. eBPF sockmap, kTLS, io_uring and XDP are not part of this (#184 comment).

## 13. Shared

### 13.1 Error codes (added)

| `code` | HTTP | Meaning |
|---|---|---|
| `owned` | 409 | The rule belongs to a set (`ruleset`) and cannot be changed alone |
| `precondition_failed` | 412 | The `If-Match` etag differs from the set's current one |
| `stale_generation` | 409 | The set's `generation` is older than the current one |
| `locked_out` | 429 | This source is locked out for a while after repeated authentication failures |

### 13.2 `features` of `GET /capabilities` (added in v0.4)

```json
"features": {
  "...v0.3 entries...": "...",
  "rulesets": true, "labels": true, "conditions": true, "readyz": true,
  "limits": true, "bandwidth": true, "geoip": true, "outlier_detection": true,
  "dry_run": true, "persistence": true,
  "client_cert_auth": true, "token_expiry": true, "api_lockout": true,
  "handoff": true, "self_update": true,
  "performance": ["workers", "udp_shards", "cpu_affinity", "busy_poll_usecs", "splice"]
}
```

The `geoip` middleware appears in `middlewares`, and the services' `outlier_detection` in `services`. The above are the v0.4.0 values (at the shape PR everything was false / `[]`; each implementation PR turned its items on).

### 13.3 DB `options`

The UI's `forward_rules.options` (JSON) also carries a rule's `limits`, `bandwidth`, `geoip`, `outlier_detection` and `labels` in the same shape (all optional). The UI forms come after rproxy's shape is settled (UI issue).

### 13.4 What `PATCH` can change

`limits`, `bandwidth`, `geoip`, `outlier_detection` and `labels` given to `PATCH` replace the current value as a whole (`{}` removes it; left out keeps it). None of them drops connections.

## 14. Decisions (2026-10-07, approved by the owner)

- The controller is a separate repository, `max3584/rproxy-gateway`, in Rust (kube-rs). Locally it sits in the same folder as rproxy-api and the UI so all three are managed together (`../rproxy-gateway`).
- Changing a single rule that belongs to a rule set is refused with `409 owned` (no `?force`; the controller would revert it anyway).
- #144 `persist` defaults to false (set it only on tokens that should store; the UI stores in its own DB, so no double storage).
- #144's `node` column matches the UI's `forward_rules.target` (node or group, UI #98).
- API-created rules have `origin: "api"`; the UI follows.
- #174: `systemctl reload` stays SIGHUP (reload settings and certificates); handoff is SIGUSR2 (used on package upgrades).
- #174 signatures use minisign (a key separate from apt's GPG key).
- #167 lockout is on by default (20 failures per minute → 5 minutes; the Unix socket is exempt).
- #166 UDP bandwidth limits drop what exceeds the rate.
- Rule-set names may contain `/` (Kubernetes `namespace/name`).

## 15. Deviations in the implementation

Where the implementation PRs departed from the design, or decided what the design left open. docs/en/API.md follows these.

- **#167 Control API hardening (#218)**
  - A 401 `reason` of `client_cert` was added (the token matched but the certificate bound to it is missing).
  - `api.lockout` also carries `duration_secs`.
  - The client CA is re-read on SIGHUP and also by the certificate file check (`RPROXY_CERT_CHECK_SECS`), like the control API certificate.
  - A successful authentication does not reset the failure count (it restarts when the window passes).
- **#165, #166 Limits and bandwidth (#219)**
  - Metric labels are `{protocol,listen,reason}` like the other metrics, not `{rule,reason}` as designed (`rproxy_rule_limited_total`, `rproxy_rule_bandwidth_dropped_total{protocol,listen}`).
  - HTTP/3 (QUIC) is not covered by `limits` or `bandwidth` (`limits` applies to TCP connections only; bandwidth is handled as TCP).
  - Rules with a bandwidth limit are never spliced (a `PATCH` adding a limit moves spliced connections back to a user-space copy).
- **#28 Rule sets, conditions, readiness (#220)**
  - `BackendsHealthy` on a rule that is not running is `status: "Unknown"`, reason `NotProgrammed` (False would read as "every backend down" while the state is unknown).
  - `ResolvedRefs` gained the reason `SecretUnreadable` (middleware secret files, separate from `CertificateUnreadable`).
  - `change` is `in_place` / `recreate` only for `update`; `create`, `delete` and `none` have `none`.
  - The answer to `PUT /rulesets/{name}?dry_run=true` is the rule set answer (`dry_run: true`, the would-be `etag`, `diff` on `update`), not `RulePlan`.
  - `DELETE /rulesets/{name}` also takes `If-Match`. `GET /rulesets/{name}` also shows `updated_at` and `updated_by`.
  - The `PUT /rulesets/{name}` body limit is 32 MiB (the API default of 2 MiB is too small for 10,000 rules).
- **#168 GeoIP, #170 passive health checks (#221)**
  - A connection failure's `target.down` changed from `reason: connect` to `reason: outlier` + `cause: connect` (also `refused`, `short_lived`). Health check `target.down` / `target.up` carry `reason: health_check`; the `target.up` when an ejection expires carries `reason: outlier`.
  - The L7 `cause` is the name of the crossed threshold (`consecutive_5xx`, `consecutive_gateway_failures`, `failure_percent`). Gateway failures also count toward consecutive 5xx (as in Envoy).
  - When an ejected destination fails again (all were ejected and it was tried), the ejection time restarts but the count does not grow. When every L7 server is ejected, servers that are up by health check are used.
  - A doubled ejection time goes back to the first value after `max_ejection_time` without an ejection.
  - GeoIP is checked in the order `allow_from` → `geoip` → `crowdsec` (`limits` after them).
- **#169 Diff before change, #144 storage (#222)**
  - The assignment of `change` values (as for #28 above) is written in docs/en/API.md.
  - What is stored: creation is decided by the token's `persist`, changes and deletions by the rule's `origin` (so a row never diverges when another token changes an `api` rule).
  - `--check-config --diff` trusts `RPROXY_TLS_CERT` when it asks over https (for a self-signed control API).
- **#174 Live upgrade, self-update (#223)**
  - Signatures are per release asset (the bare binary `rproxy-api-v<X.Y.Z>-<target>`), not per `.tar.gz` (releases have no `.tar.gz`).
  - Finding patches: every release attaches an index of all versions, `releases.json` (minisign-signed); self-update reads `<source>/latest/download/releases.json` and picks the newest of the same X.Y (no GitHub API; a mirror only needs the same paths).
  - `RPROXY_UPDATE_CA_FILE` (hidden environment variable): for mirrors with a private CA and for tests.
  - The handed-over state also includes the API rules (in the `GET /rules` shape, with #144's `created_by`, `created_at`, `persisted`), `stats.http`, and `counters_since` (kept from the old process), `limited` and bandwidth drops. What starts over in the new process (`limits` and `bandwidth` buckets and per-source counts, L7 `rate_limit` and similar state, ejected destinations) is in docs/en/UPGRADE.md.
  - The self-update binary is streamed into a temporary file in the cache and verified from the file (not held in memory; capped at 1 GiB).
  - During a handoff (and in the old process afterwards) change endpoints answer `503 upgrading`.

## 16. L7 and TLS for the rest of the Gateway API (#224, #226-#236)

Added to v0.4.0 by the owner's decision so that rproxy-gateway v0.4.0 can map every Gateway API feature (conformance extended features included); released together with rproxy-gateway v0.4.0. The shapes are in "L7 and TLS features for the Gateway API" of docs/en/API.md. Decisions:

- One module per feature: `l7/middleware/cors.rs` (#230), `l7/mirror.rs` (#232), `l7/deadline.rs` (#227), `l7/backend_tls.rs` (#236). HTTP/2 to backends (#233) lives in `l7/backend.rs` (connections) and `l7/server.rs` (sending); `targets` of `tls.routes` (#234) reuse `Pool` of `core/balance.rs`.
- Added to `features`: `cors`, `mirror` and `replace_host` in `middlewares`, `protocol` and `tls` in `services`, `http_options` (`headers_add`, `redirect_status`, `route_timeouts`, `server_middlewares`, `server_status`, `retry_status`), and `tls_route_targets`. The controller tells older rproxy builds apart by these.
- `add` of `headers` runs after `remove` and `set`, appending to an existing value with `,` (no space) as one field (what Envoy and the conformance tests expect).
- CORS is a separate `cors` middleware in the HTTPCORSFilter shape rather than an extension of `cors` in `headers` (`expose_headers`, wildcard origins and `*` with `allow_credentials` behave differently; `cors` of `headers` is unchanged). Preflights from origins not allowed go to the backend (as in Envoy).
- Route time limits are a route field, like the Gateway API's `timeouts` (not a middleware). `request` counts until the end of the response body; running out after the response headers ends the body with an error (the #134 rule: never look complete). `backend_request` is per attempt and replaces the service's `timeouts.response`.
- `attempts` of `retry` still counts the first attempt (the Gateway API's `attempts` counts retries, so the controller adds one). Only idempotent methods are still retried.
- The mirrored share is kept by count, not at random (spread by the golden ratio; the conformance share checks are stable). The body is copied as it streams; a mirror 64 frames behind is cut off alone (the main request never waits).
- HTTP/2 backends get one connection per server (h2 multiplexing). `auto` remembers the ALPN outcome per server. An Upgrade to an HTTP/2 backend gets 502 (no extended CONNECT).
- A service's `tls` is not merged field by field with the rule's `tls.upstream` (a BackendTLSPolicy is complete per service). `subject_alt_names` uses our own verifier for DNS names and URIs (SPIFFE); chain and validity are checked with rustls's webpki functions.
- Fixed-status servers (#235) are `status` instead of `url` in `servers[]` (not a separate kind of service, so the weight share works as it is).
- Fixes found by conformance (#238): a CORS preflight from an origin not allowed is answered by rproxy with 204 (no CORS headers) instead of going to the backend (which could allow it on its own; the Gateway API tests require it too). A `retry` attempt is picked again by `balance`, so it goes to the same server when there is only one (it always did; the conformance failure came not from rproxy but from the test cluster's Gateway API CRDs being the standard channel, which drops the experimental `retry`).
- `tls.client_auth.mode: optional_no_verify` (#238, the Gateway API's `AllowInsecureFallback`): asks for a certificate but accepts none or one that does not verify. Only possession of the key is checked in the handshake; the outcome goes to the backend to decide by `X-Client-Verify` (nginx's values), `X-Forwarded-Client-Cert` (Envoy's form), the access log and PROXY v2 `verify`. The headers are set only on rules with `client_auth`, and those the client sent are removed. `features.client_auth_modes`.
