日本語: [DESIGN-v0.4.x.md](../DESIGN-v0.4.x.md)

# v0.4.x design: shutting down on SIGTERM, the certificate API, persisting rule sets

> **Agreed design (2026-10-08, approved by the owner).** The rproxy-api part of the gaps found by the v0.4.0 acceptance tests (rproxy-gateway) and of #240 and #241. The rproxy-gateway and UI parts are in the designs of those repositories. Where the implementation departs from this is added to the last section, "6. Deviations in the implementation".

## 1. Approach

| Item | Decision |
|---|---|
| Versions | **There is no v0.5.0.** Everything ships as v0.4 patches (v0.4.1, v0.4.2, ...; "After v0.4.0" in docs/en/RELEASING.md). Additive shapes (settings, API, scopes, `features`, new DB tables) may ship in a patch; the next minor is kept for breaking changes |
| Process | One PR per item, with its shape and implementation together. A new flag is added to `features` in `GET /capabilities` and is true from the start (no shape-first PR with the flag false, unlike v0.4.0) |
| Compatibility | Everything added is optional, and leaving it out behaves as v0.4.0. **Existing setups (VM, .deb, containers) keep their behaviour** (the default of E is still "stop at once") |
| Live upgrades | Live upgrades (`handoff`) within a minor stay guaranteed. Handed-over state only grows (none of these items changes the handoff format) |
| Rolling back | Settings added by a newer patch (the token file's `allow_certs` and `certs:*` scopes, `RPROXY_SHUTDOWN_*`, `RPROXY_CERT_STORE`) may be an error for an older patch that does not know them (the token file rejects unknown fields). Remove them before rolling back to an older patch |

| Item | Version | `features` (`GET /capabilities`) | rproxy-gateway | UI |
|---|---|---|---|---|
| E. Shutting down on SIGTERM | v0.4.1 | `graceful_shutdown` | passes `5s` / `25s` to managed and fleet pods, readiness on `/readyz` | — |
| D1. #240 certificate API | v0.4.2 | `cert_store` | not used | no screen yet |
| D2. #241 persisting rule sets | v0.4.2 | `ruleset_persistence` | not used | migration 012, read-only view |
| G1. 421 Misdirected Request (7.1) | v0.4.3 | `misdirected` in `http_options` | the names of the HTTPS listeners on one port go to `tls.misdirected` (`GatewayHTTPSListenerDetectMisdirectedRequests`, v0.4.5) | — |
| G2. Per-server `cors`, redirects and `mirror` (7.2) | v0.4.3 | `server_middleware_kinds` | the `CORS`, `RequestRedirect` and `RequestMirror` filters on backendRefs (v0.4.5) | — |
| G3. External authorization (`forward_auth` extended, 7.3) | v0.4.3 | `forward_auth` | HTTPRoute's `ExternalAuth` filter (HTTP and gRPC, v0.4.5) | — |

## 2. E. Shutting down on SIGTERM (v0.4.1)

### 2.1 Today

The end of `src/main.rs` (after `wait_for_shutdown`): on SIGTERM, `/readyz` turns `draining`, the control API closes within 5 seconds, and `registry.shutdown()` stops every rule **at once** (cutting connections). Only a handoff (`handed`) waits for connections to end (`drain_all`, `RPROXY_HANDOFF_DRAIN`). So in Kubernetes the listeners vanish before the pod leaves the Service (EndpointSlice → kube-proxy, MetalLB, LB), and rollout restarts and node drains see failures.

### 2.2 Shape

| Flag / environment variable | Default | Meaning |
|---|---|---|
| `--shutdown-delay` / `RPROXY_SHUTDOWN_DELAY` | `0s` | After SIGTERM, keep accepting as before for this long while `/readyz` is `draining` (waiting for the load balancer or Service to drop the instance) |
| `--shutdown-drain` / `RPROXY_SHUTDOWN_DRAIN` | `0s` | Then close the listeners (no new connections) and wait this long for current connections to end. Cut what is left |

- Values are written like `RPROXY_HANDOFF_DRAIN` (`30s`, `2m`, or seconds). Each is at most one hour (more is a configuration error that stops the startup).
- **Both default to `0s`, the current "stop at once"** (owner's decision). `systemctl stop` / `restart` on VMs and .deb installs does not get slower. Choose the values with the flags or environment variables. rproxy-gateway passes `5s` / `25s` to its pods.
- Order: SIGTERM → `/readyz` 503 `draining`, `event=shutdown.start` → accept as before during `delay` → close the listeners (the `drain_all` path, as a handoff ends) → wait up to `drain` for TCP and HTTP connections to end → stop (cutting the rest). With both at `0s` this is exactly today's sequence.
- HTTP: once `drain` starts, responses to requests in flight get `Connection: close` (HTTP/2 GOAWAY) and the connection closes; idle keep-alive connections close at once (hyper's `graceful_shutdown`, as in a handoff). HTTP/3 takes no new QUIC connections; current ones go on.
- UDP: unchanged during `delay`. Once `drain` starts, no new sessions are created (their datagrams count as `stats.dropped`) and current sessions continue until `drain` ends (kube-proxy clears the UDP conntrack entries of a removed endpoint, so most move to the new pod).
- Control API: during `delay` and `drain`, read-only requests (`GET`), `/healthz` and `/metrics` keep answering (the UI can collect usage to the end). Changes (`POST`, `PUT`, `PATCH`, `DELETE`) get `503 shutting_down`. The control API closes just before the stop.
- A second SIGTERM or SIGINT (Ctrl-C): stop at once without waiting (as today).
- Logs: `shutdown.start` (`delay_secs`, `drain_secs`), `shutdown.drain` (when the listeners close; connections and sessions left), `shutdown.done` (connections cut, `cut`).
- Handoffs (SIGUSR2) are unchanged (`RPROXY_HANDOFF_DRAIN`). SIGTERM to the old process after a handoff is unchanged too (it cuts the wait short).
- `features.graceful_shutdown: true`.

### 2.3 With systemd (VM, .deb)

The .deb and `install.sh` defaults do not change (stop at once). To use it, set the values in `/etc/rproxy/rproxy.env`:

| In front of rproxy | `RPROXY_SHUTDOWN_DELAY` | `RPROXY_SHUTDOWN_DRAIN` |
|---|---|---|
| Nothing (clients connect directly) | `0s` | `10s` (HTTP requests finish; long TCP connections are cut after 10 seconds) |
| A load balancer that drops backends by health check (on `/readyz`) | health check interval × failures to drop + 1 second (e.g. `5s`) | `10s`–`25s` |
| A VIP such as keepalived (releasing the VIP on `/readyz`) | time for the VIP to move (e.g. `3s`) | `10s` |

- Keep `TimeoutStopSec` (systemd's default 90 seconds) above `delay + drain + 5 seconds` (past it, systemd stops the service with SIGKILL).
- `systemctl restart` gets slower by the same amount. To update the binary, a live upgrade (SIGUSR2; a .deb upgrade within one minor hands off) swaps it without waiting for `delay` / `drain` and without cutting connections.

### 2.4 Kubernetes (rproxy-gateway)

- Managed: `RPROXY_SHUTDOWN_DELAY=5s`, `RPROXY_SHUTDOWN_DRAIN=25s`, `terminationGracePeriodSeconds` of `delay + drain + 5` (35), readiness probe on `/readyz` (it drops out as soon as it is `draining`).
- Fleet: the same defaults as chart values. It runs on hostNetwork, so the gateway documentation says to pick `delay` to match how the external LB or VIP drops it.
- The controller does not PUT to a terminating pod (`deletionTimestamp` set), as today. If a change gets `503 shutting_down`, the next pod catches up.

### 2.5 Tests

Integration tests (`tests/shutdown.rs`): after SIGTERM, new connections still pass during `delay` and `/readyz` is 503; once `drain` starts new connections are refused and an existing TCP transfer completes; past `drain` connections are cut; a second SIGTERM stops at once; HTTP/1.1 keep-alive gets `Connection: close`; read-only API requests answer and changes get `503 shutting_down` during `delay`; with the defaults (`0s`, `0s`) it stops at once.

## 3. D1. #240 certificate API (v0.4.2)

### 3.1 Endpoints

| Method and path | Body | Success | Description |
|---|---|---|---|
| `PUT /certs/{name}` | `{"cert": "<PEM>", "key": "<PEM>", "chain": "<PEM>"?}` | 201 (new) / 200 (replaced) | Checks and stores: the PEM parses, the key matches the certificate, it has not expired (expired is `400 invalid`; within `--cert-warn-days` adds `warnings`). Accepts `If-Match` (the fingerprint; a mismatch is `412 precondition_failed`). Answers with the single-entry shape of `GET` |
| `GET /certs` | | 200 | `[{"name","sans","not_before","not_after","fingerprint_sha256","issuer","used_by":[<rule keys>],"updated_at","updated_by"}]`. Never returns the key |
| `GET /certs/{name}` | | 200 | One entry as above (`404 not_found` if missing) |
| `DELETE /certs/{name}` | | 204 | `409 in_use` (with `used_by` in the body) if any rule uses it (settings file, API or rule set) |

- Names: `[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?` (usable in a path as is; others are `400 invalid`). The body is at most 1 MiB.
- Keys travel over it, so **over TCP the control API accepts it only with TLS**: plain loopback and the Unix socket are allowed; a `PUT` over plain TCP from anywhere else is `403 tls_required`.
- `features.cert_store: true`. If the store is unusable (the directory cannot be created or written), the flag stays true and `PUT` answers `503 cert_store_unavailable`.

### 3.2 Using it from rules

- `{"cert": "<name>"}` in `tls.certificates[]` (instead of `cert_file`, `key_file`, `chain_file` or `acme`; exactly one). The same shape in the API, the settings file, the DB and rule sets. Not yet for `client_auth` or backend certificates (`services[].tls`).
- If the name is not in the store, creating or changing a rule through the API and a rule set PUT get `400 tls_config` (`certificate "<name>" is not in the certificate store`). Rules from the startup or a reload are `failed` (`conditions`: `ResolvedRefs: False`, `CertificateUnreadable`). When the name is `PUT` later, `failed` rules waiting for it are rebuilt.
- Replacing (a `PUT` of an existing name): rules using it switch to the new certificate without cutting connections (the certificate store's reload path; the `PUT` triggers it at once instead of waiting for `RPROXY_CERT_CHECK_SECS`).

### 3.3 Storage

- Location: `--cert-store` / `RPROXY_CERT_STORE` (default `/var/lib/rproxy/certs`, the .deb's `StateDirectory`). Not in the DB (no keys in the DB).
- Layout: `<store>/<name>/<first 16 hex digits of the fingerprint>/{tls.crt,tls.key,chain.crt}` written as temporary file → fsync → rename, then the symlink `<store>/<name>/current` is swapped by a temporary link and rename. The old version is removed after the swap. `updated_by` and `updated_at` are in `<name>/meta.json`.
- Ownership: rproxy writes the files itself, so they belong to `rproxy-api`. **Directories are 0700 and every file 0600** (the .deb's UI is in the `rproxy` group, so the group must not read them). `global.files.owner_check: strict` accepts them as they are. The store cannot be under `trusted_dirs` (a configuration error that stops the startup).
- Startup: the store directory is created if missing. If it cannot be created or written, that is `event=degraded` (`part: "cert_store"`) when `--cert-store` was given, and only an info log with the default (setups that do not use the certificate API get no new error lines).
- Live upgrades (#174): files, so nothing is handed over. With several rproxy instances (gate1 / gate2), the caller PUTs to each node.

### 3.4 Permissions and audit

- Scopes: `certs:read` (`GET`), `certs:write` (`PUT`, `DELETE`); `admin` allows everything.
- Tokens get `allow_certs` (a list of name prefixes, shaped like `allow_rulesets`). `PUT` / `DELETE` of a name outside it is `403 forbidden`.
- Using `{"cert": name}` in a rule needs `rules:write` and the name within `allow_certs` (so nobody impersonates with someone else's certificate). `GET /certs` returns only names within `allow_certs`.
- Audit: `event=audit`, `action: cert.put|cert.delete`, with the name and fingerprint only (no PEM or key in logs or error messages).
- **rproxy-gateway does not use it**: keys do not travel over the control API ("Shapes not chosen" in the gateway design). It keeps the Secret volume and certsync.

### 3.5 Tests

`tests/cert_api.rs`: PEM, key mismatch, expired, size, names, `allow_certs`, `409 in_use`, replacing switches to the new certificate without cutting connections, file modes (0600, 0700), works with `owner_check: strict`, an unwritable store, `403 tls_required` over plain TCP, no keys in the audit log.

## 4. D2. #241 persisting rule sets (v0.4.2)

- Marker: the token's `persist` decides (as #144; nothing is added to the `PUT` body). Rule sets PUT and DELETEd with a `persist: true` token are stored. Answers, `GET /rulesets` and `GET /rulesets/{name}` show `persisted` (for stored sets only). Controller tokens have no `persist`, so gateway rule sets stay in memory as before.
- Writing: before the `PUT` answers, upsert one row (not written if `generation` is below the stored one). `DELETE` removes the row. If the write fails, the set keeps running with `persisted: false` and `event=degraded` (`part: "db"`). `dry_run` writes nothing.
- Startup: restore the settings file → the UI's table → `rproxy_rules` → `rproxy_rule_sets`, in that order. A rule whose key was already taken is `failed` alone (`restore.conflict`); the rest of its set is applied (as a `PUT`). `/readyz` turns ready after the restore (as today). The owner, `generation` and `etag` are restored too. File checks on restore (`owner_check`, `trusted_dirs`) are the same as now.
- Table (`db/migrations/012_rproxy_rule_sets.sql` in the UI repository):

```sql
CREATE TABLE IF NOT EXISTS rproxy_rule_sets (
  node         VARCHAR(255) NOT NULL,     -- RPROXY_NODE_NAME (as in rproxy_rules)
  name         VARCHAR(253) NOT NULL,     -- the rule set's name
  generation   BIGINT UNSIGNED NOT NULL,
  etag         VARCHAR(64)  NOT NULL,
  owner        VARCHAR(255) NOT NULL,     -- the owning token's name (security review M3)
  rules        JSON         NOT NULL,     -- same shape as the PUT body's rules
  spec_version INT UNSIGNED NOT NULL DEFAULT 1,
  updated_by   VARCHAR(255) NOT NULL,
  updated_at   DATETIME(3)  NOT NULL,
  PRIMARY KEY (node, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON rproxy.rproxy_rule_sets TO 'rproxy'@'...';
-- GRANT SELECT ON rproxy.rproxy_rule_sets TO 'rproxy_ui'@'...';
```

- One row (JSON) per set: a rule set `PUT` is all-or-nothing, so one row write keeps it consistent. Size: a `PUT` body is up to 32 MiB; anything above MariaDB's default `max_allowed_packet` (16 MiB) cannot be written (`persisted: false`).
- Without the table (before migration 012), only `PUT`s with the persist marker get `persisted: false` and `degraded`. Startup reads nothing if the table is missing (existing setups' startup logs do not change).
- Not shared between nodes: `node` is the instance's own name and only its own rows are restored. With gate1 / gate2 the caller PUTs to both (a rule set `PUT` is idempotent). A shape where rproxy watches the DB would be a separate issue.
- `features.ruleset_persistence: true`.
- UI: reads `rproxy_rule_sets` only and shows stored sets to administrators (as with `rproxy_rules`).
- **rproxy-gateway does not use it**: the source of truth is etcd, and after an rproxy restart the controller waits for `/readyz` and PUTs again. Persisting would bring back rules of Gateways deleted while rproxy was down.
- Tests (with the same MariaDB setup as `tests/persist.rs`): store → restart → restored (`generation`, `etag`, owner), an older `generation` is not written, other nodes' rows are not restored, only conflicting rules are `failed`, sets from tokens without `persist` are not written.

## 5. Decisions (2026-10-08, approved by the owner)

| # | Decision |
|---|---|
| Versions | No v0.5.0; ship as v0.4 patches (E in v0.4.1, D1 and D2 in v0.4.2) |
| E defaults | The rproxy binary defaults to `delay 0s`, `drain 0s` (stop at once, as today). Opt in with flags or environment variables. rproxy-gateway uses `5s` / `25s` |
| #240 key mode | Every file 0600, directories 0700 (with the issue's 0640, the UI's process in the `rproxy` group could read the key) |
| #240 name limit | Tokens get `allow_certs` (name prefixes) |
| #241 persist marker | The token's `persist` (as #144; gateway tokens do not set it) |
| #241 across nodes | Not shared (per node; the caller PUTs to both) |

## 6. Deviations in the implementation

- **#241, conflicts on restore (approved by the owner, 2026-10-08)**: section 4 said "a rule whose key was already taken is `failed` alone", but the rule table holds one entry per key, so a second rule with the same key cannot be registered even as `failed`. Instead, a rule whose key or listen ports overlap a rule restored before is **left out of its set** with `restore.conflict` (a rule that cannot be applied for another reason, such as a refused file, gets `restore.skip`), and the rest of the set is applied. The set's `etag` then differs from the stored one; the `ruleset.restore` log line shows both the new `etag` and the `stored_etag`. The DB row is left as it is (the next `PUT` brings it in line).

## 7. The rest of the Gateway API (v0.4.3, rproxy-gateway v0.4.5)

The Gateway API features rproxy-gateway does not claim yet ("Not claimed" in rproxy-gateway's docs/en/CONFORMANCE.md) that need something in rproxy. All are optional and, left out, behave as v0.4.2 (requested by the owner, 2026-10-08). As in 16. of v0.4.0 (docs/en/DESIGN-v0.4.md), the Gateway API's shapes become general rproxy settings that the controller maps.

### 7.1 421 Misdirected Request (`tls.misdirected`)

- The problem: rproxy-gateway makes the HTTPS listeners of one port (different host names) one rule, and the certificate is chosen by SNI. Browsers send requests for other names in the certificate's SANs on the same HTTP/2 connection (connection coalescing, RFC 9113 §9.1.1), so they reach the routes of another listener than the one chosen by SNI. The Gateway API (the description of `Listener.hostname`, conformance test `HTTPRouteHTTPSListenerDetectMisdirectedRequests`) asks for 421 when the Host belongs to another listener, and 404 when it belongs to none.
- Shape: `tls.misdirected: {groups: [[pattern, ...], ...]}`. Patterns as in `tls.routes` (exact, `*.`, `**.`) plus `*`, which matches any name. A name belongs to the group of its closest pattern (the order of `tls::config::best_match`, `*` last). When the SNI and the Host are both in groups, and not the same one: 421. When either is in no group, or there is no SNI: nothing is checked (the routes choose).
- "Listeners" stay out of rproxy's vocabulary: rproxy knows no listeners, so it gets groups of names. The controller makes one group per listener (`*` for a listener without a host name).
- Where: `Conn::handle` in `server.rs`, before choosing a route. No route and no middleware runs (another listener's middlewares, authentication for one, do not run under this connection's name). The same for HTTP/1.1, HTTP/2 and HTTP/3 (421 is fine over HTTP/1.1 too).
- Validation: only rules with `http` and `tls.mode: terminate`; a pattern may appear once. `features`: `misdirected` in `http_options`.
- Tests: unit (the cases of the conformance test), `tests/gateway_l7.rs` (several `:authority` values on one HTTP/2 connection, HTTP/1.1).

### 7.2 Per-server `cors`, redirects and `mirror`

- The problem: the Gateway API's `filters` on a backendRef (applied only when sending to that backend) map to rproxy's `servers[].middlewares` (#229), but those allowed rewriting kinds only (`headers`, `replace_host`, path rewrites), so routes with `CORS`, `RequestRedirect` or `RequestMirror` filters on a backendRef were `UnsupportedValue`.
- Shape: `cors`, `redirect_scheme`, `redirect_regex` and `mirror` join the kinds `servers[].middlewares` may use (no new shape). `features.server_middleware_kinds` lists the allowed kinds (the controller tells older rproxies by it; `server_middlewares` in `http_options` stays as it was).
- `cors` and redirects already answer in `on_request` and add headers in `on_response`, so they run as they are in the per-server step of `forward` in `server.rs` (an answer is not retried).
- `mirror` needs the copy's body and the target service, so `forward` handles it. Once a server is picked, its middlewares run in order and a `mirror` copies the request as it is then (after the headers for the backend, `X-Forwarded-*` and the certificate's, so they are not added again when the copy is sent: `mirror::Copy.forwarded`). Of `retry` attempts, only the first that lands on a server with a `mirror` copies (once per request).
- The target service must be compiled first (`Service::compile_with`): services whose servers have a `mirror` are compiled after the others, and a `mirror` to a service whose servers have a `mirror` themselves is refused (copies are not copied, and the order is settled).
- Tests: `per_server_cors_redirects_and_mirrors` in `tests/gateway_l7.rs` (of two servers, one with CORS and a copy, the other a redirect; copies only for requests sent to that server, one `X-Forwarded-For`, the body's length, preflights, the refused shapes).

### 7.3 External authorization (`forward_auth` extended)

- The problem: the Gateway API's `ExternalAuth` filter (experimental, shaped after Envoy's ext_authz) asks, over HTTP, with the client's method, path (after the `http.path` prefix) and Host, lets only 200 through, copies every header of the answer when `allowedResponseHeaders` is empty and sends the body up to `forwardBody.maxSize`; over gRPC it uses Envoy's `envoy.service.auth.v3.Authorization/Check`. rproxy's `forward_auth` had the Traefik shape only (`GET` with `X-Forwarded-Uri`, 2xx lets through, only the headers listed are copied).
- Shape: no new middleware; `forward_auth` gets options (one place for authentication; the Traefik shape is unchanged): `service` and `path` (in Kubernetes the auth server is a list of pod IPs, more than `address`'s single URL; a service of the rule brings `balance`, `health_check` and BackendTLSPolicy's `tls` along), `client_request`, `allow_status`, `response_headers: ["*"]`, `forward_body: {max_size}`, `protocol: grpc`. `features.forward_auth` names the available options.
- Not copied with `["*"]`: headers describing the answer itself (hop-by-hop ones, `Host`, `Content-Length`, `Content-Type`, `Content-Encoding`, `Transfer-Encoding`, `Date`); copied, they would break the length or the type of the request body for the backend.
- `forward_body`: for larger bodies, the Gateway API's type description ("truncated to `maxSize`") and the filter's ("rejected with a 4xx") disagree; as Envoy's default (`allow_partial_message: false`), 413. The body read goes to the backend from memory too, as with `buffering`.
- gRPC: no protobuf code generator dependency; only the fields used are written by hand (`l7/middleware/ext_authz.rs`; unknown fields are skipped). HTTP/2 is the backend HTTP/2 of #233 (an `address` is h2c only; TLS through a `service` with `protocol: h2` and `tls`). An `ok_response.headers` entry without `append` replaces (Envoy's ext_authz rule). `response_headers_to_add` go on the client's response. gRPC errors (a `grpc-status` other than 0, an unreadable answer) are 403 (Envoy's default `status_on_error`); no connection and no answer in time are 502 and 504, as for HTTP `forward_auth`.
- Per server: `forward_auth` may be in `servers[].middlewares` (`ExternalAuth` on a backendRef). Services whose servers have a `forward_auth` with `service` are compiled later, as with the `mirror` of 7.2, and that service's servers may not send to other services themselves.
- Tests: unit (building and reading `ext_authz`, `copy_answer` with `["*"]`), `tests/ext_authz.rs` (Envoy's HTTP shape: method, path, Host, `Content-Length`, body, the headers picked, `["*"]`, 200 only, 413; gRPC with `address` and `service`, headers set and removed, headers added to the response, denials, gRPC errors; per server; the refused shapes).
- Safety: the auth server still gets the client certificate headers as rproxy saw them (#238). A gRPC `ok_response` cannot change or remove `Host` (the destination chosen by the route stays).

## 8. G. VIPs of a Kubernetes fleet and lost nodes (v0.4.3)

The rproxy-api part of two gaps found after rproxy-gateway v0.4.4 (fleet pods holding VIPs). The gateway side is in rproxy-gateway's docs/en/DESIGN-v0.4.x.md.

| Item | Shape | `features` | Default |
|---|---|---|---|
| Listening on a VIP not on the host yet | `listen_freebind: true` on a rule (`IP_FREEBIND` / `IPV6_FREEBIND`) | `listen_freebind` (Linux) | false (as before, an address not on the host fails to bind) |
| Giving up targets on a stopped node sooner | `connect_timeout` of an L4 `tcp` rule (`100ms`-`10m`) | `connect_timeout` | none (5 s when other targets can be tried, else the OS default) |

- `listen_freebind` is not automatic ("automatically for addresses not on the host" would silently take a mistyped address). It needs no privilege, so `IP_TRANSPARENT` (`CAP_NET_ADMIN`) is not used. It is a per-rule mark so that the controller can choose it per Gateway without re-creating the fleet's pods (a process-wide setting would need the DaemonSet rolled).
- `0.0.0.0` / `::` and a specific address on the same port: still refused with `409 already_exists` (no `SO_REUSEADDR`-like "the narrower one wins": where traffic goes would depend on which addresses are present, and the clash would be hidden). The error now names the other rule's set and why.
- `connect_timeout` changes in place by PATCH (from the next connection). `listen_freebind` cannot change (the sockets are opened again: re-created).
- Handoff and storage: only added to the rule's shape (in the `GET /rules` shape and `rproxy_rules.spec`; an older patch ignores the unknown key).
- Tests: `scripts/test-freebind.sh` (real path in network namespaces; CI's transparent job), `tests/listen.rs`, `tests/targets.rs` (a target that drops SYNs).

## 9. Receiving PROXY protocol (v0.4.13, #296)

Read the PROXY protocol v1 / v2 header a front end (a load balancer, another rproxy, a Kubernetes Gateway) sends, and use it as the real client's address. Until now `net::source` only wrote them.

| Item | Shape | `features` | Default |
|---|---|---|---|
| Receive PROXY headers | `proxy_protocol: {"from": [<CIDR>, ...], "required"?: bool}` of a `tcp` rule | `proxy_protocol_in` | none (as before, no header is read) |

- Whom to believe: `from` is matched against the TCP peer (the hop right in front), never the address in the header. `from` is required, cannot be empty, and `/0` is refused (no setting believes headers from just anyone). `required` defaults to `true`.
- A connection from outside `from` that starts like a header (the v2 signature, `PROXY `): **refused** (the open question of the issue). A misconfigured front end shows up, and its header does not reach the backend as data where a backend that believes headers would take a spoofed address. `conn.denied` with `reason: proxy_protocol_untrusted`. Other connections are as before.
- Waiting for the first bytes: rules where the client speaks first (TLS `sni` / `terminate`, `http`) wait for them, also from outside (rproxy reads them first anyway). Plain TCP and STARTTLS may have the server speak first, so they do not wait: only bytes already there when the connection is accepted (and, for plain TCP, once the backend is connected) are looked at, so connections from outside are not delayed; a late header can slip through there.
- Limits: 107 bytes for v1 (the spec). v2's length field could say 65535; the part after the 16 fixed bytes is capped at 4096 (addresses take at most 216 bytes (AF_UNIX); AWS's VPC endpoint id, GCP's PSC id, HAProxy's SSL TLVs and unique ids are all far smaller). The time limit is 5 s from the accept (not configurable; below the TLS handshake's 10 s, and front ends send the header right after connecting).
- Reading: look with `peek`, decide, then read exactly the header (nothing after it is read too early, so what follows (reading the ClientHello, splice, STARTTLS) is unchanged). A header arriving in pieces is waited for.
- TLVs are skipped (towards the backend rproxy writes what it saw itself). `LOCAL`, `UNKNOWN`, `AF_UNSPEC` and `AF_UNIX` keep the peer's address. `DGRAM` on a TCP connection is refused.
- Where the real client is used: `allow_from`, `geoip`, `crowdsec`, `limits`, `bandwidth`, the logs' `client`, `X-Forwarded-For` / `X-Real-IP` (and the `global.trusted_proxies` decision), `source_ip` towards the backend (`proxy_v1` / `proxy_v2` / `transparent`). The front end is the logs' `proxy_peer` (L4: the task-local `net::proxy_in::PROXY_PEER`; `http`: `Conn.proxy_peer`). The destination in a header towards the backend is still the address rproxy received the connection on.
- Order: from a front end in `from`, the header is read before `allow_from` and the rest (the earlier "`allow_from` before the PROXY header" now holds for rules without `proxy_protocol` and connections from outside `from`).
- A PATCH changes it in place (from the next connection); rule set PUTs and settings file reloads are `in_place` too. Handoff and storage: only added to the rule's shape. The database's `options` take the same shape.
- Not covered (later): PROXY v2 over UDP (a header per datagram; added in v0.4.16, 12.). HTTP/3's QUIC carries no header.
- Tests: unit (`net::proxy_in`: parsing, limits, pieces, timeouts, validation), `tests/proxy_protocol.rs` (`allow_from`, `limits`, `X-Forwarded-For` and the access log, PROXY v2 in and out, `LOCAL`, `required`, headers from outside, the shape and PATCH), the fuzz target `proxy_header_in`.

## 10. `source_ip` per `tls.routes[]` (v0.4.13, #297)

On one port's `terminate` rule (`http` rules included), pass the source differently to the L7 part (backends that take no PROXY header) and to names passed straight through (Kubernetes and the like, which want the client in PROXY v2).

| Item | Shape | `features` | Default |
|---|---|---|---|
| How a route passes the source | `tls.routes[].source_ip` (`proxy`, `proxy_v1`, `proxy_v2`) | `route_source_ip` | none (the rule's `source_ip`) |

- Routes that take it: those that reach the backend at L4 (`passthrough: true` routes of `terminate`, routes of `sni` rules; `tcp` and `udp`). The PROXY header goes in front of the client's bytes (the ClientHello), which is well defined only on connections passed through untouched. Routes rproxy terminates are `unsupported` (the issue's "the rule's first, later if needed").
- `transparent` cannot be chosen per route (`unsupported`): the `IP_TRANSPARENT` sockets, the policy routing and the return path from the backends are prepared per rule, and changing it per name would break the return path. `proxy_v1` on a `udp` route is `unsupported` as on the rule.
- A route with `proxy*` on a `transparent` rule: its backends are reached from rproxy's address (the route's value is used as it is; the rule's `transparent` is not kept with a PROXY header added).
- At run time: the route's `RouteTarget.source_ip` → `Target.source_ip`, `Runtime::source_ip_for` / `bind_as_for` (`relay_hello` and `connect` in `tcp.rs`, `session` in `udp.rs`). PATCH, rule set PUTs and reloads replace the routes (`install_routes`), so it is `in_place` (the rule's `source_ip` still re-creates the rule).
- On connections received with `proxy_protocol` (#296) the header's client is written (as with the rule's `source_ip`).
- Handoff and storage: only added to the rule's shape (`tls.routes[]`). The database's `options.tls` takes the same shape. The Traefik converter turns `proxyProtocol.version`s that differ between routers into route `source_ip`s (for routers that do not terminate).
- Tests: unit (validation in `tls::config`, round trip and `in_place` in `config::plan`), `tests/route_source_ip.rs`.

## 11. The write queue of API storage (v0.4.14, #303)

A process restarted right after kill -9 read `rproxy_rules` before the stopped process's write had committed: a row was there but its rule did not run (`stored_rules_survive_kills_with_mariadb` in CI). The fix (the owner's decision):

- Every database job goes through one queue, run in order by one worker that holds the one connection and the node's lock (`GET_LOCK`) (`config::persist::queue`). API calls queue their write and wait for its commit. Reads (startup, the check) go through the same queue, so nothing stale is read inside the process.
- Writes are transactions with a time limit (`max_statement_time` and `innodb_lock_wait_timeout` 3 seconds, `wait_timeout` 30 seconds with pings). A stopped process's write also ends within the limit, so the startup waits for the lock only that long (8 seconds) and then reads. No `KILL CONNECTION`. Without the lock it starts from what it can read and checks again once it has the lock.
- The periodic check (default 60 seconds), when the queue is empty, no API change is under way and the lock can be had without waiting: writes again what did not go through, then fixes only `origin: api` rules to match the rows. Otherwise it waits for the next round.
- A process with the same `node` name does not have the lock taken from it. When at startup a live connection (one that sends statements while it waits) keeps the lock, the startup logs `persist.duplicate_node` and stops (the owner's decision: names are unique; the new process of a live upgrade does not check). A process that started while the database could not be reached and finds out later answers its writes `persisted: false` and logs `persist.duplicate_node`.
- The check takes the rows over only rules whose row is known to be up to date (a write is recorded as under way before it is queued). It writes again without holding up API changes; its exclusive part only compares and applies. A delete that drains queues the row's deletion before the drain and does not hold the changes' shared lock while it drains (so the live upgrade's `release` is not held up; it waits 10 seconds at most anyway).
- The queue is behind a trait (`PersistQueue`); the only implementation now is in-process (no new dependency). An external queue (Redis or the like) can replace it without changing the callers.
- Rule sets (`rproxy_rule_sets`) are written through the same queue. The check only writes again sets that did not go through; it does not change running sets to match their rows (that needs the owner and generation rules).

### 11.1 The snapshot of a live upgrade, set rows, the duplicate name check (v0.4.15, #305, #306, #307)

- The live upgrade's snapshot (#305): before it takes the snapshot, the old process waits up to `FREEZE_WAIT` (10 seconds) for the API changes (creating, changing, deleting rules and rule sets: those holding the shared lock of `api::changing`) and the check's applying part to end, and takes the snapshot holding the changes' lock (`changes`) alone (`handoff::prepare`, `Store::freeze`). It holds the lock until `release` when the handoff happened, and lets go of it (`thaw`) when it did not (`handoff.refused` / `handoff.failed`). A change that does not end within the wait stops the handoff (`handoff.failed`; the old process keeps running and the change runs to its end and is written there; not the binary's fault, so the self-update does not mark the release bad). A change that gets the lock after the live upgrade started (it passed `guard` before) is refused with `503 upgrading` without changing anything. After a failed handoff such changes go on.
  Why nothing between the snapshot and `release` is lost:
  1. API changes: there are only changes that ended before the snapshot (in the snapshot; the row written, or if not, handed over from `Unwritten` in `persist_pending`) and changes refused without changing anything. No change runs in the old process only between the snapshot and `release`. A change past the old `RELEASE_WAIT` (in the old process only, `persisted: false`) no longer happens (`release` uses the frozen lock and does not wait).
  2. Writes queued before the snapshot: the old process's queue finishes them before `Release` (in order; `Release` is last). A write is recorded in `Unwritten` before it is queued, so one not done at the snapshot is in `persist_pending` and the new process writes the same content again (even if the old one went through first, nothing goes back). The new process cannot write until the lock is free, so the two processes' writes do not interleave.
  3. The check: its exclusive part (changing rules to match the rows) needs the lock, so it does not run between the snapshot and `release`. Writing again (without the lock) writes the running rules, which are the snapshot's. After `release` the queue is closed and it stops.
  4. A delete that drains: the row's deletion was queued before the drain (as in 2.). The rule is not in the snapshot.
  5. Changes that have nothing to do with storing (certificates, tokens, the settings file): as before, `guard` refuses new requests during the handoff. Static rules of the settings file are not in the snapshot; the new process reads the file. Without a database there is still a `Store` (it writes no rows), and it waits and holds changes off the same way. Only when the `Store` could not be made (a wrong `RPROXY_DATABASE_URL`, `degraded`) nothing is waited for, but changes that waited for their turn are refused all the same.
  The handoff state does not change (nothing is added).
  When the handoff does not happen (the wait before the snapshot runs out, another minor, the new process cannot be reached, a panic of the task), dropping `handoff::Running` on every way out clears the handoff mark, lets go of the lock and tells the self-update (`Upgrader::set_on_abort`). The self-update takes back the trial (`trial`) it wrote before `upgrader.start` when it is that version's (`end_trial`; the version never ran, so it is not marked bad either). The trial used to stay: the launcher could mark a version that never ran bad on an unrelated exit, and `promote` never made the running version good.
- Set rows (#306): a set's row content (`ruleset_row`) is read under the same `order` its row is queued under (`Store::save_set(registry, name, by)`, the same as `save_rule` for rules; after a PUT and when the check writes again). With two PUTs of the same `generation` at once, or the check writing again while a PUT runs, the write queued last has the content read last, so the SQL `>=` never lets older content win, and `persisted: true` means the row and the running set agree. `ruleset_row` reads under the sets' write lock (`rulesets.write`, which a PUT holds until it has set the new generation and etag), so one version's etag never goes with another version's rules.
- The duplicate name check (#307):
  - At startup the pings start right after the lock is taken (before the restore, `Store::spawn_keepalive`). A restore that takes longer than `LIVE_IDLE` (15 seconds) still looks live to another process (the pings used to start in `spawn_background` after the restore, and a second process started). The new process of a live upgrade cannot take the lock until the old one lets go, so it starts them after its restore as before (starting early would start counting `DUPLICATE_AFTER` early).
  - The heuristic (`Holder::liveness_since`) uses that `PROCESSLIST.TIME` starts again when a statement starts and when it ends. The same state with its `TIME` gone back, or a statement started after an idle look: live (a dead client sends no statements). "Running a statement at the first look, idle (for less than `LIVE_IDLE`) at the second" cannot be told (`Unsure`): on MySQL (no time limit for statements) a dead host's long statement that ended in between looks like this (it used to be taken for live and refused).
  - When it cannot tell, the startup is not refused: it waits `DUPLICATE_LOOK_AGAIN` (20 seconds) and looks again (`after_looks`). Meanwhile a live one pings, and a dead one stays idle or is dropped by `wait_timeout` (the lock comes free). Still undecided at the third look, it starts with `restore.wait`: when two processes overlap anyway, the later one does not take the lock, its writes answer `persisted: false` and `persist.duplicate_node` (`DUPLICATE_AFTER`) says so, so a warning was chosen over a refusal. The longest wait before a refusal is about 60 seconds (only when it cannot tell; about 40 seconds as before otherwise).

## 12. Receiving PROXY protocol v2 over UDP (v0.4.16, #312)

Keeps the client's address over UDP in a multi-hop setup (outer rproxy, inner rproxy, backend). The outer rule's `source_ip: proxy_v2` could already put a PROXY v2 (DGRAM) header in front of each datagram, but the inner rule could not read it.

| Item | Shape | `features` | Default |
|---|---|---|---|
| Receive PROXY headers over UDP | `proxy_protocol` of a `udp` rule (the shape of 9.) | `proxy_protocol_in_udp` | none (as before, no header is read) |

- The shape and meaning are TCP's (`from` required, not empty, no `/0`; `required` defaults to `true`). No new setting.
- Parsing: `net::proxy_in::parse_dgram`. Only v2 DGRAM (`0x12`, `0x22`), `LOCAL` and `AF_UNSPEC` (and an unspecified transport, AF_UNIX) are accepted; v1, STREAM and a header that does not end within the datagram are errors. The bounds are the TCP parser's (`V2_MAX_PAYLOAD`, 4096 bytes); it shares `parse_v2` with TCP's `parse`, only the transport check differs. The decision for one datagram (trusted peer or not, the header's client, how much to strip, why it is dropped) is the pure function `datagram`, which the `proxy_header_in` fuzz target runs too.
- Where it is read: in `l4::udp::serve`, where datagrams arrive (before `allow_from`). Datagrams from a front end go on to their session without the header (an offset into the receive batch's buffer; the one copy into the session's queue is the same as before). Reading DTLS / QUIC server names (`sniff`, `renamed`) and DTLS termination see datagrams without it.
- The session key: `Peer { from, local, named }` (the front end's address and port, the address it arrived at, the header's client). Replies go to `from` (the front end's socket) without a header. The outer rproxy has a backend socket per session, so on the inner rule the front end's ports are per client. When the client in the headers from the same front end port changes, that is another session (the previous one ends after `udp_idle_secs`; decided: front ends do not normally change the header of one socket, so a separate session is the simple way rather than starting over).
- Speed: rules without `proxy_protocol` do one relaxed load per batch of datagrams (`proxy_in::Slot`, like `limits`); nothing changes per datagram. `Peer`'s `Hash` mixes, without a header client, exactly what the (address, local) pair did. The header path is the trust check, the parse and the offset, with no allocation (`proxy_dgram` in `benches/parse.rs`: about 40-45 ns per datagram here; `l4_udp/roundtrip_1KiB_proxy_protocol` in `benches/dataplane.rs` is within the noise of the loopback round trip of `roundtrip_1KiB` without a header).
- Refusals: `stats.denied` and `conn.denied` (`warn`, `reason: proxy_protocol` / `proxy_protocol_untrusted`, `error`, `version` for the latter), thinned per front end by `Runtime.denied_log` like the other UDP refusals (UDP sources can be spoofed; the log must not flood).
- Where the header's client is used: `allow_from`, `geoip`, `crowdsec`, `limits` (datagrams and sessions), `bandwidth`, the logs' `client` (the front end is `proxy_peer`: `proxy_in::sync_with_peer` for a datagram's checks, `with_peer` for the session task), `source_ip` (`proxy_v2` writes the header's client, `transparent` binds as it) and the route's `source_ip` (#297).
- The DPDK path (`Bound::Dpdk`, the experimental `dpdk` feature): reads no header. It is refused on every path (`dpdk::proxy_protocol_refused`): create and re-create get `bind_failed` from `dpdk::claim`, a PATCH (and its dry run) the same error from `Registry::updated_spec`, and for rule set PUTs and settings file reloads `config::plan::in_place` is false, so the rule is re-created (and `failed` by `claim`). It is never changed in place with the DPDK path passing datagrams on with the header still in front (should one be there anyway, the DPDK path opens no new session, and its `conn.error` is thinned per source). Reading headers there is for later, with tests on real hardware.
- Not covered: HTTP/3 of `http` rules (quinn's UDP) reads no header, as before.
- PATCH, rule set PUTs and reloads are `in_place` (from the next batch of datagrams). Handoff and storage: the rule's shape as it is (UDP sessions are started over on a handoff anyway).
- Tests: unit (`parse_dgram`, `datagram` and `Slot` of `net::proxy_in`; round trip and `in_place` in `config::plan`; `dpdk_refuses_proxy_protocol_on_its_addresses` in `l4::dpdk`, with the `dpdk` feature in CI's `dpdk.yml`), `tests/proxy_protocol_udp.rs` (two rproxy hops, `allow_from`, `required`, headers from outside `from`, broken headers, per-source `limits`, QUIC `sni` with a route's `source_ip`, DTLS termination, adding and removing with PATCH, validation), the `proxy_header_in` fuzz target (DGRAM seeds), benchmarks.

## 13. Files rules from the API may name (v0.4.17, #319)

Security review (2026-10-23) high A, medium M2 and M3: a `rules:write` token could put any file rproxy can read in a rule's file fields (the owner check `net::files` lets rproxy's own files through). It could terminate TLS with a key of the certificate store or the ACME storage (getting around `allow_certs` and `acme:write`), and with another secret in `oidc.client_secret_file` (another rule's cookie secret, the CrowdSec key) have it sent to a token endpoint of its own, since the issuer is free.

| Item | Shape | `features` | Default |
|---|---|---|---|
| Limits on the files of API rules | no new setting. Error `code`s: `403 protected_file`, `403 file_not_allowed`, `409 secret_reuse` | `protected_files` | always (rules of the settings file as before) |

- Where: `control::rule_files::check` (`POST` / `PATCH /rules`, `PUT /rulesets/{name}`, dry runs too; after `acme_api::check_rule_scope`). The files come from `net::protected::refs`: `tls` and `http` as JSON, every `*_file` field (a new field is covered when its name ends in `_file`; a field naming a file under another name needs a change here).
- What is protected (`net::protected::current`): the certificate store (`tls::named::dir`, a tree), the ACME storage (a tree) and `Acme::protected_files` (the DNS providers' secrets, EAB, account keys outside `storage`; CA files are left out: a rule may use the same CA), the CrowdSec key (`Bouncer::key_file`), and the options' `RPROXY_TOKEN_FILE` and `RPROXY_TLS_KEY` (`set_process`; `main` sets them before `--check-config` too).
  - Decision: for secret files the file only, not its directory. The default `/etc/rproxy` holds the token file next to `users_file`s and certificates; refusing the directory would break setups in use.
- Comparison (`resolve`): opened with `O_PATH` (no read permission needed, a FIFO does not block) → the real path from `/proc/self/fd` and (device, inode). Trees by the real path's prefix (by components), files by inode (by path when they cannot be opened). A path that cannot be opened: the real path of the parent that exists plus the rest without `..` (so `<store>/<name>/current/tls.key` stored later is refused now). Not compared again when the file is read (`net::files::read`): the API passes only strings and cannot make links, so the target changes after the check only when the administrator changes the disk.
- Tokens with `allow_certs` name no file (`Principal::limited_to_stored_certs`): a key outside the store would still get around the name limit.
- OIDC (M2): `net::protected::secret_conflicts`. A client secret file is used only as the client secret of the same (issuer, client_id). It is compared with every running rule (`Registry::file_refs`; without the parts a PATCH replaces (`tls` / `http`) and the rules of the set a PUT replaces) and the other rules of the same change. Overlaps among existing rules alone are not the change's error.
- M4 (another rule's sessions passing when a cookie secret is shared): the AES-256-GCM associated data of the session and state cookies is now the cookie name, the issuer and the client_id (`oidc::Oidc::aad`). Current sessions become invalid once on the upgrade (accepted: accepting the old form would keep the hole open).
- Rules of the settings file: not refused (the host administrator's). `--check-config` turns the same judgement into warnings (`check.rs`). Rules restored from the database or stored rule sets and rules handed over by a live upgrade are not refused either (an earlier version accepted them; the checks apply at their next change).
- Tests: unit (`net::protected`: trees, files, links, `..`, hard links, paths not there yet, finding the fields, uses of client secrets; `oidc`: a cookie of another issuer or client does not open), `tests/cert_api.rs` (`rule_files_may_not_reach_the_store`: store files, links, `..`, certificates stored later, dry runs, PATCH, rule set PUT, a service's `ca_file`, the token file, other places are fine, `allow_certs`, settings file rules work), `tests/acme.rs` (`rules_may_not_name_acme_files`), `tests/crowdsec.rs` (`rules_may_not_name_the_key_file`), `tests/http_auth.rs` (`oidc_client_secrets_keep_to_one_use`), `tests/check_config.rs` (`files_the_api_may_not_name_are_warnings`).
- Added in review: kernel filesystems are refused (`/proc`, `/sys`, `/dev`, by the `statfs` type: `/proc/self/environ`'s environment, `/proc/self/fd/N`). Trees are compared by (device, inode) too (bind mounts). Restored rules get `rule.protected_file` from `Registry::warn_protected` (`restore_as`, restored rule sets, rule sets of a live upgrade). A PATCH is judged by the whole rule `Registry::updated_spec` makes. Checks and changes run one at a time under `rule_files::lock`. The files are looked at in `spawn_blocking`; `Registry::file_refs` only copies under the lock. The `409 secret_reuse` message tells nothing of other rules. Refusals of `PUT /rulesets` are audited. `RPROXY_DIFF_TOKEN_FILE` is protected too.
- Left for later: another token naming a key file of another tenant's rule (not a protected file) (a separate issue).
