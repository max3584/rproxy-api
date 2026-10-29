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

## 13. Normalising the path and Host before matching, identity headers, connection time limits (v0.4.17, #320)

High C and medium M1 of the vulnerability review (2026-10-23). `RequestInfo.path` was matched raw, so `/%61dmin`, `//admin` and `/x/../admin` passed `basic_auth`, `oidc`, `forward_auth` and `ip_allow` on `PathPrefix(`/admin`)` and went to a route without authentication. A Host with a trailing dot did not match either. Identity headers (X-Forwarded-User and so on) were removed only inside the authentication middlewares. HTTP connections had no time limit on hyper-util's `auto` detection, HTTP/2 idleness or request bodies.

| Item | Shape | `features` | Default |
|---|---|---|---|
| Path normalisation | none (always); `http.raw_path: true` turns it off | `path_normalize`, `raw_path` in `http_options` | **normalised** (the owner's decision changes the default; an exception to "left out, the same as the patch before") |
| Host normalisation | none (always) | `path_normalize` | matched lower-cased, without a trailing dot |
| Dropping identity headers | none (always) | `identity_headers` | on rules with authentication middlewares |
| Connection time limits | `global.http.timeouts` (`tls_handshake`, `first_byte`, `request_headers`, `idle`, `request_body_idle`, `http2_ping_interval`, `http2_ping_timeout`) | `http_timeouts` | `10s`, `10s`, `30s`, `180s`, `60s`, `60s`, `20s` |

- Path (`l7::normalize::path`): as Traefik v3's `sanitizePath`. Only percent-encoded unreserved characters (RFC 3986 2.3) are decoded; other escapes stay encoded with upper-case hex (`%2F` is never a separator. Traefik, in Go, resolves `..` on `URL.Path` with `%2F` decoded; rproxy resolves on the encoded path, so `/a%2F..%2Fadmin` stays one segment. Not adding separators is the safer side, so this one point differs), `.`, `..` and empty segments are resolved, above the root stops at `/` (decided: cut, not 400, as Go's `path.Clean` and RFC 3986's remove_dot_segments do), a trailing `/` stays when the path had one. A `%` without two hex digits is 400 (decided: Go's HTTP server answers 400 too). The query is untouched.
- Where: at the start of `Conn::handle` in `server.rs` (the one place HTTP/1.1, HTTP/2 and HTTP/3 all pass), `normalize_target` replaces the `Uri`. Matching, middlewares (`strip_prefix` and so on), `forward_auth` (`X-Forwarded-Uri`), `mirror`, the destination and the access log then all see the normalised path. Speed: a path already normal is scanned once and comes back `Cow::Borrowed` (no allocation, the `Uri` untouched). `path_normalize` in `benches/parse.rs`: on a development machine shared with other work, about 70 ns for a normal path and 750 ns to rebuild one (the same machine runs `matcher/route_table_7` in about 1 µs).
- `raw_path` (in a rule's `http`): replaces Traefik's `entryPoints.<name>.http.sanitizePath: false` (destinations with URLs embedded in the path, keeping `//`). Documented as unsafe with path-based authentication or `ip_allow`. Host normalisation and identity headers stay as they are with `raw_path`. The converter (`rproxy-traefik-convert`) turns `sanitizePath: false` into `raw_path: true` with a note.
- Host (`request_host`): port dropped, lower-cased, one trailing dot dropped; used by matching (`Host`, `HostRegexp`) and `tls.misdirected`. The `Host` and `X-Forwarded-Host` sent to the destination stay as the client sent them (decided: virtual hosting at the destination does not change; Traefik passes it as sent too).
- Identity headers (`Router.identity_headers`, built once in `Router::compile`): from every middleware in the rule's `http.middlewares` (also those only `servers[].middlewares` use), `basic_auth`'s `user_header`, `oidc`'s `IDENTITY_HEADERS`, `forward_auth`'s `response_headers`, and for `*` and gRPC `forward_auth` the usual names (oauth2-proxy, Authelia, Authentik). `Authorization`, `Proxy-Authorization`, `Cookie`, `Host` and names in any `forward_auth`'s `request_headers` are left out (removing them would break authentication). Removed at the start of `Conn::handle` (before ACME, `oidc` callbacks and matching) on every route; nothing happens when the list is empty.
- Connection time limits (`l7::timeouts`): `HttpGlobal.timeouts` (set by `main` from `global.http`; takes effect after a restart).
  - `handle_http` in `tcp.rs`: the TLS handshake uses `tls_handshake` (L4 `terminate` keeps its 10 seconds).
  - `serve` in `server.rs`: an `Activity` per connection (requests begun, in progress, when the last one ended). `service_fn` calls `begin`; the response body is wrapped in `Tracked`, which releases its `Busy` when it ends (is dropped) (only the response type changes; nothing is boxed again). `Activity::expired` watches `first_byte` (`Metered`'s rx still 0) and `request_headers` before the first request and `idle` (nothing in progress) always, then closes with `graceful_shutdown` and a one-second grace (`reason` of `conn.close`). Later HTTP/1.1 headers use hyper's `header_read_timeout` (= `request_headers`). HTTP/2 uses `keep_alive_interval` / `keep_alive_timeout` (PING; clients that answer PINGs are closed by `idle`).
  - Request bodies: `IdleBody` makes its timer only when a read has to wait (a GET without a body never does), stops it whenever a frame arrives, and ends the body with an error when `request_body_idle` passes while waiting (as `deadline::until`, never looking like a normal end). While the destination does not read (back pressure) nothing is read, so nothing is counted.
  - HTTP/3 (`h3.rs`): the QUIC handshake uses `tls_handshake`, request headers (`resolve_request`) `request_headers`, the body reading task's `recv_data` `request_body_idle` (then `stop_sending` and an error), and a connection without requests in progress gets GOAWAY after `idle` (waiting in `h3.accept()` keeps its state in the connection, so giving it up in `select!` is safe).
- Added after review:
  - `request_body_idle` does not apply once the response headers have been sent (`timeouts::Responded`, set after `handle` by `serve` and by `request` in `h3.rs`) nor to `content-type: application/grpc…` requests (`is_grpc`), so gRPC bidirectional streams that go quiet after a first message (etcd Watch, xDS) are not cut by default (GRPCRoute).
  - Identity headers are no longer exempted by a `forward_auth`'s `request_headers` (they are removed once, before any middleware, so a value `oidc` set still reaches a later `forward_auth`; the exemption let a client forge that name on the whole rule). Only `Authorization`, `Proxy-Authorization`, `Cookie` and `Host` are kept. Authentik's `X-Authentik-*` and oauth2-proxy's `X-Auth-Request-Access-Token` were added; names equal to one after reading `_` as `-` go too (CGI, WSGI). Values of the same names from a trusted authentication proxy in front go too (documented).
  - The bypasses left to how destinations read paths (`..;/`, `\`, `%5C`, destinations decoding `%2F`, double decoding) are documented, and `http.strict_path` (off by default) answers 400 to paths with `%2F`, `%5C`, `%3B`, `%25`, `;` or `\` (`normalize::risky`, `strict_path` in `features.http_options`; done here rather than as a follow-up).
  - Closing for a limit lets requests in progress finish (`Activity::in_progress`; one second without any).
  - `raw_path` in the access log (the path as sent, only when normalisation changed it, so detection rules still see `../`).
- Tests: unit (`l7::normalize`, `l7::timeouts`, `global.http` in `config`), `tests/path_normalize.rs` (`/%61dmin`, `//admin`, `/x/../admin`, `/admin/.` and more, and a Host with a trailing dot, over HTTP/1.1, HTTP/2 and HTTP/3; the path the destination gets; 400; `raw_path`; identity headers on a route without authentication; connections sending nothing, slowloris, only the HTTP/2 preface; HTTP/2 idleness; a slow upload that passes and a body that stops), `tests/http_semantics.rs` (path and query at the destination), the `path_normalize` benchmark.

## 14. Files rules from the API may name (v0.4.17, #319)

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
- Added in review: kernel filesystems are refused (`/proc`, `/sys`, `/dev`, by the `statfs` type: `/proc/self/environ`'s environment, `/proc/self/fd/N`). Trees are compared by (device, inode) too (bind mounts). Restored rules get `rule.protected_file` from `Registry::warn_protected` (`restore_as`, restored rule sets, rule sets of a live upgrade). A PATCH is judged by the whole rule `Registry::updated_spec` makes. Checks run one at a time (`CHECKS`), and the files of a change that passed count for later checks as an `Intent` until it is made (nobody waits while a change resolves names; a change without files takes nothing). `net::files::read` also refuses an opened fd on a kernel filesystem (a later re-read cannot be led to `/proc`). The files are looked at in `spawn_blocking`; `Registry::file_refs` only copies under the lock. The `409 secret_reuse` message tells nothing of other rules. Refusals of `PUT /rulesets` are audited. `RPROXY_DIFF_TOKEN_FILE` is protected too.
- Left for later: another token naming a key file of another tenant's rule (not a protected file) (#323, done in 15.).

## 15. Key and secret files of other owners, restored rules that do not validate (v0.4.18, #323, #327)

| Item | Shape | `features` | Default |
|---|---|---|---|
| Key and secret files of other owners (#323) | No new setting. Error `code`: `409 file_in_use` | `file_owners` | Always (`admin` tokens and rules of the settings file as before) |
| Restored rules that do not validate (#327) | `state: failed` and `error` in `GET /rules` (the shape of any failed rule), `Accepted` `False` (`Invalid`) in `conditions` | `invalid_restored` | Always (only logged before) |

- The owner in #323 (`net::protected::Owner`, `Registry::owner_of`): `Static` for rules of the settings file, the set's owner for rules of a set (`Rulesets::owner`), the token that created a rule through the API (`Registry.owners`, set by `create_by`, dropped by `take`; for an `api` rule not there, `persist::Store::created_by`), else `Restored` (rules from `forward_rules`; no token's). A PATCH does not change the owner (it stays the creating token).
- What is compared: `FileRef::is_secret` (fields ending in `key_file` or `secret_file`, and `users_file`). Certificates, chains and CAs are public and not compared (so everyone may use `ca-certificates.crt`). The same file by `Resolved::same` (the inode; the path when it cannot be opened).
- Where: `rule_files::check`'s `judge` → `owners`, after the protected files and before `secret_conflicts`. Skipped for the `admin` scope (`Principal::has(Admin)`, and without a token file). The `Intent`s in `PENDING` carry the change's token too.
- Decided: a PATCH or a rule set's PUT does not compare the files the rules it replaces name now (the rules `Replacing` leaves out), so a PATCH of the targets is not refused for a share from before (the ports restriction is the rule's boundary; only adding a file widens the reach).
- The error says nothing of the other rule (key, owner, field). Shares created by an earlier version are not refused; `Registry::warn_shared_files` (after `restore_as`, restoring rule sets, a live upgrade) logs `rule.shared_file` once per pair.
- Live upgrade: `owners` in the state (added only). After a restart `dynamic` rules have no owner (`forward_rules` has no column for it).
- #327: `Registry.invalid` (key → `Invalid { request, origin, error }`). Not an `Entry` (there is no `RuleSpec`; the users of `Entry::spec` stay as they are; no listener, no port). `list` and `get` show them with `RuleView::invalid` (made from the body); `create_spec` and `check_start` refuse the key with `409 already_exists` (`refuse_invalid_key`); `take` (`DELETE`) only removes it; `update` (`PATCH`) puts the PATCH over the body with `rule::patched_request` and calls `fix_invalid` (still invalid: nothing changes; valid: `create_spec_in(.., fixing)` drops it when it puts the rule in the table). `insert_failed` makes the key the failed rule's.
- Paths in: a validation error in `restore_as` → `note_invalid` (only logged when `listen_addr` does not read; `rule.duplicate` when the key is taken). The periodic check tries an `api` row again once it changed (`forget_invalid`) and drops one whose row is gone. A live upgrade hands over `invalid_rules` in the state (the bodies as stored, added only), validated again by `restore_as` in the new process (not in `rules`: made back from the view, fields filled with defaults would change).
- Added in review: the files of rules that did not validate are in `Registry::file_refs` too (owner by `owner_of_key`; kept by a PATCH that fixes it, from any token allowed to PATCH the rule, as for a running rule). Deleting one, its row gone or changed, or a rule set taking its key: `drop_invalid` forgets the owner too, and `forget_invalid` clears the periodic check's `Store.invalid` (the same row coming back is shown again). The owner is recorded by `create_spec_in` as the rule goes into the table (concurrent creates by one token are not refused). A restored rule set's rule with the same key: the rule is put aside while the set is applied (`stash_invalid`); only those whose keys the set took are dropped with `restore.conflict` (forgetting the owner and the row's `created_by`), the others come back (`settle_invalid`). Planning a rule set's `PUT` refuses keys of rules that did not validate up front, as for any rule outside the set. Counted as `failed` and `rproxy_rule_up 0` in `/metrics`.
- Tests: `tests/cert_api.rs` (`key_files_keep_to_their_owner`), `tests/persist.rs` (`invalid_rules_keep_their_files_and_count` and `rows_that_do_not_validate_are_failed_rules` with the memory store, `rows_that_do_not_validate_with_mariadb` with the real binary and MariaDB), `tests/handoff_freeze.rs` (`invalid_rules_and_owners_carry_over`).

## 16. The global settings API (v0.4.19, #342)

| Item | Shape | `features` | Default |
|---|---|---|---|
| `GET` / `PATCH /config/global` | `admin`. The body has the shape of the settings file's `global`, `null` clears. Error `code`s: `409 static`, `restart_only`, `in_use`, `403 protected_file`, `502 crowdsec_unavailable`, `503 not_loaded`. Table `rproxy_global` (the UI's migration 013). `RPROXY_API_ACCESS_LOG_DIR` | `global_api` | With nothing set through the API, as before (file, environment, defaults) |

- Owner's decision: items written in the file (and the environment) are the file's. The API sets only the items left out.
- Owner of the state: `config::global::Settings` (`Registry::global`). The file's items (`Values::of_file`; whether an item is written is read from `ConfigDoc::global_raw`, so `trusted_proxies: []` counts), the environment's (whether `RPROXY_UDP_MAX_SESSIONS` was given: `main` looks at clap's `value_source`), the API's values (also those not in force, `failed`), what was stored that this release does not read (`kept`), the values in force (`Live`) and where they come from. Per item: file → environment → API → default.
- Swapping: the `Snapshot` in `HttpGlobal` (`trusted_proxies`, where access log lines go, the CrowdSec bouncer, `timeouts`) is replaced as a whole in one step (`HttpGlobal::update`). `Conn::handle` in `server.rs` takes one snapshot at the start of a request and uses it for the `Forwarded` check, `client_ip` and the access log (`Logged`). `timeouts` is read when a connection starts. UDP: `udp::set_max_sessions`.
- Building and swapping: everything is built first (files opened, a new bouncer started and its first pull awaited up to `BOUNCER_SYNC_WAIT`, 10 seconds); the swap runs inside `Registry::under_rules_lock`, where what the rules use of CrowdSec is read. Creating or changing a rule checks `crowdsec_gate` again right before the table takes it (`start`, `apply`, under the rules lock), so a change removing `crowdsec` and a rule using it never cross (review M3; `clearing_crowdsec_never_crosses_a_rule_that_needs_it` in `tests/global_api.rs`). A bouncer that does not get its first pull is not swapped in; the old one stays (API: `502`; reload: `config.global_kept`). The old bouncer is stopped after the swap (a `NewBouncer` not taken stops when dropped). Restores (database, handoff) do not wait (as the file's `crowdsec` at the start).
- Start-only items (`acme`, `geoip`, `performance`, `files`, the control API's listener) are only shown. `acme` and `geoip` follow in #345 (large, deferred). `files` (the owner check) is meant to stay out of the API so it cannot be weakened through it.
- Secret- and trust-related items (`Item::unix_only`: `trusted_proxies`, `access_log`, `crowdsec`, later `acme`): only over the Unix socket under `RPROXY_API_RELOAD_UNIX_ONLY` (dry runs too; refusals are audited). Paths are absolute and go through `net::protected::protecting` (rproxy's secrets, stores, kernel filesystems). An access log can write any file (e.g. request data into `/etc/profile.d`) and tracing-appender's pruning deletes files starting with its name (review M1), so only files right in `RPROXY_API_ACCESS_LOG_DIR` (default: the directory of `RPROXY_LOG_FILE`), not links, whose name does not overlap rproxy's log (`State::access_log_allowed`). Restored values get the same checks. A key file set through the API is in `protected::current` too.
- Reload: `ConfigReloader::reload` runs `Settings::prepare_file` (build) → `Registry::validate_static` (rules) → `commit_file` (swap) → `reload_static`. A rule's mistake or a live item's changes nothing (review M5). A `crowdsec` (or `appsec_url` with `appsec` rules) that rules use and the file drops stays (`kept_crowdsec`, `kept` in `GET`; kept over other PATCHes, handed over; removed by the swap after no rule uses it). An access log that cannot be written goes to the main log (`access_log_fallback`) and `retry_access_log` runs on every `reload`. `restart_needed` lists only start-only items (before, live items were listed too). `plan_config` gets `global_changes`.
- Storage: `persist::Store::save_global` (reads the values under `order` and queues them; `Unwritten.global`, `latest_global`, the handoff's `Pending.global`). The row is read item by item (`Values::read_stored`); values that do not read and unknown items go to `kept` and are written back (`GLOBAL_SPEC_VERSION` is `rproxy_global`'s own; a newer release's row is read for the items this one knows). The check only writes it again (only rproxy writes the row, so the row never wins). At the start, after `forward_rules` is read and before the rules are restored: `load_global` → `Settings::restore`. If it cannot be read: `set_not_loaded`; `PATCH` answers `503 not_loaded` and `stored` is None, so nothing is written (a write would destroy the stored values, review M4); the check reads it first.
- Handoff: the state's `global` (added only; `Handoff`: the values in the stored shape (unknown items too), who, when, `persisted`, `not_loaded`, `kept_crowdsec`) is restored by `State::restore_rules` before the rules. A handoff to a release before v0.4.19 does not carry it (the DB row stays).
- Tests: `tests/global_api.rs` (the race, a reload refused leaving global as it was, a PATCH while not loaded, a bouncer without its first pull, `appsec` on reload, `global` in the second file of a `conf.d`), `tests/persist.rs` (`global_values_survive_a_restart_with_mariadb`), the unit tests of `src/config/global.rs` (where access logs may be, reading item by item).
