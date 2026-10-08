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
- HTTP: once `drain` starts, keep-alive connections get `Connection: close` (HTTP/2 GOAWAY, HTTP/3 the QUIC GOAWAY) and close after their current request (hyper's `graceful_shutdown`, as in a handoff).
- UDP: unchanged during `delay`. Once `drain` starts, no new sessions are created and current sessions continue until `drain` ends (kube-proxy clears the UDP conntrack entries of a removed endpoint, so most move to the new pod).
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

(Added by the implementation PRs.)
