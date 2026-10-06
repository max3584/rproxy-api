日本語: [API.md](../API.md)

# rproxy-api Control API

The contract between the UI (TCP-UDP-rproxy-ui) and rproxy-api. When changing either side, update this file as well.

## Basics

- HTTP/1.1, JSON (UTF-8). Only `GET /metrics` uses the Prometheus text format.
- The listen address is set with `--api-addr` (can be given multiple times). The port is set with `--api-port` (default 8080; `0` disables TCP).
- It can also listen on a Unix socket (`--api-socket`, `--api-socket-mode`, `--api-socket-group`). The protocol is the same HTTP/1.1 as over TCP, and a token is required in the same way.
- Authentication: if `--token-file` is given, every endpoint except `/healthz` requires `Authorization: Bearer <token>`.
  - The token file can be written in two ways.
    - One token per line (all permissions; named `token-1`, `token-2`, ... in logs). Empty lines and lines starting with `#` are ignored.
    - YAML, listing a name, SHA-256 and scopes under `tokens:` (the token itself is not stored in the file).

      ```yaml
      tokens:
        - name: ui
          sha256: 9f86d081...        # printf %s "$TOKEN" | sha256sum
          scopes: [rules:read, rules:write, metrics:read]
        - name: ci-deploy
          sha256: 2c26b46b...
          scopes: [rules:write]
          allow_listen_ports: 20000-29999   # listen ports it may create, modify and delete (range rules must fit entirely)
          expires: 2027-03-31               # valid until this date (UTC)
      ```

    - Scopes: `rules:read` (`GET /rules`, `/interfaces`), `rules:write` (`POST` / `PATCH` / `DELETE /rules`), `metrics:read` (`GET /metrics`), `acme:write` (creating and changing rules with ACME certificates, and `POST /acme/...`; docs/en/ACME.md), `admin` (everything). `GET /capabilities` can be read with any token. Insufficient scope gives `403 forbidden`.
    - Creating, modifying and deleting rules is recorded in `event: "audit"` logs (`token`, `client`, `action`, `rule`, `outcome` (`ok` / `error` / `forbidden`), and `code` on failure). `client` is the sender's IP (`unix` over the Unix socket).
    - Refused requests are recorded in `event: "audit"` too (with `client`, `method` and `path`; the token itself is never logged): a missing, unknown or expired token (401) as `outcome: "unauthorized"` with `reason` (`missing` / `invalid` / `expired`), a missing scope (403) as `outcome: "forbidden"` with `token` and `scope`. So that the log does not overflow, refused requests are logged up to 20 lines in a row per sender, then one line a second. `suppressed` in a line is the number of lines left out for that sender before it (the total is `rproxy_log_suppressed_total` in `/metrics`).
  - Multiple tokens can be valid at the same time. To rotate, list both the old and new ones, then remove the old one later.
  - On SIGHUP the token file is reloaded.
- If `--api-addr` includes a non-loopback address, `--token-file`, `--tls-cert` and `--tls-key` are all required. If any is missing, startup is refused.

## Rules

A rule is uniquely identified by the tuple `(protocol, listen_addr, listen_port)`.

```json
{
  "protocol": "tcp",
  "listen_addr": "0.0.0.0",
  "listen_port": 8888,
  "remote_addr": "example.com",
  "remote_port": 80,
  "source_ip": "proxy",
  "udp_idle_secs": 30
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `protocol` | `"tcp"` \| `"udp"` | ✓ | Case-insensitive. Always returned in lowercase in responses |
| `listen_addr` | string | ✓ | IP address (host names are not allowed) |
| `extra_listen_addrs` | string[] | | Additional IP addresses to listen on with the same port (range) (up to 16; e.g. `listen_addr` is the main IPv4 and this holds a GUA IPv6). The rule key stays `listen_addr`. Stats and logs are aggregated as one rule; the `listen` of `conn.open` shows the address that received the connection. IPv6 listeners of a rule with additional addresses are opened with `IPV6_V6ONLY`, so `0.0.0.0` and `::` can be listed together (a rule with only `::` keeps the OS default: on Linux the default also accepts IPv4). Overlap with other rules and the control API is checked including the additional addresses (`409 already_exists` / `reserved`). With `transparent`, if there is no destination (written as an IP) of an additional address's family, the result is `invalid`; IPv6 addresses need `transparent_ipv6`. QUIC for `http3` is also accepted on all addresses. Omitted from listings when empty. The source of UDP replies is the destination address the client sent to, even when listening on `0.0.0.0` / `::`, so there is no need to list addresses just to pin the reply source on a host with multiple addresses (since v0.3.10) |
| `listen_port` | 1–65535 | ✓ | |
| `remote_addr` | string | ✓ | IP address or host name. Host names are re-resolved every 30 seconds. Not written for `http` rules (destinations are in `http.services`; listings show `""` / `0`). Also not written when `targets` is used (listings show the first entry of `targets`) |
| `remote_port` | 1–65535 | ✓ | Not written for `http` rules or rules using `targets` |
| `targets` | array of objects | | Multiple destinations (v0.3.3; instead of `remote_addr` / `remote_port`, use one or the other). `{"addr", "port", "weight"?, "backup"?}`: `addr` is an IP or host name (each re-resolved), `weight` is 1 or more (default 1), `backup: true` is used only when all other destinations are down (not all can be backup). Up to 64 entries. With a port range, each destination's `port` is also shifted across the range. See "Multiple destinations" below |
| `balance` | `"round_robin"` \| `"least_conn"` \| `"failover"` | | How `targets` are balanced. Default `round_robin`. Shown in listings only when `targets` is present |
| `health_check` | object | | Checks destination liveness with a TCP connect (v0.3.3). `{"interval"?, "timeout"?, "port"?}`: `interval` default `10s`, `timeout` default `3s`, `port` is the port to connect to instead of each destination's port (required for UDP rules). Also usable on rules with only `remote_addr`. Not usable on `http` rules (use `http.services.<name>.health_check`) |
| `source_ip` | `"proxy"` \| `"proxy_v1"` \| `"proxy_v2"` \| `"transparent"` | | Default `"proxy"` (does not pass the source IP). `proxy_v1` is TCP only. `proxy_v2` also works for UDP and adds a PROXY v2 (DGRAM) header to each datagram sent to the destination (responses carry no header; the destination address is the address the client sent to, which is the receiving address even when listening on `0.0.0.0` / `::`). UDP `proxy_v2` cannot be combined with `tls.upstream.tls` (DTLS to the destination) (`unsupported`). `transparent` can be specified only when `transparent` (IPv4) / `transparent_ipv6` (IPv6 listeners) in `GET /capabilities` is true. The client and destination must be in the same address family (docs/TRANSPARENT.md). For an explanation and destination configuration examples, see docs/SOURCE-IP.md |
| `udp_idle_secs` | 1–86400 | | Seconds of inactivity before a UDP session is discarded. Default 30. Ignored for TCP |
| `listen_port_end` | 1–65535 | | End of a port range (≥ `listen_port`). Each port in `listen_port..listen_port_end` is forwarded to a destination port shifted by the same amount starting from `remote_port`. The maximum is `max_range_ports` in `GET /capabilities` (default 20000) |
| `tls` | object | | TLS (tcp) / DTLS (udp) handling. When omitted, `{"mode": "passthrough"}`. See "TLS" below |
| `starttls` | `"smtp"` \| `"imap"` \| `"pop3"` | | rproxy answers the plaintext exchange before STARTTLS and terminates TLS. Usable only on tcp rules whose `tls.mode` is `terminate` |
| `starttls_required` | bool | | Default `true`. If `false`, SMTP clients that do not use STARTTLS are passed through in plaintext (IMAP / POP3 always treat it as required). Specifying `false` without `starttls` gives `invalid` |
| `allow_from` | array of strings | | Sources allowed to connect. CIDR (`172.16.0.0/16`, `fd00::/8`) or a single IP. Omitted or empty accepts all. Up to 64 entries. TCP connections from outside the ranges are closed before TLS or the PROXY header. For UDP, datagrams from sources outside the ranges are dropped (no session is created). Refusals are counted in `stats.denied` (for UDP, per datagram) and logged as `conn.denied` (`reason: allow_from`; for UDP up to 20 lines in a row per source, then one line a second, and against floods with spoofed sources at most 200 lines in a row overall, then 50 a second; `suppressed` is the number of lines left out before it; since v0.3.20, before which UDP refusals were logged only at `debug`) |
| `crowdsec` | bool | | Default `false` (v0.3.2). If `true`, sources in the CrowdSec decisions (`global.crowdsec`, scope `Ip` / `Range`) are disconnected right after accept, just like `allow_from` (before TLS or the PROXY header). For UDP those datagrams are dropped (including ones for open sessions). Until decisions have been fetched from LAPI even once, traffic is allowed. Without `global.crowdsec` this is `invalid`. Also usable on `http` rules, but it looks at the connecting peer's IP (behind a front proxy, use the `crowdsec` middleware). Omitted from listings when `false`. Refusals are counted in `stats.denied` and logged as `conn.denied` (`reason: crowdsec`; for UDP thinned out like `allow_from`) |

The key of a range rule is `listen_port` (the start of the range). Rules with the same protocol whose listen address and port overlap cannot be created (`already_exists`).

When a UDP rule listens on `0.0.0.0` / `::`, rproxy remembers the destination address of each received datagram (`IP_PKTINFO` / `IPV6_RECVPKTINFO`) and sends replies from that address (since v0.3.10, Linux). Even on a host with multiple addresses, clients receive replies from the address they sent to (for clients that drop replies from a different address than the destination, such as IKE, WebRTC, QUIC and DTLS). Traffic from the same client (address and port) to a different address becomes a separate session, and each is answered from its own address. This applies equally to L4 relaying, DTLS termination, UDP server-name routing and HTTP/3. The `listen` of `conn.open` and the destination in the PROXY v2 header are also the receiving address.

### Multiple destinations (`targets`, v0.3.3)

```json
{
  "protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 5432,
  "targets": [
    {"addr": "10.0.0.11", "port": 5432, "weight": 2},
    {"addr": "10.0.0.12", "port": 5432},
    {"addr": "db-backup.internal", "port": 5432, "backup": true}
  ],
  "balance": "least_conn",
  "health_check": {"interval": "10s", "timeout": "3s"}
}
```

- A destination is chosen for each new connection (TCP) or new session (UDP).
  - `round_robin`: rotates in order in proportion to `weight`.
  - `least_conn`: the destination with the smallest number of currently open connections (sessions for UDP) ÷ `weight`. Ties rotate in order.
  - `failover`: uses only the first destination that is up, in the order of `targets`. When a higher one comes back, new connections go back to it.
- up / down: if `health_check` is set, its result (up until the first check). Even without it, a destination that refuses a TCP connection (or does not respond within 5 seconds) is skipped as down for 10 seconds, and the same connection is retried on the next destination. For UDP, a destination that returns ICMP unreachable is likewise marked down.
- `backup` destinations are used only when all other destinations are down. If all are down, down destinations are also tried in order (connections are not refused).
- An existing UDP session moves to the next destination when its own destination goes down (`conn.retarget`, `reason: target down`). With `failover`, existing sessions stay where they are even when a higher destination comes back.
- If some destinations cannot be resolved, the rule still works as long as others resolve (unresolved destinations are re-resolved later). If none resolve, the result is `resolve_failed` as before.
- `tls.routes` (destination per server name) remain one per route as before. `targets` is the destination for non-matching names (and for no server name).
- State changes are logged as `event: "target.down"` (`reason: health_check` / `connect`, `error`) / `"target.up"`. The rule's `stats.targets` holds per-destination `[{"addr","port","backup"?,"up","connections","total_connections","resolved"}]` (only when there are 2 or more `targets` or a `health_check`), and `/metrics` exposes `rproxy_target_up{protocol,listen,target}` (1 / 0) and `rproxy_target_connections{protocol,listen,target}`.
- When every destination is down, the rule's `all_targets_down` is `true` and `rproxy_rule_all_targets_down{protocol,listen}` in `/metrics` is 1 (v0.3.20; only for rules that show `stats.targets`; for other rules `all_targets_down` is always `false`). That is, when none is up, backups included.
- Changing destinations, `balance` or `health_check` resets per-destination connection counts and up / down state (open connections are kept).

### TLS

```json
{
  "mode": "terminate",
  "routes": [
    {"server_name": "imap.example.com", "remote_addr": "10.0.0.5", "remote_port": 143},
    {"server_name": "*.example.com", "remote_addr": "10.0.0.6", "remote_port": 8443}
  ],
  "certificates": [
    {"cert_file": "/etc/rproxy/certs/example.pem",
     "chain_file": "/etc/rproxy/certs/intermediates.pem",
     "key_file": "/etc/rproxy/certs/example.key"}
  ],
  "client_auth": {"mode": "required", "ca_file": "/etc/rproxy/clients-root.pem",
                  "chain_file": "/etc/rproxy/clients-intermediates.pem"},
  "alpn": ["h2", "http/1.1"],
  "upstream": {"tls": true, "server_name": "backend.internal", "ca_file": "/etc/rproxy/internal-ca.pem"}
}
```

| Field | Description |
|---|---|
| `mode` | `passthrough` (default; passes traffic through still encrypted), `sni` (chooses the destination by the server name in the ClientHello without decrypting; TLS for tcp, DTLS and QUIC (HTTP/3 etc.) for udp; see "UDP server-name routing" below), `terminate` (rproxy decrypts; TLS for tcp, DTLS for udp) |
| `routes` | Destination per server name (`sni` and `terminate`): `{"server_name" or "server_names", "remote_addr", "remote_port", "passthrough"?}`. For range rules, `remote_port` plus the range length must not exceed 65535. Non-matching names go to the rule's `remote_addr` / `remote_port` (`targets`). With a port range, `remote_port` here is shifted by the same amount.<br>Name syntax: `mail.example.com` (exact match), `*.example.com` (exactly one label), `**.example.com` (one or more labels, any depth; does not match `example.com` itself). `server_names` allows multiple names in one route (use either it or `server_name`). When multiple routes match: exact match → `*.` → `**.` (longer suffix first) → order written.<br>`passthrough: true` (`terminate` only): connections for that name are not terminated, and the whole ClientHello is passed through to the destination as-is (same as `sni`; the destination holds the certificate). `allow_from`, the rule's `crowdsec`, `source_ip` and stats still apply. Cannot be combined with `starttls`. Not handled for HTTP/3 (QUIC) (QUIC connections for that name are closed) |
| `unmatched` | `default` (default; names that match no `routes` and connections without SNI go to the rule's `remote_addr` / `remote_port`) or `reject` (disconnect; with `terminate`, the connection is cut without completing the handshake). Can be specified only with `sni` (tcp and udp) and tcp `terminate`, and only when `routes` is present |
| `certificates` | Required for `terminate`. `cert_file` is the server certificate, `chain_file` the intermediate CA certificates (in order from the CA that issued the server certificate toward the root; the root need not be included), `key_file` the private key. A chain concatenated into `cert_file` also works. When loading, the chain order and that the key pairs with the server certificate are verified. If there are several, one is chosen by SNI; if none matches, the first is used. DTLS keys must be PKCS#8 (`-----BEGIN PRIVATE KEY-----`) |
| `client_auth` | Client certificate verification (mTLS). `mode` is `none` (default) / `optional` (verify if sent) / `required`. `optional` and `required` require `ca_file`. `ca_file` is the root CA (trust anchor). `chain_file` holds intermediate CAs for client certificates, filling in the verification path for clients that do not send intermediates (not used as trust anchors). TLS and DTLS are verified by the same rules |
| `alpn` | ALPN offered to clients with `terminate` (tcp only) |
| `upstream` | The destination side for `terminate`. `tls: true` re-encrypts (TLS for tcp, DTLS for udp). `server_name` (default: the destination host name), `ca_file` (default: Mozilla root certificates), `insecure_skip_verify` (no verification; for testing), `cert_file` / `chain_file` / `key_file` (client certificate to the destination and its intermediate CAs) |

### UDP server-name routing (`tls.mode: sni`, v0.3.8)

udp rules can also use `tls.mode: sni` and `tls.routes` to choose the destination from the server name (SNI) in the first datagram. Since it does not terminate, rproxy needs no certificate; the destination holds the certificate.

- What can be read:
  - DTLS 1.2 / 1.3 ClientHello (plaintext; reassembled even when fragmented or spanning datagrams)
  - QUIC v1 (RFC 9000 / 9001) / v2 (RFC 9369) Initial packets (HTTP/3 etc.). Anyone can compute the Initial keys from the connection ID chosen by the client (RFC 9001 §5.2), so header protection and encryption are removed and the ClientHello is read from the CRYPTO frames. The ClientHello is reassembled even when it spans multiple Initials (large key shares, etc.)
- The first datagrams of a new client (address and port) are held until the name is known (up to 3 seconds, 16 datagrams, 64 KiB). Once the name is known, the held datagrams are sent to the destination in order, and the rest is relayed as that client's session like ordinary UDP. Up to 4096 sessions per port can be reading names at once (first datagrams from new clients beyond that are dropped; the client retransmits)
- Datagrams that are neither DTLS nor QUIC, ones without SNI, and names that match no route: with `unmatched: default` (default) they go to the rule's destination (`remote_addr` / `targets`); with `reject` they are dropped (`stats.denied`, `conn.denied` with `reason: unmatched`)
- When a new QUIC connection for a different name (an Initial with a different connection ID) arrives from the same client socket, the name is read again, and if the name differs the session is recreated (quinn and others start the next connection from the same socket). If the name is the same (after a Retry, etc.), the current destination is kept
- `allow_from` and the rule's `crowdsec` apply before the name is read. `conn.open` logs include `sni`
- `passthrough` in `routes` cannot be used (`sni` is all passthrough). udp rules with `terminate`, which terminate DTLS, do not route by name
- Limitations:
  - QUIC connection migration (the client's address or port changes) is not followed (the migrated flow is treated as a new client and the name is read again; since it is not an Initial, it goes to the rule's destination)
  - For connections using ECH (Encrypted Client Hello), the real name cannot be read (routing uses the outer public name)

Combining `terminate` with `source_ip: "proxy_v2"` adds TLS information to the PROXY v2 header as TLVs.
- `PP2_TYPE_AUTHORITY`: SNI
- `PP2_TYPE_ALPN`: ALPN
- `PP2_TYPE_SSL`: that TLS is used, whether a client certificate was presented, `PP2_SUBTYPE_SSL_VERSION`, and the client certificate's CN (`PP2_SUBTYPE_SSL_CN`)

Certificate files are loaded when a rule is created or modified. Loaded certificates are shared per certificate (multiple rules using the same files use the same instance). After that:
- Every `RPROXY_CERT_CHECK_SECS` (default 60 seconds, `0` disables), for each certificate, the size, modification time and inode of its files (certificate, key, intermediate CAs, CA) are checked; only changed certificates are reloaded and applied to the rules using them. Both overwriting (e.g. by certbot) and swapping symbolic links (as with Kubernetes Secrets) are detected. The control API certificate (`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`) is handled the same way.
- If reloading fails (e.g. key and certificate do not match mid-write), the current certificate stays in use and the next check retries (the `reload.tls` warning is logged once per file version).
- Sending SIGHUP reloads all certificates immediately, whether or not they changed.

### Certificate expiry (#115)

Expiry (notAfter) is checked when certificates are loaded (create, modify, file change, SIGHUP) and every `RPROXY_CERT_EXPIRY_CHECK_SECS` (default 86400 seconds = 1 day, `0` disables).
- **Server certificates** (`tls.certificates`; treated as expired if any one of them, including intermediate CAs, has expired):
  - Only the expired certificate is removed, and the rule keeps running with the other certificates. For names of the removed certificate, the first remaining certificate is returned (clients see a name mismatch; an expired certificate is never returned).
  - If all have expired, the rule is set to `failed` (`error` is `certificate expired: ...`) and its listener is closed. As soon as updated files are loaded (file change, SIGHUP, PATCH), it automatically returns to `running`.
  - When creating or modifying via the API, if all have expired the request is refused with `400 tls_config` (`certificate expired: ...`) (the rule is not created). At startup (DB, config file) and on reload, the rule is registered as `failed`.
- **Client authentication CAs and intermediate CAs, upstream CAs and certificates, and the control API certificate**: the rule is not stopped. They are only reported through display, logs and metrics.
- `passthrough` routes are excluded (the certificate belongs to the destination).
- From `RPROXY_CERT_WARN_DAYS` (default 14 days) before expiry, the state is `expiring`. Logs `cert.expiring` (warning), `cert.expired` (error) and `cert.ok` (renewed) are emitted once when the state changes.
- `rproxy_cert_expiry_seconds{protocol,listen,role,file}` in `/metrics` (the control API certificate is `{role="api",file}`): seconds until expiry (negative once expired).

rproxy can also obtain certificates itself through ACME (from v0.4.0: `{"acme": "<resolver>", "domains": [...]}` in `tls.certificates[]`, with `global.acme` in the settings file; the certificates obtained are loaded by the same certificate store, and renewals are applied automatically as described above). See docs/en/ACME.md. Pointing `cert_file` / `key_file` at files obtained by certbot, acme.sh, cert-manager and the like works as before (for certbot's http-01, route `/.well-known/acme-challenge/` with an `http` rule on port 80 to certbot's webroot / standalone port; tokens rproxy is not answering itself go through the routes).

Rules returned in responses include the following runtime information (`allow_from` is returned as normalized CIDRs, e.g. `10.0.0.5` → `10.0.0.5/32`).

| Field | Description |
|---|---|
| `state` | `"running"` or `"failed"` |
| `error` | The reason for `failed`. `null` when `running` |
| `resolved` | Destinations last successfully resolved (array of `"ip:port"`). Empty if not yet resolved |
| `connections` | Current number of connections (number of sessions for UDP) |
| `stats` | Totals since the rule started: `total_connections`, `rx_bytes` (client → destination), `tx_bytes` (destination → client), `tls_failures` (TLS / DTLS handshake or STARTTLS failures) |
| `started_at` | Time listening started (Unix seconds). `null` when `failed` |
| `all_targets_down` | Every destination is down (v0.3.20; see "Multiple destinations") |
| `down_services` | For `http` rules, names of services with `health_check` that have no server up (v0.3.20). Omitted when there are none |
| `cert_status` | Expiry of certificates used by a `terminate` rule (see "Certificate expiry" above). Omitted when there are no certificates. Each element has `role` (`certificate` / `client_ca` / `client_chain` / `upstream_ca` / `upstream_certificate`), `file` (the certificate file), `not_after` (RFC 3339, UTC), `days_left` (days remaining; negative once expired), `state` (`ok` / `expiring` / `expired`) |
| `acme` | State of ACME certificates (`tls.certificates[].acme`); omitted without them. Each element has `resolver`, `domains`, `state` (`pending`: not obtained yet (a self-signed stand-in is served) / `valid` / `renewing`: due for renewal / `error`: the last attempt failed (a certificate obtained earlier stays in use)), `not_after` and `renew_at` (RFC 3339), `next_attempt` (the next attempt after a failure or while `rate_limit` holds it back), `error` |
| `origin` | `dynamic` (a rule created via the API or restored from the DB) or `static` (a fixed rule; see below) |

`stats` also includes `denied` (the number of connections cut because they were outside `allow_from`, matched a `crowdsec` decision, or hit `unmatched: reject`) and `dropped` (the number of UDP datagrams rproxy could not forward and discarded: the session queue overflowed, sending failed, or too many sessions were reading names; since v0.3.9. Datagrams dropped because the kernel socket receive buffer overflowed are invisible to rproxy and not counted). In `GET /metrics` this is `rproxy_udp_dropped_total{protocol,listen}` (UDP rules only).

#### Data integrity (L4)

- TCP: when one side closes (FIN), it is propagated to the other side as a half-close (FIN), and the opposite direction continues. When one side resets (RST) or can no longer be written to, the other side is also cut with a reset (it is not made to look like a normal end; `SO_LINGER` 0). On rules that terminate TLS, if the destination resets, the client's TLS is cut without close_notify.
- UDP: datagrams are forwarded one by one, unchanged, in the order they arrive (not merged, split, reordered or duplicated). Ones rproxy discards are counted in `dropped` above.
- tests/integrity.rs verifies this by sending tens of MiB of pseudo-random data and comparing SHA-256 (TCP passthrough, terminate, `upstream.tls`, `proxy_v2`; UDP, DTLS; HTTP/1.1, HTTP/2, HTTP/3, WebSocket; `compress`, `buffering`, `retry`; reuse of upstream connections). The size can be changed with `RPROXY_TEST_INTEGRITY_MB`, and CI (`.github/workflows/integrity.yml`) runs it weekly at 512 MiB.
For rules with 2 or more destinations or a `health_check`, `stats.targets` holds per-destination state (see "Multiple destinations" above).
For `http` rules, `stats.http` also holds request counts (omitted for other rules).

```json
"http": {"requests": 5, "by_status": {"2xx": 3, "4xx": 2},
         "routes": {"site": {"requests": 3, "by_status": {"2xx": 3}}, "(none)": {"requests": 1, "by_status": {"4xx": 1}}}}
```

If there are services with `health_check`, `services` holds per-server state (`{"app": [{"url": "http://10.0.0.20:80", "up": true}, ...]}`). If any requests were refused by `rate_limit` / `in_flight`, `limited` (total) and per-route `limited` (per middleware name) are included. Requests refused by `crowdsec` appear in the same shape under `blocked` (both are also counted under `4xx` in `by_status`).

- `by_status` is grouped by the hundreds digit of the status code (`1xx`–`5xx`; empty classes are omitted). `routes` is per route name; requests that matched no route are under `(none)`.
- Counted when the response body has been fully sent (or the client disconnected).

## Config file (fixed rules)

If a config file (or its directory) is given in `RPROXY_CONFIG` (`--config`), its rules are started at startup, and changes to the file are applied without restart. 0.2's `RPROXY_STATIC_RULES` (`--static-rules`) can be used with the same meaning (both cannot be given).

- The format is determined by extension: `.yaml` / `.yml` is YAML (comments and anchors `&name` / `*name` are allowed), anything else is JSON. YAML and JSON have the same shape and the same meaning.
- The content is one of:
  - `{"version": 1, "global": {...}, "rules": [...]}` (v0.3)
  - An array of rules (the 0.2 shape)
- Each element of `rules` has the same shape as the body of `POST /rules`.
- `global` holds process-wide settings (`trusted_proxies`, `access_log`, `acme`, `crowdsec`; section 2 of docs/DESIGN-v0.3.md).
  - `acme`: ACME accounts, DNS providers, resolvers and allowed names (docs/en/ACME.md). Secrets are named by files and cannot be reached through the API.
  - `trusted_proxies`: an array of CIDRs. For `http` rules, `X-Forwarded-For` is trusted when the connecting peer is in these ranges (also applies to rules created via the API).
  - `crowdsec`: the CrowdSec bouncer (used by the `crowdsec` middleware and rules with `crowdsec: true`; using those without this is `invalid`, and for a config file rproxy does not start).
    - Calls `GET /v1/decisions/stream` on `lapi_url` (e.g. `http://127.0.0.1:8080`) every `update_interval` (default `10s`) and remembers the decisions (initially and after a failure, it refetches everything with `startup=true`). `X-Api-Key` is the content of `api_key_file` (the key created with `cscli bouncers add rproxy`; reloaded on SIGHUP).
    - Decisions used are scope `Ip` and `Range`, type `ban` and `captcha` (captcha cannot be served, so it is treated as ban). Other scopes (Country etc.) and types are not used.
    - When LAPI cannot be reached, the previous decisions stay in use and the fetch is retried with a doubling interval (up to 5 minutes) (`crowdsec.error`; `crowdsec.sync` once fetched). While nothing has ever been fetched, the middleware's `on_error` is followed.
    - `appsec_url` (e.g. `http://127.0.0.1:7422`): queries AppSec (the middleware's `appsec: true`; using `appsec: true` without this is `invalid`).
    - If `api_key_file` is missing or empty, rproxy does not start. If it cannot be read (permissions), rproxy runs without decisions until it becomes readable and SIGHUP is sent (`part: global.crowdsec`).
  - `access_log`: the access log file for `http` rules (JSON Lines; like `RPROXY_LOG_FILE`, rotated daily to `<name>.<date>.<ext>`, keeping `RPROXY_LOG_KEEP` files). If omitted, access logs go to the main log (`event: "http.access"`). If the directory does not exist, rproxy does not start. If it cannot be written, logs go to the main log (`part: global.access_log`).
- If a directory is given, the `*.yaml` / `*.yml` / `*.json` files in it are read in name order and combined into one configuration (files starting with `.` are not read; a Kubernetes ConfigMap can be mounted as-is).
  - Each file has one of the shapes above. `rules` are concatenated. Only one file may contain `global` (an error if two do).
  - If two rules have the same key (protocol, address, port), it is an error showing both file names and positions (e.g. `web.yaml rule #2`).
- Started before restoring from the DB. Works even if the DB cannot be reached.
- Cannot be modified or deleted via the API (`409 static`). To change them, edit the file.
- **Applying without restart**: every `RPROXY_CONFIG_CHECK_SECS` (default 10 seconds; `0` means only on SIGHUP), the file's size, modification time and inode (and for a directory, files added or removed) are checked, and the file is reloaded if anything changed. Sending SIGHUP reloads even if nothing changed. To get the result immediately, use `POST /config/reload` (in the endpoint table below). Swapping symbolic links (ConfigMap updates) is also detected.
  - The reloaded configuration is first validated as a whole. If there are errors, nothing is changed and the previous rules stay in use (`event: "config.error"`; once per identical content). The same applies when it cannot be read (permissions): it retries at every check until readable.
  - If valid, only the differences are applied (`event: "config.reload"`; counts of `added`, `removed`, `changed`, `unchanged`, `failed`).
    - Added rules are started and removed rules are stopped (existing connections are cut).
    - Changed rules, if the differences are only in fields changeable by PATCH (destination, `udp_idle_secs`, `tls`, `starttls`, `allow_from`, `http`), are changed in place (existing connections are not cut; for TCP, from new connections). When the port range, `source_ip` etc. change, the rule is stopped and recreated.
    - Unchanged rules are not touched (connections are not cut).
    - If a rule with the same key was created from the API (DB), that one is kept and the file's rule is logged as `rule.failed`.
  - Changes to `global` do not take effect until restart (`trusted_proxies`, `access_log`, `acme`, `crowdsec`; differences from the startup values are reported with a `config.reload` warning and `restart_needed` in `GET /config`).
  - The state is visible in `GET /config`: `{"configured":true,"path":"/etc/rproxy/conf.d","files":[...],"loaded_at":1790000000,"rules":5,"last_reload":{"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0},"error":null,"restart_needed":[]}` (`{"configured":false}` when no config file is used). `error` is the reason the latest version could not be applied (the previous version is running).
- Check before applying: `rproxy-api --check-config [PATH]` performs the same validation as at startup and reload (syntax, rule values, overlapping listeners and overlap with the control API, certificate/key/CA files and their expiry, `global`, middleware secret files) and exits 0 if there are no problems, 1 if there are errors (it opens neither listeners nor the DB; `--check-config-format json` gives `{"ok","path","files","rules","errors":[{"rule","message"}],"warnings":[...]}`). Name resolution is not performed. The package unit's `ExecReload` runs this check first (if there are errors, reload fails and SIGHUP is not sent).
- Trying to create a rule with the same key or an overlapping port from the API or DB gives `already_exists`.
- If the file does not exist, or its syntax or shape is invalid (unknown keys, `version` other than 1, references to a nonexistent ACME resolver, names outside `global.acme`'s allowlists, secret files that do not exist, etc.), rproxy does not start. If it cannot be read (permissions), rproxy starts without fixed rules.
- Rules using features this version cannot run (`false` in `features` of `GET /capabilities`) are registered as `failed` (with a reason), and the configured content is visible in `GET /rules`. Name resolution or bind failures are handled the same as for other rules.

Example: expose the dashboard (Web UI) only as `dashboard.proxy.home`, to the internal network.

```yaml
# /etc/rproxy/rproxy.yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 127.0.0.1
    remote_port: 3001
    allow_from: [172.16.0.0/16]
    tls:
      mode: terminate
      certificates:
        - cert_file: /etc/rproxy/certs/dashboard.pem
          chain_file: /etc/rproxy/certs/intermediates.pem
          key_file: /etc/rproxy/certs/dashboard.key
      routes:
        - {server_name: dashboard.proxy.home, remote_addr: 127.0.0.1, remote_port: 3001}
      unmatched: reject
```

## v0.3 settings (L7, ACME, TLS options)

The shape was fixed in v0.3.0, and the functionality is enabled step by step in v0.3.x patches (docs/RELEASING.md). Whether this version can run something is shown by `features` in `GET /capabilities`. Rules using settings that cannot run are validated for shape and then refused with `400 unsupported` (if the shape is invalid, `400 invalid` / `tls_config`). The overall design and examples are in docs/DESIGN-v0.3.md.

| Item | Location | Shape | features |
|---|---|---|---|
| L7 routing | the rule's `http` | `routes` (`name`, `match`, `priority`, `service` or `to`, `middlewares`), `default`, `services`, `middlewares`, `http3` | `http` (since v0.3.1), `http3` (since v0.3.2), `middlewares` |
| Services | `http.services.<name>` | `servers` (`url`, `weight`), `pass_host_header`, `timeouts` (`connect`, `response`), `health_check`, `sticky`, `balance` | `http`. `health_check` / `sticky` / `balance` when included in `services` |
| `match` | `http.routes[].match` | Same expressions as Traefik. Combine `Host`, `HostRegexp`, `Path`, `PathPrefix`, `PathRegexp`, `Method`, `Header`, `HeaderRegexp`, `Query`, `QueryRegexp`, `ClientIP` with `&&`, `\|\|`, `!` and parentheses | `http` |
| Middlewares | `http.middlewares.<name>` | `{type: {settings}}`. Types are `redirect_scheme`, `redirect_regex`, `rate_limit`, `in_flight`, `crowdsec`, `ip_allow`, `headers`, `forward_auth`, `oidc`, `basic_auth`, `strip_prefix`, `add_prefix`, `replace_path`, `replace_path_regex`, `compress`, `buffering`, `retry`, `circuit_breaker`, `errors`, `respond` | when the type is included in `middlewares` |
| ACME certificates | `tls.certificates[]` | `{"acme": "<resolver>", "domains": [...]}` (instead of `cert_file` / `key_file`). The resolver is one of `global.acme.resolvers` in the settings file. Needs the `acme:write` scope; names must be within the `allowed_names` of the resolver's account (and DNS provider), else `400 invalid`. tcp `terminate` only (udp: `tls_config`). docs/en/ACME.md | `acme` (true from v0.4.0) |
| TLS options | `tls.options` | `min_version` (`"1.2"` / `"1.3"`), `cipher_suites` (below) | `tls_options` (true since v0.3.2) |

- `tls.options` (v0.3.2) applies to the client-side TLS of tcp `terminate` (including `http` rules). It does not apply to TLS toward the destination (`upstream`). Not usable with UDP (DTLS) (`unsupported`).
  - `min_version`: `"1.3"` refuses TLS 1.2 clients. Omitted or `"1.2"` allows 1.2 and 1.3.
  - `cipher_suites`: names of the cipher suites to use (rustls names; for TLS 1.3 `TLS13_AES_128_GCM_SHA256`, `TLS13_AES_256_GCM_SHA384`, `TLS13_CHACHA20_POLY1305_SHA256`; for TLS 1.2 `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`, etc.). Unknown names give `tls_config` (the error lists the usable names). Versions with none of the listed suites are not offered (listing only TLS 1.3 suites gives TLS 1.3 only). `min_version: "1.3"` with no TLS 1.3 suite gives `tls_config`.
  - Key exchange curves and refusing non-matching SNI (Traefik's sniStrict; in rproxy, `tls.unmatched: reject`) are not in `options`.
  - The negotiated version and cipher suite appear in `tls_version` / `tls_cipher` of `conn.open`.
- `http` is allowed only with `protocol: tcp` and `tls.mode` `terminate` (HTTPS) or no TLS (plain HTTP). It cannot be combined with `sni`, `starttls` or port ranges. `remote_addr` / `remote_port` are not written (writing them gives `400 invalid`).
- `http` rules can also use `tls.routes` routes with `passthrough: true` (on the same port, only those names are passed through without termination; e.g. cdn and gitlab at L7, registry and `**.tenant.example.com` passed straight to Kubernetes). Non-passthrough `tls.routes` and `unmatched: reject` give `tls_config` (routing is `http.routes`, and `http.default` when nothing matches).
- `http.http3: true` (v0.3.2) also accepts QUIC + HTTP/3 over UDP on the same address and port.
  - Only with `tls.mode: terminate` (without TLS, `400 tls_config`). Cannot be combined with `source_ip: transparent` (`unsupported`).
  - Certificates and client authentication (`client_auth`) are the same as for TCP. QUIC is TLS 1.3 only, so `tls.options.cipher_suites` needs TLS 1.3 cipher suites (without `TLS13_AES_128_GCM_SHA256` it cannot be used to initialize QUIC). Certificate reloads (SIGHUP, `RPROXY_CERT_CHECK_SECS`) take effect from new QUIC connections.
  - Requests go to the same routes, middlewares and destinations as HTTP/1.1 and HTTP/2 (HTTP/1.1 to the destination). Bodies are streamed. The access log `protocol` is `HTTP/3.0`.
  - `allow_from` and the rule's `crowdsec` are checked before accepting the QUIC connection (`conn.denied`, `transport: quic`).
  - Responses on the TCP side (HTTP/1.1, HTTP/2) get `Alt-Svc: h3=":<port>"; ma=86400` (if the destination returned `Alt-Svc`, that is kept as-is). Not added while HTTP/3 is not being accepted.
  - If the UDP port cannot be used (in use, permissions) or the TLS settings cannot be used for QUIC, the rule runs on TCP only and `stats.http.http3` shows `{"listening": false, "error": "..."}` (log `event: degraded`, `part: http3`). When accepting, `{"listening": true}`. Rules without `http3` have no `http3` item.
  - Adding or removing `http3` with `PATCH` starts or stops the UDP listener (stopping cuts open QUIC connections). For rules that could not listen, PATCHing `http` with `http3: true` retries. Deleting the rule also closes the UDP port.
  - In the firewall, open UDP on the same port as TCP too.
- Adding `http` with `PATCH` replaces the whole L7 configuration (from the next request). `http` cannot be added with `PATCH` to a rule without `http` (`unsupported`; recreate it).

### Behavior of `http` rules (v0.3.1)

- Talks HTTP/1.1 and HTTP/2 with clients. With `terminate`, if `tls.alpn` is not specified, ALPN offers `h2` and `http/1.1` (`tls.alpn` in `GET /rules` remains as specified). In plaintext, HTTP/1.1 and HTTP/2 starting with the preface (h2c) are accepted.
- Routes are tried in descending `priority` (when omitted, the length of `match`; same as Traefik), and in written order for ties; the first match is used. If none match, `default` (`service` or `status`; 404 when omitted).
- `Host` excludes the port and is case-insensitive. HTTP/2 uses `:authority`. `ClientIP` is the client's IP: the connecting peer, or, if the peer is within `global.trusted_proxies`, the first untrusted address in `X-Forwarded-For` scanning from the right (same as Traefik; addresses the client prepended on the left are not used). `ip_allow`, `X-Real-IP` and the access log use the same IP.
- Limits of `match` expressions (v0.3.18): parentheses and `!` nest at most 32 levels, and one expression holds at most 256 matchers (`Host(...)` and so on; arguments are not counted). Beyond that it is a configuration error (400 from the API; an error at startup, on reload and from `--check-config` for the settings file).
- Durations (written as `10s`, `500ms`, `1m`, `2h`: `period`, `timeouts`, `interval` / `timeout` of `health_check`, `initial_interval`, `window` / `recovery`, `update_interval` and so on) are at most 365 days (`8760h`) (v0.3.18). Longer values are a configuration error.
- Talks HTTP/1.1 with destinations. `servers` uses weighted round robin by `weight` (default 1). If `url` has a path, it is prepended to the request path. Certificates of `https://` destinations are verified with `ca_file` of the rule's `tls.upstream` (Mozilla roots if absent), and `server_name` / `insecure_skip_verify` / client certificates follow it too. `tls.upstream.tls` is not used (determined by `https://` in the URL; specifying it gives `tls_config`).
- Upstream connections are reused for the next request after the response body has been read (up to 1024 idle connections per destination, closed after 4 seconds unused; on `source_ip: transparent` rules connections are not reused, since the source differs per client). If a connection being reused has been closed by the destination, the request is resent on a new connection.
- `health_check` (v0.3.2): every `interval` (default `10s`), sends `GET <URL path><path>` to each of `servers` (`Host` is the destination host); if 2xx / 3xx returns within `timeout` (default `3s`) it is up, otherwise down. Down destinations are removed from round robin and added back when they recover. Treated as up until the first check. If all are down, 503. State changes are logged as `event: "http.health"` (`service`, `server`, `up`, and `error` with the down reason). The rule's `stats.http.services.<service name>` holds `[{"url","up"}]`, and `/metrics` exposes `rproxy_http_server_up{protocol,listen,service,server}` (1 / 0). When every server of a service is down, the service's name is in the rule's `down_services` and `rproxy_http_service_down{protocol,listen,service}` is 1 (v0.3.20).
- `balance` (v0.3.3): `round_robin` (default; in proportion to `weight`), `least_conn` (the destination with the fewest in-flight requests per `weight`), `failover` (the first up destination in the order of `servers`). All exclude down destinations (per `health_check` results). If the destination in the `sticky` cookie is up, it takes precedence.
- `sticky` (v0.3.2): first-time clients get a cookie indicating the chosen destination (`<cookie>=<16-digit value derived from the URL>; Path=/; HttpOnly; SameSite=Lax`, plus `Secure` for HTTPS), and are sent to that destination afterwards. If that destination is down or the value is unknown, a destination is chosen again and the cookie is reset. The value is derived from the URL, so it does not change when rproxy restarts or other destinations are added.
- `weight` can be used to switch destinations (e.g. give the new version `weight: 1` and the current version `weight: 9` to send 10% of traffic).
- If `pass_host_header` (default true) is false, `Host` is set to the host (and port) of the destination URL.
- `X-Forwarded-For`, `X-Real-IP` (the client's IP), `X-Forwarded-Proto` (`http` / `https`), `X-Forwarded-Host` and `X-Forwarded-Port` are added toward the destination. Headers with the same names sent by the client are replaced. However, if the connecting peer is within `global.trusted_proxies`, the peer is appended to the received `X-Forwarded-For`, and received `X-Forwarded-Proto` / `-Host` / `-Port` values are kept. Hop-by-hop headers (`Connection` and those listed in it, `Keep-Alive`, `TE`, `Transfer-Encoding`, etc.) are removed.
- `Connection: Upgrade` (WebSocket etc.) is relayed as-is if the destination returns 101. Deleting the rule cuts it.
- If the destination cannot be connected to, 502; if `timeouts.connect` (default 5 seconds) or `timeouts.response` (default 60 seconds) is exceeded, 504. An `event: "http.error"` log is emitted. `timeouts.response` is the time from finishing sending the request body until the response headers arrive (time spent uploading is not included, and there is no limit on the response body either).

### HTTP forwarding semantics

rproxy talks HTTP/1.1, HTTP/2 and HTTP/3 with clients and HTTP/1.1 with destinations. In between, it handles things as follows (verified from HTTP/1.1, HTTP/2 and HTTP/3 clients in tests/http_semantics.rs).

| Item | Handling |
|---|---|
| `Cookie` | When split across multiple fields in HTTP/2 / HTTP/3 (Chrome does this), they are joined into one with `"; "` (RFC 9113 §8.2.3 / RFC 9114 §4.2.1). Middlewares (`oidc`, `sticky`, `forward_auth`) read the joined value too |
| `Set-Cookie` | Multiple `Set-Cookie` from the destination are passed to the client one by one as-is (not merged; same through `compress` and `headers`). Attributes such as `Domain` / `Path` / `Secure`, and `Location`, are not rewritten |
| Other headers | Multiple fields with the same name are passed in order, with values as raw bytes (including non-ASCII). `Authorization` is passed |
| Hop-by-hop headers | Removed in both directions: `Connection` and the names listed in it, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` (`Upgrade` for WebSocket etc. is re-added and relayed). `Via` and `Forwarded` (RFC 7239) are not added (same as Traefik's and nginx's defaults; `X-Forwarded-*` is used) |
| `Host` | The authority of HTTP/2 / HTTP/3 `:authority` and of HTTP/1.1 absolute-form targets (`GET https://a.example/ HTTP/1.1`) takes precedence over the `Host` field (RFC 9112 §3.2.2). Sent to the destination in origin-form (path and query). With `pass_host_header: false`, the host of the destination URL |
| Header size | HTTP/2 / HTTP/3 allow up to 64 KiB of headers in total per request (hyper's default 16 KiB is not enough for browsers with large cookies). HTTP/1.1 allows up to about 400 KB. Exceeding gives 431 |
| Body | Streamed (not accumulated unless `buffering` is used). Supports chunked, `Expect: 100-continue`, `HEAD` (keeps `Content-Length`), `204` / `304` |
| Timeouts | `timeouts.response` is from finishing sending the body until the response headers. Response bodies of long downloads, SSE and long polling are not cut |
| Truncated responses | If the destination cuts off mid-response (short of `Content-Length`, missing the final chunk of chunked, reset), the client side is also cut so it does not look like a complete response: HTTP/1.1 closes the connection short (for chunked, the final chunk is not sent), HTTP/2 sends RST_STREAM, HTTP/3 sends RESET_STREAM. The same applies through `compress` (the compression end is not added). For HTTP/1.0-style responses without a length (ending by closing the connection), whether the destination cut off midway cannot be known |
| Truncated requests | If the client cuts off mid-body (HTTP/1.1 disconnect, HTTP/2 RST_STREAM, HTTP/3 reset), the upstream connection is also cut without finishing the body, and it is not passed to the destination as a complete request |
- The access log (`event: "http.access"`) is one line per request: `rule`, `route` (`(none)` if nothing matched), `service`, `backend`, `client`, `method`, `host`, `path` (query not included), `query` (the query, without `?`, empty if none; since v0.3.8. Values of parameters with names likely to be secret (names containing `token`, `code`, `state`, `password`, `secret`, `key`, `signature`, `auth`, `session`, etc.) are replaced with `REDACTED`, so that GitLab's `private_token`, OIDC's `code` / `state` and the like are not left in logs), `protocol` (`HTTP/1.1` / `HTTP/2.0`), `status`, `duration_ms` (until the response body is fully sent), `bytes_in` (`Content-Length`), `bytes_out` (response body), `user_agent`, `sni`, `tls_version`, `refused_by`, `middleware`, `user`, `auth_error`. The destination is `global.access_log`.
  - `refused_by` / `middleware` (v0.3.20): the kind of the middleware that refused the request (`ip_allow`, `basic_auth`, `forward_auth`, `oidc`, `crowdsec`, `rate_limit`, `in_flight`, `buffering`, `circuit_breaker`, `respond`, …) and its name in the settings. Set only when a middleware answered with an error (4xx / 5xx), empty otherwise; redirects and `respond` with 2xx are not included.
  - `user` (v0.3.20): the user name `basic_auth` let in.
  - `auth_error` (v0.3.20): why `basic_auth` refused: `no_credentials` (no `Authorization`), `unknown_user`, `bad_password`, `unavailable` (the users file cannot be read). Neither the name tried nor the password is logged.
- `GET /metrics` exposes `rproxy_http_requests_total{protocol,listen,route,code}` (`code` is `2xx` etc.), `rproxy_http_request_duration_seconds{protocol,listen,route}` (histogram; buckets 5ms–10s), `rproxy_http_limited_total{protocol,listen,route,middleware}` (number refused by `rate_limit` / `in_flight`), and `rproxy_http_blocked_total{protocol,listen,route,middleware}` (number refused by `crowdsec`). With `global.crowdsec`, also `rproxy_crowdsec_decisions` (number of addresses and ranges blocked by decisions) `rproxy_crowdsec_synced` (1 once fetched from LAPI at least once), `rproxy_crowdsec_connected` (1 when the last fetch succeeded; v0.3.20) and `rproxy_crowdsec_last_success_timestamp_seconds` (time of the last successful fetch; v0.3.20; absent until one succeeds). Paths are not used as labels.
- Middlewares act on the request in the order written in the route's `middlewares`, and on the response in reverse order (same as Traefik). If a middleware along the way returns a response (redirect, `respond`, refusal), processing does not go further. The response side of the middlewares passed so far (`headers` etc.) also acts on that response.
- Available middlewares (v0.3.1; `features.middlewares`):
  - `redirect_scheme`: redirects requests received with a scheme different from `scheme` to `scheme://` with the same host, path and query. `port` is omitted if it is the default port (80 / 443).
  - `redirect_regex`: if `http://host[:port]/path?query` (the received URL) matches `regex`, redirects to `replacement` (`$1` and `${name}` can be used). If it does not match, proceeds to the next.
  - The redirect status code is 301 if `permanent`, otherwise 302. For methods other than GET / HEAD, 308 / 307 (keeping the method and body).
  - `respond`: responds with `status`, `body` and `content_type` (default `text/plain; charset=utf-8`). Used for routes without `service` (blocking or maintenance pages).
  - `ip_allow`: 403 if the connecting IP is not in `source_range`.
  - `headers`: `set` (an empty value deletes) and `remove` for `request` / `response`. `frame_deny` (`X-Frame-Options: DENY`), `content_type_nosniff`, `referrer_policy`, `csp`. `hsts` is added only when received over HTTPS. `cors` adds `Access-Control-Allow-Origin` (and `Access-Control-Allow-Credentials` if `allow_credentials`) and `Vary: Origin` when `Origin` is in `allow_origins` (`*` allowed), and rproxy answers preflights (`OPTIONS` with `Access-Control-Request-Method`) with 204.
  - `rate_limit`: token bucket. Averages `average` requests per `period` (default `1s`), up to `burst` at once (default 1; as in Traefik, omitting it lets only one through at a time). Exceeding gives 429 with `Retry-After` (seconds). `source` is `ip` (default; the client IP reflecting `global.trusted_proxies`) or `header:<name>` (per value of that header; the client IP if the header is absent).
  - `in_flight`: up to `amount` concurrent requests per client IP (429 beyond that). A slot is freed when the response body is fully sent (for WebSocket, when the connection ends).
  - `crowdsec`: 403 if the client IP (reflecting `global.trusted_proxies`) is in the LAPI decisions. With `appsec: true`, the request is then queried against AppSec, and if 403 is returned, 403 (sends `X-Crowdsec-Appsec-Ip` / `-Uri` / `-Host` / `-Verb` / `-Api-Key` / `-User-Agent` / `-Http-Version` and the original headers; the body is sent only when `Content-Length` is 1 MiB or less, and larger or length-less bodies are queried with headers only). `on_error` (default `allow`) decides whether to pass or return 403 when nothing has ever been fetched from LAPI and when AppSec cannot be queried (3-second timeout, responses other than 200 / 403).
  - `rate_limit` / `in_flight` counts reset when the rule's `http` changes. Up to 100,000 sources are remembered per middleware (beyond that, the least recently used half is forgotten), and buckets that have refilled are periodically discarded.
  - `strip_prefix`: if the path starts with one of `prefixes` (earlier ones take precedence), it is removed and `X-Forwarded-Prefix` is added. `add_prefix`: prepends to the path. `replace_path`: replaces the path and puts the original path in `X-Replaced-Path`. `replace_path_regex`: replaces only when it matches (also `X-Replaced-Path`). The query is kept.
- Middlewares available since v0.3.2:
  - `compress`: compresses responses with `br`, `zstd` or `gzip` according to the client's `Accept-Encoding`. `encodings` (default `[br, zstd, gzip]`) are the formats used and their priority (order when `q` values are equal). Left as-is: responses whose `Content-Length` is smaller than `min_size` (default 1024 bytes), responses that already have `Content-Encoding`, images (except SVG), video, audio, `font/woff*`, already-compressed formats (zip, gzip, zstd, pdf, etc.), `text/event-stream`, gRPC, `Cache-Control: no-transform`, and HEAD, 204, 206, 304. When compressed, `Content-Length` is removed, `Vary: Accept-Encoding` is added, and a strong `ETag` becomes weak `W/`. The body is compressed and sent as it flows (long-lived responses are not stalled).
  - `buffering`: reads the request body fully first. Exceeding `max_request_body` (bytes) gives 413 (immediately if known from `Content-Length`, otherwise while reading), and nothing is sent to the destination. A fully read body can be resent by `retry`.
  - `retry`: when the destination cannot be connected to or does not respond (cases that become 502 / 504), resends to the next destination. `attempts` is the count including the first attempt, and `initial_interval` (default `100ms`) is the first wait, doubling each time. Resending happens only for idempotent methods (GET, HEAD, OPTIONS, PUT, DELETE, TRACE) with no body or a body fully read by `buffering` (Upgrades such as WebSocket are not resent). 5xx returned by the destination is not retried.
  - `circuit_breaker`: when the ratio of 5xx responses (including 502 / 504) within `window` reaches `failure_percent` or more (evaluated when there are 10 or more), returns 503 without sending to the destination for `recovery`. After `recovery`, lets one request through; if it succeeds, normal operation resumes, and if it fails, it stops again for `recovery`. State is logged as `event: "http.breaker"`. Counts reset when the rule's `http` changes.
  - `errors`: if the response status code falls within `status` (a range or value such as `"500-599"` or `"404"`), GETs `path` from `service` (`{status}` is replaced with the status code) and returns its body and headers. The status code stays the original. If the page cannot be fetched, the original response is returned. For maintenance pages, temporarily add a `respond` route with a higher `priority`, or use an `errors` page.
- Authentication middlewares (v0.3.2, #59). They act on all HTTP/1.1, HTTP/2 and HTTP/3 requests:
  - `basic_auth`: lets through only users in `users_file` (htpasswd format; reads bcrypt `$2y$` (`htpasswd -B`), `$apr1$` (`htpasswd`'s default) and `{SHA}`; if there are other formats or plaintext lines, the whole file is treated as an error). Otherwise 401 with `WWW-Authenticate: Basic realm="<realm>"` (`realm` default `rproxy`).
    - The `Authorization` of authenticated requests is not passed to the destination (pass it with `keep_authorization: true`; choose this to match Traefik's default `removeHeader: false`). Setting `user_header` (e.g. `X-Forwarded-User`) passes the user name in that header (a header of the same name sent by the client is removed).
    - bcrypt verification runs on a separate thread, and successful combinations are remembered (forgotten when the file changes).
  - `forward_auth`: sends a `GET` to `address` for each request and lets it through on 2xx (same as Traefik's forwardAuth).
    - The auth server receives the client's headers (only the names in `request_headers` if set; hop-by-hop headers and `Host` excluded), plus `X-Forwarded-Method`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri` (path and query) and `X-Forwarded-For`. With `trust_forward_header: false` (default), `X-Forwarded-*` sent by the client are discarded and re-added; with true, received values are kept (`X-Forwarded-For` gets the peer appended).
    - On 2xx, headers from the auth server's response listed in `response_headers` replace headers of the same name in the request to the destination. Anything other than 2xx (401, a 302 redirect to a sign-in page, etc.) is returned to the client as-is.
    - If the auth server cannot be connected to, 502; if it does not answer within `timeout` (default `10s`), 504 (`event: "http.error"`). Connections to the auth server are reused.
  - `oidc`: OpenID Connect (Keycloak etc.) sign-in (authorization code flow + PKCE). Protects without oauth2-proxy.
    - Reads `/.well-known/openid-configuration` of `issuer` (e.g. `https://sso.example.com/realms/main`) on first use (on failure, retries after 10 seconds). HTTPS certificates are verified with `ca_file` (Mozilla roots if absent).
    - Register with the provider the client `client_id` (confidential; the secret is the first line of `client_secret_file`, sent via client_secret_basic) and the redirect URI `https://<host><callback_path>` (`callback_path` default `/_rproxy/oidc/callback`). `scopes` are scopes added to `openid` (e.g. `[profile, email]`).
    - Unauthenticated GET / HEAD get a 302 to the provider's sign-in (the original URL is returned to after sign-in; only same-site paths are allowed as return targets). Other methods get 401.
    - `callback_path` and `logout_path` (default `/_rproxy/oidc/logout`) are answered by this `oidc` middleware regardless of which route matched (they need not be included in the route's `match`). Logout deletes the cookie and sends the user to the provider's `end_session_endpoint` with `client_id` and `post_logout_redirect_uri=<scheme>://<host>/` (register it as an allowed URI on the provider side).
    - The ID token signature is verified with JWKS (RS256/384/512, PS256/384/512, ES256/384; for an unknown `kid`, refetched at most once per minute), and `iss`, `aud` (must include `client_id`), `exp` and `nonce` are checked.
    - The session is held in the cookie `cookie_name` (default `_rproxy_oidc`; `HttpOnly`, `SameSite=Lax`, plus `Secure` for HTTPS), encrypted with AES-256-GCM (contents: user name, email, groups, expiry, refresh token). The key is derived from the first line of `cookie_secret_file` (16 characters or more; e.g. `openssl rand -base64 32`). Changing it invalidates all sessions.
    - Once within 30 seconds of the ID token's expiry, it is refreshed with the refresh token and the cookie is reset. If refreshing fails, the user signs in again.
    - Adds `X-Forwarded-User` (`preferred_username`, else `email`, else `sub`), `X-Forwarded-Sub`, `X-Forwarded-Email` and `X-Forwarded-Groups` (values of `groups_claim` (default `groups`; dot-separated paths such as `realm_access.roles` also work), comma-separated) toward the destination. Headers of the same names sent by the client, and rproxy's cookie, are removed. In Keycloak, adding a "Group Membership" mapper to the client populates `groups`.
    - Sign-in, logout and failures are logged as `event: "oidc.login"` / `"oidc.error"` / `"oidc.refresh"`.
  - If a secret file (`users_file`, `client_secret_file`, `cookie_secret_file`) is missing or its content is invalid, `invalid` (for a config file, rproxy does not start). If it cannot be read (permissions), startup continues and requests passing through that middleware get 503. Files are reloaded when they change (within a few seconds) and also on SIGHUP. If a reload fails, the current content stays in use (`reload.secret` warning). For owner and mode, see docs/PERMISSIONS.md.
- `source_ip` is `proxy` or `transparent` (makes the client the source of the connection to the destination). `proxy_v1` / `proxy_v2` cannot be used (`invalid`; pass the client IP with `X-Forwarded-For`). `tls.routes` cannot be used either (`tls_config`; route with `Host(...)`).
- Connection stats (`stats`) are per client connection: `rx_bytes` is bytes from the client and `tx_bytes` bytes to the client.
- `http` can also be stored in the JSON of the DB `options` column (`{"tls", "starttls", "starttls_required", "allow_from", "http", "crowdsec", "targets", "balance", "health_check"}`; `crowdsec` since v0.3.2, `targets` / `balance` / `health_check` since v0.3.3). If `targets` is non-empty, `dist_addr` / `dist_port` are not read (the UI writes `''` / `0`).

## Endpoints

| Method and path | Body | On success | Description |
|---|---|---|---|
| `GET /healthz` | | 200 `ok` | No authentication required |
| `GET /capabilities` | | 200 | `{"version":"0.3.20","source_ip":[...],"transparent":true,"transparent_ipv6":true,"tls_modes":["passthrough","sni","terminate"],"dtls":true,"starttls":["smtp","imap","pop3"],"max_range_ports":20000,"features":{"http":true,"http3":true,"acme":true,"tls_options":true,"middlewares":["redirect_scheme","redirect_regex","ip_allow","headers","strip_prefix","add_prefix","replace_path","replace_path_regex","respond","rate_limit","in_flight","crowdsec","compress","buffering","retry","circuit_breaker","errors","basic_auth","forward_auth","oidc"],"services":["health_check","sticky","balance"]}}`. `version` is the release of this rproxy-api (the `version` in `Cargo.toml`; since v0.3.18, absent on older releases; the UI uses it to check the combination). `features` lists the v0.3 settings this version can run ("v0.3 settings" above). `transparent` in `source_ip` is included only when `IP_TRANSPARENT` is available. `transparent_ipv6` indicates whether transparent can be used on IPv6 listeners (`IPV6_TRANSPARENT`) |
| `GET /openapi.json` | | 200 | The OpenAPI 3.0 definition of this API (same as `docs/openapi.json`). Readable with any token |
| `GET /config` | | 200 | State of the config file (`RPROXY_CONFIG`) ("Config file" above). With `global.crowdsec`, `crowdsec` holds the state of the LAPI connection (v0.3.20): `{"connected":true,"synced":true,"last_success":1790000000,"last_error":null,"last_error_at":null,"failures":0,"decisions":12}`. `connected` is whether the last fetch succeeded, `synced` whether one ever did, `failures` the failed fetches in a row; times are Unix seconds. `rules:read` |
| `POST /config/reload` | | 200 | Reloads and applies the config file immediately and returns the result: `{"added","removed","changed","unchanged","failed","restart_needed":[...],"files":[...],"rules","warnings":[{"rule","message"}]}`. If there are errors, nothing is changed and `400 {"code":"invalid","error","errors":[...],"warnings":[...]}` is returned (`errors` is the result of the same validation as `--check-config`). Without a config file, `409 no_config`. Requires the `admin` scope (if no token file is used, anyone can use it like the other endpoints). By default only requests arriving over the Unix socket (`RPROXY_API_SOCKET`) are accepted, and TCP gets `403` (`RPROXY_API_RELOAD_UNIX_ONLY=false` accepts TCP too). Same processing as file-change detection and SIGHUP, and they never run concurrently. Recorded in `event=audit` (`action: config.reload`) |
| `GET /interfaces` | | 200 | Addresses usable for listening: `{"interfaces":[{"name":"ens18","addr":"172.16.5.1","family":"ipv4","loopback":false,"link_local":false}, ...],"reserved":[{"protocol":"tcp","addr":"127.0.0.1","port":8080,"purpose":"control API"}]}`. Only interfaces that are up are returned. `reserved` lists addresses rproxy itself uses, which cannot be used for rules |
| `GET /rules` | | 200 | Array of rules |
| `GET /rules/{protocol}/{listen_addr}/{listen_port}` | | 200 | A single rule |
| `POST /rules` | rule | 201 | Starts forwarding. Responds after name resolution and bind have completed |
| `PATCH /rules/{protocol}/{listen_addr}/{listen_port}` | `{"remote_addr","remote_port"` or `"targets"`, `"balance"?,"health_check"?,"udp_idle_secs"?,"tls"?,"starttls"?,"starttls_required"?,"allow_from"?,"crowdsec"?,"extra_listen_addrs"?,"http"?}` | 200 | Changes the destination. Including `extra_listen_addrs` replaces the additional listen addresses entirely (`[]` removes all; omitted keeps the current ones): only added addresses are opened and only removed addresses are closed (other addresses, and connections open on removed addresses, are kept). For rules listening on `::`, changes that toggle whether there are additional addresses (dual-stack vs. IPv6 only) are `unsupported` (recreate the rule). The destination (`remote_addr` / `remote_port` or `targets`, `balance`, `health_check`) is replaced together every time: an omitted `balance` becomes `round_robin`, an omitted `health_check` becomes none. To go back to a single destination, send `remote_addr` / `remote_port` (`"targets": []` may be included). Including `crowdsec` enables or disables disconnection by decisions (from the next connection). Takes effect immediately from new connections. Including `tls` replaces the whole TLS configuration (specify `starttls` together; omitting it means no STARTTLS). With `http`, the L7 settings are replaced as a whole (from the next request; adding `http` to a rule without it is `unsupported`; "v0.3 settings" above). `source_ip` and the port range cannot be changed: sending `source_ip` or `listen_port_end` with a value other than the current one is `unsupported` (the same value is accepted; to change them, re-create the rule) |
| `DELETE /rules/{protocol}/{listen_addr}/{listen_port}?drain_secs=N` | | 204 | Stops forwarding. Existing connections are cut immediately. With `drain_secs`, waits that many seconds for existing connections to finish before cutting them |
| `GET /acme` | | 200 | ACME state (docs/en/ACME.md): `{"accounts":[{"name","directory","contact","eab","allowed_names","registered"}],"dns_providers":[{"name","type","zones","allowed_names"}],"resolvers":[{"name","account","challenge","dns_provider"}],"certificates":[{"resolver","domains","state","not_after","renew_at","next_attempt","error"}],"rate_limit":{"orders","period_secs","used"}}`. Neither secrets nor where they are kept are shown. `rules:read`. `404` without `global.acme` |
| `POST /acme/renew` | `{"resolver","domains"}` | 202 | Renews that certificate now (within `rate_limit`; see `GET /acme` for the result). `acme:write`; like `POST /config/reload`, only over the Unix socket by default (`RPROXY_API_RELOAD_UNIX_ONLY`). `404` when no rule uses it. `event=audit` (`action: acme.renew`) |
| `POST /acme/accounts/{name}/register` | | 200 | Creates the account at the CA (or finds the one of its key). Scope and Unix socket as for `POST /acme/renew` |
| `POST /acme/accounts/{name}/deactivate` | | 200 | Deactivates the account at the CA and moves its key aside (`<key_file>.deactivated`; the next order creates a new account). Scope and Unix socket as for `POST /acme/renew` |
| `GET /metrics` | | 200 | Prometheus format. Requests on `http` rules are in `rproxy_http_requests_total`, `rproxy_http_request_duration_seconds` and `rproxy_http_limited_total`; upstream health checks in `rproxy_http_server_up` and `rproxy_http_service_down` ("v0.3 settings" above); every destination down in `rproxy_rule_all_targets_down`; the CrowdSec LAPI in `rproxy_crowdsec_connected`; log lines left out in `rproxy_log_suppressed_total` |

When putting an IPv6 `listen_addr` in a path, URL-encode it.

## Errors

On failure, responses take the following shape.

```json
{"error": "address already in use (os error 98)", "code": "bind_failed"}
```

| `code` | HTTP | Meaning |
|---|---|---|
| `unauthorized` | 401 | Token missing, not matching, or expired |
| `forbidden` | 403 | Outside the token's scopes or `allow_listen_ports` |
| `invalid` | 400 | Invalid body or path |
| `tls_config` | 400 | Invalid combination of TLS settings, or certificate/key/CA files cannot be read |
| `unsupported` | 400 | A setting not usable in this environment (`transparent` etc.), or a field that cannot be changed |
| `not_found` | 404 | No such rule |
| `already_exists` | 409 | A rule with the same key already exists |
| `static` | 409 | Fixed rules cannot be modified or deleted via the API |
| `reserved` | 409 | Overlaps the address and port of rproxy's own control API (checked including `0.0.0.0` / `::` and port ranges) |
| `bind_failed` | 409 | The listen port cannot be opened |
| `resolve_failed` | 502 | Name resolution of the destination failed and there is no cache |
| `internal` | 500 | Other |

## Relationship between the API, config file and UI (DB)

rproxy rules have three origins. All appear in `GET /rules`.

| Origin | `origin` | Source of truth | How to change |
|---|---|---|---|
| Config file (`RPROXY_CONFIG`) | `static` | The file | Edit the file (applied automatically). The API gives `409 static` |
| UI (TCP-UDP-rproxy-ui) | `dynamic` | The UI's DB (`forward_rules`) | From the UI. The UI writes to the DB and then calls the rproxy API. rproxy restores from the DB at startup |
| Calling the API directly (CI, scripts) | `dynamic` | rproxy's memory only | From the API. Not written to the DB, so it disappears when rproxy restarts |

- Create long-lived rules with the config file or the UI (DB). Treat rules created by calling the API directly as temporary (CI preview environments, etc.).
- The UI does not edit rules that are not in the DB. Rules created via the API do not appear in the UI list, and rules in the DB but not in rproxy show as "missing" in the UI.
- When using the API directly, use a token whose scopes and `allow_listen_ports` separate it from the UI's rules (authentication in "Basics").

## Restore at startup

With `--database-url mysql://user:pass@host:port/db`, all rules in the `forward_rules` table are loaded and started at startup. The DB user only needs the `SELECT` privilege. Rules that fail are registered as `failed`, and the remaining rules are started. Rules that became `failed` because of a name resolution failure start automatically once re-resolution succeeds.

The table definition is managed in `db/` of the UI repository. The columns rproxy reads are `protocol`, `src_addr`, `src_port`, `src_port_end`, `dist_addr`, `dist_port`, `source_ip`, `udp_idle_secs`, `options`. If `options.targets` (multiple destinations) is present, `dist_addr` / `dist_port` are not used. Rows with `options.enabled` set to `false` (rules paused in the UI) are not created at startup (counted in the `restore.paused` log).
`options` is JSON: `{"tls": <TLS>, "starttls": "smtp" | "imap" | "pop3" | null, "starttls_required": bool, "allow_from": [<CIDR>, ...], "http": <L7>, "crowdsec": bool}` (`allow_from`, `http` and `crowdsec` can be omitted). If an old table lacks these columns, default values are used.
