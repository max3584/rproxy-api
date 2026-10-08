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
          allow_rulesets: [ci/]             # v0.4: name prefixes of the rule sets it may PUT / DELETE (default: any)
          expires: 2027-03-31               # valid until this date (UTC)
          persist: true                     # v0.4 (#144): store the rules it creates in rproxy_rules (default false)
      ```

    - Scopes: `rules:read` (`GET /rules`, `/interfaces`), `rules:write` (`POST` / `PATCH` / `DELETE /rules`), `metrics:read` (`GET /metrics`), `acme:write` (creating and changing rules with ACME certificates, and `POST /acme/...`; docs/en/ACME.md), `admin` (everything). `GET /capabilities` can be read with any token. Insufficient scope gives `403 forbidden`.
    - Creating, modifying and deleting rules is recorded in `event: "audit"` logs (`token`, `client`, `action`, `rule`, `outcome` (`ok` / `error` / `forbidden`), and `code` on failure). `client` is the sender's IP (`unix` over the Unix socket).
    - Refused requests are recorded in `event: "audit"` too (with `client`, `method` and `path`; the token itself is never logged): a missing, unknown or expired token (401) as `outcome: "unauthorized"` with `reason` (`missing` / `invalid` / `expired`, or `client_cert` when the client certificate bound to the token is missing), a lockout (429) as `outcome: "locked_out"`, a missing scope (403) as `outcome: "forbidden"` with `token` and `scope`. So that the log does not overflow, refused requests are logged up to 20 lines in a row per sender, then one line a second. `suppressed` in a line is the number of lines left out for that sender before it (the total is `rproxy_log_suppressed_total` in `/metrics`).
  - Multiple tokens can be valid at the same time. To rotate, list both the old and new ones, then remove the old one later.
  - On SIGHUP the token file is reloaded.
- If `--api-addr` includes a non-loopback address, `--token-file`, `--tls-cert` and `--tls-key` are all required. If any is missing, startup is refused.

### Control API hardening (v0.4, #167)

Hardening of the TCP control API: client certificates (mTLS), token expiry notices, and locking out sources that keep failing authentication. **The Unix socket is outside all of it** (it has no TLS and is guarded by the socket file's permissions; it is never locked out).

| Flag / environment variable | Default | Meaning |
|---|---|---|
| `--tls-client-ca` / `RPROXY_TLS_CLIENT_CA` | none | CA (PEM, may hold several) verifying client certificates. Needs `--tls-cert`. Re-read on SIGHUP and by the certificate file check (`RPROXY_CERT_CHECK_SECS`) |
| `--tls-client-auth` / `RPROXY_TLS_CLIENT_AUTH` | `none` | `none`, `optional` (verified when presented; connections without one use tokens) or `required` (connections without a valid certificate fail the TLS handshake). `optional` / `required` need `--tls-client-ca` |
| `--token-warn-days` / `RPROXY_TOKEN_WARN_DAYS` | `14` | `token.expiring` is logged when a token's `expires` is closer than this many days (1-3650) |
| `--api-lockout-failures` / `RPROXY_API_LOCKOUT_FAILURES` | `20` | A source whose failed authentications (401) within `window` reach this is locked out. `0`: never |
| `--api-lockout-window` / `RPROXY_API_LOCKOUT_WINDOW` | `1m` | Counting window (1s-24h) |
| `--api-lockout-duration` / `RPROXY_API_LOCKOUT_DURATION` | `5m` | How long a source stays locked out (1s-24h) |
| `--api-lockout-exempt` / `RPROXY_API_LOCKOUT_EXEMPT` | none | Sources never counted nor locked out (comma-separated CIDRs; a controller behind NAT and the like). Connections with a verified client certificate (mTLS) are not locked out either, so an attacker guessing from the same address cannot lock out an admin or controller holding a valid certificate (security review M4). Token-only connections still get `429` before the token is looked at while locked out |

**Client certificates (mTLS)**: give an entry of the token file (YAML) a `client_cert`. Its value is the certificate's name, compared exactly with the DNS or URI subjectAltNames (the subject CN when there is none).

```yaml
tokens:
  - name: ui
    client_cert: ui.rproxy.internal      # the certificate alone (no Authorization needed)
    scopes: [rules:read, rules:write, metrics:read]
  - name: gateway-controller
    sha256: 9f86d0...
    client_cert: spiffe://cluster.local/ns/rproxy/sa/controller   # both the token and the certificate
    scopes: [rules:read, rules:write]
```

- Either `sha256` or `client_cert` is required. **With both, both are required**: a matching token on a connection whose certificate lacks that name gives `401` (`reason: "client_cert"` in the audit log). An entry with only `client_cert` authenticates by the certificate alone (two entries without `sha256` cannot share a `client_cert`).
- A request with `Authorization: Bearer` is checked by that token (an unknown token gives `401` even if a certificate-only entry would match). Without it, a certificate-only entry is looked up by the certificate's names.
- Only certificates issued by the `--tls-client-ca` CA (valid, for client authentication) pass; others fail the handshake.
- A token file with `client_cert` while `--tls-client-auth` is `none` is a configuration error that stops the startup (on a SIGHUP reload the current tokens stay). Entries that cannot be used are not silently ignored. Plain HTTP and the Unix socket have no certificate, so certificate-only entries cannot be used there.
- Audit lines (`event = "audit"`) carry `auth` (`token`, `cert` or `token+cert`).

**Token expiry**:

- At startup, on SIGHUP and once a day, tokens whose `expires` is closer than `--token-warn-days` are reported as `token.expiring` (`token`, `expires`, `days_left`) and expired ones as `token.expired` (`token`, `expires`), at `warn`, once per token each time its state changes. A token is valid until the end (UTC) of its `expires` day.
- `/metrics` has `rproxy_token_expiry_timestamp_seconds{token}` (when it stops being valid, Unix seconds).

**Locking out failing sources** (on by default: 20 failures in 1 minute lock out for 5 minutes):

- On the TCP control API, `401`s are counted per source IP (IPv6 grouped by /64). When `failures` is reached within `window`, the source's requests are refused for `duration` with `429 locked_out` without looking at the token (`Retry-After` has the seconds left). `/healthz` and `/readyz` are never refused. `403` (missing scope) is not counted.
- Locking logs `api.lockout` (`client`, `failures`, `until` (Unix seconds), `duration_secs`; `warn`), unlocking `api.unlock` (`client`). Refusals while locked out are `event = "audit"` with `outcome: "locked_out"` (thinned out per source like other refusals).
- `/metrics` has `rproxy_api_lockouts_total` (lockouts) and `rproxy_api_locked_sources` (sources locked out now).
- Up to 4096 sources are remembered (when full, the oldest not locked out are forgotten first), in memory only (a restart forgets them).
- Good clients behind the same IP are locked out too. A UI on the same host is unaffected when it connects over the Unix socket.

**Rotating tokens and certificates** (without a gap):

1. Add the new token (`sha256`) to the token file and SIGHUP (`systemctl reload rproxy-api`). Both old and new work meanwhile.
2. Switch the clients (UI, CI, ...) to the new token.
3. Remove the old token from the file and SIGHUP.

- With `expires`, `token.expiring` reports it before it runs out (`--token-warn-days`).
- For client certificates, issue a new certificate with the same name and deploy it to the client (the token file stays). To change the name: add an entry with the new name, switch the client, remove the old entry (SIGHUP each time).
- To replace the CA: put both old and new CAs in the `--tls-client-ca` file and SIGHUP, move the clients to certificates from the new CA, then remove the old CA and SIGHUP.

**The UI side (TCP-UDP-rproxy-ui)** (the contract for the UI to implement):

| UI environment variable / node key in `nodes.yaml` | Meaning |
|---|---|
| `RPROXY_API_CA_FILE` / `ca_file` | CA (PEM) verifying the rproxy control API's server certificate, for `https://` with a non-public CA |
| `RPROXY_API_CERT_FILE` / `cert_file` | The client certificate the UI presents (PEM, intermediates following it) |
| `RPROXY_API_KEY_FILE` / `key_file` | Its private key (PEM), readable only by the UI's user |

- `RPROXY_API_URL` (a node's `url`) is `https://`. `unix:` uses no certificate (authenticate with a token).
- With `cert_file` / `key_file` matching a certificate-only entry of rproxy (e.g. `client_cert: ui.rproxy.internal`), `RPROXY_API_TOKEN` (`token_file`) may be left out. For an entry with both `sha256` and `client_cert`, give both.
- Only one of `cert_file` / `key_file` is a UI configuration error. When the files change (renewal), new connections read them again (or restart the UI).
- On `429 locked_out`, do not resend for `Retry-After` and show that requests are blocked for a while after repeated authentication failures. Do not repeat `401`s automatically (they count towards the lockout).
- `features.client_cert_auth` in `GET /capabilities` says whether rproxy supports client certificates.

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
- up / down: if `health_check` is set, its result (up until the first check). Even without it, a destination that refuses a TCP connection (or does not respond within 5 seconds) is skipped as down (ejected) for 10 seconds, and the same connection is retried on the next destination. For UDP, a destination that returns ICMP unreachable is likewise ejected. How many failures, how long and how many destinations at once can be changed with the v0.4 `outlier_detection` ("v0.4 settings" below).
- `backup` destinations are used only when all other destinations are down. If all are down, down destinations are also tried in order (connections are not refused).
- An existing UDP session moves to the next destination when its own destination goes down (`conn.retarget`, `reason: target down`). With `failover`, existing sessions stay where they are even when a higher destination comes back.
- If some destinations cannot be resolved, the rule still works as long as others resolve (unresolved destinations are re-resolved later). If none resolve, the result is `resolve_failed` as before.
- `tls.routes` (destination per server name) remain one per route as before. `targets` is the destination for non-matching names (and for no server name).
- State changes are logged as `event: "target.down"` (`reason: health_check` / `outlier`, `error`; `outlier` also has `cause` (`connect`, `refused`, `short_lived`), `ejection_secs` and `ejections`) / `"target.up"` (`reason: health_check` / `outlier`). Up to v0.3 a failed connection was `reason: connect`, and there was no `target.up` when the cooldown ended. The rule's `stats.targets` holds per-destination `[{"addr","port","backup"?,"up","connections","total_connections","resolved","ejected_until","ejections"}]` (only when there are 2 or more `targets` or a `health_check`; `ejected_until` is Unix seconds while ejected, null otherwise), and `/metrics` exposes `rproxy_target_up{protocol,listen,target}` (1 / 0) and `rproxy_target_connections{protocol,listen,target}`.
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
| `client_auth` | Client certificate verification (mTLS). `mode` is `none` (default) / `optional` (verify if sent) / `required` / `optional_no_verify` (#238; see "`optional_no_verify`: client certificates not verified" below). `optional` and `required` require `ca_file`. `ca_file` is the root CA (trust anchor). `chain_file` holds intermediate CAs for client certificates, filling in the verification path for clients that do not send intermediates (not used as trust anchors). TLS and DTLS are verified by the same rules |
| `alpn` | ALPN offered to clients with `terminate` (tcp only) |
| `upstream` | The destination side for `terminate`. `tls: true` re-encrypts (TLS for tcp, DTLS for udp). `server_name` (default: the destination host name), `ca_file` (default: Mozilla root certificates), `insecure_skip_verify` (no verification; for testing), `cert_file` / `chain_file` / `key_file` (client certificate to the destination and its intermediate CAs) |

### `optional_no_verify`: client certificates not verified (#238)

`tls.client_auth.mode: optional_no_verify` asks for a client certificate but accepts the connection without one, or with one that does not verify (the Gateway API's `AllowInsecureFallback`). It works for `tcp` `terminate` (`http` rules and HTTP/3 included) and DTLS termination on `udp`. Available when `features.client_auth_modes` of `GET /capabilities` lists `optional_no_verify`.

```json
"client_auth": {"mode": "optional_no_verify", "ca_file": "/etc/rproxy/clients-root.pem"}
```

- `ca_file` may be left out. With it, a presented certificate is checked against it and the outcome (`SUCCESS` / `FAILED`) is told as below; without it, a presented certificate is always `FAILED`. `chain_file` only with `ca_file`.
- A client that sends a certificate must still prove it holds the key (the handshake signature). Chain, validity and CA are not checked (rproxy refuses nobody).
- How it is told:
  - `http` rules (with `client_auth`, any mode): the backend gets `X-Client-Verify: SUCCESS | FAILED | NONE` (the values of nginx's `$ssl_client_verify`) and, with a certificate, `X-Forwarded-Client-Cert: Hash=<SHA-256 hex>;Subject="<RFC 4514 subject>"` (Envoy's form; `Subject` only for a certificate that verified). `forward_auth` requests and `mirror` copies get the same values. The access log has `client_cn` and `client_verify`.
  - **`X-Client-Verify` and `X-Forwarded-Client-Cert` sent by a client are always removed, before the middlewares, on every rule** (plain and HTTPS rules without `client_auth`, HTTP/1.1, HTTP/2, HTTP/3, Upgrades, `forward_auth` and `mirror` included), like Envoy's SANITIZE: with one HTTPRoute on an mTLS 443 and a plain 80, port 80 cannot forge them. `mirror` copies also get the same `X-Forwarded-For`, `X-Real-IP` and `X-Forwarded-*` as the request to the backend.
  - L4 termination: `client_cn` and `client_verify` in the `conn.open` log. With `source_ip: proxy_v2`, `verify` of the PROXY v2 SSL TLV is 0 (verified, or no certificate) or 1 (a certificate that did not verify). The CN of a certificate that did not verify is not put in the TLV (`SSL_CN`).
- **Security**: this mode is no authentication. Anyone can connect (without a certificate or with a forged one), so the backend must decide by `X-Client-Verify` (or PROXY v2 `verify`). Let the backend be reached only through rproxy (connected directly, it cannot tell rproxy's headers from a client's). The Gateway API, too, means it for testing and temporary migrations. For authentication use `required`, or `optional` to check certificates when sent.

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

rproxy can also obtain certificates itself through ACME (from v0.3.21: `{"acme": "<resolver>", "domains": [...]}` in `tls.certificates[]`, with `global.acme` in the settings file; the certificates obtained are loaded by the same certificate store, and renewals are applied automatically as described above). See docs/en/ACME.md. Pointing `cert_file` / `key_file` at files obtained by certbot, acme.sh, cert-manager and the like works as before (for certbot's http-01, route `/.well-known/acme-challenge/` with an `http` rule on port 80 to certbot's webroot / standalone port; tokens rproxy is not answering itself go through the routes).

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
| `acme` | State of ACME certificates (`tls.certificates[].acme`); omitted without them. Each element has `resolver`, `domains`, `state` (`pending`: not obtained yet (a self-signed stand-in is served) / `valid` / `renewing`: due for renewal / `error`: the last attempt failed (a certificate obtained earlier stays in use)), `not_after` and `renew_at` (RFC 3339), `next_attempt` (the next attempt after a failure or while `rate_limit` holds it back), `error`, `ari` (the CA's renewal window `start` / `end`; ARI, RFC 9773) |
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
  - `files` (v0.4): `{"owner_check": "strict" | "off", "trusted_dirs": ["/var/run/rproxy-gateway/certs"]}` (default `strict`, no `trusted_dirs`). Files under `trusted_dirs` (else the environment variable `RPROXY_FILES_TRUSTED_DIRS`, separated by `:` or `,`; the settings file wins when both are given), judged by their real path after symbolic links, may be owned by root too (Kubernetes Secret volumes). Paths must be absolute. Certificate, key and secret files that rules and `global` name are used only when they belong to rproxy's user (`rproxy-api`), the group and others cannot write them, and others cannot read keys and secrets ("Owner of the files rules name" in docs/en/PERMISSIONS.md). `off` only to use root-owned files in place (knowing the risk; `degraded` at startup).
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
| ACME certificates | `tls.certificates[]` | `{"acme": "<resolver>", "domains": [...]}` (instead of `cert_file` / `key_file`). The resolver is one of `global.acme.resolvers` in the settings file. Needs the `acme:write` scope; names must be within the `allowed_names` of the resolver's account (and DNS provider), else `400 invalid`. tcp `terminate` only (udp: `tls_config`). docs/en/ACME.md | `acme` (true from v0.3.21) |
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
  - Requests go to the same routes, middlewares and destinations as HTTP/1.1 and HTTP/2 (to the destination as the service's `protocol` says; HTTP/1.1 by default). Bodies are streamed. The access log `protocol` is `HTTP/3.0`.
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
- Talks HTTP/1.1 with destinations (HTTP/2 too with the service's `protocol`; see "L7 and TLS features for the Gateway API" below). `servers` uses weighted round robin by `weight` (default 1). If `url` has a path, it is prepended to the request path. Certificates of `https://` destinations are verified with `ca_file` of the rule's `tls.upstream` (Mozilla roots if absent), and `server_name` / `insecure_skip_verify` / client certificates follow it too. `tls.upstream.tls` is not used (determined by `https://` in the URL; specifying it gives `tls_config`). A service with its own `tls` (#236) uses that instead of `tls.upstream`.
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

rproxy talks HTTP/1.1, HTTP/2 and HTTP/3 with clients and HTTP/1.1 (HTTP/2 with the service's `protocol`, #233) with destinations. In between, it handles things as follows (verified from HTTP/1.1, HTTP/2 and HTTP/3 clients in tests/http_semantics.rs).

| Item | Handling |
|---|---|
| `Cookie` | When split across multiple fields in HTTP/2 / HTTP/3 (Chrome does this), they are joined into one with `"; "` (RFC 9113 §8.2.3 / RFC 9114 §4.2.1). Middlewares (`oidc`, `sticky`, `forward_auth`) read the joined value too |
| `Set-Cookie` | Multiple `Set-Cookie` from the destination are passed to the client one by one as-is (not merged; same through `compress` and `headers`). Attributes such as `Domain` / `Path` / `Secure`, and `Location`, are not rewritten |
| Other headers | Multiple fields with the same name are passed in order, with values as raw bytes (including non-ASCII). `Authorization` is passed |
| Hop-by-hop headers | Removed in both directions: `Connection` and the names listed in it, `Keep-Alive`, `Proxy-Connection`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` (`Upgrade` for WebSocket etc. is re-added and relayed). `Via` and `Forwarded` (RFC 7239) are not added (same as Traefik's and nginx's defaults; `X-Forwarded-*` is used). HTTP/2 destinations (`protocol`) get only `te: trailers`, when the client's `TE` has `trailers` |
| Trailers | Trailers after the body pass both ways as they are between HTTP/2 destinations and HTTP/2 / HTTP/3 clients (gRPC's `grpc-status` and so on; tests/http_semantics.rs). HTTP/1.1 clients get them after a chunked body only when they sent `TE: trailers` |
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
  - The redirect status code is 301 if `permanent`, otherwise 302. For methods other than GET / HEAD, 308 / 307 (keeping the method and body). With `status` (301, 302, 303, 307, 308; #226), that one.
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
  - `retry`: when the destination cannot be connected to or does not respond (cases that become 502 / 504), resends to the next destination. `attempts` is the count including the first attempt, and `initial_interval` (default `100ms`) is the first wait, doubling each time. Resending happens only for idempotent methods (GET, HEAD, OPTIONS, PUT, DELETE, TRACE) with no body or a body fully read by `buffering` (Upgrades such as WebSocket are not resent). 5xx returned by the destination is retried only when listed in `status` (#231).
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

## v0.4 settings

Settings whose shape v0.4.0 settled and implemented (docs/en/DESIGN-v0.4.md; deviations from the design are in its "15. Deviations in the implementation"). In v0.4.0 every item of the table below works, and every v0.4 item of `features` in `GET /capabilities` is true (`performance` lists all its keys, `middlewares` includes `geoip`, `services` includes `outlier_detection`). A wrong shape is `400 invalid`. Everything is optional; leaving it out behaves as v0.3. A wrong combination of control API client certificates (`--tls-client-auth`, `--tls-client-ca`, a token's `client_cert`) is a configuration error that stops the startup, so protection is never silently weaker.

| Item | Where | Shape | features |
|---|---|---|---|
| Labels (#28, #166) | a rule's `labels` | `{key: value}`. Keys: letters, digits and `._/-` (up to 63), values up to 253 characters, at most 16. No effect on behaviour (logs, `/metrics`) | `labels` |
| L4 limits (#165) | a rule's `limits` | `max_connections`, `per_source` (`prefix_v4`, `prefix_v6`, `max_connections`, `new_connections`, `packets` (udp only), `max_sources`). Rates are `{average, period, burst}` (as the L7 `rate_limit`) | `limits` |
| Bandwidth (#166) | a rule's `bandwidth` | `upload`, `download` (`"10Mbps"`, 8kbps-100Gbps), `burst` (`"1MiB"`), `per_source` (`upload`, `download`, `prefix_v4`, `prefix_v6`, `max_sources`). TCP waits, UDP drops | `bandwidth` |
| GeoIP (#168; see "GeoIP" below) | a rule's `geoip`, the `geoip` middleware, `global.geoip` | `allow_countries`, `deny_countries` (ISO 3166-1 alpha-2), `allow_asns`, `deny_asns`, `unknown` (`allow` / `deny`). `global.geoip`: `country_db`, `asn_db` (mmdb), `check_interval`, `log_country`. Country lists need `country_db`, ASN lists need `asn_db` | `geoip`, `geoip` in `middlewares` |
| Passive health checks (#170; see "Passive health checks" below) | a rule's `outlier_detection` (L4; `invalid` on `http` rules), `http.services.<name>.outlier_detection` | L4: `consecutive_failures`, `short_lived`, `ejection_time`, `max_ejection_time`, `max_ejected_percent`. L7: `consecutive_5xx`, `consecutive_gateway_failures`, `failure_percent`, `min_requests`, `window`, `ejection_time`, `max_ejection_time`, `max_ejected_percent` | `outlier_detection`, `outlier_detection` in `services` |
| Performance (#194, #184) | `global.performance` | `workers`, `udp_shards` (1-64 or `auto`), `cpu_affinity` (`none` / `auto` / `"0-3,6"`), `busy_poll_usecs`, `splice` (`enabled`, `after`, `full_reads`, `pipe_size`). Per key: the settings file, then `RPROXY_WORKERS`, `RPROXY_UDP_SHARDS` (a number or `auto`), `RPROXY_CPU_AFFINITY`, `RPROXY_BUSY_POLL_USECS`, `RPROXY_SPLICE*`, then the default. Effective after a restart. See "Performance" below | `performance` (names of the keys that take effect; all of them) |
| Rule sets (#28) | `GET /rulesets`, `GET` / `PUT` / `DELETE /rulesets/{name}` | See "Rule sets, conditions and readiness" below | `rulesets` |
| Conditions (#28) | `conditions` in the rule view | `[{"type","status","reason","message","last_transition"}]`; types `Accepted`, `Programmed`, `ResolvedRefs`, `BackendsHealthy` (see "Rule sets, conditions and readiness" below) | `conditions` |
| Readiness (#28) | `GET /readyz` | No token. `200 {"ready": true}` / `503 {"ready": false, "reason": "starting" \| "draining"}` | `readyz` |
| Diff before change (#169) | `?dry_run=true` (`POST /rules`, `PATCH`, `DELETE`, `PUT /rulesets/{name}`, `POST /config/reload`), `POST /config/plan`, `--check-config --diff` | Answer `{"dry_run","action","change","rule","before","after","diff":[{"path","before","after"}],"warnings"}`; `change` is `none`, `in_place` or `recreate` | `dry_run` |
| Storing API-created rules (#144) | a token's `persist: true`, table `rproxy_rules`, `--node-name` | The view shows `origin: "api"`, `persisted`, `created_by`, `created_at` | `persistence` |
| Control API hardening (#167) | `--tls-client-ca`, `--tls-client-auth`, a token's `client_cert`, `--token-warn-days`, `--api-lockout-failures`, `--api-lockout-window`, `--api-lockout-duration` | `client_cert` instead of a token's `sha256`; with both, both are required. Tokens close to expiry: `token.expiring`; sources failing repeatedly: `429 locked_out` (on by default). See "Control API hardening" above | `client_cert_auth`, `token_expiry`, `api_lockout` |
| Live upgrade, self-update (#174) | SIGUSR2, `POST /admin/upgrade`, `--handoff-*`, `RPROXY_UPDATE*`, `GET` / `POST /admin/update`, `rproxy-api launch` | Hands the listening sockets to a new process within one minor. Self-update verifies signatures (minisign) first. docs/en/UPGRADE.md | `handoff`, `self_update` |

- `limits`, `bandwidth`, `geoip`, `outlier_detection` and `labels` given to `PATCH` replace the current value as a whole (`{}` removes it; left out keeps it). The DB `options` carry the same shape.
- A running rule's `stats` has `limited` (#165) and `counters_since` (#166; Unix seconds when counting started, unchanged by a handoff). `stats.targets[]` has `ejected_until` (null when not ejected) and `ejections` (#170).
- Token rotation: add the new token and SIGHUP, switch the clients, then remove the old token and SIGHUP (with `expires`, `token.expiring` reminds you). Details in "Control API hardening" above.

### Performance (`global.performance`, #194, #184)

```yaml
global:
  performance:
    workers: 8              # tokio worker threads (default: the CPUs the process may use; with a cpu_affinity list, its length)
    udp_shards: auto        # SO_REUSEPORT sockets per UDP port: 1-64 or auto (= workers). Default 1
    cpu_affinity: none      # none, auto (worker i on the i-th CPU), "0-3,6" (workers on the listed CPUs in turn; other threads within the list)
    busy_poll_usecs: 0      # SO_BUSY_POLL of listening sockets (accepted connections inherit it) in microseconds; 0-1000, 0 = off
    splice: {enabled: true, after: 0, full_reads: 4, pipe_size: 0}   # splice(2) for plain L4 TCP (docs/en/PERFORMANCE.md)
```

- Per key: the settings file, then the environment variable / flag (`RPROXY_WORKERS`, `RPROXY_UDP_SHARDS`, `RPROXY_CPU_AFFINITY`, `RPROXY_BUSY_POLL_USECS`, `RPROXY_SPLICE`, `RPROXY_SPLICE_AFTER`, `RPROXY_SPLICE_FULL_READS`, `RPROXY_SPLICE_PIPE_SIZE`), then the default; the keys of `splice` one by one too. All are decided at startup; a changed file shows them in `restart_needed`.
- At startup an `event = "performance"` line gives the values in effect and where each came from (`sources`: `workers=file` and so on). Worker threads are named `rproxy-wrk-<n>`.
- CPUs of a `cpu_affinity` list that do not exist or that the process may not use (cgroups, taskset) are left out with `degraded` (`part: global.performance.cpu_affinity`). A list shorter than `workers` is a mistake.
- `busy_poll_usecs` above `net.core.busy_read` needs `CAP_NET_ADMIN`; when it cannot be set, one `degraded` line is logged and sockets wait as usual.

### Diff before change (dry run, #169)

- `POST /rules?dry_run=true`, `PATCH /rules/...?dry_run=true`, `DELETE /rules/...?dry_run=true`: the same validation as the change itself (the same `400` / `403` / `404` / `409`), and the difference in a `200`. Nothing changes: no listener is opened and no name is resolved (certificates and secret files are read and checked). Scopes, `allow_listen_ports` and `acme:write` apply as for the change itself. Dry runs are not written to the `audit` log.
  ```json
  {"dry_run": true, "action": "update", "change": "in_place", "rule": "tcp/0.0.0.0:443",
   "before": {<the rule's current view>}, "after": {<the shape of a POST /rules body>},
   "diff": [{"path": "remote_port", "before": 80, "after": 8080}], "warnings": []}
  ```
  - `action`: `create`, `update`, `delete`, `none` (no change).
  - `change`: only says how an `update` takes effect: `in_place` (changed without dropping connections; every PATCH change is this, and what PATCH cannot change is `400 unsupported` as in the change itself) or `recreate` (the listeners are rebuilt; current connections are dropped: a PATCH that starts a `failed` rule, a settings file or rule set change PATCH could not make). `create`, `delete` and `none` always have `none` (as the `results` of `PUT /rulesets`; how many connections a delete closes is in `warnings`).
  - `before` is the rule's view (as `GET /rules/...`), `after` the rule's shape (the shape of a `POST /rules` body, without state, counters or `origin`). `diff` compares the shapes: the JSON path of each changed value (keys joined with `.`; arrays as a whole) with both values. A create compares from `{}`, a delete to `{}`.
  - `warnings`: e.g. how many connections a delete would close.
- `POST /config/reload?dry_run=true`: reads the settings file and answers what applying it would change (nothing is applied). `POST /config/plan`: compares the settings in the body (JSON in the settings file's shape) the same way (no file is read; without a settings file, there are no static rules to compare with). Both take the scope (`admin`) and Unix socket rule of `POST /config/reload`.
  ```json
  {"dry_run": true, "added": 1, "removed": 0, "changed": 1, "unchanged": 3, "failed": 0,
   "restart_needed": ["global.trusted_proxies"],
   "changes": [{"rule": "tcp/0.0.0.0:443", "action": "update", "change": "in_place", "diff": [...]}],
   "warnings": [{"rule": "...", "message": "..."}]}
  ```
  - The counts mean what `POST /config/reload` answers (`failed`: created but registered as `failed`: a setting this build cannot run, certificates that do not load, an API rule holding the address). `changes` lists the rules that change (unchanged ones are only counted). `restart_needed` compares `global` with the settings the process started with.
  - Mistakes answer, as applying does, `400 {"code":"invalid","error","errors":[...],"warnings":[...]}`.
- `rproxy-api --check-config [PATH] --diff [--diff-api unix:/path|URL] [--diff-token-file FILE]`: once the check passes, asks the running rproxy with `POST /config/plan` and prints the difference. Asked by default: `RPROXY_API_SOCKET`, else `http://<first RPROXY_API_ADDR (loopback for 0.0.0.0 / ::)>:<RPROXY_API_PORT>` (https with `RPROXY_TLS_CERT`, which is then trusted). The token is a file with one plain line (needs the `admin` scope).
  - `text` output: after the check, one line per change (`+` create, `~` change (with the changed values), `-` delete, `!` a `global` setting that needs a restart) and `plan: N to add, ...`. `json`: the `Report` with `plan` (the answer above).
  - Exit code: 1 for mistakes and failed questions (cannot connect, refused), 0 on success with or without differences.
- Rule sets (`PUT /rulesets/{name}?dry_run=true`, #28) build the difference the same way (`in_place` and `rule_diff` of `config::plan`), and `action` / `change` in their `results` mean the same (`diff` for `update` only).

### Storing API-created rules (#144)

- Rules created by a token marked `persist: true` in the token file (YAML format only; false by default) get `origin: "api"` and are stored in rproxy's table `rproxy_rules`. The UI's table (`forward_rules`) is never written. Do not mark the UI's token (the UI stores its rules in its own DB; they would be stored twice).
- Rows are written before the answer to a create, change or delete. An `api` rule's row is rewritten or deleted whichever token changes or deletes it (so the row follows the rule). A `persist: true` token changing a `dynamic` rule (the UI's, or one of a token that does not store) does not store it.
- View: `api` rules show `persisted` (whether the row is up to date), `created_by` (the token's name) and `created_at` (Unix seconds). When the row cannot be written (the DB is unreachable, the table is missing), the rule keeps running with `persisted: false` and `event = "degraded"` (`part: "db"`) is logged. Without `RPROXY_DATABASE_URL` nothing is stored (`persisted: false`). Each write logs `rule.persist` (`action: save` / `delete`, `token`).
- At startup, the UI's `forward_rules` are restored first, then this node's rows of `rproxy_rules` (`node` = `--node-name` / `RPROXY_NODE_NAME`, default the host name) as `origin: "api"`. When both have the same key, the UI's row is used and `restore.conflict` (warn) is logged. When the table cannot be read, `degraded` (`part: "db"`) is logged and only the UI's rules are restored. Rows with a `spec_version` newer than this build are skipped (`restore.skip`).
- The table definition and GRANT belong in the UI repository's `db/` migrations. The definition rproxy uses:

```sql
CREATE TABLE rproxy_rules (
  node         VARCHAR(255) NOT NULL,   -- RPROXY_NODE_NAME (default: the host name)
  protocol     VARCHAR(3)   NOT NULL,   -- tcp / udp
  listen_addr  VARCHAR(45)  NOT NULL,   -- IPv6 without brackets
  listen_port  INT UNSIGNED NOT NULL,
  spec         JSON         NOT NULL,   -- the rule in the shape of the body of POST /rules
  spec_version INT UNSIGNED NOT NULL DEFAULT 1,
  created_by   VARCHAR(255) NOT NULL,   -- token name
  created_at   DATETIME(3)  NOT NULL,
  updated_by   VARCHAR(255) NOT NULL,
  updated_at   DATETIME(3)  NOT NULL,
  PRIMARY KEY (node, protocol, listen_addr, listen_port)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON rproxy.rproxy_rules TO 'rproxy'@'%';
```

  `spec` is the rule's shape (the shape of a `POST /rules` body, as the dry run's `after`). `spec_version` is the version of how `spec` is read (1 now). Times are written in the DB session's time zone and read with `UNIX_TIMESTAMP`.
### L7 and TLS features for the Gateway API (#224, #226-#236)

Settings for rproxy-gateway (#28) to map the Gateway API's HTTPRoute, GRPCRoute, TLSRoute and BackendTLSPolicy. All are optional; left out, behavior is unchanged. `GET /capabilities` `features` tells whether they are available (`cors`, `mirror` and `replace_host` in `middlewares`, `protocol` and `tls` in `services`, the names below in `http_options`, and `tls_route_targets`).

| Item | Where | Shape | features |
|---|---|---|---|
| Appending headers (#224) | `request` / `response` of `headers` | `add: {name: value}` | `headers_add` in `http_options` |
| Redirect status (#226) | `redirect_scheme`, `redirect_regex` | `status`: 301, 302, 303, 307, 308 | `redirect_status` in `http_options` |
| Route time limits (#227) | `http.routes[].timeouts` | `{"request": "10s", "backend_request": "5s"}` | `route_timeouts` in `http_options` |
| Host rewrite (#228) | middleware `replace_host` | `{"host": "one.example.org"}` | `replace_host` in `middlewares` |
| Per-server middlewares (#229) | `http.services.<name>.servers[].middlewares` | names from `http.middlewares` | `server_middlewares` in `http_options` |
| CORS (#230) | middleware `cors` | `allow_origins`, `allow_methods`, `allow_headers`, `expose_headers`, `allow_credentials`, `max_age` | `cors` in `middlewares` |
| Retry on status (#231) | `retry` | `status: ["500", "502-504"]` | `retry_status` in `http_options` |
| Mirroring (#232) | middleware `mirror` | `{"service": "<name>", "percent": 20}` or `{"service": "<name>", "fraction": {"numerator": 1, "denominator": 3}}` | `mirror` in `middlewares` |
| HTTP/2 to backends (#233) | `http.services.<name>.protocol` | `http1` (default), `h2`, `h2c`, `auto` | `protocol` in `services` |
| Per-service backend TLS (#236) | `http.services.<name>.tls` | `server_name`, `ca_file`, `subject_alt_names`, `cert_file`, `key_file`, `chain_file`, `insecure_skip_verify` | `tls` in `services` |
| Several targets per name (#234) | `tls.routes[]` | `targets: [{addr, port, weight, backup}]`, `balance` (instead of `remote_addr` / `remote_port`) | `tls_route_targets` |
| Client certificates not verified (#238, `AllowInsecureFallback`) | `tls.client_auth.mode` | `optional_no_verify` (see "`optional_no_verify`" above) | `client_auth_modes` |
| Fixed-status servers (#235) | `http.services.<name>.servers[]` | `{"status": 500, "weight": 1}` (instead of `url`) | `server_status` in `http_options` |

Example (one HTTPRoute rule mapped):

```json
{
  "routes": [{
    "name": "r0", "match": "Host(`app.example`) && PathPrefix(`/api/`)",
    "service": "r0", "middlewares": ["r0-hdr", "r0-cors", "r0-mirror", "r0-retry"],
    "timeouts": {"request": "10s", "backend_request": "2s"}
  }],
  "services": {
    "r0": {
      "protocol": "h2c",
      "servers": [
        {"url": "http://10.1.0.5:8080", "weight": 5, "middlewares": ["r0-b0"]},
        {"url": "http://10.1.0.6:8080", "weight": 5, "middlewares": ["r0-b0"]},
        {"status": 500, "weight": 10}
      ]
    },
    "r0-shadow": {"servers": [{"url": "http://10.1.0.9:8080"}]},
    "tls-svc": {"servers": [{"url": "https://10.1.0.7:8443"}],
      "tls": {"server_name": "abc.example.com", "ca_file": "/var/run/rproxy-gateway/certs/0123456789abcdef.crt",
              "subject_alt_names": ["abc.example.com", "spiffe://abc.example.com/test-identity"]}}
  },
  "middlewares": {
    "r0-hdr": {"headers": {"request": {"set": {"X-Header-Set": "v"}, "add": {"X-Header-Add": "v"}, "remove": ["X-Header-Remove"]}}},
    "r0-b0": {"headers": {"request": {"set": {"Backend": "v1"}}}},
    "r0-cors": {"cors": {"allow_origins": ["https://www.foo.com", "https://*.bar.com"], "allow_methods": ["GET", "OPTIONS"],
                         "allow_headers": ["x-header-1"], "expose_headers": ["x-header-3"], "allow_credentials": true, "max_age": 3600}},
    "r0-mirror": {"mirror": {"service": "r0-shadow", "percent": 20}},
    "r0-retry": {"retry": {"attempts": 4, "status": ["500", "502-504"], "initial_interval": "100ms"}},
    "r0-host": {"replace_host": {"host": "one.example.org"}},
    "r0-redirect": {"redirect_regex": {"regex": "^http://([^/:]+)(:\\d+)?/(.*)$", "replacement": "https://$1/$3", "status": 303}}
  }
}
```

- **`add` of `headers`** (#224): when a header of that name exists (names are case-insensitive), the value is appended after its value (several fields joined with `,`) with `,`, as one field (`a` → `a,v`); otherwise it is added. The order is `remove` → `set` → `add`, both towards the backend (`request`) and on the response (`response`).
- **`status` of redirects** (#226): overrides `permanent` and the switch by method (308 / 307 for other than GET and HEAD). Other than 301, 302, 303, 307 and 308 is `400 invalid`.
- **`timeouts` of a route** (#227): `0s` is no limit (the same as leaving it out).
  - `request`: from receiving the request until the response body has been sent (middlewares, `retry` attempts and their waits included). Running out before the response headers gives 504 (`event: "http.error"`, `error: "request timed out"`); after them, the response is cut off (HTTP/1.1 closes the connection, HTTP/2 RST_STREAM, HTTP/3 resets the stream; it never looks complete).
  - `backend_request`: one attempt to a backend, from starting to send until the end of the response body. Running out before the response headers gives 504 (`retry` goes to the next server when it may); after them it cuts off like `request`. For this route it replaces the service's `timeouts.response` (`timeouts.connect` still applies).
  - A relay after 101 (WebSocket and the like) is not counted.
- **`replace_host`** (#228): the `Host` sent to the backend (`:authority` for HTTP/2 backends) becomes `host` (`host[:port]`), over the service's `pass_host_header`. `X-Forwarded-Host` keeps what the client sent. It does not affect `match` (it runs after the route is chosen).
- **Per-server middlewares** (#229): the middlewares in `servers[].middlewares` run only on requests sent to that server, after the route's middlewares (on a `retry` attempt, those of the server tried). On the response they run in reverse, before the response side of the route's middlewares. Allowed kinds: `headers`, `replace_host`, `strip_prefix`, `add_prefix`, `replace_path`, `replace_path_regex` (others are `400 invalid`).
- **`cors`** (#230):
  - `allow_origins`: `https://www.foo.com` (scheme, host and port exactly, case-insensitive), `*` (any), `https://*.bar.com` (`*` matches one or more of any characters, dots included). `*` may only be the first label (`https://*bar.com` would match `evilbar.com`: `400 invalid`; security review L13). `*` with `allow_credentials: true` lets every site make credentialed requests (the `Origin` is echoed, as the Gateway API says), so it logs `config.warning`.
  - A preflight (`OPTIONS` with `Origin` and `Access-Control-Request-Method`) from an allowed origin is answered by rproxy with 204: `Access-Control-Allow-Origin` (`*` when `allow_origins` is `*` and `allow_credentials` is false, otherwise the `Origin`), `Access-Control-Allow-Methods` (`allow_methods` comma-separated; with `*`, the requested method when `allow_credentials`, otherwise `*`), `Access-Control-Allow-Headers` (likewise; with `*` and `allow_credentials`, the value of `Access-Control-Request-Headers`), `Access-Control-Expose-Headers`, `Access-Control-Max-Age` (with `max_age`), `Access-Control-Allow-Credentials: true` (with `allow_credentials`), `Vary: Origin`. A preflight from an origin not allowed is answered by rproxy too, with 204 and no CORS headers (only `Vary: Origin`; it never reaches the backend, which could allow it; #238). An `OPTIONS` without `Origin` is no preflight and goes to the backend.
  - Other requests go to the backend; for an allowed origin the response gets `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Access-Control-Expose-Headers` and `Vary: Origin` (replacing the backend's headers of those names).
  - `cors` of `headers` stays as it was.
- **`status` of `retry`** (#231): when the backend answers one of these statuses (values or ranges like `"500"`, `"502-504"`), that response is dropped and the request is sent again to the next server (picked again by `balance`, so the same one when there is only one; #238). The last attempt's response is returned as it is. When a request may be sent again (idempotent method, no body or one read by `buffering`, not an Upgrade), `attempts` (counting the first) and `initial_interval` (the wait, doubling each time) are unchanged. The Gateway API's `attempts` counts retries, so it maps to `attempts + 1`.
- **`mirror`** (#232):
  - A copy of the request sent to the backend also goes to a server of `service` (a name in `http.services`), as it is after the middlewares before it in the route's `middlewares` (after a header rewrite when written after it). `Host` follows that service's `pass_host_header`.
  - Only the share `percent` (0-100) or `fraction` (`numerator` / `denominator`, `denominator` defaults to 100) is mirrored (both is `400 invalid`; left out, all). The share is kept by count (not random: the n-th request is spread by the golden ratio).
  - The mirror's response is read and dropped; failures, slowness and errors do not affect the client's response (logged as `event: "http.mirror"` at debug). The body is copied as it streams; when the mirror falls behind (64 frames queued) only the mirrored request is cut off.
  - Requests answered by an earlier middleware (redirects, refusals) are not mirrored. A route may have several.
- **`protocol`** (#233):
  - `http1` (default): HTTP/1.1, as before.
  - `h2`: HTTP/2 over TLS (ALPN `h2`) with `https://` servers; 502 when the server does not pick `h2`.
  - `h2c`: HTTP/2 starting with the preface (prior knowledge) with `http://` servers.
  - `auto`: `https://` servers are offered `h2` and `http/1.1` by ALPN and spoken to in what they pick; `http://` servers get HTTP/1.1.
  - `h2` with `http://` servers or `h2c` with `https://` ones is `400 invalid`.
  - An HTTP/2 backend gets multiplexed connections, reused (reconnected on the next request when closed). Past 100 requests on one connection another is opened, up to 8 per server. When there is still no room and a request with a body gets no stream within the server's `SETTINGS_MAX_CONCURRENT_STREAMS`, it waits `timeouts.connect` and gets 504 (security review M6: slow bodies cannot hold every request up). One connection is opened at a time, and requests with room on an open connection never wait for that. Rules with `source_ip: transparent` use a new connection per client.
  - Trailers pass both ways as they are (gRPC's `grpc-status` and so on). When the client's `TE` has `trailers`, `te: trailers` is passed to HTTP/2 backends (other hop-by-hop headers are removed as before).
  - `timeouts`, `retry`, `health_check` (a `GET` over HTTP/2), `outlier_detection` and `sticky` work as with HTTP/1.1 backends. An Upgrade (WebSocket) to an HTTP/2 backend gets 502.
  - gRPC: clients connect to rproxy over HTTP/2 (TLS or h2c). Match services and methods with `Path(`/<package.Service>/<Method>`)` and `PathPrefix(`/<package.Service>/`)`.
- **`tls` of a service** (#236):
  - Used for that service's `https://` servers instead of the rule's `tls.upstream` (fields are not mixed). Also works in plain-HTTP rules (no `tls`).
  - `server_name`: the SNI and the name verified on the certificate (default: the URL's host). `ca_file`: the CA that verifies the backend's certificate (default: the Mozilla roots). `subject_alt_names`: when given, one of the certificate's SAN DNS names or URIs (`spiffe://...` and the like) must be in this list (instead of checking `server_name`; signature and validity are still checked). `cert_file`, `key_file` (and `chain_file`): the client certificate shown to the backend. `insecure_skip_verify`: no verification (for testing).
  - The files are read when the rule is created or changed (a changed file is read again with a rule change; rproxy-gateway names files by their content hash). Ignored on a service with only `http://` servers.
- **`targets` of `tls.routes[]`** (#234): instead of `remote_addr` / `remote_port`, `targets` (the shape of the rule's `targets`, with `weight` and `backup`) and `balance` (`round_robin` (default), `least_conn`, `failover`). One of the two is required (both or neither is `400 tls_config`). A target that cannot be connected to is skipped for the next and left out for 10 seconds (like the rule's `targets`). Works for `passthrough` routes and routes of `sni` rules. Names are re-resolved like the rule's `targets`; in a port-range rule each target's port moves along.
- **`status` of `servers[]`** (#235): with `status` (100-599) instead of `url`, requests that land on that entry (its `weight` share) are answered by rproxy with that status (a body like `500 Internal Server Error`). Not health-checked, not in `outlier_detection` or `sticky` (no sticky cookie). `url` or `status`, exactly one (both or neither is `400 invalid`); no `middlewares`.

### Rule sets, conditions and readiness (for the Kubernetes controller, #28)

The Kubernetes controller (a separate repository, `max3584/rproxy-gateway`) drives rproxy through this API only. The exact shapes are in `docs/openapi.json` (`GET /openapi.json`).

**Rule sets**: send the whole of a set to `PUT /rulesets/{name}` every time and rproxy applies the difference to what runs (declarative; a PUT after a crash puts things right).

- Names: `[a-z0-9]([a-z0-9._/-]{0,251}[a-z0-9])?` (e.g. `k8s/default/web-gateway`). Write the slashes in the path as they are (`PUT /rulesets/k8s/default/web-gateway`).
- Body: `{"generation": <integer>, "rules": [<rules as for POST /rules>...]}` (up to 10,000 rules, a body up to 32 MiB). The same key twice is `400 invalid`.
- Order: everything is checked first; if anything fails, **nothing changes**.
  0. Owner (security review M3): a set belongs to the token that created it (`owner`); another token may `PUT` / `DELETE` it only with `admin` (`403 forbidden`). Names outside the token's `allow_rulesets` (name prefixes) are `403` too: give the controller's token `allow_rulesets: [k8s/]` and other `rules:write` tokens other prefixes, so nobody claims the controller's sets first after rproxy restarts. `generation` is at most 2^53 - 1 (`400 invalid`; what JSON clients read exactly).
  1. `If-Match` (when given): differing from the current etag, or no such set yet, is `412 precondition_failed`. `*` means "the set exists". Takes the quoted value of the ETag header or the body's `etag` as it is (`W/` and comma-separated lists too).
  2. `generation`: lower than the stored one is `409 stale_generation` (the same is fine).
  3. The shape of each rule (the same checks as `POST /rules`; settings this build cannot run are `unsupported`) and rules of the body that overlap each other (`400 invalid`).
  4. Conflicts with rules outside the set: a rule of the settings file with the same key is `409 static`, a rule of another set `409 owned`, a rule made by `POST /rules` or one whose listeners overlap `409 already_exists`, the control API's address `409 reserved`.
  5. The listen ports of every rule created, changed or deleted are within the token's `allow_listen_ports` (otherwise `403`; for a changed rule, what it listens on now too, so narrowing a rule cannot remove listeners outside the range; security review M2); rules with ACME certificates need `acme:write`.
  6. The certificate and secret files of every rule created or changed can be read (`400 tls_config` / `invalid`).
  - A refusal is `{"code","error","errors":[{"index","rule","code","message"}]}`: `code` and `error` (`rules[i]: ...`) are the first problem, `errors` lists every problem with a rule (`index` is its place in `rules`).
- Applying: rules left out of the set are stopped first (connections dropped); a changed rule is changed in place when PATCH can do it without dropping connections (targets, `balance`, `health_check`, timeouts, TLS, `allow_from`, `extra_listen_addrs`, `http`, `labels` and the other v0.4 settings; `change: in_place`), otherwise (port range, `source_ip`, `http` on or off) its listeners are opened again (`recreate`). New rules are created; unchanged running rules are not touched (`none`). A `failed` rule is re-created even when unchanged.
- A rule that cannot bind or resolve its targets is registered as `failed` on its own (the reason in `conditions`) and the rest is applied. The answer is `200` with a result per rule: `{"name","generation","etag","dry_run":false,"results":[{"rule":"tcp/0.0.0.0:443","action":"create|update|delete|none","change":"none|in_place|recreate","state":"running|failed","error"}]}` (in the body's order, then the deleted rules; `delete` has no `state`). The `ETag` header is `etag` in double quotes.
- The etag is `g<generation>-<the first 16 hex digits of the SHA-256 of the rules' normalized JSON in key order>`. It changes with the rules or the `generation`, not with their state (`running` / `failed`).
- `?dry_run=true`: the same checks, then the result without changing anything (`dry_run: true`, the etag the set would have, `diff` for updates). `change` and `diff` mean what "Diff before change" above says.
- Rules of a set appear in `GET /rules` with `ruleset: "<name>"` (`origin` stays `dynamic`). `PATCH` / `DELETE /rules/...` on one is `409 owned` (PUT the set instead); `POST /rules` with the same key is `409 already_exists`.
- `GET /rulesets/{name}`: `{"name","generation","etag","updated_at","updated_by","owner","rules":[<as GET /rules shows them>...]}` (in key order, with an `ETag` header). `updated_by` is the name of the token of the last PUT (empty without a token file). `GET /rulesets` lists the sets by name (`rules` is a count).
- `DELETE /rulesets/{name}?drain_secs=N`: stops the set's rules at the same time and forgets the set (waiting up to `drain_secs` for the connections of each rule). `If-Match` works here too. `204` once every connection has ended.
- Sets live in rproxy's memory only; they are written neither to the DB nor to the settings file. After rproxy restarts, the controller PUTs its sets again once `GET /readyz` answers 200. Changes to sets run one at a time (reads do not wait).
- Logs: `event = "ruleset.apply"` (`ruleset`, `generation`, `etag`, `created`, `updated`, `deleted`, `unchanged`, `failed`, `by`) and `ruleset.delete` (`ruleset`, `rules`); the rules' own `rule.create` / `rule.update` / `rule.delete` carry `ruleset`. `audit` has `action: ruleset.put` / `ruleset.delete` and `ruleset`.

**Labels**: a rule's `labels`. Not used for forwarding; shown in the `rule.create` / `rule.update` logs (`labels: "k=v,k2=v2"`) and in `/metrics` as `rproxy_rule_labels{rule="tcp/0.0.0.0:443",label_tenant="act"} 1` (characters of a key other than letters and digits become `_`; of keys that end up the same, only the first by name). `PATCH` with `labels` replaces them as a whole (`{}` removes them; left out keeps them).

**Conditions**: every rule's view (in a set or not) has these four, in this order (shaped to copy into Gateway API status). `message` is empty when `True`.

| type | `True` reason | `False` reasons |
|---|---|---|
| `Accepted` | `Accepted` | `Unsupported` (a setting this build or environment cannot run; rules from startup or a reload) |
| `Programmed` | `Listening` (`state: running`) | `BindFailed` (the port cannot be opened), `Pending` (waiting to resolve its targets, retried), `Failed` (anything else) |
| `ResolvedRefs` | `ResolvedRefs` | `ResolveFailed` (a target cannot be resolved), `CertificateExpired` (a server certificate expired), `CertificateUnreadable` (a certificate, key or CA cannot be read), `SecretUnreadable` (a middleware's secret file cannot be read) |
| `BackendsHealthy` | `Healthy` | `AllTargetsDown` (every target is down), `ServiceDown` (an `http` service has every server down; names in `message`). A rule that is not running has `status: "Unknown"`, `NotProgrammed` |

- `last_transition` is the Unix second when `status` last changed (a new `reason` or `message` alone keeps it). `Programmed` `True` starts at `started_at`; other changes are noted when the rule is read (`GET /rules`, `GET /rulesets/{name}`, the answer of a PUT). Deleting or re-creating the rule starts it over.
- The existing `state`, `error`, `all_targets_down` and `down_services` stay (the UI uses them).

**Readiness**: `GET /readyz` (no token, like `/healthz`). `200 {"ready": true}` once the startup restore (settings file, DB) is done; before that and once shutting down (also a #174 handoff, and during `RPROXY_SHUTDOWN_DELAY`), `503 {"ready": false, "reason": "starting" | "draining"}`. Failed rules do not make rproxy unready (rules report their state in `conditions`). Liveness stays `/healthz`.

### How L4 limits and bandwidth (#165, #166) behave

`features.limits` and `features.bandwidth` are true (shapes in the table above and sections 4 and 5 of docs/en/DESIGN-v0.4.md).

- `limits` are checked right after accepting (after `allow_from`, `geoip` and `crowdsec`, before TLS and PROXY headers). Over a limit, TCP closes without sending anything and UDP drops the datagram (no new session is made). On `http` rules they apply to the TCP connections (not to HTTP/3). `max_connections` counts TCP connections and UDP sessions (so does `per_source.max_connections`), `new_connections` is the rate of new connections / sessions, `packets` the rate of UDP datagrams (per source).
- Refusals are counted in `stats.limited` and `/metrics` `rproxy_rule_limited_total{protocol,listen,reason}` (rules with `limits`; labelled `protocol` and `listen` instead of `rule`, like the other metrics). They are logged as `conn.limited` (`rule`, `client`, `reason` (`max_connections` / `source_connections` / `new_connections` / `packets`), `transport` (`tcp` / `udp`); up to 20 lines in a row per source, then one a second; `suppressed` counts the lines left out).
- Sources are grouped by `prefix_v4` / `prefix_v6`, and at most `max_sources` are remembered (in 16 tables of 1/16 each; when one is full the oldest source without connections is forgotten; a source with open connections never is, so starting its count over cannot get round the limits (security review L8). While a table is full of such sources, new sources are refused by `limits` (`reason: source_connections`) and share one bucket in `bandwidth`). `max_sources` is at most 1,000,000.
- A `PATCH` of `limits` applies from the next connection / datagram. The rule's connection count is kept, and the per-source counts and buckets too while `prefix_v4`, `prefix_v6` and `max_sources` stay the same. `{}` stops counting (adding limits again counts from then on).
- `bandwidth`: TCP (including `http` rules) is shaped by waiting before reading (nothing is dropped). L4: upload is read from the client, download from the backend; `http` rules: reads from and writes to the client. While waiting, the relay gives its buffer back to the pool. UDP drops the datagrams over the rate, counted in `stats.dropped` and `rproxy_rule_bandwidth_dropped_total{protocol,listen}`. HTTP/3 is not shaped.
- Rates are token buckets (`burst` is the size, default 100 ms worth). The rule's buckets are shared by all its connections, a source's by all of that source's connections. TCP waits until 4 KiB (or `burst`, if smaller) have refilled, then reads. A datagram or read larger than what is left is lent and waited out later (the long-run rate holds).
- splice (#184) is only used on rules without a bandwidth limit; plain TCP of a rule with one is shaped in the user-space copy. When a `PATCH` adds a limit, spliced connections go back to the user-space copy before their next splice, and do not go back to splice when the limit is removed.
- A `PATCH` of `bandwidth` applies to open connections from their next read (the buckets start full).
- Rules without limits pay one relaxed atomic load per read.
- Collecting traffic (#166 5.2): `stats.rx_bytes`, `tx_bytes` and `total_connections` only grow; `stats.counters_since` is when counting started (Unix seconds; changes when the rule is re-created, not on `PATCH`); `stats.limited` is added. `/metrics` has `rproxy_process_start_time_seconds`.

### GeoIP (#168)

```yaml
global:
  geoip:
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb   # a Country or City mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb           # optional
    check_interval: 1m     # how often to look for a changed file (default 1m; 0s: never)
    log_country: true      # add country (and asn) to conn.open and http.access (default false)
rules:
  - {protocol: tcp, listen_addr: 0.0.0.0, listen_port: 25565, remote_addr: 10.0.0.5, remote_port: 25565,
     geoip: {allow_countries: [JP], deny_asns: [64496], unknown: allow}}
```

- No database is bundled. Use MaxMind's GeoLite2 (create an account and fetch it with `geoipupdate`) or any mmdb with the same fields (`country.iso_code`, else `registered_country.iso_code`, and `autonomous_system_number`). The files are read into memory (no mmap) and read again when they changed, every `check_interval` and on SIGHUP (`event: "geoip.reload"`). A version that cannot be read (half written, broken, permissions) keeps the current one (`event: "degraded"`, `part: "geoip"`, once per problem). At startup (and in `--check-config`), a missing file or one that is not an mmdb is a configuration error and rproxy does not start; one that cannot be read for permissions logs `degraded` and rproxy starts, with every client unknown to that database until it can be read.
- Decision: a hit in a `deny_*` list refuses. When any `allow_*` list is given, only a hit in one of them passes (a known country or ASN outside its list refuses, even when the other is not known; security review L18). A client of which nothing the lists need is known (not in the database, private addresses, the database unreadable) gets `unknown` (default `allow`). **An unreadable database also gives `unknown`**: set `unknown: deny` to fail closed. Databases are read up to 1 GiB (larger files are not read).
- L4 (a rule's `geoip`): checked right after accepting, after `allow_from` and before `crowdsec` (before TLS and PROXY headers). TCP connections are closed, UDP datagrams dropped (also those of open sessions; no session is created). HTTP/3: before accepting the QUIC connection. Works on `http` rules too (on the peer's IP). Refusals count in `stats.denied` and log `conn.denied` (`reason: "geoip"`, `country` and `asn` when known; UDP lines are throttled per source like `allow_from`).
- L7 (the `geoip` middleware): checked on the client IP as `global.trusted_proxies` decides it; refusals answer `403` (like `ip_allow`). `http.access` has `refused_by: "geoip"`, `middleware`, `country` and `asn`.
- With `log_country: true`, `conn.open` (TCP and UDP) and `http.access` carry `country` (and `asn`) when known.
- Country lists without `country_db` and ASN lists without `asn_db` are `400 invalid` (a validation error in the settings file). `geoip` given to `PATCH` replaces the lists as a whole, `{}` removes them (nothing is closed; from the next connection / datagram).
- Pairing with CrowdSec: coarse filtering by country / ASN with `geoip`, bans by behaviour with CrowdSec (a rule's `crowdsec: true`, the `crowdsec` middleware). The order is `allow_from` → `geoip` → `crowdsec`. CrowdSec can add the country itself (`crowdsecurity/geoip-enrich`), so rproxy's `log_country` is for reading rproxy's logs alone, e.g. in a SIEM (docs/en/CROWDSEC.md).

### Passive health checks (#170)

Destinations that keep failing in real traffic are ejected for a while (outlier detection). An ejected destination is skipped like one that is down (L4 still tries every destination in order when all are ejected or down, as before), and comes back by itself when the ejection ends (`target.up`, `reason: "outlier"`). One that `health_check` sees up again comes back at once.

**L4** (a rule's `outlier_detection`; allowed with one target, useful with several):

| Key | Default | Meaning |
|---|---|---|
| `consecutive_failures` | `1` | Failures in a row (1-1000): a TCP connection refused or timed out (`cause: connect`), ICMP unreachable for UDP (`refused`), `short_lived` |
| `short_lived` | `0s` (not counted) | TCP connections the destination ended (closed or reset) sooner than this (0s-1m) after connecting count as failures too; a connection then counts as a success when it ends. No effect on UDP |
| `ejection_time` | `10s` | The first ejection (1s-1h) |
| `max_ejection_time` | `ejection_time` | Doubled on each ejection up to this (back to `ejection_time` after this long without an ejection) |
| `max_ejected_percent` | `100` | Share of the destinations that may be ejected at once (0-100; `0`: never) |

- Without the setting (or with `{}`), rproxy behaves as up to v0.3: one failed connection ejects for 10 seconds.
- A destination that fails again while ejected (tried because all are out) has its ejection start over (not counted again).
- A `PATCH` takes effect from the next connection; the destinations keep their counts and ejections (reset when destinations, `balance` or `health_check` change too).

**L7** (`http.services.<name>.outlier_detection`; only services that have it):

| Key | Default | Meaning |
|---|---|---|
| `consecutive_5xx` | `5` | 5xx answers in a row (0: not looked at); gateway failures below count too |
| `consecutive_gateway_failures` | `3` | 502 / 503 / 504, connection failures and `timeouts.response` timeouts in a row (0: not looked at) |
| `failure_percent` | none | Eject when failures (5xx, gateway failures) are at least this share within `window` (1-100) |
| `min_requests` | `20` | Fewest requests in `window` before `failure_percent` counts |
| `window` | `30s` | The window of `failure_percent` (counted afresh each window) |
| `ejection_time` / `max_ejection_time` | `30s` / `5m` | As for L4 |
| `max_ejected_percent` | `50` | Share of the servers that may be ejected at once; by default a service with one server never ejects it |

- Separate from `circuit_breaker` (a middleware that stops the whole service): servers are ejected one by one. Each request to a server counts (each `retry` attempt too, and the pages of `errors` / `forward_auth`).
- An ejected server shows `"ejected": true` in `stats.http.services.<name>` (`up` is false; services with `outlier_detection` are listed even without `health_check`), and `rproxy_http_server_up` is 0. When every server is ejected (`max_ejected_percent: 100`), one that its health check sees up is still used.
- Logs: `target.down` (`reason: "outlier"`, `rule`, `service`, `server`, `cause`: the threshold reached, `consecutive_5xx` / `consecutive_gateway_failures` / `failure_percent`, `ejection_secs`, `ejections`) / `target.up` (`reason: "outlier"`).
- Changing `http` starts the counts over (the `Router` is rebuilt).

## Settings added in v0.4.x

Settings added by patches after v0.4.0 (docs/en/DESIGN-v0.4.x.md; additive shapes ship in patches: "After v0.4.0" in docs/en/RELEASING.md). Everything is optional, and leaving it out behaves as v0.4.0. `features` in `GET /capabilities` tells whether a setting is available.

### Shutting down on SIGTERM (v0.4.1, `features.graceful_shutdown`)

| Flag / environment variable | Default | Meaning |
|---|---|---|
| `--shutdown-delay` / `RPROXY_SHUTDOWN_DELAY` | `0s` | After SIGTERM, keep accepting as before for this long while `/readyz` answers 503 `draining` |
| `--shutdown-drain` / `RPROXY_SHUTDOWN_DRAIN` | `0s` | Then close the listeners and wait this long for current connections and sessions to end. Cut the rest |

- The default (both `0s`) is as before: SIGTERM stops at once. Values are `30s`, `2m` or seconds, each at most one hour (more is a configuration error that stops the startup).
- During `delay`: forwarding is unchanged (new connections are accepted).
- During `drain`: TCP listeners close (new connections are refused) and current connections go on. `http` rules add `Connection: close` to responses of requests in flight and then close (HTTP/2 GOAWAY); idle connections close at once. HTTP/3 takes no new QUIC connections. UDP makes no new sessions (their datagrams count as `stats.dropped`) and current sessions go on.
- During `delay` and `drain`, the control API answers reads (`GET`, `HEAD`; also `/healthz`, `/readyz`, `/metrics`) and refuses changes (`POST`, `PUT`, `PATCH`, `DELETE`, dry runs too) with `503 shutting_down`. Changes to the settings file are not applied, and no live upgrade (SIGUSR2, self-update) starts.
- A second SIGTERM or SIGINT stops without waiting for the rest.
- How the old process ends after a live upgrade (SIGUSR2) is unchanged (`RPROXY_HANDOFF_DRAIN`).
- Logs: `shutdown.start` (`delay_secs`, `drain_secs`), `shutdown.drain` (`connections`), `shutdown.now` (second signal), `shutdown.done` (`cut`). Recommended values under systemd: "Shutting down on SIGTERM" in the README.

## Endpoints

| Method and path | Body | On success | Description |
|---|---|---|---|
| `GET /healthz` | | 200 `ok` | No authentication required |
| `GET /capabilities` | | 200 | `{"version":"0.4.0","source_ip":[...],"transparent":true,"transparent_ipv6":true,"tls_modes":["passthrough","sni","terminate"],"dtls":true,"starttls":["smtp","imap","pop3"],"max_range_ports":20000,"features":{"http":true,"http3":true,"acme":true,"tls_options":true,"middlewares":["redirect_scheme","redirect_regex","ip_allow","headers","strip_prefix","add_prefix","replace_path","replace_path_regex","respond","rate_limit","in_flight","crowdsec","compress","buffering","retry","circuit_breaker","errors","basic_auth","forward_auth","oidc","geoip","cors","mirror","replace_host"],"services":["health_check","sticky","balance","outlier_detection","protocol","tls"],"http_options":["headers_add","redirect_status","route_timeouts","server_middlewares","server_status","retry_status"],"tls_route_targets":true,"client_auth_modes":["none","optional","required","optional_no_verify"],"rulesets":true,"labels":true,"conditions":true,"readyz":true,"limits":true,"bandwidth":true,"geoip":true,"outlier_detection":true,"dry_run":true,"persistence":true,"client_cert_auth":true,"token_expiry":true,"api_lockout":true,"handoff":true,"self_update":true,"performance":["workers","udp_shards","cpu_affinity","busy_poll_usecs","splice"],"graceful_shutdown":true},"build":{"version":"0.4.0","sha256":"…"}}`. `version` is the release of this rproxy-api (the `version` in `Cargo.toml`; since v0.3.18, absent on older releases; the UI uses it to check the combination). `features` lists the v0.3 and v0.4 settings this version can run ("v0.3 settings" and "v0.4 settings" above; in v0.4.0 all are true and `performance` names every key). `transparent` in `source_ip` is included only when `IP_TRANSPARENT` is available. `transparent_ipv6` indicates whether transparent can be used on IPv6 listeners (`IPV6_TRANSPARENT`). `build` is the running binary `{"version","sha256"}` (v0.4, #174; `sha256` is `null` only right after the start) |
| `GET /openapi.json` | | 200 | The OpenAPI 3.0 definition of this API (same as `docs/openapi.json`). Readable with any token |
| `GET /config` | | 200 | State of the config file (`RPROXY_CONFIG`) ("Config file" above). With `global.crowdsec`, `crowdsec` holds the state of the LAPI connection (v0.3.20): `{"connected":true,"synced":true,"last_success":1790000000,"last_error":null,"last_error_at":null,"failures":0,"decisions":12}`. `connected` is whether the last fetch succeeded, `synced` whether one ever did, `failures` the failed fetches in a row; times are Unix seconds. `rules:read` |
| `POST /config/reload` | | 200 | Reloads and applies the config file immediately and returns the result: `{"added","removed","changed","unchanged","failed","restart_needed":[...],"files":[...],"rules","warnings":[{"rule","message"}]}`. If there are errors, nothing is changed and `400 {"code":"invalid","error","errors":[...],"warnings":[...]}` is returned (`errors` is the result of the same validation as `--check-config`). Without a config file, `409 no_config`. Requires the `admin` scope (if no token file is used, anyone can use it like the other endpoints). By default only requests arriving over the Unix socket (`RPROXY_API_SOCKET`) are accepted, and TCP gets `403` (`RPROXY_API_RELOAD_UNIX_ONLY=false` accepts TCP too). Same processing as file-change detection and SIGHUP, and they never run concurrently. Recorded in `event=audit` (`action: config.reload`) |
| `GET /interfaces` | | 200 | Addresses usable for listening: `{"interfaces":[{"name":"ens18","addr":"172.16.5.1","family":"ipv4","loopback":false,"link_local":false}, ...],"reserved":[{"protocol":"tcp","addr":"127.0.0.1","port":8080,"purpose":"control API"}]}`. Only interfaces that are up are returned. `reserved` lists addresses rproxy itself uses, which cannot be used for rules |
| `GET /rules` | | 200 | Array of rules |
| `GET /rules/{protocol}/{listen_addr}/{listen_port}` | | 200 | A single rule |
| `POST /rules` | rule | 201 | Starts forwarding. Responds after name resolution and bind have completed |
| `PATCH /rules/{protocol}/{listen_addr}/{listen_port}` | `{"remote_addr","remote_port"` or `"targets"`, `"balance"?,"health_check"?,"udp_idle_secs"?,"tls"?,"starttls"?,"starttls_required"?,"allow_from"?,"crowdsec"?,"extra_listen_addrs"?,"http"?}` | 200 | Changes the destination. Including `extra_listen_addrs` replaces the additional listen addresses entirely (`[]` removes all; omitted keeps the current ones): only added addresses are opened and only removed addresses are closed (other addresses, and connections open on removed addresses, are kept). For rules listening on `::`, changes that toggle whether there are additional addresses (dual-stack vs. IPv6 only) are `unsupported` (recreate the rule). The destination (`remote_addr` / `remote_port` or `targets`, `balance`, `health_check`) is replaced together every time: an omitted `balance` becomes `round_robin`, an omitted `health_check` becomes none. To go back to a single destination, send `remote_addr` / `remote_port` (`"targets": []` may be included). Including `crowdsec` enables or disables disconnection by decisions (from the next connection). Takes effect immediately from new connections. Including `tls` replaces the whole TLS configuration (specify `starttls` together; omitting it means no STARTTLS). With `http`, the L7 settings are replaced as a whole (from the next request; adding `http` to a rule without it is `unsupported`; "v0.3 settings" above). `source_ip` and the port range cannot be changed: sending `source_ip` or `listen_port_end` with a value other than the current one is `unsupported` (the same value is accepted; to change them, re-create the rule) |
| `DELETE /rules/{protocol}/{listen_addr}/{listen_port}?drain_secs=N` | | 204 | Stops forwarding. Existing connections are cut immediately. With `drain_secs`, waits that many seconds for existing connections to finish before cutting them |
| `GET /acme` | | 200 | ACME state (docs/en/ACME.md): `{"accounts":[{"name","directory","contact","eab","allowed_names","registered"}],"dns_providers":[{"name","type","zones","allowed_names"}],"resolvers":[{"name","account","challenge","dns_provider"}],"certificates":[{"resolver","domains","state","not_after","renew_at","next_attempt","error","ari"}],"rate_limit":{"orders","period_secs","used"},"helper"}`. Neither secrets nor where they are kept are shown. `rules:read`. `404` without `global.acme` |
| `POST /acme/renew` | `{"resolver","domains"}` | 202 | Renews that certificate now (within `rate_limit`; see `GET /acme` for the result). `acme:write`; like `POST /config/reload`, only over the Unix socket by default (`RPROXY_API_RELOAD_UNIX_ONLY`). `404` when no rule uses it. `event=audit` (`action: acme.renew`) |
| `POST /acme/revoke` | `{"resolver","domains","reason"?}` | 200 | Revokes the issued certificate at the CA and orders a new one at once. Scope and Unix socket as for `POST /acme/renew`. `event=audit` (`action: acme.revoke`). docs/en/ACME.md |
| `POST /acme/accounts/{name}/register` | | 200 | Creates the account at the CA (or finds the one of its key). Scope and Unix socket as for `POST /acme/renew` |
| `POST /acme/accounts/{name}/deactivate` | | 200 | Deactivates the account at the CA and moves its key aside (`<key_file>.deactivated`; the next order creates a new account). Scope and Unix socket as for `POST /acme/renew` |
| `GET /readyz` | | 200 / 503 | v0.4 (#28): readiness without a token. `200 {"ready":true}` / `503 {"ready":false,"reason":"starting"\|"draining"}` (see "Rule sets, conditions and readiness" above) |
| `GET /rulesets` | | 200 | v0.4 (#28): rule sets `[{"name","generation","etag","rules","updated_at","updated_by"}]`. `rules:read` |
| `GET /rulesets/{name}` | | 200 | v0.4 (#28): `{"name","generation","etag","updated_at","updated_by","owner","rules":[...]}` (and an `ETag` header). Slashes in the name may be written as they are. `rules:read` |
| `PUT /rulesets/{name}?dry_run=true` | `{"generation","rules":[<rule>...]}` | 200 | v0.4 (#28): makes the set's rules exactly the body (create, change, delete). `If-Match` differing from the current etag is `412 precondition_failed`, an older `generation` is `409 stale_generation`, a key taken by a rule outside the set is `409 already_exists` / `static`. Any rule with a wrong shape changes nothing (`400`, `rules[i]: ...`). Answer `{"name","generation","etag","dry_run","results":[{"rule","action","change","state","error"}]}`. `rules:write`; every rule within `allow_listen_ports`. A single `PATCH` / `DELETE` of a set's rule is `409 owned`. Details in "Rule sets, conditions and readiness" above |
| `DELETE /rulesets/{name}?drain_secs=N` | | 204 | v0.4 (#28): stops every rule of the set at the same time and forgets the set (`If-Match` works too). `rules:write` |
| `POST /config/plan` | JSON in the settings file's shape | 200 | v0.4 (#169): compares the settings in the body with what runs and answers the difference (changes nothing; used by `--check-config --diff`). `admin`; by default only over the Unix socket |
| `POST /admin/upgrade` | | 202 | v0.4 (#174): hands over to the binary now on disk (as SIGUSR2; docs/en/UPGRADE.md). Answers `{"status":"started"}`; the handoff goes on in the background (results: `handoff.*` logs, `rproxy_handoffs_total` in `/metrics`). `409 upgrading` when one is already running. `admin`; by default only over the Unix socket |
| `GET /admin/update` | | 200 | v0.4 (#174): self-update state `{"mode","current":{"version","sha256"},"available":{"version","sha256"}\|null,"last_check","error","bad_versions"}`. `admin` |
| `POST /admin/update` | | 202 | v0.4 (#174): looks for a new patch now (`{"status":"checking"}`; results in `GET /admin/update`) and swaps it in under `RPROXY_UPDATE=auto`. `400 unsupported` with `RPROXY_UPDATE=off`. `admin`; by default only over the Unix socket |
| `GET /metrics` | | 200 | Prometheus format. Rule counts in `rproxy_rules{state}` (`running` / `failed`); per rule (labels `protocol`, `listen`) `rproxy_rule_up` (1 when running), `rproxy_connections` (open TCP connections or UDP sessions), `rproxy_connections_total`, `rproxy_bytes_total{direction}` (`rx` is client to destination, `tx` the reverse), `rproxy_tls_failures_total` (failed TLS / DTLS handshakes and STARTTLS dialogues) and `rproxy_udp_dropped_total` (UDP rules only). Requests on `http` rules are in `rproxy_http_requests_total`, `rproxy_http_request_duration_seconds` and `rproxy_http_limited_total`; upstream health checks in `rproxy_http_server_up` and `rproxy_http_service_down` ("v0.3 settings" above); every destination down in `rproxy_rule_all_targets_down`; the CrowdSec LAPI in `rproxy_crowdsec_connected`; log lines left out in `rproxy_log_suppressed_total`; control API token expiry in `rproxy_token_expiry_timestamp_seconds`; lockouts in `rproxy_api_lockouts_total` and `rproxy_api_locked_sources` ("Control API hardening" above); rule labels in `rproxy_rule_labels` (see "Rule sets, conditions and readiness" above); L4 limits and bandwidth in `rproxy_rule_limited_total` and `rproxy_rule_bandwidth_dropped_total`; the process start time in `rproxy_process_start_time_seconds` ("v0.4 settings" above). The running binary in `rproxy_build_info{version,sha256}`, live upgrades in `rproxy_handoffs_total{outcome}` (#174; `rproxy_process_start_time_seconds` is kept over live upgrades) |

When putting an IPv6 `listen_addr` in a path, URL-encode it.

## Errors

On failure, responses take the following shape.

```json
{"error": "address already in use (os error 98)", "code": "bind_failed"}
```

| `code` | HTTP | Meaning |
|---|---|---|
| `unauthorized` | 401 | Token missing, not matching, expired, or without the client certificate bound to it |
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
| `owned` | 409 | v0.4: the rule belongs to a set (`ruleset`) and cannot be changed alone |
| `precondition_failed` | 412 | v0.4: the `If-Match` etag differs from the set's current one |
| `stale_generation` | 409 | v0.4: the set's `generation` is older than the current one |
| `locked_out` | 429 | v0.4: this source is locked out for a while after repeated authentication failures (`Retry-After`) |
| `upgrading` | 503 / 409 | v0.4 (#174): a live upgrade is in progress, changes are not taken (503; send again shortly) / an upgrade is already running (409 of `POST /admin/upgrade`) |
| `shutting_down` | 503 | v0.4.1: shutting down gracefully after SIGTERM (`RPROXY_SHUTDOWN_DELAY` / `_DRAIN`), changes are not taken (send them to another rproxy) |
| `internal` | 500 | Other |

## Relationship between the API, config file and UI (DB)

rproxy rules have four origins. All appear in `GET /rules`.

| Origin | `origin` | Source of truth | How to change |
|---|---|---|---|
| Config file (`RPROXY_CONFIG`) | `static` | The file | Edit the file (applied automatically). The API gives `409 static` |
| UI (TCP-UDP-rproxy-ui) | `dynamic` | The UI's DB (`forward_rules`) | From the UI. The UI writes to the DB and then calls the rproxy API. rproxy restores from the DB at startup |
| Calling the API directly (CI, scripts) | `dynamic` | rproxy's memory only | From the API. Not written to the DB, so it disappears when rproxy restarts |
| Calling the API with a `persist: true` token (v0.4, #144) | `api` | rproxy's table `rproxy_rules` | From the API. rproxy writes `rproxy_rules` on every create, change and delete and restores it at startup ("Storing API-created rules" above) |
| Rule sets (the Kubernetes controller, v0.4) | `dynamic` (with `ruleset`) | The controller (rproxy keeps them in memory only) | `PUT /rulesets/{name}`. A single `PATCH` / `DELETE` is `409 owned`. After a restart the controller PUTs them again |

- Create long-lived rules with the config file, the UI (DB) or a `persist: true` token (v0.4). Treat rules created by calling the API directly with a token that does not store as temporary (CI preview environments, etc.).
- The UI does not edit rules that are not in the DB. Rules created via the API do not appear in the UI list, and rules in the DB but not in rproxy show as "missing" in the UI.
- When using the API directly, use a token whose scopes and `allow_listen_ports` separate it from the UI's rules (authentication in "Basics").

## Restore at startup

With `--database-url mysql://user:pass@host:port/db`, all rules in the `forward_rules` table are loaded and started at startup. The DB user only needs the `SELECT` privilege. Rules that fail are registered as `failed`, and the remaining rules are started. Rules that became `failed` because of a name resolution failure start automatically once re-resolution succeeds.

From v0.4 (#144), this node's rows of rproxy's table `rproxy_rules` are restored next (`origin: "api"`; on the same key the `forward_rules` row wins; "Storing API-created rules" above). That table needs `SELECT`, `INSERT`, `UPDATE` and `DELETE`.
Rows of `forward_rules` are split per node on the UI's side (the `target` column, UI PR #103; a per-node DB view shows each rproxy only its rows), so rproxy does not filter `forward_rules`. Of `rproxy_rules`, rproxy reads only its own `node`'s rows.

The table definition is managed in `db/` of the UI repository. The columns rproxy reads are `protocol`, `src_addr`, `src_port`, `src_port_end`, `dist_addr`, `dist_port`, `source_ip`, `udp_idle_secs`, `options`. If `options.targets` (multiple destinations) is present, `dist_addr` / `dist_port` are not used. Rows with `options.enabled` set to `false` (rules paused in the UI) are not created at startup (counted in the `restore.paused` log).
`options` is JSON: `{"tls": <TLS>, "starttls": "smtp" | "imap" | "pop3" | null, "starttls_required": bool, "allow_from": [<CIDR>, ...], "http": <L7>, "crowdsec": bool}` (`allow_from`, `http` and `crowdsec` can be omitted). If an old table lacks these columns, default values are used. The v0.4 `labels`, `limits`, `bandwidth`, `geoip` and `outlier_detection` are read in the API's shape as well (optional; "v0.4 settings" above).
