日本語: [SOURCE-IP.md](../SOURCE-IP.md)

# Passing the source IP (`source_ip`)

When rproxy connects to a target (backend), the target sees the peer as **rproxy's IP**.
As-is, the real client IP does not reach the target's logs, access restrictions, anti-spam measures, and so on.
`source_ip` is a per-rule setting that chooses whether, and how, the client's IP is conveyed to the target.

| Value | What it does | Target configuration | Suitable for |
|---|---|---|---|
| `proxy` (default) | Conveys nothing. To the target, every connection appears to come from rproxy | Not needed | When the client IP is not needed. L7 (`http`) rules (the IP is passed in `X-Forwarded-For`) |
| `proxy_v2` | Sends a short header containing the client's IP (PROXY protocol v2, binary) at the start of the connection | **Required** (configure it to accept PROXY protocol) | When the target supports PROXY protocol, such as mail, databases, and Kubernetes ingress (recommended) |
| `proxy_v1` | Sends the same header as text (PROXY protocol v1). TCP only | **Required** | Old targets that do not support v2 |
| `transparent` | rproxy connects using the client's IP | Not needed (routing configuration is needed instead) | When the target does not support PROXY protocol and the client IP is absolutely needed ([TRANSPARENT.md](TRANSPARENT.md)) |

The name `proxy` means "connect with rproxy's own IP" (it does not mean passing the IP along).

## What is PROXY protocol

For HTTP, the client IP can be conveyed in the `X-Forwarded-For` header, but TCP / UDP protocols such as mail (SMTP, IMAP), databases, and games have no place to put such a header.
PROXY protocol is the convention of **adding one line (or a short binary block) saying "the real client is 203.0.113.9:51234" at the very start of the connection, and then sending the actual data**. It was devised by HAProxy and is supported by a lot of software.

```
v1 example (text; the actual data follows this line)
PROXY TCP4 203.0.113.9 198.51.100.10 51234 443\r\n
```

- v2 is binary, can be used with UDP, and can also carry TLS information (SNI, ALPN, client certificate CN, etc.). Choose v2 for new setups.
- For UDP, rproxy adds the header to each datagram (the same approach as dnsdist, PowerDNS, and Unbound). Responses do not carry the header.

### Things to watch out for

- **Configure both sides consistently.** If you add the header but the target is not configured to accept PROXY protocol, the target treats it as invalid data and the connection breaks ("protocol error", "bad request", etc.). Conversely, if the target requires PROXY protocol and you do not add the header, the target does not accept the connection.
- **On the target, trust the header only from rproxy.** If the header is accepted from anyone, clients can write their own header and spoof their IP. Most software has a "trusted proxy IP" setting (examples below).
- **The setting is called "proxy protocol" in every piece of software.** Search for this term when looking for the target's setting.

## Target configuration examples

All of these accept PROXY protocol only on connections from rproxy (e.g. 10.0.0.1).

| Target | Configuration |
|---|---|
| Postfix (SMTP port 25) | `postscreen_upstream_proxy_protocol = haproxy` (when using postscreen), or `smtpd_upstream_proxy_protocol = haproxy` (submission, etc.) |
| Dovecot (IMAP / POP3) | `haproxy_trusted_networks = 10.0.0.1` and `haproxy = yes` per listener |
| nginx | `listen 443 ssl proxy_protocol;` and `set_real_ip_from 10.0.0.1; real_ip_header proxy_protocol;` |
| Kubernetes ingress-nginx | `use-proxy-protocol: "true"` in the ConfigMap |
| Traefik | `proxyProtocol.trustedIPs: ["10.0.0.1"]` on the entry point |
| HAProxy | `bind :443 accept-proxy` |
| MediaMTX (RTSP) | `rtspTrustedProxies: [10.0.0.1]` ([PROFILES.md](PROFILES.md)) |
| dnsdist / PowerDNS Recursor / Unbound | Each one's proxy protocol setting (UDP also works) |

Recommended combinations per use case are in [PROFILES.md](PROFILES.md).

## Which to choose

1. The client IP is not needed -> `proxy` (leave the default).
2. It is needed, and the target supports PROXY protocol -> `proxy_v2` (`proxy_v1` if an old target only supports v1).
3. It is needed, but the target does not support PROXY protocol -> `transparent` (routing configuration is needed on the rproxy host and the target; see [TRANSPARENT.md](TRANSPARENT.md)).

## Relationship with other settings

- **L7 (`http`) rules:** only `proxy` (or `transparent`) can be used. The client IP is passed in `X-Forwarded-For` / `X-Real-IP` (use `global.trusted_proxies` to trust an upstream CDN, etc.). Passthrough routes in the same rule (`tls.routes[].passthrough`) do not get PROXY protocol either.
- **Rules where rproxy terminates TLS (`terminate`):** with `proxy_v2`, TLS information (SNI, ALPN, TLS version, client certificate CN) is also passed in TLVs.
- **`source_ip` cannot be changed after creation** (recreate the rule). This is because it must be switched at the same time as the target's configuration.
- For syntax and constraints, see the rule field `source_ip` in [API.md](API.md).

## rproxy receiving PROXY protocol (`proxy_protocol`, v0.4.13)

Everything above is about rproxy **sending** to the target. When there is a load balancer in front of rproxy too (a cloud NLB, HAProxy, another rproxy, a Kubernetes Gateway) and it sends PROXY protocol, `proxy_protocol` of a `tcp` rule **receives** the header and treats the address in it as the real client.

```json
{"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 25,
 "remote_addr": "10.0.0.25", "remote_port": 25, "source_ip": "proxy_v2",
 "proxy_protocol": {"from": ["10.2.0.0/16", "172.16.10.19/32"], "required": true}}
```

- **`from` (required): the front ends whose headers are believed.** As in "Things to watch out for" above, only the front end is trusted. It is matched against the TCP peer (the hop right in front), cannot be empty, and `0.0.0.0/0` is not accepted.
- **`required` (default `true`):** a connection from `from` without a header is refused. If the front end's health checks come without one, use `false` (no header: the peer's address). A `LOCAL` header (v2's form for health checks) passes even with `true`, with the peer's address.
- **Connections from outside `from`** are ordinary connections (no header is read), but one that starts with a header is refused (`conn.denied` with `reason: proxy_protocol_untrusted`); a front end missing from `from` shows up there.
- The header's client is used by `allow_from`, `geoip`, `crowdsec`, `limits`, `bandwidth`, the logs' `client`, `X-Forwarded-For` / `X-Real-IP` and `source_ip` towards the target. The front end's address stays in the logs' `proxy_peer`.
- PROXY v2 in and PROXY v2 out (the example) carries the real client's IP from the front end to the target. v2 TLVs are skipped; towards the target rproxy writes the TLS details it saw itself.
- The details (size limits of 107 bytes for v1 and 4096 for v2, the 5 s time limit, HTTP/3 and UDP not covered) are in "Receiving PROXY protocol" in [API.md](API.md).
