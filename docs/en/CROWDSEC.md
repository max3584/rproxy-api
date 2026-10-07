日本語: [CROWDSEC.md](../CROWDSEC.md)

# Integration with CrowdSec

rproxy integrates with CrowdSec in two directions.

| Direction | What it does | Configuration |
|---|---|---|
| Block (bouncer) | Blocks IPs that are in the LAPI decisions (ban). For L7, the `crowdsec` middleware (403, AppSec as well); for L4, `crowdsec: true` on the rule (cut before TLS) | rproxy's `global.crowdsec` (docs/API.md) |
| Detect (logs) | The CrowdSec agent reads rproxy's logs, detects attacks, and bans them | The parsers, scenarios, and acquis on this page |

With both in place, the loop "CrowdSec detects from traffic passing through rproxy and bans → rproxy blocks that IP" is closed. CI (`scripts/interop/crowdsec.sh`, the `crowdsec` job in interop) verifies this loop with a real CrowdSec.

## 1. Preparing CrowdSec

```bash
# Install CrowdSec (LAPI and agent) (official procedure)
curl -fsSL https://install.crowdsec.net | sudo sh
sudo apt install crowdsec

# HTTP scenarios and AppSec rules
sudo cscli collections install crowdsecurity/base-http-scenarios crowdsecurity/http-cve \
  crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
```

## 2. Letting CrowdSec read rproxy's logs (detect)

The rproxy .deb ships the following files in `/usr/share/rproxy-api/crowdsec/` (`contrib/crowdsec/` in the repository).

| File | Location | Contents |
|---|---|---|
| `parsers/s01-parse/rproxy-logs.yaml` | `/etc/crowdsec/parsers/s01-parse/` | Parser for rproxy's JSON logs (`max3584/rproxy-logs`) |
| `scenarios/rproxy-conn-denied.yaml` | `/etc/crowdsec/scenarios/` | L4: the same IP repeatedly makes connections refused by `allow_from` within a short time (port probing, etc.) |
| `scenarios/rproxy-conn-flood.yaml` | `/etc/crowdsec/scenarios/` | L4: too many new connections from the same IP (exceeding an average of 10/s, for 200 connections) |
| `acquis.d/rproxy.yaml` | `/etc/crowdsec/acquis.d/` | rproxy's log files (`labels.type: rproxy`) |
| `acquis.d/appsec.yaml` | `/etc/crowdsec/acquis.d/` | AppSec (127.0.0.1:7422) |

```bash
S=/usr/share/rproxy-api/crowdsec
sudo install -m 644 $S/parsers/s01-parse/rproxy-logs.yaml /etc/crowdsec/parsers/s01-parse/
sudo install -m 644 $S/scenarios/*.yaml /etc/crowdsec/scenarios/
sudo install -m 644 $S/acquis.d/rproxy.yaml $S/acquis.d/appsec.yaml /etc/crowdsec/acquis.d/
sudo systemctl restart crowdsec

# Verify: run one line of rproxy's log through the parser
sudo cscli explain --log "$(tail -n 1 /var/log/rproxy/rproxy.*.log)" --type rproxy
```

- Match the file name in `acquis.d/rproxy.yaml` to `RPROXY_LOG_FILE` (`/var/log/rproxy/rproxy.log` in the default .deb). rproxy's logs are split daily into `<name>.<date>.<extension>`, so specify them with a glob (`/var/log/rproxy/*.log`). If you write the access log to a separate file with `global.access_log`, add that file too.
- Make sure CrowdSec (root) can read rproxy's log directory (`rproxy:rproxy` 750).

### Fields produced by the parser

**HTTP (`event: http.access`)** is treated as a CrowdSec HTTP access log (`log_type: http_access-log`, `service: http`). `crowdsecurity/http-logs` (s02) and existing scenarios such as `base-http-scenarios` and `http-cve` work as-is.

| CrowdSec field | rproxy log |
|---|---|
| `evt.Meta.source_ip` / `evt.Parsed.remote_addr` | `client` (the client IP, with `global.trusted_proxies` applied) |
| `evt.Meta.http_verb` / `evt.Parsed.verb` | `method` |
| `evt.Meta.http_path` / `evt.Parsed.request` | `path` and `query` (`path?query`) |
| `evt.Meta.http_status` / `evt.Parsed.status` | `status` |
| `evt.Meta.http_user_agent` / `evt.Parsed.http_user_agent` | `user_agent` |
| `evt.Meta.target_fqdn` / `evt.Parsed.target_fqdn` | `host` |
| `evt.Parsed.http_version`, `body_bytes_sent` | `protocol`, `bytes_out` |
| `evt.Meta.rproxy_rule`, `rproxy_route` | `rule`, `route` |
| `evt.Meta.rproxy_refused_by`, `rproxy_auth_error` | `refused_by` (the kind of middleware that refused: `basic_auth`, `ip_allow`, …), `auth_error` (why `basic_auth` refused: `bad_password`, …). Since v0.3.20 |
| `evt.StrTime` | `timestamp` |

**L4 (`event: conn.open` / `conn.denied`)** is `log_type: rproxy_conn` (`service: rproxy`). Fields: `evt.Meta.source_ip` (the IP part of `client`), `rproxy_event`, `rproxy_reason` (`allow_from` / `crowdsec`, etc.), `rproxy_rule`. UDP `conn.denied` lines appear at the default log level since v0.3.20 (thinned out per source, so fewer than the datagrams).

## 3. Blocking from rproxy (bouncer)

```bash
sudo cscli bouncers add rproxy -o raw | sudo tee /etc/rproxy/crowdsec.key >/dev/null
sudo chown root:rproxy /etc/rproxy/crowdsec.key && sudo chmod 640 /etc/rproxy/crowdsec.key
```

```yaml
# RPROXY_CONFIG
version: 1
global:
  crowdsec:
    lapi_url: http://127.0.0.1:8080        # do not share 8080 with rproxy's control API (change RPROXY_API_PORT)
    api_key_file: /etc/rproxy/crowdsec.key
    appsec_url: http://127.0.0.1:7422      # when using AppSec
    update_interval: 10s
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls: {mode: terminate, certificates: [...]}
    http:
      routes:
        - {name: site, match: "Host(`www.example.com`)", service: web, middlewares: [crowdsec]}
      services:
        web: {servers: [{url: "http://10.0.0.20"}]}
      middlewares:
        crowdsec: {crowdsec: {appsec: true}}   # with appsec: false, only LAPI decisions
  - protocol: tcp                               # L4: banned IPs are cut before TLS
    listen_addr: 0.0.0.0
    listen_port: 25
    remote_addr: 10.0.0.30
    remote_port: 25
    crowdsec: true
```

- If there is a CDN or load balancer in front, set `global.trusted_proxies`. The real IP from `X-Forwarded-For` is then used for `client` in the L7 log and for matching against decisions (L4 uses the connection's source IP).
- `captcha` decisions are treated as bans. Only the `Ip` and `Range` scopes are used (`Country` and `AS` are not).

### Pairing with GeoIP (v0.4, #168)

What should never get in by country or ASN can be dropped by rproxy's `geoip` (a rule's `geoip`, the L7 `geoip` middleware; an mmdb such as GeoLite2 in `global.geoip`), leaving behaviour to CrowdSec. The order is `allow_from` → `geoip` → `crowdsec`. Connections refused by `geoip` log `conn.denied` (`reason: geoip`, `country`, `asn`), requests `http.access` (`refused_by: geoip`). The parser puts `reason` into `rproxy_reason`, so scenarios can leave `geoip` out or count it (the bundled scenario counts `allow_from` only).

CrowdSec can add the country itself with `crowdsecurity/geoip-enrich` (using the same GeoLite2). rproxy's `global.geoip.log_country: true` adds `country` and `asn` to `conn.open` and `http.access`, for reading rproxy's logs without CrowdSec, e.g. in a SIEM. Both can use the same database files updated by `geoipupdate` (rproxy reads a changed file again every `check_interval`).

## 4. How CI verifies it

`scripts/interop/crowdsec.sh` installs CrowdSec (LAPI, agent, AppSec) from the official packages on a GitHub Ubuntu runner and, from clients in network namespaces going through rproxy, verifies the following:

1. `cscli explain`: the parser reads all 6 lines of the sample log (`scripts/interop/crowdsec-samples.log`); the HTTP lines reach `crowdsecurity/http-logs` and the scenarios (`http-sensitive-files`, `http-probing`, etc.), and the L4 lines reach `max3584/rproxy-conn-denied`
2. Detection: a global client probes nonexistent paths → CrowdSec detects it from rproxy's logs and bans it → that client is blocked by rproxy with 403, while other clients pass (IPv4 and IPv6)
3. L4: a client that repeatedly makes connections refused by `allow_from` is banned by `max3584/rproxy-conn-denied`, and its connections are cut by an L4 rule with `crowdsec: true`
4. AppSec: `GET /.env` (`crowdsecurity/vpatch-env-access`) is blocked with 403, while normal requests pass
5. After removing the ban with `cscli decisions delete`, the client passes again
6. A client with a private address (10.99.0.10) is not banned even when it performs the same probing

Documentation addresses are used for the clients' "global" addresses: RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) for IPv4 and RFC 3849 (2001:db8::/32) for IPv6. They have no routes on the internet, so they are safe inside a namespace, and they are not in CrowdSec's default whitelist (`crowdsecurity/whitelists`: RFC 1918, loopback, etc.). CrowdSec does not ban private addresses, so tests from `127.0.0.1` trigger neither detection nor bans.
