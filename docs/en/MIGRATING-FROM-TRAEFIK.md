日本語: [MIGRATING-FROM-TRAEFIK.md](../MIGRATING-FROM-TRAEFIK.md)

# Migrating from Traefik

`contrib/traefik2rproxy.py` (`/usr/bin/rproxy-traefik-convert` in the .deb) converts a Traefik configuration into an rproxy configuration file (`RPROXY_CONFIG`: `version: 1`, `global`, `rules`). Settings that could not be converted are listed in a comment at the top of the output and on standard error. Do not use the output as-is; review the list before deploying it.

## Usage

```bash
# From the static configuration. Also reads the dynamic configuration in providers.file filename / directory
rproxy-traefik-convert --static /etc/traefik/traefik.yml -o /etc/rproxy/rproxy.yaml

# Specify the dynamic configuration separately (file or directory; can be given any number of times)
rproxy-traefik-convert --static traefik.toml --dynamic dynamic/ -o rproxy.yaml

# From Docker labels (output of docker inspect)
docker inspect $(docker ps -q) > containers.json
rproxy-traefik-convert --static traefik.yml --docker containers.json -o rproxy.yaml

# Check against the features available in the target rproxy
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/capabilities > caps.json
rproxy-traefik-convert --static traefik.yml --capabilities caps.json -o rproxy.yaml
```

- Requirements: Python 3.8 or later. PyYAML (`apt install python3-yaml`) for reading and writing YAML, and Python 3.11 or later for reading TOML. Without PyYAML, the output is JSON (rproxy can also read JSON configuration files; `--json` also produces JSON).
- The exit code is 2 only when the input cannot be read. Even if some settings cannot be converted, it exits with 0 and lists them.
- Entry points that omit the address, such as `:443`, listen on `--listen-addr` (default `0.0.0.0`).
- The converted result is validated when `rproxy-api` starts (or when `RPROXY_CONFIG` is automatically reloaded). If there are errors, it does not start (a reload does not apply the change), so testing with a local rproxy before deploying is the safe approach.

## Mapping

### Entry points and rules

| Traefik | rproxy |
|---|---|
| `entryPoints.<name>.address` (`:443`, `192.0.2.1:80`, `:53/udp`) | One entry point becomes one rule (`protocol`, `listen_addr`, `listen_port`) |
| HTTP router | `http.routes` of the rule for that entry point (name with `@file` etc. removed) |
| Router `rule` | `match`. v3 syntax as-is. v2 `Headers` → `Header`, `HostHeader` → `Host`, `Query(`a=b`)` → `Query(`a`, `b`)`, and `{name:regex}` substitutions become `HostRegexp` / `PathRegexp` |
| `priority` | `priority` (when omitted, both use the length of `match`) |
| `entryPoints.<name>.http.redirections.entryPoint` | The rule for that entry point becomes a single route that redirects everything (`redirect_scheme`) |
| `entryPoints.<name>.http.middlewares` | Prepended to every route of that entry point |
| `entryPoints.<name>.http.tls`, router `tls` | The rule's `tls.mode: terminate` |
| `entryPoints.<name>.http3` | `http.http3: true` |
| `entryPoints.<name>.forwardedHeaders.trustedIPs` | `global.trusted_proxies` |
| `accessLog.filePath` | `global.access_log` (format is rproxy's JSON Lines; Traefik's format and filters are not converted) |
| TCP router (`HostSNI`, `tls.passthrough: true`) | `tls.routes` with `tls.mode: sni` (one per router; `server_names` if there are multiple names). `HostSNI(`*`)` becomes the rule's forwarding target (if absent, `unmatched: reject`) |
| Simple-suffix `HostSNIRegexp` (`^.+\.example\.com$` / `^[^.]+\.example\.com$`) | `**.example.com` (any depth) / `*.example.com` (one level) |
| TCP passthrough router on the same entry point as HTTP routers | Placed in the same rule's `tls.routes` with `passthrough: true` (only those names are passed through without termination) |
| TCP router (terminating TLS) | `tls.routes` with `tls.mode: terminate` |
| TCP service `proxyProtocol.version` | `source_ip: proxy_v1` / `proxy_v2` |
| UDP router | A rule with `protocol: udp` |

### Services

| Traefik | rproxy |
|---|---|
| `loadBalancer.servers[].url` / `weight` | `http.services.<name>.servers` |
| `passHostHeader: false` | `pass_host_header: false` |
| `healthCheck.path` / `interval` / `timeout` | `health_check` |
| `sticky.cookie.name` | `sticky.cookie` |
| `serversTransport` (`insecureSkipVerify`, `rootCAs`, `serverName`) | `tls.upstream` of the TLS-terminating rule (applies to all `https://` targets of the rule) |
| `weighted` | The targets of the inner services are merged into one, with weights multiplied (same for TCP / UDP) |
| `failover` | The primary service's targets followed by the `fallback` targets, with `balance: failover` (in order from the top, the first live target; no round robin even within the primary service). If there is no `health_check`, it is reported in the list |
| `mirroring` | Only the primary service is used |
| Multiple targets in a TCP / UDP service | The rule's `targets` (`balance: round_robin`, weighted). Per-server-name targets (`tls.routes`) take only one, so only the first is used there |
| `healthCheck` of a TCP / UDP service | Not converted (rproxy's L4 `health_check` checks with a TCP connection; add it if needed) |

### Middlewares

| Traefik | rproxy |
|---|---|
| `redirectScheme` / `redirectRegex` | `redirect_scheme` / `redirect_regex` |
| `stripPrefix` / `addPrefix` / `replacePath` / `replacePathRegex` | `strip_prefix` / `add_prefix` / `replace_path` / `replace_path_regex` |
| `headers` | `headers` (empty values in `customRequestHeaders` / `customResponseHeaders` mean removal, HSTS, `frameDeny`, `contentTypeNosniff`, `referrerPolicy`, `contentSecurityPolicy`, CORS. `customFrameOptionsValue`, `browserXssFilter`, and `permissionsPolicy` are added as response headers) |
| `rateLimit` | `rate_limit` (`sourceCriterion.requestHeaderName` becomes `source: header:<name>`. `ipStrategy` is not converted; `global.trusted_proxies` determines the client IP) |
| `inFlightReq` | `in_flight` (per client IP) |
| `ipAllowList` / `ipWhiteList` | `ip_allow` |
| `basicAuth` | `basic_auth`. `users` are not written to a file, so place them in htpasswd format at the path shown in the list (`$apr1$`, bcrypt, and `{SHA}` can be used as-is). `realm` → `realm`, `headerField` → `user_header`. Traefik passes `Authorization` to the backend by default, so unless `removeHeader` is set, `keep_authorization: true` is used |
| `forwardAuth` | `forward_auth`. `authResponseHeaders` → `response_headers`, `authRequestHeaders` → `request_headers`, `trustForwardHeader` → `trust_forward_header`. `authResponseHeadersRegex`, `addAuthCookiesToResponse`, and `tls` are not converted |
| OIDC plugins, oauth2-proxy | Not converted. Rewrite with the `oidc` middleware (docs/API.md). The backend receives `X-Forwarded-User` / `-Email` / `-Groups` |
| `compress` | `compress` |
| `retry` | `retry` |
| `circuitBreaker` | `circuit_breaker`. `NetworkErrorRatio() > 0.30` / `ResponseCodeRatio(...) > x` become `failure_percent` (`LatencyAtQuantileMS` is not converted) |
| `errors` | `errors` (`query` becomes `path`; the service is copied along with it) |
| `buffering` | `buffering` (`maxRequestBodyBytes`) |
| `chain` | The inner middlewares are expanded in order |
| CrowdSec bouncer plugin | `global.crowdsec` (LAPI and AppSec URLs, update interval) and the `crowdsec` middleware. **The API key is not copied**, so write it to the file shown in the list (default `/etc/rproxy/crowdsec.key`) |

Depending on the rproxy version, some middleware and service settings cannot run yet (`features` in `GET /capabilities`). The converter lists features that the output uses but rproxy does not yet have (with `--capabilities`, it checks against that rproxy's response). Rules that use settings that cannot run are registered by rproxy as `unsupported` (startup continues).

### TLS

| Traefik | rproxy |
|---|---|
| `certResolver` (ACME) | rproxy can obtain certificates through ACME too (from v0.3.21: `global.acme` and `{acme: <resolver>, domains: [...]}`, docs/en/ACME.md; the allowed names and the rest are written by hand). For now the converter points at files obtained with certbot / acme.sh / cert-manager. The converter writes certbot's locations (`--certbot-live`, default `/etc/letsencrypt/live/<name>/fullchain.pem` and `privkey.pem`) and lists the names to obtain. The `main` / `sans` of `tls.domains` become one certificate, and other routers whose names are covered by it use the same certificate |
| `tls.certificates` | `tls.certificates` of every TLS-terminating rule (rproxy selects by SNI) |
| `tls.options.<name>.minVersion` / `cipherSuites` | `tls.options.min_version` / `cipher_suites` (Go names to rustls names; ciphers not in rustls, such as CBC, are dropped) |
| `tls.options.<name>.clientAuth` | `tls.client_auth` (only the first of `caFiles`) |
| `tls.options.<name>.alpnProtocols` | `tls.alpn` |

rproxy detects changes to certificate files and reloads them (`RPROXY_CERT_CHECK_SECS`), so certbot renewals are picked up as-is. When using certbot's http-01, add a route to the port 80 rule that sends `/.well-known/acme-challenge/` to certbot (a web server serving the webroot, or the `--standalone` port), with a higher priority than the redirect.

```yaml
- protocol: tcp
  listen_addr: 0.0.0.0
  listen_port: 80
  http:
    routes:
      - name: acme
        match: PathPrefix(`/.well-known/acme-challenge/`)
        priority: 2000000
        to: http://127.0.0.1:8402   # certbot certonly --standalone --http-01-port 8402
      - name: redirect
        match: PathPrefix(`/`)
        priority: 1000000
        middlewares: [redirect]
    middlewares:
      redirect: {redirect_scheme: {scheme: https, permanent: true}}
```

## Not converted

- Traefik's own services (the `api@internal` dashboard, `ping@internal`, etc.): the routers are removed entirely. For management, use the rproxy UI (TCP-UDP-rproxy-ui)
- `metrics`: rproxy returns Prometheus format from the control API's `GET /metrics`
- Incoming PROXY protocol (`entryPoints.<name>.proxyProtocol`): rproxy does not read it (`X-Forwarded-For` added by the front end can be trusted via `global.trusted_proxies`)
- When HTTP and TCP routers share an entry point: passthrough routers with specified names are merged. Other TCP routers (TLS-terminating TCP routers, `HostSNI(`*`)`) are removed
- When a `HostSNI(`*`)` passthrough and a TLS-terminating router share an entry point: the terminating one is removed
- `HostSNIRegexp` that is not a simple suffix, `ALPN()`, label-only `defaultRule`, Kubernetes IngressRoute (CRD)
- Middlewares `digestAuth`, `contentType`, `passTLSClientCert`, `grpcWeb`, `stripPrefixRegex`, and plugins other than CrowdSec
- Fine-grained items of each setting (shown in the list as `... is not converted`)
