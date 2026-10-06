日本語: [ACME.md](../ACME.md)

# Certificates through ACME (#208)

rproxy can obtain certificates through ACME (Let's Encrypt and others) and renew them itself before they expire (from v0.3.21). Write `{acme: <resolver>, domains: [...]}` in a rule's `tls.certificates` instead of `cert_file` / `key_file`; the certificate obtained is loaded through the same mechanism as certificate files (the certificate store, #115), and a renewed one is swapped in without dropping connections. Pointing at files obtained with certbot, cert-manager and the like still works as before.

| challenge | When | What in rproxy answers |
|---|---|---|
| `http-01` | Names rproxy listens for on port 80 | An `http` rule on port 80 (it answers `/.well-known/acme-challenge/` before routes and middlewares), or the small responder of `global.acme.http01_listen` |
| `tls-alpn-01` | Names rproxy terminates TLS for on port 443 | A `terminate` rule on port 443 (a ClientHello offering only the ALPN `acme-tls/1` gets the validation certificate) |
| `dns-01` | Wildcards (`*.example.com`), names port 80 / 443 cannot be reached for from outside | A DNS provider (the PowerDNS HTTP API, a generic REST template) writes the `_acme-challenge` TXT record |

Use `http-01` / `tls-alpn-01` first: they need no right to change DNS. Keep `dns-01` for wildcards and names that cannot be reached from outside.

## Settings

ACME is set up (accounts, DNS providers, resolvers, allowed names) only in `global.acme` of the settings file (`RPROXY_CONFIG`). Rules made through the API refer to a resolver by name; secrets (DNS API keys and the like) cannot be created, read or changed through the API. Changes to `global` take effect after a restart (`restart_needed` in `GET /config`).

```yaml
# /etc/rproxy/rproxy.yaml
version: 1
global:
  acme:
    storage: /var/lib/rproxy/acme            # account keys and certificates (default); writable by rproxy's user
    accounts:
      letsencrypt:
        directory: https://acme-v02.api.letsencrypt.org/directory   # default; for tests …acme-staging-v02…
        contact: ['mailto:admin@example.com']
        allowed_names: [example.com, '*.example.com', '**.svc.example.com']   # required: names this account may get certificates for
        # key_file: /var/lib/rproxy/acme/accounts/letsencrypt.key  # default; created (0600) when missing
        # eab: {kid: ..., hmac_key_file: /etc/rproxy/acme/eab.key} # external account binding (ZeroSSL, ...)
        # ca_file: /etc/rproxy/acme/private-ca.pem                # HTTPS of a private CA (step-ca, ...)
    dns_providers:
      pdns:
        type: powerdns
        api_url: http://127.0.0.1:8081            # the part before /api/v1
        server_id: localhost                      # default
        api_key_file: /etc/rproxy/acme/pdns.key   # X-API-Key (one line)
        zones: [acme.example.net]                 # zones it may write to (default: chosen from PowerDNS's zones)
        allowed_names: ['*.example.com', example.com]   # required: names this provider may prove
      relay:
        type: http                                # generic REST (the idea of lego's httpreq)
        add:    {method: POST, url: 'https://dns-relay.example.net/present', headers: {Authorization: 'Bearer {secret}'}, body: '{"fqdn":"{fqdn}","value":"{value}"}'}
        remove: {method: POST, url: 'https://dns-relay.example.net/cleanup', headers: {Authorization: 'Bearer {secret}'}, body: '{"fqdn":"{fqdn}","value":"{value}"}'}
        secret_file: /etc/rproxy/acme/relay.token
        allowed_names: [intranet.example.com]
      bind:
        type: rfc2136                             # DNS UPDATE (RFC 2136): BIND, Knot, PowerDNS, ...
        server: 10.0.0.53                         # the primary (ip or ip:port)
        tsig_key_name: rproxy-acme
        tsig_algorithm: hmac-sha256               # default; hmac-sha512 too
        tsig_secret_file: /etc/rproxy/acme/tsig.key   # the secret in base64 (as BIND's key secret)
        zones: [acme.example.net]
        allowed_names: ['*.example.org']
      acmedns:
        type: acme_dns                            # acme-dns (joohoi/acme-dns)
        api_url: https://auth.acme-dns.example.net
        credentials_file: /var/lib/rproxy/acme/acme-dns.json   # an account per name (lego's format); registered and written (0600) when missing
        allowed_names: [vpn.example.com]
    resolvers:                                    # what rules name: an account + a challenge
      le-http: {account: letsencrypt, challenge: http-01}
      le-alpn: {account: letsencrypt, challenge: tls-alpn-01}
      le-dns:  {account: letsencrypt, challenge: dns-01, dns_provider: pdns}
    rate_limit: {orders: 10, period: 1h}          # default: at most this many orders (new and renewals, failed ones too)
    # renew_before: 30d                           # default 30 days (a third of the lifetime if that is shorter)
    # dns_servers: ['10.0.0.53']                  # DNS for CNAME, zone and TXT lookups (default: /etc/resolv.conf)
    # dns_propagation_timeout: 2m                 # how long to wait for the TXT record (then the CA is asked anyway)
    # http01_listen: ['0.0.0.0:80']               # HTTP-01 responder when no http rule listens on port 80
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - acme: le-alpn
          domains: [example.com, www.example.com]
        - acme: le-dns
          domains: ['*.example.com']
    http:
      routes:
        - {name: site, match: 'HostRegexp(`.+`)', to: 'http://127.0.0.1:3000'}
```

- `allowed_names`: `example.com` (that name), `*.example.com` (one label below, and the wildcard `*.example.com` itself), `**.example.com` (any depth). Required for accounts and DNS providers; with `dns-01` a name must be in both. A rule with any other name is `400 invalid` through the API, and a mistake in the settings file (no start, no reload).
- Wildcards need a `dns-01` resolver (`400 invalid`).
- `rfc2136`: sends an UPDATE signed with TSIG (HMAC-SHA256 / HMAC-SHA512) to `server` over UDP (TCP when truncated). The zone is from `zones`, or the SOA as `server` answers it. On the server, let the key write only TXT records of that zone (the delegated challenge zone): BIND's `update-policy { grant <key> zonesub TXT; }`, PowerDNS's `TSIG-ALLOW-DNSUPDATE`, and so on.
- `acme_dns`: uses an acme-dns account per name from `credentials_file` (JSON: `{"<name>": {"username","password","fulldomain","subdomain"}}`). A name without one is registered on its first order (`POST /register`, written 0600), and the order fails with a message to create the CNAME from `_acme-challenge.<name>` to `fulldomain` (`acme.dns` with `action: register`); once the CNAME is there, `POST /acme/renew` or the next retry obtains it. TXT values are written with `POST /update` (`X-Api-User` / `X-Api-Key`) and not removed (acme-dns keeps the latest two).
- Generic REST templates can use `{fqdn}` (the `_acme-challenge.…` name written, after following CNAMEs, without the final dot), `{value}` (the TXT value), `{zone}` and `{secret}` (the content of `secret_file`). `{secret}` may not be in the URL (URLs end up in logs; use a header or the body). Anything but 2xx is a failure.
- Secret files (`api_key_file`, `secret_file`, `hmac_key_file`) and `ca_file` that do not exist stop the startup (a mistake in the settings). One that cannot be read (permissions) fails when used, and is retried.
- The account is created at the CA on the first order (its key in `key_file`, 0600). With a key already there, the account of that key is used, so a key from another tool works too (PKCS#8 PEM, ECDSA P-256).

## How it works

1. When a rule starts using an ACME certificate (created, changed, from the settings file or the database), a certificate not obtained yet is ordered at once. Until then the rule serves a self-signed stand-in (`rproxy ACME placeholder`, never written to disk); the rule's `acme` shows `pending`.
2. Once the challenges are answered and the CA has validated them, the key (`key.pem`) and the certificate (`cert.pem`, with its intermediates) are written (0600) to `<storage>/certs/<resolver>/<first name>-<hash>/`. The certificate store sees the files change and rebuilds only the rules that use the certificate (connections stay).
3. When the CA offers ACME renewal information (ARI, RFC 9773), the certificate is renewed at a random time in its window (`suggestedWindow`; asked again every 1 to 24 hours as the CA's `Retry-After` says, so an early renewal the CA asks for, e.g. before a mass revocation, is followed; the renewal order names the old certificate with `replaces`). With a CA without ARI, it is renewed 30 days before expiry (or a third of its lifetime if that is shorter; `renew_before` changes it). A failure is retried after 1 minute, doubling up to 6 hours, and the certificate in use stays (`acme` shows `error` and `next_attempt`).
4. After a restart, stored certificates are used at once (no new order). A certificate no rule uses any more is not renewed (its files stay).
5. Orders are limited by `rate_limit` (10 per hour for the process by default); beyond that, an order waits (`acme.rate_limited`), so the CA's own limits (Let's Encrypt counts per name and per account) are not used up.

Orders are made one at a time. Expiry checks and warnings (`cert.expiring` and so on, `RPROXY_CERT_WARN_DAYS`) and `rproxy_cert_expiry_seconds` in `/metrics` are the same as for other certificate files.

### HTTP-01

- An `http` rule on port 80 answers `/.well-known/acme-challenge/<token>` for the tokens rproxy is answering now, before routes and middlewares (redirect to HTTPS, `ip_allow`, authentication...). Other tokens go through the routes as usual (a route to certbot or another tool keeps working).
- Without an `http` rule on port 80, `global.acme.http01_listen` runs a small responder (404 for anything but challenges); rules cannot take its address. Port 80 forwarded at L4 (passthrough) cannot answer.
- A rule's `allow_from` applies first: do not shut out the CA's validation (Let's Encrypt validates from many places).

### TLS-ALPN-01

- A tcp `terminate` rule (`http` rules included) answers a ClientHello that offers only the ALPN `acme-tls/1` for a name being validated with the validation certificate (with the acmeIdentifier extension, RFC 8737), then closes. Other clients are not affected. Rules with `tls.unmatched: reject` answer too.
- Rules with mode `sni` / `passthrough` on port 443, and names of `passthrough` routes, cannot answer. UDP (DTLS) rules cannot use ACME certificates (`400 tls_config`).

### DNS-01

1. The CNAME of `_acme-challenge.<name>` is followed (up to 8) to the name to write. **Delegating `_acme-challenge` to a zone only for challenges is recommended**: a leaked DNS API key then cannot change the production zone.
   ```
   ; production zone (written once, by hand)
   _acme-challenge.example.com.  CNAME  example.com.acme.example.net.
   ; the provider's zones: [acme.example.net], with an API key that can write only that zone
   ```
   Where delegation is not possible, use a key limited to the zone and to TXT records.
2. The zone written to is the longest of the provider's `zones` that holds the name (a name outside `zones` fails). Without `zones`, PowerDNS's list of zones decides, or the SOA in DNS for generic REST.
3. The record is noted in `<storage>/dns-pending.json` first, then written; rproxy waits until `dns_servers` see it (at most `dns_propagation_timeout`) and asks the CA to validate.
4. After validation, successful or not, the TXT record is removed. Records that could not be removed (or a process that stopped half way) stay in the journal and are removed on the next start (`acme.dns` with `reason: left over`).
5. PowerDNS: `PATCH /api/v1/servers/{server_id}/zones/{zone}` with a TXT RRset, `REPLACE` / `DELETE` (all values of one name in one call: a wildcard and its parent need two values).

To keep DNS secrets out of the main process, use the helper process below ("Helper process (separating secrets)").

## API

| | Scope | |
|---|---|---|
| `POST /rules` / `PATCH /rules/...` with an ACME certificate | `rules:write` and `acme:write` | `403` without `acme:write`; `400 invalid` for names outside the allowlists |
| `GET /acme` | `rules:read` | Accounts (`directory`, `contact`, `allowed_names`, `registered`), DNS providers (name, `type`, `zones`, `allowed_names`), resolvers, certificate states, orders used of `rate_limit`. No secret, and not where secrets are kept |
| `POST /acme/renew` `{"resolver", "domains"}` | `acme:write`; only over the Unix socket by default | Renews now (within `rate_limit`). `202` |
| `POST /acme/revoke` `{"resolver", "domains", "reason"?}` | same | Revokes the issued certificate at the CA and orders a new one at once (within `rate_limit`); the revoked one is served until the new one is written. `reason`: `unspecified`, `key_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation` |
| `POST /acme/accounts/{name}/register` | same | Creates the account at the CA (or finds the one of its key) |
| `POST /acme/accounts/{name}/deactivate` | same | Deactivates the account at the CA and moves its key aside (`<key_file>.deactivated`); the next order creates a new account |

- The strong operations (`POST /acme/...`) are, like `POST /config/reload`, accepted only over the Unix socket (`RPROXY_API_SOCKET`) by default. `RPROXY_API_RELOAD_UNIX_ONLY=false` allows them over TCP too (it covers both).
- Rule views get `acme`: the certificate's `state` (`pending` / `valid` / `renewing` / `error`), `not_after`, `renew_at`, `next_attempt`, `error`, and the CA's renewal window `ari` (`start`, `end`).
- Operations are logged as `event: "audit"` (`action: acme.renew` / `acme.revoke` / `acme.account.register` / `acme.account.deactivate`).

## Logs

| `event` | |
|---|---|
| `acme.order` | An order started (`resolver`, `domains`, `renewal`) |
| `acme.issue` / `acme.renew` | A certificate was obtained / renewed (`not_after`) |
| `acme.error` | An order failed (`error`, `retry_at`, `failures`) |
| `acme.ari` | The CA's renewal window was received (`start`, `end`, `renew_at`; only when it changes) |
| `acme.revoke` | A certificate was revoked (`reason`) |
| `acme.rate_limited` | `rate_limit` held an order back (`retry_at`) |
| `acme.account` | An account was created, found or deactivated |
| `acme.challenge` / `acme.answer` | A challenge was set up / answered to the CA (debug / info) |
| `acme.dns` | A TXT record was written / removed (`action: add` / `remove`, `provider`, `fqdn`, `zone`, `reason`, `outcome`) |
| `acme.listening` | `http01_listen` started listening |

Secrets (API keys, tokens, EAB keys, account keys) never appear in logs or API answers. Error answers of a provider are cut to 200 characters and have the secret masked before they are logged.

## Permissions and storage

- `storage` (default `/var/lib/rproxy/acme`) must be writable by rproxy's user. The systemd unit (.deb, install.sh) has `StateDirectory=rproxy`, which makes `/var/lib/rproxy` the rproxy user's and writable (even with `ProtectSystem=strict`). rproxy creates what is below it: directories 0700, files 0600. If it cannot be written, rproxy starts anyway (`degraded`, `part: global.acme.storage`) and serves the stand-in until certificates can be stored.
- Ports 80 / 443 need `CAP_NET_BIND_SERVICE` (the unit has it by default; docs/en/PERMISSIONS.md).
- `--check-config` also checks `global.acme`, whether the rules' names are allowed and whether the secret files exist (it writes nothing and does not contact the CA).

## Tests

CI's `clippy + tests` job runs Alpine's Pebble (the ACME test CA) and PowerDNS in the same container; tests/acme.rs obtains real certificates through HTTP-01 (`http01_listen`), TLS-ALPN-01 and DNS-01 (the PowerDNS API, RFC 2136 (TSIG SHA256 and SHA512, and a wrong key refused), acme-dns (with registration and the CNAME notice), CNAME delegation, a small relay for generic REST), and checks that TXT records are removed, that records left over from an earlier run are cleaned up, renewal over the Unix socket, use of stored certificates after a restart, and that no secret appears in answers or logs (docs/en/TESTING.md).
