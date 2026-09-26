# Traefik から移る

`contrib/traefik2rproxy.py`（.deb では `/usr/bin/rproxy-traefik-convert`）は、Traefik の設定を rproxy の設定ファイル（`RPROXY_CONFIG`。`version: 1`・`global`・`rules`）に変換します。変換できなかった設定は、出力の先頭のコメントと標準エラーに一覧されます。出力はそのまま使わず、一覧を確かめてから置いてください。

## 使い方

```bash
# 静的な設定から。providers.file の filename / directory の動的な設定も読む
rproxy-traefik-convert --static /etc/traefik/traefik.yml -o /etc/rproxy/rproxy.yaml

# 動的な設定を別に指定する（ファイルかディレクトリ。何回でも指定できる）
rproxy-traefik-convert --static traefik.toml --dynamic dynamic/ -o rproxy.yaml

# Docker のラベルから（docker inspect の出力）
docker inspect $(docker ps -q) > containers.json
rproxy-traefik-convert --static traefik.yml --docker containers.json -o rproxy.yaml

# 移す先の rproxy で使える機能と照らし合わせる
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/capabilities > caps.json
rproxy-traefik-convert --static traefik.yml --capabilities caps.json -o rproxy.yaml
```

- 必要なもの：Python 3.8 以上。YAML の読み書きには PyYAML（`apt install python3-yaml`）、TOML の読み込みには Python 3.11 以上。PyYAML がないときは JSON で出力する（rproxy は JSON の設定ファイルも読める。`--json` でも JSON になる）。
- 終了コードは、入力が読めないときだけ 2。変換できない設定があっても 0 で、一覧に出す。
- `:443` のようにアドレスを省いたエントリポイントは `--listen-addr`（既定 `0.0.0.0`）で待ち受ける。
- 変換した結果は `rproxy-api` の起動（または `RPROXY_CONFIG` の自動の読み直し）で検証される。誤りがあれば起動しない（読み直しでは反映しない）ので、置く前に手元の rproxy で試すと確実。

## 対応

### エントリポイントとルール

| Traefik | rproxy |
|---|---|
| `entryPoints.<名前>.address`（`:443`、`192.0.2.1:80`、`:53/udp`） | 1 つのエントリポイントが 1 つのルール（`protocol`・`listen_addr`・`listen_port`） |
| HTTP のルーター | そのエントリポイントのルールの `http.routes`（名前は `@file` などを除いたもの） |
| ルーターの `rule` | `match`。v3 の書き方はそのまま。v2 の `Headers` → `Header`、`HostHeader` → `Host`、`Query(`a=b`)` → `Query(`a`, `b`)`、`{name:regex}` の置き換えは `HostRegexp` / `PathRegexp` にする |
| `priority` | `priority`（省略時はどちらも `match` の長さ） |
| `entryPoints.<名前>.http.redirections.entryPoint` | そのエントリポイントのルールを、すべてをリダイレクトする 1 つのルート（`redirect_scheme`）にする |
| `entryPoints.<名前>.http.middlewares` | そのエントリポイントのすべてのルートの先頭に付ける |
| `entryPoints.<名前>.http.tls`、ルーターの `tls` | ルールの `tls.mode: terminate` |
| `entryPoints.<名前>.http3` | `http.http3: true` |
| `entryPoints.<名前>.forwardedHeaders.trustedIPs` | `global.trusted_proxies` |
| `accessLog.filePath` | `global.access_log`（書式は rproxy の JSON Lines。Traefik の書式やフィルタは変換しない） |
| TCP のルーター（`HostSNI`、`tls.passthrough: true`） | `tls.mode: sni` の `tls.routes`。`HostSNI(`*`)` がルールの転送先（なければ `unmatched: reject`） |
| TCP のルーター（TLS を終端する） | `tls.mode: terminate` の `tls.routes` |
| TCP のサービスの `proxyProtocol.version` | `source_ip: proxy_v1` / `proxy_v2` |
| UDP のルーター | `protocol: udp` のルール |

### サービス

| Traefik | rproxy |
|---|---|
| `loadBalancer.servers[].url` / `weight` | `http.services.<名前>.servers` |
| `passHostHeader: false` | `pass_host_header: false` |
| `healthCheck.path` / `interval` / `timeout` | `health_check` |
| `sticky.cookie.name` | `sticky.cookie` |
| `serversTransport`（`insecureSkipVerify`・`rootCAs`・`serverName`） | TLS を終端するルールの `tls.upstream`（ルールのすべての `https://` の転送先に効く） |
| `weighted` | 中のサービスの転送先を 1 つにまとめ、重みを掛け合わせる |
| `mirroring` / `failover` | 主のサービスだけを使う |
| TCP / UDP のサービスの転送先が複数 | 先頭の 1 つだけ（L4 のルールの転送先は 1 つ） |

### ミドルウェア

| Traefik | rproxy |
|---|---|
| `redirectScheme` / `redirectRegex` | `redirect_scheme` / `redirect_regex` |
| `stripPrefix` / `addPrefix` / `replacePath` / `replacePathRegex` | `strip_prefix` / `add_prefix` / `replace_path` / `replace_path_regex` |
| `headers` | `headers`（`customRequestHeaders` / `customResponseHeaders` の空の値は削除、HSTS、`frameDeny`、`contentTypeNosniff`、`referrerPolicy`、`contentSecurityPolicy`、CORS。`customFrameOptionsValue`・`browserXssFilter`・`permissionsPolicy` は応答のヘッダとして付ける） |
| `rateLimit` | `rate_limit`（`sourceCriterion.requestHeaderName` は `source: header:<名前>`。`ipStrategy` は変換せず、`global.trusted_proxies` でクライアントの IP を決める） |
| `inFlightReq` | `in_flight`（クライアントの IP ごと） |
| `ipAllowList` / `ipWhiteList` | `ip_allow` |
| `basicAuth` | `basic_auth`。`users` はファイルに書き出さないので、一覧に出るパスに htpasswd 形式で置く（`$apr1$`・bcrypt・`{SHA}` をそのまま使える）。`realm` → `realm`、`headerField` → `user_header`。Traefik は既定で `Authorization` を転送先に渡すので、`removeHeader` がなければ `keep_authorization: true` にする |
| `forwardAuth` | `forward_auth`。`authResponseHeaders` → `response_headers`、`authRequestHeaders` → `request_headers`、`trustForwardHeader` → `trust_forward_header`。`authResponseHeadersRegex`・`addAuthCookiesToResponse`・`tls` は変換しない |
| OIDC のプラグイン・oauth2-proxy | 変換しない。`oidc` ミドルウェア（docs/API.md）で書き直す。転送先には `X-Forwarded-User` / `-Email` / `-Groups` が届く |
| `compress` | `compress` |
| `retry` | `retry` |
| `circuitBreaker` | `circuit_breaker`。`NetworkErrorRatio() > 0.30` / `ResponseCodeRatio(...) > x` を `failure_percent` にする（`LatencyAtQuantileMS` は変換しない） |
| `errors` | `errors`（`query` を `path` に。サービスも一緒に写す） |
| `buffering` | `buffering`（`maxRequestBodyBytes`） |
| `chain` | 中のミドルウェアを順に展開する |
| CrowdSec の bouncer のプラグイン | `global.crowdsec`（LAPI・AppSec の URL、更新間隔）と `crowdsec` ミドルウェア。**API キーは写さない**ので、一覧に出るファイル（既定 `/etc/rproxy/crowdsec.key`）に書く |

rproxy のバージョンによって、まだ動かせないミドルウェアやサービスの設定があります（`GET /capabilities` の `features`）。変換ツールは、出力が使っていて rproxy がまだ持たない機能を一覧に出します（`--capabilities` を付けると、その rproxy の答えと照らし合わせる）。動かせない設定を使うルールは、rproxy が `unsupported` として登録しません（起動は続く）。

### TLS

| Traefik | rproxy |
|---|---|
| `certResolver`（ACME） | **rproxy は ACME を内蔵しない**。certbot / acme.sh / cert-manager で証明書を取り、そのファイルを指定する。変換ツールは certbot の置き場所（`--certbot-live`、既定 `/etc/letsencrypt/live/<名前>/fullchain.pem`・`privkey.pem`）を書き、取るべき名前を一覧に出す。`tls.domains` の `main` / `sans` が 1 つの証明書になり、ほかのルーターの名前がそれに含まれていれば同じ証明書を使う |
| `tls.certificates` | すべての TLS 終端のルールの `tls.certificates`（rproxy は SNI で選ぶ） |
| `tls.options.<名前>.minVersion` / `cipherSuites` | `tls.options.min_version` / `cipher_suites`（Go の名前を rustls の名前に。CBC など rustls にない暗号は外す） |
| `tls.options.<名前>.clientAuth` | `tls.client_auth`（`caFiles` は先頭の 1 つ） |
| `tls.options.<名前>.alpnProtocols` | `tls.alpn` |

証明書のファイルは rproxy が変更を検知して読み直します（`RPROXY_CERT_CHECK_SECS`）。certbot の更新をそのまま反映できます。certbot の http-01 を使うときは、80 番のルールに `/.well-known/acme-challenge/` を certbot（webroot を配る Web サーバや `--standalone` のポート）へ振り分けるルートを、リダイレクトより高い優先度で足してください。

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

## 変換しないもの

- Traefik 自身のサービス（`api@internal` のダッシュボード、`ping@internal` など）：ルーターごと外す。管理画面は rproxy の UI（TCP-UDP-rproxy-ui）を使う
- `metrics`：rproxy は制御 API の `GET /metrics` で Prometheus の形式を返す
- 受け取る PROXY protocol（`entryPoints.<名前>.proxyProtocol`）：rproxy は読まない（前段が付ける `X-Forwarded-For` は `global.trusted_proxies` で信用できる）
- HTTP と TCP のルーターが同じエントリポイントにあるとき：rproxy は 1 つのポートで両方を混ぜられないので、TCP のルーターを外す
- TLS を通すもの（passthrough）と終端するものが同じエントリポイントにあるとき：終端する方を外す
- `HostSNIRegexp`、`ALPN()`、ラベルだけの `defaultRule`、Kubernetes の IngressRoute（CRD）
- ミドルウェアの `digestAuth`、`contentType`、`passTLSClientCert`、`grpcWeb`、`stripPrefixRegex`、CrowdSec 以外のプラグイン
- 各設定の細かな項目（一覧に `... is not converted` として出る）
