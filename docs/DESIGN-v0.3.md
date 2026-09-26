# v0.3 の設計: 設定と API の形

v0.3.0 では、これから入れる機能の**設定と API の形**をまとめて決める（#72）。中身は v0.3.x のパッチで順に使えるようにする（docs/RELEASING.md）。
この文書が決まったら、docs/API.md に正式な形として書き写し、この文書は設計の経緯として残す。

目標は、今 Traefik で動いている設定（gitlab のパス別のルート・レート制限・CrowdSec、cdn の許可パス、metrics、HTTP→HTTPS）を、rproxy だけで書けるようにすること（#29）。

## 1. 方針

| 項目 | 決めたこと |
|---|---|
| 人が書くファイル | YAML（`.yaml` / `.yml`）。`.json` も同じ形で読む（#27） |
| 制御 API | JSON。ファイルのルールと同じ形 |
| DB の `options` 列 | JSON。ルールの `http` などを足す |
| 使えるかどうか | `GET /capabilities` の `features` で知らせる。まだ実装していない機能を指定したルールは `unsupported` で断る（保存もしない） |
| 互換 | 0.2 の形（ルールの配列の JSON、今の API のフィールド、今のトークンファイル）はそのまま読める |
| 再利用 | ミドルウェアやサービスはルールの中に書く（API・DB・UI で扱いやすいため）。ファイルでは YAML のアンカー（`&name` / `*name`）で使い回せる |

## 2. 設定ファイル（#27）

`RPROXY_CONFIG` にファイルかディレクトリ（`*.yaml` を名前順に読む）を指定する。書き換えたら再起動なしで差分を反映する。`RPROXY_STATIC_RULES` はこれの別名として残す（中身がルールの配列でも、下の形でもよい）。

```yaml
# /etc/rproxy/rproxy.yaml
version: 1

# プロセス全体の設定（環境変数の RPROXY_* より優先しない。どちらか片方で書く）
global:
  trusted_proxies: [10.0.0.0/8]          # #67。この範囲からの X-Forwarded-For / PROXY ヘッダを信用する
  access_log: /var/log/rproxy/access.log # #57。L7 のリクエストのログ（JSON Lines）
  acme:                                  # #17
    resolvers:
      letsencrypt:
        email: admin@example.com
        directory: https://acme-v02.api.letsencrypt.org/directory
        challenge: tls-alpn-01           # http-01 / tls-alpn-01 / dns-01
        # dns-01 のとき: provider と、秘密の値を置いたファイル
        # dns: {provider: cloudflare, credentials_file: /etc/rproxy/acme/cloudflare.env}
    storage: /var/lib/rproxy/acme
  crowdsec:                              # #55
    lapi_url: http://127.0.0.1:8080
    api_key_file: /etc/rproxy/crowdsec.key
    appsec_url: http://127.0.0.1:7422
    update_interval: 10s

rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls: {...}          # 今と同じ（下の 4. で ACME とオプションを足す）
    http: {...}         # 3. の L7
```

## 3. L7（ルールの `http`）

`http` があるルールは、TLS を終端した後（`tls.mode: terminate`）または平文で、HTTP としてリクエストごとに振り分ける。`http` を付けられるのは `protocol: tcp` で、`tls.mode` が `terminate` か、TLS なし（`passthrough` 扱いで平文の HTTP）のとき。

```yaml
http:
  http3: true                  # #56。UDP の同じポートで QUIC も受ける。Alt-Svc を付ける
  routes:                      # #52。優先度の高い順、同じなら match の長い順に試す
    - name: gitlab-login
      match: Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)
      priority: 100
      service: gitlab
      middlewares: [crowdsec, rate-limit-login]
  default:                     # どの route にも一致しないとき（省略時は 404）
    status: 404
  services:                    # #61
    gitlab:
      servers:
        - url: http://10.0.0.20:80
          weight: 1
      health_check: {path: /-/readiness, interval: 10s, timeout: 3s}
      sticky: {cookie: rproxy_gitlab}
      pass_host_header: true
      timeouts: {connect: 5s, response: 60s}   # #64
  middlewares:                 # 名前 → 種類 1 つ
    rate-limit-login: {rate_limit: {average: 5, period: 1m, burst: 10}}
    crowdsec: {crowdsec: {appsec: true}}
```

- `http` のルールには `remote_addr` / `remote_port` を書かない（転送先はすべて `services`。書くと `invalid`）。
- 転送先は `service`（名前）か、`to: http://host:port`（サービスを 1 つだけ書く省略形）で指定する。
- `X-Forwarded-For` / `-Proto` / `-Host` / `X-Real-IP` は常に付ける（`global.trusted_proxies` からの値は引き継ぐ。クライアントの IP は X-Forwarded-For を右から見て最初の信頼しないアドレス。PROXY ヘッダは読まない）。WebSocket はそのまま通す。
- リダイレクトだけのルート（80 番の HTTP→HTTPS など）は `service` を書かず、ミドルウェアが応答を返す。
- （v0.3.1 で決めたこと）`source_ip` は `proxy` / `transparent` だけ（PROXY ヘッダはリクエスト単位の転送に合わないので `X-Forwarded-For` で渡す）。`tls.routes` は使わず `Host(...)` で振り分ける。`https://` の転送先の検証には `tls.upstream` の `ca_file` などを使い、`tls.upstream.tls` は使わない。転送先への接続はまずリクエストごとに作り、再利用は後で足す。細かい動きは docs/API.md の「`http` のルールの動き」。

### match の書き方（Traefik と同じ）

| 条件 | 例 |
|---|---|
| `Host` / `HostRegexp` | ``Host(`gitlab.example.com`)``、``HostRegexp(`^.+\.example\.com$`)`` |
| `Path` / `PathPrefix` / `PathRegexp` | ``PathPrefix(`/api/`)`` |
| `Method` | ``Method(`POST`)`` |
| `Header` / `HeaderRegexp` | ``Header(`X-Requested-With`, `XMLHttpRequest`)`` |
| `Query` / `QueryRegexp` | ``Query(`preview`, `1`)`` |
| `ClientIP` | ``ClientIP(`10.0.0.0/8`, `fd00::/8`)`` |

`&&`・`||`・`!`・括弧で組み合わせる。

### ミドルウェアの種類

| 種類 | 設定 | issue |
|---|---|---|
| `redirect_scheme` | `scheme`（既定 https）、`port`、`permanent` | #53 |
| `redirect_regex` | `regex`、`replacement`、`permanent` | #53 |
| `rate_limit` | `average`、`period`、`burst`、`source`（`ip` / `header: X-Real-IP`） | #54 |
| `in_flight` | `amount`（同時に処理するリクエスト数） | #54 |
| `crowdsec` | `appsec`（true / false）、`on_error`（`allow` / `block`） | #55 |
| `ip_allow` | `source_range`（CIDR の一覧） | #53 と一緒に v0.3.1 |
| `headers` | `request` / `response` の `set`・`remove`、`hsts`、`frame_deny`、`content_type_nosniff`、`referrer_policy`、`csp`、`cors` | #60 |
| `forward_auth` | `address`、`response_headers`、`trust_forward_header` | #59 |
| `oidc` | `issuer`、`client_id`、`client_secret_file`、`scopes`、`cookie_secret_file` | #59 |
| `basic_auth` | `users_file`（htpasswd） | #59 |
| `strip_prefix` / `add_prefix` / `replace_path` / `replace_path_regex` | `prefixes` / `prefix` / `path` / `regex`・`replacement` | #62 |
| `compress` | `encodings`（gzip・br・zstd）、`min_size` | #63 |
| `buffering` | `max_request_body`（413） | #64 |
| `retry` | `attempts`、`initial_interval`（冪等なメソッドだけ） | #64 |
| `circuit_breaker` | `failure_percent`（1〜100）、`window`、`recovery` | #64 |
| `errors` | `status`（`500-599` など）、`service`、`path` | #65 |
| `respond` | `status`、`body`、`content_type`（メンテナンス表示や拒否） | #65 |

## 4. TLS の追加（#17、#66）

> ACME（#17）は v0.3.2 の時点で**内蔵しない**ことにした。証明書の取得・更新は certbot / cert-manager などに任せ、rproxy はファイルの変更を検知して読み直す（`RPROXY_CERT_CHECK_SECS`）。下の `acme` の形は v0.3.0 で決めたので残すが、`features.acme` は false のままで、指定すると `unsupported` になる。

```yaml
tls:
  mode: terminate
  certificates:
    - acme: letsencrypt                    # ACME で取る証明書（ファイルの代わり）
      domains: [gitlab.example.com, cdn.example.com]
    - cert_file: /etc/rproxy/tls/other.pem # 今までどおりファイルも使える
      key_file: /etc/rproxy/tls/other.key
  options:                                 # #66
    min_version: "1.2"
    cipher_suites: [TLS13_AES_128_GCM_SHA256, ...]
    alpn: [h2, http/1.1]                   # 今の alpn の置き場所をここにも
```

## 5. 制御 API

- `POST /rules`・`PATCH /rules/...` の本文に `http` と、`tls` の `acme` / `options` を足す（ファイルと同じ形）。
- `GET /capabilities` に、この版で使える機能を返す。

```json
{"features": {"http": true, "http3": false, "acme": false, "tls_options": false,
              "middlewares": ["redirect_scheme", "redirect_regex", "ip_allow", "headers"],
              "services": ["health_check"]}}
```

- `GET /rules/...` に L7 の統計（ルートごとのリクエスト数・状態コード別）を足す（#57）。

## 6. トークンの権限（#30）と Unix ソケット（#3）

トークンファイルは、今の「1 行に 1 つ」（全権限）に加えて YAML も読む。

```yaml
# /etc/rproxy/tokens.yaml
tokens:
  - name: ui
    sha256: 9f86d0...          # トークンそのものは置かない（sha256sum で作る）
    scopes: [rules:read, rules:write]
  - name: ci-deploy
    sha256: 2c26b4...
    scopes: [rules:write]
    allow_listen_ports: 20000-29999
    expires: 2027-03-31
```

- スコープ: `rules:read`、`rules:write`、`metrics:read`、`admin`（すべて）
- 変更の監査ログ: `event: "audit"`、トークンの名前、操作、ルール
- `GET /openapi.json` で API の定義を返す

Unix ソケット: `RPROXY_API_SOCKET=/run/rproxy/api.sock`（`RPROXY_API_SOCKET_MODE`、`RPROXY_API_SOCKET_GROUP`）。TCP の待ち受けと併用できる。UI は `RPROXY_API_URL=unix:/run/rproxy/api.sock`。

## 7. 例: 今の Traefik の設定を書き直すと

```yaml
version: 1
rules:
  # 80: HTTP→HTTPS（www も正規化）
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - name: redirect
          match: HostRegexp(`^.+$`)
          middlewares: [to-https]
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}

  # 443: gitlab と cdn
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - acme: letsencrypt
          domains: [gitlab.example.com, cdn.example.com]
    http:
      http3: true
      routes:
        - name: gitlab-login
          match: Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)
          service: gitlab
          middlewares: [crowdsec, rate-limit-login]
        - name: gitlab-api
          match: Host(`gitlab.example.com`) && PathPrefix(`/api/`)
          service: gitlab
          middlewares: [crowdsec]
        - name: gitlab-assets
          match: Host(`gitlab.example.com`) && (PathPrefix(`/assets/`) || PathPrefix(`/uploads/`))
          service: gitlab
          middlewares: [crowdsec, rate-limit-assets]
        - name: gitlab-internal
          match: Host(`gitlab.example.com`) && ClientIP(`10.0.0.0/8`)
          service: gitlab
        - name: gitlab
          match: Host(`gitlab.example.com`)
          service: gitlab
          middlewares: [crowdsec]
        - name: cdn-allowed
          match: Host(`cdn.example.com`) && (PathPrefix(`/file/`) || PathPrefix(`/images/`) || PathPrefix(`/iso/`))
          service: cdn
          middlewares: [crowdsec]
        - name: cdn-block
          match: Host(`cdn.example.com`)
          middlewares: [forbidden]
        - name: metrics
          match: PathPrefix(`/metrics`)
          service: metrics
          middlewares: [internal-only]
      services:
        gitlab: {servers: [{url: http://10.0.0.20:80}]}
        cdn: {servers: [{url: http://10.0.0.30:80}]}
        metrics: {servers: [{url: http://10.0.0.40:9100}]}
      middlewares:
        crowdsec: {crowdsec: {appsec: true}}
        rate-limit-login: {rate_limit: {average: 5, period: 1m, burst: 10}}
        rate-limit-assets: {rate_limit: {average: 100, period: 1s, burst: 200}}
        internal-only: {ip_allow: {source_range: [10.0.0.0/8]}}
        forbidden: {respond: {status: 403}}
```

### CrowdSec（#55、v0.3.1）

- LAPI の判定は stream（`/v1/decisions/stream`）で 1 つのタスクがまとめて取り、全ルールで共有する。判定は ID ごとに覚え、同じアドレスの別の判定が残っていれば止め続ける。
- captcha は出せないので ban と同じに扱う。scope は `Ip` と `Range` だけ。
- AppSec には、`Content-Length` が 1 MiB 以下の本文だけを送る（長さのない本文を読み切ってから転送すると、ストリーミングやアップロードを遅らせるため）。
- L4（`http` のないルール）で TLS より前に切る使い方は、まだない（#55 の残り）。

## 8. 決めていないこと（実装しながら詰める）

- `http` のルールの統計の粒度（ルート × 状態コードまで、パスまでは持たない予定）
- HTTP/2 で転送先へ送るか（まずは HTTP/1.1。gRPC が要るなら h2c を足す）
- Kubernetes の CRD（#28）は、このルールの形を `spec` にそのまま使う（`apiVersion: rproxy.max3584.net/v1alpha1`、`kind: RproxyRule`）
- source_ip の名前の変更（#49）は止めている。形を変えるなら v0.3.0 が機会
