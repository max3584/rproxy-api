# rproxy-api 制御 API

UI（TCP-UDP-rproxy-ui）と rproxy-api の間の取り決め。どちらかを変えるときは、このファイルも合わせて更新する。

## 基本

- HTTP/1.1、JSON（UTF-8）。`GET /metrics` だけは Prometheus のテキスト形式。
- 待ち受けアドレスは `--api-addr` で指定する（複数回指定できる）。ポートは `--api-port` で指定する（既定 8080。`0` で TCP を使わない）。
- Unix ソケットでも受けられる（`--api-socket`、`--api-socket-mode`、`--api-socket-group`）。中身は TCP と同じ HTTP/1.1 で、トークンも同じく要る。
- 認証：`--token-file` を指定した場合、`/healthz` 以外のエンドポイントは `Authorization: Bearer <token>` が必須になる。
  - トークンファイルは 2 つの書き方がある。
    - 1 行に 1 つトークンを書く（すべての権限。ログでの名前は `token-1`、`token-2`…）。空行と `#` で始まる行は無視する。
    - YAML で `tokens:` に名前・SHA-256・スコープを書く（トークンそのものはファイルに置かない）。

      ```yaml
      tokens:
        - name: ui
          sha256: 9f86d081...        # printf %s "$TOKEN" | sha256sum
          scopes: [rules:read, rules:write, metrics:read]
        - name: ci-deploy
          sha256: 2c26b46b...
          scopes: [rules:write]
          allow_listen_ports: 20000-29999   # 作成・変更・削除できる待ち受けポート（範囲ルールは全体が収まること）
          expires: 2027-03-31               # この日（UTC）まで有効
      ```

    - スコープ: `rules:read`（`GET /rules`・`/interfaces`）、`rules:write`（`POST` / `PATCH` / `DELETE /rules`）、`metrics:read`（`GET /metrics`）、`admin`（すべて）。`GET /capabilities` はどのトークンでも読める。足りないときは `403 forbidden`。
    - ルールの作成・変更・削除は `event: "audit"` のログに残る（`token`、`action`、`rule`、`outcome`、失敗時の `code`）。権限不足で断ったリクエストも残る。
  - 複数のトークンを同時に有効にできる。入れ替えのときは新旧を両方書いておき、あとで古い方を消す。
  - SIGHUP を受けるとトークンファイルを読み直す。
- `--api-addr` に loopback 以外のアドレスを含める場合は、`--token-file`、`--tls-cert`、`--tls-key` の指定が必須。どれかが欠けていると起動を拒否する。

## ルール

ルールは `(protocol, listen_addr, listen_port)` の組で一意に識別する。

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

| フィールド | 型 | 必須 | 説明 |
|---|---|---|---|
| `protocol` | `"tcp"` \| `"udp"` | ○ | 大文字・小文字は区別しない。応答では常に小文字で返す |
| `listen_addr` | string | ○ | IP アドレス（ホスト名は不可） |
| `listen_port` | 1–65535 | ○ | |
| `remote_addr` | string | ○ | IP アドレスまたはホスト名。ホスト名は 30 秒ごとに再解決する。`http` のルールでは書かない（転送先は `http.services`。一覧では `""` / `0`） |
| `remote_port` | 1–65535 | ○ | `http` のルールでは書かない |
| `source_ip` | `"proxy"` \| `"proxy_v1"` \| `"proxy_v2"` \| `"transparent"` | | 既定は `"proxy"`（送信元 IP を引き渡さない）。`proxy_v1` は TCP でのみ使える。`proxy_v2` は UDP でも使え、転送先へのデータグラムごとに PROXY v2（DGRAM）のヘッダを付ける（応答にはヘッダがない。宛先アドレスは待ち受けのアドレスで、`0.0.0.0` で待ち受けていれば `0.0.0.0`）。UDP の `proxy_v2` と `tls.upstream.tls`（転送先への DTLS）は組み合わせられない（`unsupported`）。`transparent` は `GET /capabilities` の `transparent`（IPv4）/ `transparent_ipv6`（IPv6 の待ち受け）が true のときだけ指定できる。クライアントと転送先は同じアドレスファミリーであること（docs/TRANSPARENT.md） |
| `udp_idle_secs` | 1–86400 | | UDP セッションを無通信で破棄するまでの秒数。既定は 30。TCP では無視する |
| `listen_port_end` | 1–65535 | | ポート範囲の終わり（`listen_port` 以上）。`listen_port..listen_port_end` の各ポートを、`remote_port` から順に同じ数だけずらした転送先へ送る。上限は `GET /capabilities` の `max_range_ports`（既定 20000） |
| `tls` | object | | TLS（tcp）/ DTLS（udp）の扱い。省略すると `{"mode": "passthrough"}`。下の「TLS」を参照 |
| `starttls` | `"smtp"` \| `"imap"` \| `"pop3"` | | STARTTLS の手前の平文のやり取りに rproxy が答え、TLS を終端する。`tls.mode` が `terminate` の tcp ルールでのみ使える |
| `starttls_required` | bool | | 既定 `true`。`false` にすると、SMTP で STARTTLS をしないクライアントも平文のまま通す（IMAP / POP3 では常に必須として扱う）。`starttls` なしで `false` を指定すると `invalid` |

| `allow_from` | string の配列 | | 接続を受け付ける送信元。CIDR（`172.16.0.0/16`、`fd00::/8`）または単一の IP。省略または空ならすべて受け付ける。最大 64 件。範囲外からの TCP 接続は、TLS や PROXY ヘッダより前に切断する。UDP は範囲外の送信元のデータグラムを捨てる（セッションを作らない） |

範囲ルールのキーは `listen_port`（範囲の先頭）。同じプロトコルで待ち受けアドレスとポートが重なるルールは作れない（`already_exists`）。

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

| フィールド | 説明 |
|---|---|
| `mode` | `passthrough`（既定。暗号化されたまま流す）、`sni`（tcp のみ。ClientHello のサーバ名で転送先を選び、復号しない）、`terminate`（rproxy で復号する。tcp は TLS、udp は DTLS） |
| `routes` | サーバ名ごとの転送先（`sni` と `terminate`）。範囲ルールでは、`remote_port` に範囲の長さを足して 65535 を超えないこと。`*.example.com` は 1 階層だけ一致する。一致しない名前はルールの `remote_addr` / `remote_port` へ。ポート範囲では、ここの `remote_port` も同じだけずれる |
| `unmatched` | `default`（既定。どの `routes` にも一致しない名前・SNI なしは、ルールの `remote_addr` / `remote_port` へ）または `reject`（切断する。`terminate` ではハンドシェイクを完了せずに切る）。tcp の `sni` / `terminate` で、`routes` があるときだけ指定できる |
| `certificates` | `terminate` で必須。`cert_file` はサーバ証明書、`chain_file` は中間 CA の証明書（サーバ証明書を発行した CA から、ルートへ向かう順。ルートは入れなくてよい）、`key_file` は秘密鍵。`cert_file` にチェーンを連結しても使える。読み込むときに、チェーンの順番と、鍵がサーバ証明書と対になっていることを確かめる。複数あれば SNI で選び、どれにも一致しなければ先頭を使う。DTLS の鍵は PKCS#8（`-----BEGIN PRIVATE KEY-----`）に限る |
| `client_auth` | クライアント証明書の検証（mTLS）。`mode` は `none`（既定）/ `optional`（送られてきたら検証する）/ `required`。`optional` と `required` では `ca_file` が必須。`ca_file` はルート CA（信頼の起点）。`chain_file` はクライアント証明書の中間 CA で、中間 CA を送ってこないクライアントのために、検証の途中経路を補う（信頼の起点にはしない）。TLS と DTLS で同じ規則で検証する |
| `alpn` | `terminate` でクライアントに提示する ALPN（tcp のみ） |
| `upstream` | `terminate` の転送先側。`tls: true` で再暗号化する（tcp は TLS、udp は DTLS）。`server_name`（既定は転送先のホスト名）、`ca_file`（既定は Mozilla のルート証明書）、`insecure_skip_verify`（検証しない。テスト用）、`cert_file` / `chain_file` / `key_file`（転送先へのクライアント証明書と、その中間 CA） |

`terminate` と `source_ip: "proxy_v2"` を組み合わせると、PROXY v2 ヘッダに TLS の情報を TLV で付ける。
- `PP2_TYPE_AUTHORITY`：SNI
- `PP2_TYPE_ALPN`：ALPN
- `PP2_TYPE_SSL`：TLS であること、クライアント証明書の有無、`PP2_SUBTYPE_SSL_VERSION`、クライアント証明書の CN（`PP2_SUBTYPE_SSL_CN`）

証明書ファイルは、ルールの作成・変更のときに読み込む。ファイルを差し替えたあとで SIGHUP を送ると、全ルールの証明書を読み直す（読めなかったルールは今の証明書のまま）。

応答で返すルールには、次の稼働情報が加わる（`allow_from` は正規化した CIDR の形で返す。例：`10.0.0.5` → `10.0.0.5/32`）。

| フィールド | 説明 |
|---|---|
| `state` | `"running"` または `"failed"` |
| `error` | `failed` の理由。`running` なら `null` |
| `resolved` | 最後に名前解決できた転送先（`"ip:port"` の配列）。まだ解決できていなければ空 |
| `connections` | 現在の接続数（UDP はセッション数） |
| `stats` | ルールが開始してからの累計：`total_connections`、`rx_bytes`（クライアント → 転送先）、`tx_bytes`（転送先 → クライアント）、`tls_failures`（TLS / DTLS のハンドシェイクや STARTTLS の失敗） |
| `started_at` | 待ち受けを始めた時刻（Unix 秒）。`failed` のときは `null` |
| `origin` | `dynamic`（API で作ったルール、または DB から復元したルール）か `static`（固定ルール。下を参照） |

`stats` には `denied`（`allow_from` の範囲外、または `unmatched: reject` で切断した接続の数）も含む。
`http` のルールでは、`stats.http` にリクエストの数も入る（ほかのルールでは省く）。

```json
"http": {"requests": 5, "by_status": {"2xx": 3, "4xx": 2},
         "routes": {"site": {"requests": 3, "by_status": {"2xx": 3}}, "(none)": {"requests": 1, "by_status": {"4xx": 1}}}}
```

- `by_status` は状態コードの百の位ごと（`1xx`〜`5xx`。0 件の区分は省く）。`routes` はルートの名前ごとで、どのルートにも一致しなかったリクエストは `(none)`。
- 応答の本文を送り終えた（またはクライアントが切断した）ときに数える。

## 設定ファイル（固定ルール）

`RPROXY_CONFIG`（`--config`）に設定ファイルを指定すると、起動時にそのルールを開始する。0.2 の `RPROXY_STATIC_RULES`（`--static-rules`）も同じ意味で使える（両方は指定できない）。

- 形式は拡張子で決まる: `.yaml` / `.yml` は YAML（コメント、アンカー `&name` / `*name` が使える）、それ以外は JSON。YAML と JSON は同じ形で、同じ意味になる。
- 中身は次のどちらか。
  - `{"version": 1, "global": {...}, "rules": [...]}`（v0.3）
  - ルールの配列（0.2 の形）
- `rules` の各要素は `POST /rules` の本文と同じ形。
- `global` はプロセス全体の設定（`trusted_proxies`、`access_log`、`acme`、`crowdsec`。docs/DESIGN-v0.3.md の 2.）。この版で動かせない項目（`acme`、`crowdsec`）は、ログに `"event":"degraded"`（`part: global.<項目>`）を出して読み飛ばす。
  - `trusted_proxies`: CIDR の配列。`http` のルールで、接続元がこの範囲なら `X-Forwarded-For` を信用する（API で作ったルールにも効く）。
  - `access_log`: `http` のルールのアクセスログのファイル（JSON Lines。`RPROXY_LOG_FILE` と同じく日ごとに `<名前>.<日付>.<拡張子>` へローテーションし、`RPROXY_LOG_KEEP` 個残す）。省略するとアクセスログはメインのログ（`event: "http.access"`）に出す。ディレクトリがなければ起動しない。書き込めなければメインのログに出す（`part: global.access_log`）。
- DB からの復元より前に開始する。DB に接続できなくても動く。
- API からは変更・削除できない（`409 static`）。変えるときは、ファイルを書き換えて rproxy を再起動する。
- 同じキーや重なるポートのルールを API や DB から作ろうとすると、`already_exists` になる。
- ファイルが存在しない、書式や形が不正（知らないキー、`version` が 1 以外、存在しない ACME の resolver の参照など）の場合は、rproxy は起動しない。読めない（権限）ときは、固定ルールなしで起動する。
- この版で動かせない機能（`GET /capabilities` の `features` が false）を使うルールは、`failed`（理由つき）として登録し、設定の内容は `GET /rules` で見える。名前解決や bind の失敗はほかのルールと同じ扱いになる。

例：ダッシュボード（Web UI）を `dashboard.proxy.home` だけで、社内から公開する。

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

## v0.3 の設定（L7・ACME・TLS のオプション）

v0.3.0 で形を決め、中身は v0.3.x のパッチで順に使えるようにする（docs/RELEASING.md）。この版で動かせるかは `GET /capabilities` の `features` で分かる。動かせない設定を使うルールは、形を検証したうえで `400 unsupported` で断る（形が不正なら `400 invalid` / `tls_config`）。設計の全体と例は docs/DESIGN-v0.3.md。

| 項目 | 場所 | 形 | features |
|---|---|---|---|
| L7 のルーティング | ルールの `http` | `routes`（`name`、`match`、`priority`、`service` か `to`、`middlewares`）、`default`、`services`、`middlewares`、`http3` | `http`（v0.3.1 から）、`http3`、`middlewares` |
| サービス | `http.services.<名前>` | `servers`（`url`、`weight`）、`pass_host_header`、`timeouts`（`connect`、`response`）、`health_check`、`sticky` | `http`。`health_check` / `sticky` は `services` に含まれるもの |
| `match` | `http.routes[].match` | Traefik と同じ式。`Host`・`HostRegexp`・`Path`・`PathPrefix`・`PathRegexp`・`Method`・`Header`・`HeaderRegexp`・`Query`・`QueryRegexp`・`ClientIP` を `&&`・`\|\|`・`!`・括弧で組み合わせる | `http` |
| ミドルウェア | `http.middlewares.<名前>` | `{種類: {設定}}`。種類は `redirect_scheme`・`redirect_regex`・`rate_limit`・`in_flight`・`crowdsec`・`ip_allow`・`headers`・`forward_auth`・`oidc`・`basic_auth`・`strip_prefix`・`add_prefix`・`replace_path`・`replace_path_regex`・`compress`・`buffering`・`retry`・`circuit_breaker`・`errors`・`respond` | `middlewares` に種類が含まれるもの |
| ACME の証明書 | `tls.certificates[]` | `{"acme": "<resolver>", "domains": [...]}`（`cert_file` / `key_file` の代わり） | `acme` |
| TLS のオプション | `tls.options` | `min_version`（`"1.2"` / `"1.3"`）、`cipher_suites` | `tls_options` |

- `http` は `protocol: tcp` で、`tls.mode` が `terminate`（HTTPS）か、TLS なし（平文の HTTP）のときだけ。`sni`・`starttls`・ポート範囲とは組み合わせられない。`remote_addr` / `remote_port` は書かない（書くと `400 invalid`）。
- `PATCH` で `http` を付けると、L7 の設定を丸ごと置き換える（次のリクエストから）。`http` のないルールに `PATCH` で `http` を付けることはできない（`unsupported`。作り直す）。

### `http` のルールの動き（v0.3.1）

- クライアントとは HTTP/1.1 と HTTP/2 で話す。`terminate` では、`tls.alpn` を指定していなければ ALPN で `h2` と `http/1.1` を提示する（`GET /rules` の `tls.alpn` は指定どおりのまま）。平文では HTTP/1.1 と、前置きで始まる HTTP/2（h2c）を受ける。
- ルートは `priority` の大きい順（省略時は `match` の文字数。Traefik と同じ）、同じなら書いた順に試し、最初に一致したものを使う。どれにも一致しなければ `default`（`service` か `status`。省略時は 404）。
- `Host` はポートを除き、大文字小文字を区別しない。HTTP/2 では `:authority` を使う。`ClientIP` はクライアントの IP：接続元、または接続元が `global.trusted_proxies` の範囲なら、`X-Forwarded-For` を右から見て最初の信頼しないアドレス（Traefik と同じ。クライアントが左に書き足したアドレスは使わない）。`ip_allow`・`X-Real-IP`・アクセスログも同じ IP を使う。
- 転送先とは HTTP/1.1 で話す。`servers` は `weight`（既定 1）の重みつきラウンドロビン。`url` にパスがあれば、リクエストのパスの前に付ける。`https://` の転送先の証明書は、ルールの `tls.upstream` の `ca_file`（なければ Mozilla のルート）で検証し、`server_name` / `insecure_skip_verify` / クライアント証明書もそれに従う。`tls.upstream.tls` は使わない（URL の `https://` で決まる。指定すると `tls_config`）。
- 転送先への接続はリクエストごとに作る（接続の再利用はまだしない）。
- `pass_host_header`（既定 true）が false なら、`Host` は転送先の URL のホスト（とポート）にする。
- 転送先へは `X-Forwarded-For`・`X-Real-IP`（クライアントの IP）、`X-Forwarded-Proto`（`http` / `https`）、`X-Forwarded-Host`、`X-Forwarded-Port` を付ける。クライアントが送ってきた同名のヘッダは置き換える。ただし接続元が `global.trusted_proxies` の範囲なら、`X-Forwarded-For` は受けた値の後ろに接続元を足し、`X-Forwarded-Proto` / `-Host` / `-Port` は受けた値を保つ。ホップごとのヘッダ（`Connection` とそこに書かれたもの、`Keep-Alive`、`TE`、`Transfer-Encoding` など）は取り除く。
- `Connection: Upgrade`（WebSocket など）は、転送先が 101 を返せばそのまま中継する。ルールを削除すると切れる。
- 転送先に接続できなければ 502、`timeouts.connect`（既定 5 秒）・`timeouts.response`（既定 60 秒。応答ヘッダまで）を過ぎると 504。`event: "http.error"` のログを出す。
- アクセスログ（`event: "http.access"`）はリクエストごとに 1 行：`rule`、`route`（一致しなければ `(none)`）、`service`、`backend`、`client`、`method`、`host`、`path`（クエリは含めない）、`protocol`（`HTTP/1.1` / `HTTP/2.0`）、`status`、`duration_ms`（応答の本文を送り終えるまで）、`bytes_in`（`Content-Length`）、`bytes_out`（応答の本文）、`user_agent`、`sni`、`tls_version`。出す先は `global.access_log`。
- `GET /metrics` の `rproxy_http_requests_total{protocol,listen,route,code}`（`code` は `2xx` など）と `rproxy_http_request_duration_seconds{protocol,listen,route}`（ヒストグラム。境界は 5ms〜10s）。ラベルにパスは入れない。
- ミドルウェアはルートの `middlewares` に書いた順にリクエストへ働き、応答へは逆の順に働く（Traefik と同じ）。途中のミドルウェアが応答を返したら（リダイレクト・`respond`・拒否）、その先へは進まない。その応答にも、それまでに通ったミドルウェアの応答側（`headers` など）が働く。
- 使えるミドルウェア（v0.3.1。`features.middlewares`）:
  - `redirect_scheme`: `scheme` と違う方式で受けたリクエストを、同じホスト・パス・クエリの `scheme://` へリダイレクトする。`port` は既定のポート（80 / 443）なら省く。
  - `redirect_regex`: `http://host[:port]/path?query`（受けた URL）が `regex` に一致すれば、`replacement`（`$1`・`${name}` が使える）へリダイレクトする。一致しなければ次へ進む。
  - リダイレクトの状態コードは、`permanent` なら 301、そうでなければ 302。GET / HEAD 以外は 308 / 307（メソッドと本文を保つ）。
  - `respond`: `status`・`body`・`content_type`（既定 `text/plain; charset=utf-8`）で応答する。`service` のないルート（ブロックやメンテナンス表示）に使う。
  - `ip_allow`: 接続元の IP が `source_range` になければ 403。
  - `headers`: `request` / `response` の `set`（空の値は削除）・`remove`。`frame_deny`（`X-Frame-Options: DENY`）、`content_type_nosniff`、`referrer_policy`、`csp`。`hsts` は HTTPS で受けたときだけ付ける。`cors` は `Origin` が `allow_origins`（`*` も可）にあるとき `Access-Control-Allow-Origin`（`allow_credentials` なら `Access-Control-Allow-Credentials` も）と `Vary: Origin` を付け、プリフライト（`OPTIONS` と `Access-Control-Request-Method`）には rproxy が 204 で答える。
  - `strip_prefix`: パスが `prefixes` のどれか（先に書いたもの優先）で始まれば取り除き、`X-Forwarded-Prefix` を付ける。`add_prefix`: パスの前に付ける。`replace_path`: パスを置き換え、元のパスを `X-Replaced-Path` に入れる。`replace_path_regex`: 一致したときだけ置き換える（`X-Replaced-Path` も）。クエリは保つ。
- `source_ip` は `proxy` か `transparent`（転送先への接続の送信元をクライアントにする）。`proxy_v1` / `proxy_v2` は使えない（`invalid`。クライアントの IP は `X-Forwarded-For` で渡す）。`tls.routes` も使えない（`tls_config`。`Host(...)` で振り分ける）。
- 接続の統計（`stats`）はクライアントとの接続単位で、`rx_bytes` はクライアントから、`tx_bytes` はクライアントへのバイト数。
- DB の `options` 列の JSON にも `http` を保存できる（`{"tls", "starttls", "starttls_required", "allow_from", "http"}`）。

## エンドポイント

| メソッドとパス | 本文 | 成功時 | 説明 |
|---|---|---|---|
| `GET /healthz` | | 200 `ok` | 認証不要 |
| `GET /capabilities` | | 200 | `{"source_ip":[...],"transparent":true,"transparent_ipv6":true,"tls_modes":["passthrough","sni","terminate"],"dtls":true,"starttls":["smtp","imap","pop3"],"max_range_ports":20000,"features":{"http":true,"http3":false,"acme":false,"tls_options":false,"middlewares":["redirect_scheme","redirect_regex","ip_allow","headers","strip_prefix","add_prefix","replace_path","replace_path_regex","respond"],"services":[]}}`。`features` はこの版で動かせる v0.3 の設定（上の「v0.3 の設定」）。`source_ip` の `transparent` は `IP_TRANSPARENT` が使えるときだけ含まれる。`transparent_ipv6` は IPv6 の待ち受けで transparent を使えるか（`IPV6_TRANSPARENT`） |
| `GET /interfaces` | | 200 | 待ち受けに使えるアドレス：`{"interfaces":[{"name":"ens18","addr":"172.16.5.1","family":"ipv4","loopback":false,"link_local":false}, ...],"reserved":[{"protocol":"tcp","addr":"127.0.0.1","port":8080,"purpose":"control API"}]}`。動作中のインターフェースだけを返す。`reserved` は rproxy 自身が使うアドレスで、ルールには使えない |
| `GET /rules` | | 200 | ルールの配列 |
| `GET /rules/{protocol}/{listen_addr}/{listen_port}` | | 200 | ルール 1 件 |
| `POST /rules` | ルール | 201 | 転送を開始する。名前解決と bind まで済ませてから応答する |
| `PATCH /rules/{protocol}/{listen_addr}/{listen_port}` | `{"remote_addr","remote_port","udp_idle_secs"?,"tls"?,"starttls"?,"starttls_required"?,"allow_from"?}` | 200 | 転送先を変える。新しい接続から即時に反映する。`tls` を付けると TLS の設定を丸ごと置き換える（`starttls` も一緒に指定する。省略すると STARTTLS なし）。`source_ip` とポート範囲は変更できない |
| `DELETE /rules/{protocol}/{listen_addr}/{listen_port}?drain_secs=N` | | 204 | 転送を停止する。既存の接続は即座に切断する。`drain_secs` を付けた場合は、その秒数だけ既存の接続の終了を待ってから切断する |
| `GET /metrics` | | 200 | Prometheus 形式。`http` のルールのリクエストは `rproxy_http_requests_total` と `rproxy_http_request_duration_seconds`（上の「v0.3 の設定」） |

IPv6 の `listen_addr` をパスに入れるときは URL エンコードする。

## エラー

失敗時は次の形で返す。

```json
{"error": "address already in use (os error 98)", "code": "bind_failed"}
```

| `code` | HTTP | 意味 |
|---|---|---|
| `unauthorized` | 401 | トークンがない、一致しない、または期限切れ |
| `forbidden` | 403 | トークンのスコープ、または `allow_listen_ports` の外 |
| `invalid` | 400 | 本文やパスが不正 |
| `tls_config` | 400 | TLS の設定の組み合わせが不正、または証明書・鍵・CA のファイルを読めない |
| `unsupported` | 400 | この環境では使えない指定（`transparent` など）、または変更できない項目 |
| `not_found` | 404 | ルールがない |
| `already_exists` | 409 | 同じキーのルールが既にある |
| `static` | 409 | 固定ルールは API から変更・削除できない |
| `reserved` | 409 | rproxy 自身の制御 API のアドレスとポートに重なる（`0.0.0.0` / `::` とポート範囲も含めて判定する） |
| `bind_failed` | 409 | 待ち受けポートを開けない |
| `resolve_failed` | 502 | 転送先の名前解決に失敗し、キャッシュもない |
| `internal` | 500 | その他 |

## 起動時の復元

`--database-url mysql://user:pass@host:port/db` を指定すると、起動時に `forward_rules` テーブルの全ルールを読み込んで開始する。DB ユーザーには `SELECT` 権限だけを与えればよい。失敗したルールは `failed` として登録し、残りのルールは開始する。名前解決に失敗して `failed` になったルールは、再解決に成功した時点で自動的に開始する。

テーブル定義は UI リポジトリの `db/` で管理する。rproxy が読む列は `protocol`、`src_addr`、`src_port`、`src_port_end`、`dist_addr`、`dist_port`、`source_ip`、`udp_idle_secs`、`options`。
`options` は JSON で `{"tls": <TLS>, "starttls": "smtp" | "imap" | "pop3" | null, "starttls_required": bool, "allow_from": [<CIDR>, ...]}`（`allow_from` は省略できる）。古いテーブルにこれらの列がなければ、既定値で読み込む。
