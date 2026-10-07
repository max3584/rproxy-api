English: [DESIGN-v0.4.md](en/DESIGN-v0.4.md)

# v0.4 の設計: 設定と API の形

> **実装済み（v0.4.0）**：この文書の項目はすべて master に入り、v0.4.0 で出す（形は #216、中身は #218〜#223）。`GET /capabilities` の `features` の v0.4 の項目はすべて true。正式な形は docs/API.md の「v0.4 の設定」で、この文書は設計の経緯として残す。実装で設計から変えたところは「15. 実装での設計との違い」。Kubernetes のコントローラ（#28）は別のリポジトリ `max3584/rproxy-gateway` で続ける。

v0.4.0 では、これから入れる機能の**設定と API の形**をまとめて決める（#215）。進め方は v0.3.0（docs/DESIGN-v0.3.md）と同じで、まず形（型・検証・`features` の false・openapi.json・docs/API.md の「v0.4 の設定」・`unsupported` のテスト）を master に入れ、その上に項目ごとの実装の PR を並べて、実装したものから `features` を true にする。

> **v0.4.0 は全部の中身が入ってから 1 回で出す**（オーナーの指示）。v0.3 のように形だけの v0.4.0 を出して中身を v0.4.x のパッチで足すことはしない。形の PR と実装の PR は master に順に入るが、リリースはすべての項目が `true` になってからにする。それまでの master では、まだの項目は `unsupported` になる。

この文書が決まったら、docs/API.md の「v0.4 の設定」に正式な形として書き写し、この文書は設計の経緯として残す。

## 1. 方針

| 項目 | 決めたこと |
|---|---|
| 置き場所 | ルールに付く設定はルールの中（API・設定ファイル・DB の `options` で同じ形）。プロセス全体の設定は設定ファイルの `global`。制御 API・起動・更新のように設定ファイルより前に要るものは今までどおり CLI の引数と `RPROXY_*` の環境変数 |
| 使えるかどうか | `GET /capabilities` の `features` に項目ごとの印（すべて false で始める）。リストの形のもの（`middlewares`・`services`・`performance`）は動かせる名前を並べる |
| まだ動かない設定 | ルール：形を検証したうえで API は `400 unsupported`（保存もしない）。起動時・再読み込みのルールは `failed` に登録して理由を出す（v0.3 と同じ）。`global`・CLI・環境変数：`event = "degraded"` を出して無視する（v0.3 と同じ）。ただし**無視すると守りが弱くなるもの**（制御 API のクライアント証明書）は起動を止める設定のエラーにする |
| まだ動かないエンドポイント | 認証・スコープを通ったあと `400 unsupported`（`unsupported` の HTTP の状態は今までどおり 400 に揃える） |
| 互換 | 0.3 の設定ファイル・API の本文・DB の行・トークンファイルはそのまま読める。足すものはすべて省略でき、省略したときの動きは 0.3 と同じ |
| 項目の境界 | 項目ごとにモジュールを分ける（下の表）。実装の PR はそのモジュールとデータプレーンを触り、共通の場所（`rule.rs`・`config/mod.rs`・`api.rs`・openapi.json）には形の PR で全部を先に入れておく |
| 単位 | 時間は今までどおりの文字列（`10s`・`500ms`・`5m`・`1h`）。速さ（帯域）は `"10Mbps"` の形の文字列（ビット毎秒、1000 倍ごと：`bps`・`kbps`・`Mbps`・`Gbps`）。量は `"256KiB"` の形（`B`・`KiB`・`MiB`・`GiB`、1024 倍ごと） |

### 項目とモジュール・`features`

| issue | 項目 | 形の置き場所（モジュール） | `features` | 実装の PR |
|---|---|---|---|---|
| #28 | Kubernetes の口（ルールの組・ラベル・状態・readiness） | `src/core/ruleset.rs`、`src/control/ruleset_api.rs` | `rulesets`、`labels`、`conditions`、`readyz` | #220 |
| #165 | L4 の送信元ごとの制限 | `src/core/limits.rs` | `limits` | #219 |
| #166 | 通信量の上限と集計 | `src/core/bandwidth.rs` | `bandwidth` | #219 |
| #167 | 制御 API の守り | `src/control/hardening.rs` | `client_cert_auth`、`token_expiry`、`api_lockout` | #218 |
| #168 | GeoIP | `src/net/geoip.rs` | `geoip`、`middlewares` の `geoip` | #221 |
| #169 | 変更前の差分 | `src/config/plan.rs` | `dry_run` | #222 |
| #170 | 受け身のヘルスチェック | `src/core/outlier.rs` | `outlier_detection`、`services` の `outlier_detection` | #221 |
| #174 | 再起動なしの更新・自動更新 | `src/control/upgrade.rs` | `handoff`、`self_update` | #223 |
| #144 | API で作ったルールの保存 | `src/config/persist.rs` | `persistence` | #222 |
| #194・#184 | performance の設定 | `src/config/performance.rs` | `performance`（動く項目の名前のリスト） | #223 |

## 2. まとめた例

```yaml
version: 1
global:
  geoip:                                   # #168
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb
    check_interval: 1m
    log_country: true
  performance:                             # #194・#184
    workers: 8
    udp_shards: auto
    cpu_affinity: auto
    busy_poll_usecs: 0
    splice: {enabled: true, after: 0, full_reads: 4, pipe_size: 0}

rules:
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 27015
    targets: [{addr: 10.0.0.10, port: 27015}, {addr: 10.0.0.11, port: 27015}]
    labels: {tenant: act, service: game}   # #28・#166
    limits:                                # #165
      max_connections: 20000
      per_source:
        max_connections: 8
        new_connections: {average: 10, period: 1s, burst: 20}
        packets: {average: 2000, period: 1s, burst: 4000}
    bandwidth:                             # #166
      download: 500Mbps
      per_source: {upload: 2Mbps, download: 10Mbps}
    geoip: {allow_countries: [JP]}         # #168
    outlier_detection:                     # #170
      consecutive_failures: 3
      ejection_time: 10s
      max_ejection_time: 5m
      max_ejected_percent: 50
```

## 3. #28 Kubernetes（Gateway API）

### 3.1 方針

- **コントローラは rproxy 本体に入れず、別のプロセスにする**。制御 API を呼んでルールを作る（rproxy は Kubernetes の API を知らない）。
- **別のリポジトリ `max3584/rproxy-gateway` にする**（このリポジトリの `controller/` にはしない）。理由：kube-rs・k8s-openapi などの大きな依存を rproxy-api の `Cargo.lock`・`cargo deny`・cross のビルドに入れない、リリースの単位（コンテナイメージ・Helm chart・CRD の版）が違う、Gateway API の conformance のテストを別の CI で回す。言語は Rust（kube-rs）を推す（このリポジトリの型と検証の考え方をそのまま使える）。rproxy とは制御 API（`docs/openapi.json`）だけでつながる。
- 本命は Gateway API。Ingress と Traefik の CRD は移行用（読むだけで、書き戻さない）。

### 3.2 rproxy 側に足す口

**ルールの組（ruleset）**：コントローラは「自分が持つルールの全体」を 1 回で渡し、rproxy が差分を当てる（宣言的。個々の POST / PATCH / DELETE を並べない。途中で落ちても次の同期で揃う）。

| メソッドとパス | 本文 | 成功時 | 説明 |
|---|---|---|---|
| `GET /rulesets` | | 200 | 組の一覧 `[{"name","generation","etag","rules":<数>,"updated_at","updated_by"}]`。`rules:read` |
| `GET /rulesets/{name}` | | 200 | `{"name","generation","etag","rules":[<ルール>...]}`。応答の `ETag` ヘッダも同じ値。`rules:read` |
| `PUT /rulesets/{name}?dry_run=true` | `{"generation": 42, "rules": [<ルール>...]}` | 200 | その組のルールを本文のとおりにする：本文にあって今ないものは作り、両方にあって違うものは PATCH と同じ道筋で変え（接続を切らずに変えられるものはそのまま）、今あって本文にないものは消す。`If-Match: <etag>` があれば今の etag と違うと `412 precondition_failed`。`generation` は呼び出し側の世代（Kubernetes の `metadata.generation` など）で、そのまま覚えて返す（減る世代は `409 stale_generation`）。応答 `{"name","generation","etag","dry_run","results":[{"rule":"tcp/0.0.0.0:443","action":"create\|update\|delete\|none","change":"none\|in_place\|recreate","state","error"}]}`。全部のルールの形を先に検証し、どれかが `invalid` なら何も変えない（`400`、`errors` に組の中の番号）。bind・名前解決の失敗はそのルールだけ `failed` にして、残りは当てる。`rules:write`、各ルールはトークンの `allow_listen_ports` の内 |
| `DELETE /rulesets/{name}?drain_secs=N` | | 204 | その組のルールをすべて消す |

- 組の名前：`[a-z0-9]([a-z0-9._/-]{0,251}[a-z0-9])?`（例 `k8s/default/web-gateway`）。
- 組のルールは `GET /rules` にも出て、`ruleset: "<名前>"` が付く。組に属するルールを個別の `PATCH` / `DELETE` で変えると `409 owned`（組の持ち主と取り合わないため。変えるなら組を PUT する）。設定ファイルのルール（`static`）と同じキーは `409 static`、組に属さない動的なルールと同じキーは `409 already_exists`（勝手に奪わない）。
- 組は rproxy のメモリにあり、DB には書かない（#144 の保存もしない）。再起動したらコントローラがもう一度 PUT する（`GET /readyz` が ready になってから）。
- etag：組のルールの正規化した JSON と世代から作る文字列（`"g42-<sha256 の先頭 16 桁>"`）。

**ラベル**：ルールの `labels`（`{キー: 値}`）。コントローラの持ち物の印（`gateway.networking.k8s.io/gateway-name` などをそのまま入れられる）と、#166 の所有者（テナント）ごとの集計に使う。

- キーは `[a-z0-9A-Z]([a-z0-9A-Z._/-]{0,61}[a-z0-9A-Z])?`、値は 0〜253 文字（制御文字なし）、1 ルール 16 個まで。
- 動きには使わない（ログ・`/metrics` に出すだけ）。`/metrics` には `rproxy_rule_labels{rule="...",label_<キーの英数字と _>="値"} 1`（info の形。数は少ないので系列が増えすぎない）。
- `PATCH` で `labels` を付けると丸ごと置き換える（`{}` で外す）。

**状態（conditions）**：ルールの表示に `conditions`（Gateway API の status にそのまま写せる形）。

```json
"conditions": [
  {"type": "Accepted",     "status": "True",  "reason": "Accepted",      "message": "", "last_transition": 1790000000},
  {"type": "Programmed",   "status": "True",  "reason": "Listening",     "message": "", "last_transition": 1790000000},
  {"type": "ResolvedRefs", "status": "False", "reason": "ResolveFailed", "message": "backend.local: no address", "last_transition": 1790000123},
  {"type": "BackendsHealthy", "status": "True", "reason": "Healthy", "message": "", "last_transition": 1790000000}
]
```

| type | True のとき | False の reason |
|---|---|---|
| `Accepted` | 形が正しく、この版で動かせる | `Invalid`・`Unsupported` |
| `Programmed` | 待ち受けている（`state: running`） | `BindFailed`・`Failed`・`Pending` |
| `ResolvedRefs` | 転送先の名前・証明書・秘密のファイルがそろっている | `ResolveFailed`・`CertificateExpired`・`CertificateUnreadable` |
| `BackendsHealthy` | 落ちていない転送先がある | `AllTargetsDown`・`ServiceDown` |

`last_transition` は Unix 秒。今の `state`・`error`・`all_targets_down`・`down_services` は残す（UI が使う）。

**readiness**：`GET /readyz`（認証なし、`/healthz` と同じ）。

- `200 {"ready": true}`：起動時の復元（設定ファイル・DB）が終わり、受け付けている。
- `503 {"ready": false, "reason": "starting" | "draining"}`：復元の途中、または #174 の引き継ぎで古いプロセスが受け付けをやめた後。
- ルールの失敗は readiness に含めない（1 つのルールの誤りで Pod ごと外さないため。ルールの状態は `conditions`）。
- `/healthz` は今までどおり生きているかだけ（liveness）。

### 3.3 コントローラ（rproxy-gateway）の形

- `GatewayClass` の `spec.controllerName: rproxy.max3584.net/gateway-controller`。
- 対応する資源（Gateway API v1.x の standard channel が主、TCP・UDP・TLS は experimental channel）：

| 資源 | rproxy のルール |
|---|---|
| `Gateway` の listener（`HTTP`・`HTTPS`・`TLS`・`TCP`・`UDP`） | 1 つの（protocol, address, port）が 1 ルール。同じポートの複数の listener（hostname 違い）は 1 つのルールにまとめる |
| `HTTPRoute` | `http.routes`。`matches`（path・headers・queryParams・method）→ `match` の式、`backendRefs` の weight → `servers` の `weight`、`filters`：`RequestHeaderModifier`・`ResponseHeaderModifier` → `headers`、`RequestRedirect` → `redirect_scheme` / `redirect_regex`、`URLRewrite` → `replace_path` / `strip_prefix`、`ExtensionRef`（`RproxyMiddleware`）→ そのミドルウェア |
| `TLSRoute` | `tls.mode: sni`（`tls.routes`）、HTTPS の listener と同じポートなら `http` のルールの passthrough の route |
| `TCPRoute`・`UDPRoute` | L4 のルール（`targets`） |
| `GRPCRoute` | まだ対応しない（転送先へ HTTP/2 で送れないため。`Accepted: False`、reason `UnsupportedValue`） |
| `ReferenceGrant` | ほかの名前空間の Service・Secret を参照するときに確かめる |
| `BackendTLSPolicy` | `https://` の転送先の `ca_file`（Secret / ConfigMap を rproxy のホストのファイルに書き出す） |

- 転送先は Service の ClusterIP ではなく **EndpointSlice の Pod の IP** を `targets` / `servers` に入れる（rproxy の負荷分散・受け身のヘルスチェックを効かせるため）。EndpointSlice が変わったら組を PUT し直す（宛先だけの違いは接続を切らずに変わる）。
- 証明書（`certificateRefs` の Secret）は、rproxy のホストのファイル（DaemonSet と共有のボリューム）に書き出して `cert_file` / `key_file` で指す（制御 API で鍵の中身を送らない）。
- Gateway API にない設定（`rate_limit`・`crowdsec`・`geoip`・`limits`・`bandwidth`・`outlier_detection` など）は、rproxy の CRD で足す：
  - `RproxyMiddleware`（`rproxy.max3584.net/v1alpha1`）：`spec` は `http.middlewares.<名前>` と同じ形。HTTPRoute の `ExtensionRef` で使う。
  - `RproxyPolicy`：`spec.targetRefs`（Gateway・listener・Service）と、ルールの `limits`・`bandwidth`・`geoip`・`outlier_detection`・`allow_from`・`crowdsec`（policy attachment、GEP-713）。
  - `RproxyRule`：ルールの形を `spec` にそのまま書く逃げ道（docs/DESIGN-v0.3.md 8. の案）。Gateway API で書けないものだけに使う。
- status：Gateway の `status.listeners[].conditions`（`Programmed`・`Accepted`）と、Route の `status.parents[].conditions`（`Accepted`・`ResolvedRefs`）を、rproxy のルールの `conditions` から書く。`observedGeneration` は組の `generation`。
- 組の名前は `k8s/<Gateway の名前空間>/<Gateway の名前>`。1 つの Gateway が 1 つの組。
- rproxy の置き方：`hostNetwork: true` の DaemonSet（L4・UDP を素直に受けられる）か、Deployment と `LoadBalancer` の Service。コントローラは各 rproxy の Pod の制御 API（mTLS #167 とトークン）に同じ組を PUT する。
- 移行用（任意、引数で有効にする）：`Ingress`（`ingressClassName: rproxy`）→ `http` のルール。Traefik の `IngressRoute`・`IngressRouteTCP`・`IngressRouteUDP`・`Middleware`（`traefik.io/v1alpha1`）→ `contrib/traefik2rproxy.py` と同じ対応（docs/MIGRATING-FROM-TRAEFIK.md）。
- 出すもの：コンテナイメージ（GHCR）、CRD、Helm chart、DaemonSet のマニフェスト。

### 3.4 互換・守り

- `labels`・`ruleset`・`conditions` のない 0.3 のルールはそのまま。
- 組の PUT は `rules:write`。コントローラ用のトークンは `allow_listen_ports` で範囲を絞る。

## 4. #165 L4 の送信元ごとの制限

ルールの `limits`（TCP・UDP、`http` のルールでは TCP の接続に効く）。

```yaml
limits:
  max_connections: 20000          # ルール全体の同時接続数（UDP はセッション数）
  per_source:
    prefix_v4: 32                 # 送信元をまとめる大きさ（既定 32 と 64）
    prefix_v6: 64
    max_connections: 8            # 1 つの送信元の同時接続数（UDP はセッション数）
    new_connections: {average: 10, period: 1s, burst: 20}   # 新しい接続（UDP は新しいセッション）の速さ
    packets: {average: 2000, period: 1s, burst: 4000}       # UDP のデータグラムの速さ（UDP だけ）
    max_sources: 65536            # 覚える送信元の数の上限（既定 65536）
```

| 項目 | 検証 |
|---|---|
| `max_connections` | 1〜10,000,000 |
| `per_source.prefix_v4` / `prefix_v6` | 1〜32 / 1〜128 |
| `per_source.max_connections` | 1〜1,000,000 |
| `new_connections` / `packets` | `average` 1 以上、`period` は 1ms〜1h（既定 1s）、`burst` は `average` 以上（既定 `average`）。L7 の `rate_limit` と同じ形 |
| `packets` | `protocol: udp` だけ（tcp は `invalid`） |
| `max_sources` | 1〜10,000,000 |
| 全体 | 少なくとも 1 つの上限があること（`{}` は「上限なし」で、PATCH で外すのに使う） |

- 判定は受け付けた直後、`allow_from`・GeoIP・CrowdSec の後、TLS・PROXY ヘッダより前。
- 超えたとき：TCP は受け付けた接続をすぐ閉じる（何も送らない）。UDP はデータグラムを捨てる（新しいセッションは作らない）。`stats.limited` に数え、`conn.limited` をログに出す：`{"event":"conn.limited","rule","client","reason":"max_connections\|source_connections\|new_connections\|packets","transport":"tcp\|udp"}`（`Throttle` で送信元ごとに間引く。CrowdSec のパーサーでも使える項目名）。`/metrics` は `rproxy_rule_limited_total{rule,reason}`。
- 覚える送信元が `max_sources` を超えたら、一番古いものから忘れる（メモリを使い切らない）。
- `PATCH` で `limits` を付けると丸ごと置き換える（次の接続・データグラムから。数えている状態は引き継ぐ）。`{}` で外す。
- 省略したときは今までどおり上限なし。

## 5. #166 通信量の上限と集計

### 5.1 帯域の上限（ルールの `bandwidth`）

```yaml
bandwidth:
  upload: 100Mbps        # クライアント → 転送先、ルール全体
  download: 500Mbps      # 転送先 → クライアント、ルール全体
  burst: 1MiB            # まとめて流してよい量（既定：100ms 分）
  per_source:
    upload: 2Mbps
    download: 10Mbps
    prefix_v4: 32
    prefix_v6: 64
    max_sources: 65536
```

- TCP（`http` のルールを含む）は待たせて絞る（読むのを遅らせる。捨てない）。UDP は超えた分のデータグラムを捨てる（`stats.dropped` と `rproxy_rule_bandwidth_dropped_total`）。
- 速さは `"<数><bps|kbps|Mbps|Gbps>"`（8kbps〜100Gbps）、`burst` は `"<数><B|KiB|MiB|GiB>"`（1KiB〜1GiB）。少なくとも 1 つの速さが要る（`{}` は PATCH で外すため）。
- L7 のルートごとの帯域はまだ持たない（必要ならミドルウェアで足す）。
- `PATCH` で丸ごと置き換える（次に読むところから効く）。

### 5.2 集計のための数

今の `stats` は再起動で消えるので、UI が定期的に取って DB に貯める。rproxy 側は差分を取りやすい形を保つ：

- ルールの `stats.rx_bytes`・`tx_bytes`・`total_connections` は単調増加のまま。
- 新しく `stats.counters_since`（Unix 秒）：この数え始めの時刻。ルールを作り直すと変わり、#174 の引き継ぎでは変わらない（数が減ったか・数え直したかを UI が見分ける）。
- `stats.limited`（#165）を足す。
- `/metrics` に `rproxy_process_start_time_seconds`（引き継ぎでは古いプロセスの値を引き継ぐ）を足す。
- 所有者（テナント）は rproxy では持たず、`labels` で印を付けて UI が集計する（ルール・ノード・所有者ごとの時間・日・月の通信量は UI #98 と合わせて UI 側）。

## 6. #167 制御 API の守り

制御 API の設定なので、今までどおり CLI の引数と環境変数で書く。

| 引数 / 環境変数 | 既定 | 意味 |
|---|---|---|
| `--tls-client-ca` / `RPROXY_TLS_CLIENT_CA` | なし | クライアント証明書を確かめる CA（PEM）。SIGHUP で読み直す。`--tls-cert` が要る |
| `--tls-client-auth` / `RPROXY_TLS_CLIENT_AUTH` | `none` | `none`・`optional`（あれば確かめる）・`required`（ない・確かめられない接続は TLS のハンドシェイクで断る）。`optional` / `required` は `--tls-client-ca` が要る |
| `--token-warn-days` / `RPROXY_TOKEN_WARN_DAYS` | 14 | トークンの `expires` がこの日数より近いと知らせる |
| `--api-lockout-failures` / `RPROXY_API_LOCKOUT_FAILURES` | 20 | `window` の間に認証に失敗した回数がこれに達した送信元を止める。0 で止めない |
| `--api-lockout-window` / `RPROXY_API_LOCKOUT_WINDOW` | `1m` | 数える時間 |
| `--api-lockout-duration` / `RPROXY_API_LOCKOUT_DURATION` | `5m` | 止める時間 |

**クライアント証明書（mTLS）**：トークンファイル（YAML）のエントリに `client_cert` を足す。

```yaml
tokens:
  - name: ui
    client_cert: ui.rproxy.internal      # 証明書の名前（DNS か URI の SAN、SAN がなければ CN）と完全一致
    scopes: [rules:read, rules:write]
  - name: gateway-controller
    sha256: 9f86d0...
    client_cert: spiffe://cluster.local/ns/rproxy/sa/controller
    scopes: [rules:read, rules:write]
```

- `sha256` と `client_cert` のどちらか片方は要る。**両方あれば両方が要る**（トークンと証明書の両方が一致したときだけ通す）。`client_cert` だけなら証明書だけで通す（`Authorization` は要らない）。
- `client_cert` のあるトークンファイルで `--tls-client-auth` が `none` なら起動を止める設定のエラー（使えないエントリを黙って無視しない）。
- この版で `client_cert_auth` が動かないとき、`--tls-client-auth optional / required` は起動を止める設定のエラーにする（無視すると制御 API が思ったより弱くなるため）。
- Unix ソケットは対象外（ソケットのファイルの権限で守る）。
- 監査ログ（`event = "audit"`）に `auth: "token" | "cert" | "token+cert"` を足す。

**トークンの期限**：

- 起動・SIGHUP・1 日 1 回、期限が `--token-warn-days` より近いトークンを `token.expiring`（`token`・`expires`・`days_left`）、切れたものを `token.expired` で知らせる（warn）。状態が変わったときに 1 回。
- `/metrics` に `rproxy_token_expiry_timestamp_seconds{token}`。
- 入れ替えの手順（新旧を同時に有効にして SIGHUP、切り替えたら古いものを消す）は docs/API.md に書く。

**失敗が続く送信元の一時停止**：

- TCP の制御 API で、`401` の送信元の IP（IPv6 は /64 でまとめる）ごとに数え、`window` の間に `failures` に達したら `duration` の間、その送信元のリクエストをトークンを見ずに `429 locked_out`（`Retry-After`）で断る。
- 止めたときに `api.lockout`（`client`・`failures`・`until`）、解いたときに `api.unlock`。止めている間の拒否は `event = "audit"`、`outcome = "locked_out"`（`Throttle` で間引く）。`/metrics` に `rproxy_api_lockouts_total`・`rproxy_api_locked_sources`。
- 覚える送信元は 4096 まで（古いものから忘れる）。Unix ソケットは対象外。

## 7. #168 GeoIP

```yaml
global:
  geoip:
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb   # Country か City の mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb           # 任意
    check_interval: 1m     # ファイルが変わったか確かめる間隔（既定 1m、0s で確かめない。SIGHUP でも読み直す）
    log_country: true      # conn.open・conn.denied・http.access に country（と asn）を足す（既定 false）
```

ルールの `geoip`（L4）と、ミドルウェアの `geoip`（L7）は同じ形：

```yaml
geoip:
  allow_countries: [JP, US]
  deny_countries: []
  allow_asns: []
  deny_asns: [64496]
  unknown: allow           # データベースにない・私用アドレス（allow / deny、既定 allow）
```

- 判定：まず `deny_*` に当たれば拒否。`allow_*` のどれかが書いてあれば、どれかの `allow_*` に当たるものだけを通す。どちらにも当たらない・分からないものは `unknown`。
- 国は ISO 3166-1 alpha-2 の大文字 2 文字（`EU` などの地域コードもデータベースにあれば使える）。ASN は 1〜4294967295。同じ値を allow と deny の両方に書くと `invalid`。少なくとも 1 つのリストが要る。
- `*_countries` は `global.geoip.country_db`、`*_asns` は `global.geoip.asn_db` が要る（設定ファイルは検証で、API は `400 invalid`）。
- L4：`allow_from` の後、受け付けた直後に判定する。UDP はデータグラムを捨てる。拒否は `stats.denied` に数え、`conn.denied` に `reason: "geoip"` と `country`（と `asn`）。
- L7：`global.trusted_proxies` で決めたクライアントの IP で判定し、拒否は `403`（`ip_allow` と同じ）。
- データベースは同梱しない（GeoLite2 は利用者が MaxMind のアカウントで取る）。読めない・壊れているときは、起動時は設定のエラー（ファイルがない）か `degraded`（権限）、動いている間は前のものを使い続ける（`event = "degraded"`、`part: "geoip"`）。

## 8. #169 変更前の差分（plan / dry-run）

**制御 API**：

- `POST /rules?dry_run=true`・`PATCH /rules/...?dry_run=true`・`DELETE /rules/...?dry_run=true`・`PUT /rulesets/{name}?dry_run=true`：検証と差分だけを返し、何も変えない（bind・名前解決もしない。証明書・秘密のファイルは読んで確かめる）。成功は `200`：

```json
{
  "dry_run": true,
  "action": "update",
  "change": "in_place",
  "rule": "tcp/0.0.0.0:443",
  "before": {<ルールの表示>},
  "after": {<ルールの形>},
  "diff": [{"path": "targets", "before": [...], "after": [...]}],
  "warnings": []
}
```

  - `action`：`create`・`update`・`delete`・`none`（同じ）。
  - `change`：`none`・`in_place`（接続を切らずに変わる）・`recreate`（待ち受けを作り直す。今の接続は切れる）。
  - `diff`：変わった項目の JSON のパス（`.` でつなぐ。配列は丸ごと）と前後の値。秘密そのものは形に含まれないので出ない。
  - 検証で断られるものは、実際の操作と同じ `400`（`invalid` など）。
- `POST /config/reload?dry_run=true`：設定ファイルを読んで、反映したら何が変わるかを返す（`{"dry_run": true, "added", "removed", "changed", "unchanged", "failed", "restart_needed", "changes": [{"rule", "action", "change", "diff"}], "warnings"}`）。スコープと Unix ソケットの決まりは `POST /config/reload` と同じ。
- `POST /config/plan`：本文の設定（設定ファイルと同じ形の JSON。`version`・`global`・`rules`）を、今動いているものと比べる（ファイルは読まない。`--check-config --diff` が使う）。応答は上と同じ形。`admin`、既定では Unix ソケットからだけ（`RPROXY_API_RELOAD_UNIX_ONLY`）。

**設定ファイル**：`rproxy-api --check-config [PATH] --diff`

| 引数 / 環境変数 | 既定 | 意味 |
|---|---|---|
| `--diff` | | 検証に通ったら、動いている rproxy に `POST /config/plan` で問い合わせて差分を出す |
| `--diff-api` / `RPROXY_DIFF_API` | `RPROXY_API_SOCKET` があればそれ、なければ `http://<RPROXY_API_ADDR の先頭>:<RPROXY_API_PORT>`（TLS なら https） | 問い合わせ先（`unix:/run/rproxy/api.sock` か URL） |
| `--diff-token-file` / `RPROXY_DIFF_TOKEN_FILE` | なし | 問い合わせに使うトークン（平文の 1 行）のファイル |

- 出力は `--check-config-format`（`text` は 1 行に 1 つの変更、`json` は `Report` に `plan` を足したもの）。
- 終了コード：検証の誤りや問い合わせの失敗は 1。差分があってもなくても成功なら 0。
- 動いている rproxy につながらないときは、検証の結果と「差分は出せなかった」を出して 1。

## 9. #170 受け身のヘルスチェック（outlier detection）

**L4**（ルールの `outlier_detection`。宛先が複数か `health_check` のあるルール）：

```yaml
outlier_detection:
  consecutive_failures: 3     # 続けて接続に失敗した回数（既定 1）
  short_lived: 0s             # この時間より前に転送先から閉じた接続も失敗に数える（既定 0s：数えない）
  ejection_time: 10s          # 最初に外す時間（既定 10s）
  max_ejection_time: 5m       # 外すたびに倍にし、ここで止める（既定 = ejection_time：倍にしない）
  max_ejected_percent: 100    # 同時に外せる宛先の割合（既定 100）
```

- 書かなければ今の動き（接続に 1 回失敗したら `FAIL_COOLDOWN` の 10 秒外す）と同じになる既定値にする。今の `FAIL_COOLDOWN` はこの既定値になる。
- `consecutive_failures` 1〜1000、時間は 1s〜1h（`short_lived` は 0s〜1m）、`max_ejection_time` ≧ `ejection_time`、`max_ejected_percent` 0〜100。
- 外した・戻したは今の `target.down` / `target.up` に `reason: "outlier"`（ヘルスチェックは `reason: "health_check"`）を足す。`stats.targets[]` に `ejected_until`（Unix 秒、外していなければ null）と `ejections`（回数）を足す。

**L7**（`http.services.<名前>.outlier_detection`）：

```yaml
outlier_detection:
  consecutive_5xx: 5               # 続けて 5xx を返した回数（0 で見ない。既定 5）
  consecutive_gateway_failures: 3  # 502・503・504・接続の失敗・タイムアウトが続いた回数（既定 3）
  failure_percent: 50              # window の中の失敗の割合（1〜100。省略で見ない）
  min_requests: 20                 # 割合を見る最小のリクエスト数（既定 20）
  window: 30s
  ejection_time: 30s
  max_ejection_time: 5m
  max_ejected_percent: 50          # 既定 50：全部は外さない
```

- `circuit_breaker`（サービス全体を止める）とは別で、サーバごとに外す。外したサーバは `stats.http` のサーバの状態に `ejected`。
- ログは `target.down` / `target.up`（`reason: "outlier"`、`service`、`server`）。

## 10. #174 再起動なしの更新とコンテナでの自動更新

### 10.1 引き継ぎ（handoff）

- 同じマイナー（X.Y）の中では、動いたまま新しいバイナリに引き継げることを保証する。マイナー・メジャーが違えば引き継がずに断り（`handoff.refused`、理由 `version`）、再起動に任せる。
- 起こし方：古いプロセスに `SIGUSR2`、または `POST /admin/upgrade`（`admin`、既定では Unix ソケットからだけ）。古いプロセスはディスクの上の今のバイナリ（`/proc/self/exe` の指していたパス）を子として起動し、待ち受けのソケット（ルールの TCP・UDP、制御 API の TCP・Unix ソケット、HTTP/3 の UDP）と状態を引き継ぎ用の Unix ソケット（`SCM_RIGHTS`）で渡す。
- 新しいプロセスは受け取ったソケットでルールを組み立て、準備ができたら（`/readyz` が ready）古いプロセスに知らせる。古いプロセスは受け付けをやめ（`/readyz` は `draining`）、今の接続が終わるのを待ってから（`stop → drain → kill`）終わる。systemd には `sd_notify` の `MAINPID=` で新しいプロセスを主に切り替える（ユニットは `Type=notify`・`NotifyAccess=all`）。
- 渡す状態：ルールの統計の数（`counters_since` と `rx_bytes` などの起点。数が減らない）、`rproxy_process_start_time_seconds`、組（#28）の中身と世代、ACME の状態はファイルから読み直す。
- UDP は一瞬途切れてよい（オーナーの了承済み）：待ち受けのソケットは渡すが、今のセッションは古いプロセスと一緒に終わる。TCP・HTTP は古いプロセスが最後まで扱うので切れない。
- 新しいプロセスが `handoff_timeout` の間に準備できなければ、古いプロセスは子を止めて今までどおり動き続ける（`handoff.failed`）。

| 引数 / 環境変数 | 既定 | 意味 |
|---|---|---|
| `--handoff-socket` / `RPROXY_HANDOFF_SOCKET` | `/run/rproxy/handoff.sock` | 引き継ぎ用の Unix ソケット（0600、rproxy のユーザーだけ） |
| `--handoff-timeout` / `RPROXY_HANDOFF_TIMEOUT` | `30s` | 新しいプロセスの準備を待つ時間 |
| `--handoff-drain` / `RPROXY_HANDOFF_DRAIN` | `5m` | 古いプロセスが今の接続の終わりを待つ最長の時間（過ぎたら切る） |

- ログ：`handoff.start`・`handoff.ready`・`handoff.done`・`handoff.failed`・`handoff.refused`。`/metrics`：`rproxy_build_info{version,sha256}`、`rproxy_handoffs_total{outcome}`。
- systemd：`systemctl reload` は今までどおり SIGHUP（設定・証明書の読み直し）のままにし、引き継ぎは SIGUSR2 に分けた（14. で決めた）。.deb の `postinst` は前の版と major.minor が同じなら `systemctl kill -s USR2`、違えば restart。
- 例外のパッチ（引き継げない修正）は、リリースの `manifest.json` の `"handoff": false` とリリースノートで知らせる。

### 10.2 コンテナでの自動更新

- イメージの入口は `rproxy-api launch`（起動役）。キャッシュのボリュームと GitHub のリリース（ミラーに変えられる）から、イメージと同じ X.Y の最新のパッチを選び、**署名を確かめてから** exec する。取れないときはキャッシュの最新、なければイメージの版。
- 動いている間：`RPROXY_UPDATE_INTERVAL` ごと、または `POST /admin/update` で新しいパッチを取り、確かめたら 10.1 の引き継ぎで入れ替える。
- 新しい版が起動しない・`RPROXY_UPDATE_HEALTHY` の間に落ちたら、前の版に戻す（前の版をキャッシュに 1 つ残す）。その版は「悪い版」として覚え、次からは選ばない。

| 環境変数（引数は同じ名前の `--update-*`） | 既定 | 意味 |
|---|---|---|
| `RPROXY_UPDATE` | `off`（イメージでは `auto`） | `off`・`check`（取って確かめ、ログと API で知らせるだけ）・`auto`（入れ替える）。apt で入れた VM では off のまま（apt と二重にしない） |
| `RPROXY_UPDATE_PIN` | なし | 版を固定する（`0.4.3`）。X.Y の外は指定できない |
| `RPROXY_UPDATE_SOURCE` | `https://github.com/max3584/rproxy-api/releases` | リリースの取り先（ミラー。`https://` だけ） |
| `RPROXY_UPDATE_CACHE` | `/var/cache/rproxy/update` | キャッシュ（書き込めるボリューム。ルートのファイルシステムが読み取り専用でもよい） |
| `RPROXY_UPDATE_INTERVAL` | `6h` | 確かめる間隔（`0s` で起動時と API だけ） |
| `RPROXY_UPDATE_PUBKEY` | バイナリに入れたリリースの鍵 | 署名を確かめる minisign の公開鍵（ファイル）。ミラーで自分で署名し直すとき |
| `RPROXY_UPDATE_HEALTHY` | `60s` | この間落ちなければ新しい版を「よい版」とする |

- 署名は **minisign**（Ed25519。確かめる側は小さな純 Rust の実装で済み、cosign のような外のサービスが要らない）。リリースのワークフローがバイナリの `.tar.gz` ごとに（実装では素のバイナリごと。15.）`.minisig` と、`SHA256SUMS`・`manifest.json`（版・`handoff` の可否・各ファイルのハッシュ）とその署名を添付する。確かめられないものは実行しない。
- API：`GET /admin/update`（`admin`）`{"mode","current":{"version","sha256"},"available":{"version","sha256"}|null,"last_check","error","bad_versions":[...]}`、`POST /admin/update`（`admin`、既定では Unix ソケットからだけ。今すぐ確かめ、`auto` なら入れ替える）。今のバイナリの版とハッシュは `GET /capabilities` の `build`（`{"version","sha256"}`）と `rproxy_build_info` にも出す。
- k8s ではレプリカの入れ替えで更新するので `RPROXY_UPDATE=off` にする（Helm chart の既定）。

## 11. #144 API で作ったルールを DB に保存する

- rproxy は**自分のテーブル `rproxy_rules` にだけ書く**。UI のテーブル（`forward_rules` / `forward_rules_log`）には触らない。テーブルの定義と GRANT は UI リポジトリの `db/` の migration に置く（下は設計のときの案。実装した定義は docs/API.md の「API で作ったルールの保存」）：

```sql
CREATE TABLE rproxy_rules (
  node        VARCHAR(255) NOT NULL,   -- どの rproxy のルールか（RPROXY_NODE_NAME、既定はホスト名）
  protocol    VARCHAR(3)   NOT NULL,
  listen_addr VARCHAR(45)  NOT NULL,
  listen_port INT UNSIGNED NOT NULL,
  spec        JSON         NOT NULL,   -- POST /rules の本文と同じ形（RuleRequest）
  spec_version INT UNSIGNED NOT NULL DEFAULT 1,
  created_by  VARCHAR(255) NOT NULL,   -- トークンの名前
  created_at  DATETIME(3)  NOT NULL,
  updated_by  VARCHAR(255) NOT NULL,
  updated_at  DATETIME(3)  NOT NULL,
  PRIMARY KEY (node, protocol, listen_addr, listen_port)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON rproxy.rproxy_rules TO 'rproxy'@'%';
```

- ルールの形を列に分けず `spec` に JSON で持つ（形が増えても列を足さずに済む。`spec_version` で読み方を決める）。
- 保存するのは、トークンに `persist: true` が付いたトークンで API から作った・変えた・消したルール。**既定は保存しない**（0.3 と同じ。UI 用のトークンが二重に保存するのを避けるため、保存したいトークンにだけ付ける）。1 行 1 トークンの書き方のトークンは保存しない。組（#28）のルールは保存しない。

```yaml
tokens:
  - name: ci-deploy
    sha256: 2c26b4...
    scopes: [rules:write]
    persist: true
```

- 作成・変更・削除のたびに書く（応答の前に。書けなくてもルールは動かしたまま、応答の `persisted: false`、ログに `event = "degraded"`、`part: "db"`）。`RPROXY_DATABASE_URL` がなければ保存しない（`persisted: false`）。
- 起動時は UI のテーブルと rproxy のテーブルの両方から復元する（自分の `node` の行だけ）。同じキーが両方にあれば UI 側を使い、`restore.conflict` を warn で出す。
- 表示：保存したルールは `origin: "api"`、`created_by`・`created_at`・`persisted`。UI の DB や保存しない API のルールは今までどおり `origin: "dynamic"`。UI は知らない `origin` の値を `dynamic` と同じに扱う（UI 側の issue）。
- 引数 / 環境変数：`--node-name` / `RPROXY_NODE_NAME`（既定はホスト名）。

## 12. performance の設定（#194・#184）

今は実験用の内部の環境変数（`RPROXY_UDP_SHARDS`・`RPROXY_SPLICE*`）だけのつまみを、設定ファイルの `global.performance` にする。**設定ファイルにあればそれを使い、なければ今の環境変数、どちらもなければ既定値**（環境変数は残す）。どれも再起動まで効かない（`restart_needed`）。

```yaml
global:
  performance:
    workers: 8              # tokio のワーカースレッドの数（既定：CPU の数）。環境変数 RPROXY_WORKERS
    udp_shards: 1           # UDP のポートごとの SO_REUSEPORT のソケットの数。1〜64 か auto（= workers）。既定 1。RPROXY_UDP_SHARDS
    cpu_affinity: none      # none・auto（ワーカーを CPU に 1 つずつ固定）・"0-3,6"（使う CPU の一覧）。RPROXY_CPU_AFFINITY
    busy_poll_usecs: 0      # データプレーンのソケットの SO_BUSY_POLL（マイクロ秒）。0 で使わない（既定）。0〜1000。RPROXY_BUSY_POLL_USECS
    splice:                 # L4 の平文の TCP の splice(2)（#184）
      enabled: true         # RPROXY_SPLICE
      after: 0              # この量を流してから splice にする（バイト数か "64KiB"）。RPROXY_SPLICE_AFTER
      full_reads: 4         # 32 KiB の読み込みがこの回数続けて満杯なら splice にする（0〜64）。RPROXY_SPLICE_FULL_READS
      pipe_size: 0          # パイプの大きさ（0 はカーネルの既定、4KiB〜16MiB）。RPROXY_SPLICE_PIPE_SIZE
```

- `features.performance` は、設定ファイルから効く項目の名前のリスト（形の PR では空）。リストにない項目を書くと `degraded` を出して無視する（環境変数のつまみは今までどおり効く）。
- `cpu_affinity` は `workers` 以上の CPU を書くこと、存在しない CPU は起動時に `degraded`（その CPU だけ使わない）。
- 適応的な動き（#194 のコメント：キューの深さで busy poll をやめる・ワーカーを増やす）はしきい値を負荷テストで決めてから。決めたしきい値に設定が要れば次のマイナーで足す。eBPF の sockmap・kTLS・io_uring・XDP はここには入れない（#184 のコメント）。

## 13. 共通

### 13.1 エラーのコード（足すもの）

| `code` | HTTP | 意味 |
|---|---|---|
| `owned` | 409 | ルールが組（`ruleset`）に属するので個別には変えられない |
| `precondition_failed` | 412 | `If-Match` の etag が今の組と違う |
| `stale_generation` | 409 | 組の `generation` が今より古い |
| `locked_out` | 429 | 認証の失敗が続いたので、この送信元を一時的に止めている |

### 13.2 `GET /capabilities` の `features`（v0.4 で足すもの）

```json
"features": {
  "...v0.3 の項目...": "...",
  "rulesets": true, "labels": true, "conditions": true, "readyz": true,
  "limits": true, "bandwidth": true, "geoip": true, "outlier_detection": true,
  "dry_run": true, "persistence": true,
  "client_cert_auth": true, "token_expiry": true, "api_lockout": true,
  "handoff": true, "self_update": true,
  "performance": ["workers", "udp_shards", "cpu_affinity", "busy_poll_usecs", "splice"]
}
```

ミドルウェアの `geoip` は `middlewares`、サービスの `outlier_detection` は `services` に名前が入る。上は v0.4.0 の値（形の PR の時点ではすべて false・`[]` で、実装の PR ごとに true にした）。

### 13.3 DB の `options`

UI の `forward_rules.options`（JSON）でも、ルールの `limits`・`bandwidth`・`geoip`・`outlier_detection`・`labels` を同じ形で読む（省略できる）。UI のフォームは rproxy の形が決まってから（UI 側の issue）。

### 13.4 `PATCH` で変えられるもの

`limits`・`bandwidth`・`geoip`・`outlier_detection`・`labels` は `PATCH` で付けると丸ごと置き換える（`{}` で外す、省けば今のまま）。どれも接続を切らずに変える。

## 14. 決めたこと（2026-10-07、オーナーの了承）

- コントローラは別のリポジトリ `max3584/rproxy-gateway`、Rust（kube-rs）。手元では rproxy-api・UI と同じフォルダに並べて置き、3 つを同じ時期に管理する（`../rproxy-gateway`）。
- 組に属するルールを個別に変えたら `409 owned` で断る（`?force` は付けない。コントローラが元に戻すため）。
- #144 の `persist` の既定は false（保存したいトークンにだけ付ける。UI は自分の DB に保存するので二重にしない）。
- #144 の `node` の列は UI の `forward_rules` の `target`（ノード・グループ、UI #98）と合わせる。
- API で作ったルールの `origin` は `"api"`。UI もそれに合わせる。
- #174：`systemctl reload` は今までどおり SIGHUP（設定・証明書の読み直し）。引き継ぎは SIGUSR2（パッケージの更新のとき）。
- #174 の署名は minisign（apt の GPG とは別の鍵）。
- #167 の一時停止は既定で有効（20 回 / 1 分で 5 分。Unix ソケットは対象外）。
- #166 の UDP の帯域の上限は、超えた分を捨てる。
- 組の名前に `/` を使ってよい（k8s の `namespace/name`）。

## 15. 実装での設計との違い

実装の PR で設計から変えたところ・設計に書いていなかったことを決めたところ。docs/API.md はこれに合わせてある。

- **#167 制御 API の守り（#218）**
  - 401 の `reason` に `client_cert` を足した（トークンは合ったが、結びついた証明書がない）。
  - `api.lockout` に `duration_secs` も出す。
  - クライアントの CA は SIGHUP のほか、証明書のファイルの確認（`RPROXY_CERT_CHECK_SECS`）でも読み直す（制御 API の証明書と同じ扱い）。
  - 認証に成功しても失敗の数は戻さない（窓が過ぎれば数え直す）。
- **#165・#166 制限と帯域（#219）**
  - 指標のラベルは設計の `{rule,reason}` ではなく、ほかの指標に合わせて `{protocol,listen,reason}`（`rproxy_rule_limited_total`・`rproxy_rule_bandwidth_dropped_total{protocol,listen}`）。
  - HTTP/3（QUIC）は `limits`・`bandwidth` の対象外（`limits` は TCP の接続だけ、帯域も TCP として扱う）。
  - 帯域の上限のあるルールでは splice しない（`PATCH` で上限を付けたら splice 中の接続もユーザー空間のコピーに戻る）。
- **#28 ルールの組・状態・readiness（#220）**
  - `BackendsHealthy` は動いていないルールで `status: "Unknown"`・reason `NotProgrammed`（宛先の状態が分からないので、False にすると「全滅」と誤読されるため）。
  - `ResolvedRefs` の reason に `SecretUnreadable` を足した（ミドルウェアの秘密のファイル。`CertificateUnreadable` と分けた）。
  - `change` は `update` のときだけ `in_place` / `recreate`、`create`・`delete`・`none` は `none`。
  - `PUT /rulesets/{name}?dry_run=true` の応答は `RulePlan` ではなく組の応答（`dry_run: true`、なるはずの `etag`、`update` に `diff`）。
  - `DELETE /rulesets/{name}` も `If-Match` を受ける。`GET /rulesets/{name}` に `updated_at`・`updated_by` も出す。
  - `PUT /rulesets/{name}` の本文の上限は 32 MiB（API の既定の 2 MiB では 10,000 ルールに足りないため）。
- **#168 GeoIP・#170 受け身のヘルスチェック（#221）**
  - 接続の失敗の `target.down` は `reason: connect` から `reason: outlier` + `cause: connect`（`refused`・`short_lived` も）に変えた。ヘルスチェックの `target.down` / `target.up` は `reason: health_check`、外した時間が過ぎたときの `target.up` は `reason: outlier`。
  - L7 の `cause` は越えたしきい値の名前（`consecutive_5xx`・`consecutive_gateway_failures`・`failure_percent`）。gateway の失敗は 5xx の連続にも数える（Envoy と同じ）。
  - 外している宛先がまた失敗したとき（すべて外れていて試されたもの）は、外す時間を数え直すだけで回数は増やさない。L7 で全部外れたときは、ヘルスチェックで up のサーバを使う。
  - 倍にした時間は、戻ってから `max_ejection_time` のあいだ外されなければ最初に戻す。
  - GeoIP の判定は `allow_from` → `geoip` → `crowdsec` の順（`limits` はその後）。
- **#169 変更前の差分・#144 保存（#222）**
  - `change` の値の割り当て（上の #28 と同じ）を docs/API.md に書いた。
  - 保存の対象：作成はトークンの `persist` で決め、変更・削除はルールの `origin` で決める（`api` のルールを別のトークンが変えても行が食い違わないように）。
  - `--check-config --diff` の問い合わせ先が https なら `RPROXY_TLS_CERT` を信頼する（自己署名の制御 API のため）。
- **#174 引き継ぎ・自動更新（#223）**
  - 署名は `.tar.gz` ごとではなく、リリースの資産（素のバイナリ `rproxy-api-v<X.Y.Z>-<target>`）ごと（リリースに `.tar.gz` がないため）。
  - パッチの探し方：リリースのたびにすべての版を並べた索引 `releases.json`（minisign で署名）を添付し、自動更新は `<source>/latest/download/releases.json` を読んで同じ X.Y の最新を選ぶ（GitHub の API に頼らない。ミラーも同じ道筋に置くだけ）。
  - `RPROXY_UPDATE_CA_FILE`（隠しの環境変数）：私設の CA のミラーとテストのため。
  - 引き継ぎで渡す状態に、API のルール（`GET /rules` の形。#144 の `created_by`・`created_at`・`persisted` ごと）、`stats.http`、`counters_since`（古いプロセスの値のまま）・`limited`・帯域で捨てた数も足した。新しいプロセスで最初からになるもの（`limits`・`bandwidth` のバケツと送信元ごとの数、L7 の `rate_limit` などの状態、外した宛先）は docs/UPGRADE.md。
  - 自動更新のバイナリは届いた分からキャッシュの一時ディレクトリに書き、ファイルから確かめる（メモリに持たない。上限 1 GiB）。
  - 引き継ぎの間（と後の古いプロセス）は、変更の API に `503 upgrading`。
