English: [DESIGN-v0.4.x.md](en/DESIGN-v0.4.x.md)

# v0.4.x の設計: SIGTERM での終わり方、証明書の API、組の保存

> **決めた設計（2026-10-08、オーナーの了承）**。v0.4.0 の受け入れテスト（rproxy-gateway）で分かった穴と、#240・#241 のうち rproxy-api の分。rproxy-gateway・UI の分は、それぞれのリポジトリの設計に書く。実装で変えたところは最後の「6. 実装での設計との違い」に足していく。

## 1. 方針

| 項目 | 決めたこと |
|---|---|
| 版 | **v0.5.0 は作らない**。すべて v0.4 のパッチで出す（v0.4.1、v0.4.2、…。docs/RELEASING.md の「v0.4.0 の後」）。足すだけの形（設定・API・スコープ・`features`・DB の新しい表）はパッチでよく、次のマイナーは破壊的な変更のためにとっておく |
| 進め方 | 項目ごとに 1 つの PR で、形と中身を一緒に入れる。`GET /capabilities` の `features` に新しい印を足して、入れたときから true にする（v0.4.0 のように形だけを false で先に入れない） |
| 互換 | 足すものはすべて省略でき、省略したときの動きは v0.4.0 と同じ。**今の環境（VM・.deb・コンテナ）の動きを変えない**（E の既定も「すぐ止める」のまま） |
| 引き継ぎ | 同じマイナーの中の引き継ぎ（`handoff`）は保証したまま。渡す状態は足すだけ（この設計の項目は引き継ぎの形を変えない） |
| 戻すとき | 新しいパッチで足した設定（トークンファイルの `allow_certs`・`certs:*` のスコープ、`RPROXY_SHUTDOWN_*`、`RPROXY_CERT_STORE`）は、それを知らない古いパッチでは誤りになることがある（トークンファイルは知らない項目を誤りにする）。古いパッチに戻すときは先に外す |

| 項目 | 版 | `features`（`GET /capabilities`） | rproxy-gateway | UI |
|---|---|---|---|---|
| E. SIGTERM での終わり方 | v0.4.1 | `graceful_shutdown` | managed・fleet の Pod に `5s`・`25s` を渡し、readiness を `/readyz` に | — |
| D1. #240 証明書の API | v0.4.2 | `cert_store` | 使わない | 画面は作らない（後で） |
| D2. #241 組の保存 | v0.4.2 | `ruleset_persistence` | 使わない | migration 012、読むだけの表示 |
| G1. 421 Misdirected Request（7.1） | v0.4.3 | `http_options` の `misdirected` | 同じポートの HTTPS のリスナーの名前を `tls.misdirected` に（`GatewayHTTPSListenerDetectMisdirectedRequests`、v0.4.5） | — |
| G2. 転送先ごとの `cors`・リダイレクト・`mirror`（7.2） | v0.4.3 | `server_middleware_kinds` | backendRef の `CORS`・`RequestRedirect`・`RequestMirror` のフィルタ（v0.4.5） | — |
| G3. 外部の認可（`forward_auth` の拡張、7.3） | v0.4.3 | `forward_auth` | HTTPRoute の `ExternalAuth` フィルタ（HTTP・gRPC、v0.4.5） | — |

## 2. E. SIGTERM での終わり方（v0.4.1）

### 2.1 今

`src/main.rs` の終わりの処理（`wait_for_shutdown` の後）：SIGTERM なら `/readyz` を `draining` にし、制御 API を 5 秒で閉じ、`registry.shutdown()` ですべてのルールを**すぐに**止める（接続も切る）。今の接続の終わりを待つのは引き継ぎ（`handed`）のときだけ（`drain_all`、`RPROXY_HANDOFF_DRAIN`）。そのため Kubernetes では、Pod を Service から外す（EndpointSlice → kube-proxy・MetalLB・LB）より先に待ち受けが消え、rollout restart・node drain で失敗が出る。

### 2.2 形

| 引数 / 環境変数 | 既定 | 意味 |
|---|---|---|
| `--shutdown-delay` / `RPROXY_SHUTDOWN_DELAY` | `0s` | SIGTERM の後、`/readyz` を `draining` にしたまま、これだけ今までどおり受け付ける（ロードバランサ・Service から外れるのを待つ） |
| `--shutdown-drain` / `RPROXY_SHUTDOWN_DRAIN` | `0s` | その後、待ち受けを閉じて（新しい接続を受けない）、今の接続の終わりをこれだけ待つ。過ぎたら切る |

- 値は `RPROXY_HANDOFF_DRAIN` と同じ書き方（`30s`・`2m`・秒の数）。上限はそれぞれ 1 時間（超えると起動を止める設定のエラー）。
- **既定は両方 `0s` で、今と同じ「すぐ止める」**（オーナーの決定）。VM・.deb の `systemctl stop` / `restart` は遅くならない。使うときは引数・環境変数で選ぶ。rproxy-gateway は自分の Pod に `5s`・`25s` を渡す。
- 順：SIGTERM → `/readyz` 503 `draining`、`event=shutdown.start` → `delay` の間は今のまま受け付ける → 待ち受けを閉じる（引き継ぎの `drain_all` の道筋。引き継ぎの終わり方と同じ）→ TCP・HTTP の接続の終わりを `drain` まで待つ → 止める（残りを切る）。両方 `0s` なら今の処理そのもの。
- HTTP：`drain` に入ったら、処理中のリクエストの応答に `Connection: close`（HTTP/2 は GOAWAY）を付けて閉じ、アイドルの keep-alive の接続はすぐ閉じる（hyper の `graceful_shutdown`。引き継ぎと同じ）。HTTP/3 は新しい QUIC の接続を受けず、今の接続は続く。
- UDP：`delay` の間は今のまま。`drain` に入ったら新しいセッションを作らず（そのデータグラムは `stats.dropped`）、今のセッションは `drain` の終わりまで続ける（kube-proxy は外れた宛先の UDP の conntrack を消すので、多くは新しい Pod へ移る）。
- 制御 API：`delay`・`drain` の間も、読むだけの API（`GET`）と `/healthz`・`/metrics` は答える（UI の利用量が最後まで取れる）。変更の API（`POST`・`PUT`・`PATCH`・`DELETE`）は `503 shutting_down`。制御 API は止める直前に閉じる。
- 2 回目の SIGTERM・SIGINT（Ctrl-C）：残りを待たずにすぐ止める（今と同じ動き）。
- ログ：`shutdown.start`（`delay_secs`・`drain_secs`）、`shutdown.drain`（待ち受けを閉じたとき。残りの接続・セッションの数）、`shutdown.done`（切った接続の数 `cut`）。
- 引き継ぎ（SIGUSR2）は今のまま（`RPROXY_HANDOFF_DRAIN`）。引き継いだ後の古いプロセスに来た SIGTERM も今のまま（待ちを短くする）。
- `features.graceful_shutdown: true`。

### 2.3 systemd（VM・.deb）で使うとき

.deb・`install.sh` の既定は変えない（すぐ止まる）。使うなら `/etc/rproxy/rproxy.env` に書く：

| 前にあるもの | `RPROXY_SHUTDOWN_DELAY` | `RPROXY_SHUTDOWN_DRAIN` |
|---|---|---|
| なし（クライアントが直接つなぐ） | `0s` | `10s`（HTTP のリクエストは終わり、長い TCP は 10 秒で切る） |
| ヘルスチェックで外すロードバランサ（`/readyz` を見る） | ヘルスチェックの間隔 × 外すまでの回数 + 1 秒（例 `5s`） | `10s`〜`25s` |
| keepalived などの VIP（`/readyz` で VIP を手放す） | VIP が移るまでの時間（例 `3s`） | `10s` |

- `TimeoutStopSec`（systemd の既定 90 秒）は `delay + drain + 5 秒` より長くしておく（超えると systemd が SIGKILL で止める）。
- `systemctl restart` もこの分だけ遅くなる。バイナリの更新は引き継ぎ（SIGUSR2、.deb の更新は同じマイナーなら引き継ぎ）を使えば、`delay`・`drain` を待たずに接続を切らずに入れ替わる。

### 2.4 Kubernetes（rproxy-gateway）

- managed：`RPROXY_SHUTDOWN_DELAY=5s`・`RPROXY_SHUTDOWN_DRAIN=25s`、`terminationGracePeriodSeconds` を `delay + drain + 5`（35）、readiness の probe を `/readyz` に（`draining` ですぐ外れる）。
- fleet：chart の値で同じ既定。hostNetwork なので外の LB・VIP の外れ方に合わせて `delay` を決めることを gateway の文書に書く。
- コントローラは終わりかけ（`deletionTimestamp` あり）の Pod に PUT しない（今と同じ）。変更の API が `503 shutting_down` になっても、次の Pod で揃う。

### 2.5 試験

結合の試験（`tests/shutdown.rs`）：SIGTERM の後、`delay` の間は新しい接続が通り `/readyz` は 503、`drain` に入ると新しい接続は断られ、前からの TCP の転送は最後まで届く、`drain` を過ぎると切る、2 回目の SIGTERM ですぐ止まる、HTTP/1.1 の keep-alive に `Connection: close`、`delay` の間の読むだけの API と変更の `503 shutting_down`、既定（`0s`・`0s`）ではすぐ止まる。

## 3. D1. #240 証明書の API（v0.4.2）

### 3.1 エンドポイント

| メソッドとパス | 本文 | 成功時 | 説明 |
|---|---|---|---|
| `PUT /certs/{name}` | `{"cert": "<PEM>", "key": "<PEM>", "chain": "<PEM>"?}` | 201（新しく）/ 200（差し替え） | 確かめて保存する：PEM が読める、鍵と証明書が合う、期限内（切れていれば `400 invalid`、`--cert-warn-days` 以内は `warnings`）。`If-Match`（指紋）を受ける（違えば `412 precondition_failed`）。応答は `GET` の 1 件の形 |
| `GET /certs` | | 200 | `[{"name","sans","not_before","not_after","fingerprint_sha256","issuer","used_by":[<ルールのキー>],"updated_at","updated_by"}]`。鍵は返さない |
| `GET /certs/{name}` | | 200 | 上の 1 件（なければ `404 not_found`） |
| `DELETE /certs/{name}` | | 204 | 使うルール（設定ファイル・API・組を含む）があれば `409 in_use`（本文に `used_by`） |

- 名前：`[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?`（パスにそのまま使えるもの。外は `400 invalid`）。本文は 1 MiB まで。
- 鍵が流れるので、**TCP の制御 API は TLS のときだけ**受け付ける：loopback の平文と Unix ソケットは許し、それ以外の平文の TCP からの `PUT` は `403 tls_required`。
- `features.cert_store: true`。ストアが使えない（ディレクトリを作れない・書けない）ときも印は true で、`PUT` が `503 cert_store_unavailable`。

### 3.2 ルールから使う

- `tls.certificates[]` に `{"cert": "<name>"}`（`cert_file`・`key_file`・`chain_file`・`acme` の代わり。どれか 1 つ）。API・設定ファイル・DB・組のどれでも同じ形。`client_auth`・転送先（`services[].tls`）の証明書にはまだ使わない。
- 名前がストアになければ、API の作成・変更・組の PUT は `400 tls_config`（`certificate "<name>" is not in the certificate store`）。起動時・再読み込みのルールは `failed`（`conditions` の `ResolvedRefs: False`、`CertificateUnreadable`）。あとから `PUT` されたら、その名前を待っていた `failed` のルールを組み立て直す。
- 差し替え（同じ名前の `PUT`）：使っているルールは接続を切らずに新しい証明書になる（証明書のストアの読み直しの道筋。`RPROXY_CERT_CHECK_SECS` を待たずに、`PUT` がすぐ読み直させる）。

### 3.3 保存

- 置き場所：`--cert-store` / `RPROXY_CERT_STORE`（既定 `/var/lib/rproxy/certs`。.deb の `StateDirectory`）。DB には置かない（鍵を DB に入れない）。
- 形：`<store>/<name>/<指紋の先頭 16 桁>/{tls.crt,tls.key,chain.crt}` に一時ファイル → fsync → rename で書き、`<store>/<name>/current` のシンボリックリンクを一時のリンク → rename で付け替える。古い版は付け替えの後に消す。`updated_by`・`updated_at` は `<name>/meta.json`。
- ファイルの持ち主：rproxy が自分で書くので `rproxy-api` のもの。**ディレクトリは 0700、ファイルはすべて 0600**（.deb の UI は `rproxy` のグループに入っているので、グループに読ませない）。`global.files.owner_check: strict` をそのまま通る。`trusted_dirs` の下には置けない（起動を止める設定のエラー）。
- 起動時：ストアのディレクトリがなければ作る。作れない・書けないときは `--cert-store` を指定していれば `event=degraded`（`part: "cert_store"`）、既定のままなら info のログだけ（証明書の API を使わない今の環境にログの誤りを増やさない）。
- 引き継ぎ（#174）：ファイルなので何も渡さない。複数の rproxy（gate1 / gate2）では、呼ぶ側がノードごとに `PUT` する。

### 3.4 権限と監査

- スコープ：`certs:read`（`GET`）、`certs:write`（`PUT`・`DELETE`）、`admin` はすべて。
- トークンに `allow_certs`（名前の接頭辞の一覧、`allow_rulesets` と同じ形）。外の名前の `PUT`・`DELETE` は `403 forbidden`。
- ルールで `{"cert": name}` を使うには、`rules:write` と、その名前が `allow_certs` の内であること（ほかの人の証明書でなりすまさないため）。`GET /certs` は `allow_certs` の内だけを返す。
- 監査：`event=audit`、`action: cert.put|cert.delete`、名前と指紋だけ（PEM・鍵はログ・誤りの文に出さない）。
- **rproxy-gateway は使わない**：鍵を制御 API に流さない（gateway の設計の「選ばなかった形」）。Secret のボリュームと certsync のまま。

### 3.5 試験

`tests/cert_api.rs`：PEM・鍵の不一致・期限切れ・大きさ・名前、`allow_certs`、`409 in_use`、差し替えで接続を切らずに新しい証明書になる、ファイルのモード（0600・0700）、`owner_check: strict` で使える、ストアに書けないとき、平文の TCP の `403 tls_required`、監査ログに鍵がない。

## 4. D2. #241 組の保存（v0.4.2）

- 印：組の保存はトークンの `persist` で決める（#144 と同じ。`PUT` の本文には足さない）。`persist: true` のトークンで `PUT`・`DELETE` した組を保存する。応答・`GET /rulesets`・`GET /rulesets/{name}` に `persisted`（保存した組だけ）。コントローラのトークンは `persist` を持たないので、gateway の組は今までどおりメモリだけ。
- 書くとき：`PUT` の応答の前に 1 行を upsert（`generation` が DB の値より小さければ書かない）。`DELETE` で行を消す。書けなければ組は動かしたまま `persisted: false`、`event=degraded`（`part: "db"`）。`dry_run` は書かない。
- 起動時：設定ファイル → UI の表 → `rproxy_rules` → `rproxy_rule_sets` の順に戻す。前のものと同じキーのルールはそのルールだけ `failed`（`restore.conflict`）、組の残りは当てる（`PUT` と同じ）。`/readyz` は戻し終わってから ready（今と同じ）。持ち主（`owner`）・`generation`・`etag` も戻す。戻すときのファイルの確かめ（`owner_check`・`trusted_dirs`）は今と同じ。
- 表（UI のリポジトリの `db/migrations/012_rproxy_rule_sets.sql`）：

```sql
CREATE TABLE IF NOT EXISTS rproxy_rule_sets (
  node         VARCHAR(255) NOT NULL,     -- RPROXY_NODE_NAME（rproxy_rules と同じ）
  name         VARCHAR(253) NOT NULL,     -- 組の名前
  generation   BIGINT UNSIGNED NOT NULL,
  etag         VARCHAR(64)  NOT NULL,
  owner        VARCHAR(255) NOT NULL,     -- 組の持ち主のトークンの名前（セキュリティレビュー M3）
  rules        JSON         NOT NULL,     -- PUT の本文の rules と同じ形
  spec_version INT UNSIGNED NOT NULL DEFAULT 1,
  updated_by   VARCHAR(255) NOT NULL,
  updated_at   DATETIME(3)  NOT NULL,
  PRIMARY KEY (node, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON rproxy.rproxy_rule_sets TO 'rproxy'@'...';
-- GRANT SELECT ON rproxy.rproxy_rule_sets TO 'rproxy_ui'@'...';
```

- 1 つの組を 1 行（JSON）：組の `PUT` は全部か何もなしなので、1 行の書き込みで揃う。大きさ：`PUT` の本文は 32 MiB まで、MariaDB の `max_allowed_packet` の既定（16 MiB）より大きいときは書けない（`persisted: false`）。
- 表がない（migration 012 の前）ときは、保存の印のある `PUT` だけが `persisted: false` と `degraded` になる。起動時の読み込みは表がなければ何もしない（今の環境の起動ログを変えない）。
- ノードの間で分けあわない：`node` は自分の名前で、戻すのも自分の行だけ。gate1 / gate2 では呼ぶ側が両方に `PUT` する（組の `PUT` は冪等）。rproxy が DB を見張る形にするなら別の issue。
- `features.ruleset_persistence: true`。
- UI：`rproxy_rule_sets` を読むだけで、保存した組を管理者にだけ出す（`rproxy_rules` と同じ扱い）。
- **rproxy-gateway は使わない**：正は etcd にあり、rproxy の再起動後はコントローラが `/readyz` を待って PUT し直す。保存すると、止まっている間に消した Gateway のルールが戻ってくる。
- 試験（`tests/persist.rs` の MariaDB の試験と同じ仕組み）：保存 → 再起動 → 戻る（`generation`・`etag`・`owner`）、古い `generation` を書かない、ほかのノードの行を戻さない、衝突のルールだけ `failed`、`persist` のないトークンの組は書かない。

## 5. 決めたこと（2026-10-08、オーナーの了承）

| # | 決めたこと |
|---|---|
| 版 | v0.5.0 は作らず、v0.4 のパッチで出す（E は v0.4.1、D1・D2 は v0.4.2） |
| E の既定 | rproxy のバイナリの既定は `delay 0s`・`drain 0s`（今と同じくすぐ止める）。引数・環境変数で選ぶ。rproxy-gateway は `5s`・`25s` |
| #240 の鍵のモード | ファイルはすべて 0600、ディレクトリは 0700（issue の 0640 だと `rproxy` のグループの UI のプロセスが読める） |
| #240 の名前の制限 | トークンの `allow_certs`（名前の接頭辞）を付ける |
| #241 の保存の印 | トークンの `persist`（#144 と同じ。gateway のトークンには付けない） |
| #241 のノードの間 | 分けあわない（ノードごと、呼ぶ側が両方に PUT） |

## 6. 実装での設計との違い

- **#241 の起動時の取り合い（オーナーの了承、2026-10-08）**：4. では「前のものと同じキーのルールはそのルールだけ `failed`」としていたが、ルールの表はキーごとに 1 つなので、同じキーの 2 つ目のルールは `failed` としても登録できない。そこで、前に戻したルールとキー・待ち受けが重なるルールは**その組から外して** `restore.conflict`（ファイルを読めないなど、ほかの理由で当てられないルールは `restore.skip`）を出し、組の残りを当てる。外したときは組の `etag` が保存したものと変わり、`ruleset.restore` のログに新しい `etag` と保存した `stored_etag` の両方を出す。DB の行はそのままにする（次の `PUT` で揃う）。

## 7. Gateway API の残り（v0.4.3、rproxy-gateway v0.4.5）

rproxy-gateway が名乗っていない Gateway API の機能（rproxy-gateway の docs/CONFORMANCE.md の「名乗っていないもの」）のうち、rproxy に口が要るもの。どれも省略でき、省略したときは v0.4.2 と同じ（オーナーの依頼、2026-10-08）。v0.4.0 の 16.（docs/DESIGN-v0.4.md）と同じく、Gateway API の形を rproxy の一般の設定にして、コントローラが写す。

### 7.1 421 Misdirected Request（`tls.misdirected`）

- 困ること：rproxy-gateway は同じポートの HTTPS のリスナー（ホスト名が違う）を 1 つのルールにまとめ、証明書を SNI で選ぶ。ブラウザは証明書の SAN にある別の名前のリクエストを同じ HTTP/2 の接続で送る（connection coalescing、RFC 9113 §9.1.1）ので、SNI で選んだリスナーとは別のリスナーのルートに届く。Gateway API（`Listener.hostname` の説明、conformance の `HTTPRouteHTTPSListenerDetectMisdirectedRequests`）は、Host がほかのリスナーに当たるなら 421、どのリスナーにも当たらなければ 404 を求める。
- 形：`tls.misdirected: {groups: [[パターン, ...], ...]}`。パターンは `tls.routes` と同じ（完全一致・`*.`・`**.`）に、どの名前にも当たる `*` を足したもの。名前は最も近いパターンのグループに入る（`tls::config::best_match` と同じ順で、`*` が最後）。SNI と Host がどちらもグループに入り、違うグループなら 421。どちらかがどのグループにも入らない・SNI がないときは確かめない（ルートで選ぶ）。
- 「リスナー」を rproxy の言葉にしない：rproxy はリスナーを知らないので、名前の集まりとして渡す。コントローラはリスナーごとに 1 つのグループ（ホスト名のないリスナーは `*`）を作る。
- どこで：`server.rs` の `Conn::handle` で、ルートを選ぶ前に。ルートもミドルウェアも通らない（ほかのリスナーのルートのミドルウェア（認証など）を、この接続の名前で動かさない）。HTTP/1.1・HTTP/2・HTTP/3 のどれも同じ（421 は HTTP/1.1 でも正しい）。
- 検証：`http` と `tls.mode: terminate` のルールだけ。同じパターンを 2 か所に書けない。`features`：`http_options` の `misdirected`。
- 試験：単体（conformance の組み合わせ）、`tests/gateway_l7.rs`（1 つの HTTP/2 の接続で複数の `:authority`、HTTP/1.1）。

### 7.2 転送先ごとの `cors`・リダイレクト・`mirror`

- 困ること：Gateway API の backendRef の `filters`（その backend に送るときだけ働く）は、rproxy の `servers[].middlewares`（#229）に写しているが、使える種類が書き換えだけ（`headers`・`replace_host`・パスの書き換え）なので、`CORS`・`RequestRedirect`・`RequestMirror` のフィルタのルートは `UnsupportedValue` だった。
- 形：`servers[].middlewares` に使える種類へ `cors`・`redirect_scheme`・`redirect_regex`・`mirror` を足す（形は増やさない）。`features.server_middleware_kinds` に使える種類の一覧（コントローラはこれで古い rproxy を見分ける。`http_options` の `server_middlewares` は前のまま）。
- `cors`・リダイレクト：もともと `on_request` で答え、`on_response` でヘッダを付けるので、`server.rs` の `forward` の転送先ごとの処理でそのまま動く（答えたら送り直さない）。
- `mirror`：写しの本文と送り先のサービスが要るので `forward` が扱う。転送先を選んだ後、その転送先のミドルウェアを順に通し、`mirror` のところでその時の形を写す（転送先へのヘッダ（`X-Forwarded-*`・証明書）を付けた後なので、写しを送るときに付け直さない：`mirror::Copy.forwarded`）。`retry` の送り直しでは、最初に `mirror` のある転送先に当たったときだけ写す（1 つのリクエストで 1 回）。
- 写しの先のサービスは先に組み立てる必要がある（`Service::compile_with`）。転送先が `mirror` を持つサービスを後に組み立て、`mirror` の先のサービスの転送先が自分で `mirror` を持つことは断る（写しを写さない。順が決まる）。
- 試験：`tests/gateway_l7.rs` の `per_server_cors_redirects_and_mirrors`（2 つの転送先の片方が CORS と写し、片方がリダイレクト。写しは送った転送先の分だけ・`X-Forwarded-For` は 1 つ・本文の長さ、プリフライト、断る形）。

### 7.3 外部の認可（`forward_auth` の拡張）

- 困ること：Gateway API の `ExternalAuth` フィルタ（experimental、Envoy の ext_authz の形）は、HTTP なら「クライアントのメソッド・パス（`http.path` の接頭辞の後ろ）・Host で問い合わせ、200 だけを通し、`allowedResponseHeaders` が空なら応答のヘッダをすべて写す、`forwardBody.maxSize` まで本文も送る」、gRPC なら Envoy の `envoy.service.auth.v3.Authorization/Check`。rproxy の `forward_auth` は Traefik の形（`GET` に `X-Forwarded-Uri`、2xx で通す、書いたヘッダだけ写す）だけだった。
- 形：新しいミドルウェアを作らず `forward_auth` に項目を足す（認証の口を 1 つに保つ。Traefik の形はそのまま）：`service`・`path`（Kubernetes では宛先が Pod の IP の一覧で、`address` の 1 つの URL では足りない。ルールのサービスを使えば `balance`・`health_check`・BackendTLSPolicy の `tls` もそのまま）、`client_request`、`allow_status`、`response_headers: ["*"]`、`forward_body: {max_size}`、`protocol: grpc`。`features.forward_auth` に使える項目の名前。
- `["*"]` で写さないヘッダ：応答そのものを表すもの（ホップごと、`Host`・`Content-Length`・`Content-Type`・`Content-Encoding`・`Transfer-Encoding`・`Date`）。写すと転送先へのリクエストの本文の長さや種類が壊れる。
- `forward_body`：大きいものは Gateway API の型の説明（「`maxSize` で切って送る」）とフィルタの説明（「4xx で断る」）が食い違う。Envoy の既定（`allow_partial_message: false`）と同じく 413 で断る。読んだ本文は `buffering` と同じく転送先にもメモリから送る。
- gRPC：protobuf のコード生成の依存を足さず、使う欄だけを手で書いた（`l7/middleware/ext_authz.rs`。知らない欄は読み飛ばす）。HTTP/2 は転送先の HTTP/2（#233）をそのまま使う（`address` は h2c だけ、TLS は `service` の `protocol: h2`・`tls`）。`ok_response.headers` の `append` がないときは置き換え（Envoy の ext_authz の決まり）。`response_headers_to_add` はクライアントへの応答に付ける。gRPC の誤り（`grpc-status` が 0 でない・応答が読めない）は 403（Envoy の `status_on_error` の既定）、つながらない・時間切れは HTTP の `forward_auth` と同じ 502・504。
- 転送先ごと：`servers[].middlewares` にも `forward_auth` を書ける（backendRef の `ExternalAuth`）。`service` を使う `forward_auth` を転送先が持つサービスは、7.2 の `mirror` と同じく後に組み立て、その先のサービスの転送先が自分で別のサービスへ送ることは断る。
- 試験：単体（`ext_authz` の組み立てと読み取り、`copy_answer` の `["*"]`）、`tests/ext_authz.rs`（Envoy の HTTP の形：メソッド・パス・Host・`Content-Length`・本文・ヘッダの選び方・`["*"]`・200 だけ・413、gRPC：`address` と `service`、ヘッダの付け外し・応答に足すヘッダ・断り・gRPC の誤り、転送先ごと、断る形）。
- 守り：認証サーバへのヘッダは今までどおりクライアントの証明書のヘッダを rproxy の見たものにする（#238）。gRPC の `ok_response` が `Host` を変える・外すことは受け付けない（ルートを選んだ後の宛先を変えさせない）。

## 8. G. Kubernetes の fleet の VIP とノードの喪失（v0.4.3）

rproxy-gateway の v0.4.4（fleet の Pod が VIP を持つ）の後に分かった 2 つの穴のうち、rproxy-api の分。gateway の側は rproxy-gateway の docs/DESIGN-v0.4.x.md に書く。

| 項目 | 形 | `features` | 既定 |
|---|---|---|---|
| まだホストにない VIP で待ち受ける | ルールの `listen_freebind: true`（`IP_FREEBIND` / `IPV6_FREEBIND`） | `listen_freebind`（Linux） | false（今までどおり、ホストにないアドレスは bind に失敗） |
| 止まったノードの宛先を早く諦める | L4 の `tcp` のルールの `connect_timeout`（`100ms`〜`10m`） | `connect_timeout` | なし（ほかに宛先があれば 5 秒、なければ OS の既定） |

- `listen_freebind` は自動にしない（「ホストにないアドレスなら自動で」は、打ち間違えたアドレスを黙って受け付ける）。権限は要らないので、`IP_TRANSPARENT`（`CAP_NET_ADMIN`）は使わない。ルールごとの印にしたのは、fleet の Pod を作り直さずにコントローラが Gateway ごとに選べるように（プロセス全体の設定にすると DaemonSet の入れ替えが要る）。
- `0.0.0.0` / `::` と同じポートの特定のアドレス：今までどおり `409 already_exists` で断る（`SO_REUSEADDR` で狭いほうが勝つ形にはしない。届く先がアドレスの有無で変わり、取り合いが見えなくなる）。誤りの文に、重なる相手のルールの組と理由を足した。
- `connect_timeout` は PATCH でその場で変えられる（次の接続から）。`listen_freebind` は変えられない（ソケットを開き直すので作り直し）。
- 引き継ぎ・保存：ルールの形に足すだけ（`GET /rules` の形・`rproxy_rules.spec` に入る。古いパッチは知らない項目を無視して読む）。
- 試験：`scripts/test-freebind.sh`（名前空間の実経路。CI の transparent のジョブ）、`tests/listen.rs`、`tests/targets.rs`（SYN を捨てる宛先）。

## 9. PROXY protocol を受け取る（v0.4.13、#296）

前段（ロードバランサ・別の rproxy・Kubernetes の Gateway）が付けた PROXY protocol v1 / v2 のヘッダを読み、本当のクライアントのアドレスとして使う。今までの `net::source` は書くだけだった。

| 項目 | 形 | `features` | 既定 |
|---|---|---|---|
| PROXY ヘッダを受け取る | `tcp` のルールの `proxy_protocol: {"from": [<CIDR>, ...], "required"?: bool}` | `proxy_protocol_in` | なし（今までどおり、ヘッダは読まない） |

- 信じる相手：`from` は TCP の接続元（すぐ前の段）で判定し、ヘッダの中のアドレスでは判定しない。`from` は必須で空にできず、`/0` も断る（誰のヘッダでも信じる設定を作らせない）。`required` は既定 `true`。
- `from` の外からヘッダらしきもの（v2 の署名・`PROXY `）で始まる接続：**断る**（issue の「決めること」。前段の設定ミスに気づけ、ヘッダがデータとして転送先に流れて、ヘッダを信じる転送先にアドレスを偽られることもない）。`conn.denied` の `reason: proxy_protocol_untrusted`。ほかの接続は今までどおり。
- 最初のバイトの待ち方：クライアントから先に送るルール（TLS の `sni`・`terminate`、`http`）は、外からの接続でも最初のバイトを待つ（どのみち rproxy が最初に読む）。平文の TCP と STARTTLS はサーバから先に送ることがあるので待たず、受け付けたとき（と平文の TCP では転送先につながったとき）に届いているバイトだけを見る（外からの接続を遅らせないため。取りこぼしはありうる）。
- 上限：v1 は 107 バイト（仕様）。v2 は長さの欄が 16 ビット（65535）まで言えるが、固定の 16 バイトの後を 4096 バイトまでにした（アドレスは最大 216 バイト（AF_UNIX）、AWS の VPC エンドポイント ID・GCP の PSC の ID・HAProxy の SSL の TLV・unique ID はどれもずっと小さい）。時間の上限は受け付けてから 5 秒（変えられない。TLS のハンドシェイクの 10 秒より短く、前段は接続の直後に送るので足りる）。
- 読み方：`peek` で見て判断してから、ヘッダの分だけを読む（ヘッダの後のバイトを読みすぎないので、後の処理（ClientHello の読み取り・splice・STARTTLS）はそのまま）。細切れに届くときは届くのを待つ。
- TLV は読み飛ばす（転送先へは rproxy 自身が見たものを書く）。`LOCAL`・`UNKNOWN`・`AF_UNSPEC`・`AF_UNIX` は接続元のアドレスのまま。TCP の接続の `DGRAM` は断る。
- 本当のクライアントを使うところ：`allow_from`・`geoip`・`crowdsec`・`limits`・`bandwidth`、ログの `client`、`X-Forwarded-For`・`X-Real-IP`（`global.trusted_proxies` の判定も）、転送先への `source_ip`（`proxy_v1` / `proxy_v2` / `transparent`）。前段はログの `proxy_peer`（L4 はタスクローカル `net::proxy_in::PROXY_PEER`、`http` は `Conn.proxy_peer`）。転送先へのヘッダの宛先は今までどおり rproxy が受けたアドレス。
- 順序：`from` の前段からはヘッダを読んでから `allow_from` などを確かめる（それまでの「`allow_from` は PROXY ヘッダより前」は、`proxy_protocol` のないルールと `from` の外の接続でだけ成り立つ）。
- PATCH でその場で変わる（次の接続から）。組の PUT・設定ファイルの再読み込みも `in_place`。引き継ぎ・保存：ルールの形に足すだけ。DB の `options` にも同じ形で書ける。
- 対象外（後の段階）：UDP の PROXY v2（データグラムごとのヘッダ。v0.4.16 で入れた、12.）。HTTP/3 の QUIC にはヘッダがない。
- 試験：単体（`net::proxy_in`：解析・上限・細切れ・時間切れ・検証）、`tests/proxy_protocol.rs`（`allow_from`・`limits`・`X-Forwarded-For` とアクセスログ・PROXY v2 で受けて PROXY v2 で送る・`LOCAL`・`required`・外からのヘッダ・形と PATCH）、ファジングの `proxy_header_in`。

## 10. `tls.routes[]` ごとの `source_ip`（v0.4.13、#297）

1 つのポートの `terminate`（`http` のルールを含む）のルールで、L7 の部分（PROXY のヘッダを受けない転送先）と、そのまま流す名前（Kubernetes など、PROXY v2 でクライアントを受けたい転送先）とで送信元の渡し方を分ける。

| 項目 | 形 | `features` | 既定 |
|---|---|---|---|
| route ごとの送信元の渡し方 | `tls.routes[].source_ip`（`proxy`・`proxy_v1`・`proxy_v2`） | `route_source_ip` | なし（ルールの `source_ip`） |

- 書ける route：L4 で転送先へつなぐもの（`terminate` の `passthrough: true` の route、`sni` のルールの route。`tcp`・`udp`）。PROXY のヘッダはクライアントのバイト（ClientHello）の前に置くので、終端せずに流す接続でだけ意味がはっきりする。rproxy が終端する route は `unsupported`（issue の「まずルールのもの、要るなら後で」）。
- `transparent` は route ごとには選べない（`unsupported`）：`IP_TRANSPARENT` のソケット・ポリシールーティング・転送先からの戻りの経路の準備がルールの単位で、名前ごとに変えると戻りの経路が合わない。`udp` の route の `proxy_v1` もルールと同じく `unsupported`。
- `transparent` のルールの route に `proxy*` を書いたとき：その route の転送先へは rproxy のアドレスからつなぐ（route の値をそのまま使う。ルールの `transparent` を残して PROXY ヘッダを足す形にはしない）。
- 実行時は route の `RouteTarget.source_ip` → `Target.source_ip`、`Runtime::source_ip_for` / `bind_as_for`（`tcp.rs` の `relay_hello`・`connect`、`udp.rs` の `session`）。PATCH・組の PUT・再読み込みは route の差し替え（`install_routes`）なので `in_place`（ルールの `source_ip` は今までどおり作り直し）。
- `proxy_protocol`（#296）で受けた接続では、ヘッダのクライアントを書く（ルールの `source_ip` と同じ）。
- 引き継ぎ・保存：ルールの形（`tls.routes[]`）に足すだけ。DB の `options.tls` にも同じ形で書ける。Traefik の変換は、ルーターごとに違う `proxyProtocol.version` を route の `source_ip` にする（終端しないルーターだけ）。
- 試験：単体（`tls::config` の検証、`config::plan` の round trip と `in_place`）、`tests/route_source_ip.rs`。

## 11. API の保存の書き込みの列（v0.4.14、#303）

kill -9 の直後に起動し直したプロセスが、止まったプロセスの書き込みの確定より先に `rproxy_rules` を読み、行はあるのにルールが動かない、が起きた（CI の `stored_rules_survive_kills_with_mariadb`）。直し方（オーナーの決定）：

- DB への仕事はすべて 1 本の列を通り、1 つの係が 1 本の接続とノードのロック（`GET_LOCK`）を持って順に実行する（`config::persist::queue`）。API は入れて確定を待つ。読み込み（起動時・照合）も同じ列を通るので、プロセスの中で古いものを読まない。
- 書き込みは時間に上限のあるトランザクション（`max_statement_time`・`innodb_lock_wait_timeout` 3 秒、`wait_timeout` 30 秒と ping）。止まったプロセスの書き込みも上限のうちに終わるので、起動はロックをその間（8 秒）だけ待って読む。`KILL CONNECTION` は使わない。取れなければ読めるもので始め、取れたら照らし直す。
- 定期の照合（既定 60 秒）は、列が空で API の変更が途中でないときに、ロックを待たずに取れたら：書けなかったものを書き直し、行に合わせて `origin: api` のルールだけを直す。取れなければ次の回へ。
- 同じ `node` の名前のプロセスからはロックを取り上げない。起動時に生きている接続（待つあいだに文を送っている）がロックを持ち続けていれば、`persist.duplicate_node` を出して起動をやめる（オーナーの決定：名前は一意。引き継ぎの新しいプロセスは確かめない）。DB に届かないあいだに起動して後から分かったときは、書き込みを `persisted: false` にして `persist.duplicate_node` を出す。
- 照合が行を正とするのは行が最新と分かっているルールだけ（書き込みは列に入れる前に「書きかけ」として覚える）。書き直しは API の変更を止めずに行い、照合の単独の区間は比べて当てるところだけ。drain を待つ削除は、行の削除を drain の前に列に入れ、drain のあいだ変更の共有の鍵を持たない（引き継ぎの `release` を止めない、待つのも 10 秒まで）。
- 列は trait（`PersistQueue`）の後ろに置き、今はプロセスの中の実装だけ（依存を足さない）。外の列（Redis など）に替えても呼び出し側は変わらない。
- 組（`rproxy_rule_sets`）も同じ列で書く。照合は書けなかった組を書き直すだけで、動いている組を行に合わせて変えることはしない（持ち主・世代の扱いが要るため）。

### 11.1 引き継ぎの写し・組の行・同じ名前の判定（v0.4.15、#305・#306・#307）

- 引き継ぎの写し（#305）：古いプロセスは写しを取る前に、API の変更（ルール・組の作成・変更・削除。`api::changing` の共有の鍵を持つもの）と照合の当てる区間が終わるのを `FREEZE_WAIT`（10 秒）まで待ち、変更の鍵（`changes`）を単独で持ったまま写しを取る（`handoff::prepare`・`Store::freeze`）。鍵は引き継げたら `release` まで持ち、引き継げなかったら（`handoff.refused` / `handoff.failed`）放す（`thaw`）。待っても終わらない変更があれば引き継ぎをしない（`handoff.failed`。古いプロセスが動き続け、変更はそこで最後まで動いて書かれる。バイナリのせいではないので、自動更新はその版を悪い版にしない）。引き継ぎが始まった後に鍵を得た変更（`guard` を引き継ぎの前に通ったもの）は、何も変えずに `503 upgrading` で断る。引き継ぎが失敗した後は断らずに続ける。
  写しから `release` までに失われるものがないこと：
  1. API の変更：写しの前に終わったもの（写しに入り、行は書けたか、書けていなければ `Unwritten` から `persist_pending` で渡る）と、何も変えずに断ったものしかない。写しから `release` までに古いプロセスでだけ動く変更はない。前の `RELEASE_WAIT` を超えた変更（古いプロセスにだけ入り `persisted: false`）は、もう起きない（`release` は凍らせた鍵をそのまま使い、待たない）。
  2. 写しの前に列に入った書き込み：古いプロセスの列が `Release` の前に終える（順番どおり、`Release` が最後）。書き込みは列に入れる前に `Unwritten` に覚えるので、写しの時点で終わっていなければ `persist_pending` に入り、新しいプロセスが同じ中身を書き直す（古いほうが先に通っていても、中身が戻ることはない）。新しいプロセスはロックが空くまで書けないので、2 つのプロセスの書き込みが入れ違うこともない。
  3. 照合：単独の区間（行に合わせてルールを変える）は鍵が要るので写しから `release` まで動かない。書き直し（鍵なし）は動いているルール＝写しの中身を書くだけ。`release` の後は列が閉じて止まる。
  4. drain を待つ削除：行の削除は drain の前に列に入っている（2. と同じ）。ルールは写しにない。
  5. 保存と関係のない変更（証明書・トークン・設定ファイル）は今までどおり `guard` が引き継ぎ中の新しい要求を断る。設定ファイルの固定ルールは写しに入れず、新しいプロセスがファイルから読む。DB の設定がなくても `Store` はあり（行を書かないだけ）、同じように待って止める。`Store` が作れなかったとき（`RPROXY_DATABASE_URL` の誤り、`degraded`）だけは待たないが、順番を待っていた変更はやはり断る。
  引き継ぎの状態の形は変えない（足すものもない）。
  引き継ぎをしなかったとき（写しの前の待ちが上限を超えた・マイナーが違う・新しいプロセスにつなげない・タスクの panic）は、どの道でも `handoff::Running` の drop が引き継ぎの印を外し、鍵を放し、自動更新に知らせる（`Upgrader::set_on_abort`）。自動更新は `upgrader.start` の前に書いた試し（`trial`）を、その版のものなら取り下げる（`end_trial`。動かなかった版なので悪い版にもしない）。前は試しが残り、起動役が動いていない版を、関係のない終わり方で悪い版にしたり、`promote` が今の版を良い版にしなかったりした。
- 組の行（#306）：組の行の中身（`ruleset_row`）は、行を列に入れるのと同じ `order` の中で読む（`Store::save_set(registry, name, by)`。ルールの `save_rule` と同じ形。PUT の後も照合の書き直しも）。同じ `generation` の PUT が重なっても、照合の書き直しと PUT がぶつかっても、最後に列に入った書き込みが最後に読んだ中身なので、SQL の `>=` で古い中身が勝つことはなく、`persisted: true` は行と動いている組が同じときだけになる。`ruleset_row` は組の書き込みの鍵（`rulesets.write`。PUT が新しい世代と etag を入れ終わるまで持つ）の下で読むので、ある版の etag と別の版のルールが混ざらない。
- 同じ名前の判定（#307）：
  - 起動時は、ロックを取った直後から（復元の前に）ping を始める（`Store::spawn_keepalive`）。復元に `LIVE_IDLE`（15 秒）より長くかかっても、もう 1 つのプロセスからは生きて見える（前は ping が復元の後の `spawn_background` からで、2 つ目が起動していた）。引き継ぎの新しいプロセスは、古いプロセスが放すまでロックを取れないので、今までどおり復元の後から（早く始めると `DUPLICATE_AFTER` を早く数え始めてしまう）。
  - 判定（`Holder::liveness_since`）は、`PROCESSLIST.TIME` が文の始まりと終わりで数え直されることを使う。同じ状態のまま `TIME` が戻った・何もしていない状態から文が始まった：生きている（死んだクライアントは文を送れない）。「1 回目は文の途中、2 回目は何もしていない（`LIVE_IDLE` より短い）」は決められない（`Unsure`）：MySQL（文に時間の上限がない）で、落ちたホストの長い文が間に終わったときにこう見える（前は生きているとみなして断っていた）。
  - 決められないときは、断らずに `DUPLICATE_LOOK_AGAIN`（20 秒）待ってもう 1 回見る（`after_looks`）。その間に、生きているものは ping し、死んだものは何もしないか `wait_timeout` で切られてロックが空く。3 回目でも決められなければ断らずに `restore.wait` で起動を続ける：重なっても、後のプロセスはロックを取り上げず、書き込みが `persisted: false` と `persist.duplicate_node`（`DUPLICATE_AFTER`）になるので、警告にとどめる方を選んだ。断るまでの時間は最長で約 60 秒（決められないときだけ。ふだんは今までどおり約 40 秒）。

## 12. UDP で PROXY protocol v2 を受け取る（v0.4.16、#312）

多段の構成（外側の rproxy → 内側の rproxy → 転送先）で、UDP でもクライアントのアドレスを保つ。外側の `source_ip: proxy_v2` はもともとデータグラムごとに PROXY v2（DGRAM）のヘッダを付けて送れたが、内側が読めなかった。

| 項目 | 形 | `features` | 既定 |
|---|---|---|---|
| UDP の PROXY ヘッダを受け取る | `udp` のルールの `proxy_protocol`（形は 9. と同じ） | `proxy_protocol_in_udp` | なし（今までどおり、ヘッダは読まない） |

- 形と意味は TCP と同じ（`from` は必須・空と `/0` は不可、`required` は既定 `true`）。新しい設定の項目はない。
- 解析：`net::proxy_in::parse_dgram`。v2 の DGRAM（`0x12`・`0x22`）、`LOCAL`、`AF_UNSPEC`（と転送の種類の指定なし、AF_UNIX）だけを受け付け、v1・STREAM・データグラムの中で終わらないヘッダは誤り。上限は TCP の解析と同じ（`V2_MAX_PAYLOAD` 4096 バイト）。TCP の `parse` と同じ `parse_v2` を使い、違いは転送の種類の判定だけ。データグラム 1 つの判断（信じる前段か・ヘッダのクライアント・外す長さ・捨てる理由）は純粋な関数 `datagram` で、ファジングの `proxy_header_in` も通す。
- どこで読むか：`l4::udp::serve` の、データグラムを受けたところ（`allow_from` より前）。前段からのデータグラムは、ヘッダを外した残り（受信のまとまりのバッファの中の位置をずらすだけ。写しは今までどおりセッションの列に入れる 1 回だけ）をセッションに渡す。DTLS・QUIC の名前の読み取り（`sniff`・`renamed`）も、DTLS の終端もヘッダのないデータグラムを見る。
- セッションの鍵：`Peer { from, local, named }`（前段のアドレス・ポート、受けたアドレス、ヘッダのクライアント）。返事は `from`（前段のソケット）へ、ヘッダなしで返す。外側の rproxy はセッションごとに転送先へのソケットを持つので、内側では前段のポートがクライアントごとに分かれる。同じ前段のポートのヘッダのクライアントが変わったら別のセッション（前のものは `udp_idle_secs` で終わる。決めたこと：ヘッダを付け替える前段はふつうないので、作り直さずに分ける方を単純にした）。
- 速さ：`proxy_protocol` のないルールは、データグラムのまとまりごとに relaxed load 1 回（`proxy_in::Slot`、`limits` と同じ形）で、データグラムごとの処理は変わらない。`Peer` の `Hash` はヘッダのクライアントがないとき、今までの（アドレス, 受けたアドレス）の組と同じものだけを混ぜる。ヘッダを読む道は、信じる前段の判定・解析・外す位置だけで割り当てなし（`benches/parse.rs` の `proxy_dgram`：手元で 1 データグラムあたり約 40〜45 ns。`benches/dataplane.rs` の `l4_udp/roundtrip_1KiB_proxy_protocol` は loopback の往復のばらつきの中で、ヘッダなしの `roundtrip_1KiB` と区別できない）。
- 拒否：`stats.denied` と `conn.denied`（`warn`、`reason: proxy_protocol` / `proxy_protocol_untrusted`、`error`、外からのものは `version`）。UDP のほかの拒否と同じく `Runtime.denied_log` で前段ごとに間引く（送信元を偽れる UDP で、ログをあふれさせない）。
- ヘッダのクライアントを使うところ：`allow_from`・`geoip`・`crowdsec`・`limits`（データグラムとセッション）・`bandwidth`、ログの `client`（前段は `proxy_peer`。データグラムの判定は `proxy_in::sync_with_peer`、セッションのタスクは `with_peer`）、`source_ip`（`proxy_v2` はヘッダのクライアントを書き、`transparent` はヘッダのクライアントで bind する）、route の `source_ip`（#297）。
- DPDK の道（`Bound::Dpdk`、実験の機能 `dpdk`）：ヘッダを読まない。どの道でも断る（`dpdk::proxy_protocol_refused`）：作成と作り直しは `dpdk::claim` が `bind_failed`、PATCH（と dry run）は `Registry::updated_spec` が同じ誤り、組の PUT と設定ファイルの再読み込みは `config::plan::in_place` が偽になって作り直し（`claim` で `failed`）。その場で変えて DPDK の道がヘッダを付けたままのデータグラムを流すことはない（なお付いていれば、DPDK の道の新しいセッションは作らず、`conn.error` は送信元ごとに間引く）。読めるようにするのは、実機の確かめと一緒に後で。
- 対象外：`http` のルールの HTTP/3（quinn の UDP）は今までどおりヘッダを読まない。
- PATCH・組の PUT・再読み込みは `in_place`（次のデータグラムのまとまりから）。引き継ぎ・保存はルールの形のまま（UDP のセッションは引き継ぎで作り直し）。
- 試験：単体（`net::proxy_in` の `parse_dgram`・`datagram`・`Slot`、`config::plan` の round trip と `in_place`、`l4::dpdk` の `dpdk_refuses_proxy_protocol_on_its_addresses`（機能 `dpdk`、CI の `dpdk.yml`））、`tests/proxy_protocol_udp.rs`（2 段の rproxy・`allow_from`・`required`・外からのヘッダ・壊れたヘッダ・送信元ごとの `limits`・QUIC の `sni` と route の `source_ip`・DTLS の終端・PATCH での付け外し・検証）、ファジングの `proxy_header_in`（DGRAM の seeds）、ベンチマーク。

## 13. 照合の前のパスと Host の正規化・身元のヘッダ・接続の時間の上限（v0.4.17、#320）

脆弱性の点検（2026-10-23）の高 C と中 M1。`RequestInfo.path` を生のまま照合していたので、`/%61dmin`・`//admin`・`/x/../admin` が `PathPrefix(`/admin`)` に付けた `basic_auth`・`oidc`・`forward_auth`・`ip_allow` を素通りして認証のないルートに流れた。Host の末尾のドットも当たらなかった。身元のヘッダ（X-Forwarded-User など）は認証のミドルウェアの中でしか消していなかった。HTTP の接続には、hyper-util の `auto` の判定・HTTP/2 のアイドル・リクエストの本文に待ち時間の上限がなかった。

| 項目 | 形 | `features` | 既定 |
|---|---|---|---|
| パスの正規化 | なし（いつも）。`http.raw_path: true` で止める | `http_options` の `path_normalize`・`raw_path` | **正規化する**（オーナーの決定で既定を変える。「省略したときは前のパッチと同じ」の例外） |
| Host の正規化 | なし（いつも） | `path_normalize` | 小文字・末尾のドットを落として照合 |
| 身元のヘッダを消す | なし（いつも） | `identity_headers` | 認証のミドルウェアのあるルールで消す |
| 接続の時間の上限 | `global.http.timeouts`（`tls_handshake`・`first_byte`・`request_headers`・`idle`・`request_body_idle`・`http2_ping_interval`・`http2_ping_timeout`） | `http_timeouts` | `10s`・`10s`・`30s`・`180s`・`60s`・`60s`・`20s` |

- パス（`l7::normalize::path`）：Traefik v3 の `sanitizePath` に合わせる。unreserved（RFC 3986 2.3）のパーセント符号化だけを戻し、ほかは符号化のまま 16 進を大文字に（`%2F` は区切りにしない。Go の Traefik は `%2F` を戻した `URL.Path` で `..` を解くが、rproxy は符号化のままのパスで解く：`/a%2F..%2Fadmin` は 1 つの区切りのまま。区切りを増やさない方が安全なので、ここだけ違う）、`.`・`..`・空の区切りを解き、ルートより上は `/` で止め（決めたこと：400 にせずに切り詰める。Go の `path.Clean`・RFC 3986 の remove_dot_segments と同じ）、末尾の `/` は元のパスにあれば残す。`%` の後に 16 進が 2 つないものは 400（決めたこと：Go の HTTP サーバも 400）。クエリは変えない。
- どこで：`server.rs` の `Conn::handle` の最初（HTTP/1.1・HTTP/2・HTTP/3 が通る 1 か所）で `normalize_target` が `Uri` を置き換える。以後の照合・ミドルウェア（`strip_prefix` など）・`forward_auth`（`X-Forwarded-Uri`）・`mirror`・転送先・アクセスログはどれも正規化したパスを見る。速さ：すでに正規化されたパスは 1 回なめるだけで `Cow::Borrowed`（割り当てなし、`Uri` もそのまま）。`benches/parse.rs` の `path_normalize`：手元（ほかの作業と共有の機械）で normal が約 70 ns、作り直しが約 750 ns（`matcher/route_table_7` の約 1 µs と同じ程度の機械）。
- `raw_path`（ルールの `http`）：Traefik の `entryPoints.<name>.http.sanitizePath: false` の代わり（URL をパスに埋める転送先など、`//` を残したいとき）。パスでの認証・`ip_allow` と組み合わせると安全でないと文書に書く。Host の正規化と身元のヘッダは `raw_path` でも変わらない。変換ツール（`rproxy-traefik-convert`）は `sanitizePath: false` を `raw_path: true` と注意書きにする。
- Host（`request_host`）：ポートを除き、小文字に、末尾のドットを 1 つ落とす。照合（`Host`・`HostRegexp`）と `tls.misdirected` が使う。転送先へ送る `Host`・`X-Forwarded-Host` はクライアントが送ったまま（決めたこと：転送先の仮想ホストの扱いを変えない。Traefik も送られたまま渡す）。
- 身元のヘッダ（`Router.identity_headers`、`Router::compile` で一度だけ作る）：ルールの `http.middlewares` のすべて（`servers[].middlewares` だけで使うものも）から、`basic_auth` の `user_header`、`oidc` の `IDENTITY_HEADERS`、`forward_auth` の `response_headers`、`*` と gRPC の `forward_auth` はよく使われる名前（oauth2-proxy・Authelia・Authentik）。認証に使う `Authorization`・`Proxy-Authorization`・`Cookie`・`Host` と、どれかの `forward_auth` の `request_headers` の名前は除く（消すと認証が通らない）。`Conn::handle` の最初（ACME・`oidc` のコールバック・照合より前）にどのルートでも消す。空ならなにもしない。
- 接続の時間の上限（`l7::timeouts`）：`HttpGlobal.timeouts`（`main` が `global.http` から入れる。再起動まで効かない）。
  - `tcp.rs` の `handle_http`：TLS のハンドシェイクは `tls_handshake`（L4 の `terminate` は今までの 10 秒のまま）。
  - `server.rs` の `serve`：接続ごとの `Activity`（始まったリクエストの数・処理中の数・最後に終わった時刻）。`service_fn` が `begin` し、応答の本文を包む `Tracked` が終わり（drop）で `Busy` を放す（応答の型を変えるだけで、もう 1 回は箱に入れない）。`Activity::expired` が、最初のリクエストの前は `first_byte`（`Metered` の rx が 0 のまま）と `request_headers`、いつも `idle`（処理中がないまま）を見て、過ぎたら `graceful_shutdown` と 1 秒の猶予の後に閉じる（`conn.close` の `reason`）。HTTP/1.1 の 2 つめからのヘッダは hyper の `header_read_timeout`（= `request_headers`）。HTTP/2 は `keep_alive_interval` / `keep_alive_timeout`（PING。PING に答えるクライアントは `idle` で閉じる）。
  - リクエストの本文：`IdleBody` が、読もうとして待つときだけタイマーを作り（本文のない GET は作らない）、フレームが届くたびに止め、待つあいだに `request_body_idle` が過ぎたら誤りで終える（`deadline::until` と同じく、正常な終わりに見せない）。転送先が読まないあいだ（背圧）は読もうとしないので数えない。
  - HTTP/3（`h3.rs`）：QUIC のハンドシェイクは `tls_handshake`、リクエストのヘッダ（`resolve_request`）は `request_headers`、本文を読むタスクの `recv_data` は `request_body_idle`（過ぎたら `stop_sending` と誤り）、処理中のリクエストのない接続は `idle` で GOAWAY（`h3.accept()` の待ちは接続に状態を持つので、`select!` で手放してよい）。
- レビューで足したこと：
  - `request_body_idle` は応答のヘッダを送った後（`timeouts::Responded`、`serve` と `h3.rs` の `request` が `handle` の後に立てる）と、`content-type: application/grpc…` のリクエスト（`is_grpc`）には効かない。最初のメッセージの後に黙る gRPC の双方向のストリーム（etcd の Watch・xDS）を既定で切らないため（GRPCRoute）。
  - 身元のヘッダは `forward_auth` の `request_headers` でも除かない（消すのはミドルウェアより前の 1 回なので、`oidc` の付けた値は後の `forward_auth` に届く。除くとその名前をルール全体で偽れた）。除くのは `Authorization`・`Proxy-Authorization`・`Cookie`・`Host` だけ。Authentik の `X-Authentik-*`、oauth2-proxy の `X-Auth-Request-Access-Token` を足した。`_` を `-` と読んで同じになる名前も消す（CGI・WSGI）。前の信頼する認証のプロキシの付けた同じ名前も消える（文書に書く）。
  - 転送先の解釈で残る回り込み（`..;/`・`\`・`%5C`・`%2F` を戻す転送先・二重の復号）を文書に書き、`http.strict_path`（既定は無効）で `%2F`・`%5C`・`%3B`・`%25`・`;`・`\` を含むパスを 400 にできるようにした（`normalize::risky`、`features.http_options` の `strict_path`。後の課題にせずここで入れた）。
  - 上限で閉じるとき、処理中のリクエストがあれば終わるまで待つ（`Activity::in_progress`。なければ 1 秒）。
  - アクセスログに `raw_path`（正規化でパスが変わったときだけ、送られたままのパス。検知のルールが `../` を見られるように）。
- 試験：単体（`l7::normalize`・`l7::timeouts`・`config` の `global.http`）、`tests/path_normalize.rs`（`/%61dmin`・`//admin`・`/x/../admin`・`/admin/.` などと末尾のドットの Host を HTTP/1.1・HTTP/2・HTTP/3 で、転送先が受け取るパス、400、`raw_path`、認証のないルートでの身元のヘッダ、何も送らない接続・slowloris・HTTP/2 の前置きだけ、HTTP/2 のアイドル、遅いアップロードが通ることと止まった本文）、`tests/http_semantics.rs`（転送先へのパスとクエリ）、ベンチマーク `path_normalize`。

## 14. API のルールが指せるファイル（v0.4.17、#319）

脆弱性の点検（2026-10-23）の高 A・中 M2・M3：`rules:write` のトークンは、ルールのファイルの項目に rproxy が読めるどのファイルでも書けた（所有者の確認 `net::files` は rproxy のものなら通す）。証明書のストアや ACME の保存先の鍵で TLS を終端でき（`allow_certs`・`acme:write` の回り込み）、`oidc.client_secret_file` に別の秘密（ほかのルールの cookie の秘密、CrowdSec のキー）を書くと、issuer を自由に書けるので自分の token endpoint に送らせられた。

| 項目 | 形 | `features` | 既定 |
|---|---|---|---|
| API のルールのファイルの制限 | 新しい設定はない。誤りの `code`：`403 protected_file`・`403 file_not_allowed`・`409 secret_reuse` | `protected_files` | いつも（設定ファイルのルールは今までどおり） |

- どこで：`control::rule_files::check`（`POST` / `PATCH /rules`・`PUT /rulesets/{name}`、`dry_run` も。`acme_api::check_rule_scope` の後）。ファイルの一覧は `net::protected::refs`：`tls` と `http` を JSON にして、`*_file` の項目をすべて拾う（項目を足しても名前が `_file` で終われば入る。終わらない名前でファイルを指す項目を足すときはここを直す）。
- 守るもの（`net::protected::current`）：証明書のストア（`tls::named::dir`、木）、ACME の保存先（木）と `Acme::protected_files`（DNS のプロバイダの秘密・EAB・`storage` の外のアカウントの鍵。CA のファイルは除く：ルールの CA と同じものを使ってよい）、CrowdSec のキー（`Bouncer::key_file`）、オプションの `RPROXY_TOKEN_FILE`・`RPROXY_TLS_KEY`（`set_process`、`main` が `--check-config` の前にも入れる）。
  - 決めたこと：秘密のファイルはディレクトリではなくそのファイルだけ。既定の `/etc/rproxy` にトークンのファイルと `users_file`・証明書が並び、ディレクトリで断ると今の使い方が動かなくなる。
- 比べ方（`resolve`）：`O_PATH` で開く（読む権限は要らない、FIFO で止まらない）→ `/proc/self/fd` の本当のパスと（デバイス, inode）。木は本当のパスの前方一致（要素ごと）、ファイルは inode（開けなければパス）。開けないパスは、ある親までの本当のパスに残りを `..` を除いて足したもの（後で保存される `<store>/<name>/current/tls.key` も今断る）。ファイルを読む時（`net::files::read`）には比べない：API は文字列しか渡せず、リンクを作れないので、確かめた後に行き先が変わるのは管理者がディスクを変えたときだけ。
- `allow_certs` のあるトークンはファイルを書けない（`Principal::limited_to_stored_certs`）：ストアの外の鍵でも、名前の制限を回り込む道になるため。
- OIDC（M2）：`net::protected::secret_conflicts`。client secret のファイルは、同じ（issuer, client_id）の client secret としてだけ使える。比べる相手は動いているすべてのルール（`Registry::file_refs`。PATCH は置き換える部分（`tls` / `http`）、組の PUT はその組のルールを除く）と、同じ変更の中のルール。今あるルールどうしの重なりは、その変更の誤りにしない。
- M4（cookie の秘密を使い回したときに別のルールのセッションが通る）：セッションと state の cookie の AES-256-GCM の関連データを cookie の名前・issuer・client_id にした（`oidc::Oidc::aad`）。今のセッションは上げたときに一度だけ無効になる（受け入れた：古い形を受け付けると回り込みが残る）。
- 設定ファイルのルール：断らない（ホストの管理者のもの）。`--check-config` が同じ判定を警告にする（`check.rs`）。DB・組の保存から戻すルール、引き継ぎで渡すルールも断らない（前の版で受け付けたもの。次の変更で確かめる）。
- 試験：単体（`net::protected`：木・ファイル・リンク・`..`・ハードリンク・まだないパス、項目の拾い方、client secret の使い道。`oidc`：別の issuer・client の cookie は開かない）、`tests/cert_api.rs`（`rule_files_may_not_reach_the_store`：ストアのファイル・リンク・`..`・後で保存されるもの、dry run・PATCH・組の PUT・サービスの `ca_file`、トークンのファイル、ほかの場所はよい、`allow_certs`、設定ファイルのルールは動く）、`tests/acme.rs`（`rules_may_not_name_acme_files`）、`tests/crowdsec.rs`（`rules_may_not_name_the_key_file`）、`tests/http_auth.rs`（`oidc_client_secrets_keep_to_one_use`）、`tests/check_config.rs`（`files_the_api_may_not_name_are_warnings`）。
- レビューで足したもの：カーネルのファイルシステム（`/proc`・`/sys`・`/dev`、`statfs` の種類）を断る（`/proc/self/environ` の環境変数・`/proc/self/fd/N`）。木は（デバイス, inode）でも比べる（bind mount）。戻したルールは `Registry::warn_protected` が `rule.protected_file` を出す（`restore_as`・組の復元・引き継ぎの組）。PATCH は `Registry::updated_spec` で出来上がるルール全体を確かめる。確かめは 1 つずつ（`CHECKS`）で、通った変更のファイルは `Intent` として変更が終わるまで後の確かめに数える（変更の名前解決の間は誰も待たせない。ファイルのない変更は何も取らない）。`net::files::read` も開いた fd がカーネルのファイルシステムなら断る（後の読み直しを `/proc` へ向けられない）。ファイルを見るのは `spawn_blocking`、`Registry::file_refs` はロックの下では写すだけ。`409 secret_reuse` の文にほかのルールのことは出さない。`PUT /rulesets` の断りも監査に残す。`RPROXY_DIFF_TOKEN_FILE` も守る。
- 残したもの：ほかのテナントのルールの鍵のファイル（守るファイルではないもの）を別のトークンが指せること（#323、15. で扱った）。

## 15. ほかの持ち主の鍵・秘密のファイル・戻すときに検証で落ちたルール（v0.4.18、#323・#327）

| 項目 | 形 | `features` | 既定 |
|---|---|---|---|
| ほかの持ち主の鍵・秘密のファイル（#323） | 新しい設定はない。誤りの `code`：`409 file_in_use` | `file_owners` | いつも（`admin` のトークンと設定ファイルのルールは今までどおり） |
| 戻すときに検証で落ちたルール（#327） | `GET /rules` の `state: failed`・`error`（形は今までの `failed` のルールと同じ）、`conditions` の `Accepted` が `False`（`Invalid`） | `invalid_restored` | いつも（前はログだけ） |

- #323 の持ち主（`net::protected::Owner`、`Registry::owner_of`）：設定ファイルのルールは `Static`、組のルールは組の持ち主（`Rulesets::owner`）、API で作ったルールは作ったトークン（`Registry.owners`。`create_by` が入れ、`take` で消す。`api` のルールで覚えていなければ `persist::Store::created_by`）、それ以外（`forward_rules` から戻したもの）は `Restored`（どのトークンとも違う）。PATCH で持ち主は変えない（作ったトークンのまま）。
- 比べるもの：`FileRef::is_secret`（`key_file` で終わる項目・`secret_file` で終わる項目・`users_file`）。証明書・チェーン・CA は公開のものなので比べない（`ca-certificates.crt` を全員が使えるように）。同じかは `Resolved::same`（inode。開けなければパス）。
- どこで：`rule_files::check` の `judge` → `owners`。守るファイルの確かめの後、`secret_conflicts` の前。`admin` のスコープ（`Principal::has(Admin)`、トークンファイルがないときも）は飛ばす。`PENDING` の `Intent` も変更のトークンを持つ。
- 決めたこと：PATCH・組の PUT は、置き換えるルールが今指すファイル（`Replacing` で外したルールのファイル）を比べない。宛先だけの PATCH が、前からの共有で断られないように（ポートの制限がそのルールの境界で、ファイルを新しく足すときだけ手が広がる）。
- 誤りの文は相手のことを出さない（キー・持ち主・項目）。前の版で作られた共有は断らず、`Registry::warn_shared_files`（`restore_as`・組の復元・引き継ぎの後）が組み合わせごとに 1 回 `rule.shared_file`。
- 引き継ぎ：状態に `owners`（足すだけ）。再起動では `dynamic` のルールの持ち主は残らない（`forward_rules` に列がない）。
- #327：`Registry.invalid`（キー → `Invalid { request, origin, error }`）。`Entry` には入れない（`RuleSpec` がないので、`Entry::spec` を使うところを変えずに済むように。待ち受けもポートも持たない）。`list`・`get` が `RuleView::invalid`（本文から作る）で出し、`create_spec`・`check_start` は同じキーを `409 already_exists`（`refuse_invalid_key`）、`take`（`DELETE`）は消すだけ、`update`（`PATCH`）は `rule::patched_request` で本文に重ねて `fix_invalid`（検証に通らなければ何も変えない。通れば `create_spec_in(.., fixing)` が表に入れるときに消す）。`insert_failed` はそのキーを失敗したルールのものにする。
- 戻す道：`restore_as` の検証の誤り → `note_invalid`（`listen_addr` が読めなければログだけ。キーが取られていれば `rule.duplicate`）。照合は `api` の行が変われば `forget_invalid` してもう一度、行がなくなれば消す。引き継ぎは状態の `invalid_rules`（保存されていたままの本文、足すだけ）を渡し、新しいプロセスが `restore_as` でもう一度検証する（`rules` には入れない：表示の形から戻すと既定で埋めた項目が変わるため）。
- レビューで足したもの：検証で落ちたルールのファイルも `Registry::file_refs` に入れる（持ち主は `owner_of_key`。直す PATCH は、そのルールを PATCH できるトークンならどれでも `kept` にする。動いているルールと同じ）。消す・行がなくなる・変わる・組に譲るときは `drop_invalid` が持ち主も忘れ、`forget_invalid` は照合の `Store.invalid` も消す（同じ行が戻れば出し直す）。持ち主は `create_spec_in` が表に入れるときに覚える（同じトークンの同時の作成が `409` にならないように）。戻す組のルールと同じキーは、組を当てる間だけ外し（`stash_invalid`）、組がそのキーを取ったものだけ消して `restore.conflict`（持ち主と行の `created_by` も忘れる）、ほかは戻す（`settle_invalid`）。組の `PUT` の計画は、検証で落ちたルールのキーも組の外のルールと同じく先に断る。`/metrics` の `failed` と `rproxy_rule_up 0` に数える。
- 試験：`tests/cert_api.rs`（`key_files_keep_to_their_owner`）、`tests/persist.rs`（`invalid_rules_keep_their_files_and_count`・`rows_that_do_not_validate_are_failed_rules`：メモリのストア、`rows_that_do_not_validate_with_mariadb`：本物のバイナリと MariaDB）、`tests/handoff_freeze.rs`（`invalid_rules_and_owners_carry_over`）。

## 16. 応答のキャッシュ（v0.4.19、#340）

| 項目 | 形 | `features` | 既定 |
|---|---|---|---|
| 応答のキャッシュ | ミドルウェア `cache`（`ttl` は必須。`stale_on_error`・`max_body`・`max_entries`・`max_memory`・`vary`・`status`・`share_credentials`・`share_after_auth`・`header`）。`stats.http.cache`・`rproxy_http_cache_*`・アクセスログの `cache` | `middlewares` の `cache` | 書いたルートだけ |

- 置き場所：`l7/middleware/cache.rs`。状態（`Store`：キー → `Slot { entry, flight }`、古い順の `order`、バイト数）は組み立てた `Router` のミドルウェアにあり、`http` を変えると空から（`rate_limit` と同じ。引き継ぎでも渡さない。数だけ `HttpCounters.cache` で渡す、足すだけ）。
- 道筋：`server.rs` の要求側で `Cache::request` がメモリから答える（`HIT`。後ろのミドルウェアは動かず、前のものの応答側は動く）か、`Pending` を `Sent.caches` に入れて先へ進む。応答側の `Cache::response` が持つかを決める。まとめ方は `tokio::sync::watch`：持っていないキーの最初のリクエストが `Lead`（`Slot.flight`）になり、同じキーのほかは待つ。`Lead` が答えを持てば `Fresh`、古い答えを返せば `Stale`、持てなければ `Uncacheable`（待っていたものはそれぞれ転送先へ。並ばせない）、drop（クライアントが切れた）なら `Abandoned`（待っていたものがもう一度見て、1 つが代わりに行く。3 回まで）。
- 決めたこと：
  - 持たないもの：GET・HEAD 以外、`Authorization`・`Cookie`・`Proxy-Authorization`（`share_credentials` で持つ）、`Range`・`Upgrade`・本文のあるリクエスト。`status` にない状態コード（選べるのは RFC 9110 §15.1 の既定でキャッシュできるもののうち 200・203・204・300・301・308・404・410）、`Set-Cookie`・`Cache-Control` の `no-store`・`private`・`no-cache`・`Vary: *`・`Content-Range`・`max_body` を超える本文・トレーラー・途中で切れた本文の応答。
  - 時間は `ttl` だけ（転送先の `max-age` などは見ない。運用で決めた短い時間を守るため）。クライアントの `Cache-Control` も見ない（だれでも転送先へ毎回送らせられないように）。
  - 認証：ルートで `cache` の後ろに通すかを決める種類（`GATES`：`ip_allow`・`geoip`・`crowdsec`・`basic_auth`・`forward_auth`・`oidc`）を置けない、前の利用者を確かめる種類（`SIGN_IN`）は `share_after_auth` が要る、ルートのサービスの転送先の `forward_auth` は断る（`HttpSpec::check_cache_route`）。キャッシュは利用者を区別しないので、利用者ごとに違う答えを別の利用者に見せないことを形で守る。
  - `Vary`：応答の `Vary` の名前（`Content-Encoding` があれば `Accept-Encoding` も）と答えたリクエストの値を持ち、合わないリクエストには使わない。キーごとに 1 つだけ持つ（値の多いヘッダは `vary` でキーを分ける）。
  - `max_memory`（既定 64 MiB）は issue になかったが足した：既定の `max_entries`（1024）× `max_body`（1 MiB）が 1 GiB になり、メモリを少なくする方針に合わないため。
  - 古いものから捨てる：`ttl` はミドルウェアごとに同じなので、入れた順が期限の順。入れるたびに `stale_on_error` まで過ぎたものを先頭から捨て、超えた分も先頭から。
  - 条件つきのリクエスト：先に行くリクエストからは `If-None-Match`・`If-Modified-Since` を外して全体を取り、`If-None-Match` だけ rproxy が 304 で答える。
- レビューで足したもの（#343）：
  - キーにルートの名前（同じミドルウェアを書いたルートどうしで答えを混ぜない。`Header` で分けたベータ版のルート、`ip_allow` の後ろのルート）、受けた方式とポート、`tls.client_auth` のルールではクライアント証明書（`X-Client-Verify` と `X-Forwarded-Client-Cert` の中身）を入れる（`cache::Ask`）。証明書を出したリクエストは資格情報（`share_credentials` なしは `BYPASS`）。
  - HTTP/2・HTTP/3 で `Content-Length` なしに DATA フレームを送る GET：`cache::settle` が本文を 1 秒まで見て（読んだものは戻す）、あれば `BYPASS`。
  - 認証のミドルウェアが応答に付けるもの（`oidc` の `Set-Cookie`、gRPC の `forward_auth` の `response_headers_to_add`）は、そのミドルウェアの応答側（チェーンの位置ごと）で付ける。前は応答側の前に全部付けていたので、後ろのキャッシュが持って別の利用者に返していた。後ろのミドルウェアの応答側はもうこれを見ない（`headers` の `remove` で消すなら前に置く）。
  - `cors`（と `headers` の `cors`）は許さないオリジンにも `Vary: Origin`（後ろのキャッシュが許さないオリジンへの答えを許したオリジンに返さないように）。
  - 持てない答えのキーは `ttl` のあいだ並ばせない（`Store.passes`、`max_entries` まで）。古い答えのない 5xx は待っていたものに渡す（`Done::Error`）。待つのは `WAIT_LIMIT`（10 秒）まで、本文を読むのは `COLLECT_LIMIT`（5 秒）まで、`text/event-stream` は持たない。
  - 落ちている間：`Slot.failed` から `ttl` は転送先へ行かずに `STALE`、その後は 1 つが試し、ほかはすぐ `STALE`。
  - `header` にホップごと・本文の形・キャッシュのヘッダを使わせない。`MISS` は転送先の `Age` を残す。`/metrics` の数は期限を過ぎたものを捨ててから。If-None-Match は引用符の中の `,` を読む。`Accept-Encoding` は符号化の名前の組で比べる。`oidc` の後ろで `share_credentials` のない `cache` は `--check-config` の警告（`HttpSpec::warnings`）。
  - 単体テストは止めた時計（`tokio::time::pause`、`Instant` は `tokio::time::Instant`）で時間を進める。
- 測るもの：`benches/dataplane.rs` の `l7_cache/hit`（PR の `Benchmarks` が比べる。最初に 1 回埋めて、測るものはすべて `HIT` を確かめる）。
- 試験：`tests/http_cache.rs`、`src/l7/middleware/cache.rs` の単体テスト。
