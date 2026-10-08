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
- HTTP：`drain` に入ったら keep-alive の接続に `Connection: close`（HTTP/2 は GOAWAY、HTTP/3 は QUIC の GOAWAY）を返し、終わったリクエストから閉じる（hyper の `graceful_shutdown`。引き継ぎと同じ）。
- UDP：`delay` の間は今のまま。`drain` に入ったら新しいセッションを作らず、今のセッションは `drain` の終わりまで続ける（kube-proxy は外れた宛先の UDP の conntrack を消すので、多くは新しい Pod へ移る）。
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

（実装の PR で足す）
