# 権限

rproxy-api は root やネットワークの強い権限を持つホストで動かす前提にしている。
ホストの設定（パッケージのインストール、ポリシールーティング）は root で行う。rproxy-api 本体は `rproxy` ユーザーで動き、必要な capability だけを systemd から受け取る。

## rproxy-api プロセスの権限

| capability | 使う機能 | なくした場合 |
|---|---|---|
| `CAP_NET_BIND_SERVICE` | 1024 未満のポート（25、443 など）で待ち受ける | 1024 未満のルールだけが使えない。API での作成は `bind_failed`（理由と必要な権限つき）、起動時に復元するルールと固定ルールは `failed` として残る |
| `CAP_NET_ADMIN` | `source_ip: transparent`（`IP_TRANSPARENT` でクライアントの IP を名乗って接続する） | `GET /capabilities` の `transparent` が false になり、UI の選択肢から消える（理由を表示する）。API での作成は `unsupported`。DB から復元する transparent のルールと固定ルールは `failed`（`needs Linux and CAP_NET_ADMIN`）として残る |

どちらの権限を外しても rproxy-api は起動し、ほかのルールはそのまま動く（CI の `install.sh` ジョブで、drop-in で両方を外した状態を確かめている）。固定ルールのファイルで起動を止めるのは書き方の誤り（アドレスが不正、ルール同士の重なりなど）だけで、権限が足りないだけのルールでは止めない。

- どちらもユニット（`/usr/lib/systemd/system/rproxy-api.service`、install.sh のバイナリなら `/etc/systemd/system/`）の `AmbientCapabilities` と `CapabilityBoundingSet` で与えている。ほかの capability は持たない。
- 使わない権限は `systemctl edit rproxy-api` で外せる。install.sh を実行し直しても、外した権限は戻さない。
  ```ini
  [Service]
  # transparent を使わない
  AmbientCapabilities=
  AmbientCapabilities=CAP_NET_BIND_SERVICE
  CapabilityBoundingSet=~CAP_NET_ADMIN
  ```
- ユニットは `NoNewPrivileges=yes` なので、バイナリに `setcap` で付けた権限は効かない。権限はユニットで与える。
- 手で起動する場合（systemd を使わない場合）は、root で動かすか `setcap cap_net_bind_service,cap_net_admin+ep` をバイナリに付ける。

### systemd のサンドボックス

| 設定 | 影響 |
|---|---|
| `ProtectSystem=strict` | `/usr`・`/etc` などは読み取りだけ。書けるのは `/var/log/rproxy`（`LogsDirectory`）だけ |
| `ProtectHome=yes` | `/home`・`/root` が見えない。証明書・鍵・固定ルールのファイルをここに置くと読めない |
| `PrivateTmp=yes` | `/tmp` はサービス専用。ホストの `/tmp` のファイルは見えない |
| `LimitNOFILE=65536` | ポート範囲のルールは 1 ポートに 1 つのソケットを使う（起動時に上限まで引き上げる） |

## ホスト側の設定（root）

| 作業 | 方法 |
|---|---|
| インストール・アンインストール | `apt`、または `scripts/install.sh`（root で実行） |
| transparent の戻りのパケットのポリシールーティング | `install.sh --transparent-clients <CIDR> --transparent-iface <IF>`。`rproxy-transparent-routing.service` が起動時に `ip rule` / `ip route`（テーブル 100）を設定する。設定は `/etc/rproxy/transparent-routing.conf` |
| 転送先の戻りの経路 | 転送先のデフォルトゲートウェイを rproxy のホストにする（または転送先でクライアント宛ての経路を rproxy に向ける）。転送先側の作業なので install.sh の対象外 |

## ファイル

| パス | 所有者・モード | 中身と注意 |
|---|---|---|
| `/etc/rproxy/` | `root:rproxy` 750 | 設定の置き場所。rproxy ユーザーは読むだけ |
| `/etc/rproxy/rproxy.env` | `root:root` 640 | 設定。DB のパスワードを含みうる。systemd（root）が読んで環境変数として渡すので、rproxy ユーザーが読める必要はない |
| `/etc/rproxy/tokens` | `root:rproxy` 640 | 制御 API のトークン（1 行に 1 つ、またはスコープ付きの YAML）。変えたら `systemctl reload rproxy-api` |
| 証明書・秘密鍵（`tls` の `cert_file` / `key_file` / `ca_file` / `chain_file`） | 例 `root:rproxy` 640 | rproxy ユーザーが読めること。`/home`・`/root`・`/tmp` 以外に置く（`/etc/rproxy/tls/` など） |
| CrowdSec の API キー（`global.crowdsec.api_key_file`、例 `/etc/rproxy/crowdsec.key`） | `root:rproxy` 640 | `cscli bouncers add rproxy` で作ったキー。rproxy ユーザーが読めること。変えたら `systemctl reload rproxy-api` |
| 固定ルール（`RPROXY_STATIC_RULES`） | 例 `root:rproxy` 640 | 同上。install.sh は rproxy ユーザーが読めるかを確かめる |
| `/run/rproxy/api.sock`（`RPROXY_API_SOCKET`） | `rproxy:<RPROXY_API_SOCKET_GROUP>` 660（既定） | 制御 API の Unix ソケット。接続できるのは所有者とグループだけ。ユニットの `RuntimeDirectory=rproxy` が `/run/rproxy` を作る（systemd を使わないときは自分で作る） |
| `/etc/rproxy/transparent-routing.conf` | `root:root` 644 | transparent 用のポリシールーティングの設定 |
| `/var/log/rproxy/` | `rproxy:rproxy` 750 | ログ。クライアントの IP、SNI、クライアント証明書の CN を含むので、閲覧できる人を絞る |

## 制御 API

- Unix ソケット（`RPROXY_API_SOCKET`）を使うと、ファイルのモードとグループで接続できる利用者を絞れる（loopback の TCP は同じホストの誰でも接続できる）。`RPROXY_API_PORT=0` で TCP を閉じられる。
- 既定の待ち受けは `127.0.0.1`。loopback 以外で待ち受けるには、トークンファイルと TLS 証明書の両方が必須（どちらかがなければ起動しない）。
- 1 行に 1 つ書いたトークンは全権限。YAML の書き方では、トークンごとにスコープ（`rules:read` / `rules:write` / `metrics:read` / `admin`）・変更できる待ち受けポート・有効期限を決められ、ファイルには SHA-256 だけを置く（docs/API.md）。変更は `event: "audit"` のログに残る。
- 複数のトークンを同時に有効にできるので、新しいトークンを足して reload し、UI を切り替えてから古いトークンを消せば止めずに入れ替えられる。

## DB（MariaDB）

| ユーザー | 権限 | 用途 |
|---|---|---|
| rproxy-api 用（例 `rproxy`） | `SELECT ON forward_rules` | 起動時にルールを復元する（書き込まない） |
| UI 用（例 `rproxy_ui`） | `SELECT, INSERT, UPDATE, DELETE ON forward_rules`、`SELECT, INSERT ON forward_rules_log` | ルールの管理と変更履歴 |

GRANT の例は UI リポジトリの `db/README.md`。

## UI（TCP-UDP-rproxy-ui）

- Keycloak でサインインした利用者だけが使える。ルールは利用者（Keycloak の `sub`）ごとに持ち、ほかの利用者のルールは見えない。固定ルールはサインインしていればだれでも見える（変更はできない）。
- ロールによる権限の分け方（閲覧だけ、など）は UI の #4 で検討している。
- UI サーバは `RPROXY_API_TOKEN`（rproxy のトークン）と DB のパスワードを持つ。`.env.local` は 600 にする。

## GitHub（開発・配布）

| もの | 置き場所 | 注意 |
|---|---|---|
| apt リポジトリの署名鍵 | Actions の Secrets（`APT_GPG_PRIVATE_KEY` / `APT_GPG_KEY_ID`） | パスフレーズなし。予備はオフラインで保管する（docs/APT.md） |
| main / master | ルールセット | PR 経由でだけ変更でき、CI の必須チェックが通るまでマージできない。force push と削除は禁止 |
| `v*` タグ | ルールセット | 削除と付け替えは禁止（公開したバージョンの中身を変えない） |
