English: [PERMISSIONS.md](en/PERMISSIONS.md)

# 権限

rproxy-api は root やネットワークの強い権限を持つホストで動かす前提にしている。
ホストの設定（パッケージのインストール、ポリシールーティング）は root で行う。rproxy-api 本体は `rproxy-api` ユーザー（主グループ `rproxy`）で動き、必要な capability だけを systemd から受け取る。v0.3 までのユーザー `rproxy` は、v0.4 の .deb・install.sh が uid を変えずに `rproxy-api` に改名する（ファイルの所有者はそのまま）。UI（`rproxy-ui` ユーザー）を `rproxy` グループに入れると、グループの読み取りでファイルを共有できる。

## rproxy-api プロセスの権限

| capability | 使う機能 | なくした場合 |
|---|---|---|
| `CAP_NET_BIND_SERVICE` | 1024 未満のポート（25、443 など）で待ち受ける | 1024 未満のルールだけが使えない。API での作成は `bind_failed`（理由と必要な権限つき）、起動時に復元するルールと固定ルールは `failed` として残る |
| `CAP_NET_ADMIN` | `source_ip: transparent`（`IP_TRANSPARENT` でクライアントの IP を名乗って接続する） | `GET /capabilities` の `transparent` が false になり、UI の選択肢から消える（理由を表示する）。API での作成は `unsupported`。DB から復元する transparent のルールと固定ルールは `failed`（`needs Linux and CAP_NET_ADMIN`）として残る。`global.performance.busy_poll_usecs` を `net.core.busy_read` より大きくするのにも使う（なければ `degraded` を出して busy poll なしで動く） |

カーネルでの転送（`global.performance.xdp`、#260。既定は off）を使うときだけ、さらに `CAP_BPF`（5.8 より前のカーネルは `CAP_SYS_ADMIN`）と `CAP_NET_ADMIN`、AF_XDP には `CAP_NET_RAW` が要る。ユニットは既定ではこれらを与えないので、使うときに `systemctl edit rproxy-api` で `AmbientCapabilities` と `CapabilityBoundingSet` に足す。足りなければ起動時の試験に通らず、`degraded`（`reason: missing CAP_BPF ...`）を出して今の処理で動く。`rproxy-api --check-kernel` で事前に確かめられる。

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
| `ProtectSystem=strict` | `/usr`・`/etc` などは読み取りだけ。書けるのは `/var/log/rproxy`（`LogsDirectory`）と `/var/lib/rproxy`（`StateDirectory`。ACME の保存場所）だけ |
| `ProtectHome=yes` | `/home`・`/root` が見えない。証明書・鍵・固定ルールのファイルをここに置くと読めない |
| `PrivateTmp=yes` | `/tmp` はサービス専用。ホストの `/tmp` のファイルは見えない |
| `LimitNOFILE=65536` | ポート範囲のルールは 1 ポートに 1 つのソケットを使う（起動時に上限まで引き上げる） |
| `Type=notify`・`NotifyAccess=all`・`RuntimeDirectory=rproxy` | 再起動なしの更新（#174、docs/UPGRADE.md）：古いプロセスが `/run/rproxy/handoff.sock`（0600、起動した子の pid だけ受け付ける）でソケットを渡し、`MAINPID=` で新しいプロセスを主にする。新しいプロセスは同じユニットの中で動き、同じ権限（ambient の capability）を持つ |

### ACME の補助プロセス（`rproxy-acme-helper.service`、任意）

`global.acme.helper` を使うとき（docs/ACME.md の「補助プロセス」）。DNS のプロバイダの秘密はこのプロセスだけが読みます。

| 項目 | 値 |
|---|---|
| ユーザー | `rproxy-acme`（.deb の postinst が作る）。補助のグループ `rproxy`（設定ファイルを読み、ソケットのグループにする。本体の `rproxy-api` の主グループ） |
| capability | なし（`CapabilityBoundingSet=` は空） |
| ソケット | `/run/rproxy-acme/helper.sock`（`rproxy-acme:rproxy` 660。`RuntimeDirectory=rproxy-acme`）。`--allow-user rproxy-api` で相手のユーザーも確かめる |
| 秘密のファイル | 例 `/etc/rproxy/acme-helper/`（`root:rproxy-acme` 750、ファイルは 640）。rproxy-api ユーザーには読めない |
| 書くもの | `/var/lib/rproxy-acme/`（`StateDirectory`、700）：acme-dns の `credentials_file` |

### ルールが指すファイルの所有者（v0.4、オーナーの決定）

ルール（API・ルールの組・設定ファイル）と `global` が指すファイル（証明書・鍵・CA・チェーン、サービスの `tls`、`client_auth.ca_file`、`basic_auth` の `users_file`、`oidc` の秘密、`global.crowdsec.api_key_file`、ACME の秘密）は、次を満たすものだけ使う（`global.files.owner_check: strict`、既定）。`rules:write` のトークンで、ほかのサービスの鍵や root のファイルを rproxy に読ませる（使う・在るかを探る）ことを防ぐ。

- 所有者が rproxy のプロセスのユーザー（`rproxy-api`）。シンボリックリンクは先のファイルで確かめ、リンク自体の所有者も rproxy-api か root。
- グループ・ほかの人が書けない（`g-w,o-w`）。
- 鍵・秘密はほかの人が読めない（600 か 640。グループ `rproxy` の読み取りはよい：UI と共有するとき）。証明書・CA は 644 まで。
- 満たさなければ API は `400 tls_config` / `invalid`（理由つき）、設定ファイルは設定の誤り（起動・再読み込みで止まる）。`--check-config` は、サービスのユーザーで動かせば誤り、ほかのユーザー（root）で動かせば rproxy-api について確かめた警告。確かめるのは開いたファイル（fstat）なので、確かめたものを読む。
- certbot などが root のファイルを作るなら、deploy hook で rproxy-api のものに写す（例：`install -o rproxy-api -g rproxy -m 0640 privkey.pem /etc/rproxy/tls/a.key`）。どうしても root のファイルをそのまま使うなら `global.files.owner_check: off`（`rules:write` のトークンを持つ人が、rproxy の読めるどのファイルでも証明書・鍵として使えるようになる。起動時に `degraded` を出す）。
- 信頼するディレクトリ（`global.files.trusted_dirs`、なければ環境変数 `RPROXY_FILES_TRUSTED_DIRS`。`:` か `,` 区切りの絶対パス、既定はなし）：開いたファイルの本当のパス（シンボリックリンクをすべてたどった先。`..` で外へは出られない）がその下にあれば、root のものも使う。Kubernetes の Secret のボリューム（root の持ち物、グループは fsGroup、0440、root の `..data` のリンク）のためで、rproxy-gateway は `RPROXY_FILES_TRUSTED_DIRS=/var/run/rproxy-gateway/certs` を渡す。ほかの確かめ（グループ・ほかの人が書けない、鍵はほかの人が読めない（0440 は通る）、リンクは rproxy か root のもの）はそのまま。root 以外のユーザーのファイルは、その下でも使わない。起動時に `files.trusted_dirs` のログに出す。`--check-config` も同じものを使う。そのディレクトリに root が置いたファイルは `rules:write` のトークンから鍵として使えるので、ほかの用途のファイルを置かない。
- 制御 API の証明書・トークンのファイル（`RPROXY_TLS_*`、`RPROXY_TOKEN_FILE`）・GeoIP のデータベースは対象外（ルールからは指せない）。

### ルールの宛先

`rules:write`（と `PUT /rulesets`）のトークンは、ルールの宛先（`remote_addr`・`targets`・サービスの `url`・`forward_auth` の `address`・`mirror` の先のサービス）をどこにでも向けられる。rproxy は宛先を絞らないので、内側のネットワーク（メタデータの IP・管理用のサービス）に向けられたくないときは、トークンを分けて渡す相手を絞り、rproxy のホストの出口（egress のファイアウォール）で絞る。

## ホスト側の設定（root）

| 作業 | 方法 |
|---|---|
| インストール・アンインストール | `apt`、または `scripts/install.sh`（root で実行） |
| transparent の戻りのパケットのポリシールーティング | `install.sh --transparent-clients <CIDR> --transparent-iface <IF>`。`rproxy-transparent-routing.service` が起動時に `ip rule` / `ip route`（テーブル 100）を設定する。設定は `/etc/rproxy/transparent-routing.conf` |
| 転送先の戻りの経路 | 転送先のデフォルトゲートウェイを rproxy のホストにする（または転送先でクライアント宛ての経路を rproxy に向ける）。転送先側の作業なので install.sh の対象外 |

## ファイル

| パス | 所有者・モード | 中身と注意 |
|---|---|---|
| `/etc/rproxy/` | `root:rproxy` 750 | 設定の置き場所。rproxy-api ユーザーは読むだけ |
| `/etc/rproxy/rproxy.env` | `root:root` 640 | 設定。DB のパスワードを含みうる。systemd（root）が読んで環境変数として渡すので、rproxy-api ユーザーが読める必要はない |
| `/etc/rproxy/tokens` | `root:rproxy` 640 | 制御 API のトークン（1 行に 1 つ、またはスコープ付きの YAML）。変えたら `systemctl reload rproxy-api` |
| 証明書・秘密鍵（`tls` の `cert_file` / `key_file` / `ca_file` / `chain_file`、サービスの `tls`） | `rproxy-api:rproxy`、鍵は 600 か 640・証明書は 644 まで | **rproxy-api ユーザーのものだけ使う**（下の「ルールが指すファイルの所有者」）。`/home`・`/root`・`/tmp` 以外に置く（`/etc/rproxy/tls/` など） |
| CrowdSec の API キー（`global.crowdsec.api_key_file`、例 `/etc/rproxy/crowdsec.key`） | `rproxy-api:rproxy` 640 | `cscli bouncers add rproxy` で作ったキー。rproxy-api ユーザーのもの（所有者の確認）。変えたら `systemctl reload rproxy-api` |
| 認証のミドルウェアの秘密（`basic_auth` の `users_file`、`oidc` の `client_secret_file` / `cookie_secret_file`。例 `/etc/rproxy/auth/`） | `rproxy-api:rproxy` 640（ディレクトリは 750） | rproxy-api ユーザーのもの（所有者の確認）。ほかの利用者に読ませない（`cookie_secret_file` が漏れるとセッションのクッキーを作れる、`client_secret_file` はプロバイダのクライアントの秘密）。読めないとそのミドルウェアは 503 を返す。変えると数秒以内に読み直す（SIGHUP でもすぐ）。`cookie_secret_file` を変えるとすべてのサインインが切れる |
| 固定ルール（`RPROXY_STATIC_RULES`） | 例 `root:rproxy` 640 | 同上。install.sh は rproxy-api ユーザーが読めるかを確かめる |
| `/run/rproxy/api.sock`（`RPROXY_API_SOCKET`） | `rproxy-api:<RPROXY_API_SOCKET_GROUP>` 660（既定） | 制御 API の Unix ソケット。接続できるのは所有者とグループだけ。ユニットの `RuntimeDirectory=rproxy` が `/run/rproxy` を作る（systemd を使わないときは自分で作る） |
| `/run/rproxy/handoff.sock`（`--handoff-socket` / `RPROXY_HANDOFF_SOCKET`、#174） | `rproxy-api` 600（SEQPACKET） | 再起動なしの更新の間だけある引き継ぎ用のソケット。つなげるのは古いプロセスが起動した子（pid で確かめる）だけで、子の側も相手が自分の親で同じユーザーか、ソケットのディレクトリをほかのユーザーが書けないかを確かめる。親のディレクトリ（`/run/rproxy`）がないと引き継ぎは `handoff.failed` になり、古いプロセスが動き続ける（docs/UPGRADE.md） |
| 制御 API のクライアントの CA（`--tls-client-ca` / `RPROXY_TLS_CLIENT_CA`、#167） | 例 `root:rproxy` 640 | mTLS でクライアント証明書を確かめる CA（PEM）。秘密ではないが、書き換えられると証明書の認証を通せるので rproxy-api ユーザーには書かせない。制御 API の証明書・鍵（`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`）と同じく SIGHUP とファイルの変化で読み直す |
| GeoIP のデータベース（`global.geoip` の `country_db` / `asn_db`、#168） | 例 `root:rproxy` 640 | rproxy-api ユーザーが読めること（読めなければ `degraded` で起動し、読めるまで国・ASN は「分からない」）。更新のツール（`geoipupdate` など）は置き換え（rename）で書く。`check_interval` と SIGHUP で読み直す |
| `/etc/rproxy/transparent-routing.conf` | `root:root` 644 | transparent 用のポリシールーティングの設定 |
| `/var/lib/rproxy/`（`global.acme.storage` の既定 `/var/lib/rproxy/acme`） | `rproxy-api:rproxy` 750（`acme/` の下はディレクトリ 700・ファイル 600） | ACME のアカウントの鍵（`accounts/<名前>.key`）、取った証明書と鍵（`certs/`）、消していない DNS-01 の TXT の記録（`dns-pending.json`）。ユニットの `StateDirectory=rproxy` が作る。アカウントの鍵が漏れると、そのアカウントで証明書の失効・注文ができる。purge で消える（docs/ACME.md） |
| `/var/lib/rproxy/certs/`（`RPROXY_CERT_STORE` の既定、v0.4.2） | `rproxy-api` のもの。ディレクトリ 700・ファイル 600 | `PUT /certs/{name}` で受け取った証明書と鍵（#240。rproxy が自分で書く） |
| ACME の DNS のプロバイダの秘密（`global.acme.dns_providers` の `api_key_file` / `secret_file` / `tsig_secret_file` / `credentials_file`（acme-dns。rproxy が書く）、EAB の `hmac_key_file`。例 `/etc/rproxy/acme/`） | `rproxy-api:rproxy` 640（ディレクトリは 750） | rproxy-api ユーザーのもの（所有者の確認。補助プロセスを使うときは `rproxy-acme` のもの）。ほかの利用者に読ませない（DNS のレコードを書き換えられる。`_acme-challenge` を専用のゾーンに委任し、そのゾーンだけに書ける鍵にすると被害を狭められる）。API からは読めない |
| `/var/log/rproxy/` | `rproxy-api:rproxy` 750 | ログ。クライアントの IP、SNI、クライアント証明書の CN を含むので、閲覧できる人を絞る |
| 自動更新のキャッシュ（`RPROXY_UPDATE_CACHE`、既定 `/var/cache/rproxy/update`、#174。コンテナの `rproxy-api launch` だけ） | サーバを動かすユーザーのもの 700（rproxy が 700 で作る） | 取ったリリースのバイナリ・署名・マニフェスト（`<版>/`）と `state.json`（よい版・前の版・悪い版・試している版）。実行する前に毎回署名を確かめ直すが、書き換えられると悪い版の印やロールバックを操作できるので、ほかのユーザーには書かせない。書き込めるボリュームにする（ルートのファイルシステムは読み取り専用でよい）。apt で入れた VM では使わない（`RPROXY_UPDATE` は off） |

## 制御 API

- Unix ソケット（`RPROXY_API_SOCKET`）を使うと、ファイルのモードとグループで接続できる利用者を絞れる（loopback の TCP は同じホストの誰でも接続できる）。`RPROXY_API_PORT=0` で TCP を閉じられる。
- 既定の待ち受けは `127.0.0.1`。loopback 以外で待ち受けるには、トークンファイルと TLS 証明書の両方が必須（どちらかがなければ起動しない）。
- 1 行に 1 つ書いたトークンは全権限。YAML の書き方では、トークンごとにスコープ（`rules:read` / `rules:write` / `metrics:read` / `acme:write` / `admin`）・変更できる待ち受けポート・有効期限・結びつけるクライアント証明書（`client_cert`）・作ったルールを DB に保存するか（`persist`）を決められ、ファイルには SHA-256 だけを置く（docs/API.md）。変更は `event: "audit"` のログに残る。
- v0.4（#167）：TCP の制御 API はクライアント証明書（mTLS、`--tls-client-auth optional|required` と `--tls-client-ca`）でも確かめられる。期限の近いトークンは `token.expiring` / `token.expired` で知らせる。401 が続く送信元（IPv6 は /64）は既定で一時停止（20 回 / 1 分で 5 分、`429 locked_out`）。Unix ソケットは数えない（docs/API.md の「制御 API の守り」）。
- 強い操作（`POST /config/reload`・`/admin/upgrade`・`/admin/update`・ACME の更新や失効）は既定で Unix ソケットからだけ（`RPROXY_API_RELOAD_UNIX_ONLY`）。
- 複数のトークンを同時に有効にできるので、新しいトークンを足して reload し、UI を切り替えてから古いトークンを消せば止めずに入れ替えられる。

## DB（MariaDB）

| ユーザー | 権限 | 用途 |
|---|---|---|
| rproxy-api 用（例 `rproxy`。DB のユーザーで OS のユーザーとは別） | `SELECT ON forward_rules`。API で作ったルールを保存するとき（#144、トークンの `persist: true`）は `SELECT, INSERT, UPDATE, DELETE ON rproxy_rules` も | 起動時にルールを復元する（`forward_rules` には書き込まない）。`rproxy_rules` には自分の `node` の行だけを書く。権限がなければ `degraded`（`part: db`）でルールは動かしたまま `persisted: false` |
| UI 用（例 `rproxy_ui`） | `SELECT, INSERT, UPDATE, DELETE ON forward_rules`、`SELECT, INSERT ON forward_rules_log` | ルールの管理と変更履歴 |

GRANT の例は UI リポジトリの `db/README.md`。`rproxy_rules` の定義と GRANT は docs/API.md の「API で作ったルールの保存」。

## UI（TCP-UDP-rproxy-ui）

- Keycloak でサインインした利用者だけが使える。ルールは利用者（Keycloak の `sub`）ごとに持ち、ほかの利用者のルールは見えない。固定ルールはサインインしていればだれでも見える（変更はできない）。
- ロールによる権限の分け方（閲覧だけ、など）は UI の #4 で検討している。
- UI サーバは `RPROXY_API_TOKEN`（rproxy のトークン）と DB のパスワードを持つ。`.env.local` は 600 にする。

## GitHub（開発・配布）

| もの | 置き場所 | 注意 |
|---|---|---|
| apt リポジトリの署名鍵 | Actions の Secrets（`APT_GPG_PRIVATE_KEY` / `APT_GPG_KEY_ID`） | パスフレーズなし。予備はオフラインで保管する（docs/APT.md） |
| リリースの署名鍵（minisign、#174） | Actions の Secret `MINISIGN_SECRET_KEY`（秘密鍵）、変数 `MINISIGN_PUBLIC_KEY`（公開鍵。バイナリに入る） | apt の鍵とは別。パスワードなし。予備はオフラインで保管する。漏れると自動更新に任意のバイナリを入れられる（docs/RELEASING.md） |
| main / master | ルールセット | PR 経由でだけ変更でき、CI の必須チェックが通るまでマージできない。force push と削除は禁止 |
| `v*` タグ | ルールセット | 削除と付け替えは禁止（公開したバージョンの中身を変えない） |
