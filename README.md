# rproxy-api

[![CI](https://github.com/max3584/rproxy-api/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/max3584/rproxy-api/actions/workflows/ci.yml)
[![Interop](https://github.com/max3584/rproxy-api/actions/workflows/interop.yml/badge.svg?branch=master)](https://github.com/max3584/rproxy-api/actions/workflows/interop.yml)
[![cargo-deny](https://github.com/max3584/rproxy-api/actions/workflows/deny.yml/badge.svg?branch=master)](https://github.com/max3584/rproxy-api/actions/workflows/deny.yml)
[![Release](https://img.shields.io/github/v/release/max3584/rproxy-api)](https://github.com/max3584/rproxy-api/releases/latest)
[![apt](https://img.shields.io/badge/apt-max3584.github.io%2Frproxy--api-blue)](https://max3584.github.io/rproxy-api/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen?logo=renovatebot)](https://github.com/max3584/rproxy-api/issues?q=is%3Aissue+is%3Aopen+%22Dependency+Dashboard%22)

English: [README.en.md](README.en.md)

稼働中に TCP/UDP の転送を追加・変更・削除・問い合わせできる L4 フォワーダ。
制御は HTTP API で行い、管理 UI は [TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui) にある。

構成図（全体・モジュール・接続の流れ・ルールの状態）は [docs/architecture/](docs/architecture/README.md)。

## インストール

### install.sh（VM 向け）

systemd で動く Linux に、root で実行する。Debian / Ubuntu では apt リポジトリから、それ以外では GitHub Release の静的リンクのバイナリ（x86_64 / aarch64 / armv7）を入れ、ユーザー・設定・ユニットを作って起動する。

```shell
curl -fsSL https://raw.githubusercontent.com/max3584/rproxy-api/master/scripts/install.sh | bash -s -- \
  --api-addr 127.0.0.1 --database-url 'mysql://rproxy:password@db.example:3306/rproxy'
```

- 最後に UI の `.env.local` に設定する `RPROXY_API_URL` と `RPROXY_API_TOKEN` の取り出し方を表示する
- 制御 API の既定のポート 8080 が使われていれば、初回だけ 8081〜8099 の空きを選ぶ
- ログは `/var/log/rproxy/rproxy.<日付>.log`（rproxy が日ごとに分けて古いものを消すので logrotate は不要）。`--log-file -` で journald に出す
- もう一度実行するとアップグレード（設定とトークンは残し、指定したオプションだけを書き換える）
- `source_ip: transparent` の権限（`CAP_NET_ADMIN`）はユニットで与える。戻りのパケットのポリシールーティングは `--transparent-clients <CIDR> --transparent-iface <IF>` で入れる（下の「送信元 IP の引き渡し」）
- `--uninstall`（`--purge` で設定・トークン・ログも消す）。オプションの一覧は `install.sh --help`。必要な権限は [docs/PERMISSIONS.md](docs/PERMISSIONS.md)

### apt（Debian / Ubuntu）

apt リポジトリから入れられる（amd64 / arm64 / armhf）。同じリポジトリに管理 UI の `rproxy-ui` もある（`sudo apt install rproxy-api rproxy-ui`。UI は Node.js 20.9 以上が要る。[TCP-UDP-rproxy-ui の README](https://github.com/max3584/TCP-UDP-rproxy-ui)）。

```shell
sudo curl -fsSLo /usr/share/keyrings/rproxy-archive-keyring.gpg https://max3584.github.io/rproxy-api/rproxy-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/rproxy-archive-keyring.gpg] https://max3584.github.io/rproxy-api stable main" \
  | sudo tee /etc/apt/sources.list.d/rproxy-api.list
sudo apt update && sudo apt install rproxy-api
```

インストールしただけでは起動しない。`/etc/rproxy/rproxy.env` を書き換えてから `sudo systemctl enable --now rproxy-api` で起動する。
API のトークンはインストール時に `/etc/rproxy/tokens` に生成される（UI の `RPROXY_API_TOKEN` に設定する）。
パッケージの中身と、リポジトリの公開の仕組みは [docs/APT.md](docs/APT.md)。

バックアップと復旧（何を取るか、DB と設定ファイルの取り方、戻す順番と確かめ方、新しいホストへの移し方、DB なしで動かす方法）は [docs/BACKUP.md](docs/BACKUP.md)。

性能の改善の記録（採用したもの・採用しなかったものとその理由、測り方の注意）は [docs/PERFORMANCE.md](docs/PERFORMANCE.md)。

## 起動

設定は環境変数で行う。起動ディレクトリに `.env` があれば読み込む（例は [.env.example](.env.example)）。
同じ項目をコマンドライン引数（`--api-port` など）で指定した場合は、引数が優先される。

```shell
cargo build --locked --release
cp .env.example .env   # 値を環境に合わせて書き換える
./target/release/rproxy-api
```

メモリの割り当ては既定で libc の malloc（リリースのバイナリは musl の malloc。メモリが最も少ない）。L7（HTTP/2・小さいリクエストの多い HTTP）で CPU を減らしたいときは、mimalloc でビルドできる：`cargo build --locked --release --features alloc-mimalloc`（C コンパイラでビルドする）。手元の測定では HTTP/2 と小さい HTTP のリクエストが 20〜30% 速く、CPU 秒あたりの処理が 25〜170% 増えるかわりに、起動直後のメモリが約 6 MiB、負荷時のピークが 15〜40 MiB 増える。

systemd で動かす場合は `EnvironmentFile=/etc/rproxy/rproxy.env` で同じ内容を渡せる。

| 環境変数 | 引数 | 既定 | 説明 |
|---|---|---|---|
| `RPROXY_API_ADDR` | `--api-addr` | `127.0.0.1` | 制御 API の待ち受けアドレス。カンマ区切りで複数指定できる |
| `RPROXY_API_PORT` | `--api-port` | `8080` | 制御 API のポート。`0` で TCP では待ち受けない（`RPROXY_API_SOCKET` が必須） |
| `RPROXY_API_SOCKET` | `--api-socket` | なし | 制御 API の Unix ソケット（例 `/run/rproxy/api.sock`）。TCP と併用できる。トークンは TCP と同じく要る。親ディレクトリがないと起動しない。前回の残りのソケットは置き換える |
| `RPROXY_API_SOCKET_MODE` | `--api-socket-mode` | `660` | ソケットファイルのモード（8 進数） |
| `RPROXY_API_SOCKET_GROUP` | `--api-socket-group` | なし | ソケットファイルのグループ（名前か ID）。UI を動かすユーザーが入っているグループにする |
| `RPROXY_TOKEN_FILE` | `--token-file` | なし | Bearer トークンのファイル（1 行 1 トークン、または名前・SHA-256・スコープを書いた YAML。docs/API.md）。指定すると認証が必須になる。SIGHUP と、ファイルが変わったとき（`RPROXY_TOKENS_CHECK_SECS`）に読み直す |
| `RPROXY_TOKENS_CHECK_SECS` | `--tokens-check-secs` | `10` | トークンファイルが変わったかを確かめる間隔（秒）。大きさ・更新時刻・inode・権限を、シンボリックリンクをたどって見る（Kubernetes の Secret のボリュームの更新も見つける）。誤りのある版では今のトークンのまま警告を 1 回。`0` なら SIGHUP のときだけ（v0.4.2） |
| `RPROXY_TLS_CERT` / `RPROXY_TLS_KEY` | `--tls-cert` / `--tls-key` | なし | 制御 API の TLS 証明書と秘密鍵（PEM）。SIGHUP で読み直す |
| `RPROXY_CERT_CHECK_SECS` | `--cert-check-secs` | `60` | 証明書ファイル（ルールの `tls` と制御 API）が変わったかを確かめる間隔（秒）。変わったものだけ読み直す（certbot・cert-manager の更新をそのまま反映）。`0` で止める |
| `RPROXY_CERT_STORE` | `--cert-store` | `/var/lib/rproxy/certs` | `PUT /certs/{name}` で受け取った証明書と鍵の置き場所（v0.4.2、#240。ディレクトリ 0700・ファイル 0600。ルールからは `{"cert": "<name>"}`。docs/API.md の「証明書の API」）。`trusted_dirs` の下には置けない |
| `RPROXY_CERT_EXPIRY_CHECK_SECS` | `--cert-expiry-check-secs` | `86400` | 証明書の期限を確かめる間隔（秒。読み込むときにも確かめる）。切れたサーバ証明書は外し、ルールの証明書がすべて切れたらそのルールを止める（docs/API.md の「証明書の期限」）。`0` で止める |
| `RPROXY_CERT_WARN_DAYS` | `--cert-warn-days` | `14` | 期限の何日前から `expiring`（警告）にするか |
| `RPROXY_LOG_FILE` | `--log-file` | 標準出力 | JSON Lines のログ。日ごとに `<名前>.<日付>.<拡張子>` へローテーションする |
| `RPROXY_LOG_KEEP` | `--log-keep` | `14` | 残すログファイルの数 |
| `RPROXY_LOG_LEVEL` | `--log-level` | `info` | `debug` などのフィルタ |
| `RPROXY_CONFIG` | `--config` | なし | 設定ファイル（YAML / JSON。`version`・`global`・`rules`）か、そのディレクトリ。ルールは固定ルールとして開始し、ファイルが変わると再起動なしで差分を反映する（docs/API.md の「設定ファイル」）。起動時に中身が不正なら起動しない |
| `RPROXY_CONFIG_CHECK_SECS` | `--config-check-secs` | `10` | 設定ファイルが変わったかを確かめる間隔（秒）。`0` なら SIGHUP のときだけ読み直す |
| `RPROXY_API_RELOAD_UNIX_ONLY` | `--api-reload-unix-only` | `true` | `POST /config/reload`（設定ファイルをその場で読み直して結果を返す）と ACME の強い操作（`POST /acme/...`。docs/ACME.md）を Unix ソケットからだけ受け付ける。`false` で TCP の制御 API でも受け付ける（`admin` / `acme:write` のトークンが要る） |
| — | `--check-kernel` | — | カーネルでの転送（`global.performance.ebpf` / `xdp`、#260）の速い道をすべて、テストデータを流して確かめ、表で出して終わる（`--check-kernel-format json` で JSON）。`--config` / `RPROXY_CONFIG` で求めたものがすべて使えれば 0、そうでなければ 1 |
| — | `--check-config [PATH]` | — | 設定ファイル（PATH、なければ `RPROXY_CONFIG`）を確かめて終わる。問題がなければ 0、誤りがあれば 1。`--check-config-format json` で JSON（下の「設定を確かめる」） |
| `RPROXY_STATIC_RULES` | `--static-rules` | なし | `RPROXY_CONFIG` の 0.2 の名前（ルールの配列の JSON も読める）。両方は指定できない |
| `RPROXY_DATABASE_URL` | `--database-url` | なし | 起動時にルールを復元する MariaDB/MySQL（`mysql://user:pass@host:port/db`） |
| `RPROXY_MAX_RANGE_PORTS` | `--max-range-ports` | `20000` | 1 ルールで開けるポート範囲の上限 |
| `RPROXY_DNS_INTERVAL` | `--dns-interval` | `30` | 転送先ホスト名を再解決する間隔（秒）。解決に失敗したときは前回の結果を使い続ける |

v0.4 で足した項目（どれも動く。ルールに付ける設定と `global` の項目は docs/API.md の「v0.4 の設定」。制御 API の守りは「制御 API の守り」、再起動なしの更新・自動更新は docs/UPGRADE.md）：

| 環境変数 | 引数 | 既定 | 説明 |
|---|---|---|---|
| `RPROXY_TLS_CLIENT_CA` | `--tls-client-ca` | なし | 制御 API のクライアント証明書を確かめる CA（PEM）。SIGHUP で読み直す（#167） |
| `RPROXY_TLS_CLIENT_AUTH` | `--tls-client-auth` | `none` | 制御 API のクライアント証明書：`none`・`optional`（あれば確かめる）・`required`（ない接続はハンドシェイクで断る）。トークンファイルの `client_cert` で証明書を認証に使う（#167） |
| `RPROXY_TOKEN_WARN_DAYS` | `--token-warn-days` | `14` | トークンの期限の何日前から `token.expiring` を出すか（#167） |
| `RPROXY_API_LOCKOUT_FAILURES` / `_WINDOW` / `_DURATION` | `--api-lockout-failures` / `-window` / `-duration` | `20` / `1m` / `5m` | TCP の制御 API で認証の失敗（401）が続いた送信元を `429 locked_out` で止める（既定で有効。`0` で止めない。Unix ソケットは対象外）（#167） |
| `RPROXY_API_LOCKOUT_EXEMPT` | `--api-lockout-exempt` | なし | 一時停止しない送信元（カンマ区切りの CIDR）。検証済みのクライアント証明書（mTLS）の接続も止めない（v0.4） |
| `RPROXY_FILES_TRUSTED_DIRS` | `--files-trusted-dirs` | なし | ルールが指すファイルを root のものでも使うディレクトリ（`:` か `,` 区切りの絶対パス。Kubernetes の Secret のボリューム）。設定ファイルの `global.files.trusted_dirs` があればそちら（v0.4、docs/PERMISSIONS.md） |
| `RPROXY_NODE_NAME` | `--node-name` | ホスト名 | `rproxy_rules` での名前。起動時はこの名前の行だけを復元する（#144、docs/API.md の「API で作ったルールの保存」） |
| `RPROXY_HANDOFF_SOCKET` / `_TIMEOUT` / `_DRAIN` | `--handoff-socket` / `-timeout` / `-drain` | `/run/rproxy/handoff.sock` / `30s` / `5m` | 再起動なしの更新（#174）：SIGUSR2 か `POST /admin/upgrade` で、ディスクの上のバイナリに待ち受けのソケットを渡す。引き継ぎ用のソケット、新しいプロセスを待つ時間、古いプロセスが今の接続を待つ時間。docs/UPGRADE.md |
| `RPROXY_SHUTDOWN_DELAY` / `RPROXY_SHUTDOWN_DRAIN` | `--shutdown-delay` / `--shutdown-drain` | `0s` / `0s` | SIGTERM での終わり方（v0.4.1）。既定はすぐ止める（今までと同じ）。`DELAY` の間は `/readyz` を 503 `draining` にしたまま受け付け（前のロードバランサから外れるのを待つ）、続けて待ち受けを閉じて今の接続の終わりを `DRAIN` まで待つ。その間、制御 API の読むだけの要求は答え、変更は `503 shutting_down`。2 回目の SIGTERM ですぐ止まる。それぞれ 1 時間まで。systemd での推奨値は下の「SIGTERM での終わり方」 |
| `RPROXY_UPDATE` | `--update` | `off` | 自動更新（コンテナ。#174）：`off`・`check`・`auto`。`RPROXY_UPDATE_PIN`・`_SOURCE`・`_CACHE`・`_INTERVAL`・`_PUBKEY`・`_HEALTHY` も。イメージの入口は `rproxy-api launch`。docs/UPGRADE.md |
| `RPROXY_WORKERS` / `RPROXY_CPU_AFFINITY` / `RPROXY_BUSY_POLL_USECS` | `--workers` / `--cpu-affinity` / `--busy-poll-usecs` | CPU の数 / `none` / `0` | performance（#194。設定ファイルの `global.performance` が先）。`RPROXY_UDP_SHARDS`（数か `auto`）・`RPROXY_SPLICE*` も。docs/API.md の「performance」 |
| `RPROXY_DIFF_API` / `RPROXY_DIFF_TOKEN_FILE` | `--diff` / `--diff-api` / `--diff-token-file` | `RPROXY_API_SOCKET`、なければ制御 API / なし | `--check-config --diff`：動いている rproxy に `POST /config/plan` で問い合わせた差分（#169、docs/API.md の「変更前の差分」） |

`RPROXY_API_ADDR` に loopback 以外を含める場合は、トークンファイルと TLS 証明書の指定が必須。どれかが欠けていると起動しない。

### 起動できないものがあるとき

設定のエラー（値の誤り、存在しないパス、ファイルの中身の誤り）では起動しない。
それ以外の環境の問題では、使えない部分だけを止めて起動を続ける（ログに `"event":"degraded"` と `part` を出す）。

| 状況 | 動作 |
|---|---|
| ログのディレクトリに書けない | 標準出力にログを出す（`part: log`） |
| トークンファイルが読めない（権限） | 制御 API はすべてのリクエストを 401 で拒否する。読めるようにして SIGHUP するか、`RPROXY_TOKENS_CHECK_SECS` の確認で解除（`part: tokens`） |
| 制御 API の TLS 証明書・鍵が読めない（権限）、ポートが使用中 | ルールの転送は動かしたまま、その制御 API のアドレスだけを開き直す（10 秒後から間隔を倍々に延ばし、最大 5 分）（`part: api_tls` / `part: api`） |
| 制御 API の Unix ソケットを作れない（権限、別のプロセスが使用中） | ソケットなしで起動する（`part: api_socket`） |
| `http.http3` のルールの UDP のポートを使えない（使用中、権限） | そのルールは TCP（HTTP/1.1・HTTP/2）だけで動く。`stats.http.http3` に理由が出る（`part: http3`） |
| 固定ルールのファイルが読めない（権限） | 固定ルールなしで起動する（`part: static_rules`） |
| `global.access_log` のディレクトリに書き込めない | アクセスログをメインのログに出す（`part: global.access_log`） |
| DB に接続できない | DB のルールなしで起動する（`restore.error`） |
| `rproxy_rules` を読めない・書けない（テーブルがない、権限、DB が落ちている） | 起動時は UI のルールだけを復元する。API のルールは動かしたまま `persisted: false`（`part: db`、#144） |
| `global.geoip` のデータベースが読めない（権限）・新しい版が壊れている | 読めるまで国・ASN は「分からない」（`unknown` の扱い）、読み直しでは今のものを使い続ける（`part: geoip`） |
| `global.performance` の `busy_poll_usecs` を設定できない・`cpu_affinity` に存在しない CPU | `SO_BUSY_POLL` なしで動く / その CPU を除く（`part: global.performance.*`） |
| `global.performance.ebpf` / `xdp` の速い道が起動時の試験に通らない（権限、カーネル、ドライバ） | 今の処理（splice・`recvmmsg`）で動く（`part: global.performance.ebpf.tcp` / `global.performance.xdp.mode`、`reason`）。`fallback: false` なら起動を止める（#260、docs/API.md の「performance」） |
| 自動更新のキャッシュのディレクトリを作れない | 転送は動かしたまま、直るまで自動更新は失敗する（`part: update.cache`） |
| 権限（capability）が足りないルール | そのルールだけを理由つきの `failed` にする（[docs/PERMISSIONS.md](docs/PERMISSIONS.md)） |


### SIGTERM での終わり方（v0.4.1）

既定では、SIGTERM（`systemctl stop`）ですべての転送をすぐに止める（今の接続も切る）。前にロードバランサや VIP があるときや、今の接続を終わらせてから止めたいときは、`RPROXY_SHUTDOWN_DELAY`・`RPROXY_SHUTDOWN_DRAIN` を `/etc/rproxy/rproxy.env` に書く：

1. SIGTERM が来たら `/readyz` を 503 `draining` にし、`DELAY` の間は今までどおり受け付ける（ヘルスチェックで外れるのを待つ）。
2. 待ち受けを閉じ（新しい接続・UDP のセッションを受けない）、今の接続が終わるのを `DRAIN` まで待つ。HTTP は処理中のリクエストに `Connection: close`（HTTP/2 は GOAWAY）を付けて閉じ、アイドルの接続はすぐ閉じる。UDP の今のセッションは続く。
3. 残りを切って終わる。2 回目の SIGTERM・Ctrl-C ではすぐに止める。

その間、制御 API の読むだけの要求（`GET`・`/metrics`）は答え、変更は `503 shutting_down` で断る。

| 前にあるもの | `RPROXY_SHUTDOWN_DELAY` | `RPROXY_SHUTDOWN_DRAIN` |
|---|---|---|
| なし（クライアントが直接つなぐ） | `0s` | `10s` |
| `/readyz` をヘルスチェックするロードバランサ | 間隔 × 外すまでの回数 + 1 秒（例 `5s`） | `10s`〜`25s` |
| keepalived などの VIP | VIP が移るまでの時間（例 `3s`） | `10s` |

systemd の `TimeoutStopSec`（既定 90 秒）は `DELAY + DRAIN + 5 秒` より長くしておく。`systemctl restart` もこの分だけ遅くなるので、バイナリの更新には再起動なしの更新（SIGUSR2、[docs/UPGRADE.md](docs/UPGRADE.md)）を使う。Kubernetes では rproxy-gateway が `5s`・`25s` を渡す。

## 使い方

API の詳細は [docs/API.md](docs/API.md) を参照。

```bash
TOKEN=$(head -1 /etc/rproxy/tokens)

# 転送を追加
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":8888,"remote_addr":"192.168.1.2","remote_port":8080}'

# 一覧
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules

# 転送先を変更（新しい接続から即時に反映）
curl -H "Authorization: Bearer $TOKEN" -X PATCH http://127.0.0.1:8080/rules/tcp/0.0.0.0/8888 \
  -d '{"remote_addr":"192.168.1.3","remote_port":8081}'

# 宛先を複数に（balance: round_robin / least_conn / failover。health_check で生死を確かめる）
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":5432,
       "targets":[{"addr":"10.0.0.11","port":5432},{"addr":"10.0.0.12","port":5432},{"addr":"10.0.0.13","port":5432,"backup":true}],
       "balance":"least_conn","health_check":{"interval":"10s"}}'

# IPv4 と IPv6 を 1 つのルールで待ち受ける（extra_listen_addrs。0.0.0.0 と :: も並べられる）
curl -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"203.0.113.5","extra_listen_addrs":["2001:db8::5"],"listen_port":443,
       "remote_addr":"10.0.0.20","remote_port":443}'

# 停止（既存の接続も切断。?drain_secs=30 で終了を待つ）
curl -H "Authorization: Bearer $TOKEN" -X DELETE http://127.0.0.1:8080/rules/tcp/0.0.0.0/8888
```

## 固定ルールと、ダッシュボードの公開

`RPROXY_CONFIG` に設定ファイル（YAML か JSON）かそのディレクトリを指定すると、起動時にそのルールを開始します（DB からの復元より前）。ファイルを書き換えると、再起動なしで差分だけを反映します（変わっていないルールの接続は切りません。誤りがあれば反映せず、`GET /config` とログで知らせます）。API と画面からは変更・削除できないので、rproxy 経由で Web UI を公開するルールに向いています（誤って消して、画面に入れなくなることがありません）。

例（[contrib/rproxy.example.yaml](contrib/rproxy.example.yaml)）：`dashboard.proxy.home` だけを、社内のネットワークから 443 で受け付けます。

- `tls.routes` と `tls.unmatched: reject`：ほかの名前や SNI なしの接続は、証明書を返す前に切る（Traefik の `Host(...)` のルールにあたる）
- `allow_from`：範囲外の送信元は TLS より前に切る
- Web UI（rproxy-ui のパッケージ）は既定で `127.0.0.1:3000` だけで待ち受ける。`NEXTAUTH_URL` は `https://dashboard.proxy.home` にする

SNI やサーバ名は、クライアントが自由に名乗れます。名前での振り分けだけではアクセス制限にならないので、`allow_from`、mTLS（`client_auth`）、Web UI のログインを組み合わせてください。

Traefik から移るときは、`rproxy-traefik-convert`（[contrib/traefik2rproxy.py](contrib/traefik2rproxy.py)。.deb に入っている）で Traefik の設定（静的・動的な設定、Docker のラベル）をこの設定ファイルに変換できます。変換できなかった設定は出力の先頭と標準エラーに一覧されます（[docs/MIGRATING-FROM-TRAEFIK.md](docs/MIGRATING-FROM-TRAEFIK.md)）。

systemd で動かす例は [contrib/rproxy-api.service](contrib/rproxy-api.service) にあります（80 / 443 などのために `CAP_NET_BIND_SERVICE` を付ける）。

### 設定を確かめる

設定ファイルを書き換えたら、反映する前に `rproxy-api --check-config` で確かめられます（nginx の `nginx -t` にあたる）。起動時・再読み込みと同じ検証（書式、ルールの値、待ち受けの重なり、制御 API との重なり、証明書・鍵・CA のファイルと期限、`global` と認証などの秘密のファイル）をして、問題がなければ 0、誤りがあれば 1 で終わります。待ち受けも DB も開かず、動いている rproxy にも触りません。

```bash
rproxy-api --check-config                            # RPROXY_CONFIG（/etc/rproxy/rproxy.env など）のファイル
rproxy-api --check-config /etc/rproxy/conf.d         # ファイルかディレクトリを指定
rproxy-api --check-config /etc/rproxy/rproxy.yaml --check-config-format json   # スクリプト向け
rproxy-api --check-config /etc/rproxy/rproxy.yaml && systemctl reload rproxy-api
rproxy-api --check-config /etc/rproxy/rproxy.yaml --diff --diff-token-file /etc/rproxy/admin.token   # 動いている rproxy と比べた差分も出す
```

- 誤り：ファイル・ルール（`rproxy.yaml rule #2` など）ごとに理由を出す。最初の 1 つで止めず、すべて出す
- 警告：期限が近い証明書（`RPROXY_CERT_WARN_DAYS`）、この版や権限で動かせない設定（起動すると `failed` になる）、`rproxy` のユーザーが読めないかもしれないファイル（所有者とモードからの判断）
- JSON：`{"ok": false, "path": "...", "files": [...], "rules": 3, "errors": [{"rule": "rproxy.yaml rule #2", "message": "..."}], "warnings": [...]}`
- 名前解決はしない（転送先の名前が引けるかは、起動したときに分かる）
- 設定ファイルが指定されていなければ、確かめるものがないので 0 で終わる
- `--diff`：検証に通ったら、動いている rproxy に `POST /config/plan` で問い合わせ、反映すると作る・変える・消すルールを 1 行ずつ出す（`+` / `~` / `-`、再起動が要る `global` は `!`）。問い合わせ先の既定は `RPROXY_API_SOCKET`、なければ制御 API（`--diff-api` で指定）。トークンは `admin` のスコープ（`--diff-token-file`）。docs/API.md の「変更前の差分」

パッケージ（と install.sh）の systemd のユニットは、`systemctl reload rproxy-api` で先にこの確認をします。誤りがあれば reload は失敗し（`journalctl -u rproxy-api` に理由）、rproxy には何も送りません。そのときは、トークンや証明書の読み直しも行われないので、設定ファイルを直してから reload してください。

### その場で反映して結果を受け取る

`systemctl reload` は合図を送るだけなので、反映できたかはコマンドの結果では分かりません。スクリプトで結果がほしいときは、制御 API の `POST /config/reload` を使います。読み直して反映し、追加・変更・削除の数（誤りがあれば何も変えずに `400` と理由）を返します。

```bash
curl --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $ADMIN_TOKEN" -X POST http://localhost/config/reload
# {"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0,"restart_needed":[],"files":["/etc/rproxy/rproxy.yaml"],"rules":5,"warnings":[]}
```

- `admin` のスコープを持つトークンだけが使えます（UI 用の `rules:read` / `rules:write` では使えない）
- 既定では Unix ソケット（`RPROXY_API_SOCKET`）からだけ受け付けます。TCP の制御 API から使うなら `RPROXY_API_RELOAD_UNIX_ONLY=false`
- `POST /config/reload?dry_run=true` は反映せずに、反映したら何が変わるか（`changes`。ルールごとの `diff` と、接続を切らずに変えられるか（`change`：`in_place` / `recreate`））を返します。ルールの `POST` / `PATCH` / `DELETE` と `PUT /rulesets/{name}` にも `?dry_run=true` があります
- ファイルの変化の検知・SIGHUP と同じ処理で、同時には動きません

## TLS・DTLS・STARTTLS・ポート範囲

ルールごとに、中身をどう扱うかを選べます（詳細は [docs/API.md](docs/API.md)、用途別の設定例は [docs/PROFILES.md](docs/PROFILES.md)）。

| 設定 | 動作 |
|---|---|
| `tls.mode: passthrough`（既定） | 暗号化されたまま流す |
| `tls.mode: sni` | ClientHello のサーバ名で転送先を振り分ける（復号しない。tcp は TLS、udp は DTLS と QUIC（HTTP/3 など）。docs/API.md の「UDP のサーバ名での振り分け」） |
| `tls.mode: terminate` | rproxy で TLS（tcp）/ DTLS（udp）を終端する。SNI での証明書の選択、mTLS（`client_auth`）、ALPN、転送先への再暗号化（`upstream`）に対応。`tls.routes` の `passthrough: true` の名前だけは終端せずにそのまま流せる（L7 のルールと同じポートでも） |
| `starttls: smtp / imap / pop3` | STARTTLS の手前の平文のやり取りに rproxy が答え、TLS を終端する |
| `listen_port_end` | ポート範囲をまとめて転送する（RTP、TURN のリレー、WebRTC のメディア、FTP のパッシブモード） |

証明書はファイルで指定するか、ACME（Let's Encrypt など。HTTP-01・TLS-ALPN-01・DNS-01（PowerDNS・RFC 2136・acme-dns・汎用の REST））で rproxy に取らせます（`{acme: <resolver>, domains: [...]}`、[docs/ACME.md](docs/ACME.md)）。制御 API の `PUT /certs/{name}` で証明書と鍵を渡して保存し、ルールから `{cert: <name>}` で使うこともできます（v0.4.2、docs/API.md の「証明書の API」）。ファイルが変わると自動で読み直すので（`RPROXY_CERT_CHECK_SECS`）、certbot や cert-manager で更新した証明書がそのまま使われます（SIGHUP ですぐに読み直すこともできます）。ACME で取った証明書も期限の前に自分で更新し、同じ仕組みで差し替えます。DNS-01 の秘密は、別のユーザーで動かす補助プロセス `rproxy-api acme-helper`（`rproxy-acme-helper.service`）だけに持たせることもできます。`source_ip: proxy_v2` と組み合わせると、SNI・ALPN・クライアント証明書の CN を PROXY v2 の TLV で転送先に渡します。

## CrowdSec

CrowdSec の判定で止める（L7 の `crowdsec` ミドルウェア、L4 のルールの `crowdsec: true`、AppSec）だけでなく、CrowdSec のエージェントに rproxy のログを読ませて、rproxy を通るアクセスから攻撃を見つけて ban させることもできます。パーサー・シナリオ・acquis は `contrib/crowdsec/`（.deb では `/usr/share/rproxy-api/crowdsec/`）、手順は [docs/CROWDSEC.md](docs/CROWDSEC.md)。本物の CrowdSec との一周（検知 → ban → rproxy で止める）は CI（interop の `crowdsec` ジョブ）で確かめています。

## 送信元 IP の引き渡し

ルールごとに `source_ip` で選ぶ。PROXY protocol とは何か、どれを選ぶか、転送先（Postfix・Dovecot・nginx・ingress-nginx など）の設定の例は [docs/SOURCE-IP.md](docs/SOURCE-IP.md)。

| 値 | 動作 | 前提 |
|---|---|---|
| `proxy`（既定） | 転送先からは rproxy の IP に見える | なし |
| `proxy_v1` / `proxy_v2` | TCP は接続の先頭に、UDP（`proxy_v2` のみ）はデータグラムごとに PROXY protocol ヘッダを付ける | 転送先が PROXY protocol に対応していること。UDP は dnsdist・PowerDNS・Unbound と同じく、毎回のデータグラムにヘッダを付け、応答にはヘッダを付けない |
| `transparent` | クライアントの IP を名乗って接続する（`IP_TRANSPARENT` / `IPV6_TRANSPARENT`） | Linux、`CAP_NET_ADMIN`。IPv4 と IPv6。転送先からの戻りパケットが rproxy のホストを通ること（[docs/TRANSPARENT.md](docs/TRANSPARENT.md)） |

`transparent` を使うには、rproxy に `CAP_NET_ADMIN` を与え、転送先からの戻りパケットを rproxy のホスト自身で受け取るポリシールーティングを設定する。
apt・install.sh で入れた場合は、ユニットが `CAP_NET_ADMIN` を与えているので権限の設定は要らない。ポリシールーティング（下の 1）は install.sh でまとめて入れられる（起動時に毎回設定する `rproxy-transparent-routing.service` を作る）。

```bash
install.sh --transparent-clients 10.0.1.0/24 --transparent-iface eth1
rproxy-transparent-routing status   # 入っている ip rule / ip route を見る
```

手で起動する場合（systemd を使わない場合）は、root で動かすかバイナリに権限を付ける。権限の一覧は [docs/PERMISSIONS.md](docs/PERMISSIONS.md)。

```bash
setcap cap_net_bind_service,cap_net_admin+ep ./target/release/rproxy-api
```

戻りパケットの受け取り方は2通りある。

1. **クライアントのアドレス範囲が決まっている場合**（`scripts/test-transparent.sh` で動作確認済み）。
   転送先側のインターフェースから届いた、クライアント宛てのパケットをローカル扱いにする。

   ```bash
   ip route add local 10.0.1.0/24 dev lo table 100   # クライアントのアドレス範囲
   ip rule add iif <転送先側のインターフェース> lookup 100
   ```

2. **クライアントのアドレス範囲が決まっていない場合**（`ROUTING=iptables` / `ROUTING=nft` の `scripts/test-transparent.sh` で動作確認済み）。
   rproxy の transparent ソケット宛てのパケットだけに印を付けて、ローカル扱いにする。

   ```bash
   # iptables
   iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j MARK --set-mark 1
   iptables -t mangle -A PREROUTING -p udp -m socket --transparent -j MARK --set-mark 1
   # または nftables
   nft add table ip rproxy
   nft add chain ip rproxy prerouting '{ type filter hook prerouting priority mangle; }'
   nft add rule ip rproxy prerouting socket transparent 1 meta mark set 1

   ip rule add fwmark 1 lookup 100
   ip route add local 0.0.0.0/0 dev lo table 100
   ```

   再起動後も残すには、nftables なら `/etc/nftables.conf` に、`ip rule` / `ip route` は `rproxy-transparent-routing` と同じように起動時に設定する。

どちらの場合も、転送先のデフォルトゲートウェイを rproxy のホストにする（または転送先側でクライアント宛ての経路を rproxy に向ける）必要がある。
使えるかどうかは `GET /capabilities` で確認できる。

`scripts/test-transparent.sh` は、root 権限なしでユーザー名前空間とネットワーク名前空間の中に「クライアント・rproxy・転送先」の構成を作る。そのうえで、`proxy` と `transparent` のそれぞれについて、TCP と UDP で転送先から見える送信元アドレスを確かめる（`cargo build` のあとに実行）。

## ログ

1 行 1 イベントの JSON。共通の項目は `timestamp`、`level`、`event`、`rule`（`tcp/0.0.0.0:8888` の形）。既定の `RPROXY_LOG_LEVEL=info` で出るもの（`debug` だけのものは最後の行）。SIEM・CrowdSec で拾うなら、まず `audit`・`conn.denied`・`http.access`・`tls.error`・`target.down`・`cert.*`・`crowdsec.error`。各項目は docs/API.md。

| `event` | 内容 |
|---|---|
| `rule.create` / `rule.update` / `rule.delete` / `rule.failed` | ルールの作成・変更・削除・異常停止（`labels`、組のルールは `ruleset` も） |
| `ruleset.apply` / `ruleset.delete` | ルールの組（v0.4、#28）を当てた（`ruleset`・`generation`・`etag`・作った・変えた・消した・そのまま・失敗の数・`by`）/ 組を消した |
| `config.reload` / `config.error` | 設定ファイルの反映（件数、再起動が要る `global` の変更）と、反映できなかった理由 |
| `start` / `shutdown` / `fatal` | 起動（`version`、transparent・認証・TLS の有無など）/ 終了 / 起動できない設定の誤り |
| `shutdown.start` / `shutdown.drain` / `shutdown.now` / `shutdown.done` | `RPROXY_SHUTDOWN_DELAY` / `_DRAIN` のある SIGTERM：始めた（`delay_secs`・`drain_secs`）/ 待ち受けを閉じた（残りの接続・セッションの数 `connections`）/ 2 回目の SIGTERM ですぐ止める / 止めた（切った接続・セッションの数 `cut`） |
| `degraded` | 環境の問題で一部を止めて起動を続けた（`part`：`api`・`api_tls`・`tokens`・`log`・`global.*` など） |
| `api.listening` / `api.retry` / `api.stopped` | 制御 API の待ち受けの開始 / 開けないので再試行 / 止まった |
| `audit` | 制御 API での変更（トークンの名前、`client`、操作、ルール、結果）と、断ったリクエスト：トークンがない・違う（`outcome: unauthorized`、`reason`）、権限不足（`outcome: forbidden`）、一時停止中（`outcome: locked_out`）。認証の方法（`auth`：`token`・`cert`・`token+cert`）。断ったリクエストの行は送信元ごとに間引く（`suppressed`） |
| `token.expiring` / `token.expired` | 制御 API のトークンの期限が近い（`RPROXY_TOKEN_WARN_DAYS` より近い）/ 切れた（`token`、`expires`、`days_left`）。起動・SIGHUP・1 日 1 回、状態が変わったときに 1 回だけ |
| `api.lockout` / `api.unlock` | 認証の失敗が続いた送信元（`client`。IPv6 は /64）を止めた（`failures`、`until`）/ 解いた |
| `reload.tokens` / `reload.tls` / `reload.rules_tls` / `reload.crowdsec` | SIGHUP でトークン・制御 API の証明書・ルールの証明書・CrowdSec の鍵を読み直した（読めなければ今のものを使い続ける）。`reload.tokens` はトークンファイルが変わったときにも出る（`reason: "file changed"`、数の `tokens` だけ。誤りのある版の警告は版ごとに 1 回） |
| `geoip.reload` | `global.geoip` のデータベースを読んだ・読み直した（`db`：`country` / `asn`、`path`、`build_epoch`）。読めないときは `degraded`（`part: geoip`）で今のものを使い続ける |
| `static.loaded` / `rule.listen` / `rule.duplicate` | 固定ルールを読み込んだ / 待ち受けのアドレスが変わった / 同じキーのルールを読み飛ばした |
| `conn.open` / `conn.close` | 接続（UDP はセッション）の開始と終了。`client`、`target`、`rx_bytes`、`tx_bytes`、`duration_ms`、`reason`。TLS を終端したときは `tls_version`・`tls_cipher` など。HTTP/3 の QUIC 接続は `transport: quic`。`global.geoip.log_country` で `country`・`asn` |
| `conn.denied` | 断った接続（UDP はデータグラム）：`reason` は `allow_from`・`geoip`（`country`・`asn`）・`crowdsec`・`unmatched`。`client`（`IP:ポート`）、`sni`。UDP は送信元ごとに間引く（`suppressed`：その前に省いた行の数）。HTTP/3 は `transport: quic` |
| `conn.limited` | ルールの `limits`（#165）で断った接続（UDP はデータグラム）：`reason` は `max_connections`・`source_connections`・`new_connections`・`packets`、`transport` は `tcp`・`udp`、`client`。送信元ごとに間引く（`suppressed`） |
| `conn.error` / `tls.error` / `accept.error` / `recv.error` | 転送先に接続できない・ClientHello を読めないなどの接続の失敗 / TLS・DTLS のハンドシェイクの失敗 / 受け付け・受信の失敗 |
| `http3.listening` / `http3.error` | `http.http3` のルールが UDP で HTTP/3 を受け始めた / QUIC の証明書を作り直せない |
| `http.error` | `http` のルールで転送先に接続できない・時間切れ（ルートの `timeouts` を含む）・`retry` の `status` で送り直す（`route`、`service`、`backend`、`status`、`retry` のときは `attempt`）。`http` のルールのリクエストは `http.access`（アクセスログ。`global.access_log` を指定すれば別のファイル。項目は docs/API.md） |
| `http.access` | `http` のルールのリクエスト（アクセスログ）。断ったミドルウェア（`refused_by`・`middleware`）、`basic_auth` のユーザー（`user`）と断った理由（`auth_error`）、`tls.client_auth` のあるルールではクライアント証明書の `client_cn`・`client_verify`（`SUCCESS` / `FAILED` / `NONE`）を含む。`global.geoip.log_country`（と `geoip` ミドルウェアが断ったとき）は `country`・`asn` |
| `oidc.login` / `oidc.refresh` / `oidc.error` / `oidc.cookie` | `oidc` ミドルウェアのサインイン（`user`）、リフレッシュの失敗、プロバイダとのやり取りの失敗、セッションが大きすぎてリフレッシュトークンを持てない |
| `reload.secret` | 認証のミドルウェアの秘密のファイル（htpasswd・OIDC のシークレット）を読み直した、または読み直せず今の中身を使い続ける |
| `http.health` / `http.breaker` | ヘルスチェックで転送先が down / up になった（`service`、`server`、`up`）、`circuit_breaker` が開いた・閉じた（`middleware`、`state`） |
| `http.mirror` | `mirror` ミドルウェアの写しの結果（debug。`middleware`、`service`、`backend`、`status`、失敗なら `error`）。クライアントの応答には影響しない |
| `crowdsec.sync` / `crowdsec.error` | CrowdSec の LAPI から判定を取得した（`added`、`deleted`、`decisions`）/ 取得できない・AppSec に問い合わせできない（それまでの判定を使い続ける） |
| `conn.retarget` | UDP セッションの転送先の切り替え（名前解決の変化、または宛先が down になった：`reason: target down`） |
| `target.down` / `target.up` | 複数の宛先（`targets`）・`health_check` のあるルールで、宛先が down / up になった（`reason: health_check` / `outlier`。`outlier` は実際の通信の失敗で外した・戻した：`cause`、`ejection_secs`）。`http` のサービスの `outlier_detection` でも（`service`、`server`） |
| `dns.change` / `dns.stale` | 転送先の名前解決結果の変化 / 解決失敗（前回の結果を使い続ける） |
| `restore.*` | 起動時の DB からの復元（`restore.paused` は UI で一時停止していて作らなかったルールの数。`restore.conflict` は `rproxy_rules` と UI の `forward_rules` に同じキーがあり UI の行を使った、#144） |
| `rule.persist` | `persist: true` のトークンの API のルール（`origin: "api"`）を `rproxy_rules` に書いた・消した（`action: save` / `delete`、`token`。#144） |
| `ruleset.persist` / `ruleset.restore` / `restore.rulesets` | `persist: true` のトークンのルールの組を `rproxy_rule_sets` に書いた・消した（`action: save` / `delete`、`token`。v0.4.2、#241）/ 起動時に組を 1 つ戻した（`ruleset`・`generation`・`etag`）/ 戻した組の数 |
| `acme.order` / `acme.issue` / `acme.renew` / `acme.revoke` / `acme.ari` / `acme.error` / `acme.rate_limited` | ACME の注文を始めた / 証明書を取った / 更新した / 失敗した（`retry_at`）/ 発行の上限で後に回した（docs/ACME.md） |
| `acme.account` / `acme.dns` / `acme.challenge` / `acme.answer` / `acme.listening` | ACME のアカウントを作った・無効にした / DNS-01 の TXT を書いた・消した / challenge を用意した・答えた / `http01_listen` で待ち受けを始めた。秘密は出さない |
| `acme.helper` | ACME の補助プロセス（`rproxy-api acme-helper`）が待ち受けを始めた・許していない相手を断った・失敗した（`outcome`：`listening` / `refused` / `error`） |
| `cert.expiring` / `cert.expired` / `cert.ok` | 証明書の期限が近い（`RPROXY_CERT_WARN_DAYS` 以内）/ 切れた / 更新された（`file`、`not_after`、`days_left`）。状態が変わったときに 1 回だけ |
| `cert.check` | 定期の期限の確認（`rules_updated`：切れた証明書を外した・止めたルールの数） |
| `performance` | 起動時の `global.performance` の値と出どころ（`sources`）。`SO_BUSY_POLL` を設定できない・存在しない CPU は `degraded`（`part: global.performance.busy_poll_usecs` / `global.performance.cpu_affinity`） |
| `performance.probe` | 求められたカーネルでの転送（`global.performance.ebpf` / `xdp`、#260）の起動時の試験の結果（`feature`・`requested`・`active`・`mode`・`reason`・`tests`）。機能ごとに 1 行、何も求めなければ出ない |
| `handoff.start` / `handoff.sent` / `handoff.ready` / `handoff.drain` / `handoff.done` / `handoff.failed` / `handoff.refused` / `handoff.busy` / `handoff.received` / `handoff.sockets` / `handoff.counters` / `handoff.rule` / `handoff.ruleset` | 再起動なしの更新：始めた / ソケットと状態を渡した / 新しいプロセス（`pid`）の準備ができた / 古いプロセスが今の接続を待つ / 終わった / できなかった（古いプロセスが動き続ける）/ マイナーが違う・別のプロセスがつないだので断った / もう動いている / 新しいプロセスが受け取った / 受け取ったソケットを使った・使わずに閉じた / 古いプロセスの最後の数を足した（届かなければ warn）/ 受け取った API のルール・ルールの組を読めない・当てられない（warn）（docs/UPGRADE.md） |
| `update.check` / `update.available` / `update.fetched` / `update.restart_needed` / `update.healthy` / `update.rollback` / `update.interrupted` / `update.clear_bad` / `update.error` / `launch.start` / `launch.mainpid` / `launch.notify_refused` / `launch.exit` | 自動更新：探したが新しいパッチはない / 新しいパッチがある / 確かめてキャッシュに入れた / 引き継げないパッチなので次の再起動で使う / よい版になった / 悪い版として戻した / 試している版が起動役ごと止まった（3 回で悪い版）/ 悪い版の印を外した / 失敗（署名が合わないなど）/ 起動役（`rproxy-api launch`）がサーバを起動した / 引き継ぎで主プロセスが変わった / 自分の子孫でないプロセスからの `MAINPID=` を断った / サーバが終わった（`code`）。キャッシュに書けないときは `degraded`（`part: update.cache`） |
| （`debug` だけ）`udp.drop` / `udp.send_error` / `udp.recv_error` / `tcp.nodelay` / `target.eject_skipped` | UDP のデータグラムを捨てた（数は `stats.dropped`）/ 送受信の失敗 / TCP_NODELAY を設定できない / `max_ejected_percent` のため失敗した宛先を外さなかった |

## 開発

```bash
cargo test     # 単体テスト（src/）と、実際にソケットを使う結合テスト（tests/。一覧は docs/TESTING.md）
cargo clippy --all-targets
```

## 由来とライセンス

rproxy-api は glacierx の [rproxy](https://github.com/glacierx/rproxy)（MIT License）を出発点に始めた。
今は制御 API・TLS・DTLS・STARTTLS・送信元 IP の引き渡しなどを含め、コードはすべて作り直した独立したプロジェクトで、元のプロジェクトとは別に開発している。
TCP の双方向の転送ループと、UDP のクライアントごとのセッションという設計は元のプロジェクトに由来する（`src/l4/tcp.rs` と `src/l4/udp.rs` の先頭に記載）。

MIT License。元のプロジェクトの著作権表示も含めて [LICENSE](LICENSE) を参照。