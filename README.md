# rproxy-api

稼働中に TCP/UDP の転送を追加・変更・削除・問い合わせできる L4 フォワーダ。
制御は HTTP API で行い、管理 UI は [TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui) にある。

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

## 起動

設定は環境変数で行う。起動ディレクトリに `.env` があれば読み込む（例は [.env.example](.env.example)）。
同じ項目をコマンドライン引数（`--api-port` など）で指定した場合は、引数が優先される。

```shell
cargo build --release
cp .env.example .env   # 値を環境に合わせて書き換える
./target/release/rproxy-api
```

systemd で動かす場合は `EnvironmentFile=/etc/rproxy/rproxy.env` で同じ内容を渡せる。

| 環境変数 | 引数 | 既定 | 説明 |
|---|---|---|---|
| `RPROXY_API_ADDR` | `--api-addr` | `127.0.0.1` | 制御 API の待ち受けアドレス。カンマ区切りで複数指定できる |
| `RPROXY_API_PORT` | `--api-port` | `8080` | 制御 API のポート。`0` で TCP では待ち受けない（`RPROXY_API_SOCKET` が必須） |
| `RPROXY_API_SOCKET` | `--api-socket` | なし | 制御 API の Unix ソケット（例 `/run/rproxy/api.sock`）。TCP と併用できる。トークンは TCP と同じく要る。親ディレクトリがないと起動しない。前回の残りのソケットは置き換える |
| `RPROXY_API_SOCKET_MODE` | `--api-socket-mode` | `660` | ソケットファイルのモード（8 進数） |
| `RPROXY_API_SOCKET_GROUP` | `--api-socket-group` | なし | ソケットファイルのグループ（名前か ID）。UI を動かすユーザーが入っているグループにする |
| `RPROXY_TOKEN_FILE` | `--token-file` | なし | Bearer トークンのファイル（1 行 1 トークン、または名前・SHA-256・スコープを書いた YAML。docs/API.md）。指定すると認証が必須になる。SIGHUP で読み直す |
| `RPROXY_TLS_CERT` / `RPROXY_TLS_KEY` | `--tls-cert` / `--tls-key` | なし | 制御 API の TLS 証明書と秘密鍵（PEM）。SIGHUP で読み直す |
| `RPROXY_LOG_FILE` | `--log-file` | 標準出力 | JSON Lines のログ。日ごとに `<名前>.<日付>.<拡張子>` へローテーションする |
| `RPROXY_LOG_KEEP` | `--log-keep` | `14` | 残すログファイルの数 |
| `RPROXY_LOG_LEVEL` | `--log-level` | `info` | `debug` などのフィルタ |
| `RPROXY_CONFIG` | `--config` | なし | 設定ファイル（YAML / JSON。`version`・`global`・`rules`）。ルールは固定ルールとして開始する（docs/API.md の「設定ファイル」）。中身が不正なら起動しない |
| `RPROXY_STATIC_RULES` | `--static-rules` | なし | `RPROXY_CONFIG` の 0.2 の名前（ルールの配列の JSON も読める）。両方は指定できない |
| `RPROXY_DATABASE_URL` | `--database-url` | なし | 起動時にルールを復元する MariaDB/MySQL（`mysql://user:pass@host:port/db`） |
| `RPROXY_MAX_RANGE_PORTS` | `--max-range-ports` | `20000` | 1 ルールで開けるポート範囲の上限 |
| `RPROXY_DNS_INTERVAL` | `--dns-interval` | `30` | 転送先ホスト名を再解決する間隔（秒）。解決に失敗したときは前回の結果を使い続ける |

`RPROXY_API_ADDR` に loopback 以外を含める場合は、トークンファイルと TLS 証明書の指定が必須。どれかが欠けていると起動しない。

### 起動できないものがあるとき

設定のエラー（値の誤り、存在しないパス、ファイルの中身の誤り）では起動しない。
それ以外の環境の問題では、使えない部分だけを止めて起動を続ける（ログに `"event":"degraded"` と `part` を出す）。

| 状況 | 動作 |
|---|---|
| ログのディレクトリに書けない | 標準出力にログを出す（`part: log`） |
| トークンファイルが読めない（権限） | 制御 API はすべてのリクエストを 401 で拒否する。読めるようにして SIGHUP すると解除（`part: tokens`） |
| 制御 API の TLS 証明書・鍵が読めない（権限）、ポートが使用中 | ルールの転送は動かしたまま、その制御 API のアドレスだけを開き直す（10 秒後から間隔を倍々に延ばし、最大 5 分）（`part: api_tls` / `part: api`） |
| 制御 API の Unix ソケットを作れない（権限、別のプロセスが使用中） | ソケットなしで起動する（`part: api_socket`） |
| 固定ルールのファイルが読めない（権限） | 固定ルールなしで起動する（`part: static_rules`） |
| DB に接続できない | DB のルールなしで起動する（`restore.error`） |
| 権限（capability）が足りないルール | そのルールだけを理由つきの `failed` にする（[docs/PERMISSIONS.md](docs/PERMISSIONS.md)） |


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

# 停止（既存の接続も切断。?drain_secs=30 で終了を待つ）
curl -H "Authorization: Bearer $TOKEN" -X DELETE http://127.0.0.1:8080/rules/tcp/0.0.0.0/8888
```

## 固定ルールと、ダッシュボードの公開

`RPROXY_CONFIG` に設定ファイル（YAML か JSON）を指定すると、起動時にそのルールを開始します（DB からの復元より前）。API と画面からは変更・削除できないので、rproxy 経由で Web UI を公開するルールに向いています（誤って消して、画面に入れなくなることがありません）。

例（[contrib/rproxy.example.yaml](contrib/rproxy.example.yaml)）：`dashboard.proxy.home` だけを、社内のネットワークから 443 で受け付けます。

- `tls.routes` と `tls.unmatched: reject`：ほかの名前や SNI なしの接続は、証明書を返す前に切る（Traefik の `Host(...)` のルールにあたる）
- `allow_from`：範囲外の送信元は TLS より前に切る
- Web UI（rproxy-ui のパッケージ）は既定で `127.0.0.1:3000` だけで待ち受ける。`NEXTAUTH_URL` は `https://dashboard.proxy.home` にする

SNI やサーバ名は、クライアントが自由に名乗れます。名前での振り分けだけではアクセス制限にならないので、`allow_from`、mTLS（`client_auth`）、Web UI のログインを組み合わせてください。

systemd で動かす例は [contrib/rproxy-api.service](contrib/rproxy-api.service) にあります（80 / 443 などのために `CAP_NET_BIND_SERVICE` を付ける）。

## TLS・DTLS・STARTTLS・ポート範囲

ルールごとに、中身をどう扱うかを選べます（詳細は [docs/API.md](docs/API.md)、用途別の設定例は [docs/PROFILES.md](docs/PROFILES.md)）。

| 設定 | 動作 |
|---|---|
| `tls.mode: passthrough`（既定） | 暗号化されたまま流す |
| `tls.mode: sni` | ClientHello のサーバ名で転送先を振り分ける（復号しない。tcp のみ） |
| `tls.mode: terminate` | rproxy で TLS（tcp）/ DTLS（udp）を終端する。SNI での証明書の選択、mTLS（`client_auth`）、ALPN、転送先への再暗号化（`upstream`）に対応 |
| `starttls: smtp / imap / pop3` | STARTTLS の手前の平文のやり取りに rproxy が答え、TLS を終端する |
| `listen_port_end` | ポート範囲をまとめて転送する（RTP、TURN のリレー、WebRTC のメディア、FTP のパッシブモード） |

証明書はファイルで指定し、SIGHUP で読み直します。`source_ip: proxy_v2` と組み合わせると、SNI・ALPN・クライアント証明書の CN を PROXY v2 の TLV で転送先に渡します。

## 送信元 IP の引き渡し

ルールごとに `source_ip` で選ぶ。

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

1 行 1 イベントの JSON。共通の項目は `timestamp`、`level`、`event`、`rule`（`tcp/0.0.0.0:8888` の形）。

| `event` | 内容 |
|---|---|
| `rule.create` / `rule.update` / `rule.delete` / `rule.failed` | ルールの作成・変更・削除・異常停止 |
| `audit` | 制御 API での変更（トークンの名前、操作、ルール、結果）と、権限不足で断ったリクエスト |
| `conn.open` / `conn.close` | 接続（UDP はセッション）の開始と終了。`client`、`target`、`rx_bytes`、`tx_bytes`、`duration_ms`、`reason` |
| `conn.retarget` | UDP セッションの転送先の切り替え |
| `dns.change` / `dns.stale` | 転送先の名前解決結果の変化 / 解決失敗（前回の結果を使い続ける） |
| `restore.*` | 起動時の DB からの復元 |

## 開発

```bash
cargo test     # 単体テストと、実際にソケットを使う結合テスト（tests/api.rs）
cargo clippy --all-targets
```

## 由来とライセンス

rproxy-api は glacierx の [rproxy](https://github.com/glacierx/rproxy)（MIT License）を出発点に始めた。
今は制御 API・TLS・DTLS・STARTTLS・送信元 IP の引き渡しなどを含め、コードはすべて作り直した独立したプロジェクトで、元のプロジェクトとは別に開発している。
TCP の双方向の転送ループと、UDP のクライアントごとのセッションという設計は元のプロジェクトに由来する（`src/tcp.rs` と `src/udp.rs` の先頭に記載）。

MIT License。元のプロジェクトの著作権表示も含めて [LICENSE](LICENSE) を参照。