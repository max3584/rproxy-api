# rproxy-api

稼働中に TCP/UDP の転送を追加・変更・削除・問い合わせできる L4 フォワーダ。
制御は HTTP API で行い、管理 UI は [TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui) にある。

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
| `RPROXY_API_PORT` | `--api-port` | `8080` | 制御 API のポート |
| `RPROXY_TOKEN_FILE` | `--token-file` | なし | Bearer トークンのファイル（1 行 1 トークン）。指定すると認証が必須になる。SIGHUP で読み直す |
| `RPROXY_TLS_CERT` / `RPROXY_TLS_KEY` | `--tls-cert` / `--tls-key` | なし | 制御 API の TLS 証明書と秘密鍵（PEM）。SIGHUP で読み直す |
| `RPROXY_LOG_FILE` | `--log-file` | 標準出力 | JSON Lines のログ。日ごとに `<名前>.<日付>.<拡張子>` へローテーションする |
| `RPROXY_LOG_KEEP` | `--log-keep` | `14` | 残すログファイルの数 |
| `RPROXY_LOG_LEVEL` | `--log-level` | `info` | `debug` などのフィルタ |
| `RPROXY_STATIC_RULES` | `--static-rules` | なし | 固定ルールの JSON ファイル（下の「固定ルール」を参照）。中身が不正なら起動しない |
| `RPROXY_DATABASE_URL` | `--database-url` | なし | 起動時にルールを復元する MariaDB/MySQL（`mysql://user:pass@host:port/db`） |
| `RPROXY_MAX_RANGE_PORTS` | `--max-range-ports` | `20000` | 1 ルールで開けるポート範囲の上限 |
| `RPROXY_DNS_INTERVAL` | `--dns-interval` | `30` | 転送先ホスト名を再解決する間隔（秒）。解決に失敗したときは前回の結果を使い続ける |

`RPROXY_API_ADDR` に loopback 以外を含める場合は、トークンファイルと TLS 証明書の指定が必須。どれかが欠けていると起動しない。

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

`RPROXY_STATIC_RULES` に JSON のファイルを指定すると、起動時にそのルールを開始します（DB からの復元より前）。API と画面からは変更・削除できないので、rproxy 経由で Web UI を公開するルールに向いています（誤って消して、画面に入れなくなることがありません）。

例（[contrib/static-rules.example.json](contrib/static-rules.example.json)）：`dashboard.proxy.home` だけを、社内のネットワークから 443 で受け付けます。

- `tls.routes` と `tls.unmatched: reject`：ほかの名前や SNI なしの接続は、証明書を返す前に切る（Traefik の `Host(...)` のルールにあたる）
- `allow_from`：範囲外の送信元は TLS より前に切る
- Web UI は `127.0.0.1:3001` だけで待ち受ける（`next start -H 127.0.0.1 -p 3001`）。`NEXTAUTH_URL` は `https://dashboard.proxy.home` にする

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
| `proxy_v1` / `proxy_v2` | 接続の先頭に PROXY protocol ヘッダを付ける | TCP のみ。転送先が PROXY protocol に対応していること |
| `transparent` | クライアントの IP を名乗って接続する（`IP_TRANSPARENT`） | Linux、IPv4、`CAP_NET_ADMIN`。転送先からの戻りパケットが rproxy のホストを通ること |

`transparent` を使うには、rproxy に権限を与え、転送先からの戻りパケットを rproxy のホスト自身で受け取るポリシールーティングを設定する。

```bash
# rproxy に権限を与える（root で動かさない場合）
setcap cap_net_admin+ep ./target/release/rproxy-api
```

戻りパケットの受け取り方は2通りある。

1. **クライアントのアドレス範囲が決まっている場合**（`scripts/test-transparent.sh` で動作確認済み）。
   転送先側のインターフェースから届いた、クライアント宛てのパケットをローカル扱いにする。

   ```bash
   ip route add local 10.0.1.0/24 dev lo table 100   # クライアントのアドレス範囲
   ip rule add iif <転送先側のインターフェース> lookup 100
   ```

2. **クライアントのアドレス範囲が決まっていない場合**（未検証）。
   rproxy の transparent ソケット宛てのパケットだけに印を付けて、ローカル扱いにする。

   ```bash
   iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j MARK --set-mark 1
   iptables -t mangle -A PREROUTING -p udp -m socket --transparent -j MARK --set-mark 1
   ip rule add fwmark 1 lookup 100
   ip route add local 0.0.0.0/0 dev lo table 100
   ```

どちらの場合も、転送先のデフォルトゲートウェイを rproxy のホストにする（または転送先側でクライアント宛ての経路を rproxy に向ける）必要がある。
使えるかどうかは `GET /capabilities` で確認できる。

`scripts/test-transparent.sh` は、root 権限なしでユーザー名前空間とネットワーク名前空間の中に「クライアント・rproxy・転送先」の構成を作る。そのうえで、`proxy` と `transparent` のそれぞれについて、TCP と UDP で転送先から見える送信元アドレスを確かめる（`cargo build` のあとに実行）。

## ログ

1 行 1 イベントの JSON。共通の項目は `timestamp`、`level`、`event`、`rule`（`tcp/0.0.0.0:8888` の形）。

| `event` | 内容 |
|---|---|
| `rule.create` / `rule.update` / `rule.delete` / `rule.failed` | ルールの作成・変更・削除・異常停止 |
| `conn.open` / `conn.close` | 接続（UDP はセッション）の開始と終了。`client`、`target`、`rx_bytes`、`tx_bytes`、`duration_ms`、`reason` |
| `conn.retarget` | UDP セッションの転送先の切り替え |
| `dns.change` / `dns.stale` | 転送先の名前解決結果の変化 / 解決失敗（前回の結果を使い続ける） |
| `restore.*` | 起動時の DB からの復元 |

## 開発

```bash
cargo test     # 単体テストと、実際にソケットを使う結合テスト（tests/api.rs）
cargo clippy --all-targets
```

---
### About rproxy-api
rproxy-api is a derivative of the rproxy project by glacierx. The project utilizes core functionalities from the original rproxy implementation and introduces additional features, including API server capabilities and enhanced logging.

### Original Project
- **Project Name:** rproxy
- **Original Author:** glacierx
- **License:** MIT License

### Modifications
- Added API server functionality for control and monitoring.
- Enhanced logging and configuration options.

### License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.