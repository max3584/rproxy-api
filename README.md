# rproxy-api

稼働中に TCP/UDP の転送を追加・変更・削除・問い合わせできる L4 フォワーダ。
制御は HTTP API で行い、管理 UI は [TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui) にある。

## 起動

```shell
cargo build --release

./target/release/rproxy-api \
    --api-addr 127.0.0.1 \
    --api-port 8080 \
    --token-file /etc/rproxy/tokens \
    --log-file /var/log/rproxy/rproxy.log \
    --database-url mysql://rproxy:password@127.0.0.1:3306/rproxy
```

| 引数 | 既定 | 説明 |
|---|---|---|
| `--api-addr` | `127.0.0.1` | 制御 API の待ち受けアドレス。複数回指定できる |
| `--api-port` | `8080` | 制御 API のポート |
| `--token-file` | なし | Bearer トークンのファイル（1 行 1 トークン）。指定すると認証が必須になる。SIGHUP で読み直す |
| `--tls-cert` / `--tls-key` | なし | 制御 API の TLS 証明書と秘密鍵（PEM）。SIGHUP で読み直す |
| `--log-file` | 標準出力 | JSON Lines のログ。日ごとに `<名前>.<日付>.<拡張子>` へローテーションする |
| `--log-keep` | `14` | 残すログファイルの数 |
| `--log-level` | `info` | `debug` などのフィルタ |
| `--database-url` | なし | 起動時にルールを復元する MariaDB/MySQL。環境変数 `RPROXY_DATABASE_URL` でも指定できる |
| `--dns-interval` | `30` | 転送先ホスト名を再解決する間隔（秒）。解決に失敗したときは前回の結果を使い続ける |

`--api-addr` に loopback 以外を含める場合は、`--token-file` と `--tls-cert` / `--tls-key` の指定が必須。どれかが欠けていると起動しない。

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

## 送信元 IP の引き渡し

ルールごとに `source_ip` で選ぶ。

| 値 | 動作 | 前提 |
|---|---|---|
| `proxy`（既定） | 転送先からは rproxy の IP に見える | なし |
| `proxy_v1` / `proxy_v2` | 接続の先頭に PROXY protocol ヘッダを付ける | TCP のみ。転送先が PROXY protocol に対応していること |
| `transparent` | クライアントの IP を名乗って接続する（`IP_TRANSPARENT`） | Linux、IPv4、`CAP_NET_ADMIN`。転送先からの戻りパケットが rproxy のホストを通ること |

`transparent` を使うには、rproxy に権限を与え、戻りパケットを rproxy のホスト自身で受け取るポリシールーティングを設定する。

```bash
# rproxy に権限を与える（root で動かさない場合）
setcap cap_net_admin+ep ./target/release/rproxy-api

# 転送先からの戻りパケットをローカルで受け取る
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j MARK --set-mark 1
iptables -t mangle -A PREROUTING -p udp -m socket --transparent -j MARK --set-mark 1
```

さらに、転送先のデフォルトゲートウェイを rproxy のホストにする（または転送先側でクライアント宛ての経路を rproxy に向ける）必要がある。
使えるかどうかは `GET /capabilities` で確認できる。

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