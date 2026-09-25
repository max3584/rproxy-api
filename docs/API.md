# rproxy-api 制御 API

UI（TCP-UDP-rproxy-ui）と rproxy-api の間の取り決め。どちらかを変えるときは、このファイルも合わせて更新する。

## 基本

- HTTP/1.1、JSON（UTF-8）。`GET /metrics` だけは Prometheus のテキスト形式。
- 待ち受けアドレスは `--api-addr` で指定する（複数回指定できる）。ポートは `--api-port` で指定する（既定 8080）。
- 認証：`--token-file` を指定した場合、`/healthz` 以外のエンドポイントは `Authorization: Bearer <token>` が必須になる。
  - トークンファイルには 1 行に 1 つトークンを書く。空行と `#` で始まる行は無視する。
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
| `remote_addr` | string | ○ | IP アドレスまたはホスト名。ホスト名は 30 秒ごとに再解決する |
| `remote_port` | 1–65535 | ○ | |
| `source_ip` | `"proxy"` \| `"proxy_v1"` \| `"proxy_v2"` \| `"transparent"` | | 既定は `"proxy"`（送信元 IP を引き渡さない）。`proxy_v1` と `proxy_v2` は TCP でのみ使える。`transparent` は IPv4 でのみ使え、`GET /capabilities` が許可しているときだけ指定できる |
| `udp_idle_secs` | 1–86400 | | UDP セッションを無通信で破棄するまでの秒数。既定は 30。TCP では無視する |
| `listen_port_end` | 1–65535 | | ポート範囲の終わり（`listen_port` 以上）。`listen_port..listen_port_end` の各ポートを、`remote_port` から順に同じ数だけずらした転送先へ送る。上限は `GET /capabilities` の `max_range_ports`（既定 20000） |
| `tls` | object | | TLS（tcp）/ DTLS（udp）の扱い。省略すると `{"mode": "passthrough"}`。下の「TLS」を参照 |
| `starttls` | `"smtp"` \| `"imap"` \| `"pop3"` | | STARTTLS の手前の平文のやり取りに rproxy が答え、TLS を終端する。`tls.mode` が `terminate` の tcp ルールでのみ使える |
| `starttls_required` | bool | | 既定 `true`。`false` にすると、SMTP で STARTTLS をしないクライアントも平文のまま通す（IMAP / POP3 では常に必須） |

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
| `routes` | サーバ名ごとの転送先（`sni` と `terminate`）。`*.example.com` は 1 階層だけ一致する。一致しない名前はルールの `remote_addr` / `remote_port` へ。ポート範囲では、ここの `remote_port` も同じだけずれる |
| `certificates` | `terminate` で必須。`cert_file` はサーバ証明書、`chain_file` は中間 CA の証明書（サーバ証明書を発行した CA から、ルートへ向かう順。ルートは入れなくてよい）、`key_file` は秘密鍵。`cert_file` にチェーンを連結しても使える。読み込むときに、チェーンの順番と、鍵がサーバ証明書と対になっていることを確かめる。複数あれば SNI で選び、どれにも一致しなければ先頭を使う。DTLS の鍵は PKCS#8（`-----BEGIN PRIVATE KEY-----`）に限る |
| `client_auth` | クライアント証明書の検証（mTLS）。`mode` は `none`（既定）/ `optional`（送られてきたら検証する）/ `required`。`optional` と `required` では `ca_file` が必須。`ca_file` はルート CA（信頼の起点）。`chain_file` はクライアント証明書の中間 CA で、中間 CA を送ってこないクライアントのために、検証の途中経路を補う（信頼の起点にはしない）。TLS と DTLS で同じ規則で検証する |
| `alpn` | `terminate` でクライアントに提示する ALPN（tcp のみ） |
| `upstream` | `terminate` の転送先側。`tls: true` で再暗号化する（tcp は TLS、udp は DTLS）。`server_name`（既定は転送先のホスト名）、`ca_file`（既定は Mozilla のルート証明書）、`insecure_skip_verify`（検証しない。テスト用）、`cert_file` / `chain_file` / `key_file`（転送先へのクライアント証明書と、その中間 CA） |

`terminate` と `source_ip: "proxy_v2"` を組み合わせると、PROXY v2 ヘッダに TLS の情報を TLV で付ける。
- `PP2_TYPE_AUTHORITY`：SNI
- `PP2_TYPE_ALPN`：ALPN
- `PP2_TYPE_SSL`：TLS であること、クライアント証明書の有無、`PP2_SUBTYPE_SSL_VERSION`、クライアント証明書の CN（`PP2_SUBTYPE_SSL_CN`）

証明書ファイルは、ルールの作成・変更のときに読み込む。ファイルを差し替えたあとで SIGHUP を送ると、全ルールの証明書を読み直す（読めなかったルールは今の証明書のまま）。

応答で返すルールには、次の稼働情報が加わる。

| フィールド | 説明 |
|---|---|
| `state` | `"running"` または `"failed"` |
| `error` | `failed` の理由。`running` なら `null` |
| `resolved` | 最後に名前解決できた転送先（`"ip:port"` の配列）。まだ解決できていなければ空 |
| `connections` | 現在の接続数（UDP はセッション数） |
| `stats` | ルールが開始してからの累計：`total_connections`、`rx_bytes`（クライアント → 転送先）、`tx_bytes`（転送先 → クライアント）、`tls_failures`（TLS / DTLS のハンドシェイクや STARTTLS の失敗） |
| `started_at` | 待ち受けを始めた時刻（Unix 秒）。`failed` のときは `null` |

## エンドポイント

| メソッドとパス | 本文 | 成功時 | 説明 |
|---|---|---|---|
| `GET /healthz` | | 200 `ok` | 認証不要 |
| `GET /capabilities` | | 200 | `{"source_ip":[...],"transparent":true,"tls_modes":["passthrough","sni","terminate"],"dtls":true,"starttls":["smtp","imap","pop3"],"max_range_ports":20000}`。`source_ip` の `transparent` は `IP_TRANSPARENT` が使えるときだけ含まれる |
| `GET /rules` | | 200 | ルールの配列 |
| `GET /rules/{protocol}/{listen_addr}/{listen_port}` | | 200 | ルール 1 件 |
| `POST /rules` | ルール | 201 | 転送を開始する。名前解決と bind まで済ませてから応答する |
| `PATCH /rules/{protocol}/{listen_addr}/{listen_port}` | `{"remote_addr","remote_port","udp_idle_secs"?,"tls"?,"starttls"?,"starttls_required"?}` | 200 | 転送先を変える。新しい接続から即時に反映する。`tls` を付けると TLS の設定を丸ごと置き換える（`starttls` も一緒に指定する。省略すると STARTTLS なし）。`source_ip` とポート範囲は変更できない |
| `DELETE /rules/{protocol}/{listen_addr}/{listen_port}?drain_secs=N` | | 204 | 転送を停止する。既存の接続は即座に切断する。`drain_secs` を付けた場合は、その秒数だけ既存の接続の終了を待ってから切断する |
| `GET /metrics` | | 200 | Prometheus 形式 |

IPv6 の `listen_addr` をパスに入れるときは URL エンコードする。

## エラー

失敗時は次の形で返す。

```json
{"error": "address already in use (os error 98)", "code": "bind_failed"}
```

| `code` | HTTP | 意味 |
|---|---|---|
| `unauthorized` | 401 | トークンがない、または一致しない |
| `invalid` | 400 | 本文やパスが不正 |
| `tls_config` | 400 | TLS の設定の組み合わせが不正、または証明書・鍵・CA のファイルを読めない |
| `unsupported` | 400 | この環境では使えない指定（`transparent` など）、または変更できない項目 |
| `not_found` | 404 | ルールがない |
| `already_exists` | 409 | 同じキーのルールが既にある |
| `bind_failed` | 409 | 待ち受けポートを開けない |
| `resolve_failed` | 502 | 転送先の名前解決に失敗し、キャッシュもない |
| `internal` | 500 | その他 |

## 起動時の復元

`--database-url mysql://user:pass@host:port/db` を指定すると、起動時に `forward_rules` テーブルの全ルールを読み込んで開始する。DB ユーザーには `SELECT` 権限だけを与えればよい。失敗したルールは `failed` として登録し、残りのルールは開始する。名前解決に失敗して `failed` になったルールは、再解決に成功した時点で自動的に開始する。

テーブル定義は UI リポジトリの `db/` で管理する。rproxy が読む列は `protocol`、`src_addr`、`src_port`、`src_port_end`、`dist_addr`、`dist_port`、`source_ip`、`udp_idle_secs`、`options`。
`options` は JSON で `{"tls": <TLS>, "starttls": "smtp" | "imap" | "pop3" | null, "starttls_required": bool}`。古いテーブルにこれらの列がなければ、既定値で読み込む。
