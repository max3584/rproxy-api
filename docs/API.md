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

応答で返すルールには、次の稼働情報が加わる。

| フィールド | 説明 |
|---|---|
| `state` | `"running"` または `"failed"` |
| `error` | `failed` の理由。`running` なら `null` |
| `resolved` | 最後に名前解決できた転送先（`"ip:port"` の配列）。まだ解決できていなければ空 |
| `connections` | 現在の接続数（UDP はセッション数） |

## エンドポイント

| メソッドとパス | 本文 | 成功時 | 説明 |
|---|---|---|---|
| `GET /healthz` | | 200 `ok` | 認証不要 |
| `GET /capabilities` | | 200 | `{"source_ip":["proxy","proxy_v1","proxy_v2","transparent"],"transparent":true}`。`transparent` は `IP_TRANSPARENT` が使えるときだけ含まれる |
| `GET /rules` | | 200 | ルールの配列 |
| `GET /rules/{protocol}/{listen_addr}/{listen_port}` | | 200 | ルール 1 件 |
| `POST /rules` | ルール | 201 | 転送を開始する。名前解決と bind まで済ませてから応答する |
| `PATCH /rules/{protocol}/{listen_addr}/{listen_port}` | `{"remote_addr","remote_port","udp_idle_secs"?}` | 200 | 転送先を変える。新しい接続から即時に反映する。`source_ip` は変更できない |
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
| `unsupported` | 400 | この環境では使えない指定（`transparent` など）、または変更できない項目 |
| `not_found` | 404 | ルールがない |
| `already_exists` | 409 | 同じキーのルールが既にある |
| `bind_failed` | 409 | 待ち受けポートを開けない |
| `resolve_failed` | 502 | 転送先の名前解決に失敗し、キャッシュもない |
| `internal` | 500 | その他 |

## 起動時の復元

`--database-url mysql://user:pass@host:port/db` を指定すると、起動時に `forward_rules` テーブルの全ルールを読み込んで開始する。DB ユーザーには `SELECT` 権限だけを与えればよい。失敗したルールは `failed` として登録し、残りのルールは開始する。名前解決に失敗して `failed` になったルールは、再解決に成功した時点で自動的に開始する。

テーブル定義は UI リポジトリの `db/` で管理する。rproxy が読む列は `protocol`、`src_addr`、`src_port`、`dist_addr`、`dist_port`、`source_ip`、`udp_idle_secs`。
