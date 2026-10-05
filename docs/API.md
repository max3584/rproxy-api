English: [API.md](en/API.md)

# rproxy-api 制御 API

UI（TCP-UDP-rproxy-ui）と rproxy-api の間の取り決め。どちらかを変えるときは、このファイルも合わせて更新する。

## 基本

- HTTP/1.1、JSON（UTF-8）。`GET /metrics` だけは Prometheus のテキスト形式。
- 待ち受けアドレスは `--api-addr` で指定する（複数回指定できる）。ポートは `--api-port` で指定する（既定 8080。`0` で TCP を使わない）。
- Unix ソケットでも受けられる（`--api-socket`、`--api-socket-mode`、`--api-socket-group`）。中身は TCP と同じ HTTP/1.1 で、トークンも同じく要る。
- 認証：`--token-file` を指定した場合、`/healthz` 以外のエンドポイントは `Authorization: Bearer <token>` が必須になる。
  - トークンファイルは 2 つの書き方がある。
    - 1 行に 1 つトークンを書く（すべての権限。ログでの名前は `token-1`、`token-2`…）。空行と `#` で始まる行は無視する。
    - YAML で `tokens:` に名前・SHA-256・スコープを書く（トークンそのものはファイルに置かない）。

      ```yaml
      tokens:
        - name: ui
          sha256: 9f86d081...        # printf %s "$TOKEN" | sha256sum
          scopes: [rules:read, rules:write, metrics:read]
        - name: ci-deploy
          sha256: 2c26b46b...
          scopes: [rules:write]
          allow_listen_ports: 20000-29999   # 作成・変更・削除できる待ち受けポート（範囲ルールは全体が収まること）
          expires: 2027-03-31               # この日（UTC）まで有効
      ```

    - スコープ: `rules:read`（`GET /rules`・`/interfaces`）、`rules:write`（`POST` / `PATCH` / `DELETE /rules`）、`metrics:read`（`GET /metrics`）、`admin`（すべて）。`GET /capabilities` はどのトークンでも読める。足りないときは `403 forbidden`。
    - ルールの作成・変更・削除は `event: "audit"` のログに残る（`token`、`action`、`rule`、`outcome`、失敗時の `code`）。権限不足で断ったリクエストも残る。
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
| `extra_listen_addrs` | string[] | | 同じポート（範囲）で追加で待ち受ける IP アドレス（最大 16 件。例 `listen_addr` が代表の IPv4 で、ここに GUA の IPv6）。ルールのキーは `listen_addr` のまま。統計・ログは 1 つのルールとしてまとめ、`conn.open` の `listen` に受けたアドレスが出る。追加のアドレスがあるルールの IPv6 の待ち受けは `IPV6_V6ONLY` で開くので、`0.0.0.0` と `::` を並べられる（`::` だけのルールは OS の既定のまま：Linux の既定では IPv4 も受ける）。ほかのルール・制御 API との重なりは、追加のアドレスも含めて確かめる（`409 already_exists` / `reserved`）。`transparent` では、追加のアドレスのファミリーの宛先（IP で書いたもの）が 1 つもなければ `invalid`、IPv6 のアドレスは `transparent_ipv6` が要る。`http3` の QUIC も全部のアドレスで受ける。一覧では空なら省く。UDP の返信の送信元は、`0.0.0.0` / `::` で待ち受けていてもクライアントが送った宛先のアドレスになるので、アドレスを複数持つホストで返信元を固定するためにアドレスを並べる必要はない（v0.3.10 から） |
| `listen_port` | 1–65535 | ○ | |
| `remote_addr` | string | ○ | IP アドレスまたはホスト名。ホスト名は 30 秒ごとに再解決する。`http` のルールでは書かない（転送先は `http.services`。一覧では `""` / `0`）。`targets` を使うときも書かない（一覧では `targets` の先頭が入る） |
| `remote_port` | 1–65535 | ○ | `http` のルール・`targets` を使うルールでは書かない |
| `targets` | object の配列 | | 宛先を複数にする（v0.3.3、`remote_addr` / `remote_port` の代わり。どちらか一方）。`{"addr", "port", "weight"?, "backup"?}`：`addr` は IP かホスト名（それぞれ再解決する）、`weight` は 1 以上（既定 1）、`backup: true` はほかの宛先がすべて down のときだけ使う（全部を backup にはできない）。最大 64 件。ポート範囲では各宛先の `port` も範囲の分ずれる。下の「複数の宛先」 |
| `balance` | `"round_robin"` \| `"least_conn"` \| `"failover"` | | `targets` の振り分け方。既定 `round_robin`。一覧では `targets` があるときだけ出す |
| `health_check` | object | | 宛先の生死を TCP の接続で確かめる（v0.3.3）。`{"interval"?, "timeout"?, "port"?}`：`interval` 既定 `10s`、`timeout` 既定 `3s`、`port` は各宛先のポートの代わりに接続するポート（UDP のルールでは必須）。`remote_addr` だけのルールでも使える。`http` のルールでは使えない（`http.services.<名前>.health_check`） |
| `source_ip` | `"proxy"` \| `"proxy_v1"` \| `"proxy_v2"` \| `"transparent"` | | 既定は `"proxy"`（送信元 IP を引き渡さない）。`proxy_v1` は TCP でのみ使える。`proxy_v2` は UDP でも使え、転送先へのデータグラムごとに PROXY v2（DGRAM）のヘッダを付ける（応答にはヘッダがない。宛先アドレスはクライアントが送った宛先のアドレス。`0.0.0.0` / `::` で待ち受けていても、受けたアドレスになる）。UDP の `proxy_v2` と `tls.upstream.tls`（転送先への DTLS）は組み合わせられない（`unsupported`）。`transparent` は `GET /capabilities` の `transparent`（IPv4）/ `transparent_ipv6`（IPv6 の待ち受け）が true のときだけ指定できる。クライアントと転送先は同じアドレスファミリーであること（docs/TRANSPARENT.md） 。説明と転送先の設定の例は docs/SOURCE-IP.md |
| `udp_idle_secs` | 1–86400 | | UDP セッションを無通信で破棄するまでの秒数。既定は 30。TCP では無視する |
| `listen_port_end` | 1–65535 | | ポート範囲の終わり（`listen_port` 以上）。`listen_port..listen_port_end` の各ポートを、`remote_port` から順に同じ数だけずらした転送先へ送る。上限は `GET /capabilities` の `max_range_ports`（既定 20000） |
| `tls` | object | | TLS（tcp）/ DTLS（udp）の扱い。省略すると `{"mode": "passthrough"}`。下の「TLS」を参照 |
| `starttls` | `"smtp"` \| `"imap"` \| `"pop3"` | | STARTTLS の手前の平文のやり取りに rproxy が答え、TLS を終端する。`tls.mode` が `terminate` の tcp ルールでのみ使える |
| `starttls_required` | bool | | 既定 `true`。`false` にすると、SMTP で STARTTLS をしないクライアントも平文のまま通す（IMAP / POP3 では常に必須として扱う）。`starttls` なしで `false` を指定すると `invalid` |
| `allow_from` | string の配列 | | 接続を受け付ける送信元。CIDR（`172.16.0.0/16`、`fd00::/8`）または単一の IP。省略または空ならすべて受け付ける。最大 64 件。範囲外からの TCP 接続は、TLS や PROXY ヘッダより前に切断する。UDP は範囲外の送信元のデータグラムを捨てる（セッションを作らない） |
| `crowdsec` | bool | | 既定 `false`（v0.3.2）。`true` にすると、CrowdSec の判定（`global.crowdsec`、scope `Ip` / `Range`）に入っている送信元を、`allow_from` と同じく受け付けた直後（TLS や PROXY ヘッダより前）に切断する。UDP はそのデータグラムを捨てる（開いているセッションのものも）。LAPI から一度も判定を取れていない間は通す。`global.crowdsec` がないと `invalid`。`http` のルールでも使えるが、見るのは接続元の IP（前段のプロキシの後ろでは `crowdsec` ミドルウェアを使う）。一覧では `false` のとき省く。断った数は `stats.denied`、ログは `conn.denied`（`reason: crowdsec`） |

範囲ルールのキーは `listen_port`（範囲の先頭）。同じプロトコルで待ち受けアドレスとポートが重なるルールは作れない（`already_exists`）。

UDP のルールを `0.0.0.0` / `::` で待ち受けると、rproxy は受けたデータグラムの宛先アドレスを覚え（`IP_PKTINFO` / `IPV6_RECVPKTINFO`）、返信はそのアドレスから送る（v0.3.10 から。Linux）。アドレスを複数持つホストでも、クライアントは送った宛先から返信を受け取れる（IKE・WebRTC・QUIC・DTLS など、宛先と違うアドレスからの返信を捨てるクライアントのため）。同じクライアント（アドレスとポート）が別のアドレスに送ったものは別のセッションになり、それぞれのアドレスから返す。L4 の中継・DTLS の終端・UDP のサーバ名での振り分け・HTTP/3 のどれも同じ。`conn.open` の `listen` と PROXY v2 のヘッダの宛先も受けたアドレスになる。

### 複数の宛先（`targets`、v0.3.3）

```json
{
  "protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 5432,
  "targets": [
    {"addr": "10.0.0.11", "port": 5432, "weight": 2},
    {"addr": "10.0.0.12", "port": 5432},
    {"addr": "db-backup.internal", "port": 5432, "backup": true}
  ],
  "balance": "least_conn",
  "health_check": {"interval": "10s", "timeout": "3s"}
}
```

- 新しい接続（TCP）・新しいセッション（UDP）ごとに宛先を選ぶ。
  - `round_robin`：`weight` の比率で順に回す。
  - `least_conn`：いま開いている接続（UDP はセッション）の数 ÷ `weight` が一番小さい宛先。同じなら順に回す。
  - `failover`：`targets` の上から順に、up の最初の宛先だけを使う。上位が戻れば、新しい接続から戻る。
- up / down：`health_check` があれば、その結果（最初の確認までは up）。なくても、TCP の接続を断られた（または 5 秒以内に応答がない）宛先は、10 秒のあいだ down として飛ばし、同じ接続を次の宛先で接続し直す。UDP は、転送先から ICMP の到達不能が返った宛先を同じく down にする。
- `backup` の宛先は、ほかの宛先がすべて down のときだけ使う。すべて down なら、down の宛先も順に試す（接続を断らない）。
- UDP の既存のセッションは、自分の宛先が down になったら次の宛先へ移る（`conn.retarget`、`reason: target down`）。`failover` で上位が戻っても、既存のセッションはそのまま。
- 名前解決できない宛先があっても、ほかの宛先が解決できればルールは動く（解決できない宛先は後から再解決する）。すべて解決できなければ、これまでどおり `resolve_failed`。
- `tls.routes`（サーバ名ごとの転送先）は今までどおり route ごとに 1 つ。`targets` は一致しない名前（とサーバ名なし）の転送先。
- 状態が変わると `event: "target.down"`（`reason: health_check` / `connect`、`error`）/ `"target.up"` のログ。ルールの `stats.targets` に宛先ごとの `[{"addr","port","backup"?,"up","connections","total_connections","resolved"}]`（`targets` が 2 つ以上か `health_check` があるときだけ）、`/metrics` に `rproxy_target_up{protocol,listen,target}`（1 / 0）と `rproxy_target_connections{protocol,listen,target}`。
- 宛先・`balance`・`health_check` を変えると、宛先ごとの接続数と up / down は最初からになる（開いている接続はそのまま）。

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
| `mode` | `passthrough`（既定。暗号化されたまま流す）、`sni`（ClientHello のサーバ名で転送先を選び、復号しない。tcp は TLS、udp は DTLS と QUIC（HTTP/3 など）。下の「UDP のサーバ名での振り分け」）、`terminate`（rproxy で復号する。tcp は TLS、udp は DTLS） |
| `routes` | サーバ名ごとの転送先（`sni` と `terminate`）：`{"server_name" または "server_names", "remote_addr", "remote_port", "passthrough"?}`。範囲ルールでは、`remote_port` に範囲の長さを足して 65535 を超えないこと。一致しない名前はルールの `remote_addr` / `remote_port`（`targets`）へ。ポート範囲では、ここの `remote_port` も同じだけずれる。<br>名前の書き方：`mail.example.com`（完全一致）、`*.example.com`（1 階層だけ）、`**.example.com`（1 階層以上、何階層でも。`example.com` 自体には一致しない）。`server_names` で 1 つの route に名前を複数書ける（`server_name` とどちらか一方）。複数の route に一致するときは、完全一致 → `*.` → `**.`（接尾辞が長い方）→ 書いた順。<br>`passthrough: true`（`terminate` だけ）：その名前の接続は終端せず、ClientHello ごと転送先へそのまま流す（`sni` と同じ。証明書は転送先が持つ）。`allow_from`・ルールの `crowdsec`・`source_ip`・統計は効く。`starttls` とは組み合わせられない。HTTP/3（QUIC）では扱わない（その名前の QUIC の接続は閉じる） |
| `unmatched` | `default`（既定。どの `routes` にも一致しない名前・SNI なしは、ルールの `remote_addr` / `remote_port` へ）または `reject`（切断する。`terminate` ではハンドシェイクを完了せずに切る）。`sni`（tcp・udp）と tcp の `terminate` で、`routes` があるときだけ指定できる |
| `certificates` | `terminate` で必須。`cert_file` はサーバ証明書、`chain_file` は中間 CA の証明書（サーバ証明書を発行した CA から、ルートへ向かう順。ルートは入れなくてよい）、`key_file` は秘密鍵。`cert_file` にチェーンを連結しても使える。読み込むときに、チェーンの順番と、鍵がサーバ証明書と対になっていることを確かめる。複数あれば SNI で選び、どれにも一致しなければ先頭を使う。DTLS の鍵は PKCS#8（`-----BEGIN PRIVATE KEY-----`）に限る |
| `client_auth` | クライアント証明書の検証（mTLS）。`mode` は `none`（既定）/ `optional`（送られてきたら検証する）/ `required`。`optional` と `required` では `ca_file` が必須。`ca_file` はルート CA（信頼の起点）。`chain_file` はクライアント証明書の中間 CA で、中間 CA を送ってこないクライアントのために、検証の途中経路を補う（信頼の起点にはしない）。TLS と DTLS で同じ規則で検証する |
| `alpn` | `terminate` でクライアントに提示する ALPN（tcp のみ） |
| `upstream` | `terminate` の転送先側。`tls: true` で再暗号化する（tcp は TLS、udp は DTLS）。`server_name`（既定は転送先のホスト名）、`ca_file`（既定は Mozilla のルート証明書）、`insecure_skip_verify`（検証しない。テスト用）、`cert_file` / `chain_file` / `key_file`（転送先へのクライアント証明書と、その中間 CA） |

### UDP のサーバ名での振り分け（`tls.mode: sni`、v0.3.8）

udp のルールでも `tls.mode: sni` と `tls.routes` で、最初のデータグラムのサーバ名（SNI）から転送先を選べる。終端しないので rproxy に証明書は要らず、証明書は転送先が持つ。

- 読めるもの：
  - DTLS 1.2 / 1.3 の ClientHello（平文。断片に分かれていても、データグラムをまたいでもつなぎ合わせる）
  - QUIC v1（RFC 9000 / 9001）/ v2（RFC 9369）の Initial パケット（HTTP/3 など）。Initial の鍵はクライアントが選んだ接続 ID から誰でも計算できる（RFC 9001 §5.2）ので、ヘッダの保護と暗号を外して CRYPTO フレームから ClientHello を読む。ClientHello が複数の Initial にまたがっても（大きな鍵共有など）つなぎ合わせる
- 新しいクライアント（アドレスとポート）の最初のデータグラムを、名前が分かるまで持つ（最大 3 秒・16 データグラム・64 KiB）。名前が分かったら、持っていたデータグラムを順番どおり転送先へ送り、あとは今までの UDP と同じくそのクライアントのセッションとして中継する。名前を読んでいるセッションは 1 ポートあたり 4096 まで（超えた新しいクライアントの最初のデータグラムは捨てる。クライアントが再送する）
- DTLS でも QUIC でもないデータグラム、SNI がないもの、どの route にも一致しない名前：`unmatched: default`（既定）ならルールの宛先（`remote_addr` / `targets`）、`reject` なら捨てる（`stats.denied`、`conn.denied` の `reason: unmatched`）
- 同じクライアントのソケットから、別の名前への新しい QUIC の接続（違う接続 ID の Initial）が来たら、名前を読み直し、違う名前ならセッションを作り直す（quinn などは 1 つのソケットから次の接続を始める）。同じ名前（Retry の後など）なら今の転送先のまま
- `allow_from`・ルールの `crowdsec` は名前を読む前に効く。`conn.open` のログに `sni`
- `routes` の `passthrough` は使えない（`sni` はすべて passthrough）。DTLS を終端する `terminate` の udp のルールは名前で振り分けない
- できないこと：
  - QUIC の接続の移動（クライアントのアドレスやポートが変わる）は追いかけない（移った先は新しいクライアントとして名前を読み直す。Initial でないので、ルールの宛先へ）
  - ECH（Encrypted Client Hello）を使う接続では、本当の名前は読めない（外側の public name で振り分ける）

`terminate` と `source_ip: "proxy_v2"` を組み合わせると、PROXY v2 ヘッダに TLS の情報を TLV で付ける。
- `PP2_TYPE_AUTHORITY`：SNI
- `PP2_TYPE_ALPN`：ALPN
- `PP2_TYPE_SSL`：TLS であること、クライアント証明書の有無、`PP2_SUBTYPE_SSL_VERSION`、クライアント証明書の CN（`PP2_SUBTYPE_SSL_CN`）

証明書ファイルは、ルールの作成・変更のときに読み込む。読み込んだ証明書は証明書の単位で共有する（同じファイルを使う複数のルールは同じものを使う）。そのあとは：
- `RPROXY_CERT_CHECK_SECS`（既定 60 秒、`0` で止める）ごとに、証明書ごとにファイル（証明書・鍵・中間 CA・CA）の大きさ・更新時刻・inode を確かめ、変わった証明書だけ読み直して、それを使うルールに反映する。certbot などでの上書きも、Kubernetes の Secret のようにシンボリックリンクを差し替える方式も検知する。制御 API の証明書（`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`）も同じ。
- 読み直せなかったとき（書き込み途中で鍵と証明書が合わないなど）は今の証明書のまま使い、次の確認でもう一度試す（`reload.tls` の警告はファイルの版ごとに 1 回）。
- SIGHUP を送ると、変わったかどうかにかかわらず全部の証明書をすぐに読み直す。

### 証明書の期限（#115）

証明書を読み込むとき（作成・変更・ファイルの変化・SIGHUP）と、`RPROXY_CERT_EXPIRY_CHECK_SECS`（既定 86400 秒 = 1 日、`0` で止める）ごとに、期限（notAfter）を確かめる。
- **サーバ証明書**（`tls.certificates`。中間 CA を含めて、どれか 1 枚でも切れていれば切れた扱い）：
  - 切れた証明書だけを外し、ほかの証明書で動き続ける。外した証明書の名前には、残りの先頭の証明書を返す（クライアントからは名前の不一致に見える。切れた証明書を返すことはない）。
  - すべて切れたら、ルールを `failed`（`error` は `certificate expired: ...`）にして待ち受けを閉じる。更新されたファイルを読み込めた時点（ファイルの変化・SIGHUP・PATCH）で、自動で `running` に戻る。
  - API で作成・変更するときに、すべて切れていれば `400 tls_config`（`certificate expired: ...`）で断る（作らない）。起動時（DB・設定ファイル）と読み直しのときは `failed` として登録する。
- **クライアント認証の CA・中間 CA、転送先向けの CA・証明書、制御 API の証明書**：ルールは止めない。表示・ログ・メトリクスで知らせるだけ。
- `passthrough` の route は対象外（証明書は転送先のもの）。
- 期限の `RPROXY_CERT_WARN_DAYS`（既定 14 日）前から `expiring`。状態が変わったときに 1 回だけ、ログ `cert.expiring`（警告）・`cert.expired`（エラー）・`cert.ok`（更新された）を出す。
- `/metrics` の `rproxy_cert_expiry_seconds{protocol,listen,role,file}`（制御 API の証明書は `{role="api",file}`）：期限までの秒数（切れたら負）。

ACME は rproxy に内蔵しない。証明書の取得と更新は certbot・acme.sh・cert-manager などに任せ、そのファイルを `cert_file` / `key_file` に指定する（更新は上のとおり自動で反映される）。certbot の http-01 は、80 番の `http` のルールで `/.well-known/acme-challenge/` を certbot の webroot / standalone のポートへ振り分ければよい。

応答で返すルールには、次の稼働情報が加わる（`allow_from` は正規化した CIDR の形で返す。例：`10.0.0.5` → `10.0.0.5/32`）。

| フィールド | 説明 |
|---|---|
| `state` | `"running"` または `"failed"` |
| `error` | `failed` の理由。`running` なら `null` |
| `resolved` | 最後に名前解決できた転送先（`"ip:port"` の配列）。まだ解決できていなければ空 |
| `connections` | 現在の接続数（UDP はセッション数） |
| `stats` | ルールが開始してからの累計：`total_connections`、`rx_bytes`（クライアント → 転送先）、`tx_bytes`（転送先 → クライアント）、`tls_failures`（TLS / DTLS のハンドシェイクや STARTTLS の失敗） |
| `started_at` | 待ち受けを始めた時刻（Unix 秒）。`failed` のときは `null` |
| `cert_status` | `terminate` のルールが使う証明書の期限（下の「証明書の期限」）。証明書がなければ省く。各要素は `role`（`certificate` / `client_ca` / `client_chain` / `upstream_ca` / `upstream_certificate`）、`file`（証明書のファイル）、`not_after`（RFC 3339、UTC）、`days_left`（残りの日数。切れたら負）、`state`（`ok` / `expiring` / `expired`） |
| `origin` | `dynamic`（API で作ったルール、または DB から復元したルール）か `static`（固定ルール。下を参照） |

`stats` には `denied`（`allow_from` の範囲外、`crowdsec` の判定、または `unmatched: reject` で切断した接続の数）と、`dropped`（UDP で rproxy が転送できずに捨てたデータグラムの数：セッションの待ち行列があふれた、送信に失敗した、名前を読んでいるセッションが多すぎる。v0.3.9 から。カーネルのソケットの受信バッファがあふれて捨てたものは rproxy からは見えないので数えない）も含む。`GET /metrics` では `rproxy_udp_dropped_total{protocol,listen}`（UDP のルールだけ）。

#### データの完全性（L4）

- TCP：片方が閉じた（FIN）ときは、もう片方にも半分閉じた（FIN）として伝え、反対の向きはそのまま続ける。片方がリセット（RST）した、または書き込めなくなったときは、もう片方もリセットで切る（正常に終わったように見せない。`SO_LINGER` 0）。TLS を終端するルールでは、転送先がリセットしたらクライアントの TLS は close_notify なしで切れる。
- UDP：データグラムは 1 つずつそのまま、届いた順に転送する（まとめない・分けない・並べ替えない・重ねない）。rproxy が捨てたものは上の `dropped` に数える。
- tests/integrity.rs で、何十 MiB の擬似乱数のデータを流して SHA-256 を比べて確かめている（TCP の passthrough・terminate・`upstream.tls`・`proxy_v2`、UDP・DTLS、HTTP/1.1・HTTP/2・HTTP/3・WebSocket、`compress`・`buffering`・`retry`、転送先への接続の再利用）。`RPROXY_TEST_INTEGRITY_MB` で大きさを変えられ、CI（`.github/workflows/integrity.yml`）で毎週 512 MiB で動かす。
宛先が 2 つ以上か `health_check` のあるルールでは、`stats.targets` に宛先ごとの状態が入る（上の「複数の宛先」）。
`http` のルールでは、`stats.http` にリクエストの数も入る（ほかのルールでは省く）。

```json
"http": {"requests": 5, "by_status": {"2xx": 3, "4xx": 2},
         "routes": {"site": {"requests": 3, "by_status": {"2xx": 3}}, "(none)": {"requests": 1, "by_status": {"4xx": 1}}}}
```

`health_check` のあるサービスがあれば、`services` に転送先ごとの状態が入る（`{"app": [{"url": "http://10.0.0.20:80", "up": true}, ...]}`）。`rate_limit` / `in_flight` で断ったリクエストがあれば、`limited`（合計）とルートごとの `limited`（ミドルウェアの名前ごと）も入る。`crowdsec` で断ったリクエストは同じ形で `blocked` に入る（どちらも `by_status` の `4xx` にも数える）。

- `by_status` は状態コードの百の位ごと（`1xx`〜`5xx`。0 件の区分は省く）。`routes` はルートの名前ごとで、どのルートにも一致しなかったリクエストは `(none)`。
- 応答の本文を送り終えた（またはクライアントが切断した）ときに数える。

## 設定ファイル（固定ルール）

`RPROXY_CONFIG`（`--config`）に設定ファイル（またはそのディレクトリ）を指定すると、起動時にそのルールを開始し、ファイルが変わると再起動なしで反映する。0.2 の `RPROXY_STATIC_RULES`（`--static-rules`）も同じ意味で使える（両方は指定できない）。

- 形式は拡張子で決まる: `.yaml` / `.yml` は YAML（コメント、アンカー `&name` / `*name` が使える）、それ以外は JSON。YAML と JSON は同じ形で、同じ意味になる。
- 中身は次のどちらか。
  - `{"version": 1, "global": {...}, "rules": [...]}`（v0.3）
  - ルールの配列（0.2 の形）
- `rules` の各要素は `POST /rules` の本文と同じ形。
- `global` はプロセス全体の設定（`trusted_proxies`、`access_log`、`acme`、`crowdsec`。docs/DESIGN-v0.3.md の 2.）。この版で動かせない項目（`acme`）は、ログに `"event":"degraded"`（`part: global.<項目>`）を出して読み飛ばす。
  - `trusted_proxies`: CIDR の配列。`http` のルールで、接続元がこの範囲なら `X-Forwarded-For` を信用する（API で作ったルールにも効く）。
  - `crowdsec`: CrowdSec の bouncer（`crowdsec` ミドルウェアと、ルールの `crowdsec: true` が使う。書かずにそれらを使うと `invalid`、設定ファイルなら起動しない）。
    - `lapi_url`（例 `http://127.0.0.1:8080`）の `GET /v1/decisions/stream` を `update_interval`（既定 `10s`）ごとに呼び、判定を覚えておく（最初と、失敗した後は `startup=true` で全部を取り直す）。`X-Api-Key` は `api_key_file` の中身（`cscli bouncers add rproxy` で作ったキー。SIGHUP で読み直す）。
    - 使う判定は scope が `Ip` と `Range`、type が `ban` と `captcha`（captcha は出せないので ban として扱う）。ほかの scope（Country など）と type は使わない。
    - LAPI に届かないときは、それまでの判定を使い続け、間隔を倍々に延ばして（最大 5 分）取り直す（`crowdsec.error`。取得できたら `crowdsec.sync`）。一度も取得できていない間は、ミドルウェアの `on_error` に従う。
    - `appsec_url`（例 `http://127.0.0.1:7422`）: AppSec に問い合わせる（ミドルウェアの `appsec: true`。書かずに `appsec: true` を使うと `invalid`）。
    - `api_key_file` がないか空なら起動しない。読めない（権限）なら、読めるようになって SIGHUP するまで判定なしで動く（`part: global.crowdsec`）。
  - `access_log`: `http` のルールのアクセスログのファイル（JSON Lines。`RPROXY_LOG_FILE` と同じく日ごとに `<名前>.<日付>.<拡張子>` へローテーションし、`RPROXY_LOG_KEEP` 個残す）。省略するとアクセスログはメインのログ（`event: "http.access"`）に出す。ディレクトリがなければ起動しない。書き込めなければメインのログに出す（`part: global.access_log`）。
- ディレクトリを指定すると、その中の `*.yaml` / `*.yml` / `*.json` を名前の順に読み、1 つの設定としてまとめる（`.` で始まるものは読まない。Kubernetes の ConfigMap をそのままマウントできる）。
  - 各ファイルは上のどちらかの形。`rules` はつなげる。`global` を書けるのは 1 つのファイルだけ（2 つにあるとエラー）。
  - 同じキー（プロトコル・アドレス・ポート）のルールが 2 つあると、両方のファイル名と位置（`web.yaml rule #2` など）を示してエラーにする。
- DB からの復元より前に開始する。DB に接続できなくても動く。
- API からは変更・削除できない（`409 static`）。変えるときはファイルを書き換える。
- **再起動なしの反映**：`RPROXY_CONFIG_CHECK_SECS`（既定 10 秒。`0` なら SIGHUP のときだけ）ごとに、ファイルの大きさ・更新時刻・inode（ディレクトリならファイルの増減も）を確かめ、変わっていれば読み直す。SIGHUP を送ると、変わっていなくても読み直す。結果をその場で知りたいときは `POST /config/reload`（下のエンドポイントの表）。シンボリックリンクの差し替え（ConfigMap の更新）も検知する。
  - 読み直した設定は、まず全体を検証する。誤りがあれば何も変えず、それまでのルールを使い続ける（`event: "config.error"`。同じ内容では 1 回だけ）。読めない（権限）ときも同じで、読めるようになるまで確認のたびに試す。
  - 正しければ差分だけを反映する（`event: "config.reload"`。`added`・`removed`・`changed`・`unchanged`・`failed` の件数）。
    - 増えたルールは開始し、なくなったルールは停止する（既存の接続は切る）。
    - 変わったルールは、PATCH で変えられる項目（転送先、`udp_idle_secs`、`tls`、`starttls`、`allow_from`、`http`）だけの違いなら、そのまま変える（既存の接続は切らない。TCP は新しい接続から）。ポート範囲・`source_ip` などが変わったときは、停止してから作り直す。
    - 変わっていないルールには触らない（接続も切らない）。
    - 同じキーのルールが API（DB）から作られていれば、そちらを残してファイルのルールを `rule.failed` としてログに出す。
  - `global` の変更は再起動するまで効かない（`trusted_proxies`・`access_log`・`crowdsec`。起動時の値と違うと `config.reload` の警告と `GET /config` の `restart_needed` で知らせる）。
  - 状態は `GET /config` で見える：`{"configured":true,"path":"/etc/rproxy/conf.d","files":[...],"loaded_at":1790000000,"rules":5,"last_reload":{"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0},"error":null,"restart_needed":[]}`（設定ファイルを使っていなければ `{"configured":false}`）。`error` は最新の版を反映できなかった理由（それまでの版が動いている）。
- 反映する前に確かめる：`rproxy-api --check-config [PATH]` が、起動時・再読み込みと同じ検証（書式、ルールの値、待ち受けの重なり・制御 API との重なり、証明書・鍵・CA のファイルと期限、`global`、ミドルウェアの秘密のファイル）をして、問題がなければ 0、誤りがあれば 1 で終わる（待ち受けも DB も開かない。`--check-config-format json` で `{"ok","path","files","rules","errors":[{"rule","message"}],"warnings":[...]}`）。名前解決はしない。パッケージのユニットの `ExecReload` は、先にこの確認をする（誤りがあれば reload は失敗し、SIGHUP を送らない）。
- 同じキーや重なるポートのルールを API や DB から作ろうとすると、`already_exists` になる。
- ファイルが存在しない、書式や形が不正（知らないキー、`version` が 1 以外、存在しない ACME の resolver の参照など）の場合は、rproxy は起動しない。読めない（権限）ときは、固定ルールなしで起動する。
- この版で動かせない機能（`GET /capabilities` の `features` が false）を使うルールは、`failed`（理由つき）として登録し、設定の内容は `GET /rules` で見える。名前解決や bind の失敗はほかのルールと同じ扱いになる。

例：ダッシュボード（Web UI）を `dashboard.proxy.home` だけで、社内から公開する。

```yaml
# /etc/rproxy/rproxy.yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 127.0.0.1
    remote_port: 3001
    allow_from: [172.16.0.0/16]
    tls:
      mode: terminate
      certificates:
        - cert_file: /etc/rproxy/certs/dashboard.pem
          chain_file: /etc/rproxy/certs/intermediates.pem
          key_file: /etc/rproxy/certs/dashboard.key
      routes:
        - {server_name: dashboard.proxy.home, remote_addr: 127.0.0.1, remote_port: 3001}
      unmatched: reject
```

## v0.3 の設定（L7・ACME・TLS のオプション）

v0.3.0 で形を決め、中身は v0.3.x のパッチで順に使えるようにする（docs/RELEASING.md）。この版で動かせるかは `GET /capabilities` の `features` で分かる。動かせない設定を使うルールは、形を検証したうえで `400 unsupported` で断る（形が不正なら `400 invalid` / `tls_config`）。設計の全体と例は docs/DESIGN-v0.3.md。

| 項目 | 場所 | 形 | features |
|---|---|---|---|
| L7 のルーティング | ルールの `http` | `routes`（`name`、`match`、`priority`、`service` か `to`、`middlewares`）、`default`、`services`、`middlewares`、`http3` | `http`（v0.3.1 から）、`http3`（v0.3.2 から）、`middlewares` |
| サービス | `http.services.<名前>` | `servers`（`url`、`weight`）、`pass_host_header`、`timeouts`（`connect`、`response`）、`health_check`、`sticky`、`balance` | `http`。`health_check` / `sticky` / `balance` は `services` に含まれるもの |
| `match` | `http.routes[].match` | Traefik と同じ式。`Host`・`HostRegexp`・`Path`・`PathPrefix`・`PathRegexp`・`Method`・`Header`・`HeaderRegexp`・`Query`・`QueryRegexp`・`ClientIP` を `&&`・`\|\|`・`!`・括弧で組み合わせる | `http` |
| ミドルウェア | `http.middlewares.<名前>` | `{種類: {設定}}`。種類は `redirect_scheme`・`redirect_regex`・`rate_limit`・`in_flight`・`crowdsec`・`ip_allow`・`headers`・`forward_auth`・`oidc`・`basic_auth`・`strip_prefix`・`add_prefix`・`replace_path`・`replace_path_regex`・`compress`・`buffering`・`retry`・`circuit_breaker`・`errors`・`respond` | `middlewares` に種類が含まれるもの |
| ACME の証明書 | `tls.certificates[]` | `{"acme": "<resolver>", "domains": [...]}`（`cert_file` / `key_file` の代わり）。**内蔵しない方針にしたため使えない**（常に `unsupported`）。外部のツールで取ったファイルを使う（上の「TLS」） | `acme`（常に false） |
| TLS のオプション | `tls.options` | `min_version`（`"1.2"` / `"1.3"`）、`cipher_suites`（下） | `tls_options`（v0.3.2 から true） |

- `tls.options`（v0.3.2）は tcp の `terminate`（`http` のルールを含む）の、クライアントとの TLS に効く。転送先への TLS（`upstream`）には効かない。UDP（DTLS）では使えない（`unsupported`）。
  - `min_version`: `"1.3"` で TLS 1.2 のクライアントを断る。省略・`"1.2"` なら 1.2 と 1.3。
  - `cipher_suites`: 使う暗号スイートの名前（rustls の名前。TLS 1.3 は `TLS13_AES_128_GCM_SHA256`・`TLS13_AES_256_GCM_SHA384`・`TLS13_CHACHA20_POLY1305_SHA256`、TLS 1.2 は `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`・`TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` など）。知らない名前は `tls_config`（エラーに使える名前の一覧が出る）。書いたスイートがない版は提示しない（TLS 1.3 のスイートだけを書けば TLS 1.3 だけになる）。`min_version: "1.3"` で TLS 1.3 のスイートが 1 つもないと `tls_config`。
  - 鍵交換の曲線と、一致しない SNI を断る設定（Traefik の sniStrict。rproxy では `tls.unmatched: reject`）は `options` にはない。
  - 決まった版と暗号スイートは `conn.open` の `tls_version` / `tls_cipher` に出る。
- `http` は `protocol: tcp` で、`tls.mode` が `terminate`（HTTPS）か、TLS なし（平文の HTTP）のときだけ。`sni`・`starttls`・ポート範囲とは組み合わせられない。`remote_addr` / `remote_port` は書かない（書くと `400 invalid`）。
- `http` のルールでも、`tls.routes` の `passthrough: true` の route は使える（同じポートで、その名前だけを終端せずに流す。例：cdn・gitlab は L7、registry と `**.tenant.example.com` は Kubernetes へそのまま）。passthrough でない `tls.routes` と `unmatched: reject` は `tls_config`（振り分けは `http.routes`、一致しないときは `http.default`）。
- `http.http3: true`（v0.3.2）で、同じアドレス・ポートの UDP でも QUIC + HTTP/3 を受ける。
  - `tls.mode: terminate` のときだけ（TLS なしなら `400 tls_config`）。`source_ip: transparent` とは組み合わせられない（`unsupported`）。
  - 証明書・クライアント認証（`client_auth`）は TCP と同じもの。QUIC は TLS 1.3 だけなので、`tls.options.cipher_suites` に TLS 1.3 の暗号スイートが要る（`TLS13_AES_128_GCM_SHA256` がないと QUIC の初期化に使えない）。証明書の読み直し（SIGHUP、`RPROXY_CERT_CHECK_SECS`）は新しい QUIC 接続から効く。
  - リクエストは HTTP/1.1・HTTP/2 と同じルート・ミドルウェア・転送先に渡る（転送先へは HTTP/1.1）。本文は流しながら送る。アクセスログの `protocol` は `HTTP/3.0`。
  - `allow_from` とルールの `crowdsec` は QUIC の接続を受ける前に確かめる（`conn.denied`、`transport: quic`）。
  - TCP 側（HTTP/1.1・HTTP/2）の応答には `Alt-Svc: h3=":<ポート>"; ma=86400` を付ける（転送先が `Alt-Svc` を返したときはそのまま）。HTTP/3 を受けていないあいだは付けない。
  - UDP のポートを使えない（使用中・権限）、または TLS の設定が QUIC に使えないときは、ルールは TCP だけで動き、`stats.http.http3` に `{"listening": false, "error": "..."}` と出る（ログは `event: degraded`、`part: http3`）。受けているときは `{"listening": true}`。`http3` のないルールには `http3` の項目がない。
  - `PATCH` で `http3` を付け外しすると、UDP の待ち受けを始める・止める（止めると開いている QUIC 接続は切る）。受けられなかったルールは、`http3: true` のまま `http` を PATCH するともう一度試す。ルールを削除すると UDP のポートも閉じる。
  - ファイアウォールでは TCP と同じポートの UDP も開ける。
- `PATCH` で `http` を付けると、L7 の設定を丸ごと置き換える（次のリクエストから）。`http` のないルールに `PATCH` で `http` を付けることはできない（`unsupported`。作り直す）。

### `http` のルールの動き（v0.3.1）

- クライアントとは HTTP/1.1 と HTTP/2 で話す。`terminate` では、`tls.alpn` を指定していなければ ALPN で `h2` と `http/1.1` を提示する（`GET /rules` の `tls.alpn` は指定どおりのまま）。平文では HTTP/1.1 と、前置きで始まる HTTP/2（h2c）を受ける。
- ルートは `priority` の大きい順（省略時は `match` の文字数。Traefik と同じ）、同じなら書いた順に試し、最初に一致したものを使う。どれにも一致しなければ `default`（`service` か `status`。省略時は 404）。
- `Host` はポートを除き、大文字小文字を区別しない。HTTP/2 では `:authority` を使う。`ClientIP` はクライアントの IP：接続元、または接続元が `global.trusted_proxies` の範囲なら、`X-Forwarded-For` を右から見て最初の信頼しないアドレス（Traefik と同じ。クライアントが左に書き足したアドレスは使わない）。`ip_allow`・`X-Real-IP`・アクセスログも同じ IP を使う。
- `match` の式の上限（v0.3.18）：括弧と `!` の入れ子は 32 段まで、1 つの式に書ける条件（`Host(...)` など。引数の数は数えない）は 256 個まで。超えると設定の誤り（API は 400、設定ファイルは起動・再読み込み・`--check-config` の誤り）。
- 時間の値（`10s`・`500ms`・`1m`・`2h` の形。`period`・`timeouts`・`health_check` の `interval` / `timeout`・`initial_interval`・`window` / `recovery`・`update_interval` など）は 365 日（`8760h`）まで（v0.3.18）。それより長い値は設定の誤り。
- 転送先とは HTTP/1.1 で話す。`servers` は `weight`（既定 1）の重みつきラウンドロビン。`url` にパスがあれば、リクエストのパスの前に付ける。`https://` の転送先の証明書は、ルールの `tls.upstream` の `ca_file`（なければ Mozilla のルート）で検証し、`server_name` / `insecure_skip_verify` / クライアント証明書もそれに従う。`tls.upstream.tls` は使わない（URL の `https://` で決まる。指定すると `tls_config`）。
- 転送先への接続は、応答の本文を読み終えたあと、次のリクエストに使い回す（転送先ごとに待機中の接続は 32 本まで。`source_ip: transparent` のルールでは、送信元がクライアントごとに違うので使い回さない）。使い回そうとした接続を転送先が閉じていたら、新しい接続で送り直す。
- `health_check`（v0.3.2）: `interval`（既定 `10s`）ごとに各 `servers` へ `GET <URLのパス><path>`（`Host` は転送先のホスト）を送り、`timeout`（既定 `3s`）以内に 2xx / 3xx が返れば up、そうでなければ down。down の転送先はラウンドロビンから外し、戻れば入れる。最初の確認までは up として扱う。すべて down なら 503。状態が変わると `event: "http.health"` のログ（`service`、`server`、`up`、down の理由の `error`）。ルールの `stats.http.services.<サービス名>` に `[{"url","up"}]`、`/metrics` に `rproxy_http_server_up{protocol,listen,service,server}`（1 / 0）。
- `balance`（v0.3.3）: `round_robin`（既定。`weight` の比率）、`least_conn`（処理中のリクエストが `weight` あたり一番少ない転送先）、`failover`（`servers` の上から順に、up の最初の転送先）。どれも down の転送先は外す（`health_check` の結果）。`sticky` のクッキーの転送先が up なら、そちらが優先。
- `sticky`（v0.3.2）: 初めてのクライアントには、選んだ転送先を示すクッキー（`<cookie>=<URL から作った 16 桁の値>; Path=/; HttpOnly; SameSite=Lax`、HTTPS なら `Secure` も）を付け、以後そのクッキーの転送先へ送る。その転送先が down か、知らない値なら選び直してクッキーを付け直す。値は URL から作るので、rproxy を再起動してもほかの転送先を足しても変わらない。
- `weight` で転送先を切り替えられる（例：新しい版を `weight: 1`、今の版を `weight: 9` にして 1 割だけ流す）。
- `pass_host_header`（既定 true）が false なら、`Host` は転送先の URL のホスト（とポート）にする。
- 転送先へは `X-Forwarded-For`・`X-Real-IP`（クライアントの IP）、`X-Forwarded-Proto`（`http` / `https`）、`X-Forwarded-Host`、`X-Forwarded-Port` を付ける。クライアントが送ってきた同名のヘッダは置き換える。ただし接続元が `global.trusted_proxies` の範囲なら、`X-Forwarded-For` は受けた値の後ろに接続元を足し、`X-Forwarded-Proto` / `-Host` / `-Port` は受けた値を保つ。ホップごとのヘッダ（`Connection` とそこに書かれたもの、`Keep-Alive`、`TE`、`Transfer-Encoding` など）は取り除く。
- `Connection: Upgrade`（WebSocket など）は、転送先が 101 を返せばそのまま中継する。ルールを削除すると切れる。
- 転送先に接続できなければ 502、`timeouts.connect`（既定 5 秒）・`timeouts.response`（既定 60 秒）を過ぎると 504。`event: "http.error"` のログを出す。`timeouts.response` は、リクエストの本文を送り終えてから応答ヘッダが届くまでの時間（アップロードにかかる時間は含めない。応答の本文にも上限はない）。

### HTTP の転送の扱い

rproxy はクライアントとは HTTP/1.1・HTTP/2・HTTP/3 で、転送先とは HTTP/1.1 で話す。そのあいだで次のように扱う（tests/http_semantics.rs で HTTP/1.1・HTTP/2・HTTP/3 のクライアントから確かめている）。

| 項目 | 扱い |
|---|---|
| `Cookie` | HTTP/2・HTTP/3 で複数のフィールドに分けて届いたもの（Chrome はそうする）は `"; "` で 1 本にまとめる（RFC 9113 §8.2.3 / RFC 9114 §4.2.1）。まとめたものをミドルウェア（`oidc`・`sticky`・`forward_auth`）も読む |
| `Set-Cookie` | 転送先の複数の `Set-Cookie` は 1 本ずつそのままクライアントへ（まとめない。`compress`・`headers` を通っても同じ）。`Domain` / `Path` / `Secure` などの属性、`Location` は書き換えない |
| そのほかのヘッダ | 同じ名前の複数のフィールドは順番どおり、値はバイトのまま（ASCII 以外も）渡す。`Authorization` は渡す |
| ホップごとのヘッダ | 両方向で取り除く：`Connection` とそこに書かれた名前、`Keep-Alive`、`Proxy-Connection`、`Proxy-Authenticate`、`Proxy-Authorization`、`TE`、`Trailer`、`Transfer-Encoding`、`Upgrade`（WebSocket などの `Upgrade` は付け直して中継する）。`Via` と `Forwarded`（RFC 7239）は付けない（Traefik・nginx の既定と同じ。`X-Forwarded-*` を使う） |
| `Host` | HTTP/2・HTTP/3 の `:authority`、HTTP/1.1 の absolute-form の宛先（`GET https://a.example/ HTTP/1.1`）の authority を、`Host` フィールドより優先する（RFC 9112 §3.2.2）。転送先には origin-form（パスとクエリ）で送る。`pass_host_header: false` なら転送先の URL のホスト |
| ヘッダの大きさ | HTTP/2・HTTP/3 は 1 リクエストのヘッダの合計 64 KiB まで（hyper の既定の 16 KiB では、大きなクッキーのブラウザで足りない）。HTTP/1.1 は約 400 KB まで。超えると 431 |
| 本文 | 流しながら中継する（`buffering` がなければため込まない）。chunked、`Expect: 100-continue`、`HEAD`（`Content-Length` を保つ）、`204` / `304` に対応 |
| タイムアウト | `timeouts.response` は本文を送り終えてから応答ヘッダまで。長いダウンロード・SSE・ロングポーリングの応答の本文は切らない |
| 途中で切れた応答 | 転送先が応答の途中で切れたら（`Content-Length` に足りない、chunked の最後のチャンクがない、リセット）、クライアントにも完全な応答に見えないように切る：HTTP/1.1 は足りないまま接続を閉じる（chunked なら最後のチャンクを送らない）、HTTP/2 は RST_STREAM、HTTP/3 は RESET_STREAM。`compress` を通していても同じ（圧縮の終わりを付けない）。長さのない（接続を閉じて終わる）HTTP/1.0 型の応答は、転送先の側で途中かどうかが分からない |
| 途中で切れたリクエスト | クライアントが本文の途中で切れたら（HTTP/1.1 の切断、HTTP/2 の RST_STREAM、HTTP/3 のリセット）、転送先への接続も本文を終えずに切り、転送先に完全なリクエストとして渡さない |
- アクセスログ（`event: "http.access"`）はリクエストごとに 1 行：`rule`、`route`（一致しなければ `(none)`）、`service`、`backend`、`client`、`method`、`host`、`path`（クエリは含めない）、`query`（クエリ。`?` なし、なければ空。v0.3.8 から。秘密になりやすい名前のパラメータ（`token`・`code`・`state`・`password`・`secret`・`key`・`signature`・`auth`・`session` などを名前に含むもの）は値を `REDACTED` に置き換える。GitLab の `private_token`、OIDC の `code` / `state` などをログに残さないため）、`protocol`（`HTTP/1.1` / `HTTP/2.0`）、`status`、`duration_ms`（応答の本文を送り終えるまで）、`bytes_in`（`Content-Length`）、`bytes_out`（応答の本文）、`user_agent`、`sni`、`tls_version`。出す先は `global.access_log`。
- `GET /metrics` の `rproxy_http_requests_total{protocol,listen,route,code}`（`code` は `2xx` など）と `rproxy_http_request_duration_seconds{protocol,listen,route}`（ヒストグラム。境界は 5ms〜10s）、`rproxy_http_limited_total{protocol,listen,route,middleware}`（`rate_limit` / `in_flight` で断った数）、`rproxy_http_blocked_total{protocol,listen,route,middleware}`（`crowdsec` で断った数）。`global.crowdsec` があれば `rproxy_crowdsec_decisions`（判定で止めているアドレスと範囲の数）と `rproxy_crowdsec_synced`（LAPI から一度でも取得できたら 1）。ラベルにパスは入れない。
- ミドルウェアはルートの `middlewares` に書いた順にリクエストへ働き、応答へは逆の順に働く（Traefik と同じ）。途中のミドルウェアが応答を返したら（リダイレクト・`respond`・拒否）、その先へは進まない。その応答にも、それまでに通ったミドルウェアの応答側（`headers` など）が働く。
- 使えるミドルウェア（v0.3.1。`features.middlewares`）:
  - `redirect_scheme`: `scheme` と違う方式で受けたリクエストを、同じホスト・パス・クエリの `scheme://` へリダイレクトする。`port` は既定のポート（80 / 443）なら省く。
  - `redirect_regex`: `http://host[:port]/path?query`（受けた URL）が `regex` に一致すれば、`replacement`（`$1`・`${name}` が使える）へリダイレクトする。一致しなければ次へ進む。
  - リダイレクトの状態コードは、`permanent` なら 301、そうでなければ 302。GET / HEAD 以外は 308 / 307（メソッドと本文を保つ）。
  - `respond`: `status`・`body`・`content_type`（既定 `text/plain; charset=utf-8`）で応答する。`service` のないルート（ブロックやメンテナンス表示）に使う。
  - `ip_allow`: 接続元の IP が `source_range` になければ 403。
  - `headers`: `request` / `response` の `set`（空の値は削除）・`remove`。`frame_deny`（`X-Frame-Options: DENY`）、`content_type_nosniff`、`referrer_policy`、`csp`。`hsts` は HTTPS で受けたときだけ付ける。`cors` は `Origin` が `allow_origins`（`*` も可）にあるとき `Access-Control-Allow-Origin`（`allow_credentials` なら `Access-Control-Allow-Credentials` も）と `Vary: Origin` を付け、プリフライト（`OPTIONS` と `Access-Control-Request-Method`）には rproxy が 204 で答える。
  - `rate_limit`: トークンバケット。`period`（既定 `1s`）あたり平均 `average` 件、一度に `burst` 件まで（既定 1。Traefik と同じく、省くと 1 件ずつしか通さない）。超えたら 429 と `Retry-After`（秒）。`source` は `ip`（既定。`global.trusted_proxies` を反映したクライアントの IP）か `header:<名前>`（そのヘッダの値ごと。ヘッダがなければクライアントの IP）。
  - `in_flight`: クライアントの IP ごとに、同時に処理するリクエストを `amount` 件まで（超えたら 429）。応答の本文を送り終えたとき（WebSocket なら接続が終わったとき）に空く。
  - `crowdsec`: クライアントの IP（`global.trusted_proxies` を反映）が LAPI の判定にあれば 403。`appsec: true` なら、続けて AppSec にリクエストを問い合わせ、403 が返れば 403（`X-Crowdsec-Appsec-Ip` / `-Uri` / `-Host` / `-Verb` / `-Api-Key` / `-User-Agent` / `-Http-Version` と元のヘッダを送る。本文は `Content-Length` が 1 MiB 以下のときだけ送り、それより大きいか長さのない本文はヘッダだけで問い合わせる）。`on_error`（既定 `allow`）は、LAPI から一度も取得できていないときと AppSec に問い合わせできないとき（時間切れ 3 秒、200 / 403 以外の応答）に通すか 403 にするか。
  - `rate_limit` / `in_flight` の数はルールの `http` を変えると最初からになる。覚えておく送信元は 1 つのミドルウェアで 10 万件まで（超えたら長く使っていない方から半分を忘れる）で、満杯に戻ったバケットは定期的に捨てる。
  - `strip_prefix`: パスが `prefixes` のどれか（先に書いたもの優先）で始まれば取り除き、`X-Forwarded-Prefix` を付ける。`add_prefix`: パスの前に付ける。`replace_path`: パスを置き換え、元のパスを `X-Replaced-Path` に入れる。`replace_path_regex`: 一致したときだけ置き換える（`X-Replaced-Path` も）。クエリは保つ。
- v0.3.2 で使えるようになったミドルウェア:
  - `compress`: クライアントの `Accept-Encoding` に合わせて応答を `br`・`zstd`・`gzip` で圧縮する。`encodings`（既定 `[br, zstd, gzip]`）は使う形式と優先順（`q` 値が同じときの順）。`min_size`（既定 1024 バイト）より `Content-Length` が小さい応答、すでに `Content-Encoding` のある応答、画像（SVG を除く）・動画・音声・`font/woff*`・圧縮済みの形式（zip・gzip・zstd・pdf など）・`text/event-stream`・gRPC、`Cache-Control: no-transform`、HEAD・204・206・304 はそのまま。圧縮したら `Content-Length` を外し、`Vary: Accept-Encoding` を足し、強い `ETag` を弱い `W/` にする。本文は流れてきた分ずつ圧縮して送る（長く続く応答も止めない）。
  - `buffering`: リクエストの本文を先に読み切る。`max_request_body`（バイト）を超えたら 413（`Content-Length` で分かればすぐに、分からなければ読みながら）で、転送先には送らない。読み切った本文は `retry` で送り直せる。
  - `retry`: 転送先に接続できない・応答がない（502 / 504 になるもの）ときに、次の転送先へ送り直す。`attempts` は最初の 1 回を含む回数、`initial_interval`（既定 `100ms`）は最初の待ち時間で、回ごとに倍になる。送り直すのは冪等なメソッド（GET・HEAD・OPTIONS・PUT・DELETE・TRACE）で、本文がないか、`buffering` で読み切った本文のときだけ（WebSocket などの Upgrade は送り直さない）。転送先が返した 5xx は送り直さない。
  - `circuit_breaker`: 応答のうち 5xx（502 / 504 を含む）の割合が `window` の中で `failure_percent` 以上になったら（10 件以上あるときに判定）、`recovery` のあいだ転送先へ送らずに 503 を返す。`recovery` を過ぎたら 1 件だけ通し、成功すれば元に戻し、失敗すればまた `recovery` だけ止める。状態は `event: "http.breaker"` のログ。数はルールの `http` を変えると最初からになる。
  - `errors`: 応答の状態コードが `status`（`"500-599"`・`"404"` のような範囲か値）に入れば、`service` の `path`（`{status}` は状態コードに置き換える）を GET し、その本文とヘッダで返す。状態コードは元のまま。ページを取れなければ元の応答を返す。メンテナンス表示には、`respond` のルートを `priority` を上げて一時的に足すか、`errors` のページを使う。
- 認証のミドルウェア（v0.3.2、#59）。HTTP/1.1・HTTP/2・HTTP/3 のどのリクエストにも働く:
  - `basic_auth`: `users_file`（htpasswd 形式。bcrypt `$2y$`（`htpasswd -B`）・`$apr1$`（`htpasswd` の既定）・`{SHA}` を読む。ほかの形式や平文の行があればファイル全体を誤りとして扱う）の利用者だけを通す。通らなければ 401 と `WWW-Authenticate: Basic realm="<realm>"`（`realm` の既定 `rproxy`）。
    - 通ったリクエストの `Authorization` は転送先に渡さない（`keep_authorization: true` で渡す。Traefik の既定の `removeHeader: false` と同じにするならこちら）。`user_header`（例 `X-Forwarded-User`）を書くと、利用者の名前をそのヘッダで渡す（クライアントが送った同名のヘッダは取り除く）。
    - bcrypt の照合は別のスレッドで行い、通った組み合わせは覚えておく（ファイルが変われば忘れる）。
  - `forward_auth`: リクエストごとに `address` へ `GET` を送り、2xx なら通す（Traefik の forwardAuth と同じ）。
    - 認証サーバへは、クライアントのヘッダ（`request_headers` を書けばその名前だけ。ホップごとのヘッダと `Host` は除く）と、`X-Forwarded-Method`・`X-Forwarded-Proto`・`X-Forwarded-Host`・`X-Forwarded-Uri`（パスとクエリ）・`X-Forwarded-For` を送る。`trust_forward_header: false`（既定）ならクライアントが送った `X-Forwarded-*` は捨てて付け直し、true なら受けた値を保つ（`X-Forwarded-For` は後ろに接続元を足す）。
    - 2xx なら、認証サーバの応答のうち `response_headers` に書いたヘッダで、転送先へのリクエストの同名のヘッダを置き換える。2xx 以外（401・302 のサインイン画面へのリダイレクトなど）は、その応答をそのままクライアントに返す。
    - 認証サーバに接続できなければ 502、`timeout`（既定 `10s`）以内に答えがなければ 504（`event: "http.error"`）。認証サーバへの接続は使い回す。
  - `oidc`: OpenID Connect（Keycloak など）のサインイン（認可コードフロー + PKCE）。oauth2-proxy なしで保護できる。
    - `issuer`（例 `https://sso.example.com/realms/main`）の `/.well-known/openid-configuration` を最初に使うときに読む（失敗したら 10 秒おいて試し直す）。HTTPS の証明書は `ca_file`（なければ Mozilla のルート）で検証する。
    - プロバイダには、クライアント `client_id`（confidential。シークレットは `client_secret_file` の 1 行目、client_secret_basic で送る）と、リダイレクト URI `https://<ホスト><callback_path>`（`callback_path` の既定 `/_rproxy/oidc/callback`）を登録する。`scopes` は `openid` に足すスコープ（例 `[profile, email]`）。
    - サインインしていない GET / HEAD はプロバイダのサインインへ 302（元の URL はサインイン後に戻る。戻り先は同じサイトのパスだけ）。それ以外のメソッドは 401。
    - `callback_path` と `logout_path`（既定 `/_rproxy/oidc/logout`）はどのルートに一致したかにかかわらず、この `oidc` ミドルウェアが答える（ルートの `match` に含めなくてよい）。ログアウトはクッキーを消して、プロバイダの `end_session_endpoint` へ `client_id` と `post_logout_redirect_uri=<scheme>://<ホスト>/` を付けて送る（プロバイダ側に許可する URI として登録する）。
    - ID トークンは JWKS（RS256/384/512・PS256/384/512・ES256/384。知らない `kid` なら 1 分に 1 回まで取り直す）で署名を確かめ、`iss`・`aud`（`client_id` を含む）・`exp`・`nonce` を確かめる。
    - セッションはクッキー `cookie_name`（既定 `_rproxy_oidc`。`HttpOnly`・`SameSite=Lax`、HTTPS なら `Secure`）に AES-256-GCM で暗号化して持つ（中身は利用者の名前・メール・グループ・期限・リフレッシュトークン）。鍵は `cookie_secret_file` の 1 行目（16 文字以上。`openssl rand -base64 32` など）から作る。変えるとすべてのセッションが無効になる。
    - ID トークンの期限の 30 秒前を過ぎたら、リフレッシュトークンで取り直してクッキーを付け直す。取り直せなければサインインし直す。
    - 転送先へは `X-Forwarded-User`（`preferred_username`、なければ `email`、なければ `sub`）・`X-Forwarded-Sub`・`X-Forwarded-Email`・`X-Forwarded-Groups`（`groups_claim`（既定 `groups`、ドット区切りで `realm_access.roles` なども）の値をカンマ区切り）を付ける。クライアントが送った同名のヘッダと、rproxy のクッキーは取り除く。Keycloak ではクライアントに「Group Membership」のマッパーを足すと `groups` が入る。
    - サインイン・ログアウト・失敗は `event: "oidc.login"` / `"oidc.error"` / `"oidc.refresh"`。
  - 秘密のファイル（`users_file`・`client_secret_file`・`cookie_secret_file`）がない・中身が誤っていれば `invalid`（設定ファイルなら起動しない）。読めない（権限）なら起動は続け、そのミドルウェアを通るリクエストに 503 を返す。ファイルは変わったら（数秒以内に）読み直し、SIGHUP でも読み直す。読み直しに失敗したら今の中身を使い続ける（`reload.secret` の警告）。所有者とモードは docs/PERMISSIONS.md。
- `source_ip` は `proxy` か `transparent`（転送先への接続の送信元をクライアントにする）。`proxy_v1` / `proxy_v2` は使えない（`invalid`。クライアントの IP は `X-Forwarded-For` で渡す）。`tls.routes` も使えない（`tls_config`。`Host(...)` で振り分ける）。
- 接続の統計（`stats`）はクライアントとの接続単位で、`rx_bytes` はクライアントから、`tx_bytes` はクライアントへのバイト数。
- DB の `options` 列の JSON にも `http` を保存できる（`{"tls", "starttls", "starttls_required", "allow_from", "http", "crowdsec", "targets", "balance", "health_check"}`。`crowdsec` は v0.3.2、`targets` / `balance` / `health_check` は v0.3.3 から）。`targets` が空でなければ `dist_addr` / `dist_port` は読まない（UI は `''` / `0` を入れる）。

## エンドポイント

| メソッドとパス | 本文 | 成功時 | 説明 |
|---|---|---|---|
| `GET /healthz` | | 200 `ok` | 認証不要 |
| `GET /capabilities` | | 200 | `{"source_ip":[...],"transparent":true,"transparent_ipv6":true,"tls_modes":["passthrough","sni","terminate"],"dtls":true,"starttls":["smtp","imap","pop3"],"max_range_ports":20000,"features":{"http":true,"http3":true,"acme":false,"tls_options":true,"middlewares":["redirect_scheme","redirect_regex","ip_allow","headers","strip_prefix","add_prefix","replace_path","replace_path_regex","respond","rate_limit","in_flight","crowdsec","compress","buffering","retry","circuit_breaker","errors"],"services":["health_check","sticky","balance"]}}`。`features` はこの版で動かせる v0.3 の設定（上の「v0.3 の設定」）。`source_ip` の `transparent` は `IP_TRANSPARENT` が使えるときだけ含まれる。`transparent_ipv6` は IPv6 の待ち受けで transparent を使えるか（`IPV6_TRANSPARENT`） |
| `GET /openapi.json` | | 200 | この API の OpenAPI 3.0 の定義（`docs/openapi.json` と同じ）。どのトークンでも読める |
| `GET /config` | | 200 | 設定ファイル（`RPROXY_CONFIG`）の状態（上の「設定ファイル」）。`rules:read` |
| `POST /config/reload` | | 200 | 設定ファイルをその場で読み直して反映し、結果を返す：`{"added","removed","changed","unchanged","failed","restart_needed":[...],"files":[...],"rules","warnings":[{"rule","message"}]}`。誤りがあれば何も変えずに `400 {"code":"invalid","error","errors":[...],"warnings":[...]}`（`errors` は `--check-config` と同じ検証の結果）。設定ファイルがなければ `409 no_config`。`admin` のスコープが要る（トークンファイルを使っていなければ、ほかのエンドポイントと同じく誰でも使える）。既定では Unix ソケット（`RPROXY_API_SOCKET`）から来たリクエストだけを受け付け、TCP からは `403`（`RPROXY_API_RELOAD_UNIX_ONLY=false` で TCP も受け付ける）。ファイルの変化の検知・SIGHUP と同じ処理で、同時には動かない。`event=audit`（`action: config.reload`）に残る |
| `GET /interfaces` | | 200 | 待ち受けに使えるアドレス：`{"interfaces":[{"name":"ens18","addr":"172.16.5.1","family":"ipv4","loopback":false,"link_local":false}, ...],"reserved":[{"protocol":"tcp","addr":"127.0.0.1","port":8080,"purpose":"control API"}]}`。動作中のインターフェースだけを返す。`reserved` は rproxy 自身が使うアドレスで、ルールには使えない |
| `GET /rules` | | 200 | ルールの配列 |
| `GET /rules/{protocol}/{listen_addr}/{listen_port}` | | 200 | ルール 1 件 |
| `POST /rules` | ルール | 201 | 転送を開始する。名前解決と bind まで済ませてから応答する |
| `PATCH /rules/{protocol}/{listen_addr}/{listen_port}` | `{"remote_addr","remote_port"` または `"targets"`, `"balance"?,"health_check"?,"udp_idle_secs"?,"tls"?,"starttls"?,"starttls_required"?,"allow_from"?,"crowdsec"?,"extra_listen_addrs"?}` | 200 | 転送先を変える。`extra_listen_addrs` を付けると追加の待ち受けアドレスを丸ごと置き換える（`[]` ですべて外す。省けば今のまま）：足したアドレスだけを開き、外したアドレスだけを閉じる（ほかのアドレスと、外したアドレスで開いている接続はそのまま）。`::` で待ち受けるルールで、追加のアドレスの有無（dual-stack と IPv6 だけ）が変わる変更は `unsupported`（作り直す）。転送先（`remote_addr` / `remote_port` か `targets`、`balance`、`health_check`）は毎回まとめて置き換える：省いた `balance` は `round_robin`、省いた `health_check` はなし。宛先 1 つに戻すときは `remote_addr` / `remote_port` を送る（`"targets": []` は付けてもよい）。`crowdsec` を付けると、判定での切断を有効・無効にする（次の接続から）。新しい接続から即時に反映する。`tls` を付けると TLS の設定を丸ごと置き換える（`starttls` も一緒に指定する。省略すると STARTTLS なし）。`source_ip` とポート範囲は変更できない |
| `DELETE /rules/{protocol}/{listen_addr}/{listen_port}?drain_secs=N` | | 204 | 転送を停止する。既存の接続は即座に切断する。`drain_secs` を付けた場合は、その秒数だけ既存の接続の終了を待ってから切断する |
| `GET /metrics` | | 200 | Prometheus 形式。`http` のルールのリクエストは `rproxy_http_requests_total`・`rproxy_http_request_duration_seconds`・`rproxy_http_limited_total`、転送先のヘルスチェックは `rproxy_http_server_up`（上の「v0.3 の設定」） |

IPv6 の `listen_addr` をパスに入れるときは URL エンコードする。

## エラー

失敗時は次の形で返す。

```json
{"error": "address already in use (os error 98)", "code": "bind_failed"}
```

| `code` | HTTP | 意味 |
|---|---|---|
| `unauthorized` | 401 | トークンがない、一致しない、または期限切れ |
| `forbidden` | 403 | トークンのスコープ、または `allow_listen_ports` の外 |
| `invalid` | 400 | 本文やパスが不正 |
| `tls_config` | 400 | TLS の設定の組み合わせが不正、または証明書・鍵・CA のファイルを読めない |
| `unsupported` | 400 | この環境では使えない指定（`transparent` など）、または変更できない項目 |
| `not_found` | 404 | ルールがない |
| `already_exists` | 409 | 同じキーのルールが既にある |
| `static` | 409 | 固定ルールは API から変更・削除できない |
| `reserved` | 409 | rproxy 自身の制御 API のアドレスとポートに重なる（`0.0.0.0` / `::` とポート範囲も含めて判定する） |
| `bind_failed` | 409 | 待ち受けポートを開けない |
| `resolve_failed` | 502 | 転送先の名前解決に失敗し、キャッシュもない |
| `internal` | 500 | その他 |

## API・設定ファイル・UI（DB）の関係

rproxy のルールには 3 つの出どころがある。どれも `GET /rules` に出る。

| 出どころ | `origin` | 正はどこか | 変え方 |
|---|---|---|---|
| 設定ファイル（`RPROXY_CONFIG`） | `static` | ファイル | ファイルを書き換える（自動で反映）。API からは `409 static` |
| UI（TCP-UDP-rproxy-ui） | `dynamic` | UI の DB（`forward_rules`） | UI から。UI は DB に書いてから rproxy の API を呼ぶ。rproxy は起動時に DB から復元する |
| API を直接呼ぶ（CI・スクリプト） | `dynamic` | rproxy のメモリだけ | API から。DB には書かれないので、rproxy を再起動すると消える |

- 長く残すルールは、設定ファイルか UI（DB）で作る。API を直接呼んで作ったルールは一時的なもの（CI のプレビュー環境など）として扱う。
- UI は DB にないルールを編集しない。API で作ったルールは UI の一覧に出ず、DB にあるが rproxy にないルールは UI で「未登録」（missing）になる。
- API を直接使うときは、スコープと `allow_listen_ports` で UI のルールと範囲を分けたトークンを使う（「基本」の認証）。

## 起動時の復元

`--database-url mysql://user:pass@host:port/db` を指定すると、起動時に `forward_rules` テーブルの全ルールを読み込んで開始する。DB ユーザーには `SELECT` 権限だけを与えればよい。失敗したルールは `failed` として登録し、残りのルールは開始する。名前解決に失敗して `failed` になったルールは、再解決に成功した時点で自動的に開始する。

テーブル定義は UI リポジトリの `db/` で管理する。rproxy が読む列は `protocol`、`src_addr`、`src_port`、`src_port_end`、`dist_addr`、`dist_port`、`source_ip`、`udp_idle_secs`、`options`。`options.targets`（複数の宛先）があれば `dist_addr` / `dist_port` は使わない。`options.enabled` が `false` の行（UI で一時停止したルール）は起動時に作らない（ログ `restore.paused` に数）。
`options` は JSON で `{"tls": <TLS>, "starttls": "smtp" | "imap" | "pop3" | null, "starttls_required": bool, "allow_from": [<CIDR>, ...], "http": <L7>, "crowdsec": bool}`（`allow_from`・`http`・`crowdsec` は省略できる）。古いテーブルにこれらの列がなければ、既定値で読み込む。
