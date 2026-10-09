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
          allow_rulesets: [ci/]             # v0.4：PUT / DELETE できるルールの組の名前の先頭（省略ですべて）
          allow_certs: [ci-]                # v0.4.2（#240）：PUT / DELETE / 読む・ルールで使える保存した証明書の名前の先頭（省略ですべて）
          expires: 2027-03-31               # この日（UTC）まで有効
          persist: true                     # v0.4（#144）：作ったルールを rproxy_rules に保存する（既定 false）
      ```

    - スコープ: `rules:read`（`GET /rules`・`/interfaces`）、`rules:write`（`POST` / `PATCH` / `DELETE /rules`）、`metrics:read`（`GET /metrics`）、`acme:write`（ACME の証明書を使うルールの作成・変更と `POST /acme/...`。docs/ACME.md）、`certs:read`（`GET /certs`。v0.4.2）、`certs:write`（`PUT` / `DELETE /certs/{name}`。v0.4.2）、`admin`（すべて）。`GET /capabilities` はどのトークンでも読める。足りないときは `403 forbidden`。
    - ルールの作成・変更・削除は `event: "audit"` のログに残る（`token`、`client`、`action`、`rule`、`outcome`（`ok` / `error` / `forbidden`）、失敗時の `code`）。`client` は送信元の IP（Unix ソケットからは `unix`）。
    - 断ったリクエストも `event: "audit"` に残る（`client`・`method`・`path` つき。トークンそのものは出さない）：トークンがない・知らない・期限切れ（401）は `outcome: "unauthorized"` と `reason`（`missing` / `invalid` / `expired`、トークンに結びついたクライアント証明書がないときは `client_cert`）、一時停止中（429）は `outcome: "locked_out"`、スコープが足りない（403）は `outcome: "forbidden"` と `token`・`scope`。ログがあふれないように、断ったリクエストの行は送信元ごとに続けて 20 行まで、その後は 1 秒に 1 行にする。出した行の `suppressed` は、その送信元でその前に省いた行の数（省いた行の合計は `/metrics` の `rproxy_log_suppressed_total`）。
  - 複数のトークンを同時に有効にできる。入れ替えのときは新旧を両方書いておき、あとで古い方を消す。
  - SIGHUP を受けるとトークンファイルを読み直す。
  - SIGHUP がなくても、`--tokens-check-secs` / `RPROXY_TOKENS_CHECK_SECS`（既定 10 秒、`0` なら SIGHUP のときだけ）ごとにファイルの大きさ・更新時刻・inode・権限を確かめ、変わっていれば読み直す（v0.4.2、#253、`features.tokens_reload`）。パスはシンボリックリンクをたどって確かめるので、Kubernetes の Secret のボリューム（`..data` のリンクの差し替え）の更新も見つける。消したトークンは次の確認から通らない。処理中のリクエストと一時停止（lockout）の状態はそのまま。
  - 読めない・誤りのある版では今のトークンを使い続け、その版について `reload.tokens` の警告を 1 回だけ出す（ファイルがまた変われば読み直す）。読み直したときの `reload.tokens` はトークンの数（`tokens`）だけで、トークンやハッシュは出さない。起動時に読めなかった（権限）ファイルも、読めるようになれば次の確認で使い始める。
- `--api-addr` に loopback 以外のアドレスを含める場合は、`--token-file`、`--tls-cert`、`--tls-key` の指定が必須。どれかが欠けていると起動を拒否する。

### 制御 API の守り（v0.4、#167）

TCP の制御 API の守りを足す：クライアント証明書（mTLS）、トークンの期限の知らせ、認証の失敗が続く送信元の一時停止。**Unix ソケットはどれの対象でもない**（TLS がなく、ソケットのファイルの権限で守る。止められることもない）。

| 引数 / 環境変数 | 既定 | 意味 |
|---|---|---|
| `--tls-client-ca` / `RPROXY_TLS_CLIENT_CA` | なし | クライアント証明書を確かめる CA（PEM。複数可）。`--tls-cert` が要る。SIGHUP と証明書のファイルの確認（`RPROXY_CERT_CHECK_SECS`）で読み直す |
| `--tls-client-auth` / `RPROXY_TLS_CLIENT_AUTH` | `none` | `none`・`optional`（出されれば確かめる。ない接続はトークンで）・`required`（証明書がない・確かめられない接続は TLS のハンドシェイクで断る）。`optional` / `required` は `--tls-client-ca` が要る |
| `--token-warn-days` / `RPROXY_TOKEN_WARN_DAYS` | `14` | トークンの `expires` がこの日数より近いと `token.expiring` を出す（1〜3650） |
| `--api-lockout-failures` / `RPROXY_API_LOCKOUT_FAILURES` | `20` | `window` の間に認証に失敗（401）した回数がこれに達した送信元を止める。`0` で止めない |
| `--api-lockout-window` / `RPROXY_API_LOCKOUT_WINDOW` | `1m` | 数える時間（1s〜24h） |
| `--api-lockout-duration` / `RPROXY_API_LOCKOUT_DURATION` | `5m` | 止める時間（1s〜24h） |
| `--api-lockout-exempt` / `RPROXY_API_LOCKOUT_EXEMPT` | なし | 数えず止めない送信元（カンマ区切りの CIDR。NAT の後ろのコントローラなど）。検証済みのクライアント証明書（mTLS）で来た接続も止めない（同じアドレスから推測を続ける攻撃者に、正しい証明書を持つ管理者やコントローラを締め出させないため。セキュリティレビュー M4）。トークンだけの接続は、止まっているあいだトークンを確かめる前に `429` |

**クライアント証明書（mTLS）**：トークンファイル（YAML）のエントリに `client_cert` を書く。値は証明書の名前で、DNS か URI の subjectAltName（なければ subject の CN）と完全一致で比べる。

```yaml
tokens:
  - name: ui
    client_cert: ui.rproxy.internal      # 証明書だけで通す（Authorization は要らない）
    scopes: [rules:read, rules:write, metrics:read]
  - name: gateway-controller
    sha256: 9f86d0...
    client_cert: spiffe://cluster.local/ns/rproxy/sa/controller   # トークンと証明書の両方が要る
    scopes: [rules:read, rules:write]
```

- `sha256` と `client_cert` のどちらかは要る。**両方あれば両方が要る**：トークンが合っても、接続の証明書にその名前がなければ `401`（監査ログの `reason: "client_cert"`）。`client_cert` だけのエントリは証明書だけで通す（`sha256` のない 2 つのエントリに同じ `client_cert` は書けない）。
- `Authorization: Bearer` を付けたリクエストは、そのトークンで確かめる（知らないトークンなら、証明書だけで通るエントリがあっても `401`）。付けなければ、証明書の名前で `client_cert` だけのエントリを探す。
- 証明書は `--tls-client-ca` の CA が発行したもの（期限内・クライアント認証の用途）だけが通る。ほかの CA のものはハンドシェイクで断る。
- `client_cert` のあるトークンファイルで `--tls-client-auth` が `none` なら、起動を止める設定のエラー（SIGHUP の読み直しなら今のトークンを使い続ける）。使えないエントリを黙って無視しない。平文の HTTP や Unix ソケットでは証明書がないので、`client_cert` だけのエントリは使えない。
- 監査ログ（`event = "audit"`）に `auth`（`token`・`cert`・`token+cert`）が付く。

**トークンの期限**：

- 起動・SIGHUP・1 日 1 回、`expires` が `--token-warn-days` より近いトークンを `token.expiring`（`token`・`expires`・`days_left`）、切れたトークンを `token.expired`（`token`・`expires`）で知らせる（`warn`）。トークンごとに状態が変わったときに 1 回だけ。`expires` の日（UTC）の終わりまで有効。
- `/metrics` に `rproxy_token_expiry_timestamp_seconds{token}`（有効でなくなる時刻、Unix 秒）。

**失敗が続く送信元の一時停止**（既定で有効：1 分に 20 回で 5 分）：

- TCP の制御 API で、`401` になった送信元の IP（IPv6 は /64 でまとめる）ごとに数え、`window` の間に `failures` に達したら `duration` の間、その送信元のリクエストをトークンを見ずに `429 locked_out` で断る（`Retry-After` に残りの秒）。`/healthz`・`/readyz` は止めない。`403`（スコープ不足）は数えない。
- 止めたときに `api.lockout`（`client`・`failures`・`until`（Unix 秒）・`duration_secs`、`warn`）、解いたときに `api.unlock`（`client`）。止めている間の拒否は `event = "audit"`・`outcome: "locked_out"`（ほかの拒否と同じく送信元ごとに間引く）。
- `/metrics` に `rproxy_api_lockouts_total`（止めた回数）・`rproxy_api_locked_sources`（今止めている送信元の数）。
- 覚える送信元は 4096 まで（あふれたら、止めていない送信元のうち古いものから忘れる）。プロセスの中だけで覚え、再起動で消える。
- 同じ IP の後ろにいる正しいクライアントも一緒に止まる。UI を同じホストに置くなら Unix ソケットでつなぐと影響を受けない。

**トークン・証明書の入れ替え**（止めずに入れ替える）：

1. 新しいトークン（`sha256`）をトークンファイルに足して SIGHUP（`systemctl reload rproxy-api`）。v0.4.2 からは SIGHUP を送らなくても `RPROXY_TOKENS_CHECK_SECS` のうちに読み直す。この間は新旧どちらでも通る。
2. クライアント（UI・CI など）を新しいトークンに切り替える。
3. 古いトークンをトークンファイルから消して SIGHUP。

- `expires` を付けておくと、切れる前に `token.expiring` で知らせる（`--token-warn-days`）。
- クライアント証明書は、同じ名前で新しい証明書を発行してクライアントに配る（トークンファイルは変えなくてよい）。名前を変えるときは、新しい名前のエントリを足す → クライアントを切り替える → 古いエントリを消す（どれも SIGHUP）。
- CA を入れ替えるときは、`--tls-client-ca` のファイルに新旧の CA を並べて SIGHUP → クライアントの証明書を新しい CA のものに替える → 古い CA を消して SIGHUP。

**UI（TCP-UDP-rproxy-ui）の側**（UI が実装するときの取り決め）：

| UI の環境変数 / `nodes.yaml` のノードの項目 | 意味 |
|---|---|
| `RPROXY_API_CA_FILE` / `ca_file` | rproxy の制御 API のサーバ証明書を確かめる CA（PEM）。`https://` で、公的な CA でないときに使う |
| `RPROXY_API_CERT_FILE` / `cert_file` | UI が出すクライアント証明書（PEM。中間 CA があれば続けて書く） |
| `RPROXY_API_KEY_FILE` / `key_file` | その秘密鍵（PEM）。UI を動かすユーザーだけが読めるようにする |

- `RPROXY_API_URL`（ノードの `url`）は `https://` にする。`unix:` では証明書を使わない（トークンで通す）。
- `cert_file` / `key_file` を指定し、rproxy の `client_cert` だけのエントリ（例：`client_cert: ui.rproxy.internal`）に当たるなら、`RPROXY_API_TOKEN`（`token_file`）は省ける。`sha256` と `client_cert` の両方があるエントリなら両方を指定する。
- 片方だけ（`cert_file` だけ・`key_file` だけ）は UI の設定のエラー。ファイルが変わったら（証明書の更新）新しい接続から読み直す（または UI を再起動する）。
- rproxy が `429 locked_out` を返したら、`Retry-After` の間は送り直さず、画面に「認証の失敗が続いたため一時的に止められている」と出す。`401` を自動で繰り返さない（一時停止の回数に入る）。
- `GET /capabilities` の `features.client_cert_auth` で、rproxy がクライアント証明書に対応しているかを確かめられる。

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
| `listen_freebind` | bool | | `true` で、待ち受けるアドレス（`listen_addr`・`extra_listen_addrs`）がまだホストになくても待ち受ける（`IP_FREEBIND` / `IPV6_FREEBIND`。v0.4.3、`features.listen_freebind`）。下の「まだホストにないアドレスで待ち受ける」。既定 `false`。PATCH では変えられない（違う値は `unsupported`）。一覧では `true` のときだけ出す |
| `listen_port` | 1–65535 | ○ | |
| `remote_addr` | string | ○ | IP アドレスまたはホスト名。ホスト名は 30 秒ごとに再解決する。`http` のルールでは書かない（転送先は `http.services`。一覧では `""` / `0`）。`targets` を使うときも書かない（一覧では `targets` の先頭が入る） |
| `remote_port` | 1–65535 | ○ | `http` のルール・`targets` を使うルールでは書かない |
| `targets` | object の配列 | | 宛先を複数にする（v0.3.3、`remote_addr` / `remote_port` の代わり。どちらか一方）。`{"addr", "port", "weight"?, "backup"?}`：`addr` は IP かホスト名（それぞれ再解決する）、`weight` は 1 以上（既定 1）、`backup: true` はほかの宛先がすべて down のときだけ使う（全部を backup にはできない）。最大 64 件。ポート範囲では各宛先の `port` も範囲の分ずれる。下の「複数の宛先」 |
| `balance` | `"round_robin"` \| `"least_conn"` \| `"failover"` | | `targets` の振り分け方。既定 `round_robin`。一覧では `targets` があるときだけ出す |
| `health_check` | object | | 宛先の生死を TCP の接続で確かめる（v0.3.3）。`{"interval"?, "timeout"?, "port"?}`：`interval` 既定 `10s`、`timeout` 既定 `3s`、`port` は各宛先のポートの代わりに接続するポート（UDP のルールでは必須）。`remote_addr` だけのルールでも使える。`http` のルールでは使えない（`http.services.<名前>.health_check`） |
| `connect_timeout` | string | | 宛先への TCP の接続にかけてよい時間（`100ms`〜`10m`。v0.4.3、`features.connect_timeout`）。過ぎたら失敗として数え（`outlier_detection` の `connect`）、次の宛先で接続し直す。宛先が 1 つならクライアントの接続を閉じる。省くと今までどおり（ほかに宛先があれば 5 秒、なければ OS の既定（Linux は約 2 分））。`tcp` のルールだけ（`udp` と `http` のルールは `invalid`。`http` は `http.services.<名前>.timeouts.connect`）。`tls.routes` の宛先にも効く。PATCH で付けると置き換え（`0s` で外す、省けば今のまま）、次の接続から効く |
| `source_ip` | `"proxy"` \| `"proxy_v1"` \| `"proxy_v2"` \| `"transparent"` | | 既定は `"proxy"`（送信元 IP を引き渡さない）。`proxy_v1` は TCP でのみ使える。`proxy_v2` は UDP でも使え、転送先へのデータグラムごとに PROXY v2（DGRAM）のヘッダを付ける（応答にはヘッダがない。宛先アドレスはクライアントが送った宛先のアドレス。`0.0.0.0` / `::` で待ち受けていても、受けたアドレスになる）。UDP の `proxy_v2` と `tls.upstream.tls`（転送先への DTLS）は組み合わせられない（`unsupported`）。`transparent` は `GET /capabilities` の `transparent`（IPv4）/ `transparent_ipv6`（IPv6 の待ち受け）が true のときだけ指定できる。クライアントと転送先は同じアドレスファミリーであること（docs/TRANSPARENT.md） 。説明と転送先の設定の例は docs/SOURCE-IP.md |
| `udp_idle_secs` | 1–86400 | | UDP セッションを無通信で破棄するまでの秒数。既定は 30。TCP では無視する |
| `listen_port_end` | 1–65535 | | ポート範囲の終わり（`listen_port` 以上）。`listen_port..listen_port_end` の各ポートを、`remote_port` から順に同じ数だけずらした転送先へ送る。上限は `GET /capabilities` の `max_range_ports`（既定 20000） |
| `tls` | object | | TLS（tcp）/ DTLS（udp）の扱い。省略すると `{"mode": "passthrough"}`。下の「TLS」を参照 |
| `starttls` | `"smtp"` \| `"imap"` \| `"pop3"` | | STARTTLS の手前の平文のやり取りに rproxy が答え、TLS を終端する。`tls.mode` が `terminate` の tcp ルールでのみ使える |
| `starttls_required` | bool | | 既定 `true`。`false` にすると、SMTP で STARTTLS をしないクライアントも平文のまま通す（IMAP / POP3 では常に必須として扱う）。`starttls` なしで `false` を指定すると `invalid` |
| `allow_from` | string の配列 | | 接続を受け付ける送信元。CIDR（`172.16.0.0/16`、`fd00::/8`）または単一の IP。省略または空ならすべて受け付ける。最大 64 件。範囲外からの TCP 接続は、TLS や PROXY ヘッダより前に切断する。UDP は範囲外の送信元のデータグラムを捨てる（セッションを作らない）。断った数は `stats.denied`（UDP はデータグラムごと）、ログは `conn.denied`（`reason: allow_from`。UDP は送信元ごとに続けて 20 行まで、その後は 1 秒に 1 行。送信元を偽った大量のデータグラムに備えて、全体でも続けて 200 行、その後は 1 秒に 50 行まで。`suppressed` はその前に省いた行の数。v0.3.20 から。それより前の UDP は `debug` でだけ出ていた） |
| `crowdsec` | bool | | 既定 `false`（v0.3.2）。`true` にすると、CrowdSec の判定（`global.crowdsec`、scope `Ip` / `Range`）に入っている送信元を、`allow_from` と同じく受け付けた直後（TLS や PROXY ヘッダより前）に切断する。UDP はそのデータグラムを捨てる（開いているセッションのものも）。LAPI から一度も判定を取れていない間は通す。`global.crowdsec` がないと `invalid`。`http` のルールでも使えるが、見るのは接続元の IP（前段のプロキシの後ろでは `crowdsec` ミドルウェアを使う）。一覧では `false` のとき省く。断った数は `stats.denied`、ログは `conn.denied`（`reason: crowdsec`。UDP は `allow_from` と同じく間引く） |

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
- up / down：`health_check` があれば、その結果（最初の確認までは up）。なくても、TCP の接続を断られた（または 5 秒以内に応答がない）宛先は、10 秒のあいだ down として飛ばし（外す）、同じ接続を次の宛先で接続し直す。UDP は、転送先から ICMP の到達不能が返った宛先を同じく外す。外す回数・時間・割合は v0.4 の `outlier_detection`（下の「v0.4 の設定」）で変えられる。
- `backup` の宛先は、ほかの宛先がすべて down のときだけ使う。すべて down なら、down の宛先も順に試す（接続を断らない）。
- UDP の既存のセッションは、自分の宛先が down になったら次の宛先へ移る（`conn.retarget`、`reason: target down`）。`failover` で上位が戻っても、既存のセッションはそのまま。
- 名前解決できない宛先があっても、ほかの宛先が解決できればルールは動く（解決できない宛先は後から再解決する）。すべて解決できなければ、これまでどおり `resolve_failed`。
- `tls.routes`（サーバ名ごとの転送先）は今までどおり route ごとに 1 つ。`targets` は一致しない名前（とサーバ名なし）の転送先。
- 状態が変わると `event: "target.down"`（`reason: health_check` / `outlier`、`error`。`outlier` は `cause`（`connect`・`refused`・`short_lived`）と `ejection_secs`・`ejections` も）/ `"target.up"`（`reason: health_check` / `outlier`）のログ。v0.3 までは接続の失敗が `reason: connect` で、外した時間が過ぎたときの `target.up` はなかった。ルールの `stats.targets` に宛先ごとの `[{"addr","port","backup"?,"up","connections","total_connections","resolved","ejected_until","ejections"}]`（`targets` が 2 つ以上か `health_check` があるときだけ。`ejected_until` は外している間だけ Unix 秒、ほかは null）、`/metrics` に `rproxy_target_up{protocol,listen,target}`（1 / 0）と `rproxy_target_connections{protocol,listen,target}`。
- 宛先がすべて down のときは、ルールの `all_targets_down` が `true`、`/metrics` の `rproxy_rule_all_targets_down{protocol,listen}` が 1（v0.3.20。`stats.targets` を出すルールだけ。ほかのルールでは `all_targets_down` はいつも `false`）。backup の宛先も含めて、どれも down のとき。
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
| `client_auth` | クライアント証明書の検証（mTLS）。`mode` は `none`（既定）/ `optional`（送られてきたら検証する）/ `required` / `optional_no_verify`（#238。下の「証明書を確かめない `optional_no_verify`」）。`optional` と `required` では `ca_file` が必須。`ca_file` はルート CA（信頼の起点）。`chain_file` はクライアント証明書の中間 CA で、中間 CA を送ってこないクライアントのために、検証の途中経路を補う（信頼の起点にはしない）。TLS と DTLS で同じ規則で検証する |
| `alpn` | `terminate` でクライアントに提示する ALPN（tcp のみ） |
| `upstream` | `terminate` の転送先側。`tls: true` で再暗号化する（tcp は TLS、udp は DTLS）。`server_name`（既定は転送先のホスト名）、`ca_file`（既定は Mozilla のルート証明書）、`insecure_skip_verify`（検証しない。テスト用）、`cert_file` / `chain_file` / `key_file`（転送先へのクライアント証明書と、その中間 CA） |

### 証明書を確かめない `optional_no_verify`（#238）

`tls.client_auth.mode: optional_no_verify` は、クライアント証明書を求めるが、送られなくても、検証に通らなくても接続を受ける（Gateway API の `AllowInsecureFallback`）。`tcp` の `terminate`（`http` のルールと HTTP/3 を含む）と `udp` の DTLS の終端で使える。`GET /capabilities` の `features.client_auth_modes` に `optional_no_verify` があれば使える。

```json
"client_auth": {"mode": "optional_no_verify", "ca_file": "/etc/rproxy/clients-root.pem"}
```

- `ca_file` は省ける。あれば、送られた証明書をそれで確かめた結果（`SUCCESS` / `FAILED`）を下の形で知らせる。なければ送られた証明書はいつも `FAILED`。`chain_file` は `ca_file` があるときだけ。
- 証明書を送ったクライアントは、その鍵を持っていることだけは TLS のハンドシェイクで確かめる（署名）。チェーン・期限・CA は確かめない（rproxy は断らない）。
- 知らせ方：
  - `http` のルール（`client_auth` があるとき。どのモードでも）：転送先へ `X-Client-Verify: SUCCESS | FAILED | NONE`（nginx の `$ssl_client_verify` と同じ値）と、証明書があれば `X-Forwarded-Client-Cert: Hash=<SHA-256 の 16 進>;Subject="<RFC 4514 の subject>"`（Envoy の形。`Subject` は確かめられた証明書のときだけ）。`forward_auth` の問い合わせと `mirror` の写しにも同じ値を付ける。アクセスログに `client_cn`・`client_verify`。
  - **クライアントが送ってきた `X-Client-Verify`・`X-Forwarded-Client-Cert` は、どのルールでも（`client_auth` のない平文・HTTPS のルール、HTTP/1.1・HTTP/2・HTTP/3、Upgrade、`forward_auth`・`mirror` を含む）、ミドルウェアより前に必ず消す**（Envoy の SANITIZE と同じ。同じ HTTPRoute を mTLS の 443 と平文の 80 に付けても、80 から偽れない）。`mirror` の写しの `X-Forwarded-For`・`X-Real-IP`・`X-Forwarded-*` も、転送先へのリクエストと同じものにする。
  - L4 の終端：`conn.open` のログに `client_cn`・`client_verify`。`source_ip: proxy_v2` なら、PROXY v2 の SSL の TLV の `verify` が 0（確かめた、または証明書なし）か 1（確かめられなかった証明書）。確かめられなかった証明書の CN は TLV（`SSL_CN`）に入れない。
- **安全上の注意**：このモードは認証にならない。誰でも（証明書なし・偽の証明書で）接続できるので、許すかどうかは転送先が `X-Client-Verify`（または PROXY v2 の `verify`）を見て決めなければならない。転送先へは rproxy を通る経路だけにする（直接つながると、転送先はヘッダが rproxy のものか分からない）。Gateway API も試験や一時的な移行のためのものとしている。認証に使うなら `required`、使えるなら確かめる `optional`。

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

証明書は ACME で rproxy に取らせることもできる（v0.3.21 から。`tls.certificates[]` に `{"acme": "<resolver>", "domains": [...]}`、設定ファイルの `global.acme`。取った証明書も同じ証明書のストアで読み込み、更新は上と同じく自動で反映される）。詳しくは docs/ACME.md。certbot・acme.sh・cert-manager などで取ったファイルを `cert_file` / `key_file` に指定するやり方もそのまま使える（certbot の http-01 は、80 番の `http` のルールで `/.well-known/acme-challenge/` を certbot の webroot / standalone のポートへ振り分ければよい。rproxy 自身が答えているトークンでなければルートに渡る）。

応答で返すルールには、次の稼働情報が加わる（`allow_from` は正規化した CIDR の形で返す。例：`10.0.0.5` → `10.0.0.5/32`）。

| フィールド | 説明 |
|---|---|
| `state` | `"running"` または `"failed"` |
| `error` | `failed` の理由。`running` なら `null` |
| `resolved` | 最後に名前解決できた転送先（`"ip:port"` の配列）。まだ解決できていなければ空 |
| `connections` | 現在の接続数（UDP はセッション数） |
| `stats` | ルールが開始してからの累計：`total_connections`、`rx_bytes`（クライアント → 転送先）、`tx_bytes`（転送先 → クライアント）、`tls_failures`（TLS / DTLS のハンドシェイクや STARTTLS の失敗） |
| `started_at` | 待ち受けを始めた時刻（Unix 秒）。`failed` のときは `null` |
| `all_targets_down` | 宛先がすべて down（v0.3.20。下の「複数の宛先」） |
| `down_services` | `http` のルールで、`health_check` のあるサービスのうち、up の転送先が 1 つもないものの名前（v0.3.20）。なければ省く |
| `cert_status` | `terminate` のルールが使う証明書の期限（下の「証明書の期限」）。証明書がなければ省く。各要素は `role`（`certificate` / `client_ca` / `client_chain` / `upstream_ca` / `upstream_certificate`）、`file`（証明書のファイル）、`not_after`（RFC 3339、UTC）、`days_left`（残りの日数。切れたら負）、`state`（`ok` / `expiring` / `expired`） |
| `acme` | ACME の証明書（`tls.certificates[].acme`）の状態。なければ省く。各要素は `resolver`、`domains`、`state`（`pending`：まだ取れていない（自己署名の仮の証明書を返す）／`valid`／`renewing`：更新の時期／`error`：最後の試みが失敗（取れていた証明書はそのまま使う））、`not_after`・`renew_at`（RFC 3339）、`next_attempt`（失敗や `rate_limit` で待っている次の時刻）、`error`、`ari`（CA の更新の窓 `start`・`end`。ARI、RFC 9773） |
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
- `global` はプロセス全体の設定（`trusted_proxies`、`access_log`、`acme`、`crowdsec`。docs/DESIGN-v0.3.md の 2.）。
  - `acme`: ACME のアカウント・DNS のプロバイダ・resolver・許可する名前（docs/ACME.md）。秘密はファイルで指し、API からは触れない。
  - `files`（v0.4）：`{"owner_check": "strict" | "off", "trusted_dirs": ["/var/run/rproxy-gateway/certs"]}`（既定 `strict`、`trusted_dirs` なし）。`trusted_dirs`（なければ環境変数 `RPROXY_FILES_TRUSTED_DIRS`、`:` か `,` 区切り。両方あれば設定ファイル）の下にある（シンボリックリンクをたどった本当のパスで判断）ファイルは root のものでもよい（Kubernetes の Secret のボリューム）。絶対パスでなければ設定の誤り。ルールと `global` が指す証明書・鍵・秘密のファイルは、rproxy のユーザー（`rproxy-api`）のもので、グループ・ほかの人が書けず、鍵・秘密はほかの人が読めないものだけ使う（docs/PERMISSIONS.md の「ルールが指すファイルの所有者」）。`off` は root のファイルをそのまま使うときだけ（危険を承知で。起動時に `degraded`）。
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
  - `global` の変更は再起動するまで効かない（`trusted_proxies`・`access_log`・`acme`・`crowdsec`。起動時の値と違うと `config.reload` の警告と `GET /config` の `restart_needed` で知らせる）。
  - 状態は `GET /config` で見える：`{"configured":true,"path":"/etc/rproxy/conf.d","files":[...],"loaded_at":1790000000,"rules":5,"last_reload":{"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0},"error":null,"restart_needed":[]}`（設定ファイルを使っていなければ `{"configured":false}`）。`error` は最新の版を反映できなかった理由（それまでの版が動いている）。
- 反映する前に確かめる：`rproxy-api --check-config [PATH]` が、起動時・再読み込みと同じ検証（書式、ルールの値、待ち受けの重なり・制御 API との重なり、証明書・鍵・CA のファイルと期限、`global`、ミドルウェアの秘密のファイル）をして、問題がなければ 0、誤りがあれば 1 で終わる（待ち受けも DB も開かない。`--check-config-format json` で `{"ok","path","files","rules","errors":[{"rule","message"}],"warnings":[...]}`）。名前解決はしない。パッケージのユニットの `ExecReload` は、先にこの確認をする（誤りがあれば reload は失敗し、SIGHUP を送らない）。
- 同じキーや重なるポートのルールを API や DB から作ろうとすると、`already_exists` になる。
- ファイルが存在しない、書式や形が不正（知らないキー、`version` が 1 以外、存在しない ACME の resolver の参照、`global.acme` の許可の外の名前、ない秘密のファイルなど）の場合は、rproxy は起動しない。読めない（権限）ときは、固定ルールなしで起動する。
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
| ACME の証明書 | `tls.certificates[]` | `{"acme": "<resolver>", "domains": [...]}`（`cert_file` / `key_file` の代わり）。resolver は設定ファイルの `global.acme.resolvers`。`acme:write` のスコープが要り、名前は resolver のアカウント（と DNS のプロバイダ）の `allowed_names` の内だけ（外なら `400 invalid`）。tcp の `terminate` だけ（udp は `tls_config`）。docs/ACME.md | `acme`（v0.3.21 から true） |
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
  - リクエストは HTTP/1.1・HTTP/2 と同じルート・ミドルウェア・転送先に渡る（転送先へはサービスの `protocol` のとおり。既定は HTTP/1.1）。本文は流しながら送る。アクセスログの `protocol` は `HTTP/3.0`。
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
- 転送先とは HTTP/1.1 で話す（サービスの `protocol` で HTTP/2 も。下の「Gateway API 向けの L7・TLS」）。`servers` は `weight`（既定 1）の重みつきラウンドロビン。`url` にパスがあれば、リクエストのパスの前に付ける。`https://` の転送先の証明書は、ルールの `tls.upstream` の `ca_file`（なければ Mozilla のルート）で検証し、`server_name` / `insecure_skip_verify` / クライアント証明書もそれに従う。`tls.upstream.tls` は使わない（URL の `https://` で決まる。指定すると `tls_config`）。サービスに `tls`（#236）があれば、そのサービスでは `tls.upstream` の代わりにそれを使う。
- 転送先への接続は、応答の本文を読み終えたあと、次のリクエストに使い回す（転送先ごとに待機中の接続は 1024 本まで、使われないまま 4 秒たったものは閉じる。`source_ip: transparent` のルールでは、送信元がクライアントごとに違うので使い回さない）。使い回そうとした接続を転送先が閉じていたら、新しい接続で送り直す。
- `health_check`（v0.3.2）: `interval`（既定 `10s`）ごとに各 `servers` へ `GET <URLのパス><path>`（`Host` は転送先のホスト）を送り、`timeout`（既定 `3s`）以内に 2xx / 3xx が返れば up、そうでなければ down。down の転送先はラウンドロビンから外し、戻れば入れる。最初の確認までは up として扱う。すべて down なら 503。状態が変わると `event: "http.health"` のログ（`service`、`server`、`up`、down の理由の `error`）。ルールの `stats.http.services.<サービス名>` に `[{"url","up"}]`、`/metrics` に `rproxy_http_server_up{protocol,listen,service,server}`（1 / 0）。サービスの転送先がすべて down なら、ルールの `down_services` にサービスの名前が入り、`rproxy_http_service_down{protocol,listen,service}` が 1（v0.3.20）。
- `balance`（v0.3.3）: `round_robin`（既定。`weight` の比率）、`least_conn`（処理中のリクエストが `weight` あたり一番少ない転送先）、`failover`（`servers` の上から順に、up の最初の転送先）。どれも down の転送先は外す（`health_check` の結果）。`sticky` のクッキーの転送先が up なら、そちらが優先。
- `sticky`（v0.3.2）: 初めてのクライアントには、選んだ転送先を示すクッキー（`<cookie>=<URL から作った 16 桁の値>; Path=/; HttpOnly; SameSite=Lax`、HTTPS なら `Secure` も）を付け、以後そのクッキーの転送先へ送る。その転送先が down か、知らない値なら選び直してクッキーを付け直す。値は URL から作るので、rproxy を再起動してもほかの転送先を足しても変わらない。
- `weight` で転送先を切り替えられる（例：新しい版を `weight: 1`、今の版を `weight: 9` にして 1 割だけ流す）。
- `pass_host_header`（既定 true）が false なら、`Host` は転送先の URL のホスト（とポート）にする。
- 転送先へは `X-Forwarded-For`・`X-Real-IP`（クライアントの IP）、`X-Forwarded-Proto`（`http` / `https`）、`X-Forwarded-Host`、`X-Forwarded-Port` を付ける。クライアントが送ってきた同名のヘッダは置き換える。ただし接続元が `global.trusted_proxies` の範囲なら、`X-Forwarded-For` は受けた値の後ろに接続元を足し、`X-Forwarded-Proto` / `-Host` / `-Port` は受けた値を保つ。ホップごとのヘッダ（`Connection` とそこに書かれたもの、`Keep-Alive`、`TE`、`Transfer-Encoding` など）は取り除く。
- `Connection: Upgrade`（WebSocket など）は、転送先が 101 を返せばそのまま中継する。ルールを削除すると切れる。
- 転送先に接続できなければ 502、`timeouts.connect`（既定 5 秒）・`timeouts.response`（既定 60 秒）を過ぎると 504。`event: "http.error"` のログを出す。`timeouts.response` は、リクエストの本文を送り終えてから応答ヘッダが届くまでの時間（アップロードにかかる時間は含めない。応答の本文にも上限はない）。

### HTTP の転送の扱い

rproxy はクライアントとは HTTP/1.1・HTTP/2・HTTP/3 で、転送先とは HTTP/1.1（サービスの `protocol` で HTTP/2、#233）で話す。そのあいだで次のように扱う（tests/http_semantics.rs で HTTP/1.1・HTTP/2・HTTP/3 のクライアントから確かめている）。

| 項目 | 扱い |
|---|---|
| `Cookie` | HTTP/2・HTTP/3 で複数のフィールドに分けて届いたもの（Chrome はそうする）は `"; "` で 1 本にまとめる（RFC 9113 §8.2.3 / RFC 9114 §4.2.1）。まとめたものをミドルウェア（`oidc`・`sticky`・`forward_auth`）も読む |
| `Set-Cookie` | 転送先の複数の `Set-Cookie` は 1 本ずつそのままクライアントへ（まとめない。`compress`・`headers` を通っても同じ）。`Domain` / `Path` / `Secure` などの属性、`Location` は書き換えない |
| そのほかのヘッダ | 同じ名前の複数のフィールドは順番どおり、値はバイトのまま（ASCII 以外も）渡す。`Authorization` は渡す |
| ホップごとのヘッダ | 両方向で取り除く：`Connection` とそこに書かれた名前、`Keep-Alive`、`Proxy-Connection`、`Proxy-Authenticate`、`Proxy-Authorization`、`TE`、`Trailer`、`Transfer-Encoding`、`Upgrade`（WebSocket などの `Upgrade` は付け直して中継する）。`Via` と `Forwarded`（RFC 7239）は付けない（Traefik・nginx の既定と同じ。`X-Forwarded-*` を使う）。HTTP/2 の転送先（`protocol`）へは、クライアントの `TE` に `trailers` があれば `te: trailers` だけを渡す |
| トレーラー | 本文の後のトレーラーは、HTTP/2 の転送先と HTTP/2・HTTP/3 のクライアントのあいだで両方向にそのまま渡す（gRPC の `grpc-status` など。tests/http_semantics.rs）。HTTP/1.1 のクライアントへは、`TE: trailers` を送ってきたときだけ chunked の後に付ける |
| `Host` | HTTP/2・HTTP/3 の `:authority`、HTTP/1.1 の absolute-form の宛先（`GET https://a.example/ HTTP/1.1`）の authority を、`Host` フィールドより優先する（RFC 9112 §3.2.2）。転送先には origin-form（パスとクエリ）で送る。`pass_host_header: false` なら転送先の URL のホスト |
| ヘッダの大きさ | HTTP/2・HTTP/3 は 1 リクエストのヘッダの合計 64 KiB まで（hyper の既定の 16 KiB では、大きなクッキーのブラウザで足りない）。HTTP/1.1 は約 400 KB まで。超えると 431 |
| 本文 | 流しながら中継する（`buffering` がなければため込まない）。chunked、`Expect: 100-continue`、`HEAD`（`Content-Length` を保つ）、`204` / `304` に対応 |
| タイムアウト | `timeouts.response` は本文を送り終えてから応答ヘッダまで。長いダウンロード・SSE・ロングポーリングの応答の本文は切らない |
| 途中で切れた応答 | 転送先が応答の途中で切れたら（`Content-Length` に足りない、chunked の最後のチャンクがない、リセット）、クライアントにも完全な応答に見えないように切る：HTTP/1.1 は足りないまま接続を閉じる（chunked なら最後のチャンクを送らない）、HTTP/2 は RST_STREAM、HTTP/3 は RESET_STREAM。`compress` を通していても同じ（圧縮の終わりを付けない）。長さのない（接続を閉じて終わる）HTTP/1.0 型の応答は、転送先の側で途中かどうかが分からない |
| 途中で切れたリクエスト | クライアントが本文の途中で切れたら（HTTP/1.1 の切断、HTTP/2 の RST_STREAM、HTTP/3 のリセット）、転送先への接続も本文を終えずに切り、転送先に完全なリクエストとして渡さない |
- アクセスログ（`event: "http.access"`）はリクエストごとに 1 行：`rule`、`route`（一致しなければ `(none)`）、`service`、`backend`、`client`、`method`、`host`、`path`（クエリは含めない）、`query`（クエリ。`?` なし、なければ空。v0.3.8 から。秘密になりやすい名前のパラメータ（`token`・`code`・`state`・`password`・`secret`・`key`・`signature`・`auth`・`session` などを名前に含むもの）は値を `REDACTED` に置き換える。GitLab の `private_token`、OIDC の `code` / `state` などをログに残さないため）、`protocol`（`HTTP/1.1` / `HTTP/2.0`）、`status`、`duration_ms`（応答の本文を送り終えるまで）、`bytes_in`（`Content-Length`）、`bytes_out`（応答の本文）、`user_agent`、`sni`、`tls_version`、`refused_by`、`middleware`、`user`、`auth_error`。出す先は `global.access_log`。
  - `refused_by`・`middleware`（v0.3.20）：リクエストを断ったミドルウェアの種類（`ip_allow`・`basic_auth`・`forward_auth`・`oidc`・`crowdsec`・`rate_limit`・`in_flight`・`buffering`・`circuit_breaker`・`respond` など）と、設定での名前。ミドルウェアがエラー（4xx / 5xx）を返したときだけ入れ、ほかは空。リダイレクトや `respond` の 2xx は入れない。
  - `user`（v0.3.20）：`basic_auth` が通したユーザー名。
  - `auth_error`（v0.3.20）：`basic_auth` が断った理由：`no_credentials`（`Authorization` がない）、`unknown_user`、`bad_password`、`unavailable`（ユーザーのファイルを読めない）。断ったときのユーザー名とパスワードは出さない。
- `GET /metrics` の `rproxy_http_requests_total{protocol,listen,route,code}`（`code` は `2xx` など）と `rproxy_http_request_duration_seconds{protocol,listen,route}`（ヒストグラム。境界は 5ms〜10s）、`rproxy_http_limited_total{protocol,listen,route,middleware}`（`rate_limit` / `in_flight` で断った数）、`rproxy_http_blocked_total{protocol,listen,route,middleware}`（`crowdsec` で断った数）。`global.crowdsec` があれば `rproxy_crowdsec_decisions`（判定で止めているアドレスと範囲の数）、`rproxy_crowdsec_synced`（LAPI から一度でも取得できたら 1）、`rproxy_crowdsec_connected`（最後の取得が成功していれば 1。v0.3.20）、`rproxy_crowdsec_last_success_timestamp_seconds`（最後に取得できた時刻。v0.3.20。一度も取れていなければ出さない）。ラベルにパスは入れない。
- ミドルウェアはルートの `middlewares` に書いた順にリクエストへ働き、応答へは逆の順に働く（Traefik と同じ）。途中のミドルウェアが応答を返したら（リダイレクト・`respond`・拒否）、その先へは進まない。その応答にも、それまでに通ったミドルウェアの応答側（`headers` など）が働く。
- 使えるミドルウェア（v0.3.1。`features.middlewares`）:
  - `redirect_scheme`: `scheme` と違う方式で受けたリクエストを、同じホスト・パス・クエリの `scheme://` へリダイレクトする。`port` は既定のポート（80 / 443）なら省く。
  - `redirect_regex`: `http://host[:port]/path?query`（受けた URL）が `regex` に一致すれば、`replacement`（`$1`・`${name}` が使える）へリダイレクトする。一致しなければ次へ進む。
  - リダイレクトの状態コードは、`permanent` なら 301、そうでなければ 302。GET / HEAD 以外は 308 / 307（メソッドと本文を保つ）。`status`（301・302・303・307・308、#226）を書けばそれを使う。
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
  - `retry`: 転送先に接続できない・応答がない（502 / 504 になるもの）ときに、次の転送先へ送り直す。`attempts` は最初の 1 回を含む回数、`initial_interval`（既定 `100ms`）は最初の待ち時間で、回ごとに倍になる。送り直すのは冪等なメソッド（GET・HEAD・OPTIONS・PUT・DELETE・TRACE）で、本文がないか、`buffering` で読み切った本文のときだけ（WebSocket などの Upgrade は送り直さない）。転送先が返した 5xx は、`status`（#231）に書いたものだけ送り直す。
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
    - v0.4.3 から（Gateway API の `ExternalAuth` のため。どれも省略でき、省略すれば上のとおり。`features.forward_auth` に使える項目の名前）：
      - `service`：`address` の代わりに、ルールの `http.services` の名前（転送先・`balance`・`health_check`・`tls` をそのまま使う）。問い合わせるパスは `path`（既定 `/`）。`timeout` は 1 回の問い合わせの上限（サービスの `timeouts.response` より先に効く）。
      - `client_request: true`：Envoy の HTTP の ext_authz の形。`GET` ではなくクライアントのメソッドで、パスは `address` のパス（`service` なら `path`）の後ろにクライアントのパスとクエリをつないだもの（`/auth` + `/app/x?q=1` → `/auth/app/x?q=1`）、`Host` はクライアントのもの、`Content-Length` は送る本文の長さ（本文を送らなければ 0）。`X-Forwarded-*` はそのまま付ける。`request_headers` を書かなければクライアントのヘッダをすべて送る（Gateway API の「書かなければ `Authorization` などだけ」はコントローラが名前を書く）。
      - `allow_status`：通す状態コード（`"200"`・`"200-204"` のような値か範囲の一覧。既定は 2xx）。ほかの状態コードの応答はそのままクライアントに返す。
      - `response_headers: ["*"]`：通したとき、応答のヘッダをすべて転送先へのリクエストに写す（同名のヘッダは置き換え）。応答そのものを表すもの（ホップごとのヘッダ、`Host`・`Content-Length`・`Content-Type`・`Content-Encoding`・`Transfer-Encoding`・`Date`）は写さない。`"*"` はほかの名前と一緒に書けない。
      - `forward_body: {max_size: <バイト>}`：クライアントの本文を `max_size` まで読み切って（`buffering` と同じ）認証サーバにも送る。長いものは 413、本文が途中で切れたら 400。読み切った本文は転送先にも送る（`retry` で送り直せる）。
      - `protocol: grpc`：Envoy の ext_authz v3 の gRPC（`envoy.service.auth.v3.Authorization/Check`）で問い合わせる。`address` は `http://`（HTTP/2 の prior knowledge、h2c）だけ。TLS なら `service`（`protocol: h2`・`tls`）を使う（`service` は `protocol` が `h2` か `h2c` のもの）。`CheckRequest` には接続元・接続先のアドレス、時刻、メソッド、ヘッダ（`request_headers` を書けばその名前だけ。`:authority`・`:method`・`:path`・`:scheme` はいつも。同じ名前のヘッダは `,` でつなぐ）、パス（クエリを含む）、ホスト、スキーム、プロトコル、本文の大きさ、`forward_body` の本文を入れる。`CheckResponse` の `status.code` が 0 なら通し、`ok_response.headers`（`append` の指定どおり。指定がなければ置き換え）を転送先へのリクエストに、`headers_to_remove` を外し、`response_headers_to_add` をクライアントへの応答に付ける。0 でなければ `denied_response` の状態コード（なければ 403）・ヘッダ・本文で答える。gRPC の誤り（`grpc-status` が 0 でない、応答が読めない）は 403、つながらなければ 502、時間切れは 504。`client_request`・`allow_status`・`path`・`response_headers` は使えない（認証サーバの答えが決める）。
      - 転送先ごとのミドルウェア（`servers[].middlewares`）にも書ける（その転送先へ送るリクエストだけを問い合わせる。Gateway API の backendRef の `ExternalAuth`）。
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

## v0.4 の設定

v0.4.0 で形を決めて中身まで入れた設定（docs/DESIGN-v0.4.md。設計との違いはその「15. 実装での設計との違い」）。v0.4.0 では下の表の項目がすべて動き、`GET /capabilities` の `features` の v0.4 の項目はすべて true（`performance` はすべての項目の名前、`middlewares` に `geoip`、`services` に `outlier_detection`）。形が不正なら `400 invalid`。どれも省略でき、省略したときの動きは v0.3 と同じ。制御 API のクライアント証明書（`--tls-client-auth`・`--tls-client-ca`、トークンの `client_cert`）の組み合わせの誤りは、守りが弱くならないように起動を止める設定のエラー。

| 項目 | 場所 | 形 | features |
|---|---|---|---|
| ラベル（#28・#166） | ルールの `labels` | `{キー: 値}`。キーは英数字と `._/-`（63 文字まで）、値は 253 文字まで、16 個まで。動きには使わない（ログ・`/metrics`） | `labels` |
| L4 の制限（#165） | ルールの `limits` | `max_connections`、`per_source`（`prefix_v4`・`prefix_v6`・`max_connections`・`new_connections`・`packets`（udp だけ）・`max_sources`）。速さは `{average, period, burst}`（L7 の `rate_limit` と同じ） | `limits` |
| 帯域（#166） | ルールの `bandwidth` | `upload`・`download`（`"10Mbps"`、8kbps〜100Gbps）、`burst`（`"1MiB"`）、`per_source`（`upload`・`download`・`prefix_v4`・`prefix_v6`・`max_sources`）。TCP は待たせ、UDP は捨てる | `bandwidth` |
| GeoIP（#168。下の「GeoIP」） | ルールの `geoip`、ミドルウェアの `geoip`、`global.geoip` | `allow_countries`・`deny_countries`（ISO 3166-1 alpha-2）、`allow_asns`・`deny_asns`、`unknown`（`allow` / `deny`）。`global.geoip` は `country_db`・`asn_db`（mmdb）・`check_interval`・`log_country`。国のリストは `country_db`、ASN のリストは `asn_db` が要る | `geoip`、`middlewares` の `geoip` |
| 受け身のヘルスチェック（#170。下の「受け身のヘルスチェック」） | ルールの `outlier_detection`（L4。`http` のルールでは `invalid`）、`http.services.<名前>.outlier_detection` | L4：`consecutive_failures`・`short_lived`・`ejection_time`・`max_ejection_time`・`max_ejected_percent`。L7：`consecutive_5xx`・`consecutive_gateway_failures`・`failure_percent`・`min_requests`・`window`・`ejection_time`・`max_ejection_time`・`max_ejected_percent` | `outlier_detection`、`services` の `outlier_detection` |
| performance（#194・#184） | `global.performance` | `workers`、`udp_shards`（1〜64 か `auto`）、`cpu_affinity`（`none` / `auto` / `"0-3,6"`）、`busy_poll_usecs`、`splice`（`enabled`・`after`・`full_reads`・`pipe_size`）。項目ごとに、設定ファイル → 環境変数 `RPROXY_WORKERS`・`RPROXY_UDP_SHARDS`（数か `auto`）・`RPROXY_CPU_AFFINITY`・`RPROXY_BUSY_POLL_USECS`・`RPROXY_SPLICE*` → 既定の順。再起動まで効かない。下の「performance」 | `performance`（効く項目の名前。すべて） |
| ルールの組（#28） | `GET /rulesets`、`GET` / `PUT` / `DELETE /rulesets/{name}` | 下の「ルールの組・状態・readiness」 | `rulesets` |
| 状態（#28） | ルールの表示の `conditions` | `[{"type","status","reason","message","last_transition"}]`。type は `Accepted`・`Programmed`・`ResolvedRefs`・`BackendsHealthy`（下の「ルールの組・状態・readiness」） | `conditions` |
| readiness（#28） | `GET /readyz` | 認証なし。`200 {"ready": true}` / `503 {"ready": false, "reason": "starting" \| "draining"}` | `readyz` |
| 変更前の差分（#169） | `?dry_run=true`（`POST /rules`・`PATCH`・`DELETE`・`PUT /rulesets/{name}`・`POST /config/reload`）、`POST /config/plan`、`--check-config --diff` | 応答は `{"dry_run","action","change","rule","before","after","diff":[{"path","before","after"}],"warnings"}`。`change` は `none`・`in_place`・`recreate` | `dry_run` |
| API で作ったルールの保存（#144） | トークンの `persist: true`、テーブル `rproxy_rules`、`--node-name` | 表示に `origin: "api"`・`persisted`・`created_by`・`created_at` | `persistence` |
| 制御 API の守り（#167） | `--tls-client-ca`・`--tls-client-auth`、トークンの `client_cert`、`--token-warn-days`、`--api-lockout-failures`・`--api-lockout-window`・`--api-lockout-duration` | `client_cert` はトークンの `sha256` の代わり、両方あれば両方が要る。期限が近いトークンは `token.expiring`、続けて失敗した送信元は `429 locked_out`（既定で有効）。上の「制御 API の守り」 | `client_cert_auth`、`token_expiry`、`api_lockout` |
| 再起動なしの更新・自動更新（#174） | SIGUSR2・`POST /admin/upgrade`、`--handoff-*`、`RPROXY_UPDATE*`、`GET` / `POST /admin/update`、`rproxy-api launch` | 同じマイナーの中で待ち受けのソケットを新しいプロセスに渡す。自動更新は署名（minisign）を確かめてから。docs/UPGRADE.md | `handoff`、`self_update` |

- `limits`・`bandwidth`・`geoip`・`outlier_detection`・`labels` は `PATCH` で付けると丸ごと置き換える（`{}` で外す、省けば今のまま）。DB の `options` でも同じ形で読む。
- ルールの `stats` に `limited`（#165）と `counters_since`（#166、数え始めの Unix 秒。引き継ぎでは変わらない）が出る（動いているルール）。数はメモリにだけあり、再起動（異常終了の後も）では 0 から数え直す（`counters_since` も起動の時刻になる）。`stats.targets[]` に `ejected_until`（外していなければ null）・`ejections`（#170）が出る。
- トークンの入れ替え：新しいトークンを足して SIGHUP、クライアントを切り替えてから古いトークンを消して SIGHUP（`expires` を付けておくと `token.expiring` で知らせる）。詳しくは上の「制御 API の守り」。

### performance（`global.performance`、#194・#184）

```yaml
global:
  performance:
    workers: 8              # tokio のワーカースレッドの数（既定：使える CPU の数。cpu_affinity の一覧があればその数）
    udp_shards: auto        # UDP のポートごとの SO_REUSEPORT のソケットの数。1〜64 か auto（= workers）。既定 1
    cpu_affinity: none      # none・auto（ワーカー i を i 番目の CPU に固定）・"0-3,6"（ワーカーを一覧の CPU に順に固定し、ほかのスレッドは一覧の中で動かす）
    busy_poll_usecs: 0      # 待ち受けのソケット（受け付けた接続も引き継ぐ）の SO_BUSY_POLL（マイクロ秒）。0〜1000、0 で使わない
    splice: {enabled: true, after: 0, full_reads: 4, pipe_size: 0}   # L4 の平文の TCP の splice(2)（docs/PERFORMANCE.md）
```

- 項目ごとに、設定ファイル → 環境変数・引数（`RPROXY_WORKERS`・`RPROXY_UDP_SHARDS`・`RPROXY_CPU_AFFINITY`・`RPROXY_BUSY_POLL_USECS`・`RPROXY_SPLICE`・`RPROXY_SPLICE_AFTER`・`RPROXY_SPLICE_FULL_READS`・`RPROXY_SPLICE_PIPE_SIZE`）→ 既定の順で決める。`splice` の中も項目ごと。どれも起動のときだけ決まり、ファイルを変えたら `restart_needed` に出る。
- 起動時に `event = "performance"` の行に、効いている値と出どころ（`sources`：`workers=file` など）を出す。ワーカーのスレッドの名前は `rproxy-wrk-<番号>`。
- `cpu_affinity` の一覧の CPU が存在しない・このプロセスが使えない（cgroup・taskset）ものは除いて `degraded`（`part: global.performance.cpu_affinity`）。一覧が `workers` より少ないのは設定の誤り。
- `busy_poll_usecs` を `net.core.busy_read` より大きくするには `CAP_NET_ADMIN` が要る。設定できなければ `degraded` を 1 回出して普通に待つ。

### 変更前の差分（dry run、#169）

- `POST /rules?dry_run=true`・`PATCH /rules/...?dry_run=true`・`DELETE /rules/...?dry_run=true`：実際の操作と同じ検証（同じ `400` / `403` / `404` / `409`）をして、`200` で差分を返す。何も変えない：待ち受けを開かず、名前解決もしない（証明書・秘密のファイルは読んで確かめる）。スコープ・`allow_listen_ports`・`acme:write` も実際の操作と同じ。`audit` のログには残さない。
  ```json
  {"dry_run": true, "action": "update", "change": "in_place", "rule": "tcp/0.0.0.0:443",
   "before": {<今のルールの表示>}, "after": {<POST /rules の本文の形>},
   "diff": [{"path": "remote_port", "before": 80, "after": 8080}], "warnings": []}
  ```
  - `action`：`create`・`update`・`delete`・`none`（変わらない）。
  - `change`：`update` の効き方だけを表す。`in_place`（接続を切らずに変わる。PATCH の変更はすべてこれで、PATCH で変えられないものは実際の操作と同じく `400 unsupported`）・`recreate`（待ち受けを作り直す。今の接続は切れる：`failed` のルールを動かすとき、設定ファイル・組の変更で PATCH では変えられないもの）。`create`・`delete`・`none` は常に `none`（`PUT /rulesets` の `results` と同じ。削除で切れる接続の数は `warnings`）。
  - `before` はルールの表示（`GET /rules/...` と同じ）、`after` はルールの形（`POST /rules` の本文の形。状態・統計・`origin` はない）。`diff` は形どうしを比べた、変わった項目の JSON のパス（`.` でつなぐ。配列は丸ごと）と前後の値。作成は `{}` から、削除は `{}` へ。
  - `warnings`：削除で切れる接続の数など。
- `POST /config/reload?dry_run=true`：設定ファイルを読んで、反映したら何が変わるかを返す（反映しない）。`POST /config/plan`：本文の設定（設定ファイルと同じ形の JSON）を同じように比べる（ファイルは読まない。設定ファイルを使っていなければ、固定ルールはまだないものとして比べる）。どちらもスコープ（`admin`）と Unix ソケットの決まりは `POST /config/reload` と同じ。
  ```json
  {"dry_run": true, "added": 1, "removed": 0, "changed": 1, "unchanged": 3, "failed": 0,
   "restart_needed": ["global.trusted_proxies"],
   "changes": [{"rule": "tcp/0.0.0.0:443", "action": "update", "change": "in_place", "diff": [...]}],
   "warnings": [{"rule": "...", "message": "..."}]}
  ```
  - 数は `POST /config/reload` の答えと同じ意味（`failed` は作られるが `failed` になるもの：この版で動かない設定、証明書を読めない、API のルールが同じアドレスを持っている）。`changes` は変わるルールだけ（変わらないものは `unchanged` の数だけ）。`restart_needed` は起動したときの `global` との違い。
  - 誤りがあれば、反映と同じく `400 {"code":"invalid","error","errors":[...],"warnings":[...]}`。
- `rproxy-api --check-config [PATH] --diff [--diff-api unix:/path|URL] [--diff-token-file FILE]`：検証に通ったら、動いている rproxy に `POST /config/plan` で問い合わせて差分を出す。問い合わせ先の既定は `RPROXY_API_SOCKET`、なければ `http://<RPROXY_API_ADDR の先頭（0.0.0.0 / :: なら loopback）>:<RPROXY_API_PORT>`（`RPROXY_TLS_CERT` があれば https で、その証明書を信頼する）。トークンは平文の 1 行のファイル（`admin` のスコープが要る）。
  - `text` の出力は検証の結果の後に 1 行に 1 つの変更（`+` 作成・`~` 変更（変わった項目）・`-` 削除、`!` 再起動が要る `global`）と `plan: N to add, ...`。`json` は `Report` に `plan`（上の答え）を足したもの。
  - 終了コード：検証の誤り・問い合わせの失敗（つながらない、断られた）は 1、差分があってもなくても成功なら 0。
- 組（`PUT /rulesets/{name}?dry_run=true`、#28）も同じ差分の作り方（`config::plan` の `in_place`・`rule_diff`）で、`results` の `action`・`change` の意味も同じ（`diff` は `update` だけ）。

### API で作ったルールの保存（#144）

- トークンファイルで `persist: true` を付けたトークン（YAML の書き方だけ。既定は false）で作ったルールは `origin: "api"` になり、rproxy のテーブル `rproxy_rules` に保存する。UI のテーブル（`forward_rules`）には書かない。UI 用のトークンには付けない（UI は自分の DB に保存するので二重になる）。
- 書くのは作成・変更・削除の応答の前。`api` のルールは、どのトークンで変えても・消しても行を書き直す・消す（行がルールと食い違わないように）。`persist: true` のトークンでも、`dynamic` のルール（UI・保存しないトークンのもの）を変えたときは保存しない。
- 表示：`origin: "api"` のルールに `persisted`（行が最新か）・`created_by`（作ったトークンの名前）・`created_at`（Unix 秒）。書けなかったとき（DB に届かない、テーブルがない）はルールを動かしたまま `persisted: false`、ログに `event = "degraded"`（`part: "db"`）。`RPROXY_DATABASE_URL` がなければ保存しない（`persisted: false`）。保存したら `rule.persist`（`action: save` / `delete`、`token`）。
- 起動時は UI の `forward_rules` を復元してから、`rproxy_rules` の自分の `node`（`--node-name` / `RPROXY_NODE_NAME`、既定はホスト名）の行を `origin: "api"` で復元する。同じキーが両方にあれば UI の行を使い、`restore.conflict`（warn）を出す。テーブルが読めなければ `degraded`（`part: "db"`）を出して、UI のルールだけで起動する。`spec_version` がこの版より新しい行は `restore.skip` で読み飛ばす。
- テーブルの定義と GRANT は UI リポジトリの `db/` の migration に置く。rproxy が使う定義：

```sql
CREATE TABLE rproxy_rules (
  node         VARCHAR(255) NOT NULL,   -- RPROXY_NODE_NAME (default: the host name)
  protocol     VARCHAR(3)   NOT NULL,   -- tcp / udp
  listen_addr  VARCHAR(45)  NOT NULL,   -- IPv6 without brackets
  listen_port  INT UNSIGNED NOT NULL,
  spec         JSON         NOT NULL,   -- the rule in the shape of the body of POST /rules
  spec_version INT UNSIGNED NOT NULL DEFAULT 1,
  created_by   VARCHAR(255) NOT NULL,   -- token name
  created_at   DATETIME(3)  NOT NULL,
  updated_by   VARCHAR(255) NOT NULL,
  updated_at   DATETIME(3)  NOT NULL,
  PRIMARY KEY (node, protocol, listen_addr, listen_port)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON rproxy.rproxy_rules TO 'rproxy'@'%';
```

  `spec` はルールの形（`POST /rules` の本文の形、dry run の `after` と同じ）。`spec_version` は `spec` の読み方の版（今は 1）。時刻は DB のセッションのタイムゾーンで書き、`UNIX_TIMESTAMP` で読む。
### Gateway API 向けの L7・TLS（#224・#226〜#236）

rproxy-gateway（#28）が Gateway API の HTTPRoute・GRPCRoute・TLSRoute・BackendTLSPolicy を写すための設定。どれも省略でき、省略したときの動きはいままでと同じ。使えるかは `GET /capabilities` の `features` で分かる（`middlewares` に `cors`・`mirror`・`replace_host`、`services` に `protocol`・`tls`、`http_options` に下の名前、`tls_route_targets`）。

| 項目 | 場所 | 形 | features |
|---|---|---|---|
| ヘッダを足す（#224） | `headers` の `request` / `response` | `add: {名前: 値}` | `http_options` の `headers_add` |
| リダイレクトの状態コード（#226） | `redirect_scheme`・`redirect_regex` | `status`: 301・302・303・307・308 | `http_options` の `redirect_status` |
| ルートの時間の上限（#227） | `http.routes[].timeouts` | `{"request": "10s", "backend_request": "5s"}` | `http_options` の `route_timeouts` |
| Host の書き換え（#228） | ミドルウェア `replace_host` | `{"host": "one.example.org"}` | `middlewares` の `replace_host` |
| 転送先ごとのミドルウェア（#229、v0.4.3 で `cors`・リダイレクト・`mirror`） | `http.services.<名前>.servers[].middlewares` | `http.middlewares` の名前の一覧 | `http_options` の `server_middlewares`（使える種類は `server_middleware_kinds`） |
| CORS（#230） | ミドルウェア `cors` | `allow_origins`・`allow_methods`・`allow_headers`・`expose_headers`・`allow_credentials`・`max_age` | `middlewares` の `cors` |
| 状態コードでの送り直し（#231） | `retry` | `status: ["500", "502-504"]` | `http_options` の `retry_status` |
| ミラー（#232） | ミドルウェア `mirror` | `{"service": "<名前>", "percent": 20}` か `{"service": "<名前>", "fraction": {"numerator": 1, "denominator": 3}}` | `middlewares` の `mirror` |
| 転送先との HTTP/2（#233） | `http.services.<名前>.protocol` | `http1`（既定）・`h2`・`h2c`・`auto` | `services` の `protocol` |
| サービスごとの転送先の TLS（#236） | `http.services.<名前>.tls` | `server_name`・`ca_file`・`subject_alt_names`・`cert_file`・`key_file`・`chain_file`・`insecure_skip_verify` | `services` の `tls` |
| 名前ごとの複数の宛先（#234） | `tls.routes[]` | `targets: [{addr, port, weight, backup}]`・`balance`（`remote_addr` / `remote_port` の代わり） | `tls_route_targets` |
| クライアント証明書を確かめない（#238、`AllowInsecureFallback`） | `tls.client_auth.mode` | `optional_no_verify`（上の「証明書を確かめない `optional_no_verify`」） | `client_auth_modes` |
| 固定の状態コードの転送先（#235） | `http.services.<名前>.servers[]` | `{"status": 500, "weight": 1}`（`url` の代わり） | `http_options` の `server_status` |
| 421 Misdirected Request（v0.4.3） | `tls.misdirected` | `{"groups": [["*"], ["b.example"], ["**.w.example"]]}` | `http_options` の `misdirected` |
| 外部の認可（v0.4.3、`ExternalAuth`） | ミドルウェア `forward_auth` | `service`・`path`・`client_request`・`allow_status`・`response_headers: ["*"]`・`forward_body`・`protocol: grpc`（上の「`forward_auth`」） | `forward_auth` |

例（HTTPRoute 1 つの規則を写したもの）：

```json
{
  "routes": [{
    "name": "r0", "match": "Host(`app.example`) && PathPrefix(`/api/`)",
    "service": "r0", "middlewares": ["r0-hdr", "r0-cors", "r0-mirror", "r0-retry"],
    "timeouts": {"request": "10s", "backend_request": "2s"}
  }],
  "services": {
    "r0": {
      "protocol": "h2c",
      "servers": [
        {"url": "http://10.1.0.5:8080", "weight": 5, "middlewares": ["r0-b0"]},
        {"url": "http://10.1.0.6:8080", "weight": 5, "middlewares": ["r0-b0"]},
        {"status": 500, "weight": 10}
      ]
    },
    "r0-shadow": {"servers": [{"url": "http://10.1.0.9:8080"}]},
    "tls-svc": {"servers": [{"url": "https://10.1.0.7:8443"}],
      "tls": {"server_name": "abc.example.com", "ca_file": "/var/run/rproxy-gateway/certs/0123456789abcdef.crt",
              "subject_alt_names": ["abc.example.com", "spiffe://abc.example.com/test-identity"]}}
  },
  "middlewares": {
    "r0-hdr": {"headers": {"request": {"set": {"X-Header-Set": "v"}, "add": {"X-Header-Add": "v"}, "remove": ["X-Header-Remove"]}}},
    "r0-b0": {"headers": {"request": {"set": {"Backend": "v1"}}}},
    "r0-cors": {"cors": {"allow_origins": ["https://www.foo.com", "https://*.bar.com"], "allow_methods": ["GET", "OPTIONS"],
                         "allow_headers": ["x-header-1"], "expose_headers": ["x-header-3"], "allow_credentials": true, "max_age": 3600}},
    "r0-mirror": {"mirror": {"service": "r0-shadow", "percent": 20}},
    "r0-retry": {"retry": {"attempts": 4, "status": ["500", "502-504"], "initial_interval": "100ms"}},
    "r0-host": {"replace_host": {"host": "one.example.org"}},
    "r0-redirect": {"redirect_regex": {"regex": "^http://([^/:]+)(:\\d+)?/(.*)$", "replacement": "https://$1/$3", "status": 303}}
  }
}
```

- **`headers` の `add`**（#224）：同じ名前のヘッダ（大文字小文字を区別しない）があれば、その値（複数のフィールドなら `,` でつないだもの）の後ろに `,` で足して 1 本にする（`a` → `a,v`）。なければ足す。順は `remove` → `set` → `add`。転送先へ（`request`）も応答へ（`response`）も同じ。
- **リダイレクトの `status`**（#226）：指定すると、`permanent` とメソッドによる切り替え（GET・HEAD 以外は 308 / 307）より優先する。301・302・303・307・308 のほかは `400 invalid`。
- **ルートの `timeouts`**（#227）：`0s` は上限なし（省略と同じ）。
  - `request`：リクエストを受けてから応答の本文を送り終えるまで（ミドルウェア・`retry` の送り直し・待ち時間を含む）。応答ヘッダの前に過ぎたら 504（`event: "http.error"`、`error: "request timed out"`）。応答ヘッダの後に過ぎたら応答を途中で切る（HTTP/1.1 は接続を閉じる、HTTP/2 は RST_STREAM、HTTP/3 はストリームのリセット。完全な応答に見せない）。
  - `backend_request`：転送先への 1 回の送信の、送り始めから応答の本文の終わりまで。応答ヘッダの前に過ぎたら 504（`retry` が送り直せるなら次の転送先へ）。応答ヘッダの後は `request` と同じく切る。このルートではサービスの `timeouts.response` の代わりに使う（`timeouts.connect` はそのまま）。
  - 101（WebSocket など）の後の中継は数えない。
- **`replace_host`**（#228）：転送先へ送る `Host`（HTTP/2 の転送先なら `:authority`）を `host`（`host[:port]`）にする。サービスの `pass_host_header` より優先。`X-Forwarded-Host` はクライアントが送った値のまま。`match` には効かない（ルートを選んだ後に働く）。
- **転送先ごとのミドルウェア**（#229）：`servers[].middlewares` のミドルウェアは、その転送先へ送るリクエストにだけ、ルートのミドルウェアの後に働く（`retry` の送り直しでは、送り直す先の転送先のもの）。応答へは逆の順で、ルートのミドルウェアの応答側より先に働く。使える種類は `headers`・`replace_host`・`strip_prefix`・`add_prefix`・`replace_path`・`replace_path_regex`、v0.4.3 から `cors`・`redirect_scheme`・`redirect_regex`・`mirror`・`forward_auth`（ほかは `400 invalid`。`features.server_middleware_kinds` に一覧）。
  - v0.4.3 で足した種類（Gateway API の backendRef の `CORS`・`RequestRedirect`・`RequestMirror` のフィルタ）：`cors` はその転送先に当たったプリフライトに答え、その転送先の応答に CORS のヘッダを付ける。`redirect_scheme`・`redirect_regex` はその転送先に当たったリクエストに転送先へ送らずリダイレクトで答える（`retry` の送り直しはしない）。`mirror` はその転送先へ送るリクエストの写しを、そこまでのミドルウェア（ルートのもの、その転送先の前のもの）を通った形で `service` の転送先へも送る（`X-Forwarded-*` もそのまま。1 つのリクエストで 1 回だけ：`retry` の送り直しでは、最初に `mirror` のある転送先に当たったときだけ）。本文は流れてくるそのまま、`buffering` で読み切った本文はそれを写す。`mirror` の先のサービスの転送先が自分で `mirror` を持つと `400 invalid`（写しを写さない）。
- **`cors`**（#230）：
  - `allow_origins`：`https://www.foo.com`（スキーム・ホスト・ポートの完全一致、大文字小文字を区別しない）、`*`（すべて）、`https://*.bar.com`（`*` は 1 文字以上の何にでも一致。`.` を含む）。`*` は先頭のラベルとしてだけ書ける（`https://*bar.com` は `evilbar.com` に一致してしまうので `400 invalid`。セキュリティレビュー L13）。`*` と `allow_credentials: true` を同時に書くと、どのサイトにも資格情報つきのリクエストを許すことになるので `config.warning` を出す（Gateway API の決まりどおり `Origin` をそのまま返す）。
  - プリフライト（`OPTIONS` で `Origin` と `Access-Control-Request-Method` があるもの）は、オリジンを許すなら rproxy が 204 で答える：`Access-Control-Allow-Origin`（`allow_origins` が `*` で `allow_credentials` が false なら `*`、ほかは `Origin` の値）、`Access-Control-Allow-Methods`（`allow_methods` をカンマ区切りで。`*` なら、`allow_credentials` のときは求められたメソッド、そうでなければ `*`）、`Access-Control-Allow-Headers`（同じく。`*` なら `allow_credentials` のときは `Access-Control-Request-Headers` の値）、`Access-Control-Expose-Headers`、`Access-Control-Max-Age`（`max_age` があれば）、`Access-Control-Allow-Credentials: true`（`allow_credentials` のとき）、`Vary: Origin`。許さないオリジンのプリフライトも rproxy が 204 で答え、CORS のヘッダは付けない（`Vary: Origin` だけ。転送先へは送らない。#238。転送先が許してしまわないように）。`Origin` のない `OPTIONS` はプリフライトではないので転送先へ。
  - ふつうのリクエストは転送先へ送り、オリジンを許すなら応答に `Access-Control-Allow-Origin`・`Access-Control-Allow-Credentials`・`Access-Control-Expose-Headers`・`Vary: Origin` を付ける（転送先が返した同じ名前のヘッダは置き換える）。
  - `headers` の `cors` はいままでのまま。
- **`retry` の `status`**（#231）：転送先がこの状態コード（`"500"`・`"502-504"` のような値か範囲）を返したら、その応答を捨てて次の転送先へ送り直す（`balance` で選び直すので、転送先が 1 つなら同じ転送先へ。#238）。最後の回の応答はそのまま返す。送り直せる条件（冪等なメソッド、本文がないか `buffering` で読み切ったもの、Upgrade でない）と `attempts`（最初の 1 回を含む回数）・`initial_interval`（待ち時間。回ごとに倍）はいままでと同じ。Gateway API の `attempts` は送り直しの回数なので、写すときは `attempts + 1`。
- **`mirror`**（#232）：
  - 転送先へ送るリクエストの写しを、`service`（`http.services` の名前）の転送先へも送る。写しはルートの `middlewares` でそこまでのミドルウェアを通った形（ヘッダの書き換えの後ろに書けば書き換えた形）。`Host` は `service` の `pass_host_header` に従う。
  - `percent`（0〜100）か `fraction`（`numerator` / `denominator`、`denominator` の既定 100）の割合だけ写す（両方は `400 invalid`。省略で全部）。割合は数で揃える（無作為ではなく、`n` 件目を黄金比で散らす）。
  - ミラーの応答は読み捨て、つながらない・遅い・失敗はクライアントの応答に影響しない（ログは `event: "http.mirror"` の debug）。本文は流れてくる分を写し、ミラーが追いつかない（64 フレーム分たまった）ときはミラーの送信だけを途中で止める。
  - 前のミドルウェアが答えたリクエスト（リダイレクト・拒否）は写さない。1 つのルートに複数書ける。
- **`protocol`**（#233）：
  - `http1`（既定）：いままでどおり HTTP/1.1。
  - `h2`：`https://` の転送先と TLS（ALPN `h2`）の HTTP/2。転送先が `h2` を選ばなければ 502。
  - `h2c`：`http://` の転送先と、前置きから始める HTTP/2（prior knowledge）。
  - `auto`：`https://` の転送先は ALPN で `h2` と `http/1.1` を提示して、転送先が選んだほうで話す。`http://` の転送先は HTTP/1.1。
  - `h2` は `http://`、`h2c` は `https://` の転送先とは組み合わせられない（`400 invalid`）。
  - HTTP/2 の転送先とは、接続を多重化して使い回す（閉じられたら次のリクエストでつなぎ直す）。1 本の接続に 100 件を超えて流すときは、転送先ごとに 8 本まで接続を足す。それでも空きがなく、転送先の `SETTINGS_MAX_CONCURRENT_STREAMS` で本文のあるリクエストがストリームを得られないときは、`timeouts.connect` の間待って 504（セキュリティレビュー M6：遅い本文で全部のリクエストが止まらないように）。接続を開くのは一度に 1 つで、空きのある接続を使うリクエストは待たない。`source_ip: transparent` のルールではクライアントごとに新しい接続。
  - トレーラーは両方向にそのまま流す（gRPC の `grpc-status` など）。クライアントの `TE` に `trailers` があれば、HTTP/2 の転送先へ `te: trailers` を渡す（ほかのホップごとのヘッダはいままでどおり取り除く）。
  - `timeouts`・`retry`・`health_check`（HTTP/2 で `GET`）・`outlier_detection`・`sticky` は HTTP/1.1 の転送先と同じ。HTTP/2 の転送先への Upgrade（WebSocket）は 502。
  - gRPC：クライアントは HTTP/2（TLS か h2c）で rproxy につなぐ。サービス・メソッドの一致は `Path(`/<package.Service>/<Method>`)`・`PathPrefix(`/<package.Service>/`)` で書く。
- **サービスの `tls`**（#236）：
  - そのサービスの `https://` の転送先には、ルールの `tls.upstream` の代わりにこれを使う（項目ごとに混ぜない）。平文の HTTP のルール（`tls` なし）でも使える。
  - `server_name`：SNI と、証明書で確かめる名前（既定は URL のホスト）。`ca_file`：転送先の証明書を確かめる CA（既定は Mozilla のルート）。`subject_alt_names`：指定すると、証明書の SAN の DNS 名か URI（`spiffe://...` など）のどれかがこの一覧にあることを確かめる（`server_name` での名前の確認の代わり。署名・期限は確かめる）。`cert_file`・`key_file`（・`chain_file`）：転送先へ出すクライアント証明書。`insecure_skip_verify`：確かめない（試験用）。
  - ファイルはルールを作る・変えるときに読む（変わったファイルはルールの変更で読み直す。rproxy-gateway は中身のハッシュの名前にする）。`http://` の転送先だけのサービスに書いても使わない。
- **`tls.routes[]` の `targets`**（#234）：`remote_addr` / `remote_port` の代わりに `targets`（ルールの `targets` と同じ形、`weight`・`backup` も同じ）と `balance`（`round_robin`（既定）・`least_conn`・`failover`）。どちらか一方が要る（両方・どちらもなしは `400 tls_config`）。接続できない宛先は次の宛先へ移り、10 秒外す（ルールの `targets` と同じ）。`passthrough` の route、`sni` のルールの route のどちらでも使える。名前の再解決もルールの `targets` と同じ。ポート範囲のルールでは各宛先のポートも同じだけずれる。
- **`servers[]` の `status`**（#235）：`url` の代わりに `status`（100〜599）を書くと、その転送先に当たったリクエスト（`weight` の割合）に rproxy がその状態コードで答える（本文は `500 Internal Server Error` のような文）。ヘルスチェック・`outlier_detection`・`sticky` の対象にしない（`sticky` のクッキーも付けない）。`url` と `status` はどちらか一方（両方・どちらもなしは `400 invalid`）。`middlewares` は付けられない。
- **`tls.misdirected`**（v0.4.3、Gateway API の `GatewayHTTPSListenerDetectMisdirectedRequests`）：同じポートの名前の違う HTTPS のリスナーを 1 つのルールにまとめたとき、HTTP/2 の接続の使い回し（connection coalescing。証明書の SAN にある別の名前のリクエストを同じ接続で送る）で、ほかのリスナーの名前のリクエストが届くのを 421 Misdirected Request（RFC 9110 §15.5.20）で断る。
  - `groups`：名前のパターンのグループの一覧（`tls.routes` と同じ書き方：完全一致・`*.`（1 階層）・`**.`（何階層でも）。`*` はどの名前にも一致するグループ。同じパターンを 2 か所に書くと `400 tls_config`）。名前は最も近いパターンのグループに入る（完全一致 → `*.` → 長い `**.` → `*`）。
  - 接続の TLS のサーバ名（SNI）と、リクエストの `Host`（HTTP/2・HTTP/3 は `:authority`、ポートを除く）がどちらもグループに入り、違うグループなら 421（ルートもミドルウェアも通らない。アクセスログは `route: "(none)"`・`refused_by: "misdirected"`）。どちらかがどのグループにも入らないとき（`*` のグループがなく、ほかのリスナーの名前でもない）と SNI のない接続は確かめず、いつものとおり `http.routes` で選ぶ（一致しなければ `http.default`、既定 404）。HTTP/1.1・HTTP/3 も同じ。
  - `http` と `tls.mode: terminate` のルールだけ（ほかは `400 tls_config`）。省略すれば確かめない（v0.4.2 までと同じ）。

### ルールの組・状態・readiness（Kubernetes のコントローラ向け、#28）

Kubernetes のコントローラ（別のリポジトリ `max3584/rproxy-gateway`）は、この API だけで rproxy を動かす。正確な形は `docs/openapi.json`（`GET /openapi.json`）。

**ルールの組（ruleset）**：`PUT /rulesets/{name}` に「その組のルールの全体」を毎回まとめて送ると、rproxy が今のルールとの差を当てる（宣言的。途中で落ちても次の PUT で揃う）。

- 名前は `[a-z0-9]([a-z0-9._/-]{0,251}[a-z0-9])?`（例 `k8s/default/web-gateway`）。パスの `/` はそのまま書く（`PUT /rulesets/k8s/default/web-gateway`）。
- 本文は `{"generation": <整数>, "rules": [<POST /rules と同じルール>...]}`（ルールは 10,000 個まで、本文は 32 MiB まで）。同じキーのルールを 2 つ書くと `400 invalid`。
- 順番：まず全部を確かめ、どれかが通らなければ**何も変えない**。
  0. 持ち主（セキュリティレビュー M3）：組はそれを作ったトークン（`owner`）のもので、ほかのトークンは `admin` でなければ `PUT` / `DELETE` できない（`403 forbidden`）。トークンの `allow_rulesets`（名前の先頭の一覧）の外の名前も `403`。rproxy の再起動のあと先に組を作られないように、コントローラのトークンには `allow_rulesets: [k8s/]` のように付け、ほかの `rules:write` のトークンには付けない名前にする。`generation` は 2^53 - 1 まで（`400 invalid`。JSON のクライアントが正しく読める数）。
  1. `If-Match`（あれば）：今の etag と違う、または組がまだないと `412 precondition_failed`。`*` は「組があれば」。ETag ヘッダの引用符つきの値でも、本文の `etag` の値そのままでもよい（`W/`・カンマ区切りも受ける）。
  2. `generation`：覚えている値より小さいと `409 stale_generation`（同じ値はよい）。
  3. 各ルールの形（`POST /rules` と同じ検証。この版で動かせない設定は `unsupported`）と、本文の中のルール同士の重なり（`400 invalid`）。
  4. 組の外のルールとの取り合い：設定ファイルのルールと同じキーは `409 static`、ほかの組のルールは `409 owned`、`POST /rules` で作ったルールや待ち受けが重なるルールは `409 already_exists`、制御 API のアドレスは `409 reserved`。
  5. 作る・変える・消すルールの待ち受けポートがトークンの `allow_listen_ports` の内か（外なら `403`。変えるルールは、今の待ち受けの範囲も内であること：狭めて範囲の外の待ち受けを消せないように。セキュリティレビュー M2）、ACME の証明書を使うルールには `acme:write`。
  6. 作る・変えるルールの証明書・秘密のファイルが読めるか（`400 tls_config` / `invalid`）。
  - 断るときの本文は `{"code","error","errors":[{"index","rule","code","message"}]}`。`code` と `error`（`rules[i]: ...`）は最初の問題、`errors` はルールの問題のすべて（`index` は本文の `rules` の何番目か）。
- 当て方：組から外れたルールを先に止め（接続は切れる）、変わったルールは PATCH で接続を切らずに変えられる違い（宛先・`balance`・`health_check`・時間・TLS・`allow_from`・`extra_listen_addrs`・`http`・`labels` などの v0.4 の設定）ならその場で変え（`change: in_place`）、そうでなければ（ポートの範囲・`source_ip`・`http` の有無）待ち受けを作り直す（`recreate`）。新しいルールは作り、変わらず動いているルールには触らない（`none`）。`failed` のルールは変わっていなくても作り直す。
- bind・名前解決に失敗したルールはそのルールだけ `failed` に登録して（理由は `conditions`）、残りは当てる。応答は `200` で、ルールごとの結果を返す：`{"name","generation","etag","dry_run":false,"results":[{"rule":"tcp/0.0.0.0:443","action":"create|update|delete|none","change":"none|in_place|recreate","state":"running|failed","error"}]}`（本文の順、その後に消したルール。`delete` には `state` がない）。応答の `ETag` ヘッダは `etag` を `"` で囲んだもの。
- etag は `g<generation>-<ルールの正規化した JSON（キーの順）の SHA-256 の先頭 16 桁>`。ルールか `generation` が変わると変わり、状態（`running` / `failed`）では変わらない。
- `?dry_run=true`：同じ確かめをして、変えずに結果（`dry_run: true`、なるはずの `etag`、`update` には `diff`）を返す。`change` と `diff` の意味は上の「変更前の差分」と同じ。
- 組のルールは `GET /rules` にも出て `ruleset: "<名前>"` が付く（`origin` は `dynamic`）。個別の `PATCH` / `DELETE /rules/...` は `409 owned`（変えるなら組を PUT する）。`POST /rules` で同じキーは `409 already_exists`。
- `GET /rulesets/{name}`：`{"name","generation","etag","updated_at","updated_by","owner","rules":[<GET /rules と同じ表示>...]}`（キーの順、`ETag` ヘッダつき）。`updated_by` は最後に PUT したトークンの名前（トークンファイルがなければ空）。`GET /rulesets` は名前の順の一覧（`rules` は数）。
- `DELETE /rulesets/{name}?drain_secs=N`：組のルールを同時に止めて組を消す（`drain_secs` の間、各ルールの接続の終わりを待つ）。`If-Match` も使える。全部の接続が終わってから `204`。
- 組は rproxy のメモリにだけあり、DB にも設定ファイルにも書かない（v0.4.2 から、`persist: true` のトークンの組だけは `rproxy_rule_sets` に保存できる：下の「ルールの組の保存」）。rproxy を再起動したら、コントローラは `GET /readyz` が 200 になってから組を PUT し直す。組の変更は 1 つずつ順に行う（読むのは待たない）。
- ログ：`event = "ruleset.apply"`（`ruleset`・`generation`・`etag`・`created`・`updated`・`deleted`・`unchanged`・`failed`・`by`）、`ruleset.delete`（`ruleset`・`rules`）。個々のルールの `rule.create` / `rule.update` / `rule.delete` にも `ruleset` が付く。`audit` は `action: ruleset.put` / `ruleset.delete` と `ruleset`。

**ラベル**：ルールの `labels`。動きには使わず、`rule.create` / `rule.update` のログ（`labels: "k=v,k2=v2"`）と `/metrics` の `rproxy_rule_labels{rule="tcp/0.0.0.0:443",label_tenant="act"} 1` に出す（キーの英数字以外は `_`。同じ名前になるキーは名前の順で先のものだけ）。`PATCH` で付けると丸ごと置き換える（`{}` で外す、省けば今のまま）。

**状態（conditions）**：どのルールの表示にも（組でなくても）、次の 4 つがこの順で付く（Gateway API の status にそのまま写せる形）。`message` は `True` のとき空。

| type | `True` の reason | `False` の reason |
|---|---|---|
| `Accepted` | `Accepted` | `Unsupported`（この版・この環境で動かせない設定。起動時・再読み込みのルール） |
| `Programmed` | `Listening`（`state: running`） | `BindFailed`（ポートを開けない）、`Pending`（転送先の名前解決を待って再試行中）、`Failed`（その他） |
| `ResolvedRefs` | `ResolvedRefs` | `ResolveFailed`（名前解決できない転送先がある）、`CertificateExpired`（サーバ証明書が切れた）、`CertificateUnreadable`（証明書・鍵・CA を読めない）、`SecretUnreadable`（ミドルウェアの秘密のファイルを読めない） |
| `BackendsHealthy` | `Healthy` | `AllTargetsDown`（すべての宛先が down）、`ServiceDown`（サーバがすべて down の `http` のサービスがある。`message` に名前）。動いていないルールは `status: "Unknown"`・`NotProgrammed` |

- `last_transition` は `status` が最後に変わった Unix 秒（`reason`・`message` だけが変わっても動かない）。`Programmed` の `True` は `started_at` から。ほかの変化はルールを読んだとき（`GET /rules`・`GET /rulesets/{name}`・PUT の応答）に気づいた時刻。ルールを消す・作り直すと最初から。
- 今までの `state`・`error`・`all_targets_down`・`down_services` もそのまま（UI が使う）。

**readiness**：`GET /readyz`（認証なし、`/healthz` と同じ）。起動時の復元（設定ファイル・DB）が終わると `200 {"ready": true}`、その前と、終了の処理に入った後（#174 の引き継ぎでも、`RPROXY_SHUTDOWN_DELAY` の間も）は `503 {"ready": false, "reason": "starting" | "draining"}`。ルールの失敗は readiness に含めない（ルールの状態は `conditions`）。生きているかは今までどおり `/healthz`。

### L4 の制限と帯域（#165・#166）の動き

`features.limits`・`features.bandwidth` は true（形は上の表と docs/DESIGN-v0.4.md の 4・5）。

- `limits` は受け付けた直後（`allow_from`・`geoip`・`crowdsec` の後、TLS・PROXY ヘッダより前）に確かめる。超えたら TCP は何も送らずに閉じ、UDP はデータグラムを捨てる（新しいセッションは作らない）。`http` のルールでは TCP の接続に効く（HTTP/3 には効かない）。`max_connections` は TCP の接続・UDP のセッションの数（`per_source.max_connections` も同じ）、`new_connections` は新しい接続・セッションの速さ、`packets` は UDP のデータグラムの速さ（送信元ごと）。
- 断った数は `stats.limited`、`/metrics` の `rproxy_rule_limited_total{protocol,listen,reason}`（`limits` のあるルールだけ。ほかの指標と同じく `rule` の代わりに `protocol`・`listen` のラベル）。ログは `conn.limited`（`rule`・`client`・`reason`（`max_connections` / `source_connections` / `new_connections` / `packets`）・`transport`（`tcp` / `udp`）。送信元ごとに続けて 20 行まで、その後は 1 秒に 1 行、`suppressed` は省いた行の数）。
- 送信元は `prefix_v4` / `prefix_v6` でまとめ、覚えるのは `max_sources` まで（16 に分けた表ごとに上限の 1/16。いっぱいになったら、接続の残っていない古いものから忘れる。接続の残っている送信元は忘れない（数え直しで制限をすり抜けられないように。セキュリティレビュー L8）。表がそういう送信元でいっぱいのあいだ、新しい送信元は `limits` では断り（`reason: source_connections`）、`bandwidth` では 1 つの共有のバケツを使う）。`max_sources` は 1,000,000 まで。
- `PATCH` で `limits` を変えると、次の接続・データグラムから効く。ルール全体の接続数は引き継ぎ、送信元ごとの数とバケツは `prefix_v4`・`prefix_v6`・`max_sources` が同じなら引き継ぐ。`{}` で外すと数えるのをやめる（あとで付け直したときは、そこから数える）。
- `bandwidth`：TCP（`http` のルールを含む）は読むのを待たせて絞る（捨てない）。L4 は上り（クライアントから読む）・下り（転送先から読む）、`http` のルールはクライアントからの読み込みとクライアントへの書き込み。待っている間は中継のバッファをプールに返す。UDP は超えたデータグラムを捨て、`stats.dropped` と `rproxy_rule_bandwidth_dropped_total{protocol,listen}` に数える。HTTP/3 は絞らない。
- 速さはトークンバケツ（`burst` が大きさ、既定は 100 ms 分）。ルール全体のバケツはルールの全接続、送信元ごとのバケツはその送信元の全接続で分ける。TCP は 4 KiB（`burst` が小さければその大きさ）たまるまで待ってから読む。データグラムや読んだ量が残りより大きければ借りにして、その分あとで待つ（長い目で見て速さを守る）。
- splice（#184）は帯域の上限のないルールでだけ使う。上限のあるルールの平文の TCP はユーザー空間のコピーで絞る。`PATCH` で上限を付けると、splice している接続も次の splice の前にユーザー空間のコピーに戻り、それからは上限を外しても splice に戻らない。
- `PATCH` で `bandwidth` を変えると、開いている接続にも次に読むところから効く（バケツは満杯から）。
- 上限を付けていないルールの転送は、読み込みごとに 1 回の不可分な読み出し（relaxed load）が増えるだけ。
- 集計（#166 5.2）：`stats.rx_bytes`・`tx_bytes`・`total_connections` は単調増加、`stats.counters_since` は数え始めた時刻（Unix 秒。ルールを作り直すと変わる、`PATCH` では変わらない）、`stats.limited` を足した。`/metrics` に `rproxy_process_start_time_seconds`。

### GeoIP（#168）

```yaml
global:
  geoip:
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb   # Country か City の mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb           # 任意
    check_interval: 1m     # ファイルが変わったか確かめる間隔（既定 1m、0s で確かめない）
    log_country: true      # conn.open・http.access に country（と asn）を足す（既定 false）
rules:
  - {protocol: tcp, listen_addr: 0.0.0.0, listen_port: 25565, remote_addr: 10.0.0.5, remote_port: 25565,
     geoip: {allow_countries: [JP], deny_asns: [64496], unknown: allow}}
```

- データベースは同梱しない。MaxMind の GeoLite2（アカウントを作って `geoipupdate` で取る）か、同じ項目（`country.iso_code`、なければ `registered_country.iso_code`、`autonomous_system_number`）を持つ mmdb を使う。ファイルはメモリに読み込み（mmap はしない）、`check_interval` ごとと SIGHUP で変わっていれば読み直す（`event: "geoip.reload"`）。読み直せない（書きかけ・壊れている・権限）ときは今のものを使い続ける（`event: "degraded"`、`part: "geoip"`。同じ問題は 1 回だけ）。起動時（と `--check-config`）は、ファイルがない・mmdb でないなら設定のエラーで起動しない。権限で読めないなら `degraded` を出して起動し、読めるまでそのデータベースの判定はすべて「分からない」になる。
- 判定：まず `deny_*` に当たれば拒否。`allow_*` のどれかが書いてあれば、どれかの `allow_*` に当たるものだけ通す（分かっている国か ASN が、そのリストに当たらなければ拒否。もう一方が分からなくても拒否する。セキュリティレビュー L18）。リストが要る国・ASN がどれも分からない（データベースにない・私用アドレス・データベースが読めない）ものは `unknown`（既定 `allow`）。**データベースが読めないときも `unknown` になる**ので、拒否に倒したいときは `unknown: deny` にする。データベースは 1 GiB まで（それより大きいファイルは読まない）。
- L4（ルールの `geoip`）：`allow_from` の後、`crowdsec` の前、受け付けた直後（TLS・PROXY ヘッダより前）に判定する。TCP は接続を閉じ、UDP はデータグラムを捨てる（開いているセッションのものも。セッションは作らない）。HTTP/3 は QUIC の接続を受ける前。`http` のルールでも使える（見るのは接続元の IP）。拒否は `stats.denied` に数え、`conn.denied`（`reason: "geoip"`、分かれば `country`・`asn`。UDP は `allow_from` と同じく送信元ごとに間引く）。
- L7（ミドルウェアの `geoip`）：`global.trusted_proxies` で決めたクライアントの IP で判定し、拒否は `403`（`ip_allow` と同じ）。`http.access` の `refused_by: "geoip"`・`middleware`、`country`・`asn`。
- `log_country: true` で、`conn.open`（TCP・UDP）と `http.access` に `country`（と `asn`）が付く（分からないときは付かない）。
- 国のリストは `country_db`、ASN のリストは `asn_db` がないと `400 invalid`（設定ファイルは検証の誤り）。`PATCH` で `geoip` を付けると丸ごと置き換え、`{}` で外す（接続は切らない。次の接続・データグラムから）。
- CrowdSec と組み合わせるとき：国・ASN での粗い絞り込みは `geoip`、振る舞いでの ban は CrowdSec（L4 のルールの `crowdsec: true`、L7 の `crowdsec` ミドルウェア）。判定の順は `allow_from` → `geoip` → `crowdsec`。CrowdSec の側でも `crowdsecurity/geoip-enrich` で国を付けられるので、rproxy の `log_country` は SIEM などで rproxy のログだけを見るとき向け（docs/CROWDSEC.md）。

### 受け身のヘルスチェック（#170）

実際の通信で失敗が続いた宛先を、しばらく外す（outlier detection）。外した宛先は down と同じく選ばない（L4 は、すべての宛先が外れている・down のときは今までどおり順に試す）。外す時間が過ぎたら自然に戻る（`target.up`、`reason: "outlier"`）。`health_check` で up に戻った宛先はすぐ戻る。

**L4**（ルールの `outlier_detection`。宛先が 1 つでも使えるが、意味があるのは複数のとき）：

| 項目 | 既定 | 意味 |
|---|---|---|
| `consecutive_failures` | `1` | 続けて失敗した回数（1〜1000）。失敗は TCP の接続を断られた・時間切れ（`cause: connect`）、UDP の ICMP の到達不能（`refused`）、`short_lived` |
| `short_lived` | `0s`（数えない） | TCP で、転送先が先に閉じた（切った）接続のうち、つながってからこの時間（0s〜1m）より短いものも失敗に数える。そのとき接続の成功は接続が終わるときに数える。UDP には効かない |
| `ejection_time` | `10s` | 最初に外す時間（1s〜1h） |
| `max_ejection_time` | `ejection_time` | 外すたびに倍にし、ここで止める（戻ってからこの時間のあいだ外されなければ、`ejection_time` に戻る） |
| `max_ejected_percent` | `100` | 同時に外せる宛先の割合（0〜100。`0` で外さない） |

- 書かなければ v0.3 までと同じ（接続に 1 回失敗したら 10 秒外す）。`{}` も同じ。
- 外しているあいだにまた失敗した宛先（すべて外れていて試されたもの）は、外す時間を最初から数え直す（回数は増やさない）。
- `PATCH` で変えると次の接続から効き、宛先ごとの回数と外している状態はそのまま（宛先・`balance`・`health_check` も変えたときは最初から）。

**L7**（`http.services.<名前>.outlier_detection`。書いたサービスだけ）：

| 項目 | 既定 | 意味 |
|---|---|---|
| `consecutive_5xx` | `5` | 続けて 5xx を返した回数（0 で見ない）。下の gateway の失敗も数える |
| `consecutive_gateway_failures` | `3` | 502・503・504、接続できない、`timeouts.response` の時間切れが続いた回数（0 で見ない） |
| `failure_percent` | なし | `window` の中で失敗（5xx・gateway の失敗）の割合がこれ以上なら外す（1〜100） |
| `min_requests` | `20` | `failure_percent` を見る最小のリクエスト数 |
| `window` | `30s` | `failure_percent` を数える窓（区切りごとに数え直す） |
| `ejection_time` / `max_ejection_time` | `30s` / `5m` | L4 と同じ |
| `max_ejected_percent` | `50` | 同時に外せるサーバの割合。既定ではサーバが 1 つのサービスは外さない |

- `circuit_breaker`（ミドルウェア。サービス全体を止める）とは別で、サーバごとに外す。数えるのは転送先への 1 回ごとのリクエスト（`retry` の試し直しもそれぞれ数える。`errors`・`forward_auth` のページの取得も）。
- 外したサーバは `stats.http.services.<名前>` のサーバに `"ejected": true`（`up` は false。`outlier_detection` のあるサービスは `health_check` がなくても出る）、`/metrics` の `rproxy_http_server_up` も 0。すべてのサーバが外れていて（`max_ejected_percent: 100`）、ヘルスチェックで up のものがあれば、それを使う。
- ログは `target.down`（`reason: "outlier"`、`rule`、`service`、`server`、`cause`：越えたしきい値 `consecutive_5xx`・`consecutive_gateway_failures`・`failure_percent`、`ejection_secs`、`ejections`）/ `target.up`（`reason: "outlier"`）。
- `http` を変えると数え直し（`Router` を組み立て直すため）。

## v0.4.x で足した設定

v0.4.0 の後にパッチで足した設定（docs/DESIGN-v0.4.x.md。足すだけの形はパッチで出す：docs/RELEASING.md の「v0.4.0 の後」）。どれも省略でき、省略したときの動きは v0.4.0 と同じ。使えるかは `GET /capabilities` の `features` で分かる。

### SIGTERM での終わり方（v0.4.1、`features.graceful_shutdown`）

| 引数 / 環境変数 | 既定 | 意味 |
|---|---|---|
| `--shutdown-delay` / `RPROXY_SHUTDOWN_DELAY` | `0s` | SIGTERM の後、`/readyz` を 503 `draining` にしたまま、これだけ今までどおり受け付ける |
| `--shutdown-drain` / `RPROXY_SHUTDOWN_DRAIN` | `0s` | その後、待ち受けを閉じて、今の接続・セッションの終わりをこれだけ待つ。過ぎたら切る |

- 既定（両方 `0s`）は今までと同じで、SIGTERM ですぐ止める。値は `30s`・`2m`・秒の数で、それぞれ 1 時間まで（超えると起動を止める設定のエラー）。
- `delay` の間：転送は今のまま（新しい接続も受ける）。
- `drain` の間：TCP の待ち受けを閉じ（新しい接続は断られる）、今の接続は続く。`http` のルールは処理中のリクエストの応答に `Connection: close` を付けてから閉じ（HTTP/2 は GOAWAY）、アイドルの接続はすぐ閉じる。HTTP/3 は新しい QUIC の接続を受けない。UDP は新しいセッションを作らず（そのデータグラムは `stats.dropped`）、今のセッションは続く。
- `delay`・`drain` の間、制御 API の読むだけの要求（`GET`・`HEAD`。`/healthz`・`/readyz`・`/metrics` も）は答え、変更（`POST`・`PUT`・`PATCH`・`DELETE`、dry run も）は `503 shutting_down`。設定ファイルの変化は反映しない。再起動なしの更新（SIGUSR2・自動更新）も始めない。
- 2 回目の SIGTERM・SIGINT で残りを待たずに止める。
- 引き継ぎ（SIGUSR2）の後の古いプロセスの終わり方は今までどおり（`RPROXY_HANDOFF_DRAIN`）。
- ログ：`shutdown.start`（`delay_secs`・`drain_secs`）、`shutdown.drain`（`connections`）、`shutdown.now`（2 回目のシグナル）、`shutdown.done`（`cut`）。systemd での推奨値は README の「SIGTERM での終わり方」。

### 証明書の API（v0.4.2、#240、`features.cert_store`）

証明書と鍵を制御 API で渡して rproxy に保存し、ルールから名前で使う（cert-manager などの Secret を外から押し込む使い方）。鍵は DB に置かず、応答・ログに出さない。

| メソッドとパス | 本文 | 成功時 | 説明 |
|---|---|---|---|
| `PUT /certs/{name}` | `{"cert": "<PEM>", "key": "<PEM>", "chain": "<PEM>"?}` | 201（新しく）/ 200（差し替え） | 確かめて保存する：PEM が読める、鍵と証明書が合う、チェーンの順、期限内（切れていれば `400 invalid`、`RPROXY_CERT_WARN_DAYS` 以内なら応答に `warnings`）。`If-Match`（`fingerprint_sha256`、`*` はあれば）が違えば `412 precondition_failed`。応答は下の 1 件の形と `ETag`。本文は 1 MiB まで（超えると 413） |
| `GET /certs` | | 200 | `[{"name","sans","not_before","not_after","fingerprint_sha256","issuer","used_by":["tcp/0.0.0.0:443",...],"updated_at","updated_by"}]`（トークンの `allow_certs` の内だけ）。鍵は返さない |
| `GET /certs/{name}` | | 200 | 上の 1 件（なければ `404 not_found`） |
| `DELETE /certs/{name}` | | 204 | 使うルール（設定ファイル・API・組）があれば `409 in_use`（本文に `used_by`）。`If-Match` も受ける |

- 名前：`[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?`（外は `400 invalid`）。
- スコープ：`certs:read`（`GET`）、`certs:write`（`PUT`・`DELETE`）。トークンの `allow_certs`（名前の先頭）の外は `403 forbidden`。
- 鍵が流れるので、TCP の制御 API では TLS か loopback からだけ受け付ける（Unix ソケットもよい）。ほかの平文の TCP からの `PUT` は `403 tls_required`。
- ルールからは `tls.certificates[]` に `{"cert": "<name>"}`（`cert_file`・`key_file`・`chain_file`・`acme` の代わり。どれか 1 つ）。API・設定ファイル・DB・組で同じ形。`tcp` の `terminate`（`http` のルールを含む）と `udp` の DTLS で使える。`client_auth`・転送先の証明書にはまだ使えない。使うには `rules:write` と、名前がトークンの `allow_certs` の内であること（外は `403`）。
  - 保存していない名前：API の作成・変更・組の PUT は `400 tls_config`（`certificate "<name>" is not in the certificate store`）。起動時・再読み込みのルールは `failed` になり、その名前が `PUT` されると動き出す。
  - 差し替え（同じ名前の `PUT`）：使っているルールは接続を切らずに新しい証明書になる（`RPROXY_CERT_CHECK_SECS` を待たない）。
- 保存先：`--cert-store` / `RPROXY_CERT_STORE`（既定 `/var/lib/rproxy/certs`）。`<name>/<指紋の先頭 16 桁>/tls.crt`（チェーンつき）・`tls.key` に書き、`<name>/current` のシンボリックリンクを付け替える。ディレクトリは 0700、ファイルは 0600 で rproxy-api のもの（`global.files.owner_check: strict` で使える）。`trusted_dirs` の下には置けない（起動を止める）。書けないときは `PUT` が `503 cert_store_unavailable`（`RPROXY_CERT_STORE` を指定していれば起動時に `degraded`、`part: "cert_store"`）。
- 監査：`event=audit`、`action: cert.put` / `cert.delete`、`cert`（名前）・`fingerprint_sha256` だけ。
- 引き継ぎ（#174）ではファイルなので何も渡さない。複数の rproxy にはノードごとに `PUT` する。rproxy-gateway は使わない（Secret のボリューム）。

### ルールの組の保存（v0.4.2、#241、`features.ruleset_persistence`）

- `persist: true` のトークン（上の「API で作ったルールの保存」と同じ印。`PUT` の本文には足さない）で `PUT /rulesets/{name}` した組を、テーブル `rproxy_rule_sets` に 1 行（組のルールを JSON で）保存する。一度保存した組は、どのトークンで変えても・消しても行を書き直す・消す。`persist` のないトークン（Kubernetes のコントローラなど）の組は今までどおりメモリだけ。
- 書くのは `PUT` の応答の前（`dry_run` は書かない）。行の `generation` がこの `PUT` より新しければ書き換えない。`DELETE` で行を消す。書けなければ（DB に届かない、テーブルがない、`max_allowed_packet` を超える）組は動かしたまま `persisted: false`、ログに `event = "degraded"`（`part: "db"`）。保存したら `ruleset.persist`（`action: save` / `delete`）。
- 表示：保存した組の `PUT` の応答・`GET /rulesets`・`GET /rulesets/{name}` に `persisted`（行が最新か）。保存しない組には付かない。
- 起動時：設定ファイル → UI の `forward_rules` → `rproxy_rules` の後に、自分の `node` の行を戻す（持ち主・`generation` も。`etag` は同じルールなら同じ値になる）。前に戻したルールとキー・待ち受けが重なるルールや、ファイルを読めないルールはその組から外して（`restore.conflict` / `restore.skip`）、残りを当てる（`ruleset.restore`）。`/readyz` は戻し終わってから ready。テーブルがなければ（migration 012 の前）何もしない。
- ノードの間では分けあわない（自分の `node` の行だけ）。複数の rproxy には呼ぶ側がそれぞれに `PUT` する。rproxy-gateway は使わない（正は Kubernetes にあり、再起動の後はコントローラが PUT し直す）。
- 大きさ：`PUT` の本文は 32 MiB までだが、MariaDB の `max_allowed_packet`（既定 16 MiB）を超える組は書けない（`persisted: false`）。
- テーブル（UI リポジトリの `db/migrations/012_rproxy_rule_sets.sql`）：

```sql
CREATE TABLE IF NOT EXISTS rproxy_rule_sets (
  node         VARCHAR(255) NOT NULL,   -- RPROXY_NODE_NAME (as in rproxy_rules)
  name         VARCHAR(253) NOT NULL,   -- the rule set's name
  generation   BIGINT UNSIGNED NOT NULL,
  etag         VARCHAR(64)  NOT NULL,
  owner        VARCHAR(255) NOT NULL,   -- the owning token's name
  rules        JSON         NOT NULL,   -- the set's rules, each in the shape of the body of POST /rules
  spec_version INT UNSIGNED NOT NULL DEFAULT 1,
  updated_by   VARCHAR(255) NOT NULL,
  updated_at   DATETIME(3)  NOT NULL,
  PRIMARY KEY (node, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
GRANT SELECT, INSERT, UPDATE, DELETE ON rproxy.rproxy_rule_sets TO 'rproxy'@'%';
GRANT SELECT ON rproxy.rproxy_rule_sets TO 'rproxy_ui'@'%';
```

### まだホストにないアドレスで待ち受ける（v0.4.3、`features.listen_freebind`）

VIP のように、今は別のホストが持っていて後からこのホストに来るアドレスで待ち受ける（Kubernetes の fleet で、VIP ごとに別の Gateway が同じポートを使う形。rproxy-gateway の docs/DESIGN-v0.4.x.md 7.）。

- ルールに `"listen_freebind": true`。ソケットを `IP_FREEBIND`（IPv6 は `IPV6_FREEBIND`）で開くので、アドレスがインタフェースになくても bind でき、ルールは `running` になる。アドレスが足されたら、そのアドレスに来たものから届く（ルールを作り直さない）。外されても待ち受けはそのまま。
- Linux だけ（ほかでは `features.listen_freebind` が false で、使うと `400 unsupported`）。権限は要らない（`IP_TRANSPARENT` と違い `CAP_NET_ADMIN` は要らない）。`net.ipv4.ip_nonlocal_bind=1` のホストでは付けなくても bind できる。
- 付けないルールは今までどおり：ホストにないアドレスは bind に失敗し、`failed`（`bind_failed`）。打ち間違えたアドレスを黙って受け付けないように、自動では付けない。
- UDP：特定のアドレスで待ち受けるので、返信はそのアドレスから出る（`IP_PKTINFO` は要らない）。HTTP/3（`http.http3`）の QUIC のソケットも同じく開く。
- PATCH では変えられない（ソケットを開き直すため。違う値は `unsupported`、同じ値か省けば受け付ける）。組の PUT と設定ファイルの再読み込みでは作り直し（`change: recreate`）。
- 同じポートの 2 つのルール：特定のアドレスどうし（`192.0.2.10:443` と `192.0.2.11:443`）は並べられる（キーが `listen_addr` を含む）。`0.0.0.0` / `::` のルールはそのポートをすべてのアドレスで取るので、同じポートの特定のアドレスのルールとは並べられない（どちらを先に作っても後のものが `409 already_exists`。`SO_REUSEADDR` で「より狭いアドレスが勝つ」形にはしない：どちらに届くかがアドレスの有無で変わり、取り合いが見えなくなるため）。誤りの文に重なる相手のルールと、組のルールならその組の名前が出る（`tcp/0.0.0.0:443 overlaps with tcp/192.0.2.10:443 (rule set k8s/a/web): a rule on 0.0.0.0 / :: takes the port on every address; ...`）。
- 実経路は `scripts/test-freebind.sh`（名前空間。CI の transparent のジョブ）で確かめる。

### 宛先への接続の時間（v0.4.3、`features.connect_timeout`）

L4 の `tcp` のルールの `connect_timeout`（上の表）。止まったノードの宛先は SYN に答えないので、断られる（RST）のと違い、接続は OS の再送（Linux で約 2 分）か、ほかに宛先があるときの 5 秒まで待つ。`connect_timeout` でこれを短くすると、そのあいだに来た接続も早く次の宛先に移り、宛先は `outlier_detection` で外れる（既定は 1 回で 10 秒）。

- 宛先が 1 つ・複数のどちらでも効く（複数のときは 5 秒の代わり）。`tls.routes` の宛先も同じ。
- 短すぎると、混んだ宛先・遠い宛先を落ちたとみなす。同じクラスタの中なら `1s`〜`3s` を目安に（SYN の最初の再送が 1 秒後）。
- `http` のルールは今までどおりサービスの `timeouts.connect`（既定 5 秒）。

## エンドポイント

| メソッドとパス | 本文 | 成功時 | 説明 |
|---|---|---|---|
| `GET /healthz` | | 200 `ok` | 認証不要 |
| `GET /capabilities` | | 200 | `{"version":"0.4.0","source_ip":[...],"transparent":true,"transparent_ipv6":true,"tls_modes":["passthrough","sni","terminate"],"dtls":true,"starttls":["smtp","imap","pop3"],"max_range_ports":20000,"features":{"http":true,"http3":true,"acme":true,"tls_options":true,"middlewares":["redirect_scheme","redirect_regex","ip_allow","headers","strip_prefix","add_prefix","replace_path","replace_path_regex","respond","rate_limit","in_flight","crowdsec","compress","buffering","retry","circuit_breaker","errors","basic_auth","forward_auth","oidc","geoip","cors","mirror","replace_host"],"services":["health_check","sticky","balance","outlier_detection","protocol","tls"],"http_options":["headers_add","redirect_status","route_timeouts","server_middlewares","server_status","retry_status","misdirected"],"server_middleware_kinds":["headers","replace_host","strip_prefix","add_prefix","replace_path","replace_path_regex","cors","redirect_scheme","redirect_regex","mirror","forward_auth"],"forward_auth":["service","grpc","client_request","allow_status","forward_body","all_response_headers"],"tls_route_targets":true,"client_auth_modes":["none","optional","required","optional_no_verify"],"rulesets":true,"labels":true,"conditions":true,"readyz":true,"limits":true,"bandwidth":true,"geoip":true,"outlier_detection":true,"dry_run":true,"persistence":true,"client_cert_auth":true,"token_expiry":true,"api_lockout":true,"handoff":true,"self_update":true,"performance":["workers","udp_shards","cpu_affinity","busy_poll_usecs","splice"],"graceful_shutdown":true,"cert_store":true,"ruleset_persistence":true},"build":{"version":"0.4.0","sha256":"…"}}`。`version` はこの rproxy-api のリリースの版（`Cargo.toml` の `version`。v0.3.18 から。それより古い版では含まれない。UI が組み合わせを確かめるのに使う）。`features` はこの版で動かせる v0.3・v0.4 の設定（上の「v0.3 の設定」「v0.4 の設定」。v0.4.0 ではすべて true、`performance` はすべての項目の名前）。`source_ip` の `transparent` は `IP_TRANSPARENT` が使えるときだけ含まれる。`transparent_ipv6` は IPv6 の待ち受けで transparent を使えるか（`IPV6_TRANSPARENT`）。`build` は動いているバイナリ `{"version","sha256"}`（v0.4、#174。`sha256` は起動の直後だけ `null`） |
| `GET /openapi.json` | | 200 | この API の OpenAPI 3.0 の定義（`docs/openapi.json` と同じ）。どのトークンでも読める |
| `GET /config` | | 200 | 設定ファイル（`RPROXY_CONFIG`）の状態（上の「設定ファイル」）。`global.crowdsec` があれば `crowdsec` に LAPI との接続の状態（v0.3.20）：`{"connected":true,"synced":true,"last_success":1790000000,"last_error":null,"last_error_at":null,"failures":0,"decisions":12}`。`connected` は最後の取得が成功したか、`synced` は一度でも取得できたか、`failures` は続けて失敗した回数、時刻は Unix 秒。`rules:read` |
| `POST /config/reload` | | 200 | 設定ファイルをその場で読み直して反映し、結果を返す：`{"added","removed","changed","unchanged","failed","restart_needed":[...],"files":[...],"rules","warnings":[{"rule","message"}]}`。誤りがあれば何も変えずに `400 {"code":"invalid","error","errors":[...],"warnings":[...]}`（`errors` は `--check-config` と同じ検証の結果）。設定ファイルがなければ `409 no_config`。`admin` のスコープが要る（トークンファイルを使っていなければ、ほかのエンドポイントと同じく誰でも使える）。既定では Unix ソケット（`RPROXY_API_SOCKET`）から来たリクエストだけを受け付け、TCP からは `403`（`RPROXY_API_RELOAD_UNIX_ONLY=false` で TCP も受け付ける）。ファイルの変化の検知・SIGHUP と同じ処理で、同時には動かない。`event=audit`（`action: config.reload`）に残る |
| `GET /interfaces` | | 200 | 待ち受けに使えるアドレス：`{"interfaces":[{"name":"ens18","addr":"172.16.5.1","family":"ipv4","loopback":false,"link_local":false}, ...],"reserved":[{"protocol":"tcp","addr":"127.0.0.1","port":8080,"purpose":"control API"}]}`。動作中のインターフェースだけを返す。`reserved` は rproxy 自身が使うアドレスで、ルールには使えない |
| `GET /rules` | | 200 | ルールの配列 |
| `GET /rules/{protocol}/{listen_addr}/{listen_port}` | | 200 | ルール 1 件 |
| `POST /rules` | ルール | 201 | 転送を開始する。名前解決と bind まで済ませてから応答する |
| `PATCH /rules/{protocol}/{listen_addr}/{listen_port}` | `{"remote_addr","remote_port"` または `"targets"`, `"balance"?,"health_check"?,"udp_idle_secs"?,"tls"?,"starttls"?,"starttls_required"?,"allow_from"?,"crowdsec"?,"extra_listen_addrs"?,"http"?}` | 200 | 転送先を変える。`extra_listen_addrs` を付けると追加の待ち受けアドレスを丸ごと置き換える（`[]` ですべて外す。省けば今のまま）：足したアドレスだけを開き、外したアドレスだけを閉じる（ほかのアドレスと、外したアドレスで開いている接続はそのまま）。`::` で待ち受けるルールで、追加のアドレスの有無（dual-stack と IPv6 だけ）が変わる変更は `unsupported`（作り直す）。転送先（`remote_addr` / `remote_port` か `targets`、`balance`、`health_check`）は毎回まとめて置き換える：省いた `balance` は `round_robin`、省いた `health_check` はなし。宛先 1 つに戻すときは `remote_addr` / `remote_port` を送る（`"targets": []` は付けてもよい）。`crowdsec` を付けると、判定での切断を有効・無効にする（次の接続から）。新しい接続から即時に反映する。`tls` を付けると TLS の設定を丸ごと置き換える（`starttls` も一緒に指定する。省略すると STARTTLS なし）。`http` を付けると L7 の設定を丸ごと置き換える（次のリクエストから。`http` のないルールに付けるのは `unsupported`。上の「v0.3 の設定」）。`source_ip` とポート範囲は変更できない：`source_ip`・`listen_port_end` を今と違う値で送ると `unsupported`（同じ値なら受け付ける。変えるときは作り直す） |
| `DELETE /rules/{protocol}/{listen_addr}/{listen_port}?drain_secs=N` | | 204 | 転送を停止する。既存の接続は即座に切断する。`drain_secs` を付けた場合は、その秒数だけ既存の接続の終了を待ってから切断する |
| `GET /acme` | | 200 | ACME の状態（docs/ACME.md）：`{"accounts":[{"name","directory","contact","eab","allowed_names","registered"}],"dns_providers":[{"name","type","zones","allowed_names"}],"resolvers":[{"name","account","challenge","dns_provider"}],"certificates":[{"resolver","domains","state","not_after","renew_at","next_attempt","error","ari"}],"rate_limit":{"orders","period_secs","used"},"helper"}`。秘密も秘密のファイルの場所も出さない。`rules:read`。`global.acme` がなければ `404` |
| `POST /acme/renew` | `{"resolver","domains"}` | 202 | その証明書を今すぐ更新する（`rate_limit` の内で。結果は `GET /acme`）。`acme:write`。`POST /config/reload` と同じく既定では Unix ソケットからだけ（`RPROXY_API_RELOAD_UNIX_ONLY`）。どのルールも使っていなければ `404`。`event=audit`（`action: acme.renew`） |
| `POST /acme/revoke` | `{"resolver","domains","reason"?}` | 200 | 取った証明書を CA で失効させ、すぐに新しい証明書を注文する。スコープと Unix ソケットは `POST /acme/renew` と同じ。`event=audit`（`action: acme.revoke`）。docs/ACME.md |
| `POST /acme/accounts/{name}/register` | | 200 | アカウントを CA に作る（鍵があればそのアカウントを探す）。スコープと Unix ソケットは `POST /acme/renew` と同じ |
| `POST /acme/accounts/{name}/deactivate` | | 200 | アカウントを CA で無効にし、鍵を `<key_file>.deactivated` に退ける（次の注文で新しいアカウントを作る）。スコープと Unix ソケットは `POST /acme/renew` と同じ |
| `GET /readyz` | | 200 / 503 | v0.4（#28）：認証不要の readiness。`200 {"ready":true}` / `503 {"ready":false,"reason":"starting"\|"draining"}`（上の「ルールの組・状態・readiness」） |
| `GET /rulesets` | | 200 | v0.4（#28）：ルールの組の一覧 `[{"name","generation","etag","rules","updated_at","updated_by"}]`。`rules:read` |
| `GET /rulesets/{name}` | | 200 | v0.4（#28）：`{"name","generation","etag","updated_at","updated_by","owner","rules":[...]}`（`ETag` ヘッダも）。名前の `/` はそのまま書ける。`rules:read` |
| `PUT /rulesets/{name}?dry_run=true` | `{"generation","rules":[<ルール>...]}` | 200 | v0.4（#28）：その組のルールを本文のとおりにする（作る・変える・消す）。`If-Match` が今の etag と違えば `412 precondition_failed`、古い `generation` は `409 stale_generation`、組に属さないルールと同じキーは `409 already_exists` / `static`。どれかのルールの形が不正なら何も変えない（`400`、`rules[i]: ...`）。応答 `{"name","generation","etag","dry_run","results":[{"rule","action","change","state","error"}]}`。`rules:write`、各ルールは `allow_listen_ports` の内。組のルールを個別に `PATCH` / `DELETE` すると `409 owned`。詳しくは上の「ルールの組・状態・readiness」 |
| `DELETE /rulesets/{name}?drain_secs=N` | | 204 | v0.4（#28）：その組のルールをすべて同時に止めて組を消す（`If-Match` も使える）。`rules:write` |
| `POST /config/plan` | 設定ファイルの形の JSON | 200 | v0.4（#169）：本文の設定を今動いているものと比べて差分を返す（何も変えない。`--check-config --diff` が使う）。`admin`、既定では Unix ソケットからだけ |
| `POST /admin/upgrade` | | 202 | v0.4（#174）：ディスクの上の今のバイナリに引き継ぐ（SIGUSR2 と同じ。docs/UPGRADE.md）。`{"status":"started"}` を返し、引き継ぎは後ろで進む（結果はログの `handoff.*` と `/metrics` の `rproxy_handoffs_total`）。すでに動いていれば `409 upgrading`。`admin`、既定では Unix ソケットからだけ |
| `GET /admin/update` | | 200 | v0.4（#174）：自動更新の状態 `{"mode","current":{"version","sha256"},"available":{"version","sha256"}\|null,"last_check","error","bad_versions"}`。`admin` |
| `POST /admin/update` | | 202 | v0.4（#174）：今すぐ新しいパッチを確かめ（`{"status":"checking"}`。結果は `GET /admin/update`）、`RPROXY_UPDATE=auto` なら入れ替える。`RPROXY_UPDATE=off` なら `400 unsupported`。`admin`、既定では Unix ソケットからだけ |
| `GET /certs` | | 200 | v0.4.2（#240）：保存した証明書（`certs:read`、`allow_certs` の内だけ）。上の「証明書の API」 |
| `GET` / `PUT` / `DELETE /certs/{name}` | `{"cert","key","chain"?}` | 200 / 201 / 204 | v0.4.2（#240）：1 件を読む（`certs:read`）・保存する・消す（`certs:write`。`PUT` は TLS か loopback か Unix ソケットから）。上の「証明書の API」 |
| `GET /metrics` | | 200 | Prometheus 形式。ルールの数は `rproxy_rules{state}`（`running` / `failed`）、ルールごと（ラベル `protocol`・`listen`）に `rproxy_rule_up`（動いていれば 1）・`rproxy_connections`（開いている TCP の接続・UDP のセッション）・`rproxy_connections_total`・`rproxy_bytes_total{direction}`（`rx` はクライアントから転送先、`tx` はその逆）・`rproxy_tls_failures_total`（TLS / DTLS のハンドシェイクと STARTTLS のやり取りの失敗）・`rproxy_udp_dropped_total`（UDP のルールだけ）。`http` のルールのリクエストは `rproxy_http_requests_total`・`rproxy_http_request_duration_seconds`・`rproxy_http_limited_total`、転送先のヘルスチェックは `rproxy_http_server_up`・`rproxy_http_service_down`（上の「v0.3 の設定」）、宛先の全滅は `rproxy_rule_all_targets_down`、CrowdSec の LAPI は `rproxy_crowdsec_connected`、間引いたログの行は `rproxy_log_suppressed_total`、制御 API のトークンの期限は `rproxy_token_expiry_timestamp_seconds`、一時停止は `rproxy_api_lockouts_total`・`rproxy_api_locked_sources`（上の「制御 API の守り」）、ルールのラベルは `rproxy_rule_labels`（上の「ルールの組・状態・readiness」）、L4 の制限・帯域は `rproxy_rule_limited_total`・`rproxy_rule_bandwidth_dropped_total`、プロセスの開始時刻は `rproxy_process_start_time_seconds`（上の「v0.4 の設定」）。動いているバイナリは `rproxy_build_info{version,sha256}`、引き継ぎは `rproxy_handoffs_total{outcome}`（#174。`rproxy_process_start_time_seconds` は引き継ぎでも変わらない） |

IPv6 の `listen_addr` をパスに入れるときは URL エンコードする。

## エラー

失敗時は次の形で返す。

```json
{"error": "address already in use (os error 98)", "code": "bind_failed"}
```

| `code` | HTTP | 意味 |
|---|---|---|
| `unauthorized` | 401 | トークンがない、一致しない、期限切れ、またはトークンに結びついたクライアント証明書がない |
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
| `owned` | 409 | v0.4：ルールが組（`ruleset`）に属するので個別には変えられない |
| `precondition_failed` | 412 | v0.4：`If-Match` の etag が今の組と違う |
| `stale_generation` | 409 | v0.4：組の `generation` が今より古い |
| `locked_out` | 429 | v0.4：認証の失敗が続いたので、この送信元を一時的に止めている（`Retry-After`） |
| `upgrading` | 503 / 409 | v0.4（#174）：再起動なしの更新の途中なので変更を受け付けない（503。少し待って送り直す）／すでに更新が動いている（`POST /admin/upgrade` の 409） |
| `shutting_down` | 503 | v0.4.1：SIGTERM の後の終わり方（`RPROXY_SHUTDOWN_DELAY` / `_DRAIN`）の途中なので変更を受け付けない（ほかの rproxy に送る） |
| `tls_required` | 403 | v0.4.2：鍵を含む `PUT /certs` を平文の TCP（loopback 以外）で送った |
| `in_use` | 409 | v0.4.2：保存した証明書をルールが使っている（`used_by`） |
| `cert_store_unavailable` | 503 | v0.4.2：証明書の保存先に書けない |
| `internal` | 500 | その他 |

## API・設定ファイル・UI（DB）の関係

rproxy のルールには 4 つの出どころがある。どれも `GET /rules` に出る。

| 出どころ | `origin` | 正はどこか | 変え方 |
|---|---|---|---|
| 設定ファイル（`RPROXY_CONFIG`） | `static` | ファイル | ファイルを書き換える（自動で反映）。API からは `409 static` |
| UI（TCP-UDP-rproxy-ui） | `dynamic` | UI の DB（`forward_rules`） | UI から。UI は DB に書いてから rproxy の API を呼ぶ。rproxy は起動時に DB から復元する |
| API を直接呼ぶ（CI・スクリプト） | `dynamic` | rproxy のメモリだけ | API から。DB には書かれないので、rproxy を再起動すると消える |
| `persist: true` のトークンで API を呼ぶ（v0.4、#144） | `api` | rproxy のテーブル `rproxy_rules` | API から。rproxy が作成・変更・削除のたびに `rproxy_rules` に書き、起動時に復元する（上の「API で作ったルールの保存」） |
| ルールの組（Kubernetes のコントローラ、v0.4） | `dynamic`（`ruleset` つき） | コントローラ（rproxy はメモリだけ） | `PUT /rulesets/{name}`。個別の `PATCH` / `DELETE` は `409 owned`。再起動したらコントローラが PUT し直す |
| `persist: true` のトークンのルールの組（v0.4.2、#241） | `dynamic`（`ruleset` つき） | rproxy の `rproxy_rule_sets`（組ごとに 1 行） | `PUT` / `DELETE /rulesets/{name}`。起動時に `rproxy_rules` の後に戻す |

- 長く残すルールは、設定ファイルか UI（DB）、または `persist: true` のトークン（v0.4）で作る。保存しないトークンで API を直接呼んで作ったルールは一時的なもの（CI のプレビュー環境など）として扱う。
- UI は DB にないルールを編集しない。API で作ったルールは UI の一覧に出ず、DB にあるが rproxy にないルールは UI で「未登録」（missing）になる。
- API を直接使うときは、スコープと `allow_listen_ports` で UI のルールと範囲を分けたトークンを使う（「基本」の認証）。

## 起動時の復元

`--database-url mysql://user:pass@host:port/db` を指定すると、起動時に `forward_rules` テーブルの全ルールを読み込んで開始する。DB ユーザーには `SELECT` 権限だけを与えればよい。失敗したルールは `failed` として登録し、残りのルールは開始する。名前解決に失敗して `failed` になったルールは、再解決に成功した時点で自動的に開始する。

v0.4（#144）からは、続けて rproxy のテーブル `rproxy_rules` の自分の `node` の行も復元する（`origin: "api"`。同じキーは `forward_rules` の行が先。上の「API で作ったルールの保存」）。このテーブルには `SELECT`・`INSERT`・`UPDATE`・`DELETE` が要る。
`forward_rules` のノードでの振り分けは UI 側でする（`target` 列、UI PR #103。ノードごとの DB のビューがその rproxy の行だけを見せる）ので、rproxy は `forward_rules` を絞り込まない。`rproxy_rules` は rproxy が自分の `node` の行だけを読む。

テーブル定義は UI リポジトリの `db/` で管理する。rproxy が読む列は `protocol`、`src_addr`、`src_port`、`src_port_end`、`dist_addr`、`dist_port`、`source_ip`、`udp_idle_secs`、`options`。`options.targets`（複数の宛先）があれば `dist_addr` / `dist_port` は使わない。`options.enabled` が `false` の行（UI で一時停止したルール）は起動時に作らない（ログ `restore.paused` に数）。
`options` は JSON で `{"tls": <TLS>, "starttls": "smtp" | "imap" | "pop3" | null, "starttls_required": bool, "allow_from": [<CIDR>, ...], "http": <L7>, "crowdsec": bool}`（`allow_from`・`http`・`crowdsec` は省略できる）。古いテーブルにこれらの列がなければ、既定値で読み込む。v0.4 の `labels`・`limits`・`bandwidth`・`geoip`・`outlier_detection` も API と同じ形で読む（省略できる。上の「v0.4 の設定」）。
