English: [GUIDE.md](en/GUIDE.md)

# 設定と運用の手引き

rproxy-api をはじめて使う人のための、やりたいこと別の手引きです。設定ファイル（`RPROXY_CONFIG`、YAML）の書き方と、制御 API の使い方を、例を見ながら順に進めます。後半は、更新・バックアップ・監視などの日々の運用です。

- 項目の意味と細かい動きは [API.md](API.md) が正です。この手引きは、長い話は API.md の節へのリンクにしています。
- 例はそのまま貼り付けて使える形にしています。アドレス・名前・パスは自分の環境に合わせて書き換えてください。
- 例のアドレスは文書用のもの（`192.0.2.0/24`・`198.51.100.0/24`・`203.0.113.0/24`・`2001:db8::/32`）と私用のもの（`10.0.0.0/8` など）です。

## 目次

設定

1. [インストールと起動](#1-インストールと起動)
2. [はじめてのルール](#2-はじめてのルール)
3. [L4 の転送（UDP・ポート範囲・複数の宛先）](#3-l4-の転送udpポート範囲複数の宛先)
4. [TLS](#4-tls)
5. [L7（`http` のルール）](#5-l7http-のルール)
6. [送信元 IP](#6-送信元-ip)
7. [守り（トークン・CrowdSec・GeoIP・ファイル）](#7-守りトークンcrowdsecgeoipファイル)
8. [`global` の設定](#8-global-の設定)
9. [動かしたまま変える](#9-動かしたまま変える)
10. [保存・ルールの組・dry run](#10-保存ルールの組dry-run)
11. [見る（ログ・`/metrics`・統計）](#11-見るログmetrics統計)

運用

12. [更新と戻し方](#12-更新と戻し方)
13. [バックアップと復旧](#13-バックアップと復旧)
14. [監視とアラート](#14-監視とアラート)
15. [ログの扱い](#15-ログの扱い)
16. [容量の上限](#16-容量の上限)
17. [レシピ](#17-レシピ)
18. [困ったとき](#18-困ったとき)

## 1. インストールと起動

### apt（Debian / Ubuntu）

```shell
sudo curl -fsSLo /usr/share/keyrings/rproxy-archive-keyring.gpg https://max3584.github.io/rproxy-api/rproxy-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/rproxy-archive-keyring.gpg] https://max3584.github.io/rproxy-api stable main" \
  | sudo tee /etc/apt/sources.list.d/rproxy-api.list
sudo apt update && sudo apt install rproxy-api
```

入れただけでは起動しません。`/etc/rproxy/rproxy.env` を書き換えてから起動します。

```shell
sudoedit /etc/rproxy/rproxy.env
sudo systemctl enable --now rproxy-api
```

### install.sh（systemd の Linux。VM 向け）

Debian / Ubuntu では apt から、ほかではリリースのバイナリを入れ、ユーザー・設定・ユニットを作って起動します。

```shell
curl -fsSL https://raw.githubusercontent.com/max3584/rproxy-api/master/scripts/install.sh | sudo bash -s -- --api-addr 127.0.0.1
```

もう一度実行するとアップグレードです（設定とトークンは残ります）。オプションは `install.sh --help`。

### 主な環境変数

設定は環境変数（`/etc/rproxy/rproxy.env`）で渡します。よく使うものだけを挙げます。すべての項目は [README の「起動」](../README.md#起動) の表にあります。

| 環境変数 | 既定 | 何を決めるか |
|---|---|---|
| `RPROXY_API_ADDR` / `RPROXY_API_PORT` | `127.0.0.1` / `8080` | 制御 API の待ち受け。loopback 以外ならトークンと TLS が必須 |
| `RPROXY_API_SOCKET` | なし | 制御 API の Unix ソケット（例 `/run/rproxy/api.sock`）。`POST /config/reload` などの強い操作は既定でここからだけ |
| `RPROXY_TOKEN_FILE` | なし（パッケージは `/etc/rproxy/tokens`） | 制御 API のトークン。指定すると認証が必須 |
| `RPROXY_CONFIG` | なし | 設定ファイル（YAML / JSON）かそのディレクトリ。ここのルールは固定ルール |
| `RPROXY_DATABASE_URL` | なし | UI のルールと、API で保存したルールを戻す MariaDB |
| `RPROXY_LOG_FILE` / `RPROXY_LOG_LEVEL` | 標準出力 / `info` | ログ（JSON Lines、日ごとに分ける） |
| `RPROXY_NODE_NAME` | ホスト名 | DB でのノードの名前。ノードごとに違う名前にする |

### 動いているか確かめる

```shell
systemctl status rproxy-api
TOKEN=$(sudo head -1 /etc/rproxy/tokens)     # パッケージが作った 1 行のトークン（すべての権限）。/etc/rproxy は root:rproxy 750
curl -s http://127.0.0.1:8080/healthz          # ok（認証なし）
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/capabilities | jq '{version, features: (.features | keys | length)}'
```

起動しないときは `journalctl -u rproxy-api` を見ます。設定の誤り（値・パス・ファイルの中身）では起動しません。権限・使用中のポート・DB など環境の問題では、使えない部分だけ止めて起動を続け、ログに `"event":"degraded"` と `part` を出します（[README の「起動できないものがあるとき」](../README.md#起動できないものがあるとき)）。

### 制御 API の Unix ソケットを開く

`POST /config/reload`・`PATCH /config/global`（一部の項目）・`POST /admin/*`・ACME の強い操作は、既定では Unix ソケットからだけ受け付けます。パッケージの既定ではソケットは開いていないので、使うときは開きます。

```shell
sudoedit /etc/rproxy/rproxy.env
#   RPROXY_API_SOCKET=/run/rproxy/api.sock      ← コメントを外す
#   RPROXY_API_SOCKET_GROUP=rproxy              ← コメントを外す
sudo systemctl restart rproxy-api
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" http://localhost/capabilities | jq .version
```

ソケットは `rproxy-api` のもので、モードは 660 です。上のように `sudo` で使うか、使う人をグループ `rproxy` に入れます（`sudo usermod -aG rproxy $USER` の後に入り直す）。トークンは Unix ソケットでも要り、強い操作には `admin` のスコープが要ります（パッケージが作った 1 行のトークンは `admin`）。この手引きのソケットの例は、どれもこの準備のうえで `$TOKEN` を使います。

## 2. はじめてのルール

例として、`0.0.0.0:8888` に来た TCP を `192.168.1.2:8080` へ流します。

### 設定ファイルで書く

```yaml
# /etc/rproxy/rproxy.yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8888
    remote_addr: 192.168.1.2
    remote_port: 8080
```

`/etc/rproxy/rproxy.env` に `RPROXY_CONFIG=/etc/rproxy/rproxy.yaml` を書きます（`RPROXY_CONFIG` を足したときだけ restart が要ります）。

```shell
sudo -u rproxy-api rproxy-api --check-config /etc/rproxy/rproxy.yaml   # 0 なら問題なし、1 なら誤り
sudo systemctl restart rproxy-api
```

`--check-config` は起動・読み直しと同じ検証をして、待ち受けも DB も開きません。書き換えるたびにまず通してください（nginx の `nginx -t` にあたります）。2 回目からは restart は要りません：ファイルの変化を `RPROXY_CONFIG_CHECK_SECS`（既定 10 秒）ごとに見て、差分だけを反映します。すぐに反映したいときは `systemctl reload rproxy-api`（先に `--check-config` を通し、誤りがあれば何も送りません）。

確かめ方：

```shell
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules \
  | jq '.[] | {protocol, listen_addr, listen_port, origin, state, error}'
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/config | jq '{files, rules, last_reload, error}'
```

`state` が `running` なら動いています。`failed` なら `error` と `conditions` に理由があります。

- YAML は 1.2 として読みます。`yes`・`on` は文字列です。`010` のような数は数になるので、文字列にしたいときは引用符で囲みます。
- ディレクトリを指定すると、中の `*.yaml` / `*.yml` / `*.json` を名前の順にまとめて読みます。`global` を書けるのは 1 つのファイルだけです（[API.md の「設定ファイル」](API.md#設定ファイル固定ルール)）。

### 制御 API で作る

同じルールを API で作ります。本文は設定ファイルの `rules` の 1 つと同じ形です。

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":8889,"remote_addr":"192.168.1.2","remote_port":8080}'

# 転送先を変える（新しい接続から）
curl -s -H "Authorization: Bearer $TOKEN" -X PATCH http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889 \
  -d '{"remote_addr":"192.168.1.3","remote_port":8080}'

# 消す（今の接続も切る。?drain_secs=30 で 30 秒まで終わりを待つ）
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889
```

ルールのキーは `(protocol, listen_addr, listen_port)` です。IPv6 のアドレスをパスに入れるときは URL エンコードします（`::` は `%3A%3A`）。

### 設定ファイルと API の違い

| | 設定ファイル | API |
|---|---|---|
| 表示の `origin` | `static` | `dynamic`（トークンの `persist: true` なら `api`） |
| 変え方 | ファイルを書き換える（自動で反映） | `PATCH` / `DELETE`。固定ルールは `409 static` |
| 再起動の後 | ファイルから作り直す | `dynamic` は消える。UI のルールは DB から、`api` は `rproxy_rules` から戻す |
| 向いているもの | 消えては困るもの（UI を公開するルールなど） | UI・CI・コントローラが変えるもの |

- 同じキーはどちらか一方です。ファイルにあるキーを `POST /rules` で作ると `409 already_exists`、ファイルのルールを `PATCH` / `DELETE` すると `409 static`、API にあるキーをファイルに書くと、ファイルのルールが `rule.failed` になります。
- 固定ルールの待ち受けに API から http のルートや `tls.routes` の名前を **足す** ときは、重ねる分（overlay、v0.4.23、#397）を使います。ファイルのルールそのものは変わりません。

  ```shell
  curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H 'If-None-Match: *' \
    http://127.0.0.1:8080/rules/tcp/0.0.0.0/443/overlay \
    -d '{"http":{"routes":[{"name":"wiki","match":"Host(`wiki.example.com`)","service":"wiki"}],
         "services":{"wiki":{"servers":[{"url":"http://10.0.0.5:8080"}]}}}}'
  ```

  重ねる分のルートは、ファイルのルートに当たらないリクエストだけを見ます。名前がファイルと重なると `409 overlay_conflict` です（[API.md の「固定ルールの待ち受けに重ねる分」](API.md#固定ルールの待ち受けに重ねる分v0423397featuresstatic_overlay)）。

## 3. L4 の転送（UDP・ポート範囲・複数の宛先）

ここからの例は、設定ファイルの `rules:` の下に足すものです。API なら同じ形を JSON にして `POST /rules` に送ります。

### UDP

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 53
    remote_addr: 10.0.0.53
    remote_port: 53
    udp_idle_secs: 30        # 黙っているセッションを捨てるまでの秒数（既定 30）
```

- `0.0.0.0` / `::` で待ち受けても、返事はクライアントが送った宛先のアドレスから返します。
- 転送先の返事とクライアントの 2 つ目のデータグラムがそろうまでのセッションは、5 秒で終わります（送信元の偽装への備え。[API.md の「UDP の送信元の偽装への備え」](API.md#udp-の送信元の偽装への備えv0420354)）。1 つ送った後は受けるだけのクライアントは、何か送り続けるようにします。
- 1 つのルールのセッションの既定の上限は `RPROXY_UDP_MAX_SESSIONS`（16384）です。多くのクライアントを受けるなら、ルールの `limits.max_connections` か、この値を上げます。

### ポート範囲

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 10000
    listen_port_end: 10100     # 10000〜10100 を
    remote_addr: 10.0.0.40
    remote_port: 20000         # 20000〜20100 へ、同じ数だけずらして送る
```

1 つのルールのポートは `RPROXY_MAX_RANGE_PORTS`（既定 20000）まで。ポートごとにソケットを 1 つ使います（16 章）。

### 待ち受けのアドレスを複数にする

```yaml
  - protocol: tcp
    listen_addr: 203.0.113.5
    extra_listen_addrs: ['2001:db8::5']   # IPv4 と IPv6 を 1 つのルールで
    listen_port: 443
    remote_addr: 10.0.0.20
    remote_port: 443
```

最大 16 件です。キーは `listen_addr` のままで、統計は 1 つにまとまります。

### 宛先を複数にする（振り分けと切り替え）

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 5432
    targets:
      - {addr: 10.0.0.11, port: 5432, weight: 2, max_connections: 200}
      - {addr: 10.0.0.12, port: 5432, max_connections: 200}
      - {addr: db-backup.internal, port: 5432, backup: true}
    balance: least_conn        # round_robin（既定）/ least_conn / failover
    health_check: {interval: 10s, timeout: 3s}
    connect_timeout: 3s
```

- `failover` は上から順に、生きている最初の宛先だけを使います。`backup: true` はほかがすべて down のときだけ使います。
- `health_check` は TCP の接続で確かめます（UDP のルールでは `port` が必須）。なくても、つながらない宛先は 10 秒外します（`outlier_detection` で変えられる）。
- `max_connections`（宛先ごと、v0.4.19）：いっぱいの宛先は飛ばし、すべていっぱいなら断ります（`conn.limited` の `reason: target_full`）。
- `connect_timeout`：省くと、ほかに宛先があれば 5 秒、なければ 30 秒です。`tcp` のルールだけ。

確かめ方：`GET /rules/tcp/0.0.0.0/5432` の `stats.targets`（宛先ごとの `up`・`connections`）、`/metrics` の `rproxy_target_up`。

### ルール全体の接続の上限

```yaml
    limits:
      max_connections: 2000          # ルール全体（UDP はセッション）
      per_source:
        max_connections: 50          # 1 つの送信元（既定は IPv4 /32・IPv6 /64 ごと）
        new_connections: {average: 10, period: 1s, burst: 20}
```

断ったものは `stats.limited`・`/metrics` の `rproxy_rule_limited_total{reason}`・ログの `conn.limited` です（[API.md の「L4 の制限と帯域」](API.md#l4-の制限と帯域165166の動き)）。帯域は `bandwidth`（`upload`・`download`、例 `"10Mbps"`）で絞れます。

### 長く黙る接続

`tcp` のルールは、どちらの向きにも何も流れない接続を `idle_timeout`（既定 `1h`）で切ります。DB のプールなど長く黙る接続は延ばします（`0s` で上限なし）。

```yaml
    idle_timeout: 8h
    half_close_timeout: 1m           # 片側が閉じた後（既定 1m）
```

## 4. TLS

ルールの `tls.mode` で中身の扱いを選びます。用途別の例は [PROFILES.md](PROFILES.md) にもあります。

| `tls.mode` | 動き | 証明書 |
|---|---|---|
| `passthrough`（既定） | 暗号のまま流す | 転送先 |
| `sni` | ClientHello の名前で転送先を選ぶ（復号しない。tcp は TLS、udp は DTLS・QUIC） | 転送先 |
| `terminate` | rproxy が TLS（tcp）/ DTLS（udp）を終端する | rproxy |

### 名前で振り分ける（`sni`）

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 10.0.0.10           # どの名前にも当たらないとき
    remote_port: 443
    tls:
      mode: sni
      routes:
        - {server_name: git.example.com, remote_addr: 10.0.0.11, remote_port: 443}
        - {server_names: ['*.apps.example.com', 'apps.example.com'], remote_addr: 10.0.0.12, remote_port: 8443}
      unmatched: reject              # 当たらない名前・SNI なしは切る
```

名前は完全一致・`*.`（1 階層）・`**.`（何階層でも）です。名前での振り分けはアクセス制限になりません（クライアントは名前を自由に名乗れます）。制限は `allow_from` や mTLS と組み合わせます。

### 終端する（`terminate`）

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8443
    remote_addr: 10.0.0.30
    remote_port: 8080                # 転送先へは平文
    allow_from: [10.0.0.0/8]         # 範囲の外は TLS より前に切る
    tls:
      mode: terminate
      certificates:
        - cert_file: /etc/rproxy/tls/site.pem
          chain_file: /etc/rproxy/tls/intermediates.pem
          key_file: /etc/rproxy/tls/site.key
      options: {min_version: '1.2'}
```

- 証明書・鍵は `rproxy-api` のユーザーのもので、鍵は 600 か 640 にします（[PERMISSIONS.md](PERMISSIONS.md)）。certbot などで root のファイルができるなら、deploy hook で写します。
- ファイルが変わると `RPROXY_CERT_CHECK_SECS`（既定 60 秒）のうちに読み直します。接続は切りません。
- 期限の近い証明書は `cert.expiring` のログと `/metrics` の `rproxy_cert_expiry_seconds` で分かります。

### 転送先へも TLS（再暗号化・mTLS）

```yaml
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/site.pem, key_file: /etc/rproxy/tls/site.key}
      upstream:
        tls: true
        server_name: backend.internal
        ca_file: /etc/rproxy/tls/internal-ca.pem
        cert_file: /etc/rproxy/tls/client.pem        # 転送先へのクライアント証明書（mTLS）
        key_file: /etc/rproxy/tls/client.key
```

クライアントに証明書を求めるときは `client_auth`：`{mode: required, ca_file: /etc/rproxy/tls/clients-ca.pem}`。

### DTLS

`protocol: udp` で `mode: terminate` にすると DTLS を終端します。鍵は PKCS#8（`-----BEGIN PRIVATE KEY-----`）に限ります。WebRTC のメディアは終端できないので passthrough で流します。

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 5684
    remote_addr: 10.0.0.60
    remote_port: 5683
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/coap.pem, key_file: /etc/rproxy/tls/coap.key}
```

### STARTTLS（メール）

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 587
    remote_addr: 10.0.0.20
    remote_port: 587
    source_ip: proxy_v2              # 転送先に送信元 IP と TLS の情報を渡す
    starttls: smtp                   # smtp / imap / pop3
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/mail.pem, key_file: /etc/rproxy/tls/mail.key}
```

25 番の MTA 間では、TLS を使わない相手もいるので `starttls_required: false` にします。

### 自動の証明書（ACME）

`global.acme` にアカウントと resolver を書き、ルールの証明書を `{acme: <resolver>, domains: [...]}` にします。

```yaml
version: 1
global:
  acme:
    accounts:
      letsencrypt:
        contact: ['mailto:admin@example.com']
        allowed_names: [example.com, '*.example.com']    # 必須：取ってよい名前
    resolvers:
      le-alpn: {account: letsencrypt, challenge: tls-alpn-01}
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 10.0.0.30
    remote_port: 8080
    tls:
      mode: terminate
      certificates:
        - acme: le-alpn
          domains: [example.com, www.example.com]
```

- 取れるまでは自己署名の仮の証明書を返します。ルールの表示の `acme` の `state` が `valid` になれば取れています。状態は `GET /acme`。
- `tls-alpn-01` は 443 番の `terminate`、`http-01` は 80 番の `http` のルール（か `http01_listen`）が答えます。ワイルドカードは `dns-01` だけです。
- 試すときは Let's Encrypt の staging（`directory: https://acme-staging-v02.api.letsencrypt.org/directory`）を使うと、回数の制限に当たりません。
- API で ACME の証明書を使うルールを作るには `acme:write` のスコープが要ります。DNS-01 のプロバイダ・補助プロセス・稼働中の変更は [ACME.md](ACME.md)。

## 5. L7（`http` のルール）

`http` を付けた `tcp` のルールは、HTTP を解釈してルートで振り分けます。TLS は `terminate`（HTTPS）か、なし（平文の HTTP）です。`remote_addr` / `remote_port` は書きません（転送先は `http.services`）。

### ルート・サービス・ミドルウェア

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/site.pem, key_file: /etc/rproxy/tls/site.key}
    http:
      http3: true                    # 同じポートの UDP でも HTTP/3 を受ける
      pre_routing: [secure-headers]  # ルートを選ぶ前にすべてのリクエストへ
      routes:
        - name: app
          match: Host(`app.example.com`)
          service: app
          middlewares: [compress, cache]
        - name: admin
          match: Host(`app.example.com`) && PathPrefix(`/admin`)
          service: app
          middlewares: [office-only, login]
        - name: api
          match: Host(`api.example.com`)
          service: api
          middlewares: [per-ip]
      default: {status: 404}
      services:
        app:
          servers:
            - {url: 'http://10.0.0.10:3000'}
            - {url: 'http://10.0.0.11:3000'}
          health_check: {path: /healthz, interval: 10s}
          timeouts: {connect: 5s, response: 60s}
        api:
          servers:
            - {url: 'http://10.0.0.12:8080', max_connections: 500}
      middlewares:
        secure-headers:
          headers:
            hsts: {max_age: 31536000, include_subdomains: true}
            frame_deny: true
            content_type_nosniff: true
        compress: {compress: {}}
        cache: {cache: {ttl: 60s}}
        office-only: {ip_allow: {source_range: [10.0.0.0/8, '2001:db8:10::/48']}}
        login: {basic_auth: {users_file: /etc/rproxy/auth/htpasswd, realm: admin}}
        per-ip: {rate_limit: {average: 50, period: 1s, burst: 100}}
```

- ルートは `priority` の大きい順（省くと `match` の文字数）に試します。上の例では長い `admin` が `app` より先です。どれにも当たらなければ `default`。
- `match` は Traefik と同じ式です：`Host`・`HostRegexp`・`Path`・`PathPrefix`・`PathRegexp`・`Method`・`Header`・`Query`・`ClientIP` などを `&&`・`||`・`!` で組み合わせます。
- ミドルウェアは書いた順にリクエストへ、逆の順に応答へ働きます。
- サービスを作らずに 1 つの URL へ送るなら、ルートに `to: 'http://10.0.0.10:3000'` と書けます。
- パスと Host は照合の前に正規化します（`/%61dmin` や `/x/../admin` で `PathPrefix(`/admin`)` を素通りできません）。

### よく使うミドルウェア

```yaml
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
        old-docs: {redirect_regex: {regex: '^https://old\.example\.com/(.*)', replacement: 'https://docs.example.com/$1'}}
        sso:
          forward_auth:
            address: 'http://127.0.0.1:9091/api/verify'
            response_headers: [Remote-User, Remote-Groups]
        no-index: {headers: {response: {set: {X-Robots-Tag: noindex}}}}
        api-cache: {cache: {ttl: 30s, stale_on_error: 5m, vary: [Accept-Language]}}
        maintenance: {respond: {status: 503, body: 'maintenance'}}
```

| 種類 | 何をするか |
|---|---|
| `basic_auth` | htpasswd（`htpasswd -B` の bcrypt を勧める）の利用者だけを通す。`user_header` で名前を転送先へ |
| `forward_auth` | 認証サーバ（Authelia・oauth2-proxy など）に問い合わせ、2xx なら通す |
| `oidc` | OpenID Connect のサインイン（Keycloak など。oauth2-proxy なしで） |
| `headers` | 要求・応答のヘッダの `set`・`add`・`remove`、`hsts`・`frame_deny`・`csp` など |
| `redirect_scheme` / `redirect_regex` | HTTPS へ・別の URL へリダイレクトする |
| `rate_limit` / `in_flight` | 送信元ごとの速さ・同時の数。超えたら 429 |
| `cache` | GET の応答をメモリに `ttl` のあいだ持つ。認証のミドルウェアの後ろには `share_after_auth` が要る |
| `compress` | br・zstd・gzip で圧縮する |
| `ip_allow` | 送信元の範囲の外は 403 |

ほかの種類（`crowdsec`・`geoip`・`cors`・`mirror`・`retry`・`circuit_breaker`・`errors`・パスの書き換えなど）と細かい動きは [API.md の「HTTP の転送の扱い」](API.md#http-の転送の扱い) と「Gateway API 向けの L7・TLS」にあります。

### 80 番から HTTPS へ

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - {name: to-https, match: 'PathPrefix(`/`)', middlewares: [to-https]}
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
```

ACME の `http-01` の答えはルートより先に返すので、このルールと一緒に使えます。

### HTTP/3

`http.http3: true` で、同じアドレス・ポートの UDP でも HTTP/3 を受けます（`terminate` のときだけ）。ファイアウォールで UDP のポートも開けます。受けられないときは TCP だけで動き、`GET /rules` の `stats.http.http3` に理由が出ます。

### 時間の上限（`global.http.timeouts`）

`http` のルールのクライアントの接続の上限は、ルールではなく `global` に書きます（下は今の設定ファイルの `global` に足す分）。新しい接続から効きます。

```yaml
global:
  http:
    timeouts:
      idle: 5m                 # 処理中のリクエストのない接続（既定 180s）
      request_body_idle: 2m    # 本文を送らずに黙っている時間（既定 60s）
      upgraded_idle: 4h        # WebSocket などで何も流れない時間（既定 1h）
```

項目と既定は [API.md の「HTTP の転送の扱い」の `global.http.timeouts`](API.md#http-の転送の扱い)。転送先の時間はサービスの `timeouts`（`connect`・`response`）です。

## 6. 送信元 IP

転送先からは、ふつう rproxy の IP に見えます。クライアントの IP を渡すには、ルールの `source_ip` を選びます。選び方と転送先の設定は [SOURCE-IP.md](SOURCE-IP.md) にあります。

| `source_ip` | 動き | 転送先の準備 |
|---|---|---|
| `proxy`（既定） | 渡さない | なし |
| `proxy_v2` / `proxy_v1` | 接続の先頭（UDP は v2 だけ、データグラムごと）に PROXY protocol のヘッダを付ける | PROXY protocol を受ける設定 |
| `transparent` | クライアントの IP を名乗って接続する | 戻りの経路（[TRANSPARENT.md](TRANSPARENT.md)） |

- `http` のルールでは、IP は `X-Forwarded-For`・`X-Real-IP` で渡ります（`source_ip` は `proxy` か `transparent`）。
- `source_ip` は作った後に変えられません（作り直します）。

### 前段の PROXY protocol を受け取る

rproxy の前にロードバランサがいて PROXY protocol を付けてくるときは、ルールの `proxy_protocol` で読みます。

```yaml
    proxy_protocol:
      from: [10.2.0.0/16]          # ヘッダを信じる前段だけ（必須、/0 は不可）
      required: true               # from からの接続にヘッダがなければ断る（既定）
```

以後の `allow_from`・`limits`・ログ・`source_ip` はヘッダのクライアントで動きます。前段のアドレスはログの `proxy_peer` です。

### `X-Forwarded-For` を信じる前段

`http` のルールの前に CDN やロードバランサがあるときは、`global.trusted_proxies` にその範囲を書きます（下は今の設定ファイルの `global` に足す分）。そこからの接続の `X-Forwarded-For` を信じて、`ClientIP`・`ip_allow`・`rate_limit`・ログに本当のクライアントを使います。

```yaml
global:
  trusted_proxies: [10.2.0.0/16]
```

## 7. 守り（トークン・CrowdSec・GeoIP・ファイル）

### トークン

トークンファイル（`RPROXY_TOKEN_FILE`）は 2 通りの書き方があります。1 行に 1 つ書いたトークンは、すべての権限（`admin`）です。YAML で書くと、名前・SHA-256・スコープを分けられ、トークンそのものはファイルに置きません。

```shell
TOKEN=$(openssl rand -hex 32)
printf %s "$TOKEN" | sha256sum      # この値を sha256 に書く
```

```yaml
# /etc/rproxy/tokens（root:rproxy 640）
tokens:
  - name: ui
    sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    scopes: [admin]                     # UI のトークンは admin にする（v0.4.23）
  - name: ci-deploy
    sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    scopes: [rules:read, rules:write]
    allow_listen_ports: 20000-29999     # 作る・変える・消すことができる待ち受けポート
    max_rules: 200
    expires: 2027-03-31
  - name: k8s-controller
    sha256: fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
    scopes: [rules:read, rules:write]
    allow_rulesets: [k8s/]              # PUT / DELETE できる組の名前の先頭
  - name: monitoring
    sha256: baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096
    scopes: [metrics:read]
```

- スコープ：`rules:read`・`rules:write`・`metrics:read`・`acme:write`・`certs:read`・`certs:write`・`admin`。足りないと `403 forbidden`。
- **持ち主だけが直す・消す**（v0.4.23、#401）：`admin` でないトークンは、自分で作ったルール・重ねる分・組だけを直す・消すことができます。ほかは `403 not_owner`。持ち主はトークンの **名前** です（`sha256` を入れ替えても名前が同じなら持ち主は変わりません）。
- `allow_restored: true`：作ったトークンの分からないルール（DB から戻した UI のルールなど）も直せます。UI のトークンを `admin` にしない構成で、UI のトークンにだけ付けます。v0.4.23 からの項目です（この文書を書いた時点では未リリース）。v0.4.22 以前で書くと、トークンファイル全体が読まれず、すべてのトークンが通らなくなります（トークンの項目は知らない名前を誤りにする）。戻すときも先に外してください。
- 変えたら `systemctl reload rproxy-api`。SIGHUP がなくても `RPROXY_TOKENS_CHECK_SECS`（既定 10 秒）のうちに読み直します。入れ替えは「新しいものを足す → クライアントを切り替える → 古いものを消す」の順です。
- 認証に 1 分で 20 回失敗した送信元は 5 分止まります（`429 locked_out`。Unix ソケットは対象外）。
- 制御 API を loopback の外で開くなら、トークンと TLS（`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`）が必須です。同じホストの UI は Unix ソケットでつなぐのが安全です。クライアント証明書（mTLS）の使い方は [API.md の「制御 API の守り」](API.md#制御-api-の守りv04167)。

### CrowdSec

LAPI の判定（ban）に入った IP を止めます。L7 は `crowdsec` ミドルウェア、L4 はルールの `crowdsec: true` です。

```shell
sudo cscli bouncers add rproxy -o raw | sudo tee /etc/rproxy/crowdsec.key >/dev/null
sudo chown rproxy-api:rproxy /etc/rproxy/crowdsec.key && sudo chmod 640 /etc/rproxy/crowdsec.key
```

```yaml
version: 1
global:
  crowdsec:
    lapi_url: 'http://127.0.0.1:8081'     # 制御 API と同じポートにしない
    api_key_file: /etc/rproxy/crowdsec.key
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 25
    remote_addr: 10.0.0.30
    remote_port: 25
    crowdsec: true                        # ban された IP は TLS より前に切る
```

`GET /config` の `crowdsec`（`connected`・`decisions`）で LAPI とつながっているか分かります。rproxy のログを CrowdSec に読ませて攻撃を見つける向きは [CROWDSEC.md](CROWDSEC.md)。

### GeoIP

国・ASN で通すものを決めます。`global.geoip` に GeoLite2 などの mmdb を書きます。

```yaml
version: 1
global:
  geoip:
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 22
    remote_addr: 10.0.0.70
    remote_port: 22
    geoip: {allow_countries: [JP], unknown: deny}
```

判定の順は `allow_from` → `geoip` → `crowdsec` です（[API.md の「GeoIP」](API.md#geoip168)）。

### ルールが指すファイル

- 証明書・鍵・秘密のファイルは `rproxy-api` のユーザーのもので、グループ・ほかの人が書けないものだけ使います（`global.files.owner_check: strict`、既定）。Kubernetes の Secret のボリュームは `global.files.trusted_dirs` に書きます。
- API のルールは、証明書のストア・ACME の保存先・rproxy の秘密（トークンファイルなど）・`/proc` などを指せません（`403 protected_file`）。
- `admin` でないトークンは、ほかの持ち主のルールが使う鍵・秘密のファイルを指せません（`409 file_in_use`）。
- 理由は API の答えに出さず、ログの `config.file` に出します（[PERMISSIONS.md](PERMISSIONS.md)）。

## 8. `global` の設定

`global` はプロセス全体の設定です。設定ファイルの `global` に書くか、ファイルに書いていない項目なら `PATCH /config/global`（`admin`）で変えられます。**ファイル（と環境変数）に書いた項目はファイルが勝ちます**（API では `409 static`）。

| 項目 | 変え方 | 出どころ |
|---|---|---|
| `trusted_proxies`・`access_log`・`crowdsec`・`geoip`・`acme` | 動いたまま（Unix ソケットからだけ） | ファイル / API |
| `http.timeouts` | 動いたまま（新しい接続から） | ファイル / API |
| `udp_max_sessions`・`cache_max_memory` | 動いたまま | 環境変数 / API |
| `performance`・`files` | 再起動が要る | ファイル / 環境変数 |

```shell
SOCK=/run/rproxy/api.sock                    # 1 章の「制御 API の Unix ソケットを開く」
sudo curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" http://localhost/config/global | jq '.items | map_values({value, source, apply})'

sudo curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" -X PATCH 'http://localhost/config/global?dry_run=true' \
  -d '{"http":{"timeouts":{"idle":"5m"}},"udp_max_sessions":32768}'
# よければ ?dry_run=true を外して送る。null を送るとその項目の API の値を消す
```

- 書いた項目は丸ごと置き換えます（`http.timeouts` の中も丸ごと）。
- DB があれば `rproxy_global` に保存し、再起動の後も戻します。DB がなければプロセスの中だけです。
- 起動のときだけ読む項目を設定ファイルで変えると、`GET /config` の `restart_needed` に出ます（[API.md の「global の設定の API」](API.md#global-の設定の-apiv0419342featuresglobal_api)）。

## 9. 動かしたまま変える

### 設定ファイルを読み直す

ファイルを書き換えると、10 秒ごとの確認で差分だけを反映します。結果をその場で受け取るには `POST /config/reload`（`admin`、既定は Unix ソケットからだけ）を使います。

```shell
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" -X POST 'http://localhost/config/reload?dry_run=true' | jq
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" -X POST http://localhost/config/reload
# {"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0,"restart_needed":[],...}
```

誤りがあれば何も変えずに `400` と理由を返し、それまでの設定で動き続けます。`--check-config --diff` でも、動いている rproxy との差分を見られます。

### 接続を切らない変更（`in_place`）と切る変更（`recreate`）

| 変えるもの | 効き方 |
|---|---|
| 宛先（`remote_*`・`targets`・`balance`・`health_check`）、`tls`、`starttls`、`allow_from`、`http`、`extra_listen_addrs`、時間、`limits`・`bandwidth`・`geoip`・`labels` など | `in_place`：今の接続はそのまま。TCP は新しい接続から、UDP は今のセッションも移る（`extra_listen_addrs` から外したアドレスの UDP のセッションは終わる） |
| `listen_port_end`（ポート範囲）、`source_ip`、`listen_freebind`、`http` の有無、`::` で待ち受けるルールの追加のアドレスの有無（dual-stack と IPv6 だけの切り替え） | `recreate`：待ち受けを作り直す。今の接続は切れる。API の `PATCH` では `400 unsupported`（作り直す） |

どちらになるかは `?dry_run=true` の答えの `change` で前もって分かります。

### 止めるときに待つ（drain）

- ルールを消すとき：`DELETE /rules/...?drain_secs=30`（3600 秒まで）。
- プロセスを止めるとき：`RPROXY_SHUTDOWN_DELAY`（`/readyz` を 503 にして待つ）と `RPROXY_SHUTDOWN_DRAIN`（今の接続の終わりを待つ）。前にロードバランサがあるときの値は [README の「SIGTERM での終わり方」](../README.md#sigterm-での終わり方v041)。

### バイナリを入れ替える（再起動なし）

同じマイナー（X.Y）の中のパッチは、TCP・HTTP の接続を切らずに入れ替えられます。

```shell
sudo systemctl kill -s USR2 --kill-whom=main rproxy-api    # ディスクの上のバイナリに引き継ぐ
journalctl -u rproxy-api | grep -E '"handoff\.(done|failed|refused)"'
```

UDP のセッションは新しいプロセスで作り直します。`systemctl restart` は今の接続を切るので、更新には引き継ぎを使います（12 章、[UPGRADE.md](UPGRADE.md)）。

## 10. 保存・ルールの組・dry run

### API で作ったルールを残す

保存しないトークンで作ったルール（`origin: dynamic`）は、rproxy のメモリにしかなく、再起動で消えます。残す方法は 3 つです。

1. 設定ファイルに書く。
2. UI で作る（UI の DB に入り、起動のときに戻す）。
3. トークンに `persist: true` を付けて API で作る（`origin: api`。`RPROXY_DATABASE_URL` の `rproxy_rules` に書く）。

```yaml
tokens:
  - name: ci-deploy
    sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    scopes: [rules:read, rules:write]
    persist: true
```

答えの `persisted: true` は DB で確定したことです。DB に届かなければルールは動かしたまま `persisted: false` で、定期の照合が書き直します。テーブルの定義は [API.md の「API で作ったルールの保存」](API.md#api-で作ったルールの保存144)。UI のトークンには付けません（UI が自分の DB に書くので二重になります）。

### ルールの組（自動化向け）

コントローラや CI は、組のルールの全体を毎回まとめて `PUT` します。rproxy が今との差を当てます。

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PUT http://127.0.0.1:8080/rulesets/ci/preview-42 -d '{
  "generation": 1,
  "rules": [
    {"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":20042,"remote_addr":"10.0.5.42","remote_port":8080}
  ]}' | jq '.results'
```

- どれかのルールが通らなければ何も変えません。`generation` が前より小さいと `409 stale_generation`。`If-Match` に `etag` を付けると、ほかの人の変更を上書きしません。
- 組のルールを個別に `PATCH` / `DELETE` すると `409 owned` です。
- 組はメモリだけにあります（`persist: true` のトークンなら `rproxy_rule_sets` に保存）。再起動の後は `GET /readyz` が 200 になってから PUT し直します（[API.md の「ルールの組・状態・readiness」](API.md#ルールの組状態readinesskubernetes-のコントローラ向け28)）。

### dry run

`POST` / `PATCH` / `DELETE /rules`・`PUT /rulesets/{name}`・`POST /config/reload`・`PATCH /config/global`・重ねる分の `PUT` / `DELETE` は `?dry_run=true` を受けます。同じ検証をして、何も変えずに差分を返します。

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PATCH 'http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889?dry_run=true' \
  -d '{"remote_addr":"10.0.0.13","remote_port":8080}' | jq '{action, change, diff}'
```

`PATCH` は宛先（`remote_addr` / `remote_port` か `targets`、`balance`、`health_check`）を毎回まとめて置き換えます。省いた `balance` は `round_robin`、省いた `health_check` はなしになるので、`targets` のあるルールではそれらも一緒に送ります（`diff` で確かめられます）。

## 11. 見る（ログ・`/metrics`・統計）

### ログ

1 行 1 イベントの JSON です。`event` で種類を分けます（一覧は [README の「ログ」](../README.md#ログ)）。

```shell
# ファイルに出しているとき（パッケージの既定）
tail -F /var/log/rproxy/rproxy.$(date -u +%F).log      # ファイルの日付は UTC | jq -c 'select(.event == "degraded" or .event == "rule.failed" or .event == "audit")'
# journald に出しているとき
journalctl -u rproxy-api -o cat | jq -c 'select(.event == "conn.denied" or .event == "degraded")'
```

まず見るもの：`degraded`（環境の問題で一部を止めた）、`rule.failed`、`config.error`、`audit`（API の変更）、`conn.denied`・`conn.limited`、`tls.error`、`target.down`、`cert.expiring`。

### `/metrics`

Prometheus の形式です。`metrics:read`（か `admin`）のトークンが要ります。

```shell
curl -s -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:8080/metrics | grep -E '^rproxy_(rules|rule_up|connections) '
```

### ルールの統計

`GET /rules/{protocol}/{addr}/{port}` の `stats`（`connections`・`rx_bytes`・`tx_bytes`・`denied`・`limited`・`targets`・`http` など）と `conditions` を見ます。数はメモリにだけあり、再起動で 0 から数え直します（引き継ぎでは減りません）。

## 12. 更新と戻し方

### apt

```shell
sudo apt update && sudo apt install rproxy-api
journalctl -u rproxy-api -n 50 | grep -E '"handoff\.|"start"'
```

パッケージは、前の版と major.minor が同じなら SIGUSR2 で引き継ぎ（接続を切らない）、違えば restart します。リリースノートに「再起動が要る」とあるパッチは restart です。

- v0.4.23 に上げると、`admin` でないトークンは自分で作ったルールしか直せなくなります（#401）。YAML のトークンファイルで UI のトークンを `rules:read`・`rules:write` にしていると、UI の「API のルール」の画面と複数のノードの同期が `403 not_owner` になります。上げる前に UI のトークンを `admin` にするか、`allow_restored: true` を足します（7 章）。

### 自動更新（コンテナ）

イメージの入口を `rproxy-api launch` にし、`RPROXY_UPDATE=auto`（知らせるだけなら `check`）を渡します。同じ X.Y の新しいパッチを、署名を確かめてから引き継ぎで入れ替えます。`RPROXY_UPDATE_HEALTHY`（既定 60 秒）より前に落ちた版は悪い版として戻します。apt の VM と Kubernetes では `off` のままにします（[UPGRADE.md の「自動更新」](UPGRADE.md#自動更新コンテナ)）。

```shell
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" http://localhost/admin/update | jq
```

### 手で引き継ぐ

バイナリを置き換えてから `systemctl kill -s USR2 --kill-whom=main rproxy-api`、または `POST /admin/upgrade`（`admin`、Unix ソケットから）。`handoff.done` が出れば終わりです。新しいプロセスが 30 秒のうちに準備できなければ、古いプロセスが動き続けます（`handoff.failed`）。

### 前の版に戻す

```shell
apt-cache policy rproxy-api                 # 入れられる版（リポジトリは過去の版も残している）
sudo apt install rproxy-api=0.4.22-1        # 版は <番号>-1 の形。同じマイナーなら、戻すときも引き継ぎで動く
```

戻す前に確かめること：

- **新しい版で足した設定を先に外す。** 古い版は知らない項目を誤りにします。たとえばトークンファイルの `allow_restored`（v0.4.23）を書いたまま v0.4.22 に戻すと、トークンファイル全体を読まず、すべてのトークンが通らなくなります。リリースノートの「追加」に、どの版から使えるかが書いてあります。
- 設定ファイルの新しい項目も同じです。戻す版のバイナリで `--check-config` を通してから戻します。
- `PATCH /config/global` の値（v0.4.19 から）は、それより前の版への引き継ぎでは渡りません（DB の行は残ります）。
- マイナーをまたいで戻すときは restart です（引き継げません）。
- v0.4.22 以前に戻すと、持ち主だけが直す・消す守り（#401、v0.4.23）がなくなります。`rules:write` のトークンはどれも、ほかのトークンのルールを直す・消すことができるようになります。

## 13. バックアップと復旧

取るものと戻す順番は [BACKUP.md](BACKUP.md) にあります。要点だけ挙げます。

| 取るもの | 場所 |
|---|---|
| 環境変数ファイル・トークン | `/etc/rproxy/rproxy.env`、`/etc/rproxy/tokens` |
| 設定ファイル（固定ルールはここにしかない） | `RPROXY_CONFIG` |
| 証明書・鍵・秘密のファイル | 設定とルールに書いたパス、`/var/lib/rproxy/certs/`（`PUT /certs`）、`/var/lib/rproxy/acme/`（ACME） |
| DB | `forward_rules`（UI のルール）、`rproxy_rules`・`rproxy_rule_sets`・`rproxy_global`・`rproxy_rule_overlays`（v0.4.23 から）（rproxy が書く） |

戻す順番：パッケージを入れる（起動しない）→ `/etc/rproxy` と鍵を戻す → DB を戻す → `--check-config` → rproxy-api を起動 → UI を起動 → 確かめる。保存しないトークンで API から作ったルールは DB にないので、残したければ `GET /rules` の控えを取っておきます。

## 14. 監視とアラート

### 集める

```yaml
# prometheus.yml
scrape_configs:
  - job_name: rproxy
    scheme: https                                       # loopback の外の制御 API は TLS が必須
    tls_config:
      ca_file: /etc/prometheus/rproxy-api-ca.pem        # 自己署名なら、その証明書か CA
    authorization:
      credentials_file: /etc/prometheus/rproxy.token     # metrics:read のトークン（平文）
    static_configs:
      - targets: ['10.0.0.2:8080']
```

制御 API を loopback の外で開くには、トークンファイルと TLS（`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`）が必須です（どれかがなければ起動しません）。`RPROXY_API_ADDR` に監視の網のアドレスを足します（例 `127.0.0.1,10.0.0.2`）。loopback だけのままにするなら、Prometheus を同じホストで動かし、`scheme: http`・`targets: ['127.0.0.1:8080']` にします（`tls_config` は要りません）。

### 見る値

| 見たいこと | 値 |
|---|---|
| 動いていないルール | `rproxy_rules{state="failed"}`、`rproxy_rule_up == 0` |
| 宛先の全滅 | `rproxy_rule_all_targets_down`、`rproxy_http_service_down`、`rproxy_target_up` |
| 制限で断った数 | `rproxy_rule_limited_total{reason}`（`max_connections`・`source_connections`・`new_connections`・`packets`・`target_full`・`fd_budget`）、`rproxy_http_limited_total` |
| ファイルの数の枠 | `rproxy_session_budget_in_use` / `rproxy_session_budget_limit` |
| 証明書の期限 | `rproxy_cert_expiry_seconds` |
| CrowdSec | `rproxy_crowdsec_connected` |
| 背景のタスクの落ち | `rproxy_task_restarts_total{part}` |
| ログの取りこぼし | `rproxy_log_dropped_total` |
| 引き継ぎ | `rproxy_handoffs_total{outcome}`、`rproxy_build_info` |

### アラートの例

```yaml
# rproxy-alerts.yml
groups:
  - name: rproxy
    rules:
      - alert: RproxyRuleFailed
        expr: rproxy_rules{state="failed"} > 0
        for: 5m
        annotations: {summary: '動いていないルールがある（GET /rules の state・error）'}
      - alert: RproxyAllTargetsDown
        expr: rproxy_rule_all_targets_down == 1 or rproxy_http_service_down == 1
        for: 2m
      - alert: RproxyLimited
        expr: sum by (protocol, listen, reason) (rate(rproxy_rule_limited_total{reason!="fd_budget"}[5m])) > 1
        for: 10m
        annotations: {summary: '{{ $labels.listen }} が {{ $labels.reason }} で断り続けている'}
      - alert: RproxyFdBudgetRefusing
        expr: sum(rate(rproxy_rule_limited_total{reason="fd_budget"}[5m])) > 0
        annotations: {summary: 'ファイルの数の枠が埋まり、接続・セッションを断っている（LimitNOFILE を上げる）'}
      - alert: RproxyFdBudgetHigh
        expr: rproxy_session_budget_limit > 0 and rproxy_session_budget_in_use / rproxy_session_budget_limit > 0.8
        for: 10m
      - alert: RproxyCertExpiring
        expr: rproxy_cert_expiry_seconds < 7 * 86400
      - alert: RproxyCrowdsecDisconnected
        expr: rproxy_crowdsec_connected == 0
        for: 5m
      - alert: RproxyTaskRestarted
        expr: increase(rproxy_task_restarts_total[15m]) > 0
        annotations: {summary: '背景のタスクが落ちて動き直した（ログの degraded の part）'}
      - alert: RproxyLogDropped
        expr: increase(rproxy_log_dropped_total[5m]) > 0
```

### `degraded` を見つける

`degraded`（環境の問題で一部を止めた）は `/metrics` の値がなく、ログだけに出ます。ログの仕組みで拾います。

```shell
journalctl -u rproxy-api --since -1h -o cat | jq -c 'select(.event == "degraded") | {timestamp, part, error}'
```

Loki なら `{unit="rproxy-api.service"} | json | event="degraded"` のような問い合わせでアラートにできます。

## 15. ログの扱い

- **置き場所**：パッケージの既定は `/var/log/rproxy/rproxy.<日付>.log`（`RPROXY_LOG_FILE`）。rproxy が日ごとに分け、`RPROXY_LOG_KEEP`（既定 14）を超えた古いものを消すので logrotate は要りません。`RPROXY_LOG_FILE` の行を消すと標準出力に出て、systemd では journald に入ります。
- **アクセスログ**：`http` のルールのリクエストは `http.access` です。`global.access_log: /var/log/rproxy/access.log` で別のファイルに分けられます。API で入れるときは `RPROXY_API_ACCESS_LOG_DIR` の下だけです（そのディレクトリは rproxy のアクセスログだけにします）。
- **量**：攻撃で同じ行があふれないよう、`conn.denied`・`conn.limited`・`tls.error` などは送信元ごとに間引きます（省いた数は次の行の `suppressed`）。クライアントが決める長い項目は 2,048 バイトで切ります。
- **秘密**：クエリの `token`・`code`・`password` などは `REDACTED` にします。ログにはクライアントの IP・SNI・証明書の CN が入るので、読める人を絞ります（`/var/log/rproxy` は 750）。
- **CrowdSec**：同梱のパーサーとシナリオで、CrowdSec に rproxy のログを読ませられます（[CROWDSEC.md](CROWDSEC.md)）。`acquis` のファイル名は glob（`/var/log/rproxy/*.log`）で書きます。

## 16. 容量の上限

ソケットはファイル記述子を使います。rproxy は起動のときにファイルの数の上限（`RLIMIT_NOFILE`）をハードの上限まで上げます。パッケージのユニットは `LimitNOFILE=65536` です。

| 上限 | 既定 | 何を数えるか |
|---|---|---|
| `LimitNOFILE`（ユニット） | `65536` | プロセスのファイル記述子のすべて |
| `RPROXY_MAX_LISTENERS` | `0`（自動：(上限 − 1024) の半分。65536 なら 32256） | 制御 API で開ける待ち受けのソケット（アドレス × ポート、`http3` は 2 倍） |
| 接続とセッションの枠 | 上限 − 1024 − `RPROXY_MAX_LISTENERS`（65536 なら 32256） | TCP の接続は 2 つ（受けたソケットと転送先）、`http` の接続は 1 つと転送先への接続ごとに 1 つ、UDP のセッションは 1 つ、splice のパイプは 2 つ |
| `RPROXY_MAX_RANGE_PORTS` | `20000` | 1 つのルールのポートの数 |
| `RPROXY_MAX_RULES` / `RPROXY_MAX_RULESETS` | `10000` / `1000` | API で作れるルール・組の数 |
| `RPROXY_UDP_MAX_SESSIONS` | `16384` | 1 つの UDP のルールのセッション（ルールの `limits.max_connections` があればそちら） |

- 枠が埋まると、新しい接続はすぐ閉じ、UDP のセッションは断るか確立していない古いものを終えます。`conn.limited` の `reason: fd_budget` と `rproxy_rule_limited_total{reason="fd_budget"}` で分かります。65536 では TCP の中継が同時に約 16000 本です。足りなければ `LimitNOFILE` を上げます：

  ```shell
  sudo systemctl edit rproxy-api
  # [Service]
  # LimitNOFILE=262144
  sudo systemctl restart rproxy-api
  ```

- 起動の `start` の行に `session_budget`・`max_listeners`・`fd_reserve` が出ます。今の使い方は `rproxy_session_budget_in_use`。
- 設定ファイル・DB から戻すルールは上限に数えますが、断りません（API の増やす変更だけ `409 limit`）。
- **転送先への接続の送信元ポート**（OS の決まり）：rproxy から転送先への TCP の接続と UDP のセッションは、1 つずつ rproxy のホストのエフェメラルポートを使います。Linux の既定（`net.ipv4.ip_local_port_range` の 32768〜60999）では、送信元のアドレスと 1 つの転送先（アドレス・ポート）の組で約 28000 本までです。1 つの転送先にそれより多くつなぐなら、範囲を広げるか、`targets` で転送先を分けます。`source_ip: transparent` ではクライアントのアドレスで出るので、この組は分かれます。

## 17. レシピ

どれも設定ファイルの例です。証明書のパス・アドレスを書き換え、`--check-config` を通してから使ってください。

### Web アプリを HTTPS で公開する（ACME）

```yaml
version: 1
global:
  acme:
    accounts:
      letsencrypt:
        contact: ['mailto:admin@example.com']
        allowed_names: [app.example.com]
    resolvers:
      le-http: {account: letsencrypt, challenge: http-01}
rules:
  - protocol: tcp                  # 80：ACME の http-01 に答え、ほかは HTTPS へ
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - {name: to-https, match: 'PathPrefix(`/`)', middlewares: [to-https]}
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
  - protocol: tcp                  # 443：終端して Web アプリへ
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - acme: le-http
          domains: [app.example.com]
    http:
      http3: true
      routes:
        - name: app
          match: Host(`app.example.com`)
          service: app
          middlewares: [secure, compress]
      services:
        app:
          servers: [{url: 'http://127.0.0.1:3000'}]
          health_check: {path: /, interval: 10s}
      middlewares:
        secure: {headers: {hsts: {max_age: 31536000}, content_type_nosniff: true}}
        compress: {compress: {}}
```

80・443 の TCP と 443 の UDP（HTTP/3）を開けます。証明書の状態は `GET /acme`。

### DB を TCP で中継する（長く黙る接続）

```yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 10.0.0.2
    listen_port: 5432
    targets:
      - {addr: 10.0.1.11, port: 5432}
      - {addr: 10.0.1.12, port: 5432}
    balance: failover              # 主に送り、落ちたら次へ
    health_check: {interval: 5s, timeout: 2s}
    connect_timeout: 3s
    idle_timeout: 12h              # プールの接続を 1h で切らない
    allow_from: [10.0.0.0/16]
    limits: {max_connections: 1000}
```

### UDP のゲームサーバ

```yaml
version: 1
rules:
  - protocol: udp
    listen_addr: 0.0.0.0
    extra_listen_addrs: ['::']
    listen_port: 27015
    remote_addr: 10.0.0.80
    remote_port: 27015
    udp_idle_secs: 120             # 黙るプレイヤーを 30 秒で切らない
    limits:
      max_connections: 4000        # このルールのセッション（既定の 16384 の代わり）
      per_source:
        max_connections: 4
        packets: {average: 200, period: 1s, burst: 400}
```

### 1 つの 443 を名前で分ける

```yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/example.pem, key_file: /etc/rproxy/tls/example.key}
      routes:
        - server_names: ['**.k8s.example.com']    # Kubernetes へそのまま（証明書は向こう）
          passthrough: true
          remote_addr: 10.2.255.131
          remote_port: 443
          source_ip: proxy_v2
    http:
      routes:
        - {name: wiki, match: Host(`wiki.example.com`), to: 'http://10.0.0.5:8080'}
        - {name: git, match: Host(`git.example.com`), to: 'http://10.0.0.6:3000'}
      default: {status: 404}
```

名前ごとに終端するもの（`wiki`・`git`）と、そのまま流すもの（`**.k8s.example.com`）を 1 つのポートで分けます。証明書をすべて転送先が持つなら `tls.mode: sni` の例（4 章）を使います。

## 18. 困ったとき

### API の誤り

答えは `{"error": "...", "code": "..."}` です。すべての `code` は [API.md の「エラー」](API.md#エラー)。

| `code`（HTTP） | 意味 | すること |
|---|---|---|
| `static`（409） | 設定ファイルのルールを `PATCH` / `DELETE` した・組の `PUT` で取ろうとした（`PATCH /config/global` ならファイル・環境変数の項目） | ファイルを書き換える。API から足すなら重ねる分 |
| `already_exists`（409） | 同じキーか、待ち受けの重なるルールがある（設定ファイルのキーへの `POST` も） | `GET /rules` で探す。アドレス・ポートを変える |
| `reserved`（409） | 制御 API（か `http01_listen`）のアドレスとポートに重なる | 別のポートにする。`GET /interfaces` の `reserved` |
| `bind_failed`（409） | ポートを開けない（ほかのプロセスが使用中、権限） | `ss -lntup` で使っているものを探す。1024 未満は `CAP_NET_BIND_SERVICE` |
| `not_owner`（403） | `admin` でないトークンが、ほかのトークンの作ったものを直す・消そうとした | 作ったトークンか `admin` で。UI のトークンは `admin`（か `allow_restored`） |
| `forbidden`（403） | スコープ・`allow_listen_ports` の外。Unix ソケットだけの操作を TCP から | トークンを見直す。強い操作は `RPROXY_API_SOCKET` から |
| `file_in_use`（409） | ほかの持ち主のルールが使う鍵・秘密のファイルを指した | 自分のファイルを用意する（または `admin`） |
| `protected_file`（403） | 証明書のストア・ACME の保存先・rproxy の秘密などを指した | 別の場所に置く |
| `file_not_allowed`（403） | `allow_certs` のトークンがファイルのパスを書いた | `{cert: <name>}`（保存した証明書）を使う |
| `tls_config` / `invalid`（400） | 形の誤り、ファイルが使えない | 形の誤りは答えに理由が出る。ファイルが使えない（所有者・モード・ない・中身）ときは理由を答えに出さず、ログの `config.file` に出す。`--check-config` で確かめる |
| `unsupported`（400） | この版・環境で使えない、`PATCH` で変えられない項目 | `GET /capabilities` の `features`。作り直す |
| `limit`（409） | `RPROXY_MAX_*` かトークンの `max_rules`・`max_rulesets` を超える | 使っていないものを消す・上限を上げる（16 章） |
| `owned`（409） | 組のルールを個別に変えようとした | 組を `PUT` する |
| `stale_generation`（409） / `precondition_failed`（412） | 古い `generation`、`If-Match` の外れ | 読み直してから送る |
| `resolve_failed`（502） | 転送先の名前を引けない | DNS を確かめる。直れば自動で動き出す |
| `locked_out`（429） | 認証の失敗が続いた送信元 | `Retry-After` まで待つ。トークンを直す |
| `upgrading` / `shutting_down`（503） | 引き継ぎ・終わり方の途中 | 少し待って送り直す |
| `no_config`（409） | 設定ファイルを使っていないのに `POST /config/reload` | `RPROXY_CONFIG` を設定する |
| `restart_only`（409） / `in_use`（409） | 再起動が要る `global` の項目 / ルールが使うものを消す | ファイルで変えて再起動 / 先にルールを直す |

### ルールが `failed`・動かない

- `GET /rules` の `error` と `conditions`（`BindFailed`・`ResolveFailed`・`CertificateUnreadable` など）を見る。
- ログの `rule.failed`・`config.error`・`config.file` を見る。
- 設定ファイルなら `--check-config`、反映の結果は `GET /config` の `error`。
- `persisted: false`：DB に届いていない。`degraded` の `part: db` を見る。

### 接続が断られる

| ログ | 理由 | すること |
|---|---|---|
| `conn.denied`（`allow_from`・`geoip`・`crowdsec`・`unmatched`） | アクセス制御で断った | 範囲・国・ban を確かめる。`unmatched` は `tls.routes` の名前 |
| `conn.denied`（`proxy_protocol*`） | PROXY protocol のヘッダがない・前段が `from` の外 | 前段のアドレスを `from` に書く |
| `conn.limited`（`max_connections` ほか） | ルールの `limits` | 上限を上げる |
| `conn.limited`（`target_full`） | 宛先がすべて `max_connections` | 宛先を足す・上限を上げる |
| `conn.limited`（`fd_budget`） | プロセスのファイルの数の枠が埋まった | `LimitNOFILE` を上げる（16 章） |
| `tls.error` | TLS のハンドシェイクの失敗 | 証明書・名前・`min_version`・クライアントの対応 |
| `target.down` | 宛先の生死の確認に落ちた | 転送先・`health_check` の `port` |
