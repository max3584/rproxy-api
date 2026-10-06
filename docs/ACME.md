English: [ACME.md](en/ACME.md)

# ACME で証明書を取る（#208）

rproxy は ACME（Let's Encrypt など）で証明書を取り、期限の前に自分で更新できます（v0.4.0 から）。ルールの `tls.certificates` に `cert_file` / `key_file` の代わりに `{acme: <resolver>, domains: [...]}` を書くだけで、取った証明書は今までの証明書ファイルと同じ仕組み（証明書のストア、#115）で読み込まれ、更新されると接続を切らずに差し替わります。certbot・cert-manager などで取ったファイルを指定するやり方も、今までどおり使えます。

| challenge | 使う場面 | rproxy の何が答えるか |
|---|---|---|
| `http-01` | rproxy が 80 番で待ち受けている名前 | 80 番の `http` のルール（ルートやミドルウェアより先に `/.well-known/acme-challenge/` に答える）か、`global.acme.http01_listen` の小さな応答役 |
| `tls-alpn-01` | rproxy が 443 番で TLS を終端している名前 | 443 番の `terminate` のルール（ALPN `acme-tls/1` だけを提示する ClientHello に、検証用の証明書で答える） |
| `dns-01` | ワイルドカード（`*.example.com`）、外から 80 / 443 に届かない名前 | DNS のプロバイダ（PowerDNS の HTTP API、汎用の REST）で `_acme-challenge` の TXT を書く |

DNS の書き換えの権限が要らない `http-01` / `tls-alpn-01` を先に使い、`dns-01` はワイルドカードや外から届かない名前だけにしてください。

## 設定

ACME の設定（アカウント・DNS のプロバイダ・resolver・許可する名前）は、設定ファイル（`RPROXY_CONFIG`）の `global.acme` にだけ書きます。API のルールは resolver を名前で指すだけで、秘密（DNS の API キーなど）を API から作る・読む・変えることはできません。`global` の変更は再起動で効きます（`GET /config` の `restart_needed`）。

```yaml
# /etc/rproxy/rproxy.yaml
version: 1
global:
  acme:
    storage: /var/lib/rproxy/acme            # アカウントの鍵・証明書（既定）。rproxy のユーザーが書ける場所
    accounts:
      letsencrypt:
        directory: https://acme-v02.api.letsencrypt.org/directory   # 既定。テストは …acme-staging-v02…
        contact: ['mailto:admin@example.com']
        allowed_names: [example.com, '*.example.com', '**.svc.example.com']   # 必須：このアカウントで取ってよい名前
        # key_file: /var/lib/rproxy/acme/accounts/letsencrypt.key  # 既定。なければ作る（0600）
        # eab: {kid: ..., hmac_key_file: /etc/rproxy/acme/eab.key} # 外部アカウントの紐付け（ZeroSSL など）
        # ca_file: /etc/rproxy/acme/private-ca.pem                # 私設の CA（step-ca など）の HTTPS 用
    dns_providers:
      pdns:
        type: powerdns
        api_url: http://127.0.0.1:8081            # /api/v1 より前
        server_id: localhost                      # 既定
        api_key_file: /etc/rproxy/acme/pdns.key   # X-API-Key（中身は 1 行）
        zones: [acme.example.net]                 # 書いてよいゾーン（省略時は PowerDNS のゾーンの一覧から選ぶ）
        allowed_names: ['*.example.com', example.com]   # 必須：このプロバイダで証明してよい名前
      relay:
        type: http                                # 汎用の REST（lego の httpreq と同じ考え方）
        add:    {method: POST, url: 'https://dns-relay.example.net/present', headers: {Authorization: 'Bearer {secret}'}, body: '{"fqdn":"{fqdn}","value":"{value}"}'}
        remove: {method: POST, url: 'https://dns-relay.example.net/cleanup', headers: {Authorization: 'Bearer {secret}'}, body: '{"fqdn":"{fqdn}","value":"{value}"}'}
        secret_file: /etc/rproxy/acme/relay.token
        allowed_names: [intranet.example.com]
    resolvers:                                    # ルールが名前で指すもの：アカウント + challenge
      le-http: {account: letsencrypt, challenge: http-01}
      le-alpn: {account: letsencrypt, challenge: tls-alpn-01}
      le-dns:  {account: letsencrypt, challenge: dns-01, dns_provider: pdns}
    rate_limit: {orders: 10, period: 1h}          # 既定。新しい発行と更新（失敗も）の回数の上限
    # renew_before: 30d                           # 既定は 30 日（寿命の 1/3 が短ければそちら）
    # dns_servers: ['10.0.0.53']                  # CNAME・ゾーン・TXT を調べる DNS（既定は /etc/resolv.conf）
    # dns_propagation_timeout: 2m                 # TXT が見えるまで待つ時間（過ぎたら CA に頼む）
    # http01_listen: ['0.0.0.0:80']               # 80 番に http のルールがないときの HTTP-01 の応答役
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - acme: le-alpn
          domains: [example.com, www.example.com]
        - acme: le-dns
          domains: ['*.example.com']
    http:
      routes:
        - {name: site, match: 'HostRegexp(`.+`)', to: 'http://127.0.0.1:3000'}
```

- `allowed_names`：`example.com`（その名前だけ）、`*.example.com`（1 階層下。ワイルドカード `*.example.com` そのものも含む）、`**.example.com`（何階層でも）。アカウントにも DNS のプロバイダにも必須で、`dns-01` では両方に含まれる名前だけを取れます。それ以外の名前を使うルールは、API では `400 invalid`、設定ファイルでは起動しない・反映しない誤りです。
- ワイルドカードは `dns-01` の resolver だけで取れます（`400 invalid`）。
- 汎用の REST のテンプレートでは `{fqdn}`（`_acme-challenge.…` の書き込み先。CNAME をたどった後。末尾の `.` なし）・`{value}`（TXT の値）・`{zone}`（ゾーン）・`{secret}`（`secret_file` の中身）を差し込めます。`{secret}` は URL には書けません（URL はログに出るため。ヘッダか本文に）。2xx 以外は失敗です。
- 秘密のファイル（`api_key_file`・`secret_file`・`hmac_key_file`）と `ca_file` がなければ起動しません（設定の誤り）。読めない（権限）ときは、使うときに失敗して再試行します。
- アカウントは最初の注文のときに CA に作ります（鍵は `key_file`、0600）。鍵が既にあれば、その鍵のアカウントを使います。ほかのツールで作ったアカウントの鍵（PKCS#8 の PEM、ECDSA P-256）も使えます。

## 動き

1. ルールが ACME の証明書を使い始めると（作成・変更・設定ファイル・DB からの復元）、まだ取っていない証明書は、すぐに注文します。取れるまでは自己署名の仮の証明書（`rproxy ACME placeholder`）を返します（ディスクには書きません）。ルールの表示の `acme` は `pending`。
2. challenge に答え、CA が確かめたら、鍵（`key.pem`）と証明書（`cert.pem`、中間 CA つき）を `<storage>/certs/<resolver>/<最初の名前>-<ハッシュ>/` に 0600 で書きます。証明書のストアがファイルの変化として読み直し、その証明書を使うルールだけを組み立て直します（接続は切りません）。
3. 期限の 30 日前（寿命の 1/3 のほうが短ければそちら。`renew_before` で変えられる）に更新します。失敗したら 1 分から倍々に、最大 6 時間の間をあけて再試行し、それまでの証明書を使い続けます（`acme` は `error`、`next_attempt` に次の時刻）。
4. 再起動しても、保存した証明書をすぐに使います（新しい注文はしません）。どのルールも使わなくなった証明書は更新しません（ファイルは残します）。
5. 発行の回数は `rate_limit`（既定 1 時間に 10 回、プロセス全体）までです。超えたら注文を後に回します（`acme.rate_limited`）。CA のレート制限（Let's Encrypt は名前ごと・アカウントごと）を使い切らないためです。

注文は 1 つずつ順に行います。期限の確認・警告（`cert.expiring` など、`RPROXY_CERT_WARN_DAYS`）・`/metrics` の `rproxy_cert_expiry_seconds` は、ほかの証明書ファイルと同じです。

### HTTP-01

- 80 番の `http` のルールは、`/.well-known/acme-challenge/<token>` のうち rproxy が今答えているトークンにだけ、ルート・ミドルウェア（HTTPS へのリダイレクト、`ip_allow`、認証など）より先に答えます。ほかのトークンはいつもどおりルートに渡ります（certbot など、ほかのツールへ振り分けるルートも共存できます）。
- 80 番に `http` のルールがないときは、`global.acme.http01_listen` に小さな応答役を置けます（challenge のほかは 404）。このアドレスはルールに使えません。80 番を L4 で転送している（passthrough）ときは答えられません。
- ルールの `allow_from` は先に効きます。CA の検証元（Let's Encrypt はいろいろな場所から来ます）を締め出さないようにしてください。

### TLS-ALPN-01

- `terminate` の tcp のルール（`http` のルールを含む）が、ALPN に `acme-tls/1` だけを載せた ClientHello で、今確かめている名前を求められたときに、検証用の証明書（acmeIdentifier の拡張つき、RFC 8737）で答えて閉じます。ほかのクライアントには影響しません。`tls.unmatched: reject` のルールでも答えます。
- 443 番が `sni` / `passthrough` のルールや、`passthrough` の route の名前では答えられません。UDP（DTLS）のルールでは ACME の証明書は使えません（`400 tls_config`）。

### DNS-01

1. `_acme-challenge.<名前>` の CNAME をたどって、書き込み先を決めます（最大 8 段）。**`_acme-challenge` を challenge 専用のゾーンに CNAME で委任する運用を勧めます**：DNS の API キーが漏れても、本番のゾーンは書き換えられません。
   ```
   ; 本番のゾーン（一度だけ手で書く）
   _acme-challenge.example.com.  CNAME  example.com.acme.example.net.
   ; プロバイダの zones: [acme.example.net]、API キーはこのゾーンだけに書けるものを
   ```
   委任できないときは、ゾーン単位・TXT だけに書ける狭い権限のキーを使ってください。
2. 書き込むゾーンは、プロバイダの `zones` のうち一番長く一致するもの（`zones` にない名前は失敗）。`zones` がなければ、PowerDNS はゾーンの一覧から、汎用の REST は DNS の SOA から決めます。
3. 書く前に `<storage>/dns-pending.json` に記録し、TXT を書き、`dns_servers` から見えるまで待って（最長 `dns_propagation_timeout`）、CA に検証を頼みます。
4. 検証が終わったら、成功しても失敗しても TXT を消します。消せなかったもの（と、途中でプロセスが止まったもの）は記録に残り、次の起動のときに消します（`acme.dns` の `reason: left over`）。
5. PowerDNS は `PATCH /api/v1/servers/{server_id}/zones/{zone}` で TXT の RRset を `REPLACE` / `DELETE` します（同じ名前の値は 1 回でまとめて。ワイルドカードとその親を一緒に取るときは 2 つの値）。

将来の候補：RFC 2136（TSIG の動的更新）、acme-dns、ACME と DNS の処理を秘密を持つ別のプロセスに分けること。

## API

| | スコープ | 説明 |
|---|---|---|
| `POST /rules`・`PATCH /rules/...` で ACME の証明書を使う | `rules:write` と `acme:write` | `acme:write` がなければ `403`。名前が許可の外なら `400 invalid` |
| `GET /acme` | `rules:read` | アカウント（`directory`・`contact`・`allowed_names`・`registered`）、DNS のプロバイダ（名前・`type`・`zones`・`allowed_names`）、resolver、証明書の状態、`rate_limit` の使った回数。秘密も、秘密のファイルの場所も出さない |
| `POST /acme/renew` `{"resolver", "domains"}` | `acme:write`、既定は Unix ソケットからだけ | 今すぐ更新する（`rate_limit` の内で）。`202` |
| `POST /acme/accounts/{name}/register` | 同上 | アカウントを CA に作る（鍵があればそのアカウントを探す） |
| `POST /acme/accounts/{name}/deactivate` | 同上 | アカウントを CA で無効にし、鍵を `<key_file>.deactivated` に退ける。次の注文で新しいアカウントを作る |

- 強い操作（`POST /acme/...`）は `POST /config/reload` と同じく、既定では Unix ソケット（`RPROXY_API_SOCKET`）からだけ受け付けます。TCP からも受けるには `RPROXY_API_RELOAD_UNIX_ONLY=false`（両方に効きます）。
- ルールの表示には `acme`（その証明書の `state`：`pending` / `valid` / `renewing` / `error`、`not_after`、`renew_at`、`next_attempt`、`error`）が加わります。
- 操作は `event: "audit"`（`action: acme.renew` / `acme.account.register` / `acme.account.deactivate`）に残ります。

## ログ

| `event` | 内容 |
|---|---|
| `acme.order` | 注文を始めた（`resolver`・`domains`・`renewal`） |
| `acme.issue` / `acme.renew` | 証明書を取った・更新した（`not_after`） |
| `acme.error` | 注文が失敗した（`error`・`retry_at`・`failures`） |
| `acme.rate_limited` | `rate_limit` で注文を後に回した（`retry_at`） |
| `acme.account` | アカウントを作った・見つけた・無効にした |
| `acme.challenge` / `acme.answer` | challenge を用意した・CA に答えた（debug / info） |
| `acme.dns` | TXT を書いた・消した（`action: add` / `remove`、`provider`・`fqdn`・`zone`・`reason`・`outcome`） |
| `acme.listening` | `http01_listen` で待ち受けを始めた |

秘密（API キー、トークン、EAB の鍵、アカウントの鍵）はログにも API の応答にも出しません。プロバイダの誤りの応答は 200 文字までに切り、秘密を伏せてから出します。

## 権限と保存場所

- `storage`（既定 `/var/lib/rproxy/acme`）は rproxy のユーザーが書ける必要があります。systemd のユニット（.deb・install.sh）は `StateDirectory=rproxy` で `/var/lib/rproxy` を rproxy のものにして書けるようにしています（`ProtectSystem=strict` でも）。その下は rproxy が作り、ディレクトリは 0700、ファイルは 0600 です。書けないときは起動を続け（`degraded`、`part: global.acme.storage`）、証明書を保存できない間は仮の証明書のままです。
- 80 / 443 番で待ち受けるには `CAP_NET_BIND_SERVICE`（ユニットは既定で持っています。docs/PERMISSIONS.md）。
- `--check-config` は `global.acme` と、ルールの名前が許可の内か、秘密のファイルがあるかも確かめます（何も書かず、CA にもつなぎません）。

## 試験

CI の `clippy + tests` のジョブが、Alpine の Pebble（ACME の試験用の CA）と PowerDNS を同じコンテナで動かし、tests/acme.rs で HTTP-01（`http01_listen`）・TLS-ALPN-01・DNS-01（PowerDNS、CNAME の委任、汎用の REST の小さな中継）で実際に証明書を取り、TXT が消えること、前の起動の TXT の後片付け、Unix ソケットからの更新、再起動の後に保存した証明書を使うこと、秘密が応答とログに出ないことを確かめます（docs/TESTING.md）。
