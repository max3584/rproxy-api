# 送信元 IP の引き渡し（`source_ip`）

rproxy が転送先（バックエンド）に接続すると、転送先からは相手が **rproxy の IP** に見えます。
そのままでは、転送先のログ・アクセス制限・スパム対策などに本当のクライアントの IP が届きません。
`source_ip` は、クライアントの IP を転送先へ伝えるかどうか、どう伝えるかをルールごとに選ぶ設定です。

| 値 | 何をするか | 転送先の設定 | 向いている場面 |
|---|---|---|---|
| `proxy`（既定） | 何も伝えない。転送先からはすべて rproxy からの接続に見える | 不要 | クライアントの IP が要らないとき。L7（`http`）のルール（IP は `X-Forwarded-For` で渡る） |
| `proxy_v2` | 接続の先頭に、クライアントの IP を書いた短いヘッダ（PROXY protocol v2、バイナリ）を付けて送る | **必要**（PROXY protocol を受ける設定） | メール・DB・Kubernetes の ingress など、転送先が PROXY protocol に対応しているとき（推奨） |
| `proxy_v1` | 同じヘッダを文字列（PROXY protocol v1）で送る。TCP だけ | **必要** | v2 に対応していない古い転送先 |
| `transparent` | rproxy がクライアントの IP を名乗って接続する | 不要（代わりに経路の設定が必要） | PROXY protocol に対応していない転送先で、どうしてもクライアントの IP が要るとき（[TRANSPARENT.md](TRANSPARENT.md)） |

名前の `proxy` は「rproxy 自身の IP で接続する」という意味です（IP を渡すという意味ではありません）。

## PROXY protocol とは

HTTP なら `X-Forwarded-For` ヘッダでクライアントの IP を伝えられますが、メール（SMTP・IMAP）・DB・ゲームなどの TCP / UDP には、そういうヘッダを付ける場所がありません。
そこで、**接続の最初に「本当のクライアントは 203.0.113.9:51234 です」という 1 行（または短いバイナリ）を付けてから、本来のデータを流す**、という取り決めが PROXY protocol です。HAProxy が考えたもので、多くのソフトが対応しています。

```
v1 の例（文字列。この 1 行のあとに、本来のデータが続く）
PROXY TCP4 203.0.113.9 198.51.100.10 51234 443\r\n
```

- v2 はバイナリで、UDP にも使え、TLS の情報（SNI・ALPN・クライアント証明書の CN など）も一緒に渡せます。新しく設定するなら v2 を選びます。
- UDP では、rproxy はデータグラムごとにヘッダを付けます（dnsdist・PowerDNS・Unbound と同じ方式）。応答にはヘッダは付きません。

### 気をつけること

- **両側の設定を揃える。** 転送先が PROXY protocol を受ける設定になっていないのにヘッダを付けると、転送先はそれを不正なデータとみなし、接続が壊れます（「protocol error」「bad request」など）。逆に、転送先が PROXY protocol を必須にしているのにヘッダを付けないと、転送先は接続を受け付けません。
- **転送先では、ヘッダを信じる相手を rproxy だけに絞る。** 誰からでもヘッダを受け付けると、クライアントが自分でヘッダを書いて IP を偽れます。多くのソフトに「信頼するプロキシの IP」の設定があります（下の例）。
- **設定の名前は、どのソフトでも「proxy protocol」。** 転送先の設定を探すときは、この言葉で探します。

## 転送先の設定の例

どれも「rproxy（例 10.0.0.1）からの接続だけ PROXY protocol を受ける」形です。

| 転送先 | 設定 |
|---|---|
| Postfix（SMTP 25 番） | `postscreen_upstream_proxy_protocol = haproxy`（postscreen を使う場合）、または `smtpd_upstream_proxy_protocol = haproxy`（submission など） |
| Dovecot（IMAP / POP3） | `haproxy_trusted_networks = 10.0.0.1` と、リスナーごとに `haproxy = yes` |
| nginx | `listen 443 ssl proxy_protocol;` と `set_real_ip_from 10.0.0.1; real_ip_header proxy_protocol;` |
| Kubernetes の ingress-nginx | ConfigMap に `use-proxy-protocol: "true"` |
| Traefik | エントリポイントに `proxyProtocol.trustedIPs: ["10.0.0.1"]` |
| HAProxy | `bind :443 accept-proxy` |
| MediaMTX（RTSP） | `rtspTrustedProxies: [10.0.0.1]`（[PROFILES.md](PROFILES.md)） |
| dnsdist / PowerDNS Recursor / Unbound | それぞれの proxy protocol の設定（UDP も可） |

用途ごとのおすすめの組み合わせは [PROFILES.md](PROFILES.md) にあります。

## どれを選ぶか

1. クライアントの IP が要らない → `proxy`（既定のまま）。
2. 要る。転送先が PROXY protocol に対応している → `proxy_v2`（古い転送先で v1 しか使えなければ `proxy_v1`）。
3. 要る。でも転送先が PROXY protocol に対応していない → `transparent`（rproxy のホストと転送先の経路の設定が要る。[TRANSPARENT.md](TRANSPARENT.md)）。

## ほかの設定との関係

- **L7（`http`）のルール：** `proxy`（または `transparent`）だけが使えます。クライアントの IP は `X-Forwarded-For` / `X-Real-IP` で渡ります（前段の CDN などを信じるには `global.trusted_proxies`）。同じルールの passthrough の route（`tls.routes[].passthrough`）にも PROXY protocol は付きません。
- **TLS を rproxy で終端するルール（`terminate`）：** `proxy_v2` なら、TLS の情報（SNI・ALPN・TLS のバージョン・クライアント証明書の CN）も TLV で渡ります。
- **`source_ip` は作成後に変えられません**（作り直す）。転送先の設定と同時に切り替える必要があるためです。
- 設定の書き方・制約は [API.md](API.md) のルールの項目 `source_ip`。
