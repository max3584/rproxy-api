# transparent（クライアントの IP のまま転送先に接続する）

`source_ip: transparent` のルールでは、rproxy がクライアントのアドレスを送信元にして転送先へ接続する（`IP_TRANSPARENT` / `IPV6_TRANSPARENT`）。
転送先のログやアクセス制御には、rproxy ではなくクライアントのアドレスが見える。TCP と UDP、IPv4 と IPv6 に対応する。

転送先が PROXY protocol に対応していれば、`source_ip: proxy_v2` のほうが簡単（経路を変えずに、ヘッダでクライアントのアドレスを渡せる）。
transparent は、PROXY protocol に対応していない転送先で、送信元のアドレスが要るときに使う。

## 必要なもの

| どこで | 何を | 方法 |
|---|---|---|
| rproxy | `CAP_NET_ADMIN` | apt・install.sh で入れたユニットが与える（docs/PERMISSIONS.md）。`GET /capabilities` の `transparent` / `transparent_ipv6` で確かめる |
| rproxy | 転送先からの戻りのパケットを、自分宛てとして受け取る | 下の「rproxy のルーティング」 |
| 転送先 | クライアント宛ての応答を rproxy に返す | デフォルトゲートウェイが rproxy なら何もしなくてよい。別の出口があるなら下の「転送先の戻りの経路」 |

- 待ち受けのアドレスとクライアント、転送先は同じアドレスファミリーであること（IPv6 のクライアントを IPv4 の転送先に transparent で渡すことはできない）。`[::]` で待ち受けた IPv4 のクライアント（`::ffff:a.b.c.d`）は IPv4 として扱う。
- 名前空間の中の実経路で、IPv4 / IPv6 × 3 通りの受け取り方 × 転送先の 2 通りの戻り方を CI で確かめている（`scripts/test-transparent.sh`）。

## 例: 入口は GUA、内部は ULA、外へは代表 IP で出る構成

```
インターネット ── GUA ──▶ rproxy ── ULA ──▶ 転送先
                                              │ 外へ出るとき（アップデートなど）
                                              └──▶ 出口のルータ（代表 IP で NAT）
```

- `proxy`（既定）: 転送先には rproxy の ULA が見える。
- `transparent`: 転送先にはクライアントの GUA が見える。ただし転送先の応答はクライアントの GUA 宛てになるので、そのままだと出口のルータへ出てしまう。**転送先で「rproxy から届いた接続の応答だけ rproxy に返す」設定が必要**（下の「転送先の戻りの経路」）。ほかの通信は今までどおり出口のルータから代表 IP で出る。

## rproxy のルーティング

転送先から届く、クライアント宛ての戻りのパケットを、rproxy のホスト自身で受け取る。install.sh で入れる（`rproxy-transparent-routing.service` が起動時に設定する）。

```shell
# クライアントの範囲が決まっている場合（IPv4 / IPv6 を混ぜてよい）
install.sh --transparent-clients 10.0.1.0/24,2001:db8:1::/64 --transparent-iface eth1

# インターネットのクライアントなど、範囲を決められない場合（nftables が要る）
install.sh --transparent-clients any

rproxy-transparent-routing status
```

- 範囲を指定すると、転送先側のインターフェース（`--transparent-iface`）から届いた、その範囲宛てのパケットだけを自分宛てにする（`ip rule iif` + `local` の経路）。
- `any` は、rproxy の transparent ソケット宛てのパケットだけに nftables（`socket transparent`）で印を付けて自分宛てにする。rproxy が転送先のゲートウェイを兼ねていても、ほかの通信は巻き込まない。
- 手で設定する場合は README の「送信元 IP の引き渡し」（iptables / nftables の例）。

## 転送先の戻りの経路

転送先のデフォルトゲートウェイが rproxy なら、何もしなくてよい。
別の出口（代表 IP のルータなど）がある場合は、転送先（Linux）で次の設定を入れる。rproxy から届いた接続に conntrack の印を付け、その接続の応答だけを rproxy へ送る。

```shell
# 転送先で。eth0 は rproxy とつながるインターフェース、fd00:2::1 / 10.0.2.1 は rproxy のアドレス
nft -f - <<'EOF'
table inet rproxy_return {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "eth0" ip6 saddr != fd00::/8 ct mark set 0x52
    iifname "eth0" ip saddr != 10.0.0.0/8 ct mark set 0x52
  }
  chain output {
    type route hook output priority mangle; policy accept;
    ct mark 0x52 meta mark set 0x52
  }
}
EOF
ip -6 rule add fwmark 0x52 lookup 200
ip -6 route add default via fd00:2::1 table 200
ip -4 rule add fwmark 0x52 lookup 200
ip -4 route add default via 10.0.2.1 table 200
```

- `saddr != <内部の範囲>` は、内部どうしの通信（rproxy 以外の内部のホストからの接続）に印を付けないため。rproxy 専用のインターフェースがあれば `iifname` だけでよい。
- 再起動後も残すには、nftables は `/etc/nftables.conf` に、`ip rule` / `ip route` はネットワークの設定（systemd-networkd の `[RoutingPolicyRule]` など）に書く。
- CI（`RETURN=gateway`）では、転送先のデフォルトゲートウェイを別の出口にした構成で、この設定があれば transparent が通ることを確かめている。

## 確かめ方

1. `curl -H "Authorization: Bearer $(sudo cat /etc/rproxy/tokens)" http://127.0.0.1:8080/capabilities` で `"transparent": true` / `"transparent_ipv6": true`
2. `source_ip: transparent` のルールを作り、転送先のログにクライアントのアドレスが出ること
3. つながらないときは、転送先で応答がどこへ出ているかを見る（`tcpdump -ni any host <クライアント>`）。出口のルータへ出ていれば「転送先の戻りの経路」、rproxy に届いているのに受け取れていなければ「rproxy のルーティング」
