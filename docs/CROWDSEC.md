English: [CROWDSEC.md](en/CROWDSEC.md)

# CrowdSec との連携

rproxy は CrowdSec と 2 つの向きで連携します。

| 向き | 何をするか | 設定 |
|---|---|---|
| 止める（bouncer） | LAPI の判定（ban）に入っている IP を止める。L7 は `crowdsec` ミドルウェア（403、AppSec も）、L4 はルールの `crowdsec: true`（TLS より前に切る） | rproxy の `global.crowdsec`（docs/API.md） |
| 見つける（ログ） | CrowdSec のエージェントが rproxy のログを読み、攻撃を見つけて ban する | このページのパーサー・シナリオ・acquis |

両方を入れると、「rproxy を通るアクセスから CrowdSec が見つけて ban → rproxy がその IP を止める」が一周します。CI（`scripts/interop/crowdsec.sh`、interop の `crowdsec` ジョブ）で、本物の CrowdSec を使ってこの一周を確かめています。

## 1. CrowdSec の準備

```bash
# CrowdSec（LAPI・エージェント）を入れる（公式の手順）
curl -fsSL https://install.crowdsec.net | sudo sh
sudo apt install crowdsec

# HTTP のシナリオと AppSec のルール
sudo cscli collections install crowdsecurity/base-http-scenarios crowdsecurity/http-cve \
  crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules
```

## 2. rproxy のログを読ませる（見つける）

rproxy の .deb には `/usr/share/rproxy-api/crowdsec/` に次のファイルが入っています（リポジトリでは `contrib/crowdsec/`）。

| ファイル | 置き場所 | 中身 |
|---|---|---|
| `parsers/s01-parse/rproxy-logs.yaml` | `/etc/crowdsec/parsers/s01-parse/` | rproxy の JSON のログのパーサー（`max3584/rproxy-logs`） |
| `scenarios/rproxy-conn-denied.yaml` | `/etc/crowdsec/scenarios/` | L4：`allow_from` で断られた接続を同じ IP が短い間に繰り返す（ポートの探索など） |
| `scenarios/rproxy-conn-flood.yaml` | `/etc/crowdsec/scenarios/` | L4：同じ IP からの新しい接続が多すぎる（平均 10 件/秒を超えて 200 件ぶん） |
| `acquis.d/rproxy.yaml` | `/etc/crowdsec/acquis.d/` | rproxy のログのファイル（`labels.type: rproxy`） |
| `acquis.d/appsec.yaml` | `/etc/crowdsec/acquis.d/` | AppSec（127.0.0.1:7422） |

```bash
S=/usr/share/rproxy-api/crowdsec
sudo install -m 644 $S/parsers/s01-parse/rproxy-logs.yaml /etc/crowdsec/parsers/s01-parse/
sudo install -m 644 $S/scenarios/*.yaml /etc/crowdsec/scenarios/
sudo install -m 644 $S/acquis.d/rproxy.yaml $S/acquis.d/appsec.yaml /etc/crowdsec/acquis.d/
sudo systemctl restart crowdsec

# 確かめる：rproxy のログの 1 行をパーサーに通す
sudo cscli explain --log "$(tail -n 1 /var/log/rproxy/rproxy.*.log)" --type rproxy
```

- `acquis.d/rproxy.yaml` のファイル名は、`RPROXY_LOG_FILE`（既定の .deb では `/var/log/rproxy/rproxy.log`）に合わせます。rproxy のログは日ごとに `<名前>.<日付>.<拡張子>` へ分かれるので、glob（`/var/log/rproxy/*.log`）で指定します。`global.access_log` でアクセスログを別のファイルにしているなら、そのファイルも足します。
- CrowdSec（root）が rproxy のログのディレクトリ（`rproxy:rproxy` 750）を読めることを確かめます。

### パーサーが作る項目

**HTTP（`event: http.access`）** は、CrowdSec の HTTP のアクセスログ（`log_type: http_access-log`、`service: http`）として扱います。`crowdsecurity/http-logs`（s02）と、`base-http-scenarios`・`http-cve` などの既存のシナリオがそのまま使えます。

| CrowdSec の項目 | rproxy のログ |
|---|---|
| `evt.Meta.source_ip` / `evt.Parsed.remote_addr` | `client`（`global.trusted_proxies` を反映したクライアントの IP） |
| `evt.Meta.http_verb` / `evt.Parsed.verb` | `method` |
| `evt.Meta.http_path` / `evt.Parsed.request` | `path` と `query`（`path?query`） |
| `evt.Meta.http_status` / `evt.Parsed.status` | `status` |
| `evt.Meta.http_user_agent` / `evt.Parsed.http_user_agent` | `user_agent` |
| `evt.Meta.target_fqdn` / `evt.Parsed.target_fqdn` | `host` |
| `evt.Parsed.http_version`・`body_bytes_sent` | `protocol`・`bytes_out` |
| `evt.Meta.rproxy_rule`・`rproxy_route` | `rule`・`route` |
| `evt.Meta.rproxy_refused_by`・`rproxy_auth_error` | `refused_by`（断ったミドルウェアの種類。`basic_auth`・`ip_allow` など）・`auth_error`（`basic_auth` が断った理由。`bad_password` など）。v0.3.20 から |
| `evt.StrTime` | `timestamp` |

**L4（`event: conn.open` / `conn.denied`）** は `log_type: rproxy_conn`（`service: rproxy`）。`evt.Meta.source_ip`（`client` の IP の部分）、`rproxy_event`、`rproxy_reason`（`allow_from` / `crowdsec` など）、`rproxy_rule`。UDP の `conn.denied` は v0.3.20 から既定のログレベルで出る（送信元ごとに間引くので、データグラムの数より少ない）。

## 3. rproxy から止める（bouncer）

```bash
sudo cscli bouncers add rproxy -o raw | sudo tee /etc/rproxy/crowdsec.key >/dev/null
sudo chown root:rproxy /etc/rproxy/crowdsec.key && sudo chmod 640 /etc/rproxy/crowdsec.key
```

```yaml
# RPROXY_CONFIG
version: 1
global:
  crowdsec:
    lapi_url: http://127.0.0.1:8080        # rproxy の制御 API と同じ 8080 にしない（RPROXY_API_PORT を変える）
    api_key_file: /etc/rproxy/crowdsec.key
    appsec_url: http://127.0.0.1:7422      # AppSec を使うとき
    update_interval: 10s
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls: {mode: terminate, certificates: [...]}
    http:
      routes:
        - {name: site, match: "Host(`www.example.com`)", service: web, middlewares: [crowdsec]}
      services:
        web: {servers: [{url: "http://10.0.0.20"}]}
      middlewares:
        crowdsec: {crowdsec: {appsec: true}}   # appsec: false なら LAPI の判定だけ
  - protocol: tcp                               # L4：ban された IP は TLS より前に切る
    listen_addr: 0.0.0.0
    listen_port: 25
    remote_addr: 10.0.0.30
    remote_port: 25
    crowdsec: true
```

- 前段に CDN やロードバランサがあるなら `global.trusted_proxies` を設定します。L7 のログの `client` と判定の照合に、`X-Forwarded-For` の本当の IP が使われます（L4 は接続元の IP）。
- `captcha` の判定は ban として扱います。scope は `Ip` と `Range` だけ（`Country`・`AS` は使いません）。

### GeoIP と組み合わせる（v0.4、#168）

国・ASN で最初から通さないものは rproxy の `geoip`（ルールの `geoip`、L7 の `geoip` ミドルウェア。`global.geoip` に GeoLite2 などの mmdb）で落とし、残りの振る舞いを CrowdSec で見る、という分け方ができる。判定の順は `allow_from` → `geoip` → `crowdsec`。`geoip` で断った接続は `conn.denied`（`reason: geoip`、`country`・`asn`）、リクエストは `http.access`（`refused_by: geoip`）。パーサーは `reason` を `rproxy_reason` に入れるので、シナリオで `geoip` を除く・数えることができる（同梱のシナリオは `allow_from` だけを数える）。

国の情報は CrowdSec の側でも `crowdsecurity/geoip-enrich`（同じ GeoLite2 を使う）で付けられる。rproxy の `global.geoip.log_country: true` は `conn.open`・`http.access` に `country`・`asn` を足すので、CrowdSec を通さずに SIEM などで rproxy のログを見るとき向け。どちらも同じデータベースのファイルを `geoipupdate` で更新すればよい（rproxy は変わったファイルを `check_interval` ごとに読み直す）。

## 4. CI での確かめ方

`scripts/interop/crowdsec.sh` は、GitHub の Ubuntu のランナーで CrowdSec（LAPI・エージェント・AppSec）を公式のパッケージから入れ、ネットワーク名前空間のクライアントから rproxy を通して、次を確かめます。

1. `cscli explain`：見本のログ（`scripts/interop/crowdsec-samples.log`）の 6 行すべてをパーサーが読み、HTTP の行が `crowdsecurity/http-logs` とシナリオ（`http-sensitive-files`・`http-probing` など）へ、L4 の行が `max3584/rproxy-conn-denied` へ届く
2. 検知：global なクライアントが存在しないパスを探索する → CrowdSec が rproxy のログから見つけて ban → そのクライアントは rproxy に 403 で止められ、ほかのクライアントは通る（IPv4 と IPv6）
3. L4：`allow_from` で断られる接続を繰り返したクライアントが `max3584/rproxy-conn-denied` で ban され、`crowdsec: true` の L4 のルールで接続を切られる
4. AppSec：`GET /.env`（`crowdsecurity/vpatch-env-access`）を 403 で止め、ふつうのリクエストは通す
5. `cscli decisions delete` で ban を外すと、また通る
6. 私用アドレス（10.99.0.10）のクライアントは、同じ探索をしても ban されない

クライアントの「global な」アドレスには、文書用のアドレスを使っています。IPv4 は RFC 5737（192.0.2.0/24・198.51.100.0/24・203.0.113.0/24）、IPv6 は RFC 3849（2001:db8::/32）です。インターネットでは経路がないので名前空間の中なら安全で、CrowdSec の既定の whitelist（`crowdsecurity/whitelists`：RFC 1918・ループバックなど）にも入りません。CrowdSec は私用アドレスを ban しないので、`127.0.0.1` からの試験では検知も ban も起きません。
