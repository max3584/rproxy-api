English: [architecture.md](../en/architecture.md)

# 構成図

## まとめ（v0.4.19）

rproxy-api・TCP-UDP-rproxy-ui・rproxy-gateway の 3 つがどうつながるかと、1 つの接続が rproxy の中で通る道です。下の「詳しい図」は v0.4.0 の時点のものです。

![3 つのリポジトリのつながり](system.svg)

- 利用者の通信は青の太線だけを通ります。UI と rproxy-gateway は rproxy の制御 API を呼ぶだけで、データの経路には入りません。
- VIP は rproxy が持たず、keepalived・MetalLB・クラウドの LB などプラットフォームに任せます。
- **rproxy-api**：1 つのプロセスがデータの経路と制御 API（TCP と Unix ソケット）を持ちます。設定ファイルの読み直しや再起動なしの引き継ぎ（SIGUSR2）でも、開いている接続は切りません。
- **TCP-UDP-rproxy-ui**：ルールを MariaDB の `forward_rules` に持ち、各ノードへ制御 API で送ります。rproxy は起動時にこのテーブル（複数ノードではノードごとのビュー）を読んで戻します。
- **rproxy-gateway**：Kubernetes の Gateway API をルールセットに変え、`PUT /rulesets` で各 Pod に送ります。UI には発見の Secret で Pod を見せます（UI からは見るだけ）。

![1 つの接続が rproxy の中で通る道](request-path.svg)

断られる接続はできるだけ手前で落とします（TLS を解く前に allow_from・limits）。上限に達した宛先は選ばず、すべてが上限なら TCP は閉じ、UDP は捨て、HTTP は 503 を返します。`cache` の HIT はミドルウェアで答え、サービスへは行きません。

### 設定をどこで変えるか

| 何を | どこで変える | 保存先 | 反映 |
|---|---|---|---|
| 固定のルール | 設定ファイル（`RPROXY_CONFIG`） | ファイル | 読み直しで即時 |
| UI のルール | UI（`origin: dynamic`） | UI の DB `forward_rules` | 即時 |
| API のルール | 制御 API `POST /rules`（`origin: api`） | `rproxy_rules` | 即時 |
| ルールセット | rproxy-gateway `PUT /rulesets` | `rproxy_rule_sets` | 即時・まとめて |
| global（変わる値） | 制御 API `PATCH /config/global`・UI の global の画面 | `rproxy_global` | 即時（`trusted_proxies`・`access_log`・`crowdsec`・`http.timeouts`・UDP のセッション上限・`cache_max_memory`） |
| global（固定の値） | 設定ファイル・環境変数（API より強い） | ファイル・環境 | 一部は再起動（`acme`・`geoip`・`performance`・`files`・制御 API の待ち受け） |
| トークン | トークンファイル | ファイル | 変化を見て読み直す |

## 詳しい図（v0.4.0）

今の構成（v0.4.0）を図にしたものです（SVG）。図は SVG を直接直します（PlantUML のソースはリポジトリに置きません）。モジュールや状態を変えたら図も直します。

| 図 | 内容 |
|---|---|
| [system.svg](system.svg) | 3 つのリポジトリのつながり（v0.4.19。上の「まとめ」） |
| [request-path.svg](request-path.svg) | 1 つの接続が rproxy の中で通る道（v0.4.19。上の「まとめ」） |
| [overview.svg](overview.svg) | 全体（UI・DB（`forward_rules`・`rproxy_rules`）・rproxy・Kubernetes のコントローラ（rproxy-gateway）・リリースの取り先（自動更新）・設定ファイル・証明書・GeoIP のデータベース・転送先・CrowdSec・OIDC・ACME の CA と DNS） |
| [internals.svg](internals.svg) | rproxy-api のモジュールの構成（起動・`global.performance`、制御プレーン（API の守り・ルールの組の API・引き継ぎと自動更新）、設定（再読み込み・`--check-config`・dry run の差分・DB の復元と保存）、Registry（ルールの組・状態・readiness）、受け付けの判定と宛先（allow_from・GeoIP・limits・bandwidth・balance・outlier）、L4 / L7 のデータプレーン、共通（証明書ストア・ACME・補助プロセス・ログ）） |
| [connection.svg](connection.svg) | TCP の 1 つの接続の流れ（`proxy_protocol` の前段なら PROXY ヘッダ → allow_from → GeoIP → CrowdSec → limits → TLS → L4 / L7 → 転送先、接続の失敗で宛先を外す outlier_detection、帯域の上限つきの中継） |
| [rule_state.svg](rule_state.svg) | ルールの状態（rproxy の running / failed、UI の paused / missing / unknown。証明書の期限切れでの failed を含む）と、ルールの組・`rproxy_rules` の復元・conditions・dry run・引き継ぎとの関係 |

![全体](overview.svg)
![モジュール](internals.svg)
![接続の流れ](connection.svg)
![ルールの状態](rule_state.svg)
