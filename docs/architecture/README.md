English: [architecture.md](../en/architecture.md)

# 構成図

今の構成（v0.4.0）を図にしたものです（SVG）。図は SVG を直接直します（PlantUML のソースはリポジトリに置きません）。モジュールや状態を変えたら図も直します。

| 図 | 内容 |
|---|---|
| [overview.svg](overview.svg) | 全体（UI・DB（`forward_rules`・`rproxy_rules`）・rproxy・Kubernetes のコントローラ（rproxy-gateway）・リリースの取り先（自動更新）・設定ファイル・証明書・GeoIP のデータベース・転送先・CrowdSec・OIDC・ACME の CA と DNS） |
| [internals.svg](internals.svg) | rproxy-api のモジュールの構成（起動・`global.performance`、制御プレーン（API の守り・ルールの組の API・引き継ぎと自動更新）、設定（再読み込み・`--check-config`・dry run の差分・DB の復元と保存）、Registry（ルールの組・状態・readiness）、受け付けの判定と宛先（allow_from・GeoIP・limits・bandwidth・balance・outlier）、L4 / L7 のデータプレーン、共通（証明書ストア・ACME・補助プロセス・ログ）） |
| [connection.svg](connection.svg) | TCP の 1 つの接続の流れ（allow_from → GeoIP → CrowdSec → limits → TLS → L4 / L7 → 転送先、接続の失敗で宛先を外す outlier_detection、帯域の上限つきの中継） |
| [rule_state.svg](rule_state.svg) | ルールの状態（rproxy の running / failed、UI の paused / missing / unknown。証明書の期限切れでの failed を含む）と、ルールの組・`rproxy_rules` の復元・conditions・dry run・引き継ぎとの関係 |

![全体](overview.svg)
![モジュール](internals.svg)
![接続の流れ](connection.svg)
![ルールの状態](rule_state.svg)
