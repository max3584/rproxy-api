English: [architecture.md](../en/architecture.md)

# 構成図

今の構成を図にしたものです（SVG）。

| 図 | 内容 |
|---|---|
| [overview.svg](overview.svg) | 全体（UI・DB・rproxy・設定ファイル・証明書・転送先・CrowdSec・OIDC） |
| [internals.svg](internals.svg) | rproxy-api のモジュールの構成（制御プレーン・Registry・L4 / L7 のデータプレーン・共通） |
| [connection.svg](connection.svg) | TCP の 1 つの接続の流れ（allow_from・CrowdSec → TLS → L4 / L7 → 転送先） |
| [rule_state.svg](rule_state.svg) | ルールの状態（rproxy の running / failed、UI の paused / missing / unknown。証明書の期限切れでの failed を含む） |

![全体](overview.svg)
![モジュール](internals.svg)
![接続の流れ](connection.svg)
![ルールの状態](rule_state.svg)
