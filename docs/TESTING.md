# テスト一覧（rproxy-api）

| 実行方法 | 対象 | CI のジョブ |
|---|---|---|
| `cargo test` | 単体テスト（`src/`）と結合テスト（`tests/`） | `test` |
| `RPROXY_TEST_DATABASE_URL=mysql://... cargo test --test db_restore` | MariaDB からの復元。変数がなければスキップ | `test`（MariaDB のサービスコンテナを使う） |
| `scripts/test-transparent.sh` | `source_ip` の実経路（ネットワーク名前空間。root 不要） | `transparent` |
| `cargo build`（macOS / Windows） | Linux 以外でビルドが通るか | `build` |

結合テストは loopback 上で実際にソケットを開く。制御 API、転送先のエコーサーバ、クライアントがすべて本物で、名前解決だけを差し替えている（`tests/common/mod.rs`）。

## 単体テスト（`src/`）

| ファイル | テスト | 確かめること |
|---|---|---|
| `rule.rs` | `protocol_is_case_insensitive` | `"TCP"` も受け付け、`source_ip` の既定は `proxy` |
| | `defaults_udp_idle` | UDP の無通信破棄の既定は 30 秒 |
| | `rejects_hostname_listen_and_zero_ports` | 待ち受けアドレスはホスト名不可、ポート 0 は不可 |
| | `proxy_protocol_is_tcp_only` | UDP で `proxy_v2` は `unsupported` |
| | `transparent_needs_capability_and_ipv4` | 権限がない、または IPv6 のときは `transparent` を拒否 |
| | `ipv6_remote_is_bracketed` | IPv6 の転送先は `[::1]:80` の形になる |
| `resolve.rs` | `keeps_cached_answer_while_dns_is_down` | 名前解決に失敗している間も、前回の結果を使い続ける |
| | `empty_answer_is_an_error` | 空の応答は `resolve_failed` |
| `auth.rs` | `rotates_tokens` | 複数トークンの同時有効、読み直し、不正なファイルでは現状維持 |
| | `disabled_allows_all` | トークンファイルなしなら認証なし |
| `source.rs` | `v1_header` / `v2_header_ipv4` / `v2_header_ipv6_length` | PROXY protocol ヘッダのバイト列 |
| `registry.rs` | `a_panicking_listener_marks_only_its_rule_failed` | listener が panic すると、そのルールだけが `failed` になる |
| | `a_stale_supervisor_does_not_touch_a_recreated_rule` | 古い世代の監視タスクは、作り直したルールに触らない |

## 結合テスト：制御 API（`tests/api.rs`）

| テスト | 確かめること |
|---|---|
| `tcp_lifecycle_stops_immediately_and_port_is_reusable` | 追加 → 転送 → 停止が 1 秒以内、既存の接続も切れ、同じポートで再追加できる |
| `update_retargets_new_tcp_connections_at_once` | 変更は新しい接続から即時に反映され、既存の接続は元の転送先のまま |
| `errors_use_the_api_format` | 重複 409、bind 失敗 409（何も残らない）、不正な入力 400、UDP での `proxy_v2` 400、名前解決失敗 502、404 |
| `bearer_token_is_required_when_configured` | トークンなしは 401、`/healthz` は認証不要 |
| `udp_sessions_follow_updates_and_port_is_reusable` | UDP の既存セッションも新しい転送先に切り替わり、停止後すぐに同じポートを再利用できる |
| `udp_sessions_expire_after_idle_timeout` | `udp_idle_secs` でセッションが破棄される |
| `proxy_protocol_v2_header_carries_the_client` | 転送先が受け取る v2 ヘッダに、クライアントのアドレスとポートが入る |
| `drain_waits_for_connections_to_finish` | `drain_secs` の間は既存の接続が使え、閉じたら停止が完了する |
| `restore_retries_rules_whose_target_does_not_resolve_yet` | 復元時に名前解決できなかったルールは `failed` になり、解決できたら自動で開始する |
| `dns_outage_keeps_forwarding_to_cached_address` | DNS 障害中もキャッシュした転送先に転送できる |
| `metrics_and_capabilities` | `/metrics` の値（接続数・バイト数）と `/capabilities` |

## 結合テスト：転送の動作（`tests/dataplane.rs`）

| テスト | 確かめること |
|---|---|
| `large_transfer_keeps_every_byte` | 16 MiB の往復でデータが壊れない |
| `many_concurrent_connections` | 200 本の同時接続がすべて正しく応答する |
| `half_close_lets_the_backend_answer_after_client_eof` | クライアントが送信だけを閉じても、転送先の応答を受け取れる |
| `backend_closing_first_reaches_the_client` | 転送先から切断すると、クライアントにも EOF が届く |
| `backend_down_closes_the_client_and_recovers` | 転送先が落ちていてもクライアントは待たされずに切断され、ルールは `running` のまま。転送先が復帰すると転送が再開する |
| `falls_back_to_the_next_resolved_address` | 名前解決で複数のアドレスが返り、先頭につながらないときは次のアドレスを使う |
| `udp_clients_do_not_see_each_others_replies` | UDP クライアント 20 個の応答が混ざらない |
| `udp_large_datagram_is_forwarded_whole` / `udp_datagram_near_64k_is_forwarded_whole` | 大きなデータグラム（最大 60,000 バイト）が分割されずに届く |
| `ipv6_listen_and_target` | IPv6 での待ち受けと転送。URL エンコードした IPv6 のキーで削除できる |
| `proxy_protocol_v1_header_carries_the_client` | 転送先が受け取る v1 ヘッダの文字列 |
| `concurrent_creates_of_the_same_rule_yield_one_winner` | 同じルールを 10 本同時に追加しても、成功するのは 1 本だけ |
| `a_silent_api_client_does_not_block_others` | 何も送らない接続があっても、ほかのリクエストは待たされない（元の実装の不具合の再発防止） |

## DB からの復元（`tests/db_restore.rs`）

| テスト | 確かめること |
|---|---|
| `loads_current_and_legacy_tables` | 現在のテーブルを読める。範囲外のポートの行は飛ばす。`source_ip` / `udp_idle_secs` 列がない古いテーブルも既定値で読める |

## transparent の実経路（`scripts/test-transparent.sh`）

クライアント（10.0.1.2）・rproxy・転送先（10.0.2.2）をネットワーク名前空間で作り、転送先から見える送信元を確かめる。

| 組み合わせ | 期待する結果 |
|---|---|
| TCP / `proxy` | 転送先には rproxy の IP が見える |
| TCP / `transparent` | 転送先にはクライアントの IP とポートが見える |
| UDP / `proxy` | 転送先には rproxy の IP が見える |
| UDP / `transparent` | 転送先にはクライアントの IP とポートが見える |

## まだテストしていないこと

- 長時間の負荷（数時間の連続転送、メモリの増え方）
- TLS を有効にした制御 API（手動では確認済み、自動テストはない）
- SIGHUP によるトークン・証明書の再読込（手動では確認済み）
- iptables（`-m socket`）を使う transparent のルーティング手順
