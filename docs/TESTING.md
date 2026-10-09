English: [TESTING.md](en/TESTING.md)

# テスト一覧（rproxy-api）

| 実行方法 | 対象 | CI のジョブ |
|---|---|---|
| `cargo test` | 単体テスト（`src/`）と結合テスト（`tests/`） | `test` |
| `RPROXY_TEST_DATABASE_URL=mysql://... cargo test --test db_restore --test persist` | MariaDB からの復元（`forward_rules`）と、API で作ったルールの保存・再起動をまたぐ復元（`rproxy_rules`、#144）。変数がなければその部分はスキップ | `test`（同じコンテナで Alpine の MariaDB を動かす） |
| `RPROXY_TEST_PEBBLE=… RPROXY_TEST_PDNS=… RPROXY_TEST_PDNS_SCHEMA=… RPROXY_TEST_SQLITE3=… cargo test --test acme` | ACME（docs/ACME.md）：Pebble（ACME の試験用の CA）と PowerDNS を起動して、HTTP-01・TLS-ALPN-01・DNS-01（PowerDNS の API・RFC 2136（PowerDNS の DNS UPDATE、TSIG の HMAC-SHA256 と SHA512）・acme-dns（小さな偽物）・CNAME の委任・汎用の REST）で実際に証明書を取る。変数がなければその部分はスキップ（API の守りの試験はいつも動く）。`RPROXY_TEST_REQUIRE_ACME=1` でスキップを失敗にする | `test`（同じコンテナで Alpine の `pebble`・`pdns`・`pdns-backend-sqlite3`・`pdns-doc`・`sqlite`。`RPROXY_TEST_REQUIRE_ACME=1`） |
| `cargo test --test self_update` | 自動更新（#174）：署名つきのリリースのミラー（HTTPS）から取って確かめ、引き継ぎで入れ替える・起動役（`launch`）・ロールバック。minisign の道具で作った署名を確かめる試験は、`minisign` がなければスキップ（`RPROXY_TEST_REQUIRE_MINISIGN=1` でスキップを失敗にする） | `test`（Alpine の `minisign`。`RPROXY_TEST_REQUIRE_MINISIGN=1`） |
| `RPROXY_TEST_CRASH_ROUNDS=50 cargo test --test crash` | 異常終了（SIGKILL）の試験の繰り返しを増やす（下の「異常終了」。既定は各 3 回、MariaDB の試験は `RPROXY_TEST_DATABASE_URL` があるときだけ） | Crash ワークフロー（手動だけ） |
| `scripts/test-transparent.sh` | `source_ip` の実経路（ネットワーク名前空間。root 不要） | `transparent` |
| `scripts/test-freebind.sh` | `listen_freebind` の実経路：まだないアドレス（VIP）で待ち受け、後から足すと届く。同じポートの 2 つの VIP（ネットワーク名前空間。root 不要） | `transparent` |
| `cargo bench --bench '*'` | 性能のベンチマーク（`benches/`、criterion）。`cargo test` では各ベンチマークを 1 回だけ動かして壊れていないことを確かめる | `test`（1 回だけ）、`Benchmarks`（比較） |
| `cargo +nightly fuzz run <ターゲット>` | 自前のパーサーのファジング（下の「ファジング」） | Fuzz ワークフローの `fuzz` |
| `scripts/load/run.sh` | 大きな通信を流し続ける負荷・soak のテスト（転送効率。下の「負荷・soak のテスト」） | Load ワークフロー（手動だけ） |

## CI の実行環境

GitHub のランナーは Ubuntu の VM だけなので、ジョブは Alpine のコンテナ（`container: alpine:3.24`。musl で、リリースのバイナリ・.deb と同じ libc）の中で動かす（#191）。パッケージは apk で入れ、Rust は rustup の stable（fuzz は nightly）。

| ワークフロー / ジョブ | 環境 |
|---|---|
| CI の `test`・`package`、Benchmarks、Integrity、Soak、Fuzz、Dependencies（cargo-deny）、Milestone、Interop の `build`・`mail`・`media` | `alpine:3.24` |
| CI の `transparent` | `alpine:3.24`（特権つき。名前空間・veth・nft / iptables） |
| Load | `alpine:3.24`（特権つき。名前空間・veth・tc netem。`sch_netem` はホストの `/lib/modules` から読む） |
| Interop の `crowdsec` | `crowdsecurity/crowdsec`（CrowdSec の公式のイメージ。Alpine。Alpine のパッケージに CrowdSec がない）、特権つき |
| Cross build・Release の `build` | `alpine:3.24`。musl の x86_64 はそのまま、ほかは cargo-zigbuild（zig）でクロスビルドし、gnu は glibc 2.17 向けにリンクする（`scripts/build-release.sh`） |
| Release の `apt`・Cross build の `apt (dry run)` | `debian:13-slim`（apt リポジトリを作る apt-ftparchive が Debian の道具） |
| CI の `deb`・`install` | ランナーの VM（Ubuntu）で直接。.deb のインストール・apt リポジトリからの更新・purge と、install.sh（systemd が前提）を確かめるので、systemd が PID 1 で動いている必要がある（コンテナではできない）。Rust はビルドせず、`package` ジョブ（Alpine）が作った musl のバイナリと .deb を確かめる |

ファジングは sanitizer なしで動かす（Rust の AddressSanitizer は glibc のターゲットにしかない。下の「ファジング」）。

結合テストは loopback 上で実際にソケットを開く。制御 API、転送先のエコーサーバ、クライアントがすべて本物で、名前解決だけを差し替えている（`tests/common/mod.rs`）。

SIEM・CrowdSec が読むログの行は、テストのプロセスの中で本物と同じ JSON の形で集めて確かめる（`tests/common/logs.rs`。`logs::capture()` のあと `logs::wait_for` で、ルールやパスで自分の行を選ぶ）：UDP の `conn.denied` と間引き（`tests/access.rs`）、L4 の `crowdsec` の `conn.denied`・`http.access` の `refused_by`（`tests/crowdsec.rs`）、制御 API の 401 / 403 と変更の `audit`（`tests/api.rs`）、`token.expiring` / `token.expired`（`tests/api_hardening.rs`）、`http.access` の `refused_by`・`user`・`auth_error`（`tests/http.rs`・`tests/http_auth.rs`）。

## 単体テスト（`src/`）

| ファイル | テスト | 確かめること |
|---|---|---|
| `core/rule.rs` | `protocol_is_case_insensitive` | `"TCP"` も受け付け、`source_ip` の既定は `proxy` |
| | `defaults_udp_idle` | UDP の無通信破棄の既定は 30 秒 |
| | `rejects_hostname_listen_and_zero_ports` | 待ち受けアドレスはホスト名不可、ポート 0 は不可 |
| | `proxy_protocol_is_tcp_only` | UDP で `proxy_v2` は `unsupported` |
| | `transparent_needs_capability_and_ipv4` | 権限がない、または IPv6 のときは `transparent` を拒否 |
| | `ipv6_remote_is_bracketed` | IPv6 の転送先は `[::1]:80` の形になる |
| `core/resolve.rs` | `keeps_cached_answer_while_dns_is_down` | 名前解決に失敗している間も、前回の結果を使い続ける |
| | `empty_answer_is_an_error` | 空の応答は `resolve_failed` |
| `control/auth.rs` | `rotates_tokens` | 複数トークンの同時有効、読み直し、不正なファイルでは現状維持 |
| | `refresh_reads_changed_files` | #253：変わったファイル（その場の書き換え・Secret のボリュームのようなシンボリックリンクの差し替え）だけを読み直す。誤りのある版は今のトークンのままで 1 回だけ試す。SIGHUP の後は同じ版を読まない。一時停止の状態は残る |
| | `disabled_allows_all` | トークンファイルなしなら認証なし |
| `net/source.rs` | `v1_header` / `v2_header_ipv4` / `v2_header_ipv6_length` | PROXY protocol ヘッダのバイト列 |
| | `port_ranges` | 範囲の検証（逆順、上限超え、転送先のポートが 65535 を超える） |
| `tls/config.rs` | `wildcard_matches_one_label` | `*.example.com` は 1 階層だけに一致する |
| | `validation_rules` | 証明書なしの terminate、UDP の sni、terminate なしの STARTTLS、CA なしの mTLS を拒否 |
| | `missing_files_are_reported` | 読めない証明書ファイルは、パスを含めて `tls_config` で返す |
| `tls/sni.rs` | `reads_server_name` / `needs_the_whole_record` / `handles_a_hello_split_across_records` / `rejects_plain_text` | rustls が作る ClientHello からサーバ名を読む。途中までのデータ、複数レコードに分かれた ClientHello、TLS でないデータ |
| `l4/starttls.rs` | `smtp_ehlo_then_starttls` / `imap_capability_and_starttls` / `pop3_capa_and_stls` / `quit_closes` | 各プロトコルの STARTTLS 前のやり取り。TLS 前のメール送信・ログインは拒否する |
| | `smtp_optional_tls_hands_over_plain_commands` | `starttls_required: false` では、平文のコマンドを転送先へ引き継ぐ |
| | `data_before_the_handshake_is_refused` | STARTTLS の直後に紛れ込ませたコマンドを受け付けない |
| | `ehlo_reply_loses_starttls` | TLS 後の EHLO の応答から `STARTTLS` を取り除く |
| | `ehlo_reply_with_non_utf8_bytes_does_not_panic` | メールサーバの EHLO の応答に UTF-8 でないバイトや多バイト文字があっても panic しない（ファジングで見つかった入力、#162） |
| `net/source.rs` | `v2_header_carries_tls_tlvs` | PROXY v2 の TLV（AUTHORITY、SSL、CN）と長さ |
| `core/registry.rs` | `a_panicking_listener_marks_only_its_rule_failed` | listener が panic すると、そのルールだけが `failed` になる |
| | `a_stale_supervisor_does_not_touch_a_recreated_rule` | 古い世代の監視タスクは、作り直したルールに触らない |
| `core/ruleset.rs` | `etags_follow_the_rules_and_the_generation` | etag はルールの順に依らず、ルールか世代が変わると変わる。`If-Match` の書き方（引用符・`W/`・リスト・`*`） |
| | `last_transition_moves_only_when_the_status_changes` | `last_transition` は `status` が変わったときだけ動く（`reason` だけでは動かない）。消すと最初から |
| | `conditions_from_the_view` | 状態・誤りの `code` から 4 つの `conditions` の status と reason |
| | `label_metrics_lines` | `rproxy_rule_labels` の行（名前の置き換え、同じ名前になるキー、値のエスケープ） |
| | `readiness_states` | `starting` → ready → `draining`（ready に戻らない） |

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
| `small_writes_are_not_delayed_by_nagle` | 2 回に分けた小さな書き込みの往復が、どちら向きでも遅延 ACK（約 40 ms）を待たない（両側の TCP_NODELAY、#176） |

## 結合テスト：ポート範囲と TLS（`tests/tls.rs`）

テスト用の CA とサーバ証明書・クライアント証明書は、実行のたびに作る（`tests/common/pki.rs`）。

| テスト | 確かめること |
|---|---|
| `tcp_port_range_maps_one_to_one` / `udp_port_range_maps_one_to_one` | 範囲の各ポートが、転送先の対応するポートへ届く。削除すると全ポートが閉じる |
| `overlapping_ranges_are_rejected` | 範囲が重なるルールは作れない（プロトコルが違えばよい） |
| `sni_routes_without_decrypting` | SNI で転送先を選ぶ（ワイルドカードを含む）。転送先の証明書でクライアントと転送先の間の TLS が成立する（rproxy は復号しない）。平文は切断する |
| `terminate_sends_plain_text_and_tls_details_in_proxy_v2` | 転送先には平文が届き、PROXY v2 の TLV に SNI と ALPN が入る |
| `mtls_required_checks_client_certificates` | 正しい CA のクライアント証明書だけを受け付け、失敗は `rproxy_tls_failures_total` に数える |
| `terminate_can_re_encrypt_towards_the_backend` | 転送先へ TLS で再暗号化する。転送先の証明書の名前が違えば失敗する |
| `certificates_are_chosen_by_sni` | 複数の証明書から SNI で選ぶ |
| `bad_tls_settings_are_reported` | 読めないファイル、証明書なしの terminate、未知の mode、UDP の sni を拒否し、何も残らない |
| `reload_picks_up_renewed_certificates_and_patch_changes_tls` | 証明書ファイルを差し替えて再読込すると新しい証明書が使われる。PATCH で passthrough に戻せる |
| `terminate_does_not_stall_under_backpressure` | クライアントの送信バッファを小さくして、終端したルールで 1 MiB の往復を 16 回。どの回も全部のバイトが壊れずに返る（#187） |
| `optional_no_verify_lets_any_client_certificate_in` | `client_auth.mode: optional_no_verify`（#238）：正しい CA・別の CA・証明書なしのどのクライアントも通る（`ca_file` ありとなし）。`optional` に `ca_file` がなければ `tls_config`。`features.client_auth_modes` |
| `a_tls_route_spreads_over_several_targets` | `tls.routes` の `targets`（#234）：重みどおりに配り、つながらない宛先は飛ばす。`balance: failover`。`remote_addr` と `targets` の両方・どちらもなし・`targets` なしの `balance` は `tls_config` |
| `files_others_may_write_or_read_are_refused` | ルールの鍵がほかの人に読める・証明書がグループに書けると `400 tls_config`（理由つき）、0644 の証明書と 0640 の鍵は使える（`global.files.owner_check`） |

## 結合テスト：多段の CA（`tests/chain.rs`）

中間 CA が 1 段（3 層）と 2 段（4 層）の両方で確かめる。クライアントが信頼するのはルートだけ。

| テスト | 確かめること |
|---|---|
| `server_certificates_need_their_intermediates` | `chain_file` がないとクライアントは検証できず、あれば検証できる |
| `a_full_chain_in_cert_file_still_works` | `cert_file` にチェーンを連結した従来の指定でも動く |
| `wrong_order_and_wrong_key_are_rejected` | 順番が逆のチェーンと、別の証明書の鍵を `tls_config` で拒否する |
| `mtls_with_multi_tier_client_certificates` | `ca_file` がルートだけでも、中間 CA を送るクライアントは通る。証明書だけを送るクライアントは、`client_auth.chain_file` があれば通り、なければ通らない。別の PKI の証明書は通らない |
| `dtls_mtls_with_multi_tier_client_certificates` | DTLS でも同じ規則。検証できないクライアントは、ハンドシェイクのあと何も転送せずに切る |

## 結合テスト：アクセス制御と固定ルール（`tests/access.rs`）

| テスト | 確かめること |
|---|---|
| `allow_from_limits_tcp_clients_and_can_change_live` | 範囲外の TCP クライアントは切断され（接続数には数えず `denied` に数える）、PATCH で範囲を変えるとすぐ反映される。不正な CIDR は `invalid` |
| `allow_from_limits_udp_clients` | 範囲外の UDP の送信元にはセッションを作らない |
| `unmatched_names_are_rejected_when_asked` | `terminate` で、証明書には含まれていてもどの `routes` にも一致しない名前は、ハンドシェイクを完了せずに切る（TLS の失敗には数えない）。`unmatched: default` なら通る。`routes` なしの `reject` は `tls_config` |
| `sni_rules_reject_unmatched_names_before_forwarding` | `sni` でも、一致しない名前は転送せずに切る |
| `static_rules_are_protected_from_the_api` | 固定ルールは `origin: static` で動き、PATCH / DELETE は `409 static`、同じキーの追加は `already_exists`。`shutdown` では止まる |
| `a_broken_static_file_starts_nothing` | 不正なルールや重なりがあれば、1 件も開始せずにエラーを返す |

## 結合テスト：STARTTLS（`tests/starttls.rs`）

| テスト | 確かめること |
|---|---|
| `smtp_starttls_is_terminated_by_rproxy` | 平文の EHLO → STARTTLS → TLS 上の EHLO（応答から STARTTLS が消える）→ MAIL。平文のコマンドは転送先に届かない |
| `smtp_without_tls_is_allowed_when_not_required` | `starttls_required: false` では平文のまま通り、EHLO が転送先へ引き継がれる |
| `imap_starttls_is_terminated_by_rproxy` | TLS 前の LOGIN は拒否し、パスワードは TLS 上でだけ流れる |
| `pop3_stls_is_terminated_by_rproxy` | TLS 前の USER は拒否し、STLS のあとは転送先に届く |
| `starttls_needs_terminate` | `tls.mode: terminate` なしの `starttls` は `tls_config` |

## 結合テスト：DTLS（`tests/dtls.rs`）

| テスト | 確かめること |
|---|---|
| `dtls_is_terminated_and_forwarded_as_plain_udp` | DTLS を終端し、転送先には平文の UDP を送る。クライアントごとに別のセッションになる |
| `dtls_client_certificates_can_be_required` | クライアント証明書を必須にできる |
| `dtls_can_be_re_encrypted_towards_the_backend` | 転送先へ DTLS で再暗号化する |
| `dtls_needs_a_pkcs8_key` | PKCS#8 でない鍵は `tls_config` |

## 結合テスト：データの完全性（`tests/integrity.rs`、#134）

何十 MiB の擬似乱数のデータ（1 MiB のブロックから、流れの番号とチャンクの番号で決まる位置を切り出したもの。並べ替え・重複・ずれがあればハッシュが変わる）を流し、SHA-256 を比べる。大きさは `RPROXY_TEST_INTEGRITY_MB`（既定 32。`.github/workflows/integrity.yml` が毎週 512 で動かす）。

| テスト | 確かめること |
|---|---|
| `tcp_streams_arrive_unchanged_on_every_path` | TCP の passthrough・`proxy_v2`・terminate・`upstream.tls` で、4 本の接続が同時に両方向へ流したデータが変わらずに届く |
| `a_reset_is_passed_on_as_a_reset_and_a_close_as_a_close` | 転送先のリセットはクライアントに、クライアントのリセットは転送先にリセットとして届く（正常な終わりに見えない）。片方の FIN は半分閉じとして伝わる。TLS を終端しても、転送先のリセットで TLS はきれいに終わらない |
| `udp_datagrams_arrive_unchanged_once_and_in_order` | 番号つきのデータグラム（1 バイト〜65,507 バイト）が 4 つのクライアントから、変わらずに 1 回ずつ順番どおり返る。`stats.dropped` は 0 |
| `dtls_records_arrive_unchanged_once_and_in_order` | DTLS を終端したルールでも同じ |
| `http_bodies_arrive_unchanged_on_every_protocol` | HTTP/1.1・HTTP/2・HTTP/3 のダウンロード（`Content-Length` と chunked）とアップロード（長さつきと chunked）が、4 本同時でも変わらない |
| `middlewares_keep_bodies_intact` | `compress`（gzip・br・zstd を展開すると元に戻る）、`buffering`、`retry`（1 台目が止まっていても。アップロードは冪等な PUT）で変わらない |
| `reused_backend_connections_never_mix_bodies` | 1 本の HTTP/2 の接続で 48 件を同時に、続けて 16 件を順に送り、転送先への接続を使い回しても、どの応答・リクエストも自分の本文だけを持つ |
| `websocket_streams_arrive_unchanged` | WebSocket（Upgrade）の両方向の流れが変わらない |
| `a_response_cut_off_by_the_backend_never_looks_complete` | 転送先が応答の途中で切れると、HTTP/1.1・HTTP/2・HTTP/3 のクライアントには誤り（途中で終わった）として見える（`Content-Length`・chunked・`compress` を通したもの） |
| `a_request_cut_off_by_the_client_never_reaches_the_backend_as_complete` | クライアントが本文の途中で切れる（HTTP/1.1 の `Content-Length` と chunked の切断、HTTP/2 の RST_STREAM、HTTP/3 のリセット）と、転送先には完全なリクエストとして届かない |
| `http2_backends_and_mirrors_keep_bodies_intact` | h2c の転送先（`protocol: h2c`、#233）とのダウンロード・アップロード、`mirror`（#232）を通したアップロードが、HTTP/1.1・HTTP/2・HTTP/3 のクライアントで変わらない |
| `http2_backend_cut_offs_and_route_timeouts_never_look_complete` | h2c の転送先が応答の途中で切れたとき、ルートの `timeouts.request` / `backend_request`（#227）が応答の本文の途中で過ぎたとき、どのクライアントにも誤りとして見える |

## 結合テスト：TCP のリレー（`tests/relay.rs`、#185）

`l4::relay` は向きごとのバッファを、送るデータがあるあいだだけスレッドごとのプールから借りる。貸しているバッファの数（`l4::relay::buffers_in_use`）はプロセス全体の値なので、テストは 1 つの関数にまとめている。

| テスト | 確かめること |
|---|---|
| `relay_buffers_and_half_closes` | データが通り終わった接続（平文 50 本、TLS の終端 20 本）はバッファを持たない（そのあとも使える）。転送先が読まず詰まっている接続はバッファを持ち、終わったら返す。転送先が先に FIN を送っても（平文・TLS の終端）、クライアントが先に終えても（TLS の終端）、半分閉じとして伝わり、残りの向きのデータが全部届く |

## 結合テスト：L4 の制限と帯域（`tests/limits.rs`、#165・#166）

| テスト | 確かめること |
|---|---|
| `capabilities_say_limits_and_bandwidth_run` | `features.limits`・`features.bandwidth` が true |
| `tcp_connections_are_limited_per_source_and_per_rule` | 送信元ごと・ルール全体の同時接続数を超えた TCP の接続は何も送らずに閉じる（`stats.limited`、`rproxy_rule_limited_total` の `reason`）。閉じた接続の分は空く。`PATCH` で上限を変えても開いている接続は数えたまま、`{}` で外れる。`stats.counters_since`・`rproxy_process_start_time_seconds` |
| `tcp_new_connections_are_a_rate` | 新しい接続の速さ（`new_connections`） |
| `http_rules_limit_their_connections` | `http` のルールでは TCP の接続に効く |
| `udp_sessions_and_datagrams_are_limited` | UDP のセッションの数と、送信元ごとのデータグラムの速さ（`packets`）。超えたデータグラムは捨て、セッションを作らない |
| `tcp_bandwidth_waits_and_applies_to_open_connections` | 下りの上限を `PATCH` で付けると、splice で大きな転送をしている接続も絞られ（1 MB/s）、バイトは欠けない。外すと速さが戻る |
| `tcp_upload_per_source_waits` | 送信元ごとの上りの上限で、クライアントの書き込みが待たされる |
| `http_rules_are_shaped` | `http` のルールの応答が下りの上限で絞られる |
| `udp_bandwidth_drops_over_the_rate` | UDP の下りの上限を超えたデータグラムを捨て、`stats.dropped`・`rproxy_rule_bandwidth_dropped_total` に数える（上りはそのまま） |

## 結合テスト：v0.4 の形（`tests/v04_shapes.rs`、#215）

v0.4 の設定（docs/DESIGN-v0.4.md）の形をまとめて確かめる。v0.4.0 ではすべての項目が動く（`features` はすべて true）ので、ここに残っているのは `features` の一覧・新しいエンドポイントのスコープ・`--check-config` と起動時の引数の検証・0.3 の設定ファイルがそのまま通ることだけ。各機能が動くことは、機能ごとのテスト（`tests/api_hardening.rs`・`rulesets.rs`・`limits.rs`・`geoip.rs`・`outlier.rs`・`plan.rs`・`persist.rs`・`handoff.rs`・`self_update.rs`・`performance.rs`）で確かめる。

| テスト | 確かめること |
|---|---|
| `capabilities_list_every_v0_4_feature_as_on` | v0.4 の `features` の印がすべて true（`client_cert_auth`・`token_expiry`・`api_lockout`・`rulesets`・`labels`・`conditions`・`readyz`・`geoip`・`outlier_detection`・`limits`・`bandwidth`・`dry_run`・`persistence`・`handoff`・`self_update`、ミドルウェアの `geoip`・サービスの `outlier_detection`） |
| `upgrade_and_update_endpoints_answer`・`performance_keys_are_all_applied` | 実装した #174・performance：`handoff`・`self_update` が true、`build`、ライブラリとして組んだルーターでの `/admin/*` の答え（Unix ソケットだけの決まり、`GET /admin/update` は `mode: off`）、`features.performance` がすべての項目 |
| `new_endpoints_need_their_scopes` | 新しいエンドポイントのスコープと Unix ソケットだけの決まり |
| `check_config_validates_the_v0_4_shapes`・`a_0_3_settings_file_still_passes` | `--check-config` は v0.4 の形の誤りをエラーにする。v0.4 の設定はすべて動くので警告にならない。0.3 の設定ファイルは警告なしで通る |
| `v0_4_flags_are_checked_at_startup` | 引数・環境変数の誤り（`--tls-client-auth` に CA がない、`--tls-client-ca` に `--tls-cert` がない、`--token-warn-days 0` など）は起動を止める |

## 結合テスト：制御 API の守り（`tests/api_hardening.rs`、#167）

| テスト | 確かめること |
|---|---|
| `client_certificates_authenticate_alone_or_bound_to_a_token` | main.rs と同じ TLS（`ClientCertAcceptor`）で、`optional` では証明書だけのエントリが証明書（SAN、なければ CN）で通り、スコープも効く。知らない名前・証明書なしは 401、トークンは証明書なしでも通る。証明書に結びついたトークンは、その証明書がないと 401。ほかの CA の証明書はハンドシェイクで断る。`required` では証明書のない接続を断る |
| `failing_sources_are_locked_out_over_tcp_but_not_the_unix_socket` | 窓の中の 401 が上限に達した送信元は、正しいトークンでも `429 locked_out`（`Retry-After`）。Unix ソケットの失敗は数えず、止めている間も Unix ソケットは通る。`/healthz` は止めない。`/metrics` の `rproxy_api_lockouts_total`・`rproxy_api_locked_sources`。時間が過ぎれば戻る |
| `verified_certificates_and_exempt_sources_are_not_locked_out` | 止められた送信元からでも検証済みのクライアント証明書の接続は通る、`--api-lockout-exempt` の範囲は数えも止めもしない、形の誤りは起動を止める（セキュリティレビュー M4） |
| `lockout_is_on_by_default` | 既定（オーナーの決定）で 20 回目の失敗で止まる |
| `expiring_tokens_are_reported_and_exported` | 期限の近いトークンは `token.expiring`（`days_left`）、切れたものは `token.expired`、状態が変わったときに 1 回だけ。`/metrics` の `rproxy_token_expiry_timestamp_seconds` |
| `the_binary_serves_client_certificates` | 本物のバイナリ：`client_cert` のあるトークンファイルで `--tls-client-auth` がなければ起動しない。`required` では証明書だけで `/rules` を読め、証明書のない接続は断る |
| `the_binary_reads_a_changed_token_file_without_sighup` | #253：本物のバイナリ（`RPROXY_TOKENS_CHECK_SECS=1`）が SIGHUP なしでトークンファイルを読み直す。その場の書き換えで足したトークンが通り、Secret のボリュームのような `..data` のリンクの差し替えで新しいトークンが通って消したトークンは 401。誤りのある版では今のトークンのまま、警告は 1 回。ログにトークンは出ない。`features.tokens_reload` |

## 結合テスト：再起動なしの更新（`tests/handoff.rs`、#174）

本物のバイナリを起動して、SIGUSR2 と `POST /admin/upgrade` で引き継ぐ（docs/UPGRADE.md）。

| テスト | 確かめること |
|---|---|
| `tcp_connections_survive_and_new_ones_go_to_the_new_process` | 引き継ぎの前に開いた TCP の接続（固定ルールと API のルール）は古いプロセスが最後まで運ぶ。引き継ぎの後の新しい接続は新しいプロセスのもの（`/proc` でサーバ側のソケットの持ち主を確かめる）。UDP は新しいセッションで続く。API のルール（`targets`・`allow_from`）がそのまま移る。制御 API の TCP と Unix ソケットも移る。`rproxy_process_start_time_seconds` は変わらない。古いプロセスは接続が終わると正常に終わり、統計の数は減らず、古いプロセスが待っている間に数えた分も足される（接続数とバイト数がぴったり）。2 回目の引き継ぎを Unix ソケットの `POST /admin/upgrade` で。最後に普通に止めるとソケットのファイルを消す |
| `api_rules_and_http_counters_carry_over` | `persist: true` のトークンのルールが DB を読み直さずに `origin: "api"`・`created_by`・`created_at`・`persisted` のまま戻る。`stats.http` のルートごとの数が引き継がれて、その後も増える |
| `a_failed_handoff_keeps_the_old_process` | 新しいプロセスにつなげない（引き継ぎ用のソケットのディレクトリがない）と `handoff.failed` で、古いプロセスが動き続ける。`rproxy_handoffs_total{outcome="failed"}`・`rproxy_build_info`。TCP からの `POST /admin/upgrade` は既定で 403 |

## 結合テスト：SIGTERM での終わり方（`tests/shutdown.rs`、v0.4.1）

本物のバイナリに SIGTERM を送る（docs/DESIGN-v0.4.x.md の 2.、`RPROXY_SHUTDOWN_DELAY` / `_DRAIN`）。

| テスト | 確かめること |
|---|---|
| `by_default_sigterm_stops_at_once` | 既定（両方 `0s`）ではすぐ止まり、今の接続も切れる（今までと同じ）。`features.graceful_shutdown` |
| `delay_keeps_accepting_then_drain_lets_connections_end` | `delay` の間：`/readyz` は 503、`GET /rules` は答え、`POST /rules` は `503 shutting_down`、新しい TCP の接続が通る。`drain` の間：新しい TCP の接続は断られ、前からの TCP の接続・UDP のセッションは続き、新しい UDP のセッションは作られない。アイドルの HTTP/1.1 の接続は閉じ、処理中のリクエストの応答は `Connection: close`。`drain` を過ぎると残りを切って終わる（`shutdown.done` の `cut`） |
| `a_second_sigterm_stops_at_once` | `delay` の間の 2 回目の SIGTERM ですぐ止まる（`shutdown.now`） |
| `a_second_sigterm_cuts_the_drain_short` | `drain` の間の 2 回目の SIGTERM で待つのをやめ、残りの接続を切る |
| `values_out_of_range_stop_the_startup` | 1 時間を超える値は起動を止める |

## 結合テスト：証明書の API（`tests/cert_api.rs`、#240、v0.4.2）

| テスト | 確かめること |
|---|---|
| `store_use_replace_and_delete` | `PUT /certs/{name}` が 201 と `ETag`（指紋）、ファイルは 0600・ディレクトリは 0700。`{"cert": name}` のルールがその証明書で TLS を終える（owner check を通る）。`If-Match` の違いは 412、差し替え（200）で開いている接続は続き、新しい接続は新しい証明書。古い版は消える。使っている間の `DELETE` は `409 in_use`（`used_by`）、使わなくなれば 204。監査の行に名前と指紋があり、鍵はない。`features.cert_store` |
| `bad_certificates_and_names_are_refused` | 読めない PEM・鍵の不一致・期限切れ・鍵なし・知らない項目・名前の誤りは `400 invalid`（応答に鍵を出さない）、1 MiB を超える本文は 413、期限が近いものは `warnings`。保存していない名前を使うルールは `400 tls_config`、`cert` と `cert_file` の両方は誤り |
| `a_failed_rule_starts_once_its_certificate_is_stored` | 設定ファイルのルールが保存していない名前を使うと `failed`、その名前を `PUT` すると動き出す |
| `scopes_and_allow_certs` | `certs:read` / `certs:write` のスコープ、`allow_certs` の外の名前は `PUT`・ルールでの使用とも 403、`GET /certs` は `allow_certs` の内だけ |

## 結合テスト：ルールの組の保存（`tests/ruleset_persist.rs`、#241、v0.4.2）

| テスト | 確かめること |
|---|---|
| `persist_tokens_store_their_sets` | `persist: true` のトークンの組は 1 行（`generation`・`etag`・持ち主・ルール）で保存され、応答・`GET /rulesets`・`GET /rulesets/{name}` に `persisted`。dry run と `persist` のないトークンの組は書かない。保存した組は `admin` が変えても行が変わる（持ち主はそのまま）。書けなければ `persisted: false`。`DELETE` で行が消える。`features.ruleset_persistence` |
| `stored_sets_are_restored` | 保存した組が `generation`・`etag`・持ち主ごと戻る。先に戻したルールとキーが重なるルールだけ外して、残りを当てる。持ち主が戻るので、ほかのトークンは変えられない |
| `sets_survive_a_restart_with_mariadb` | 本物のバイナリと MariaDB（`RPROXY_TEST_DATABASE_URL`）：テーブルがなくても起動し `persisted: false`。保存 → 再起動で戻る。ほかのノードの行は戻さない。新しい `generation` の行を古い `PUT` で書き換えない。`DELETE` で行が消える |

## 結合テスト：performance（`tests/performance.rs`、#194・#184）

本物のバイナリを起動して、`global.performance` の効き目を外から確かめる。

| テスト | 確かめること |
|---|---|
| `the_settings_file_sets_workers_shards_and_pinning` | 設定ファイルが環境変数より先：ワーカーのスレッド（`rproxy-wrk-*`）の数、ワーカー i が一覧の i 番目の CPU に固定（`/proc/<pid>/task/*/status` の `Cpus_allowed_list`）、`udp_shards: auto` でポートのソケットがワーカーの数（`/proc/net/udp`）、`splice` の項目ごとの上書き、`performance` の行の `sources` |
| `the_environment_applies_without_the_file` | 設定ファイルに `global.performance` がなければ `RPROXY_WORKERS`・`RPROXY_UDP_SHARDS=auto`・`RPROXY_SPLICE=0` が効く。何もなければ既定（UDP のソケット 1 本、固定なし） |
| `cpus_that_do_not_exist_are_left_out` | 存在しない CPU は除いて `degraded`、ワーカーは使える CPU の数 |

## 結合テスト：自動更新（`tests/self_update.rs`、#174）

HTTPS のミラー（テストの中の小さなサーバ。バイナリは GitHub と同じくリダイレクトで渡す）に、このバイナリを次のパッチの番号で署名して置く。

| テスト | 確かめること |
|---|---|
| `a_signed_patch_is_swapped_in_and_a_forged_one_refused` | 署名つきの索引（番号が飛んでいて、ほかのマイナーも並ぶ）から新しいパッチを選び、`POST /admin/update` で取って確かめ、引き継ぎで入れ替える（新しいプロセスはキャッシュのバイナリ）。`RPROXY_UPDATE_HEALTHY` の後によい版になる。署名がバイナリと合わないパッチは断り（`GET /admin/update` の `error`）、キャッシュにも入れない |
| `launch_runs_the_newest_patch_follows_upgrades_and_rolls_back` | `rproxy-api launch` が最新のパッチを選んで起動する（trial）。SIGUSR2 を渡して引き継ぎの後の主プロセスを追う。trial の版が落ちたら悪い版にしてイメージの版で起動し直す。SIGTERM でサーバと一緒に終わる |
| `a_trial_stopped_by_a_signal_is_not_bad_and_bad_marks_can_be_cleared` | 試している版を起動役への SIGTERM で止めても悪い版にしない（`trial` は消える）。`rproxy-api update-clear-bad --version` で悪い版の印を外せる（セキュリティレビュー M1） |
| `a_trial_killed_three_times_is_bad` | 試している版が SIGKILL で止まる：コンテナごと（起動役も）と、サーバだけ（コンテナのメモリの上限の OOM killer はいちばん大きいサーバを選ぶ）。どちらも `update.interrupted` で数え（サーバだけのときは起動役がその場で起動し直す）、3 回目で悪い版にしてイメージの版を起動する（セキュリティレビュー M1） |
| `signatures_of_the_minisign_tool_verify` | minisign の道具で作った鍵と署名（既定の事前ハッシュの形と古い形）を確かめられる |

## 結合テスト：異常終了（`tests/crash.rs`）

本物のバイナリを SIGKILL（OOM killer・`kill -9` と同じ）で止め、同じファイルで起動し直す（systemd・起動役の再起動と同じ）。kill の時刻はでたらめに変え、各試験を `RPROXY_TEST_CRASH_ROUNDS` 回（既定 3）繰り返す。多く回すのは手動の Crash ワークフロー（`gh workflow run crash.yml -f rounds=50`）。プロセスは自分のプロセスグループで動かし、引き継ぎの新しいプロセスもまとめて止める（systemd の `KillMode=control-group`・コンテナの終わりと同じ）。

| テスト | 確かめること |
|---|---|
| `stored_certificates_survive_kills_during_writes` | `PUT` / `DELETE /certs` を 4 本で続けている間に kill。起動し直すと、保存した証明書はどれも送ったもののどれかで、鍵と組になって読める（ディスクの `current/` を直接確かめる）。`GET /certs` とディスクが一致し、`remove` が脇に置いたもの（`.removing-*`）は残らない。その証明書を使うルールは送った証明書で動く |
| `leftovers_of_a_killed_process_do_not_stop_the_startup` | kill されたプロセスが残すもの（制御 API の Unix ソケット・引き継ぎのソケットのファイル、証明書のストアの一時ファイル・`current.tmp`・`current` のない名前・`.removing-*`）があっても起動し、Unix ソケットで答え、引き継ぎもできる |
| `a_kill_under_traffic_comes_back_with_the_same_rules` | TCP・UDP・HTTP を流している間に kill。起動し直すと `/readyz` が最初に 200 を返したときにはルールがすべてそろっていて（`GET /rules` が kill の前と同じ。数・`started_at` を除く）、流れ、数は 0 から（`counters_since` が起動の時刻） |
| `kills_during_a_live_upgrade_leave_a_service_that_starts_again` | 引き継ぎ（SIGUSR2）の途中（すぐ・`handoff.start`・`handoff.received`・`handoff.sent`・`restore.start`・`handoff.ready` の直後）に古いプロセス・新しいプロセス・両方を kill。準備の前に新しいプロセスが死んだら古いプロセスが変更も含めて動き続け、古いプロセスだけが死んだら新しいプロセスは引き継ぐか自分で終わる（止まったままにならない）。どの場合も起動し直すと、ルール・制御 API（TCP と Unix ソケット）が戻る |
| `stored_rules_survive_kills_with_mariadb` | `persist: true` のトークンでルールの作成・変更・削除を 6 本で続けている間に kill。起動し直すと、各ルールは最後に答えた変更のとおりか、kill のときに送っていた変更のとおり（`origin: api`・`persisted: true`）で、`rproxy_rules` の行とも一致する |
| `stored_rule_sets_survive_kills_with_mariadb` | `persist: true` のトークンでルールの組を世代を上げながら `PUT` し続けている間に kill。起動し直すと、組は最後に答えた世代か kill のときに送っていた世代で、その世代のルールがちょうどそろう |

## 結合テスト：変更前の差分（`tests/plan.rs`、#169）

| テスト | 確かめること |
|---|---|
| `dry_runs_of_the_rule_endpoints_change_nothing` | `POST` / `PATCH` / `DELETE` の `dry_run` は `action`・`change`・`before`（表示）・`after`（形）・`diff` を返し、何も作らない・変えない・消さない（待ち受けも開かない）。誤りは実際の操作と同じ答え（`invalid`・`tls_config`（証明書を読む）・`already_exists`・`unsupported`・`not_found`・`static`）。名前は解決しない |
| `rule_set_dry_runs_change_nothing` | `PUT /rulesets/{name}?dry_run=true` が組の確かめをして、ルールごとの `action`・`change`（変わらない・接続を切らない変更（`diff`）・作り直し・削除・作成）と、なるはずの etag を返し、組もルールも変えない。古い `generation` は実際と同じく断る |
| `dry_runs_need_the_same_permissions` | `allow_listen_ports` とスコープは dry run にも効く |
| `config_plan_compares_with_the_static_rules` | `POST /config/plan` が固定ルールとの違い（作成・接続を切らない変更・作り直し・削除・変わらない数）、`restart_needed`、API のルールが持つアドレスの警告（`failed`）を返し、何も変えない。誤りは `400` と `errors` |
| `config_reload_dry_run_reads_the_file_and_applies_nothing` | `POST /config/reload?dry_run=true` はファイルを読んで差分を返すだけ。誤りは `400`。そのあとの本当の reload は反映する |
| `check_config_diff_asks_the_running_rproxy` | 本物のバイナリを Unix ソケットで動かし、`--check-config --diff` が差分を出す（`text`・`json`、既定の問い合わせ先 `RPROXY_API_SOCKET`、`--diff-token-file`）。トークンなし（401）・つながらない・`--diff-api` の誤り・設定の誤りは 1 |

## 結合テスト：API で作ったルールの保存（`tests/persist.rs`、#144）

| テスト | 確かめること |
|---|---|
| `persist_tokens_store_their_rules` | `persist: true` のトークンのルールは `origin: "api"`・`persisted`・`created_by`・`created_at` で行が書かれる（メモリのストア）。保存しないトークンのルールは `dynamic` のまま。`api` のルールの変更はどのトークンでも書き、作った人は残る。書けなければ `persisted: false` で動き続ける。削除で行も消える。dry run は書かない |
| `without_a_database_nothing_is_stored` | `RPROXY_DATABASE_URL` がなければ `api` だが `persisted: false` |
| `restored_rows_are_api_rules` | 復元した行は `api` のルール（`persisted: true`、保存した `created_at`）。同じキーは UI の行が先 |
| `rules_survive_a_restart_with_mariadb` | MariaDB（`RPROXY_TEST_DATABASE_URL`）と本物のバイナリ：作ったルールが `rproxy_rules` に書かれ（変更も）、再起動で `api` として戻る。UI の行と同じキーは UI のもの（`restore.conflict`）、ほかの `node` の行は戻らない。削除で行も消える |
| `a_blank_node_name_stops_the_startup` | 空白だけの `RPROXY_NODE_NAME` は設定のエラー |
## 結合テスト：ルールの組・ラベル・状態・readiness（`tests/rulesets.rs`、#28）

Kubernetes のコントローラ（`max3584/rproxy-gateway`）が使う口。

| テスト | 確かめること |
|---|---|
| `capabilities_turn_the_controller_features_on` | `features` の `rulesets`・`labels`・`conditions`・`readyz` が true |
| `a_set_is_applied_as_a_whole_with_minimal_disruption` | `/` を含む名前の組を作る（`ETag` ヘッダ、`GET /rules` の `ruleset`・`labels`・`conditions`、`GET /rulesets`）。同じ本文はすべて `none` で etag も同じ。宛先だけの違いは `in_place` で、前からの接続は切れずに新しい接続が新しい宛先へ。`source_ip` の違いは `recreate`。外したルールは `delete`。`DELETE /rulesets/{name}` で全部止まる |
| `sets_refuse_stale_writes_and_do_not_take_other_rules` | `If-Match` の食い違い・まだない組への `If-Match`（412）、古い `generation`（409 `stale_generation`）、引用符なし・リスト・`W/` の `If-Match`。組のルールの個別の PATCH / DELETE は `409 owned`、ほかの組は `owned`、POST のルールは `already_exists`（何も作らない）。不正なルールが 1 つあれば何も変えず、`errors` にすべての問題。本文の中の重なり。`dry_run` は消えるルールを答えて何も変えない（詳しくは tests/plan.rs）。名前の誤り |
| `a_rule_that_cannot_bind_fails_alone` | 使用中のポートのルールだけ `failed`（`Programmed` が `False`・`BindFailed`、`BackendsHealthy` が `Unknown`、読み直しても `last_transition` は同じ）、残りは動く。ポートが空いてから同じ本文を PUT すると作り直して動く |
| `conditions_report_targets_that_are_down` | 宛先がすべて down のルールは `BackendsHealthy` が `False`・`AllTargetsDown`（組でないルールにも `conditions`） |
| `labels_are_kept_replaced_and_exported` | `labels` の表示、`/metrics` の `rproxy_rule_labels`、PATCH で丸ごと置き換え・省けばそのまま・`{}` で外す、誤ったキーは `invalid` |
| `readyz_follows_the_startup_and_the_shutdown` | トークンなしで `starting`（503）→ ready（200）→ `draining`（503。ready に戻らない） |
| `sets_need_rules_write_within_the_allowed_ports` | `rules:read` のトークンは読めるが PUT / DELETE は 403、`allow_listen_ports` の外のルールは 403、`updated_by` はトークンの名前 |
| `sets_belong_to_their_token_and_old_ports_are_checked` | 組は作ったトークンのもの（ほかのトークンは大きな `generation` でも `403`、`admin` は変えられて `owner` は残る）、`allow_rulesets` の外の名前は `403`、2^53 を超える `generation` は `400`、変える前の待ち受けの範囲が `allow_listen_ports` の外なら `403`（セキュリティレビュー M2・M3） |

起動した rproxy が復元の後に `GET /readyz` で 200 を返すことは `tests/startup.rs` の `readyz_answers_once_started`。

## 結合テスト：GeoIP（`tests/geoip.rs`、#168）

mmdb はテストが作る（`tests/common/mmdb.rs`：IPv6 の木（IPv4 は ::/96）、32 ビットのレコード、文字列と整数の map だけの小さな書き手。MaxMind のデータベースは使わない・置かない）。loopback の送信元で国を分ける：127.0.0.1 は JP、127.0.0.2 は US（AS64496）、127.0.0.3 はデータベースにない。単体テスト（`net::geoip`）は判定の表、ファイルからの読み込み・壊れた版を飛ばす読み直し・起動時の誤り。

| テスト | 確かめること |
|---|---|
| `tcp_rules_refuse_by_country_and_asn` | `allow_countries` で JP は通り US は閉じる、分からないものは既定で通す。`conn.denied` の `reason: geoip`・`country`・`asn`、`log_country` の `conn.open` の `country`、`stats.denied`。PATCH で `deny_asns`・`unknown: deny` に変え、`{}` で外す |
| `udp_rules_drop_datagrams_by_country` | 断る国のデータグラムは捨て、セッションを作らない |
| `lists_need_the_databases` | `global.geoip` がない・国のデータベースだけのとき、国 / ASN のリスト（ルール・ミドルウェア）は `400 invalid` |
| `the_middleware_answers_403_for_the_client_trusted_proxies_name` | ミドルウェアは `403`。信頼するプロキシの `X-Forwarded-For` のクライアントで判定し、信頼しない送信元のものは見ない。`http.access` の `refused_by: geoip`・`country`・`asn` |
| `check_config_reads_the_databases` | `--check-config` はデータベースを読む。ない・mmdb でないファイルはエラー |

## 結合テスト：受け身のヘルスチェック（`tests/outlier.rs`、#170）

設定がないときの動き（1 回の失敗で 10 秒外す）は `tests/targets.rs`。単体テスト（`core::outlier`・`core::balance`）は既定値、倍にする外す時間、L7 のしきい値、`max_ejected_percent`、`short_lived`。

| テスト | 確かめること |
|---|---|
| `consecutive_failures_eject_a_target_for_a_while` | 3 回続けて断られたら外す（`stats.targets[]` の `up`・`ejections`・`ejected_until`、`target.down` の `reason: outlier`・`cause: connect`）。`ejection_time` の後に自然に戻る（`target.up`） |
| `short_lived_connections_count_as_failures` | 転送先がすぐ閉じる接続は `short_lived` で失敗（`cause: short_lived`）。クライアントが終えた接続は数えない |
| `max_ejected_percent_keeps_targets_and_patch_changes_it_in_place` | `max_ejected_percent: 0` は外さない。PATCH の `{}` で既定に戻る |
| `http_servers_that_keep_failing_are_ejected` | 500 を続けて返すサーバを外し、残りに送る（`stats.http.services` の `ejected`、`target.down` の `service`・`server`・`cause`） |
| `http_ejection_leaves_at_least_half_by_default` | 既定の `max_ejected_percent: 50` で、全部は外さない |

## 結合テスト：そのほか

ここまでの節にないテストのファイル（中身はファイルの先頭の説明とテストの名前を見る）。

| ファイル | 確かめること |
|---|---|
| `tests/check_config.rs` | `rproxy-api --check-config`（#140。ほかの人が読める鍵は誤り、`global.files.owner_check: off` なら通る）：起動・再読み込みと同じ道筋で設定ファイルを確かめ、何も開かず、終了コード・テキスト・JSON で答える |
| `tests/startup.rs` | 本物のバイナリの起動：設定の誤りは止まり、環境の問題（権限・使用中のポート）は制限つきで動き続けて、直れば戻る。制御 API の TLS と SIGHUP の読み直し、`GET /readyz` |
| `tests/targets.rs` | 複数の宛先（#98）：`targets`・`balance`（round_robin / least_conn / failover）・`backup`・`health_check`（L4 と `http` のサービス）。`outlier_detection` がないときの既定の動き。`connect_timeout`（v0.4.3。SYN を捨てる宛先） |
| `tests/listen.rs` | 1 つのルールの複数の待ち受けアドレス（`extra_listen_addrs`、#99）、まだホストにないアドレスでの待ち受け（`listen_freebind`、v0.4.3。実経路は `scripts/test-freebind.sh`） |
| `tests/udp_shards.rs` | UDP のポートを `SO_REUSEPORT` の複数のソケットで読む（#194）：セッションが二重にならない、返信の送信元（#137）、数の合計 |
| `tests/udp_source.rs` | ワイルドカードで待ち受ける UDP の返信が、クライアントが送った宛先のアドレスから出る（#137。127.0.0.2 宛て） |
| `tests/udp_sni.rs` | UDP の `tls.mode: sni`（#130）：本物の QUIC（quinn）・DTLS のクライアントと転送先 |
| `tests/http.rs` | `http` のルールの L7 のルーティング |
| `tests/http3.rs` | `http3: true` の HTTP/3（#56）、quinn + h3 のクライアント |
| `tests/http_auth.rs` | 認証のミドルウェア（#59）：`basic_auth`・`forward_auth`・`oidc` |
| `tests/http_resilience.rs` | ヘルスチェック・`sticky`・`compress`・`buffering`・`retry`・`circuit_breaker`・`errors`・転送先の接続の使い回し（#61・#63・#64・#65） |
| `tests/http_semantics.rs` | HTTP の転送の約束（docs/API.md の「HTTP の転送の扱い」）：HTTP/2 の転送先のストリームが埋まったときの 504 と接続の追加（セキュリティレビュー M6）。`client_auth` のない HTTPS のルールでクライアントの証明書のヘッダを HTTP/1.1・HTTP/2・HTTP/3 とも消す（セキュリティレビュー H1）。クッキー・繰り返しのフィールド・hop-by-hop・本文・大きなヘッダ・時間切れを HTTP/1.1・HTTP/2・HTTP/3 のクライアントで。HTTP/2 の転送先（#233）：h2c の 1 本の接続の多重化、トレーラーの両方向（gRPC の trailers-only の応答を含む）、`te: trailers`、h2（TLS + ALPN）・`auto`（`h2` / `http/1.1` のどちらを選ぶ転送先でも）・`h2` を選ばない転送先は 502、`protocol` と URL のスキームの組み合わせ |
| `tests/gateway_l7.rs` | Gateway API 向けの L7（#224・#226〜#232・#235）：`headers` の `add`、リダイレクトの `status`、ルートの `timeouts`（504、送信ごと、本文の途中で切る）、`replace_host`、転送先ごとのミドルウェア、`cors`（プリフライト・ワイルドカードのオリジン）、`retry` の `status`、`mirror`（割合・本文・つながらないミラー）、`status` の転送先、`features`。許さないオリジンのプリフライトに rproxy が答える・転送先が 1 つでも `retry` が送り直す、クライアント証明書の `X-Client-Verify`・`X-Forwarded-Client-Cert`（`optional_no_verify`、偽のヘッダは消す）（#238）。`client_auth` のない平文のルール・Upgrade・`forward_auth`・`mirror` でも証明書のヘッダを偽れない、`mirror` の写しの X-Forwarded-For（セキュリティレビュー H1・M5） |
| `tests/backend_tls.rs` | サービスの `tls`（#236）：サービスの CA・SNI の名前、`subject_alt_names`（DNS 名・URI）、転送先へのクライアント証明書、平文の HTTP のルールからの `https://` の転送先、形とファイルの誤り |
| `tests/crowdsec.rs` | `crowdsec` ミドルウェア（偽の LAPI と AppSec） |
| `tests/acme.rs` | ACME（#208）：API の守り（いつも動く）と、Pebble・PowerDNS で実際に証明書を取る（上の表） |
| `tests/traefik_convert.rs` | `contrib/traefik2rproxy.py` が `tests/fixtures/traefik/` を変換し、rproxy が受け付ける。python3 と PyYAML がなければスキップ（CI は `RPROXY_TEST_REQUIRE_PYTHON=1`） |

## DB からの復元（`tests/db_restore.rs`）

| テスト | 確かめること |
|---|---|
| `loads_every_schema_version` | `src_port_end` / `options` 列（`allow_from` を含む）を含む現在のテーブル（壊れた `options` の行は飛ばす）、その前のテーブル、`source_ip` / `udp_idle_secs` もない古いテーブルのどれからも読める |

## transparent の実経路（`scripts/test-transparent.sh`）

クライアント（10.0.1.2）・rproxy・転送先（10.0.2.2）をネットワーク名前空間で作り、転送先から見える送信元を確かめる。

| 組み合わせ | 期待する結果 |
|---|---|
| TCP / `proxy` | 転送先には rproxy の IP が見える |
| TCP / `transparent` | 転送先にはクライアントの IP とポートが見える |
| UDP / `proxy` | 転送先には rproxy の IP が見える |
| UDP / `transparent` | 転送先にはクライアントの IP とポートが見える |

## 性能の回帰（Benchmarks ワークフロー、#163）

`benches/` の criterion のベンチマーク。遅くなる変更に気付くためのもので、数字そのものに意味はない（同じマシンで比べたときだけ意味がある）。

| ベンチマーク | 測るもの |
|---|---|
| `benches/parse.rs` の `matcher/*` | L7 の `match` の評価（7 本のルートを順に見て最後に一致するリクエスト 1 件）と、7 本の式の解析（正規表現を含む） |
| `clienthello/*` | rustls が作る ClientHello（約 250 バイトと 3 KiB）からサーバ名を読む（`sni::parse_client_hello`） |
| `quic_initial/v1` / `v2` | RFC 9001 / 9369 の Initial（`tests/fixtures/quic`）から鍵を計算し、ヘッダの保護と AEAD を外してサーバ名を読む（`udp_sni::Sniffer`） |
| `benches/dataplane.rs` の `l4_tcp/*` | TCP の転送の 1 MiB の往復（スループット）と、新しい接続（接続 → 1 バイトの往復 → 切断） |
| `l4_udp/*` | UDP の 1 KiB の往復と、新しいセッション（毎回新しい送信元ポート） |
| `tls_terminate/*` | TLS の終端の新しい接続（再開なしの完全なハンドシェイク）と、終端した接続での 1 MiB の往復 |
| `l7_http1/request` / `l7_http2/*` | `http` のルール（ルート 4 本、`headers`・`strip_prefix` のミドルウェア）への HTTP/1.1 の keep-alive のリクエスト、HTTP/2（h2c）の 1 件ずつと 32 件同時 |

`dataplane` は `tests/` と同じハーネス（`tests/common`）で、制御 API からルールを作り、loopback で本物のクライアントと転送先をつなぐ。手元では `cargo bench --bench '*'`（全体で 1〜2 分）、一部だけなら `cargo bench --bench dataplane -- l7_http2`。変更の前後を比べるには、前で `-- --save-baseline before`、後で `-- --baseline before`。

`.github/workflows/bench.yml` が `src/`・`benches/`・`tests/common/`・`Cargo.*` を変えた PR で動く。ランナーは速さが揺れるので、同じジョブでマージベース（`--save-baseline base`）と PR（`--baseline-lenient base`）を続けて測り、`scripts/bench-summary.py` が表にしてジョブのサマリーと PR のコメント（1 件を更新する）に出す。平均が 15 % より遅くなり、95 % の信頼区間がすべて遅い側にあるものを警告にする（失敗にはしない。必須のチェックでもない）。警告が出たら、まずジョブを再実行して同じ結果になるか確かめる。

`dataplane` の 1 回の繰り返しが 30 秒進まないとき（`STALL`）は、ベンチマークが止まったものとして panic し、何をしていたか（書いた・読み戻したバイト数、TLS のクライアントが送っていないレコードを持っているか）とルールの統計を出す（#187）。ワークフローの各ステップにもタイムアウト（20 分）がある。TLS のストリームは `write_all` のあとに `flush` しないと、ソケットが詰まっていたときの最後のレコードが rustls に残る（#187 の止まった原因。クライアント側の問題で、rproxy のリレー（`l4::relay`）は読むものがないときに flush する）。

切り分け用に `examples/stall_probe.rs` がある（`bench.yml` の `stall-probe` ジョブ）。同じ 1 MiB の往復を 1 回 3 秒のタイムアウトで何百回も繰り返し、L4 の TCP・TLS の終端・rproxy を通さない TLS、クライアントの flush の有無、送信バッファ（既定・4 KiB）、rproxy を同じプロセスで動かすか別のプロセス（`--rproxy target/release/rproxy-api`）にするか、を並べて止まった回数と時間を表にする。#187 では、止まるのは flush しない TLS のクライアントだけで、rproxy を通さなくても、別のプロセスにしても同じように止まり、そのときクライアントの rustls は送っていないレコードを持っていた（`wants_write = true`）。flush するクライアントが止まったらジョブは失敗する。手元では `cargo run --release --example stall_probe -- --iters 300`。

## まだテストしていないこと

- 実際のメールクライアント（Thunderbird など）と、ブラウザの WebRTC（手動で確かめる：#42・#44）。実際のメールサーバ（Postfix / Dovecot）・TURN（coturn）・RTSP（MediaMTX）との組み合わせは Interop ワークフロー（下）で確かめている
- 数時間を超える連続転送（Load ワークフローの soak は手動で `soak_secs` を長くすれば回せる）
- iptables（`-m socket`）を使う transparent のルーティング手順

TLS を有効にした制御 API と、SIGHUP によるトークン・証明書の再読込は `tests/startup.rs`（`an_unreadable_api_certificate_is_retried`・`sighup_reloads_tokens_and_the_api_certificate_and_keeps_them_on_bad_files`）で確かめている。

## 実際のサーバとの組み合わせ（Interop ワークフロー）

`.github/workflows/interop.yml` が、実際のサーバを rproxy の後ろに置いて通す。時間がかかるので必須のチェックにはせず、`src/` や `scripts/interop/` を変えた PR、毎週、手動（Actions の画面から）で動かす。

| スクリプト | 相手 | 確かめること |
|---|---|---|
| `scripts/interop/mail.sh` | Postfix / Dovecot | STARTTLS の終端 + PROXY v2 で、Submission・SMTP（STARTTLS 任意）・IMAP・IMAPS・POP3 が通る。STARTTLS 前の送信・ログインを拒否する |
| `scripts/interop/media.sh` | coturn / MediaMTX | TURN の UDP・TCP の素通し、TLS の終端、DTLS の終端で、割り当てと中継ができる（中継アドレスは範囲ルール越し）。RTSP（TCP interleaved）と RTSPS の終端で映像を受け取れる。10000 ポートの UDP の範囲ルールを作って消す時間・ファイル数・メモリ |

| `scripts/interop/crowdsec.sh` | CrowdSec（LAPI・エージェント・AppSec） | rproxy のログから CrowdSec が検知して ban し、rproxy（L7 の `crowdsec`・L4 の `crowdsec: true`・AppSec）が止める。文書用アドレスのクライアント（IPv4・IPv6）は ban され、私用アドレスは whitelist で ban されない |

10000 ポートの範囲ルール（UDP）の結果（GitHub の Ubuntu ランナー、2026-09）: 作成 約 0.2 秒、ファイル記述子 +10000（削除で元に戻る）、RSS 約 +94 MiB。

どれも使い捨てのコンテナ（mail・media は `alpine:3.24`、crowdsec は CrowdSec の公式のイメージ）の中で root で動かし、サーバをスクリプトが設定して起動する。手元の機械では実行しない。

## 長時間の負荷テスト（Soak ワークフロー）

`scripts/soak.py` が rproxy-api（release ビルド）に TCP と UDP の負荷をかけ続け、10 秒ごとに RSS・fd の数・接続数を CSV に書く。

- TCP: 接続の開け閉めを繰り返すワーカー 200 と、つなぎっぱなしで送り続ける接続 20
- UDP: 送信元ポートを変えながら送る 100 クライアント（`udp_idle_secs: 5` でセッションの作成と破棄を繰り返す）
- 合格の条件: 負荷を止めた後に fd の数が元に戻る（+20 以内）、後半の RSS が前半の 1.5 倍を超えない、転送の失敗が 0.1% 以下

`.github/workflows/soak.yml` は必要なときだけ手動で動かす（定期の実行も PR での実行もしない）。Actions の画面か `gh workflow run soak.yml -f duration=<秒>` で時間（既定 3600 秒）を指定し、CSV は artifact に残る。手元では `cargo build --release && ulimit -n 65536 && scripts/soak.py --duration 600`。


## 負荷・soak のテスト（Load ワークフロー、#183）

試した改善とその結果（採用しなかったものを含む）は [PERFORMANCE.md](PERFORMANCE.md) に記録する。

大きな通信を何度も・長く流したときの転送効率（速さ、遅延、CPU 1 コアあたりの転送量、メモリ、FD、UDP の取りこぼし）を測る。カーネルでの高速化（#184）とメモリの削減（#185）の前後を比べるための基準の数字で、上の criterion のベンチマークより重く長い。数字はマシンで変わるので、同じマシン（ランナー）の前回と比べて見る。

`scripts/load/run.sh` がネットワーク名前空間を 3 つ作り、真ん中で `scripts/load/load.py` を動かす。

```
client 10.71.1.2 ── 10.71.1.1 [rproxy / HAProxy / ルータ] 10.71.2.1 ── 10.71.2.2 backend
```

- **direct**（基準）：プロキシなし。真ん中の名前空間のカーネルが転送するので、同じ veth と netem を通る
- **rproxy**：release ビルド。ログは `LOG_LEVEL`（既定 `warn`。接続ごとのログの重さを測りたいときは `info`）
- **haproxy**：入っていれば同じ条件で並べる（参考。UDP は対象外）
- `NETEM="delay 5ms loss 0.1%"` で、クライアント側の回線の両方向に tc netem をかける
- 送受信は `scripts/load/loadgen/`（std だけの小さなクレート。自分の `Cargo.toml`・`Cargo.lock`・workspace で、直下の build・test・deny には入らない）。大きな転送は擬似乱数のデータで、受け手が 1 バイトずつ送られるはずの中身と比べる（チェックサムより厳しい。抜け・重複・並べ替え・ずれがあれば失敗）

| シナリオ | 測るもの | 道具 |
|---|---|---|
| `tcp` | TCP の速さ（上り 1 本・8 本、下り 1 本） | iperf3 |
| `verify` | `SIZE_MIB` の転送を `REPEAT` 回、1 本と 4 本で。全バイトを転送先で確かめる | loadgen `send` / `sink` |
| `tls` | TLS 終端（`tls.mode: terminate`）への上り（全バイト確認）と、再開なしの新しいハンドシェイクの数 | socat、`openssl s_time` |
| `http` | L7 の小さなリクエスト（HTTP/1.1・h2c・TLS 上の HTTP/2。req/s、p50 / p99）と大きなダウンロード（全バイト確認） | h2load、curl |
| `udp` | 1400 バイトを `UDP_BW` で（取りこぼし・ジッタ）、64 バイトを最大の速さと `UDP_PPS` で 16 の送信元から（届いた pps、取りこぼし、rproxy の `stats.dropped`、カーネルの受信バッファあふれ） | iperf3、loadgen `udp-flood` / `udp-sink` |
| `latency` | 64 バイトの往復を 1 本と 64 本で（p50 / p99） | loadgen `rtt` |
| `churn` | 接続 → 1 KiB の往復 → 切断を 32 並列で（1 秒あたりの接続数） | loadgen `churn` |
| `memory` | 新しく起動したプロセスで：起動直後、ルール `RULES` 件（既定 100・1000）、待機中の接続 `CONNS` 本、転送中（4 KiB の往復）の接続、UDP のセッション `UDP_SESSIONS` 個。1 件・1 本・1 つあたりの RSS と FD | loadgen `hold` / `udp-hold` |
| `soak` | `SOAK_SECS` 秒、iperf3（`SOAK_BW`）・接続の開け閉め・送信元を変え続ける UDP を同時に。RSS・FD・CPU を記録（`soak.csv`） | |

表の値：

- **GiB / proxy CPU-s**：プロキシのプロセス（全スレッドのユーザー + システム時間）の CPU 1 秒あたりに運んだ量。**proxy cores** は使ったコアの数
- **GiB / system CPU-s**：マシン全体（クライアント・転送先・カーネルの転送・プロキシ）の CPU 1 秒あたり。direct と比べられる
- **vs direct**：同じ条件の direct に対する速さ（Gbit/s・req/s・pps・conns/s）の割合
- **peak RSS**：その間のプロキシの RSS の最大（L7 のリクエスト中のメモリもここに出る）

失敗（終了コード 1）にするのは確かめごとだけ：転送したデータが 1 バイトでも違う、シナリオが動かない、接続・セッションが張れない、接続を閉じた後に FD が戻らない、soak で FD が元（+20）に戻らない・RSS の後半 1/4 の平均が前半 1/4（最初の 1 割を除く）の 1.5 倍を超える・接続の失敗が 0.1 % を超える。遅くなったことは前回との差分（表の `(+x%)`。悪い向きに 10 % を超えると太字）で見る。

設定（環境変数）：

| 変数 | 既定 | 意味 |
|---|---|---|
| `SCENARIOS` | すべて | 動かすシナリオ（カンマ区切り） |
| `SIZE_MIB` / `REPEAT` | 1024 / 3 | 大きな転送 1 回の大きさと回数 |
| `DURATION` | 10 | 速さ・遅延を測る 1 回の秒数 |
| `CONNS` / `UDP_SESSIONS` / `RULES` | 2000 / 1000 / 100,1000 | `memory` の接続数・セッション数・ルール数 |
| `UDP_BW` / `UDP_PPS` | 1G / 50000 | `udp` の iperf3 の帯域と、64 バイトの決まった速さ |
| `H2_REQS` / `H2_CONNS` | 200000 / 64 | h2load のリクエスト数と接続数（HTTP/2 は接続あたり 10 本同時） |
| `SOAK_SECS` / `SOAK_BW` | 0（省く）/ 1G | soak の秒数と iperf3 の帯域 |
| `NETEM` | なし | tc netem の引数（例 `delay 5ms loss 0.1%`） |
| `HAPROXY` | auto | `0` で HAProxy を並べない |
| `BINS` | なし（`BIN`、既定 `target/release/rproxy-api`） | 並べて比べる rproxy のビルド（`ラベル=パス,ラベル=パス`。最初が基準） |
| `OUT` / `PREVIOUS` | `load-results` / なし | 結果の置き場所、比べる前回の `results.json` |

### 手元・VM で動かす

```bash
sudo apt-get install iperf3 nghttp2-client socat haproxy   # ないものは飛ばす（HAProxy は任意）
cargo build --release
cargo build --release --locked --manifest-path scripts/load/loadgen/Cargo.toml --target-dir target/loadgen
SIZE_MIB=256 REPEAT=1 DURATION=5 SOAK_SECS=60 scripts/load/run.sh      # root なし（ユーザー名前空間）
sudo -E env "PATH=$PATH" SOAK_SECS=3600 scripts/load/run.sh            # 開けるファイルの数・ソケットのバッファを上げられる
scripts/load/report.py load-results/results.json old/results.json      # 2 回の結果を比べる
```

root なしで動かすにはユーザー名前空間が要る（Ubuntu 24.04 以降は `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`）。netem には `sch_netem` のモジュールが要る（Ubuntu では `linux-modules-extra-$(uname -r)`）。結果は `load-results/` の `results.json`（すべての値）と `summary.md`（表）。

### CI

`.github/workflows/load.yml` は手動（Actions の画面か `gh workflow run load.yml`。大きさ・回数・秒数・接続数・soak の秒数・netem の条件・シナリオを指定できる）でだけ動かす。重く長いので定期や PR では動かさない（オーナーが頼んだときに回す）。必須のチェックでもない。

- `load (clean)`：netem なしで全シナリオ（既定 2 GiB × 3、接続 5000、soak 10 分）
- `load (netem)`：`delay 5ms loss 0.1%` で `tcp`・`verify`・`tls`・`http`・`udp`・`latency`（512 MiB）

ジョブは Alpine のコンテナ（musl。リリースのバイナリと同じ libc）で、rproxy も musl でビルドする。musl の malloc は glibc のより遅いので、結果の頭に各ビルドの libc とアロケータ（バイナリから読む）を書く。比べるのは libc とアロケータが同じもの同士にする（違えば「Builds compared」に注意を出す）。

結果は artifact（`load-clean` / `load-netem`、90 日）とジョブのサマリーに残す。前回の成功した手動の実行（master を先に、なければほかのブランチ）の artifact を取ってきて、差分を表に出す。ランナーは 4 コアの共有の VM なので、1 回だけの差は気にせず、続けて出る変化を見る。

### 高速化の案を比べる（`perf/<topic>` のブランチ）

高速化・メモリの削減の案は、案ごとに `perf/<topic>` のブランチ（例 `perf/splice`・`perf/ktls`・`perf/mimalloc`）にして、Load ワークフローで master と比べる。案が増えればブランチも増える。

```bash
gh workflow run load.yml -f refs=master,perf/splice,perf/sockmap
gh workflow run load.yml -f refs=master,perf/mimalloc -f scenarios=memory,soak -f soak_secs=1800
```

- `refs`（カンマ区切り。既定 `master`）の各 ref をそれぞれビルドし、同じランナーで同じシナリオを動かす。ランナーの揺れがどれにも同じように効くように、シナリオ（とその中の繰り返し）ごとに ref を順に回す（A, B, C, A, B, C, …）。rproxy はビルドごとに別のアドレス（10.71.1.11〜）で同時に起動しておき、測るものだけに流す（`memory`・`soak` はビルドごとに新しく起動する）
- `summary.md` の先頭に「Builds compared」：シナリオごとに ref ごとの列を並べ、最初の ref（基準）に対する差分を出す。JSON は全体の `results.json` と ref ごとの `results-<ref>.json`（`/` は `_`）
- ref が増えるほど時間がかかる（soak はビルドごと）。必要なシナリオだけを `scenarios` で選ぶ
- `profile: true`（#195）：`load (clean)` で HTTP の小さなリクエスト（HTTP/1.1・h2c・h2 over TLS）の間、rproxy を `perf record -g`（499 Hz）で記録し、artifact の `profile/` にフレームグラフ（`<ケース>-<ターゲット>.svg`）と重い関数の一覧（`.txt`、`perf report` の self と children）を残す。スタックを辿れるように、このジョブだけフレームポインタ（`-C force-frame-pointers=yes`）・シンボル・行の情報つきでビルドする（リリースは今までどおり strip）。記録の負荷もあるので、数字はふだんの実行と比べない（比べる計測は `profile` なしで別に回す）。手元では `PROFILE=1 FLAMEGRAPH=<brendangregg/FlameGraph のディレクトリ>`（`perf` が要る）
  ```bash
  gh workflow run load.yml --ref perf/h2-cpu -f refs=master,perf/h2-cpu -f scenarios=http -f profile=true
  ```
- ワークフローの手動実行は、既定のブランチ（master）にあるワークフローだけが Actions の画面・`gh workflow run` に出る。スクリプト（`scripts/load/`）は実行したブランチ（`--ref`。既定は master）のものを使う

`scripts/soak.py`（上の「長時間の負荷テスト」）は loopback で接続の開け閉めを中心にした soak（手動）で、そのまま残している。

## ファジング（Fuzz ワークフロー）

インターネットから届くものを自前で読んでいる部分を、[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)（libFuzzer）で確かめる（#162）。panic・範囲外の読み出し・止まらないループ・メモリの使い過ぎを探す。`fuzz/` は独立したクレート（自分の `Cargo.toml`・`Cargo.lock`・workspace）で、リポジトリの直下の `cargo build`・`cargo test`・`cargo deny` には入らない。

| ターゲット | 対象 | 入力の形 |
|---|---|---|
| `tls_client_hello` | `tls::sni`：TLS の ClientHello（レコード、ハンドシェイク、本体） | バイト列そのまま |
| `udp_sni` | `tls::udp_sni` の `Sniffer`：DTLS の ClientHello の断片と QUIC v1 / v2 の Initial | データグラムごとに 16 ビットの長さを前に付ける |
| `quic_initial` | 同じく QUIC。ファザーが選んだフレームを Initial の鍵で暗号化して渡す（AEAD の内側のフレームの解析と CRYPTO のつなぎ合わせまで届くように） | フラグ（v2）、DCID、（パケット番号、フレーム）の並び |
| `proxy_header` | `net::source`：PROXY protocol v1 / v2 のヘッダ。rproxy は書くだけなので、どんなアドレス・TLS の情報でも正しい形で、読み戻すと同じになることを確かめる | `arbitrary` |
| `matcher` | `l7::matcher`：`match` の式の解析と評価 | 式、続けて 1 行ずつホスト・パス・クエリ・メソッド・ヘッダ・クライアントの IP |
| `starttls` | `l4::starttls`：STARTTLS 前のクライアントとのやり取り、メールサーバの挨拶と EHLO の応答、平文での引き継ぎ | 先頭のバイト（プロトコル・STARTTLS 必須・1 回に読む量）、続けて相手が送るもの |
| `config` | `config::ConfigDoc::parse`（YAML / JSON）と、ルールごとの `RuleRequest::validate` | 先頭のバイト（偶数: YAML、奇数: JSON）、続けて文書 |
| `dns_response` | `acme::dnsq::parse_response`：DNS-01 で読む DNS の応答（CNAME・SOA・TXT、名前の圧縮とそのループ） | バイト列そのまま |
| `tsig_answer` | `acme::rfc2136::verify_answer`：RFC 2136 の UPDATE への応答の TSIG（署名のないもの・作ったものが通らないこと） | バイト列そのまま |

入力の種は `fuzz/seeds/<ターゲット>/`（`python3 fuzz/gen_seeds.py` で作り直せる。TLS の ClientHello は Python の ssl、QUIC は `tests/fixtures/quic` の RFC 9001 / 9369 の例、設定は `contrib/rproxy.example.yaml` と `docs/en/` の例）。

`.github/workflows/fuzz.yml` が、`src/` か `fuzz/` を変えた PR で各ターゲットを 60 秒、毎日 10 分動かす（必須のチェックではない）。CI は Alpine（musl）なので sanitizer なし（`--sanitizer none`。Rust の AddressSanitizer は glibc のターゲットにしかない）で、debug assertions（整数のあふれの検査）を有効にする。ターゲットのパーサーは unsafe のない Rust なので、範囲外へのアクセスは sanitizer がなくても境界の検査で panic になる。毎日の実行で育てたコーパスは Actions のキャッシュに残し、次の実行の種にする。落ちたら `fuzz-artifacts-*` の成果物に入力が残るので、`cargo +nightly fuzz run <ターゲット> <入力のファイル>` で再現し、直したらその入力を単体テストに足す。

手元では（nightly と C/C++ コンパイラが要る）：

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run matcher fuzz/corpus/matcher fuzz/seeds/matcher -- -max_total_time=60
```
