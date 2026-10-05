日本語: [TESTING.md](../TESTING.md)

# Test list (rproxy-api)

| How to run | Scope | CI job |
|---|---|---|
| `cargo test` | Unit tests (`src/`) and integration tests (`tests/`) | `test` |
| `RPROXY_TEST_DATABASE_URL=mysql://... cargo test --test db_restore` | Restoring from MariaDB. Skipped if the variable is not set | `test` (uses a MariaDB service container) |
| `scripts/test-transparent.sh` | The real path of `source_ip` (network namespaces; no root required) | `transparent` |
| `cargo bench --bench '*'` | Performance benchmarks (`benches/`, criterion). `cargo test` runs each benchmark once to check that it still works | `test` (once), `Benchmarks` (comparison) |

Integration tests open real sockets on loopback. The control API, the echo server used as the target, and the clients are all real; only name resolution is replaced (`tests/common/mod.rs`).

## Unit tests (`src/`)

| File | Test | What it checks |
|---|---|---|
| `core/rule.rs` | `protocol_is_case_insensitive` | `"TCP"` is also accepted, and `source_ip` defaults to `proxy` |
| | `defaults_udp_idle` | The default UDP idle timeout is 30 seconds |
| | `rejects_hostname_listen_and_zero_ports` | The listen address cannot be a hostname, and port 0 is not allowed |
| | `proxy_protocol_is_tcp_only` | `proxy_v2` on UDP is `unsupported` |
| | `transparent_needs_capability_and_ipv4` | `transparent` is rejected without the capability or with IPv6 |
| | `ipv6_remote_is_bracketed` | An IPv6 target takes the form `[::1]:80` |
| `core/resolve.rs` | `keeps_cached_answer_while_dns_is_down` | While name resolution fails, the previous result keeps being used |
| | `empty_answer_is_an_error` | An empty answer is `resolve_failed` |
| `control/auth.rs` | `rotates_tokens` | Multiple tokens valid at the same time, reloading, and keeping the current state on an invalid file |
| | `disabled_allows_all` | Without a token file there is no authentication |
| `net/source.rs` | `v1_header` / `v2_header_ipv4` / `v2_header_ipv6_length` | The bytes of the PROXY protocol headers |
| | `port_ranges` | Range validation (reversed order, exceeding the limit, target port exceeding 65535) |
| `tls/config.rs` | `wildcard_matches_one_label` | `*.example.com` matches exactly one level |
| | `validation_rules` | Rejects terminate without a certificate, sni on UDP, STARTTLS without terminate, and mTLS without a CA |
| | `missing_files_are_reported` | An unreadable certificate file is reported as `tls_config`, including the path |
| `tls/sni.rs` | `reads_server_name` / `needs_the_whole_record` / `handles_a_hello_split_across_records` / `rejects_plain_text` | Reads the server name from a ClientHello produced by rustls. Partial data, a ClientHello split across multiple records, and non-TLS data |
| `l4/starttls.rs` | `smtp_ehlo_then_starttls` / `imap_capability_and_starttls` / `pop3_capa_and_stls` / `quit_closes` | The pre-STARTTLS exchange for each protocol. Sending mail or logging in before TLS is refused |
| | `smtp_optional_tls_hands_over_plain_commands` | With `starttls_required: false`, plain-text commands are handed over to the target |
| | `data_before_the_handshake_is_refused` | Commands smuggled in right after STARTTLS are not accepted |
| | `ehlo_reply_loses_starttls` | `STARTTLS` is removed from the EHLO reply after TLS |
| `net/source.rs` | `v2_header_carries_tls_tlvs` | PROXY v2 TLVs (AUTHORITY, SSL, CN) and their lengths |
| `core/registry.rs` | `a_panicking_listener_marks_only_its_rule_failed` | When a listener panics, only that rule becomes `failed` |
| | `a_stale_supervisor_does_not_touch_a_recreated_rule` | A supervisor task from an old generation does not touch a recreated rule |

## Integration tests: control API (`tests/api.rs`)

| Test | What it checks |
|---|---|
| `tcp_lifecycle_stops_immediately_and_port_is_reusable` | Add → forward → stop within 1 second, existing connections are also closed, and the rule can be re-added on the same port |
| `update_retargets_new_tcp_connections_at_once` | Changes apply immediately to new connections, while existing connections keep the original target |
| `errors_use_the_api_format` | Duplicate 409, bind failure 409 (nothing left behind), invalid input 400, `proxy_v2` on UDP 400, resolution failure 502, 404 |
| `bearer_token_is_required_when_configured` | No token gives 401; `/healthz` needs no authentication |
| `udp_sessions_follow_updates_and_port_is_reusable` | Existing UDP sessions also switch to the new target, and the same port can be reused right after stopping |
| `udp_sessions_expire_after_idle_timeout` | Sessions are discarded after `udp_idle_secs` |
| `proxy_protocol_v2_header_carries_the_client` | The v2 header received by the target contains the client's address and port |
| `drain_waits_for_connections_to_finish` | Existing connections remain usable during `drain_secs`, and stopping completes once they close |
| `restore_retries_rules_whose_target_does_not_resolve_yet` | Rules whose target could not be resolved at restore become `failed`, and start automatically once it resolves |
| `dns_outage_keeps_forwarding_to_cached_address` | Forwarding to the cached target continues during a DNS outage |
| `metrics_and_capabilities` | Values in `/metrics` (connection count, byte count) and `/capabilities` |

## Integration tests: forwarding behavior (`tests/dataplane.rs`)

| Test | What it checks |
|---|---|
| `large_transfer_keeps_every_byte` | Data is not corrupted in a 16 MiB round trip |
| `many_concurrent_connections` | 200 concurrent connections all respond correctly |
| `half_close_lets_the_backend_answer_after_client_eof` | Even if the client closes only its sending side, it still receives the target's reply |
| `backend_closing_first_reaches_the_client` | When the target disconnects, EOF also reaches the client |
| `backend_down_closes_the_client_and_recovers` | When the target is down, the client is disconnected without waiting and the rule stays `running`. Forwarding resumes when the target comes back |
| `falls_back_to_the_next_resolved_address` | When name resolution returns multiple addresses and the first cannot be connected to, the next address is used |
| `udp_clients_do_not_see_each_others_replies` | Replies to 20 UDP clients do not get mixed up |
| `udp_large_datagram_is_forwarded_whole` / `udp_datagram_near_64k_is_forwarded_whole` | Large datagrams (up to 60,000 bytes) arrive without being split |
| `ipv6_listen_and_target` | Listening and forwarding over IPv6. Deletion works with a URL-encoded IPv6 key |
| `proxy_protocol_v1_header_carries_the_client` | The string of the v1 header received by the target |
| `concurrent_creates_of_the_same_rule_yield_one_winner` | Even if the same rule is added 10 times concurrently, only one succeeds |
| `a_silent_api_client_does_not_block_others` | A connection that sends nothing does not make other requests wait (regression test for a bug in the original implementation) |
| `small_writes_are_not_delayed_by_nagle` | A round trip of small writes sent in two pieces does not wait for a delayed ACK (~40 ms) in either direction (TCP_NODELAY on both hops, #176) |

## Integration tests: port ranges and TLS (`tests/tls.rs`)

The test CA, server certificates, and client certificates are generated on every run (`tests/common/pki.rs`).

| Test | What it checks |
|---|---|
| `tcp_port_range_maps_one_to_one` / `udp_port_range_maps_one_to_one` | Each port in the range reaches the corresponding port on the target. Deleting closes all ports |
| `overlapping_ranges_are_rejected` | Rules with overlapping ranges cannot be created (fine if the protocol differs) |
| `sni_routes_without_decrypting` | The target is chosen by SNI (including wildcards). TLS between the client and the target is established with the target's certificate (rproxy does not decrypt). Plain text is disconnected |
| `terminate_sends_plain_text_and_tls_details_in_proxy_v2` | The target receives plain text, and the PROXY v2 TLVs contain SNI and ALPN |
| `mtls_required_checks_client_certificates` | Only client certificates from the correct CA are accepted; failures are counted in `rproxy_tls_failures_total` |
| `terminate_can_re_encrypt_towards_the_backend` | Re-encrypts toward the target with TLS. Fails if the name on the target's certificate is wrong |
| `certificates_are_chosen_by_sni` | Chooses among multiple certificates by SNI |
| `bad_tls_settings_are_reported` | Rejects unreadable files, terminate without a certificate, unknown modes, and sni on UDP, leaving nothing behind |
| `reload_picks_up_renewed_certificates_and_patch_changes_tls` | After replacing the certificate files and reloading, the new certificate is used. PATCH can switch back to passthrough |

## Integration tests: multi-tier CA (`tests/chain.rs`)

Checked with both one intermediate CA (3 tiers) and two intermediate CAs (4 tiers). The client trusts only the root.

| Test | What it checks |
|---|---|
| `server_certificates_need_their_intermediates` | Without `chain_file` the client cannot verify; with it, it can |
| `a_full_chain_in_cert_file_still_works` | The legacy form with the chain concatenated into `cert_file` also works |
| `wrong_order_and_wrong_key_are_rejected` | A chain in reverse order and a key for a different certificate are rejected with `tls_config` |
| `mtls_with_multi_tier_client_certificates` | Even when `ca_file` contains only the root, clients that send the intermediate CA pass. Clients that send only their certificate pass if `client_auth.chain_file` is set, and fail otherwise. Certificates from a different PKI do not pass |
| `dtls_mtls_with_multi_tier_client_certificates` | The same rules apply to DTLS. Clients that cannot be verified are disconnected after the handshake without forwarding anything |

## Integration tests: access control and static rules (`tests/access.rs`)

| Test | What it checks |
|---|---|
| `allow_from_limits_tcp_clients_and_can_change_live` | TCP clients outside the range are disconnected (not counted as connections but counted as `denied`), and changing the range with PATCH takes effect immediately. An invalid CIDR is `invalid` |
| `allow_from_limits_udp_clients` | No session is created for UDP sources outside the range |
| `unmatched_names_are_rejected_when_asked` | With `terminate`, a name that is in the certificate but does not match any `routes` is disconnected without completing the handshake (not counted as a TLS failure). With `unmatched: default` it passes. `reject` without `routes` is `tls_config` |
| `sni_rules_reject_unmatched_names_before_forwarding` | With `sni` too, names that do not match are disconnected without forwarding |
| `static_rules_are_protected_from_the_api` | Static rules run with `origin: static`; PATCH / DELETE give `409 static`, and adding the same key gives `already_exists`. They stop on `shutdown` |
| `a_broken_static_file_starts_nothing` | If there are invalid rules or overlaps, nothing is started and an error is returned |

## Integration tests: STARTTLS (`tests/starttls.rs`)

| Test | What it checks |
|---|---|
| `smtp_starttls_is_terminated_by_rproxy` | Plain-text EHLO → STARTTLS → EHLO over TLS (STARTTLS disappears from the reply) → MAIL. Plain-text commands do not reach the target |
| `smtp_without_tls_is_allowed_when_not_required` | With `starttls_required: false`, plain text passes through and EHLO is handed over to the target |
| `imap_starttls_is_terminated_by_rproxy` | LOGIN before TLS is refused, and the password flows only over TLS |
| `pop3_stls_is_terminated_by_rproxy` | USER before TLS is refused, and after STLS commands reach the target |
| `starttls_needs_terminate` | `starttls` without `tls.mode: terminate` is `tls_config` |

## Integration tests: DTLS (`tests/dtls.rs`)

| Test | What it checks |
|---|---|
| `dtls_is_terminated_and_forwarded_as_plain_udp` | DTLS is terminated and plain UDP is sent to the target. Each client gets a separate session |
| `dtls_client_certificates_can_be_required` | Client certificates can be made mandatory |
| `dtls_can_be_re_encrypted_towards_the_backend` | Re-encrypts toward the target with DTLS |
| `dtls_needs_a_pkcs8_key` | A key that is not PKCS#8 is `tls_config` |

## Integration tests: data integrity (`tests/integrity.rs`, #134)

Streams tens of MiB of pseudo-random data (slices of a 1 MiB block at positions determined by the stream number and chunk number, so any reordering, duplication, or shift changes the hash) and compares SHA-256. The size is `RPROXY_TEST_INTEGRITY_MB` (default 32; `.github/workflows/integrity.yml` runs it weekly with 512).

| Test | What it checks |
|---|---|
| `tcp_streams_arrive_unchanged_on_every_path` | With TCP passthrough, `proxy_v2`, terminate, and `upstream.tls`, data sent in both directions over 4 concurrent connections arrives unchanged |
| `a_reset_is_passed_on_as_a_reset_and_a_close_as_a_close` | A reset from the target reaches the client, and a reset from the client reaches the target, as a reset (it does not look like a normal end). A FIN on one side is propagated as a half-close. Even with TLS terminated, a reset from the target does not end TLS cleanly |
| `udp_datagrams_arrive_unchanged_once_and_in_order` | Numbered datagrams (1 byte to 65,507 bytes) from 4 clients come back unchanged, exactly once each, and in order. `stats.dropped` is 0 |
| `dtls_records_arrive_unchanged_once_and_in_order` | The same with a rule that terminates DTLS |
| `http_bodies_arrive_unchanged_on_every_protocol` | HTTP/1.1, HTTP/2, and HTTP/3 downloads (`Content-Length` and chunked) and uploads (with length and chunked) are unchanged, even with 4 concurrent streams |
| `middlewares_keep_bodies_intact` | Unchanged through `compress` (decompressing gzip, br, and zstd restores the original), `buffering`, and `retry` (even when the first backend is down; the upload is an idempotent PUT) |
| `reused_backend_connections_never_mix_bodies` | Sending 48 requests concurrently over one HTTP/2 connection, then 16 sequentially, every response and request carries only its own body even when backend connections are reused |
| `websocket_streams_arrive_unchanged` | WebSocket (Upgrade) streams in both directions are unchanged |
| `a_response_cut_off_by_the_backend_never_looks_complete` | When the target cuts off in the middle of a response, HTTP/1.1, HTTP/2, and HTTP/3 clients see an error (truncated) (for `Content-Length`, chunked, and through `compress`) |
| `a_request_cut_off_by_the_client_never_reaches_the_backend_as_complete` | When the client cuts off in the middle of the body (HTTP/1.1 `Content-Length` and chunked truncation, HTTP/2 RST_STREAM, HTTP/3 reset), the target never receives it as a complete request |

## Restoring from the DB (`tests/db_restore.rs`)

| Test | What it checks |
|---|---|
| `loads_every_schema_version` | Can read from the current table including the `src_port_end` / `options` columns (including `allow_from`; rows with broken `options` are skipped), the previous table, and old tables that also lack `source_ip` / `udp_idle_secs` |

## Real path of transparent (`scripts/test-transparent.sh`)

Creates the client (10.0.1.2), rproxy, and the target (10.0.2.2) in network namespaces, and checks the source address seen by the target.

| Combination | Expected result |
|---|---|
| TCP / `proxy` | The target sees rproxy's IP |
| TCP / `transparent` | The target sees the client's IP and port |
| UDP / `proxy` | The target sees rproxy's IP |
| UDP / `transparent` | The target sees the client's IP and port |

## Performance regressions (Benchmarks workflow, #163)

Criterion benchmarks in `benches/`. They are there to notice changes that make things slower; the numbers themselves mean nothing (they are only meaningful compared on the same machine).

| Benchmark | What it measures |
|---|---|
| `matcher/*` in `benches/parse.rs` | Evaluating L7 `match` expressions (one request checked against 7 routes in turn, matching the last), and parsing the 7 expressions (regexes included) |
| `clienthello/*` | Reading the server name from a ClientHello made by rustls (about 250 bytes and 3 KiB; `sni::parse_client_hello`) |
| `quic_initial/v1` / `v2` | Deriving the keys, removing header protection and AEAD, and reading the server name from the RFC 9001 / 9369 Initial packets (`tests/fixtures/quic`, `udp_sni::Sniffer`) |
| `l4_tcp/*` in `benches/dataplane.rs` | A 1 MiB round trip through TCP forwarding (throughput), and new connections (connect → 1-byte round trip → close) |
| `l4_udp/*` | A 1 KiB UDP round trip, and new sessions (a new source port every time) |
| `tls_terminate/*` | New connections with TLS termination (full handshakes, no resumption), and a 1 MiB round trip on a terminated connection |
| `l7_http1/request` / `l7_http2/*` | Requests to an `http` rule (4 routes, `headers` and `strip_prefix` middlewares): HTTP/1.1 keep-alive, HTTP/2 (h2c) one at a time and 32 at once |

`dataplane` uses the same harness as `tests/` (`tests/common`): rules are created through the control API, and real clients and backends are connected over loopback. Locally: `cargo bench --bench '*'` (1–2 minutes in all), or only some with `cargo bench --bench dataplane -- l7_http2`. To compare before and after a change, use `-- --save-baseline before` before and `-- --baseline before` after.

`.github/workflows/bench.yml` runs on PRs that change `src/`, `benches/`, `tests/common/` or `Cargo.*`. Runners vary in speed, so the merge base (`--save-baseline base`) and the PR (`--baseline-lenient base`) are measured one after the other in the same job, and `scripts/bench-summary.py` puts a table in the job summary and in a PR comment (one comment, updated). A benchmark whose mean got more than 15 % slower, with the whole 95 % confidence interval on the slower side, becomes a warning (not a failure, and not a required check). On a warning, first re-run the job to see whether it happens again.

## Not yet tested

- Combinations with real mail servers (Postfix / Dovecot) and real WebRTC, TURN, and RTSP clients

- Long-running load (hours of continuous forwarding, memory growth)
- The control API with TLS enabled (checked manually, no automated test)
- Reloading tokens and certificates via SIGHUP (checked manually)
- The transparent routing procedure using iptables (`-m socket`)

## Combinations with real servers (Interop workflow)

`.github/workflows/interop.yml` puts real servers behind rproxy and runs traffic through them. Because it takes a long time, it is not a required check; it runs on PRs that change `src/` or `scripts/interop/`, weekly, and manually (from the Actions page).

| Script | Counterpart | What it checks |
|---|---|---|
| `scripts/interop/mail.sh` | Postfix / Dovecot | With STARTTLS termination + PROXY v2, Submission, SMTP (STARTTLS optional), IMAP, IMAPS, and POP3 work. Sending and logging in before STARTTLS are refused |
| `scripts/interop/media.sh` | coturn / MediaMTX | Allocation and relaying work with TURN UDP and TCP passthrough, TLS termination, and DTLS termination (the relay addresses go through a range rule). Video can be received via RTSP (TCP interleaved) and RTSPS termination. Time, file count, and memory to create and delete a 10000-port UDP range rule |

Results for a 10000-port range rule (UDP) (GitHub Ubuntu runner, 2026-09): creation about 0.2 seconds, file descriptors +10000 (back to the original after deletion), RSS about +94 MiB.

It installs packages with sudo, so do not run it locally.

## Long-running load test (Soak workflow)

`scripts/soak.py` keeps putting TCP and UDP load on rproxy-api (release build), and writes RSS, fd count, and connection count to a CSV every 10 seconds.

- TCP: 200 workers that repeatedly open and close connections, and 20 connections that stay open and keep sending
- UDP: 100 clients that send while changing their source port (with `udp_idle_secs: 5`, sessions are repeatedly created and discarded)
- Pass criteria: after the load stops, the fd count returns to the original (within +20), RSS in the second half does not exceed 1.5 times that of the first half, and forwarding failures are 0.1% or less

`.github/workflows/soak.yml` runs it for 30 minutes weekly and keeps the CSV as an artifact. To run it for hours, trigger it manually from the Actions page with `duration` (seconds). Locally: `cargo build --release && ulimit -n 65536 && scripts/soak.py --duration 600`.

