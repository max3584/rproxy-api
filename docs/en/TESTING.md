日本語: [TESTING.md](../TESTING.md)

# Test list (rproxy-api)

| How to run | Scope | CI job |
|---|---|---|
| `cargo test` | Unit tests (`src/`) and integration tests (`tests/`) | `test` |
| `RPROXY_TEST_DATABASE_URL=mysql://... cargo test --test db_restore --test persist` | Restoring from MariaDB (`forward_rules`), and storing API-created rules and restoring them across a restart (`rproxy_rules`, #144). Those parts are skipped if the variable is not set | `test` (runs Alpine's MariaDB in the same container) |
| `RPROXY_TEST_PEBBLE=… RPROXY_TEST_PDNS=… RPROXY_TEST_PDNS_SCHEMA=… RPROXY_TEST_SQLITE3=… cargo test --test acme` | ACME (docs/en/ACME.md): starts Pebble (the ACME test CA) and PowerDNS and obtains real certificates through HTTP-01, TLS-ALPN-01 and DNS-01 (the PowerDNS API, RFC 2136 (PowerDNS's DNS UPDATE, TSIG HMAC-SHA256 and SHA512), acme-dns (a small stand-in), CNAME delegation, generic REST). That part is skipped without the variables (the tests of the API's guards always run); `RPROXY_TEST_REQUIRE_ACME=1` turns the skip into a failure | `test` (Alpine's `pebble`, `pdns`, `pdns-backend-sqlite3`, `pdns-doc` and `sqlite` in the same container; `RPROXY_TEST_REQUIRE_ACME=1`) |
| `cargo test --test self_update` | Self-update (#174): fetching and verifying from a signed release mirror (HTTPS), swapping in with a handoff, the launcher (`launch`), rollback. The test of signatures made by the minisign tool is skipped without `minisign` (`RPROXY_TEST_REQUIRE_MINISIGN=1` makes skipping a failure) | `test` (Alpine's `minisign`; `RPROXY_TEST_REQUIRE_MINISIGN=1`) |
| `RPROXY_TEST_CRASH_ROUNDS=50 cargo test --test crash` | More rounds of the abnormal termination (SIGKILL) tests ("Abnormal termination" below; 3 each by default, the MariaDB ones only with `RPROXY_TEST_DATABASE_URL`) | Crash workflow (manual only) |
| `scripts/test-transparent.sh` | The real path of `source_ip` (network namespaces; no root required) | `transparent` |
| `scripts/test-freebind.sh` | The real path of `listen_freebind`: listening on addresses (VIPs) not on the host yet, which arrive once they are added; the same port on two VIPs (network namespaces; no root required) | `transparent` |
| `cargo bench --bench '*'` | Performance benchmarks (`benches/`, criterion). `cargo test` runs each benchmark once to check that it still works | `test` (once), `Benchmarks` (comparison) |
| `cargo +nightly fuzz run <target>` | Fuzzing the hand-written parsers (see "Fuzzing" below) | `fuzz` in the Fuzz workflow |
| `scripts/load/run.sh` | Load and soak tests with large, long transfers (transfer efficiency; see "Load and soak tests" below) | Load workflow (manual only) |

## CI environment

GitHub's runners are Ubuntu VMs only, so the jobs run inside Alpine containers (`container: alpine:3.24`: musl, the same libc as the release binaries and the .deb) (#191). Packages come from apk, Rust is rustup's stable (nightly for fuzzing).

| Workflow / job | Environment |
|---|---|
| CI `test` and `package`, Benchmarks, Integrity, Soak, Fuzz, Dependencies (cargo-deny), Milestone, Interop `build`, `mail` and `media` | `alpine:3.24` |
| CI `transparent` | `alpine:3.24` (privileged: namespaces, veth, nft / iptables) |
| Load | `alpine:3.24` (privileged: namespaces, veth, tc netem; `sch_netem` is loaded from the host's `/lib/modules`) |
| Interop `crowdsec` | `crowdsecurity/crowdsec` (CrowdSec's official image, Alpine-based; Alpine has no CrowdSec package), privileged |
| Cross build and Release `build` | `alpine:3.24`. x86_64 musl natively, the others cross-built with cargo-zigbuild (zig); gnu is linked against glibc 2.17 (`scripts/build-release.sh`) |
| Release `apt` and Cross build `apt (dry run)` | `debian:13-slim` (apt-ftparchive, which builds the apt repository, is a Debian tool) |
| CI `deb` and `install` | Directly on the runner VM (Ubuntu). They check installing the .deb, upgrading from an apt repository and purging, and install.sh (which requires systemd), so systemd has to run as PID 1, which a container cannot do. They build no Rust: they check the musl binary and .deb made by the `package` job (Alpine) |
| DPDK (`dpdk.yml`, #261) | Directly on the runner VM (Ubuntu). DPDK comes from Ubuntu's packages (`libdpdk-dev`); hugepages and `net_tap` (TAP devices) need the host kernel and sudo. See "The DPDK data plane" below |

Fuzzing runs without a sanitizer (Rust's AddressSanitizer exists only for glibc targets; see "Fuzzing" below).

To find a flaky test or check that it is fixed, run it many times in the manual Repeat workflow instead of on a developer's machine (`gh workflow run repeat.yml -f test=udp_sni -f times=100`, also `--ref <branch>` and `-f filter=<test name>`). It stops at the first failing run and prints its output and how many runs passed before it. `-f mariadb=true` starts MariaDB as the CI's test job does (Pebble and PowerDNS are not set up, so tests that need them skip themselves).

Integration tests open real sockets on loopback. The control API, the echo server used as the target, and the clients are all real; only name resolution is replaced (`tests/common/mod.rs`).

Log lines that SIEMs and CrowdSec read are collected inside the test process in the same JSON form as the binary writes and checked (`tests/common/logs.rs`: `logs::capture()`, then `logs::wait_for` picking the test's own lines by rule or path): UDP `conn.denied` and its thinning out (`tests/access.rs`), `conn.denied` of the L4 `crowdsec` and `refused_by` in `http.access` (`tests/crowdsec.rs`), 401 / 403 and change `audit` lines of the control API (`tests/api.rs`), `token.expiring` / `token.expired` (`tests/api_hardening.rs`), `refused_by`, `user` and `auth_error` in `http.access` (`tests/http.rs`, `tests/http_auth.rs`).

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
| | `refresh_reads_changed_files` | #253: only a changed file (rewritten in place, or a symbolic link swapped as in a Secret volume) is read again. A version with a mistake keeps the current tokens and is tried once. After SIGHUP the same version is not read again. The lockout state stays |
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
| | `ehlo_reply_with_non_utf8_bytes_does_not_panic` | Non-UTF-8 bytes or multi-byte characters in the mail server's EHLO reply do not cause a panic (an input found by fuzzing, #162) |
| `net/source.rs` | `v2_header_carries_tls_tlvs` | PROXY v2 TLVs (AUTHORITY, SSL, CN) and their lengths |
| `net/proxy_in.rs` | `reads_back_what_rproxy_writes` / `every_prefix_asks_for_more` / `other_protocols_are_not_headers` | Received PROXY headers (#296): the v1 / v2 headers rproxy writes (with TLVs) read back, a partial one waits for more, other protocols are not headers |
| | `v1_unknown_and_bad_lines` / `v2_local_unspec_and_limits` | v1 `UNKNOWN`, broken lines and the 107-byte limit; v2 `LOCAL`, `AF_UNSPEC`, `AF_UNIX`, `DGRAM` and the 4096-byte limit (refused before the bytes arrive) |
| | `read_consumes_just_the_header` / `read_without_a_header` / `read_gives_up_on_a_slow_header` / `untrusted_headers_are_seen` | A header in pieces is waited for and exactly it is read; with and without `required`; timeouts; headers from outside `from` are seen (waiting and not) |
| | `validation` | `from` is required, empty or `/0` is `invalid`, `udp` is `unsupported`, `required` defaults to true |
| `core/registry.rs` | `a_panicking_listener_marks_only_its_rule_failed` | When a listener panics, only that rule becomes `failed` |
| | `a_stale_supervisor_does_not_touch_a_recreated_rule` | A supervisor task from an old generation does not touch a recreated rule |
| `core/ruleset.rs` | `etags_follow_the_rules_and_the_generation` | The etag does not depend on the order of the rules and changes with the rules or the generation. How `If-Match` may be written (quoted, `W/`, a list, `*`) |
| | `last_transition_moves_only_when_the_status_changes` | `last_transition` moves only when `status` changes (not for a new `reason` alone); deleting starts it over |
| | `conditions_from_the_view` | The status and reason of the four `conditions` from the state and the error's `code` |
| | `label_metrics_lines` | `rproxy_rule_labels` lines (names, keys that end up the same, escaped values) |
| | `readiness_states` | `starting` → ready → `draining` (never ready again) |
| `config/persist.rs` | `reconcile_leaves_rules_whose_row_is_not_up_to_date` | Rules taken over from a live upgrade with `persisted: false` (no row, an older row) and a row that could not be deleted: the check neither deletes, puts the row back nor creates, and writes them once the database is back. From then on the rows win |
| | `reconcile_does_not_hold_up_changes_while_it_writes_again` | While the check writes again (slow writes), an API change gets `changing` at once |
| | `reconcile_counts_an_invalid_row_once` | A row that does not make a rule is not counted as `created` every round; once the row is right the rule starts |
| | `a_late_removal_spares_a_newer_rule_with_the_key` | A late deletion of an older rule's row spares the row and `persisted` of a newer `api` rule with the same key |
| | `a_write_on_its_way_is_not_undone` | The check does not delete a rule whose write is under way (recorded as such) |
| | `a_write_that_went_through_ends_a_busy_episode` | A write that went through counts as holding the lock and resets `busy_since` (a later `persist.duplicate_node` does not come early) |
| | `release_does_not_wait_for_ever` | `release` of a store that was not frozen (after a live upgrade it always is, #305) waits for a change under way only up to its bound before it lets go of the lock |
| | `pending_writes_read_back` | What a live upgrade hands over of the writes not done (`Pending`) reads back; an empty one from an older process reads too |
| | `the_startup_refuses_only_a_holder_shown_live` | The startup's next step after looking at the lock's holder (`after_looks`, #307): a holder idle for longer than `LIVE_IDLE` at the first look lets it go on, a holder that pinged in between (also while it restores) is refused, one idle all along lets it go on. When a long write ended in between on MySQL (a statement, then briefly idle) it is not refused: it waits `DUPLICATE_LOOK_AGAIN` and looks again, going on if the holder stayed idle, refusing if it pinged, and not refusing if it still cannot tell |
| `config/persist/queue.rs` | `a_holder_is_live_when_it_ran_statements_in_between` | Two looks at the lock's holder: it is live when it sent a statement in between (its `TIME` went back, or a statement started), when another connection holds the lock now or when it cannot be seen; not live when it stayed idle or ran one statement all along |
| | `a_statement_that_ended_in_between_is_no_proof_of_life` | A statement at the first look and briefly idle at the second (a dead host's long write ending on MySQL, #307): not taken for live but `Unsure` (idle for `LIVE_IDLE` or longer: not live). At a third look it is not live if it stayed idle, live if it pinged |
| `control/upgrade/update.rs` | `cached_releases_are_verified_again` | (among others) the trial of a version that was not handed over to is taken back by `end_trial`, not marked bad; another version's trial is left alone |

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
| `terminate_does_not_stall_under_backpressure` | With a small client send buffer, 16 round trips of 1 MiB through a terminating rule; every byte comes back intact each time (#187) |
| `optional_no_verify_lets_any_client_certificate_in` | `client_auth.mode: optional_no_verify` (#238): clients with a certificate of the right CA, another CA, or none all get in (with and without `ca_file`). `optional` without `ca_file` is `tls_config`. `features.client_auth_modes` |
| `a_tls_route_spreads_over_several_targets` | `targets` of `tls.routes` (#234): spread by weight, a target that cannot be connected to is skipped; `balance: failover`. `remote_addr` with `targets`, neither, or `balance` without `targets` is `tls_config` |
| `files_others_may_write_or_read_are_refused` | A rule's key readable by others or a certificate writable by the group is `400 tls_config` (with the reason); a 0644 certificate and a 0640 key are fine (`global.files.owner_check`) |

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
| `http2_backends_and_mirrors_keep_bodies_intact` | Downloads and uploads with an h2c backend (`protocol: h2c`, #233), and uploads through `mirror` (#232), arrive unchanged from HTTP/1.1, HTTP/2 and HTTP/3 clients |
| `http2_backend_cut_offs_and_route_timeouts_never_look_complete` | An h2c backend cutting off a response, and a route's `timeouts.request` / `backend_request` (#227) running out in the middle of a response body, look like errors to every client |

## Integration tests: the TCP relay (`tests/relay.rs`, #185)

`l4::relay` borrows each direction's buffer from a per-thread pool only while it has data to pass on. The number of lent buffers (`l4::relay::buffers_in_use`) is process-wide, so the test is a single function.

| Test | What it checks |
|---|---|
| `relay_buffers_and_half_closes` | Connections whose data has passed (50 plain, 20 with TLS terminated) hold no buffer (and still work afterwards). A connection stuck on a backend that does not read holds one, and gives it back when it ends. When the backend sends its FIN first (plain and TLS termination) or the client ends first (TLS termination), it is passed on as a half-close and the data of the other direction all arrives |

## Integration tests: L4 limits and bandwidth (`tests/limits.rs`, #165, #166)

| Test | What it checks |
|---|---|
| `capabilities_say_limits_and_bandwidth_run` | `features.limits` and `features.bandwidth` are true |
| `tcp_connections_are_limited_per_source_and_per_rule` | A TCP connection over the per-source or the rule's concurrent connections is closed without anything sent (`stats.limited`, `reason` in `rproxy_rule_limited_total`). A closed connection frees its place. A `PATCH` of the limits keeps counting the open connections; `{}` removes them. `stats.counters_since`, `rproxy_process_start_time_seconds` |
| `tcp_new_connections_are_a_rate` | The rate of new connections (`new_connections`) |
| `http_rules_limit_their_connections` | On `http` rules they apply to the TCP connections |
| `udp_sessions_and_datagrams_are_limited` | The number of UDP sessions and the per-source datagram rate (`packets`). Datagrams over them are dropped and make no session |
| `tcp_bandwidth_waits_and_applies_to_open_connections` | A download limit added by `PATCH` slows a connection already moving a bulk transfer with splice (1 MB/s), without losing a byte; removed, it is fast again |
| `tcp_upload_per_source_waits` | A per-source upload limit makes the client's writes wait |
| `http_rules_are_shaped` | Responses of an `http` rule are shaped by the download limit |
| `udp_bandwidth_drops_over_the_rate` | UDP datagrams over the download limit are dropped and counted in `stats.dropped` and `rproxy_rule_bandwidth_dropped_total` (the upload is untouched) |

## Integration tests: receiving PROXY protocol (`tests/proxy_protocol.rs`, #296)

Every connection comes from 127.0.0.1, so `from: ["127.0.0.1/32"]` makes the test the front end, and another range makes it a peer outside `from`.

| Test | What it checks |
|---|---|
| `the_shape_validation_and_capabilities` | `features.proxy_protocol_in`; the listed shape (with `required`); PATCH replaces, keeps when left out, `{}` removes; an empty or missing `from`, `/0` and a broken address are `invalid`; `udp` can be created too (#312) |
| `allow_from_judges_the_client_in_the_header` | `allow_from` judges the header's client (v1 and v2). The header does not reach the backend |
| `required_refuses_a_connection_without_a_header` | With `required` (the default) a connection without a header is refused; with `false` it goes on with the peer's address. A broken header is refused either way |
| `a_header_from_outside_from_is_refused` | Headers (v1, v2) from outside `from` are refused (`conn.denied` with `reason: proxy_protocol_untrusted`); connections without one go through. On a TLS `sni` rule a header arriving late is waited for and found |
| `proxy_v2_out_carries_the_client_of_the_header` | `source_ip: proxy_v2` writes the header's client to the backend (v1 in, v2 out); `client` and `proxy_peer` of `conn.open`; `LOCAL` keeps the peer's address |
| `per_source_limits_count_the_client_of_the_header` | Per-source `limits` count per client of the header (another client behind the same front end gets through) |
| `http_rules_forward_the_client_of_the_header` | `X-Forwarded-For` / `X-Real-IP` of an `http` rule and `client` of `http.access` are the header's client, `proxy_peer` the front end |

## Integration tests: receiving PROXY protocol over UDP (`tests/proxy_protocol_udp.rs`, #312)

Every datagram comes from 127.0.0.1, so `from: ["127.0.0.1/32"]` makes the test (or an outer rproxy rule) the front end. Nothing is read once right after a change: replies and counters are waited for.

| Test | What it checks |
|---|---|
| `the_shape_validation_and_patch_in_place` | `features.proxy_protocol_in_udp`. Added with PATCH, the same socket's next datagrams have their header read and stripped (the rule stays `running`), `required` drops datagrams without one, and after `{}` headers are data again. An empty or missing `from`, `/0` and a broken address are `invalid` (create and PATCH) |
| `two_hops_keep_the_client` | Outer rproxy (`source_ip: proxy_v2`), inner rproxy (`proxy_protocol`, `source_ip: proxy_v2`), a backend that reads the header: the backend sees the original client, and replies reach the client through both hops without headers. A session per client; `client` and `proxy_peer` of the inner `conn.open` |
| `allow_from_required_and_bad_headers` | `allow_from` judges the header's client; `required` drops datagrams without one (`reason: proxy_protocol`). With `required: false` those pass, while v1, STREAM and cut-short headers are dropped (`stats.denied`) |
| `a_header_from_outside_from_is_dropped` | Headers (v1, v2) from outside `from` are dropped (`reason: proxy_protocol_untrusted`, `client` is the front end); datagrams without one pass |
| `per_source_limits_count_the_client_of_the_header` | Per-source `limits` count the header's client; another client in the headers of the same front end socket is another session |
| `sni_reads_the_name_past_the_header` | A `tls.mode: sni` rule behind an outer rproxy reads the QUIC server name past the header (real quinn), starts over for a connection to another name from the same socket, and a route's `source_ip: proxy_v2` writes the header's client and the inner rule's address |
| `dtls_is_terminated_past_the_header` | On a `tls.mode: terminate` (DTLS) rule, the handshake and data go through with a client that puts a header in front of every datagram; replies carry none, and the backend (`source_ip: proxy_v2`) and `client` of `conn.open` see the header's client, `proxy_peer` the front end |

## Integration tests: `source_ip` per route (`tests/route_source_ip.rs`, #297)

The backends are sockets that only record what they receive: whether a PROXY header comes, what it says, and that the ClientHello (QUIC: the Initial) follows.

| Test | What it checks |
|---|---|
| `a_passthrough_route_of_an_http_rule_sends_proxy_v2_and_l7_does_not` | On one port's `http` rule, the backend of a passthrough route with `source_ip: proxy_v2` gets a v2 header with the client's address; the HTTP to the L7 service gets none |
| `a_passthrough_route_passes_on_the_client_of_an_incoming_proxy_header` | On connections received with `proxy_protocol` (#296), a route's `proxy_v1` header names the header's client |
| `routes_of_an_sni_rule_override_the_rules_source_ip` | On an `sni` rule (the rule has `proxy_v2`): a route's `proxy` (no header) and `proxy_v1`; routes without one and unmatched names use the rule's. A PATCH of a route's value is `in_place` (dry run) and applies from the next connection |
| `a_udp_sni_route_sends_proxy_v2_datagrams` | On a `udp` `sni` rule (QUIC), only the datagrams of the `proxy_v2` route carry the DGRAM header |
| `route_source_ip_is_validated_and_advertised` | `features.route_source_ip`. A terminated route, `transparent` on a route and `proxy_v1` on a `udp` route are `unsupported`; an unknown value is a 4xx |

## Integration tests: v0.4 shapes (`tests/v04_shapes.rs`, #215)

Checks the shapes of the v0.4 settings (docs/en/DESIGN-v0.4.md) as a whole. In v0.4.0 every item runs (all `features` flags are true), so what remains here is the `features` list, the scopes of the new endpoints, the validation by `--check-config` and of the startup flags, and that a 0.3 settings file still passes. That each feature works is checked by its own tests (`tests/api_hardening.rs`, `rulesets.rs`, `limits.rs`, `geoip.rs`, `outlier.rs`, `plan.rs`, `persist.rs`, `handoff.rs`, `self_update.rs`, `performance.rs`).

| Test | What it checks |
|---|---|
| `capabilities_list_every_v0_4_feature_as_on` | Every v0.4 flag in `features` is true (`client_cert_auth`, `token_expiry`, `api_lockout`, `rulesets`, `labels`, `conditions`, `readyz`, `geoip`, `outlier_detection`, `limits`, `bandwidth`, `dry_run`, `persistence`, `handoff`, `self_update`; the `geoip` middleware and services' `outlier_detection`) |
| `upgrade_and_update_endpoints_answer`, `performance_keys_are_all_applied` | Implemented #174 and performance: `handoff` and `self_update` are true, `build`, the `/admin/*` answers of a router built as a library (Unix socket only; `GET /admin/update` is `mode: off`), `features.performance` lists every key |
| `new_endpoints_need_their_scopes` | Scopes of the new endpoints and the Unix-socket-only rule |
| `check_config_validates_the_v0_4_shapes`, `a_0_3_settings_file_still_passes` | `--check-config` reports wrong v0.4 shapes as errors; every v0.4 setting runs, so nothing is warned about. A 0.3 settings file passes without warnings |
| `v0_4_flags_are_checked_at_startup` | Wrong flags / environment variables (`--tls-client-auth` without a CA, `--tls-client-ca` without `--tls-cert`, `--token-warn-days 0`, ...) stop the startup |

## Integration tests: control API hardening (`tests/api_hardening.rs`, #167)

| Test | What it checks |
|---|---|
| `client_certificates_authenticate_alone_or_bound_to_a_token` | With the TLS of main.rs (`ClientCertAcceptor`) in `optional` mode, a certificate-only entry authenticates by the certificate (SAN, else CN) with its scopes. An unknown name or no certificate is 401; tokens work without a certificate. A token bound to a certificate is 401 without it. A certificate from another CA fails the handshake. `required` refuses connections without a certificate |
| `failing_sources_are_locked_out_over_tcp_but_not_the_unix_socket` | A source reaching the limit of 401s in the window gets `429 locked_out` (`Retry-After`) even with a good token. Failures over the Unix socket are not counted, and the Unix socket works while locked out. `/healthz` is never refused. `rproxy_api_lockouts_total` and `rproxy_api_locked_sources` in `/metrics`. It recovers when the time is up |
| `verified_certificates_and_exempt_sources_are_not_locked_out` | A verified client certificate gets in from a locked-out address; `--api-lockout-exempt` sources are neither counted nor locked out; a malformed value stops the startup (security review M4) |
| `lockout_is_on_by_default` | By default (owner's decision) the 20th failure locks out |
| `expiring_tokens_are_reported_and_exported` | A token close to expiry gives `token.expiring` (`days_left`), an expired one `token.expired`, once per change. `rproxy_token_expiry_timestamp_seconds` in `/metrics` |
| `the_binary_serves_client_certificates` | The real binary: a token file with `client_cert` and no `--tls-client-auth` stops the startup; with `required`, `/rules` is read with the certificate alone and connections without one are refused |
| `the_binary_reads_a_changed_token_file_without_sighup` | #253: the real binary (`RPROXY_TOKENS_CHECK_SECS=1`) re-reads the token file without SIGHUP. A token added in place works; after a `..data` link swap as in a Secret volume the new token works and removed ones get 401. A version with a mistake keeps the current tokens with one warning. No token appears in the log. `features.tokens_reload` |

## Integration tests: live upgrades (`tests/handoff.rs`, #174)

Starts the real binary and hands over with SIGUSR2 and `POST /admin/upgrade` (docs/en/UPGRADE.md).

| Test | What it checks |
|---|---|
| `tcp_connections_survive_and_new_ones_go_to_the_new_process` | TCP connections opened before the handoff (a static rule and an API rule) are carried by the old process to the end. New connections after it are the new process's (the owner of the server-side socket is found in `/proc`). UDP goes on in a new session. API rules (`targets`, `allow_from`) carry over, as do the control API's TCP and Unix sockets. `rproxy_process_start_time_seconds` stays. The old process exits cleanly once its connections end; counters never go down and what the old process counted while it drained is added (exact connection and byte counts). A second handoff through `POST /admin/upgrade` on the Unix socket. A plain stop at the end removes the socket file |
| `api_rules_and_http_counters_carry_over` | Rules of a `persist: true` token come back as `origin: "api"` with `created_by`, `created_at` and `persisted`, without reading the database. `stats.http` by route carries over and keeps counting |
| `a_failed_handoff_keeps_the_old_process` | When the new process cannot connect (the handoff socket's directory is missing): `handoff.failed`, and the old process keeps running. `rproxy_handoffs_total{outcome="failed"}`, `rproxy_build_info`. `POST /admin/upgrade` over TCP is 403 by default |

## Integration tests: the snapshot of a live upgrade and changes (`tests/handoff_freeze.rs`, #305, v0.4.15)

In-process, with a memory store and two registries (the old process, and the new one started from the snapshot; both see the same rows). A handoff in progress (`handoff::set_active`) is process-wide, so the tests of this file run one at a time.

| Test | What it checks |
|---|---|
| `changes_around_the_snapshot_are_in_it_or_refused` | A live upgrade starts while a change's write is under way, and more changes to the same rule come right around the snapshot and after it: the snapshot (`handoff::prepare`) waits for the change under way, later changes (rules and rule sets) get `503 upgrading` without changing anything. The old process does not change after the snapshot; the new process runs the last answered change, and its row matches (`persisted: true`). Changes after the snapshot used to run in the old process only |
| `a_change_that_does_not_end_in_time_stops_the_handoff` | A change that does not end within the wait (a slow write): the handoff does not happen (`prepare` fails) and the change runs to its end in the old process with `persisted: true` (`release` used to give up at its bound, and the change was in the old process only and not written) |
| `after_a_failed_handoff_the_waiting_changes_go_on` | The handoff failed after the snapshot: changes that waited meanwhile go on (not refused) and are written |
| `a_handoff_that_panics_lets_the_changes_go_on` | The handoff task panics after the snapshot: dropping `handoff::Running` clears the handoff mark and lets go of the lock, so the change that waited does not hang (nor get 503) but goes on and is written, and the self-update is told the handoff did not happen (`set_on_abort`: it takes back its trial) |
| `invalid_rules_and_owners_carry_over` | #327, #323: restored rules that do not validate (`api`, `dynamic`) go over as their stored bodies, not in the snapshot's `rules`; they are `failed` in the new process too (with `created_by`) and a PATCH fixes them; who created each rule goes over too |

## Integration tests: shutting down on SIGTERM (`tests/shutdown.rs`, v0.4.1)

Sends SIGTERM to the real binary (section 2 of docs/en/DESIGN-v0.4.x.md, `RPROXY_SHUTDOWN_DELAY` / `_DRAIN`).

| Test | What it checks |
|---|---|
| `by_default_sigterm_stops_at_once` | By default (both `0s`) it stops at once and cuts current connections (as before). `features.graceful_shutdown` |
| `delay_keeps_accepting_then_drain_lets_connections_end` | During `delay`: `/readyz` is 503, `GET /rules` answers, `POST /rules` is `503 shutting_down`, new TCP connections pass. During `drain`: new TCP connections are refused, existing TCP connections and UDP sessions go on, no new UDP session is made. An idle HTTP/1.1 connection is closed and the response of a request in flight carries `Connection: close`. Past `drain` the rest is cut and the process exits (`cut` in `shutdown.done`) |
| `a_second_sigterm_stops_at_once` | A second SIGTERM during `delay` stops at once (`shutdown.now`) |
| `a_second_sigterm_cuts_the_drain_short` | A second SIGTERM during `drain` stops waiting and cuts the connections left |
| `values_out_of_range_stop_the_startup` | A value above one hour stops the startup |

## Integration tests: certificate API (`tests/cert_api.rs`, #240, v0.4.2)

| Test | What it checks |
|---|---|
| `store_use_replace_and_delete` | `PUT /certs/{name}` answers 201 with an `ETag` (the fingerprint); files are 0600 and directories 0700. A rule with `{"cert": name}` terminates TLS with it (passing the owner check). A mismatching `If-Match` is 412; replacing it (200) keeps open connections and new ones get the new certificate; the old version is removed. `DELETE` while in use is `409 in_use` (`used_by`), 204 once unused. Audit lines have the name and fingerprint, never the key. `features.cert_store` |
| `bad_certificates_and_names_are_refused` | Unreadable PEM, a mismatching key, expired, no key, unknown fields and bad names are `400 invalid` (no key in the answer); a body above 1 MiB is 413; expiring soon gives `warnings`. A rule naming a certificate that is not stored is `400 tls_config`; `cert` with `cert_file` is a mistake |
| `a_failed_rule_starts_once_its_certificate_is_stored` | A settings-file rule naming a certificate not stored is `failed`, and starts once the name is `PUT` |
| `scopes_and_allow_certs` | The `certs:read` / `certs:write` scopes; names outside `allow_certs` are 403 for `PUT` and in rules; `GET /certs` lists only names within `allow_certs` |
| `rule_files_may_not_reach_the_store` | #319: a rule from the API naming a file under the store (itself, through a symbolic link, through `..`, a name stored later) gets `403 protected_file` (dry runs, PATCH, a rule set PUT, a service's `ca_file` too), and the token file the same. Other places are fine. An `allow_certs` token names no file: `403 file_not_allowed` (`{"cert"}` is fine). A settings file rule runs with the store's files. A restored rule runs with `rule.protected_file` (no path); a PATCH of only its targets is 403. Refusals of `PUT /rulesets` are audited. `features.protected_files` |
| `key_files_keep_to_their_owner` | #323: another token naming the key of a rule (itself, a hard link, a symbolic link, `..`, a dry run) gets `409 file_in_use` (the error says nothing of the other rule); the same certificate with a copy of the key passes; the same token and `admin` pass; a PATCH adding it to an own rule is refused, one of the targets only passes; keys of another token's rule set, of the settings file and of a restored rule without a known creator are refused, the set owner's PUT passes; a share from before runs, said by `rule.shared_file` (no path) |

## Integration tests: storing rule sets (`tests/ruleset_persist.rs`, #241, v0.4.2)

| Test | What it checks |
|---|---|
| `persist_tokens_store_their_sets` | A set of a `persist: true` token is stored as one row (`generation`, `etag`, owner, rules), and the answer, `GET /rulesets` and `GET /rulesets/{name}` show `persisted`. Dry runs and sets of tokens without `persist` are not written. A stored set changed by an `admin` updates its row (the owner stays). A failing write gives `persisted: false`. `DELETE` removes the row. `features.ruleset_persistence` |
| `a_set_draining_holds_up_neither_other_sets_nor_the_release` | While `DELETE /rulesets/a?drain_secs` drains, a `PUT` of another set does not wait and is written (`persisted: true`), and a live upgrade's `release` ends at once |
| `stored_sets_are_restored` | A stored set comes back with its `generation`, `etag` and owner. Only a rule whose key overlaps a rule restored before is left out; the rest applies. The owner is restored, so other tokens may not change it |
| `two_puts_of_the_same_generation_leave_the_row_of_the_set_that_runs` | Two `PUT`s of the same `generation` at once (the one that changed the set first stops before it queues its row while the other runs to its end, #306): the row is the running set (the later one) and says `persisted: true`. The set is read under the same `order` its row is queued under |
| `the_check_writing_a_set_again_does_not_undo_a_put` | The check writes again a set that did not go through while a `PUT` of the same `generation` runs to its end (#306): the check writes the set as it is when it queues it, so the row stays the `PUT`'s, with `persisted: true` |
| `sets_survive_a_restart_with_mariadb` | The real binary with MariaDB (`RPROXY_TEST_DATABASE_URL`): it starts without the table and answers `persisted: false`; stored, restarted, restored; other nodes' rows stay out; an older `PUT` does not overwrite a row with a newer `generation`; `DELETE` removes the row |

## Integration tests: the global settings API (`tests/global_api.rs`, #342, v0.4.19)

| Test | What it checks |
|---|---|
| `the_api_sets_what_the_file_leaves_out_and_the_next_request_takes_it` | `admin` only. The file's items `409 static` (`items`), `restart` items `409 restart_only`, `crowdsec` over TCP `403`, mistakes and a missing `access_log` directory `400`, `/proc` `403 protected_file`. A dry run of `trusted_proxies` changes nothing; the real change makes the next request's `X-Forwarded-For` believed. `access_log` sends the next lines to the file. `null` goes back to the default |
| `udp_sessions_and_http_timeouts_change_for_the_next_session_and_connection` | `udp_max_sessions: 1` refuses the next new session, clearing it lets it in. `http.timeouts.first_byte: 1s` closes a new connection after a second; clearing it goes back to the default |
| `crowdsec_through_the_unix_socket_and_the_rules_that_need_it` | `crowdsec` set over the Unix socket lets rules that use it be created; while rules use it, it cannot be cleared (`409 in_use`). Its key file set through the API cannot be named by rules |
| `stored_restored_and_written_again` | A memory store: the row is written before the answer (`persisted: true`); a failed write stays in force with `persisted: false`, is in the handoff's `pending` and written again by the check. Restored at a restart it is in force, and the file's items are `shadowed` (`config.global_shadowed`) |
| `a_live_upgrade_hands_the_values_over` | Through the handoff state's `global`, the new process puts the same values in force before the rules (who set them, `persisted`) |
| `a_reload_that_brings_the_item_into_the_file_wins` | An item that appears in the file on a reload wins (not in `restart_needed`), the API value is `shadowed` and cannot be changed through the API (`409 static`). A mistake in a live item refuses the reload. Once the file leaves it out, the API value is back |

## Integration tests: performance (`tests/performance.rs`, #194, #184)

Starts the real binary and checks the effect of `global.performance` from outside.

| Test | What it checks |
|---|---|
| `the_settings_file_sets_workers_shards_and_pinning` | The settings file wins over the environment: the number of worker threads (`rproxy-wrk-*`), worker i pinned to the i-th listed CPU (`Cpus_allowed_list` in `/proc/<pid>/task/*/status`), `udp_shards: auto` opening as many sockets per port as workers (`/proc/net/udp`), `splice` overridden key by key, `sources` in the `performance` line |
| `the_environment_applies_without_the_file` | Without `global.performance` in the settings file, `RPROXY_WORKERS`, `RPROXY_UDP_SHARDS=auto` and `RPROXY_SPLICE=0` apply. With nothing set, the defaults (one UDP socket, no pinning) |
| `cpus_that_do_not_exist_are_left_out` | CPUs that do not exist are left out with `degraded`; the workers are as many as the usable CPUs |

## Integration tests: kernel offload (`tests/kernel_offload.rs`, #260)

Checks the startup test of `global.performance.xdp` and `--check-kernel` with the real binary. Whether a fast path works depends on the machine (privileges, kernel), so the tests check that the outcome is reported consistently either way.

| Test | What it checks |
|---|---|
| `nothing_requested_probes_nothing` | Nothing requested: nothing is tested (no `performance.probe` line), `performance` of `GET /capabilities` says `requested: off` everywhere |
| `requested_fast_paths_are_probed_and_fall_back_with_a_reason` | One `performance.probe` line per requested feature with the same `active` as `GET /capabilities`; when not usable, a `reason` and `degraded` (`part`) |
| `fallback_false_stops_startup_when_the_fast_path_is_not_usable` | With `fallback: false` an unusable fast path stops startup |
| `mistakes_in_the_settings_stop_startup_and_the_check` | Wrong `RPROXY_XDP_*` and settings-file values stop startup and `--check-kernel` |
| `check_kernel_tests_every_fast_path_and_prints_a_table` | `--check-kernel` prints a row per fast path and the host; its exit status matches the requested one's result; the JSON says the same |

### offload-verify (testing-only always-on cross-check, #260)

The cargo feature `offload-verify` (off by default, never in release builds; the default build has none of this code). Each fast path cross-checks counts, stalls and how connections end while running and at the end; a mismatch logs `offload.verify` at `error` with the numbers (also on stderr) and counts on `/metrics` (`rproxy_offload_verify_failures_total`, this build only). Tests fail when it is not zero (`common::assert_offload_verified`, at the end of the TCP and UDP cases of tests/integrity.rs); content is compared end to end by tests/integrity.rs. The stall threshold is `RPROXY_OFFLOAD_VERIFY_STALL_SECS` (default 5 s). With `RPROXY_XDP_MODE` set, the in-process rproxy also runs the startup test and uses the fast path (`common::offload_from_env`; `RPROXY_TEST_REQUIRE_OFFLOAD` makes an unusable one a failure). In the sockmap experiment (docs/en/PERFORMANCE.md) it found four kernel quirks and the backlog stall.

## The DPDK data plane (`dpdk.yml`, #261)

Only for builds with the cargo feature `dpdk` (not in the default CI's `cargo test`). `.github/workflows/dpdk.yml` runs on PRs that change `crates/`, `src/l4/dpdk.rs` and the like (not a required check). Correctness only (speed is measured on real hardware; docs/en/PERFORMANCE.md).

| What | Checks |
|---|---|
| Unit tests of `crates/rproxy-dpdk` (no DPDK; `cargo test -p rproxy-dpdk`) | Frame parsing and rewriting (the incremental checksum update equals one computed from scratch; fragments, broken headers), ARP and ping replies, NAT sessions (both ways, answers from other addresses dropped, idle, stopping rules, the gateway, retargeting, 2,000 clients), the startup check's scenario (it notices corruption) |
| `crates/rproxy-dpdk/tests/ring.rs` (DPDK, no root, `--no-huge`) | The startup check through the `net_ring` loopback port in real mbufs. The lcore loop (`io::run`) on one end of a `net_memif` pair, 500 datagrams there and back from the other end, compared |
| `scripts/test-dpdk.sh` (sudo, hugepages) | The real `rproxy-api` with two ports, `net_tap` and `net_af_packet` (veth), against kernel UDP sockets (20 clients × 70 datagrams of 0-1472 bytes, a rule across ports, a port range), ping, `performance.dpdk` of `GET /capabilities`, `--check-kernel`, and when it cannot be used `fallback: true` (degraded) / `false` (no start) |

Locally: after `sudo apt install libdpdk-dev`, `cargo test -p rproxy-dpdk --features ffi` and `cargo build --features dpdk && sudo scripts/test-dpdk.sh`.

## Integration tests: self-update (`tests/self_update.rs`, #174)

An HTTPS mirror (a small server in the test; binaries are answered with a redirect, as GitHub does) carries this binary signed under the next patch number.

| Test | What it checks |
|---|---|
| `a_signed_patch_is_swapped_in_and_a_forged_one_refused` | The new patch is picked from the signed index (with a gap in the numbers and another minor listed); `POST /admin/update` fetches and verifies it and swaps it in with a handoff (the new process runs the cached binary); after `RPROXY_UPDATE_HEALTHY` it is the good version. A patch whose signature does not match its binary is refused (`error` in `GET /admin/update`) and never cached |
| `launch_runs_the_newest_patch_follows_upgrades_and_rolls_back` | `rproxy-api launch` picks and starts the newest patch (on trial), passes SIGUSR2 on and follows the main process after the handoff; a version on trial that dies is marked bad and the image's version starts instead; SIGTERM stops the server and the launcher |
| `a_trial_stopped_by_a_signal_is_not_bad_and_bad_marks_can_be_cleared` | A version on trial stopped by SIGTERM to the launcher is not marked bad (the `trial` is cleared); `rproxy-api update-clear-bad --version` takes a bad mark off (security review M1) |
| `a_trial_killed_three_times_is_bad` | A version on trial stopped by SIGKILL: the whole container (the launcher too), and the server alone (the OOM killer of the container's memory limit picks the largest process, the server). Both count as `update.interrupted` (for the server alone the launcher starts it again at once); the third makes the version bad and the image's version starts (security review M1) |
| `signatures_of_the_minisign_tool_verify` | Keys and signatures made by the minisign tool (the default prehashed form and the legacy one) verify |

## Integration tests: hostile traffic (`tests/hostile.rs`)

Runs the real binary in its own process group with 16 hostile senders and 2 legitimate clients at once (`RPROXY_TEST_HOSTILE_SECS` seconds per round, default 2; two rounds, up to six while the memory still grows). The random seed is printed; `RPROXY_TEST_HOSTILE_SEED` repeats the same input and `RPROXY_TEST_HOSTILE_ONLY=name,...` narrows the kinds of input. Each round checks: legitimate exchanges match byte for byte; the process is alive, `GET /rules` answers and every rule is running; after the load stops, connections go back to 0 and the `/proc/<pid>/fd` and thread counts return to the baseline within a margin; RSS stops growing from round to round (the RSS after a round is not what is in use then but what the allocator kept from the round's peak, and the peak depends on the CPU the round got: with the whole suite alongside, a starved first round stayed low and the second looked like a leak, #328. It climbs over the first rounds to where the peaks add nothing and stays there, so the test fails only if each round up to the sixth adds more than 8 MiB, or a sixteenth, to the one before); no panicked, fatal or `rule.failed` in the log. Run it longer in CI's Repeat workflow ("CI environment" above).

| Test | What it sends |
|---|---|
| `tcp_survives_hostile_traffic` | random bytes, immediate close, connecting without sending, sending slowly, one huge write |
| `tls_survives_hostile_traffic` | broken, truncated and fragmented ClientHellos and bad SNI to sni, terminate and terminate with passthrough routes |
| `http_survives_hostile_traffic` | invalid methods, no Host, oversized and too many headers, broken chunked, Content-Length / Transfer-Encoding conflicts (a request sent behind must not reach the backend), headers with CR / LF, pipelined garbage, HTTP/2 preface garbage |
| `starttls_survives_hostile_traffic` | garbage before or instead of STARTTLS on smtp, imap and pop3, commands slipped in before TLS (they must not reach the mail server) |
| `udp_survives_hostile_traffic` | random and oversized datagrams, many source ports, garbage posing as DTLS or QUIC, truncated, mutated and replayed QUIC Initials and DTLS ClientHellos, to plain, QUIC and DTLS sni and DTLS terminate rules |

Received PROXY protocol (#296, #312) is not sent here (the header parser is the fuzz target `proxy_header_in`, the behavior `tests/proxy_protocol.rs` and `tests/proxy_protocol_udp.rs`).

## Integration tests: abnormal termination (`tests/crash.rs`)

The real binary is stopped with SIGKILL (as by the OOM killer or `kill -9`) and started again on the same files (as systemd or the launcher restarts it). Kill times are random; each test runs `RPROXY_TEST_CRASH_ROUNDS` rounds (default 3). Many more rounds: the manual Crash workflow (`gh workflow run crash.yml -f rounds=50`). The process runs in a process group of its own, so a handoff's new process is stopped with it (as with systemd's `KillMode=control-group` or the end of a container).

| Test | What it checks |
|---|---|
| `stored_certificates_survive_kills_during_writes` | Killed while 4 writers `PUT` / `DELETE /certs`. After the restart every stored certificate is one of those sent and loads with its key (checked on disk under `current/`); `GET /certs` matches the disk; nothing `remove` set aside (`.removing-*`) is left; a rule using one runs with a certificate that was sent |
| `leftovers_of_a_killed_process_do_not_stop_the_startup` | What a killed process leaves (the control API's Unix socket and the handoff socket files, temporary files in the certificate store, `current.tmp`, a name without `current`, `.removing-*`) does not stop the startup; the Unix socket answers and a handoff works |
| `a_kill_under_traffic_comes_back_with_the_same_rules` | Killed under TCP, UDP and HTTP traffic. After the restart, when `/readyz` first answers 200 every rule is there (`GET /rules` as before the kill, without counters and `started_at`), traffic flows, and the counters start from zero (`counters_since` is the new start) |
| `kills_during_a_live_upgrade_leave_a_service_that_starts_again` | The old process, the new one, or both killed during a handoff (SIGUSR2): at once, or right after `handoff.start`, `handoff.received`, `handoff.sent`, `restore.start`, `handoff.ready`. A new process killed before it is ready leaves the old one running, changes included; a new process whose old one died takes over or ends by itself (it does not hang). In every case a restart brings back the rules and the control API (TCP and Unix socket) |
| `stored_rules_survive_kills_with_mariadb` | Killed while 6 writers create, change and delete rules with a `persist: true` token. After the restart each rule is as the last answered change left it or as the change sent at the kill (`origin: api`, `persisted: true`), and matches its row in `rproxy_rules` |
| `a_write_still_running_at_the_kill_is_read_after_it_is_done` | A write (create, delete) sent at the kill is still running in MariaDB (held up by a row lock of the test; in CI it was a slow commit). The restarted process waits for the node's lock before it reads the rows (not ready meanwhile). A write that had not committed is undone with its connection, so a create leaves neither row nor rule and a delete leaves both (rows and rules agree). A delete held past the write's bound is undone by the lock wait timeout, and the new process gets the lock (no `restore.wait`) |
| `a_held_node_lock_holds_up_the_start_only_for_its_bound` | The node's lock is held by a connection that has done nothing for longer than a live rproxy ever does: the startup waits only `STARTUP_WAIT` (8 seconds), logs `restore.wait` (with the holder's `host`) and restores the readable rows |
| `the_periodic_check_makes_the_running_rules_what_the_rows_say` | The periodic check (`RPROXY_PERSIST_CHECK_SECS=1`): a row added straight to the database starts its rule, a changed row replaces it, a deleted row deletes it (`persist.reconcile`) |
| `the_periodic_check_does_not_undo_a_change_under_way` | A PATCH whose write is held up by a row lock (and fails, `persisted: false`): the check does not put the older row back meanwhile, and afterwards writes the running rule again |
| `a_second_process_with_the_same_node_name_does_not_start` | A second process with the same `node` name does not take the lock; it waits up to `DUPLICATE_STARTUP_WAIT` (40 seconds), sees the holder keep sending statements (live), logs `persist.duplicate_node` (error, `phase: startup`, the holder's `host`) and `fatal` (`--node-name`, `RPROXY_NODE_NAME`), and exits non-zero (never ready, its static rule never listens). The first keeps the lock and its writes |
| `a_duplicate_started_while_the_database_was_down_does_not_take_the_lock` | A second process with the same name started while the database could not be reached (the test's forwarder opens later): it does not take the lock, its writes answer `persisted: false` at once, and after `DUPLICATE_AFTER` it logs `persist.duplicate_node`. The first keeps the lock and its writes |
| `a_process_with_the_same_node_name_that_restores_for_long_is_seen_live` | The first process with a name takes the lock and then restores for longer than `LIVE_IDLE` (the test's forwarder holds up its read of the UI's rules, #307): it pings from the moment it has the lock, so the second one sees it live and stops with `persist.duplicate_node` (it used to take it for a connection left behind and start, and the first one's connection was dropped by `wait_timeout`). The first finishes its restore and keeps the lock |
| `a_connection_opened_again_takes_the_lock_again` | After the connection broke (KILL in MariaDB), the ping takes the lock again on the connection opened again (without waiting for a write) |
| `a_live_upgrade_carries_what_was_not_written` | A live upgrade with a change the old process could not write (a PATCH held up by a row lock, `persisted: false`): the new process runs the rule as changed, its check does not put the older row back, and it writes the row |
| `without_the_database_a_change_answers_at_once` | The database cannot be reached: a change answers `persisted: false` at once |
| `after_a_live_upgrade_the_new_process_holds_the_node_lock` | After a live upgrade (SIGUSR2) the old process, draining, lets go of the node's lock and the new process's writes hold it. The new process is not taken for a duplicate node name (no `persist.duplicate_node`, no `fatal`) |
| `stored_rule_sets_survive_kills_with_mariadb` | Killed while a rule set is `PUT` with growing generations by a `persist: true` token. After the restart the set has the last answered generation or the one sent at the kill, with exactly that generation's rules |

## Integration tests: diff before change (`tests/plan.rs`, #169)

| Test | What it checks |
|---|---|
| `dry_runs_of_the_rule_endpoints_change_nothing` | `dry_run` on `POST` / `PATCH` / `DELETE` answers `action`, `change`, `before` (view), `after` (shape) and `diff`, and creates, changes and deletes nothing (no listener is opened). Mistakes get the change's own answers (`invalid`, `tls_config` (certificates are read), `already_exists`, `unsupported`, `not_found`, `static`). Names are not resolved |
| `rule_set_dry_runs_change_nothing` | `PUT /rulesets/{name}?dry_run=true` runs the set's checks and answers each rule's `action` and `change` (unchanged, in place (with `diff`), re-created, deleted, created) and the etag the set would have, changing neither the set nor its rules. An older `generation` is refused as in the PUT itself |
| `dry_runs_need_the_same_permissions` | `allow_listen_ports` and scopes apply to dry runs |
| `config_plan_compares_with_the_static_rules` | `POST /config/plan` answers the difference from the static rules (creates, in-place changes, re-creations, deletes, the unchanged count), `restart_needed`, and a warning for an address an API rule holds (`failed`), changing nothing. Mistakes: `400` with `errors` |
| `config_reload_dry_run_reads_the_file_and_applies_nothing` | `POST /config/reload?dry_run=true` reads the file and only answers the difference. Mistakes: `400`. A real reload afterwards applies |
| `check_config_diff_asks_the_running_rproxy` | With the real binary on a Unix socket, `--check-config --diff` prints the difference (`text`, `json`, the default `RPROXY_API_SOCKET`, `--diff-token-file`). No token (401), nothing listening, a wrong `--diff-api` and mistakes in the file exit 1 |

## Integration tests: storing API-created rules (`tests/persist.rs`, #144)

| Test | What it checks |
|---|---|
| `persist_tokens_store_their_rules` | Rules of a `persist: true` token are `origin: "api"` with `persisted`, `created_by` and `created_at`, and get a row (memory store). Rules of other tokens stay `dynamic`. Changes to an `api` rule are written whichever token makes them, keeping the creator. A failed write leaves the rule running with `persisted: false`. Deleting removes the row. Dry runs write nothing |
| `without_a_database_nothing_is_stored` | Without `RPROXY_DATABASE_URL`: `api`, but `persisted: false` |
| `restored_rows_are_api_rules` | Restored rows are `api` rules (`persisted: true`, the stored `created_at`). The UI's row wins on the same key |
| `a_change_whose_client_went_away_is_still_written` | A `POST` whose client went away before the answer (a memory store with slow writes): the change runs to its end, the row is written and `persisted: true`. A check while the write is under way does not delete the rule |
| `a_delete_with_drain_spares_a_new_rule_with_the_key` | A `POST` with the same key while `DELETE ?drain_secs` drains: the `POST` does not wait for the drain, and the old rule's row is deleted first, so the new rule keeps its row and `persisted: true` |
| `release_does_not_wait_for_a_drain` | While a delete drains, a live upgrade's `release` lets go of the lock at once (the row was deleted before the drain) |
| `rules_survive_a_restart_with_mariadb` | MariaDB (`RPROXY_TEST_DATABASE_URL`) and the real binary: a created (and changed) rule is written to `rproxy_rules` and comes back as `api` after a restart. On the UI's key the UI's rule is used (`restore.conflict`); other nodes' rows stay out. Deleting removes the row |
| `global_values_survive_a_restart_with_mariadb` | #342: the real binary and MariaDB: `PATCH /config/global` is in force without `rproxy_global` (`persisted: false`); with the table, one row is written before the answer (`persisted: true`). A restart restores it before the rules (`restore.global`) |
| `rows_that_do_not_validate_are_failed_rules` | #327 (memory store): rows that do not validate are `failed` in `GET /rules` (the reason, the stored body, `created_by`, `Invalid` in `conditions`); a `POST` with the key gets `409`, a PATCH that does not fix it `400`; a fixing PATCH (and its dry run) starts it and writes the row; `DELETE` removes it with its row. The periodic check shows a new row as `failed`, starts it once it changed, drops it once it is gone |
| `invalid_rules_keep_their_files_and_count` | #327, #323: another token may not name the key of a rule that did not validate (`409 file_in_use`); the owner's fixing PATCH passes despite a share from before; one whose key a restored set left out stays, and a set's `PUT` with its key gets `409` (`already_exists`); the `created_by` of a row whose key a set took is forgotten; counted as `failed` and `rproxy_rule_up 0` in `/metrics`; a restored rule set's rule with the key wins; deleting it forgets the owner, and the same row coming back is shown as `failed` again |
| `rows_that_do_not_validate_with_mariadb` | #327 (MariaDB and the real binary): rows of `rproxy_rules` and `forward_rules` that do not validate are `failed`; the one fixed by a PATCH is written and runs after a restart; the `forward_rules` one goes with `DELETE` and is back at the next start |
| `a_blank_node_name_stops_the_startup` | A blank `RPROXY_NODE_NAME` is a configuration error |
## Integration tests: rule sets, labels, conditions, readiness (`tests/rulesets.rs`, #28)

What the Kubernetes controller (`max3584/rproxy-gateway`) uses.

| Test | What it checks |
|---|---|
| `capabilities_turn_the_controller_features_on` | `rulesets`, `labels`, `conditions` and `readyz` in `features` are true |
| `a_set_is_applied_as_a_whole_with_minimal_disruption` | A set whose name has `/` is created (`ETag` header, `ruleset`, `labels` and `conditions` in `GET /rules`, `GET /rulesets`). The same body is all `none` with the same etag. A new target alone is `in_place`: an earlier connection stays while new ones go to the new target. A different `source_ip` is `recreate`. A rule left out is `delete`. `DELETE /rulesets/{name}` stops everything |
| `sets_refuse_stale_writes_and_do_not_take_other_rules` | A wrong `If-Match` and `If-Match` on a set that does not exist (412), an older `generation` (409 `stale_generation`), unquoted / list / `W/` `If-Match`. PATCH / DELETE of a set's rule is `409 owned`, another set's rule `owned`, a POSTed rule `already_exists` (nothing created). One invalid rule changes nothing and `errors` lists every problem. Overlaps within the body. `dry_run` answers the rules that would go and changes nothing (more in tests/plan.rs). Wrong names |
| `a_rule_that_cannot_bind_fails_alone` | Only the rule on a busy port is `failed` (`Programmed` `False` / `BindFailed`, `BackendsHealthy` `Unknown`, `last_transition` unchanged when read again); the rest runs. Once the port is free, the same body re-creates it and it runs |
| `conditions_report_targets_that_are_down` | A rule with every target down has `BackendsHealthy` `False` / `AllTargetsDown` (rules outside sets have `conditions` too) |
| `labels_are_kept_replaced_and_exported` | `labels` in the view, `rproxy_rule_labels` in `/metrics`, PATCH replacing them as a whole / keeping them when left out / `{}` removing them, a wrong key is `invalid` |
| `readyz_follows_the_startup_and_the_shutdown` | Without a token: `starting` (503) → ready (200) → `draining` (503; never ready again) |
| `sets_need_rules_write_within_the_allowed_ports` | A `rules:read` token can read but not PUT / DELETE (403), rules outside `allow_listen_ports` are 403, `updated_by` is the token's name |
| `sets_belong_to_their_token_and_old_ports_are_checked` | A set belongs to the token that made it (others get `403` even with a huge `generation`; `admin` may change it and the `owner` stays); names outside `allow_rulesets` are `403`; a `generation` past 2^53 is `400`; a change whose current listen range is outside `allow_listen_ports` is `403` (security review M2, M3) |

That a started rproxy answers 200 on `GET /readyz` after the restore is `readyz_answers_once_started` in `tests/startup.rs`.


## Integration tests: GeoIP (`tests/geoip.rs`, #168)

The mmdb files are made by the test (`tests/common/mmdb.rs`: a small writer of an IPv6 tree (IPv4 under ::/96), 32-bit records and maps of strings and integers; no MaxMind database is used or committed). Loopback sources stand for countries: 127.0.0.1 is JP, 127.0.0.2 is US (AS64496), 127.0.0.3 is not in the databases. Unit tests (`net::geoip`) cover the decision table, reading files, reloading that skips a broken version, and startup errors.

| Test | What it checks |
|---|---|
| `tcp_rules_refuse_by_country_and_asn` | With `allow_countries`, JP passes and US is closed; unknown passes by default. `conn.denied` with `reason: geoip`, `country`, `asn`; `country` in `conn.open` with `log_country`; `stats.denied`. PATCH to `deny_asns` and `unknown: deny`, `{}` removes it |
| `udp_rules_drop_datagrams_by_country` | Datagrams of a refused country are dropped and no session is made |
| `lists_need_the_databases` | Without `global.geoip`, or with only a country database, country / ASN lists (rules, middleware) are `400 invalid` |
| `the_middleware_answers_403_for_the_client_trusted_proxies_name` | The middleware answers `403`, on the client a trusted proxy names in `X-Forwarded-For` (not believed from untrusted peers). `http.access` with `refused_by: geoip`, `country`, `asn` |
| `check_config_reads_the_databases` | `--check-config` reads the databases; a missing file or one that is not an mmdb is an error |

## Integration tests: passive health checks (`tests/outlier.rs`, #170)

The behaviour without the setting (one failure ejects for 10 s) is in `tests/targets.rs`. Unit tests (`core::outlier`, `core::balance`) cover the defaults, doubling ejections, the L7 thresholds, `max_ejected_percent` and `short_lived`.

| Test | What it checks |
|---|---|
| `consecutive_failures_eject_a_target_for_a_while` | Ejected after 3 refused connections in a row (`up`, `ejections`, `ejected_until` in `stats.targets[]`; `target.down` with `reason: outlier`, `cause: connect`), back by itself after `ejection_time` (`target.up`) |
| `short_lived_connections_count_as_failures` | Connections the target closes at once are failures with `short_lived` (`cause: short_lived`); those the client ends are not |
| `max_ejected_percent_keeps_targets_and_patch_changes_it_in_place` | `max_ejected_percent: 0` never ejects; PATCH with `{}` goes back to the defaults |
| `http_servers_that_keep_failing_are_ejected` | A server answering 500 in a row is ejected and the rest get the requests (`ejected` in `stats.http.services`; `target.down` with `service`, `server`, `cause`) |
| `http_ejection_leaves_at_least_half_by_default` | The default `max_ejected_percent: 50` never ejects them all |
## Integration tests: others

Test files not covered by the sections above (see the description at the top of each file and the test names).

| File | What it checks |
|---|---|
| `tests/check_config.rs` | `rproxy-api --check-config` (#140; a key readable by others is an error, fine with `global.files.owner_check: off`): validates the settings file the way startup and reloads do, opens nothing, reports through its exit code, text and JSON. Files the API would refuse (#319) are warnings (`files_the_api_may_not_name_are_warnings`) |
| `tests/startup.rs` | Starting the real binary: configuration mistakes stop it; problems in the environment (permissions, a busy port) leave it running in a restricted mode that recovers. TLS on the control API, reloads on SIGHUP, `GET /readyz` |
| `tests/targets.rs` | Several destinations (#98): `targets`, `balance` (round_robin / least_conn / failover), `backup`, `health_check` (L4 and services of `http` rules). The default behaviour without `outlier_detection`. `connect_timeout` (v0.4.3; a target that drops SYNs) |
| `tests/listen.rs` | One rule listening on several addresses (`extra_listen_addrs`, #99); listening on addresses not on the host yet (`listen_freebind`, v0.4.3; the real path is `scripts/test-freebind.sh`) |
| `tests/udp_shards.rs` | Reading a UDP port with several `SO_REUSEPORT` sockets (#194): no session opened twice, the reply source (#137), counters add up |
| `tests/udp_source.rs` | UDP replies on wildcard listeners leave from the address the client sent to (#137; to 127.0.0.2) |
| `tests/udp_sessions.rs` | The default cap of a udp rule's sessions (#332, `RPROXY_UDP_MAX_SESSIONS`): new sessions beyond it refused, taken again once idle ones end, a rule's `limits.max_connections` first, 0 for none (the cap is process-wide, so only this file's one test changes it) |
| `tests/udp_sni.rs` | UDP `tls.mode: sni` (#130) with real QUIC (quinn) and DTLS clients and backends; the slots of sessions waiting for the rest of their name are bounded per source prefix (#332) |
| `tests/http.rs` | L7 routing of `http` rules |
| `tests/http3.rs` | HTTP/3 with `http3: true` (#56), with a quinn + h3 client |
| `tests/http_auth.rs` | Authentication middlewares (#59): `basic_auth`, `forward_auth`, `oidc`. Reusing an OIDC client secret file is `409 secret_reuse` (#319, `oidc_client_secrets_keep_to_one_use`; `/proc/self/environ` and `/proc/self/fd/N` are `403 protected_file`; the message tells nothing of other rules) |
| `tests/http_resilience.rs` | Health checks, `sticky`, `compress`, `buffering`, `retry`, `circuit_breaker`, `errors` and kept backend connections (#61, #63, #64, #65) |
| `tests/http_semantics.rs` | The HTTP forwarding contract ("HTTP forwarding semantics" in docs/en/API.md): 504 when an HTTP/2 backend's streams are taken, and more connections (security review M6); client certificate headers dropped on an HTTPS rule without `client_auth` over HTTP/1.1, HTTP/2 and HTTP/3 (security review H1); cookies, repeated fields, hop-by-hop headers, bodies, large headers and timeouts with HTTP/1.1, HTTP/2 and HTTP/3 clients. HTTP/2 backends (#233): one multiplexed h2c connection, trailers both ways (including a gRPC trailers-only answer), `te: trailers`, h2 (TLS + ALPN) and `auto` (with backends picking `h2` or `http/1.1`), 502 when the backend does not pick `h2`, `protocol` against the URL scheme; the normalised path and the query at the destination (#320) |
| `tests/path_normalize.rs` | The path and Host normalised before matching (#320): `/%61dmin`, `//admin`, `/x/../admin`, `/admin/.` and a Host with a trailing dot hit the `ip_allow` route over HTTP/1.1, HTTP/2 and HTTP/3; the path the destination gets, 400 for broken escapes, `raw_path`. Identity headers dropped on a route without authentication. `global.http.timeouts`: connections sending nothing, slowloris and only the HTTP/2 preface are closed, HTTP/2 idleness, a slow upload passes and a body that stops is cut; `strict_path`, `raw_path` in the access log, bodies of answered streams and of gRPC never cut by `request_body_idle` |
| `tests/gateway_l7.rs` | L7 for the Gateway API (#224, #226-#232, #235): `add` of `headers`, redirect `status`, route `timeouts` (504, per attempt, cutting a body off), `replace_host`, per-server middlewares, `cors` (preflights, wildcard origins), `status` of `retry`, `mirror` (share, bodies, an unreachable mirror), `status` servers, `features`. Preflights from origins not allowed answered by rproxy, `retry` again with one server, `X-Client-Verify` and `X-Forwarded-Client-Cert` of client certificates (`optional_no_verify`, forged headers removed) (#238). Certificate headers cannot be forged on plain rules without `client_auth`, Upgrades, `forward_auth` or `mirror`, and the X-Forwarded-For of `mirror` copies (security review H1, M5) |
| `tests/backend_tls.rs` | A service's `tls` (#236): its CA and SNI name, `subject_alt_names` (DNS names and URIs), a client certificate towards the backend, `https://` backends from a plain-HTTP rule, mistakes in shape and files |
| `tests/crowdsec.rs` | The `crowdsec` middleware (a fake LAPI and AppSec). Rules from the API may not name the key file (#319, `rules_may_not_name_the_key_file`) |
| `tests/acme.rs` | ACME (#208): the API's guards (always run; the storage and secret files of #319 in `rules_may_not_name_acme_files`) and obtaining real certificates with Pebble and PowerDNS (table above) |
| `tests/traefik_convert.rs` | The Traefik converter (`crates/rproxy-traefik`): rproxy reads and accepts the output of every case (`cases`) in `tests/fixtures/traefik/`; some are checked in detail. The middlewares the converter knows (`KNOWN_MIDDLEWARES`) are in `Features::CURRENT` |
| The tests of `crates/rproxy-traefik` (`cargo test -p rproxy-traefik`) | The output is byte for byte `tests/fixtures/traefik/*/expected*` (written by the Python version, `contrib/traefik2rproxy.py`; how to add one: `tests/fixtures/traefik/README.md`), exit codes and `-o`, unit tests of the YAML writer (as PyYAML writes), rules, middlewares and durations. It reads local files the administrator gives it, so there is no fuzz target (nothing read from the Internet) |

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
| `proxy_dgram/v4` / `v6` / `untrusted_plain` | What `proxy_protocol` of a `udp` rule (#312) decides for each datagram (`proxy_in::datagram`: trusted peer or not, parsing the v2 DGRAM header, the offset to strip; no allocation). `untrusted_plain` is a datagram without a header from outside `from` |
| `l4_tcp/*` in `benches/dataplane.rs` | A 1 MiB round trip through TCP forwarding (throughput), and new connections (connect → 1-byte round trip → close) |
| `l4_udp/*` | A 1 KiB UDP round trip, and new sessions (a new source port every time). `roundtrip_1KiB_proxy_protocol` is the same round trip with a PROXY v2 header to a rule with `proxy_protocol` (#312) |
| `tls_terminate/*` | New connections with TLS termination (full handshakes, no resumption), and a 1 MiB round trip on a terminated connection |
| `l7_http1/request` / `l7_http2/*` | Requests to an `http` rule (4 routes, `headers` and `strip_prefix` middlewares): HTTP/1.1 keep-alive, HTTP/2 (h2c) one at a time and 32 at once |

`dataplane` uses the same harness as `tests/` (`tests/common`): rules are created through the control API, and real clients and backends are connected over loopback. Locally: `cargo bench --bench '*'` (1–2 minutes in all), or only some with `cargo bench --bench dataplane -- l7_http2`. To compare before and after a change, use `-- --save-baseline before` before and `-- --baseline before` after.

`.github/workflows/bench.yml` runs on PRs that change `src/`, `benches/`, `tests/common/`, `examples/resource_probe.rs` or `Cargo.*`. Runners vary in speed, so the merge base (`--save-baseline base`) and the PR (`--baseline-lenient base`) are measured one after the other in the same job, and `scripts/bench-summary.py` puts a table in the job summary and in a PR comment (one comment, updated). A benchmark whose mean got more than 15 % slower, with the whole 95 % confidence interval on the slower side, becomes a warning (not a failure, and not a required check). On a warning, first re-run the job to see whether it happens again.

CPU and memory are measured by `examples/resource_probe.rs` in the same job (step "resource usage (merge base vs. PR)"). It runs the release binaries (`rproxy-api`) of the merge base and of the PR as their own processes, a fresh one per workload (no configuration file; rules are created through the control API on 127.0.0.1), drives a fixed amount of traffic over loopback and reads `/proc/<pid>`: CPU time (utime + stime of `stat`, all threads), `VmRSS`, `VmHWM` and the number of FDs. No namespaces or root needed. Workloads: `udp` (1,000 sessions from 1,000 sockets → memory per session (RSS after them − RSS before, divided by the count), then 100 round trips of 64 bytes per session → CPU per round trip), `udp-pp` (the same with `proxy_protocol` on the rule: every datagram carries a PROXY v2 DGRAM header, each socket naming a client of its own (198.18.0.0/15); skipped for builds whose `/capabilities` lacks `features.proxy_protocol_in_udp`), `tcp` (1,000 idle connections → memory per connection, 2,000 connect / 1 KiB echo / close → CPU per connection, 1 GiB uploaded over 4 connections → CPU per MiB). The two binaries take turns (A, B, B, A, ...) for 5 rounds; the table shows the medians, and a figure of the PR worse than the merge base by more than `THRESHOLD` (15 %) for CPU or `MEM_THRESHOLD` (15 %) for memory becomes a warning (not a failure). The table goes into the job summary and the PR comment next to the criterion table; the raw numbers are in the `resource-usage` artifact (`resources.json`). The numbers are a sanity check on a runner (CPU time comes in 10 ms ticks); the load tests below ("Load and soak tests") are the careful comparison. Locally: `cargo build --release --bin rproxy-api --example resource_probe`, then `target/release/examples/resource_probe --rproxy base=<an older binary> --rproxy pr=target/release/rproxy-api` (`--rounds`, `--sessions`, `--datagrams`, `--conns`, `--churn` and `--mib` change the amounts).

When one iteration of `dataplane` makes no progress for 30 seconds (`STALL`), the benchmark treats it as a stall and panics with what it was doing (bytes written and read back, whether the TLS client still holds unsent records) and the rule counters (#187). Each workflow step also has a timeout (20 minutes). A TLS stream must be flushed after `write_all`: when the socket was full, the last records stay in rustls until then (the cause of the stall in #187, on the client side; rproxy's relay (`l4::relay`) flushes whenever it has nothing to read).

For telling the causes apart there is `examples/stall_probe.rs` (the `stall-probe` job of `bench.yml`). It repeats the same 1 MiB echo hundreds of times with a 3-second timeout per iteration, across L4 TCP, TLS termination and TLS without rproxy, the client flushing or not, the default or a 4 KiB send buffer, and rproxy in the same process or as its own process (`--rproxy target/release/rproxy-api`), and prints how many iterations stalled and how long they took. In #187 only TLS clients that did not flush stalled, just the same without rproxy and with rproxy as its own process, and their rustls still held unsent records (`wants_write = true`). The job fails if a client that flushes stalls. Locally: `cargo run --release --example stall_probe -- --iters 300`.

## Not yet tested

- Real mail clients (Thunderbird etc.) and WebRTC in browsers (checked by hand: #42, #44). Combinations with real mail servers (Postfix / Dovecot), TURN (coturn) and RTSP (MediaMTX) are checked by the Interop workflow (below)
- Continuous forwarding for many hours (the Load workflow's soak can do it when run manually with a long `soak_secs`)
- The transparent routing procedure using iptables (`-m socket`)

The control API with TLS enabled and reloading tokens and certificates via SIGHUP are checked in `tests/startup.rs` (`an_unreadable_api_certificate_is_retried`, `sighup_reloads_tokens_and_the_api_certificate_and_keeps_them_on_bad_files`).

## Combinations with real servers (Interop workflow)

`.github/workflows/interop.yml` puts real servers behind rproxy and runs traffic through them. Because it takes a long time, it is not a required check; it runs on PRs that change `src/` or `scripts/interop/`, weekly, and manually (from the Actions page).

| Script | Counterpart | What it checks |
|---|---|---|
| `scripts/interop/mail.sh` | Postfix / Dovecot | With STARTTLS termination + PROXY v2, Submission, SMTP (STARTTLS optional), IMAP, IMAPS, and POP3 work. Sending and logging in before STARTTLS are refused |
| `scripts/interop/media.sh` | coturn / MediaMTX | Allocation and relaying work with TURN UDP and TCP passthrough, TLS termination, and DTLS termination (the relay addresses go through a range rule). Video can be received via RTSP (TCP interleaved) and RTSPS termination. Time, file count, and memory to create and delete a 10000-port UDP range rule |
| `scripts/interop/webrtc.sh` | headless Chromium / MediaMTX / coturn | A browser's WebRTC (published over WHIP, read over WHEP; the video is a canvas) receives video through rproxy (#44). Direct: the media UDP goes through a range rule (passthrough) and the selected candidate's peer is rproxy's address. TURN: with `iceTransportPolicy: relay` it connects only through coturn behind rproxy, and the video it receives comes through rproxy's TURN rule. Both decode at least 30 frames |
| `scripts/interop/crowdsec.sh` | CrowdSec (LAPI, agent, AppSec) | CrowdSec detects and bans from rproxy's logs, and rproxy (L7 `crowdsec`, L4 `crowdsec: true`, AppSec) blocks. Clients with documentation addresses (IPv4 and IPv6) are banned; a private address is whitelisted and never banned |

Results for a 10000-port range rule (UDP) (GitHub Ubuntu runner, 2026-09): creation about 0.2 seconds, file descriptors +10000 (back to the original after deletion), RSS about +94 MiB.

They all run as root inside a throwaway container (`alpine:3.24` for mail, media and webrtc, CrowdSec's official image for crowdsec), and the scripts configure and start the servers themselves. Do not run them on your own machine.

## Long-running load test (Soak workflow)

`scripts/soak.py` keeps putting TCP and UDP load on rproxy-api (release build), and writes RSS, fd count, and connection count to a CSV every 10 seconds.

- TCP: 200 workers that repeatedly open and close connections, and 20 connections that stay open and keep sending
- UDP: 100 clients that send while changing their source port (with `udp_idle_secs: 5`, sessions are repeatedly created and discarded)
- Pass criteria: after the load stops, the fd count returns to the original (within +20), RSS in the second half does not exceed 1.5 times that of the first half, and forwarding failures are 0.1% or less

`.github/workflows/soak.yml` runs only on demand (no schedule, not on pull requests): trigger it from the Actions page or with `gh workflow run soak.yml -f duration=<seconds>` (default 3600), and the CSV is kept as an artifact. Locally: `cargo build --release && ulimit -n 65536 && scripts/soak.py --duration 600`.


## Load and soak tests (Load workflow, #183)

Optimizations tried and their results (including the ones not adopted) are recorded in [PERFORMANCE.md](PERFORMANCE.md).

Measures transfer efficiency when large transfers run many times and for a long time: throughput, latency, bytes per CPU core, memory, FDs, and UDP drops. These are the baseline numbers for comparing before and after kernel acceleration (#184) and memory reduction (#185); heavier and longer than the criterion benchmarks above. The numbers depend on the machine, so compare them with the previous run on the same kind of machine (runner).

`scripts/load/run.sh` builds three network namespaces and runs `scripts/load/load.py` in the middle one.

```
client 10.71.1.2 ── 10.71.1.1 [rproxy / HAProxy / router] 10.71.2.1 ── 10.71.2.2 backend
```

- **direct** (the baseline): no proxy. The kernel of the middle namespace forwards it, so it crosses the same veths and netem
- **rproxy**: the release build. Logs at `LOG_LEVEL` (default `warn`; use `info` to include the cost of per-connection logs)
- **haproxy**: when installed, side by side under the same conditions (for reference; not for UDP)
- `NETEM="delay 5ms loss 0.1%"` applies tc netem to the client link, in both directions
- Traffic comes from `scripts/load/loadgen/` (a small std-only crate with its own `Cargo.toml`, `Cargo.lock` and workspace; not part of the root build, test or deny). Large transfers carry pseudo-random data that the receiver compares byte by byte with what must have been sent (stricter than a checksum: anything lost, duplicated, reordered or shifted fails)

| Scenario | What it measures | Tools |
|---|---|---|
| `tcp` | TCP throughput (upload with 1 and 8 streams, download with 1) | iperf3 |
| `verify` | `SIZE_MIB` transfers, `REPEAT` times, with 1 and 4 streams; the backend checks every byte | loadgen `send` / `sink` |
| `tls` | Uploads into TLS termination (`tls.mode: terminate`, every byte checked) and new full handshakes per second | socat, `openssl s_time` |
| `http` | Small L7 requests (HTTP/1.1, h2c, HTTP/2 over TLS; req/s, p50 / p99) and large downloads (every byte checked) | h2load, curl |
| `udp` | 1400-byte datagrams at `UDP_BW` (loss, jitter); 64-byte datagrams at full speed and at `UDP_PPS` from 16 sources (delivered pps, loss, rproxy's `stats.dropped`, kernel receive-buffer drops) | iperf3, loadgen `udp-flood` / `udp-sink` |
| `latency` | 64-byte round trips on 1 and 64 connections (p50 / p99) | loadgen `rtt` |
| `churn` | Connect → 1 KiB round trip → close, 32 in parallel (connections per second) | loadgen `churn` |
| `memory` | In freshly started processes: idle, with `RULES` rules (default 100 and 1000), `CONNS` idle connections, the same connections busy (4 KiB round trips), and `UDP_SESSIONS` UDP sessions. RSS and FDs per rule, connection and session | loadgen `hold` / `udp-hold` |
| `soak` | `SOAK_SECS` seconds of iperf3 (`SOAK_BW`), connection churn, and UDP with ever-changing sources at once; RSS, FDs and CPU are recorded (`soak.csv`) | |

Values in the tables:

- **GiB / proxy CPU-s**: bytes moved per CPU-second of the proxy process (user + system time of all threads). **proxy cores** is the number of cores it used
- **GiB / system CPU-s**: per CPU-second of the whole machine (client, backend, kernel forwarding, proxy); comparable with direct
- **vs direct**: the rate (Gbit/s, req/s, pps, conns/s) relative to direct in the same case
- **peak RSS**: the proxy's highest RSS during the run (memory while L7 requests are in flight shows up here)

Only checks fail the run (exit code 1): transferred data differs by even one byte, a scenario does not run, connections or sessions cannot be established, FDs do not come back after the connections close, or in the soak the FDs do not return to the start (+20), the average RSS of the last quarter exceeds 1.5 times that of the first quarter (after the first 10%), or more than 0.1% of the connections fail. Slower numbers show up as deltas against the previous run (`(+x%)` in the tables; bold when more than 10% worse).

Settings (environment variables):

| Variable | Default | Meaning |
|---|---|---|
| `SCENARIOS` | all | Scenarios to run (comma-separated) |
| `SIZE_MIB` / `REPEAT` | 1024 / 3 | Size and count of the large transfers |
| `DURATION` | 10 | Seconds per throughput / latency run |
| `CONNS` / `UDP_SESSIONS` / `RULES` | 2000 / 1000 / 100,1000 | Connections, sessions and rules for `memory` |
| `UDP_BW` / `UDP_PPS` | 1G / 50000 | iperf3 bandwidth for `udp`, and the fixed rate for 64-byte datagrams |
| `H2_REQS` / `H2_CONNS` | 200000 / 64 | h2load requests and connections (HTTP/2: 10 concurrent streams per connection) |
| `SOAK_SECS` / `SOAK_BW` | 0 (skipped) / 1G | Soak duration and its iperf3 bandwidth |
| `NETEM` | none | tc netem arguments (e.g. `delay 5ms loss 0.1%`) |
| `HAPROXY` | auto | `0` leaves HAProxy out |
| `BINS` | none (`BIN`, default `target/release/rproxy-api`) | rproxy builds to compare side by side (`label=path,label=path`; the first is the baseline) |
| `OUT` / `PREVIOUS` | `load-results` / none | Where results go; an earlier `results.json` to compare with |

### Running locally or on a VM

```bash
sudo apt-get install iperf3 nghttp2-client socat haproxy   # missing tools are skipped (HAProxy is optional)
cargo build --release
cargo build --release --locked --manifest-path scripts/load/loadgen/Cargo.toml --target-dir target/loadgen
SIZE_MIB=256 REPEAT=1 DURATION=5 SOAK_SECS=60 scripts/load/run.sh      # without root (user namespace)
sudo -E env "PATH=$PATH" SOAK_SECS=3600 scripts/load/run.sh            # can raise open files and socket buffers
scripts/load/report.py load-results/results.json old/results.json      # compare two runs
```

Without root it needs user namespaces (on Ubuntu 24.04 and later, `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`). netem needs the `sch_netem` module (on Ubuntu, `linux-modules-extra-$(uname -r)`). Results go to `load-results/`: `results.json` (every value) and `summary.md` (the tables).

### CI

`.github/workflows/load.yml` runs only manually (from the Actions page or `gh workflow run load.yml`, with size, count, duration, connections, soak duration, netem conditions and scenarios). It is heavy and long, so it does not run on a schedule or on PRs (run it when the owner asks), and it is not a required check.

- `load (clean)`: every scenario without netem (by default 2 GiB × 3, 5000 connections, a 10-minute soak)
- `load (netem)`: `tcp`, `verify`, `tls`, `http`, `udp` and `latency` with `delay 5ms loss 0.1%` (512 MiB)

The job runs in an Alpine container (musl, the same libc as the release binaries) and builds rproxy with musl too. musl's malloc is slower than glibc's, so the results start with each build's libc and allocator (read from the binary); compare only builds with the same libc and allocator ("Builds compared" warns when they differ).

Results are kept as artifacts (`load-clean` / `load-netem`, 90 days) and in the job summary. The artifact of the last successful manual run (master first, else any branch) is downloaded and the tables show the deltas. The runners are shared 4-core VMs: ignore a single change and look for changes that repeat.

### Comparing optimization ideas (`perf/<topic>` branches)

Each speed-up or memory-reduction idea gets its own `perf/<topic>` branch (for example `perf/splice`, `perf/ktls`, `perf/mimalloc`) and is compared with master by the Load workflow. More ideas, more branches.

```bash
gh workflow run load.yml -f refs=master,perf/splice,perf/sockmap
gh workflow run load.yml -f refs=master,perf/mimalloc -f scenarios=memory,soak -f soak_secs=1800
```

- Every ref in `refs` (comma-separated, default `master`) is built, and the same scenarios run for each on the same runner. So that the runner's ups and downs hit them all alike, each scenario (and each repetition within it) goes through the refs in turn (A, B, C, A, B, C, ...). One rproxy per build runs at the same time on its own address (10.71.1.11 and up) and only the one being measured gets traffic (`memory` and `soak` start fresh processes per build)
- `summary.md` starts with "Builds compared": per scenario, a column per ref and the change against the first ref (the baseline). JSON: the whole `results.json` and one `results-<ref>.json` per ref (`/` becomes `_`)
- More refs take longer (the soak runs per build); pick the scenarios you need with `scenarios`
- `profile: true` (#195): `load (clean)` records rproxy with `perf record -g` (499 Hz) during the small HTTP requests (HTTP/1.1, h2c, h2 over TLS) and keeps flame graphs (`<case>-<target>.svg`) and the heaviest functions (`.txt`, `perf report` self and children) in `profile/` of the artifact. So that stacks can be walked, this job alone builds with frame pointers (`-C force-frame-pointers=yes`), symbols and line tables (releases stay stripped). Recording costs something too, so do not compare its numbers with ordinary runs (measure without `profile` in a separate run). Locally: `PROFILE=1 FLAMEGRAPH=<dir of brendangregg/FlameGraph>` (needs `perf`)
  ```bash
  gh workflow run load.yml --ref perf/h2-cpu -f refs=master,perf/h2-cpu -f scenarios=http -f profile=true
  ```
- Only workflows on the default branch (master) can be dispatched from the Actions page or `gh workflow run`. The scripts (`scripts/load/`) come from the branch the run is started on (`--ref`, master by default)

`scripts/soak.py` (the "Long-running load test" above) is the (manual) loopback soak centered on connection churn, and stays as it is.

## Fuzzing (Fuzz workflow)

The parts that read what arrives from the internet with rproxy's own code are checked with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) (#162), looking for panics, out-of-bounds reads, endless loops and excessive memory use. `fuzz/` is a crate of its own (its own `Cargo.toml`, `Cargo.lock` and workspace), so `cargo build`, `cargo test` and `cargo deny` at the repository root do not include it.

| Target | What it covers | Input format |
|---|---|---|
| `tls_client_hello` | `tls::sni`: the TLS ClientHello (records, handshake, body) | Raw bytes |
| `udp_sni` | The `Sniffer` of `tls::udp_sni`: DTLS ClientHello fragments and QUIC v1 / v2 Initial packets | Datagrams, each prefixed with a 16-bit length |
| `quic_initial` | QUIC again, with frames chosen by the fuzzer encrypted with the Initial keys (so the frame parser behind the AEAD and the CRYPTO reassembly are reached) | Flags (v2), DCID, then (packet number, frames) packets |
| `proxy_header` | `net::source`: the PROXY protocol v1 / v2 headers written towards backends. For any addresses and TLS details the header is well formed and reads back to the same values | `arbitrary` |
| `proxy_header_in` | `net::proxy_in::parse`: PROXY headers received from front ends (#296). No panic on any bytes; a header is never longer than the limits (v1 107, v2 16 + 4096 bytes) or the input; the header's own bytes give the same answer and shorter prefixes ask for more; agreement with `classify`; the addresses read, written again by rproxy, read back the same. The same bytes as a `udp` datagram (#312, `parse_dgram`, `datagram`): never asks for more, only v2 DGRAM (and `LOCAL`, `UNSPEC`) accepted, the header ends within the datagram, and rproxy's own DGRAM header reads back the same | raw bytes |
| `matcher` | `l7::matcher`: parsing and evaluating `match` expressions | The expression, then one per line: host, path, query, method, header, client IP |
| `starttls` | `l4::starttls`: the dialogue with the client before STARTTLS, the mail server's greeting and EHLO reply, the plain-text hand-over | A first byte (protocol, STARTTLS required, bytes per read), then what the peer sends |
| `config` | `config::ConfigDoc::parse` (YAML / JSON) and `RuleRequest::validate` for each rule | A first byte (even: YAML, odd: JSON), then the document |
| `dns_response` | `acme::dnsq::parse_response`: DNS answers read for DNS-01 (CNAME, SOA, TXT, name compression and its loops) | The bytes as they are |
| `tsig_answer` | `acme::rfc2136::verify_answer`: the TSIG of answers to RFC 2136 updates (nothing unsigned or forged passes) | The bytes as they are |
| `http_url` | `net::url::parse`: the http(s) URLs rproxy connects to (#324; from settings and the API, and from the internet like an OIDC discovery document or an ACME directory). An accepted URL has a non-empty host and a port between 1 and 65535, `http::Uri` reads it the same way, and it reads the same again | The bytes as they are (UTF-8) |
| `dpdk_packet` | `rproxy_dpdk::packet` and the forwarder `rproxy_dpdk::engine`: frames the DPDK path receives (Ethernet, ARP, IPv4, UDP, ICMP echo). A UDP datagram with right checksums keeps right checksums and its payload when rewritten and passed on | Frames, each prefixed with a 16-bit length |

The seeds are in `fuzz/seeds/<target>/` (rebuilt with `python3 fuzz/gen_seeds.py`: TLS ClientHellos from Python's ssl, QUIC from the RFC 9001 / 9369 examples in `tests/fixtures/quic`, settings from `contrib/rproxy.example.yaml` and the examples in `docs/en/`).

`.github/workflows/fuzz.yml` runs each target for 60 seconds on pull requests that change `src/`, `crates/` or `fuzz/`, and for 10 minutes every day (not a required check). CI runs on Alpine (musl), so without a sanitizer (`--sanitizer none`; Rust's AddressSanitizer exists only for glibc targets), with debug assertions (integer overflow checks) on. The targeted parsers are Rust without unsafe, so an out-of-bounds access panics on the bounds check even without a sanitizer. The corpus grown by the daily runs is kept in the Actions cache and seeds the next run. When a target crashes, the input is in the `fuzz-artifacts-*` artifact: reproduce it with `cargo +nightly fuzz run <target> <input file>`, and once fixed, add the input to a unit test.

Locally (needs nightly and a C/C++ compiler):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run matcher fuzz/corpus/matcher fuzz/seeds/matcher -- -max_total_time=60
```
