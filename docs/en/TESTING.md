日本語: [TESTING.md](../TESTING.md)

# Test list (rproxy-api)

| How to run | Scope | CI job |
|---|---|---|
| `cargo test` | Unit tests (`src/`) and integration tests (`tests/`) | `test` |
| `RPROXY_TEST_DATABASE_URL=mysql://... cargo test --test db_restore --test persist` | Restoring from MariaDB (`forward_rules`), and storing API-created rules and restoring them across a restart (`rproxy_rules`, #144). Those parts are skipped if the variable is not set | `test` (runs Alpine's MariaDB in the same container) |
| `RPROXY_TEST_PEBBLE=… RPROXY_TEST_PDNS=… RPROXY_TEST_PDNS_SCHEMA=… RPROXY_TEST_SQLITE3=… cargo test --test acme` | ACME (docs/en/ACME.md): starts Pebble (the ACME test CA) and PowerDNS and obtains real certificates through HTTP-01, TLS-ALPN-01 and DNS-01 (the PowerDNS API, RFC 2136 (PowerDNS's DNS UPDATE, TSIG HMAC-SHA256 and SHA512), acme-dns (a small stand-in), CNAME delegation, generic REST). That part is skipped without the variables (the tests of the API's guards always run); `RPROXY_TEST_REQUIRE_ACME=1` turns the skip into a failure | `test` (Alpine's `pebble`, `pdns`, `pdns-backend-sqlite3`, `pdns-doc` and `sqlite` in the same container; `RPROXY_TEST_REQUIRE_ACME=1`) |
| `cargo test --test self_update` | Self-update (#174): fetching and verifying from a signed release mirror (HTTPS), swapping in with a handoff, the launcher (`launch`), rollback. The test of signatures made by the minisign tool is skipped without `minisign` (`RPROXY_TEST_REQUIRE_MINISIGN=1` makes skipping a failure) | `test` (Alpine's `minisign`; `RPROXY_TEST_REQUIRE_MINISIGN=1`) |
| `scripts/test-transparent.sh` | The real path of `source_ip` (network namespaces; no root required) | `transparent` |
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

Fuzzing runs without a sanitizer (Rust's AddressSanitizer exists only for glibc targets; see "Fuzzing" below).

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
| `core/registry.rs` | `a_panicking_listener_marks_only_its_rule_failed` | When a listener panics, only that rule becomes `failed` |
| | `a_stale_supervisor_does_not_touch_a_recreated_rule` | A supervisor task from an old generation does not touch a recreated rule |
| `core/ruleset.rs` | `etags_follow_the_rules_and_the_generation` | The etag does not depend on the order of the rules and changes with the rules or the generation. How `If-Match` may be written (quoted, `W/`, a list, `*`) |
| | `last_transition_moves_only_when_the_status_changes` | `last_transition` moves only when `status` changes (not for a new `reason` alone); deleting starts it over |
| | `conditions_from_the_view` | The status and reason of the four `conditions` from the state and the error's `code` |
| | `label_metrics_lines` | `rproxy_rule_labels` lines (names, keys that end up the same, escaped values) |
| | `readiness_states` | `starting` → ready → `draining` (never ready again) |

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

## Integration tests: live upgrades (`tests/handoff.rs`, #174)

Starts the real binary and hands over with SIGUSR2 and `POST /admin/upgrade` (docs/en/UPGRADE.md).

| Test | What it checks |
|---|---|
| `tcp_connections_survive_and_new_ones_go_to_the_new_process` | TCP connections opened before the handoff (a static rule and an API rule) are carried by the old process to the end. New connections after it are the new process's (the owner of the server-side socket is found in `/proc`). UDP goes on in a new session. API rules (`targets`, `allow_from`) carry over, as do the control API's TCP and Unix sockets. `rproxy_process_start_time_seconds` stays. The old process exits cleanly once its connections end; counters never go down and what the old process counted while it drained is added (exact connection and byte counts). A second handoff through `POST /admin/upgrade` on the Unix socket. A plain stop at the end removes the socket file |
| `api_rules_and_http_counters_carry_over` | Rules of a `persist: true` token come back as `origin: "api"` with `created_by`, `created_at` and `persisted`, without reading the database. `stats.http` by route carries over and keeps counting |
| `a_failed_handoff_keeps_the_old_process` | When the new process cannot connect (the handoff socket's directory is missing): `handoff.failed`, and the old process keeps running. `rproxy_handoffs_total{outcome="failed"}`, `rproxy_build_info`. `POST /admin/upgrade` over TCP is 403 by default |

## Integration tests: shutting down on SIGTERM (`tests/shutdown.rs`, v0.4.1)

Sends SIGTERM to the real binary (section 2 of docs/en/DESIGN-v0.4.x.md, `RPROXY_SHUTDOWN_DELAY` / `_DRAIN`).

| Test | What it checks |
|---|---|
| `by_default_sigterm_stops_at_once` | By default (both `0s`) it stops at once and cuts current connections (as before). `features.graceful_shutdown` |
| `delay_keeps_accepting_then_drain_lets_connections_end` | During `delay`: `/readyz` is 503, `GET /rules` answers, `POST /rules` is `503 shutting_down`, new TCP connections pass. During `drain`: new TCP connections are refused, existing TCP connections and UDP sessions go on, no new UDP session is made. An idle HTTP/1.1 connection is closed and the response of a request in flight carries `Connection: close`. Past `drain` the rest is cut and the process exits (`cut` in `shutdown.done`) |
| `a_second_sigterm_stops_at_once` | A second SIGTERM during `delay` stops at once (`shutdown.now`) |
| `a_second_sigterm_cuts_the_drain_short` | A second SIGTERM during `drain` stops waiting and cuts the connections left |
| `values_out_of_range_stop_the_startup` | A value above one hour stops the startup |

## Integration tests: performance (`tests/performance.rs`, #194, #184)

Starts the real binary and checks the effect of `global.performance` from outside.

| Test | What it checks |
|---|---|
| `the_settings_file_sets_workers_shards_and_pinning` | The settings file wins over the environment: the number of worker threads (`rproxy-wrk-*`), worker i pinned to the i-th listed CPU (`Cpus_allowed_list` in `/proc/<pid>/task/*/status`), `udp_shards: auto` opening as many sockets per port as workers (`/proc/net/udp`), `splice` overridden key by key, `sources` in the `performance` line |
| `the_environment_applies_without_the_file` | Without `global.performance` in the settings file, `RPROXY_WORKERS`, `RPROXY_UDP_SHARDS=auto` and `RPROXY_SPLICE=0` apply. With nothing set, the defaults (one UDP socket, no pinning) |
| `cpus_that_do_not_exist_are_left_out` | CPUs that do not exist are left out with `degraded`; the workers are as many as the usable CPUs |

## Integration tests: self-update (`tests/self_update.rs`, #174)

An HTTPS mirror (a small server in the test; binaries are answered with a redirect, as GitHub does) carries this binary signed under the next patch number.

| Test | What it checks |
|---|---|
| `a_signed_patch_is_swapped_in_and_a_forged_one_refused` | The new patch is picked from the signed index (with a gap in the numbers and another minor listed); `POST /admin/update` fetches and verifies it and swaps it in with a handoff (the new process runs the cached binary); after `RPROXY_UPDATE_HEALTHY` it is the good version. A patch whose signature does not match its binary is refused (`error` in `GET /admin/update`) and never cached |
| `launch_runs_the_newest_patch_follows_upgrades_and_rolls_back` | `rproxy-api launch` picks and starts the newest patch (on trial), passes SIGUSR2 on and follows the main process after the handoff; a version on trial that dies is marked bad and the image's version starts instead; SIGTERM stops the server and the launcher |
| `a_trial_stopped_by_a_signal_is_not_bad_and_bad_marks_can_be_cleared` | A version on trial stopped by SIGTERM to the launcher is not marked bad (the `trial` is cleared); `rproxy-api update-clear-bad --version` takes a bad mark off (security review M1) |
| `signatures_of_the_minisign_tool_verify` | Keys and signatures made by the minisign tool (the default prehashed form and the legacy one) verify |

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
| `rules_survive_a_restart_with_mariadb` | MariaDB (`RPROXY_TEST_DATABASE_URL`) and the real binary: a created (and changed) rule is written to `rproxy_rules` and comes back as `api` after a restart. On the UI's key the UI's rule is used (`restore.conflict`); other nodes' rows stay out. Deleting removes the row |
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
| `tests/check_config.rs` | `rproxy-api --check-config` (#140; a key readable by others is an error, fine with `global.files.owner_check: off`): validates the settings file the way startup and reloads do, opens nothing, reports through its exit code, text and JSON |
| `tests/startup.rs` | Starting the real binary: configuration mistakes stop it; problems in the environment (permissions, a busy port) leave it running in a restricted mode that recovers. TLS on the control API, reloads on SIGHUP, `GET /readyz` |
| `tests/targets.rs` | Several destinations (#98): `targets`, `balance` (round_robin / least_conn / failover), `backup`, `health_check` (L4 and services of `http` rules). The default behaviour without `outlier_detection` |
| `tests/listen.rs` | One rule listening on several addresses (`extra_listen_addrs`, #99) |
| `tests/udp_shards.rs` | Reading a UDP port with several `SO_REUSEPORT` sockets (#194): no session opened twice, the reply source (#137), counters add up |
| `tests/udp_source.rs` | UDP replies on wildcard listeners leave from the address the client sent to (#137; to 127.0.0.2) |
| `tests/udp_sni.rs` | UDP `tls.mode: sni` (#130) with real QUIC (quinn) and DTLS clients and backends |
| `tests/http.rs` | L7 routing of `http` rules |
| `tests/http3.rs` | HTTP/3 with `http3: true` (#56), with a quinn + h3 client |
| `tests/http_auth.rs` | Authentication middlewares (#59): `basic_auth`, `forward_auth`, `oidc` |
| `tests/http_resilience.rs` | Health checks, `sticky`, `compress`, `buffering`, `retry`, `circuit_breaker`, `errors` and kept backend connections (#61, #63, #64, #65) |
| `tests/http_semantics.rs` | The HTTP forwarding contract ("HTTP forwarding semantics" in docs/en/API.md): 504 when an HTTP/2 backend's streams are taken, and more connections (security review M6); client certificate headers dropped on an HTTPS rule without `client_auth` over HTTP/1.1, HTTP/2 and HTTP/3 (security review H1); cookies, repeated fields, hop-by-hop headers, bodies, large headers and timeouts with HTTP/1.1, HTTP/2 and HTTP/3 clients. HTTP/2 backends (#233): one multiplexed h2c connection, trailers both ways (including a gRPC trailers-only answer), `te: trailers`, h2 (TLS + ALPN) and `auto` (with backends picking `h2` or `http/1.1`), 502 when the backend does not pick `h2`, `protocol` against the URL scheme |
| `tests/gateway_l7.rs` | L7 for the Gateway API (#224, #226-#232, #235): `add` of `headers`, redirect `status`, route `timeouts` (504, per attempt, cutting a body off), `replace_host`, per-server middlewares, `cors` (preflights, wildcard origins), `status` of `retry`, `mirror` (share, bodies, an unreachable mirror), `status` servers, `features`. Preflights from origins not allowed answered by rproxy, `retry` again with one server, `X-Client-Verify` and `X-Forwarded-Client-Cert` of client certificates (`optional_no_verify`, forged headers removed) (#238). Certificate headers cannot be forged on plain rules without `client_auth`, Upgrades, `forward_auth` or `mirror`, and the X-Forwarded-For of `mirror` copies (security review H1, M5) |
| `tests/backend_tls.rs` | A service's `tls` (#236): its CA and SNI name, `subject_alt_names` (DNS names and URIs), a client certificate towards the backend, `https://` backends from a plain-HTTP rule, mistakes in shape and files |
| `tests/crowdsec.rs` | The `crowdsec` middleware (a fake LAPI and AppSec) |
| `tests/acme.rs` | ACME (#208): the API's guards (always run) and obtaining real certificates with Pebble and PowerDNS (table above) |
| `tests/traefik_convert.rs` | `contrib/traefik2rproxy.py` converts `tests/fixtures/traefik/` and rproxy accepts the result. Skipped without python3 and PyYAML (CI sets `RPROXY_TEST_REQUIRE_PYTHON=1`) |

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

| `scripts/interop/crowdsec.sh` | CrowdSec (LAPI, agent, AppSec) | CrowdSec detects and bans from rproxy's logs, and rproxy (L7 `crowdsec`, L4 `crowdsec: true`, AppSec) blocks. Clients with documentation addresses (IPv4 and IPv6) are banned; a private address is whitelisted and never banned |

Results for a 10000-port range rule (UDP) (GitHub Ubuntu runner, 2026-09): creation about 0.2 seconds, file descriptors +10000 (back to the original after deletion), RSS about +94 MiB.

They all run as root inside a throwaway container (`alpine:3.24` for mail and media, CrowdSec's official image for crowdsec), and the scripts configure and start the servers themselves. Do not run them on your own machine.

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
| `proxy_header` | `net::source`: PROXY protocol v1 / v2 headers. rproxy only writes them, so the target checks that for any addresses and TLS details the header is well formed and reads back to the same values | `arbitrary` |
| `matcher` | `l7::matcher`: parsing and evaluating `match` expressions | The expression, then one per line: host, path, query, method, header, client IP |
| `starttls` | `l4::starttls`: the dialogue with the client before STARTTLS, the mail server's greeting and EHLO reply, the plain-text hand-over | A first byte (protocol, STARTTLS required, bytes per read), then what the peer sends |
| `config` | `config::ConfigDoc::parse` (YAML / JSON) and `RuleRequest::validate` for each rule | A first byte (even: YAML, odd: JSON), then the document |
| `dns_response` | `acme::dnsq::parse_response`: DNS answers read for DNS-01 (CNAME, SOA, TXT, name compression and its loops) | The bytes as they are |
| `tsig_answer` | `acme::rfc2136::verify_answer`: the TSIG of answers to RFC 2136 updates (nothing unsigned or forged passes) | The bytes as they are |

The seeds are in `fuzz/seeds/<target>/` (rebuilt with `python3 fuzz/gen_seeds.py`: TLS ClientHellos from Python's ssl, QUIC from the RFC 9001 / 9369 examples in `tests/fixtures/quic`, settings from `contrib/rproxy.example.yaml` and the examples in `docs/en/`).

`.github/workflows/fuzz.yml` runs each target for 60 seconds on pull requests that change `src/` or `fuzz/`, and for 10 minutes every day (not a required check). CI runs on Alpine (musl), so without a sanitizer (`--sanitizer none`; Rust's AddressSanitizer exists only for glibc targets), with debug assertions (integer overflow checks) on. The targeted parsers are Rust without unsafe, so an out-of-bounds access panics on the bounds check even without a sanitizer. The corpus grown by the daily runs is kept in the Actions cache and seeds the next run. When a target crashes, the input is in the `fuzz-artifacts-*` artifact: reproduce it with `cargo +nightly fuzz run <target> <input file>`, and once fixed, add the input to a unit test.

Locally (needs nightly and a C/C++ compiler):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run matcher fuzz/corpus/matcher fuzz/seeds/matcher -- -max_total_time=60
```
