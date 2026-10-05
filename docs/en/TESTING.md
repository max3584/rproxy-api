日本語: [TESTING.md](../TESTING.md)

# Test list (rproxy-api)

| How to run | Scope | CI job |
|---|---|---|
| `cargo test` | Unit tests (`src/`) and integration tests (`tests/`) | `test` |
| `RPROXY_TEST_DATABASE_URL=mysql://... cargo test --test db_restore` | Restoring from MariaDB. Skipped if the variable is not set | `test` (runs Alpine's MariaDB in the same container) |
| `scripts/test-transparent.sh` | The real path of `source_ip` (network namespaces; no root required) | `transparent` |
| `cargo bench --bench '*'` | Performance benchmarks (`benches/`, criterion). `cargo test` runs each benchmark once to check that it still works | `test` (once), `Benchmarks` (comparison) |
| `cargo +nightly fuzz run <target>` | Fuzzing the hand-written parsers (see "Fuzzing" below) | `fuzz` in the Fuzz workflow |

## CI environment

GitHub's runners are Ubuntu VMs only, so the jobs run inside Alpine containers (`container: alpine:3.22`: musl, the same libc as the release binaries and the .deb) (#191). Packages come from apk, Rust is rustup's stable (nightly for fuzzing).

| Workflow / job | Environment |
|---|---|
| CI `test` and `package`, Benchmarks, Integrity, Soak, Fuzz, Dependencies (cargo-deny), Milestone, Interop `build`, `mail` and `media` | `alpine:3.22` |
| CI `transparent` | `alpine:3.22` (privileged: namespaces, veth, nft / iptables) |
| Interop `crowdsec` | `crowdsecurity/crowdsec` (CrowdSec's official image, Alpine-based; Alpine has no CrowdSec package), privileged |
| Cross build and Release `build` | `alpine:3.22`. x86_64 musl natively, the others cross-built with cargo-zigbuild (zig); gnu is linked against glibc 2.17 (`scripts/build-release.sh`) |
| Release `apt` and Cross build `apt (dry run)` | `debian:13-slim` (apt-ftparchive, which builds the apt repository, is a Debian tool) |
| CI `deb` and `install` | Directly on the runner VM (Ubuntu). They check installing the .deb, upgrading from an apt repository and purging, and install.sh (which requires systemd), so systemd has to run as PID 1, which a container cannot do. They build no Rust: they check the musl binary and .deb made by the `package` job (Alpine) |

Fuzzing runs without a sanitizer (Rust's AddressSanitizer exists only for glibc targets; see "Fuzzing" below).

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
| | `ehlo_reply_with_non_utf8_bytes_does_not_panic` | Non-UTF-8 bytes or multi-byte characters in the mail server's EHLO reply do not cause a panic (an input found by fuzzing, #162) |
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
| `terminate_does_not_stall_under_backpressure` | With a small client send buffer, 16 round trips of 1 MiB through a terminating rule; every byte comes back intact each time (#187) |

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

When one iteration of `dataplane` makes no progress for 30 seconds (`STALL`), the benchmark treats it as a stall and panics with what it was doing (bytes written and read back, whether the TLS client still holds unsent records) and the rule counters (#187). Each workflow step also has a timeout (20 minutes). A TLS stream must be flushed after `write_all`: when the socket was full, the last records stay in rustls until then (the cause of the stall in #187, on the client side; rproxy's `copy_bidirectional` flushes whenever it has nothing to read).

For telling the causes apart there is `examples/stall_probe.rs` (the `stall-probe` job of `bench.yml`). It repeats the same 1 MiB echo hundreds of times with a 3-second timeout per iteration, across L4 TCP, TLS termination and TLS without rproxy, the client flushing or not, the default or a 4 KiB send buffer, and rproxy in the same process or as its own process (`--rproxy target/release/rproxy-api`), and prints how many iterations stalled and how long they took. In #187 only TLS clients that did not flush stalled, just the same without rproxy and with rproxy as its own process, and their rustls still held unsent records (`wants_write = true`). The job fails if a client that flushes stalls. Locally: `cargo run --release --example stall_probe -- --iters 300`.

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

| `scripts/interop/crowdsec.sh` | CrowdSec (LAPI, agent, AppSec) | CrowdSec detects and bans from rproxy's logs, and rproxy (L7 `crowdsec`, L4 `crowdsec: true`, AppSec) blocks. Clients with documentation addresses (IPv4 and IPv6) are banned; a private address is whitelisted and never banned |

Results for a 10000-port range rule (UDP) (GitHub Ubuntu runner, 2026-09): creation about 0.2 seconds, file descriptors +10000 (back to the original after deletion), RSS about +94 MiB.

They all run as root inside a throwaway container (`alpine:3.22` for mail and media, CrowdSec's official image for crowdsec), and the scripts configure and start the servers themselves. Do not run them on your own machine.

## Long-running load test (Soak workflow)

`scripts/soak.py` keeps putting TCP and UDP load on rproxy-api (release build), and writes RSS, fd count, and connection count to a CSV every 10 seconds.

- TCP: 200 workers that repeatedly open and close connections, and 20 connections that stay open and keep sending
- UDP: 100 clients that send while changing their source port (with `udp_idle_secs: 5`, sessions are repeatedly created and discarded)
- Pass criteria: after the load stops, the fd count returns to the original (within +20), RSS in the second half does not exceed 1.5 times that of the first half, and forwarding failures are 0.1% or less

`.github/workflows/soak.yml` runs only on demand (no schedule, not on pull requests): trigger it from the Actions page or with `gh workflow run soak.yml -f duration=<seconds>` (default 3600), and the CSV is kept as an artifact. Locally: `cargo build --release && ulimit -n 65536 && scripts/soak.py --duration 600`.


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

The seeds are in `fuzz/seeds/<target>/` (rebuilt with `python3 fuzz/gen_seeds.py`: TLS ClientHellos from Python's ssl, QUIC from the RFC 9001 / 9369 examples in `tests/fixtures/quic`, settings from `contrib/rproxy.example.yaml` and the examples in `docs/en/`).

`.github/workflows/fuzz.yml` runs each target for 60 seconds on pull requests that change `src/` or `fuzz/`, and for 10 minutes every day (not a required check). CI runs on Alpine (musl), so without a sanitizer (`--sanitizer none`; Rust's AddressSanitizer exists only for glibc targets), with debug assertions (integer overflow checks) on. The targeted parsers are Rust without unsafe, so an out-of-bounds access panics on the bounds check even without a sanitizer. The corpus grown by the daily runs is kept in the Actions cache and seeds the next run. When a target crashes, the input is in the `fuzz-artifacts-*` artifact: reproduce it with `cargo +nightly fuzz run <target> <input file>`, and once fixed, add the input to a unit test.

Locally (needs nightly and a C/C++ compiler):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run matcher fuzz/corpus/matcher fuzz/seeds/matcher -- -max_total_time=60
```
