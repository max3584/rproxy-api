日本語: [TESTING.md](../TESTING.md)

# Test list (rproxy-api)

| How to run | Scope | CI job |
|---|---|---|
| `cargo test` | Unit tests (`src/`) and integration tests (`tests/`) | `test` |
| `RPROXY_TEST_DATABASE_URL=mysql://... cargo test --test db_restore` | Restoring from MariaDB. Skipped if the variable is not set | `test` (uses a MariaDB service container) |
| `scripts/test-transparent.sh` | The real path of `source_ip` (network namespaces; no root required) | `transparent` |
| `cargo bench --bench '*'` | Performance benchmarks (`benches/`, criterion). `cargo test` runs each benchmark once to check that it still works | `test` (once), `Benchmarks` (comparison) |
| `cargo +nightly fuzz run <target>` | Fuzzing the hand-written parsers (see "Fuzzing" below) | `fuzz` in the Fuzz workflow |
| `scripts/load/run.sh` | Load and soak tests with large, long transfers (transfer efficiency; see "Load and soak tests" below) | Load workflow (manual only) |

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

- Continuous forwarding for many hours (the Load workflow's soak can do it when run manually with a long `soak_secs`)
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


## Load and soak tests (Load workflow, #183)

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

Results are kept as artifacts (`load-clean` / `load-netem`, 90 days) and in the job summary. The artifact of the last successful manual run (master first, else any branch) is downloaded and the tables show the deltas. The runners are shared 4-core VMs: ignore a single change and look for changes that repeat.

`scripts/soak.py` (the "Long-running load test" above) is the weekly loopback soak centered on connection churn, and stays as it is.

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

`.github/workflows/fuzz.yml` runs each target for 60 seconds on pull requests that change `src/` or `fuzz/`, and for 10 minutes every day (not a required check). The corpus grown by the daily runs is kept in the Actions cache and seeds the next run. When a target crashes, the input is in the `fuzz-artifacts-*` artifact: reproduce it with `cargo +nightly fuzz run <target> <input file>`, and once fixed, add the input to a unit test.

Locally (needs nightly and a C/C++ compiler):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run matcher fuzz/corpus/matcher fuzz/seeds/matcher -- -max_total_time=60
```
