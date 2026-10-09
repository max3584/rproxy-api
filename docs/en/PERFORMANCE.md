日本語: [PERFORMANCE.md](../PERFORMANCE.md)

# Performance work log (rproxy-api)

What was tried for speed, CPU and memory, and how it turned out. It records **what was not adopted and why**, not only what was, so the same things aren't tried again and can be revisited when conditions change.
The work is tracked in the milestone "performance" with the label "area: performance". How to measure is in [TESTING.md](TESTING.md), "Load and soak tests" (`load.yml`; `refs` measures several branches in turn on the same runner).

## Measurement conditions and caveats

- A GitHub runner (4 vCPU), with virtual links (network namespaces and veth). Expect smaller gaps on real NICs.
- Runners vary a lot from run to run (the same master gave 27k to 58k req/s). **Only compare columns within one run.** Two identical builds side by side differ by about 5%.
- Before #197, `load.py`'s h2load appended latencies to the same file. **In runs before that, HTTP p50 / p99 are wrong for every column except the first.**
- Before #200, `load.yml`'s concurrency group was per branch, so runs started from the same branch cancelled each other.
- How other projects (HAProxy, nginx, Envoy, Pingora, linkerd2-proxy, Cilium, …) handle these is summarised in comments on issues #184, #185, #194 and #195.

## Baseline (v0.3.17 / v0.3.18)

| Measurement | direct | rproxy | HAProxy |
|---|---|---|---|
| TCP, 1 stream | 28 Gbit/s | 6–7 Gbit/s | 10.6 Gbit/s |
| L4 data per CPU | – | 0.65–0.85 GiB per CPU-second | 1.2–1.3 |
| HTTP/2 small requests | – | about 30k req/s | about 90k req/s |
| Memory per TCP connection | – | 17.7 KiB idle / 25.7 KiB busy | about 3.3 KiB |
| UDP, 64 bytes at full rate | about 470k pps | about 240k pps (lost in the kernel receive buffer) | – |

## Adopted (v0.3.19)

| Change | PR | Effect (vs v0.3.18) | Notes |
|---|---|---|---|
| TCP relay holds a buffer only while data is ready (`src/l4/relay.rs`) | #198 | 7.5 KiB per connection (−58 to −71%), TCP 1 stream more than 2× | 32 KiB buffers. TLS is read 8 KiB at a time (reading 16–32 KiB made TLS termination 14–25% slower) |
| splice(2) for large transfers only (`src/l4/splice.rs`) | #202 | About 7× data per CPU on large transfers (with #198), TCP 8 streams 3.7× | Plain TCP only. Switches after 4 full 32 KiB reads in a row. Pipes are returned while idle. Mind `pipe-user-pages-soft` when not running as root |
| HTTP/2 CPU (reusing upstream connections, trimming per-request work) | #197 | HTTP/2 +50–60%, latency about −30% | Up to 1024 idle upstream connections per server, closed after 4 s. Peak memory is higher under heavy load |
| UDP batching (`recvmmsg` / `sendmmsg`) and a larger receive buffer | #199 | +65% delivered, loss 57% → 21% | `SO_REUSEPORT` sharding defaults to 1 socket (see below) |
| mimalloc as an option (`--features alloc-mimalloc`) | #201 | HTTP +9–26%, per CPU +17–31% | The default stays musl's malloc (see below) |

## Not adopted

### aws-lc-rs as the rustls crypto provider (#196, closed)
- **Tried:** switched rustls, tokio-rustls and quinn from ring to aws-lc-rs.
- **Result** (run 37386709216): TLS termination −3%, handshakes/s −6%, **handshakes per CPU +22%**, HTTP/2 over TLS +3% (noise). Binary 5–14% larger, RSS +2 MiB, build +30–50 s. dtls depends on ring, so two crypto libraries would ship.
- **Why not:** ring already uses AES-NI / VAES; crypto was not the bottleneck (TLS termination is limited by record handling and copies).
- **Found on the way:** with both rustls features `ring` and `aws-lc-rs` enabled, rustls can't pick a default provider and DTLS mTLS verification panics. With ring only, as today, it doesn't happen.
- **Revisit when:** handshake-heavy use, or post-quantum key exchange (X25519MLKEM768) is needed.

### kTLS (#204, closed)
- **Tried:** for L4 TLS termination, after the rustls handshake, extract the secrets (`dangerous_extract_secrets`), hand them to `TCP_ULP tls` with `TLS_TX` / `TLS_RX`, and read/write plaintext. All 6 combinations of TLS 1.2 / 1.3 × AES-GCM 128/256 / ChaCha20 worked correctly.
- **Result** (run 37394020575): data per CPU +3%, **throughput −18%**, handshakes +6% (noise). With the original 8 KiB buffers, −33%.
- **Why not:** ring's userspace AES-GCM is about as fast as the kernel's, and the plaintext copy remains.
- **Limits:** a KeyUpdate from the client closes the connection (rustls's buffered API can't give the next keys); connections near the AES-GCM record limit are closed too.
- **Revisit when:** trying kTLS together with splice so plaintext never enters userspace (as HAProxy 3.3's kTLS + splice).

### splice from the first byte
- Costs more CPU on small exchanges (64-byte ping-pong, 64 connections: −12 to −13% per CPU). The adopted version (#202) switches only during sustained large transfers.
- The first version used more FDs (6 per idle connection, from pipes held while idle and a pipe pool). Fixed by returning pipes while idle, a small pool, and emptying the pool when unused.

### 64 KiB relay buffers
- Only slightly faster than 32 KiB, while retransmits on 8-stream iperf3 went 379 → 1,706 and up to about 2 MiB more is pooled per thread. 32 KiB was chosen.

### jemalloc
- Doesn't build for armv7 (zig cc rejects jemalloc's `-mcpu` flag). Every Alpine job would need `make`. aarch64 needs `JEMALLOC_SYS_WITH_LG_PAGE` for 16 KiB / 64 KiB page kernels. 2.4× idle RSS and RSS kept growing in the soak (1.18). Not faster than mimalloc.

### mimalloc as the default allocator
- Faster (HTTP +9–26%), but +8 MiB idle and +12 MiB after load. Following the minimal-memory policy, the default stays musl and mimalloc is opt-in (#201).
- The 64 KiB UDP session buffers: under musl, untouched pages didn't count in RSS; under mimalloc they all did (650 MiB on a 10000-port range). These receive buffers now come from `std::alloc::System` (`RecvBuf`).

### UDP sharding by default (`SO_REUSEPORT`)
- One socket per worker added +3.5% delivered and cut loss 45% → 34%, but used more CPU, and per-CPU throughput was better without it. Faster receiving moved the bottleneck to session handling and the receiver. Default is 1; `global.performance.udp_shards` (v0.4; `auto` = the workers) or `RPROXY_UDP_SHARDS` raises it. Revisit on machines with spare cores.
- UDP GRO / GSO (quinn-udp) isn't used: quinn-udp sets DF (`IP_MTU_DISCOVER`), which changes behaviour for generic UDP forwarding, and GRO barely helps with small packets from many clients.

### Boxing the large HTTP/2 futures
- Meant to reduce memcpy; on its own it made no difference, so it was reverted (within #197).

### Researched but not tried
- **eBPF sockmap:** Cilium removed it in 1.14; many pitfalls for socket-to-socket forwarding.
- **io_uring:** Google disabled it on production servers; little published data.
- **XDP, busy poll:** hard to verify on GitHub runners.
- **Thread-per-core runtime:** Pingora also defaults to work stealing. TCP / HTTP stay as they are.

## Next candidates
- Forwarding in the kernel (#260, in progress): `global.performance.ebpf` (plain L4 TCP through a BPF sockmap) and `global.performance.xdp` (UDP through AF_XDP). Opt-in; only fast paths whose startup test with real data passed are used (`rproxy-api --check-kernel`). The framework (settings, tests, `GET /capabilities`) comes first, then the fast paths one by one, with their results recorded here.
  - **sockmap (`ebpf.tcp: sockmap`, plain L4 TCP)**: after rproxy sets up both TCP sockets (handshake, PROXY protocol, `source_ip`, and the `allow_from` / `crowdsec` / `limits` admission checks all in user space), it puts the two sockets in a per-connection sockmap (2 slots) where a tiny stream-verdict BPF program (which side is told by `skb->local_port`) hands each one's bytes to the other — socket to socket inside the kernel, no system calls or copies (splice, one level up). The aya toolchain (nightly, rust-src, bpf-linker) is not pulled in — for disk and the 6 release targets — so the ~9-instruction BPF bytecode is loaded straight through bpf(2) (the default build is unchanged, no new dependency). There are no byte/bandwidth BPF counters yet, so rules with `bandwidth` keep splice; byte totals come from `TCP_INFO` at the end. **Finding**: the kernel (6.17) does not pass a FIN through a sockmap redirect (a user-space read still returns EOF). So rproxy passes the half-close on: on EOF from one side it waits until everything that side sent has reached the other socket's send queue (`TCP_INFO` received bytes against the other's acked + `TIOCOUTQ`), then `shutdown(SHUT_WR)`s the other (the redirect goes through a backlog, so an early FIN would overtake data). Correctness is checked in the CI root job (`offload`): the startup test (loopback pairs, >64 KiB, split writes, SHA-256, FIN, and EOF on the sockmap socket) and a real rproxy relaying a round trip over sockmap (`tests/kernel_offload.rs`). **The throughput measurement (the Load workflow against master) is still to come; results will be recorded here.**
- HTTP/2: the profile still shows memcpy (about 11%), the allocator (about 12%) and kernel wakeups (about 7%). Fewer, larger h2 writes.
- Multi-core use (#194): adapt to queue depth (per-role pipeline, per-core parallelism, backpressure).
- Memory (#185): share UDP session buffers per worker.
