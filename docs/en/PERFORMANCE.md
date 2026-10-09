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

### Relaying plain L4 TCP inside the kernel with an eBPF sockmap (#260, #265, closed)
- **Tried:** after rproxy sets up both TCP sockets as usual (handshake, PROXY protocol, `source_ip`, and the `allow_from` / `crowdsec` / `limits` checks in user space), the two sockets go into a per-connection SOCKMAP (2 slots) where a tiny stream-verdict BPF program (direction told by `skb->local_port`; the bytecode loaded straight through bpf(2)) hands each one's bytes to the other — socket to socket inside the kernel, no system calls or copies. Checked by the startup test with real data (loopback pairs, >64 KiB, split writes, SHA-256, data and FIN back to back) and by the testing-only always-on cross-check (`offload-verify`). CI kernel 6.17.0-azure, privileged container.
- **Kernel quirks found and fixed on the way:**
  1. The redirect does not pass a FIN on (a user-space read still returns EOF). → rproxy `shutdown(SHUT_WR)`s the other socket once the data has reached its send queue (`TCP_INFO` received bytes against the other's acked + `TIOCOUTQ`); the redirect goes through a backlog, so an early FIN would overtake data.
  2. Redirecting the empty skb (the FIN) makes the kernel's backlog put EPIPE on the other socket (a send returning 0 counts as an error; moved 458,866 / queued 458,865, the difference being the FIN's sequence number). → the verdict returns `SK_PASS` for empty skbs.
  3. When both sides close at once, a `shutdown` after the data was through fails with ENOTCONN / EPIPE, which was taken as a relay failure and reset the connection. → best effort.
  4. Bytes queued before the sockets went into the sockmap (a client that sends at once) were picked up by the user-space read (the verdict only runs on the next data_ready). → `SO_RCVLOWAT` is set right after insertion, which runs the verdict.
- **Why not adopted** (`tests/integrity.rs` over sockmap with offload-verify): with 4 connections each sending 8 MiB both ways at once, one sometimes stalled. Client → backend: 7,962,624 bytes redirected but 4,816,843 in the backend socket; the backend's send queue was empty and everything written was acknowledged (not TCP flow control). **About 3 MB stayed in the psock redirect backlog with no progress for more than 5 s** (backend → client also had 64 KiB left, and the client-side socket got EPIPE).
- **Why it cannot be made safe:** sending a stalled connection back to user space drops what is left in the backlog (it would break the promise never to show a cut-off stream as complete). The startup test with test data cannot be relied on to reproduce this parallel two-way stall (the short tests and a real rproxy's 256 KiB round trip all passed). The same call Cilium made when it removed the feature in 1.14.
- **Revisit if:** a kernel fixes the backlog stall, and a test that reproduces it (parallel two-way bulk transfers checked by offload-verify) passes.
- **Kept:** the startup-test framework, `--check-kernel` and `offload-verify`, for AF_XDP (#260 stage 3) and DPDK (#261). The four fixes are a reference for any fast path that hands sockets over.

### Passing L4 UDP through AF_XDP (#260, #266, paused)
- **What is in**: an XDP program that steers only the rules' UDP ports to an AF_XDP socket (`bpf/xdp-redirect/`, aya-ebpf; the built object is committed), the UMEM and the four rings (`src/net/offload/xdp/`, xdpilone), frame parsing and reply building, and the startup self-test (`--check-kernel`). Cargo feature `kernel-offload` (not in the default build or the releases).
- **What is not**: carrying the UDP data plane (`l4/udp.rs`) over AF_XDP. Even when the self-test passes it is not used at startup; `GET /capabilities` `performance.xdp` shows `active: false` (reason: self-test passed, the data path is not in this build).
- **Why it stopped** (owner's decision): the gains depend on kernel and NIC tuning, and there is no real hardware to measure on. Building the data path would only be checked for correctness in CI, adding complexity without knowing whether it is faster. Tuning is left for another time.
- **Tuning needed in production** (the premise when resuming):
  - NIC and driver supporting native XDP and AF_XDP zero-copy (veth and most virtual NICs only do generic and copy, the slow path).
  - Queues: the number of NIC RX queues and RSS (which queue a packet lands on), IRQ CPU affinity. **Bind an AF_XDP socket on every RX queue** (the program hands a packet to the socket of the queue it arrived on; packets on a queue without one go up the normal stack).
  - Privileges: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW` (privileged on Kubernetes).
  - Measuring: compare with the current `recvmmsg` / `sendmmsg` on the same NIC (64-byte pps, loss, work per CPU), and with DPDK (#261).
- **What tripped the startup self-test** (CI, kernel 6.17.0-azure, privileged container):
  1. A BPF object embedded with `include_bytes!` is not aligned, and the ELF parse failed (`error parsing ELF data`). → aya's `include_bytes_aligned!`.
  2. veth has one queue per CPU by default, so datagrams landed on queues other than 0 and missed the socket on queue 0. → the test's veth has one queue (in production, bind every queue).
  3. With both veth ends in one network namespace, the kernel delivers to the peer's address as local and never uses the veth (the program counted 0 UDP packets). → the sender gets its own namespace and the veth peer is created in it (`IFLA_NET_NS_FD`).
  4. Zero-copy bind on veth is `Not supported` (copy mode works).
  - To find these, the self-test's failure reason includes the program's counters (UDP seen, port matched, redirect failed) and the socket's `XDP_STATISTICS`.
- **Resuming**: on `perf/af-xdp`: (1) sockets on all RX queues, (2) `l4/udp.rs` receive/send over the XSK (falling back to the current path), (3) `offload-verify` checks (packet and byte counts, stalls, content), (4) the integrity / UDP tests over AF_XDP, (5) measuring on real hardware.

### Researched but not tried
- **io_uring:** Google disabled it on production servers; little published data.
- **XDP, busy poll:** hard to verify on GitHub runners.
- **Thread-per-core runtime:** Pingora also defaults to work stealing. TCP / HTTP stay as they are.

## Next candidates
- Forwarding in the kernel (#260, #261, paused): AF_XDP goes as far as the startup self-test ("Passing L4 UDP through AF_XDP" above); DPDK as far as a separate build checked for correctness in CI. Both need NIC/queue tuning and real hardware to measure, left for another time.
- HTTP/2: the profile still shows memcpy (about 11%), the allocator (about 12%) and kernel wakeups (about 7%). Fewer, larger h2 writes.
- Multi-core use (#194): adapt to queue depth (per-role pipeline, per-core parallelism, backpressure).
- Memory (#185): share UDP session buffers per worker.
