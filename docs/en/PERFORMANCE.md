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

## Experiment: the DPDK data plane (#261)

Takes the NIC away from the kernel and drives it from user space with a DPDK PMD, to see how far the limits of L4 UDP forwarding (pps, latency) go. **Whether to adopt it is decided on numbers from real hardware** (a GitHub runner can only check correctness).

### Shape
- A separate build only: the cargo feature `dpdk` (`cargo build --release --features dpdk`; needs DPDK 22.11 or later through `pkg-config libdpdk`). Not in the default build or the six release targets (musl, armv7). If shipped, it would be a separate artifact for x86_64 / aarch64 glibc (DPDK linked dynamically), once adopted.
- The C part is only a thin wrapper, `crates/rproxy-dpdk/src/shim.c` (DPDK's fast-path functions are static inline). Frame parsing and rewriting, sessions and ARP are Rust (`packet`, `engine` in `crates/rproxy-dpdk`), unit tested and fuzzed (`dpdk_packet`) without DPDK.
- UDP only. TCP would need a user-space TCP stack and is left out (TCP goes through #260's eBPF). L7, TLS and the control API stay on the kernel.
- Which rules go through DPDK: **every UDP rule whose listen address is an address of a DPDK port** (the kernel does not have that address, so there is nothing else to choose). A per-rule `performance: dpdk` does not seem needed (there is no point splitting the same address between the kernel and DPDK). Rules using what the DPDK path cannot do (`source_ip` PROXY protocol / transparent, `tls` DTLS / sni, `http`) cannot be created on such an address (`bind_failed` with the reason). `allow_from`, `geoip`, `crowdsec`, `limits`, `bandwidth`, port ranges, `targets` / `balance` / health checks, `udp_idle_secs`, the stats and the `conn.open` / `conn.close` lines work as on the kernel path (the lines carry `path: dpdk`).
- How: each client session gets a NAT port on the source address (32768-60999, rule ports skipped); the backend's answers to that port go back to the client (the same shape as the kernel path's connected upstream socket). It answers ARP for its addresses, asks for the MACs of backends / the gateway, and answers ping. IPv4 only (IPv6, VLAN tags and IP fragments are dropped). Each lcore takes some RX queues and has its own TX queue on every port (`tx_queues` at least the number of lcores). The rule table is copied into each lcore (taken again only when its version changes); sessions sit behind one Mutex per NAT port (contended only when two lcores touch the same session).
- The startup check (the owner's rule, the same framework as #260, `net::offload::probe`): hugepages → EAL → mempool → **test datagrams through the forwarder in real mbufs over rproxy's loopback port (`net_ring_rpchk`)**, compared (ARP both ways, `burst` datagrams of 8 sizes from a client to the backend, the backend's answers; addresses, ports, MACs, checksums, payload) → the configured ports are started (link state). If any step fails it is not used (`reason`) and the kernel path runs (`fallback: false` stops the start). The result goes to `performance.probe` (`feature: dpdk`), `degraded` (`part: global.performance.dpdk`), `GET /capabilities` `performance.dpdk`, and the `rproxy-api --check-kernel` table (the `dpdk.enabled=true` row and each step).
- Nothing counts or watches while it runs. Anomalies are logged when handled, at the existing levels (TX queue full: `dpdk.tx_full` at debug; backend MAC unknown, NAT ports exhausted: the datagram counts in `stats.dropped`).

### CI (correctness only)
`.github/workflows/dpdk.yml` (on the runner VM, Ubuntu's `libdpdk-dev`):
- `crates/rproxy-dpdk` unit tests (no DPDK) and `tests/ring.rs` (no root, `--no-huge`): the startup check through `net_ring`, the lcore loop through a `net_memif` pair (500 datagrams there and back, compared).
- `scripts/test-dpdk.sh` (sudo, hugepages): the real `rproxy-api` with two ports, `net_tap` (`dtap0`) and `net_af_packet` (veth), against kernel UDP sockets (echo servers, 20 clients × 70 datagrams of 0-1472 bytes), contents compared. Also a rule across ports (client on af_packet, backend on tap), a port range, ping, `GET /capabilities`, `--check-kernel`, and the fallback when it cannot be used (`true`: degraded; `false`: no start).
- The runner's numbers say nothing about DPDK's speed (virtual NICs, shared CPUs); none are recorded here.

### Measuring on real hardware (run by the owner)
1. **Preparation** (root)
   - Hugepages: `echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages` (2 GiB; the 65535-mbuf pool takes about 160 MiB). For 1 GB pages boot with `default_hugepagesz=1G hugepagesz=1G hugepages=4` and set `hugepages: {size: 1GB}`.
   - CPUs: give the forwarding lcores their CPUs. Booting with `isolcpus=2-5 nohz_full=2-5 rcu_nocbs=2-5` (the lcores' CPUs) is the sure way. Keep rproxy's workers off them with `global.performance.cpu_affinity` (an overlap is a settings error). Use CPUs on the NIC's NUMA node (`cat /sys/bus/pci/devices/0000:3b:00.0/numa_node`).
   - Bind the NIC to vfio-pci (the kernel no longer sees the port: **keep SSH / management on another NIC**):
     ```sh
     modprobe vfio-pci
     ip link set ens1f0 down
     dpdk-devbind.py --bind=vfio-pci 0000:3b:00.0      # back: dpdk-devbind.py --bind=ixgbe 0000:3b:00.0 (the original driver)
     dpdk-devbind.py --status
     ```
     This needs an IOMMU (`intel_iommu=on iommu=pt`; on by default on AMD). In a VM, vfio-pci's no-IOMMU mode (`echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`) or the virtio PMD. Mellanox (mlx5) is bifurcated and needs no rebinding (give the PCI address in `pci`, the driver stays mlx5_core).
2. **Settings** (`RPROXY_CONFIG`)
   ```yaml
   global:
     performance:
       cpu_affinity: "0-1"          # rproxy's workers (not on the lcores)
       dpdk:
         enabled: true
         lcores: "2-5"              # the first CPU is the main lcore (it forwards too)
         eal_args: ["--in-memory", "--file-prefix=rproxy"]
         ports:
           - pci: "0000:3b:00.0"
             rx_queues: 4           # as many as lcores (RSS spreads them over the lcores)
             tx_queues: 4           # at least the number of lcores
             rx_desc: 1024
             tx_desc: 1024
             addresses: ["198.51.100.2/24"]
             gateway: 198.51.100.1  # next hop to backends / clients on other networks
         mempool: { mbufs: 65535, cache: 256 }
         hugepages: { size: 2MB }
         burst: 32
         fallback: false            # when measuring, better not to start at all if it cannot be used
   rules:
     - { protocol: udp, listen_addr: 198.51.100.2, listen_port: 5300, remote_addr: 198.51.100.10, remote_port: 5300 }
   ```
   Check first with `sudo rproxy-api --check-kernel --config rproxy.yaml` (the `dpdk.enabled=true` row `usable`, and each step). Once started, `GET /capabilities` shows `performance.dpdk.active` and `mode` (DPDK version, lcores, port links).
3. **Comparing**: on the same machines and peers, measure in turn (a) the current path (the NIC back on the kernel, the same address, the best of `udp_shards` / `busy_poll_usecs`) and (b) the DPDK path (1, 2 and 4 lcores). Load from another machine (`pktgen-dpdk` or TRex; otherwise `scripts/load/loadgen`'s `udp-flood` (`--sources`, `--size 64`, `--pps 0`, `--threads`) as the sender and `udp-sink` at the backend, the tools of `load.py`'s "64 B max rate"). Look at: the maximum pps of 64-byte datagrams and the loss (sent vs. received by the backend), Gbit/s at 1472 bytes, p50 / p99 round-trip latency, CPU use outside the lcores, with 1, 1,000 and 100,000 sessions (clients). Match `/rules` `stats` (rx / tx bytes, `dropped`) against what the backend received.
4. **Write the results here** (with the reasons if not adopted).

### Where it stands
- Implemented and checked for correctness. No speed numbers yet (waiting for hardware).
- Rule of thumb for the decision: if AF_XDP (#260 step 1, zero-copy) on the same NIC reaches 70-80% or more of DPDK's 64-byte pps, **adopt AF_XDP and not DPDK** (it shares the NIC with the kernel, needs no vfio rebinding, no hugepages, no separate build, and TCP fits the same framework). Only if DPDK is clearly ahead and there is a use that can give it a whole NIC (a host dedicated to large volumes of small UDP packets) consider shipping it as a separate artifact (x86_64 / aarch64 glibc).
- Known limits: IPv4 only, IP fragments dropped, no jumbo frames (one mbuf per frame), backend MACs are relearned only from ARP replies / gratuitous ARP, about 28,000 NAT ports per source address (add addresses for more sessions), UDP checksums are updated, not verified (a broken one is dropped by the backend's kernel; when the peer of a veth leaves checksums to the "hardware", frames read with `net_af_packet` carry a partial value, so when trying it on veth run `ethtool -K <veth> tx off` on the peer), sessions behind one Mutex per NAT port (contended when RSS delivers the answers to another lcore; if that matters, pick NAT ports whose answers hash to the same queue by computing Toeplitz).

## Next candidates
- DPDK (#261): the "Experiment" above, waiting for numbers from real hardware.
- Forwarding in the kernel (#260, in progress): `global.performance.ebpf` (plain L4 TCP through a BPF sockmap) and `global.performance.xdp` (UDP through AF_XDP). Opt-in; only fast paths whose startup test with real data passed are used (`rproxy-api --check-kernel`). The framework (settings, tests, `GET /capabilities`) comes first, then the fast paths one by one, with their results recorded here.
- HTTP/2: the profile still shows memcpy (about 11%), the allocator (about 12%) and kernel wakeups (about 7%). Fewer, larger h2 writes.
- Multi-core use (#194): adapt to queue depth (per-role pipeline, per-core parallelism, backpressure).
- Memory (#185): share UDP session buffers per worker.
