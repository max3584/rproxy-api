日本語: [DESIGN.md](../DESIGN.md)

# rproxy-api design notes

A design record for moving the implementation forward. This is an organization based on
reading the code as of 2026-09-25 (`829521a`), not a finalized specification.

---

## 1. What gap does this project fill?

**An L4 forwarder whose TCP/UDP forwards can be added, removed, and queried while running.**

Forwarding itself (`tokio::io::copy_bidirectional`) has no value. There are plenty of
existing implementations. The value lies in **being able to query and change "which ports
are open right now and where they forward to" via an API**, and that is where the existing
options leave a gap.

| | Forwarding | Opening/closing ports while running | Querying the ledger |
|---|---|---|---|
| Traefik | ○ | **✕** entryPoints are static config and require a restart | ✕ |
| nginx (stream) | ○ | ✕ config file + reload | ✕ |
| HAProxy | ○ (TCP only) | ✕ config file + reload | ✕ |
| **rproxy-api** | ○ | **○** | **○ (upcoming)** |

Traefik's limitation is an actual operational problem. Every additional port requires
editing the static config and restarting, so a pre-allocation workaround gets considered:
"define a set of reserved entryPoints in advance (a port pool)". **If listeners can be
spawned via an API, that workaround itself becomes unnecessary.**

### 1.1 Desired properties

- The list of open ports can be obtained from **a single authoritative place**
- Opening and closing ports does not require a restart
- Since the open ports are known, **packet filter rules can be generated from them**
  (drift from hand-maintained rules structurally cannot happen)

### 1.2 Non-goals

L7 is out of scope. TLS termination, SNI routing, and HTTP middleware are left to Traefik and the like.
Paths that need those do not go through rproxy-api.

---

## 2. Current state (`829521a`)

### What works

- Bidirectional TCP / UDP forwarding
- Adding forwards via the API (`{"property":"UP", ...}`)
- Following the destination via DNS re-resolution every 30 seconds
- `STOP` / `UPDATE` via a per-proxy control socket

### What does not work

- **`LIST`** — there is no way to query what is open
- **`DOWN`** — stopping from the API (you have to connect to each proxy's control socket individually)
- **API authentication and authorization**
- **Preserving the source IP** (§4)

---

## 3. Rebuilding the control plane

This is the core issue. **Async itself is not what is hard; what blocks new features is that
the lifecycle is expressed through sockets and shared mutable state.**

### 3.1 The current structure and what it causes

| Location | Current | Consequence |
|---|---|---|
| `src/api.rs:46,53` | Starts a control listener on `127.0.0.2:<port>` / `127.0.0.3:<port>` for every proxy | N proxies mean 2N listeners. Control paths are scattered and there is no place to see the whole. Two proxies sharing a listen_port cannot be created |
| `src/api.rs:47-49` | Discards the `JoinHandle` from `tokio::spawn(...)` | No way to refer to a proxy after it starts. **The root cause why `LIST` / `DOWN` cannot be written** |
| `src/tcp.rs:123-127` | Reads the stop flag only in the branch of the 30-second DNS tick | The flag goes unnoticed while waiting in `accept()`. Stopping takes up to 30 seconds |
| `src/tcp.rs:147` | `try_join(main_task, control)` | The main task and control wait on each other's completion and cannot finish independently |
| `src/tcp.rs:56,63` and others | Shares remote via `Arc<Mutex<String>>` | The update path becomes bidirectional, making it hard to track who writes |

### 3.2 Replacement

The five issues above are **solved together by introducing a single registry.**

```rust
use tokio_util::sync::CancellationToken;
use tokio::sync::watch;

#[derive(Clone, Debug, serde::Serialize)]
pub struct ProxySpec {
    pub id:       ProxyId,
    pub protocol: Protocol,        // Tcp | Udp
    pub listen:   SocketAddr,
    pub remote:   String,          // kept as a hostname (for DNS re-resolution)
}

pub struct ProxyHandle {
    pub spec:   ProxySpec,
    cancel:     CancellationToken,
    join:       JoinHandle<()>,
    remote_tx:  watch::Sender<SocketAddr>,   // written by DNS re-resolution, read by connection tasks
}

pub type Registry = Arc<RwLock<HashMap<ProxyId, ProxyHandle>>>;
```

With this:

- **`LIST`** → just walk the registry and return the `spec`s
- **`DOWN`** → `cancel.cancel()`, then `join.await`
- **Control listeners become unnecessary** — `sync()` and the `127.0.0.2` / `127.0.0.3`
  mechanism disappear entirely. The port collision problem disappears too
- **The `try_join` coupling is removed** — the proxy itself only needs to watch its own token

### 3.3 Stopping uses `CancellationToken`

```rust
loop {
    tokio::select! {
        _ = token.cancelled() => break,          // exit immediately
        r = listener.accept() => {
            let (inbound, peer) = match r { Ok(v) => v, Err(e) => { /* log */ continue } };
            let child = token.child_token();     // propagate to established connections
            tracker.spawn(handle_conn(inbound, peer, remote_rx.clone(), child));
        }
    }
}
```

Polling disappears, and so does the 30-second wait. Passing `child_token()` to connection tasks
lets `DOWN` also wind down the in-flight connections.

To wait for the in-flight connections before finishing, use `tokio_util::task::TaskTracker`.

```rust
tracker.close();
tracker.wait().await;
```

### 3.4 Destination updates use `watch`

Drop `Arc<Mutex<String>>`.

```rust
// DNS re-resolution task (one writer)
let _ = remote_tx.send(resolved_addr);

// Connection tasks (N readers)
let addr = *remote_rx.borrow();
```

This becomes a one-way flow with one writer and N readers. No lock has to be passed around,
and `UPDATE` and DNS re-resolution ride the same path. **This is the tool we wanted when we
said "we want to change the configuration flexibly".**

### 3.5 The API endpoint

Currently `src/api.rs:33` and `src/api.rs:108` call `try_read` once and parse the JSON.
This fails when a command arrives split across TCP segments.

Either make it newline-delimited (`\n`) and read it fully with `BufReader::lines()`, or add a
length prefix. Since `LIST` also needs to return a response, it has to be shaped into
**a protocol with requests and responses** in any case.

---

## 4. How to handle the source IP

It is not preserved currently. `src/tcp.rs:39` does `TcpStream::connect(remote)` and
`src/udp.rs:49` does `UdpSocket::bind("0.0.0.0:0")`; both connect from their own address,
so the backend sees the rproxy-api host as the connection source.

There are two options, and **their prerequisites differ greatly**.

### 4.1 Sending the PROXY protocol

Right after connecting, before any application data, a header is injected that declares the client's IP.
This is the same mechanism Traefik / HAProxy / nginx use.

```
0d0a0d0a000d0a515549540a 21 11 000c <src ip><dst ip><sport><dport>
└── v2 signature (12B) ┘ │  │  └ len
                          │  └ AF_INET + STREAM
                          └ version 2 + PROXY command
```

- **No routing prerequisites.** The return traffic does not have to pass through rproxy-api
- **The backend must support it.** Sending it to something that does not support it makes the
  header be treated as malformed input and breaks the connection
- **TCP only.** UDP has no such mechanism
- The real IP is visible **only at the application layer**. The backend's kernel sees only
  rproxy-api's IP (it cannot be used in packet filters)

Supported by: Postfix (`smtpd_upstream_proxy_protocol`),
Dovecot (`haproxy = yes`), MediaMTX (`rtspTrustedProxies` / `rtmpTrustedProxies`),
nginx, HAProxy, Envoy.

### 4.2 Claiming the real IP with IP_TRANSPARENT

Set `IP_TRANSPARENT` with `socket2`, bind the client's IP:port, and then connect
to the backend.

```rust
let sock = Socket::new(Domain::IPV4, Type::STREAM, None)?;
sock.set_ip_transparent(true)?;      // requires CAP_NET_ADMIN
sock.set_reuse_address(true)?;
sock.bind(&client_addr.into())?;     // ← claim the real client's IP:port
sock.connect(&remote.into())?;
```

- **Protocol-independent.** No support is needed on the backend at all. Works for IPsec and NTP too
- **Works with UDP as well**
- **The real IP is visible at the kernel level.** It can be used in the backend's packet filters too
- **The return path must go through rproxy-api.** This is a constraint, not a choice:
  rproxy-api is the endpoint of the upstream connection, so the handshake cannot complete
  unless it receives the SYN-ACK and everything after it

> **The last point decides whether it can be adopted.** If the backend's default gateway is not
> the rproxy-api host, the return traffic takes a different path, so **forwarding does not work**.
> Either policy routing on the backend or changing the gateway is a prerequisite.

### 4.3 Which one to implement

**Both are needed.** They are not mutually exclusive; it should be selectable per forward.

```json
{"property":"UP", "listen_addr":"...", "listen_port":25,
 "remote_addr":"...", "remote_port":2525,
 "protocol":"TCP", "source_ip":"proxy_protocol_v2"}
```

`source_ip` takes one of three values: `none` (default) / `proxy_protocol_v2` / `transparent`.
`proxy_protocol_v2` works even in environments that cannot meet the routing prerequisites,
so implementing it first covers a wider range of uses.

---

## 5. Known bugs (as of 0.2, kept as a record)

In priority order. File locations are those of the code of 2026-09-25 (`829521a`), and all of these have been fixed (the current layout is under "Layout" in CLAUDE.md).

| Location | Description |
|---|---|
| `src/main.rs:65-78` | **If the logfile already exists, `set_logger` is not called** (it is only in the `else` branch). In addition, `Logger::log` only writes to stdout with `println!`, and `--logfile` is not used anywhere. The README description does not match the implementation |
| `src/main.rs:58` | `fn flush(&self) { todo!() }` — panics as soon as `log::logger().flush()` is called |
| `src/api.rs:33`, `src/api.rs:108` | Reads with a single `try_read` and parses the JSON. Fails on split arrival (§3.5) |
| `src/udp.rs:86` | `panic!` on send failure. A single datagram failure takes down the whole task |
| `src/api.rs:48,55` | `.unwrap()` inside spawned tasks. Same as above |
| `src/tcp.rs:123-127` | Stopping takes up to 30 seconds (§3.1) |
| `src/api.rs:38` | **The API has no authentication or authorization.** `UP` can listen on any address:port and forward to any destination. Defaulting to loopback is reasonable, but it is mandatory if exposed over the network |
| `Cargo.toml` | `sqlx` (mysql feature) is unused in `src/`. It makes the dependency tree heavy |
| `src/main.rs:4` | `mod lib;` — a module named `lib` in a binary crate works, but it is confusing because cargo treats `lib.rs` specially |
| `README.md` | The clone URL is `TCP-UDP-rproxy`, the binary name is `./forward`, and the "Update remote address" example is `{"property":"STOP", ...}`, while the implementation expects `"UPDATE"` (`src/api.rs:121`) |

---

## 6. Order of work

1. **Introduce the registry** (§3.2) — `LIST` / `DOWN` come in here. Control listeners are removed at the same time
2. **`CancellationToken`** (§3.3) — eliminate the 30-second wait
3. **`watch` channel** (§3.4) — remove `Arc<Mutex<_>>`
4. **Clean up the API protocol** (§3.5) — newline-delimited, request/response, error format
5. **API authentication** — at minimum a shared token. Mandatory if exposed over the network
6. **Bug fixes** (§5) — the logger issues are independent of 1 and can be fixed first
7. **`source_ip: proxy_protocol_v2`** (§4.1) — no routing prerequisites, so it applies widely
8. **`source_ip: transparent`** (§4.2) — for environments that can meet the routing prerequisites

It is natural to land 1–3 as a single change; once that is done, the rest can be stacked straightforwardly.

---

## 7. References

- Design decisions on the deployment environment side are recorded separately in `doc/l4-design.md`
  of `gitops/proxy-config` (which services to move to rproxy-api, how to handle routing)
- PROXY protocol specification: https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt
- Linux transparent proxy: https://docs.kernel.org/networking/tproxy.html
