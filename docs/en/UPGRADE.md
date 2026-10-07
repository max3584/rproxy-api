日本語: [UPGRADE.md](../UPGRADE.md)

# Live upgrades and the self-update (#174)

rproxy-api can swap in a new binary while it runs (a **handoff**). Patches within one minor (X.Y) take over without cutting TCP or HTTP connections. In a container it can fetch the newest patch of the image's X.Y and swap it in by itself (the **self-update**). The design is section 10 of docs/en/DESIGN-v0.4.md.

## Handoff

Triggers:

- `SIGUSR2` to the running process (`systemctl kill -s USR2 --kill-whom=main rproxy-api`)
- `POST /admin/upgrade` (`admin` scope; by default only over the Unix socket: `RPROXY_API_RELOAD_UNIX_ONLY`). `202 {"status":"started"}`, or `409 upgrading` when one is already running
- upgrading the .deb (see "Package" below)

Steps:

1. The old process opens the handoff Unix socket (`--handoff-socket`, 0600) and starts the binary on disk (the file `/proc/self/exe` pointed at, i.e. the one a package upgrade replaced) as its child, with the same arguments and environment. Only that child (checked by pid) may connect.
2. The new process states its version. Another major.minor is refused (`handoff.refused`) and the old process keeps running (minor upgrades restart).
3. The old process passes every listening socket (`SCM_RIGHTS`): the rules' TCP and UDP sockets (whole `SO_REUSEPORT` groups), HTTP/3's UDP sockets, the control API on TCP and on the Unix socket, `global.acme.http01_listen`. Then its state: the rules made through the API (`origin: api` ones with their creator, time and `persisted`), the rule sets (#28) with their generations, and every rule's counters including `stats.http` by route, `limited`, datagrams dropped over `bandwidth`, and `counters_since`.
4. The new process starts as usual, but wherever it would open a socket it takes the inherited one (the same socket, so nothing is refused while both run). Rules come from the settings file and from the API rules and rule sets of the old process (sets keep their generation and etag; not re-read from the database: the API rules include what changed since the old process read it at its start). The counters are added to the old process's (they never go down), and `counters_since` and `rproxy_process_start_time_seconds` carry over. When ready, it tells the old process (`handoff.ready`).
5. The old process tells systemd (`Type=notify`, `NotifyAccess=all`) and `rproxy-api launch` the new main pid (`MAINPID=`), stops accepting, waits up to `--handoff-drain` (default 5 minutes) for its connections to end, closes the rest, sends what it counted meanwhile to the new process and exits (`handoff.done`). `systemctl stop` (SIGTERM) cuts the wait short.
6. If the new process is not ready within `--handoff-timeout` (default 30 seconds), the old process stops it and goes on as before (`handoff.failed`).

Guarantees:

- **TCP and HTTP are not cut**: connections the old process holds stay with it to the end; new connections go to the new process. HTTP rules finish the requests in flight and then close idle connections once they stop accepting (clients reconnect to the new process).
- **UDP may pause briefly** (agreed with the owner): the listening sockets move, but the current sessions end with the old process and are recreated in the new one (the backend sees a new source port; QUIC passthrough should survive through connection migration, DTLS and terminated QUIC / DTLS reconnect).
- During a handoff (and in the old process afterwards) requests that change something (anything but `GET`, except `/admin/*`) get `503 upgrading`: a change the old process takes after it handed its state over would be lost. Send it again shortly.
- What starts over in the new process: the per-source state of `limits` (#165: connection counts, rate buckets, the sources it tracks) and the buckets of `bandwidth` (#166), the state of the `http` middlewares `rate_limit`, `in_flight` and `circuit_breaker`, targets ejected by passive health checks (#170), and health check results (up until the first check). Connections the old process drains count in the old process, so meanwhile one source may exceed `max_connections` across both (it settles as old connections end).
- `global.performance` (worker count and so on) is decided when the new process starts. UDP socket groups are taken over as they are (resizing a group changes how the kernel spreads clients; a new `udp_shards` applies when the rule's sockets are opened again).

| Flag / environment variable | Default | Meaning |
|---|---|---|
| `--handoff-socket` / `RPROXY_HANDOFF_SOCKET` | `/run/rproxy/handoff.sock` | Unix socket of the handoff (only during one, 0600). Its directory must exist |
| `--handoff-timeout` / `RPROXY_HANDOFF_TIMEOUT` | `30s` | How long to wait for the new process (1s-10m) |
| `--handoff-drain` / `RPROXY_HANDOFF_DRAIN` | `5m` | Longest the old process waits for its connections (0-24h) |

Logs: `handoff.start`, `handoff.sent`, `handoff.received`, `handoff.ready`, `handoff.drain`, `handoff.done`, `handoff.counters`, `handoff.failed`, `handoff.refused`, `handoff.sockets`. `/metrics`: `rproxy_build_info{version,sha256}`, `rproxy_handoffs_total{outcome="done|failed|refused"}`, `rproxy_process_start_time_seconds`. `GET /capabilities` has `build`: `{"version","sha256"}`.

### systemd

The unit is `Type=notify` with `NotifyAccess=all` (`READY=1` once started; in a handoff the old process sends `MAINPID=<new pid>`). `systemctl reload` stays SIGHUP (re-reading settings and certificates); the handoff is SIGUSR2 (the owner's decision).

### Package (.deb)

When a running service is upgraded, `postinst` hands it over with SIGUSR2 if the previous version has the same major.minor, and checks that the main process changed (otherwise it restarts). Another major.minor restarts. An exception patch that cannot be handed over ships `/usr/share/rproxy-api/restart-required` (docs/en/RELEASING.md). On VMs installed with apt the self-update (below) stays off (not twice with apt).

## Self-update (containers)

Make `rproxy-api launch` the image's entry point (with `RPROXY_UPDATE=auto` and so on; other arguments and `RPROXY_*` go to the server unchanged).

- The launcher picks the newest patch of the image's X.Y from the cache and the release source, **verifies its signatures**, and starts it as its child. When the source cannot be reached (an outage, a closed network) it takes the newest cached one, else the image's version. It then stays as the container's init: it passes signals (TERM, INT, HUP, USR2) to the server and follows the new main process after a handoff (`launch.mainpid`), and adopts orphaned processes (`PR_SET_CHILD_SUBREAPER`).
- While running: every `RPROXY_UPDATE_INTERVAL`, or on `POST /admin/update` (`admin`; by default only over the Unix socket; `202 {"status":"checking"}`), it looks for a new patch and swaps a verified one in with a handoff. `check` only reports it (log `update.available`, `GET /admin/update`).
- A new version that keeps running for `RPROXY_UPDATE_HEALTHY` becomes the good one (`update.healthy`; the previous good one is kept, the rest is removed from the cache). One that fails before (does not start, fails the handoff, exits) is remembered as bad and never chosen again, and the previous good version (else the image's) starts instead (`update.rollback`).
- On Kubernetes, replicas are replaced for updates: set `RPROXY_UPDATE=off`.

| Environment variable (flags: the same `--update-*`) | Default | Meaning |
|---|---|---|
| `RPROXY_UPDATE` | `off` | `off`, `check`, `auto` |
| `RPROXY_UPDATE_PIN` | none | Pin a version (`0.4.3`; an older patch of the same X.Y works too) |
| `RPROXY_UPDATE_SOURCE` | `https://github.com/max3584/rproxy-api/releases` | Where releases come from (`https://` only). A mirror uses the same paths `<source>/download/v<X.Y.Z>/<file>` and the index `<source>/latest/download/releases.json` (and `.minisig`) |
| `RPROXY_UPDATE_CACHE` | `/var/cache/rproxy/update` | Cache (a writable volume; the root file system may be read-only) |
| `RPROXY_UPDATE_INTERVAL` | `6h` | How often to look (`0s`: at start and through the API only) |
| `RPROXY_UPDATE_PUBKEY` | the release key built in | minisign public key file that verifies releases (for a mirror that signs again). Needed with builds that have no key built in |
| `RPROXY_UPDATE_HEALTHY` | `60s` | A new version that runs this long is good |

### What is verified

- Fetched: `manifest.json` (version, whether a `handoff` is allowed, SHA-256 of each binary) and its `.minisig`, this target's binary `rproxy-api-v<X.Y.Z>-<target>` and its `.minisig`. Which releases exist comes from the signed index `<source>/latest/download/releases.json` (`{"releases":[{"version":"0.4.3"},...]}`; the release workflow writes it with every release, listing every release of every minor). Patch numbers have gaps (only the repository whose code changed is released), so the newest release of the same X.Y that is newer than the running one and not bad is picked from the index rather than probing numbers (if its manifest does not verify, the next older one).
- Signatures are **minisign** (Ed25519; both the default BLAKE2b-prehashed form and the legacy one). Nothing runs unless the manifest's and the binary's signatures, the manifest's version and the SHA-256 in the manifest all check out. Cached releases are verified again before they run.
- A patch with `"handoff": false` is not swapped in; `update.restart_needed` is logged (it runs at the next start).
- `GET /admin/update`: `{"mode","current":{"version","sha256"},"available":{"version","sha256"}|null,"last_check","error","bad_versions":[...]}`.
- Cache: `<cache>/<version>/` (binary, signatures, manifest) and `state.json` (`good`, `previous`, `bad`, `trial`).

Logs: `update.check`, `update.available`, `update.fetched`, `update.healthy`, `update.rollback`, `update.restart_needed`, `update.error`; the launcher's `launch.start`, `launch.mainpid`, `launch.exit`.
