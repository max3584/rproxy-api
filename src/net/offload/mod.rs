//! Kernel offload of the L4 data plane (#260): `global.performance.ebpf`
//! (plain TCP through a BPF sockmap, or TC / XDP NAT) and
//! `global.performance.xdp` (UDP through AF_XDP).
//!
//! Every fast path is opt-in and is only used after `probe` pushed test data
//! through it at startup (the same tests as `rproxy-api --check-kernel`).
//! What fails falls back to the current path. While running, nothing watches
//! or counts; only an anomaly that was handled (a fast-path operation failed,
//! a connection went back to user space) is logged.
//!
//! - `host`: privileges and kernel settings, for the reasons and the table
//! - `bpf`: the bpf(2) calls the fast paths share
//! - `probe`: the per-feature tests, their report (`performance.probe`,
//!   `degraded`, `GET /capabilities` `performance`) and the text table
//! - `sockmap`: plain L4 TCP through a BPF sockmap
//! - `verify` (cargo feature `offload-verify`, tests only): the always-on
//!   cross-check of the fast paths; not in release builds

pub mod bpf;
pub mod host;
pub mod probe;
#[cfg(target_os = "linux")]
pub mod sockmap;
#[cfg(all(feature = "offload-verify", target_os = "linux"))]
pub mod verify;
