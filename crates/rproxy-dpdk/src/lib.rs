//! DPDK data plane for rproxy-api's L4 UDP forwarding (#261, experimental).
//!
//! - `packet`: Ethernet / ARP / IPv4 / UDP parsing and rewriting.
//! - `engine`: the forwarder (rules, sessions with NAT ports, ARP), generic
//!   over the rules so it runs without DPDK in tests.
//! - `selftest`: the startup check's scenario (test datagrams through the path).
//! - `ffi` / `io` (feature `ffi`): EAL, mempool, ports, the lcore loop.

pub mod engine;
pub mod packet;
pub mod selftest;

#[cfg(feature = "ffi")]
pub mod ffi;
#[cfg(feature = "ffi")]
pub mod io;
