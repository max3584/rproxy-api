// The futures of a TCP connection (accept -> PROXY header -> TLS -> the HTTP stack) nest
// deeper than rustc's default limit of 128 when it proves they are `Send` at `spawn`
// (nightly's future-incompatible recursion_depth_exceeding_limit, rust-lang/rust#159228).
#![recursion_limit = "256"]

pub mod acme;
pub mod config;
pub mod control;
pub mod core;
pub mod error;
pub mod l4;
pub mod l7;
pub mod logging;
pub mod net;
pub mod tls;
