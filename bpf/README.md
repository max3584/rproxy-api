# eBPF programs (#260)

Standalone crates built for the BPF target, like `fuzz/` they are **not** part of
the top-level `cargo build` / `test` / `deny` (own `Cargo.toml`, own workspace).

## `xdp-redirect/`

The AF_XDP redirect program for L4 UDP (`global.performance.xdp`). The compiled
object is checked in at `src/net/offload/bpf_obj/xdp_redirect.bpf.o` and loaded
by `aya` at run time (under the `kernel-offload` cargo feature), so the default
build and the 6 release targets need no BPF toolchain.

Rebuild it after changing `xdp-redirect/src/` (needs a nightly toolchain with
`rust-src` and `bpf-linker`; install locally, not in CI):

```sh
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo install bpf-linker            # or a prebuilt binary (needs LLVM to build from source)
cargo +nightly build --release --target bpfel-unknown-none -Z build-std=core \
  --manifest-path bpf/xdp-redirect/Cargo.toml
cp bpf/xdp-redirect/target/bpfel-unknown-none/release/xdp-redirect \
  src/net/offload/bpf_obj/xdp_redirect.bpf.o
```

BPF bytecode is endian-specific but architecture-independent; `bpfel` (little
endian) covers all six release targets (x86_64, aarch64, armv7 are all LE).
