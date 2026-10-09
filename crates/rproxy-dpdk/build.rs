//! With the `ffi` feature: compiles src/shim.c against DPDK (pkg-config
//! `libdpdk`; set PKG_CONFIG_PATH for a DPDK outside the system paths) and
//! links it. Without it: nothing.

fn main() {
	println!("cargo:rerun-if-changed=build.rs");
	#[cfg(feature = "ffi")]
	ffi();
}

#[cfg(feature = "ffi")]
fn ffi() {
	println!("cargo:rerun-if-changed=src/shim.c");
	println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
	let dpdk = match pkg_config::Config::new().atleast_version("22.11").probe("libdpdk") {
		Ok(lib) => lib,
		Err(e) => panic!("the dpdk feature needs DPDK 22.11 or later (pkg-config libdpdk, e.g. apt install libdpdk-dev): {e}"),
	};
	let mut build = cc::Build::new();
	build.file("src/shim.c").warnings(true).flag_if_supported("-Wno-unused-parameter");
	for path in &dpdk.include_paths {
		build.include(path);
	}
	// rte_config.h and the -march DPDK's inline functions need (pkg-config --cflags)
	let cflags = std::process::Command::new(std::env::var("PKG_CONFIG").unwrap_or_else(|_| "pkg-config".into()))
		.args(["--cflags", "libdpdk"])
		.output()
		.expect("pkg-config --cflags libdpdk");
	let cflags = String::from_utf8_lossy(&cflags.stdout).to_string();
	let mut words = cflags.split_whitespace();
	while let Some(w) = words.next() {
		if w == "-include" {
			if let Some(h) = words.next() {
				build.flag("-include").flag(h);
			}
		} else if w.starts_with("-m") || w.starts_with("-D") {
			build.flag(w);
		}
	}
	build.compile("rproxy_dpdk_shim");
}
