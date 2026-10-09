//! `global.performance.xdp` (#260): kernel offload of the L4 UDP data plane.
//! Opt-in, takes effect at startup only. Each key comes from the settings file,
//! else its environment variable (`RPROXY_XDP_*`), else the default (off).
//!
//! (`global.performance.ebpf` with `tcp: sockmap` was tried and not adopted;
//! docs/PERFORMANCE.md.)
//!
//! What is requested here is only used after the startup probe
//! (`net::offload::probe`) pushed test data through the fast path; what fails
//! the probe falls back to the current path (`fallback: false` stops startup
//! instead).

use serde::{Deserialize, Serialize};

pub const MIN_RING: u32 = 64;
pub const MAX_RING: u32 = 16384;
pub const MAX_BATCH: u32 = 1024;
pub const MAX_QUEUES: u32 = 256;
pub const MAX_INTERFACES: usize = 64;
/// IFNAMSIZ - 1
const MAX_IFNAME: usize = 15;

/// `xdp.mode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XdpMode {
	#[default]
	Off,
	/// UDP rules receive and send through AF_XDP sockets
	AfXdp,
	/// the XDP program forwards by itself (stage 2)
	Native,
}

impl XdpMode {
	pub fn as_str(self) -> &'static str {
		match self {
			XdpMode::Off => "off",
			XdpMode::AfXdp => "af_xdp",
			XdpMode::Native => "native",
		}
	}
}

/// `xdp.attach`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XdpAttach {
	/// native when the driver can, else generic
	#[default]
	Auto,
	Driver,
	Generic,
}

impl XdpAttach {
	pub fn as_str(self) -> &'static str {
		match self {
			XdpAttach::Auto => "auto",
			XdpAttach::Driver => "driver",
			XdpAttach::Generic => "generic",
		}
	}
}

/// The word `auto`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Auto {
	Auto,
}

/// `true`, `false` or `auto`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AutoBool {
	Bool(bool),
	Auto(Auto),
}

/// A count or `auto`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AutoCount {
	Count(u32),
	Auto(Auto),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpSpec {
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub mode: Option<XdpMode>,
	/// NICs to attach to (default: from the rules' listen addresses).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub interfaces: Option<Vec<String>>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub attach: Option<XdpAttach>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub zero_copy: Option<AutoBool>,
	/// RX queues to use (auto: the NIC's queues, at most the workers).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub queues: Option<AutoCount>,
	/// Entries of each XSK ring (RX, TX, fill, completion): a power of two.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub ring_size: Option<u32>,
	/// Bytes of one UMEM frame: 2048 or 4096.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub frame_size: Option<u32>,
	/// Packets handled per batch.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub batch: Option<u32>,
	/// SO_PREFER_BUSY_POLL on the XSKs.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub busy_poll: Option<bool>,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub fallback: Option<bool>,
}

fn check_ifname(name: &str) -> Result<(), String> {
	let ok = !name.is_empty()
		&& name.len() <= MAX_IFNAME
		&& name != "."
		&& name != ".."
		&& name.bytes().all(|b| b.is_ascii_graphic() && b != b'/' && b != b':');
	if ok {
		Ok(())
	} else {
		Err(format!("{name:?} is not an interface name (1-{MAX_IFNAME} characters, no '/', ':' or spaces)"))
	}
}

impl XdpSpec {
	pub fn check(&self, p: &str) -> Result<(), String> {
		if let Some(list) = &self.interfaces {
			if list.len() > MAX_INTERFACES {
				return Err(format!("{p}.interfaces: at most {MAX_INTERFACES}"));
			}
			for name in list {
				check_ifname(name).map_err(|e| format!("{p}.interfaces: {e}"))?;
			}
		}
		if let Some(AutoCount::Count(n)) = self.queues {
			if n == 0 || n > MAX_QUEUES {
				return Err(format!("{p}.queues must be 1-{MAX_QUEUES} or auto"));
			}
		}
		if let Some(n) = self.ring_size {
			if !(MIN_RING..=MAX_RING).contains(&n) || !n.is_power_of_two() {
				return Err(format!("{p}.ring_size must be a power of two, {MIN_RING}-{MAX_RING}"));
			}
		}
		if self.frame_size.is_some_and(|n| n != 2048 && n != 4096) {
			return Err(format!("{p}.frame_size must be 2048 or 4096"));
		}
		if let Some(b) = self.batch {
			if b == 0 || b > MAX_BATCH {
				return Err(format!("{p}.batch must be 1-{MAX_BATCH}"));
			}
			let ring = self.ring_size.unwrap_or(DEFAULT_RING);
			if b > ring {
				return Err(format!("{p}.batch ({b}) is larger than ring_size ({ring})"));
			}
		}
		if self.attach == Some(XdpAttach::Generic) && self.zero_copy == Some(AutoBool::Bool(true)) {
			return Err(format!("{p}: zero_copy: true needs the driver (attach: auto or driver)"));
		}
		Ok(())
	}
}

pub const DEFAULT_RING: u32 = 2048;
pub const DEFAULT_FRAME: u32 = 4096;
pub const DEFAULT_BATCH: u32 = 64;

/// `xdp` as resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Xdp {
	pub mode: XdpMode,
	/// Empty: from the rules' listen addresses.
	pub interfaces: Vec<String>,
	pub attach: XdpAttach,
	/// None: auto.
	pub zero_copy: Option<bool>,
	/// None: auto.
	pub queues: Option<u32>,
	pub ring_size: u32,
	pub frame_size: u32,
	pub batch: u32,
	pub busy_poll: bool,
	pub fallback: bool,
}

impl Default for Xdp {
	fn default() -> Xdp {
		Xdp {
			mode: XdpMode::Off,
			interfaces: vec![],
			attach: XdpAttach::Auto,
			zero_copy: None,
			queues: None,
			ring_size: DEFAULT_RING,
			frame_size: DEFAULT_FRAME,
			batch: DEFAULT_BATCH,
			busy_poll: false,
			fallback: true,
		}
	}
}

fn word<T: serde::de::DeserializeOwned>(key: &str, v: &str) -> Result<T, String> {
	serde_json::from_value(serde_json::Value::String(v.to_string())).map_err(|_| format!("{key}={v:?} is not one of the allowed words"))
}

fn flag(key: &str, v: &str) -> Result<bool, String> {
	match v {
		"1" | "true" | "on" | "yes" => Ok(true),
		"0" | "false" | "off" | "no" => Ok(false),
		_ => Err(format!("{key}={v:?} is not true or false")),
	}
}

fn number(key: &str, v: &str) -> Result<u32, String> {
	v.parse().map_err(|_| format!("{key}={v:?} is not a number"))
}

/// `RPROXY_XDP_*` as a spec (None where unset), checked like the settings
/// file. `var` reads one variable (blank counts as unset).
pub fn from_env_with(var: impl Fn(&str) -> Option<String>) -> Result<XdpSpec, String> {
	let get = |k: &str| var(k).map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
	let mut xdp = XdpSpec::default();
	if let Some(v) = get("RPROXY_XDP_MODE") {
		xdp.mode = Some(word("RPROXY_XDP_MODE", &v)?);
	}
	if let Some(v) = get("RPROXY_XDP_INTERFACES") {
		xdp.interfaces = Some(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());
	}
	if let Some(v) = get("RPROXY_XDP_ATTACH") {
		xdp.attach = Some(word("RPROXY_XDP_ATTACH", &v)?);
	}
	if let Some(v) = get("RPROXY_XDP_ZERO_COPY") {
		xdp.zero_copy = Some(if v == "auto" { AutoBool::Auto(Auto::Auto) } else { AutoBool::Bool(flag("RPROXY_XDP_ZERO_COPY", &v)?) });
	}
	if let Some(v) = get("RPROXY_XDP_QUEUES") {
		xdp.queues = Some(if v == "auto" { AutoCount::Auto(Auto::Auto) } else { AutoCount::Count(number("RPROXY_XDP_QUEUES", &v)?) });
	}
	if let Some(v) = get("RPROXY_XDP_RING_SIZE") {
		xdp.ring_size = Some(number("RPROXY_XDP_RING_SIZE", &v)?);
	}
	if let Some(v) = get("RPROXY_XDP_FRAME_SIZE") {
		xdp.frame_size = Some(number("RPROXY_XDP_FRAME_SIZE", &v)?);
	}
	if let Some(v) = get("RPROXY_XDP_BATCH") {
		xdp.batch = Some(number("RPROXY_XDP_BATCH", &v)?);
	}
	if let Some(v) = get("RPROXY_XDP_BUSY_POLL") {
		xdp.busy_poll = Some(flag("RPROXY_XDP_BUSY_POLL", &v)?);
	}
	if let Some(v) = get("RPROXY_XDP_FALLBACK") {
		xdp.fallback = Some(flag("RPROXY_XDP_FALLBACK", &v)?);
	}
	xdp.check("RPROXY_XDP").map_err(env_names)?;
	Ok(xdp)
}

/// `from_env_with` on the process environment.
pub fn from_env() -> Result<XdpSpec, String> {
	from_env_with(|k| std::env::var(k).ok())
}

/// `RPROXY_XDP.ring_size must ...` → `RPROXY_XDP_RING_SIZE must ...`
fn env_names(e: String) -> String {
	let e = e.replacen("RPROXY_XDP.", "RPROXY_XDP_", 1);
	match e.split_once(' ') {
		Some((key, rest)) => format!("{} {rest}", key.to_uppercase()),
		None => e,
	}
}

/// Each key from the file, else the environment, else the default.
pub fn resolve(file: Option<&XdpSpec>, env: &XdpSpec) -> Xdp {
	let none = XdpSpec::default();
	let fx = file.unwrap_or(&none);
	let ex = env;
	let d = Xdp::default();
	Xdp {
		mode: fx.mode.or(ex.mode).unwrap_or(d.mode),
		interfaces: fx.interfaces.clone().or_else(|| ex.interfaces.clone()).unwrap_or_default(),
		attach: fx.attach.or(ex.attach).unwrap_or(d.attach),
		zero_copy: match fx.zero_copy.or(ex.zero_copy) {
			Some(AutoBool::Bool(b)) => Some(b),
			_ => None,
		},
		queues: match fx.queues.or(ex.queues) {
			Some(AutoCount::Count(n)) => Some(n),
			_ => None,
		},
		ring_size: fx.ring_size.or(ex.ring_size).unwrap_or(d.ring_size),
		frame_size: fx.frame_size.or(ex.frame_size).unwrap_or(d.frame_size),
		batch: fx.batch.or(ex.batch).unwrap_or(d.batch),
		busy_poll: fx.busy_poll.or(ex.busy_poll).unwrap_or(d.busy_poll),
		fallback: fx.fallback.or(ex.fallback).unwrap_or(d.fallback),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn shapes_and_validation() {
		let x: XdpSpec = crate::config::from_yaml(
			"{mode: af_xdp, interfaces: [eth0, ens1f0], attach: auto, zero_copy: auto, queues: 4, ring_size: 2048, frame_size: 4096, batch: 64, busy_poll: false, fallback: true}",
		)
		.unwrap();
		x.check("x").unwrap();
		assert_eq!(x.mode, Some(XdpMode::AfXdp));
		assert_eq!(x.zero_copy, Some(AutoBool::Auto(Auto::Auto)));
		let x: XdpSpec = crate::config::from_yaml("{zero_copy: true, queues: auto}").unwrap();
		assert_eq!((x.zero_copy, x.queues), (Some(AutoBool::Bool(true)), Some(AutoCount::Auto(Auto::Auto))));
		assert!(crate::config::from_yaml::<XdpSpec>("{mode: dpdk}").is_err());
		assert!(crate::config::from_yaml::<XdpSpec>("{rings: 4}").is_err(), "unknown keys");
		for bad in [
			"{ring_size: 1000}",
			"{ring_size: 32}",
			"{ring_size: 32768}",
			"{frame_size: 1024}",
			"{batch: 0}",
			"{batch: 2048}",
			"{ring_size: 64, batch: 128}",
			"{queues: 0}",
			"{queues: 1000}",
			"{interfaces: ['']}",
			"{interfaces: ['a/b']}",
			"{interfaces: ['averyveryverylongname']}",
			"{attach: generic, zero_copy: true}",
		] {
			let x: XdpSpec = crate::config::from_yaml(bad).unwrap();
			assert!(x.check("x").is_err(), "{bad}");
		}
	}

	#[test]
	fn the_file_wins_over_the_environment_then_the_defaults() {
		let vars = |pairs: &'static [(&'static str, &'static str)]| {
			move |k: &str| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
		};
		let env = from_env_with(vars(&[
			("RPROXY_XDP_MODE", "af_xdp"),
			("RPROXY_XDP_INTERFACES", "eth0, eth1"),
			("RPROXY_XDP_ZERO_COPY", "false"),
			("RPROXY_XDP_RING_SIZE", "4096"),
			("RPROXY_XDP_FALLBACK", "0"),
			("RPROXY_XDP_BATCH", " "),
		]))
		.unwrap();
		let x = resolve(None, &env);
		assert_eq!((x.mode, x.interfaces.clone(), x.zero_copy, x.ring_size, x.batch, x.fallback), (XdpMode::AfXdp, vec!["eth0".into(), "eth1".into()], Some(false), 4096, DEFAULT_BATCH, false));

		let fx: XdpSpec = crate::config::from_yaml("{ring_size: 512, zero_copy: auto}").unwrap();
		let x = resolve(Some(&fx), &env);
		assert_eq!((x.mode, x.ring_size, x.zero_copy), (XdpMode::AfXdp, 512, None));

		assert_eq!(resolve(None, &Default::default()), Xdp::default());

		for bad in [
			&[("RPROXY_XDP_MODE", "fast")][..],
			&[("RPROXY_XDP_RING_SIZE", "1000")][..],
			&[("RPROXY_XDP_BUSY_POLL", "maybe")][..],
			&[("RPROXY_XDP_QUEUES", "x")][..],
		] {
			let err = from_env_with(vars(bad)).unwrap_err();
			assert!(err.contains("RPROXY_"), "{err}");
		}
		assert!(from_env_with(vars(&[("RPROXY_XDP_RING_SIZE", "1000")])).unwrap_err().starts_with("RPROXY_XDP_RING_SIZE "));
	}
}
