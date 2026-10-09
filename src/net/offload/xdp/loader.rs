//! Loading and attaching the XDP redirect program and filling its maps (aya).
//! Keeps the program attached and the maps alive for as long as `Steer` lives;
//! dropping it detaches the program and the host goes back to normal.

use std::io;

use aya::maps::{HashMap as BpfHashMap, XskMap};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;

/// The XDP redirect object, built from `bpf/xdp-redirect` (see `bpf/README.md`).
static PROGRAM: &[u8] = include_bytes!("../bpf_obj/xdp_redirect.bpf.o");

/// How the program is attached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
	/// Native (driver) XDP.
	Driver,
	/// Generic (SKB) XDP: slower, works everywhere (veth, CI).
	Generic,
}

impl Mode {
	fn flags(self) -> XdpFlags {
		match self {
			Mode::Driver => XdpFlags::DRV_MODE,
			Mode::Generic => XdpFlags::SKB_MODE,
		}
	}
}

fn err(e: impl std::fmt::Display) -> io::Error {
	io::Error::other(e.to_string())
}

/// The loaded, attached program and its maps on one interface. Drop detaches.
pub struct Steer {
	ebpf: Ebpf,
	iface: String,
	mode: Mode,
}

impl Steer {
	/// Loads the program and attaches it to `iface` in `mode`. The caller then
	/// adds the rule ports (`add_port`) and the XSK of each queue (`set_xsk`).
	pub fn attach(iface: &str, mode: Mode) -> io::Result<Steer> {
		let mut ebpf = Ebpf::load(PROGRAM).map_err(err)?;
		let program: &mut Xdp = ebpf.program_mut("xdp_redirect").ok_or_else(|| io::Error::other("xdp_redirect not in the object"))?.try_into().map_err(err)?;
		program.load().map_err(err)?;
		program.attach(iface, mode.flags()).map_err(err)?;
		Ok(Steer { ebpf, iface: iface.to_string(), mode })
	}

	/// Steers this UDP destination port to the XSKs.
	pub fn add_port(&mut self, port: u16) -> io::Result<()> {
		let mut ports: BpfHashMap<_, u16, u8> = BpfHashMap::try_from(self.ebpf.map_mut("PORTS").ok_or_else(|| io::Error::other("no PORTS map"))?).map_err(err)?;
		ports.insert(port, 1u8, 0).map_err(err)
	}

	/// Binds the AF_XDP socket `fd` as the target for RX `queue`.
	pub fn set_xsk(&mut self, queue: u32, fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
		use std::os::fd::AsRawFd;
		let mut xsks: XskMap<_> = XskMap::try_from(self.ebpf.map_mut("XSKS").ok_or_else(|| io::Error::other("no XSKS map"))?).map_err(err)?;
		xsks.set(queue, fd.as_raw_fd(), 0).map_err(err)
	}

	pub fn iface(&self) -> &str {
		&self.iface
	}

	pub fn mode(&self) -> Mode {
		self.mode
	}
}
