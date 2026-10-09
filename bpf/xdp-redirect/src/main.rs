//! AF_XDP redirect program for L4 UDP (#260, stage 1). The eBPF side is tiny:
//! for a UDP packet whose destination port is in `PORTS`, redirect it to the
//! AF_XDP socket bound to this RX queue (`XSKS`); everything else is passed up
//! to the normal network stack (`XDP_PASS`), so rproxy only takes the ports of
//! its UDP rules and the host keeps working as usual.
//!
//! rproxy still does the real work in user space (sessions, PROXY protocol,
//! `source_ip`, `allow_from` / `limits` / `bandwidth`); this only moves the
//! packets of the right ports to the XSK with no per-packet system call.
//!
//! Built with aya-ebpf; the object is checked in at
//! `src/net/offload/bpf_obj/xdp_redirect.bpf.o` and loaded by `aya` at run time
//! (see `bpf/README.md`). Not part of the default build.

#![no_std]
#![no_main]

use aya_ebpf::{
	bindings::xdp_action::{XDP_ABORTED, XDP_PASS},
	macros::{map, xdp},
	maps::{HashMap, XskMap},
	programs::XdpContext,
};
use core::mem;

/// RX queue -> the AF_XDP socket for it (user space fills this).
#[map]
static XSKS: XskMap = XskMap::with_max_entries(256, 0);

/// Destination UDP ports rproxy takes (key: port in host order, value: 1).
#[map]
static PORTS: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const IPPROTO_UDP: u8 = 17;
const ETH_HLEN: usize = 14;
const IPV6_HLEN: usize = 40;

/// Reads a `T` at `offset` from the packet, checking bounds against `data_end`.
#[inline(always)]
fn load<T: Copy>(ctx: &XdpContext, offset: usize) -> Option<T> {
	let start = ctx.data();
	let end = ctx.data_end();
	let len = mem::size_of::<T>();
	if start + offset + len > end {
		return None;
	}
	// SAFETY: the bounds against data_end are checked just above (the verifier
	// requires this); the pointer is within the packet.
	Some(unsafe { *((start + offset) as *const T) })
}

#[xdp]
pub fn xdp_redirect(ctx: XdpContext) -> u32 {
	match try_redirect(&ctx) {
		Some(action) => action,
		None => XDP_PASS,
	}
}

#[inline(always)]
fn try_redirect(ctx: &XdpContext) -> Option<u32> {
	// EtherType at offset 12; big-endian on the wire
	let eth_type = u16::from_be(load::<u16>(ctx, 12)?);
	let (udp_off, proto) = match eth_type {
		ETH_P_IP => {
			// IHL is the low nibble of the first byte, in 32-bit words
			let vihl = load::<u8>(ctx, ETH_HLEN)?;
			let ihl = ((vihl & 0x0f) as usize) * 4;
			if ihl < 20 {
				return None;
			}
			let proto = load::<u8>(ctx, ETH_HLEN + 9)?;
			(ETH_HLEN + ihl, proto)
		}
		ETH_P_IPV6 => {
			// no extension-header walking: only plain UDP (next header == UDP)
			let proto = load::<u8>(ctx, ETH_HLEN + 6)?;
			(ETH_HLEN + IPV6_HLEN, proto)
		}
		_ => return None,
	};
	if proto != IPPROTO_UDP {
		return None;
	}
	// UDP destination port is the second u16 of the UDP header
	let dport = u16::from_be(load::<u16>(ctx, udp_off + 2)?);
	// SAFETY: map lookup; the pointer is valid for the program's lifetime
	if unsafe { PORTS.get(&dport) }.is_none() {
		return None;
	}
	// redirect to the XSK of this RX queue; if none is bound, pass it up
	// SAFETY: reading a scalar context field
	let queue = unsafe { (*ctx.ctx).rx_queue_index };
	Some(XSKS.redirect(queue, XDP_PASS as u64).unwrap_or(XDP_ABORTED))
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
	loop {}
}
