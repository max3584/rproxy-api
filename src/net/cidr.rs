//! Address ranges for `allow_from`.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::error::ApiError;

pub const MAX_ALLOW_FROM: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr {
	net: IpAddr,
	prefix: u8,
}

/// IPv4 clients may arrive as IPv4-mapped IPv6 on dual-stack sockets.
fn canonical(ip: IpAddr) -> IpAddr {
	match ip {
		IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
		v4 => v4,
	}
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
	match ip {
		IpAddr::V4(v4) => {
			let bits = u32::from(v4);
			let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
			IpAddr::V4((bits & m).into())
		}
		IpAddr::V6(v6) => {
			let bits = u128::from(v6);
			let m = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
			IpAddr::V6((bits & m).into())
		}
	}
}

impl Cidr {
	pub fn contains(&self, ip: IpAddr) -> bool {
		let ip = canonical(ip);
		ip.is_ipv4() == self.net.is_ipv4() && mask(ip, self.prefix) == self.net
	}
}

impl FromStr for Cidr {
	type Err = ApiError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let bad = || ApiError::invalid(format!("allow_from: not an address or CIDR: {s}"));
		let (addr, prefix) = match s.trim().split_once('/') {
			Some((a, p)) => (a, Some(p.parse::<u8>().map_err(|_| bad())?)),
			None => (s.trim(), None),
		};
		let ip = canonical(addr.trim_matches(|c| c == '[' || c == ']').parse::<IpAddr>().map_err(|_| bad())?);
		let max = if ip.is_ipv4() { 32 } else { 128 };
		let prefix = prefix.unwrap_or(max);
		if prefix > max {
			return Err(ApiError::invalid(format!("allow_from: prefix /{prefix} is too long for {addr}")));
		}
		Ok(Cidr { net: mask(ip, prefix), prefix })
	}
}

impl fmt::Display for Cidr {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/{}", self.net, self.prefix)
	}
}

pub fn parse_list(list: &[String]) -> Result<Vec<Cidr>, ApiError> {
	if list.len() > MAX_ALLOW_FROM {
		return Err(ApiError::invalid(format!("allow_from may hold at most {MAX_ALLOW_FROM} entries")));
	}
	list.iter().map(|s| s.parse()).collect()
}

/// Empty means everyone.
pub fn allows(list: &[Cidr], ip: IpAddr) -> bool {
	list.is_empty() || list.iter().any(|c| c.contains(ip))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn c(s: &str) -> Cidr {
		s.parse().unwrap()
	}

	#[test]
	fn parses_and_normalizes() {
		assert_eq!(c("10.1.2.3").to_string(), "10.1.2.3/32");
		assert_eq!(c("172.16.9.9/16").to_string(), "172.16.0.0/16");
		assert_eq!(c("fd00::1/8").to_string(), "fd00::/8");
		assert_eq!(c("::ffff:10.0.0.1").to_string(), "10.0.0.1/32");
		assert_eq!(c("0.0.0.0/0").to_string(), "0.0.0.0/0");
		for bad in ["", "host.example", "10.0.0.0/33", "fd00::/129", "10.0.0.0/x"] {
			assert_eq!(bad.parse::<Cidr>().unwrap_err().code, "invalid", "{bad}");
		}
	}

	#[test]
	fn matches_addresses() {
		let net = c("172.16.0.0/16");
		assert!(net.contains("172.16.200.1".parse().unwrap()));
		assert!(!net.contains("172.17.0.1".parse().unwrap()));
		assert!(net.contains("::ffff:172.16.0.5".parse().unwrap()), "IPv4-mapped clients");
		assert!(!net.contains("fd00::1".parse().unwrap()));
		assert!(c("fd00::/8").contains("fdff::1".parse().unwrap()));
		assert!(c("0.0.0.0/0").contains("8.8.8.8".parse().unwrap()));
		assert!(allows(&[], "1.2.3.4".parse().unwrap()));
		assert!(!allows(&[net], "1.2.3.4".parse().unwrap()));
	}

	#[test]
	fn limits_the_list() {
		let many: Vec<String> = (0..65).map(|i| format!("10.0.0.{i}")).collect();
		assert_eq!(parse_list(&many).unwrap_err().code, "invalid");
		assert_eq!(parse_list(&many[..64]).unwrap().len(), 64);
	}
}
