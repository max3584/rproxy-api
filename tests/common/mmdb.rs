//! A tiny MaxMind DB (mmdb) writer for tests (#168): Country and ASN databases
//! with made-up networks, so no MaxMind database is needed or committed. Only
//! what the tests use: an IPv6 tree (IPv4 under ::/96), 32-bit records, and
//! maps of strings and unsigned integers.
#![allow(dead_code)]

use std::net::IpAddr;

/// A value of the data section.
pub enum Value {
	Str(String),
	U32(u32),
	Map(Vec<(String, Value)>),
}

/// `{"country": {"iso_code": code}}`, as in GeoLite2-Country.
pub fn country(code: &str) -> Value {
	Value::Map(vec![("country".into(), Value::Map(vec![("iso_code".into(), Value::Str(code.into()))]))])
}

/// `{"registered_country": {"iso_code": code}}` only (no `country`), as for some anycast networks.
pub fn registered_country(code: &str) -> Value {
	Value::Map(vec![("registered_country".into(), Value::Map(vec![("iso_code".into(), Value::Str(code.into()))]))])
}

/// `{"autonomous_system_number": n, "autonomous_system_organization": org}`, as in GeoLite2-ASN.
pub fn asn(n: u32, org: &str) -> Value {
	Value::Map(vec![
		("autonomous_system_number".into(), Value::U32(n)),
		("autonomous_system_organization".into(), Value::Str(org.into())),
	])
}

fn control(out: &mut Vec<u8>, kind: u8, size: usize) {
	// kinds above 7 are "extended": type 0 and the kind - 7 in the next byte
	let (first, extended) = if kind > 7 { (0u8, Some(kind - 7)) } else { (kind << 5, None) };
	let (low, extra): (u8, Vec<u8>) = match size {
		0..=28 => (size as u8, vec![]),
		29..=284 => (29, vec![(size - 29) as u8]),
		285..=65_820 => (30, ((size - 285) as u16).to_be_bytes().to_vec()),
		_ => (31, ((size - 65_821) as u32).to_be_bytes()[1..].to_vec()),
	};
	out.push(first | low);
	out.extend(extended);
	out.extend(extra);
}

fn encode(out: &mut Vec<u8>, v: &Value) {
	match v {
		Value::Str(s) => {
			control(out, 2, s.len());
			out.extend_from_slice(s.as_bytes());
		}
		Value::U32(n) => {
			let bytes = n.to_be_bytes();
			let skip = bytes.iter().take_while(|b| **b == 0).count();
			control(out, 6, 4 - skip);
			out.extend_from_slice(&bytes[skip..]);
		}
		Value::Map(entries) => {
			control(out, 7, entries.len());
			for (k, v) in entries {
				encode(out, &Value::Str(k.clone()));
				encode(out, v);
			}
		}
	}
}

fn uint(out: &mut Vec<u8>, kind: u8, n: u64) {
	let bytes = n.to_be_bytes();
	let skip = bytes.iter().take_while(|b| **b == 0).count();
	control(out, kind, 8 - skip);
	out.extend_from_slice(&bytes[skip..]);
}

#[derive(Clone, Copy)]
enum Rec {
	Empty,
	Node(usize),
	Data(usize),
}

/// The bits of a network in the IPv6 tree (IPv4 under ::/96) and its length.
fn bits(net: &str) -> (u128, u32) {
	let (ip, len) = net.split_once('/').unwrap_or((net, ""));
	match ip.parse::<IpAddr>().unwrap() {
		IpAddr::V4(v4) => (u128::from(u32::from(v4)), 96 + len.parse::<u32>().unwrap_or(32)),
		IpAddr::V6(v6) => (u128::from(v6), len.parse::<u32>().unwrap_or(128)),
	}
}

/// An mmdb file with `networks` (`"10.1.0.0/16"`, `"2001:db8::/32"`, or a single address).
pub fn build(database_type: &str, networks: &[(&str, Value)]) -> Vec<u8> {
	let mut nodes: Vec<[Rec; 2]> = vec![[Rec::Empty; 2]];
	let mut data = vec![];
	for (net, value) in networks {
		let offset = data.len();
		encode(&mut data, value);
		let (addr, len) = bits(net);
		let mut node = 0;
		for depth in 0..len {
			let bit = ((addr >> (127 - depth)) & 1) as usize;
			if depth == len - 1 {
				nodes[node][bit] = Rec::Data(offset);
				break;
			}
			node = match nodes[node][bit] {
				Rec::Node(n) => n,
				_ => {
					nodes.push([Rec::Empty; 2]);
					let n = nodes.len() - 1;
					nodes[node][bit] = Rec::Node(n);
					n
				}
			};
		}
	}
	let count = nodes.len();
	let mut out = vec![];
	for node in &nodes {
		for rec in node {
			let v = match *rec {
				Rec::Empty => count,
				Rec::Node(n) => n,
				Rec::Data(offset) => count + 16 + offset,
			};
			out.extend_from_slice(&(v as u32).to_be_bytes());
		}
	}
	out.extend_from_slice(&[0u8; 16]);
	out.extend_from_slice(&data);
	out.extend_from_slice(b"\xAB\xCD\xEFMaxMind.com");
	let mut meta = vec![];
	control(&mut meta, 7, 9);
	let key = |m: &mut Vec<u8>, k: &str| encode(m, &Value::Str(k.into()));
	key(&mut meta, "node_count");
	uint(&mut meta, 6, count as u64);
	key(&mut meta, "record_size");
	uint(&mut meta, 5, 32);
	key(&mut meta, "ip_version");
	uint(&mut meta, 5, 6);
	key(&mut meta, "database_type");
	encode(&mut meta, &Value::Str(database_type.into()));
	key(&mut meta, "languages");
	control(&mut meta, 11, 1);
	encode(&mut meta, &Value::Str("en".into()));
	key(&mut meta, "binary_format_major_version");
	uint(&mut meta, 5, 2);
	key(&mut meta, "binary_format_minor_version");
	uint(&mut meta, 5, 0);
	key(&mut meta, "build_epoch");
	uint(&mut meta, 9, 1_700_000_000);
	key(&mut meta, "description");
	encode(&mut meta, &Value::Map(vec![("en".into(), Value::Str("rproxy test data".into()))]));
	out.extend(meta);
	out
}
