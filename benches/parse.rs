//! CPU-only benchmarks (no sockets): the `match` expressions of L7 routes, the
//! TLS ClientHello walk of `sni` rules, the QUIC Initial and the DTLS ClientHello
//! (whole, and in fragments, #332) of UDP `sni` rules, the
//! PROXY v2 header in front of each datagram of a UDP rule with `proxy_protocol`, and
//! the normalisation of request paths before routing (#320), and the choice of an L4 target
//! for a new connection (`balance`, with and without `max_connections`, #341).
//! Run with `cargo bench --bench parse`; CI compares a PR with its merge base
//! (.github/workflows/bench.yml, docs/TESTING.md).

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use rproxy_api::l7::matcher::{Matcher, RequestInfo};
use rproxy_api::net::proxy_in::{datagram, ProxyProtocol};
use rproxy_api::net::source::proxy_v2_dgram_header;
use rproxy_api::tls::sni::{parse_client_hello, Parse};
use rproxy_api::tls::udp_sni::{Sniff, Sniffer};

/// A route table like the GitLab / CDN examples in docs/PROFILES.md: the request
/// matches only the last route, so every earlier one is evaluated and rejected.
const ROUTES: &[&str] = &[
	"Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)",
	"Host(`gitlab.example.com`) && (PathPrefix(`/assets/`) || PathPrefix(`/uploads/`))",
	"Host(`cdn.example.com`) && PathRegexp(`^/v[0-9]+/`) && !ClientIP(`10.0.0.0/8`, `192.168.0.0/16`)",
	"HostRegexp(`^(www|static)\\.example\\.org$`) && Header(`x-tenant`, `blue`)",
	"Host(`*.internal.example`) && ClientIP(`10.0.0.0/8`)",
	"Host(`api.example.com`) && PathPrefix(`/v1/`) && Query(`debug`)",
	"Host(`api.example.com`) && PathPrefix(`/v2/`) && (Method(`GET`) || Method(`HEAD`)) && HeaderRegexp(`accept`, `json`)",
];

/// The path check every L7 request goes through (#320): an already normal path is only
/// scanned (borrowed, nothing allocated); one with escapes and dot segments is rebuilt.
fn path_normalize(c: &mut Criterion) {
	use rproxy_api::l7::normalize;
	let mut g = c.benchmark_group("path_normalize");
	g.throughput(Throughput::Elements(1));
	let normal = "/api/v2/projects/42/issues/%E3%81%82/comments.json";
	assert!(matches!(normalize::path(normal), Ok(std::borrow::Cow::Borrowed(_))));
	g.bench_function("normal", |b| b.iter(|| normalize::path(black_box(normal)).map(|p| p.len())));
	let odd = "/api//v2/./projects/%34%32/../42/issues/%e3%81%82/comments.json";
	g.bench_function("rebuilt", |b| b.iter(|| normalize::path(black_box(odd)).map(|p| p.len())));
	g.finish();
}

fn matcher(c: &mut Criterion) {
	let mut g = c.benchmark_group("matcher");
	let routes: Vec<Matcher> = ROUTES.iter().map(|r| Matcher::parse(r).unwrap()).collect();
	let headers = vec![
		("accept".to_string(), "application/json".to_string()),
		("user-agent".to_string(), "bench/1.0".to_string()),
		("x-tenant".to_string(), "green".to_string()),
	];
	let req = RequestInfo {
		host: "API.example.com:8443",
		path: "/v2/projects/42/issues",
		query: "page=2&per_page=50",
		method: "GET",
		headers: &headers,
		client: "203.0.113.9".parse().unwrap(),
	};
	assert_eq!(routes.iter().position(|m| m.matches(&req)), Some(ROUTES.len() - 1));

	g.throughput(Throughput::Elements(1));
	g.bench_function("route_table_7", |b| b.iter(|| black_box(&routes).iter().position(|m| m.matches(black_box(&req)))));
	// compiling the expressions (regexes included), as when a rule is created or changed
	g.throughput(Throughput::Elements(ROUTES.len() as u64));
	g.bench_function("parse_7", |b| b.iter(|| ROUTES.iter().map(|r| Matcher::parse(black_box(r)).unwrap()).collect::<Vec<_>>()));
	g.finish();
}

/// The ClientHello (TLS records included) that rustls sends for `name`.
fn client_hello(name: &str, alpn: &[&str]) -> Vec<u8> {
	let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
		.with_safe_default_protocol_versions()
		.unwrap()
		.with_root_certificates(rustls::RootCertStore::empty())
		.with_no_client_auth();
	config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
	let mut conn = rustls::ClientConnection::new(Arc::new(config), name.to_string().try_into().unwrap()).unwrap();
	let mut out = vec![];
	conn.write_tls(&mut out).unwrap();
	out
}

fn clienthello(c: &mut Criterion) {
	let mut g = c.benchmark_group("clienthello");
	let hello = client_hello("www.example.com", &["h2", "http/1.1"]);
	assert_eq!(parse_client_hello(&hello), Parse::Done(Some("www.example.com".into())));
	g.throughput(Throughput::Bytes(hello.len() as u64));
	g.bench_function("tls_sni", |b| b.iter(|| parse_client_hello(black_box(&hello))));

	// a bigger hello (many ALPN names), as with post-quantum key shares
	let alpn: Vec<String> = (0..20).map(|i| format!("{i:02}-{}", "x".repeat(150))).collect();
	let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
	let big = client_hello("www.example.com", &alpn);
	assert!(big.len() > 3000, "{}", big.len());
	assert_eq!(parse_client_hello(&big), Parse::Done(Some("www.example.com".into())));
	g.throughput(Throughput::Bytes(big.len() as u64));
	g.bench_function("tls_sni_3k", |b| b.iter(|| parse_client_hello(black_box(&big))));
	g.finish();
}

fn hex(s: &str) -> Vec<u8> {
	let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
	(0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn quic(c: &mut Criterion) {
	let mut g = c.benchmark_group("quic_initial");
	for (name, file) in [
		("v1", include_str!("../tests/fixtures/quic/rfc9001-client-initial.hex")),
		("v2", include_str!("../tests/fixtures/quic/rfc9369-client-initial.hex")),
	] {
		let packet = hex(file);
		assert_eq!(Sniffer::default().push(&packet), Sniff::Done(Some("example.com".into())));
		g.throughput(Throughput::Bytes(packet.len() as u64));
		// key derivation, header protection, AES-GCM and the ClientHello walk
		g.bench_function(name, |b| {
			b.iter_batched(Sniffer::default, |mut s| s.push(black_box(&packet)), BatchSize::SmallInput)
		});
	}
	g.finish();
}

/// DTLS records carrying the ClientHello rustls makes for `name` (as DTLS 1.2: an empty cookie after the session id),
/// cut into fragments at `cuts`, one record each.
fn dtls_hello(name: &str, alpn: &[&str], cuts: &[usize]) -> Vec<Vec<u8>> {
	let tls = client_hello(name, alpn);
	let mut hs = vec![];
	let mut p = &tls[..];
	while p.len() >= 5 {
		let len = u16::from_be_bytes([p[3], p[4]]) as usize;
		hs.extend_from_slice(&p[5..5 + len]);
		p = &p[5 + len..];
	}
	let tls_body = &hs[4..];
	let sid = usize::from(tls_body[34]);
	let body = [&[0xfe, 0xfd][..], &tls_body[2..35 + sid], &[0], &tls_body[35 + sid..]].concat();
	let mut bounds = vec![0];
	bounds.extend_from_slice(cuts);
	bounds.push(body.len());
	bounds
		.windows(2)
		.enumerate()
		.map(|(i, w)| {
			let frag = &body[w[0]..w[1]];
			let mut h = vec![1];
			h.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
			h.extend_from_slice(&[0, 0]);
			h.extend_from_slice(&(w[0] as u32).to_be_bytes()[1..]);
			h.extend_from_slice(&(frag.len() as u32).to_be_bytes()[1..]);
			h.extend_from_slice(frag);
			let mut rec = vec![22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, i as u8];
			rec.extend_from_slice(&(h.len() as u16).to_be_bytes());
			rec.extend_from_slice(&h);
			rec
		})
		.collect()
}

/// The DTLS ClientHello of a UDP `sni` rule (#130): whole in one datagram, and in 8
/// fragments, one datagram each, in order and in reverse order (the reassembly, #332).
fn dtls(c: &mut Criterion) {
	let mut g = c.benchmark_group("dtls_hello");
	let alpn: Vec<String> = (0..6).map(|i| format!("{i:02}-{}", "x".repeat(150))).collect();
	let alpn: Vec<&str> = alpn.iter().map(String::as_str).collect();
	let whole = dtls_hello("www.example.com", &alpn, &[]).remove(0);
	assert_eq!(Sniffer::default().push(&whole), Sniff::Done(Some("www.example.com".into())));
	g.throughput(Throughput::Bytes(whole.len() as u64));
	g.bench_function("one_datagram", |b| b.iter_batched(Sniffer::default, |mut s| s.push(black_box(&whole)), BatchSize::SmallInput));
	let len = whole.len() - 25;
	let cuts: Vec<usize> = (1..8).map(|i| len * i / 8).collect();
	let mut parts = dtls_hello("www.example.com", &alpn, &cuts);
	g.bench_function("fragments_8", |b| {
		b.iter_batched(Sniffer::default, |mut s| parts.iter().map(|p| s.push(black_box(p))).last(), BatchSize::SmallInput)
	});
	parts.reverse();
	let mut s = Sniffer::default();
	let got: Vec<Sniff> = parts.iter().map(|p| s.push(p)).collect();
	assert_eq!(got.last(), Some(&Sniff::Done(Some("www.example.com".into()))));
	g.bench_function("fragments_8_reversed", |b| {
		b.iter_batched(
			Sniffer::default,
			|mut s| parts.iter().map(|p| s.push(black_box(p))).last(),
			BatchSize::SmallInput,
		)
	});
	g.finish();
}

/// `proxy_protocol` of a udp rule (#312): what `l4::udp::serve` does for each datagram
/// from a front end before the usual checks: is the peer in `from`, read the v2 DGRAM
/// header, and the offset of the payload (nothing is copied or allocated).
fn proxy_dgram(c: &mut Criterion) {
	let mut g = c.benchmark_group("proxy_dgram");
	let pp = ProxyProtocol { from: vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()], required: true };
	let front: std::net::IpAddr = "10.1.2.3".parse().unwrap();
	for (name, src, dst) in [("v4", "192.0.2.7:4000", "10.9.9.9:443"), ("v6", "[2001:db8::7]:4000", "[fd00::9]:443")] {
		let d = [proxy_v2_dgram_header(src.parse().unwrap(), dst.parse().unwrap()), vec![0xc3; 1200]].concat();
		assert!(matches!(datagram(&pp, front, &d), Ok((Some(_), _))));
		g.throughput(Throughput::Elements(1));
		g.bench_function(name, |b| {
			b.iter(|| {
				let (client, skip) = datagram(black_box(&pp), black_box(front), black_box(&d)).unwrap();
				(client, black_box(&d[skip..]).len())
			})
		});
	}
	// a datagram from outside `from`: only its first bytes are looked at
	let plain = vec![0xc3; 1200];
	let outside: std::net::IpAddr = "192.0.2.1".parse().unwrap();
	g.bench_function("untrusted_plain", |b| b.iter(|| datagram(black_box(&pp), black_box(outside), black_box(&plain))));
	g.finish();
}

fn config() -> Criterion {
	Criterion::default().warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(3))
}

/// What every new L4 connection / UDP session does before it connects: the targets in the
/// order `balance` gives (`Pool::order`), and the count on the first one that has room
/// (`Lease::take`). Four targets; `_capped` gives each a `max_connections` it never reaches,
/// so the difference is the cost of looking at the counts.
fn balance(c: &mut Criterion) {
	use rproxy_api::core::balance::{Balance, Lease, Member, Pool, TargetSpec};
	let pool = |balance: Balance, max_connections: Option<u32>| {
		let members = (1..=4u16)
			.map(|port| {
				let spec = TargetSpec { addr: "127.0.0.1".into(), port, weight: None, backup: false, max_connections };
				let tx = tokio::sync::watch::channel(vec![std::net::SocketAddr::from(([127, 0, 0, 1], port))]).0;
				Arc::new(Member::new(spec, Arc::new(tx), None))
			})
			.collect();
		Pool::new(members, balance, Arc::new(tokio::sync::watch::channel(0).0), true)
	};
	let mut g = c.benchmark_group("balance");
	g.throughput(Throughput::Elements(1));
	for (name, balance, max) in [
		("round_robin", Balance::RoundRobin, None),
		("least_conn", Balance::LeastConn, None),
		("failover", Balance::Failover, None),
		("round_robin_capped", Balance::RoundRobin, Some(1_000_000)),
		("least_conn_capped", Balance::LeastConn, Some(1_000_000)),
	] {
		let p = pool(balance, max);
		g.bench_function(name, |b| b.iter(|| black_box(p.order().into_iter().find_map(Lease::take))));
	}
	g.finish();
}

criterion_group! {
	name = benches;
	config = config();
	targets = matcher, path_normalize, clienthello, quic, dtls, proxy_dgram, balance
}
criterion_main!(benches);
