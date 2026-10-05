//! CPU-only benchmarks (no sockets): the `match` expressions of L7 routes, the
//! TLS ClientHello walk of `sni` rules and the QUIC Initial of UDP `sni` rules.
//! Run with `cargo bench --bench parse`; CI compares a PR with its merge base
//! (.github/workflows/bench.yml, docs/TESTING.md).

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};

use rproxy_api::l7::matcher::{Matcher, RequestInfo};
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
	let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
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

fn config() -> Criterion {
	Criterion::default().warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(3))
}

criterion_group! {
	name = benches;
	config = config();
	targets = matcher, clienthello, quic
}
criterion_main!(benches);
