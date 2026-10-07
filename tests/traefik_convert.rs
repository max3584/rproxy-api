//! contrib/traefik2rproxy.py: converts the Traefik configurations in
//! tests/fixtures/traefik/ and checks that rproxy reads and accepts the result.
//! Needs python3 with PyYAML; skipped without them unless
//! RPROXY_TEST_REQUIRE_PYTHON is set (CI sets it).

use std::path::{Path, PathBuf};
use std::process::Command;

use rproxy_api::config::ConfigDoc;
use rproxy_api::l7::MiddlewareSpec;
use rproxy_api::core::rule::{Caps, Features, RuleRequest};

fn root() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn python_ready() -> bool {
	let ok = Command::new("python3").args(["-c", "import yaml"]).output().is_ok_and(|o| o.status.success());
	if !ok {
		assert!(std::env::var_os("RPROXY_TEST_REQUIRE_PYTHON").is_none(), "python3 with PyYAML is required");
		eprintln!("skipped: python3 with PyYAML is not available");
	}
	ok
}

/// Runs the converter; returns (settings document, stderr).
fn convert(args: &[&str]) -> (ConfigDoc, String) {
	let out = Command::new("python3").arg(root().join("contrib/traefik2rproxy.py")).args(args).current_dir(root()).output().unwrap();
	let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
	assert!(out.status.success(), "converter failed:\n{stderr}");
	let text = String::from_utf8(out.stdout).unwrap();
	let doc = ConfigDoc::parse(Path::new("converted.yaml"), &text).unwrap_or_else(|e| panic!("{e}\n{text}"));
	let caps = Caps { transparent: true, transparent_ipv6: true, features: Features::ALL, ..Default::default() };
	for r in &doc.rules {
		r.clone().validate(&caps).unwrap_or_else(|e| panic!("{}:{}: {}\n{text}", r.protocol, r.listen_port, e.message));
	}
	(doc, stderr)
}

fn rule(doc: &ConfigDoc, port: u16) -> &RuleRequest {
	doc.rules.iter().find(|r| r.listen_port == port).unwrap_or_else(|| panic!("no rule on {port}"))
}

#[test]
fn gitlab_and_cdn_behind_crowdsec() {
	if !python_ready() {
		return;
	}
	let (doc, notes) = convert(&["--static", "tests/fixtures/traefik/gitlab-cdn/traefik.yml"]);
	assert_eq!(doc.rules.len(), 2);

	// 80: everything to https
	let http = rule(&doc, 80).http.as_ref().unwrap();
	assert_eq!(http.routes.len(), 1);
	assert!(matches!(http.middlewares["redirect"], MiddlewareSpec::RedirectScheme { permanent: true, port: None, .. }));

	// 443: the routers of both hosts on one rule, with one certificate from rproxy's ACME
	let r = rule(&doc, 443);
	let tls = r.tls.as_ref().unwrap();
	assert_eq!(tls.certificates.len(), 1, "cdn.example.com is a SAN of the gitlab certificate");
	assert_eq!(tls.certificates[0].acme.as_deref(), Some("letsencrypt"));
	assert_eq!(tls.certificates[0].domains, ["gitlab.example.com", "cdn.example.com"]);
	let acme = doc.global.acme.as_ref().unwrap();
	assert_eq!(acme.accounts["letsencrypt"].contact, ["mailto:admin@example.com"]);
	assert_eq!(acme.resolvers["letsencrypt"].challenge, "tls-alpn-01", "tlsChallenge");
	// the old way: certbot's files
	let (old, _) = convert(&["--static", "tests/fixtures/traefik/gitlab-cdn/traefik.yml", "--certs", "certbot"]);
	let old_tls = rule(&old, 443).tls.as_ref().unwrap();
	assert_eq!(old_tls.certificates[0].cert_file, "/etc/letsencrypt/live/gitlab.example.com/fullchain.pem");
	assert!(old.global.acme.is_none());
	let http = r.http.as_ref().unwrap();
	let names: Vec<&str> = http.routes.iter().map(|r| r.name.as_str()).collect();
	for want in ["gitlab-login", "gitlab-api", "gitlab-assets", "gitlab-internal", "gitlab", "cdn-allowed", "cdn-block", "metrics"] {
		assert!(names.contains(&want), "{want} missing: {names:?}");
	}
	assert!(!names.contains(&"dashboard"), "api@internal has no equivalent");
	// the Kubernetes routers on the same port pass TLS through by name (dynamic/k8s.yml)
	let pass: Vec<(Vec<String>, bool)> = tls.routes.iter().map(|r| (r.patterns(), r.passthrough)).collect();
	assert_eq!(
		pass,
		[
			(vec!["registry.example.com".to_string()], true),
			(vec!["**.tenant.example.com".to_string()], true),
			(vec!["*.apps.example.com".to_string()], true),
		]
	);
	assert!(!notes.contains("left out: registry"), "{notes}");
	assert!(http.http3);
	assert!(matches!(http.middlewares["crowdsec"], MiddlewareSpec::Crowdsec { appsec: true, .. }));
	assert!(matches!(&http.middlewares["rate-limit-login"], MiddlewareSpec::RateLimit { average: 5, period, burst: Some(10), .. } if period == "1m"));

	let crowdsec = doc.global.crowdsec.as_ref().unwrap();
	assert_eq!(crowdsec.lapi_url, "http://127.0.0.1:8080");
	assert_eq!(crowdsec.appsec_url.as_deref(), Some("http://127.0.0.1:7422"));
	assert_eq!(doc.global.trusted_proxies, ["10.0.0.0/8", "192.0.2.0/24"]);
	assert!(!notes.contains("not-a-real-key"), "the bouncer key must not be copied anywhere");
	assert!(notes.contains("api@internal"), "{notes}");
}

#[test]
fn tcp_and_udp_routers_from_toml() {
	if !python_ready()
		|| !Command::new("python3").args(["-c", "import tomllib"]).output().is_ok_and(|o| o.status.success())
	{
		return;
	}
	let (doc, _) = convert(&["--static", "tests/fixtures/traefik/tcp-udp/traefik.toml"]);
	assert_eq!(doc.rules.len(), 4);
	let sni = rule(&doc, 443);
	let tls = sni.tls.as_ref().unwrap();
	// one route per router; a router with several HostSNI names lists them in server_names
	assert_eq!(tls.routes.iter().map(|r| r.patterns().len()).sum::<usize>(), 2);
	// HostSNI(`*`) is the default: a weighted service becomes targets with weights
	let weights: Vec<(&str, Option<u32>)> = sni.targets.iter().map(|t| (t.addr.as_str(), t.weight)).collect();
	assert_eq!(weights, [("10.0.1.11", Some(3)), ("10.0.1.12", None)]);
	assert!(sni.remote_addr.is_empty());
	let ssh = rule(&doc, 2222);
	assert_eq!(ssh.listen_addr, "192.0.2.10");
	assert_eq!(ssh.source_ip.as_str(), "proxy_v2");
	assert_eq!(ssh.targets.len(), 2, "several servers: targets");
	let imaps = rule(&doc, 993).tls.as_ref().unwrap();
	assert_eq!(imaps.options.as_ref().unwrap().min_version.as_deref(), Some("1.3"));
	let dns = rule(&doc, 53);
	assert_eq!((dns.protocol.to_string().as_str(), dns.targets.len()), ("udp", 2));
}

#[test]
fn failover_services() {
	if !python_ready() {
		return;
	}
	let (doc, notes) = convert(&["--static", "tests/fixtures/traefik/failover/traefik.yml"]);
	let http = rule(&doc, 8080).http.as_ref().unwrap();
	let svc = http.services.values().find(|s| s.servers.len() == 3).unwrap();
	let urls: Vec<&str> = svc.servers.iter().map(|s| s.url.as_str()).collect();
	// h2c:// becomes protocol h2c (#233)
	let grpc = http.services.values().find(|s| s.servers.len() == 1).unwrap();
	assert_eq!((grpc.servers[0].url.as_str(), grpc.protocol), ("http://10.0.4.1:50051", rproxy_api::l7::UpstreamProtocol::H2c));
	assert_eq!(urls, ["http://10.0.2.1:80", "http://10.0.2.2:80", "http://10.0.3.1:80"], "main first, then the fallback");
	assert_eq!(svc.balance, rproxy_api::core::balance::Balance::Failover);
	assert!(svc.health_check.is_some());
	assert!(notes.contains("failover service"), "{notes}");
}

#[test]
fn docker_labels_with_middlewares() {
	if !python_ready() {
		return;
	}
	let (doc, notes) = convert(&[
		"--static",
		"tests/fixtures/traefik/docker/traefik.yml",
		"--docker",
		"tests/fixtures/traefik/docker/inspect.json",
	]);
	assert_eq!(doc.rules.len(), 2, "the container with traefik.enable=false is left out");
	let http = rule(&doc, 8443).http.as_ref().unwrap();
	let route = &http.routes[0];
	assert!(route.rule.contains("Header(`X-Env`, `prod`)"), "v2 Headers: {}", route.rule);
	assert!(route.rule.contains("HostRegexp("), "v2 placeholders: {}", route.rule);
	let kinds: Vec<&str> = route.middlewares.iter().map(|m| http.middlewares[m].kind()).collect();
	assert_eq!(
		kinds,
		["compress", "strip_prefix", "basic_auth", "forward_auth", "retry", "circuit_breaker", "errors", "buffering"],
		"entry point middlewares first, then the chain expanded in order"
	);
	assert!(http.services.contains_key("error-pages"), "the errors middleware's service comes along");
	assert!(http.services["whoami"].health_check.is_some());
	assert!(!notes.contains("needs features"), "authentication works now too: {notes}");
	let MiddlewareSpec::ForwardAuth { response_headers, trust_forward_header, .. } = &http.middlewares["forward"] else { panic!() };
	assert_eq!((response_headers.len(), *trust_forward_header), (2, true));
	let MiddlewareSpec::BasicAuth { keep_authorization, .. } = &http.middlewares["auth"] else { panic!() };
	assert!(*keep_authorization, "Traefik passes Authorization on unless removeHeader");
	assert!(!notes.contains("$apr1$"), "password hashes are not copied");
}

#[test]
fn cert_resolvers_become_acme_resolvers() {
	if !python_ready() {
		return;
	}
	let (doc, notes) = convert(&["--static", "tests/fixtures/traefik/acme/traefik.yml"]);
	let acme = doc.global.acme.as_ref().unwrap();
	// every challenge: dnsChallenge (pdns, a provider rproxy lacks), httpChallenge
	let challenges: Vec<(&str, &str, Option<&str>)> =
		acme.resolvers.iter().map(|(n, r)| (n.as_str(), r.challenge.as_str(), r.dns_provider.as_deref())).collect();
	assert_eq!(
		challenges,
		[("cloud", "dns-01", Some("cloud-dns")), ("web", "http-01", None), ("wildcard", "dns-01", Some("wildcard-dns"))]
	);
	assert_eq!(acme.dns_providers["wildcard-dns"].kind, "powerdns");
	assert_eq!(acme.dns_providers["cloud-dns"].kind, "http", "route53: a REST template to fill in");
	assert!(notes.contains("route53"), "{notes}");
	let account = &acme.accounts["wildcard"];
	assert_eq!(account.directory.as_deref(), Some("https://acme-staging-v02.api.letsencrypt.org/directory"));
	assert_eq!(account.allowed_names, ["apps.example.org", "*.apps.example.org"]);
	assert_eq!(account.eab.as_ref().unwrap().kid, "kid-123");
	assert_eq!(acme.dns_servers, ["10.0.0.53:53"]);
	// secrets are not copied; the wildcard comes with its apex in one certificate
	let text = std::fs::read_to_string(root().join("tests/fixtures/traefik/acme/traefik.yml")).unwrap();
	assert!(text.contains("not-a-real-hmac-SECRET"));
	let out = Command::new("python3")
		.arg(root().join("contrib/traefik2rproxy.py"))
		.args(["--static", "tests/fixtures/traefik/acme/traefik.yml"])
		.current_dir(root())
		.output()
		.unwrap();
	assert!(!String::from_utf8_lossy(&out.stdout).contains("SECRET") && !notes.contains("SECRET"));
	let certs = &rule(&doc, 443).tls.as_ref().unwrap().certificates;
	let got: Vec<(Option<&str>, usize)> = certs.iter().map(|c| (c.acme.as_deref(), c.domains.len())).collect();
	assert_eq!(got, [(Some("wildcard"), 2), (Some("web"), 2), (Some("cloud"), 1)]);
	assert!(notes.contains("acme.json") && notes.contains("CHANGE-ME"), "{notes}");
}
