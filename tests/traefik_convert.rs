//! The Traefik converter (crates/rproxy-traefik, `rproxy-traefik-convert`):
//! converts the Traefik configurations in tests/fixtures/traefik/ and checks that
//! rproxy reads and accepts the result. The crate's own tests
//! (crates/rproxy-traefik/tests/fixtures.rs) hold the output to the expected files
//! byte for byte; these check what the result means to rproxy.

use std::path::{Path, PathBuf};

use clap::Parser;
use rproxy_api::config::ConfigDoc;
use rproxy_api::core::rule::{Caps, Features, RuleRequest};
use rproxy_api::l7::MiddlewareSpec;
use rproxy_traefik::cli::{self, Args};

fn root() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Runs the converter on arguments as the command takes them (paths relative to
/// `dir`); returns (settings text, notes).
fn run_in(dir: &Path, args: &[&str]) -> (String, String) {
	let mut argv = vec!["rproxy-traefik-convert".to_string()];
	let mut path_next = false;
	for a in args {
		argv.push(if path_next { dir.join(a).to_string_lossy().into_owned() } else { a.to_string() });
		path_next = matches!(*a, "--static" | "--dynamic" | "--docker" | "--capabilities");
	}
	let out = cli::run(&Args::try_parse_from(&argv).unwrap()).unwrap_or_else(|e| panic!("{args:?}: {e:?}"));
	(out.text, out.notes.join("\n"))
}

/// Converts and checks that rproxy reads the settings and accepts every rule.
fn accepted(text: &str, what: &str) -> ConfigDoc {
	let doc = ConfigDoc::parse(Path::new("converted.yaml"), text).unwrap_or_else(|e| panic!("{what}: {e}\n{text}"));
	let caps = Caps { transparent: true, transparent_ipv6: true, features: Features::ALL, ..Default::default() };
	for r in &doc.rules {
		r.clone().validate(&caps).unwrap_or_else(|e| panic!("{what}: {}:{}: {}\n{text}", r.protocol, r.listen_port, e.message));
	}
	doc
}

/// Runs the converter (paths relative to the repository); returns (settings document, notes).
fn convert(args: &[&str]) -> (ConfigDoc, String) {
	let (text, notes) = run_in(&root(), args);
	(accepted(&text, &format!("{args:?}")), notes)
}

fn rule(doc: &ConfigDoc, port: u16) -> &RuleRequest {
	doc.rules.iter().find(|r| r.listen_port == port).unwrap_or_else(|| panic!("no rule on {port}"))
}

/// Every case of every fixture (tests/fixtures/traefik/*/cases) converts into
/// settings that rproxy accepts.
#[test]
fn every_fixture_is_accepted() {
	let base = root().join("tests/fixtures/traefik");
	let mut n = 0;
	for dir in std::fs::read_dir(&base).unwrap().map(|e| e.unwrap().path()).filter(|p| p.is_dir()) {
		let cases = std::fs::read_to_string(dir.join("cases")).unwrap();
		for line in cases.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
			let args: Vec<&str> = line.split_whitespace().skip(1).collect();
			let (text, _) = run_in(&dir, &args);
			accepted(&text, &format!("{} {line}", dir.display()));
			n += 1;
		}
	}
	assert!(n >= 10, "{n} cases");
}

/// What the converter assumes rproxy runs (without --capabilities) is what this
/// build runs.
#[test]
fn known_features_are_current() {
	for m in rproxy_traefik::KNOWN_MIDDLEWARES {
		assert!(Features::CURRENT.middlewares.contains(m), "KNOWN_MIDDLEWARES has {m}, which rproxy does not run");
	}
	for s in rproxy_traefik::KNOWN_SERVICE_OPTIONS {
		assert!(Features::CURRENT.services.contains(s), "KNOWN_SERVICE_OPTIONS has {s}");
	}
}

#[test]
fn gitlab_and_cdn_behind_crowdsec() {
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
	// an older rproxy (GET /capabilities) lacks the authentication middlewares
	let (_, notes) = convert(&[
		"--static",
		"tests/fixtures/traefik/docker/traefik.yml",
		"--docker",
		"tests/fixtures/traefik/docker/inspect.json",
		"--capabilities",
		"tests/fixtures/traefik/docker/capabilities.json",
	]);
	assert!(notes.contains("GET /capabilities does not list yet") && notes.contains("basic_auth, forward_auth, sticky"), "{notes}");
}

#[test]
fn cert_resolvers_become_acme_resolvers() {
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
	let (out, _) = run_in(&root(), &["--static", "tests/fixtures/traefik/acme/traefik.yml"]);
	assert!(!out.contains("SECRET") && !notes.contains("SECRET"));
	let certs = &rule(&doc, 443).tls.as_ref().unwrap().certificates;
	let got: Vec<(Option<&str>, usize)> = certs.iter().map(|c| (c.acme.as_deref(), c.domains.len())).collect();
	assert_eq!(got, [(Some("wildcard"), 2), (Some("web"), 2), (Some("cloud"), 1)]);
	assert!(notes.contains("acme.json") && notes.contains("CHANGE-ME"), "{notes}");
}

#[test]
fn every_middleware_kind() {
	let (doc, notes) = convert(&["--static", "tests/fixtures/traefik/middlewares/traefik.yml"]);
	let http = rule(&doc, 8443).http.as_ref().unwrap();
	let mut kinds: Vec<&str> = http.middlewares.values().map(MiddlewareSpec::kind).collect();
	kinds.sort();
	kinds.dedup();
	assert_eq!(
		kinds,
		[
			"add_prefix",
			"basic_auth",
			"buffering",
			"circuit_breaker",
			"compress",
			"forward_auth",
			"headers",
			"in_flight",
			"ip_allow",
			"rate_limit",
			"redirect_regex",
			"redirect_scheme",
			"replace_path",
			"replace_path_regex",
			"retry",
			"strip_prefix",
		]
	);
	let MiddlewareSpec::BasicAuth { keep_authorization, users_file, .. } = &http.middlewares["users"] else { panic!() };
	assert_eq!((users_file.as_str(), *keep_authorization), ("/etc/traefik/users.htpasswd", false), "removeHeader: true");
	// the chain inside a chain comes in order
	let admin = http.routes.iter().find(|r| r.name == "admin").unwrap();
	assert_eq!(admin.middlewares, ["security", "office", "users", "in-flight", "breaker"]);
	// a router to Traefik's own service stays when a middleware answers by itself
	assert!(http.routes.iter().any(|r| r.name == "to-dashboard" && r.service.is_none()));
	// weighted: flattened with the weights multiplied
	let weights: Vec<Option<u32>> = http.services["api-split"].servers.iter().map(|s| s.weight).collect();
	assert_eq!(weights, [Some(3), Some(2)]);
	let tls = rule(&doc, 8443).tls.as_ref().unwrap();
	assert_eq!(tls.upstream.ca_file.as_deref(), Some("/etc/traefik/ca/internal.pem"));
	for want in ["digestAuth has no rproxy equivalent", "plugin geoblock", "not one middleware type", "middleware missing is not defined"] {
		assert!(notes.contains(want), "{want}: {notes}");
	}
	// the redirecting entry point goes to the port given by number
	let MiddlewareSpec::RedirectScheme { port, permanent, .. } = &rule(&doc, 80).http.as_ref().unwrap().middlewares["redirect"] else {
		panic!()
	};
	assert_eq!((*port, *permanent), (Some(8443), false));
}

#[test]
fn tcp_routers_that_terminate_tls() {
	let (doc, notes) = convert(&["--static", "tests/fixtures/traefik/tls-tcp/traefik.toml"]);
	let smtps = rule(&doc, 465);
	assert_eq!(smtps.allow_from, ["192.0.2.0/24", "2001:db8::/32"]);
	let certs: Vec<Option<&str>> = smtps.tls.as_ref().unwrap().certificates.iter().map(|c| c.acme.as_deref()).collect();
	assert_eq!(certs, [Some("le"), Some("zone")]);
	let acme = doc.global.acme.as_ref().unwrap();
	assert_eq!((acme.dns_providers["le-dns"].kind.as_str(), acme.dns_providers["zone-dns"].kind.as_str()), ("rfc2136", "acme_dns"));
	assert!(notes.contains("terminating routers left out: term"), "{notes}");
	let (doc, _) = convert(&["--static", "tests/fixtures/traefik/tls-tcp/traefik.toml", "--certs", "certbot"]);
	let certs: Vec<&str> = rule(&doc, 465).tls.as_ref().unwrap().certificates.iter().map(|c| c.cert_file.as_str()).collect();
	assert_eq!(certs, ["/etc/letsencrypt/live/mail.example.net/fullchain.pem", "/etc/letsencrypt/live/mx.example.net/fullchain.pem"]);
	let game = rule(&doc, 27015);
	let weights: Vec<Option<u32>> = game.targets.iter().map(|t| t.weight).collect();
	assert_eq!(weights, [Some(6), None]);
}
