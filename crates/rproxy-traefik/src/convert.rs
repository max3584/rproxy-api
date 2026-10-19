//! The conversion: Traefik's static and dynamic configuration → one rproxy settings
//! document (`version: 1`, `global`, `rules`). Each entry point becomes one rule; its
//! HTTP routers become `http.routes`, its TCP routers `tls.routes`, a UDP router the
//! rule's targets. What has no rproxy equivalent is noted (docs/MIGRATING-FROM-TRAEFIK.md).

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;

use crate::load::InputError;
use crate::middleware::{convert_middleware, duration, Converted, MiddlewareEnv, KNOWN_MIDDLEWARES, KNOWN_SERVICE_OPTIONS};
use crate::rule::{call_args, host_names, sni_regexp_pattern, translate_http_rule, CALL};
use crate::value::{
	as_bool, as_int, as_list, as_str_list, g, map, provider_of, py_repr_opt, py_str, py_str_opt, strip_provider, truthy, Map,
	Value,
};
use crate::{NoteSink, Notes};

/// Traefik's own services (`api@internal` and so on): a router to one is left out
/// unless its middlewares answer by themselves (a redirect).
const INTERNAL_SERVICES: &[&str] = &["api", "dashboard", "prometheus", "ping", "rest", "noop", "acme-http"];

/// Go (Traefik) names of cipher suites → rustls names; CBC and RSA key exchange have
/// no rustls equivalent.
const CIPHER_SUITES: &[(&str, &str)] = &[
	("TLS_AES_128_GCM_SHA256", "TLS13_AES_128_GCM_SHA256"),
	("TLS_AES_256_GCM_SHA384", "TLS13_AES_256_GCM_SHA384"),
	("TLS_CHACHA20_POLY1305_SHA256", "TLS13_CHACHA20_POLY1305_SHA256"),
	("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
	("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
	("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
	("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
	("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
	("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
	("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
	("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
];

/// Traefik's TLS versions → rproxy's `min_version`.
pub fn tls_version(v: &str) -> Option<&'static str> {
	match v {
		"VersionTLS12" => Some("1.2"),
		"VersionTLS13" => Some("1.3"),
		_ => None,
	}
}

/// A Go cipher suite name → the rustls name rproxy takes, if rustls has it.
pub fn cipher_suite(go_name: &str) -> Option<&'static str> {
	CIPHER_SUITES.iter().find(|(g, _)| *g == go_name).map(|(_, r)| *r)
}

/// Traefik's `clientAuthType` → rproxy's `client_auth.mode`.
pub fn client_auth_mode(t: &str) -> &'static str {
	match t {
		"RequestClientCert" | "VerifyClientCertIfGiven" => "optional",
		"RequireAnyClientCert" | "RequireAndVerifyClientCert" => "required",
		_ => "none",
	}
}

/// Where routers with a `certResolver` get their certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Certs {
	/// rproxy's own ACME (`global.acme`, one resolver per Traefik resolver).
	Acme,
	/// certbot's files under `certbot_live`.
	Certbot,
}

/// How to convert.
#[derive(Clone, Debug)]
pub struct Options {
	/// The address for entry points written as `:port`.
	pub listen_addr: String,
	/// With [`Certs::Certbot`]: where certbot keeps certificates.
	pub certbot_live: String,
	pub certs: Certs,
}

impl Default for Options {
	fn default() -> Options {
		Options { listen_addr: "0.0.0.0".into(), certbot_live: "/etc/letsencrypt/live".into(), certs: Certs::Acme }
	}
}

/// A backend of a TCP / UDP service: host, port, weight.
type Server = (String, i64, i64);

struct TcpRoute {
	name: String,
	names: Vec<String>,
	host: String,
	port: i64,
	servers: Vec<Server>,
	proxy: Option<i64>,
	tls: Option<Value>,
	client_ip: Vec<Vec<String>>,
}

impl TcpRoute {
	fn catch_all(&self) -> bool {
		self.names.iter().any(|n| n == "*")
	}

	fn passthrough(&self) -> bool {
		matches!(&self.tls, Some(t @ Value::Map(_)) if as_bool(g(t, &["passthrough"]), false))
	}
}

/// One entry point: one rproxy rule.
struct Rule {
	ep: String,
	protocol: String,
	addr: String,
	port: i64,
	/// (router name, route, TLS router?)
	http_routes: Vec<(String, Map, bool)>,
	services: Map,
	middlewares: Map,
	tcp_routes: Vec<TcpRoute>,
	udp_service: Option<Vec<Server>>,
	certificates: Vec<Value>,
	tls_options: Option<Value>,
	client_auth: Option<Map>,
	alpn: Option<Vec<Value>>,
	http3: bool,
	redirect: Option<Value>,
	default_middlewares: Vec<String>,
	default_tls: Option<Value>,
	/// `proxy_protocol` from the entry point's `proxyProtocol.trustedIPs` (tcp).
	proxy_protocol: Option<Value>,
}

/// The names of one certificate, in order and as a set.
type Lineage = (Vec<String>, HashSet<String>);

struct CertRequest {
	rule: usize,
	names: Vec<String>,
	explicit: bool,
	resolver: String,
	where_: String,
}

/// What converting fills in for `global`.
#[derive(Default)]
struct GlobalState {
	trusted_proxies: Vec<Value>,
	upstream: Map,
	crowdsec: Option<Map>,
}

/// The file provider's side of middleware conversion.
struct Ctx<'a> {
	notes: &'a mut Notes,
	global: &'a mut GlobalState,
	needs_services: Vec<String>,
}

impl NoteSink for Ctx<'_> {
	fn note(&mut self, where_: &str, text: &str) {
		self.notes.note(where_, text);
	}
}

impl MiddlewareEnv for Ctx<'_> {
	fn basic_auth_users_file(&mut self, name: &str, cfg: &Value, where_: &str) -> Option<String> {
		if let Some(f) = g(cfg, &["usersFile"]).filter(|v| v.truthy()) {
			return Some(py_str(f));
		}
		let f = format!("/etc/rproxy/auth/{name}.htpasswd");
		if truthy(g(cfg, &["users"])) {
			self.notes.note(where_, &format!("basicAuth.users are not copied; put them in {f} (htpasswd format)"));
		}
		Some(f)
	}

	fn errors_service(&mut self, service: Option<&Value>, _where: &str) -> Option<String> {
		let name = strip_provider(&service.filter(|v| v.truthy()).map(py_str).unwrap_or_default());
		if !self.needs_services.contains(&name) {
			self.needs_services.push(name.clone());
		}
		Some(name)
	}

	fn crowdsec_global(&mut self, global: Map, trusted_ips: Vec<Value>, where_: &str) {
		match &self.global.crowdsec {
			Some(c) if !c.is_empty() && *c != global => self.notes.note(
				where_,
				"several CrowdSec bouncer settings; rproxy has one (global.crowdsec), the first is used",
			),
			_ => self.global.crowdsec = Some(global),
		}
		self.global.trusted_proxies.extend(trusted_ips);
	}
}

/// An entry point or backend address: host (without `[]`), port, `tcp` / `udp`.
fn parse_address(address: Option<&Value>, where_: &str) -> Result<(String, i64, String), InputError> {
	static ADDRESS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.*):([0-9]+)(?:/(tcp|udp))?$").unwrap());
	let text = address.filter(|v| v.truthy()).map(py_str).unwrap_or_default();
	let fail = || InputError(format!("{where_}: address {} not understood", py_repr_opt(address)));
	let c = ADDRESS.captures(text.trim()).ok_or_else(fail)?;
	let port = c[2].parse::<i64>().map_err(|_| fail())?;
	Ok((c[1].trim_matches(['[', ']']).to_string(), port, c.get(3).map_or("tcp", |m| m.as_str()).to_string()))
}

/// A Traefik resolver name as an rproxy account / resolver name (letters, digits, `-`
/// and `_`).
fn acme_name(resolver: &str) -> String {
	let s: String = resolver.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).take(64).collect();
	if s.is_empty() {
		"acme".into()
	} else {
		s
	}
}

/// `Host(...)` of names as Python wrote it (backquotes), for `host_names`.
fn host_rule(names: &[String]) -> String {
	format!("Host({})", names.iter().filter(|n| *n != "*").map(|n| format!("`{n}`")).collect::<Vec<_>>().join(", "))
}

/// The arguments of `backends`: one backend → `remote_addr` / `remote_port`, several →
/// `targets` (round robin by weight).
fn backends(servers: &[Server]) -> Map {
	if servers.len() == 1 {
		let (host, port, _) = &servers[0];
		return map([("remote_addr", host.into()), ("remote_port", (*port).into())]);
	}
	let targets: Vec<Value> = servers
		.iter()
		.map(|(host, port, weight)| {
			let mut t = map([("addr", host.into()), ("port", (*port).into())]);
			if *weight != 1 {
				t.insert("weight", *weight);
			}
			Value::Map(t)
		})
		.collect();
	map([("targets", targets.into())])
}

/// A global.acme.dns_providers entry for a lego DNS provider, with placeholders.
fn dns_provider_skeleton(provider: &str, name: &str, names: &[String], where_: &str, notes: &mut Notes) -> Map {
	let allowed: Value = names.to_vec().into();
	let mut out = match provider {
		"pdns" => {
			notes.note(where_, &format!("dnsChallenge pdns: set api_url and write the API key into /etc/rproxy/acme/{name}-pdns.key"));
			map([
				("type", "powerdns".into()),
				("api_url", "http://CHANGE-ME.invalid:8081".into()),
				("api_key_file", format!("/etc/rproxy/acme/{name}-pdns.key").into()),
			])
		}
		"rfc2136" => {
			notes.note(
				where_,
				&format!("dnsChallenge rfc2136: set server and tsig_key_name, and write the TSIG secret into /etc/rproxy/acme/{name}-tsig.key"),
			);
			map([
				("type", "rfc2136".into()),
				("server", "127.0.0.1:53".into()),
				("tsig_key_name", "CHANGE-ME".into()),
				("tsig_secret_file", format!("/etc/rproxy/acme/{name}-tsig.key").into()),
			])
		}
		"acme-dns" | "acmedns" => {
			notes.note(where_, "dnsChallenge acme-dns: set api_url; existing lego accounts (ACME_DNS_STORAGE_PATH) can be used as credentials_file");
			map([
				("type", "acme_dns".into()),
				("api_url", "https://CHANGE-ME.invalid".into()),
				("credentials_file", "/var/lib/rproxy/acme/acme-dns.json".into()),
			])
		}
		_ => {
			let shown = if provider.is_empty() { "?" } else { provider };
			notes.note(
				where_,
				&format!(
					"dnsChallenge {shown}: rproxy has no such provider; a generic REST template (type http) with placeholders is written: point it at the provider's API or a small relay (docs/en/ACME.md)"
				),
			);
			let call = |method: &str| {
				map([
					("url", "https://CHANGE-ME.invalid/{fqdn}".into()),
					("headers", map([("Authorization", "Bearer {secret}".into())]).into()),
					("body", "{\"value\":\"{value}\"}".into()),
					("method", method.into()),
				])
			};
			map([
				("type", "http".into()),
				("add", call("POST").into()),
				("remove", call("DELETE").into()),
				("secret_file", format!("/etc/rproxy/acme/{name}-dns.token").into()),
			])
		}
	};
	out.insert("allowed_names", allowed);
	out
}

/// The converter. [`convert`] runs it.
struct Converter<'a> {
	static_: &'a Value,
	dynamic: &'a Value,
	http: Value,
	opts: Options,
	acme: Option<Map>,
	rules: Vec<Rule>,
	global: GlobalState,
	cert_requests: Vec<CertRequest>,
	lineage_names: Vec<(String, Vec<String>)>,
	notes: &'a mut Notes,
}

/// Converts Traefik's static and dynamic configuration (the dynamic one merged from
/// every source, Docker labels included) into an rproxy settings document. Notes (what
/// did not convert) are added to `notes`. An error only for an entry point address
/// that cannot be read.
pub fn convert(static_: &Value, dynamic: &Value, opts: &Options, notes: &mut Notes) -> Result<Value, InputError> {
	let empty = Value::Map(Map::new());
	let http = g(dynamic, &["http"]).filter(|v| v.truthy()).cloned().unwrap_or_else(|| empty.clone());
	let mut c = Converter {
		static_,
		dynamic,
		http,
		opts: Options { certbot_live: opts.certbot_live.trim_end_matches('/').to_string(), ..opts.clone() },
		acme: None,
		rules: vec![],
		global: GlobalState::default(),
		cert_requests: vec![],
		lineage_names: vec![],
		notes,
	};
	c.convert()
}

impl Converter<'_> {
	fn note(&mut self, where_: &str, text: &str) {
		self.notes.note(where_, text);
	}

	fn rule_index(&self, name: &str) -> Option<usize> {
		self.rules.iter().position(|r| r.ep == name)
	}

	fn entry_points(&mut self) -> Result<(), InputError> {
		let mut eps = match g(self.static_, &["entryPoints"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		if eps.is_empty() {
			self.note("static", "no entryPoints; using web (:80) and websecure (:443)");
			eps = map([("web", map([("address", ":80".into())]).into()), ("websecure", map([("address", ":443".into())]).into())]);
		}
		for (name, ep) in eps.iter() {
			let (host, port, proto) = parse_address(g(ep, &["address"]), &format!("entryPoints.{name}"))?;
			let empty = Value::Map(Map::new());
			let http = g(ep, &["http"]).filter(|v| v.truthy()).unwrap_or(&empty);
			let redirect = g(http, &["redirections", "entryPoint"]).filter(|v| v.truthy()).cloned();
			let default_middlewares = as_list(g(http, &["middlewares"])).iter().map(|m| strip_provider(&py_str(m))).collect();
			let default_tls = g(http, &["tls"]).map(|t| if t.truthy() { t.clone() } else { empty.clone() });
			for ip in as_list(g(ep, &["forwardedHeaders", "trustedIPs"])) {
				self.global.trusted_proxies.push(ip);
			}
			let where_ = format!("entryPoints.{name}");
			if as_bool(g(ep, &["forwardedHeaders", "insecure"]), false) {
				self.note(&where_, "forwardedHeaders.insecure: list the proxies in global.trusted_proxies instead");
			}
			// receiving PROXY headers: rproxy believes them only from listed front ends; as in
			// Traefik, the header is optional from them (required: false)
			let mut proxy_protocol = None;
			if let Some(pp) = g(ep, &["proxyProtocol"]) {
				let trusted = as_list(g(pp, &["trustedIPs"]));
				if proto != "tcp" {
					self.note(&where_, "proxyProtocol is read on tcp entry points only");
				} else if trusted.is_empty() {
					self.note(&where_, "proxyProtocol without trustedIPs: list the front ends in proxy_protocol.from");
				} else {
					proxy_protocol = Some(Value::Map(map([("from", trusted.into()), ("required", false.into())])));
				}
				if as_bool(g(pp, &["insecure"]), false) {
					self.note(&where_, "proxyProtocol.insecure: rproxy believes PROXY headers only from proxy_protocol.from");
				}
			}
			let rule = Rule {
				ep: name.clone(),
				protocol: proto,
				addr: if host.is_empty() { self.opts.listen_addr.clone() } else { host },
				port,
				http_routes: vec![],
				services: Map::new(),
				middlewares: Map::new(),
				tcp_routes: vec![],
				udp_service: None,
				certificates: vec![],
				tls_options: None,
				client_auth: None,
				alpn: None,
				http3: g(ep, &["http3"]).is_some(),
				redirect,
				default_middlewares,
				default_tls,
				proxy_protocol,
			};
			match self.rule_index(name) {
				Some(i) => self.rules[i] = rule,
				None => self.rules.push(rule),
			}
		}
		Ok(())
	}

	fn eps_for(&self, router: &Value, protocol: &str) -> Vec<usize> {
		let names = as_list(g(router, &["entryPoints"]));
		if names.is_empty() {
			return (0..self.rules.len()).filter(|i| self.rules[*i].protocol == protocol).collect();
		}
		names.iter().filter_map(|n| n.as_str().and_then(|n| self.rule_index(n))).collect()
	}

	// ------------------------------------------------------------ services

	fn http_service(&mut self, name: &str, where_: &str, seen: &[String]) -> Option<Map> {
		let Some(svc) = g(&self.http, &["services", name]).cloned() else {
			self.note(where_, &format!("service {name} is not defined"));
			return None;
		};
		let mut seen = seen.to_vec();
		seen.push(name.to_string());
		if let Some(lb) = g(&svc, &["loadBalancer"]) {
			let mut out = map([("servers", Value::List(vec![]))]);
			let mut servers = vec![];
			for s in as_list(g(lb, &["servers"])) {
				let mut url = g(&s, &["url"]).cloned().unwrap_or(Value::Null);
				// Traefik's h2c:// scheme: HTTP/2 without TLS (rproxy: protocol h2c, #233)
				if let Some(rest) = url.as_str().and_then(|u| u.strip_prefix("h2c://")) {
					url = format!("http://{rest}").into();
					out.insert("protocol", "h2c");
				}
				let mut server = map([("url", url)]);
				if let Some(w) = as_int(g(&s, &["weight"]), None).filter(|w| *w != 1) {
					server.insert("weight", w);
				}
				servers.push(Value::Map(server));
			}
			out.insert("servers", servers);
			if g(lb, &["passHostHeader"]).is_some() && !as_bool(g(lb, &["passHostHeader"]), false) {
				out.insert("pass_host_header", false);
			}
			if let Some(hc) = g(lb, &["healthCheck"]).filter(|v| v.truthy()) {
				let path = g(hc, &["path"]).filter(|v| v.truthy()).cloned().unwrap_or_else(|| "/".into());
				let mut check = map([("path", path)]);
				for (key, out_key) in [("interval", "interval"), ("timeout", "timeout")] {
					if truthy(g(hc, &[key])) {
						check.insert(out_key, duration(g(hc, &[key]), where_, None, self.notes));
					}
				}
				for opt in ["scheme", "port", "hostname", "headers", "status", "method", "mode"] {
					if g(hc, &[opt]).is_some() {
						self.note(where_, &format!("healthCheck.{opt} is not converted"));
					}
				}
				out.insert("health_check", check);
			}
			if let Some(sticky) = g(lb, &["sticky", "cookie"]) {
				let cookie = match sticky {
					Value::Map(_) => g(sticky, &["name"]).filter(|v| v.truthy()).cloned(),
					_ => None,
				};
				out.insert("sticky", map([("cookie", cookie.unwrap_or_else(|| format!("rproxy_{name}").into()))]));
			}
			if let Some(t) = g(lb, &["serversTransport"]).filter(|v| v.truthy()) {
				let st = g(&self.http, &["serversTransports", &strip_provider(&py_str(t))]).cloned().unwrap_or(Value::Map(Map::new()));
				self.apply_transport(&st, where_);
			}
			if g(lb, &["responseForwarding"]).is_some() {
				self.note(where_, "responseForwarding is not converted");
			}
			return Some(out);
		}
		if let Some(weighted) = g(&svc, &["weighted"]) {
			self.note(where_, &format!("weighted service {name}: flattened into one service (weights multiplied)"));
			let mut servers = vec![];
			for part in as_list(g(weighted, &["services"])) {
				let sub = strip_provider(&py_str_opt(g(&part, &["name"])));
				if seen.contains(&sub) {
					continue;
				}
				let inner = self.http_service(&sub, where_, &seen);
				let w = as_int(g(&part, &["weight"]), Some(1)).unwrap_or(1);
				for s in inner.as_ref().and_then(|i| i.get("servers")).and_then(Value::as_list).into_iter().flatten() {
					let sw = s.as_map().and_then(|m| m.get("weight")).and_then(|w| as_int(Some(w), None)).unwrap_or(1);
					servers.push(Value::Map(map([("url", s.as_map().and_then(|m| m.get("url")).cloned().unwrap_or(Value::Null)), ("weight", (w * sw).into())])));
				}
			}
			return (!servers.is_empty()).then(|| map([("servers", servers.into())]));
		}
		if let Some(failover) = g(&svc, &["failover"]) {
			let main = strip_provider(&g(failover, &["service"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default());
			let fallback = strip_provider(&g(failover, &["fallback"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default());
			let mut parts = vec![];
			for n in [&main, &fallback] {
				if !n.is_empty() && !seen.contains(n) {
					if let Some(p) = self.http_service(n, where_, &seen) {
						parts.push(p);
					}
				}
			}
			if parts.is_empty() {
				return None;
			}
			let mut out = parts[0].clone();
			let servers: Vec<Value> = parts.iter().flat_map(|p| p.get("servers").and_then(Value::as_list).cloned().unwrap_or_default()).collect();
			out.insert("servers", servers);
			out.insert("balance", "failover");
			self.note(
				where_,
				&format!(
					"failover service {name}: the servers of {main} then {fallback}, balance: failover (the first server that is up; within {main} no round robin)"
				),
			);
			if !parts.iter().any(|p| p.contains_key("health_check")) {
				self.note(where_, &format!("failover service {name}: add a health_check so a server that is down is noticed"));
			}
			return Some(out);
		}
		if let Some(mirroring) = g(&svc, &["mirroring"]) {
			let main = strip_provider(&py_str_opt(g(mirroring, &["service"])));
			self.note(
				where_,
				&format!(
					"mirroring service {name}: only its main service {main} is used (add a mirror middleware to the routes by hand to copy requests)"
				),
			);
			return if seen.contains(&main) { None } else { self.http_service(&main, where_, &seen) };
		}
		self.note(where_, &format!("service {name}: type not converted"));
		None
	}

	fn apply_transport(&mut self, st: &Value, where_: &str) {
		if as_bool(g(st, &["insecureSkipVerify"]), false) {
			self.global.upstream.insert("insecure_skip_verify", true);
			self.note(where_, "insecureSkipVerify: applies to every https:// backend of the rule in rproxy");
		}
		let cas = as_list(g(st, &["rootCAs"]));
		if let Some(first) = cas.first() {
			self.global.upstream.insert("ca_file", first.clone());
			if cas.len() > 1 {
				self.note(where_, "several rootCAs: only the first is used (concatenate them into one file)");
			}
		}
		if let Some(n) = g(st, &["serverName"]).filter(|v| v.truthy()) {
			self.global.upstream.insert("server_name", n.clone());
		}
	}

	// ------------------------------------------------------------ middlewares

	fn middleware_chain(&mut self, names: &[String], where_: &str, rule: usize, ctx: &mut Vec<String>, depth: usize) -> Vec<String> {
		let mut out = vec![];
		for name in names {
			let Some(spec) = g(&self.http, &["middlewares", name]).cloned() else {
				self.note(where_, &format!("middleware {name} is not defined (or not from the file provider); left out"));
				continue;
			};
			if self.rules[rule].middlewares.contains_key(name) {
				out.push(name.clone());
				continue;
			}
			let mut env = Ctx { notes: &mut *self.notes, global: &mut self.global, needs_services: std::mem::take(ctx) };
			let converted = convert_middleware(name, &spec, &format!("middleware {name}"), &mut env);
			*ctx = env.needs_services;
			match converted {
				Converted::Chain(chain) => {
					if depth < 5 {
						let names: Vec<String> = chain.into_iter().map(|c| c.name).collect();
						out.extend(self.middleware_chain(&names, where_, rule, ctx, depth + 1));
					}
				}
				Converted::None => {}
				Converted::One(v) => {
					self.rules[rule].middlewares.insert(name.clone(), v);
					out.push(name.clone());
				}
			}
		}
		out
	}

	// ------------------------------------------------------------ routers

	fn http_routers(&mut self) {
		let routers = match g(&self.http, &["routers"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		for (full_name, r) in routers.iter() {
			let name = strip_provider(full_name);
			let where_ = format!("router {name}");
			let Some(rule_text) = g(r, &["rule"]).filter(|v| v.truthy()).map(py_str) else {
				self.note(&where_, "no rule; left out");
				continue;
			};
			let Some(matched) = translate_http_rule(&rule_text, &where_, self.notes) else { continue };
			for ri in self.eps_for(r, "tcp") {
				if self.rules[ri].redirect.is_some() {
					let ep = self.rules[ri].ep.clone();
					self.note(&where_, &format!("on entry point {ep}, which redirects everything; left out there"));
					continue;
				}
				let mut tls = g(r, &["tls"]).cloned().or_else(|| self.rules[ri].default_tls.clone());
				if let Some(Value::Str(_)) = &tls {
					tls = if as_bool(tls.as_ref(), false) { Some(Value::Map(Map::new())) } else { None };
				}
				let mut ctx = vec![];
				let mut names = self.rules[ri].default_middlewares.clone();
				names.extend(as_list(g(r, &["middlewares"])).iter().map(|m| strip_provider(&py_str(m))));
				let mws = self.middleware_chain(&names, &where_, ri, &mut ctx, 0);
				let mut route = map([("name", name.as_str().into()), ("match", matched.as_str().into())]);
				if let Some(p) = as_int(g(r, &["priority"]), None).filter(|p| *p != 0) {
					route.insert("priority", p);
				}
				let service_v = g(r, &["service"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default();
				let svc = strip_provider(&service_v);
				let answered = mws.iter().any(|m| {
					self.rules[ri].middlewares.get(m).and_then(Value::as_map).and_then(Map::first).is_some_and(|(k, _)| {
						matches!(k.as_str(), "redirect_scheme" | "redirect_regex" | "respond")
					})
				});
				if INTERNAL_SERVICES.contains(&svc.as_str()) || provider_of(&service_v) == "internal" {
					if !answered {
						self.note(&where_, &format!("service {} is Traefik's own; router left out", py_str_opt(g(r, &["service"]))));
						continue;
					}
				} else if !svc.is_empty() {
					let Some(converted) = self.http_service(&svc, &where_, &[]) else { continue };
					self.rules[ri].services.insert(svc.clone(), converted);
					route.insert("service", svc.as_str());
				} else if !answered {
					self.note(&where_, "no service; left out");
					continue;
				}
				for extra in &ctx {
					if let Some(converted) = self.http_service(extra, &where_, &[]) {
						self.rules[ri].services.insert(extra.clone(), converted);
					}
				}
				if !mws.is_empty() {
					route.insert("middlewares", mws.clone());
				}
				if let Some(t) = &tls {
					self.router_tls(ri, t, &rule_text, &where_);
				}
				self.rules[ri].http_routes.push((name.clone(), route, tls.is_some()));
			}
		}
	}

	fn router_tls(&mut self, rule: usize, tls: &Value, rule_text: &str, where_: &str) {
		let resolver = g(tls, &["certResolver"]).filter(|v| v.truthy()).cloned();
		let mut domains: Vec<Value> = vec![];
		for d in as_list(g(tls, &["domains"])) {
			domains.push(g(&d, &["main"]).cloned().unwrap_or(Value::Null));
			domains.extend(as_list(g(&d, &["sans"])));
		}
		let explicit: Vec<String> = domains.iter().filter(|d| d.truthy()).map(py_str).collect();
		if let Some(resolver) = resolver {
			let names = if explicit.is_empty() { host_names(rule_text) } else { explicit.clone() };
			self.cert_requests.push(CertRequest {
				rule,
				names,
				explicit: !explicit.is_empty(),
				resolver: py_str(&resolver),
				where_: where_.to_string(),
			});
		}
		let options = strip_provider(&g(tls, &["options"]).filter(|v| v.truthy()).map_or_else(|| "default".into(), py_str));
		self.apply_tls_options(rule, &options, where_);
	}

	fn sorted_requests(&self) -> Vec<usize> {
		let mut order: Vec<usize> = (0..self.cert_requests.len()).collect();
		order.sort_by_key(|i| !self.cert_requests[*i].explicit);
		order
	}

	/// certResolver routers → rproxy's ACME (or certbot's files). Like Traefik, a
	/// certificate that already covers a router's names is reused; names given in
	/// tls.domains come first.
	fn assign_certificates(&mut self) {
		if self.opts.certs == Certs::Acme {
			return self.assign_acme();
		}
		let mut lineages: Vec<(String, HashSet<String>)> = vec![];
		for i in self.sorted_requests() {
			let req = &self.cert_requests[i];
			if req.names.is_empty() {
				continue;
			}
			let wanted: HashSet<String> = req.names.iter().cloned().collect();
			let found = match lineages.iter().find(|(_, have)| wanted.is_subset(have)) {
				Some((main, _)) => main.clone(),
				None => {
					let main = req.names[0].trim_start_matches(['*', '.']).to_string();
					lineages.push((main.clone(), wanted));
					let names = dedup(&req.names);
					match self.lineage_names.iter_mut().find(|(m, _)| *m == main) {
						Some(entry) => entry.1 = names,
						None => self.lineage_names.push((main.clone(), names)),
					}
					main
				}
			};
			let live = &self.opts.certbot_live;
			let cert = Value::Map(map([
				("cert_file", format!("{live}/{found}/fullchain.pem").into()),
				("key_file", format!("{live}/{found}/privkey.pem").into()),
			]));
			let rule = &mut self.rules[self.cert_requests[i].rule];
			if !rule.certificates.contains(&cert) {
				rule.certificates.push(cert);
			}
		}
		for i in 0..self.cert_requests.len() {
			let req = &self.cert_requests[i];
			if req.names.is_empty() && self.rules[req.rule].certificates.is_empty() {
				let (where_, text) = (req.where_.clone(), format!("certResolver {}: no domain to name the certificate by; add it by hand", req.resolver));
				self.note(&where_, &text);
			}
		}
		for (main, names) in self.lineage_names.clone() {
			let live = self.opts.certbot_live.clone();
			self.note(
				"certificates",
				&format!(
					"get {} with certbot (or cert-manager, or rproxy's own ACME: global.acme, docs/en/ACME.md) into {live}/{main}/; rproxy re-reads renewed files by itself",
					names.join(", ")
				),
			);
		}
	}

	/// certResolver routers → `{acme: <resolver>, domains: [...]}` and a global.acme
	/// skeleton: an account and a resolver per Traefik resolver, DNS providers with
	/// placeholders. No secret is copied (EAB keys, DNS credentials, acme.json): files to
	/// fill in are named.
	fn assign_acme(&mut self) {
		let resolvers = match g(self.static_, &["certificatesResolvers"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		let resolvers_v = Value::Map(resolvers.clone());
		let mut lineages: Vec<(String, Vec<Lineage>)> = vec![];
		let mut names_of: Vec<(String, Vec<String>)> = vec![];
		for i in self.sorted_requests() {
			let (rule, names, resolver, where_) = {
				let r = &self.cert_requests[i];
				(r.rule, r.names.clone(), r.resolver.clone(), r.where_.clone())
			};
			if names.is_empty() {
				self.note(&where_, &format!("certResolver {resolver}: no domain to name the certificate by; add it by hand"));
				continue;
			}
			if !resolvers.contains_key(&resolver) {
				self.note(&where_, &format!("certResolver {resolver} is not in certificatesResolvers; left out"));
				continue;
			}
			let wanted: HashSet<String> = names.iter().cloned().collect();
			let have = match lineages.iter_mut().position(|(r, _)| *r == resolver) {
				Some(p) => &mut lineages[p].1,
				None => {
					lineages.push((resolver.clone(), vec![]));
					&mut lineages.last_mut().unwrap().1
				}
			};
			let found = match have.iter().find(|(_, st)| wanted.is_subset(st)) {
				Some((lst, _)) => lst.clone(),
				None => {
					let lst = dedup(&names);
					have.push((lst.clone(), lst.iter().cloned().collect()));
					lst
				}
			};
			let all = match names_of.iter_mut().position(|(r, _)| *r == resolver) {
				Some(p) => &mut names_of[p].1,
				None => {
					names_of.push((resolver.clone(), vec![]));
					&mut names_of.last_mut().unwrap().1
				}
			};
			for n in &found {
				if !all.contains(n) {
					all.push(n.clone());
				}
			}
			let cert = Value::Map(map([("acme", acme_name(&resolver).into()), ("domains", found.into())]));
			if !self.rules[rule].certificates.contains(&cert) {
				self.rules[rule].certificates.push(cert);
			}
		}
		if names_of.is_empty() {
			return;
		}
		let mut accounts = Map::new();
		let mut acme_resolvers = Map::new();
		let mut dns_servers: Option<Vec<Value>> = None;
		let mut providers = Map::new();
		for (resolver, names) in &names_of {
			let empty = Value::Map(Map::new());
			let cfg = g(&resolvers_v, &[resolver, "acme"]).filter(|v| v.truthy()).unwrap_or(&empty).clone();
			let name = acme_name(resolver);
			let where_ = format!("certificatesResolvers.{resolver}");
			let mut account = Map::new();
			if let Some(ca) = g(&cfg, &["caServer"]).filter(|v| v.truthy()) {
				account.insert("directory", ca.clone());
			}
			if let Some(email) = g(&cfg, &["email"]).filter(|v| v.truthy()) {
				account.insert("contact", vec![format!("mailto:{}", py_str(email))]);
			}
			account.insert("allowed_names", names.clone());
			if let Some(eab) = g(&cfg, &["eab"]).filter(|v| v.truthy()) {
				let kid = g(eab, &["kid"]).filter(|v| v.truthy()).cloned().unwrap_or_else(|| "CHANGE-ME".into());
				account.insert("eab", map([("kid", kid), ("hmac_key_file", format!("/etc/rproxy/acme/{name}-eab.key").into())]));
				self.note(&where_, &format!("eab: write the HMAC key (hmacEncoded) into /etc/rproxy/acme/{name}-eab.key (not copied here)"));
			}
			accounts.insert(name.clone(), account);
			if let Some(storage) = g(&cfg, &["storage"]).filter(|v| v.truthy()) {
				self.note(
					&where_,
					&format!("storage {} (acme.json) is not read: rproxy creates a new account and obtains the certificates again", py_str(storage)),
				);
			}
			if let Some(dns) = g(&cfg, &["dnsChallenge"]) {
				let dns = if dns.truthy() { dns.clone() } else { Value::Map(Map::new()) };
				let provider = format!("{name}-dns");
				let kind = g(&dns, &["provider"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default();
				providers.insert(provider.clone(), dns_provider_skeleton(&kind, &name, names, &where_, self.notes));
				acme_resolvers.insert(
					name.clone(),
					map([("account", name.as_str().into()), ("challenge", "dns-01".into()), ("dns_provider", provider.into())]),
				);
				let servers: Vec<Value> = as_list(g(&dns, &["resolvers"])).into_iter().filter(Value::truthy).collect();
				if !servers.is_empty() {
					let list = dns_servers.get_or_insert_with(Vec::new);
					for s in servers {
						if !list.contains(&s) {
							list.push(s);
						}
					}
				}
			} else if g(&cfg, &["httpChallenge"]).is_some() {
				acme_resolvers.insert(name.clone(), map([("account", name.as_str().into()), ("challenge", "http-01".into())]));
				self.note(
					&where_,
					"httpChallenge: rproxy's http rules on port 80 answer HTTP-01 before their routes (or set global.acme.http01_listen)",
				);
			} else {
				acme_resolvers.insert(name.clone(), map([("account", name.as_str().into()), ("challenge", "tls-alpn-01".into())]));
			}
		}
		let mut acme = map([("accounts", accounts.into()), ("resolvers", acme_resolvers.into())]);
		if let Some(servers) = dns_servers {
			acme.insert("dns_servers", servers);
		}
		if !providers.is_empty() {
			acme.insert("dns_providers", providers);
		}
		self.acme = Some(acme);
		self.note(
			"global.acme",
			"check the accounts' allowed_names (the names found in the routers) and fill in every CHANGE-ME and secret file; then rproxy-api --check-config (docs/en/ACME.md)",
		);
	}

	fn apply_tls_options(&mut self, rule: usize, name: &str, where_: &str) {
		let Some(opts) = g(self.dynamic, &["tls", "options", name]).cloned() else { return };
		let label = format!("tls.options.{name}");
		let mut converted = Map::new();
		if let Some(version) = g(&opts, &["minVersion"]).filter(|v| v.truthy()) {
			match version.as_str().and_then(tls_version) {
				Some(v) => converted.insert("min_version", v),
				None => self.note(&label, &format!("minVersion {}: rproxy supports TLS 1.2 and 1.3 only", py_str(version))),
			}
		}
		let mut suites: Vec<Value> = vec![];
		for s in as_str_list(g(&opts, &["cipherSuites"])) {
			match cipher_suite(&s) {
				Some(r) => suites.push(r.into()),
				None => self.note(&label, &format!("cipher suite {s} is not available in rproxy; left out")),
			}
		}
		if !suites.is_empty() {
			converted.insert("cipher_suites", suites);
		}
		if truthy(g(&opts, &["maxVersion"])) || truthy(g(&opts, &["curvePreferences"])) || as_bool(g(&opts, &["sniStrict"]), false) {
			self.note(&label, "maxVersion / curvePreferences / sniStrict are not converted");
		}
		if !converted.is_empty() {
			let converted = Value::Map(converted);
			match &self.rules[rule].tls_options {
				Some(current) if *current != converted => {
					let ep = self.rules[rule].ep.clone();
					self.note(where_, &format!("entry point {ep}: routers use different TLS options; rproxy has one set per rule"));
				}
				_ => self.rules[rule].tls_options = Some(converted),
			}
		}
		let alpn = as_list(g(&opts, &["alpnProtocols"]));
		if !alpn.is_empty() {
			self.rules[rule].alpn = Some(alpn);
		}
		if let Some(ca) = g(&opts, &["clientAuth"]).filter(|v| v.truthy()) {
			let kind = g(ca, &["clientAuthType"]).filter(|v| v.truthy()).map_or_else(|| "NoClientCert".into(), py_str);
			let mode = client_auth_mode(&kind);
			let files = as_list(g(ca, &["caFiles"]));
			if mode != "none" {
				let mut auth = map([("mode", mode.into())]);
				if let Some(f) = files.first() {
					auth.insert("ca_file", f.clone());
				}
				if files.len() > 1 {
					self.note(&label, "several clientAuth.caFiles: concatenate them into one file");
				}
				self.rules[rule].client_auth = Some(auth);
			}
		}
	}

	/// The backends of a TCP / UDP service: a loadBalancer's servers, or a weighted
	/// service flattened (weights multiplied).
	fn l4_servers(&mut self, section: &str, name: &str, where_: &str, seen: &[String]) -> Vec<Server> {
		let Some(svc) = g(self.dynamic, &[section, "services", name]) else {
			self.note(where_, &format!("service {name} is not defined"));
			return vec![];
		};
		let mut seen = seen.to_vec();
		seen.push(name.to_string());
		if let Some(lb) = g(svc, &["loadBalancer"]) {
			let mut out = vec![];
			for s in as_list(g(lb, &["servers"])) {
				let address = g(&s, &["address"]);
				match parse_address(address, where_) {
					Ok((host, port, _)) => {
						let w = as_int(g(&s, &["weight"]), Some(1)).filter(|w| *w != 0).unwrap_or(1);
						out.push((host, port, w));
					}
					Err(_) => self.note(where_, &format!("backend address {} not understood; left out", py_repr_opt(address))),
				}
			}
			if g(lb, &["healthCheck"]).is_some() {
				self.note(
					where_,
					&format!("service {name}: healthCheck is not converted (rproxy checks L4 targets with a TCP connection: health_check)"),
				);
			}
			return out;
		}
		if let Some(weighted) = g(svc, &["weighted"]) {
			let mut out = vec![];
			for part in as_list(g(weighted, &["services"])) {
				let sub = strip_provider(&py_str_opt(g(&part, &["name"])));
				if seen.contains(&sub) {
					continue;
				}
				let w = as_int(g(&part, &["weight"]), Some(1)).filter(|w| *w != 0).unwrap_or(1);
				out.extend(self.l4_servers(section, &sub, where_, &seen).into_iter().map(|(h, p, pw)| (h, p, w * pw)));
			}
			return out;
		}
		self.note(where_, &format!("service {name}: type not converted"));
		vec![]
	}

	fn tcp_routers(&mut self) {
		let empty = Value::Map(Map::new());
		let tcp = g(self.dynamic, &["tcp"]).filter(|v| v.truthy()).unwrap_or(&empty).clone();
		let routers = match g(&tcp, &["routers"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		for (full_name, r) in routers.iter() {
			let name = strip_provider(full_name);
			let where_ = format!("tcp router {name}");
			let text = g(r, &["rule"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default();
			let mut names: Vec<String> = vec![];
			let mut others: Vec<Vec<String>> = vec![];
			for m in CALL.captures_iter(&text) {
				match &m[1] {
					"HostSNI" => names.extend(call_args(&m[2])),
					"HostSNIRegexp" => {
						for regex in call_args(&m[2]) {
							match sni_regexp_pattern(&regex) {
								Some(p) => names.push(p),
								None => self.note(
									&where_,
									&format!(
										"HostSNIRegexp `{regex}` is not a plain suffix; not converted (rproxy takes names, *.suffix for one label and **.suffix for any depth)"
									),
								),
							}
						}
					}
					"ClientIP" => others.push(call_args(&m[2])),
					other => self.note(&where_, &format!("{other} is not converted (rproxy L4 routes by SNI only)")),
				}
			}
			if text.contains("&&") && !names.is_empty() {
				self.note(&where_, "combined rule: only its HostSNI part is used");
			}
			let svc_name = strip_provider(&g(r, &["service"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default());
			let svc = g(&tcp, &["services", &svc_name, "loadBalancer"]).cloned();
			let servers = self.l4_servers("tcp", &svc_name, &where_, &[]);
			if servers.is_empty() {
				self.note(&where_, &format!("service {svc_name} has no servers; left out"));
				continue;
			}
			let (host, port, _) = servers[0].clone();
			let proxy = as_int(svc.as_ref().and_then(|s| g(s, &["proxyProtocol", "version"])), None);
			let mut tls = g(r, &["tls"]).cloned();
			if let Some(Value::Str(_)) = &tls {
				tls = if as_bool(tls.as_ref(), false) { Some(Value::Map(Map::new())) } else { None };
			}
			for ri in self.eps_for(r, "tcp") {
				if let Some(t) = &tls {
					if !as_bool(g(t, &["passthrough"]), false) {
						self.router_tls(ri, t, &host_rule(&names), &where_);
					}
				}
				self.rules[ri].tcp_routes.push(TcpRoute {
					name: name.clone(),
					names: if names.is_empty() { vec!["*".into()] } else { names.clone() },
					host: host.clone(),
					port,
					servers: servers.clone(),
					proxy,
					tls: tls.clone(),
					client_ip: others.clone(),
				});
			}
		}
		let udp = g(self.dynamic, &["udp"]).filter(|v| v.truthy()).unwrap_or(&empty).clone();
		let routers = match g(&udp, &["routers"]) {
			Some(Value::Map(m)) => m.clone(),
			_ => Map::new(),
		};
		for (full_name, r) in routers.iter() {
			let where_ = format!("udp router {}", strip_provider(full_name));
			let svc_name = strip_provider(&g(r, &["service"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default());
			let servers = self.l4_servers("udp", &svc_name, &where_, &[]);
			if servers.is_empty() {
				self.note(&where_, &format!("service {svc_name} has no servers; left out"));
				continue;
			}
			for ri in self.eps_for(r, "udp") {
				if self.rules[ri].udp_service.as_ref().is_some_and(|s| !s.is_empty()) {
					let ep = self.rules[ri].ep.clone();
					self.note(&where_, &format!("entry point {ep} already has a UDP router; left out"));
					continue;
				}
				self.rules[ri].udp_service = Some(servers.clone());
			}
		}
	}

	// ------------------------------------------------------------ output

	fn base(&self, rule: usize) -> Map {
		let r = &self.rules[rule];
		let mut m = map([("protocol", r.protocol.as_str().into()), ("listen_addr", r.addr.as_str().into()), ("listen_port", r.port.into())]);
		if let Some(pp) = &r.proxy_protocol {
			m.insert("proxy_protocol", pp.clone());
		}
		m
	}

	fn tls_spec(&mut self, rule: usize, mode: &str, where_: &str) -> Map {
		let mut tls = map([("mode", mode.into())]);
		if mode == "terminate" {
			let mut certs = self.rules[rule].certificates.clone();
			for c in as_list(g(self.dynamic, &["tls", "certificates"])) {
				let cert_file = g(&c, &["certFile"]).cloned().unwrap_or(Value::Null);
				let has_file = cert_file.truthy();
				let cert = Value::Map(map([("cert_file", cert_file), ("key_file", g(&c, &["keyFile"]).cloned().unwrap_or(Value::Null))]));
				if has_file && !certs.contains(&cert) {
					certs.push(cert);
				}
			}
			if certs.is_empty() {
				let ep = self.rules[rule].ep.clone();
				let (cert_file, key_file) = (format!("/etc/rproxy/tls/{ep}.pem"), format!("/etc/rproxy/tls/{ep}.key"));
				self.note(where_, &format!("no certificate found; put one at {cert_file}"));
				certs.push(Value::Map(map([("cert_file", cert_file.into()), ("key_file", key_file.into())])));
			}
			tls.insert("certificates", certs);
			let r = &self.rules[rule];
			if let Some(o) = r.tls_options.as_ref().filter(|o| o.truthy()) {
				tls.insert("options", o.clone());
			}
			if let Some(ca) = r.client_auth.as_ref().filter(|c| !c.is_empty()) {
				tls.insert("client_auth", ca.clone());
			}
			if let Some(alpn) = r.alpn.as_ref().filter(|a| !a.is_empty()) {
				tls.insert("alpn", alpn.clone());
			}
		}
		tls
	}

	fn sni_route(&mut self, rule: usize, t: usize, where_: &str, passthrough: bool) -> Value {
		let route = &self.rules[rule].tcp_routes[t];
		let names: Vec<String> = route.names.iter().map(|n| n.to_lowercase()).collect();
		let mut out = if names.len() == 1 { map([("server_name", names[0].as_str().into())]) } else { map([("server_names", names.into())]) };
		out.insert("remote_addr", route.host.as_str());
		out.insert("remote_port", route.port);
		if passthrough {
			out.insert("passthrough", true);
		}
		if route.servers.len() > 1 {
			let text = format!("router {}: a server-name route (tls.routes) has one backend; the first is used", route.name);
			self.note(where_, &text);
		}
		Value::Map(out)
	}

	fn output_rules(&mut self) -> Vec<Value> {
		let mut order: Vec<usize> = (0..self.rules.len()).collect();
		order.sort_by(|a, b| {
			let (a, b) = (&self.rules[*a], &self.rules[*b]);
			(a.port, &a.protocol, &a.addr).cmp(&(b.port, &b.protocol, &b.addr))
		});
		let mut out = vec![];
		for ri in order {
			let where_ = format!("entry point {}", self.rules[ri].ep);
			if self.rules[ri].protocol == "udp" {
				if let Some(servers) = self.rules[ri].udp_service.clone().filter(|s| !s.is_empty()) {
					let mut rule = self.base(ri);
					for (k, v) in backends(&servers) {
						rule.insert(k, v);
					}
					out.push(Value::Map(rule));
				}
				continue;
			}
			if self.rules[ri].redirect.is_some() {
				out.push(self.redirect_rule(ri));
				if !self.rules[ri].tcp_routes.is_empty() {
					self.note(&where_, "TCP routers on an entry point that redirects are left out");
				}
				continue;
			}
			if !self.rules[ri].http_routes.is_empty() {
				let routes = &self.rules[ri].tcp_routes;
				let passthrough: Vec<usize> = (0..routes.len()).filter(|i| routes[*i].passthrough() && !routes[*i].catch_all()).collect();
				let rest: Vec<String> = (0..routes.len()).filter(|i| !passthrough.contains(i)).map(|i| routes[i].name.clone()).collect();
				if !rest.is_empty() {
					self.note(
						&where_,
						&format!(
							"TCP routers next to HTTP routers on one port are combined only when they pass TLS through for named hosts; left out: {}",
							rest.join(", ")
						),
					);
				}
				out.push(self.http_rule(ri, &where_, &passthrough));
			} else if !self.rules[ri].tcp_routes.is_empty() {
				out.push(self.tcp_rule(ri, &where_));
			}
		}
		out
	}

	fn redirect_rule(&mut self, ri: usize) -> Value {
		let redir = self.rules[ri].redirect.clone().unwrap_or(Value::Null);
		let to = g(&redir, &["to"]).filter(|v| v.truthy()).map(py_str).unwrap_or_default();
		let target = self.rule_index(&to);
		let scheme = g(&redir, &["scheme"]).filter(|v| v.truthy()).cloned().unwrap_or_else(|| "https".into());
		let mut mw = map([("scheme", scheme.clone()), ("permanent", as_bool(g(&redir, &["permanent"]), true).into())]);
		let port = match target {
			None if !to.is_empty() && to.bytes().all(|b| b.is_ascii_digit()) => to.parse::<i64>().unwrap_or(443),
			Some(t) => self.rules[t].port,
			None => 443,
		};
		if port != (if scheme == Value::from("https") { 443 } else { 80 }) {
			mw.insert("port", port);
		}
		let route = map([
			("name", "redirect".into()),
			("match", "PathPrefix(`/`)".into()),
			("priority", 1000000.into()),
			("middlewares", vec!["redirect"].into()),
		]);
		let http = map([
			("routes", vec![Value::Map(route)].into()),
			("middlewares", map([("redirect", map([("redirect_scheme", mw.into())]).into())]).into()),
		]);
		let mut rule = self.base(ri);
		rule.insert("http", http);
		Value::Map(rule)
	}

	fn http_rule(&mut self, ri: usize, where_: &str, passthrough: &[usize]) -> Value {
		let all = self.rules[ri].http_routes.clone();
		let tls_routes: Vec<&(String, Map, bool)> = all.iter().filter(|r| r.2).collect();
		let plain: Vec<&(String, Map, bool)> = all.iter().filter(|r| !r.2).collect();
		let mut routes: Vec<&(String, Map, bool)> = all.iter().collect();
		let mut mode = None;
		if !tls_routes.is_empty() {
			mode = Some("terminate");
			if !plain.is_empty() {
				let names: Vec<&str> = plain.iter().map(|r| r.0.as_str()).collect();
				self.note(where_, &format!("routers without TLS on a TLS entry point are left out: {}", names.join(", ")));
			}
			routes = tls_routes;
		}
		let mut http = Map::new();
		if self.rules[ri].http3 {
			http.insert("http3", true);
		}
		let mut names = HashSet::new();
		let mut list = vec![];
		for (name, route, _) in &routes {
			if names.insert(name.clone()) {
				list.push(Value::Map(route.clone()));
			}
		}
		http.insert("routes", list);
		let mut used_services: HashSet<String> = routes.iter().filter_map(|(_, r, _)| r.get("service").map(py_str)).collect();
		let used_mws: HashSet<String> = routes
			.iter()
			.flat_map(|(_, r, _)| r.get("middlewares").and_then(Value::as_list).cloned().unwrap_or_default())
			.map(|m| py_str(&m))
			.collect();
		let rule = &self.rules[ri];
		for m in &used_mws {
			if let Some(svc) = rule.middlewares.get(m).and_then(|spec| g(spec, &["errors", "service"])) {
				used_services.insert(py_str(svc));
			}
		}
		let services: Map = rule.services.iter().filter(|(k, _)| used_services.contains(*k)).map(|(k, v)| (k.clone(), v.clone())).collect();
		let middlewares: Map = rule.middlewares.iter().filter(|(k, _)| used_mws.contains(*k)).map(|(k, v)| (k.clone(), v.clone())).collect();
		let uses_https = services.values().any(|svc| {
			svc.as_map()
				.and_then(|s| s.get("servers"))
				.and_then(Value::as_list)
				.is_some_and(|l| l.iter().any(|s| g(s, &["url"]).and_then(Value::as_str).is_some_and(|u| u.starts_with("https://"))))
		});
		if !services.is_empty() {
			http.insert("services", services);
		}
		if !middlewares.is_empty() {
			http.insert("middlewares", middlewares);
		}
		let mut result = self.base(ri);
		let upstream = self.global.upstream.clone();
		if let Some(mode) = mode {
			let mut tls = self.tls_spec(ri, mode, where_);
			if !upstream.is_empty() && uses_https {
				tls.insert("upstream", upstream);
			}
			if !passthrough.is_empty() {
				let routes: Vec<Value> = passthrough
					.iter()
					.map(|t| {
						let mut route = self.sni_route(ri, *t, where_, true);
						// PROXY protocol towards this passthrough backend only (#297)
						let own = source_name(self.rules[ri].tcp_routes[*t].proxy);
						if let (Value::Map(m), true) = (&mut route, own != "proxy") {
							m.insert("source_ip", own);
						}
						route
					})
					.collect();
				tls.insert("routes", routes);
				for t in passthrough {
					let route = &self.rules[ri].tcp_routes[*t];
					let (name, client_ip) = (route.name.clone(), !route.client_ip.is_empty());
					if client_ip {
						self.note(where_, &format!("router {name}: ClientIP is not converted for passthrough routes"));
					}
				}
			}
			result.insert("tls", tls);
		} else if !passthrough.is_empty() {
			let names: Vec<String> = passthrough.iter().map(|t| self.rules[ri].tcp_routes[*t].name.clone()).collect();
			self.note(
				where_,
				&format!("TLS passthrough routers need an entry point whose HTTP routers use TLS; left out: {}", names.join(", ")),
			);
		} else if !upstream.is_empty() && uses_https {
			self.note(
				where_,
				"serversTransport settings (insecureSkipVerify, rootCAs) apply in rproxy only to rules that terminate TLS; https:// backends of this plain-HTTP rule are verified against the system roots",
			);
		}
		result.insert("http", http);
		Value::Map(result)
	}

	fn tcp_rule(&mut self, ri: usize, where_: &str) -> Value {
		let routes_all = &self.rules[ri].tcp_routes;
		let n = routes_all.len();
		let catch_all: Vec<usize> = (0..n).filter(|i| routes_all[*i].catch_all()).collect();
		let named: Vec<usize> = (0..n).filter(|i| !routes_all[*i].catch_all()).collect();
		let passthrough: Vec<usize> = (0..n).filter(|i| routes_all[*i].passthrough()).collect();
		let mut terminate: Vec<usize> = (0..n).filter(|i| routes_all[*i].tls.is_some() && !passthrough.contains(i)).collect();
		let mut routes: Vec<usize> = (0..n).collect();
		if !passthrough.is_empty() && !terminate.is_empty() && passthrough.iter().any(|i| routes_all[*i].catch_all()) {
			let names: Vec<String> = terminate.iter().map(|i| routes_all[*i].name.clone()).collect();
			self.note(
				where_,
				&format!(
					"a HostSNI(`*`) passthrough router cannot share a port with terminating routers; terminating routers left out: {}",
					names.join(", ")
				),
			);
			routes.retain(|i| !terminate.contains(i));
			terminate.clear();
		}
		let routes_all = &self.rules[ri].tcp_routes;
		let mut proxies: Vec<Option<i64>> = vec![];
		for i in &routes {
			if !proxies.contains(&routes_all[*i].proxy) {
				proxies.push(routes_all[*i].proxy);
			}
		}
		let ips: Vec<String> = routes.iter().flat_map(|i| routes_all[*i].client_ip.iter().flatten().cloned()).collect();
		let default = catch_all.first().copied().unwrap_or(routes[0]);
		let backend = backends(&routes_all[default].servers);
		let proxy = routes_all[routes[0]].proxy;
		// routes relayed at L4 (mode sni, passthrough) carry their own source_ip (#297);
		// terminated routes and the default take the rule's
		let sni_mode = terminate.is_empty();
		let conflict = routes.iter().any(|i| {
			let r = &routes_all[*i];
			source_name(r.proxy) != source_name(proxy) && !(named.contains(i) && (sni_mode || r.passthrough()))
		});
		if proxies.len() > 1 && conflict {
			self.note(where_, "routers use different PROXY protocol versions; rproxy has one per rule for terminated routes and the default (the first is used)");
		}
		let mut result = self.base(ri);
		for (k, v) in backend {
			result.insert(k, v);
		}
		if let Some(p @ (1 | 2)) = proxy {
			result.insert("source_ip", format!("proxy_v{p}"));
		}
		if !ips.is_empty() {
			result.insert("allow_from", ips);
			self.note(where_, "ClientIP of TCP routers applies to the whole rule (allow_from)");
		}
		if named.is_empty() && terminate.is_empty() && passthrough.is_empty() {
			if catch_all.len() > 1 {
				self.note(where_, "several HostSNI(`*`) routers; the first is used");
			}
			return Value::Map(result);
		}
		let mode = if terminate.is_empty() { "sni" } else { "terminate" };
		let mut tls = if mode == "terminate" { self.tls_spec(ri, mode, where_) } else { map([("mode", "sni".into())]) };
		let routes: Vec<Value> = named
			.iter()
			.map(|t| {
				let pass = mode == "terminate" && self.rules[ri].tcp_routes[*t].passthrough();
				let own = source_name(self.rules[ri].tcp_routes[*t].proxy);
				let mut route = self.sni_route(ri, *t, where_, pass);
				if (mode == "sni" || pass) && own != source_name(proxy) {
					if let Value::Map(m) = &mut route {
						m.insert("source_ip", own);
					}
				}
				route
			})
			.collect();
		tls.insert("routes", routes);
		if catch_all.is_empty() {
			tls.insert("unmatched", "reject");
		}
		result.insert("tls", tls);
		Value::Map(result)
	}

	fn global_spec(&mut self) -> Map {
		let mut out = Map::new();
		let mut proxies: Vec<Value> = vec![];
		for ip in &self.global.trusted_proxies {
			if !proxies.contains(ip) {
				proxies.push(ip.clone());
			}
		}
		if !proxies.is_empty() {
			out.insert("trusted_proxies", proxies);
		}
		if let Some(access) = g(self.static_, &["accessLog"]) {
			match g(access, &["filePath"]).filter(|v| v.truthy()) {
				Some(path) => {
					out.insert("access_log", path.clone());
					self.note("accessLog", "rproxy writes JSON Lines (event http.access); Traefik's format and filters are not converted");
				}
				None => self.note(
					"accessLog",
					"Traefik logs to stdout; rproxy writes http.access lines to its own log unless global.access_log is set",
				),
			}
		}
		if let Some(c) = self.global.crowdsec.as_ref().filter(|c| !c.is_empty()) {
			out.insert("crowdsec", c.clone());
		}
		if let Some(acme) = self.acme.as_ref().filter(|a| !a.is_empty()) {
			out.insert("acme", acme.clone());
		}
		out
	}

	fn convert(&mut self) -> Result<Value, InputError> {
		self.entry_points()?;
		if let Some(st) = g(self.static_, &["serversTransport"]).filter(|v| v.truthy()) {
			self.apply_transport(st, "serversTransport");
		}
		self.http_routers();
		self.tcp_routers();
		self.assign_certificates();
		if self.opts.certs != Certs::Acme {
			if let Some(Value::Map(resolvers)) = g(self.static_, &["certificatesResolvers"]) {
				for name in resolvers.keys() {
					self.note(
						"certificatesResolvers",
						&format!("{name}: not converted (--certs certbot); use certbot / cert-manager and point cert_file / key_file at the files"),
					);
				}
			}
		}
		if g(self.static_, &["api"]).is_some() {
			self.note("api", "Traefik's dashboard has no equivalent; use the rproxy UI (TCP-UDP-rproxy-ui)");
		}
		if g(self.static_, &["metrics"]).is_some() {
			self.note("metrics", "rproxy serves Prometheus metrics at GET /metrics of its control API");
		}
		let rules = self.output_rules();
		let mut doc = map([("version", 1.into())]);
		let glob = self.global_spec();
		if !glob.is_empty() {
			doc.insert("global", glob);
		}
		doc.insert("rules", rules);
		Ok(Value::Map(doc))
	}
}

/// `source_ip` for a Traefik service's `proxyProtocol.version`.
fn source_name(version: Option<i64>) -> &'static str {
	match version {
		Some(1) => "proxy_v1",
		Some(2) => "proxy_v2",
		_ => "proxy",
	}
}

fn dedup(names: &[String]) -> Vec<String> {
	let mut out: Vec<String> = vec![];
	for n in names {
		if !out.contains(n) {
			out.push(n.clone());
		}
	}
	out
}

/// What a settings document uses that rproxy may lack: middleware kinds, service
/// options (`health_check`, `sticky`, `balance`) and whether `http3` is on.
pub fn used_features(doc: &Value) -> (Vec<String>, Vec<String>, bool) {
	let (mut mws, mut opts, mut http3) = (Vec::<String>::new(), Vec::<String>::new(), false);
	for r in as_list(g(doc, &["rules"])) {
		let empty = Value::Map(Map::new());
		let http = r.as_map().and_then(|m| m.get("http")).filter(|v| v.truthy()).unwrap_or(&empty);
		http3 |= http.as_map().and_then(|m| m.get("http3")).is_some_and(Value::truthy);
		for spec in http.as_map().and_then(|m| m.get("middlewares")).and_then(Value::as_map).into_iter().flat_map(Map::values) {
			for k in spec.as_map().into_iter().flat_map(Map::keys) {
				if !mws.contains(k) {
					mws.push(k.clone());
				}
			}
		}
		for svc in http.as_map().and_then(|m| m.get("services")).and_then(Value::as_map).into_iter().flat_map(Map::values) {
			for k in KNOWN_SERVICE_OPTIONS {
				if svc.as_map().is_some_and(|s| s.contains_key(k)) && !opts.iter().any(|o| o == k) {
					opts.push(k.to_string());
				}
			}
		}
	}
	(mws, opts, http3)
}

/// The features a settings document needs that the target rproxy does not list:
/// checked against `GET /capabilities` (its JSON) when given, otherwise against what
/// this converter knows rproxy runs. Adds a note when something is missing.
pub fn check_capabilities(doc: &Value, capabilities: Option<&Value>, notes: &mut Notes) -> Vec<String> {
	let (mws, opts, http3) = used_features(doc);
	let (known_mws, known_opts, has_http3): (Vec<String>, Vec<String>, bool) = match capabilities {
		Some(caps) => {
			let empty = Value::Map(Map::new());
			let features = caps.as_map().and_then(|m| m.get("features")).filter(|v| v.truthy()).unwrap_or(&empty);
			let list = |key: &str| -> Vec<String> {
				features.as_map().and_then(|m| m.get(key)).and_then(Value::as_list).map(|l| l.iter().map(py_str).collect()).unwrap_or_default()
			};
			(list("middlewares"), list("services"), features.as_map().and_then(|m| m.get("http3")).is_some_and(Value::truthy))
		}
		None => (
			KNOWN_MIDDLEWARES.iter().map(|s| s.to_string()).collect(),
			KNOWN_SERVICE_OPTIONS.iter().map(|s| s.to_string()).collect(),
			true,
		),
	};
	let mut missing_mws: Vec<String> = mws.into_iter().filter(|m| !known_mws.contains(m)).collect();
	missing_mws.sort();
	let mut missing_opts: Vec<String> = opts.into_iter().filter(|o| !known_opts.contains(o)).collect();
	missing_opts.sort();
	let mut missing = missing_mws;
	missing.extend(missing_opts);
	if http3 && !has_http3 {
		missing.push("http3".into());
	}
	if !missing.is_empty() {
		let source = if capabilities.is_some() { "GET /capabilities" } else { "rproxy at the time of this converter" };
		notes.note(
			"",
			&format!(
				"needs features that {source} does not list yet (rules using them are refused as unsupported): {}",
				missing.join(", ")
			),
		);
	}
	missing
}
