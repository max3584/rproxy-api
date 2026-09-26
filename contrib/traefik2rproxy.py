#!/usr/bin/env python3
"""Convert a Traefik configuration into an rproxy settings file (RPROXY_CONFIG).

Reads the Traefik static configuration (entry points, trusted IPs, access log,
plugins), the dynamic configuration (file provider: routers, services,
middlewares, TLS) and optionally `docker inspect` output (labels), and writes
one rproxy settings document (`version: 1`, `global`, `rules`).

Settings that have no rproxy equivalent are listed as comments at the top of the
output and on stderr. See docs/MIGRATING-FROM-TRAEFIK.md.

  traefik2rproxy.py --static /etc/traefik/traefik.yml > /etc/rproxy/rproxy.yaml
  traefik2rproxy.py --static traefik.toml --dynamic dynamic/ --docker inspect.json -o rproxy.yaml

Needs Python 3.8+. YAML input and output need PyYAML (python3-yaml); without
it the output is JSON (rproxy reads that too). TOML input needs Python 3.11+.
"""

import argparse
import json
import math
import os
import re
import sys

try:
    import yaml
except ImportError:  # JSON output still works
    yaml = None

# What rproxy-api (master at the time of writing) runs; the rest is refused as
# `unsupported` until a newer version adds it. GET /capabilities tells for sure.
KNOWN_MIDDLEWARES = {
    "redirect_scheme", "redirect_regex", "ip_allow", "headers", "strip_prefix", "add_prefix",
    "replace_path", "replace_path_regex", "respond", "rate_limit", "in_flight", "crowdsec", "compress", "buffering",
    "retry", "circuit_breaker", "errors", "basic_auth", "forward_auth", "oidc",
}
KNOWN_SERVICE_OPTIONS = {"health_check", "sticky"}

INTERNAL_SERVICES = {"api", "dashboard", "prometheus", "ping", "rest", "noop", "acme-http"}

# Go (Traefik) names of cipher suites -> rustls names; CBC and RSA key exchange have no rustls equivalent
CIPHER_SUITES = {
    "TLS_AES_128_GCM_SHA256": "TLS13_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384": "TLS13_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256": "TLS13_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
}

TLS_VERSIONS = {"VersionTLS12": "1.2", "VersionTLS13": "1.3"}

CLIENT_AUTH = {
    "NoClientCert": "none",
    "RequestClientCert": "optional",
    "VerifyClientCertIfGiven": "optional",
    "RequireAnyClientCert": "required",
    "RequireAndVerifyClientCert": "required",
}


class Notes:
    """Things that did not convert, shown in the output and on stderr."""

    def __init__(self):
        self.items = []

    def add(self, where, text):
        line = f"{where}: {text}" if where else text
        if line not in self.items:
            self.items.append(line)


NOTES = Notes()


class InputError(Exception):
    pass


# ---------------------------------------------------------------- reading


def load_file(path):
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise InputError(f"{path}: {e}") from e
    try:
        if ext in (".yml", ".yaml"):
            if yaml is None:
                raise InputError(f"{path}: reading YAML needs PyYAML (apt install python3-yaml)")
            return yaml.safe_load(data) or {}
        if ext == ".toml":
            try:
                import tomllib
            except ImportError as e:
                raise InputError(f"{path}: reading TOML needs Python 3.11 or later") from e
            return tomllib.loads(data.decode())
        if ext == ".json":
            return json.loads(data)
    except InputError:
        raise
    except Exception as e:  # noqa: BLE001 - any parser error
        raise InputError(f"{path}: {e}") from e
    raise InputError(f"{path}: unknown file type (use .yml, .yaml, .toml or .json)")


def load_dynamic(path):
    """A file, or every configuration file of a directory (like the file provider)."""
    if os.path.isdir(path):
        merged = {}
        for name in sorted(os.listdir(path)):
            if name.startswith(".") or os.path.splitext(name)[1].lower() not in (".yml", ".yaml", ".toml", ".json"):
                continue
            deep_merge(merged, load_file(os.path.join(path, name)))
        return merged
    return load_file(path)


def deep_merge(into, other):
    for k, v in (other or {}).items():
        if isinstance(v, dict) and isinstance(into.get(k), dict):
            deep_merge(into[k], v)
        else:
            into[k] = v
    return into


def g(d, *keys, default=None):
    """Case-insensitive lookup through nested maps (TOML and labels differ in case)."""
    cur = d
    for key in keys:
        if not isinstance(cur, dict):
            return default
        if key in cur:
            cur = cur[key]
            continue
        low = key.lower()
        for k, v in cur.items():
            if isinstance(k, str) and k.lower() == low:
                cur = v
                break
        else:
            return default
    return cur


def as_list(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    if isinstance(v, dict):  # labels: domains[0] -> {"0": ...}
        return [v[k] for k in sorted(v, key=lambda x: int(x) if str(x).isdigit() else 0)]
    return list(v)


def as_bool(v, default=False):
    if v is None:
        return default
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes")
    return bool(v)


def as_int(v, default=None):
    if v is None or v == "":
        return default
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def strip_provider(name):
    return str(name).split("@", 1)[0]


def provider_of(name):
    return str(name).split("@", 1)[1] if "@" in str(name) else ""


def duration(v, where, default=None):
    """A Go duration (or seconds as a number) as rproxy writes it: 500ms, 10s, 5m, 1h."""
    if v is None or v == "":
        return default
    if isinstance(v, (int, float)):
        ms = int(v * 1000)
    else:
        total = 0.0
        parts = re.findall(r"([0-9.]+)(ns|us|µs|ms|s|m|h)", str(v))
        if not parts or "".join(a + b for a, b in parts) != str(v).strip():
            if re.fullmatch(r"[0-9.]+", str(v).strip()):
                return duration(float(v), where, default)
            NOTES.add(where, f"duration {v!r} not understood; left out")
            return default
        unit = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "ms": 1, "s": 1000, "m": 60000, "h": 3600000}
        for num, u in parts:
            total += float(num) * unit[u]
        ms = int(round(total))
    for size, unit in ((3600000, "h"), (60000, "m"), (1000, "s")):
        if ms and ms % size == 0:
            return f"{ms // size}{unit}"
    return f"{max(ms, 1)}ms"


# ---------------------------------------------------------------- docker labels


def labels_to_config(labels):
    """traefik.http.routers.x.rule=... labels as a nested map like the file provider's."""
    root = {}
    for key, value in labels.items():
        if not key.startswith("traefik."):
            continue
        parts = key.split(".")[1:]
        cur = root
        for i, part in enumerate(parts):
            m = re.fullmatch(r"(.+)\[(\d+)\]", part)
            names = [m.group(1), m.group(2)] if m else [part]
            for j, name in enumerate(names):
                last = i == len(parts) - 1 and j == len(names) - 1
                if last:
                    cur[name] = value
                else:
                    nxt = cur.get(name)
                    if not isinstance(nxt, dict):
                        nxt = cur[name] = {}
                    cur = nxt
    return root


def load_docker(path):
    containers = load_file(path)
    if isinstance(containers, dict):
        containers = [containers]
    dynamic = {}
    for c in containers:
        labels = g(c, "Config", "Labels") or g(c, "Labels") or {}
        name = str(g(c, "Name") or g(c, "Names") or "container").lstrip("/")
        if not as_bool(labels.get("traefik.enable"), default=True):
            continue
        conf = labels_to_config(labels)
        http = g(conf, "http") or {}
        routers = g(http, "routers") or {}
        services = g(http, "services") or {}
        networks = g(c, "NetworkSettings", "Networks") or {}
        wanted = labels.get("traefik.docker.network")
        ip = None
        for net, info in networks.items():
            if wanted and net != wanted:
                continue
            ip = g(info, "IPAddress") or ip
            if ip:
                break
        host = ip or name
        if not ip:
            NOTES.add(f"docker {name}", f"no container IP in the inspect output; the backend is written as {name!r}")
        exposed = sorted((g(c, "Config", "ExposedPorts") or {}).keys())
        default_port = exposed[0].split("/")[0] if exposed else None
        if routers and not services:
            services = {name: {}}
        for sname, svc in services.items():
            lb = g(svc, "loadBalancer") or {}
            server = g(lb, "server") or {}
            port = server.get("port") or default_port
            scheme = server.get("scheme") or "http"
            if port is None:
                NOTES.add(f"docker {name}", f"service {sname}: no port (loadbalancer.server.port); left out")
                continue
            lb = dict(lb)
            lb.pop("server", None)
            lb["servers"] = [{"url": f"{scheme}://{host}:{port}"}]
            svc = dict(svc)
            svc["loadBalancer"] = lb
            services[sname] = svc
        for rname, r in routers.items():
            if not g(r, "service") and len(services) == 1:
                r["service"] = next(iter(services))
            if not g(r, "rule"):
                NOTES.add(f"docker {name}", f"router {rname}: no rule (Traefik's defaultRule is not converted); left out")
        http["routers"] = {k: v for k, v in routers.items() if g(v, "rule")}
        http["services"] = services
        conf["http"] = http
        deep_merge(dynamic, conf)
    return dynamic


# ---------------------------------------------------------------- rule syntax

CALL = re.compile(r"([A-Za-z]+)\(((?:\s*(?:`[^`]*`|\"(?:[^\"\\]|\\.)*\")\s*,?)*)\)")
ARG = re.compile(r"`([^`]*)`|\"((?:[^\"\\]|\\.)*)\"")
PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::((?:[^{}]|\{[^{}]*\})*))?\}")
HTTP_MATCHERS = {"Host", "HostRegexp", "Path", "PathPrefix", "PathRegexp", "Method", "Header", "HeaderRegexp",
                 "Query", "QueryRegexp", "ClientIP"}


def call_args(text):
    return [a if a is not None else b for a, b in ARG.findall(text)]


def quote(args):
    return ", ".join(f"`{a}`" for a in args)


def v2_template(value, segment):
    """Traefik v2 placeholders ({name} or {name:regex}) as a regular expression."""
    out, pos = "", 0
    for m in PLACEHOLDER.finditer(value):
        out += re.escape(value[pos:m.start()]) + "(?:" + (m.group(2) or segment) + ")"
        pos = m.end()
    return out + re.escape(value[pos:])


def translate_http_rule(rule, where):
    """Traefik v2 / v3 router rule -> rproxy `match` (the v3 syntax). None if it cannot be expressed."""
    failed = []

    def one(m):
        name, args = m.group(1), call_args(m.group(2))
        if name in ("Headers", "HeadersRegexp"):
            name = name.replace("Headers", "Header")
        if name == "HostHeader":
            name = "Host"
        if name == "Query" and len(args) == 1 and "=" in args[0]:
            args = args[0].split("=", 1)
        if name in ("Host", "HostRegexp") and any(PLACEHOLDER.search(a) for a in args):
            regex = "|".join(v2_template(a, "[^.]+") if PLACEHOLDER.search(a) else re.escape(a) for a in args)
            NOTES.add(where, "v2 host placeholders converted to HostRegexp")
            return f"HostRegexp(`^(?:{regex})$`)"
        if name in ("Path", "PathPrefix") and any(PLACEHOLDER.search(a) for a in args):
            regex = "|".join(v2_template(a, "[^/]+") if PLACEHOLDER.search(a) else re.escape(a) for a in args)
            end = "$" if name == "Path" else ""
            NOTES.add(where, "v2 path placeholders converted to PathRegexp")
            return f"PathRegexp(`^(?:{regex}){end}`)"
        if name == "HostRegexp" and len(args) > 1:
            args = ["|".join(f"(?:{a})" for a in args)]
        if name not in HTTP_MATCHERS:
            failed.append(name)
            return m.group(0)
        return f"{name}({quote(args)})"

    out = CALL.sub(one, rule.strip())
    if failed:
        NOTES.add(where, f"matcher {', '.join(sorted(set(failed)))} has no rproxy equivalent; router left out")
        return None
    return out


def host_names(rule):
    names = []
    for m in CALL.finditer(rule or ""):
        if m.group(1) in ("Host", "HostHeader"):
            names += [a.lower() for a in call_args(m.group(2)) if not PLACEHOLDER.search(a)]
    return names


# ---------------------------------------------------------------- middlewares


def convert_headers(cfg, where):
    out = {}
    req = {"set": {}, "remove": []}
    resp = {"set": {}, "remove": []}
    for key, ops in (("customRequestHeaders", req), ("customResponseHeaders", resp)):
        for k, v in (g(cfg, key) or {}).items():
            if v in ("", None):
                ops["remove"].append(k)
            else:
                ops["set"][k] = str(v)
    if g(cfg, "customFrameOptionsValue"):
        resp["set"]["X-Frame-Options"] = str(g(cfg, "customFrameOptionsValue"))
    if as_bool(g(cfg, "browserXssFilter")):
        resp["set"]["X-XSS-Protection"] = "1; mode=block"
    if g(cfg, "permissionsPolicy"):
        resp["set"]["Permissions-Policy"] = str(g(cfg, "permissionsPolicy"))
    for name, ops in (("request", req), ("response", resp)):
        entry = {k: v for k, v in ops.items() if v}
        if entry:
            out[name] = entry
    sts = as_int(g(cfg, "stsSeconds"), 0)
    if sts > 0:
        out["hsts"] = {"max_age": sts, "include_subdomains": as_bool(g(cfg, "stsIncludeSubdomains")),
                       "preload": as_bool(g(cfg, "stsPreload"))}
        if as_bool(g(cfg, "forceSTSHeader")):
            NOTES.add(where, "forceSTSHeader: rproxy sends HSTS only on HTTPS")
    if as_bool(g(cfg, "frameDeny")):
        out["frame_deny"] = True
    if as_bool(g(cfg, "contentTypeNosniff")):
        out["content_type_nosniff"] = True
    if g(cfg, "referrerPolicy"):
        out["referrer_policy"] = str(g(cfg, "referrerPolicy"))
    if g(cfg, "contentSecurityPolicy"):
        out["csp"] = str(g(cfg, "contentSecurityPolicy"))
    origins = as_list(g(cfg, "accessControlAllowOriginList"))
    if origins:
        cors = {"allow_origins": origins}
        if g(cfg, "accessControlAllowMethods"):
            cors["allow_methods"] = as_list(g(cfg, "accessControlAllowMethods"))
        if g(cfg, "accessControlAllowHeaders"):
            cors["allow_headers"] = as_list(g(cfg, "accessControlAllowHeaders"))
        if as_bool(g(cfg, "accessControlAllowCredentials")):
            cors["allow_credentials"] = True
        if as_int(g(cfg, "accessControlMaxAge")):
            cors["max_age"] = as_int(g(cfg, "accessControlMaxAge"))
        out["cors"] = cors
    known = {"customrequestheaders", "customresponseheaders", "customframeoptionsvalue", "browserxssfilter",
             "permissionspolicy", "stsseconds", "stsincludesubdomains", "stspreload", "forcestsheader", "framedeny",
             "contenttypenosniff", "referrerpolicy", "contentsecuritypolicy", "accesscontrolalloworiginlist",
             "accesscontrolallowmethods", "accesscontrolallowheaders", "accesscontrolallowcredentials",
             "accesscontrolmaxage", "addvaryheader"}
    for k in cfg:
        if k.lower() not in known:
            NOTES.add(where, f"headers.{k} is not converted")
    return {"headers": out}


def convert_circuit_breaker(cfg, where):
    expr = str(g(cfg, "expression") or "")
    m = re.search(r"(NetworkErrorRatio\(\)|ResponseCodeRatio\([^)]*\))\s*>=?\s*([0-9.]+)", expr)
    if not m:
        NOTES.add(where, f"circuitBreaker expression {expr!r} cannot be converted (only NetworkErrorRatio / ResponseCodeRatio); left out")
        return None
    if re.search(r"&&|\|\||LatencyAtQuantileMS", expr):
        NOTES.add(where, f"circuitBreaker expression {expr!r}: only {m.group(0)!r} is used")
    if m.group(1).startswith("ResponseCodeRatio"):
        NOTES.add(where, "circuitBreaker ResponseCodeRatio: rproxy counts 5xx and connection failures as failures")
    percent = min(100, max(1, math.ceil(float(m.group(2)) * 100)))
    return {"circuit_breaker": {"failure_percent": percent, "window": "10s",
                                "recovery": duration(g(cfg, "fallbackDuration"), where, "10s")}}


def convert_crowdsec(cfg, where, state):
    if not as_bool(g(cfg, "enabled"), default=True):
        return None
    scheme = g(cfg, "crowdsecLapiScheme") or "http"
    host = g(cfg, "crowdsecLapiHost") or "crowdsec:8080"
    key_file = g(cfg, "crowdsecLapiKeyFile")
    if not key_file:
        key_file = "/etc/rproxy/crowdsec.key"
        if g(cfg, "crowdsecLapiKey"):
            NOTES.add(where, f"the CrowdSec bouncer key is not copied; write it to {key_file} (owner root, group rproxy, mode 640)")
    appsec = as_bool(g(cfg, "crowdsecAppsecEnabled"))
    glob = {"lapi_url": f"{scheme}://{host}", "api_key_file": key_file}
    if appsec:
        glob["appsec_url"] = f"http://{g(cfg, 'crowdsecAppsecHost') or 'crowdsec:7422'}"
    interval = as_int(g(cfg, "updateIntervalSeconds"))
    if interval:
        glob["update_interval"] = f"{interval}s"
    if state.get("crowdsec") and state["crowdsec"] != glob:
        NOTES.add(where, "several CrowdSec bouncer settings; rproxy has one (global.crowdsec), the first is used")
    else:
        state["crowdsec"] = glob
    for ip in as_list(g(cfg, "forwardedHeadersTrustedIPs")):
        state.setdefault("trusted_proxies", []).append(ip)
    if str(g(cfg, "crowdsecMode") or "").lower() in ("alone", "appsec"):
        NOTES.add(where, f"crowdsecMode {g(cfg, 'crowdsecMode')}: rproxy always reads decisions from the LAPI stream")
    mw = {"appsec": appsec}
    if appsec and as_bool(g(cfg, "crowdsecAppsecUnreachableBlock"), default=True):
        mw["on_error"] = "block"
    return {"crowdsec": mw}


def convert_middleware(name, spec, where, ctx):
    """One Traefik middleware -> (rproxy middleware or None, [names of a chain])."""
    if not isinstance(spec, dict) or len(spec) != 1:
        NOTES.add(where, "not one middleware type; left out")
        return None, None
    kind, cfg = next(iter(spec.items()))
    cfg = cfg or {}
    k = kind.lower()
    if k == "chain":
        return None, [strip_provider(m) for m in as_list(g(cfg, "middlewares"))]
    if k == "redirectscheme":
        out = {"scheme": g(cfg, "scheme") or "https", "permanent": as_bool(g(cfg, "permanent"))}
        port = as_int(g(cfg, "port"))
        if port and not ((out["scheme"] == "https" and port == 443) or (out["scheme"] == "http" and port == 80)):
            out["port"] = port
        return {"redirect_scheme": out}, None
    if k == "redirectregex":
        return {"redirect_regex": {"regex": g(cfg, "regex"), "replacement": g(cfg, "replacement"),
                                   "permanent": as_bool(g(cfg, "permanent"))}}, None
    if k == "stripprefix":
        if as_bool(g(cfg, "forceSlash")):
            NOTES.add(where, "stripPrefix.forceSlash is not converted")
        return {"strip_prefix": {"prefixes": as_list(g(cfg, "prefixes"))}}, None
    if k == "addprefix":
        return {"add_prefix": {"prefix": g(cfg, "prefix")}}, None
    if k == "replacepath":
        return {"replace_path": {"path": g(cfg, "path")}}, None
    if k == "replacepathregex":
        return {"replace_path_regex": {"regex": g(cfg, "regex"), "replacement": g(cfg, "replacement")}}, None
    if k == "headers":
        return convert_headers(cfg, where), None
    if k == "ratelimit":
        average = as_int(g(cfg, "average"), 0)
        if average <= 0:
            NOTES.add(where, "rateLimit.average 0 means no limit; left out")
            return None, None
        out = {"average": average, "period": duration(g(cfg, "period"), where, "1s")}
        burst = as_int(g(cfg, "burst"))
        if burst:
            out["burst"] = burst
        source = g(cfg, "sourceCriterion") or {}
        if g(source, "requestHeaderName"):
            out["source"] = f"header:{g(source, 'requestHeaderName')}"
        elif as_bool(g(source, "requestHost")):
            NOTES.add(where, "rateLimit by request host is not converted; limited per client IP")
        if g(source, "ipStrategy"):
            NOTES.add(where, "ipStrategy is not converted; rproxy uses global.trusted_proxies for the client IP")
        return {"rate_limit": out}, None
    if k == "inflightreq":
        if g(cfg, "sourceCriterion"):
            NOTES.add(where, "inFlightReq.sourceCriterion is not converted; counted per client IP")
        return {"in_flight": {"amount": as_int(g(cfg, "amount"), 1)}}, None
    if k in ("ipallowlist", "ipwhitelist"):
        if g(cfg, "ipStrategy"):
            NOTES.add(where, "ipStrategy is not converted; rproxy uses global.trusted_proxies for the client IP")
        if g(cfg, "rejectStatusCode"):
            NOTES.add(where, "rejectStatusCode is not converted (rproxy answers 403)")
        return {"ip_allow": {"source_range": as_list(g(cfg, "sourceRange"))}}, None
    if k == "basicauth":
        users_file = g(cfg, "usersFile")
        if not users_file:
            users_file = f"/etc/rproxy/auth/{name}.htpasswd"
            if g(cfg, "users"):
                NOTES.add(where, f"basicAuth.users are not copied; put them in {users_file} (htpasswd format)")
        out = {"users_file": users_file}
        if g(cfg, "realm"):
            out["realm"] = g(cfg, "realm")
        # Traefik passes Authorization on unless removeHeader; rproxy removes it unless keep_authorization
        if not as_bool(g(cfg, "removeHeader")):
            out["keep_authorization"] = True
        if g(cfg, "headerField"):
            out["user_header"] = g(cfg, "headerField")
        return {"basic_auth": out}, None
    if k == "forwardauth":
        out = {"address": g(cfg, "address")}
        if g(cfg, "authResponseHeaders"):
            out["response_headers"] = as_list(g(cfg, "authResponseHeaders"))
        if as_bool(g(cfg, "trustForwardHeader")):
            out["trust_forward_header"] = True
        if g(cfg, "authRequestHeaders"):
            out["request_headers"] = as_list(g(cfg, "authRequestHeaders"))
        for opt in ("tls", "authResponseHeadersRegex", "addAuthCookiesToResponse"):
            if g(cfg, opt) is not None:
                NOTES.add(where, f"forwardAuth.{opt} is not converted")
        return {"forward_auth": out}, None
    if k == "compress":
        out = {}
        if g(cfg, "encodings"):
            out["encodings"] = as_list(g(cfg, "encodings"))
        if as_int(g(cfg, "minResponseBodyBytes")):
            out["min_size"] = as_int(g(cfg, "minResponseBodyBytes"))
        for opt in ("excludedContentTypes", "includedContentTypes", "defaultEncoding"):
            if g(cfg, opt) is not None:
                NOTES.add(where, f"compress.{opt} is not converted")
        return {"compress": out}, None
    if k == "retry":
        out = {"attempts": as_int(g(cfg, "attempts"), 1)}
        if g(cfg, "initialInterval"):
            out["initial_interval"] = duration(g(cfg, "initialInterval"), where)
        return {"retry": out}, None
    if k == "circuitbreaker":
        return convert_circuit_breaker(cfg, where), None
    if k == "errors":
        service = strip_provider(g(cfg, "service") or "")
        ctx["needs_services"].add(service)
        return {"errors": {"status": [str(s) for s in as_list(g(cfg, "status"))], "service": service,
                           "path": g(cfg, "query") or "/"}}, None
    if k == "buffering":
        limit = as_int(g(cfg, "maxRequestBodyBytes"))
        if not limit:
            NOTES.add(where, "buffering without maxRequestBodyBytes is not converted")
            return None, None
        for opt in ("maxResponseBodyBytes", "memRequestBodyBytes", "memResponseBodyBytes", "retryExpression"):
            if g(cfg, opt) is not None:
                NOTES.add(where, f"buffering.{opt} is not converted")
        return {"buffering": {"max_request_body": limit}}, None
    if k == "plugin":
        for plugin, pcfg in (cfg or {}).items():
            if "crowdsec" in plugin.lower() or "bouncer" in plugin.lower():
                return convert_crowdsec(pcfg or {}, where, ctx["global"]), None
            NOTES.add(where, f"plugin {plugin} has no rproxy equivalent; left out")
        return None, None
    NOTES.add(where, f"middleware type {kind} has no rproxy equivalent; left out")
    return None, None


# ---------------------------------------------------------------- the conversion


class Rule:
    def __init__(self, ep_name, protocol, addr, port):
        self.ep = ep_name
        self.protocol = protocol
        self.addr = addr
        self.port = port
        self.http_routes = []  # (router name, converted route, tls router?)
        self.services = {}
        self.middlewares = {}
        self.tcp_routes = []
        self.udp_service = None
        self.certificates = []
        self.tls_options = None
        self.client_auth = None
        self.alpn = None
        self.upstream = {}
        self.http3 = False
        self.redirect = None
        self.default_middlewares = []
        self.default_tls = None


def parse_address(address, where):
    m = re.fullmatch(r"(.*):(\d+)(?:/(tcp|udp))?", str(address or "").strip())
    if not m:
        raise InputError(f"{where}: address {address!r} not understood")
    host = m.group(1).strip("[]")
    return host, int(m.group(2)), m.group(3) or "tcp"


class Converter:
    def __init__(self, static, dynamic, listen_addr, certbot_live):
        self.static = static or {}
        self.dynamic = dynamic or {}
        self.listen_addr = listen_addr
        self.certbot_live = certbot_live.rstrip("/")
        self.rules = {}
        self.global_state = {}
        self.http = g(self.dynamic, "http") or {}
        self.cert_requests = []
        self.lineage_names = {}

    def entry_points(self):
        eps = g(self.static, "entryPoints") or {}
        if not eps:
            NOTES.add("static", "no entryPoints; using web (:80) and websecure (:443)")
            eps = {"web": {"address": ":80"}, "websecure": {"address": ":443"}}
        for name, ep in eps.items():
            host, port, proto = parse_address(g(ep, "address"), f"entryPoints.{name}")
            rule = Rule(name, proto, host or self.listen_addr, port)
            http = g(ep, "http") or {}
            redir = g(http, "redirections", "entryPoint")
            if redir:
                rule.redirect = redir
            rule.default_middlewares = [strip_provider(m) for m in as_list(g(http, "middlewares"))]
            if g(http, "tls") is not None:
                rule.default_tls = g(http, "tls") or {}
            if g(ep, "http3") is not None:
                rule.http3 = True
            for ip in as_list(g(ep, "forwardedHeaders", "trustedIPs")):
                self.global_state.setdefault("trusted_proxies", []).append(ip)
            if as_bool(g(ep, "forwardedHeaders", "insecure")):
                NOTES.add(f"entryPoints.{name}", "forwardedHeaders.insecure: list the proxies in global.trusted_proxies instead")
            if g(ep, "proxyProtocol") is not None:
                NOTES.add(f"entryPoints.{name}", "proxyProtocol (receiving PROXY headers) is not supported by rproxy")
            self.rules[name] = rule

    def eps_for(self, router, protocol):
        names = as_list(g(router, "entryPoints"))
        if not names:
            names = [n for n, r in self.rules.items() if r.protocol == protocol]
        return [self.rules[n] for n in names if n in self.rules]

    # ------------------------------------------------------------ services

    def http_service(self, name, where, seen=None):
        svc = g(self.http, "services", name)
        if svc is None:
            NOTES.add(where, f"service {name} is not defined")
            return None
        seen = (seen or set()) | {name}
        lb = g(svc, "loadBalancer")
        if lb is not None:
            out = {"servers": []}
            for s in as_list(g(lb, "servers")):
                server = {"url": g(s, "url")}
                if as_int(g(s, "weight")) not in (None, 1):
                    server["weight"] = as_int(g(s, "weight"))
                out["servers"].append(server)
            if g(lb, "passHostHeader") is not None and not as_bool(g(lb, "passHostHeader")):
                out["pass_host_header"] = False
            hc = g(lb, "healthCheck")
            if hc:
                check = {"path": g(hc, "path") or "/"}
                if g(hc, "interval"):
                    check["interval"] = duration(g(hc, "interval"), where)
                if g(hc, "timeout"):
                    check["timeout"] = duration(g(hc, "timeout"), where)
                for opt in ("scheme", "port", "hostname", "headers", "status", "method", "mode"):
                    if g(hc, opt) is not None:
                        NOTES.add(where, f"healthCheck.{opt} is not converted")
                out["health_check"] = check
            sticky = g(lb, "sticky", "cookie")
            if sticky is not None:
                out["sticky"] = {"cookie": (g(sticky, "name") if isinstance(sticky, dict) else None) or f"rproxy_{name}"}
            transport = g(lb, "serversTransport")
            if transport:
                self.servers_transport(strip_provider(transport), where)
            if g(lb, "responseForwarding") is not None:
                NOTES.add(where, "responseForwarding is not converted")
            return out
        weighted = g(svc, "weighted")
        if weighted is not None:
            NOTES.add(where, f"weighted service {name}: flattened into one service (weights multiplied)")
            out = {"servers": []}
            for part in as_list(g(weighted, "services")):
                sub = strip_provider(g(part, "name"))
                if sub in seen:
                    continue
                inner = self.http_service(sub, where, seen)
                w = as_int(g(part, "weight"), 1)
                for s in (inner or {}).get("servers", []):
                    out["servers"].append({"url": s["url"], "weight": w * s.get("weight", 1)})
            return out if out["servers"] else None
        for kind in ("mirroring", "failover"):
            other = g(svc, kind)
            if other is not None:
                main = strip_provider(g(other, "service"))
                NOTES.add(where, f"{kind} service {name}: only its main service {main} is used")
                return self.http_service(main, where, seen) if main not in seen else None
        NOTES.add(where, f"service {name}: type not converted")
        return None

    def servers_transport(self, name, where):
        st = g(self.http, "serversTransports", name) or {}
        self.apply_transport(st, where)

    def apply_transport(self, st, where):
        up = self.global_state.setdefault("upstream", {})
        if as_bool(g(st, "insecureSkipVerify")):
            up["insecure_skip_verify"] = True
            NOTES.add(where, "insecureSkipVerify: applies to every https:// backend of the rule in rproxy")
        cas = as_list(g(st, "rootCAs"))
        if cas:
            up["ca_file"] = cas[0]
            if len(cas) > 1:
                NOTES.add(where, "several rootCAs: only the first is used (concatenate them into one file)")
        if g(st, "serverName"):
            up["server_name"] = g(st, "serverName")

    # ------------------------------------------------------------ middlewares

    def middleware_chain(self, names, where, rule, ctx, depth=0):
        out = []
        for name in names:
            spec = g(self.http, "middlewares", name)
            if spec is None:
                NOTES.add(where, f"middleware {name} is not defined (or not from the file provider); left out")
                continue
            if name in rule.middlewares:
                out.append(name)
                continue
            converted, chain = convert_middleware(name, spec, f"middleware {name}", ctx)
            if chain is not None:
                if depth < 5:
                    out += self.middleware_chain(chain, where, rule, ctx, depth + 1)
                continue
            if converted is None:
                continue
            rule.middlewares[name] = converted
            out.append(name)
        return out

    # ------------------------------------------------------------ routers

    def http_routers(self):
        routers = g(self.http, "routers") or {}
        for full_name, r in routers.items():
            name = strip_provider(full_name)
            where = f"router {name}"
            rule_text = g(r, "rule")
            if not rule_text:
                NOTES.add(where, "no rule; left out")
                continue
            match = translate_http_rule(rule_text, where)
            if match is None:
                continue
            for rule in self.eps_for(r, "tcp"):
                if rule.redirect is not None:
                    NOTES.add(where, f"on entry point {rule.ep}, which redirects everything; left out there")
                    continue
                tls = g(r, "tls")
                if tls is None:
                    tls = rule.default_tls
                if isinstance(tls, str):
                    tls = {} if as_bool(tls) else None
                ctx = {"global": self.global_state, "needs_services": set()}
                mws = self.middleware_chain(rule.default_middlewares + [strip_provider(m) for m in as_list(g(r, "middlewares"))],
                                            where, rule, ctx)
                route = {"name": name, "match": match}
                if as_int(g(r, "priority")):
                    route["priority"] = as_int(g(r, "priority"))
                svc = strip_provider(g(r, "service") or "")
                answered = any(next(iter(rule.middlewares[m])) in ("redirect_scheme", "redirect_regex", "respond") for m in mws)
                if svc in INTERNAL_SERVICES or provider_of(g(r, "service") or "") == "internal":
                    if not answered:
                        NOTES.add(where, f"service {g(r, 'service')} is Traefik's own; router left out")
                        continue
                elif svc:
                    converted = self.http_service(svc, where)
                    if converted is None:
                        continue
                    rule.services[svc] = converted
                    route["service"] = svc
                elif not answered:
                    NOTES.add(where, "no service; left out")
                    continue
                for extra in ctx["needs_services"]:
                    converted = self.http_service(extra, where)
                    if converted is not None:
                        rule.services[extra] = converted
                if mws:
                    route["middlewares"] = mws
                if tls is not None:
                    self.router_tls(rule, tls, rule_text, where)
                rule.http_routes.append((name, route, tls is not None))

    def router_tls(self, rule, tls, rule_text, where):
        resolver = g(tls, "certResolver")
        domains = []
        for d in as_list(g(tls, "domains")):
            domains += [g(d, "main")] + as_list(g(d, "sans"))
        explicit = [d for d in domains if d]
        if resolver:
            self.cert_requests.append((rule, explicit or host_names(rule_text), bool(explicit), resolver, where))
        options = strip_provider(g(tls, "options") or "default")
        self.apply_tls_options(rule, options, where)

    def assign_certificates(self):
        """certResolver routers -> certbot's files. Like Traefik, a certificate that already
        covers a router's names is reused; names given in tls.domains come first."""
        lineages = []  # (main, names)
        for rule, names, explicit, resolver, where in sorted(self.cert_requests, key=lambda r: not r[2]):
            if not names:
                continue
            found = next((main for main, have in lineages if set(names) <= have), None)
            if found is None:
                found = names[0].lstrip("*.")
                lineages.append((found, set(names)))
                self.lineage_names[found] = list(dict.fromkeys(names))
            cert = {"cert_file": f"{self.certbot_live}/{found}/fullchain.pem", "key_file": f"{self.certbot_live}/{found}/privkey.pem"}
            if cert not in rule.certificates:
                rule.certificates.append(cert)
        for rule, names, explicit, resolver, where in self.cert_requests:
            if not names and not rule.certificates:
                NOTES.add(where, f"certResolver {resolver}: no domain to name the certificate by; add it by hand")
        for main, names in self.lineage_names.items():
            NOTES.add("certificates", f"rproxy does not run ACME: get {', '.join(names)} with certbot (or cert-manager) "
                      f"into {self.certbot_live}/{main}/; rproxy re-reads renewed files by itself")

    def apply_tls_options(self, rule, name, where):
        opts = g(self.dynamic, "tls", "options", name)
        if opts is None:
            return
        converted = {}
        version = g(opts, "minVersion")
        if version:
            if version in TLS_VERSIONS:
                converted["min_version"] = TLS_VERSIONS[version]
            else:
                NOTES.add(f"tls.options.{name}", f"minVersion {version}: rproxy supports TLS 1.2 and 1.3 only")
        suites = []
        for s in as_list(g(opts, "cipherSuites")):
            if s in CIPHER_SUITES:
                suites.append(CIPHER_SUITES[s])
            else:
                NOTES.add(f"tls.options.{name}", f"cipher suite {s} is not available in rproxy; left out")
        if suites:
            converted["cipher_suites"] = suites
        if g(opts, "maxVersion") or g(opts, "curvePreferences") or as_bool(g(opts, "sniStrict")):
            NOTES.add(f"tls.options.{name}", "maxVersion / curvePreferences / sniStrict are not converted")
        if converted:
            if rule.tls_options not in (None, converted):
                NOTES.add(where, f"entry point {rule.ep}: routers use different TLS options; rproxy has one set per rule")
            else:
                rule.tls_options = converted
        alpn = as_list(g(opts, "alpnProtocols"))
        if alpn:
            rule.alpn = alpn
        ca = g(opts, "clientAuth")
        if ca:
            mode = CLIENT_AUTH.get(g(ca, "clientAuthType") or "NoClientCert", "none")
            files = as_list(g(ca, "caFiles"))
            if mode != "none":
                rule.client_auth = {"mode": mode}
                if files:
                    rule.client_auth["ca_file"] = files[0]
                if len(files) > 1:
                    NOTES.add(f"tls.options.{name}", "several clientAuth.caFiles: concatenate them into one file")

    def tcp_routers(self):
        tcp = g(self.dynamic, "tcp") or {}
        for full_name, r in (g(tcp, "routers") or {}).items():
            name = strip_provider(full_name)
            where = f"tcp router {name}"
            text = str(g(r, "rule") or "")
            names = []
            others = []
            for m in CALL.finditer(text):
                if m.group(1) == "HostSNI":
                    names += call_args(m.group(2))
                elif m.group(1) == "ClientIP":
                    others.append(("ClientIP", call_args(m.group(2))))
                else:
                    NOTES.add(where, f"{m.group(1)} is not converted (rproxy L4 routes by SNI only)")
            if "&&" in text and names:
                NOTES.add(where, "combined rule: only its HostSNI part is used")
            svc_name = strip_provider(g(r, "service") or "")
            svc = g(tcp, "services", svc_name, "loadBalancer")
            servers = as_list(g(svc, "servers"))
            if not servers:
                NOTES.add(where, f"service {svc_name} has no servers; left out")
                continue
            if len(servers) > 1:
                NOTES.add(where, f"service {svc_name}: rproxy L4 forwards to one backend; the first is used")
            address = g(servers[0], "address")
            try:
                host, port, _ = parse_address(address, where)
            except InputError:
                NOTES.add(where, f"backend address {address!r} not understood; left out")
                continue
            proxy = as_int(g(svc, "proxyProtocol", "version"))
            tls = g(r, "tls")
            if isinstance(tls, str):
                tls = {} if as_bool(tls) else None
            for rule in self.eps_for(r, "tcp"):
                if tls is not None and not as_bool(g(tls, "passthrough")):
                    self.router_tls(rule, tls, "Host(" + quote([n for n in names if n != "*"]) + ")", where)
                rule.tcp_routes.append({"name": name, "names": names or ["*"], "host": host, "port": port,
                                        "proxy": proxy, "tls": tls, "client_ip": others, "rule_text": text})
        udp = g(self.dynamic, "udp") or {}
        for full_name, r in (g(udp, "routers") or {}).items():
            where = f"udp router {strip_provider(full_name)}"
            svc_name = strip_provider(g(r, "service") or "")
            servers = as_list(g(udp, "services", svc_name, "loadBalancer", "servers"))
            if not servers:
                NOTES.add(where, f"service {svc_name} has no servers; left out")
                continue
            if len(servers) > 1:
                NOTES.add(where, f"service {svc_name}: rproxy forwards to one backend; the first is used")
            host, port, _ = parse_address(g(servers[0], "address"), where)
            for rule in self.eps_for(r, "udp"):
                if rule.udp_service:
                    NOTES.add(where, f"entry point {rule.ep} already has a UDP router; left out")
                    continue
                rule.udp_service = (host, port)

    # ------------------------------------------------------------ output

    def base(self, rule):
        return {"protocol": rule.protocol, "listen_addr": rule.addr, "listen_port": rule.port}

    def tls_spec(self, rule, mode, where):
        tls = {"mode": mode}
        if mode == "terminate":
            certs = list(rule.certificates)
            for c in as_list(g(self.dynamic, "tls", "certificates")):
                cert = {"cert_file": g(c, "certFile"), "key_file": g(c, "keyFile")}
                if cert["cert_file"] and cert not in certs:
                    certs.append(cert)
            if not certs:
                certs = [{"cert_file": f"/etc/rproxy/tls/{rule.ep}.pem", "key_file": f"/etc/rproxy/tls/{rule.ep}.key"}]
                NOTES.add(where, f"no certificate found; put one at {certs[0]['cert_file']}")
            tls["certificates"] = certs
            if rule.tls_options:
                tls["options"] = rule.tls_options
            if rule.client_auth:
                tls["client_auth"] = rule.client_auth
            if rule.alpn:
                tls["alpn"] = rule.alpn
        return tls

    def output_rules(self):
        out = []
        for rule in sorted(self.rules.values(), key=lambda r: (r.port, r.protocol, r.addr)):
            where = f"entry point {rule.ep}"
            if rule.protocol == "udp":
                if rule.udp_service:
                    host, port = rule.udp_service
                    out.append({**self.base(rule), "remote_addr": host, "remote_port": port})
                continue
            if rule.redirect is not None:
                out.append(self.redirect_rule(rule))
                if rule.tcp_routes:
                    NOTES.add(where, "TCP routers on an entry point that redirects are left out")
                continue
            if rule.http_routes:
                if rule.tcp_routes:
                    NOTES.add(where, "TCP routers next to HTTP routers on one port cannot be combined in rproxy; TCP routers left out: "
                              + ", ".join(t["name"] for t in rule.tcp_routes))
                out.append(self.http_rule(rule, where))
            elif rule.tcp_routes:
                converted = self.tcp_rule(rule, where)
                if converted:
                    out.append(converted)
        return out

    def redirect_rule(self, rule):
        redir = rule.redirect
        target = self.rules.get(str(g(redir, "to") or ""))
        scheme = g(redir, "scheme") or "https"
        mw = {"scheme": scheme, "permanent": as_bool(g(redir, "permanent"), default=True)}
        if target is None and str(g(redir, "to") or "").isdigit():
            port = int(g(redir, "to"))
        else:
            port = target.port if target else 443
        if port != (443 if scheme == "https" else 80):
            mw["port"] = port
        http = {
            "routes": [{"name": "redirect", "match": "PathPrefix(`/`)", "priority": 1000000, "middlewares": ["redirect"]}],
            "middlewares": {"redirect": {"redirect_scheme": mw}},
        }
        return {**self.base(rule), "http": http}

    def http_rule(self, rule, where):
        tls_routes = [r for r in rule.http_routes if r[2]]
        plain = [r for r in rule.http_routes if not r[2]]
        routes = rule.http_routes
        mode = None
        if tls_routes:
            mode = "terminate"
            if plain:
                NOTES.add(where, "routers without TLS on a TLS entry point are left out: " + ", ".join(r[0] for r in plain))
            routes = tls_routes
        http = {}
        if rule.http3:
            http["http3"] = True
        names = set()
        http["routes"] = []
        for name, route, _ in routes:
            if name in names:
                continue
            names.add(name)
            http["routes"].append(route)
        used_services = {r.get("service") for _, r, _ in routes}
        used_mws = {m for _, r, _ in routes for m in r.get("middlewares", [])}
        for m in used_mws:
            spec = rule.middlewares[m]
            if "errors" in spec:
                used_services.add(spec["errors"]["service"])
        http["services"] = {k: v for k, v in rule.services.items() if k in used_services}
        http["middlewares"] = {k: v for k, v in rule.middlewares.items() if k in used_mws}
        if not http["services"]:
            del http["services"]
        if not http["middlewares"]:
            del http["middlewares"]
        result = self.base(rule)
        upstream = self.global_state.get("upstream")
        uses_https = any(s["url"].startswith("https://") for svc in http.get("services", {}).values() for s in svc["servers"])
        if mode:
            tls = self.tls_spec(rule, mode, where)
            if upstream and uses_https:
                tls["upstream"] = dict(upstream)
            result["tls"] = tls
        elif upstream and uses_https:
            NOTES.add(where, "serversTransport settings (insecureSkipVerify, rootCAs) apply in rproxy only to rules that "
                      "terminate TLS; https:// backends of this plain-HTTP rule are verified against the system roots")
        result["http"] = http
        return result

    def tcp_rule(self, rule, where):
        routes = rule.tcp_routes
        catch_all = [t for t in routes if "*" in t["names"]]
        named = [t for t in routes if "*" not in t["names"]]
        passthrough = [t for t in routes if isinstance(t["tls"], dict) and as_bool(g(t["tls"], "passthrough"))]
        terminate = [t for t in routes if t["tls"] is not None and t not in passthrough]
        if passthrough and terminate:
            NOTES.add(where, "TLS passthrough and termination on one port cannot be combined; terminating routers left out: "
                      + ", ".join(t["name"] for t in terminate))
            routes = [t for t in routes if t not in terminate]
            terminate = []
        proxies = {t["proxy"] for t in routes}
        if len(proxies) > 1:
            NOTES.add(where, "routers use different PROXY protocol versions; rproxy has one per rule (the first is used)")
        ips = [ip for t in routes for kind, args in t["client_ip"] for ip in args]
        result = self.base(rule)
        default = catch_all[0] if catch_all else routes[0]
        result["remote_addr"] = default["host"]
        result["remote_port"] = default["port"]
        proxy = routes[0]["proxy"]
        if proxy in (1, 2):
            result["source_ip"] = f"proxy_v{proxy}"
        if ips:
            result["allow_from"] = ips
            NOTES.add(where, "ClientIP of TCP routers applies to the whole rule (allow_from)")
        if not named and not terminate and not passthrough:
            if len(catch_all) > 1:
                NOTES.add(where, "several HostSNI(`*`) routers; the first is used")
            return result
        mode = "terminate" if terminate else "sni"
        if mode == "terminate":
            tls = self.tls_spec(rule, mode, where)
        else:
            tls = {"mode": "sni"}
        tls["routes"] = [{"server_name": n.lower(), "remote_addr": t["host"], "remote_port": t["port"]}
                         for t in named for n in t["names"]]
        if not catch_all:
            tls["unmatched"] = "reject"
        result["tls"] = tls
        return result

    def global_spec(self):
        out = {}
        proxies = []
        for ip in self.global_state.get("trusted_proxies", []):
            if ip not in proxies:
                proxies.append(ip)
        if proxies:
            out["trusted_proxies"] = proxies
        access = g(self.static, "accessLog")
        if access is not None:
            path = g(access, "filePath")
            if path:
                out["access_log"] = path
                NOTES.add("accessLog", "rproxy writes JSON Lines (event http.access); Traefik's format and filters are not converted")
            else:
                NOTES.add("accessLog", "Traefik logs to stdout; rproxy writes http.access lines to its own log unless global.access_log is set")
        if self.global_state.get("crowdsec"):
            out["crowdsec"] = self.global_state["crowdsec"]
        return out

    def convert(self):
        self.entry_points()
        st = g(self.static, "serversTransport")
        if st:
            self.apply_transport(st, "serversTransport")
        self.http_routers()
        self.tcp_routers()
        self.assign_certificates()
        for name in g(self.static, "certificatesResolvers") or {}:
            NOTES.add("certificatesResolvers", f"{name}: rproxy does not run ACME; use certbot / cert-manager and point cert_file / key_file at the files")
        if g(self.static, "api") is not None:
            NOTES.add("api", "Traefik's dashboard has no equivalent; use the rproxy UI (TCP-UDP-rproxy-ui)")
        if g(self.static, "metrics") is not None:
            NOTES.add("metrics", "rproxy serves Prometheus metrics at GET /metrics of its control API")
        rules = self.output_rules()
        doc = {"version": 1}
        glob = self.global_spec()
        if glob:
            doc["global"] = glob
        doc["rules"] = rules
        return doc


# ---------------------------------------------------------------- main


def used_features(doc):
    mws, opts, http3 = set(), set(), False
    for r in doc.get("rules", []):
        http = r.get("http") or {}
        http3 |= bool(http.get("http3"))
        for spec in (http.get("middlewares") or {}).values():
            mws |= set(spec)
        for svc in (http.get("services") or {}).values():
            opts |= {k for k in ("health_check", "sticky") if k in svc}
    return mws, opts, http3


def main(argv=None):
    p = argparse.ArgumentParser(description="Convert a Traefik configuration into an rproxy settings file.")
    p.add_argument("--static", help="Traefik static configuration (traefik.yml / .toml)")
    p.add_argument("--dynamic", action="append", default=[],
                   help="dynamic configuration file or directory (repeatable; default: the file provider of --static)")
    p.add_argument("--docker", help="output of `docker inspect <containers...>` (JSON) to read labels from")
    p.add_argument("-o", "--output", help="write here instead of stdout")
    p.add_argument("--listen-addr", default="0.0.0.0", help="address for entry points written as :port (default 0.0.0.0)")
    p.add_argument("--certbot-live", default="/etc/letsencrypt/live",
                   help="where certbot keeps certificates, for routers with a certResolver")
    p.add_argument("--capabilities", help="GET /capabilities of the target rproxy (JSON file), to check what it runs")
    p.add_argument("--json", action="store_true", help="write JSON instead of YAML")
    args = p.parse_args(argv)

    try:
        static = load_file(args.static) if args.static else {}
        dynamic_paths = list(args.dynamic)
        if not dynamic_paths and args.static:
            base = os.path.dirname(os.path.abspath(args.static))
            for key in ("filename", "directory"):
                path = g(static, "providers", "file", key)
                if path:
                    dynamic_paths.append(path if os.path.isabs(path) else os.path.join(base, path))
        dynamic = {}
        for path in dynamic_paths:
            deep_merge(dynamic, load_dynamic(path))
        if args.docker:
            deep_merge(dynamic, load_docker(args.docker))
        elif g(static, "providers", "docker") is not None:
            NOTES.add("providers.docker", "Docker labels are read only with --docker (docker inspect output)")
        if not args.static and not dynamic_paths and not args.docker:
            p.error("give --static, --dynamic or --docker")
        capabilities = load_file(args.capabilities) if args.capabilities else None
    except InputError as e:
        print(f"traefik2rproxy: {e}", file=sys.stderr)
        return 2

    doc = Converter(static, dynamic, args.listen_addr, args.certbot_live).convert()

    mws, opts, http3 = used_features(doc)
    if capabilities is not None:
        features = capabilities.get("features") or {}
        known_mws, known_opts, has_http3 = set(features.get("middlewares", [])), set(features.get("services", [])), bool(features.get("http3"))
    else:
        known_mws, known_opts, has_http3 = KNOWN_MIDDLEWARES, KNOWN_SERVICE_OPTIONS, True
    missing = sorted(mws - known_mws) + sorted(opts - known_opts) + (["http3"] if http3 and not has_http3 else [])
    if missing:
        source = "GET /capabilities" if capabilities is not None else "rproxy at the time of this converter"
        NOTES.add("", f"needs features that {source} does not list yet (rules using them are refused as unsupported): "
                  + ", ".join(missing))

    header = ["Converted from the Traefik configuration by contrib/traefik2rproxy.py.",
              "Check it before use; see docs/MIGRATING-FROM-TRAEFIK.md."]
    if NOTES.items:
        header += ["", "Not converted / to check:"] + [f"- {n}" for n in NOTES.items]
    if args.json or yaml is None:
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    else:
        body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False, width=200)
        text = "".join(f"# {line}".rstrip() + "\n" for line in header) + "\n" + body
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    for n in NOTES.items:
        print(f"traefik2rproxy: {n}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
