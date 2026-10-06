#!/usr/bin/env python3
"""Writes the seed inputs of the fuzz targets to fuzz/seeds/<target>/.

The seeds are committed; run this again only to change them (python3 fuzz/gen_seeds.py
from the repository root). TLS ClientHellos come from Python's ssl module (OpenSSL),
the QUIC packets from tests/fixtures/quic (RFC 9001 / RFC 9369 appendix A), the
settings files from contrib/ and the examples in docs/en/.
"""

import pathlib
import re
import shutil
import ssl
import struct

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEEDS = ROOT / "fuzz" / "seeds"


def put(target, name, data):
    d = SEEDS / target
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data if isinstance(data, bytes) else data.encode())


def client_hello(name, alpn=None):
    """TLS records carrying a ClientHello for `name` (no SNI when None)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=name)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def handshake(records):
    """The handshake bytes of TLS records (record headers removed)."""
    out, p = b"", 0
    while p + 5 <= len(records):
        n = struct.unpack(">H", records[p + 3 : p + 5])[0]
        out += records[p + 5 : p + 5 + n]
        p += 5 + n
    return out


def dtls_hello(name, cookie=b"", cuts=()):
    """DTLS 1.2 records (one per fragment) carrying a ClientHello for `name`."""
    hs = handshake(client_hello(name))
    body = hs[4:]
    # TLS -> DTLS ClientHello: version fefd, and a cookie after the session id
    sid = body[34]
    body = b"\xfe\xfd" + body[2 : 35 + sid] + bytes([len(cookie)]) + cookie + body[35 + sid :]
    total = len(body)
    edges = [0, *cuts, total]
    records = []
    for i, (a, b) in enumerate(zip(edges, edges[1:])):
        frag = bytes([1]) + total.to_bytes(3, "big") + (0).to_bytes(2, "big")
        frag += a.to_bytes(3, "big") + (b - a).to_bytes(3, "big") + body[a:b]
        rec = bytes([22]) + b"\xfe\xfd" + b"\x00\x00" + i.to_bytes(6, "big")
        rec += len(frag).to_bytes(2, "big") + frag
        records.append(rec)
    return records


def framed(datagrams):
    """The udp_sni input format: each datagram prefixed with its 16-bit length."""
    return b"".join(len(d).to_bytes(2, "big") + d for d in datagrams)


def varint(v):
    if v < 64:
        return bytes([v])
    if v < 16384:
        return (v | 0x4000).to_bytes(2, "big")
    return (v | 0x8000_0000).to_bytes(4, "big")


def crypto(offset, data):
    return b"\x06" + varint(offset) + varint(len(data)) + data


def quic_input(v2, dcid, packets):
    """The quic_initial input format: flags, DCID, then (packet number, frames) packets."""
    out = bytes([1 if v2 else 0, len(dcid)]) + dcid
    for pn, frames in packets:
        out += bytes([pn]) + len(frames).to_bytes(2, "big") + frames
    return out


def main():
    shutil.rmtree(SEEDS, ignore_errors=True)

    # tls_client_hello
    for name, alpn in [("mail.example.com", None), ("Example.COM", ["h2", "http/1.1"]), (None, None)]:
        put("tls_client_hello", f"hello-{name or 'no-sni'}", client_hello(name, alpn))
    rec = client_hello("split.example")
    body = rec[5:]
    split = b"\x16\x03\x01" + struct.pack(">H", 40) + body[:40]
    split += b"\x16\x03\x01" + struct.pack(">H", len(body) - 40) + body[40:]
    put("tls_client_hello", "hello-split-records", split)
    put("tls_client_hello", "handshake-only", handshake(rec))

    # udp_sni: QUIC from the RFCs, DTLS built here
    for f in sorted((ROOT / "tests" / "fixtures" / "quic").glob("*.hex")):
        packet = bytes.fromhex(re.sub(r"\s", "", f.read_text()))
        put("udp_sni", f.stem, framed([packet]))
    put("udp_sni", "dtls-one-record", framed([b"".join(dtls_hello("dtls.example"))]))
    recs = dtls_hello("frag.example", cookie=b"\x01" * 20, cuts=(50, 120))
    put("udp_sni", "dtls-fragments-reordered", framed([recs[2], recs[0], recs[1]]))

    # quic_initial: CRYPTO frames carrying a ClientHello, whole or split
    hello = handshake(client_hello("quic.example", ["h3"]))
    dcid = bytes.fromhex("8394c8f03e515708")
    put("quic_initial", "v1-one-packet", quic_input(False, dcid, [(0, crypto(0, hello))]))
    put("quic_initial", "v2-one-packet", quic_input(True, dcid, [(0, crypto(0, hello))]))
    half = len(hello) // 2
    put(
        "quic_initial",
        "v1-two-packets-reversed",
        quic_input(False, dcid, [(1, crypto(half, hello[half:])), (0, b"\x01" + crypto(0, hello[:half]))]),
    )
    ack = b"\x02" + varint(0) + varint(0) + varint(0) + varint(0)
    put("quic_initial", "v1-ack-and-ping", quic_input(False, b"", [(0, ack + b"\x01" + crypto(0, hello))]))

    # proxy_header: the target reads its inputs with `arbitrary`; any bytes do
    put("proxy_header", "v4", bytes([0, 192, 0, 2, 1, 0, 198, 51, 100, 1, 0x13, 0x88, 0, 80, 0]))
    put("proxy_header", "v6-tls", bytes([1]) + bytes(range(32)) + b"\x01\xbb\x00\x50\x01" + b"h2\x00mail.example\x00TLSv1.3\x00cn\x00")

    # matcher: an expression, then (one per line) host, path, query, method, header, client IP
    request = "\nApi.Example.com:8443\n/api/v1\ndebug=1&x\nPOST\nx-requested-with: XMLHttpRequest\n10.1.2.3"
    for i, expr in enumerate(
        [
            "Host(`gitlab.example.com`) && Method(`POST`) && Path(`/users/sign_in`)",
            "Host(`gitlab.example.com`) && (PathPrefix(`/assets/`) || PathPrefix(`/uploads/`))",
            'ClientIP(`10.0.0.0/8`, "fd00::/8")',
            "Host(`*.example.com`) && !Query(`debug`, `1`)",
            "Header(`X-Requested-With`, `XMLHttpRequest`) || HeaderRegexp(`X-Id`, `^[0-9]+$`)",
            "HostRegexp(`^api\\.`) && PathRegexp(`^/api/v[0-9]+`) && QueryRegexp(`x`, `.*`)",
            "!(Method(`GET`, `HEAD`) || !Host(`**.example.com`))",
        ]
    ):
        put("matcher", f"expr-{i}", expr + request)
    # just past the limits (#180): nesting 33 deep, 257 matchers
    put("matcher", "limit-not", "!" * 33 + "Host(`a`)" + request)
    put("matcher", "limit-paren", "(" * 33 + "Host(`a`)" + ")" * 33 + request)
    put("matcher", "limit-terms", " && ".join(["Host(`a`)"] * 257) + request)
    put("matcher", "limit-deepest", " || ".join(["!" * 31 + "Path(`/`)"] * 256) + request)

    # starttls: mode byte (protocol, required, read size), then what the client sends,
    # NUL, and what the mail server sends
    for name, mode, text in [
        ("smtp", 0x04, "EHLO client\r\nMAIL FROM:<a@b>\r\nSTARTTLS\r\n"),
        ("smtp-optional", 0x00, "EHLO c\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\n"),
        ("smtp-ehlo-reply", 0x0c, "EHLO c\r\n\0" "220 mx.example ESMTP\r\n250-mx.example\r\n250-STARTTLS\r\n250 8BITMIME\r\n"),
        ("smtp-plain-replay", 0x00, "EHLO c\r\nMAIL FROM:<a@b>\r\n\0" "250-mx.example\r\n250 SIZE 1000\r\n"),
        ("smtp-injection", 0x04, "EHLO c\r\nSTARTTLS\r\nMAIL FROM:<evil@x>\r\n"),
        ("imap", 0x05, "a1 CAPABILITY\r\na2 LOGIN u p\r\na3 STARTTLS\r\n"),
        ("pop3", 0x16, "CAPA\r\nUSER x\r\nSTLS\r\n"),
        ("pop3-quit", 0x06, "QUIT\r\n"),
    ]:
        put("starttls", name, bytes([mode]) + text.encode())

    # config: 0 = YAML, 1 = JSON, then the document
    put("config", "rproxy.example.yaml", b"\x00" + (ROOT / "contrib" / "rproxy.example.yaml").read_bytes())
    # durations at and past 365 days (#180)
    put(
        "config",
        "durations.yaml",
        b"\x00version: 1\nrules:\n"
        b"  - {protocol: tcp, listen_addr: 127.0.0.1, listen_port: 80, remote_addr: a, remote_port: 1, health_check: {interval: 8760h, timeout: 525601m}}\n"
        b"  - protocol: tcp\n    listen_addr: 127.0.0.1\n    listen_port: 81\n    http:\n"
        b"      routes: [{name: a, match: \"!(Host(`a`) || !Path(`/`))\", to: \"http://b\", middlewares: [rl, cb]}]\n"
        b"      middlewares:\n        rl: {rate_limit: {average: 1, period: 18446744073709551615ms}}\n"
        b"        cb: {circuit_breaker: {failure_percent: 50, window: 5124095576030432m, recovery: 31536000s}}\n",
    )
    n = 0
    for doc in ["API.md", "DESIGN-v0.3.md", "CROWDSEC.md", "MIGRATING-FROM-TRAEFIK.md", "PROFILES.md"]:
        text = (ROOT / "docs" / "en" / doc).read_text()
        for lang, block in re.findall(r"```(yaml|json)\n(.*?)```", text, re.S):
            if "protocol" not in block and "global" not in block:
                continue
            n += 1
            put("config", f"{doc.lower().removesuffix('.md')}-{n}.{lang}", (b"\x00" if lang == "yaml" else b"\x01") + block.encode())

    # dns_response: answers DNS-01 reads (CNAME of _acme-challenge, SOA, TXT), with name compression
    def name(n):
        return b"".join(bytes([len(l)]) + l.encode() for l in n.split(".")) + b"\0"

    def rr(owner, rtype, rdata):
        return owner + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata

    def response(qname, qtype, answers, authority=b"", an=0, ns=0, rcode=0):
        head = struct.pack(">HHHHHH", 0x1234, 0x8180 | rcode, 1, an, ns, 0)
        return head + name(qname) + struct.pack(">HH", qtype, 1) + answers + authority

    q = "_acme-challenge.www.example.com"
    cname = rr(b"\xc0\x0c", 5, name("www.acme.example.net"))
    put("dns_response", "cname", response(q, 5, cname, an=1))
    target = 12 + len(name(q)) + 4 + 12  # the CNAME's target, after its record header
    txt = rr(bytes([0xC0, target]), 16, b"\x05hello\x03 me")
    put("dns_response", "cname-txt", response(q, 16, cname + txt, an=2))
    soa = rr(name("acme.example.net"), 6, b"\xc0\x0c\xc0\x0c" + bytes(20))
    put("dns_response", "nxdomain-soa", response(q, 6, b"", soa, ns=1, rcode=3))
    put("dns_response", "pointer-loop", response(q, 5, b"\xc0\x2f", an=1))


if __name__ == "__main__":
    main()
