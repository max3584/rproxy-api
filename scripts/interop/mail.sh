#!/usr/bin/env bash
# 実際の Postfix / Dovecot を rproxy の STARTTLS の終端（PROXY v2 つき）の後ろに置き、
# 送信・受信が通ることを確かめる（issue #15）。GitHub の Ubuntu ランナー用（sudo を使い、パッケージを入れる）。
#
#   cargo build && scripts/interop/mail.sh
#
#   client ──TLS──▶ rproxy ──平文 + PROXY v2──▶ Postfix（10587 / 10025）/ Dovecot（10143 / 10110）
#
# ポートは root のいらない番号にしている（1587 = Submission、1025 = SMTP、1143 = IMAP、1993 = IMAPS、1110 = POP3）。
# rproxy-api を本番で動かしている機械では実行しない。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${BIN:-$ROOT/target/debug/rproxy-api}
WORK=$(mktemp -d)
API=http://127.0.0.1:18300
PASS=mailtest-password

fail() { echo "FAIL: $*" >&2; sudo tail -n 40 /var/log/mail.log 2>/dev/null >&2 || sudo journalctl -u postfix -u dovecot --no-pager -n 40 >&2; cat "$WORK/rproxy.log" >&2; exit 1; }

echo "== packages"
echo "postfix postfix/main_mailer_type select Local only" | sudo debconf-set-selections
echo "postfix postfix/mailname string mail.test" | sudo debconf-set-selections
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q postfix dovecot-imapd dovecot-pop3d openssl >/dev/null
grep -q ' mail.test$' /etc/hosts || echo '127.0.0.1 mail.test' | sudo tee -a /etc/hosts >/dev/null
id mailtest >/dev/null 2>&1 || sudo useradd -m mailtest
echo "mailtest:$PASS" | sudo chpasswd

echo "== postfix: plain listeners that expect PROXY v2 from rproxy"
sudo postconf -e myhostname=mail.test mydestination='mail.test, localhost' home_mailbox=Maildir/ \
	inet_interfaces=loopback-only inet_protocols=ipv4
for port in 10587 10025; do
	sudo postconf -M "127.0.0.1:$port/inet=127.0.0.1:$port inet n - n - - smtpd"
	sudo postconf -P "127.0.0.1:$port/inet/smtpd_upstream_proxy_protocol=haproxy" \
		"127.0.0.1:$port/inet/smtpd_tls_security_level=none"
done
sudo systemctl restart postfix

echo "== dovecot: plain listeners that expect PROXY v2 from rproxy (TLS is terminated at rproxy)"
sudo tee /etc/dovecot/conf.d/99-rproxy-interop.conf >/dev/null <<'EOF'
mail_location = maildir:~/Maildir
haproxy_trusted_networks = 127.0.0.1
ssl = no
service imap-login {
  inet_listener imap-rproxy {
    address = 127.0.0.1
    port = 10143
    haproxy = yes
  }
}
service pop3-login {
  inet_listener pop3-rproxy {
    address = 127.0.0.1
    port = 10110
    haproxy = yes
  }
}
EOF
sudo systemctl restart dovecot

echo "== test CA and the mail.test certificate"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=interop-ca \
	-keyout "$WORK/ca.key" -out "$WORK/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=mail.test \
	-keyout "$WORK/mail.key" -out "$WORK/mail.csr" 2>/dev/null
printf 'subjectAltName=DNS:mail.test\n' > "$WORK/san.ext"
openssl x509 -req -in "$WORK/mail.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" -CAcreateserial -days 2 \
	-extfile "$WORK/san.ext" -out "$WORK/mail.pem" 2>/dev/null

echo "== rproxy"
(cd "$WORK" && RPROXY_API_PORT=18300 exec "$BIN" > "$WORK/rproxy.log" 2>&1) &
RP=$!
trap 'kill $RP 2>/dev/null || true' EXIT
for _ in $(seq 50); do curl -sf "$API/healthz" >/dev/null && break; sleep 0.2; done
tls="{\"mode\":\"terminate\",\"certificates\":[{\"cert_file\":\"$WORK/mail.pem\",\"key_file\":\"$WORK/mail.key\"}]}"
rule() { # rule <listen> <backend> <starttls or null> [starttls_required]
	local extra=''
	[ -z "${4:-}" ] || extra=",\"starttls_required\":$4"
	local code
	code=$(curl -s -o "$WORK/resp" -w '%{http_code}' -X POST "$API/rules" -d "{\"protocol\":\"tcp\",\"listen_addr\":\"127.0.0.1\",\"listen_port\":$1,
		\"remote_addr\":\"127.0.0.1\",\"remote_port\":$2,\"source_ip\":\"proxy_v2\",\"tls\":$tls,\"starttls\":$3$extra}")
	[ "$code" = 201 ] || fail "rule $1: $code $(cat "$WORK/resp")"
}
rule 1587 10587 '"smtp"'          # Submission: STARTTLS required
rule 1025 10025 '"smtp"' false    # SMTP from other MTAs: STARTTLS optional
rule 1143 10143 '"imap"'          # IMAP + STARTTLS
rule 1993 10143 null              # IMAPS
rule 1110 10110 '"pop3"'          # POP3 + STLS

echo "== clients"
python3 - "$WORK/ca.pem" "$PASS" <<'EOF'
import imaplib, poplib, smtplib, ssl, sys, time, uuid
ca, password = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(cafile=ca)
mark = uuid.uuid4().hex[:12]

def message(subject):
    return f"From: sender@example.org\r\nTo: mailtest@mail.test\r\nSubject: {subject}\r\n\r\nhello through rproxy\r\n"

# Submission (1587): STARTTLS terminated by rproxy, then plain + PROXY v2 to Postfix
with smtplib.SMTP("mail.test", 1587, timeout=10) as s:
    s.ehlo("client.example.org")
    assert s.has_extn("starttls"), "STARTTLS is not offered"
    s.starttls(context=ctx)
    s.ehlo("client.example.org")
    assert not s.has_extn("starttls"), "STARTTLS offered again after TLS"
    s.sendmail("sender@example.org", ["mailtest@mail.test"], message(f"submission {mark}"))
print("submission (STARTTLS) sent")

# Submission refuses mail before STARTTLS
with smtplib.SMTP("mail.test", 1587, timeout=10) as s:
    s.ehlo("client.example.org")
    try:
        s.sendmail("sender@example.org", ["mailtest@mail.test"], message("must not arrive"))
        raise SystemExit("submission accepted mail without STARTTLS")
    except smtplib.SMTPException as e:
        print(f"submission without STARTTLS refused: {e.__class__.__name__}")

# SMTP (1025) with starttls_required: false: an MTA that does not use TLS is accepted
with smtplib.SMTP("mail.test", 1025, timeout=10) as s:
    s.ehlo("mta.example.org")
    s.sendmail("sender@example.org", ["mailtest@mail.test"], message(f"plain-mta {mark}"))
print("smtp without TLS sent")
with smtplib.SMTP("mail.test", 1025, timeout=10) as s:
    s.ehlo("mta.example.org")
    s.starttls(context=ctx)
    s.ehlo("mta.example.org")
    s.sendmail("sender@example.org", ["mailtest@mail.test"], message(f"tls-mta {mark}"))
print("smtp with STARTTLS sent")

def wait_for(check, what):
    for _ in range(60):
        if check():
            return
        time.sleep(0.5)
    raise SystemExit(f"timed out: {what}")

# IMAP (1143) with STARTTLS
def imap_subjects(conn):
    conn.select("INBOX")
    _, data = conn.search(None, "SUBJECT", mark)
    subjects = []
    for num in data[0].split():
        _, msg = conn.fetch(num, "(BODY[HEADER.FIELDS (SUBJECT)])")
        subjects.append(msg[0][1].decode().strip().removeprefix("Subject: "))
    return sorted(subjects)

expected = sorted([f"submission {mark}", f"plain-mta {mark}", f"tls-mta {mark}"])
def imap_has_all():
    with imaplib.IMAP4("mail.test", 1143, timeout=10) as m:
        m.starttls(ssl_context=ctx)
        m.login("mailtest", password)
        return imap_subjects(m) == expected
wait_for(imap_has_all, "all three mails in the mailbox")
print("imap (STARTTLS): all three mails are there")

# IMAP refuses a login before STARTTLS (rproxy requires it for IMAP)
with imaplib.IMAP4("mail.test", 1143, timeout=10) as m:
    try:
        m.login("mailtest", password)
        raise SystemExit("IMAP login accepted without STARTTLS")
    except imaplib.IMAP4.error as e:
        print(f"imap login without STARTTLS refused: {e}")

# IMAPS (1993)
with imaplib.IMAP4_SSL("mail.test", 1993, ssl_context=ctx, timeout=10) as m:
    m.login("mailtest", password)
    assert imap_subjects(m) == expected
print("imaps: ok")

# POP3 (1110) with STLS
p = poplib.POP3("mail.test", 1110, timeout=10)
p.stls(context=ctx)
p.user("mailtest")
p.pass_(password)
count, _ = p.stat()
assert count >= 3, count
p.quit()
print(f"pop3 (STLS): {count} messages")
EOF

echo "== the backend saw the client address from PROXY v2"
sudo grep -q 'connect from .*\[127.0.0.1\]' /var/log/mail.log 2>/dev/null || sudo journalctl -u postfix --no-pager | grep -q 'connect from' || fail "no connection in the Postfix log"
echo "OK"
