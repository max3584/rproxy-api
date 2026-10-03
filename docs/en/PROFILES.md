日本語: [PROFILES.md](../PROFILES.md)

# Configuration examples by use case

Recommended settings for common setups. The "profiles" in the UI are just templates that fill these settings into the form.
Replace the certificate paths and addresses in the examples to match your environment.

## Certificates (multi-tier CA)

With a multi-tier CA such as root → intermediate CA → … → server certificate, clients cannot verify the server certificate unless the intermediate CAs are sent along with it.

- `cert_file`: the server certificate
- `chain_file`: the intermediate CAs (concatenated in order from the CA that issued the server certificate toward the root; the root does not need to be included)
- `key_file`: the private key

mTLS works the same way. Put only the root in `client_auth.ca_file`. If clients do not send their intermediate CAs, put the intermediate CAs in `client_auth.chain_file`. The intermediate CAs are used only as the path for verification; the trust anchor remains the root.

## Choosing a mode

| What you want to do | `tls.mode` | Notes |
|---|---|---|
| Pass traffic through without touching its content | `passthrough` (default) | If you need the source IP, use `source_ip: proxy_v2` (the target must support it). Also usable with UDP (for DNS, the proxy protocol settings of dnsdist, PowerDNS Recursor, or Unbound. Each datagram grows by 16–52 bytes, so watch out for datagrams close to the MTU) |
| Route to different targets by hostname on a single port (the targets hold the certificates) | `sni` | tcp (TLS) and udp (DTLS, QUIC). Examples: send HTTP/3 on 443/udp to different servers by name, split TURN over DTLS on 5349/udp by name |
| On a single port, terminate some hosts at rproxy and pass others through to the target as-is | `terminate` + `passthrough: true` in `tls.routes` | Also usable with L7 (`http`) rules. Example: terminate cdn and gitlab with rproxy's certificates, pass registry and `**.tenant.example.com` through to Kubernetes (cert-manager) |
| Hold the certificate at rproxy and send plain text (or separate TLS) to the target | `terminate` | mTLS, ALPN, and re-encryption also go here |
| Accept mail STARTTLS at rproxy | `terminate` + `starttls` | SMTP / IMAP / POP3 |
| Accept DTLS at rproxy | `terminate` (udp) | TURN over DTLS, CoAP, syslog, etc. (not WebRTC media; see below) |
| Pass a fixed range of ports through together | `listen_port_end` | RTP, TURN relays, FTP passive mode |

## HTTPS / routing multiple services on 443

Each target holds its own certificate, and rproxy routes by looking only at SNI.

```json
{"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 443,
 "remote_addr": "10.0.0.10", "remote_port": 443,
 "tls": {"mode": "sni", "routes": [
   {"server_name": "git.example.com", "remote_addr": "10.0.0.11", "remote_port": 443},
   {"server_name": "*.apps.example.com", "remote_addr": "10.0.0.12", "remote_port": 8443}
 ]}}
```

## Mail

| Use | Port | Recommended |
|---|---|---|
| Receiving between MTAs (SMTP) | 25 | `passthrough` + `source_ip: proxy_v2` (Postfix `postscreen_upstream_proxy_protocol = haproxy`). If rproxy accepts TLS, use `starttls: smtp` with `starttls_required: false` (because some MTAs do not use TLS) |
| Mail submission (Submission) | 587 | `terminate` + `starttls: smtp` (required by default) |
| SMTPS | 465 | `terminate` |
| IMAP | 143 | `terminate` + `starttls: imap` |
| IMAPS | 993 | `terminate`, or `passthrough` + `proxy_v2` (Dovecot `haproxy = yes`) |
| POP3 / POP3S | 110 / 995 | `starttls: pop3` / `terminate` |

Example for Submission (587). Sends plain text to the target and passes the source IP and TLS information via PROXY v2.

```json
{"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 587,
 "remote_addr": "10.0.0.20", "remote_port": 587, "source_ip": "proxy_v2",
 "tls": {"mode": "terminate", "certificates": [
   {"cert_file": "/etc/rproxy/certs/mail.pem", "key_file": "/etc/rproxy/certs/mail.key"}]},
 "starttls": "smtp"}
```

Notes:
- rproxy answers the commands before STARTTLS itself. After TLS is established, it passes the client's EHLO to the target and removes `STARTTLS` from the target's reply.
- Clients that have completed TLS reach the target SMTP server as plain text. Either configure it to allow authentication (AUTH) over plain text, or re-encrypt with `upstream.tls`.
- For IMAP / POP3, STARTTLS is mandatory (logging in before using TLS is refused).

### Target configuration (verified with Postfix / Dovecot)

`scripts/interop/mail.sh` (the Interop workflow in CI) verifies that Submission, SMTP (`starttls_required: false`), IMAP (STARTTLS), IMAPS, and POP3 (STLS) work against Postfix 3.8 / Dovecot 2.3 on Ubuntu 24.04. Configure the listeners that receive connections from rproxy as follows.

```text
# Postfix: master.cf (listen on an address reachable only from rproxy)
10.0.0.20:587 inet n - n - - smtpd
  -o smtpd_upstream_proxy_protocol=haproxy
  -o smtpd_tls_security_level=none
```

```text
# Dovecot: rproxy terminates TLS, so this listener is plain text + PROXY v2
haproxy_trusted_networks = 10.0.0.10        # rproxy's address
service imap-login {
  inet_listener imap-rproxy {
    address = 10.0.0.20
    port = 10143
    haproxy = yes
  }
}
```

- The connection source seen by the target is the client address passed via PROXY v2 (`connect from` in the Postfix log).
- **SMTP AUTH**: Postfix does not read the TLS information in PROXY v2, so it treats connections whose TLS was terminated by rproxy as "plain text" too. To use AUTH, set `-o smtpd_tls_auth_only=no` on the listener for rproxy and make Dovecot SASL accept plain-text authentication (in that case, make sure nothing other than rproxy can reach this listener). If you want to avoid that, re-encrypt to Postfix with `upstream.tls`. (AUTH combinations are not verified in CI.)
- **Dovecot login**: CI verifies that login works over connections from 127.0.0.1 with the default `disable_plaintext_auth = yes` left as is (Dovecot treats 127.0.0.1 as a secure connection). For connections from other addresses, verify on real hardware that Dovecot treats them as TLS-protected based on the TLS information in PROXY v2.

## RTSP / RTSPS

| Use | Configuration |
|---|---|
| RTSP control | `passthrough` on 554/tcp. For MediaMTX, `source_ip: proxy_v2` (combined with `rtspTrustedProxies`) |
| RTSPS | `terminate` (or `passthrough`) on 322/tcp |
| RTP / RTCP | **TCP interleaved is recommended** (the video also goes through the port 554 connection, so no extra configuration is needed) |

When RTP flows over UDP, the server sends RTP to the client address specified in SETUP. With rproxy in between, the client looks like rproxy to the server, so for playback (the server-to-client direction) L4 forwarding alone cannot create the return path.
UDP range rules are usable when the RTP / RTCP ports are fixed, as with MediaMTX (default 8000 / 8001), and the traffic goes from client to server.

```json
{"protocol": "udp", "listen_addr": "0.0.0.0", "listen_port": 8000, "listen_port_end": 8001,
 "remote_addr": "10.0.0.30", "remote_port": 8000}
```

## WebRTC

WebRTC media is encrypted with DTLS-SRTP. The key exchange is bound between the browser and the media server by the certificate fingerprint written in the SDP. Therefore, **terminating DTLS at rproxy makes the connection fail. Pass media through with `passthrough`.**

| Use | Configuration |
|---|---|
| Signaling (HTTPS / WSS) | `sni` or `terminate` on 443/tcp |
| Media (ICE, UDP) | Make the media server's UDP port range a range rule with the same numbers. Have the media server announce rproxy's public IP as its own address (LiveKit `rtc.node_ip`, mediasoup `announcedAddress`, Janus `nat_1_1_mapping`) |
| TURN (coturn) | `passthrough` on 3478/udp and 3478/tcp. 5349/tcp (TURN over TLS) can be `terminate` or `passthrough`, and 5349/udp (TURN over DTLS) can be `terminate`. Make the relay port range (coturn `min-port` to `max-port`) a range rule, and set coturn's `external-ip` to rproxy's public IP |

Example media range rule (when LiveKit uses 50000–60000/udp):

```json
{"protocol": "udp", "listen_addr": "0.0.0.0", "listen_port": 50000, "listen_port_end": 60000,
 "remote_addr": "10.0.0.40", "remote_port": 50000, "udp_idle_secs": 60}
```

- A range can cover at most 20000 ports per rule (adjustable with `RPROXY_MAX_RANGE_PORTS`).
- One socket is opened per port, so at startup rproxy raises its open file limit as far as it can. Under systemd, also raise `LimitNOFILE=`.

## FTP (passive mode)

Use `passthrough` on 21/tcp, and make the passive range (vsftpd `pasv_min_port` to `pasv_max_port`) a tcp range rule. Set vsftpd's `pasv_address` to rproxy's public IP.
