# 用途別の設定例

よく使う構成の推奨設定。UI の「プロファイル」は、ここの設定をフォームに入れるだけのひな形です。
例の証明書のパスとアドレスは、環境に合わせて読み替えてください。

## 証明書（多段の CA）

ルート → 中間 CA → … → サーバ証明書のような多段の CA では、サーバ証明書と一緒に中間 CA を送らないと、クライアントが検証できません。

- `cert_file`：サーバ証明書
- `chain_file`：中間 CA（サーバ証明書を発行した CA から、ルートへ向かう順に連結する。ルートは入れなくてよい）
- `key_file`：秘密鍵

mTLS も同じ考え方です。`client_auth.ca_file` にはルートだけを入れます。クライアントが中間 CA を送ってこない場合は、`client_auth.chain_file` に中間 CA を入れます。中間 CA は検証の途中経路として使うだけで、信頼の起点はルートのままです。

## 選び方

| やりたいこと | `tls.mode` | 補足 |
|---|---|---|
| 中身に触れずに流す | `passthrough`（既定） | 送信元 IP が必要なら `source_ip: proxy_v2`（転送先の対応が必要）。UDP でも使える（DNS なら dnsdist・PowerDNS Recursor・Unbound の proxy protocol の設定。データグラムごとに 16〜52 バイト大きくなるので、MTU に近い大きさのデータグラムに注意） |
| 1 つのポートで、ホスト名ごとに転送先を分ける（証明書は転送先が持つ） | `sni` | tcp のみ |
| rproxy で証明書を持ち、転送先には平文（または別の TLS）で送る | `terminate` | mTLS、ALPN、再暗号化もここ |
| メールの STARTTLS を rproxy で受ける | `terminate` + `starttls` | SMTP / IMAP / POP3 |
| DTLS を rproxy で受ける | `terminate`（udp） | TURN over DTLS、CoAP、syslog など（WebRTC のメディアは不可。下を参照） |
| 決まった範囲のポートをまとめて流す | `listen_port_end` | RTP、TURN のリレー、FTP のパッシブモード |

## HTTPS / 複数サービスを 443 で振り分ける

証明書は転送先がそれぞれ持ち、rproxy は SNI だけを見て振り分けます。

```json
{"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 443,
 "remote_addr": "10.0.0.10", "remote_port": 443,
 "tls": {"mode": "sni", "routes": [
   {"server_name": "git.example.com", "remote_addr": "10.0.0.11", "remote_port": 443},
   {"server_name": "*.apps.example.com", "remote_addr": "10.0.0.12", "remote_port": 8443}
 ]}}
```

## メール

| 用途 | ポート | 推奨 |
|---|---|---|
| MTA 間の受信（SMTP） | 25 | `passthrough` + `source_ip: proxy_v2`（Postfix の `postscreen_upstream_proxy_protocol = haproxy`）。rproxy で TLS を受ける場合は `starttls: smtp`、`starttls_required: false`（TLS を使わない MTA もあるため） |
| メール送信（Submission） | 587 | `terminate` + `starttls: smtp`（既定で必須） |
| SMTPS | 465 | `terminate` |
| IMAP | 143 | `terminate` + `starttls: imap` |
| IMAPS | 993 | `terminate`、または `passthrough` + `proxy_v2`（Dovecot の `haproxy = yes`） |
| POP3 / POP3S | 110 / 995 | `starttls: pop3` / `terminate` |

Submission（587）の例。転送先には平文で送り、PROXY v2 で送信元 IP と TLS の情報を渡します。

```json
{"protocol": "tcp", "listen_addr": "0.0.0.0", "listen_port": 587,
 "remote_addr": "10.0.0.20", "remote_port": 587, "source_ip": "proxy_v2",
 "tls": {"mode": "terminate", "certificates": [
   {"cert_file": "/etc/rproxy/certs/mail.pem", "key_file": "/etc/rproxy/certs/mail.key"}]},
 "starttls": "smtp"}
```

注意：
- rproxy は STARTTLS の前のコマンドに自分で答えます。TLS を確立したあと、クライアントの EHLO を転送先に渡し、転送先の応答から `STARTTLS` を取り除きます。
- 転送先の SMTP サーバには、TLS を済ませたクライアントが平文で届きます。認証（AUTH）を平文で許す設定にするか、`upstream.tls` で再暗号化してください。
- IMAP / POP3 では STARTTLS が必須です（TLS を使う前のログインは拒否します）。

### 転送先の設定（Postfix / Dovecot で確認済み）

`scripts/interop/mail.sh`（CI の Interop ワークフロー）で、Ubuntu 24.04 の Postfix 3.8 / Dovecot 2.3 を相手に、Submission・SMTP（`starttls_required: false`）・IMAP（STARTTLS）・IMAPS・POP3（STLS）が通ることを確かめています。rproxy からの接続を受けるリスナーは次のようにします。

```text
# Postfix: master.cf（rproxy からだけ届くアドレスで待ち受ける）
10.0.0.20:587 inet n - n - - smtpd
  -o smtpd_upstream_proxy_protocol=haproxy
  -o smtpd_tls_security_level=none
```

```text
# Dovecot: TLS は rproxy が終端するので、このリスナーは平文 + PROXY v2
haproxy_trusted_networks = 10.0.0.10        # rproxy のアドレス
service imap-login {
  inet_listener imap-rproxy {
    address = 10.0.0.20
    port = 10143
    haproxy = yes
  }
}
```

- 転送先から見える接続元は、PROXY v2 で渡したクライアントのアドレスになります（Postfix のログの `connect from`）。
- **SMTP の AUTH**: Postfix は PROXY v2 の TLS の情報を読まないので、rproxy が TLS を終端した接続も「平文」として扱います。AUTH を使うなら、rproxy からのリスナーで `-o smtpd_tls_auth_only=no` にし、Dovecot の SASL が平文の認証を受け付けるようにする必要があります（その場合、このリスナーには rproxy 以外から届かないようにする）。それを避けたいときは `upstream.tls` で Postfix まで再暗号化してください。（AUTH の組み合わせは CI では確かめていません）
- **Dovecot のログイン**: CI では 127.0.0.1 からの接続で、既定の `disable_plaintext_auth = yes` のままログインできることを確かめています（Dovecot は 127.0.0.1 を安全な接続として扱います）。ほかのアドレスからの場合は、Dovecot が PROXY v2 の TLS の情報をもとに TLS 済みとして扱うことを実機で確かめてください。

## RTSP / RTSPS

| 用途 | 設定 |
|---|---|
| RTSP の制御 | 554/tcp を `passthrough`。MediaMTX なら `source_ip: proxy_v2`（`rtspTrustedProxies` と組み合わせる） |
| RTSPS | 322/tcp を `terminate`（または `passthrough`） |
| RTP / RTCP | **TCP interleaved を推奨**（映像も 554 番の接続の中を通るので、追加の設定は要らない） |

UDP で RTP を流す場合、サーバは SETUP で指定されたクライアントのアドレスへ RTP を送ります。rproxy を挟むとサーバからはクライアントが rproxy に見えるため、再生（サーバからクライアントへの方向）は L4 の転送だけでは戻りの経路が作れません。
UDP の範囲ルールが使えるのは、MediaMTX のように RTP / RTCP のポートが決まっていて（既定 8000 / 8001）、クライアントからサーバへ送る方向のときです。

```json
{"protocol": "udp", "listen_addr": "0.0.0.0", "listen_port": 8000, "listen_port_end": 8001,
 "remote_addr": "10.0.0.30", "remote_port": 8000}
```

## WebRTC

WebRTC のメディアは DTLS-SRTP で暗号化されます。鍵の交換は、SDP に書かれた証明書のフィンガープリントでブラウザとメディアサーバの間で結びつけられています。そのため、**rproxy で DTLS を終端すると接続が成立しません。メディアは `passthrough` で流します。**

| 用途 | 設定 |
|---|---|
| シグナリング（HTTPS / WSS） | 443/tcp を `sni` または `terminate` |
| メディア（ICE、UDP） | メディアサーバの UDP ポート範囲を、同じ番号で範囲ルールにする。メディアサーバには、rproxy の公開 IP を自分のアドレスとして告知させる（LiveKit `rtc.node_ip`、mediasoup `announcedAddress`、Janus `nat_1_1_mapping`） |
| TURN（coturn） | 3478/udp と 3478/tcp を `passthrough`。5349/tcp（TURN over TLS）は `terminate` または `passthrough`、5349/udp（TURN over DTLS）は `terminate` にできる。リレー用のポート範囲（coturn の `min-port`〜`max-port`）を範囲ルールにし、coturn の `external-ip` に rproxy の公開 IP を設定する |

メディアの範囲ルールの例（LiveKit が 50000〜60000/udp を使う場合）：

```json
{"protocol": "udp", "listen_addr": "0.0.0.0", "listen_port": 50000, "listen_port_end": 60000,
 "remote_addr": "10.0.0.40", "remote_port": 50000, "udp_idle_secs": 60}
```

- 範囲は 1 ルールで最大 20000 ポートです（`RPROXY_MAX_RANGE_PORTS` で変えられる）。
- ポートごとにソケットを 1 つ開くので、rproxy は起動時に開けるファイル数の上限を、上げられるところまで引き上げます。systemd では `LimitNOFILE=` も上げてください。

## FTP（パッシブモード）

21/tcp を `passthrough`、パッシブ用の範囲（vsftpd の `pasv_min_port`〜`pasv_max_port`）を tcp の範囲ルールにします。vsftpd の `pasv_address` には rproxy の公開 IP を設定します。
