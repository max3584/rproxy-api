# 用途別の設定例

よく使う構成の推奨設定。UI の「プロファイル」は、ここの設定をフォームに入れるだけのひな形です。
例の証明書のパスとアドレスは、環境に合わせて読み替えてください。

## 選び方

| やりたいこと | `tls.mode` | 補足 |
|---|---|---|
| 中身に触れずに流す | `passthrough`（既定） | 送信元 IP が必要なら `source_ip: proxy_v2`（転送先の対応が必要） |
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
