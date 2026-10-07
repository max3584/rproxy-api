English: [UPGRADE.md](en/UPGRADE.md)

# 再起動なしの更新と自動更新（#174）

rproxy-api は、動いたまま新しいバイナリに入れ替えられる（**引き継ぎ**、handoff）。同じマイナー（X.Y）の中のパッチは、TCP・HTTP の接続を切らずに入れ替わる。コンテナでは、イメージと同じ X.Y の最新のパッチを自分で取って入れ替えられる（**自動更新**）。設計は docs/DESIGN-v0.4.md の 10.。

## 引き継ぎ（handoff）

起こし方：

- 動いているプロセスに `SIGUSR2`（`systemctl kill -s USR2 --kill-whom=main rproxy-api`）
- `POST /admin/upgrade`（`admin` のスコープ。既定では Unix ソケットからだけ：`RPROXY_API_RELOAD_UNIX_ONLY`）。`202 {"status":"started"}`、すでに動いていれば `409 upgrading`
- .deb の更新（下の「パッケージ」）

流れ：

1. 古いプロセスが引き継ぎ用の Unix ソケット（`--handoff-socket`、0600）を開き、ディスクの上の今のバイナリ（`/proc/self/exe` の指していたファイル。パッケージの更新で置き換わったもの）を同じ引数・環境で子として起動する。そのソケットにつなげるのは、起動した子（pid で確かめる）だけ。
2. 新しいプロセスが版を名乗る。major.minor が違えば断り（`handoff.refused`）、古いプロセスがそのまま動き続ける（マイナーの更新は再起動で）。
3. 古いプロセスが待ち受けのソケットをすべて渡す（`SCM_RIGHTS`）：ルールの TCP・UDP（`SO_REUSEPORT` の組ごと）、HTTP/3 の UDP、制御 API の TCP と Unix ソケット、`global.acme.http01_listen`。続けて状態（API で作ったルール（`origin: api` は作ったトークン・時刻・`persisted` ごと）、ルールの組（#28）とその世代、各ルールの統計の数と `stats.http` のルートごとの数、`limited`・帯域で捨てた数、`counters_since`）。
4. 新しいプロセスは普段どおりに起動するが、ソケットを開くところでは受け取ったソケットを使う（同じソケットなので、入れ替わりの間も接続を断らない）。ルールは設定ファイルと、古いプロセスから受け取った API のルール・ルールの組で作る（組は同じ世代・etag のまま。DB からは読み直さない：古いプロセスが起動時に読んだあとの変更が API のルールに入っているので）。統計の数は古いプロセスの数に足す（減らない）。`counters_since` と `rproxy_process_start_time_seconds` も引き継ぐ。準備ができたら古いプロセスに知らせる（`handoff.ready`）。
5. 古いプロセスは systemd（`Type=notify`・`NotifyAccess=all`）と `rproxy-api launch` に新しい主プロセスを知らせ（`MAINPID=`）、受け付けをやめ、今の接続が終わるのを `--handoff-drain`（既定 5 分）まで待ち、残りを切ってから、待っている間に数えた分を新しいプロセスに送って終わる（`handoff.done`）。`systemctl stop`（SIGTERM）が来たら待つのをやめる。
6. 新しいプロセスが `--handoff-timeout`（既定 30 秒）の間に準備できなければ、古いプロセスは子を止めて今までどおり動き続ける（`handoff.failed`）。

守ること：

- **TCP・HTTP は切れない**：古いプロセスが持っている接続は最後まで古いプロセスが扱う。新しい接続は新しいプロセスへ。HTTP のルールは、受け付けをやめたところで処理中のリクエストを終えてからアイドルの接続を閉じる（クライアントは新しいプロセスにつなぎ直す）。
- **UDP は一瞬途切れてよい**（オーナーの了承）：待ち受けのソケットは渡すが、今のセッションは古いプロセスと一緒に終わり、新しいプロセスで作り直す（転送先から見ると送信元のポートが変わる。QUIC の passthrough は接続の移動で続く見込み、DTLS と、終端している QUIC・DTLS はつなぎ直し）。
- 引き継ぎの間（と、その後の古いプロセス）では、変更の API（`GET` 以外。`/admin/*` は除く）に `503 upgrading` を返す。渡した状態のあとで古いプロセスが受けた変更は失われるので、少し待って送り直す。
- 新しいプロセスで最初からになるもの：`limits`（#165）の送信元ごとの数（接続数・速さのバケツ・覚えている送信元）と `bandwidth`（#166）のバケツ、`http` のミドルウェアの `rate_limit`・`in_flight`・`circuit_breaker` の状態、受け身のヘルスチェック（#170）の外した宛先、ヘルスチェックの結果（最初の確認まで up）。古いプロセスが drain しているあいだの接続は古いプロセスの数で数えるので、その間は同じ送信元が新旧で合わせて `max_connections` を超えることがある（古い接続が終われば戻る）。
- `global.performance`（ワーカーの数など）は新しいプロセスの起動のときに決まる。UDP のソケットの組は受け取ったものをそのまま使う（組の大きさを変えるとカーネルの振り分けが変わるため。`udp_shards` の変更はルールのソケットを開き直したときから）。

| 引数 / 環境変数 | 既定 | 意味 |
|---|---|---|
| `--handoff-socket` / `RPROXY_HANDOFF_SOCKET` | `/run/rproxy/handoff.sock` | 引き継ぎ用の Unix ソケット（引き継ぎの間だけ、0600）。親のディレクトリが要る |
| `--handoff-timeout` / `RPROXY_HANDOFF_TIMEOUT` | `30s` | 新しいプロセスの準備を待つ時間（1 秒〜10 分） |
| `--handoff-drain` / `RPROXY_HANDOFF_DRAIN` | `5m` | 古いプロセスが今の接続の終わりを待つ最長の時間（0〜24 時間） |

ログ：`handoff.start`・`handoff.sent`・`handoff.received`・`handoff.ready`・`handoff.drain`・`handoff.done`・`handoff.counters`・`handoff.failed`・`handoff.refused`・`handoff.sockets`。`/metrics`：`rproxy_build_info{version,sha256}`、`rproxy_handoffs_total{outcome="done|failed|refused"}`、`rproxy_process_start_time_seconds`。`GET /capabilities` の `build` は `{"version","sha256"}`。

### systemd

ユニットは `Type=notify`・`NotifyAccess=all`（起動が終わったら `READY=1`、引き継ぎでは古いプロセスが `MAINPID=<新しい pid>` を送る）。`systemctl reload` は今までどおり SIGHUP（設定・証明書の読み直し）で、引き継ぎは SIGUSR2（オーナーの決定）。

### パッケージ（.deb）

`postinst` は動いているサービスを更新するとき、前の版と major.minor が同じなら SIGUSR2 で引き継ぎ、主プロセスが変わったのを確かめる（変わらなければ restart）。major.minor が違えば restart。引き継げない例外のパッチは `/usr/share/rproxy-api/restart-required` を入れて出す（docs/RELEASING.md）。apt で入れた VM では自動更新（下）は off のまま（apt と二重にしない）。

## 自動更新（コンテナ）

イメージの入口を `rproxy-api launch` にする（環境変数は `RPROXY_UPDATE=auto` などを渡す。ほかの引数・`RPROXY_*` はそのままサーバに渡る）。

- 起動役（launch）は、イメージと同じ X.Y の最新のパッチを、キャッシュとリリースの取り先から選び、**署名を確かめてから**子として起動する。取り先に届かない（障害・閉じたネットワーク）ときはキャッシュの最新、なければイメージの版。そのあとはコンテナの init として残り、シグナル（TERM・INT・HUP・USR2）をサーバに渡し、引き継ぎで主プロセスが変わったら新しいほうを追う（`launch.mainpid`）。孤児になったプロセスも引き取る（`PR_SET_CHILD_SUBREAPER`）。
- 動いている間：`RPROXY_UPDATE_INTERVAL` ごと、または `POST /admin/update`（`admin`、既定では Unix ソケットからだけ。`202 {"status":"checking"}`）で新しいパッチを探し、確かめたら引き継ぎで入れ替える。`check` なら知らせるだけ（ログ `update.available` と `GET /admin/update`）。
- 新しい版は、`RPROXY_UPDATE_HEALTHY` の間動き続けたら「よい版」になる（`update.healthy`。前のよい版を 1 つ残し、ほかはキャッシュから消す）。それまでに落ちたら（起動しない・引き継ぎに失敗した・すぐ落ちた）「悪い版」として覚えて二度と選ばず、前のよい版（なければイメージの版）で起動し直す（`update.rollback`）。
- k8s ではレプリカの入れ替えで更新するので `RPROXY_UPDATE=off` にする。

| 環境変数（引数は同じ名前の `--update-*`） | 既定 | 意味 |
|---|---|---|
| `RPROXY_UPDATE` | `off` | `off`・`check`・`auto` |
| `RPROXY_UPDATE_PIN` | なし | 版を固定する（`0.4.3`。同じ X.Y の古いパッチにも戻せる） |
| `RPROXY_UPDATE_SOURCE` | `https://github.com/max3584/rproxy-api/releases` | リリースの取り先（`https://` だけ）。ミラーは同じ道筋 `<source>/download/v<X.Y.Z>/<file>` と、索引 `<source>/latest/download/releases.json`（と `.minisig`）を置く |
| `RPROXY_UPDATE_CACHE` | `/var/cache/rproxy/update` | キャッシュ（書き込めるボリューム。ルートのファイルシステムは読み取り専用でよい） |
| `RPROXY_UPDATE_INTERVAL` | `6h` | 確かめる間隔（`0s` で起動時と API だけ） |
| `RPROXY_UPDATE_PUBKEY` | バイナリに入れたリリースの鍵 | 署名を確かめる minisign の公開鍵のファイル（ミラーで自分で署名し直すとき）。鍵が入っていないビルドではこれが要る |
| `RPROXY_UPDATE_HEALTHY` | `60s` | この間落ちなければ新しい版を「よい版」とする |

### 確かめること

- 取るもの：`manifest.json`（版、`handoff` の可否、各バイナリの SHA-256）とその `.minisig`、このターゲットのバイナリ `rproxy-api-v<X.Y.Z>-<target>` とその `.minisig`。どの版があるかは、署名つきの索引 `<source>/latest/download/releases.json`（`{"releases":[{"version":"0.4.3"},...]}`。リリースのワークフローがリリースのたびに、すべてのマイナーのすべてのリリースを並べて書く）で知る。番号は飛ぶ（動くものが変わったリポジトリだけを出すため）ので、順に試すのではなく索引から、同じ X.Y で今より新しく悪い版でない最新のものを選ぶ（そのマニフェストが確かめられなければ 1 つ古いものへ）。
- 署名は **minisign**（Ed25519。既定の BLAKE2b の事前ハッシュの形と古い形の両方）。マニフェストとバイナリの両方の署名、マニフェストの版、マニフェストの SHA-256 との一致がそろわないものは実行しない。キャッシュのものも起動の前に確かめ直す。
- `"handoff": false` のパッチは入れ替えず、`update.restart_needed` を出す（次の起動で使う）。
- `GET /admin/update`：`{"mode","current":{"version","sha256"},"available":{"version","sha256"}|null,"last_check","error","bad_versions":[...]}`。
- キャッシュ：`<cache>/<版>/`（バイナリ・署名・マニフェスト）と `state.json`（`good`・`previous`・`bad`・`trial`）。

ログ：`update.check`・`update.available`・`update.fetched`・`update.healthy`・`update.rollback`・`update.restart_needed`・`update.error`、起動役の `launch.start`・`launch.mainpid`・`launch.exit`。
