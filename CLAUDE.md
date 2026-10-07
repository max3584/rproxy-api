# CLAUDE.md — rproxy-api

稼働中に TCP/UDP の転送を追加・変更・削除・問い合わせできる L4 フォワーダ（Rust / tokio / axum）。glacierx/rproxy を出発点にしたが、すべて作り直した独立したプロジェクト（帰属の表記は LICENSE と README の末尾）。
管理 UI は別リポジトリ `../TCP-UDP-rproxy-ui`（Next.js）で、HTTP API で操作する。

## コマンド

```bash
cargo build
cargo test                    # 単体テスト（src/）と、loopback で実ソケットを使う結合テスト（tests/。一覧は docs/TESTING.md）
cargo clippy --all-targets
cargo bench --bench '*'       # criterion のベンチマーク（benches/）。PR では bench.yml がマージベースと比べて、遅くなったら警告（docs/TESTING.md）
scripts/test-transparent.sh   # transparent の実経路テスト（root 不要、名前空間を使う。cargo build の後）
scripts/load/run.sh           # 負荷・soak のテスト（転送効率、#183。名前空間で direct / rproxy / HAProxy を比べる。Load ワークフローは頼まれたときに手動でだけ動かす。高速化の案は `perf/<topic>` のブランチにして `gh workflow run load.yml -f refs=master,perf/a,perf/b` で同じランナーで交互に比べる。docs/TESTING.md。試した改善は採用しなかったものも理由と一緒に docs/PERFORMANCE.md（日本語・英語）に記録する）
cargo run                     # 設定は環境変数 RPROXY_* か .env（.env.example を参照）
```

- 設定項目は `src/main.rs` の `Options`（clap）。すべて `RPROXY_*` 環境変数でも指定でき、起動時に `.env` を読む。項目を増やすときは `.env.example` と README（`README.md`・`README.en.md`）の表も更新する。

- ring（rustls）のビルドには C コンパイラが要る。
- グローバルアロケータ（#185）：既定は libc の malloc（リリースは musl。メモリを最も少なくする方針）。cargo の機能 `alloc-mimalloc`（既定で無効。`src/main.rs` の `#[global_allocator]`、バイナリだけ）で mimalloc にできる（L7 の CPU が減り、メモリが増える）。CI の `clippy + tests` が `--features alloc-mimalloc` でもビルドを確かめる。UDP のセッションの 64 KiB の受信バッファは `net::udpsock::RecvBuf` で libc の allocator から取る（グローバルアロケータが mimalloc でも、触れていないページがメモリにならないように。待ち受けの受信は `Batch` の mmap で、どの allocator も通らない）。jemalloc（tikv-jemallocator）も比べたが、armv7 を zig でビルドできない・`make` が要る・aarch64 のページの大きさを決め打ちにする必要がある・メモリが多いので採らなかった。
- `Cargo.lock` はコミットしている（#150）。CI・リリース・パッケージのビルドは `--locked` で、`Cargo.lock` と食い違えば失敗する。依存を変えたら `cargo build` で更新した `Cargo.lock` も同じ PR に入れる。Renovate は cargo を `rangeStrategy: update-lockfile` で更新する（互換の範囲の更新は `Cargo.lock` だけ。`Cargo.toml` の下限は互換が切れる更新のときだけ上がる）。
- `deny.toml` と `.github/workflows/deny.yml`（`cargo deny --locked check`）：RustSec の勧告（脆弱性・メンテ終了・yank）、ライセンス、取得元（crates.io だけ）を、依存を変える PR と毎日確かめる（必須のチェックではない）。直せない勧告は `advisories.ignore` に `{ id = "RUSTSEC-…", reason = "…" }` で、理由と外す条件を書いて足す。新しいライセンスは中身を確かめてから `licenses.allow` に足す。依存を足したら `cargo machete` で使っていないものがないか確かめる（`md-5` は `md5` の名前で使っているので `[package.metadata.cargo-machete]` で除外）。
- ファジング（#162）：`fuzz/` は cargo-fuzz の独立したクレート（自分の `Cargo.toml`・`Cargo.lock`・workspace。直下の build・test・deny には入らない）。ターゲットは ClientHello（`tls::sni`）、DTLS・QUIC（`tls::udp_sni`）、PROXY ヘッダ（`net::source`）、`match` の式、STARTTLS、設定ファイル、DNS の応答（`acme::dnsq`）、RFC 2136 の応答の TSIG（`acme::rfc2136`）。`.github/workflows/fuzz.yml` が PR（`src/`・`fuzz/`）で各 60 秒、毎日 10 分動かす（必須ではない。Alpine なので sanitizer なし：Rust の ASan は glibc のターゲットだけ）。インターネットから読むものの解析を足したり変えたりしたら、ターゲットと `fuzz/seeds/`（`fuzz/gen_seeds.py`）も直す。見つかった入力は直してから単体テストに足す。詳細は docs/TESTING.md。
- `Cargo.toml` を変える PR（Renovate を含む）では `.github/workflows/cross.yml` がリリースと同じ手順（`scripts/build-release.sh` の 6 ターゲット、musl の .deb、`debian:13-slim` で使い捨ての鍵の apt リポジトリ）を通す（ARM・musl・gnu だけで壊れる依存の更新やリリースの手順の誤りを、マージ前に見つけるため）。
- リリースは `v*` タグの push で `.github/workflows/release.yml` が Linux の 6 ターゲット（x86_64・aarch64・armv7 の gnu と musl）向けに Alpine のコンテナでビルドし（`scripts/build-release.sh`：musl の x86_64 はそのまま、ほかは cargo-zigbuild。gnu は glibc 2.17 向け）、amd64 / arm64 / armhf の `.deb`（musl の静的リンク）を作って `gh-pages` の apt リポジトリに載せる。タグと `Cargo.toml` の `version` を揃えること。`GET /capabilities` の `version` は `env!("CARGO_PKG_VERSION")`。rproxy-ui の .deb はタグの push では載せず、`workflow_dispatch`（`ui_tag`）で載せる。詳細は `docs/APT.md`。
- `scripts/install.sh` は VM 向けのインストーラ（root・systemd が前提。Debian / Ubuntu は apt、それ以外はリリースのバイナリ）。設定の雛形は `debian/rproxy.env` と `contrib/rproxy-api.service` を使う（チェックアウトから実行したときは手元のもの、curl で実行したときは GitHub のもの）。CI の `install.sh` ジョブ（`scripts/test-install.sh`。ランナーの VM で、`package` ジョブが Alpine で作った musl のバイナリを使う）で実際に入れて確かめる。
- パッケージ（`debian/`、`[package.metadata.deb]`）を変えたら `cargo deb` で作り、CI の `Debian package` ジョブ（`scripts/test-deb.sh`。`package` ジョブが Alpine で作った .deb を、ランナーの VM に sudo でインストールするので手元では実行しない）で確かめる。`debian/rproxy-api.service` は `contrib/rproxy-api.service` と `ExecStart` 以外を揃える。
- CI の実行環境（#191。一覧は docs/TESTING.md の「CI の実行環境」）：ジョブは Alpine のコンテナ（`container: alpine:3.24`。名前空間・nft を使うものは `options: --privileged`）で動かし、Debian / Ubuntu の重いイメージは使わない。例外は .deb のための 2 か所だけ：apt リポジトリを作る release の `apt`（と cross の `apt (dry run)`）は `debian:13-slim`、.deb と install.sh を確かめる CI の `deb`・`install` は systemd が PID 1 で要るのでランナーの VM で直接（Rust はビルドしない）。ジョブを足すときもこれに合わせる。最初のステップで `apk add` する（`actions/checkout` には git、`actions/cache`・`rust-cache` には GNU の tar と zstd、`run:` を bash で動かすには bash が要る）。コンテナの中では `${{ runner.temp }}`・`${{ github.workspace }}` がランナーの側のパスになるので、`$RUNNER_TEMP`・`$GITHUB_WORKSPACE` を使う。必須のチェックはジョブの `name:` で照合しているので、名前を変えない（ルールセットも直すときだけ）。

## 構成

`src/` は役割ごとのフォルダに分けている（#157）：`control/`（制御 API）、`config/`（設定ファイル）、`core/`（ルールの管理）、`net/`（ソケット・アクセス制御）、`l4/`（L4 の転送）、`tls/`（TLS・SNI）、`acme/`（ACME）、`l7/`（L7。ミドルウェアは `l7/middleware/`）。直下は `main.rs`・`lib.rs`・`error.rs`・`logging.rs`。

| ファイル | 役割 |
|---|---|
| `src/main.rs` | 設定（環境変数・`.env`・引数）、ログ初期化、TLS、起動時の DB 復元、制御 API の起動、SIGHUP（トークン・証明書の再読込）と終了処理 |
| `src/control/api.rs` | axum のルーター。Bearer 認証のミドルウェア。エラーは常に `ApiError` の JSON |
| `src/control/auth.rs` | トークンファイル（複数トークン同時有効、再読込）。スコープ `rules:read`・`rules:write`・`metrics:read`・`acme:write`・`admin` |
| `src/control/acme_api.rs` | ACME の API（#208）：`GET /acme`（名前と状態だけ。秘密もそのファイルの場所も出さない）、強い操作 `POST /acme/renew`・`/acme/revoke`・`/acme/accounts/{name}/register`・`deactivate`（`acme:write`、既定は Unix ソケットからだけ。`RPROXY_API_RELOAD_UNIX_ONLY` を共有）。ACME の証明書を使うルールの作成・変更にも `acme:write` が要る（`check_rule_scope`） |
| `src/config/mod.rs` | 設定ファイル（`RPROXY_CONFIG`。YAML / JSON、`version`・`global`・`rules`。ディレクトリなら名前の順にまとめる）。YAML は JSON の値を経由して読む（`{種類: 設定}` の enum が API と同じ意味になるように）。変更の検知は `config::fingerprint`、反映は `src/config/reload.rs` の `ConfigReloader::reload`（`main.rs` の `watch_config`・SIGHUP・`POST /config/reload` が共有し、Mutex で同時に動かない）→ `Registry::reload_static`（差分だけ。PATCH で変えられる違いは接続を切らずに変える） |
| `src/config/reload.rs` | 設定ファイルの再読み込み（`ConfigReloader`）。最後に反映した指紋・誤りを持ち、ファイルの監視・SIGHUP・`POST /config/reload`（`admin` のスコープ。既定は Unix ソケットからだけ：`api::Transport::UnixSocket` の拡張と `RPROXY_API_RELOAD_UNIX_ONLY`）が同じものを使う。失敗したときの詳しい理由は `check::check` |
| `src/config/check.rs` | `rproxy-api --check-config`（#140）：設定ファイルを起動時・再読み込みと同じ道筋で確かめる（`ConfigDoc::load`、`Registry::check_rules`。`check_rules` は `validate_static` と同じ検証と、`prepare` のうちソケットと名前解決を除いた `build_parts`（証明書・`http`・秘密のファイル）を通り、誤りで止めずにすべて集める）。待ち受け・DB・制御 API は開かない。`rproxy` のユーザーが読めないかもしれないファイルは所有者とモードから警告 |
| `src/config/db.rs` | 起動時に `forward_rules` を読む（sqlx / mysql） |
| `src/core/registry.rs` | 稼働中ルールの唯一の持ち主。作成・変更・削除・一覧・metrics、listener の監視（panic したら `failed`）、名前解決できないルールの再試行 |
| `src/core/rule.rs` | ルールの型と検証。`Features`（この版で動かせる v0.3 の設定。`GET /capabilities` の `features`。パッチで中身を入れたら true にする） |
| `src/core/proxy.rs` | ルールごとの実行時状態 `Runtime`（トークン、watch、統計、`TaskTracker`）。`select` が転送先の候補を良い順に返す（`Target.candidates`） |
| `src/core/balance.rs` | 複数の宛先（#98）：`targets` / `balance`（round_robin・least_conn・failover）/ `backup` / L4 の `health_check`（TCP の接続）。`Pool` は `Runtime.pool` にあり、宛先が変わったら丸ごと差し替える。接続に失敗した宛先は `FAIL_COOLDOWN` のあいだ飛ばす。`Lease` が宛先ごとの接続数を数える。状態の変化は `Runtime.pool_events` で UDP のセッションに知らせる（落ちた宛先から移る） |
| `src/core/resolve.rs` | 名前解決と定期再解決。失敗時は前回の結果（watch の中身）を使い続ける。テスト用に差し替え可能 |
| `src/net/listen.rs` | 待ち受けのソケット（`IPV6_V6ONLY` の有無）と、2 つの待ち受けアドレスが重なるかの判定（`clash`。`::` は V6ONLY がなければ IPv4 も含む）。ルールの `extra_listen_addrs`（#99）はアドレスごとに `Running.listeners` のトークンで止め、PATCH で足したアドレスは `add_listeners` から監視のタスクに渡す。UDP はポートごとに `SO_REUSEPORT` の組（`udp_shards`。数は `registry::udp_shards` で既定は 1、`RPROXY_UDP_SHARDS` で増やす実験用のつまみ。テストは `force_udp_shards`、#194）と大きめの `SO_RCVBUF`。組は先に `SO_REUSEPORT` なしで 1 回 bind して、ほかのソケットが持つポートに黙って加わらないようにする。数はソケットを開くときにだけ決める（組の大きさが変わるとカーネルの振り分けが変わり、セッションのない shard に移る） |
| `src/net/udpsock.rs` | ルールの UDP の待ち受けソケット（`Listener`）。`0.0.0.0` / `::` では `IP_PKTINFO` / `IPV6_RECVPKTINFO` で受けた宛先（`Local`）を覚え、返信は `sendmsg` でそこから送る（#137。アドレスが複数のホストで、カーネルに任せると違うアドレスから返ってしまう）。UDP のセッションは（クライアント, `Local`）ごと。受信は `recv_batch`（`recvmmsg`、バッファは shard ごとに 1 つ）、転送先への送信は `send_connected`（`sendmmsg`、PROXY v2 のヘッダは iovec で前に付ける） |
| `src/net/source.rs` | PROXY protocol v1/v2 ヘッダ（v2 は TLS の TLV つき）、`IP_TRANSPARENT` ソケット、その可否の判定 |
| `src/net/cidr.rs` | `allow_from` の CIDR（IPv4-mapped IPv6 も IPv4 として扱う） |
| `src/l4/tcp.rs` / `src/l4/udp.rs` | データプレーン。停止は `CancellationToken`、転送先は `watch` で受け取る。UDP は shard（`SO_REUSEPORT` のソケット）ごとに `serve` が 1 つ動き、セッションの表も shard ごと（カーネルが 4 タプルのハッシュで同じクライアントを同じソケットに渡す）。ポートで共有するのは `udp::Port`（名前を読んでいるセッションの数）だけ |
| `src/l4/relay.rs` | 両方向のコピー（#185）：L4 の TCP の中継と HTTP の upgrade（WebSocket）。`tokio::io::copy_bidirectional` と同じ半分閉じ・flush・誤りの扱いで、バッファ（32 KiB。TLS から読むときは `TLS_READ_SIZE` の 8 KiB）はデータが流れている間だけスレッドごとのプールから借りる（アイドルの接続は持たない。`buffers_in_use`）。`Copy` は `Handover` を渡すと、大きな転送だと分かったところで `Step::Handover` を返して `splice.rs` に渡す |
| `src/l4/splice.rs` | 平文の L4 TCP（passthrough・sni・terminate の passthrough route。`tcp.rs` の `finish_plain`）の大きな転送を splice(2) で（#184）。向きごとに `relay::Copy` で始め、32 KiB の読み込みが 4 回続けて満杯になったら splice に切り替える。パイプは読めるデータがあるときだけ取り、待つ間は共有のプール（最大 8 本）に返し、splice している向きがなくなったらプールを空にする（`pipes_in_use`・`pooled`）。EINVAL / ENOSYS・パイプが作れないときはその向きの残りをユーザー空間のコピーで。半分閉じ・失敗時の RST・バイト数は `finish` と同じ。実験用の内部の環境変数 `RPROXY_SPLICE`（0 で無効）・`RPROXY_SPLICE_AFTER`・`RPROXY_SPLICE_FULL_READS`・`RPROXY_SPLICE_PIPE_SIZE`（形は v0.4.0 で決める。文書にはまだ書かない） |
| `src/l4/starttls.rs` | SMTP / IMAP / POP3 の STARTTLS 前のやり取りと、TLS 後の転送先の挨拶の読み捨て |
| `src/tls/config.rs` | `tls` の設定の型と検証、証明書・鍵・CA の読み込み（`KeyedCert` / `CertBundle`）、SNI での証明書の選択、rustls / dtls クレート の設定の組み立て（`TlsRuntime::build` は読み込み済みの `RuleCerts` から組み立てる。`TlsRuntime::load` はファイルから直接）。証明書の期限を調べるのは `inspect_certificate` だけ（純粋な関数） |
| `src/tls/certstore.rs` | 証明書のストア（#115、`Registry.certs`）：ルールが使う証明書をファイルの組（`Source`）ごとに 1 回だけ読み込んで共有する。ファイルの変化（`refresh`、#90）・SIGHUP（`reload_all`）・期限（`newly_expired`）を証明書ごとに扱い、`Registry::apply_certs` が変わった証明書を使うルールだけを組み立て直す。誰も使わなくなった証明書は `retain` で捨てる。期限のログ（`cert.expiring` / `cert.expired`）は状態が変わったときに 1 回 |
| `src/acme/mod.rs` | ACME（#208、docs/ACME.md）：`Acme`（`Registry::set_acme`）が `global.acme` とルールが使う証明書（`set_wanted`。`Registry::gc_certs` が渡す）を持ち、1 つのタスク（`spawn`）が順に注文・更新する（CA の ARI（RFC 9773）の窓のランダムな時刻、ARI がなければ期限の 30 日前か寿命の 1/3。失敗は 1 分から倍々で最大 6 時間、`rate_limit`）。取った証明書は `<storage>/certs/...` に 0600 で書き、証明書のストアの `Source::Acme` がほかのファイルと同じく読み直す（`on_change` → `reload_changed_tls`）。まだないあいだは自己署名の仮の証明書（ディスクに書かない）。名前の許可（`allowed_names`）は `config::AcmeGlobal::check_names` だけで判断し、API・設定ファイル・`--check-config`・注文の直前で同じものを使う |
| `src/acme/config.rs` | `global.acme` の型と検証（アカウント・DNS のプロバイダ・resolver・`rate_limit`）、`allowed_names` のパターン（`name_allowed`） |
| `src/acme/challenge.rs` | 答えている challenge（プロセスで共有）：HTTP-01 は `http` のルール（`server.rs` の `Conn::handle` の最初）と `http01_listen`、TLS-ALPN-01 は `tcp.rs` の `accept_tls`（ALPN が `acme-tls/1` だけの ClientHello）。`Answers` を drop すると取り下げる |
| `src/acme/dns.rs`・`dnsq.rs`・`rfc2136.rs` | DNS-01：PowerDNS の HTTP API、RFC 2136（TSIG の HMAC-SHA256/512、`rfc2136.rs`。応答の TSIG も確かめる：要求の MAC を含む署名・時刻・BADSIG/BADKEY/BADTIME）、acme-dns（アカウントは `credentials_file`、なければ登録）、汎用の REST のテンプレート（秘密はファイルから使うときに読み、ログ・誤りの文に出さない）、書いた TXT の記録（`dns-pending.json`。起動時に残りを消す）。`dnsq` は CNAME・SOA・TXT を引く小さな DNS のクライアント（応答の解析はファジングの対象） |
| `src/acme/helper.rs` | ACME の補助プロセス（`rproxy-api acme-helper`、`global.acme.helper`）：DNS のプロバイダの秘密を持ち、本体の代わりに TXT の場所を決めて書く・消す（`dns::Backend::Helper`）。1 行 1 JSON（`locate`・`present`・`cleanup`）を Unix ソケットで。名前の許可・値の形・書き込み先を自分で確かめ、`--allow-user` は SO_PEERCRED。本体は helper があると DNS の秘密のファイルを開かない。ユニットは `contrib/` と `debian/rproxy-acme-helper.service`（ユーザー `rproxy-acme`） |
| `src/acme/http.rs` | CA と DNS の API への HTTP（instant-acme の `HttpClient`。hyper・rustls（ring）・web PKI のルートか `ca_file`） |
| `src/tls/sni.rs` | ClientHello からサーバ名を読む（`tls.mode: sni` と、`terminate` の `passthrough` の route。ClientHello の本体の解析 `hello_server_name` / `parse_handshake` は udp の DTLS・QUIC（`udp_sni`）と共有。読んだバイトは転送先へそのまま送るか、`tcp.rs` の `Prefixed` で rustls に渡し直して終端する） |
| `src/tls/udp_sni.rs` | udp の `tls.mode: sni`（#130）：DTLS の ClientHello（断片のつなぎ合わせ）と QUIC v1 / v2 の Initial（接続 ID から鍵を計算し、ヘッダの保護と AEAD を外して CRYPTO フレームをつなぐ）からサーバ名を読む `Sniffer`。`udp.rs` の `sniff` が新しいセッションの最初のデータグラムを持って名前を読み、`renamed` が同じソケットからの別の名前の新しい QUIC の接続でセッションを作り直す。テストは RFC 9001 / 9369 付録 A の例と、tests/udp_sni.rs（本物の quinn・dtls のクライアントとサーバ） |
| `src/tls/dtls.rs` | 共有の UDP ソケットから 1 クライアント分のデータグラムを dtls クレート に渡す `Conn` |
| `src/l7/mod.rs`・`src/l7/matcher.rs` | L7（ルールの `http`）の設定の型と検証、`match` の式（Traefik と同じ書き方）の解析と評価 |
| `src/l7/server.rs` | `http` のルールのデータプレーン（hyper）。クライアントとは HTTP/1.1・HTTP/2、転送先とは HTTP/1.1。`Router` はルールの `Runtime.http` に入れ、変更時は丸ごと差し替える（古い `Router` が drop されるとヘルスチェックも止まる）。本文・応答・転送先が要るミドルウェア（`buffering`・`retry`・`circuit_breaker`・`errors`・`compress`・`crowdsec`）はここで動かす |
| `src/l7/h3.rs` | HTTP/3（`http.http3`）：ルールと同じアドレス・ポートの UDP の quinn の Endpoint、h3 のリクエストを `server.rs` の `Conn::handle` に渡す。QUIC の TLS は `TlsRuntime.quic_config`（TCP と同じ証明書・クライアント認証、TLS 1.3、ALPN h3）を接続ごとに読むので、証明書の読み直しもそのまま効く。UDP を使えなければ TCP だけで動き、`Runtime.h3` に理由を持つ。本文の型 `Body` の誤りは `BoxError`（hyper と h3 の両方） |
| `src/l7/backend.rs` | サービスと転送先：重みつきラウンドロビン（down を除く）、ヘルスチェック、`sticky` のクッキー、転送先ごとの待機中の接続（応答の本文を読み終えたら戻す）、接続（`Dialer`） |
| `src/l7/resilience.rs` | `buffering`（本文を上限つきで読み切る）、`retry` の待ち時間、`circuit_breaker`（`Breaker` と、結果を必ず返す `Ticket`） |
| `src/l7/compress.rs` | `compress`：`Accept-Encoding` の交渉、圧縮しない応答の判定、流れてきた分ずつ圧縮する本文（gzip・br・zstd） |
| `src/l7/access.rs` | `global.trusted_proxies`・`global.access_log`（`HttpGlobal`。`Registry` の `Config.http` から全ルールの `Runtime.global` へ）、X-Forwarded-For からクライアントの IP を決める、アクセスログ、ルートごとのリクエストの統計（`stats.http`・`/metrics`） |
| `src/l7/middleware/mod.rs` | ミドルウェア（リダイレクト、`respond`、`ip_allow`、`headers`、パスの書き換え、`rate_limit`・`in_flight`）。`Router::compile` で一度だけ組み立てる |
| `src/l7/middleware/auth.rs` | 認証のミドルウェア（#59）：`basic_auth`（htpasswd の bcrypt / APR1 / {SHA}、通った組み合わせのキャッシュ）、`forward_auth` の問い合わせのヘッダと応答の写し（送るのは `server.rs` が転送先の接続で）、秘密のファイル（`SecretFile`。変わったら数秒以内に読み直す、SIGHUP で `Router::reload_secrets`） |
| `src/l7/middleware/oidc.rs` | `oidc`：認可コード + PKCE、discovery と JWKS のキャッシュ、ID トークンの検証（ring。RS/PS/ES）、AES-256-GCM で暗号化したセッションのクッキー、リフレッシュ、ログアウト。コールバックとログアウトのパスは `server.rs` がルーティングの前に渡す。プロバイダへの HTTP は `crowdsec::call` |
| `src/l7/middleware/crowdsec.rs` | `global.crowdsec` の bouncer（`Bouncer`。LAPI の stream を 1 つのタスクで取り、判定を ID ごとに覚える。API キーは SIGHUP で読み直す）と AppSec への問い合わせ。`crowdsec` ミドルウェアは非同期なので `server.rs` が直接呼ぶ |
| `src/l7/middleware/limit.rs` | `rate_limit`（送信元ごとのトークンバケット。覚える送信元は上限つき）と `in_flight`（`Hold` を応答の本文が終わるまで持つ）。状態は組み立てた `Router` にあり、`http` を変えると最初からになる |
| `src/logging.rs` | tracing の JSON Lines 出力（日次ローテーション）。`Throttle`：攻撃で同じ行があふれないよう、送信元ごと・全体でログを間引く（UDP の `conn.denied`、制御 API の 401 / 403。省いた数は次の行の `suppressed` と `rproxy_log_suppressed_total`） |

構成図は `docs/architecture/`（SVG だけ。PlantUML のソースはリポジトリに置かない）。モジュールや状態を変えたら図も直す。

## 制御 API（UI との契約）

`docs/API.md` が正。ルールのキーは `(protocol, listen_addr, listen_port)`。
形を変えるときは UI 側の `components/rproxy.ts` と、テーブル定義（UI リポジトリの `db/`）も合わせて変える。

## 設計上の約束

- v0.3 の設定の形は docs/DESIGN-v0.3.md と docs/API.md の「v0.3 の設定」が正。形はマイナーでまとめて決め、中身はパッチで入れる（docs/RELEASING.md）。
- v0.4 の形は docs/DESIGN-v0.4.md と docs/API.md の「v0.4 の設定」が正（#215）。**v0.4.0 は中身まで全部そろえてから 1 回で出す**（v0.4.x の途中の版を作らない。オーナーの決定）。機能ごとにモジュールを分けてある（`core/limits.rs`・`core/bandwidth.rs`・`core/outlier.rs`・`core/ruleset.rs`・`net/geoip.rs`・`config/performance.rs`・`config/plan.rs`・`config/persist.rs`・`control/hardening.rs`・`control/ruleset_api.rs`・`control/upgrade.rs`）。実装したら `Features::CURRENT` を true にし、`tests/v04_shapes.rs` のその機能のテストを動くことのテストに置き換える。Kubernetes のコントローラは別のリポジトリ `../rproxy-gateway`（`max3584/rproxy-gateway`）で、rproxy とは制御 API だけでつながる。中身を入れたら `Features::CURRENT` を true にし、`unsupported` のテストを動くことのテストに置き換える。

- 起動時に止めるのは設定のエラー（値の誤り、存在しないパス、ファイルの中身の誤り）だけ。権限・使用中のポート・DB など環境の問題では、使えない部分だけを止めて起動を続け、`event = "degraded"`（`part` で箇所）をログに出す（README の「起動できないものがあるとき」、`tests/startup.rs`）。トークンが読めないときに認証なしにはしない（API を閉じる）。

- ルールの状態は `Registry` だけが持つ。タスクの `JoinHandle` を捨てない。
- 停止は `stop`（受け付け停止）→ 任意の drain → `kill`（既存接続の切断）の順。`delete` は listener が閉じ、全接続が終わってから返る。
- 転送先の変更は `watch` 経由。TCP は新しい接続から、UDP は既存のセッションも切り替わる。宛先が複数のルールでは、UDP のセッションは自分の宛先が down になったときだけ移る（`failover` で上位が戻っても、既存のセッションはそのまま）。
- 宛先（`remote_addr` か `targets`、`balance`、`health_check`）は PATCH で毎回まとめて置き換える（省いた `balance` は round_robin、`health_check` はなし）。一覧の `remote_addr` / `remote_port` は `targets` の先頭（古いクライアント・ログ用）。DB の `options.targets` があれば `dist_addr` / `dist_port` は読まない。
- データプレーンの TCP のソケット（受け付けた接続・転送先への接続）はすべて TCP_NODELAY（#176。`net::source::nodelay`、転送先は `connect_tcp` が設定する。失敗は debug のログだけで接続は続ける）。新しく TCP をつなぐ・受け付ける処理を足したら通す。Nagle が両側にあると小さな書き込みが遅延 ACK を待つ（約 40 ms）。確かめるのは tests/dataplane.rs の `small_writes_are_not_delayed_by_nagle`。
- データプレーンのタスクで `unwrap()` / `panic!` を使わない。万一 panic しても、監視タスクがそのルールだけを `failed` にする。
- ログは `event` フィールドで種類を分ける（一覧は README）。
- 利用者向けの文書は日本語と英語の両方がある（日本語は `README.md`・`docs/*.md`・`docs/architecture/README.md`、英語は `README.en.md`・`docs/en/`）。片方を変えたら、同じ PR でもう片方も直す。文書を足したら英語版も作り、互いの先頭のリンクと `.deb` の assets（英語版は `/usr/share/doc/rproxy-api/en/`）も揃える。

## アクセス制御と固定ルール

- `allow_from` は受け付けた直後（TLS や PROXY ヘッダより前）に確かめる。UDP は範囲外のデータグラムを捨てる。拒否は `stats.denied` に数え、`conn.denied` をログに出す。
- `tls.unmatched: reject` の `terminate` は、`LazyConfigAcceptor` で ClientHello を読んでから判断する（一致しない名前には証明書を返さない）。
- `tls.routes` の名前：完全一致・`*.`（1 階層）・`**.`（何階層でも）、`server_names` で複数。選び方は `tls::config::best_match`（完全一致 → `*.` → 長い `**.` → 書いた順）。`passthrough` の route がある `terminate` のルールは、先に `sni::read_client_hello` で読み、passthrough の名前なら `relay_hello`、それ以外は読んだバイトを `Prefixed` で rustls に渡す（`http` のルールも同じ。HTTP/3 は passthrough の名前の接続を閉じる）。
- 設定ファイルの検証を変えたら、`--check-config`（`src/config/check.rs`・`Registry::check_rules`・`build_parts`）も同じ道筋を通っているか確かめる（tests/check_config.rs）。ユニットの `ExecReload` は先に `--check-config` を実行するので、ここで誤りになる変更は reload を止める。
- 固定ルール（`origin: static`）は `Registry::load_static` で起動時に作り、ファイルが変わったら `Registry::reload_static` で差分を反映する（誤りがあれば何も変えない）。API からの変更・削除は `409 static`。`global` の変更は再起動まで効かない（`GET /config` の `restart_needed`）。
- API の定義は `docs/openapi.json`（`GET /openapi.json`）。エンドポイントを足したら、ここにも足す（`api.rs` のテストがルーターとの食い違いを見つける）。
- バージョン管理とリリースは docs/RELEASING.md の決まりで、確認を取らずに進める（番号は UI と別々に進め、タグはずれてよい。動くものが変わったリポジトリだけ番号を上げて出す。組み合わせは UI が `GET /capabilities` の `version` で確かめ、UI のリリースノートに必要な rproxy-api の最小の版を書く。UI の .deb は UI のリリースの後に `gh workflow run release.yml -R max3584/rproxy-api -f ui_tag=vX.Y.Z` で apt に載せる。PR・issue を作るときにパッチ／マイナーのマイルストーンを付ける。マージ後のタグ・リリースノート・マイルストーンの片付けまで行う）。
- PR のブランチに追加で push する前に、その PR がまだ開いているか（`gh pr view <n> --json state`）を確かめる。マージ後に push したコミットは master に入らない（#20/#22、#32 で起きた）。
- 文字列の置き換えでコードを編集するときは、置き換えの対象が 1 件見つかることを確かめる（見つからないまま空振りして、修正が入っていなかったことがある）。

## TLS まわりの約束

- L7 の転送の約束は docs/API.md の「HTTP の転送の扱い」と tests/http_semantics.rs（HTTP/1.1・HTTP/2・HTTP/3 のクライアントで確かめる）。転送の処理を変えたらここに足す。`Host` は `request_authority`（`:authority`・absolute-form が `Host` より先）、HTTP/2・HTTP/3 のヘッダの上限は `MAX_HEADER_SECTION`（64 KiB）、`timeouts.response` は本文を送り終えてから（`until_sent` / `within`）。
- データの完全性（#134）：途中で切れたものを、完全に終わったように見せない。L4 の TCP は、リレーが失敗したら（片方のリセット、書き込めない）両方をリセット（`tcp.rs` の `finish` と `handle` の `reset_on_close`、SO_LINGER 0）。FIN は半分閉じとして伝える。L7 は本文の誤りをそのまま流す（hyper が HTTP/1.1 は接続を切り、HTTP/2 は RST_STREAM）。HTTP/3 は `h3.rs` の `respond` の失敗で `stop_stream`（quinn の SendStream は drop で正常に finish してしまう）。本文を包む型（`compress.rs` の `Compressed` など）は、誤りを `Poll::Ready(None)`（正常な終わり）に変えない。UDP で rproxy が捨てたデータグラムは `stats.dropped`。確かめるのは tests/integrity.rs（転送の処理を変えたらここも回す）。
- L7：HTTP/2・HTTP/3 では、クライアントが `cookie` を複数のフィールドに分けて送れる（Chrome はそうする）。`server.rs` の `Conn::handle` の最初で `join_cookie_fields` が `"; "` で 1 本にまとめる（RFC 9113 §8.2.3 / RFC 9114 §4.2.1。HTTP/1.1 の転送先は Cookie を 1 行しか読まない）。転送先に渡すヘッダは、HTTP/1.1 で意味が変わるものがないか気をつける。
- 証明書ファイルは証明書のストア（`certstore`）が読む。作成・変更で初めて使うとき、SIGHUP、`RPROXY_CERT_CHECK_SECS` ごとの確認で変わっていたときだけ読む（`Registry::reload_changed_tls`、`tls::config::fingerprint`）。同じファイルを使うルールは同じ読み込み結果を共有する。ACME（#208。v0.3.21 から内蔵する方針に変えた）で取った証明書も同じストアで読む（`Source::Acme`、ファイルは `global.acme.storage`）。外部のツール（certbot・cert-manager）で取ったファイルを指定するやり方もそのまま使える。接続ごとには `Runtime.tls`（`RwLock<Arc<TlsRuntime>>`）の複製を使う（接続ごとにファイルを読まない）。
- 証明書の期限（#115）：期限は `tls::config::inspect_certificate` だけで調べる。サーバ証明書は切れたものを SNI の候補から外し、すべて切れたらルールを `failed`（`tls::config::CERT_EXPIRED`）にして待ち受けを閉じる。更新されたファイルが読めたら `apply_certs` が自動で戻す。API の作成・変更では断る（`400 tls_config`）。CA・転送先向けの証明書・制御 API の証明書（ストアの外、`note_external`）は止めずに知らせるだけ。定期の確認は `RPROXY_CERT_EXPIRY_CHECK_SECS`（`Registry::check_certificate_expiry`）。
- STARTTLS では、STARTTLS への応答より前に届いた余分なデータを受け付けない（コマンドの紛れ込み対策）。
- WebRTC のメディア（DTLS-SRTP）は終端できない（SDP のフィンガープリントに結びついているため）。docs/PROFILES.md に書いてあるとおり passthrough で流す。
- 設定の例と用途別の推奨は `docs/PROFILES.md`。UI のプロファイルもこれに合わせる。

## 注意点

- UDP の返信の送信元（#137）：ワイルドカードで待ち受ける UDP は `udpsock::Listener` を通して、受けた宛先のアドレスから返す。UDP の待ち受けソケットに直接 `send_to` を書かない。HTTP/3 は quinn（quinn-udp）が自分で同じことをしている。確かめるのは tests/udp_source.rs（127.0.0.2 宛て）と `scripts/test-udp-source.sh`（名前空間で 1 つのインターフェースに IPv4・IPv6 のアドレスを 2 つずつ。CI の transparent のジョブ）。
- `transparent` は Linux・`CAP_NET_ADMIN` が前提（IPv4 は `IP_TRANSPARENT`、IPv6 は `IPV6_TRANSPARENT`。socket2 0.6 の `set_ip_transparent_v4` / `_v6`）で、ポリシールーティングの設定も要る（README）。ユニットは `CAP_NET_ADMIN` を既定で与え、ポリシールーティングは `contrib/rproxy-transparent-routing`（install.sh の `--transparent-*`）で入れる。権限を足したり外したりしたら docs/PERMISSIONS.md も直す。`scripts/test-transparent.sh` で名前空間の中の実経路では確認済み。`FAMILY=4|6`・`ROUTING=iif|iptables|nft`・`RETURN=rproxy|gateway`（転送先の出口が別のルータで、転送先で connmark を使う構成）の組み合わせを CI で確かめている。利用者向けの説明は docs/TRANSPARENT.md。
- DB からの復元（`src/config/db.rs`）は MariaDB 11.4 で確認済み。テーブルが古く `source_ip` / `udp_idle_secs` 列がない場合は、既定値で読み込む。
- CrowdSec の検知（#129）：`contrib/crowdsec/` のパーサー（`max3584/rproxy-logs`）は rproxy のログの JSON（`http.access` と `conn.open` / `conn.denied`）の項目名に依っている。ログの項目を変えたらパーサーと `scripts/interop/crowdsec-samples.log` も直す。CI の `crowdsec` ジョブ（`scripts/interop/crowdsec.sh`）は本物の CrowdSec で、文書用アドレス（RFC 5737 / RFC 3849）のクライアントを ban させて確かめる（私用アドレスは CrowdSec が whitelist するので検知の試験にならない）。
- `contrib/traefik2rproxy.py`（.deb では `/usr/bin/rproxy-traefik-convert`）は Traefik の設定からの変換ツール（Python 3、YAML は PyYAML）。サーバのバイナリには入れない。設定の形やミドルウェアを足したら、変換の対応（docs/MIGRATING-FROM-TRAEFIK.md の表と `KNOWN_MIDDLEWARES`）も直す。`tests/traefik_convert.rs` が `tests/fixtures/traefik/` を変換して rproxy の検証に通す（CI は `RPROXY_TEST_REQUIRE_PYTHON=1`）。
- 空の環境変数（`RPROXY_DATABASE_URL=` など）は未設定として扱う（`main` で clap に渡す前に取り除く）。
- 派生元のコードに由来するファイルには帰属コメントが付いている。MIT ライセンスの表記は残すこと。
- ACME（#208、docs/ACME.md）の守り：秘密（DNS の API キー・トークン・EAB の鍵）は `global.acme` でファイルを指すだけで、API から作る・読む・変えることはできず、`GET` の応答・ログ・誤りの文に出さない（`dns::excerpt` で伏せる）。取ってよい名前はアカウントと DNS のプロバイダの `allowed_names`（外は `400 invalid`）。ACME の証明書を使うルールには `acme:write`、強い操作は既定で Unix ソケットからだけ。注文は `rate_limit` まで。TXT は検証の後に必ず消し、消せなかったものは `dns-pending.json` から次の起動で消す。ACME の処理を変えたら tests/acme.rs（Pebble・PowerDNS。CI の `clippy + tests` が `RPROXY_TEST_REQUIRE_ACME=1` で動かす）を通す。
