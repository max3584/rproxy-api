# CLAUDE.md — rproxy-api

稼働中に TCP/UDP の転送を追加・変更・削除・問い合わせできる L4 フォワーダ（Rust / tokio / axum）。glacierx/rproxy を出発点にしたが、すべて作り直した独立したプロジェクト（帰属の表記は LICENSE と README の末尾）。
管理 UI は別リポジトリ `../TCP-UDP-rproxy-ui`（Next.js）で、HTTP API で操作する。

## コマンド

```bash
cargo build
cargo test                    # 単体テスト + tests/api.rs（loopback で実ソケットを使う結合テスト）
cargo clippy --all-targets
scripts/test-transparent.sh   # transparent の実経路テスト（root 不要、名前空間を使う。cargo build の後）
cargo run                     # 設定は環境変数 RPROXY_* か .env（.env.example を参照）
```

- 設定項目は `src/main.rs` の `Options`（clap）。すべて `RPROXY_*` 環境変数でも指定でき、起動時に `.env` を読む。項目を増やすときは `.env.example` と README（`README.md`・`README.en.md`）の表も更新する。

- ring（rustls）のビルドには C コンパイラが要る。
- `Cargo.lock` はコミットしている（#150）。CI・リリース・パッケージのビルドは `--locked` で、`Cargo.lock` と食い違えば失敗する。依存を変えたら `cargo build` で更新した `Cargo.lock` も同じ PR に入れる。Renovate は cargo を `rangeStrategy: update-lockfile` で更新する（互換の範囲の更新は `Cargo.lock` だけ。`Cargo.toml` の下限は互換が切れる更新のときだけ上がる）。
- `deny.toml` と `.github/workflows/deny.yml`（`cargo deny --locked check`）：RustSec の勧告（脆弱性・メンテ終了・yank）、ライセンス、取得元（crates.io だけ）を、依存を変える PR と毎日確かめる（必須のチェックではない）。直せない勧告は `advisories.ignore` に `{ id = "RUSTSEC-…", reason = "…" }` で、理由と外す条件を書いて足す。新しいライセンスは中身を確かめてから `licenses.allow` に足す。依存を足したら `cargo machete` で使っていないものがないか確かめる（`md-5` は `md5` の名前で使っているので `[package.metadata.cargo-machete]` で除外）。
- `Cargo.toml` を変える PR（Renovate を含む）では `.github/workflows/cross.yml` がリリースと同じターゲット（arm・musl）をビルドする（ARM や musl だけで壊れる依存の更新を、マージ前に見つけるため）。
- リリースは `v*` タグの push で `.github/workflows/release.yml` が Linux の 6 ターゲット（x86_64・aarch64・armv7 の gnu と musl）向けにクロスビルドし、amd64 / arm64 / armhf の `.deb`（musl の静的リンク）を作って `gh-pages` の apt リポジトリに載せる。タグと `Cargo.toml` の `version` を揃えること。詳細は `docs/APT.md`。
- `scripts/install.sh` は VM 向けのインストーラ（root・systemd が前提。Debian / Ubuntu は apt、それ以外はリリースのバイナリ）。設定の雛形は `debian/rproxy.env` と `contrib/rproxy-api.service` を使う（チェックアウトから実行したときは手元のもの、curl で実行したときは GitHub のもの）。CI の `install.sh` ジョブ（`scripts/test-install.sh`）で実際に入れて確かめる。
- パッケージ（`debian/`、`[package.metadata.deb]`）を変えたら `cargo deb` で作り、CI の `Debian package` ジョブ（`scripts/test-deb.sh`。sudo でインストールするので手元では実行しない）で確かめる。`debian/rproxy-api.service` は `contrib/rproxy-api.service` と `ExecStart` 以外を揃える。

## 構成

`src/` は役割ごとのフォルダに分けている（#157）：`control/`（制御 API）、`config/`（設定ファイル）、`core/`（ルールの管理）、`net/`（ソケット・アクセス制御）、`l4/`（L4 の転送）、`tls/`（TLS・SNI）、`l7/`（L7。ミドルウェアは `l7/middleware/`）。直下は `main.rs`・`lib.rs`・`error.rs`・`logging.rs`。

| ファイル | 役割 |
|---|---|
| `src/main.rs` | 設定（環境変数・`.env`・引数）、ログ初期化、TLS、起動時の DB 復元、制御 API の起動、SIGHUP（トークン・証明書の再読込）と終了処理 |
| `src/control/api.rs` | axum のルーター。Bearer 認証のミドルウェア。エラーは常に `ApiError` の JSON |
| `src/control/auth.rs` | トークンファイル（複数トークン同時有効、再読込） |
| `src/config/mod.rs` | 設定ファイル（`RPROXY_CONFIG`。YAML / JSON、`version`・`global`・`rules`。ディレクトリなら名前の順にまとめる）。YAML は JSON の値を経由して読む（`{種類: 設定}` の enum が API と同じ意味になるように）。変更の検知は `config::fingerprint`、反映は `src/config/reload.rs` の `ConfigReloader::reload`（`main.rs` の `watch_config`・SIGHUP・`POST /config/reload` が共有し、Mutex で同時に動かない）→ `Registry::reload_static`（差分だけ。PATCH で変えられる違いは接続を切らずに変える） |
| `src/config/reload.rs` | 設定ファイルの再読み込み（`ConfigReloader`）。最後に反映した指紋・誤りを持ち、ファイルの監視・SIGHUP・`POST /config/reload`（`admin` のスコープ。既定は Unix ソケットからだけ：`api::Transport::UnixSocket` の拡張と `RPROXY_API_RELOAD_UNIX_ONLY`）が同じものを使う。失敗したときの詳しい理由は `check::check` |
| `src/config/check.rs` | `rproxy-api --check-config`（#140）：設定ファイルを起動時・再読み込みと同じ道筋で確かめる（`ConfigDoc::load`、`Registry::check_rules`。`check_rules` は `validate_static` と同じ検証と、`prepare` のうちソケットと名前解決を除いた `build_parts`（証明書・`http`・秘密のファイル）を通り、誤りで止めずにすべて集める）。待ち受け・DB・制御 API は開かない。`rproxy` のユーザーが読めないかもしれないファイルは所有者とモードから警告 |
| `src/config/db.rs` | 起動時に `forward_rules` を読む（sqlx / mysql） |
| `src/core/registry.rs` | 稼働中ルールの唯一の持ち主。作成・変更・削除・一覧・metrics、listener の監視（panic したら `failed`）、名前解決できないルールの再試行 |
| `src/core/rule.rs` | ルールの型と検証。`Features`（この版で動かせる v0.3 の設定。`GET /capabilities` の `features`。パッチで中身を入れたら true にする） |
| `src/core/proxy.rs` | ルールごとの実行時状態 `Runtime`（トークン、watch、統計、`TaskTracker`）。`select` が転送先の候補を良い順に返す（`Target.candidates`） |
| `src/core/balance.rs` | 複数の宛先（#98）：`targets` / `balance`（round_robin・least_conn・failover）/ `backup` / L4 の `health_check`（TCP の接続）。`Pool` は `Runtime.pool` にあり、宛先が変わったら丸ごと差し替える。接続に失敗した宛先は `FAIL_COOLDOWN` のあいだ飛ばす。`Lease` が宛先ごとの接続数を数える。状態の変化は `Runtime.pool_events` で UDP のセッションに知らせる（落ちた宛先から移る） |
| `src/core/resolve.rs` | 名前解決と定期再解決。失敗時は前回の結果（watch の中身）を使い続ける。テスト用に差し替え可能 |
| `src/net/listen.rs` | 待ち受けのソケット（`IPV6_V6ONLY` の有無）と、2 つの待ち受けアドレスが重なるかの判定（`clash`。`::` は V6ONLY がなければ IPv4 も含む）。ルールの `extra_listen_addrs`（#99）はアドレスごとに `Running.listeners` のトークンで止め、PATCH で足したアドレスは `add_listeners` から監視のタスクに渡す |
| `src/net/udpsock.rs` | ルールの UDP の待ち受けソケット（`Listener`）。`0.0.0.0` / `::` では `IP_PKTINFO` / `IPV6_RECVPKTINFO` で受けた宛先（`Local`）を覚え、返信は `sendmsg` でそこから送る（#137。アドレスが複数のホストで、カーネルに任せると違うアドレスから返ってしまう）。UDP のセッションは（クライアント, `Local`）ごと |
| `src/net/source.rs` | PROXY protocol v1/v2 ヘッダ（v2 は TLS の TLV つき）、`IP_TRANSPARENT` ソケット、その可否の判定 |
| `src/net/cidr.rs` | `allow_from` の CIDR（IPv4-mapped IPv6 も IPv4 として扱う） |
| `src/l4/tcp.rs` / `src/l4/udp.rs` | データプレーン。停止は `CancellationToken`、転送先は `watch` で受け取る |
| `src/l4/starttls.rs` | SMTP / IMAP / POP3 の STARTTLS 前のやり取りと、TLS 後の転送先の挨拶の読み捨て |
| `src/tls/config.rs` | `tls` の設定の型と検証、証明書・鍵・CA の読み込み（`KeyedCert` / `CertBundle`）、SNI での証明書の選択、rustls / dtls クレート の設定の組み立て（`TlsRuntime::build` は読み込み済みの `RuleCerts` から組み立てる。`TlsRuntime::load` はファイルから直接）。証明書の期限を調べるのは `inspect_certificate` だけ（純粋な関数） |
| `src/tls/certstore.rs` | 証明書のストア（#115、`Registry.certs`）：ルールが使う証明書をファイルの組（`Source`）ごとに 1 回だけ読み込んで共有する。ファイルの変化（`refresh`、#90）・SIGHUP（`reload_all`）・期限（`newly_expired`）を証明書ごとに扱い、`Registry::apply_certs` が変わった証明書を使うルールだけを組み立て直す。誰も使わなくなった証明書は `retain` で捨てる。期限のログ（`cert.expiring` / `cert.expired`）は状態が変わったときに 1 回 |
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
| `src/logging.rs` | tracing の JSON Lines 出力（日次ローテーション） |

構成図は `docs/architecture/`（SVG だけ。PlantUML のソースはリポジトリに置かない）。モジュールや状態を変えたら図も直す。

## 制御 API（UI との契約）

`docs/API.md` が正。ルールのキーは `(protocol, listen_addr, listen_port)`。
形を変えるときは UI 側の `components/rproxy.ts` と、テーブル定義（UI リポジトリの `db/`）も合わせて変える。

## 設計上の約束

- v0.3 の設定の形は docs/DESIGN-v0.3.md と docs/API.md の「v0.3 の設定」が正。形はマイナーでまとめて決め、中身はパッチで入れる（docs/RELEASING.md）。中身を入れたら `Features::CURRENT` を true にし、`unsupported` のテストを動くことのテストに置き換える。

- 起動時に止めるのは設定のエラー（値の誤り、存在しないパス、ファイルの中身の誤り）だけ。権限・使用中のポート・DB など環境の問題では、使えない部分だけを止めて起動を続け、`event = "degraded"`（`part` で箇所）をログに出す（README の「起動できないものがあるとき」、`tests/startup.rs`）。トークンが読めないときに認証なしにはしない（API を閉じる）。

- ルールの状態は `Registry` だけが持つ。タスクの `JoinHandle` を捨てない。
- 停止は `stop`（受け付け停止）→ 任意の drain → `kill`（既存接続の切断）の順。`delete` は listener が閉じ、全接続が終わってから返る。
- 転送先の変更は `watch` 経由。TCP は新しい接続から、UDP は既存のセッションも切り替わる。宛先が複数のルールでは、UDP のセッションは自分の宛先が down になったときだけ移る（`failover` で上位が戻っても、既存のセッションはそのまま）。
- 宛先（`remote_addr` か `targets`、`balance`、`health_check`）は PATCH で毎回まとめて置き換える（省いた `balance` は round_robin、`health_check` はなし）。一覧の `remote_addr` / `remote_port` は `targets` の先頭（古いクライアント・ログ用）。DB の `options.targets` があれば `dist_addr` / `dist_port` は読まない。
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
- バージョン管理とリリースは docs/RELEASING.md の決まりで、確認を取らずに進める（番号の並びは UI と共有し、両方の動くものが変わったら同じ番号で一緒に、片方だけなら片方だけ出す。UI だけの版は `release.yml` の手動実行で apt に載せる。PR・issue を作るときにパッチ／マイナーのマイルストーンを付ける。マージ後のタグ・リリースノート・マイルストーンの片付けまで行う）。
- PR のブランチに追加で push する前に、その PR がまだ開いているか（`gh pr view <n> --json state`）を確かめる。マージ後に push したコミットは master に入らない（#20/#22、#32 で起きた）。
- 文字列の置き換えでコードを編集するときは、置き換えの対象が 1 件見つかることを確かめる（見つからないまま空振りして、修正が入っていなかったことがある）。

## TLS まわりの約束

- L7 の転送の約束は docs/API.md の「HTTP の転送の扱い」と tests/http_semantics.rs（HTTP/1.1・HTTP/2・HTTP/3 のクライアントで確かめる）。転送の処理を変えたらここに足す。`Host` は `request_authority`（`:authority`・absolute-form が `Host` より先）、HTTP/2・HTTP/3 のヘッダの上限は `MAX_HEADER_SECTION`（64 KiB）、`timeouts.response` は本文を送り終えてから（`until_sent` / `within`）。
- データの完全性（#134）：途中で切れたものを、完全に終わったように見せない。L4 の TCP は、リレーが失敗したら（片方のリセット、書き込めない）両方をリセット（`tcp.rs` の `finish` と `handle` の `reset_on_close`、SO_LINGER 0）。FIN は半分閉じとして伝える。L7 は本文の誤りをそのまま流す（hyper が HTTP/1.1 は接続を切り、HTTP/2 は RST_STREAM）。HTTP/3 は `h3.rs` の `respond` の失敗で `stop_stream`（quinn の SendStream は drop で正常に finish してしまう）。本文を包む型（`compress.rs` の `Compressed` など）は、誤りを `Poll::Ready(None)`（正常な終わり）に変えない。UDP で rproxy が捨てたデータグラムは `stats.dropped`。確かめるのは tests/integrity.rs（転送の処理を変えたらここも回す）。
- L7：HTTP/2・HTTP/3 では、クライアントが `cookie` を複数のフィールドに分けて送れる（Chrome はそうする）。`server.rs` の `Conn::handle` の最初で `join_cookie_fields` が `"; "` で 1 本にまとめる（RFC 9113 §8.2.3 / RFC 9114 §4.2.1。HTTP/1.1 の転送先は Cookie を 1 行しか読まない）。転送先に渡すヘッダは、HTTP/1.1 で意味が変わるものがないか気をつける。
- 証明書ファイルは証明書のストア（`certstore`）が読む。作成・変更で初めて使うとき、SIGHUP、`RPROXY_CERT_CHECK_SECS` ごとの確認で変わっていたときだけ読む（`Registry::reload_changed_tls`、`tls::config::fingerprint`）。同じファイルを使うルールは同じ読み込み結果を共有する。ACME は内蔵しない方針（証明書は外部のツールで取る）。接続ごとには `Runtime.tls`（`RwLock<Arc<TlsRuntime>>`）の複製を使う（接続ごとにファイルを読まない）。
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
