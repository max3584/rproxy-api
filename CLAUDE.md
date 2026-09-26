# CLAUDE.md — rproxy-api

稼働中に TCP/UDP の転送を追加・変更・削除・問い合わせできる L4 フォワーダ（Rust / tokio / axum）。glacierx/rproxy のフォーク。
管理 UI は別リポジトリ `../TCP-UDP-rproxy-ui`（Next.js）で、HTTP API で操作する。

## コマンド

```bash
cargo build
cargo test                    # 単体テスト + tests/api.rs（loopback で実ソケットを使う結合テスト）
cargo clippy --all-targets
scripts/test-transparent.sh   # transparent の実経路テスト（root 不要、名前空間を使う。cargo build の後）
cargo run                     # 設定は環境変数 RPROXY_* か .env（.env.example を参照）
```

- 設定項目は `src/main.rs` の `Options`（clap）。すべて `RPROXY_*` 環境変数でも指定でき、起動時に `.env` を読む。項目を増やすときは `.env.example` と README の表も更新する。

- ring（rustls）のビルドには C コンパイラが要る。
- リリースは `v*` タグの push で `.github/workflows/release.yml` が 9 ターゲット向けにクロスビルドし、amd64 / arm64 / armhf の `.deb`（musl の静的リンク）を作って `gh-pages` の apt リポジトリに載せる。タグと `Cargo.toml` の `version` を揃えること。詳細は `docs/APT.md`。
- `scripts/install.sh` は VM 向けのインストーラ（root・systemd が前提。Debian / Ubuntu は apt、それ以外はリリースのバイナリ）。設定の雛形は `debian/rproxy.env` と `contrib/rproxy-api.service` を使う（チェックアウトから実行したときは手元のもの、curl で実行したときは GitHub のもの）。CI の `install.sh` ジョブ（`scripts/test-install.sh`）で実際に入れて確かめる。
- パッケージ（`debian/`、`[package.metadata.deb]`）を変えたら `cargo deb` で作り、CI の `Debian package` ジョブ（`scripts/test-deb.sh`。sudo でインストールするので手元では実行しない）で確かめる。`debian/rproxy-api.service` は `contrib/rproxy-api.service` と `ExecStart` 以外を揃える。

## 構成

| ファイル | 役割 |
|---|---|
| `src/main.rs` | 設定（環境変数・`.env`・引数）、ログ初期化、TLS、起動時の DB 復元、制御 API の起動、SIGHUP（トークン・証明書の再読込）と終了処理 |
| `src/api.rs` | axum のルーター。Bearer 認証のミドルウェア。エラーは常に `ApiError` の JSON |
| `src/registry.rs` | 稼働中ルールの唯一の持ち主。作成・変更・削除・一覧・metrics、listener の監視（panic したら `failed`）、名前解決できないルールの再試行 |
| `src/tcp.rs` / `src/udp.rs` | データプレーン。停止は `CancellationToken`、転送先は `watch` で受け取る |
| `src/proxy.rs` | ルールごとの実行時状態 `Runtime`（トークン、watch、統計、`TaskTracker`） |
| `src/resolve.rs` | 名前解決と定期再解決。失敗時は前回の結果（watch の中身）を使い続ける。テスト用に差し替え可能 |
| `src/source.rs` | PROXY protocol v1/v2 ヘッダ（v2 は TLS の TLV つき）、`IP_TRANSPARENT` ソケット、その可否の判定 |
| `src/cidr.rs` | `allow_from` の CIDR（IPv4-mapped IPv6 も IPv4 として扱う） |
| `src/tlsconf.rs` | `tls` の設定の型と検証、証明書・鍵・CA の読み込み、SNI での証明書の選択、rustls / webrtc-dtls の設定の組み立て（`TlsRuntime`） |
| `src/sni.rs` | ClientHello からサーバ名を読む（`tls.mode: sni`。読んだバイトは転送先へそのまま送る） |
| `src/starttls.rs` | SMTP / IMAP / POP3 の STARTTLS 前のやり取りと、TLS 後の転送先の挨拶の読み捨て |
| `src/dtls.rs` | 共有の UDP ソケットから 1 クライアント分のデータグラムを webrtc-dtls に渡す `Conn` |
| `src/rule.rs` | ルールの型と検証 |
| `src/auth.rs` | トークンファイル（複数トークン同時有効、再読込） |
| `src/db.rs` | 起動時に `forward_rules` を読む（sqlx / mysql） |
| `src/logging.rs` | tracing の JSON Lines 出力（日次ローテーション） |

## 制御 API（UI との契約）

`docs/API.md` が正。ルールのキーは `(protocol, listen_addr, listen_port)`。
形を変えるときは UI 側の `components/rproxy.ts` と、テーブル定義（UI リポジトリの `db/`）も合わせて変える。

## 設計上の約束

- ルールの状態は `Registry` だけが持つ。タスクの `JoinHandle` を捨てない。
- 停止は `stop`（受け付け停止）→ 任意の drain → `kill`（既存接続の切断）の順。`delete` は listener が閉じ、全接続が終わってから返る。
- 転送先の変更は `watch` 経由。TCP は新しい接続から、UDP は既存のセッションも切り替わる。
- データプレーンのタスクで `unwrap()` / `panic!` を使わない。万一 panic しても、監視タスクがそのルールだけを `failed` にする。
- ログは `event` フィールドで種類を分ける（一覧は README）。

## アクセス制御と固定ルール

- `allow_from` は受け付けた直後（TLS や PROXY ヘッダより前）に確かめる。UDP は範囲外のデータグラムを捨てる。拒否は `stats.denied` に数え、`conn.denied` をログに出す。
- `tls.unmatched: reject` の `terminate` は、`LazyConfigAcceptor` で ClientHello を読んでから判断する（一致しない名前には証明書を返さない）。
- 固定ルール（`origin: static`）は `Registry::load_static` で起動時に作る。API からの変更・削除は `409 static`。`shutdown` だけは止める。
- 文字列の置き換えでコードを編集するときは、置き換えの対象が 1 件見つかることを確かめる（見つからないまま空振りして、修正が入っていなかったことがある）。

## TLS まわりの約束

- 証明書ファイルは作成・変更・SIGHUP のときだけ読む。接続ごとには `Runtime.tls`（`RwLock<Arc<TlsRuntime>>`）の複製を使う。
- STARTTLS では、STARTTLS への応答より前に届いた余分なデータを受け付けない（コマンドの紛れ込み対策）。
- WebRTC のメディア（DTLS-SRTP）は終端できない（SDP のフィンガープリントに結びついているため）。docs/PROFILES.md に書いてあるとおり passthrough で流す。
- 設定の例と用途別の推奨は `docs/PROFILES.md`。UI のプロファイルもこれに合わせる。

## 注意点

- `transparent` は Linux・IPv4・`CAP_NET_ADMIN` が前提で、ポリシールーティングの設定も要る（README）。`scripts/test-transparent.sh` で名前空間の中の実経路では確認済み。README の iptables を使う手順は未検証。
- DB からの復元（`src/db.rs`）は MariaDB 11.4 で確認済み。テーブルが古く `source_ip` / `udp_idle_secs` 列がない場合は、既定値で読み込む。
- 空の環境変数（`RPROXY_DATABASE_URL=` など）は未設定として扱う（`main` で clap に渡す前に取り除く）。
- 派生元のコードに由来するファイルには帰属コメントが付いている。MIT ライセンスの表記は残すこと。
