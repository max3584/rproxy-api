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
- リリースは `v*` タグの push で `.github/workflows/release.yml` が 9 ターゲット向けにクロスビルドする。

## 構成

| ファイル | 役割 |
|---|---|
| `src/main.rs` | 設定（環境変数・`.env`・引数）、ログ初期化、TLS、起動時の DB 復元、制御 API の起動、SIGHUP（トークン・証明書の再読込）と終了処理 |
| `src/api.rs` | axum のルーター。Bearer 認証のミドルウェア。エラーは常に `ApiError` の JSON |
| `src/registry.rs` | 稼働中ルールの唯一の持ち主。作成・変更・削除・一覧・metrics、listener の監視（panic したら `failed`）、名前解決できないルールの再試行 |
| `src/tcp.rs` / `src/udp.rs` | データプレーン。停止は `CancellationToken`、転送先は `watch` で受け取る |
| `src/proxy.rs` | ルールごとの実行時状態 `Runtime`（トークン、watch、統計、`TaskTracker`） |
| `src/resolve.rs` | 名前解決と定期再解決。失敗時は前回の結果（watch の中身）を使い続ける。テスト用に差し替え可能 |
| `src/source.rs` | PROXY protocol v1/v2 ヘッダ、`IP_TRANSPARENT` ソケット、その可否の判定 |
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

## 注意点

- `transparent` は Linux・IPv4・`CAP_NET_ADMIN` が前提で、ポリシールーティングの設定も要る（README）。`scripts/test-transparent.sh` で名前空間の中の実経路では確認済み。README の iptables を使う手順は未検証。
- DB からの復元（`src/db.rs`）は MariaDB 11.4 で確認済み。テーブルが古く `source_ip` / `udp_idle_secs` 列がない場合は、既定値で読み込む。
- 空の環境変数（`RPROXY_DATABASE_URL=` など）は未設定として扱う（`main` で clap に渡す前に取り除く）。
- 派生元のコードに由来するファイルには帰属コメントが付いている。MIT ライセンスの表記は残すこと。
