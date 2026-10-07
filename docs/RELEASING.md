English: [RELEASING.md](en/RELEASING.md)

# バージョン管理とリリース

rproxy-api（[max3584/rproxy-api](https://github.com/max3584/rproxy-api)）と UI（[max3584/TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)）は、**バージョン番号をリポジトリごとに別々に進める**（リリースのタグは両者でずれてよい）。
それぞれ、自分の動くものが変わったときだけ、自分の番号を上げて出す。

組み合わせは UI が確かめる。UI は動くのに必要な rproxy-api の最小の版を持ち、各ノードの rproxy-api の版（`GET /capabilities` の `version`。v0.3.18 から）と比べて、古い・分からない・UI が知らない新しいマイナーのときは画面に注意を出す。機能ごとの細かい判断は今までどおり `GET /capabilities` の `features` で行う。UI のリリースノートには、必要な rproxy-api の最小の版を書く。

## バージョンの上げ方

マイナーを頻繁に上げないように、**形（インターフェース）はマイナーでまとめて決め、中身はパッチで順に使えるようにする**。

| 変更 | 上げる桁 | 例 |
|---|---|---|
| 設定ファイル・制御 API・DB（`options` など）の形を足す・変える（1.0 までは破壊的な変更もここ） | マイナー | 0.2.x → 0.3.0 |
| すでに形を決めてある機能の中身を使えるようにする（`GET /capabilities` で使えるかを知らせる） | パッチ | 0.3.0 → 0.3.1 |
| バグの修正、依存の更新（ビルドするものが変わる）、パッケージ・インストーラの改善 | パッチ | 0.3.1 → 0.3.2 |
| README・文書・CI・テストだけの変更 | 上げない | 次にコードが変わるリリースに一緒に入れる |

- **バージョンを上げるのは、動くもの（rproxy-api のバイナリ・ソースコード、UI のコード、パッケージの中身）が変わったときだけ**。README・文書・バッジ・CI・テストだけの変更ではリリースしない（マイルストーンに残し、次のリリースと一緒に出す）。
- マイナーでは、次のしばらくで入れる機能の設定と API の形をまとめて決め、docs/API.md に書く。中身がまだの項目は、`GET /capabilities` で使えないと知らせ、指定されたら `unsupported` で断る。
- 形を変えずに済まない変更が出たら、次のマイナーにまとめる。
- **v0.4.0 は例外**（オーナーの決定、#215）：形を決めたあと中身をパッチで順に出すのではなく、すべての中身をそろえてから 1 回で出す（v0.4.0 の前に途中の版を作らない）。v0.4.0 では `GET /capabilities` の v0.4 の `features` はすべて true で（`features.performance` はすべての項目）、v0.4 の設定で `unsupported` になるものはない。

### v0.4.0 を出す前に確かめること

- リリースの署名の鍵（下の「リリースの署名」）：シークレット `MINISIGN_SECRET_KEY` と変数 `MINISIGN_PUBLIC_KEY` を入れておく。入れずにタグを打つと、v0.4.0 は署名なしで、鍵の入っていないバイナリになる（v0.4.0 のバイナリの自動更新には、ずっと `RPROXY_UPDATE_PUBKEY` が要る）。
- 引き継ぎ（`handoff`）は同じマイナーの中だけなので、v0.3.x から v0.4.0 への .deb の更新は restart になる（`postinst`）。リリースノートにも書く。

## マイルストーン

- 「次のパッチ」（例 v0.2.3）、「次のマイナー」（例 v0.3.0。形を決める作業）、「実装」（例 v0.3.x。中身を使えるようにする作業）を開いておく。
- PR と issue を作るときに、上の表で決めたマイルストーンを付ける。付け忘れた PR には、`.github/workflows/milestone.yml` が一番近いバージョンのマイルストーンを付ける（Renovate の PR も同じ）。
- パッチを出すときは、「実装」のうち済んだものをそのパッチのマイルストーン（例 v0.3.1）に移して出す。
- 環境や管理者の操作を待つ確認作業（実機での確認、アプリの導入など）は、リリースを止めないようにマイルストーンを付けない。
- マイルストーンの中身が全部閉じたらリリースする。終わらなかったものは次のマイルストーンに移す。

## リリースの手順

出すリポジトリだけで行う（もう片方のバージョンは上げない）。

1. **バージョンを上げる PR**（ブランチ `release/vX.Y.Z`）
   - rproxy-api: `Cargo.toml` の `version` と、`Cargo.lock` の rproxy-api の版（`cargo update -p rproxy-api --offline`）。`Cargo.lock` を直し忘れると、`--locked` でビルドする CI とリリースが止まる
   - UI: `npm version X.Y.Z --no-git-tag-version`（`package.json` と `package-lock.json`）。新しい rproxy-api の機能が要るようになったら、必要な rproxy-api の最小の版（UI の `components/version.ts`）も上げる
   - 両方のリポジトリにまたがる変更は、両方で同じ名前のブランチにする（UI の e2e は同じ名前の rproxy-api のブランチがあればそれで、なければ既定ブランチでテストする）
2. **マージされたらリリースする**（`vX.Y.Z`。タグはルールセットで削除・付け替えができないので、打つ前にコミットを確かめる）
   - rproxy-api: タグの push で `release.yml` がバイナリ・.deb を作り、GitHub Release に添付し、apt リポジトリに rproxy-api を載せる。タグと `Cargo.toml` の `version` が違うと止まる
   - UI: `gh release create vX.Y.Z --target <マージコミットの完全な ID>` でタグとリリースを作る。公開すると `release.yml` が `rproxy-ui_X.Y.Z-1_all.deb` を作って添付する。添付されたら、rproxy-api の `release.yml` を手動で実行して apt に載せる（`gh workflow run release.yml -R max3584/rproxy-api -f ui_tag=vX.Y.Z`。rproxy-api はビルドしない）
3. **リリースノート**: そのマイルストーンでマージした PR から、日本語で「主な変更」を書く。UI のリリースノートには、必要な rproxy-api の最小の版（例「rproxy-api v0.3.18 以上」）を書く
4. **マイルストーンを閉じ**、次のパッチのマイルストーンを作る
5. apt で公開されたこと（`apt-cache policy rproxy-api` / `apt-cache policy rproxy-ui` で新しいバージョンが見える）を確かめる

## 再起動なしの更新とパッチ（#174、v0.4 から）

- **同じマイナー（X.Y）の中のパッチは、動いたまま引き継げることを保証する**（docs/UPGRADE.md）。.deb の更新は major.minor が同じなら引き継ぎ（SIGUSR2）、違えば restart。コンテナの自動更新も同じ X.Y の中だけを追う。
- 引き継ぎで渡すもの（ソケットの種類、`handoff.rs` の `State` の形、メッセージ）は**マイナーの中では変えない**（足すときは古い版が知らない項目を読み飛ばせる形で）。形を変えるならマイナーを上げる。同じマイナーの中なら古いパッチに戻すのも同じ引き継ぎで動く。
- **例外のパッチ**（どうしても再起動が要る修正）：`debian/restart-required`（空のファイル）をコミットし、`Cargo.toml` の `assets` に `["debian/restart-required", "usr/share/rproxy-api/", "644"]` を足して出す。`release.yml` の `sign` が `manifest.json` を `"handoff": false` にし（自動更新は入れ替えず次の起動で使う）、.deb の `postinst` は restart する。リリースノートにも「再起動が要る」と書く。次のパッチでは両方を外す。

## リリースの署名（minisign、#174）

`release.yml` の `sign` ジョブが、索引 `releases.json`（すべてのリリースの版。自動更新は最新のリリースのものを読む）を作り、各バイナリと `manifest.json`・`SHA256SUMS`・`releases.json` に minisign の署名（`.minisig`）を付けてリリースに添付する。自動更新は署名を確かめられないものを実行しない。apt の GPG の鍵とは別の鍵（オーナーの決定）。

鍵を作る（手元で 1 回。秘密鍵はリポジトリに置かない）：

```bash
minisign -G -p minisign.pub -s minisign.key      # パスワードを付ける（手元に保管する鍵のファイルを守る）
# minisign -G -W -p minisign.pub -s minisign.key # パスワードなしにするなら -W
```

- **秘密鍵**：`minisign.key` のファイルの中身をそのまま、リポジトリのシークレット **`MINISIGN_SECRET_KEY`** に入れる（`gh secret set MINISIGN_SECRET_KEY -R max3584/rproxy-api < minisign.key`）。手元の `minisign.key` はオフラインの場所に保管する。
- **パスワード**：鍵にパスワードを付けたときは、リポジトリのシークレット **`MINISIGN_PASSWORD`** に入れる（`gh secret set MINISIGN_PASSWORD -R max3584/rproxy-api`、対話で入れる）。`sign` は標準入力でパスワードを渡す。
- **公開鍵**：`minisign.pub` の 2 行目（base64）を、リポジトリの変数 **`MINISIGN_PUBLIC_KEY`** に入れる（`gh variable set MINISIGN_PUBLIC_KEY -R max3584/rproxy-api --body "$(tail -n1 minisign.pub)"`）。リリースのビルドがこれをバイナリに入れ（`RPROXY_RELEASE_PUBKEY`）、`RPROXY_UPDATE_PUBKEY` の既定になる。`minisign.pub` は README・リリースノートにも載せる。
- タグの push の `sign` が失敗したとき（パスワードの入れ忘れなど）は、直してから `gh workflow run release.yml -R max3584/rproxy-api -f sign_tag=vX.Y.Z` で、リリース済みのタグに署名と自動更新のファイルを付け直す（ビルドはしない）。
- シークレットがないときは、`manifest.json`・`SHA256SUMS` を署名なしで添付し、警告を出して進む（自動更新はそのリリースを使わない）。変数がないときは鍵の入っていないバイナリになり、自動更新には `RPROXY_UPDATE_PUBKEY` が要る。
- 鍵を替えるとき：新しい鍵で署名した版を出す前に、古い鍵の入った版から新しい鍵の入った版へは自動更新できない（古い版は新しい鍵の署名を確かめられない）。その切り替えはマイナーの更新（再起動）に合わせるか、利用者に `RPROXY_UPDATE_PUBKEY` で新しい鍵を渡してもらう。
