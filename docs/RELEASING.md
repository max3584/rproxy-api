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
