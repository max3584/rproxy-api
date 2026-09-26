# Debian パッケージと apt リポジトリ

## パッケージの中身

`cargo deb` で作る（設定は `Cargo.toml` の `[package.metadata.deb]`、スクリプトとユニットは `debian/`）。
リリースでは musl で静的リンクしたバイナリを使うので、Debian / Ubuntu のどのリリースでも同じパッケージが動く。

| パス | 内容 |
|---|---|
| `/usr/bin/rproxy-api` | 本体 |
| `/usr/lib/systemd/system/rproxy-api.service` | ユニット（`contrib/rproxy-api.service` と同じ内容で、`ExecStart` だけ `/usr/bin`） |
| `/etc/rproxy/rproxy.env` | 設定（conffile。アップグレードで書き換えた内容は保たれる） |
| `/etc/rproxy/tokens` | API のトークン。初回のインストール時に 1 つ生成する（`root:rproxy`、640） |
| `/var/log/rproxy/` | ログ（`rproxy.<日付>.log`、JSON Lines）。rproxy が日ごとに分け、`RPROXY_LOG_KEEP` を超えた古いものを消すので logrotate は不要 |
| `/usr/share/doc/rproxy-api/` | README、API.md、PROFILES.md、固定ルールの例 |

- インストール時に `rproxy` システムユーザーを作る。サービスはこのユーザーで動き、ユニットが `CAP_NET_BIND_SERVICE`（1024 未満のポート）と `CAP_NET_ADMIN`（`source_ip: transparent`）を与える（docs/PERMISSIONS.md）。
- インストールしただけでは有効にも起動にもしない（設定前に API が上がらないように）。`systemctl enable --now rproxy-api` で起動する。
- アップグレードでは、動いていれば再起動する（`try-restart`）。トークンと設定は変えない。
- `apt purge` で `/etc/rproxy/tokens`、`/etc/rproxy/`、`/var/log/rproxy/` を消す。`rproxy` ユーザーは残す。
- ログを journald（`journalctl -u rproxy-api`）に出すなら、`rproxy.env` の `RPROXY_LOG_FILE` の行をコメントにする。
- `source_ip: transparent` の戻りのパケットのポリシールーティングは、`scripts/install.sh --transparent-clients ... --transparent-iface ...` で入れられる（README の「送信元 IP の引き渡し」）。

CI の `Debian package` ジョブ（`scripts/test-deb.sh`）が、実際にインストール・起動・署名つきリポジトリからの再インストール・purge までを確かめる。

## リポジトリ

`v*` のタグを push すると `.github/workflows/release.yml` が次を行う。

1. 各ターゲットのバイナリと、amd64 / arm64 / armhf の `.deb` を作って GitHub Release に添付する（タグと `Cargo.toml` の `version` が違うと止まる）
2. `scripts/apt-repo.sh` で `.deb` を `gh-pages` ブランチの apt リポジトリに足し、索引（`dists/stable/`）を署名し直して push する

`https://max3584.github.io/rproxy-api/` を GitHub Pages が配る。構成は次のとおり。

```
pool/main/r/rproxy-api/rproxy-api_<version>_<arch>.deb   過去のバージョンも残す
dists/stable/main/binary-{amd64,arm64,armhf}/Packages{,.gz}
dists/stable/{Release,InRelease,Release.gpg}
rproxy-archive-keyring.gpg                                signed-by= に使う公開鍵
```

同じバージョンのパッケージを中身を変えて出し直すことはできない（`apt-repo.sh` が止める）。直すときはバージョンを上げる。

packaging のファイル（`debian/`、`Cargo.toml`、`release.yml`、`apt-repo.sh`）を変える PR では、release.yml が公開せずにビルドとパッケージの作成だけを行う。

## 初回の準備（リポジトリの管理者が 1 回だけ）

### 1. 署名用の鍵を作り、GitHub の Secrets に登録する

パスフレーズなしの署名専用の鍵を作る（CI が対話なしで署名するため）。秘密鍵は Secrets 以外に置かない。

```shell
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key 'rproxy-api apt repository <max3584.work@gmail.com>' ed25519 sign never
KEY_ID=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
gpg --armor --export-secret-keys "$KEY_ID" | gh secret set APT_GPG_PRIVATE_KEY -R max3584/rproxy-api
gh secret set APT_GPG_KEY_ID -R max3584/rproxy-api --body "$KEY_ID"
# 失くしたときに困らないよう、秘密鍵をオフラインで保管してから消す
gpg --armor --export-secret-keys "$KEY_ID" > rproxy-apt-signing-key.asc
rm -rf "$GNUPGHOME"
```

Secrets がなければ、release.yml は apt リポジトリの更新だけを飛ばす（警告を出す）。

### 2. 最初のリリースの後で GitHub Pages を有効にする

`gh-pages` ブランチは最初のリリースで作られる。その後で 1 回だけ実行する。

```shell
gh api -X POST repos/max3584/rproxy-api/pages -f 'source[branch]=gh-pages' -f 'source[path]=/'
```

### 鍵を替えるとき

新しい鍵を Secrets に登録してタグを打つと、索引と `rproxy-archive-keyring.gpg` が新しい鍵に替わる。
使っている側は `rproxy-archive-keyring.gpg` を取り直すまで `apt update` が署名エラーになる。

## 手元で試す

```shell
cargo deb                                   # target/debian/rproxy-api_<version>-1_amd64.deb
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase '' --quick-gen-key 'test <test@example.invalid>' ed25519 sign never
scripts/apt-repo.sh /tmp/apt-repo target/debian/*.deb
python3 -m http.server 8000 -d /tmp/apt-repo
```

`scripts/test-deb.sh` はインストールとアンインストールを実際に行うので、rproxy-api を本番で動かしている機械では実行しない。
