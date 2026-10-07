English: [BACKUP.md](en/BACKUP.md)

# バックアップと復旧

rproxy-api と管理 UI（[TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)）の、何を・どう取って・どう戻すか。
パスは .deb（apt）と `scripts/install.sh` で入れたときの既定です。違う場所にしていれば読み替えてください。

## 何を取るか

| 対象 | 場所 | 中身・注意 |
|---|---|---|
| rproxy の環境変数ファイル | `/etc/rproxy/rproxy.env` | `RPROXY_*` の設定。`RPROXY_DATABASE_URL` を書いていれば DB のパスワードを含む |
| トークンファイル | `/etc/rproxy/tokens`（`RPROXY_TOKEN_FILE`） | 1 行 1 トークン（平文）か、名前・SHA-256・スコープの YAML（docs/API.md）。平文の形式ならそのまま API の鍵 |
| 設定ファイル（固定ルール） | `RPROXY_CONFIG` のファイルかディレクトリ（例 `/etc/rproxy/rproxy.yaml`） | `version`・`global`・`rules`。固定ルールは DB に入らないので、ここにしかない |
| 設定ファイルが指すファイル | 設定ファイル・ルールに書いたパス | 証明書・鍵・CA（`cert_file`・`chain_file`・`key_file`・`ca_file`）、`basic_auth` の `users_file`、`oidc` などの秘密のファイル、CrowdSec の `api_key_file` |
| 制御 API の証明書と鍵 | `RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`（例 `/etc/rproxy/tls/`） | 制御 API を TLS で開いているときだけ |
| UI で作ったルールの TLS の証明書 | DB の `options` に書いたパス | DB にあるのはパスだけ。ファイルは別に取る |
| certbot などの証明書 | 例 `/etc/letsencrypt/` | 取り直せるが、移すなら更新の設定ごと取る |
| transparent のポリシールーティング | `/etc/rproxy/transparent-routing.conf`、`/usr/local/sbin/rproxy-transparent-routing`、`/etc/systemd/system/rproxy-transparent-routing.service` | `install.sh --transparent-*` で入れたときだけ |
| systemd の上書き | `/etc/systemd/system/rproxy-api.service.d/`（`systemctl edit` の drop-in）、`install.sh` で入れたときは `/etc/systemd/system/rproxy-api.service` も | 権限（capability）を変えていれば必要 |
| UI の DB | MariaDB の `forward_rules`（ルール）、`forward_rules_log`（変更の履歴） | UI で作ったルールの正はここ。テーブルの定義は UI リポジトリの `db/schema.sql` |
| UI の環境変数ファイル | `/etc/rproxy-ui/rproxy-ui.env`（600） | `NEXTAUTH_SECRET`、`KEYCLOAK_CLIENT_SECRET`、`DB_PASSWORD`、`RPROXY_API_TOKEN` を含む |
| ログ（任意） | `/var/log/rproxy/`（`RPROXY_LOG_FILE`。日ごとに `rproxy.<日付>.log`、`RPROXY_LOG_KEEP` 個を超えると消える）、`global.access_log` のファイル | 動かすのには要らない。調査・監査のために残すなら取る |

取らなくてよいもの：

- `/run/rproxy/`（`RPROXY_API_SOCKET` の Unix ソケット）。ユニットの `RuntimeDirectory=rproxy` で起動のたびに作り直される
- バイナリとパッケージの中身（`/usr/bin/rproxy-api`、`/usr/lib/rproxy-ui` など）。入れ直せばよい。戻すときは同じ版か新しい版を入れる
- API を直接呼んで作ったルール（`origin: dynamic` だが DB にないもの）。rproxy のメモリにしかなく、再起動で消える一時的なもの（docs/API.md の「API・設定ファイル・UI（DB）の関係」）。残すなら下の「`GET /rules` の控え」で取る

## 取り方

### DB

`--single-transaction` で、テーブルをロックせずに一貫した時点の内容を取ります（両テーブルは InnoDB）。

```bash
mariadb-dump --single-transaction --default-character-set=utf8mb4 \
  -h 127.0.0.1 -u rproxy_backup -p rproxy forward_rules forward_rules_log \
  | gzip > rproxy-db-$(date +%Y%m%d-%H%M%S).sql.gz
```

- データベース名は UI の `DB_DATABASE`（既定 `rproxy`）に合わせる
- 出力には `DROP TABLE IF EXISTS` と `CREATE TABLE` が入るので、戻すときに先にテーブルを作らなくてよい
- バックアップ用のユーザーは読むだけでよい。UI のユーザー（`rproxy_ui`）や rproxy のユーザー（`rproxy`、`forward_rules` の `SELECT` だけ）とは分ける

```sql
CREATE USER 'rproxy_backup'@'localhost' IDENTIFIED BY '<password>';
GRANT SELECT, LOCK TABLES ON rproxy.* TO 'rproxy_backup'@'localhost';
```

パスワードはコマンドラインに書かず、root だけが読めるファイルに置きます。

```ini
# /etc/rproxy-backup/my.cnf（root:root 600）
[client]
host=127.0.0.1
user=rproxy_backup
password=<password>
```

### 設定ファイル・鍵・トークン

```bash
sudo tar -C / -czpf rproxy-etc-$(date +%Y%m%d-%H%M%S).tar.gz \
  etc/rproxy etc/rproxy-ui etc/systemd/system/rproxy-api.service.d
```

`etc/rproxy-ui` や drop-in のディレクトリがないホストでは、ないものを外します（`tar` はないパスで失敗します）。
`/etc/rproxy` の外に置いた証明書・秘密のファイル（`/etc/letsencrypt` など）も、同じ `tar` に足します。

### `GET /rules` の控え（任意）

rproxy が今動かしているルールの一覧です。戻すときの比較と、DB を使えないときに rproxy だけで動かす（下）ための材料になります。

```bash
TOKEN=$(grep -v -e '^#' -e '^[[:space:]]*$' /etc/rproxy/tokens | head -n1 | tr -d '[:space:]')
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules > rproxy-rules-$(date +%Y%m%d-%H%M%S).json
# Unix ソケット（RPROXY_API_SOCKET）なら
curl -fsS --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" http://localhost/rules > rules.json
```

- トークンの 1 行目を使うのは平文の形式のときだけ。YAML の形式（`tokens:`）はファイルに SHA-256 しかないので、`rules:read` のスコープのトークン（UI の `RPROXY_API_TOKEN` など）を使う
- ポートは `RPROXY_API_PORT`（インストール時に使用中なら 8081〜8099 にずれている）

UI の「エクスポート（JSON）」（UI の README の「エクスポートとインポート」）も、ルールの控えとして使えます。停止中のルールも含み、UI の「インポート」でそのまま戻せます。

### systemd の timer で毎日取る

例です。パス・データベース名・保存の日数は環境に合わせてください。

```sh
#!/bin/sh
# /usr/local/sbin/rproxy-backup（root:root 700）
set -eu
umask 077
dest=/var/backups/rproxy
stamp=$(date +%Y%m%d-%H%M%S)
install -d -m 0700 "$dest"

# DB（UI のルールと変更の履歴）
mariadb-dump --defaults-extra-file=/etc/rproxy-backup/my.cnf \
  --single-transaction --default-character-set=utf8mb4 \
  rproxy forward_rules forward_rules_log | gzip > "$dest/db-$stamp.sql.gz"

# 設定ファイル・トークン・鍵（あるものだけ）
set --
for p in etc/rproxy etc/rproxy-ui etc/systemd/system/rproxy-api.service.d etc/letsencrypt; do
  [ -e "/$p" ] && set -- "$@" "$p"
done
tar -C / -czpf "$dest/etc-$stamp.tar.gz" "$@"

# 30 日より古いものを消す
find "$dest" -type f -mtime +30 -delete
```

```ini
# /etc/systemd/system/rproxy-backup.service
[Unit]
Description=Back up rproxy-api and rproxy-ui
After=mariadb.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rproxy-backup
```

```ini
# /etc/systemd/system/rproxy-backup.timer
[Unit]
Description=Daily backup of rproxy-api and rproxy-ui

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now rproxy-backup.timer
sudo systemctl start rproxy-backup.service   # 一度動かして確かめる
journalctl -u rproxy-backup.service
```

同じホストに置いただけでは、ホストが壊れたときに一緒に失われます。暗号化して（下の「安全のために」）別の場所へ送ってください。

## 戻す順番

新しく入れ直したホスト（または同じホスト）に戻す順番です。

1. **パッケージを入れる**：rproxy-api と rproxy-ui（README の「インストール」）。同じ版か新しい版にする。インストールで `rproxy` / `rproxy-ui` のユーザーができる（`tar` は所有者を名前で戻すので、先にユーザーが要る）。まだ起動しない
2. **設定ファイル・トークン・鍵を戻す**：

   ```bash
   sudo systemctl stop rproxy-api rproxy-ui 2>/dev/null || true
   sudo tar -C / -xzpf rproxy-etc-<日時>.tar.gz
   sudo chgrp rproxy /etc/rproxy /etc/rproxy/tokens && sudo chmod 0750 /etc/rproxy && sudo chmod 0640 /etc/rproxy/tokens
   sudo systemctl daemon-reload
   ```

   インストールで作られたトークンと環境変数ファイルは、戻したもので上書きされます（UI の `RPROXY_API_TOKEN` と rproxy のトークンがそのまま合う）。
   証明書・鍵・秘密のファイルは `rproxy` のユーザーが読めること（グループ `rproxy` で読めるなど）
3. **DB を戻す**：

   ```bash
   sudo mariadb -e "CREATE DATABASE IF NOT EXISTS rproxy CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
   gunzip -c rproxy-db-<日時>.sql.gz | sudo mariadb rproxy
   ```

   DB のユーザー（UI の `rproxy_ui`、rproxy の `rproxy`）と権限は、ダンプに入っていないので作り直す（UI リポジトリの `db/README.md` の「DB ユーザー」）。
   新しい版の UI に古いダンプを戻したときは、足りない migration を順に流す（`/usr/share/rproxy-ui/db/migrations/`、`db/README.md`）
4. **rproxy の設定を確かめる**：`sudo -u rproxy-api rproxy-api --check-config`（下の「戻した後の確認」）
5. **rproxy-api を起動する**：`sudo systemctl enable --now rproxy-api`。起動時に DB の `forward_rules` からルールを復元する
6. **rproxy-ui を起動する**：`sudo systemctl enable --now rproxy-ui`
7. **確かめる**（下）

rproxy-api は DB より先に起動しても止まりません（DB のルールなしで起動し、ログに `restore.error`）。その場合は DB を戻してから `sudo systemctl restart rproxy-api` で読み直させます。

## 戻した後の確認

### 設定ファイル

```bash
sudo -u rproxy-api rproxy-api --check-config /etc/rproxy/rproxy.yaml
```

起動時・再読み込みと同じ検証（書式、ルールの値、待ち受けの重なり、証明書・鍵・CA のファイルと期限、秘密のファイル）をして、問題がなければ 0 で終わります。
`rproxy` のユーザーで実行すると、そのユーザーが読めないファイルも分かります（root で実行すると、読めないかもしれないファイルを所有者とモードから警告します）。
引数を省くと `RPROXY_CONFIG` のファイルを確かめます（`/etc/rproxy/rproxy.env` は systemd が読むファイルなので、手で実行するときは `--check-config` にパスを渡すのが確実です）。

### ログ

```bash
journalctl -u rproxy-api -b | grep -E '"event":"(restore\.[a-z_]+|degraded)"'
# RPROXY_LOG_FILE を使っているなら
grep -hE '"event":"(restore\.[a-z_]+|degraded)"' /var/log/rproxy/rproxy.*.log
```

- `restore.start`（`rules` に DB から読んだ数）が出ていること
- `restore.error`（DB に接続できない）、`restore.skip`（読めない行）、`restore.legacy_schema`（列が足りない古いテーブル）、`degraded`（使えない部分。`part` に箇所）がないこと
- `restore.paused` は UI で停止中のルールの数（起動しないのが正しい）

### `GET /rules` と DB を比べる

rproxy が動かしている UI のルール（`origin: dynamic`）と、DB の `forward_rules`（停止中のものを除く）が同じキーの集まりになっていることを確かめます。

```bash
TOKEN=...   # 上の「GET /rules の控え」と同じ
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules \
  | jq -r '.[] | select(.origin == "dynamic") | "\(.protocol)\t\(.listen_addr)\t\(.listen_port)"' | sort > api.tsv
sudo mariadb -N -B rproxy -e "SELECT protocol, src_addr, src_port FROM forward_rules
  WHERE COALESCE(JSON_VALUE(options, '$.enabled'), 'true') <> 'false'" | sort > db.tsv
diff db.tsv api.tsv && echo "一致"

# 動いていないルール（理由つき）
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules \
  | jq -r '.[] | select(.state == "failed") | "\(.protocol) \(.listen_addr):\(.listen_port) \(.error)"'
```

- `db.tsv` にだけある行：DB にあるが rproxy にないルール。`failed` ではなく一覧にもなければ、`restore.skip` のログを見る。UI では「未登録」（missing）と出る
- `api.tsv` にだけある行：API を直接呼んで作ったルール（DB にない）
- `failed` の理由が `bind_failed` なら、待ち受けのアドレスがこのホストにないか、ポートが使用中（新しいホストに移したときは下を参照）
- UI からも、一覧の状態と「変更の履歴」が戻っていることを見る

## 新しいホストへ移す

1. 古いホストで最新のバックアップを取る（UI での変更を止めてから取ると、取り漏れがない）
2. 新しいホストに上の「戻す順番」で戻す
3. ホストが変わると変わるものを直す：
   - **待ち受けのアドレス**：`listen_addr` に古いホストの IP を書いたルールは `bind_failed` になる。`GET /interfaces` で使えるアドレスを見て、UI（DB のルール）と設定ファイル（固定ルール）を直す。`0.0.0.0` / `::` のルールはそのまま動く
   - **DB の場所**：`RPROXY_DATABASE_URL`（`/etc/rproxy/rproxy.env`）と UI の `DB_HOST`。DB のユーザーのホストの部分（`'rproxy'@'127.0.0.1'` など）
   - **制御 API**：`RPROXY_API_ADDR` に古い IP を書いていれば直す。UI の `RPROXY_API_URL`
   - **UI の URL**：変わるなら `NEXTAUTH_URL` と、Keycloak の Valid redirect URIs（`${NEXTAUTH_URL}/api/auth/callback/keycloak`）
   - **transparent**：ポリシールーティングはホストごとの設定。`install.sh --transparent-*` で入れ直すか、戻した `transparent-routing.conf` のインターフェース名を確かめる（docs/TRANSPARENT.md）。転送先からの戻りの経路も新しいホストを通るようにする
   - **証明書**：certbot などの更新の設定ごと移すか、新しいホストで取り直す。DNS の向き先を変えるまで http-01 では取れない
   - **ファイアウォール・DNS**：待ち受けのポートを開け、名前を新しいホストに向ける
4. 待ち受けの IP をそのまま引き継ぐ（同じ IP を新しいホストに付け替える）なら、古いホストの rproxy-api を止めてから新しいホストのものを起動する（同じアドレスでは片方しか待ち受けられない）
5. 「戻した後の確認」をする

## DB を使えないとき、rproxy だけで動かす

- **動いている rproxy はそのまま動き続けます**。rproxy が DB を読むのは起動時だけなので、DB が壊れても今のルールは止まりません。DB を直すまで rproxy-api を再起動しないのが一番安全です（UI からの変更はできません）
- DB に接続できないまま起動すると、DB のルールなしで起動します（`restore.error`。固定ルールと制御 API は動く）

再起動が要るときは、今のルール（または控えの `GET /rules`）を設定ファイルに書き出して、固定ルールとして動かせます。

```bash
TOKEN=...
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules > rules.json
jq '{version: 1, rules: [.[] | select(.origin == "dynamic")
      | del(.origin, .state, .error, .resolved, .connections, .stats, .started_at, .cert_status)
      | if has("targets") or has("http") then del(.remote_addr, .remote_port) else . end]}' \
  rules.json > from-db.json
sudo install -o root -g rproxy -m 0640 from-db.json /etc/rproxy/from-db.json
sudo -u rproxy-api rproxy-api --check-config /etc/rproxy/from-db.json
```

- `jq` は稼働情報（`state`・`stats` など）を落とし、宛先が複数のルールと L7（`http`）のルールでは一覧用の `remote_addr` / `remote_port` を落とす（`targets` と一緒には受け付けないため）
- `/etc/rproxy/rproxy.env` で `RPROXY_CONFIG=/etc/rproxy/from-db.json` にし、`RPROXY_DATABASE_URL` をコメントにして `sudo systemctl restart rproxy-api`
- すでに `RPROXY_CONFIG` で固定ルールを使っているなら、ディレクトリ（例 `/etc/rproxy/conf.d/`。中のファイルを名前の順に読む）にして、そこに `from-db.json` を置く。キーが重なるルールは誤りになる
- UI のエクスポート（JSON）の `rules` の中身からも作れる（停止中のルールと `enabled` を除く。UI の README の「エクスポートとインポート」）
- この間のルールは固定ルール（`origin: static`）なので、API・UI からは変えられない（`409 static`）。変えるときはファイルを書き換える（自動で反映）

DB を直したら、`RPROXY_CONFIG` を元に戻し（`from-db.json` を外す）、`RPROXY_DATABASE_URL` を戻して `sudo systemctl restart rproxy-api`。
同じキーのルールが設定ファイルと DB の両方にあると、DB のほうが起動できないので、必ず先に `from-db.json` を外します。その後「`GET /rules` と DB を比べる」で確かめます。

## 安全のために

- バックアップには API のトークン（平文の形式なら API の鍵そのもの）、TLS の秘密鍵、DB・Keycloak のパスワード、`NEXTAUTH_SECRET` が入る。本番と同じく扱う
- 置き場所は root だけが読めるようにする（上のスクリプトは `umask 077` と 0700 のディレクトリ）
- ホストの外に送る前に暗号化する。例（[age](https://github.com/FiloSottile/age) の公開鍵で。秘密鍵はバックアップと別の場所に置く）：

  ```bash
  age -R /etc/rproxy-backup/recipients.txt -o etc-<日時>.tar.gz.age etc-<日時>.tar.gz
  # gpg なら
  gpg --encrypt --recipient backup@example.com etc-<日時>.tar.gz
  ```

- 戻した後の権限：`/etc/rproxy` は `root:rproxy` の 0750、`/etc/rproxy/tokens` は `root:rproxy` の 0640、`/etc/rproxy/rproxy.env` は 0640、`/etc/rproxy-ui/rproxy-ui.env` は `root:root` の 0600（パッケージのインストール時と同じ）。秘密鍵は `rproxy` が読める最小の権限（例 `root:rproxy` の 0640）
- トークンは YAML の形式（SHA-256 だけを書く）にすると、トークンファイルのバックアップが漏れても API の鍵にはならない（docs/API.md）。UI の `RPROXY_API_TOKEN` は平文なので、UI の環境変数ファイルは別に守る
- バックアップが漏れたかもしれないときは、トークン（ファイルを書き換えて `systemctl reload rproxy-api`）、DB のパスワード、Keycloak のクライアントシークレット、TLS の鍵を取り替える
- 戻す手順は、実際に別のホストで試しておく（取れているつもりで取れていないことがある）
