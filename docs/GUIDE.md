English: [GUIDE.md](en/GUIDE.md)

# 設定と運用の手引き

この手引きは、rproxy-api を入れて TCP・UDP・HTTP の転送を作り、それを日々運用していくための説明書です。Linux とネットワークの基本（systemd、ポート、TLS の証明書、CIDR）は知っているけれど、rproxy は初めて、という運用者を読み手に想定しています。やりたいことごとに、そのまま貼って使える設定の例と、うまくいったかを確かめるコマンドを載せています。

rproxy-api は、受けた接続やデータグラムを決まった転送先へ中継するプロキシです。何をどこへ中継するかの決まりを **ルール** と呼びます。ルールは、設定ファイルに書くことも、動いている rproxy に HTTP の **制御 API** で送ることもできます。この 2 つの入れ方の違いが、この手引きを読むうえでいちばん大切なところなので、最初の [この手引きの地図](#この手引きの地図) で説明します。

関連する文書は次のとおりです。

- 項目の正確な意味と細かい動きは [API.md](API.md) が正です。この手引きでは、長くなる話は API.md の節へのリンクにしています。
- 用途別の設定の例は [PROFILES.md](PROFILES.md)、送信元 IP の渡し方は [SOURCE-IP.md](SOURCE-IP.md)、ファイルの権限は [PERMISSIONS.md](PERMISSIONS.md)、ACME は [ACME.md](ACME.md)、再起動なしの更新は [UPGRADE.md](UPGRADE.md)、バックアップは [BACKUP.md](BACKUP.md) にあります。

例のアドレス・名前・パスは自分の環境に合わせて書き換えてください。例のアドレスは、文書のために予約されたもの（`192.0.2.0/24`・`198.51.100.0/24`・`203.0.113.0/24`・`2001:db8::/32`）と、私用のもの（`10.0.0.0/8` など）です。例の YAML は `rproxy-api --check-config` に通る形にしてあります。

## この手引きの地図

### ルールの 2 つの入れ方

rproxy-api のルールには、入れ方が 2 つあります。どちらで入れても、ルールの形（書ける項目と意味）は同じです。違うのは、誰がルールを持ち、どう変え、再起動の後にどうなるかです。

| | 設定ファイルで書く | 制御 API で作る |
|---|---|---|
| 書く場所 | `RPROXY_CONFIG` が指す YAML / JSON のファイル | 動いている rproxy の HTTP の API（`POST /rules` など） |
| できるルールの呼び名 | **固定ルール**（static。表示の `origin` は `static`） | **動的なルール**（dynamic。`origin` は `dynamic` か `api`） |
| 変え方 | ファイルを書き換えます。rproxy が自動で読み直します | API で `PATCH`・`DELETE` するか、ルールの組を `PUT` します |
| 再起動の後 | ファイルからもう一度作ります | 保存の仕方によります（[10.1](#101-api-で作ったルールを残す)） |
| 向いている使い方 | 運用者が手で決める、あまり変わらない構成 | 管理 UI、CI、Kubernetes のコントローラなどの自動化 |

設定ファイルの方は、nginx や HAProxy の設定ファイルと同じように考えて構いません。ファイルが正で、API からは変えられません。制御 API の方は、ほかのプログラムが rproxy を操作するための口です。管理 UI（[TCP-UDP-rproxy-ui](https://github.com/max3584/TCP-UDP-rproxy-ui)）も、この API でルールを作っています。

2 つは同じ rproxy の中で一緒に使えます。たとえば、管理 UI そのものを公開するルールは消えては困るので設定ファイルに書き、日々のルールは UI から作る、という分け方ができます。ただし、同じ待ち受け（プロトコル・アドレス・ポート）のルールはどちらか一方にしか作れません。設定ファイルのルールの待ち受けに API から HTTP のルートなどを足したいときは、**重ねる分**（overlay）という別の仕組みを使います（[2.4](#24-設定ファイルと-api-の違い)）。

### 読む人ごとの道すじ

全部を順に読む必要はありません。自分の使い方に合う行の章から読んでください。

| 読む人 | まず読む章 | 必要になったら読む章 |
|---|---|---|
| 設定ファイルだけで運用する人 | [1.](#1-インストールと起動)、[2.1〜2.2](#21-設定ファイルで書く)、[3.〜6.](#3-l4-の転送udpポート範囲複数の宛先)（ルールの中身）、[9.1](#91-設定ファイルを読み直す) | [7.](#7-守りトークンcrowdsecgeoipファイル)、[8.](#8-global-の設定)、[11.〜18.](#11-見るログmetrics統計)（運用） |
| 制御 API を使う人（CI・スクリプト・コントローラ） | [1.](#1-インストールと起動)、[2.](#2-はじめてのルール)、[7.1](#71-トークン)（トークン）、[10.](#10-保存ルールの組dry-run)（保存・ルールの組・dry run） | [9.](#9-動かしたまま変える)、[18.1](#181-api-の誤り)（API の誤り）。ルールの中身は [3.〜6.](#3-l4-の転送udpポート範囲複数の宛先) |
| 管理 UI を動かす人 | [1.](#1-インストールと起動)（とくに [1.5](#15-制御-api-の-unix-ソケットを開く)）、[2.4](#24-設定ファイルと-api-の違い)、[7.1](#71-トークン)（UI のトークンは `admin`）、[12.1](#121-apt-で上げる)（v0.4.23 での注意） | [10.1](#101-api-で作ったルールを残す)（UI のトークンに `persist` を付けない理由）、[13.](#13-バックアップと復旧)（DB のバックアップ） |

### この手引きに出てくる言葉

よく出てくる言葉を先にまとめます。どれも、最初に出てくるところで詳しく説明しています。

| 言葉 | 意味 | 説明のある節 |
|---|---|---|
| ルールのキー | ルールを見分ける組（プロトコル・待ち受けのアドレス・ポート）。API のパスにも使います | [2.3](#23-制御-api-で作る) |
| 固定ルール / 動的なルール | 設定ファイルのルール / 制御 API で作ったルール | [2.4](#24-設定ファイルと-api-の違い) |
| 重ねる分（overlay） | 固定ルールの待ち受けに、API から足す HTTP のルートや TLS の名前 | [2.4](#24-設定ファイルと-api-の違い) |
| スコープ | トークンに許す操作の範囲（`rules:write`・`admin` など） | [7.1](#71-トークン) |
| 持ち主 | ルールなどを作ったトークンの名前。`admin` でないトークンは自分のものだけを変えられます | [7.1](#71-トークン) |
| persist（保存） | API で作ったルールを DB に書き、再起動の後も戻すこと | [10.1](#101-api-で作ったルールを残す) |
| ルールの組（ruleset） | 名前を付けたルールのまとまり。全体を毎回 `PUT` して、rproxy に差を当てさせます | [10.2](#102-ルールの組自動化向け) |
| dry run | 何も変えずに、変えたら何が起きるかだけを返す試し | [10.3](#103-dry-run) |
| `in_place` / `recreate` | 今の接続を切らずに変わる変更 / 待ち受けを作り直して接続が切れる変更 | [9.2](#92-接続を切らない変更in_placeと切る変更recreate) |
| drain | 止めるときに、新しい接続を受けずに今の接続が終わるのを待つこと | [9.3](#93-止めるときに待つdrain) |
| 引き継ぎ（handoff、SIGUSR2） | 動いたまま新しいバイナリに入れ替えること | [9.4](#94-バイナリを入れ替える再起動なし) |
| `degraded` | 権限や DB など環境の問題で、一部だけを止めて動き続けているという知らせ | [1.4](#14-動いているか確かめる) |
| 接続とセッションの枠（fd budget） | プロセスのファイル記述子のうち、接続と UDP のセッションに使える数 | [16.](#16-容量の上限) |

## 目次

**第 1 部 はじめる**

1. [インストールと起動](#1-インストールと起動)
2. [はじめてのルール](#2-はじめてのルール)

**第 2 部 ルールの中身**（設定ファイルでも API でも同じ形です）

3. [L4 の転送（UDP・ポート範囲・複数の宛先）](#3-l4-の転送udpポート範囲複数の宛先)
4. [TLS](#4-tls)
5. [L7（`http` のルール）](#5-l7http-のルール)
6. [送信元 IP](#6-送信元-ip)

**第 3 部 守りとプロセス全体の設定**

7. [守り（トークン・CrowdSec・GeoIP・ファイル）](#7-守りトークンcrowdsecgeoipファイル)
8. [`global` の設定](#8-global-の設定)

**第 4 部 動かしたまま変える・API で自動化する**

9. [動かしたまま変える](#9-動かしたまま変える)
10. [保存・ルールの組・dry run](#10-保存ルールの組dry-run)

**第 5 部 運用**

11. [見る（ログ・`/metrics`・統計）](#11-見るログmetrics統計)
12. [更新と戻し方](#12-更新と戻し方)
13. [バックアップと復旧](#13-バックアップと復旧)
14. [監視とアラート](#14-監視とアラート)
15. [ログの扱い](#15-ログの扱い)
16. [容量の上限](#16-容量の上限)
17. [レシピ](#17-レシピ)
18. [困ったとき](#18-困ったとき)

## 第 1 部 はじめる

第 1 部では、rproxy-api を入れて起動し（1.）、最初のルールを設定ファイルと制御 API の両方で作ります（2.）。2 つの入れ方の違いもここで説明します。

## 1. インストールと起動

この章では、rproxy-api を入れて起動し、制御 API に話しかけられるところまでを進めます。Debian / Ubuntu なら apt で、それ以外の systemd の Linux なら install.sh で入れます。どちらで入れても、rproxy-api の設定は `/etc/rproxy/rproxy.env` の環境変数で渡します。

### 1.1 apt で入れる（Debian / Ubuntu）

次のコマンドで、rproxy-api の apt リポジトリの署名鍵を置き、リポジトリを足して、パッケージを入れます。

```shell
sudo curl -fsSLo /usr/share/keyrings/rproxy-archive-keyring.gpg https://max3584.github.io/rproxy-api/rproxy-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/rproxy-archive-keyring.gpg] https://max3584.github.io/rproxy-api stable main" \
  | sudo tee /etc/apt/sources.list.d/rproxy-api.list
sudo apt update && sudo apt install rproxy-api
```

パッケージは、サービスのユーザー `rproxy-api`（主グループ `rproxy`）、環境変数のファイル `/etc/rproxy/rproxy.env`、制御 API のトークンを 1 つ書いたトークンファイル `/etc/rproxy/tokens`、systemd のユニット `rproxy-api.service` を作ります。

入れただけでは起動しません。`/etc/rproxy/rproxy.env` を自分の環境に合わせて書き換えてから、サービスを有効にして起動します。どの環境変数を変えるかは [1.3](#13-主な環境変数) で説明します。

```shell
sudoedit /etc/rproxy/rproxy.env
sudo systemctl enable --now rproxy-api
```

### 1.2 install.sh で入れる（systemd の Linux。VM 向け）

install.sh は、VM に 1 回で入れるためのスクリプトです。Debian / Ubuntu では apt から、ほかのディストリビューションではリリースのバイナリを入れ、ユーザー・設定・ユニットを作って起動まで済ませます。

```shell
curl -fsSL https://raw.githubusercontent.com/max3584/rproxy-api/master/scripts/install.sh | sudo bash -s -- --api-addr 127.0.0.1
```

`--api-addr 127.0.0.1` は、制御 API を同じホストの中（loopback）だけで待ち受けるという指定です（これが既定でもあります）。ほかのオプション（ポート、DB、ログの置き場所、transparent の経路など）は `install.sh --help` で見られます。

同じコマンドをもう一度実行すると、アップグレードになります。設定とトークンはそのまま残ります。

### 1.3 主な環境変数

rproxy-api のプロセスの設定は、環境変数で渡します。パッケージでは systemd が `/etc/rproxy/rproxy.env` を読んで渡すので、このファイルを書き換えて `sudo systemctl restart rproxy-api` で効かせます。ここでは、はじめに決めることの多いものだけを説明します。すべての項目は [README の「起動」](../README.md#起動) の表にあります。

| 環境変数 | 既定 | 何を決めるか |
|---|---|---|
| `RPROXY_API_ADDR` / `RPROXY_API_PORT` | `127.0.0.1` / `8080` | 制御 API を待ち受けるアドレスとポート |
| `RPROXY_API_SOCKET` | なし | 制御 API の Unix ソケットのパス |
| `RPROXY_TOKEN_FILE` | なし（パッケージでは `/etc/rproxy/tokens`） | 制御 API のトークンファイル |
| `RPROXY_CONFIG` | なし | 設定ファイル（固定ルール）の場所 |
| `RPROXY_DATABASE_URL` | なし | ルールを戻すための MariaDB |
| `RPROXY_LOG_FILE` / `RPROXY_LOG_LEVEL` | 標準出力 / `info` | ログの出し先と細かさ |
| `RPROXY_NODE_NAME` | ホスト名 | DB の中でこの rproxy を見分ける名前 |

- **`RPROXY_API_ADDR` / `RPROXY_API_PORT`**：制御 API を TCP で待ち受けるアドレスとポートです。既定の `127.0.0.1` では、同じホストからしか API に届きません。アドレスはカンマ区切りで複数書けます（例 `127.0.0.1,10.0.0.2`）。loopback 以外のアドレスを含めるときは、トークンファイル（`RPROXY_TOKEN_FILE`）と TLS の証明書・鍵（`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`）が必須で、どれかが欠けていると rproxy は起動しません。トークンが平文のネットワークを流れないようにするためです。ポートを `0` にすると TCP では待ち受けず、Unix ソケット（下）だけになります。
- **`RPROXY_API_SOCKET`**：制御 API をファイルシステムの上の Unix ソケット（例 `/run/rproxy/api.sock`）でも受けます。既定では開きません。設定ファイルの読み直し（`POST /config/reload`）などの影響の大きい操作は、既定ではこのソケットからだけ受け付けるので、それらを API から使うなら開きます（[1.5](#15-制御-api-の-unix-ソケットを開く)）。同じホストで管理 UI を動かすときも、TCP よりソケットでつなぐ方が安全です。
- **`RPROXY_TOKEN_FILE`**：制御 API のトークンを書いたファイルです。指定すると、`/healthz`・`/readyz` 以外のすべてのエンドポイントに `Authorization: Bearer <トークン>` が要ります。指定しなければ認証はありません（その場合、API は loopback でしか開けません）。パッケージは `/etc/rproxy/tokens` を作って指定しているので、入れた直後から認証が有効です。トークンの書き方は [7.1](#71-トークン) で説明します。
- **`RPROXY_CONFIG`**：設定ファイル（YAML か JSON）か、それを入れたディレクトリのパスです。ここに書いたルールが固定ルールになります（[2.1](#21-設定ファイルで書く)）。設定ファイルを使わず、ルールをすべて API や UI で作るなら指定しません。
- **`RPROXY_DATABASE_URL`**：MariaDB への接続先（`mysql://user:pass@host:port/db`）です。指定すると、rproxy は起動するときに、管理 UI が DB に保存したルールと、API で保存したルール（[10.1](#101-api-で作ったルールを残す)）を戻します。指定しなければ、API で作ったルールは rproxy のメモリにしかなく、再起動で消えます。管理 UI と一緒に使うときや、API のルールを残したいときに設定します。
- **`RPROXY_LOG_FILE` / `RPROXY_LOG_LEVEL`**：ログは 1 行に 1 つの JSON（JSON Lines）です。既定では標準出力に出し、systemd ではそれが journald に入ります。パッケージは `RPROXY_LOG_FILE=/var/log/rproxy/rproxy.log` を設定しているので、`/var/log/rproxy/rproxy.<日付>.log` に日ごとに分けて書きます（[15.](#15-ログの扱い)）。`RPROXY_LOG_LEVEL` は `info` のままで、調べものをするときだけ細かくします。
- **`RPROXY_NODE_NAME`**：DB の中でこの rproxy を見分ける名前で、既定はホスト名です。1 つの DB を複数の rproxy で使うときは、ノードごとに違う名前にしてください。同じ名前のプロセスがすでに動いていると、後から起動した方は約 40 秒待ってから `persist.duplicate_node` の誤りを出して終わります。

### 1.4 動いているか確かめる

起動したら、サービスの状態と、制御 API が答えるかを確かめます。下の例では、パッケージが作ったトークンをシェルの変数 `TOKEN` に読み込んでから API を呼んでいます。

```shell
systemctl status rproxy-api
TOKEN=$(sudo head -1 /etc/rproxy/tokens)     # パッケージが作った 1 行のトークン（すべての権限）。/etc/rproxy は root:rproxy 750
curl -s http://127.0.0.1:8080/healthz          # ok（認証なし）
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/capabilities | jq '{version, features: (.features | keys | length)}'
```

- `/healthz` は認証なしで `ok` を返します。プロセスが生きているかを見るためのものです。
- `/capabilities` は、動いている rproxy の版（`version`）と、この版で使える設定の一覧（`features`）を返します。版や機能の対応を確かめるときに使います。`/etc/rproxy` は `root:rproxy` の 750 なので、トークンを読むには `sudo` が要ります。

起動しないときは `journalctl -u rproxy-api` でログを見ます。rproxy は、問題の種類によって止まり方を変えます。

- **設定の誤り**（値の誤り、存在しないパス、ファイルの中身の誤り）では起動しません。直すまで動かないので、ログの誤りの文を見て直します。
- **環境の問題**（権限がない、ポートがほかのプロセスに使われている、DB に届かない など）では、使えない部分だけを止めて、残りで起動を続けます。このときログに `"event":"degraded"` と、止めた箇所を示す `part` を出します。この手引きでは、この状態を「`degraded`」と呼びます。詳しくは [README の「起動できないものがあるとき」](../README.md#起動できないものがあるとき) にあります。

### 1.5 制御 API の Unix ソケットを開く

制御 API のうち、プロセス全体に効く強い操作は、既定では Unix ソケットからだけ受け付けます。対象は、設定ファイルの読み直し（`POST /config/reload`）、`global` の設定の一部の項目の変更（`PATCH /config/global`、[8.](#8-global-の設定)）、`/admin/*`（更新など）、ACME の強い操作です。ソケットのファイルの権限で、使える OS の利用者を絞れるからです。これらを使うときや、同じホストの管理 UI をソケットでつなぐときは、ソケットを開きます。

パッケージの既定ではソケットは閉じているので、`/etc/rproxy/rproxy.env` の 2 行のコメントを外して再起動します。最後の行は、開いたソケットで API が答えるかの確かめです。

```shell
sudoedit /etc/rproxy/rproxy.env
#   RPROXY_API_SOCKET=/run/rproxy/api.sock      ← コメントを外す
#   RPROXY_API_SOCKET_GROUP=rproxy              ← コメントを外す
sudo systemctl restart rproxy-api
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" http://localhost/capabilities | jq .version
```

- `RPROXY_API_SOCKET` はソケットのパス、`RPROXY_API_SOCKET_GROUP` はソケットのファイルのグループです。ソケットの持ち主は `rproxy-api` で、モードは 660（`RPROXY_API_SOCKET_MODE`）なので、使えるのは root と、グループ `rproxy` に入っている利用者です。
- 上の例のように `sudo` で使うか、使う人をグループ `rproxy` に入れます（`sudo usermod -aG rproxy $USER` の後に入り直します）。
- `curl` の URL のホスト名（`localhost`）は形だけで、実際には `--unix-socket` のソケットに送ります。
- Unix ソケットからでもトークンは要ります。強い操作には `admin` のスコープ（すべての権限）が要りますが、パッケージが作った 1 行のトークンは `admin` です。

この手引きのソケットを使う例は、どれもこの準備ができていて、`$TOKEN` に `admin` のトークンが入っているものとして書いています。

## 2. はじめてのルール

この章では、最初の転送のルールを、設定ファイルと制御 API の両方で作ります。例として、`0.0.0.0:8888` に来た TCP の接続を `192.168.1.2:8080` へ中継します。最後に、2 つの入れ方の違いと、混ぜて使うときの決まりを説明します。

### 2.1 設定ファイルで書く

設定ファイルは、運用者がルールを手で決めて残しておくための方法です。ファイルに書いたルールは **固定ルール** になり、API からは変えられず、再起動してもファイルからもう一度作られます。

次の YAML は、上の転送を 1 つだけ書いた設定ファイルです。

```yaml
# /etc/rproxy/rproxy.yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8888
    remote_addr: 192.168.1.2
    remote_port: 8080
```

- `version: 1` は設定ファイルの形の版で、今は `1` だけです。
- `rules` の下に、ルールを 1 つずつ書きます。`protocol`（`tcp` か `udp`）・`listen_addr`・`listen_port` が待ち受けで、この 3 つの組がルールの **キー**（ルールを見分けるもの）になります。
- `remote_addr`・`remote_port` が転送先です。転送先にはホスト名も書けます。

rproxy にこのファイルを読ませるには、`/etc/rproxy/rproxy.env` に `RPROXY_CONFIG=/etc/rproxy/rproxy.yaml` を書きます。環境変数を変えたので、このときだけは再起動が要ります。

```shell
sudo -u rproxy-api rproxy-api --check-config /etc/rproxy/rproxy.yaml   # 0 なら問題なし、1 なら誤り
sudo systemctl restart rproxy-api
```

`--check-config` は、起動や読み直しのときと同じ検証（書式、値、待ち受けの重なり、証明書や鍵のファイル など）をして、問題がなければ終了コード 0、誤りがあれば 1 で終わります。待ち受けも DB も開かないので、動いている rproxy に影響はありません。nginx の `nginx -t` にあたるもので、設定ファイルを書き換えるたびに、まずこれを通してください。`sudo -u rproxy-api` で動かすのは、サービスのユーザーがファイルを読めるかまで確かめるためです。

2 回目からは再起動は要りません。rproxy は設定ファイルの変化を `RPROXY_CONFIG_CHECK_SECS`（既定 10 秒）ごとに見て、変わっていれば読み直し、違うところだけを反映します。すぐに反映したいときは `sudo systemctl reload rproxy-api` を使います。パッケージのユニットの reload は先に `--check-config` を実行し、誤りがあれば rproxy に何も送りません。読み直しの詳しい動きは [9.1](#91-設定ファイルを読み直す) で説明します。

### 2.2 ルールが動いているか確かめる

ルールが動いているかは、制御 API で確かめます。1 つ目のコマンドはルールの一覧から主な項目だけを、2 つ目は設定ファイルの読み込みの状態を出します。

```shell
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/rules \
  | jq '.[] | {protocol, listen_addr, listen_port, origin, state, error}'
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/config | jq '{files, rules, last_reload, error}'
```

- ルールの `state` が `running` なら動いています。`failed` なら動いておらず、理由が `error` と `conditions`（`BindFailed`・`ResolveFailed` などの状態の一覧）に出ます。
- `origin` はルールの出どころです。設定ファイルのルールは `static` になります（[2.4](#24-設定ファイルと-api-の違い)）。
- `GET /config` の `files` は読んだファイル、`rules` はその中のルールの数、`last_reload` は最後の読み直しで増えた・減った・変わったルールの数です。`error` が `null` でなければ、最新のファイルは反映できず、前の版が動き続けています。

YAML とファイルの置き方で気をつけることが 2 つあります。

- YAML は 1.2 として読みます。YAML 1.1 と違い、`yes`・`on` は真偽値ではなく文字列です。`010` のように数に見えるものは数になるので、文字列にしたいときは引用符で囲みます。
- `RPROXY_CONFIG` にディレクトリを指定すると、中の `*.yaml` / `*.yml` / `*.json` を名前の順にまとめて読みます。用途ごとにファイルを分けたいときや、Kubernetes の ConfigMap をそのまま置くときに便利です。ただし、`global`（プロセス全体の設定、[8.](#8-global-の設定)）を書けるのは 1 つのファイルだけです（[API.md の「設定ファイル」](API.md#設定ファイル固定ルール)）。

### 2.3 制御 API で作る

制御 API は、ほかのプログラム（管理 UI、CI、スクリプト）が動いている rproxy にルールを作らせるための口です。API で作ったルールは **動的なルール** になり、作る・変える・消すをその場で行えます。

次の例では、同じ転送を待ち受けのポートを 8889 にして API で作り、転送先を変え、最後に消します。本文の JSON は、設定ファイルの `rules` の 1 つと同じ形です。

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X POST http://127.0.0.1:8080/rules \
  -d '{"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":8889,"remote_addr":"192.168.1.2","remote_port":8080}'

# 転送先を変える（新しい接続から）
curl -s -H "Authorization: Bearer $TOKEN" -X PATCH http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889 \
  -d '{"remote_addr":"192.168.1.3","remote_port":8080}'

# 消す（今の接続も切る。?drain_secs=30 で 30 秒まで終わりを待つ）
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889
```

- `POST /rules` は、名前解決と待ち受けの開始まで済ませてから答えます。答えが返ったときには、もう転送が始まっています。
- `PATCH` と `DELETE` のパスは `/rules/{protocol}/{listen_addr}/{listen_port}` で、ルールのキーそのものです。IPv6 のアドレスをパスに入れるときは URL エンコードします（`::` は `%3A%3A`）。
- `PATCH` で転送先を変えると、今つながっている TCP の接続はそのまま前の転送先と話し続け、新しい接続から新しい転送先へ行きます。
- `DELETE` は既定では今の接続もすぐに切ります。`?drain_secs=30` を付けると、新しい接続は受けずに、今の接続が終わるのを最大 30 秒待ってから切ります（drain、[9.3](#93-止めるときに待つdrain)）。

### 2.4 設定ファイルと API の違い

ここまでの 2 つのルールは、`GET /rules` では同じように並びますが、出どころ（`origin`）と扱いが違います。次の表は、その違いをまとめたものです。

| | 設定ファイル | API |
|---|---|---|
| 表示の `origin` | `static` | `dynamic`（トークンの `persist: true` なら `api`） |
| 変え方 | ファイルを書き換えます（自動で反映されます） | `PATCH` / `DELETE` で変えます。固定ルールは `409 static` です |
| 再起動の後 | ファイルから作り直します | `dynamic` は消えます。UI のルールは DB から、`api` は `rproxy_rules` から戻ります |
| 向いているもの | 消えては困るもの（UI を公開するルールなど） | UI・CI・コントローラが変えるもの |

表の言葉を補います。

- **`dynamic`** は、API で作り、rproxy のメモリにだけあるルールです。管理 UI で作ったルールも `dynamic` ですが、UI は自分の DB（テーブル `forward_rules`）にも書いているので、rproxy の再起動の後は DB から戻ります。API を直接呼んで作った `dynamic` のルールは、再起動で消えます。
- **`api`** は、`persist: true`（保存する）の印を付けたトークンで作ったルールです。rproxy が自分のテーブル `rproxy_rules` に書き、再起動の後に戻します。どのトークンに `persist` を付けるかと、保存の細かい動きは [10.1](#101-api-で作ったルールを残す) で説明します。

同じキーのルールは、設定ファイルと API のどちらか一方にしか作れません。

- 設定ファイルにあるキーで `POST /rules` すると `409 already_exists` になります。
- 設定ファイルのルールを `PATCH` / `DELETE` すると `409 static` になります。変えるときはファイルを書き換えます。
- API で作ったルールと同じキーを後からファイルに書くと、API のルールが残り、ファイルのルールは動かずにログに `rule.failed` が出ます。

固定ルールの待ち受けに、API から HTTP のルートや `tls.routes` の名前を **足したい** ことがあります。たとえば、443 番を設定ファイルで終端していて、そこに UI から新しいサイトを足す場合です。このときは、ルールそのものではなく **重ねる分**（overlay、v0.4.23、#397）を使います。重ねる分は固定ルールとは別に持つので、ファイルのルールは変わりません。

次の例は、`tcp/0.0.0.0:443` の固定ルールに、`wiki.example.com` へのルートとそのサービスを重ねます。

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PUT -H 'If-None-Match: *' \
  http://127.0.0.1:8080/rules/tcp/0.0.0.0/443/overlay \
  -d '{"http":{"routes":[{"name":"wiki","match":"Host(`wiki.example.com`)","service":"wiki"}],
       "services":{"wiki":{"servers":[{"url":"http://10.0.0.5:8080"}]}}}}'
```

- `PUT .../overlay` は、そのルールの重ねる分を本文のとおりに丸ごと置き換えます。
- `If-None-Match: *` は「まだ重ねる分がないときだけ作る」という意味です。ほかの人が先に作っていたら、上書きせずに `412 precondition_failed` で断ります。今あるものを直すときは、`GET` で受け取った `ETag` を `If-Match` に付けて `PUT` します。
- 本文の `http` は、ルールの `http`（[5.](#5-l7http-のルール)）のうち `routes`・`services`・`middlewares` と同じ形です。`http` を重ねられるのは、固定ルールに `http` があるときだけです。`tls.routes` の名前を重ねることもできます。

重ねる分のルートは、ファイルのルートのどれにも当たらないリクエストだけを見ます。そのため、重ねる分からファイルのサイトを横取りしたり、ファイルのルートの認証を避けたりはできません。ファイルにすでにある名前（ルート・サービス・ミドルウェア）を使うと `409 overlay_conflict` で断ります。細かい決まりは [API.md の「固定ルールの待ち受けに重ねる分」](API.md#固定ルールの待ち受けに重ねる分v0423397featuresstatic_overlay) にあります。

## 第 2 部 ルールの中身

第 2 部では、ルールに書ける項目を、やりたいことごとに説明します。L4 の転送（3.）、TLS（4.）、HTTP を解釈して振り分ける L7（5.）、転送先にクライアントの IP を渡す方法（6.）の順です。ここに出てくる項目は、設定ファイルに書いても、API で送っても同じ意味になります。

## 3. L4 の転送（UDP・ポート範囲・複数の宛先）

この章では、中身を解釈せずにバイトをそのまま中継する L4 の転送の書き方を説明します。UDP、ポートの範囲、待ち受けのアドレスを複数にする方法、宛先を複数にして振り分ける方法、接続の数と時間の上限です。

この章の例は、設定ファイルの `rules:` の下に足す 1 つのルール（か、その一部）です。API で作るときは、同じ形を JSON にして `POST /rules` に送ります。

### 3.1 UDP

UDP には接続がないので、rproxy は「同じクライアントから来るデータグラムのまとまり」を **セッション** として覚え、転送先からの返事をそのクライアントへ返します。DNS・ゲーム・VoIP などを中継するときに使います。

次のルールは、53 番の UDP を `10.0.0.53` の DNS サーバへ中継します。

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 53
    remote_addr: 10.0.0.53
    remote_port: 53
    udp_idle_secs: 30        # 黙っているセッションを捨てるまでの秒数（既定 30）
```

`udp_idle_secs` は、何も届かなくなったセッションを捨てるまでの秒数です。既定は 30 秒です。ゲームのように、クライアントがしばらく黙ってもセッションを続けたいときは延ばします（[17.3](#173-udp-のゲームサーバ) の例では 120 秒にしています）。

UDP のルールには、ほかにも知っておくことがあります。

- `0.0.0.0` や `::` で待ち受けても、返事はクライアントが送った宛先のアドレスから返します。ホストにアドレスが複数あっても、クライアントは送った相手から返事を受け取れます。
- 確立していないセッション、つまり転送先の返事と、クライアントからの 2 つ目のデータグラムの両方がまだそろっていないセッションは、5 秒で終わります。送信元を偽ったデータグラムでセッションの表を埋められないための備えです（[API.md の「UDP の送信元の偽装への備え」](API.md#udp-の送信元の偽装への備えv0420354)）。1 つ送った後は受けるだけ、というクライアントはこの 5 秒で切られるので、何か送り続けるようにします。
- 1 つのルールが同時に持てるセッションの数は、既定では `RPROXY_UDP_MAX_SESSIONS`（16384）までです。多くのクライアントを受けるなら、そのルールの `limits.max_connections`（[3.5](#35-ルール全体の接続の上限)）か、この環境変数を上げます。

### 3.2 ポート範囲

ゲームサーバや RTP のように、連続した多くのポートをまとめて中継したいときは、1 つのルールでポートの範囲を書けます。

次のルールは、UDP の 10000〜10100 番を、`10.0.0.40` の 20000〜20100 番へ中継します。

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 10000
    listen_port_end: 10100     # 10000〜10100 を
    remote_addr: 10.0.0.40
    remote_port: 20000         # 20000〜20100 へ、同じ数だけずらして送る
```

- `listen_port` から `listen_port_end` までが待ち受けの範囲です。
- 転送先のポートは、待ち受けのポートと同じだけずらします。上の例では 10005 番に来たものが 20005 番へ行きます。
- 1 つのルールに書けるポートの数は、`RPROXY_MAX_RANGE_PORTS`（既定 20000）までです。
- ポートごとにソケットを 1 つ使うので、大きな範囲はファイル記述子を多く使います（[16.](#16-容量の上限)）。
- ポートの範囲は作った後に変えられません。変えるときはルールを作り直します。

### 3.3 待ち受けのアドレスを複数にする

IPv4 と IPv6 の両方、あるいは複数の決まったアドレスで同じ転送を受けたいときは、`extra_listen_addrs` に追加の待ち受けのアドレスを書きます。

次のルールは、`203.0.113.5` と `2001:db8::5` の 443 番を 1 つのルールで受けます。

```yaml
  - protocol: tcp
    listen_addr: 203.0.113.5
    extra_listen_addrs: ['2001:db8::5']   # IPv4 と IPv6 を 1 つのルールで
    listen_port: 443
    remote_addr: 10.0.0.20
    remote_port: 443
```

追加のアドレスは 16 件まで書けます。ルールのキーは `listen_addr` のままで、統計も 1 つのルールにまとまります。ルールを 2 つ作るより、設定と監視がまとまる利点があります。

### 3.4 宛先を複数にする（振り分けと切り替え）

1 つのルールの転送先を複数にすると、接続を振り分けたり、落ちた転送先を避けて切り替えたりできます。`remote_addr` / `remote_port` の代わりに `targets` を書きます。

次のルールは、PostgreSQL への接続を 2 台に振り分け、両方が落ちたときだけ予備の 1 台を使います。

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 5432
    targets:
      - {addr: 10.0.0.11, port: 5432, weight: 2, max_connections: 200}
      - {addr: 10.0.0.12, port: 5432, max_connections: 200}
      - {addr: db-backup.internal, port: 5432, backup: true}
    balance: least_conn        # round_robin（既定）/ least_conn / failover
    health_check: {interval: 10s, timeout: 3s}
    connect_timeout: 3s
```

項目ごとの意味は次のとおりです。

| 項目 | 何を決めるか |
|---|---|
| `targets[].weight` | 振り分けの重みです。既定は 1 で、上の例では 1 台目に 2 倍の割合で送ります |
| `targets[].max_connections` | その宛先に同時に開く接続の上限です（v0.4.19） |
| `targets[].backup` | `true` の宛先は、ほかの宛先がすべて down のときだけ使います |
| `balance` | 宛先の選び方です |
| `health_check` | 宛先が生きているかを定期的に確かめます |
| `connect_timeout` | 宛先への接続を待つ時間です |

`balance` は次の 3 つから選びます。

- `round_robin`（既定）：`weight` の比率で順に回します。宛先の性能がそろっているときに使います。
- `least_conn`：いま開いている接続（UDP はセッション）の数を `weight` で割った値がいちばん小さい宛先を選びます。DB のように接続が長く続き、本数に偏りが出やすいときに向いています。
- `failover`：上から順に、生きている最初の宛先だけを使います。主と予備がはっきり決まっている構成で使います。

宛先が生きているか（up / down）は、次のように決まります。

- `health_check` を書くと、`interval` ごとに TCP で接続してみて、`timeout` のうちにつながれば up とみなします。UDP のルールでは、確かめる TCP のポートを `port` で書く必要があります。
- `health_check` がなくても、接続に失敗した宛先は 10 秒のあいだ外して、次の宛先で接続し直します。外す回数や時間は `outlier_detection` で変えられます（[API.md の「受け身のヘルスチェック」](API.md#受け身のヘルスチェック170)）。

`max_connections` に達した宛先は飛ばして次の宛先を使い、すべての宛先がいっぱいなら接続を断ります。断ったことはログの `conn.limited` に `reason: target_full` で出ます。

`connect_timeout` を省くと、ほかに宛先があれば 5 秒、宛先が 1 つなら 30 秒待ちます。宛先が落ちたときに早く次へ移りたいなら短くします。`tcp` のルールだけの項目です。

宛先ごとの状態は、`GET /rules/tcp/0.0.0.0/5432` の `stats.targets`（宛先ごとの `up`・`connections`）と、`/metrics` の `rproxy_target_up` で確かめられます。

### 3.5 ルール全体の接続の上限

1 つのルールが受ける接続の数や、1 つの送信元が開ける接続の数に上限を付けると、転送先を守ったり、1 人のクライアントに資源を使い切られないようにしたりできます。

次の例は、ルールに足す `limits` です。

```yaml
    limits:
      max_connections: 2000          # ルール全体（UDP はセッション）
      per_source:
        max_connections: 50          # 1 つの送信元（既定は IPv4 /32・IPv6 /64 ごと）
        new_connections: {average: 10, period: 1s, burst: 20}
```

- `max_connections` は、ルール全体で同時に開ける接続の数です。UDP のルールではセッションの数になります。
- `per_source` は、送信元ごとの上限です。送信元は、既定では IPv4 は 1 アドレス（/32）、IPv6 は /64 ごとにまとめて数えます（`prefix_v4`・`prefix_v6` で変えられます）。
- `per_source.max_connections` は、1 つの送信元が同時に開ける接続の数です。
- `per_source.new_connections` は、新しい接続を開く速さです。上の例では、平均で 1 秒に 10 本、一度に 20 本までのばらつきを許します。

上限を超えた接続は、TCP では何も送らずに閉じ、UDP ではデータグラムを捨てます。断った数は、ルールの `stats.limited`、`/metrics` の `rproxy_rule_limited_total{reason}`、ログの `conn.limited` で分かります（[API.md の「L4 の制限と帯域」](API.md#l4-の制限と帯域165166の動き)）。

帯域を絞りたいときは、ルールの `bandwidth` に `upload`・`download`（例 `"10Mbps"`）を書きます。TCP は読むのを待たせて速さを抑え、UDP は超えた分を捨てます。

### 3.6 長く黙る接続

TCP のルールは、どちらの向きにも何も流れない接続を、`idle_timeout`（既定 `1h`）で切ります。使われなくなった接続がいつまでも資源を持たないようにするためです。DB の接続プールのように、長く黙っていても続けたい接続を中継するときは延ばします。`0s` にすると上限がなくなります。

```yaml
    idle_timeout: 8h
    half_close_timeout: 1m           # 片側が閉じた後（既定 1m）
```

- 数えるのは接続を流れるバイトだけです。TCP の keepalive のプローブは数えないので、keepalive を送っていても `idle_timeout` で切れます。
- `half_close_timeout` は、片側だけが送信を閉じた（FIN を送った）後に、もう片側を待つ時間です。既定は 1 分です。`0s` にすると、この時間は使わず `idle_timeout` だけで切ります。
- `http` のルールには効きません。`http` のルールの時間は `global.http.timeouts`（[5.5](#55-時間の上限globalhttptimeouts)）で決めます。

## 4. TLS

この章では、TLS の接続をどう扱うかを説明します。暗号のまま流すか、名前を見て振り分けるか、rproxy で復号（終端）するかを、ルールの `tls.mode` で選びます。用途別の例は [PROFILES.md](PROFILES.md) にもあります。

| `tls.mode` | 動き | 証明書を持つ場所 |
|---|---|---|
| `passthrough`（既定） | 暗号のまま流します | 転送先 |
| `sni` | 復号せずに、ClientHello のサーバ名を読んで転送先を選びます | 転送先 |
| `terminate` | rproxy が TLS を終端し、転送先へは平文か新しい TLS で送ります | rproxy |

- **`passthrough`**：`tls` を書かないときの動きです。rproxy は TLS であることを気にせず、バイトをそのまま流します。
- **`sni`**：TLS の最初のメッセージ（ClientHello）にはクライアントが行きたいサーバ名（SNI）が平文で入っています。rproxy はそれだけを読み、名前ごとに転送先を選びます。中身は復号しないので、証明書は転送先が持ちます。tcp では TLS、udp では DTLS と QUIC（HTTP/3 など）の名前を読めます。
- **`terminate`**：rproxy が証明書を持って TLS を終わらせます。tcp では TLS、udp では DTLS です。HTTP を解釈する `http` のルール（[5.](#5-l7http-のルール)）を使うときや、証明書を 1 か所にまとめたいときに選びます。

### 4.1 名前で振り分ける（`sni`）

1 つの 443 番に複数のサイトがあり、それぞれのサーバが自分の証明書を持っている場合は、`sni` で名前ごとに転送先を分けます。

次のルールは、`git.example.com` を `10.0.0.11` へ、`apps.example.com` とその 1 階層下の名前を `10.0.0.12` へ送り、それ以外の名前は切ります。

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 10.0.0.10           # どの名前にも当たらないとき
    remote_port: 443
    tls:
      mode: sni
      routes:
        - {server_name: git.example.com, remote_addr: 10.0.0.11, remote_port: 443}
        - {server_names: ['*.apps.example.com', 'apps.example.com'], remote_addr: 10.0.0.12, remote_port: 8443}
      unmatched: reject              # 当たらない名前・SNI なしは切る
```

- `routes` の 1 つが 1 組の名前と転送先です。名前を 1 つなら `server_name`、複数なら `server_names` に書きます。
- 名前の書き方は 3 通りです。`git.example.com` は完全一致、`*.example.com` は 1 階層だけ下の名前、`**.example.com` は何階層下でも当たります。複数の route に当たるときは、完全一致、`*.`、長い `**.`、書いた順の順で選びます。
- `unmatched` は、どの route にも当たらない名前と、SNI のない接続の扱いです。既定の `default` ではルールの `remote_addr` / `remote_port` へ送り、`reject` では切ります。

名前での振り分けは、アクセスの制限にはなりません。クライアントは ClientHello にどんな名前でも書けるからです。接続できる相手を絞りたいときは、`allow_from`（送信元のアドレスの範囲）や、クライアント証明書（mTLS）と組み合わせます。

### 4.2 終端する（`terminate`）

rproxy で TLS を終わらせ、転送先へは平文で送る場合の例です。社内のアプリに、rproxy で HTTPS を付けるときなどに使います。

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 8443
    remote_addr: 10.0.0.30
    remote_port: 8080                # 転送先へは平文
    allow_from: [10.0.0.0/8]         # 範囲の外は TLS より前に切る
    tls:
      mode: terminate
      certificates:
        - cert_file: /etc/rproxy/tls/site.pem
          chain_file: /etc/rproxy/tls/intermediates.pem
          key_file: /etc/rproxy/tls/site.key
      options: {min_version: '1.2'}
```

- `certificates` には、サーバ証明書（`cert_file`）、中間 CA の証明書（`chain_file`）、秘密鍵（`key_file`）を書きます。複数書くと、クライアントの名乗る名前に合う証明書を選びます。
- `allow_from` は、接続を受け付けてよい送信元の範囲です。範囲の外の接続は、TLS のハンドシェイクより前に切ります。
- `options.min_version` は、受け付ける TLS のいちばん古い版です。

証明書のファイルについて、運用で気をつけることがあります。

- 証明書と鍵は、サービスのユーザー `rproxy-api` が持ち主のファイルにし、鍵のモードは 600 か 640 にします。rproxy は、ほかの人が書き換えられるファイルや、ほかの人が読める鍵を使いません（[PERMISSIONS.md](PERMISSIONS.md)、[7.4](#74-ルールが指すファイル)）。certbot などで root の持ち物のファイルができるなら、deploy hook で写します。
- ファイルが変わると、`RPROXY_CERT_CHECK_SECS`（既定 60 秒）のうちに読み直します。今の接続は切りません。certbot の更新もそのまま反映されます。
- 期限の近い証明書は、ログの `cert.expiring` と、`/metrics` の `rproxy_cert_expiry_seconds` で分かります。

### 4.3 転送先へも TLS（再暗号化・mTLS）

rproxy で終端した後、転送先へも TLS でつなぐことができます。転送先までの経路も暗号にしたいときや、転送先がクライアント証明書を求めるときに使います。

次の例は、ルールの `tls` に `upstream` を足したものです。

```yaml
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/site.pem, key_file: /etc/rproxy/tls/site.key}
      upstream:
        tls: true
        server_name: backend.internal
        ca_file: /etc/rproxy/tls/internal-ca.pem
        cert_file: /etc/rproxy/tls/client.pem        # 転送先へのクライアント証明書（mTLS）
        key_file: /etc/rproxy/tls/client.key
```

- `upstream.tls: true` で、転送先へ TLS でつなぎます。
- `server_name` は、転送先に送る SNI と、転送先の証明書を確かめるときの名前です。
- `ca_file` は、転送先の証明書を確かめる CA です。社内の CA で発行した証明書を使うときに書きます。
- `cert_file` / `key_file` は、rproxy が転送先に出すクライアント証明書と鍵です。転送先が mTLS を求めるときだけ書きます。

逆に、クライアントに証明書を求めるときは、`tls` に `client_auth` を書きます。たとえば `client_auth: {mode: required, ca_file: /etc/rproxy/tls/clients-ca.pem}` とすると、`clients-ca.pem` の CA が発行した証明書を持つクライアントだけを通します。`mode` には `none`（既定）・`optional`（出されたら確かめる）・`required`・`optional_no_verify`（求めるが、なくても確かめられなくても通す）があります。

### 4.4 DTLS

DTLS は UDP の上の TLS です。`protocol: udp` のルールで `mode: terminate` にすると、rproxy が DTLS を終端し、転送先へは平文の UDP で送ります。CoAP のような IoT のプロトコルで使います。

```yaml
  - protocol: udp
    listen_addr: 0.0.0.0
    listen_port: 5684
    remote_addr: 10.0.0.60
    remote_port: 5683
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/coap.pem, key_file: /etc/rproxy/tls/coap.key}
```

DTLS の鍵は PKCS#8（ファイルの先頭が `-----BEGIN PRIVATE KEY-----`）に限ります。WebRTC のメディア（DTLS-SRTP）は、証明書が SDP のフィンガープリントに結びついているので終端できません。passthrough でそのまま流します。

### 4.5 STARTTLS（メール）

SMTP・IMAP・POP3 は、平文で始めてから `STARTTLS` コマンドで TLS に切り替えます。`starttls` を書くと、rproxy がこのやり取りをクライアントと行い、TLS を終端します。

次のルールは、メールの投稿（587 番）を終端して、転送先の MTA に渡します。

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 587
    remote_addr: 10.0.0.20
    remote_port: 587
    source_ip: proxy_v2              # 転送先に送信元 IP と TLS の情報を渡す
    starttls: smtp                   # smtp / imap / pop3
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/mail.pem, key_file: /etc/rproxy/tls/mail.key}
```

- `starttls` には `smtp`・`imap`・`pop3` のどれかを書きます。
- `source_ip: proxy_v2` は、転送先にクライアントの IP と TLS の情報を PROXY protocol で渡す指定です（[6.](#6-送信元-ip)）。メールサーバが送信元を見て判断するときに要ります。

既定（`starttls_required: true`）では、STARTTLS をしないクライアントは断ります。MTA どうしが話す 25 番では TLS を使わない相手もいるので、`starttls_required: false` にして平文も受けます。`false` が効くのは SMTP だけで、IMAP と POP3 ではいつも STARTTLS が必須です。

### 4.6 自動の証明書（ACME）

ACME は、Let's Encrypt などの CA から証明書を自動で取り、期限の前に更新する仕組みです。rproxy-api は ACME のクライアントを内蔵しているので、certbot なしで証明書を用意できます。

使い方は 2 段です。まず `global.acme`（プロセス全体の設定）に CA のアカウントと、証明書の取り方（resolver）を書きます。次に、ルールの証明書を `cert_file` の代わりに `{acme: <resolver の名前>, domains: [...]}` にします。

次の例は、Let's Encrypt から `example.com` と `www.example.com` の証明書を、443 番の TLS で確かめる方法（`tls-alpn-01`）で取ります。

```yaml
version: 1
global:
  acme:
    accounts:
      letsencrypt:
        contact: ['mailto:admin@example.com']
        allowed_names: [example.com, '*.example.com']    # 必須：取ってよい名前
    resolvers:
      le-alpn: {account: letsencrypt, challenge: tls-alpn-01}
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    remote_addr: 10.0.0.30
    remote_port: 8080
    tls:
      mode: terminate
      certificates:
        - acme: le-alpn
          domains: [example.com, www.example.com]
```

- `accounts` は CA のアカウントです。`contact` は CA からの連絡先、`allowed_names` はこのアカウントで取ってよい名前の一覧で、書くのが必須です。ルールや API から、ほかの名前の証明書を勝手に取らせないためです。
- `resolvers` は、どのアカウントでどの方法（challenge）で取るかの組で、ルールからはこの名前で指します。
- ルールの `certificates` の `acme` に resolver の名前を、`domains` に証明書に入れる名前を書きます。

取り方（challenge）は、ドメインを持っていることを CA にどう示すかで選びます。

- `tls-alpn-01` は、443 番の `terminate` のルールが CA の確かめに答えます。
- `http-01` は、80 番の `http` のルール（か、`global.acme` の `http01_listen`）が答えます。
- ワイルドカード（`*.example.com`）の証明書は `dns-01` でだけ取れます。DNS のプロバイダの設定が要ります。

運用で知っておくことは次のとおりです。

- 証明書が取れるまでは、自己署名の仮の証明書を返します。ルールの表示の `acme` の `state` が `valid` になれば取れています。状態は `GET /acme` でも見られます。
- 試すときは、Let's Encrypt の staging（`directory: https://acme-staging-v02.api.letsencrypt.org/directory`）を使うと、本番の回数の制限に当たりません。
- API で ACME の証明書を使うルールを作るには、トークンに `acme:write` のスコープが要ります。
- DNS-01 のプロバイダ、秘密を持つ補助プロセス、動いたままの変更は [ACME.md](ACME.md) で説明しています。

## 5. L7（`http` のルール）

この章では、HTTP を解釈して、ホスト名やパスで転送先を選ぶ L7 の転送を説明します。Traefik や nginx の `server` / `location` にあたる使い方です。1 つの 443 番で複数のサイトを受けたり、認証・リダイレクト・圧縮などの処理（ミドルウェア）を挟んだりするときに使います。

`tcp` のルールに `http` を書くと、L7 のルールになります。TLS は `terminate`（HTTPS）か、なし（平文の HTTP）のどちらかです。転送先は `http.services` に書くので、`remote_addr` / `remote_port` は書きません。

### 5.1 ルート・サービス・ミドルウェア

`http` のルールは、3 つの部品でできています。

- **ルート**（`routes`）：どのリクエストを、どのサービスへ送るかの決まりです。`match` の式でリクエストを選びます。
- **サービス**（`services`）：転送先のサーバの組です。振り分け、ヘルスチェック、時間の上限をここで決めます。
- **ミドルウェア**（`middlewares`）：リクエストや応答に挟む処理です。名前を付けて定義し、ルートから名前で使います。

次の例は、`app.example.com` と `api.example.com` の 2 つのサイトを 1 つの 443 番で受けます。`/admin` は社内からだけ、ログインを付けて通し、`api` には送信元ごとの流量の制限を掛けます。

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/site.pem, key_file: /etc/rproxy/tls/site.key}
    http:
      http3: true                    # 同じポートの UDP でも HTTP/3 を受ける
      pre_routing: [secure-headers]  # ルートを選ぶ前にすべてのリクエストへ
      routes:
        - name: app
          match: Host(`app.example.com`)
          service: app
          middlewares: [compress, cache]
        - name: admin
          match: Host(`app.example.com`) && PathPrefix(`/admin`)
          service: app
          middlewares: [office-only, login]
        - name: api
          match: Host(`api.example.com`)
          service: api
          middlewares: [per-ip]
      default: {status: 404}
      services:
        app:
          servers:
            - {url: 'http://10.0.0.10:3000'}
            - {url: 'http://10.0.0.11:3000'}
          health_check: {path: /healthz, interval: 10s}
          timeouts: {connect: 5s, response: 60s}
        api:
          servers:
            - {url: 'http://10.0.0.12:8080', max_connections: 500}
      middlewares:
        secure-headers:
          headers:
            hsts: {max_age: 31536000, include_subdomains: true}
            frame_deny: true
            content_type_nosniff: true
        compress: {compress: {}}
        cache: {cache: {ttl: 60s}}
        office-only: {ip_allow: {source_range: [10.0.0.0/8, '2001:db8:10::/48']}}
        login: {basic_auth: {users_file: /etc/rproxy/auth/htpasswd, realm: admin}}
        per-ip: {rate_limit: {average: 50, period: 1s, burst: 100}}
```

主な行を説明します。

- `http3: true` は、同じアドレス・ポートの UDP でも HTTP/3 を受けます（[5.4](#54-http3)）。
- `pre_routing` は、ルートを選ぶ前にすべてのリクエストへ掛けるミドルウェアです。上の例では、セキュリティのヘッダをすべての応答に付けています。
- `routes` の `admin` は、`app.example.com` のうちパスが `/admin` で始まるものを選び、`office-only`（社内の範囲だけ）と `login`（Basic 認証）を通してから `app` に送ります。
- `default` は、どのルートにも当たらないリクエストへの答えです。上の例では 404 を返します。
- `services` の `app` は 2 台のサーバに振り分け、`/healthz` を 10 秒ごとに確かめます。`timeouts` は、サーバへの接続を 5 秒、応答を 60 秒まで待つという意味です。
- `api` のサーバの `max_connections` は、そのサーバへ同時に開く接続の上限です。

ルートの選ばれ方と、ミドルウェアの順は次のとおりです。

- ルートは `priority` の大きい順に試します。`priority` を省くと `match` の式の文字数が使われるので、長い（細かい）式が先になります。上の例では、長い `admin` が `app` より先に試されます。どれにも当たらなければ `default` です。
- `match` は Traefik と同じ書き方の式です。`Host`・`HostRegexp`・`Path`・`PathPrefix`・`PathRegexp`・`Method`・`Header`・`Query`・`ClientIP` などを、`&&`（かつ）・`||`（または）・`!`（でない）で組み合わせます。
- ミドルウェアは、書いた順にリクエストへ、逆の順に応答へ働きます。
- サービスを作らずに 1 つの URL へ送るだけなら、ルートに `to: 'http://10.0.0.10:3000'` と書けます。
- パスと Host は、照合の前に正規化します。たとえば `/%61dmin` や `/x/../admin` は `/admin` として照合されるので、こうした書き方で `PathPrefix(`/admin`)` の守りを素通りすることはできません。

### 5.2 よく使うミドルウェア

ミドルウェアは、`http.middlewares` の下に `名前: {種類: {設定}}` の形で定義します。次の例は、よく使う種類をいくつか並べたものです。

```yaml
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
        old-docs: {redirect_regex: {regex: '^https://old\.example\.com/(.*)', replacement: 'https://docs.example.com/$1'}}
        sso:
          forward_auth:
            address: 'http://127.0.0.1:9091/api/verify'
            response_headers: [Remote-User, Remote-Groups]
        no-index: {headers: {response: {set: {X-Robots-Tag: noindex}}}}
        api-cache: {cache: {ttl: 30s, stale_on_error: 5m, vary: [Accept-Language]}}
        maintenance: {respond: {status: 503, body: 'maintenance'}}
```

- `to-https` は、HTTP のリクエストを HTTPS へ恒久的にリダイレクトします。
- `old-docs` は、古いホストの URL を、正規表現で新しいホストの同じパスへリダイレクトします。
- `sso` は、認証サーバ（例では Authelia）に問い合わせて、2xx が返ったリクエストだけを通します。`response_headers` に書いたヘッダ（利用者名・グループ）を、認証サーバの答えから転送先へ写します。
- `no-index` は、応答に `X-Robots-Tag: noindex` を付けます。
- `api-cache` は、GET の応答を 30 秒持ちます。`stale_on_error: 5m` は、転送先が 5xx を返したときに、5 分までは古い答えを返すという意味です。`vary` に書いたヘッダの値ごとに別の答えを持ちます。
- `maintenance` は、転送先に送らずに 503 と本文を返します。メンテナンスの間だけルートに付けます。

種類ごとの役割は次のとおりです。

| 種類 | 何をするか |
|---|---|
| `basic_auth` | htpasswd のファイルに載っている利用者だけを通します。ハッシュは `htpasswd -B` の bcrypt を勧めます。`user_header` で利用者名を転送先へ渡せます |
| `forward_auth` | 認証サーバ（Authelia・oauth2-proxy など）に問い合わせ、2xx なら通します |
| `oidc` | OpenID Connect のサインインを rproxy が行います（Keycloak など。oauth2-proxy は要りません） |
| `headers` | リクエストと応答のヘッダの `set`・`add`・`remove` と、`hsts`・`frame_deny`・`csp` などのセキュリティのヘッダを扱います |
| `redirect_scheme` / `redirect_regex` | HTTPS へ、または別の URL へリダイレクトします |
| `rate_limit` / `in_flight` | 送信元ごとのリクエストの速さ / 同時の数を制限します。超えたら 429 を返します |
| `cache` | GET の応答をメモリに `ttl` のあいだ持ちます。認証のミドルウェアの後ろに置くときは `share_after_auth` が要ります |
| `compress` | 応答を br・zstd・gzip で圧縮します |
| `ip_allow` | 送信元のアドレスが範囲の外なら 403 を返します |

ほかの種類（`crowdsec`・`geoip`・`cors`・`mirror`・`retry`・`circuit_breaker`・`errors`・パスの書き換えなど）と、それぞれの細かい動きは、[API.md の「HTTP の転送の扱い」](API.md#http-の転送の扱い) と「Gateway API 向けの L7・TLS」にあります。

### 5.3 80 番から HTTPS へ

HTTPS のサイトを作ったら、80 番に来た平文の HTTP を HTTPS へリダイレクトするのがふつうです。次のルールは、80 番のすべてのリクエストを HTTPS へ送ります。

```yaml
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - {name: to-https, match: 'PathPrefix(`/`)', middlewares: [to-https]}
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
```

ルートの `match: 'PathPrefix(`/`)'` はすべてのパスに当たります。このルートにはサービスがなく、ミドルウェアがリダイレクトを返すので、転送先には何も送りません。

ACME の `http-01` の確かめへの答えは、ルートより先に返します。そのため、このルールを置いたままでも `http-01` で証明書を取れます。

### 5.4 HTTP/3

`http.http3: true` を書くと、TCP と同じアドレス・ポートの UDP でも HTTP/3 を受けます。`terminate` のルールでだけ使えます。ファイアウォールでは、TCP に加えて UDP のポートも開けてください。

UDP のポートを開けないなど、HTTP/3 を受けられないときも、ルールは TCP だけで動き続けます。理由は `GET /rules` の `stats.http.http3` に出ます。

### 5.5 時間の上限（`global.http.timeouts`）

`http` のルールでは、クライアントの接続をどれだけ待つかを、ルールごとではなく `global`（プロセス全体の設定）でまとめて決めます。黙ったままの接続や、本文を送らないクライアントに資源を持たれ続けないための上限です。

次の例は、今の設定ファイルの `global` に足す分です。変えた値は新しい接続から効きます。

```yaml
global:
  http:
    timeouts:
      idle: 5m                 # 処理中のリクエストのない接続（既定 180s）
      request_body_idle: 2m    # 本文を送らずに黙っている時間（既定 60s）
      upgraded_idle: 4h        # WebSocket などで何も流れない時間（既定 1h）
```

- `idle` は、処理中のリクエストがない keep-alive の接続を閉じるまでの時間です。
- `request_body_idle` は、クライアントがリクエストの本文を送らずに黙っていてよい時間です。全体の時間ではなく、黙っている時間を数えます。大きなファイルをゆっくり上げるクライアントがいるなら延ばします。
- `upgraded_idle` は、WebSocket などに切り替えた（Upgrade した）接続で、何も流れないまま待つ時間です。チャットのように長く黙る WebSocket を使うなら延ばします。

ほかの項目と既定の値は、[API.md の「HTTP の転送の扱い」の `global.http.timeouts`](API.md#http-の転送の扱い) にあります。転送先の側の時間（接続・応答を待つ時間）は、サービスの `timeouts`（`connect`・`response`）で決めます。

## 6. 送信元 IP

この章では、転送先にクライアントの本当の IP アドレスを伝える方法を説明します。rproxy は転送先へ自分で接続し直すので、何もしなければ、転送先から見える接続元は rproxy の IP になります。転送先のアクセスログやアクセス制限でクライアントを見分けたいときは、ルールの `source_ip` で渡し方を選びます。選び方と、転送先の側の設定は [SOURCE-IP.md](SOURCE-IP.md) で詳しく説明しています。

| `source_ip` | 動き | 転送先に要る準備 |
|---|---|---|
| `proxy`（既定） | クライアントの IP を渡しません | なし |
| `proxy_v2` / `proxy_v1` | 接続の先頭に PROXY protocol のヘッダを付けます | PROXY protocol を受ける設定 |
| `transparent` | クライアントの IP を名乗って転送先へ接続します | 戻りの経路の設定（[TRANSPARENT.md](TRANSPARENT.md)） |

- **`proxy`** は既定の動きです。転送先からは rproxy の IP に見えます。
- **`proxy_v2` / `proxy_v1`** は、接続の最初に PROXY protocol のヘッダ（クライアントと待ち受けのアドレス・ポート）を付けて送ります。HAProxy が決めた形で、nginx・Postfix・多くのサーバが読めます。v2 はバイナリで、TLS の情報も渡せます。UDP では v2 だけを使い、データグラムごとにヘッダを付けます。転送先が PROXY protocol を受ける設定になっていないと、ヘッダを中身と取り違えて動かなくなるので、両方を同時に切り替えます。
- **`transparent`** は、rproxy がクライアントの IP を送信元にして転送先へ接続します。転送先には何の変更も要りませんが、転送先からの返事が rproxy に戻るように経路を設定する必要があり、`CAP_NET_ADMIN` の権限も要ります。

ほかにも、次のことに気をつけます。

- `http` のルールでは、クライアントの IP は `X-Forwarded-For`・`X-Real-IP` のヘッダで渡ります。`source_ip` は `proxy` か `transparent` だけが使えます。
- `source_ip` は作った後に変えられません。変えるときはルールを作り直します。

### 6.1 前段の PROXY protocol を受け取る

rproxy の前にロードバランサがいて、それが PROXY protocol のヘッダを付けてくる場合は、rproxy がそのヘッダを読む必要があります。そうしないと、rproxy に見えるクライアントは前段のロードバランサになってしまいます。ルールの `proxy_protocol` で、ヘッダを読む相手を指定します。

```yaml
    proxy_protocol:
      from: [10.2.0.0/16]          # ヘッダを信じる前段だけ（必須、/0 は不可）
      required: true               # from からの接続にヘッダがなければ断る（既定）
```

- `from` は、ヘッダを信じてよい前段のアドレスの範囲です。書くのが必須で、`/0`（すべて）は書けません。誰からのヘッダでも信じると、クライアントが好きな IP を名乗れてしまうからです。
- `required: true`（既定）では、`from` の範囲からの接続にヘッダがなければ断ります。

ヘッダを読んだ後は、`allow_from`・`limits`・ログ・`source_ip` が、どれもヘッダに書かれたクライアントのアドレスで動きます。前段のロードバランサのアドレスは、ログの `proxy_peer` に出ます。

### 6.2 `X-Forwarded-For` を信じる前段

`http` のルールの前に CDN やロードバランサがある場合、クライアントの IP は前段が付ける `X-Forwarded-For` のヘッダに入っています。どの前段のヘッダを信じるかを、`global.trusted_proxies` に範囲で書きます。

次の例は、今の設定ファイルの `global` に足す分です。

```yaml
global:
  trusted_proxies: [10.2.0.0/16]
```

この範囲から来た接続では、`X-Forwarded-For` を信じて、`ClientIP` の照合、`ip_allow`、`rate_limit`、ログに本当のクライアントの IP を使います。範囲の外から来た接続の `X-Forwarded-For` は信じません。範囲を広げすぎると、クライアントがヘッダを偽ってアドレスでの制限を抜けられるので、前段のアドレスだけを書いてください。

## 第 3 部 守りとプロセス全体の設定

第 3 部では、ルールの外にある設定を説明します。制御 API を誰に使わせるか（トークン）と、ルールの通信を守る仕組み（CrowdSec・GeoIP・ファイルの確かめ）が 7. です。8. では、プロセス全体に効く `global` の設定を、設定ファイルと API のどちらで決めるかを説明します。

## 7. 守り（トークン・CrowdSec・GeoIP・ファイル）

この章では、rproxy を守るための仕組みを 4 つ説明します。制御 API を使える相手と操作を絞るトークン（7.1）、悪い振る舞いをした IP を止める CrowdSec（7.2）、国や ASN で通す相手を決める GeoIP（7.3）、ルールが指すファイルの確かめ（7.4）です。

### 7.1 トークン

トークンは、制御 API を使う人やプログラムを見分け、それぞれにできる操作を絞るための合言葉です。制御 API を使う構成では、どれでもトークンを使います。管理 UI・CI・監視・Kubernetes のコントローラのように、API を使う相手が複数あるなら、相手ごとに別のトークンを作り、要る権限だけを与えます。

#### トークンファイルの 2 つの書き方

トークンは、`RPROXY_TOKEN_FILE` が指すトークンファイルに書きます。書き方は 2 通りあります。

- **1 行に 1 つ**：トークンの文字列そのものを 1 行に 1 つ書きます。どのトークンもすべての権限（`admin`）を持ち、ログには `token-1`・`token-2` のような名前で出ます。パッケージが作る `/etc/rproxy/tokens` はこの形です。API を使うのが自分だけ、あるいは管理 UI だけのときはこれで足ります。
- **YAML**：`tokens:` の下に、トークンごとの名前・SHA-256 のハッシュ・権限（スコープ）・制限を書きます。トークンの文字列そのものはファイルに置かず、ハッシュだけを置きます。相手ごとに権限を分けたいときは、こちらを使います。

YAML の書き方では、まずトークンを作り、そのハッシュを求めます。次のコマンドの 1 行目がトークン（クライアントに渡すもの）、2 行目がファイルに書くハッシュです。

```shell
TOKEN=$(openssl rand -hex 32)
printf %s "$TOKEN" | sha256sum      # この値を sha256 に書く
```

次のトークンファイルは、管理 UI・CI・Kubernetes のコントローラ・監視の 4 つの相手に、それぞれ別の権限を与える例です。

```yaml
# /etc/rproxy/tokens（root:rproxy 640）
tokens:
  - name: ui
    sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    scopes: [admin]                     # UI のトークンは admin にする（v0.4.23）
  - name: ci-deploy
    sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    scopes: [rules:read, rules:write]
    allow_listen_ports: 20000-29999     # 作る・変える・消すことができる待ち受けポート
    max_rules: 200
    expires: 2027-03-31
  - name: k8s-controller
    sha256: fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9
    scopes: [rules:read, rules:write]
    allow_rulesets: [k8s/]              # PUT / DELETE できる組の名前の先頭
  - name: monitoring
    sha256: baa5a0964d3320fbc0c6a922140453c8513ea24ab8fd0577034804a967248096
    scopes: [metrics:read]
```

4 つのトークンは、次のように使い分けています。

- `ui` は管理 UI のトークンで、すべての権限（`admin`）を持ちます。なぜ `admin` が要るかは、下の「持ち主だけが直す・消す」で説明します。
- `ci-deploy` は CI のトークンです。ルールを読み書きできますが、待ち受けのポートは 20000〜29999 番の中だけ、持てるルールは 200 個まで、使えるのは 2027 年 3 月 31 日までです。
- `k8s-controller` は Kubernetes のコントローラのトークンです。ルールの組（[10.2](#102-ルールの組自動化向け)）のうち、名前が `k8s/` で始まるものだけを扱えます。
- `monitoring` は Prometheus のトークンで、`/metrics` を読むことしかできません。

ファイルは `root:rproxy` の 640 にします。rproxy のサービスのユーザーが読めて、ほかの人は読めないようにするためです。

#### トークンの項目

YAML のトークンに書ける主な項目は次のとおりです。必須なのは `name`・`scopes` と、`sha256`（か、下の `client_cert`）です。ほかは省くと制限なしになります。

| 項目 | 省いたとき | 何を決めるか |
|---|---|---|
| `name` | （必須） | トークンの名前。ログと、作ったものの持ち主に使います |
| `sha256` | （必須） | トークンの文字列の SHA-256 |
| `scopes` | （必須。空にはできません） | 許す操作の範囲 |
| `allow_listen_ports` | すべてのポート | 作る・変える・消すことができるルールの待ち受けポート |
| `allow_rulesets` | すべての名前 | `PUT` / `DELETE` できるルールの組の名前の先頭 |
| `max_rules` | 上限なし（プロセスの上限だけ） | このトークンが持てるルールの数 |
| `expires` | 期限なし | このトークンを使える最後の日 |
| `allow_restored` | `false` | 作ったトークンの分からないルールも直せるか（v0.4.23） |
| `persist` | `false` | このトークンで作ったルールを DB に保存するか（[10.1](#101-api-で作ったルールを残す)） |

- **`name`**：ファイルの中で一意の名前です。監査のログ（`event: "audit"`）の `token` にこの名前が出るので、誰の操作かが分かります。また、このトークンで作ったルールや組の **持ち主** はこの名前になります（下で説明します）。
- **`sha256`**：クライアントが送るトークンの文字列の SHA-256 を、16 進で書きます。rproxy は送られてきたトークンのハッシュをこれと比べます。ファイルが漏れても、トークンそのものは分かりません。
- **`scopes`**：このトークンに許す操作です。下の表から必要なものだけを並べます。
- **`allow_listen_ports`**：このトークンで作る・変える・消すことができるルールの待ち受けポートを、`20000-29999` のような範囲か、1 つの番号で書きます。ポートの範囲のルールは、範囲の全体がこの中に収まっている必要があります。CI に一時的なルールを作らせるときに、本番のポート（443 番など）に触れないように使います。外のポートを指すと `403 forbidden` です。
- **`allow_rulesets`**：このトークンが `PUT` / `DELETE` できるルールの組の、名前の先頭を並べます。コントローラに `[k8s/]` のように付け、ほかの `rules:write` のトークンには付けない名前にしておくと、rproxy の再起動の後にほかのトークンが先に同じ名前の組を作ってしまうことを防げます。
- **`max_rules`**：このトークンが作ったルールと、このトークンの組のルールを合わせた数の上限です。超える作成は `409 limit` で断ります。1 つのトークンにプロセスの資源を使い切らせないための上限です。組の数の上限は `max_rulesets` で決めます。
- **`expires`**：この日（UTC）の終わりまで使えます。期限が近づくと、`RPROXY_TOKEN_WARN_DAYS`（既定 14 日）前からログに `token.expiring` を出し、切れると `token.expired` を出して通さなくなります。CI のように、定期的に入れ替えたいトークンに付けます。
- **`allow_restored`**、**`persist`**：下と [10.1](#101-api-で作ったルールを残す) で説明します。

ほかに、使える保存した証明書の名前の先頭（`allow_certs`）、ホストにないアドレスでの待ち受けを許すか（`allow_freebind`）、クライアント証明書の名前（`client_cert`）があります。どれも [API.md の「基本」](API.md#基本) と「制御 API の守り」で説明しています。

#### スコープ

スコープは次の 7 つです。`admin` はすべてを含みます。足りないスコープの操作は `403 forbidden` で断ります。

| スコープ | 許す操作 |
|---|---|
| `rules:read` | ルール・組・重ねる分・設定ファイルの状態を読むこと（`GET /rules`・`GET /interfaces` など） |
| `rules:write` | ルールを作る・変える・消すこと、組と重ねる分を置く・消すこと |
| `metrics:read` | `GET /metrics` を読むこと |
| `acme:write` | ACME の証明書を使うルールを作る・変えること、`POST /acme/...` |
| `certs:read` | 保存した証明書の一覧と中身（鍵を除く）を読むこと |
| `certs:write` | 証明書を保存する・消すこと（`PUT` / `DELETE /certs/{name}`） |
| `admin` | すべて。設定ファイルの読み直し、`global` の設定、更新などの強い操作はこれだけが使えます |

`GET /capabilities` は、どのスコープのトークンでも読めます。

#### 持ち主だけが直す・消す（v0.4.23、#401）

v0.4.23 からは、`admin` でないトークンは、**自分で作った** ルール・重ねる分・組だけを直す・消すことができます。ほかのトークンが作ったものを直そうとすると `403 not_owner` で断ります。CI のトークンが、別のチームのルールを消してしまうようなことを防ぐためです。

- 持ち主は、作ったトークンの **名前** です。同じ名前のまま `sha256` を新しいトークンのものに入れ替えても、持ち主は変わりません。
- `admin` のトークンは、どの持ち主のものでも直す・消すことができます。`admin` が直しても、持ち主は変わりません。
- 読むこと（`GET`）は、持ち主に関係なくスコープだけで決まります。

ここで困るのが、**作ったトークンの分からないルール** です。管理 UI の DB（`forward_rules`）から戻したルールや、再起動の後の `dynamic` のルールがこれにあたります。こうしたルールを直せるのは、`admin` と、`allow_restored: true` を付けたトークンだけです。

管理 UI は、ほかのトークンが作ったルールを直す画面（「API のルール」）と、複数のノードへの送り直しで、自分の作っていないルールを変えます。そのため、**UI のトークンは `admin` にします**。上の例の `ui` がそうです。

`admin` にしたくない構成で、UI が戻したルールだけを直せればよいなら、UI のトークンを `rules:read`・`rules:write` にして `allow_restored: true` を付けます。`allow_restored` は UI のトークンにだけ付け、CI などのトークンには付けません。

`allow_restored` は v0.4.23 で足した項目です。v0.4.22 以前の rproxy は、知らない項目を書いたトークンファイルを丸ごと読まないので、すべてのトークンが通らなくなります。古い版に戻すときは、先にこの行を外してください（[12.4](#124-前の版に戻す)）。

#### トークンを変える・入れ替える

トークンファイルを書き換えたら、`sudo systemctl reload rproxy-api`（SIGHUP）で読み直させます。reload を送らなくても、rproxy は `RPROXY_TOKENS_CHECK_SECS`（既定 10 秒）ごとにファイルの変化を見て読み直します。読み直したファイルに誤りがあれば、前のトークンのまま動き続け、ログに `reload.tokens` の警告を出します。

トークンを止めずに入れ替えるときは、次の順に進めます。

1. 新しいトークンをファイルに足します。この間は新旧のどちらでも通ります。
2. クライアント（UI・CI など）を新しいトークンに切り替えます。
3. 古いトークンをファイルから消します。

名前で持ち主が決まるので、名前の扱いには気をつけます。消したトークンの名前を、別の人や別の用途の新しいトークンに使い回さないでください。前のトークンが作ったものを、そのまま直せてしまいます。逆に、名前を変えると、前の名前で作ったものは `admin` でしか直せなくなります。名前は 1 つのファイルに 1 回しか書けないので、上の 3 つの手順で入れ替えると名前が変わります。そのトークンで作ったルールなどがあって持ち主を変えたくないときは、名前を変えずに `sha256` だけを新しいものに書き換えます。この場合は新旧が同時には通らないので、止められないクライアントはその間に送り直す必要があります。詳しくは [API.md の「トークン・証明書の入れ替え」](API.md#制御-api-の守りv04167) にあります。

#### 認証の失敗が続く送信元を止める

TCP の制御 API では、認証に失敗し続ける送信元を一時的に止めます。既定では、1 分のうちに 20 回失敗した送信元（IPv6 は /64 ごと）を 5 分止め、その間のリクエストはトークンを見ずに `429 locked_out` で断ります。トークンを総当たりで探されないための備えです。

- 回数と時間は `RPROXY_API_LOCKOUT_FAILURES`・`_WINDOW`・`_DURATION` で変えられます。`RPROXY_API_LOCKOUT_FAILURES=0` で止めなくなります。
- 同じ IP の後ろにいる正しいクライアントも一緒に止まります。NAT の後ろのコントローラのように止めたくない送信元は、`RPROXY_API_LOCKOUT_EXEMPT` に CIDR で書きます。
- Unix ソケットからのリクエストは数えず、止めることもありません。

#### 制御 API を外に開くとき

制御 API を loopback の外（ほかのホスト）に開くときは、トークンファイルと TLS（`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`）が必須です。どちらかがないと rproxy は起動しません。トークンが平文で流れないようにするためです。

同じホストで動かす管理 UI は、TCP ではなく Unix ソケット（[1.5](#15-制御-api-の-unix-ソケットを開く)）でつなぐ方が安全です。ネットワークに API を開かずに済み、上の一時停止にも巻き込まれません。トークンに加えてクライアント証明書（mTLS）でも確かめたいときは、[API.md の「制御 API の守り」](API.md#制御-api-の守りv04167) を見てください。

### 7.2 CrowdSec

CrowdSec は、ログから攻撃を見つけて、その IP を止める判定（ban）を配るオープンソースの仕組みです。rproxy は CrowdSec の LAPI（判定を配る API）から判定を受け取り、ban された IP の接続やリクエストを止める bouncer として動けます。CrowdSec をすでに使っているか、攻撃の多いサービス（SSH・メールなど）を公開するときに使います。

止める場所は 2 つあります。L4 のルールでは、ルールに `crowdsec: true` を書きます。`http` のルールでは、`crowdsec` ミドルウェアを使います。

まず、CrowdSec の側で rproxy 用の bouncer のキーを作り、サービスのユーザーだけが読めるファイルに置きます。

```shell
sudo cscli bouncers add rproxy -o raw | sudo tee /etc/rproxy/crowdsec.key >/dev/null
sudo chown rproxy-api:rproxy /etc/rproxy/crowdsec.key && sudo chmod 640 /etc/rproxy/crowdsec.key
```

次に、設定ファイルの `global.crowdsec` に LAPI の場所とキーのファイルを書き、止めたいルールに `crowdsec: true` を付けます。次の例は、25 番のメールで ban された IP を切ります。

```yaml
version: 1
global:
  crowdsec:
    lapi_url: 'http://127.0.0.1:8081'     # 制御 API と同じポートにしない
    api_key_file: /etc/rproxy/crowdsec.key
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 25
    remote_addr: 10.0.0.30
    remote_port: 25
    crowdsec: true                        # ban された IP は TLS より前に切る
```

- `lapi_url` は CrowdSec の LAPI の URL です。LAPI の既定のポートは rproxy の制御 API と同じ 8080 なので、同じホストで動かすなら、どちらかのポートを変えます（例では LAPI を 8081 にしています）。
- `api_key_file` は、上で作ったキーのファイルです。
- rproxy は LAPI から判定を定期的に取ってメモリに持ち、接続ごとに LAPI へ問い合わせはしません。LAPI に届かないあいだは、それまでの判定を使い続けます。

LAPI とつながっているかは、`GET /config` の `crowdsec`（`connected`・`decisions`）で分かります。逆向きに、rproxy のログを CrowdSec に読ませて攻撃を見つけさせる方法は [CROWDSEC.md](CROWDSEC.md) にあります。

### 7.3 GeoIP

GeoIP は、送信元の IP がどの国・どの ASN（ネットワークの運用者）のものかで、通すかどうかを決める仕組みです。日本からしか使わない SSH を海外から触らせない、といった粗い絞り込みに使います。

`global.geoip` に、GeoLite2 などの mmdb 形式のデータベースを書き、ルールの `geoip` で通す国を決めます。データベースは同梱していないので、MaxMind のアカウントを作り、`geoipupdate` などで取ってきます。

次の例は、22 番の SSH を日本からの接続だけに絞ります。

```yaml
version: 1
global:
  geoip:
    country_db: /var/lib/GeoIP/GeoLite2-Country.mmdb
    asn_db: /var/lib/GeoIP/GeoLite2-ASN.mmdb
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 22
    remote_addr: 10.0.0.70
    remote_port: 22
    geoip: {allow_countries: [JP], unknown: deny}
```

- `country_db` は国のデータベース、`asn_db` は ASN のデータベースです。ASN で絞らないなら `asn_db` は要りません。
- `allow_countries` は通す国の一覧です。この一覧があると、一覧の国の接続だけを通します。
- `unknown` は、国が分からない接続の扱いです。私用のアドレスや、データベースにないアドレス、データベースが読めないときがこれにあたります。既定の `allow` では通すので、確実に絞りたいときは例のように `deny` にします。

判定の順は `allow_from` → `geoip` → `crowdsec` です（[API.md の「GeoIP」](API.md#geoip168)）。

### 7.4 ルールが指すファイル

ルールは、証明書・鍵・htpasswd・OIDC の秘密など、いろいろなファイルを指します。rproxy は、こうしたファイルを書き換えられたり盗まれたりしないように、使う前に持ち主と権限を確かめます。証明書を置くとき、API でルールを作らせるときに知っておいてください。

- 証明書・鍵・秘密のファイルは、サービスのユーザー `rproxy-api` が持ち主で、グループやほかの人が書けないものだけを使います。鍵と秘密は、ほかの人が読めないことも求めます。この確かめは `global.files.owner_check: strict`（既定）で行います。Kubernetes の Secret のボリュームのように root の持ち物になる場所は、`global.files.trusted_dirs` に書くと使えます。
- API で作るルールは、証明書のストア、ACME の保存先、rproxy 自身の秘密（トークンファイルなど）、`/proc` などを指せません（`403 protected_file`）。API を使える人に、rproxy の秘密を読ませないためです。
- `admin` でないトークンは、ほかの持ち主のルールが使っている鍵や秘密のファイルを指せません（`409 file_in_use`）。別のチームの鍵で TLS を終端して、そのサイトになりすますことを防ぐためです。
- ファイルを使えなかった理由は、API の答えには出さず、ログの `config.file` に出します。API の答えから、ファイルがあるかどうかを探られないようにするためです（[PERMISSIONS.md](PERMISSIONS.md)）。

## 8. `global` の設定

この章では、ルールではなくプロセス全体に効く設定 `global` を説明します。信じる前段（[6.2](#62-x-forwarded-for-を信じる前段)）、アクセスログ、CrowdSec（[7.2](#72-crowdsec)）、GeoIP（[7.3](#73-geoip)）、ACME（[4.6](#46-自動の証明書acme)）、HTTP の時間（[5.5](#55-時間の上限globalhttptimeouts)）などがここに入ります。

`global` は、設定ファイルの `global` に書くか、制御 API の `PATCH /config/global`（`admin` が要ります）で変えます。ルールと同じく、**ファイル（と環境変数）に書いた項目はファイルが勝ちます**。ファイルに書いた項目を API で変えようとすると `409 static` で断ります。決まった値はファイルに、管理 UI の設定の画面などで変えたい値は API に、と分けて使います。

項目ごとに、変え方と、値をどこで決めるかが違います。

| 項目 | 変え方 | 値を決める場所 |
|---|---|---|
| `trusted_proxies`・`access_log`・`crowdsec`・`geoip`・`acme` | 動いたまま（Unix ソケットからだけ） | ファイル / API |
| `http.timeouts` | 動いたまま（新しい接続から） | ファイル / API |
| `udp_max_sessions`・`cache_max_memory` | 動いたまま | 環境変数 / API |
| `performance`・`files` | 再起動が要る | ファイル / 環境変数 |

- 「動いたまま」の項目は、再起動せずに入れ替わります。そのうち 1 行目の項目は、変えると守りが緩むことがある（信じる前段を広げる、ファイルを書く・読む など）ので、既定では API の Unix ソケットからだけ変えられます。
- `udp_max_sessions`（[3.1](#31-udp)）と `cache_max_memory`（すべての `cache` が使うメモリの合計の上限）は、ファイルではなく環境変数（`RPROXY_UDP_MAX_SESSIONS`・`RPROXY_CACHE_MAX_MEMORY`）か API で決めます。
- `performance`（ワーカーの数など）と `files`（[7.4](#74-ルールが指すファイル)）は起動のときにだけ読むので、変えたら再起動が要ります。

次の例は、Unix ソケットの API で今の値を見てから、`http.timeouts` と `udp_max_sessions` を変える前に dry run で確かめます。

```shell
SOCK=/run/rproxy/api.sock                    # 1 章の「制御 API の Unix ソケットを開く」
sudo curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" http://localhost/config/global | jq '.items | map_values({value, source, apply})'

sudo curl -s --unix-socket $SOCK -H "Authorization: Bearer $TOKEN" -X PATCH 'http://localhost/config/global?dry_run=true' \
  -d '{"http":{"timeouts":{"idle":"5m"}},"udp_max_sessions":32768}'
# よければ ?dry_run=true を外して送る。null を送るとその項目の API の値を消す
```

- `GET /config/global` の `items` には、項目ごとに今効いている値（`value`）、その値の出どころ（`source`：`file`・`env`・`api`・`default`）、変え方（`apply`：`live` か `restart`）が出ます。
- `PATCH` の本文は、設定ファイルの `global` と同じ形です。`?dry_run=true` を付けると、何も変えずに、変わる項目だけを返します。
- 項目に `null` を送ると、その項目の API の値を消して既定に戻します。

`PATCH` の動きで気をつけることは次のとおりです。

- 書いた項目は丸ごと置き換えます。`http.timeouts` も、中の 1 つだけを送ると、送らなかった項目は既定に戻ります。
- DB（`RPROXY_DATABASE_URL`）があれば、API で入れた値をテーブル `rproxy_global` に保存し、再起動の後も戻します。DB がなければ、値はこのプロセスの中だけにあり、再起動で消えます。
- 起動のときだけ読む項目を設定ファイルで変えると、再起動するまで効きません。そのことは `GET /config` の `restart_needed` に出ます（[API.md の「global の設定の API」](API.md#global-の設定の-apiv0419342featuresglobal_api)）。

## 第 4 部 動かしたまま変える・API で自動化する

第 4 部では、動いている rproxy を止めずに変える方法（9.）と、制御 API でルールを作るときの保存・ルールの組・dry run（10.）を説明します。10. は、CI やコントローラなどの自動化から API を使う人に向けた章です。

## 9. 動かしたまま変える

この章では、今の接続をなるべく切らずに設定やバイナリを変える方法を説明します。設定ファイルの読み直し、接続を切る変更と切らない変更の見分け方、止めるときに接続の終わりを待つ drain、再起動なしでバイナリを入れ替える引き継ぎの 4 つです。

### 9.1 設定ファイルを読み直す

設定ファイルを書き換えると、rproxy は 10 秒（`RPROXY_CONFIG_CHECK_SECS`）ごとの確認で変化に気づき、違うところだけを反映します。増えたルールは始め、なくなったルールは止め、変わったルールだけを変え、変わっていないルールには触りません。

自動の確認を待たずに、読み直した結果をその場で受け取りたいときは、`POST /config/reload` を使います。プロセス全体に効く強い操作なので、`admin` のトークンが要り、既定では Unix ソケットからだけ受け付けます。次の例では、まず `?dry_run=true` で何が変わるかだけを見てから、本当に読み直します。

```shell
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" -X POST 'http://localhost/config/reload?dry_run=true' | jq
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" -X POST http://localhost/config/reload
# {"added":1,"removed":0,"changed":1,"unchanged":3,"failed":0,"restart_needed":[],...}
```

答えの数は、増えた（`added`）・消えた（`removed`）・変わった（`changed`）・変わらない（`unchanged`）・作ったが動かない（`failed`）ルールの数です。`restart_needed` には、再起動しないと効かない `global` の項目が並びます。

ファイルに誤りがあれば、何も変えずに `400` と理由を返し、それまでの設定で動き続けます。自動の確認で誤りを見つけたときも同じで、ログに `config.error` を出します。`rproxy-api --check-config --diff` でも、書き換えたファイルを動いている rproxy と比べた差分を見られます。

### 9.2 接続を切らない変更（`in_place`）と切る変更（`recreate`）

ルールを変えたとき、今の接続がどうなるかは、変えた項目で決まります。rproxy は変更を 2 種類に分けて扱います。

- **`in_place`**：ルールの待ち受けはそのままで、中身だけを入れ替えます。今の接続は切れません。
- **`recreate`**：待ち受けを閉じて作り直します。そのルールの今の接続は切れます。

| 変えるもの | 効き方 |
|---|---|
| 宛先（`remote_*`・`targets`・`balance`・`health_check`）、`tls`、`starttls`、`allow_from`、`http`、`extra_listen_addrs`、時間、`limits`・`bandwidth`・`geoip`・`labels` など | `in_place` |
| `listen_port_end`（ポート範囲）、`source_ip`、`listen_freebind`、`http` の有無、`::` で待ち受けるルールの追加のアドレスの有無（dual-stack と IPv6 だけの切り替え） | `recreate` |

`in_place` の変更が今の通信にどう効くかは、プロトコルで違います。

- TCP は、今の接続は前の設定のまま続き、新しい接続から新しい設定になります。
- UDP は、今のセッションも新しい宛先に移ります。ただし、`extra_listen_addrs` から外したアドレスの UDP のセッションは終わります。

`recreate` になる変更は、API の `PATCH` では受け付けず、`400 unsupported` で断ります。変えたいときは、ルールを消してから作り直します。設定ファイルの読み直しとルールの組の `PUT` では、rproxy が自分で作り直します。

どちらになるかは、変更を送る前に `?dry_run=true`（[10.3](#103-dry-run)）の答えの `change` で分かります。

### 9.3 止めるときに待つ（drain）

drain は、止める前に新しい接続を受けるのをやめ、今の接続が自然に終わるのをしばらく待つことです。ダウンロードやデータベースのトランザクションの途中で、接続を急に切らないようにするために使います。

- **ルールを消すとき**：`DELETE /rules/...?drain_secs=30` のように、待つ秒数を付けます（3600 秒まで）。付けなければ、今の接続はすぐに切ります。
- **プロセスを止めるとき**（`systemctl stop` の SIGTERM）：既定ではすぐに止まります。2 つの環境変数で、止まり方を段階にできます。
  - `RPROXY_SHUTDOWN_DELAY`：まず `/readyz` を 503 にして「もうすぐ止まる」と前段に知らせ、この時間のあいだは今までどおり受け付けます。前段のロードバランサが、ほかの rproxy へ通信を移すための時間です。
  - `RPROXY_SHUTDOWN_DRAIN`：続けて待ち受けを閉じ、今の接続が終わるのをこの時間まで待ちます。過ぎても残る接続は切ります。

前にロードバランサがあるときの値の決め方は、[README の「SIGTERM での終わり方」](../README.md#sigterm-での終わり方v041) にあります。

### 9.4 バイナリを入れ替える（再起動なし）

rproxy-api は、動いたまま新しいバイナリに入れ替えられます。これを **引き継ぎ**（handoff）と呼びます。`systemctl restart` は今の接続をすべて切りますが、引き継ぎでは TCP・HTTP の接続を切りません。同じマイナー版（X.Y）の中のパッチ（例 0.4.22 → 0.4.23）で使えます。

引き継ぎは、動いている rproxy に SIGUSR2 のシグナルを送って始めます。

```shell
sudo systemctl kill -s USR2 --kill-whom=main rproxy-api    # ディスクの上のバイナリに引き継ぐ
journalctl -u rproxy-api | grep -E '"handoff\.(done|failed|refused)"'
```

1 行目は、サービスの主プロセスにだけ SIGUSR2 を送ります。2 行目は、引き継ぎの結果のログを探します。

引き継ぎは次のように進みます。

1. 古いプロセスが、ディスクの上の新しいバイナリを子として起動します。
2. 古いプロセスが、待ち受けのソケットと、API で作ったルールやルールの組などの状態を、新しいプロセスに渡します。同じソケットを使い続けるので、入れ替わりの間も新しい接続を取りこぼしません。
3. 新しいプロセスが準備できたら、新しい接続は新しいプロセスが受けます。古いプロセスは、自分の持っている接続が終わるのを待ってから終わります（`RPROXY_HANDOFF_DRAIN`、既定 5 分）。

結果はログに出ます。`handoff.done` は成功です。`handoff.refused` はマイナー版が違うので断ったことで、`handoff.failed` は新しいプロセスが準備できなかったことです。どちらの失敗でも、古いプロセスがそのまま動き続けます。

UDP のセッションは渡さず、新しいプロセスで作り直します。そのため UDP は一瞬途切れることがあります。パッケージの更新は、同じマイナー版ならこの引き継ぎを自動で使います（[12.](#12-更新と戻し方)、[UPGRADE.md](UPGRADE.md)）。

## 10. 保存・ルールの組・dry run

この章は、制御 API でルールを作る人に向けた章です。API で作ったルールを再起動の後も残す方法（10.1）、たくさんのルールをまとめて宣言的に管理するルールの組（10.2）、変更を送る前に結果を確かめる dry run（10.3）を説明します。

### 10.1 API で作ったルールを残す

保存しないトークンで API から作ったルール（`origin: dynamic`）は、rproxy のメモリにしかなく、再起動で消えます。CI のプレビュー環境のように一時的なルールならそれで構いませんが、残したいルールには次の 3 つの方法があります。

1. 設定ファイルに書きます（固定ルールになります）。
2. 管理 UI で作ります。UI が自分の DB に書き、rproxy の起動のときに戻します。
3. トークンに `persist: true` を付けて、API で作ります。このトークンで作ったルールは `origin: api` になり、rproxy が `RPROXY_DATABASE_URL` の DB のテーブル `rproxy_rules` に書き、起動のときに戻します。

3 つ目の方法では、トークンファイルの YAML で、保存したいトークンに `persist: true` を足します。

```yaml
tokens:
  - name: ci-deploy
    sha256: 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    scopes: [rules:read, rules:write]
    persist: true
```

保存の動きは次のとおりです。

- rproxy は、ルールの作成・変更・削除の答えを返す前に、DB に書きます。答えの `persisted: true` は、DB で確定したという意味です。
- DB に届かないときも、ルールは動かしたまま `persisted: false` で答えます。書けなかったものは、定期の照合（`RPROXY_PERSIST_CHECK_SECS`、既定 60 秒）が後で書き直します。
- `rproxy_rules` の自分のノード（`RPROXY_NODE_NAME`）の行だけを戻します。テーブルの定義は [API.md の「API で作ったルールの保存」](API.md#api-で作ったルールの保存144) にあります。

**UI のトークンには `persist` を付けません**。UI は作ったルールを自分の DB（`forward_rules`）に書くので、付けると同じルールを 2 か所に保存することになります。

### 10.2 ルールの組（自動化向け）

ルールの組（ruleset）は、名前を付けたルールのまとまりです。Kubernetes のコントローラや CI のように、プログラムが多くのルールを管理するときに使います。

ルールを 1 つずつ `POST`・`PATCH`・`DELETE` する代わりに、「この組のルールは全体でこうなっているべきだ」という一覧を毎回まとめて `PUT` します。rproxy は今のルールとの差を求めて、足りないルールを作り、変わったルールを変え、一覧から消えたルールを止めます。途中で失敗しても、次の `PUT` で正しい状態にそろうので、呼ぶ側は差分を覚えておく必要がありません。

次の例は、`ci/preview-42` という名前の組に、ルールを 1 つ置きます。

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PUT http://127.0.0.1:8080/rulesets/ci/preview-42 -d '{
  "generation": 1,
  "rules": [
    {"protocol":"tcp","listen_addr":"0.0.0.0","listen_port":20042,"remote_addr":"10.0.5.42","remote_port":8080}
  ]}' | jq '.results'
```

- パスの `ci/preview-42` が組の名前です。名前には `/` を含められます。
- `generation` は、呼ぶ側が付ける版の番号です。変えるたびに大きくします。
- `rules` は、この組のルールの全体です。1 つずつの形は `POST /rules` の本文と同じです。
- 答えの `results` には、ルールごとに何をしたか（`action`：`create`・`update`・`delete`・`none`）と、接続を切ったか（`change`：`in_place`・`recreate`、[9.2](#92-接続を切らない変更in_placeと切る変更recreate)）が並びます。

組の決まりは次のとおりです。

- 送ったルールのどれか 1 つでも検証に通らなければ、何も変えません。
- `generation` が前に受けたものより小さいと、`409 stale_generation` で断ります。遅れて届いた古い `PUT` で新しい状態を上書きしないためです。
- 答えの `etag` を、次の `PUT` の `If-Match` ヘッダに付けると、その間にほかの誰かが組を変えていたら `412 precondition_failed` で断ります。ほかの人の変更を気づかずに上書きしないためです。
- 組のルールを個別に `PATCH` / `DELETE` すると `409 owned` です。組のルールは、組の `PUT` で変えます。
- 組は、作ったトークンのものです。`admin` でないほかのトークンは `PUT` も `DELETE` もできません（`403 not_owner`）。

組は rproxy のメモリにだけあり、再起動で消えます。`persist: true` のトークンの組だけは、テーブル `rproxy_rule_sets` に保存されて戻ります。保存しない構成では、再起動の後、`GET /readyz` が 200 を返す（起動のときの復元が終わった）のを待ってから、呼ぶ側が組を `PUT` し直します（[API.md の「ルールの組・状態・readiness」](API.md#ルールの組状態readinesskubernetes-のコントローラ向け28)）。

### 10.3 dry run

dry run は、変更と同じ検証をして、何も変えずに「変えたら何が起きるか」だけを返す試しです。本番のルールを変える前に、誤りがないか、今の接続が切れないかを確かめるのに使います。

`?dry_run=true` を付けられるのは、`POST` / `PATCH` / `DELETE /rules`、`PUT /rulesets/{name}`、`POST /config/reload`、`PATCH /config/global`、重ねる分の `PUT` / `DELETE` です。dry run では待ち受けも開かず、名前解決もしません。

次の例は、8889 番のルールの転送先を変えたらどうなるかを確かめます。

```shell
curl -s -H "Authorization: Bearer $TOKEN" -X PATCH 'http://127.0.0.1:8080/rules/tcp/0.0.0.0/8889?dry_run=true' \
  -d '{"remote_addr":"10.0.0.13","remote_port":8080}' | jq '{action, change, diff}'
```

- `action` は、何をするかです（`create`・`update`・`delete`・`none`）。
- `change` は、`update` のときに接続を切らずに変わるか（`in_place`）、切れるか（`recreate`）です。
- `diff` は、変わる項目ごとの前と後の値です。

`PATCH` で気をつけることがあります。`PATCH` は宛先に関わる項目（`remote_addr` / `remote_port` か `targets`、`balance`、`health_check`）を、毎回まとめて置き換えます。省いた `balance` は `round_robin` に、省いた `health_check` はなしになります。そのため、`targets` のあるルールの宛先を変えるときは、`balance` と `health_check` も一緒に送ってください。何が消えるかは、dry run の `diff` で確かめられます。

## 第 5 部 運用

第 5 部では、動いている rproxy を見守り、更新し、困ったときに直すための手順をまとめます。ログ・メトリクス・統計の見方（11.）、更新と戻し方（12.）、バックアップ（13.）、監視（14.）、ログの扱い（15.）、容量の上限（16.）、よく使う構成の例（17.）、困ったとき（18.）です。

## 11. 見る（ログ・`/metrics`・統計）

この章では、rproxy が今どうなっているかを見る 3 つの方法を説明します。何が起きたかを時系列で追うログ、Prometheus で集めて傾向を見る `/metrics`、ルールごとの今の数を見る統計です。

### 11.1 ログ

ログは 1 行に 1 つのイベントを書いた JSON です。各行の `event` が、イベントの種類を表します。種類の一覧は [README の「ログ」](../README.md#ログ) にあります。

次の例は、ログを流しながら、気をつけたいイベントだけを `jq` で選んで表示します。1 つ目はファイルに出しているとき、2 つ目は journald に出しているときの例です。

```shell
# ファイルに出しているとき（パッケージの既定。ファイルの日付は UTC）
tail -F /var/log/rproxy/rproxy.$(date -u +%F).log | jq -c 'select(.event == "degraded" or .event == "rule.failed" or .event == "audit")'
# journald に出しているとき
journalctl -u rproxy-api -o cat | jq -c 'select(.event == "conn.denied" or .event == "degraded")'
```

ログのファイルは日ごとに分かれ、ファイル名の日付は UTC です。そのため、例では `date -u` で今日のファイル名を作っています。

まず見るとよいイベントは次のとおりです。

| `event` | 意味 |
|---|---|
| `degraded` | 環境の問題で、一部を止めて動き続けています（`part` が箇所） |
| `rule.failed` | ルールが動いていません |
| `config.error` | 設定ファイルを読み直せず、前の版で動いています |
| `audit` | 制御 API での変更と、断ったリクエストの記録です |
| `conn.denied`・`conn.limited` | アクセス制御・上限で接続を断りました |
| `tls.error` | TLS のハンドシェイクに失敗しました |
| `target.down` | 宛先が落ちたと判断しました |
| `cert.expiring` | 証明書の期限が近づいています |

### 11.2 `/metrics`

`/metrics` は、Prometheus の形式の数値です。ルールの数、ルールごとの接続数やバイト数、宛先の状態、断った数などを、時系列で集めて傾向を見たりアラートにしたりするのに使います。読むには `metrics:read`（か `admin`）のトークンが要ります。

次の例は、ルールの数と、ルールごとの状態・接続数の行だけを取り出します。

```shell
curl -s -H "Authorization: Bearer $METRICS_TOKEN" http://127.0.0.1:8080/metrics | grep -E '^rproxy_(rules|rule_up|connections) '
```

Prometheus での集め方と、見るとよい値は [14.](#14-監視とアラート) で説明します。

### 11.3 ルールの統計

1 つのルールの今の様子を見るときは、`GET /rules/{protocol}/{addr}/{port}` の `stats` と `conditions` を見ます。

- `stats` には、開いている接続の数（`connections`）、受けた・送ったバイト数（`rx_bytes`・`tx_bytes`）、アクセス制御で断った数（`denied`）、上限で断った数（`limited`）、宛先ごとの様子（`targets`）、`http` のルールのルートごとの数（`http`）などが入ります。
- `conditions` は、ルールが受け付けられたか、待ち受けているか、参照（証明書・転送先の名前）が解決できたか、宛先が生きているかの 4 つの状態です（[API.md の「ルールの組・状態・readiness」](API.md#ルールの組状態readinesskubernetes-のコントローラ向け28)）。

数はメモリにだけあるので、再起動すると 0 から数え直します。引き継ぎ（[9.4](#94-バイナリを入れ替える再起動なし)）では、古いプロセスの数を引き継ぐので減りません。

## 12. 更新と戻し方

この章では、rproxy-api を新しい版に上げる方法と、問題があったときに前の版に戻す方法を説明します。apt で入れた VM では apt で、コンテナでは自動更新で上げます。どちらも、同じマイナー版の中なら、引き継ぎ（[9.4](#94-バイナリを入れ替える再起動なし)）で接続を切らずに入れ替わります。

### 12.1 apt で上げる

apt で入れた rproxy は、ふつうのパッケージと同じように上げます。2 行目は、入れ替わりがどう終わったかをログで確かめます。

```shell
sudo apt update && sudo apt install rproxy-api
journalctl -u rproxy-api -n 50 | grep -E '"handoff\.|"start"'
```

パッケージは、前の版と major.minor が同じなら SIGUSR2 で引き継ぎ（接続を切りません）、違えば restart します（接続が切れます）。ログに `handoff.done` があれば引き継ぎで、`start` だけなら restart で入れ替わっています。リリースノートに「再起動が要る」とあるパッチは、同じマイナー版でも restart になります。

v0.4.23 に上げるときは、トークンの権限に気をつけてください。

- v0.4.23 から、`admin` でないトークンは自分で作ったルールしか直せなくなります（[7.1](#71-トークン) の「持ち主だけが直す・消す」、#401）。
- YAML のトークンファイルで UI のトークンを `rules:read`・`rules:write` にしていると、UI の「API のルール」の画面と、複数のノードの同期が `403 not_owner` で止まります。
- 上げる前に、UI のトークンを `admin` にするか、`allow_restored: true` を足してください。1 行に 1 つの書き方のトークンは `admin` なので、何もしなくて構いません。

### 12.2 自動更新（コンテナ）

コンテナで動かすときは、rproxy-api に自分で新しいパッチを取ってこさせることができます。イメージの入口（entrypoint）を `rproxy-api launch` にし、環境変数 `RPROXY_UPDATE=auto` を渡します。新しい版があることを知らせるだけにしたいなら `check` にします。

- 自動更新は、同じ X.Y の新しいパッチだけを、署名を確かめてから、引き継ぎで入れ替えます。
- 新しい版が `RPROXY_UPDATE_HEALTHY`（既定 60 秒）より前に落ちたら、悪い版として覚え、前の版に戻します。
- apt の VM と Kubernetes では `off`（既定）のままにします。VM では apt と二重に更新しないため、Kubernetes ではレプリカの入れ替えで更新するためです（[UPGRADE.md の「自動更新」](UPGRADE.md#自動更新コンテナ)）。

自動更新の今の状態（今の版、見つけた新しい版、悪い版の一覧など）は、次のコマンドで見られます。

```shell
sudo curl -s --unix-socket /run/rproxy/api.sock -H "Authorization: Bearer $TOKEN" http://localhost/admin/update | jq
```

### 12.3 手で引き継ぐ

パッケージを使わずにバイナリを置き換えたときは、自分で引き継ぎを始めます。バイナリを置き換えてから `systemctl kill -s USR2 --kill-whom=main rproxy-api` を実行するか、`POST /admin/upgrade`（`admin`、Unix ソケットから）を呼びます。

ログに `handoff.done` が出れば終わりです。新しいプロセスが 30 秒（`RPROXY_HANDOFF_TIMEOUT`）のうちに準備できなければ、古いプロセスが動き続け、ログに `handoff.failed` が出ます。

### 12.4 前の版に戻す

新しい版で問題が起きたときは、apt で前の版を指定して入れ直します。リポジトリは過去の版も残しています。

```shell
apt-cache policy rproxy-api                 # 入れられる版（リポジトリは過去の版も残している）
sudo apt install rproxy-api=0.4.22-1        # 版は <番号>-1 の形。同じマイナーなら、戻すときも引き継ぎで動く
```

1 行目で入れられる版の一覧を見て、2 行目で版を指定して入れます。パッケージの版は `<番号>-1` の形です。同じマイナー版の中で戻すなら、戻すときも引き継ぎで接続を切りません。

古い版は、新しい版で足した設定の項目を知りません。そのため、戻す前に次のことを確かめてください。

- **新しい版で足した設定を先に外します。** 古い版は知らない項目を誤りにします。たとえば、トークンファイルに `allow_restored`（v0.4.23）を書いたまま v0.4.22 に戻すと、トークンファイル全体を読まず、すべてのトークンが通らなくなります。どの項目がどの版から使えるかは、リリースノートの「追加」に書いてあります。
- **設定ファイルも同じです。** 戻す版のバイナリで `--check-config` を通してから戻します。
- **`PATCH /config/global` の値**（v0.4.19 から）は、それより前の版への引き継ぎでは渡りません。DB の行は残るので、v0.4.19 以後に戻せばまた読みます。
- **マイナー版をまたいで戻すとき** は restart になります。引き継ぎはできません。
- **v0.4.22 以前に戻すと**、持ち主だけが直す・消す守り（#401、v0.4.23）がなくなります。`rules:write` のトークンはどれも、ほかのトークンのルールを直す・消すことができるようになります。

## 13. バックアップと復旧

この章では、rproxy-api のホストが壊れたときに同じ状態に戻すため、何を取っておき、どの順で戻すかを説明します。取るものと戻す手順の詳細は [BACKUP.md](BACKUP.md) にあります。ここでは要点だけを挙げます。

| 取るもの | 場所 |
|---|---|
| 環境変数のファイルとトークン | `/etc/rproxy/rproxy.env`、`/etc/rproxy/tokens` |
| 設定ファイル | `RPROXY_CONFIG` のパス |
| 証明書・鍵・秘密のファイル | 設定とルールに書いたパス、`/var/lib/rproxy/certs/`、`/var/lib/rproxy/acme/` |
| DB | `forward_rules`、`rproxy_rules`・`rproxy_rule_sets`・`rproxy_global`・`rproxy_rule_overlays` |

- 設定ファイルは、固定ルールのただ 1 つの置き場所です。ほかのどこにも写しはないので、必ず取っておきます。
- `/var/lib/rproxy/certs/` は、制御 API の `PUT /certs` で保存した証明書の置き場所、`/var/lib/rproxy/acme/` は ACME で取った証明書とアカウントの鍵の置き場所です。
- DB のうち `forward_rules` は管理 UI のルール、`rproxy_` で始まるテーブルは rproxy が書くもの（保存した API のルール・ルールの組・`global` の API の値・重ねる分。`rproxy_rule_overlays` は v0.4.23 から）です。

戻すときは、次の順に進めます。rproxy が起動するときに設定と DB を読むので、先にそれらを戻しておきます。

1. パッケージを入れます（まだ起動しません）。
2. `/etc/rproxy` と鍵のファイルを戻します。
3. DB を戻します。
4. `--check-config` で設定ファイルを確かめます。
5. rproxy-api を起動します。
6. 管理 UI を起動します。
7. `GET /rules` などで、ルールが戻ったことを確かめます。

保存しないトークンで API から作ったルール（`origin: dynamic`）は DB にないので、戻りません。それも残したいなら、`GET /rules` の結果を控えとして取っておきます。

## 14. 監視とアラート

この章では、Prometheus で rproxy の `/metrics` を集め、問題に気づくためのアラートを作る方法を説明します。`/metrics` に出ない `degraded` の拾い方も最後に説明します。

### 14.1 集める

次の `prometheus.yml` は、別のホストの Prometheus から、TLS で開いた制御 API の `/metrics` を集める設定です。

```yaml
# prometheus.yml
scrape_configs:
  - job_name: rproxy
    scheme: https                                       # loopback の外の制御 API は TLS が必須
    tls_config:
      ca_file: /etc/prometheus/rproxy-api-ca.pem        # 自己署名なら、その証明書か CA
    authorization:
      credentials_file: /etc/prometheus/rproxy.token     # metrics:read のトークン（平文）
    static_configs:
      - targets: ['10.0.0.2:8080']
```

- `scheme: https` と `tls_config.ca_file` は、制御 API の TLS の証明書を確かめるための設定です。
- `authorization.credentials_file` には、`metrics:read` のトークンの文字列（ハッシュではありません）を書いたファイルを指します。

rproxy の側では、制御 API を監視の網に開きます。loopback の外で開くには、トークンファイルと TLS（`RPROXY_TLS_CERT` / `RPROXY_TLS_KEY`）が必須で、どれかがなければ起動しません。そのうえで、`RPROXY_API_ADDR` に監視の網のアドレスを足します（例 `127.0.0.1,10.0.0.2`）。

制御 API を loopback だけのままにしたいなら、Prometheus を同じホストで動かし、`scheme: http`・`targets: ['127.0.0.1:8080']` にします。このときは `tls_config` は要りません。

### 14.2 見る値

`/metrics` のうち、運用で見るとよい値を、知りたいことごとにまとめます。

| 知りたいこと | 値 |
|---|---|
| 動いていないルール | `rproxy_rules{state="failed"}`、`rproxy_rule_up == 0` |
| 宛先がすべて落ちた | `rproxy_rule_all_targets_down`、`rproxy_http_service_down`、`rproxy_target_up` |
| 上限で断った数 | `rproxy_rule_limited_total{reason}`、`rproxy_http_limited_total` |
| 接続とセッションの枠 | `rproxy_session_budget_in_use` / `rproxy_session_budget_limit` |
| 証明書の期限 | `rproxy_cert_expiry_seconds` |
| CrowdSec とのつながり | `rproxy_crowdsec_connected` |
| 背景のタスクの落ち | `rproxy_task_restarts_total{part}` |
| ログの取りこぼし | `rproxy_log_dropped_total` |
| 引き継ぎ | `rproxy_handoffs_total{outcome}`、`rproxy_build_info` |

いくつかの値を補います。

- `rproxy_rule_limited_total` の `reason` は、断った理由です。`max_connections`・`source_connections`・`new_connections`・`packets` はルールの `limits`（[3.5](#35-ルール全体の接続の上限)）、`target_full` は宛先の `max_connections`（[3.4](#34-宛先を複数にする振り分けと切り替え)）、`fd_budget` はプロセスの接続とセッションの枠（[16.](#16-容量の上限)）です。
- 接続とセッションの枠は、使っている数（`in_use`）と上限（`limit`）の比で、どれだけ埋まっているかが分かります。
- 背景のタスク（設定ファイルの監視、ACME、DB など）は、落ちても自動で動き直します。`rproxy_task_restarts_total` が増えたら、ログの `degraded` の `part` で、どこが落ちたかを見ます。
- `rproxy_log_dropped_total` は、ログの書き込みが追いつかずに捨てた行の数です。
- `rproxy_build_info` は、動いているバイナリの版です。引き継ぎの後に版が変わったかを確かめられます。

### 14.3 アラートの例

次のファイルは、上の値を使った Prometheus のアラートの例です。

```yaml
# rproxy-alerts.yml
groups:
  - name: rproxy
    rules:
      - alert: RproxyRuleFailed
        expr: rproxy_rules{state="failed"} > 0
        for: 5m
        annotations: {summary: '動いていないルールがある（GET /rules の state・error）'}
      - alert: RproxyAllTargetsDown
        expr: rproxy_rule_all_targets_down == 1 or rproxy_http_service_down == 1
        for: 2m
      - alert: RproxyLimited
        expr: sum by (protocol, listen, reason) (rate(rproxy_rule_limited_total{reason!="fd_budget"}[5m])) > 1
        for: 10m
        annotations: {summary: '{{ $labels.listen }} が {{ $labels.reason }} で断り続けている'}
      - alert: RproxyFdBudgetRefusing
        expr: sum(rate(rproxy_rule_limited_total{reason="fd_budget"}[5m])) > 0
        annotations: {summary: 'ファイルの数の枠が埋まり、接続・セッションを断っている（LimitNOFILE を上げる）'}
      - alert: RproxyFdBudgetHigh
        expr: rproxy_session_budget_limit > 0 and rproxy_session_budget_in_use / rproxy_session_budget_limit > 0.8
        for: 10m
      - alert: RproxyCertExpiring
        expr: rproxy_cert_expiry_seconds < 7 * 86400
      - alert: RproxyCrowdsecDisconnected
        expr: rproxy_crowdsec_connected == 0
        for: 5m
      - alert: RproxyTaskRestarted
        expr: increase(rproxy_task_restarts_total[15m]) > 0
        annotations: {summary: '背景のタスクが落ちて動き直した（ログの degraded の part）'}
      - alert: RproxyLogDropped
        expr: increase(rproxy_log_dropped_total[5m]) > 0
```

それぞれのアラートは、次のときに鳴ります。

- `RproxyRuleFailed`：動いていないルールが 5 分続いたときです。理由は `GET /rules` の `state`・`error` で見ます。
- `RproxyAllTargetsDown`：あるルールの宛先、または `http` のサービスのサーバがすべて落ちて 2 分たったときです。
- `RproxyLimited`：ルールの上限で 1 秒に 1 回より多く断り続けて 10 分たったときです。上限が小さすぎるか、攻撃を受けているかのどちらかです。枠（`fd_budget`）での断りは、次のアラートで別に扱います。
- `RproxyFdBudgetRefusing`：プロセスの接続とセッションの枠が埋まって断り始めたときです。`LimitNOFILE` を上げます（[16.](#16-容量の上限)）。
- `RproxyFdBudgetHigh`：枠の 8 割を超えて 10 分たったときです。埋まる前に気づくためのものです。
- `RproxyCertExpiring`：期限まで 7 日を切った証明書があるときです。
- `RproxyCrowdsecDisconnected`：CrowdSec の LAPI とつながらないまま 5 分たったときです。
- `RproxyTaskRestarted`、`RproxyLogDropped`：背景のタスクが落ちたとき、ログを取りこぼしたときです。

### 14.4 `degraded` を見つける

`degraded`（環境の問題で一部を止めて動いている状態、[1.4](#14-動いているか確かめる)）には `/metrics` の値がなく、ログにだけ出ます。そのため、ログを集める仕組みで拾います。

次のコマンドは、この 1 時間の `degraded` を、時刻・箇所・理由だけにして並べます。

```shell
journalctl -u rproxy-api --since -1h -o cat | jq -c 'select(.event == "degraded") | {timestamp, part, error}'
```

Loki を使っているなら、`{unit="rproxy-api.service"} | json | event="degraded"` のような問い合わせでアラートにできます。

## 15. ログの扱い

この章では、ログの置き場所、量、中に入る情報の扱いを説明します。ログの保存の期間を決めるときや、ログを読める人を決めるときに読んでください。

- **置き場所**：パッケージの既定では、`/var/log/rproxy/rproxy.<日付>.log` に書きます（`RPROXY_LOG_FILE`）。rproxy が日ごとにファイルを分け、`RPROXY_LOG_KEEP`（既定 14）個を超えた古いファイルを消すので、logrotate は要りません。`/etc/rproxy/rproxy.env` の `RPROXY_LOG_FILE` の行を消すと、ログは標準出力に出て、systemd ではそれが journald に入ります。
- **アクセスログ**：`http` のルールのリクエストは、1 件ごとに `http.access` のイベントになります。量が多いので、`global.access_log: /var/log/rproxy/access.log` で別のファイルに分けられます。API（`PATCH /config/global`）でこれを入れるときは、`RPROXY_API_ACCESS_LOG_DIR` のディレクトリの下にだけ置けます。rproxy はそのディレクトリの古いファイルを消すので、そこは rproxy のアクセスログだけの場所にしてください。
- **量**：攻撃を受けて同じ行があふれないように、`conn.denied`・`conn.limited`・`tls.error` などは送信元ごとに間引きます。間引いた行の数は、次に出す行の `suppressed` に入ります。クライアントが決める長い項目（ヘッダの値など）は 2,048 バイトで切ります。
- **秘密**：URL のクエリの `token`・`code`・`password` などの値は `REDACTED` に置き換えて書きます。それでも、ログにはクライアントの IP・SNI・証明書の CN が入るので、読める人を絞ってください（`/var/log/rproxy` は 750 です）。
- **CrowdSec**：同梱のパーサーとシナリオで、CrowdSec に rproxy のログを読ませ、攻撃を見つけさせられます（[CROWDSEC.md](CROWDSEC.md)）。ファイル名は日ごとに変わるので、CrowdSec の `acquis` には glob（`/var/log/rproxy/*.log`）で書きます。

## 16. 容量の上限

この章では、rproxy が同時に扱える接続や待ち受けの数を決める上限と、それが足りなくなったときの対処を説明します。多くの接続を受けるホストを用意するときや、`fd_budget` のアラートが鳴ったときに読んでください。

Linux では、ソケットは 1 つごとにファイル記述子（fd）を使います。プロセスが開けるファイル記述子の数には上限（`RLIMIT_NOFILE`）があり、rproxy は起動のときにこれをハードの上限まで上げます。パッケージのユニットは `LimitNOFILE=65536` です。

rproxy は、この上限を待ち受けのソケットと、接続・セッションに分けて使います。1024 は、ログのファイルや DB の接続など、そのほかのために残しておきます。

| 上限 | 既定 | 何を数えるか |
|---|---|---|
| `LimitNOFILE`（ユニット） | `65536` | プロセスのファイル記述子のすべて |
| `RPROXY_MAX_LISTENERS` | `0`（自動） | 制御 API で開ける待ち受けのソケット |
| 接続とセッションの枠 | 上限 − 1024 − `RPROXY_MAX_LISTENERS` | 接続と UDP のセッションが使うファイル記述子 |
| `RPROXY_MAX_RANGE_PORTS` | `20000` | 1 つのルールのポートの数 |
| `RPROXY_MAX_RULES` / `RPROXY_MAX_RULESETS` | `10000` / `1000` | API で作れるルール・組の数 |
| `RPROXY_UDP_MAX_SESSIONS` | `16384` | 1 つの UDP のルールのセッションの数 |

- **`RPROXY_MAX_LISTENERS`**：待ち受けのソケットの数の上限です。数えるのは、待ち受けのアドレスの数とポートの数をかけたもので、`http3` のルールは TCP と UDP の 2 倍になります。既定の `0` は自動で、(上限 − 1024) の半分になります。`LimitNOFILE=65536` なら 32256 です。
- **接続とセッションの枠**（fd budget）：残りのファイル記述子のうち、接続とセッションに使える数です。65536 なら 32256 になります。使う数は、TCP の中継が 1 本につき 2 つ（受けたソケットと転送先へのソケット）、`http` の接続が 1 つと転送先への接続ごとに 1 つ、UDP のセッションが 1 つ、splice のパイプが 2 つです。
- **`RPROXY_MAX_RANGE_PORTS`**：1 つのルールに書けるポートの範囲の大きさです（[3.2](#32-ポート範囲)）。
- **`RPROXY_MAX_RULES` / `RPROXY_MAX_RULESETS`**：API で作れるルールと組の数の上限です。`0` で上限なしになります。
- **`RPROXY_UDP_MAX_SESSIONS`**：1 つの UDP のルールが同時に持てるセッションの数です。ルールに `limits.max_connections` があれば、そちらを使います（[3.1](#31-udp)）。

接続とセッションの枠が埋まると、新しい TCP の接続はすぐに閉じ、UDP のセッションは断るか、確立していない古いセッションを終えて場所を空けます。そのことは、ログの `conn.limited` の `reason: fd_budget` と、`/metrics` の `rproxy_rule_limited_total{reason="fd_budget"}` で分かります。65536 では、TCP の中継を同時に約 16000 本扱えます。足りなければ、次のように `LimitNOFILE` を上げます。

```shell
sudo systemctl edit rproxy-api
# [Service]
# LimitNOFILE=262144
sudo systemctl restart rproxy-api
```

`systemctl edit` で開いたエディタに、コメントの 2 行（`[Service]` と `LimitNOFILE=262144`）を書いて保存します。ユニットの上限は再起動で効きます。

上限について、ほかに知っておくことは次のとおりです。

- 起動のときのログの `start` の行に、枠の大きさ（`session_budget`）、`max_listeners`、残しておく数（`fd_reserve`）が出ます。今使っている数は `/metrics` の `rproxy_session_budget_in_use` です。
- 設定ファイルや DB から戻すルールも上限に数えますが、上限を超えていても断りません。断るのは、API で数を増やす変更だけです（`409 limit`）。
- **転送先への接続の送信元ポート**（OS の決まり）：rproxy から転送先への TCP の接続と UDP のセッションは、1 つずつ rproxy のホストのエフェメラルポートを使います。Linux の既定（`net.ipv4.ip_local_port_range` の 32768〜60999）では、送信元のアドレスと 1 つの転送先（アドレス・ポート）の組ごとに、約 28000 本までです。1 つの転送先にそれより多くつなぐなら、範囲を広げるか、`targets` で転送先を分けます。`source_ip: transparent` ではクライアントのアドレスで出るので、この組は分かれます。

## 17. レシピ

この章では、よくある構成を、そのまま使える設定ファイルの形で紹介します。証明書のパスとアドレスを自分の環境に合わせて書き換え、`--check-config` を通してから使ってください。

### 17.1 Web アプリを HTTPS で公開する（ACME）

同じホストで 3000 番で動く Web アプリを、Let's Encrypt の証明書で HTTPS にして公開します。80 番は ACME の確かめに答え、ほかのリクエストは HTTPS へリダイレクトします。

```yaml
version: 1
global:
  acme:
    accounts:
      letsencrypt:
        contact: ['mailto:admin@example.com']
        allowed_names: [app.example.com]
    resolvers:
      le-http: {account: letsencrypt, challenge: http-01}
rules:
  - protocol: tcp                  # 80：ACME の http-01 に答え、ほかは HTTPS へ
    listen_addr: 0.0.0.0
    listen_port: 80
    http:
      routes:
        - {name: to-https, match: 'PathPrefix(`/`)', middlewares: [to-https]}
      middlewares:
        to-https: {redirect_scheme: {scheme: https, permanent: true}}
  - protocol: tcp                  # 443：終端して Web アプリへ
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - acme: le-http
          domains: [app.example.com]
    http:
      http3: true
      routes:
        - name: app
          match: Host(`app.example.com`)
          service: app
          middlewares: [secure, compress]
      services:
        app:
          servers: [{url: 'http://127.0.0.1:3000'}]
          health_check: {path: /, interval: 10s}
      middlewares:
        secure: {headers: {hsts: {max_age: 31536000}, content_type_nosniff: true}}
        compress: {compress: {}}
```

- `global.acme` は、`app.example.com` の証明書を `http-01` で取るアカウントと resolver です（[4.6](#46-自動の証明書acme)）。
- 1 つ目のルール（80 番）は、ACME の確かめに答え、それ以外を HTTPS へリダイレクトします（[5.3](#53-80-番から-https-へ)）。
- 2 つ目のルール（443 番）は、ACME の証明書で終端し、HSTS などのヘッダと圧縮を付けて Web アプリに送ります。`http3: true` で HTTP/3 も受けます。

ファイアウォールでは、TCP の 80 番・443 番と、HTTP/3 のための UDP の 443 番を開けます。証明書の状態は `GET /acme` で確かめます。

### 17.2 DB を TCP で中継する（長く黙る接続）

PostgreSQL の主と予備の 2 台の前に rproxy を置き、アプリからは 1 つのアドレスでつなげるようにします。主が落ちたら予備へ切り替えます。

```yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 10.0.0.2
    listen_port: 5432
    targets:
      - {addr: 10.0.1.11, port: 5432}
      - {addr: 10.0.1.12, port: 5432}
    balance: failover              # 主に送り、落ちたら次へ
    health_check: {interval: 5s, timeout: 2s}
    connect_timeout: 3s
    idle_timeout: 12h              # プールの接続を 1h で切らない
    allow_from: [10.0.0.0/16]
    limits: {max_connections: 1000}
```

- `balance: failover` と `health_check` で、5 秒ごとに主を確かめ、落ちていたら次の宛先を使います（[3.4](#34-宛先を複数にする振り分けと切り替え)）。
- `idle_timeout: 12h` は、アプリの接続プールが長く黙って持つ接続を、既定の 1 時間で切らないためです（[3.6](#36-長く黙る接続)）。
- `allow_from` で社内の網からだけ受け、`limits` で接続の数を 1000 本までにします。

### 17.3 UDP のゲームサーバ

UDP のゲームサーバを、IPv4 と IPv6 の両方で公開します。プレイヤーごとの資源の使い過ぎも抑えます。

```yaml
version: 1
rules:
  - protocol: udp
    listen_addr: 0.0.0.0
    extra_listen_addrs: ['::']
    listen_port: 27015
    remote_addr: 10.0.0.80
    remote_port: 27015
    udp_idle_secs: 120             # 黙るプレイヤーを 30 秒で切らない
    limits:
      max_connections: 4000        # このルールのセッション（既定の 16384 の代わり）
      per_source:
        max_connections: 4
        packets: {average: 200, period: 1s, burst: 400}
```

- `extra_listen_addrs: ['::']` で、IPv6 でも同じポートで受けます（[3.3](#33-待ち受けのアドレスを複数にする)）。
- `udp_idle_secs: 120` で、しばらく黙るプレイヤーのセッションを、既定の 30 秒で捨てないようにします（[3.1](#31-udp)）。
- `limits` で、ルール全体のセッションを 4000 まで、1 つの送信元のセッションを 4 つまで、データグラムを平均で 1 秒に 200 個までに抑えます（[3.5](#35-ルール全体の接続の上限)）。

### 17.4 1 つの 443 を名前で分ける

1 つの 443 番で、rproxy が終端して中継するサイトと、証明書を持つ転送先へそのまま流すサイトを、名前で分けます。

```yaml
version: 1
rules:
  - protocol: tcp
    listen_addr: 0.0.0.0
    listen_port: 443
    tls:
      mode: terminate
      certificates:
        - {cert_file: /etc/rproxy/tls/example.pem, key_file: /etc/rproxy/tls/example.key}
      routes:
        - server_names: ['**.k8s.example.com']    # Kubernetes へそのまま（証明書は向こう）
          passthrough: true
          remote_addr: 10.2.255.131
          remote_port: 443
          source_ip: proxy_v2
    http:
      routes:
        - {name: wiki, match: Host(`wiki.example.com`), to: 'http://10.0.0.5:8080'}
        - {name: git, match: Host(`git.example.com`), to: 'http://10.0.0.6:3000'}
      default: {status: 404}
```

- `tls.routes` の `passthrough: true` の route は、`**.k8s.example.com` の名前の接続を終端せず、ClientHello ごと Kubernetes のロードバランサへ流します。証明書は向こうが持ち、`source_ip: proxy_v2` でクライアントの IP を PROXY protocol で渡します。
- それ以外の名前は rproxy が `example.pem` で終端し、`http` のルートで `wiki`・`git` に振り分けます。どちらにも当たらなければ 404 を返します。

すべてのサイトの証明書を転送先が持っているなら、rproxy で終端する必要はありません。`tls.mode: sni` の例（[4.1](#41-名前で振り分けるsni)）を使います。

## 18. 困ったとき

この章では、うまくいかないときに見る場所と、よくある原因を説明します。API が誤りを返したとき（18.1）、ルールが動かないとき（18.2）、接続が断られるとき（18.3）の順です。

### 18.1 API の誤り

制御 API は、失敗すると `{"error": "...", "code": "..."}` の形の JSON を返します。`error` は人が読むための文、`code` はプログラムで見分けるための短い名前です。すべての `code` は [API.md の「エラー」](API.md#エラー) にあります。

よく出る `code` と、そのときにすることは次のとおりです。

| `code`（HTTP） | 意味 | すること |
|---|---|---|
| `static`（409） | 設定ファイルのルールを `PATCH` / `DELETE` しようとしました。組の `PUT` で同じキーを取ろうとしたときも、`PATCH /config/global` でファイル・環境変数の項目を変えようとしたときもこれです | ファイルを書き換えます。固定ルールの待ち受けに API から足すなら、重ねる分を使います（[2.4](#24-設定ファイルと-api-の違い)） |
| `already_exists`（409） | 同じキーのルールか、待ち受けの重なるルールがすでにあります。設定ファイルのキーへの `POST` もこれです | `GET /rules` で探し、アドレスかポートを変えます |
| `reserved`（409） | 制御 API（か `http01_listen`）のアドレスとポートに重なります | 別のポートにします。rproxy が使うアドレスは `GET /interfaces` の `reserved` で分かります |
| `bind_failed`（409） | ポートを開けません。ほかのプロセスが使っているか、権限がありません | `ss -lntup` で使っているものを探します。1024 未満のポートには `CAP_NET_BIND_SERVICE` が要ります |
| `not_owner`（403） | `admin` でないトークンが、ほかのトークンの作ったものを直そうとしました | 作ったトークンか、`admin` のトークンで変えます。UI のトークンは `admin`（か `allow_restored`）にします（[7.1](#71-トークン)） |
| `forbidden`（403） | スコープか `allow_listen_ports` の外です。Unix ソケットだけの操作を TCP から呼んだときもこれです | トークンを見直します。強い操作は `RPROXY_API_SOCKET` から呼びます |
| `file_in_use`（409） | ほかの持ち主のルールが使っている鍵・秘密のファイルを指しました | 自分のファイルを用意します（か、`admin` で作ります） |
| `protected_file`（403） | 証明書のストア・ACME の保存先・rproxy の秘密などを指しました | ファイルを別の場所に置きます |
| `file_not_allowed`（403） | `allow_certs` のトークンが、ファイルのパスを書きました | 保存した証明書を `{cert: <name>}` で指します |
| `tls_config` / `invalid`（400） | 形の誤りか、ファイルが使えません | 下の説明を見てください |
| `unsupported`（400） | この版・この環境で使えない設定か、`PATCH` では変えられない項目です | `GET /capabilities` の `features` を見ます。変えられない項目はルールを作り直します（[9.2](#92-接続を切らない変更in_placeと切る変更recreate)） |
| `limit`（409） | `RPROXY_MAX_*` か、トークンの `max_rules`・`max_rulesets` を超えます | 使っていないものを消すか、上限を上げます（[16.](#16-容量の上限)） |
| `owned`（409） | 組のルールを個別に変えようとしました | 組を `PUT` します（[10.2](#102-ルールの組自動化向け)） |
| `stale_generation`（409） / `precondition_failed`（412） | 古い `generation` を送ったか、`If-Match` が今と合いません | 今の状態を読み直してから送ります |
| `resolve_failed`（502） | 転送先の名前を引けません | DNS を確かめます。引けるようになれば自動で動き出します |
| `locked_out`（429） | 認証の失敗が続いたので、この送信元を止めています | `Retry-After` の秒数だけ待ち、トークンを直します |
| `upgrading` / `shutting_down`（503） | 引き継ぎか、止まる途中です | 少し待って送り直します |
| `no_config`（409） | 設定ファイルを使っていないのに `POST /config/reload` を呼びました | `RPROXY_CONFIG` を設定します |
| `restart_only`（409） | 再起動が要る `global` の項目を API で変えようとしました | ファイルで変えて再起動します |
| `in_use`（409） | ルールが使っているもの（`global` の項目、保存した証明書など）を消そうとしました | 先にルールを直します |

`tls_config` / `invalid` は、原因によって理由の出る場所が違います。

- 形の誤り（項目の名前や値の誤り）は、答えの `error` に理由が出ます。
- ファイルが使えない（持ち主・モードが合わない、ない、中身が読めない）ときは、理由を答えに出さず、ログの `config.file` に出します（[7.4](#74-ルールが指すファイル)）。設定ファイルなら `--check-config` が理由を出すので、それで確かめます。

### 18.2 ルールが `failed`・動かない

ルールの `state` が `failed` のときや、動いているはずなのに通らないときは、次の順に見ます。

1. `GET /rules` のそのルールの `error` と `conditions` を見ます。`conditions` の理由（`BindFailed`・`ResolveFailed`・`CertificateUnreadable` など）で、待ち受け・名前解決・証明書のどこが原因かが分かります。
2. ログの `rule.failed`・`config.error`・`config.file` を見ます。
3. 設定ファイルのルールなら `--check-config` を通します。読み直しの結果は `GET /config` の `error` に出ます。
4. API のルールで `persisted: false` なら、ルールは動いていますが DB に書けていません。ログの `degraded` の `part: db` を見て、DB への接続を確かめます。

### 18.3 接続が断られる

クライアントの接続が断られるときは、ログの `conn.denied`・`conn.limited` などと、その理由（`reason`）を見ます。

| ログ | 理由 | すること |
|---|---|---|
| `conn.denied`（`allow_from`・`geoip`・`crowdsec`・`unmatched`） | アクセス制御で断りました | 送信元の範囲・国・ban を確かめます。`unmatched` は、`tls.routes` に当たらない名前でした |
| `conn.denied`（`proxy_protocol*`） | PROXY protocol のヘッダがないか、前段が `from` の外です | 前段のアドレスを `from` に書きます（[6.1](#61-前段の-proxy-protocol-を受け取る)） |
| `conn.limited`（`max_connections` ほか） | ルールの `limits` を超えました | 上限を上げます（[3.5](#35-ルール全体の接続の上限)） |
| `conn.limited`（`target_full`） | 宛先がすべて `max_connections` に達しました | 宛先を足すか、上限を上げます |
| `conn.limited`（`fd_budget`） | プロセスの接続とセッションの枠が埋まりました | `LimitNOFILE` を上げます（[16.](#16-容量の上限)） |
| `tls.error` | TLS のハンドシェイクに失敗しました | 証明書、名前、`min_version`、クライアントの対応している版を確かめます |
| `target.down` | 宛先の生死の確認に失敗しました | 転送先が動いているか、`health_check` の `port` が正しいかを確かめます |
