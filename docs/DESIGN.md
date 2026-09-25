# rproxy-api 設計メモ

実装を進めるための設計記録。2026-09-25 時点のコード (`829521a`) を読んだ上での
整理であり、確定仕様ではない。

---

## 1. このプロジェクトは何を埋めるのか

**稼働中に TCP/UDP の転送を追加・削除・問い合わせできる L4 フォワーダ。**

転送そのもの (`tokio::io::copy_bidirectional`) に価値は無い。既存の実装が
いくらでもある。価値があるのは **「今どのポートが開いていて、どこへ転送して
いるか」を API で問い合わせ・変更できること**で、ここは既存の選択肢に空きが
ある。

| | 転送 | 稼働中のポート開閉 | 台帳の問い合わせ |
|---|---|---|---|
| Traefik | ○ | **✕** entryPoint は static config で再起動が要る | ✕ |
| nginx (stream) | ○ | ✕ 設定ファイル + reload | ✕ |
| HAProxy | ○ (TCP のみ) | ✕ 設定ファイル + reload | ✕ |
| **rproxy-api** | ○ | **○** | **○ (これから)** |

Traefik の制約は実際に運用で問題になっている。ポートを 1 本増やすたびに
static config の編集と再起動が要るため、「予約 entryPoint 群を事前に定義して
おく (ポートプール)」という先食いの回避策が検討される。**API でリスナーを
生やせるなら、その回避策自体が不要になる。**

### 1.1 目指す性質

- 開いているポートの一覧が、**1 つの権威ある場所**から取れる
- ポートの開閉に再起動が要らない
- 開いているポートが分かるので、**パケットフィルタのルールをそこから生成できる**
  (手書きの同期ズレが構造的に起きなくなる)

### 1.2 目指さないもの

L7 は範囲外。TLS 終端・SNI 振り分け・HTTP ミドルウェアは Traefik 等に任せる。
それらが必要な経路は rproxy-api を通さない。

---

## 2. 現状 (`829521a`)

### できていること

- TCP / UDP の双方向転送
- API (`{"property":"UP", ...}`) による転送の追加
- 30 秒周期の DNS 再解決による転送先の追従
- proxy ごとの制御ソケット経由の `STOP` / `UPDATE`

### できていないこと

- **`LIST`** — 何が開いているか問い合わせられない
- **`DOWN`** — API からの停止 (proxy ごとの制御ソケットに個別に繋ぐ必要がある)
- **API の認証・認可**
- **送信元 IP の保持** (§4)

---

## 3. 制御プレーンの作り直し

ここが本丸。**非同期そのものが難しいのではなく、ライフサイクルをソケットと
共有可変状態で表現していることが機能追加を止めている。**

### 3.1 現状の構造と、それが招いていること

| 箇所 | 現状 | 結果 |
|---|---|---|
| `src/api.rs:46,53` | proxy 1 本ごとに `127.0.0.2:<port>` / `127.0.0.3:<port>` へ制御 listener を立てる | proxy N 個で listener 2N 個。制御経路が散り、全体を見る場所が無い。listen_port を共有する 2 本が作れない |
| `src/api.rs:47-49` | `tokio::spawn(...)` の `JoinHandle` を捨てている | 起動後の proxy を参照する手段が無い。**`LIST` / `DOWN` が書けない根本原因** |
| `src/tcp.rs:123-127` | stop フラグを 30 秒周期の DNS tick の分岐でのみ読む | `accept()` 待機中はフラグに気づかない。停止に最大 30 秒 |
| `src/tcp.rs:147` | `try_join(main_task, control)` | 本体と制御が互いの完了を待ち、単独で終われない |
| `src/tcp.rs:56,63` 他 | `Arc<Mutex<String>>` で remote を共有 | 更新経路が双方向になり、誰が書くのか追いにくい |

### 3.2 置き換え

上の 5 つは **1 つのレジストリ導入でまとめて解ける。**

```rust
use tokio_util::sync::CancellationToken;
use tokio::sync::watch;

#[derive(Clone, Debug, serde::Serialize)]
pub struct ProxySpec {
    pub id:       ProxyId,
    pub protocol: Protocol,        // Tcp | Udp
    pub listen:   SocketAddr,
    pub remote:   String,          // ホスト名のまま保持 (DNS 再解決するため)
}

pub struct ProxyHandle {
    pub spec:   ProxySpec,
    cancel:     CancellationToken,
    join:       JoinHandle<()>,
    remote_tx:  watch::Sender<SocketAddr>,   // DNS 再解決が書き、接続タスクが読む
}

pub type Registry = Arc<RwLock<HashMap<ProxyId, ProxyHandle>>>;
```

これで:

- **`LIST`** → レジストリを舐めて `spec` を返すだけ
- **`DOWN`** → `cancel.cancel()` してから `join.await`
- **制御 listener が不要になる** — `sync()` と `127.0.0.2` / `127.0.0.3` の
  仕掛けごと消える。ポート衝突の問題も消える
- **`try_join` の結合が解ける** — proxy 本体は自分のトークンだけ見ればよい

### 3.3 停止は `CancellationToken`

```rust
loop {
    tokio::select! {
        _ = token.cancelled() => break,          // 即座に抜ける
        r = listener.accept() => {
            let (inbound, peer) = match r { Ok(v) => v, Err(e) => { /* log */ continue } };
            let child = token.child_token();     // 確立済み接続へ波及させる
            tracker.spawn(handle_conn(inbound, peer, remote_rx.clone(), child));
        }
    }
}
```

ポーリングが消え、30 秒待ちが無くなる。`child_token()` を接続タスクへ渡せば、
`DOWN` で在庫中の接続も畳める。

在庫を待ってから終わらせたい場合は `tokio_util::task::TaskTracker` を使う。

```rust
tracker.close();
tracker.wait().await;
```

### 3.4 転送先の更新は `watch`

`Arc<Mutex<String>>` をやめる。

```rust
// DNS 再解決タスク (書き手は 1 つ)
let _ = remote_tx.send(resolved_addr);

// 接続タスク (読み手は N)
let addr = *remote_rx.borrow();
```

書き手が 1 つ、読み手が N という一方向の流れになる。ロックを持ち回らずに
済み、`UPDATE` も DNS 再解決も同じ経路に乗る。**「設定を柔軟に変えたい」で
欲しかった道具はこれ。**

### 3.5 API の受け口

現状 `src/api.rs:33` と `src/api.rs:108` が `try_read` を一発呼んで JSON を
パースしている。コマンドが TCP セグメントに分割されて届くと失敗する。

行区切り (`\n`) にして `BufReader::lines()` で読み切るか、長さプレフィックスを
付ける。`LIST` の応答を返す必要もあるので、いずれにせよ**要求と応答のある
プロトコル**に整える必要がある。

---

## 4. 送信元 IP をどう扱うか

現状は保持していない。`src/tcp.rs:39` が `TcpStream::connect(remote)`、
`src/udp.rs:49` が `UdpSocket::bind("0.0.0.0:0")` で、どちらも自分のアドレスから
接続するため、バックエンドから見た接続元は rproxy-api のホストになる。

選択肢は 2 つあり、**前提条件が大きく違う**。

### 4.1 PROXY protocol を送る

接続直後、アプリデータより前にヘッダを流し込んでクライアントの IP を申告する。
Traefik / HAProxy / nginx が使っているのと同じ方式。

```
0d0a0d0a000d0a515549540a 21 11 000c <src ip><dst ip><sport><dport>
└─ v2 署名 (12 bytes) ──┘ │  │  └ len
                          │  └ AF_INET + STREAM
                          └ version 2 + PROXY command
```

- **経路の前提が無い。** 戻りが rproxy-api を通らなくてよい
- **バックエンド側の対応が必須。** 対応していないところへ送ると、ヘッダが
  異常な入力として扱われ接続が壊れる
- **TCP のみ。** UDP には仕組みが無い
- 実 IP が見えるのは**アプリ層だけ**。バックエンドのカーネルには
  rproxy-api の IP しか見えない (パケットフィルタでは使えない)

対応しているもの: Postfix (`smtpd_upstream_proxy_protocol`)、
Dovecot (`haproxy = yes`)、MediaMTX (`rtspTrustedProxies` / `rtmpTrustedProxies`)、
nginx、HAProxy、Envoy。

### 4.2 IP_TRANSPARENT で実 IP を名乗る

`socket2` で `IP_TRANSPARENT` を立て、クライアントの IP:port を bind してから
バックエンドへ接続する。

```rust
let sock = Socket::new(Domain::IPV4, Type::STREAM, None)?;
sock.set_ip_transparent(true)?;      // CAP_NET_ADMIN が要る
sock.set_reuse_address(true)?;
sock.bind(&client_addr.into())?;     // ← 実クライアントの IP:port を名乗る
sock.connect(&remote.into())?;
```

- **プロトコル非依存。** バックエンド側の対応が一切要らない。IPsec でも NTP でも効く
- **UDP でも使える**
- **カーネルレベルで実 IP が見える。** バックエンドのパケットフィルタでも使える
- **戻り経路が rproxy-api を通る必要がある。** これは選択ではなく制約で、
  rproxy-api は上流接続の端点なので、SYN-ACK 以降を受け取れないと握手が
  完了しない

> **最後の点が採用可否を決める。** バックエンドのデフォルトゲートウェイが
> rproxy-api のホストでない場合、戻りは別経路を通るため**転送が成立しない**。
> バックエンド側にポリシールーティングを入れるか、ゲートウェイを変えるかの
> どちらかが前提になる。

### 4.3 どちらを実装するか

**両方が要る。** 排他ではなく、転送ごとに選べるべき。

```json
{"property":"UP", "listen_addr":"...", "listen_port":25,
 "remote_addr":"...", "remote_port":2525,
 "protocol":"TCP", "source_ip":"proxy_protocol_v2"}
```

`source_ip` は `none` (既定) / `proxy_protocol_v2` / `transparent` の 3 値。
経路の前提を満たせない環境でも `proxy_protocol_v2` なら使えるので、
先にこちらを実装する方が適用範囲が広い。

---

## 5. 既知の不具合

優先度順。

| 箇所 | 内容 |
|---|---|
| `src/main.rs:65-78` | **logfile が既に存在すると `set_logger` が呼ばれない** (`else` 側にしかない)。加えて `Logger::log` は `println!` で stdout に書くだけで、`--logfile` はどこにも使われていない。README の説明と実装が一致していない |
| `src/main.rs:58` | `fn flush(&self) { todo!() }` — `log::logger().flush()` が呼ばれた時点で panic |
| `src/api.rs:33`, `src/api.rs:108` | `try_read` 一発で読んで JSON パース。分割到着で失敗する (§3.5) |
| `src/udp.rs:86` | 送信失敗で `panic!`。1 データグラムの失敗がタスクごと落とす |
| `src/api.rs:48,55` | spawn したタスク内で `.unwrap()`。同上 |
| `src/tcp.rs:123-127` | 停止に最大 30 秒かかる (§3.1) |
| `src/api.rs:38` | **API に認証・認可が無い。** `UP` で任意のアドレス:ポートに listen し任意の宛先へ転送できる。既定が loopback なのは妥当だが、ネットワーク越しに開けるなら必須 |
| `Cargo.toml` | `sqlx` (mysql feature) が `src/` から未使用。依存ツリーが重くなる |
| `src/main.rs:4` | `mod lib;` — バイナリクレートで `lib` という名前のモジュールは動くが、cargo が `lib.rs` を特別扱いするため紛らわしい |
| `README.md` | clone URL が `TCP-UDP-rproxy`、バイナリ名が `./forward`、「Update remote address」の例が `{"property":"STOP", ...}` だが実装は `"UPDATE"` を期待 (`src/api.rs:121`) |

---

## 6. 進める順番

1. **レジストリ導入** (§3.2) — `LIST` / `DOWN` がここで入る。制御 listener の撤去も同時
2. **`CancellationToken`** (§3.3) — 30 秒待ちの解消
3. **`watch` チャネル** (§3.4) — `Arc<Mutex<_>>` の撤去
4. **API プロトコルの整理** (§3.5) — 行区切り、要求/応答、エラー形式
5. **API の認証** — 最低でも共有トークン。ネットワーク越しに開けるなら必須
6. **不具合修正** (§5) — logger 周りは 1 と独立して先に直せる
7. **`source_ip: proxy_protocol_v2`** (§4.1) — 経路の前提が無いので適用範囲が広い
8. **`source_ip: transparent`** (§4.2) — 経路の前提が満たせる環境向け

1〜3 は 1 つの変更として入れるのが自然で、ここが済めば以降は素直に積める。

---

## 7. 参考

- 適用先の環境側の設計判断は `gitops/proxy-config` の `doc/l4-design.md` に
  分けて記録している (どのサービスを rproxy-api に寄せるか、経路をどうするか)
- PROXY protocol 仕様: https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt
- Linux transparent proxy: https://docs.kernel.org/networking/tproxy.html
