English: [PERFORMANCE.md](en/PERFORMANCE.md)

# 性能の改善の記録（rproxy-api）

速さ・CPU・メモリのために試したことと、その結果の記録。採用したものだけでなく、**採用しなかったものと理由も残す**（同じことをもう一度試さないため、条件が変わったときに見直すため）。
進め方はマイルストーン「performance」とラベル「area: performance」。測り方は [TESTING.md](TESTING.md) の「負荷・soak のテスト」（`load.yml`、`refs` で複数のブランチを同じランナーで交互に測る）。

## 測る条件と読み方の注意

- GitHub のランナー（4 vCPU）の中の、ネットワーク名前空間と veth の仮想の回線。実際の NIC では差が小さくなる見込み。
- 同じランナーでも実行ごとに速さが大きく揺れる（同じ master が 27k〜58k req/s）。**比べてよいのは同じ実行の中の列どうしだけ**。同じものを 2 つ並べたときの揺れは約 5%。
- `load.py` の h2load は、#197 より前は遅延の記録を同じファイルに追記していた。**それより前の実行の HTTP の p50 / p99 は、表の先頭の列以外は正しくない。**
- `load.yml` の同時実行のグループは、#200 より前はブランチ単位で、同じブランチから起動した実行が取り消し合っていた。
- 調べたほかのプロジェクト（HAProxy・nginx・Envoy・Pingora・linkerd2-proxy・Cilium など）のやり方は、#184・#185・#194・#195 の issue のコメントにまとめた。

## 基準（v0.3.17 / v0.3.18 の時点）

| 項目 | 直結 | rproxy | HAProxy |
|---|---|---|---|
| TCP 1 本 | 28 Gbit/s | 6〜7 Gbit/s | 10.6 Gbit/s |
| L4 の CPU あたりの転送量 | – | 0.65〜0.85 GiB/CPU 秒 | 1.2〜1.3 |
| HTTP/2 の小さいリクエスト | – | 約 30k req/s | 約 90k req/s |
| TCP の接続 1 本あたりのメモリ | – | 17.7 KiB（待機中）/ 25.7 KiB（転送中） | 約 3.3 KiB |
| UDP 64 バイトの全力 | 約 47 万 pps | 約 24 万 pps（取りこぼしはカーネルの受信バッファ） | – |

## 採用したもの（v0.3.19）

| 変更 | PR | 効果（v0.3.18 との比べ） | 気をつけること |
|---|---|---|---|
| TCP の転送のバッファを必要なときだけ持つ（`src/l4/relay.rs`） | #198 | 接続 1 本あたり 7.5 KiB（-58〜71%）、TCP 1 本 2 倍以上 | バッファは 32 KiB。TLS は 8 KiB ずつ読む（16〜32 KiB で読むと TLS 終端が 14〜25% 遅くなった） |
| 大きな転送だけ splice(2)（`src/l4/splice.rs`） | #202 | 大きな転送の CPU あたりの量が約 7 倍（#198 と合わせて）、TCP 8 本 3.7 倍 | plain の TCP だけ。32 KiB の読み込みが 4 回続けて満杯になったら切り替える。パイプは待機中に返す。root 以外では `pipe-user-pages-soft` に注意 |
| HTTP/2 の CPU（転送先の接続の使い回し・リクエストごとの処理の省略） | #197 | HTTP/2 +50〜60%、遅延 -30% 前後 | 待機中の転送先の接続はサーバごとに最大 1024 本、4 秒で閉じる。高い負荷の間はピークのメモリが増える |
| UDP のまとめ読み・まとめ書き（`recvmmsg` / `sendmmsg`）と大きな受信バッファ | #199 | 届く量 +65%、取りこぼし 57% → 21% | ソケットの分割（`SO_REUSEPORT`）は既定で 1 本（下の「採用しなかったもの」） |
| mimalloc を選べるようにする（`--features alloc-mimalloc`） | #201 | HTTP +9〜26%、CPU あたり +17〜31% | 既定は musl の malloc のまま（下） |

## 採用しなかったもの

### rustls の暗号の実装を aws-lc-rs にする（#196、閉じた）
- **試したこと**：rustls・tokio-rustls・quinn の暗号の実装を ring から aws-lc-rs に替えた。
- **結果**（run 37386709216）：TLS 終端の速さ -3%、ハンドシェイク/秒 -6%、**ハンドシェイクの CPU あたり +22%**、HTTP/2 over TLS +3%（揺れの範囲）。バイナリが 5〜14% 大きくなり、RSS +2 MiB、ビルド +30〜50 秒。dtls が ring に依存するので暗号のライブラリが 2 つになる。
- **理由**：ring も AES-NI / VAES を使っており、暗号の計算はボトルネックではなかった（TLS 終端が遅いのはレコードの処理とコピー）。
- **気付いたこと**：rustls の `ring` と `aws-lc-rs` の feature が両方有効になると、既定のプロバイダを選べずに DTLS の mTLS の検証で panic する。ring だけの今は起きない。
- **見直す条件**：ハンドシェイクが非常に多い使い方、耐量子の鍵交換（X25519MLKEM768）が必要になったとき。

### kTLS（#204、閉じた）
- **試したこと**：TLS 終端の L4 で、rustls のハンドシェイクの後に鍵を取り出し（`dangerous_extract_secrets`）、`TCP_ULP tls` と `TLS_TX` / `TLS_RX` に渡して平文で読み書きする。TLS 1.2 / 1.3 × AES-GCM 128/256 / ChaCha20 の 6 通りは正しく動いた。
- **結果**（run 37394020575）：CPU あたりの転送量 +3%、**速さ -18%**、ハンドシェイク +6%（揺れの範囲）。8 KiB のバッファのままでは -33%。
- **理由**：ring のユーザー空間の AES-GCM がカーネルと同じくらい速く、平文のコピーも残る。
- **残る制限**：クライアントからの KeyUpdate を受けると接続を切る（rustls の buffered API から次の鍵を取れない）。AES-GCM のレコード数の上限に近づいた接続も切る。
- **見直す条件**：splice と組み合わせて平文をユーザー空間に持ち込まない形（HAProxy 3.3 の kTLS + splice）を試すとき。

### 常に splice する（最初のバイトから）
- 小さなやり取りで CPU を余計に使う（64 バイトの往復、64 本で CPU あたり -12〜13%）。大きな転送が続くときだけ切り替える形（#202）にした。
- 最初の版は、使い回し用のパイプと待機中の接続のパイプで FD が増えた（待機中の接続 1 本あたり 6 本）。待機中に返す・プールを小さくする・使われなくなったら空にする形に直した。

### TCP の転送のバッファを 64 KiB にする
- 32 KiB よりわずかに速いだけで、iperf3 の 8 本で再送が 379 → 1,706 に増え、スレッドあたり最大約 2 MiB を余計に持つ。32 KiB にした。

### jemalloc
- armv7 向けにビルドできない（zig cc が jemalloc の `-mcpu` の指定を受け付けない）。Alpine のジョブすべてに `make` が要る。aarch64 では 16 KiB / 64 KiB ページのカーネル向けに `JEMALLOC_SYS_WITH_LG_PAGE` が要る。待機中の RSS が 2.4 倍で、soak で RSS が増え続けた（1.18）。mimalloc より速くもない。

### mimalloc を既定のアロケータにする
- 速さは上がる（HTTP +9〜26%）が、待機中のメモリ +8 MiB、負荷の後 +12 MiB。メモリを最小限にする方針なので、既定は musl のままにして選べるようにした（#201）。
- UDP のセッションの 64 KiB のバッファは、musl では使わないページが RSS に出なかったが、mimalloc では全部数えられた（1 万ポートの範囲で 650 MiB）。この受信バッファだけ `std::alloc::System` から取る（`RecvBuf`）。

### UDP のソケットを既定で分割する（`SO_REUSEPORT`）
- 分割（ワーカーの数）で届く量はさらに +3.5%、取りこぼし 45% → 34% だが、CPU が増え、CPU あたりの量は分割しないほうが上。受信が速くなった分、セッションの処理と受け側が詰まるようになった。既定は 1 本、`global.performance.udp_shards`（v0.4。`auto` でワーカーの数）か `RPROXY_UDP_SHARDS` で増やせる。コアに余裕のあるマシンで測ってから見直す。
- UDP の GRO / GSO（quinn-udp）は使っていない。quinn-udp は DF を立てる（`IP_MTU_DISCOVER`）ので、汎用の UDP の転送で動きが変わる。GRO は多数のクライアントからの小さなパケットにはほぼ効かない。

### HTTP/2 の大きな処理を Box に入れる
- memcpy を減らすつもりで入れたが、それだけでは効果がなかったので戻した（#197 の中で）。

### 調べただけで試していないもの
- **eBPF の sockmap**：Cilium が 1.14 でこの機能を削除しており、ソケット間の受け渡しの落とし穴が多い。
- **io_uring**：Google が本番のサーバで無効にしている。公開されている性能値も限られる。
- **XDP・busy poll**：GitHub のランナーでは確かめにくい。
- **thread-per-core のランタイム**：Pingora も既定は work stealing。TCP / HTTP は今のまま。

## 実験中：DPDK のデータプレーン（#261）

NIC をカーネルから外して DPDK の PMD でユーザー空間から直接扱い、L4 の UDP の転送の上限（pps・遅延）がどこまで上がるかを確かめる実験。**採否は実機の数字を見て決める**（GitHub のランナーで確かめられるのは正しさだけ）。

### 形
- 別のビルドだけ：cargo の機能 `dpdk`（`cargo build --release --features dpdk`。DPDK 22.11 以降の `pkg-config libdpdk` が要る）。既定のビルドと 6 つのリリースのターゲット（musl・armv7）には入らない。配るなら x86_64 / aarch64 の glibc の別の成果物（DPDK を動的にリンク。採ると決めたとき）。
- C は `crates/rproxy-dpdk/src/shim.c` の薄い包み（DPDK の速い道の関数は static inline なので）だけ。フレームの解析・書き換え・セッション・ARP は Rust（`crates/rproxy-dpdk` の `packet`・`engine`）で、DPDK なしで単体テストとファジング（`dpdk_packet`）を回す。
- UDP だけ。TCP はユーザー空間の TCP スタックが要るので扱わない（TCP は #260 の eBPF で）。L7・TLS・制御 API はカーネルのまま。
- どのルールが DPDK を通るか：**待ち受けのアドレスが DPDK のポートのアドレスである UDP のルール全部**（そのアドレスはカーネルにないので、ほかに選びようがない）。ルールごとの `performance: dpdk` は要らないと考える（同じアドレスでカーネルと分ける意味がない）。DPDK の道ができないこと（`source_ip` の PROXY protocol・transparent、`tls` の DTLS / sni、`http`）を使うルールは、そのアドレスでは作れない（`bind_failed` に理由）。`allow_from`・`geoip`・`crowdsec`・`limits`・`bandwidth`・ポートの範囲・`targets` / `balance` / ヘルスチェック・`udp_idle_secs`・統計・`conn.open` / `conn.close` のログはカーネルの道と同じ（ログに `path: dpdk`）。
- 仕組み：クライアントごとのセッションに、送信元のアドレスの NAT のポート（32768〜60999、ルールのポートは除く）を 1 つ割り当て、転送先からの返事をそのポートで受けてクライアントに返す（カーネルの道の接続した上りのソケットと同じ形）。ARP（自分のアドレスへの問い合わせに答える・転送先 / ゲートウェイの MAC を問い合わせる）と ping への返事は自分でする。IPv4 だけ（IPv6・VLAN・IP の断片は捨てる）。lcore ごとに RX キューを受け持ち、TX キューは lcore ごとに 1 つ（`tx_queues` は lcore の数以上）。ルールの表は lcore ごとの写し（版が変わったときだけ取り直す）、セッションは NAT のポートごとの Mutex（ほかの lcore と同じセッションを触るときだけ競合）。
- 起動時の確かめ（オーナーの決め、#260 と同じ枠組み `net::offload::probe`）：ヒュージページ → EAL → mempool → **rproxy のループバックのポート（`net_ring_rpchk`）に、本物の mbuf でテストのデータグラムを通して比べる**（ARP の両向き、クライアント → 転送先の 8 種類の大きさを `burst` 個、転送先からの返事。アドレス・ポート・MAC・チェックサム・中身）→ 設定のポートを開く（リンクの状態）。どれかが通らなければ使わず（`reason`）、カーネルの道に戻る（`fallback: false` なら起動を止める）。結果は `performance.probe`（`feature: dpdk`）、`degraded`（`part: global.performance.dpdk`）、`GET /capabilities` の `performance.dpdk`、`rproxy-api --check-kernel` の表（`dpdk.enabled=true` の行と各段階）。
- 動いている間は数えたり見張ったりしない。異常を扱ったときだけ今のログの決まりで出す（TX キューがいっぱい：`dpdk.tx_full` を debug、転送先の MAC が分からない・NAT のポートが尽きた：そのデータグラムを `stats.dropped`）。

### CI（正しさだけ）
`.github/workflows/dpdk.yml`（ランナーの VM、Ubuntu の `libdpdk-dev`）：
- `crates/rproxy-dpdk` の単体テスト（DPDK なし）と `tests/ring.rs`（root なし・`--no-huge`）：起動時の確かめを `net_ring` に、lcore のループを `net_memif` の組に通す（500 個のデータグラムの往復を比べる）。
- `scripts/test-dpdk.sh`（sudo・ヒュージページ）：本物の `rproxy-api` を `net_tap`（`dtap0`）と `net_af_packet`（veth）の 2 つのポートで動かし、カーネルの UDP のソケット（エコーのサーバとクライアント 20 個 × 70 個のデータグラム、0〜1472 バイト）と往復させて中身を比べる。ポートをまたぐルール（クライアントは af_packet、転送先は tap）、ポートの範囲、ping、`GET /capabilities`、`--check-kernel`、使えないときの `fallback`（`true` で degraded、`false` で起動しない）も。
- ランナーの数字は DPDK の速さについて何も言わない（仮想の NIC・共有の CPU）。ここには書かない。

### 実機での測り方（オーナーが手で回す）
1. **準備**（root）
   - ヒュージページ：`echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`（2 GiB。mempool の 65535 mbuf で約 160 MiB）。1 GB のページは起動時に `default_hugepagesz=1G hugepagesz=1G hugepages=4` を付けて `hugepages: {size: 1GB}`。
   - CPU：転送の lcore を専有させる。カーネルの起動の引数に `isolcpus=2-5 nohz_full=2-5 rcu_nocbs=2-5`（lcore と同じ CPU）を付けるのが確実。rproxy のワーカーは `global.performance.cpu_affinity` で lcore 以外の CPU に（重なると設定の誤り）。同じ NUMA ノードの CPU と NIC を使う（`cat /sys/bus/pci/devices/0000:3b:00.0/numa_node`）。
   - NIC を vfio-pci に付け替える（このポートはカーネルから見えなくなる。**SSH・管理の通信は別の NIC で**）：
     ```sh
     modprobe vfio-pci
     ip link set ens1f0 down
     dpdk-devbind.py --bind=vfio-pci 0000:3b:00.0      # 戻すとき：dpdk-devbind.py --bind=ixgbe 0000:3b:00.0（元のドライバ）
     dpdk-devbind.py --status
     ```
     IOMMU が要る（`intel_iommu=on iommu=pt` / AMD は既定）。仮想マシンなら `vfio-pci` の no-IOMMU（`echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`）か virtio の PMD。Mellanox（mlx5）は付け替えずに bifurcated のまま使える（`pci` にアドレス、ドライバは mlx5_core のまま）。
2. **設定**（`RPROXY_CONFIG`）
   ```yaml
   global:
     performance:
       cpu_affinity: "0-1"          # rproxy のワーカー（lcore と重ねない）
       dpdk:
         enabled: true
         lcores: "2-5"              # 最初の CPU が main lcore（転送もする）
         eal_args: ["--in-memory", "--file-prefix=rproxy"]
         ports:
           - pci: "0000:3b:00.0"
             rx_queues: 4           # lcore の数に合わせる（RSS で lcore に配る）
             tx_queues: 4           # lcore の数以上
             rx_desc: 1024
             tx_desc: 1024
             addresses: ["198.51.100.2/24"]
             gateway: 198.51.100.1  # 別のネットワークの転送先・クライアントへの次の宛先
         mempool: { mbufs: 65535, cache: 256 }
         hugepages: { size: 2MB }
         burst: 32
         fallback: false            # 測るときは、使えなければ起動しないほうが分かりやすい
   rules:
     - { protocol: udp, listen_addr: 198.51.100.2, listen_port: 5300, remote_addr: 198.51.100.10, remote_port: 5300 }
   ```
   `sudo rproxy-api --check-kernel --config rproxy.yaml` で先に確かめる（表の `dpdk.enabled=true` が `usable`、段階ごとの結果）。起動したら `GET /capabilities` の `performance.dpdk.active` と `mode`（DPDK の版・lcore・ポートのリンク）。
3. **比べ方**：同じマシン・同じ相手で、(a) 今の道（NIC をカーネルに戻し、同じアドレスで `udp_shards`・`busy_poll_usecs` を変えて最良のもの）、(b) DPDK の道（lcore 1・2・4）を交互に測る。負荷は別のマシンから（`pktgen-dpdk`・TRex、なければ `scripts/load/loadgen` の `udp-flood`（`--sources`・`--size 64`・`--pps 0`・`--threads`）を送る側、`udp-sink` を転送先で。`load.py` の「64 B max rate」と同じ道具）。見るもの：64 バイトの最大の pps と取りこぼし（送った数と転送先が受けた数）、1472 バイトの Gbit/s、p50 / p99 の遅延（往復）、lcore 以外の CPU 使用率、セッション（クライアントの数）1・1,000・100,000。`/rules` の `stats`（rx/tx バイト・`dropped`）と転送先の受信数を突き合わせる。
4. **結果をここに書く**（採らなかった場合も理由と一緒に）。

### 今の判断
- 実装と正しさの確かめまで。速さの数字はまだない（実機待ち）。
- 採るかどうかの目安：同じ NIC で、AF_XDP（#260 の段階 1、zero-copy）が DPDK の 64 バイトの pps の 7〜8 割以上に届くなら、**AF_XDP を採り DPDK は採らない**（NIC をカーネルと共有できる・vfio の付け替えもヒュージページも別のビルドも要らない・TCP も同じ枠組み）。DPDK が明らかに上回り、NIC を専有できる使い方（UDP の大量の小さいパケットだけを受ける専用のホスト）があるときだけ、別の成果物（x86_64 / aarch64 の glibc）として配ることを考える。
- 分かっている制限：IPv4 だけ、IP の断片は捨てる、ジャンボフレームなし（mbuf 1 つに収まるものだけ）、転送先の MAC は ARP の返事・GARP からだけ覚え直す、NAT のポートは送信元のアドレスごとに約 28,000（セッションが多いならアドレスを足す）、UDP のチェックサムは確かめずに差分だけ直す（壊れたものは転送先のカーネルが捨てる。veth の相手側がチェックサムを「ハードウェア」に任せていると `net_af_packet` で読むフレームは途中の値なので、veth で試すときは相手側で `ethtool -K <veth> tx off`）、セッションの表は NAT のポートごとの Mutex（RSS で返事が別の lcore に着くとき競合する。速さが問題なら Toeplitz を計算して返事が同じキューに着く NAT のポートを選ぶ）。

## 次の候補
- DPDK（#261）：上の「実験中」。実機の数字を待っている。
- カーネルでの転送（#260、進めている）：`global.performance.ebpf`（平文の L4 TCP を BPF の sockmap で）・`global.performance.xdp`（UDP を AF_XDP で）。オプトインで、起動時にテストデータを流して確かめた速い道だけを使う（`rproxy-api --check-kernel`）。枠組み（設定の形・試験・`GET /capabilities`）を先に入れ、速い道は 1 つずつ足して、ここに結果を書く。
- HTTP/2：プロファイルで残っているのは memcpy（約 11%）、アロケータ（約 12%）、カーネルの起床（約 7%）。h2 の書き込みをまとめて大きくする。
- 複数のコアの使い方（#194）：キューの深さで動きを変える（役ごとのパイプライン・コアごとの並列・バックプレッシャー）。
- メモリ（#185）：UDP のセッションのバッファをワーカーごとに共有する。
