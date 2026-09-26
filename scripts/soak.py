#!/usr/bin/env python3
"""長時間の負荷テスト（ソーク）。rproxy-api を起動して TCP と UDP の負荷をかけ続け、
RSS とファイル記述子の数が増え続けないことを確かめる（issue #8）。

    cargo build --release && scripts/soak.py --duration 1800 [--bin target/release/rproxy-api]

- TCP: 接続を開け閉めし続けるワーカー（既定 200）と、つなぎっぱなしで送り続ける接続（既定 20）
- UDP: 送信元ポートを変えながら送り続け、セッションの作成と破棄（udp_idle_secs）を繰り返す
- 10 秒ごとに rproxy の RSS・fd の数・/rules の接続数を CSV（--out）に書く

合格の条件（どれかが外れたら終了コード 1）:
- 負荷を止めて UDP のセッションが切れた後の fd の数が、負荷をかける前 + 20 以内に戻る
- 後半 1/4 の RSS の平均が、前半 1/4（最初の 1 割を除く）の平均の 1.5 倍を超えない（増え続けていない）
- 転送の失敗が全体の 0.1% 以下
"""

import argparse
import asyncio
import csv
import json
import os
import random
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request

API_PORT = 18500
TCP_LISTEN, TCP_BACKEND = 18501, 18511
UDP_LISTEN, UDP_BACKEND = 18502, 18512
UDP_IDLE = 5


def api(method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{API_PORT}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read() or b"null")


def proc_stats(pid):
    rss = 0
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                rss = int(line.split()[1])
    fds = len(os.listdir(f"/proc/{pid}/fd"))
    return rss, fds


class Counters:
    def __init__(self):
        self.ok = 0
        self.failed = 0
        self.bytes = 0


async def tcp_echo_server():
    async def handle(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
    return await asyncio.start_server(handle, "127.0.0.1", TCP_BACKEND, backlog=1024)


class UdpEcho(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.transport.sendto(data, addr)


async def tcp_churn(stop, c):
    """connect, send a few KB, read it back, close; over and over"""
    while not stop.is_set():
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", TCP_LISTEN), 5)
            payload = os.urandom(random.randint(1, 8192))
            writer.write(payload)
            await writer.drain()
            got = await asyncio.wait_for(reader.readexactly(len(payload)), 5)
            writer.close()
            await writer.wait_closed()
            if got == payload:
                c.ok += 1
                c.bytes += len(payload) * 2
            else:
                c.failed += 1
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            c.failed += 1
            await asyncio.sleep(0.1)


async def tcp_stream(stop, c):
    """one long-lived connection that keeps sending"""
    while not stop.is_set():
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", TCP_LISTEN), 5)
            while not stop.is_set():
                payload = os.urandom(16384)
                writer.write(payload)
                await writer.drain()
                await asyncio.wait_for(reader.readexactly(len(payload)), 5)
                c.ok += 1
                c.bytes += len(payload) * 2
                await asyncio.sleep(0.05)
            writer.close()
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            c.failed += 1
            await asyncio.sleep(0.5)


async def udp_client(stop, c):
    """a client that changes its source port every few seconds (a new session each time)"""
    loop = asyncio.get_running_loop()
    while not stop.is_set():
        replies = asyncio.Queue()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                replies.put_nowait(data)

        transport, _ = await loop.create_datagram_endpoint(Client, remote_addr=("127.0.0.1", UDP_LISTEN))
        until = time.monotonic() + random.uniform(1, 4)
        while time.monotonic() < until and not stop.is_set():
            payload = os.urandom(random.randint(16, 1200))
            transport.sendto(payload)
            try:
                got = await asyncio.wait_for(replies.get(), 2)
                if got == payload:
                    c.ok += 1
                    c.bytes += len(payload) * 2
                else:
                    c.failed += 1
            except asyncio.TimeoutError:
                c.failed += 1
            await asyncio.sleep(0.02)
        transport.close()


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--duration", type=int, default=600, help="負荷をかける秒数（既定 600）")
    ap.add_argument("--bin", default=os.path.join(os.path.dirname(__file__), "..", "target", "release", "rproxy-api"))
    ap.add_argument("--churn", type=int, default=200, help="TCP の開け閉めのワーカー数")
    ap.add_argument("--streams", type=int, default=20, help="TCP のつなぎっぱなしの接続数")
    ap.add_argument("--udp", type=int, default=100, help="UDP のクライアント数")
    ap.add_argument("--out", default="soak.csv")
    args = ap.parse_args()

    work = tempfile.mkdtemp(prefix="rproxy-soak-")
    log = open(os.path.join(work, "rproxy.log"), "w")
    env = {"PATH": os.environ.get("PATH", ""), "RPROXY_API_PORT": str(API_PORT), "RPROXY_LOG_LEVEL": "warn"}
    rp = subprocess.Popen([os.path.abspath(args.bin)], cwd=work, env=env, stdout=log, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{API_PORT}/healthz", timeout=1)
                break
            except OSError:
                await asyncio.sleep(0.2)
        tcp_server = await tcp_echo_server()
        udp_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(UdpEcho, local_addr=("127.0.0.1", UDP_BACKEND))
        api("POST", "/rules", {"protocol": "tcp", "listen_addr": "127.0.0.1", "listen_port": TCP_LISTEN,
                               "remote_addr": "127.0.0.1", "remote_port": TCP_BACKEND})
        api("POST", "/rules", {"protocol": "udp", "listen_addr": "127.0.0.1", "listen_port": UDP_LISTEN,
                               "remote_addr": "127.0.0.1", "remote_port": UDP_BACKEND, "udp_idle_secs": UDP_IDLE})
        await asyncio.sleep(1)
        base_rss, base_fds = proc_stats(rp.pid)
        print(f"baseline: RSS {base_rss} kB, fds {base_fds}", flush=True)

        stop = asyncio.Event()
        c = Counters()
        tasks = [asyncio.create_task(tcp_churn(stop, c)) for _ in range(args.churn)]
        tasks += [asyncio.create_task(tcp_stream(stop, c)) for _ in range(args.streams)]
        tasks += [asyncio.create_task(udp_client(stop, c)) for _ in range(args.udp)]

        samples = []
        started = time.monotonic()
        with open(args.out, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["elapsed_s", "rss_kb", "fds", "tcp_connections", "udp_sessions", "ok", "failed", "bytes"])
            while (elapsed := time.monotonic() - started) < args.duration:
                await asyncio.sleep(10)
                rss, fds = proc_stats(rp.pid)
                rules = {(r["protocol"]): r for r in api("GET", "/rules")}
                row = [int(elapsed), rss, fds, rules["tcp"]["connections"], rules["udp"]["connections"], c.ok, c.failed, c.bytes]
                samples.append(row)
                w.writerow(row)
                f.flush()
                print(" ".join(f"{k}={v}" for k, v in zip(["t", "rss", "fds", "tcp", "udp", "ok", "failed", "bytes"], row)), flush=True)

        stop.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        # let UDP sessions expire and closed TCP connections go away
        await asyncio.sleep(UDP_IDLE * 3)
        end_rss, end_fds = proc_stats(rp.pid)
        tcp_server.close()
        udp_transport.close()
    finally:
        rp.send_signal(signal.SIGTERM)
        try:
            rp.wait(10)
        except subprocess.TimeoutExpired:
            rp.kill()

    # skip the first tenth (buffers and tasks are still being allocated)
    warm = len(samples) // 10
    quarter = max(1, (len(samples) - warm) // 4)
    early = sum(s[1] for s in samples[warm:warm + quarter]) / quarter
    late = sum(s[1] for s in samples[-quarter:]) / quarter
    total = c.ok + c.failed
    fail_rate = c.failed / total if total else 1
    print(f"after load: RSS {end_rss} kB, fds {end_fds} (baseline {base_fds})")
    print(f"RSS early {early:.0f} kB, late {late:.0f} kB ({late / early:.2f}x)")
    print(f"transfers ok={c.ok} failed={c.failed} ({fail_rate:.4%}), {c.bytes / 1e9:.2f} GB")
    problems = []
    if end_fds > base_fds + 20:
        problems.append(f"fds did not come back: {base_fds} -> {end_fds}")
    if late > early * 1.5:
        problems.append(f"RSS kept growing: {early:.0f} -> {late:.0f} kB")
    if fail_rate > 0.001:
        problems.append(f"too many failed transfers: {fail_rate:.4%}")
    if problems:
        print("FAIL: " + "; ".join(problems) + f" (rproxy log: {work}/rproxy.log)")
        sys.exit(1)
    print("OK")


if __name__ == "__main__":
    asyncio.run(main())
