#!/usr/bin/env python3
"""Summarises a criterion run compared with a saved baseline (.github/workflows/bench.yml).

    scripts/bench-summary.py <criterion dir> <threshold %> <baseline name> > summary.md

Reads <dir>/<group>/<bench>/{new,<baseline>,change}/*.json as criterion writes
them, prints a Markdown table, and prints a GitHub Actions `::warning::` line
(on stderr, which the runner also reads) for every benchmark that got slower
by more than the threshold with the whole 95 % confidence interval above zero.
Always exits 0: a regression is a warning, not a failure.
"""

import json
import sys
from pathlib import Path


def load(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def fmt_time(ns):
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("µs", 1e3)):
        if ns >= scale:
            return f"{ns / scale:.3g} {unit}"
    return f"{ns:.3g} ns"


def fmt_rate(ns, throughput):
    if not throughput or ns <= 0:
        return ""
    (kind, amount), = throughput.items()
    per_sec = amount * 1e9 / ns
    if kind == "Bytes":
        if per_sec >= 2**30:
            return f"{per_sec / 2**30:.3g} GiB/s"
        return f"{per_sec / 2**20:.3g} MiB/s"
    for unit, scale in (("M", 1e6), ("k", 1e3)):
        if per_sec >= scale:
            return f"{per_sec / scale:.3g} {unit}/s"
    return f"{per_sec:.3g} /s"


def main():
    root, threshold, baseline = Path(sys.argv[1]), float(sys.argv[2]), sys.argv[3]
    rows, regressions = [], []
    for bench in sorted(root.glob("**/new/benchmark.json")):
        d = bench.parent.parent
        meta = load(bench) or {}
        name = meta.get("full_id") or str(d.relative_to(root))
        new = load(d / "new" / "estimates.json")
        base = load(d / baseline / "estimates.json")
        change = load(d / "change" / "estimates.json")
        if not new:
            continue
        new_ns = new["mean"]["point_estimate"]
        head = f"{fmt_time(new_ns)} ({fmt_rate(new_ns, meta.get('throughput'))})".replace(" ()", "")
        if not base or not change:
            rows.append((name, "—", head, "no baseline", ""))
            continue
        base_ns = base["mean"]["point_estimate"]
        c = change["mean"]
        pct, lo, hi = (100 * c["point_estimate"], 100 * c["confidence_interval"]["lower_bound"],
                       100 * c["confidence_interval"]["upper_bound"])
        mark = ""
        if pct > threshold and lo > 0:
            mark = "⚠️ slower"
            regressions.append((name, pct))
        elif pct < -threshold and hi < 0:
            mark = "faster"
        base_txt = f"{fmt_time(base_ns)} ({fmt_rate(base_ns, meta.get('throughput'))})".replace(" ()", "")
        rows.append((name, base_txt, head, f"{pct:+.1f} % [{lo:+.1f}, {hi:+.1f}]", mark))

    out = ["## Benchmarks (merge base → PR)", ""]
    if not rows:
        out.append("No criterion results found.")
    else:
        if regressions:
            out.append(f"**{len(regressions)} benchmark(s) slower by more than {threshold:g} %** "
                       "(GitHub's runners are noisy: re-run the job before trusting a single result).")
        else:
            out.append(f"No benchmark is slower by more than {threshold:g} %.")
        out += ["", "| benchmark | merge base | PR | change (mean, 95 % CI) | |", "|---|---|---|---|---|"]
        out += [f"| `{n}` | {b} | {h} | {c} | {m} |" for n, b, h, c, m in rows]
        out += ["", "Times are the mean per iteration; lower is better. Both runs are on the same runner in the same job."]
    print("\n".join(out))
    for name, pct in regressions:
        print(f"::warning title=Benchmark regression::{name} is {pct:.1f} % slower than the merge base", file=sys.stderr)


if __name__ == "__main__":
    main()
