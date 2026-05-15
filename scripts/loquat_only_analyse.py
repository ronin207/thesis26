#!/usr/bin/env python3
"""Analyse a loquat_only multi-signature sweep JSONL.

Reads results/loquat_only_multi_*.jsonl and produces:
  - A CSV summary at <jsonl>.csv with one row per (security_level, n_sigs).
  - A linearity check per security level (cycles_per_sig should be ~constant).
  - A pretty-printed table to stdout.

Usage:
  python3 scripts/loquat_only_analyse.py results/loquat_only_multi_*.jsonl
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path


def load(path: Path):
    rows = []
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def main():
    if len(sys.argv) != 2:
        print("usage: loquat_only_analyse.py <jsonl>", file=sys.stderr)
        sys.exit(2)
    path = Path(sys.argv[1])
    rows = load(path)
    rows.sort(key=lambda r: (r["security_level"], r["n_sigs"]))

    csv_path = path.with_suffix(".csv")
    phase_names = [p["name"] for p in rows[0]["phases"]]
    cols = (
        ["security_level", "n_sigs", "n_accepted", "total_cycles", "cycles_per_sig",
         "prove_wallclock_ms"]
        + [f"{p}_cycles" for p in phase_names]
        + [f"{p}_per_sig" for p in phase_names]
    )

    with csv_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            row = [
                r["security_level"],
                r["n_sigs"],
                r["n_accepted"],
                r["total_cycles"],
                r["cycles_per_sig"],
                f"{r['prove_wallclock_ms']:.2f}",
            ]
            row += [p["cycles_total"] for p in r["phases"]]
            row += [p["cycles_per_sig"] for p in r["phases"]]
            w.writerow(row)
    print(f"csv -> {csv_path}")

    print()
    print(f"{'λ':>3} {'n':>4} {'total_cycles':>15} {'cyc/sig':>13} "
          f"{'wall_ms':>9} {'accepted':>10}")
    print("-" * 60)
    for r in rows:
        print(f"{r['security_level']:>3} {r['n_sigs']:>4} "
              f"{r['total_cycles']:>15,} {r['cycles_per_sig']:>13,} "
              f"{r['prove_wallclock_ms']:>9.0f} "
              f"{r['n_accepted']}/{r['n_sigs']:>4}")

    print()
    print("LINEARITY CHECK (cycles_per_sig should be ~constant within a λ):")
    print(f"{'λ':>3}  {'min':>13} {'max':>13} {'spread':>8}")
    print("-" * 45)
    for sec in sorted({r["security_level"] for r in rows}):
        cps = [r["cycles_per_sig"] for r in rows if r["security_level"] == sec]
        lo, hi = min(cps), max(cps)
        spread = (hi - lo) / lo * 100 if lo > 0 else 0
        print(f"{sec:>3}  {lo:>13,} {hi:>13,} {spread:>7.2f}%")

    print()
    print("PHASE BREAKDOWN at n=32 (or largest available n per λ):")
    print(f"{'λ':>3} {'phase':<24} {'cycles':>15} {'%':>7} {'per_sig':>14}")
    print("-" * 75)
    for sec in sorted({r["security_level"] for r in rows}):
        cells = [r for r in rows if r["security_level"] == sec]
        if not cells:
            continue
        # pick n=32 if available, else max n
        target = next((r for r in cells if r["n_sigs"] == 32), max(cells, key=lambda r: r["n_sigs"]))
        print(f"{sec:>3} (n={target['n_sigs']}, total={target['total_cycles']:,})")
        for p in target["phases"]:
            print(f"    {p['name']:<24} {p['cycles_total']:>15,} "
                  f"{p['pct']:>6.2f}% {p['cycles_per_sig']:>14,}")


if __name__ == "__main__":
    main()
