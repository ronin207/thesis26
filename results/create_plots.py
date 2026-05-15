#!/usr/bin/env python3
"""Generate thesis figures from the M5 Pro bench JSONLs.

Reads:
    results/bench_1776147058.jsonl          (B7 + B5)
    results/bench_m5pro_b3.jsonl            (B3)
    results/bench_m5pro_remaining.jsonl     (B1, B2, B4)

Writes PNG + PDF figures into:
    results/figures/

Figures produced:
    fig_b3_nc_regression.{png,pdf}     — N_C(k) linear regression per (rev, policy)
    fig_b3_policy_overhead.{png,pdf}   — bar: constant added by each policy
    fig_b3_rev_overhead.{png,pdf}      — bar: constant added by rev depth
    fig_b4_backend_timing.{png,pdf}    — aurora vs fractal prove/verify times
    fig_b4_backend_proofsize.{png,pdf} — aurora vs fractal proof size
    fig_b5_griffin_stack.{png,pdf}     — Griffin cost breakdown
    fig_b7_d2_breakdown.{png,pdf}      — ShowCre D2 cost phases at measured k
"""

from __future__ import annotations

import json
from pathlib import Path
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np

HERE = Path(__file__).resolve().parent
OUT = HERE / "figures"
OUT.mkdir(exist_ok=True)

FILES = [
    HERE / "bench_1776147058.jsonl",
    HERE / "bench_m5pro_b3.jsonl",
    HERE / "bench_m5pro_remaining.jsonl",
]

# Publication-grade defaults.
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "legend.fontsize": 9,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "axes.grid": True,
    "grid.alpha": 0.3,
    "grid.linestyle": "--",
    "figure.dpi": 120,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})


def load_all():
    recs = []
    for p in FILES:
        if not p.exists():
            continue
        for line in p.read_text().splitlines():
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return recs


def save(fig, name):
    fig.savefig(OUT / f"{name}.png")
    fig.savefig(OUT / f"{name}.pdf")
    plt.close(fig)
    print(f"  → {name}.{{png,pdf}}")


# ────────────────────────────────────────────────────────────────
# B3 — constraint-count regression
# ────────────────────────────────────────────────────────────────

def plot_b3_nc_regression(recs):
    """Fit N_C(k) = a + b·k per (rev_depth, policy), plot lines + zoomed inset.

    All six (rev, policy) configurations share the same slope b within rounding,
    and intercepts differ by < 3,500 constraints. We therefore render:
      - main panel: a single fitted line + all 36 scatter points (thesis's
        linear-scaling claim)
      - inset panel: zoomed view at k=1 showing the tiny intercept differences
        across (rev, policy), with residuals to the main fit.
    """
    data = defaultdict(dict)  # (rev, pol) -> {k: constraint_count}
    for r in recs:
        if r.get("suite") != "B3" or r.get("type") != "sample":
            continue
        cfg = r.get("config", {})
        k = cfg.get("k")
        rev = cfg.get("rev_depth")
        pol = cfg.get("policy")
        cc = r.get("metrics", {}).get("constraint_count")
        if None in (k, rev, pol, cc):
            continue
        data[(rev, pol)][k] = cc

    if not data:
        print("  [skip] B3: no data")
        return

    colors = {"none": "#1f77b4", "gpa": "#2ca02c", "gpa_degree": "#d62728"}
    markers = {10: "o", 20: "s"}

    # Pooled fit across all configurations.
    all_ks, all_ys = [], []
    fit_lines = []
    for (rev, pol), kv in sorted(data.items()):
        ks_i = np.array(sorted(kv))
        ys_i = np.array([kv[k] for k in ks_i])
        b_i, a_i = np.polyfit(ks_i, ys_i, 1)
        fit_lines.append((rev, pol, a_i, b_i))
        all_ks.extend(ks_i.tolist())
        all_ys.extend(ys_i.tolist())
    all_ks = np.array(all_ks)
    all_ys = np.array(all_ys)
    b_pooled, a_pooled = np.polyfit(all_ks, all_ys, 1)
    r2 = 1 - np.sum((all_ys - (a_pooled + b_pooled * all_ks)) ** 2) / np.sum(
        (all_ys - all_ys.mean()) ** 2)

    fig, ax = plt.subplots(figsize=(7.0, 4.5))
    kfit = np.linspace(0, all_ks.max() * 1.05, 200)
    ax.plot(kfit, a_pooled + b_pooled * kfit, "k-", linewidth=1.3,
            label=fr"pooled fit: $N_C = {a_pooled:,.0f} + {b_pooled:,.0f}\,k$   ($R^2 = {r2:.5f}$)")

    for (rev, pol), kv in sorted(data.items()):
        ks_i = np.array(sorted(kv))
        ys_i = np.array([kv[k] for k in ks_i])
        ax.scatter(
            ks_i, ys_i,
            marker=markers.get(rev, "x"), s=42,
            color=colors.get(pol, "gray"),
            edgecolor="black", linewidth=0.5,
            label=f"pol={pol}, rev={rev}",
            zorder=3,
        )

    ax.set_xlabel(r"Number of TAs / credentials $k$")
    ax.set_ylabel(r"ShowCre R1CS constraint count $N_C$")
    ax.set_title(r"B3: $N_C(k)$ linear scaling across policy / revocation depth")
    ax.legend(loc="upper left", framealpha=0.95, fontsize=8, ncol=1)
    ax.ticklabel_format(style="sci", axis="y", scilimits=(6, 6))
    ax.set_xlim(-0.5, all_ks.max() * 1.08)

    # Inset: zoomed intercepts at k=1 with tiny overhead differences.
    # Place in lower-right of the main axes.
    from mpl_toolkits.axes_grid1.inset_locator import inset_axes
    axins = inset_axes(ax, width="40%", height="40%", loc="lower right",
                       borderpad=1.2)
    k1_vals = [(rev, pol, data[(rev, pol)].get(1)) for (rev, pol) in sorted(data.keys())
               if data[(rev, pol)].get(1) is not None]
    labels = [f"r={rev}\n{pol}" for rev, pol, _ in k1_vals]
    vals = [v for _, _, v in k1_vals]
    bar_colors = [colors.get(pol, "gray") for _, pol, _ in k1_vals]
    bars = axins.bar(range(len(vals)), vals, color=bar_colors, edgecolor="black",
                     linewidth=0.5)
    vmin, vmax = min(vals), max(vals)
    axins.set_ylim(vmin - (vmax - vmin) * 0.4, vmax + (vmax - vmin) * 0.25)
    axins.set_xticks(range(len(vals)))
    axins.set_xticklabels(labels, fontsize=6)
    axins.tick_params(axis="y", labelsize=6)
    axins.set_title(r"Intercept detail at $k=1$", fontsize=8)
    axins.set_ylabel(r"$N_C(1)$", fontsize=7)
    for bar, v in zip(bars, vals):
        axins.text(bar.get_x() + bar.get_width() / 2,
                   bar.get_height() + (vmax - vmin) * 0.03,
                   f"{v:,}", ha="center", va="bottom", fontsize=5.5)
    axins.grid(alpha=0.2)

    print(f"    B3 pooled fit N_C(k) = {a_pooled:,.0f} + {b_pooled:,.0f}·k   R² = {r2:.6f}")
    print("    B3 per-config fits:")
    for rev, pol, a, b in fit_lines:
        print(f"      rev={rev:>2}, pol={pol:<10}  a = {a:>12,.0f}   b = {b:>10,.0f}")

    save(fig, "fig_b3_nc_regression")


def plot_b3_policy_overhead(recs):
    """How many constraints does each policy predicate add (at fixed k=1, rev=20)?"""
    base = None
    diffs = {}
    for r in recs:
        if r.get("suite") != "B3" or r.get("type") != "sample":
            continue
        cfg = r.get("config", {})
        if cfg.get("k") != 1 or cfg.get("rev_depth") != 20:
            continue
        cc = r.get("metrics", {}).get("constraint_count")
        pol = cfg.get("policy")
        if pol == "none":
            base = cc
        else:
            diffs[pol] = cc

    if base is None or not diffs:
        print("  [skip] B3 policy overhead: missing data")
        return

    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    names = ["none"] + list(diffs.keys())
    totals = [base] + [diffs[n] for n in diffs]
    overhead = [0] + [t - base for t in totals[1:]]

    bars = ax.bar(names, totals, color=["#7f7f7f", "#2ca02c", "#d62728"], edgecolor="black")
    for bar, tot, ov in zip(bars, totals, overhead):
        lbl = f"{tot:,}" + (f"\n(+{ov:,})" if ov else "")
        ax.text(bar.get_x() + bar.get_width() / 2, tot + 3000, lbl,
                ha="center", va="bottom", fontsize=9)

    ax.set_ylabel(r"ShowCre constraints $N_C$")
    ax.set_title(r"B3: Policy overhead at $k=1$, rev=20")
    ax.set_ylim(0, max(totals) * 1.12)
    save(fig, "fig_b3_policy_overhead")


def plot_b3_rev_overhead(recs):
    """Constraint cost of increasing revocation depth from 10 → 20 (k=1, pol=none)."""
    vals = {}
    for r in recs:
        if r.get("suite") != "B3" or r.get("type") != "sample":
            continue
        cfg = r.get("config", {})
        if cfg.get("k") != 1 or cfg.get("policy") != "none":
            continue
        vals[cfg.get("rev_depth")] = r.get("metrics", {}).get("constraint_count")

    if len(vals) < 2:
        print("  [skip] B3 rev overhead: missing data")
        return

    fig, ax = plt.subplots(figsize=(5.0, 3.5))
    revs = sorted(vals)
    totals = [vals[r] for r in revs]
    bars = ax.bar([f"rev={r}" for r in revs], totals,
                  color=["#1f77b4", "#ff7f0e"], edgecolor="black")
    delta = totals[1] - totals[0]
    for bar, tot in zip(bars, totals):
        ax.text(bar.get_x() + bar.get_width() / 2, tot + 3000, f"{tot:,}",
                ha="center", va="bottom", fontsize=9)
    ax.set_ylabel(r"ShowCre constraints $N_C$")
    ax.set_title(rf"B3: Revocation-depth overhead at $k=1$, pol=none  ($\Delta = {delta:,}$)")
    ax.set_ylim(0, max(totals) * 1.12)
    save(fig, "fig_b3_rev_overhead")


# ────────────────────────────────────────────────────────────────
# B4 — backend comparison
# ────────────────────────────────────────────────────────────────

def plot_b4_backend(recs):
    """aurora vs fractal at fixed circuit: prove/verify timing + proof size."""
    agg = defaultdict(lambda: defaultdict(list))  # variant -> metric -> [values]
    for r in recs:
        if r.get("suite") != "B4" or r.get("type") != "sample" or r.get("is_warmup"):
            continue
        v = r["variant"]
        ph = r.get("phases", {})
        m = r.get("metrics", {})
        if "prove_ms" in ph:
            agg[v]["prove_ms"].append(ph["prove_ms"])
        if "verify_ms" in ph:
            agg[v]["verify_ms"].append(ph["verify_ms"])
        if "proof_bytes" in m:
            agg[v]["proof_bytes"].append(m["proof_bytes"])

    if "aurora" not in agg:
        print("  [skip] B4: no aurora data")
        return

    variants = list(agg.keys())

    # ── Figure 1: timing
    fig, ax = plt.subplots(figsize=(5.5, 3.8))
    x = np.arange(len(variants))
    w = 0.36
    prove_mean = [np.mean(agg[v]["prove_ms"]) / 1000 for v in variants]
    prove_std = [np.std(agg[v]["prove_ms"]) / 1000 for v in variants]
    verify_mean = [np.mean(agg[v]["verify_ms"]) / 1000 for v in variants]
    verify_std = [np.std(agg[v]["verify_ms"]) / 1000 for v in variants]

    bp = ax.bar(x - w / 2, prove_mean, w, yerr=prove_std,
                label="prove", color="#1f77b4", capsize=4, edgecolor="black")
    bv = ax.bar(x + w / 2, verify_mean, w, yerr=verify_std,
                label="verify", color="#ff7f0e", capsize=4, edgecolor="black")

    for bars, means in [(bp, prove_mean), (bv, verify_mean)]:
        for bar, m in zip(bars, means):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.4,
                    f"{m:.1f}s", ha="center", va="bottom", fontsize=9)

    ax.set_xticks(x)
    ax.set_xticklabels(variants)
    ax.set_ylabel("Time (s)")
    ax.set_title("B4: Backend prove / verify (k=2, rev=20, n=10 runs)")
    ax.legend()
    save(fig, "fig_b4_backend_timing")

    # ── Figure 2: proof size (linear scale; values are close)
    fig, ax = plt.subplots(figsize=(5.0, 3.5))
    pbs = [np.mean(agg[v]["proof_bytes"]) / 1024 for v in variants]
    pbs_mb = [p / 1024 for p in pbs]
    bars = ax.bar(variants, pbs_mb,
                  color=["#1f77b4", "#2ca02c"][: len(variants)],
                  edgecolor="black")
    for bar, mb in zip(bars, pbs_mb):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                f"{mb:.2f} MB", ha="center", va="bottom", fontsize=9)
    ax.set_ylabel("Proof size (MB)")
    ax.set_title("B4: Proof size per backend (k=2, rev=20)")
    ax.set_ylim(0, max(pbs_mb) * 1.15)
    save(fig, "fig_b4_backend_proofsize")


# ────────────────────────────────────────────────────────────────
# B5 — Griffin hash breakdown
# ────────────────────────────────────────────────────────────────

def plot_b5_griffin(recs):
    """Two-panel B5 figure:
      (a) prove/verify timing for variants that ran aurora (full vs loquat-only)
      (b) constraint-count decomposition across all four variants
    """
    agg = defaultdict(lambda: defaultdict(list))
    for r in recs:
        if r.get("suite") != "B5" or r.get("type") != "sample" or r.get("is_warmup"):
            continue
        v = r["variant"]
        for k, val in r.get("phases", {}).items():
            agg[v][k].append(val)
        for k, val in r.get("metrics", {}).items():
            if isinstance(val, (int, float)):
                agg[v][k].append(val)

    if not agg:
        print("  [skip] B5: no data")
        return

    timed_variants = [v for v in agg if agg[v].get("prove_ms")]
    cc_order = ["merkle_only", "loquat_only", "loquat_only_aurora", "full_credential"]
    cc_variants = [v for v in cc_order if v in agg and agg[v].get("constraint_count")]

    fig, (axL, axR) = plt.subplots(1, 2, figsize=(10.5, 4.2),
                                   gridspec_kw={"width_ratios": [1, 1.2]})

    # ── Left panel: prove/verify timing (aurora-bearing variants only)
    x = np.arange(len(timed_variants))
    w = 0.38
    prove = [np.mean(agg[v]["prove_ms"]) / 1000 for v in timed_variants]
    verify = [np.mean(agg[v]["verify_ms"]) / 1000 for v in timed_variants]
    bp = axL.bar(x - w / 2, prove, w, label="prove", color="#1f77b4", edgecolor="black")
    bv = axL.bar(x + w / 2, verify, w, label="verify", color="#ff7f0e", edgecolor="black")
    for bars, vals in [(bp, prove), (bv, verify)]:
        for bar, val in zip(bars, vals):
            axL.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.8,
                     f"{val:.1f}s", ha="center", va="bottom", fontsize=8)
    axL.set_xticks(x)
    axL.set_xticklabels(timed_variants, rotation=10, ha="right", fontsize=9)
    axL.set_ylabel("Wall time (s)")
    axL.set_title("(a) Aurora prove / verify time")
    axL.legend(loc="upper right")
    axL.set_ylim(0, max(max(prove), max(verify)) * 1.2)

    # ── Right panel: constraint-count decomposition with % of full_credential
    full_cc = float(np.mean(agg["full_credential"]["constraint_count"])) if \
        agg.get("full_credential", {}).get("constraint_count") else None
    ccs = [np.mean(agg[v]["constraint_count"]) for v in cc_variants]
    colors = ["#9467bd", "#17becf", "#2ca02c", "#d62728"][: len(cc_variants)]
    bars = axR.bar(cc_variants, ccs, color=colors, edgecolor="black")
    for bar, cc in zip(bars, ccs):
        pct = (100 * cc / full_cc) if full_cc else 0
        axR.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.02,
                 f"{cc:,.0f}\n({pct:.1f}%)", ha="center", va="bottom", fontsize=8)
    axR.set_ylabel(r"R1CS constraints $N_C$")
    axR.set_title(f"(b) Constraint decomposition vs full credential ({int(full_cc):,})")
    axR.set_ylim(0, max(ccs) * 1.22)
    plt.setp(axR.get_xticklabels(), rotation=10, ha="right", fontsize=9)

    fig.suptitle("B5: Loquat + Griffin cost breakdown at k=2, rev=20", y=1.01)
    save(fig, "fig_b5_griffin_stack")


# ────────────────────────────────────────────────────────────────
# B7 — D2 breakdown at measured k
# ────────────────────────────────────────────────────────────────

def plot_b7_d2(recs):
    """Stacked bar of indexer / prove / verify phases per (variant, config_key)."""
    agg = defaultdict(lambda: defaultdict(list))
    for r in recs:
        if r.get("suite") != "B7" or r.get("type") != "sample" or r.get("is_warmup"):
            continue
        key = f"{r['variant']}\n{r['config_key']}"
        ph = r.get("phases", {})
        for k, val in ph.items():
            agg[key][k].append(val)

    if not agg:
        print("  [skip] B7: no data")
        return

    keys = list(agg.keys())
    phase_names = ["indexer_ms", "prove_ms", "verify_ms"]
    colors = ["#8c564b", "#1f77b4", "#ff7f0e"]

    bot = np.zeros(len(keys))
    fig, ax = plt.subplots(figsize=(7.5, 4.0))
    for pname, col in zip(phase_names, colors):
        vals = np.array([np.mean(agg[k].get(pname, [0])) / 1000 for k in keys])
        ax.bar(keys, vals, bottom=bot, label=pname.replace("_ms", ""),
               color=col, edgecolor="black")
        for i, (v, b) in enumerate(zip(vals, bot)):
            if v > 2:
                ax.text(i, b + v / 2, f"{v:.1f}s", ha="center", va="center",
                        color="white", fontsize=8)
        bot += vals

    ax.set_ylabel("Wall time (s)")
    ax.set_title("B7: ShowCre D2 phase decomposition")
    ax.legend(loc="upper right")
    plt.setp(ax.get_xticklabels(), rotation=0, fontsize=8)
    save(fig, "fig_b7_d2_breakdown")


def main():
    recs = load_all()
    print(f"Loaded {len(recs)} records")
    print(f"Writing figures to {OUT}/")

    plot_b3_nc_regression(recs)
    plot_b3_policy_overhead(recs)
    plot_b3_rev_overhead(recs)
    plot_b4_backend(recs)
    plot_b5_griffin(recs)
    plot_b7_d2(recs)

    print("Done.")


if __name__ == "__main__":
    main()
