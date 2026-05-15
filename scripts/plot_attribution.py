"""Plot the three-level attribution + speedup ceiling figures.

Reads `results/loquat_three_level_20260512_024956.jsonl` and writes PNGs into
`results/figures/`.

Three figures:
  fig1_headline_lambda128.png   — cost decomposition stacked bar + speedup ceiling bars
  fig2_cross_lambda.png         — three-security-level cost decomposition
  fig3_phase_lambda128.png      — Algorithm-7 phase decomposition at λ=128
"""

import json
import os
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "results" / "loquat_three_level_20260512_024956.jsonl"
OUT = ROOT / "results" / "figures"
OUT.mkdir(parents=True, exist_ok=True)

# Microbenched primitive costs (from companion JSONs).
CYC_PER_GRIFFIN = 910_143
CYC_PER_FP127_MUL = 243
CYC_PER_FP2_MUL = 1_394
FP127_MULS_PER_GRIFFIN = 2_580  # avg estimate, see §5 of spec

# Projected precompile costs (RISC0-modeled).
PC_GRIFFIN = 100
PC_FP127 = 5
PC_FP2 = 100  # cyc/op for add/sub/mul

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

rows = [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]
by_lam = {r["security_level"]: r for r in rows}


def decompose(row):
    """Return dict with cycle counts for the four-block decomposition."""
    total = row["total_cycles"]
    griffin_perms = row["total_griffin_perms"]
    fp127_total = row["total_fp127_muls"]
    fp2_total = row["total_fp2_muls"]

    griffin_cyc = griffin_perms * CYC_PER_GRIFFIN
    fp127_in_griffin = griffin_perms * FP127_MULS_PER_GRIFFIN
    fp127_outside = max(0, fp127_total - fp127_in_griffin)
    fp127_outside_cyc = fp127_outside * CYC_PER_FP127_MUL
    fp2_wrappers_cyc = fp2_total * (CYC_PER_FP2_MUL - 4 * CYC_PER_FP127_MUL)
    fp_mul_inside_griffin_cyc = fp127_in_griffin * CYC_PER_FP127_MUL
    griffin_other_cyc = griffin_cyc - fp_mul_inside_griffin_cyc
    floor = max(0, total - griffin_cyc - fp127_outside_cyc - fp2_wrappers_cyc)

    return {
        "total": total,
        "griffin": griffin_cyc,
        "fp_in_griffin": fp_mul_inside_griffin_cyc,
        "griffin_other": griffin_other_cyc,
        "fp_outside": fp127_outside_cyc,
        "fp2_wrap": fp2_wrappers_cyc,
        "floor": floor,
        "griffin_perms": griffin_perms,
        "fp127_total": fp127_total,
        "fp2_total": fp2_total,
    }


def projections(row):
    """Cycle count under each precompile combination."""
    d = decompose(row)
    griffin_perms = d["griffin_perms"]
    fp127_total = d["fp127_total"]
    fp2_total = d["fp2_total"]
    fp127_outside = fp127_total - griffin_perms * FP127_MULS_PER_GRIFFIN

    baseline = d["total"]

    # +Griffin: replace griffin work with PC_GRIFFIN per perm
    g_only = baseline - d["griffin"] + griffin_perms * PC_GRIFFIN

    # +Griffin + F_p mul: also replace the outside-Griffin F_p mul cost
    g_fp = g_only - d["fp_outside"] + fp127_outside * PC_FP127

    # +Griffin + F_p²: replace BOTH griffin work AND the F_p² + its inner F_p muls.
    # The F_p² mul wrapper is 1394 cyc = 4×F_p mul (972) + 422 wrapper. When the
    # F_p² precompile attacks it, all 1394 → 100. So we save the full
    # fp2_total * 1394 instead of just the wrapper.
    fp2_full_cyc = fp2_total * CYC_PER_FP2_MUL
    g_fp2 = (
        baseline
        - d["griffin"]
        + griffin_perms * PC_GRIFFIN
        - fp2_full_cyc
        + fp2_total * PC_FP2
    )
    # F_p muls outside griffin AND outside F_p² mul wrappers: the residual.
    fp127_outside_fp2 = fp127_outside - 4 * fp2_total
    g_fp2 = max(g_fp2, baseline * 0.01)  # safety

    # +Griffin + F_p² + F_p mul: also replace the F_p muls that remain
    # outside griffin and outside fp2 muls (Legendre PRF only)
    g_all = g_fp2 - max(0, fp127_outside_fp2) * CYC_PER_FP127_MUL + max(0, fp127_outside_fp2) * PC_FP127

    return {
        "baseline": baseline,
        "g_only": g_only,
        "g_fp": g_fp,
        "g_fp2": g_fp2,
        "g_all": g_all,
    }


# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

# Visually: Griffin family in oranges/browns; F_p² in teal; F_p outside in blue;
# floor in slate-gray. Hierarchy = importance.
COL_GRIFFIN_FP = "#C65D2E"      # F_p mul inside Griffin (the dominant slice)
COL_GRIFFIN_OTHER = "#E8A87C"   # Griffin's non-F_p-mul work
COL_FP_OUTSIDE = "#5B8DBE"      # F_p mul outside Griffin (Legendre)
COL_FP2 = "#4CB5AE"             # F_p² mul wrappers
COL_FLOOR = "#5A6675"           # rv32im control-flow floor


# ---------------------------------------------------------------------------
# Figure 1: headline composite at λ=128
# ---------------------------------------------------------------------------

def fig1():
    d128 = decompose(by_lam[128])
    p128 = projections(by_lam[128])
    total = d128["total"]

    fig, (axL, axR) = plt.subplots(1, 2, figsize=(13, 5.4), gridspec_kw={"width_ratios": [1.2, 1.4]})

    # ----- Left: stacked-bar cost decomposition (single bar, horizontal) -----
    blocks = [
        ("F_p mul inside Griffin", d128["fp_in_griffin"], COL_GRIFFIN_FP),
        ("Griffin (non-F_p-mul work)", d128["griffin_other"], COL_GRIFFIN_OTHER),
        ("F_p mul outside Griffin", d128["fp_outside"], COL_FP_OUTSIDE),
        (r"F_$p^2$ mul wrappers", d128["fp2_wrap"], COL_FP2),
        ("rv32im control-flow floor", d128["floor"], COL_FLOOR),
    ]
    left = 0.0
    for label, cyc, col in blocks:
        pct = 100.0 * cyc / total
        axL.barh([0], [cyc], left=[left], height=0.6, color=col, edgecolor="white", linewidth=1.0)
        if pct >= 4:
            axL.text(
                left + cyc / 2.0,
                0,
                f"{pct:.1f}%",
                ha="center",
                va="center",
                color="white",
                fontsize=11,
                fontweight="bold",
            )
        # Thin slices: omit inline label; their percentages appear in the legend.
        left += cyc

    axL.set_yticks([])
    axL.set_ylim(-0.5, 1.2)
    axL.set_xlim(0, total * 1.005)
    axL.set_xlabel("rv32im cycles per Loquat verify (λ=128)")
    axL.set_title(
        f"Cycle decomposition — Loquat verify at λ=128\n"
        f"total = {total/1e6:.1f}M cyc; Griffin dominates 92.9%",
        fontsize=12,
        pad=12,
    )

    # Legend below — include the percentage in each label so thin slices are readable
    legend_labels = [
        f"{lab}  ({100.0 * cyc / total:.2f}%)" for lab, cyc, _ in blocks
    ]
    handles = [plt.Rectangle((0, 0), 1, 1, color=col) for _, _, col in blocks]
    axL.legend(
        handles,
        legend_labels,
        loc="upper center",
        bbox_to_anchor=(0.5, -0.18),
        ncol=2,
        frameon=False,
        fontsize=9.5,
    )

    # Spines: keep only bottom
    for spine in ("top", "right", "left"):
        axL.spines[spine].set_visible(False)

    # ----- Right: speedup-ceiling bars -----
    configs = [
        ("none\n(baseline)", p128["baseline"], "#9AA5B1"),
        ("+ Griffin", p128["g_only"], COL_GRIFFIN_FP),
        ("+ Griffin\n+ F_p mul", p128["g_fp"], "#D77860"),
        ("+ Griffin\n+ F_$p^2$", p128["g_fp2"], COL_FP2),
        ("+ all three", p128["g_all"], "#3A8C86"),
    ]

    xs = np.arange(len(configs))
    heights = np.array([p128["baseline"] / c[1] for c in configs])
    bar_colors = [c[2] for c in configs]
    bars = axR.bar(xs, heights, color=bar_colors, edgecolor="white", width=0.65)

    for i, (b, sp) in enumerate(zip(bars, heights)):
        cy = configs[i][1]
        label = f"{sp:.1f}×\n{cy/1e6:.1f}M cyc"
        axR.text(
            b.get_x() + b.get_width() / 2.0,
            b.get_height() + 0.6,
            label,
            ha="center",
            va="bottom",
            fontsize=9.5,
            fontweight="bold",
        )

    # Ceiling line (drawn lighter so labels are not eclipsed)
    ceiling = heights[3]  # Griffin + F_p²
    axR.axhline(ceiling, color=COL_FLOOR, linestyle=":", linewidth=1.2, alpha=0.55)
    # Place the ceiling annotation on the LEFT side, above the short bars,
    # where it doesn't collide with the tall-bar value labels.
    axR.annotate(
        "control-flow\nfloor caps\nspeedup here",
        xy=(0.7, ceiling),
        xytext=(0.7, ceiling * 0.72),
        ha="center",
        va="center",
        fontsize=9,
        color=COL_FLOOR,
        style="italic",
        arrowprops=dict(arrowstyle="->", color=COL_FLOOR, lw=0.9, alpha=0.7),
    )

    axR.set_xticks(xs)
    axR.set_xticklabels([c[0] for c in configs], fontsize=9.5)
    axR.set_ylabel("speedup vs baseline")
    axR.set_ylim(0, max(heights) * 1.20)
    axR.set_title(
        "Projected speedup under precompile combinations (λ=128)\n"
        "F_$p^2$ precompile, not F_p mul, breaks the 15× barrier",
        fontsize=12,
        pad=12,
    )
    for spine in ("top", "right"):
        axR.spines[spine].set_visible(False)
    axR.yaxis.grid(True, alpha=0.3)
    axR.set_axisbelow(True)

    fig.tight_layout()
    out = OUT / "fig1_headline_lambda128.png"
    fig.savefig(out, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out}")


# ---------------------------------------------------------------------------
# Figure 2: cross-λ comparison
# ---------------------------------------------------------------------------

def fig2():
    lams = [80, 100, 128]
    decomps = [decompose(by_lam[l]) for l in lams]

    fig, ax = plt.subplots(figsize=(8.5, 5.2))

    component_order = [
        ("F_p mul inside Griffin", "fp_in_griffin", COL_GRIFFIN_FP),
        ("Griffin (non-F_p-mul)", "griffin_other", COL_GRIFFIN_OTHER),
        ("F_p mul outside Griffin", "fp_outside", COL_FP_OUTSIDE),
        (r"F_$p^2$ mul wrappers", "fp2_wrap", COL_FP2),
        ("rv32im control-flow floor", "floor", COL_FLOOR),
    ]

    xs = np.arange(len(lams))
    bottoms = np.zeros(len(lams))
    handles = []
    for label, key, col in component_order:
        values = np.array([d[key] / 1e6 for d in decomps])
        bars = ax.bar(
            xs,
            values,
            bottom=bottoms,
            color=col,
            edgecolor="white",
            linewidth=0.8,
            width=0.55,
            label=label,
        )
        handles.append(bars)
        # Percent labels for big slices
        for i, v in enumerate(values):
            pct = 100.0 * decomps[i][key] / decomps[i]["total"]
            if pct >= 5:
                ax.text(
                    xs[i],
                    bottoms[i] + v / 2.0,
                    f"{pct:.1f}%",
                    ha="center",
                    va="center",
                    color="white",
                    fontsize=9,
                    fontweight="bold",
                )
        bottoms += values

    # Total labels at top
    for i, d in enumerate(decomps):
        ax.text(
            xs[i],
            d["total"] / 1e6 + 12,
            f"{d['total']/1e6:.0f}M\n{d['griffin_perms']} Griffin",
            ha="center",
            va="bottom",
            fontsize=9.5,
        )

    ax.set_xticks(xs)
    ax.set_xticklabels([f"λ = {l}" for l in lams])
    ax.set_ylabel("rv32im cycles per verify (millions)")
    ax.set_title(
        "Three-level cost decomposition stays nearly invariant across security levels\n"
        "Griffin always ≈93%, F_$p^2$ wrappers <2%, control-flow floor ≈5%",
        fontsize=11.5,
        pad=12,
    )
    ax.set_ylim(0, max(d["total"] for d in decomps) / 1e6 * 1.15)
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.10), ncol=3, frameon=False, fontsize=9.5)

    fig.tight_layout()
    out = OUT / "fig2_cross_lambda.png"
    fig.savefig(out, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out}")


# ---------------------------------------------------------------------------
# Figure 3: Algorithm-7 phase decomposition at λ=128
# ---------------------------------------------------------------------------

def fig3():
    row = by_lam[128]
    total = row["total_cycles"]

    phases = row["phases"]
    phase_labels = [p["name"].replace("_", "\n", 1) for p in phases]
    phase_cycles = [p["cycles_total"] for p in phases]
    phase_perms = [p["griffin_perms_total"] for p in phases]
    phase_fp127 = [p["fp127_muls_total"] for p in phases]

    # Sum of accounted-for phase cycles; residual is parsing/verifier glue.
    accounted = sum(phase_cycles)
    residual = max(0, total - accounted)

    fig, ax = plt.subplots(figsize=(11, 5.6))

    n = len(phases)
    xs = np.arange(n + 1)

    # Color by Griffin perms — phases that hash more get the Griffin color;
    # phases without Griffin get the F_p mul outside color; residual is floor.
    bar_colors = []
    for p in phases:
        if p["griffin_perms_total"] > 0:
            bar_colors.append(COL_GRIFFIN_FP)
        else:
            bar_colors.append(COL_FP_OUTSIDE)
    bar_colors.append(COL_FLOOR)

    heights = [c / 1e6 for c in phase_cycles] + [residual / 1e6]
    bars = ax.bar(xs, heights, color=bar_colors, edgecolor="white", width=0.7)

    labels = phase_labels + ["residual\n(parsing/glue)"]

    # Annotation: cycles in M + Griffin perm count + F_p mul count
    for i, (b, c, p) in enumerate(zip(bars, phase_cycles + [residual], phases + [None])):
        pct = 100.0 * c / total
        if p is not None:
            tag = f"{c/1e6:.1f}M ({pct:.1f}%)\n{p['griffin_perms_total']} Griffin\n{p['fp127_muls_total']:,} F_p mul"
        else:
            tag = f"{c/1e6:.1f}M ({pct:.1f}%)\nrv32im glue"
        ax.text(
            b.get_x() + b.get_width() / 2.0,
            b.get_height() + 8,
            tag,
            ha="center",
            va="bottom",
            fontsize=8.5,
            linespacing=1.15,
        )

    ax.set_xticks(xs)
    ax.set_xticklabels(labels, fontsize=9, rotation=0)
    ax.set_ylabel("rv32im cycles per verify (millions)")
    ax.set_ylim(0, max(heights) * 1.35)
    ax.set_title(
        "Algorithm-7 phase decomposition at λ=128\n"
        "ldt_openings consumes 76.7% of cycles — concentrated in 704 Griffin perms (Merkle paths)",
        fontsize=11.5,
        pad=14,
    )
    for spine in ("top", "right"):
        ax.spines[spine].set_visible(False)
    ax.yaxis.grid(True, alpha=0.3)
    ax.set_axisbelow(True)

    # Legend strip
    legend_handles = [
        plt.Rectangle((0, 0), 1, 1, color=COL_GRIFFIN_FP, label="Griffin-heavy phase"),
        plt.Rectangle((0, 0), 1, 1, color=COL_FP_OUTSIDE, label="F_p-only phase (Legendre)"),
        plt.Rectangle((0, 0), 1, 1, color=COL_FLOOR, label="residual / rv32im glue"),
    ]
    ax.legend(handles=legend_handles, loc="upper left", frameon=False, fontsize=9.5)

    fig.tight_layout()
    out = OUT / "fig3_phase_lambda128.png"
    fig.savefig(out, dpi=160, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {out}")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    fig1()
    fig2()
    fig3()
