#!/usr/bin/env python3
# Trilemma slide — supervisor rebuild applying the Sako panel's convergent findings.
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Polygon, Ellipse, FancyBboxPatch, Circle
import matplotlib.font_manager as fm

GREEN = "#2E7D32"; BLUE = "#1565C0"; PURPLE = "#6A1B9A"
ORANGE = "#E65100"; RED = "#C62828"; GREY = "#5f6368"; INK = "#202124"
LGREY = "#9aa0a6"

fig = plt.figure(figsize=(13.333, 7.5), dpi=200)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")

# ---------- header ----------
ax.text(0.5, 0.975, "Flexible · Post-Quantum · Private — pick two on a laptop",
        ha="center", va="center", fontsize=25, fontweight="bold", color=INK)
ax.text(0.5, 0.936,
        "Goal: can one credential proof be all three on a 24 GB laptop?      "
        "Result: no — each substrate buys two; the centre is empty.",
        ha="center", va="center", fontsize=13.5, color=INK)
ax.text(0.5, 0.906,
        "I measure one BDEC-PLUM credential proof on three substrates (the means); the three properties are the axis.",
        ha="center", va="center", fontsize=10.8, color=INK)
ax.text(0.5, 0.882,
        "orange = my measurements   ·   contribution = the orange numbers + locating the empty centre",
        ha="center", va="center", fontsize=9.8, color=ORANGE, style="italic")

# ---------- triangle ----------
TOP = (0.50, 0.818); BL = (0.175, 0.300); BR = (0.825, 0.300)
ax.add_patch(Polygon([TOP, BL, BR], closed=True, facecolor="#f4f6f8",
                     edgecolor=LGREY, linewidth=2.0, zorder=1))

def corner_pill(xy, text, color, dy):
    x, y = xy
    ax.add_patch(FancyBboxPatch((x-0.115, y-0.028), 0.23, 0.056,
                 boxstyle="round,pad=0.006,rounding_size=0.02",
                 facecolor=color, edgecolor="none", zorder=5))
    ax.text(x, y, text, ha="center", va="center", fontsize=15.5,
            fontweight="bold", color="white", zorder=6)

corner_pill(TOP, "FLEXIBLE", GREEN, 0)
# the load-bearing definition, legible, NOT prove-time flagged
ax.text(0.50, 0.768, "cost to CHANGE the relation = re-derive + re-audit",
        ha="center", va="center", fontsize=11, color=GREEN, fontweight="bold")
ax.text(0.50, 0.744, "— an assurance footprint, NOT prove-time —",
        ha="center", va="center", fontsize=11, color=RED, fontweight="bold")

corner_pill(BL, "POST-QUANTUM", BLUE, 0)
ax.text(0.175, 0.254, "(sound vs a quantum adversary*)", ha="center", va="center",
        fontsize=9.5, color=BLUE)
corner_pill(BR, "PRIVATE", PURPLE, 0)
ax.text(0.825, 0.254, "(zero-knowledge)", ha="center", va="center",
        fontsize=9.5, color=PURPLE)

# edge dots (where each substrate sits)
EL = (0.3375, 0.559); ER = (0.6625, 0.559); EB = (0.50, 0.300)
for d in (EL, ER, EB):
    ax.add_patch(Circle(d, 0.0075, facecolor=INK, edgecolor="none", zorder=7))

# ---------- substrate callout boxes ----------
def box(cx, cy, w, h, lines):
    ax.add_patch(FancyBboxPatch((cx-w/2, cy-h/2), w, h,
                 boxstyle="round,pad=0.004,rounding_size=0.012",
                 facecolor="white", edgecolor=LGREY, linewidth=1.2, zorder=8))
    n = len(lines); top = cy + h/2 - 0.026
    step = (h - 0.044) / max(n-1, 1)
    for i, (t, s, c, wt) in enumerate(lines):
        ax.text(cx, top - i*step, t, ha="center", va="center",
                fontsize=s, color=c, fontweight=wt, zorder=9)

def leader(p0, p1):
    ax.plot([p0[0], p1[0]], [p0[1], p1[1]], color=LGREY, lw=1.0, zorder=2)

# LEFT edge: zkVM base STARK (PQ + flexible, not private)
leader((0.30, 0.60), EL)
box(0.165, 0.705, 0.315, 0.165, [
    ("zkVM base STARK  (SP1 / RISC Zero)", 11.5, INK, "bold"),
    ("props:  ✓ post-quantum*  ✓ flexible  ✗ private", 10.5, INK, "normal"),
    ("measured:  PLUM verify ≈32.5 min  (n=2)  λ=80", 10, ORANGE, "bold"),
    ("✗ not zero-knowledge (succinct STARK only)", 9.6, RED, "normal"),
])

# RIGHT edge: zkVM + ZK wrap (flexible + private, not PQ; infeasible here)
leader((0.70, 0.60), ER)
box(0.835, 0.705, 0.315, 0.165, [
    ("zkVM + ZK wrap  (Groth16 / PLONK)", 11.5, INK, "bold"),
    ("props:  ✓ flexible  ✓ private  ✗ post-quantum", 10.5, INK, "normal"),
    ("✗ pairing-based → not post-quantum (Shor)", 10, RED, "bold"),
    ("observed:  PLONK OOM ≈20/24 GB; Groth16 x86-only", 9.0, ORANGE, "normal"),
])

# BOTTOM edge: Static circuit Aurora (PQ + private, not flexible) — carries R_static
leader((0.50, 0.215), EB)
box(0.50, 0.145, 0.66, 0.145, [
    ("Static circuit  (Aurora)", 12, INK, "bold"),
    ("props:  ✓ post-quantum   ✓ private   ✗ flexible", 11, INK, "normal"),
    ("measured:  PQ zero-knowledge proof ≈22 min (mean of 3, 21.4–22.9) λ=80 · Loquat-Fp127 proxy", 10.2, ORANGE, "bold"),
    ("✗ flexible: a change ⇒ re-derive + RE-AUDIT  (recompile only ≈0.3 s — the cost is assurance, not time)", 9.6, RED, "normal"),
])

# ---------- the empty centre = the contribution (dominant) ----------
CX, CY = 0.50, 0.480
# dashed, empty (no fill struck): an unreached region, not a crossed-out claim
ax.add_patch(Ellipse((CX, CY), 0.215, 0.20, facecolor="#fdecea",
                     edgecolor=RED, linewidth=3.0, linestyle="--", zorder=4))
ax.text(CX, CY+0.024, "all three", ha="center", va="center", fontsize=12,
        fontweight="bold", color=RED, zorder=6)
ax.text(CX, CY-0.004, "at once", ha="center", va="center", fontsize=12,
        fontweight="bold", color=RED, zorder=6)
ax.text(CX, CY-0.040, "@ 24 GB", ha="center", va="center", fontsize=10.5,
        color=RED, zorder=6)
ax.text(CX, 0.352, "UNREACHED — the wall this thesis locates", ha="center", va="center",
        fontsize=12.5, fontweight="bold", color=RED)
ax.text(CX, 0.327, "no substrate reaches the centre:  PLONK wrap OOM (measured)  ·  no PQ-sound ZK wrap exists yet (open)",
        ha="center", va="center", fontsize=9.3, color=GREY)

# ---------- footer caveats ----------
ax.text(0.5, 0.052,
        "λ=80 is the largest level observable within 24 GB, not a deployment level "
        "· zkVM prove = single / 2 runs, Aurora = Loquat-Fp127 proxy (n=3) · *QROM lifts open",
        ha="center", va="center", fontsize=9, color=GREY)
ax.text(0.5, 0.026,
        "all receipts are succinct STARKs, none is zero-knowledge "
        "· the empty centre is the open problem: a feasible post-quantum-sound ZK wrap would fill it",
        ha="center", va="center", fontsize=9, color=GREY)

fig.savefig("/tmp/trilemma_sako/trilemma_final.png", dpi=200, facecolor="white")
print("wrote /tmp/trilemma_sako/trilemma_final.png")
