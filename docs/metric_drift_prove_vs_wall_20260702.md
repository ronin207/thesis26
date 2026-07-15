# Metric drift: the BDEC "prove (succinct)" column mixes `prove_ms` and wall-clock

**Date:** 2026-07-02. **Status:** correction record; drives a prose edit to §5/§6/§8. **Not a
re-measurement** — all five figures are genuine ACCEPTED receipts. This is a labeling +
consistency fix, verified against the raw run logs (file:line below).

## The defect

The thesis reports the SP1 BDEC prove numbers as a "prove (succinct)" column, but the five
cited figures are drawn from two different clocks:

- The **6/11** record (`pub_hardening_20260611`) reports true **`prove_ms`** (the prover's own
  internal timer).
- The **6/12** record (`audit5_campaign_20260612`) figures cited in the thesis are the host
  **wall-clock (`real`)** times, whose true `prove_ms` are lower.

So each "n=2 pair" mixes one `prove_ms` value with one wall value, and the `k=2` figure is a
wall value presented under a "prove" label.

## Evidence (verified from raw logs, 2026-07-02)

| relation | run | `prove_ms` → min | wall (`real`) → min | log:line |
|---|---|---|---|---|
| CreGen | 6/11 (S9) | 1618670 → **26.98** | 1834.76 s → 30.58 | `pub_hardening_20260611/s9_cregen_prove.log:357,360` |
| CreGen | 6/12 (b1) | 1646719 → **27.45** | 1866.65 s → **31.11** | `audit5_campaign_20260612/b1_cregen_prove_repeat2.log:358,361` |
| ShowCre k=1 | 6/11 (S9) | 2409157 → **40.15** | 2657.72 s → 44.30 | `pub_hardening_20260611/s9_showcre_k1_prove.log:357,360` |
| ShowCre k=1 | 6/12 (b2) | 2411196 → **40.19** | 2654.68 s → **44.24** | `audit5_campaign_20260612/b2_showcre_k1_prove_repeat2.log:358,361` |
| ShowCre k=2 | 6/12 (b3) | 3222673 → **53.71** | 3488.22 s → **58.14** | `audit5_campaign_20260612/b3_showcre_k2_prove.log:357,360` |

All five printed `accepted=true`; CreGen 6/11 and 6/12 share `proof_bytes=295969667` (byte-
identical proof), so these are real, reproducible receipts — not fabricated, not extrapolated.

## What the thesis currently prints (all are the mixed/wall values)

- `06-evaluation.tex:431` — table: CreGen "prove (succinct) $26.98$ and $31.11$ min ($n=2$)".
  → `26.98` = prove (6/11); **`31.11` = wall (6/12); its true prove is `27.45`**.
- `06-evaluation.tex:432` — table: ShowCre $k{=}1$ "$40.15$ and $44.24$ min ($n=2$)".
  → `40.15` = prove (6/11); **`44.24` = wall (6/12); its true prove is `40.19`**.
- `06-evaluation.tex:433` — table: ShowCre $k{=}2$ "$58.14$ min ($n{=}1$)".
  → **`58.14` = wall; its true prove is `53.71`**.
- `06-evaluation.tex:566` — summary: CreGen "completes, $27$--$31$ min".
- `06-evaluation.tex:567` — summary: ShowCre "completes, $40$--$58$ min".
- `05-system.tex:16,17,149` and `08-conclusion.tex:11` — prose repeats the mixed pairs
  (26.98/31.11, 40.15/44.24, 58.14).

## Three consequences

1. **The `k=2` figure overstates prove time by ~8%.** `58.14` min under a "prove" label vs the
   receipt's true `prove_ms` of `53.71` min = +4.43 min, +8.2%.
2. **The "ranges" read as replication spread but are prove-vs-wall artifacts.** The apparent
   CreGen "$27$--$31$" (≈15%) and ShowCre "$40$--$58$" spans are the two-clock gap, **not**
   run-to-run variance. True prove-to-prove variance is tiny: CreGen `26.98` vs `27.45` = **+1.7%**;
   ShowCre k=1 `40.15` vs `40.19` = **+0.1%**. The current phrasing *understates* the method's
   reproducibility (the real story is tight replication).
3. **Internal contradiction on `n`.** `06-evaluation.tex:431-432` label CreGen and ShowCre k=1
   as `($n=2$)`, but `06-evaluation.tex:1044` states "the remaining prove-mode figures (the
   CreGen and ShowCre relations) are single runs." At the run level `n=2` is correct for CreGen
   and ShowCre k=1 (S9 + audit5 are two runs each); only ShowCre k=2 is a single run. Line 1044
   is stale.

Precedent: same class of defect as the June-2026 `25h → 51h` startup-contamination case
(`docs/measurements/...`), direction reversed here (wall > prove). Wall is the contaminated
clock: the 2026-07-02 CreGen re-run logs show host `fileproviderd` (iCloud sync) pinned at
~99% throughout, which inflates wall but not `prove_ms`.

## Recommended correction — report `prove_ms` consistently

`prove_ms` is the prover-internal metric, matches the "prove" column label, is far less
machine-state-contaminated than wall, and makes the replication tight (a strength, not a
spread). Corrected column:

| relation | corrected prove | note |
|---|---|---|
| CreGen, SP1 | **26.98 and 27.45 min** ($n=2$; +1.7%) | replaces 26.98 / 31.11 |
| ShowCre k=1, SP1 | **40.15 and 40.19 min** ($n=2$; +0.1%) | replaces 40.15 / 44.24 |
| ShowCre k=2, SP1 | **53.71 min** ($n=1$) | replaces 58.14 |

Per-line edits:
- `06-evaluation.tex:431` → `$26.98$ and $27.45$~min ($n=2$)`.
- `06-evaluation.tex:432` → `$40.15$ and $40.19$~min ($n=2$)`.
- `06-evaluation.tex:433` → `$53.71$~min ($n{=}1$)`.
- `06-evaluation.tex:566` → CreGen "completes, $\approx 27$~min" (or `$27.0$--$27.5$`).
- `06-evaluation.tex:567` → ShowCre "completes, $40$--$54$~min".
- `06-evaluation.tex:1044` → fix the stale claim: CreGen and ShowCre $k{=}1$ are $n=2$; only
  ShowCre $k{=}2$ is a single run.
- `05-system.tex:16` → `$26.98$ and $27.45$~min, $n=2$`.
- `05-system.tex:17` → `$40.15$ and $40.19$~min at $k=1$, $n=2$; $53.71$~min at $k=2$, $n=1$`.
- `05-system.tex:149` and `08-conclusion.tex:11` → same substitutions in the prose.
- Add a one-line metric definition where the column first appears: "`prove` denotes the
  prover's reported `prove_ms`; end-to-end wall is reported separately."

## Open decisions (Operator's call — metric semantics)

1. **Which clock is the headline.** The thesis's own metric list names "total proof generation
   time" as the goal metric, which reads as *wall*. If wall is the intended semantics, then
   (a) report wall **consistently** for all five (CreGen 30.58/31.11, ShowCre k=1 44.30/44.24,
   k=2 58.14), (b) relabel the column "wall (succinct)", and (c) disclose the `fileproviderd`
   contamination and that wall is machine-state-dependent. **Do not mix.** Recommended: report
   `prove_ms` as the headline "prove" column and wall as a separate disclosed column.
2. **The `26.98` reproducibility caveat (separate finding).** The 6/11 CreGen run never
   machine-logged its `SHARD_SIZE` (only a human-written `SUMMARY.txt` asserts `2^22`), and the
   2026-07-02 re-run at `2^22` on the current fork FAILS with a `2^30` jagged round-area
   overflow. So the current fork does not reproduce a CreGen prove at the documented tuning;
   see the shard-overflow investigation. This does not change the metric-label fix above (the
   6/11 and 6/12 receipts are real), but it bears on whether `26.98/27.45` is reproducible on
   the shipped fork.
