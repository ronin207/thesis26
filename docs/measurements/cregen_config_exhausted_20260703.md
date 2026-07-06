# CreGen prove on the current fork: config levers exhausted, 2^30 overflow is fork-pinned (2026-07-03)

> **⚠️ SUPERSEDED (2026-07-03, same day).** This "config exhausted / fork-pinned" conclusion
> was WRONG. Root cause found and FIXED by a config knob: the overflow is the deferred-Griffin
> shard exceeding 2^29 (jagged commit pads to next_pow2 = 2^30); `HEIGHT_THRESHOLD=2^16` keeps
> it under 2^29 and CreGen COMPLETES (70.90 min, accepted). See
> `cregen_h16_20260703/RESULT.md` and `cregen_overflow_experiment_log_20260703.md`. I had not
> gone low enough on HEIGHT, and I had the wrong culprit (Griffin cost-model, not the cause).

**Decisive negative result.** The BDEC CreGen succinct prove does **not** complete on
the current (dirty) sp1 fork `8bf0248bc` at any shard config tried; the jagged-PCS
`round area out of bounds (< 2^30)` overflow recurs. It is not config-fixable.

## Attempts (all λ=80, syscall/with-precompile arm, fork 8bf0248bc-dirty)

| SHARD_SIZE | HEIGHT_THRESHOLD | outcome | when | peak RSS |
|---|---|---|---|---|
| 2^22 | 2^20 | `2^30` overflow | ~34 min | ~15.4 GiB |
| 2^20 | 2^20 | `2^30` overflow | mid-prove | ~14 GiB |
| **2^20** | **2^17** | **`2^30` overflow** | **~40 min** | **13.76 GiB** |

`ELEMENT_THRESHOLD=2^26`, `TRACE_CHUNK_SLOTS=2`, `RAYON_NUM_THREADS=8` throughout.
None OOM'd (peak ≤ ~15 GiB / 24 GiB); none was killed by the machine (see execution
note). The failure is always the deterministic `2^30` round-area overflow.

## Why HEIGHT_THRESHOLD=2^17 was expected to work — and didn't

If the overflowing round were the Griffin chip capped at `HEIGHT_THRESHOLD` rows, its
area would be `2^17 × 3819 ≈ 5×10^8 < 2^30` — safely under. It still overflowed. So
the overflowing round is **not** a simple height-capped Griffin chip: either a
different wide chip / an aggregated round, or the shard budgeter packs by the
**mispriced** Griffin cost regardless of `HEIGHT_THRESHOLD`. Root cause is the
cost-model: `rv64im_costs.json` prices the Griffin chip at **348** vs its real
~**3819** columns, so the budgeter under-counts Griffin and forms shards whose real
round area exceeds `2^30`.

## Conclusion

- The `2^30` overflow is **fork-pinned** (cost-model mispricing), not tunable via
  `SHARD_SIZE` / `HEIGHT_THRESHOLD`.
- The thesis-cited **26.98-min CreGen** number is a **6/11-fork** result; the current
  dirty fork does **not** reproduce a completing CreGen at any config. (This confirms
  the reproducibility gap flagged in `metric_drift_prove_vs_wall_20260702.md`.)

## Execution mechanism — solved (separate from the above)

- Claude **tool-background** jobs (`run_in_background`) are reaped ~inconsistently
  (76 s–35 min) — NOT sleep/OOM/overflow/crash. Verified: 0 macOS sleep events,
  `SleepDisabled=1`, AC power.
- **User `!`-launch survives** (this run ran ~40 min idle to its overflow). A **detached
  self-launch** (`python3 ... start_new_session=True`) **also survives** (verified with
  a +300 s marker test 06:43). So future runs can be executed survivably by either.

## Sharpened diagnosis (2026-07-03, after inspecting the fork diff)

- The sp1 fork **commit is identical** (`8bf0248bc`, 2026-05-20) on 6/11 and now.
- The **uncommitted changes do NOT touch the core prove**: `griffin_fp192/mod.rs` is
  a `#[cfg(test)] mod fault_injection;` line (test-only, not compiled in `--release`);
  `compress_shape.json` + `gnark-ffi/build.rs` are **wrap/recursion-layer**, not the
  core `.run()` STARK. So the core-prove code that overflows is **byte-identical** to 6/11.
- The **cost-model (`rv64im_costs.json` `GriffinFp192: 348`) is committed and clean** —
  it was `348` on 6/11 too.

**So "revert the fork" would NOT change the core-prove overflow** (the uncommitted
changes don't affect it), and identical code + identical cost-model on 6/11 completed
while now it overflows. The only remaining variables:
- **The 6/11 config was never machine-logged.** Its `SHARD_SIZE` exists only in a
  human-written `SUMMARY.txt` ("2^22"), never echoed by the program (per Lane-A
  forensics). My `2^22` run overflows with the same code — so **either 6/11 did not
  actually run at `2^22`, or the build/dependencies drifted** (`Cargo.lock` has moved).
- **Net: the thesis-cited 26.98-min CreGen is not reproducible on the current tree at
  any config tried, and its config is not machine-verified** — a real provenance gap on
  a cited number (deepens `metric_drift_prove_vs_wall_20260702.md`).

## Decision needed (Q2 — reframed)

Reverting the fork is out (won't affect the core overflow). The honest options:
1. **Cost-model fix** — edit committed `rv64im_costs.json:49` `GriffinFp192: 348 →
   ~3819`. This is the ONE remaining lever that could change shard budgeting to account
   for Griffin's real width; SHARD/HEIGHT knobs don't. **Uncertain** (HEIGHT=2^17 should
   have capped the round area and didn't, so the mechanism isn't fully pinned) — verify
   with one test run. A committed-fork edit → Operator's call.
2. **Build drift — RULED OUT (2026-07-03).** `Cargo.lock` is clean (no dep version
   changes); deps are identical to 6/11. So same commit + same deps + same cost-model +
   same core code + same input (264256 bytes) — the regression is mechanically
   unexplained, which points hard at the one unverified variable: the 6/11 `SHARD_SIZE`
   was never machine-logged and was likely not actually `2^22`.
3. **Park + caveat** — treat 26.98-min as a non-reproducible 6/11 datum and add a
   reproducibility caveat where it is cited (§5/§6/§8), per the metric-drift doc.

Not made autonomously — the fork edit and the provenance caveat are the Operator's call.
