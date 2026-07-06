# CreGen 2^30 round-area overflow — experiment log (2026-07-03)

**Goal:** make BDEC CreGen prove complete on the current tree, OR exhaust the solution
space rigorously. Hypothesis-driven; every experiment logged with result + conclusion so
the dead-ends are traceable. All fork edits are **reversible** (git checkout after) and
used for *testing*, not to alter the shipped artifact without the Operator's sign-off.

## Ground truth (before this log)
- CreGen overflows the jagged-PCS `2^30` round-area bound (`slop/crates/jagged/src/verifier.rs:238`) at every config tried: `SHARD 2^22/HEIGHT 2^20`, `SHARD 2^20/HEIGHT 2^20`, `SHARD 2^20/HEIGHT 2^17`. Overflow appears ~34–40 min in (a late shard). Peak RSS ≤ 15 GiB (never OOM).
- Regression cause ruled out: uncommitted sp1 changes (test-only `#[cfg(test)]` + wrap-layer), cost-model (`GriffinFp192: 348` committed, same 6/11), deps (`Cargo.lock` clean), input (identical 264256 B). Same commit+deps+code+input, yet 6/11 completed.
- 6/11's `SHARD_SIZE` was never machine-logged (human `SUMMARY` claims `2^22`, unverified).
- **Execution solved:** detached self-launch (`python3 … start_new_session=True`) survives (verified +300 s marker). Runner: `platforms/zkvms/sp1/scripts/run_bench_unattended.sh` (fail-fast overflow watchdog + wall cap).
- Feedback loop cost: ~40 min per CreGen prove to reach the overflow.

## Open puzzle
`HEIGHT_THRESHOLD=2^17` should cap the Griffin chip at `2^17` rows → round area `2^17 × 3819 ≈ 5×10^8 < 2^30`, yet it still overflowed. So the overflowing round is NOT a single height-capped Griffin chip. Understanding *what it is* is the pre-req for any smart fix. (→ code-analysis workflow running.)

## Hypotheses (provisional, to be refined by the code analysis)
- H1 cost-model: `GriffinFp192 348 → ~3819` reduces shard packing → round area < 2^30. [reversible edit + 1 prove]
- H2 instrument: patch `verifier.rs` (or the prover round-area computation) to LOG all round_areas + the overflowing round index/value → learn the exact magnitude + which chip. [reversible edit + 1 prove; ideally dump EARLY, pre-prove]
- H3 config: an untried knob (`ELEMENT_THRESHOLD`↓, default/no-tuning, or a *larger* shard) bounds round_area < 2^30.
- H4 mechanism: the overflow round is a SUM over many chips (not per-chip height) → HEIGHT can't help; the lever is chip-count-per-round or the cost-model.

## Experiments
(appended below as they run)

### E0 — code analysis (workflow `wf_8efc9c04`) — DONE
**Round mechanism:** a "round" = one `commit_multilinears` (per shard: preprocessed + main). `round_area = Σ_chips(real_row_count × column_count)` — a SUM over all chips in the commitment (`verifier.rs:220-234`, prover `jagged/src/prover.rs:110-112`). So `HEIGHT_THRESHOLD` (caps ONE chip's height) can never bound the sum; the sum is admitted by cost-weighted area vs `ELEMENT_THRESHOLD` (`shapes.rs:242-243`).
**Griffin is NOT the culprit.** CreGen ≈ 2×1052 = **2,104 Griffin perms** (Cell-2 measured 1052/verify). Griffin round even at buggy cost, no cap = `2104×14×3819 = 1.13e8 = 0.10×2^30`. Overflow needs >20,082 perms in one shard — an order of magnitude more. So the **cost-model fix (348→3819) would NOT help** (E4 dropped unless E1 shows ≥7,392).
**It's the CORE prove** (`bdec_cregen_host.rs:101 .run()`, no recursion → recursion-layer hypothesis refuted). Cost JSON is `include_str!`-embedded (needs rebuild to change). Env opts ARE consumed on the worker path (`worker/config.rs:71`).
**Tractable lever exists** (not fork-pinned): `ELEMENT_THRESHOLD < 2^30/ρ` forces every round < 2^30 (ρ = worst chip width/cost). Only intractable if the overflow is a single indivisible round (e.g. preprocessed table > 2^30) — no evidence yet.

**The crux to resolve:** I ran `ELEMENT_THRESHOLD=67M` (< 90M) and it STILL overflowed → either the env wasn't consumed on my run path, OR the culprit round has ρ>16, OR it's the (unshardable) preprocessed round.

### E1 — Griffin perm count — RESOLVED by prior data (skipped a run)
Count ≈ 2,104 (2 × measured 1052, `four_scheme_benchmark.md`). << 20,082. **Confirms Griffin is not the overflowing round.** → go to E2.

### E2 — shape-dump the failing round (name the culprit chip) — NEXT
Enable the existing per-chip debug log (`shard.rs:660-668`, no code edit) via targeted `RUST_LOG`; run the prove detached (survivable); poll the streaming per-shard chip breakdown. Learn: (a) are shards ~67M (env consumed) or ~402M (default)? (b) which chip dominates the overflowing round? Then the lever is decided (ELEMENT_THRESHOLD if shardable / preprocessed if not).

**E2 interim (07:38, 56 shards, RUST_LOG honored):**
- **`ELEMENT_THRESHOLD=67M` IS consumed** — main-execution shards are **~31M cells** (2^25 vars), not the 402M default. Env-not-consumed hypothesis REFUTED.
- **Main rounds are NOT the overflow** — all 56 shards ~31M (0.03×2^30); chips = standard RISC-V (Add/Load/Branch/Global/Bitwise…), largest ~5M cells (Global). No overflow yet.
- Griffin shards (deferred, later) are capped at ≤9,362 perms by HEIGHT=2^17 → ≤0.47×2^30, so they can't overflow either.
- **Inference:** the overflow is a large *final/global* round (candidate: the global memory-finalize shard accumulating every touched address across the 243M-cycle run). Letting E2 run to capture the specific overflowing shard's chip breakdown; watching the streaming "Total number of cells" for one approaching 2^30.

**E2 poll 2 (08:01, 327 shards):** ALL main shards ≤ 38M cells; biggest chip = Global 0.029×2^30; no Griffin yet; no overflow.

**E2 DIAGNOSIS COMPLETE (08:18) — root cause found:**
The overflow is the deferred-**Griffin shard** (proved last). Its full breakdown:
`GriffinFp192 (base) | Main Cols = 3819 | Rows = 130,816 | Cells = 499.6M` (the dominant chip; 9,344 perms × 14 rows × 3819 cols) + `Global 74.3M` + `MemoryLocal 3M` + Control/others → **Total = 581,604,864 cells, "number of variables: 30".**
**Mechanism:** the jagged commit stacks the shard's total cells into a polynomial padded to the next power of two (`total.next_power_of_two()`, shard.rs:668-672). 581M > 2^29 (536.9M) ⇒ pads to **2^30** ⇒ the round-area check `>= 1<<30` (verifier.rs:238) fires. So `round_area` ≠ raw Σ(rows×cols); it is the **stacked size = next_pow2(total_cells)**. The `2^17` HEIGHT cap gave 9,344 Griffin perms ⇒ 581M shard ⇒ just over 2^29 ⇒ 2^30 ⇒ overflow.
**Also:** CreGen's Griffin count is ~9,344 (one shard at cap), NOT the ~2,104 estimate from Cell-2×2 — the estimate was low (CreGen's Merkle/BCS commitments add more Griffin than the base symbol checks).
**FIX (config, no rebuild):** keep every shard's total cells ≤ 2^29. `HEIGHT_THRESHOLD=2^16` caps Griffin at min(67M/5805, 65536/14)=4,681 perms ⇒ base Griffin ≈250M ⇒ Griffin shard ≈332M < 2^29 ⇒ pads to 2^29 ⇒ NO overflow. (Only a ~8% reduction below 581M is strictly needed; 2^16 gives comfortable margin.)

### E3 — HEIGHT_THRESHOLD=2^16 (the fix) — ✅ SUCCESS
CreGen **COMPLETED** (accepted=true): **prove_ms=4,254,093 = 70.90 min**, wall 72.4min, verify 27.6s, proof_bytes **1.47 GB**, peak RSS **13.98 GiB**, overflow_errs=0. Full record: `cregen_h16_20260703/RESULT.md`.
**The config lever is CONFIRMED: `HEIGHT_THRESHOLD` keeps the deferred-Griffin shard < 2^29, avoiding the next_pow2→2^30 round-area overflow. NOT fork-pinned; cost-model fix NOT needed.** This supersedes the earlier same-day "config exhausted / fork-pinned" conclusion.
Caveats: workaround config (not the shipped 2^22), ~2.6× slower than the 6/11 26.98min (unlogged config), proof ~5× bigger (1.47GB vs 296MB) from the many small shards.

### E4 — SHARD_SIZE=2^22 + HEIGHT=2^16 — ✅ DONE, but NOT faster
COMPLETED: prove_ms=4,257,727 (**70.96 min**), proof 1.47GB (byte-identical to E3), peak 13.22GiB, accepted, overflow=0. **`SHARD_SIZE` has NO material effect** (E3 2^20 = 70.90min vs E4 2^22 = 70.96min, same proof). ~71min is inherent to CreGen at this fork/λ with the fix. `cregen_s22_h16_20260703/RESULT.md`.

---

## FINAL SUMMARY — CreGen 2^30 overflow SOLVED (2026-07-03)

**Problem:** BDEC CreGen succinct prove failed with `round area out of bounds (>= 2^30)` at every config tried earlier today; concluded (wrongly) "config-exhausted / fork-pinned."

**Root cause (found via the E2 shape-dump):** the overflowing round is the deferred-**Griffin shard**. Its base `GriffinFp192` chip = 9,344 perms × 14 rows × 3,819 cols = **499.6M cells**; with Global (74M) + memory the shard totals **581M cells**. The jagged PCS stacks each shard into a polynomial padded to the **next power of two**; `581M > 2^29 (536.9M)` ⇒ pads to **2^30** ⇒ the `>= 1<<30` check (`slop/jagged/verifier.rs:238`) fires. The checked quantity is the *stacked* size, not the raw cell sum — which is why raw counts always looked under the bound, and why `HEIGHT=2^17` (9,344-perm cap) landed just over.

**Fix (config knob — no fork edit, no cost-model change, no rebuild):** `HEIGHT_THRESHOLD ≤ 2^16` caps the Griffin shard at ≤4,681 perms → total < 2^29 → stays under. The Griffin **cost-model** bug (348 vs real 3,819) is real but is NOT the cause (only ~2,104-worth would be needed to matter differently; the shard-size padding is the mechanism).

**Machine-verified completing configs (λ=80, fork 8bf0248bc-dirty, syscall arm):**
- E3 `SHARD 2^20 / HEIGHT 2^16`: **70.90 min**, proof 1.47 GB, peak 13.98 GiB, accepted.
- E4 `SHARD 2^22 / HEIGHT 2^16`: **70.96 min**, proof 1.47 GB, peak 13.22 GiB, accepted.
- `SHARD_SIZE` is irrelevant to speed/size; ~71 min is inherent at this config.

**Honest caveats:** this is a **de-tuned workaround** config; it is ~2.6× slower and produces a ~5× larger proof (1.47 GB) than the buried 6/11 datum (26.98 min / 296 MB), whose config was **never machine-logged**. So the 6/11 number remains a provenance question; these runs document a config that verifiably works.

**Operator's remaining choices (CreGen no longer a blocker):**
1. Adopt `HEIGHT_THRESHOLD=2^16` as the documented CreGen benchmark config (honest, machine-verified, but slow/heavy) — OR recover the 6/11 config's provenance for the faster number.
2. Still open (separate arms): the ZK-wrap (computational-ZK goal, ~51h vk_map regen) and the emulated no-precompile baseline.
3. Still held in your lane: the 2 Sako abstract/framing edits (config-matched baseline; "realised" → "benchmarked").

**Loop stopped here — CreGen is solved (root cause + fix + verified number).**
