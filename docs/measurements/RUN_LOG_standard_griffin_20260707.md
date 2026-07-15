# Standard-Griffin era — consolidated run log

Every execution run recorded in the standard-Griffin measurement era (2026-07-06 → 2026-07-07),
with exact parameters and results per run, grounded in the run records under `docs/measurements/`.
Nothing here is from memory; each number cites its record path (and line where useful).

## Legend / conventions

- **Arms.** `syscall` = PLUM/BDEC guest built **WITH the Griffin precompile** (`GRIFFIN_FP192_PERMUTE` syscall) **plus `UINT256_MUL`** (256-bit modmul) for the 192-bit field ops. This is the shipped/measured "with precompile" pipeline. `emulated` = **NO precompile**: Griffin runs as ordinary RISC-V (rv32im), every 192-bit op is `UINT256_MUL`-emulated. `sha3` = Cell-3 control, Griffin replaced by SHA-3 (existing SHA-256/keccak precompile). `zk-wrap` = the full Core→Compress→Shrink→Wrap(BN254)→Plonk chain.
  - NB: the "with precompile" arm here is **Griffin precompile + `UINT256_MUL`**, *not* the dedicated `FP192_MUL` / `FP192_POW_RES` chips. Those are the separate per-op keystone/settle experiment (branch `prf-precompiles`); they are **not** in the shipped measured pipeline (§C, §D).
- **Machine / λ.** Target hardware MacBook Pro M5 Pro, 24 GB RAM, `RAYON_NUM_THREADS=8`, `SP1_PROVER=cpu`; all runs λ=80 (PLUM-80) unless noted.
- **Standard-Griffin build (main batch §A–§C):** repo HEAD `cde7874695e770ef7eef93c4f946d957a0e2b89b`; sp1 sub HEAD `8bf0248bc5b6b7ba7c820253c3918ea277008641` (working tree dirty = standard-Griffin chip fix).
- **Sound-path (wraps §E):** `vk_verification ON`, `mprotect OFF`, `SP1_CIRCUIT_MODE unset` (stock `~/.sp1/circuits/plonk/v6.1.0`), `SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=2`, `SP1_PROVER=cpu`, native gnark (stock v6.1.0), reduced vk_map. sp1 submodule @`74e1c1e8a`, branch `griffin-standard-mds-fix`, probe_b working tree.
- **Guards.** Baseline proves ran under a per-item wall watchdog (cap noted). The emulated (no-precompile) proves **DNF by watchdog timeout, NOT OOM** — peak RSS ~13.6–13.75 GB (~57% of 24 GB), not memory-bound. Wraps ran under a tree-RSS soft-kill (23.5 GB) + wall cap.
- **Verdicts.** `OK` = prove+verify (or execute) completed & accepted. `DNF` = did-not-finish (watchdog). `PASS`/`VERIFY_OK` = wrap chain closed and SP1-verified.

---

## A. Baseline STARK cells (Cell 1 / Cell 2 / Cell 3)

### A0. PLUM-verify execute anchor — syscall arm (M5)
Execute-only sanity establishing the cycle/perm anchor for the syscall pipeline.
- workload: PLUM-verify, execute mode, **syscall** arm (Griffin precompile) · date 2026-07-06 · λ=80
- config: `SHARD_SIZE=4194304` (2²²) `ELEMENT_THRESHOLD=67108864` (2²⁶) `HEIGHT_THRESHOLD=1048576` (2²⁰) `RAYON_NUM_THREADS=8`
- result: accepted=true · cycles **123,372,417** · **griffin_fp192=1052** · **uint256_mul=69,433** · peak **7.09 GB** · wall 33 s · verdict OK
- evidence: `docs/measurements/master_batch_20260706/M5_plum_execute_l80/meta.txt:9,12-15`; summary `.../MASTER_SUMMARY.tsv:2`

### A1. Cell 1 — PLUM-verify prove, EMULATED (no precompile) (C1e)
- workload: PLUM-verify prove · **emulated** (Griffin via rv32im, no precompile) · SHA-3? no (Griffin) · λ=80 · `PLUM_ZK_WRAP=core`
- config: TUNED `SHARD_SIZE=4194304` (2²²) `HEIGHT_THRESHOLD=1048576` (2²⁰) `ELEMENT_THRESHOLD=67108864` (2²⁶) `TRACE_CHUNK_SLOTS=2` `RAYON_NUM_THREADS=8`
- result: **DNF (time, watchdog cap 20 min; RSS ~13.62 GB, not memory-bound)** — rc=137, wall 1202 s; accepted=false; cycles NA; peak **13.62 GB**; verdict FINDING(bound)
- death: `WATCHDOG_KILL cap=1200s`
- evidence: `docs/measurements/master_batch_20260706/C1e_cell1_emulated/meta.txt:11,16-19`; `.../C1e_cell1_emulated/death_tail.txt:2`

> **Emulated-arm completion is EXTRAPOLATED, not measured.** The only completion figure for the no-precompile arm is a **~30 h linear extrapolation** (PLUM-verify only), derived from the Cell-1 emulated execute cycle count (7,213,403,896 cycles, §D1) vs the syscall prove anchor. The ~30 h value itself is **not present in any run record read here** — treat it as extrapolated and cite its derivation, never as a measured datum. (See "Flags," below.)

### A2. Cell 2 — PLUM-verify prove, SYSCALL (Griffin precompile + Uint256Mul) (C2, n=5)
- workload: PLUM-verify prove · **syscall** (Griffin precompile + `UINT256_MUL`) · Griffin hasher · λ=80 · `PLUM_ZK_WRAP=core` · cap 2700 s
- config: TUNED `SHARD_SIZE=4194304` (2²²) `HEIGHT_THRESHOLD=1048576` (2²⁰) `ELEMENT_THRESHOLD=67108864` (2²⁶) `TRACE_CHUNK_SLOTS=2` `RAYON_NUM_THREADS=8`
- execute sanity: accepted=true, cycles **123,372,417**

| run | prove_ms | prove_min | peak_gb | verdict |
|---|---|---|---|---|
| C2.run1 | 866465 | 14.44 | 12.91 | OK |
| C2.run2 | 850692 | 14.18 | 13.80 | OK |
| C2.run3 | 849426 | 14.16 | 13.37 | OK |
| C2.run4 | 850973 | 14.18 | 13.19 | OK |
| C2.run5 | 855438 | 14.26 | 15.09 | OK |

- n=5 summary: prove-time **14.16–14.44 min** (mean ≈ 14.24 min); peak RAM 12.91–15.09 GB; all accepted=true, cycles 123,372,417.
- evidence: `docs/measurements/master_batch_20260706/MASTER_SUMMARY.tsv:8-12`; per-run config `.../C2_cell2_syscall/run1/meta.txt:5,11,16-20`

### A3. Cell 3 — PLUM-verify prove, SHA-3 control (C3, n=5)
- workload: PLUM-verify prove · **sha3** arm (`PLUM_HASHER=sha3`, existing SHA precompile) · λ=80 · `PLUM_ZK_WRAP=core` · cap 2700 s
- config: TUNED `SHARD_SIZE=4194304` (2²²) `HEIGHT_THRESHOLD=1048576` (2²⁰) `ELEMENT_THRESHOLD=67108864` (2²⁶) `TRACE_CHUNK_SLOTS=2` `RAYON_NUM_THREADS=8`
- execute sanity: accepted=true, cycles **110,798,116**

| run | prove_ms | prove_min | peak_gb | verdict |
|---|---|---|---|---|
| C3.run1 | 799447 | 13.32 | 14.92 | OK |
| C3.run2 | 802815 | 13.38 | 14.31 | OK |
| C3.run3 | 791357 | 13.19 | 13.99 | OK |
| C3.run4 | 780924 | 13.02 | 14.84 | OK |
| C3.run5 | 798516 | 13.31 | 14.12 | OK |

- n=5 summary: prove-time **13.02–13.38 min** (mean ≈ 13.24 min); peak RAM 13.99–14.92 GB; all accepted=true, cycles 110,798,116.
- evidence: `docs/measurements/master_batch_20260706/MASTER_SUMMARY.tsv:13-17`; per-run config `.../C3_cell3_sha3/run1/meta.txt:8-12,17-21`

---

## B. Credential core — CreGen / ShowCre (syscall + emulated)

BDEC guests use the H16 config: small-shard, `HEIGHT_THRESHOLD=2^16` (overflow-avoidance).

### B1. CreGen — prove, SYSCALL (CG)
- workload: BDEC CreGen prove · **syscall** (Griffin precompile + `UINT256_MUL`) · λ=80 · cap 7200 s
- config: `SHARD_SIZE=1048576` (2²⁰) `HEIGHT_THRESHOLD=65536` (2¹⁶) `ELEMENT_THRESHOLD=67108864` (2²⁶) `TRACE_CHUNK_SLOTS=2` `RAYON_NUM_THREADS=8`
- execute sanity: accepted=true, cycles **289,221,111**
- result: prove_ms **4,137,423** = **68.96 min** · proof_bytes **1,473,690,434** · peak **13.21 GB** · accepted=true · verdict OK · wall 4229 s
- evidence: `docs/measurements/master_batch_20260706/CG_cregen_syscall/meta.txt:10,15-19`

### B2. CreGen — prove, EMULATED (no precompile) (R7e)
- workload: BDEC CreGen prove · **emulated** · λ=80 · cap 1800 s
- config: identical H16 (`SHARD_SIZE=1048576` / `HEIGHT_THRESHOLD=65536` / `ELEMENT_THRESHOLD=67108864` / `TRACE_CHUNK_SLOTS=2` / `RAYON_NUM_THREADS=8`)
- result: **DNF (time, watchdog cap 30 min; RSS ~13.75 GB, not memory-bound)** — rc=137, wall 1803 s; accepted=false; verdict FINDING(bound)
- death: `WATCHDOG_KILL cap=1800s`
- evidence: `docs/measurements/master_batch_20260706/R7e_cregen_emulated/meta.txt:10,15-18`; `.../R7e_cregen_emulated/death_tail.txt:1`

### B3. ShowCre k=1 — prove, SYSCALL (S1)
- workload: BDEC ShowCre prove · **syscall** · `BDEC_SHOWCRE_K=1` · λ=80 · cap 9000 s
- config: H16 (`SHARD_SIZE=1048576` / `HEIGHT_THRESHOLD=65536` / `ELEMENT_THRESHOLD=67108864` / `TRACE_CHUNK_SLOTS=2` / `RAYON_NUM_THREADS=8`)
- execute sanity: accepted=true, cycles **433,087,189**
- result: prove_ms **6,200,184** = **103.34 min** · proof_bytes **2,195,116,844** · peak **12.36 GB** · accepted=true · verdict OK · wall 6331 s
- evidence: `docs/measurements/master_batch_20260706/S1_showcre_k1_syscall/meta.txt:11,16-20`

### B4. ShowCre k=2 — prove, SYSCALL (S2)
- workload: BDEC ShowCre prove · **syscall** · `BDEC_SHOWCRE_K=2` · λ=80 · cap 12000 s
- config: H16 (as B3)
- execute sanity: accepted=true, cycles **575,089,654**
- result: prove_ms **8,209,063** = **136.82 min** · proof_bytes **2,911,822,343** · peak **13.83 GB** · accepted=true · verdict OK · wall 8384 s
- evidence: `docs/measurements/master_batch_20260706/S2_showcre_k2_syscall/meta.txt:11,16-20`

### B5. ShowCre k=1 — prove, EMULATED (no precompile) (R8e)
- workload: BDEC ShowCre prove · **emulated** · `BDEC_SHOWCRE_K=1` · λ=80 · cap 1800 s
- config: H16 (as B3)
- result: **DNF (time, watchdog cap 30 min; RSS ~13.63 GB, not memory-bound)** — rc=137, wall 1803 s; accepted=false; verdict FINDING(bound)
- death: `WATCHDOG_KILL cap=1800s`
- evidence: `docs/measurements/master_batch_20260706/R8e_showcre_k1_emulated/meta.txt:11,16-18`; `.../R8e_showcre_k1_emulated/death_tail.txt:1`

---

## C. Keystone (M4) + FMT tax + leakage (A2)

> These are the per-op / matched-field / anonymity side experiments. The keystone chip-prove uses the dedicated `FP192_MUL` / `FP192_POW_RES` chips (branch worktree, sp1 v6.2.1) — a **separate** experiment from the shipped syscall pipeline (§A/§B), which uses Griffin + `UINT256_MUL`.

### C1. FMT matched-field per-mult cycle tax (KFMT)
- workload: execute-mode per-mult cycle tax, Fp192 (ℓ=7) vs KoalaBear (ℓ=1); M=10000/20000 slope · date 2026-07-06
- config: `SHARD_SIZE=4194304` `ELEMENT_THRESHOLD=67108864` `HEIGHT_THRESHOLD=1048576` `RAYON_NUM_THREADS=8` (execute)
- result: Fp192 **3121.0930 cycles/mul**, KoalaBear **19.0 cycles/mul**, ratio **164.2681** (ℓ=7 baseline; ℓ²=49) · peak 7.75 GB · wall 11 s · verdict OK
- evidence: `docs/measurements/master_batch_20260706/KFMT_keystone_fmt_execute/meta.txt:12-16,18`

### C2. Keystone chip-prove (M4) — dedicated-chip vs host-served trace area
Deterministic precompile-chip trace area (cols × rows), sp1 v6.2.1 worktree fork, nothing committed. λ=80.
- `FP192_MUL` vs host `UINT256_MUL`, per 192-bit modmul (supervisor widths): dedicated **304** cells/op vs host **371** → ratio **0.8194** → model prediction **FALSIFIED** (dedicated ~18% smaller; hardcoding modulus deletes modulus-memory columns).
- `FP192_POW_RES` (B2) per symbol: dedicated **118,302** cells (ctrl 73 + 191×step 619) vs host `UINT256_MUL` S&M **96,831** (261×371) vs host `FP192_MUL` S&M **79,344** (261×304) → B2/uint256 **1.2217**, B2/fp192mul **1.4910** → chip-area verdict **NO PAY** (B2 larger); but execute-mode cycles B2 **365** vs guest-loop **6549** (**17.9× fewer** RISCV cycles) point the other way → full-machine verdict **INCONCLUSIVE**.
- completeness (prove smoke, all green): `test_fp192_mul` 12.32 s (22 ops); `test_fp192_powres_prove` 15.55 s; `test_uint256_mul` 17.34 s (102 ops).
- evidence: `docs/measurements/keystone_chipprove_20260706/RESULT.md:36-55,65-70,93-99,136-147`

### C3. Anonymity leakage — execute, N=20 (A2e)
- workload: 20 witnesses, fixed pk+M, fresh signing randomness, Cell-2 ELF · execute · λ=80
- config: `SHARD_SIZE=4194304` `HEIGHT_THRESHOLD=1048576`
- result: cycles distinct=20, min **123,827,404** max **126,263,077** spread 2,435,673; **griffin_fp192 distinct=1 (1052, spread 0)**; uint256_mul distinct=20 (69,313–69,436); sig_bytes invariant (47,976). Verdict FINDING(leak-located): trace-count invariant (positive anonymity micro-result) but nonzero cycle spread = located leak. peak 7.69 GB, wall 502 s.
- evidence: `docs/measurements/master_batch_20260706/A2e_leakage_execute/meta.txt:8-13`

### C4. Anonymity leakage — prove, N=3 (A2p)
- workload: 3 witnesses, core-prove, proof-size variance · λ=80 · cap 5400 s
- config: TUNED `SHARD_SIZE=4194304` (2²²) `HEIGHT_THRESHOLD=1048576` (2²⁰)
- result: 3 proofs, all accepted; prove_ms 856241 / 865353 / 850380; proof_bytes 154,665,328 / 156,116,354 / 153,205,678 (distinct=3, spread 2,910,676) → proof_size data-independent = false. peak 14.52 GB, wall 2661 s, verdict OK.
- evidence: `docs/measurements/master_batch_20260706/A2p_leakage_prove/meta.txt:8-14`

---

## D. Certain-tier (2026-07-07) — Cell-1 execute · fixpoint · POW_RES settle

### D1. Cell-1 PLUM-verify execute, EMULATED (a)
Establishes the emulated cycle count that anchors the ~30 h extrapolation.
- workload: PLUM-80 verify, execute, **emulated** (Griffin via rv32im, no precompile), Griffin hasher · input 216,232 bytes
- result: accepted=true · cycles **7,213,403,896** · elapsed_ms 34,315 · syscalls **4,870,761** (all `uint256_mul=4,870,761`; **griffin_fp192=0**)
- evidence: `docs/measurements/certain_tier_20260706/a_cell1_execute_emulated/stdout.log:1-5`

### D2. Fixpoint reconfirm (b)
- workload: recursion-shape fixpoint check — `test_find_recursion_shape`
- result: **ok. 1 passed** (finished in 4.47 s); confirms the recursion shape is a fixpoint.
- evidence: `docs/measurements/certain_tier_20260706/b_fixpoint_reconfirm/stdout.log:3-5`

### D3. POW_RES settle — B2-only prove (c1) and S&M-only prove (c2)
Single-arm settle on an identical **28-symbol** workload (branch `prf-precompiles`, fork HEAD `5c82940bda…`, dirty = powres guests + settle tests, uncommitted). λ=80, `SP1_PROVER=cpu`, cap 10800 s (3 h) + 24 GB watchdog.
- **c1 (B2-only):** N_SYMBOLS=28, 28 `FP192_POW_RES` syscalls, 0 `FP192_MUL` → passed=true, wall **34 s**, peak **2.79 GB**, verdict OK.
- **c2 (S&M-only):** N_SYMBOLS=28, 7308 `FP192_MUL` syscalls (28×261), 0 `FP192_POW_RES` → passed=true, wall **40 s**, peak **2.91 GB**, verdict OK.

> **Fix that unblocked c1.** The B2 arm passed **only after** the `FP192_POW_RES` multi-shard executor fix (a spurious `clk` bump in the syscall handler was corrected). The fix is a code change on branch `prf-precompiles`; it is **not itself documented in these run records** — see Flags.

> **Use the summed 3-shard trace-cell totals, not the driver field.** The driver's `CERTAIN_SUMMARY.tsv` (and the RESULT.md header line) report only the **first shard**, which is buggy. From the RESULT.md verbatim per-shard lines:
> - c1 (B2): 1,937,552 + 4,830,240 + 4,601,824 = **11,369,616 ≈ 11.37 M cells**
> - c2 (S&M): 30,256,496 + 34,860,256 + 4,713,632 = **69,830,384 ≈ 69.83 M cells**
> - → S&M / B2 = **6.14×**, i.e. **B2 pays ~6.1×** at the full-machine (summed unpadded) level. (This flips the per-op keystone's "B2 chip 1.22–1.49× larger": on the real 28-symbol prove, B2's RISCV-cycle saving dominates.)

- evidence (verbatim shard lines): `docs/measurements/certain_tier_20260706/c1_powres_b2_prove/RESULT.md:19-21`; `.../c2_powres_sm_prove/RESULT.md:19-21`; first-shard-only driver field `docs/measurements/certain_tier_20260706/CERTAIN_SUMMARY.tsv:2-3`; metas `.../c1_powres_b2_prove/meta.txt:9-10`, `.../c2_powres_sm_prove/meta.txt:9-10`

---

## E. ZK-wraps (sound path, native gnark, stock v6.1.0)

All on sp1 submodule @`74e1c1e8a`, branch `griffin-standard-mds-fix`, probe_b working tree. Chain: Core → Compress → Shrink → Wrap(BN254) → Plonk(gnark native) → SP1 verify. Sound-path: `vk_verification ON`, `mprotect OFF`, `SP1_CIRCUIT_MODE unset`, workers=2, `SP1_PROVER=cpu`, reduced vk_map + stock v6.1.0 gnark circuit.

### E1. Probe B — griffin_smoke wrap (feasibility)
- workload: `griffin_smoke` guest (elf 75,592 bytes) · λ n/a (smoke)
- result: core_prove **10.41 s**, core_shards **3**, build_vks **16.36 s** (n_setups=15), plonk_chain **767.93 s** (≈12.80 min), verify **0.25 s VERIFY_OK** → **PASS**. gnark plonk `nbConstraints=27,576,375`. maxRSS **16,174,137,344 B = 15.06 GiB**. test finished in 818.28 s.
- evidence: `/private/tmp/claude-501/-Users-takumiotsuka-…/scratchpad/probeb_native_run.log:5-7,23,43,51-53,56,59` (scratchpad; not committed under docs/)

### E2. PLUM-verify wrap
- workload: **Cell-2 syscall ELF** (`GRIFFIN_FP192_PERMUTE=1052`, `UINT256_MUL≈69,433`, cycles 123,372,417, exact Cell-2 witness match) · λ=80 · config inherited from Cell-2 tuned (SHARD 2²², HEIGHT 2²⁰)
- result: **PASS / VERIFY_OK**. core_shards **104** (7 distinct shard shapes + 12 tail = 19 union setups); `nbConstraints=27,576,375` (stock 27.5 M circuit); gnark prove 589,360.87 ms (9.82 min).
  - **deployable per-proof wrapped wall = plonk_chain 2810.04 s = 46.83 min** (decomp: Core ~15.0 + Compress+Shrink ~18.9 + Wrap(BN254) ~2.9 + Plonk ~10.2 min).
  - one-time setup (amortized, not per-proof): standalone Core 898.75 s + build_vks 30.57 s (19 setups) = 929.32 s = 15.49 min.
  - **peak RAM (maxRSS) = 16,418,865,152 B = 15.29 GiB** (headroom 8.71 GiB / 36% under 24 GB).
  - Δ vs non-wrapped Cell-2 STARK: wrap tail (Compress+Shrink+Wrap+Plonk) = 1911.29 s = 31.85 min added → ~3.3× wall, +31.9 min.
- evidence: `docs/measurements/plum_verify_wrap_20260707/progress.log:10,18-25,31-33,39,42,49`

### E3. CreGen wrap (first BDEC wrap)
- workload: **measured CreGen syscall ELF** (target cycles 289,221,111, `GRIFFIN_FP192_PERMUTE=13,206`, `UINT256_MUL=137,971`, exact measured-CreGen witness match) · λ=80
- config: `SHARD_SIZE=2^20` `HEIGHT_THRESHOLD=2^16 (=65536, overflow-avoidance)` `ELEMENT_THRESHOLD=2^26` `TRACE_CHUNK_SLOTS=2` `RAYON_NUM_THREADS=8` · guards: 23.5 GB tree-RSS soft-kill + 5.5 h wall cap (cap later **lifted** at ~4 h once RAM proven bounded)
- result: **PASS / VERIFY_OK**. core_shards **1018** (9.8× PLUM's 104; 14 distinct shard shapes → 26 union setups); `nbConstraints=27,576,375` (stock, = PLUM); gnark plonk took 669,739 ms = 11.16 min.
  - **deployable per-proof wrapped wall = plonk_chain 15,127.24 s = 252.12 min = 4.20 h** (Compress ~166 min dominates, ~0.16 min/shard ≈ linear in shard count).
  - one-time setup (amortized): standalone Core 4346.13 s (72.44 min) + vk_map 40.72 s (26 setups) = 73.11 min.
  - **peak RAM (maxRSS) = 16,780,476,416 B = 15.63 GiB** (headroom 8.37 GiB / 35% under 24 GB; sampler peak 14.98 GiB). RAM bounded throughout (compress does not accumulate) → full CreGen wrap fits 24 GB.
- evidence: `docs/measurements/cregen_wrap_20260707/progress.log:4,10,18-19,28,30,32-39`

### E4. ShowCre wrap — PROJECTED, PAUSED (not run)
- ShowCre k=1 / k=2 zk-wraps were **not executed**. Projection (~5.9 h k1 / ~7.7 h k2) is a caller-supplied estimate scaled from the CreGen wrap's shard-count → compress-tail relationship; **no ShowCre-wrap run record exists**. See §F (TODO) and Flags.

---

## F. Not-yet-run / TODO

- **ShowCre wraps (k=1, k=2):** paused, not run. Projected ~5.9 h (k1) / ~7.7 h (k2) — projection only, no record.
- **RISC0 re-baseline:** no standard-Griffin-era RISC Zero run in these records (the only RISC0 CreGen composite record is the terminated 2026-05-31 restructure run, `docs/measurements/risc0_cregen_composite_20260531_1553/RESULT.md`, out of this era).
- **λ=128 re-measurement:** all runs above are λ=80; no λ=128 run recorded.
- **Emulated-arm completion (measured):** only DNF-by-watchdog exists (§A1/§B2/§B5); a real completing emulated prove has not been run — the sole completion figure is the ~30 h extrapolation.

---

## Flags — parameters/numbers NOT found in the records read

1. **~30 h emulated-completion figure (§A1):** the ~30 h value and its exact extrapolation arithmetic are **not present in any record here**. Records supply only the inputs: Cell-1 emulated execute cycles 7,213,403,896 (§D1) and the syscall prove anchor (§A2). Mark ~30 h as EXTRAPOLATED (PLUM-verify only), not measured.
2. **ShowCre-wrap projection ~5.9 h / ~7.7 h (§E4):** not in any run record — no ShowCre-wrap was executed. Caller-supplied projection only.
3. **POW_RES multi-shard executor "spurious clk bump" fix (§D3):** the fix is asserted (and is consistent with c1 passing) but the diff/handler change is **not documented inside the certain-tier run records** — it lives in branch `prf-precompiles` code, not in the measurement artifacts read here.
4. **Probe B (§E1)** evidence is in the session scratchpad (`.../scratchpad/probeb_native_run.log`), **not** under `docs/measurements/` — flagged for provenance since it is not committed with the other records.

_All other run parameters (config knobs, arms, hashers, caps, results) were found verbatim in the cited records._
