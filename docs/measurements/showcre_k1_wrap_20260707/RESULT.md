# showcre_k1_wrap_20260707 — BDEC ShowCre (k=1) sound zk-wrap, end-to-end

**Run:** started 2026-07-07T18:07:38Z, ended 2026-07-08T05:53:56Z (~11.76 h, continuous, no sleep gap).
rc=0, VERIFY_OK. PID 18510.
Harness: `sp1_prover` test `shapes::tests::probe_showcre_plonk_reduced_vkmap`; reduced vk_map
(guest-own shard shapes, ~24 setups), stock gnark v6.1.0 PLONK/BN254 wrap circuit.
Workload: BDEC ShowCre k=1 = k+2 = 3 PLUM-Griffin verifications (standard-Griffin), λ=80.
Witness = real measured ShowCre, execute-validated at generation time
(cycles=433,087,189, GRIFFIN_FP192_PERMUTE=19,809).

## RESULT (MEASURED)
- **VERIFY_OK** — gnark PLONK/BN254 verifier accepted (`verify END wall_s=0.25 VERIFY_OK`; `PASS`).
- **observed_total_wall_s = 42,335.25 s ≈ 11.76 h** (11 h 46 m), continuous end-to-end.
  Decomposition (from the `SHOWCREWRAP PASS` line):
  - `setup_core_wall_s      = 10,641.07 s ≈ 2.96 h`  — one-time standalone shape-extraction Core pass
  - `vkmap_wall_s           =     58.27 s`           — reduced vk_map build (~24 setups)
  - `deployable_per_proof_wall_s = 31,635.67 s ≈ 8.79 h`  — plonk_chain (Core+Compress+Shrink+Wrap+Plonk)
  - `verify_wall_s          =      0.25 s`
- **peak RSS = 15,654,400 KB = 14.93 GiB** (sampler_peak_kb=15654400) — under the 24 GB / 23.5 GB softkill budget.

## Reading
- ShowCre k=1 (3 verifies) sound zk-wrap is DEPLOYABLE on 24 GB: completes and verifies,
  ~8.79 h deployable-per-proof (given setup), ~11.76 h end-to-end incl. the one-time core-shape pass,
  peak 14.93 GiB.
- Wrap cost scales with the number of verifications / shards, consistent with compress dominating and
  scaling with shard count: single-verify PLUM wrap 46.83 min → CreGen 2-verify wrap 4.20 h →
  ShowCre k=1 3-verify wrap 8.79 h (per-proof).
- Timing valid: continuous run, no sleep/clamshell gap (log timestamps + rss sampler continuous).

## Scope / honesty
- k=2 (4 verifies) is NOT run here. Awaits explicit Operator go. Do NOT extrapolate a k=2 number from this.
- Non-statement-bound cost workload (guest commits pass/fail boolean, JBind off); this prices the
  ShowCre verification wrap, it is not a realised anonymity instance.

## Thesis touchpoints (update in careful mode, no scale/skip language)
- §5/§6 "ShowCre wrap not produced" → PRODUCED / measured: 8.79 h deployable-per-proof,
  11.76 h end-to-end, 14.93 GiB peak, VERIFY_OK.
