# Keystone matched-field control — FORECAST (recorded before any run)

**Status: held-out forecast.** This file is written and committed BEFORE the guest
program exists and BEFORE any measurement. The measurement (RESULT.md, to follow)
is the test of these predictions. Editing the numbers below after seeing a result
would void the held-out property.

Date recorded: 2026-07-01. Author: criterion-spine measurement plan.

## What is being tested

`prop:field-match` (§4, `04-theoretical.tex`): for an algebraic primitive whose
cost is dominated by `F_p` arithmetic, the field-mismatch benefit a precompile
removes is `0` at `ℓ=1` (native field = prover field) and grows as `Θ(ℓ²)` for
`ℓ>1`. Its load-bearing input is `prop:fmt-lb`: per multiplication,
`FMT(mult) = cyc_em / cyc_nat ∈ [ℓ, ℓ²]`, with the schoolbook routine the
evaluated zkVMs use attaining the `ℓ²` end.

Here `ℓ = ⌈log₂ p / ⌊log₂ p_vm⌋⌉`. Prover field = SP1 KoalaBear,
`p_vm = 2³¹ − 2²⁴ + 1`, so `⌊log₂ p_vm⌋ = 30`. For PLUM's `F_p` (199-bit),
`ℓ = ⌈199/30⌉ = 7`.

## Measurement (execute-mode, no proving)

A guest performs `M` field multiplications over field `F`, using the **software
(non-precompile) multi-limb** path, and the host reports total execute-mode guest
cycles. Run for:
- `F = KoalaBear` (ℓ=1, native single-limb) → `cyc_KB`
- `F = Fp192` (199-bit, ℓ=7, software multi-limb emulation; precompile dispatch
  disabled so the un-mitigated emulation cost is what is counted) → `cyc_192`

Per-multiplication cost: `c_F = (cyc_F − cyc_baseline) / M`, where `cyc_baseline`
is an `M=0` (or loop-only) run subtracted to remove loop/IO overhead.

## FORECAST (predictions, recorded before the run)

1. **Per-mult field-mismatch tax** `c_192 / c_KB ∈ [7, 49]`, schoolbook-dominated,
   so expected **near the ℓ²=49 end** (the whole-workload Cell-1/Cell-2 ratio of
   `56.4×` sits just above `49`, consistent with permutation-level overhead on top
   of the bare multiplication bound).
2. **Necessity direction of `prop:field-match`:** the emulation cost `cyc_em` that a
   precompile would remove is `≈ ℓ²·cyc_nat` at `ℓ=7` and `≈ 1·cyc_nat` at `ℓ=1`,
   i.e. the field-mismatch benefit is **~0 at the matched field** and large at the
   mismatched field.
3. **Prove-mode corollary (to be confirmed separately, on target hardware):** by
   `prop:precompile-pays`, at `ℓ=1` the benefit term `(cyc_em − cyc_syscall)` is
   non-positive (a native multiplication costs no more than the syscall overhead),
   while chip area `A_P > 0`; therefore a precompile **does not pay on the
   field-mismatch axis** for a field-matched algebraic primitive. Predicted sign:
   no field-mismatch prove-time benefit at `ℓ=1`.

## Falsification conditions

- `c_192 / c_KB ≈ 1` (no scaling with `ℓ`) would falsify `prop:fmt-lb` and the
  necessity half of `prop:field-match`.
- `c_192 / c_KB` far below `ℓ=7` would mean the limb-aligned lower bound is wrong.
- `c_192 / c_KB` far above `ℓ²=49` (beyond permutation/control overhead) would mean
  the model omits a super-quadratic term and the trace-area accounting needs revision.

## Notes / scope

- This measures the FIELD-mismatch tax for an **algebraic** operation (multiplication),
  the class `prop:field-match` governs. Bitwise primitives (SHA/Keccak) carry a
  separate bit-emulation tax and are out of scope (§4 scope paragraph).
- A stronger, follow-on test holds the **primitive** constant and varies only the
  field (e.g. Poseidon2 over KoalaBear vs over the 199-bit prime), isolating the
  field axis at the permutation level; it requires building a large-field Poseidon2
  arm and is deferred.

## Apparatus note (recorded before the run, after inspecting the implementation)

The software Fp192 multiplication path (`src/primitives/field/p192.rs`, the
`#[cfg(not(all(target_os="zkvm", feature="sp1")))]` arm) uses `num_bigint::BigUint`
(general-purpose bignum: heap allocation, non-limb-aligned), **not** the limb-aligned
4×u64 schoolbook routine that `prop:fmt-lb`'s `ℓ²` bound assumes — the module's
Phase-1.5 swap to explicit limb arithmetic is not yet done (doc-comment p192.rs:54-62).
The KoalaBear baseline is a naive single-limb `u64` `(a·b) mod p`
(`p = 2³¹−2²⁴+1 = 0x7f000001`), an upper bound on the true native-field cost.

Consequence: `prop:fmt-lb` is a **lower** bound (`FMT ≥ ℓ`); `num_bigint ≥ schoolbook`,
so the measured per-mult ratio should be **≥ ℓ=7** and likely **well above ℓ²=49**
(BigUint overhead) — which is CONSISTENT with the lower bound, not a violation. The
schoolbook-tight test (ratio near 49) needs the Phase-1.5 limb-aligned mul and is
deferred. **What this run tests is the necessity direction of `prop:field-match`:**
the field-mismatch benefit (= emulated cost a precompile removes) is large at ℓ=7 and
collapses toward the native single-limb cost at ℓ=1.

Revised falsification: ratio `≈ 1` (no scaling with field width) falsifies necessity;
ratio `≥ 7` (any large value) confirms it. The absolute magnitude is an implementation
datum (num_bigint), not the schoolbook bound.
