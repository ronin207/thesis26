# B2 result — measured vs. held-out FORECAST

Date: 2026-07-01. Fork-worktree branch `prf-precompiles`. **FORECAST.md
was NOT edited** (held-out property preserved); this file records the
outcome.

## What was built

The composed t-th power-residue PRF symbol-check precompile (structure
B2): `FP192_POW_RES` computes `a <- a^((p-1)/t) mod p`, `t=256`, in one
syscall. Executor path (compute + event + tracing/minimal handlers +
guest entrypoint) and the AIR chips (controller + per-step, with the
schedule↔selector one-hot binding + S&M chaining constraints) all
**compile**; the executor path is **execute-verified** (symbol ==
guest-loop == BigUint reference). Full `RiscvAir` integration + the
191-step cross-chip lookup are **not wired**, so B2 is **not
smoke-proven** (honest status; see SOUNDNESS_B2.md §5).

## Parameters (measured)

- Exponent `e = (p-1)/256`: **L = 191 bits**, popcount **70**.
- S&M multiplications per symbol = `L + popcount` = **261**.
- B2 step chip width: **619 columns/row**; controller: **73 columns**.
- B2 step-rows per eval: **191**, each row = **2 `FieldOpCols`** (one
  unconditional square + one unconditional multiply, selected).

## The two-outcome criterion (the actual test)

| | Griffin (Precompile #1) | PRF / B2 (Precompile #3) |
|---|---|---|
| field-match | mismatched (ℓ=7) | mismatched (ℓ=7) |
| already served by a lower precompile? | **no** (nothing does Griffin) | **yes** (`FP192_MUL`/`UINT256_MUL` already do every modmul) |
| forecast | PAYS (recovers feasibility) | **does NOT pay** |
| measured | (prior work) | **does NOT pay — confirmed** |

## CRITERION result: does NOT pay — **matches forecast (sign correct)**

The forecast predicted the PRF precompile does **not** pay in prove
cost, because its ~300 multiplications are already served by the modmul,
so a controller re-internalizes essentially the same modmul trace.

**Prove-cost proxy (chip area), measured exactly:**
- Guest-loop realization: **261** `Fp192Mul` chip rows/eval (1
  `FieldOpCols` each) — the de-facto baseline.
- B2: **382** `FieldOpCols`/eval (191 step-rows × 2) **plus** a
  192-wide one-hot per step **plus** the controller row + cross-chip
  lookup.

So B2 **re-internalizes the modmul area and adds to it** (382 > 261
field multiplies), removing only the guest RISC-V loop/dispatch
overhead. It does not reduce — it slightly increases — the
prove-dominating field-arithmetic area. **Does not pay. Forecast
confirmed, and by a cleaner mechanism than anticipated** (the forecast
guessed "chip area ≈ ~300 modmul-rows"; the AIR is forced to do an
*unconditional* multiply every step, so it is worse: 382 vs 261).

## The instructive nuance: execute-mode cycles MISLEAD

Measured execute-mode cost per PRF symbol (`take_cycle_tracker_totals`,
`test_fp192_powres_execute`):

| realization | execute cycles / symbol |
|---|---|
| B2 (1 syscall) | **365** |
| guest-loop (261 `FP192_MUL` syscalls) | **6,549** |
| ratio | **17.9× fewer for B2** |

Execute-mode strongly *favors* B2 — because it counts RISC-V
instruction/syscall-dispatch cycles, of which B2 issues one vs. 261.
**But this is not the metric the forecast is about.** Prove cost is
dominated by chip trace area (the `FieldOpCols` blocks), which B2 does
NOT reduce (382 ≥ 261). The ~6,184-cycle execute saving is exactly the
"small core area removed" the forecast named — negligible against the
modmul area that both realizations must pay. **Reporting execute cycles
alone would falsely suggest B2 pays; the prove-cost (chip-area) metric
shows it does not.** This is the sharpest single finding of B2.

## METHOD result: interface carries, with one new obligation

The precompile interface (i/o-equivalence, isolation, constant
preprocessing-bound parameters) instantiates for the modexp with a
soundness argument of the same shape as Griffin's — **carries.** The
one thing that is genuinely new (absent in B1) is the fixed-exponent
schedule↔selector equality (F7) + chain balance (F8). Per the
FORECAST's soundness gate, the "family" first-liner is earned only once
F7/F8 is established at the constraint level; today F7 is drafted and
**partially discharged** (per-row bit-binding proven; chain
completeness still an assumption pending the lookup wiring). See
SOUNDNESS_B2.md.

## Falsification check

- Interface did NOT fail to carry (no fundamentally different soundness
  shape needed) → METHOD not falsified.
- CRITERION sign NOT wrong (B2 does not pay in prove cost) → predictive
  claim not falsified.
