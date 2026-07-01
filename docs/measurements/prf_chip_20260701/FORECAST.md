# PRF symbol-check precompile — held-out FORECAST (second interface instantiation)

**Status: held-out.** Written before the chip exists. Tests (i) the framework's
*method* claim and (ii) the criterion's *cross-primitive* prediction. Editing after
a result voids the held-out property.

Date recorded: 2026-07-01.

## The primitive
The *t*-th power-residue PRF symbol check is `a^((p-1)/t) mod p`, `t=256`, so the
exponent `(p-1)/256` is ~191-bit. Square-and-multiply ≈ **~300** `Fp192`
multiplications (`p192.rs`: "~300 syscalls"). Its current realization is a **guest
loop** whose every multiplication already routes to the `UINT256_MUL` precompile.

## What is tested
1. **METHOD (framework).** The precompile interface — input-output equivalence over
   `F_p`, isolation behind a cross-table lookup, constant preprocessing-bound
   modulus — carries from the Griffin *permutation* to this *modexp*, with a
   soundness argument of the same shape. If it carries, the construction has **two**
   instantiations of one interface: "a precompile" → "a family."
2. **CRITERION (predictive).** `prop:precompile-pays` predicts whether the PRF
   precompile lowers prove cost.

## FORECAST (committed before design/measure)
- **METHOD:** the interface **carries**. The modexp is large-prime algebraic (same
  class as Griffin); i/o-equivalence + isolation + constant-modulus apply unchanged;
  the soundness argument instantiates the interface (the chip computes
  `a^((p-1)/t) mod p`, memory-bound, over a fixed modulus). Prediction: carries →
  the construction becomes a family.
- **CRITERION (sign): the PRF precompile does NOT pay** significantly in prove time.
  Reason (`prop:precompile-pays`): its ~300 multiplications are **already** served by
  `UINT256_MUL`, so a dedicated modexp chip re-internalizes essentially the same
  modmul trace (chip area ≈ ~300 modmul-rows) while removing only the guest
  loop/syscall-orchestration overhead (small core area). Removed core < added chip
  area → **does not pay**. This is a **different** no-pay reason than the matched-field
  case: here the primitive is *mismatched* (`ℓ=7`) but *already covered* by a
  lower-level precompile.
- **Two-outcome criterion demonstration:** Griffin (mismatched, unserved → **PAYS**,
  recovers feasibility) vs PRF (mismatched, already-served → **does NOT pay**), both
  predicted by the same inequality.

## Falsification
- Interface does **not** carry (modexp needs a fundamentally different soundness
  shape) → the "method"/"family" claim fails; it's two ad-hoc chips.
- Criterion **sign wrong** (PRF precompile pays substantially) → cross-primitive
  predictiveness falsified; revisit `prop:precompile-pays`.

## Note (why build a precompile predicted not to pay)
Its value is the METHOD (interface carries → family) + the CRITERION validation
(predicted no-pay), **not** a speedup. A precompile the criterion says won't pay is
the point: the criterion tells you which precompiles *not* to build.

## Soundness gate (do not skip)
"A family" is earned only when the chip's **constraint-level soundness** is
established as an interface instantiation (per-family argument like Griffin's
Appendix B), not merely when it smoke-proves. A smoke-passing-but-unaudited chip
does NOT flip the first-liner.
