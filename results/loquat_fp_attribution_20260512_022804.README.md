# Loquat zkVM two-level attribution: Griffin + F_p multiplication — 2026-05-12

## Setup

Two-level cycle attribution: at the **Griffin permutation** abstraction
and at the **F_p (Mersenne-127) multiplication** abstraction, both
measured empirically by counter instrumentation and microbench.

Added in this iteration:
- `FP127_MUL_COUNT: AtomicU64` in [src/loquat/field_p127.rs](../src/loquat/field_p127.rs)
- Incremented in `impl Mul for Fp127`
- New `fp_mul_microbench` guest + host binaries
- Updated `loquat_only` guest to snapshot Fp127 mul count per phase

The Griffin permutation counter was re-microbenched under the new counter
overhead (slightly higher than the earlier 892,840 figure) to keep all
attribution numbers internally consistent.

Files:
- `loquat_fp_attribution_20260512_022804.jsonl` — 3 attribution rows
- `loquat_fp_attribution_20260512_022804_griffin_bench.json` — Griffin microbench (re-run)
- `loquat_fp_attribution_20260512_022804_fp_bench.json` — Fp127::mul microbench
- This README

## Microbenches

| primitive | n | total cycles | **cycles per op** |
|---|---:|---:|---:|
| Griffin permutation (raw, 4-lane, ~11 rounds) | 10,000 | 9,100,998,768 | **910,099** |
| Fp127::mul (Mersenne-127, tight loop) | 100,000 | 24,353,920 | **243** |

The Griffin per-permutation cost moved from 892,840 (without Fp127
counter) to 910,099 (with Fp127 counter). The ~2% increase is the
overhead of the Fp127 counter increment, called ~2,580 times per
permutation — consistent with ~7 cycles per atomic-add.

## Total attribution at three security levels

| λ | total cycles | Griffin perms | F_p muls | **Griffin %** | **F_p mul %** | non-Griffin % |
|---:|---:|---:|---:|---:|---:|---:|
| 80 | 698,611,363 | 727 | 1,856,229 | **94.71%** | **64.57%** | 5.29% |
| 100 | 856,977,477 | 884 | 2,276,714 | **93.88%** | **64.56%** | 6.12% |
| 128 | 912,170,913 | 931 | 2,418,910 | **92.89%** | **64.44%** | 7.11% |

Both attributions are **measured**, not projected.

## Inside one Griffin permutation (λ=128)

| component | cycles | % of Griffin |
|---|---:|---:|
| F_p multiplications (~2,580 per perm × 243 cyc) | 627,116 | **68.91%** |
| Other work (F_p additions, struct ops, function calls, control flow) | 282,983 | **31.09%** |
| **Total Griffin cyc/perm** | **910,099** | 100% |

A Griffin permutation is **not** a pure F_p multiplication pile — only
~69% of its cycles are multiplications. The other ~31% is the cost of
manipulating 128-bit values on 32-bit RISC-V: multi-word copies, struct
field accesses, function call ABI overhead. These are still
arithmetic-mismatch artifacts, but they are *not* attacked by a pure F_p
multiplication precompile — they would require a Griffin-level
precompile that handles the entire round structure as one circuit
operation.

## Outside Griffin (λ=128)

The 7.11% non-Griffin remainder at λ=128 (≈64.9M cycles) splits roughly:

| component | F_p mul cycles | non-F_p-mul cycles |
|---|---:|---:|
| Legendre PRF checks (`legendre_constraints` phase) | ~4M | ~2M |
| FRI polynomial reconstruction (inside `ldt_openings`) | ~1M | ~50M |
| Loquat control flow, struct ops, transcript bookkeeping | 0 | ~8M |
| **Subtotal** | **~5M** | **~60M** |

The bulk of non-Griffin work is **F_p² operations in FRI polynomial
reconstruction**: F_p² addition, subtraction, and the multi-limb
multiplications inside F_p². These are uncounted by `FP127_MUL_COUNT`
(which counts only F_p mults; F_p² adds don't decompose into F_p muls)
but show up in the cycle count as the ~50M "non-F_p-mul" non-Griffin
work.

## Honest interpretation: how the two abstractions relate

The vault and prior thesis framing identified the **Arithmetic Mismatch**
as the root cause: Loquat operates over F_p (and F_p² for FRI), neither
of which match RISC-V's native 32-bit word size, forcing multi-limb
software emulation on every field operation.

This measurement confirms it at multiple levels:

| abstraction | what's attributed | empirical attribution at λ=128 |
|---|---|---:|
| **Algorithm** (Griffin permutations) | Griffin perm × cycles_per_perm | **92.89%** |
| **Arithmetic** (F_p multiplication) | F_p muls × cycles_per_mul | **64.44%** |
| **Architecture** (any non-native-word work) | All cycles minus a small irreducible floor | likely ~99%+ if also counted F_p² ops |

The three attribution numbers are not in conflict. They are *the same
phenomenon at different levels*:

- The Algorithm-level view says: *replace Griffin permutations with a
  precompile circuit and you attack 92.89% of cycles*.
- The Arithmetic-level view says: *replace F_p multiplications with a
  precompile and you attack 64.44% of cycles*.
- The Architecture-level view (implied, not yet measured) would say:
  *every F_p and F_p² operation in software is expensive on 32-bit
  RISC-V; replace all of them with precompiles and you attack nearly
  100%*.

**The Architecture-level claim is the thesis-level claim.** The Algorithm
and Arithmetic measurements are *evidence for* the Architecture claim,
not competing claims.

## Revised speedup projections (correcting the earlier spec)

The earlier `spec/griffin_precompile.md` projected **35.8×** speedup at
λ=128 with both a Griffin and an F_p mul precompile. That projection
was wrong because it assumed F_p mul precompile would attack the entire
non-Griffin remainder. The measurement shows otherwise.

Revised projections, assuming Griffin precompile costs 100 cyc/invocation
and F_p mul precompile costs 5 cyc/invocation:

| λ | baseline | Griffin precompile alone | F_p mul precompile alone | Griffin + F_p mul precompiles |
|---:|---:|---:|---:|---:|
| 80 | 698.6 M | 37.0 M (**18.9×**) | 256.8 M (2.7×) | 32.9 M (**21.2×**) |
| 100 | 857.0 M | 52.5 M (**16.3×**) | 315.1 M (2.7×) | 47.4 M (**18.1×**) |
| 128 | 912.2 M | 65.0 M (**14.0×**) | 336.5 M (2.7×) | 59.9 M (**15.2×**) |

Key correction: **adding an F_p mul precompile on top of a Griffin
precompile gives only ~1× additional speedup**, not ~2.5× as I projected
in the spec. The reason: most non-Griffin work is F_p² additions and
struct manipulation, not F_p multiplications.

To reach ~30× or higher speedups at λ=128, you would need a third
precompile: F_p² arithmetic (covering both add and mul over the
quadratic extension used in FRI). This is design-space work for the
spec, not addressed by the current measurement.

## Implications for the precompile design

1. **A Griffin precompile is the right primary target.** It attacks
   92.89% of cycles, including the ~28% non-mul work inside Griffin
   that an F_p mul precompile cannot reach. Projected speedup at
   λ=128: ~14×.
2. **An F_p mul precompile alone has limited value** (~2.7× speedup
   regardless of Griffin precompile presence). It is *not* a substitute
   for a Griffin precompile.
3. **The bottleneck for higher speedups is F_p² arithmetic in FRI**,
   not F_p arithmetic in Griffin. A precompile spec for F_p² operations
   over Mersenne-127's quadratic extension would push the speedup from
   ~15× toward ~50×+. This is a natural extension of the spec.
4. **The "Arithmetic Mismatch" framing is rigorously supported.** The
   F_p multiplication measurement provides a 64.44% lower bound that
   any reviewer can verify by inspecting the counter + microbench data.
   The Griffin measurement at 92.89% is a stronger statement at a
   higher level of abstraction.

## What changed about the spec

The earlier spec (`spec/griffin_precompile.md` v0.1) projected ~35.8×
speedup at λ=128 with both Griffin and F_p mul precompiles. The
empirical data shows that figure is incorrect — the correct projection
is ~15.2× with both precompiles, because F_p mul precompile attacks
only a small additional slice (~5M cycles) on top of what the Griffin
precompile already covers.

The spec should be revised in §5 to:
- Replace the 35.8× projection with the measured 15.2×.
- Add a third precompile candidate (F_p² arithmetic) targeting FRI
  polynomial reconstruction work.
- Project the combined Griffin + F_p² precompile speedup as the path
  to ~30× and beyond.

I will produce that revision separately.

## Caveats

1. **Counter overhead is ~2% on Griffin permutations** (910,099 vs 892,840
   cycles/perm). The Griffin attribution percentage is robust to this;
   absolute numbers shifted by ~3%.
2. **The F_p² operation count is not directly measured.** F_p² adds
   don't decompose into F_p muls, so they are uncounted. The "~50M
   non-mul cycles in FRI" claim is derived by subtraction, not direct
   measurement. A follow-up measurement could instrument F_p² operations
   for a third level of attribution.
3. **All projections assume modeled precompile costs** (Griffin: 100
   cyc; F_p mul: 5 cyc) based on comparable RISC0 precompiles. Actual
   costs would depend on implementation.
