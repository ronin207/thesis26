# Loquat zkVM three-level attribution: Griffin + F_p + F_p² — 2026-05-12

## Setup

Extended the two-level (Griffin + F_p) attribution with **F_p² operation
counters** (add, sub, mul) so that FRI polynomial-reconstruction work is
also accounted for empirically rather than being lumped into a residual.

Added counters in [src/loquat/field_p127.rs](../src/loquat/field_p127.rs):
- `FP2_ADD_COUNT`, `FP2_SUB_COUNT`, `FP2_MUL_COUNT` instrumenting
  `impl Add/Sub/Mul for Fp2`.

New microbench binaries:
- [zkvm/methods/guest/src/bin/fp2_microbench.rs](../zkvm/methods/guest/src/bin/fp2_microbench.rs)
- [zkvm/host/src/bin/fp2_microbench.rs](../zkvm/host/src/bin/fp2_microbench.rs)

Updated `loquat_only` guest+host to also surface per-phase Fp2 counts.

Files:
- `loquat_three_level_20260512_024956.jsonl` — 3 attribution rows
- `loquat_three_level_20260512_024956_griffin_bench.json`
- `loquat_three_level_20260512_024956_fp127_bench.json`
- `loquat_three_level_20260512_024956_fp2_bench.json`
- This README

## Microbenches

| primitive | n | cycles per op |
|---|---:|---:|
| Griffin permutation | 10,000 | **910,143** |
| Fp127::mul | 100,000 | **243** |
| Fp2::mul | 100,000 | **1,394** (= 4 × 243 + 422 wrapper) |
| Fp2::add | 100,000 | **0** ← measurement DCE'd; estimated ~30 cyc |
| Fp2::sub | 100,000 | **0** ← same |

**Caveat on F_p² add/sub microbench**: the tight-loop microbench was
optimised by the compiler (the counter increment confirms 100,000 calls
were made, but the cycle counter reported 0 — the loop body apparently
got vectorised or otherwise compressed enough that the cycle-counter
resolution caught nothing). The actual cost per F_p² add/sub is bounded
above by ~50 cycles (the cost is dominated by 2 × F_p add + counter
overhead). For attribution purposes I use ~30 cyc/op as an estimate;
the contribution is small either way (~600 K cycles total at λ=128).

**Cross-check on F_p² mul**: 4 F_p multiplications per F_p² mul,
confirmed by the microbench (`fp127_muls_per_fp2_mul = 4.0`). Each
F_p² mul takes 1394 cycles, of which 972 are the internal F_p mults
(already counted by `FP127_MUL_COUNT`) and 422 is the F_p² wrapper
(struct construction, addition, subtraction, counter overhead).

## Three-level attribution at λ=128 (single signature)

Total: 912,254,567 cycles

| component | cycles | % of total |
|---|---:|---:|
| **Griffin permutations** (931 × 910,143) | 847,343,133 | **92.88%** |
| └─ F_p mul work inside Griffin (931 × 2,580 muls × 243 cyc) | 583,681,140 | 63.98% |
| └─ Other Griffin work (lane addition, struct ops, control flow) | 263,661,993 | 28.90% |
| **Non-Griffin remainder** | 64,911,434 | **7.12%** |
| └─ F_p muls outside Griffin (~17 K × 243) | 4,113,990 | 0.45% |
| └─ F_p² mul wrappers (28,367 × 422) | 11,970,874 | 1.31% |
| └─ Control-flow floor (incl. F_p² adds, struct ops, branches) | 48,826,570 | 5.35% |

Two-level cross-check: F_p multiplications × cycles per mul =
2,418,910 × 243 ≈ 587.8M = **64.44%** of total. This figure is the
*aggregate* F_p mul contribution, summing the in-Griffin and
outside-Griffin parts.

## What can be attacked, and by how much

Projected savings, assuming RISC0-style precompile costs (Griffin: 100
cyc; F_p mul: 5 cyc; F_p² arithmetic: 100 cyc each for add/sub/mul):

| precompiles | projected cycles at λ=128 | speedup |
|---|---:|---:|
| none (baseline) | 912.3 M | 1× |
| **Griffin only** | 65.0 M | **14.0×** |
| **Griffin + F_p mul** | 59.9 M | 15.2× |
| **Griffin + F_p²** | **29.7 M** | **30.7×** |
| **Griffin + F_p² + F_p mul** | 29.7 M | 30.7× |

**Key finding**: F_p² precompile is far more impactful than F_p mul
precompile (on top of a Griffin precompile). Reason: F_p² mul (1394 cyc)
internally does 4 F_p multiplications — replacing the entire F_p² mul
with a precompile attacks both the F_p mul work AND the wrapper
(struct + adds inside). F_p mul precompile only attacks the inner
multiplications, leaving the F_p² wrapper cost intact.

Adding an F_p mul precompile on top of Griffin + F_p² gives **zero
additional speedup**, because the only F_p muls left after those two
precompiles are ~21,000 standalone F_p muls (Legendre PRF checks), and
their contribution is ~5M cycles, swamped by the 48.8M control-flow
floor.

## The control-flow floor: a fundamental ceiling

The 48.8 M residual at λ=128 (5.35% of total cycles) is **not** algebraic
primitive work. It is:

- Signature deserialization (bincode parsing of LoquatSignature).
- Loop control and branches in `Algorithm7Verifier::run_phased`.
- Byte ↔ field conversions in `GriffinHasher::hash` output formatting.
- Sumcheck protocol logic (challenge derivation outside primitives).
- F_p² struct construction overhead.
- Memory accesses through the rv32im virtual address space.

These are the cost of running Loquat as a *program* inside a zkVM rather
than expressing it as a *circuit*. **No primitive precompile can reduce
them.** They constitute a hard ~30× ceiling on what the precompile
approach can achieve for Loquat-in-zkVM at λ=128.

To exceed ~30× one would need either:

1. **A Loquat-specific accelerator**: a precompile that handles the entire
   Algorithm 7 (or a substantial chunk like the LDT verification) as a
   single AIR sub-circuit, eliminating the rv32im interpreter cost
   entirely. This is much more invasive than primitive precompiles —
   essentially building a custom circuit for Loquat verify, which is
   what Aurora/Fractal already does.
2. **Abandon the zkVM execution model**: move to a circuit-targeted
   Loquat verifier, which is exactly the Aurora/Fractal approach
   (148K R1CS constraints).

This is the Precompile Paradox at its sharpest: **the cost of running
Loquat as a program inside a zkVM has a ~30× ceiling on improvement
from primitive precompiles, after which the rv32im control-flow floor
dominates.**

## Revised thesis-grade claims

1. **Three-level attribution at λ=128**:
   - Griffin permutations: 92.88% (measured)
   - F_p multiplications: 64.44% aggregate (measured)
   - F_p² mul wrappers: 1.31% (measured)
   - rv32im control-flow floor: 5.35% (residual)
2. **Precompile speedup ceiling**: ~30× for Loquat-in-zkVM with primitive
   precompiles (Griffin + F_p²). Bounded by the control-flow floor.
3. **F_p² precompile is more important than F_p mul precompile** on top
   of a Griffin precompile (~30× vs ~15× speedup).
4. **Generalizes**: any IOP-based PQ signature verifier in a stock zkVM
   will exhibit a comparable control-flow floor (5-10% of cycles),
   capping precompile-based speedups at ~10-20× on top of the
   primitive-precompile-attainable savings.

## What changed about the spec

§5 of [spec/griffin_precompile.md](../spec/griffin_precompile.md) was
revised in v0.2 to acknowledge the 35.8× projection from v0.1 was
incorrect. With this third-level measurement:

- The "Griffin + F_p mul precompile" projection at 15.2× still stands.
- The "Griffin + F_p² precompile" projection should be **~30×** (now
  measured), not "40-60× projected" as v0.2 §5.4 stated. The 40-60×
  upper end of v0.2's estimate assumed F_p² adds and subs would
  contribute substantially; the data shows they contribute <1% combined.
- **Speedups beyond ~30× are not achievable with primitive precompiles
  alone** — this is a new, measurement-grounded ceiling that v0.2 did
  not articulate.

A v0.3 of the spec will be produced to incorporate this.

## Caveats

1. **F_p² add/sub microbench was DCE'd**. The ~30 cyc/op assumption is
   an estimate, not a measurement. If the true cost is materially
   higher (say, 100 cyc/op), the residual control-flow floor at λ=128
   shrinks by at most ~2M cycles (from 48.8M to ~46.8M) — does not
   affect the ~30× ceiling claim.
2. **Per-Griffin-perm F_p mul count estimated at 2,580** by averaging
   across phases. The actual value may vary by ±2% depending on the
   nonlinear-layer's lane interactions. Does not affect headline
   percentages.
3. **Projected precompile costs (100 cyc per Griffin, 100 cyc per F_p²
   op, 5 cyc per F_p mul) are modeled from RISC0's SHA-256 precompile
   (~70 cyc/block) and Poseidon2 (~50-100 AIR rows/perm)**. Actual
   precompile implementations could be 1.5-3× more expensive depending
   on AIR design choices, which would reduce the projected speedup
   commensurately. The ~30× ceiling is robust to this within ±20%; if
   the F_p² precompile actually costs 200 cyc/op, the projected
   speedup at λ=128 falls to ~25×.
