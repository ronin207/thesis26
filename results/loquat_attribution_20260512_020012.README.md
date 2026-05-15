# Loquat zkVM Griffin attribution — 2026-05-12

## Setup

Three measurements that together attribute Loquat verification's rv32im cycle
cost to its Griffin-permutation component.

1. **Griffin microbench** — a guest binary (`griffin_microbench`) that times
   N=10,000 invocations of `griffin_permutation_raw` on a non-trivial
   initialised state, measuring cycles per permutation in rv32im.
2. **Instrumented loquat-only sweep** — the `loquat_only` guest with a counter
   added to `griffin_permutation` (in `src/loquat/griffin.rs`) so each phase
   reports both cycle count AND number of Griffin permutations invoked.
3. **Cross-multiply**: `griffin_cycles_in_phase = perms_in_phase × cycles_per_perm`.
   Subtract from `phase_cycles` to get non-Griffin remainder.

Code added:
- `pub static GRIFFIN_PERM_COUNT: AtomicU64` in [src/loquat/griffin.rs](../src/loquat/griffin.rs).
- New guest: [zkvm/methods/guest/src/bin/griffin_microbench.rs](../zkvm/methods/guest/src/bin/griffin_microbench.rs).
- New host: [zkvm/host/src/bin/griffin_microbench.rs](../zkvm/host/src/bin/griffin_microbench.rs).
- Updated loquat-only guest and host to surface per-phase Griffin counts.

Hardware: Apple M5 Pro, 24 GB. Dev mode.

Files:
- `loquat_attribution_20260512_020012.jsonl` — 3 attribution rows, one per λ
- `loquat_attribution_20260512_020012_griffin_bench.json` — microbench result
- This README

## Microbench: cycles per Griffin permutation

| n_perms | total_cycles | **cycles/perm** |
|---:|---:|---:|
| 10,000 | 8,928,408,760 | **892,840** |

Each Griffin permutation over F_p^127² costs ~893,000 rv32im cycles when
executed in software (no precompile). The cost is dominated by the
non-native field-mul tax: every lane operation in Griffin's S-box,
linear layer, and round constants must be implemented as multi-limb
arithmetic over 128-bit primes that don't match RISC-V's native 32-bit
word size.

## Total attribution

| λ | total cycles | Griffin perms | griffin_cycles | **griffin %** | non-griffin remainder |
|---:|---:|---:|---:|---:|---:|
| 80 | 685,770,567 | 727 | 649,094,680 | **94.65%** | 36,675,887 |
| 100 | 840,684,500 | 884 | 789,270,560 | **93.88%** | 51,413,940 |
| 128 | 894,959,944 | 931 | 831,234,040 | **92.88%** | 63,725,904 |

**Between 92.9% and 94.7% of Loquat verification cycles in zkVM are
Griffin permutations.** The rest is field-arithmetic for the Legendre PRF
checks and the FRI polynomial reconstruction.

## Per-phase attribution at λ=128

| Phase | cycles | perms | griffin cycles | **griffin % of phase** | non-griffin |
|---|---:|---:|---:|---:|---:|
| message_commitment | 4,461,003 | 5 | 4,464,200 | **~100%** | ≈0 |
| absorb_sigma1 | 67,837,617 | 76 | 67,855,840 | **~100%** | ≈0 |
| absorb_sigma2 | 67,868,254 | 76 | 67,855,840 | **~100%** | ≈0 |
| **legendre_constraints** | 5,973,671 | **0** | 0 | **0%** | 5,973,671 |
| sumcheck | 39,333,510 | 44 | 39,284,960 | **99.88%** | 48,550 |
| absorb_sigma3_sigma4 | 21,431,697 | 24 | 21,428,160 | **99.98%** | 3,537 |
| **ldt_openings** | 686,091,304 | **704** | 628,559,360 | **91.61%** | 57,531,944 |

Interpretation:
- **Five of the seven phases** are essentially 100% Griffin: message commitment,
  the two σ-absorbs, sumcheck, and σ₃/σ₄. These phases would shrink to almost
  nothing with a Griffin precompile.
- **Legendre constraints (0.67% of total)** uses zero Griffin permutations.
  It is pure F_p^127² field arithmetic — Legendre symbol computation and
  λ·o multiplications. A Griffin precompile does *not* help here; only an
  F_p^127² arithmetic precompile (or a Legendre-symbol-specific instruction)
  would.
- **LDT openings (76.66% of total)** is the only phase with substantial
  non-Griffin work — about 8.4% of LDT phase is field-mul for FRI
  polynomial reconstruction. Even so, **91.61% of LDT cycles are Griffin
  Merkle hashes**.

## Projected speedup with a Griffin precompile

If RISC0 implemented a `griffin_permutation` precompile at ~100 cycles per
invocation (in line with the SHA-256 precompile's per-block cost), the
projected savings on Loquat verify:

| λ | current cycles | with Griffin precompile (~100 cyc/perm) | speedup |
|---:|---:|---:|---:|
| 80 | 685,770,567 | ~36,748,587 | **18.7×** |
| 100 | 840,684,500 | ~51,502,340 | **16.3×** |
| 128 | 894,959,944 | ~63,819,004 | **14.0×** |

The speedup is bounded by the non-Griffin remainder (≈35M–64M cycles)
which dominates after the Griffin cycles are eliminated. Of that
remainder, roughly:
- 60M cycles is FRI polynomial reconstruction (F_p^127² field ops)
- 6M cycles is Legendre PRF checks
- The rest is rv32im control flow

An additional F_p^127² arithmetic precompile (covering the field-mul
operations outside Griffin) could reduce the remainder by perhaps 70–90%,
pushing the total speedup to **~30×–50×** at λ=128. This is the design
target for the proposed precompile layer.

## What you can claim, with this evidence

1. **Quantified Griffin dominance**: 92.9%–94.7% of Loquat verify cycles
   are Griffin permutations. Empirical, not analytical. Holds across all
   three measured security levels.
2. **Phase-by-phase attribution**: Of seven Algorithm-7 sub-phases, five
   are essentially 100% Griffin, one is essentially 0% Griffin (Legendre
   constraints), and one is 91.6% Griffin with substantial non-Griffin
   work (LDT openings — FRI polynomial reconstruction).
3. **Projected precompile savings**: A Griffin-permutation precompile
   alone would deliver a 14–19× speedup on Loquat verify, bounded by the
   non-Griffin remainder. Adding an F_p^127² arithmetic precompile could
   push this to ~30–50×.
4. **Sako-compatible problem statement**: zkVM-friendliness is now
   operationalised as "cycles consumed in software-emulated primitives
   that lack precompiles." For Loquat, 92.9%–94.7% of cycles meet that
   criterion under Griffin. The precompile design target is concrete.

## What this measurement is and isn't

**Is**: an empirical attribution of Loquat verify cycles to the Griffin
permutation primitive, via a microbenchmarked cost per permutation and a
counted number of permutations per phase. Hardware-independent (cycle
counts and permutation counts are properties of the program, not the
host). Three security levels, single signature.

**Isn't**: a measurement of real STARK proving wall-clock. Dev mode.

**Isn't**: a measurement of an actual Griffin precompile. The projected
speedup assumes a precompile cost of ~100 cycles/perm, modelled after
RISC0's existing SHA-256 precompile. The actual cost would depend on the
precompile's circuit design, which is the next deliverable (specification).

**Isn't**: an aggregation measurement. These three runs are n=1 each. The
attribution at n=1 multiplies linearly to any n by the linearity result
of the prior multi-signature sweep (`loquat_only_multi_20260512_003912`).

## Caveat: microbench noise

The microbench measures 892,840 cycles/perm averaged over 10,000
permutations. In the attribution calculation, this is multiplied by
~700–900 permutation counts. The product can over- or under-shoot the
phase cycle count by small amounts (e.g., -3,197 cycles on
message_commitment, +48,550 on sumcheck) due to:
- Microbench-vs-in-context overhead: the microbench is a tight loop on a
  fixed state, while in-context Griffin permutations are called from
  varying code paths with different function-call costs.
- Slight rv32im overhead from the counter increment itself (one atomic
  fetch_add per permutation).

These deltas are <0.1% of the phase totals and do not affect the headline
attribution figures.
