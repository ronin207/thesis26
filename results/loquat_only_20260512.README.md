# Loquat-only zkVM phase decomposition — 2026-05-12

## Setup

One `loquat_verify` (Algorithm 7) executed inside RISC Zero zkVM, dev mode,
on Apple M5 Pro. No BDEC scaffolding (no Merkle tree, no credential, no
pseudonym, no policy). Pipeline:

```
loquat_setup(λ) → keygen_with_params → loquat_sign(msg) → guest::loquat_verify_phased(...)
```

Guest snapshots `risc0_zkvm::guest::env::cycle_count()` at the start of each
Algorithm-7 sub-phase. The per-phase delta is the cost of that phase in
rv32im cycles when the host writes the witness + when the prover would have
to commit a STARK trace covering those cycles (we only run dev mode here,
so we measure execution, not proving wall-clock — but trace_cycles is a
real, hardware-independent measurement of the workload).

Files:
- `loquat_only_20260512.jsonl` — three JSON lines, one per security level.
- `loquat_only_20260512.README.md` — this file.

Implementation:
- Host: [zkvm/host/src/bin/loquat_only.rs](../zkvm/host/src/bin/loquat_only.rs)
- Guest: [zkvm/methods/guest/src/bin/loquat_only.rs](../zkvm/methods/guest/src/bin/loquat_only.rs)
- Phased verifier API: `vc_pqc::loquat::loquat_verify_phased<H: FnMut(&str)>(...)`
  added to [src/loquat/verify.rs](../src/loquat/verify.rs).

## Result table

| phase | λ=80 cycles | λ=80 % | λ=100 cycles | λ=100 % | λ=128 cycles | λ=128 % |
|---|---:|---:|---:|---:|---:|---:|
| message_commitment    |   4,460,896 |  0.7% |   4,460,896 |  0.5% |   4,460,896 |  0.5% |
| absorb_sigma1         |  53,559,259 |  7.8% |  67,854,261 |  8.1% |  67,875,418 |  7.6% |
| absorb_sigma2         |  53,530,903 |  7.8% |  67,873,265 |  8.1% |  67,820,633 |  7.6% |
| legendre_constraints  |   4,480,894 |  0.7% |   5,966,874 |  0.7% |   5,977,452 |  0.7% |
| sumcheck              |  39,314,983 |  5.7% |  39,292,798 |  4.7% |  39,315,630 |  4.4% |
| absorb_sigma3_sigma4  |  21,424,863 |  3.1% |  21,430,409 |  2.5% |  21,443,309 |  2.4% |
| **ldt_openings**      | **507,125,688** | **73.9%** | **632,303,550** | **75.2%** | **686,478,392** | **76.7%** |
| done_to_exit          |         150 |  0.0% |         150 |  0.0% |         150 |  0.0% |
| **TOTAL**             | **685,859,574** | | **841,144,141** | | **895,333,818** | |

## Headline finding

**LDT/FRI openings dominate Loquat verification inside the zkVM at every
security level we tested (74% → 75% → 77% as λ grows).** The Legendre PRF
constraint check — the part that gives Loquat its name and which the prior
literature (and our own earlier framing) suggested was the bottleneck — is
**0.7%** at every security level. The story is not "Legendre is expensive."
The story is "the FRI opening path (Merkle authentication + Griffin re-hash
+ field-mul reconstruction) is expensive, because every Merkle path opening
and every FRI query re-hashes through Griffin over F_p^127², which has no
zkVM precompile."

## Scaling behaviour

- `message_commitment` is **constant** at 4.46M cycles (single Griffin hash
  over the fixed-size message). Security-level independent.
- `legendre_constraints` is **constant in % terms** at 0.7% — its
  cycle-count tracks linearly with the number of Legendre checks
  (`params.m * params.n`), but other phases grow proportionally.
- `absorb_sigma1`/`absorb_sigma2` grow 53.5M → 67.8M as λ goes 80 → 128
  (more challenge expansion via Griffin).
- `sumcheck` is **essentially constant** at ~39M cycles — Loquat's sumcheck
  is over a fixed-size coset.
- `ldt_openings` grows linearly with λ: **507M → 632M → 686M**. This is
  where the security parameter cost lives.

## Implication for precompile design

A zkVM precompile for Loquat should target what dominates the cycles:

1. **Griffin permutation over F_p^127²** — used in every transcript absorb,
   every Merkle node hash, every FRI commitment. The σ₁/σ₂ phases alone are
   16% of cycles; the LDT phase is another 74% and is *also* Griffin-bound.
   A Griffin precompile that runs at native speed (no rv32im emulation)
   would attack ~90% of total cycles.
2. **F_p^127² extension-field arithmetic** — the underlying primitive that
   Griffin needs. Required regardless of whether Griffin itself is a
   precompile (the LDT polynomial reconstruction also does extension-field
   multiplications).
3. **Merkle path verification with Griffin nodes** — secondary, because if
   Griffin is precompiled the rest of Merkle verification is just
   pointer-walking and small comparisons.

A precompile for **Legendre symbol over F_p** would save 0.7% of cycles.
Almost nothing.

## What this measurement is and isn't

**Is**: a faithful trace-cycle decomposition of Algorithm 7 (Loquat verify)
when executed inside a general-purpose zkVM with no precompiles for any of
Loquat's primitives. The cycle counts are hardware-independent: they
represent the number of rv32im instructions RISC0 would have to STARK over,
regardless of how fast the host happens to be.

**Isn't**: a measurement of real STARK-proving wall-clock. Dev mode skips
proof generation; `prove_wallclock_ms` in the JSON is execution-only. If
you want real proving time per cycle for M5 Pro Metal, you'd need a
calibration anchor run (cycles → real prove ms ratio) — see the abandoned
`results/anchor_20260511_030057/` for the failed attempt at that.

**Isn't**: a measurement of the cost of running Loquat *outside* the zkVM.
That's host-CPU wall-clock for Loquat verify, which is microseconds — see
`sign_ms` in the JSON, which is about 16 ms total for sign+verify on host.

## Provenance

- Built from commit at `/Users/takumiotsuka/.../research/thesis/`.
- Phased verifier added in `src/loquat/verify.rs::loquat_verify_phased`.
- Re-exported via `src/loquat/mod.rs::loquat_verify_phased`.
- Guest binary: `zkvm/methods/guest/src/bin/loquat_only.rs`.
- Host binary: `zkvm/host/src/bin/loquat_only.rs`.
- Run command: `cargo run --release --bin loquat_only -- --security-level <L> --message "loquat-only-anchor"`.
- Each cell: ~4-5 seconds wall-clock on M5 Pro in dev mode.
