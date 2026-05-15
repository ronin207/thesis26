# Loquat-only multi-signature zkVM sweep — 2026-05-12

## Setup

21-cell sweep of `n × loquat_verify` inside RISC Zero zkVM (dev mode) on
Apple M5 Pro. Goal: validate scaling and phase-decomposition stability
across the parameter regime the Loquat paper benchmarks (n up to 64,
λ ∈ {80, 100, 128}).

Pipeline per cell:
```
loquat_setup(λ)
  → keygen_with_params × n     (n distinct keypairs)
  → loquat_sign(msg_i) × n     (n distinct messages "loquat-only-XXXXXXXX")
  → guest: for each item, loquat_verify_phased
           cycle snapshots per Algorithm-7 phase
           per-phase totals summed across all n verifies
```

Hardware: Apple M5 Pro, 24 GB unified memory. Dev mode → cycle counts only,
no real STARK proving.

Files:
- `loquat_only_multi_20260512_003912.jsonl` — 21 JSON lines, one per cell
- `loquat_only_multi_20260512_003912.csv` — flattened with per-phase columns
- `loquat_only_multi_20260512_003912.log` — per-cell timestamps
- This README

Code:
- Guest: [zkvm/methods/guest/src/bin/loquat_only.rs](../zkvm/methods/guest/src/bin/loquat_only.rs)
- Host: [zkvm/host/src/bin/loquat_only.rs](../zkvm/host/src/bin/loquat_only.rs)
- Phased verifier: `vc_pqc::loquat::loquat_verify_phased`
- Analysis script: [scripts/loquat_only_analyse.py](../scripts/loquat_only_analyse.py)

## Results: total cycles

| λ \ n | 1 | 2 | 4 | 8 | 16 | 32 | 64 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 80 | 686M | 1.37B | 2.74B | 5.48B | 10.97B | 21.94B | **43.88B** |
| 100 | 841M | 1.68B | 3.36B | 6.73B | 13.45B | 26.90B | **53.81B** |
| 128 | 895M | 1.79B | 3.58B | 7.16B | 14.32B | 28.64B | **57.27B** |

## Linearity check

Per-signature cost (`total_cycles / n`) is essentially constant within each λ:

| λ | min cyc/sig | max cyc/sig | spread |
|---:|---:|---:|---:|
| 80 | 685,456,069 | 686,010,322 | **0.08%** |
| 100 | 840,722,459 | 840,889,231 | **0.02%** |
| 128 | 894,837,820 | 895,145,289 | **0.03%** |

The fit `total_cycles(n) = n × c(λ)` holds to better than one-tenth of a
percent across n=1..64. There is **no amortization across independent
`loquat_verify` calls** in a stock RISC0 guest.

## Phase decomposition is invariant to n

At n=32:

| Phase | λ=80 % | λ=100 % | λ=128 % |
|---|---:|---:|---:|
| message_commitment    | 0.65% | 0.53% | 0.50% |
| absorb_sigma1         | 7.81% | 8.07% | 7.58% |
| absorb_sigma2         | 7.81% | 8.07% | 7.58% |
| legendre_constraints  | 0.65% | 0.71% | 0.67% |
| sumcheck              | 5.73% | 4.67% | 4.39% |
| absorb_sigma3_sigma4  | 3.13% | 2.55% | 2.39% |
| **ldt_openings**      | **73.95%** | **75.18%** | **76.68%** |

Compared to the single-sig run from 2026-05-12 morning (`results/loquat_only_20260512.jsonl`),
the percentages are identical to within a fraction of a percent. **The
precompile-paradox phase profile is invariant to the number of signatures
aggregated.**

## Comparison to the Loquat paper (Zhang et al. 2024/868, Table 2)

The paper's headline aggregation benchmark (n=64 LOQUAT-128 in Aurora,
i7-12700KF, 28 GB):

| metric | Loquat paper (Aurora) | Loquat paper (Fractal) | This run (RISC0 zkVM) |
|---|---:|---:|---:|
| max # sigs in 28 GB | 64 | 16 | 64+ (no R1CS budget; cycle-bound only) |
| aggregate prove | 553 s | 556 s | 57.27 B rv32im cycles (no real prove time here) |
| aggregate size | 207 KB | **145 KB (constant)** | TBD (need real-mode anchor) |
| verify time | 62 s | 0.78 s | ~ms (standard STARK verify) |

The 57.27 B cycle count at λ=128, n=64 represents the **trace size the
RISC0 STARK prover would have to commit to** for the same aggregate
workload. Whether this translates to a faster, slower, or comparable real
prove time vs Aurora's 553 s requires the wall-clock calibration anchor
(see `results/anchor_*` for prior abandoned attempts).

## R1CS-to-rv32im expansion factor

Loquat paper Table 1: LOQUAT-128 R1CS verification = **148,825 constraints**.
This run, λ=128: **895,145,289 rv32im cycles** per verify.

Expansion factor = 895M / 148K ≈ **6,015×**.

This is the Precompile Paradox quantified at the canonical metric: the
R1CS-friendly arithmetization that Loquat was designed for compiles into
~6000× more rv32im trace cycles when run inside a general-purpose zkVM
without Griffin precompiles. That ratio is what a Griffin/F_p^127²
precompile would substantially shrink.

## What this measurement is and isn't

**Is**: a hardware-independent, deterministic measurement of the rv32im
trace size produced by Algorithm 7 (Loquat verify) inside RISC0, swept
across n and λ, with phase-level decomposition. Validates that the
precompile-paradox profile from the n=1 case is invariant to n. Provides
the apples-to-apples cycle-count comparison to the Loquat paper's
aggregate-signature regime.

**Isn't**: a real-mode STARK proving wall-clock. Dev mode skips proof
generation; `prove_wallclock_ms` in the JSON is execution time only.

**Isn't**: an aggregation-aware verifier — we loop independent
`loquat_verify` calls. The paper's Aurora-Fractal aggregation builds the
aggregate proof at the SNARK level (one circuit over n sigs); we do the
same semantically (one zkVM proof over n sigs in a loop), but with no
shared-witness amortization. **This itself is a thesis-relevant finding**:
stock zkVMs offer no aggregation primitive equivalent to Fractal's
recursive composition, so aggregation in zkVM is strictly linear.

## Provenance

- Run script: `for sec in 80 100 128; do for n in 1 2 4 8 16 32 64; do cargo run --release --bin loquat_only --quiet -- --security-level $sec --n $n; done; done`
- Started 00:39:12 JST, finished 01:32:20 JST (~53 minutes wall-clock,
  dominated by ~60s cargo re-link per cell — not the actual execution).
- Total dev-mode execution time across all 21 cells ≈ 30 minutes.
- 100% of verifies accepted (`n_accepted == n_sigs` for every cell).
