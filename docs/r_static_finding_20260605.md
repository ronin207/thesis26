# R_static measurement + finding (2026-06-05)

Measures the static-circuit **recompile cost** (the crossover denominator the defense
pivot named as the #1 missing number). Raw data: `docs/measurements/r_static_20260605/`.

**Seam labels that travel with every number here:** this is the **Loquat-BDEC circuit in
Aurora/libiop over Fp127**, achieved **107.5-bit** security, **zk=false** — it is **NOT
PLUM** (PLUM is a STIR scheme over a ~192/199-bit prime and does not run in this Fp127
Aurora harness; verified against the PLUM paper 2026-06-05). Because `emit_aurora_r1cs` has
no runtime-φ flag, this is **R_static as a function of circuit size + the two BDEC points**,
not a literal per-φ delta.

## Definition
R_static (per-recompile, BEFORE proving) = t_emit (R1CS construction) + t_load + t_param_setup.
The prover (t_P) is per-proof and reported separately. Tool: `scripts/fp127_aurora_runner.*`
(already instrumented to print the load+setup line before proving) + `emit_aurora_r1cs`.

## Data (M5 Pro 24 GB)
| circuit | constraints | R1CS load | param-setup | prove | verify | proof |
|---|---|---|---|---|---|---|
| synth 2^6 | 64 | 0.16 ms | 0.0020 ms | 26 ms | 16 ms | 114 KB |
| synth 2^8 | 256 | 0.30 ms | 0.0021 ms | 88 ms | 43 ms | 175 KB |
| synth 2^10 | 1,024 | 0.51 ms | 0.0021 ms | 0.35 s | 0.11 s | 257 KB |
| synth 2^12 | 4,096 | 1.9 ms | 0.0023 ms | 1.44 s | 0.37 s | 336 KB |
| synth 2^14 | 16,384 | 4.8 ms | 0.0025 ms | 6.2 s | 1.4 s | 433 KB |
| BDEC λ=80 | 524,288 | 84 ms | 0.0029 ms | 3.77 min | 41.7 s | 704 KB |
| BDEC λ=128 | 524,288 | 103 ms | 0.0034 ms | 3.75 min | 41.2 s | 704 KB |

R1CS **emit** (recompile front-end): ~0.2 s CPU (raw constraints 327,850 @ λ=80 / 454,198 @
λ=128, padded to 2^19 = 524,288). First-run wall of 13.76 s was cargo warmup; cached run 0.48 s.
All runs ACCEPT.

## Finding
- **R_static ≈ 0.3 s** for the full 524K-constraint BDEC circuit (emit ~0.2 s + load ~0.1 s +
  param-setup ~3 µs).
- **Param-setup is ~microseconds at every circuit size** — empirical confirmation that Aurora
  is **non-preprocessing**: there is no expensive per-circuit indexer to redo on a φ change.
- The minutes (3.77 min) are the **per-proof prover**, incurred on every presentation
  regardless of whether φ changed; the Aurora verifier is ~41 s (linear, as expected).

## Implication for the thesis (honest)
**The wall-clock agility crossover does NOT hold against Aurora.** The intended crossover
("the zkVM amortizes because the static path pays R_static per φ-change") has a denominator of
~0.3 s, so no number of predicate changes makes the zkVM win on recompile wall-clock. On the
per-proof axis the static path is also far ahead (3.77 min for the whole relation vs the
zkVM's 32.5 min for a single PLUM-verify and DNF for full BDEC) — heavy seam caveat: that
comparison crosses scheme/field/λ/ZK.

Re-grounding options, ranked:
1. Reframe rigidity as the **re-audit / engineering cost** of a new relation-specific circuit
   (the actual "rigidity crisis": Zcash Sapling→Orchard ~2-year rewrite, not a 0.3 s recompile).
   Wall-clock does not capture this; say so explicitly.
2. Compare against a **preprocessing SNARK** (Groth16 / Marlin / circuit-specific Plonk) where
   per-circuit keygen is genuinely expensive and R_static is large. Aurora was the wrong
   baseline for a wall-clock flexibility argument.
3. Keep flexibility **qualitative** (zkVM N_circ = N_audit = 0 per φ; static ≥ 1), with the
   measured caveat that the per-change wall-clock is small for a transparent SNARK.

This is Sako's "is the setting persuasive?" applied to the crossover: for wall-clock vs Aurora,
no. The finding refines the flexibility contribution rather than supporting the naive version.

## 2026-06-06 addendum — Fractal (preprocessing) endpoint: the both-sides result
Verified against `docs/measurements/r_static_20260605/fractal_run_*.{json,log}`. Same harness,
same Loquat-BDEC Fp127 R1CS, 107.3-bit, zk=false (NOT PLUM — same seam as the Aurora number).
Runner: `scripts/fp127_fractal_runner.{cpp,sh}` (copy of the Aurora runner; only main()'s
prover/verifier section changed). R_static = the standalone `fractal_snark_indexer` wall-clock.

| circuit | constraints | Aurora R_static (param-setup) | Fractal R_static (indexer) |
|---|---|---|---|
| synth 2^10 | 1,024 | 0.0021 ms | 0.863 s (ACCEPT) |
| synth 2^12 | 4,096 | 0.0023 ms | 3.74 s (ACCEPT) |
| synth 2^14 | 16,384 | 0.0025 ms | 18.5 s (ACCEPT) |
| BDEC 2^19 (λ=80) | 524,288 | 0.0029 ms | OOM-killed ~33 min (mid-indexer, 2^27 FFT) |
| BDEC 2^19 (λ=128) | 524,288 | 0.0034 ms | OOM-killed ~33 min |

**Finding: R_static is conditional on the static baseline's preprocessing model.**
- Non-preprocessing (Aurora): R_static ≈ microseconds, flat in size → the zkVM has NO
  wall-clock flexibility advantage.
- Preprocessing (Fractal): R_static grows superlinearly (~5× per 4× constraints) and is
  INFEASIBLE at the BDEC circuit size on 24 GB (deterministic OOM at ~33 min, during a
  2^27-element codeword-domain FFT) → the zkVM has a LARGE, here-decisive flexibility
  advantage (its per-φ-change recompile is a guest rebuild, seconds, with no per-circuit indexer).

**Honest flexibility claim, now MEASURED on both sides:** the zkVM's wall-clock flexibility
advantage is conditional on the static baseline's preprocessing model — negligible against a
non-preprocessing transparent argument (Aurora), and large (indeed, at this circuit size, the
static baseline's per-circuit indexing is itself infeasible on the target hardware) against a
preprocessing one (Fractal). This is the non-curated both-sides result Sako's "which axis?"
question demanded.

Caveats: (1) the BDEC OOM is at `RS_extra_dimensions=5` (mirroring the Aurora-matched baseline);
a lower RS might let the indexer fit and yield a finite (still large) R_static — a one-knob
follow-up, but it moves off the Aurora-matched parameters. (2) Loquat/Fp127 proxy, NOT PLUM.
(3) zk=false.

## Companions
`docs/measurements/r_static_20260605/SUMMARY.txt` + `fractal_run_*` (raw),
`docs/thesis_defense_pivot_plan_20260605.md`, `docs/thesis_landscape_realignment_20260605.md`.
