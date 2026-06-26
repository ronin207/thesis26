# BDEC ShowCre (PLUM-Griffin) — execute-mode measurement, RISC0

- Date: 2026-06-02. Hardware: Apple M5 Pro, 24 GB. Security: λ=80.
- Guest: `bdec_showcre_plum_griffin` (new) — the `k+2` PLUM verifications of the
  ShowCre relation `R_show` under a witness-only `pk_U`: `k` pseudonym-ownership
  checks, one verifier-facing pseudonym check, one shown-credential check.
- Host: `bdec_showcre_plum_host` (new), `BDEC_SHOWCRE_K` selects `k`.
- Mode: execute (RISC-V cycle count, machine-independent, always terminates).

## Results

| Stage | #verify | total cycles | per-verify | exec wall |
|---|---|---|---|---|
| CreGen (`bdec_credgen_plum_griffin`) | 2     | 9.40e9  | 4.70e9 | ~65 s  |
| ShowCre k=1 (φ₁)                      | 3     | 1.41e10 | 4.69e9 | ~101 s |
| ShowCre k=2 (φ₂)                      | 4     | 1.88e10 | 4.69e9 | ~137 s |
| ShowCre k=14 (stress)                 | 16    | DNF     | —      | guest-OOM |

k=1/k=2 `all_ok=true`. Per-verification cost is constant at ≈4.69e9 cycles, so
ShowCre total = `(k+2)·4.69e9`. Griffin permutations: k=1 → 3156, k=2 → 4208
(≈1052 per verification).

**k=14 finding (guest-allocator wall):** the host signs+verifies all 16/16, but
the in-guest execute exhausts RISC0's default non-reclaiming bump allocator across
the 16 accumulated verifications (`Out of memory! ... Enable heap-embedded-alloc
to reclaim`). This is an in-guest heap limit, distinct from the prover-side memory
frontier. The reclaiming allocator (`heap-embedded-alloc`) clears it at extra
cycle cost; the projected 7.5e10 rests on the measured per-verification constant,
not on a completed k=14 run.

## Cost-model validation (upgrades §6 from extrapolation to measurement)

- §6 `eq:cost-showcre` extrapolation k=2 → 1.9e10. **Measured: 1.88e10.** ✓
- k=1 → 1.41e10 = (1+2)·4.69e9. ✓
- The k=14 projection (16·4.69e9 = 7.5e10) rests on the same measured
  per-verification constant, now empirically supported at k=1,2.

## What is proved (and what is not)

The guest commits ONLY `(all_ok, per-stage outcomes, counters)` to the journal.
`pk_U` and every signature are private witnesses, never committed. So the proof
attests the `k+2` signature-verification relation `R_show` — ownership of valid
credentials and pseudonyms under a hidden `pk_U`, i.e. anonymity/unlinkability —
NOT the presentation predicate φ, which the relying party checks verifier-side on
the disclosed attributes (base BDEC, ProSec 2024 p.12–13). A zero-knowledge wrap
of the receipt proves this same relation in zero knowledge; it does not add φ.

## Frontier (prove / ZK-wrap)

- CreGen prove (composite) reached 2452/9936 segments in 34.7 h before being
  terminated (~4.6-day projection); succinct hit an internal-verifier rejection.
  ShowCre prove is larger (k+2 vs 2 verifications).
- ZK wrap (Groth16/PLONK) documented to OOM at ~20–24 GB; RISC0 Groth16
  additionally needs an x86/Docker prover. Attempt-and-document is the next step.

## Host-side note

PLUM-Griffin signing is ≈30 s/signature on host; `k+2` signatures dominate host
setup (k=2: sign_ms≈117 s) but are outside the measured in-zkVM cost.
