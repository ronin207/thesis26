# PLUM implementation plan (measurement-grade)

*Started 2026-05-13. Working document.*

## Goal

Implement PLUM (Zhang, Fu, Steinfeld, Liu, Yuen, Au — ProvSec 2025) inside
`vc-pqc` to the point where we can run the same three-level attribution
measurement we ran on Loquat. The deliverable is a second data point for
the "field-mismatch + algebraic-hash dominance" thesis claim.

**Quality bar**: correct enough to verify a real PLUM signature and produce
trustworthy cycle counts in RISC0 dev-mode. NOT production / deployment
ready.

## Headline facts (from the paper)

| | Loquat-128 | PLUM-128 |
|---|---|---|
| Field | $2^{127}-1$ (Mersenne, 127-bit) | $2^{64} \cdot p_0 + 1$ (199-bit) |
| Field extension | $\mathbb{F}_{p^2}$ for soundness | None (prime chosen to avoid) |
| PRF | Legendre (t=2) | t-th power residue, **t=256** |
| LDT | FRI (4 rounds) | **STIR** (1 round at λ=128) |
| Sumcheck | Univariate over $\mathbb{F}_{p^2}$ | Univariate over $\mathbb{F}_p$ |
| Hash | Griffin (state 4 / capacity 2) | Same shape, re-instantiated for $\mathbb{F}_p$ 199-bit |
| Signature size | 57 KB | 37 KB (1.5× smaller) |
| R1CS verify | 148K | 116K (1.28× smaller) |
| Est. verify (Griffin) | 0.21 s | 2.75 s |

The prime explicitly:
$p = 2^{64} \cdot 25955366385296571073907086806836816173771 + 1$
- bit length **199** (paper's "192-bit" is loose)
- limbs (LE u64): `[0x1, 0x987f6782d66cdacb, 0x46a5bbe0c4e96289, 0x4c]`
- 2-adicity 64 (smooth subgroup of size $2^{64}$)
- $t = 256$ divides $p-1$; the t-th power residue PRF needs exponent $(p-1)/256$

Key parameter values at λ=128: $t=256$, $m=4$, $n=7$, $B=28$, $L=2^{12}$,
$\beta=0.961$, $\eta=4$, $d^*=128$, $d_{\mathsf{stop}}=32$, $R=1$ STIR round,
$\kappa_0=26$.

## Architecture decision

PLUM is **a sibling scheme** to Loquat under `src/plum/`, NOT an extension
of `src/loquat/`. Reasons:

1. Different field — `Fp127` and `Fp192` cannot share a type alias.
2. Different LDT — STIR is a different protocol from FRI.
3. Different PRF — t-th power residue is more general than Legendre.
4. Loquat code in the worktree is on a clean branch; the prior
   instrumentation (`GRIFFIN_PERM_COUNT` etc.) lives in the parent repo's
   `feature/succinct-proof-measurement` branch as uncommitted changes.
   Adding to either is risky. PLUM as a parallel scheme avoids the
   integration issue entirely.

Layout:

```
src/plum/
├── mod.rs              # re-exports
├── field_p192.rs       # Fp192 arithmetic + FP192_MUL_COUNT counter
├── field_utils.rs      # type aliases (F = Fp192, no F2)
├── prf.rs              # t-th power residue PRF
├── griffin.rs          # Griffin re-instantiated for Fp192
├── hasher.rs           # PlumHasher trait (Griffin or SHA3)
├── merkle.rs           # Merkle commitment (parameterised over hasher)
├── transcript.rs       # Fiat–Shamir transcript
├── stir.rs             # STIR low-degree test
├── sumcheck.rs         # Univariate sumcheck over Fp (no extension)
├── setup.rs            # PlumPublicParams + setup()
├── keygen.rs           # Key generation
├── sign.rs             # Sign (Algorithms 3-5 in the paper, 6 phases)
├── verify.rs           # Verify (Algorithm 6) + plum_verify_phased
└── tests.rs
```

## Phased plan

### Phase 1 — Field (this session)

- 1a. `src/plum/field_p192.rs`: Fp192 type with add, sub, neg, mul,
  pow, inverse, equality, zero/one, debug, serde.
- 1b. `FP192_MUL_COUNT` static counter from day 1 (parallels Loquat's
  `FP127_MUL_COUNT`).
- 1c. Tests vs `num_bigint::BigUint` oracle for 1000s of random
  inputs.
- 1d. `src/plum/field_utils.rs`: type alias `F = Fp192`, helpers.

**Note on internal representation**: for speed of authoring, this
phase uses `num_bigint::BigUint` internally. Phase 1.5 (separate)
will rewrite the hot path with explicit 4×u64 limb arithmetic +
Barrett reduction so that zkVM cycle measurements reflect realistic
multi-limb cost rather than BigUint overhead. Sequencing this lets
us validate correctness with simple code before tuning.

### Phase 1.5 — Limb-native arithmetic (~2 days)

Replace `BigUint` internals with 4-limb schoolbook + Barrett reduction.
This is the phase whose output the zkVM measurement actually reflects.

### Phase 2 — PRF + t-th power residue (~3 days)

- `src/plum/prf.rs`: `t_power_residue_prf(K, a) -> Z_t` using exponent
  $(p-1)/t$ and a precomputed discrete-log table for the 256-th roots
  of unity (small lookup, since t=256).
- Tests: PRF is multiplicatively homomorphic ($\mathcal{L}^t_0(ab) =
  \mathcal{L}^t_0(a) + \mathcal{L}^t_0(b) \bmod t$ for nonzero $a, b$).
- Section 3.1 of PLUM (Def 1).

### Phase 3 — Griffin over Fp192 (~3 days)

- `src/plum/griffin.rs`: Griffin permutation parameterised over the new
  field. Same shape: state 4 compression / state 3 expansion, capacity 2.
- Re-derive round constants from SHAKE256 seed for the new prime.
- Add `PLUM_GRIFFIN_PERM_COUNT` counter from day 1.
- Microbench: cycles per Griffin permutation. Expected ~2-3× Loquat's
  910K cyc/perm because the field is bigger (199-bit vs 127-bit) — this
  matters for the thesis claim.

### Phase 4 — Merkle + transcript + hasher trait (~2 days)

- Mostly structural; reuse patterns from `src/loquat/`. Generalise the
  hasher into a trait so we can swap Griffin / SHA3 to study sensitivity.

### Phase 5 — STIR low-degree test (~5-7 days)

- **The hardest part**. Re-read Arnon-Chiesa-Fenzi-Yogev 2024 "STIR".
- For PLUM-128: $R = \log_4(128/32) = 1$ round. Massively simpler than
  full STIR — a single fold + final-polynomial degree check.
- Implementation: rate correction polynomial $\hat{p}(x)$, STIR folding,
  Merkle commitment per round, final polynomial check.

### Phase 6 — Univariate sumcheck over Fp (~2 days)

- Like Loquat's, but no extension field. Simpler. Reuse FFT scaffolding
  pattern but for Fp192's smooth subgroup.

### Phase 7 — Setup + KeyGen (~1 day)

- Algorithm 1 (setup) and Algorithm 2 (keygen) from the paper.
- 2-adicity of p is 64, so the smooth subgroup is plenty large for our
  parameter choices ($|H| = 2m = 8$, $|U| = 2^{12}$).

### Phase 8 — Sign (Algorithms 3-5) (~5 days)

- 6 phases per the paper:
  1. Commit to secret key and randomness
  2. Compute residuosity symbols
  3. Compute witness for univariate sumcheck (+ ZK)
  4. Univariate sumcheck
  5. Rate correction for STIR
  6. STIR folding rounds

### Phase 9 — Verify (Algorithm 6) (~3 days)

- Equivalent of `Algorithm7Verifier` in Loquat.
- Provide `plum_verify_phased<H: FnMut(&'static str)>(...)` with the
  same instrumentation hook contract as Loquat.

### Phase 10 — ZKVM guest + host (~2 days)

- Mirror `zkvm/methods/guest/src/bin/loquat_only.rs` for PLUM.
- Counters: `PLUM_GRIFFIN_PERM_COUNT`, `FP192_MUL_COUNT`.

### Phase 11 — Three-level attribution measurement (~1 day)

- Run microbenches: Griffin-over-Fp192, Fp192::mul.
- Run PLUM verify in dev mode at λ ∈ {80, 100, 128}.
- Compute three-level decomposition (Griffin / Fp192 mul / control-flow
  floor), compare with Loquat.

## Total effort estimate

**3-5 weeks** of focused engineering. Phase 5 (STIR) is the largest
single risk and could push longer.

## What "comparing to Loquat" gives us

The thesis claim is *"field-mismatch overhead dominates zkVM cycle cost
for algebraic-IOP-based PQ signatures."* Loquat gives one data point at
127-bit (Mersenne). PLUM gives a second at 199-bit (non-Mersenne, smooth).

If PLUM shows: Griffin ≈ 90%+ of cycles, control-flow floor ≈ 5-10%,
F_p mul dominant inside Griffin — same shape as Loquat — the claim
generalises across primes and across LDTs (FRI vs STIR). This is the
strongest empirical case we can make from two schemes in one zkVM.

If PLUM looks materially different, that's interesting too — we learn
which factors actually drive the cycle-cost dominance.
