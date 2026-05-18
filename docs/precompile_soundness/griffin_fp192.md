# Soundness note — Custom `GRIFFIN_FP192_PERMUTE` precompile for the Griffin permutation over PLUM's prime field

**Deliverable:** the "Griffin permutation" module of the thesis's
three-precompile suite, as built for the SP1 zkVM target. This is the
*load-bearing* precompile of the suite — PLUM §4.2's R1CS
decomposition assigns 91% of constraints (~94% of muls under our
attribution) to hash work, and Griffin is the construction PLUM
uses.

**Phase status (2026-05-18).** Phases 3a–3f are committed: chip
registered, executor handlers implementing native compute, guest
routed through syscall under `cfg(all(target_os = "zkvm", feature =
"sp1", not(feature = "sp1-no-griffin-syscall")))`, A/B measurement
harness landing a clean 56× execute-cycle delta on PLUM-80. **Phase
3d-stage-3 (the AIR constraints) has not been written.** This
document is the soundness rubric stage-3 will be implemented against,
not a post-hoc justification.

**Sibling soundness note.** The `UINT256_MUL` Fp192 multiplication
module (`docs/precompile_soundness/uint256_mul_for_fp192.md`)
documents the cross-precompile output-range contract this AIR must
satisfy. The Griffin AIR's output canonicality (item B-8 below) is
the satisfaction of that contract from this side.

## Construction

We write a custom Griffin AIR rather than reusing an upstream chip,
because no SP1 chip computes a Griffin permutation over a 199-bit
prime field. The closest upstream pattern is `Poseidon2Chip` at
`submodules/sp1/crates/core/machine/src/syscall/precompiles/poseidon2/air.rs`
— same general shape (permutation precompile with single-pointer
state I/O, per-round columns, memory binding), but over a small
prime (Plonky3 BabyBear/KoalaBear, 31 bits) rather than PLUM's
199-bit prime.

### Layers

The construction has five components on the SP1 side and one on the
guest side.

1. **Guest-side syscall trampoline** at
   `submodules/sp1/crates/zkvm/entrypoint/src/syscalls/griffin_fp192.rs`.
   Exposed via `sp1_zkvm::syscalls::syscall_griffin_fp192_permute(*mut [u64; 16])`.
   `ecall` with `t0 = GRIFFIN_FP192_PERMUTE = 0x00_00_01_35`,
   `a0 = state_ptr`, `a1 = 0`.

2. **Guest-side call site** in
   `src/primitives/hash/griffin_p192.rs::plum_griffin_permutation`.
   Pack `[Fp192; 4]` → `[u64; 16]` (little-endian limbs per lane),
   call syscall, unpack via `Fp192::from_limbs` (which reduces mod p
   defensively).

3. **Executor (tracing-mode) handler** at
   `submodules/sp1/crates/core/executor/src/vm/syscall/griffin_fp192.rs`.
   Records memory accesses; consumes pre-laid write records from the
   minimal executor's queue. Emits `PrecompileEvent::GriffinFp192`.

4. **Executor (minimal-mode) handler** at
   `submodules/sp1/crates/core/executor/src/minimal/precompiles/griffin_fp192.rs`.
   The load-bearing path: reads the 16-word state from guest memory,
   calls `griffin_fp192_compute::permute_in_place`, writes the
   permuted state back.

5. **Vendored native compute** at
   `submodules/sp1/crates/core/executor/src/griffin_fp192_compute.rs`.
   Mirrors `src/primitives/hash/griffin_p192.rs`. SHAKE256-derived
   round constants, d=3 S-box, 4×4 MDS matrix, 14 rounds for PLUM's
   parameters.

6. **AIR chip (stage-3, TO BE WRITTEN)** at
   `submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/`.
   Currently a skeleton: `included() = false`, single trivial
   `assert_bool(is_real)` constraint. Stage-3 lands the real
   per-round constraints.

## Trust model

The Griffin precompile's correctness reduces to:

  - **(T1) Upstream SP1 cross-table lookup argument is sound.**
    Same assumption as the `UINT256_MUL` note. We are downstream
    consumers; SP1's release process audits this.
  - **(T2) The AIR encodes the Griffin permutation exactly.**
    This is the work of stage-3 and the subject of §"Stage-3 soundness
    checklist" below.
  - **(T3) The chip's trace generator and the executor's native
    compute (`griffin_fp192_compute::permute_in_place`) compute the
    same function.** Witnessed by `equivalence_tests` (host-side,
    randomized 256-vector property test + 3 hand-picked vectors +
    modulus equality check). Note this currently verifies
    `executor ≡ reference`, NOT `chip ≡ executor` — stage-3 must add
    the second check by deriving the AIR witness from the same
    `permute_lanes` code (audit finding A-2).
  - **(T4) The vendored compute matches the host reference exactly.**
    Witnessed by the same 256-vector property test (currently
    `executor ≡ host`). Drift detector for parameter
    derivation (SHAKE seed string, round count formula, MDS matrix
    entries).

Under (T1)–(T4), PLUM Verify under the syscall route produces the
same accept/reject decision as PLUM Verify under native compute, and
PLUM's EU-CMA reduction (paper §5) transfers without modification
(because Griffin is treated as a deterministic permutation by the
reduction, exactly the surface the syscall exposes).

**(T5) — orthogonal but upstream of the AIR — QROM analysis for
Griffin at d=3, state-width 4, 199-bit field, 14 rounds.** PLUM's
EU-CMA argument under Fiat-Shamir requires Griffin to be (Q)ROM-
replaceable. The Griffin paper analyzes the original instantiations;
our 199-bit-field instantiation may or may not be covered by that
analysis. **The AIR cannot rescue Griffin if Griffin is QROM-
distinguishable under these parameters.** This is a thesis-level
claim independent of the AIR work; flagged here so the defence
notices.

## Stage-3 soundness checklist (the rubric)

Each row is a property the AIR must enforce. Layout: **constraint
math** / **failure mode if missing or weak** / **attacker capability**
/ **source spec** / **status** (PLANNED / IMPLEMENTED / TESTED).

### B-1 — Forward S-box on lane 1 (degree-3)

For each round, `state_after[1] = state_before[1]³ (mod p)`. **PLANNED.**
- Failure mode: wrong `d` parameter; or `out₁ = in₁ · in₁ · in₁'` with
  `in₁' ≠ in₁`.
- Attacker capability: find a `state'` whose forward S-box differs
  from the spec → collision under the broken Griffin → PLUM EU-CMA
  forgery.
- Source spec: `src/primitives/hash/griffin_p192.rs:247` (forward
  S-box), Griffin paper §2.3, our `d = 3` derivation in
  `pick_d_and_inverse`.

### B-2 — Inverse S-box on lane 0 (degree-3 backward)

For each round, `state_before[0] = state_after[0]³ (mod p)`. The AIR
cannot raise to `d_inv` directly (199-bit exponent → unboundedly high
constraint degree); instead it constrains the *backward* relation
`out₀^d = in₀`, which is equivalent in a permutation. **PLANNED.**
- Failure mode: omit the backward check; constrain forward `in₀³ =
  out₀` instead of backward — these aren't equivalent because the
  S-box is `x → x^d_inv` here, not `x → x^d`.
- Attacker capability: same forgery vector as B-1 but on lane 0.
- Source spec: `src/primitives/hash/griffin_p192.rs:245`.

### B-3 — Quadratic layer on lanes 2, 3

For each round and each `i ∈ {2, 3}`:

    L_i      = (i - 1) · z₀ + z₁ + z_{i-1}
    state_after[i] = state_before[i] · (L_i² + α_{i-2}·L_i + β_{i-2})

where `z₀ = state_after[0]`, `z₁ = state_after[1]`, `z_{i-1} = state_after[i-1]`
(reading from after-S-box state per the reference's `nonlinear_layer`).
**PLANNED.**
- Failure mode: wrong α/β; wrong L formula (off-by-one in the index
  multiplier); missing the multiplication by `state_before[i]`.
- Attacker capability: collide on lanes 2/3.
- Source spec: `griffin_p192.rs:250-267`, `li()` at 293.

### B-4 — MDS linear layer

For each row of the matrix-vector product:

    next[row] = Σ_{col=0..4} matrix[row][col] · state[col]

where `matrix = circulant([2, 1, 1, 1])`. **PLANNED.**
- Failure mode: wrong matrix (e.g., `[1, 1, 1, 1]` — not MDS, only
  rank 1).
- Attacker capability: low-weight differential trail attacks; reduced-
  round collision.
- Source spec: `griffin_p192.rs:496-505` (circulant), mirrored at
  `griffin_fp192_compute.rs:360-374`.

### B-5 — Round constants from SHAKE256

After round `r ∈ 0..rounds-1`, lane `ℓ ∈ 0..4` is offset by
`RC[r * 4 + ℓ]`, where `RC` is derived from
`SHAKE256("PlumGriffin({modulus},{state_width},{capacity},{security_level})")`
unrolled into `(rounds - 1) * 4 = 13 * 4 = 52` field elements.
**PLANNED.**
- Failure mode: RC silently zeroed (test
  `zero_state_is_not_a_fixed_point` would catch all-zero, but a
  single wrong constant slips through); RC supplied per-row by the
  prover rather than fixed in preprocessing (this is B-10).
- Attacker capability: slide attacks, fixed-point exploitation.
- Source spec: `griffin_p192.rs:344-402`
  (`compute_plum_griffin_params`), `griffin_fp192_compute.rs:217-247`
  on the executor side.

### B-6 — Round count

`rounds = 14` for our parameters. Derived from Griffin paper's
security bound: `rgb` grows until the security threshold is met,
then `rounds = ceil(((rgb + 1).max(6)) * 1.2)`. **PINNED** by
`round_count_matches_integer_formula` test (`griffin_p192.rs:557`
post-A-4 fix). The integer formula is `(base * 12 + 9) / 10`; the
prior f64 path was retired in commit ⟨TBD⟩ as audit finding A-4.
- Failure mode: one too few rounds.
- Attacker capability: reduced-round collision → forge any signature.
- Source spec: `griffin_p192.rs:458-480`,
  `griffin_fp192_compute.rs:300-322`.

### B-7 — Memory binding

Each non-padding row reads exactly the 16 `u64` words at
`arg1 = event.ptr` recorded in the
`GriffinFp192PrecompileEvent`, and writes the permuted state to the
same 16 words. The address arithmetic must match the
`AddrAddOperation` pattern in `poseidon2/air.rs:483-558` so the
multi-table lookup argument balances. **PLANNED.**
- Failure mode: chip reads from wrong address; chip claims a write
  was at clk `c` but actually fired at clk `c'`.
- Attacker capability: claim a Griffin syscall acted on address `A`
  when the trace fires it at address `B` — witness binding broken.
- Source spec: pattern at `poseidon2/air.rs:483-558`, event struct
  at `submodules/sp1/crates/core/executor/src/events/precompiles/griffin_fp192.rs`.

### B-8 — Output canonicality (per-lane range check)

Each output limb buffer `[l₀, l₁, l₂, l₃]` satisfies the four-limb
inequality `[l₀, l₁, l₂, l₃] < MODULUS_LIMBS`. **PLANNED — this is
the satisfaction of the cross-precompile contract documented in
`uint256_mul_for_fp192.md`.**
- Failure mode: output lane is non-canonical; the guest then calls
  `Fp192::to_limbs` on it (`p192.rs:189-197`) which silently
  truncates digits beyond the 4th in release builds (audit finding
  A-1). Downstream Fp192::mul receives a wrong-modulus value;
  signature acceptance becomes meaningless.
- Attacker capability: field-mismatch — verifier sees one value,
  prover proved another. Direct path to forgery.
- Source spec: SP1's `Uint256MulModChip` output range check at
  `sp1-core-machine-6.2.1/src/syscall/precompiles/uint256/air.rs:435`
  is the analog we should follow structurally.

### B-9 — `is_real` discipline

`is_real ∈ {0, 1}` per row. The `is_real = 0` rows are padding —
their state columns are unconstrained and they do not participate in
the syscall lookup argument. **PARTIALLY IMPLEMENTED** (the trivial
`assert_bool(local.is_real)` constraint is in place from Phase 3e
prep; the lookup-argument hookup is stage-3 work).
- Failure mode: padding row accidentally claims `is_real = 1` and
  emits a lookup token for a Griffin syscall that never executed.
- Attacker capability: "ghost permutation" — claim a Griffin output
  with no corresponding syscall, then point downstream verifier
  computation at it.
- Source spec: pattern at `poseidon2/air.rs:430-451`.

### B-10 — Parameter immutability (preprocessing)

The α, β, RC, MDS matrix entries are *committed by the verifier in
preprocessing* — not row columns the prover supplies. **PLANNED.**
- Failure mode: prover chooses RC per row.
- Attacker capability: total break. For any input/output pair, find
  a "permutation" by picking RC values that make the algebra close.
  Trivial collision.
- Source spec: convention; round constants live in preprocessing
  tables (`PreprocessedAir` pattern). Witnessed by the test pinning
  the SHAKE seed string in `griffin_p192.rs` and
  `griffin_fp192_compute.rs`.

## Cross-codebase agreement (current state)

`platforms/zkvms/sp1/equivalence_tests/tests/griffin_fp192_equivalence.rs`:

| Test | What it pins |
|---|---|
| `modulus_limbs_agree` | `MODULUS_LIMBS` constant equality between executor and reference — fastest possible drift detector for the SHAKE seed. |
| `permutation_matches_reference_on_simple_vector` | `[1, 2, 3, 4]` lanes; smallest non-trivial diff. |
| `permutation_matches_reference_on_zero_input` | Zero state; isolates the round-constants layer (S-box and linear map zero map to zero). |
| `permutation_matches_reference_on_high_entropy_input` | 16-word non-uniform input; catches limb-ordering bugs. |
| `permutation_matches_reference_on_random_inputs` (post-A-2 fix) | **256 randomized vectors** under fixed seed; addresses audit finding A-2 (the hand-picked vectors might agree by coincidence if both sides share a bug invisible to those patterns). False-pass probability per vector is at most `1/p ≈ 2^-199`. |

256 random vectors after A-2 fix is the strongest evidence available
without a constraint-level audit. **Drift detector for stages 3a–3f;
not a substitute for stage-3's structural proof of `chip ≡ executor`.**

## What this argument does NOT cover

- **Constraint-level verification of stage-3.** Stage-3 doesn't
  exist. The B-1 to B-10 checklist above is what stage-3 needs to
  satisfy; until stage-3 lands, this is a rubric, not an argument.

- **QROM analysis for our Griffin parameters (T5).** Upstream of the
  AIR. A thesis-level claim that needs to be verified against the
  Griffin paper. **If Griffin at d=3, state-width 4, 199-bit field
  with 14 rounds turns out to be QROM-distinguishable, no amount of
  AIR engineering recovers it.**

- **Public audit citations for the SP1 cross-table lookup argument
  (T1).** Same gap as in `uint256_mul_for_fp192.md`. Best we can say
  is "pinned to SP1 v6.2.1, production release process audited".

- **Stage-3-internal soundness arguments per constraint family.**
  As stage-3 lands, each B-x section above becomes a sub-argument
  with the AIR constraint quoted and reduced to the spec line in
  `griffin_p192.rs`. Today those sections are PLANNED.

## Property-table status (current, pre-stage-3)

| Property | Status | Notes |
|---|---|---|
| (a) Reference Griffin spec correct | UPSTREAM-TRUSTED | Griffin paper + PLUM §4.2. (T5 caveat above re: QROM.) |
| (b) Executor compute ≡ reference compute | EMPIRICALLY TESTED | 256 random vectors + 3 hand-picked + modulus check. |
| (c) Modulus, d, round count, MDS matrix, SHAKE seed string drift detection | PAPER-AUDITED + EMPIRICALLY TESTED | Module-doc constants quoted from spec; tests pin values. |
| (d) Chip ≡ executor (witness ≡ constraint) | **UNVERIFIED — stage-3 deliverable** | This is the work. |
| (e) AIR memory binding | **UNVERIFIED — stage-3 deliverable** | Pattern from poseidon2. |
| (f) Output canonicality (per-lane `< p`) | **UNVERIFIED — stage-3 deliverable** | Satisfies cross-precompile contract. |
| (g) Parameter immutability | **UNVERIFIED — stage-3 deliverable** | Preprocessing tables. |
| (h) `is_real` discipline + lookup-argument balance | PARTIALLY IMPLEMENTED | Trivial bool constraint live; lookup hookup is stage-3. |
| (i) ZK preserved | OUT-OF-SCOPE | Same as `uint256_mul_for_fp192.md`. |
| (j) QROM analysis for our Griffin parameters | **UNVERIFIED — upstream claim** | Thesis-level check; AIR cannot rescue. |

## Audit caveats from proof-checker (2026-05-18, pre-stage-3)

1. **A-1 (HIGH).** `Fp192::to_limbs` silently truncates digits beyond
   the 4th in release builds (`debug_assert!` is a no-op). Safe today
   only by transitive reliance on every constructor reducing mod p.
   **Mitigation:** stage-3 must enforce B-8 (output canonicality)
   strictly so the dependency on transitive canonicality is broken.

2. **A-2 (MEDIUM).** Cross-codebase tests verify executor ≡ reference,
   not chip ≡ executor. **Mitigation (partial):** the 256-vector
   randomized property test reduces the "coincidence" risk on the
   tested half. The other half (chip ≡ executor) requires stage-3
   to derive AIR witness rows from `permute_lanes`, not a
   re-implementation.

3. **A-3 (MEDIUM).** Pack/unpack inherits A-1's truncation. Same
   mitigation as A-1.

4. **A-4 (LOW).** `f64` round count — **FIXED** in this revision.
   Replaced with `(base * 12).div_ceil(10)` on both sides; pinned by
   `round_count_matches_integer_formula` test at
   `griffin_p192.rs:557`.

5. **Cross-cutting (T5).** QROM analysis for our Griffin parameters
   is upstream of the AIR. Flagged for thesis defence; track
   separately.

These caveats are tracked here so a thesis reviewer reading this
note can audit our awareness of the gaps before stage-3 lands.
