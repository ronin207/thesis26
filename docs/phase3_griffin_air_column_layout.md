# Phase 3d-stage-3 — Griffin Fp192 AIR column-layout plan

**Status.** Design sketch, not implementation. The implementation lands as
a sequence of commits, each adding one constraint family from
`docs/precompile_soundness/griffin_fp192.md`'s B-1 to B-10 rubric.

**Submitted-for-review-before-writing.** This document exists so that
the column layout is auditable *before* 1000+ lines of constraint
code locks in choices that would be expensive to revisit.

**Revision history.**
- 2026-05-18 v1 — original sketch with placeholder `FieldVar<T>` /
  `LaneRangeCheck<T>` types.
- 2026-05-18 v2 (**current**) — revised after studying poseidon2,
  uint256, and keccak chips. Replaced placeholder types with concrete
  SP1 primitives: `FieldOpCols<T, Fp192FieldParams>` (modular
  arithmetic), `FieldLtCols<T, Fp192FieldParams>` (output canonicality),
  `Limbs<T, U32>` (state representation as 32 u8 limbs). Also reversed
  the "one fat row vs many small rows" choice — see §"Row scheduling"
  below.

## Scale realism (read this first)

The SP1 chips closest to ours in shape:

| Chip | LOC | Files |
|---|---|---|
| `Poseidon2Chip` | 608 | 1 (`air.rs`) + heavy leaning on upstream `sp1_hypercube::operations::poseidon2` module |
| `Uint256MulChip` | 517 | 1 |
| `KeccakChip` | **1,032** | 6 (`air.rs`, `columns.rs`, `constants.rs`, `controller.rs`, `trace.rs`, `mod.rs`) |

Griffin Fp192 doesn't have an upstream module to lean on (no
`sp1_hypercube::operations::griffin`). The full chip will be
**closer to keccak's footprint than poseidon2's** — probably
800–1,200 LOC across 4–6 files. This is genuinely multi-week work
implemented as 8–10 incremental commits per the B-x checklist.

## What the AIR is constraining

One Griffin permutation per chip row. The state is `4 lanes × 4 u64
limbs each = 16 u64 words = 128 bytes` in guest memory. The AIR
constrains:

  - The state at `arg1` *before* the syscall = the input lanes the
    AIR's per-round columns walk through.
  - The state at `arg1` *after* the syscall = the final-round
    columns.
  - All 14 rounds' algebra (S-box, quadratic layer, MDS, round
    constants) ties input to output.

## Row scheduling (revised after primitive study)

**(A) Many small rows.** Each chip row = one **round** of a permutation.
14 rounds → 14 rows per Griffin syscall. Per-row column count is
small (~500–800 cells). Cross-row constraints (`Air::eval` reads
`local` *and* `next`) thread the round-to-round state.

**(B) One fat row.** Each chip row = one **full permutation**. 1 row
per syscall. Per-row column count is enormous (~14 rounds × ~500
cells/round = ~7,000 cells per row).

**Choice: (A) many small rows (REVISED from v1).** Reasoning:

  1. **Multi-limb arithmetic cost scales with row width.** Each
     `FieldOpCols<T, Fp192FieldParams>` is ~95 cells (32 limbs + 63
     witness limbs + carry). Per round Griffin needs ~6–10 of these
     (cube, two quadratic factors, MDS dot products, round constants
     addition). That's 600–950 `FieldOpCols` cells per round × 14
     rounds = **8,400–13,300 cells per fat row**. Many small rows
     stay under SP1's per-chip row-width budget.
  2. Cross-row state threading is `assert_eq!(next.state, local.computed_next_state)`
     — mechanical and pattern-conforming with the way `KeccakChip`
     handles its 24-round permutation (see
     `submodules/sp1/crates/core/machine/src/syscall/precompiles/keccak256/`).
  3. Padding to power-of-2 row counts is per-row, not per-permutation,
     so the cost is similar in both schemes once you account for
     row width.

The downsides we accept:
  - **Memory binding only happens at the first and last round-rows**
    of a permutation. We need an `is_first_round` / `is_last_round`
    discipline column. The first-round row reads input from memory;
    the last-round row writes output to memory. The middle rows are
    pure algebra.
  - **Lookup-argument hookup fires only on the last round-row**
    (where the syscall "completes" from the verifier's perspective).

## Concrete primitives (post-study)

| Type | Source | Role |
|---|---|---|
| `Fp192FieldParams` | `sp1-curves/src/fp192.rs` (**landed** this commit) | `FieldParameters` impl pinning PLUM's prime as `MODULUS`. The "parameter immutability" of B-10. |
| `FieldOpCols<T, Fp192FieldParams>` | `sp1-core-machine/.../operations/field/field_op.rs` | One modular arithmetic op (add/sub/mul) per cell. ~95 cells/op (32 limbs + 63 witness limbs + carry plumbing). |
| `FieldLtCols<T, Fp192FieldParams>` | `sp1-core-machine/.../operations/field/range.rs` | Output canonicality (`< p`). B-8 uses this directly. |
| `Limbs<T, U32>` | `sp1-curves/src/params.rs` | 32 u8 limbs = our 199-bit value in canonical limb form. |
| `MemoryAccessColsU8<T>` | `sp1-core-machine/src/memory/` | Memory access record at a single u64 word. We use 16 per permutation. |
| `AddrAddOperation<T>` | `sp1-core-machine/src/operations/` | `ptr + offset` arithmetic for the 16 memory slots. |
| `SyscallAddrOperation<T>` | `sp1-core-machine/src/operations/` | Syscall arg-pointer alignment + sanity. |

## Column-layout sketch (one row = one round of one permutation)

```rust
#[derive(AlignedBorrow)]
#[repr(C)]
pub struct GriffinFp192Cols<T, M: TrustMode> {
    // ──────────────────── Syscall / clk plumbing ──────────────────
    pub clk_high: T,
    pub clk_low: T,
    pub ptr: SyscallAddrOperation<T>,

    // ────────────────── Round-position discipline ─────────────────
    /// 1 for the first round-row of a permutation, 0 elsewhere. The
    /// first row reads input from memory; subsequent rows take input
    /// from `prev_row.state_after_round`.
    pub is_first_round: T,
    /// 1 for the last round-row of a permutation, 0 elsewhere. The
    /// last row writes output to memory and emits the syscall-receive
    /// lookup token.
    pub is_last_round: T,
    /// Round index 0..ROUNDS encoded as a limb. Used by the
    /// preprocessing table lookup for round constants (B-5/B-10).
    pub round_idx: T,

    // ────────── Memory binding (active only on first/last row) ────
    /// Address arithmetic for the 16 u64 words. Same columns are
    /// populated in every row; the constraint only fires on
    /// `is_first_round + is_last_round` rows.
    pub addrs: [AddrAddOperation<T>; 16],
    /// Memory access records for the 16 u64 words. On first-round
    /// rows: read input. On last-round rows: write output.
    pub memory: [MemoryAccessColsU8<T>; 16],

    // ─────────────────────── Per-round state ──────────────────────
    /// State entering this round: 4 lanes × Limbs<T, U32>.
    pub state_before: [Limbs<T, U32>; 4],
    /// State after the nonlinear layer (S-boxes + quadratic).
    pub state_after_nonlinear: [Limbs<T, U32>; 4],
    /// State after the MDS linear layer.
    pub state_after_mds: [Limbs<T, U32>; 4],
    /// State after the round-constants addition (= input to next round).
    /// On `is_last_round` rows, this is the output written to memory.
    pub state_after_round: [Limbs<T, U32>; 4],

    // ─────────────────────── B-1: forward S-box ───────────────────
    /// `state_after_nonlinear[1] = state_before[1]^3`. Two FieldOpCols:
    /// one for `x^2`, one for `x^2 * x`.
    pub sbox1_sq: FieldOpCols<T, Fp192FieldParams>,
    pub sbox1_cube: FieldOpCols<T, Fp192FieldParams>,

    // ─────────────────── B-2: inverse S-box (backward) ────────────
    /// `state_before[0] = state_after_nonlinear[0]^3`. Symmetric to
    /// B-1 but constrained backward — we witness the *post-S-box*
    /// lane 0 value, then assert its cube equals the *pre-S-box*
    /// value. Two FieldOpCols.
    pub sbox0_sq: FieldOpCols<T, Fp192FieldParams>,
    pub sbox0_cube: FieldOpCols<T, Fp192FieldParams>,

    // ─────────────────────── B-3: quadratic layer ─────────────────
    /// For each i ∈ {2, 3}: L_i = (i-1)·z₀ + z₁ + z_{i-1}.
    /// 2 FieldOpCols per lane (add then add).
    pub l_values: [[FieldOpCols<T, Fp192FieldParams>; 2]; 2], // [l_2, l_3] × [step1, step2]
    /// L_i² — square of the linear combination.
    pub l_squared: [FieldOpCols<T, Fp192FieldParams>; 2],
    /// α_{i-2} · L_i — middle term of the quadratic factor.
    pub alpha_times_l: [FieldOpCols<T, Fp192FieldParams>; 2],
    /// L_i² + α·L_i + β — full quadratic factor (2 adds chained).
    pub quad_factor_partial: [FieldOpCols<T, Fp192FieldParams>; 2],
    pub quad_factor: [FieldOpCols<T, Fp192FieldParams>; 2],
    /// state_after_nonlinear[i] = state_before[i] · quad_factor[i].
    pub quad_mul: [FieldOpCols<T, Fp192FieldParams>; 2],

    // ───────────────────────── B-4: MDS layer ─────────────────────
    /// Each row = Σ matrix[i][j] · state_after_nonlinear[j].
    /// Circulant [2,1,1,1] matrix, so each output is `2·in[i] + in[j₁] + in[j₂] + in[j₃]`.
    /// One scaling FieldOpCols (× 2) per lane + 3 add FieldOpCols.
    pub mds_doubled: [FieldOpCols<T, Fp192FieldParams>; 4],
    pub mds_partial: [[FieldOpCols<T, Fp192FieldParams>; 3]; 4],

    // ─────────────── B-5: round constants addition ────────────────
    /// Per lane: state_after_round[ℓ] = state_after_mds[ℓ] + RC[r*4+ℓ].
    /// RC[r*4+ℓ] is read from preprocessing via PairBuilder.
    pub rc_add: [FieldOpCols<T, Fp192FieldParams>; 4],

    // ─────────────── B-8: output canonicality (last row) ──────────
    /// Per-lane range check on state_after_round. Fires only on
    /// `is_last_round`. Closes the cross-precompile contract from
    /// `uint256_mul_for_fp192.md`.
    pub output_range_checks: [FieldLtCols<T, Fp192FieldParams>; 4],

    // ───────────────────────── Page prot ──────────────────────────
    pub address_slice_page_prot_access: M::SliceProtCols<T>,

    // ───────────────────────── Bookkeeping ────────────────────────
    /// Boolean row flag. 1 = real permutation row, 0 = padding.
    pub is_real: T,
}
```

**Width estimate (revised).** Each `FieldOpCols<T, Fp192FieldParams>`
is ~95 cells. Per-round FieldOp count: 2 (B-1) + 2 (B-2) + 8 (B-3) + 4
(B-4 doubled) + 12 (B-4 partial) + 4 (B-5) + 4 (B-8, last row only)
= **36 FieldOps × 95 cells = ~3,420 cells**. Plus 4×32 state limbs ×
4 state stages = 512 cells. Plus 16 memory access + addrs ≈ 200
cells. Plus bookkeeping ≈ 20 cells.

**Total: ~4,150 cells per row.** Comparable to keccak's per-row width.

## Per-permutation footprint

  - Rows per permutation: **14** (one per round)
  - Cells per row: ~4,150
  - Total cells per permutation: ~58,000

PLUM-80 fires 1,052 Griffin syscalls (per Phase 3f measurement) →
~61M trace cells. This is sized for the prover; SP1's shard limit
should accommodate it without exotic configuration.

## Constraint families (the implementation order)

Each landed as a separate commit. Each commit:
  - Adds the constraint(s).
  - Adds a trace-generation test (the test takes a known input,
    walks the AIR row by hand against a reference, asserts the
    constraint evaluates to zero).
  - Fills in the corresponding section of
    `docs/precompile_soundness/griffin_fp192.md` (B-x).
  - Adds an adversarial probe: tamper one cell in the trace, assert
    the constraint catches it (zero-knowledge regression net).

Order (lowest-risk to highest-risk):

1. **B-9, B-10** — `is_real` discipline + preprocessing tables.
   Mechanical; pattern conformity. No new algebra.
2. **B-7** — Memory binding. Lift directly from `poseidon2/air.rs`'s
   `AddrAddOperation`/`MemoryAccessCols` plumbing.
3. **B-1** — Forward S-box (lane 1). Single-constraint family; tests
   the cubing spill technique.
4. **B-4** — MDS linear layer. Tests the `state_after_mds` spill
   plumbing.
5. **B-5** — Round constants. Trivial once B-4 is in.
6. **B-3** — Quadratic layer (lanes 2, 3). Most algebra; tests the
   `l_squared` / `quad_factor` spills.
7. **B-2** — Inverse S-box (lane 0). Degree-3 backward constraint;
   the conceptually-trickiest piece.
8. **B-8** — Output canonicality. Last because it depends on
   `state[ROUNDS]` being constrained; without earlier constraints
   the range check is meaningless.
9. **(integration)** — Wire up the lookup argument so events get
   received. Switch `included()` to true. First commit where the
   chip actually emits rows.

## Where the per-row computation is heaviest

Profile (rough):

- 14 rounds × 1 cubing per round (B-1): 14 cubings.
- 14 rounds × 1 cubing per round (B-2): 14 cubings.
- 14 rounds × 2 quadratics per round (B-3): 28 quadratics.
- 14 rounds × 4 lanes × 4 dot-products (B-4): 224 dot products =
  224 multiplications.

**~280 multiplications per row.** Trace-gen cost dominates. Mitigation
strategies (orthogonal to soundness):

  - Cache reusable values across rounds where possible.
  - Use SIMD inside `permute_lanes` to reuse the same computation
    the executor does (this is also stage-3's witness derivation —
    audit finding A-2's recommended pattern).

## Where the proof-checker audit lives in this layout

  - **A-1 (HIGH).** Per-lane output range check is `output_range_checks`
    above (B-8). Stage-3's last constraint family.
  - **A-2 (MEDIUM).** Witness derivation: `state[r]` columns must be
    populated by stepping `permute_lanes`, not a re-implementation.
    See "Where the per-row computation is heaviest" above.
  - **A-3 (MEDIUM).** Inherits A-1; same mitigation.
  - **A-4 (LOW).** **Already fixed** in this revision (integer
    round-count formula).

## What this doc does NOT design

  - **Trace-row scheduling across shards.** SP1 shards traces by row
    count; `num_rows` and `included` already follow `Poseidon2Chip`'s
    pattern. No deviation expected.
  - **`PreprocessedAir` table layout for α/β/RC.** Defer to stage-3's
    B-10 commit.
  - **Exact field representation choice (`Word<T>` vs custom limb
    layout).** Defer to first-constraint-family commit (B-9, mechanical).
  - **Page-prot record handling in user-mode SyscallContext.** Defer
    to integration commit.
