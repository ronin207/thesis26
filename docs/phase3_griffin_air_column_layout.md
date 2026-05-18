# Phase 3d-stage-3 — Griffin Fp192 AIR column-layout plan

**Status.** Design sketch, not implementation. The implementation lands as
a sequence of commits, each adding one constraint family from
`docs/precompile_soundness/griffin_fp192.md`'s B-1 to B-10 rubric.

**Submitted-for-review-before-writing.** This document exists so that
the column layout is auditable *before* 1000+ lines of constraint
code locks in choices that would be expensive to revisit.

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

## Two layout strategies, and the choice

**(A) Many small rows.** Each chip row = one **round** of a permutation.
14 rounds → 14 rows per Griffin syscall. Per-row column count is
small (~60 columns). Cross-row constraints (`Air::eval` reads `local`
*and* `next`) thread the round-to-round state.

**(B) One fat row.** Each chip row = one **full permutation**. 1 row
per syscall. Per-row column count is huge (~14 × 60 = ~840 columns).
All constraints are within `local`; no `next`-row reads.

**Choice: (B) one fat row, like `Poseidon2Chip`.** Reasoning:

  1. Pattern conformity — `poseidon2/air.rs` uses fat rows; we lift
     less novel machinery if we match.
  2. Memory binding is cleaner — one row reads/writes one
     contiguous 128-byte block; the address arithmetic doesn't have
     to thread across rows.
  3. Lookup-argument hookup is simpler — one event → one row → one
     send/receive token.
  4. Padding to power-of-2 row counts is cheaper when rows are heavy
     (fewer dummy rows needed).

The downside (a wider row × max-constraint-degree budget) is real
but tractable — `MAX_CONSTRAINT_DEGREE` in SP1 is 3, our quadratic
layer is degree 4 inside the parenthesized form (`L_i² + α·L_i + β`),
and we'll need to introduce an intermediate column to spill `L_i²`
into. That's the same pattern poseidon2 uses for its S-box.

## Column-layout sketch (one row = one permutation)

```rust
#[derive(AlignedBorrow)]
#[repr(C)]
pub struct GriffinFp192Cols<T: Copy, M: TrustMode> {
    // ──────────────────── Syscall / clk plumbing ──────────────────
    /// High bits of syscall clk.
    pub clk_high: T,
    /// Low bits of syscall clk.
    pub clk_low: T,
    /// Pointer to the 16-u64 state buffer.
    pub ptr: SyscallAddrOperation<T>,

    // ──────────────────────── Memory binding ──────────────────────
    /// Address arithmetic for each of the 16 u64 words.
    pub addrs: [AddrAddOperation<T>; 16],
    /// Memory access record per word. After-AIR, this column is the
    /// guest-observable post-permutation state. Read-write per the
    /// `mw_slice_without_prot` event in
    /// `crates/core/executor/src/events/precompiles/griffin_fp192.rs`.
    pub memory: [MemoryAccessCols<T>; 16],

    // ─────────────────── Input/output range checks ────────────────
    /// Per-lane range check on INPUT — asserts each input Fp192
    /// is in [0, p). Carries B-8's cross-precompile contract from
    /// the OTHER direction (we trust the input to be canonical
    /// because UINT256_MUL guarantees its outputs canonical; this
    /// range check is the receipt).
    pub input_range_checks: [LaneRangeCheck<T>; 4],
    /// Per-lane range check on OUTPUT (B-8). The structural
    /// satisfaction of `uint256_mul_for_fp192.md`'s contract — this
    /// is the line that says "no non-canonical Fp192 escapes this
    /// chip."
    pub output_range_checks: [LaneRangeCheck<T>; 4],

    // ─────────────────────── Per-round state ──────────────────────
    /// Lane state at the start of each round. `state[0]` = input
    /// state; `state[ROUNDS]` = output state. 15 entries × 4 lanes ×
    /// 4 limbs = 240 cells.
    pub state: [[FieldVar<T>; 4]; ROUNDS_PLUS_ONE],

    // ─────────────────── Per-round S-box (B-1, B-2) ───────────────
    /// `sbox_lane1_squared[r] = state[r][1]²`. Spilled into a column
    /// so the cubing in B-1 is degree 3 instead of degree 4.
    pub sbox_lane1_squared: [FieldVar<T>; ROUNDS],

    // ─────────────── Per-round quadratic layer (B-3) ──────────────
    /// `l_i[r]` for `i ∈ {2, 3}` — the linear combination used in
    /// the quadratic factor.
    pub l_values: [[FieldVar<T>; 2]; ROUNDS], // [l_2, l_3] per round
    /// `l_i_squared[r][i-2] = l_i[r][i-2]²`. Same spill trick as
    /// sbox_lane1_squared — keeps the quadratic factor at degree 3.
    pub l_squared: [[FieldVar<T>; 2]; ROUNDS],
    /// Quadratic-factor evaluations
    /// `quad[r][i-2] = l_squared + α[i-2]·l + β[i-2]`. Degree-1 in
    /// columns; combined with `state[r][i]` to update `state[r+1][i]`.
    pub quad_factor: [[FieldVar<T>; 2]; ROUNDS],

    // ──────────────────── Post-MDS, post-RC state ─────────────────
    /// `state_after_mds[r]` — output of the MDS layer for round `r`,
    /// before round-constants addition. Spilled so MDS (B-4) and RC
    /// (B-5) are each degree-1 constraints.
    pub state_after_mds: [[FieldVar<T>; 4]; ROUNDS],

    // ───────────────────────── Lookup / page prot ─────────────────
    pub address_slice_page_prot_access: M::SliceProtCols<T>,

    // ───────────────────────── Bookkeeping ────────────────────────
    /// Boolean row flag (B-9).
    pub is_real: T,

    _marker: PhantomData<M>,
}
```

Where `FieldVar<T>` is shorthand for a 4-limb `[u64-like<T>; 4]`
representation (the actual SP1 type to use is whatever the
`Uint256MulModChip` adopts at `sp1-core-machine/.../uint256/columns.rs`
— `Word<T>` or equivalent).

`ROUNDS = 14`, `ROUNDS_PLUS_ONE = 15`.

## Per-row column count estimate

- Plumbing: `clk_high + clk_low + ptr` ≈ 6 cells (after expanding
  SyscallAddrOperation).
- Memory: 16 `AddrAddOperation` × ~3 cells + 16 `MemoryAccessCols` ×
  ~4 cells = ~112 cells.
- Range checks: 8 × `LaneRangeCheck` × ~4 cells = ~32 cells.
- State: `15 × 4 × 4 = 240 cells`.
- S-box spills: `14 × 4 = 56 cells`.
- Quadratic layer: `14 × 2 × 3 × 4 = 336 cells` (l + l² + quad, 4
  limbs each, 2 lanes per round).
- Post-MDS: `14 × 4 × 4 = 224 cells`.
- Page prot + `is_real`: ~10 cells.

**Total: ~1,016 cells per row.**

Compare poseidon2 (BabyBear): ~150 cells per row × 4 rows per
permutation = 600 cells per permutation. Our row is ~1.7× wider per
permutation, but we have 14 rounds against poseidon2's ~12 rounds and
our limbs are 4× wider (199-bit vs 31-bit). Expected.

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
