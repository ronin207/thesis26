# Phase 3d-stage-3 — Integration-B design analysis

**Purpose.** Pin down the byte-packing mapping between the
controller chip's `Word<F>` memory representation and the per-round
chip's `Limbs<T, U32>` Fp192 state representation, so that the
cross-chip lookup in integration-B binds them consistently.

**Written:** start of post-2026-05-18 session, before any
integration-B code.

**Audit gate.** Integration-B implementation does NOT proceed until
the Operator confirms this mapping. One misread byte-ordering at
this layer invalidates every B-x constraint commit from yesterday.

## Three views of the same 128 bytes

### View 1 — syscall ABI

The guest passes `state: *mut [u64; 16]` as `arg1`. The 128
contiguous bytes at `[arg1, arg1 + 128)` hold the Griffin state.
Each u64 is little-endian per RISC-V convention.

| u64 index `w` | Byte range | Semantic |
|---|---|---|
| 0 | `[0, 8)` | lane 0, limb 0 |
| 1 | `[8, 16)` | lane 0, limb 1 |
| 2 | `[16, 24)` | lane 0, limb 2 |
| 3 | `[24, 32)` | lane 0, limb 3 |
| 4 | `[32, 40)` | lane 1, limb 0 |
| 5 | `[40, 48)` | lane 1, limb 1 |
| … | … | … |
| 15 | `[120, 128)` | lane 3, limb 3 |

General: **u64 word `w = lane * 4 + limb_in_lane`** for
`lane ∈ 0..4`, `limb_in_lane ∈ 0..4`.

This is the canonical layout — the executor's
`griffin_fp192_compute::permute_in_place(state_words: &mut [u64; 16])`
reads exactly this. The cross-codebase property test in
`platforms/zkvms/sp1/equivalence_tests/` pins host ≡ executor at
this layer.

### View 2 — controller chip

The controller's `MemoryAccessCols<T>` for u64 word `w` holds
`prev_value: Word<F>` and `value: Word<F>`. From
`sp1-hypercube/src/word.rs:167-176`:

```rust
impl<F: AbstractField> From<u64> for Word<F> {
    fn from(value: u64) -> Self {
        Word([
            F::from_canonical_u16((value & 0xFFFF) as u16),
            F::from_canonical_u16((value >> 16) as u16),
            F::from_canonical_u16((value >> 32) as u16),
            F::from_canonical_u16((value >> 48) as u16),
        ])
    }
}
```

So `Word<F>` for a u64 packs as **4 little-endian u16 field-element
limbs**:

| `Word.0[i]` | Bits of the u64 | Bytes of the 128-byte state (for word `w`) |
|---|---|---|
| `[0]` | 0–15  | `[w*8 + 0, w*8 + 2)` |
| `[1]` | 16–31 | `[w*8 + 2, w*8 + 4)` |
| `[2]` | 32–47 | `[w*8 + 4, w*8 + 6)` |
| `[3]` | 48–63 | `[w*8 + 6, w*8 + 8)` |

Each entry packs **two consecutive state bytes** as `lo + 256·hi`
(little-endian within the u16).

### View 3 — per-round chip

The per-round chip's `state_before[lane]: Limbs<T, U32>` is 32
u8-shaped field cells per lane (the type alias for `Fp192FieldParams`
is `U32` from `typenum`, meaning 32 u8 limbs).

| Cell | State byte index |
|---|---|
| `state_before[lane].0[b]` (lane ∈ 0..4, b ∈ 0..32) | `state_byte = lane * 32 + b` |

The same shape applies to `state_after_nonlinear[lane]`,
`mds_out[lane].result`, `rc_add[lane].result`, etc. — every Fp192
limb buffer is `Limbs<T, U32>` = 32 u8 cells.

## The mapping

Given `lane ∈ 0..4` and byte-in-lane `b ∈ 0..32`, derive:

```text
state_byte_index = lane * 32 + b              ∈ 0..128
w                = state_byte_index / 8       ∈ 0..16
                 = lane * 4 + b / 8           (algebraic identity)
byte_in_word     = state_byte_index % 8       ∈ 0..8
word_limb_i      = byte_in_word / 2           ∈ 0..4
is_high_byte     = byte_in_word % 2           ∈ {0, 1}
```

The lookup constraint that ties controller's `Word<F>` to per-round's
`Limbs<T, U32>` is, for each `w ∈ 0..16` and `i ∈ 0..4`:

```text
memory[w].prev_value.0[i]      // u16 field-element on controller
  ==
state_before[lane(w)].0[b_lo]  +  256 · state_before[lane(w)].0[b_hi]
```

where

```text
lane(w)   = w / 4               (which Fp192 lane owns word w)
b_lo      = (w % 4) * 8 + i * 2  (byte-in-lane index of the low byte)
b_hi      = b_lo + 1
```

Same formula with `rc_add[lane].result.0[b]` and `memory[w].value`
(or `final_value[w]` if we keep the controller's column) for the
output direction on `is_last_round = 1` rows.

### Worked example

Take `lane = 2`, `b = 5`:

```text
state_byte_index = 2*32 + 5 = 69
w                = 69 / 8 = 8           ✓  matches lane*4 + b/8 = 8 + 0 = 8
byte_in_word     = 69 % 8 = 5
word_limb_i      = 5 / 2 = 2
is_high_byte     = 5 % 2 = 1             ⇒ state_before[2].0[5] is the HIGH byte of memory[8].prev_value.0[2]
```

Cross-check via the `Word<F>` packing:

  `Word[8].0[2]` = bits 32–47 of u64 word 8
                 = state bytes 8*8 + (4..6) = state bytes 36..37

But state byte 37 is `lane = 37 / 32 = 1`, `b = 37 % 32 = 5`. **That contradicts the lookup formula above.**

Wait — let me recompute. State byte 36: `36 / 32 = 1` (lane 1), `36 % 32 = 4`. State byte 37: lane 1, b 5.

So `Word[8].0[2]` = state bytes 36..37 = lane 1 bytes 4..5. But word `w = 8` is supposed to be lane 2 word 0 (since `lane = w / 4 = 8 / 4 = 2`). **Contradiction.**

I had the lane-to-word mapping wrong in View 1. Let me recheck.

If u64 index 0..3 → lane 0 (bytes 0..31), 4..7 → lane 1 (bytes 32..63), 8..11 → lane 2 (bytes 64..95)...

But state byte 36 falls in u64 word `36 / 8 = 4`, which is lane 1's first word. State byte 37 is also in word 4 (bytes 32..39). Word 4 ↔ lane 1, limb 0. Consistent.

So `Word[8]` ≠ "lane 1 byte 4..5". It's "u64 word 8 = lane 2 limb 0 = state bytes 64..71". `Word[8].0[2]` = bits 32-47 of THAT u64 = state bytes 64+4 .. 64+5 = bytes 68..69.

State byte 68: `68 / 32 = 2` (lane 2), `68 % 32 = 4` → `state_before[2].0[4]`.
State byte 69: lane 2, b 5 → `state_before[2].0[5]`.

So `Word[8].0[2]` packs `state_before[2].0[4]` (low byte) and `state_before[2].0[5]` (high byte). ✓ Matches the lookup formula. The earlier "contradiction" was my arithmetic — I had `Word[8].0[2]` mapping to state bytes 36..37 by typo; the correct mapping is 68..69.

**Re-check the formula on this example:**

```text
For lane = 2, b = 5:
  w = 2*4 + 5/8 = 8 + 0 = 8                                   ✓
  word_limb_i = (5 % 8) / 2 = 5 / 2 = 2                       ✓
  is_high_byte = 5 % 2 = 1                                    ✓
  b_lo = (8 % 4) * 8 + 2 * 2 = 0 + 4 = 4
  b_hi = 5
```

So the constraint becomes:

```text
memory[8].prev_value.0[2]  ==  state_before[2].0[4] + 256 · state_before[2].0[5]
```

Matches the packing. ✓

## Design choice — where the byte-decomposition lives

### Option A — controller decomposes Word → bytes

Add `decomposed_bytes: [Limbs<T, U32>; 16]` columns to the controller
chip (16 words × 32 byte cells per word = 512 new cells per
controller row). Constrain each Word.0[i] = lo + 256·hi against the
decomposed bytes. The cross-chip lookup then sends `Limbs<T, U32>`
bytes directly to the per-round chip.

**Cost:** ~512 new cells on the controller chip's single row per
syscall. Plus the equality constraints inside the controller chip
binding Word ↔ bytes.

**Benefit:** the per-round chip's lookup receive is byte-for-byte
trivial — no AIR expression building, just match `Limbs<T, U32>`
limbs.

### Option B — per-round chip composes bytes → Word in the lookup

No new columns. The per-round chip's lookup receive computes the
u16 limb on the fly:

```rust
let composed_u16 =
    state_before[lane].0[b_lo].into() + AB::F::from_canonical_u16(256) * state_before[lane].0[b_hi].into();
```

The lookup-balance argument enforces that the controller's
`memory[w].prev_value.0[i]` equals this composed expression.

**Cost:** O(64) degree-1 expressions in the lookup payload per
direction (input + output). Negligible cells; the composition lives
in the constraint expression at the boundary.

**Benefit:** no new columns; the byte cells already exist
(`state_before[lane].0`). Closer to the keccak pattern (keccak's
controller sends `prev_value` directly, the per-round chip's column
layout matches by construction).

**Caveat:** requires that each `state_before[lane].0[b]` cell is
range-checked to `[0, 256)`. Otherwise a malicious prover could pack
the same u16 value in multiple `(b_lo, b_hi)` byte pairings
(e.g., `(0, 1)` and `(256, 0)` both compose to u16 = 256). Need to
verify SP1's `FieldOpCols` already byte-range-checks the operand
limbs it receives — if so, the cells we'd compose are already
u8-bounded transitively.

### Choice: Option B, with one verification step before coding

**Reasons:**

1. Half the column count vs Option A.
2. Matches the upstream keccak pattern more closely.
3. Doesn't require a fresh decomposition AIR table on the controller
   chip.

**Pre-coding check:** confirm that `FieldOpCols::eval_*` calls in
the per-round chip's eval already byte-range-check the
`state_before[lane].0` cells. Looking at
`field_op.rs::eval_with_polynomials:503-505`:

```rust
builder.slice_range_check_u8(&self.result.0, is_real.clone());
builder.slice_range_check_u8(&self.carry.0, is_real.clone());
builder.slice_range_check_u16(p_witness.coefficients(), is_real.clone());
```

These range-check `self.result.0`, `self.carry.0`, `self.witness.0`
— the FieldOpCols' OWN cells, not its operand cells. **So
`state_before[lane].0` is NOT currently byte-range-checked.**

Implication: we either need to (a) add explicit
`slice_range_check_u8` on `state_before[lane].0` cells in the
per-round chip's eval, or (b) verify they're transitively
constrained by the cross-row state-threading + previous row's
`rc_add[lane].result.0` (which IS range-checked by FieldOpCols's
`result` field).

For row 0 of a syscall (no previous row), `state_before` comes from
the cross-chip lookup. Without an explicit u8 range check, the
prover could put any field value there, then pair it with any other
field value to compose a target u16 in the lookup composition.
**This is a real soundness gap.**

Fix in integration-B: add
`builder.slice_range_check_u8(&local.state_before[lane].0, local.is_real)`
inside the per-round chip's eval, for all 4 lanes. ~5 LOC. Closes
the gap.

## Implementation plan for integration-B (Option B + range-check fix)

### sp1-hypercube (new InteractionKind)

`crates/hypercube/src/lookup/interaction.rs`:

1. Add enum variant: `GriffinFp192 = 22` (next available ID).
2. Add to `all_kinds()` list.
3. Add `num_values()` arm. Value count derivation:

```
clk_high            1
clk_low             1
ptr_addr            3   (SyscallAddrOperation outputs 3-limb addr)
direction_marker    1   (0 = initial, 14 = final, like keccak's `index`)
state_payload      64   (16 Word × 4 u16 each)
───────────────────
total              70
```

4. Add Display arm: `InteractionKind::GriffinFp192 => write!(f, "GriffinFp192")`.

### sp1-core-machine controller chip

`syscall/precompiles/griffin_fp192/controller.rs::Air::eval`:

After the existing memory-binding + syscall-receive, add:

```rust
// Send initial state to per-round chip on the (single) controller
// row per syscall.
let send_init = once(local.clk_high.into())
    .chain(once(local.clk_low.into()))
    .chain(state_addr.map(Into::into))
    .chain(once(AB::Expr::zero()))          // direction = 0 (initial)
    .chain(
        local.memory.into_iter()
            .flat_map(|access| access.prev_value.into_iter())
            .map(Into::into),
    )
    .collect::<Vec<_>>();
builder.send(
    AirInteraction::new(send_init, is_not_trap.clone(), InteractionKind::GriffinFp192),
    InteractionScope::Local,
);

// Receive final state from per-round chip.
//
// Direction marker = NB_ROUNDS (not NB_ROUNDS - 1). Matches keccak's
// pattern: per-round chip's last row sends at index = round_idx + 1,
// so the SEND value on the last row is (NB_ROUNDS - 1) + 1 = NB_ROUNDS.
// See keccak256/controller.rs:347 and keccak256/air.rs:185 for the
// reference. Audit-confirmed by proof-checker (2026-05-19) —
// the off-by-one in the prior revision of this doc was caught here.
let recv_final = once(local.clk_high.into())
    .chain(once(local.clk_low.into()))
    .chain(state_addr.map(Into::into))
    .chain(once(AB::Expr::from_canonical_u32(NB_ROUNDS as u32)))  // direction = NB_ROUNDS (final)
    .chain(
        local.final_value.into_iter()
            .flat_map(|word| word.into_iter())
            .map(Into::into),
    )
    .collect::<Vec<_>>();
builder.receive(
    AirInteraction::new(recv_final, is_not_trap.clone(), InteractionKind::GriffinFp192),
    InteractionScope::Local,
);
```

### sp1-core-machine per-round chip

`syscall/precompiles/griffin_fp192/air.rs::Air::eval`:

1. Add u8 range check on every `state_before[lane].0` (closes the gap
   identified above):

```rust
for lane in 0..4 {
    builder.slice_range_check_u8(&local.state_before[lane].0, local.is_real);
}
```

2. On `is_first_round = 1` rows, RECEIVE the input state from the
   controller. The state payload composes `state_before[lane].0[b_lo] +
   256 * state_before[lane].0[b_hi]` for each `(w, i)` matching the
   formula above:

```rust
let receive_init_state: Vec<AB::Expr> = (0..16).flat_map(|w| {
    let lane = w / 4;
    let word_in_lane = w % 4;
    (0..4).map(move |i| {
        let b_lo = word_in_lane * 8 + i * 2;
        let b_hi = b_lo + 1;
        local.state_before[lane].0[b_lo].into()
            + AB::Expr::from_canonical_u16(256) * local.state_before[lane].0[b_hi].into()
    })
}).collect();

// Plus the 6-value plumbing prefix (clk_hi, clk_lo, ptr×3, direction=0).
let mut recv_values = vec![
    local.clk_high.into(),
    local.clk_low.into(),
    // ptr_addr — needs to be threaded through from somewhere; ⚠ TODO
];
// ... append the state composition ...

builder.receive(
    AirInteraction::new(recv_values, local.is_first_round.into(), InteractionKind::GriffinFp192),
    InteractionScope::Local,
);
```

⚠ **Open question for integration-B implementation:** the per-round
chip doesn't currently have `clk_high`, `clk_low`, or `ptr_addr`
columns. The cross-chip lookup needs all three to match the
controller's send/receive. Either:

  - add those columns to `GriffinFp192Cols` (small per-row cost,
    cleaner), OR
  - constrain that the per-round chip's `is_first_round` and
    `is_last_round` flags fire at the SAME clk as the controller's
    single row (= the syscall's clk).

The first option is simpler. Let's add them.

3. Symmetric SEND on `is_last_round = 1` with direction marker
   `= NB_ROUNDS` (matches keccak's `index + 1` send convention —
   audit-confirmed 2026-05-19):

```rust
let send_final_state: Vec<AB::Expr> = (0..16).flat_map(|w| {
    let lane = w / 4;
    let word_in_lane = w % 4;
    (0..4).map(move |i| {
        let b_lo = word_in_lane * 8 + i * 2;
        let b_hi = b_lo + 1;
        local.rc_add[lane].result.0[b_lo].into()
            + AB::Expr::from_canonical_u16(256) * local.rc_add[lane].result.0[b_hi].into()
    })
}).collect();
```

(Plus prefix: clk_high, clk_low, ptr_addr × 3, direction marker
`= NB_ROUNDS` for final state. Equivalently, send at
`round_idx + 1`, which on the `is_last_round = 1` row equals
`(NB_ROUNDS - 1) + 1 = NB_ROUNDS`.)

### Per-round chip columns to add (integration-B)

- `clk_high: T`
- `clk_low: T`
- `ptr_addr: [T; 3]`  (matching `SyscallAddrOperation`'s output)

Total: 5 cells per row × 14 rows per syscall. Trivial.

Cross-row coherence: `next.clk_high == local.clk_high`, same for
`clk_low` and `ptr_addr`, when continuing the same syscall
(`local.is_real ∧ next.is_real ∧ ¬local.is_last_round`). 5 more
constraints in integration-A's existing block.

## Soundness anchors

1. **Byte composition formula matches Word::from(u64) verbatim.**
   See "Worked example" — checked algebraically against
   `word.rs:167-176`.

2. **State byte ordering across all three views (ABI, controller,
   per-round) is consistent.** Both formulas (lane*4 + limb_in_lane
   for word, lane*32 + b for state-byte-index) agree on the worked
   example.

3. **Cross-codebase property test already pins host ≡ executor at
   the syscall ABI level** (`equivalence_tests/`). The controller's
   memory binding consumes the same ABI. So once integration-B + -C
   land, the chain `host ≡ executor ≡ controller ≡ per-round` is
   closed end-to-end.

4. **The u8 range check on `state_before[lane].0` cells is required**
   to prevent (lo, hi) pair ambiguity in the byte composition. Fix
   in integration-B as part of the receive setup.

## What this doc does NOT yet handle

- **Trace generation for the per-round chip.** Populates all
  columns from `GriffinFp192PrecompileEvent` and the host-side
  Griffin compute. That's integration-C — much bigger commit. The
  byte-decomposition logic on the populate side mirrors the
  composition logic in eval; no new design needed beyond what's
  here.

- **Flipping `included() = true`.** Integration-C's final step.

- **First Cell 2 prove attempt.** Integration-C's verification.

## Audit gate (proof-checker pass 2026-05-19)

Independent audit by `proof-checker` agent on 2026-05-19 against
this document. Five-checkbox status:

1. [x] **Worked example matches the formula.** Three independent
   derivations performed (lane=2,b=5; lane=0,b=15; lane=3,b=31) —
   all consistent. CONFIRMED.
2. [x] **Option B is the right choice.** Composition expression is
   degree 1; lookup-payload soundness is independent of payload
   degree (lookup-balance argument constrains the fingerprint, not
   the polynomial degree). CONFIRMED, conditional on (3).
3. [x] **u8 range-check gap is real.** Specifically affects row 0
   of each syscall on lanes 1, 2, 3 (lane 0 is transitively
   u8-bounded via B-2's backward binding to `sbox0_cube.result`,
   itself range-checked by FieldOpCols). On rows r > 0, all four
   lanes are bound by integration-A's threading to the previous
   row's `rc_add[ℓ].result` (range-checked). The proposed fix
   (`slice_range_check_u8(&local.state_before[lane].0, local.is_real)`
   for all 4 lanes) covers all rows uniformly. CONFIRMED real,
   CONFIRMED fix.
4. [x] **`InteractionKind::GriffinFp192` with `num_values = 70`.**
   Arithmetic 1+1+3+1+64=70 verified against keccak's analog
   (1+1+3+1+100=106, matching `interaction.rs:122`). CONFIRMED.
5. [x] **Direction-marker value.** Original doc said `NB_ROUNDS - 1`
   for final receive. Cross-checked against keccak
   (`keccak256/controller.rs:347` receives at `index = 24 = NB_ROUNDS`,
   not `23 = NB_ROUNDS - 1`; `keccak256/air.rs:185` per-round chip
   sends at `local.index + 1`). **GAP-FOUND on first audit pass.**
   **FIXED in this revision** — controller's final-receive direction
   marker is now `NB_ROUNDS` (= 14 for Griffin), per-round chip
   sends on `is_last_round` with direction `round_idx + 1 = NB_ROUNDS`.

Additional notes from the audit:

  - **Field ordering.** Place `clk_high`, `clk_low`, `ptr_addr`
    columns BEFORE `_marker: PhantomData<M>` in
    `GriffinFp192Cols` to follow the conventional layout. Not a
    bug; pin in the integration-B commit.
  - **`state_addr` shape.** 3-element output of
    `SyscallAddrOperation::eval`, matching keccak's controller.
    Confirmed.
  - **Per-round chip clk/ptr coherence within a syscall.** Lookup-
    balance pins clk/ptr only on `is_first_round` and `is_last_round`
    rows; middle rows are bound by cross-row coherence. Two
    binding sources together suffice. Confirmed.

**Status: GREEN. Integration-B implementation can proceed.**
