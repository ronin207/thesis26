# Phase 3d-stage-3 — Next-session resumption note

**Written:** end of 2026-05-18 session, after 15 stage-3 commits.

This note exists so the next session can pick up without re-deriving
the design decisions that were in flight when we stopped.

## Where we stopped

The per-round chip (`GriffinFp192Chip`) is **algebraically complete**:
all B-x per-round constraint families (B-1 through B-5 plus B-8)
plus cross-row threading (integration-A) are landed and pass clippy
on the SP1 fork.

The controller chip (`GriffinFp192ControlChip`) is **memory-binding
complete** (B-7a + B-7b): syscall pointer arithmetic,
per-word address arithmetic, page-prot, 16-word memory R/W binding,
syscall-receive token from `SyscallChip`, full trace generation
populating columns from `GriffinFp192PrecompileEvent`. The chip is
registered in `RiscvAir` and the cost-table.

**`included()` returns `false` on BOTH chips.** Activating them now
would fire interaction-balance failures because the cross-chip
lookup between controller and per-round (integration-B) is not yet
wired.

## What remains for stage-3

### Integration-B — cross-chip lookup between controller and per-round

**Scope.** Bind the controller's memory `prev_value` (input state read
from `arg1`) to the per-round chip's `state_before` on `is_first_round=1`
rows; bind the per-round chip's `rc_add[ℓ].result` on
`is_last_round=1` rows to the controller's `final_value` (output state
written to `arg1`).

**The design decision we paused on: representation reconciliation.**
The two chips use different limb formats for the same 128-byte state:

| Chip | Representation | Why |
|---|---|---|
| Controller (`GriffinFp192ControlChip`) | `MemoryAccessCols<T>` × 16, each holding a `Word<T>` (= 4 u16-ish limbs per u64) | SP1's standard memory access pattern |
| Per-round (`GriffinFp192Chip`) | `Limbs<T, U32>` × 4 (each lane = 32 u8 limbs) | `FieldOpCols<T, Fp192FieldParams>` requires `Limbs<T, P::Limbs>` |

For the cross-chip lookup to bind state contents (not just clk/ptr),
the payload must encode the 128-byte state in a way both chips can
constrain against their respective columns.

**Two design options, neither tried yet:**

  **Option 1 — Refactor per-round state to Word<T>.**
  Change `state_before: [Limbs<T, U32>; 4]` to a Word-quartet
  representation. **Rejected:** breaks every B-1..B-8 constraint
  that feeds `Limbs<T, U32>` into `FieldOpCols::eval` /
  `eval_with_polynomials`. Major rewrite, high risk.

  **Option 2 — Translation layer at the lookup boundary.**
  Send the controller's `memory[i].prev_value` as 64 cells (16 Words
  × 4 limbs). Receive on per-round side. Add 64 byte-equality
  constraints binding each Word u16-limb to two u8 limbs of the
  appropriate `state_before[lane].0[byte_idx]`. The mapping:

  ```
  memory[word_idx].prev_value[limb_idx]                     // controller
  ↔
  state_before[lane(word_idx)].0[byte_lo(word_idx, limb_idx)] +
    state_before[lane(word_idx)].0[byte_hi(word_idx, limb_idx)] * 256
  ```

  where `lane(word_idx) = word_idx / 4`,
        `byte_lo = (word_idx % 4) * 8 + limb_idx * 2`,
        `byte_hi = (word_idx % 4) * 8 + limb_idx * 2 + 1`.

  **Recommended.** But the bit-packing math needs to be worked out
  on paper with a worked example before coding — that's the first
  thing to do next session.

### Integration-C — trace generation + activation

**Three sub-tasks:**

1. **Trace generation for the per-round chip.** Populates all 9
   column families × 14 rows × N syscalls. The B-3 and B-4
   `eval_with_polynomials` calls require manual population: compute
   the BigUint result for the polynomial expression, then call
   `FieldOpCols::populate_carry_and_witness` directly (the standard
   `populate` only handles binary Add/Sub/Mul/Div).

2. **Flip `included()` to `true`** on both chips conditional on
   `!shard.get_precompile_events(SyscallCode::GRIFFIN_FP192_PERMUTE).is_empty()`.

3. **Cell 2 prove attempt.** Run `PLUM_HOST_MODE=prove
   PLUM_PROVE_ARM=syscall cargo run --release --bin plum_host`.
   Expected: either real prove-gen time (the thesis's first
   goal-aligned measurement) or a failure that surfaces a stage-3
   bug. Probably memory-pressured on 24GB.

## What's settled and write-able right now

If a parallel writing track makes sense, these sections of the
thesis are settled and could be drafted while implementation
continues:

- **Problem statement + motivation** — Sako's A→B template, the
  field-mismatch overhead, why PQ-in-zkVM is currently impractical.
- **Phase 1+2+A results** — 38% SP1 / 70% RISC0 cycle reduction on
  UINT256_MUL; soundness argument in
  `docs/precompile_soundness/uint256_mul_for_fp192.md`.
- **Cell 1 infeasibility evidence** — three OOM-kill attempts of
  PLUM-80 with rv32im-emulated Griffin on M5 Pro 24GB; SP1's own
  watchdog warned at 88.96% memory in 86 seconds.
- **Phase 3f execute-cycle delta** — 56× reduction at execute-mode
  (124M vs 6.96B cycles for syscall vs emulated arms). Useful as
  upper bound on what stage-3 prove-time can claim.
- **Audit findings A-1..A-4** — all closed or mitigated (A-1 closed
  by B-8 just tonight).
- **Stage-3 soundness rubric** — `docs/precompile_soundness/griffin_fp192.md`
  with B-1..B-10 each at IMPLEMENTED or PARTIALLY IMPLEMENTED status.

What's NOT yet write-able:
- Cell 2 prove-gen time — depends on integration-C.
- "Practically acceptable" threshold — operator decision.
- Final four-cell evaluation table.
- Conclusion / future work.

## First action next session

Spend 15 minutes on paper / whiteboard working out the byte-packing
mapping for Option 2 above. Then encode it in integration-B.
