# Phase 3 — Griffin Fp192 AIR implementation plan

**Status**: Phase 3a complete (SP1 fork wired). Phases 3b–3f are the
multi-week climb. This document is the execution roadmap for those
sessions so each one doesn't have to rediscover the architecture.

**Goal**: Cut PLUM-80 proof-gen time from 6 h 19 m (current on M5 Pro
24 GB with Phase 1+2+A precompile suite) to roughly 1 h or less by
moving Griffin permutations from emulated rv32im execution to a
custom AIR chip in our SP1 fork.

**Why this is the right target**: Per-phase verify attribution
measurement (2026-05-17, `per_phase_attribution_across_security_levels`
test) shows ~94 % of Fp192::mul invocations and ~100 % of verify wall
clock concentrate in Step 2 + STIR, which is dominated by Merkle
hash compressions (936 hashes × 129,833 cyc = 121.5 M verify cycles
for PLUM-80 on RISC0). Griffin is the hash. Targeting it directly is
the only remaining lever for an order-of-magnitude reduction.

---

## Architectural model (no SP1 redesign)

We are filling SP1's documented "precompile plugin slot", not
modifying SP1's architecture. SP1's STARK proof system, ISA, executor,
existing precompiles, SDK API, and toolchain stay identical to
upstream v6.2.1.

Net diff to SP1: ~5–8 files modified, ~300–500 lines added. Most
additions live in a new directory
(`crates/core/machine/src/syscall/precompiles/griffin_fp192/`); the
existing-file changes are mostly enum variant additions and chip
registration lines.

---

## Phase 3 sub-phases

### Phase 3a — Fork setup *(✅ complete)*

- SP1 submodule pinned at v6.2.1 (commit `98a376e8`).
- `[patch.crates-io]` in `platforms/zkvms/sp1/Cargo.toml` overrides
  every sp1-* crate to the local checkout.
- Verified: `cargo check --release` in `platforms/zkvms/sp1/script/`
  compiles cleanly against the fork.

### Phase 3b — Griffin chip skeleton *(scaffolding only, no constraints)*

Create `submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/`:

- `mod.rs` — declare `air`, re-export `GriffinFp192Chip`. Add a `tests`
  module (currently empty; populated in Phase 3f).
- `air.rs` — define:
  - `GriffinFp192Chip<M: TrustMode>` struct (mirror `Uint256MulChip`).
  - `GriffinFp192Cols<T, M: TrustMode>` column struct with
    `#[derive(AlignedBorrow)]`. Columns at minimum:
    - `clk_high`, `clk_low` (syscall clock)
    - `state_ptr: SyscallAddrOperation<T>` (pointer to 4×Fp192 state)
    - `state_addrs: [AddrAddOperation<T>; 4]` (per-Fp192 address derivation)
    - `state_memory: GenericArray<MemoryAccessColsU8<T>, ...>` (read+write)
    - `is_real: T`
    - Per-round S-box columns (4 lanes × 14 rounds × 2 muls for x³)
    - Per-round linear-layer columns (4 lanes × 14 rounds, matrix-mul accumulators)
    - Round-constant addition columns (4 lanes × 14 rounds)
    - `address_slice_page_prot_access` columns (TrustMode-conditional)
  - Stub `MachineAir`, `BaseAir`, `Air`, `Syscall` impls — `eval` body
    can be `builder.assert_zero(local.is_real)` as a placeholder so
    the chip can register cleanly. `included()` returns `false` so
    the empty trace is never assembled.
- Estimated time: ~2 hours.

### Phase 3c — Register syscall + chip *(plumbing only)*

Three SP1 source files to patch:

1. `crates/core/executor/src/syscall_code.rs`:
   - Add `SyscallCode::GRIFFIN_FP192_PERMUTE = 0x00_01_01_<picked unique value>` variant.
   - Add the value to the `from_u32` match.
   - Add `GRIFFIN_FP192_PERMUTE => RiscvAirId::GriffinFp192` mapping (plus the User-mode variant if needed).

2. `crates/core/executor/src/events/precompiles/mod.rs`:
   - Add `PrecompileEvent::GriffinFp192(GriffinFp192Event)` variant.
   - Define `GriffinFp192Event` struct with the event data (input state, output state, memory records).
   - Add the variant to `get_local_mem_events` match arm.

3. `crates/zkvm/entrypoint/src/syscalls/`:
   - Add `griffin_fp192.rs` with the user-facing `extern "C" fn
     syscall_griffin_fp192_permute(state: *mut [u64; 16])` (4 Fp192
     elements × 4 u64 limbs each = 16 u64 = 128 bytes).
   - Re-export from `syscalls/mod.rs`.

Plus the machine config registers the new chip alongside existing
precompiles.

Estimated time: ~2 hours.

### Phase 3d — Implement Griffin AIR constraints *(THE multi-week work)*

This is the deep work. Encode Griffin's permutation as algebraic
constraints over the AIR's columns. Reference:
- `src/primitives/hash/griffin_p192.rs` — Rust reference implementation
- Griffin paper (Grassi et al., CRYPTO 2023) — the original construction
- CLAUDE.md `references/` — Loquat paper §5 has Griffin instantiation discussion

Structure of the permutation (from `griffin_p192.rs`):

- **State**: 4 Fp192 elements. PLUM uses width-4 for compression, width-3 for expansion. We target width-4 only (the dominant cost; expansion is rarer).
- **S-box**: x³ for d=3. Two multiplications per S-box: `x² = x*x`, `x³ = x²*x`. Constraint:
    ```
    sq[i] = state[i] * state[i]
    cb[i] = sq[i] * state[i]
    ```
- **Linear layer**: matrix-multiply with small fixed coefficients (Griffin's specific 4×4 MDS matrix). Mostly additions and shifts; some constant scalings.
- **Round constants**: precomputed via SHAKE256 from the round-key generation procedure in `griffin_p192.rs::compute_round_constants`. Treat as fixed constants in the AIR (lookup table or unrolled).
- **Round count**: 14 rounds (the formula `get_number_of_rounds` evaluates to 14 at λ=128 for d=3).

Total constraint count budget (rough): 14 rounds × (4 S-box × 2 muls + 4×4 matrix mul + 4 const adds) = 14 × 28 = ~400 mul-like constraints per permutation, plus the memory-access binding (~32 byte accesses × 8 columns).

Implementation order:
1. Hardcode round constants (compute via SHAKE256, paste into a const array).
2. Encode one round of S-box + linear layer.
3. Replicate × 14 rounds.
4. Add memory binding (read 4 Fp192, write 4 Fp192).
5. Add output range check (`< p`) on each output Fp192 limb.

Estimated time: **4–6 weeks**. Most of the time is debugging
constraint vs reference mismatches via small test vectors.

### Phase 3e — Wire vc-pqc griffin_p192 to syscall

In `src/primitives/hash/griffin_p192.rs::plum_griffin_permutation_raw`,
add a third cfg branch (alongside existing host fallback and any
future risc0 path):

```rust
#[cfg(all(target_os = "zkvm", feature = "sp1"))]
{
    unsafe {
        sp1_zkvm::syscalls::syscall_griffin_fp192_permute(
            state.as_mut_ptr() as *mut [u64; 16],
        );
    }
    return;
}
```

This is one of the smaller changes — maybe 20 lines.

Estimated time: ~30 minutes.

### Phase 3f — Build + measure

1. Rebuild SP1 program (the guest ELF).
2. Run `PLUM_HOST_MODE=execute ./target/release/plum_host` — confirm
   cycle count drops vs the 179,952,920 Phase-1+2+A SP1 baseline.
   Target: ~20–40 M cycles (90 %+ reduction).
3. Run `PLUM_HOST_MODE=prove` — measure real proof-gen wall clock.
   Target: ≤ 30 min on M5 Pro 24 GB (vs current 6h19m on RISC0).
4. Run `PLUM_HOST_MODE=adversarial` — confirm soundness still holds
   (all 7 tamper cases reject).
5. Mirror to RISC0 once SP1 is validated.

Estimated time: ~1 day.

---

## Soundness argument outline (write up after 3d completes)

`docs/precompile_soundness/griffin_fp192_air.md` should argue:

1. **Functional correctness reduction**: each constraint in
   `griffin_fp192/air.rs::eval` implements one step of the Griffin
   reference permutation in `griffin_p192.rs`. Walk through the
   correspondence S-box ↔ x² + x*x²,  matrix layer ↔ field-add chain,
   round constants ↔ AIR constants.
2. **Memory binding**: the AIR's `state_memory` access columns are
   constrained by SP1's standard memory-checking framework
   (`MemoryAccessColsU8` + `AddressSlicePageProtOperation`); we
   inherit memory-binding soundness from SP1's existing audit.
3. **Output range check**: each output Fp192 element constrained
   `< MODULUS_LIMBS`, ensuring canonicality for downstream callers.
4. **Cross-precompile contract**: the Griffin chip produces canonical
   Fp192 outputs, satisfying the operand-canonicality precondition
   of the UINT256_MUL chip our Phase 1 already uses (see existing
   `uint256_mul_for_fp192.md` §"Composability").
5. **Adversarial probe**: re-run the 7-case probe with Griffin AIR
   active; all-pass is empirical confirmation.

---

## Risks and mitigations

- **Risk**: SP1's chip framework changes between v6.2.1 and a future
  release we want to upgrade to. **Mitigation**: pin v6.2.1 throughout
  the thesis; defer upgrade to post-defence.
- **Risk**: round-constant computation in the AIR is expensive (16
  bytes × ~14 rounds × 4 lanes of SHAKE256 derivation). **Mitigation**:
  hardcode the constants as a fixed table — they're deterministic and
  never change.
- **Risk**: Griffin AIR row count is too large for SP1's per-shard
  capacity. **Mitigation**: shard-friendly construction (each
  permutation fits in one row × ~50 columns; 977 permutations per
  PLUM verify = ~977 rows; well within SP1's shard size).
- **Risk**: constraint debugging takes longer than 4–6 weeks because
  Griffin semantics + SP1 AIR DSL is unfamiliar territory.
  **Mitigation**: build incrementally (one round, then unroll); use
  the existing `griffin_p192.rs` Rust impl as a per-step oracle in
  unit tests.

---

## Out of scope for Phase 3

- RISC0/Zirgen port of the Griffin AIR — defer until SP1 version
  stabilises and ships
- Expansion-mode Griffin (width-3) — only width-4 (compression) is on
  the verify hot path
- Optimisations beyond first-working version (e.g. trace packing,
  bitwise S-box, fused linear layer)
- ZK property analysis — per CLAUDE.md, ZK is out of scope for the
  thesis

---

## Verification checklist (gate before considering Phase 3 done)

- [ ] SP1 fork compiles cleanly with Griffin chip registered (Phase 3b/3c done)
- [ ] One Griffin permutation, run via syscall, matches `griffin_p192.rs` reference output (Phase 3d unit test)
- [ ] PLUM-80 verify cycle count drops from 179,952,920 to ≤ 40,000,000 (Phase 3f executor)
- [ ] PLUM-80 real proof-gen wall clock ≤ 1 hr on M5 Pro 24 GB (Phase 3f prove)
- [ ] Adversarial probe 7/7 PASS with Griffin AIR active (Phase 3f)
- [ ] Soundness arg written and proof-checker-audited (`docs/precompile_soundness/griffin_fp192_air.md`)
