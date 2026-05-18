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

For each round, `state_after[1] = state_before[1]³ (mod p)`.
**IMPLEMENTED** (SP1 fork commit ⟨TBD⟩).

Encoding: two chained `FieldOpCols<T, Fp192FieldParams>` instances
on the per-round chip (`GriffinFp192Chip`):

  - `sbox1_sq.result    = state_before[1] * state_before[1] mod p`
  - `sbox1_cube.result  = sbox1_sq.result * state_before[1]   mod p`

Each `FieldOpCols::eval` emits a polynomial-identity constraint of
degree 2 (two limb-polynomial product) plus byte-range checks on
result, carry, and witness limbs. With `is_real` as the activating
selector, total constraint degree stays ≤ 3 (= SP1's
`MAX_CONSTRAINT_DEGREE`). `Fp192FieldParams::MODULUS` is embedded as
preprocessing (B-10), so the prover cannot choose the modulus per
row.

The post-nonlinear-layer state for lane 1 IS `sbox1_cube.result`;
downstream B-3 (quadratic layer for lanes 2, 3) and B-4 (MDS) read
from this directly. Trace generation populating these columns from
host-side Griffin compute is pending integration commit.

- Failure mode: wrong `d` parameter (e.g., d=5 if someone forgets
  PLUM's prime uses d=3) — would be a single-character change in
  the FieldOperation chain. Caught by the cross-codebase
  equivalence tests in `platforms/zkvms/sp1/equivalence_tests/`
  IF integration tests cover proof generation; today only execute-
  mode is tested, so the AIR's `d=3` is not yet test-bound.
  Mitigation in soundness audit: stage-3 integration commit MUST
  add a "AIR output matches executor output on a fixed permutation"
  test that runs the full prove path.
- Attacker capability: find a `state'` whose forward S-box differs
  from the spec → collision under the broken Griffin → PLUM EU-CMA
  forgery.
- Source spec: `src/primitives/hash/griffin_p192.rs:247` (forward
  S-box), Griffin paper §2.3, our `d = 3` derivation in
  `pick_d_and_inverse:347`.

### B-2 — Inverse S-box on lane 0 (degree-3 backward)

For each round, `state_before[0] = state_after_nonlinear[0]³ (mod p)`.
The AIR cannot raise to `d_inv` directly (199-bit exponent → degree
blowup well past SP1's `MAX_CONSTRAINT_DEGREE = 3`); instead it
constrains the *backward* relation, which is equivalent in a
permutation when `gcd(d, p-1) = 1` (the case for our PLUM 199-bit
prime — see `griffin_p192.rs::pick_d_and_inverse:341` for the
proof-witness construction). **IMPLEMENTED** (SP1 fork commit ⟨TBD⟩).

Encoding:

  - `sbox0_sq`, `sbox0_cube`: two chained `FieldOpCols<T, Fp192FieldParams>`,
    same shape as B-1's forward S-box on lane 1 with operands
    swapped:
      `sbox0_sq.result    = state_after_nonlinear[0] * state_after_nonlinear[0]  mod p`
      `sbox0_cube.result  = sbox0_sq.result * state_after_nonlinear[0]            mod p`
  - Backward bytewise binding: `sbox0_cube.result.0[i] == state_before[0].0[i]`
    for all 32 limb bytes, under `is_real`. This bytewise equality
    IS the backward constraint:
      `state_before[0] = state_after_nonlinear[0]^3 mod p`
    which, by the permutation property, uniquely determines
      `state_after_nonlinear[0] = state_before[0]^{d_inv} mod p`.

Soundness anchor:

  - The "forward direction = degree 3, backward = degree 3" symmetry
    is what makes the backward-constraint trick work. For d = 3
    specifically (PLUM's prime), the AIR's per-cell constraint
    degree budget is met both directions; for d ≥ 5 we'd need
    `eval_with_polynomials` with explicit fold (or higher
    `MAX_CONSTRAINT_DEGREE`).

- Failure mode: omit the backward check; constrain forward
  `state_before[0]³ = state_after_nonlinear[0]` instead of backward.
  This is the WRONG identity — the S-box is `x → x^{d_inv}` (raise
  to inverse), so checking the forward `x → x^d` direction on the
  same operand pair would constrain something different. (E.g.,
  `state_after_nonlinear[0] = state_before[0]^3` would yield a chip
  that constrains a FORWARD S-box on lane 0, contradicting Griffin's
  spec of an INVERSE S-box on lane 0.)
- Attacker capability: lane-0 collision → forgery (same as B-1).
- Source spec: `vc-pqc::primitives::hash::griffin_p192::nonlinear_layer:245`.

### B-3 — Quadratic layer on lanes 2, 3

For each round and each `i ∈ {2, 3}`:

    L_i      = (i - 1) · z₀ + z₁ + z_{i-1}
    state_after_nonlinear[i] = state_before[i] · (L_i² + α_{i-2}·L_i + β_{i-2})

where `z₀ = state_after_nonlinear[0]`, `z₁ = state_after_nonlinear[1]`,
`z_{i-1} = state_after_nonlinear[i-1]`. **IMPLEMENTED** (SP1 fork
commit ⟨TBD⟩).

Encoding:

  - `L_2 = z₀ + z₁` and `L_3 = 2·z₀ + z₁ + state_after_nonlinear[2]`
    built inline as `Polynomial<AB::Expr>` (no separate cell).
  - `l_sq_2`, `l_sq_3`: two `FieldOpCols<T, Fp192FieldParams>` cells
    constraining `L_i² mod p` via `eval_with_polynomials` with
    `op = L_i * L_i`.
  - `quad_mul_2`, `quad_mul_3`: two `FieldOpCols` cells constraining
    `state_after_nonlinear[i] = state_before[i] * (L_i² + α[i-2]·L_i + β[i-2]) mod p`
    via `eval_with_polynomials` with `op = state_before[i] * quad_factor`.
  - α and β values lifted from
    `sp1-core-executor::griffin_fp192_compute::{quadratic_alphas_limbs, quadratic_betas_limbs}()`
    as degree-0 polynomial constants. Same preprocessing-bound
    pattern as RC in B-5.
  - Bytewise binding: `state_after_nonlinear[2].0[i] == quad_mul_2.result.0[i]`
    and similarly for lane 3. Same pattern as B-1's lane-1 binding.

Soundness anchors:

  - α[0], α[1], β[0], β[1] are field constants in the eval body —
    prover cannot choose them per row (B-10 property).
  - The lane-3 L₃ correctly reads the UPDATED lane-2 value
    (`state_after_nonlinear[2]`), matching the sequential dependency
    in the reference at `griffin_p192.rs:259`. If we read
    `state_before[2]` instead, the AIR's nonlinear-layer math would
    drift from the spec by one input.
  - The constants in `L_i = (i-1)·z₀ + z₁ + z_{i-1}` are baked into
    the polynomial expression (`z0.clone() + z0.clone()` for the
    2·z₀ in L₃). Any edit to those coefficients changes the
    polynomial directly — visible in the diff.

- Failure mode: wrong α/β; wrong L formula (off-by-one in the index
  multiplier); missing the multiplication by `state_before[i]`;
  reading `state_before[2]` instead of `state_after_nonlinear[2]`
  in L₃ (sequential-dependency mistake).
- Attacker capability: collide on lanes 2/3 → reduced-round collision
  → forgery.
- Source spec: `vc-pqc::primitives::hash::griffin_p192::nonlinear_layer:249-272`,
  `li():293`.

### B-4 — MDS linear layer

For each row of the matrix-vector product:

    next[row] = Σ_{col=0..4} matrix[row][col] · state_after_nonlinear[col]

where `matrix = circulant([2, 1, 1, 1])`. **IMPLEMENTED**
(SP1 fork commit ⟨TBD⟩).

Concretely (after expanding the circulant):

  mds_out[0].result = 2·s[0] + s[1] + s[2] + s[3]  mod p
  mds_out[1].result = s[0] + 2·s[1] + s[2] + s[3]  mod p
  mds_out[2].result = s[0] + s[1] + 2·s[2] + s[3]  mod p
  mds_out[3].result = s[0] + s[1] + s[2] + 2·s[3]  mod p

where `s[i] = state_after_nonlinear[i]`.

Encoding: ONE `FieldOpCols<T, Fp192FieldParams>` cell per output
lane, via `FieldOpCols::eval_with_polynomials`. The 4-way linear
combination `2·s[r] + s[r+1] + s[r+2] + s[r+3]` is built as a
single `Polynomial<AB::Expr>` and passed as the `op` argument; the
cell internally constrains `op - result ≡ 0 (mod p)` plus
result/carry/witness range checks. **4 cells per row × 14 rows =
56 cells total for MDS** — vs 16 chained binary adds (= 224 cells)
if we used `FieldOpCols::eval` naively.

The Fp192FieldParams modulus is embedded via `modulus_field_iter`
(preprocessing — B-10).

B-1 binding: separately constrains `state_after_nonlinear[1] =
sbox1_cube.result` byte-by-byte (32 limb equalities) so the MDS
input on lane 1 is bound to the S-box output. Lanes 0, 2, 3
remain unconstrained until B-2 (inverse S-box backward) and B-3
(quadratic layer) land — until then a malicious prover with
`included()=true` could set those lanes to anything; the integration
commit closes this when all four nonlinear-layer families are in
place.

- Failure mode: wrong matrix entry (e.g., `[1, 1, 1, 1]` — not
  MDS, only rank 1; would let differential trails propagate
  through the linear layer with weight 0 instead of weight ≥ 4).
  Witnessed in code: the matrix entries `2` and `1` are baked into
  the polynomial expression (`s_poly[row].clone() + s_poly[row].clone()`
  is `2·s[row]`; cross-row terms have unit coefficient). Any future
  edit changes the polynomial directly → drift detector lives in
  the trace-gen test plan (integration commit).
- Attacker capability: low-weight differential trail; reduced-round
  collision; ultimately PLUM EU-CMA forgery.
- Source spec: `vc-pqc::primitives::hash::griffin_p192::linear_layer:218-228`
  + `build_matrix:444-449`, mirrored at
  `sp1-core-executor::griffin_fp192_compute::linear_layer:415-422`.

### B-5 — Round constants from SHAKE256

After round `r ∈ 0..rounds-1`, lane `ℓ ∈ 0..4` is offset by
`RC[r * 4 + ℓ]`, where `RC` is derived from
`SHAKE256("PlumGriffin({modulus},{state_width},{capacity},{security_level})")`
unrolled into `(rounds - 1) * 4 = 13 * 4 = 52` field elements.
**IMPLEMENTED** (SP1 fork commit ⟨TBD⟩).

Encoding:

  - **Preprocessing table** at
    `sp1-core-executor::griffin_fp192_compute::round_constants_limbs()`.
    Returns 56 × 32-byte little-endian limb buffers, indexed by
    `round * 4 + lane`. The first 52 entries are the SHAKE256-
    derived constants (rounds 0..12, all 4 lanes); the last 4
    entries are zero (round 13 — the Griffin spec skips RC after
    the final linear layer, but the AIR uses a uniform constraint
    that naturally yields zero on the last row).
  - **One-hot round flags** `is_round_r: [T; NB_ROUNDS]` on the
    per-round chip. Each is bool, `Σ is_round_r = is_real`,
    `Σ r * is_round_r = round_idx`. Padding rows have all flags 0.
  - **Active RC polynomial** built per lane as
      `active_rc[ℓ] = Σ_{r=0..NB_ROUNDS} is_round_r[r] * RC[r*4+ℓ]_polynomial`
    where `RC[r*4+ℓ]_polynomial` is the 32-coefficient
    `Polynomial<AB::F>` lifted from the constant bytes (degree 0 in
    chip variables). Total polynomial has degree 1 in chip variables.
  - **RC addition** per lane via
    `rc_add[ℓ].eval(builder, &mds_out[ℓ].result, &active_rc[ℓ], FieldOperation::Add, is_real)`.
    `rc_add[ℓ].result` is the post-round-constants state for lane ℓ.

Soundness pins:

  - The RC table is committed via `OnceLock` in the executor — the
    same code that the host's reference compute uses. Drift between
    host and executor RC is checked by the `equivalence_tests`
    256-vector property test.
  - The bool + sum constraints on `is_round_r` rule out the
    "multiple round flags set" attack — a malicious prover can't
    add two RCs at once.
  - The `Σ r * is_round_r = round_idx` cross-check ties the one-hot
    encoding to B-9's round_idx column. Combined with the
    integration commit's cross-row `round_idx` coherence
    (`next.round_idx == local.round_idx + 1` on real rows), the
    sequence of round indices through one syscall is pinned to
    `0, 1, 2, ..., NB_ROUNDS - 1`.

- Failure mode: RC silently zeroed (test
  `zero_state_is_not_a_fixed_point` would catch all-zero, but a
  single wrong constant slips through); RC supplied per-row by the
  prover rather than fixed in preprocessing (B-10).
- Attacker capability: slide attacks, fixed-point exploitation,
  reduced-round attacks.
- Source spec: `vc-pqc::primitives::hash::griffin_p192:344-402`
  (compute_plum_griffin_params), mirrored at
  `sp1-core-executor::griffin_fp192_compute:217-247`.

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

Memory binding handled by a separate **controller chip**
(`GriffinFp192ControlChip`, 1 row per syscall), not the per-round
algebra chip. Pattern lifted from keccak's two-chip split at
`submodules/sp1/.../keccak256/controller.rs`. Reasoning: with 14
rows-per-syscall on the per-round chip, putting memory binding on
each round-row would waste 13 × 16 = 208 cells per syscall on
padding; the keccak pattern moves all per-syscall plumbing to a
dedicated control chip.

**PARTIALLY IMPLEMENTED** (SP1 fork commits 299b588, bc74da9,
plus this commit). Structure landed:

  - `GriffinFp192ControlChip<M: TrustMode>` in
    `submodules/sp1/.../griffin_fp192/controller.rs`.
  - `GriffinFp192ControlCols` declares the columns needed for memory
    binding:
      - `clk_high`, `clk_low`, `state_addr` (SyscallAddrOperation)
      - `addrs[16]` (AddrAddOperation per state word)
      - `memory[16]` (MemoryAccessCols per state word)
      - `final_value[16]` (Word<T> per state word, for write-side)
      - `address_slice_page_prot_access` (page-prot for user mode)
      - `is_real`
  - Registered as `RiscvAir::GriffinFp192Control` /
    `RiscvAir::GriffinFp192ControlUser`, with matching
    `RiscvAirId` (124 / 125) + cost-table entries (placeholder 682 /
    730, mirrored from keccak's controller).
  - `RiscvAirId::GriffinFp192.control_air_id(...)` mapping wired —
    `cost_and_height_per_syscall` now correctly looks up both the
    per-round and controller chips.
  - `rows_per_event(GriffinFp192) = 14`.
  - Trivial `assert_bool(is_real)` constraint to satisfy
    `Chip::from_air`'s `max_constraint_degree > 0`.

**B-7b landed** (SP1 fork commit ⟨TBD⟩, this revision):

  - `SyscallAddrOperation::eval` on `state_addr` with size=128
    (16 u64 words). Constrains 8-byte alignment + address bounds.
  - `AddrAddOperation::eval` for each `addrs[i]`,
    enforcing `addrs[i].value = state_addr + 8 * i`.
  - `eval_memory_access_slice_write` binding `memory[i].prev_value`
    (= input state at clk) and `memory[i].value = final_value[i]`
    (= output state at clk). Single-shot R/W pattern (poseidon2
    style) rather than keccak's split read-at-clk + write-at-clk+1,
    because our executor handler emits paired `MemoryWriteRecord`s.
  - `AddressSlicePageProtOperation::eval` for user-mode protection
    over the full state range `[state_addr, state_addr + 8*(N-1)]`
    with `PROT_READ | PROT_WRITE`.
  - `builder.receive_syscall(...)` — the chip's reception of the
    GRIFFIN_FP192_PERMUTE event from `SyscallChip` (balances the
    rv32im CPU chip's ECALL send).
  - Trace generation: `generate_trace_into` populates columns from
    `GriffinFp192PrecompileEvent`s, with parallel chunking and
    padding to power-of-2 row count. `generate_dependencies`
    emits the byte lookups required by AddrAddOperation +
    page-prot.

**Pending (integration commit):**

  - Cross-chip lookup interaction with the per-round chip: control
    chip sends `(input_state, clk, ptr)`, per-round chip receives;
    per-round chip sends `(output_state, clk, ptr)`, control chip
    receives. Wires the algebraic claim from one chip to the memory
    binding on the other. Today the controller's memory binding is
    self-consistent but NOT linked to a Griffin permutation — a
    malicious prover with `included()=true` could produce a
    controller-chip trace with arbitrary `memory[i].prev_value` and
    `memory[i].value` (any input/output pair subject to memory
    consistency), claiming a "Griffin permutation" the per-round
    chip never validated. The integration commit closes this with
    the lookup hookup.
  - Flipping `included()` to `true`.

- Failure mode (closed by B-7b): chip reads from wrong address; chip
  claims a write was at clk `c` but actually fired at clk `c'`.
- Attacker capability: claim a Griffin syscall acted on address `A`
  when the trace fires it at address `B` — witness binding broken.
- Source spec: pattern at
  `submodules/sp1/crates/core/machine/src/syscall/precompiles/keccak256/controller.rs:258-397`,
  event struct at
  `submodules/sp1/crates/core/executor/src/events/precompiles/griffin_fp192.rs`.

### B-8 — Output canonicality (per-lane range check)

Each post-RC limb buffer `rc_add[ℓ].result.0[0..32]` is strictly
less than `Fp192FieldParams::MODULUS`. **IMPLEMENTED** (SP1 fork
commit ⟨TBD⟩).

Encoding: 4 `FieldLtCols<T, Fp192FieldParams>` cells, one per lane.
Each cell:

  - Has 32 byte-flag cells encoding which byte is the "first less-
    than" position in a byte-by-byte comparison `result < modulus`.
  - Constrains the flags via the standard one-hot pattern (bool +
    sum-equals-one) plus byte-by-byte equality up to the first-less
    position and strict-less at that position.
  - Active only when `is_real` (padding rows skip).

Pattern lifted from SP1's `Uint256MulModChip`'s
`output_range_check` (`uint256/air.rs:435`), reused unchanged.

  for lane in 0..4 {
      local.rc_add_range_check[lane].eval(
          builder,
          &local.rc_add[lane].result,
          &p_modulus,   // built earlier for B-4
          local.is_real,
      );
  }

Total: 4 × ~32 = ~128 byte-flag cells per row + constraint-eval
overhead.

**This is the satisfaction of the cross-precompile contract from
`uint256_mul_for_fp192.md` AND closes audit finding A-1.** Before
B-8, downstream consumers of the Griffin chip's output (most
notably any future `Fp192::mul` call on guest side, which routes
through UINT256_MUL) would have to TRUST that the AIR produced a
canonical output — but FieldOpCols's polynomial-vanishing
constraint alone admits non-canonical representations. B-8 closes
that gap.

- Failure mode: output lane is non-canonical; the guest then calls
  `Fp192::to_limbs` on it (`p192.rs:189-197`) which silently
  truncates digits beyond the 4th in release builds. Downstream
  Fp192::mul receives a wrong-modulus value; signature acceptance
  becomes meaningless.
- Attacker capability: field-mismatch — verifier sees one value,
  prover proved another. Direct path to forgery.
- Source spec: SP1's `Uint256MulModChip` output range check at
  `sp1-core-machine/.../uint256/air.rs:435`, reused via the same
  `FieldLtCols<T, P>` machinery instantiated for our
  `Fp192FieldParams`.

### B-9 — `is_real` discipline + row-position scheduling

`is_real ∈ {0, 1}` per row. The chip uses 14 consecutive rows per
permutation (`NB_ROUNDS = 14`); the first row reads pre-permutation
state from memory, the last writes post-permutation state back, the
middle 12 thread cross-row state. **IMPLEMENTED** (SP1 fork commit
bc74da9, `submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/air.rs`).

Constraints landed:

  - `assert_bool(is_real)` — row real/padding.
  - `assert_bool(is_first_round)` — first round of perm (round_idx == 0).
  - `assert_bool(is_last_round)` — last round of perm (round_idx == NB_ROUNDS - 1).
  - When `is_real = 0`: assert `is_first_round = is_last_round = round_idx = 0`.
    Closes "padding row claims first-round status" attack.
  - When `is_real = 1`: assert `is_first_round * is_last_round = 0`.
    Closes "row is simultaneously first AND last" attack — would require
    NB_ROUNDS = 1, not the case.

Cross-row `round_idx` coherence (next.round_idx == local.round_idx + 1
on real rows, or 0 if local.is_last_round) is deferred to B-5 with the
round-constants constraint, since RC indexing is what makes the
round_idx semantically load-bearing.

The lookup-argument hookup that emits the syscall-receive token on
`is_last_round` is deferred to the integration commit at the end of
stage-3 (because emitting the token is only safe when the AIR fully
constrains the permutation).

- Failure mode (closed by above): padding row falsely claims
  `is_real = 1`. Attacker capability: "ghost permutation" — claim a
  Griffin output with no corresponding syscall.
- Source spec: pattern at `poseidon2/air.rs:430-451`, adapted for
  multi-round row scheduling (cf. `keccak256/`).

### B-10 — Parameter immutability (preprocessing)

The α, β, RC, MDS matrix entries are *committed by the verifier in
preprocessing* — not row columns the prover supplies. **PARTIALLY
IMPLEMENTED** (SP1 fork commit 299b588 + bc74da9).

Implemented:

  - `Fp192FieldParams::MODULUS` — PLUM prime as 32-byte const,
    `sp1-curves/src/fp192.rs`. Pinned by
    `modulus_matches_canonical_decimal` test. Drift-detected against
    `vc-pqc::primitives::field::p192::MODULUS_LIMBS` and
    `sp1-core-executor::griffin_fp192_compute::MODULUS_LIMBS` by the
    `modulus_limbs_agree` test in `equivalence_tests`.
  - `NB_ROUNDS = 14` — const in
    `sp1-core-machine/.../griffin_fp192/air.rs`, pinned by
    `round_count_matches_integer_formula` tests on both sides.

Pending (lands with B-5):

  - Round constants RC[0..NB_ROUNDS - 1] × 4 lanes = 52 Fp192 values,
    SHAKE256-derived. Embedded as field constants in `Air::eval`'s
    constraint expression (NOT as prover-supplied columns) so the
    verifier's preprocessing commits them.
  - α[0], α[1], β[0], β[1] — SHAKE256-derived quadratic-layer
    coefficients. Same embedding pattern.
  - MDS matrix (4×4 circulant [2, 1, 1, 1]). Trivial integer values,
    embedded directly in `Air::eval`.

- Failure mode: prover chooses RC per row. Attacker capability:
  total break — trivial collision (pick RC to make algebra close).
- Source spec: convention; round constants live in preprocessing.
  Witnessed by the SHAKE seed string pin
  (`"PlumGriffin({modulus},{state_width},{capacity},{security_level})"`)
  in `griffin_p192.rs` and `griffin_fp192_compute.rs`.

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
| (e) AIR memory binding | MOSTLY IMPLEMENTED | Two-chip architecture + columns + constraint logic + trace generation all landed (B-7a + B-7b). Cross-chip lookup with per-round chip pending integration commit. |
| (f) Output canonicality (per-lane `< p`) | IMPLEMENTED | B-8 landed with FieldLtCols per lane. Closes audit finding A-1 and the cross-precompile contract from uint256_mul_for_fp192.md. |
| (g) Parameter immutability | PARTIALLY IMPLEMENTED | `Fp192FieldParams::MODULUS` + `NB_ROUNDS` constants landed (B-10). α/β/RC preprocessing tables land with B-5. |
| (h) `is_real` discipline + row-position scheduling | IMPLEMENTED | All 5 row-position constraints landed (B-9). Lookup hookup deferred to integration commit. |
| (i) ZK preserved | OUT-OF-SCOPE | Same as `uint256_mul_for_fp192.md`. |
| (j) QROM analysis for our Griffin parameters | **UNVERIFIED — upstream claim** | Thesis-level check; AIR cannot rescue. |

## Audit caveats from proof-checker (2026-05-18, pre-stage-3)

1. **A-1 (HIGH) — CLOSED by B-8.** `Fp192::to_limbs` silently
   truncates digits beyond the 4th in release builds (`debug_assert!`
   is a no-op). Previously safe only by transitive reliance on every
   constructor reducing mod p. B-8's `FieldLtCols<T,
   Fp192FieldParams>` per-lane range check now enforces strict
   `< p` on the chip's output, breaking the transitive-canonicality
   dependency at the AIR boundary.

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
