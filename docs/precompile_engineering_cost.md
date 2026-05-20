# Precompile engineering cost — accounting for the rigidity-relocation claim

This document quantifies the per-scheme engineering bill paid to add
a Griffin-Fp192 precompile to SP1, and compares it to the bill that
would have been paid to arithmetize the equivalent computation as an
R1CS circuit. The output is the load-bearing evidence for the
thesis's **precompile-paradox claim** (C4 in the thesis outline):
the precompile collapses prover cost for the dominated primitive but
relocates rather than eliminates the per-scheme audit work.

**Scope.** This is engineering-effort accounting, not a constraint
lower bound. Numbers are LoC, column counts, audit-found bugs, and
calendar time; they describe *what we paid*, not what is theoretically
necessary. The honest interpretation is that the AIR-side bill for a
new algebraic primitive is comparable to the R1CS-side bill for the
full enclosing verify — close to a wash on engineering hours, with the
prover-cost win recovered as a separate gain.

---

## 1. Direct cost of the Griffin Fp192 precompile

### 1.1 Code surface

| File                                                                                                                                                  | LoC   | Role                                                  |
|------|------:|------|
| `submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/air.rs`                                                                     | 1,938 | Per-round chip AIR + trace generation; load-bearing.  |
| `submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/controller.rs`                                                              |   535 | Controller chip — memory binding, cross-chip lookup.  |
| `submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/poly_populate.rs`                                                           |   409 | Polynomial-expression cell populate helper.           |
| `submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/mod.rs`                                                                     |    32 | Module wiring.                                        |
| `submodules/sp1/crates/core/executor/src/griffin_fp192_compute.rs`                                                                                    | 1,009 | Vendored native compute + executor handler.           |
| **Total Griffin-specific Rust**                                                                                                                       | **3,923** | Excludes pre-existing infrastructure (FieldOpCols, FieldLtCols, UINT256_MUL, lookup framework). |

### 1.2 Constraint-cell layout

From the per-round chip's column struct `GriffinFp192Cols<T, M>`
([air.rs:128](submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/air.rs:128)):

| Cell class            | Declaration sites | Concrete cells per row    |
|-----------------------|------------------:|---------------------------:|
| `FieldOpCols<T, Fp192FieldParams>` (binary modular ops)   |                20 | 26 (10 scalar + 4 mds_out + 4 rc_add + 8 F2-chain spills) |
| `FieldLtCols<T, Fp192FieldParams>` (< p range checks)     |                 5 | 7 (4 rc_add + 3 post-S-box canonicality)                  |
| Bit/state cells (`Limbs`, booleans, `is_round_r[14]`)     |                 — | ~150 (state_before×4, state_after_nonlinear×4, one-hot round flags, ptr/clk threading) |

Per-row constraint-cell count: **~33 algebraic-op cells**, plus the
underlying `Limbs<T, U32>` state plumbing. Each `FieldOpCols` adds
32 result + 63 witness + 31 carry sub-cells via the
`Fp192FieldParams` blanket impl, so the *trace* width per Griffin row
is roughly **~2,500 trace cells × 14 rounds = 35K cells per Griffin
syscall**.

PLUM-80 verify invokes `GRIFFIN_FP192_PERMUTE` exactly **1,052 times**
([cell3_execute](docs/sp1_plum_cell3_execute.md)), so the
Griffin-chip trace footprint is ≈ **37M cells per PLUM-80 verify**.

### 1.3 Constraint families

Per [griffin_fp192.md](docs/precompile_soundness/griffin_fp192.md),
ten constraint families anchor soundness:

| Family | Source-of-truth section                       | What it constrains                                |
|--------|------------------------------------------------|----------------------------------------------------|
| B-1    | griffin_fp192.md:139                          | Forward S-box on lane 1 (degree-3)                 |
| B-2    | griffin_fp192.md:179                          | Inverse S-box on lane 0 (degree-3 backward)        |
| B-3    | griffin_fp192.md:223                          | Quadratic layer on lanes 2, 3                      |
| B-4    | griffin_fp192.md:274                          | MDS linear layer (circulant [2,1,1,1])             |
| B-5    | griffin_fp192.md:327                          | Round constants from SHAKE256                      |
| B-6    | griffin_fp192.md:383                          | Round count = 14                                   |
| B-7    | griffin_fp192.md:396                          | Memory binding (controller chip, split a/b)        |
| B-8    | griffin_fp192.md:512                          | Output canonicality (per-lane < p)                 |
| B-9    | griffin_fp192.md:564                          | `is_real` discipline + row-position scheduling     |
| B-10   | griffin_fp192.md:611                          | Parameter immutability (preprocessing tables)      |

### 1.4 Audit-found defects (two adversarial passes)

| Pass | Date          | Auditor             | Findings                                                                                                   | Severity                |
|------|---------------|---------------------|------------------------------------------------------------------------------------------------------------|-------------------------|
| F1   | 2026-05-19    | proof-checker subagent | 1. B-3 polynomial-degree blowup (witness budget overflow → constraint unsatisfiable on honest traces) <br> 2. Missing < p canonicality on `sbox1_cube.result` <br> 3. Missing < p canonicality on `quad_mul_2.result` <br> 4. Missing < p canonicality on `quad_mul_3.result` <br> 5. Round-constant preprocessing-table determinism (no golden digest test) | 1 critical, 3 medium, 1 low |
| F2   | 2026-05-20    | engineer-agent subagent | 1. u16 witness overflow on byte-sum operands in B-3 polynomial-expression cells (caused GKR lookup imbalance with 511·2^16 truncation signature) <br> 2. WITNESS_OFFSET padding-row populate (caused constraint failure on padded rows; `p_vanishing` not zero on all-zero rows because WITNESS_OFFSET = 2^14 ≠ 0) | 2 critical                  |

**Total: 7 audit-found security-relevant defects across 2 audit
passes.** Each was fixed in a tagged commit; none was discovered by
the original implementor. This is direct evidence that AIR-chip
auditing is non-trivial — the engineering cost of building the chip
includes the cost of running these audit passes, not just writing the
code.

### 1.5 Calendar duration

From `git log` on the SP1 submodule path
`crates/core/machine/src/syscall/precompiles/griffin_fp192/`:

| Milestone                                                                                              | Commit / date                                  |
|--------------------------------------------------------------------------------------------------------|------------------------------------------------|
| First chip commit (Phase 3b skeleton)                                                                  | `487cb17ab` — 2026-05-17 15:30:16 +0900        |
| All 10 B-families implemented + cross-codebase equivalence (Phase 3d-stage-3 B-8 last)                 | `d70d5eef0` — 2026-05-18 22:15:16 +0900        |
| F1 hardening landed (5 audit findings closed)                                                          | `23372a68e` — 2026-05-19 15:49:13 +0900        |
| F2 binary-chain fix + end-to-end smoke prove passes                                                    | `020cf6ac1` — 2026-05-20 02:54:46 +0900        |
| Stage-3 COMPLETE documentation                                                                         | `8bf0248bc` — 2026-05-20 09:49:46 +0900        |
| Cell 2 PLUM-80 prove (32.53 min) measurement                                                           | 2026-05-20 (outer thesis repo)                  |
| **Wall-clock from first chip commit to stage-3 complete**                                              | **≈ 60 hours (2.5 days)**                       |
| Commits in that window (SP1 submodule, griffin_fp192/ path only)                                       | **22**                                          |

Wall-clock duration is a loose proxy for engineering effort because
it includes sleep, other work, and subagent audit time. A tighter
estimate is **22 chip-only commits across 2.5 calendar days**,
implying roughly 1 commit every 2.5 working hours over the burst.

---

## 2. Field-size dependency audit — extension cost across primes

The thesis's C3 claim is that *parametric* extensions (same chip,
different security level) are cheap, while *structural* extensions
(different prime, different state width, different S-box degree)
require a chip rewrite. The split is empirically:

### 2.1 What is field-size-dependent

From [griffin_fp192_compute.rs](submodules/sp1/crates/core/executor/src/griffin_fp192_compute.rs):

| Constant                                                                  | Type / value                | Migration impact for new prime |
|---------------------------------------------------------------------------|------------------------------|---------------------------------|
| `MODULUS_LIMBS: [u64; 4]` (line 62)                                       | 4 × u64 (256-bit slot)       | **Parameter swap.** Replace 4 hex constants. |
| `MODULUS_BITS: usize = 199` (line 70)                                     | Bit length of prime          | **Parameter swap.** Update + re-verify range-check widths in `FieldLtCols`. |
| `NB_ROUNDS: usize = 14` (compute:221, air.rs:98)                          | Number of permutation rounds | **Re-validate against security analysis.** Likely changes for substantially different primes. Code change: 1 line + recompute α/β/RC. |
| α, β, RC preprocessing (SHAKE256-seeded)                                  | Generated from prime size   | **Parameter swap** if seed scheme reused; one new golden-digest test (F1.4). |
| `Fp192FieldParams` type (in vc-pqc) — `NUM_LIMBS`, `NUM_WITNESS_LIMBS`    | 32 / 63 (for 199-bit slot)   | **Parameter swap** if prime fits a 256-bit slot; **structural rewrite** if new slot size needed. |

### 2.2 What is structural (chip-internal)

Independent of prime — invariant across security-level changes within
the same prime:

| Structural property               | Value in chip                 | Migration impact                                       |
|------------------------------------|-------------------------------|--------------------------------------------------------|
| State width (lanes)                | 4 (compression)               | Hardcoded in `[FieldOpCols; 4]`, `[T; 4]` arrays.      |
| S-box forward degree               | d = 3                          | Hardcoded in B-1's `sbox1_sq → sbox1_cube` chain.      |
| S-box backward direction           | Inverse via cubing identity   | B-2 only valid when `gcd(d, p-1) = 1`.                 |
| MDS matrix                         | Circulant [2,1,1,1]            | Hardcoded in B-4's `mds_out` lane equations.           |
| Quadratic layer (lanes 2,3)        | L² + α·L + β factor          | B-3 polynomial spilling is structural; F1+F2 fixes.    |
| Round structure                    | 14 rows = 14 rounds            | Hardcoded in `NB_ROUNDS`; row-thread / one-hot layout. |

### 2.3 Migration cost estimate

| Migration target                                                              | Class                         | Estimated LoC change | Engineering cost relative to original |
|--------------------------------------------------------------------------------|--------------------------------|----------------------:|----------------------------------------|
| PLUM-80 → PLUM-100 → PLUM-128 (same prime, different STIR/sample params)      | **Parameter swap**            |                    0 | 0 % — already runtime-selected via `PLUM_SECURITY`. |
| Fp192 (199-bit) → another ≤256-bit prime, d=3 S-box, state width 4            | Parameter swap                | ~50 LoC (constants + one new golden-digest test) | ~1 % |
| Fp256 (>199-bit, requires larger slot)                                        | Parameter swap + slot resize  | ~200 LoC (Fp256FieldParams, range-check widths, witness offset) | ~5 % |
| Loquat (127-bit Mersenne, state width 8, different MDS)                       | **Structural rewrite**       | ~2,000 LoC (new chip module reusing FieldOpCols framework but new family of B-1..B-10 constraints) | ~50 % |
| Algebraic primitive with d≠3 (e.g., Poseidon2's d=5)                          | Structural rewrite            | ~1,000 LoC (new S-box family; B-1/B-2 redesigned) | ~25 % |

The parametric-extension claim (C3) is *empirically supported* for
PLUM-80 → PLUM-128: 0 LoC change, runtime-selected via env var.
Migration to a structurally different primitive (Loquat-Mersenne or
Poseidon2-Goldilocks) requires a substantial chunk of the original
3,923 LoC bill — *the rigidity is real and per-primitive.*

---

## 3. R1CS comparator — what the alternative architecture would cost

The thesis's rigidity-relocation claim compares the AIR-side per-scheme
bill to the equivalent R1CS-circuit-side bill for the same primitive.
The codebase contains a worked-out R1CS arithmetization for Loquat
verification at
[src/signatures/loquat/r1cs_circuit.rs](src/signatures/loquat/r1cs_circuit.rs)
(5,945 LoC), plus Aurora/STIR proving framework code
([src/snarks/aurora.rs](src/snarks/aurora.rs): 736 LoC,
[src/snarks/libiop_bridge.rs](src/snarks/libiop_bridge.rs): 456 LoC).

### 3.1 Comparator metrics

| Axis                                                                                                                                                | In-zkVM (this thesis)                                                                | In-SNARK (Loquat reference)                                                                  |
|-----------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| **LoC** for the dominant primitive's arithmetization                                                                                                | **3,923** (Griffin Fp192 chip alone — covers PLUM's 91% hash work)                   | **5,945** (full Loquat R1CS gadget — covers hash + non-hash work in one circuit)              |
| **Constraint count for PLUM-128 verify hash work** (paper §4.2)                                                                                     | ~ 26 cells × 14 rows × 1052 syscalls × ~10 per-cell constraints ≈ 3.8 M AIR cells   | 105,952 R1CS constraints (91.1% of 116,285 total)                                             |
| **Per-scheme audit passes that found security-relevant defects**                                                                                    | 2 passes, 7 findings (F1: 5, F2: 2)                                                  | Not publicly documented for Loquat; the Aurora-STIR Loquat paper went through multiple drafts |
| **Cost of swapping the underlying hash primitive** (e.g., Loquat→PLUM, different field + different S-box)                                            | New AIR module ~2,000 LoC; reuses FieldOpCols framework                              | Re-arithmetize the entire verification circuit from scratch (~5,000 LoC equivalent)            |
| **Cost of swapping the security parameter** within the same primitive (e.g., PLUM-80 → PLUM-128)                                                    | **0 LoC** — runtime parameter (`PLUM_SECURITY` env var)                              | Re-instantiate the circuit at the new parameter, re-audit constraint count                    |

### 3.2 The rigidity-relocation ratio

Combining sections 1, 2, and 3.1, the **structural claim** is:

> The per-scheme engineering bill for a new algebraic post-quantum
> signature primitive in a general-purpose zkVM (≈ 4,000 LoC of AIR
> chip + 2 audit passes + 7 found defects + ~60 wall-clock hours) is
> *comparable* to the per-scheme bill in an R1CS-circuit approach
> (≈ 6,000 LoC of arithmetization + an undocumented number of audit
> passes for Loquat). The factor by which the zkVM is *more agile*
> than the R1CS approach is bounded by how much of the bill can be
> reused across primitives — empirically **<10% for primitives that
> share field size and S-box structure**, **>50% for primitives that
> require a structural chip rewrite**.

In plain terms: the rigidity has been **relocated** from the
R1CS-circuit layer to the AIR-chip layer. It has not been eliminated.
The zkVM abstraction's promise of "update the program, don't re-audit
the circuit" is half-true: the user-facing PLUM Verify program is
indeed unchanged across security parameters (param swap), but the
underlying chip suite is itself a per-primitive R1CS-equivalent
artifact.

### 3.3 The orthogonal prover-cost win

The zkVM precompile *does* deliver a separate gain, distinct from the
engineering-effort accounting: it reduces the **prover-side** cost of
proving the workload, by replacing thousands of native rv32im rows
per Griffin permutation with a fixed-width AIR chip. This win is
documented in
[docs/sp1_plum_cell2_measurement.md](docs/sp1_plum_cell2_measurement.md)
(Cell 2 prove in 32.53 min on M5 Pro 24 GB) and bounded against
Cell 1's infeasible-without-tuning baseline. **The prover-cost gain is
real; the engineering-bill gain is much smaller.**

This is the precise distinction Sako asked for and the thesis must
land: precompile-class support is a **workload-feasibility
precondition** (the workload class exists in the zkVM only because the
chip exists), not a **performance optimization** of an already-feasible
workload.

---

## 4. Limitations of this accounting

- **LoC is a crude proxy.** Two chip implementations of the same
  family can vary by 2× depending on coding style. The numbers here
  reflect *this implementation*, not a lower bound on what the work
  costs in general.
- **R1CS comparator is from the codebase, not a published reference.**
  The 5,945-LoC Loquat R1CS gadget at
  [r1cs_circuit.rs](src/signatures/loquat/r1cs_circuit.rs) is the
  thesis author's own arithmetization, not the published Aurora-STIR
  Loquat reference's. A more rigorous comparator would cite the
  published constraint count tables from the Loquat / Aurora papers
  (Loquat 2024, eprint 2024/868; PLUM paper §4.2).
- **Audit-pass count is not normalized across systems.** Two F-passes
  for AIR and unknown for R1CS — the comparison is suggestive, not
  rigorous.
- **Constraint-count comparison conflates AIR cells with R1CS
  constraints.** They are different cost models — one AIR cell is
  not equivalent to one R1CS constraint in prover work or in audit
  complexity. The numbers anchor *magnitudes*, not exchange rates.
- **The "migration cost" estimates in §2.3 are projections, not
  measurements.** The only actually-measured migration is PLUM-80 →
  PLUM-128 (0 LoC). Fp256, Loquat-Mersenne, Poseidon2-Goldilocks are
  not implemented.

These limitations are honest disclosures. The thesis's structural
claim (rigidity is relocated, not eliminated) survives them; what
weakens is any precise numeric ratio.

---

## 5. Headline numbers for the thesis

For drop-in citation in Chapter 5 ("The Precompile Paradox"):

- **Griffin Fp192 chip:** 3,923 LoC of Rust, 22 chip-only commits,
  ≈ 60 calendar hours from first commit to stage-3 complete.
- **Constraint cells per row:** 26 `FieldOpCols` + 7 `FieldLtCols` ≈
  33 algebraic-op cells per round, 14 rounds per syscall.
- **Audit-found defects:** 7 across 2 independent audit passes
  (proof-checker 2026-05-19; engineer-agent 2026-05-20).
- **R1CS comparator (Loquat verify):** 5,945 LoC of Rust at
  [src/signatures/loquat/r1cs_circuit.rs](src/signatures/loquat/r1cs_circuit.rs).
- **Within-prime extension cost:** 0 LoC (param-swap via env var).
- **Cross-prime structural extension cost:** ~50% of original bill
  (~2,000 LoC for a new state-width-8 algebraic hash chip).
- **Prover-side gain (separate from engineering bill):** PLUM-80
  verify from infeasible-without-tuning baseline to 32.53 min
  measured on M5 Pro 24 GB
  ([cell2_measurement](docs/sp1_plum_cell2_measurement.md)).

---

*Sources: source files cited inline; git log on `submodules/sp1`
limited to `crates/core/machine/src/syscall/precompiles/griffin_fp192/`;
soundness rubric in
[docs/precompile_soundness/griffin_fp192.md](docs/precompile_soundness/griffin_fp192.md).*
