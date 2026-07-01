# Soundness note — Precompile #2 "B1": constant-modulus `FP192_MUL`

**Status: DRAFT, honest.** This note states B1 as an *instantiation of
the precompile interface*, not as a new soundness result. B1 adds no new
arithmetic constraints; it is a **subtraction** from the audited
`UINT256_MUL` chip. Its soundness families F1–F6 are therefore
*inherited*, and the one thing B1 changes (constant modulus) is exactly
the interface property that `UINT256_MUL` lacks. **B1 does NOT prove the
PRF in-circuit** — see the honest gap in §4.

Build artifacts (isolated SP1 fork-worktree, branch `prf-precompiles`,
off pinned fork commit `8bf0248…`):
- chip: `crates/core/machine/src/syscall/precompiles/fp192_mul/{mod,air}.rs`
- event: `crates/core/executor/src/events/precompiles/fp192_mul.rs`
- executor compute: `crates/core/executor/src/fp192_mul_compute.rs`
- tracing / minimal handlers, syscall code `FP192_MUL = 0x00_01_01_36`,
  guest entrypoint `syscall_fp192_mulmod`.

---

## 1. What B1 is

The guest already lowers every `Fp192::mul` to a syscall and runs the
power-residue PRF's exponentiation as left-to-right square-and-multiply
over that mul (DESIGN.md §2.0). On the current build that path runs as
`UINT256_MUL` syscalls, which read the modulus from memory every call —
so the field is prover-supplied data, not a chip constant.

B1 replaces that with a dedicated chip `FP192_MUL` that computes
`x ← (x · y) mod p` for the **constant** 199-bit prime
`p = Fp192FieldParams::MODULUS`. Square-and-multiply and the 256-entry
`dlog_ω` table stay in the guest; the chip certifies one multiplication
per syscall.

Construction = the `uint256` chip with:
- `U256Field` → `Fp192FieldParams` (constant `MODULUS`), and
- the modulus-from-memory machinery **deleted**: the `modulus_memory`
  columns, the `IsZeroOperation`, the `modulus_is_not_zero` selector, and
  the `2^256`-fallback modulus polynomial are all removed. The reduction
  polynomial is now `Fp192FieldParams::MODULUS` (preprocessing-bound,
  constraint-fixed every row), exactly as the `fptower` `FpOpChip` does
  for curve base fields.

## 2. The three interface properties

**(i) I/O equivalence over F_p.** The syscall's output equals
`(x · y) mod p` for the field elements read from memory. This is the
`FieldOpCols::eval` contract (`operations/field/field_op.rs`, safety doc:
`result = a·b mod M` for operands in `[0, 2^{nb_bits})`), instantiated at
`M = Fp192FieldParams::MODULUS`. No new proof burden. The
square-and-multiply identity `∏(Fp192 mul) = a^e` is a **guest-program**
fact (see §4, gap 1), not an AIR claim.

**(ii) Isolation via cross-table lookup.** The precompile cannot be
invoked, nor its result injected, except through the CPU's ECALL, and the
multiplicities balance. Inherited: `receive_syscall(FP192_MUL, …)`
balances the CPU's syscall send exactly as in `uint256`. B1 has **no**
internal controller / cross-chip lookup (unlike Griffin) — it is a
single self-contained chip, so there is no extra interaction to argue.

**(iii) Constant preprocessing-bound modulus.** A malicious prover cannot
choose the field per row. Inherited from `Fp192FieldParams`
(`crates/curves/src/fp192.rs`, audit finding B-10 "parameter
immutability"): `MODULUS` is `const`, expanded into the reduction
polynomial at preprocessing. **This is the property the status-quo
`UINT256_MUL` path fails, and the sole soundness reason B1 exists.**

## 3. Per-family inheritance (analogue of Griffin's Appendix B)

| Family | Source | Status |
|---|---|---|
| F1 modular-multiply reduction (`x·y − q·p == result`, limbs) | `FieldOpCols::eval` / `eval_with_modulus` (audited) | PROVABLE (inherited) |
| F2 carry / u8-u16 range on witness limbs | `FieldOpCols` witness + byte lookups | PROVABLE (inherited) |
| F3 output canonicality `result < p` | `FieldLtCols::eval` vs constant `p` | PROVABLE (inherited) |
| F4 constant modulus | `Fp192FieldParams::MODULUS` `const` | PROVABLE (inherited) |
| F5 memory binding (x read+write, y read) | `eval_memory_access_slice_{read,write}` + `AddrAddOperation` | PROVABLE (inherited) |
| F6 syscall multiplicity | `receive_syscall` balance | PROVABLE (inherited) |

No F7/F8: B1 has no fixed-exponent S&M AIR and no controller lookup
(those belong to the DESIGN's optional B2/A variants, not built).

## 4. Honest gaps (do not overclaim)

1. **Guest-side square-and-multiply (the load-bearing caveat).** B1
   certifies each *multiplication* under the constant modulus. It does
   **not** certify the PRF exponentiation `a^((p-1)/t) mod p`: the S&M
   loop is a guest algorithm, trusted like any other guest code and
   discharged only by the rv32im CPU trace. **State plainly: "the PRF is
   NOT proven in-circuit for B1."** In-circuit S&M would be the DESIGN's
   B2/A, which carry a genuine new proof obligation (fixed-exponent
   schedule ↔ selector column) — not built here.

2. **Executor ⇄ reference drift.** `Fp192FieldParams::MODULUS`,
   `fp192_mul_compute::MODULUS_LIMBS` (re-exported from
   `griffin_fp192_compute::MODULUS_LIMBS`), and `p192::MODULUS_LIMBS`
   must stay byte-identical. Guarded by
   `fp192_mul_compute::tests::modulus_matches_canonical_decimal` and
   `Fp192FieldParams::modulus_matches_canonical_decimal` (both assert the
   same canonical decimal). Assumption = "the drift tests are complete."

3. **Substituted prime (project-wide).** Every statement is over the
   substituted 199-bit prime, not PLUM's printed (composite) `p_0`. Any
   claim conditioned on the specific decimal value of `p` is open until
   the canonical `p_0` is obtained (CLAUDE.md action item).

## 5. Verification performed

- `cargo check -p sp1-core-executor` — clean.
- `cargo check -p sp1-core-machine` — clean.
- `cargo test -p sp1-core-executor --lib fp192_mul_compute` — 5/5
  (modulus-canonical, ·0, ·1, wrap-around vs BigUint, `(p-1)²≡1`).
- `cargo test -p sp1-core-machine --release test_fp192_mul` — **pass**.
  The `fp192-mul-test` guest invokes `FP192_MUL` on 20 reduced random
  operand pairs plus ·1/·0 edge cases and asserts each result against a
  `BigUint` reference; `run_test` first **executes** (all guest asserts
  fire) then **proves** the core shards, exercising F1–F6 of the AIR.

Cost note: `rv64im_costs.json` gets `Fp192MulMod`/`Fp192MulModUser`
entries; the values are set equal to `Uint256MulMod` as a conservative
over-estimate (B1 has strictly fewer columns than uint256). Refine from
`Chip::cost()` before any packing-sensitive measurement.
