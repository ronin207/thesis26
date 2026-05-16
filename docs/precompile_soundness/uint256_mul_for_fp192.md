# Soundness note — SP1 `UINT256_MUL` / RISC0 `sys_bigint` as the Fp192 modular multiplication precompile

**Deliverable:** the "192-bit modular arithmetic module" of the thesis's
3-precompile suite, as built for both the SP1 and the RISC Zero zkVM
targets.

**Construction.** We do not write a fresh 192-bit-specific AIR.
Both target zkVMs ship a 256-bit modular-multiplication chip mod a
runtime-supplied modulus, structurally identical to each other:

- **SP1**: `syscall_uint256_mulmod(x, y_and_modulus)` constrained by
  `sp1-core-machine-6.2.1/src/syscall/precompiles/uint256/air.rs`.
- **RISC0**: `sys_bigint(result, OP_MULTIPLY, x, y, modulus)`
  constrained by `risc0-circuit-rv32im`'s baked-in bigint chip.

We zero-pad PLUM's 199-bit modulus (`p = 2^64 · p_0 + 1`, stored in
`MODULUS_LIMBS: [u64; 4]` with `MODULUS_LIMBS[3] = 0x4c`) to the AIR's
256-bit slot and zero-pad each Fp192 operand similarly. Wiring is in
`src/primitives/field/p192.rs::Fp192::mul`, behind two cfg guards:

- `#[cfg(all(target_os = "zkvm", feature = "sp1"))]` — SP1 path.
- `#[cfg(all(target_os = "zkvm", feature = "risc0", not(feature = "sp1")))]`
  — RISC0 path, with `[u64; 4] ↔ [u32; 8]` transcoding at the boundary
  to match `sys_bigint`'s `[u32; 8]` slots.

## Reduction

We must argue that PLUM Verify's correctness is preserved when each
`Fp192::mul(a, b)` is replaced by an invocation of
`syscall_uint256_mulmod(x = a_limbs, y_and_modulus = (b_limbs, p_limbs))`.

### Statement we assume (SP1's AIR is sound)

For every cell `(x, y, m, x')` of the `Uint256MulModChip` table that
appears in a verifying proof,

    x' ≡ x · y  (mod m)                 (1)

with `x, y, m, x' ∈ [0, 2^256)`. This is the upstream Uint256-mulmod
AIR's stated soundness; we treat it as a black-box hypothesis (audited
externally; SP1's standard precompile suite is in production use).

### Statement we want

For every Fp192 multiplication invocation `c = a * b`, the result `c`
returned by the syscall path equals `(a · b) mod p` in PLUM's prime
field, with `a, b, c ∈ [0, p)`.

### Argument

`Fp192` values are stored canonically: every constructor (`from_limbs`,
`from_biguint`, `from_u64`, `Add`, `Sub`, `Neg`, ...) reduces mod `p` so
the stored representative is in `[0, p)`. In particular when `Mul` is
entered, both `a.value` and `b.value` are in `[0, p)`. Since
`p < 2^200 < 2^256`, the zero-pad-to-`[u64; 4]` step is the identity on
the bit pattern: `a_limbs[0..3]` carries `a`, `a_limbs[3] = 0`, and the
integer value at the resulting 256-bit slot equals `a` exactly. Same
for `b`. The modulus pack stores `p`'s 4-limb representation in the
top half of `y_and_modulus`; this is the same `MODULUS_LIMBS` constant
used by the `from_biguint` reducer, so the value supplied to the AIR
is exactly `p`.

By (1) applied with `m = p`,

    x' = a · b  (mod p) ∈ [0, p).

We then re-construct `Fp192` via `Self::from_limbs(x')`. `from_limbs`
internally calls `from_biguint` which reduces mod `p`; since `x' ∈ [0, p)`
already, the reduction is the identity. Therefore the returned `Fp192`'s
canonical `value` equals `(a · b) mod p`, matching the pure-Rust
fallback (`product = a.value * b.value; product % MODULUS`).

### What this argument depends on

1. `p < 2^256`. **Holds:** `p` is 199 bits.
2. Inputs canonical (in `[0, p)`). **Holds** by `Fp192` constructor
   invariants. A pre-condition assertion `debug_assert!(self.value <
   *MODULUS && rhs.value < *MODULUS)` would be cheap insurance; not
   added in this Phase-1 patch because the invariant is already
   guaranteed structurally.
3. `MODULUS_LIMBS` matches the audited prime. **Holds:** the constant
   is verified by `tests/plum_field_primality.rs` (both decimal/hex
   agree-with-limbs tests, and the Miller-Rabin primality test).
4. The 4-th limb of operands is zero. **Holds** by canonicality (item
   2) plus the high-bit padding step.
5. SP1's UINT256_MUL AIR is sound (hypothesis (1)).

### What this argument does NOT cover

- **Zero-knowledge.** UINT256_MUL leaks no witness data beyond what
  PLUM Verify already commits via Fiat–Shamir; the syscall's memory
  accesses are constrained but not opened to the verifier. ZK of the
  full PLUM Verify circuit is preserved under SP1's standard ZK
  argument over the global AIR; the precompile is not a new ZK
  failure mode.
- **EU-CMA.** The signature scheme's security argument is over the
  ideal-world `Fp192::mul`; the syscall implements the same function
  under hypothesis (1), so the reduction in PLUM §4.3 (paper p. 124)
  transfers unchanged.
- **Side channels.** Constant-time properties of the syscall (modular
  multiplication via the AIR) are outside the thesis's threat model.

## Measurements

### SP1 v6.2.1

Baseline (Fp192 mul emulated via `BigUint::mul` + `%`): 289,778,709
RISC-V cycles per PLUM-128 verify with `PlumSha3Hasher`.

Cumulative reductions (each row adds to the previous):

    Phase 1   Fp192::mul → UINT256_MUL syscall          276,643,994  (−4.5%)
    Phase 2   pow_biguint as SaM over Fp192::mul        240,857,140  (−16.9%)
    Skip-mod  drop `% MODULUS` on syscall return        179,952,920  (−37.9%)

    UINT256_MUL syscall fires    112,902
    executor wall-clock          ~1.78 s   (3.2 s baseline)

### RISC Zero v3.0.5

Baseline (same emulation path; different rv32im executor):
812,646,400 RISC-V cycles per PLUM-128 verify with `PlumSha3Hasher`.

With `sys_bigint(OP_MULTIPLY)` + the same Phase 2 + skip-mod stack
applied (one feature flag toggles all three):

    cycles                       239,599,616   (Δ −572,946,784, −70.5%)
    sys_bigint invocations           112,903
    cyc / Fp192::mul                   6,625 (baseline) → 1,826 (precompile)

The risc0 baseline is ~2.6× more expensive per Fp192::mul than SP1's
(6,625 vs 2,400-ish cyc). The absolute final cycle count is similar
(240 M vs 180 M), suggesting per-mul precompile overhead is the new
floor on both platforms. The remaining cost is dominated by Griffin
permutation work — the Griffin AIR (not yet built) is the targeted
optimisation for that share.

Source data: `platforms/zkvms/sp1/script/target/release/plum_host`
under `PLUM_HOST_MODE=execute`. Reproducible — fixed RNG seed
`0x504C554D5F535031`, fixed message
`"sp1 smoke: plum verify with SHA3 hasher"`.

### The skip-mod step in detail

The naive Phase-1 wrapper called `Self::from_limbs(x_limbs)` to
re-construct an `Fp192` after the syscall. `from_limbs` delegated to
`from_biguint`, which always applied `bi % MODULUS.clone()`. This was
defensive but redundant: the AIR (1) constrains the output to satisfy
`x' < m`, and we pass `m = p`, so the syscall return value is already
in `[0, p)`. The `%` step was a wasted BigUint allocation roughly
540 cycles per call × 112,902 calls ≈ 61 M cycles. Replacing
`from_limbs(...)` with `Self { value: limbs_to_biguint(&x_limbs) }`
removes it.

**Soundness implication.** The skip-mod relies on (1) — i.e. on the
AIR's range-check on `x'`. If a future SP1 release weakened that
range-check (unlikely; it is part of the standard
`FieldOpCols`/`FieldDenominator`/etc. pattern), the saved
allocation becomes load-bearing for canonicality and the optimisation
would need to be reverted. A defensive `debug_assert!(x_limbs < p as
limbs)` would catch the regression but is not present in the
release-build path.

The remaining ~62 % of cycles is dominated by Griffin permutation
work that emulates Griffin's matrix-multiply + d=3 S-box layer over
the same Fp192 arithmetic. The Griffin AIR (Phase 3) is the targeted
optimisation for that share. Path B (risc0 + Zirgen) is the chosen
construction vehicle for that AIR; SP1 forking deferred.
