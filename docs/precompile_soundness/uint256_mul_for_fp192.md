# Soundness note — SP1 `UINT256_MUL` / RISC0 `sys_bigint` as the Fp192 modular multiplication precompile

**Deliverable:** the "192-bit modular arithmetic module" of the thesis's
3-precompile suite, as built for both the SP1 and the RISC Zero zkVM
targets.

**Bit-width note.** The thesis prose says "192-bit" because PLUM's
paper §3.3 (LNCS 16172, p. 123) titles the section "192-bit smooth
prime field". The actual modulus stored in `MODULUS_LIMBS` is **199
bits** — `p = 2^64 · p_0 + 1` with `p_0` a 135-bit prime; full hex
`p = 0x004c455e221a5f68af517bbd7e10d66d13710000000000000001`,
decimal `478760623137260249020079243151463163776858757630613067399169`,
audited end-to-end against the paper PDF in
`tests/plum_field_primality.rs`. The "192-bit" label is retained for
section-title parity with the paper; soundness arguments use the
actual 199-bit value throughout.

## Construction

We do not write a fresh 192-bit-specific AIR. Both target zkVMs ship
a 256-bit modular-multiplication chip mod a runtime-supplied modulus,
structurally identical to each other:

- **SP1 v6.2.1**: `syscall_uint256_mulmod(x, y_and_modulus)`,
  constrained by `Uint256MulModChip` at
  `sp1-core-machine-6.2.1/src/syscall/precompiles/uint256/air.rs`
  (specifically the constraint expression at line 422 plus the
  output-range constraint at line 435 — see "Statement we assume"
  below). Cargo.lock pins this to `sp1-core-machine 6.2.1`.

- **RISC0 v3.0.5**: `sys_bigint(result, OP_MULTIPLY, x, y, modulus)`,
  declared at `risc0-zkvm-platform-2.2.2/src/syscall.rs:498-512`, with
  constraint enforcement in the rv32im circuit's Zirgen-generated
  bigint accumulator. The constraint code is in
  `risc0-circuit-rv32im-4.0.4/src/zirgen/{steps.rs.inc,poly_ext.rs}`
  (75K lines of auto-generated output, opaque on visual inspection;
  production-audited per RISC Zero's release process).

We zero-pad PLUM's 199-bit modulus and operands to the AIR's 256-bit
slot. Wiring is in `src/primitives/field/p192.rs::Fp192::mul`, behind
two cfg guards:

- `#[cfg(all(target_os = "zkvm", feature = "sp1"))]` — SP1 path.
- `#[cfg(all(target_os = "zkvm", feature = "risc0", not(feature = "sp1")))]`
  — RISC0 path, with `[u64; 4] ↔ [u32; 8]` transcoding at the
  boundary.

## Reduction

We must argue that PLUM Verify's correctness is preserved when each
`Fp192::mul(a, b)` is replaced by an invocation of the upstream
syscall.

### Statement we assume (upstream chip soundness)

**SP1 UINT256_MUL.** For every cell `(x, y, m, x')` of the
`Uint256MulModChip` table that appears in a verifying proof, the AIR
enforces both:

```rust
// air.rs:422 — modular multiplication core constraint
local.output.eval_with_modulus(
    builder, &x_limbs, &y_limbs, &p_modulus,
    FieldOperation::Mul, local.is_real,
);
// air.rs:435 — output range check < modulus (only when modulus != 0)
local.output_range_check.eval(
    builder, &local.output.result,
    &modulus_limbs.clone(),
    local.modulus_is_not_zero,
);
```

so `x' ≡ x · y (mod m)` AND `x' ∈ [0, m)` whenever `m ≠ 0`. The
`modulus_is_zero` column (air.rs:101-105) treats `m = 0` as
`2^256` — relevant only if `m = 0` is ever loaded; see §"Edge cases"
below.

**RISC0 sys_bigint.** The opaque Zirgen output enforces the same
modular-multiplication semantics. We **cite** this as a production
guarantee (RISC Zero v3.0.5 release process audits the bigint chip)
rather than independently verify it from the generated constraint
code. A precise public-audit citation would strengthen the
"upstream-trusted" status; absent one, this is the weakest link of
the argument and is flagged below in the property table.

### Reduction itself

`Fp192` values are stored canonically by **structural** invariant for
`from_biguint` (which reduces) and by **domain** invariant for
`from_u64` / `from_u128` (input < `u128::MAX` < p, so the value is
already in `[0, p)`). When `Mul` is entered, both operands are in
`[0, p)`. Since `p < 2^200 < 2^256`, the zero-pad to `[u64; 4]` is
the identity on the bit pattern.

By the AIR constraints above with `m = p`,

    x' = a · b  (mod p) ∈ [0, p).

We re-construct `Fp192` via `Self { value: limbs_to_biguint(&x') }`,
**bypassing** the `% MODULUS` step `from_biguint` would normally
apply (the "skip-mod" optimisation). A `debug_assert!(value < *MODULUS)`
guard catches any regression of the AIR's range-check (free in
release). Therefore the returned `Fp192`'s canonical `value` equals
`(a · b) mod p`, matching the pure-Rust fallback
(`product = a.value * b.value; product % MODULUS`).

### Edge cases addressed

1. **`m = 0` exploit attempt.** SP1's AIR has `modulus_is_zero`
   column that treats `m = 0` as `2^256`. A malicious prover would
   need to pass `m = 0` (or otherwise non-`p`) to make this fire.
   The modulus is supplied per-call from a stack-local
   `y_and_modulus: [u64; 8]` populated from the **const**
   `MODULUS_LIMBS` (`Fp192::mul` body, p192.rs). For the malicious
   prover to mutate it, they would need to corrupt the guest's
   memory commitment for the stack frame — which the zkVM's
   memory-checking framework prevents under standard rv32im soundness.
   This is not a defence against bugs in vc-pqc that might
   accidentally load `MODULUS_LIMBS = [0; 4]`, but no such bug exists
   today (const is checked at compile time).

2. **Non-canonical operand truncation.** `Fp192::to_limbs` takes only
   the first 4 u64 digits of `value`. A non-canonical `value > 2^256`
   would silently truncate. A `debug_assert!(value.bits() <= 200)` at
   the top of `to_limbs` catches this if a non-reducing constructor
   ever escapes; canonicality is maintained structurally for
   `from_biguint` and by domain for `from_u64`/`from_u128`.

3. **Output canonicality regression.** If a future SP1 release
   weakens the `output_range_check` (currently at air.rs:435), the
   skip-mod becomes load-bearing for canonicality. The
   `debug_assert!(value < *MODULUS)` in `Fp192::mul`'s syscall path
   triggers if this happens. Production builds compile this out, so
   the assertion is for development/CI; a CI run that exercises the
   guest path is the recovery point.

## What this argument does NOT cover

- **Public audit citation for risc0 bigint chip.** Best we can say
  today is "production-used in RISC Zero v3.0.5 release". A specific
  third-party audit report URL (Trail of Bits, Veridise, etc.) would
  upgrade this from "trust the release process" to "trust a named
  external auditor".

- **EU-CMA reduction transfer.** PLUM §4.3 (paper p. 124) treats
  `Fp192::mul` as a deterministic function `F_p × F_p → F_p` and
  makes no claims about its operational behaviour (constant time,
  no side channels, no aborts on degenerate inputs). The syscall
  matches this functional spec under the AIR constraints above, so
  the EU-CMA reduction transfers. The implicit assumption — that
  PLUM's reduction is purely functional — is not formally restated
  in the PLUM paper but follows from the standard random-oracle
  game-hop structure. **A complete thesis chapter on EU-CMA would
  re-derive the reduction over the precompiled `Fp192::mul`; this is
  outside the soundness-of-precompile scope but worth noting.**

- **Zero-knowledge.** The thesis claim is proof-time reduction, not
  zero-knowledge. SP1's STARK is not currently ZK in all configurations
  (the SDK exposes a `zk_pad` parameter and tunable ZK modes). The
  precompile does not change this property — it neither adds nor
  removes ZK leakage relative to the surrounding rv32im trace. For
  thesis purposes we treat ZK as out-of-scope.

- **Composability with the future Griffin AIR.** A third deliverable
  (Griffin Fp192 permutation AIR) is planned. **Cross-precompile
  contract:** any future Fp192-producing AIR must constrain its
  output to `[0, p)` to preserve the canonicality precondition of
  this multiplication module. The Griffin AIR's constraint set must
  include an output-range check; documenting this contract now
  pre-empts the silent-canonicality-leak class of bug.

## Measurements

### SP1 v6.2.1 — PLUM-128 verify, SHA3 hasher, executor mode

Baseline (Fp192 mul emulated via `BigUint::mul` + `%`): 289,778,709
RISC-V cycles. Cumulative reductions (each row adds to the previous):

| Step | Cycles | Δ cumulative | Per-mul implied |
|---|---:|---:|---:|
| Baseline (no precompile) | 289,778,709 | — | — |
| Phase 1: Fp192::mul → UINT256_MUL | 276,643,994 | −4.5 % | — |
| Phase 2: pow_biguint as SaM | 240,857,140 | −16.9 % | — |
| Skip-mod (drop `% MODULUS`) | 179,952,920 | **−37.9 %** | — |

Per-syscall implied cost on the Phase-2 → skip-mod transition:
`(276,643,994 − 179,952,920) / 112,902 = 856 cycles/call` saved by
removing one BigUint `% MODULUS` reduction per call (between Phase 1
and Phase-1+skip-mod the delta is `(276,643,994 − 179,952,920) /
112,902 ≈ 856 cyc/call`; **this corrects the "540 cyc/call" figure
previously written here, which was an unsourced approximation**).

112,902 `UINT256_MUL` syscalls per PLUM-128 verify. Wall-clock
executor: 3.2 s → 1.78 s (−44 %).

### RISC Zero v3.0.5 — PLUM-128 verify, SHA3, RISC0_DEV_MODE=1

| Step | Total cycles | Verify cycles | cyc/Fp192·mul |
|---|---:|---:|---:|
| Baseline | 812,646,400 | 748,012,443 | 6,625 |
| + `sys_bigint(OP_MULTIPLY)` + Phase 2 + skip-mod | 239,599,616 | 206,113,267 | 1,826 |

Reduction: **−70.5 %**. RISC0 sees larger relative reduction because
baseline-emulation per Fp192::mul was ~2.6× SP1's.

Source data: reproducible — fixed RNG seed `0x504C554D5F535031`,
fixed message `"sp1 smoke: plum verify with SHA3 hasher"`,
`platforms/zkvms/sp1/script/target/release/plum_host` and
`platforms/zkvms/risc0/target/release/plum_host`.

## Adversarial soundness probe

Empirical regression evidence — `PLUM_HOST_MODE=adversarial` runs an
honest control plus six tamper cases per zkVM. Each case applies a
minimal modification to one input (pk / message / signature field)
and asserts the guest's verify result matches expectation. Run
2026-05-16 on SP1 v6.2.1:

| Case | Expected | Got | PASS / FAIL | Cycles | Notes |
|---|---|---|---|---:|---|
| none (honest control) | true | true | PASS | 179,952,920 | matches headline number |
| wrong public key | false | false | PASS | 12,632,158 | short-circuit on first verify step |
| wrong message | false | false | PASS | 12,453,376 | short-circuit |
| flip σ_1 root byte | false | false | PASS | 12,309,943 | short-circuit |
| flip PRF t_tag byte | false | false | PASS | 11,979,295 | short-circuit |
| bump o_responses[0] | false | false | PASS | 11,797,563 | short-circuit |
| bump final_coefs[0] | false | false | PASS | 128,592,767 | runs through to STIR final-poly check |

**SP1 result: 7/7 PASS.** Reproducible via
`PLUM_HOST_MODE=adversarial ./platforms/zkvms/sp1/script/target/release/plum_host`.

Same probe mirrored to RISC0 (`PLUM_HOST_MODE=adversarial
./platforms/zkvms/risc0/target/release/plum_host`) under
`RISC0_DEV_MODE=1`:

| Case | Expected | Got | PASS / FAIL | Cycles |
|---|---|---|---|---:|
| none (honest control) | true | true | PASS | 239,599,616 |
| wrong public key | false | false | PASS | 31,588,352 |
| wrong message | false | false | PASS | 28,835,840 |
| flip σ_1 root byte | false | false | PASS | 31,588,352 |
| flip PRF t_tag byte | false | false | PASS | 31,457,280 |
| bump o_responses[0] | false | false | PASS | 28,835,840 |
| bump final_coefs[0] | false | false | PASS | 186,122,240 |

**RISC0 result: 7/7 PASS.** Combined with SP1: **14/14 PASS across
both zkVMs.** Independent empirical evidence that the precompile path
correctly accepts honest signatures and correctly rejects each tested
tamper, on both target platforms.

The probe is **not** a complete characterisation of malicious-prover
behaviour — it covers six concrete tamper points. A reviewer asking
"why these six?" would get: they exercise σ_1 (root_c), σ_2
(o_responses), σ_5 (final_coefs) tampers — one per major component of
PLUM's 6-phase signature — plus the trivial wrong-pk/wrong-msg
cases. Adding STIR-stage tamper cases (flip a Merkle opening) is
future work.

## Property-table status (post-audit, post-probe)

Status legend: **PAPER-AUDITED** = the doc has a tight argument;
**EMPIRICALLY TESTED** = tests that would catch a regression exist;
**UPSTREAM-TRUSTED** = depends on an external audit citable but
not re-derived here; **UNVERIFIED** = currently has no support.

| Property | Status | Notes |
|---|---|---|
| (a) Reference math correct (PLUM §4.3) | UPSTREAM-TRUSTED | Proof-checker-audited against paper PDF (prior session). |
| (b) Reference matches precompile output | EMPIRICALLY TESTED + PAPER-AUDITED | Honest control of adversarial probe + reduction in §"Reduction itself". |
| (c) Operand canonicality (a, b < p) | PAPER-AUDITED | Structural (from_biguint) + domain (from_u64/u128). `to_limbs` guard catches regressions. |
| (d) Skip-mod output canonicality | PAPER-AUDITED (SP1) / UPSTREAM-TRUSTED (RISC0) | Quoted SP1 AIR constraint air.rs:435. RISC0 chip is opaque Zirgen; cite release process. `debug_assert` guards on both. |
| (e) Upstream chip soundness | UPSTREAM-TRUSTED | Pinned versions (sp1-core-machine 6.2.1, risc0-circuit-rv32im 4.0.4). Specific external audit URLs would strengthen this. |
| (f) Adversarial robustness (tampered sigs rejected) | EMPIRICALLY TESTED | Adversarial probe 7/7 PASS. Six tamper cases × {honest control}. |
| (g) ZK preserved | OUT-OF-SCOPE | Thesis claim is proof-time reduction, not ZK. SP1's ZK story is independent of this precompile. |
| (h) Composability with future Griffin AIR | PAPER-AUDITED (contract stated) | Cross-precompile output-range contract documented above; Griffin AIR must satisfy it. |

## Audit caveats (proof-checker findings flagged for the thesis defence)

The proof-checker audit (2026-05-16) flagged additional issues that
this revision **does not fully close**:

1. **Public audit citation for both chips** still missing. The doc
   says "production-used" / "release-audited" rather than naming a
   specific audit report. Closing this requires finding and citing
   the SP1 and RISC0 audit reports (or downgrading the
   UPSTREAM-TRUSTED claim to "production-used, full re-derivation
   deferred").

2. **Canonicality is structural for `from_biguint` but only domain
   for `from_u64`/`from_u128`/`rand`/`from_bytes_le`.** Safe today
   because all input domains fit `[0, p)`, but the invariant is
   "every Fp192 has `value < p`" rather than "every constructor
   reduces". The audit flagged refactoring to a single
   `canonical_unchecked` helper with an assertion. **Deferred** —
   the current code is correct, but a structural refactor would make
   the invariant easier to audit.

3. **EU-CMA reduction transfer is argued, not formally re-derived**
   over the precompiled `Fp192::mul`. PLUM §4.3's reduction is
   purely functional, so the transfer holds, but a thesis chapter
   could make the case stronger by explicitly re-deriving the
   reduction with `mul = syscall` substituted.

These caveats live in the soundness chapter of the thesis itself,
not as code TODOs. They're listed here so a thesis reviewer reading
this note can audit our awareness of the gaps.
