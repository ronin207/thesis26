# KEYSTONE chip-prove measurement (M4) — dedicated-chip vs host-served

Date: 2026-07-06
Machine: MacBook Pro M-series (18-core), main measurement batch already done (no timing contention).
Fork: `.claude/worktrees/thesis-restructure-criterion/sp1-fork` (sp1 v6.2.1), non-synced
`CARGO_TARGET_DIR` under scratchpad. Nothing committed.

Purpose: check the cost model's OUT-OF-SAMPLE prediction for the operator's two
non-Griffin precompile chips, so the abstract's "open positive case + specified
deciding experiment" can be resolved. Primary signal = deterministic
precompile-chip **trace area** (columns x rows), per the model's own definition.
Prove-time is a confounded secondary (see caveats). A falsified prediction is a
valid result and is reported as-is.

## Method

- Trace area is deterministic: each chip's column count = `size_of::<Cols<u8>>()`
  (every field is a `u8` under `#[repr(C)]`), obtained from rustc via an added
  print-only harness test `keystone_trace_area_geometry` in
  `crates/core/machine/src/syscall/precompiles/fp192_powres/mod.rs` (uncommitted,
  authorized harness work). Rows/op read from each chip's `num_rows`:
  - `UINT256_MUL`, `FP192_MUL`: 1 row per multiply syscall.
  - `FP192_POW_RES` (B2): 1 controller row + L=191 step rows per symbol.
- Supervisor-mode widths are the arm that fires in the smoke proves
  (`enable_untrusted_programs = false`).
- Exponent schedule cross-checked independently in Python from the guest modulus:
  p = 199-bit, e = (p-1)/256 = 191-bit (L=191), popcount(e)=70,
  guest-loop square-and-multiply muls = L + popcount = 261. Matches the harness.
- Completeness confirmed by the two dedicated prove smoke tests (execute + prove +
  verify), plus the host `test_uint256_mul`. All green.

## Raw captured output (verbatim)

Harness (`keystone_trace_area_geometry`):
```
KEYSTONE_GEOM WIDTHS(cols): uint256_mul_sup=371 uint256_mul_usr=419 fp192_mul_sup=304 fp192_mul_usr=352 powres_ctrl=73 powres_step=619
KEYSTONE_GEOM SCHEDULE: L(exp_bits)=191 popcount(set_bits)=70 guest_loop_muls=L+popcount=261
KEYSTONE_GEOM MUL_EXP(per 192-bit modmul, supervisor): dedicated_fp192_mul_cells=304 host_uint256_mul_cells=371 ratio_ded/host=0.8194
KEYSTONE_GEOM POWRES_EXP(per symbol, supervisor): B2_dedicated_cells=118302 (ctrl 73 + 191x step 619); host_uint256_cells=96831 (261x 371); host_fp192mul_cells=79344 (261x 304)
KEYSTONE_GEOM POWRES_RATIO: B2/host_uint256=1.2217 B2/host_fp192mul=1.4910
```

Execute-mode cycles (`test_fp192_powres_execute`):
```
B2 AIR: step_chip_width=619 cols, controller_width=73 cols, L=191 step-rows/eval (each step-row = 2 FieldOpCols) => 382 FieldOpCols/eval vs guest-loop 261 Fp192Mul-rows/eval
FP192_POW_RES execute-mode cycles: b2_precompile=365  guest_loop=6549
  guest_loop / b2 = 17.9x (execute-mode favors B2: 1 syscall vs ~261)
```

Prove smoke tests (completeness; wall time):
```
test_fp192_mul          : ok. 1 passed ("fp192-mul all tests passed")            finished in 12.32s  (22 FP192_MUL ops)
test_fp192_powres_prove : ok. 1 passed ("B2 == guest-loop == reference symbol")  finished in 15.55s  (runs BOTH arms in one guest)
test_uint256_mul        : ok. 1 passed ("All tests passed successfully!")         finished in 17.34s  (102 UINT256_MUL ops, NON-matched)
```

---

## Chip 1 — FP192_MUL (192-bit modular multiply)

Deciding experiment: dedicated FP192_MUL chip trace-area vs host UINT256_MUL-served,
per 192-bit modmul, matched op count (rows/op = 1 for both, so the comparison is the
column width).

| Arm | cells / op |
|---|---|
| Dedicated FP192_MUL (supervisor) | 304 |
| Host UINT256_MUL (supervisor) | 371 |
| ratio dedicated / host | **0.8194** |

Model prediction: "chip area >= host, so no pay."

**VERDICT: FALSIFIED (on the named trace-area metric).** The dedicated chip is
~18% SMALLER per op (304 < 371), not >=. Cause: FP192_MUL is a strict subtraction
from UINT256_MUL — hardcoding the modulus deletes the modulus-from-memory columns
(modulus_memory, IsZeroOperation, modulus_is_not_zero, and the modulus-pointer
address arithmetic). The 256-bit field slot (32 limbs) is identical, so the
FieldOpCols are the same width; the whole gap is the deleted modulus machinery.

Caveat (does not overturn the falsification, but bounds its reach): the model's
operative claim is about the marginal cost of adding a WHOLE NEW TABLE to the
machine (fixed per-chip overhead in the recursion/verify shape — the same
"precompile-paradox" the Griffin work already documented). The per-op trace-area
experiment does not measure that fixed overhead; on per-op area alone the dedicated
chip leans slightly toward paying (~18%), which the audit/engineering cost of a
custom chip for an 18% saving may or may not justify. Prove-time was not a clean
matched-op comparison (host guest = 102 ops vs dedicated guest = 22 ops).

## Chip 2 — FP192_POW_RES (power-residue PRF symbol, a^((p-1)/t) mod p) — the OPEN case

Deciding experiment: dedicated B2 chip vs host-served square-and-multiply, per symbol.

| Arm | cells / symbol | field-mul ops |
|---|---|---|
| Dedicated B2 (ctrl 73 + 191 x step 619) | 118,302 | 382 (both branches every step) |
| Host UINT256_MUL S&M (261 x 371) | 96,831 | 261 |
| Host FP192_MUL S&M (261 x 304) — de-facto in-repo baseline | 79,344 | 261 |
| B2 / host_uint256 | **1.2217** | |
| B2 / host_fp192mul | **1.4910** | |

Model: "may predict a pay (the one irreducibly-large-prime component); whichever
way it lands is valid."

**VERDICT on the PRIMARY signal (precompile-chip trace area): NO PAY.** The
dedicated power-residue chip is 1.22x (vs UINT256-served) to 1.49x (vs FP192_MUL-
served) LARGER, not smaller. Two structural reasons, both real:
1. B2 computes BOTH branches (sq AND prod) every step unconditionally = 382 field
   muls, vs the guest-loop's 261 (it skips the multiply on zero exponent bits).
   1.46x more field-multiply work.
2. Each B2 step row is very wide (619 cols), dominated by the MAX_STEPS=192 one-hot
   `is_step_r` selector plus two FieldOpCols + two FieldLtCols + chained
   acc_in/base/acc_out.

**COUNTER-SIGNAL (why the full-machine verdict is INCONCLUSIVE, not settled):**
the precompile-chip-only area excludes the RISCV base-machine cost of executing the
syscalls. B2 issues 1 syscall; the host S&M issues 261. Execute-mode cycles:
b2=365 vs guest_loop=6549 (17.9x; 6,184 fewer cycles for B2). Those saved cycles
become saved CPU/memory rows in the base machine that the chip-only area does not
count, and they point the OPPOSITE way. Whether B2 pays on TOTAL machine trace area
depends on whether ~6,184 saved RISCV cycles' worth of base-machine rows exceeds the
~21k (vs uint256) to ~39k (vs fp192mul) extra precompile cells. This measurement
does not isolate that (the powres guest runs both arms together, so a single prove
cannot separate them; a clean per-arm total-area comparison needs two single-arm
guest ELFs — not built here).

**Design caveat:** the "no pay" on chip area is partly an artifact of THIS B2 design.
The 192-wide one-hot selector and unconditional both-branch evaluation are design
choices; a leaner schedule binding (range-checked step_idx + preprocessed EXP_BITS
lookup) and/or conditional multiply could shrink the step row substantially and move
the chip-area verdict. The result is for the as-implemented B2, not a lower bound on
power-residue precompiles.

---

## Bottom line

- **FP192_MUL:** model prediction FALSIFIED on trace area — the dedicated chip is
  ~18% narrower per op (304 vs 371), because hardcoding the modulus deletes the
  modulus-memory columns. (Whether an 18% saving justifies a custom table is the
  separate marginal-overhead question the experiment does not measure.)
- **FP192_POW_RES (open positive case):** on the primary precompile-chip trace-area
  signal it lands NEGATIVE — the dedicated B2 chip is 1.22-1.49x LARGER than
  host-served square-and-multiply. But the 17.9x RISCV-side syscall-cycle reduction
  (365 vs 6549), which chip-only area excludes, points the other way, so the
  full-machine verdict is INCONCLUSIVE pending a per-arm total-area (two single-arm
  guests) or an end-to-end matched prove.
- All three chips prove-and-verify (completeness green).

Both results are honest as-measured; neither number was bent to fit the model.
