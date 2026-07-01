# Soundness note — Precompile #3 "B2": composed power-residue PRF `FP192_POW_RES`

**Status: SOUND + COMPLETE — smoke-proven end-to-end (2026-07-01).**
Constraint-level soundness closed (Path-A wiring + adversarial `proof-checker`
re-verify, agent `a51c1ada`); completeness then demonstrated by a core STARK
smoke-prove (`test_fp192_powres_prove`, 370 s — see the completeness note at the
end). B2 is now validated at the same core-prove level as Griffin. B2 is the first instantiation of the thesis's precompile
interface that *composes* an existing sound gadget rather than subtracting
from one. Its field arithmetic is inherited unchanged from the audited
`FieldOpCols` (exactly as B1); the new, load-bearing obligation was the
fixed-exponent square-and-multiply schedule↔selector equality (F7) plus the
square-and-multiply chain balance (F8).

**Closure verdict (proof-checker, adversarial break-attempts constructed and
refuted per property):**
- **Chain binding CLOSED** — LogUp multiset balance over the (clk,ptr,a)
  fingerprint (kind=23, emitted by exactly the two fp192_powres chips) forces
  `acc_0=1`, `base≡a` on every row, `acc_out_k=acc_in_{k+1}`, and
  `symbol=acc_L`. Skip / repeat / cross-syscall-splice / self-contained
  phantom-chain / `symbol≠acc_L` all break balance (directions strictly
  increase, so no phantom chain self-balances without the controller anchor).
- **Off-by-one CLOSED** — `assert_zero(is_step_r[exp_bit_len()..MAX_STEPS])`
  + one-hot + `Σr·is_step_r=step_idx` pin `step_idx∈{0..190}`; phantom
  step-191 / direction-192 unreachable.
- **Byte injectivity CLOSED** — `slice_range_check_u8` on `acc_in`/`base`
  makes the u16 payload composition injective; non-byte packing dead.
- **Payload sufficiency CLOSED** — the 38-value fingerprint binds every
  output-determining field (clk, ptr, direction, acc, base).
- **No new false-accept hole.** Two *hardening* notes (missing step-chip
  not-mprotect guard — safe via the flow argument but recommend an explicit
  guard for defense-in-depth; redundant `is_first/last_step` flags — belt-
  and-suspenders, soundness-irrelevant).

Rests on three inherited (non-B2-specific) assumptions: LogUp/permutation
soundness, the `FieldOpCols` 32-limb operand budget, and unique authentic
(clk,ptr). `L=191` is runtime-computed but non-load-bearing (constraints are
symbolic in `exp_bit_len()`).

**Completeness is DEMONSTRATED (2026-07-01, `test_fp192_powres_prove`).** The
chip now runs end-to-end: execute + core STARK prove + verify all pass (370 s);
the guest asserts `B2 == guest-loop == reference a^((p-1)/256) mod p`, and the
191-row step trace + controller + cross-chip `Fp192PowRes` lookup balance into a
valid proof. The MachineAir impls + trace generators + registration were written
(the ~400-line plumbing); `RiscvAir` internal consistency assertions
(chips==discriminants, chips==costs) pass. **No soundness constraint was
weakened** — the single bug found was a trace-gen element-vs-row slicing fix.
The step-chip not-mprotect guard was added (defense-in-depth).

So B2 is now validated at the **same core-prove level as Griffin**: constraint-
level soundness (adversarially closed) + completeness (smoke-proven). Caveats:
(i) CORE prove only — the recursion/compress shape is deferred, as with Griffin's
own smoke-prove; (ii) the user/mprotect path is disabled by the guard (no page-
prot columns), so it is not sound for a real user path — out of scope for this
core-prove validation.

Build artifacts (isolated SP1 fork-worktree, branch `prf-precompiles`):

- executor compute: `crates/core/executor/src/fp192_powres_compute.rs`
  (native reference + the S&M chain; 5/5 unit tests pass, incl.
  `chain_matches_modpow`, `symbol_is_t_th_root_of_unity`).
- event: `crates/core/executor/src/events/precompiles/fp192_powres.rs`.
- tracing + minimal handlers: `vm/syscall/fp192_powres.rs`,
  `minimal/precompiles/fp192_powres.rs`; syscall code
  `FP192_POW_RES = 0x00_01_01_37`; guest entrypoint `syscall_fp192_powres`.
- AIR chips: `crates/core/machine/src/syscall/precompiles/fp192_powres/air.rs`
  (`Fp192PowResControlChip` + `Fp192PowResStepChip`; **compiles**,
  column layout + `eval` constraints + `populate_step_rows`).
- guest + measurement: `crates/test-artifacts/programs/fp192-powres/`,
  test `test_fp192_powres_execute` (execute-mode, passes).

**Integration status (honest).** The two chips compile and their
constraints + trace-generation are written, BUT they are **not yet
wired into the `RiscvAir` enum / cost table / recursion shape**, and the
cross-step `InteractionKind::Fp192PowRes` lookup is **specified but not
registered**. Consequently B2 has been **executed and verified for
correctness (symbol == guest-loop == BigUint reference), but has NOT
been smoke-proven**. See §5.

---

## 1. What B2 is

One `FP192_POW_RES` syscall computes the entire PRF symbol
`a <- a^((p-1)/t) mod p`, `t = 256`, over PLUM's 199-bit prime `p`.
Both `p` and the exponent `e = (p-1)/256` (bit length `L = 191`) are
chip constants. Structure = the Griffin controller / per-round split:

- **Controller** (1 row/syscall): binds `a` (read) + symbol (write) in
  memory, receives the syscall, and anchors the lookup chain — SENDs
  `(acc=1, base=a)` at `direction=0`, RECEIVEs `(acc=symbol)` at
  `direction=L`.
- **Per-step** (`L=191` rows/syscall): each row is one S&M step —
  `sq = acc_in^2`, `prod = sq·base`, `acc_out = bit ? prod : sq` — and
  chains via the `Fp192PowRes` lookup (RECEIVE at `direction=step_idx`,
  SEND at `direction=step_idx+1`). The exponent bit is a **preprocessing
  selector**, bound to the fixed schedule through a one-hot column.

## 2. The three interface properties

**(i) I/O equivalence over F_p.** *The syscall output equals
`a^((p-1)/t) mod p`.* Unlike B1 (where this rested on a **guest** S&M
loop and was explicitly *not* an in-circuit claim), B2 moves the S&M
chain **into the AIR**. So (i) decomposes into:
  - each step's `sq` and `prod` equal `acc_in²` resp. `sq·base` mod p —
    **inherited-provable** from `FieldOpCols::eval` (F1–F4);
  - the steps compose into `a^e` for the *fixed* `e` — this is the
    **new obligation F7 (schedule↔selector) + F8 (chain balance)**,
    argued in §3, only **partially discharged** (§4).

**(ii) Isolation via cross-table lookup.** Inherited for the syscall
boundary (`receive_syscall` on the controller, as B1/Griffin). B2 adds
an *internal* `Fp192PowRes` send/receive between controller and step
chips; its multiplicity balance is the Griffin-controller argument
transplanted (F8). **Provable by analogy, but not yet exercised (the
lookup is unregistered).**

**(iii) Constant preprocessing-bound modulus AND exponent.** Inherited
for the modulus (`Fp192FieldParams::MODULUS`, audit B-10). B2 adds a
second constant — the **exponent schedule `EXP_BITS`** — baked into the
`eval` as compile-time constants (the analogue of Griffin's baked round
constants). A malicious prover can choose neither the field nor the
exponent per row *provided F7 holds*.

## 3. Per-family breakdown (analogue of Griffin's Appendix B)

| Family | Statement | Source | Status |
|---|---|---|---|
| F1 modular-multiply reduction (`sq`, `prod`) | `FieldOpCols::eval_with_modulus` | audited (inherited) | **PROVABLE (inherited)** |
| F2 carry / u8-u16 range | `FieldOpCols` witness + byte lookups | inherited | **PROVABLE (inherited)** |
| F3 output canonicality `<p` (`sq_range`, `prod_range`) | `FieldLtCols::eval` | inherited | **PROVABLE (inherited)** |
| F4 constant modulus | `Fp192FieldParams::MODULUS` const | inherited (B-10) | **PROVABLE (inherited)** |
| F5 memory binding (a read+write) | `eval_memory_access_slice_write` (controller) | inherited | **PROVABLE (inherited)** — *controller `eval` not yet landed* |
| F6 syscall multiplicity | `receive_syscall` (controller) | inherited | **PROVABLE (inherited)** — *not yet landed* |
| **F7 schedule ↔ selector equality** | active bit at step k = `EXP_BITS[k]`, the fixed exponent | **NEW** | **PARTIAL — see §4** |
| F8 accumulator/chain balance | step k SENDs `acc_out` at dir k+1; step k+1 RECEIVEs it at dir k+1; controller anchors dir 0 / dir L | Griffin-controller transplant | **PROVABLE by analogy — not yet registered** |

### F7 — what is actually constrained (the contribution)

The step chip commits a one-hot vector `is_step_r[0..192]` and, when
`is_real`, constrains (implemented in `air.rs::eval`):

1. **exactly-one-hot:** `Σ_r is_step_r[r] = 1`, each `is_step_r[r]`
   boolean;
2. **index binding:** `Σ_r r·is_step_r[r] = step_idx`;
3. **active bit:** `active_bit = Σ_r is_step_r[r]·EXP_BITS[r]`, with
   `EXP_BITS` the compile-time exponent bits;
4. **selection:** `acc_out[i] = sq[i] + active_bit·(prod[i] − sq[i])`
   (limb-wise);
5. **boundary:** `is_first_step ⇒ step_idx=0 ∧ acc_in=1`;
   `is_last_step ⇒ step_idx=L−1`.

**What this proves at the constraint level:** *given* that `step_idx`
takes each value in `{0,…,L−1}` exactly once per syscall, constraints
(1)–(3) force `active_bit` on the `step_idx=k` row to equal the fixed
constant `EXP_BITS[k]` — the prover cannot substitute a different bit
schedule. Combined with (4) and F1–F4, the per-row transition is
exactly `acc_{k+1} = EXP_BITS[k] ? acc_k²·a : acc_k²`, and with the
boundary (5) the composition over `k=0..L` is `a^e mod p` for the
**fixed** `e`. That is the intended power-residue exponent.

## 4. Honest gaps (do NOT overclaim)

1. **F7 is only PARTIALLY discharged: it rests on the F8 chain
   forcing `step_idx` to be a permutation of `{0,…,L−1}`.** The
   one-hot + index-binding constraints pin `active_bit` to
   `EXP_BITS[step_idx]` *on each row*, but they do **not by themselves**
   force the *set* of `step_idx` values across a syscall's rows to be
   exactly `{0,…,L−1}` with no repeats/omissions. That completeness is
   supposed to come from the F8 lookup chain (each `direction` value
   `1..L` is produced once by a SEND and consumed once by a RECEIVE, so
   the steps must form a single 0→L path). **Until the F8 lookup is
   registered and the whole thing smoke-proves, F7's completeness is an
   ASSUMPTION, not a verified fact.** This is the exact analogue of
   Griffin's open `asm:air` chip-constraint-equality caveat, and it is
   the item most needing review. A malicious prover who could break the
   chain (e.g. repeat a favourable `step_idx`) is only excluded if F8
   balances — which is unproven here.

2. **Controller `eval` (F5/F6) and the F8 send/receive are written in
   the design but NOT yet in code.** `air.rs` currently lands the step
   chip's arithmetic + F7 constraints and the controller *column
   layout*; the controller's memory-binding/`receive_syscall`/lookup-
   anchor `eval` and the step chip's lookup send/receive are deferred to
   the `RiscvAir` integration step. So the present artifact is
   **not provable as-is**; it is a compiling, constraint-complete
   *core* (F1–F4, F7-per-row) plus a specified-but-unwired boundary.

3. **Executor ⇄ reference drift.** `Fp192FieldParams::MODULUS`,
   `griffin_fp192_compute::MODULUS_LIMBS`, and the exponent
   `(p-1)/256` derived from them must stay byte-identical. Guarded by
   `fp192_powres_compute::tests::{modulus_matches_canonical_decimal,
   exponent_is_p_minus_1_over_t}`. Assumption = "the drift tests are
   complete."

4. **Substituted prime (project-wide).** Every statement is over the
   substituted 199-bit prime, not PLUM's printed (composite) `p_0`;
   conditioned on the substitution (CLAUDE.md action item).

5. **dlog_ω stays in the guest.** As in B1, the final 256-entry
   discrete-log map `dlog_ω` that turns the symbol `y ∈ ⟨ω⟩` into an
   index is a guest table, not in-AIR. B2 certifies `y`, not the index.

## 5. Verification performed

- `cargo test -p sp1-core-executor --lib fp192_powres_compute` — 5/5.
- `cargo check -p sp1-core-machine --lib` — clean (both chips compile).
- `cargo test -p sp1-core-machine --release test_fp192_powres_execute`
  — **pass (execute-mode)**. The guest computes one symbol via B2's
  single `FP192_POW_RES` syscall AND via a guest square-and-multiply
  loop over `FP192_MUL`, and asserts both equal a `BigUint` reference.
  Correctness of the B2 executor path is thus established end-to-end.
- **Smoke-prove: NOT performed.** The `RiscvAir` wiring + F8 lookup
  registration are the remaining step; without them the step/controller
  chips emit no proving rows. This is the honest "where it is stuck".

## 6. Does the interface carry? (METHOD claim)

**Yes, structurally — with one genuinely new proof obligation.** The
i/o-equivalence, isolation, and constant-parameter properties all
instantiate for the modexp exactly as the FORECAST predicted, and the
field arithmetic is reused verbatim from B1/`FieldOpCols`. The soundness
argument has the *same shape* as Griffin's (per-family table, cross-chip
lookup, baked constants). The one thing that does **not** come for free
— and that B1 did not have — is F7/F8: the fixed-exponent schedule must
be tied to the selector and the chain forced by the lookup. Per the
FORECAST's own soundness gate, **"a family" is earned only when this
constraint-level soundness is established, not when it merely
smoke-proves** — and here F7's completeness is still an assumption. So
the correct claim today is: *the interface carries and the construction
is built and correctness-verified; the schedule-soundness (F7/F8) is
drafted and partially discharged, pending the lookup wiring + review.*
