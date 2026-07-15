# FieldOpCols determinism — formal-verification de-risk prototype

**Date:** 2026-07-06  **Scope:** de-risk step 1 of a machine-checked under-constraint
(determinism) harness for the Griffin-Fp192 AIR. Target unit = the single
`FieldOpCols` limb-gadget (the thesis's `lem:limb-gadget`).
**No zkVM prove was run.** This is pure solver work.

## (a) Which solver

- **cvc5 1.3.4** (`bin/cvc5`, macOS-arm64 **static-gpl** — the GPL build bundles
  CoCoALib, required for the native finite-field / Groebner solver). Downloaded from
  the cvc5 GitHub release (not in Homebrew). `--version`: `cvc5 1.3.4 [git f3b21c4]`.
- **z3 4.15.4** (pre-installed, `/opt/homebrew/bin/z3`). Top-tier QF_BV engine.
- Picus: not installed (would sit on top of cvc5 anyway).

cvc5's native **finite-field theory** (`(_ FiniteField 2130706433)`, KoalaBear
`q = 2^31 - 2^24 + 1`) is confirmed working (smoke tests pass). **But it does not
scale**: the FF/Groebner backend with bit-decomposed range gadgets **timed out at
120s even for n=2** (both default `gb` and `split` solver modes, both `mul` and the
linear `add`). Root cause: idempotent bit constraints (`b*b=b`) define a Boolean
variety of 2^(hundreds) points that Groebner-basis blows up on. This is a known
limitation of raw FF solving, not an encoding bug.

**Workhorse = a sound bit-vector reduction (QF_BV).** Every gadget constraint's
integer value is `Sigma = p_vanishing_k - product_k`; with all limbs range-checked
(result/carry < 256, witness < 2^16, operands byte-canonical < 256),
`|Sigma| <= ~2.1M (op) + ~2.1M (carry*mod) + ~16.8M (256*witness) + 255 < ~21M`,
which is `< q/2 ~ 1.06e9`. Hence `Sigma == 0 (mod q)` <=> `Sigma == 0 over Z` for
every range-checked assignment — **no wraparound witness is reachable**. So the BV
model is faithful to the F_q AIR over the range-checked domain (this is the same
limb-magnitude side-condition `lem:limb-gadget` itself relies on). The byte-canonical
operand precondition is exactly the invariant the real code's **F2 fix** enforces
(`griffin_fp192/air.rs:369-395`: byte-sum operands push witness to ~2^25 > u16).

## (b) Did the encoding + query RUN

**Yes, end-to-end.** Fidelity guards both pass, on both solvers:

| Guard | file | z3 | cvc5 | meaning |
|---|---|---|---|---|
| Oracle (reference `populate()` witness) | `smt/oracle_mul_n2.smt2` | **sat** | — | constraints ADMIT the honest witness (encoding matches the algorithm in `field_op.rs`) |
| Negative control (one result byte +1) | `smt/negctl_mul_n2.smt2` | **unsat** | **unsat** | constraints REJECT a wrong witness (they have teeth) |

The oracle is a byte-exact Python mirror of `FieldOpCols::populate_carry_and_witness`
(synthetic division by `X-256`, `+WITNESS_OFFSET`), so a passing oracle means the SMT
constraints agree with the reference generator.

## (c) The RESULT

**The bare `FieldOpCols` limb-gadget is UNDER-CONSTRAINED (a determinism finding),
and adding the `result < p` canonicity check makes it DETERMINISTIC.**

- **FieldOpCols ALONE, n=2 mul:** `sat` in **1.38s** (z3). Explicit two-witness model:
  - operands `a=63751, b=21137`, `a*b=1,347,504,887`, `M=65521`.
  - copy 2 = honest: `result=1, carry=20566`.
  - copy 1 = alternate: `result=65522 (=1+M), carry=20565 (=carry-1)`; **identical witness**.
  - Both satisfy `result + carry*M = a*b` coefficient-wise, so `p_vanishing` (hence the
    witness) is unchanged. The gadget pins down only `result + carry*M`, i.e. **result
    is determined only mod M** — result and carry individually are NOT unique.
- **+ result<M canonicity, n=2 mul:** `unsat` — **deterministic**.
  - tight modulus (mod_bytes=2): cvc5 **94.21s**, z3 timed out at 120s.
  - loose modulus (mod_bytes=1): z3 **4.1s**, cvc5 **3.1s**.
- operand-canonical (a,b < M) alone does NOT fix it (still `sat`, 2.41s) — as predicted,
  the ambiguity is on the output side, not the input side.

**This matches the real code exactly.** The Griffin Fp192 AIR already pairs its
`FieldOpCols` cells with explicit `FieldLtCols` (`< p`) checks for this very reason:
`rc_add_range_check` ("**B-8** output canonicality: rc_add < p"),
`sbox1_cube_range_check`, `quad_mul_2/3_range_check` ("**F1 / Finding 4**: `< p`
canonicality"). The harness **independently rediscovered** the need for these checks
from first principles and confirmed they restore determinism. So `lem:limb-gadget` is
true **conditional on the companion result-canonicity check** — the bare gadget is
deterministic only up to the mod-M residue class.

## (d) At what size

- Fidelity guards + headline finding + its resolution: **full byte-canonical structure,
  n=2** (base 256, 3 witness limbs, WITNESS_OFFSET=2^14, exact `field_op.rs` constraints).
- Scale sweep (loose PLUM-like modulus, `sweep_results.log`):

```
== detection (SAT) ==            VARS   ASSERTS  result   time
n=2  det  z3                     18     9        sat      0.1s
n=4  det  z3                     38     17       sat      0.3s
n=8  det  z3                     78     33       sat      6.7s
n=16 det  z3                     158    65       timeout  90.0s
n=32 det  z3 (FULL gadget)       318    129      timeout  120.0s
== determinism proof (UNSAT), result<M ==
n=2  proof z3                    18     11       unsat    4.1s
n=2  proof cvc5                  18     11       unsat    3.1s
n=3  proof z3                    28     15       timeout  120.0s
```

Detection (finding bugs, SAT) is tractable to **n≈8**; the determinism **proof**
(UNSAT — the direction verification actually needs) is tractable only to **n≈2-3**.
The full gadget is **n=32**. The monolithic single-query encoding **does not reach it**.

## (e) HONEST scale assessment — does this compose to the full row / 7 families?

**No — not as a monolithic bit-blasted query. Composition REQUIRES decomposition.**

1. **The under-constraint phenomenon is n-independent and structural.** The mod-M
   result ambiguity at n=2 is the identical phenomenon at n=32; likewise polynomial-
   division uniqueness of the witness. These are algebraic facts, not things that need
   re-bit-blasting at n=32.
2. **Monolithic n=32 is infeasible** (detection times out by n=16; the UNSAT proof
   times out by n=3). A single 3,819-var row with 26 FieldOpCols + 7 families as one
   SMT query is far beyond that wall.
3. **The tractable, correct decomposition** (the "verify once, trust the instances"
   framing, made precise):
   - (i) **Per-gadget-TYPE determinism at small representative n**, WITH its
     canonicity side-conditions — this prototype does exactly this for FieldOpCols.
     There are only a handful of distinct gadget types (FieldOpCols mul/add,
     FieldLtCols, the S-box/MDS glue), not 26 unique problems.
   - (ii) **n-uniformity**: argue the constraint SHAPE is identical across limb count
     and the determinism proof (canonical-residue uniqueness + monic-division
     uniqueness) is independent of n. This is an algebraic argument (paper lemma or a
     proof assistant), NOT an SMT bit-blast.
   - (iii) **Composition across cells**: each gadget's `.result` is byte-bound to the
     next cell's operand (the air.rs "B-1 binding"); if every cell is deterministic
     given canonical inputs and every output is canonicalized (`< p`), the whole row is
     deterministic by induction. This composition lemma is checkable structurally.
   The SMT solver is a **component** (base cases + the canonicity side-conditions),
   not the whole verification.

**Net de-risk verdict.** The hard prerequisites are CLEARED: (1) a native FF solver is
installed and its theory works; (2) the gadget's constraints can be encoded faithfully
and validated against the reference generator; (3) the harness produces meaningful,
real answers — it found a genuine, developer-documented structural property (B-8/F1)
and confirmed its fix. The residual risk is NOT "can the tool check anything" (cleared)
but "monolithic scale" — and the resolution (decompose per-gadget-type + algebraic
n-uniformity/composition) is a known, standard shape. **The whole-harness estimate is
de-risked to the extent that the CHECK ITSELF works; but a fully-automated end-to-end
n=32 / 7-family run is NOT on the monolithic path and should be scoped as
decomposition, not brute force.**

## (f) Concrete next iteration

1. **Add the FieldLtCols determinism check as its own unit** (`range.rs` / `field_lt.rs`)
   — the companion the B-8/F1 finding shows is load-bearing. Same harness, `--op`-style
   extension.
2. **Compose gadget+canonicity as the real `lem:limb-gadget` statement**: verify
   `FieldOpCols(mul) + result<M` deterministic at n=2,3,4 as base cases; write the
   n-uniformity lemma (monic-division + canonical-residue uniqueness) as the general
   argument. The SMT runs are evidence for the base case, not the whole proof.
3. **Push the UNSAT direction** with (a) z3/cvc5 tactics tuned for BV validity (bit-blast
   + CaDiCaL), (b) fixing `a,b` symbolically to kill the `a*b` nonlinearity and checking
   witness-only determinism, (c) per-coefficient local determinism (each vanishing
   constraint is a small local check) instead of whole-gadget.
4. **Probe the F2 boundary**: run a determinism query with byte-SUM operands (max 510)
   to reproduce the witness > u16 over-range the developers documented — turns the F2
   comment into a machine-checked lemma about the operand-canonicity precondition.
5. **Automate IR extraction** (currently hand-encoded): emit the monomial list directly
   from `eval_with_polynomials` rather than by hand, so the 7 families come for free once
   the per-type + composition lemmas are in place.

## Files

- `gen_determinism_smt.py` — parametric SMT-LIB generator (BV default, FF cross-check),
  oracle mirror of `populate_carry_and_witness`, determinism/oracle/single modes.
- `run.sh` — reproduces the 4 headline queries + negative control.
- `run_sweep.sh` / `sweep_results.log` — the scale sweep above.
- `smt/*.smt2` — the concrete queries (oracle, negative control, determinism ±canonicity).
- `bin/cvc5` — the solver binary (gitignored; not committed).

Ground truth read: `submodules/sp1/crates/core/machine/src/operations/field/field_op.rs`,
`.../field/util_air.rs`, `submodules/sp1/crates/curves/src/fp192.rs`,
`submodules/sp1/crates/core/machine/src/syscall/precompiles/griffin_fp192/air.rs`.
