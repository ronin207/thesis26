# PLUM circuit baseline: custom Aurora-over-Fp192 SNARK build

**Goal.** Produce a circuit-side proving baseline for `PLUM.Verify` so the
thesis can compare circuit-oriented vs zkVM proving of the *same* relation
over the *same* prime. Today only a zkVM-side number exists (SP1 Cells); the
Aurora "Cell 4" is a Loquat-Fp127 proxy, NOT PLUM (PLUM is STIR over Fp192;
the Fp127 libiop harness cannot run it). See `docs/r_static_finding_20260605.md`.

**Decision (2026-06-22).** Build the custom SNARK (Path A). Staged with a
verification gate per stage; if Stage 4 (STIR-in-R1CS) stalls, ship Stages 1-3
as the ~90%-of-constraints Merkle-Griffin term and fall back to the paper's
§4.2 algebraic decomposition for the rest (the "defensible estimate" exit).

## Stage map

| Stage | What | Status |
|---|---|---|
| 1 | Fp192 base field in libff (no Fp2; base-field s=64) | ✅ DONE, gated |
| 2 | Griffin-Fp192 permutation as R1CS gadget | ✅ DONE, gated (304 constraints) |
| 3 | t=256 power-residue PRF symbol check as R1CS | ✅ DONE, gated (287 constraints) |
| 4 | STIR inner-IOP verifier as R1CS (the cliff) | Operator chose COMPLETE; decomposed 4a/4b/4c |
| 4a | Merkle-path verify gadget (Griffin-Fp192 hash) | ✅ done, gated (1245/path, depth 4; root bound) |
| 4b | Polynomial gadgets (eval, lagrange, vanishing, degree-correction) | ✅ done, gated (inverses constrained) |
| 4c | STIR assembly -> full PLUM.Verify | decomposed below |
| 4c-1 | Griffin-Fp192 sponge (absorb/squeeze) + leaf/byte hash | in progress |
| 4c-2 | Fiat-Shamir transcript replay — GRIFFIN-FS | ✅ done, gated (canonical extraction; 2 soundness holes closed) |
| 4c-3a | Poly multiply + divide_by_linear gadgets | ✅ done, gated (quotient identity-bound) |
| 4c-3b | One STIR fold round (fold + Merkle open + degree-correct) | in progress |
| 4c-3c | OOD consistency + final-poly fiber check | |
| 4c-4 | Top-level PLUM.Verify assembly + public-input designation | |
| 4c-4 | Top-level PLUM.Verify assembly + public-input designation | |

### MAJOR FINDING (2026-06-22): PLUM Fiat-Shamir is SHAKE256, not Griffin
`transcript.rs:77-86` — every squeeze is `shake256_expand(state‖ctr‖label)`; the `H`
(Griffin/SHA3) param is PhantomData and does NOT affect the squeeze. `verify.rs:196-223`
does many squeezes. A faithful circuit needs Keccak-in-R1CS (~150k constraints/perm x many
perms x dozens of squeezes = millions of constraints), which would dominate and contradict
the §4.2 Griffin-91% premise. SHAKE256 is a zkVM-friendly FS choice (Keccak precompile) that
is circuit-hostile — a clean instance of the thesis's substrate-dependence. DECISION PENDING:
(A) Griffin-FS in circuit [reuse 4c-1 sponge, paper-faithful, days], (B) exclude FS / challenges
as public inputs [measure algebraic core, fastest], (C) Keccak-in-R1CS [faithful to impl, weeks,
wrong number]. Recommended A or B, not C.

### Stage 4c assembly-layer obligations (accumulating — must all hold for the full circuit to be sound)
1. The Merkle `claimed_root` must be a transcript-committed/public wire, NOT a free witness (else prover sets claimed_root = computed_root). [from 4a]
2. Fiat-Shamir transcript replay must be in-circuit (challenges derived from committed data, not free).
3. Leaf-hash gadget (byte-sponge PlumGriffinHasher::hash_bytes) once per opening — 4a covers only internal-node compressions.
4. The Fp192 R1CS builder has no public-input/witness distinction; the Aurora-feeding layer (Stage 5) must designate the public inputs.
5. Linear-folding methodology (Stage 2, 304 vs ~110) — settle before reporting any constraint/cost number.
| 5 | Instantiate libiop Aurora over Fp192, prove+verify | |
| 6 | Land as the PLUM circuit baseline in four_scheme_benchmark | |

## Stage 1 (DONE)

Artifacts:
- `scripts/compute_fp192_constants.py` — self-verifying constant derivation.
- `submodules/libiop/depends/libff/libff/algebra/curves/fp192/fp192_fields.{hpp,cpp}`.
- one line in `submodules/libiop/depends/libff/libff/CMakeLists.txt`.

Prime (byte-identical to `src/primitives/field/p192.rs::MODULUS_LIMBS`):
`p = 0x4c455e221a5f68af517bbd7e10d66d13710000000000000001` (199-bit),
`p - 1 = 2^64 * p_0`, `p_0` prime, `root_of_unity = 3^{p_0}` (order exactly 2^64).

Gates passed: field math (Python), on-disk-vs-recomputed transcription (exact),
standalone compile, runtime self-consistency (inverse, rou order 2^64,
`get_root_of_unity(2^17)`), and external ground truth (libff mul/add/wrap/div
== Python big-int).

Caveat carried forward: substitute prime (paper `p_0` composite). Valid for
cycle/timing/constraint counts (bit-width + 2-adicity preserved); NOT valid for
any claim conditioned on the specific value of `p`. Action item: confirm
canonical `p_0` with PLUM authors.

Not yet established (Stage 5 risk): that Aurora actually instantiates/proves
over base Fp192. Recon argues yes (field-generic prover, s=64 suffices); not
yet demonstrated.

## Stage 2 (DONE)

Artifact: `src/primitives/r1cs/griffin_fp192_gadget.rs` (new parallel module over the
Rust Fp192 field; the existing Fp127-monomorphized Loquat R1CS layer was left untouched),
registered in `src/primitives/r1cs/mod.rs`.

Gates passed (run serially as `cargo test --lib griffin_fp192`, 0.02 s):
- `griffin_fp192_gadget_matches_software_and_is_satisfied` — output equals the software
  `griffin_p192` permutation AND the correct witness satisfies all constraints (fidelity +
  completeness; also confirms params are PLUM's d=3 / 14-round / width-4 / cap-2, since a
  wrong constant would diverge).
- `corrupted_witness_is_rejected` — a tampered witness violates a constraint (soundness vs
  under-constraining).

Cost: **304 constraints, 309 variables per permutation.** This is ~2.8x the paper's §4.2
~110 R1CS/compression because the gadget MATERIALIZES every linear operation (linear_form,
MDS layer, round-constant adds) as its own constraint+variable, while the paper counts only
multiplicative constraints (linear folds for free in optimal R1CS). HONEST but non-folded.
**Decision deferred to Stage 5/6:** either fold linear constraints to match the paper, OR
keep this style but apply it identically to the Loquat circuit baseline so the cross-scheme
comparison stays apples-to-apples — and report the methodology. Do not report a prover-cost
number without resolving this.

LESSON (build infra): running multiple cargo-invoking verifier agents in `parallel()`
deadlocks on cargo's build-directory lock (processes sleep at 0% CPU). Stage-2's verify phase
stalled ~24 min this way. Fix: at most ONE cargo-running agent at a time per stage.

## Stage 3 (DONE)

Same module `src/primitives/r1cs/griffin_fp192_gadget.rs`. Builds the t=256 power-residue
PRF symbol check: `symbol = shifted^((p-1)/256)` via a new `pow_const_biguint` (full ~191-bit
BigUint exponent, NOT u128-truncated), then binds the integer PRF output i (the value PLUM
`verify.rs:251` consumes) as 8 boolean-constrained wires, recomputes `ω^i` in-circuit from
those bits, enforces `symbol == ω^i`, and exposes the bits + index as constrained wires.

**287 constraints/symbol.** (264 before the index-binding fix; +23 for binding i.)

Soundness story: a proof-checker audit FIRST caught that the original gadget constrained only
the field-element symbol, leaving the consumed integer i unconstrained (under-constraining +
cost-undercount). Fixed and re-audited clean; forged-index attack (even fully-consistent
forgery for every wrong j in [0,256)) is rejected. OWED: a written soundness argument tying
these R1CS constraints to the spec (thesis requires one per AIR module).

## Stage 4 decision point — Complete vs Cost-faithful estimate

Stages 1-3 built the reusable primitives (Griffin-Fp192 gadget = the ~90% Merkle term; PRF
gadget). Stage 4 is the STIR verifier assembly. Two paths (await Operator's choice):
- **A Complete:** fully arithmetize the STIR verifier (FS replay, fold loop, degree
  correction, Lagrange/OOD, 4-tree Merkle). Weeks, high risk; yields a functionally-correct
  PLUM circuit + exact measured cost.
- **B Cost-faithful estimate (recommended for a cost thesis):** pin PLUM.Verify's constraint
  profile (Griffin gadget x #permutations + PRF x #symbols + paper §4.2 algebraic remainder),
  generate a structurally-faithful R1CS of that size, and measure Aurora-over-Fp192 prover time
  on it. Days, low risk; Aurora cost is governed by (#constraints, #vars, FFT domain), not the
  semantic correctness of each constraint. Claim scoped to "Aurora cost for a PLUM.Verify-profile
  circuit; functional STIR arithmetization is future work."
Both still need the Stage-2 linear-folding methodology resolved before any number is reported.

## Stage 2 entry notes (historical)

Port the Griffin gadget *shape* from the 5,945-line Loquat
`src/signatures/loquat/r1cs_circuit.rs` (`griffin_permutation_circuit` at :5794,
nonlinear/linear/round-constant layers at :5808/5857/5887). Re-target to
PLUM Griffin-Fp192: d=3, 14 rounds, 4 lanes, capacity 2
(`src/primitives/hash/griffin_p192.rs:167`, rounds :585, d :562). The Rust R1CS
layer (`src/primitives/r1cs/mod.rs`) is monomorphized to Fp127 — the field must
be swapped to Fp192 or the layer made generic. Gate: gadget output matches the
in-tree software Griffin-Fp192 on test vectors.
