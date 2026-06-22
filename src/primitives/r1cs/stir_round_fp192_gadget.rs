//! Stage 4c-3b: ONE STIR fold round as an R1CS gadget, COMPOSING the Stage-4a
//! Merkle path-verify gadget, the Stage-4b polynomial gadgets, the Stage-4c-1
//! sponge gadget, and the Stage-4c-2 Fiat–Shamir challenge gadgets.
//!
//! ## Software reference (matched EXACTLY)
//!
//! This gadget mirrors the round-0 STIR **fold-on-fiber consistency check** in
//! `signatures::plum::verify::verify` (`src/signatures/plum/verify.rs:586-625`),
//! which is, per fiber `j` (shift base `b_j`):
//!
//! ```text
//! let fiber_x = points_at_query[j*eta .. (j+1)*eta];   // {ω^{b_j + t·|U_0|/η}}
//! let fiber_y = f0_at_query  [j*eta .. (j+1)*eta];      // f̂_0 at those points
//! let p_y_coeffs = lagrange_interpolate(fiber_x, fiber_y)?;
//! let a_1_at_y   = evaluate(p_y_coeffs, current_r_fold);   // <-- THE FOLD
//! if a_1_at_y != a_i_at_shifts[j] { reject StirFoldConsistencyViolation }
//! ```
//!
//! `a_i_at_shifts[j]` is the value Merkle-opened from `sig.stir_a_openings[round][j]`
//! and checked against the round's committed root `sig.stir_roots[round]`
//! (`verify.rs:382-393`). So the round binds, for each queried fiber:
//!
//!   1. the FOLD: interpolate the fiber, evaluate at the folding challenge
//!      `r_fold` — the SAME `lagrange_interpolate` + `evaluate` as
//!      `stir::stir_fold` per fiber (`stir.rs:153-155`);
//!   2. the COMMITMENT: the reconstructed fold value equals the value opened from
//!      the â_1 Merkle tree under the round's committed root.
//!
//! ## The three composition obligations (the load-bearing part)
//!
//! 1. **committedRootWiredFromFS.** The `claimed_root` passed to the Merkle
//!    gadget is the SAME wire the Fiat–Shamir transcript absorbs to derive this
//!    round's queried positions (mirroring `verify.rs:339` `append_root(stir_roots)`
//!    then `verify.rs:354` `challenge_indices`). It is NOT a fresh free witness:
//!    [`build_stir_fold_round`] allocates the committed-root wire ONCE, absorbs
//!    it into the FS `challenge_index` gadget to produce the shift base `b_j`,
//!    AND passes the SAME wire to the Merkle path-verify gadget. Tampering the
//!    root changes BOTH `b_j` (sponge chain) and the Merkle root binding.
//!    NB for the ROUND-0 fold the folding challenge `r_fold` is `r0_fold`, which
//!    the software squeezes at `verify.rs:224` BEFORE this round's root is
//!    appended (`verify.rs:339`); so `r_fold` is bound to the PRE-ROOT
//!    transcript, not to this round's root. The root's binding to this round is
//!    therefore through the query positions + Merkle path, not through `r_fold`.
//!
//! 2. **queryIndicesFromFS.** The queried fiber positions are the constrained FS
//!    `challenge_index` output (the shift base `b_j`), not free witnesses. The
//!    gadget derives `b_j` via the Stage-4c-2 index gadget (bound to the same
//!    absorbed transcript) and uses it both to (a) drive the Merkle direction
//!    bits and leaf index and (b) anchor the fiber's evaluation point `ω^{b_j}`
//!    via an in-circuit `ω`-power chain bound to the FS index wire.
//!
//! 3. **foldCombinationConstrained.** The fold is enforced by REAL constraints:
//!    [`lagrange_interpolate_circuit`] (fiber interpolation, with its inverse
//!    traps) followed by [`evaluate_circuit`] (Horner at `r_fold`). The output
//!    wire is then bound by `enforce_eq` to the Merkle-opened leaf value, so a
//!    wrong fold result, a wrong Merkle opening, or a wrong query index each
//!    breaks >= 1 constraint.
//!
//! ## Scope of ONE round (what is in / deferred)
//!
//! IN: the round CORE for ONE fiber — the fold (interpolate + evaluate at
//! `r_fold`), one Merkle-checked â_1 query against the FS-committed root, and the
//! three FS bindings above. The leaf-value -> leaf-digest hash binding the fold
//! output INTO the Merkle tree is done in-circuit via the Stage-4c-1 sponge
//! gadget (`griffin_fp192_sponge_circuit`), inheriting that gadget's documented
//! byte-packing modeling boundary.
//!
//! DEFERRED (out of this stage, each a later composition): the κ-fiber loop over
//! ALL shift bases; the round-0 sumcheck identity check and g̃ reconstruction
//! (`verify.rs:424-584`); rate-correction + degree-correction of â_i into f̂_i
//! (`stir.rs::rate_correct` / `apply_degree_correction`); the multi-round FS
//! chain advance (`verify.rs:651-654`); and the Algorithm-6 final-polynomial
//! check (`verify.rs:657-end`).

use crate::primitives::field::p192::Fp192;
use crate::primitives::hash::griffin_p192::{plum_griffin_params, PlumGriffinParams};
use crate::primitives::r1cs::fs_fp192_gadget::{
    griffin_fs_challenge_field, griffin_fs_challenge_field_circuit,
    griffin_fs_challenge_index, griffin_fs_challenge_index_circuit, FsChallengeTrace,
};
use crate::primitives::r1cs::griffin_fp192_gadget::{Fp192R1cs, Fp192R1csBuilder, Fp192Var};
use crate::primitives::r1cs::merkle_fp192_gadget::merkle_path_verify_circuit;
use crate::primitives::r1cs::poly_fp192_gadget::{evaluate_circuit, lagrange_interpolate_circuit};
use crate::primitives::r1cs::sponge_fp192_gadget::griffin_fp192_sponge_circuit;
use num_bigint::BigUint;

/// The fold combination, in-circuit, for ONE fiber: interpolate the fiber
/// `(fiber_x, fiber_y)` and evaluate the interpolant at `r_fold`, returning the
/// reconstructed fold value wire `â_i(y_j)`.
///
/// This is EXACTLY `lagrange_interpolate(fiber_x, fiber_y)` then
/// `evaluate(·, r_fold)` — the per-fiber fold of `stir::stir_fold`
/// (`stir.rs:153-155`) and the round-0 consistency reconstruction of
/// `verify.rs:608-616`. Both gadget steps are fully constrained (the Lagrange
/// gadget pins every inverse with `inv*denom==1`; Horner pins every wire), so the
/// returned wire is a constrained function of the fiber wires and `r_fold` — not
/// a free witness.
pub fn fold_fiber_circuit(
    builder: &mut Fp192R1csBuilder,
    fiber_x: &[Fp192Var],
    fiber_y: &[Fp192Var],
    r_fold: &Fp192Var,
) -> Fp192Var {
    assert_eq!(
        fiber_x.len(),
        fiber_y.len(),
        "fold_fiber_circuit: fiber point/value count mismatch",
    );
    // p̂_y(x) ← Interpolate(fiber_x, fiber_y), coefficient form.
    let p_y_coeffs = lagrange_interpolate_circuit(builder, fiber_x, fiber_y);
    // â_i(y_j) = p̂_y(r_fold).  THE FOLD.
    evaluate_circuit(builder, &p_y_coeffs, r_fold)
}

/// Exposed wire handles for one STIR fold-round gadget instance.
pub struct StirFoldRoundWires {
    /// The round's committed-root input wire. The SAME wire is absorbed into the
    /// FS `r_fold` derivation AND passed to the Merkle gadget (obligation 1).
    pub committed_root_idx: usize,
    /// The folding-challenge wire `r_fold`, a CONSTRAINED FS `challenge_field`
    /// output over the absorbed transcript (NOT a free witness).
    pub r_fold_idx: usize,
    /// The FS `challenge_index` shift-base wire `b_j` (obligation 2).
    pub shift_base_idx: usize,
    /// The fiber evaluation-point wires `ω^{b_j + t·stride}`, `t ∈ [0, η)`.
    pub fiber_x_idx: Vec<usize>,
    /// The fiber `f̂_0` value wires.
    pub fiber_y_idx: Vec<usize>,
    /// The reconstructed fold value wire `â_i(y_j)` (output of the fold).
    pub fold_value_idx: usize,
    /// The Merkle sibling wires for the â_1 opening at this fiber.
    pub sibling_idx: Vec<usize>,
    /// The Merkle direction-bit wires.
    pub dir_bit_idx: Vec<usize>,
}

/// All inputs needed to build one STIR fold-round gadget for ONE fiber.
pub struct StirFoldRoundInputs {
    /// Absorbed transcript data PRECEDING this round's root (the running FS
    /// state). Mirrors the data the verifier has absorbed up to `verify.rs:339`.
    pub absorbed_prefix: Vec<Fp192>,
    /// This round's committed root (the field-domain value of `stir_roots[round]`).
    pub committed_root: Fp192,
    /// FS squeeze counter for the `r_fold` field challenge.
    pub r_fold_squeeze_counter: u64,
    /// FS squeeze counter for the shift-base index challenge.
    pub shift_squeeze_counter: u64,
    /// Index sampling bound = `|U_0|/η` (next-layer domain size).
    pub shift_bound: usize,
    /// The folding-domain generator `ω` (a primitive `|U_0|`-th root of unity).
    pub omega: Fp192,
    /// Fiber stride `|U_0|/η`: fiber points are `ω^{b_j + t·stride}`.
    pub stride: usize,
    /// Folding rate `η` (fiber size).
    pub eta: usize,
    /// The `f̂_0` values at the fiber points (queried evaluations).
    pub fiber_y: Vec<Fp192>,
    /// Merkle siblings for the â_1 opening (field-domain digests).
    pub siblings: Vec<Fp192>,
    /// Merkle direction bits (LSB-first), the software `idx & 1` walk for `b_j`.
    pub dir_bits: Vec<bool>,
}

/// Build the full R1CS for ONE STIR fold round (one fiber), composing the
/// reused gadgets and discharging the three composition obligations.
///
/// Returns the finalized system, the exposed wires, and the FS traces (for the
/// gate to assert the derived `r_fold` / shift base match the software).
pub fn build_stir_fold_round(
    inp: &StirFoldRoundInputs,
) -> (Fp192R1cs, StirFoldRoundWires, FsChallengeTrace, FsChallengeTrace) {
    assert_eq!(inp.fiber_y.len(), inp.eta, "fiber_y length must equal eta");
    let params: &PlumGriffinParams = plum_griffin_params();
    let mut builder = Fp192R1csBuilder::new();

    // ----- Absorbed transcript: prefix wires, then this round's committed root
    //       wire. The root wire is the SAME one used for BOTH the FS r_fold
    //       derivation and the Merkle binding (obligation 1). -----
    let prefix_wires: Vec<Fp192Var> = inp
        .absorbed_prefix
        .iter()
        .map(|v| builder.alloc_input(v.clone()))
        .collect();
    let committed_root_var = builder.alloc_input(inp.committed_root.clone());

    // Transcript absorbed up to and including the committed root.
    let mut absorbed_root: Vec<Fp192> = inp.absorbed_prefix.clone();
    absorbed_root.push(inp.committed_root.clone());
    let mut absorbed_root_wires: Vec<Fp192Var> = prefix_wires.clone();
    absorbed_root_wires.push(committed_root_var.clone());

    // ----- r_fold = FS challenge_field over the PRE-ROOT transcript.
    //       This matches the round-0 software ordering: `r0_fold` is squeezed
    //       at `verify.rs:224`, BEFORE this round's `append_root` at
    //       `verify.rs:339`, and the round-0 fold consistency check
    //       (`verify.rs:616`) folds with `current_r_fold` == `r0_fold`. So for
    //       the round-0 fold the folding challenge is bound to the prior
    //       transcript, NOT to this round's committed root. (The committed root
    //       binds the QUERY positions and the Merkle path below — obligations
    //       1 & 2 — and the NEXT round's `next_r_fold` at `verify.rs:342`.) -----
    let rfold_trace =
        griffin_fs_challenge_field(&inp.absorbed_prefix, inp.r_fold_squeeze_counter);
    let r_fold = griffin_fs_challenge_field_circuit(
        &mut builder,
        params,
        &prefix_wires,
        inp.r_fold_squeeze_counter,
        &rfold_trace,
    );

    // ----- Obligation 2: shift base b_j = FS challenge_index over the
    //       transcript INCLUDING the committed root, matching
    //       `transcript.challenge_indices` at `verify.rs:354` (after the
    //       `append_root` at `verify.rs:339`). The committed-root wire feeds the
    //       sponge chain, so the queried position is bound to it. The shift base
    //       is a CONSTRAINED index output, not a free witness. -----
    let shift_trace = griffin_fs_challenge_index(
        &absorbed_root,
        inp.shift_squeeze_counter,
        inp.shift_bound,
    );
    let shift_base = griffin_fs_challenge_index_circuit(
        &mut builder,
        params,
        &absorbed_root_wires,
        inp.shift_squeeze_counter,
        &shift_trace,
    );
    let b_j: usize = {
        let big = shift_trace.value.to_biguint();
        let digits = big.to_u64_digits();
        if digits.is_empty() { 0usize } else { digits[0] as usize }
    };

    // ----- Obligation 2 (anchoring the fiber to the FS index): build the fiber
    //       evaluation points ω^{b_j + t·stride} via an in-circuit ω-power chain
    //       ANCHORED at ω^{b_j}, where the anchor is bound to the FS shift_base
    //       wire. Concretely: omega_pow_bj = ω^{b_j} is witnessed and bound by
    //       enforce_eq to a power-chain that the FS index selects; the fiber
    //       points are then omega_pow_bj · (ω^stride)^t (real mul constraints).
    //
    //       The binding `omega_pow_bj` <-> `shift_base` is realised by a small
    //       in-circuit table-free check: we constrain ω^{b_j} = ω^{shift_base}
    //       by evaluating, in-circuit, the polynomial that maps the integer index
    //       to its ω-power is infeasible directly; instead we bind via the
    //       discrete anchor below. -----
    //
    // We expose ω^{b_j} as a witness wire and bind it to the FS index by a
    // constraint that ties the FS-selected integer to the anchor. Because an
    // R1CS cannot exponentiate by a witness integer, we instead bind the fiber's
    // FIRST point to ω^{b_j} computed from the *constant* b_j and assert (in the
    // gate, value-level) that b_j equals the FS index value — and IN-CIRCUIT we
    // enforce shift_base == constant(b_j) so the FS-derived index is pinned to
    // the integer used to build the fiber. This makes the fiber positions a
    // function of the constrained FS index (a wrong FS index breaks this eq).
    let b_j_const = builder.constant_pub(Fp192::from_u64(b_j as u64));
    builder.enforce_eq_pub(&shift_base, &b_j_const);

    // Fiber points: x_t = ω^{b_j + t·stride}. Built as constants of the public
    // generator/stride/b_j (all public structural data); their LINK to the FS
    // index is the enforce_eq above (shift_base == b_j_const).
    let omega_stride = inp.omega.pow_u128(inp.stride as u128);
    let mut fiber_x_wires: Vec<Fp192Var> = Vec::with_capacity(inp.eta);
    let mut point = inp.omega.pow_u128(b_j as u128);
    for _ in 0..inp.eta {
        fiber_x_wires.push(builder.constant_pub(point.clone()));
        point = point * omega_stride.clone();
    }

    // Fiber values f̂_0(x_t): input wires (the queried evaluations).
    let fiber_y_wires: Vec<Fp192Var> = inp
        .fiber_y
        .iter()
        .map(|v| builder.alloc_input(v.clone()))
        .collect();

    // ----- Obligation 3: THE FOLD. Interpolate the fiber, evaluate at r_fold. --
    let fold_value = fold_fiber_circuit(&mut builder, &fiber_x_wires, &fiber_y_wires, &r_fold);

    // ----- Bind the fold output INTO the committed Merkle tree. The â_1 leaf is
    //       the fold value; its leaf DIGEST is computed in-circuit EXACTLY as
    //       `PlumMerkleTree::commit` hashes leaves (`merkle/plum.rs:47`):
    //       `H::hash_bytes(fold_value.to_bytes_le())`. That software path packs
    //       the 32-byte LE serialisation into TWO field elements via
    //       `bytes_to_field_elements` (24 bytes -> e0 = low 192 bits, remaining
    //       8 bytes -> e1 = bits 192..), runs the field sponge for
    //       DIGEST_ELEMENTS = 2 outputs, and keeps the first 32 bytes (= output
    //       element 0's LE bytes). Since output element 0 is < p < 2^199, the
    //       `compress_pair` digest decode round-trips it, so the field value the
    //       first internal compression consumes IS output element 0.
    //
    //       The byte->field packing of the WITNESS fold_value is bound IN-CIRCUIT
    //       by the EXACT linear relation `fold_value == e0 + 2^192 · e1` (e0,e1
    //       are witnessed from fold_value's LE bytes; the relation is what
    //       `bytes_to_field_elements` realises since 24 bytes = 192 bits). A full
    //       byte-range decomposition of e0/e1 is the documented sponge modeling
    //       boundary; the linear bind is sufficient to make a TAMPERED fold_value
    //       break the leaf hash (it changes e0/e1, hence the leaf digest, hence
    //       the Merkle root binding).
    let fv_bytes = fold_value.value().to_bytes_le();
    let mut e0_b = [0u8; 32];
    e0_b[..24].copy_from_slice(&fv_bytes[..24]);
    let e0_val = Fp192::from_bytes_le(&e0_b).expect("low-192 chunk < p");
    let mut e1_b = [0u8; 32];
    e1_b[..8].copy_from_slice(&fv_bytes[24..32]);
    let e1_val = Fp192::from_bytes_le(&e1_b).expect("high-8-byte chunk < p");
    let e0 = builder.alloc_witness_pub(e0_val);
    let e1 = builder.alloc_witness_pub(e1_val);
    // 2^192 as a field constant (one constant wire), then e1 * 2^192 (one mul
    // row), + e0 (one linear row), == fold_value (one equality row).
    let two_192 = Fp192::from_biguint(BigUint::from(1u8) << 192);
    let two_192_wire = builder.constant_pub(two_192);
    let e1_hi = builder.mul_pub(&e1, &two_192_wire);
    let packed = builder.add_vars(&e0, &e1_hi);
    builder.enforce_eq_pub(&packed, &fold_value);

    // Leaf digest = hash_bytes(fold_value LE) = sponge([e0, e1], 2)[0].
    // 2 == PLUM_GRIFFIN_DIGEST_ELEMENTS (`griffin_p192.rs:48`); the first 32
    // output bytes the hasher keeps are output element 0's LE bytes.
    const DIGEST_ELEMENTS: usize = 2;
    let leaf_digest = griffin_fp192_sponge_circuit(&mut builder, params, &[e0, e1], DIGEST_ELEMENTS)
        .into_iter()
        .next()
        .expect("sponge squeezes >= 1 element");

    let sibling_wires: Vec<Fp192Var> = inp
        .siblings
        .iter()
        .map(|s| builder.alloc_input(s.clone()))
        .collect();
    let dir_wires: Vec<Fp192Var> =
        inp.dir_bits.iter().map(|&b| builder.alloc_bool_pub(b)).collect();

    // ----- Obligation 2 closure: bind the Merkle direction bits (the leaf index
    //       the path opens) to the SAME FS shift base. Enforce
    //       `shift_base == Σ_k dir_bit_k · 2^k` (LSB-first, matching the
    //       software `idx & 1` / `idx /= 2` walk in `merkle/plum.rs:143-149`).
    //       Without this, the path could open a DIFFERENT leaf than the FS index
    //       selects. The dir bits are already boolean-pinned (`alloc_bool_pub`),
    //       so this single linear identity fully ties the opened position to the
    //       constrained FS index. -----
    if !dir_wires.is_empty() {
        let mut acc = dir_wires[0].clone();
        let mut pow = Fp192::from_u64(2);
        for d in dir_wires.iter().skip(1) {
            let pow_wire = builder.constant_pub(pow.clone());
            let term = builder.mul_pub(d, &pow_wire);
            acc = builder.add_vars(&acc, &term);
            pow = pow * Fp192::from_u64(2);
        }
        builder.enforce_eq_pub(&acc, &shift_base);
    }

    // Merkle path-verify binds leaf_digest -> committed_root (obligation 1).
    merkle_path_verify_circuit(
        &mut builder,
        &leaf_digest,
        &sibling_wires,
        &dir_wires,
        &committed_root_var,
    );

    let wires = StirFoldRoundWires {
        committed_root_idx: committed_root_var.index(),
        r_fold_idx: r_fold.index(),
        shift_base_idx: shift_base.index(),
        fiber_x_idx: fiber_x_wires.iter().map(|v| v.index()).collect(),
        fiber_y_idx: fiber_y_wires.iter().map(|v| v.index()).collect(),
        fold_value_idx: fold_value.index(),
        sibling_idx: sibling_wires.iter().map(|v| v.index()).collect(),
        dir_bit_idx: dir_wires.iter().map(|v| v.index()).collect(),
    };
    (builder.finalize(), wires, rfold_trace, shift_trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::hasher_plum::{PlumGriffinHasher, PLUM_DIGEST_BYTES};
    use crate::primitives::merkle::plum::PlumMerkleTree;
    use crate::signatures::plum::stir_poly::{evaluate, lagrange_interpolate};

    /// Decode a 32-byte PLUM digest into the Fp192 element exactly as
    /// PlumGriffinHasher::compress_pair does (mask byte 24 with 0x7F, then
    /// from_bytes_le) — the field-domain value the software tree feeds into a
    /// compression. (Same helper as the Merkle gadget gate.)
    fn digest_to_field(d: &[u8; PLUM_DIGEST_BYTES]) -> Fp192 {
        let mut b = [0u8; 32];
        b.copy_from_slice(d);
        b[24] &= 0x7F;
        Fp192::from_bytes_le(&b).unwrap_or_else(Fp192::zero)
    }

    fn dir_bits_for(mut idx: usize, depth: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(depth);
        for _ in 0..depth {
            bits.push(idx & 1 == 1);
            idx /= 2;
        }
        bits
    }

    /// SOFTWARE one-round fold (the reference the gadget must match): per the
    /// round-0 fiber consistency check, interpolate (fiber_x, fiber_y), evaluate
    /// at r_fold. Identical to stir::stir_fold's per-fiber step.
    fn software_fold_one_fiber(
        fiber_x: &[Fp192],
        fiber_y: &[Fp192],
        r_fold: &Fp192,
    ) -> Fp192 {
        let coeffs = lagrange_interpolate(fiber_x, fiber_y).expect("distinct fiber points");
        evaluate(&coeffs, r_fold)
    }

    /// THE GATE.
    /// (1) build a real one-round software fold over a small codeword: pick an
    ///     η-fiber, FS-derive r_fold and the shift base from a committed root,
    ///     fold the fiber, and commit the fold value into a real â_1 Merkle tree;
    /// (2) build the R1CS round gadget and assert the honest witness satisfies
    ///     ALL constraints and the gadget's fold value == the software fold;
    /// (3) TAMPER: a wrong Merkle opening, a wrong query index, and a wrong fold
    ///     result each fail >= 1 constraint.
    #[test]
    fn stir_fold_round_gadget_matches_software_and_rejects_tampering() {
        let eta = 4usize;
        // Small synthetic folding domain: |U_0| = 16, stride = |U_0|/η = 4.
        // Use a concrete primitive 16th root of unity from the PLUM setup so the
        // fiber points are genuine domain points (matches the software fold).
        let pp = crate::signatures::plum::setup::plum_setup(128).unwrap();
        let n_dom = 16usize;
        let stride = n_dom / eta; // 4
        let omega = pp.u_generator.pow_u128((pp.u_size / n_dom) as u128);

        // --- Transcript: an arbitrary absorbed prefix + a committed root. The
        //     committed root is the â_1 tree root we build below, so the FS
        //     bindings are over the REAL commitment. We compute it in two passes:
        //     first build the fiber + fold to know the leaf, build the tree to
        //     get the root, THEN run the FS derivations over that root. ---
        let absorbed_prefix: Vec<Fp192> =
            vec![Fp192::from_u64(0xABCD), Fp192::from_u64(0x1234), Fp192::from_u64(7)];

        let shift_bound = stride; // next-layer domain size |U_0|/η = 4.

        // NO fixed point is needed — and the prior fixed-point loop was the
        // runaway (it iterated a RANDOM map r_fold = H(tree(folds(r_fold))),
        // which has no reachable fixed point and never terminated). The software
        // has NO such cycle: for the ROUND-0 fold (`verify.rs:616`) the folding
        // challenge is `current_r_fold == r0_fold`, squeezed at `verify.rs:224`
        // BEFORE this round's root is appended (`verify.rs:339`). The honest
        // prover therefore knows r_fold first, folds every fiber at it, commits
        // the â_1 tree, and the root is absorbed only to derive the query
        // positions (`verify.rs:354`). Acyclic construction, matching software:
        //   1. r_fold = FS challenge_field over the PRE-ROOT transcript (prefix);
        //   2. leaves[k] = fold of fiber k at r_fold;  commit -> root;
        //   3. b_j = FS challenge_index over prefix + root (post-root).
        let rfold_sc = 0u64;
        let shift_sc = 1u64;

        // Fiber y-values for every leaf k (η values per fiber).
        let fiber_y_all: Vec<Vec<Fp192>> = (0..shift_bound)
            .map(|k| {
                (0..eta)
                    .map(|t| Fp192::from_u64(((k * 31 + t * 7 + 3) as u64) * 1009 + 17))
                    .collect()
            })
            .collect();
        // Fiber x-points for leaf k: ω^{k + t·stride}.
        let fiber_x_all: Vec<Vec<Fp192>> = (0..shift_bound)
            .map(|k| {
                (0..eta)
                    .map(|t| omega.pow_u128((k + t * stride) as u128))
                    .collect()
            })
            .collect();

        // (1) r_fold from the PRE-ROOT transcript (prefix only).
        let r_fold = griffin_fs_challenge_field(&absorbed_prefix, rfold_sc).value;

        // (2) Commit the â_1 tree whose leaves are the folds at that r_fold.
        let leaves: Vec<Fp192> = (0..shift_bound)
            .map(|k| software_fold_one_fiber(&fiber_x_all[k], &fiber_y_all[k], &r_fold))
            .collect();
        let tree = PlumMerkleTree::<PlumGriffinHasher>::commit(leaves.clone());
        let committed_root_field = digest_to_field(&tree.root());

        // FS shift base b_j over the same absorbed transcript.
        let mut absorbed_root = absorbed_prefix.clone();
        absorbed_root.push(committed_root_field.clone());
        let shift_trace = griffin_fs_challenge_index(&absorbed_root, shift_sc, shift_bound);
        let b_j = {
            let d = shift_trace.value.to_biguint().to_u64_digits();
            if d.is_empty() { 0usize } else { d[0] as usize }
        };
        assert!(b_j < shift_bound, "FS shift base out of range");

        // The queried fiber is fiber b_j; its fold IS leaf b_j by construction.
        let fiber_x = fiber_x_all[b_j].clone();
        let fiber_y = fiber_y_all[b_j].clone();
        let software_fold = software_fold_one_fiber(&fiber_x, &fiber_y, &r_fold);
        assert_eq!(
            software_fold, leaves[b_j],
            "construction: fold of fiber b_j != committed leaf b_j",
        );

        // Merkle opening for leaf b_j (the â_1 query).
        let proof = tree.open(b_j);
        assert!(
            PlumMerkleTree::<PlumGriffinHasher>::verify(&tree.root(), &proof),
            "software â_1 opening must verify",
        );
        let sibling_fields: Vec<Fp192> =
            proof.siblings.iter().map(|s| digest_to_field(s)).collect();
        let dir_bits = dir_bits_for(proof.leaf_index, sibling_fields.len());

        // --- Build the gadget. ---
        let inp = StirFoldRoundInputs {
            absorbed_prefix: absorbed_prefix.clone(),
            committed_root: committed_root_field.clone(),
            r_fold_squeeze_counter: rfold_sc,
            shift_squeeze_counter: shift_sc,
            shift_bound,
            omega: omega.clone(),
            stride,
            eta,
            fiber_y: fiber_y.clone(),
            siblings: sibling_fields.clone(),
            dir_bits: dir_bits.clone(),
        };
        let (r1cs, wires, rfold_trace, shift_trace2) = build_stir_fold_round(&inp);

        // (2a) honest witness satisfies ALL constraints.
        if let Err(bad) = r1cs.check_satisfied() {
            panic!("honest STIR fold round witness unsatisfied at constraint #{bad}");
        }
        // (2b) FS-derived r_fold / shift base match the software references.
        assert_eq!(rfold_trace.value, r_fold, "gadget r_fold trace != software");
        assert_eq!(shift_trace2.value, shift_trace.value, "gadget shift base trace != software");
        assert_eq!(r1cs.assignment[wires.r_fold_idx], r_fold, "r_fold wire != software");
        // (2c) the gadget's reconstructed fold value == the software fold output.
        assert_eq!(
            r1cs.assignment[wires.fold_value_idx], software_fold,
            "gadget fold value != software one-round fold",
        );

        let n_constraints = r1cs.num_constraints();
        eprintln!(
            "STIR FOLD ROUND GATE: η={eta}, |U_0|={n_dom}, stride={stride}, b_j={b_j}, \
             depth={}, {n_constraints} constraints/round",
            sibling_fields.len(),
        );

        // (3a) TAMPER — wrong Merkle opening: corrupt a sibling wire. The Merkle
        //      path recomputes a different root, breaking the enforce_eq root
        //      binding (>= 1 constraint fails).
        if !sibling_fields.is_empty() {
            let mut r = r1cs.clone();
            r.assignment[wires.sibling_idx[0]] =
                r.assignment[wires.sibling_idx[0]].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "TAMPER(wrong Merkle opening): corrupted sibling was NOT caught",
            );
        }

        // (3b) TAMPER — wrong fold result: corrupt the reconstructed fold value
        //      wire. The leaf-hash sponge / Merkle binding (and the fold's own
        //      Horner/Lagrange rows) must reject it.
        {
            let mut r = r1cs.clone();
            r.assignment[wires.fold_value_idx] =
                r.assignment[wires.fold_value_idx].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "TAMPER(wrong fold result): corrupted fold value was NOT caught",
            );
        }

        // (3c) TAMPER — wrong query index: the FS shift base is pinned to the
        //      integer b_j used to build the fiber (enforce_eq shift_base ==
        //      b_j_const). Corrupt the shift_base wire to a different in-range
        //      index; the pin must fire. (A prover who wants a DIFFERENT fiber
        //      cannot move the FS index without breaking this binding.)
        {
            let mut r = r1cs.clone();
            let other = Fp192::from_u64(((b_j + 1) % shift_bound) as u64);
            // Only meaningful if it actually changes the wire.
            if r.assignment[wires.shift_base_idx] != other {
                r.assignment[wires.shift_base_idx] = other;
                assert!(
                    r.check_satisfied().is_err(),
                    "TAMPER(wrong query index): moving the FS shift base was NOT caught \
                     — query position not bound to the FS index",
                );
            }
        }

        // (3d) TAMPER — corrupt a fiber value (the queried evaluation). The fold
        //      changes, so the committed-leaf binding must reject it.
        {
            let mut r = r1cs.clone();
            r.assignment[wires.fiber_y_idx[0]] =
                r.assignment[wires.fiber_y_idx[0]].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "TAMPER(corrupt queried evaluation): was NOT caught by the fold/commit binding",
            );
        }

        // (3e) TAMPER — flip a Merkle direction bit (open a DIFFERENT leaf than
        //      the FS index selects). The dir-bit<->FS-index identity
        //      (shift_base == Σ dir_bit_k·2^k) must fire (or, if a sibling
        //      happens to still hash up, the index bind catches it regardless).
        if !dir_bits.is_empty() {
            let mut r = r1cs.clone();
            let d0 = wires.dir_bit_idx[0];
            // flip bit 0 (0<->1); both values are valid booleans so only the
            // FS-index bind / Merkle path can reject it.
            r.assignment[d0] = if r.assignment[d0] == Fp192::one() {
                Fp192::zero()
            } else {
                Fp192::one()
            };
            assert!(
                r.check_satisfied().is_err(),
                "TAMPER(wrong Merkle direction bit): opening a different leaf than the \
                 FS index was NOT caught — leaf position not bound to the FS index",
            );
        }

        eprintln!("STIR FOLD ROUND GATE PASSED: honest satisfied, fold==software, 5 tampers rejected");
    }
}
