//! Merkle authentication-path verification as an R1CS gadget (Stage 4a),
//! over PLUM's `Fp192` field, reusing the Stage-2 Griffin-Fp192 permutation
//! gadget as the 2-to-1 compression.
//!
//! ## Software reference (matched exactly)
//!
//! `crate::primitives::merkle::plum::PlumMerkleTree::<PlumGriffinHasher>`
//! (`src/primitives/merkle/plum.rs`). The path-verify loop this gadget
//! mirrors is `PlumMerkleTree::verify` (`plum.rs:189`) /
//! `verify_digest_leaf` (`plum.rs:137`):
//!
//! ```text
//! let mut digest = leaf_digest;                 // 32-byte digest
//! let mut idx = leaf_index;
//! for sibling in siblings {
//!     let (left, right) = if idx & 1 == 0 { (digest, *sibling) }
//!                         else            { (*sibling, digest) };
//!     digest = H::compress_pair(&left, &right);
//!     idx /= 2;
//! }
//! root == digest
//! ```
//!
//! The combine `H::compress_pair` for the Griffin instantiation
//! (`src/primitives/hash/hasher_plum.rs:95`) is, in the field domain,
//! exactly ONE Griffin-Fp192 permutation:
//!
//!   * decode the two 32-byte child digests as `Fp192` (mask byte 24 with
//!     `0x7F`, then `from_bytes_le`),
//!   * load the **compression** state `[left, right, 0, 0]` (state width 4,
//!     capacity 2 — `PLUM_GRIFFIN_STATE_WIDTH = 4`, `PLUM_GRIFFIN_CAPACITY = 2`),
//!   * run one `plum_griffin_permutation`,
//!   * the parent digest is lane 0 serialised back to 32 bytes.
//!
//! ### Byte/field-domain faithfulness (asserted, not assumed)
//!
//! Internal-node digests are `lane0.to_bytes_le()[..32]`. Because `p` is a
//! 199-bit prime, every field element serialises with bit 7 of byte 24 equal
//! to 0, so the `byte[24] &= 0x7F` mask in `compress_pair` is a no-op and
//! `Fp192::from_bytes_le(lane0.to_bytes_le())` round-trips to `lane0`. Hence
//! the byte digest carried up the tree and the field element lane-0 carry the
//! the **same** value, and a field-domain path-verify is bit-identical to the
//! software byte-domain path-verify. The gate test asserts this round-trip
//! identity directly (`griffin_compress_field_roundtrip_is_identity`) so the
//! modeling is grounded.
//!
//! The leaf-digest input to this gadget is the field element a software
//! verifier feeds into the FIRST `compress_pair` — i.e. the value the leaf's
//! 32-byte digest decodes to. The leaf-level byte sponge hash
//! (`H::hash_bytes`) is performed once per path and is OUT OF SCOPE for this
//! path-combine gadget; the dominant Merkle cost (878 of 977 Griffin perms in
//! PLUM-128 verify) is the internal-node compressions this gadget builds.
//!
//! ## The R1CS Merkle trap (handled)
//!
//! Each per-level direction bit `d_level` is:
//!   1. **boolean-constrained** by a real `d*d = d` constraint (`alloc_bool`),
//!   2. the left/right child swap is **enforced by that bit** with real
//!      constraints — `diff = sib - cur`, `d_diff = d * diff` (one mul row),
//!      `left = cur + d_diff`, `right = sib - d_diff` (linear rows). A prover
//!      cannot reorder siblings without flipping `d`, and `d` is boolean-pinned,
//!      so the only two reachable orderings are `(cur, sib)` and `(sib, cur)`,
//!      matching the software `idx & 1` branch. This is the structure of
//!      Loquat's `merkle_path_opening_fields_pi`
//!      (`src/signatures/loquat/r1cs_circuit.rs:159`), ported to a
//!      single-field-element PLUM digest.

use crate::primitives::field::p192::Fp192;
use crate::primitives::hash::griffin_p192::{
    PLUM_GRIFFIN_STATE_WIDTH, plum_griffin_params,
};
use crate::primitives::r1cs::griffin_fp192_gadget::{
    Fp192R1cs, Fp192R1csBuilder, Fp192Var, griffin_fp192_permutation_circuit,
};

/// Wire handles exposed by the Merkle path-verify gadget so callers/tests can
/// read or poke specific wires.
pub struct MerklePathWires {
    /// The leaf-digest input wire (field-domain value of the leaf's digest).
    pub leaf_idx: usize,
    /// One sibling-digest wire index per level (leaf level up to the root).
    pub sibling_idx: Vec<usize>,
    /// One direction-bit wire index per level (boolean-constrained).
    pub dir_bit_idx: Vec<usize>,
    /// The recomputed-root wire index (lane 0 of the topmost compression).
    pub root_idx: usize,
    /// The claimed/committed-root input wire index. A real `enforce_eq`
    /// constraint binds `root_idx == claimed_root_idx`, so the system is
    /// satisfiable iff the recomputed root matches this externally-supplied
    /// value (a Stage-4c transcript root; the test supplies the true software
    /// root).
    pub claimed_root_idx: usize,
}

/// In-circuit handle for the recomputed root and the wires of the gadget.
pub struct MerklePathVars {
    pub root: Fp192Var,
    pub wires: MerklePathWires,
}

/// Apply the PLUM Griffin Merkle authentication-path recompute in-circuit,
/// returning the recomputed-root wire.
///
/// `leaf` is the leaf-digest field element (the value the leaf's 32-byte
/// digest decodes to). `siblings[level]` is the sibling digest at that level,
/// and `dir_bits[level]` is the software `(idx >> level) & 1` direction bit
/// (LSB-first, leaf level = level 0). Both vectors must have equal length =
/// tree depth.
///
/// At each level: `dir = 0` ⇒ `(left, right) = (current, sibling)`;
/// `dir = 1` ⇒ `(left, right) = (sibling, current)`; then one Griffin
/// permutation on `[left, right, 0, 0]`, with lane 0 as the parent digest.
///
/// `claimed_root` is the externally-supplied root the recomputed root MUST
/// equal: the gadget emits a real `enforce_eq(computed_root, claimed_root)`
/// constraint. This is the in-circuit counterpart of the software verify's
/// terminal `*root == digest` check (`merkle::plum::verify`, plum.rs:201).
/// Without it the system is satisfiable for whatever root the path recomputes,
/// so a consistent-witness tampered path would NOT be rejected by any
/// constraint. Returns the recomputed-root wire (now constrained equal to
/// `claimed_root`).
pub fn merkle_path_verify_circuit(
    builder: &mut Fp192R1csBuilder,
    leaf: &Fp192Var,
    siblings: &[Fp192Var],
    dir_bits: &[Fp192Var],
    claimed_root: &Fp192Var,
) -> Fp192Var {
    assert_eq!(
        siblings.len(),
        dir_bits.len(),
        "merkle_path_verify_circuit: sibling/direction-bit count mismatch",
    );

    let params = plum_griffin_params();
    let mut current = leaf.clone();

    for level in 0..siblings.len() {
        let sib = &siblings[level];
        let dir = &dir_bits[level];
        let cur = current.clone();

        // Conditional swap, enforced by the boolean direction bit:
        //   diff   = sib - cur
        //   d_diff = dir * diff           (the ONLY multiplication of the swap)
        //   left   = cur + d_diff
        //   right  = sib - d_diff
        // dir = 0 -> (left, right) = (cur, sib); dir = 1 -> (sib, cur).
        let diff = builder.sub_vars(sib, &cur);
        let d_diff = builder.mul_pub(dir, &diff);
        let left = builder.add_vars(&cur, &d_diff);
        let right = builder.sub_vars(sib, &d_diff);

        // One Griffin permutation on the compression state [left, right, 0, 0].
        let zero0 = builder.constant_pub(Fp192::zero());
        let zero1 = builder.constant_pub(Fp192::zero());
        let mut state: Vec<Fp192Var> = vec![left, right, zero0, zero1];
        debug_assert_eq!(state.len(), PLUM_GRIFFIN_STATE_WIDTH);
        griffin_fp192_permutation_circuit(builder, params, &mut state);

        // Parent digest = lane 0.
        current = state[0].clone();
    }

    // BINDING: the recomputed root must equal the claimed/committed root.
    // One real linear constraint (`computed_root - claimed_root == 0`). This
    // is the in-circuit `*root == digest` (plum.rs:201); without it the
    // recomputed-root wire is unconstrained against any reference value.
    builder.enforce_eq_pub(&current, claimed_root);

    current
}

/// Build the full R1CS for one Merkle authentication-path verification, with
/// the witness assigned by the gadget's own computation. Returns the finalized
/// system plus the exposed wire indices.
///
/// `leaf` is the leaf-digest field element; `siblings` and `dir_bits` are
/// LSB-first per-level (leaf level = index 0). `claimed_root` is the
/// externally-supplied root the recomputed root is constrained to equal (a
/// Stage-4c transcript root; the gate test supplies the true software root).
pub fn build_merkle_path_verify(
    leaf: Fp192,
    siblings: &[Fp192],
    dir_bits: &[bool],
    claimed_root: Fp192,
) -> (Fp192R1cs, MerklePathWires) {
    assert_eq!(
        siblings.len(),
        dir_bits.len(),
        "build_merkle_path_verify: sibling/direction-bit count mismatch",
    );
    let mut builder = Fp192R1csBuilder::new();

    let leaf_var = builder.alloc_input(leaf);
    let sibling_vars: Vec<Fp192Var> = siblings
        .iter()
        .map(|s| builder.alloc_input(s.clone()))
        .collect();
    // Each direction bit is allocated with a real b*b=b constraint.
    let dir_vars: Vec<Fp192Var> =
        dir_bits.iter().map(|&b| builder.alloc_bool_pub(b)).collect();
    // The claimed/committed root is an input wire; the gadget binds the
    // recomputed root to it with a real enforce_eq constraint.
    let claimed_root_var = builder.alloc_input(claimed_root);

    let root = merkle_path_verify_circuit(
        &mut builder,
        &leaf_var,
        &sibling_vars,
        &dir_vars,
        &claimed_root_var,
    );

    let wires = MerklePathWires {
        leaf_idx: leaf_var.index(),
        sibling_idx: sibling_vars.iter().map(|v| v.index()).collect(),
        dir_bit_idx: dir_vars.iter().map(|v| v.index()).collect(),
        root_idx: root.index(),
        claimed_root_idx: claimed_root_var.index(),
    };
    (builder.finalize(), wires)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::hasher_plum::{
        PLUM_DIGEST_BYTES, PlumGriffinHasher, PlumHasher,
    };
    use crate::primitives::merkle::plum::PlumMerkleTree;

    /// Decode a 32-byte PLUM digest into the `Fp192` element exactly as
    /// `PlumGriffinHasher::compress_pair` does (mask byte 24 with 0x7F, then
    /// `from_bytes_le`). This is the field-domain value the software tree
    /// feeds into a compression.
    fn digest_to_field(d: &[u8; PLUM_DIGEST_BYTES]) -> Fp192 {
        let mut b = [0u8; 32];
        b.copy_from_slice(d);
        b[24] &= 0x7F;
        Fp192::from_bytes_le(&b).unwrap_or_else(Fp192::zero)
    }

    /// The first 32 bytes of `f.to_bytes_le()` — the byte digest a software
    /// compression emits for a lane-0 field output.
    fn field_to_digest(f: &Fp192) -> [u8; PLUM_DIGEST_BYTES] {
        let bytes = f.to_bytes_le();
        let mut out = [0u8; PLUM_DIGEST_BYTES];
        out.copy_from_slice(&bytes[..PLUM_DIGEST_BYTES]);
        out
    }

    /// GROUNDING: the byte/field round-trip for an internal-node digest is the
    /// identity, so field-domain path-verify == software byte-domain
    /// path-verify. If this ever fails, the whole field-domain modeling is
    /// unsound and the gate below is meaningless — so we assert it first.
    #[test]
    fn griffin_compress_field_roundtrip_is_identity() {
        // A real internal-node digest: compress two arbitrary child digests.
        let a = PlumGriffinHasher::hash_bytes(b"child-A");
        let b = PlumGriffinHasher::hash_bytes(b"child-B");
        let parent = PlumGriffinHasher::compress_pair(&a, &b);
        // Decode -> re-encode must round-trip.
        let f = digest_to_field(&parent);
        let reencoded = field_to_digest(&f);
        assert_eq!(
            reencoded, parent,
            "field<->byte round-trip is NOT the identity for a real internal digest",
        );
        // And re-decoding the re-encoded bytes gives the same field element.
        assert_eq!(digest_to_field(&reencoded), f);
    }

    /// Sibling-chain direction bits for a leaf index, LSB-first per level,
    /// matching the software `idx & 1; idx /= 2` walk.
    fn dir_bits_for(mut idx: usize, depth: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(depth);
        for _ in 0..depth {
            bits.push(idx & 1 == 1);
            idx /= 2;
        }
        bits
    }

    /// THE GATE.
    /// (1) build a real Merkle tree in software over Griffin-Fp192;
    /// (2) build the R1CS path-verify gadget for a leaf + its path;
    /// (3) assert the honest witness satisfies all constraints AND the gadget's
    ///     recomputed root == the software root;
    /// (4) assert a TAMPERED path (wrong sibling / wrong leaf / flipped
    ///     direction bit) makes >= 1 constraint fail OR diverges the root.
    #[test]
    fn merkle_path_gadget_matches_software_and_rejects_tampering() {
        // (1) real software tree over Griffin-Fp192. 11 leaves -> padded 16,
        //     depth 4 (a non-power-of-two leaf count to exercise padding).
        let n = 11usize;
        let leaves: Vec<Fp192> =
            (0..n).map(|i| Fp192::from_u64(i as u64 * 31 + 7)).collect();
        let tree = PlumMerkleTree::<PlumGriffinHasher>::commit(leaves.clone());
        let software_root = tree.root();
        let depth = tree.open(0).siblings.len();
        eprintln!("software tree: {n} leaves, padded {}, depth {depth}", tree.len_padded());
        assert!(PlumMerkleTree::<PlumGriffinHasher>::verify(&software_root, &tree.open(0)));

        let mut reported_constraints = 0usize;

        for leaf_index in 0..n {
            let proof = tree.open(leaf_index);
            // Software sanity: this honest proof verifies.
            assert!(
                PlumMerkleTree::<PlumGriffinHasher>::verify(&software_root, &proof),
                "software verify failed for honest leaf {leaf_index}",
            );

            // The leaf-digest field element the software feeds into the first
            // compression (decode of the leaf's byte digest).
            let leaf_digest = PlumGriffinHasher::hash_bytes(&proof.leaf.to_bytes_le());
            let leaf_field = digest_to_field(&leaf_digest);
            // Sibling field elements (decode of each sibling byte digest).
            let sibling_fields: Vec<Fp192> =
                proof.siblings.iter().map(|s| digest_to_field(s)).collect();
            let dir_bits = dir_bits_for(proof.leaf_index, sibling_fields.len());
            // The claimed/committed root the gadget binds against: the true
            // software root decoded to its field-domain value. This is FIXED
            // externally (NOT recomputed from a tampered path), so the
            // enforce_eq binding is meaningful.
            let claimed_root_field = digest_to_field(&software_root);

            // (2) gadget R1CS + witness.
            let (r1cs, wires) = build_merkle_path_verify(
                leaf_field.clone(),
                &sibling_fields,
                &dir_bits,
                claimed_root_field.clone(),
            );
            reported_constraints = r1cs.num_constraints();

            // (3a) honest witness satisfies all constraints (including the new
            //      computed-root == claimed-root enforce_eq).
            if let Err(bad) = r1cs.check_satisfied() {
                panic!("leaf {leaf_index}: constraint #{bad} unsatisfied by honest witness");
            }
            // (3b) gadget recomputed root == software root (compare in BYTES,
            //      the software domain).
            let gadget_root_field = r1cs.assignment[wires.root_idx].clone();
            assert_eq!(
                field_to_digest(&gadget_root_field),
                software_root,
                "leaf {leaf_index}: gadget root != software root",
            );

            // (4a) IN-CIRCUIT TAMPER: flip a sibling and build a FULLY
            //      CONSISTENT witness for the tampered path (every conditional-
            //      swap / Griffin row is internally satisfied), while the
            //      claimed root stays pinned to the TRUE software root. The
            //      tampered path recomputes a DIFFERENT root, so the new
            //      enforce_eq(computed_root, claimed_root) constraint must FAIL.
            //      This is the binding the gate must demonstrate: tamper is
            //      rejected BY A CONSTRAINT, not by an out-of-circuit compare.
            if !sibling_fields.is_empty() {
                let mut bad_siblings = sibling_fields.clone();
                bad_siblings[0] = bad_siblings[0].clone() + Fp192::one();
                let (r_bad, _w_bad) = build_merkle_path_verify(
                    leaf_field.clone(),
                    &bad_siblings,
                    &dir_bits,
                    claimed_root_field.clone(), // pinned to TRUE root
                );
                // Sanity: the divergence is real at the field level.
                assert_ne!(
                    field_to_digest(&r_bad.assignment[_w_bad.root_idx]),
                    software_root,
                    "leaf {leaf_index}: tampered sibling still recomputed the software root",
                );
                // THE BINDING: a constraint (the enforce_eq) must reject it.
                let failing = r_bad.check_satisfied();
                assert!(
                    failing.is_err(),
                    "leaf {leaf_index}: tampered-sibling consistent witness was NOT \
                     rejected by any constraint — root binding (enforce_eq) is missing",
                );
                // PROBE: the ONLY failing constraint must be the LAST one (the
                // enforce_eq root binding), confirming every other (swap /
                // Griffin) row is satisfied by the consistent forged witness.
                assert_eq!(
                    failing.unwrap_err(),
                    r_bad.num_constraints() - 1,
                    "leaf {leaf_index}: failing constraint is not the terminal root enforce_eq",
                );
            }

            // (4b) IN-CIRCUIT TAMPER: wrong leaf, fully consistent witness,
            //      claimed root pinned to the true software root. Recomputed
            //      root diverges -> the enforce_eq constraint must FAIL.
            {
                let bad_leaf = leaf_field.clone() + Fp192::one();
                let (r_bad, _w_bad) = build_merkle_path_verify(
                    bad_leaf,
                    &sibling_fields,
                    &dir_bits,
                    claimed_root_field.clone(), // pinned to TRUE root
                );
                assert_ne!(
                    field_to_digest(&r_bad.assignment[_w_bad.root_idx]),
                    software_root,
                    "leaf {leaf_index}: tampered leaf still recomputed the software root",
                );
                assert!(
                    r_bad.check_satisfied().is_err(),
                    "leaf {leaf_index}: tampered-leaf consistent witness was NOT \
                     rejected by any constraint — root binding (enforce_eq) is missing",
                );
            }

            // (4c) TAMPER: corrupt a sibling wire IN the honest witness so the
            //      conditional-swap / Griffin constraints catch it (>=1
            //      constraint fails). This exercises the constraint system, not
            //      just root divergence.
            if !sibling_fields.is_empty() {
                let mut r_corrupt = r1cs.clone();
                r_corrupt.assignment[wires.sibling_idx[0]] =
                    r_corrupt.assignment[wires.sibling_idx[0]].clone() + Fp192::one();
                assert!(
                    r_corrupt.check_satisfied().is_err(),
                    "leaf {leaf_index}: corrupting a sibling wire was NOT caught by any constraint",
                );
            }

            // (4d) TAMPER: flip a direction bit value to its opposite valid
            //      boolean. The swap is enforced by the bit, so the downstream
            //      left/right/Griffin wires (computed from the ORIGINAL bit)
            //      become inconsistent -> >=1 constraint fails. This is the
            //      Stage-3 index-bug guard: a flipped direction must break a
            //      constraint, not silently reorder.
            if !dir_bits.is_empty() {
                // pick a level whose honest bit we flip
                let level = dir_bits.len() - 1;
                let mut r_flip = r1cs.clone();
                let cur = r_flip.assignment[wires.dir_bit_idx[level]].clone();
                // flip 0<->1 (stays boolean, so b*b=b still holds; the swap
                // multiplication d*diff is what must now fail).
                let flipped = Fp192::one() - cur;
                r_flip.assignment[wires.dir_bit_idx[level]] = flipped;
                assert!(
                    r_flip.check_satisfied().is_err(),
                    "leaf {leaf_index}: flipping direction bit at level {level} was NOT caught \
                     — the swap is not enforced by the bit (Stage-3 index bug)",
                );
            }

            // (4e) TAMPER: set a direction bit to a NON-boolean value (2). The
            //      b*b=b constraint must fire.
            if !dir_bits.is_empty() {
                let mut r_nb = r1cs.clone();
                r_nb.assignment[wires.dir_bit_idx[0]] = Fp192::from_u64(2);
                assert!(
                    r_nb.check_satisfied().is_err(),
                    "leaf {leaf_index}: non-boolean direction bit (2) accepted — b*b=b missing",
                );
            }
        }

        eprintln!(
            "MERKLE PATH-VERIFY GATE PASSED: depth {depth}, {reported_constraints} constraints/path",
        );
    }

    /// STRONGEST direction-bit forgery: a prover flips a direction bit AND
    /// rebuilds the whole gadget honestly for the flipped bits, so every
    /// per-level conditional-swap / Griffin row is internally satisfied — no
    /// partial-tamper inconsistency. The claimed root stays pinned to the TRUE
    /// software root. The conditional swap is enforced by the bit, so the
    /// flipped ordering drives a DIFFERENT Griffin compression, the recomputed
    /// root diverges, and the enforce_eq(computed_root, claimed_root)
    /// constraint must FAIL. This is the Stage-3 index-bug guard at full
    /// strength, now IN-CIRCUIT: a consistently-forged direction cannot
    /// satisfy the constraint system when bound to the true root.
    #[test]
    fn flipped_direction_cannot_reproduce_root() {
        let n = 11usize;
        let leaves: Vec<Fp192> =
            (0..n).map(|i| Fp192::from_u64(i as u64 * 17 + 3)).collect();
        let tree = PlumMerkleTree::<PlumGriffinHasher>::commit(leaves);
        let software_root = tree.root();
        let claimed_root_field = digest_to_field(&software_root);

        let mut tested_levels = 0usize;
        for leaf_index in 0..n {
            let proof = tree.open(leaf_index);
            let leaf_digest = PlumGriffinHasher::hash_bytes(&proof.leaf.to_bytes_le());
            let leaf_field = digest_to_field(&leaf_digest);
            let sibling_fields: Vec<Fp192> =
                proof.siblings.iter().map(|s| digest_to_field(s)).collect();
            let honest_bits = dir_bits_for(proof.leaf_index, sibling_fields.len());

            for level in 0..honest_bits.len() {
                let mut forged = honest_bits.clone();
                forged[level] = !forged[level];
                // Fully consistent witness for the forged bits, root pinned to
                // the TRUE software root.
                let (r_forge, w_forge) = build_merkle_path_verify(
                    leaf_field.clone(),
                    &sibling_fields,
                    &forged,
                    claimed_root_field.clone(),
                );
                // The forged path recomputes a DIFFERENT root.
                let forged_root = field_to_digest(&r_forge.assignment[w_forge.root_idx]);
                assert_ne!(
                    forged_root, software_root,
                    "leaf {leaf_index} level {level}: a consistently-forged direction bit \
                     reproduced the software root — the swap is NOT bound to the bit",
                );
                // THE BINDING: bound to the true root, the constraint system
                // is now UNSATISFIABLE (the enforce_eq fails). Exactly one
                // class of constraint should break: the root equality.
                assert!(
                    r_forge.check_satisfied().is_err(),
                    "leaf {leaf_index} level {level}: a consistently-forged direction-bit \
                     witness was NOT rejected by any constraint — root binding missing",
                );
                tested_levels += 1;
            }
        }
        assert!(tested_levels > 0, "no levels exercised");
        eprintln!(
            "FORGED-DIRECTION GATE PASSED (IN-CIRCUIT): {tested_levels} (leaf,level) flips, \
             none satisfied the root-bound constraint system",
        );
    }
}
