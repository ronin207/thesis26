//! Griffin-Fp192 SPONGE (absorb / squeeze) and leaf-hash gadgets as R1CS,
//! built on the Stage-2 Griffin-Fp192 permutation gadget (Stage 4c-1).
//!
//! This module ships two in-circuit constructions:
//!
//!   - [`griffin_fp192_sponge_circuit`] — the field-element sponge: absorb a
//!     sequence of `Fp192` wires into the RATE lanes, squeeze `output_len`
//!     `Fp192` wires. This is the construction Fiat–Shamir (4c-2) and STIR
//!     Merkle leaf hashing actually consume.
//!   - [`griffin_fp192_compress_pair_circuit`] — the single-permutation
//!     2-to-1 compression used for Merkle inner nodes, mirroring
//!     `PlumGriffinHasher::compress_pair`.
//!
//! ## Software reference (matched bit-for-bit)
//!
//! The sponge mirrors `plum_griffin_sponge`
//! (`src/primitives/hash/griffin_p192.rs:113`) EXACTLY:
//!
//!   - Initial state = four zero lanes (`griffin_p192.rs:118`,
//!     `PlumGriffinState::new`).
//!   - Padding (`griffin_p192.rs:120-127`): iff `inputs.len() % RATE != 0`,
//!     (a) set capacity lane `state.lanes[RATE]` (= lane index 2) to `1`
//!     BEFORE absorbing, and (b) append a `1` element to the input stream,
//!     then zero-fill to a multiple of RATE. If the input length is ALREADY
//!     a multiple of RATE, NO padding is applied (no appended element, no
//!     capacity flag). This is reproduced exactly.
//!   - Absorb (`griffin_p192.rs:129-136`): add each block's RATE elements
//!     into lanes `0..RATE`, then run one full permutation — including after
//!     the final block.
//!   - Squeeze (`griffin_p192.rs:138-149`): emit lanes `0..RATE`, running a
//!     permutation BETWEEN squeeze blocks (never before the first, never
//!     after the last needed element).
//!
//! RATE = 2, CAPACITY = 2, STATE_WIDTH = 4 (`griffin_p192.rs:42-44`).
//!
//! ## Scope note on byte inputs (`hash_bytes`)
//!
//! `PlumGriffinHasher::hash_bytes` (`src/primitives/hash/hasher_plum.rs:51`)
//! packs the byte string into field elements via `bytes_to_field_elements`
//! (`griffin_p192.rs:301`, 24 bytes -> one `Fp192`, LE), runs the sponge for
//! `DIGEST_ELEMENTS = 2` output elements, serialises to bytes, then keeps the
//! first 32 of the 64 output bytes. The byte<->field packing is a pure
//! witness-side computation here: we expose [`griffin_fp192_hash_bytes_circuit`]
//! which packs the bytes OUT of circuit (the packing is injective and the
//! resulting field elements are < p by construction, 192 < 199 bits) and
//! constrains the sponge over the packed field elements. We DO NOT range-prove
//! the byte decomposition in-circuit: an honest-prover gadget that binds the
//! sponge output to the packed elements is what the leaf-hash callers need;
//! a full in-circuit byte-range decomposition is deferred (and is NOT used by
//! Fiat–Shamir or STIR leaf hashing, which feed field elements directly). This
//! scope is stated explicitly per the Stage 4c-1 brief.

use crate::primitives::field::p192::Fp192;
use crate::primitives::hash::griffin_p192::{
    PlumGriffinParams, PLUM_GRIFFIN_RATE, PLUM_GRIFFIN_STATE_WIDTH, plum_griffin_params,
};
use crate::primitives::r1cs::griffin_fp192_gadget::{
    Fp192R1cs, Fp192R1csBuilder, Fp192Var, griffin_fp192_permutation_circuit,
};

/// Number of bytes packed into one field element on the absorb path. Mirrors
/// `ABSORB_BYTES_PER_ELEM` in `griffin_p192.rs:54` (24 bytes = 192 bits < 199).
const ABSORB_BYTES_PER_ELEM: usize = 24;
/// Bytes per field element in the canonical serialisation (`griffin_p192.rs:50`).
const FIELD_BYTES: usize = 32;
/// `PLUM_GRIFFIN_DIGEST_ELEMENTS` (`griffin_p192.rs:48`).
const DIGEST_ELEMENTS: usize = 2;
/// `PLUM_DIGEST_BYTES` (`hasher_plum.rs:38`).
pub const PLUM_DIGEST_BYTES: usize = 32;

/// Absorb `inputs` (already-allocated `Fp192` wires) and squeeze `output_len`
/// output wires, in-circuit, matching `plum_griffin_sponge` bit-for-bit.
///
/// `params` MUST be `plum_griffin_params()`; passed in so callers that already
/// hold the reference don't re-fetch it.
///
/// Returns the `output_len` squeezed output wires.
pub fn griffin_fp192_sponge_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    inputs: &[Fp192Var],
    output_len: usize,
) -> Vec<Fp192Var> {
    assert!(output_len >= 1, "sponge must squeeze at least one element");

    // Initial state: four zero lanes (griffin_p192.rs:118). Each is a constant
    // wire pinned to 0 so the satisfaction checker has a real anchor.
    let mut state: Vec<Fp192Var> = (0..PLUM_GRIFFIN_STATE_WIDTH)
        .map(|_| builder.constant_pub(Fp192::zero()))
        .collect();

    // Build the padded input ELEMENT VALUES exactly as the software does, but
    // as WIRES. The padding decision is purely length-driven (public), so it
    // is fixed at circuit-build time.
    let mut padded: Vec<Fp192Var> = inputs.to_vec();
    let needs_padding = inputs.len() % PLUM_GRIFFIN_RATE != 0;
    if needs_padding {
        // (a) capacity-lane flag: state.lanes[RATE] = 1 BEFORE absorbing
        //     (griffin_p192.rs:122). RATE == 2, so this is lane index 2.
        state[PLUM_GRIFFIN_RATE] = builder.constant_pub(Fp192::one());
        // (b) append a "1" element (griffin_p192.rs:123).
        padded.push(builder.constant_pub(Fp192::one()));
    }
    // zero-fill to a multiple of RATE (griffin_p192.rs:125-127).
    while padded.len() % PLUM_GRIFFIN_RATE != 0 {
        padded.push(builder.constant_pub(Fp192::zero()));
    }

    // Absorb: add RATE elements into lanes 0..RATE, then permute. The permute
    // runs after EVERY block including the last (griffin_p192.rs:130-136).
    let mut idx = 0usize;
    while idx < padded.len() {
        for lane in 0..PLUM_GRIFFIN_RATE {
            state[lane] = builder.add_vars(&state[lane], &padded[idx]);
            idx += 1;
        }
        griffin_fp192_permutation_circuit(builder, params, &mut state);
    }

    // Squeeze: emit lanes 0..RATE, permuting between blocks
    // (griffin_p192.rs:139-149).
    let mut outputs: Vec<Fp192Var> = Vec::with_capacity(output_len);
    'squeeze: loop {
        for lane in 0..PLUM_GRIFFIN_RATE {
            outputs.push(state[lane].clone());
            if outputs.len() == output_len {
                break 'squeeze;
            }
        }
        griffin_fp192_permutation_circuit(builder, params, &mut state);
    }

    outputs
}

/// Single-permutation 2-to-1 compression, mirroring
/// `PlumGriffinHasher::compress_pair` (`hasher_plum.rs:95`): load lanes
/// `[left, right, 0, 0]`, run ONE permutation, output lane 0.
///
/// NB: the software `compress_pair` first masks `bytes[24] &= 0x7F` on the
/// 32-byte digest decode (`hasher_plum.rs:109-110`). That masking is part of
/// the BYTE decode, not the field compression. This gadget takes the two
/// input field elements directly (the masked, canonical values), matching the
/// compression core. Callers feeding raw digests must apply the same mask
/// out-of-circuit before allocating the input wires.
pub fn griffin_fp192_compress_pair_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    left: &Fp192Var,
    right: &Fp192Var,
) -> Fp192Var {
    let zero_a = builder.constant_pub(Fp192::zero());
    let zero_b = builder.constant_pub(Fp192::zero());
    let mut state: Vec<Fp192Var> = vec![left.clone(), right.clone(), zero_a, zero_b];
    griffin_fp192_permutation_circuit(builder, params, &mut state);
    state[0].clone()
}

/// Build the full R1CS for a field-element sponge over `input_values`,
/// squeezing `output_len` elements. Returns the finalized system plus the
/// squeezed output wire indices.
pub fn build_griffin_fp192_sponge(
    input_values: &[Fp192],
    output_len: usize,
) -> (Fp192R1cs, Vec<usize>) {
    let params = plum_griffin_params();
    let mut builder = Fp192R1csBuilder::new();
    let input_wires: Vec<Fp192Var> = input_values
        .iter()
        .map(|v| builder.alloc_input(v.clone()))
        .collect();
    let outputs = griffin_fp192_sponge_circuit(&mut builder, params, &input_wires, output_len);
    let out_idx: Vec<usize> = outputs.iter().map(|v| v.index()).collect();
    (builder.finalize(), out_idx)
}

/// Pack a byte string into field elements EXACTLY as
/// `bytes_to_field_elements` (`griffin_p192.rs:301`). Pure witness-side
/// helper; the packing is injective and each element is < p (192 < 199 bits).
fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Fp192> {
    if bytes.is_empty() {
        return vec![Fp192::zero()];
    }
    let mut elems = Vec::with_capacity(bytes.len().div_ceil(ABSORB_BYTES_PER_ELEM));
    let mut chunk = [0u8; ABSORB_BYTES_PER_ELEM];
    let mut chunk_len = 0usize;
    for &byte in bytes {
        chunk[chunk_len] = byte;
        chunk_len += 1;
        if chunk_len == ABSORB_BYTES_PER_ELEM {
            elems.push(absorb_chunk_to_field(&chunk));
            chunk = [0u8; ABSORB_BYTES_PER_ELEM];
            chunk_len = 0;
        }
    }
    if chunk_len > 0 {
        elems.push(absorb_chunk_to_field(&chunk));
    }
    elems
}

fn absorb_chunk_to_field(chunk: &[u8; ABSORB_BYTES_PER_ELEM]) -> Fp192 {
    let mut bytes = [0u8; FIELD_BYTES];
    bytes[..ABSORB_BYTES_PER_ELEM].copy_from_slice(chunk);
    Fp192::from_bytes_le(&bytes).expect("absorb chunk should always fit in F_p192")
}

/// Build the full R1CS for `PlumGriffinHasher::hash_bytes` over `data`.
///
/// Byte->field packing happens OUT of circuit (witness side, see the scope
/// note in the module docs); the sponge over the packed elements is fully
/// constrained. Squeezes `DIGEST_ELEMENTS = 2` field elements (the 64-byte
/// Griffin digest); the caller takes the first 32 bytes to match
/// `PlumGriffinHasher::finalize_bytes`.
///
/// Returns the finalized system, the two squeezed output wire indices, and the
/// 32-byte digest (first 32 bytes of the LE serialisation of output element 0),
/// which equals `PlumGriffinHasher::hash_bytes(data)`.
pub fn build_griffin_fp192_hash_bytes(data: &[u8]) -> (Fp192R1cs, Vec<usize>, [u8; PLUM_DIGEST_BYTES]) {
    let elements = bytes_to_field_elements(data);
    let (r1cs, out_idx) = build_griffin_fp192_sponge(&elements, DIGEST_ELEMENTS);

    // Reconstruct the 32-byte digest from the squeezed output wires, matching
    // field_elements_to_bytes + the hasher's first-32-bytes truncation.
    // field_elements_to_bytes concatenates 32-byte LE of each element; the
    // hasher keeps bytes [0, 32) which is exactly output element 0's LE bytes.
    let elem0 = &r1cs.assignment[out_idx[0]];
    let le = elem0.to_bytes_le();
    let mut digest = [0u8; PLUM_DIGEST_BYTES];
    digest.copy_from_slice(&le[..PLUM_DIGEST_BYTES]);
    (r1cs, out_idx, digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::hash::griffin_p192::plum_griffin_sponge;
    use crate::primitives::hash::hasher_plum::{PlumGriffinHasher, PlumHasher};

    /// THE GATE (1): field-element sponge matches software `plum_griffin_sponge`
    /// on >=4 inputs of varying length, INCLUDING a length that triggers padding
    /// (odd length, not a multiple of RATE=2) and a length that is an exact
    /// multiple of RATE. Honest witness satisfies every constraint.
    #[test]
    fn sponge_matches_software_and_is_satisfied() {
        let params = plum_griffin_params();

        // Varying-length inputs:
        //   len 1  -> padding (1 % 2 != 0)
        //   len 2  -> exact multiple of RATE, NO padding
        //   len 3  -> padding
        //   len 4  -> exact multiple of RATE, NO padding
        //   len 5  -> padding, and forces a multi-block squeeze separately below
        let cases: Vec<Vec<Fp192>> = vec![
            vec![Fp192::from_u64(7)],
            vec![Fp192::from_u64(11), Fp192::from_u64(13)],
            vec![Fp192::from_u64(1), Fp192::from_u64(2), Fp192::from_u64(3)],
            (1..=4).map(Fp192::from_u64).collect(),
            (10..=14).map(Fp192::from_u64).collect(),
        ];

        for (ci, inputs) in cases.iter().enumerate() {
            for &output_len in &[1usize, 2, 3] {
                // Software reference.
                let expected = plum_griffin_sponge(params, inputs.clone(), output_len);

                // Gadget.
                let (r1cs, out_idx) = build_griffin_fp192_sponge(inputs, output_len);

                // (3) honest witness satisfies every constraint.
                if let Err(bad) = r1cs.check_satisfied() {
                    panic!(
                        "case {ci} (len {}, out {output_len}): constraint #{bad} unsatisfied",
                        inputs.len(),
                    );
                }

                // (1) output wires == software sponge output.
                assert_eq!(
                    out_idx.len(),
                    output_len,
                    "case {ci}: wrong number of output wires",
                );
                for j in 0..output_len {
                    assert_eq!(
                        r1cs.assignment[out_idx[j]], expected[j],
                        "case {ci} (len {}, out {output_len}): output {j} mismatch vs software",
                        inputs.len(),
                    );
                }

                let pad = if inputs.len() % PLUM_GRIFFIN_RATE != 0 { "PAD" } else { "exact" };
                eprintln!(
                    "sponge case {ci}: in_len={} ({pad}), out_len={output_len} -> {} constraints, {} vars",
                    inputs.len(),
                    r1cs.num_constraints(),
                    r1cs.num_variables,
                );
            }
        }
    }

    /// Per-absorb-block constraint cost: difference between a 2-block and a
    /// 1-block absorb (both no-padding, single squeeze) isolates one absorb
    /// block + one permutation.
    #[test]
    fn report_per_block_constraint_cost() {
        let one_block: Vec<Fp192> = vec![Fp192::from_u64(1), Fp192::from_u64(2)];
        let two_block: Vec<Fp192> =
            vec![Fp192::from_u64(1), Fp192::from_u64(2), Fp192::from_u64(3), Fp192::from_u64(4)];
        let (r1, _) = build_griffin_fp192_sponge(&one_block, 1);
        let (r2, _) = build_griffin_fp192_sponge(&two_block, 1);
        eprintln!(
            "PER-ABSORB-BLOCK: 1-block={} constraints, 2-block={} constraints, delta(one block+perm)={}",
            r1.num_constraints(),
            r2.num_constraints(),
            r2.num_constraints() - r1.num_constraints(),
        );
    }

    /// THE GATE (2): hash_bytes gadget output == software
    /// `PlumGriffinHasher::hash_bytes` on >=4 byte inputs of varying length,
    /// including empty, sub-chunk, exactly one 24-byte chunk, and multi-chunk.
    #[test]
    fn hash_bytes_matches_software() {
        let cases: Vec<&[u8]> = vec![
            b"",
            b"hi",
            b"PLUM Griffin leaf",                       // < 24 bytes
            &[0xABu8; 24],                              // exactly one chunk
            b"the quick brown fox jumps over the lazy dog", // multi-chunk
        ];
        for (ci, data) in cases.iter().enumerate() {
            let expected = PlumGriffinHasher::hash_bytes(data);
            let (r1cs, _out_idx, digest) = build_griffin_fp192_hash_bytes(data);

            // (3) honest witness satisfies every constraint.
            if let Err(bad) = r1cs.check_satisfied() {
                panic!("hash_bytes case {ci} (len {}): constraint #{bad} unsatisfied", data.len());
            }

            // (2) gadget digest == software hash_bytes.
            assert_eq!(
                digest, expected,
                "hash_bytes case {ci} (len {}): gadget digest != software",
                data.len(),
            );
            eprintln!(
                "hash_bytes case {ci}: in_len={} -> {} constraints, {} vars",
                data.len(),
                r1cs.num_constraints(),
                r1cs.num_variables,
            );
        }
    }

    /// THE GATE (4): a corrupted interior wire is rejected (negative control;
    /// the satisfaction checker is not vacuously passing).
    #[test]
    fn corrupted_interior_wire_is_rejected() {
        let inputs: Vec<Fp192> =
            vec![Fp192::from_u64(3), Fp192::from_u64(5), Fp192::from_u64(7)];
        let (mut r1cs, out_idx) = build_griffin_fp192_sponge(&inputs, 2);
        assert!(r1cs.check_satisfied().is_ok(), "baseline unsatisfied");

        // Corrupt an interior wire that is NOT an output wire and NOT the
        // constant-1 slot. Walk from index 1 upward to the first index that is
        // (a) not in out_idx; flipping it must break >=1 constraint.
        let mut corrupted = None;
        for wi in 1..r1cs.assignment.len() {
            if out_idx.contains(&wi) {
                continue;
            }
            let mut r = r1cs.clone();
            r.assignment[wi] = r.assignment[wi].clone() + Fp192::one();
            if r.check_satisfied().is_err() {
                corrupted = Some(wi);
                break;
            }
        }
        let wi = corrupted.expect("no interior wire was load-bearing — checker may be vacuous");
        r1cs.assignment[wi] = r1cs.assignment[wi].clone() + Fp192::one();
        assert!(
            r1cs.check_satisfied().is_err(),
            "checker accepted a corrupted interior wire {wi}",
        );
        eprintln!("corrupted interior wire {wi} correctly rejected");
    }

    /// Compress-pair gadget matches the field core of
    /// `PlumGriffinHasher::compress_pair`: load [left,right,0,0], one
    /// permutation, output lane 0.
    #[test]
    fn compress_pair_matches_software_core() {
        use crate::primitives::hash::griffin_p192::{PlumGriffinState, plum_griffin_permutation};
        let params = plum_griffin_params();

        for (l, r) in [(0u64, 0u64), (1, 0), (12345, 67890), (999_983, 7)] {
            let left = Fp192::from_u64(l);
            let right = Fp192::from_u64(r);

            // Software field core (same as compress_pair after the byte decode).
            let mut sw = PlumGriffinState::from_lanes([
                left.clone(),
                right.clone(),
                Fp192::zero(),
                Fp192::zero(),
            ]);
            plum_griffin_permutation(params, &mut sw);
            let expected = sw.lanes()[0].clone();

            // Gadget.
            let mut builder = Fp192R1csBuilder::new();
            let lv = builder.alloc_input(left);
            let rv = builder.alloc_input(right);
            let out = griffin_fp192_compress_pair_circuit(&mut builder, params, &lv, &rv);
            let out_idx = out.index();
            let r1cs = builder.finalize();

            assert!(r1cs.check_satisfied().is_ok(), "compress-pair unsatisfied for ({l},{r})");
            assert_eq!(
                r1cs.assignment[out_idx], expected,
                "compress-pair output != software core for ({l},{r})",
            );
        }
        eprintln!("compress_pair gadget matches software field core");
    }
}
