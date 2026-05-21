//! SP1 hash-based PQ anchor (Phase B6.2).
//!
//! Verifies a SHA-256 Merkle authentication path of depth 22 over a
//! 32-byte leaf — exercising the *same workload shape* that
//! dominates SPHINCS+/SLH-DSA verification (FORS + WOTS+ + hypertree
//! authentication paths reduce to many SHA-256 invocations on
//! 64-byte inputs). The SP1 sha2 patch routes SHA-256 through
//! `SHA_COMPRESS` + `SHA_EXTEND` precompiles.
//!
//! Why a Merkle path instead of full SLH-DSA: the `slh-dsa` crate's
//! signature 2.3.0-pre dependency conflicts with the stable signature
//! 2.2 that the SP1-patched k256 0.13.4 pulls in. Rather than fork
//! the patch table, we exercise the *workload shape that dominates*
//! SLH-DSA verify (Merkle path SHA-256 batches) and cross-cite
//! Fenbushi 2025 for the actual SLH-DSA prove-time number on a
//! comparable zkVM.
//!
//! Depth 22 ≈ FORS-tree height in SLH-DSA-128f. Concretely a
//! SLH-DSA-128f verify performs roughly 5k–20k SHA-256 calls
//! depending on the param set (FORS_HEIGHT × FORS_NUM_TREES +
//! WOTS_LEN × HYPERTREE_HEIGHT + ...). Our 22-iteration path is a
//! conservative *single-tree* baseline.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct GuestInput {
    /// 32-byte starting leaf.
    leaf: [u8; 32],
    /// Sibling hashes along the authentication path (each 32 bytes).
    siblings: Vec<[u8; 32]>,
    /// Direction bit per level: 0 = sibling on right, 1 = sibling on left.
    directions: Vec<u8>,
    /// 32-byte expected root.
    expected_root: [u8; 32],
}

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input: GuestInput =
        bincode::deserialize(&bytes).expect("sphincs guest: bincode decode failed");

    assert_eq!(input.siblings.len(), input.directions.len(),
        "sphincs guest: path / direction length mismatch");

    let mut acc = input.leaf;
    for (sib, dir) in input.siblings.iter().zip(input.directions.iter()) {
        let mut h = Sha256::new();
        if *dir == 0 {
            h.update(&acc);
            h.update(sib);
        } else {
            h.update(sib);
            h.update(&acc);
        }
        let out = h.finalize();
        acc.copy_from_slice(&out);
    }

    let accepted = acc == input.expected_root;
    sp1_zkvm::io::commit(&accepted);
}
