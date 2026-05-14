//! Merkle vector commitment for PLUM.
//!
//! Generic over `PlumHasher` so the same tree code works for Griffin
//! and SHA3 instantiations. Leaves are `F_p192` field elements (each
//! hashed to a 32-byte digest before placement), internal nodes use
//! `H::compress_pair` so we pay exactly one 2-to-1 compression per
//! level (mirrors Loquat's single-permutation Merkle optimisation).
//!
//! Tree shape: leaves are padded to the next power of two with zero
//! field elements. Authentication paths return one sibling per level,
//! plus the leaf's index so the verifier knows which side is which.

use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::field_p192::Fp192;
use super::hasher::{PLUM_DIGEST_BYTES, PlumHasher};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlumMerkleProof {
    pub leaf_index: usize,
    pub leaf: Fp192,
    /// Sibling digests, indexed from leaf level up to (but not including)
    /// the root. `siblings[i]` is the sibling at level `i` (level 0 = leaves).
    pub siblings: Vec<[u8; PLUM_DIGEST_BYTES]>,
}

pub struct PlumMerkleTree<H: PlumHasher> {
    /// All levels, bottom up. `levels[0]` is the leaf-digest level.
    levels: Vec<Vec<[u8; PLUM_DIGEST_BYTES]>>,
    leaves: Vec<Fp192>,
    n_leaves_padded: usize,
    _hasher: PhantomData<H>,
}

impl<H: PlumHasher> PlumMerkleTree<H> {
    /// Build a tree over `leaves`. Empty input is rejected.
    pub fn commit(leaves: Vec<Fp192>) -> Self {
        assert!(!leaves.is_empty(), "PLUM Merkle: cannot commit to empty vector");
        let n = leaves.len();
        let n_padded = n.next_power_of_two();

        // Hash each leaf (Fp192::to_bytes_le → 32 bytes → hash).
        let mut current: Vec<[u8; PLUM_DIGEST_BYTES]> = Vec::with_capacity(n_padded);
        for leaf in &leaves {
            current.push(H::hash_bytes(&leaf.to_bytes_le()));
        }
        // Pad with the digest of `Fp192::zero()`.
        let zero_digest = H::hash_bytes(&Fp192::zero().to_bytes_le());
        while current.len() < n_padded {
            current.push(zero_digest);
        }

        let mut levels: Vec<Vec<[u8; PLUM_DIGEST_BYTES]>> = Vec::new();
        levels.push(current);

        while levels.last().unwrap().len() > 1 {
            let lower = levels.last().unwrap();
            let mut next: Vec<[u8; PLUM_DIGEST_BYTES]> = Vec::with_capacity(lower.len() / 2);
            for chunk in lower.chunks(2) {
                next.push(H::compress_pair(&chunk[0], &chunk[1]));
            }
            levels.push(next);
        }

        Self {
            levels,
            leaves,
            n_leaves_padded: n_padded,
            _hasher: PhantomData,
        }
    }

    pub fn root(&self) -> [u8; PLUM_DIGEST_BYTES] {
        *self.levels.last().unwrap().first().unwrap()
    }

    pub fn leaves(&self) -> &[Fp192] {
        &self.leaves
    }

    pub fn len_padded(&self) -> usize {
        self.n_leaves_padded
    }

    /// Open the authentication path for the leaf at `index` (must be < original
    /// `leaves.len()`).
    pub fn open(&self, index: usize) -> PlumMerkleProof {
        assert!(index < self.leaves.len(), "PLUM Merkle: open index out of range");
        let mut siblings: Vec<[u8; PLUM_DIGEST_BYTES]> = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling_idx = idx ^ 1;
            siblings.push(level[sibling_idx]);
            idx /= 2;
        }
        PlumMerkleProof {
            leaf_index: index,
            leaf: self.leaves[index].clone(),
            siblings,
        }
    }

    /// Verify a proof against a stated root. Returns `true` iff the proof
    /// reconstructs the root and references the claimed leaf value.
    pub fn verify(root: &[u8; PLUM_DIGEST_BYTES], proof: &PlumMerkleProof) -> bool {
        let mut digest = H::hash_bytes(&proof.leaf.to_bytes_le());
        let mut idx = proof.leaf_index;
        for sibling in &proof.siblings {
            let (left, right) = if idx & 1 == 0 {
                (digest, *sibling)
            } else {
                (*sibling, digest)
            };
            digest = H::compress_pair(&left, &right);
            idx /= 2;
        }
        *root == digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::hasher::{PlumGriffinHasher, PlumSha3Hasher};

    fn sample_leaves(n: usize) -> Vec<Fp192> {
        (0..n).map(|i| Fp192::from_u64(i as u64 * 31 + 7)).collect()
    }

    #[test]
    fn griffin_tree_commits_and_opens_all_leaves() {
        let leaves = sample_leaves(13);
        let tree = PlumMerkleTree::<PlumGriffinHasher>::commit(leaves.clone());
        let root = tree.root();
        for (i, _) in leaves.iter().enumerate() {
            let proof = tree.open(i);
            assert!(
                PlumMerkleTree::<PlumGriffinHasher>::verify(&root, &proof),
                "verify failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn sha3_tree_commits_and_opens_all_leaves() {
        let leaves = sample_leaves(17);
        let tree = PlumMerkleTree::<PlumSha3Hasher>::commit(leaves.clone());
        let root = tree.root();
        for (i, _) in leaves.iter().enumerate() {
            let proof = tree.open(i);
            assert!(
                PlumMerkleTree::<PlumSha3Hasher>::verify(&root, &proof),
                "verify failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn padding_is_power_of_two() {
        let tree = PlumMerkleTree::<PlumSha3Hasher>::commit(sample_leaves(5));
        assert_eq!(tree.len_padded(), 8);
        let tree = PlumMerkleTree::<PlumSha3Hasher>::commit(sample_leaves(8));
        assert_eq!(tree.len_padded(), 8);
        let tree = PlumMerkleTree::<PlumSha3Hasher>::commit(sample_leaves(9));
        assert_eq!(tree.len_padded(), 16);
    }

    #[test]
    fn tampered_leaf_breaks_verification() {
        let leaves = sample_leaves(8);
        let tree = PlumMerkleTree::<PlumGriffinHasher>::commit(leaves);
        let mut proof = tree.open(3);
        proof.leaf = Fp192::from_u64(0xdead_beef);
        assert!(!PlumMerkleTree::<PlumGriffinHasher>::verify(&tree.root(), &proof));
    }

    #[test]
    fn tampered_sibling_breaks_verification() {
        let leaves = sample_leaves(8);
        let tree = PlumMerkleTree::<PlumSha3Hasher>::commit(leaves);
        let mut proof = tree.open(2);
        proof.siblings[0][0] ^= 0xFF;
        assert!(!PlumMerkleTree::<PlumSha3Hasher>::verify(&tree.root(), &proof));
    }

    #[test]
    fn root_changes_with_any_leaf_change() {
        let mut leaves = sample_leaves(6);
        let t1 = PlumMerkleTree::<PlumGriffinHasher>::commit(leaves.clone());
        leaves[2] = Fp192::from_u64(0xdead_beef);
        let t2 = PlumMerkleTree::<PlumGriffinHasher>::commit(leaves);
        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn proof_serde_roundtrips() {
        let leaves = sample_leaves(8);
        let tree = PlumMerkleTree::<PlumSha3Hasher>::commit(leaves);
        let proof = tree.open(5);
        let encoded = bincode::serialize(&proof).expect("encode");
        let decoded: PlumMerkleProof = bincode::deserialize(&encoded).expect("decode");
        assert!(PlumMerkleTree::<PlumSha3Hasher>::verify(&tree.root(), &decoded));
    }
}
