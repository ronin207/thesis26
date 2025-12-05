//! Merkle Tree Implementation for Loquat
//!
//! This module provides a Merkle tree implementation using Griffin hash function
//! for use in the LDT phase of the Loquat signature scheme.
//!
//! Griffin is used instead of SHA256 because:
//! - It's SNARK-friendly (low circuit complexity)
//! - It operates natively over prime fields
//! - It's more efficient in zero-knowledge proof systems

use super::field_utils::{self, F};
use super::griffin::{griffin_permutation_raw, GRIFFIN_STATE_WIDTH};
use super::hasher::GriffinHasher;
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Configuration for Merkle tree construction.
#[derive(Debug, Clone, Copy)]
pub struct MerkleConfig {
    /// Number of raw leaves to hash together into one Merkle leaf.
    leaf_arity: usize,
}

impl MerkleConfig {
    /// Standard Merkle tree: one node per leaf.
    pub const fn standard() -> Self {
        Self { leaf_arity: 1 }
    }

    /// TreeCap optimization (paper §4.3): hash `leaf_arity` nodes into 1 leaf.
    pub fn tree_cap(leaf_arity: usize) -> Self {
        Self {
            leaf_arity: leaf_arity.max(1),
        }
    }

    /// Returns how many nodes are collapsed into a single leaf.
    pub const fn leaf_arity(&self) -> usize {
        self.leaf_arity
    }
}

/// A Merkle tree using Griffin hash function.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: Vec<Vec<u8>>,
    leaf_count: usize,
    config: MerkleConfig,
}

impl MerkleTree {
    /// Create a new Merkle tree from a set of leaves.
    pub fn new<T: AsRef<[u8]>>(leaves: &[T]) -> Self {
        Self::new_with_config(leaves, MerkleConfig::standard())
    }

    /// Create a new Merkle tree using the provided configuration.
    pub fn new_with_config<T: AsRef<[u8]>>(leaves: &[T], config: MerkleConfig) -> Self {
        let leaf_count = leaves.len();
        if leaf_count == 0 {
            return Self {
                nodes: vec![],
                leaf_count: 0,
                config,
            };
        }
        let arity = config.leaf_arity.max(1);
        let chunked_leaf_count = (leaf_count + arity - 1) / arity;
        let mut nodes = vec![vec![0u8; 32]; 2 * chunked_leaf_count];

        // Hash leaves into the tree using Griffin; optionally collapse multiple nodes per leaf.
        for (i, chunk) in leaves.chunks(arity).enumerate() {
            let compressed = compress_leaf_single_permutation(chunk);
            nodes[chunked_leaf_count + i] = compressed;
        }

        // Build the tree from the leaves up
        for i in (1..chunked_leaf_count).rev() {
            nodes[i] = compress_internal_single_permutation(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self {
            nodes,
            leaf_count: chunked_leaf_count,
            config,
        }
    }

    /// Get the root of the tree.
    pub fn root(&self) -> Option<Vec<u8>> {
        if self.nodes.is_empty() {
            None
        } else {
            Some(self.nodes[1].clone())
        }
    }

    /// Generate an authentication path for a leaf.
    pub fn generate_auth_path(&self, leaf_index: usize) -> Vec<Vec<u8>> {
        if leaf_index >= self.leaf_count {
            return vec![];
        }
        let mut path = Vec::new();
        let mut current_index = leaf_index + self.leaf_count;

        while current_index > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            path.push(self.nodes[sibling_index].clone());
            current_index /= 2;
        }

        path
    }

    /// Verify an authentication path using Griffin hash.
    pub fn verify_auth_path<T: AsRef<[u8]>>(
        root: &[u8],
        leaf: T,
        leaf_index: usize,
        path: &[Vec<u8>],
    ) -> bool {
        Self::verify_auth_path_with_config(root, leaf, leaf_index, path, MerkleConfig::standard())
    }

    /// Verify an authentication path using Griffin hash with a custom configuration.
    pub fn verify_auth_path_with_config<T: AsRef<[u8]>>(
        root: &[u8],
        leaf: T,
        leaf_index: usize,
        path: &[Vec<u8>],
        config: MerkleConfig,
    ) -> bool {
        let _ = config; // reserved for potential arity-aware path checks
        let mut current_hash = compress_leaf_single_permutation(std::slice::from_ref(&leaf));
        let mut current_index_in_level = leaf_index;

        for sibling_hash in path {
            if current_index_in_level % 2 == 0 {
                current_hash =
                    compress_internal_single_permutation(&current_hash, sibling_hash);
            } else {
                current_hash =
                    compress_internal_single_permutation(sibling_hash, &current_hash);
            }
            current_index_in_level /= 2;
        }

        current_hash == root
    }

    /// Get the number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Returns the configuration used to build this tree.
    pub fn config(&self) -> MerkleConfig {
        self.config
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }
}

/// Compress a slice of leaves (already grouped per leaf_arity chunk) into a single
/// 32-byte digest using exactly one Griffin permutation.
fn compress_leaf_single_permutation<T: AsRef<[u8]>>(leaves: &[T]) -> Vec<u8> {
    // Fold all 16-byte chunks of all leaves into two accumulators.
    let mut acc = [F::zero(); 2];
    let mut buf16 = [0u8; 16];
    let mut chunk_count: usize = 0;

    for leaf in leaves {
        for (i, byte) in leaf.as_ref().iter().enumerate() {
            buf16[i % 16] = *byte;
            if i % 16 == 15 {
                let elem = field_utils::bytes_to_field_element(&buf16);
                acc[chunk_count % 2] += elem;
                chunk_count += 1;
                buf16 = [0u8; 16];
            }
        }
        // flush remainder in this leaf
        let rem = leaf.as_ref().len() % 16;
        if rem != 0 {
            let elem = field_utils::bytes_to_field_element(&buf16);
            acc[chunk_count % 2] += elem;
            chunk_count += 1;
            buf16 = [0u8; 16];
        }
    }

    let mut state = [F::zero(); GRIFFIN_STATE_WIDTH];
    state[0] = acc[0];
    state[1] = acc[1];
    state[2] = F::new(chunk_count as u128); // length tag
    // state[3] stays zero

    griffin_permutation_raw(&mut state);

    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&field_utils::field_to_bytes(&state[0]));
    out.extend_from_slice(&field_utils::field_to_bytes(&state[1]));
    out.truncate(32);
    out
}

fn digest_to_fields(digest: &[u8]) -> [F; 2] {
    let mut out = [F::zero(); 2];
    for (i, chunk) in digest.chunks(16).enumerate() {
        let mut limb = [0u8; 16];
        limb.copy_from_slice(chunk);
        out[i] = field_utils::bytes_to_field_element(&limb);
    }
    out
}

fn compress_internal_single_permutation(left: &[u8], right: &[u8]) -> Vec<u8> {
    let lf = digest_to_fields(left);
    let rf = digest_to_fields(right);
    let mut state = [F::zero(); GRIFFIN_STATE_WIDTH];
    state[0] = lf[0];
    state[1] = lf[1];
    state[2] = rf[0];
    state[3] = rf[1];
    griffin_permutation_raw(&mut state);
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&field_utils::field_to_bytes(&state[0]));
    out.extend_from_slice(&field_utils::field_to_bytes(&state[1]));
    out.truncate(32);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_basic() {
        let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec()];
        let tree = MerkleTree::new(&leaves);

        assert_eq!(tree.leaf_count(), 2);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_merkle_tree_empty() {
        let leaves: Vec<Vec<u8>> = vec![];
        let tree = MerkleTree::new(&leaves);

        assert!(tree.is_empty());
        assert!(tree.root().is_none());
    }

    #[test]
    fn test_merkle_auth_path() {
        let leaves: Vec<Vec<u8>> = vec![
            b"leaf0".to_vec(),
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
        ];
        let tree = MerkleTree::new(&leaves);
        let root = tree.root().unwrap();

        for i in 0..4 {
            let path = tree.generate_auth_path(i);
            assert!(MerkleTree::verify_auth_path(&root, &leaves[i], i, &path));
        }
    }

    #[test]
    fn test_merkle_invalid_auth_path() {
        let leaves: Vec<Vec<u8>> = vec![
            b"leaf0".to_vec(),
            b"leaf1".to_vec(),
            b"leaf2".to_vec(),
            b"leaf3".to_vec(),
        ];
        let tree = MerkleTree::new(&leaves);
        let root = tree.root().unwrap();

        let path = tree.generate_auth_path(0);
        // Try to verify with wrong leaf
        assert!(!MerkleTree::verify_auth_path(
            &root,
            b"wrong_leaf",
            0,
            &path
        ));
    }

    #[test]
    fn test_merkle_determinism() {
        let leaves: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
        let tree1 = MerkleTree::new(&leaves);
        let tree2 = MerkleTree::new(&leaves);

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_merkle_different_leaves() {
        let leaves1: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
        let leaves2: Vec<Vec<u8>> = vec![b"c".to_vec(), b"d".to_vec()];
        let tree1 = MerkleTree::new(&leaves1);
        let tree2 = MerkleTree::new(&leaves2);

        assert_ne!(tree1.root(), tree2.root());
    }
}
