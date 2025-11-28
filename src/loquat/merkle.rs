//! Merkle Tree Implementation for Loquat
//!
//! This module provides a Merkle tree implementation using Griffin hash function
//! for use in the LDT phase of the Loquat signature scheme.
//!
//! Griffin is used instead of SHA256 because:
//! - It's SNARK-friendly (low circuit complexity)
//! - It operates natively over prime fields
//! - It's more efficient in zero-knowledge proof systems

use super::hasher::{GriffinHasher, LoquatHasher};
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// A Merkle tree using Griffin hash function.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    nodes: Vec<Vec<u8>>,
    leaf_count: usize,
}

impl MerkleTree {
    /// Create a new Merkle tree from a set of leaves.
    pub fn new<T: AsRef<[u8]>>(leaves: &[T]) -> Self {
        let leaf_count = leaves.len();
        if leaf_count == 0 {
            return Self {
                nodes: vec![],
                leaf_count: 0,
            };
        }
        let mut nodes = vec![vec![0u8; 32]; 2 * leaf_count];

        // Hash leaves into the tree using Griffin
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[leaf_count + i] = GriffinHasher::hash(leaf.as_ref());
        }

        // Build the tree from the leaves up
        for i in (1..leaf_count).rev() {
            let mut hasher = GriffinHasher::new();
            hasher.update(&nodes[2 * i]);
            hasher.update(&nodes[2 * i + 1]);
            nodes[i] = hasher.finalize();
        }

        Self { nodes, leaf_count }
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
        let mut current_hash = GriffinHasher::hash(leaf.as_ref());
        let mut current_index_in_level = leaf_index;

        for sibling_hash in path {
            let mut hasher = GriffinHasher::new();
            if current_index_in_level % 2 == 0 {
                hasher.update(&current_hash);
                hasher.update(sibling_hash);
            } else {
                hasher.update(sibling_hash);
                hasher.update(&current_hash);
            }
            current_hash = hasher.finalize();
            current_index_in_level /= 2;
        }

        current_hash == root
    }

    /// Get the number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }
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
