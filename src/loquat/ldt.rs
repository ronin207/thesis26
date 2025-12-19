use super::field_utils::F2;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDTProof {
    pub commitments: Vec<[u8; 32]>,
    /// Layer-t cap nodes (paper §4.3) for each commitment layer.
    /// When non-empty, the corresponding commitment root is defined as
    /// `H(cap_nodes[layer])` and Merkle auth paths are truncated to that cap layer.
    pub cap_nodes: Vec<Vec<[u8; 32]>>,
    pub openings: Vec<LDTOpening>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LDTOpening {
    pub position: usize,
    /// Opened codeword chunks per FRI/LDT layer (length = r+1).
    /// Each chunk corresponds to the Merkle leaf at that layer (TreeCap leaf_arity = 2^eta).
    pub codeword_chunks: Vec<Vec<F2>>,
    /// Merkle authentication paths per layer (length = r+1), truncated to the cap layer.
    pub auth_paths: Vec<Vec<Vec<u8>>>,
}
