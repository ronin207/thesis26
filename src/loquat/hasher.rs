//! Hash Abstraction Layer
//!
//! This module provides a trait-based abstraction for hash functions,
//! allowing easy switching between SHA256 and Griffin (or other hash functions).
//!
//! Griffin is preferred for SNARK-friendly applications as it has significantly
//! lower circuit complexity compared to SHA256.

use super::field_p127::Fp127;
use super::griffin::griffin_hash;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Hash function type selector
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HashType {
    /// Griffin algebraic hash (SNARK-friendly, default)
    #[default]
    Griffin,
    /// SHA256 (legacy, for compatibility)
    Sha256,
}

/// Trait for hash functions used in the Loquat signature scheme
pub trait LoquatHasher: Clone {
    /// Create a new hasher instance
    fn new() -> Self;

    /// Update the hasher state with additional data
    fn update(&mut self, data: &[u8]);

    /// Finalize and return the hash digest
    fn finalize(self) -> Vec<u8>;

    /// Reset the hasher to initial state
    fn reset(&mut self);

    /// One-shot hash function
    fn hash(data: &[u8]) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash multiple pieces of data
    fn hash_many(parts: &[&[u8]]) -> Vec<u8>
    where
        Self: Sized,
    {
        let mut hasher = Self::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize()
    }
}

/// Griffin hasher implementation
#[derive(Clone)]
pub struct GriffinHasher {
    buffer: Vec<u8>,
}

impl LoquatHasher for GriffinHasher {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(self) -> Vec<u8> {
        griffin_hash(&self.buffer)
    }

    fn reset(&mut self) {
        self.buffer.clear();
    }
}

/// SHA256 hasher implementation (for backward compatibility)
#[derive(Clone)]
pub struct Sha256Hasher {
    buffer: Vec<u8>,
}

impl LoquatHasher for Sha256Hasher {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize(self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.buffer);
        hasher.finalize().to_vec()
    }

    fn reset(&mut self) {
        self.buffer.clear();
    }
}

/// Default hasher type alias (uses Griffin)
pub type DefaultHasher = GriffinHasher;

/// Convenience function to hash data using the default hasher (Griffin)
pub fn hash(data: &[u8]) -> Vec<u8> {
    GriffinHasher::hash(data)
}

/// Convenience function to hash data using Griffin
pub fn griffin_hash_bytes(data: &[u8]) -> Vec<u8> {
    GriffinHasher::hash(data)
}

/// Convenience function to hash data using SHA256 (legacy)
pub fn sha256_hash_bytes(data: &[u8]) -> Vec<u8> {
    Sha256Hasher::hash(data)
}

/// Hash with domain separation
pub fn hash_with_domain(domain: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hasher = GriffinHasher::new();
    hasher.update(domain);
    hasher.update(&(data.len() as u64).to_le_bytes());
    hasher.update(data);
    hasher.finalize()
}

/// Hash two field elements and return bytes
pub fn hash_field_elements(a: Fp127, b: Fp127) -> Vec<u8> {
    let mut hasher = GriffinHasher::new();
    hasher.update(&a.0.to_le_bytes());
    hasher.update(&b.0.to_le_bytes());
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_griffin_hasher() {
        let data = b"test data";
        let hash1 = GriffinHasher::hash(data);
        let hash2 = GriffinHasher::hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_sha256_hasher() {
        let data = b"test data";
        let hash1 = Sha256Hasher::hash(data);
        let hash2 = Sha256Hasher::hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_different_hashers_different_output() {
        let data = b"test data";
        let griffin_hash = GriffinHasher::hash(data);
        let sha256_hash = Sha256Hasher::hash(data);
        // Different hash functions should produce different outputs
        assert_ne!(griffin_hash, sha256_hash);
    }

    #[test]
    fn test_incremental_hashing() {
        let data1 = b"hello ";
        let data2 = b"world";
        let combined = b"hello world";

        let mut hasher = GriffinHasher::new();
        hasher.update(data1);
        hasher.update(data2);
        let incremental = hasher.finalize();

        let direct = GriffinHasher::hash(combined);
        assert_eq!(incremental, direct);
    }

    #[test]
    fn test_hash_with_domain() {
        let domain = b"test_domain";
        let data = b"test_data";
        let hash1 = hash_with_domain(domain, data);
        let hash2 = hash_with_domain(domain, data);
        assert_eq!(hash1, hash2);

        // Different domains should produce different hashes
        let hash3 = hash_with_domain(b"other_domain", data);
        assert_ne!(hash1, hash3);
    }
}
