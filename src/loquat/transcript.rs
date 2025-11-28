//! Transcript Implementation for Fiat-Shamir Transform
//!
//! This module provides a transcript implementation using Griffin hash function
//! for the Fiat-Shamir transform in the Loquat signature scheme.
//!
//! Griffin is used instead of SHA256 because:
//! - It's SNARK-friendly (low circuit complexity)
//! - It operates natively over prime fields
//! - It's more efficient in zero-knowledge proof systems

use super::hasher::{GriffinHasher, LoquatHasher};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

/// Minimal transcript implementation (Fiat-Shamir) using Griffin hash.
/// Compatible with no_std builds.
#[derive(Clone)]
pub struct Transcript {
    /// Accumulated state for hashing
    state: Vec<u8>,
    /// Counter for challenge generation
    counter: u64,
}

impl Transcript {
    /// Create a new transcript with the given label
    pub fn new(label: &[u8]) -> Self {
        let mut state = Vec::new();
        state.extend_from_slice(b"loquat.transcript.griffin");
        state.extend_from_slice(&(label.len() as u64).to_le_bytes());
        state.extend_from_slice(label);
        Self { state, counter: 0 }
    }

    /// Append a message to the transcript
    pub fn append_message(&mut self, label: &[u8], data: &[u8]) {
        self.state
            .extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state
            .extend_from_slice(&(data.len() as u64).to_le_bytes());
        self.state.extend_from_slice(data);
    }

    /// Generate challenge bytes from the transcript
    pub fn challenge_bytes(&mut self, label: &[u8], output: &mut [u8]) {
        let mut offset = 0usize;
        let mut chunk_index: u32 = 0;

        while offset < output.len() {
            // Build input for this chunk
            let mut hasher = GriffinHasher::new();
            hasher.update(&self.state);
            hasher.update(&(label.len() as u64).to_le_bytes());
            hasher.update(label);
            hasher.update(&self.counter.to_le_bytes());
            hasher.update(&chunk_index.to_le_bytes());

            let digest = hasher.finalize();
            let remaining = output.len() - offset;
            let take = remaining.min(digest.len());
            output[offset..offset + take].copy_from_slice(&digest[..take]);
            offset += take;
            chunk_index = chunk_index.wrapping_add(1);
        }

        // Update transcript state with the challenge
        self.append_message(label, output);
        self.counter = self.counter.wrapping_add(1);
    }

    /// Get a single challenge field element (convenience method)
    pub fn challenge_scalar(&mut self, label: &[u8]) -> [u8; 32] {
        let mut output = [0u8; 32];
        self.challenge_bytes(label, &mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_determinism() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.append_message(b"data", b"hello");
        t2.append_message(b"data", b"hello");

        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];

        t1.challenge_bytes(b"challenge", &mut c1);
        t2.challenge_bytes(b"challenge", &mut c2);

        assert_eq!(c1, c2);
    }

    #[test]
    fn test_transcript_different_inputs() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.append_message(b"data", b"hello");
        t2.append_message(b"data", b"world");

        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];

        t1.challenge_bytes(b"challenge", &mut c1);
        t2.challenge_bytes(b"challenge", &mut c2);

        assert_ne!(c1, c2);
    }

    #[test]
    fn test_transcript_sequential_challenges() {
        let mut t = Transcript::new(b"test");
        t.append_message(b"data", b"test data");

        let mut c1 = [0u8; 32];
        let mut c2 = [0u8; 32];

        t.challenge_bytes(b"challenge1", &mut c1);
        t.challenge_bytes(b"challenge2", &mut c2);

        // Sequential challenges should be different
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_transcript_large_output() {
        let mut t = Transcript::new(b"test");
        t.append_message(b"data", b"test data");

        let mut output = [0u8; 128];
        t.challenge_bytes(b"large_challenge", &mut output);

        // Should fill the entire buffer
        assert!(!output.iter().all(|&b| b == 0));
    }
}
