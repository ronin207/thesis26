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
use super::field_utils::{F, F2};
use super::griffin::{get_griffin_params, griffin_sponge};
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

/// Field-native transcript using Griffin sponge directly over field elements.
///
/// This is intended for SNARK-friendly Fiat–Shamir: the exact same transcript
/// derivation can be mirrored inside the R1CS without any byte/bit constraints.
///
/// Design notes:
/// - Domain separation is done by mixing (label_tag, label_len, payload_len).
/// - Challenges additionally mix an internal counter to avoid collisions across
///   repeated queries with the same label.
#[derive(Clone, Debug)]
pub struct FieldTranscript {
    /// Chaining value (2 field elements ≈ 32 bytes of state)
    state: [F; 2],
    /// Counter for challenge generation (mixed into the hash)
    counter: u64,
}

impl FieldTranscript {
    /// Create a new field-native transcript with the given label.
    pub fn new(label: &[u8]) -> Self {
        let domain_tag = pack_label_tag(b"loquat.transcript.field.griffin");
        let (label_tag, label_len) = label_tags(label);
        let state = hash_to_digest(&[
            domain_tag,
            label_tag,
            label_len,
            // Explicitly bind the initial counter value.
            F::new(0),
        ]);
        Self { state, counter: 0 }
    }

    /// Absorb a sequence of field elements under a label.
    pub fn append_f_vec(&mut self, label: &[u8], values: &[F]) {
        self.absorb(label, values);
    }

    /// Absorb a sequence of F² elements under a label.
    pub fn append_f2_vec(&mut self, label: &[u8], values: &[F2]) {
        let mut flat = Vec::with_capacity(values.len() * 2);
        for v in values {
            flat.push(v.c0);
            flat.push(v.c1);
        }
        self.absorb(label, &flat);
    }

    /// Absorb a single field element under a label.
    pub fn append_f(&mut self, label: &[u8], value: F) {
        self.absorb(label, &[value]);
    }

    /// Absorb a single F² element under a label.
    pub fn append_f2(&mut self, label: &[u8], value: F2) {
        self.absorb(label, &[value.c0, value.c1]);
    }

    /// Absorb a 32-byte digest under a label as two field elements (little-endian limbs).
    pub fn append_digest32_as_fields(&mut self, label: &[u8], digest32: &[u8; 32]) {
        let lo = F::new(u128::from_le_bytes(digest32[0..16].try_into().unwrap()));
        let hi = F::new(u128::from_le_bytes(digest32[16..32].try_into().unwrap()));
        self.absorb(label, &[lo, hi]);
    }

    /// Produce a 2-field “seed” (≈ 32 bytes) challenge and update the transcript state.
    pub fn challenge_seed(&mut self, label: &[u8]) -> [F; 2] {
        let (label_tag, label_len) = label_tags(label);
        // Mix counter as a payload of length 1.
        let counter_f = F::new(self.counter as u128);
        let digest = hash_to_digest_prefixed(&self.state, label_tag, label_len, &[counter_f]);
        self.state = digest;
        self.counter = self.counter.wrapping_add(1);
        digest
    }

    /// Produce a single field challenge (first limb of `challenge_seed`).
    pub fn challenge_f(&mut self, label: &[u8]) -> F {
        self.challenge_seed(label)[0]
    }

    /// Produce an F² challenge (two limbs of `challenge_seed`).
    pub fn challenge_f2(&mut self, label: &[u8]) -> F2 {
        let d = self.challenge_seed(label);
        F2::new(d[0], d[1])
    }

    fn absorb(&mut self, label: &[u8], payload: &[F]) {
        let (label_tag, label_len) = label_tags(label);
        let digest = hash_to_digest_prefixed(&self.state, label_tag, label_len, payload);
        self.state = digest;
    }
}

/// Expand a 2-field seed into `count` field elements using Griffin, with domain separation.
///
/// This mirrors the paper’s `Expand` helper (seed + domain + counter → hash output),
/// but stays entirely within the field.
pub fn expand_f(seed: [F; 2], count: usize, domain: &[u8]) -> Vec<F> {
    if count == 0 {
        return Vec::new();
    }
    // Efficient expand: treat (seed || domain) as sponge input and squeeze `count` elements.
    // This is cheap to mirror in-circuit (no per-element rehash loop).
    let params = get_griffin_params();
    let (domain_tag, domain_len) = label_tags(domain);
    let inputs = vec![
        seed[0],
        seed[1],
        domain_tag,
        domain_len,
        F::new(count as u128),
    ];
    griffin_sponge(params, inputs, count)
}

/// Expand a 2-field seed into `count` F² values whose imaginary component is 0.
pub fn expand_f2_real(seed: [F; 2], count: usize, domain: &[u8]) -> Vec<F2> {
    expand_f(seed, count, domain)
        .into_iter()
        .map(|x| F2::new(x, F::zero()))
        .collect()
}

/// Expand a 2-field seed into `count` indices in `[0, modulus)`.
pub fn expand_index(seed: [F; 2], count: usize, domain: &[u8], modulus: usize) -> Vec<usize> {
    if modulus == 0 {
        return vec![0usize; count];
    }
    // Circuit-friendly reduction:
    // - Take the low k bits where k = ceil(log2(modulus)).
    // - Since all supported `modulus` values satisfy 2^k < 2*modulus, a single
    //   conditional subtraction yields `x_low mod modulus`.
    //
    // This is easy to mirror in-circuit (bit-decompose once, then one subtract).
    let k = (usize::BITS - (modulus.saturating_sub(1)).leading_zeros()) as usize;
    let mask = if k >= 128 { u128::MAX } else { (1u128 << k) - 1 };
    expand_f(seed, count, domain)
        .into_iter()
        .map(|x| {
            let mut v = (x.0 & mask) as usize;
            if v >= modulus {
                v -= modulus;
            }
            v
        })
        .collect()
}

fn hash_to_digest(inputs: &[F]) -> [F; 2] {
    let params = get_griffin_params();
    let outputs = griffin_sponge(params, inputs.to_vec(), 2);
    [outputs[0], outputs[1]]
}

fn hash_to_digest_prefixed(state: &[F; 2], label_tag: F, label_len: F, payload: &[F]) -> [F; 2] {
    // inputs := state || label_tag || label_len || payload_len || payload
    let mut inputs = Vec::with_capacity(2 + 3 + payload.len());
    inputs.push(state[0]);
    inputs.push(state[1]);
    inputs.push(label_tag);
    inputs.push(label_len);
    inputs.push(F::new(payload.len() as u128));
    inputs.extend_from_slice(payload);
    hash_to_digest(&inputs)
}

fn label_tags(label: &[u8]) -> (F, F) {
    (pack_label_tag(label), F::new(label.len() as u128))
}

fn pack_label_tag(label: &[u8]) -> F {
    // Pack up to 16 bytes of the label into a field element (little-endian).
    // This is used purely for domain separation of *fixed* labels.
    let mut arr = [0u8; 16];
    let take = core::cmp::min(16, label.len());
    arr[..take].copy_from_slice(&label[..take]);
    F::new(u128::from_le_bytes(arr))
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

    #[test]
    fn test_field_transcript_determinism() {
        let mut t1 = FieldTranscript::new(b"test");
        let mut t2 = FieldTranscript::new(b"test");
        t1.append_f(b"x", F::new(123));
        t2.append_f(b"x", F::new(123));
        let c1 = t1.challenge_seed(b"c");
        let c2 = t2.challenge_seed(b"c");
        assert_eq!(c1, c2);
    }
}
