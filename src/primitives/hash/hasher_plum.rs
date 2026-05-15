//! Hasher abstraction for PLUM.
//!
//! Two concrete instantiations:
//!   - `PlumGriffinHasher` — Griffin-over-`F_p192`, the SNARK-friendly
//!     instantiation the paper assumes when reporting R1CS constraints.
//!   - `PlumSha3Hasher` — SHA3-256, the zkVM-friendly comparison point
//!     so we can measure the cycle-cost difference between an algebraic
//!     and a precompile-friendly hash inside the same scheme.
//!
//! Both implement `PlumHasher`, which exposes:
//!   - `update / finalize_bytes` — generic absorb / squeeze byte path,
//!     used by Fiat–Shamir transcript and Merkle tree leaf hashing.
//!   - `compress_pair` — domain-separated compression of two field
//!     elements down to one digest, used for Merkle inner nodes.
//!
//! The trait is byte-in / byte-out so callers can compose freely. The
//! `compress_pair` helper exists specifically because the Merkle tree
//! benefits from one-permutation compression rather than a full sponge
//! absorb each level (mirrors Loquat's `Use single-permutation Merkle
//! compression` optimisation).

use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use sha3::{
    Digest, Sha3_256,
    Shake256,
    digest::{ExtendableOutput, Update as Sha3Update, XofReader},
};

use crate::primitives::field::p192::Fp192;
use crate::primitives::hash::griffin_p192::{
    PlumGriffinState, plum_griffin_params, plum_griffin_permutation,
};

/// Output of every PLUM hasher is a 32-byte digest. The Griffin
/// instantiation produces 64 bytes natively (two Fp192 lanes); we keep
/// the first 32 bytes for compatibility with the SHA3 path.
pub const PLUM_DIGEST_BYTES: usize = 32;

/// Counter incremented on every Merkle-style 2-to-1 compression of the
/// active hasher. Lets the zkVM attribution measurement separate
/// "compression" cost from generic absorb work.
pub static PLUM_HASHER_COMPRESS_COUNT: AtomicU64 = AtomicU64::new(0);

pub trait PlumHasher: Sized {
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize_bytes(self) -> [u8; PLUM_DIGEST_BYTES];
    fn compress_pair(left: &[u8; PLUM_DIGEST_BYTES], right: &[u8; PLUM_DIGEST_BYTES]) -> [u8; PLUM_DIGEST_BYTES];

    fn hash_bytes(data: &[u8]) -> [u8; PLUM_DIGEST_BYTES] {
        let mut h = Self::new();
        h.update(data);
        h.finalize_bytes()
    }

    /// Hash a slice of field elements (32-byte LE serialisation each).
    fn hash_fields(elements: &[Fp192]) -> [u8; PLUM_DIGEST_BYTES] {
        let mut h = Self::new();
        for elem in elements {
            h.update(&elem.to_bytes_le());
        }
        h.finalize_bytes()
    }
}

// ---------------------------------------------------------------------------
// Griffin instantiation
// ---------------------------------------------------------------------------

/// Algebraic hash over `F_p192`. Two-block compression uses one Griffin
/// permutation per call (matches Loquat's `griffin_permutation_raw`
/// optimisation on the Merkle hot path).
pub struct PlumGriffinHasher {
    buffer: Vec<u8>,
}

impl PlumHasher for PlumGriffinHasher {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    fn finalize_bytes(self) -> [u8; PLUM_DIGEST_BYTES] {
        let digest = crate::primitives::hash::griffin_p192::plum_griffin_hash(&self.buffer);
        let mut out = [0u8; PLUM_DIGEST_BYTES];
        // Take the first 32 bytes of the 64-byte Griffin digest.
        out.copy_from_slice(&digest[..PLUM_DIGEST_BYTES]);
        out
    }

    fn compress_pair(
        left: &[u8; PLUM_DIGEST_BYTES],
        right: &[u8; PLUM_DIGEST_BYTES],
    ) -> [u8; PLUM_DIGEST_BYTES] {
        PLUM_HASHER_COMPRESS_COUNT.fetch_add(1, AtomicOrdering::Relaxed);

        // Decode the 32-byte digests as `F_p192` elements (the high byte
        // of each digest is always < 0x80 because Griffin's `to_bytes_le`
        // output for a 199-bit value has the top bit zero — but we mask
        // defensively to keep things canonical).
        let mut left_bytes = [0u8; 32];
        let mut right_bytes = [0u8; 32];
        left_bytes.copy_from_slice(left);
        right_bytes.copy_from_slice(right);
        left_bytes[24] &= 0x7F;
        right_bytes[24] &= 0x7F;
        let left_field =
            Fp192::from_bytes_le(&left_bytes).unwrap_or_else(Fp192::zero);
        let right_field =
            Fp192::from_bytes_le(&right_bytes).unwrap_or_else(Fp192::zero);

        // Single-permutation compression: load lanes [left, right, 0, 0]
        // and run one Griffin permutation. Output is the first lane.
        let params = plum_griffin_params();
        let mut state = PlumGriffinState::from_lanes([
            left_field,
            right_field,
            Fp192::zero(),
            Fp192::zero(),
        ]);
        plum_griffin_permutation(params, &mut state);

        let out_field = &state.lanes()[0];
        let bytes = out_field.to_bytes_le();
        let mut out = [0u8; PLUM_DIGEST_BYTES];
        out.copy_from_slice(&bytes[..PLUM_DIGEST_BYTES]);
        out
    }
}

// ---------------------------------------------------------------------------
// SHA3-256 instantiation
// ---------------------------------------------------------------------------

/// Non-algebraic hash for comparison cycle measurements. zkVM-friendly
/// because production RISC0 supports a SHA-256 precompile and Keccak-f
/// is in the same cost ballpark.
pub struct PlumSha3Hasher {
    inner: Sha3_256,
}

impl PlumHasher for PlumSha3Hasher {
    fn new() -> Self {
        Self { inner: Sha3_256::new() }
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut self.inner, data);
    }

    fn finalize_bytes(self) -> [u8; PLUM_DIGEST_BYTES] {
        let out = self.inner.finalize();
        let mut bytes = [0u8; PLUM_DIGEST_BYTES];
        bytes.copy_from_slice(&out);
        bytes
    }

    fn compress_pair(
        left: &[u8; PLUM_DIGEST_BYTES],
        right: &[u8; PLUM_DIGEST_BYTES],
    ) -> [u8; PLUM_DIGEST_BYTES] {
        PLUM_HASHER_COMPRESS_COUNT.fetch_add(1, AtomicOrdering::Relaxed);
        let mut h = Sha3_256::new();
        Digest::update(&mut h, left);
        Digest::update(&mut h, right);
        let out = h.finalize();
        let mut bytes = [0u8; PLUM_DIGEST_BYTES];
        bytes.copy_from_slice(&out);
        bytes
    }
}

// ---------------------------------------------------------------------------
// Free-standing utilities
// ---------------------------------------------------------------------------

/// XOF expansion of an arbitrary byte string into `n_bytes` of pseudo-random
/// output. Used by the Fiat–Shamir transcript's `challenge_bytes_xof`.
pub fn shake256_expand(seed: &[u8], n_bytes: usize) -> Vec<u8> {
    let mut shake = Shake256::default();
    Sha3Update::update(&mut shake, seed);
    let mut reader = shake.finalize_xof();
    let mut out = std::vec![0u8; n_bytes];
    XofReader::read(&mut reader, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_determinism<H: PlumHasher>(data: &[u8]) {
        let a = H::hash_bytes(data);
        let b = H::hash_bytes(data);
        assert_eq!(a, b);
    }

    #[test]
    fn griffin_hasher_is_deterministic() {
        assert_determinism::<PlumGriffinHasher>(b"PLUM hasher test");
    }

    #[test]
    fn sha3_hasher_is_deterministic() {
        assert_determinism::<PlumSha3Hasher>(b"PLUM hasher test");
    }

    #[test]
    fn distinct_inputs_yield_distinct_digests() {
        let a = PlumGriffinHasher::hash_bytes(b"alpha");
        let b = PlumGriffinHasher::hash_bytes(b"beta");
        assert_ne!(a, b);
        let c = PlumSha3Hasher::hash_bytes(b"alpha");
        let d = PlumSha3Hasher::hash_bytes(b"beta");
        assert_ne!(c, d);
    }

    #[test]
    fn compress_pair_griffin_changes_with_inputs() {
        let z = [0u8; PLUM_DIGEST_BYTES];
        let mut o = [0u8; PLUM_DIGEST_BYTES];
        o[0] = 1;
        let out_z = PlumGriffinHasher::compress_pair(&z, &z);
        let out_o = PlumGriffinHasher::compress_pair(&o, &z);
        assert_ne!(out_z, out_o);
    }

    #[test]
    fn compress_pair_sha3_matches_serial_hash() {
        let l = [3u8; PLUM_DIGEST_BYTES];
        let r = [5u8; PLUM_DIGEST_BYTES];
        let via_compress = PlumSha3Hasher::compress_pair(&l, &r);

        let mut h = PlumSha3Hasher::new();
        h.update(&l);
        h.update(&r);
        let via_update = h.finalize_bytes();

        assert_eq!(via_compress, via_update);
    }

    #[test]
    fn compress_counter_ticks() {
        let z = [0u8; PLUM_DIGEST_BYTES];
        let before = PLUM_HASHER_COMPRESS_COUNT.load(AtomicOrdering::Relaxed);
        let _ = PlumGriffinHasher::compress_pair(&z, &z);
        let _ = PlumSha3Hasher::compress_pair(&z, &z);
        let after = PLUM_HASHER_COMPRESS_COUNT.load(AtomicOrdering::Relaxed);
        assert!(after >= before + 2);
    }

    #[test]
    fn hash_fields_works_for_griffin() {
        let elems = std::vec![Fp192::from_u64(7), Fp192::from_u64(11)];
        let a = PlumGriffinHasher::hash_fields(&elems);
        let b = PlumGriffinHasher::hash_fields(&elems);
        assert_eq!(a, b);
        // Different elements → different digest.
        let elems2 = std::vec![Fp192::from_u64(7), Fp192::from_u64(13)];
        let c = PlumGriffinHasher::hash_fields(&elems2);
        assert_ne!(a, c);
    }

    #[test]
    fn shake256_expand_is_deterministic() {
        let a = shake256_expand(b"PLUM seed", 64);
        let b = shake256_expand(b"PLUM seed", 64);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }
}
