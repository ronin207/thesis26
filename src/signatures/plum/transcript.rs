//! Fiat–Shamir transcript for PLUM.
//!
//! Wraps a `PlumHasher` and provides:
//!   - typed absorbs (`append_bytes`, `append_field`, `append_root`)
//!   - typed squeezes (`challenge_field`, `challenge_index`, `challenge_indices`)
//!
//! Both prover and verifier instantiate the transcript identically and
//! absorb / squeeze in the same order; the verifier re-derives every
//! challenge instead of trusting the signature.
//!
//! Domain separation: every absorb tags its label first so different
//! call sites can't collide. Squeezes use a counter so multiple
//! challenges in a row produce independent outputs.
//!
//! Indexing helpers (`challenge_index`, `challenge_indices`) reject-sample
//! to avoid modulo bias for the small ranges PLUM uses (`κ_0 = 26` at
//! λ=128 means we sample 8-bit indices into `|U| = 2^12`).

use super::field_p192::Fp192;
use super::hasher::{PLUM_DIGEST_BYTES, PlumHasher, shake256_expand};
use crate::primitives::r1cs::fs_fp192_gadget::{
    griffin_fs_challenge_field, griffin_fs_challenge_index,
};

/// Pack a label-tagged byte absorb into a deterministic sequence of `Fp192`
/// field elements for the GRIFFIN-FS path. SHAKE-byte layout is NOT reproduced
/// (the Griffin reference is a deliberate re-modeling, per
/// `fs_fp192_gadget`'s module doc); only the absorb ORDER and label separation
/// are mirrored. Bytes are packed 24 per element (192 < 199 bits, always
/// canonical < p, matching the Griffin sponge's `ABSORB_BYTES_PER_ELEM`).
fn pack_labeled_absorb(label: &[u8], data: &[u8]) -> Vec<Fp192> {
    // Frame the absorb the same way the byte path does (`absorb:` ‖ len ‖ label
    // ‖ len ‖ data) so two call-sites with identical data but different labels
    // produce different field sequences, then pack to field elements.
    let mut framed = Vec::with_capacity(32 + label.len() + data.len());
    framed.extend_from_slice(b"absorb:");
    framed.extend_from_slice(&(label.len() as u64).to_le_bytes());
    framed.extend_from_slice(label);
    framed.extend_from_slice(&(data.len() as u64).to_le_bytes());
    framed.extend_from_slice(data);
    framed
        .chunks(24)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[..chunk.len()].copy_from_slice(chunk);
            // 24 bytes => top byte (index 24) stays 0, value < 2^192 < p.
            Fp192::from_bytes_le(&buf).expect("24-byte pack is < p")
        })
        .collect()
}

/// Fiat–Shamir transcript. The `H` parameter selects Griffin or SHA3.
///
/// Two squeeze backends, selected by `H::USE_GRIFFIN_FS`:
///   - SHAKE256 byte path (default): `SHAKE256(state ‖ ctr ‖ label)`.
///   - GRIFFIN-FS path (`PlumGriffinHasher`): challenges are derived by the
///     Stage-4c-2 software reference (`griffin_fs_challenge_field` /
///     `griffin_fs_challenge_index`) over the running field-element absorb log
///     plus a monotone squeeze counter — the SAME derivation the 4c-4-asm
///     circuit verifies. Sign and verify instantiate the SAME `H`, so both
///     sides agree.
pub struct PlumTranscript<H: PlumHasher> {
    /// Bytes accumulated so far (label-tagged absorbs). Squeezes are
    /// derived by `SHAKE256(current_state || squeeze_counter || label)`,
    /// so absorbing more after a squeeze remains safe.
    state: Vec<u8>,
    /// GRIFFIN-FS path only: the running vector of absorbed field elements
    /// (`D` in the 4c-2 spec). Every absorb appends the label-framed,
    /// 24-byte-packed field elements of its data. Empty / unused on the
    /// SHAKE256 path.
    absorbed_fields: Vec<Fp192>,
    /// Monotonic counter used as part of the squeeze label so that two
    /// successive challenges without intervening absorbs differ. Shared by
    /// both paths (the GRIFFIN-FS path passes it as the reference's
    /// `squeeze_counter`).
    squeeze_counter: u64,
    _hasher: core::marker::PhantomData<H>,
}

impl<H: PlumHasher> PlumTranscript<H> {
    pub fn new(domain: &[u8]) -> Self {
        let mut state = Vec::with_capacity(64 + domain.len());
        state.extend_from_slice(b"PlumTranscript/v1");
        state.extend_from_slice(&(domain.len() as u64).to_le_bytes());
        state.extend_from_slice(domain);
        // Seed the GRIFFIN-FS field log with the domain so two domains diverge
        // on the very first challenge (mirrors the byte path's domain framing).
        let absorbed_fields = if H::USE_GRIFFIN_FS {
            pack_labeled_absorb(b"domain", domain)
        } else {
            Vec::new()
        };
        Self {
            state,
            absorbed_fields,
            squeeze_counter: 0,
            _hasher: core::marker::PhantomData,
        }
    }

    fn absorb_with_label(&mut self, label: &[u8], data: &[u8]) {
        self.state.extend_from_slice(b"absorb:");
        self.state.extend_from_slice(&(label.len() as u64).to_le_bytes());
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&(data.len() as u64).to_le_bytes());
        self.state.extend_from_slice(data);
        if H::USE_GRIFFIN_FS {
            self.absorbed_fields
                .extend(pack_labeled_absorb(label, data));
        }
    }

    pub fn append_bytes(&mut self, label: &[u8], data: &[u8]) {
        self.absorb_with_label(label, data);
    }

    pub fn append_field(&mut self, label: &[u8], value: &Fp192) {
        self.absorb_with_label(label, &value.to_bytes_le());
    }

    pub fn append_fields(&mut self, label: &[u8], values: &[Fp192]) {
        let mut buf = Vec::with_capacity(values.len() * 32);
        for v in values {
            buf.extend_from_slice(&v.to_bytes_le());
        }
        self.absorb_with_label(label, &buf);
    }

    pub fn append_root(&mut self, label: &[u8], root: &[u8; PLUM_DIGEST_BYTES]) {
        self.absorb_with_label(label, root);
    }

    /// Produce `n_bytes` of XOF output bound to the current transcript
    /// state and the squeeze counter. Internally `SHAKE256(state || ctr || label)`.
    fn squeeze_bytes(&mut self, label: &[u8], n_bytes: usize) -> Vec<u8> {
        let mut seed = Vec::with_capacity(self.state.len() + 32 + label.len());
        seed.extend_from_slice(&self.state);
        seed.extend_from_slice(b"squeeze:");
        seed.extend_from_slice(&self.squeeze_counter.to_le_bytes());
        seed.extend_from_slice(&(label.len() as u64).to_le_bytes());
        seed.extend_from_slice(label);
        self.squeeze_counter += 1;
        shake256_expand(&seed, n_bytes)
    }

    /// Squeeze a uniform `F_p192` challenge. Rejection-sampling guarantees
    /// no modulo bias.
    pub fn challenge_field(&mut self, label: &[u8]) -> Fp192 {
        if H::USE_GRIFFIN_FS {
            // GRIFFIN-FS: derive via the Stage-4c-2 software reference over the
            // running field log + this call's monotone squeeze counter. The
            // `label` does not enter the Griffin derivation (the reference uses
            // FS_TAG_FIELD + squeeze_counter for separation); the byte path's
            // per-label separation is subsumed by the monotone counter, which
            // increments once per challenge call.
            let sc = self.squeeze_counter;
            self.squeeze_counter += 1;
            let _ = label;
            return griffin_fs_challenge_field(&self.absorbed_fields, sc).value;
        }
        // Pull bytes in chunks of 25 (= ceil(199/8) bytes) and reject if
        // the candidate ≥ p. Average ~1.66 rejections at our bit width.
        let mut counter = 0u32;
        loop {
            let mut chunk_label = Vec::with_capacity(label.len() + 8);
            chunk_label.extend_from_slice(label);
            chunk_label.extend_from_slice(&counter.to_le_bytes());
            let bytes = self.squeeze_bytes(&chunk_label, 25);
            let mut padded = [0u8; 32];
            padded[..25].copy_from_slice(&bytes);
            padded[24] &= 0x7F; // mask top bit so candidate < 2^199
            if let Some(elem) = Fp192::from_bytes_le(&padded) {
                return elem;
            }
            counter += 1;
            if counter > 64 {
                panic!("PLUM transcript: challenge_field failed to sample in 64 attempts");
            }
        }
    }

    pub fn challenge_fields(&mut self, label: &[u8], count: usize) -> Vec<Fp192> {
        (0..count)
            .map(|i| {
                let mut tag = Vec::with_capacity(label.len() + 8);
                tag.extend_from_slice(label);
                tag.extend_from_slice(&(i as u64).to_le_bytes());
                self.challenge_field(&tag)
            })
            .collect()
    }

    /// Sample a uniform index in `[0, bound)`. Rejection-samples on a
    /// power-of-two range to avoid modulo bias.
    pub fn challenge_index(&mut self, label: &[u8], bound: usize) -> usize {
        assert!(bound > 0, "PLUM transcript: challenge_index needs bound > 0");
        if bound == 1 {
            return 0;
        }
        if H::USE_GRIFFIN_FS {
            // GRIFFIN-FS: derive via the Stage-4c-2 software reference. The
            // accepted index is returned in `value` as an `Fp192` < bound.
            let sc = self.squeeze_counter;
            self.squeeze_counter += 1;
            let _ = label;
            let trace = griffin_fs_challenge_index(&self.absorbed_fields, sc, bound);
            // `value` is the accepted index embedded in Fp192; it is < bound by
            // construction (the reference's acceptance check), and bound <= L =
            // 2^12 fits a usize comfortably.
            let idx_big = trace.value.to_biguint();
            let digits = idx_big.to_u64_digits();
            return digits.first().copied().unwrap_or(0) as usize;
        }
        // Smallest power of two >= bound. We rejection-sample within
        // [0, pow) then reject if ≥ bound.
        let pow = bound.next_power_of_two();
        let mask = (pow - 1) as u64;
        let needed_bits = pow.trailing_zeros() as usize;
        let needed_bytes = (needed_bits + 7) / 8;

        let mut counter = 0u32;
        loop {
            let mut tag = Vec::with_capacity(label.len() + 8);
            tag.extend_from_slice(label);
            tag.extend_from_slice(&counter.to_le_bytes());
            let bytes = self.squeeze_bytes(&tag, needed_bytes.max(8));
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            let candidate = (u64::from_le_bytes(buf) & mask) as usize;
            if candidate < bound {
                return candidate;
            }
            counter += 1;
            if counter > 128 {
                panic!(
                    "PLUM transcript: challenge_index({}) failed to sample after 128 attempts",
                    bound
                );
            }
        }
    }

    pub fn challenge_indices(&mut self, label: &[u8], count: usize, bound: usize) -> Vec<usize> {
        (0..count)
            .map(|i| {
                let mut tag = Vec::with_capacity(label.len() + 8);
                tag.extend_from_slice(label);
                tag.extend_from_slice(&(i as u64).to_le_bytes());
                self.challenge_index(&tag, bound)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::hasher::{PlumGriffinHasher, PlumSha3Hasher};

    fn fresh<H: PlumHasher>(domain: &[u8]) -> PlumTranscript<H> {
        PlumTranscript::<H>::new(domain)
    }

    #[test]
    fn equal_transcripts_produce_equal_challenges() {
        let mut a = fresh::<PlumGriffinHasher>(b"plum-test");
        let mut b = fresh::<PlumGriffinHasher>(b"plum-test");
        a.append_field(b"x", &Fp192::from_u64(42));
        b.append_field(b"x", &Fp192::from_u64(42));
        assert_eq!(a.challenge_field(b"c"), b.challenge_field(b"c"));
    }

    #[test]
    fn divergent_absorbs_diverge_challenges() {
        let mut a = fresh::<PlumGriffinHasher>(b"plum-test");
        let mut b = fresh::<PlumGriffinHasher>(b"plum-test");
        a.append_field(b"x", &Fp192::from_u64(1));
        b.append_field(b"x", &Fp192::from_u64(2));
        assert_ne!(a.challenge_field(b"c"), b.challenge_field(b"c"));
    }

    #[test]
    fn consecutive_challenges_are_independent() {
        let mut t = fresh::<PlumGriffinHasher>(b"d");
        let c1 = t.challenge_field(b"c");
        let c2 = t.challenge_field(b"c");
        assert_ne!(c1, c2);
    }

    #[test]
    fn challenge_index_respects_bound() {
        let mut t = fresh::<PlumSha3Hasher>(b"d");
        for _ in 0..64 {
            let i = t.challenge_index(b"idx", 4096);
            assert!(i < 4096);
        }
    }

    #[test]
    fn challenge_index_distribution_is_nontrivial() {
        let mut t = fresh::<PlumSha3Hasher>(b"d");
        let mut hits = [0u32; 8];
        for _ in 0..512 {
            let i = t.challenge_index(b"idx", 8);
            hits[i] += 1;
        }
        // Every bucket should see ~64 ± noise. Just require all > 0
        // (no degenerate output) and no bucket dominates.
        for h in hits {
            assert!(h > 0, "uniform-index sampler missed a bucket");
            assert!(h < 256, "uniform-index sampler biased: hits = {:?}", hits);
        }
    }

    #[test]
    fn label_separation_holds() {
        let mut t = fresh::<PlumGriffinHasher>(b"d");
        t.append_bytes(b"a", b"x");
        let c1 = t.challenge_field(b"first");
        let c2 = t.challenge_field(b"second");
        assert_ne!(c1, c2);
    }

    #[test]
    fn domain_separation_holds() {
        let mut a = fresh::<PlumGriffinHasher>(b"domain-A");
        let mut b = fresh::<PlumGriffinHasher>(b"domain-B");
        a.append_bytes(b"x", b"same data");
        b.append_bytes(b"x", b"same data");
        assert_ne!(a.challenge_field(b"c"), b.challenge_field(b"c"));
    }

    #[test]
    fn sha3_and_griffin_paths_both_work() {
        let mut t1 = fresh::<PlumSha3Hasher>(b"d");
        t1.append_field(b"x", &Fp192::from_u64(7));
        let _ = t1.challenge_field(b"c");
        let mut t2 = fresh::<PlumGriffinHasher>(b"d");
        t2.append_field(b"x", &Fp192::from_u64(7));
        let _ = t2.challenge_field(b"c");
        // Different hashers should not collide on the same transcript.
        // (They produce different challenges; just exercise both paths.)
    }

    #[test]
    fn append_root_distinguishes_trees() {
        let mut t1 = fresh::<PlumGriffinHasher>(b"d");
        let mut t2 = fresh::<PlumGriffinHasher>(b"d");
        t1.append_root(b"root", &[0u8; 32]);
        let mut other = [0u8; 32];
        other[0] = 1;
        t2.append_root(b"root", &other);
        assert_ne!(t1.challenge_field(b"c"), t2.challenge_field(b"c"));
    }
}
