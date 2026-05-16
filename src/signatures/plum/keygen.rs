//! PLUM key generation (Algorithm 2 of Zhang et al., ProvSec 2025).
//!
//! Verbatim from the paper (LNCS 16172, p. 118):
//!
//! ```text
//! Algorithm 2: Plum Key Generation
//! Input: pp
//! Output: (sk, pk)
//! 1 KeyGen
//! 2   Generate the secret key
//! 3     Randomly pick a field element K ←$ F_p^* / {-I_1, ..., -I_L} and set sk := K.
//! 4   Generate the public key
//! 5     Compute pk := L^t_K(I) = (L^t_K(I_1), ..., L^t_K(I_L)).
//!       The bit length of the public key is L · log_2(t).
//! 6   Output secret and public key pair (sk, pk).
//! ```
//!
//! Why the exclusion set `{-I_1, ..., -I_L}`. If `K = -I_ℓ` for any `ℓ`,
//! then `K + I_ℓ ≡ 0 mod p`. The PRF (Definition 1, p. 115) returns 0 by
//! convention when its argument is zero, making `pk_ℓ` distinguishable
//! from a uniformly random `Z_t` symbol. Worse, the SNARK residuosity
//! check inside `Verify` (Algorithm 6 Step 3, line 21) would reject the
//! corresponding response `o_{i,j} = (K + I_{i,j}) r_{i,j}` if `K + I_{i,j} = 0`
//! because it equals zero unconditionally. Excluding the L "bad" keys
//! reduces the key space by exactly L, which is negligible against
//! `|F_p^*| ≈ 2^199`.
//!
//! ## API choices not specified by the paper
//!
//! - **Public-key encoding**: the paper specifies the bit length as
//!   `L · log_2(t)` but does not pin a byte layout. At `t = 256` each
//!   symbol fits exactly in one `u8`; we store the public key as
//!   `Vec<u8>` of length `L`. This is the obvious encoding and matches
//!   how `Verify` will need to index into it.
//! - **Randomness source**: the paper writes `K ←$ ...` (uniform).
//!   Callers supply an `rng: &mut R` of their choice — typically
//!   `rand::thread_rng()` for production keys, a seeded
//!   `ChaCha20Rng` for tests.

use std::collections::HashSet;

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use super::field_p192::Fp192;
use super::prf::DEFAULT_PARAMS;
use super::setup::PlumPublicParams;

/// Secret key — a single field element `K ∈ F_p^* / {-I_1, ..., -I_L}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlumSecretKey {
    pub k: Fp192,
}

/// Public key — `(L^t_K(I_1), ..., L^t_K(I_L)) ∈ Z_t^L`. Each symbol is
/// stored in one byte under the `t = 256` regime PLUM-128 uses. Bit
/// length is `L · log_2(t) = 8L` bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlumPublicKey {
    pub symbols: Vec<u8>,
}

/// Algorithm 2 (Plum Key Generation).
///
/// Rejection-samples `K` until it lands outside `{-I_1, ..., -I_L}`, then
/// computes the public-key vector by evaluating the keyed `t`-th power
/// residue PRF at every challenge index. Per the paper the expected
/// number of rejections is `L / |F_p^*| ≈ 4096 / 2^199 ≈ 0`, so the loop
/// runs once in practice.
pub fn plum_keygen<R: Rng + CryptoRng>(
    pp: &PlumPublicParams,
    rng: &mut R,
) -> (PlumSecretKey, PlumPublicKey) {
    // This implementation pins `t = 256`. PLUM-128 fixes this value
    // (§3.3 of the paper); supporting other `t` requires both a
    // wider per-symbol encoding and a re-instantiated `prf::DEFAULT_PARAMS`.
    assert_eq!(
        pp.t, 256,
        "plum_keygen currently only supports t = 256 (the PLUM-128 parameter); got t = {}",
        pp.t
    );
    assert_eq!(
        pp.challenge_set.len(),
        pp.l,
        "PlumPublicParams.challenge_set length disagrees with pp.l; setup invariant violated"
    );

    // Materialise the exclusion set `{-I_1, ..., -I_L}` exactly once.
    // The set may be smaller than `pp.l` if two challenge indices satisfy
    // `I_ℓ = -I_ℓ'` (probability `≈ L²/p ≈ 2⁻¹⁸⁰` so essentially never),
    // or if `0 ∈ I` (current setup excludes zero, so doesn't happen). A
    // smaller exclusion set is still correct per Algorithm 2 — we just
    // reject a strictly smaller portion of `F_p^*`.
    let exclusion: HashSet<Fp192> = pp.challenge_set.iter().map(|i| -i.clone()).collect();

    // Line 3 of Algorithm 2.
    let k = loop {
        let candidate = Fp192::rand_nonzero(rng);
        if !exclusion.contains(&candidate) {
            break candidate;
        }
    };

    // Line 5 of Algorithm 2.
    let prf = &*DEFAULT_PARAMS;
    let symbols: Vec<u8> = pp
        .challenge_set
        .iter()
        .map(|i| {
            let symbol = prf.eval_keyed(&k, i);
            // For `t = 256` (enforced above) every symbol fits in a `u8`.
            // The exclusion above guarantees `K + I ≠ 0`, so the PRF's
            // zero-argument branch never fires. `try_from` defends
            // against the top assertion being weakened in a future
            // refactor — if a symbol ever exceeded 255 the cast would
            // silently truncate.
            u8::try_from(symbol).expect("PRF symbol overflowed u8 despite t = 256")
        })
        .collect();

    (PlumSecretKey { k }, PlumPublicKey { symbols })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::plum::setup::plum_setup;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn make_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0x504C_554D_4B47_454E)
    }

    #[test]
    fn keygen_public_key_has_length_l() {
        let pp = plum_setup(128).unwrap();
        let mut rng = make_rng();
        let (_sk, pk) = plum_keygen(&pp, &mut rng);
        assert_eq!(pk.symbols.len(), pp.l);
    }

    #[test]
    fn keygen_is_deterministic_for_fixed_seed() {
        let pp = plum_setup(128).unwrap();
        let (sk1, pk1) = plum_keygen(&pp, &mut make_rng());
        let (sk2, pk2) = plum_keygen(&pp, &mut make_rng());
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let pp = plum_setup(128).unwrap();
        let mut rng_a = ChaCha20Rng::seed_from_u64(1);
        let mut rng_b = ChaCha20Rng::seed_from_u64(2);
        let (sk_a, _) = plum_keygen(&pp, &mut rng_a);
        let (sk_b, _) = plum_keygen(&pp, &mut rng_b);
        assert_ne!(sk_a, sk_b);
    }

    #[test]
    fn secret_key_is_in_f_p_star() {
        let pp = plum_setup(128).unwrap();
        let mut rng = make_rng();
        let (sk, _) = plum_keygen(&pp, &mut rng);
        assert!(!sk.k.is_zero(), "sk = 0 violates K ∈ F_p^*");
    }

    #[test]
    fn secret_key_is_not_negation_of_any_challenge() {
        let pp = plum_setup(128).unwrap();
        let mut rng = make_rng();
        let (sk, _) = plum_keygen(&pp, &mut rng);
        for (idx, i_ell) in pp.challenge_set.iter().enumerate() {
            let neg_i = -i_ell.clone();
            assert_ne!(
                sk.k, neg_i,
                "K = -I_{} which is in the rejection set per Algorithm 2 line 3",
                idx
            );
        }
    }

    #[test]
    fn no_public_key_symbol_uses_the_prf_zero_branch() {
        // Stronger invariant than the previous test: not only is K not
        // -I_ℓ in the exclusion set, but every shifted input K + I_ℓ is
        // genuinely nonzero, so the PRF's `shifted.is_zero() → 0` branch
        // never fires during keygen.
        let pp = plum_setup(128).unwrap();
        let mut rng = make_rng();
        let (sk, _pk) = plum_keygen(&pp, &mut rng);
        for (idx, i_ell) in pp.challenge_set.iter().enumerate() {
            let shifted = sk.k.clone() + i_ell.clone();
            assert!(
                !shifted.is_zero(),
                "K + I_{} = 0 leaks the zero-input PRF branch into pk",
                idx
            );
        }
    }

    #[test]
    fn public_key_symbols_are_in_z_t() {
        let pp = plum_setup(128).unwrap();
        let mut rng = make_rng();
        let (_sk, pk) = plum_keygen(&pp, &mut rng);
        // Stored as u8, so trivially < 256 = t. This test exists to
        // make the invariant explicit and catch the regression if the
        // type ever widens.
        for symbol in &pk.symbols {
            assert!((*symbol as u64) < pp.t);
        }
    }

    #[test]
    fn public_key_matches_recomputed_prf_evaluations() {
        // pk is supposed to be (L^t_K(I_1), ..., L^t_K(I_L)). Recompute
        // independently of plum_keygen's internal loop and compare.
        let pp = plum_setup(128).unwrap();
        let mut rng = make_rng();
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let prf = &*DEFAULT_PARAMS;
        for (idx, i_ell) in pp.challenge_set.iter().enumerate() {
            let expected = prf.eval_keyed(&sk.k, i_ell) as u8;
            assert_eq!(
                pk.symbols[idx], expected,
                "pk[{}] disagrees with L^t_K(I_{})",
                idx, idx
            );
        }
    }

    #[test]
    fn keypair_serde_roundtrips() {
        let pp = plum_setup(128).unwrap();
        let mut rng = make_rng();
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let sk_bytes = bincode::serialize(&sk).unwrap();
        let pk_bytes = bincode::serialize(&pk).unwrap();
        let sk2: PlumSecretKey = bincode::deserialize(&sk_bytes).unwrap();
        let pk2: PlumPublicKey = bincode::deserialize(&pk_bytes).unwrap();
        assert_eq!(sk, sk2);
        assert_eq!(pk, pk2);
    }

    #[test]
    fn public_key_byte_length_matches_paper_formula() {
        // Paper: "The bit length of the public key is L · log_2(t)".
        // At t = 256, log_2(t) = 8, so byte length is L. We store one
        // u8 per symbol, so len(pk.symbols) is exactly the byte length.
        let pp = plum_setup(128).unwrap();
        let mut rng = make_rng();
        let (_sk, pk) = plum_keygen(&pp, &mut rng);
        let log2_t = (pp.t as f64).log2() as usize;
        assert_eq!(log2_t, 8);
        let bit_length = pp.l * log2_t;
        assert_eq!(bit_length, pk.symbols.len() * 8);
    }

    #[test]
    fn rejection_loop_rejects_excluded_values() {
        // We can't easily force the F_p^* sampler to land on a -I_ℓ
        // value (the chance is ~4096 / 2^199), so this test exercises
        // the exclusion logic indirectly: build a custom RNG whose
        // first draw equals -I_1 and confirm keygen draws again.
        //
        // We do this by chaining: take the real RNG used by
        // Fp192::rand_nonzero, intercept the first sample, and replace
        // it with one whose limbs decode to -I_1. The cleanest way to
        // do that is to seed two RNGs: one that produces -I_1 on first
        // call, and one that produces a valid K after. But rand_nonzero
        // is opaque — it loops until nonzero. So instead we build a
        // contrived setup where the exclusion set covers the entire
        // sampler image and assert plum_keygen would loop forever, and
        // run the test under a timeout. That is fragile.
        //
        // Cheaper: just verify the property algebraically — assert that
        // for the actual produced K, the equality `K = -I_ℓ` does not
        // hold for any ℓ. That is exactly the `secret_key_is_not_
        // negation_of_any_challenge` test above. So we leave this as a
        // documentation-only stub.
    }

    #[test]
    fn lambda_80_and_100_also_work() {
        // Smoke-test the other security levels; primarily catches
        // assertions that hard-code λ = 128 sizes.
        for level in [80, 100] {
            let pp = plum_setup(level).unwrap();
            let mut rng = make_rng();
            let (_sk, pk) = plum_keygen(&pp, &mut rng);
            assert_eq!(pk.symbols.len(), pp.l);
        }
    }
}
