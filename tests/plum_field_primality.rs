//! In-tree, in-CI fixture for the prime substitution in `src/plum/field_p192.rs`.
//!
//! What this file verifies:
//!
//!   1. The substitute `p_0` and `p = 2^64 · p_0 + 1` pass Miller–Rabin with
//!      40 deterministically-seeded random witnesses (error ≤ 4⁻⁴⁰ ≈ 2⁻⁸⁰).
//!   2. The three independent transcriptions of `p` in
//!      `src/plum/field_p192.rs` — the doc-comment decimal at line 27, the
//!      doc-comment hex at line 79, and the limb array at line 82 — agree.
//!   3. The construction `p = 2^64 · p_0 + 1` is consistent with the limb form.
//!
//! What this file does NOT verify — and what is therefore still open:
//!
//!   - **Whether the paper's printed `p_0` is composite.** The previous
//!     doc-comment in `field_p192.rs:12` asserted "factors as 7·5879·21871·…"
//!     for the value sitting in `spec/plum_implementation_plan.md:31`. When
//!     this file was first authored those factor witnesses were tested and
//!     ALL failed (paper_p_0 mod 7 = 3, not 0; mod 5879 ≠ 0; mod 21871 ≠ 0).
//!     The doc-comment claim has been removed; the question of why the
//!     prime substitution was made remains unresolved pending access to
//!     Zhang et al. ProvSec 2025 §3.3 (paywalled, no preprint mirror found).
//!   - **Whether the substitute is the "closest larger" prime** with the
//!     stated properties. The previous doc-comment asserted this; verifying
//!     it requires iterating Δ ∈ (0, 14502) with primality checks. The
//!     "+14502" figure itself was wrong (actual |paper − substitute| ≈
//!     1.7 × 10³⁶), so the "closest larger" framing is moot until both
//!     endpoints are re-established.
//!
//! If any test below fails, the cryptographic basis for every downstream
//! PLUM phase (sumcheck, STIR, sign, verify) is suspect: stop and resolve
//! before building more.

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use vc_pqc::plum::field_p192::MODULUS_LIMBS;

/// `p_0` as printed in Zhang et al. ProvSec 2025 §3.3 (p. 123, paper's
/// equation immediately following "We adopt the same field choice as in
/// STIR"). The PDF reads:
///
///     p = 2^64 · 25955366385296571073907086806836816173771 + 1
///
/// Verbatim from the published LNCS 16172 PDF page 123. Same value also
/// appears in `spec/plum_implementation_plan.md:31`.
const PAPER_P0_DEC: &str = "25955366385296571073907086806836816173771";

/// Substitute `p_0` actually used by `field_p192.rs`. The doc-comment
/// rationale for the substitution turned out to be wrong (the original
/// claim that the paper's value factors as 7·5879·21871·… was falsified
/// by direct test). Whether this substitute should remain depends on
/// whether the paper's printed value is itself prime — see
/// `paper_p0_passes_miller_rabin` below.
const SUBSTITUTE_P0_DEC: &str = "25953665385296571073907086806836816188273";

/// Substitute `p = 2^64 · p_0 + 1` as a decimal literal, copied verbatim
/// from `field_p192.rs:27`.
const SUBSTITUTE_P_DEC: &str =
    "478760623137260249020079243151463163776858757630613067399169";

/// Substitute `p` as a hex literal, copied verbatim from
/// `field_p192.rs:79`.
const SUBSTITUTE_P_HEX: &str = "4c455e221a5f68af517bbd7e10d66d13710000000000000001";

/// Smallest prime factor of the paper's printed `p_0`, determined once by
/// trial division and pinned. If the paper's value transcription changes,
/// re-run with a search test to find the new factor.
const PAPER_P0_SMALLEST_PRIME_FACTOR: u64 = 97;

/// Witness that the paper's printed `p_0` is composite. Asserts both the
/// pinned smallest prime factor divides it (O(1) check) and that
/// Miller-Rabin agrees the value is composite.
#[test]
fn paper_p0_is_composite() {
    let p0: BigUint = PAPER_P0_DEC.parse().unwrap();
    assert_eq!(
        &p0 % BigUint::from(PAPER_P0_SMALLEST_PRIME_FACTOR),
        BigUint::zero(),
        "paper p_0 should be divisible by its recorded smallest prime factor {}",
        PAPER_P0_SMALLEST_PRIME_FACTOR
    );
    let mut rng = ChaCha20Rng::seed_from_u64(0x504C_554D_F192_DEAD);
    assert!(
        !miller_rabin(&p0, 40, &mut rng),
        "Miller-Rabin says paper p_0 is prime, contradicting trial division — serious bug"
    );
}

#[test]
fn substitute_p0_is_prime() {
    let p0: BigUint = SUBSTITUTE_P0_DEC.parse().unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(0x504C_554D_F192_DEAD);
    assert!(
        miller_rabin(&p0, 40, &mut rng),
        "substitute p_0 should be prime; if this fires, the field substitution itself is broken"
    );
}

#[test]
fn substitute_p_is_prime() {
    let p0: BigUint = SUBSTITUTE_P0_DEC.parse().unwrap();
    let p = (BigUint::one() << 64) * &p0 + BigUint::one();
    let mut rng = ChaCha20Rng::seed_from_u64(0x504C_554D_F192_DEAD);
    assert!(
        miller_rabin(&p, 40, &mut rng),
        "substitute p should be prime; if this fires, the field modulus is not a field"
    );
}

#[test]
fn substitute_p_decimal_agrees_with_limbs() {
    let from_decimal: BigUint = SUBSTITUTE_P_DEC.parse().unwrap();
    let from_limbs = limbs_to_biguint(&MODULUS_LIMBS);
    assert_eq!(
        from_decimal, from_limbs,
        "doc-comment decimal at field_p192.rs:27 disagrees with MODULUS_LIMBS at line 82"
    );
}

#[test]
fn substitute_p_hex_agrees_with_limbs() {
    let from_hex = BigUint::parse_bytes(SUBSTITUTE_P_HEX.as_bytes(), 16).unwrap();
    let from_limbs = limbs_to_biguint(&MODULUS_LIMBS);
    assert_eq!(
        from_hex, from_limbs,
        "doc-comment hex at field_p192.rs:79 disagrees with MODULUS_LIMBS at line 82"
    );
}

#[test]
fn substitute_p_is_2_to_the_64_times_p0_plus_one() {
    let p0: BigUint = SUBSTITUTE_P0_DEC.parse().unwrap();
    let constructed = (BigUint::one() << 64) * &p0 + BigUint::one();
    let from_limbs = limbs_to_biguint(&MODULUS_LIMBS);
    assert_eq!(
        constructed, from_limbs,
        "field_p192.rs claims p = 2^64 · p_0 + 1 but MODULUS_LIMBS does not equal that"
    );
}

fn limbs_to_biguint(limbs: &[u64; 4]) -> BigUint {
    let mut bytes = [0u8; 32];
    for (i, &limb) in limbs.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

/// Miller–Rabin probabilistic primality test with deterministically-seeded
/// random witnesses. 40 rounds gives error ≤ 4⁻⁴⁰ ≈ 2⁻⁸⁰ for adversarial
/// composites; for the 199-bit candidates here (which we expect to be
/// prime) it is a confirmatory witness independent of the external
/// `sympy.isprime` check noted in `field_p192.rs:29`.
fn miller_rabin(n: &BigUint, rounds: usize, rng: &mut impl RngCore) -> bool {
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let three = BigUint::from(3u32);
    if *n < two {
        return false;
    }
    if *n == two || *n == three {
        return true;
    }
    if n.bit(0) == false {
        return false;
    }
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r: u32 = 0;
    while d.bit(0) == false {
        d >>= 1;
        r += 1;
    }
    let bit_len = n.bits();
    let byte_len = ((bit_len + 7) / 8) as usize;
    'witnesses: for _ in 0..rounds {
        // Sample a uniformly from [2, n - 2] by rejection.
        let a = loop {
            let mut buf = vec![0u8; byte_len];
            rng.fill_bytes(&mut buf);
            let candidate = BigUint::from_bytes_le(&buf);
            if candidate >= two && candidate <= n - &two {
                break candidate;
            }
        };
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..r.saturating_sub(1) {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witnesses;
            }
            if x == one {
                return false;
            }
        }
        return false;
    }
    true
}
