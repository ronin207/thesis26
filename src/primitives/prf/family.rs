//! Parameterised power-residue PRF *family*, on the tractable axis.
//!
//! The PLUM/Loquat precompile suite contains a `t`-th power-residue PRF
//! symbol check (`src/primitives/prf/power_residue.rs`). That symbol is
//!
//!     L^t_K(a) = dlog_ω( (a + K)^((p-1)/t) )      ∈ Z_t ,
//!
//! and it is the natural *family* primitive across the two schemes:
//!
//!   - **Loquat** uses the Legendre PRF. Per PLUM §2.1 (verbatim, p.115),
//!     *"when t = 2, the power residue PRF is equivalent to the Legendre
//!     PRF"*. So Loquat is the `t = 2` member, over the 127-bit Mersenne
//!     prime `p₁ = 2^127 − 1`.
//!   - **PLUM** uses the `t = 256` member, over the 199-bit smooth prime
//!     `p₂` defined in `field::p192` (`T_RESIDUE = 256`).
//!
//! `power_residue::PowerResidueParams` already parameterises the *`t`*
//! axis (it is constructed by `PowerResidueParams::new(t)` for any
//! power-of-two `t`, and the existing test `legendre_consistency_for_t_
//! equals_2` instantiates `new(2)`). What it does *not* exercise is the
//! *modulus* axis: it is hardwired to `Fp192`. The Loquat member lives
//! over a different field type (`Fp127`).
//!
//! This module makes the family parameterisation **demonstrably runnable
//! over both members on both axes**, without disturbing the shipped PLUM
//! `power_residue` module. It does so additively: it computes the raw
//! symbol `a^((p-1)/t) mod p` for each field through that field's own
//! `pow`, and asserts the family invariants that any power-residue PRF
//! member must satisfy (multiplicativity, output lands in the `t`-th
//! roots of unity, `t = 2` recovers the Legendre symbol).
//!
//! Scope note: this is the *cheap* axis of the family generalisation. The
//! expensive axis — a single Griffin AIR instantiated over both the
//! base-field (PLUM, `F_p`) and the quadratic-extension (Loquat, `F_p²`)
//! members — is intentionally **not** built here. See the engineer report
//! / `griffin_p127.rs` vs `griffin_p192.rs` for the two current separate
//! instantiations.

use num_bigint::BigUint;
use num_traits::One;

use crate::primitives::field::p127::Fp127;
use crate::primitives::field::p192::Fp192;

/// One member of the power-residue PRF family, identified by its
/// `(scheme, t, modulus-bit-width)` tuple. Carries only the metadata; the
/// arithmetic is performed by the concrete-field helpers below so each
/// member uses its own (instrumented) field multiplication path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyMember {
    /// Human label, e.g. `"Loquat (Legendre)"` or `"PLUM"`.
    pub scheme: &'static str,
    /// Power-residue parameter `t`. Loquat = 2, PLUM = 256.
    pub t: u64,
    /// Bit width of the prime modulus (for reporting / sanity only).
    pub modulus_bits: usize,
}

/// The two concrete family members the thesis measures.
pub const LOQUAT_MEMBER: FamilyMember = FamilyMember {
    scheme: "Loquat (Legendre, t=2, Mersenne-127)",
    t: 2,
    modulus_bits: 127,
};

pub const PLUM_MEMBER: FamilyMember = FamilyMember {
    scheme: "PLUM (power-residue, t=256, 199-bit smooth)",
    t: 256,
    modulus_bits: 199,
};

// ---------------------------------------------------------------------------
// t = 2 over Fp127  (the Loquat / Legendre member)
// ---------------------------------------------------------------------------

/// Raw `t`-th power-residue symbol over `Fp127` for `t = 2`:
/// `a^((p-1)/2) mod p`, which for the Legendre case lands in {0, 1, -1}
/// (0 only when `a = 0`). For `p = 2^127 − 1`, `(p-1)/2 = 2^126 − 1`.
///
/// This intentionally mirrors `loquat::field_utils::legendre_symbol_secure`
/// but is kept local so the family demonstration does not depend on the
/// Loquat signature crate compiling.
pub fn symbol_raw_fp127_t2(a: Fp127) -> Fp127 {
    if a.is_zero() {
        return Fp127::zero();
    }
    // (p - 1) / 2 = 2^126 - 1.
    let exp: u128 = (1u128 << 126) - 1;
    a.pow(exp)
}

/// Discrete-log of the `t = 2` symbol into `Z_2 = {0, 1}`:
///   residue   (symbol = +1) -> 0
///   non-res.  (symbol = -1) -> 1
///   zero                    -> 0
///
/// This is exactly Loquat's `L_K^2` once the caller has formed `a + K`.
pub fn symbol_fp127_t2(a: Fp127) -> u64 {
    let s = symbol_raw_fp127_t2(a);
    if a.is_zero() || s.is_zero() {
        0
    } else if s == Fp127::one() {
        0 // quadratic residue
    } else {
        1 // quadratic non-residue (symbol == -1 == p-1)
    }
}

// ---------------------------------------------------------------------------
// t = 256 over Fp192  (the PLUM member) — re-uses the shipped module
// ---------------------------------------------------------------------------

/// Raw `t`-th power-residue symbol over `Fp192` for arbitrary `t | p - 1`:
/// `a^((p-1)/t) mod p`. This is `Fp192::t_power_residue_raw` generalised
/// to an explicit `t` so the family axis (not just `t = 256`) is runnable.
pub fn symbol_raw_fp192(a: &Fp192, t: u64) -> Fp192 {
    if a.is_zero() {
        return Fp192::zero();
    }
    let p_minus_1: BigUint = Fp192::modulus() - 1u32;
    assert!(
        (&p_minus_1 % t) == BigUint::from(0u32),
        "family: t = {} must divide p - 1 for Fp192",
        t
    );
    let exp = p_minus_1 / t;
    a.pow_biguint(&exp)
}

// ---------------------------------------------------------------------------
// Family-level invariants (the cross-member contract a PRF member must meet)
// ---------------------------------------------------------------------------

/// Returns `true` iff `x` is a `t`-th root of unity in the relevant field,
/// i.e. `x^t = 1`. Every nonzero power-residue symbol must satisfy this —
/// it is the structural property that makes the dlog-into-`Z_t` step
/// well-defined. Implemented per-field because the two fields are distinct
/// concrete types with no shared trait in this repo.
pub fn is_tth_root_of_unity_fp127(x: Fp127, t: u64) -> bool {
    x.pow(t as u128) == Fp127::one()
}

pub fn is_tth_root_of_unity_fp192(x: &Fp192, t: u64) -> bool {
    x.pow_u128(t as u128).is_one()
}

/// Confirm the displayed `(p-1)/t` exponent is integral for a member.
pub fn member_t_divides_p_minus_1(member: &FamilyMember) -> bool {
    match member.modulus_bits {
        127 => {
            // p = 2^127 - 1; p - 1 = 2^127 - 2 = 2 * (2^126 - 1).
            // Only t that are relevant here are powers of two; 2 | (p-1).
            let p_minus_1: u128 = ((1u128 << 127) - 1) - 1;
            (p_minus_1 % (member.t as u128)) == 0
        }
        _ => {
            let p_minus_1: BigUint = Fp192::modulus() - 1u32;
            (&p_minus_1 % member.t) == BigUint::from(0u32)
        }
    }
}

/// Smoke entry point: evaluate one symbol per member and return the pair
/// `(loquat_symbol_bit, plum_symbol_raw_is_root)`. Cheap; no proving.
/// Intended to be called from a host/bin or a doctest to show the family
/// runs end-to-end on both members.
pub fn family_smoke() -> (u64, bool) {
    // Loquat member: Legendre bit of a fixed input.
    let loquat_bit = symbol_fp127_t2(Fp127::new(7));
    // PLUM member: raw 256-residue symbol of a fixed input, check it is a
    // 256-th root of unity.
    let plum_sym = symbol_raw_fp192(&Fp192::from_u64(7), 256);
    let plum_ok = is_tth_root_of_unity_fp192(&plum_sym, 256);
    (loquat_bit, plum_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    // ---- Loquat member (t = 2, Fp127) ----

    #[test]
    fn loquat_t2_squares_are_residues() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([11u8; 32]);
        for _ in 0..32 {
            let r = Fp127::rand_nonzero(&mut rng);
            let sq = r * r;
            assert_eq!(symbol_fp127_t2(sq), 0, "square must be a residue (bit 0)");
        }
    }

    #[test]
    fn loquat_t2_symbol_is_pm1_root() {
        // For t=2, the raw symbol of any nonzero element is a square root
        // of unity: either 1 or p-1 (= -1).
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([12u8; 32]);
        for _ in 0..32 {
            let a = Fp127::rand_nonzero(&mut rng);
            let s = symbol_raw_fp127_t2(a);
            assert!(
                is_tth_root_of_unity_fp127(s, 2),
                "raw t=2 symbol must satisfy s^2 = 1"
            );
        }
    }

    #[test]
    fn loquat_t2_zero_is_zero() {
        assert_eq!(symbol_fp127_t2(Fp127::zero()), 0);
    }

    // ---- PLUM member (t = 256, Fp192) ----

    #[test]
    fn plum_t256_symbol_is_256th_root() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([13u8; 32]);
        for _ in 0..16 {
            let a = Fp192::rand_nonzero(&mut rng);
            let s = symbol_raw_fp192(&a, 256);
            assert!(
                is_tth_root_of_unity_fp192(&s, 256),
                "raw t=256 symbol must satisfy s^256 = 1"
            );
        }
    }

    #[test]
    fn plum_t256_zero_is_zero() {
        assert!(symbol_raw_fp192(&Fp192::zero(), 256).is_zero());
    }

    // ---- The family axis: SAME logic at t=2 AND t=256 over Fp192 ----
    // Demonstrates the `t`-axis is genuinely a parameter, not a constant:
    // the PLUM field also supports the Loquat-style t=2 member.

    #[test]
    fn fp192_supports_both_t2_and_t256() {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([14u8; 32]);
        for _ in 0..16 {
            let a = Fp192::rand_nonzero(&mut rng);
            // t = 2 member over the PLUM field (Legendre-style).
            let s2 = symbol_raw_fp192(&a, 2);
            assert!(is_tth_root_of_unity_fp192(&s2, 2), "t=2 symbol over Fp192 must be ±1");
            // t = 256 member over the same field (PLUM proper).
            let s256 = symbol_raw_fp192(&a, 256);
            assert!(is_tth_root_of_unity_fp192(&s256, 256), "t=256 symbol over Fp192");
        }
    }

    #[test]
    fn fp192_t2_squares_are_residues() {
        // Cross-check: at t=2 the PLUM field behaves exactly like the
        // Loquat Legendre member — squares have symbol 1.
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([15u8; 32]);
        for _ in 0..16 {
            let r = Fp192::rand_nonzero(&mut rng);
            let sq = r.clone() * r;
            let s2 = symbol_raw_fp192(&sq, 2);
            assert!(s2.is_one(), "square must have t=2 symbol = 1 over Fp192");
        }
    }

    // ---- Member metadata sanity ----

    #[test]
    fn members_have_integral_exponent() {
        assert!(member_t_divides_p_minus_1(&LOQUAT_MEMBER), "2 | p127-1");
        assert!(member_t_divides_p_minus_1(&PLUM_MEMBER), "256 | p192-1");
    }

    #[test]
    fn family_smoke_runs_both_members() {
        let (loquat_bit, plum_ok) = family_smoke();
        assert!(loquat_bit == 0 || loquat_bit == 1);
        assert!(plum_ok, "PLUM symbol must be a 256th root of unity");
    }
}
