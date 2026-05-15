//! Public-parameter setup for PLUM (Algorithm 1 in the paper).
//!
//! At each supported security level λ ∈ {80, 100, 128} we materialise:
//!
//!   - **PRF parameters** — `t = 256`, public-key length `L`, challenged-
//!     symbol count `B`, and the PRF index set `I ⊆ F_p` of size `L`.
//!   - **Sumcheck domain** — multiplicative coset `H ⊆ F_p` of size `2m`,
//!     with `m = 4` at λ=128.
//!   - **STIR / low-degree-test domains** — initial code domain `U` of
//!     size `|U| = 2^12 = 4096`, the folding parameter `η = 4`, max
//!     degree `d* = 128`, stopping degree `d_stop = 32`, round count
//!     `R = log_η(d*/d_stop) = 1`, and per-round query repetition `κ_i`.
//!
//! The smooth multiplicative subgroup of size `2^64` (this field's
//! 2-adicity) is more than enough room for both `U` of size `2^12` and
//! `H` of size `2^3`. We pick a primitive root `g` of `F_p^*` via the
//! same procedure as `plum::prf::find_primitive_root_of_unity` and
//! derive generators `ω_U = g^{(p-1)/|U|}` and `ω_H = g^{(p-1)/|H|}`.
//! `H` is taken to be a coset `H = c · ⟨ω_H⟩` with shift `c` chosen so
//! that `H ∩ U = ∅` (we pick the smallest small integer that is not a
//! power of `ω_U`).
//!
//! The PRF challenge set `I` is sampled deterministically by SHAKE256
//! over a domain-separated seed, so two runs with the same security
//! level produce the same `I` and the prover and verifier see identical
//! parameters without communicating.

use std::collections::HashSet;

use num_bigint::BigUint;
use num_traits::One;
use serde::{Deserialize, Serialize};

use super::field_p192::{Fp192, T_RESIDUE};
use super::hasher::shake256_expand;

/// Parameters that depend only on the security level. Hardcoded from
/// PLUM Table 2 (Griffin instantiation) at λ ∈ {80, 100, 128}.
#[derive(Debug, Clone, Copy)]
pub struct PlumSecurityProfile {
    pub security_level: usize,
    /// Public key length in PRF symbols.
    pub l: usize,
    /// Number of challenged residuosity symbols.
    pub b: usize,
    /// Degree parameter for the witness polynomial (m=4 across all λ).
    pub m: usize,
    /// Parallel-execution count.
    pub n: usize,
    /// STIR first-round query complexity (κ_0).
    pub kappa_0: usize,
    /// Maximum polynomial degree at the start of the low-degree test.
    pub d_star: usize,
    /// Stopping degree.
    pub d_stop: usize,
    /// STIR folding parameter.
    pub eta: usize,
    /// `|U|` — initial code-domain size.
    pub code_domain_size: usize,
    /// `|H|` — sumcheck coset size (= 2m).
    pub sumcheck_coset_size: usize,
}

impl PlumSecurityProfile {
    pub const fn r_rounds(&self) -> usize {
        let mut r = 0usize;
        let mut deg = self.d_star;
        while deg > self.d_stop {
            deg /= self.eta;
            r += 1;
        }
        r
    }
}

/// Lookup the profile for a paper-listed security level.
pub fn security_profile(security_level: usize) -> Option<PlumSecurityProfile> {
    Some(match security_level {
        // Values from PLUM Table 2 (Griffin instantiation column).
        80 => PlumSecurityProfile {
            security_level: 80,
            l: 1 << 12, // L = 4096 — matches the paper's "L = 2^12" remark
            b: 16,
            m: 4,
            n: 7,
            kappa_0: 16,
            d_star: 128,
            d_stop: 32,
            eta: 4,
            code_domain_size: 1 << 12,
            sumcheck_coset_size: 8,
        },
        100 => PlumSecurityProfile {
            security_level: 100,
            l: 1 << 12,
            b: 21,
            m: 4,
            n: 7,
            kappa_0: 21,
            d_star: 128,
            d_stop: 32,
            eta: 4,
            code_domain_size: 1 << 12,
            sumcheck_coset_size: 8,
        },
        128 => PlumSecurityProfile {
            security_level: 128,
            l: 1 << 12,
            b: 28,
            m: 4,
            n: 7,
            kappa_0: 26,
            d_star: 128,
            d_stop: 32,
            eta: 4,
            code_domain_size: 1 << 12,
            sumcheck_coset_size: 8,
        },
        _ => return None,
    })
}

/// All public parameters PLUM needs to sign and verify at a given λ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlumPublicParams {
    pub security_level: usize,
    pub t: u64,
    pub l: usize,
    pub b: usize,
    pub m: usize,
    pub n: usize,
    pub kappa_0: usize,
    pub d_star: usize,
    pub d_stop: usize,
    pub eta: usize,
    pub r_rounds: usize,
    /// Generator `ω_U` such that `⟨ω_U⟩ = U` has order `|U|`.
    pub u_generator: Fp192,
    pub u_size: usize,
    /// Generator `ω_H` such that `⟨ω_H⟩` has order `|H| = 2m`.
    pub h_generator: Fp192,
    /// Coset shift `c` such that `H = c · ⟨ω_H⟩` is disjoint from `U`.
    pub h_shift: Fp192,
    pub h_size: usize,
    /// PRF challenge index set `I = {I_1, …, I_L}`.
    pub challenge_set: Vec<Fp192>,
    /// Per-round STIR query complexity `κ_i`.
    pub kappas: Vec<usize>,
    /// Per-round code domain size `|U_i| = |U_0| / η^i`.
    pub u_sizes: Vec<usize>,
}

impl PlumPublicParams {
    pub fn r(&self) -> usize {
        self.r_rounds
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlumSetupError {
    UnsupportedSecurityLevel(usize),
    NoGeneratorFound,
    NoCosetShiftFound,
}

impl core::fmt::Display for PlumSetupError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedSecurityLevel(l) => write!(f, "unsupported security level: {}", l),
            Self::NoGeneratorFound => write!(f, "could not find a generator of F_p^* within search bound"),
            Self::NoCosetShiftFound => write!(f, "could not find a coset shift disjoint from U within search bound"),
        }
    }
}

impl std::error::Error for PlumSetupError {}

/// Build the public parameters for the given security level.
pub fn plum_setup(security_level: usize) -> Result<PlumPublicParams, PlumSetupError> {
    let profile = security_profile(security_level)
        .ok_or(PlumSetupError::UnsupportedSecurityLevel(security_level))?;

    // 1. Primitive root g of F_p^* (full-order generator).
    let g = find_primitive_root_of_fp_star()?;
    let pm1 = Fp192::modulus() - 1u32;

    // 2. ω_U of order |U|.
    assert!(profile.code_domain_size.is_power_of_two());
    assert!(profile.code_domain_size.trailing_zeros() as usize <= super::field_p192::TWO_ADICITY);
    let u_exp = &pm1 / BigUint::from(profile.code_domain_size as u64);
    let u_generator = g.pow_biguint(&u_exp);

    // 3. ω_H of order |H|.
    let h_exp = &pm1 / BigUint::from(profile.sumcheck_coset_size as u64);
    let h_generator = g.pow_biguint(&h_exp);

    // 4. Choose shift c for H so that H ∩ U = ∅. Concretely, c must not
    //    be a (|U|)-th power. Equivalently c^|U| ≠ 1.
    let h_shift = find_coset_shift_outside_u(&u_generator, profile.code_domain_size)?;

    // 5. Per-round STIR sizes. PLUM (and STIR) define |U_i| = |U_{i-1}| / η,
    //    and κ_i = max(κ_0 · η^{-i} log_η ..., minimum). For our R=1 case
    //    we only need κ_0 and κ_1, with κ_1 being a small constant — set
    //    κ_R = max(2, κ_0 / 2) per the paper's pattern. Future tuning can
    //    swap this for the exact formula once Phase 6/5 implementations
    //    consume it.
    let r_rounds = profile.r_rounds();
    let mut u_sizes = Vec::with_capacity(r_rounds + 1);
    let mut current = profile.code_domain_size;
    u_sizes.push(current);
    for _ in 0..r_rounds {
        current /= profile.eta;
        u_sizes.push(current);
    }

    let mut kappas = Vec::with_capacity(r_rounds + 1);
    kappas.push(profile.kappa_0);
    for _ in 0..r_rounds {
        kappas.push((profile.kappa_0 / 2).max(2));
    }

    // 6. Sample the PRF index set I from a SHAKE256 seed.
    let challenge_set = sample_challenge_set(security_level, profile.l);

    Ok(PlumPublicParams {
        security_level,
        t: T_RESIDUE,
        l: profile.l,
        b: profile.b,
        m: profile.m,
        n: profile.n,
        kappa_0: profile.kappa_0,
        d_star: profile.d_star,
        d_stop: profile.d_stop,
        eta: profile.eta,
        r_rounds,
        u_generator,
        u_size: profile.code_domain_size,
        h_generator,
        h_shift,
        h_size: profile.sumcheck_coset_size,
        challenge_set,
        kappas,
        u_sizes,
    })
}

/// Search for `g ∈ F_p^*` with full order `p - 1`. For our prime,
/// `p - 1 = 2^64 · p_0` with `p_0` prime, so we only need to verify
/// `g^{(p-1)/2} ≠ 1` and `g^{(p-1)/p_0} ≠ 1`.
fn find_primitive_root_of_fp_star() -> Result<Fp192, PlumSetupError> {
    use num_traits::Zero;
    let pm1 = Fp192::modulus() - 1u32;
    // Factor p - 1 = 2^64 · p_0. We extract p_0 by shifting.
    let mut cofactor = pm1.clone();
    while cofactor.is_zero() || (&cofactor % 2u32) == BigUint::from(0u32) {
        cofactor /= 2u32;
        if cofactor.is_zero() {
            break;
        }
    }
    // cofactor is the odd part; for our prime that's p_0 (prime).
    let half = &pm1 / 2u32;
    let by_p0 = &pm1 / &cofactor;

    for g_int in 2u64..1u64 << 16 {
        let g = Fp192::from_u64(g_int);
        if g.is_zero() {
            continue;
        }
        let test_half = g.pow_biguint(&half);
        if test_half.is_one() {
            continue;
        }
        let test_by_p0 = g.pow_biguint(&by_p0);
        if test_by_p0.is_one() {
            continue;
        }
        return Ok(g);
    }
    Err(PlumSetupError::NoGeneratorFound)
}

fn find_coset_shift_outside_u(
    u_generator: &Fp192,
    u_size: usize,
) -> Result<Fp192, PlumSetupError> {
    // `c` is in U iff `c^|U| = 1`. We want the smallest small integer
    // that is NOT in U. Note: any element of order p-1 (or a non-trivial
    // divisor not dividing |U|) suffices.
    let u_order = BigUint::from(u_size as u64);
    let _u_check = u_generator.clone();
    for c_int in 2u64..1u64 << 16 {
        let c = Fp192::from_u64(c_int);
        if c.is_zero() {
            continue;
        }
        let raised = c.pow_biguint(&u_order);
        if !raised.is_one() {
            return Ok(c);
        }
    }
    Err(PlumSetupError::NoCosetShiftFound)
}

fn sample_challenge_set(security_level: usize, l: usize) -> Vec<Fp192> {
    // We pull 25 bytes per attempted draw (= 200 bits, mask the top bit so
    // candidates land in [0, 2^199)). With our prime's top byte = 0x4c the
    // acceptance rate is ~0.60. We re-seed if the initial allocation
    // happens to be insufficient (vanishingly unlikely at our parameter
    // sizes, but the logic is here for robustness).
    let bytes_per_draw = 25;
    let target_bytes = l * bytes_per_draw * 4;

    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(b"PLUM/challenge_set/v1");
    seed.extend_from_slice(&(security_level as u64).to_le_bytes());
    seed.extend_from_slice(&(l as u64).to_le_bytes());

    let mut stream = shake256_expand(&seed, target_bytes);
    let mut set = Vec::with_capacity(l);
    let mut seen: HashSet<Fp192> = HashSet::with_capacity(l);
    let mut cursor = 0usize;
    let mut reseed_counter = 0u32;

    while set.len() < l {
        if cursor + bytes_per_draw > stream.len() {
            // Re-seed with a counter so we get a fresh stream.
            let mut next_seed = seed.clone();
            next_seed.extend_from_slice(b"/reseed");
            next_seed.extend_from_slice(&reseed_counter.to_le_bytes());
            reseed_counter += 1;
            stream = shake256_expand(&next_seed, target_bytes);
            cursor = 0;
            if reseed_counter > 16 {
                panic!(
                    "PLUM setup: challenge-set sampling exhausted {} reseed attempts",
                    reseed_counter
                );
            }
            continue;
        }

        let mut padded = [0u8; 32];
        padded[..bytes_per_draw]
            .copy_from_slice(&stream[cursor..cursor + bytes_per_draw]);
        padded[bytes_per_draw - 1] &= 0x7F; // mask top bit of byte 24
        cursor += bytes_per_draw;

        let Some(elem) = Fp192::from_bytes_le(&padded) else { continue };
        if elem.is_zero() {
            continue;
        }
        if seen.insert(elem.clone()) {
            set.push(elem);
        }
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_security_levels_resolve() {
        for level in [80usize, 100, 128] {
            let pp = plum_setup(level).expect("setup must succeed");
            assert_eq!(pp.security_level, level);
        }
    }

    #[test]
    fn unsupported_security_level_errors() {
        assert!(plum_setup(64).is_err());
    }

    #[test]
    fn lambda_128_parameters_match_paper() {
        // PLUM Table 2 (Griffin row, λ=128): κ_0=26, |σ| derivation
        // assumes m=4, n=7, B=28, L=2^12, η=4, d*=128, d_stop=32, R=1.
        let pp = plum_setup(128).unwrap();
        assert_eq!(pp.b, 28);
        assert_eq!(pp.m, 4);
        assert_eq!(pp.n, 7);
        assert_eq!(pp.l, 1 << 12);
        assert_eq!(pp.kappa_0, 26);
        assert_eq!(pp.d_star, 128);
        assert_eq!(pp.d_stop, 32);
        assert_eq!(pp.eta, 4);
        assert_eq!(pp.r_rounds, 1);
        assert_eq!(pp.u_size, 1 << 12);
        assert_eq!(pp.h_size, 8);
    }

    #[test]
    fn u_generator_has_order_u_size() {
        let pp = plum_setup(128).unwrap();
        let raised = pp.u_generator.pow_u128(pp.u_size as u128);
        assert!(raised.is_one(), "u_generator^|U| should equal 1");
        // And ω_U^(|U|/2) ≠ 1 (primitivity for power-of-two order)
        let half = pp.u_generator.pow_u128((pp.u_size / 2) as u128);
        assert!(!half.is_one(), "u_generator is not a primitive |U|-th root");
    }

    #[test]
    fn h_generator_has_order_h_size() {
        let pp = plum_setup(128).unwrap();
        let raised = pp.h_generator.pow_u128(pp.h_size as u128);
        assert!(raised.is_one());
        let half = pp.h_generator.pow_u128((pp.h_size / 2) as u128);
        assert!(!half.is_one());
    }

    #[test]
    fn h_and_u_are_disjoint() {
        let pp = plum_setup(128).unwrap();
        // H = c · <ω_H>, U = <ω_U>. Any h = c · ω_H^j ∈ H is in U iff
        // c · ω_H^j ∈ U iff c ∈ U · ω_H^{-j}. Since |H|=8 | |U|=4096,
        // ω_H is itself in U, so the question reduces to c ∈ U.
        // c ∈ U iff c^|U| = 1. Our shift was chosen specifically to fail
        // this check.
        let raised = pp.h_shift.pow_u128(pp.u_size as u128);
        assert!(!raised.is_one(), "H ⊆ U — disjointness violated");
    }

    #[test]
    fn u_sizes_descend_by_eta() {
        let pp = plum_setup(128).unwrap();
        assert_eq!(pp.u_sizes.len(), pp.r_rounds + 1);
        for win in pp.u_sizes.windows(2) {
            assert_eq!(win[0], win[1] * pp.eta);
        }
    }

    #[test]
    fn challenge_set_has_correct_size_and_uniqueness() {
        let pp = plum_setup(128).unwrap();
        assert_eq!(pp.challenge_set.len(), pp.l);
        let unique: HashSet<&Fp192> = pp.challenge_set.iter().collect();
        assert_eq!(unique.len(), pp.l, "challenge set has duplicates");
    }

    #[test]
    fn challenge_set_is_deterministic_per_security_level() {
        let pp1 = plum_setup(128).unwrap();
        let pp2 = plum_setup(128).unwrap();
        assert_eq!(pp1.challenge_set, pp2.challenge_set);
        let pp_80 = plum_setup(80).unwrap();
        assert_ne!(pp1.challenge_set, pp_80.challenge_set);
    }

    #[test]
    fn r_rounds_is_one_at_lambda_128() {
        // log_4(128/32) = log_4(4) = 1 → STIR runs only one folding round.
        let pp = plum_setup(128).unwrap();
        assert_eq!(pp.r_rounds, 1);
    }

    #[test]
    fn serde_roundtrip() {
        let pp = plum_setup(128).unwrap();
        let encoded = bincode::serialize(&pp).expect("encode");
        let decoded: PlumPublicParams = bincode::deserialize(&encoded).expect("decode");
        assert_eq!(pp.security_level, decoded.security_level);
        assert_eq!(pp.b, decoded.b);
        assert_eq!(pp.challenge_set, decoded.challenge_set);
        assert_eq!(pp.u_generator, decoded.u_generator);
        assert_eq!(pp.h_shift, decoded.h_shift);
    }
}
