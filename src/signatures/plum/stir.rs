//! STIR low-degree-test prover machinery (Phase 5b).
//!
//! Algorithm 5 of Zhang et al., PLUM, ProvSec 2025 (LNCS 16172 p. 121).
//! This module currently implements the **fold** step — Algorithm 5
//! lines 4–8:
//!
//! ```text
//! for y ∈ U_{i-1}^η do
//!   Define S_y = {x ∈ U_{i-1} | x^η = y}.
//!   Set p̂_y(x) ← Interpolate(S_y, f̂_{i-1}|_{S_y}).
//!   f'_i.append(p̂_y(r_{i-1}^fold))
//! Interpolate â_i ← Interpolate(U_{i-1}^η, f'_i).
//! ```
//!
//! Rate correction (lines 9–13), the final-polynomial check (lines 14–15),
//! and the protocol-level Merkle commitments live in Phase 5c.
//!
//! For PLUM-128 (η = 4, |U_0| = 2¹², R = 1; paper p. 123 §3.3:
//! "We set the folding parameter η = 4 …", "|U| = d*/ρ = 2¹²", and
//! "We set d_stop = 32, leading to the round complexity of 1 in the
//! low-degree test") this runs once, producing `â_1` of degree
//! `< |U_0|/η = 1024` in coefficient form. The computation is 1024
//! four-point Lagrange interpolations + one length-1024 IFFT.
//!
//! ## Domain conventions
//!
//! `U_{i-1}` is taken to be a multiplicative subgroup `⟨ω⟩` of `F_p^*`
//! with `|U_{i-1}| = n`, where `ω` is a primitive `n`-th root of unity
//! and `η | n`. `U_{i-1}^η = ⟨ω^η⟩` is then a subgroup of size `n/η`.
//! For PLUM-128 setup builds `U_0 = ⟨ω_U⟩` (no shift), so this matches
//! `pp.u_generator` directly.
//!
//! Fibers: for `y_k = ω^{kη} ∈ U_{i-1}^η`, the fiber
//! `S_{y_k} = {x ∈ U_{i-1} : x^η = y_k}` consists of
//! `{ω^{k + t·(n/η)} : t ∈ [0, η)}` — i.e., a stride-`(n/η)` slice of
//! the evaluations array.

use super::field_p192::Fp192;
use super::fft::{FftError, interpolate_on_coset};
use super::stir_poly::{
    StirPolyError, degree_correction_polynomial, divide_by_linear_product, evaluate,
    lagrange_interpolate, multiply,
};

#[derive(Debug)]
pub enum StirError {
    DomainNotPowerOfTwo,
    EtaDoesNotDivideDomain,
    EvaluationsLengthMismatch,
    InterpolationError(StirPolyError),
    FftError(FftError),
    /// `G_i` (the union of `r_i^out` and the `κ_i` shift challenges) and
    /// the values vector passed to `rate_correct` must have the same length.
    RateCorrectLengthMismatch,
}

impl core::fmt::Display for StirError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DomainNotPowerOfTwo => {
                write!(f, "STIR fold requires |U_{{i-1}}| to be a power of two")
            }
            Self::EtaDoesNotDivideDomain => {
                write!(f, "STIR fold requires η | |U_{{i-1}}|")
            }
            Self::EvaluationsLengthMismatch => write!(
                f,
                "evaluations.len() must equal the domain size |U_{{i-1}}|"
            ),
            Self::InterpolationError(e) => write!(f, "Lagrange: {}", e),
            Self::FftError(e) => write!(f, "FFT: {}", e),
            Self::RateCorrectLengthMismatch => write!(
                f,
                "rate_correct: G_i and values must have the same length"
            ),
        }
    }
}

impl std::error::Error for StirError {}

impl From<StirPolyError> for StirError {
    fn from(e: StirPolyError) -> Self {
        Self::InterpolationError(e)
    }
}

impl From<FftError> for StirError {
    fn from(e: FftError) -> Self {
        Self::FftError(e)
    }
}

/// One STIR fold round. Maps `f̂_{i-1}|_{U_{i-1}}` to `â_i` in
/// coefficient form, with `deg(â_i) < |U_{i-1}|/η`.
///
/// Inputs:
/// - `evaluations`: `f̂_{i-1}` at `(ω^0, ω^1, ..., ω^{n-1})` in that
///   order, where `n = |U_{i-1}| = evaluations.len()`.
/// - `generator`: `ω`, primitive `n`-th root of unity in `F_p^*`.
/// - `eta`: the folding rate, must divide `n`.
/// - `r_fold`: the folding challenge `r_{i-1}^fold ∈ F_p` from the
///   prior round's transcript (or from Algorithm 4 line 14 for the
///   first STIR round).
///
/// Output: `â_i` in coefficient form, length `n/η`.
pub fn stir_fold(
    evaluations: &[Fp192],
    generator: &Fp192,
    eta: usize,
    r_fold: &Fp192,
) -> Result<Vec<Fp192>, StirError> {
    let n = evaluations.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(StirError::DomainNotPowerOfTwo);
    }
    if eta == 0 || n % eta != 0 {
        return Err(StirError::EtaDoesNotDivideDomain);
    }
    // Fail fast on a non-primitive generator. `interpolate_on_coset`
    // below would catch this too, but only after `fold_size` wasted
    // Lagrange interpolations.
    let one = Fp192::one();
    if generator.pow_u128(n as u128) != one
        || (n > 1 && generator.pow_u128((n / 2) as u128) == one)
    {
        return Err(StirError::FftError(FftError::GeneratorWrongOrder));
    }
    let fold_size = n / eta;

    // Per-fiber Lagrange + evaluate at r_fold. The fiber for y_k =
    // ω^{kη} is {ω^{k + t · fold_size} : t ∈ [0, η)}.
    let mut fold_evals = Vec::with_capacity(fold_size);
    for k in 0..fold_size {
        // Build the fiber domain and the values on it.
        let mut fiber_x = Vec::with_capacity(eta);
        let mut fiber_y = Vec::with_capacity(eta);
        let mut idx = k;
        for _ in 0..eta {
            // x_t = ω^idx; lazily computed once we know the index. We
            // avoid recomputing ω^idx by pulling from evaluations and
            // tracking the explicit point separately.
            //
            // Note: in the future, fiber_x can be precomputed once per
            // generator (the η-th root of unity is shared across all
            // fibers). For now we recompute via pow_u128 — at PLUM-128
            // that's 4096 pow_u128 calls per round, negligible vs the
            // sumcheck/STIR cost downstream.
            fiber_x.push(generator.pow_u128(idx as u128));
            fiber_y.push(evaluations[idx].clone());
            idx += fold_size;
        }
        // p̂_y(x) by Lagrange, evaluated at r_fold.
        let p_y_coeffs = lagrange_interpolate(&fiber_x, &fiber_y)?;
        fold_evals.push(evaluate(&p_y_coeffs, r_fold));
    }

    // Interpolate â_i ← Interpolate(U_{i-1}^η, fold_evals). Domain is
    // ⟨ω^η⟩ of size fold_size, a subgroup (shift = 1). The IFFT
    // produces coefficients in ascending order.
    let omega_eta = generator.pow_u128(eta as u128);
    let coeffs = interpolate_on_coset(&fold_evals, &Fp192::one(), &omega_eta)?;
    Ok(coeffs)
}

/// STIR rate correction (Algorithm 5 lines 11–13, paper p. 121).
///
/// Given `â_i` in coefficient form, the challenge set
/// `G_i = (r_i^out, r_{i,1}^shift, …, r_{i,κ}^shift)`, and the
/// corresponding values `b_i` is supposed to take at those points
/// (`b_i(r_i^out) = β_i = â_i(r_i^out)`, `b_i(r_{i,j}^shift) =
/// â_i(r_{i,j}^shift)`), this function:
///
///   1. Lagrange-interpolates `b_i(x)` of degree `< |G_i|` through
///      `(G_i, values)`.
///   2. Computes `â_i'(x) = (â_i(x) − b_i(x)) / Π_{α ∈ G_i}(x − α)`.
///      The division is exact by construction: the numerator vanishes
///      at every `α ∈ G_i` because `(â_i − b_i)(α) = â_i(α) − values[α]
///      = 0` by the definition of `b_i`.
///   3. Returns `â_i'`. Caller composes with `t_i` via
///      `apply_degree_correction` to get `f̂_i`.
///
/// Inputs:
/// - `a_i`: `â_i` in coefficient form.
/// - `g_i`: the challenge set, ordered `(r_i^out, r_{i,1}^shift, …)`.
/// - `values`: same length as `g_i`. `values[0] = β_i = â_i(r_i^out)`
///   in the protocol; `values[1..]` are `â_i(r_{i,j}^shift)`.
///
/// The function does NOT re-evaluate `â_i` at the challenge points
/// itself, because the protocol already provides those evaluations
/// (β_i is sent before the secondary challenges are derived). For
/// independent verification, callers can re-evaluate via
/// `stir_poly::evaluate`.
///
/// Preconditions (not all enforced by the type system):
///   - `g_i` contains pairwise-distinct elements. In PLUM's protocol
///     this holds with probability `1 − O(|G_i|² / |F_p|)` because
///     `r_i^out` and `r_{i,j}^shift` come from independent Fiat-Shamir
///     outputs (Alg 5 lines 10–11). Violation surfaces as
///     `InterpolationError(InterpolationDomainNotDistinct)`.
///   - `g_i.len() == values.len()`. Enforced.
///   - `values[ℓ] == evaluate(a_i, g_i[ℓ])` for every `ℓ`. Violation
///     surfaces as `InterpolationError(QuotientRemainderNonZero)`.
pub fn rate_correct(
    a_i: &[Fp192],
    g_i: &[Fp192],
    values: &[Fp192],
) -> Result<Vec<Fp192>, StirError> {
    if g_i.len() != values.len() {
        return Err(StirError::RateCorrectLengthMismatch);
    }
    if g_i.is_empty() {
        // No correction — the protocol-degenerate case where κ = 0
        // and there's no r_i^out either. Return a_i unchanged.
        return Ok(a_i.to_vec());
    }
    debug_assert!(
        g_i.len() <= a_i.len() + 1,
        "rate_correct: |G_i| = {} exceeds deg(â_i) + 1 = {}; check caller wiring",
        g_i.len(),
        a_i.len() + 1
    );
    let b_i = lagrange_interpolate(g_i, values)?;
    // Subtract b_i from a_i (coefficient-wise; pad with zeros).
    let len = a_i.len().max(b_i.len());
    let mut numerator = vec![Fp192::zero(); len];
    for (i, c) in a_i.iter().enumerate() {
        numerator[i] = c.clone();
    }
    for (i, c) in b_i.iter().enumerate() {
        numerator[i] = numerator[i].clone() - c.clone();
    }
    // Divide by Π_{α ∈ G_i}(x − α). The division is exact by the
    // construction of b_i; divide_by_linear_product errors if not.
    let quotient = divide_by_linear_product(&numerator, g_i)?;
    Ok(quotient)
}

/// Compose `â_i'` with the degree-correction polynomial `t_i` to
/// produce `f̂_i = â_i' · t_i` (Algorithm 5 line 13, paper p. 121).
///
/// `t_i` is built from `(r_comb, κ_i)` via `stir_poly::
/// degree_correction_polynomial`, so the caller need only provide the
/// scalar parameters. Returns the coefficients of `f̂_i`.
pub fn apply_degree_correction(
    a_i_prime: &[Fp192],
    r_comb: &Fp192,
    kappa: usize,
) -> Vec<Fp192> {
    let t_i = degree_correction_polynomial(r_comb, kappa);
    multiply(a_i_prime, &t_i)
}

/// Coefficient-form STIR fold (Algorithm 5 line 14 "the last round
/// defines coefs that contains < d_R coefficients of a polynomial
/// f̂_{R+1}, which is defined by folding f̂_R").
///
/// Where `stir_fold` takes evaluations on a domain and returns the
/// interpolated `â_i`, this function takes coefficients directly. The
/// standard FRI/STIR fold identity is
///
///     (fold f)_k = Σ_{r=0}^{η-1} r_fold^r · coeffs[k·η + r].
///
/// Derivation: write `f(x) = Σ_{r=0}^{η-1} x^r · f_r(x^η)` with
/// `f_r(y) := Σ_k c_{kη + r} y^k`. The fold at `α = r_fold` is
/// `(fold f)(y) = Σ_r α^r · f_r(y)`, whose coefficient at `y^k` is
/// `Σ_r α^r · c_{kη + r}`. ☐
///
/// Returns a vector of length `⌈coeffs.len() / η⌉`. For PLUM-128 with
/// R = 1 and `d_R = d_stop = 32`, the final `coefs` is bounded by 32
/// elements per Algorithm 5 line 14 — the caller must ensure
/// `coeffs.len() ≤ η · d_stop` so the output respects the
/// `< d_stop` degree bound.
pub fn fold_coefficients(coeffs: &[Fp192], eta: usize, r_fold: &Fp192) -> Vec<Fp192> {
    assert!(eta > 0, "stir::fold_coefficients: η must be > 0");
    if coeffs.is_empty() {
        return Vec::new();
    }
    let n_out = coeffs.len().div_ceil(eta);
    let mut out = vec![Fp192::zero(); n_out];
    let mut alpha_r = Fp192::one();
    for r in 0..eta {
        let mut k = 0usize;
        while k * eta + r < coeffs.len() {
            out[k] = out[k].clone() + alpha_r.clone() * coeffs[k * eta + r].clone();
            k += 1;
        }
        alpha_r = alpha_r * r_fold.clone();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::plum::fft::evaluate_on_coset;
    use crate::signatures::plum::setup::plum_setup;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rand_coeffs(n: usize, seed: u64) -> Vec<Fp192> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..n).map(|_| Fp192::rand(&mut rng)).collect()
    }

    fn fp_from(seed: u64) -> Fp192 {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        Fp192::rand(&mut rng)
    }

    // Reference fold: `fold_coefficients` is the same identity, so
    // re-export under the historical test name for clarity in the
    // existing tests below.
    fn naive_fold_from_coefficients(
        coeffs: &[Fp192],
        eta: usize,
        r_fold: &Fp192,
    ) -> Vec<Fp192> {
        fold_coefficients(coeffs, eta, r_fold)
    }

    #[test]
    fn fold_recovers_oracle_for_random_polynomial() {
        // Pick a small η-friendly synthetic setup: n = 16, η = 4.
        // ω = primitive 16th root of unity, computable from the prime.
        let pp = plum_setup(128).unwrap();
        // ω₁₆ = ω_U^(|U|/16). |U| = 4096, so exponent = 256.
        let n = 16usize;
        let eta = 4usize;
        let omega = pp.u_generator.pow_u128((pp.u_size / n) as u128);
        // f of degree < n, given by random coefficients.
        let coeffs = rand_coeffs(n, 0xA000_0001);
        // Evaluations on U = ⟨ω⟩ via direct Horner.
        let evaluations: Vec<Fp192> = (0..n)
            .map(|j| {
                let x = omega.pow_u128(j as u128);
                let mut acc = Fp192::zero();
                for c in coeffs.iter().rev() {
                    acc = acc * x.clone() + c.clone();
                }
                acc
            })
            .collect();
        let r_fold = fp_from(0xA000_0002);
        let folded = stir_fold(&evaluations, &omega, eta, &r_fold).unwrap();
        let expected = naive_fold_from_coefficients(&coeffs, eta, &r_fold);
        assert_eq!(folded.len(), n / eta);
        // The folded polynomial should evaluate identically to expected
        // on the smaller domain ⟨ω^η⟩, i.e., over the n/η subgroup.
        let omega_eta = omega.pow_u128(eta as u128);
        for k in 0..(n / eta) {
            let y = omega_eta.pow_u128(k as u128);
            let lhs = {
                let mut acc = Fp192::zero();
                for c in folded.iter().rev() {
                    acc = acc * y.clone() + c.clone();
                }
                acc
            };
            let rhs = {
                let mut acc = Fp192::zero();
                for c in expected.iter().rev() {
                    acc = acc * y.clone() + c.clone();
                }
                acc
            };
            assert_eq!(lhs, rhs, "fold disagrees with oracle on ⟨ω^η⟩ at index {}", k);
        }
    }

    #[test]
    fn fold_at_plum_128_sized_domain() {
        // Exercise the production-sized fold: |U_0| = 4096, η = 4 →
        // â_1 of length 1024.
        let pp = plum_setup(128).unwrap();
        let coeffs = rand_coeffs(pp.u_size, 0xA000_0011);
        let evaluations =
            evaluate_on_coset(&coeffs, &Fp192::one(), &pp.u_generator).unwrap();
        let r_fold = fp_from(0xA000_0012);
        let folded = stir_fold(&evaluations, &pp.u_generator, pp.eta, &r_fold).unwrap();
        assert_eq!(folded.len(), pp.u_size / pp.eta);
        // Oracle check at a few points of ⟨ω^η⟩.
        let omega_eta = pp.u_generator.pow_u128(pp.eta as u128);
        let expected = naive_fold_from_coefficients(&coeffs, pp.eta, &r_fold);
        let mut y = Fp192::one();
        for _ in 0..32 {
            let lhs = evaluate(&folded, &y);
            let rhs = evaluate(&expected, &y);
            assert_eq!(lhs, rhs);
            y = y * omega_eta.clone();
        }
    }

    #[test]
    fn fold_at_random_r_does_not_zero() {
        let pp = plum_setup(128).unwrap();
        let coeffs = rand_coeffs(64, 0xA000_0021);
        let n = 64usize;
        let omega = pp.u_generator.pow_u128((pp.u_size / n) as u128);
        let evaluations: Vec<Fp192> = (0..n)
            .map(|j| evaluate(&coeffs, &omega.pow_u128(j as u128)))
            .collect();
        let r_fold = fp_from(0xA000_0022);
        let folded = stir_fold(&evaluations, &omega, pp.eta, &r_fold).unwrap();
        // At least one folded coefficient should be nonzero (overwhelming
        // probability — the random r_fold avoids any specific structure).
        assert!(folded.iter().any(|c| !c.is_zero()));
    }

    #[test]
    fn fold_low_degree_polynomial_stays_low_degree() {
        // If f has degree < n/η to begin with, the fold should still
        // have degree < n/η (and in fact deg(fold(f)) ≤ deg(f) / η).
        let pp = plum_setup(128).unwrap();
        let n = 16usize;
        let eta = 4usize;
        let omega = pp.u_generator.pow_u128((pp.u_size / n) as u128);
        // Polynomial of degree < n/η = 4: only first 4 coefficients
        // nonzero.
        let mut coeffs = vec![Fp192::zero(); n];
        let small = rand_coeffs(4, 0xA000_0031);
        for (i, c) in small.iter().enumerate() {
            coeffs[i] = c.clone();
        }
        let evaluations: Vec<Fp192> = (0..n)
            .map(|j| evaluate(&coeffs, &omega.pow_u128(j as u128)))
            .collect();
        let r_fold = fp_from(0xA000_0032);
        let folded = stir_fold(&evaluations, &omega, eta, &r_fold).unwrap();
        assert_eq!(folded.len(), n / eta);
        // Per the standard fold identity, deg(fold(f)) ≤ deg(f)/η. If
        // deg(f) < 4 and η = 4, then deg(fold(f)) < 1 — i.e., fold is a
        // constant. (Coefficients [1..] should be zero.)
        for c in folded.iter().skip(1) {
            assert!(
                c.is_zero(),
                "fold of degree<4 poly should be a constant; index = {:?}",
                c
            );
        }
    }

    #[test]
    fn fold_at_r_zero_picks_even_indexed_coefficients() {
        // (fold f)(y) at α = 0 equals f_0(y) = Σ_k c_{kη} y^k.
        let pp = plum_setup(128).unwrap();
        let n = 16usize;
        let eta = 4usize;
        let omega = pp.u_generator.pow_u128((pp.u_size / n) as u128);
        let coeffs = rand_coeffs(n, 0xA000_0071);
        let evaluations: Vec<Fp192> = (0..n)
            .map(|j| evaluate(&coeffs, &omega.pow_u128(j as u128)))
            .collect();
        let folded = stir_fold(&evaluations, &omega, eta, &Fp192::zero()).unwrap();
        let expected = naive_fold_from_coefficients(&coeffs, eta, &Fp192::zero());
        // expected[k] = c_{kη + 0} = c_{kη}.
        let omega_eta = omega.pow_u128(eta as u128);
        for k in 0..(n / eta) {
            let y = omega_eta.pow_u128(k as u128);
            assert_eq!(evaluate(&folded, &y), evaluate(&expected, &y));
        }
    }

    #[test]
    fn fold_with_eta_one_is_identity_evaluation() {
        // eta = 1 means fold_size = n, each fiber is {ω^k} (singleton),
        // Lagrange returns the constant f(ω^k), evaluating at any
        // r_fold returns f(ω^k). The "folded coefficients" are then
        // IFFT(evaluations) = coefficients of f itself.
        let pp = plum_setup(128).unwrap();
        let n = 8usize;
        let eta = 1usize;
        let omega = pp.u_generator.pow_u128((pp.u_size / n) as u128);
        let coeffs = rand_coeffs(n, 0xA000_0081);
        let evaluations: Vec<Fp192> = (0..n)
            .map(|j| evaluate(&coeffs, &omega.pow_u128(j as u128)))
            .collect();
        let r_fold = fp_from(0xA000_0082);
        let folded = stir_fold(&evaluations, &omega, eta, &r_fold).unwrap();
        assert_eq!(folded.len(), n);
        assert_eq!(folded, coeffs);
    }

    #[test]
    fn rate_correct_matches_lagrange_then_division() {
        // Build â_i randomly, pick a few challenges, set values to
        // â_i evaluated at those challenges, run rate_correct, and
        // verify â_i'(x) · Π(x − α) + b_i(x) = â_i(x).
        let a_i = rand_coeffs(64, 0xB000_0001);
        // Pick |G_i| = 5 challenges: 1 r_out and 4 shifts (matching
        // Alg 5 line 12 where |G_i| = κ + 1; using a small κ here).
        let g_i: Vec<Fp192> = (0..5)
            .map(|s| fp_from(0xB000_0002 + s as u64))
            .collect();
        let values: Vec<Fp192> = g_i.iter().map(|x| evaluate(&a_i, x)).collect();
        let a_prime = rate_correct(&a_i, &g_i, &values).unwrap();
        // deg(â_i') ≤ deg(â_i) − |G_i|
        assert!(a_prime.len() <= a_i.len() - g_i.len() + 1);
        // â_i(α) − b_i(α) = 0 for α ∈ G_i; outside G_i,
        // â_i(x) = â_i'(x) · Π(x − α) + b_i(x).
        let b_i = lagrange_interpolate(&g_i, &values).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0xB000_0003);
        for _ in 0..8 {
            let x = Fp192::rand(&mut rng);
            let lhs = evaluate(&a_i, &x);
            // Compute Π(x − α).
            let mut prod = Fp192::one();
            for alpha in &g_i {
                prod = prod * (x.clone() - alpha.clone());
            }
            let rhs = evaluate(&a_prime, &x) * prod + evaluate(&b_i, &x);
            assert_eq!(lhs, rhs);
        }
    }

    #[test]
    fn rate_correct_with_empty_g_i_is_identity() {
        let a_i = rand_coeffs(8, 0xB000_0010);
        let out = rate_correct(&a_i, &[], &[]).unwrap();
        assert_eq!(out, a_i);
    }

    #[test]
    fn rate_correct_rejects_length_mismatch() {
        let a_i = rand_coeffs(8, 0xB000_0020);
        let g_i = vec![fp_from(0xB000_0021), fp_from(0xB000_0022)];
        let values = vec![fp_from(0xB000_0023)];
        assert!(matches!(
            rate_correct(&a_i, &g_i, &values),
            Err(StirError::RateCorrectLengthMismatch)
        ));
    }

    #[test]
    fn rate_correct_errors_on_non_root_value() {
        // If we lie about â_i(α) — pass a value other than what â_i
        // actually evaluates to — the numerator (â_i − b_i) does NOT
        // vanish at α, so divide_by_linear_product should reject.
        let a_i = rand_coeffs(8, 0xB000_0030);
        let alpha = fp_from(0xB000_0031);
        let true_value = evaluate(&a_i, &alpha);
        // Tamper the value.
        let wrong_value = true_value + Fp192::one();
        let result = rate_correct(&a_i, &[alpha], &[wrong_value]);
        assert!(matches!(
            result,
            Err(StirError::InterpolationError(
                StirPolyError::QuotientRemainderNonZero
            ))
        ));
    }

    #[test]
    fn apply_degree_correction_matches_geometric_series() {
        // f̂_i = â_i' · t_i where t_i(x) = Σ_{j=0..κ+1} r_comb^j · x^j.
        // We verify f̂_i(x) = â_i'(x) · t_i(x) at random points.
        let a_prime = rand_coeffs(20, 0xB000_0040);
        let r_comb = fp_from(0xB000_0041);
        let kappa = 5usize;
        let f_i = apply_degree_correction(&a_prime, &r_comb, kappa);
        assert_eq!(f_i.len(), a_prime.len() + kappa + 1);
        let mut rng = ChaCha20Rng::seed_from_u64(0xB000_0042);
        for _ in 0..8 {
            let x = Fp192::rand(&mut rng);
            let lhs = evaluate(&f_i, &x);
            // t_i(x) directly:
            let mut t_x = Fp192::zero();
            let mut power = Fp192::one();
            for _ in 0..(kappa + 2) {
                t_x = t_x + power.clone();
                power = power * r_comb.clone() * x.clone();
            }
            let rhs = evaluate(&a_prime, &x) * t_x;
            assert_eq!(lhs, rhs);
        }
    }

    #[test]
    fn fold_coefficients_matches_evaluations_fold_on_subgroup() {
        // The two folds — stir_fold (from evaluations) and
        // fold_coefficients (from coefficients) — must produce the
        // same polynomial.
        let pp = plum_setup(128).unwrap();
        let n = 16usize;
        let eta = 4usize;
        let omega = pp.u_generator.pow_u128((pp.u_size / n) as u128);
        let coeffs = rand_coeffs(n, 0xB000_0050);
        let evaluations: Vec<Fp192> = (0..n)
            .map(|j| evaluate(&coeffs, &omega.pow_u128(j as u128)))
            .collect();
        let r_fold = fp_from(0xB000_0051);
        let from_evals = stir_fold(&evaluations, &omega, eta, &r_fold).unwrap();
        let from_coeffs = fold_coefficients(&coeffs, eta, &r_fold);
        // Both should evaluate identically on ⟨ω^η⟩.
        let omega_eta = omega.pow_u128(eta as u128);
        for k in 0..(n / eta) {
            let y = omega_eta.pow_u128(k as u128);
            assert_eq!(evaluate(&from_evals, &y), evaluate(&from_coeffs, &y));
        }
    }

    #[test]
    fn fold_coefficients_handles_non_multiple_length() {
        // Length not divisible by η: the last partial block contributes
        // a shorter geometric sum.
        let coeffs = rand_coeffs(9, 0xB000_0060);
        let eta = 4usize;
        let r_fold = fp_from(0xB000_0061);
        let folded = fold_coefficients(&coeffs, eta, &r_fold);
        assert_eq!(folded.len(), 9usize.div_ceil(eta));
        // Spot-check: out[0] = c_0 + α·c_1 + α²·c_2 + α³·c_3.
        let expected_0 = coeffs[0].clone()
            + r_fold.clone() * coeffs[1].clone()
            + r_fold.clone() * r_fold.clone() * coeffs[2].clone()
            + r_fold.clone() * r_fold.clone() * r_fold.clone() * coeffs[3].clone();
        assert_eq!(folded[0], expected_0);
        // out[2] = c_8 only (since c_9, c_10, c_11 don't exist).
        assert_eq!(folded[2], coeffs[8]);
    }

    #[test]
    fn fold_coefficients_empty_input_returns_empty() {
        let folded = fold_coefficients(&[], 4, &Fp192::one());
        assert!(folded.is_empty());
    }

    #[test]
    fn fold_rejects_non_primitive_generator() {
        // Pass a generator that's NOT a primitive n-th root of unity.
        // E.g., 1 has order 1, not n.
        let evals = rand_coeffs(16, 0xA000_0091);
        let bad_gen = Fp192::one();
        let r_fold = fp_from(0xA000_0092);
        assert!(matches!(
            stir_fold(&evals, &bad_gen, 4, &r_fold),
            Err(StirError::FftError(FftError::GeneratorWrongOrder))
        ));
    }

    #[test]
    fn fold_rejects_non_power_of_two() {
        let evals = rand_coeffs(15, 0xA000_0041);
        let omega = Fp192::one();
        let r_fold = Fp192::zero();
        assert!(matches!(
            stir_fold(&evals, &omega, 4, &r_fold),
            Err(StirError::DomainNotPowerOfTwo)
        ));
    }

    #[test]
    fn fold_rejects_eta_not_dividing() {
        let evals = rand_coeffs(16, 0xA000_0051);
        let omega = fp_from(0xA000_0052);
        let r_fold = fp_from(0xA000_0053);
        assert!(matches!(
            stir_fold(&evals, &omega, 3, &r_fold),
            Err(StirError::EtaDoesNotDivideDomain)
        ));
    }

    #[test]
    fn fold_is_linear_in_r_fold_for_eta_2_oracle() {
        // For η = 2 the fold should satisfy fold_r(f) = f_even + r ·
        // f_odd where f(x) = f_even(x²) + x · f_odd(x²). We check that
        // (fold_r1 + fold_r2) on the same input matches fold computed
        // at r1 + r2 — this is a sanity check on the linearity in
        // r_fold of the fold operator.
        let pp = plum_setup(128).unwrap();
        let n = 16usize;
        let eta = 2usize;
        let omega = pp.u_generator.pow_u128((pp.u_size / n) as u128);
        let coeffs = rand_coeffs(n, 0xA000_0061);
        let evaluations: Vec<Fp192> = (0..n)
            .map(|j| evaluate(&coeffs, &omega.pow_u128(j as u128)))
            .collect();
        let r_a = fp_from(0xA000_0062);
        let r_b = fp_from(0xA000_0063);
        let fold_a = stir_fold(&evaluations, &omega, eta, &r_a).unwrap();
        let fold_b = stir_fold(&evaluations, &omega, eta, &r_b).unwrap();
        // f_even, f_odd come from the decomposition; fold_a − f_even
        // should be r_a · f_odd, hence (fold_a − fold_b) / (r_a − r_b)
        // should equal f_odd. We don't reconstruct f_even/f_odd here;
        // we just check that fold_a − fold_b = (r_a − r_b) · f_odd is
        // *some* polynomial, and that its value at random points is
        // consistent.
        let r_diff = r_a.clone() - r_b.clone();
        let r_diff_inv = r_diff.inverse().unwrap();
        let mut f_odd: Vec<Fp192> = fold_a
            .iter()
            .zip(fold_b.iter())
            .map(|(a, b)| (a.clone() - b.clone()) * r_diff_inv.clone())
            .collect();
        // f_odd should equal the odd part of f, i.e., coefficients
        // c_1, c_3, c_5, ... of the original polynomial.
        let expected_odd: Vec<Fp192> =
            coeffs.iter().enumerate().filter_map(|(i, c)| if i % 2 == 1 { Some(c.clone()) } else { None }).collect();
        // f_odd may have trailing zeros where coeffs ran out; trim.
        while f_odd.last().map_or(false, |c| c.is_zero()) {
            f_odd.pop();
        }
        assert_eq!(f_odd, expected_odd);
    }
}
