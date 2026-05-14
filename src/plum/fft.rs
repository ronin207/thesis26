//! Coset FFT / IFFT over `Fp192`.
//!
//! Mirrors `src/loquat/fft.rs` but operates directly on `Fp192` instead of
//! the `F_p²` extension Loquat uses. Cooley-Tukey radix-2 butterfly, in
//! place, bit-reversed input.
//!
//! Used by `plum::sumcheck` to switch between coefficient form and
//! evaluations on the sumcheck domain `H` (a small multiplicative coset of
//! size `2m`, `m = 4` at λ=128) and on the STIR code domain `U` (a larger
//! multiplicative coset of size `2¹²`). Both domains are inside the
//! `2^64`-order smooth subgroup `F_p^* / ⟨g^((p-1)/2^64)⟩`, which the
//! `Fp192` modulus is chosen specifically to make large.

use super::field_p192::Fp192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FftError {
    NonPowerOfTwoLength,
    EmptyDomain,
    GeneratorWrongOrder,
    ShiftNotInvertible,
    LengthInverseFailed,
}

impl core::fmt::Display for FftError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonPowerOfTwoLength => write!(f, "FFT length must be a power of two"),
            Self::EmptyDomain => write!(f, "FFT length must be > 0"),
            Self::GeneratorWrongOrder => {
                write!(f, "generator does not have order equal to FFT length")
            }
            Self::ShiftNotInvertible => write!(f, "coset shift must be invertible"),
            Self::LengthInverseFailed => write!(f, "length has no inverse in F_p"),
        }
    }
}

impl std::error::Error for FftError {}

fn check_power_of_two(len: usize) -> Result<(), FftError> {
    if len == 0 {
        return Err(FftError::EmptyDomain);
    }
    if !len.is_power_of_two() {
        return Err(FftError::NonPowerOfTwoLength);
    }
    Ok(())
}

fn check_generator(generator: &Fp192, domain_size: usize) -> Result<(), FftError> {
    let n = domain_size as u128;
    if generator.pow_u128(n) != Fp192::one() {
        return Err(FftError::GeneratorWrongOrder);
    }
    if domain_size > 1 && generator.pow_u128(n / 2) == Fp192::one() {
        return Err(FftError::GeneratorWrongOrder);
    }
    Ok(())
}

fn bit_reverse_permutation(values: &mut [Fp192]) {
    let n = values.len();
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            values.swap(i, j);
        }
    }
}

/// In-place radix-2 Cooley-Tukey FFT.
///
/// Input is interpreted as coefficients of a polynomial of degree less
/// than `values.len()`; output is its evaluations at `1, root, root², …,
/// root^{n-1}`. `root` must be a primitive `n`-th root of unity.
pub fn fft_in_place(values: &mut [Fp192], root: &Fp192) -> Result<(), FftError> {
    check_power_of_two(values.len())?;
    check_generator(root, values.len())?;

    bit_reverse_permutation(values);

    let n = values.len();
    let mut len = 2;
    while len <= n {
        let step = n / len;
        let w_len = root.pow_u128(step as u128);
        for i in (0..n).step_by(len) {
            let mut w = Fp192::one();
            let half = len / 2;
            for j in 0..half {
                let u = values[i + j].clone();
                let t = values[i + j + half].clone() * w.clone();
                values[i + j] = u.clone() + t.clone();
                values[i + j + half] = u - t;
                w *= w_len.clone();
            }
        }
        len <<= 1;
    }
    Ok(())
}

/// In-place inverse FFT. Inverse of `fft_in_place` modulo the standard
/// scaling: applying `fft_in_place(.., root)` then `ifft_in_place(..,
/// root)` yields the identity (up to `Vec` allocation differences).
pub fn ifft_in_place(values: &mut [Fp192], root: &Fp192) -> Result<(), FftError> {
    check_power_of_two(values.len())?;
    let inv_root = root.inverse().ok_or(FftError::ShiftNotInvertible)?;
    fft_in_place(values, &inv_root)?;

    let n = values.len() as u64;
    let inv_n = Fp192::from_u64(n)
        .inverse()
        .ok_or(FftError::LengthInverseFailed)?;
    for value in values.iter_mut() {
        *value *= inv_n.clone();
    }
    Ok(())
}

/// Evaluate the polynomial whose coefficients are `coeffs` at every point
/// of the multiplicative coset `c · ⟨ω⟩ = (c, c·ω, c·ω², …, c·ω^{n-1})`,
/// where `c = shift`, `ω = generator`, `n = coeffs.len()`.
///
/// Implementation: scale `coeffs[i] ← coeffs[i] · c^i` and FFT.
/// Justification: `f(c·ω^k) = Σ_i coeffs[i] · c^i · ω^{ki}` is exactly
/// the FFT of `coeffs[i] · c^i`.
pub fn evaluate_on_coset(
    coeffs: &[Fp192],
    shift: &Fp192,
    generator: &Fp192,
) -> Result<Vec<Fp192>, FftError> {
    if coeffs.is_empty() {
        return Ok(Vec::new());
    }
    check_power_of_two(coeffs.len())?;
    check_generator(generator, coeffs.len())?;
    if shift.is_zero() {
        return Err(FftError::ShiftNotInvertible);
    }

    let mut scaled = coeffs.to_vec();
    let mut shift_power = Fp192::one();
    for coeff in scaled.iter_mut() {
        *coeff = coeff.clone() * shift_power.clone();
        shift_power = shift_power * shift.clone();
    }
    fft_in_place(&mut scaled, generator)?;
    Ok(scaled)
}

/// Inverse of `evaluate_on_coset`: given evaluations of a polynomial of
/// degree less than `n` on the coset `c · ⟨ω⟩`, recover its `n`
/// coefficients.
pub fn interpolate_on_coset(
    evaluations: &[Fp192],
    shift: &Fp192,
    generator: &Fp192,
) -> Result<Vec<Fp192>, FftError> {
    if evaluations.is_empty() {
        return Ok(Vec::new());
    }
    check_power_of_two(evaluations.len())?;
    check_generator(generator, evaluations.len())?;
    let inv_shift = shift.inverse().ok_or(FftError::ShiftNotInvertible)?;

    let mut spectrum = evaluations.to_vec();
    ifft_in_place(&mut spectrum, generator)?;

    let mut coeffs = Vec::with_capacity(spectrum.len());
    let mut power = Fp192::one();
    for val in spectrum.into_iter() {
        coeffs.push(val * power.clone());
        power = power * inv_shift.clone();
    }
    Ok(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plum::setup::plum_setup;

    fn naive_evaluate(coeffs: &[Fp192], point: &Fp192) -> Fp192 {
        // Horner.
        let mut acc = Fp192::zero();
        for coeff in coeffs.iter().rev() {
            acc = acc * point.clone() + coeff.clone();
        }
        acc
    }

    fn random_coeffs(n: usize, seed: u64) -> Vec<Fp192> {
        use rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..n).map(|_| Fp192::rand(&mut rng)).collect()
    }

    fn small_coset_params() -> (Fp192, Fp192, usize) {
        // Use a tiny synthetic domain for fast unit tests: take a
        // primitive 8-th root of unity by lifting ω_H (order 2m = 8 at
        // λ=128) from the production setup; use shift = 1 so the coset
        // is the subgroup itself.
        let pp = plum_setup(128).expect("setup");
        (pp.h_generator.clone(), Fp192::one(), pp.h_size)
    }

    #[test]
    fn fft_matches_naive_evaluations_on_subgroup() {
        let (omega, shift, n) = small_coset_params();
        let coeffs = random_coeffs(n, 0x7000_1111);
        let fft_evals = evaluate_on_coset(&coeffs, &shift, &omega).expect("fft eval");
        // Build the explicit domain to verify against naive Horner.
        let mut point = shift.clone();
        for evaluation in fft_evals.iter() {
            let expected = naive_evaluate(&coeffs, &point);
            assert_eq!(*evaluation, expected);
            point = point * omega.clone();
        }
    }

    #[test]
    fn fft_ifft_roundtrip_on_subgroup() {
        let (omega, shift, n) = small_coset_params();
        let coeffs = random_coeffs(n, 0x7000_2222);
        let values = evaluate_on_coset(&coeffs, &shift, &omega).expect("forward fft");
        let recovered = interpolate_on_coset(&values, &shift, &omega).expect("inverse fft");
        assert_eq!(coeffs, recovered);
    }

    #[test]
    fn fft_ifft_roundtrip_on_proper_coset() {
        // Use the production sumcheck coset H = h_shift · ⟨h_generator⟩
        // (size 2m = 8 at λ=128) to exercise the non-trivial shift path.
        let pp = plum_setup(128).unwrap();
        let coeffs = random_coeffs(pp.h_size, 0x7000_3333);
        let values =
            evaluate_on_coset(&coeffs, &pp.h_shift, &pp.h_generator).expect("forward fft");
        let recovered =
            interpolate_on_coset(&values, &pp.h_shift, &pp.h_generator).expect("inverse fft");
        assert_eq!(coeffs, recovered);
    }

    #[test]
    fn coset_evaluations_match_naive_on_proper_coset() {
        let pp = plum_setup(128).unwrap();
        let coeffs = random_coeffs(pp.h_size, 0x7000_4444);
        let values =
            evaluate_on_coset(&coeffs, &pp.h_shift, &pp.h_generator).expect("forward fft");
        let mut point = pp.h_shift.clone();
        for evaluation in values.iter() {
            assert_eq!(*evaluation, naive_evaluate(&coeffs, &point));
            point = point * pp.h_generator.clone();
        }
    }

    #[test]
    fn constant_polynomial_evaluates_constantly() {
        let (omega, shift, n) = small_coset_params();
        let mut coeffs = vec![Fp192::zero(); n];
        let c = Fp192::from_u64(42);
        coeffs[0] = c.clone();
        let values = evaluate_on_coset(&coeffs, &shift, &omega).expect("fft");
        for v in &values {
            assert_eq!(*v, c);
        }
    }

    #[test]
    fn fft_rejects_non_power_of_two_length() {
        let (omega, shift, _n) = small_coset_params();
        let coeffs = random_coeffs(3, 0x7000_5555);
        assert!(matches!(
            evaluate_on_coset(&coeffs, &shift, &omega),
            Err(FftError::NonPowerOfTwoLength)
        ));
    }

    #[test]
    fn fft_rejects_generator_of_wrong_order() {
        let (_omega, shift, n) = small_coset_params();
        // Use 1 — which trivially has order 1, not n.
        let bad_root = Fp192::one();
        let coeffs = random_coeffs(n, 0x7000_6666);
        assert!(matches!(
            evaluate_on_coset(&coeffs, &shift, &bad_root),
            Err(FftError::GeneratorWrongOrder)
        ));
    }

    #[test]
    fn larger_domain_works() {
        // Step up to the STIR code domain |U| = 4096 at λ=128 to
        // exercise the FFT on its production-sized input.
        let pp = plum_setup(128).unwrap();
        assert_eq!(pp.u_size, 4096);
        let coeffs = random_coeffs(pp.u_size, 0x7000_7777);
        let values = evaluate_on_coset(&coeffs, &Fp192::one(), &pp.u_generator)
            .expect("fft on |U|=4096");
        let recovered =
            interpolate_on_coset(&values, &Fp192::one(), &pp.u_generator).expect("ifft");
        assert_eq!(coeffs, recovered);
    }
}
