//! STIR-specific polynomial primitives.
//!
//! Phase 5 of `spec/plum_implementation_plan.md`. PLUM's STIR low-degree
//! test (Algorithm 5, paper p. 121) uses four polynomial operations that
//! the BCRSVW univariate-sumcheck primitives in `sumcheck.rs` do not
//! provide:
//!
//!   - **Lagrange interpolation on small fibers** (line 6 of Alg 5):
//!     `Interpolate(S_y, f̂_{i-1}|_{S_y})` for `|S_y| = η`. We do this
//!     once per `y ∈ U_{i-1}^η`, so |U_{i-1}|/η times per STIR round.
//!     At PLUM-128 (η = 4, |U_0| = 2¹²) that's 1024 four-point
//!     interpolations per round. The same primitive is also reused at
//!     the larger size |U_R| ≈ d_stop = 32 in Algorithm 5 line 14 when
//!     the prover interpolates the final-round `coefs` of `f̂_{R+1}`.
//!   - **Schoolbook polynomial multiplication** (line 13 of Alg 5):
//!     `f̂_i = â_i' · t_i`. Per-round inputs are bounded by
//!     `deg(â_i') ≤ d_{i-1} − |G_i|` and `deg(t_i) = κ_i + 1`; both
//!     stay well within field-arithmetic limits.
//!   - **Quotient by a product of linear factors** (line 12 of Alg 5):
//!     `â_i'(x) := (â_i(x) − b_i(x)) / Π_{α ∈ G_i}(x − α)`. Since the
//!     numerator vanishes at every `α ∈ G_i` by construction, the
//!     quotient is exact. We use Ruffini / Horner-style synthetic
//!     division applied once per root.
//!   - **Degree-correction polynomial `t_i`** (line 13 of Alg 5):
//!     `t_i(x) = (1 − (r·x)^{κ+2}) / (1 − r·x)`. The rational form is
//!     the geometric-series identity, so as a polynomial,
//!     `t_i(x) = Σ_{j=0}^{κ+1} r^j · x^j`. We materialise it in
//!     coefficient form.
//!
//! Polynomials are represented as `Vec<Fp192>` in ascending-degree
//! order (`coeffs[i]` is the coefficient of `x^i`). Empty vectors
//! represent the zero polynomial.

use super::field_p192::Fp192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StirPolyError {
    InterpolationDomainNotDistinct,
    InterpolationLengthMismatch,
    QuotientRemainderNonZero,
}

impl core::fmt::Display for StirPolyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InterpolationDomainNotDistinct => write!(
                f,
                "Lagrange interpolation requires distinct domain points"
            ),
            Self::InterpolationLengthMismatch => {
                write!(f, "Lagrange points and values must have the same length")
            }
            Self::QuotientRemainderNonZero => write!(
                f,
                "polynomial does not vanish at the supplied root; division is not exact"
            ),
        }
    }
}

impl std::error::Error for StirPolyError {}

/// Evaluate `coeffs` at `x` via Horner's method.
pub fn evaluate(coeffs: &[Fp192], x: &Fp192) -> Fp192 {
    let mut acc = Fp192::zero();
    for coeff in coeffs.iter().rev() {
        acc = acc * x.clone() + coeff.clone();
    }
    acc
}

/// Schoolbook polynomial multiplication. `O(deg(a) · deg(b))`. PLUM's
/// STIR call sites have `deg(a), deg(b) < d_stop = 32` per Algorithm 5,
/// so quadratic cost is acceptable.
///
/// Side-channel note: the `ai.is_zero()` short-circuit makes this
/// variable-time on input sparsity. PLUM-style inputs (`â_i'`, `t_i`)
/// are dense in expectation so the leak is negligible in practice, but
/// when `field_p192.rs` is migrated to a constant-time backend in
/// Phase 1.5, either remove this short-circuit or accept the residual
/// sparsity leak. Tracked as a non-blocking item.
pub fn multiply(a: &[Fp192], b: &[Fp192]) -> Vec<Fp192> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![Fp192::zero(); a.len() + b.len() - 1];
    for (i, ai) in a.iter().enumerate() {
        if ai.is_zero() {
            continue;
        }
        for (j, bj) in b.iter().enumerate() {
            out[i + j] = out[i + j].clone() + ai.clone() * bj.clone();
        }
    }
    out
}

/// Lagrange interpolation through the points `(domain[i], values[i])`.
/// Returns the unique polynomial of degree `< n` (where `n = domain.len()`)
/// passing through all points, in coefficient form.
///
/// Implementation: `L(x) = Σ_i values[i] · l_i(x)`, where
/// `l_i(x) = Π_{j ≠ i} (x − domain[j]) / (domain[i] − domain[j])`. Builds
/// each `l_i` explicitly in coefficient form via repeated multiplication
/// by `(x − domain[j])`, scales by the inverse of the product of
/// denominators, and accumulates `values[i] · l_i`. `O(n²)` total work.
/// For PLUM-128's `n = η = 4` this is trivial.
pub fn lagrange_interpolate(
    domain: &[Fp192],
    values: &[Fp192],
) -> Result<Vec<Fp192>, StirPolyError> {
    if domain.len() != values.len() {
        return Err(StirPolyError::InterpolationLengthMismatch);
    }
    if domain.is_empty() {
        return Ok(Vec::new());
    }
    let n = domain.len();
    // Check domain elements are distinct. O(n²) — fine for small n.
    for i in 0..n {
        for j in (i + 1)..n {
            if domain[i] == domain[j] {
                return Err(StirPolyError::InterpolationDomainNotDistinct);
            }
        }
    }

    let mut result = vec![Fp192::zero(); n];
    for i in 0..n {
        // Build the unnormalised basis polynomial l_i^unscaled(x) =
        // Π_{j ≠ i} (x − domain[j]). Start from the constant 1.
        let mut basis = vec![Fp192::one()];
        let mut denom = Fp192::one();
        for (j, dj) in domain.iter().enumerate() {
            if j == i {
                continue;
            }
            // Multiply basis by (x − dj). basis is a polynomial; this
            // is a (degree+1)-shift + subtraction of dj * basis.
            let mut next = vec![Fp192::zero(); basis.len() + 1];
            for (k, bk) in basis.iter().enumerate() {
                next[k] = next[k].clone() - dj.clone() * bk.clone();
                next[k + 1] = next[k + 1].clone() + bk.clone();
            }
            basis = next;
            // Accumulate (domain[i] − domain[j]) into the denominator.
            denom = denom * (domain[i].clone() - dj.clone());
        }
        // l_i(x) = basis(x) / denom; scale by values[i] and add to result.
        let inv_denom = denom
            .inverse()
            .expect("denom is a product of non-zero differences; cannot be zero");
        let scale = values[i].clone() * inv_denom;
        for (k, bk) in basis.iter().enumerate() {
            result[k] = result[k].clone() + scale.clone() * bk.clone();
        }
    }
    Ok(result)
}

/// Synthetic division of `coeffs` (a polynomial) by `(x − root)`. The
/// caller must have established that `evaluate(coeffs, &root) = 0`; if
/// the remainder is non-zero this function returns
/// `QuotientRemainderNonZero`.
///
/// Returns the quotient `q(x)` of degree `deg(coeffs) − 1`. Empty input
/// gives empty output. Constant non-zero input is an error (cannot be
/// divisible by `(x − root)`).
pub fn divide_by_linear(coeffs: &[Fp192], root: &Fp192) -> Result<Vec<Fp192>, StirPolyError> {
    if coeffs.is_empty() {
        return Ok(Vec::new());
    }
    // For a polynomial p(x) = Σ c_i x^i with p(root) = 0, the quotient
    // q(x) = Σ q_i x^i with q_{n−1} = c_n, q_{i} = c_{i+1} + root · q_{i+1}
    // (Ruffini). After the loop the remainder lives in c_0 + root · q_0;
    // we verify it's zero before returning.
    let n = coeffs.len();
    if n == 1 {
        if coeffs[0].is_zero() {
            return Ok(Vec::new());
        } else {
            return Err(StirPolyError::QuotientRemainderNonZero);
        }
    }
    let mut quotient = vec![Fp192::zero(); n - 1];
    quotient[n - 2] = coeffs[n - 1].clone();
    for i in (0..(n - 2)).rev() {
        quotient[i] = coeffs[i + 1].clone() + root.clone() * quotient[i + 1].clone();
    }
    let remainder = coeffs[0].clone() + root.clone() * quotient[0].clone();
    if !remainder.is_zero() {
        return Err(StirPolyError::QuotientRemainderNonZero);
    }
    Ok(quotient)
}

/// Divide `coeffs` by `Π_{α ∈ roots} (x − α)`. Returns the quotient.
/// Errors if the numerator does not vanish at every supplied root
/// (i.e., the division is not exact). Repeated `divide_by_linear`
/// applied in order; each call shrinks the degree by 1.
pub fn divide_by_linear_product(
    coeffs: &[Fp192],
    roots: &[Fp192],
) -> Result<Vec<Fp192>, StirPolyError> {
    let mut current = coeffs.to_vec();
    for root in roots {
        current = divide_by_linear(&current, root)?;
    }
    Ok(current)
}

/// Build `t_i(x)` in coefficient form. Per Algorithm 5 line 13,
///
///     t_i(x) = (1 − (r·x)^{κ+2}) / (1 − r·x)
///
/// for `r·x ≠ 1`, with the limit value `κ+2` at the removable
/// singularity `r·x = 1`. The geometric-series identity collapses this
/// rational expression to the polynomial
///
///     t_i(x) = Σ_{j=0}^{κ+1} r^j · x^j.
///
/// Returns the coefficient vector `[1, r, r², …, r^{κ+1}]`, of length
/// `κ + 2`.
pub fn degree_correction_polynomial(r_comb: &Fp192, kappa: usize) -> Vec<Fp192> {
    let len = kappa + 2;
    let mut coeffs = Vec::with_capacity(len);
    let mut power = Fp192::one();
    for _ in 0..len {
        coeffs.push(power.clone());
        power = power * r_comb.clone();
    }
    coeffs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::plum::setup::plum_setup;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rand_coeffs(n: usize, seed: u64) -> Vec<Fp192> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..n).map(|_| Fp192::rand(&mut rng)).collect()
    }

    fn rand_points(n: usize, seed: u64) -> Vec<Fp192> {
        // Sample n distinct random non-zero field elements. Collisions
        // happen with probability ~n²/|F|, negligible for n ≤ 32.
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let candidate = Fp192::rand(&mut rng);
            if !candidate.is_zero() && !out.contains(&candidate) {
                out.push(candidate);
            }
        }
        out
    }

    #[test]
    fn evaluate_constant() {
        let c = Fp192::from_u64(7);
        let coeffs = vec![c.clone()];
        assert_eq!(evaluate(&coeffs, &Fp192::from_u64(42)), c);
        assert_eq!(evaluate(&coeffs, &Fp192::zero()), c);
    }

    #[test]
    fn evaluate_x_squared_plus_one() {
        // p(x) = 1 + x²; check at x = 3 ⇒ 10.
        let coeffs = vec![Fp192::from_u64(1), Fp192::zero(), Fp192::from_u64(1)];
        assert_eq!(
            evaluate(&coeffs, &Fp192::from_u64(3)),
            Fp192::from_u64(10)
        );
    }

    #[test]
    fn multiply_commutative() {
        let a = rand_coeffs(8, 0x9000_0001);
        let b = rand_coeffs(5, 0x9000_0002);
        let ab = multiply(&a, &b);
        let ba = multiply(&b, &a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn multiply_matches_pointwise() {
        let a = rand_coeffs(6, 0x9000_0003);
        let b = rand_coeffs(4, 0x9000_0004);
        let product = multiply(&a, &b);
        // (a·b)(x) should equal a(x)·b(x) at random x.
        let mut rng = ChaCha20Rng::seed_from_u64(0x9000_0004_CC);
        for _ in 0..16 {
            let x = Fp192::rand(&mut rng);
            assert_eq!(evaluate(&product, &x), evaluate(&a, &x) * evaluate(&b, &x));
        }
    }

    #[test]
    fn multiply_zero_polynomial() {
        let a = rand_coeffs(5, 0x9000_0005);
        let zero: Vec<Fp192> = Vec::new();
        assert_eq!(multiply(&a, &zero), Vec::<Fp192>::new());
        assert_eq!(multiply(&zero, &a), Vec::<Fp192>::new());
    }

    #[test]
    fn lagrange_interpolates_constant() {
        let domain = rand_points(4, 0x9000_0011);
        let c = Fp192::from_u64(42);
        let values = vec![c.clone(); 4];
        let coeffs = lagrange_interpolate(&domain, &values).unwrap();
        // Should be the polynomial p(x) = 42 with trailing zeros.
        assert!(coeffs.len() <= 4);
        for x in &domain {
            assert_eq!(evaluate(&coeffs, x), c);
        }
    }

    #[test]
    fn lagrange_interpolates_random_polynomial() {
        // Pick a random poly of degree 3, evaluate at 4 distinct
        // points, then interpolate. Should recover the original.
        let original = rand_coeffs(4, 0x9000_0012);
        let domain = rand_points(4, 0x9000_0013);
        let values: Vec<Fp192> = domain.iter().map(|x| evaluate(&original, x)).collect();
        let recovered = lagrange_interpolate(&domain, &values).unwrap();
        // Recovered may have leading zeros if the original had a zero
        // top coefficient; compare via evaluation at fresh points.
        let mut rng = ChaCha20Rng::seed_from_u64(0x9000_0013_BB);
        for _ in 0..8 {
            let x = Fp192::rand(&mut rng);
            assert_eq!(evaluate(&recovered, &x), evaluate(&original, &x));
        }
    }

    #[test]
    fn lagrange_at_eta_4_for_stir_fiber() {
        // Simulate one STIR fiber: |S_y| = η = 4, polynomial of degree
        // < 4, recover it exactly.
        let original = rand_coeffs(4, 0x9000_0014);
        let domain = rand_points(4, 0x9000_0015);
        let values: Vec<Fp192> = domain.iter().map(|x| evaluate(&original, x)).collect();
        let recovered = lagrange_interpolate(&domain, &values).unwrap();
        for x in &domain {
            assert_eq!(evaluate(&recovered, x), evaluate(&original, x));
        }
    }

    #[test]
    fn lagrange_rejects_repeated_domain() {
        let mut domain = rand_points(3, 0x9000_0016);
        domain.push(domain[0].clone());
        let values = rand_coeffs(4, 0x9000_0017);
        assert!(matches!(
            lagrange_interpolate(&domain, &values),
            Err(StirPolyError::InterpolationDomainNotDistinct)
        ));
    }

    #[test]
    fn lagrange_rejects_length_mismatch() {
        let domain = rand_points(4, 0x9000_0018);
        let values = rand_coeffs(3, 0x9000_0019);
        assert!(matches!(
            lagrange_interpolate(&domain, &values),
            Err(StirPolyError::InterpolationLengthMismatch)
        ));
    }

    #[test]
    fn divide_by_linear_returns_correct_quotient() {
        // f(x) = (x − 5) · (x² + 3) = x³ − 5x² + 3x − 15.
        // After dividing by (x − 5) we should get x² + 3.
        let f = vec![
            Fp192::zero() - Fp192::from_u64(15),
            Fp192::from_u64(3),
            Fp192::zero() - Fp192::from_u64(5),
            Fp192::one(),
        ];
        let quotient = divide_by_linear(&f, &Fp192::from_u64(5)).unwrap();
        let expected = vec![Fp192::from_u64(3), Fp192::zero(), Fp192::one()];
        assert_eq!(quotient, expected);
    }

    #[test]
    fn divide_by_linear_rejects_non_root() {
        // f(x) = x + 1; dividing by (x − 7) is not exact (f(7) = 8).
        let f = vec![Fp192::one(), Fp192::one()];
        assert!(matches!(
            divide_by_linear(&f, &Fp192::from_u64(7)),
            Err(StirPolyError::QuotientRemainderNonZero)
        ));
    }

    #[test]
    fn divide_by_linear_product_matches_polynomial_division() {
        // Build f = (x − r_1)(x − r_2)(x − r_3) · q(x) where q is random,
        // then verify divide_by_linear_product(f, {r_1, r_2, r_3}) = q.
        let q = rand_coeffs(5, 0x9000_0021);
        let roots = rand_points(3, 0x9000_0022);
        let mut f = q.clone();
        for r in &roots {
            // Multiply f by (x − r).
            let mut next = vec![Fp192::zero(); f.len() + 1];
            for (k, fk) in f.iter().enumerate() {
                next[k] = next[k].clone() - r.clone() * fk.clone();
                next[k + 1] = next[k + 1].clone() + fk.clone();
            }
            f = next;
        }
        let recovered = divide_by_linear_product(&f, &roots).unwrap();
        // q may have leading zeros stripped vs recovered; compare via
        // evaluation at random points.
        let mut rng = ChaCha20Rng::seed_from_u64(0x9000_0023);
        for _ in 0..8 {
            let x = Fp192::rand(&mut rng);
            assert_eq!(evaluate(&recovered, &x), evaluate(&q, &x));
        }
    }

    #[test]
    fn divide_by_linear_product_rejects_non_root_set() {
        // Build f that vanishes at r_1, r_2 but not r_3.
        let q = rand_coeffs(4, 0x9000_0024);
        let valid_roots = rand_points(2, 0x9000_0025);
        let mut f = q.clone();
        for r in &valid_roots {
            let mut next = vec![Fp192::zero(); f.len() + 1];
            for (k, fk) in f.iter().enumerate() {
                next[k] = next[k].clone() - r.clone() * fk.clone();
                next[k + 1] = next[k + 1].clone() + fk.clone();
            }
            f = next;
        }
        // Append a wrong root.
        let mut roots = valid_roots.clone();
        roots.push(Fp192::from_u64(0xDEADBEEF));
        assert!(matches!(
            divide_by_linear_product(&f, &roots),
            Err(StirPolyError::QuotientRemainderNonZero)
        ));
    }

    #[test]
    fn degree_correction_polynomial_matches_rational_form() {
        // Build t_i for r = 3, κ = 5 (κ+2 = 7 coefficients).
        // Verify at random x ≠ 1/r that the polynomial form matches
        // the rational form.
        let r = Fp192::from_u64(3);
        let kappa = 5;
        let t = degree_correction_polynomial(&r, kappa);
        assert_eq!(t.len(), kappa + 2);
        // Coefficients should be 1, r, r², …, r^{κ+1}.
        let mut expected_power = Fp192::one();
        for c in &t {
            assert_eq!(*c, expected_power);
            expected_power = expected_power * r.clone();
        }
        // Evaluation check against the rational form: at x = 5 (so r·x
        // = 15 ≠ 1), the value should be (1 − 15^{κ+2}) / (1 − 15).
        let x = Fp192::from_u64(5);
        let rx = r.clone() * x.clone();
        let rx_pow = rx.pow_u128((kappa + 2) as u128);
        let expected =
            (Fp192::one() - rx_pow) * (Fp192::one() - rx).inverse().unwrap();
        assert_eq!(evaluate(&t, &x), expected);
    }

    #[test]
    fn degree_correction_at_singularity_evaluates_to_kappa_plus_2() {
        // The polynomial form should give the correct limit value at
        // x = 1/r where the rational form has a removable singularity.
        let r = Fp192::from_u64(11);
        let kappa = 7;
        let t = degree_correction_polynomial(&r, kappa);
        let x = r.inverse().unwrap(); // r·x = 1.
        let expected = Fp192::from_u64((kappa + 2) as u64);
        assert_eq!(evaluate(&t, &x), expected);
    }

    #[test]
    fn lagrange_at_stir_fiber_in_production_domain() {
        // Use a real STIR fiber: 4 distinct points from U_0 = ⟨ω_U⟩.
        // Pick 4 consecutive elements (well, all elements with the
        // same x^η = y).
        let pp = plum_setup(128).unwrap();
        // Build the η-th-power-equal coset: pick x_0 = 1, then x_k =
        // x_0 · ζ_η^k where ζ_η is an η-th root of unity in F_p.
        // ζ_η = ω_U^{|U_0|/η}.
        let eta = pp.eta;
        let zeta = pp.u_generator.pow_u128((pp.u_size / eta) as u128);
        let mut fiber = vec![Fp192::one()];
        let mut cur = Fp192::one();
        for _ in 1..eta {
            cur = cur * zeta.clone();
            fiber.push(cur.clone());
        }
        assert_eq!(fiber.len(), eta);
        // Sanity: every element of the fiber raised to η is the same.
        let target = fiber[0].pow_u128(eta as u128);
        for x in &fiber {
            assert_eq!(x.pow_u128(eta as u128), target);
        }
        // Interpolate a random polynomial of degree < η through the
        // fiber.
        let p = rand_coeffs(eta, 0x9000_0030);
        let values: Vec<Fp192> = fiber.iter().map(|x| evaluate(&p, x)).collect();
        let recovered = lagrange_interpolate(&fiber, &values).unwrap();
        for x in &fiber {
            assert_eq!(evaluate(&recovered, x), evaluate(&p, x));
        }
    }
}
