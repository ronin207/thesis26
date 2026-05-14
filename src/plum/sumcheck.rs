//! Univariate sumcheck primitives over `Fp192`.
//!
//! PLUM's sumcheck (Algorithm 4 Phase 4, Zhang et al. ProvSec 2025 p. 120)
//! is the BCRSVW univariate-sumcheck construction: given a polynomial
//! `f̂(x) ∈ F_p[x]` and a multiplicative coset `H = c · ⟨ω⟩ ⊂ F_p^*` of
//! size `n`, the prover wants to convince the verifier that
//! `S = Σ_{a ∈ H} f̂(a)`. The trick is to write `f̂` uniquely as
//!
//!     f̂(x) = ĝ(x) + Z_H(x) · ĥ(x),    deg(ĝ) < n,
//!
//! where `Z_H(x) = x^n − c^n` is the vanishing polynomial of `H`. The
//! verifier checks (i) the division identity at a random STIR challenge
//! point and (ii) `S = n · ĝ_0(c)` where `ĝ_0(c)` is the constant
//! coefficient of `ĝ(cx)` (equivalently, the `H`-sum of `ĝ` is
//! determined by its bottom `n` coefficients).
//!
//! This module provides the three primitives PLUM's `Sign` / `Verify`
//! need:
//!
//!   - [`vanishing_poly_evaluate`] — `Z_H(x)` at an arbitrary point.
//!   - [`sum_over_coset`] — `Σ_{a ∈ H} f(a)` from coefficient form.
//!   - [`decompose`] — produce `(ĝ, ĥ)` such that `f = ĝ + Z_H · ĥ`.
//!
//! The protocol scaffolding (transcript binding, STIR challenge sampling,
//! Merkle commits of `ĥ|_U`) belongs in `sign` / `verify`; this module is
//! deliberately just the polynomial layer.

use super::field_p192::Fp192;

/// Evaluate `Z_H(x) = x^|H| − shift^|H|` at the point `x`.
///
/// `H = shift · ⟨ω⟩` of size `domain_size`. Two algebraic facts:
///
///   - `Z_H(x) = Π_{a ∈ H}(x − a)` — degree-`|H|` polynomial vanishing
///     exactly on `H`.
///   - The product simplifies to `x^|H| − shift^|H|` because
///     `Π_{a ∈ ⟨ω⟩}(y − a) = y^|H| − 1` for any primitive `|H|`-th
///     root of unity `ω` (so substituting `y = x/shift` and clearing
///     denominators gives the closed form).
pub fn vanishing_poly_evaluate(domain_size: usize, shift: &Fp192, x: &Fp192) -> Fp192 {
    let n = domain_size as u128;
    x.pow_u128(n) - shift.pow_u128(n)
}

/// `Σ_{a ∈ H} f(a)` for `H = shift · ⟨ω⟩` of size `domain_size`, with
/// `f` represented by its coefficients in ascending order
/// (`coeffs[i]` is the coefficient of `x^i`).
///
/// Derivation. `Σ_{a ∈ H} a^i = Σ_{k=0}^{n−1} (shift · ω^k)^i =
/// shift^i · Σ_k ω^{ki}`. The inner sum is `n` if `n | i` and `0`
/// otherwise. So
///
///     Σ_{a ∈ H} f(a) = n · Σ_{k ≥ 0} f_{kn} · shift^{kn}.
///
/// For PLUM's sumcheck the relevant `f` is `ĝ(x)` with `deg(ĝ) < n`, so
/// only the `k = 0` term contributes: the sum is `n · ĝ_0`. We
/// implement the general formula so callers can compute over `f̂` or
/// `f̂'` directly when convenient.
pub fn sum_over_coset(coeffs: &[Fp192], domain_size: usize, shift: &Fp192) -> Fp192 {
    assert!(
        domain_size > 0,
        "sumcheck::sum_over_coset: domain_size must be > 0 (matches decompose's invariant)"
    );
    assert!(
        !shift.is_zero(),
        "sumcheck::sum_over_coset: shift must be nonzero; H = 0·⟨ω⟩ is meaningless"
    );
    let n = domain_size;
    let n_field = Fp192::from_u64(n as u64);
    let shift_pow_n = shift.pow_u128(n as u128);

    // Iterate i = 0, n, 2n, ... while we still have coefficients.
    // Track shift^{kn} incrementally.
    let mut acc = Fp192::zero();
    let mut shift_kn = Fp192::one(); // shift^{0·n}
    let mut idx = 0;
    while idx < coeffs.len() {
        acc = acc + coeffs[idx].clone() * shift_kn.clone();
        shift_kn = shift_kn * shift_pow_n.clone();
        idx += n;
    }
    n_field * acc
}

/// Decompose `f(x) = g(x) + Z_H(x) · h(x)`, where `H = shift · ⟨ω⟩` of
/// size `domain_size`, so that `deg(g) < domain_size`. The
/// decomposition is unique by Euclidean division: `g` is the residue,
/// `h` is the quotient.
///
/// Implementation: long division by `Z_H(x) = x^n − c^n`. Iterate from
/// the top of `f` downward. If the leading term is at position `i ≥ n`,
/// then the quotient picks up `f_i x^{i−n}` and the residue at position
/// `i − n` accumulates `c^n · f_i`. The cost is one multiply per
/// coefficient at index `≥ n`, plus `O(d)` allocations.
///
/// Returns `(g, h)` with
///   - `g.len() == min(coeffs.len(), domain_size)`,
///   - `h.len() == max(0, coeffs.len() − domain_size)`.
///
/// Panics on `domain_size == 0` — caller should never pass this.
pub fn decompose(
    coeffs: &[Fp192],
    domain_size: usize,
    shift: &Fp192,
) -> (Vec<Fp192>, Vec<Fp192>) {
    assert!(domain_size > 0, "sumcheck decompose: domain_size must be > 0");
    assert!(
        !shift.is_zero(),
        "sumcheck decompose: shift must be nonzero; H = 0·⟨ω⟩ is meaningless"
    );

    let n = domain_size;
    let d = coeffs.len();
    if d <= n {
        // f already has degree < |H|; trivially f = f + Z_H · 0.
        return (coeffs.to_vec(), Vec::new());
    }

    // Make a mutable working copy of f. We will overwrite the top
    // coefficients with the h vector after their contribution to g has
    // been absorbed.
    let mut work = coeffs.to_vec();
    let shift_pow_n = shift.pow_u128(n as u128);

    // Process from high to low. At iteration `i = d-1, d-2, ..., n`,
    // the coefficient work[i] represents the residual top coefficient
    // of the partially-reduced polynomial. It becomes h[i-n], and we
    // add shift_pow_n * work[i] to work[i-n].
    let mut h = vec![Fp192::zero(); d - n];
    for i in (n..d).rev() {
        let top = work[i].clone();
        h[i - n] = top.clone();
        // work[i] is now consumed; no need to clear it.
        work[i - n] = work[i - n].clone() + shift_pow_n.clone() * top;
    }

    // The remaining work[0..n] is g.
    work.truncate(n);
    (work, h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plum::fft::evaluate_on_coset;
    use crate::plum::setup::plum_setup;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn naive_evaluate(coeffs: &[Fp192], point: &Fp192) -> Fp192 {
        let mut acc = Fp192::zero();
        for coeff in coeffs.iter().rev() {
            acc = acc * point.clone() + coeff.clone();
        }
        acc
    }

    fn rand_coeffs(n: usize, seed: u64) -> Vec<Fp192> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..n).map(|_| Fp192::rand(&mut rng)).collect()
    }

    fn coset_elements(shift: &Fp192, generator: &Fp192, n: usize) -> Vec<Fp192> {
        let mut out = Vec::with_capacity(n);
        let mut cur = shift.clone();
        for _ in 0..n {
            out.push(cur.clone());
            cur = cur * generator.clone();
        }
        out
    }

    #[test]
    fn vanishing_poly_zero_on_coset() {
        let pp = plum_setup(128).unwrap();
        let elements = coset_elements(&pp.h_shift, &pp.h_generator, pp.h_size);
        for a in &elements {
            let z = vanishing_poly_evaluate(pp.h_size, &pp.h_shift, a);
            assert!(z.is_zero(), "Z_H(a) should be zero for a ∈ H");
        }
    }

    #[test]
    fn vanishing_poly_nonzero_off_coset() {
        let pp = plum_setup(128).unwrap();
        // u_generator generates the larger domain U, which is disjoint
        // from H by construction (setup arranges this). So any element
        // of U is off H.
        let mut x = pp.u_generator.clone();
        for _ in 0..16 {
            let z = vanishing_poly_evaluate(pp.h_size, &pp.h_shift, &x);
            assert!(
                !z.is_zero(),
                "Z_H should not vanish on U; setup is supposed to keep them disjoint"
            );
            x = x * pp.u_generator.clone();
        }
    }

    #[test]
    fn sum_over_coset_matches_naive_for_low_degree() {
        let pp = plum_setup(128).unwrap();
        // deg(f) < |H|: only the constant term contributes, so the sum
        // should be |H| · f_0.
        let coeffs = rand_coeffs(pp.h_size, 0x8000_0001);
        let formula = sum_over_coset(&coeffs, pp.h_size, &pp.h_shift);
        let naive = coset_elements(&pp.h_shift, &pp.h_generator, pp.h_size)
            .iter()
            .map(|a| naive_evaluate(&coeffs, a))
            .fold(Fp192::zero(), |acc, x| acc + x);
        assert_eq!(formula, naive);
        // Also check the closed form n · f_0.
        let expected = Fp192::from_u64(pp.h_size as u64) * coeffs[0].clone();
        assert_eq!(formula, expected);
    }

    #[test]
    fn sum_over_coset_matches_naive_for_higher_degree() {
        let pp = plum_setup(128).unwrap();
        // 3·|H| + 1 coefficients exercises all three terms in the
        // closed-form: f_0 + f_{|H|} · c^{|H|} + f_{2|H|} · c^{2|H|}.
        let len = 3 * pp.h_size + 1;
        let coeffs = rand_coeffs(len, 0x8000_0002);
        let formula = sum_over_coset(&coeffs, pp.h_size, &pp.h_shift);
        let naive = coset_elements(&pp.h_shift, &pp.h_generator, pp.h_size)
            .iter()
            .map(|a| naive_evaluate(&coeffs, a))
            .fold(Fp192::zero(), |acc, x| acc + x);
        assert_eq!(formula, naive);
    }

    #[test]
    fn decompose_below_degree_n_is_trivial() {
        let pp = plum_setup(128).unwrap();
        let coeffs = rand_coeffs(pp.h_size, 0x8000_0003);
        let (g, h) = decompose(&coeffs, pp.h_size, &pp.h_shift);
        assert_eq!(g, coeffs);
        assert!(h.is_empty());
    }

    #[test]
    fn decompose_satisfies_identity_at_coset_points() {
        let pp = plum_setup(128).unwrap();
        // deg(f) ≈ 4m + κ·η at λ=128 ≈ 32 + 26·4 ≈ 136. Pick 200 to
        // give plenty of headroom and exercise the long-division loop.
        let coeffs = rand_coeffs(200, 0x8000_0004);
        let (g, h) = decompose(&coeffs, pp.h_size, &pp.h_shift);
        assert!(g.len() <= pp.h_size, "deg(g) < |H| invariant violated");
        // f(a) should equal g(a) + Z_H(a) · h(a) for every a, including
        // a ∈ H (where Z_H(a) = 0 and so f(a) should equal g(a)).
        let elements = coset_elements(&pp.h_shift, &pp.h_generator, pp.h_size);
        for a in &elements {
            let f_a = naive_evaluate(&coeffs, a);
            let g_a = naive_evaluate(&g, a);
            assert_eq!(f_a, g_a, "f(a) ≠ g(a) on H, contradicting deg(g) < |H|");
        }
    }

    #[test]
    fn decompose_satisfies_identity_at_random_points() {
        let pp = plum_setup(128).unwrap();
        let coeffs = rand_coeffs(200, 0x8000_0005);
        let (g, h) = decompose(&coeffs, pp.h_size, &pp.h_shift);
        let mut rng = ChaCha20Rng::seed_from_u64(0x8000_0005_AAA);
        for _ in 0..16 {
            let x = Fp192::rand(&mut rng);
            let f_x = naive_evaluate(&coeffs, &x);
            let g_x = naive_evaluate(&g, &x);
            let h_x = naive_evaluate(&h, &x);
            let z_x = vanishing_poly_evaluate(pp.h_size, &pp.h_shift, &x);
            assert_eq!(f_x, g_x + z_x * h_x, "decomposition identity fails at random x");
        }
    }

    #[test]
    fn decompose_satisfies_identity_on_u_codomain() {
        // The verifier-side check actually evaluates the decomposition
        // at points of U (because the prover commits ĥ|_U). Exercise
        // that path.
        let pp = plum_setup(128).unwrap();
        let coeffs = rand_coeffs(200, 0x8000_0006);
        let (g, h) = decompose(&coeffs, pp.h_size, &pp.h_shift);
        let u_points = coset_elements(&Fp192::one(), &pp.u_generator, 64);
        for u in &u_points {
            let f_u = naive_evaluate(&coeffs, u);
            let g_u = naive_evaluate(&g, u);
            let h_u = naive_evaluate(&h, u);
            let z_u = vanishing_poly_evaluate(pp.h_size, &pp.h_shift, u);
            assert_eq!(f_u, g_u + z_u * h_u);
        }
    }

    #[test]
    fn decompose_degree_bounds_are_tight() {
        let pp = plum_setup(128).unwrap();
        // f has degree d-1 = 199; expect deg(g) < 8 and deg(h) ≤ 191.
        let coeffs = rand_coeffs(200, 0x8000_0007);
        let (g, h) = decompose(&coeffs, pp.h_size, &pp.h_shift);
        assert!(g.len() <= pp.h_size);
        assert!(h.len() <= 200 - pp.h_size);
        assert_eq!(g.len() + h.len(), 200);
    }

    #[test]
    fn sumcheck_round_trip_with_fft() {
        // Use FFT to evaluate ĥ on U from coefficient form, then check
        // the decomposition at every U-point. This is the path the
        // signer will take (ĥ|_U comes from a coset FFT of h's coeffs).
        let pp = plum_setup(128).unwrap();
        let coeffs = rand_coeffs(200, 0x8000_0008);
        let (g, h) = decompose(&coeffs, pp.h_size, &pp.h_shift);
        // Zero-extend h to a power of two we can FFT (next-power-of-two
        // of h.len() or |U|, whichever's larger; use |U|).
        let mut h_padded = h.clone();
        h_padded.resize(pp.u_size, Fp192::zero());
        let h_on_u = evaluate_on_coset(&h_padded, &Fp192::one(), &pp.u_generator)
            .expect("fft on |U|");
        // Verify a few points of the U evaluation against the direct
        // identity.
        let mut u = Fp192::one();
        for h_at_u in h_on_u.iter().take(32) {
            let f_u = naive_evaluate(&coeffs, &u);
            let g_u = naive_evaluate(&g, &u);
            let z_u = vanishing_poly_evaluate(pp.h_size, &pp.h_shift, &u);
            assert_eq!(f_u, g_u + z_u * h_at_u.clone());
            u = u * pp.u_generator.clone();
        }
    }
}
