//! Stage 4c-4-sub: the two STIR algebraic checks deferred by Stages 4c-3b /
//! 4c-3c, as R1CS gadgets over PLUM's `Fp192`, COMPOSING the Stage-4b polynomial
//! gadgets ([`lagrange_interpolate_circuit`], [`evaluate_circuit`],
//! [`multiply_circuit`], [`divide_by_linear_circuit`]) with the Stage-2
//! [`Fp192R1csBuilder`].
//!
//! ## (1) RATE-CORRECTION DIVISION
//!
//! Software references (matched EXACTLY):
//!
//!  * Per-fiber, pointwise form — `signatures::plum::verify::plum_verify`,
//!    the Algorithm-6 final-poly rate-correction block (`verify.rs:732-760`):
//!
//!    ```text
//!    let b_x   = evaluate(&b_hat_r, x);                     // 738
//!    let prod  = Π_{α ∈ g_r} (x - α);                       // 739-742
//!    let prod_inv = prod.inverse()?;                        // 743 (reject on None)
//!    let a_prime_x = (fiber_a_r[t] - b_x) * prod_inv;       // 757
//!    let t_r_x = evaluate(&t_r_coeffs, x);                  // 758
//!    fiber_f_r.push(a_prime_x * t_r_x);                     // 759
//!    ```
//!
//!  * Coefficient form — `signatures::plum::stir::rate_correct`
//!    (`stir.rs:204-237`):
//!
//!    ```text
//!    let b_i       = lagrange_interpolate(g_i, values)?;    // 223
//!    let numerator = a_i - b_i  (coeff-wise, zero-padded);  // 224-232
//!    let quotient  = divide_by_linear_product(numerator, g_i)?;  // 235
//!    ```
//!    where `divide_by_linear_product` (`stir_poly.rs:201`) folds
//!    `divide_by_linear` (`stir_poly.rs:169`) over the roots — exactly the
//!    quotient/remainder polynomial identity `q·(x-α)+r == p`, `r == 0`.
//!
//! The 4c-3b/4c-3c gadgets took the rate-corrected fiber values `f̂_R(x_t)` as
//! INPUTS; these gadgets PRODUCE them from the Merkle-opened `â_R(x_t)`, closing
//! the obligation flagged DEFERRED at `ood_finalpoly_fp192_gadget.rs:58-61` and
//! `stir_round_fp192_gadget.rs:70-71`.
//!
//! ### The R1CS division trap (handled — the quotient is NOT a free witness)
//!
//! [`rate_correction_pointwise_circuit`] enforces the division by the
//! multiplication-back identity
//!
//! ```text
//!     a_prime_x * prod == (a_R_x - b_x)
//! ```
//!
//! as a REAL `mul` + `enforce_eq` row, where `prod = Π(x-α)` is itself built
//! from real `mul_pub` constraints over the α wires (NOT a free wire) and
//! `a_prime_x` is a witness wire pinned by that equality. Corrupting `a_prime_x`,
//! any `α`, or `b_hat_r` breaks the row. (When `prod == 0` the row degenerates to
//! `a_prime_x*0 == num`, forcing `num == 0`; for an honest nonzero numerator this
//! is unsatisfiable — mirroring the software's `prod.inverse() == None` reject at
//! `verify.rs:743-755`.)
//!
//! [`rate_correct_coeffs_circuit`] uses the coefficient form: Lagrange-interpolate
//! `b̂` in-circuit, subtract from `â_i`, then compose [`divide_by_linear_circuit`]
//! over the α_i. Each [`divide_by_linear_circuit`] already pins its quotient by
//! `q·(x-α)+r == p` and the exactness row `r == 0` — so the composed quotient is
//! fully bound, never free.
//!
//! ## (2) ROUND-0 SUMCHECK IDENTITY
//!
//! Software reference (matched EXACTLY): `verify.rs:561-584`, the sum-over-`H`
//! consistency check that gates round 0:
//!
//! ```text
//! let mu_check = Σ_j epsilons[j] · (Σ_i lambdas[j][i] · o_responses[j·m+i]); // 561-572
//! let target   = z · mu_check + sig.s_sum;                                   // 573
//! let actual_sum = Σ_{a ∈ h_points} evaluate(&g_hat_coeffs, a);              // 574-577
//! if actual_sum != target { reject(SumcheckIdentityViolation{usize::MAX}); } // 578-584
//! ```
//!
//! [`sumcheck_sum_identity_circuit`] mirrors this: it reconstructs `mu_check` and
//! `target` from constrained multiply/add chains, recomputes `actual_sum` by
//! Horner-evaluating the interpolant `g_hat` at every `h_point` and summing, and
//! ENFORCES `actual_sum == target` as the real accept equality. The OOD half of
//! the round-0 identity (`verify.rs:537-560`) is ALREADY gadgetized as
//! [`super::ood_finalpoly_fp192_gadget::ood_consistency_circuit`]; this module adds
//! the complementary sum-over-`H` half.
//!
//! ## Scope boundary
//!
//! The public-input/instance boundary (which of pk / message / roots / transcript
//! wires are designated PUBLIC) is the top-level circuit's job (Stage 4c-4-pi) and
//! is NOT re-implemented here: every gadget takes EXISTING wires and the build
//! wrappers `alloc_input` them for the gate tests only.

use crate::primitives::field::p192::Fp192;
use crate::primitives::r1cs::griffin_fp192_gadget::{Fp192R1cs, Fp192R1csBuilder, Fp192Var};
use crate::primitives::r1cs::poly_fp192_gadget::{
    divide_by_linear_circuit, evaluate_circuit, lagrange_interpolate_circuit, multiply_circuit,
};

// ===========================================================================
// (1) RATE-CORRECTION DIVISION
// ===========================================================================

/// In-circuit rate-correction at ONE fiber point, pointwise form, matching
/// `verify.rs:738-759` value-for-value. Returns the wire holding
/// `f̂_R(x) = â_R'(x) · t_R(x)` where
/// `â_R'(x) = (â_R(x) − b̂_R(x)) / Π_{α ∈ g_r}(x − α)`.
///
/// Inputs (EXISTING wires): `x` the fiber point; `a_r_x` the Merkle-opened
/// `â_R(x)` (= `proof.leaf` at `verify.rs:729`); `b_hat_r` the interpolant `b̂_R`
/// coefficients; `g_r` the challenge set `G_R = (r^out, r^shift_1, …)`; `t_r` the
/// degree-correction polynomial `t_R` coefficients.
///
/// The division is enforced by the multiplication-back identity
/// `a_prime_x · prod == (a_r_x − b_x)` — `a_prime_x` is a witness wire, NOT free,
/// and `prod` is built from real `mul` constraints over the α wires
/// (`rateCorrectionQuotientBound`).
///
/// Returns `(f_r_x, a_prime_x)`: the corrected fiber value `f̂_R(x)` and the
/// pinned quotient wire `â_R'(x)` (exposed for callers/tamper tests).
pub fn rate_correction_pointwise_circuit(
    builder: &mut Fp192R1csBuilder,
    x: &Fp192Var,
    a_r_x: &Fp192Var,
    b_hat_r: &[Fp192Var],
    g_r: &[Fp192Var],
    t_r: &[Fp192Var],
) -> (Fp192Var, Fp192Var) {
    // b_x = b̂_R(x), Horner (verify.rs:738).
    let b_x = evaluate_circuit(builder, b_hat_r, x);
    // numerator = â_R(x) − b̂_R(x)  (verify.rs:757, the `(fiber_a_r[t] - b_x)`).
    let num = builder.sub_vars(a_r_x, &b_x);
    // prod = Π_{α ∈ g_r} (x − α)  built from REAL constraints (verify.rs:739-742).
    let mut prod = builder.constant_pub(Fp192::one());
    for alpha in g_r {
        let x_minus_alpha = builder.sub_vars(x, alpha);
        prod = builder.mul_pub(&prod, &x_minus_alpha);
    }
    // a_prime_x value: (num)/prod, computed as the software does (verify.rs:757).
    // Allocated as a WITNESS wire, then PINNED by a_prime_x*prod == num below.
    let prod_inv = prod
        .value()
        .inverse()
        .expect("rate_correction_pointwise_circuit: Π(x-α)=0 (software rejects, verify.rs:743)");
    let a_prime_val = num.value().clone() * prod_inv;
    let a_prime_x = builder.alloc_witness_pub(a_prime_val);
    // REAL constraint pinning the division: a_prime_x * prod == num.
    builder.enforce_mul_pub(&a_prime_x, &prod, &num);
    // t_R(x), Horner (verify.rs:758).
    let t_r_x = evaluate_circuit(builder, t_r, x);
    // f̂_R(x) = â_R'(x) · t_R(x)  (verify.rs:759).
    let f_r_x = builder.mul_pub(&a_prime_x, &t_r_x);
    (f_r_x, a_prime_x)
}

/// In-circuit rate-correction in COEFFICIENT form, matching
/// `stir::rate_correct` (`stir.rs:223-235`): Lagrange-interpolate `b̂` through
/// `(g_i, values)`, subtract from `â_i`, divide by `Π_{α ∈ g_i}(x − α)`.
///
/// Returns the quotient `â_i'` coefficient wires. The division composes
/// [`divide_by_linear_circuit`] over the α_i; each application binds its quotient
/// by the polynomial identity `q·(x-α)+r == p` and the exactness row `r == 0`, so
/// the composed quotient is NEVER a free witness (`rateCorrectionQuotientBound`).
///
/// `g_i` must be DISTINCT (the software's Lagrange / divide preconditions). The
/// honest caller passes `values[ℓ] = evaluate(â_i, g_i[ℓ])` so each division is
/// exact (matching `stir.rs:202` `values[ℓ] == evaluate(a_i, g_i[ℓ])`).
pub fn rate_correct_coeffs_circuit(
    builder: &mut Fp192R1csBuilder,
    a_i: &[Fp192Var],
    g_i: &[Fp192Var],
    values: &[Fp192Var],
) -> Vec<Fp192Var> {
    assert_eq!(
        g_i.len(),
        values.len(),
        "rate_correct_coeffs_circuit: |g_i| != |values| (software: RateCorrectLengthMismatch)",
    );
    if g_i.is_empty() {
        // κ = 0 degenerate case: return â_i unchanged (stir.rs:212-216).
        return a_i.to_vec();
    }
    // b̂ = Interpolate(g_i, values), coefficient form (stir.rs:223).
    let b_hat = lagrange_interpolate_circuit(builder, g_i, values);
    // numerator = â_i − b̂  (coeff-wise, zero-padded) (stir.rs:224-232).
    let len = a_i.len().max(b_hat.len());
    let zero = builder.constant_pub(Fp192::zero());
    let mut numerator: Vec<Fp192Var> = Vec::with_capacity(len);
    for k in 0..len {
        let a_k = a_i.get(k).cloned().unwrap_or_else(|| zero.clone());
        let b_k = b_hat.get(k).cloned().unwrap_or_else(|| zero.clone());
        numerator.push(builder.sub_vars(&a_k, &b_k));
    }
    // quotient = numerator / Π_{α ∈ g_i}(x − α): fold divide_by_linear_circuit
    // over the roots (stir.rs:235 -> divide_by_linear_product, stir_poly.rs:201).
    let mut current = numerator;
    for alpha in g_i {
        current = divide_by_linear_circuit(builder, &current, alpha);
    }
    current
}

/// Compose `â_i'` with the degree-correction polynomial `t_i` to produce
/// `f̂_i = â_i' · t_i`, coefficient form, matching `stir::apply_degree_correction`
/// (`stir.rs:245-252`) which is `multiply(a_i_prime, t_i)`. `t_i` is passed as
/// coefficient wires (built from `degree_correction_polynomial`).
pub fn apply_degree_correction_circuit(
    builder: &mut Fp192R1csBuilder,
    a_i_prime: &[Fp192Var],
    t_i: &[Fp192Var],
) -> Vec<Fp192Var> {
    multiply_circuit(builder, a_i_prime, t_i)
}

// ===========================================================================
// (2) ROUND-0 SUMCHECK IDENTITY
// ===========================================================================

/// In-circuit round-0 sumcheck identity (sum-over-`H`), matching
/// `verify.rs:561-584`. Enforces
///
/// ```text
///     Σ_{a ∈ h_points} g_hat(a)  ==  z · mu_check + s_sum
/// ```
///
/// where `mu_check = Σ_j epsilons[j] · (Σ_i lambdas[j][i] · o_responses[j·m+i])`.
///
/// Inputs (EXISTING wires): `g_hat_coeffs` the interpolant coefficients (the
/// software's `g_hat_coeffs` from `verify.rs:545`); `h_points` the domain `H`;
/// `z`, `s_sum` the transcript/signature scalars; `epsilons[j]`, `lambdas[j][i]`,
/// `o_responses[j·m+i]` the BCRSVW combination data. `n = epsilons.len()`,
/// `m = lambdas[0].len()`, and `o_responses.len() == n·m`.
///
/// The enforced equality `actual_sum == target` IS the software accept condition
/// at `verify.rs:578` (`sumcheckIdentityConstrained`). `mu_check`, `target`, and
/// `actual_sum` are all built from REAL multiply/add chains.
#[allow(clippy::too_many_arguments)]
pub fn sumcheck_sum_identity_circuit(
    builder: &mut Fp192R1csBuilder,
    g_hat_coeffs: &[Fp192Var],
    h_points: &[Fp192Var],
    z: &Fp192Var,
    s_sum: &Fp192Var,
    epsilons: &[Fp192Var],
    lambdas: &[Vec<Fp192Var>],
    o_responses: &[Fp192Var],
) -> Fp192Var {
    let n = epsilons.len();
    assert_eq!(lambdas.len(), n, "sumcheck: lambdas row count != n");
    let m = if n > 0 { lambdas[0].len() } else { 0 };
    assert_eq!(
        o_responses.len(),
        n * m,
        "sumcheck: o_responses.len() != n*m",
    );

    // mu_check = Σ_j epsilons[j] · (Σ_i lambdas[j][i] · o_responses[j*m+i]).
    let mut mu = builder.constant_pub(Fp192::zero());
    for j in 0..n {
        let mut inner = builder.constant_pub(Fp192::zero());
        for i in 0..m {
            let idx = j * m + i;
            // term = lambdas[j][i] * o_responses[idx]  (real mul).
            let term = builder.mul_pub(&lambdas[j][i], &o_responses[idx]);
            inner = builder.add_vars(&inner, &term);
        }
        // contrib = epsilons[j] * inner  (real mul).
        let contrib = builder.mul_pub(&epsilons[j], &inner);
        mu = builder.add_vars(&mu, &contrib);
    }

    // target = z * mu + s_sum  (verify.rs:573).
    let z_mu = builder.mul_pub(z, &mu);
    let target = builder.add_vars(&z_mu, s_sum);

    // actual_sum = Σ_{a ∈ h_points} g_hat(a)  (verify.rs:574-577).
    let mut actual_sum = builder.constant_pub(Fp192::zero());
    for a in h_points {
        let g_at_a = evaluate_circuit(builder, g_hat_coeffs, a);
        actual_sum = builder.add_vars(&actual_sum, &g_at_a);
    }

    // REAL accept constraint: actual_sum == target  (verify.rs:578).
    builder.enforce_eq_pub(&actual_sum, &target);
    actual_sum
}

// ===========================================================================
// Build wrappers (gate tests): stand up a complete R1CS for one gadget call.
// ===========================================================================

/// Exposed wire indices for a pointwise rate-correction instance.
pub struct RateCorrectionPointwiseWires {
    pub x_idx: usize,
    pub a_r_x_idx: usize,
    pub b_hat_r_idx: Vec<usize>,
    pub g_r_idx: Vec<usize>,
    pub t_r_idx: Vec<usize>,
    pub f_r_x_idx: usize,
    /// The pinned `a_prime_x` witness wire (the quotient), exposed for tamper tests.
    pub a_prime_x_idx: usize,
}

/// Build an R1CS for one pointwise rate-correction. The honest caller passes
/// `a_r_x = evaluate(â_R, x)` so the in-circuit division is exact.
pub fn build_rate_correction_pointwise(
    x: Fp192,
    a_r_x: Fp192,
    b_hat_r: &[Fp192],
    g_r: &[Fp192],
    t_r: &[Fp192],
) -> (Fp192R1cs, RateCorrectionPointwiseWires) {
    let mut builder = Fp192R1csBuilder::new();
    let x_var = builder.alloc_input(x);
    let a_r_x_var = builder.alloc_input(a_r_x);
    let b_hat_vars: Vec<Fp192Var> = b_hat_r.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let g_r_vars: Vec<Fp192Var> = g_r.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let t_r_vars: Vec<Fp192Var> = t_r.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let (f_r_x, a_prime_x) = rate_correction_pointwise_circuit(
        &mut builder,
        &x_var,
        &a_r_x_var,
        &b_hat_vars,
        &g_r_vars,
        &t_r_vars,
    );
    let wires = RateCorrectionPointwiseWires {
        x_idx: x_var.index(),
        a_r_x_idx: a_r_x_var.index(),
        b_hat_r_idx: b_hat_vars.iter().map(|v| v.index()).collect(),
        g_r_idx: g_r_vars.iter().map(|v| v.index()).collect(),
        t_r_idx: t_r_vars.iter().map(|v| v.index()).collect(),
        f_r_x_idx: f_r_x.index(),
        a_prime_x_idx: a_prime_x.index(),
    };
    (builder.finalize(), wires)
}

/// Exposed wire indices for a coefficient-form rate-correction instance.
pub struct RateCorrectCoeffsWires {
    pub a_i_idx: Vec<usize>,
    pub g_i_idx: Vec<usize>,
    pub values_idx: Vec<usize>,
    pub quotient_idx: Vec<usize>,
}

/// Build an R1CS for one coefficient-form rate-correction (`stir::rate_correct`).
pub fn build_rate_correct_coeffs(
    a_i: &[Fp192],
    g_i: &[Fp192],
    values: &[Fp192],
) -> (Fp192R1cs, RateCorrectCoeffsWires) {
    let mut builder = Fp192R1csBuilder::new();
    let a_i_vars: Vec<Fp192Var> = a_i.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let g_i_vars: Vec<Fp192Var> = g_i.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let values_vars: Vec<Fp192Var> = values.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let quotient = rate_correct_coeffs_circuit(&mut builder, &a_i_vars, &g_i_vars, &values_vars);
    let wires = RateCorrectCoeffsWires {
        a_i_idx: a_i_vars.iter().map(|v| v.index()).collect(),
        g_i_idx: g_i_vars.iter().map(|v| v.index()).collect(),
        values_idx: values_vars.iter().map(|v| v.index()).collect(),
        quotient_idx: quotient.iter().map(|v| v.index()).collect(),
    };
    (builder.finalize(), wires)
}

/// Exposed wire indices for a sumcheck-sum-identity instance.
pub struct SumcheckSumIdentityWires {
    pub g_hat_idx: Vec<usize>,
    pub h_points_idx: Vec<usize>,
    pub z_idx: usize,
    pub s_sum_idx: usize,
    pub epsilons_idx: Vec<usize>,
    pub lambdas_idx: Vec<Vec<usize>>,
    pub o_responses_idx: Vec<usize>,
    pub actual_sum_idx: usize,
}

/// Build an R1CS for one round-0 sumcheck (sum-over-`H`) identity. The honest
/// caller passes data with `Σ_{a∈H} g_hat(a) == z·mu + s_sum`.
#[allow(clippy::too_many_arguments)]
pub fn build_sumcheck_sum_identity(
    g_hat_coeffs: &[Fp192],
    h_points: &[Fp192],
    z: Fp192,
    s_sum: Fp192,
    epsilons: &[Fp192],
    lambdas: &[Vec<Fp192>],
    o_responses: &[Fp192],
) -> (Fp192R1cs, SumcheckSumIdentityWires) {
    let mut builder = Fp192R1csBuilder::new();
    let g_hat_vars: Vec<Fp192Var> =
        g_hat_coeffs.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let h_vars: Vec<Fp192Var> = h_points.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let z_var = builder.alloc_input(z);
    let s_sum_var = builder.alloc_input(s_sum);
    let eps_vars: Vec<Fp192Var> = epsilons.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let lambda_vars: Vec<Vec<Fp192Var>> = lambdas
        .iter()
        .map(|row| row.iter().map(|c| builder.alloc_input(c.clone())).collect())
        .collect();
    let o_vars: Vec<Fp192Var> = o_responses.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let actual_sum = sumcheck_sum_identity_circuit(
        &mut builder,
        &g_hat_vars,
        &h_vars,
        &z_var,
        &s_sum_var,
        &eps_vars,
        &lambda_vars,
        &o_vars,
    );
    let wires = SumcheckSumIdentityWires {
        g_hat_idx: g_hat_vars.iter().map(|v| v.index()).collect(),
        h_points_idx: h_vars.iter().map(|v| v.index()).collect(),
        z_idx: z_var.index(),
        s_sum_idx: s_sum_var.index(),
        epsilons_idx: eps_vars.iter().map(|v| v.index()).collect(),
        lambdas_idx: lambda_vars
            .iter()
            .map(|row| row.iter().map(|v| v.index()).collect())
            .collect(),
        o_responses_idx: o_vars.iter().map(|v| v.index()).collect(),
        actual_sum_idx: actual_sum.index(),
    };
    (builder.finalize(), wires)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::plum::stir::rate_correct;
    use crate::signatures::plum::stir_poly::{
        degree_correction_polynomial, evaluate, lagrange_interpolate,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rand_coeffs(n: usize, seed: u64) -> Vec<Fp192> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..n).map(|_| Fp192::rand(&mut rng)).collect()
    }

    fn rand_distinct(n: usize, seed: u64) -> Vec<Fp192> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut out: Vec<Fp192> = Vec::with_capacity(n);
        while out.len() < n {
            let c = Fp192::rand(&mut rng);
            if !c.is_zero() && !out.contains(&c) {
                out.push(c);
            }
        }
        out
    }

    /// Build an honest rate-correction instance: pick â_R, the challenge set
    /// `g_r`, set `b̂_R = Interpolate(g_r, â_R(g_r))` (so `â_R − b̂_R` vanishes on
    /// `g_r`, i.e. the division is exact), pick a fiber point `x` disjoint from
    /// `g_r`, and `t_R = degree_correction_polynomial(r_comb, |g_r|-1)`.
    fn honest_pointwise(
        deg: usize,
        kappa1: usize,
        seed: u64,
    ) -> (Fp192, Fp192, Vec<Fp192>, Vec<Fp192>, Vec<Fp192>, Fp192) {
        let a_r = rand_coeffs(deg, seed);
        let g_r = rand_distinct(kappa1, seed ^ 0xAAAA);
        let values: Vec<Fp192> = g_r.iter().map(|p| evaluate(&a_r, p)).collect();
        let b_hat = lagrange_interpolate(&g_r, &values).unwrap();
        // fiber point distinct from every α (so Π(x-α) != 0).
        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0x5555);
        let x = loop {
            let c = Fp192::rand(&mut rng);
            if !c.is_zero() && !g_r.contains(&c) {
                break c;
            }
        };
        let a_r_x = evaluate(&a_r, &x);
        let r_comb = Fp192::rand(&mut rng);
        let t_r = degree_correction_polynomial(&r_comb, g_r.len().saturating_sub(1));
        // software fiber value f̂_R(x).
        let b_x = evaluate(&b_hat, &x);
        let mut prod = Fp192::one();
        for alpha in &g_r {
            prod = prod * (x.clone() - alpha.clone());
        }
        let a_prime_x = (a_r_x.clone() - b_x) * prod.inverse().unwrap();
        let f_r_x = a_prime_x * evaluate(&t_r, &x);
        (x, a_r_x, b_hat, g_r, t_r, f_r_x)
    }

    // -------------------------------------------------------------------
    // GATE (1a): RATE-CORRECTION DIVISION — pointwise form (verify.rs).
    // -------------------------------------------------------------------
    #[test]
    fn rate_correction_pointwise_gate() {
        // TINY: deg(â_R) in {4,6}, |g_r| in {2,3}, η implied by single fiber pt.
        let mut last = (0usize, 0usize, 0usize);
        for (deg, k1, sd) in [(4usize, 2usize, 0x9001u64), (6, 3, 0x9002), (6, 2, 0x9003)] {
            let (x, a_r_x, b_hat, g_r, t_r, f_soft) = honest_pointwise(deg, k1, sd);
            let (r1cs, wires) =
                build_rate_correction_pointwise(x, a_r_x, &b_hat, &g_r, &t_r);
            // (1) honest witness satisfies ALL constraints.
            assert!(
                r1cs.check_satisfied().is_ok(),
                "rate-pointwise: honest unsatisfied (deg={deg}, k1={k1})",
            );
            // (2) gadget output == software f̂_R(x).
            assert_eq!(
                r1cs.assignment[wires.f_r_x_idx], f_soft,
                "rate-pointwise: gadget f_r_x != software (deg={deg}, k1={k1})",
            );
            last = (deg, k1, r1cs.num_constraints());
        }
        eprintln!("[GATE] rate-pointwise: deg={} k1={} -> {} constraints", last.0, last.1, last.2);

        // (3) TAMPER — wrong quotient: corrupt the pinned a_prime_x wire. The
        //     multiplication-back identity a_prime_x*prod == num must reject.
        {
            let (x, a_r_x, b_hat, g_r, t_r, _) = honest_pointwise(6, 3, 0x9004);
            let (base, wires) =
                build_rate_correction_pointwise(x, a_r_x, &b_hat, &g_r, &t_r);
            assert!(base.check_satisfied().is_ok());
            let mut r = base.clone();
            r.assignment[wires.a_prime_x_idx] =
                r.assignment[wires.a_prime_x_idx].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "rate-pointwise: WRONG quotient (a_prime_x) ACCEPTED — division not bound",
            );
        }
    }

    // -------------------------------------------------------------------
    // GATE (1b): RATE-CORRECTION DIVISION — coefficient form (stir::rate_correct).
    // -------------------------------------------------------------------
    #[test]
    fn rate_correct_coeffs_gate() {
        let mut last = (0usize, 0usize, 0usize);
        for (deg, k, sd) in [(5usize, 2usize, 0xA001u64), (6, 3, 0xA002), (7, 2, 0xA003)] {
            let a_i = rand_coeffs(deg, sd);
            let g_i = rand_distinct(k, sd ^ 0xBBBB);
            // honest values: â_i evaluated at the challenge set (so divisible).
            let values: Vec<Fp192> = g_i.iter().map(|p| evaluate(&a_i, p)).collect();
            // software reference.
            let q_soft = rate_correct(&a_i, &g_i, &values).unwrap();
            let (r1cs, wires) = build_rate_correct_coeffs(&a_i, &g_i, &values);
            // (1) honest satisfies all constraints.
            assert!(
                r1cs.check_satisfied().is_ok(),
                "rate-coeffs: honest unsatisfied (deg={deg}, k={k})",
            );
            // (2) gadget quotient coeffs == software rate_correct, term by term.
            assert_eq!(
                wires.quotient_idx.len(),
                q_soft.len(),
                "rate-coeffs: quotient length mismatch (deg={deg}, k={k})",
            );
            for (idx, qc) in wires.quotient_idx.iter().zip(q_soft.iter()) {
                assert_eq!(
                    &r1cs.assignment[*idx], qc,
                    "rate-coeffs: quotient coeff != software (deg={deg}, k={k})",
                );
            }
            last = (deg, k, r1cs.num_constraints());
        }
        eprintln!("[GATE] rate-coeffs: deg={} k={} -> {} constraints", last.0, last.1, last.2);

        // (3) TAMPER — wrong quotient: corrupt a quotient coeff wire. The
        //     divide_by_linear identity q*(x-α)+r == p must reject.
        {
            let a_i = rand_coeffs(6, 0xA004);
            let g_i = rand_distinct(3, 0xA004 ^ 0xBBBB);
            let values: Vec<Fp192> = g_i.iter().map(|p| evaluate(&a_i, p)).collect();
            let (base, wires) = build_rate_correct_coeffs(&a_i, &g_i, &values);
            assert!(base.check_satisfied().is_ok());
            let mut r = base.clone();
            let tgt = wires.quotient_idx[0];
            r.assignment[tgt] = r.assignment[tgt].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "rate-coeffs: WRONG quotient coeff ACCEPTED — quotient not bound",
            );
        }
    }

    // -------------------------------------------------------------------
    // GATE (2): ROUND-0 SUMCHECK (sum-over-H) IDENTITY (verify.rs:561-584).
    // -------------------------------------------------------------------
    #[test]
    fn sumcheck_sum_identity_gate() {
        // Honest construction: pick mu data, h_points, z, s_sum, and a g_hat
        // whose sum over H equals z*mu + s_sum. We engineer g_hat as a constant
        // poly c so Σ_H g_hat = |H|*c, then solve c = (target)/|H|.
        let build_honest = |n: usize, m: usize, hsz: usize, seed: u64| {
            let h_points = rand_distinct(hsz, seed);
            let z = rand_coeffs(1, seed ^ 1)[0].clone();
            let s_sum = rand_coeffs(1, seed ^ 2)[0].clone();
            let epsilons = rand_coeffs(n, seed ^ 3);
            let lambdas: Vec<Vec<Fp192>> =
                (0..n).map(|j| rand_coeffs(m, seed ^ (10 + j as u64))).collect();
            let o_responses = rand_coeffs(n * m, seed ^ 4);
            // software mu + target.
            let mut mu = Fp192::zero();
            for j in 0..n {
                let mut inner = Fp192::zero();
                for i in 0..m {
                    inner = inner + lambdas[j][i].clone() * o_responses[j * m + i].clone();
                }
                mu = mu + epsilons[j].clone() * inner;
            }
            let target = z.clone() * mu + s_sum.clone();
            // pick g_hat = [c] (constant), so Σ_H g_hat = |H|*c == target.
            let hsz_field = Fp192::from_u64(hsz as u64);
            let c = target * hsz_field.inverse().unwrap();
            let g_hat = vec![c];
            (g_hat, h_points, z, s_sum, epsilons, lambdas, o_responses)
        };

        let mut last = (0usize, 0usize, 0usize, 0usize);
        for (n, m, hsz, sd) in [(2usize, 2usize, 2usize, 0xC001u64), (2, 3, 3, 0xC002)] {
            let (g_hat, h_points, z, s_sum, eps, lam, o) = build_honest(n, m, hsz, sd);
            // cross-check the honest construction against software accept condition.
            let actual: Fp192 = h_points
                .iter()
                .map(|a| evaluate(&g_hat, a))
                .fold(Fp192::zero(), |acc, x| acc + x);
            let mut mu = Fp192::zero();
            for j in 0..n {
                let mut inner = Fp192::zero();
                for i in 0..m {
                    inner = inner + lam[j][i].clone() * o[j * m + i].clone();
                }
                mu = mu + eps[j].clone() * inner;
            }
            assert_eq!(actual, z.clone() * mu + s_sum.clone(), "honest setup invalid");

            let (r1cs, wires) =
                build_sumcheck_sum_identity(&g_hat, &h_points, z, s_sum, &eps, &lam, &o);
            // (1) honest satisfies all constraints.
            assert!(
                r1cs.check_satisfied().is_ok(),
                "sumcheck: honest unsatisfied (n={n}, m={m}, |H|={hsz})",
            );
            // (2) gadget actual_sum wire == software actual_sum.
            assert_eq!(
                r1cs.assignment[wires.actual_sum_idx], actual,
                "sumcheck: gadget actual_sum != software (n={n}, m={m})",
            );
            last = (n, m, hsz, r1cs.num_constraints());
        }
        eprintln!(
            "[GATE] sumcheck: n={} m={} |H|={} -> {} constraints",
            last.0, last.1, last.2, last.3
        );

        // (3) TAMPER — wrong sumcheck value: corrupt s_sum (changes target only,
        //     so actual_sum != target). The enforce_eq accept row must reject.
        {
            let (g_hat, h_points, z, s_sum, eps, lam, o) = build_honest(2, 2, 2, 0xC003);
            let (base, wires) =
                build_sumcheck_sum_identity(&g_hat, &h_points, z, s_sum, &eps, &lam, &o);
            assert!(base.check_satisfied().is_ok());
            let mut r = base.clone();
            r.assignment[wires.s_sum_idx] =
                r.assignment[wires.s_sum_idx].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "sumcheck: WRONG s_sum (target) ACCEPTED — identity not enforced",
            );
        }
        // (3') TAMPER — corrupt an o_response (changes mu => target): must reject.
        {
            let (g_hat, h_points, z, s_sum, eps, lam, o) = build_honest(2, 3, 3, 0xC004);
            let (base, wires) =
                build_sumcheck_sum_identity(&g_hat, &h_points, z, s_sum, &eps, &lam, &o);
            assert!(base.check_satisfied().is_ok());
            let mut r = base.clone();
            let tgt = wires.o_responses_idx[0];
            r.assignment[tgt] = r.assignment[tgt].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "sumcheck: WRONG o_response ACCEPTED — mu not bound into identity",
            );
        }
    }
}
