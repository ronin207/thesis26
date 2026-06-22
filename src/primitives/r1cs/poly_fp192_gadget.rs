//! STIR polynomial operations as R1CS constraint gadgets (Stage 4b), over
//! PLUM's `Fp192` field, reusing the Stage-2 [`Fp192R1csBuilder`] /
//! [`Fp192Var`] from [`crate::primitives::r1cs::griffin_fp192_gadget`].
//!
//! ## Software references (matched EXACTLY)
//!
//! Each gadget mirrors one PLUM STIR-verifier polynomial primitive:
//!
//!   * [`evaluate_circuit`]    ← `signatures::plum::stir_poly::evaluate`
//!     (`src/signatures/plum/stir_poly.rs:64`) — Horner.
//!   * [`lagrange_interpolate_circuit`]
//!     ← `signatures::plum::stir_poly::lagrange_interpolate`
//!     (`src/signatures/plum/stir_poly.rs:108`) — has DIVISIONS.
//!   * [`vanishing_poly_evaluate_circuit`]
//!     ← `signatures::plum::sumcheck::vanishing_poly_evaluate`
//!     (`src/signatures/plum/sumcheck.rs:40`) — `x^|H| - shift^|H|`.
//!   * [`degree_correction_evaluate_circuit`]
//!     ← `evaluate(degree_correction_polynomial(r, κ), x)` over
//!     `signatures::plum::stir_poly::degree_correction_polynomial`
//!     (`src/signatures/plum/stir_poly.rs:224`) + `evaluate`.
//!
//! ## The R1CS division/inverse trap (handled — see Stage-3 note)
//!
//! `lagrange_interpolate` scales each basis polynomial by `inv_denom`, the
//! field inverse of `denom = Π_{j≠i}(domain[i] - domain[j])`. An UNCONSTRAINED
//! inverse is an under-constraining hole (a malicious prover could assign any
//! value). This gadget allocates `inv_denom` as a witness wire and pins it with
//! a REAL multiplication constraint `inv_denom * denom == 1` (one R1CS row per
//! `i`). The software relies on `denom != 0` (guaranteed because the domain
//! points are distinct, so every factor `domain[i] - domain[j]` is nonzero); we
//! preserve that precondition by REQUIRING the caller pass distinct domain
//! points — mirroring the software's `InterpolationDomainNotDistinct`
//! pre-check — and assert it before building, since `inv*denom==1` is
//! unsatisfiable when `denom == 0`.

use crate::primitives::field::p192::Fp192;
use crate::primitives::r1cs::griffin_fp192_gadget::{Fp192R1cs, Fp192R1csBuilder, Fp192Var};

// ---------------------------------------------------------------------------
// (1) Horner polynomial evaluation
// ---------------------------------------------------------------------------

/// In-circuit Horner evaluation of `coeffs` at `x`, matching
/// `stir_poly::evaluate` (`stir_poly.rs:64`) wire-for-value:
///
/// ```text
/// acc = 0;
/// for coeff in coeffs.iter().rev() { acc = acc * x + coeff; }
/// ```
///
/// `coeffs` and `x` are existing wires (typically `alloc_input`). Returns the
/// wire holding `evaluate(coeffs, x)`. Empty `coeffs` returns a constant-0 wire
/// (matching `evaluate`'s behaviour: the fold over an empty iterator is 0).
///
/// Cost: for `n = coeffs.len()`, `n` multiplications (`acc*x`) and `n` additions
/// (`+ coeff`); the first iteration's `acc*x` is `0*x` so it is still emitted as
/// a real constraint to keep the structure uniform with the software loop.
pub fn evaluate_circuit(
    builder: &mut Fp192R1csBuilder,
    coeffs: &[Fp192Var],
    x: &Fp192Var,
) -> Fp192Var {
    let mut acc = builder.constant_pub(Fp192::zero());
    for coeff in coeffs.iter().rev() {
        let acc_x = builder.mul_pub(&acc, x);
        acc = builder.add_vars(&acc_x, coeff);
    }
    acc
}

// ---------------------------------------------------------------------------
// (2) Lagrange interpolation (returns coefficient wires) — has divisions
// ---------------------------------------------------------------------------

/// In-circuit Lagrange interpolation, matching `stir_poly::lagrange_interpolate`
/// (`stir_poly.rs:108`). Given `domain[i]` (DISTINCT) and `values[i]` as wires,
/// returns the `n` coefficient wires of the degree-`< n` interpolant in
/// ascending order.
///
/// Mirrors the software exactly:
///   * build each unnormalised basis `Π_{j≠i}(x - domain[j])` in coefficient
///     form by repeated multiply-by-`(x - domain[j])`;
///   * accumulate `denom = Π_{j≠i}(domain[i] - domain[j])`;
///   * scale by `values[i] / denom` and add into `result`.
///
/// ### Division handling (the trap)
/// `inv_denom` is allocated as a WITNESS wire and pinned by the real constraint
/// `inv_denom * denom == 1` (see [`enforce_inverse`]). `denom != 0` is
/// guaranteed by the distinct-domain precondition, asserted up front. With a
/// zero `denom` the inverse constraint is unsatisfiable, so a malicious prover
/// cannot fabricate `inv_denom`.
///
/// # Panics
/// Panics if `domain.len() != values.len()` or if the domain has a repeated
/// point — mirroring the `InterpolationLengthMismatch` /
/// `InterpolationDomainNotDistinct` errors the software returns (here surfaced
/// as a build-time panic because an R1CS gadget has no error channel).
pub fn lagrange_interpolate_circuit(
    builder: &mut Fp192R1csBuilder,
    domain: &[Fp192Var],
    values: &[Fp192Var],
) -> Vec<Fp192Var> {
    assert_eq!(
        domain.len(),
        values.len(),
        "lagrange_interpolate_circuit: domain/values length mismatch \
         (software: InterpolationLengthMismatch)",
    );
    let n = domain.len();
    if n == 0 {
        return Vec::new();
    }
    // Distinct-domain precondition (software pre-check + the denom!=0 the
    // inverse constraint needs). O(n^2), fine for STIR's n = eta = 4.
    for i in 0..n {
        for j in (i + 1)..n {
            assert_ne!(
                domain[i].value(),
                domain[j].value(),
                "lagrange_interpolate_circuit: repeated domain point \
                 (software: InterpolationDomainNotDistinct); denom would be 0",
            );
        }
    }

    // result[k] accumulates the k-th coefficient. Start as constant-0 wires.
    let mut result: Vec<Fp192Var> = (0..n).map(|_| builder.constant_pub(Fp192::zero())).collect();

    for i in 0..n {
        // basis = Π_{j != i} (x - domain[j]), coefficient form, ascending.
        // Start from the constant polynomial 1 ( [one] ).
        let mut basis: Vec<Fp192Var> = vec![builder.constant_pub(Fp192::one())];
        // denom = Π_{j != i} (domain[i] - domain[j]).
        let mut denom = builder.constant_pub(Fp192::one());

        for (j, dj) in domain.iter().enumerate() {
            if j == i {
                continue;
            }
            // next = basis * (x - dj): next[k] = -dj*basis[k] + basis[k-1].
            // (matches stir_poly.rs:140-145).
            let mut next: Vec<Fp192Var> =
                (0..basis.len() + 1).map(|_| builder.constant_pub(Fp192::zero())).collect();
            for (k, bk) in basis.iter().enumerate() {
                // next[k]   -= dj * bk
                let dj_bk = builder.mul_pub(dj, bk);
                next[k] = builder.sub_vars(&next[k], &dj_bk);
                // next[k+1] += bk
                next[k + 1] = builder.add_vars(&next[k + 1], bk);
            }
            basis = next;
            // denom *= (domain[i] - domain[j]).
            let diff = builder.sub_vars(&domain[i], dj);
            denom = builder.mul_pub(&denom, &diff);
        }

        // inv_denom = denom^{-1}, pinned by inv_denom * denom == 1.
        let inv_denom = enforce_inverse(builder, &denom);
        // scale = values[i] * inv_denom.
        let scale = builder.mul_pub(&values[i], &inv_denom);
        // result[k] += scale * basis[k].
        for (k, bk) in basis.iter().enumerate() {
            let term = builder.mul_pub(&scale, bk);
            result[k] = builder.add_vars(&result[k], &term);
        }
    }
    result
}

/// Allocate `inv = denom^{-1}` as a witness wire and pin it with the real
/// constraint `inv * denom == 1` (one R1CS multiplication row). Requires
/// `denom != 0` (the caller's distinct-domain precondition guarantees this);
/// panics on a zero `denom` because `inv*denom==1` is then unsatisfiable, so we
/// refuse to emit an unsatisfiable constraint silently.
fn enforce_inverse(builder: &mut Fp192R1csBuilder, denom: &Fp192Var) -> Fp192Var {
    let denom_val = denom.value().clone();
    assert!(
        !denom_val.is_zero(),
        "enforce_inverse: denom == 0 has no inverse; \
         distinct-domain precondition violated",
    );
    let inv_val = denom_val
        .inverse()
        .expect("denom != 0 asserted above; inverse exists");
    let inv = builder.alloc_witness_pub(inv_val);
    let one = builder.constant_pub(Fp192::one());
    // inv * denom == 1, a REAL constraint pinning the witness.
    builder.enforce_mul_pub(&inv, denom, &one);
    inv
}

// ---------------------------------------------------------------------------
// (3) Vanishing polynomial evaluation: Z_H(x) = x^|H| - shift^|H|
// ---------------------------------------------------------------------------

/// In-circuit `Z_H(x) = x^|H| - shift^|H|`, matching
/// `sumcheck::vanishing_poly_evaluate` (`sumcheck.rs:40`):
/// `x.pow_u128(n) - shift.pow_u128(n)`.
///
/// `x` and `shift` are wires; `domain_size = |H|` is a public structural
/// parameter (the coset size, known to the verifier). Both powers are computed
/// in-circuit via repeated squaring (real constraints), so the gadget output
/// equals the software value bit-for-bit.
///
/// Returns the wire holding `Z_H(x)`. `domain_size == 0` gives
/// `x^0 - shift^0 = 1 - 1 = 0` (matching `pow_u128(0) = 1`).
pub fn vanishing_poly_evaluate_circuit(
    builder: &mut Fp192R1csBuilder,
    domain_size: usize,
    shift: &Fp192Var,
    x: &Fp192Var,
) -> Fp192Var {
    let x_pow = pow_const_u128_pub(builder, x, domain_size as u128);
    let shift_pow = pow_const_u128_pub(builder, shift, domain_size as u128);
    builder.sub_vars(&x_pow, &shift_pow)
}

// ---------------------------------------------------------------------------
// (4) Degree-correction polynomial evaluation
// ---------------------------------------------------------------------------

/// In-circuit evaluation of the degree-correction polynomial at `x`, matching
/// `evaluate(degree_correction_polynomial(r, kappa), x)`.
///
/// `degree_correction_polynomial(r, kappa)` (`stir_poly.rs:224`) returns the
/// coefficient vector `[1, r, r^2, ..., r^{kappa+1}]` (length `kappa + 2`).
/// This gadget builds those `kappa + 2` coefficient wires in-circuit as a
/// power chain (`r^{j} = r^{j-1} * r`, real mul constraints), then Horner-
/// evaluates at `x` via [`evaluate_circuit`].
///
/// `r` and `x` are wires; `kappa` is a public structural parameter.
pub fn degree_correction_evaluate_circuit(
    builder: &mut Fp192R1csBuilder,
    r: &Fp192Var,
    kappa: usize,
    x: &Fp192Var,
) -> Fp192Var {
    let len = kappa + 2;
    let mut coeffs: Vec<Fp192Var> = Vec::with_capacity(len);
    // power = r^0 = 1, then *= r each step (mirrors stir_poly.rs:227-231).
    let mut power = builder.constant_pub(Fp192::one());
    for _ in 0..len {
        coeffs.push(power.clone());
        power = builder.mul_pub(&power, r);
    }
    evaluate_circuit(builder, &coeffs, x)
}

// ---------------------------------------------------------------------------
// (5) Schoolbook polynomial multiplication (Stage 4c-3a)
// ---------------------------------------------------------------------------

/// In-circuit schoolbook polynomial multiplication, matching
/// `stir_poly::multiply` (`stir_poly.rs:82`) coefficient-for-coefficient:
///
/// ```text
/// out[i + j] += a[i] * b[j]    (ascending-degree, out len = a.len()+b.len()-1)
/// ```
///
/// `a` and `b` are coefficient wires (ascending degree). Returns the
/// `a.len() + b.len() - 1` product-coefficient wires (ascending degree). Empty
/// `a` or empty `b` returns an empty `Vec`, matching the software's early return
/// for `a.is_empty() || b.is_empty()`.
///
/// ### Why every output is pinned (no free witness)
/// Each partial product `a[i] * b[j]` is emitted as a REAL multiplication
/// constraint via [`Fp192R1csBuilder::mul_pub`], and each accumulation into
/// `out[i+j]` is a REAL linear constraint via
/// [`Fp192R1csBuilder::add_vars`]. The output coefficient wires are therefore
/// constrained sums of constrained products — there is no unconstrained witness
/// a malicious prover could set freely. Corrupting any output coefficient breaks
/// the `add_vars` linear constraint that defines it.
///
/// The software's `ai.is_zero()` short-circuit (a timing optimisation) is NOT
/// replicated: skipping the zero rows would make the constraint COUNT
/// input-dependent, which an R1CS must not be. Emitting the `0 * b[j]` rows
/// anyway yields the identical coefficient values (adding `0` changes nothing),
/// so the gadget output matches the software output exactly while keeping the
/// constraint structure uniform.
pub fn multiply_circuit(
    builder: &mut Fp192R1csBuilder,
    a: &[Fp192Var],
    b: &[Fp192Var],
) -> Vec<Fp192Var> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let out_len = a.len() + b.len() - 1;
    let mut out: Vec<Fp192Var> =
        (0..out_len).map(|_| builder.constant_pub(Fp192::zero())).collect();
    for (i, ai) in a.iter().enumerate() {
        for (j, bj) in b.iter().enumerate() {
            // term = a[i] * b[j]  (real mul constraint).
            let term = builder.mul_pub(ai, bj);
            // out[i+j] += term     (real linear constraint).
            out[i + j] = builder.add_vars(&out[i + j], &term);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// (6) Quotient by a linear factor (x - root) (Stage 4c-3a) — the division trap
// ---------------------------------------------------------------------------

/// In-circuit exact division of `coeffs` by `(x - root)`, matching
/// `stir_poly::divide_by_linear` (`stir_poly.rs:169`). The software requires the
/// division to be exact (`p(root) = 0`); it returns the quotient `q(x)` of
/// degree `deg(coeffs) - 1` and ERRORS (`QuotientRemainderNonZero`) otherwise.
///
/// Returns the `n - 1` quotient-coefficient wires (ascending degree) for an
/// `n`-coefficient input. Empty input returns an empty `Vec`. A length-1 input
/// (constant) is only divisible when that constant is `0`, in which case the
/// quotient is empty; a non-zero constant is a precondition violation (the
/// software returns `QuotientRemainderNonZero`) and panics here, since an R1CS
/// gadget has no error channel and the `r == 0` constraint would be
/// unsatisfiable.
///
/// ## The R1CS division trap (handled — quotient is NOT a free witness)
///
/// The quotient coefficients are allocated as WITNESS wires (their values come
/// from the same Ruffini recurrence the software runs), and then PINNED by the
/// polynomial identity
///
/// ```text
///     p(x) == q(x) * (x - root) + r
/// ```
///
/// enforced COEFFICIENT-BY-COEFFICIENT as real constraints. Writing
/// `(x - root)` as `[-root, 1]`, the product `q(x)*(x - root)` has coefficient
/// `k` equal to `q_{k-1} - root * q_k` (with `q_{-1} = q_n = 0`). The remainder
/// `r` is a single constant wire (degree 0). The enforced rows are:
///
/// ```text
///     k = 0:        p_0       == r - root * q_0
///     1 <= k <= n-2: p_k      == q_{k-1} - root * q_k
///     k = n-1:      p_{n-1}   == q_{n-2}
///     exactness:    r         == 0
/// ```
///
/// These `n + 1` equality constraints fully determine the `n - 1` quotient wires
/// and the remainder wire, and the `r == 0` row encodes the software's
/// `remainder.is_zero()` exactness check. An unconstrained quotient would be an
/// under-constraining hole; corrupting any `q_k` violates the identity row(s)
/// that mention it.
///
/// # Panics
/// Panics if a non-zero constant is passed (software: `QuotientRemainderNonZero`)
/// or if `evaluate(coeffs, root) != 0` (the division is not exact, so `r == 0`
/// would be unsatisfiable) — refusing to emit an unsatisfiable constraint
/// system silently, mirroring the software's error return.
pub fn divide_by_linear_circuit(
    builder: &mut Fp192R1csBuilder,
    coeffs: &[Fp192Var],
    root: &Fp192Var,
) -> Vec<Fp192Var> {
    let n = coeffs.len();
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        // Constant input: divisible by (x - root) only if the constant is 0.
        assert!(
            coeffs[0].value().is_zero(),
            "divide_by_linear_circuit: non-zero constant is not divisible by \
             (x - root) (software: QuotientRemainderNonZero)",
        );
        return Vec::new();
    }

    // --- Compute the quotient values via the SAME Ruffini recurrence the
    //     software runs (stir_poly.rs:185-189), as witness values. ---
    let mut q_vals = vec![Fp192::zero(); n - 1];
    q_vals[n - 2] = coeffs[n - 1].value().clone();
    for i in (0..(n - 2)).rev() {
        q_vals[i] =
            coeffs[i + 1].value().clone() + root.value().clone() * q_vals[i + 1].clone();
    }
    // Remainder value: r = p_0 + root * q_0  (must be 0 for exact division).
    let r_val = coeffs[0].value().clone() + root.value().clone() * q_vals[0].clone();
    assert!(
        r_val.is_zero(),
        "divide_by_linear_circuit: division is not exact (p(root) != 0) \
         (software: QuotientRemainderNonZero); r == 0 would be unsatisfiable",
    );

    // --- Allocate quotient + remainder as WITNESS wires (free until pinned). ---
    let q: Vec<Fp192Var> = q_vals
        .iter()
        .map(|v| builder.alloc_witness_pub(v.clone()))
        .collect();
    let r = builder.alloc_witness_pub(r_val);

    // --- Pin them with the identity p(x) == q(x)*(x - root) + r, coeff-by-coeff.
    // For each k, build the wire for [q*(x - root) + r]_k and enforce it equals
    // p_k = coeffs[k] as a real equality constraint.
    for k in 0..n {
        // prod_k = q_{k-1} - root * q_k   (with out-of-range q treated as 0).
        // term_low  = q_{k-1}              (present iff k >= 1)
        // term_high = root * q_k           (present iff k <= n-2, i.e. q_k exists)
        let prod_k: Fp192Var = match (k >= 1, k <= n - 2) {
            (true, true) => {
                // q_{k-1} - root * q_k
                let root_qk = builder.mul_pub(root, &q[k]);
                builder.sub_vars(&q[k - 1], &root_qk)
            }
            (true, false) => {
                // k == n-1: only q_{n-2}
                q[k - 1].clone()
            }
            (false, true) => {
                // k == 0: -root * q_0
                let root_q0 = builder.mul_pub(root, &q[0]);
                let zero = builder.constant_pub(Fp192::zero());
                builder.sub_vars(&zero, &root_q0)
            }
            (false, false) => {
                // n == 1 handled above; unreachable for n >= 2.
                unreachable!("n >= 2 guaranteed above")
            }
        };
        // Add the remainder only into the degree-0 coefficient.
        let rhs = if k == 0 {
            builder.add_vars(&prod_k, &r)
        } else {
            prod_k
        };
        // Enforce p_k == rhs  (real equality constraint pinning the quotient).
        builder.enforce_eq_pub(&coeffs[k], &rhs);
    }

    // --- Exactness: r == 0, mirroring the software's remainder.is_zero(). ---
    let zero = builder.constant_pub(Fp192::zero());
    builder.enforce_eq_pub(&r, &zero);

    q
}

// ---------------------------------------------------------------------------
// Local helper: base^exp for a small u128 exponent, square-and-multiply.
// ---------------------------------------------------------------------------

/// `base^exp` for a `u128` exponent via square-and-multiply, each squaring /
/// multiply a real R1CS constraint. Mirrors the private
/// `Fp192R1csBuilder::pow_const_u128` (the griffin gadget keeps that private),
/// re-expressed here over the public `mul_pub` / `constant_pub` surface.
/// `exp == 0` returns a constant-1 wire (matching `Fp192::pow_u128(0) = 1`).
fn pow_const_u128_pub(builder: &mut Fp192R1csBuilder, base: &Fp192Var, exp: u128) -> Fp192Var {
    if exp == 0 {
        return builder.constant_pub(Fp192::one());
    }
    let mut result: Option<Fp192Var> = None;
    let mut current = base.clone();
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = Some(match result {
                None => current.clone(),
                Some(r) => builder.mul_pub(&r, &current),
            });
        }
        e >>= 1;
        if e > 0 {
            current = builder.mul_pub(&current, &current);
        }
    }
    result.expect("exp > 0 guarantees a result")
}

// ---------------------------------------------------------------------------
// Build wrappers: stand up a complete R1CS for one gadget invocation, with the
// witness assigned by the gadget's own computation. Used by the gate tests.
// ---------------------------------------------------------------------------

/// Build the R1CS for `evaluate(coeffs, x)`. Returns the system and the output
/// wire index (read `r1cs.assignment[out_idx]` for the claimed evaluation).
pub fn build_evaluate(coeffs: &[Fp192], x: Fp192) -> (Fp192R1cs, usize) {
    let mut builder = Fp192R1csBuilder::new();
    let coeff_vars: Vec<Fp192Var> = coeffs.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let x_var = builder.alloc_input(x);
    let out = evaluate_circuit(&mut builder, &coeff_vars, &x_var);
    let out_idx = out.index();
    (builder.finalize(), out_idx)
}

/// Build the R1CS for `lagrange_interpolate(domain, values)`. Returns the
/// system and the `n` coefficient-wire indices (ascending degree).
pub fn build_lagrange_interpolate(
    domain: &[Fp192],
    values: &[Fp192],
) -> (Fp192R1cs, Vec<usize>) {
    let mut builder = Fp192R1csBuilder::new();
    let domain_vars: Vec<Fp192Var> =
        domain.iter().map(|d| builder.alloc_input(d.clone())).collect();
    let value_vars: Vec<Fp192Var> =
        values.iter().map(|v| builder.alloc_input(v.clone())).collect();
    let coeffs = lagrange_interpolate_circuit(&mut builder, &domain_vars, &value_vars);
    let coeff_idx: Vec<usize> = coeffs.iter().map(|c| c.index()).collect();
    (builder.finalize(), coeff_idx)
}

/// Build the R1CS for `vanishing_poly_evaluate(domain_size, shift, x)`. Returns
/// the system and the output wire index.
pub fn build_vanishing_poly_evaluate(
    domain_size: usize,
    shift: Fp192,
    x: Fp192,
) -> (Fp192R1cs, usize) {
    let mut builder = Fp192R1csBuilder::new();
    let shift_var = builder.alloc_input(shift);
    let x_var = builder.alloc_input(x);
    let out = vanishing_poly_evaluate_circuit(&mut builder, domain_size, &shift_var, &x_var);
    let out_idx = out.index();
    (builder.finalize(), out_idx)
}

/// Build the R1CS for `evaluate(degree_correction_polynomial(r, kappa), x)`.
/// Returns the system and the output wire index.
pub fn build_degree_correction_evaluate(
    r: Fp192,
    kappa: usize,
    x: Fp192,
) -> (Fp192R1cs, usize) {
    let mut builder = Fp192R1csBuilder::new();
    let r_var = builder.alloc_input(r);
    let x_var = builder.alloc_input(x);
    let out = degree_correction_evaluate_circuit(&mut builder, &r_var, kappa, &x_var);
    let out_idx = out.index();
    (builder.finalize(), out_idx)
}

/// Build the R1CS for `multiply(a, b)`. Returns the system and the
/// `a.len()+b.len()-1` product-coefficient wire indices (ascending degree); an
/// empty input pair yields an empty index vector.
pub fn build_multiply(a: &[Fp192], b: &[Fp192]) -> (Fp192R1cs, Vec<usize>) {
    let mut builder = Fp192R1csBuilder::new();
    let a_vars: Vec<Fp192Var> = a.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let b_vars: Vec<Fp192Var> = b.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let out = multiply_circuit(&mut builder, &a_vars, &b_vars);
    let out_idx: Vec<usize> = out.iter().map(|c| c.index()).collect();
    (builder.finalize(), out_idx)
}

/// Build the R1CS for `divide_by_linear(coeffs, root)`. Returns the system and
/// the `coeffs.len()-1` quotient-coefficient wire indices (ascending degree).
pub fn build_divide_by_linear(coeffs: &[Fp192], root: Fp192) -> (Fp192R1cs, Vec<usize>) {
    let mut builder = Fp192R1csBuilder::new();
    let coeff_vars: Vec<Fp192Var> =
        coeffs.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let root_var = builder.alloc_input(root);
    let q = divide_by_linear_circuit(&mut builder, &coeff_vars, &root_var);
    let q_idx: Vec<usize> = q.iter().map(|c| c.index()).collect();
    (builder.finalize(), q_idx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::plum::stir_poly::{
        degree_correction_polynomial, divide_by_linear, evaluate, lagrange_interpolate, multiply,
    };
    use crate::signatures::plum::sumcheck::vanishing_poly_evaluate;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rand_coeffs(n: usize, seed: u64) -> Vec<Fp192> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        (0..n).map(|_| Fp192::rand(&mut rng)).collect()
    }

    fn rand_distinct_points(n: usize, seed: u64) -> Vec<Fp192> {
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

    // -------------------------------------------------------------------
    // GATE (1): Horner evaluate.
    // -------------------------------------------------------------------
    #[test]
    fn evaluate_gadget_gate() {
        let mut count = None;
        for (s, n) in [(0xE1u64, 1usize), (0xE2, 4), (0xE3, 8), (0xE4, 13), (0xE5, 32)] {
            let coeffs = rand_coeffs(n, s);
            let x = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(s ^ 0xAA));
            let expected = evaluate(&coeffs, &x);

            let (r1cs, out_idx) = build_evaluate(&coeffs, x.clone());
            // (1) honest witness satisfies all constraints.
            assert!(
                r1cs.check_satisfied().is_ok(),
                "evaluate: honest witness unsatisfied (n={n})",
            );
            // (2) gadget output == software output.
            assert_eq!(
                r1cs.assignment[out_idx], expected,
                "evaluate: gadget output != software evaluate (n={n})",
            );
            eprintln!("[GATE] evaluate (n={n}): {} constraints", r1cs.num_constraints());
            count = Some(r1cs.num_constraints());
        }
        // (3) corrupted output wire rejected.
        {
            let coeffs = rand_coeffs(6, 0xE6);
            let x = Fp192::from_u64(99);
            let (mut r1cs, out_idx) = build_evaluate(&coeffs, x);
            assert!(r1cs.check_satisfied().is_ok());
            r1cs.assignment[out_idx] = r1cs.assignment[out_idx].clone() + Fp192::one();
            assert!(
                r1cs.check_satisfied().is_err(),
                "evaluate: corrupted output wire ACCEPTED",
            );
        }
        eprintln!("[GATE] evaluate (n=32): {} constraints", count.unwrap());
    }

    // -------------------------------------------------------------------
    // GATE (2): Lagrange interpolation (DIVISIONS).
    // -------------------------------------------------------------------
    #[test]
    fn lagrange_interpolate_gadget_gate() {
        let mut report = None;
        for (sd, sv, n) in [
            (0x1001u64, 0x2001u64, 2usize),
            (0x1002, 0x2002, 4), // STIR eta = 4
            (0x1003, 0x2003, 4),
            (0x1004, 0x2004, 6),
            (0x1005, 0x2005, 8),
        ] {
            let domain = rand_distinct_points(n, sd);
            let values = rand_coeffs(n, sv);
            let expected = lagrange_interpolate(&domain, &values).unwrap();

            let (r1cs, coeff_idx) = build_lagrange_interpolate(&domain, &values);
            // (1) honest witness satisfies all constraints (incl. inv*denom==1).
            assert!(
                r1cs.check_satisfied().is_ok(),
                "lagrange: honest witness unsatisfied (n={n})",
            );
            // (2) gadget coefficient wires == software coefficients.
            assert_eq!(coeff_idx.len(), expected.len(), "lagrange: coeff count (n={n})");
            for (k, &idx) in coeff_idx.iter().enumerate() {
                assert_eq!(
                    r1cs.assignment[idx], expected[k],
                    "lagrange: coeff {k} != software (n={n})",
                );
            }
            eprintln!("[GATE] lagrange (n={n}): {} constraints", r1cs.num_constraints());
            report = Some((n, r1cs.num_constraints()));
        }

        // (3a) corrupted output coefficient wire rejected.
        {
            let domain = rand_distinct_points(4, 0x1111);
            let values = rand_coeffs(4, 0x2222);
            let (mut r1cs, coeff_idx) = build_lagrange_interpolate(&domain, &values);
            assert!(r1cs.check_satisfied().is_ok());
            r1cs.assignment[coeff_idx[0]] = r1cs.assignment[coeff_idx[0]].clone() + Fp192::one();
            assert!(
                r1cs.check_satisfied().is_err(),
                "lagrange: corrupted coeff wire ACCEPTED",
            );
        }
        // (3b) THE DIVISION TRAP: corrupting an inverse witness must be rejected
        //      by the inv*denom==1 constraint. We locate an inverse wire by
        //      perturbing each interior wire and confirming >=1 rejection; more
        //      directly, perturb ALL interior wires and require every one is
        //      caught (no unconstrained wire). This proves no unconstrained hole.
        {
            let domain = rand_distinct_points(4, 0x3333);
            let values = rand_coeffs(4, 0x4444);
            let (base, _coeff_idx) = build_lagrange_interpolate(&domain, &values);
            assert!(base.check_satisfied().is_ok());
            // Inputs occupy indices 1..=(2n); index 0 is the constant-1 slot.
            // Every wire from the first non-input onward is gadget-internal and
            // must be pinned by some constraint.
            let first_internal = 1 + 2 * domain.len();
            let mut all_caught = true;
            for wi in first_internal..base.assignment.len() {
                let mut r = base.clone();
                r.assignment[wi] = r.assignment[wi].clone() + Fp192::one();
                if r.check_satisfied().is_ok() {
                    all_caught = false;
                    eprintln!("[GATE] lagrange: interior wire {wi} UNCONSTRAINED");
                }
            }
            assert!(
                all_caught,
                "lagrange: at least one interior wire (possibly an inverse) is \
                 UNCONSTRAINED — under-constraining hole",
            );
        }
        // (3c) DIRECT INVERSE SOUNDNESS: locate the `inv*denom==1` constraints
        //      (signature: a=[(inv,1)], b=[(denom,1)], c=[(one,1)] with the
        //      c-wire holding value 1) and assign a WRONG inverse value
        //      inv' = inv + 1 != 1/denom. The `inv*denom==1` row must reject it.
        //      This pins the rejection to the named inverse constraint, not to
        //      some downstream consumer.
        {
            let domain = rand_distinct_points(4, 0x5151);
            let values = rand_coeffs(4, 0x6262);
            let (base, _coeff_idx) = build_lagrange_interpolate(&domain, &values);
            assert!(base.check_satisfied().is_ok());
            let mut probed = 0usize;
            for con in &base.constraints {
                // single-term, coeff-1 a/b/c with c on a value-1 wire.
                let is_single_one = |row: &Vec<(usize, Fp192)>| {
                    row.len() == 1 && row[0].1 == Fp192::one()
                };
                if is_single_one(&con.a)
                    && is_single_one(&con.b)
                    && is_single_one(&con.c)
                    && base.assignment[con.c[0].0] == Fp192::one()
                {
                    let inv_idx = con.a[0].0;
                    let denom_idx = con.b[0].0;
                    // Confirm this really is an inverse pair: inv*denom == 1.
                    if base.assignment[inv_idx].clone() * base.assignment[denom_idx].clone()
                        != Fp192::one()
                    {
                        continue;
                    }
                    let mut r = base.clone();
                    // Wrong inverse value (inv' != 1/denom since denom != 0).
                    r.assignment[inv_idx] = r.assignment[inv_idx].clone() + Fp192::one();
                    assert!(
                        r.check_satisfied().is_err(),
                        "lagrange: WRONG inverse value ACCEPTED at wire {inv_idx} \
                         (inv*denom==1 did not fire)",
                    );
                    probed += 1;
                }
            }
            assert!(
                probed >= 1,
                "lagrange: no inv*denom==1 constraint found to probe \
                 (inverse trap may be missing)",
            );
            eprintln!("[GATE] lagrange: {probed} inverse wire(s) directly probed, all rejected");
        }

        let (n, c) = report.unwrap();
        eprintln!("[GATE] lagrange (n={n}): {c} constraints");
    }

    // -------------------------------------------------------------------
    // GATE (3): Vanishing polynomial Z_H(x) = x^|H| - shift^|H|.
    // -------------------------------------------------------------------
    #[test]
    fn vanishing_poly_evaluate_gadget_gate() {
        let mut count = None;
        for (sx, ss, hsize) in [
            (0x51u64, 0x61u64, 4usize),
            (0x52, 0x62, 8),
            (0x53, 0x63, 16),
            (0x54, 0x64, 64),
            (0x55, 0x65, 1),
        ] {
            let x = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(sx));
            let shift = Fp192::rand_nonzero(&mut ChaCha20Rng::seed_from_u64(ss));
            let expected = vanishing_poly_evaluate(hsize, &shift, &x);

            let (r1cs, out_idx) = build_vanishing_poly_evaluate(hsize, shift.clone(), x.clone());
            assert!(
                r1cs.check_satisfied().is_ok(),
                "vanishing: honest witness unsatisfied (|H|={hsize})",
            );
            assert_eq!(
                r1cs.assignment[out_idx], expected,
                "vanishing: gadget output != software (|H|={hsize})",
            );
            eprintln!("[GATE] vanishing (|H|={hsize}): {} constraints", r1cs.num_constraints());
            count = Some((hsize, r1cs.num_constraints()));
        }
        // (3) corrupted output wire rejected.
        {
            let (mut r1cs, out_idx) =
                build_vanishing_poly_evaluate(16, Fp192::from_u64(5), Fp192::from_u64(9));
            assert!(r1cs.check_satisfied().is_ok());
            r1cs.assignment[out_idx] = r1cs.assignment[out_idx].clone() + Fp192::one();
            assert!(
                r1cs.check_satisfied().is_err(),
                "vanishing: corrupted output wire ACCEPTED",
            );
        }
        let (h, c) = count.unwrap();
        eprintln!("[GATE] vanishing (|H|={h}): {c} constraints");
    }

    // -------------------------------------------------------------------
    // GATE (4): Degree-correction polynomial evaluation.
    // -------------------------------------------------------------------
    #[test]
    fn degree_correction_evaluate_gadget_gate() {
        let mut count = None;
        for (sr, sx, kappa) in [
            (0x71u64, 0x81u64, 2usize),
            (0x72, 0x82, 5),
            (0x73, 0x83, 7),
            (0x74, 0x84, 16),
            (0x75, 0x85, 26), // ~ STIR kappa at lambda=128
        ] {
            let r = Fp192::rand_nonzero(&mut ChaCha20Rng::seed_from_u64(sr));
            let x = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(sx));
            // Software reference: build coeffs then Horner-evaluate.
            let t_coeffs = degree_correction_polynomial(&r, kappa);
            let expected = evaluate(&t_coeffs, &x);

            let (r1cs, out_idx) = build_degree_correction_evaluate(r.clone(), kappa, x.clone());
            assert!(
                r1cs.check_satisfied().is_ok(),
                "degree_correction: honest witness unsatisfied (kappa={kappa})",
            );
            assert_eq!(
                r1cs.assignment[out_idx], expected,
                "degree_correction: gadget output != software (kappa={kappa})",
            );
            eprintln!("[GATE] degree_correction (kappa={kappa}): {} constraints", r1cs.num_constraints());
            count = Some((kappa, r1cs.num_constraints()));
        }
        // (3) corrupted output wire rejected.
        {
            let (mut r1cs, out_idx) =
                build_degree_correction_evaluate(Fp192::from_u64(3), 5, Fp192::from_u64(5));
            assert!(r1cs.check_satisfied().is_ok());
            r1cs.assignment[out_idx] = r1cs.assignment[out_idx].clone() + Fp192::one();
            assert!(
                r1cs.check_satisfied().is_err(),
                "degree_correction: corrupted output wire ACCEPTED",
            );
        }
        let (k, c) = count.unwrap();
        eprintln!("[GATE] degree_correction (kappa={k}): {c} constraints");
    }

    // -------------------------------------------------------------------
    // GATE (5): Schoolbook polynomial multiplication (Stage 4c-3a).
    // -------------------------------------------------------------------
    #[test]
    fn multiply_gadget_gate() {
        let mut report = None;
        // >= 4 fresh input pairs of varying sizes (incl. STIR-scale).
        for (sa, sb, na, nb) in [
            (0xA1u64, 0xB1u64, 1usize, 1usize),
            (0xA2, 0xB2, 4, 4),
            (0xA3, 0xB3, 6, 4), // matches stir_poly's multiply_matches_pointwise
            (0xA4, 0xB4, 8, 5),
            (0xA5, 0xB5, 32, 32),
        ] {
            let a = rand_coeffs(na, sa);
            let b = rand_coeffs(nb, sb);
            let expected = multiply(&a, &b);

            let (r1cs, out_idx) = build_multiply(&a, &b);
            // (1) honest witness satisfies all constraints.
            assert!(
                r1cs.check_satisfied().is_ok(),
                "multiply: honest witness unsatisfied (na={na}, nb={nb})",
            );
            // (2) gadget output == software output, coefficient-for-coefficient.
            assert_eq!(
                out_idx.len(),
                expected.len(),
                "multiply: output length != software (na={na}, nb={nb})",
            );
            for (k, &idx) in out_idx.iter().enumerate() {
                assert_eq!(
                    r1cs.assignment[idx], expected[k],
                    "multiply: coeff {k} != software (na={na}, nb={nb})",
                );
            }
            eprintln!(
                "[GATE] multiply (na={na}, nb={nb}): {} constraints",
                r1cs.num_constraints()
            );
            report = Some((na, nb, r1cs.num_constraints()));
        }

        // (4) a corrupted product coefficient fails >= 1 constraint.
        {
            let a = rand_coeffs(6, 0xA6);
            let b = rand_coeffs(4, 0xB6);
            let (mut r1cs, out_idx) = build_multiply(&a, &b);
            assert!(r1cs.check_satisfied().is_ok());
            // Corrupt a mid-degree product coefficient.
            let target = out_idx[out_idx.len() / 2];
            r1cs.assignment[target] = r1cs.assignment[target].clone() + Fp192::one();
            assert!(
                r1cs.check_satisfied().is_err(),
                "multiply: corrupted product coefficient ACCEPTED",
            );
        }

        // No-output-is-free check: every output wire is pinned. Perturbing any
        // output coefficient must be caught (proves the accumulation binds it).
        {
            let a = rand_coeffs(5, 0xA7);
            let b = rand_coeffs(5, 0xB7);
            let (base, out_idx) = build_multiply(&a, &b);
            assert!(base.check_satisfied().is_ok());
            for &idx in &out_idx {
                let mut r = base.clone();
                r.assignment[idx] = r.assignment[idx].clone() + Fp192::one();
                assert!(
                    r.check_satisfied().is_err(),
                    "multiply: output wire {idx} UNCONSTRAINED (free product coeff)",
                );
            }
        }

        let (na, nb, c) = report.unwrap();
        eprintln!("[GATE] multiply (na={na}, nb={nb}): {c} constraints");
    }

    // -------------------------------------------------------------------
    // GATE (6): Quotient by a linear factor (x - root) — the division trap.
    // -------------------------------------------------------------------
    #[test]
    fn divide_by_linear_gadget_gate() {
        // Helper: build p(x) = q(x) * (x - root) with q random, so the
        // division is exact and divide_by_linear(p, root) == q. Mirrors the
        // construction in stir_poly's divide_by_linear_product test.
        fn build_exact_dividend(q: &[Fp192], root: &Fp192) -> Vec<Fp192> {
            // multiply q by (x - root) = [-root, 1].
            multiply(q, &[Fp192::zero() - root.clone(), Fp192::one()])
        }

        let mut report = None;
        // >= 4 fresh (random q, random root) inputs of varying degree.
        for (sq, sr, nq) in [
            (0xC1u64, 0xD1u64, 1usize),
            (0xC2, 0xD2, 3),
            (0xC3, 0xD3, 5),
            (0xC4, 0xD4, 8),
            (0xC5, 0xD5, 16),
        ] {
            let q_ref = rand_coeffs(nq, sq);
            let root = Fp192::rand_nonzero(&mut ChaCha20Rng::seed_from_u64(sr));
            let p = build_exact_dividend(&q_ref, &root);
            // Sanity: software agrees the division is exact and returns q_ref.
            let q_sw = divide_by_linear(&p, &root)
                .expect("constructed dividend is exact by build_exact_dividend");
            assert_eq!(q_sw, q_ref, "test setup: software quotient != q_ref (nq={nq})");

            let (r1cs, q_idx) = build_divide_by_linear(&p, root.clone());
            // (1) honest witness satisfies all constraints (incl. identity + r==0).
            assert!(
                r1cs.check_satisfied().is_ok(),
                "divide_by_linear: honest witness unsatisfied (nq={nq})",
            );
            // (2) gadget quotient wires == software quotient.
            assert_eq!(
                q_idx.len(),
                q_sw.len(),
                "divide_by_linear: quotient length != software (nq={nq})",
            );
            for (k, &idx) in q_idx.iter().enumerate() {
                assert_eq!(
                    r1cs.assignment[idx], q_sw[k],
                    "divide_by_linear: quotient coeff {k} != software (nq={nq})",
                );
            }
            eprintln!(
                "[GATE] divide_by_linear (deg p={}, |q|={}): {} constraints",
                p.len() - 1,
                q_idx.len(),
                r1cs.num_constraints()
            );
            report = Some((q_idx.len(), r1cs.num_constraints()));
        }

        // (3) THE TRAP: a corrupted quotient coefficient must fail >= 1
        //     constraint — the q*(x-root)+r == p identity catches it.
        {
            let q_ref = rand_coeffs(6, 0xC6);
            let root = Fp192::rand_nonzero(&mut ChaCha20Rng::seed_from_u64(0xD6));
            let p = build_exact_dividend(&q_ref, &root);
            let (base, q_idx) = build_divide_by_linear(&p, root);
            assert!(base.check_satisfied().is_ok());
            // Corrupt EVERY quotient coefficient in turn; each must be caught.
            for &idx in &q_idx {
                let mut r = base.clone();
                r.assignment[idx] = r.assignment[idx].clone() + Fp192::one();
                assert!(
                    r.check_satisfied().is_err(),
                    "divide_by_linear: corrupted quotient coeff at wire {idx} ACCEPTED \
                     — quotient is a FREE witness (under-constraining hole)",
                );
            }
        }

        // (3'') WRONG QUOTIENT, RIGHT DEGREE: replace the ENTIRE quotient
        //     witness with a different degree-(n-2) polynomial q' = s*q
        //     (s != 0, s != 1). This is a coherent alternative quotient of the
        //     SAME degree (leading coeff s*q_{n-2} != 0), not a single-coeff
        //     bump. The q*(x-root)+r == p identity must reject it for EVERY
        //     remainder value, because (q - q')*(x-root) has degree |q| >= 1
        //     while it would have to equal a constant (r' - r) to be absorbed.
        {
            let q_ref = rand_coeffs(5, 0xC8); // |q| = 5  => degree-4 quotient
            let root = Fp192::rand_nonzero(&mut ChaCha20Rng::seed_from_u64(0xD8));
            let p = build_exact_dividend(&q_ref, &root);
            let (base, q_idx) = build_divide_by_linear(&p, root);
            assert!(base.check_satisfied().is_ok());
            // Confirm the leading quotient coeff is nonzero so q' = s*q keeps
            // the same degree (does not collapse to a lower-degree polynomial).
            let lead = base.assignment[*q_idx.last().unwrap()].clone();
            assert!(!lead.is_zero(), "test setup: leading quotient coeff is zero");
            // Overwrite ONLY the quotient witness wires (not the remainder, not
            // any intermediate wire), so any rejection is attributable to the
            // q*(x-root)+r == p identity rows and not to a corrupted internal
            // wire. The remainder keeps its honest value (0). The identity must
            // reject: q' = 2q differs from q in every nonzero coefficient, so the
            // degree-(n-1) rows mentioning q'_{k} can no longer equal p_k.
            let s = Fp192::from_u64(2);
            let mut r = base.clone();
            for &idx in &q_idx {
                r.assignment[idx] = s.clone() * r.assignment[idx].clone();
            }
            let verdict = r.check_satisfied();
            assert!(
                verdict.is_err(),
                "divide_by_linear: WRONG quotient q'=2q (same degree, only \
                 quotient wires overwritten) ACCEPTED — identity failed to fire",
            );
            eprintln!(
                "[GATE] divide_by_linear: wrong quotient q'=2q (same degree) rejected \
                 at constraint {:?}",
                verdict.unwrap_err()
            );
        }

        // Exactness-row check: corrupting the remainder witness (set r != 0) must
        // be rejected by the r == 0 constraint. We locate the remainder wire as
        // the witness that, when bumped, still satisfies the per-coefficient
        // identity for k>=1 but breaks k==0 and/or r==0. Direct approach: rebuild
        // and confirm that NO interior wire is free (every internal wire pinned).
        {
            let q_ref = rand_coeffs(5, 0xC7);
            let root = Fp192::rand_nonzero(&mut ChaCha20Rng::seed_from_u64(0xD7));
            let p = build_exact_dividend(&q_ref, &root);
            let (base, _q_idx) = build_divide_by_linear(&p, root);
            assert!(base.check_satisfied().is_ok());
            // Inputs occupy indices 1..=(p.len()+1): p.len() coeffs + 1 root.
            let first_internal = 1 + p.len() + 1;
            let mut all_caught = true;
            for wi in first_internal..base.assignment.len() {
                let mut r = base.clone();
                r.assignment[wi] = r.assignment[wi].clone() + Fp192::one();
                if r.check_satisfied().is_ok() {
                    all_caught = false;
                    eprintln!("[GATE] divide_by_linear: interior wire {wi} UNCONSTRAINED");
                }
            }
            assert!(
                all_caught,
                "divide_by_linear: an interior wire (quotient/remainder/intermediate) is \
                 UNCONSTRAINED — under-constraining hole",
            );
        }

        let (qlen, c) = report.unwrap();
        eprintln!("[GATE] divide_by_linear (|q|={qlen}): {c} constraints");
    }
}
