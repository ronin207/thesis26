//! Stage 4c-3c: the STIR verifier's OUT-OF-DOMAIN (OOD) consistency check and
//! the Algorithm-6 FINAL-POLYNOMIAL fiber check as R1CS gadgets over PLUM's
//! `Fp192`, COMPOSING the Stage-4b polynomial gadgets
//! ([`lagrange_interpolate_circuit`], [`evaluate_circuit`]) with the Stage-2
//! [`Fp192R1csBuilder`].
//!
//! ## Software references (matched EXACTLY)
//!
//! ### (A) OOD consistency check
//! `signatures::plum::verify::plum_verify` (`src/signatures/plum/verify.rs`,
//! the round-0 sumcheck-identity block `verify.rs:537-560`):
//!
//! ```text
//! let g_hat_coeffs = lagrange_interpolate(interp_points, interp_values)?; // 545
//! for q in 0..total_queries {                                             // 549
//!     if interp_set.contains(&q) { continue; }                            // 550
//!     let (ref s, ref g_value) = g_at_query[q];                           // 553
//!     let expected = evaluate(&g_hat_coeffs, s);                          // 554
//!     if expected != *g_value {                                           // 555
//!         return Reject(SumcheckIdentityViolation { query: q });          // 556
//!     }
//! }
//! ```
//!
//! The verifier interpolates the degree-`< |H|` polynomial `g_hat` from `|H|`
//! distinct query points, then re-evaluates it at the REMAINING query points
//! (points OUTSIDE the interpolation set — the "out-of-domain" points relative to
//! that set) and ENFORCES that the interpolant's value EQUALS the claimed value
//! `g_value` opened at each such point. [`ood_consistency_circuit`] mirrors this:
//! interpolate, evaluate at the OOD point, `enforce_eq` with the claimed value.
//! The OOD point `s` and claimed value `g_value` are wire INPUTS coming from the
//! transcript-derived query data (`verify.rs:506-508`), NOT free constants.
//!
//! ### (B) Final-polynomial fiber check (Alg 6 line 18)
//! `signatures::plum::verify::plum_verify` (`verify.rs:762-781`):
//!
//! ```text
//! let p_y_coeffs = lagrange_interpolate(&fiber_x, &fiber_f_r)?;           // 763
//! let f_r_plus_1_at_r_fin = evaluate(&p_y_coeffs, &current_r_fold);       // 771
//! let r_fin = current_generator.pow_u128((b * pp.eta) as u128);          // 774
//! let claimed = evaluate(&sig.final_coefs, &r_fin);                       // 775
//! if f_r_plus_1_at_r_fin != claimed {                                     // 777
//!     return Reject(FinalPolynomialMismatch { fin_index: i });            // 779
//! }
//! ```
//!
//! The verifier interpolates `p̂_y` on the η fiber points `(fiber_x, fiber_f_r)`
//! where `fiber_f_r[t] = f̂_R(x_t)`, evaluates at the folding challenge
//! `r_R^fold` to reconstruct `f̂_{R+1}(r_i^fin)`, and ENFORCES that this equals
//! `sig.final_coefs` evaluated at `r_i^fin`. [`final_poly_fiber_circuit`] mirrors
//! this exactly: interpolate the fiber, Horner-evaluate at `r_fold`, Horner-
//! evaluate `final_coefs` at `r_fin`, `enforce_eq` the two.
//!
//! ## Scope boundary (what is IN / DEFERRED here)
//!
//! IN: the two algebraic ACCEPT conditions above, each as a REAL enforced
//! equality between two constrained interpolate/evaluate chains. The fiber values
//! `fiber_f_r` (= `f̂_R(x_t)`) are wire INPUTS — the rate-correction step that
//! derives them from the Merkle-opened `â_R` (`verify.rs:735-760`, with its own
//! `a_prime = (a_R - b_R)/Π(x-α)` division) is a DISTINCT obligation and is NOT
//! re-derived here, matching the `stir_round_fp192_gadget` per-fiber boundary.
//!
//! DEFERRED (later composition / Stage 4c-4): the FS derivation that ties the OOD
//! point / claimed value / `r_fin` / `final_coefs` to the absorbed transcript
//! (those wires are exposed as gadget inputs here so the caller — the top-level
//! verifier circuit — can bind them); the public-input/instance boundary
//! designating pk/message/roots (Stage 4c-4); and the Merkle openings of `â_R`.

use crate::primitives::field::p192::Fp192;
use crate::primitives::r1cs::griffin_fp192_gadget::{Fp192R1cs, Fp192R1csBuilder, Fp192Var};
use crate::primitives::r1cs::poly_fp192_gadget::{evaluate_circuit, lagrange_interpolate_circuit};

// ---------------------------------------------------------------------------
// (A) OOD consistency check
// ---------------------------------------------------------------------------

/// In-circuit OOD consistency: interpolate the degree-`< |interp_domain|`
/// polynomial through `(interp_domain, interp_values)`, evaluate it at
/// `ood_point`, and ENFORCE that the result equals `claimed_value`.
///
/// Matches `verify.rs:545` + `verify.rs:553-558` for ONE out-of-interpolation-set
/// query point. `interp_domain` must be DISTINCT (the software's
/// `lagrange_interpolate` precondition; the Lagrange gadget asserts it). The
/// returned wire is the interpolant evaluated at `ood_point`; the enforced
/// equality `interpolant(ood_point) == claimed_value` is the real OOD constraint
/// (a wrong claimed value, or a tampered interpolation input, breaks it).
///
/// `ood_point` and `claimed_value` are EXISTING wires (transcript/query inputs,
/// not free constants — obligation `oodConstrained`).
pub fn ood_consistency_circuit(
    builder: &mut Fp192R1csBuilder,
    interp_domain: &[Fp192Var],
    interp_values: &[Fp192Var],
    ood_point: &Fp192Var,
    claimed_value: &Fp192Var,
) -> Fp192Var {
    // g_hat = Interpolate(interp_domain, interp_values), coefficient form.
    let g_hat = lagrange_interpolate_circuit(builder, interp_domain, interp_values);
    // expected = g_hat(ood_point), Horner.
    let expected = evaluate_circuit(builder, &g_hat, ood_point);
    // REAL constraint: interpolant value at the OOD point == claimed OOD value
    // (verify.rs:555 `if expected != *g_value { reject }`).
    builder.enforce_eq_pub(&expected, claimed_value);
    expected
}

// ---------------------------------------------------------------------------
// (B) Final-polynomial fiber check (Alg 6 line 18)
// ---------------------------------------------------------------------------

/// In-circuit final-polynomial fiber check: interpolate `p̂_y` on the η fiber
/// `(fiber_x, fiber_f_r)`, evaluate at `r_fold` to reconstruct
/// `f̂_{R+1}(r_fin)`, evaluate `final_coefs` at `r_fin`, and ENFORCE the two are
/// equal.
///
/// Matches `verify.rs:763` + `verify.rs:771` + `verify.rs:775` +
/// `verify.rs:777`. The enforced equality
/// `interpolate(fiber)(r_fold) == evaluate(final_coefs, r_fin)` is the exact
/// software accept condition (`finalPolyConstrained`). `fiber_x`, `fiber_f_r`,
/// `r_fold`, `final_coefs`, `r_fin` are EXISTING wires. The reconstructed
/// `f̂_{R+1}(r_fin)` wire is returned for the caller's inspection.
///
/// `fiber_x` must be DISTINCT (Lagrange precondition; asserted by the Lagrange
/// gadget). `fiber_f_r[t] = f̂_R(x_t)` are inputs (the rate-corrected fiber
/// values), not re-derived here — see the module-level scope boundary.
pub fn final_poly_fiber_circuit(
    builder: &mut Fp192R1csBuilder,
    fiber_x: &[Fp192Var],
    fiber_f_r: &[Fp192Var],
    r_fold: &Fp192Var,
    final_coefs: &[Fp192Var],
    r_fin: &Fp192Var,
) -> Fp192Var {
    assert_eq!(
        fiber_x.len(),
        fiber_f_r.len(),
        "final_poly_fiber_circuit: fiber point/value count mismatch",
    );
    // p̂_y(x) ← Interpolate(fiber_x, fiber_f_r), coefficient form.
    let p_y = lagrange_interpolate_circuit(builder, fiber_x, fiber_f_r);
    // f̂_{R+1}(r_fin) = p̂_y(r_fold).  THE FOLD at the final folding challenge.
    let f_r_plus_1 = evaluate_circuit(builder, &p_y, r_fold);
    // claimed = final_coefs(r_fin), Horner.
    let claimed = evaluate_circuit(builder, final_coefs, r_fin);
    // REAL constraint: f̂_{R+1}(r_fin) == final_coefs(r_fin)
    // (verify.rs:777 `if f_r_plus_1_at_r_fin != claimed { reject }`).
    builder.enforce_eq_pub(&f_r_plus_1, &claimed);
    f_r_plus_1
}

// ---------------------------------------------------------------------------
// Build wrappers: stand up a complete R1CS for one gadget invocation, with the
// witness assigned by the gadget's own computation. Used by the gate tests.
// ---------------------------------------------------------------------------

/// Exposed wire indices for an OOD-consistency gadget instance.
pub struct OodConsistencyWires {
    pub interp_domain_idx: Vec<usize>,
    pub interp_values_idx: Vec<usize>,
    pub ood_point_idx: usize,
    pub claimed_value_idx: usize,
    pub expected_idx: usize,
}

/// Build the R1CS for one OOD consistency check. `interp_domain` /
/// `interp_values` define the interpolation set (|H| distinct points);
/// `ood_point` is the out-of-set query point and `claimed_value` the opened value
/// at it. The honest caller passes `claimed_value = evaluate(interpolant,
/// ood_point)` so the enforced equality holds.
pub fn build_ood_consistency(
    interp_domain: &[Fp192],
    interp_values: &[Fp192],
    ood_point: Fp192,
    claimed_value: Fp192,
) -> (Fp192R1cs, OodConsistencyWires) {
    let mut builder = Fp192R1csBuilder::new();
    let domain_vars: Vec<Fp192Var> = interp_domain
        .iter()
        .map(|d| builder.alloc_input(d.clone()))
        .collect();
    let value_vars: Vec<Fp192Var> = interp_values
        .iter()
        .map(|v| builder.alloc_input(v.clone()))
        .collect();
    let ood_point_var = builder.alloc_input(ood_point);
    let claimed_var = builder.alloc_input(claimed_value);
    let expected = ood_consistency_circuit(
        &mut builder,
        &domain_vars,
        &value_vars,
        &ood_point_var,
        &claimed_var,
    );
    let wires = OodConsistencyWires {
        interp_domain_idx: domain_vars.iter().map(|v| v.index()).collect(),
        interp_values_idx: value_vars.iter().map(|v| v.index()).collect(),
        ood_point_idx: ood_point_var.index(),
        claimed_value_idx: claimed_var.index(),
        expected_idx: expected.index(),
    };
    (builder.finalize(), wires)
}

/// Exposed wire indices for a final-polynomial-fiber gadget instance.
pub struct FinalPolyFiberWires {
    pub fiber_x_idx: Vec<usize>,
    pub fiber_f_r_idx: Vec<usize>,
    pub r_fold_idx: usize,
    pub final_coefs_idx: Vec<usize>,
    pub r_fin_idx: usize,
    pub f_r_plus_1_idx: usize,
}

/// Build the R1CS for one final-polynomial fiber check. The honest caller passes
/// a `final_coefs` whose evaluation at `r_fin` equals the fold of the fiber at
/// `r_fold`, so the enforced equality holds.
pub fn build_final_poly_fiber(
    fiber_x: &[Fp192],
    fiber_f_r: &[Fp192],
    r_fold: Fp192,
    final_coefs: &[Fp192],
    r_fin: Fp192,
) -> (Fp192R1cs, FinalPolyFiberWires) {
    let mut builder = Fp192R1csBuilder::new();
    let fiber_x_vars: Vec<Fp192Var> =
        fiber_x.iter().map(|d| builder.alloc_input(d.clone())).collect();
    let fiber_f_r_vars: Vec<Fp192Var> =
        fiber_f_r.iter().map(|v| builder.alloc_input(v.clone())).collect();
    let r_fold_var = builder.alloc_input(r_fold);
    let final_coefs_vars: Vec<Fp192Var> =
        final_coefs.iter().map(|c| builder.alloc_input(c.clone())).collect();
    let r_fin_var = builder.alloc_input(r_fin);
    let f_r_plus_1 = final_poly_fiber_circuit(
        &mut builder,
        &fiber_x_vars,
        &fiber_f_r_vars,
        &r_fold_var,
        &final_coefs_vars,
        &r_fin_var,
    );
    let wires = FinalPolyFiberWires {
        fiber_x_idx: fiber_x_vars.iter().map(|v| v.index()).collect(),
        fiber_f_r_idx: fiber_f_r_vars.iter().map(|v| v.index()).collect(),
        r_fold_idx: r_fold_var.index(),
        final_coefs_idx: final_coefs_vars.iter().map(|v| v.index()).collect(),
        r_fin_idx: r_fin_var.index(),
        f_r_plus_1_idx: f_r_plus_1.index(),
    };
    (builder.finalize(), wires)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::plum::stir_poly::{evaluate, lagrange_interpolate};
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

    /// Pick an out-of-set point distinct from every interpolation-domain point
    /// (so it is genuinely "out of domain" relative to the interpolation set, as
    /// the software's non-interp query points are).
    fn rand_point_outside(domain: &[Fp192], seed: u64) -> Fp192 {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        loop {
            let c = Fp192::rand(&mut rng);
            if !c.is_zero() && !domain.contains(&c) {
                return c;
            }
        }
    }

    // -------------------------------------------------------------------
    // GATE (A): OOD consistency check.
    // -------------------------------------------------------------------
    #[test]
    fn ood_consistency_gadget_gate() {
        // TINY SCALE: small interpolation sets (|H| in {2,3,4}) — STIR-realistic
        // and far under the 60s bound.
        let mut report = None;
        // (2) gadget OOD output == software on >= 2 small inputs.
        for (sd, sv, so, n) in [
            (0x1001u64, 0x2001u64, 0x3001u64, 2usize),
            (0x1002, 0x2002, 0x3002, 3),
            (0x1003, 0x2003, 0x3003, 4),
            (0x1004, 0x2004, 0x3004, 4),
        ] {
            let domain = rand_distinct_points(n, sd);
            let values = rand_coeffs(n, sv);
            let ood_point = rand_point_outside(&domain, so);

            // SOFTWARE reference (verify.rs:545 + verify.rs:554): interpolate,
            // evaluate the interpolant at the OOD point. The honest claimed value
            // IS this software evaluation (what an honest opening would carry).
            let g_hat = lagrange_interpolate(&domain, &values).unwrap();
            let claimed = evaluate(&g_hat, &ood_point);

            let (r1cs, wires) =
                build_ood_consistency(&domain, &values, ood_point.clone(), claimed.clone());

            // (1) honest witness satisfies ALL constraints.
            assert!(
                r1cs.check_satisfied().is_ok(),
                "ood: honest witness unsatisfied (n={n})",
            );
            // (2) gadget output == software interpolant-at-OOD value.
            assert_eq!(
                r1cs.assignment[wires.expected_idx], claimed,
                "ood: gadget output != software evaluate(interpolant, ood) (n={n})",
            );
            eprintln!("[GATE] ood (n={n}): {} constraints", r1cs.num_constraints());
            report = Some((n, r1cs.num_constraints()));
        }

        // (3a) TAMPER — wrong OOD (claimed) value: the enforce_eq
        //      interpolant(ood)==claimed must reject. We rebuild with a claimed
        //      value that is NOT the interpolant's value at the OOD point.
        {
            let n = 4usize;
            let domain = rand_distinct_points(n, 0x4001);
            let values = rand_coeffs(n, 0x4002);
            let ood_point = rand_point_outside(&domain, 0x4003);
            let g_hat = lagrange_interpolate(&domain, &values).unwrap();
            let honest = evaluate(&g_hat, &ood_point);
            let wrong = honest.clone() + Fp192::one();
            let (r1cs, _wires) =
                build_ood_consistency(&domain, &values, ood_point, wrong);
            assert!(
                r1cs.check_satisfied().is_err(),
                "ood: WRONG claimed OOD value ACCEPTED — enforce_eq did not fire",
            );
        }

        // (3a') TAMPER — corrupt the claimed_value WIRE on an honest system: the
        //       OOD equality constraint must reject (pins the rejection to the
        //       claimed value, the transcript-supplied OOD value).
        {
            let n = 3usize;
            let domain = rand_distinct_points(n, 0x4101);
            let values = rand_coeffs(n, 0x4102);
            let ood_point = rand_point_outside(&domain, 0x4103);
            let g_hat = lagrange_interpolate(&domain, &values).unwrap();
            let claimed = evaluate(&g_hat, &ood_point);
            let (base, wires) =
                build_ood_consistency(&domain, &values, ood_point, claimed);
            assert!(base.check_satisfied().is_ok());
            let mut r = base.clone();
            r.assignment[wires.claimed_value_idx] =
                r.assignment[wires.claimed_value_idx].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "ood: corrupted claimed-value wire ACCEPTED",
            );
        }

        // (3b) TAMPER — WRONG INTERPOLATION: corrupt an interpolation VALUE wire.
        //      The interpolant changes, so interpolant(ood) no longer equals the
        //      (unchanged) claimed value — the OOD equality must reject. This is
        //      the "wrong interpolation" tamper.
        {
            let n = 4usize;
            let domain = rand_distinct_points(n, 0x4201);
            let values = rand_coeffs(n, 0x4202);
            let ood_point = rand_point_outside(&domain, 0x4203);
            let g_hat = lagrange_interpolate(&domain, &values).unwrap();
            let claimed = evaluate(&g_hat, &ood_point);
            let (base, wires) =
                build_ood_consistency(&domain, &values, ood_point, claimed);
            assert!(base.check_satisfied().is_ok());
            let mut r = base.clone();
            // Corrupt one interpolation value — re-deriving the rest of the
            // interpolation chain in-circuit would change interpolant(ood), but a
            // raw wire bump leaves downstream wires stale, so SOME constraint
            // (the interpolation chain or the final OOD equality) must fire.
            r.assignment[wires.interp_values_idx[0]] =
                r.assignment[wires.interp_values_idx[0]].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "ood: corrupted interpolation value (wrong interpolation) ACCEPTED",
            );
        }

        let (n, c) = report.unwrap();
        eprintln!("[GATE] ood (n={n}): {c} constraints");
    }

    // -------------------------------------------------------------------
    // GATE (B): Final-polynomial fiber check (Alg 6 line 18).
    // -------------------------------------------------------------------
    #[test]
    fn final_poly_fiber_gadget_gate() {
        // TINY SCALE: η = 4 fiber, small final-poly degree (< 6). STIR-realistic.
        let eta = 4usize;
        let mut report = None;

        // (2) gadget output == software on >= 2 small inputs.
        for (sx, sf, sr, srf, nfinal) in [
            (0x5001u64, 0x6001u64, 0x7001u64, 0x8001u64, 2usize),
            (0x5002, 0x6002, 0x7002, 0x8002, 4),
            (0x5003, 0x6003, 0x7003, 0x8003, 5),
        ] {
            let fiber_x = rand_distinct_points(eta, sx);
            let fiber_f_r = rand_coeffs(eta, sf);
            let r_fold = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(sr));
            let r_fin = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(srf));

            // SOFTWARE (verify.rs:763 + verify.rs:771): interpolate the fiber,
            // evaluate at r_fold to get f̂_{R+1}(r_fin).
            let p_y = lagrange_interpolate(&fiber_x, &fiber_f_r).unwrap();
            let f_r_plus_1 = evaluate(&p_y, &r_fold);

            // Construct an HONEST final_coefs so that final_coefs(r_fin) ==
            // f_r_plus_1 (verify.rs:775 + verify.rs:777). We pick nfinal-1 random
            // low coeffs and solve the top coefficient to hit the target at r_fin;
            // a constant offset is simplest: final_coefs = [f_r_plus_1] padded
            // with random higher coeffs whose contribution at r_fin we cancel.
            // Simplest exact construction: pick random coeffs c[1..], set
            // c[0] = f_r_plus_1 - Σ_{k>=1} c[k]·r_fin^k. Then final_coefs(r_fin)
            // = f_r_plus_1 exactly.
            let mut final_coefs = rand_coeffs(nfinal, sf ^ 0xFFFF);
            // Compute Σ_{k>=1} c[k]·r_fin^k.
            let mut acc = Fp192::zero();
            let mut pow = r_fin.clone(); // r_fin^1
            for k in 1..nfinal {
                acc = acc + final_coefs[k].clone() * pow.clone();
                pow = pow * r_fin.clone();
            }
            final_coefs[0] = f_r_plus_1.clone() - acc;
            // Sanity: software claimed value now matches.
            assert_eq!(
                evaluate(&final_coefs, &r_fin),
                f_r_plus_1,
                "test setup: honest final_coefs(r_fin) != f_r_plus_1",
            );

            let (r1cs, wires) = build_final_poly_fiber(
                &fiber_x,
                &fiber_f_r,
                r_fold.clone(),
                &final_coefs,
                r_fin.clone(),
            );

            // (1) honest witness satisfies ALL constraints.
            assert!(
                r1cs.check_satisfied().is_ok(),
                "final_poly: honest witness unsatisfied (nfinal={nfinal})",
            );
            // (2) gadget reconstructed f̂_{R+1}(r_fin) == software.
            assert_eq!(
                r1cs.assignment[wires.f_r_plus_1_idx], f_r_plus_1,
                "final_poly: gadget fold != software fold (nfinal={nfinal})",
            );
            eprintln!(
                "[GATE] final_poly (eta={eta}, nfinal={nfinal}): {} constraints",
                r1cs.num_constraints()
            );
            report = Some((nfinal, r1cs.num_constraints()));
        }

        // (3) TAMPER — WRONG FINAL-POLY FIBER VALUE: corrupt the constant
        //     coefficient of final_coefs so final_coefs(r_fin) no longer equals
        //     the fold. The final-poly equality must reject (matching the software
        //     `FinalPolynomialMismatch`). This is the wrong-final-poly tamper.
        {
            let fiber_x = rand_distinct_points(eta, 0x9001);
            let fiber_f_r = rand_coeffs(eta, 0x9002);
            let r_fold = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(0x9003));
            let r_fin = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(0x9004));
            let p_y = lagrange_interpolate(&fiber_x, &fiber_f_r).unwrap();
            let f_r_plus_1 = evaluate(&p_y, &r_fold);
            let mut final_coefs = rand_coeffs(4, 0x9005);
            let mut acc = Fp192::zero();
            let mut pow = r_fin.clone();
            for k in 1..final_coefs.len() {
                acc = acc + final_coefs[k].clone() * pow.clone();
                pow = pow * r_fin.clone();
            }
            final_coefs[0] = f_r_plus_1.clone() - acc;
            // TAMPER the final poly: flip the constant coeff. Now
            // final_coefs(r_fin) = f_r_plus_1 + 1 != fold.
            final_coefs[0] = final_coefs[0].clone() + Fp192::one();
            let (r1cs, _wires) = build_final_poly_fiber(
                &fiber_x, &fiber_f_r, r_fold, &final_coefs, r_fin,
            );
            assert!(
                r1cs.check_satisfied().is_err(),
                "final_poly: WRONG final-poly fiber value ACCEPTED — enforce_eq did not fire",
            );
        }

        // (3') TAMPER — WRONG INTERPOLATION: corrupt a fiber value wire on an
        //      honest system. The fold changes, breaking the final-poly equality.
        {
            let fiber_x = rand_distinct_points(eta, 0xA001);
            let fiber_f_r = rand_coeffs(eta, 0xA002);
            let r_fold = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(0xA003));
            let r_fin = Fp192::rand(&mut ChaCha20Rng::seed_from_u64(0xA004));
            let p_y = lagrange_interpolate(&fiber_x, &fiber_f_r).unwrap();
            let f_r_plus_1 = evaluate(&p_y, &r_fold);
            let mut final_coefs = rand_coeffs(4, 0xA005);
            let mut acc = Fp192::zero();
            let mut pow = r_fin.clone();
            for k in 1..final_coefs.len() {
                acc = acc + final_coefs[k].clone() * pow.clone();
                pow = pow * r_fin.clone();
            }
            final_coefs[0] = f_r_plus_1.clone() - acc;
            let (base, wires) = build_final_poly_fiber(
                &fiber_x, &fiber_f_r, r_fold, &final_coefs, r_fin,
            );
            assert!(base.check_satisfied().is_ok());
            let mut r = base.clone();
            r.assignment[wires.fiber_f_r_idx[0]] =
                r.assignment[wires.fiber_f_r_idx[0]].clone() + Fp192::one();
            assert!(
                r.check_satisfied().is_err(),
                "final_poly: corrupted fiber value (wrong interpolation) ACCEPTED",
            );
        }

        let (nfinal, c) = report.unwrap();
        eprintln!("[GATE] final_poly (nfinal={nfinal}): {c} constraints");
    }
}
