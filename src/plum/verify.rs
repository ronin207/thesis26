//! PLUM signature verification (Algorithm 6, paper p. 122).
//!
//! Algorithm 6 has three high-level steps:
//!
//!   Step 1 — Recompute Challenges (Alg 6 lines 2–3). Replay the
//!     Fiat-Shamir transcript exactly as the signer did, deriving the
//!     same `(I_{i,j})`, `(λ_{i,j}, ε_j)`, `z`, `r`, `r_0^fold`,
//!     STIR `r_i^out`, `r_i^fold`, `r_i^comb`, `r_{i,j}^shift`, and
//!     final `r_i^fin` challenges.
//!   Step 2 — Recompute Leaf Nodes (Alg 6 lines 4–12). For each
//!     queried evaluation point `s` of `U_0`, the verifier
//!     reconstructs `f̂_0(s)` from `ĉ'_1(s), ..., ĉ'_n(s), ŝ(s), ĥ(s)`
//!     (the opened Merkle leaves) plus the BCRSVW sumcheck identity
//!     `p̂(s) = (|H| · f̂'(s) − |H| · Z_H(s) · ĥ(s) − (zµ + S)) / (|H| · s)`.
//!   Step 3 — Check STIR Proofs + Check Residuosity Proofs
//!     (Alg 6 lines 13–24). The STIR-fold-consistency loop checks
//!     each round's authentication path against the running f̂_i; the
//!     residuosity loop checks `o_{i,j} ≠ 0 ∧ L_0^t(o_{i,j}) =
//!     pk_{I_{i,j}} + T_{i,j}` for every (i,j) ∈ [m] × [n].
//!
//! ## What this implementation covers vs. defers
//!
//! **Covered**:
//!   - Step 1 in full (FS replay through Phase 5).
//!   - Step 2 (Alg 6 lines 4-12) at the *algebraic-identity* level:
//!     for every FS-derived query point `s ∈ U_0`, the verifier
//!     opens `ĉ'_j(s), ŝ(s), ĥ(s)` against their committed Merkle
//!     roots, recomputes `g̃(s) = f̂'(s) − Z_H(s) · ĥ(s)`, and checks
//!     two things:
//!       (a) The implied `g̃` lies on a polynomial of degree `< |H|`.
//!           Lagrange-interpolated from the first `|H|` distinct
//!           query points and verified at the remaining `κ_0 − |H|`.
//!       (b) The BCRSVW sumcheck identity `Σ_{a ∈ H} g̃(a) = z·µ + S`
//!           with `µ = Σ_j ε_j · Σ_i λ_{i,j} · o_{i,j}` (Alg 6 line 11).
//!   - Step 3 residuosity check (Alg 6 line 21): for every `(i,j)`,
//!     `o_{i,j} ≠ 0 ∧ L_0^t(o_{i,j}) = pk_{I_{i,j}} + T_{i,j} (mod 256)`.
//!
//! **Deferred**: STIR-verification portion of Step 3 (Alg 6 lines
//! 13–18). Requires per-round Merkle openings of `â_i|_{U_i}` at the
//! `κ_i` shift points and the final-poly check against `coefs`.
//!
//! ## Security caveat
//!
//! Per the paper §3.2 (p. 118) EUF-KO reduction (Theorem 1), the
//! soundness argument routes through the *full* IOP — sumcheck +
//! STIR + residuosity. With STIR proximity testing still deferred,
//! the EUF-KO reduction does NOT close: a forger who commits to
//! *non-low-degree* `c̃'_j, ŝ, ĥ : U_0 → F_p` (rather than evaluations
//! of polynomials of the asserted degree) could in principle
//! construct openings that pass the Merkle, residuosity, and
//! sumcheck-identity checks. The paper's `b`-boundedness
//! (`Pr[X+Y+Z=B]` bound) requires the STIR proximity test to
//! constrain the prover to low-degree witnesses.
//!
//! What this commit DOES add over the prior residuosity-only verify:
//!   - Strong cross-position binding between the σ_2 responses,
//!     committed polynomials, and the FS challenges. A naïve forger
//!     who sampled `o_{i,j}` per-position to match residuosity (the
//!     ~`B · t = 2¹³` attack against the prior partial verify) now
//!     has to ALSO commit consistent `(c̃'_j, ŝ, ĥ)` Merkle roots
//!     whose openings pass the sumcheck identity at FS-derived query
//!     points.
//!   - Detection of any tampering with the committed polynomial
//!     values via Merkle path verification.
//!
//! Treat an `Accept` from this implementation as: "the signature
//! passes everything Algorithm 6 checks except the STIR proximity
//! test." For deployment-grade EUF-CMA security, the STIR portion
//! (Phase 9c, follow-up commit) must land.

use serde::{Deserialize, Serialize};

use super::field_p192::Fp192;
use super::hasher::PlumHasher;
use super::keygen::PlumPublicKey;
use super::merkle::PlumMerkleTree;
use super::prf::DEFAULT_PARAMS;
use super::setup::PlumPublicParams;
use super::sign::PlumSignature;
use super::stir_poly::{degree_correction_polynomial, evaluate, lagrange_interpolate};
use super::sumcheck::{sum_over_coset, vanishing_poly_evaluate};
use super::transcript::PlumTranscript;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationOutcome {
    Accept,
    Reject(VerificationFailure),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationFailure {
    /// One of the σ_2 responses was zero, which would make
    /// `L_0^t(o_{i,j})` enter the PRF's zero-input branch.
    ZeroResponse { i: usize, j: usize },
    /// The residuosity check at (i, j) disagreed with the public key.
    /// `expected = pk[I_{i,j}] + T_{i,j} (mod t)`; the o-response
    /// yielded `actual = L_0^t(o_{i,j})`.
    ResiduositySymbolMismatch {
        i: usize,
        j: usize,
        expected: u8,
        actual: u8,
    },
    /// `t_tags.len() != m·n` or similar structural problem.
    MalformedSignatureShape,
    /// Merkle authentication path for the `q`-th query into the
    /// `c_prime` (column commitment) tree did not reconstruct
    /// `root_c`.
    CPrimeMerklePathInvalid { query: usize },
    /// Merkle authentication path for `ŝ` did not reconstruct `root_s`.
    SMerklePathInvalid { query: usize },
    /// Merkle authentication path for `ĥ` did not reconstruct `root_h`.
    HMerklePathInvalid { query: usize },
    /// The BCRSVW univariate-sumcheck identity
    /// `f̂'(s) = ĝ(s) + Z_H(s) · ĥ(s)` failed to be consistent at
    /// query index `q`. Specifically, after computing `g̃(s) = f̂'(s)
    /// − Z_H(s) · ĥ(s)` from the openings, the implied
    /// `Σ_{a ∈ H} g̃(a)` (computable via the closed form
    /// `|H| · g̃_0` once g̃ is interpolated) disagreed with `z·μ + S`.
    SumcheckIdentityViolation { query: usize },
    /// Fewer than `|H|` distinct query points landed in `U_0` after
    /// FS sampling. Vanishingly unlikely at PLUM-128 (`P ≈ 2⁻¹⁵⁰⁺`
    /// for `κ_0 = 26` queries into `|U_0| = 2¹²`), but this variant
    /// exists so honest signatures with mere pair-collisions (a few
    /// percent probability) are not lumped in with structural
    /// failures.
    QueryCollision { distinct_count: usize },
    /// Merkle authentication path for `â_i` at `shift_index`-th shift
    /// of `round` did not reconstruct `stir_roots[round]`.
    StirAMerklePathInvalid { round: usize, shift_index: usize },
    /// The verifier's fiber-fold reconstruction of `â_i(y_j)`
    /// disagreed with the prover's claimed `â_i(y_j)` (Merkle leaf at
    /// shift base `b_j`). This is the STIR fold-consistency check
    /// (Alg 6 lines 13–17): the prover cannot commit to a non-fold
    /// `â_i` without tripping this.
    StirFoldConsistencyViolation { round: usize, shift_index: usize },
}

/// Algorithm 6 — PLUM signature verification.
///
/// Replays the prover's Fiat-Shamir transcript and runs every check
/// the current `PlumSignature` representation supports. Specifically:
///
///   - Re-derives the residuosity index `(I_{i,j})` from `h_1`.
///   - Checks every (i,j): `o_{i,j} ≠ 0` and
///     `L_0^t(o_{i,j}) ≡ pk_{I_{i,j}} + T_{i,j} (mod t)`.
///
/// The STIR-fold check and Merkle openings are not currently performed
/// (see the module-level doc-comment for what's deferred). Callers
/// should treat an `Accept` here as "passed every check the current
/// implementation supports", not as "verified per Algorithm 6 in full".
pub fn plum_verify<H: PlumHasher>(
    pp: &PlumPublicParams,
    pk: &PlumPublicKey,
    message: &[u8],
    sig: &PlumSignature,
) -> VerificationOutcome {
    let m = pp.m;
    let n = pp.n;
    let b = pp.b;
    if sig.t_tags.len() != b || sig.o_responses.len() != b {
        return VerificationOutcome::Reject(VerificationFailure::MalformedSignatureShape);
    }
    if pk.symbols.len() != pp.l {
        return VerificationOutcome::Reject(VerificationFailure::MalformedSignatureShape);
    }

    assert_eq!(
        pp.t, 256,
        "plum_verify currently only supports t = 256; got t = {}",
        pp.t
    );

    // ─── Step 1: replay FS transcript through Phase 5 ───
    let mut transcript = PlumTranscript::<H>::new(b"PLUM/sign/v1");
    transcript.append_bytes(b"M", message);
    transcript.append_root(b"root_c", &sig.root_c);
    transcript.append_bytes(b"T", &sig.t_tags);
    // Phase 2: challenge indices into I.
    let challenge_indices: Vec<usize> =
        transcript.challenge_indices(b"phase2/indices", b, pp.l);
    let i_values: Vec<Fp192> = challenge_indices
        .iter()
        .map(|&idx| pp.challenge_set[idx].clone())
        .collect();
    transcript.append_fields(b"o_responses", &sig.o_responses);
    // Phase 3: λ + ε challenges, then commit ŝ.
    let mut lambdas: Vec<Vec<Fp192>> = Vec::with_capacity(n);
    for j in 0..n {
        let label = format!("phase3/lambda/{}", j);
        lambdas.push(transcript.challenge_fields(label.as_bytes(), m));
    }
    let epsilons: Vec<Fp192> = transcript.challenge_fields(b"phase3/epsilon", n);
    transcript.append_root(b"root_s", &sig.root_s);
    transcript.append_field(b"s_sum", &sig.s_sum);
    // Phase 4: z challenge, then commit ĥ.
    let z = transcript.challenge_field(b"phase4/z");
    transcript.append_root(b"root_h", &sig.root_h);
    // Phase 5: r and r_0^fold (consumed only by STIR; we skip), then
    // query indices (the verifier needs these for Step 2).
    let r_phase5 = transcript.challenge_field(b"phase5/r");
    let r0_fold = transcript.challenge_field(b"phase5/r0_fold");

    // Length check on STIR commitments.
    if sig.stir_roots.len() != pp.r_rounds
        || sig.stir_betas.len() != pp.r_rounds
        || sig.stir_a_openings.len() != pp.r_rounds
    {
        return VerificationOutcome::Reject(VerificationFailure::MalformedSignatureShape);
    }

    // ─── Step 3 residuosity (Alg 6 line 21) ───
    let prf = &*DEFAULT_PARAMS;
    for j in 0..n {
        for i in 0..m {
            let idx = j * m + i;
            let o = &sig.o_responses[idx];
            if o.is_zero() {
                return VerificationOutcome::Reject(
                    VerificationFailure::ZeroResponse { i, j },
                );
            }
            let lhs = prf.eval(o) as u8;
            let pk_at_i = pk.symbols[challenge_indices[idx]];
            let t_tag = sig.t_tags[idx];
            let rhs = pk_at_i.wrapping_add(t_tag);
            if lhs != rhs {
                return VerificationOutcome::Reject(
                    VerificationFailure::ResiduositySymbolMismatch {
                        i,
                        j,
                        expected: rhs,
                        actual: lhs,
                    },
                );
            }
        }
    }

    // ─── Step 2 (Alg 6 lines 4–12) + Step 3 STIR portion (lines 13–18) ───
    //
    // Layout: enter the STIR loop, mirroring Sign's FS chain. For
    // each round, after appending root_a_i and β_i, derive shift
    // bases. For round 0 only, expand shift bases to fiber-query
    // indices in U_0 and run the existing Phase 2 work (Merkle paths
    // + sumcheck identity + fiber-fold â_1 reconstruction).
    // Then for every round, verify â_i Merkle paths at shift bases
    // and cross-check the reconstructed values.

    // Pre-compute q̂_j coefficients from FS-derived (λ, I).
    let h_points: Vec<Fp192> = (0..pp.h_size)
        .map(|k| pp.h_shift.clone() * pp.h_generator.pow_u128(k as u128))
        .collect();
    let mut q_hat_coeffs: Vec<Vec<Fp192>> = Vec::with_capacity(n);
    for j in 0..n {
        let mut q_j = Vec::with_capacity(2 * m);
        for i in 0..m {
            let lambda = lambdas[j][i].clone();
            let idx = j * m + i;
            q_j.push(lambda.clone());
            q_j.push(lambda * i_values[idx].clone());
        }
        let q_hat = lagrange_interpolate(&h_points, &q_j)
            .expect("H interpolation in Verify Phase 3");
        q_hat_coeffs.push(q_hat);
    }

    // Pre-compute the rate-correction constants used to reconstruct
    // f̂_0(s) per Alg 4 line 16. These are FS-derived once per
    // verification.
    let d_star = pp.d_star;
    let kappa_eta = pp.kappa_0 * pp.eta;
    let e1 = d_star.saturating_sub(2 * pp.m + kappa_eta + 1);
    let e2 = d_star.saturating_sub(4 * pp.m + kappa_eta);
    let e3 = d_star.saturating_sub(2 * pp.m + kappa_eta);
    let e4 = d_star.saturating_sub(2 * pp.m - 1);
    let t1_coeffs = degree_correction_polynomial(&r_phase5, e1);
    let t2_coeffs = degree_correction_polynomial(&r_phase5, e2);
    let t3_coeffs = degree_correction_polynomial(&r_phase5, e3);
    let t4_coeffs = degree_correction_polynomial(&r_phase5, e4);
    let r_pow_t2 = r_phase5.pow_u128((1 + e1) as u128);
    let r_pow_t3 = r_phase5.pow_u128((2 + e1 + e2) as u128);
    let r_pow_t4 = r_phase5.pow_u128((3 + e1 + e2 + e3) as u128);
    let h_size_field = Fp192::from_u64(pp.h_size as u64);

    // µ + target for the BCRSVW p̂ formula.
    let mu_local: Fp192 = (0..n)
        .map(|j| {
            let inner: Fp192 = (0..m)
                .map(|i| {
                    let idx = j * m + i;
                    lambdas[j][i].clone() * sig.o_responses[idx].clone()
                })
                .fold(Fp192::zero(), |acc, x| acc + x);
            epsilons[j].clone() * inner
        })
        .fold(Fp192::zero(), |acc, x| acc + x);
    let p_hat_target = z.clone() * mu_local.clone() + sig.s_sum.clone();

    // ─── STIR loop ───
    let mut current_generator = pp.u_generator.clone();
    let mut current_size = pp.u_size;
    let mut current_r_fold = r0_fold.clone();

    for round in 0..pp.r_rounds {
        // FS chain for this round.
        transcript.append_root(b"stir/root", &sig.stir_roots[round]);
        let _r_out = transcript.challenge_field(b"stir/r_out");
        transcript.append_field(b"stir/beta", &sig.stir_betas[round]);
        let next_r_fold = transcript.challenge_field(b"stir/r_fold");
        let _r_comb = transcript.challenge_field(b"stir/r_comb");

        // Derive shift bases for this round.
        let kappa_shift_round = if round == 0 {
            pp.kappa_0.div_ceil(pp.eta)
        } else {
            pp.kappas[round]
        };
        let next_size = current_size / pp.eta;
        // Mirror Sign's 2x oversample + dedupe to handle birthday
        // collisions in shift base sampling.
        let raw_bases: Vec<usize> = transcript.challenge_indices(
            b"stir/shift_bases",
            kappa_shift_round * 2,
            next_size,
        );
        let mut shift_bases: Vec<usize> = Vec::with_capacity(kappa_shift_round);
        for b in &raw_bases {
            if !shift_bases.contains(b) {
                shift_bases.push(*b);
                if shift_bases.len() == kappa_shift_round {
                    break;
                }
            }
        }
        if shift_bases.len() != kappa_shift_round {
            return VerificationOutcome::Reject(
                VerificationFailure::MalformedSignatureShape,
            );
        }

        // â_i Merkle openings: verify and collect leaf values.
        if sig.stir_a_openings[round].len() != kappa_shift_round {
            return VerificationOutcome::Reject(
                VerificationFailure::MalformedSignatureShape,
            );
        }
        let mut a_i_at_shifts: Vec<Fp192> = Vec::with_capacity(kappa_shift_round);
        for (j, &b) in shift_bases.iter().enumerate() {
            let proof = &sig.stir_a_openings[round][j];
            if proof.leaf_index != b
                || !PlumMerkleTree::<H>::verify(&sig.stir_roots[round], proof)
            {
                return VerificationOutcome::Reject(
                    VerificationFailure::StirAMerklePathInvalid {
                        round,
                        shift_index: j,
                    },
                );
            }
            a_i_at_shifts.push(proof.leaf.clone());
        }

        // Round 0 is special: this is where the f̂_0 query openings,
        // the sumcheck identity check, and the fiber-fold â_1
        // reconstruction live.
        if round == 0 {
            let u_over_eta = pp.u_size / pp.eta;
            let mut query_indices: Vec<usize> =
                Vec::with_capacity(kappa_shift_round * pp.eta);
            for &base in &shift_bases {
                for t in 0..pp.eta {
                    query_indices.push(base + t * u_over_eta);
                }
            }
            let total_queries = query_indices.len();
            if query_indices != sig.query_indices {
                return VerificationOutcome::Reject(
                    VerificationFailure::MalformedSignatureShape,
                );
            }
            if sig.c_prime_openings.len() != total_queries
                || sig.c_prime_paths.len() != total_queries
                || sig.s_openings.len() != total_queries
                || sig.h_openings.len() != total_queries
            {
                return VerificationOutcome::Reject(
                    VerificationFailure::MalformedSignatureShape,
                );
            }

            // Walk the queries: verify Merkle paths, derive g̃(s_q) and
            // f̂_0(s_q).
            let mut g_at_query: Vec<(Fp192, Fp192)> =
                Vec::with_capacity(total_queries);
            let mut f0_at_query: Vec<Fp192> = Vec::with_capacity(total_queries);
            let mut points_at_query: Vec<Fp192> =
                Vec::with_capacity(total_queries);
            for q in 0..total_queries {
                let e = sig.query_indices[q];

                // (1) Merkle path for c_prime row.
                let row = &sig.c_prime_openings[q];
                if row.len() != n {
                    return VerificationOutcome::Reject(
                        VerificationFailure::MalformedSignatureShape,
                    );
                }
                let leaf_digest = H::hash_fields(row);
                if !PlumMerkleTree::<H>::verify_digest_leaf(
                    &sig.root_c,
                    e,
                    &leaf_digest,
                    &sig.c_prime_paths[q],
                ) {
                    return VerificationOutcome::Reject(
                        VerificationFailure::CPrimeMerklePathInvalid { query: q },
                    );
                }

                // (2) Merkle paths for ŝ and ĥ.
                let s_proof = &sig.s_openings[q];
                if s_proof.leaf_index != e
                    || !PlumMerkleTree::<H>::verify(&sig.root_s, s_proof)
                {
                    return VerificationOutcome::Reject(
                        VerificationFailure::SMerklePathInvalid { query: q },
                    );
                }
                let h_proof = &sig.h_openings[q];
                if h_proof.leaf_index != e
                    || !PlumMerkleTree::<H>::verify(&sig.root_h, h_proof)
                {
                    return VerificationOutcome::Reject(
                        VerificationFailure::HMerklePathInvalid { query: q },
                    );
                }

                // (3-5) Reconstruct g̃(s) per the BCRSVW identity.
                let s_point = pp.u_generator.pow_u128(e as u128);
                let s_value = &s_proof.leaf;
                let h_value = &h_proof.leaf;
                let f_hat_s: Fp192 = (0..n)
                    .map(|j_col| {
                        let q_hat_at_s = evaluate(&q_hat_coeffs[j_col], &s_point);
                        epsilons[j_col].clone() * row[j_col].clone() * q_hat_at_s
                    })
                    .fold(Fp192::zero(), |acc, x| acc + x);
                let f_prime_s = z.clone() * f_hat_s.clone() + s_value.clone();
                let z_h_s =
                    vanishing_poly_evaluate(pp.h_size, &pp.h_shift, &s_point);
                let g_at_s = f_prime_s.clone() - z_h_s.clone() * h_value.clone();

                let s_inv =
                    s_point.inverse().expect("s ∈ U_0 ⊂ F_p^*, invertible");
                let p_hat_s = (h_size_field.clone() * f_prime_s
                    - h_size_field.clone() * z_h_s.clone() * h_value.clone()
                    - p_hat_target.clone())
                    * s_inv.clone()
                    * h_size_field
                        .clone()
                        .inverse()
                        .expect("|H| invertible");

                let t1_s = evaluate(&t1_coeffs, &s_point);
                let t2_s = evaluate(&t2_coeffs, &s_point);
                let t3_s = evaluate(&t3_coeffs, &s_point);
                let t4_s = evaluate(&t4_coeffs, &s_point);
                let f0_s = t1_s * f_hat_s
                    + t2_s * r_pow_t2.clone() * s_value.clone()
                    + t3_s * r_pow_t3.clone() * h_value.clone()
                    + t4_s * r_pow_t4.clone() * p_hat_s;

                g_at_query.push((s_point.clone(), g_at_s));
                f0_at_query.push(f0_s);
                points_at_query.push(s_point);
            }

            // ─── Sumcheck identity check ───
            if total_queries < pp.h_size {
                return VerificationOutcome::Reject(
                    VerificationFailure::MalformedSignatureShape,
                );
            }
            let mut interp_indices: Vec<usize> = Vec::with_capacity(pp.h_size);
            for q in 0..total_queries {
                if interp_indices.len() == pp.h_size {
                    break;
                }
                let candidate = &g_at_query[q].0;
                let collides = interp_indices
                    .iter()
                    .any(|&prev_q| g_at_query[prev_q].0 == *candidate);
                if !collides {
                    interp_indices.push(q);
                }
            }
            if interp_indices.len() < pp.h_size {
                return VerificationOutcome::Reject(
                    VerificationFailure::QueryCollision {
                        distinct_count: interp_indices.len(),
                    },
                );
            }
            let interp_points: Vec<Fp192> = interp_indices
                .iter()
                .map(|&q| g_at_query[q].0.clone())
                .collect();
            let interp_values: Vec<Fp192> = interp_indices
                .iter()
                .map(|&q| g_at_query[q].1.clone())
                .collect();
            let g_hat_coeffs = lagrange_interpolate(&interp_points, &interp_values)
                .expect("interp_points are distinct by construction above");
            let interp_set: std::collections::HashSet<usize> =
                interp_indices.iter().copied().collect();
            for q in 0..total_queries {
                if interp_set.contains(&q) {
                    continue;
                }
                let (ref s, ref g_value) = g_at_query[q];
                let expected = evaluate(&g_hat_coeffs, s);
                if expected != *g_value {
                    return VerificationOutcome::Reject(
                        VerificationFailure::SumcheckIdentityViolation { query: q },
                    );
                }
            }
            let mu_check: Fp192 = (0..n)
                .map(|j_col| {
                    let inner: Fp192 = (0..m)
                        .map(|i_row| {
                            let idx = j_col * m + i_row;
                            lambdas[j_col][i_row].clone()
                                * sig.o_responses[idx].clone()
                        })
                        .fold(Fp192::zero(), |acc, x| acc + x);
                    epsilons[j_col].clone() * inner
                })
                .fold(Fp192::zero(), |acc, x| acc + x);
            let target = z.clone() * mu_check + sig.s_sum.clone();
            let actual_sum: Fp192 = h_points
                .iter()
                .map(|a| evaluate(&g_hat_coeffs, a))
                .fold(Fp192::zero(), |acc, x| acc + x);
            if actual_sum != target {
                return VerificationOutcome::Reject(
                    VerificationFailure::SumcheckIdentityViolation {
                        query: usize::MAX,
                    },
                );
            }

            // ─── STIR fold-on-fiber: reconstruct â_1 at shift points,
            //     then cross-check against Merkle-opened values ───
            //
            // For each shift base b_j the fiber {x_t = ω^{b_j + t·|U_0|/η}}
            // sits at queries [j·η, (j+1)·η). The reconstructed
            // â_1(y_j) is the Lagrange polynomial through (x_t,
            // f̂_0(x_t)) evaluated at r_0^fold (paper Alg 5 lines 4-7).
            // If this disagrees with the Merkle-opened â_1(y_j), the
            // prover did not actually commit to the fold of f̂_0 —
            // soundness violation per Alg 6 lines 13-17.
            for j in 0..kappa_shift_round {
                let fiber_start = j * pp.eta;
                let fiber_end = fiber_start + pp.eta;
                if fiber_end > total_queries {
                    return VerificationOutcome::Reject(
                        VerificationFailure::MalformedSignatureShape,
                    );
                }
                let fiber_x: Vec<Fp192> =
                    points_at_query[fiber_start..fiber_end].to_vec();
                let fiber_y: Vec<Fp192> =
                    f0_at_query[fiber_start..fiber_end].to_vec();
                let p_y_coeffs = match lagrange_interpolate(&fiber_x, &fiber_y) {
                    Ok(coeffs) => coeffs,
                    Err(_) => {
                        return VerificationOutcome::Reject(
                            VerificationFailure::MalformedSignatureShape,
                        );
                    }
                };
                let a_1_at_y = evaluate(&p_y_coeffs, &current_r_fold);
                if a_1_at_y != a_i_at_shifts[j] {
                    return VerificationOutcome::Reject(
                        VerificationFailure::StirFoldConsistencyViolation {
                            round,
                            shift_index: j,
                        },
                    );
                }
            }
        }

        // Advance FS chain to next round.
        current_generator = current_generator.pow_u128(pp.eta as u128);
        current_size = next_size;
        current_r_fold = next_r_fold;
    }

    // Absorb final_coefs into transcript to mirror Sign's tail. Not
    // checked yet (final-poly consistency is the remaining Phase 9c
    // follow-up).
    transcript.append_fields(b"stir/final_coefs", &sig.final_coefs);

    VerificationOutcome::Accept
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plum::hasher::PlumSha3Hasher;
    use crate::plum::keygen::plum_keygen;
    use crate::plum::setup::plum_setup;
    use crate::plum::sign::plum_sign;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// The headline correctness check: a freshly-signed signature
    /// passes the residuosity portion of Algorithm 6 on the matching
    /// public key.
    #[test]
    fn sign_then_verify_accepts() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_0001);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"hello", &mut rng);
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"hello", &sig);
        assert_eq!(outcome, VerificationOutcome::Accept);
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_0010);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"original", &mut rng);
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"tampered", &sig);
        // Different message → different FS-derived I_{i,j} → residuosity
        // check almost certainly mismatches at some (i,j).
        assert!(matches!(outcome, VerificationOutcome::Reject(_)));
    }

    #[test]
    fn verify_rejects_wrong_public_key() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_0020);
        let (sk, _pk) = plum_keygen(&pp, &mut rng);
        let (_sk2, pk2) = plum_keygen(&pp, &mut rng);
        let sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"msg", &mut rng);
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk2, b"msg", &sig);
        assert!(matches!(outcome, VerificationOutcome::Reject(_)));
    }

    #[test]
    fn verify_rejects_tampered_o_response() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_0030);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let mut sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"msg", &mut rng);
        // Flip the first o response. The residuosity check should
        // mismatch since (K + I_{0,0}) · r_{0,0} is now arbitrary.
        sig.o_responses[0] = sig.o_responses[0].clone() + Fp192::one();
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"msg", &sig);
        assert!(matches!(outcome, VerificationOutcome::Reject(_)));
    }

    #[test]
    fn verify_rejects_tampered_t_tag() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_0040);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let mut sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"msg", &mut rng);
        // Flip a T tag. Tampering T tags first changes the FS-derived
        // I challenges (because T is in root_c's preimage via the
        // transcript binding), and second changes the residuosity-check
        // RHS directly. Either way, verify should reject.
        sig.t_tags[0] = sig.t_tags[0].wrapping_add(1);
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"msg", &sig);
        assert!(matches!(outcome, VerificationOutcome::Reject(_)));
    }

    #[test]
    fn verify_rejects_tampered_c_prime_opening() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_0060);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let mut sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"msg", &mut rng);
        // Flip a c_prime value: the row digest computed by Verify will
        // not match the digest the prover hashed when building root_c,
        // so the Merkle path won't reconstruct.
        sig.c_prime_openings[0][0] = sig.c_prime_openings[0][0].clone() + Fp192::one();
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"msg", &sig);
        match outcome {
            VerificationOutcome::Reject(
                VerificationFailure::CPrimeMerklePathInvalid { .. },
            ) => {}
            other => panic!("expected CPrimeMerklePathInvalid, got {:?}", other),
        }
    }

    #[test]
    fn verify_rejects_tampered_h_opening() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_0070);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let mut sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"msg", &mut rng);
        sig.h_openings[0].leaf = sig.h_openings[0].leaf.clone() + Fp192::one();
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"msg", &sig);
        match outcome {
            VerificationOutcome::Reject(
                VerificationFailure::HMerklePathInvalid { .. },
            ) => {}
            other => panic!("expected HMerklePathInvalid, got {:?}", other),
        }
    }

    /// The STIR fold-consistency check should fire if the prover
    /// commits to an â_1 that is not the fold of f̂_0. We exhibit
    /// this by tampering one of the Merkle-opened â_1 leaf values.
    #[test]
    fn verify_rejects_tampered_stir_a_opening_leaf() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_00A0);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let mut sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"msg", &mut rng);
        sig.stir_a_openings[0][0].leaf =
            sig.stir_a_openings[0][0].leaf.clone() + Fp192::one();
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"msg", &sig);
        // Tampering a leaf invalidates the Merkle path before the
        // fold-consistency check runs, so the rejection is
        // StirAMerklePathInvalid (the Merkle-path check comes first).
        assert!(matches!(
            outcome,
            VerificationOutcome::Reject(VerificationFailure::StirAMerklePathInvalid {
                round: 0,
                shift_index: 0,
            }),
        ));
    }

    /// Pure fold-consistency violation: leave the Merkle path
    /// intact but tamper a sibling in the â_1 path so the verifier's
    /// reconstructed root matches the commitment but the leaf value
    /// disagrees with the fold of f̂_0.
    ///
    /// We approximate this by tampering both the leaf and the
    /// reconstructed Merkle root to be self-consistent — concretely,
    /// substitute a different shift's opening (different leaf value,
    /// different siblings) for the first. With overwhelming
    /// probability the substituted leaf is not what the fold of f̂_0
    /// predicts at the first shift point.
    #[test]
    fn verify_rejects_swapped_stir_a_openings_at_distinct_shifts() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_00A1);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let mut sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"msg", &mut rng);
        // Swap the openings at shifts 0 and 1. Both Merkle paths
        // remain individually valid but expose â_1 at the wrong
        // shift base (paths claim leaf_index = b_0 but values are
        // from b_1, and vice versa). The Merkle-path verify checks
        // proof.leaf_index against the FS-derived base, so this
        // mismatch is caught.
        sig.stir_a_openings[0].swap(0, 1);
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"msg", &sig);
        assert!(matches!(outcome, VerificationOutcome::Reject(_)));
    }

    #[test]
    fn verify_rejects_zero_o_response() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xD000_0050);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let mut sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"msg", &mut rng);
        sig.o_responses[3] = Fp192::zero();
        let outcome = plum_verify::<PlumSha3Hasher>(&pp, &pk, b"msg", &sig);
        // Tampering o_responses changes post-Phase-2 FS challenges,
        // including the query_indices derived after root_h is bound.
        // The verifier might reject via the index-mismatch path before
        // reaching the residuosity loop, or via ZeroResponse if it does.
        // Either rejection mode satisfies correctness.
        assert!(
            matches!(outcome, VerificationOutcome::Reject(_)),
            "expected some rejection, got {:?}",
            outcome
        );
    }
}
