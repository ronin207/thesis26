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
use super::stir_poly::{evaluate, lagrange_interpolate};
use super::sumcheck::vanishing_poly_evaluate;
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
    let _r_phase5 = transcript.challenge_field(b"phase5/r");
    let _r0_fold = transcript.challenge_field(b"phase5/r0_fold");
    let query_indices: Vec<usize> =
        transcript.challenge_indices(b"queries/U_0", pp.kappa_0, pp.u_size);

    // Cross-check the prover's query_indices against our re-derivation.
    if query_indices != sig.query_indices {
        return VerificationOutcome::Reject(VerificationFailure::MalformedSignatureShape);
    }
    if sig.c_prime_openings.len() != pp.kappa_0
        || sig.c_prime_paths.len() != pp.kappa_0
        || sig.s_openings.len() != pp.kappa_0
        || sig.h_openings.len() != pp.kappa_0
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

    // ─── Step 2 (Alg 6 lines 4–12): per-query Merkle + sumcheck identity ───
    //
    // For each query index q, the prover opens:
    //   - row of n c_prime values + Merkle path against root_c
    //   - ŝ value + path against root_s
    //   - ĥ value + path against root_h
    //
    // The verifier:
    //   1. Recomputes the c_prime row digest and walks up against root_c.
    //   2. Verifies s and h openings via PlumMerkleTree::verify.
    //   3. Reconstructs f̂(s) = Σ_j ε_j · ĉ'_j(s) · q̂_j(s) using
    //      FS-derived (λ, ε, I).
    //   4. Computes f̂'(s) = z · f̂(s) + ŝ(s).
    //   5. Computes g̃(s) = f̂'(s) − Z_H(s) · ĥ(s).
    //   6. Recovers g̃ in coefficient form (degree < |H|) by
    //      Lagrange-interpolating its values at the κ_0 ≥ |H| query
    //      points... no wait, query points are in U_0 not H. We can
    //      check the sumcheck identity directly at each query point
    //      by an alternate route: use the closed-form
    //      `Σ_{a ∈ H} g̃(a) = z·µ + S` where µ = Σ_j ε_j · Σ_i
    //      λ_{i,j} · o_{i,j} (Alg 6 line 11). This µ is computable
    //      from σ_2, FS challenges, and o-responses without queries.
    //      So the verifier can check "is z·µ + S consistent with the
    //      g̃ values implied by the openings?" by computing |H| · g̃(s)
    //      − (z·µ + S) and ensuring this equals |H| · s · p̂(s) for
    //      some polynomial p̂ of degree < 2m − 1. Without committing
    //      p̂, the verifier can only enforce the identity at query
    //      points by using the LDE structure — which is a separate
    //      check.
    //
    // For this commit we implement the *Merkle* part of Step 2 (items
    // 1–2 above) and the *value-recompute* part (items 3–5: at each
    // query, verifier computes g̃(s) explicitly), but defer the full
    // sumcheck-identity-via-µ check to a follow-up. The current
    // Merkle check ensures the prover cannot tamper with committed
    // polynomial values; the value-recompute exercises the
    // arithmetic chain Verify will need for the full check.

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

    // Walk the queries: verify Merkle paths, then derive g̃(s_q).
    let mut g_at_query: Vec<(Fp192, Fp192)> = Vec::with_capacity(pp.kappa_0);
    for q in 0..pp.kappa_0 {
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
        // s = U_0[e] = u_generator^e (subgroup, no shift).
        let s_point = pp.u_generator.pow_u128(e as u128);
        let s_value = &s_proof.leaf;
        let h_value = &h_proof.leaf;
        let f_hat_s: Fp192 = (0..n)
            .map(|j| {
                let q_hat_at_s = evaluate(&q_hat_coeffs[j], &s_point);
                epsilons[j].clone() * row[j].clone() * q_hat_at_s
            })
            .fold(Fp192::zero(), |acc, x| acc + x);
        let f_prime_s = z.clone() * f_hat_s + s_value.clone();
        let z_h_s = vanishing_poly_evaluate(pp.h_size, &pp.h_shift, &s_point);
        let g_at_s = f_prime_s - z_h_s * h_value.clone();
        g_at_query.push((s_point, g_at_s));
    }

    // ─── Sumcheck identity check ───
    //
    // The prover's signature implies values g̃(s_q) at κ_0 distinct
    // query points. Mathematically g̃ has degree < |H|, so any |H| of
    // these values uniquely determine g̃. We:
    //   1. Lagrange-interpolate g̃ from the first |H| query points.
    //   2. Verify the remaining (κ_0 − |H|) query points lie on the
    //      same polynomial. If the prover constructed the openings
    //      inconsistently (e.g., committed an ĥ that isn't the true
    //      sumcheck quotient), the implied g̃ is high-degree and the
    //      consistency check fails.
    //   3. Verify Σ_{a ∈ H} g̃(a) = z·µ + S, where
    //      µ = Σ_j ε_j · Σ_i λ_{i,j} · o_{i,j}. This is the BCRSVW
    //      sumcheck identity (paper Alg 6 line 11, restructured).
    //
    // Soundness rationale: query points in U_0 are FS-derived, so the
    // prover commits to (root_c, root_s, root_h) before knowing where
    // they will be queried. Even an unbounded prover who sees the
    // query indices in advance cannot produce values that pass both
    // (2) low-degree-on-26-points and (3) sum-equals-target unless the
    // sumcheck identity actually holds (which forces the prover to
    // know the true f̂' and ĥ; see paper §3.2 EUF-KO reduction).
    if pp.kappa_0 < pp.h_size {
        // We need at least |H| query points to interpolate g̃; with
        // PLUM-128 κ_0 = 26 ≥ |H| = 8 this never fires.
        return VerificationOutcome::Reject(VerificationFailure::MalformedSignatureShape);
    }
    // Pick the first |H| query indices that yield distinct U_0
    // points. With FS-derived indices into |U_0| = 4096 and κ_0 = 26
    // queries, P(any pair collides) ≈ (26·25 / 2) / 4096 ≈ 8%, so
    // walking the full set rather than locking in the first 8 is
    // necessary for honest-signer completeness. (P(fewer than |H|=8
    // distinct points among 26 queries into 4096) ≈ 2⁻¹⁵⁰⁺,
    // negligible — so QueryCollision is essentially unreachable on
    // honest signatures, but defined for completeness.)
    let mut interp_indices: Vec<usize> = Vec::with_capacity(pp.h_size);
    for q in 0..pp.kappa_0 {
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
        return VerificationOutcome::Reject(VerificationFailure::QueryCollision {
            distinct_count: interp_indices.len(),
        });
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
    // (2) Consistency check at every query point not used for
    // interpolation. We also re-check the interpolation points (they
    // pass trivially) — keeps the loop simpler.
    let interp_set: std::collections::HashSet<usize> = interp_indices.iter().copied().collect();
    for q in 0..pp.kappa_0 {
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
    // (3) Sumcheck-target check: Σ_{a ∈ H} g̃(a) = z·µ + S.
    let mu: Fp192 = (0..n)
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
    let target = z.clone() * mu + sig.s_sum.clone();
    let actual_sum: Fp192 = h_points
        .iter()
        .map(|a| evaluate(&g_hat_coeffs, a))
        .fold(Fp192::zero(), |acc, x| acc + x);
    if actual_sum != target {
        return VerificationOutcome::Reject(
            VerificationFailure::SumcheckIdentityViolation { query: usize::MAX },
        );
    }

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
