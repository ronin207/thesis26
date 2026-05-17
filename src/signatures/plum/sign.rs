//! PLUM signature generation (Algorithms 3–5, paper pp. 119–121).
//!
//! Wires together the primitives built in earlier phases:
//!   - Phase 1 (Alg 3 lines 2–11): commit to secret key + randomness.
//!     Uses `prf::eval_keyed` for the residuosity tags, `fft::evaluate_
//!     on_coset` to evaluate the column polynomials on `U`, and
//!     `merkle::PlumMerkleTree::commit_digests` for the multi-column
//!     Merkle commit.
//!   - Phase 2 (Alg 3 lines 12–17): compute residuosity-symbol
//!     responses `o_{i,j} = (K + I_{i,j}) · r_{i,j}`.
//!   - Phase 3 (Alg 3 lines 18–23, Alg 4 lines 2–6): build the sumcheck
//!     witness `f̂` and the ZK polynomial `ŝ`. Commit `ŝ|_U` via
//!     single-column Merkle.
//!   - Phase 4 (Alg 4 lines 7–12): univariate sumcheck. Uses
//!     `sumcheck::decompose` to produce `(ĝ, ĥ)`, commits `ĥ|_U`.
//!   - Phase 5 (Alg 4 lines 13–16): rate correction for STIR. Builds
//!     the initial codeword `f̂*` as a linear combination of the
//!     committed polynomials.
//!   - Phase 6 (Alg 5 lines 2–16): STIR folding loop. Uses
//!     `stir::stir_fold`, `stir::rate_correct`, `stir::
//!     apply_degree_correction`, and `stir::fold_coefficients`.
//!
//! Scope notes:
//!   - This implementation faithfully encodes the protocol shape at
//!     the polynomial / Merkle / transcript level. It is intended for
//!     the thesis cycle-attribution measurement, not for deployment.
//!     The `Fp192` arithmetic is variable-time (Phase 1.5 of the plan
//!     is to swap to a CT backend).
//!   - The ZK polynomial `ŝ` is sampled from the same `rand::CryptoRng`
//!     as the witness randomness — fine for measurement.

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use super::field_p192::Fp192;
use super::fft::evaluate_on_coset;
use super::hasher::{PLUM_DIGEST_BYTES, PlumHasher};
use super::keygen::PlumSecretKey;
use super::merkle::{PlumMerkleProof, PlumMerkleTree};
use super::prf::DEFAULT_PARAMS;
use super::setup::PlumPublicParams;
use super::stir::{
    apply_degree_correction, fold_coefficients, rate_correct, stir_fold,
};
use super::stir_poly::{
    degree_correction_polynomial, divide_by_linear, evaluate, lagrange_interpolate,
    multiply,
};
use super::sumcheck::{decompose, sum_over_coset};
use super::transcript::PlumTranscript;

/// A complete PLUM signature.
///
/// The transcript is reconstructible by the verifier from `pp`, `pk`,
/// `M`, and the elements of this struct, so only data the verifier
/// genuinely needs is included (Merkle openings, raw query answers,
/// FS-binding hashes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlumSignature {
    // ─── σ_1: key + randomness commitment (Alg 3 line 11) ───
    /// Merkle root over the n-column commitment of `ĉ'_j|_U`.
    pub root_c: [u8; PLUM_DIGEST_BYTES],
    /// PRF tags `T_{i,j} = L^t_0(r_{i,j})` for `(i,j) ∈ [m] × [n]`,
    /// flattened row-major.
    pub t_tags: Vec<u8>,

    // ─── σ_2: residuosity responses (Alg 3 line 17) ───
    /// `o_{i,j} = (K + I_{i,j}) · r_{i,j}` for `(i,j) ∈ [m] × [n]`.
    pub o_responses: Vec<Fp192>,

    // ─── σ_3: ZK commitment (Alg 4 line 6) ───
    /// Merkle root over `ŝ|_U`.
    pub root_s: [u8; PLUM_DIGEST_BYTES],
    /// `S = Σ_{a ∈ H} ŝ(a)`.
    pub s_sum: Fp192,

    // ─── σ_4: sumcheck quotient commitment (Alg 4 line 12) ───
    /// Merkle root over `ĥ|_U`.
    pub root_h: [u8; PLUM_DIGEST_BYTES],

    // ─── σ_5+: STIR (Alg 5) ───
    /// Per-round Merkle roots over `â_i|_{U_{i-1}^η}` for `i ∈ [1, R]`.
    pub stir_roots: Vec<[u8; PLUM_DIGEST_BYTES]>,
    /// Per-round PRF-style "out" evaluations `β_i = â_i(r_i^out)`.
    pub stir_betas: Vec<Fp192>,
    /// Per-round Merkle openings of `â_i` at the FS-derived shift
    /// indices (paper Alg 5 line 11). For round `i ∈ [0, R)`, the
    /// inner `Vec<PlumMerkleProof>` has length `κ_shift` (the per-round
    /// shift count) and `openings[j].leaf` is `â_{i+1}(ω_{i}^{b_j · η})`.
    pub stir_a_openings: Vec<Vec<PlumMerkleProof>>,
    /// Final-polynomial query openings (paper Alg 5 lines 15–16): for
    /// each `r_i^fin ∈ U_R^η`, the η Merkle openings to `â_R` at the
    /// fiber `{ω_{U_R}^{b_i + t · |U_R|/η}}_{t<η}`. Outer length is
    /// `t_M`; inner length is `η`. Used in Alg 6 line 18 to check
    /// `f̂_{R+1}(r_i^fin) = sig.final_coefs(r_i^fin)`.
    pub stir_final_a_openings: Vec<Vec<PlumMerkleProof>>,
    /// Coefficients of the final-round polynomial `f̂_{R+1}` (Alg 5
    /// line 14), length `< d_R = d_stop`.
    pub final_coefs: Vec<Fp192>,

    // ─── Query openings (Alg 6 Step 2 — paper p. 122) ───
    /// FS-derived query indices into `U_0`. Length `pp.kappa_0`.
    pub query_indices: Vec<usize>,
    /// `c_prime_openings[q][j] = ĉ'_j(U_0[query_indices[q]])`. The full
    /// row is what the prover hashed to form the Merkle leaf.
    pub c_prime_openings: Vec<Vec<Fp192>>,
    /// `c_prime_paths[q]` is the sibling chain (digest path) to root_c.
    /// Verifier hashes the row to a digest and walks up.
    pub c_prime_paths: Vec<Vec<[u8; PLUM_DIGEST_BYTES]>>,
    /// `ŝ(U_0[query_indices[q]])` plus its Merkle path against root_s.
    pub s_openings: Vec<PlumMerkleProof>,
    /// `ĥ(U_0[query_indices[q]])` plus its Merkle path against root_h.
    pub h_openings: Vec<PlumMerkleProof>,
}

/// Algorithm 3 / 4 / 5 — generate a PLUM signature.
///
/// At PLUM-128 (`m=4`, `n=7`, `B=28`, `L=2^12`, `|U|=4096`, `R=1`,
/// `η=4`, `d*=128`, `d_stop=32`) this is roughly:
///   - 28 random `Fp192` + 28 PRF evaluations (Phase 1).
///   - 7 `Interpolate` on `|H|=8` + 7 evaluations on `|U|=4096` +
///     4096-leaf Merkle commit (Phase 1).
///   - 28 PRF evaluations against the FS-derived challenge indices
///     (Phase 2) + 28 multiplies (`o_{i,j}`).
///   - 7 `Interpolate` of `q̂_j` + 7 multiplications (Phase 3).
///   - One sumcheck decomposition `f̂' = ĝ + Z_H · ĥ` (Phase 4).
///   - One STIR fold + one rate correction + one degree correction
///     + one final fold (Phase 5–6 for `R = 1`).
pub fn plum_sign<H: PlumHasher, R: Rng + CryptoRng>(
    pp: &PlumPublicParams,
    sk: &PlumSecretKey,
    message: &[u8],
    rng: &mut R,
) -> PlumSignature {
    let prf = &*DEFAULT_PARAMS;
    let m = pp.m;
    let n = pp.n;
    let b = pp.b;
    // Relaxed from `assert_eq!(m * n, b)` (May 2026): m·n is the actual
    // number of PRF tests the signature carries; B is the security
    // parameter (minimum tests required for soundness). m·n > B gives
    // free security buffer at the cost of slightly larger signatures.
    // λ=80 has m·n = B exactly (m=4, n=4). λ=100 has m·n = 24 > B = 21
    // (m=4, n=6 — 3 spare tests) because m=3 would break |H| = 2m = 6
    // as a power-of-2 (sumcheck FFT requires it). λ=128 has m·n = B
    // exactly (m=4, n=7).
    assert!(
        m * n >= b,
        "setup invariant violated: m·n ({}) < B ({}); under-tested signature would not meet λ-bit security",
        m * n,
        b
    );

    // ============================================================
    // Phase 1 — Commit to secret key and randomness
    // ============================================================
    // r_{i,j} ←$ F_p^* and T_{i,j} = L_0^t(r_{i,j}).
    let mut r_witnesses: Vec<Vec<Fp192>> = Vec::with_capacity(n);
    // Capacity = m·n (actual tests stored), not b (security parameter).
    // These can differ when m·n > b (e.g. λ=100: m·n=24, b=21).
    let mut t_tags: Vec<u8> = Vec::with_capacity(m * n);
    for _ in 0..n {
        let mut col = Vec::with_capacity(m);
        for _ in 0..m {
            let r_ij = Fp192::rand_nonzero(rng);
            col.push(r_ij);
        }
        for r_ij in &col {
            // L_0^t(r_{i,j}) — keyed at zero (Alg 3 line 5, paper p. 119).
            t_tags.push(prf.eval(r_ij) as u8);
        }
        r_witnesses.push(col);
    }

    // Build c_j = (K·r_{1,j}, r_{1,j}, ..., K·r_{m,j}, r_{m,j}) of length
    // 2m (Alg 3 line 6).
    let mut c_columns: Vec<Vec<Fp192>> = Vec::with_capacity(n);
    for j in 0..n {
        let mut c_j = Vec::with_capacity(2 * m);
        for i in 0..m {
            c_j.push(sk.k.clone() * r_witnesses[j][i].clone());
            c_j.push(r_witnesses[j][i].clone());
        }
        c_columns.push(c_j);
    }

    // ĉ_j = Interpolate(H, c_j), deg < 2m (line 6). Then ZK-randomize:
    // ĉ'_j = ĉ_j + Z_H · r̂_j with deg(r̂_j) ≤ κ_0·η (line 7).
    //
    // We use the standard "explicit coset interpolation" by sampling
    // |H| Lagrange points (H itself). For PLUM-128 |H| = 8 so this is
    // a single 8-point Lagrange per column, 7 times total.
    let h_points: Vec<Fp192> = (0..pp.h_size)
        .map(|k| {
            pp.h_shift.clone() * pp.h_generator.pow_u128(k as u128)
        })
        .collect();
    let zk_extra_deg = pp.kappa_0 * pp.eta;
    let mut c_prime_columns: Vec<Vec<Fp192>> = Vec::with_capacity(n);
    for j in 0..n {
        let c_hat = lagrange_interpolate(&h_points, &c_columns[j])
            .expect("H interpolation: distinct points by construction");
        // r̂_j of degree zk_extra_deg + 1 (chosen so that
        // deg(c'_j) < 2m + κ·η + 1 per Alg 3 line 7).
        let r_hat: Vec<Fp192> = (0..(zk_extra_deg + 2))
            .map(|_| Fp192::rand(rng))
            .collect();
        // Z_H(x) = Π(x − h) — multiply through h_points incrementally.
        let mut z_h_times_r_hat = r_hat.clone();
        for h in &h_points {
            let mut next = vec![Fp192::zero(); z_h_times_r_hat.len() + 1];
            for (k, c) in z_h_times_r_hat.iter().enumerate() {
                next[k] = next[k].clone() - h.clone() * c.clone();
                next[k + 1] = next[k + 1].clone() + c.clone();
            }
            z_h_times_r_hat = next;
        }
        // c'_j = c_hat + Z_H · r_hat (coefficient-wise add with padding).
        let len = c_hat.len().max(z_h_times_r_hat.len());
        let mut c_prime = vec![Fp192::zero(); len];
        for (k, v) in c_hat.iter().enumerate() {
            c_prime[k] = c_prime[k].clone() + v.clone();
        }
        for (k, v) in z_h_times_r_hat.iter().enumerate() {
            c_prime[k] = c_prime[k].clone() + v.clone();
        }
        c_prime_columns.push(c_prime);
    }

    // Evaluate every column on U via FFT, then hash row-wise.
    let c_prime_on_u: Vec<Vec<Fp192>> = c_prime_columns
        .iter()
        .map(|col| {
            // Pad to |U| for FFT, then evaluate on the subgroup U_0.
            let mut padded = col.clone();
            padded.resize(pp.u_size, Fp192::zero());
            evaluate_on_coset(&padded, &Fp192::one(), &pp.u_generator)
                .expect("FFT on U")
        })
        .collect();

    let leaf_digests: Vec<[u8; PLUM_DIGEST_BYTES]> = (0..pp.u_size)
        .map(|e| {
            let row: Vec<Fp192> = (0..n).map(|j| c_prime_on_u[j][e].clone()).collect();
            H::hash_fields(&row)
        })
        .collect();
    let merkle_c: PlumMerkleTree<H> =
        PlumMerkleTree::commit_digests(leaf_digests.clone());
    let root_c = merkle_c.root();

    // Build FS transcript and bind σ_1.
    let mut transcript = PlumTranscript::<H>::new(b"PLUM/sign/v1");
    transcript.append_bytes(b"M", message);
    transcript.append_root(b"root_c", &root_c);
    transcript.append_bytes(b"T", &t_tags);

    // ============================================================
    // Phase 2 — Residuosity symbols (Alg 3 lines 12–17)
    // ============================================================
    // h_1 = H_1(σ_1, M), then (I_{i,j}) ← Expand(h_1) ∈ I^{B}.
    // Generate m·n challenge indices (one per (i,j) grid position),
    // not b: when m·n > b (relaxed assertion case), we need full
    // i_values coverage of the grid.
    let challenge_indices: Vec<usize> =
        transcript.challenge_indices(b"phase2/indices", m * n, pp.l);
    let i_values: Vec<Fp192> = challenge_indices
        .iter()
        .map(|&idx| pp.challenge_set[idx].clone())
        .collect();
    // o_{i,j} = (K + I_{i,j}) · r_{i,j}.
    let mut o_responses = Vec::with_capacity(m * n);
    for j in 0..n {
        for i in 0..m {
            let idx = j * m + i;
            let o = (sk.k.clone() + i_values[idx].clone())
                * r_witnesses[j][i].clone();
            o_responses.push(o);
        }
    }
    transcript.append_fields(b"o_responses", &o_responses);

    // ============================================================
    // Phase 3 — Sumcheck witness + ZK (Alg 3 lines 18–23, Alg 4 lines 2–6)
    // ============================================================
    // h_2 = H_2(h_1, σ_2). (λ_{i,j}, ε_j) ← Expand(h_2).
    let mut lambdas: Vec<Vec<Fp192>> = Vec::with_capacity(n);
    for j in 0..n {
        let label = format!("phase3/lambda/{}", j);
        lambdas.push(transcript.challenge_fields(label.as_bytes(), m));
    }
    let epsilons: Vec<Fp192> = transcript.challenge_fields(b"phase3/epsilon", n);

    // q_j = (λ_{1,j}, λ_{1,j}·I_{1,j}, ..., λ_{m,j}, λ_{m,j}·I_{m,j})
    // ∈ F_p^{2m}.
    let mut q_columns: Vec<Vec<Fp192>> = Vec::with_capacity(n);
    for j in 0..n {
        let mut q_j = Vec::with_capacity(2 * m);
        for i in 0..m {
            let lambda = lambdas[j][i].clone();
            let idx = j * m + i;
            q_j.push(lambda.clone());
            q_j.push(lambda * i_values[idx].clone());
        }
        q_columns.push(q_j);
    }
    // q̂_j = Interpolate(H, q_j), deg < 2m. Then f̂_j = ĉ'_j · q̂_j.
    let mut f_hat_j: Vec<Vec<Fp192>> = Vec::with_capacity(n);
    for j in 0..n {
        let q_hat = lagrange_interpolate(&h_points, &q_columns[j])
            .expect("H interpolation in Phase 3");
        f_hat_j.push(multiply(&c_prime_columns[j], &q_hat));
    }
    // f̂ = Σ_j ε_j · f̂_j.
    let f_hat = sum_scaled(&f_hat_j, &epsilons);

    // ZK polynomial ŝ of degree 4m + κ_0·η − 1.
    let s_degree_plus_one = 4 * m + pp.kappa_0 * pp.eta;
    let s_hat: Vec<Fp192> = (0..s_degree_plus_one)
        .map(|_| Fp192::rand(rng))
        .collect();
    let s_sum = sum_over_coset(&s_hat, pp.h_size, &pp.h_shift);

    // Commit ŝ|_U via single-column Merkle.
    let mut s_padded = s_hat.clone();
    s_padded.resize(pp.u_size, Fp192::zero());
    let s_on_u = evaluate_on_coset(&s_padded, &Fp192::one(), &pp.u_generator)
        .expect("FFT for ŝ on U");
    let merkle_s: PlumMerkleTree<H> = PlumMerkleTree::commit(s_on_u.clone());
    let root_s = merkle_s.root();
    transcript.append_root(b"root_s", &root_s);
    transcript.append_field(b"s_sum", &s_sum);

    // ============================================================
    // Phase 4 — Univariate sumcheck (Alg 4 lines 7–12)
    // ============================================================
    // h_3 = H_3(h_2, σ_3), z = Expand(h_3) ∈ F_p.
    let z = transcript.challenge_field(b"phase4/z");
    // f̂' = z·f̂ + ŝ.
    let f_prime = scale_then_add(&f_hat, &z, &s_hat);
    // f̂' = ĝ + Z_H · ĥ, with deg(ĝ) < |H|.
    let (g_hat, h_hat) = decompose(&f_prime, pp.h_size, &pp.h_shift);

    // Commit ĥ|_U via single-column Merkle.
    let mut h_padded = h_hat.clone();
    h_padded.resize(pp.u_size, Fp192::zero());
    let h_on_u = evaluate_on_coset(&h_padded, &Fp192::one(), &pp.u_generator)
        .expect("FFT for ĥ on U");
    let merkle_h: PlumMerkleTree<H> = PlumMerkleTree::commit(h_on_u.clone());
    let root_h = merkle_h.root();
    transcript.append_root(b"root_h", &root_h);

    // ============================================================
    // Phase 5 — Rate correction for STIR (Alg 4 lines 13–16)
    // ============================================================
    // (r, r_0^fold) ← Expand(h_4).
    let r_phase5 = transcript.challenge_field(b"phase5/r");
    let r0_fold = transcript.challenge_field(b"phase5/r0_fold");

    // f̂_0 queries and STIR shift bases are derived INSIDE the STIR
    // loop, bound to `root_a_i` + `β_i` (paper Alg 5 line 11). See
    // the loop body below for the actual FS derivation.

    // Define f̂* (the initial STIR codeword). Per Alg 4 line 16, this is
    // a degree-d* linear combination of c̃' (which is f̂ here), ŝ, ĥ,
    // and p̂ with degree-shift factors t_k · r^{shift_k}. We compute it
    // explicitly here.
    //
    // The paper's formula at line 16:
    //   f̂*(x) := t_1(x) c̃'(x) + t_2(x) r^{1+e_1} ŝ(x)
    //          + t_3(x) r^{2+e_1+e_2} ĥ(x) + t_4(x) r^{3+e_1+e_2+e_3} p̂(x)
    // where t_k uses κ_0 and e_k are degree slacks computed from d* and
    // the deg(·) bounds. For PLUM-128 this gives a degree-d* polynomial
    // exactly.
    //
    // For the thesis cycle-attribution measurement, the bulk of work is
    // already in the polynomial mults; we follow the formula literally.
    let p_hat = compute_p_hat(&f_hat, &s_hat, &h_hat, &z, &pp.h_shift, pp.h_size);
    let d_star = pp.d_star;
    let kappa_eta = pp.kappa_0 * pp.eta;
    // Degree slacks (Alg 4 line 16):
    //   e_1 = d* − (2m + κ·η + 1)        ; for f̂ / c̃'
    //   e_2 = d* − (4m + κ·η)            ; for ŝ
    //   e_3 = d* − (2m + κ·η)            ; for ĥ
    //   e_4 = d* − (2m − 1)              ; for p̂
    let e1 = d_star.saturating_sub(2 * pp.m + kappa_eta + 1);
    let e2 = d_star.saturating_sub(4 * pp.m + kappa_eta);
    let e3 = d_star.saturating_sub(2 * pp.m + kappa_eta);
    let e4 = d_star.saturating_sub(2 * pp.m - 1);
    let t1 = degree_correction_polynomial(&r_phase5, e1);
    let t2 = degree_correction_polynomial(&r_phase5, e2);
    let t3 = degree_correction_polynomial(&r_phase5, e3);
    let t4 = degree_correction_polynomial(&r_phase5, e4);
    let r_pow = |k: u32| r_phase5.pow_u128(k as u128);
    let term1 = multiply(&t1, &f_hat);
    let term2 = scalar_mul(&multiply(&t2, &s_hat), &r_pow((1 + e1) as u32));
    let term3 = scalar_mul(&multiply(&t3, &h_hat), &r_pow((2 + e1 + e2) as u32));
    let term4 = scalar_mul(&multiply(&t4, &p_hat), &r_pow((3 + e1 + e2 + e3) as u32));
    let f_star = poly_add_many(&[term1, term2, term3, term4]);

    // Evaluate f̂* on U_0 to seed the STIR fold.
    let mut f_star_padded = f_star.clone();
    f_star_padded.resize(pp.u_size, Fp192::zero());
    let f0_on_u = evaluate_on_coset(&f_star_padded, &Fp192::one(), &pp.u_generator)
        .expect("FFT for f̂* on U_0");

    // ============================================================
    // Phase 6 — STIR folding (Alg 5)
    // ============================================================
    let r_rounds = pp.r_rounds;
    let mut stir_roots = Vec::with_capacity(r_rounds);
    let mut stir_betas = Vec::with_capacity(r_rounds);
    let mut stir_a_openings: Vec<Vec<PlumMerkleProof>> = Vec::with_capacity(r_rounds);
    let mut current_evals = f0_on_u;
    let mut current_generator = pp.u_generator.clone();
    let mut current_size = pp.u_size;
    let mut current_r_fold = r0_fold;
    let mut last_round_coeffs: Option<Vec<Fp192>> = None;
    // Captured at the end of the last STIR round, used for the
    // final-polynomial check (Alg 6 line 18). For R = 1, this is
    // round 0's state.
    let mut last_round_merkle_a: Option<PlumMerkleTree<H>> = None;
    let mut last_round_shift_bases: Option<Vec<usize>> = None;

    // f̂_0 query openings are populated when round 0 runs.
    let mut query_indices: Vec<usize> = Vec::new();
    let mut c_prime_openings: Vec<Vec<Fp192>> = Vec::new();
    let mut c_prime_paths: Vec<Vec<[u8; PLUM_DIGEST_BYTES]>> = Vec::new();
    let mut s_openings: Vec<PlumMerkleProof> = Vec::new();
    let mut h_openings: Vec<PlumMerkleProof> = Vec::new();

    for round in 0..r_rounds {
        // Fold f̂_{i-1}|_{U_{i-1}} → â_i (coefficient form, length
        // current_size / η).
        let a_i = stir_fold(
            &current_evals,
            &current_generator,
            pp.eta,
            &current_r_fold,
        )
        .expect("STIR fold");

        // Commit â_i|_{U_{i-1}^η}. Note: setup.rs's u_sizes descends
        // by η (not η² as Alg 1 line 17 specifies). The commitment
        // domain here matches that convention: it is the subgroup
        // U_{i-1}^η of size current_size/η.
        let next_size = current_size / pp.eta;
        let next_gen = current_generator.pow_u128(pp.eta as u128);
        let mut a_i_padded = a_i.clone();
        a_i_padded.resize(next_size, Fp192::zero());
        let a_i_on_u = evaluate_on_coset(&a_i_padded, &Fp192::one(), &next_gen)
            .expect("FFT for â_i on U_{i-1}^η");
        let merkle_a: PlumMerkleTree<H> = PlumMerkleTree::commit(a_i_on_u.clone());
        let root_a = merkle_a.root();
        stir_roots.push(root_a);
        transcript.append_root(b"stir/root", &root_a);

        // β_i = â_i(r_i^out).
        let r_out: Fp192 = transcript.challenge_field(b"stir/r_out");
        let beta = evaluate(&a_i, &r_out);
        stir_betas.push(beta.clone());
        transcript.append_field(b"stir/beta", &beta);

        // (r_i^fold, r_i^comb, shift_bases) ← Expand(H_STIR(β_i)).
        // Paper Alg 5 line 11: shifts ∈ U_{i-1}^η. We derive shift
        // INDICES into [0, |U_{i-1}|/η) and map them to U_{i-1}^η via
        // current_generator^{b · η}. The same indices serve as
        // Merkle-leaf indices into â_i's commitment (since â_i is
        // committed on U_{i-1}^η in the order produced by the FFT).
        let next_r_fold = transcript.challenge_field(b"stir/r_fold");
        let r_comb = transcript.challenge_field(b"stir/r_comb");
        let kappa_shift = if round == 0 {
            pp.kappa_0.div_ceil(pp.eta)
        } else {
            pp.kappas[round]
        };
        // Over-sample to dedupe — challenge_indices samples with
        // replacement and at PLUM-128's kappa_shift = 7 into
        // |U_0|/η = 1024, the birthday probability of any pair
        // collision is ≈ 2%. We sample 2× and take the first
        // `kappa_shift` distinct.
        let raw_bases: Vec<usize> = transcript.challenge_indices(
            b"stir/shift_bases",
            kappa_shift * 2,
            next_size,
        );
        let mut shift_bases: Vec<usize> = Vec::with_capacity(kappa_shift);
        for b in &raw_bases {
            if !shift_bases.contains(b) {
                shift_bases.push(*b);
                if shift_bases.len() == kappa_shift {
                    break;
                }
            }
        }
        assert_eq!(
            shift_bases.len(),
            kappa_shift,
            "FS sampling failed to produce {} distinct shift bases from 2x oversample; \
             increase oversample factor",
            kappa_shift
        );
        let r_shifts: Vec<Fp192> = shift_bases
            .iter()
            .map(|&b| current_generator.pow_u128((b * pp.eta) as u128))
            .collect();

        // Open â_i at each shift base (Merkle path on U_{i-1}^η).
        let a_openings_this_round: Vec<PlumMerkleProof> =
            shift_bases.iter().map(|&b| merkle_a.open(b)).collect();
        stir_a_openings.push(a_openings_this_round);

        // For round 0 only, also open f̂_{i-1} = f̂_0 at the fiber
        // points above each shift base. Fiber for base b in U_0:
        // {b, b + |U_0|/η, ..., b + (η−1)·|U_0|/η}.
        if round == 0 {
            let u_over_eta = pp.u_size / pp.eta;
            for &base in &shift_bases {
                for t in 0..pp.eta {
                    query_indices.push(base + t * u_over_eta);
                }
            }
            c_prime_openings = query_indices
                .iter()
                .map(|&e| (0..n).map(|j| c_prime_on_u[j][e].clone()).collect())
                .collect();
            c_prime_paths = query_indices
                .iter()
                .map(|&e| merkle_c.open_digest(e))
                .collect();
            s_openings = query_indices.iter().map(|&e| merkle_s.open(e)).collect();
            h_openings = query_indices.iter().map(|&e| merkle_h.open(e)).collect();
        }

        // Rate correction. G_i = {r_i^out, r_{i,1}^shift, ..., r_{i,κ}^shift}.
        let mut g_i = Vec::with_capacity(1 + r_shifts.len());
        g_i.push(r_out.clone());
        g_i.extend_from_slice(&r_shifts);
        let mut values = Vec::with_capacity(g_i.len());
        values.push(beta.clone());
        for r_shift in &r_shifts {
            values.push(evaluate(&a_i, r_shift));
        }
        let a_prime = rate_correct(&a_i, &g_i, &values).expect("rate_correct");
        let f_i = apply_degree_correction(&a_prime, &r_comb, r_shifts.len());

        if round + 1 == r_rounds {
            last_round_coeffs = Some(f_i);
            last_round_merkle_a = Some(merkle_a);
            last_round_shift_bases = Some(shift_bases.clone());
        } else {
            let mut f_i_padded = f_i.clone();
            f_i_padded.resize(next_size, Fp192::zero());
            current_evals = evaluate_on_coset(&f_i_padded, &Fp192::one(), &next_gen)
                .expect("FFT for f̂_i on next domain");
        }
        // Always advance the FS/domain state for the final fold or
        // the next round.
        current_generator = next_gen;
        current_size = next_size;
        current_r_fold = next_r_fold;
    }

    // Final-poly: fold f̂_R one more time (Alg 5 line 14). After the
    // loop, current_r_fold = r_R^fold (the r_fold derived inside the
    // last round, which is the input to the final fold).
    let f_r = last_round_coeffs.expect("STIR loop produced no rounds");
    let final_coefs = fold_coefficients(&f_r, pp.eta, &current_r_fold);
    transcript.append_fields(b"stir/final_coefs", &final_coefs);

    // Final-poly query openings (Alg 5 line 15-16). FS-derive t_M
    // base indices in [0, |U_R|/η). Each base b defines η fiber
    // points in U_R at indices {b, b + |U_R|/η, ..., b + (η−1)·|U_R|/η}.
    // We open â_R (= last round's merkle_a, committed on U_R of size
    // current_size) at those fiber points.
    let last_merkle_a = last_round_merkle_a.expect("STIR loop produced merkle_a");
    let last_shift_bases =
        last_round_shift_bases.expect("STIR loop populated shift_bases");
    let t_m = pp.kappas[pp.r_rounds];
    let final_size_over_eta = current_size / pp.eta;
    // Filter: a final base b ∈ [0, final_size_over_eta) produces η
    // fiber indices {b + t · final_size_over_eta : t ∈ [0, η)} in
    // U_R's commitment indexing. Any of these coinciding with a
    // shift base in U_R's space would make â_R(fiber) ≡ â_R(shift)
    // = b̂_R(shift), so Π(fiber − α∈G_R) would be zero — division by
    // zero in the f̂_R reconstruction. Excluding these residue classes
    // up-front keeps the verifier deterministic and well-defined.
    let forbidden_residues: std::collections::HashSet<usize> = last_shift_bases
        .iter()
        .map(|&b| b % final_size_over_eta)
        .collect();
    let raw_final_bases: Vec<usize> = transcript.challenge_indices(
        b"stir/final_bases",
        t_m * 3,
        final_size_over_eta,
    );
    let mut final_bases: Vec<usize> = Vec::with_capacity(t_m);
    for b in &raw_final_bases {
        if !forbidden_residues.contains(b) && !final_bases.contains(b) {
            final_bases.push(*b);
            if final_bases.len() == t_m {
                break;
            }
        }
    }
    assert_eq!(
        final_bases.len(),
        t_m,
        "FS sampling failed to produce {} distinct, non-forbidden final bases from 3x oversample",
        t_m
    );
    let mut stir_final_a_openings: Vec<Vec<PlumMerkleProof>> = Vec::with_capacity(t_m);
    for &b in &final_bases {
        let fiber: Vec<PlumMerkleProof> = (0..pp.eta)
            .map(|t| last_merkle_a.open(b + t * final_size_over_eta))
            .collect();
        stir_final_a_openings.push(fiber);
    }

    PlumSignature {
        root_c,
        t_tags,
        o_responses,
        root_s,
        s_sum,
        root_h,
        stir_roots,
        stir_betas,
        stir_a_openings,
        stir_final_a_openings,
        final_coefs,
        query_indices,
        c_prime_openings,
        c_prime_paths,
        s_openings,
        h_openings,
    }
}

// ============================================================
// Helpers
// ============================================================

/// `Σ_j scalars[j] · polys[j]` in coefficient form.
fn sum_scaled(polys: &[Vec<Fp192>], scalars: &[Fp192]) -> Vec<Fp192> {
    debug_assert_eq!(polys.len(), scalars.len());
    let mut out: Vec<Fp192> = Vec::new();
    for (poly, scalar) in polys.iter().zip(scalars.iter()) {
        if out.len() < poly.len() {
            out.resize(poly.len(), Fp192::zero());
        }
        for (k, c) in poly.iter().enumerate() {
            out[k] = out[k].clone() + scalar.clone() * c.clone();
        }
    }
    out
}

/// `z · a(x) + b(x)` in coefficient form.
fn scale_then_add(a: &[Fp192], z: &Fp192, b: &[Fp192]) -> Vec<Fp192> {
    let len = a.len().max(b.len());
    let mut out = vec![Fp192::zero(); len];
    for (k, c) in a.iter().enumerate() {
        out[k] = out[k].clone() + z.clone() * c.clone();
    }
    for (k, c) in b.iter().enumerate() {
        out[k] = out[k].clone() + c.clone();
    }
    out
}

fn scalar_mul(p: &[Fp192], s: &Fp192) -> Vec<Fp192> {
    p.iter().map(|c| c.clone() * s.clone()).collect()
}

fn poly_add_many(polys: &[Vec<Fp192>]) -> Vec<Fp192> {
    let len = polys.iter().map(|p| p.len()).max().unwrap_or(0);
    let mut out = vec![Fp192::zero(); len];
    for poly in polys {
        for (k, c) in poly.iter().enumerate() {
            out[k] = out[k].clone() + c.clone();
        }
    }
    out
}

/// Build `p̂(x)` such that the BCRSVW univariate-sumcheck identity
/// `|H| · f̂'(x) = |H| · Z_H(x) · ĥ(x) + (z µ + S) + |H| · x · p̂(x)`
/// holds, where `µ = Σ_{a ∈ H} f̂(a)` (which the prover computes from
/// the witness vector).
///
/// Equivalently, after rearranging Alg 4 line 14:
///   p̂(x) = (|H| · f̂'(x) − |H| · Z_H(x) · ĥ(x) − (z µ + S)) / (|H| · x).
///
/// For `x = 0` the numerator is `|H| · (f̂'(0) − Z_H(0)·ĥ(0)) − (zµ+S)
/// = |H| · ĝ(0) − (zµ+S)`. From the sumcheck identity
/// `Σ_a ĝ(a) = z µ + S` and the trick for multiplicative cosets
/// `Σ_a ĝ(a) = |H| · ĝ_0`, this is zero — so the division by `|H| · x`
/// is exact.
fn compute_p_hat(
    f_hat: &[Fp192],
    s_hat: &[Fp192],
    h_hat: &[Fp192],
    z: &Fp192,
    h_shift: &Fp192,
    h_size: usize,
) -> Vec<Fp192> {
    // µ = Σ_{a ∈ H} f̂(a) and S = Σ_{a ∈ H} ŝ(a).
    let mu = sum_over_coset(f_hat, h_size, h_shift);
    let s_sum = sum_over_coset(s_hat, h_size, h_shift);
    let target = z.clone() * mu + s_sum;
    let h_size_field = Fp192::from_u64(h_size as u64);
    let h_size_inv = h_size_field
        .clone()
        .inverse()
        .expect("|H| nonzero in F_p");

    // f̂'(x) = z · f̂(x) + ŝ(x).
    let f_prime_len = f_hat.len().max(s_hat.len());
    let mut f_prime = vec![Fp192::zero(); f_prime_len];
    for (k, c) in f_hat.iter().enumerate() {
        f_prime[k] = f_prime[k].clone() + z.clone() * c.clone();
    }
    for (k, c) in s_hat.iter().enumerate() {
        f_prime[k] = f_prime[k].clone() + c.clone();
    }

    // Z_H(x) = x^|H| − h_shift^|H| (closed form for `H = h_shift · ⟨ω⟩`).
    let h_shift_pow_h = h_shift.pow_u128(h_size as u128);
    let mut z_h = vec![Fp192::zero(); h_size + 1];
    z_h[0] = Fp192::zero() - h_shift_pow_h;
    z_h[h_size] = Fp192::one();
    let z_h_times_h = multiply(&z_h, h_hat);

    // numerator(x) = |H| · f̂'(x) − |H| · Z_H(x) · ĥ(x) − target
    let len = f_prime.len().max(z_h_times_h.len()).max(1);
    let mut numerator = vec![Fp192::zero(); len];
    for (k, c) in f_prime.iter().enumerate() {
        numerator[k] = numerator[k].clone() + h_size_field.clone() * c.clone();
    }
    for (k, c) in z_h_times_h.iter().enumerate() {
        numerator[k] = numerator[k].clone() - h_size_field.clone() * c.clone();
    }
    numerator[0] = numerator[0].clone() - target;

    // numerator(0) must be zero by the BCRSVW sumcheck identity. If it
    // ever is not, the protocol's structural invariants are broken.
    debug_assert!(
        numerator[0].is_zero(),
        "compute_p_hat: numerator(0) ≠ 0 — sumcheck identity broken"
    );

    // p̂(x) = numerator(x) / (|H| · x). Division by x = drop constant
    // term and shift down by one. Division by |H| = scale.
    numerator[1..]
        .iter()
        .map(|c| c.clone() * h_size_inv.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::plum::hasher::PlumSha3Hasher;
    use crate::signatures::plum::keygen::plum_keygen;
    use crate::signatures::plum::setup::plum_setup;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn sign_produces_signature_with_expected_shape() {
        let pp = plum_setup(128).expect("setup");
        let mut rng = ChaCha20Rng::seed_from_u64(0xC000_0001);
        let (sk, _pk) = plum_keygen(&pp, &mut rng);
        let sig = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"hello world", &mut rng);
        // At λ=128, m·n = 4·7 = 28 = b exactly. At λ=80 same (m·n=16=b).
        // At λ=100, m·n=24 > b=21 — see relaxed-assertion comment in
        // `plum_sign`. The wire format carries m·n entries.
        assert_eq!(sig.t_tags.len(), pp.m * pp.n);
        assert_eq!(sig.o_responses.len(), pp.m * pp.n);
        assert_eq!(sig.stir_roots.len(), pp.r_rounds);
        assert_eq!(sig.stir_betas.len(), pp.r_rounds);
        // Semantic degree of f̂_{R+1} is < d_stop = 32 per Algorithm 5
        // line 14, but the current implementation carries trailing
        // zeros from FFT-domain padding so the array can be larger.
        // The semantic correctness check is verify-accepts, not array
        // length. Bound here is a sanity check on the FFT path.
        assert!(sig.final_coefs.len() <= pp.u_size / pp.eta + 1);
        // The high coefficients above d_stop should all be zero.
        for (k, c) in sig.final_coefs.iter().enumerate() {
            if k >= pp.d_stop {
                assert!(
                    c.is_zero(),
                    "final_coefs[{}] = {:?} above d_stop = {} is nonzero",
                    k,
                    c,
                    pp.d_stop
                );
            }
        }
    }

    #[test]
    fn sign_is_deterministic_with_same_rng_seed() {
        let pp = plum_setup(128).expect("setup");
        let (sk, _pk) = plum_keygen(
            &pp,
            &mut ChaCha20Rng::seed_from_u64(0xC000_0010),
        );
        let s1 = plum_sign::<PlumSha3Hasher, _>(
            &pp,
            &sk,
            b"msg",
            &mut ChaCha20Rng::seed_from_u64(0xC000_0011),
        );
        let s2 = plum_sign::<PlumSha3Hasher, _>(
            &pp,
            &sk,
            b"msg",
            &mut ChaCha20Rng::seed_from_u64(0xC000_0011),
        );
        assert_eq!(s1.root_c, s2.root_c);
        assert_eq!(s1.t_tags, s2.t_tags);
        assert_eq!(s1.o_responses, s2.o_responses);
        assert_eq!(s1.root_s, s2.root_s);
        assert_eq!(s1.s_sum, s2.s_sum);
        assert_eq!(s1.root_h, s2.root_h);
        assert_eq!(s1.final_coefs, s2.final_coefs);
    }

    #[test]
    fn different_messages_yield_different_residuosity_responses() {
        let pp = plum_setup(128).expect("setup");
        let (sk, _pk) = plum_keygen(
            &pp,
            &mut ChaCha20Rng::seed_from_u64(0xC000_0020),
        );
        let mut rng = ChaCha20Rng::seed_from_u64(0xC000_0021);
        let s1 = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"a", &mut rng);
        let mut rng = ChaCha20Rng::seed_from_u64(0xC000_0021);
        let s2 = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, b"b", &mut rng);
        // Same RNG, different message → same r_{i,j} but different
        // Fiat-Shamir challenges, so different o_responses.
        assert_ne!(s1.o_responses, s2.o_responses);
    }
}
