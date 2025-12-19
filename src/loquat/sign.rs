#[cfg(feature = "std")]
use super::encoding;
#[cfg(feature = "std")]
use super::errors::{LoquatError, LoquatResult};
#[cfg(feature = "std")]
use super::field_utils;
use super::field_utils::{F, F2};
#[cfg(feature = "std")]
use super::hasher::{GriffinHasher, LoquatHasher};
#[cfg(feature = "std")]
use super::ldt::LDTOpening;
use super::ldt::LDTProof;
use super::sumcheck::UnivariateSumcheckProof;
#[cfg(feature = "std")]
use super::transcript::{FieldTranscript, expand_f, expand_f2_real, expand_index};
#[cfg(feature = "std")]
use super::{
    fft::{evaluate_on_coset, interpolate_on_coset},
    field_utils::legendre_prf_secure,
    keygen::LoquatKeyPair,
    merkle::{MerkleConfig, MerkleTree},
    setup::LoquatPublicParams,
    sumcheck::generate_sumcheck_proof,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::{cmp, string::ToString};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoquatSignature {
    /// The root of the Merkle tree of LDT commitments.
    pub root_c: [u8; 32],
    /// Merkle root for s evaluations.
    pub root_s: [u8; 32],
    /// Merkle root for h evaluations.
    pub root_h: [u8; 32],
    /// Tree-cap layer nodes (paper §4.3) for the c' Merkle commitment.
    /// When non-empty, Merkle proofs are truncated to this layer and the root is
    /// computed by hashing these nodes together.
    pub c_cap_nodes: Vec<[u8; 32]>,
    /// Tree-cap layer nodes (paper §4.3) for the ŝ Merkle commitment.
    pub s_cap_nodes: Vec<[u8; 32]>,
    /// Tree-cap layer nodes (paper §4.3) for the ĥ Merkle commitment.
    pub h_cap_nodes: Vec<[u8; 32]>,
    /// Openings for c′/ŝ/ĥ at the LDT query positions (paper §4.3).
    pub query_openings: Vec<LoquatQueryOpening>,
    /// The values of the t polynomial at the query points.
    pub t_values: Vec<Vec<F>>,
    /// The values of the o polynomial at the query points.
    pub o_values: Vec<Vec<F>>,
    /// FRI folding challenges h_{5+i}.
    pub fri_challenges: Vec<F2>,
    /// Challenge vector e used in Algorithm 5.
    pub e_vector: Vec<F2>,
    /// Sum Σ_{a∈H} ŝ(a).
    pub s_sum: F2,
    /// Claimed sum μ.
    pub mu: F2,
    /// Challenge z used in Algorithm 5.
    pub z_challenge: F2,
    /// The univariate sumcheck proof.
    pub pi_us: UnivariateSumcheckProof,
    /// The LDT proof.
    pub ldt_proof: LDTProof,
    /// The message commitment.
    pub message_commitment: Vec<u8>,
    /// Optional signing transcript for debugging/instrumentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript: Option<LoquatSigningTranscript>,
}

impl LoquatSignature {
    pub fn new(
        artifact: LoquatSignatureArtifact,
        transcript: Option<LoquatSigningTranscript>,
    ) -> Self {
        Self {
            root_c: artifact.root_c,
            root_s: artifact.root_s,
            root_h: artifact.root_h,
            c_cap_nodes: artifact.c_cap_nodes,
            s_cap_nodes: artifact.s_cap_nodes,
            h_cap_nodes: artifact.h_cap_nodes,
            query_openings: artifact.query_openings,
            t_values: artifact.t_values,
            o_values: artifact.o_values,
            fri_challenges: artifact.fri_challenges,
            e_vector: artifact.e_vector,
            s_sum: artifact.s_sum,
            mu: artifact.mu,
            z_challenge: artifact.z_challenge,
            pi_us: artifact.pi_us,
            ldt_proof: artifact.ldt_proof,
            message_commitment: artifact.message_commitment,
            transcript,
        }
    }

    pub fn artifact(&self) -> LoquatSignatureArtifact {
        self.into()
    }

    pub fn transcript(&self) -> Option<&LoquatSigningTranscript> {
        self.transcript.as_ref()
    }
}

#[cfg(feature = "std")]
pub fn flatten_signature_for_hash(signature: &LoquatSignature) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&signature.root_c);
    bytes.extend_from_slice(&signature.root_s);
    bytes.extend_from_slice(&signature.root_h);
    for node in &signature.c_cap_nodes {
        bytes.extend_from_slice(node);
    }
    for node in &signature.s_cap_nodes {
        bytes.extend_from_slice(node);
    }
    for node in &signature.h_cap_nodes {
        bytes.extend_from_slice(node);
    }
    flatten_field_matrix(&signature.t_values, &mut bytes);
    flatten_field_matrix(&signature.o_values, &mut bytes);
    flatten_field2_vector(&signature.fri_challenges, &mut bytes);
    flatten_field2_vector(&signature.e_vector, &mut bytes);
    bytes.extend_from_slice(&field_utils::field2_to_bytes(&signature.s_sum));
    bytes.extend_from_slice(&field_utils::field2_to_bytes(&signature.mu));
    bytes.extend_from_slice(&field_utils::field2_to_bytes(&signature.z_challenge));
    bytes.extend_from_slice(&field_utils::field2_to_bytes(&signature.pi_us.claimed_sum));
    bytes.extend_from_slice(&field_utils::field2_to_bytes(
        &signature.pi_us.final_evaluation,
    ));
    for poly in &signature.pi_us.round_polynomials {
        bytes.extend_from_slice(&field_utils::field2_to_bytes(&poly.c0));
        bytes.extend_from_slice(&field_utils::field2_to_bytes(&poly.c1));
    }
    for opening in &signature.ldt_proof.openings {
        bytes.extend_from_slice(&(opening.position as u64).to_le_bytes());
        flatten_nested_field2(&opening.codeword_chunks, &mut bytes);
        for path in &opening.auth_paths {
            flatten_byte_paths(path, &mut bytes);
        }
    }
    for opening in &signature.query_openings {
        bytes.extend_from_slice(&(opening.position as u64).to_le_bytes());
        for col in &opening.c_prime_chunk {
            flatten_field2_vector(col, &mut bytes);
        }
        flatten_field2_vector(&opening.s_chunk, &mut bytes);
        flatten_field2_vector(&opening.h_chunk, &mut bytes);
        flatten_byte_paths(&opening.c_auth_path, &mut bytes);
        flatten_byte_paths(&opening.s_auth_path, &mut bytes);
        flatten_byte_paths(&opening.h_auth_path, &mut bytes);
    }
    bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoquatQueryOpening {
    pub position: usize,
    pub c_prime_chunk: Vec<Vec<F2>>,
    pub s_chunk: Vec<F2>,
    pub h_chunk: Vec<F2>,
    pub c_auth_path: Vec<Vec<u8>>,
    pub s_auth_path: Vec<Vec<u8>>,
    pub h_auth_path: Vec<Vec<u8>>,
}

#[cfg(feature = "std")]
fn flatten_field_matrix(matrix: &[Vec<F>], out: &mut Vec<u8>) {
    for row in matrix {
        for value in row {
            out.extend_from_slice(&field_utils::field_to_bytes(value));
        }
    }
}

#[cfg(feature = "std")]
fn flatten_field2_matrix(matrix: &[Vec<F2>], out: &mut Vec<u8>) {
    for row in matrix {
        flatten_field2_vector(row, out);
    }
}

#[cfg(feature = "std")]
fn flatten_field2_vector(values: &[F2], out: &mut Vec<u8>) {
    for value in values {
        out.extend_from_slice(&field_utils::field2_to_bytes(value));
    }
}

#[cfg(feature = "std")]
fn flatten_nested_field2(matrix: &[Vec<F2>], out: &mut Vec<u8>) {
    for row in matrix {
        flatten_field2_vector(row, out);
    }
}

#[cfg(feature = "std")]
fn flatten_two_nested_field2(blocks: &[Vec<Vec<F2>>], out: &mut Vec<u8>) {
    for block in blocks {
        flatten_nested_field2(block, out);
    }
}

#[cfg(feature = "std")]
fn flatten_byte_paths(paths: &[Vec<u8>], out: &mut Vec<u8>) {
    for node in paths {
        out.extend_from_slice(node);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoquatSignatureArtifact {
    pub root_c: [u8; 32],
    pub root_s: [u8; 32],
    pub root_h: [u8; 32],
    pub c_cap_nodes: Vec<[u8; 32]>,
    pub s_cap_nodes: Vec<[u8; 32]>,
    pub h_cap_nodes: Vec<[u8; 32]>,
    pub query_openings: Vec<LoquatQueryOpening>,
    pub t_values: Vec<Vec<F>>,
    pub o_values: Vec<Vec<F>>,
    pub fri_challenges: Vec<F2>,
    pub e_vector: Vec<F2>,
    pub s_sum: F2,
    pub mu: F2,
    pub z_challenge: F2,
    pub pi_us: UnivariateSumcheckProof,
    pub ldt_proof: LDTProof,
    pub message_commitment: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoquatSigningTranscript {
    /// Randomness matrix r_{j,i} captured during signing.
    pub randomness_matrix: Vec<Vec<F>>,
    /// Original evaluations of c_j over H before masking.
    pub c_evals_on_h: Vec<Vec<F2>>,
}

impl From<&LoquatSignature> for LoquatSignatureArtifact {
    fn from(sig: &LoquatSignature) -> Self {
        Self {
            root_c: sig.root_c,
            root_s: sig.root_s,
            root_h: sig.root_h,
            c_cap_nodes: sig.c_cap_nodes.clone(),
            s_cap_nodes: sig.s_cap_nodes.clone(),
            h_cap_nodes: sig.h_cap_nodes.clone(),
            query_openings: sig.query_openings.clone(),
            t_values: sig.t_values.clone(),
            o_values: sig.o_values.clone(),
            fri_challenges: sig.fri_challenges.clone(),
            e_vector: sig.e_vector.clone(),
            s_sum: sig.s_sum,
            mu: sig.mu,
            z_challenge: sig.z_challenge,
            pi_us: sig.pi_us.clone(),
            ldt_proof: sig.ldt_proof.clone(),
            message_commitment: sig.message_commitment.clone(),
        }
    }
}

#[cfg(feature = "std")]
pub fn loquat_sign(
    message: &[u8],
    keypair: &LoquatKeyPair,
    params: &LoquatPublicParams,
) -> Result<LoquatSignature, LoquatError> {
    loquat_debug!("\n================== ALGORITHMS 4-6: LOQUAT SIGN ==================");
    loquat_debug!("INPUT: Public parameter L-pp, secret key sk, message M");
    loquat_debug!("Following Algorithms 4, 5, 6 specification from rules.mdc");
    loquat_debug!("Message length: {} bytes", message.len());
    loquat_debug!(
        "Public key length: {} field elements",
        keypair.public_key.len()
    );
    loquat_debug!(
        "Parameters: m={}, n={}, L={}, B={}, κ={}",
        params.m,
        params.n,
        params.l,
        params.b,
        params.kappa
    );

    let mut transcript = FieldTranscript::new(b"loquat_signature");

    // Use Griffin hash for message commitment (SNARK-friendly)
    let message_commitment = GriffinHasher::hash(message);
    let mut message_commitment_arr = [0u8; 32];
    message_commitment_arr.copy_from_slice(&message_commitment);
    transcript.append_digest32_as_fields(b"message_commitment", &message_commitment_arr);
    loquat_debug!(
        "✓ Message commitment computed: {} bytes",
        message_commitment.len()
    );

    // Use TreeCap to halve Merkle leaf count as in paper §4.3.
    let merkle_leaf_arity = 1usize << params.eta;
    // Layer-t cap (paper §4.3): truncate auth paths at depth t≈log2(κ) and hash
    // those cap nodes together to form the root.
    let leaf_count = (params.coset_u.len() / merkle_leaf_arity.max(1)).max(1);
    let tree_height = if leaf_count.is_power_of_two() {
        leaf_count.trailing_zeros() as usize
    } else {
        0
    };
    let cap_height = (usize::BITS - 1 - params.kappa.max(1).leading_zeros()) as usize;
    let cap_height = cap_height.min(tree_height);
    let merkle_config = MerkleConfig::tree_cap(merkle_leaf_arity).with_cap_height(cap_height);

    loquat_debug!("\n================== ALGORITHM 4: LOQUAT SIGN PART I ==================");

    // Phase 1: Commit to secret key and randomness
    loquat_debug!("\n--- PHASE 1: Commit to secret key and randomness ---");
    loquat_debug!("Following Algorithm 4, Phase 1 specification");

    loquat_debug!("\n--- Step 1.1: Computing T values (Legendre PRF outputs) ---");

    let mut rng = rand::thread_rng();
    let mut c_prime_evals_on_u: Vec<Vec<F2>> =
        vec![Vec::with_capacity(params.n); params.coset_u.len()];
    let mut c_prime_on_u_per_j: Vec<Vec<F2>> = Vec::with_capacity(params.n);
    let mut c_on_h_per_j: Vec<Vec<F2>> = Vec::with_capacity(params.n);
    let mut t_values = Vec::with_capacity(params.n);
    let mut r_values: Vec<Vec<F>> = vec![Vec::with_capacity(params.m); params.n];

    let h_order = params.coset_h.len() as u128;
    let z_h_constant = params.h_shift.pow(h_order);
    let z_h_on_u: Vec<F2> = params
        .coset_u
        .iter()
        .map(|&u| u.pow(h_order) - z_h_constant)
        .collect();

    loquat_debug!("✓ Generated vanishing polynomial values Z_H(x) over U");

    loquat_debug!("✓ Sampling randomness matrix r_{{j,i}} and constructing masked polynomials");

    let u_len = params.coset_u.len();
    for j in 0..params.n {
        let mut t_j = Vec::with_capacity(params.m);
        let mut c_j_evals_on_h = Vec::with_capacity(2 * params.m);

        for _ in 0..params.m {
            let r_sample = F::rand_nonzero(&mut rng);
            r_values[j].push(r_sample);
            let t_val = legendre_prf_secure(r_sample);
            t_j.push(t_val);
            c_j_evals_on_h.push(F2::new(keypair.secret_key * r_sample, F::zero()));
            c_j_evals_on_h.push(F2::new(r_sample, F::zero()));
        }
        t_values.push(t_j);
        c_on_h_per_j.push(c_j_evals_on_h.clone());

        let c_hat_coeffs =
            interpolate_on_coset(&c_j_evals_on_h, params.h_shift, params.h_generator)?;
        let mut c_hat_coeffs_padded = vec![F2::zero(); u_len];
        c_hat_coeffs_padded[..c_hat_coeffs.len()].copy_from_slice(&c_hat_coeffs);
        let c_hat_on_u =
            evaluate_on_coset(&c_hat_coeffs_padded, params.u_shift, params.u_generator)?;

        let mut r_hat_coeffs = vec![F2::zero(); u_len];
        let mask_bound = params.kappa.saturating_mul(1 << params.eta);
        if u_len > 0 {
            let max_index = cmp::min(mask_bound, u_len - 1);
            for coeff in r_hat_coeffs.iter_mut().take(max_index + 1) {
                *coeff = F2::rand(&mut rng);
            }
        }
        let r_hat_on_u = evaluate_on_coset(&r_hat_coeffs, params.u_shift, params.u_generator)?;

        let mut c_prime_on_u = Vec::with_capacity(u_len);
        for i in 0..u_len {
            let value = c_hat_on_u[i] + (z_h_on_u[i] * r_hat_on_u[i]);
            c_prime_evals_on_u[i].push(value);
            c_prime_on_u.push(value);
        }
        c_prime_on_u_per_j.push(c_prime_on_u);
    }

    loquat_debug!(
        "✓ Generated randomness matrix r_{{j,i}} for j ∈ [{}], i ∈ [{}]",
        params.n,
        params.m
    );
    loquat_debug!("✓ Masked commitments prepared for Merkle binding over U");

    loquat_debug!("✓ Computed masked evaluations ĉ'_j|_U for all j ∈ [n]");

    // Merkle tree commitment to c' evaluations over U
    loquat_debug!("\n--- Step 1.4: Merkle commitment to c'_j evaluations over U ---");
    let leaves: Vec<Vec<u8>> = c_prime_evals_on_u
        .iter()
        .map(|evals| field_utils::serialize_field2_slice(evals))
        .collect();
    let merkle_tree = MerkleTree::new_with_config(&leaves, merkle_config);
    let root_c: [u8; 32] = merkle_tree
        .root()
        .unwrap()
        .try_into()
        .expect("root is not 32 bytes");
    transcript.append_digest32_as_fields(b"root_c", &root_c);
    loquat_debug!(
        "✓ Merkle tree created with {} leaves for |U| = {}",
        leaves.len(),
        params.coset_u.len()
    );
    loquat_debug!("✓ root_c committed to transcript");

    let mut t_flat = Vec::with_capacity(params.m * params.n);
    for row in &t_values {
        t_flat.extend_from_slice(row);
    }
    transcript.append_f_vec(b"t_values", &t_flat);
    loquat_debug!("✓ σ₁ = (root_c, {{T_{{i,j}}}}) added to transcript");

    // Phase 2: Compute residuosity symbols
    loquat_debug!("\n--- PHASE 2: Compute residuosity symbols ---");
    loquat_debug!("Following Algorithm 4, Phase 2 specification");

    let h1_seed = transcript.challenge_seed(b"h1");
    loquat_debug!("✓ h₁ = H₁(σ₁, M) computed");

    let num_checks = params.m * params.n;
    let i_indices = expand_index(h1_seed, num_checks, b"I_indices", params.l);
    loquat_debug!(
        "✓ Expanded h₁ to get I_{{i,j}} indices: {} total",
        i_indices.len()
    );

    let mut o_values = Vec::with_capacity(params.n);
    loquat_debug!("\n--- Step 2.1: Computing o_{{i,j}} values ---");
    for j in 0..params.n {
        let mut o_j = Vec::with_capacity(params.m);
        for i in 0..params.m {
            let i_ij = params.public_indices[i_indices[j * params.m + i]];
            let o_val = (keypair.secret_key + i_ij) * r_values[j][i];
            o_j.push(o_val);
        }
        o_values.push(o_j);
    }
    let mut o_flat = Vec::with_capacity(params.m * params.n);
    for row in &o_values {
        o_flat.extend_from_slice(row);
    }
    transcript.append_f_vec(b"o_values", &o_flat);
    loquat_debug!("✓ σ₂ = {{o_{{i,j}}}} added to transcript");

    // Phase 3: Compute witness vector for univariate sumcheck
    loquat_debug!("\n--- PHASE 3: Compute witness vector for univariate sumcheck ---");
    loquat_debug!("Following Algorithm 4, Phase 3 specification");

    let h2_seed = transcript.challenge_seed(b"h2");
    loquat_debug!("✓ h₂ = H₂(σ₂, h₁) computed");

    let lambda_scalars = expand_f(h2_seed, num_checks, b"lambdas");
    let epsilon_vals = expand_f2_real(h2_seed, params.n, b"e_j");
    loquat_debug!("✓ Expanded h₂ to get λ_{{i,j}} and ε_j values");

    loquat_debug!("\n--- Step 3.3: Building witness polynomial data ---");
    let mut f_on_h = vec![F2::zero(); params.coset_h.len()];
    let mut f_on_u = vec![F2::zero(); params.coset_u.len()];

    for j in 0..params.n {
        let epsilon = epsilon_vals[j];

        let mut q_eval_on_h = Vec::with_capacity(2 * params.m);
        for i in 0..params.m {
            let lambda_scalar = lambda_scalars[j * params.m + i];
            let lambda_f2 = F2::new(lambda_scalar, F::zero());
            let index = i_indices[j * params.m + i];
            let public_i = params.public_indices[index];
            let public_f2 = F2::new(public_i, F::zero());
            q_eval_on_h.push(lambda_f2);
            q_eval_on_h.push(lambda_f2 * public_f2);
        }

        let q_hat_coeffs = interpolate_on_coset(&q_eval_on_h, params.h_shift, params.h_generator)?;
        let mut q_hat_coeffs_padded = vec![F2::zero(); params.coset_u.len()];
        q_hat_coeffs_padded[..q_hat_coeffs.len()].copy_from_slice(&q_hat_coeffs);
        let q_hat_on_u =
            evaluate_on_coset(&q_hat_coeffs_padded, params.u_shift, params.u_generator)?;

        let c_prime_on_u = &c_prime_on_u_per_j[j];
        for i in 0..params.coset_u.len() {
            let value = c_prime_on_u[i] * q_hat_on_u[i];
            f_on_u[i] += epsilon * value;
        }

        let c_on_h = &c_on_h_per_j[j];
        for (idx, (c_val, q_val)) in c_on_h.iter().zip(q_eval_on_h.iter()).enumerate() {
            f_on_h[idx] += epsilon * (*c_val * *q_val);
        }
    }

    let mu: F2 = {
        let mut acc = F2::zero();
        for j in 0..params.n {
            let epsilon = epsilon_vals[j];
            for i in 0..params.m {
                let lambda_scalar = lambda_scalars[j * params.m + i];
                let o_scalar = o_values[j][i];
                let term = F2::new(lambda_scalar * o_scalar, F::zero());
                acc += epsilon * term;
            }
        }
        acc
    };

    let computed_mu: F2 = f_on_h.iter().copied().sum();
    if computed_mu != mu {
        loquat_debug!(
            "⚠️ Warning: Σ f_on_h = {:?}, expected μ = {:?}",
            computed_mu,
            mu
        );
    } else {
        loquat_debug!("✓ Polynomial evaluations over H sum to μ");
    }
    loquat_debug!(
        "✓ μ = Σ_{{j=1}}^n ε_j * (Σ_{{i=1}}^m λ_{{i,j}} * o_{{i,j}}) = {:?}",
        mu
    );

    // Execute the univariate sumcheck protocol
    loquat_debug!("\n--- Step 3.4: Executing univariate sumcheck protocol ---");
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let pi_us = generate_sumcheck_proof(&f_on_h, mu, num_variables, &mut transcript)?;
    loquat_debug!("✓ Generated πUS with claimed_sum: {:?}", pi_us.claimed_sum);

    loquat_debug!("\n================== ALGORITHM 5: LOQUAT SIGN PART II ==================");
    let mask_degree_bound = 4 * params.m + (params.kappa * (1 << params.eta));
    let mut s_coeffs = vec![F2::zero(); params.coset_u.len()];
    if params.coset_u.len() > 0 {
        let coeff_bound = cmp::min(mask_degree_bound + 1, params.coset_u.len());
        for coeff in s_coeffs.iter_mut().take(coeff_bound) {
            *coeff = F2::rand(&mut rng);
        }
    }
    let s_on_u = evaluate_on_coset(&s_coeffs, params.u_shift, params.u_generator)?;
    let mut s_on_h = Vec::with_capacity(params.coset_h.len());
    for &point in params.coset_h.iter() {
        let mut value = F2::zero();
        let mut power = F2::one();
        for coeff in s_coeffs.iter() {
            value += *coeff * power;
            power *= point;
        }
        s_on_h.push(value);
    }
    let s_sum: F2 = s_on_h.iter().copied().sum();
    let s_leaves: Vec<Vec<u8>> = encoding::serialize_field2_leaves(&s_on_u);
    let s_merkle = MerkleTree::new_with_config(&s_leaves, merkle_config);
    let root_s_vec = s_merkle.root().ok_or_else(|| LoquatError::MerkleError {
        operation: "s_commitment".to_string(),
        details: "Merkle tree root is empty".to_string(),
    })?;
    let root_s: [u8; 32] =
        root_s_vec
            .try_into()
            .map_err(|v: Vec<u8>| LoquatError::MerkleError {
                operation: "s_commitment".to_string(),
                details: format!("Merkle root has length {} but expected 32", v.len()),
            })?;
    transcript.append_digest32_as_fields(b"root_s", &root_s);
    transcript.append_f2(b"s_sum", s_sum);
    loquat_debug!("✓ σ₃ = (root_s, S) added to transcript");

    let z_scalar = transcript.challenge_f(b"h3");
    let z = F2::new(z_scalar, F::zero());
    loquat_debug!("✓ h₃ = H₃(σ₃, h₂) computed");

    let f_prime_on_u: Vec<F2> = f_on_u
        .iter()
        .zip(s_on_u.iter())
        .map(|(&f_val, &s_val)| z * f_val + s_val)
        .collect();
    let f_prime_on_h: Vec<F2> = f_on_h
        .iter()
        .zip(s_on_h.iter())
        .map(|(&f_val, &s_val)| z * f_val + s_val)
        .collect();

    let g_coeffs = interpolate_on_coset(&f_prime_on_h, params.h_shift, params.h_generator)?;
    let mut g_coeffs_padded = vec![F2::zero(); params.coset_u.len()];
    g_coeffs_padded[..g_coeffs.len()].copy_from_slice(&g_coeffs);
    let g_on_u = evaluate_on_coset(&g_coeffs_padded, params.u_shift, params.u_generator)?;

    let mut h_on_u = Vec::with_capacity(params.coset_u.len());
    for i in 0..params.coset_u.len() {
        let numerator = f_prime_on_u[i] - g_on_u[i];
        let denom = z_h_on_u[i];
        let denom_inv = denom
            .inverse()
            .ok_or_else(|| LoquatError::invalid_parameters("Encountered zero divisor in Z_H(u)"))?;
        h_on_u.push(numerator * denom_inv);
    }

    let h_leaves: Vec<Vec<u8>> = encoding::serialize_field2_leaves(&h_on_u);
    let h_merkle = MerkleTree::new_with_config(&h_leaves, merkle_config);
    let root_h_vec = h_merkle.root().ok_or_else(|| LoquatError::MerkleError {
        operation: "h_commitment".to_string(),
        details: "Merkle tree root is empty".to_string(),
    })?;
    let root_h: [u8; 32] =
        root_h_vec
            .try_into()
            .map_err(|v: Vec<u8>| LoquatError::MerkleError {
                operation: "h_commitment".to_string(),
                details: format!("Merkle root has length {} but expected 32", v.len()),
            })?;
    transcript.append_digest32_as_fields(b"root_h", &root_h);
    loquat_debug!("✓ σ₄ = (root_h) added to transcript");

    let h4_seed = transcript.challenge_seed(b"h4");
    let e_vector = expand_f2_real(h4_seed, 8, b"e_vector");
    loquat_debug!("✓ h₄ = H₄(σ₄, h₃) computed");

    let h_size_scalar = F2::new(F::new(params.coset_h.len() as u128), F::zero());
    let z_mu_plus_s = z * mu + s_sum;
    let mut p_on_u = Vec::with_capacity(params.coset_u.len());
    for (idx, &x) in params.coset_u.iter().enumerate() {
        let numerator = h_size_scalar * f_prime_on_u[idx]
            - h_size_scalar * z_h_on_u[idx] * h_on_u[idx]
            - z_mu_plus_s;
        let denom = h_size_scalar * x;
        let denom_inv = denom.inverse().ok_or_else(|| {
            LoquatError::invalid_parameters("Encountered zero denominator in p(x) computation")
        })?;
        p_on_u.push(numerator * denom_inv);
    }

    let mut c_row = Vec::with_capacity(params.coset_u.len());
    for idx in 0..params.coset_u.len() {
        let mut sum = F2::zero();
        for j in 0..params.n {
            sum += c_prime_on_u_per_j[j][idx];
        }
        c_row.push(sum);
    }

    let base_rows = vec![
        c_row.clone(),
        s_on_u.clone(),
        h_on_u.clone(),
        p_on_u.clone(),
    ];
    let mut pi_rows = base_rows.clone();
    for (row_idx, base_row) in base_rows.iter().enumerate() {
        let exponent = params
            .rho_star_num
            .checked_sub(params.rho_numerators[row_idx])
            .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_i"))?
            as u128;
        let mut scaled_row = Vec::with_capacity(params.coset_u.len());
        for (value, &y) in base_row.iter().zip(params.coset_u.iter()) {
            let y_pow = y.pow(exponent);
            scaled_row.push(*value * y_pow);
        }
        pi_rows.push(scaled_row);
    }

    let mut f0_on_u = vec![F2::zero(); params.coset_u.len()];
    for (row_idx, row) in pi_rows.iter().enumerate() {
        let coeff = e_vector[row_idx];
        for (col, value) in row.iter().enumerate() {
            f0_on_u[col] += coeff * *value;
        }
    }
    loquat_debug!("✓ f^(0) evaluations computed over U");

    loquat_debug!(
        "\n================== ALGORITHM 6: LOQUAT SIGN PART III (LDT) =================="
    );
    let ldt_codeword = f0_on_u.clone();
    loquat_debug!(
        "✓ LDT codeword length: {} (evaluations of f^(0) over U)",
        ldt_codeword.len()
    );
    let (ldt_proof, fri_challenges) = ldt_protocol(
        &ldt_codeword,
        params,
        merkle_config,
        &mut transcript,
    )?;

    let c_cap_nodes = merkle_tree.cap_nodes().to_vec();
    let s_cap_nodes = s_merkle.cap_nodes().to_vec();
    let h_cap_nodes = h_merkle.cap_nodes().to_vec();

    // Collect openings for c′/ŝ/ĥ aligned with LDT query positions.
    let leaf_arity = merkle_config.leaf_arity();
    let mut query_openings = Vec::with_capacity(params.kappa);
    for opening in &ldt_proof.openings {
        let chunk_index = opening.position / leaf_arity;
        let chunk_start = chunk_index * leaf_arity;
        let chunk_end = (chunk_start + leaf_arity).min(params.coset_u.len());

        let mut c_prime_chunk = Vec::with_capacity(chunk_end - chunk_start);
        for col in chunk_start..chunk_end {
            let mut per_j = Vec::with_capacity(params.n);
            for j in 0..params.n {
                per_j.push(c_prime_on_u_per_j[j][col]);
            }
            c_prime_chunk.push(per_j);
        }

        let s_chunk = s_on_u[chunk_start..chunk_end].to_vec();
        let h_chunk = h_on_u[chunk_start..chunk_end].to_vec();

        let c_auth_path = merkle_tree.generate_auth_path(chunk_index);
        let s_auth_path = s_merkle.generate_auth_path(chunk_index);
        let h_auth_path = h_merkle.generate_auth_path(chunk_index);

        query_openings.push(LoquatQueryOpening {
            position: opening.position,
            c_prime_chunk,
            s_chunk,
            h_chunk,
            c_auth_path,
            s_auth_path,
            h_auth_path,
        });
    }

    loquat_debug!("\n--- FINAL SIGNATURE ASSEMBLY ---");

    let artifact = LoquatSignatureArtifact {
        root_c,
        root_s,
        root_h,
        c_cap_nodes,
        s_cap_nodes,
        h_cap_nodes,
        query_openings,
        t_values,
        o_values,
        fri_challenges,
        e_vector,
        s_sum,
        mu,
        z_challenge: z,
        pi_us,
        ldt_proof,
        message_commitment,
    };

    let transcript = LoquatSigningTranscript {
        randomness_matrix: r_values,
        c_evals_on_h: c_on_h_per_j,
    };

    loquat_debug!("✓ σ = {{root_c, root_s, root_h, T_{{i,j}}, o_{{i,j}}, πUS, πLDT}} assembled");

    loquat_debug!("================== ALGORITHMS 4-6 COMPLETE ==================\n");
    Ok(LoquatSignature::new(artifact, Some(transcript)))
}

#[cfg(feature = "std")]
fn ldt_protocol(
    codeword: &[F2],
    params: &LoquatPublicParams,
    merkle_config: MerkleConfig,
    transcript: &mut FieldTranscript,
) -> LoquatResult<(LDTProof, Vec<F2>)> {
    let chunk_size = 1 << params.eta;

    let mut layer_codewords = Vec::with_capacity(params.r + 1);
    layer_codewords.push(codeword.to_vec());
    let mut folding_challenges = Vec::with_capacity(params.r);

    let mut merkle_trees = Vec::with_capacity(params.r + 1);
    let mut merkle_commitments = Vec::with_capacity(params.r + 1);
    let mut cap_nodes = Vec::with_capacity(params.r + 1);

    let initial_leaves: Vec<Vec<u8>> = encoding::serialize_field2_leaves(codeword);
    let initial_merkle_tree = MerkleTree::new_with_config(&initial_leaves, merkle_config);
    let initial_commitment_vec =
        initial_merkle_tree
            .root()
            .ok_or_else(|| LoquatError::MerkleError {
                operation: "initial_commitment".to_string(),
                details: "Merkle tree root is empty".to_string(),
            })?;
    let initial_commitment: [u8; 32] =
        initial_commitment_vec
            .try_into()
            .map_err(|v: Vec<u8>| LoquatError::MerkleError {
                operation: "initial_commitment".to_string(),
                details: format!("Merkle root has length {} but expected 32", v.len()),
            })?;

    merkle_commitments.push(initial_commitment);
    transcript.append_digest32_as_fields(b"merkle_commitment", &initial_commitment);
    cap_nodes.push(initial_merkle_tree.cap_nodes().to_vec());
    merkle_trees.push(initial_merkle_tree);

    let mut current_codeword = codeword.to_vec();

    for _round in 0..params.r {
        let challenge = transcript_challenge_f2(transcript);
        folding_challenges.push(challenge);

        let mut next_codeword =
            Vec::with_capacity((current_codeword.len() + chunk_size - 1) / chunk_size);
        for chunk in current_codeword.chunks(chunk_size) {
            let mut coeff = F2::one();
            let mut acc = F2::zero();
            for &val in chunk {
                acc += val * coeff;
                coeff *= challenge;
            }
            next_codeword.push(acc);
        }
        layer_codewords.push(next_codeword.clone());
        current_codeword = next_codeword;

        let leaves: Vec<Vec<u8>> = encoding::serialize_field2_leaves(&current_codeword);
        let merkle_tree = MerkleTree::new_with_config(&leaves, merkle_config);
        let commitment_vec = merkle_tree.root().ok_or_else(|| LoquatError::MerkleError {
            operation: "commitment".to_string(),
            details: "Merkle tree root is empty".to_string(),
        })?;
        let commitment: [u8; 32] =
            commitment_vec
                .try_into()
                .map_err(|v: Vec<u8>| LoquatError::MerkleError {
                    operation: "commitment".to_string(),
                    details: format!("Merkle root has length {} but expected 32", v.len()),
                })?;

        merkle_commitments.push(commitment);
        transcript.append_digest32_as_fields(b"merkle_commitment", &commitment);
        cap_nodes.push(merkle_tree.cap_nodes().to_vec());
        merkle_trees.push(merkle_tree);
    }

    let mut openings = Vec::with_capacity(params.kappa);
    for _ in 0..params.kappa {
        let challenge = transcript_challenge_f2(transcript);
        let position = challenge.c0.0 as usize % layer_codewords[0].len();
        let mut fold_index = position;

        let mut codeword_chunks = Vec::with_capacity(params.r + 1);
        let mut auth_paths = Vec::with_capacity(params.r + 1);

        for round in 0..=params.r {
            let layer_len = layer_codewords[round].len();
            let chunk_len = chunk_size.min(layer_len);
            let chunk_start = if layer_len > chunk_size {
                (fold_index / chunk_size) * chunk_size
            } else {
                0
            };
            let chunk_end = (chunk_start + chunk_len).min(layer_len);
            codeword_chunks.push(layer_codewords[round][chunk_start..chunk_end].to_vec());

            let leaf_index = if layer_len > chunk_size {
                fold_index / chunk_size
            } else {
                0
            };
            auth_paths.push(merkle_trees[round].generate_auth_path(leaf_index));

            if round < params.r {
                fold_index /= chunk_size;
            }
        }

        openings.push(LDTOpening {
            position,
            codeword_chunks,
            auth_paths,
        });
    }

    let proof = LDTProof {
        commitments: merkle_commitments,
        cap_nodes,
        openings,
    };

    Ok((proof, folding_challenges))
}

pub fn transcript_challenge_f2(transcript: &mut FieldTranscript) -> F2 {
    transcript.challenge_f2(b"challenge")
}
