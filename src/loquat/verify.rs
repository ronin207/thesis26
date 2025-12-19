use super::encoding;
use super::errors::{LoquatError, LoquatResult};
use super::fft::interpolate_on_coset;
use super::field_utils::{self, F, F2, u128_to_field};
use super::hasher::{GriffinHasher, LoquatHasher};
use super::merkle::MerkleConfig;
use super::setup::LoquatPublicParams;
use super::sign::LoquatSignature;
use super::sumcheck::verify_sumcheck_proof;
use super::transcript::{FieldTranscript, expand_f, expand_f2_real, expand_index};
#[cfg(not(feature = "std"))]
use alloc::{string::ToString, vec, vec::Vec};
#[cfg(feature = "std")]
use std::string::ToString;

/// Generate transcript challenge - must match the implementation in sign.rs
fn transcript_challenge_f2(transcript: &mut FieldTranscript) -> F2 {
    transcript.challenge_f2(b"challenge")
}

fn eval_poly(coeffs: &[F2], point: F2) -> F2 {
    let mut acc = F2::zero();
    for coeff in coeffs.iter().rev() {
        acc *= point;
        acc += *coeff;
    }
    acc
}

/// Holds all challenges derived via the Fiat-Shamir transform.
/// These are re-derived by the verifier and used to check the proof.
#[derive(Debug)]
pub struct Challenges {
    /// Challenged indices into the public parameter set `I`. (from h1)
    pub i_indices: Vec<usize>,
    /// Lambda values for the sumcheck. (from h2)
    pub lambdas: Vec<F2>,
    /// `e_j` values for combining parallel sumcheck instances. (from h2)
    pub e_j: Vec<F2>,
}

// NOTE: Expand helpers are now provided by `loquat::transcript` as field-native
// variants (`expand_f`, `expand_f2_real`, `expand_index`) to match the in-circuit
// Fiat–Shamir implementation.

/* LEGACY LDT VERIFICATION (kept verbatim per user request)
fn verify_ldt_proof(
    signature: &LoquatSignature,
    params: &LoquatPublicParams,
    transcript: &mut FieldTranscript,
) -> LoquatResult<bool> {
    loquat_debug!("--- ALGORITHM 7: LDT VERIFICATION (Steps 4-6) ---");
    loquat_debug!("Following rules.mdc: 'Verify LDT and Sumcheck Consistency at Query Points'");

    let ldt_proof = &signature.ldt_proof;

    if ldt_proof.commitments.len() != params.r + 1 {
        loquat_debug!(
            "✗ LDT FAILED: Wrong number of commitments. Expected {}, got {}",
            params.r + 1,
            ldt_proof.commitments.len()
        );
        return Ok(false);
    }

    if ldt_proof.openings.len() != params.kappa {
        loquat_debug!(
            "✗ LDT FAILED: Wrong number of openings. Expected {}, got {}",
            params.kappa,
            ldt_proof.openings.len()
        );
        return Ok(false);
    }

    loquat_debug!(
        "✓ LDT structure verification: {} commitments, {} openings",
        ldt_proof.commitments.len(),
        ldt_proof.openings.len()
    );

    transcript.append_message(b"merkle_commitment", &ldt_proof.commitments[0]);

    let mut folding_challenges = Vec::with_capacity(params.r);
    for i in 0..params.r {
        let challenge = transcript_challenge_f2(transcript);
        folding_challenges.push(challenge);

        if i + 1 < ldt_proof.commitments.len() {
            transcript.append_message(b"merkle_commitment", &ldt_proof.commitments[i + 1]);
        }
    }
    loquat_debug!(
        "✓ Re-derived {} FRI folding challenges",
        folding_challenges.len()
    );

    if signature.fri_codewords.len() != params.r + 1
        || signature.fri_rows.len() != params.r + 1
        || signature.fri_challenges.len() != params.r
    {
        loquat_debug!("✗ Signature missing FRI folding transcript");
        return Ok(false);
    }

    if signature.fri_rows[0].len() != signature.pi_rows.len() {
        loquat_debug!("✗ Π row count mismatch");
        return Ok(false);
    }

    for (idx, layer) in signature.fri_codewords.iter().enumerate() {
        let leaves: Vec<Vec<u8>> = encoding::serialize_field2_leaves(layer);
        let tree = super::merkle::MerkleTree::new(&leaves);
        let root = tree.root().ok_or_else(|| LoquatError::MerkleError {
            operation: "verify_fri_root".to_string(),
            details: "Merkle tree root is empty".to_string(),
        })?;
        if root.as_slice() != ldt_proof.commitments[idx] {
            loquat_debug!("✗ FRI commitment mismatch at layer {}", idx);
            return Ok(false);
        }
    }

    if folding_challenges != signature.fri_challenges {
        loquat_debug!("✗ Folding challenges mismatch between signer and verifier");
        return Ok(false);
    }

    let chunk_size = 1 << params.eta;

    loquat_debug!(
        "\n--- Step 4: Verifying κ={} LDT Query Proofs ---",
        params.kappa
    );
    for (query_idx, opening) in ldt_proof.openings.iter().enumerate() {
        #[cfg(not(feature = "std"))]
        let _ = query_idx;
        let challenge = transcript_challenge_f2(transcript);
        let expected_pos = challenge.c0.0 as usize % signature.fri_codewords[0].len();
        if opening.position != expected_pos {
            loquat_debug!(
                "✗ Query {}: position mismatch with transcript challenge",
                query_idx
            );
            return Ok(false);
        }
        if opening.position >= signature.fri_codewords[0].len() {
            loquat_debug!("✗ Query {}: position out of range", query_idx);
            return Ok(false);
        }
        if opening.codeword_chunks.len() != params.r || opening.row_chunks.len() != params.r {
            loquat_debug!("✗ Query {}: incomplete folding data", query_idx);
            return Ok(false);
        }

        let mut fold_index = opening.position;
        for round in 0..params.r {
            let layer_len = signature.fri_codewords[round].len();
            let chunk_len = chunk_size.min(layer_len);
            let chunk_start = if layer_len > chunk_size {
                (fold_index / chunk_size) * chunk_size
            } else {
                0
            };
            let chunk_end = (chunk_start + chunk_len).min(layer_len);

            let expected_chunk = &signature.fri_codewords[round][chunk_start..chunk_end];
            if opening.codeword_chunks[round] != expected_chunk {
                loquat_debug!(
                    "✗ Query {}: codeword chunk mismatch at round {}",
                    query_idx,
                    round
                );
                return Ok(false);
            }

            let mut coeff = F2::one();
            let mut folded_val = F2::zero();
            for &val in expected_chunk {
                folded_val += val * coeff;
                coeff *= signature.fri_challenges[round];
            }

            let expected_next = signature.fri_codewords[round + 1][fold_index / chunk_size];
            if folded_val != expected_next {
                loquat_debug!(
                    "✗ Query {}: codeword folding inconsistency at round {}",
                    query_idx,
                    round
                );
                return Ok(false);
            }

            if signature.fri_rows[round].len() != opening.row_chunks[round].len() {
                loquat_debug!(
                    "✗ Query {}: row chunk count mismatch at round {}",
                    query_idx,
                    round
                );
                return Ok(false);
            }

            for (row_idx, chunk) in opening.row_chunks[round].iter().enumerate() {
                let expected_row_chunk =
                    &signature.fri_rows[round][row_idx][chunk_start..chunk_end];
                if chunk != expected_row_chunk {
                    loquat_debug!(
                        "✗ Query {}: Π row chunk mismatch at round {}, row {}",
                        query_idx,
                        round,
                        row_idx
                    );
                    return Ok(false);
                }

                let mut coeff = F2::one();
                let mut folded_row = F2::zero();
                for &val in chunk {
                    folded_row += val * coeff;
                    coeff *= signature.fri_challenges[round];
                }

                let expected_row_next =
                    signature.fri_rows[round + 1][row_idx][fold_index / chunk_size];
                if folded_row != expected_row_next {
                    loquat_debug!(
                        "✗ Query {}: Π row folding inconsistency at round {}, row {}",
                        query_idx,
                        round,
                        row_idx
                    );
                    return Ok(false);
                }
            }

            if layer_len > chunk_size {
                fold_index /= chunk_size;
            } else {
                fold_index = 0;
            }
        }

        let final_expected = signature.fri_codewords.last().unwrap()[fold_index];
        if opening.final_eval != final_expected {
            loquat_debug!("✗ Query {}: final folded evaluation mismatch", query_idx);
            return Ok(false);
        }

        let leaf_bytes = field2_to_bytes(&opening.final_eval).to_vec();
        if !super::merkle::MerkleTree::verify_auth_path_with_config(
            ldt_proof.commitments.last().unwrap().as_ref(),
            &leaf_bytes,
            fold_index,
            &opening.auth_path,
            merkle_config,
        ) {
            loquat_debug!("✗ Query {}: final Merkle authentication failed", query_idx);
            return Ok(false);
        }
    }

    loquat_debug!("✓ LDT Query Verification: {} queries passed", params.kappa);
    loquat_debug!("✓ LDT VERIFICATION SUCCESSFUL");
    Ok(true)
}
*/

fn verify_ldt_proof(
    signature: &LoquatSignature,
    params: &LoquatPublicParams,
    transcript: &mut FieldTranscript,
    indices: &[usize],
    lambdas: &[F],
    epsilons: &[F2],
) -> LoquatResult<bool> {
    let merkle_leaf_arity = 1usize << params.eta;
    let leaf_count = (params.coset_u.len() / merkle_leaf_arity.max(1)).max(1);
    let tree_height = if leaf_count.is_power_of_two() {
        leaf_count.trailing_zeros() as usize
    } else {
        0
    };
    let cap_height = (usize::BITS - 1 - params.kappa.max(1).leading_zeros()) as usize;
    let cap_height = cap_height.min(tree_height);
    let merkle_config = MerkleConfig::tree_cap(merkle_leaf_arity).with_cap_height(cap_height);
    let ldt_proof = &signature.ldt_proof;

    // Basic structure checks.
    if ldt_proof.commitments.len() != params.r + 1
        || ldt_proof.cap_nodes.len() != params.r + 1
        || ldt_proof.openings.len() != params.kappa
        || signature.query_openings.len() != params.kappa
    {
        return Ok(false);
    }
    if indices.len() != params.m * params.n || lambdas.len() != params.m * params.n {
        return Ok(false);
    }
    if epsilons.len() != params.n {
        return Ok(false);
    }

    // Re-derive folding challenges from transcript and ensure the signer committed to the same.
    transcript.append_digest32_as_fields(b"merkle_commitment", &ldt_proof.commitments[0]);
    let mut folding_challenges = Vec::with_capacity(params.r);
    for round in 0..params.r {
        folding_challenges.push(transcript_challenge_f2(transcript));
        if round + 1 < ldt_proof.commitments.len() {
            transcript.append_digest32_as_fields(
                b"merkle_commitment",
                &ldt_proof.commitments[round + 1],
            );
        }
    }
    if signature.fri_challenges != folding_challenges {
        return Ok(false);
    }

    // Precompute q̂_j coefficients (by interpolating q_j over H), so we can evaluate q̂_j(x) at
    // query points without materializing full vectors over U.
    let mut q_hat_coeffs_per_j: Vec<Vec<F2>> = Vec::with_capacity(params.n);
    for j in 0..params.n {
        let mut q_eval_on_h = Vec::with_capacity(2 * params.m);
        for i in 0..params.m {
            let lambda_scalar = lambdas[j * params.m + i];
            let lambda_f2 = F2::new(lambda_scalar, F::zero());
            let index = indices[j * params.m + i];
            let public_i = params.public_indices[index];
            let public_f2 = F2::new(public_i, F::zero());
            q_eval_on_h.push(lambda_f2);
            q_eval_on_h.push(lambda_f2 * public_f2);
        }
        q_hat_coeffs_per_j.push(interpolate_on_coset(
            &q_eval_on_h,
            params.h_shift,
            params.h_generator,
        )?);
    }

    // Constants for p(x) computation.
    let h_order = params.coset_h.len() as u128;
    let z_h_constant = params.h_shift.pow(h_order);
    let h_size_scalar = F2::new(F::new(params.coset_h.len() as u128), F::zero());
    let z_mu_plus_s = signature.z_challenge * signature.mu + signature.s_sum;

    let chunk_size = 1usize << params.eta;
    let leaf_arity = merkle_config.leaf_arity();

    for (query_idx, ldt_opening) in ldt_proof.openings.iter().enumerate() {
        // Bind query positions to the Fiat–Shamir transcript.
        let query_challenge = transcript_challenge_f2(transcript);
        let expected_position = query_challenge.c0.0 as usize % params.coset_u.len();
        if ldt_opening.position != expected_position {
            return Ok(false);
        }

        let query_opening = &signature.query_openings[query_idx];
        if query_opening.position != expected_position {
            return Ok(false);
        }

        if ldt_opening.codeword_chunks.len() != params.r + 1
            || ldt_opening.auth_paths.len() != params.r + 1
        {
            return Ok(false);
        }

        // Verify Merkle openings for c′/ŝ/ĥ (tree-cap + layer-t cap).
        let chunk_index = expected_position / leaf_arity.max(1);
        if query_opening.c_prime_chunk.len() != leaf_arity
            || query_opening.s_chunk.len() != leaf_arity
            || query_opening.h_chunk.len() != leaf_arity
        {
            return Ok(false);
        }
        if ldt_opening.codeword_chunks[0].len() != leaf_arity {
            return Ok(false);
        }

        let mut c_leaf = Vec::new();
        for per_point in &query_opening.c_prime_chunk {
            c_leaf.extend_from_slice(&field_utils::serialize_field2_slice(per_point));
        }
        let s_leaf = field_utils::serialize_field2_slice(&query_opening.s_chunk);
        let h_leaf = field_utils::serialize_field2_slice(&query_opening.h_chunk);

        if !super::merkle::MerkleTree::verify_auth_path_with_cap(
            &signature.root_c,
            &signature.c_cap_nodes,
            &c_leaf,
            chunk_index,
            &query_opening.c_auth_path,
            merkle_config,
        ) {
            return Ok(false);
        }
        if !super::merkle::MerkleTree::verify_auth_path_with_cap(
            &signature.root_s,
            &signature.s_cap_nodes,
            &s_leaf,
            chunk_index,
            &query_opening.s_auth_path,
            merkle_config,
        ) {
            return Ok(false);
        }
        if !super::merkle::MerkleTree::verify_auth_path_with_cap(
            &signature.root_h,
            &signature.h_cap_nodes,
            &h_leaf,
            chunk_index,
            &query_opening.h_auth_path,
            merkle_config,
        ) {
            return Ok(false);
        }

        // Recompute missing code elements and check only at the opened query chunk (paper §4.3).
        let chunk_start = chunk_index * leaf_arity;
        for offset in 0..leaf_arity {
            let global_idx = chunk_start + offset;
            let x = params.coset_u[global_idx];

            // f(x) = Σ_j ε_j · c′_j(x) · q̂_j(x)
            let mut f_val = F2::zero();
            for j in 0..params.n {
                if query_opening.c_prime_chunk[offset].len() != params.n {
                    return Ok(false);
                }
                let q_hat = eval_poly(&q_hat_coeffs_per_j[j], x);
                f_val += epsilons[j] * query_opening.c_prime_chunk[offset][j] * q_hat;
            }

            let f_prime = signature.z_challenge * f_val + query_opening.s_chunk[offset];
            let z_h = x.pow(h_order) - z_h_constant;

            // p(x) = (|H|·f'(x) − |H|·Z_H(x)·h(x) − (z·μ + S)) / (|H|·x)
            let numerator =
                h_size_scalar * f_prime - h_size_scalar * z_h * query_opening.h_chunk[offset] - z_mu_plus_s;
            let denom = h_size_scalar * x;
            let denom_inv = denom.inverse().ok_or_else(|| {
                LoquatError::invalid_parameters("Encountered zero denominator in p(x) computation")
            })?;
            let p_val = numerator * denom_inv;

            // c(x) = Σ_j c′_j(x)
            let mut c_sum = F2::zero();
            for val in &query_opening.c_prime_chunk[offset] {
                c_sum += *val;
            }

            // Interleaved code f^(0)(x).
            let exponents: [u128; 4] = [
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[0])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_1"))? as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[1])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_2"))? as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[2])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_3"))? as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[3])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_4"))? as u128,
            ];

            let base = [c_sum, query_opening.s_chunk[offset], query_opening.h_chunk[offset], p_val];
            let mut f0 = F2::zero();
            for row_idx in 0..4 {
                f0 += signature.e_vector[row_idx] * base[row_idx];
                f0 += signature.e_vector[row_idx + 4] * (base[row_idx] * x.pow(exponents[row_idx]));
            }

            if f0 != ldt_opening.codeword_chunks[0][offset] {
                return Ok(false);
            }
        }

        // Verify LDT opening (Merkle authentication per layer + folding consistency).
        let mut fold_index = expected_position;
        let mut layer_len = params.coset_u.len();
        for round in 0..=params.r {
            let expected_chunk_len = chunk_size.min(layer_len);
            if ldt_opening.codeword_chunks[round].len() != expected_chunk_len {
                return Ok(false);
            }

            let leaf_bytes = field_utils::serialize_field2_slice(&ldt_opening.codeword_chunks[round]);
            let leaf_index = fold_index / chunk_size;
            if !super::merkle::MerkleTree::verify_auth_path_with_cap(
                &ldt_proof.commitments[round],
                &ldt_proof.cap_nodes[round],
                &leaf_bytes,
                leaf_index,
                &ldt_opening.auth_paths[round],
                merkle_config,
            ) {
                return Ok(false);
            }

            if round < params.r {
                let challenge = folding_challenges[round];
                let mut coeff = F2::one();
                let mut folded = F2::zero();
                for &entry in &ldt_opening.codeword_chunks[round] {
                    folded += entry * coeff;
                    coeff *= challenge;
                }

                let next_index = fold_index / chunk_size;
                let next_layer_len = ((layer_len + chunk_size - 1) / chunk_size).max(1);
                let next_chunk_start = if next_layer_len > chunk_size {
                    (next_index / chunk_size) * chunk_size
                } else {
                    0
                };
                let next_offset = next_index - next_chunk_start;
                if folded != ldt_opening.codeword_chunks[round + 1][next_offset] {
                    return Ok(false);
                }

                fold_index = next_index;
                layer_len = next_layer_len;
            }
        }
    }

    Ok(true)
}

struct Algorithm7Verifier<'a> {
    message: &'a [u8],
    signature: &'a LoquatSignature,
    public_key: &'a [F],
    params: &'a LoquatPublicParams,
    transcript: FieldTranscript,
}

impl<'a> Algorithm7Verifier<'a> {
    fn new(
        message: &'a [u8],
        signature: &'a LoquatSignature,
        public_key: &'a [F],
        params: &'a LoquatPublicParams,
    ) -> Self {
        let transcript = FieldTranscript::new(b"loquat_signature");
        Self {
            message,
            signature,
            public_key,
            params,
            transcript,
        }
    }

    fn verify_message_commitment(&mut self) -> LoquatResult<()> {
        // Use Griffin hash for message commitment (SNARK-friendly)
        let commitment = GriffinHasher::hash(self.message);
        if commitment.len() != 32 {
            return Err(LoquatError::verification_failure(
                "message commitment must be 32 bytes",
            ));
        }
        let mut commitment_arr = [0u8; 32];
        commitment_arr.copy_from_slice(&commitment);
        self.transcript
            .append_digest32_as_fields(b"message_commitment", &commitment_arr);
        if commitment != self.signature.message_commitment {
            loquat_debug!("✗ Message commitment mismatch");
            return Err(LoquatError::verification_failure(
                "message commitment mismatch",
            ));
        }
        loquat_debug!("✓ Message binding verified");
        Ok(())
    }

    fn absorb_sigma1(&mut self) -> LoquatResult<Vec<usize>> {
        self.transcript
            .append_digest32_as_fields(b"root_c", &self.signature.root_c);
        let mut t_flat = Vec::with_capacity(self.params.m * self.params.n);
        for row in &self.signature.t_values {
            t_flat.extend_from_slice(row);
        }
        self.transcript.append_f_vec(b"t_values", &t_flat);

        let h1_seed = self.transcript.challenge_seed(b"h1");
        let num_checks = self.params.m * self.params.n;
        let indices = expand_index(h1_seed, num_checks, b"I_indices", self.params.l);
        Ok(indices)
    }

    fn absorb_sigma2(&mut self) -> LoquatResult<(Vec<F>, Vec<F2>)> {
        let mut o_flat = Vec::with_capacity(self.params.m * self.params.n);
        for row in &self.signature.o_values {
            o_flat.extend_from_slice(row);
        }
        self.transcript.append_f_vec(b"o_values", &o_flat);

        let h2_seed = self.transcript.challenge_seed(b"h2");
        let num_checks = self.params.m * self.params.n;
        let lambdas: Vec<F> = expand_f(h2_seed, num_checks, b"lambdas");
        let epsilons: Vec<F2> = expand_f2_real(h2_seed, self.params.n, b"e_j");
        Ok((lambdas, epsilons))
    }

    fn verify_legendre_constraints(
        &self,
        indices: &[usize],
        lambdas: &[F],
        epsilons: &[F2],
    ) -> LoquatResult<()> {
        for j in 0..self.params.n {
            for i in 0..self.params.m {
                let o_ij = self.signature.o_values[j][i];
                let t_ij = self.signature.t_values[j][i];
                let pk_entry = self.public_key[indices[j * self.params.m + i]];
                if o_ij.is_zero() {
                    loquat_debug!("✗ o[{}][{}] is zero", j, i);
                    return Err(LoquatError::verification_failure("o_ij must be non-zero"));
                }
                let actual = field_utils::legendre_prf_secure(o_ij);
                let expected = pk_entry + t_ij - u128_to_field(2) * pk_entry * t_ij;
                if actual != expected {
                    loquat_debug!("✗ Legendre PRF check failed at ({},{})", j, i);
                    return Err(LoquatError::verification_failure(
                        "Legendre PRF consistency failed",
                    ));
                }
            }
        }

        let mut mu = F2::zero();
        for j in 0..self.params.n {
            let epsilon = epsilons[j];
            for i in 0..self.params.m {
                mu += epsilon
                    * F2::new(
                        lambdas[j * self.params.m + i] * self.signature.o_values[j][i],
                        F::zero(),
                    );
            }
        }
        if mu != self.signature.mu {
            loquat_debug!("✗ μ mismatch");
            return Err(LoquatError::verification_failure("μ mismatch"));
        }
        Ok(())
    }

    fn verify_sumcheck(&mut self) -> LoquatResult<()> {
        loquat_debug!("--- Algorithm 7 · Sumcheck Verification ---");
        let num_variables = (self.params.coset_h.len()).trailing_zeros() as usize;
        if !verify_sumcheck_proof(&self.signature.pi_us, num_variables, &mut self.transcript)? {
            loquat_debug!("✗ Sumcheck verification failed");
            return Err(LoquatError::verification_failure(
                "sumcheck verification failed",
            ));
        }
        Ok(())
    }

    fn absorb_sigma3_sigma4(&mut self) -> LoquatResult<()> {
        self.transcript
            .append_digest32_as_fields(b"root_s", &self.signature.root_s);
        self.transcript.append_f2(b"s_sum", self.signature.s_sum);

        let z_scalar = self.transcript.challenge_f(b"h3");
        let z = F2::new(z_scalar, F::zero());
        if z != self.signature.z_challenge {
            loquat_debug!("✗ z challenge mismatch");
            return Err(LoquatError::verification_failure("z challenge mismatch"));
        }

        self.transcript
            .append_digest32_as_fields(b"root_h", &self.signature.root_h);
        let h4_seed = self.transcript.challenge_seed(b"h4");
        let expected_e = expand_f2_real(h4_seed, 8, b"e_vector");
        if expected_e != self.signature.e_vector {
            loquat_debug!("✗ e-vector mismatch");
            return Err(LoquatError::verification_failure("e-vector mismatch"));
        }
        Ok(())
    }

    fn verify_ldt(&mut self) -> LoquatResult<()> {
        unreachable!("verify_ldt must be called with transcript-derived indices/lambdas/epsilons");
    }

    fn verify_ldt_openings(
        &mut self,
        indices: &[usize],
        lambdas: &[F],
        epsilons: &[F2],
    ) -> LoquatResult<()> {
        if self.signature.e_vector.len() != 8 {
            return Err(LoquatError::verification_failure("e-vector length mismatch"));
        }
        if !verify_ldt_proof(
            self.signature,
            self.params,
            &mut self.transcript,
            indices,
            lambdas,
            epsilons,
        )? {
            loquat_debug!("✗ Low-degree test failed");
            return Err(LoquatError::verification_failure("low-degree test failed"));
        }
        Ok(())
    }

    fn run(mut self) -> LoquatResult<()> {
        self.verify_message_commitment()?;
        let indices = self.absorb_sigma1()?;
        let (lambdas, epsilons) = self.absorb_sigma2()?;
        self.verify_legendre_constraints(&indices, &lambdas, &epsilons)?;
        self.verify_sumcheck()?;
        self.absorb_sigma3_sigma4()?;
        self.verify_ldt_openings(&indices, &lambdas, &epsilons)?;
        loquat_debug!("✓ Loquat verification completed");
        Ok(())
    }
}

/* LEGACY LOQUAT VERIFY (retained verbatim for reference)
pub fn loquat_verify(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &Vec<F>,
    params: &LoquatPublicParams,
) -> LoquatResult<bool> {
    loquat_debug!("\n================== ALGORITHM 7: LOQUAT VERIFY ==================");
    loquat_debug!("INPUT: Signature σ, public key pk, message M");

    let mut transcript = Transcript::new(b"loquat_signature");
    transcript.append_message(b"message", message);

    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_commitment = hasher.finalize().to_vec();
    transcript.append_message(b"message_commitment", &message_commitment);

    if message_commitment != signature.message_commitment {
        loquat_debug!("✗ Message commitment mismatch");
        return Ok(false);
    }
    loquat_debug!("✓ Message commitment verified");

    transcript.append_message(b"root_c", &signature.root_c);
    let t_bytes = encoding::serialize_field_matrix(&signature.t_values);
    transcript.append_message(b"t_values", &t_bytes);
    loquat_debug!("✓ σ₁ = (root_c, {{T_{{i,j}}}}) added to transcript");

    let mut h1_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h1", &mut h1_bytes);
    loquat_debug!("✓ h₁ = H₁(σ₁, M) recomputed");

    let num_checks = params.m * params.n;
    let i_indices = expand_challenge(&h1_bytes, num_checks, b"I_indices", &mut |b| {
        (u64::from_le_bytes(b[0..8].try_into().unwrap()) as usize) % params.l
    });
    loquat_debug!("✓ Expanded h₁ to regenerate I_{{i,j}} indices");

    let o_bytes = encoding::serialize_field_matrix(&signature.o_values);
    transcript.append_message(b"o_values", &o_bytes);
    loquat_debug!("✓ σ₂ = {{o_{{i,j}}}} added to transcript");

    let mut h2_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h2", &mut h2_bytes);
    loquat_debug!("✓ h₂ = H₂(σ₂, h₁) recomputed");

    let lambda_scalars: Vec<F> = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| {
        field_utils::bytes_to_field_element(b)
    });
    let epsilon_vals: Vec<F2> = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| {
        F2::new(field_utils::bytes_to_field_element(b), F::zero())
    });
    loquat_debug!("✓ Expanded h₂ to regenerate λ_{{i,j}} and ε_j values");

    if signature.pi_rows.len() != 8 {
        loquat_debug!("✗ Signature missing stacked matrix rows");
        return Ok(false);
    }

    if signature.c_prime_evals.len() != params.n
        || signature.s_evals.len() != params.coset_u.len()
        || signature.h_evals.len() != params.coset_u.len()
        || signature.f_prime_evals.len() != params.coset_u.len()
        || signature.p_evals.len() != params.coset_u.len()
        || signature.f0_evals.len() != params.coset_u.len()
        || signature
            .pi_rows
            .iter()
            .any(|row| row.len() != params.coset_u.len())
    {
        loquat_debug!("✗ Signature has inconsistent evaluation vector lengths");
        return Ok(false);
    }

    loquat_debug!("\n================== ALGORITHM 7: STEP 3 - CHECKING PROOFS ==================");

    loquat_debug!("\n--- Step 3.1: Legendre PRF Constraint Verification ---");

    for j in 0..params.n {
        for i in 0..params.m {
            let o_ij = signature.o_values[j][i];
            let t_ij = signature.t_values[j][i];
            let i_ij_index = i_indices[j * params.m + i];
            let pk_val = public_key[i_ij_index];

            if o_ij.is_zero() {
                loquat_debug!("✗ FAILED: o[{}][{}] is zero", j, i);
                return Ok(false);
            }

            let actual_lps = field_utils::legendre_prf_secure(o_ij);
            let two = u128_to_field(2);
            let expected_lps = pk_val + t_ij - two * pk_val * t_ij;

            if actual_lps != expected_lps {
                loquat_debug!("✗ FAILED: Legendre PRF check failed at [{}][{}]", j, i);
                return Ok(false);
            }
        }
    }
    loquat_debug!("✓ All Legendre PRF checks passed");

    let mut mu_check = F2::zero();
    for j in 0..params.n {
        let epsilon = epsilon_vals[j];
        for i in 0..params.m {
            let lambda_scalar = lambda_scalars[j * params.m + i];
            let o_scalar = signature.o_values[j][i];
            mu_check += epsilon * F2::new(lambda_scalar * o_scalar, F::zero());
        }
    }
    if mu_check != signature.mu {
        loquat_debug!("✗ μ mismatch between prover and verifier");
        return Ok(false);
    }
    loquat_debug!("✓ μ value verified");

    if signature.e_vector.len() != 8 {
        loquat_debug!("✗ e-vector length mismatch");
        return Ok(false);
    }

    let mut c_row_expected = Vec::with_capacity(params.coset_u.len());
    for idx in 0..params.coset_u.len() {
        let mut sum = F2::zero();
        for j in 0..params.n {
            sum += signature.c_prime_evals[j][idx];
        }
        c_row_expected.push(sum);
    }
    if c_row_expected != signature.pi_rows[0] {
        loquat_debug!("✗ Stacked matrix ĉ′ row mismatch");
        return Ok(false);
    }
    if signature.s_evals != signature.pi_rows[1]
        || signature.h_evals != signature.pi_rows[2]
        || signature.p_evals != signature.pi_rows[3]
    {
        loquat_debug!("✗ Π₀ rows do not match stored evaluations");
        return Ok(false);
    }

    for row_idx in 0..4 {
        let exponent = params
            .rho_star_num
            .checked_sub(params.rho_numerators[row_idx])
            .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_i"))?
            as u128;
        let mut scaled_expected = Vec::with_capacity(params.coset_u.len());
        for (value, &y) in signature.pi_rows[row_idx].iter().zip(params.coset_u.iter()) {
            let y_pow = y.pow(exponent);
            scaled_expected.push(*value * y_pow);
        }
        if scaled_expected != signature.pi_rows[row_idx + 4] {
            loquat_debug!("✗ Π₁ row {} mismatch", row_idx + 1);
            return Ok(false);
        }
    }
    loquat_debug!("✓ Π rows verified");

    let mut f0_expected = vec![F2::zero(); params.coset_u.len()];
    for (row_idx, row) in signature.pi_rows.iter().enumerate() {
        let coeff = signature.e_vector[row_idx];
        for (col, value) in row.iter().enumerate() {
            f0_expected[col] += coeff * *value;
        }
    }
    if f0_expected != signature.f0_evals {
        loquat_debug!("✗ f^(0) evaluations mismatch");
        return Ok(false);
    }
    loquat_debug!("✓ f^(0) evaluations verified");

    loquat_debug!("\n--- Step 3.2: Univariate Sumcheck Verification ---");
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let sumcheck_result = verify_sumcheck_proof(&signature.pi_us, num_variables, &mut transcript)?;
    if !sumcheck_result {
        loquat_debug!("✗ SUMCHECK FAILED");
        return Ok(false);
    }
    loquat_debug!("✓ SUMCHECK PASSED");

    transcript.append_message(b"root_s", &signature.root_s);
    let s_sum_bytes = field2_to_bytes(&signature.s_sum);
    transcript.append_message(b"s_sum", &s_sum_bytes);
    loquat_debug!("✓ σ₃ = (root_s, S) added to transcript");

    let mut h3_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h3", &mut h3_bytes);
    let expected_z_scalar = field_utils::bytes_to_field_element(&h3_bytes);
    let expected_z = F2::new(expected_z_scalar, F::zero());
    if expected_z != signature.z_challenge {
        loquat_debug!("✗ Z challenge mismatch");
        return Ok(false);
    }
    loquat_debug!("✓ h₃ challenge verified");

    transcript.append_message(b"root_h", &signature.root_h);
    loquat_debug!("✓ σ₄ = (root_h) added to transcript");

    let mut h4_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h4", &mut h4_bytes);
    let expected_e_vector = expand_challenge(&h4_bytes, 8, b"e_vector", &mut |b| {
        F2::new(field_utils::bytes_to_field_element(b), F::zero())
    });
    if expected_e_vector != signature.e_vector {
        loquat_debug!("✗ e-vector mismatch in Algorithm 5");
        return Ok(false);
    }
    loquat_debug!("✓ h₄ challenge verified");

    loquat_debug!("\n--- Step 3.3: Low-Degree Test Verification ---");
    let ldt_result = verify_ldt_proof(signature, params, &mut transcript)?;
    if !ldt_result {
        loquat_debug!("✗ LDT FAILED");
        return Ok(false);
    }
    loquat_debug!("✓ LDT PASSED");

    loquat_debug!("\n--- ALGORITHM 7: FINAL DECISION ---");
    loquat_debug!("✓ VERIFICATION SUCCESSFUL: Signature is valid");
    Ok(true)
}
*/

pub fn loquat_verify(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &Vec<F>,
    params: &LoquatPublicParams,
) -> LoquatResult<bool> {
    let verifier = Algorithm7Verifier::new(message, signature, public_key, params);
    match verifier.run() {
        Ok(()) => Ok(true),
        Err(LoquatError::VerificationFailure { .. }) => Ok(false),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loquat::{keygen::keygen_with_params, setup::loquat_setup, sign::loquat_sign};

    #[test]
    fn test_valid_signature_verification() {
        let params = loquat_setup(128).unwrap();
        let keypair = keygen_with_params(&params).unwrap();
        let message = b"A message to sign and verify";
        let signature = loquat_sign(message, &keypair, &params).unwrap();

        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature_tampered_message() {
        let params = loquat_setup(128).unwrap();
        let keypair = keygen_with_params(&params).unwrap();
        let message = b"Original message";
        let tampered_message = b"Tampered message";
        let signature = loquat_sign(message, &keypair, &params).unwrap();

        let is_valid =
            loquat_verify(tampered_message, &signature, &keypair.public_key, &params).unwrap();
        assert!(!is_valid);
    }
}
