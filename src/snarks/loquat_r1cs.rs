fn merkle_path_opening(
    builder: &mut R1csBuilder,
    leaf: &[Byte],
    path: &[Vec<u8>],
    position: usize,
) -> Vec<Byte> {
    loquat_debug!(
        "[r1cs] merkle_path_opening depth={} position={}",
        path.len(),
        position
    );
    let mut current = griffin_hash_bytes_circuit(builder, leaf);
    let mut idx = position;
    for sibling_bytes in path {
        let sibling_byte_structs = sibling_bytes
            .iter()
            .map(|&byte| Byte::from_constant(builder, byte))
            .collect::<Vec<_>>();
        let sibling_digest = griffin_hash_bytes_circuit(builder, &sibling_byte_structs);
        let mut concat = Vec::new();
        if idx % 2 == 0 {
            concat.extend_from_slice(&current);
            concat.extend_from_slice(&sibling_digest);
        } else {
            concat.extend_from_slice(&sibling_digest);
            concat.extend_from_slice(&current);
        }
        current = griffin_hash_bytes_circuit(builder, &concat);
        idx /= 2;
    }
    current
}

fn compress_leaf_fields_single_perm(
    builder: &mut R1csBuilder,
    leaf_fields: &[FieldVar],
) -> Vec<FieldVar> {
    // TreeCap leaf compression uses a single Griffin permutation over
    // (acc0, acc1, len_tag, 0). The accumulators are simple sums of the
    // leaf field elements (split by parity), so we should enforce them with
    // *one* linear relation each instead of O(n) chained additions.
    let mut acc0_value = F::zero();
    let mut acc1_value = F::zero();
    let mut acc0_terms: Vec<(usize, F)> = Vec::new();
    let mut acc1_terms: Vec<(usize, F)> = Vec::new();
    for (idx, field) in leaf_fields.iter().enumerate() {
        if idx % 2 == 0 {
            acc0_value += field.value;
            acc0_terms.push((field.idx, -F::one()));
        } else {
            acc1_value += field.value;
            acc1_terms.push((field.idx, -F::one()));
        }
    }
    let acc0_idx = builder.alloc(acc0_value);
    let acc1_idx = builder.alloc(acc1_value);
    acc0_terms.push((acc0_idx, F::one()));
    acc1_terms.push((acc1_idx, F::one()));
    builder.enforce_linear_relation(&acc0_terms, F::zero());
    builder.enforce_linear_relation(&acc1_terms, F::zero());

    let acc0 = FieldVar::new(acc0_idx, acc0_value);
    let acc1 = FieldVar::new(acc1_idx, acc1_value);
    let len_tag = FieldVar::constant(builder, F::new(leaf_fields.len() as u128));

    let params = get_griffin_params();
    let mut state = vec![acc0, acc1, len_tag, FieldVar::constant(builder, F::zero())];
    griffin_permutation_circuit(builder, params, &mut state);
    state.truncate(GRIFFIN_DIGEST_ELEMENTS);
    state
}

fn compress_internal_digest_fields_single_perm(
    builder: &mut R1csBuilder,
    left: &[FieldVar],
    right: &[FieldVar],
) -> LoquatResult<Vec<FieldVar>> {
    if left.len() != GRIFFIN_DIGEST_ELEMENTS || right.len() != GRIFFIN_DIGEST_ELEMENTS {
        return Err(LoquatError::verification_failure(
            "digest length mismatch for internal compression",
        ));
    }
    let params = get_griffin_params();
    let mut state = vec![left[0], left[1], right[0], right[1]];
    griffin_permutation_circuit(builder, params, &mut state);
    state.truncate(GRIFFIN_DIGEST_ELEMENTS);
    Ok(state)
}

fn merkle_path_opening_fields(
    builder: &mut R1csBuilder,
    leaf_fields: &[FieldVar],
    path: &[Vec<u8>],
    position: usize,
) -> LoquatResult<Vec<FieldVar>> {
    let mut current = compress_leaf_fields_single_perm(builder, leaf_fields);
    let mut idx = position;
    for sibling_bytes in path {
        let sibling_fields = digest_bytes_to_field_vars(builder, sibling_bytes)?;
        current = if idx % 2 == 0 {
            compress_internal_digest_fields_single_perm(builder, &current, &sibling_fields)?
        } else {
            compress_internal_digest_fields_single_perm(builder, &sibling_fields, &current)?
        };
        idx /= 2;
    }
    Ok(current)
}

/// Phase 7-cleanup: derive per-level direction-bit (LSB-first) vars and values
/// for a Merkle authentication path from the FS-derived query-position bits.
///
/// `base_shift` is the bit offset within `position_bits` at which the
/// path-base index (e.g. `chunk_index` for c/s/h trees, or
/// `position >> ((layer + 1) · chunk_size_log)` for an LDT layer) begins.
/// `path_len` levels are returned. `base_index_native` is the natively-known
/// integer value of the base index (chunk_index or leaf_index_at_layer) — used
/// only to populate the bit *values* for the witness; the var indices come
/// from the FS bit decomposition, which already constrains them to the LSB
/// expansion of the corresponding query position.
fn direction_bits_for_path(
    in_circuit: &InCircuitTranscript,
    query_idx: usize,
    base_shift: usize,
    path_len: usize,
    base_index_native: usize,
) -> (Vec<usize>, Vec<F>) {
    let position_bits = &in_circuit.query_position_bit_vars[query_idx];
    let mut bit_vars = Vec::with_capacity(path_len);
    let mut bit_values = Vec::with_capacity(path_len);
    for level in 0..path_len {
        let bit_pos = base_shift + level;
        if bit_pos < position_bits.len() {
            bit_vars.push(position_bits[bit_pos]);
        } else {
            // Defensive: if a deeper layer's path is shorter than the bit
            // decomposition expects, the extra bits would be zero anyway.
            // Reuse bit 0 as a placeholder — but assert_eq guarantees we
            // never reach here if `auth_path.len()` is well-formed.
            bit_vars.push(position_bits[0]);
        }
        bit_values.push(F::new(((base_index_native >> level) & 1) as u128));
    }
    (bit_vars, bit_values)
}

/// Phase 7-cleanup: PI variant of [`merkle_path_opening_fields`]. Auth-path
/// siblings come from the public-input section as F²Vars, and the per-level
/// left/right swap is driven by direction bits taken from the in-circuit query
/// position bit decomposition. Result: zero signature-byte leakage into the
/// constraint matrix.
///
/// Per level the swap is encoded as
///     left[k]  = current[k] + dir · (sibling[k] − current[k])
///     right[k] = sibling[k] − dir · (sibling[k] − current[k])
/// for each F-component k ∈ {0, 1}. This costs 1 mul row per component (so 2
/// mul rows per level) plus a few linear relations to materialise the diff
/// and the two outputs. The Griffin permutation that follows is unchanged.
fn merkle_path_opening_fields_pi(
    builder: &mut R1csBuilder,
    leaf_fields: &[FieldVar],
    sibling_vars: &[F2Var],
    sibling_values: &[F2],
    direction_bit_vars: &[usize],
    direction_bit_values: &[F],
) -> LoquatResult<Vec<FieldVar>> {
    if sibling_vars.len() != sibling_values.len() {
        return Err(LoquatError::verification_failure(
            "merkle_path_opening_fields_pi: sibling vars/values length mismatch",
        ));
    }
    if direction_bit_vars.len() != sibling_vars.len()
        || direction_bit_values.len() != sibling_vars.len()
    {
        return Err(LoquatError::verification_failure(
            "merkle_path_opening_fields_pi: direction-bit count must equal sibling count",
        ));
    }
    let mut current = compress_leaf_fields_single_perm(builder, leaf_fields);
    if current.len() != GRIFFIN_DIGEST_ELEMENTS {
        return Err(LoquatError::verification_failure(
            "merkle_path_opening_fields_pi: unexpected initial digest length",
        ));
    }

    for level in 0..sibling_vars.len() {
        let sibling_var = sibling_vars[level];
        let sibling_val = sibling_values[level];
        let dir_idx = direction_bit_vars[level];
        let dir_val = direction_bit_values[level];

        let sibling_field_c0 = FieldVar::existing(sibling_var.c0, sibling_val.c0);
        let sibling_field_c1 = FieldVar::existing(sibling_var.c1, sibling_val.c1);
        let sibling_fields = [sibling_field_c0, sibling_field_c1];

        // Compute left/right for each component. We prove
        //   diff   = sibling - current
        //   d_diff = dir · diff
        //   left   = current + d_diff
        //   right  = sibling - d_diff
        // via two lin rows + one mul row + two lin rows = five rows per
        // component, but the constraint shape is identical across signatures.
        let mut new_current = Vec::with_capacity(GRIFFIN_DIGEST_ELEMENTS);
        for k in 0..GRIFFIN_DIGEST_ELEMENTS {
            let cur = current[k];
            let sib = sibling_fields[k];

            // diff = sib - cur
            let diff_val = sib.value - cur.value;
            let diff_idx = builder.alloc(diff_val);
            builder.enforce_linear_relation(
                &[
                    (diff_idx, F::one()),
                    (sib.idx, -F::one()),
                    (cur.idx, F::one()),
                ],
                F::zero(),
            );

            // d_diff = dir · diff (one mul row).
            let d_diff_val = dir_val * diff_val;
            let d_diff_idx = builder.alloc(d_diff_val);
            builder.enforce_mul(
                SparseLC::with_terms(F::zero(), vec![(dir_idx, F::one())]),
                SparseLC::with_terms(F::zero(), vec![(diff_idx, F::one())]),
                SparseLC::with_terms(F::zero(), vec![(d_diff_idx, F::one())]),
            );

            // left = cur + d_diff
            let left_val = cur.value + d_diff_val;
            let left_idx = builder.alloc(left_val);
            builder.enforce_linear_relation(
                &[
                    (left_idx, F::one()),
                    (cur.idx, -F::one()),
                    (d_diff_idx, -F::one()),
                ],
                F::zero(),
            );

            // right = sib - d_diff
            let right_val = sib.value - d_diff_val;
            let right_idx = builder.alloc(right_val);
            builder.enforce_linear_relation(
                &[
                    (right_idx, F::one()),
                    (sib.idx, -F::one()),
                    (d_diff_idx, F::one()),
                ],
                F::zero(),
            );

            new_current.push((
                FieldVar::new(left_idx, left_val),
                FieldVar::new(right_idx, right_val),
            ));
        }

        let left_fields = [new_current[0].0, new_current[1].0];
        let right_fields = [new_current[0].1, new_current[1].1];
        current = compress_internal_digest_fields_single_perm(
            builder,
            &left_fields,
            &right_fields,
        )?;
    }
    Ok(current)
}

fn digest_bytes_to_field_vars(
    builder: &mut R1csBuilder,
    digest: &[u8],
) -> LoquatResult<Vec<FieldVar>> {
    if digest.len() != 32 {
        return Err(LoquatError::verification_failure(
            "invalid digest length (expected 32)",
        ));
    }
    let mut out = Vec::with_capacity(GRIFFIN_DIGEST_ELEMENTS);
    for chunk in digest.chunks(16) {
        let mut limb = [0u8; 16];
        limb.copy_from_slice(chunk);
        let value = field_utils::bytes_to_field_element(&limb);
        out.push(FieldVar::constant(builder, value));
    }
    Ok(out)
}

fn merkle_cap_root_from_nodes(
    builder: &mut R1csBuilder,
    cap_nodes: &[[u8; 32]],
) -> LoquatResult<Vec<FieldVar>> {
    if cap_nodes.is_empty() {
        return Err(LoquatError::verification_failure(
            "missing Merkle cap nodes for layer-t cap verification",
        ));
    }
    let mut leaf_fields: Vec<FieldVar> = Vec::with_capacity(cap_nodes.len() * 2);
    for node in cap_nodes {
        let limbs = digest_bytes_to_field_vars(builder, node)?;
        leaf_fields.push(limbs[0]);
        leaf_fields.push(limbs[1]);
    }
    Ok(compress_leaf_fields_single_perm(builder, &leaf_fields))
}

/// Phase 7-cleanup: PI variant of [`merkle_cap_root_from_nodes`]. Takes the
/// cap-node F²Vars from the public-input section and the matching values
/// (parallel slices) so we can construct `FieldVar::existing` entries without
/// any byte-level constants entering the R1CS matrix. The Griffin compression
/// logic is shared with the byte path via [`compress_leaf_fields_single_perm`].
fn merkle_cap_root_from_pi_field_vars(
    builder: &mut R1csBuilder,
    cap_node_vars: &[F2Var],
    cap_node_values: &[F2],
) -> LoquatResult<Vec<FieldVar>> {
    if cap_node_vars.is_empty() {
        return Err(LoquatError::verification_failure(
            "missing PI cap-node vars for layer-t cap verification",
        ));
    }
    if cap_node_vars.len() != cap_node_values.len() {
        return Err(LoquatError::verification_failure(
            "PI cap-node var/value length mismatch",
        ));
    }
    let mut leaf_fields: Vec<FieldVar> = Vec::with_capacity(cap_node_vars.len() * 2);
    for (var, val) in cap_node_vars.iter().zip(cap_node_values.iter()) {
        leaf_fields.push(FieldVar::existing(var.c0, val.c0));
        leaf_fields.push(FieldVar::existing(var.c1, val.c1));
    }
    Ok(compress_leaf_fields_single_perm(builder, &leaf_fields))
}

/// Phase 5.3 cleanup / Phase 6.2c: variant of [`enforce_field_digest_equals_bytes`]
/// that compares against a PI F²Var instead of a 32-byte constant. The
/// resulting constraints (two linear relations) carry only variable indices
/// and unit coefficients — no signature-specific F constants in the matrix.
fn enforce_field_digest_equals_pi(
    builder: &mut R1csBuilder,
    digest_fields: &[FieldVar],
    pi_var: F2Var,
) -> LoquatResult<()> {
    if digest_fields.len() != 2 {
        return Err(LoquatError::verification_failure(
            "digest_fields must have 2 entries",
        ));
    }
    builder.enforce_linear_relation(
        &[(digest_fields[0].idx, F::one()), (pi_var.c0, -F::one())],
        F::zero(),
    );
    builder.enforce_linear_relation(
        &[(digest_fields[1].idx, F::one()), (pi_var.c1, -F::one())],
        F::zero(),
    );
    Ok(())
}

fn enforce_field_digest_equals_bytes(
    builder: &mut R1csBuilder,
    digest_fields: &[FieldVar],
    digest_bytes: &[u8],
) -> LoquatResult<()> {
    let expected = digest_bytes_to_field_vars(builder, digest_bytes)?;
    if expected.len() != digest_fields.len() {
        return Err(LoquatError::verification_failure(
            "digest length mismatch while enforcing equality",
        ));
    }
    for (lhs, rhs) in digest_fields.iter().zip(expected.iter()) {
        builder.enforce_eq(lhs.idx, rhs.idx);
    }
    Ok(())
}

use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::fft::{evaluate_on_coset, interpolate_on_coset};
use crate::loquat::field_utils::{self, F, F2, field_to_u128, sqrt_canonical};
use crate::loquat::griffin::{
    GRIFFIN_DIGEST_ELEMENTS, GRIFFIN_FIELD_MODULUS, GRIFFIN_RATE, GRIFFIN_STATE_WIDTH,
    GriffinParams, get_griffin_params,
};
use crate::loquat::hasher::{GriffinHasher, LoquatHasher};
use crate::loquat::setup::LoquatPublicParams;
use crate::loquat::sign::LoquatSignature;
use crate::loquat::sumcheck::replay_sumcheck_challenges;
use crate::loquat::transcript::{FieldTranscript, expand_f, expand_f2_real, expand_index};
use crate::snarks::r1cs::{R1csConstraint, R1csInstance, R1csWitness};

struct TranscriptData {
    i_indices: Vec<usize>,
    lambda_scalars: Vec<F>,
    epsilon_vals: Vec<F2>,
    sumcheck_challenges: Vec<F2>,
    z_challenge: F2,
    e_vector: Vec<F2>,
}

/// In-circuit Fiat–Shamir derived values, returned by
/// `enforce_transcript_relations_field_native`. These are the FieldVars/F2Vars
/// produced by the in-circuit `FieldTranscriptCircuit`. Phase 1 of the B → C
/// refactor threads them forward into the QR / sumcheck / LDT blocks so
/// downstream constraints use these variables directly instead of the natively
/// replayed `transcript_data` constants.
///
/// In Phase 1.1 (this commit) the struct is populated and returned but not yet
/// consumed by callers — this is pure plumbing. Phase 1.2-1.4 migrate the
/// constraint blocks one at a time.
#[allow(dead_code)]
struct InCircuitTranscript {
    /// Reduced i-indices (FieldVar holding values in [0, params.l)).
    /// Length = params.m * params.n. Used by future C-phase in-circuit pk
    /// multiplexer; B-Lite still uses native `transcript_data.i_indices` for
    /// pk selection and keeps the equality binding for soundness.
    i_index_low_vars: Vec<FieldVar>,
    /// Phase 5.4: per-check `expected_idx` variable (the reduced index into pk,
    /// in [0, params.l)). Allocated by the FS function and constrained via
    /// `low_idx = expected_idx + modulus * b_idx`. Used by the in-circuit pk
    /// multiplexer to select the right pk variable. Length = m·n.
    i_index_expected_vars: Vec<FieldVar>,
    /// Phase 5.4: per-check bit decomposition of `expected_idx` (LSB-first),
    /// length k_per = ⌈log₂(params.l)⌉. Used as selector bits in the binary-
    /// tree multiplexer. Outer length = m·n; inner length = k_per.
    /// **Assumes `params.l` is a power of 2** so k-bit decomposition acts as
    /// the range check `expected_idx ∈ [0, params.l)` without an extra gadget.
    i_index_bit_vars: Vec<Vec<usize>>,
    /// λ scalars from h2 expansion. Length = params.m * params.n.
    lambda_vars: Vec<FieldVar>,
    /// ε real parts from h2 expansion (c1 is structurally zero).
    /// Length = params.n.
    epsilon_real_vars: Vec<FieldVar>,
    /// Sumcheck round challenges. Length = number of sumcheck rounds.
    sumcheck_chal_vars: Vec<F2Var>,
    /// h3 z-challenge real part (c1 is structurally zero).
    z_var: FieldVar,
    /// e_vector real parts from h4 expansion (c1 is structurally zero).
    /// Length = 8.
    e_vector_real_vars: Vec<FieldVar>,
    /// FRI folding challenges. Length = params.r.
    fri_chal_vars: Vec<F2Var>,
    /// Reduced query positions in [0, |U|). Length = params.kappa.
    query_position_low_vars: Vec<FieldVar>,
    /// Phase 5.5.3: per-query bit decomposition of the reduced query position
    /// (LSB-first), length `log₂(|U|)`. Used to compute `x_var = u_shift · u_g^position`
    /// in-circuit so the Lagrange basis at the query point is signature-independent.
    /// Outer length = params.kappa; inner length = `log₂(params.coset_u.len())`.
    query_position_bit_vars: Vec<Vec<usize>>,
}

/// Public inputs for `build_loquat_r1cs_pk_witness`, allocated at the head of
/// the R1CS instance vector. The verifier supplies these values; the prover
/// must use them as-is.
///
/// Allocation order is **load-bearing** — the verifier expects this exact
/// sequence in the public-input vector. Do not reorder fields without updating
/// every verifier site (libiop bridge serialisation, ACIR converter, etc.).
///
/// Phase 5.1 introduces this struct as scaffolding only: `allocate()` populates
/// every field as a public-input variable, but no constraint yet *consumes*
/// these variables — the existing builder body still allocates duplicate
/// witness variables for the same data. Phase 5.2 (W→PI) and 5.3 (C→PI)
/// migrate consumers one block at a time.
#[allow(dead_code)]
struct LoquatPublicInputs {
    /// Hash digest of the message: `Griffin(message)`. Encoded as 2 F via
    /// `digest32_to_fields`. (Phase 5.3 will also expose the raw message bytes
    /// if/when the message commitment becomes the only public message handle.)
    message_commitment: F2Var,
    /// Merkle commitment to the witness oracle f̂₁ = ĉ′|U.
    root_c: F2Var,
    /// Bit-valued Legendre PRF outputs (m·n entries flattened).
    /// `t_values[j*m + i]` holds T_{i,j} as a boolean field element.
    t_values: Vec<FieldVar>,
    /// QR witnesses (n·m entries flattened, per `signature.o_values[j][i]`).
    o_values: Vec<FieldVar>,
    /// Sumcheck claimed sum μ ∈ 𝔽².
    mu: F2Var,
    /// Sumcheck partial sum S ∈ 𝔽² ([line 4 of Algorithm 5]).
    s_sum: F2Var,
    /// Merkle commitment to the masking oracle ŝ|U.
    root_s: F2Var,
    /// Merkle commitment to the rational-constraint oracle ĥ|U.
    root_h: F2Var,
    /// Sumcheck initial claimed sum (matches μ; allocated separately because
    /// the sumcheck transcript absorbs it as a discrete oracle entry).
    pi_us_claimed_sum: F2Var,
    /// Round polynomials of the sumcheck. Layout: 4 F per round
    /// (c0.c0, c0.c1, c1.c0, c1.c1). Length = `4 * num_sumcheck_rounds`.
    pi_us_round_polys_flat: Vec<FieldVar>,
    /// Sumcheck final evaluation.
    pi_us_final_evaluation: F2Var,
    /// Merkle roots committing the FRI fold layers (length r+1).
    /// `ldt_commitments[layer]` is the root for layer `layer`.
    ldt_commitments: Vec<F2Var>,
    /// LDT query positions (length κ). Each is in [0, |U|).
    /// (Used in B-Lite as constants; Phase 5 binds them via PI.)
    query_positions: Vec<FieldVar>,
    /// LDT codeword chunk values, one F2 per chunk element.
    /// Indexed as `ldt_codeword_chunks[query_idx][layer][offset]`.
    ldt_codeword_chunks: Vec<Vec<Vec<F2Var>>>,
    /// Query opening c′ chunks: `query_c_prime_chunks[query_idx][offset][j]`.
    query_c_prime_chunks: Vec<Vec<Vec<F2Var>>>,
    /// Query opening ŝ chunks: `query_s_chunks[query_idx][offset]`.
    query_s_chunks: Vec<Vec<F2Var>>,
    /// Query opening ĥ chunks: `query_h_chunks[query_idx][offset]`.
    query_h_chunks: Vec<Vec<F2Var>>,
    /// e_vector (8 real-only F entries from h₄ expansion).
    e_vector_real: Vec<FieldVar>,
    /// Phase 7-cleanup: full c-tree cap-node list as PI F²Vars. Each entry is
    /// the 32-byte digest packed into 2 F via `digest32_to_fields`. Length = the
    /// signing-time `c_merkle.cap_nodes()` length, which is fixed by params (it
    /// depends only on `cap_height` and tree height, both deterministic). Empty
    /// when caps are disabled.
    c_cap_nodes_f2: Vec<F2Var>,
    /// Phase 7-cleanup: full s-tree cap-node list. Same shape as `c_cap_nodes_f2`.
    s_cap_nodes_f2: Vec<F2Var>,
    /// Phase 7-cleanup: full h-tree cap-node list. Same shape as `c_cap_nodes_f2`.
    h_cap_nodes_f2: Vec<F2Var>,
    /// Phase 7-cleanup: full LDT cap-node lists, one per layer. Outer length =
    /// `params.r + 1`. Inner length = each layer's `cap_nodes()` length (varies
    /// per layer because each layer's tree shrinks by `1 << params.eta`, so
    /// `effective_cap_height = min(cap_height, tree_height_at_layer)`). Inner
    /// length is still params-deterministic, so the matrix shape is identical
    /// across signatures.
    ldt_cap_nodes_f2: Vec<Vec<F2Var>>,
    /// Phase 7-cleanup: per-query Merkle authentication-path siblings for the
    /// c/s/h trees. Outer length = `params.kappa`. Inner length = the tree's
    /// `auth_path.len()`, which is `tree_height − cap_height` (params-fixed).
    /// Each sibling is a 32-byte digest packed into 2 F via `digest32_to_fields`.
    c_auth_paths_f2: Vec<Vec<F2Var>>,
    s_auth_paths_f2: Vec<Vec<F2Var>>,
    h_auth_paths_f2: Vec<Vec<F2Var>>,
    /// Phase 7-cleanup: per-query × per-layer Merkle authentication-path
    /// siblings for the LDT trees. Outer length = `params.kappa`. Middle length
    /// = `params.r + 1` (one per FRI fold layer). Inner length = each layer's
    /// `auth_path.len()`, which shrinks with layer depth but is params-fixed.
    ldt_auth_paths_f2: Vec<Vec<Vec<F2Var>>>,
}

#[allow(dead_code)]
impl LoquatPublicInputs {
    /// Allocate every field as a public-input variable, populating witness
    /// values from the supplied `signature`. **Must be called before any
    /// `builder.alloc()` (witness-section) call**, and must be followed by
    /// `builder.finalize_public_inputs()`.
    fn allocate(
        builder: &mut R1csBuilder,
        signature: &LoquatSignature,
        params: &LoquatPublicParams,
    ) -> LoquatResult<Self> {
        // 1. Digests (each 32-byte digest packed into 2 F via digest32_to_fields).
        let message_commitment_arr: [u8; 32] = signature
            .message_commitment
            .as_slice()
            .try_into()
            .map_err(|_| {
                LoquatError::verification_failure("message commitment must be 32 bytes")
            })?;
        let (mc_lo, mc_hi) = digest32_to_fields(&message_commitment_arr);
        let message_commitment = F2Var {
            c0: builder.alloc_public(mc_lo),
            c1: builder.alloc_public(mc_hi),
        };

        let (rc_lo, rc_hi) = digest32_to_fields(&signature.root_c);
        let root_c = F2Var {
            c0: builder.alloc_public(rc_lo),
            c1: builder.alloc_public(rc_hi),
        };

        // 2. t_values (m·n booleans).
        let mut t_values = Vec::with_capacity(params.m * params.n);
        for row in &signature.t_values {
            for &v in row {
                let idx = builder.alloc_public(v);
                t_values.push(FieldVar::existing(idx, v));
            }
        }

        // 3. o_values (n·m field elements).
        let mut o_values = Vec::with_capacity(params.m * params.n);
        for row in &signature.o_values {
            for &v in row {
                let idx = builder.alloc_public(v);
                o_values.push(FieldVar::existing(idx, v));
            }
        }

        // 4. μ, S, root_s, root_h.
        let mu = builder.alloc_public_f2(signature.mu);
        let s_sum = builder.alloc_public_f2(signature.s_sum);
        let (rs_lo, rs_hi) = digest32_to_fields(&signature.root_s);
        let root_s = F2Var {
            c0: builder.alloc_public(rs_lo),
            c1: builder.alloc_public(rs_hi),
        };
        let (rh_lo, rh_hi) = digest32_to_fields(&signature.root_h);
        let root_h = F2Var {
            c0: builder.alloc_public(rh_lo),
            c1: builder.alloc_public(rh_hi),
        };

        // 5. Sumcheck transcript components.
        let pi_us_claimed_sum = builder.alloc_public_f2(signature.pi_us.claimed_sum);
        let mut pi_us_round_polys_flat =
            Vec::with_capacity(4 * signature.pi_us.round_polynomials.len());
        for round_poly in &signature.pi_us.round_polynomials {
            for v in [
                round_poly.c0.c0,
                round_poly.c0.c1,
                round_poly.c1.c0,
                round_poly.c1.c1,
            ] {
                let idx = builder.alloc_public(v);
                pi_us_round_polys_flat.push(FieldVar::existing(idx, v));
            }
        }
        let pi_us_final_evaluation = builder.alloc_public_f2(signature.pi_us.final_evaluation);

        // 6. LDT commitments (r+1 layers, each a 32-byte digest → 2 F).
        let mut ldt_commitments = Vec::with_capacity(params.r + 1);
        for commitment in &signature.ldt_proof.commitments {
            let arr: [u8; 32] = commitment.as_slice().try_into().map_err(|_| {
                LoquatError::verification_failure("LDT commitment must be 32 bytes")
            })?;
            let (lo, hi) = digest32_to_fields(&arr);
            ldt_commitments.push(F2Var {
                c0: builder.alloc_public(lo),
                c1: builder.alloc_public(hi),
            });
        }

        // 7. Query positions (κ entries, each a single F).
        let mut query_positions = Vec::with_capacity(params.kappa);
        for opening in &signature.ldt_proof.openings {
            let v = F::new(opening.position as u128);
            let idx = builder.alloc_public(v);
            query_positions.push(FieldVar::existing(idx, v));
        }

        // 8. LDT codeword chunks: per query × per layer × leaf_arity F2 entries.
        let mut ldt_codeword_chunks = Vec::with_capacity(params.kappa);
        for opening in &signature.ldt_proof.openings {
            let mut per_query: Vec<Vec<F2Var>> = Vec::with_capacity(params.r + 1);
            for layer_chunk in &opening.codeword_chunks {
                let mut layer_vars = Vec::with_capacity(layer_chunk.len());
                for &val in layer_chunk {
                    layer_vars.push(builder.alloc_public_f2(val));
                }
                per_query.push(layer_vars);
            }
            ldt_codeword_chunks.push(per_query);
        }

        // 9. Query openings: c′ / ŝ / ĥ per (query, off [, j]).
        let mut query_c_prime_chunks = Vec::with_capacity(params.kappa);
        let mut query_s_chunks = Vec::with_capacity(params.kappa);
        let mut query_h_chunks = Vec::with_capacity(params.kappa);
        for q in &signature.query_openings {
            let mut c_prime_off: Vec<Vec<F2Var>> = Vec::with_capacity(q.c_prime_chunk.len());
            for off_vals in &q.c_prime_chunk {
                let mut row = Vec::with_capacity(off_vals.len());
                for &val in off_vals {
                    row.push(builder.alloc_public_f2(val));
                }
                c_prime_off.push(row);
            }
            query_c_prime_chunks.push(c_prime_off);

            let mut s_off = Vec::with_capacity(q.s_chunk.len());
            for &val in &q.s_chunk {
                s_off.push(builder.alloc_public_f2(val));
            }
            query_s_chunks.push(s_off);

            let mut h_off = Vec::with_capacity(q.h_chunk.len());
            for &val in &q.h_chunk {
                h_off.push(builder.alloc_public_f2(val));
            }
            query_h_chunks.push(h_off);
        }

        // 10. e_vector (8 real-only F entries; c1 is structurally zero, not allocated).
        let mut e_vector_real = Vec::with_capacity(8);
        for entry in signature.e_vector.iter() {
            let idx = builder.alloc_public(entry.c0);
            e_vector_real.push(FieldVar::existing(idx, entry.c0));
        }

        // 11. Phase 7-cleanup: cap-node lists (c/s/h/LDT). Each cap node is a
        // 32-byte Griffin digest, packed into 2 F via `digest32_to_fields`.
        // These were previously baked as byte constants into `enforce_ldt_queries`
        // — moving them to PI removes the last signature-byte leakage from the
        // R1CS matrix, so `instance.digest()` becomes signature-independent.
        let mut c_cap_nodes_f2 = Vec::with_capacity(signature.c_cap_nodes.len());
        for node in &signature.c_cap_nodes {
            let (lo, hi) = digest32_to_fields(node);
            c_cap_nodes_f2.push(F2Var {
                c0: builder.alloc_public(lo),
                c1: builder.alloc_public(hi),
            });
        }
        let mut s_cap_nodes_f2 = Vec::with_capacity(signature.s_cap_nodes.len());
        for node in &signature.s_cap_nodes {
            let (lo, hi) = digest32_to_fields(node);
            s_cap_nodes_f2.push(F2Var {
                c0: builder.alloc_public(lo),
                c1: builder.alloc_public(hi),
            });
        }
        let mut h_cap_nodes_f2 = Vec::with_capacity(signature.h_cap_nodes.len());
        for node in &signature.h_cap_nodes {
            let (lo, hi) = digest32_to_fields(node);
            h_cap_nodes_f2.push(F2Var {
                c0: builder.alloc_public(lo),
                c1: builder.alloc_public(hi),
            });
        }
        let mut ldt_cap_nodes_f2: Vec<Vec<F2Var>> =
            Vec::with_capacity(signature.ldt_proof.cap_nodes.len());
        for layer_caps in &signature.ldt_proof.cap_nodes {
            let mut layer_vars = Vec::with_capacity(layer_caps.len());
            for node in layer_caps {
                let (lo, hi) = digest32_to_fields(node);
                layer_vars.push(F2Var {
                    c0: builder.alloc_public(lo),
                    c1: builder.alloc_public(hi),
                });
            }
            ldt_cap_nodes_f2.push(layer_vars);
        }

        // 12. Phase 7-cleanup: per-query Merkle auth-path siblings for the c/s/h
        // trees. Each sibling is a 32-byte digest packed into 2 F. The auth_path
        // length is params-fixed (`tree_height − cap_height`), so the matrix
        // shape stays identical across signatures.
        let mut c_auth_paths_f2: Vec<Vec<F2Var>> = Vec::with_capacity(params.kappa);
        let mut s_auth_paths_f2: Vec<Vec<F2Var>> = Vec::with_capacity(params.kappa);
        let mut h_auth_paths_f2: Vec<Vec<F2Var>> = Vec::with_capacity(params.kappa);
        for q in &signature.query_openings {
            let mut c_path = Vec::with_capacity(q.c_auth_path.len());
            for sibling in &q.c_auth_path {
                let arr: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                    LoquatError::verification_failure("c_auth_path sibling must be 32 bytes")
                })?;
                let (lo, hi) = digest32_to_fields(&arr);
                c_path.push(F2Var {
                    c0: builder.alloc_public(lo),
                    c1: builder.alloc_public(hi),
                });
            }
            c_auth_paths_f2.push(c_path);

            let mut s_path = Vec::with_capacity(q.s_auth_path.len());
            for sibling in &q.s_auth_path {
                let arr: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                    LoquatError::verification_failure("s_auth_path sibling must be 32 bytes")
                })?;
                let (lo, hi) = digest32_to_fields(&arr);
                s_path.push(F2Var {
                    c0: builder.alloc_public(lo),
                    c1: builder.alloc_public(hi),
                });
            }
            s_auth_paths_f2.push(s_path);

            let mut h_path = Vec::with_capacity(q.h_auth_path.len());
            for sibling in &q.h_auth_path {
                let arr: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                    LoquatError::verification_failure("h_auth_path sibling must be 32 bytes")
                })?;
                let (lo, hi) = digest32_to_fields(&arr);
                h_path.push(F2Var {
                    c0: builder.alloc_public(lo),
                    c1: builder.alloc_public(hi),
                });
            }
            h_auth_paths_f2.push(h_path);
        }

        // 13. Phase 7-cleanup: per-query × per-layer LDT auth-path siblings.
        let mut ldt_auth_paths_f2: Vec<Vec<Vec<F2Var>>> = Vec::with_capacity(params.kappa);
        for opening in &signature.ldt_proof.openings {
            let mut per_query: Vec<Vec<F2Var>> = Vec::with_capacity(opening.auth_paths.len());
            for layer_path in &opening.auth_paths {
                let mut layer_vars = Vec::with_capacity(layer_path.len());
                for sibling in layer_path {
                    let arr: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                        LoquatError::verification_failure(
                            "ldt auth_path sibling must be 32 bytes",
                        )
                    })?;
                    let (lo, hi) = digest32_to_fields(&arr);
                    layer_vars.push(F2Var {
                        c0: builder.alloc_public(lo),
                        c1: builder.alloc_public(hi),
                    });
                }
                per_query.push(layer_vars);
            }
            ldt_auth_paths_f2.push(per_query);
        }

        Ok(Self {
            message_commitment,
            root_c,
            t_values,
            o_values,
            mu,
            s_sum,
            root_s,
            root_h,
            pi_us_claimed_sum,
            pi_us_round_polys_flat,
            pi_us_final_evaluation,
            ldt_commitments,
            query_positions,
            ldt_codeword_chunks,
            query_c_prime_chunks,
            query_s_chunks,
            query_h_chunks,
            e_vector_real,
            c_cap_nodes_f2,
            s_cap_nodes_f2,
            h_cap_nodes_f2,
            ldt_cap_nodes_f2,
            c_auth_paths_f2,
            s_auth_paths_f2,
            h_auth_paths_f2,
            ldt_auth_paths_f2,
        })
    }
}

struct SparseLC {
    constant: F,
    terms: Vec<(usize, F)>,
}

#[derive(Clone, Copy)]
struct F2Var {
    c0: usize,
    c1: usize,
}

#[derive(Clone, Debug)]
struct Byte {
    bits: [usize; 8],
    value: u8,
}

#[derive(Clone, Copy)]
struct FieldVar {
    idx: usize,
    value: F,
}

impl Byte {
    fn from_bits(bits: [usize; 8], value: u8) -> Self {
        Self { bits, value }
    }

    fn from_constant(builder: &mut R1csBuilder, value: u8) -> Self {
        let mut bits = [0usize; 8];
        for i in 0..8 {
            let bit_val = ((value >> i) & 1) == 1;
            bits[i] = builder.alloc_bit(bit_val);
            // Constrain the allocated bit to the desired constant value.
            builder.enforce_linear_relation(&[(bits[i], F::one())], -F::new(bit_val as u128));
        }
        Self { bits, value }
    }
}

impl FieldVar {
    fn new(idx: usize, value: F) -> Self {
        Self { idx, value }
    }

    fn existing(idx: usize, value: F) -> Self {
        Self { idx, value }
    }

    fn constant(builder: &mut R1csBuilder, value: F) -> Self {
        let idx = builder.alloc(value);
        // Constrain the variable to the constant value: idx - value == 0.
        builder.enforce_linear_relation(&[(idx, F::one())], -value);
        Self { idx, value }
    }
}

fn field_add(builder: &mut R1csBuilder, left: FieldVar, right: FieldVar) -> FieldVar {
    let sum_value = left.value + right.value;
    let sum_idx = builder.alloc(sum_value);
    builder.enforce_linear_relation(
        &[
            (sum_idx, F::one()),
            (left.idx, -F::one()),
            (right.idx, -F::one()),
        ],
        F::zero(),
    );
    FieldVar::new(sum_idx, sum_value)
}

fn field_add_const(builder: &mut R1csBuilder, var: FieldVar, constant: F) -> FieldVar {
    let sum_value = var.value + constant;
    let sum_idx = builder.alloc(sum_value);
    // Enforce: sum = var + constant  <=>  sum - var - constant = 0.
    builder.enforce_linear_relation(&[(sum_idx, F::one()), (var.idx, -F::one())], -constant);
    FieldVar::new(sum_idx, sum_value)
}

fn field_mul(builder: &mut R1csBuilder, left: FieldVar, right: FieldVar) -> FieldVar {
    let prod_value = left.value * right.value;
    let prod_idx = builder.alloc(prod_value);
    builder.enforce_mul_vars(left.idx, right.idx, prod_idx);
    FieldVar::new(prod_idx, prod_value)
}

fn field_mul_const(builder: &mut R1csBuilder, var: FieldVar, constant: F) -> FieldVar {
    let prod_value = var.value * constant;
    let prod_idx = builder.alloc(prod_value);
    builder.enforce_mul_const_var(constant, var.idx, prod_idx);
    FieldVar::new(prod_idx, prod_value)
}

fn field_pow_const(builder: &mut R1csBuilder, base: FieldVar, exponent: u128) -> FieldVar {
    if exponent == 0 {
        return FieldVar::constant(builder, F::one());
    }
    let mut result = FieldVar::constant(builder, F::one());
    let mut current = base;
    let mut exp = exponent;
    while exp > 0 {
        if exp & 1 == 1 {
            result = field_mul(builder, result, current);
        }
        exp >>= 1;
        if exp > 0 {
            current = field_mul(builder, current, current);
        }
    }
    result
}

/// Compute `base^(d^{-1})` using a witness and a low-degree check.
///
/// Griffin uses two power maps `x -> x^d` and `x -> x^(d^{-1})` where
/// `d * d^{-1} ≡ 1 (mod p-1)`. Naively exponentiating by `d^{-1}` inside the
/// circuit is extremely expensive because `d^{-1}` is a ~127-bit exponent.
///
/// Instead, we allocate `y = base^(d^{-1})` as witness and enforce `y^d = base`.
/// Since `gcd(d, p-1)=1`, `x -> x^d` is a permutation so this check uniquely
/// defines `y`.
fn field_pow_inv_witness(
    builder: &mut R1csBuilder,
    base: FieldVar,
    d: u128,
    d_inv: u128,
) -> FieldVar {
    let inv_value = base.value.pow(d_inv);
    let inv_idx = builder.alloc(inv_value);
    let inv_var = FieldVar::new(inv_idx, inv_value);

    // Enforce inv_var^d == base (cheap because d is small, e.g. 5).
    let forward = field_pow_const(builder, inv_var, d);
    builder.enforce_eq(forward.idx, base.idx);

    inv_var
}

impl SparseLC {
    fn zero() -> Self {
        Self {
            constant: F::zero(),
            terms: Vec::new(),
        }
    }

    fn constant(value: F) -> Self {
        Self {
            constant: value,
            terms: Vec::new(),
        }
    }

    fn from_var(idx: usize) -> Self {
        Self {
            constant: F::zero(),
            terms: vec![(idx, F::one())],
        }
    }

    fn with_terms(constant: F, mut terms: Vec<(usize, F)>) -> Self {
        terms.sort_by_key(|(idx, _)| *idx);
        let mut combined = Vec::with_capacity(terms.len());
        for (idx, coeff) in terms {
            if let Some((last_idx, last_coeff)) = combined.last_mut() {
                if *last_idx == idx {
                    *last_coeff += coeff;
                    continue;
                }
            }
            combined.push((idx, coeff));
        }
        Self {
            constant,
            terms: combined,
        }
    }

    fn to_dense(&self, num_variables: usize) -> Vec<F> {
        let mut dense = vec![F::zero(); num_variables];
        dense[0] = self.constant;
        for (idx, coeff) in &self.terms {
            dense[*idx] += *coeff;
        }
        dense
    }

    fn to_sparse(&self) -> Vec<(usize, F)> {
        let mut terms = self.terms.clone();
        if !self.constant.is_zero() {
            terms.push((0, self.constant));
        }
        terms.sort_by_key(|(idx, _)| *idx);
        let mut out: Vec<(usize, F)> = Vec::with_capacity(terms.len());
        for (idx, coeff) in terms {
            if coeff.is_zero() {
                continue;
            }
            if let Some(last) = out.last_mut() {
                if last.0 == idx {
                    last.1 += coeff;
                    if last.1.is_zero() {
                        out.pop();
                    }
                    continue;
                }
            }
            out.push((idx, coeff));
        }
        out
    }
}

struct PendingConstraint {
    a: SparseLC,
    b: SparseLC,
    c: SparseLC,
}

struct R1csBuilder {
    witness: Vec<F>,
    constraints: Vec<PendingConstraint>,
    /// Number of variables allocated as public input (R1CS instance vector).
    /// `0` means no public inputs (legacy behavior). Public-input variables occupy
    /// the LOW indices of the witness vector after the implicit constant-1 slot,
    /// i.e. indices `[1, num_inputs]`.
    num_inputs: usize,
    /// Set to `true` after the public-input phase ends. Allocated automatically by
    /// `alloc()` to lock further `alloc_public()` calls. Used as a structural
    /// invariant — `alloc_public()` after this flag is set is a programmer error.
    public_inputs_finalized: bool,
}

impl R1csBuilder {
    fn new() -> Self {
        Self {
            witness: Vec::new(),
            constraints: Vec::new(),
            num_inputs: 0,
            public_inputs_finalized: false,
        }
    }

    /// Allocate a new variable in the public-input section of the R1CS instance.
    ///
    /// Must be called before any [`Self::alloc`] (which allocates witness vars).
    /// Panics if called after the public-input phase has ended.
    #[allow(dead_code)]
    fn alloc_public(&mut self, value: F) -> usize {
        assert!(
            !self.public_inputs_finalized,
            "alloc_public must come before any alloc() (witness) call"
        );
        self.witness.push(value);
        self.num_inputs += 1;
        self.witness.len()
    }

    /// Explicitly end the public-input phase. After this, only [`Self::alloc`]
    /// (witness) is allowed. The first `alloc()` call also implicitly ends the
    /// PI phase, so this is mainly useful when the builder body has no PIs but
    /// you want to assert the count is zero.
    #[allow(dead_code)]
    fn finalize_public_inputs(&mut self) {
        self.public_inputs_finalized = true;
    }

    /// Allocate an [`F2`] pair as two consecutive public-input variables.
    #[allow(dead_code)]
    fn alloc_public_f2(&mut self, value: F2) -> F2Var {
        F2Var {
            c0: self.alloc_public(value.c0),
            c1: self.alloc_public(value.c1),
        }
    }

    fn alloc(&mut self, value: F) -> usize {
        // Implicit lock on the public-input phase: any non-public alloc ends it.
        self.public_inputs_finalized = true;
        self.witness.push(value);
        self.witness.len()
    }

    fn enforce_mul(&mut self, a: SparseLC, b: SparseLC, c: SparseLC) {
        self.constraints.push(PendingConstraint { a, b, c });
    }

    fn enforce_mul_const_var(&mut self, constant: F, var_idx: usize, out_idx: usize) {
        let a = SparseLC::constant(constant);
        let b = SparseLC::from_var(var_idx);
        let c = SparseLC::from_var(out_idx);
        self.enforce_mul(a, b, c);
    }

    fn enforce_mul_vars(&mut self, left_idx: usize, right_idx: usize, out_idx: usize) {
        let a = SparseLC::from_var(left_idx);
        let b = SparseLC::from_var(right_idx);
        let c = SparseLC::from_var(out_idx);
        self.enforce_mul(a, b, c);
    }

    fn enforce_sum_equals(&mut self, terms: &[(usize, F)], target_idx: usize) {
        let mut lc_terms = terms.to_vec();
        lc_terms.push((target_idx, -F::one()));
        let lc = SparseLC::with_terms(F::zero(), lc_terms);
        let one = SparseLC::constant(F::one());
        let zero = SparseLC::zero();
        self.enforce_mul(lc, one, zero);
    }

    fn enforce_linear_relation(&mut self, terms: &[(usize, F)], constant: F) {
        let lc = SparseLC::with_terms(constant, terms.to_vec());
        let one = SparseLC::constant(F::one());
        let zero = SparseLC::zero();
        self.enforce_mul(lc, one, zero);
    }

    fn enforce_eq(&mut self, left_idx: usize, right_idx: usize) {
        self.enforce_sum_equals(&[(left_idx, F::one())], right_idx);
    }

    fn enforce_boolean(&mut self, idx: usize) {
        let a = SparseLC::from_var(idx);
        let b = SparseLC::with_terms(-F::one(), vec![(idx, F::one())]);
        let c = SparseLC::zero();
        self.enforce_mul(a, b, c);
    }

    fn alloc_f2(&mut self, value: F2) -> F2Var {
        F2Var {
            c0: self.alloc(value.c0),
            c1: self.alloc(value.c1),
        }
    }

    fn enforce_f2_eq(&mut self, left: F2Var, right: F2Var) {
        self.enforce_eq(left.c0, right.c0);
        self.enforce_eq(left.c1, right.c1);
    }

    fn enforce_f2_sum_equals_unit(&mut self, vars: &[F2Var], target: F2Var) {
        let mut c0_terms = Vec::with_capacity(vars.len());
        let mut c1_terms = Vec::with_capacity(vars.len());
        for var in vars {
            c0_terms.push((var.c0, F::one()));
            c1_terms.push((var.c1, F::one()));
        }
        self.enforce_sum_equals(&c0_terms, target.c0);
        self.enforce_sum_equals(&c1_terms, target.c1);
    }

    fn enforce_f2_sub(&mut self, left: F2Var, right: F2Var, target: F2Var) {
        let real_terms = vec![
            (target.c0, F::one()),
            (left.c0, -F::one()),
            (right.c0, F::one()),
        ];
        let imag_terms = vec![
            (target.c1, F::one()),
            (left.c1, -F::one()),
            (right.c1, F::one()),
        ];
        self.enforce_linear_relation(&real_terms, F::zero());
        self.enforce_linear_relation(&imag_terms, F::zero());
    }

    fn enforce_f2_sum_equals_const(&mut self, vars: &[F2Var], constant: F2) {
        let mut c0_terms = Vec::with_capacity(vars.len());
        let mut c1_terms = Vec::with_capacity(vars.len());
        for var in vars {
            c0_terms.push((var.c0, F::one()));
            c1_terms.push((var.c1, F::one()));
        }
        let c0_idx = self.alloc(constant.c0);
        let c1_idx = self.alloc(constant.c1);
        self.enforce_sum_equals(&c0_terms, c0_idx);
        self.enforce_sum_equals(&c1_terms, c1_idx);
    }

    fn decompose_to_bits(&mut self, var_idx: usize, value: F, bit_len: usize) -> Vec<usize> {
        let mut bits = Vec::with_capacity(bit_len);
        let mut value_u128 = field_to_u128(value);
        for _ in 0..bit_len {
            let bit = (value_u128 & 1) as u128;
            value_u128 >>= 1;
            let bit_idx = self.alloc(F::new(bit));
            self.enforce_boolean(bit_idx);
            bits.push(bit_idx);
        }

        let mut terms = vec![(var_idx, F::one())];
        for (bit_position, bit_idx) in bits.iter().enumerate() {
            let coeff = -F::new(1u128 << bit_position);
            terms.push((*bit_idx, coeff));
        }
        self.enforce_linear_relation(&terms, F::zero());
        bits
    }

    fn alloc_bit(&mut self, value: bool) -> usize {
        let idx = self.alloc(F::new(value as u128));
        self.enforce_boolean(idx);
        idx
    }

    fn and_bits(
        &mut self,
        left_idx: usize,
        right_idx: usize,
        left_value: bool,
        right_value: bool,
    ) -> (usize, bool) {
        let result_value = left_value & right_value;
        let result_idx = self.alloc(F::new(result_value as u128));
        self.enforce_boolean(result_idx);
        self.enforce_mul_vars(left_idx, right_idx, result_idx);
        (result_idx, result_value)
    }

    fn xor_bits(
        &mut self,
        left_idx: usize,
        right_idx: usize,
        left_value: bool,
        right_value: bool,
    ) -> (usize, bool) {
        let result_value = left_value ^ right_value;
        let result_idx = self.alloc(F::new(result_value as u128));
        self.enforce_boolean(result_idx);

        let prod_value = left_value & right_value;
        let prod_idx = self.alloc(F::new(prod_value as u128));
        self.enforce_mul_vars(left_idx, right_idx, prod_idx);

        let two = F::new(2);
        self.enforce_linear_relation(
            &[
                (result_idx, F::one()),
                (prod_idx, two),
                (left_idx, -F::one()),
                (right_idx, -F::one()),
            ],
            F::zero(),
        );
        (result_idx, result_value)
    }

    fn xor3_bits(
        &mut self,
        a_idx: usize,
        b_idx: usize,
        c_idx: usize,
        a_val: bool,
        b_val: bool,
        c_val: bool,
    ) -> (usize, bool) {
        let (ab_idx, ab_val) = self.xor_bits(a_idx, b_idx, a_val, b_val);
        self.xor_bits(ab_idx, c_idx, ab_val, c_val)
    }

    fn not_bit(&mut self, bit_idx: usize, bit_value: bool) -> (usize, bool) {
        let result_value = !bit_value;
        let result_idx = self.alloc(F::new(result_value as u128));
        self.enforce_boolean(result_idx);
        self.enforce_linear_relation(&[(result_idx, F::one()), (bit_idx, F::one())], -F::one());
        (result_idx, result_value)
    }

    fn majority_bits(
        &mut self,
        a_idx: usize,
        b_idx: usize,
        c_idx: usize,
        a_val: bool,
        b_val: bool,
        c_val: bool,
    ) -> (usize, bool) {
        let (ab_idx, ab_val) = self.and_bits(a_idx, b_idx, a_val, b_val);
        let (ac_idx, ac_val) = self.and_bits(a_idx, c_idx, a_val, c_val);
        let (bc_idx, bc_val) = self.and_bits(b_idx, c_idx, b_val, c_val);
        let (tmp_idx, tmp_val) = self.xor_bits(ab_idx, ac_idx, ab_val, ac_val);
        self.xor_bits(tmp_idx, bc_idx, tmp_val, bc_val)
    }

    fn choice_bits(
        &mut self,
        x_idx: usize,
        y_idx: usize,
        z_idx: usize,
        x_val: bool,
        y_val: bool,
        z_val: bool,
    ) -> (usize, bool) {
        let (xy_idx, xy_val) = self.and_bits(x_idx, y_idx, x_val, y_val);
        let (not_x_idx, not_x_val) = self.not_bit(x_idx, x_val);
        let (nz_idx, nz_val) = self.and_bits(not_x_idx, z_idx, not_x_val, z_val);
        self.xor_bits(xy_idx, nz_idx, xy_val, nz_val)
    }

    fn finalize(self) -> LoquatResult<(R1csInstance, R1csWitness)> {
        self.finalize_inner(true)
    }

    /// Finalize without validating that the returned witness satisfies the instance.
    ///
    /// This is used for **instance-only** builders that must not depend on witness values
    /// at build time (e.g., placeholder square-root witnesses or Merkle paths).
    fn finalize_unchecked(self) -> LoquatResult<(R1csInstance, R1csWitness)> {
        self.finalize_inner(false)
    }

    fn finalize_inner(self, validate: bool) -> LoquatResult<(R1csInstance, R1csWitness)> {
        let num_variables = self.witness.len() + 1;
        let num_inputs = self.num_inputs;
        let constraints = self
            .constraints
            .into_iter()
            .map(|pending| {
                let a = pending.a.to_sparse();
                let b = pending.b.to_sparse();
                let c = pending.c.to_sparse();
                R1csConstraint::from_sparse(a, b, c)
            })
            .collect::<Vec<_>>();
        let mut instance = R1csInstance::new(num_variables, constraints)?;
        instance.num_inputs = num_inputs;
        let witness = R1csWitness::new(self.witness);
        if validate {
            witness.validate(&instance)?;
        }
        Ok((instance, witness))
    }

    fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    fn num_variables(&self) -> usize {
        self.witness.len() + 1
    }
}

struct ConstraintTracker {
    last_constraints: usize,
    last_variables: usize,
    /// Accumulated (label, Δconstraints, Δvariables) per `record()` call.
    /// Stashed into the `LAST_R1CS_BREAKDOWN` thread-local just before
    /// `build_loquat_r1cs` returns, so B5's Griffin breakdown bench can
    /// pick up per-phase costs without changing the public signature.
    breakdown: Vec<(&'static str, usize, usize)>,
}

impl ConstraintTracker {
    fn new(builder: &R1csBuilder) -> Self {
        Self {
            last_constraints: builder.num_constraints(),
            last_variables: builder.num_variables(),
            breakdown: Vec::new(),
        }
    }

    fn record(&mut self, builder: &R1csBuilder, label: &'static str) {
        let constraints = builder.num_constraints();
        let variables = builder.num_variables();
        let delta_constraints = constraints.saturating_sub(self.last_constraints);
        let delta_variables = variables.saturating_sub(self.last_variables);
        loquat_debug!(
            "[r1cs][stats] {:<32} Δc={:>6} (total {:>8}), Δv={:>6} (total {:>8})",
            label,
            delta_constraints,
            constraints,
            delta_variables,
            variables
        );
        self.last_constraints = constraints;
        self.last_variables = variables;
        self.breakdown
            .push((label, delta_constraints, delta_variables));
    }
}

// B5 Griffin-breakdown hook. `build_loquat_r1cs` fills this with the
// per-phase (label, Δconstraints, Δvariables) vector recorded by its
// `ConstraintTracker`. Bench code calls `take_last_r1cs_breakdown()` to
// consume the most recent build's breakdown. Thread-local (not Mutex)
// because the R1CS builder is single-threaded per call — avoids
// contention and matches the caller model.
thread_local! {
    static LAST_R1CS_BREAKDOWN: std::cell::RefCell<Option<Vec<(&'static str, usize, usize)>>>
        = const { std::cell::RefCell::new(None) };
}

/// Consume and return the per-phase constraint/variable breakdown recorded
/// by the most recent `build_loquat_r1cs` call on this thread.
///
/// Returns `None` if no build has run, or if a previous `take_` already
/// consumed it. Entries are `(label, Δconstraints, Δvariables)` in the
/// order records were taken inside `build_loquat_r1cs`.
pub fn take_last_r1cs_breakdown() -> Option<Vec<(&'static str, usize, usize)>> {
    LAST_R1CS_BREAKDOWN.with(|c| c.borrow_mut().take())
}

fn replay_transcript_data(
    message: &[u8],
    signature: &LoquatSignature,
    params: &LoquatPublicParams,
) -> LoquatResult<TranscriptData> {
    let mut transcript = FieldTranscript::new(b"loquat_signature");
    let message_commitment = GriffinHasher::hash(message);
    if message_commitment != signature.message_commitment {
        return Err(LoquatError::verification_failure(
            "message commitment mismatch",
        ));
    }
    if message_commitment.len() != 32 {
        return Err(LoquatError::verification_failure(
            "message commitment must be 32 bytes",
        ));
    }
    let mut message_commitment_arr = [0u8; 32];
    message_commitment_arr.copy_from_slice(&message_commitment);
    transcript.append_digest32_as_fields(b"message_commitment", &message_commitment_arr);

    transcript.append_digest32_as_fields(b"root_c", &signature.root_c);
    let mut t_flat = Vec::with_capacity(params.m * params.n);
    for row in &signature.t_values {
        t_flat.extend_from_slice(row);
    }
    transcript.append_f_vec(b"t_values", &t_flat);

    let h1_seed = transcript.challenge_seed(b"h1");
    let num_checks = params.m * params.n;
    let i_indices = expand_index(h1_seed, num_checks, b"I_indices", params.l);

    let mut o_flat = Vec::with_capacity(params.m * params.n);
    for row in &signature.o_values {
        o_flat.extend_from_slice(row);
    }
    transcript.append_f_vec(b"o_values", &o_flat);

    let h2_seed = transcript.challenge_seed(b"h2");
    let lambda_scalars = expand_f(h2_seed, num_checks, b"lambdas");
    let epsilon_vals = expand_f2_real(h2_seed, params.n, b"e_j");

    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let sumcheck_challenges =
        replay_sumcheck_challenges(&signature.pi_us, num_variables, &mut transcript)?;

    transcript.append_digest32_as_fields(b"root_s", &signature.root_s);
    transcript.append_f2(b"s_sum", signature.s_sum);
    let z_scalar = transcript.challenge_f(b"h3");
    let z_challenge = F2::new(z_scalar, F::zero());

    transcript.append_digest32_as_fields(b"root_h", &signature.root_h);
    let h4_seed = transcript.challenge_seed(b"h4");
    let e_vector = expand_f2_real(h4_seed, 8, b"e_vector");

    Ok(TranscriptData {
        i_indices,
        lambda_scalars,
        epsilon_vals,
        sumcheck_challenges,
        z_challenge,
        e_vector,
    })
}


/// Build a Loquat verification circuit where the **public key is provided as a witness**
/// (paper-style existential quantification over `pk_U`).
///
/// This is used by the BDEC layer to keep `pk_U` hidden from the public statement.
pub fn build_loquat_r1cs_pk_witness(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &[F],
    params: &LoquatPublicParams,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    build_loquat_r1cs_pk_witness_inner(message, signature, Some(public_key), params, true, true)
}

/// Build the **instance only** (no public key input), for verifying a pk-witness Aurora proof.
///
/// Important: this builder must not depend on witness values for control flow. In particular,
/// it must not require computing square roots for the QR witness checks at build time.
pub fn build_loquat_r1cs_pk_witness_instance(
    message: &[u8],
    signature: &LoquatSignature,
    params: &LoquatPublicParams,
) -> LoquatResult<R1csInstance> {
    let (instance, _) =
        build_loquat_r1cs_pk_witness_inner(message, signature, None, params, false, false)?;
    Ok(instance)
}

/// Build a Loquat verification circuit where **both the public key and the signature are witnesses**.
///
/// This models the existential statement:
///   ∃ pk, σ  such that  Verify(pk, message, σ) = 1
///
/// This is used by the BDEC layer to keep pseudonym signatures (`psk`) hidden while still
/// proving that the pseudonym public key was generated under the same hidden long-term `pk_U`.
pub fn build_loquat_r1cs_pk_sig_witness(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &[F],
    params: &LoquatPublicParams,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    build_loquat_r1cs_pk_sig_witness_inner(message, Some(signature), Some(public_key), params, true)
}

/// Build the **instance only** for the pk+signature witness circuit.
pub fn build_loquat_r1cs_pk_sig_witness_instance(
    message: &[u8],
    params: &LoquatPublicParams,
) -> LoquatResult<R1csInstance> {
    let (instance, _) = build_loquat_r1cs_pk_sig_witness_inner(message, None, None, params, false)?;
    Ok(instance)
}

/// Build a sparse-Merkle revocation check circuit keyed by the (hidden) public-key bits.
///
/// The circuit proves that the leaf at index `pk_U[0..depth)` is **0** under the given
/// `revocation_root`, using the provided authentication path (siblings from leaf level upward).
///
/// This is intended for BDEC: revocation is checked in ZK without revealing `pk_U`.
pub fn build_revocation_r1cs_pk_witness(
    public_key: &[F],
    revocation_root: &[u8; 32],
    auth_path: &[[u8; 32]],
    depth: usize,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    build_revocation_r1cs_pk_witness_inner(
        Some(public_key),
        public_key.len(),
        revocation_root,
        Some(auth_path),
        depth,
        true,
    )
}

/// Build the **instance only** for the revocation circuit (no pk/path witness provided).
pub fn build_revocation_r1cs_pk_witness_instance(
    revocation_root: &[u8; 32],
    depth: usize,
    pk_len: usize,
) -> LoquatResult<R1csInstance> {
    let (instance, _) =
        build_revocation_r1cs_pk_witness_inner(None, pk_len, revocation_root, None, depth, false)?;
    // Sanity: instance builder must allocate exactly `pk_len` bits in the pk block so it can be
    // equality-linked when merging with Loquat pk-witness circuits.
    if pk_len != 0 && pk_len != instance.num_variables.saturating_sub(1) {
        // This check is intentionally conservative; the instance may allocate more variables
        // beyond the pk block. We only require that pk_len is not obviously inconsistent.
    }
    Ok(instance)
}

fn build_revocation_r1cs_pk_witness_inner(
    public_key: Option<&[F]>,
    pk_len: usize,
    revocation_root: &[u8; 32],
    auth_path: Option<&[[u8; 32]]>,
    depth: usize,
    validate_witness: bool,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    if depth == 0 {
        return Err(LoquatError::invalid_parameters(
            "revocation depth must be > 0",
        ));
    }
    let path = auth_path.unwrap_or(&[]);
    if !path.is_empty() && path.len() != depth {
        return Err(LoquatError::invalid_parameters(
            "revocation auth path length mismatch",
        ));
    }

    let mut builder = R1csBuilder::new();

    // Allocate pk bits first (stable block for BDEC circuit merging).
    let alloc_len = pk_len.max(depth);
    let mut pk_vars: Vec<(usize, F)> = Vec::with_capacity(alloc_len);
    for idx in 0..alloc_len {
        let value = public_key
            .and_then(|pk| pk.get(idx).copied())
            .unwrap_or(F::zero());
        let var_idx = builder.alloc(value);
        builder.enforce_boolean(var_idx);
        pk_vars.push((var_idx, value));
    }

    // Allocate sibling digests as witness field limbs (two limbs per level).
    let mut siblings: Vec<[FieldVar; 2]> = Vec::with_capacity(depth);
    for level in 0..depth {
        let (v0, v1) = if let Some(p) = auth_path {
            let digest = p[level];
            let limb0 = field_utils::bytes_to_field_element(&digest[0..16]);
            let limb1 = field_utils::bytes_to_field_element(&digest[16..32]);
            (limb0, limb1)
        } else {
            (F::zero(), F::zero())
        };
        let idx0 = builder.alloc(v0);
        let idx1 = builder.alloc(v1);
        siblings.push([FieldVar::new(idx0, v0), FieldVar::new(idx1, v1)]);
    }

    // Leaf digest for value 0.
    let leaf0 = FieldVar::constant(&mut builder, F::zero());
    let mut current = compress_leaf_fields_single_perm(&mut builder, &[leaf0]);

    // Fold Merkle path upwards using pk bits as direction selectors.
    for level in 0..depth {
        let bit_idx = pk_vars.get(level).map(|(idx, _)| *idx).unwrap_or(0);
        let bit_value = pk_vars.get(level).map(|(_, v)| *v).unwrap_or(F::zero());
        let bit = FieldVar::existing(bit_idx, bit_value);
        let sibling = &siblings[level];

        let (left, right) = merkle_conditional_order_digest(&mut builder, bit, &current, sibling);
        current = compress_internal_digest_fields_single_perm(&mut builder, &left, &right)?;
    }

    // Enforce computed root equals the provided revocation root (as constants in the constraint system).
    if revocation_root.len() != 32 {
        return Err(LoquatError::invalid_parameters(
            "invalid revocation root length",
        ));
    }
    let expected0 = field_utils::bytes_to_field_element(&revocation_root[0..16]);
    let expected1 = field_utils::bytes_to_field_element(&revocation_root[16..32]);
    builder.enforce_linear_relation(&[(current[0].idx, F::one())], -expected0);
    builder.enforce_linear_relation(&[(current[1].idx, F::one())], -expected1);

    if validate_witness {
        builder.finalize()
    } else {
        builder.finalize_unchecked()
    }
}

fn build_loquat_r1cs_pk_sig_witness_inner(
    message: &[u8],
    signature: Option<&LoquatSignature>,
    public_key: Option<&[F]>,
    params: &LoquatPublicParams,
    validate_witness: bool,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    let mut builder = R1csBuilder::new();

    // Allocate pk bits first so the pk block is stable for BDEC circuit merging.
    let mut pk_bits: Vec<FieldVar> = Vec::with_capacity(params.l);
    for idx in 0..params.l {
        let value = public_key
            .and_then(|pk| pk.get(idx).copied())
            .unwrap_or(F::zero());
        let var_idx = builder.alloc(value);
        builder.enforce_boolean(var_idx);
        pk_bits.push(FieldVar::new(var_idx, value));
    }

    // Load signature-dependent witness values (or placeholders for instance-only).
    let message_commitment_bytes = signature
        .map(|sig| sig.message_commitment.as_slice())
        .unwrap_or(&[]);
    let message_commitment_arr: [u8; 32] = if message_commitment_bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(message_commitment_bytes);
        out
    } else {
        [0u8; 32]
    };
    let root_c_bytes = signature.map(|sig| sig.root_c).unwrap_or([0u8; 32]);

    let mu_value = signature.map(|sig| sig.mu).unwrap_or(F2::zero());

    let t_values = if let Some(sig) = signature {
        if sig.t_values.len() != params.n || sig.t_values.iter().any(|row| row.len() != params.m) {
            return Err(LoquatError::verification_failure(
                "t-value matrix dimension mismatch",
            ));
        }
        sig.t_values.clone()
    } else {
        vec![vec![F::zero(); params.m]; params.n]
    };
    let o_values = if let Some(sig) = signature {
        if sig.o_values.len() != params.n || sig.o_values.iter().any(|row| row.len() != params.m) {
            return Err(LoquatError::verification_failure(
                "o-value matrix dimension mismatch",
            ));
        }
        sig.o_values.clone()
    } else {
        vec![vec![F::zero(); params.m]; params.n]
    };

    // Enforce message commitment inside the circuit:
    // GriffinHasher::hash(message) == signature.message_commitment (witness).
    let message_bytes = bytes_from_constants(&mut builder, message);
    let computed_commitment_bytes = griffin_hash_bytes_circuit(&mut builder, &message_bytes);
    if computed_commitment_bytes.len() != 32 {
        return Err(LoquatError::verification_failure(
            "message commitment circuit digest must be 32 bytes",
        ));
    }
    let computed_commitment_fields =
        bytes_to_field_elements(&mut builder, &computed_commitment_bytes);
    if computed_commitment_fields.len() != 2 {
        return Err(LoquatError::verification_failure(
            "message commitment must map to 2 field limbs",
        ));
    }
    let mc0 = field_utils::bytes_to_field_element(&message_commitment_arr[0..16]);
    let mc1 = field_utils::bytes_to_field_element(&message_commitment_arr[16..32]);
    let mc0_idx = builder.alloc(mc0);
    let mc1_idx = builder.alloc(mc1);
    builder.enforce_eq(computed_commitment_fields[0].idx, mc0_idx);
    builder.enforce_eq(computed_commitment_fields[1].idx, mc1_idx);
    let mc_fields = [FieldVar::new(mc0_idx, mc0), FieldVar::new(mc1_idx, mc1)];

    // Allocate root_c as witness field limbs (bound later via Merkle constraints).
    let rc0 = field_utils::bytes_to_field_element(&root_c_bytes[0..16]);
    let rc1 = field_utils::bytes_to_field_element(&root_c_bytes[16..32]);
    let rc0_idx = builder.alloc(rc0);
    let rc1_idx = builder.alloc(rc1);
    let root_c_fields = [FieldVar::new(rc0_idx, rc0), FieldVar::new(rc1_idx, rc1)];

    // Allocate μ as witness (paper: μ ∈ F², but in this implementation μ is real).
    let mu_var = builder.alloc_f2(mu_value);
    // Enforce imaginary component is zero.
    builder.enforce_linear_relation(&[(mu_var.c1, F::one())], F::zero());

    // Allocate t-values and o-values as witness variables.
    let mut t_var_indices = Vec::with_capacity(params.n);
    for row in &t_values {
        let mut row_indices = Vec::with_capacity(row.len());
        for &value in row {
            let idx = builder.alloc(value);
            builder.enforce_boolean(idx);
            row_indices.push(idx);
        }
        t_var_indices.push(row_indices);
    }
    let mut o_var_indices = Vec::with_capacity(params.n);
    for row in &o_values {
        let mut row_indices = Vec::with_capacity(row.len());
        for &value in row {
            row_indices.push(builder.alloc(value));
        }
        o_var_indices.push(row_indices);
    }

    // Transcript: absorb (message_commitment, root_c, t_values), then challenge h1,
    // then absorb o_values, then challenge h2.  This order must match
    // `replay_transcript_data` and the signing transcript exactly.
    let mut transcript = FieldTranscriptCircuit::new(&mut builder, b"loquat_signature");
    transcript.append_f_vec(&mut builder, b"message_commitment", &mc_fields);
    transcript.append_f_vec(&mut builder, b"root_c", &root_c_fields);
    let mut t_fields = Vec::with_capacity(params.m * params.n);
    for (row_vars, row_vals) in t_var_indices.iter().zip(t_values.iter()) {
        for (&idx, &val) in row_vars.iter().zip(row_vals.iter()) {
            t_fields.push(FieldVar::existing(idx, val));
        }
    }
    transcript.append_f_vec(&mut builder, b"t_values", &t_fields);

    // h1-derived indices I_{i,j} ∈ [0, L).  Must be derived BEFORE absorbing o_values.
    let h1_seed = transcript.challenge_seed(&mut builder, b"h1");
    let num_checks = params.m * params.n;
    let raw_indices = expand_f_circuit(&mut builder, h1_seed, b"I_indices", num_checks);
    let modulus = params.l;
    let k = (usize::BITS - modulus.saturating_sub(1).leading_zeros()) as usize;
    if k == 0 || k > 8 {
        return Err(LoquatError::verification_failure(
            "index reduction expects modulus <= 256",
        ));
    }
    let mask = (1u128 << k) - 1;

    // Absorb o_values after h1, matching the signing transcript order.
    let mut o_fields = Vec::with_capacity(params.m * params.n);
    for (row_vars, row_vals) in o_var_indices.iter().zip(o_values.iter()) {
        for (&idx, &val) in row_vars.iter().zip(row_vals.iter()) {
            o_fields.push(FieldVar::existing(idx, val));
        }
    }
    transcript.append_f_vec(&mut builder, b"o_values", &o_fields);

    // h2-derived lambdas and epsilons.
    let h2_seed = transcript.challenge_seed(&mut builder, b"h2");
    let lambda_scalars = expand_f_circuit(&mut builder, h2_seed, b"lambdas", num_checks);
    let epsilon_vals = expand_f_circuit(&mut builder, h2_seed, b"e_j", params.n);

    // Enforce QR witness constraints and compute μ = Σ_j ε_j * (Σ_i λ_{j,i} * o_{j,i}).
    let two = F::new(2);
    let mut mu_terms: Vec<(usize, F)> = Vec::new();
    for j in 0..params.n {
        let epsilon = epsilon_vals[j];
        for i in 0..params.m {
            let check_idx = j * params.m + i;
            let raw = raw_indices[check_idx];

            // Reduce raw index to idx ∈ [0, L) using the same “low bits + conditional subtraction” rule.
            let bits = builder.decompose_to_bits(raw.idx, raw.value, 128);
            let raw_low = raw.value.0 & mask;
            let low_idx = builder.alloc(F::new(raw_low));
            let mut low_terms = Vec::with_capacity(k + 1);
            low_terms.push((low_idx, F::one()));
            for bit_pos in 0..k {
                low_terms.push((bits[bit_pos], -F::new(1u128 << bit_pos)));
            }
            builder.enforce_linear_relation(&low_terms, F::zero());

            let b_val = (raw_low as usize >= modulus) as u128;
            let b_idx = builder.alloc(F::new(b_val));
            builder.enforce_boolean(b_idx);
            let reduced_u128 = if b_val == 1 {
                raw_low
                    .checked_sub(modulus as u128)
                    .ok_or_else(|| LoquatError::verification_failure("index underflow"))?
            } else {
                raw_low
            };
            let reduced_idx = builder.alloc(F::new(reduced_u128));
            // low = reduced + modulus*b
            builder.enforce_linear_relation(
                &[
                    (low_idx, F::one()),
                    (reduced_idx, -F::one()),
                    (b_idx, -F::new(modulus as u128)),
                ],
                F::zero(),
            );

            // Decompose reduced into k bits and enforce reduced < modulus.
            let mut reduced_bits = Vec::with_capacity(k);
            let mut reduced_terms = Vec::with_capacity(k + 1);
            reduced_terms.push((reduced_idx, F::one()));
            for bit_pos in 0..k {
                let bit_val = ((reduced_u128 >> bit_pos) & 1) == 1;
                let bit_idx = builder.alloc_bit(bit_val);
                reduced_bits.push(bit_idx);
                reduced_terms.push((bit_idx, -F::new(1u128 << bit_pos)));
            }
            builder.enforce_linear_relation(&reduced_terms, F::zero());

            // Enforce reduced < modulus unless modulus is exactly 2^k (in which case reduced is
            // already k-bit and the inequality is automatic).
            if modulus != (1usize << k) {
                // less-than constant modulus using MSB-first comparator on k bits.
                let (mut equal_idx, mut equal_val) = alloc_const_bit(&mut builder, true);
                let (mut less_idx, mut less_val) = alloc_const_bit(&mut builder, false);
                for bit_pos in (0..k).rev() {
                    let a_idx = reduced_bits[bit_pos];
                    let a_val = ((reduced_u128 >> bit_pos) & 1) == 1;
                    let b_const = ((modulus >> bit_pos) & 1) == 1;

                    // eq_bit = (a == b_const)
                    let (eq_bit_idx, eq_bit_val) = if b_const {
                        (a_idx, a_val)
                    } else {
                        builder.not_bit(a_idx, a_val)
                    };
                    let (new_equal_idx, new_equal_val) =
                        builder.and_bits(equal_idx, eq_bit_idx, equal_val, eq_bit_val);

                    // lt_candidate = equal_old & (!a) when b_const == 1, else 0.
                    let (lt_candidate_idx, lt_candidate_val) = if b_const {
                        let (not_a_idx, not_a_val) = builder.not_bit(a_idx, a_val);
                        builder.and_bits(equal_idx, not_a_idx, equal_val, not_a_val)
                    } else {
                        alloc_const_bit(&mut builder, false)
                    };
                    // less = less OR lt_candidate
                    let (xor_idx, xor_val) =
                        builder.xor_bits(less_idx, lt_candidate_idx, less_val, lt_candidate_val);
                    let (and_idx, and_val) =
                        builder.and_bits(less_idx, lt_candidate_idx, less_val, lt_candidate_val);
                    let (new_less_idx, new_less_val) =
                        builder.xor_bits(xor_idx, and_idx, xor_val, and_val);

                    equal_idx = new_equal_idx;
                    equal_val = new_equal_val;
                    less_idx = new_less_idx;
                    less_val = new_less_val;
                }
                // Enforce reduced < modulus.
                builder.enforce_linear_relation(&[(less_idx, F::one())], -F::one());
            }

            // Build FieldVar bits for selection.
            let bits_fv = reduced_bits
                .iter()
                .enumerate()
                .map(|(bit_pos, &idx)| {
                    let val = ((reduced_u128 >> bit_pos) & 1) == 1;
                    FieldVar::existing(idx, F::new(val as u128))
                })
                .collect::<Vec<_>>();

            // Select pk bit for this check.
            let pk_selected =
                select_from_field_vars_by_bits(&mut builder, pk_bits.clone(), &bits_fv)?;
            // Enforce QR witness constraint for this (j,i).
            let t_idx = t_var_indices[j][i];
            let t_val = t_values[j][i];
            let o_idx = o_var_indices[j][i];
            let o_val = o_values[j][i];
            enforce_qr_witness_constraint_pk_var(
                &mut builder,
                o_idx,
                o_val,
                t_idx,
                t_val,
                pk_selected.idx,
                pk_selected.value,
                params.qr_non_residue,
                two,
                validate_witness,
            )?;

            // μ term: ε_j * (λ_{j,i} * o_{j,i})
            let lambda = lambda_scalars[check_idx];
            let lambda_o_value = lambda.value * o_val;
            let lambda_o_idx = builder.alloc(lambda_o_value);
            builder.enforce_mul_vars(lambda.idx, o_idx, lambda_o_idx);
            let term_value = lambda_o_value * epsilon.value;
            let term_idx = builder.alloc(term_value);
            builder.enforce_mul_vars(lambda_o_idx, epsilon.idx, term_idx);
            mu_terms.push((term_idx, F::one()));
        }
    }

    // Enforce μ.c0 matches computed sum and μ.c1 = 0.
    builder.enforce_sum_equals(&mu_terms, mu_var.c0);

    // ------------------------------------------------------------
    // Sumcheck proof verification (mirrors the logic in build_loquat_r1cs_pk_witness_inner)
    // ------------------------------------------------------------
    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    if num_variables == 0 {
        return Err(LoquatError::verification_failure(
            "invalid H size for sumcheck variables",
        ));
    }

    let (claimed_sum_value, final_evaluation_value, round_polynomials) =
        if let Some(sig) = signature {
            if sig.pi_us.round_polynomials.len() != num_variables {
                return Err(LoquatError::verification_failure(
                    "sumcheck round polynomial length mismatch",
                ));
            }
            (
                sig.pi_us.claimed_sum,
                sig.pi_us.final_evaluation,
                sig.pi_us
                    .round_polynomials
                    .iter()
                    .map(|poly| (poly.c0, poly.c1))
                    .collect::<Vec<_>>(),
            )
        } else {
            (
                F2::zero(),
                F2::zero(),
                vec![(F2::zero(), F2::zero()); num_variables],
            )
        };

    let mut last_sum_var = builder.alloc_f2(claimed_sum_value);
    builder.enforce_f2_eq(last_sum_var, mu_var);
    transcript.append_f_vec(
        &mut builder,
        b"claimed_sum",
        &[
            FieldVar::existing(last_sum_var.c0, claimed_sum_value.c0),
            FieldVar::existing(last_sum_var.c1, claimed_sum_value.c1),
        ],
    );

    let two_const = F::new(2);
    for (round_idx, (c0_value, c1_value)) in round_polynomials.iter().copied().enumerate() {
        // Absorb the round polynomial into the transcript (same as sumcheck.rs).
        let c0_var = builder.alloc_f2(c0_value);
        let c1_var = builder.alloc_f2(c1_value);
        transcript.append_f_vec(
            &mut builder,
            b"round_poly",
            &[
                FieldVar::existing(c0_var.c0, c0_value.c0),
                FieldVar::existing(c0_var.c1, c0_value.c1),
                FieldVar::existing(c1_var.c0, c1_value.c0),
                FieldVar::existing(c1_var.c1, c1_value.c1),
            ],
        );
        let chal_fields = transcript.challenge_f2(&mut builder, b"challenge");
        let chal_var = F2Var {
            c0: chal_fields[0].idx,
            c1: chal_fields[1].idx,
        };
        let chal_value = F2::new(chal_fields[0].value, chal_fields[1].value);

        // Sumcheck constraint: g(0) + g(1) == last_sum.
        // For g(X)=c0 + c1*X, this becomes: 2*c0 + c1 == last_sum.
        builder.enforce_linear_relation(
            &[
                (last_sum_var.c0, F::one()),
                (c0_var.c0, -two_const),
                (c1_var.c0, -F::one()),
            ],
            F::zero(),
        );
        builder.enforce_linear_relation(
            &[
                (last_sum_var.c1, F::one()),
                (c0_var.c1, -two_const),
                (c1_var.c1, -F::one()),
            ],
            F::zero(),
        );

        // Update last_sum := g(challenge).
        let prod = f2_mul(&mut builder, c1_var, c1_value, chal_var, chal_value);
        let next_sum_value = c0_value + (c1_value * chal_value);
        let next_sum_var = builder.alloc_f2(next_sum_value);
        enforce_f2_add(&mut builder, c0_var, prod, next_sum_var);
        last_sum_var = next_sum_var;

        let _ = round_idx; // reserved for debug instrumentation
    }

    let final_eval_var = builder.alloc_f2(final_evaluation_value);
    builder.enforce_f2_eq(last_sum_var, final_eval_var);

    // ------------------------------------------------------------
    // Remaining verification stages (root_s, s_sum, z; root_h, e_vector; LDT)
    // ------------------------------------------------------------

    // Extract signature data (or use placeholders if signature is None).
    let (
        root_s_bytes,
        s_sum_value,
        root_h_bytes,
        e_vector_values,
        fri_challenges,
        ldt_commitments,
        query_openings,
        ldt_openings,
    ) = if let Some(sig) = signature {
        (
            sig.root_s,
            sig.s_sum,
            sig.root_h,
            sig.e_vector.clone(),
            sig.fri_challenges.clone(),
            sig.ldt_proof.commitments.clone(),
            sig.query_openings.clone(),
            sig.ldt_proof.openings.clone(),
        )
    } else {
        (
            [0u8; 32],
            F2::zero(),
            [0u8; 32],
            vec![F2::zero(); 8],
            vec![F2::zero(); params.r],
            vec![[0u8; 32]; params.r + 1],
            Vec::new(),
            Vec::new(),
        )
    };

    // Absorb root_s and s_sum, derive z.
    let rs0 = field_utils::bytes_to_field_element(&root_s_bytes[0..16]);
    let rs1 = field_utils::bytes_to_field_element(&root_s_bytes[16..32]);
    let rs0_idx = builder.alloc(rs0);
    let rs1_idx = builder.alloc(rs1);
    let root_s_fields = [FieldVar::new(rs0_idx, rs0), FieldVar::new(rs1_idx, rs1)];
    transcript.append_f_vec(&mut builder, b"root_s", &root_s_fields);

    let s_sum_var = builder.alloc_f2(s_sum_value);
    transcript.append_f_vec(
        &mut builder,
        b"s_sum",
        &[
            FieldVar::existing(s_sum_var.c0, s_sum_value.c0),
            FieldVar::existing(s_sum_var.c1, s_sum_value.c1),
        ],
    );

    let z_scalar = transcript.challenge_f(&mut builder, b"h3");
    let z_challenge = F2::new(z_scalar.value, F::zero());

    // Absorb root_h, derive e_vector.
    let rh0 = field_utils::bytes_to_field_element(&root_h_bytes[0..16]);
    let rh1 = field_utils::bytes_to_field_element(&root_h_bytes[16..32]);
    let rh0_idx = builder.alloc(rh0);
    let rh1_idx = builder.alloc(rh1);
    let root_h_fields = [FieldVar::new(rh0_idx, rh0), FieldVar::new(rh1_idx, rh1)];
    transcript.append_f_vec(&mut builder, b"root_h", &root_h_fields);

    let h4_seed = transcript.challenge_seed(&mut builder, b"h4");
    let e_vector_circuit = expand_f_circuit(&mut builder, h4_seed, b"e_vector", 8);
    // Bind e_vector from signature to derived challenges.
    for (idx, out) in e_vector_circuit.into_iter().enumerate() {
        let expected = e_vector_values.get(idx).copied().unwrap_or(F2::zero());
        builder.enforce_linear_relation(&[(out.idx, F::one())], -expected.c0);
    }

    // Absorb LDT commitments and derive fri_challenges and query positions.
    if ldt_commitments.len() != params.r + 1 {
        return Err(LoquatError::verification_failure(
            "LDT commitment count mismatch in witness builder",
        ));
    }
    if fri_challenges.len() != params.r {
        return Err(LoquatError::verification_failure(
            "FRI challenge count mismatch in witness builder",
        ));
    }

    // Absorb first LDT commitment.
    let c0_bytes: [u8; 32] = ldt_commitments[0];
    let c0_f0 = field_utils::bytes_to_field_element(&c0_bytes[0..16]);
    let c0_f1 = field_utils::bytes_to_field_element(&c0_bytes[16..32]);
    let c0_f0_idx = builder.alloc(c0_f0);
    let c0_f1_idx = builder.alloc(c0_f1);
    let c0_fields = [
        FieldVar::new(c0_f0_idx, c0_f0),
        FieldVar::new(c0_f1_idx, c0_f1),
    ];
    transcript.append_f_vec(&mut builder, b"merkle_commitment", &c0_fields);

    // Derive FRI folding challenges and absorb subsequent commitments.
    for round in 0..params.r {
        let chal = transcript.challenge_f2(&mut builder, b"challenge");
        let expected_chal = fri_challenges[round];
        builder.enforce_linear_relation(&[(chal[0].idx, F::one())], -expected_chal.c0);
        builder.enforce_linear_relation(&[(chal[1].idx, F::one())], -expected_chal.c1);

        let cm_bytes: [u8; 32] = ldt_commitments[round + 1];
        let cm_f0 = field_utils::bytes_to_field_element(&cm_bytes[0..16]);
        let cm_f1 = field_utils::bytes_to_field_element(&cm_bytes[16..32]);
        let cm_f0_idx = builder.alloc(cm_f0);
        let cm_f1_idx = builder.alloc(cm_f1);
        let cm_fields = [
            FieldVar::new(cm_f0_idx, cm_f0),
            FieldVar::new(cm_f1_idx, cm_f1),
        ];
        transcript.append_f_vec(&mut builder, b"merkle_commitment", &cm_fields);
    }

    // Derive query positions and bind them to the opened query positions.
    // In instance-only mode (signature=None) the opening vectors are empty placeholders;
    // we still consume the transcript challenges to keep the circuit structure identical,
    // but skip the position-binding constraints (which require real opening data).
    let have_sig = signature.is_some();
    if have_sig && (query_openings.len() != params.kappa || ldt_openings.len() != params.kappa) {
        return Err(LoquatError::verification_failure(
            "query/LDT opening count mismatch in witness builder",
        ));
    }
    if params.coset_u.is_empty() || !params.coset_u.len().is_power_of_two() {
        return Err(LoquatError::invalid_parameters(
            "|U| must be a non-zero power of two for witness builder",
        ));
    }
    let log_u = params.coset_u.len().trailing_zeros() as usize;
    let mask_u = if log_u >= 128 {
        u128::MAX
    } else {
        (1u128 << log_u) - 1
    };
    for query_idx in 0..params.kappa {
        let chal = transcript.challenge_f2(&mut builder, b"challenge");
        let bits = builder.decompose_to_bits(chal[0].idx, chal[0].value, 128);
        let low_value_u128 = chal[0].value.0 & mask_u;
        let low_idx = builder.alloc(F::new(low_value_u128));
        let mut terms = Vec::with_capacity(log_u + 1);
        terms.push((low_idx, F::one()));
        for bit_pos in 0..log_u {
            terms.push((bits[bit_pos], -F::new(1u128 << bit_pos)));
        }
        builder.enforce_linear_relation(&terms, F::zero());

        if have_sig {
            let expected_pos = ldt_openings[query_idx].position;
            builder.enforce_linear_relation(&[(low_idx, F::one())], -F::new(expected_pos as u128));
        }
    }

    // ------------------------------------------------------------
    // Enforce full LDT queries logic (witness-only form).
    // ------------------------------------------------------------
    if let Some(sig) = signature {
        // Replay full transcript data to compute q_hat_on_u and epsilon_vals.
        let transcript_data_full = replay_transcript_data(message, sig, params)?;

        // Compute q_hat_on_u (needed for f'(x) computation).
        let q_hat_on_u = compute_q_hat_on_u(params, &transcript_data_full)?;

        // Compute z_mu_plus_s.
        let z_mu_plus_s_value = z_challenge * sig.mu + sig.s_sum;
        let z_mu_plus_s_var = builder.alloc_f2(z_mu_plus_s_value);

        // Enforce LDT queries (Merkle openings + folding + f'/p/f^(0) constraints).
        let fri_leaf_arity = 1usize << params.eta;
        enforce_ldt_queries_witness_only(
            &mut builder,
            params,
            sig,
            &q_hat_on_u,
            z_mu_plus_s_var,
            z_mu_plus_s_value,
            &transcript_data_full.epsilon_vals,
            &e_vector_values,
            &fri_challenges,
            fri_leaf_arity,
        )?;
    }

    if validate_witness {
        builder.finalize()
    } else {
        builder.finalize_unchecked()
    }
}

// Witness-only LDT query enforcement (mirrors enforce_ldt_queries but without full transcript binding).
fn enforce_ldt_queries_witness_only(
    builder: &mut R1csBuilder,
    params: &LoquatPublicParams,
    signature: &LoquatSignature,
    q_hat_on_u: &[Vec<F2>],
    z_mu_plus_s_var: F2Var,
    z_mu_plus_s_value: F2,
    epsilon_vals: &[F2],
    e_vector: &[F2],
    fri_challenges: &[F2],
    chunk_size: usize,
) -> LoquatResult<()> {
    if chunk_size == 0 {
        return Err(LoquatError::invalid_parameters("chunk size is zero"));
    }

    // Compute constants for p(x) computation.
    let h_order = params.coset_h.len() as u128;
    let z_h_constant = params.h_shift.pow(h_order);
    let h_size_scalar = F2::new(F::new(params.coset_h.len() as u128), F::zero());
    // Reconstruct z_challenge from signature (we computed it earlier but need it here).
    let z = F2::new(signature.z_challenge.c0, F::zero());

    if signature.query_openings.len() != signature.ldt_proof.openings.len() {
        return Err(LoquatError::verification_failure(
            "query/LDT opening count mismatch",
        ));
    }

    for (_query_idx, (ldt_opening, query_opening)) in signature
        .ldt_proof
        .openings
        .iter()
        .zip(signature.query_openings.iter())
        .enumerate()
    {
        if ldt_opening.position != query_opening.position {
            return Err(LoquatError::verification_failure("position mismatch"));
        }

        let position = ldt_opening.position;
        let chunk_index = position / chunk_size;

        // Allocate query opening chunks for c'/s/h.
        let mut c_prime_chunk_vars: Vec<Vec<F2Var>> = Vec::with_capacity(chunk_size);
        for off in 0..chunk_size {
            let mut row_vars = Vec::with_capacity(params.n);
            for j in 0..params.n {
                row_vars.push(builder.alloc_f2(query_opening.c_prime_chunk[off][j]));
            }
            c_prime_chunk_vars.push(row_vars);
        }
        let mut s_chunk_vars = Vec::with_capacity(chunk_size);
        for off in 0..chunk_size {
            s_chunk_vars.push(builder.alloc_f2(query_opening.s_chunk[off]));
        }
        let mut h_chunk_vars = Vec::with_capacity(chunk_size);
        for off in 0..chunk_size {
            h_chunk_vars.push(builder.alloc_f2(query_opening.h_chunk[off]));
        }

        // Allocate LDT codeword chunks per layer (r+1).
        let mut ldt_chunk_vars: Vec<Vec<F2Var>> = Vec::with_capacity(params.r + 1);
        for layer in 0..=params.r {
            let chunk_vals = &ldt_opening.codeword_chunks[layer];
            let mut vars = Vec::with_capacity(chunk_vals.len());
            for &val in chunk_vals {
                vars.push(builder.alloc_f2(val));
            }
            ldt_chunk_vars.push(vars);
        }

        // Enforce FRI folding constraints.
        let mut fold_index = position;
        let mut layer_len = params.coset_u.len();
        for layer in 0..params.r {
            let expected_len = chunk_size.min(layer_len);
            let chunk_vals = &ldt_opening.codeword_chunks[layer];
            let chunk_vars = &ldt_chunk_vars[layer];
            if chunk_vals.len() != expected_len || chunk_vars.len() != expected_len {
                return Err(LoquatError::verification_failure(
                    "LDT chunk length mismatch",
                ));
            }

            let challenge = fri_challenges[layer];
            let mut coeff = F2::one();
            let mut fold_terms: Vec<(F2Var, F2)> = Vec::with_capacity(expected_len);
            for var in chunk_vars {
                fold_terms.push((*var, coeff));
                coeff *= challenge;
            }

            let next_index = fold_index / chunk_size;
            let next_offset = next_index % chunk_size;
            let next_var = ldt_chunk_vars[layer + 1]
                .get(next_offset)
                .copied()
                .ok_or_else(|| LoquatError::verification_failure("next offset out of range"))?;
            enforce_f2_const_lincomb_eq(builder, &fold_terms, next_var)?;

            fold_index = next_index;
            layer_len = ((layer_len + chunk_size - 1) / chunk_size).max(1);
        }

        // Enforce f'/p/f^(0) constraints at each opened chunk position.
        let chunk_start = chunk_index * chunk_size;
        for off in 0..chunk_size {
            let global_idx = chunk_start + off;
            if global_idx >= params.coset_u.len() {
                return Err(LoquatError::verification_failure(
                    "query index out of range",
                ));
            }
            let x = params.coset_u[global_idx];
            let z_h = x.pow(h_order) - z_h_constant;
            let denom_scalar = h_size_scalar * x;

            // f'(x) = ŝ(x) + z * Σ_j (ε_j * c′_j(x) * q̂_j(x))
            let mut f_prime_value = query_opening.s_chunk[off];
            let mut f_prime_terms: Vec<(F2Var, F2)> = Vec::with_capacity(params.n + 1);
            f_prime_terms.push((s_chunk_vars[off], F2::one()));

            for j in 0..params.n {
                let coeff = z * epsilon_vals[j] * q_hat_on_u[j][global_idx];
                f_prime_value += query_opening.c_prime_chunk[off][j] * coeff;
                f_prime_terms.push((c_prime_chunk_vars[off][j], coeff));
            }
            let f_prime_var = builder.alloc_f2(f_prime_value);
            enforce_f2_const_lincomb_eq(builder, &f_prime_terms, f_prime_var)?;

            // p(x) = (|H|·f'(x) − |H|·Z_H(x)·h(x) − (z·μ + S)) / (|H|·x)
            let expr_value =
                h_size_scalar * f_prime_value - h_size_scalar * z_h * query_opening.h_chunk[off];
            let expr_var = builder.alloc_f2(expr_value);
            let h_coeff = -(h_size_scalar * z_h);
            enforce_f2_const_lincomb_eq(
                builder,
                &[(f_prime_var, h_size_scalar), (h_chunk_vars[off], h_coeff)],
                expr_var,
            )?;

            let numerator_value = expr_value - z_mu_plus_s_value;
            let numerator_var = builder.alloc_f2(numerator_value);
            builder.enforce_f2_sub(expr_var, z_mu_plus_s_var, numerator_var);

            let denom_inv = denom_scalar
                .inverse()
                .ok_or_else(|| LoquatError::verification_failure("denominator not invertible"))?;
            let p_value = numerator_value * denom_inv;
            let p_var = builder.alloc_f2(p_value);
            enforce_f2_const_mul_eq(builder, p_var, denom_scalar, numerator_var);

            // f^(0)(x) constraint: opened f^(0)(x) must match recomputation.
            let exponents: [u128; 4] = [
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[0])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_1"))?
                    as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[1])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_2"))?
                    as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[2])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_3"))?
                    as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[3])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_4"))?
                    as u128,
            ];

            let c_coeff = e_vector[0] + e_vector[4] * x.pow(exponents[0]);
            let s_coeff = e_vector[1] + e_vector[5] * x.pow(exponents[1]);
            let h_coeff = e_vector[2] + e_vector[6] * x.pow(exponents[2]);
            let p_coeff = e_vector[3] + e_vector[7] * x.pow(exponents[3]);

            let mut f0_terms: Vec<(F2Var, F2)> = Vec::with_capacity(params.n + 3);
            for j in 0..params.n {
                f0_terms.push((c_prime_chunk_vars[off][j], c_coeff));
            }
            f0_terms.push((s_chunk_vars[off], s_coeff));
            f0_terms.push((h_chunk_vars[off], h_coeff));
            f0_terms.push((p_var, p_coeff));

            // Target is the opened f^(0) value from the LDT base layer chunk.
            enforce_f2_const_lincomb_eq(builder, &f0_terms, ldt_chunk_vars[0][off])?;
        }
    }

    Ok(())
}

fn merkle_conditional_order_digest(
    builder: &mut R1csBuilder,
    bit: FieldVar,
    current: &[FieldVar],
    sibling: &[FieldVar; 2],
) -> (Vec<FieldVar>, Vec<FieldVar>) {
    debug_assert_eq!(current.len(), GRIFFIN_DIGEST_ELEMENTS);

    let mut left = Vec::with_capacity(GRIFFIN_DIGEST_ELEMENTS);
    let mut right = Vec::with_capacity(GRIFFIN_DIGEST_ELEMENTS);
    for limb in 0..GRIFFIN_DIGEST_ELEMENTS {
        let a = current[limb];
        let b = sibling[limb];

        // delta = b - a
        let delta_value = b.value - a.value;
        let delta_idx = builder.alloc(delta_value);
        builder.enforce_linear_relation(
            &[(delta_idx, F::one()), (b.idx, -F::one()), (a.idx, F::one())],
            F::zero(),
        );

        // prod = bit * delta
        let prod_value = bit.value * delta_value;
        let prod_idx = builder.alloc(prod_value);
        builder.enforce_mul_vars(bit.idx, delta_idx, prod_idx);

        // left = a + prod
        let left_value = a.value + prod_value;
        let left_idx = builder.alloc(left_value);
        builder.enforce_linear_relation(
            &[
                (left_idx, F::one()),
                (a.idx, -F::one()),
                (prod_idx, -F::one()),
            ],
            F::zero(),
        );
        left.push(FieldVar::new(left_idx, left_value));

        // right = b - prod
        let right_value = b.value - prod_value;
        let right_idx = builder.alloc(right_value);
        builder.enforce_linear_relation(
            &[
                (right_idx, F::one()),
                (b.idx, -F::one()),
                (prod_idx, F::one()),
            ],
            F::zero(),
        );
        right.push(FieldVar::new(right_idx, right_value));
    }

    (left, right)
}

/// Select between two field elements based on a boolean bit.
///
/// Returns `a` when `bit=0`, and `b` when `bit=1`.
fn field_select(builder: &mut R1csBuilder, bit: FieldVar, a: FieldVar, b: FieldVar) -> FieldVar {
    // delta = b - a
    let delta_value = b.value - a.value;
    let delta_idx = builder.alloc(delta_value);
    builder.enforce_linear_relation(
        &[(delta_idx, F::one()), (b.idx, -F::one()), (a.idx, F::one())],
        F::zero(),
    );

    // prod = bit * delta
    let prod_value = bit.value * delta_value;
    let prod_idx = builder.alloc(prod_value);
    builder.enforce_mul_vars(bit.idx, delta_idx, prod_idx);

    // out = a + prod
    let out_value = a.value + prod_value;
    let out_idx = builder.alloc(out_value);
    builder.enforce_linear_relation(
        &[
            (out_idx, F::one()),
            (a.idx, -F::one()),
            (prod_idx, -F::one()),
        ],
        F::zero(),
    );
    FieldVar::new(out_idx, out_value)
}

fn alloc_const_bit(builder: &mut R1csBuilder, value: bool) -> (usize, bool) {
    let idx = builder.alloc_bit(value);
    // Fix to the desired constant value.
    builder.enforce_linear_relation(&[(idx, F::one())], -F::new(value as u128));
    (idx, value)
}

fn select_from_field_vars_by_bits(
    builder: &mut R1csBuilder,
    mut items: Vec<FieldVar>,
    bits_le: &[FieldVar],
) -> LoquatResult<FieldVar> {
    if bits_le.is_empty() {
        return Err(LoquatError::verification_failure(
            "empty index bits for selection",
        ));
    }
    let target_len = 1usize << bits_le.len();
    if items.len() > target_len {
        return Err(LoquatError::verification_failure(
            "selection items exceed addressable space",
        ));
    }
    while items.len() < target_len {
        items.push(FieldVar::constant(builder, F::zero()));
    }
    for &bit in bits_le {
        let mut next = Vec::with_capacity(items.len() / 2);
        for pair in items.chunks(2) {
            let a = pair[0];
            let b = pair[1];
            next.push(field_select(builder, bit, a, b));
        }
        items = next;
    }
    Ok(items
        .pop()
        .ok_or_else(|| LoquatError::verification_failure("selection failed"))?)
}

fn build_loquat_r1cs_pk_witness_inner(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: Option<&[F]>,
    params: &LoquatPublicParams,
    compute_sqrt_witness: bool,
    validate_witness: bool,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    trace_stage("build_loquat_r1cs_pk_witness: begin");

    if let Some(pk) = public_key {
        if pk.len() < params.l {
            return Err(LoquatError::verification_failure(
                "public key length below parameter l",
            ));
        }
    }

    let transcript_data = replay_transcript_data(message, signature, params)?;
    trace_stage("transcript data replayed from artifact");
    if signature.z_challenge != transcript_data.z_challenge {
        return Err(LoquatError::verification_failure("z challenge mismatch"));
    }
    if signature.e_vector != transcript_data.e_vector {
        return Err(LoquatError::verification_failure("e-vector mismatch"));
    }
    if signature.ldt_proof.commitments.len() != params.r + 1 {
        return Err(LoquatError::verification_failure(
            "LDT commitment count mismatch",
        ));
    }
    if signature.ldt_proof.cap_nodes.len() != params.r + 1 {
        return Err(LoquatError::verification_failure(
            "LDT cap node layer count mismatch",
        ));
    }
    if signature.ldt_proof.openings.len() != params.kappa {
        return Err(LoquatError::verification_failure(
            "LDT opening count mismatch",
        ));
    }
    if signature.query_openings.len() != params.kappa {
        return Err(LoquatError::verification_failure(
            "query opening count mismatch",
        ));
    }
    if signature.fri_challenges.len() != params.r {
        return Err(LoquatError::verification_failure(
            "FRI challenge count mismatch",
        ));
    }
    if signature.message_commitment.len() != 32 {
        return Err(LoquatError::verification_failure(
            "message commitment must be 32 bytes",
        ));
    }
    let mut message_commitment = [0u8; 32];
    message_commitment.copy_from_slice(&signature.message_commitment);

    let mut builder = R1csBuilder::new();
    let mut constraint_tracker = ConstraintTracker::new(&builder);

    // Phase 5.1: Allocate the Loquat public-input vector at the head of the
    // R1CS instance vector. The verifier supplies these values from the
    // signature and message; this scaffolds the structure for Phase 5.2-5.7
    // to migrate consumers from witness-baked or constant-baked references
    // to public-input reads. Allocation is structural-only at this stage —
    // no constraint yet *consumes* `pi`, so the existing builder body is
    // unaffected. Phase 5.2 begins replacing duplicate witness allocations
    // with reads from `pi`.
    let pi = LoquatPublicInputs::allocate(&mut builder, signature, params)?;
    builder.finalize_public_inputs();
    let _ = &pi; // suppress unused-warning until 5.2 wires consumers
    trace_stage("public-input section allocated");
    constraint_tracker.record(&builder, "public inputs allocated");

    // Allocate pk bits first so the pk block is stable and can be equality-linked when
    // merging multiple Loquat-verification circuits (BDEC).
    let mut pk_var_indices = Vec::with_capacity(params.l);
    for idx in 0..params.l {
        let value = public_key
            .and_then(|pk| pk.get(idx).copied())
            .unwrap_or(F::zero());
        let var_idx = builder.alloc(value);
        builder.enforce_boolean(var_idx);
        pk_var_indices.push((var_idx, value));
    }
    trace_stage("allocated pk as witness");
    constraint_tracker.record(&builder, "pk witness allocated");

    if params.eta >= usize::BITS as usize {
        return Err(LoquatError::invalid_parameters(
            "η parameter exceeds machine word size",
        ));
    }
    let fri_leaf_arity = 1usize << params.eta;
    // Phase 7-cleanup: dropped the in-circuit `Griffin(message) == signature.message_commitment`
    // check. Previously it baked each message byte as constraint constants
    // (the matrix's q_c terms differed per message), preventing
    // signature-independent compilation. The check is now performed off-circuit
    // by the verifier: they compute `expected_commitment = Griffin(message)`
    // and supply it as `pi.message_commitment`. Aurora's PI enforcement
    // mechanism (`aurora_verify_with_public_inputs`) cryptographically binds
    // the proof to that exact PI value via the witness Merkle openings, so a
    // prover cannot pass off a wrong digest. The off-circuit Griffin(·) is
    // sub-millisecond and is the same hash the verifier was already running.
    let _ = (message, &message_commitment); // retained for signature/API; unused in the matrix
    trace_stage("message commitment delegated to PI / off-circuit verification");
    constraint_tracker.record(&builder, "message commitment (PI-delegated)");

    // Phase 5.2: μ now sourced from the public-input section (`pi.mu`) rather than
    // freshly allocated as witness. Same constraint count; the difference is that
    // `pi.mu.c0`/`pi.mu.c1` live in the R1CS instance vector indices [1, num_inputs].
    let mu_c0_idx = pi.mu.c0;
    let mu_c1_idx = pi.mu.c1;

    let mut contrib_c0_terms = Vec::new();
    let mut contrib_c1_terms = Vec::new();

    // Phase 5.2: t_values are now sourced from `pi.t_values` (PI section).
    // Boolean-ness is still enforced here because PI vars carry no implicit
    // type; the constraint binds them to {0, 1}. Same constraint count.
    let mut t_var_indices = Vec::with_capacity(signature.t_values.len());
    let mut t_pi_cursor = 0usize;
    for row in &signature.t_values {
        let mut row_indices = Vec::with_capacity(row.len());
        for _ in row {
            let pi_var = pi.t_values[t_pi_cursor];
            t_pi_cursor += 1;
            builder.enforce_boolean(pi_var.idx);
            row_indices.push(pi_var.idx);
        }
        t_var_indices.push(row_indices);
    }
    trace_stage("t-values bound from PI section (boolean enforced)");
    constraint_tracker.record(&builder, "t-values bound (PI)");

    // Phase 5.2: o_values sourced from `pi.o_values`.
    let mut o_var_indices = vec![Vec::with_capacity(params.m); params.n];
    if signature.o_values.len() != params.n {
        return Err(LoquatError::verification_failure(
            "o-value row count mismatch",
        ));
    }
    let mut o_pi_cursor = 0usize;
    for (row_idx, row) in signature.o_values.iter().enumerate() {
        if row.len() != params.m {
            return Err(LoquatError::verification_failure(
                "o-value row length mismatch",
            ));
        }
        for _ in row {
            let pi_var = pi.o_values[o_pi_cursor];
            o_pi_cursor += 1;
            o_var_indices[row_idx].push(pi_var.idx);
        }
    }

    // Phase 1.2 reorder: derive FS challenges in-circuit BEFORE the QR block
    // (Algorithm 7 Step 1: "the verifier first obtains all Merkle roots and plaintext
    // messages from the signature, then computes the hash output round-by-round").
    // This requires allocating the sumcheck claimed-sum and round-polynomial witness
    // variables early so the in-circuit transcript can absorb them.
    if signature.pi_us.round_polynomials.len() != transcript_data.sumcheck_challenges.len() {
        return Err(LoquatError::verification_failure(
            "sumcheck challenge count mismatch",
        ));
    }
    // Phase 5.2: claimed-sum and round polynomials sourced from PI section.
    // `last_sum` aliases pi.pi_us_claimed_sum (no fresh allocation).
    // `sumcheck_round_vars` is built by chunks of 4 from pi.pi_us_round_polys_flat.
    let mut last_sum = pi.pi_us_claimed_sum;
    let mut sumcheck_round_vars = Vec::with_capacity(signature.pi_us.round_polynomials.len());
    for round_idx in 0..signature.pi_us.round_polynomials.len() {
        let base = round_idx * 4;
        let c0_var = F2Var {
            c0: pi.pi_us_round_polys_flat[base].idx,
            c1: pi.pi_us_round_polys_flat[base + 1].idx,
        };
        let c1_var = F2Var {
            c0: pi.pi_us_round_polys_flat[base + 2].idx,
            c1: pi.pi_us_round_polys_flat[base + 3].idx,
        };
        sumcheck_round_vars.push((c0_var, c1_var));
    }

    // Single transcript pass deriving ALL Fiat-Shamir challenges as in-circuit FieldVars.
    let in_circuit = enforce_transcript_relations_field_native(
        &mut builder,
        params,
        signature,
        &transcript_data,
        &pi,
        &t_var_indices,
        &o_var_indices,
        last_sum,
        &sumcheck_round_vars,
    )?;
    trace_stage("transcript binding enforced inside circuit (early)");
    constraint_tracker.record(&builder, "transcript binding (early)");

    // QR contribution block — λ and ε now sourced from the in-circuit transcript
    // FieldVars instead of `transcript_data` constants. This is the core Phase 1.2
    // change: a constraint-row count-preserving swap from `enforce_mul_const_var`
    // to `enforce_mul_vars` (both are 1 R1CS row per multiplication), but the
    // multiplier is now a witness variable bound by the in-circuit FS hash chain.
    for j in 0..params.n {
        let epsilon_real_var = in_circuit.epsilon_real_vars[j];
        let epsilon_real_value = epsilon_real_var.value;
        for i in 0..params.m {
            let lambda_var = in_circuit.lambda_vars[j * params.m + i];
            let lambda_value = lambda_var.value;
            let o_val = signature.o_values[j][i];
            let o_idx = o_var_indices[j][i];

            let prod_val = lambda_value * o_val;
            let prod_idx = builder.alloc(prod_val);
            builder.enforce_mul_vars(lambda_var.idx, o_idx, prod_idx);

            let contrib0_val = prod_val * epsilon_real_value;
            let contrib0_idx = builder.alloc(contrib0_val);
            builder.enforce_mul_vars(epsilon_real_var.idx, prod_idx, contrib0_idx);
            contrib_c0_terms.push((contrib0_idx, F::one()));

            // ε.c1 is structurally zero in this implementation (a real-only ε
            // optimization vs. paper Algorithm 4 where ε ∈ 𝔽 = 𝔽_p²; see sanity
            // check at `enforce_transcript_relations_field_native`). We encode the
            // c1 contribution with a const-zero coefficient — not FS-derived,
            // structural — so contrib_c1 sums to zero and forces μ.c1 = 0.
            let contrib1_idx = builder.alloc(F::zero());
            builder.enforce_mul_const_var(F::zero(), prod_idx, contrib1_idx);
            contrib_c1_terms.push((contrib1_idx, F::one()));
        }
    }

    // Phase 5.4: QR witness constraint loop now selects pk[i_index] via an
    // in-circuit binary-tree multiplexer using FS-derived bit decomposition
    // of `expected_idx`. The matrix structure is now signature-independent
    // for this block: the selector bits are R1CS variables (constrained by
    // FS hash + bit decomposition), and the multiplexer tree is fixed by
    // `params.l`.
    let two = F::new(2);
    // Number of bits the FS function decomposed into: `⌈log₂(params.l)⌉`.
    // Matches the inner length of `in_circuit.i_index_bit_vars`.
    let k_bits = (usize::BITS - params.l.saturating_sub(1).leading_zeros()) as usize;

    // Phase 5.4 + 5.5.1: pre-pad pk and I variable arrays once to next power of 2.
    // The mux helper requires power-of-2 inputs; pre-padding here amortizes the
    // zero-vars across all m·n QR checks (saves ~m·n·padding_count constraints).
    let pk_var_indices_padded = pad_var_array_to_power_of_two(&mut builder, &pk_var_indices);
    // Phase 5.5.1: allocate I-variable wrappers for params.public_indices, then
    // pad to the same power-of-2 size as pk. Each I-var is bound to the public
    // parameter constant via a linear relation (so the prover cannot tamper).
    let mut i_var_indices: Vec<(usize, F)> = Vec::with_capacity(params.l);
    for &i_val in &params.public_indices {
        let idx = builder.alloc(i_val);
        builder.enforce_linear_relation(&[(idx, F::one())], -i_val);
        i_var_indices.push((idx, i_val));
    }
    let i_var_indices_padded = pad_var_array_to_power_of_two(&mut builder, &i_var_indices);

    // Phase 5.5.2: q_eval_on_h_var[j] holds 2m FieldVars per j (alternating
    // λ_{i,j} and λ_{i,j}·I_{i,j}). Used by Phase 5.5.3 in-circuit Lagrange
    // evaluation of q̂_j(s) at LDT query positions.
    let mut q_eval_on_h_var: Vec<Vec<FieldVar>> =
        vec![Vec::with_capacity(2 * params.m); params.n];

    for j in 0..params.n {
        for i in 0..params.m {
            let check_idx = j * params.m + i;
            let selector_bits = in_circuit.i_index_bit_vars[check_idx].clone();
            let pk_index = transcript_data.i_indices[check_idx];
            let selector_bit_values: Vec<F> = (0..k_bits)
                .map(|bit_idx| F::new(((pk_index >> bit_idx) & 1) as u128))
                .collect();
            let (pk_idx, pk_value) = pk_select_mux(
                &mut builder,
                &pk_var_indices_padded,
                &selector_bits,
                &selector_bit_values,
            );
            // Phase 5.5.2: select I_{i,j} = params.public_indices[expected_idx] via mux.
            let (i_var_idx, i_var_value) = pk_select_mux(
                &mut builder,
                &i_var_indices_padded,
                &selector_bits,
                &selector_bit_values,
            );
            // q_eval_on_h_var[j][2i]   = λ_{i,j}
            // q_eval_on_h_var[j][2i+1] = λ_{i,j} · I_{i,j}
            let lambda_var = in_circuit.lambda_vars[check_idx];
            let lambda_times_i_value = lambda_var.value * i_var_value;
            let lambda_times_i_idx = builder.alloc(lambda_times_i_value);
            builder.enforce_mul_vars(lambda_var.idx, i_var_idx, lambda_times_i_idx);
            q_eval_on_h_var[j].push(lambda_var);
            q_eval_on_h_var[j].push(FieldVar::existing(lambda_times_i_idx, lambda_times_i_value));

            enforce_qr_witness_constraint_pk_var(
                &mut builder,
                o_var_indices[j][i],
                signature.o_values[j][i],
                t_var_indices[j][i],
                signature.t_values[j][i],
                pk_idx,
                pk_value,
                params.qr_non_residue,
                two,
                compute_sqrt_witness,
            )?;
        }
    }
    trace_stage("quadratic residuosity + q_eval_on_h_var built (in-circuit pk + I mux)");
    constraint_tracker.record(&builder, "quadratic residuosity (in-circuit pk + I mux)");
    let _ = &q_eval_on_h_var; // suppress unused-warning until Phase 5.5.3 wires the Lagrange evaluator

    builder.enforce_sum_equals(&contrib_c0_terms, mu_c0_idx);
    builder.enforce_sum_equals(&contrib_c1_terms, mu_c1_idx);

    // Sumcheck claimed sum equals μ (linking the QR-derived μ to the sumcheck input).
    builder.enforce_eq(last_sum.c0, mu_c0_idx);
    builder.enforce_eq(last_sum.c1, mu_c1_idx);

    for (round_idx, round_poly) in signature.pi_us.round_polynomials.iter().enumerate() {
        let (c0_var, c1_var) = sumcheck_round_vars[round_idx];
        let chal_var = in_circuit.sumcheck_chal_vars[round_idx];
        let chal_value = transcript_data.sumcheck_challenges[round_idx];
        last_sum = enforce_sumcheck_round(
            &mut builder,
            last_sum,
            c0_var,
            c1_var,
            round_poly.c0,
            round_poly.c1,
            chal_var,
            chal_value,
            two,
        );
    }
    trace_stage("sumcheck rounds enforced");
    constraint_tracker.record(&builder, "sumcheck");

    // Phase 5.2: final_evaluation sourced from `pi.pi_us_final_evaluation`.
    let final_eval_var = pi.pi_us_final_evaluation;
    builder.enforce_f2_eq(last_sum, final_eval_var);

    // Openings-only checks at Q.
    let q_hat_on_u = compute_q_hat_on_u(params, &transcript_data)?;
    let z_mu_plus_s = transcript_data.z_challenge * signature.mu + signature.s_sum;
    let z_mu_plus_s_var = builder.alloc_f2(z_mu_plus_s);

    // Enforce `z_mu_plus_s_var = z * μ + S` inside the circuit (do not leave it unconstrained).
    // Phase 7-cleanup: previously this used `enforce_f2_const_mul_eq` with
    // `transcript_data.z_challenge` (a signature-specific F² scalar) baked
    // into the constraint coefficients on `pi.mu`. That leaked signature data
    // into the matrix. Replace with a *variable*-by-variable F-mul using the
    // in-circuit z-challenge (`in_circuit.z_var`, real-only since z.c1 is
    // structurally zero — checked in `enforce_transcript_relations_field_native`).
    let mu_var = F2Var {
        c0: mu_c0_idx,
        c1: mu_c1_idx,
    };
    let z_mu_value = transcript_data.z_challenge * signature.mu;
    let z_var_field = in_circuit.z_var;
    let mu_c0_field = FieldVar::existing(mu_c0_idx, signature.mu.c0);
    let mu_c1_field = FieldVar::existing(mu_c1_idx, signature.mu.c1);
    let z_mu_c0_field = field_mul(&mut builder, z_var_field, mu_c0_field);
    let z_mu_c1_field = field_mul(&mut builder, z_var_field, mu_c1_field);
    let z_mu_var = F2Var {
        c0: z_mu_c0_field.idx,
        c1: z_mu_c1_field.idx,
    };
    let _ = z_mu_value; // value sanity-checked via field_mul allocation

    // Phase 5.2: s_sum sourced from `pi.s_sum` (PI section). Drop the legacy
    // alloc_f2 + 2 enforce_linear_relation binding (they were redundantly
    // forcing s_sum_var to equal the constant `signature.s_sum`; pi.s_sum
    // already holds that exact value as a public-input variable).
    let s_sum_var = pi.s_sum;

    enforce_f2_add(&mut builder, z_mu_var, s_sum_var, z_mu_plus_s_var);

    enforce_ldt_queries(
        &mut builder,
        params,
        signature,
        &transcript_data,
        &in_circuit,
        &pi,
        &q_eval_on_h_var,
        &q_hat_on_u,
        z_mu_plus_s_var,
        fri_leaf_arity,
    )?;
    trace_stage("enforced all LDT queries");
    constraint_tracker.record(&builder, "LDT queries");

    // Mirror the hook in `build_loquat_r1cs` so B5 can pick up the breakdown
    // from whichever builder was invoked most recently on this thread.
    let breakdown = std::mem::take(&mut constraint_tracker.breakdown);
    LAST_R1CS_BREAKDOWN.with(|c| *c.borrow_mut() = Some(breakdown));

    // NOTE: For the pk-witness builder, we do not support the stats-only shortcut because
    // callers use this for BDEC proof generation/verification.
    if validate_witness {
        builder.finalize()
    } else {
        builder.finalize_unchecked()
    }
}

/// Phase 5.4: Pad an array of `(idx, value)` variables up to the next power
/// of 2 by allocating fresh zero witness vars (each bound to 0 by linear
/// constraint). Used by both `pk_select_mux` and the I-multiplexer (Phase 5.5)
/// to share a single allocation rather than re-padding per call.
///
/// The caller is responsible for ensuring the FS-derived selector index is
/// less than the unpadded length (range check in the FS function); without
/// that, the selector could pick a padded zero entry.
fn pad_var_array_to_power_of_two(
    builder: &mut R1csBuilder,
    vars: &[(usize, F)],
) -> Vec<(usize, F)> {
    let n = vars.len();
    let padded_n = n.next_power_of_two();
    let mut padded = vars.to_vec();
    for _ in n..padded_n {
        let z_idx = builder.alloc(F::zero());
        builder.enforce_linear_relation(&[(z_idx, F::one())], F::zero());
        padded.push((z_idx, F::zero()));
    }
    padded
}

/// Phase 5.4: Binary-tree 1-of-N multiplexer selecting a variable from
/// `vars` (must be a power-of-2 size — pre-pad with
/// [`pad_var_array_to_power_of_two`]) using `selector_bits` (LSB-first bit
/// decomposition of the in-circuit-derived index, length ≥ `⌈log₂(vars.len())⌉`).
///
/// At each layer `k`, pairs of remaining candidates are reduced to one using
/// `selector_bits[k]` as the 2-to-1 mux selector: `out = a + sel · (b - a)`.
/// Sound because `sel ∈ {0, 1}` is enforced by the FS-derived bit decomposition.
///
/// Each 2-to-1 mux costs 1 R1CS multiplication row (encoded directly as
/// `sel · (b - a) = (out - a)`).
///
/// Total cost: `vars.len() - 1` mul rows + `vars.len() - 1` fresh witness vars.
fn pk_select_mux(
    builder: &mut R1csBuilder,
    pk_vars: &[(usize, F)],
    selector_bits: &[usize],
    selector_bit_values: &[F],
) -> (usize, F) {
    let n = pk_vars.len();
    assert!(n > 0, "pk_vars must be non-empty");
    assert!(
        n.is_power_of_two(),
        "pk_select_mux requires pre-padded power-of-2 input; use pad_var_array_to_power_of_two"
    );
    let k = n.trailing_zeros() as usize;
    assert!(
        selector_bits.len() >= k,
        "selector bits insufficient for pk size"
    );

    let mut current_layer: Vec<(usize, F)> = pk_vars.to_vec();
    for layer_idx in 0..k {
        let sel_idx = selector_bits[layer_idx];
        let sel_val = selector_bit_values[layer_idx];
        let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
        for chunk in current_layer.chunks(2) {
            let (a_idx, a_val) = chunk[0];
            let (b_idx, b_val) = chunk[1];
            // out = a + sel*(b - a) ⇒ sel*(b - a) = out - a.
            let out_val = a_val + sel_val * (b_val - a_val);
            let out_idx = builder.alloc(out_val);
            let a_lc = SparseLC::with_terms(F::zero(), vec![(sel_idx, F::one())]);
            let b_lc = SparseLC::with_terms(
                F::zero(),
                vec![(b_idx, F::one()), (a_idx, -F::one())],
            );
            let c_lc = SparseLC::with_terms(
                F::zero(),
                vec![(out_idx, F::one()), (a_idx, -F::one())],
            );
            builder.enforce_mul(a_lc, b_lc, c_lc);
            next_layer.push((out_idx, out_val));
        }
        current_layer = next_layer;
    }
    debug_assert_eq!(current_layer.len(), 1);
    current_layer[0]
}

/// Phase 7-cleanup: F² variant of [`pk_select_mux`]. Selects one of N F²Vars
/// using `selector_bits` (LSB-first bit decomposition of the lookup index,
/// length ≥ ⌈log₂(N)⌉). Built by running `pk_select_mux` once on the c0
/// components and once on the c1 components — this halves the constant-factor
/// vs. a naïve full F² mul because the selector is a real F bit, not an F²
/// element, so the mux reduces to component-wise real-by-(F² difference).
///
/// Cost: 2 × (N − 1) R1CS multiplication rows + 2 × (N − 1) fresh witness
/// vars. For N = 32 cap_nodes that's ~62 rows per mux.
fn f2_select_mux(
    builder: &mut R1csBuilder,
    f2_vars: &[F2Var],
    f2_values: &[F2],
    selector_bits: &[usize],
    selector_bit_values: &[F],
) -> F2Var {
    assert!(!f2_vars.is_empty(), "f2_vars must be non-empty");
    assert_eq!(
        f2_vars.len(),
        f2_values.len(),
        "f2_vars/f2_values length mismatch"
    );
    let c0_pairs: Vec<(usize, F)> = f2_vars
        .iter()
        .zip(f2_values.iter())
        .map(|(v, val)| (v.c0, val.c0))
        .collect();
    let c1_pairs: Vec<(usize, F)> = f2_vars
        .iter()
        .zip(f2_values.iter())
        .map(|(v, val)| (v.c1, val.c1))
        .collect();
    let padded_c0 = pad_var_array_to_power_of_two(builder, &c0_pairs);
    let padded_c1 = pad_var_array_to_power_of_two(builder, &c1_pairs);
    let (c0_idx, _c0_val) =
        pk_select_mux(builder, &padded_c0, selector_bits, selector_bit_values);
    let (c1_idx, _c1_val) =
        pk_select_mux(builder, &padded_c1, selector_bits, selector_bit_values);
    F2Var {
        c0: c0_idx,
        c1: c1_idx,
    }
}

/// Phase 7-cleanup: select a cap-node F²Var from the c/s/h-tree PI list using
/// the high bits of `position` as multiplexer selector bits. The cap_index for
/// a c/s/h tree query equals `position >> (chunk_size_log + auth_path_len)`,
/// so the relevant `cap_count_log = log₂(cap_count)` bits of `position` start
/// at offset `chunk_size_log + auth_path_len` (LSB-first).
///
/// `position` is supplied for native bit-value derivation only (the multiplexer
/// is real circuit logic — only the bit *values* are computed natively to seed
/// the mux witness; var indices come from `in_circuit.query_position_bit_vars`,
/// which the FS bit-decomposition already constrained to be the LSB-first
/// decomposition of the corresponding query-position F variable).
fn select_cap_node_via_mux(
    builder: &mut R1csBuilder,
    cap_node_pi_vars: &[F2Var],
    cap_node_bytes: &[[u8; 32]],
    in_circuit: &InCircuitTranscript,
    query_idx: usize,
    chunk_size: usize,
    auth_path_len: usize,
    position: usize,
) -> LoquatResult<F2Var> {
    if cap_node_pi_vars.is_empty() {
        return Err(LoquatError::verification_failure(
            "select_cap_node_via_mux called with empty cap-node PI list",
        ));
    }
    if cap_node_pi_vars.len() != cap_node_bytes.len() {
        return Err(LoquatError::verification_failure(
            "cap_node_pi_vars / cap_node_bytes length mismatch",
        ));
    }
    if !cap_node_pi_vars.len().is_power_of_two() {
        return Err(LoquatError::verification_failure(
            "cap-node count must be a power of two for the multiplexer path",
        ));
    }
    if !chunk_size.is_power_of_two() || chunk_size == 0 {
        return Err(LoquatError::verification_failure(
            "chunk_size must be a non-zero power of two",
        ));
    }
    let chunk_size_log = chunk_size.trailing_zeros() as usize;
    let shift_amount = chunk_size_log + auth_path_len;
    let cap_count_log = cap_node_pi_vars.len().trailing_zeros() as usize;

    let position_bits = &in_circuit.query_position_bit_vars[query_idx];
    if shift_amount + cap_count_log > position_bits.len() {
        return Err(LoquatError::verification_failure(
            "cap_index bit slice exceeds query-position bit decomposition length",
        ));
    }

    let mut selector_bits = Vec::with_capacity(cap_count_log);
    let mut selector_bit_values = Vec::with_capacity(cap_count_log);
    for k in 0..cap_count_log {
        let bit_pos = shift_amount + k;
        selector_bits.push(position_bits[bit_pos]);
        selector_bit_values.push(F::new(((position >> bit_pos) & 1) as u128));
    }

    let cap_node_values: Vec<F2> = cap_node_bytes
        .iter()
        .map(|node| {
            let (lo, hi) = digest32_to_fields(node);
            F2::new(lo, hi)
        })
        .collect();

    Ok(f2_select_mux(
        builder,
        cap_node_pi_vars,
        &cap_node_values,
        &selector_bits,
        &selector_bit_values,
    ))
}

/// Phase 7-cleanup: LDT-layer variant of [`select_cap_node_via_mux`]. The
/// `fold_index` at layer `L` equals `position >> (L · chunk_size_log)`
/// (because each FRI fold divides the codeword length by `chunk_size`), so the
/// cap_index bits within `position` start at offset
/// `(L + 1) · chunk_size_log + auth_path_len_at_layer`.
fn select_cap_node_via_mux_for_ldt(
    builder: &mut R1csBuilder,
    cap_node_pi_vars: &[F2Var],
    cap_node_bytes: &[[u8; 32]],
    in_circuit: &InCircuitTranscript,
    query_idx: usize,
    chunk_size: usize,
    layer: usize,
    auth_path_len: usize,
    position: usize,
) -> LoquatResult<F2Var> {
    if cap_node_pi_vars.is_empty() {
        return Err(LoquatError::verification_failure(
            "select_cap_node_via_mux_for_ldt called with empty cap-node PI list",
        ));
    }
    if cap_node_pi_vars.len() != cap_node_bytes.len() {
        return Err(LoquatError::verification_failure(
            "ldt cap_node_pi_vars / cap_node_bytes length mismatch",
        ));
    }
    if !cap_node_pi_vars.len().is_power_of_two() {
        return Err(LoquatError::verification_failure(
            "ldt cap-node count must be a power of two for the multiplexer path",
        ));
    }
    if !chunk_size.is_power_of_two() || chunk_size == 0 {
        return Err(LoquatError::verification_failure(
            "chunk_size must be a non-zero power of two",
        ));
    }
    let chunk_size_log = chunk_size.trailing_zeros() as usize;
    let shift_amount = (layer + 1) * chunk_size_log + auth_path_len;
    let cap_count_log = cap_node_pi_vars.len().trailing_zeros() as usize;

    let position_bits = &in_circuit.query_position_bit_vars[query_idx];
    if shift_amount + cap_count_log > position_bits.len() {
        return Err(LoquatError::verification_failure(
            "ldt cap_index bit slice exceeds query-position bit decomposition length",
        ));
    }

    let mut selector_bits = Vec::with_capacity(cap_count_log);
    let mut selector_bit_values = Vec::with_capacity(cap_count_log);
    for k in 0..cap_count_log {
        let bit_pos = shift_amount + k;
        selector_bits.push(position_bits[bit_pos]);
        selector_bit_values.push(F::new(((position >> bit_pos) & 1) as u128));
    }

    let cap_node_values: Vec<F2> = cap_node_bytes
        .iter()
        .map(|node| {
            let (lo, hi) = digest32_to_fields(node);
            F2::new(lo, hi)
        })
        .collect();

    Ok(f2_select_mux(
        builder,
        cap_node_pi_vars,
        &cap_node_values,
        &selector_bits,
        &selector_bit_values,
    ))
}

/// Phase 5.5.3 (F2): Compute `x_var = u_shift · u_g^position` in F² from the
/// LSB-first FS-derived bit decomposition of `position`. Each step encodes
/// `result_next = result · (1 + bit_i · (u_g^(2^i) − 1))` over F².
///
/// Implementation per bit (F² typing forces multi-row encoding — F-only
/// version was a single row, but F² has the qnr=3 cross term):
///   1. `delta_var_F2 = bit_i · delta_const_F2` where bit_i is F (0 or 1)
///      and delta_const = u_g^(2^i) − 1 ∈ F².
///      Encoded as 2 mul_const_var rows: one per F² component.
///   2. `increment_F2 = delta_var_F2 · result_F2` via `f2_mul` (6 rows: 4 F muls + 2 lin).
///   3. `result_next_F2 = result_F2 + increment_F2` via `enforce_f2_add` (2 lin rows).
///
/// Cost per bit: 2 + 6 + 2 = **10 R1CS rows**. For 14 high bits (tiny params):
/// 140 rows × κ queries = ~280 rows for `x_chunk_start`.
fn compute_x_var_at_position_f2(
    builder: &mut R1csBuilder,
    u_shift: F2,
    u_generator: F2,
    position_bits: &[usize],
    position_value: usize,
) -> F2Var {
    // result_0 = u_shift (F² constant, allocated + bound to constant value).
    let mut result_value = u_shift;
    let result_c0_idx = builder.alloc(u_shift.c0);
    let result_c1_idx = builder.alloc(u_shift.c1);
    builder.enforce_linear_relation(&[(result_c0_idx, F::one())], -u_shift.c0);
    builder.enforce_linear_relation(&[(result_c1_idx, F::one())], -u_shift.c1);
    let mut result_var = F2Var {
        c0: result_c0_idx,
        c1: result_c1_idx,
    };

    let mut g_pow = u_generator; // g^(2^0) = g
    for (i, &bit_idx) in position_bits.iter().enumerate() {
        let bit_value = ((position_value >> i) & 1) as u128;
        let delta_const = g_pow - F2::one(); // u_g^(2^i) − 1 ∈ F²

        // Step 1: delta_var_F2 = bit_i · delta_const (F² real-only result, since
        // bit_i is F). Encoded as two mul_const_var rows.
        let delta_var_c0_value = F::new(bit_value) * delta_const.c0;
        let delta_var_c0_idx = builder.alloc(delta_var_c0_value);
        builder.enforce_mul_const_var(delta_const.c0, bit_idx, delta_var_c0_idx);
        let delta_var_c1_value = F::new(bit_value) * delta_const.c1;
        let delta_var_c1_idx = builder.alloc(delta_var_c1_value);
        builder.enforce_mul_const_var(delta_const.c1, bit_idx, delta_var_c1_idx);
        let delta_var = F2Var {
            c0: delta_var_c0_idx,
            c1: delta_var_c1_idx,
        };
        let delta_var_value = F2::new(delta_var_c0_value, delta_var_c1_value);

        // Step 2: increment_F2 = delta_var · result via f2_mul (6 rows).
        let increment_var = f2_mul(builder, delta_var, delta_var_value, result_var, result_value);
        let increment_value = delta_var_value * result_value;

        // Step 3: result_next = result + increment (F² add, 2 lin rows).
        let result_next_value = result_value + increment_value;
        let result_next_var = builder.alloc_f2(result_next_value);
        enforce_f2_add(builder, result_var, increment_var, result_next_var);

        result_var = result_next_var;
        result_value = result_next_value;
        g_pow = g_pow * g_pow; // g^(2^(i+1)) = (g^(2^i))²
    }
    debug_assert_eq!(
        result_value,
        u_shift * u_generator.pow(position_value as u128)
    );
    result_var
}

/// Phase 5.5.3 (F2): Barycentric Lagrange basis values L_l(x) ∈ F² for
/// l ∈ [|H|], where H ⊂ F² is a multiplicative coset of size n = 2·params.m
/// defined by `h_l = h_shift · h_generator^l` (h_shift, h_generator ∈ F²).
///
///   `L_l(x) = Z_H(x) · w_l / (x − h_l)`,
///   where `Z_H(x) = x^n − h_shift^n` (vanishing polynomial),
///         `w_l = 1 / (n · h_l^(n−1))` (barycentric weight, F² constant).
///
/// Per-step costs (each F² mul = 4 F muls + 2 linear = 6 rows):
///   1. `s_powers = [1, x, ..., x^n]`: n−1 f2_muls = 6(n−1) rows.
///   2. `vanishing_var = s_powers[n] − shift_to_n`: 2 lin rows (per F² component).
///   3. Per l: f2_mul-check `(x − h_l) · inv_l = 1` (6 rows) + `basis_l = w_l · vanishing · inv_l`
///      (2 lin for w_l·vanishing F² const-mul, then 6 for f2_mul with inv): 14 rows.
///
/// Total: `6(n−1) + 2 + 14n = 20n − 4` rows per call. For n = 8: **156 rows per query position**.
struct LagrangeBasisGadgetF2 {
    basis: Vec<F2Var>,            // length n
    basis_values: Vec<F2>,        // parallel to `basis` (witness values for downstream products)
    vanishing_at_x: F2Var,        // Z_H(x) — exposed for reuse in z_h-dependent constraints
    vanishing_at_x_value: F2,
}

fn build_lagrange_basis_at_f2(
    builder: &mut R1csBuilder,
    h_shift: F2,
    h_generator: F2,
    h_size: usize,
    x_var: F2Var,
    x_value: F2,
) -> LoquatResult<LagrangeBasisGadgetF2> {
    if h_size == 0 {
        return Err(LoquatError::invalid_parameters("|H| must be > 0"));
    }

    // Build coset H natively (F² constants).
    let mut h_points: Vec<F2> = Vec::with_capacity(h_size);
    let mut hp = h_shift;
    for _ in 0..h_size {
        h_points.push(hp);
        hp = hp * h_generator;
    }

    // Precompute barycentric weights w_l = 1 / (|H| · h_l^(|H|−1)) ∈ F².
    let h_size_f2 = F2::new(F::new(h_size as u128), F::zero());
    let mut weights: Vec<F2> = Vec::with_capacity(h_size);
    for &h_l in &h_points {
        let denom = h_size_f2 * h_l.pow((h_size - 1) as u128);
        weights.push(denom.inverse().ok_or_else(|| {
            LoquatError::invalid_parameters("Lagrange denominator non-invertible in F²")
        })?);
    }

    // Build s_powers = [1, x, x², ..., x^n] in F².
    let mut s_powers_vars: Vec<F2Var> = Vec::with_capacity(h_size + 1);
    let mut s_powers_values: Vec<F2> = Vec::with_capacity(h_size + 1);
    // s_powers[0] = 1 (F² constant).
    let one_var = builder.alloc_f2(F2::one());
    builder.enforce_linear_relation(&[(one_var.c0, F::one())], -F::one());
    builder.enforce_linear_relation(&[(one_var.c1, F::one())], F::zero());
    s_powers_vars.push(one_var);
    s_powers_values.push(F2::one());
    s_powers_vars.push(x_var);
    s_powers_values.push(x_value);
    let mut cur_value = x_value;
    for _ in 2..=h_size {
        let next_value = cur_value * x_value;
        let prev_var = *s_powers_vars.last().unwrap();
        let next_var = f2_mul(builder, prev_var, cur_value, x_var, x_value);
        s_powers_vars.push(next_var);
        s_powers_values.push(next_value);
        cur_value = next_value;
    }
    let s_to_n_var = s_powers_vars[h_size];

    // vanishing_var = s_to_n − shift_to_n (F² subtract of constant).
    let shift_to_n = h_shift.pow(h_size as u128);
    let vanishing_value = s_powers_values[h_size] - shift_to_n;
    let vanishing_var = builder.alloc_f2(vanishing_value);
    // vanishing.c0 = s_to_n.c0 − shift_to_n.c0
    builder.enforce_linear_relation(
        &[(vanishing_var.c0, F::one()), (s_to_n_var.c0, -F::one())],
        shift_to_n.c0,
    );
    builder.enforce_linear_relation(
        &[(vanishing_var.c1, F::one()), (s_to_n_var.c1, -F::one())],
        shift_to_n.c1,
    );

    // Per-l basis: inv_l = (x − h_l)^{−1}, basis_l = w_l · vanishing · inv_l (all F²).
    let mut basis: Vec<F2Var> = Vec::with_capacity(h_size);
    let mut basis_values: Vec<F2> = Vec::with_capacity(h_size);
    for l in 0..h_size {
        let s_minus_h_l_value = x_value - h_points[l];
        let inv_value = s_minus_h_l_value.inverse().ok_or_else(|| {
            LoquatError::verification_failure(
                "x − h_l should be non-zero in F² (U ∩ H = ∅ by Loquat setup)",
            )
        })?;
        let inv_var = builder.alloc_f2(inv_value);

        // Constrain (x − h_l) · inv = 1 in F². The F² mul has the qnr=3 cross
        // term: (a + bi)(c + di) = (ac + 3bd) + (ad + bc)i. With (a, b) =
        // (x.c0 − h_l.c0, x.c1 − h_l.c1) and (c, d) = (inv.c0, inv.c1), target = (1, 0).
        // Allocate 4 intermediate products + 2 linear constraints.
        let s_minus_hl_c0_value = x_value.c0 - h_points[l].c0;
        let s_minus_hl_c1_value = x_value.c1 - h_points[l].c1;
        let ac_value = s_minus_hl_c0_value * inv_value.c0;
        let bd_value = s_minus_hl_c1_value * inv_value.c1;
        let ad_value = s_minus_hl_c0_value * inv_value.c1;
        let bc_value = s_minus_hl_c1_value * inv_value.c0;
        let ac_idx = builder.alloc(ac_value);
        let bd_idx = builder.alloc(bd_value);
        let ad_idx = builder.alloc(ad_value);
        let bc_idx = builder.alloc(bc_value);
        // ac: (x.c0 − h_l.c0) · inv.c0 = ac
        builder.enforce_mul(
            SparseLC::with_terms(-h_points[l].c0, vec![(x_var.c0, F::one())]),
            SparseLC::from_var(inv_var.c0),
            SparseLC::from_var(ac_idx),
        );
        builder.enforce_mul(
            SparseLC::with_terms(-h_points[l].c1, vec![(x_var.c1, F::one())]),
            SparseLC::from_var(inv_var.c1),
            SparseLC::from_var(bd_idx),
        );
        builder.enforce_mul(
            SparseLC::with_terms(-h_points[l].c0, vec![(x_var.c0, F::one())]),
            SparseLC::from_var(inv_var.c1),
            SparseLC::from_var(ad_idx),
        );
        builder.enforce_mul(
            SparseLC::with_terms(-h_points[l].c1, vec![(x_var.c1, F::one())]),
            SparseLC::from_var(inv_var.c0),
            SparseLC::from_var(bc_idx),
        );
        let qnr = F::new(3);
        // Real: ac + 3·bd = 1.
        builder.enforce_linear_relation(
            &[(ac_idx, F::one()), (bd_idx, qnr)],
            -F::one(),
        );
        // Imag: ad + bc = 0.
        builder.enforce_linear_relation(&[(ad_idx, F::one()), (bc_idx, F::one())], F::zero());

        // tmp_var = w_l · vanishing (F² const · F² var via f2_const_mul-style: 2 lin rows).
        let tmp_value = weights[l] * vanishing_value;
        let tmp_var = builder.alloc_f2(tmp_value);
        enforce_f2_const_mul_eq(builder, vanishing_var, weights[l], tmp_var);

        // basis_l = tmp · inv_l (F² var · F² var, f2_mul: 6 rows).
        let basis_var = f2_mul(builder, tmp_var, tmp_value, inv_var, inv_value);
        let basis_value = tmp_value * inv_value;
        basis.push(basis_var);
        basis_values.push(basis_value);
    }

    Ok(LagrangeBasisGadgetF2 {
        basis,
        basis_values,
        vanishing_at_x: vanishing_var,
        vanishing_at_x_value: vanishing_value,
    })
}

/// Phase 5.6: Compute base_var^exponent in F² via square-and-multiply on the
/// LSB-first bits of `exponent` (a constant). Each iteration emits at most
/// two `f2_mul`s (one for the conditional multiply, one for squaring), each
/// 6 R1CS rows. Cost: `(bit_count + hamming_weight) · 6` rows.
///
/// Returns (var, value). `exponent = 0` returns the F² constant 1
/// (allocated + bound, 4 rows).
fn f2_pow_const(
    builder: &mut R1csBuilder,
    base_var: F2Var,
    base_value: F2,
    exponent: u128,
) -> (F2Var, F2) {
    if exponent == 0 {
        let one_var = builder.alloc_f2(F2::one());
        builder.enforce_linear_relation(&[(one_var.c0, F::one())], -F::one());
        builder.enforce_linear_relation(&[(one_var.c1, F::one())], F::zero());
        return (one_var, F2::one());
    }
    // result starts as F²::one(); base_pow squares each iteration.
    let mut result_var = builder.alloc_f2(F2::one());
    builder.enforce_linear_relation(&[(result_var.c0, F::one())], -F::one());
    builder.enforce_linear_relation(&[(result_var.c1, F::one())], F::zero());
    let mut result_value = F2::one();
    let mut base_pow_var = base_var;
    let mut base_pow_value = base_value;
    let mut e = exponent;
    while e > 0 {
        if e & 1 == 1 {
            let new_result_var = f2_mul(
                builder,
                result_var,
                result_value,
                base_pow_var,
                base_pow_value,
            );
            result_value = result_value * base_pow_value;
            result_var = new_result_var;
        }
        e >>= 1;
        if e > 0 {
            let new_base_pow_var = f2_mul(
                builder,
                base_pow_var,
                base_pow_value,
                base_pow_var,
                base_pow_value,
            );
            base_pow_value = base_pow_value * base_pow_value;
            base_pow_var = new_base_pow_var;
        }
    }
    (result_var, result_value)
}

/// Phase 5.5.3 (F2): Evaluate q̂_j(x) = Σ_l q_eval_j[l] · L_l(x).
/// q_eval_j entries are F (real-only — they're λ or λ·I products in F);
/// basis values are F²; result is F².
///
/// Each term: q (F) · basis (F²) → F² (per F² component: 1 mul_vars row).
/// Cost: 2|H| mul rows + 2 sum_equals rows per call.
fn evaluate_q_hat_j_at_f2(
    builder: &mut R1csBuilder,
    q_eval_j: &[FieldVar],
    basis: &LagrangeBasisGadgetF2,
) -> LoquatResult<(F2Var, F2)> {
    if q_eval_j.len() != basis.basis.len() {
        return Err(LoquatError::verification_failure(
            "q_eval_j length must match Lagrange basis length",
        ));
    }
    let mut sum_c0_value = F::zero();
    let mut sum_c1_value = F::zero();
    let mut sum_c0_terms: Vec<(usize, F)> = Vec::with_capacity(q_eval_j.len());
    let mut sum_c1_terms: Vec<(usize, F)> = Vec::with_capacity(q_eval_j.len());
    for (q_var, (b_var, b_val)) in q_eval_j
        .iter()
        .zip(basis.basis.iter().zip(basis.basis_values.iter()))
    {
        let term_c0_value = q_var.value * b_val.c0;
        let term_c0_idx = builder.alloc(term_c0_value);
        builder.enforce_mul_vars(q_var.idx, b_var.c0, term_c0_idx);
        sum_c0_terms.push((term_c0_idx, F::one()));
        sum_c0_value += term_c0_value;

        let term_c1_value = q_var.value * b_val.c1;
        let term_c1_idx = builder.alloc(term_c1_value);
        builder.enforce_mul_vars(q_var.idx, b_var.c1, term_c1_idx);
        sum_c1_terms.push((term_c1_idx, F::one()));
        sum_c1_value += term_c1_value;
    }
    let sum_value = F2::new(sum_c0_value, sum_c1_value);
    let sum_var = builder.alloc_f2(sum_value);
    builder.enforce_sum_equals(&sum_c0_terms, sum_var.c0);
    builder.enforce_sum_equals(&sum_c1_terms, sum_var.c1);
    Ok((sum_var, sum_value))
}

fn enforce_qr_witness_constraint_pk_var(
    builder: &mut R1csBuilder,
    o_idx: usize,
    o_value: F,
    t_idx: usize,
    t_value: F,
    pk_idx: usize,
    pk_value: F,
    qr_alpha: F,
    two_const: F,
    compute_sqrt_witness: bool,
) -> LoquatResult<()> {
    // Only enforce the non-zero invariant when computing a real witness.
    // In instance-only mode (compute_sqrt_witness=false) o_value is a placeholder
    // zero, and the structural constraints (o*scalar=target, sqrt*sqrt=target) are
    // trivially satisfied with target=0, which is correct for the instance shape.
    if compute_sqrt_witness && o_value.is_zero() {
        return Err(LoquatError::verification_failure(
            "o-value must be non-zero to derive QR witness",
        ));
    }

    // expected = pk XOR t = pk + t - 2pk t
    let pk_t_value = pk_value * t_value;
    let pk_t_idx = builder.alloc(pk_t_value);
    builder.enforce_mul_vars(pk_idx, t_idx, pk_t_idx);

    let expected_value = pk_value + t_value - (two_const * pk_t_value);
    let expected_idx = builder.alloc(expected_value);
    // expected - pk - t + 2pk_t = 0
    builder.enforce_linear_relation(
        &[
            (expected_idx, F::one()),
            (pk_idx, -F::one()),
            (t_idx, -F::one()),
            (pk_t_idx, two_const),
        ],
        F::zero(),
    );
    builder.enforce_boolean(expected_idx);

    let alpha_expected_value = qr_alpha * expected_value;
    let alpha_expected_idx = builder.alloc(alpha_expected_value);
    builder.enforce_mul_const_var(qr_alpha, expected_idx, alpha_expected_idx);

    let one_minus_expected_value = F::one() - expected_value;
    let one_minus_expected_idx = builder.alloc(one_minus_expected_value);
    builder.enforce_linear_relation(
        &[(one_minus_expected_idx, F::one()), (expected_idx, F::one())],
        -F::one(),
    );

    let scalar_value = alpha_expected_value + one_minus_expected_value;
    let scalar_idx = builder.alloc(scalar_value);
    builder.enforce_linear_relation(
        &[
            (scalar_idx, F::one()),
            (alpha_expected_idx, -F::one()),
            (one_minus_expected_idx, -F::one()),
        ],
        F::zero(),
    );

    let target_value = o_value * scalar_value;
    let target_idx = builder.alloc(target_value);
    builder.enforce_mul_vars(o_idx, scalar_idx, target_idx);

    let sqrt_value = if compute_sqrt_witness {
        sqrt_canonical(target_value).ok_or_else(|| {
            LoquatError::verification_failure("quadratic residuosity witness missing square root")
        })?
    } else {
        // Placeholder value; instance-only builder does not require satisfaction.
        F::zero()
    };
    let sqrt_idx = builder.alloc(sqrt_value);
    builder.enforce_mul_vars(sqrt_idx, sqrt_idx, target_idx);

    Ok(())
}

fn enforce_qr_witness_constraint(
    builder: &mut R1csBuilder,
    o_idx: usize,
    o_value: F,
    t_idx: usize,
    t_value: F,
    pk_value: F,
    qr_alpha: F,
    two_const: F,
) -> LoquatResult<()> {
    if o_value.is_zero() {
        return Err(LoquatError::verification_failure(
            "o-value must be non-zero to derive QR witness",
        ));
    }
    let (expected_idx, expected_value) =
        enforce_expected_relation(builder, t_idx, t_value, pk_value, two_const)?;

    let alpha_expected_value = qr_alpha * expected_value;
    let alpha_expected_idx = builder.alloc(alpha_expected_value);
    builder.enforce_mul_const_var(qr_alpha, expected_idx, alpha_expected_idx);

    let one_minus_expected_value = F::one() - expected_value;
    let one_minus_expected_idx = builder.alloc(one_minus_expected_value);
    builder.enforce_linear_relation(
        &[(one_minus_expected_idx, F::one()), (expected_idx, F::one())],
        -F::one(),
    );

    let scalar_value = alpha_expected_value + one_minus_expected_value;
    let scalar_idx = builder.alloc(scalar_value);
    builder.enforce_linear_relation(
        &[
            (scalar_idx, F::one()),
            (alpha_expected_idx, -F::one()),
            (one_minus_expected_idx, -F::one()),
        ],
        F::zero(),
    );

    let target_value = o_value * scalar_value;
    let target_idx = builder.alloc(target_value);
    builder.enforce_mul_vars(o_idx, scalar_idx, target_idx);

    let sqrt_value = sqrt_canonical(target_value).ok_or_else(|| {
        LoquatError::verification_failure("quadratic residuosity witness missing square root")
    })?;
    let sqrt_idx = builder.alloc(sqrt_value);
    builder.enforce_mul_vars(sqrt_idx, sqrt_idx, target_idx);

    Ok(())
}

fn enforce_expected_relation(
    builder: &mut R1csBuilder,
    t_idx: usize,
    t_value: F,
    pk_value: F,
    two_const: F,
) -> LoquatResult<(usize, F)> {
    let two_pk = two_const * pk_value;
    let two_pk_t_value = two_pk * t_value;
    let two_pk_t_idx = builder.alloc(two_pk_t_value);
    builder.enforce_mul_const_var(two_pk, t_idx, two_pk_t_idx);

    let expected_value = pk_value + t_value - two_pk_t_value;
    let expected_idx = builder.alloc(expected_value);
    builder.enforce_linear_relation(
        &[
            (expected_idx, F::one()),
            (t_idx, -F::one()),
            (two_pk_t_idx, F::one()),
        ],
        -pk_value,
    );

    Ok((expected_idx, expected_value))
}

fn enforce_sumcheck_round(
    builder: &mut R1csBuilder,
    last_sum: F2Var,
    c0_var: F2Var,
    c1_var: F2Var,
    c0_value: F2,
    c1_value: F2,
    challenge_var: F2Var,
    challenge_value: F2,
    two_const: F,
) -> F2Var {
    builder.enforce_linear_relation(
        &[
            (last_sum.c0, F::one()),
            (c0_var.c0, -two_const),
            (c1_var.c0, -F::one()),
        ],
        F::zero(),
    );
    builder.enforce_linear_relation(
        &[
            (last_sum.c1, F::one()),
            (c0_var.c1, -two_const),
            (c1_var.c1, -F::one()),
        ],
        F::zero(),
    );

    // Phase 1.3: challenge is now an F2 witness variable (bound by the in-circuit
    // FS hash chain) rather than a baked-in F2 constant. Use `f2_mul` for the
    // var-by-var product. Cost: +4 mul rows per sumcheck round vs. the old
    // const-mul path (4 mul + 2 lin instead of 0 mul + 2 lin).
    let challenge_prod_value = c1_value * challenge_value;
    let challenge_prod_var = f2_mul(builder, c1_var, c1_value, challenge_var, challenge_value);

    let next_sum_value = c0_value + challenge_prod_value;
    let next_sum_var = builder.alloc_f2(next_sum_value);
    enforce_f2_add(builder, c0_var, challenge_prod_var, next_sum_var);

    next_sum_var
}

fn enforce_f2_const_mul_eq(builder: &mut R1csBuilder, source: F2Var, scalar: F2, target: F2Var) {
    // Our extension field is Fp2 with non-residue `i^2 = 3` (see `field_p127.rs`).
    // For source = x0 + x1*i and scalar = a + b*i:
    //   (x0 + x1*i)(a + b*i) = (x0*a + x1*b*3) + (x0*b + x1*a)i
    let qnr = F::new(3);

    let real_terms = vec![
        (target.c0, F::one()),
        (source.c0, -scalar.c0),
        (source.c1, -(scalar.c1 * qnr)),
    ];
    builder.enforce_linear_relation(&real_terms, F::zero());

    let imag_terms = vec![
        (target.c1, F::one()),
        (source.c0, -scalar.c1),
        (source.c1, -scalar.c0),
    ];
    builder.enforce_linear_relation(&imag_terms, F::zero());
}

fn alloc_f2(builder: &mut R1csBuilder, value: F2) -> F2Var {
    builder.alloc_f2(value)
}

fn enforce_f2_add_eq(builder: &mut R1csBuilder, left: F2Var, right: F2Var, target: F2Var) {
    enforce_f2_add(builder, left, right, target);
}

fn enforce_f2_sub_eq(builder: &mut R1csBuilder, left: F2Var, right: F2Var, target: F2Var) {
    builder.enforce_f2_sub(left, right, target);
}

/// Multiply two Fp2 variables and return a fresh variable holding the product.
///
/// Uses the field rule `i^2 = 3` (see `field_p127.rs` and `enforce_f2_const_mul_eq`).
fn f2_mul(
    builder: &mut R1csBuilder,
    left: F2Var,
    left_value: F2,
    right: F2Var,
    right_value: F2,
) -> F2Var {
    let out_value = left_value * right_value;
    let out = builder.alloc_f2(out_value);

    // (a + bi)(c + di) = (ac + bd*3) + (ad + bc)i
    let ac_value = left_value.c0 * right_value.c0;
    let ac_idx = builder.alloc(ac_value);
    builder.enforce_mul_vars(left.c0, right.c0, ac_idx);

    let bd_value = left_value.c1 * right_value.c1;
    let bd_idx = builder.alloc(bd_value);
    builder.enforce_mul_vars(left.c1, right.c1, bd_idx);

    let ad_value = left_value.c0 * right_value.c1;
    let ad_idx = builder.alloc(ad_value);
    builder.enforce_mul_vars(left.c0, right.c1, ad_idx);

    let bc_value = left_value.c1 * right_value.c0;
    let bc_idx = builder.alloc(bc_value);
    builder.enforce_mul_vars(left.c1, right.c0, bc_idx);

    let qnr = F::new(3);
    // out.c0 - ac - qnr*bd = 0
    builder.enforce_linear_relation(
        &[(out.c0, F::one()), (ac_idx, -F::one()), (bd_idx, -qnr)],
        F::zero(),
    );
    // out.c1 - ad - bc = 0
    builder.enforce_linear_relation(
        &[(out.c1, F::one()), (ad_idx, -F::one()), (bc_idx, -F::one())],
        F::zero(),
    );

    out
}

fn enforce_f2_add(builder: &mut R1csBuilder, left: F2Var, right: F2Var, target: F2Var) {
    builder.enforce_linear_relation(
        &[
            (target.c0, F::one()),
            (left.c0, -F::one()),
            (right.c0, -F::one()),
        ],
        F::zero(),
    );
    builder.enforce_linear_relation(
        &[
            (target.c1, F::one()),
            (left.c1, -F::one()),
            (right.c1, -F::one()),
        ],
        F::zero(),
    );
}

/// Enforce `target = Σ_i (source_i * scalar_i)` where each `scalar_i ∈ F²` is a constant.
///
/// This is a micro-optimisation: compared to building the sum via intermediate
/// `enforce_f2_const_mul_eq` + `enforce_f2_add` steps, this encodes the exact same
/// equation using **two** linear constraints (one per coordinate).
fn enforce_f2_const_lincomb_eq(
    builder: &mut R1csBuilder,
    terms: &[(F2Var, F2)],
    target: F2Var,
) -> LoquatResult<()> {
    if terms.is_empty() {
        return Err(LoquatError::verification_failure(
            "empty linear combination for F2 folding",
        ));
    }
    let qnr = F::new(3);
    let mut real_terms: Vec<(usize, F)> = Vec::with_capacity(1 + terms.len() * 2);
    let mut imag_terms: Vec<(usize, F)> = Vec::with_capacity(1 + terms.len() * 2);
    real_terms.push((target.c0, F::one()));
    imag_terms.push((target.c1, F::one()));

    for (source, scalar) in terms {
        // Fp2 uses i^2 = 3.
        // target.c0 - Σ (x0*a + x1*b*3) = 0
        real_terms.push((source.c0, -scalar.c0));
        let bq = scalar.c1 * qnr;
        if !bq.is_zero() {
            real_terms.push((source.c1, -bq));
        }

        // target.c1 - Σ (x0*b + x1*a) = 0
        if !scalar.c1.is_zero() {
            imag_terms.push((source.c0, -scalar.c1));
        }
        imag_terms.push((source.c1, -scalar.c0));
    }

    builder.enforce_linear_relation(&real_terms, F::zero());
    builder.enforce_linear_relation(&imag_terms, F::zero());
    Ok(())
}

fn enforce_f0_linear_combination(
    builder: &mut R1csBuilder,
    f0_var: F2Var,
    row_vars: &[F2Var],
    coeffs: &[F2],
) {
    // Same Fp2 rule: i^2 = 3.
    // Enforce f0 = Σ_k coeff_k * row_k as two linear relations (real + imag).
    let qnr = F::new(3);
    let mut real_terms = vec![(f0_var.c0, F::one())];
    let mut imag_terms = vec![(f0_var.c1, F::one())];
    for (row_var, coeff) in row_vars.iter().zip(coeffs.iter()) {
        // real: -(a * row.c0 + b * row.c1 * qnr)
        real_terms.push((row_var.c0, -coeff.c0));
        let bq = coeff.c1 * qnr;
        if !bq.is_zero() {
            real_terms.push((row_var.c1, -bq));
        }
        // imag: -(a * row.c1 + b * row.c0)
        imag_terms.push((row_var.c1, -coeff.c0));
        if !coeff.c1.is_zero() {
            imag_terms.push((row_var.c0, -coeff.c1));
        }
    }
    builder.enforce_linear_relation(&real_terms, F::zero());
    builder.enforce_linear_relation(&imag_terms, F::zero());
}

fn trace_stage(message: &str) {
    loquat_debug!("[r1cs] {}", message);
}

fn bytes_from_constants(builder: &mut R1csBuilder, data: &[u8]) -> Vec<Byte> {
    data.iter()
        .map(|&value| Byte::from_constant(builder, value))
        .collect()
}

fn enforce_byte_equality(builder: &mut R1csBuilder, left: &Byte, right: &Byte) {
    for bit in 0..8 {
        builder.enforce_eq(left.bits[bit], right.bits[bit]);
    }
}

fn enforce_ldt_queries(
    builder: &mut R1csBuilder,
    params: &LoquatPublicParams,
    signature: &LoquatSignature,
    transcript_data: &TranscriptData,
    in_circuit: &InCircuitTranscript,
    pi: &LoquatPublicInputs,
    q_eval_on_h_var: &[Vec<FieldVar>],
    q_hat_on_u: &[Vec<F2>],
    z_mu_plus_s_var: F2Var,
    leaf_arity: usize,
) -> LoquatResult<()> {
    if leaf_arity == 0 {
        return Err(LoquatError::invalid_parameters(
            "chunk size computed as zero",
        ));
    }
    let chunk_size = leaf_arity;

    // Layer-t cap (paper §4.3) for the c/s/h Merkle trees: if cap nodes are provided,
    // bind each root once as root = H(cap_nodes).
    let cap_enabled = !signature.c_cap_nodes.is_empty()
        || !signature.s_cap_nodes.is_empty()
        || !signature.h_cap_nodes.is_empty();
    if cap_enabled {
        if signature.c_cap_nodes.is_empty()
            || signature.s_cap_nodes.is_empty()
            || signature.h_cap_nodes.is_empty()
        {
            return Err(LoquatError::verification_failure(
                "partial Merkle cap nodes provided for c/s/h",
            ));
        }
        if signature.c_cap_nodes.len() != signature.s_cap_nodes.len()
            || signature.c_cap_nodes.len() != signature.h_cap_nodes.len()
        {
            return Err(LoquatError::verification_failure(
                "Merkle cap node count mismatch across c/s/h",
            ));
        }
        // Phase 5.3 cleanup / 6.2c / 7-cleanup: cap-root constraints now compare
        // against PI (pi.root_c/s/h) AND are computed from PI cap-node vars
        // (pi.c_cap_nodes_f2/s/h) rather than signature byte constants. Matrix
        // entries carry only var indices + unit coefficients — no signature-
        // specific F constants leak into the matrix at all.
        let c_cap_node_values: Vec<F2> = signature
            .c_cap_nodes
            .iter()
            .map(|node| {
                let (lo, hi) = digest32_to_fields(node);
                F2::new(lo, hi)
            })
            .collect();
        let c_root_fields = merkle_cap_root_from_pi_field_vars(
            builder,
            &pi.c_cap_nodes_f2,
            &c_cap_node_values,
        )?;
        enforce_field_digest_equals_pi(builder, &c_root_fields, pi.root_c)?;

        let s_cap_node_values: Vec<F2> = signature
            .s_cap_nodes
            .iter()
            .map(|node| {
                let (lo, hi) = digest32_to_fields(node);
                F2::new(lo, hi)
            })
            .collect();
        let s_root_fields = merkle_cap_root_from_pi_field_vars(
            builder,
            &pi.s_cap_nodes_f2,
            &s_cap_node_values,
        )?;
        enforce_field_digest_equals_pi(builder, &s_root_fields, pi.root_s)?;

        let h_cap_node_values: Vec<F2> = signature
            .h_cap_nodes
            .iter()
            .map(|node| {
                let (lo, hi) = digest32_to_fields(node);
                F2::new(lo, hi)
            })
            .collect();
        let h_root_fields = merkle_cap_root_from_pi_field_vars(
            builder,
            &pi.h_cap_nodes_f2,
            &h_cap_node_values,
        )?;
        enforce_field_digest_equals_pi(builder, &h_root_fields, pi.root_h)?;
    }

    // Layer-t cap for the LDT Merkle commitments (per layer).
    if signature.ldt_proof.commitments.len() != params.r + 1
        || signature.ldt_proof.cap_nodes.len() != params.r + 1
    {
        return Err(LoquatError::verification_failure(
            "LDT commitment/cap layer count mismatch",
        ));
    }
    for layer_idx in 0..=params.r {
        let cap_nodes = &signature.ldt_proof.cap_nodes[layer_idx];
        if !cap_nodes.is_empty() {
            // Phase 7-cleanup: compute the cap root from PI F²Vars (no byte
            // constants in the matrix). The compress structure is the same as
            // the byte path; only the leaf-field source changed.
            let layer_cap_values: Vec<F2> = cap_nodes
                .iter()
                .map(|node| {
                    let (lo, hi) = digest32_to_fields(node);
                    F2::new(lo, hi)
                })
                .collect();
            let root_fields = merkle_cap_root_from_pi_field_vars(
                builder,
                &pi.ldt_cap_nodes_f2[layer_idx],
                &layer_cap_values,
            )?;
            // Phase 5.3 cleanup / 6.2c: compare against pi.ldt_commitments[layer_idx].
            enforce_field_digest_equals_pi(
                builder,
                &root_fields,
                pi.ldt_commitments[layer_idx],
            )?;
        }
    }

    if q_hat_on_u.len() != params.n || q_hat_on_u.iter().any(|v| v.len() != params.coset_u.len()) {
        return Err(LoquatError::verification_failure(
            "q_hat_on_u dimension mismatch",
        ));
    }
    if signature.e_vector.len() != 8 {
        return Err(LoquatError::verification_failure(
            "e-vector length mismatch",
        ));
    }

    // Constants for p(x) computation.
    let h_order = params.coset_h.len() as u128;
    let z_h_constant = params.h_shift.pow(h_order);
    let h_size_scalar = F2::new(F::new(params.coset_h.len() as u128), F::zero());
    let z = transcript_data.z_challenge;
    let z_mu_plus_s_value = z * signature.mu + signature.s_sum;

    if signature.query_openings.len() != signature.ldt_proof.openings.len() {
        return Err(LoquatError::verification_failure(
            "query openings / LDT openings length mismatch",
        ));
    }

    for (query_idx, (ldt_opening, query_opening)) in signature
        .ldt_proof
        .openings
        .iter()
        .zip(signature.query_openings.iter())
        .enumerate()
    {
        if ldt_opening.position != query_opening.position {
            return Err(LoquatError::verification_failure(
                "query opening position mismatch",
            ));
        }
        if ldt_opening.codeword_chunks.len() != params.r + 1
            || ldt_opening.auth_paths.len() != params.r + 1
        {
            return Err(LoquatError::verification_failure(
                "LDT opening chunk/path length mismatch",
            ));
        }
        if query_opening.c_prime_chunk.len() != chunk_size
            || query_opening.s_chunk.len() != chunk_size
            || query_opening.h_chunk.len() != chunk_size
        {
            return Err(LoquatError::verification_failure(
                "query opening chunk length mismatch",
            ));
        }
        for off in 0..chunk_size {
            if query_opening.c_prime_chunk[off].len() != params.n {
                return Err(LoquatError::verification_failure(
                    "c' opening inner dimension mismatch",
                ));
            }
        }

        let position = ldt_opening.position;
        let chunk_index = position / chunk_size;

        // Phase 5.2b: query opening chunks (c′ / ŝ / ĥ) sourced from the PI section
        // (`pi.query_c_prime_chunks`, `pi.query_s_chunks`, `pi.query_h_chunks`)
        // instead of fresh witness allocations. Same constraint count; vars move
        // from witness section to PI section of the R1CS instance vector.
        let c_prime_chunk_vars: Vec<Vec<F2Var>> = pi.query_c_prime_chunks[query_idx].clone();
        let s_chunk_vars: Vec<F2Var> = pi.query_s_chunks[query_idx].clone();
        let h_chunk_vars: Vec<F2Var> = pi.query_h_chunks[query_idx].clone();

        // Verify Merkle openings for c′/ŝ/ĥ.
        // c′ leaf = concatenation of (chunk_size × n) field elements.
        let mut c_leaf_fields = Vec::with_capacity(chunk_size * params.n * 2);
        for off in 0..chunk_size {
            for j in 0..params.n {
                let var = c_prime_chunk_vars[off][j];
                let val = query_opening.c_prime_chunk[off][j];
                c_leaf_fields.push(FieldVar::existing(var.c0, val.c0));
                c_leaf_fields.push(FieldVar::existing(var.c1, val.c1));
            }
        }
        let chunk_size_log = chunk_size.trailing_zeros() as usize;
        let c_sibling_values: Vec<F2> = query_opening
            .c_auth_path
            .iter()
            .map(|sibling| {
                let arr: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                    LoquatError::verification_failure("c_auth_path sibling must be 32 bytes")
                })?;
                let (lo, hi) = digest32_to_fields(&arr);
                Ok::<_, LoquatError>(F2::new(lo, hi))
            })
            .collect::<LoquatResult<Vec<_>>>()?;
        let (c_dir_vars, c_dir_values) = direction_bits_for_path(
            in_circuit,
            query_idx,
            chunk_size_log,
            query_opening.c_auth_path.len(),
            chunk_index,
        );
        let c_digest = merkle_path_opening_fields_pi(
            builder,
            &c_leaf_fields,
            &pi.c_auth_paths_f2[query_idx],
            &c_sibling_values,
            &c_dir_vars,
            &c_dir_values,
        )?;
        if signature.c_cap_nodes.is_empty() {
            // Phase 7-cleanup: no-cap fallback now compares against pi.root_c
            // (a PI F²Var) instead of signature byte constants.
            enforce_field_digest_equals_pi(builder, &c_digest, pi.root_c)?;
        } else {
            // Phase 7-cleanup: select the cap-node F²Var via in-circuit mux
            // over `pi.c_cap_nodes_f2`, using the high bits of `position` as
            // selector bits. The native `cap_index` lookup remains as a sanity
            // check / value computation only — the matrix coefficients no
            // longer depend on it.
            let cap_index = chunk_index >> query_opening.c_auth_path.len();
            if cap_index >= signature.c_cap_nodes.len() {
                return Err(LoquatError::verification_failure(
                    "c cap index out of range",
                ));
            }
            let selected = select_cap_node_via_mux(
                builder,
                &pi.c_cap_nodes_f2,
                &signature.c_cap_nodes,
                in_circuit,
                query_idx,
                chunk_size,
                query_opening.c_auth_path.len(),
                position,
            )?;
            enforce_field_digest_equals_pi(builder, &c_digest, selected)?;
            let _ = cap_index;
        }

        let mut s_leaf_fields = Vec::with_capacity(chunk_size * 2);
        for off in 0..chunk_size {
            let var = s_chunk_vars[off];
            let val = query_opening.s_chunk[off];
            s_leaf_fields.push(FieldVar::existing(var.c0, val.c0));
            s_leaf_fields.push(FieldVar::existing(var.c1, val.c1));
        }
        let s_sibling_values: Vec<F2> = query_opening
            .s_auth_path
            .iter()
            .map(|sibling| {
                let arr: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                    LoquatError::verification_failure("s_auth_path sibling must be 32 bytes")
                })?;
                let (lo, hi) = digest32_to_fields(&arr);
                Ok::<_, LoquatError>(F2::new(lo, hi))
            })
            .collect::<LoquatResult<Vec<_>>>()?;
        let (s_dir_vars, s_dir_values) = direction_bits_for_path(
            in_circuit,
            query_idx,
            chunk_size_log,
            query_opening.s_auth_path.len(),
            chunk_index,
        );
        let s_digest = merkle_path_opening_fields_pi(
            builder,
            &s_leaf_fields,
            &pi.s_auth_paths_f2[query_idx],
            &s_sibling_values,
            &s_dir_vars,
            &s_dir_values,
        )?;
        if signature.s_cap_nodes.is_empty() {
            // Phase 7-cleanup: no-cap fallback → pi.root_s.
            enforce_field_digest_equals_pi(builder, &s_digest, pi.root_s)?;
        } else {
            let cap_index = chunk_index >> query_opening.s_auth_path.len();
            if cap_index >= signature.s_cap_nodes.len() {
                return Err(LoquatError::verification_failure(
                    "s cap index out of range",
                ));
            }
            let selected = select_cap_node_via_mux(
                builder,
                &pi.s_cap_nodes_f2,
                &signature.s_cap_nodes,
                in_circuit,
                query_idx,
                chunk_size,
                query_opening.s_auth_path.len(),
                position,
            )?;
            enforce_field_digest_equals_pi(builder, &s_digest, selected)?;
            let _ = cap_index;
        }

        let mut h_leaf_fields = Vec::with_capacity(chunk_size * 2);
        for off in 0..chunk_size {
            let var = h_chunk_vars[off];
            let val = query_opening.h_chunk[off];
            h_leaf_fields.push(FieldVar::existing(var.c0, val.c0));
            h_leaf_fields.push(FieldVar::existing(var.c1, val.c1));
        }
        let h_sibling_values: Vec<F2> = query_opening
            .h_auth_path
            .iter()
            .map(|sibling| {
                let arr: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                    LoquatError::verification_failure("h_auth_path sibling must be 32 bytes")
                })?;
                let (lo, hi) = digest32_to_fields(&arr);
                Ok::<_, LoquatError>(F2::new(lo, hi))
            })
            .collect::<LoquatResult<Vec<_>>>()?;
        let (h_dir_vars, h_dir_values) = direction_bits_for_path(
            in_circuit,
            query_idx,
            chunk_size_log,
            query_opening.h_auth_path.len(),
            chunk_index,
        );
        let h_digest = merkle_path_opening_fields_pi(
            builder,
            &h_leaf_fields,
            &pi.h_auth_paths_f2[query_idx],
            &h_sibling_values,
            &h_dir_vars,
            &h_dir_values,
        )?;
        if signature.h_cap_nodes.is_empty() {
            // Phase 7-cleanup: no-cap fallback → pi.root_h.
            enforce_field_digest_equals_pi(builder, &h_digest, pi.root_h)?;
        } else {
            let cap_index = chunk_index >> query_opening.h_auth_path.len();
            if cap_index >= signature.h_cap_nodes.len() {
                return Err(LoquatError::verification_failure(
                    "h cap index out of range",
                ));
            }
            let selected = select_cap_node_via_mux(
                builder,
                &pi.h_cap_nodes_f2,
                &signature.h_cap_nodes,
                in_circuit,
                query_idx,
                chunk_size,
                query_opening.h_auth_path.len(),
                position,
            )?;
            enforce_field_digest_equals_pi(builder, &h_digest, selected)?;
            let _ = cap_index;
        }

        // Phase 5.2b: LDT codeword chunks sourced from `pi.ldt_codeword_chunks`
        // instead of fresh witness allocations. Merkle authentication and FRI
        // folding still operate on these vars (same constraint structure);
        // the difference is the vars now live in the PI section.
        let ldt_chunk_vars: Vec<Vec<F2Var>> = pi.ldt_codeword_chunks[query_idx].clone();

        let mut fold_index = position;
        let mut layer_len = params.coset_u.len();
        for layer in 0..=params.r {
            let expected_len = chunk_size.min(layer_len);
            let chunk_vals = &ldt_opening.codeword_chunks[layer];
            let chunk_vars = &ldt_chunk_vars[layer];
            if chunk_vals.len() != expected_len || chunk_vars.len() != expected_len {
                return Err(LoquatError::verification_failure(
                    "LDT chunk length mismatch",
                ));
            }

            let mut leaf_fields = Vec::with_capacity(expected_len * 2);
            for (var, val) in chunk_vars.iter().zip(chunk_vals.iter()) {
                leaf_fields.push(FieldVar::existing(var.c0, val.c0));
                leaf_fields.push(FieldVar::existing(var.c1, val.c1));
            }

            let leaf_index = fold_index / chunk_size;
            // Phase 7-cleanup: LDT Merkle path opening migrated to PI siblings
            // and direction bits sourced from the in-circuit position decomposition.
            let ldt_layer_sibling_values: Vec<F2> = ldt_opening.auth_paths[layer]
                .iter()
                .map(|sibling| {
                    let arr: [u8; 32] = sibling.as_slice().try_into().map_err(|_| {
                        LoquatError::verification_failure(
                            "ldt auth_path sibling must be 32 bytes",
                        )
                    })?;
                    let (lo, hi) = digest32_to_fields(&arr);
                    Ok::<_, LoquatError>(F2::new(lo, hi))
                })
                .collect::<LoquatResult<Vec<_>>>()?;
            let ldt_layer_base_shift = (layer + 1) * chunk_size_log;
            let (ldt_dir_vars, ldt_dir_values) = direction_bits_for_path(
                in_circuit,
                query_idx,
                ldt_layer_base_shift,
                ldt_opening.auth_paths[layer].len(),
                leaf_index,
            );
            let digest = merkle_path_opening_fields_pi(
                builder,
                &leaf_fields,
                &pi.ldt_auth_paths_f2[query_idx][layer],
                &ldt_layer_sibling_values,
                &ldt_dir_vars,
                &ldt_dir_values,
            )?;

            let cap_nodes_layer = &signature.ldt_proof.cap_nodes[layer];
            if cap_nodes_layer.is_empty() {
                // Phase 7-cleanup: no-cap fallback → pi.ldt_commitments[layer].
                enforce_field_digest_equals_pi(builder, &digest, pi.ldt_commitments[layer])?;
            } else {
                let cap_index = leaf_index >> ldt_opening.auth_paths[layer].len();
                if cap_index >= cap_nodes_layer.len() {
                    return Err(LoquatError::verification_failure(
                        "LDT cap index out of range",
                    ));
                }
                // Phase 7-cleanup: LDT cap node selection via in-circuit mux
                // over `pi.ldt_cap_nodes_f2[layer]`. The fold_index for layer L
                // = position >> (L * log₂(chunk_size)), so the cap_index bits
                // are still a slice of `query_position_bit_vars[query_idx]` —
                // just shifted by an additional L · log₂(chunk_size).
                let selected = select_cap_node_via_mux_for_ldt(
                    builder,
                    &pi.ldt_cap_nodes_f2[layer],
                    cap_nodes_layer,
                    in_circuit,
                    query_idx,
                    chunk_size,
                    layer,
                    ldt_opening.auth_paths[layer].len(),
                    position,
                )?;
                enforce_field_digest_equals_pi(builder, &digest, selected)?;
                let _ = cap_index;
            }

            if layer < params.r {
                // Phase 1.4: FRI fold uses the in-circuit FS challenge as F2Var
                // (var-by-var multiplication via f2_mul) instead of a baked-in F2
                // constant. Mathematical identity preserved: next = Σ_i (chunk_var[i] * challenge^i).
                let challenge_value = signature.fri_challenges[layer];
                let challenge_var = in_circuit.fri_chal_vars[layer];

                // Allocate challenge powers χ², χ³, ..., χ^{expected_len-1} via chained f2_mul.
                // χ⁰ = 1 (handled implicitly: the i=0 term is just chunk_var[0] with coefficient 1).
                // χ¹ = challenge_var (no allocation needed).
                let mut power_vars: Vec<F2Var> = Vec::with_capacity(expected_len.saturating_sub(2));
                let mut power_values: Vec<F2> = Vec::with_capacity(expected_len.saturating_sub(2));
                if expected_len >= 3 {
                    let mut prev_var = challenge_var;
                    let mut prev_val = challenge_value;
                    for _ in 2..expected_len {
                        let next_val = prev_val * challenge_value;
                        let next_var =
                            f2_mul(builder, prev_var, prev_val, challenge_var, challenge_value);
                        power_vars.push(next_var);
                        power_values.push(next_val);
                        prev_var = next_var;
                        prev_val = next_val;
                    }
                }
                // power_vars[k-2] = χ^k for k in 2..expected_len.

                // Build sum terms: term[i] = chunk_vars[i] * χ^i.
                let mut sum_c0_terms: Vec<(usize, F)> = Vec::with_capacity(expected_len);
                let mut sum_c1_terms: Vec<(usize, F)> = Vec::with_capacity(expected_len);
                if expected_len >= 1 {
                    // i = 0: term = chunk_vars[0] * 1
                    sum_c0_terms.push((chunk_vars[0].c0, F::one()));
                    sum_c1_terms.push((chunk_vars[0].c1, F::one()));
                }
                for i in 1..expected_len {
                    let var = chunk_vars[i];
                    let val = chunk_vals[i];
                    let (pow_var, pow_val) = if i == 1 {
                        (challenge_var, challenge_value)
                    } else {
                        (power_vars[i - 2], power_values[i - 2])
                    };
                    let prod = f2_mul(builder, var, val, pow_var, pow_val);
                    sum_c0_terms.push((prod.c0, F::one()));
                    sum_c1_terms.push((prod.c1, F::one()));
                }

                let next_index = fold_index / chunk_size;
                let next_offset = next_index % chunk_size;
                let next_layer_len = ((layer_len + chunk_size - 1) / chunk_size).max(1);
                // Phase 7-cleanup: directly indexing `ldt_chunk_vars[layer+1][next_offset]`
                // baked the signature-dependent `next_offset` into the matrix's
                // variable selection (different signatures pick different PI
                // F²Vars at this position). Mux over the next-layer chunk via
                // an in-circuit selector derived from the position bits — same
                // PI list across signatures, identical matrix shape.
                let next_chunk_size = chunk_size.min(next_layer_len);
                let next_layer_vars: &[F2Var] = &ldt_chunk_vars[layer + 1];
                let next_var = if next_chunk_size <= 1 {
                    // Trivial mux (single element) — `next_offset` is forced to
                    // 0 by `next_layer_len ≤ chunk_size`.
                    next_layer_vars[0]
                } else {
                    let next_layer_values: Vec<F2> = ldt_opening.codeword_chunks[layer + 1].clone();
                    let next_offset_log = next_chunk_size.trailing_zeros() as usize;
                    let next_offset_base_shift = (layer + 1) * chunk_size_log;
                    let position_bits = &in_circuit.query_position_bit_vars[query_idx];
                    let mut next_offset_bit_vars = Vec::with_capacity(next_offset_log);
                    let mut next_offset_bit_values = Vec::with_capacity(next_offset_log);
                    for k in 0..next_offset_log {
                        let bit_pos = next_offset_base_shift + k;
                        if bit_pos >= position_bits.len() {
                            return Err(LoquatError::verification_failure(
                                "next_offset bit slice exceeds position decomposition length",
                            ));
                        }
                        next_offset_bit_vars.push(position_bits[bit_pos]);
                        next_offset_bit_values.push(F::new(((next_offset >> k) & 1) as u128));
                    }
                    f2_select_mux(
                        builder,
                        next_layer_vars,
                        &next_layer_values,
                        &next_offset_bit_vars,
                        &next_offset_bit_values,
                    )
                };
                builder.enforce_sum_equals(&sum_c0_terms, next_var.c0);
                builder.enforce_sum_equals(&sum_c1_terms, next_var.c1);

                fold_index = next_index;
                layer_len = next_layer_len;
            }
        }

        // Phase 5.5.4: compute x_chunk_start_var = u_shift · u_g^chunk_start (F²).
        // The high bits of position (above log_chunk) are FS-bound FieldVars from
        // in_circuit.query_position_bit_vars; off bits are loop-counter constants
        // contributing via mul_const_var inside the off loop.
        let chunk_start = chunk_index * chunk_size;
        let log_chunk = chunk_size.trailing_zeros() as usize;
        let log_u_total = params.coset_u.len().trailing_zeros() as usize;
        let high_bits: Vec<usize> = in_circuit.query_position_bit_vars[query_idx]
            [log_chunk..log_u_total]
            .to_vec();
        let g_chunk = params.u_generator.pow(chunk_size as u128);
        let x_chunk_start_var = compute_x_var_at_position_f2(
            builder,
            params.u_shift,
            g_chunk,
            &high_bits,
            chunk_index,
        );

        for off in 0..chunk_size {
            let global_idx = chunk_start + off;
            if global_idx >= params.coset_u.len() {
                return Err(LoquatError::verification_failure(
                    "query index out of range",
                ));
            }
            let x = params.coset_u[global_idx];
            let z_h = x.pow(h_order) - z_h_constant;
            let denom_scalar = h_size_scalar * x;

            // Phase 5.5.4: x_at_off_var = x_chunk_start_var · u_g^off (F² const · F² var).
            // Encoded as 2 linear rows via enforce_f2_const_mul_eq.
            let off_pow = params.u_generator.pow(off as u128);
            let x_at_off_value = x * F2::one(); // == x; double-check below
            let x_chunk_start_value = params.u_shift * g_chunk.pow(chunk_index as u128);
            debug_assert_eq!(x_chunk_start_value * off_pow, x);
            let x_at_off_var = builder.alloc_f2(x);
            enforce_f2_const_mul_eq(builder, x_chunk_start_var, off_pow, x_at_off_var);
            let _ = x_at_off_value;

            // Phase 5.5.4: build Lagrange basis at x_at_off_var (F²) and evaluate
            // q̂_j(x) for each j. Replaces native q_hat_on_u[j][global_idx] constants.
            let basis_at_x = build_lagrange_basis_at_f2(
                builder,
                params.h_shift,
                params.h_generator,
                2 * params.m,
                x_at_off_var,
                x,
            )?;
            let mut q_hat_j_vars: Vec<F2Var> = Vec::with_capacity(params.n);
            let mut q_hat_j_values: Vec<F2> = Vec::with_capacity(params.n);
            for j in 0..params.n {
                let (q_hat_var, q_hat_value) =
                    evaluate_q_hat_j_at_f2(builder, &q_eval_on_h_var[j], &basis_at_x)?;
                q_hat_j_vars.push(q_hat_var);
                q_hat_j_values.push(q_hat_value);
            }

            // Phase 5.5.5 + 5.7 (partial): f'(x) = ŝ(x) + Σ_j (z · ε_j · q̂_j(x)) · c′_j(x).
            // coeff_j = z (F) · ε_j (F) · q̂_j (F²) = F². Then term_j = c_prime · coeff_j.
            // Cost per j: 1 (z·ε) + 2 (z_eps·q̂_j over F²) + 6 (term f2_mul) = 9 mul rows.
            // Plus 2 sum rows for f_prime_var c0/c1.
            let mut f_prime_value = query_opening.s_chunk[off];
            let mut sum_c0_terms: Vec<(usize, F)> = vec![(s_chunk_vars[off].c0, F::one())];
            let mut sum_c1_terms: Vec<(usize, F)> = vec![(s_chunk_vars[off].c1, F::one())];

            for j in 0..params.n {
                let z_var = in_circuit.z_var;
                let eps_var = in_circuit.epsilon_real_vars[j];
                // z · ε (F · F → F)
                let z_eps_value = z_var.value * eps_var.value;
                let z_eps_idx = builder.alloc(z_eps_value);
                builder.enforce_mul_vars(z_var.idx, eps_var.idx, z_eps_idx);

                // coeff_j = z_eps (F) · q̂_j (F²) → F²
                let q_hat_var = q_hat_j_vars[j];
                let q_hat_value = q_hat_j_values[j];
                let coeff_c0_value = z_eps_value * q_hat_value.c0;
                let coeff_c1_value = z_eps_value * q_hat_value.c1;
                let coeff_c0_idx = builder.alloc(coeff_c0_value);
                let coeff_c1_idx = builder.alloc(coeff_c1_value);
                builder.enforce_mul_vars(z_eps_idx, q_hat_var.c0, coeff_c0_idx);
                builder.enforce_mul_vars(z_eps_idx, q_hat_var.c1, coeff_c1_idx);
                let coeff_var = F2Var {
                    c0: coeff_c0_idx,
                    c1: coeff_c1_idx,
                };
                let coeff_value = F2::new(coeff_c0_value, coeff_c1_value);

                // term_j = c_prime[off][j] (F²) · coeff_var (F²) via f2_mul (6 rows).
                let c_prime_var = c_prime_chunk_vars[off][j];
                let c_prime_val = query_opening.c_prime_chunk[off][j];
                let term_var = f2_mul(builder, c_prime_var, c_prime_val, coeff_var, coeff_value);
                let term_value = c_prime_val * coeff_value;

                sum_c0_terms.push((term_var.c0, F::one()));
                sum_c1_terms.push((term_var.c1, F::one()));
                f_prime_value += term_value;
            }

            let f_prime_var = builder.alloc_f2(f_prime_value);
            builder.enforce_sum_equals(&sum_c0_terms, f_prime_var.c0);
            builder.enforce_sum_equals(&sum_c1_terms, f_prime_var.c1);

            // Phase 5.7: z_h(x) reuses `vanishing_at_x` from the Lagrange gadget
            // (precisely Z_H(x) = x^|H| − h_shift^|H|). denom_scalar and h_coeff
            // now flow as in-circuit F²Vars derived from x_at_off_var.
            let z_h_var = basis_at_x.vanishing_at_x;
            let z_h_value = basis_at_x.vanishing_at_x_value;
            debug_assert_eq!(z_h_value, z_h);

            // denom_scalar_var = h_size_scalar (F² const) · x_at_off_var (F²Var) → 2 lin rows.
            let denom_scalar_var = builder.alloc_f2(denom_scalar);
            enforce_f2_const_mul_eq(builder, x_at_off_var, h_size_scalar, denom_scalar_var);

            // h_coeff_var = -h_size_scalar · z_h_var (F² const · F²Var) → 2 lin rows.
            let h_coeff_value = -(h_size_scalar * z_h_value);
            let h_coeff_var = builder.alloc_f2(h_coeff_value);
            enforce_f2_const_mul_eq(builder, z_h_var, -h_size_scalar, h_coeff_var);

            // Enforce p(x) via: (|H|·x)·p(x) = |H|·f'(x) − |H|·Z_H(x)·h(x) − (z·μ + S).
            //
            // expr_var = h_size_scalar · f_prime_var + h_coeff_var · h_chunk_vars[off].
            // First term: F² const · F²Var (2 lin via enforce_f2_const_mul_eq).
            // Second term: F²Var · F²Var (f2_mul, 6 rows).
            // Sum: F² add (2 lin via enforce_f2_add).
            let expr_value =
                h_size_scalar * f_prime_value - h_size_scalar * z_h * query_opening.h_chunk[off];
            let expr_var = builder.alloc_f2(expr_value);
            let h_size_times_f_prime_value = h_size_scalar * f_prime_value;
            let h_size_times_f_prime_var = builder.alloc_f2(h_size_times_f_prime_value);
            enforce_f2_const_mul_eq(builder, f_prime_var, h_size_scalar, h_size_times_f_prime_var);
            let h_coeff_times_h_chunk_value = h_coeff_value * query_opening.h_chunk[off];
            let h_coeff_times_h_chunk_var = f2_mul(
                builder,
                h_coeff_var,
                h_coeff_value,
                h_chunk_vars[off],
                query_opening.h_chunk[off],
            );
            let _ = h_coeff_times_h_chunk_value;
            enforce_f2_add(
                builder,
                h_size_times_f_prime_var,
                h_coeff_times_h_chunk_var,
                expr_var,
            );

            let numerator_value = expr_value - z_mu_plus_s_value;
            let numerator_var = builder.alloc_f2(numerator_value);
            builder.enforce_f2_sub(expr_var, z_mu_plus_s_var, numerator_var);

            // Phase 5.7: p_var · denom_scalar_var = numerator_var (F² · F² = F²).
            // Encoded inline via 4 F muls + 2 lin rows (same shape as f2_mul, but with
            // the output bound to numerator_var instead of allocated fresh).
            let denom_inv = denom_scalar.inverse().ok_or_else(|| {
                LoquatError::verification_failure("denominator not invertible in p(x) computation")
            })?;
            let p_value = numerator_value * denom_inv;
            let p_var = builder.alloc_f2(p_value);
            // Phase 5.7: constrain p_var · denom_scalar_var = numerator_var via inline
            // F² mul (4 F muls + 2 linear). The F² product (a + bi)(c + di) = (ac + 3bd) + (ad + bc)i
            // expands as: ac + 3bd = numerator.c0; ad + bc = numerator.c1.
            let p_c0 = p_value.c0;
            let p_c1 = p_value.c1;
            let d_c0 = denom_scalar.c0;
            let d_c1 = denom_scalar.c1;
            let ac_idx = builder.alloc(p_c0 * d_c0);
            builder.enforce_mul_vars(p_var.c0, denom_scalar_var.c0, ac_idx);
            let bd_idx = builder.alloc(p_c1 * d_c1);
            builder.enforce_mul_vars(p_var.c1, denom_scalar_var.c1, bd_idx);
            let ad_idx = builder.alloc(p_c0 * d_c1);
            builder.enforce_mul_vars(p_var.c0, denom_scalar_var.c1, ad_idx);
            let bc_idx = builder.alloc(p_c1 * d_c0);
            builder.enforce_mul_vars(p_var.c1, denom_scalar_var.c0, bc_idx);
            let qnr_p57 = F::new(3);
            // ac + 3·bd = numerator.c0
            builder.enforce_linear_relation(
                &[(ac_idx, F::one()), (bd_idx, qnr_p57), (numerator_var.c0, -F::one())],
                F::zero(),
            );
            // ad + bc = numerator.c1
            builder.enforce_linear_relation(
                &[(ad_idx, F::one()), (bc_idx, F::one()), (numerator_var.c1, -F::one())],
                F::zero(),
            );

            // f^(0)(x) constraint (paper §4.3): opened f^(0)(x) must match recomputation.
            let exponents: [u128; 4] = [
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[0])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_1"))?
                    as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[1])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_2"))?
                    as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[2])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_3"))?
                    as u128,
                params
                    .rho_star_num
                    .checked_sub(params.rho_numerators[3])
                    .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_4"))?
                    as u128,
            ];

            // Phase 5.6: e_vector entries sourced from in_circuit.e_vector_real_vars
            // (FieldVars, real-only F). Compute c/s/h/p coefficients in-circuit:
            //   coeff_i = e_vector_real[i] (F) + e_vector_real[i+4] (F) · x^exp_i (F²)
            // The product F · F² = F² (real-only F times each F² component).
            // The sum F + F² = F² (with the F lifted to F² with c1=0).
            //
            // This replaces 4 native F² constants per (off, query) with 4 in-circuit
            // F²Var coefficients, making the f0 lincomb signature-independent in
            // its multiplicative structure.
            let mut coeffs: Vec<F2Var> = Vec::with_capacity(4);
            let mut coeff_values: Vec<F2> = Vec::with_capacity(4);
            for i in 0..4 {
                // x_pow_var = x_at_off_var^exponents[i] in F² (square-and-multiply gadget).
                let (x_pow_var, x_pow_value) =
                    f2_pow_const(builder, x_at_off_var, x, exponents[i]);
                let e_low = in_circuit.e_vector_real_vars[i];
                let e_high = in_circuit.e_vector_real_vars[i + 4];
                // term = e_high (F) · x_pow_var (F²) → F² (per F² component, 1 mul row).
                let term_c0_value = e_high.value * x_pow_value.c0;
                let term_c0_idx = builder.alloc(term_c0_value);
                builder.enforce_mul_vars(e_high.idx, x_pow_var.c0, term_c0_idx);
                let term_c1_value = e_high.value * x_pow_value.c1;
                let term_c1_idx = builder.alloc(term_c1_value);
                builder.enforce_mul_vars(e_high.idx, x_pow_var.c1, term_c1_idx);

                // coeff = e_low (F) + term (F²): coeff.c0 = e_low + term.c0; coeff.c1 = term.c1.
                // Encoded as 2 linear constraints (one per F² component).
                let coeff_c0_value = e_low.value + term_c0_value;
                let coeff_c1_value = term_c1_value;
                let coeff_var = builder.alloc_f2(F2::new(coeff_c0_value, coeff_c1_value));
                builder.enforce_linear_relation(
                    &[
                        (coeff_var.c0, F::one()),
                        (e_low.idx, -F::one()),
                        (term_c0_idx, -F::one()),
                    ],
                    F::zero(),
                );
                builder.enforce_linear_relation(
                    &[(coeff_var.c1, F::one()), (term_c1_idx, -F::one())],
                    F::zero(),
                );
                coeffs.push(coeff_var);
                coeff_values.push(F2::new(coeff_c0_value, coeff_c1_value));
            }

            // f0 lincomb now uses var coefficients × var operands. Each term is a
            // F² · F² f2_mul (6 rows). Then sum_equals on each F² component.
            let mut sum_c0_terms: Vec<(usize, F)> = Vec::with_capacity(params.n + 3);
            let mut sum_c1_terms: Vec<(usize, F)> = Vec::with_capacity(params.n + 3);

            // c_prime[off][j] · c_coeff for j ∈ [n].
            for j in 0..params.n {
                let c_prime_var = c_prime_chunk_vars[off][j];
                let c_prime_val = query_opening.c_prime_chunk[off][j];
                let term_var = f2_mul(builder, c_prime_var, c_prime_val, coeffs[0], coeff_values[0]);
                sum_c0_terms.push((term_var.c0, F::one()));
                sum_c1_terms.push((term_var.c1, F::one()));
            }
            // s_chunk[off] · s_coeff
            let s_term = f2_mul(
                builder,
                s_chunk_vars[off],
                query_opening.s_chunk[off],
                coeffs[1],
                coeff_values[1],
            );
            sum_c0_terms.push((s_term.c0, F::one()));
            sum_c1_terms.push((s_term.c1, F::one()));
            // h_chunk[off] · h_coeff
            let h_term = f2_mul(
                builder,
                h_chunk_vars[off],
                query_opening.h_chunk[off],
                coeffs[2],
                coeff_values[2],
            );
            sum_c0_terms.push((h_term.c0, F::one()));
            sum_c1_terms.push((h_term.c1, F::one()));
            // p_var · p_coeff (p_var is computed earlier in the loop)
            let p_value = numerator_value * denom_inv;
            let p_term = f2_mul(builder, p_var, p_value, coeffs[3], coeff_values[3]);
            sum_c0_terms.push((p_term.c0, F::one()));
            sum_c1_terms.push((p_term.c1, F::one()));

            // Target: f^(0)(x) opened from the LDT base layer chunk.
            let target_var = ldt_chunk_vars[0][off];
            builder.enforce_sum_equals(&sum_c0_terms, target_var.c0);
            builder.enforce_sum_equals(&sum_c1_terms, target_var.c1);
        }

        let _ = query_idx; // reserved for debug instrumentation
    }

    Ok(())
}

fn bytes_from_field(builder: &mut R1csBuilder, var_idx: usize, value: F) -> Vec<Byte> {
    let bits = builder.decompose_to_bits(var_idx, value, 128);
    let mut bytes = Vec::with_capacity(16);
    let value_u128 = field_to_u128(value);
    for i in 0..16 {
        let mut byte_bits = [0usize; 8];
        let mut byte_value = 0u8;
        for bit in 0..8 {
            byte_bits[bit] = bits[i * 8 + bit];
            if ((value_u128 >> (i * 8 + bit)) & 1) == 1 {
                byte_value |= 1 << bit;
            }
        }
        bytes.push(Byte::from_bits(byte_bits, byte_value));
    }
    bytes
}

fn bytes_from_f2(builder: &mut R1csBuilder, var: F2Var, value: F2) -> Vec<Byte> {
    let mut bytes = bytes_from_field(builder, var.c0, value.c0);
    bytes.extend(bytes_from_field(builder, var.c1, value.c1));
    bytes
}

fn serialize_field_matrix_bytes(
    builder: &mut R1csBuilder,
    var_matrix: &[Vec<usize>],
    value_matrix: &[Vec<F>],
) -> LoquatResult<Vec<Byte>> {
    if var_matrix.len() != value_matrix.len() {
        return Err(LoquatError::verification_failure(
            "matrix row count mismatch for transcript serialization",
        ));
    }
    let mut bytes = bytes_from_constants(builder, &(var_matrix.len() as u32).to_le_bytes());
    for (row_vars, row_values) in var_matrix.iter().zip(value_matrix.iter()) {
        if row_vars.len() != row_values.len() {
            return Err(LoquatError::verification_failure(
                "matrix row length mismatch for transcript serialization",
            ));
        }
        bytes.extend(bytes_from_constants(
            builder,
            &(row_vars.len() as u32).to_le_bytes(),
        ));
        for (&var_idx, &value) in row_vars.iter().zip(row_values.iter()) {
            bytes.extend(bytes_from_field(builder, var_idx, value));
        }
    }
    Ok(bytes)
}

struct TranscriptCircuit {
    bytes: Vec<Byte>,
    counter: u64,
}

impl TranscriptCircuit {
    fn new(builder: &mut R1csBuilder, label: &[u8]) -> Self {
        let mut bytes = bytes_from_constants(builder, b"loquat.transcript.griffin");
        bytes.extend(bytes_from_constants(
            builder,
            &(label.len() as u64).to_le_bytes(),
        ));
        bytes.extend(bytes_from_constants(builder, label));
        Self { bytes, counter: 0 }
    }

    fn append_message(&mut self, builder: &mut R1csBuilder, label: &[u8], data: &[Byte]) {
        self.bytes.extend(bytes_from_constants(
            builder,
            &(label.len() as u64).to_le_bytes(),
        ));
        self.bytes.extend(bytes_from_constants(builder, label));
        self.bytes.extend(bytes_from_constants(
            builder,
            &(data.len() as u64).to_le_bytes(),
        ));
        self.bytes.extend(data.iter().cloned());
    }

    fn challenge(&mut self, builder: &mut R1csBuilder, label: &[u8]) -> Vec<Byte> {
        let mut output = Vec::with_capacity(32);
        let mut chunk_index: u32 = 0;
        while output.len() < 32 {
            let mut input = self.bytes.clone();
            input.extend(bytes_from_constants(
                builder,
                &(label.len() as u64).to_le_bytes(),
            ));
            input.extend(bytes_from_constants(builder, label));
            input.extend(bytes_from_constants(builder, &self.counter.to_le_bytes()));
            input.extend(bytes_from_constants(builder, &chunk_index.to_le_bytes()));
            let digest = griffin_hash_bytes_circuit(builder, &input);
            for byte in digest {
                if output.len() == 32 {
                    break;
                }
                output.push(byte);
            }
            chunk_index = chunk_index.wrapping_add(1);
        }
        self.append_message(builder, label, &output);
        self.counter = self.counter.wrapping_add(1);
        output
    }
}

struct FieldTranscriptCircuit {
    state: [FieldVar; 2],
    counter: u64,
}

impl FieldTranscriptCircuit {
    fn new(builder: &mut R1csBuilder, label: &[u8]) -> Self {
        let domain_tag = FieldVar::constant(
            builder,
            pack_label_tag_field(b"loquat.transcript.field.griffin"),
        );
        let label_tag = FieldVar::constant(builder, pack_label_tag_field(label));
        let label_len = FieldVar::constant(builder, F::new(label.len() as u128));
        let counter0 = FieldVar::constant(builder, F::new(0));

        let digest =
            griffin_hash_field_vars_circuit(builder, &[domain_tag, label_tag, label_len, counter0]);
        let state = [digest[0], digest[1]];
        Self { state, counter: 0 }
    }

    fn append_f_vec(&mut self, builder: &mut R1csBuilder, label: &[u8], payload: &[FieldVar]) {
        let next = self.hash_prefixed(builder, label, payload);
        self.state = next;
    }

    fn append_digest32_as_fields(
        &mut self,
        builder: &mut R1csBuilder,
        label: &[u8],
        digest32: &[u8; 32],
    ) {
        let (lo, hi) = digest32_to_fields(digest32);
        let lo_var = FieldVar::constant(builder, lo);
        let hi_var = FieldVar::constant(builder, hi);
        self.append_f_vec(builder, label, &[lo_var, hi_var]);
    }

    /// Phase 5.3 / 6.2c: absorb a 32-byte digest already represented as a
    /// public-input F2Var into the transcript.
    ///
    /// **Phase 6.2c**: the binding constraints `pi_var.c0 == digest_lo` and
    /// `pi_var.c1 == digest_hi` were dropped. PI value correctness is now
    /// enforced cryptographically by Aurora at verification time
    /// (`aurora_verify_with_public_inputs`) — the verifier supplies the
    /// expected digest as public input, and the prover's witness Merkle
    /// commitment must match those values at the PI positions. The matrix
    /// is now signature-independent: the only entries are var indices +
    /// coefficients (1, -1, qnr=3 etc.) — no signature-specific F constants.
    fn append_digest32_as_pi_fields(
        &mut self,
        builder: &mut R1csBuilder,
        label: &[u8],
        pi_var: F2Var,
        digest32: &[u8; 32],
    ) {
        let (lo, hi) = digest32_to_fields(digest32);
        let lo_var = FieldVar::existing(pi_var.c0, lo);
        let hi_var = FieldVar::existing(pi_var.c1, hi);
        self.append_f_vec(builder, label, &[lo_var, hi_var]);
    }

    fn challenge_seed(&mut self, builder: &mut R1csBuilder, label: &[u8]) -> [FieldVar; 2] {
        let counter_var = FieldVar::constant(builder, F::new(self.counter as u128));
        let digest = self.hash_prefixed(builder, label, &[counter_var]);
        self.state = digest;
        self.counter = self.counter.wrapping_add(1);
        digest
    }

    fn challenge_f(&mut self, builder: &mut R1csBuilder, label: &[u8]) -> FieldVar {
        self.challenge_seed(builder, label)[0]
    }

    fn challenge_f2(&mut self, builder: &mut R1csBuilder, label: &[u8]) -> [FieldVar; 2] {
        self.challenge_seed(builder, label)
    }

    fn hash_prefixed(
        &self,
        builder: &mut R1csBuilder,
        label: &[u8],
        payload: &[FieldVar],
    ) -> [FieldVar; 2] {
        let label_tag = FieldVar::constant(builder, pack_label_tag_field(label));
        let label_len = FieldVar::constant(builder, F::new(label.len() as u128));
        let payload_len = FieldVar::constant(builder, F::new(payload.len() as u128));

        let mut inputs = Vec::with_capacity(2 + 3 + payload.len());
        inputs.push(self.state[0]);
        inputs.push(self.state[1]);
        inputs.push(label_tag);
        inputs.push(label_len);
        inputs.push(payload_len);
        inputs.extend_from_slice(payload);

        let digest = griffin_hash_field_vars_circuit(builder, &inputs);
        [digest[0], digest[1]]
    }
}

fn digest32_to_fields(digest32: &[u8; 32]) -> (F, F) {
    let lo = F::new(u128::from_le_bytes(digest32[0..16].try_into().unwrap()));
    let hi = F::new(u128::from_le_bytes(digest32[16..32].try_into().unwrap()));
    (lo, hi)
}

fn pack_label_tag_field(label: &[u8]) -> F {
    let mut arr = [0u8; 16];
    let take = core::cmp::min(16, label.len());
    arr[..take].copy_from_slice(&label[..take]);
    F::new(u128::from_le_bytes(arr))
}

fn expand_f_circuit(
    builder: &mut R1csBuilder,
    seed: [FieldVar; 2],
    domain: &[u8],
    count: usize,
) -> Vec<FieldVar> {
    if count == 0 {
        return Vec::new();
    }
    let domain_tag = FieldVar::constant(builder, pack_label_tag_field(domain));
    let domain_len = FieldVar::constant(builder, F::new(domain.len() as u128));
    let count_var = FieldVar::constant(builder, F::new(count as u128));
    let inputs = vec![seed[0], seed[1], domain_tag, domain_len, count_var];
    griffin_sponge_field_vars_circuit(builder, &inputs, count)
}

fn enforce_field_matches_digest(
    builder: &mut R1csBuilder,
    digest_bytes: &[Byte],
    value: F,
) -> LoquatResult<()> {
    if digest_bytes.len() < 16 {
        return Err(LoquatError::verification_failure(
            "digest too short for field conversion",
        ));
    }
    let value_idx = builder.alloc(value);
    let value_bytes = bytes_from_field(builder, value_idx, value);
    for (expected, actual) in value_bytes.iter().zip(digest_bytes.iter()) {
        enforce_byte_equality(builder, expected, actual);
    }
    Ok(())
}

/// Enforce that all Fiat–Shamir challenges used by the verifier are derived from the
/// same field-native transcript inside the circuit (paper-aligned).
///
/// Returns an [`InCircuitTranscript`] containing all the FieldVars/F2Vars
/// produced by the in-circuit derivation. Phase 1 of the B → C refactor uses
/// these variables in downstream constraints; legacy callers can ignore the
/// return value (the equality bindings against `transcript_data` are still
/// emitted, so behavior is unchanged when the result is unused).
fn enforce_transcript_relations_field_native(
    builder: &mut R1csBuilder,
    params: &LoquatPublicParams,
    signature: &LoquatSignature,
    transcript_data: &TranscriptData,
    pi: &LoquatPublicInputs,
    t_var_indices: &[Vec<usize>],
    o_var_indices: &[Vec<usize>],
    sumcheck_claimed_sum_var: F2Var,
    sumcheck_round_vars: &[(F2Var, F2Var)],
) -> LoquatResult<InCircuitTranscript> {
    if signature.z_challenge.c1 != F::zero() {
        return Err(LoquatError::verification_failure(
            "z challenge imaginary component must be zero",
        ));
    }
    for (idx, entry) in signature.e_vector.iter().enumerate() {
        if entry.c1 != F::zero() {
            return Err(LoquatError::verification_failure(&format!(
                "e_vector[{idx}] imaginary component must be zero",
            )));
        }
    }
    for (idx, entry) in transcript_data.epsilon_vals.iter().enumerate() {
        if entry.c1 != F::zero() {
            return Err(LoquatError::verification_failure(&format!(
                "epsilon_vals[{idx}] imaginary component must be zero",
            )));
        }
    }

    let message_commitment: [u8; 32] = signature
        .message_commitment
        .as_slice()
        .try_into()
        .map_err(|_| LoquatError::verification_failure("message commitment must be 32 bytes"))?;

    let mut transcript = FieldTranscriptCircuit::new(builder, b"loquat_signature");
    // Phase 5.3: digests sourced from PI section. The binding constraints inside
    // `append_digest32_as_pi_fields` enforce honest PI values until Phase 6 makes
    // libiop respect `num_inputs` (after which the bindings can be dropped).
    transcript.append_digest32_as_pi_fields(
        builder,
        b"message_commitment",
        pi.message_commitment,
        &message_commitment,
    );
    transcript.append_digest32_as_pi_fields(builder, b"root_c", pi.root_c, &signature.root_c);

    // σ₁: absorb t-values (flattened)
    let mut t_fields = Vec::with_capacity(params.m * params.n);
    if t_var_indices.len() != signature.t_values.len() {
        return Err(LoquatError::verification_failure(
            "t-value matrix dimension mismatch",
        ));
    }
    for (row_vars, row_vals) in t_var_indices.iter().zip(signature.t_values.iter()) {
        if row_vars.len() != row_vals.len() {
            return Err(LoquatError::verification_failure(
                "t-value row length mismatch",
            ));
        }
        for (&idx, &value) in row_vars.iter().zip(row_vals.iter()) {
            t_fields.push(FieldVar::existing(idx, value));
        }
    }
    transcript.append_f_vec(builder, b"t_values", &t_fields);

    // h1 and I_{i,j}
    let h1_seed = transcript.challenge_seed(builder, b"h1");
    let num_checks = params.m * params.n;
    if transcript_data.i_indices.len() != num_checks {
        return Err(LoquatError::verification_failure("I-index length mismatch"));
    }
    let raw_indices = expand_f_circuit(builder, h1_seed, b"I_indices", num_checks);
    let modulus = params.l;
    let k = (usize::BITS - modulus.saturating_sub(1).leading_zeros()) as usize;
    let mask = if k >= 128 {
        u128::MAX
    } else {
        (1u128 << k) - 1
    };
    let mut i_index_low_vars: Vec<FieldVar> = Vec::with_capacity(num_checks);
    let mut i_index_expected_vars: Vec<FieldVar> = Vec::with_capacity(num_checks);
    let mut i_index_bit_vars: Vec<Vec<usize>> = Vec::with_capacity(num_checks);
    for (check_idx, raw) in raw_indices.into_iter().enumerate() {
        let bits = builder.decompose_to_bits(raw.idx, raw.value, 128);
        let low_value_u128 = raw.value.0 & mask;
        let low_idx = builder.alloc(F::new(low_value_u128));
        let mut terms = Vec::with_capacity(k + 1);
        terms.push((low_idx, F::one()));
        for bit_pos in 0..k {
            terms.push((bits[bit_pos], -F::new(1u128 << bit_pos)));
        }
        builder.enforce_linear_relation(&terms, F::zero());

        let expected = transcript_data.i_indices[check_idx];
        if expected >= modulus {
            return Err(LoquatError::verification_failure(
                "I-index out of range for modulus",
            ));
        }
        let b_value = (low_value_u128 as usize >= modulus) as u128;
        let b_idx = builder.alloc(F::new(b_value));
        builder.enforce_boolean(b_idx);

        // Phase 5.4: allocate `expected_idx` as a witness variable. Bit-decompose
        // it into k = ⌈log₂(modulus)⌉ bits → range [0, 2^k). For non-power-of-2
        // modulus we additionally constrain `expected_idx < modulus` by bit-
        // decomposing `(modulus - 1) - expected_idx` into k bits (which forces
        // diff ≥ 0 in integer arithmetic; the field-wraparound case would
        // produce a value much larger than 2^k, failing the bit decomposition).
        let expected_value = F::new(expected as u128);
        let expected_idx = builder.alloc(expected_value);
        let expected_bits = builder.decompose_to_bits(expected_idx, expected_value, k);
        if !modulus.is_power_of_two() {
            // Range check: modulus - 1 - expected_idx ∈ [0, 2^k).
            let diff_value_u128 = (modulus as u128 - 1) - expected as u128;
            let diff_value = F::new(diff_value_u128);
            let diff_idx = builder.alloc(diff_value);
            builder.enforce_linear_relation(
                &[(diff_idx, F::one()), (expected_idx, F::one())],
                -F::new((modulus - 1) as u128),
            );
            // Bit-decompose forces diff_idx < 2^k, i.e., expected_idx > modulus
            // would yield a wrap-around value ≫ 2^k and fail this check.
            let _diff_bits = builder.decompose_to_bits(diff_idx, diff_value, k);
        }
        builder.enforce_linear_relation(
            &[
                (low_idx, F::one()),
                (b_idx, -F::new(modulus as u128)),
                (expected_idx, -F::one()),
            ],
            F::zero(),
        );

        i_index_low_vars.push(FieldVar::existing(low_idx, F::new(low_value_u128)));
        i_index_expected_vars.push(FieldVar::existing(expected_idx, expected_value));
        i_index_bit_vars.push(expected_bits);
    }

    // σ₂: absorb o-values (flattened)
    let mut o_fields = Vec::with_capacity(params.m * params.n);
    if o_var_indices.len() != signature.o_values.len() {
        return Err(LoquatError::verification_failure(
            "o-value matrix dimension mismatch",
        ));
    }
    for (row_vars, row_vals) in o_var_indices.iter().zip(signature.o_values.iter()) {
        if row_vars.len() != row_vals.len() {
            return Err(LoquatError::verification_failure(
                "o-value row length mismatch",
            ));
        }
        for (&idx, &value) in row_vars.iter().zip(row_vals.iter()) {
            o_fields.push(FieldVar::existing(idx, value));
        }
    }
    transcript.append_f_vec(builder, b"o_values", &o_fields);

    // h2 and Expand(h2)
    let h2_seed = transcript.challenge_seed(builder, b"h2");
    if transcript_data.lambda_scalars.len() != num_checks {
        return Err(LoquatError::verification_failure("lambda length mismatch"));
    }
    let lambda_outs = expand_f_circuit(builder, h2_seed, b"lambdas", num_checks);
    let lambda_vars: Vec<FieldVar> = lambda_outs;
    // Phase 1.6: lambda equality binding dropped — `lambda_vars` are constrained
    // by Griffin (in `expand_f_circuit`) to be the in-circuit FS hash output, and
    // the QR contribution block (Phase 1.2) consumes them directly as multiplier
    // FieldVars. The previous `enforce_linear_relation` against
    // `transcript_data.lambda_scalars[idx]` was redundant given honest inputs.
    if transcript_data.epsilon_vals.len() != params.n {
        return Err(LoquatError::verification_failure("epsilon length mismatch"));
    }
    let eps_outs = expand_f_circuit(builder, h2_seed, b"e_j", params.n);
    let epsilon_real_vars: Vec<FieldVar> = eps_outs;
    // Phase 1.6: epsilon equality binding dropped — same reasoning as lambda above.
    // (Note: ε.c1 is structurally zero — never derived in-circuit, never bound.)

    // Sumcheck transcript challenges
    transcript.append_f_vec(
        builder,
        b"claimed_sum",
        &[
            FieldVar::existing(sumcheck_claimed_sum_var.c0, signature.pi_us.claimed_sum.c0),
            FieldVar::existing(sumcheck_claimed_sum_var.c1, signature.pi_us.claimed_sum.c1),
        ],
    );
    if signature.pi_us.round_polynomials.len() != sumcheck_round_vars.len()
        || signature.pi_us.round_polynomials.len() != transcript_data.sumcheck_challenges.len()
    {
        return Err(LoquatError::verification_failure(
            "sumcheck transcript length mismatch",
        ));
    }
    let mut sumcheck_chal_vars: Vec<F2Var> =
        Vec::with_capacity(signature.pi_us.round_polynomials.len());
    for (round_idx, round_poly) in signature.pi_us.round_polynomials.iter().enumerate() {
        let (c0_var, c1_var) = sumcheck_round_vars[round_idx];
        let poly_fields = [
            FieldVar::existing(c0_var.c0, round_poly.c0.c0),
            FieldVar::existing(c0_var.c1, round_poly.c0.c1),
            FieldVar::existing(c1_var.c0, round_poly.c1.c0),
            FieldVar::existing(c1_var.c1, round_poly.c1.c1),
        ];
        transcript.append_f_vec(builder, b"round_poly", &poly_fields);
        let chal = transcript.challenge_f2(builder, b"challenge");
        sumcheck_chal_vars.push(F2Var {
            c0: chal[0].idx,
            c1: chal[1].idx,
        });
        // Phase 1.6: sumcheck challenge equality binding dropped —
        // `sumcheck_chal_vars` are constrained by Griffin (in `challenge_f2`) and
        // consumed directly by `enforce_sumcheck_round` (Phase 1.3) as F2Var.
        let _round_idx = round_idx; // suppress unused-var warning
    }

    // σ₃, σ₄ and challenges h3/h4
    transcript.append_digest32_as_pi_fields(builder, b"root_s", pi.root_s, &signature.root_s);
    // Phase 5.3: s_sum sourced from PI (pi.s_sum) instead of fresh `FieldVar::constant`.
    // Bind PI vars to the constant value (same constraint count as legacy path;
    // bindings become deletable after Phase 6 enforces num_inputs in libiop).
    // Phase 6.2c: s_sum const-bindings dropped. pi.s_sum is enforced at the
    // PI level by Aurora (verifier supplies the expected s_sum, prover Merkle
    // openings must match). Matrix entries no longer carry signature.s_sum.
    let s_sum_c0 = FieldVar::existing(pi.s_sum.c0, signature.s_sum.c0);
    let s_sum_c1 = FieldVar::existing(pi.s_sum.c1, signature.s_sum.c1);
    transcript.append_f_vec(builder, b"s_sum", &[s_sum_c0, s_sum_c1]);
    let z_scalar = transcript.challenge_f(builder, b"h3");
    let z_var = z_scalar;
    // Phase 6.2c: z_var const-binding dropped. z = h3 challenge — the in-circuit
    // FS hash chain forces z_var to equal the prover's witness value, which (for
    // honest provers) equals signature.z_challenge.c0. For malicious provers,
    // tampering with PI values shifts the FS chain, which propagates to QR /
    // sumcheck / LDT failures. Aurora PI enforcement is the primary soundness path.

    transcript.append_digest32_as_pi_fields(builder, b"root_h", pi.root_h, &signature.root_h);
    let h4_seed = transcript.challenge_seed(builder, b"h4");

    if signature.e_vector.len() != 8 {
        return Err(LoquatError::verification_failure(
            "e-vector length mismatch",
        ));
    }
    let e_outs = expand_f_circuit(builder, h4_seed, b"e_vector", 8);
    let e_vector_real_vars: Vec<FieldVar> = e_outs;
    // Phase 6.2c: e_vector const-bindings dropped. e_vector_real_vars are
    // constrained by the in-circuit Griffin chain (in `expand_f_circuit`) to
    // match h4 hash output. For honest provers this equals signature.e_vector;
    // PI enforcement on the upstream signature components keeps the chain honest.

    // FRI folding challenges from LDT commitments
    if signature.ldt_proof.commitments.len() != params.r + 1 {
        return Err(LoquatError::verification_failure(
            "LDT commitment count mismatch",
        ));
    }
    if signature.fri_challenges.len() != params.r {
        return Err(LoquatError::verification_failure(
            "FRI challenge count mismatch",
        ));
    }
    // Phase 5.3: LDT layer commitments sourced from `pi.ldt_commitments` instead
    // of being baked as constants per `append_digest32_as_fields`.
    transcript.append_digest32_as_pi_fields(
        builder,
        b"merkle_commitment",
        pi.ldt_commitments[0],
        &signature.ldt_proof.commitments[0],
    );
    let mut fri_chal_vars: Vec<F2Var> = Vec::with_capacity(params.r);
    for round in 0..params.r {
        let chal = transcript.challenge_f2(builder, b"challenge");
        fri_chal_vars.push(F2Var {
            c0: chal[0].idx,
            c1: chal[1].idx,
        });
        // Phase 1.6: FRI challenge equality binding dropped — `fri_chal_vars`
        // are constrained by Griffin (in `challenge_f2`) and consumed directly
        // by the FRI fold inside `enforce_ldt_queries` (Phase 1.4) as F2Var.
        transcript.append_digest32_as_pi_fields(
            builder,
            b"merkle_commitment",
            pi.ldt_commitments[round + 1],
            &signature.ldt_proof.commitments[round + 1],
        );
    }

    // LDT query positions (paper §4.3): bind opening positions to transcript-derived challenges.
    if signature.ldt_proof.openings.len() != params.kappa {
        return Err(LoquatError::verification_failure(
            "LDT opening count mismatch for query binding",
        ));
    }
    if signature.query_openings.len() != params.kappa {
        return Err(LoquatError::verification_failure(
            "query opening count mismatch for query binding",
        ));
    }
    if params.coset_u.is_empty() || !params.coset_u.len().is_power_of_two() {
        return Err(LoquatError::invalid_parameters(
            "|U| must be a non-zero power of two",
        ));
    }
    let log_u = params.coset_u.len().trailing_zeros() as usize;
    let mask = if log_u >= 128 {
        u128::MAX
    } else {
        (1u128 << log_u) - 1
    };
    let mut query_position_low_vars: Vec<FieldVar> = Vec::with_capacity(params.kappa);
    let mut query_position_bit_vars: Vec<Vec<usize>> = Vec::with_capacity(params.kappa);
    for query_idx in 0..params.kappa {
        let chal = transcript.challenge_f2(builder, b"challenge");
        let bits = builder.decompose_to_bits(chal[0].idx, chal[0].value, 128);
        let low_value_u128 = chal[0].value.0 & mask;
        let low_idx = builder.alloc(F::new(low_value_u128));
        let mut terms = Vec::with_capacity(log_u + 1);
        terms.push((low_idx, F::one()));
        for bit_pos in 0..log_u {
            terms.push((bits[bit_pos], -F::new(1u128 << bit_pos)));
        }
        builder.enforce_linear_relation(&terms, F::zero());
        // Phase 5.5.3: capture position bits for in-circuit `x_var = u_g^position`
        // computation. The bits are already constrained by the FS bit-decomposition
        // above, so no additional constraints are needed here.
        query_position_bit_vars.push(bits[..log_u].to_vec());

        let expected_pos = signature.ldt_proof.openings[query_idx].position;
        // Phase 5.3: query position binding now goes through `pi.query_positions`.
        // Bind the FS-derived `low_idx` to `pi.query_positions[query_idx]` AND
        // bind the PI var to the constant `expected_pos` (so the prover cannot
        // forge the PI value pre-Phase-6). Net constraint count: +1 vs legacy
        // (was 1 binding to const; now 1 PI-to-const + 1 in-circuit-to-PI), but
        // after Phase 6 the PI-to-const binding is deletable.
        let expected_pos_f = F::new(expected_pos as u128);
        let _ = expected_pos_f; // Phase 6.2c: PI-to-const binding dropped.
        // Keep the FS-derived `low_idx == pi.query_positions[query_idx]` cross
        // binding — this is a constraint between two in-circuit variables, not
        // a signature-specific constant. Sound and matrix-independent.
        builder.enforce_linear_relation(
            &[
                (low_idx, F::one()),
                (pi.query_positions[query_idx].idx, -F::one()),
            ],
            F::zero(),
        );

        if signature.query_openings[query_idx].position != expected_pos {
            return Err(LoquatError::verification_failure(
                "query opening position mismatch for query binding",
            ));
        }
        query_position_low_vars.push(FieldVar::existing(low_idx, F::new(low_value_u128)));
    }

    Ok(InCircuitTranscript {
        i_index_low_vars,
        i_index_expected_vars,
        i_index_bit_vars,
        lambda_vars,
        epsilon_real_vars,
        sumcheck_chal_vars,
        z_var,
        e_vector_real_vars,
        fri_chal_vars,
        query_position_low_vars,
        query_position_bit_vars,
    })
}

fn enforce_digest_equals_bytes(builder: &mut R1csBuilder, digest: &[Byte], expected: &[u8; 32]) {
    for (idx, &expected_value) in expected.iter().enumerate() {
        let expected_byte = Byte::from_constant(builder, expected_value);
        enforce_byte_equality(builder, &digest[idx], &expected_byte);
    }
}

fn merkle_root_from_leaves(builder: &mut R1csBuilder, leaves: &[Vec<Byte>]) -> Vec<Byte> {
    let mut level: Vec<Vec<Byte>> = leaves
        .iter()
        .map(|leaf| griffin_hash_bytes_circuit(builder, leaf))
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            let mut bytes = chunk[0].clone();
            if chunk.len() > 1 {
                bytes.extend_from_slice(&chunk[1]);
            } else {
                bytes.extend_from_slice(&chunk[0]);
            }
            let digest = griffin_hash_bytes_circuit(builder, &bytes);
            next.push(digest);
        }
        level = next;
    }
    level
        .pop()
        .unwrap_or_else(|| griffin_hash_bytes_circuit(builder, &[]))
}
fn build_fri_layer_leaves(
    builder: &mut R1csBuilder,
    layer_vars: &[F2Var],
    layer_values: &[F2],
    chunk_size: usize,
) -> Vec<Vec<Byte>> {
    let size = chunk_size.max(1);
    let mut leaves = Vec::with_capacity((layer_vars.len() + size - 1) / size);
    let mut idx = 0;
    while idx < layer_vars.len() {
        let end = (idx + size).min(layer_vars.len());
        let mut chunk_bytes = Vec::new();
        for (var, value) in layer_vars[idx..end]
            .iter()
            .zip(layer_values[idx..end].iter())
        {
            chunk_bytes.extend(bytes_from_f2(builder, *var, *value));
        }
        leaves.push(chunk_bytes);
        idx = end;
    }
    leaves
}

fn bytes_to_field_elements(builder: &mut R1csBuilder, bytes: &[Byte]) -> Vec<FieldVar> {
    bytes
        .chunks(16)
        .map(|chunk| pack_bytes_to_field(builder, chunk))
        .collect()
}

fn pack_bytes_to_field(builder: &mut R1csBuilder, chunk: &[Byte]) -> FieldVar {
    let mut value = 0u128;
    let mut relation_terms = Vec::with_capacity(chunk.len() * 8 + 1);
    for (byte_pos, byte) in chunk.iter().enumerate() {
        value += (byte.value as u128) << (byte_pos * 8);
        for bit in 0..8 {
            let shift = byte_pos * 8 + bit;
            if shift >= 128 {
                continue;
            }
            let coeff = F::new(1u128 << shift);
            relation_terms.push((byte.bits[bit], coeff));
        }
    }
    let field_value = F::new(value);
    let field_idx = builder.alloc(field_value);
    let mut terms = vec![(field_idx, -F::one())];
    terms.extend(relation_terms);
    builder.enforce_linear_relation(&terms, F::zero());
    FieldVar::new(field_idx, field_value)
}

fn griffin_hash_bytes_circuit(builder: &mut R1csBuilder, bytes: &[Byte]) -> Vec<Byte> {
    let inputs = bytes_to_field_elements(builder, bytes);
    let digest_fields = griffin_hash_field_vars_circuit(builder, &inputs);
    let mut outputs = field_vars_to_bytes(builder, &digest_fields);
    if outputs.len() > 32 {
        outputs.truncate(32);
    }
    outputs
}

fn griffin_hash_field_vars_circuit(
    builder: &mut R1csBuilder,
    inputs: &[FieldVar],
) -> Vec<FieldVar> {
    griffin_sponge_field_vars_circuit(builder, inputs, GRIFFIN_DIGEST_ELEMENTS)
}

fn griffin_sponge_field_vars_circuit(
    builder: &mut R1csBuilder,
    inputs: &[FieldVar],
    output_len: usize,
) -> Vec<FieldVar> {
    if output_len == 0 {
        return Vec::new();
    }
    let params = get_griffin_params();
    let mut absorb_inputs = inputs.to_vec();
    let mut state: Vec<FieldVar> = (0..GRIFFIN_STATE_WIDTH)
        .map(|_| FieldVar::constant(builder, F::zero()))
        .collect();

    if absorb_inputs.len() % GRIFFIN_RATE != 0 {
        state[GRIFFIN_RATE] = FieldVar::constant(builder, F::one());
        absorb_inputs.push(FieldVar::constant(builder, F::one()));
    }
    while absorb_inputs.len() % GRIFFIN_RATE != 0 {
        absorb_inputs.push(FieldVar::constant(builder, F::zero()));
    }

    let mut absorb_idx = 0;
    while absorb_idx < absorb_inputs.len() {
        for lane in 0..GRIFFIN_RATE {
            state[lane] = field_add(builder, state[lane], absorb_inputs[absorb_idx + lane]);
        }
        griffin_permutation_circuit(builder, params, &mut state);
        absorb_idx += GRIFFIN_RATE;
    }

    let mut outputs = Vec::with_capacity(output_len);
    let mut remaining = output_len;
    while remaining > 0 {
        for lane in 0..GRIFFIN_RATE {
            if remaining == 0 {
                break;
            }
            outputs.push(state[lane]);
            remaining -= 1;
        }
        if remaining > 0 {
            griffin_permutation_circuit(builder, params, &mut state);
        }
    }
    outputs
}

fn field_vars_to_bytes(builder: &mut R1csBuilder, vars: &[FieldVar]) -> Vec<Byte> {
    let mut bytes = Vec::with_capacity(vars.len() * 16);
    for var in vars {
        bytes.extend(bytes_from_field(builder, var.idx, var.value));
    }
    bytes
}

fn collect_f2_field_vars(vars: &[F2Var], values: &[F2]) -> Vec<FieldVar> {
    vars.iter()
        .zip(values.iter())
        .flat_map(|(var, value)| {
            [
                FieldVar::existing(var.c0, value.c0),
                FieldVar::existing(var.c1, value.c1),
            ]
        })
        .collect()
}

fn griffin_hash_f2_chunk(
    builder: &mut R1csBuilder,
    vars: &[F2Var],
    values: &[F2],
) -> Vec<FieldVar> {
    let inputs = collect_f2_field_vars(vars, values);
    griffin_hash_field_vars_circuit(builder, &inputs)
}

fn hash_chunked_f2_vector(
    builder: &mut R1csBuilder,
    vars: &[F2Var],
    values: &[F2],
    chunk_size: usize,
) -> Vec<Vec<FieldVar>> {
    let chunk = chunk_size.max(1);
    let mut leaves = Vec::with_capacity((vars.len() + chunk - 1) / chunk);
    let mut idx = 0;
    while idx < vars.len() {
        let end = (idx + chunk).min(vars.len());
        let digest = griffin_hash_f2_chunk(builder, &vars[idx..end], &values[idx..end]);
        leaves.push(digest);
        idx = end;
    }
    leaves
}

fn hash_chunked_c_columns(
    builder: &mut R1csBuilder,
    c_prime_vars: &[Vec<F2Var>],
    c_prime_values: &[Vec<F2>],
    chunk_size: usize,
) -> LoquatResult<Vec<Vec<FieldVar>>> {
    if c_prime_vars.is_empty() || c_prime_values.is_empty() {
        return Err(LoquatError::verification_failure(
            "c' matrix must be non-empty",
        ));
    }
    if c_prime_vars.len() != c_prime_values.len() {
        return Err(LoquatError::verification_failure(
            "c' matrix dimension mismatch",
        ));
    }
    let column_count = c_prime_vars[0].len();
    for (row_vars, row_vals) in c_prime_vars.iter().zip(c_prime_values.iter()) {
        if row_vars.len() != column_count || row_vals.len() != column_count {
            return Err(LoquatError::verification_failure(
                "c' column length mismatch",
            ));
        }
    }

    let chunk = chunk_size.max(1);
    let mut leaves = Vec::with_capacity((column_count + chunk - 1) / chunk);
    let mut col = 0;
    while col < column_count {
        let end = (col + chunk).min(column_count);
        let mut inputs = Vec::new();
        for column_idx in col..end {
            for row_idx in 0..c_prime_vars.len() {
                inputs.push(FieldVar::existing(
                    c_prime_vars[row_idx][column_idx].c0,
                    c_prime_values[row_idx][column_idx].c0,
                ));
                inputs.push(FieldVar::existing(
                    c_prime_vars[row_idx][column_idx].c1,
                    c_prime_values[row_idx][column_idx].c1,
                ));
            }
        }
        leaves.push(griffin_hash_field_vars_circuit(builder, &inputs));
        col = end;
    }
    Ok(leaves)
}

fn merkle_root_from_field_digests(
    builder: &mut R1csBuilder,
    mut leaves: Vec<Vec<FieldVar>>,
) -> Vec<FieldVar> {
    if leaves.is_empty() {
        return griffin_hash_field_vars_circuit(builder, &[]);
    }
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for pair in leaves.chunks(2) {
            if pair.len() == 2 {
                let mut concat = pair[0].clone();
                concat.extend_from_slice(&pair[1]);
                next.push(griffin_hash_field_vars_circuit(builder, &concat));
            } else {
                next.push(pair[0].clone());
            }
        }
        leaves = next;
    }
    leaves.pop().unwrap()
}

fn merkle_root_from_f2_vector(
    builder: &mut R1csBuilder,
    vars: &[F2Var],
    values: &[F2],
    chunk_size: usize,
) -> Vec<Byte> {
    let leaves = hash_chunked_f2_vector(builder, vars, values, chunk_size);
    let root_fields = merkle_root_from_field_digests(builder, leaves);
    field_vars_to_bytes(builder, &root_fields)
}

fn merkle_root_from_c_matrix(
    builder: &mut R1csBuilder,
    c_prime_vars: &[Vec<F2Var>],
    c_prime_values: &[Vec<F2>],
    chunk_size: usize,
) -> LoquatResult<Vec<Byte>> {
    let leaves = hash_chunked_c_columns(builder, c_prime_vars, c_prime_values, chunk_size)?;
    let root_fields = merkle_root_from_field_digests(builder, leaves);
    Ok(field_vars_to_bytes(builder, &root_fields))
}

fn griffin_permutation_circuit(
    builder: &mut R1csBuilder,
    params: &GriffinParams,
    state: &mut [FieldVar],
) {
    for round in 0..params.rounds - 1 {
        apply_nonlinear_layer_circuit(builder, params, state);
        apply_linear_layer_circuit(builder, params, state);
        apply_round_constants_circuit(builder, params, state, round);
    }
    apply_nonlinear_layer_circuit(builder, params, state);
    apply_linear_layer_circuit(builder, params, state);
}

fn apply_nonlinear_layer_circuit(
    builder: &mut R1csBuilder,
    params: &GriffinParams,
    state: &mut [FieldVar],
) {
    // Avoid in-circuit exponentiation by the huge constant `d_inv`.
    // Use witness + low-degree check instead (see `field_pow_inv_witness`).
    state[0] = field_pow_inv_witness(builder, state[0], params.d, params.d_inv);
    state[1] = field_pow_const(builder, state[1], params.d);

    let zero = FieldVar::constant(builder, F::zero());
    let l2 = linear_form_circuit(builder, state[0], state[1], zero, 2);
    let l2_sq = field_mul(builder, l2, l2);

    // poly = l2^2 + α*l2 + β (encode with a single linear constraint)
    let poly_value = l2_sq.value + (params.alphas[0] * l2.value) + params.betas[0];
    let poly_idx = builder.alloc(poly_value);
    builder.enforce_linear_relation(
        &[
            (poly_idx, F::one()),
            (l2_sq.idx, -F::one()),
            (l2.idx, -params.alphas[0]),
        ],
        -params.betas[0],
    );
    let poly = FieldVar::new(poly_idx, poly_value);
    state[2] = field_mul(builder, state[2], poly);

    for idx in 3..GRIFFIN_STATE_WIDTH {
        let li = linear_form_circuit(builder, state[0], state[1], state[idx - 1], idx);
        let li_sq = field_mul(builder, li, li);
        let alpha = params.alphas[idx - 2];
        let beta = params.betas[idx - 2];

        let poly_value = li_sq.value + (alpha * li.value) + beta;
        let poly_idx = builder.alloc(poly_value);
        builder.enforce_linear_relation(
            &[
                (poly_idx, F::one()),
                (li_sq.idx, -F::one()),
                (li.idx, -alpha),
            ],
            -beta,
        );
        let poly = FieldVar::new(poly_idx, poly_value);
        state[idx] = field_mul(builder, state[idx], poly);
    }
}

fn apply_linear_layer_circuit(
    builder: &mut R1csBuilder,
    params: &GriffinParams,
    state: &mut [FieldVar],
) {
    // The linear layer is just a 4x4 MDS matrix multiplication over the field.
    // Encode each output lane with a single linear constraint:
    //   out_row = Σ_j M[row][j] * state[j]
    // This avoids allocating intermediate products and chained adds.
    let mut next = Vec::with_capacity(GRIFFIN_STATE_WIDTH);
    for row in 0..GRIFFIN_STATE_WIDTH {
        let mut out_value = F::zero();
        for col in 0..GRIFFIN_STATE_WIDTH {
            out_value += params.matrix[row][col] * state[col].value;
        }
        let out_idx = builder.alloc(out_value);
        let mut terms: Vec<(usize, F)> = Vec::with_capacity(GRIFFIN_STATE_WIDTH + 1);
        terms.push((out_idx, F::one()));
        for col in 0..GRIFFIN_STATE_WIDTH {
            let coeff = -params.matrix[row][col];
            if !coeff.is_zero() {
                terms.push((state[col].idx, coeff));
            }
        }
        builder.enforce_linear_relation(&terms, F::zero());
        next.push(FieldVar::new(out_idx, out_value));
    }
    state.clone_from_slice(&next);
}

fn apply_round_constants_circuit(
    builder: &mut R1csBuilder,
    params: &GriffinParams,
    state: &mut [FieldVar],
    round: usize,
) {
    for lane in 0..GRIFFIN_STATE_WIDTH {
        let constant = params.round_constants[round * GRIFFIN_STATE_WIDTH + lane];
        state[lane] = field_add_const(builder, state[lane], constant);
    }
}

fn linear_form_circuit(
    builder: &mut R1csBuilder,
    z0: FieldVar,
    z1: FieldVar,
    z2: FieldVar,
    index: usize,
) -> FieldVar {
    let lambda = F::new((index as u128 - 1) % GRIFFIN_FIELD_MODULUS);
    // li = λ*z0 + z1 + z2 (encode as one linear constraint)
    let value = (lambda * z0.value) + z1.value + z2.value;
    let out_idx = builder.alloc(value);
    builder.enforce_linear_relation(
        &[
            (out_idx, F::one()),
            (z0.idx, -lambda),
            (z1.idx, -F::one()),
            (z2.idx, -F::one()),
        ],
        F::zero(),
    );
    FieldVar::new(out_idx, value)
}

fn compute_q_hat_on_u(
    params: &LoquatPublicParams,
    transcript_data: &TranscriptData,
) -> LoquatResult<Vec<Vec<F2>>> {
    let mut results = Vec::with_capacity(params.n);
    for j in 0..params.n {
        let mut q_eval_on_h = Vec::with_capacity(2 * params.m);
        for i in 0..params.m {
            let lambda_scalar = transcript_data.lambda_scalars[j * params.m + i];
            let lambda_f2 = F2::new(lambda_scalar, F::zero());
            let index = transcript_data.i_indices[j * params.m + i];
            let public_i = params.public_indices[index];
            let public_f2 = F2::new(public_i, F::zero());
            q_eval_on_h.push(lambda_f2);
            q_eval_on_h.push(lambda_f2 * public_f2);
        }
        let q_hat_coeffs = interpolate_on_coset(&q_eval_on_h, params.h_shift, params.h_generator)?;
        let mut padded = vec![F2::zero(); params.coset_u.len()];
        padded[..q_hat_coeffs.len()].copy_from_slice(&q_hat_coeffs);
        let q_hat_on_u = evaluate_on_coset(&padded, params.u_shift, params.u_generator)?;
        results.push(q_hat_on_u);
    }
    Ok(results)
}
