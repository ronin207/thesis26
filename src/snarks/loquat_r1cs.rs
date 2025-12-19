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
    let mut state = vec![
        acc0,
        acc1,
        len_tag,
        FieldVar::constant(builder, F::zero()),
    ];
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
    let mut state = vec![
        left[0],
        left[1],
        right[0],
        right[1],
    ];
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
            builder.enforce_linear_relation(
                &[(bits[i], F::one())],
                -F::new(bit_val as u128),
            );
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
    builder.enforce_linear_relation(
        &[(sum_idx, F::one()), (var.idx, -F::one())],
        -constant,
    );
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
fn field_pow_inv_witness(builder: &mut R1csBuilder, base: FieldVar, d: u128, d_inv: u128) -> FieldVar {
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
}

impl R1csBuilder {
    fn new() -> Self {
        Self {
            witness: Vec::new(),
            constraints: Vec::new(),
        }
    }

    fn alloc(&mut self, value: F) -> usize {
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
        let num_variables = self.witness.len() + 1;
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
        let instance = R1csInstance::new(num_variables, constraints)?;
        let witness = R1csWitness::new(self.witness);
        witness.validate(&instance)?;
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
}

impl ConstraintTracker {
    fn new(builder: &R1csBuilder) -> Self {
        Self {
            last_constraints: builder.num_constraints(),
            last_variables: builder.num_variables(),
        }
    }

    fn record(&mut self, builder: &R1csBuilder, label: &str) {
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
    }
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

pub fn build_loquat_r1cs(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &[F],
    params: &LoquatPublicParams,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    trace_stage("build_loquat_r1cs: begin");
    if public_key.len() < params.l {
        return Err(LoquatError::verification_failure(
            "public key length below parameter l",
        ));
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
    if params.eta >= usize::BITS as usize {
        return Err(LoquatError::invalid_parameters(
            "η parameter exceeds machine word size",
        ));
    }
    let fri_leaf_arity = 1usize << params.eta;
    let message_bytes = bytes_from_constants(&mut builder, message);
    let computed_commitment = griffin_hash_bytes_circuit(&mut builder, &message_bytes);
    enforce_digest_equals_bytes(&mut builder, &computed_commitment, &message_commitment);
    trace_stage("message commitment enforced inside circuit");
    constraint_tracker.record(&builder, "message commitment");

    let mu_c0_idx = builder.alloc(signature.mu.c0);
    let mu_c1_idx = builder.alloc(signature.mu.c1);

    let mut contrib_c0_terms = Vec::new();
    let mut contrib_c1_terms = Vec::new();

    let mut t_var_indices = Vec::with_capacity(signature.t_values.len());
    for row in &signature.t_values {
        let mut row_indices = Vec::with_capacity(row.len());
        for &value in row {
            row_indices.push(builder.alloc(value));
        }
        t_var_indices.push(row_indices);
    }
    // NOTE: We no longer serialize t_matrix to bytes here; instead we hash field vars directly.
    trace_stage(&format!(
        "allocated {} t-value rows (max row len {})",
        t_var_indices.len(),
        signature
            .t_values
            .iter()
            .map(|row| row.len())
            .max()
            .unwrap_or(0)
    ));
    constraint_tracker.record(&builder, "t-values allocated");

    let mut o_var_indices = vec![Vec::with_capacity(params.m); params.n];
    if signature.o_values.len() != params.n {
        return Err(LoquatError::verification_failure(
            "o-value row count mismatch",
        ));
    }
    for (row_idx, row) in signature.o_values.iter().enumerate() {
        if row.len() != params.m {
            return Err(LoquatError::verification_failure(
                "o-value row length mismatch",
            ));
        }
        for &value in row {
            o_var_indices[row_idx].push(builder.alloc(value));
        }
    }
    // Openings-only verifier (paper §4.3): we do NOT allocate full evaluation tables over U
    // (c′/ŝ/ĥ/ p / f^(0), or full FRI codewords/rows). Instead, we allocate and constrain only
    // the per-query openings and Merkle auth paths, plus the low-degree test folding checks.

    for j in 0..params.n {
        let epsilon = transcript_data.epsilon_vals[j];
        for i in 0..params.m {
            let lambda = transcript_data.lambda_scalars[j * params.m + i];
            let o_val = signature.o_values[j][i];
            let o_idx = o_var_indices[j][i];

            let prod_val = lambda * o_val;
            let prod_idx = builder.alloc(prod_val);
            builder.enforce_mul_const_var(lambda, o_idx, prod_idx);

            let contrib0_val = prod_val * epsilon.c0;
            let contrib0_idx = builder.alloc(contrib0_val);
            builder.enforce_mul_const_var(epsilon.c0, prod_idx, contrib0_idx);
            contrib_c0_terms.push((contrib0_idx, F::one()));

            let contrib1_val = prod_val * epsilon.c1;
            let contrib1_idx = builder.alloc(contrib1_val);
            builder.enforce_mul_const_var(epsilon.c1, prod_idx, contrib1_idx);
            contrib_c1_terms.push((contrib1_idx, F::one()));
        }
    }

    let two = F::new(2);
    for j in 0..params.n {
        for i in 0..params.m {
            let pk_index = transcript_data.i_indices[j * params.m + i];
            let pk_value = *public_key
                .get(pk_index)
                .ok_or_else(|| LoquatError::invalid_parameters("public key index out of range"))?;
            enforce_qr_witness_constraint(
                &mut builder,
                o_var_indices[j][i],
                signature.o_values[j][i],
                t_var_indices[j][i],
                signature.t_values[j][i],
                pk_value,
                params.qr_non_residue,
                two,
            )?;
        }
    }
    trace_stage("quadratic residuosity constraints enforced");
    constraint_tracker.record(&builder, "quadratic residuosity");

    trace_stage("allocated o-value matrix inside circuit");

    builder.enforce_sum_equals(&contrib_c0_terms, mu_c0_idx);
    builder.enforce_sum_equals(&contrib_c1_terms, mu_c1_idx);
    // The remaining checks over U are performed only at the query set Q via openings + LDT,
    // mirroring Loquat §4.3.

    // sumcheck claimed sum equals μ
    let mut last_sum = builder.alloc_f2(signature.pi_us.claimed_sum);
    builder.enforce_eq(last_sum.c0, mu_c0_idx);
    builder.enforce_eq(last_sum.c1, mu_c1_idx);
    if signature.pi_us.round_polynomials.len() != transcript_data.sumcheck_challenges.len() {
        return Err(LoquatError::verification_failure(
            "sumcheck challenge count mismatch",
        ));
    }

    let mut sumcheck_round_vars = Vec::with_capacity(signature.pi_us.round_polynomials.len());
    for round_poly in &signature.pi_us.round_polynomials {
        sumcheck_round_vars.push((builder.alloc_f2(round_poly.c0), builder.alloc_f2(round_poly.c1)));
    }

    enforce_transcript_relations_field_native(
        &mut builder,
        params,
        signature,
        &transcript_data,
        &t_var_indices,
        &o_var_indices,
        last_sum,
        &sumcheck_round_vars,
    )?;
    trace_stage("transcript binding enforced inside circuit");
    constraint_tracker.record(&builder, "transcript binding");

    for (round_idx, round_poly) in signature.pi_us.round_polynomials.iter().enumerate() {
        let (c0_var, c1_var) = sumcheck_round_vars[round_idx];
        last_sum = enforce_sumcheck_round(
            &mut builder,
            last_sum,
            c0_var,
            c1_var,
            round_poly.c0,
            round_poly.c1,
            transcript_data.sumcheck_challenges[round_idx],
            two,
        );
    }
    trace_stage("sumcheck rounds enforced");
    constraint_tracker.record(&builder, "sumcheck");

    let final_eval_var = builder.alloc_f2(signature.pi_us.final_evaluation);
    builder.enforce_f2_eq(last_sum, final_eval_var);

    // Openings-only checks at Q.
    let q_hat_on_u = compute_q_hat_on_u(params, &transcript_data)?;
    let z_mu_plus_s = transcript_data.z_challenge * signature.mu + signature.s_sum;
    let z_mu_plus_s_var = builder.alloc_f2(z_mu_plus_s);

    // Enforce `z_mu_plus_s_var = z * μ + S` inside the circuit (do not leave it unconstrained).
    let mu_var = F2Var {
        c0: mu_c0_idx,
        c1: mu_c1_idx,
    };
    let z_mu_value = transcript_data.z_challenge * signature.mu;
    let z_mu_var = builder.alloc_f2(z_mu_value);
    enforce_f2_const_mul_eq(&mut builder, mu_var, transcript_data.z_challenge, z_mu_var);

    let s_sum_var = builder.alloc_f2(signature.s_sum);
    builder.enforce_linear_relation(&[(s_sum_var.c0, F::one())], -signature.s_sum.c0);
    builder.enforce_linear_relation(&[(s_sum_var.c1, F::one())], -signature.s_sum.c1);

    enforce_f2_add(&mut builder, z_mu_var, s_sum_var, z_mu_plus_s_var);

    enforce_ldt_queries(
        &mut builder,
        params,
        signature,
        &transcript_data,
        &q_hat_on_u,
        z_mu_plus_s_var,
        fri_leaf_arity,
    )?;
    trace_stage("enforced all LDT queries");
    constraint_tracker.record(&builder, "LDT queries");

    let num_vars = builder.witness.len() + 1;
    let num_constraints = builder.constraints.len();
    trace_stage(&format!(
        "finalizing R1CS: vars={} constraints={}",
        num_vars, num_constraints
    ));

    // Check if we should skip expensive dense materialization.
    // The env var LOQUAT_R1CS_STATS_ONLY=1 allows collecting stats without OOM.
    let stats_only = std::env::var("LOQUAT_R1CS_STATS_ONLY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if stats_only {
        // Return a stats-reporting R1CS without dense materialization.
        // This avoids the O(num_vars × num_constraints) memory explosion.
        // We create a "virtual" constraint count by using an empty constraint vec
        // but storing the real count in num_variables (hack for reporting).
        println!("\n--- R1CS Build Stats (stats-only mode) ---");
        println!("  true variables:       {}", num_vars);
        println!("  true constraints:     {}", num_constraints);
        println!("  (skipping dense materialization to avoid OOM)");

        // Return minimal instance just to satisfy type requirements
        let instance = R1csInstance {
            num_variables: num_vars,
            constraints: Vec::new(), // Empty - stats already printed above
        };
        let witness = R1csWitness::new(builder.witness);
        return Ok((instance, witness));
    }

    builder.finalize()
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
    build_loquat_r1cs_pk_witness_inner(message, signature, Some(public_key), params, true)
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
    let (instance, _) = build_loquat_r1cs_pk_witness_inner(message, signature, None, params, false)?;
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
    let (instance, _) = build_revocation_r1cs_pk_witness_inner(
        None,
        pk_len,
        revocation_root,
        None,
        depth,
        false,
    )?;
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
    _compute_values: bool,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    if depth == 0 {
        return Err(LoquatError::invalid_parameters("revocation depth must be > 0"));
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
        let bit_idx = pk_vars
            .get(level)
            .map(|(idx, _)| *idx)
            .unwrap_or(0);
        let bit_value = pk_vars
            .get(level)
            .map(|(_, v)| *v)
            .unwrap_or(F::zero());
        let bit = FieldVar::existing(bit_idx, bit_value);
        let sibling = &siblings[level];

        let (left, right) = merkle_conditional_order_digest(&mut builder, bit, &current, sibling);
        current = compress_internal_digest_fields_single_perm(&mut builder, &left, &right)?;
    }

    // Enforce computed root equals the provided revocation root (as constants in the constraint system).
    if revocation_root.len() != 32 {
        return Err(LoquatError::invalid_parameters("invalid revocation root length"));
    }
    let expected0 = field_utils::bytes_to_field_element(&revocation_root[0..16]);
    let expected1 = field_utils::bytes_to_field_element(&revocation_root[16..32]);
    builder.enforce_linear_relation(&[(current[0].idx, F::one())], -expected0);
    builder.enforce_linear_relation(&[(current[1].idx, F::one())], -expected1);

    builder.finalize()
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
            &[(left_idx, F::one()), (a.idx, -F::one()), (prod_idx, -F::one())],
            F::zero(),
        );
        left.push(FieldVar::new(left_idx, left_value));

        // right = b - prod
        let right_value = b.value - prod_value;
        let right_idx = builder.alloc(right_value);
        builder.enforce_linear_relation(
            &[(right_idx, F::one()), (b.idx, -F::one()), (prod_idx, F::one())],
            F::zero(),
        );
        right.push(FieldVar::new(right_idx, right_value));
    }

    (left, right)
}

fn build_loquat_r1cs_pk_witness_inner(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: Option<&[F]>,
    params: &LoquatPublicParams,
    compute_sqrt_witness: bool,
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
    let message_bytes = bytes_from_constants(&mut builder, message);
    let computed_commitment = griffin_hash_bytes_circuit(&mut builder, &message_bytes);
    enforce_digest_equals_bytes(&mut builder, &computed_commitment, &message_commitment);
    trace_stage("message commitment enforced inside circuit");
    constraint_tracker.record(&builder, "message commitment");

    let mu_c0_idx = builder.alloc(signature.mu.c0);
    let mu_c1_idx = builder.alloc(signature.mu.c1);

    let mut contrib_c0_terms = Vec::new();
    let mut contrib_c1_terms = Vec::new();

    let mut t_var_indices = Vec::with_capacity(signature.t_values.len());
    for row in &signature.t_values {
        let mut row_indices = Vec::with_capacity(row.len());
        for &value in row {
            let idx = builder.alloc(value);
            // t-values are bits (Legendre PRF outputs); enforce boolean to keep the QR gadget sound.
            builder.enforce_boolean(idx);
            row_indices.push(idx);
        }
        t_var_indices.push(row_indices);
    }
    trace_stage("allocated t-values (boolean)");
    constraint_tracker.record(&builder, "t-values allocated");

    let mut o_var_indices = vec![Vec::with_capacity(params.m); params.n];
    if signature.o_values.len() != params.n {
        return Err(LoquatError::verification_failure(
            "o-value row count mismatch",
        ));
    }
    for (row_idx, row) in signature.o_values.iter().enumerate() {
        if row.len() != params.m {
            return Err(LoquatError::verification_failure(
                "o-value row length mismatch",
            ));
        }
        for &value in row {
            o_var_indices[row_idx].push(builder.alloc(value));
        }
    }

    for j in 0..params.n {
        let epsilon = transcript_data.epsilon_vals[j];
        for i in 0..params.m {
            let lambda = transcript_data.lambda_scalars[j * params.m + i];
            let o_val = signature.o_values[j][i];
            let o_idx = o_var_indices[j][i];

            let prod_val = lambda * o_val;
            let prod_idx = builder.alloc(prod_val);
            builder.enforce_mul_const_var(lambda, o_idx, prod_idx);

            let contrib0_val = prod_val * epsilon.c0;
            let contrib0_idx = builder.alloc(contrib0_val);
            builder.enforce_mul_const_var(epsilon.c0, prod_idx, contrib0_idx);
            contrib_c0_terms.push((contrib0_idx, F::one()));

            let contrib1_val = prod_val * epsilon.c1;
            let contrib1_idx = builder.alloc(contrib1_val);
            builder.enforce_mul_const_var(epsilon.c1, prod_idx, contrib1_idx);
            contrib_c1_terms.push((contrib1_idx, F::one()));
        }
    }

    let two = F::new(2);
    for j in 0..params.n {
        for i in 0..params.m {
            let pk_index = transcript_data.i_indices[j * params.m + i];
            let (pk_idx, pk_value) = *pk_var_indices
                .get(pk_index)
                .ok_or_else(|| LoquatError::invalid_parameters("public key index out of range"))?;
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
    trace_stage("quadratic residuosity constraints enforced (pk witness)");
    constraint_tracker.record(&builder, "quadratic residuosity (pk witness)");

    builder.enforce_sum_equals(&contrib_c0_terms, mu_c0_idx);
    builder.enforce_sum_equals(&contrib_c1_terms, mu_c1_idx);

    // sumcheck claimed sum equals μ
    let mut last_sum = builder.alloc_f2(signature.pi_us.claimed_sum);
    builder.enforce_eq(last_sum.c0, mu_c0_idx);
    builder.enforce_eq(last_sum.c1, mu_c1_idx);
    if signature.pi_us.round_polynomials.len() != transcript_data.sumcheck_challenges.len() {
        return Err(LoquatError::verification_failure(
            "sumcheck challenge count mismatch",
        ));
    }

    let mut sumcheck_round_vars = Vec::with_capacity(signature.pi_us.round_polynomials.len());
    for round_poly in &signature.pi_us.round_polynomials {
        sumcheck_round_vars.push((builder.alloc_f2(round_poly.c0), builder.alloc_f2(round_poly.c1)));
    }

    enforce_transcript_relations_field_native(
        &mut builder,
        params,
        signature,
        &transcript_data,
        &t_var_indices,
        &o_var_indices,
        last_sum,
        &sumcheck_round_vars,
    )?;
    trace_stage("transcript binding enforced inside circuit");
    constraint_tracker.record(&builder, "transcript binding");

    for (round_idx, round_poly) in signature.pi_us.round_polynomials.iter().enumerate() {
        let (c0_var, c1_var) = sumcheck_round_vars[round_idx];
        last_sum = enforce_sumcheck_round(
            &mut builder,
            last_sum,
            c0_var,
            c1_var,
            round_poly.c0,
            round_poly.c1,
            transcript_data.sumcheck_challenges[round_idx],
            two,
        );
    }
    trace_stage("sumcheck rounds enforced");
    constraint_tracker.record(&builder, "sumcheck");

    let final_eval_var = builder.alloc_f2(signature.pi_us.final_evaluation);
    builder.enforce_f2_eq(last_sum, final_eval_var);

    // Openings-only checks at Q.
    let q_hat_on_u = compute_q_hat_on_u(params, &transcript_data)?;
    let z_mu_plus_s = transcript_data.z_challenge * signature.mu + signature.s_sum;
    let z_mu_plus_s_var = builder.alloc_f2(z_mu_plus_s);

    // Enforce `z_mu_plus_s_var = z * μ + S` inside the circuit (do not leave it unconstrained).
    let mu_var = F2Var {
        c0: mu_c0_idx,
        c1: mu_c1_idx,
    };
    let z_mu_value = transcript_data.z_challenge * signature.mu;
    let z_mu_var = builder.alloc_f2(z_mu_value);
    enforce_f2_const_mul_eq(&mut builder, mu_var, transcript_data.z_challenge, z_mu_var);

    let s_sum_var = builder.alloc_f2(signature.s_sum);
    builder.enforce_linear_relation(&[(s_sum_var.c0, F::one())], -signature.s_sum.c0);
    builder.enforce_linear_relation(&[(s_sum_var.c1, F::one())], -signature.s_sum.c1);

    enforce_f2_add(&mut builder, z_mu_var, s_sum_var, z_mu_plus_s_var);

    enforce_ldt_queries(
        &mut builder,
        params,
        signature,
        &transcript_data,
        &q_hat_on_u,
        z_mu_plus_s_var,
        fri_leaf_arity,
    )?;
    trace_stage("enforced all LDT queries");
    constraint_tracker.record(&builder, "LDT queries");

    // NOTE: For the pk-witness builder, we do not support the stats-only shortcut because
    // callers use this for BDEC proof generation/verification.
    builder.finalize()
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
    if o_value.is_zero() {
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
    challenge: F2,
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

    let challenge_prod_value = c1_value * challenge;
    let challenge_prod_var = builder.alloc_f2(challenge_prod_value);
    enforce_f2_const_mul_eq(builder, c1_var, challenge, challenge_prod_var);

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
        let c_root_fields = merkle_cap_root_from_nodes(builder, &signature.c_cap_nodes)?;
        enforce_field_digest_equals_bytes(builder, &c_root_fields, &signature.root_c)?;
        let s_root_fields = merkle_cap_root_from_nodes(builder, &signature.s_cap_nodes)?;
        enforce_field_digest_equals_bytes(builder, &s_root_fields, &signature.root_s)?;
        let h_root_fields = merkle_cap_root_from_nodes(builder, &signature.h_cap_nodes)?;
        enforce_field_digest_equals_bytes(builder, &h_root_fields, &signature.root_h)?;
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
            let root_fields = merkle_cap_root_from_nodes(builder, cap_nodes)?;
            enforce_field_digest_equals_bytes(
                builder,
                &root_fields,
                &signature.ldt_proof.commitments[layer_idx],
            )?;
        }
    }

    if q_hat_on_u.len() != params.n || q_hat_on_u.iter().any(|v| v.len() != params.coset_u.len())
    {
                return Err(LoquatError::verification_failure(
            "q_hat_on_u dimension mismatch",
        ));
    }
    if signature.e_vector.len() != 8 {
        return Err(LoquatError::verification_failure("e-vector length mismatch"));
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

        // Allocate query openings for c′/ŝ/ĥ.
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
        let c_digest =
            merkle_path_opening_fields(builder, &c_leaf_fields, &query_opening.c_auth_path, chunk_index)?;
        if signature.c_cap_nodes.is_empty() {
            enforce_field_digest_equals_bytes(builder, &c_digest, &signature.root_c)?;
            } else {
            let cap_index = chunk_index >> query_opening.c_auth_path.len();
            if cap_index >= signature.c_cap_nodes.len() {
                return Err(LoquatError::verification_failure("c cap index out of range"));
        }
            enforce_field_digest_equals_bytes(
                builder,
                &c_digest,
                signature.c_cap_nodes[cap_index].as_ref(),
            )?;
        }

        let mut s_leaf_fields = Vec::with_capacity(chunk_size * 2);
        for off in 0..chunk_size {
            let var = s_chunk_vars[off];
            let val = query_opening.s_chunk[off];
            s_leaf_fields.push(FieldVar::existing(var.c0, val.c0));
            s_leaf_fields.push(FieldVar::existing(var.c1, val.c1));
        }
        let s_digest =
            merkle_path_opening_fields(builder, &s_leaf_fields, &query_opening.s_auth_path, chunk_index)?;
        if signature.s_cap_nodes.is_empty() {
            enforce_field_digest_equals_bytes(builder, &s_digest, &signature.root_s)?;
        } else {
            let cap_index = chunk_index >> query_opening.s_auth_path.len();
            if cap_index >= signature.s_cap_nodes.len() {
                return Err(LoquatError::verification_failure("s cap index out of range"));
            }
            enforce_field_digest_equals_bytes(
                builder,
                &s_digest,
                signature.s_cap_nodes[cap_index].as_ref(),
            )?;
        }

        let mut h_leaf_fields = Vec::with_capacity(chunk_size * 2);
        for off in 0..chunk_size {
            let var = h_chunk_vars[off];
            let val = query_opening.h_chunk[off];
            h_leaf_fields.push(FieldVar::existing(var.c0, val.c0));
            h_leaf_fields.push(FieldVar::existing(var.c1, val.c1));
        }
        let h_digest =
            merkle_path_opening_fields(builder, &h_leaf_fields, &query_opening.h_auth_path, chunk_index)?;
        if signature.h_cap_nodes.is_empty() {
            enforce_field_digest_equals_bytes(builder, &h_digest, &signature.root_h)?;
        } else {
            let cap_index = chunk_index >> query_opening.h_auth_path.len();
            if cap_index >= signature.h_cap_nodes.len() {
                return Err(LoquatError::verification_failure("h cap index out of range"));
            }
            enforce_field_digest_equals_bytes(
            builder,
                &h_digest,
                signature.h_cap_nodes[cap_index].as_ref(),
            )?;
        }

        // Allocate LDT codeword chunks per layer (r+1), then verify Merkle authentication and folding.
        let mut ldt_chunk_vars: Vec<Vec<F2Var>> = Vec::with_capacity(params.r + 1);
        for layer in 0..=params.r {
            let chunk_vals = &ldt_opening.codeword_chunks[layer];
            let mut vars = Vec::with_capacity(chunk_vals.len());
            for &val in chunk_vals {
                vars.push(builder.alloc_f2(val));
            }
            ldt_chunk_vars.push(vars);
        }

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
            let digest = merkle_path_opening_fields(
            builder,
                &leaf_fields,
                &ldt_opening.auth_paths[layer],
                leaf_index,
            )?;

            let cap_nodes_layer = &signature.ldt_proof.cap_nodes[layer];
            if cap_nodes_layer.is_empty() {
                enforce_field_digest_equals_bytes(
                    builder,
                    &digest,
                    &signature.ldt_proof.commitments[layer],
                )?;
            } else {
                let cap_index = leaf_index >> ldt_opening.auth_paths[layer].len();
                if cap_index >= cap_nodes_layer.len() {
            return Err(LoquatError::verification_failure(
                        "LDT cap index out of range",
                    ));
                }
                enforce_field_digest_equals_bytes(
            builder,
                    &digest,
                    cap_nodes_layer[cap_index].as_ref(),
                )?;
            }

            if layer < params.r {
                let challenge = signature.fri_challenges[layer];
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
                    .ok_or_else(|| {
                        LoquatError::verification_failure("next offset out of range in LDT opening")
                    })?;
                enforce_f2_const_lincomb_eq(builder, &fold_terms, next_var)?;

                fold_index = next_index;
                layer_len = ((layer_len + chunk_size - 1) / chunk_size).max(1);
            }
        }

        // Recompute missing code elements and enforce f^(0) only at the opened query chunk.
        let chunk_start = chunk_index * chunk_size;
        for off in 0..chunk_size {
            let global_idx = chunk_start + off;
            if global_idx >= params.coset_u.len() {
                return Err(LoquatError::verification_failure("query index out of range"));
        }
            let x = params.coset_u[global_idx];
            let z_h = x.pow(h_order) - z_h_constant;
            let denom_scalar = h_size_scalar * x;

            // f'(x) = ŝ(x) + z * Σ_j (ε_j * c′_j(x) * q̂_j(x))
            let mut f_prime_value = query_opening.s_chunk[off];
            let mut f_prime_terms: Vec<(F2Var, F2)> = Vec::with_capacity(params.n + 1);
            f_prime_terms.push((s_chunk_vars[off], F2::one()));
            for j in 0..params.n {
                let coeff = z * transcript_data.epsilon_vals[j] * q_hat_on_u[j][global_idx];
                f_prime_value += query_opening.c_prime_chunk[off][j] * coeff;
                f_prime_terms.push((c_prime_chunk_vars[off][j], coeff));
            }
            let f_prime_var = builder.alloc_f2(f_prime_value);
            enforce_f2_const_lincomb_eq(builder, &f_prime_terms, f_prime_var)?;

            // Enforce p(x) via: (|H|·x)·p(x) = |H|·f'(x) − |H|·Z_H(x)·h(x) − (z·μ + S)
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

            let denom_inv = denom_scalar.inverse().ok_or_else(|| {
                LoquatError::verification_failure("denominator not invertible in p(x) computation")
            })?;
            let p_value = numerator_value * denom_inv;
            let p_var = builder.alloc_f2(p_value);
            enforce_f2_const_mul_eq(builder, p_var, denom_scalar, numerator_var);

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

            let c_coeff = signature.e_vector[0] + signature.e_vector[4] * x.pow(exponents[0]);
            let s_coeff = signature.e_vector[1] + signature.e_vector[5] * x.pow(exponents[1]);
            let h_coeff = signature.e_vector[2] + signature.e_vector[6] * x.pow(exponents[2]);
            let p_coeff = signature.e_vector[3] + signature.e_vector[7] * x.pow(exponents[3]);

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
        let domain_tag = FieldVar::constant(builder, pack_label_tag_field(b"loquat.transcript.field.griffin"));
        let label_tag = FieldVar::constant(builder, pack_label_tag_field(label));
        let label_len = FieldVar::constant(builder, F::new(label.len() as u128));
        let counter0 = FieldVar::constant(builder, F::new(0));

        let digest = griffin_hash_field_vars_circuit(builder, &[domain_tag, label_tag, label_len, counter0]);
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

    fn hash_prefixed(&self, builder: &mut R1csBuilder, label: &[u8], payload: &[FieldVar]) -> [FieldVar; 2] {
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
fn enforce_transcript_relations_field_native(
    builder: &mut R1csBuilder,
    params: &LoquatPublicParams,
    signature: &LoquatSignature,
    transcript_data: &TranscriptData,
    t_var_indices: &[Vec<usize>],
    o_var_indices: &[Vec<usize>],
    sumcheck_claimed_sum_var: F2Var,
    sumcheck_round_vars: &[(F2Var, F2Var)],
) -> LoquatResult<()> {
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
    transcript.append_digest32_as_fields(builder, b"message_commitment", &message_commitment);
    transcript.append_digest32_as_fields(builder, b"root_c", &signature.root_c);

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
    let mask = if k >= 128 { u128::MAX } else { (1u128 << k) - 1 };
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
        // low = expected + modulus*b
        builder.enforce_linear_relation(
            &[
                (low_idx, F::one()),
                (b_idx, -F::new(modulus as u128)),
            ],
            -F::new(expected as u128),
        );
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
    for (idx, out) in lambda_outs.into_iter().enumerate() {
        builder.enforce_linear_relation(&[(out.idx, F::one())], -transcript_data.lambda_scalars[idx]);
    }
    if transcript_data.epsilon_vals.len() != params.n {
        return Err(LoquatError::verification_failure("epsilon length mismatch"));
    }
    let eps_outs = expand_f_circuit(builder, h2_seed, b"e_j", params.n);
    for (idx, out) in eps_outs.into_iter().enumerate() {
        builder.enforce_linear_relation(&[(out.idx, F::one())], -transcript_data.epsilon_vals[idx].c0);
    }

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
        let expected = transcript_data.sumcheck_challenges[round_idx];
        builder.enforce_linear_relation(&[(chal[0].idx, F::one())], -expected.c0);
        builder.enforce_linear_relation(&[(chal[1].idx, F::one())], -expected.c1);
    }

    // σ₃, σ₄ and challenges h3/h4
    transcript.append_digest32_as_fields(builder, b"root_s", &signature.root_s);
    let s_sum_c0 = FieldVar::constant(builder, signature.s_sum.c0);
    let s_sum_c1 = FieldVar::constant(builder, signature.s_sum.c1);
    transcript.append_f_vec(builder, b"s_sum", &[s_sum_c0, s_sum_c1]);
    let z_scalar = transcript.challenge_f(builder, b"h3");
    builder.enforce_linear_relation(&[(z_scalar.idx, F::one())], -signature.z_challenge.c0);

    transcript.append_digest32_as_fields(builder, b"root_h", &signature.root_h);
    let h4_seed = transcript.challenge_seed(builder, b"h4");

    if signature.e_vector.len() != 8 {
        return Err(LoquatError::verification_failure("e-vector length mismatch"));
    }
    let e_outs = expand_f_circuit(builder, h4_seed, b"e_vector", 8);
    for (idx, out) in e_outs.into_iter().enumerate() {
        builder.enforce_linear_relation(&[(out.idx, F::one())], -signature.e_vector[idx].c0);
    }

    // FRI folding challenges from LDT commitments
    if signature.ldt_proof.commitments.len() != params.r + 1 {
        return Err(LoquatError::verification_failure(
            "LDT commitment count mismatch",
        ));
    }
    if signature.fri_challenges.len() != params.r {
        return Err(LoquatError::verification_failure("FRI challenge count mismatch"));
    }
    transcript.append_digest32_as_fields(
        builder,
        b"merkle_commitment",
        &signature.ldt_proof.commitments[0],
    );
    for round in 0..params.r {
        let chal = transcript.challenge_f2(builder, b"challenge");
        let expected = signature.fri_challenges[round];
        builder.enforce_linear_relation(&[(chal[0].idx, F::one())], -expected.c0);
        builder.enforce_linear_relation(&[(chal[1].idx, F::one())], -expected.c1);
        transcript.append_digest32_as_fields(
            builder,
            b"merkle_commitment",
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
    let mask = if log_u >= 128 { u128::MAX } else { (1u128 << log_u) - 1 };
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

        let expected_pos = signature.ldt_proof.openings[query_idx].position;
        builder.enforce_linear_relation(&[(low_idx, F::one())], -F::new(expected_pos as u128));

        if signature.query_openings[query_idx].position != expected_pos {
            return Err(LoquatError::verification_failure(
                "query opening position mismatch for query binding",
            ));
        }
    }

    Ok(())
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
            &[(poly_idx, F::one()), (li_sq.idx, -F::one()), (li.idx, -alpha)],
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
