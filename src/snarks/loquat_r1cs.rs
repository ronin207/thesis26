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
    let mut acc0: Option<FieldVar> = None;
    let mut acc1: Option<FieldVar> = None;
    for (idx, field) in leaf_fields.iter().enumerate() {
        let target = if idx % 2 == 0 {
            &mut acc0
        } else {
            &mut acc1
        };
        *target = Some(match target.take() {
            None => *field,
            Some(prev) => field_add(builder, prev, *field),
        });
    }
    let zero = FieldVar::constant(builder, F::zero());
    let acc0 = acc0.unwrap_or(zero);
    let acc1 = acc1.unwrap_or(zero);
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
        let mut concat = Vec::with_capacity(current.len() + sibling_fields.len());
        if idx % 2 == 0 {
            concat.extend_from_slice(&current);
            concat.extend_from_slice(&sibling_fields);
        } else {
            concat.extend_from_slice(&sibling_fields);
            concat.extend_from_slice(&current);
        }
        current = griffin_hash_field_vars_circuit(builder, &concat);
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

use crate::loquat::encoding;
use crate::loquat::errors::{LoquatError, LoquatResult};
use crate::loquat::fft::{evaluate_on_coset, interpolate_on_coset};
use crate::loquat::field_utils::{self, F, F2, field_to_u128, field2_to_bytes, sqrt_canonical};
use crate::loquat::griffin::{
    GRIFFIN_DIGEST_ELEMENTS, GRIFFIN_FIELD_MODULUS, GRIFFIN_RATE, GRIFFIN_STATE_WIDTH,
    GriffinParams, get_griffin_params,
};
use crate::loquat::hasher::{GriffinHasher, LoquatHasher};
use crate::loquat::setup::LoquatPublicParams;
use crate::loquat::sign::LoquatSignature;
use crate::loquat::sumcheck::replay_sumcheck_challenges;
use crate::loquat::transcript::Transcript;
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
    builder.enforce_linear_relation(&[(sum_idx, F::one()), (var.idx, -F::one())], constant);
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

fn expand_challenge<T>(
    seed: &[u8],
    count: usize,
    domain_separator: &[u8],
    parser: &mut dyn FnMut(&[u8]) -> T,
) -> Vec<T> {
    let mut results = Vec::with_capacity(count);
    let mut counter: u32 = 0;
    while results.len() < count {
        let mut hasher = GriffinHasher::new();
        hasher.update(seed);
        hasher.update(domain_separator);
        hasher.update(&counter.to_le_bytes());
        let hash_output = hasher.finalize();
        results.push(parser(&hash_output));
        counter += 1;
    }
    results
}

fn replay_transcript_data(
    message: &[u8],
    signature: &LoquatSignature,
    params: &LoquatPublicParams,
) -> LoquatResult<TranscriptData> {
    let mut transcript = Transcript::new(b"loquat_signature");
    transcript.append_message(b"message", message);

    let message_commitment = GriffinHasher::hash(message);
    if message_commitment != signature.message_commitment {
        return Err(LoquatError::verification_failure(
            "message commitment mismatch",
        ));
    }
    transcript.append_message(b"message_commitment", &message_commitment);

    transcript.append_message(b"root_c", &signature.root_c);
    let t_bytes = encoding::serialize_field_matrix(&signature.t_values);
    transcript.append_message(b"t_values", &t_bytes);

    let mut h1_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h1", &mut h1_bytes);
    let num_checks = params.m * params.n;
    let i_indices = expand_challenge(&h1_bytes, num_checks, b"I_indices", &mut |b| {
        (u64::from_le_bytes(b[0..8].try_into().unwrap()) as usize) % params.l
    });

    let o_bytes = encoding::serialize_field_matrix(&signature.o_values);
    transcript.append_message(b"o_values", &o_bytes);

    let mut h2_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h2", &mut h2_bytes);
    let lambda_scalars = expand_challenge(&h2_bytes, num_checks, b"lambdas", &mut |b| {
        field_utils::bytes_to_field_element(b)
    });
    let epsilon_vals = expand_challenge(&h2_bytes, params.n, b"e_j", &mut |b| {
        F2::new(field_utils::bytes_to_field_element(b), F::zero())
    });

    let num_variables = (params.coset_h.len()).trailing_zeros() as usize;
    let sumcheck_challenges =
        replay_sumcheck_challenges(&signature.pi_us, num_variables, &mut transcript)?;

    transcript.append_message(b"root_s", &signature.root_s);
    let s_sum_bytes = field2_to_bytes(&signature.s_sum);
    transcript.append_message(b"s_sum", &s_sum_bytes);
    let mut h3_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h3", &mut h3_bytes);
    let z_scalar = field_utils::bytes_to_field_element(&h3_bytes);
    let z_challenge = F2::new(z_scalar, F::zero());

    transcript.append_message(b"root_h", &signature.root_h);
    let mut h4_bytes = [0u8; 32];
    transcript.challenge_bytes(b"h4", &mut h4_bytes);
    let e_vector = expand_challenge(&h4_bytes, 8, b"e_vector", &mut |b| {
        F2::new(field_utils::bytes_to_field_element(b), F::zero())
    });

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
    if signature.ldt_proof.openings.len() != params.kappa {
        return Err(LoquatError::verification_failure(
            "LDT opening count mismatch",
        ));
    }
    if signature.fri_codewords.len() != params.r + 1
        || signature.fri_rows.len() != params.r + 1
        || signature.fri_challenges.len() != params.r
    {
        return Err(LoquatError::verification_failure(
            "FRI transcript length mismatch",
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
    // Byte representations of commitments (still used for root equality checks)
    let message_commitment_bytes = bytes_from_constants(&mut builder, &message_commitment);
    let root_c_bytes = bytes_from_constants(&mut builder, &signature.root_c);
    let root_s_bytes = bytes_from_constants(&mut builder, &signature.root_s);
    let root_h_bytes = bytes_from_constants(&mut builder, &signature.root_h);

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

    // allocate evaluation tables
    let mut c_prime_vars = Vec::with_capacity(signature.c_prime_evals.len());
    for row in &signature.c_prime_evals {
        let mut row_vars = Vec::with_capacity(row.len());
        for &value in row {
            row_vars.push(builder.alloc_f2(value));
        }
        c_prime_vars.push(row_vars);
    }

    let mut pi_row_vars = Vec::with_capacity(signature.pi_rows.len());
    for row in &signature.pi_rows {
        let mut row_vars = Vec::with_capacity(row.len());
        for &value in row {
            row_vars.push(builder.alloc_f2(value));
        }
        pi_row_vars.push(row_vars);
    }

    // Allocate s(u) evaluations and enforce sum constraint
    let mut s_vars = Vec::with_capacity(signature.s_evals.len());
    for &value in &signature.s_evals {
        s_vars.push(builder.alloc_f2(value));
    }
    builder.enforce_f2_sum_equals_const(&s_vars, signature.s_sum);
    trace_stage("s(u) values allocated");
    constraint_tracker.record(&builder, "s(u) alloc");

    // Allocate h(u) evaluations
    let mut h_vars = Vec::with_capacity(signature.h_evals.len());
    for &value in &signature.h_evals {
        h_vars.push(builder.alloc_f2(value));
    }
    trace_stage("h(u) values allocated");
    constraint_tracker.record(&builder, "h(u) alloc");
    let mut p_vars = Vec::with_capacity(signature.p_evals.len());
    for &value in &signature.p_evals {
        p_vars.push(builder.alloc_f2(value));
    }
    let mut f_prime_vars = Vec::with_capacity(signature.f_prime_evals.len());
    for &value in &signature.f_prime_evals {
        f_prime_vars.push(builder.alloc_f2(value));
    }

    let mut f0_vars = Vec::with_capacity(signature.f0_evals.len());
    for &value in &signature.f0_evals {
        f0_vars.push(builder.alloc_f2(value));
    }

    let mut fri_codeword_vars = Vec::with_capacity(signature.fri_codewords.len());
    for layer in &signature.fri_codewords {
        let mut layer_vars = Vec::with_capacity(layer.len());
        for &value in layer {
            layer_vars.push(builder.alloc_f2(value));
        }
        fri_codeword_vars.push(layer_vars);
    }

    let mut fri_row_vars = Vec::with_capacity(signature.fri_rows.len());
    for row_layer in &signature.fri_rows {
        let mut layer_rows = Vec::with_capacity(row_layer.len());
        for row in row_layer {
            let mut row_vars = Vec::with_capacity(row.len());
            for &value in row {
                row_vars.push(builder.alloc_f2(value));
            }
            layer_rows.push(row_vars);
        }
        if layer_rows.len() != pi_row_vars.len() {
            return Err(LoquatError::verification_failure(
                "Π row count mismatch in FRI rows",
            ));
        }
        fri_row_vars.push(layer_rows);
    }

    trace_stage("c'(u) values allocated (auth-path verified)");
    constraint_tracker.record(&builder, "c'(u) alloc (auth-path)");

    // NOTE: FRI layer commitment verification is done via auth paths in enforce_ldt_queries.
    // Building full Merkle trees here would be redundant and expensive.
    trace_stage("FRI layer commitments (verified via LDT auth paths)");
    constraint_tracker.record(&builder, "FRI commitments (skipped - auth paths)");

    let q_hat_on_u = compute_q_hat_on_u(params, &transcript_data)?;
    let h_order = params.coset_h.len() as u128;
    let z_h_constant = params.h_shift.pow(h_order);
    let z_h_on_u: Vec<F2> = params
        .coset_u
        .iter()
        .map(|&u| u.pow(h_order) - z_h_constant)
        .collect();
    let h_size_scalar = F2::new(F::new(params.coset_h.len() as u128), F::zero());
    let z_mu_plus_s = transcript_data.z_challenge * signature.mu + signature.s_sum;
    let z_mu_plus_s_var = builder.alloc_f2(z_mu_plus_s);
    let mut f_on_u_vars = Vec::with_capacity(params.coset_u.len());
    let mut f_on_u_values = Vec::with_capacity(params.coset_u.len());
    for idx in 0..params.coset_u.len() {
        let mut partial_var: Option<F2Var> = None;
        let mut partial_value = F2::zero();
        for j in 0..params.n {
            let c_value = signature.c_prime_evals[j][idx];
            let q_value = q_hat_on_u[j][idx];
            let prod_value = c_value * q_value;
            let prod_var = builder.alloc_f2(prod_value);
            enforce_f2_const_mul_eq(&mut builder, c_prime_vars[j][idx], q_value, prod_var);

            let epsilon = transcript_data.epsilon_vals[j];
            let eps_value = prod_value * epsilon;
            let eps_var = builder.alloc_f2(eps_value);
            enforce_f2_const_mul_eq(&mut builder, prod_var, epsilon, eps_var);

            match partial_var.take() {
                None => {
                    partial_var = Some(eps_var);
                    partial_value = eps_value;
                }
                Some(prev_var) => {
                    let new_value = partial_value + eps_value;
                    let new_var = builder.alloc_f2(new_value);
                    enforce_f2_add(&mut builder, prev_var, eps_var, new_var);
                    partial_var = Some(new_var);
                    partial_value = new_value;
                }
            }
        }
        let final_var = partial_var.expect("at least one term");
        f_on_u_vars.push(final_var);
        f_on_u_values.push(partial_value);
    }

    // Π₀ rows relations
    for idx in 0..params.coset_u.len() {
        let sum_inputs: Vec<F2Var> = c_prime_vars.iter().map(|row| row[idx]).collect();
        builder.enforce_f2_sum_equals_unit(&sum_inputs, pi_row_vars[0][idx]);
        builder.enforce_f2_eq(pi_row_vars[1][idx], s_vars[idx]);
        builder.enforce_f2_eq(pi_row_vars[2][idx], h_vars[idx]);
        builder.enforce_f2_eq(pi_row_vars[3][idx], p_vars[idx]);
    }

    // Π₁ rows scaling constraints
    for row_idx in 0..4 {
        let exponent = params
            .rho_star_num
            .checked_sub(params.rho_numerators[row_idx])
            .ok_or_else(|| LoquatError::invalid_parameters("ρ* < ρ_i"))?
            as u128;
        for (col_idx, &y) in params.coset_u.iter().enumerate() {
            let scalar = y.pow(exponent);
            enforce_f2_const_mul_eq(
                &mut builder,
                pi_row_vars[row_idx][col_idx],
                scalar,
                pi_row_vars[row_idx + 4][col_idx],
            );
        }
    }

    for j in 0..params.n {
        let epsilon = transcript_data.epsilon_vals[j];
        for i in 0..params.m {
            let lambda = transcript_data.lambda_scalars[j * params.m + i];
            let o_val = signature.o_values[j][i];
            let o_idx = builder.alloc(o_val);
            o_var_indices[j].push(o_idx);

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

    // Re-enable Fiat–Shamir binding: derive challenges in-circuit from commitments.
    // Hash field elements directly (small inputs) to stay within the paper's budget.
    // Validate challenge structure (imaginary parts zero) as before.
    // First, build compact commitments to t_values and o_values over the field.
    let t_field_vars: Vec<FieldVar> = t_var_indices
        .iter()
        .zip(signature.t_values.iter())
        .flat_map(|(row_vars, row_vals)| {
            row_vars
                .iter()
                .zip(row_vals.iter())
                .map(|(&idx, &val)| FieldVar::existing(idx, val))
        })
        .collect();
    let t_commitment_fields = griffin_hash_field_vars_circuit(&mut builder, &t_field_vars);

    let o_field_vars: Vec<FieldVar> = o_var_indices
        .iter()
        .zip(signature.o_values.iter())
        .flat_map(|(row_vars, row_vals)| {
            row_vars
                .iter()
                .zip(row_vals.iter())
                .map(|(&idx, &val)| FieldVar::existing(idx, val))
        })
        .collect();
    let o_commitment_fields = griffin_hash_field_vars_circuit(&mut builder, &o_field_vars);

    // Convert commitment bytes to field elements (first limb) for transcript chaining.
    let message_commitment_field = pack_const_bytes_to_field(&message_commitment_bytes[..16]);
    let root_c_field = pack_const_bytes_to_field(&root_c_bytes[..16]);
    let root_s_field = pack_const_bytes_to_field(&root_s_bytes[..16]);
    let root_h_field = pack_const_bytes_to_field(&root_h_bytes[..16]);
    let s_sum_field = FieldVar::existing(builder.alloc(signature.s_sum.c0), signature.s_sum.c0);

    enforce_transcript_relations_field_native(
        &mut builder,
        signature,
        message_commitment_field,
        root_c_field,
        &t_commitment_fields,
        &o_commitment_fields,
        root_s_field,
        s_sum_field,
        root_h_field,
    )?;
    trace_stage("Fiat-Shamir transcript replay enforced");
    constraint_tracker.record(&builder, "transcript binding");
    trace_stage("Fiat-Shamir transcript replay enforced");
    constraint_tracker.record(&builder, "transcript binding");

    builder.enforce_sum_equals(&contrib_c0_terms, mu_c0_idx);
    builder.enforce_sum_equals(&contrib_c1_terms, mu_c1_idx);

    for idx in 0..params.coset_u.len() {
        let zf_value = transcript_data.z_challenge * f_on_u_values[idx];
        let zf_var = builder.alloc_f2(zf_value);
        enforce_f2_const_mul_eq(
            &mut builder,
            f_on_u_vars[idx],
            transcript_data.z_challenge,
            zf_var,
        );

        let expected_value = zf_value + signature.s_evals[idx];
        let expected_var = builder.alloc_f2(expected_value);
        enforce_f2_add(&mut builder, zf_var, s_vars[idx], expected_var);

        builder.enforce_f2_eq(expected_var, f_prime_vars[idx]);

        let z_h_val = z_h_on_u[idx];
        let zh_h_value = z_h_val * signature.h_evals[idx];
        let zh_h_var = builder.alloc_f2(zh_h_value);
        enforce_f2_const_mul_eq(&mut builder, h_vars[idx], z_h_val, zh_h_var);

        let g_value = signature.f_prime_evals[idx] - zh_h_value;
        let g_var = builder.alloc_f2(g_value);
        builder.enforce_f2_sub(f_prime_vars[idx], zh_h_var, g_var);

        let hsize_g_value = h_size_scalar * g_value;
        let hsize_g_var = builder.alloc_f2(hsize_g_value);
        enforce_f2_const_mul_eq(&mut builder, g_var, h_size_scalar, hsize_g_var);

        let numerator_value = hsize_g_value - z_mu_plus_s;
        let numerator_var = builder.alloc_f2(numerator_value);
        builder.enforce_f2_sub(hsize_g_var, z_mu_plus_s_var, numerator_var);

        let denom_scalar = h_size_scalar * params.coset_u[idx];
        enforce_f2_const_mul_eq(&mut builder, p_vars[idx], denom_scalar, numerator_var);
    }

    // sumcheck claimed sum equals μ
    let mut last_sum = builder.alloc_f2(signature.pi_us.claimed_sum);
    builder.enforce_eq(last_sum.c0, mu_c0_idx);
    builder.enforce_eq(last_sum.c1, mu_c1_idx);
    if signature.pi_us.round_polynomials.len() != transcript_data.sumcheck_challenges.len() {
        return Err(LoquatError::verification_failure(
            "sumcheck challenge count mismatch",
        ));
    }
    for (round_idx, round_poly) in signature.pi_us.round_polynomials.iter().enumerate() {
        let c0_var = builder.alloc_f2(round_poly.c0);
        let c1_var = builder.alloc_f2(round_poly.c1);
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

    // f^(0) linear combination
    for col_idx in 0..params.coset_u.len() {
        let pi_column: Vec<F2Var> = pi_row_vars.iter().map(|row| row[col_idx]).collect();
        enforce_f0_linear_combination(
            &mut builder,
            f0_vars[col_idx],
            &pi_column,
            &signature.e_vector,
        );
    }

    enforce_ldt_queries(
        &mut builder,
        params,
        signature,
        &fri_codeword_vars,
        &fri_row_vars,
        fri_leaf_arity,
        &c_prime_vars,
        &signature.c_prime_evals,
        &s_vars,
        &signature.s_evals,
        &h_vars,
        &signature.h_evals,
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
    let real_terms = vec![
        (target.c0, F::one()),
        (source.c0, -scalar.c0),
        (source.c1, scalar.c1),
    ];
    builder.enforce_linear_relation(&real_terms, F::zero());

    let imag_terms = vec![
        (target.c1, F::one()),
        (source.c1, -scalar.c0),
        (source.c0, -scalar.c1),
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

fn enforce_f0_linear_combination(
    builder: &mut R1csBuilder,
    f0_var: F2Var,
    row_vars: &[F2Var],
    coeffs: &[F2],
) {
    let mut real_terms = vec![(f0_var.c0, F::one())];
    let mut imag_terms = vec![(f0_var.c1, F::one())];
    for (row_var, coeff) in row_vars.iter().zip(coeffs.iter()) {
        real_terms.push((row_var.c0, -coeff.c0));
        real_terms.push((row_var.c1, coeff.c1));
        imag_terms.push((row_var.c1, -coeff.c0));
        imag_terms.push((row_var.c0, -coeff.c1));
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
    fri_codeword_vars: &[Vec<F2Var>],
    fri_row_vars: &[Vec<Vec<F2Var>>],
    leaf_arity: usize,
    c_prime_vars: &[Vec<F2Var>],
    c_prime_values: &[Vec<F2>],
    s_vars: &[F2Var],
    s_values: &[F2],
    h_vars: &[F2Var],
    h_values: &[F2],
) -> LoquatResult<()> {
    if leaf_arity == 0 {
        return Err(LoquatError::invalid_parameters(
            "chunk size computed as zero",
        ));
    }
    let chunk_size = leaf_arity;
    let final_commitment = signature
        .ldt_proof
        .commitments
        .last()
        .copied()
        .ok_or_else(|| LoquatError::verification_failure("missing final LDT commitment"))?;
    let num_rounds = params.r;

    for (opening_idx, opening) in signature.ldt_proof.openings.iter().enumerate() {
        if opening.codeword_chunks.len() != num_rounds || opening.row_chunks.len() != num_rounds {
            return Err(LoquatError::verification_failure(
                "LDT opening does not contain all rounds",
            ));
        }
        let mut fold_index = opening.position;
        if fold_index
            >= signature
                .fri_codewords
                .first()
                .map(|layer| layer.len())
                .unwrap_or(0)
        {
            return Err(LoquatError::verification_failure(
                "LDT query position out of range",
            ));
        }

        for round in 0..num_rounds {
            let layer = signature
                .fri_codewords
                .get(round)
                .ok_or_else(|| LoquatError::verification_failure("missing FRI layer"))?;
            let next_layer_vars = fri_codeword_vars
                .get(round + 1)
                .ok_or_else(|| LoquatError::verification_failure("missing next FRI layer"))?;
            let layer_len = layer.len();
            if layer_len == 0 {
                return Err(LoquatError::verification_failure(
                    "FRI layer has zero length",
                ));
            }

            let chunk_len_candidate = chunk_size.min(layer_len);
            let chunk_start = if layer_len > chunk_size {
                (fold_index / chunk_size) * chunk_size
            } else {
                0
            };
            let chunk_end = (chunk_start + chunk_len_candidate).min(layer_len);
            if chunk_end <= chunk_start {
                return Err(LoquatError::verification_failure(
                    "invalid chunk range in FRI layer",
                ));
            }
            let chunk_len = chunk_end - chunk_start;
            let provided_chunk = &opening.codeword_chunks[round];
            if provided_chunk.len() != chunk_len {
                return Err(LoquatError::verification_failure(
                    "codeword chunk length mismatch",
                ));
            }

            let challenge = signature
                .fri_challenges
                .get(round)
                .copied()
                .ok_or_else(|| LoquatError::verification_failure("missing FRI challenge"))?;
            let mut coeff = F2::one();
            let mut folded_var: Option<F2Var> = None;
            let mut folded_value = F2::zero();

            for (offset, provided_value) in provided_chunk.iter().enumerate() {
                let provided_var = builder.alloc_f2(*provided_value);
                builder.enforce_f2_eq(provided_var, fri_codeword_vars[round][chunk_start + offset]);

                let term_value = *provided_value * coeff;
                let term_var = builder.alloc_f2(term_value);
                enforce_f2_const_mul_eq(builder, provided_var, coeff, term_var);

                folded_var = Some(match folded_var {
                    None => {
                        folded_value = term_value;
                        term_var
                    }
                    Some(prev_var) => {
                        let new_value = folded_value + term_value;
                        let new_var = builder.alloc_f2(new_value);
                        enforce_f2_add(builder, prev_var, term_var, new_var);
                        folded_value = new_value;
                        new_var
                    }
                });
                coeff *= challenge;
            }

            let folded_var =
                folded_var.ok_or_else(|| LoquatError::verification_failure("empty chunk"))?;

            let next_index = if layer_len > chunk_size {
                fold_index / chunk_size
            } else {
                0
            };
            let next_var = next_layer_vars
                .get(next_index)
                .copied()
                .ok_or_else(|| LoquatError::verification_failure("next index out of range"))?;
            builder.enforce_f2_eq(folded_var, next_var);

            let row_chunks = &opening.row_chunks[round];
            let expected_rows = signature
                .fri_rows
                .get(round)
                .ok_or_else(|| LoquatError::verification_failure("missing FRI row layer"))?;
            if row_chunks.len() != expected_rows.len() {
                return Err(LoquatError::verification_failure(
                    "row chunk count mismatch",
                ));
            }

            for (row_idx, chunk_values) in row_chunks.iter().enumerate() {
                if chunk_values.len() != chunk_len {
                    return Err(LoquatError::verification_failure(
                        "row chunk length mismatch",
                    ));
                }
                let expected_row_vars = &fri_row_vars[round][row_idx];
                let mut coeff = F2::one();
                let mut row_fold_var: Option<F2Var> = None;
                let mut row_fold_value = F2::zero();

                for (offset, &value) in chunk_values.iter().enumerate() {
                    let chunk_var = builder.alloc_f2(value);
                    builder.enforce_f2_eq(chunk_var, expected_row_vars[chunk_start + offset]);

                    let term_value = value * coeff;
                    let term_var = builder.alloc_f2(term_value);
                    enforce_f2_const_mul_eq(builder, chunk_var, coeff, term_var);

                    row_fold_var = Some(match row_fold_var {
                        None => {
                            row_fold_value = term_value;
                            term_var
                        }
                        Some(prev_var) => {
                            let new_value = row_fold_value + term_value;
                            let new_var = builder.alloc_f2(new_value);
                            enforce_f2_add(builder, prev_var, term_var, new_var);
                            row_fold_value = new_value;
                            new_var
                        }
                    });
                    coeff *= challenge;
                }

                let row_fold_var = row_fold_var.ok_or_else(|| {
                    LoquatError::verification_failure("empty row chunk encountered")
                })?;
                let next_row_var = fri_row_vars[round + 1][row_idx]
                    .get(next_index)
                    .copied()
                    .ok_or_else(|| {
                        LoquatError::verification_failure("next row index out of range")
                    })?;
                builder.enforce_f2_eq(row_fold_var, next_row_var);
            }

            fold_index = if layer_len > chunk_size {
                fold_index / chunk_size
            } else {
                0
            };
        }

        let final_layer_vars = fri_codeword_vars
            .last()
            .ok_or_else(|| LoquatError::verification_failure("missing final FRI layer"))?;
        if fold_index >= final_layer_vars.len() {
            return Err(LoquatError::verification_failure(
                "final FRI index out of range",
            ));
        }

        let final_value_var = final_layer_vars[fold_index];
        let final_eval_var = builder.alloc_f2(opening.final_eval);
        builder.enforce_f2_eq(final_eval_var, final_value_var);

        let final_layer_values = signature
            .fri_codewords
            .last()
            .ok_or_else(|| LoquatError::verification_failure("missing final FRI values"))?;
        let chunk_start = (fold_index / chunk_size) * chunk_size;
        let chunk_end = (chunk_start + chunk_size).min(final_layer_vars.len());
        let mut leaf_fields = Vec::with_capacity((chunk_end - chunk_start) * 2);
        for idx in chunk_start..chunk_end {
            leaf_fields.push(FieldVar::existing(
                final_layer_vars[idx].c0,
                final_layer_values[idx].c0,
            ));
            leaf_fields.push(FieldVar::existing(
                final_layer_vars[idx].c1,
                final_layer_values[idx].c1,
            ));
        }
        let root_fields = merkle_path_opening_fields(
            builder,
            &leaf_fields,
            &opening.auth_path,
            fold_index / chunk_size,
        )?;
        enforce_field_digest_equals_bytes(builder, &root_fields, &final_commitment)?;

        // Tree-cap auth paths for c', s, h (leaf_arity = chunk_size)
        let chunk_index = opening.position / chunk_size;

        // c'(u) leaf: concatenate all c'_j chunks at the queried positions
        if opening_idx >= signature.c_auth_paths.len() {
            return Err(LoquatError::verification_failure(
                "missing c' auth path for query",
            ));
        }
        let c_chunk_start = chunk_index * chunk_size;
        let c_chunk_end = (c_chunk_start + chunk_size).min(c_prime_vars[0].len());
        let mut c_leaf_fields = Vec::with_capacity((c_chunk_end - c_chunk_start) * c_prime_vars.len() * 2);
        for col in c_chunk_start..c_chunk_end {
            for (row_vars, row_vals) in c_prime_vars.iter().zip(c_prime_values.iter()) {
                c_leaf_fields.push(FieldVar::existing(row_vars[col].c0, row_vals[col].c0));
                c_leaf_fields.push(FieldVar::existing(row_vars[col].c1, row_vals[col].c1));
            }
        }
        let c_root_fields = merkle_path_opening_fields(
            builder,
            &c_leaf_fields,
            &signature.c_auth_paths[opening_idx],
            chunk_index,
        )?;
        enforce_field_digest_equals_bytes(builder, &c_root_fields, &signature.root_c)?;

        // s(u) leaf
        if opening_idx >= signature.s_auth_paths.len() {
            return Err(LoquatError::verification_failure(
                "missing s auth path for query",
            ));
        }
        let s_chunk_start = chunk_index * chunk_size;
        let s_chunk_end = (s_chunk_start + chunk_size).min(s_vars.len());
        let mut s_leaf_fields = Vec::with_capacity((s_chunk_end - s_chunk_start) * 2);
        for idx in s_chunk_start..s_chunk_end {
            s_leaf_fields.push(FieldVar::existing(s_vars[idx].c0, s_values[idx].c0));
            s_leaf_fields.push(FieldVar::existing(s_vars[idx].c1, s_values[idx].c1));
        }
        let s_root_fields = merkle_path_opening_fields(
            builder,
            &s_leaf_fields,
            &signature.s_auth_paths[opening_idx],
            chunk_index,
        )?;
        enforce_field_digest_equals_bytes(builder, &s_root_fields, &signature.root_s)?;

        // h(u) leaf
        if opening_idx >= signature.h_auth_paths.len() {
            return Err(LoquatError::verification_failure(
                "missing h auth path for query",
            ));
        }
        let h_chunk_start = chunk_index * chunk_size;
        let h_chunk_end = (h_chunk_start + chunk_size).min(h_vars.len());
        let mut h_leaf_fields = Vec::with_capacity((h_chunk_end - h_chunk_start) * 2);
        for idx in h_chunk_start..h_chunk_end {
            h_leaf_fields.push(FieldVar::existing(h_vars[idx].c0, h_values[idx].c0));
            h_leaf_fields.push(FieldVar::existing(h_vars[idx].c1, h_values[idx].c1));
        }
        let h_root_fields = merkle_path_opening_fields(
            builder,
            &h_leaf_fields,
            &signature.h_auth_paths[opening_idx],
            chunk_index,
        )?;
        enforce_field_digest_equals_bytes(builder, &h_root_fields, &signature.root_h)?;
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

/// Pack constant bytes (from signature) into a field element constant.
fn pack_const_bytes_to_field(bytes: &[Byte]) -> F {
    let mut value = 0u128;
    for (i, byte) in bytes.iter().take(16).enumerate() {
        value |= (byte.value as u128) << (i * 8);
    }
    F::new(value)
}

/// Field-native transcript relations - operates entirely on field elements.
/// This avoids byte serialization and bit decomposition overhead.
/// Only converts to bytes for final challenge value verification.
fn enforce_transcript_relations_field_native(
    builder: &mut R1csBuilder,
    signature: &LoquatSignature,
    message_commitment: F,
    root_c: F,
    t_commitment: &[FieldVar],
    o_commitment: &[FieldVar],
    root_s: F,
    s_sum: FieldVar,
    root_h: F,
) -> LoquatResult<()> {
    if signature.z_challenge.c1 != F::zero() {
        return Err(LoquatError::verification_failure(
            "z challenge imaginary component must be zero",
        ));
    }
    for (idx, entry) in signature.e_vector.iter().enumerate() {
        if entry.c1 != F::zero() {
            return Err(LoquatError::verification_failure(&format!(
                "e_vector[{}] imaginary component must be zero",
                idx
            )));
        }
    }

    // Field-native hash chain: operates directly on field elements.
    // Each hash takes field element inputs and produces field element outputs.
    // This matches the paper's efficient model.

    // Domain separator as field constant
    let domain_h1 = F::new(0x6831); // "h1" as a field constant

    // h1 = H(domain || message_commitment || root_c || t_commitment)
    let mut h1_input = vec![
        FieldVar::constant(builder, domain_h1),
        FieldVar::constant(builder, message_commitment),
        FieldVar::constant(builder, root_c),
    ];
    h1_input.extend_from_slice(t_commitment);
    let h1_fields = griffin_hash_field_vars_circuit(builder, &h1_input);

    // h2 = H(h1 || o_commitment)
    let mut h2_input = h1_fields.clone();
    h2_input.extend_from_slice(o_commitment);
    let h2_fields = griffin_hash_field_vars_circuit(builder, &h2_input);

    // h3 = H(h2 || root_s || s_sum) -> z_challenge
    let mut h3_input = h2_fields.clone();
    h3_input.push(FieldVar::constant(builder, root_s));
    h3_input.push(s_sum);
    let h3_fields = griffin_hash_field_vars_circuit(builder, &h3_input);

    // Verify z_challenge matches h3 output
    let expected_z = builder.alloc(signature.z_challenge.c0);
    builder.enforce_eq(h3_fields[0].idx, expected_z);

    // h4 = H(h3 || root_h) -> e_vector expansion base
    let mut h4_input = h3_fields.clone();
    h4_input.push(FieldVar::constant(builder, root_h));
    let h4_fields = griffin_hash_field_vars_circuit(builder, &h4_input);

    // e_vector[i] = H(h4 || domain || i)[0] as field element
    let domain_e = F::new(0x655f766563746f72); // "e_vector" truncated
    for (idx, entry) in signature.e_vector.iter().enumerate() {
        let mut expand_input = h4_fields.clone();
        expand_input.push(FieldVar::constant(builder, domain_e));
        expand_input.push(FieldVar::constant(builder, F::new(idx as u128)));
        let digest_fields = griffin_hash_field_vars_circuit(builder, &expand_input);

        // Verify e_vector[i] matches hash output
        let expected_e = builder.alloc(entry.c0);
        builder.enforce_eq(digest_fields[0].idx, expected_e);
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

    let mut outputs = Vec::new();
    let mut remaining = GRIFFIN_DIGEST_ELEMENTS;
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
    state[0] = field_pow_const(builder, state[0], params.d_inv);
    state[1] = field_pow_const(builder, state[1], params.d);

    let zero = FieldVar::constant(builder, F::zero());
    let l2 = linear_form_circuit(builder, state[0], state[1], zero, 2);
    let l2_sq = field_mul(builder, l2, l2);
    let alpha_term = field_mul_const(builder, l2, params.alphas[0]);
    let sum = field_add(builder, l2_sq, alpha_term);
    let poly = field_add_const(builder, sum, params.betas[0]);
    state[2] = field_mul(builder, state[2], poly);

    for idx in 3..GRIFFIN_STATE_WIDTH {
        let li = linear_form_circuit(builder, state[0], state[1], state[idx - 1], idx);
        let li_sq = field_mul(builder, li, li);
        let alpha_term = field_mul_const(builder, li, params.alphas[idx - 2]);
        let sum = field_add(builder, li_sq, alpha_term);
        let poly = field_add_const(builder, sum, params.betas[idx - 2]);
        state[idx] = field_mul(builder, state[idx], poly);
    }
}

fn apply_linear_layer_circuit(
    builder: &mut R1csBuilder,
    params: &GriffinParams,
    state: &mut [FieldVar],
) {
    let mut next = Vec::with_capacity(GRIFFIN_STATE_WIDTH);
    for row in 0..GRIFFIN_STATE_WIDTH {
        let mut acc = FieldVar::constant(builder, F::zero());
        for col in 0..GRIFFIN_STATE_WIDTH {
            let term = field_mul_const(builder, state[col], params.matrix[row][col]);
            acc = field_add(builder, acc, term);
        }
        next.push(acc);
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
    let scaled_z0 = field_mul_const(builder, z0, lambda);
    let sum = field_add(builder, scaled_z0, z1);
    field_add(builder, sum, z2)
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
