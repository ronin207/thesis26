use crate::signatures::loquat::errors::{LoquatError, LoquatResult};
use crate::signatures::loquat::field_utils::{F, field_to_u128};
use crate::signatures::loquat::griffin::griffin_hash;
use crate::signatures::loquat::{LoquatPublicParams, LoquatSignature};
use crate::compilers::noir::acir_parser::{
    AcirOpcode, AcirProgram, AssertZeroOpcode, BlackBoxFuncCallOpcode,
};
use crate::compilers::noir::black_box::{NoirBlackBoxOp, ensure_supported_black_box};
use crate::snarks::{
    R1csConstraint, R1csInstance, R1csWitness, build_loquat_r1cs_pk_witness,
    build_loquat_r1cs_pk_witness_instance, build_revocation_r1cs_pk_witness,
    build_revocation_r1cs_pk_witness_instance,
};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::vec::Vec;

#[derive(Debug, Clone)]
pub struct AcirR1csBuild {
    pub instance: R1csInstance,
    pub witness: Option<R1csWitness>,
}

#[derive(Debug, Clone, Copy)]
struct AuxProduct {
    idx: usize,
    coeff: F,
    lhs: usize,
    rhs: usize,
}

#[derive(Debug, Clone, Copy)]
struct AuxBitDecomposition {
    idx: usize,
    source_idx: usize,
    bit_pos: usize,
}

#[derive(Debug, Clone, Copy)]
struct DerivedAssignment {
    idx: usize,
    value: F,
}

pub fn compile_acir_json_to_r1cs(
    acir_json: &str,
    witness_inputs: Option<&HashMap<usize, F>>,
) -> LoquatResult<AcirR1csBuild> {
    let program = crate::compilers::noir::parse_acir_json(acir_json)?;
    convert_acir_to_r1cs(&program, witness_inputs)
}

pub fn convert_acir_to_r1cs(
    program: &AcirProgram,
    witness_inputs: Option<&HashMap<usize, F>>,
) -> LoquatResult<AcirR1csBuild> {
    let mut constraints = Vec::new();
    let mut max_var_idx = program.current_witness_index.max(1);
    let mut next_aux_idx = max_var_idx + 1;
    let mut aux_defs = Vec::new();
    let mut bit_defs = Vec::new();
    let mut derived_assignments = Vec::new();
    let mut required_inputs = BTreeSet::new();

    for opcode in &program.opcodes {
        match opcode {
            AcirOpcode::AssertZero(assert_zero) => {
                convert_assert_zero(
                    assert_zero,
                    &mut constraints,
                    &mut required_inputs,
                    &mut aux_defs,
                    &mut max_var_idx,
                    &mut next_aux_idx,
                )?;
            }
            AcirOpcode::BlackBoxFuncCall(call) => {
                convert_black_box_func_call(
                    call,
                    witness_inputs,
                    &mut constraints,
                    &mut required_inputs,
                    &mut aux_defs,
                    &mut bit_defs,
                    &mut derived_assignments,
                    &mut max_var_idx,
                    &mut next_aux_idx,
                )?;
            }
        }
    }

    let num_variables = max_var_idx + 1;
    let mut instance = R1csInstance::new(num_variables, constraints)?;
    instance.num_inputs = compute_num_inputs(program, num_variables)?;
    let witness = if let Some(inputs) = witness_inputs {
        Some(build_witness(
            num_variables,
            inputs,
            &required_inputs,
            &aux_defs,
            &bit_defs,
            &derived_assignments,
        )?)
    } else {
        None
    };

    Ok(AcirR1csBuild { instance, witness })
}

/// Phase 8: derive `R1csInstance::num_inputs` from the ACIR's `public_parameters`
/// and `return_values`.
///
/// Aurora (and the rest of the SNARK stack) requires public-input slots to occupy
/// the contiguous prefix `[1, num_inputs]` of the witness vector — the constant-1
/// slot at index 0 is followed by the public inputs and then the private witness.
/// Noir's ACIR records public parameters as a list of witness indices, which for
/// well-formed `main(pub a, pub b, ...)` declarations are typically the contiguous
/// prefix `[1, 2, ..., N]`. We accept the union of `public_parameters` and
/// `return_values`, sort it, and require it to be exactly `[1..=N]`. Empty union
/// → `num_inputs = 0` (legacy / no public-input mode).
fn compute_num_inputs(program: &AcirProgram, num_variables: usize) -> LoquatResult<usize> {
    let mut public_indices: Vec<usize> = program
        .public_parameters
        .iter()
        .copied()
        .chain(program.return_values.iter().copied())
        .collect();
    if public_indices.is_empty() {
        return Ok(0);
    }
    public_indices.sort_unstable();
    public_indices.dedup();

    for (offset, idx) in public_indices.iter().enumerate() {
        let expected = offset + 1;
        if *idx != expected {
            return Err(LoquatError::invalid_parameters(&format!(
                "ACIR public_parameters/return_values must form the contiguous prefix [1..=N] of \
                 witness indices for Aurora-compatible R1CS lowering; expected witness index \
                 {expected} at position {offset} but found {idx}. Reorder Noir `pub` parameters \
                 (and any returned values) to occupy the leading witness positions, or expose a \
                 manual remap before calling convert_acir_to_r1cs."
            )));
        }
    }

    let num_inputs = public_indices.len();
    if num_inputs >= num_variables {
        return Err(LoquatError::invalid_parameters(&format!(
            "ACIR declares {num_inputs} public inputs but instance has only {num_variables} \
             variables (including the constant slot)"
        )));
    }
    Ok(num_inputs)
}

fn convert_assert_zero(
    assert_zero: &AssertZeroOpcode,
    constraints: &mut Vec<R1csConstraint>,
    required_inputs: &mut BTreeSet<usize>,
    aux_defs: &mut Vec<AuxProduct>,
    max_var_idx: &mut usize,
    next_aux_idx: &mut usize,
) -> LoquatResult<()> {
    for term in &assert_zero.linear_combinations {
        required_inputs.insert(term.witness);
        *max_var_idx = (*max_var_idx).max(term.witness);
    }
    for term in &assert_zero.mul_terms {
        required_inputs.insert(term.lhs_witness);
        required_inputs.insert(term.rhs_witness);
        *max_var_idx = (*max_var_idx).max(term.lhs_witness.max(term.rhs_witness));
    }

    if assert_zero.mul_terms.is_empty() {
        // Pure linear expression:
        //   (Σ coeff_i * w_i + q_c) * 1 = 0
        constraints.push(build_linear_zero_constraint(
            assert_zero
                .linear_combinations
                .iter()
                .map(|t| (t.witness, t.coefficient))
                .collect(),
            assert_zero.q_c,
        ));
        return Ok(());
    }

    if assert_zero.mul_terms.len() == 1 {
        // Single multiplication term:
        //   (q_m * w_l) * w_r = -(Σ coeff_i * w_i + q_c)
        let term = assert_zero.mul_terms[0].clone();
        let mut c_terms = assert_zero
            .linear_combinations
            .iter()
            .map(|t| (t.witness, -t.coefficient))
            .collect::<Vec<_>>();
        c_terms.push((0, -assert_zero.q_c));
        constraints.push(R1csConstraint::from_sparse(
            vec![(term.lhs_witness, term.coefficient)],
            vec![(term.rhs_witness, F::one())],
            c_terms,
        ));
        return Ok(());
    }

    // Multiple multiplication terms:
    // 1) materialize each q_i * l_i * r_i as an auxiliary variable t_i
    // 2) enforce Σ t_i + linear + q_c = 0
    let mut linear_terms = assert_zero
        .linear_combinations
        .iter()
        .map(|t| (t.witness, t.coefficient))
        .collect::<Vec<_>>();

    for mul in &assert_zero.mul_terms {
        let aux_idx = *next_aux_idx;
        *next_aux_idx += 1;
        *max_var_idx = (*max_var_idx).max(aux_idx);
        constraints.push(R1csConstraint::from_sparse(
            vec![(mul.lhs_witness, mul.coefficient)],
            vec![(mul.rhs_witness, F::one())],
            vec![(aux_idx, F::one())],
        ));
        aux_defs.push(AuxProduct {
            idx: aux_idx,
            coeff: mul.coefficient,
            lhs: mul.lhs_witness,
            rhs: mul.rhs_witness,
        });
        linear_terms.push((aux_idx, F::one()));
    }

    constraints.push(build_linear_zero_constraint(linear_terms, assert_zero.q_c));
    Ok(())
}

fn convert_black_box_func_call(
    call: &BlackBoxFuncCallOpcode,
    witness_inputs: Option<&HashMap<usize, F>>,
    constraints: &mut Vec<R1csConstraint>,
    required_inputs: &mut BTreeSet<usize>,
    aux_defs: &mut Vec<AuxProduct>,
    bit_defs: &mut Vec<AuxBitDecomposition>,
    derived_assignments: &mut Vec<DerivedAssignment>,
    max_var_idx: &mut usize,
    next_aux_idx: &mut usize,
) -> LoquatResult<()> {
    reserve_output_slots(call, max_var_idx, next_aux_idx)?;
    let op = ensure_supported_black_box(&call.name)?;
    match op {
        NoirBlackBoxOp::Range => convert_range_black_box(
            call,
            constraints,
            required_inputs,
            bit_defs,
            max_var_idx,
            next_aux_idx,
        ),
        NoirBlackBoxOp::LoquatVerify => convert_loquat_verify_black_box(
            call,
            witness_inputs,
            constraints,
            required_inputs,
            derived_assignments,
            max_var_idx,
            next_aux_idx,
        ),
        NoirBlackBoxOp::MerkleNonMember => convert_merkle_non_member_black_box(
            call,
            witness_inputs,
            constraints,
            required_inputs,
            derived_assignments,
            max_var_idx,
            next_aux_idx,
        ),
        NoirBlackBoxOp::GriffinHash => convert_griffin_hash_black_box(
            call,
            witness_inputs,
            constraints,
            required_inputs,
            derived_assignments,
            max_var_idx,
        ),
    }
    .map_err(|err| {
        LoquatError::invalid_parameters(&format!(
            "failed to convert black-box opcode `{}`: {}",
            call.name, err
        ))
    })?;

    // Keep the existing aux definition vector in the call chain for future black-box
    // handlers that may decompose arithmetic into product auxiliaries.
    let _ = aux_defs;
    Ok(())
}

fn reserve_output_slots(
    call: &BlackBoxFuncCallOpcode,
    max_var_idx: &mut usize,
    next_aux_idx: &mut usize,
) -> LoquatResult<()> {
    for output in &call.outputs {
        if *output == 0 {
            return Err(LoquatError::invalid_parameters(
                "black-box output witness cannot be 0",
            ));
        }
        *max_var_idx = (*max_var_idx).max(*output);
        if *next_aux_idx <= *output {
            *next_aux_idx = *output + 1;
        }
    }
    Ok(())
}

fn convert_range_black_box(
    call: &BlackBoxFuncCallOpcode,
    constraints: &mut Vec<R1csConstraint>,
    required_inputs: &mut BTreeSet<usize>,
    bit_defs: &mut Vec<AuxBitDecomposition>,
    max_var_idx: &mut usize,
    next_aux_idx: &mut usize,
) -> LoquatResult<()> {
    let input = call
        .inputs
        .first()
        .ok_or_else(|| LoquatError::invalid_parameters("RANGE requires one input witness"))?;
    let witness_idx = input
        .witness
        .ok_or_else(|| LoquatError::invalid_parameters("RANGE input must reference a witness"))?;
    let num_bits = input
        .num_bits
        .ok_or_else(|| LoquatError::invalid_parameters("RANGE input missing `num_bits`"))?;

    if num_bits == 0 || num_bits > 127 {
        return Err(LoquatError::invalid_parameters(
            "RANGE `num_bits` must be in [1, 127] for the current field",
        ));
    }

    required_inputs.insert(witness_idx);
    *max_var_idx = (*max_var_idx).max(witness_idx);

    let mut linear_terms = vec![(witness_idx, F::one())];
    for bit_pos in 0..num_bits {
        let bit_idx = *next_aux_idx;
        *next_aux_idx += 1;
        *max_var_idx = (*max_var_idx).max(bit_idx);

        // Enforce boolean: bit * (bit - 1) = 0
        constraints.push(R1csConstraint::from_sparse(
            vec![(bit_idx, F::one())],
            vec![(bit_idx, F::one()), (0, -F::one())],
            Vec::new(),
        ));

        bit_defs.push(AuxBitDecomposition {
            idx: bit_idx,
            source_idx: witness_idx,
            bit_pos,
        });

        let coeff = F::new(1u128 << bit_pos);
        linear_terms.push((bit_idx, -coeff));
    }

    // Enforce witness equals the weighted bit-sum.
    constraints.push(build_linear_zero_constraint(linear_terms, F::zero()));
    Ok(())
}

fn convert_loquat_verify_black_box(
    call: &BlackBoxFuncCallOpcode,
    witness_inputs: Option<&HashMap<usize, F>>,
    constraints: &mut Vec<R1csConstraint>,
    required_inputs: &mut BTreeSet<usize>,
    derived_assignments: &mut Vec<DerivedAssignment>,
    max_var_idx: &mut usize,
    next_aux_idx: &mut usize,
) -> LoquatResult<()> {
    let payload = payload_object(call)?;

    let message = parse_u8_array_fixed(
        payload.get("message").ok_or_else(|| {
            LoquatError::invalid_parameters("loquat_verify payload missing `message`")
        })?,
        32,
        "loquat_verify.message",
    )?;

    let signature: LoquatSignature = serde_json::from_value(
        payload
            .get("signature")
            .ok_or_else(|| {
                LoquatError::invalid_parameters("loquat_verify payload missing `signature`")
            })?
            .clone(),
    )
    .map_err(|err| {
        LoquatError::invalid_parameters(&format!(
            "failed to parse loquat_verify.signature JSON: {err}"
        ))
    })?;

    let params: LoquatPublicParams = serde_json::from_value(
        payload
            .get("params")
            .ok_or_else(|| {
                LoquatError::invalid_parameters("loquat_verify payload missing `params`")
            })?
            .clone(),
    )
    .map_err(|err| {
        LoquatError::invalid_parameters(&format!(
            "failed to parse loquat_verify.params JSON: {err}"
        ))
    })?;

    let pk_inputs = parse_pk_input_witnesses(call, payload, params.l)?;
    for idx in &pk_inputs {
        required_inputs.insert(*idx);
        *max_var_idx = (*max_var_idx).max(*idx);
    }

    let (sub_instance, sub_witness) = if let Some(inputs) = witness_inputs {
        let public_key = pk_inputs
            .iter()
            .map(|idx| {
                inputs.get(idx).copied().ok_or_else(|| {
                    LoquatError::invalid_parameters(&format!(
                        "missing loquat_verify public-key witness value at index {idx}"
                    ))
                })
            })
            .collect::<LoquatResult<Vec<_>>>()?;
        let (instance, witness) =
            build_loquat_r1cs_pk_witness(&message, &signature, &public_key, &params)?;
        (instance, Some(witness))
    } else {
        (
            build_loquat_r1cs_pk_witness_instance(&message, &signature, &params)?,
            None,
        )
    };

    let link_map = (0..params.l)
        .map(|offset| (offset + 1, pk_inputs[offset]))
        .collect::<HashMap<usize, usize>>();

    merge_subcircuit(
        constraints,
        max_var_idx,
        next_aux_idx,
        derived_assignments,
        &sub_instance,
        sub_witness.as_ref(),
        &link_map,
    )?;

    enforce_true_outputs(call, constraints, derived_assignments, max_var_idx)?;
    Ok(())
}

fn convert_merkle_non_member_black_box(
    call: &BlackBoxFuncCallOpcode,
    witness_inputs: Option<&HashMap<usize, F>>,
    constraints: &mut Vec<R1csConstraint>,
    required_inputs: &mut BTreeSet<usize>,
    derived_assignments: &mut Vec<DerivedAssignment>,
    max_var_idx: &mut usize,
    next_aux_idx: &mut usize,
) -> LoquatResult<()> {
    let payload = payload_object(call)?;

    let depth = payload
        .get("depth")
        .ok_or_else(|| LoquatError::invalid_parameters("merkle_non_member payload missing `depth`"))
        .and_then(parse_usize_from_value)?;

    let pk_len = if let Some(v) = payload.get("pk_len") {
        parse_usize_from_value(v)?
    } else {
        depth.max(
            payload
                .get("pk_inputs")
                .and_then(Value::as_array)
                .map(|arr| arr.len())
                .unwrap_or(depth),
        )
    };

    if pk_len < depth {
        return Err(LoquatError::invalid_parameters(
            "merkle_non_member requires `pk_len >= depth`",
        ));
    }

    let pk_inputs = parse_pk_input_witnesses(call, payload, pk_len)?;
    for idx in &pk_inputs {
        required_inputs.insert(*idx);
        *max_var_idx = (*max_var_idx).max(*idx);
    }

    let root = parse_u8_array_fixed(
        payload.get("root").ok_or_else(|| {
            LoquatError::invalid_parameters("merkle_non_member payload missing `root`")
        })?,
        32,
        "merkle_non_member.root",
    )?;
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&root);

    let auth_path = payload.get("auth_path").map(parse_auth_path).transpose()?;

    let (sub_instance, sub_witness) = if let Some(inputs) = witness_inputs {
        let path = auth_path.ok_or_else(|| {
            LoquatError::invalid_parameters(
                "merkle_non_member requires `auth_path` payload when witness generation is enabled",
            )
        })?;
        let public_key = pk_inputs
            .iter()
            .map(|idx| {
                inputs.get(idx).copied().ok_or_else(|| {
                    LoquatError::invalid_parameters(&format!(
                        "missing merkle_non_member public-key witness value at index {idx}"
                    ))
                })
            })
            .collect::<LoquatResult<Vec<_>>>()?;
        let (instance, witness) =
            build_revocation_r1cs_pk_witness(&public_key, &root_arr, &path, depth)?;
        (instance, Some(witness))
    } else {
        (
            build_revocation_r1cs_pk_witness_instance(&root_arr, depth, pk_len)?,
            None,
        )
    };

    let link_map = (0..pk_len)
        .map(|offset| (offset + 1, pk_inputs[offset]))
        .collect::<HashMap<usize, usize>>();

    merge_subcircuit(
        constraints,
        max_var_idx,
        next_aux_idx,
        derived_assignments,
        &sub_instance,
        sub_witness.as_ref(),
        &link_map,
    )?;

    enforce_true_outputs(call, constraints, derived_assignments, max_var_idx)?;
    Ok(())
}

/// Phase 8: lift the constant-only restriction so griffin_hash can be invoked on
/// witness-typed inputs from a Noir circuit.
///
/// Soundness note: there is **no R1CS-native Griffin permutation gadget** in this
/// path — we delegate digest computation to the host (`griffin_hash` in
/// `loquat::griffin`). The emitted constraints assert
/// `output_byte_i == host_computed_digest_byte_i` as constants, which is sound
/// only when the witness input bytes are themselves constrained elsewhere in the
/// circuit (e.g., by being public inputs or being derived from public inputs via
/// arithmetic gates). A malicious prover that supplies arbitrary witness bytes
/// here would bake a different digest into the constraint constants on each
/// `convert_acir_to_r1cs` call. This matches the existing pattern for
/// `loquat_verify` and `merkle_non_member` black boxes (which similarly delegate
/// the heavy native check to the merged sub-circuit at compile time).
///
/// A full algebraic Griffin gadget — reusing the in-circuit
/// `griffin_permutation_circuit` from `src/snarks/loquat_r1cs.rs` — is left for
/// future work; that path is what the Loquat verifier circuit already uses
/// internally and requires moving the ACIR lowerer onto `R1csBuilder`.
fn convert_griffin_hash_black_box(
    call: &BlackBoxFuncCallOpcode,
    witness_inputs: Option<&HashMap<usize, F>>,
    constraints: &mut Vec<R1csConstraint>,
    required_inputs: &mut BTreeSet<usize>,
    derived_assignments: &mut Vec<DerivedAssignment>,
    max_var_idx: &mut usize,
) -> LoquatResult<()> {
    let mut input_bytes = Vec::with_capacity(call.inputs.len());
    let mut had_witness_input = false;
    for input in &call.inputs {
        if let Some(value) = input.constant {
            input_bytes.push(u8_from_field(value)?);
            continue;
        }

        let witness_idx = input.witness.ok_or_else(|| {
            LoquatError::invalid_parameters(
                "griffin_hash input must specify either a `constant` or a `witness` index",
            )
        })?;
        if witness_idx == 0 {
            return Err(LoquatError::invalid_parameters(
                "griffin_hash witness input cannot reference index 0 (constant slot)",
            ));
        }
        had_witness_input = true;
        required_inputs.insert(witness_idx);
        *max_var_idx = (*max_var_idx).max(witness_idx);

        let inputs_map = witness_inputs.ok_or_else(|| {
            LoquatError::invalid_parameters(
                "griffin_hash with witness inputs requires `witness_inputs` to be supplied to \
                 convert_acir_to_r1cs (instance-only lowering with witness-typed inputs is not \
                 supported because there is no R1CS-native Griffin gadget in this path yet)",
            )
        })?;
        let field_value = inputs_map.get(&witness_idx).copied().ok_or_else(|| {
            LoquatError::invalid_parameters(&format!(
                "missing witness value for griffin_hash input at index {witness_idx}"
            ))
        })?;
        input_bytes.push(u8_from_field(field_value)?);
    }

    let digest = griffin_hash(&input_bytes);
    if digest.len() != 32 {
        return Err(LoquatError::invalid_parameters(
            "griffin_hash digest length mismatch (expected 32)",
        ));
    }
    if call.outputs.len() != digest.len() {
        return Err(LoquatError::invalid_parameters(&format!(
            "griffin_hash expects {} output witnesses, got {}",
            digest.len(),
            call.outputs.len()
        )));
    }
    let _ = had_witness_input;

    for (idx, byte) in call.outputs.iter().zip(digest.iter()) {
        *max_var_idx = (*max_var_idx).max(*idx);
        constraints.push(build_linear_zero_constraint(
            vec![(*idx, F::one())],
            -F::new(*byte as u128),
        ));
        derived_assignments.push(DerivedAssignment {
            idx: *idx,
            value: F::new(*byte as u128),
        });
    }
    Ok(())
}

fn merge_subcircuit(
    constraints: &mut Vec<R1csConstraint>,
    max_var_idx: &mut usize,
    next_aux_idx: &mut usize,
    derived_assignments: &mut Vec<DerivedAssignment>,
    instance: &R1csInstance,
    witness: Option<&R1csWitness>,
    link_map: &HashMap<usize, usize>,
) -> LoquatResult<()> {
    if instance.num_variables == 0 {
        return Err(LoquatError::invalid_parameters(
            "cannot merge empty subcircuit",
        ));
    }

    let mut var_map = vec![0usize; instance.num_variables];
    for (local_idx, mapped_idx) in link_map {
        if *local_idx == 0 || *local_idx >= instance.num_variables {
            return Err(LoquatError::invalid_parameters(&format!(
                "subcircuit link index {local_idx} out of range"
            )));
        }
        if *mapped_idx == 0 {
            return Err(LoquatError::invalid_parameters(
                "subcircuit links cannot map to ACIR constant slot 0",
            ));
        }
        var_map[*local_idx] = *mapped_idx;
        *max_var_idx = (*max_var_idx).max(*mapped_idx);
    }

    for local_idx in 1..instance.num_variables {
        if var_map[local_idx] != 0 {
            continue;
        }
        let allocated = *next_aux_idx;
        *next_aux_idx += 1;
        *max_var_idx = (*max_var_idx).max(allocated);
        var_map[local_idx] = allocated;
    }

    for c in &instance.constraints {
        constraints.push(R1csConstraint::from_sparse(
            remap_terms(&c.a, &var_map)?,
            remap_terms(&c.b, &var_map)?,
            remap_terms(&c.c, &var_map)?,
        ));
    }

    if let Some(sub_witness) = witness {
        if sub_witness.assignment.len() + 1 != instance.num_variables {
            return Err(LoquatError::invalid_parameters(
                "subcircuit witness length does not match subcircuit instance",
            ));
        }
        for local_idx in 1..instance.num_variables {
            let global_idx = var_map[local_idx];
            derived_assignments.push(DerivedAssignment {
                idx: global_idx,
                value: sub_witness.assignment[local_idx - 1],
            });
        }
    }

    Ok(())
}

fn remap_terms(terms: &[(usize, F)], var_map: &[usize]) -> LoquatResult<Vec<(usize, F)>> {
    let mut out = Vec::with_capacity(terms.len());
    for (idx, coeff) in terms {
        if *idx >= var_map.len() {
            return Err(LoquatError::invalid_parameters(&format!(
                "subcircuit term index {idx} out of range during merge"
            )));
        }
        out.push((var_map[*idx], *coeff));
    }
    Ok(out)
}

fn enforce_true_outputs(
    call: &BlackBoxFuncCallOpcode,
    constraints: &mut Vec<R1csConstraint>,
    derived_assignments: &mut Vec<DerivedAssignment>,
    max_var_idx: &mut usize,
) -> LoquatResult<()> {
    for output in &call.outputs {
        if *output == 0 {
            return Err(LoquatError::invalid_parameters(
                "black-box output witness cannot be 0",
            ));
        }
        *max_var_idx = (*max_var_idx).max(*output);
        constraints.push(build_linear_zero_constraint(
            vec![(*output, F::one())],
            -F::one(),
        ));
        derived_assignments.push(DerivedAssignment {
            idx: *output,
            value: F::one(),
        });
    }
    Ok(())
}

fn payload_object(call: &BlackBoxFuncCallOpcode) -> LoquatResult<&serde_json::Map<String, Value>> {
    call.payload
        .as_ref()
        .ok_or_else(|| {
            LoquatError::invalid_parameters(&format!(
                "black-box `{}` requires a `payload` object",
                call.name
            ))
        })?
        .as_object()
        .ok_or_else(|| LoquatError::invalid_parameters("black-box payload must be a JSON object"))
}

fn parse_pk_input_witnesses(
    call: &BlackBoxFuncCallOpcode,
    payload: &serde_json::Map<String, Value>,
    needed: usize,
) -> LoquatResult<Vec<usize>> {
    let candidates = if let Some(v) = payload.get("pk_inputs") {
        let arr = v
            .as_array()
            .ok_or_else(|| LoquatError::invalid_parameters("`pk_inputs` must be an array"))?;
        arr.iter()
            .map(parse_usize_from_value)
            .collect::<LoquatResult<Vec<_>>>()?
    } else {
        call.inputs
            .iter()
            .filter_map(|input| input.witness)
            .collect::<Vec<_>>()
    };

    if candidates.len() < needed {
        return Err(LoquatError::invalid_parameters(&format!(
            "expected at least {needed} public-key witness indices, got {}",
            candidates.len()
        )));
    }

    if candidates.iter().any(|idx| *idx == 0) {
        return Err(LoquatError::invalid_parameters(
            "public-key witness indices cannot include 0",
        ));
    }

    Ok(candidates[..needed].to_vec())
}

fn parse_auth_path(value: &Value) -> LoquatResult<Vec<[u8; 32]>> {
    let arr = value
        .as_array()
        .ok_or_else(|| LoquatError::invalid_parameters("`auth_path` must be an array"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let bytes = parse_u8_array_fixed(entry, 32, "merkle_non_member.auth_path entry")?;
        let mut node = [0u8; 32];
        node.copy_from_slice(&bytes);
        if idx < out.len() {
            // no-op, retained for explicit index-driven parsing clarity
        }
        out.push(node);
    }
    Ok(out)
}

fn parse_u8_array_fixed(value: &Value, expected_len: usize, label: &str) -> LoquatResult<Vec<u8>> {
    let arr = value.as_array().ok_or_else(|| {
        LoquatError::invalid_parameters(&format!("{label} must be an array of bytes"))
    })?;
    if arr.len() != expected_len {
        return Err(LoquatError::invalid_parameters(&format!(
            "{label} length mismatch: expected {expected_len}, got {}",
            arr.len()
        )));
    }
    arr.iter()
        .map(|entry| parse_u8_from_value(entry, label))
        .collect::<LoquatResult<Vec<_>>>()
}

fn parse_u8_from_value(value: &Value, label: &str) -> LoquatResult<u8> {
    let parsed = if let Some(v) = value.as_u64() {
        v
    } else if let Some(v) = value.as_i64() {
        if v < 0 {
            return Err(LoquatError::invalid_parameters(&format!(
                "{label} contains negative byte value {v}"
            )));
        }
        v as u64
    } else if let Some(s) = value.as_str() {
        s.parse::<u64>().map_err(|err| {
            LoquatError::invalid_parameters(&format!("invalid byte string `{s}` in {label}: {err}"))
        })?
    } else {
        return Err(LoquatError::invalid_parameters(&format!(
            "{label} contains non-numeric byte entry"
        )));
    };

    if parsed > u8::MAX as u64 {
        return Err(LoquatError::invalid_parameters(&format!(
            "{label} contains out-of-range byte value {parsed}"
        )));
    }
    Ok(parsed as u8)
}

fn parse_usize_from_value(value: &Value) -> LoquatResult<usize> {
    if let Some(v) = value.as_u64() {
        return Ok(v as usize);
    }
    if let Some(v) = value.as_i64() {
        if v < 0 {
            return Err(LoquatError::invalid_parameters(
                "expected non-negative integer",
            ));
        }
        return Ok(v as usize);
    }
    if let Some(s) = value.as_str() {
        return s.parse::<usize>().map_err(|err| {
            LoquatError::invalid_parameters(&format!("invalid integer string `{s}`: {err}"))
        });
    }
    Err(LoquatError::invalid_parameters(
        "expected integer JSON value",
    ))
}

fn build_linear_zero_constraint(terms: Vec<(usize, F)>, constant: F) -> R1csConstraint {
    let mut a_terms = terms;
    a_terms.push((0, constant));
    R1csConstraint::from_sparse(a_terms, vec![(0, F::one())], Vec::new())
}

fn build_witness(
    num_variables: usize,
    witness_inputs: &HashMap<usize, F>,
    required_inputs: &BTreeSet<usize>,
    aux_defs: &[AuxProduct],
    bit_defs: &[AuxBitDecomposition],
    derived_assignments: &[DerivedAssignment],
) -> LoquatResult<R1csWitness> {
    for idx in required_inputs {
        if *idx == 0 {
            return Err(LoquatError::invalid_parameters(
                "ACIR witness index 0 is reserved for the constant slot",
            ));
        }
        if !witness_inputs.contains_key(idx) {
            return Err(LoquatError::invalid_parameters(&format!(
                "missing witness value for index {idx}"
            )));
        }
    }

    let mut assignment = vec![F::zero(); num_variables.saturating_sub(1)];
    let mut assigned = vec![false; num_variables.saturating_sub(1)];

    for (idx, value) in witness_inputs {
        if *idx == 0 || *idx >= num_variables {
            continue;
        }
        set_assignment_value(
            *idx,
            *value,
            &mut assignment,
            &mut assigned,
            num_variables,
            "input",
        )?;
    }

    for aux in aux_defs {
        let lhs = get_assignment_value(aux.lhs, &assignment, num_variables)?;
        let rhs = get_assignment_value(aux.rhs, &assignment, num_variables)?;
        let aux_value = aux.coeff * lhs * rhs;
        set_assignment_value(
            aux.idx,
            aux_value,
            &mut assignment,
            &mut assigned,
            num_variables,
            "aux product",
        )?;
    }

    for aux in bit_defs {
        let source = get_assignment_value(aux.source_idx, &assignment, num_variables)?;
        let source_u128 = field_to_u128(source);
        let bit = ((source_u128 >> aux.bit_pos) & 1) as u128;
        set_assignment_value(
            aux.idx,
            F::new(bit),
            &mut assignment,
            &mut assigned,
            num_variables,
            "range bit",
        )?;
    }

    for derived in derived_assignments {
        set_assignment_value(
            derived.idx,
            derived.value,
            &mut assignment,
            &mut assigned,
            num_variables,
            "derived",
        )?;
    }

    Ok(R1csWitness::new(assignment))
}

fn set_assignment_value(
    idx: usize,
    value: F,
    assignment: &mut [F],
    assigned: &mut [bool],
    num_variables: usize,
    source: &str,
) -> LoquatResult<()> {
    if idx == 0 || idx >= num_variables {
        return Err(LoquatError::invalid_parameters(&format!(
            "{} assignment index {} out of bounds for {} variables",
            source, idx, num_variables
        )));
    }
    let slot = idx - 1;
    if assigned[slot] {
        if assignment[slot] != value {
            return Err(LoquatError::invalid_parameters(&format!(
                "conflicting assignment for witness {} from {}",
                idx, source
            )));
        }
        return Ok(());
    }
    assignment[slot] = value;
    assigned[slot] = true;
    Ok(())
}

fn get_assignment_value(idx: usize, assignment: &[F], num_variables: usize) -> LoquatResult<F> {
    if idx == 0 {
        return Ok(F::one());
    }
    if idx >= num_variables {
        return Err(LoquatError::invalid_parameters(&format!(
            "witness index {idx} out of bounds for {num_variables} variables"
        )));
    }
    Ok(assignment[idx - 1])
}

fn u8_from_field(value: F) -> LoquatResult<u8> {
    let raw = field_to_u128(value);
    if raw > u8::MAX as u128 {
        return Err(LoquatError::invalid_parameters(&format!(
            "field value {raw} does not fit into a byte"
        )));
    }
    Ok(raw as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anoncreds::bdec::BdecRevocationAccumulator;
    use crate::compilers::noir::parse_acir_json;
    use serde_json::json;

    #[test]
    fn convert_single_mul_assert_zero_to_satisfied_r1cs() {
        let json = r#"
        {
            "current_witness_index": 3,
            "opcodes": [
                {
                    "AssertZero": {
                        "value": {
                            "mul_terms": [[1, 1, 2]],
                            "linear_combinations": [[-1, 3]],
                            "q_c": 0
                        }
                    }
                }
            ]
        }
        "#;

        let program = parse_acir_json(json).expect("ACIR parse");
        let mut witness_inputs = HashMap::new();
        witness_inputs.insert(1, F::new(3));
        witness_inputs.insert(2, F::new(5));
        witness_inputs.insert(3, F::new(15));

        let build = convert_acir_to_r1cs(&program, Some(&witness_inputs)).expect("conversion");
        let witness = build.witness.expect("witness should be generated");
        build
            .instance
            .is_satisfied(&witness)
            .expect("generated witness must satisfy converted R1CS");
    }

    #[test]
    fn convert_multi_mul_assert_zero_to_satisfied_r1cs() {
        let json = r#"
        {
            "current_witness_index": 5,
            "opcodes": [
                {
                    "AssertZero": {
                        "value": {
                            "mul_terms": [[1, 1, 2], [1, 3, 4]],
                            "linear_combinations": [[-1, 5]],
                            "q_c": 0
                        }
                    }
                }
            ]
        }
        "#;

        let program = parse_acir_json(json).expect("ACIR parse");
        let mut witness_inputs = HashMap::new();
        witness_inputs.insert(1, F::new(2));
        witness_inputs.insert(2, F::new(3));
        witness_inputs.insert(3, F::new(4));
        witness_inputs.insert(4, F::new(5));
        witness_inputs.insert(5, F::new(26)); // 2*3 + 4*5

        let build = convert_acir_to_r1cs(&program, Some(&witness_inputs)).expect("conversion");
        let witness = build.witness.expect("witness should be generated");
        build
            .instance
            .is_satisfied(&witness)
            .expect("generated witness must satisfy converted R1CS");
    }

    #[test]
    fn convert_range_black_box_to_satisfied_r1cs() {
        let json = r#"
        {
            "current_witness_index": 1,
            "opcodes": [
                {
                    "BlackBoxFuncCall": {
                        "value": {
                            "name": "RANGE",
                            "inputs": [{"witness": 1, "num_bits": 8}],
                            "outputs": []
                        }
                    }
                }
            ]
        }
        "#;

        let program = parse_acir_json(json).expect("ACIR parse");
        let mut witness_inputs = HashMap::new();
        witness_inputs.insert(1, F::new(233));

        let build = convert_acir_to_r1cs(&program, Some(&witness_inputs)).expect("conversion");
        let witness = build.witness.expect("witness should be generated");
        build
            .instance
            .is_satisfied(&witness)
            .expect("range-constrained witness must satisfy converted R1CS");
    }

    #[test]
    fn convert_merkle_non_member_black_box_to_satisfied_r1cs() {
        let depth = 3usize;
        let pk_len = 8usize;
        let mut public_key = vec![F::zero(); pk_len];
        public_key[0] = F::one();
        public_key[2] = F::one();

        let accumulator = BdecRevocationAccumulator::new(depth).expect("accumulator");
        let root = accumulator.root();
        let auth_path = accumulator.auth_path(&public_key).expect("auth path");

        let payload = json!({
            "depth": depth,
            "pk_len": pk_len,
            "pk_inputs": (1..=pk_len).collect::<Vec<usize>>(),
            "root": root,
            "auth_path": auth_path,
        });

        let program_json = json!({
            "current_witness_index": pk_len,
            "opcodes": [
                {
                    "BlackBoxFuncCall": {
                        "value": {
                            "name": "merkle_non_member",
                            "inputs": [],
                            "outputs": [pk_len + 1],
                            "payload": payload
                        }
                    }
                }
            ]
        })
        .to_string();

        let program = parse_acir_json(&program_json).expect("ACIR parse");

        let mut witness_inputs = HashMap::new();
        for (offset, value) in public_key.iter().enumerate() {
            witness_inputs.insert(offset + 1, *value);
        }

        let build = convert_acir_to_r1cs(&program, Some(&witness_inputs)).expect("conversion");
        let witness = build.witness.expect("witness should be generated");
        build
            .instance
            .is_satisfied(&witness)
            .expect("revocation witness must satisfy merged R1CS");

        assert_eq!(witness.assignment[pk_len], F::one());
    }

    #[test]
    fn convert_acir_sets_num_inputs_from_public_parameters() {
        // Two `pub` parameters at witness positions 1 and 2 plus an asserted
        // product at position 3 — Aurora-compatible R1CS lowering should record
        // `num_inputs = 2`.
        let json = r#"
        {
            "current_witness_index": 3,
            "public_parameters": [1, 2],
            "opcodes": [
                {
                    "AssertZero": {
                        "value": {
                            "mul_terms": [[1, 1, 2]],
                            "linear_combinations": [[-1, 3]],
                            "q_c": 0
                        }
                    }
                }
            ]
        }
        "#;

        let program = parse_acir_json(json).expect("ACIR parse");
        let mut witness_inputs = HashMap::new();
        witness_inputs.insert(1, F::new(3));
        witness_inputs.insert(2, F::new(5));
        witness_inputs.insert(3, F::new(15));

        let build = convert_acir_to_r1cs(&program, Some(&witness_inputs)).expect("conversion");
        assert_eq!(build.instance.num_inputs, 2);
        let witness = build.witness.expect("witness should be generated");
        build
            .instance
            .is_satisfied(&witness)
            .expect("generated witness must satisfy converted R1CS");
    }

    #[test]
    fn convert_acir_rejects_non_prefix_public_parameters() {
        // Public parameter at position 2 alone — does not form a contiguous prefix.
        let json = r#"
        {
            "current_witness_index": 3,
            "public_parameters": [2],
            "opcodes": [
                {
                    "AssertZero": {
                        "value": {
                            "mul_terms": [[1, 1, 2]],
                            "linear_combinations": [[-1, 3]],
                            "q_c": 0
                        }
                    }
                }
            ]
        }
        "#;

        let program = parse_acir_json(json).expect("ACIR parse");
        let err = convert_acir_to_r1cs(&program, None)
            .err()
            .expect("non-prefix public_parameters must be rejected");
        assert!(
            format!("{err}").contains("contiguous prefix"),
            "expected error to mention contiguous-prefix requirement, got: {err}"
        );
    }

    #[test]
    fn convert_griffin_hash_with_constant_inputs_remains_satisfied() {
        // Phase 8 regression: even with the constant-only restriction lifted,
        // the original constant-input path must still produce a satisfied R1CS.
        let json = r#"
        {
            "current_witness_index": 1,
            "opcodes": [
                {
                    "BlackBoxFuncCall": {
                        "value": {
                            "name": "griffin_hash",
                            "inputs": [
                                {"constant": 1},
                                {"constant": 2},
                                {"constant": 3}
                            ],
                            "outputs": [
                                2, 3, 4, 5, 6, 7, 8, 9,
                                10, 11, 12, 13, 14, 15, 16, 17,
                                18, 19, 20, 21, 22, 23, 24, 25,
                                26, 27, 28, 29, 30, 31, 32, 33
                            ]
                        }
                    }
                }
            ]
        }
        "#;

        let program = parse_acir_json(json).expect("ACIR parse");
        let mut witness_inputs = HashMap::new();
        witness_inputs.insert(1usize, F::new(0));
        let build = convert_acir_to_r1cs(&program, Some(&witness_inputs)).expect("conversion");
        let witness = build.witness.expect("witness");
        build
            .instance
            .is_satisfied(&witness)
            .expect("griffin_hash with constant inputs should remain satisfied");
    }

    #[test]
    fn convert_griffin_hash_with_witness_inputs_to_satisfied_r1cs() {
        // Phase 8: griffin_hash now accepts witness-typed inputs when the host
        // supplies the corresponding values. The host computes the digest and
        // the conversion bakes it into output equality constraints.
        let json = r#"
        {
            "current_witness_index": 3,
            "opcodes": [
                {
                    "BlackBoxFuncCall": {
                        "value": {
                            "name": "griffin_hash",
                            "inputs": [
                                {"witness": 1},
                                {"witness": 2},
                                {"witness": 3}
                            ],
                            "outputs": [
                                4, 5, 6, 7, 8, 9, 10, 11,
                                12, 13, 14, 15, 16, 17, 18, 19,
                                20, 21, 22, 23, 24, 25, 26, 27,
                                28, 29, 30, 31, 32, 33, 34, 35
                            ]
                        }
                    }
                }
            ]
        }
        "#;

        let program = parse_acir_json(json).expect("ACIR parse");
        let mut witness_inputs = HashMap::new();
        witness_inputs.insert(1usize, F::new(0xAB));
        witness_inputs.insert(2usize, F::new(0xCD));
        witness_inputs.insert(3usize, F::new(0xEF));

        let build = convert_acir_to_r1cs(&program, Some(&witness_inputs)).expect("conversion");
        let witness = build.witness.expect("witness");
        build
            .instance
            .is_satisfied(&witness)
            .expect("griffin_hash with witness inputs should be satisfied");
    }

    #[test]
    fn convert_griffin_hash_rejects_witness_inputs_in_instance_only_mode() {
        // Phase 8: instance-only lowering with witness-typed griffin_hash inputs
        // is rejected because there is no R1CS-native Griffin gadget on this path.
        let json = r#"
        {
            "current_witness_index": 1,
            "opcodes": [
                {
                    "BlackBoxFuncCall": {
                        "value": {
                            "name": "griffin_hash",
                            "inputs": [{"witness": 1}],
                            "outputs": [
                                2, 3, 4, 5, 6, 7, 8, 9,
                                10, 11, 12, 13, 14, 15, 16, 17,
                                18, 19, 20, 21, 22, 23, 24, 25,
                                26, 27, 28, 29, 30, 31, 32, 33
                            ]
                        }
                    }
                }
            ]
        }
        "#;

        let program = parse_acir_json(json).expect("ACIR parse");
        let err = convert_acir_to_r1cs(&program, None)
            .err()
            .expect("witness griffin_hash inputs without witness_inputs map must error");
        assert!(
            format!("{err}").contains("witness_inputs"),
            "expected error to mention witness_inputs requirement, got: {err}"
        );
    }
}
