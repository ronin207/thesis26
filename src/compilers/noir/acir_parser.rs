use crate::signatures::loquat::errors::{LoquatError, LoquatResult};
use crate::signatures::loquat::field_utils::F;
use serde_json::Value;
use std::vec::Vec;

const P127_MODULUS: u128 = (1u128 << 127) - 1;

#[derive(Debug, Clone, PartialEq)]
pub struct AcirProgram {
    pub current_witness_index: usize,
    pub opcodes: Vec<AcirOpcode>,
    /// Phase 8: Witnesses marked `pub` in the Noir source. These are the
    /// public-input positions that nargo records in the ACIR JSON's
    /// `public_parameters` (or `private_parameters` complement). Empty if the
    /// ACIR artifact has no public-parameter annotations (older nargo or
    /// circuits without `pub` markers).
    pub public_parameters: Vec<usize>,
    /// Phase 8: Witnesses returned from the Noir `main` function. Treated as
    /// public outputs by the verifier. Loquat's circuit currently has no
    /// returned values (asserts only), so this is typically empty for our
    /// `loquat_verify` / `bdec_showver` Noir packages.
    pub return_values: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AcirOpcode {
    AssertZero(AssertZeroOpcode),
    BlackBoxFuncCall(BlackBoxFuncCallOpcode),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssertZeroOpcode {
    pub mul_terms: Vec<MulTerm>,
    pub linear_combinations: Vec<LinTerm>,
    pub q_c: F,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MulTerm {
    pub coefficient: F,
    pub lhs_witness: usize,
    pub rhs_witness: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinTerm {
    pub coefficient: F,
    pub witness: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlackBoxFuncCallOpcode {
    pub name: String,
    pub inputs: Vec<BlackBoxInput>,
    pub outputs: Vec<usize>,
    pub payload: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlackBoxInput {
    pub witness: Option<usize>,
    pub constant: Option<F>,
    pub num_bits: Option<usize>,
}

pub fn parse_acir_json(acir_json: &str) -> LoquatResult<AcirProgram> {
    let root: Value =
        serde_json::from_str(acir_json).map_err(|err| LoquatError::SerializationError {
            details: format!("failed to parse ACIR JSON: {err}"),
        })?;

    let obj = root
        .as_object()
        .ok_or_else(|| LoquatError::invalid_parameters("ACIR root must be a JSON object"))?;

    let current_witness_index = obj
        .get("current_witness_index")
        .ok_or_else(|| LoquatError::invalid_parameters("ACIR missing `current_witness_index`"))
        .and_then(parse_usize)?;

    let opcodes_value = obj
        .get("opcodes")
        .ok_or_else(|| LoquatError::invalid_parameters("ACIR missing `opcodes`"))?;

    let opcodes_array = opcodes_value
        .as_array()
        .ok_or_else(|| LoquatError::invalid_parameters("ACIR `opcodes` must be an array"))?;

    let mut opcodes = Vec::with_capacity(opcodes_array.len());
    for opcode_value in opcodes_array {
        opcodes.push(parse_opcode(opcode_value)?);
    }

    let public_parameters = parse_witness_index_list(obj, &["public_parameters", "publicParameters"])?;
    let return_values = parse_witness_index_list(obj, &["return_values", "returnValues"])?;

    Ok(AcirProgram {
        current_witness_index,
        opcodes,
        public_parameters,
        return_values,
    })
}

fn parse_witness_index_list(
    obj: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> LoquatResult<Vec<usize>> {
    let Some(value) = pick_key(obj, keys) else {
        return Ok(Vec::new());
    };

    if value.is_null() {
        return Ok(Vec::new());
    }

    if let Some(arr) = value.as_array() {
        let mut out = Vec::with_capacity(arr.len());
        for entry in arr {
            out.push(parse_usize(entry)?);
        }
        return Ok(out);
    }

    if let Some(inner_obj) = value.as_object() {
        for inner_key in &["indices", "values", "items"] {
            if let Some(inner) = inner_obj.get(*inner_key) {
                if let Some(arr) = inner.as_array() {
                    let mut out = Vec::with_capacity(arr.len());
                    for entry in arr {
                        out.push(parse_usize(entry)?);
                    }
                    return Ok(out);
                }
            }
        }
    }

    Err(LoquatError::invalid_parameters(
        "ACIR public_parameters/return_values must be an array of witness indices",
    ))
}

fn parse_opcode(value: &Value) -> LoquatResult<AcirOpcode> {
    let object = value
        .as_object()
        .ok_or_else(|| LoquatError::invalid_parameters("ACIR opcode must be a JSON object"))?;

    if let Some(assert_zero) = object.get("AssertZero") {
        return Ok(AcirOpcode::AssertZero(parse_assert_zero(assert_zero)?));
    }
    if let Some(black_box) = pick_key(object, &["BlackBoxFuncCall", "black_box_func_call"]) {
        return Ok(AcirOpcode::BlackBoxFuncCall(parse_black_box_func_call(
            black_box,
        )?));
    }

    let keys = object.keys().cloned().collect::<Vec<_>>().join(", ");
    Err(LoquatError::invalid_parameters(&format!(
        "unsupported ACIR opcode; expected `AssertZero` or `BlackBoxFuncCall`, found keys: {keys}"
    )))
}

fn parse_assert_zero(value: &Value) -> LoquatResult<AssertZeroOpcode> {
    let normalized = unwrap_value_field(value);
    let object = normalized.as_object().ok_or_else(|| {
        LoquatError::invalid_parameters("AssertZero payload must be a JSON object")
    })?;

    let mul_terms_value = pick_key(object, &["mul_terms", "mulTerms"])
        .ok_or_else(|| LoquatError::invalid_parameters("AssertZero missing `mul_terms`"))?;
    let linear_terms_value = pick_key(
        object,
        &[
            "linear_combinations",
            "linearCombinations",
            "linear_terms",
            "linearTerms",
        ],
    )
    .ok_or_else(|| LoquatError::invalid_parameters("AssertZero missing `linear_combinations`"))?;
    let q_c_value = pick_key(object, &["q_c", "qC", "constant"])
        .ok_or_else(|| LoquatError::invalid_parameters("AssertZero missing `q_c`"))?;

    let mul_terms = mul_terms_value
        .as_array()
        .ok_or_else(|| LoquatError::invalid_parameters("`mul_terms` must be an array"))?
        .iter()
        .map(parse_mul_term)
        .collect::<LoquatResult<Vec<_>>>()?;

    let linear_combinations = linear_terms_value
        .as_array()
        .ok_or_else(|| LoquatError::invalid_parameters("`linear_combinations` must be an array"))?
        .iter()
        .map(parse_lin_term)
        .collect::<LoquatResult<Vec<_>>>()?;

    Ok(AssertZeroOpcode {
        mul_terms,
        linear_combinations,
        q_c: parse_field(q_c_value)?,
    })
}

fn parse_mul_term(value: &Value) -> LoquatResult<MulTerm> {
    if let Some(items) = value.as_array() {
        if items.len() < 3 {
            return Err(LoquatError::invalid_parameters(
                "mul term array must have at least 3 elements: [coeff, lhs, rhs]",
            ));
        }
        return Ok(MulTerm {
            coefficient: parse_field(&items[0])?,
            lhs_witness: parse_usize(&items[1])?,
            rhs_witness: parse_usize(&items[2])?,
        });
    }

    let obj = value
        .as_object()
        .ok_or_else(|| LoquatError::invalid_parameters("mul term must be an array or object"))?;

    let coeff = pick_key(obj, &["q_m", "coeff", "coefficient", "mul_coeff"])
        .ok_or_else(|| LoquatError::invalid_parameters("mul term missing coefficient"))?;

    let lhs = pick_key(obj, &["lhs", "left", "w_l", "wl", "a"])
        .ok_or_else(|| LoquatError::invalid_parameters("mul term missing lhs witness"))?;
    let rhs = pick_key(obj, &["rhs", "right", "w_r", "wr", "b"])
        .ok_or_else(|| LoquatError::invalid_parameters("mul term missing rhs witness"))?;

    Ok(MulTerm {
        coefficient: parse_field(coeff)?,
        lhs_witness: parse_usize(lhs)?,
        rhs_witness: parse_usize(rhs)?,
    })
}

fn parse_lin_term(value: &Value) -> LoquatResult<LinTerm> {
    if let Some(items) = value.as_array() {
        if items.len() < 2 {
            return Err(LoquatError::invalid_parameters(
                "linear term array must have at least 2 elements: [coeff, witness]",
            ));
        }
        return Ok(LinTerm {
            coefficient: parse_field(&items[0])?,
            witness: parse_usize(&items[1])?,
        });
    }

    let obj = value
        .as_object()
        .ok_or_else(|| LoquatError::invalid_parameters("linear term must be an array or object"))?;

    let coeff = pick_key(obj, &["coeff", "coefficient", "q_l", "q"])
        .ok_or_else(|| LoquatError::invalid_parameters("linear term missing coefficient"))?;
    let witness = pick_key(obj, &["witness", "w", "idx", "index"])
        .ok_or_else(|| LoquatError::invalid_parameters("linear term missing witness index"))?;

    Ok(LinTerm {
        coefficient: parse_field(coeff)?,
        witness: parse_usize(witness)?,
    })
}

fn parse_black_box_func_call(value: &Value) -> LoquatResult<BlackBoxFuncCallOpcode> {
    let normalized = unwrap_value_field(value);
    let object = normalized.as_object().ok_or_else(|| {
        LoquatError::invalid_parameters("BlackBoxFuncCall payload must be a JSON object")
    })?;

    let name_value = pick_key(object, &["name", "op", "func", "function"])
        .ok_or_else(|| LoquatError::invalid_parameters("BlackBoxFuncCall missing `name`"))?;
    let name = name_value
        .as_str()
        .ok_or_else(|| LoquatError::invalid_parameters("BlackBoxFuncCall `name` must be a string"))?
        .to_string();

    let inputs = if let Some(inputs_value) = pick_key(object, &["inputs", "input"]) {
        let arr = inputs_value.as_array().ok_or_else(|| {
            LoquatError::invalid_parameters("BlackBoxFuncCall `inputs` must be an array")
        })?;
        arr.iter()
            .map(parse_black_box_input)
            .collect::<LoquatResult<Vec<_>>>()?
    } else {
        Vec::new()
    };

    let outputs = if let Some(outputs_value) = pick_key(object, &["outputs", "output"]) {
        parse_black_box_outputs(outputs_value)?
    } else {
        Vec::new()
    };

    let payload = pick_key(object, &["payload", "data", "metadata", "extra"]).cloned();

    Ok(BlackBoxFuncCallOpcode {
        name,
        inputs,
        outputs,
        payload,
    })
}

fn parse_black_box_outputs(value: &Value) -> LoquatResult<Vec<usize>> {
    let arr = value.as_array().ok_or_else(|| {
        LoquatError::invalid_parameters("BlackBoxFuncCall `outputs` must be an array")
    })?;
    arr.iter().map(parse_output_witness).collect()
}

fn parse_output_witness(value: &Value) -> LoquatResult<usize> {
    if let Some(v) = parse_output_witness_opt(value)? {
        return Ok(v);
    }
    Err(LoquatError::invalid_parameters(
        "BlackBox output entry must include a witness index",
    ))
}

fn parse_output_witness_opt(value: &Value) -> LoquatResult<Option<usize>> {
    if let Some(v) = value.as_u64() {
        return Ok(Some(v as usize));
    }
    if let Some(v) = value.as_i64() {
        if v < 0 {
            return Err(LoquatError::invalid_parameters(
                "BlackBox output witness index must be non-negative",
            ));
        }
        return Ok(Some(v as usize));
    }
    if let Some(s) = value.as_str() {
        let parsed = s.parse::<usize>().map_err(|err| {
            LoquatError::invalid_parameters(&format!(
                "invalid black-box output witness index `{s}`: {err}"
            ))
        })?;
        return Ok(Some(parsed));
    }
    if let Some(obj) = value.as_object() {
        if let Some(inner) = pick_key(obj, &["witness", "output", "index", "value"]) {
            return Ok(Some(parse_usize(inner)?));
        }
    }
    Ok(None)
}

fn parse_black_box_input(value: &Value) -> LoquatResult<BlackBoxInput> {
    if let Some(items) = value.as_array() {
        if items.is_empty() {
            return Err(LoquatError::invalid_parameters(
                "black-box input array must not be empty",
            ));
        }
        let witness = parse_output_witness_opt(&items[0])?;
        let num_bits = if items.len() >= 2 {
            Some(parse_usize(&items[1])?)
        } else {
            None
        };
        return Ok(BlackBoxInput {
            witness,
            constant: None,
            num_bits,
        });
    }

    if value.is_number() || value.is_string() {
        return Ok(BlackBoxInput {
            witness: parse_output_witness_opt(value)?,
            constant: None,
            num_bits: None,
        });
    }

    let obj = value.as_object().ok_or_else(|| {
        LoquatError::invalid_parameters("black-box input must be an object/number/array")
    })?;

    let witness = if let Some(w) = pick_key(obj, &["witness", "index", "idx"]) {
        if let Some(inner_obj) = w.as_object() {
            if let Some(inner) = pick_key(inner_obj, &["witness", "index", "value"]) {
                Some(parse_usize(inner)?)
            } else {
                Some(parse_usize(w)?)
            }
        } else {
            Some(parse_usize(w)?)
        }
    } else {
        None
    };

    let constant = if let Some(c) = pick_key(obj, &["constant", "const", "value"]) {
        if c.is_object() && witness.is_some() {
            None
        } else {
            Some(parse_field(c)?)
        }
    } else {
        None
    };

    let num_bits = if let Some(bits) = pick_key(obj, &["num_bits", "numBits", "bits"]) {
        Some(parse_usize(bits)?)
    } else {
        None
    };

    Ok(BlackBoxInput {
        witness,
        constant,
        num_bits,
    })
}

fn parse_usize(value: &Value) -> LoquatResult<usize> {
    if let Some(v) = value.as_u64() {
        return Ok(v as usize);
    }
    if let Some(v) = value.as_i64() {
        if v < 0 {
            return Err(LoquatError::invalid_parameters(
                "witness index must be non-negative",
            ));
        }
        return Ok(v as usize);
    }
    if let Some(s) = value.as_str() {
        return s.parse::<usize>().map_err(|err| {
            LoquatError::invalid_parameters(&format!("invalid witness index `{s}`: {err}"))
        });
    }
    if let Some(obj) = value.as_object() {
        if let Some(inner) = pick_key(obj, &["value", "index", "witness"]) {
            return parse_usize(inner);
        }
    }
    Err(LoquatError::invalid_parameters(
        "failed to parse witness index from JSON value",
    ))
}

fn parse_field(value: &Value) -> LoquatResult<F> {
    match value {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                return Ok(F::new(u as u128));
            }
            if let Some(i) = n.as_i64() {
                return Ok(signed_to_field(i.is_negative(), i.unsigned_abs() as u128));
            }
            Err(LoquatError::invalid_parameters(
                "number does not fit in supported integer range",
            ))
        }
        Value::String(s) => parse_field_string(s),
        Value::Object(obj) => {
            if let Some(inner) = pick_key(obj, &["value", "coeff", "coefficient", "q"]) {
                parse_field(inner)
            } else {
                Err(LoquatError::invalid_parameters(
                    "object field element missing numeric `value`",
                ))
            }
        }
        _ => Err(LoquatError::invalid_parameters(
            "unsupported JSON value for field element",
        )),
    }
}

fn parse_field_string(raw: &str) -> LoquatResult<F> {
    let normalized = raw.replace('_', "");
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return Err(LoquatError::invalid_parameters("empty field string"));
    }

    if let Some(hex_digits) = trimmed.strip_prefix("0x") {
        let value = u128::from_str_radix(hex_digits, 16).map_err(|err| {
            LoquatError::invalid_parameters(&format!(
                "invalid hex field element `{trimmed}`: {err}"
            ))
        })?;
        return Ok(F::new(value));
    }

    if let Some(hex_digits) = trimmed.strip_prefix("-0x") {
        let value = u128::from_str_radix(hex_digits, 16).map_err(|err| {
            LoquatError::invalid_parameters(&format!(
                "invalid hex field element `{trimmed}`: {err}"
            ))
        })?;
        return Ok(signed_to_field(true, value));
    }

    if let Ok(value) = trimmed.parse::<i128>() {
        return Ok(signed_to_field(value.is_negative(), value.unsigned_abs()));
    }

    Err(LoquatError::invalid_parameters(&format!(
        "failed to parse field element string `{trimmed}`"
    )))
}

fn signed_to_field(is_negative: bool, magnitude: u128) -> F {
    if !is_negative {
        return F::new(magnitude);
    }
    let reduced = magnitude % P127_MODULUS;
    if reduced == 0 {
        F::zero()
    } else {
        F::new(P127_MODULUS - reduced)
    }
}

fn unwrap_value_field(value: &Value) -> &Value {
    if let Some(obj) = value.as_object() {
        if let Some(inner) = obj.get("value") {
            return inner;
        }
    }
    value
}

fn pick_key<'a>(obj: &'a serde_json::Map<String, Value>, keys: &[&str]) -> Option<&'a Value> {
    for key in keys {
        if let Some(value) = obj.get(*key) {
            return Some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_assert_zero_program() {
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

        let parsed = parse_acir_json(json).expect("ACIR should parse");
        assert_eq!(parsed.current_witness_index, 3);
        assert_eq!(parsed.opcodes.len(), 1);
        match &parsed.opcodes[0] {
            AcirOpcode::AssertZero(op) => {
                assert_eq!(op.mul_terms.len(), 1);
                assert_eq!(op.linear_combinations.len(), 1);
                assert!(op.q_c.is_zero());
            }
            AcirOpcode::BlackBoxFuncCall(_) => {
                panic!("expected AssertZero opcode")
            }
        }
    }

    #[test]
    fn parse_program_without_public_parameters_defaults_to_empty() {
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

        let parsed = parse_acir_json(json).expect("ACIR should parse");
        assert!(parsed.public_parameters.is_empty());
        assert!(parsed.return_values.is_empty());
    }

    #[test]
    fn parse_program_with_public_parameters_and_return_values() {
        let json = r#"
        {
            "current_witness_index": 5,
            "public_parameters": [1, 2],
            "return_values": [5],
            "opcodes": []
        }
        "#;

        let parsed = parse_acir_json(json).expect("ACIR should parse");
        assert_eq!(parsed.public_parameters, vec![1, 2]);
        assert_eq!(parsed.return_values, vec![5]);
    }

    #[test]
    fn parse_program_with_indices_object_form() {
        // Some nargo versions emit `{"indices": [...]}` — the parser tolerates that.
        let json = r#"
        {
            "current_witness_index": 4,
            "public_parameters": { "indices": [3, 4] },
            "opcodes": []
        }
        "#;

        let parsed = parse_acir_json(json).expect("ACIR should parse");
        assert_eq!(parsed.public_parameters, vec![3, 4]);
        assert!(parsed.return_values.is_empty());
    }

    #[test]
    fn parse_black_box_func_call_opcode() {
        let json = r#"
        {
            "current_witness_index": 4,
            "opcodes": [
                {
                    "BlackBoxFuncCall": {
                        "value": {
                            "name": "RANGE",
                            "inputs": [
                                { "witness": 1, "num_bits": 8 }
                            ],
                            "outputs": [4]
                        }
                    }
                }
            ]
        }
        "#;

        let parsed = parse_acir_json(json).expect("ACIR should parse");
        assert_eq!(parsed.current_witness_index, 4);
        assert_eq!(parsed.opcodes.len(), 1);

        match &parsed.opcodes[0] {
            AcirOpcode::BlackBoxFuncCall(call) => {
                assert_eq!(call.name, "RANGE");
                assert_eq!(call.inputs.len(), 1);
                assert_eq!(call.inputs[0].witness, Some(1));
                assert_eq!(call.inputs[0].num_bits, Some(8));
                assert_eq!(call.outputs, vec![4]);
            }
            AcirOpcode::AssertZero(_) => panic!("expected BlackBoxFuncCall opcode"),
        }
    }
}
