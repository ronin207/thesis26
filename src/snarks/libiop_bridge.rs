use crate::snarks::r1cs::{R1csConstraint, R1csInstance, R1csWitness};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LibiopStatus {
    Ok = 0,
    NullPointer = 1,
    InvalidArgument = 2,
    AllocationFailure = 3,
    ProofFailure = 4,
    InternalError = 5,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum LibiopDomainType {
    Affine = 0,
    Multiplicative = 1,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct LibiopAuroraOptions {
    pub security_parameter: usize,
    pub fri_localization_parameter: usize,
    pub rs_extra_dimensions: usize,
    pub domain_type: LibiopDomainType,
    pub make_zk: u8,
}

impl Default for LibiopAuroraOptions {
    fn default() -> Self {
        Self {
            security_parameter: 128,
            fri_localization_parameter: 3,
            rs_extra_dimensions: 2,
            domain_type: LibiopDomainType::Affine,
            make_zk: 0,
        }
    }
}

pub type LibiopFractalOptions = LibiopAuroraOptions;

#[repr(C)]
pub struct LibiopR1cs {
    pub num_variables: usize,
    pub num_constraints: usize,
    pub a: *const u8,
    pub b: *const u8,
    pub c: *const u8,
}

#[repr(C)]
pub struct LibiopWitness {
    pub assignment: *const u8,
    pub assignment_len: usize,
}

#[repr(C)]
pub struct LibiopBuffer {
    pub data: *mut u8,
    pub len: usize,
}

unsafe extern "C" {
    pub fn libiop_initialize() -> LibiopStatus;

    pub fn libiop_aurora_prove(
        instance: *const LibiopR1cs,
        witness: *const LibiopWitness,
        options: *const LibiopAuroraOptions,
        out_proof: *mut LibiopBuffer,
    ) -> LibiopStatus;

    pub fn libiop_aurora_verify(
        instance: *const LibiopR1cs,
        options: *const LibiopAuroraOptions,
        proof_bytes: *const u8,
        proof_len: usize,
        out_valid: *mut c_int,
    ) -> LibiopStatus;

    pub fn libiop_fractal_prove(
        instance: *const LibiopR1cs,
        witness: *const LibiopWitness,
        options: *const LibiopFractalOptions,
        out_proof: *mut LibiopBuffer,
    ) -> LibiopStatus;

    pub fn libiop_fractal_verify(
        instance: *const LibiopR1cs,
        options: *const LibiopFractalOptions,
        proof_bytes: *const u8,
        proof_len: usize,
        out_valid: *mut c_int,
    ) -> LibiopStatus;

    pub fn libiop_buffer_free(buffer: *mut LibiopBuffer);

    pub fn libiop_last_error_message() -> *const c_char;
}

#[derive(Debug)]
pub struct LibiopError {
    pub status: LibiopStatus,
    pub message: String,
}

impl std::fmt::Display for LibiopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LibiopError({:?}): {}", self.status, self.message)
    }
}

impl std::error::Error for LibiopError {}

fn check_status(status: LibiopStatus) -> Result<(), LibiopError> {
    if status == LibiopStatus::Ok {
        Ok(())
    } else {
        let msg = unsafe {
            let ptr = libiop_last_error_message();
            if ptr.is_null() {
                "Unknown error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        Err(LibiopError {
            status,
            message: msg,
        })
    }
}

struct SerializedR1cs {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
    num_variables: usize,
    num_constraints: usize,
}

fn serialize_constraints(constraints: &[R1csConstraint], num_variables: usize) -> SerializedR1cs {
    let field_bytes = 8; // gf64 is 8 bytes
    let field_variables = num_variables.saturating_sub(1);
    let padded_field_variables = if field_variables == 0 {
        1
    } else {
        ((field_variables + 1).next_power_of_two()).saturating_sub(1)
    };
    let padded_num_variables = padded_field_variables + 1;
    let padded_row_len = padded_num_variables * field_bytes;

    let padded_constraints = constraints.len().next_power_of_two().max(1);
    let total_len = padded_constraints * padded_row_len;

    let mut a_buf = vec![0u8; total_len];
    let mut b_buf = vec![0u8; total_len];
    let mut c_buf = vec![0u8; total_len];

    for (i, constraint) in constraints.iter().enumerate() {
        let offset = i * padded_row_len;

        // Helper to write a row
        let write_row = |coeffs: &[crate::loquat::field_utils::F], buf: &mut [u8]| {
            for (var_idx, coeff) in coeffs.iter().enumerate() {
                if var_idx >= padded_num_variables {
                    break;
                }
                let bytes = crate::loquat::field_utils::field_to_bytes(coeff);
                let start = offset + var_idx * field_bytes;
                buf[start..start + field_bytes].copy_from_slice(&bytes[..field_bytes]);
            }
        };

        write_row(&constraint.a, &mut a_buf);
        write_row(&constraint.b, &mut b_buf);
        write_row(&constraint.c, &mut c_buf);
    }

    SerializedR1cs {
        a: a_buf,
        b: b_buf,
        c: c_buf,
        num_variables: padded_num_variables,
        num_constraints: padded_constraints,
    }
}

fn serialize_witness(witness: &R1csWitness, padded_num_variables: usize) -> Vec<u8> {
    let field_bytes = 8;
    let target_assignment_len = padded_num_variables.saturating_sub(1);
    let mut buf = vec![0u8; target_assignment_len * field_bytes];
    for (idx, val) in witness.assignment.iter().enumerate() {
        if idx >= target_assignment_len {
            break;
        }
        let bytes = crate::loquat::field_utils::field_to_bytes(val);
        let start = idx * field_bytes;
        buf[start..start + field_bytes].copy_from_slice(&bytes[..field_bytes]);
    }
    buf
}

pub fn initialize() -> Result<(), LibiopError> {
    unsafe { check_status(libiop_initialize()) }
}

pub fn aurora_prove_ffi(
    instance: &R1csInstance,
    witness: &R1csWitness,
    options: Option<LibiopAuroraOptions>,
) -> Result<Vec<u8>, LibiopError> {
    let serialized = serialize_constraints(&instance.constraints, instance.num_variables);
    let c_r1cs = LibiopR1cs {
        num_variables: serialized.num_variables,
        num_constraints: serialized.num_constraints,
        a: serialized.a.as_ptr(),
        b: serialized.b.as_ptr(),
        c: serialized.c.as_ptr(),
    };

    let w_buf = serialize_witness(witness, serialized.num_variables);
    let c_witness = LibiopWitness {
        assignment: w_buf.as_ptr(),
        assignment_len: serialized.num_variables.saturating_sub(1),
    };

    let opts = options.unwrap_or_default();
    let mut out_proof = LibiopBuffer {
        data: ptr::null_mut(),
        len: 0,
    };

    unsafe {
        check_status(libiop_aurora_prove(
            &c_r1cs,
            &c_witness,
            &opts,
            &mut out_proof,
        ))?;
    }

    let proof = unsafe { slice::from_raw_parts(out_proof.data, out_proof.len).to_vec() };
    unsafe { libiop_buffer_free(&mut out_proof) };
    Ok(proof)
}

pub fn aurora_verify_ffi(
    instance: &R1csInstance,
    proof: &[u8],
    options: Option<LibiopAuroraOptions>,
) -> Result<bool, LibiopError> {
    let serialized = serialize_constraints(&instance.constraints, instance.num_variables);
    let c_r1cs = LibiopR1cs {
        num_variables: serialized.num_variables,
        num_constraints: serialized.num_constraints,
        a: serialized.a.as_ptr(),
        b: serialized.b.as_ptr(),
        c: serialized.c.as_ptr(),
    };

    let opts = options.unwrap_or_default();
    let mut valid = 0;

    unsafe {
        check_status(libiop_aurora_verify(
            &c_r1cs,
            &opts,
            proof.as_ptr(),
            proof.len(),
            &mut valid,
        ))?;
    }

    Ok(valid != 0)
}

pub fn fractal_prove_ffi(
    instance: &R1csInstance,
    witness: &R1csWitness,
    options: Option<LibiopFractalOptions>,
) -> Result<Vec<u8>, LibiopError> {
    let serialized = serialize_constraints(&instance.constraints, instance.num_variables);
    let c_r1cs = LibiopR1cs {
        num_variables: serialized.num_variables,
        num_constraints: serialized.num_constraints,
        a: serialized.a.as_ptr(),
        b: serialized.b.as_ptr(),
        c: serialized.c.as_ptr(),
    };

    let w_buf = serialize_witness(witness, serialized.num_variables);
    let c_witness = LibiopWitness {
        assignment: w_buf.as_ptr(),
        assignment_len: serialized.num_variables.saturating_sub(1),
    };

    let opts = options.unwrap_or_default();
    let mut out_proof = LibiopBuffer {
        data: ptr::null_mut(),
        len: 0,
    };

    unsafe {
        check_status(libiop_fractal_prove(
            &c_r1cs,
            &c_witness,
            &opts,
            &mut out_proof,
        ))?;
    }

    let proof = unsafe { slice::from_raw_parts(out_proof.data, out_proof.len).to_vec() };
    unsafe { libiop_buffer_free(&mut out_proof) };
    Ok(proof)
}

pub fn fractal_verify_ffi(
    instance: &R1csInstance,
    proof: &[u8],
    options: Option<LibiopFractalOptions>,
) -> Result<bool, LibiopError> {
    let serialized = serialize_constraints(&instance.constraints, instance.num_variables);
    let c_r1cs = LibiopR1cs {
        num_variables: serialized.num_variables,
        num_constraints: serialized.num_constraints,
        a: serialized.a.as_ptr(),
        b: serialized.b.as_ptr(),
        c: serialized.c.as_ptr(),
    };

    let opts = options.unwrap_or_default();
    let mut valid = 0;

    unsafe {
        check_status(libiop_fractal_verify(
            &c_r1cs,
            &opts,
            proof.as_ptr(),
            proof.len(),
            &mut valid,
        ))?;
    }

    Ok(valid != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loquat::field_utils::F;

    fn aurora_instance() -> (R1csInstance, R1csWitness) {
        // Aurora requires:
        // num_variables = 2^k - 1 (e.g., 7)
        // num_constraints = 2^m (e.g., 8)

        let num_variables = 7;
        let num_constraints = 8;

        let mut constraints = Vec::with_capacity(num_constraints);

        // Constraint 1: x * y = z
        let mut a = vec![F::zero(); num_variables];
        a[1] = F::one(); // x
        let mut b = vec![F::zero(); num_variables];
        b[2] = F::one(); // y
        let mut c = vec![F::zero(); num_variables];
        c[3] = F::one(); // z
        constraints.push(R1csConstraint::new(a, b, c));

        // Dummy constraints: 0 * 0 = 0
        for _ in 1..num_constraints {
            let a = vec![F::zero(); num_variables];
            let b = vec![F::zero(); num_variables];
            let c = vec![F::zero(); num_variables];
            constraints.push(R1csConstraint::new(a, b, c));
        }

        let instance = R1csInstance::new(num_variables, constraints).unwrap();

        // Witness: x=3, y=5, z=15, plus dummy variables
        let mut assignment = vec![F::new(3), F::new(5), F::new(15)];
        assignment.resize(num_variables - 1, F::zero());

        let witness = R1csWitness::new(assignment);

        (instance, witness)
    }

    fn fractal_instance() -> (R1csInstance, R1csWitness) {
        // Fractal requires:
        // num_variables = num_constraints = 2^k (e.g., 8)

        let num_variables = 8;
        let num_constraints = 8;

        let mut constraints = Vec::with_capacity(num_constraints);

        // Constraint 1: x * y = z
        let mut a = vec![F::zero(); num_variables];
        a[1] = F::one(); // x
        let mut b = vec![F::zero(); num_variables];
        b[2] = F::one(); // y
        let mut c = vec![F::zero(); num_variables];
        c[3] = F::one(); // z
        constraints.push(R1csConstraint::new(a, b, c));

        // Dummy constraints: 0 * 0 = 0
        for _ in 1..num_constraints {
            let a = vec![F::zero(); num_variables];
            let b = vec![F::zero(); num_variables];
            let c = vec![F::zero(); num_variables];
            constraints.push(R1csConstraint::new(a, b, c));
        }

        let instance = R1csInstance::new(num_variables, constraints).unwrap();

        // Witness: x=3, y=5, z=15, plus dummy variables
        let mut assignment = vec![F::new(3), F::new(5), F::new(15)];
        assignment.resize(num_variables - 1, F::zero());

        let witness = R1csWitness::new(assignment);

        (instance, witness)
    }

    #[test]
    fn test_aurora_ffi() {
        initialize().unwrap();
        let (instance, witness) = aurora_instance();

        let proof = aurora_prove_ffi(&instance, &witness, None).expect("Proving failed");
        let valid = aurora_verify_ffi(&instance, &proof, None).expect("Verification failed");

        assert!(valid, "Aurora proof should be valid");
    }

    #[test]
    fn test_fractal_ffi() {
        initialize().unwrap();
        let (instance, witness) = fractal_instance();

        let proof = fractal_prove_ffi(&instance, &witness, None).expect("Proving failed");
        let valid = fractal_verify_ffi(&instance, &proof, None).expect("Verification failed");

        assert!(valid, "Fractal proof should be valid");
    }
}
