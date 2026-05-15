use crate::signatures::loquat::errors::{LoquatError, LoquatResult};
use crate::signatures::loquat::field_utils::F;
use crate::compilers::noir::{AcirR1csBuild, compile_acir_json_to_r1cs};
use crate::snarks::{AuroraParams, AuroraProof, R1csInstance, aurora_prove, aurora_verify};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NoirAuroraBackend {
    pub aurora_params: AuroraParams,
}

impl NoirAuroraBackend {
    pub fn new(aurora_params: AuroraParams) -> Self {
        Self { aurora_params }
    }

    pub fn compile(
        &self,
        acir_json: &str,
        witness_inputs: Option<&HashMap<usize, F>>,
    ) -> LoquatResult<AcirR1csBuild> {
        compile_acir_json_to_r1cs(acir_json, witness_inputs)
    }

    pub fn prove(&self, compiled: &AcirR1csBuild) -> LoquatResult<AuroraProof> {
        let witness = compiled.witness.as_ref().ok_or_else(|| {
            LoquatError::invalid_parameters(
                "cannot prove Noir circuit without witness values; pass witness inputs to compile()",
            )
        })?;
        aurora_prove(&compiled.instance, witness, &self.aurora_params)
    }

    pub fn verify(&self, instance: &R1csInstance, proof: &AuroraProof) -> LoquatResult<bool> {
        Ok(aurora_verify(instance, proof, &self.aurora_params, None)?.is_some())
    }
}
