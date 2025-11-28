#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
#[cfg(feature = "std")]
use std::vec::Vec;

#[derive(Clone, Debug)]
pub struct GriffinParams;

#[derive(Clone, Debug)]
pub struct GriffinState;

pub fn get_griffin_params() -> GriffinParams {
    GriffinParams
}

pub fn griffin_hash(_params: &GriffinParams, data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn griffin_hash_default(data: &[u8]) -> Vec<u8> {
    let params = get_griffin_params();
    griffin_hash(&params, data)
}

pub fn griffin_sponge(_params: &GriffinParams, _state: &mut GriffinState) {
    // Do nothing
}
