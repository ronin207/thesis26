//! Jolt Loquat verification guest (smoke).
//!
//! Loquat is no_std-compatible, so its verify path can run as a Jolt
//! `#[jolt::provable]` function directly. PLUM is std-only (`HashMap` /
//! `HashSet` in `plum::*`) and is intentionally not included here.
//!
//! Input shape: `postcard`-encoded `(LoquatPublicParams, message_bytes,
//! public_key, LoquatSignature)`. We bundle as a typed struct so the
//! prover and host stay in lock-step.

#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use vc_pqc::signatures::loquat::{
    LoquatPublicParams, LoquatSignature, field_utils::F, loquat_verify,
};

#[derive(Serialize, Deserialize)]
pub struct LoquatGuestInput {
    pub params: LoquatPublicParams,
    pub message: Vec<u8>,
    pub public_key: Vec<F>,
    pub signature: LoquatSignature,
}

#[jolt::provable(heap_size = 16777216, max_trace_length = 16777216)]
fn loquat_smoke(input_bytes: Vec<u8>) -> bool {
    let input: LoquatGuestInput = postcard::from_bytes(&input_bytes)
        .expect("guest: postcard decode failed");
    match loquat_verify(&input.message, &input.signature, &input.public_key, &input.params) {
        Ok(accepted) => accepted,
        Err(_) => false,
    }
}
