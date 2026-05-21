//! SP1 Loquat verification guest (Phase B6.4, same-family Legendre-PRF
//! PQ scheme).
//!
//! Verifies a Loquat signature (Mersenne-127 field, SHA-3 hash chain
//! — the original Loquat paper instantiation, before PLUM's
//! generalisation to t-th power residue + Griffin Fp192). Routes
//! Keccak through the workspace tiny-keccak SP1 patch.
//!
//! Expected cost regime: roughly Cell-3-like (PLUM-SHA3) since the
//! hash work is similar, modulo a smaller prime field; this is the
//! same-family confirmation that the Loquat → PLUM transition's
//! cost difference is specifically the algebraic-hash design choice,
//! not the Legendre-PRF family as a whole.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

use vc_pqc::signatures::loquat::field_utils::F;
use vc_pqc::signatures::loquat::setup::LoquatPublicParams;
use vc_pqc::signatures::loquat::sign::LoquatSignature;
use vc_pqc::signatures::loquat::verify::loquat_verify;

#[derive(Serialize, Deserialize)]
struct GuestInput {
    /// Arbitrary signed message.
    message: Vec<u8>,
    /// Loquat signature.
    signature: LoquatSignature,
    /// Public key — a vector of Mersenne-127 field elements.
    public_key: Vec<F>,
    /// Public parameters (lambda, evaluation domain, Merkle config, ...).
    params: LoquatPublicParams,
}

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input: GuestInput =
        bincode::deserialize(&bytes).expect("loquat guest: bincode decode failed");

    let accepted = loquat_verify(
        &input.message,
        &input.signature,
        &input.public_key,
        &input.params,
    )
    .expect("loquat guest: verification errored");

    sp1_zkvm::io::commit(&accepted);
}
