//! SP1 PLUM verification guest (smoke).
//!
//! Reads `(pp, pk, message, sig)` over the SP1 input stream, runs
//! `plum_verify` with `PlumSha3Hasher`, and commits a single `bool`
//! indicating the verification outcome.
//!
//! Intentionally minimal — no cycle-attribution counters, no Griffin
//! variant. Once this smoke builds and a proof round-trips, the
//! attribution and Griffin variants port over from the risc0 guest
//! mechanically.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

use vc_pqc::signatures::plum::hasher::PlumSha3Hasher;
use vc_pqc::signatures::plum::keygen::PlumPublicKey;
use vc_pqc::signatures::plum::setup::PlumPublicParams;
use vc_pqc::signatures::plum::sign::PlumSignature;
use vc_pqc::signatures::plum::verify::{VerificationOutcome, plum_verify};

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk: PlumPublicKey,
    message: Vec<u8>,
    signature: PlumSignature,
}

pub fn main() {
    let input_bytes = sp1_zkvm::io::read_vec();
    let input: GuestInput =
        bincode::deserialize(&input_bytes).expect("guest: bincode decode failed");

    let outcome = plum_verify::<PlumSha3Hasher>(
        &input.pp,
        &input.pk,
        &input.message,
        &input.signature,
    );

    let accepted = matches!(outcome, VerificationOutcome::Accept);
    sp1_zkvm::io::commit(&accepted);
}
