//! SP1 PLUM verification guest (Phase 3f — Griffin variant + Cell 3
//! SHA3 variant via `plum-sha3-hasher` feature).
//!
//! Reads `(pp, pk, message, sig)` over the SP1 input stream, runs
//! `plum_verify` with the cfg-selected hasher, and commits a single
//! `bool` indicating the verification outcome.
//!
//! ### Hash variant — three build arms
//!
//! - default features              → Griffin via `GRIFFIN_FP192_PERMUTE`
//!   syscall (Cell 2 — load-bearing precompile path).
//! - `--features griffin-emulated` → Griffin in rv32im (Cell 1 —
//!   precompile-less baseline; UINT256_MUL still on).
//! - `--features plum-sha3-hasher` → SHA3-256 in software (Cell 3 —
//!   control arm; isolates whether Cell 2's win is Griffin-specific
//!   or any-precompile).
//!
//! Per PLUM §4.2's R1CS decomposition: 91% of constraints are
//! attributable to hash work, so swapping the hash dominates the
//! cycle-cost delta between arms.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

#[cfg(feature = "plum-sha3-hasher")]
use vc_pqc::signatures::plum::hasher::PlumSha3Hasher as Hasher;
// Griffin for hashing, SHAKE256 for Fiat–Shamir: the faithful Cell 2 runtime
// configuration (1,052 Griffin perms). NOT `PlumGriffinHasher`, whose
// `USE_GRIFFIN_FS = true` routes FS through the quadratic Griffin sponge
// (~6,575 perms) — that flag is retained only for the Stage-4c-4 circuit gate.
#[cfg(not(feature = "plum-sha3-hasher"))]
use vc_pqc::signatures::plum::hasher::PlumGriffinShakeFsHasher as Hasher;

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

    let outcome = plum_verify::<Hasher>(
        &input.pp,
        &input.pk,
        &input.message,
        &input.signature,
    );

    let accepted = matches!(outcome, VerificationOutcome::Accept);
    sp1_zkvm::io::commit(&accepted);
}
