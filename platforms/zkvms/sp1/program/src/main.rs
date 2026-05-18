//! SP1 PLUM verification guest (Phase 3f — Griffin variant).
//!
//! Reads `(pp, pk, message, sig)` over the SP1 input stream, runs
//! `plum_verify` with `PlumGriffinHasher`, and commits a single
//! `bool` indicating the verification outcome.
//!
//! ### Hash variant
//!
//! Switched from `PlumSha3Hasher` (Phase 1+2+A smoke) to
//! `PlumGriffinHasher` (Phase 3f measurement target). Griffin is the
//! load-bearing primitive on the PLUM-verify hot path (per PLUM
//! §4.2's R1CS decomposition: 91% of constraints, ~94% of muls
//! attributable to Step 2 / STIR Merkle work). Without this switch,
//! the SP1 `GRIFFIN_FP192_PERMUTE` syscall is dormant — the
//! cfg-gated route in `vc-pqc::primitives::hash::griffin_p192`
//! compiles in but is never reached.
//!
//! ### A/B isolation
//!
//! Built with default features → Griffin permutation routes through
//! the syscall. Built with `--features griffin-emulated` → Griffin
//! permutation runs natively in rv32im (UINT256_MUL precompile still
//! on, isolating the Griffin contribution).

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

use vc_pqc::signatures::plum::hasher::PlumGriffinHasher;
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

    let outcome = plum_verify::<PlumGriffinHasher>(
        &input.pp,
        &input.pk,
        &input.message,
        &input.signature,
    );

    let accepted = matches!(outcome, VerificationOutcome::Accept);
    sp1_zkvm::io::commit(&accepted);
}
