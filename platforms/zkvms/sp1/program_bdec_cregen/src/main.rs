//! BDEC CreGen statement (ProSec 2024, §3) — PLUM-Griffin, SP1 port.
//!
//! Proves the two `Sig.Verify` instances of the BDEC CreGen relation under a
//! shared (witness-only) PLUM public key `pk_U`:
//!
//!   1. `plum_verify(pp, pk_U, h_{U,TA}, c_{U,TA}) = 1`
//!   2. `plum_verify(pp, pk_U, ppk_{U,TA}, psk_{U,TA}) = 1`
//!
//! SP1 mirror of
//! `platforms/zkvms/risc0/methods/guest/src/bin/bdec_credgen_plum_griffin.rs`.
//!
//! ## Measurement model
//!
//! SP1 reports cycles and syscall counts host-side from the `ExecutionReport`
//! (see `script/src/bin/bdec_cregen_host.rs`), so this guest stays minimal:
//! it commits ONLY the aggregate `both_ok` bool. `pk_U` and both signatures
//! are private witnesses read off the input stream and are NEVER committed.
//!
//! ## Hash arm (build-time)
//!
//! - default features              → Griffin via `GRIFFIN_FP192_PERMUTE`
//!   syscall (the load-bearing precompile path).
//! - `--features griffin-emulated` → Griffin in rv32im (precompile-less
//!   baseline; `UINT256_MUL` still on).
//!
//! ## Why `plum_verify_phased` and not `plum_verify`
//!
//! `plum_verify` does not clear the static `VERIFY_PHASE_SNAPSHOTS` buffer at
//! entry, which corrupts the second sequential verify in a single guest
//! invocation. `plum_verify_phased` clears the buffer per call. See the RISC0
//! guest doc-comment and `docs/plum_in_bdec_blocker_20260529.md`.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

use vc_pqc::signatures::plum::hasher::PlumGriffinHasher;
use vc_pqc::signatures::plum::keygen::PlumPublicKey;
use vc_pqc::signatures::plum::setup::PlumPublicParams;
use vc_pqc::signatures::plum::sign::PlumSignature;
use vc_pqc::signatures::plum::verify::{VerificationOutcome, plum_verify_phased};

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    h_u_ta: Vec<u8>,
    c_u_ta: PlumSignature,
    ppk_u_ta: Vec<u8>,
    psk_u_ta: PlumSignature,
}

pub fn main() {
    let input_bytes = sp1_zkvm::io::read_vec();
    let input: GuestInput =
        bincode::deserialize(&input_bytes).expect("guest: bincode decode failed");

    // 1. credential signature over the attribute hash.
    let cred = plum_verify_phased::<PlumGriffinHasher>(
        &input.pp,
        &input.pk_u,
        &input.h_u_ta,
        &input.c_u_ta,
    );
    let sig_ok = matches!(cred.outcome, VerificationOutcome::Accept);

    // 2. pseudonym-ownership signature, same hidden pk_U.
    let nym = plum_verify_phased::<PlumGriffinHasher>(
        &input.pp,
        &input.pk_u,
        &input.ppk_u_ta,
        &input.psk_u_ta,
    );
    let nym_ok = matches!(nym.outcome, VerificationOutcome::Accept);

    // Only the aggregate boolean is public; pk_U and the signatures stay
    // private (never committed).
    let both_ok = sig_ok && nym_ok;
    sp1_zkvm::io::commit(&both_ok);
}
