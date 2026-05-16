//! PLUM signature verification guest binary — **Griffin hasher variant**.
//!
//! Mirror of `plum_verify.rs` (which uses `PlumSha3Hasher`) but
//! parameterised over `PlumGriffinHasher`. Phase 11 of
//! `spec/plum_implementation_plan.md` runs both binaries on the same
//! `(pp, pk, message, signature)` shape and compares the three-level
//! cycle attribution.
//!
//! The signature itself is hasher-dependent (Merkle commits + Fiat-
//! Shamir absorbs use the hasher), so the host must sign with
//! `PlumGriffinHasher` to produce a signature this binary will
//! accept.

use std::sync::atomic::Ordering;

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

use vc_pqc::plum::field_p192::{FP192_ADD_COUNT, FP192_MUL_COUNT};
use vc_pqc::plum::griffin::PLUM_GRIFFIN_PERM_COUNT;
use vc_pqc::plum::hasher::{PLUM_HASHER_COMPRESS_COUNT, PlumGriffinHasher};
use vc_pqc::plum::keygen::PlumPublicKey;
use vc_pqc::plum::prf::PLUM_PRF_EVAL_COUNT;
use vc_pqc::plum::setup::PlumPublicParams;
use vc_pqc::plum::sign::PlumSignature;
use vc_pqc::plum::verify::{VerificationOutcome, plum_verify};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk: PlumPublicKey,
    message: Vec<u8>,
    signature: PlumSignature,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct PlumGuestCounters {
    pub fp192_muls: u64,
    pub fp192_adds: u64,
    pub griffin_perms: u64,
    pub prf_evals: u64,
    pub hasher_compresses: u64,
    pub verify_cycles_self_reported: u64,
}

#[derive(Serialize, Deserialize)]
struct GuestOutput {
    verified: bool,
    counters: PlumGuestCounters,
}

fn main() {
    let input: GuestInput = env::read();

    FP192_MUL_COUNT.store(0, Ordering::SeqCst);
    FP192_ADD_COUNT.store(0, Ordering::SeqCst);
    PLUM_GRIFFIN_PERM_COUNT.store(0, Ordering::SeqCst);
    PLUM_PRF_EVAL_COUNT.store(0, Ordering::SeqCst);
    PLUM_HASHER_COMPRESS_COUNT.store(0, Ordering::SeqCst);

    let cycles_before = env::cycle_count();
    let outcome = plum_verify::<PlumGriffinHasher>(
        &input.pp,
        &input.pk,
        &input.message,
        &input.signature,
    );
    let cycles_after = env::cycle_count();

    let verified = matches!(outcome, VerificationOutcome::Accept);
    let counters = PlumGuestCounters {
        fp192_muls: FP192_MUL_COUNT.load(Ordering::SeqCst),
        fp192_adds: FP192_ADD_COUNT.load(Ordering::SeqCst),
        griffin_perms: PLUM_GRIFFIN_PERM_COUNT.load(Ordering::SeqCst),
        prf_evals: PLUM_PRF_EVAL_COUNT.load(Ordering::SeqCst),
        hasher_compresses: PLUM_HASHER_COMPRESS_COUNT.load(Ordering::SeqCst),
        verify_cycles_self_reported: cycles_after.saturating_sub(cycles_before) as u64,
    };

    env::commit(&GuestOutput { verified, counters });
}
