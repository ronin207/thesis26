//! PLUM signature verification guest binary.
//!
//! Phase 10 of `spec/plum_implementation_plan.md`. Runs `plum_verify`
//! over a host-supplied (pp, pk, message, sig) tuple inside the risc0
//! zkVM. Resets and reads the cycle-attribution counters
//! (`FP192_MUL_COUNT`, `FP192_ADD_COUNT`, `PLUM_GRIFFIN_PERM_COUNT`,
//! `PLUM_PRF_EVAL_COUNT`, `PLUM_HASHER_COMPRESS_COUNT`) so the host
//! can break down the total cycle count by operation class — the
//! thesis Phase 11 measurement target.
//!
//! This binary uses std (not no_std). The PLUM modules depend on
//! `std::collections::HashMap` and `std::collections::HashSet` in
//! several spots that would require a deeper refactor to swap for
//! `alloc::collections::BTreeMap/BTreeSet`. risc0 3.0 supports std
//! on the guest target, so we lean on that for now.

use std::sync::atomic::Ordering;

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

use vc_pqc::plum::field_p192::{FP192_ADD_COUNT, FP192_MUL_COUNT};
use vc_pqc::plum::griffin::PLUM_GRIFFIN_PERM_COUNT;
use vc_pqc::plum::hasher::{PLUM_HASHER_COMPRESS_COUNT, PlumSha3Hasher};
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

/// Cycle-attribution counters. Loads of `AtomicU64` statics inside
/// the guest after `plum_verify` returns. The atomic operations
/// themselves cost a few cycles each; that's part of the measurement
/// and is the same across runs, so it cancels in cross-scheme
/// comparisons.
#[derive(Default, Serialize, Deserialize, Debug)]
pub struct PlumGuestCounters {
    pub fp192_muls: u64,
    pub fp192_adds: u64,
    pub griffin_perms: u64,
    pub prf_evals: u64,
    pub hasher_compresses: u64,
    /// `env::cycle_count()` delta across the `plum_verify` call.
    /// The host reads `prove_info.stats.total_cycles` for the full
    /// guest execution including (de)serialisation overhead; this
    /// inner count isolates the verify itself.
    pub verify_cycles_self_reported: u64,
}

#[derive(Serialize, Deserialize)]
struct GuestOutput {
    verified: bool,
    counters: PlumGuestCounters,
}

fn main() {
    let input: GuestInput = env::read();

    // Zero counters before the operation under test. The hasher's
    // counter is shared with any prior calls during deserialisation
    // (PlumSignature carries Fp192 values which deserialise via
    // serde + Fp192::from_bytes_le, but that path does not touch
    // FP192_MUL_COUNT). Defensive reset to make the measurement
    // unambiguous.
    FP192_MUL_COUNT.store(0, Ordering::SeqCst);
    FP192_ADD_COUNT.store(0, Ordering::SeqCst);
    PLUM_GRIFFIN_PERM_COUNT.store(0, Ordering::SeqCst);
    PLUM_PRF_EVAL_COUNT.store(0, Ordering::SeqCst);
    PLUM_HASHER_COMPRESS_COUNT.store(0, Ordering::SeqCst);

    let cycles_before = env::cycle_count();
    let outcome = plum_verify::<PlumSha3Hasher>(
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
