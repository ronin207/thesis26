//! BDEC CreGen statement (ProSec 2024, §3) — PLUM-Griffin instantiation.
//!
//! Proves the two `Sig.Verify` instances of the BDEC CreGen relation under a
//! shared (witness-only) PLUM public key `pk_U`:
//!
//!   1. `plum_verify(pp, pk_U, h_{U,TA}, c_{U,TA}) = 1`
//!   2. `plum_verify(pp, pk_U, ppk_{U,TA}, psk_{U,TA}) = 1`
//!
//! Mirror of `plum_verify_griffin.rs` but doubled — same counter-attribution
//! plumbing, accumulated across both verifications. The signature scheme is
//! parameterised over `PlumGriffinHasher` so the Griffin Fp192 precompile
//! activates on every internal hash/Merkle/PRF call.
//!
//! ## Beachhead, not destination
//!
//! This is the smallest BDEC sub-protocol that exercises the PLUM-in-BDEC
//! type plumbing end-to-end. The full pp2 ShowCre/ShowVer guest
//! (`methods/guest/src/main.rs`) replaces Loquat with PLUM in a much larger
//! statement; this file establishes that the underlying primitive swap
//! compiles and runs before we attack the full protocol.
//!
//! ## Security surface (POC)
//!
//! - `pk_u`, `c_u_ta`, `psk_u_ta` are read from the executor environment as
//!   private witnesses and **never committed to the receipt journal**. Only
//!   `(sig_ok, nym_ok, both_ok, counters)` go through `env::commit`. A
//!   reviewer should confirm this by reading `main()` below.
//! - Under `ProverOpts::succinct()` the resulting receipt is **NOT** formally
//!   zero-knowledge; BDEC anonymity theorems (ProSec 2024 Thm 2, 3) require
//!   `compressed().groth16()` wrapping. This is documented in
//!   `docs/plum_in_bdec_integration_plan_20260529.md` §3.1 and is an explicit
//!   thesis decision, not an oversight.

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
use vc_pqc::plum::verify::{VerificationOutcome, plum_verify_phased};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    h_u_ta: Vec<u8>,
    c_u_ta: PlumSignature,
    ppk_u_ta: Vec<u8>,
    psk_u_ta: PlumSignature,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct CredGenCounters {
    pub fp192_muls: u64,
    pub fp192_adds: u64,
    pub griffin_perms: u64,
    pub prf_evals: u64,
    pub hasher_compresses: u64,
    pub cred_verify_cycles: u64,
    pub nym_verify_cycles: u64,
    pub total_cycles: u64,
}

#[derive(Serialize, Deserialize)]
struct GuestOutput {
    sig_ok: bool,
    nym_ok: bool,
    both_ok: bool,
    cred_outcome: VerificationOutcome,
    nym_outcome: VerificationOutcome,
    counters: CredGenCounters,
}

fn main() {
    let input: GuestInput = env::read();

    FP192_MUL_COUNT.store(0, Ordering::SeqCst);
    FP192_ADD_COUNT.store(0, Ordering::SeqCst);
    PLUM_GRIFFIN_PERM_COUNT.store(0, Ordering::SeqCst);
    PLUM_PRF_EVAL_COUNT.store(0, Ordering::SeqCst);
    PLUM_HASHER_COMPRESS_COUNT.store(0, Ordering::SeqCst);

    let cycles_t0 = env::cycle_count();

    // Using plum_verify_phased instead of plum_verify because the latter
    // does not clear the static VERIFY_PHASE_SNAPSHOTS buffer at entry,
    // which empirically corrupts the second sequential call in a single
    // guest invocation. plum_verify_phased clears the buffer per call.
    // See docs/plum_in_bdec_blocker_20260529.md.
    let cred_t0 = env::cycle_count();
    let cred_report = plum_verify_phased::<PlumGriffinHasher>(
        &input.pp,
        &input.pk_u,
        &input.h_u_ta,
        &input.c_u_ta,
    );
    let cred_t1 = env::cycle_count();
    let sig_ok = matches!(cred_report.outcome, VerificationOutcome::Accept);

    let nym_t0 = env::cycle_count();
    let nym_report = plum_verify_phased::<PlumGriffinHasher>(
        &input.pp,
        &input.pk_u,
        &input.ppk_u_ta,
        &input.psk_u_ta,
    );
    let nym_t1 = env::cycle_count();
    let nym_ok = matches!(nym_report.outcome, VerificationOutcome::Accept);

    let cycles_t1 = env::cycle_count();

    let both_ok = sig_ok && nym_ok;
    let counters = CredGenCounters {
        fp192_muls: FP192_MUL_COUNT.load(Ordering::SeqCst),
        fp192_adds: FP192_ADD_COUNT.load(Ordering::SeqCst),
        griffin_perms: PLUM_GRIFFIN_PERM_COUNT.load(Ordering::SeqCst),
        prf_evals: PLUM_PRF_EVAL_COUNT.load(Ordering::SeqCst),
        hasher_compresses: PLUM_HASHER_COMPRESS_COUNT.load(Ordering::SeqCst),
        cred_verify_cycles: cred_t1.saturating_sub(cred_t0) as u64,
        nym_verify_cycles: nym_t1.saturating_sub(nym_t0) as u64,
        total_cycles: cycles_t1.saturating_sub(cycles_t0) as u64,
    };

    env::commit(&GuestOutput {
        sig_ok,
        nym_ok,
        both_ok,
        cred_outcome: cred_report.outcome,
        nym_outcome: nym_report.outcome,
        counters,
    });
}
