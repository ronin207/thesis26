//! BDEC ShowCre statement (ProSec 2024, §4.1) — PLUM-Griffin instantiation.
//!
//! Proves the `k+2` `Sig.Verify` instances of the BDEC ShowCre relation
//! `R_show` under a shared (witness-only) PLUM public key `pk_U`:
//!
//!   /\_{j=1}^{k} plum_verify(pp, pk_U, m_nym^{(j)}, psk_{U,TA}^{(j)}) = 1   (k pseudonym-ownership)
//!   /\          plum_verify(pp, pk_U, m_nym_{U,V},  psk_{U,V})       = 1   (verifier-facing pseudonym)
//!   /\          plum_verify(pp, pk_U, m_show,       c_{U,V})         = 1   (shown credential over A_down)
//!
//! This is the `k+2` generalisation of `bdec_credgen_plum_griffin.rs` (which
//! proves the 2-verification CreGen relation). The signature scheme is
//! parameterised over `PlumGriffinHasher`, so the Griffin Fp192 precompile
//! activates on every internal hash / Merkle / PRF call.
//!
//! ## What is (and is not) proved
//!
//! The presentation predicate phi (`GPA > 3.5`, etc.) is NOT part of this
//! relation. Following base BDEC, phi is checked by the relying party on the
//! disclosed attribute set `A_down` OUTSIDE the proof. What this proof attests
//! (and, once the receipt is wrapped in a zero-knowledge SNARK, attests in
//! zero knowledge) is ownership of `k+2` valid signatures under the hidden
//! `pk_U`, which is exactly what delivers anonymity and unlinkability, not phi.
//!
//! ## Security surface (POC)
//!
//! - `pk_u` and all signatures are read as private witnesses and are NEVER
//!   committed to the receipt journal. Only `(all_ok, per-stage outcomes,
//!   counters)` go through `env::commit`. A reviewer should confirm this in
//!   `main()` below.
//! - Under `ProverOpts::succinct()`/`composite()` the receipt is NOT formally
//!   zero-knowledge; BDEC anonymity (ProSec 2024 Thm 2, 3) requires a Groth16
//!   wrap. See `docs/plum_in_bdec_integration_plan_20260529.md`.

#![no_main]

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
    /// `k` pseudonym-ownership checks: message `m_nym^{(j)}` and signature `psk_{U,TA}^{(j)}`.
    nym_msgs: Vec<Vec<u8>>,
    nym_sigs: Vec<PlumSignature>,
    /// Verifier-facing pseudonym check.
    nym_uv_msg: Vec<u8>,
    nym_uv_sig: PlumSignature,
    /// Shown-credential check over the disclosed attributes `A_down`.
    show_msg: Vec<u8>,
    show_sig: PlumSignature,
}

#[derive(Default, Serialize, Deserialize, Debug)]
pub struct ShowCreCounters {
    pub k: u64,
    pub n_verifications: u64,
    pub fp192_muls: u64,
    pub fp192_adds: u64,
    pub griffin_perms: u64,
    pub prf_evals: u64,
    pub hasher_compresses: u64,
    pub nym_verify_cycles: u64,
    pub uv_verify_cycles: u64,
    pub show_verify_cycles: u64,
    pub total_cycles: u64,
}

#[derive(Serialize, Deserialize)]
struct GuestOutput {
    all_ok: bool,
    nym_oks: Vec<bool>,
    uv_ok: bool,
    show_ok: bool,
    counters: ShowCreCounters,
}

fn main() {
    let input: GuestInput = env::read();
    let k = input.nym_msgs.len();
    assert_eq!(
        k,
        input.nym_sigs.len(),
        "nym_msgs and nym_sigs length mismatch"
    );

    FP192_MUL_COUNT.store(0, Ordering::SeqCst);
    FP192_ADD_COUNT.store(0, Ordering::SeqCst);
    PLUM_GRIFFIN_PERM_COUNT.store(0, Ordering::SeqCst);
    PLUM_PRF_EVAL_COUNT.store(0, Ordering::SeqCst);
    PLUM_HASHER_COMPRESS_COUNT.store(0, Ordering::SeqCst);

    let cycles_t0 = env::cycle_count();

    // k pseudonym-ownership checks, each binding a teaching-authority
    // pseudonym to the hidden pk_U. plum_verify_phased clears the per-call
    // phase buffer, so sequential calls in one invocation are independent.
    let mut nym_oks = Vec::with_capacity(k);
    let nym_t0 = env::cycle_count();
    for j in 0..k {
        let report = plum_verify_phased::<PlumGriffinHasher>(
            &input.pp,
            &input.pk_u,
            &input.nym_msgs[j],
            &input.nym_sigs[j],
        );
        nym_oks.push(matches!(report.outcome, VerificationOutcome::Accept));
    }
    let nym_t1 = env::cycle_count();

    // Verifier-facing pseudonym check.
    let uv_t0 = env::cycle_count();
    let uv_report = plum_verify_phased::<PlumGriffinHasher>(
        &input.pp,
        &input.pk_u,
        &input.nym_uv_msg,
        &input.nym_uv_sig,
    );
    let uv_t1 = env::cycle_count();
    let uv_ok = matches!(uv_report.outcome, VerificationOutcome::Accept);

    // Shown-credential check over the disclosed attributes.
    let show_t0 = env::cycle_count();
    let show_report = plum_verify_phased::<PlumGriffinHasher>(
        &input.pp,
        &input.pk_u,
        &input.show_msg,
        &input.show_sig,
    );
    let show_t1 = env::cycle_count();
    let show_ok = matches!(show_report.outcome, VerificationOutcome::Accept);

    let cycles_t1 = env::cycle_count();

    let all_ok = nym_oks.iter().all(|&b| b) && uv_ok && show_ok;
    let counters = ShowCreCounters {
        k: k as u64,
        n_verifications: (k + 2) as u64,
        fp192_muls: FP192_MUL_COUNT.load(Ordering::SeqCst),
        fp192_adds: FP192_ADD_COUNT.load(Ordering::SeqCst),
        griffin_perms: PLUM_GRIFFIN_PERM_COUNT.load(Ordering::SeqCst),
        prf_evals: PLUM_PRF_EVAL_COUNT.load(Ordering::SeqCst),
        hasher_compresses: PLUM_HASHER_COMPRESS_COUNT.load(Ordering::SeqCst),
        nym_verify_cycles: nym_t1.saturating_sub(nym_t0) as u64,
        uv_verify_cycles: uv_t1.saturating_sub(uv_t0) as u64,
        show_verify_cycles: show_t1.saturating_sub(show_t0) as u64,
        total_cycles: cycles_t1.saturating_sub(cycles_t0) as u64,
    };

    env::commit(&GuestOutput {
        all_ok,
        nym_oks,
        uv_ok,
        show_ok,
        counters,
    });
}
