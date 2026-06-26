//! BDEC ShowCre statement (ProSec 2024, §4.1) — PLUM-Griffin, SP1 port.
//!
//! Proves the `k+2` `Sig.Verify` instances of `R_show` under a shared
//! (witness-only) PLUM public key `pk_U`:
//!
//!   /\_{j=1}^{k} plum_verify(pp, pk_U, m_nym^{(j)}, psk_{U,TA}^{(j)}) = 1
//!   /\          plum_verify(pp, pk_U, m_nym_{U,V},  psk_{U,V})       = 1
//!   /\          plum_verify(pp, pk_U, m_show,       c_{U,V})         = 1
//!
//! SP1 mirror of
//! `platforms/zkvms/risc0/methods/guest/src/bin/bdec_showcre_plum_griffin.rs`,
//! the `k+2` generalisation of the CreGen guest.
//!
//! ## What is (and is not) proved
//!
//! The presentation predicate phi is NOT part of this relation. Following base
//! BDEC, phi is checked by the relying party on the disclosed attribute set
//! `A_down` OUTSIDE the proof. This relation attests ownership of `k+2` valid
//! signatures under the hidden `pk_U` — what delivers anonymity, not phi.
//!
//! ## Measurement model / privacy
//!
//! SP1 reports cycles and syscall counts host-side (`ExecutionReport`); this
//! guest commits ONLY the aggregate `all_ok` bool. `pk_U` and all signatures
//! are private witnesses, NEVER committed.
//!
//! `plum_verify_phased` clears the per-call phase buffer, so the `k+2`
//! sequential verifies in one invocation are independent (cf. the RISC0 guest
//! doc-comment and `docs/plum_in_bdec_blocker_20260529.md`).

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
    /// `k` pseudonym-ownership checks.
    nym_msgs: Vec<Vec<u8>>,
    nym_sigs: Vec<PlumSignature>,
    /// Verifier-facing pseudonym check.
    nym_uv_msg: Vec<u8>,
    nym_uv_sig: PlumSignature,
    /// Shown-credential check over the disclosed attributes `A_down`.
    show_msg: Vec<u8>,
    show_sig: PlumSignature,
}

pub fn main() {
    let input_bytes = sp1_zkvm::io::read_vec();
    let input: GuestInput =
        bincode::deserialize(&input_bytes).expect("guest: bincode decode failed");

    let k = input.nym_msgs.len();
    assert_eq!(k, input.nym_sigs.len(), "nym_msgs/nym_sigs length mismatch");

    let mut all_ok = true;

    // k pseudonym-ownership checks, each binding a teaching-authority
    // pseudonym to the hidden pk_U.
    for j in 0..k {
        let r = plum_verify_phased::<PlumGriffinHasher>(
            &input.pp,
            &input.pk_u,
            &input.nym_msgs[j],
            &input.nym_sigs[j],
        );
        all_ok &= matches!(r.outcome, VerificationOutcome::Accept);
    }

    // Verifier-facing pseudonym check.
    let uv = plum_verify_phased::<PlumGriffinHasher>(
        &input.pp,
        &input.pk_u,
        &input.nym_uv_msg,
        &input.nym_uv_sig,
    );
    all_ok &= matches!(uv.outcome, VerificationOutcome::Accept);

    // Shown-credential check over the disclosed attributes.
    let show = plum_verify_phased::<PlumGriffinHasher>(
        &input.pp,
        &input.pk_u,
        &input.show_msg,
        &input.show_sig,
    );
    all_ok &= matches!(show.outcome, VerificationOutcome::Accept);

    sp1_zkvm::io::commit(&all_ok);
}
