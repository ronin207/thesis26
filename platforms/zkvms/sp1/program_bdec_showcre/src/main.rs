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
//! SP1 reports cycles and syscall counts host-side (`ExecutionReport`). The
//! default build commits ONLY the aggregate `all_ok` bool. Under the `jbind`
//! feature the guest additionally commits the public statement
//! `x_show = ((ppk_{U,TA}^{(j)})_j, ppk_{U,V}, h_{U,V})` (the thesis relation,
//! Section 3), binding the receipt to the disclosed-attribute hash `h_{U,V}`
//! (which fixes WHICH attributes were shown). The shown credential `c_{U,V}`
//! stays in the WITNESS (`w_show`), as do `pk_U` and every secret signature
//! (`psk_{U,TA}`, `psk_{U,V}`) — NEVER committed, which is what the anonymity
//! proof requires.
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

    // Default: commit only the aggregate outcome (bool-only functional
    // benchmark). Under `jbind`: additionally bind the public statement
    // x_show — the k teaching-authority pseudonym keys (`nym_msgs`), the
    // verifier pseudonym key (`nym_uv_msg`), and the disclosed-attribute
    // hash h_{U,V} (`show_msg`). The shown credential c_{U,V} (`show_sig`),
    // pk_U, and the psk signatures stay private witnesses, never committed —
    // c_{U,V} in the witness is what the anonymity proof (Section 5) requires.
    #[cfg(feature = "jbind")]
    sp1_zkvm::io::commit(&(
        (&input.nym_msgs, &input.nym_uv_msg, &input.show_msg),
        all_ok,
    ));
    #[cfg(not(feature = "jbind"))]
    sp1_zkvm::io::commit(&all_ok);
}
