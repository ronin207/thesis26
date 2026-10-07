//! ARTIFACT run for the defense demo — NOT a timing run.
//!
//! Proves the MEASURED ShowCre witness (`showcre_k2_witness.bin`, the exact
//! guest-input bytes of the 2026-07-10/11 measured runs) with the JBIND ELF and
//! PERSISTS the receipt + verifying key, so the demo can verify a real
//! statement-bound receipt live. The measured host bins stay untouched; the
//! `GuestInput` mirror below is verbatim from `bdec_showcre_host.rs` so the
//! measured witness bytes decode unchanged.
//!
//! Machine state is uncontrolled here (the run may suspend/resume with the
//! laptop lid); the wall-clock printed below must never be cited as a
//! measurement. Timing claims live in `docs/measurements/bdec_e2e_20260710/`.
//!
//! Env:
//!   BDEC_ARTIFACT_WITNESS  path to the saved witness bin (raw GuestInput bincode)
//!   BDEC_ARTIFACT_DIR      output directory for receipt + vk

use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};
use std::time::Instant;

use vc_pqc::signatures::plum::keygen::PlumPublicKey;
use vc_pqc::signatures::plum::setup::PlumPublicParams;
use vc_pqc::signatures::plum::sign::PlumSignature;

const JBIND_ELF: &[u8] = include_bytes!(env!("BDEC_SHOWCRE_JBIND_ELF_PATH"));

/// Verbatim mirror of `bdec_showcre_host.rs::GuestInput`.
#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    nym_msgs: Vec<Vec<u8>>,
    nym_sigs: Vec<PlumSignature>,
    nym_uv_msg: Vec<u8>,
    nym_uv_sig: PlumSignature,
    show_msg: Vec<u8>,
    show_sig: PlumSignature,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let witness_path =
        std::env::var("BDEC_ARTIFACT_WITNESS").expect("set BDEC_ARTIFACT_WITNESS");
    let out_dir = std::env::var("BDEC_ARTIFACT_DIR").expect("set BDEC_ARTIFACT_DIR");
    std::fs::create_dir_all(&out_dir).expect("create BDEC_ARTIFACT_DIR");
    let bytes = std::fs::read(&witness_path).expect("read witness bin");
    let input: GuestInput = bincode::deserialize(&bytes).expect("decode GuestInput");
    let k = input.nym_msgs.len();
    println!(
        "=== ShowCre k={k} JBIND ARTIFACT PROVE (measured witness, {} bytes) ===",
        bytes.len()
    );
    println!("NOT a timing run: wall-clock below is not citable.");

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let pk_proof = client.setup(Elf::Static(JBIND_ELF)).expect("setup failed");
    let t = Instant::now();
    let proof = client.prove(&pk_proof, stdin).run().expect("prove failed");
    println!(
        "prove wall {:.1} min (artifact run)",
        t.elapsed().as_secs_f64() / 60.0
    );
    client
        .verify(&proof, pk_proof.verifying_key(), None)
        .expect("verify failed");

    // Bind-check the journal against the measured statement, as the measured
    // host does: the guest commits ((nym_msgs, nym_uv_msg, show_msg), all_ok);
    // c_{U,V} (show_sig) stays a private witness.
    let ((nym_msgs, nym_uv_msg, show_msg), accepted): (
        (Vec<Vec<u8>>, Vec<u8>, Vec<u8>),
        bool,
    ) = bincode::deserialize(proof.public_values.as_slice()).expect("decode journal");
    let bound = nym_msgs == input.nym_msgs
        && nym_uv_msg == input.nym_uv_msg
        && show_msg == input.show_msg;
    assert!(accepted, "guest rejected the measured witness");
    assert!(bound, "journal does not match the measured statement (JBind)");
    println!("accepted=true statement_bound=true VERIFY_OK");

    let proof_bytes = bincode::serialize(&proof).expect("serialize proof");
    let vk_bytes =
        bincode::serialize(pk_proof.verifying_key()).expect("serialize vk");
    let proof_path = format!("{out_dir}/showcre_k{k}_jbind_receipt.bin");
    let vk_path = format!("{out_dir}/showcre_k{k}_jbind_vk.bin");
    std::fs::write(&proof_path, &proof_bytes).expect("write receipt");
    std::fs::write(&vk_path, &vk_bytes).expect("write vk");
    println!("SAVED receipt {} bytes -> {proof_path}", proof_bytes.len());
    println!("SAVED vk      {} bytes -> {vk_path}", vk_bytes.len());
    println!("=== ARTIFACT RUN DONE ===");
}
