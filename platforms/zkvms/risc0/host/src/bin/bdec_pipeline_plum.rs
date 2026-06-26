//! End-to-end BDEC x PLUM pipeline (ProSec 2024), step by step.
//!
//! Runs the seven algorithms in order with the PLUM-Griffin instantiation:
//!   1. Setup        (outside zkVM)
//!   2. PriGen       (outside zkVM)
//!   3. NymKey       (outside zkVM)
//!   4. CreGen       (INSIDE zkVM)   -- 2 signature-verification predicates
//!   5. CreVer       (outside zkVM)
//!   6. ShowCre      (INSIDE zkVM)   -- k+2 signature-verification predicates
//!   7. ShowVer      (outside zkVM)  -- receipt + verifier-side phi check
//!
//! The two zkVM relations run through the RISC0 prover. Set RISC0_DEV_MODE=1 for
//! a fast end-to-end demonstration: receipts are mocked but still flow through
//! CreVer/ShowVer, so the full wiring is exercised in minutes. This is a
//! correctness/wiring demonstration, NOT a prove-time measurement -- real proving
//! is the multi-day (or outsourced) path quantified separately.

use std::time::Instant;

use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use risc0_zkvm::{ExecutorEnv, ProverOpts, default_prover};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use methods::{
    BDEC_CREDGEN_PLUM_GRIFFIN_ELF, BDEC_CREDGEN_PLUM_GRIFFIN_ID, BDEC_SHOWCRE_PLUM_GRIFFIN_ELF,
    BDEC_SHOWCRE_PLUM_GRIFFIN_ID,
};
use vc_pqc::plum::hasher::PlumGriffinHasher;
use vc_pqc::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::plum::sign::{PlumSignature, plum_sign};
use vc_pqc::plum::verify::{VerificationOutcome, plum_verify};

#[derive(Serialize, Deserialize)]
struct CredGenInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    h_u_ta: Vec<u8>,
    c_u_ta: PlumSignature,
    ppk_u_ta: Vec<u8>,
    psk_u_ta: PlumSignature,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct CredGenCounters {
    fp192_muls: u64,
    fp192_adds: u64,
    griffin_perms: u64,
    prf_evals: u64,
    hasher_compresses: u64,
    cred_verify_cycles: u64,
    nym_verify_cycles: u64,
    total_cycles: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct CredGenOutput {
    sig_ok: bool,
    nym_ok: bool,
    both_ok: bool,
    cred_outcome: VerificationOutcome,
    nym_outcome: VerificationOutcome,
    counters: CredGenCounters,
}

#[derive(Serialize, Deserialize)]
struct ShowCreInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    nym_msgs: Vec<Vec<u8>>,
    nym_sigs: Vec<PlumSignature>,
    nym_uv_msg: Vec<u8>,
    nym_uv_sig: PlumSignature,
    show_msg: Vec<u8>,
    show_sig: PlumSignature,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct ShowCreCounters {
    k: u64,
    n_verifications: u64,
    fp192_muls: u64,
    fp192_adds: u64,
    griffin_perms: u64,
    prf_evals: u64,
    hasher_compresses: u64,
    nym_verify_cycles: u64,
    uv_verify_cycles: u64,
    show_verify_cycles: u64,
    total_cycles: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct ShowCreOutput {
    all_ok: bool,
    nym_oks: Vec<bool>,
    uv_ok: bool,
    show_ok: bool,
    counters: ShowCreCounters,
}

fn step(n: u32, name: &str, placement: &str) {
    println!("\n=== Step {n}: BDEC.{name}   [{placement}] ===");
}

fn det(seed: u64, n: usize) -> Vec<u8> {
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    let mut b = vec![0u8; n];
    r.fill_bytes(&mut b);
    b
}

fn main() {
    let lambda: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let k: usize = std::env::var("BDEC_SHOWCRE_K")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&k: &usize| k >= 1)
        .unwrap_or(2);
    let dev = std::env::var("RISC0_DEV_MODE").as_deref() == Ok("1");

    println!("BDEC x PLUM-Griffin end-to-end pipeline  (lambda={lambda}, k={k}, dev_mode={dev})");
    if !dev {
        println!("NOTE: RISC0_DEV_MODE is not set; the two zkVM steps will attempt REAL proving");
        println!("      (multi-day on this hardware). Set RISC0_DEV_MODE=1 for the fast demo.");
    }
    let prover = default_prover();
    let opts = ProverOpts::default();

    // ---- 1. Setup ------------------------------------------------------------
    step(1, "Setup", "outside zkVM");
    let pp = plum_setup(lambda).expect("plum_setup");
    println!("public parameters generated for lambda={lambda}.");

    // ---- 2. PriGen -----------------------------------------------------------
    step(2, "PriGen", "outside zkVM");
    let mut kg = ChaCha20Rng::seed_from_u64(0x4244_4543_5049_0001);
    let (sk_u, pk_u) = plum_keygen(&pp, &mut kg);
    println!("user long-term keypair (sk_U, pk_U) generated.");
    println!("pk_U is the witness the proofs hide; it never leaves the prover.");

    // ---- 3. NymKey -----------------------------------------------------------
    step(3, "NymKey", "outside zkVM");
    let mut sr = ChaCha20Rng::seed_from_u64(0x4244_4543_5049_0003);
    let ppk_ta: Vec<Vec<u8>> = (0..k).map(|j| det(0x5441_0000 ^ j as u64, 32)).collect();
    let psk_ta: Vec<PlumSignature> = ppk_ta
        .iter()
        .map(|p| plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, p, &mut sr))
        .collect();
    let ppk_uv = det(0x5556_0001, 32);
    let psk_uv = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_uv, &mut sr);
    println!("{k} teaching-authority pseudonym(s) + 1 verifier pseudonym, each");
    println!("authenticated by a signature under pk_U (NymKey of ProSec 2024).");

    // ---- 4. CreGen (zkVM) ----------------------------------------------------
    step(4, "CreGen", "INSIDE zkVM");
    let h_u_ta = {
        let mut h = Sha256::new();
        h.update(b"bdec-pipeline-attribute-hash-v1");
        h.finalize().to_vec()
    };
    let c_u_ta = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &h_u_ta, &mut sr);
    let credgen_input = CredGenInput {
        pp: pp.clone(),
        pk_u: pk_u.clone(),
        h_u_ta,
        c_u_ta,
        ppk_u_ta: ppk_ta[0].clone(),
        psk_u_ta: psk_ta[0].clone(),
    };
    let env = ExecutorEnv::builder()
        .write(&credgen_input)
        .unwrap()
        .build()
        .unwrap();
    println!("proving the 2-verification CreGen relation under hidden pk_U ...");
    let t0 = Instant::now();
    let credgen_prove = prover
        .prove_with_opts(env, BDEC_CREDGEN_PLUM_GRIFFIN_ELF, &opts)
        .expect("CreGen prove");
    let credgen_out: CredGenOutput = credgen_prove.receipt.journal.decode().unwrap();
    println!(
        "CreGen proved in {:?} (dev_mode={dev}); relation holds: both_ok={}.",
        t0.elapsed(),
        credgen_out.both_ok
    );

    // ---- 5. CreVer (outside) -------------------------------------------------
    step(5, "CreVer", "outside zkVM");
    credgen_prove
        .receipt
        .verify(BDEC_CREDGEN_PLUM_GRIFFIN_ID)
        .expect("CreVer: credential receipt failed to verify");
    println!("credential receipt verifies against the CreGen image id.");
    if dev {
        println!("(dev mode: receipt is mocked, so this checks the WIRING, not real soundness.)");
    }

    // ---- 6. ShowCre (zkVM) ---------------------------------------------------
    step(6, "ShowCre", "INSIDE zkVM");
    let a_down = {
        let mut h = Sha256::new();
        h.update(b"bdec-pipeline-disclosed-attributes-A-down-v1");
        h.finalize().to_vec()
    };
    let show_sig = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &a_down, &mut sr);
    let showcre_input = ShowCreInput {
        pp: pp.clone(),
        pk_u: pk_u.clone(),
        nym_msgs: ppk_ta.clone(),
        nym_sigs: psk_ta.clone(),
        nym_uv_msg: ppk_uv.clone(),
        nym_uv_sig: psk_uv.clone(),
        show_msg: a_down.clone(),
        show_sig,
    };
    let env = ExecutorEnv::builder()
        .write(&showcre_input)
        .unwrap()
        .build()
        .unwrap();
    println!("proving the {}-verification ShowCre relation under hidden pk_U ...", k + 2);
    let t0 = Instant::now();
    let showcre_prove = prover
        .prove_with_opts(env, BDEC_SHOWCRE_PLUM_GRIFFIN_ELF, &opts)
        .expect("ShowCre prove");
    let showcre_out: ShowCreOutput = showcre_prove.receipt.journal.decode().unwrap();
    println!(
        "ShowCre proved in {:?} (dev_mode={dev}); relation holds: all_ok={}.",
        t0.elapsed(),
        showcre_out.all_ok
    );

    // ---- 7. ShowVer (outside) ------------------------------------------------
    step(7, "ShowVer", "outside zkVM");
    showcre_prove
        .receipt
        .verify(BDEC_SHOWCRE_PLUM_GRIFFIN_ID)
        .expect("ShowVer: showing receipt failed to verify");
    println!("showing receipt verifies against the ShowCre image id.");
    // The presentation predicate phi is checked verifier-side on the disclosed
    // attributes A_down (base BDEC, ProSec 2024 p.12-13). Demonstrate with a
    // simple disclosed-attribute predicate.
    let phi_ok = !a_down.is_empty(); // placeholder predicate over the disclosed set
    println!("verifier-side check on disclosed A_down: phi(A_down) = {phi_ok}");
    println!("(membership / non-revocation / phi are all relying-party checks, not in the proof.)");

    // ---- done ----------------------------------------------------------------
    let ok = credgen_out.both_ok && showcre_out.all_ok && phi_ok;
    println!("\n=== Pipeline complete: Setup -> PriGen -> NymKey -> CreGen -> CreVer -> ShowCre -> ShowVer ===");
    println!("end-to-end PLUM-BDEC pipeline {}", if ok { "SUCCEEDED" } else { "FAILED" });
    assert!(ok, "pipeline did not complete cleanly");
}
