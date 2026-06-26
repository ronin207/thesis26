//! BDEC CreGen (ProSec 2024 §3) — PLUM-Griffin host driver on RISC0.
//!
//! Drives `methods::BDEC_CREDGEN_PLUM_GRIFFIN_ELF`. The guest runs two
//! `plum_verify` calls under a shared witness-only `pk_U`, mirroring the
//! formal CreGen relation:
//!
//!   Verify(pk_U, h_{U,TA}, c_{U,TA}) ∧ Verify(pk_U, ppk_{U,TA}, psk_{U,TA})
//!
//! The host generates a fresh PLUM keypair, fabricates the two messages
//! (`h_{U,TA}` modelled as the SHA-256 of a placeholder attribute list,
//! `ppk_{U,TA}` modelled as a fresh 32-byte pseudonym public), signs both
//! with `PlumGriffinHasher`, and submits the bundle to the guest.
//!
//! ## Modes
//!
//! - `BDEC_HOST_MODE=execute` (default): fast executor-only run for cycle
//!   counting and correctness smoke. No STARK is produced.
//! - `BDEC_HOST_MODE=prove`: real STARK prove with `ProverOpts::succinct()`.
//!   Reports wall-clock prove time and cycle count.
//!
//! ## Sako-framing anchor (do not lose)
//!
//! This binary is the smallest measurement that anchors the load-bearing
//! claim of the thesis: "PLUM-in-BDEC inside a general-purpose zkVM
//! escapes the rigidity of the Aurora-static-circuit instantiation."
//! It is not the full ShowCre/ShowVer — that is the next step on top.
//! See `docs/plum_in_bdec_integration_plan_20260529.md` for the full
//! integration sequencing.
//!
//! ## Security surface (POC reminder)
//!
//! - `pk_u`, `c_u_ta`, `psk_u_ta` are private witnesses. The guest
//!   commits only `(sig_ok, nym_ok, both_ok, counters)` to the journal;
//!   the witnesses never leave the executor environment via `commit`.
//! - The succinct receipt is NOT zero-knowledge in the formal sense.
//!   BDEC anonymity theorems are contingent on Groth16 wrapping. See
//!   `docs/plum_in_bdec_integration_plan_20260529.md` §3.1 + §4.

use std::sync::atomic::Ordering;
use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use risc0_zkvm::{ExecutorEnv, ProverOpts, default_executor, default_prover};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use methods::{BDEC_CREDGEN_PLUM_GRIFFIN_ELF, BDEC_CREDGEN_PLUM_GRIFFIN_ID};
use vc_pqc::plum::field_p192::{FP192_ADD_COUNT, FP192_MUL_COUNT};
use vc_pqc::plum::griffin::PLUM_GRIFFIN_PERM_COUNT;
use vc_pqc::plum::hasher::{PLUM_HASHER_COMPRESS_COUNT, PlumGriffinHasher};
use vc_pqc::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::plum::prf::PLUM_PRF_EVAL_COUNT;
use vc_pqc::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::plum::sign::{PlumSignature, plum_sign};
use vc_pqc::plum::verify::{VerificationOutcome, plum_verify};

// Mirror the guest's GuestInput / GuestOutput structs exactly. Separate
// crates so bincode-over-serde matches by structural shape.
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
struct GuestOutput {
    sig_ok: bool,
    nym_ok: bool,
    both_ok: bool,
    cred_outcome: VerificationOutcome,
    nym_outcome: VerificationOutcome,
    counters: CredGenCounters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostMode {
    Execute,
    Prove,
}

fn parse_mode() -> HostMode {
    match std::env::var("BDEC_HOST_MODE").as_deref() {
        Ok("prove") => HostMode::Prove,
        Ok("execute") | Err(_) => HostMode::Execute,
        Ok(other) => panic!(
            "unknown BDEC_HOST_MODE={other:?}; use 'execute' or 'prove'"
        ),
    }
}

fn parse_security() -> usize {
    std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80)
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    info!("BDEC CreGen × PLUM-Griffin × RISC0 — host driver");

    let mode = parse_mode();
    let security_level = parse_security();
    info!("mode = {mode:?}, security_level = {security_level}");

    let setup_t0 = Instant::now();
    let pp = plum_setup(security_level).expect("plum_setup failed");
    let setup_ms = setup_t0.elapsed().as_millis();
    info!("plum_setup completed in {setup_ms} ms");

    // Deterministic RNG so measurements are reproducible. The seed is
    // arbitrary; it must not be re-used in a real deployment.
    let mut keygen_rng = ChaCha20Rng::seed_from_u64(0x4244_4543_0000_0001); // "BDEC\0\0\0\x01"
    let (sk_u, pk_u) = plum_keygen(&pp, &mut keygen_rng);

    // h_{U,TA}: in the real BDEC protocol this is the hash of the attribute
    // list. For the beachhead measurement we use a placeholder hash. The
    // measurement cost depends on signature length and pp, not on the
    // content of h_{U,TA}, so this is faithful for cycle-counting.
    let h_u_ta = {
        let mut hasher = Sha256::new();
        hasher.update(b"bdec-cregen-poc-attribute-hash-v1");
        hasher.finalize().to_vec()
    };

    // ppk_{U,TA}: pseudonym public bytes. 32 bytes of deterministic randomness.
    let mut nym_rng = ChaCha20Rng::seed_from_u64(0x4244_4543_0000_0002);
    let mut ppk_u_ta = vec![0u8; 32];
    use rand::RngCore;
    nym_rng.fill_bytes(&mut ppk_u_ta);

    info!(
        "signing two messages with PlumGriffinHasher (h_u_ta {} B, ppk_u_ta {} B)",
        h_u_ta.len(),
        ppk_u_ta.len()
    );

    let mut sign_rng = ChaCha20Rng::seed_from_u64(0x4244_4543_0000_0003);
    let sign_t0 = Instant::now();
    let c_u_ta = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &h_u_ta, &mut sign_rng);
    let psk_u_ta = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_ta, &mut sign_rng);
    let sign_ms = sign_t0.elapsed().as_millis();
    info!("host-side signing completed in {sign_ms} ms (both signatures)");

    // Host-side verification of both signatures BEFORE submitting to the
    // guest. Isolates host-bug vs guest-bug: if either of these fails on
    // the host, the guest will also reject. If both pass on host but the
    // guest rejects, the bug is in guest-side serde / counter handling.
    let host_sig_ok = matches!(
        plum_verify::<PlumGriffinHasher>(&pp, &pk_u, &h_u_ta, &c_u_ta),
        VerificationOutcome::Accept,
    );
    let host_nym_ok = matches!(
        plum_verify::<PlumGriffinHasher>(&pp, &pk_u, &ppk_u_ta, &psk_u_ta),
        VerificationOutcome::Accept,
    );
    info!(
        "host-side verify: sig_ok={} nym_ok={}",
        host_sig_ok, host_nym_ok
    );
    if !(host_sig_ok && host_nym_ok) {
        panic!(
            "host-side PLUM verify rejected one of the signatures (sig_ok={}, nym_ok={}). \
             The bug is in host-side keygen/sign, not the guest. Stopping before guest run.",
            host_sig_ok, host_nym_ok
        );
    }

    let input = GuestInput {
        pp,
        pk_u,
        h_u_ta,
        c_u_ta,
        ppk_u_ta,
        psk_u_ta,
    };

    // Reset host-side counters for a clean comparison if the operator
    // wants to compare host-side cost to guest-side cost.
    FP192_MUL_COUNT.store(0, Ordering::SeqCst);
    FP192_ADD_COUNT.store(0, Ordering::SeqCst);
    PLUM_GRIFFIN_PERM_COUNT.store(0, Ordering::SeqCst);
    PLUM_PRF_EVAL_COUNT.store(0, Ordering::SeqCst);
    PLUM_HASHER_COMPRESS_COUNT.store(0, Ordering::SeqCst);

    let env = ExecutorEnv::builder()
        .write(&input)
        .expect("write input")
        .build()
        .expect("build env");

    match mode {
        HostMode::Execute => {
            let executor = default_executor();
            let exec_t0 = Instant::now();
            let session_info = executor
                .execute(env, BDEC_CREDGEN_PLUM_GRIFFIN_ELF)
                .expect("guest execution failed");
            let exec_ms = exec_t0.elapsed().as_millis();

            let output: GuestOutput =
                risc0_zkvm::serde::from_slice(&session_info.journal.bytes)
                    .expect("decode journal");

            info!(
                "execute mode: total_cycles_estimate={}",
                session_info.cycles()
            );
            info!("exec_ms = {exec_ms}");
            info!(
                "guest output: sig_ok={} nym_ok={} both_ok={}",
                output.sig_ok, output.nym_ok, output.both_ok
            );
            info!("cred_outcome: {:?}", output.cred_outcome);
            info!("nym_outcome:  {:?}", output.nym_outcome);
            info!("counters: {:#?}", output.counters);
            assert!(
                output.both_ok,
                "CreGen relation did not hold under PLUM-Griffin — \
                 host-side keygen/sign produced bytes the guest rejects. \
                 Investigate before running prove mode."
            );
            println!(
                "scheme=plum-griffin-bdec-credgen mode=execute \
                 setup_ms={setup_ms} sign_ms={sign_ms} exec_ms={exec_ms} \
                 cycles_estimate={cycles} cred_cycles={cred_cyc} \
                 nym_cycles={nym_cyc} both_ok={both_ok}",
                cycles = session_info.cycles(),
                cred_cyc = output.counters.cred_verify_cycles,
                nym_cyc = output.counters.nym_verify_cycles,
                both_ok = output.both_ok,
            );
        }
        HostMode::Prove => {
            let prover = default_prover();
            // BDEC_PROVER_OPTS selects which RISC Zero receipt class to
            // produce. Default is "composite" (no recursive aggregation,
            // larger receipt, more reliable on long workloads); switching
            // to "succinct" enables recursion. After the 15.6 h
            // succinct-mode failure on 2026-05-29 we default to composite
            // until the recursion failure is understood. See
            // docs/risc0_prove_failure_finding_20260530.md.
            let opts_kind = std::env::var("BDEC_PROVER_OPTS")
                .unwrap_or_else(|_| "composite".to_string());
            let prover_opts = match opts_kind.as_str() {
                "composite" => ProverOpts::default(),
                "succinct" => ProverOpts::succinct(),
                "groth16" => ProverOpts::groth16(),
                other => panic!(
                    "unknown BDEC_PROVER_OPTS={other:?}; \
                     use 'composite', 'succinct', or 'groth16'"
                ),
            };
            info!("prover_opts kind = {}", opts_kind);
            let prove_t0 = Instant::now();
            let prove_info = prover
                .prove_with_opts(env, BDEC_CREDGEN_PLUM_GRIFFIN_ELF, &prover_opts)
                .expect("prove failed");
            let prove_ms = prove_t0.elapsed().as_millis();

            let output: GuestOutput = prove_info
                .receipt
                .journal
                .decode()
                .expect("decode journal");

            info!("prove mode (ProverOpts::succinct, NOT zero-knowledge)");
            info!("prove_ms = {prove_ms}");
            info!(
                "total_cycles={} ",
                prove_info.stats.total_cycles
            );
            info!(
                "guest output: sig_ok={} nym_ok={} both_ok={}",
                output.sig_ok, output.nym_ok, output.both_ok
            );
            info!("counters: {:#?}", output.counters);

            // Optional: verify the receipt against the expected image ID to
            // catch silent ELF/host-image-ID mismatches.
            prove_info
                .receipt
                .verify(BDEC_CREDGEN_PLUM_GRIFFIN_ID)
                .expect("receipt verification failed");

            println!(
                "scheme=plum-griffin-bdec-credgen mode=prove \
                 setup_ms={setup_ms} sign_ms={sign_ms} prove_ms={prove_ms} \
                 total_cycles={cycles} cred_cycles={cred_cyc} \
                 nym_cycles={nym_cyc} both_ok={both_ok}",
                cycles = prove_info.stats.total_cycles,
                cred_cyc = output.counters.cred_verify_cycles,
                nym_cyc = output.counters.nym_verify_cycles,
                both_ok = output.both_ok,
            );
        }
    }
}
