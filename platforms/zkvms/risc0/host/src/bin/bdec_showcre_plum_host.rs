//! BDEC ShowCre (ProSec 2024 §4.1) — PLUM-Griffin host driver on RISC0.
//!
//! Drives `methods::BDEC_SHOWCRE_PLUM_GRIFFIN_ELF`. The guest runs `k+2`
//! `plum_verify` calls under a shared witness-only `pk_U`, mirroring the
//! formal ShowCre relation `R_show`:
//!
//!   /\_{j=1}^{k} Verify(pk_U, m_nym^{(j)}, psk_{U,TA}^{(j)})
//!   /\          Verify(pk_U, m_nym_{U,V}, psk_{U,V})
//!   /\          Verify(pk_U, m_show,       c_{U,V})
//!
//! Placement in the full BDEC system: Setup / PriGen / NymKey / CreGen run
//! before this (CreGen itself inside the zkVM, see bdec_credgen_plum_host);
//! the relying party's ledger-membership, non-revocation, and presentation
//! predicate phi checks run AFTER, on the host, outside the proof. This
//! binary measures only the in-zkVM ShowCre statement.
//!
//! ## Modes
//!
//! - `BDEC_HOST_MODE=execute` (default): executor-only run for cycle counting
//!   (machine-independent, always terminates).
//! - `BDEC_HOST_MODE=prove`: real STARK prove. `BDEC_PROVER_OPTS` selects
//!   composite / succinct / groth16. ShowCre is k+2 verifications, so prove
//!   cost is larger than CreGen; on consumer hardware this is expected to
//!   reach the frontier documented in the evaluation chapter.
//!
//! ## Parameters
//!
//! - `BDEC_SHOWCRE_K` (default 2): number of credentials shown. The thesis
//!   uses k=1 (phi_1) and k=2 (phi_2) as running examples and extrapolates the
//!   cost model to larger k.
//!
//! ## Security surface (POC reminder)
//!
//! `pk_u` and all signatures are private witnesses. The guest commits only
//! `(all_ok, per-stage outcomes, counters)`. The succinct/composite receipt is
//! NOT zero-knowledge; BDEC anonymity is contingent on a Groth16 wrap.

use std::sync::atomic::Ordering;
use std::time::Instant;

use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;
use risc0_zkvm::{ExecutorEnv, ProverOpts, default_executor, default_prover};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use methods::{BDEC_SHOWCRE_PLUM_GRIFFIN_ELF, BDEC_SHOWCRE_PLUM_GRIFFIN_ID};
use vc_pqc::plum::field_p192::{FP192_ADD_COUNT, FP192_MUL_COUNT};
use vc_pqc::plum::griffin::PLUM_GRIFFIN_PERM_COUNT;
use vc_pqc::plum::hasher::{PLUM_HASHER_COMPRESS_COUNT, PlumGriffinHasher};
use vc_pqc::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::plum::prf::PLUM_PRF_EVAL_COUNT;
use vc_pqc::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::plum::sign::{PlumSignature, plum_sign};
use vc_pqc::plum::verify::{VerificationOutcome, plum_verify};

// Mirror the guest's GuestInput / GuestOutput structs exactly.
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

#[derive(Default, Serialize, Deserialize, Debug)]
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
struct GuestOutput {
    all_ok: bool,
    nym_oks: Vec<bool>,
    uv_ok: bool,
    show_ok: bool,
    counters: ShowCreCounters,
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
        Ok(other) => panic!("unknown BDEC_HOST_MODE={other:?}; use 'execute' or 'prove'"),
    }
}

fn parse_security() -> usize {
    std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80)
}

fn parse_k() -> usize {
    std::env::var("BDEC_SHOWCRE_K")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&k: &usize| k >= 1)
        .unwrap_or(2)
}

/// Deterministic 32-byte pseudonym public, distinct per (label, index).
fn pseudonym_bytes(seed: u64) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut buf = vec![0u8; 32];
    rng.fill_bytes(&mut buf);
    buf
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    info!("BDEC ShowCre × PLUM-Griffin × RISC0 — host driver");

    let mode = parse_mode();
    let security_level = parse_security();
    let k = parse_k();
    info!("mode = {mode:?}, security_level = {security_level}, k = {k}");

    let setup_t0 = Instant::now();
    let pp = plum_setup(security_level).expect("plum_setup failed");
    let setup_ms = setup_t0.elapsed().as_millis();
    info!("plum_setup completed in {setup_ms} ms");

    // One long-term keypair: every ShowCre verification is under pk_U.
    let mut keygen_rng = ChaCha20Rng::seed_from_u64(0x4244_4543_5343_0001); // "BDECSC\0\x01"
    let (sk_u, pk_u) = plum_keygen(&pp, &mut keygen_rng);

    // Build the k pseudonym messages (m_nym^{(j)}), the verifier-facing
    // pseudonym message (m_nym_{U,V}), and the shown-credential message
    // (m_show = encoding of the disclosed attributes A_down). Cost depends on
    // signature length and pp, not on message content, so deterministic
    // placeholders are faithful for cycle counting.
    let nym_msgs: Vec<Vec<u8>> = (0..k)
        .map(|j| pseudonym_bytes(0x5359_4D00_0000_0000 ^ (j as u64)))
        .collect();
    let nym_uv_msg = pseudonym_bytes(0x5359_4D5F_5556_0001);
    let show_msg = {
        let mut hasher = Sha256::new();
        hasher.update(b"bdec-showcre-disclosed-attributes-A-down-v1");
        hasher.finalize().to_vec()
    };

    info!("signing k+2 = {} messages with PlumGriffinHasher", k + 2);
    let mut sign_rng = ChaCha20Rng::seed_from_u64(0x4244_4543_5343_0003);
    let sign_t0 = Instant::now();
    let nym_sigs: Vec<PlumSignature> = nym_msgs
        .iter()
        .map(|m| plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, m, &mut sign_rng))
        .collect();
    let nym_uv_sig = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &nym_uv_msg, &mut sign_rng);
    let show_sig = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &show_msg, &mut sign_rng);
    let sign_ms = sign_t0.elapsed().as_millis();
    info!("host-side signing completed in {sign_ms} ms ({} signatures)", k + 2);

    // Host-side verification of all k+2 signatures before submitting to the
    // guest. Isolates host-bug vs guest-bug.
    let host_nym_ok = nym_msgs.iter().zip(nym_sigs.iter()).all(|(m, s)| {
        matches!(
            plum_verify::<PlumGriffinHasher>(&pp, &pk_u, m, s),
            VerificationOutcome::Accept
        )
    });
    let host_uv_ok = matches!(
        plum_verify::<PlumGriffinHasher>(&pp, &pk_u, &nym_uv_msg, &nym_uv_sig),
        VerificationOutcome::Accept
    );
    let host_show_ok = matches!(
        plum_verify::<PlumGriffinHasher>(&pp, &pk_u, &show_msg, &show_sig),
        VerificationOutcome::Accept
    );
    info!(
        "host-side verify: nym_ok(all {})={} uv_ok={} show_ok={}",
        k, host_nym_ok, host_uv_ok, host_show_ok
    );
    if !(host_nym_ok && host_uv_ok && host_show_ok) {
        panic!(
            "host-side PLUM verify rejected a signature (nym={host_nym_ok}, \
             uv={host_uv_ok}, show={host_show_ok}). Bug is in host keygen/sign, \
             not the guest. Stopping before guest run."
        );
    }

    let input = GuestInput {
        pp,
        pk_u,
        nym_msgs,
        nym_sigs,
        nym_uv_msg,
        nym_uv_sig,
        show_msg,
        show_sig,
    };

    // Reset host-side counters for a clean host-vs-guest comparison.
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
                .execute(env, BDEC_SHOWCRE_PLUM_GRIFFIN_ELF)
                .expect("guest execution failed");
            let exec_ms = exec_t0.elapsed().as_millis();

            let output: GuestOutput =
                risc0_zkvm::serde::from_slice(&session_info.journal.bytes).expect("decode journal");

            info!("execute mode: total_cycles_estimate={}", session_info.cycles());
            info!("exec_ms = {exec_ms}");
            info!(
                "guest output: all_ok={} uv_ok={} show_ok={} (k={})",
                output.all_ok, output.uv_ok, output.show_ok, output.counters.k
            );
            info!("counters: {:#?}", output.counters);
            assert!(
                output.all_ok,
                "ShowCre relation did not hold under PLUM-Griffin — host-side \
                 keygen/sign produced bytes the guest rejects."
            );
            println!(
                "scheme=plum-griffin-bdec-showcre mode=execute k={k} \
                 setup_ms={setup_ms} sign_ms={sign_ms} exec_ms={exec_ms} \
                 cycles_estimate={cycles} nym_cycles={nym_cyc} uv_cycles={uv_cyc} \
                 show_cycles={show_cyc} all_ok={all_ok}",
                cycles = session_info.cycles(),
                nym_cyc = output.counters.nym_verify_cycles,
                uv_cyc = output.counters.uv_verify_cycles,
                show_cyc = output.counters.show_verify_cycles,
                all_ok = output.all_ok,
            );
        }
        HostMode::Prove => {
            let prover = default_prover();
            let opts_kind =
                std::env::var("BDEC_PROVER_OPTS").unwrap_or_else(|_| "composite".to_string());
            let prover_opts = match opts_kind.as_str() {
                "composite" => ProverOpts::default(),
                "succinct" => ProverOpts::succinct(),
                "groth16" => ProverOpts::groth16(),
                other => panic!(
                    "unknown BDEC_PROVER_OPTS={other:?}; use 'composite', 'succinct', or 'groth16'"
                ),
            };
            info!("prover_opts kind = {} (k = {})", opts_kind, k);
            let prove_t0 = Instant::now();
            let prove_info = prover
                .prove_with_opts(env, BDEC_SHOWCRE_PLUM_GRIFFIN_ELF, &prover_opts)
                .expect("prove failed");
            let prove_ms = prove_t0.elapsed().as_millis();

            let output: GuestOutput =
                prove_info.receipt.journal.decode().expect("decode journal");

            info!("prove mode (opts={opts_kind}, succinct/composite are NOT zero-knowledge)");
            info!("prove_ms = {prove_ms}");
            info!("total_cycles={}", prove_info.stats.total_cycles);
            info!(
                "guest output: all_ok={} uv_ok={} show_ok={} (k={})",
                output.all_ok, output.uv_ok, output.show_ok, output.counters.k
            );
            info!("counters: {:#?}", output.counters);

            prove_info
                .receipt
                .verify(BDEC_SHOWCRE_PLUM_GRIFFIN_ID)
                .expect("receipt verification failed");

            println!(
                "scheme=plum-griffin-bdec-showcre mode=prove opts={opts_kind} k={k} \
                 setup_ms={setup_ms} sign_ms={sign_ms} prove_ms={prove_ms} \
                 total_cycles={cycles} nym_cycles={nym_cyc} uv_cycles={uv_cyc} \
                 show_cycles={show_cyc} all_ok={all_ok}",
                cycles = prove_info.stats.total_cycles,
                nym_cyc = output.counters.nym_verify_cycles,
                uv_cyc = output.counters.uv_verify_cycles,
                show_cyc = output.counters.show_verify_cycles,
                all_ok = output.all_ok,
            );
        }
    }
}
