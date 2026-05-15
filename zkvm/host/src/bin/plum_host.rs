//! PLUM verifier zkVM host driver.
//!
//! Phase 10 of `spec/plum_implementation_plan.md`. Generates a PLUM
//! keypair, signs a message, then invokes the `plum_verify` guest
//! binary in the risc0 zkVM and reports the cycle-attribution
//! counters.
//!
//! Modes:
//!   - executor mode (default, set via `PLUM_HOST_MODE=executor`):
//!     run the guest without proving. Fast (~seconds), produces
//!     real cycle counts but no proof. Useful for Phase 11 cycle-
//!     attribution measurement.
//!   - prove mode (`PLUM_HOST_MODE=prove`): full risc0 prover.
//!     Slow (~minutes to hours). Use when you need an actual proof.

use std::sync::atomic::Ordering;
use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use risc0_zkvm::{ExecutorEnv, default_prover};
use serde::{Deserialize, Serialize};
use tracing::info;

use methods::{PLUM_VERIFY_ELF, PLUM_VERIFY_ID};
use vc_pqc::plum::field_p192::{FP192_ADD_COUNT, FP192_MUL_COUNT};
use vc_pqc::plum::griffin::PLUM_GRIFFIN_PERM_COUNT;
use vc_pqc::plum::hasher::{PLUM_HASHER_COMPRESS_COUNT, PlumSha3Hasher};
use vc_pqc::plum::keygen::{PlumPublicKey, PlumSecretKey, plum_keygen};
use vc_pqc::plum::prf::PLUM_PRF_EVAL_COUNT;
use vc_pqc::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::plum::sign::{PlumSignature, plum_sign};

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk: PlumPublicKey,
    message: Vec<u8>,
    signature: PlumSignature,
}

#[derive(Default, Serialize, Deserialize, Debug)]
struct PlumGuestCounters {
    fp192_muls: u64,
    fp192_adds: u64,
    griffin_perms: u64,
    prf_evals: u64,
    hasher_compresses: u64,
    verify_cycles_self_reported: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct GuestOutput {
    verified: bool,
    counters: PlumGuestCounters,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    info!("PLUM zkVM host — Phase 10 wiring");

    // Build a host-side keypair + signature. RNG seed is fixed so
    // the measurement is reproducible.
    info!("generating PLUM public parameters at λ = 128");
    let pp = plum_setup(128).expect("setup");
    let mut rng = ChaCha20Rng::seed_from_u64(0x504C_554D_0000_0001);
    let (sk, pk) = plum_keygen(&pp, &mut rng);
    let message = b"plum-zkvm-phase-10".to_vec();
    info!("signing message ({} bytes)", message.len());
    // Reset host-side counters before signing for reproducibility
    // (the guest does its own reset before verify).
    FP192_MUL_COUNT.store(0, Ordering::SeqCst);
    FP192_ADD_COUNT.store(0, Ordering::SeqCst);
    PLUM_GRIFFIN_PERM_COUNT.store(0, Ordering::SeqCst);
    PLUM_PRF_EVAL_COUNT.store(0, Ordering::SeqCst);
    PLUM_HASHER_COMPRESS_COUNT.store(0, Ordering::SeqCst);
    let sign_start = Instant::now();
    let signature: PlumSignature = plum_sign::<PlumSha3Hasher, _>(&pp, &sk, &message, &mut rng);
    let sign_elapsed_ms = sign_start.elapsed().as_secs_f64() * 1000.0;
    let host_sign_counters = PlumGuestCounters {
        fp192_muls: FP192_MUL_COUNT.load(Ordering::SeqCst),
        fp192_adds: FP192_ADD_COUNT.load(Ordering::SeqCst),
        griffin_perms: PLUM_GRIFFIN_PERM_COUNT.load(Ordering::SeqCst),
        prf_evals: PLUM_PRF_EVAL_COUNT.load(Ordering::SeqCst),
        hasher_compresses: PLUM_HASHER_COMPRESS_COUNT.load(Ordering::SeqCst),
        verify_cycles_self_reported: 0, // sign doesn't go through env::cycle_count
    };

    let guest_input = GuestInput {
        pp: pp.clone(),
        pk,
        message,
        signature,
    };

    let env = ExecutorEnv::builder()
        .write(&guest_input)
        .expect("serialise guest input")
        .build()
        .expect("build executor env");

    let mode = std::env::var("PLUM_HOST_MODE").unwrap_or_else(|_| "executor".to_string());
    let _ = pk_unused_warning_suppress(&sk);

    info!("invoking guest in mode: {mode}");
    let invoke_start = Instant::now();

    match mode.as_str() {
        "prove" => {
            let prover = default_prover();
            let prove_info = prover
                .prove(env, PLUM_VERIFY_ELF)
                .expect("guest proof generation");
            let invoke_elapsed_s = invoke_start.elapsed().as_secs_f64();
            let receipt = prove_info.receipt;
            receipt
                .verify(PLUM_VERIFY_ID)
                .expect("receipt verification");
            let journal: GuestOutput =
                receipt.journal.decode().expect("decode journal");
            print_summary(
                &mode,
                &journal,
                &host_sign_counters,
                sign_elapsed_ms,
                invoke_elapsed_s * 1000.0,
                Some(prove_info.stats.total_cycles),
                Some(receipt.seal_size()),
            );
        }
        _ => {
            // executor mode: fast cycle counting without proving.
            // risc0 3.x exposes execution via the prover's
            // execute() path. We can also use a lower-level
            // ExecutorImpl directly. For maximal portability we
            // re-use the prove() path but on the executor-backed
            // prover (BONSAI_API_URL=mock or env feature). For
            // now, fallback to "fake" prove which runs the guest
            // and produces a non-cryptographic receipt.
            let prover = default_prover();
            let prove_info = prover
                .prove(env, PLUM_VERIFY_ELF)
                .expect("guest execution");
            let invoke_elapsed_s = invoke_start.elapsed().as_secs_f64();
            let receipt = prove_info.receipt;
            let journal: GuestOutput =
                receipt.journal.decode().expect("decode journal");
            print_summary(
                &mode,
                &journal,
                &host_sign_counters,
                sign_elapsed_ms,
                invoke_elapsed_s * 1000.0,
                Some(prove_info.stats.total_cycles),
                None,
            );
        }
    }
}

fn print_summary(
    mode: &str,
    journal: &GuestOutput,
    host_sign_counters: &PlumGuestCounters,
    sign_elapsed_ms: f64,
    invoke_elapsed_ms: f64,
    total_cycles: Option<u64>,
    proof_size_bytes: Option<usize>,
) {
    println!();
    println!("════ PLUM zkVM Phase 10 results (mode={mode}) ════");
    println!("verified           : {}", journal.verified);
    println!("sign elapsed       : {:.2} ms (host)", sign_elapsed_ms);
    println!("guest invoke       : {:.2} ms", invoke_elapsed_ms);
    if let Some(c) = total_cycles {
        println!("total cycles       : {c}");
    }
    if let Some(b) = proof_size_bytes {
        println!("proof seal bytes   : {b}");
    }
    println!();
    println!("─── Counters (verify, in-guest) ───");
    println!("Fp192 muls         : {}", journal.counters.fp192_muls);
    println!("Fp192 adds         : {}", journal.counters.fp192_adds);
    println!("Griffin perms      : {}", journal.counters.griffin_perms);
    println!("PRF evals          : {}", journal.counters.prf_evals);
    println!("hasher compresses  : {}", journal.counters.hasher_compresses);
    println!(
        "verify cycles      : {} (self-reported via env::cycle_count)",
        journal.counters.verify_cycles_self_reported
    );
    println!();
    println!("─── Counters (sign, host-side, for reference) ───");
    println!("Fp192 muls         : {}", host_sign_counters.fp192_muls);
    println!("Fp192 adds         : {}", host_sign_counters.fp192_adds);
    println!("Griffin perms      : {}", host_sign_counters.griffin_perms);
    println!("PRF evals          : {}", host_sign_counters.prf_evals);
    println!(
        "hasher compresses  : {}",
        host_sign_counters.hasher_compresses
    );
}

/// `PlumSecretKey` is intentionally unused by the host past signing;
/// keep this stub to suppress the warning rather than annotating
/// `_sk` (which would obscure the intent at the call site).
fn pk_unused_warning_suppress(_sk: &PlumSecretKey) {}
