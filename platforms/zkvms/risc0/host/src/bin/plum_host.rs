//! PLUM verifier zkVM host driver (Phase 11 — three-level attribution).
//!
//! Generates a PLUM keypair, signs the same message twice (once with
//! `PlumSha3Hasher`, once with `PlumGriffinHasher`), and invokes both
//! guest variants. Prints a three-level cycle-attribution comparison:
//!
//!   1. Total cycles + self-reported verify cycles per variant.
//!   2. Per-operation-class counts (Fp192 mul / add, Griffin perm,
//!      PRF eval, hasher compress).
//!   3. Implied cycles per operation (`verify_cycles / count`) for
//!      the dominant classes.
//!
//! Default mode runs both. Override with `PLUM_HOST_HASHER=sha3` or
//! `PLUM_HOST_HASHER=griffin` to run just one. Set
//! `PLUM_HOST_MODE=prove` for real proving (slow). Default is dev/
//! executor mode for fast measurement.

use std::sync::atomic::Ordering;
use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use risc0_zkvm::{ExecutorEnv, default_prover};
use serde::{Deserialize, Serialize};
use tracing::info;

use methods::{PLUM_VERIFY_ELF, PLUM_VERIFY_GRIFFIN_ELF, PLUM_VERIFY_GRIFFIN_ID, PLUM_VERIFY_ID};
use vc_pqc::plum::field_p192::{FP192_ADD_COUNT, FP192_MUL_COUNT};
use vc_pqc::plum::griffin::PLUM_GRIFFIN_PERM_COUNT;
use vc_pqc::plum::hasher::{PLUM_HASHER_COMPRESS_COUNT, PlumGriffinHasher, PlumSha3Hasher};
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

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
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

#[derive(Debug, Clone)]
struct VariantResult {
    label: &'static str,
    verified: bool,
    sign_elapsed_ms: f64,
    invoke_elapsed_ms: f64,
    total_cycles: Option<u64>,
    sign_counters: PlumGuestCounters,
    verify_counters: PlumGuestCounters,
    signature_bytes: usize,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();
    info!("PLUM zkVM Phase 11 — three-level attribution measurement");

    let pp = plum_setup(128).expect("setup");
    let mut keygen_rng = ChaCha20Rng::seed_from_u64(0x504C_554D_0000_0001);
    let (sk, pk) = plum_keygen(&pp, &mut keygen_rng);
    let message = b"plum-zkvm-phase-11".to_vec();
    info!(
        "keypair generated; message = {:?} ({} bytes)",
        std::str::from_utf8(&message).unwrap_or("<binary>"),
        message.len()
    );

    // Adversarial soundness probe mode: empirical evidence for row (f)
    // of the soundness property table. Sibling of the SP1 host's
    // `PLUM_HOST_MODE=adversarial`. Generates an honest SHA3 signature,
    // then runs six tamper cases, asserting the guest's verify result
    // matches expectation.
    if std::env::var("PLUM_HOST_MODE").as_deref() == Ok("adversarial") {
        run_adversarial(&pp, &sk, &pk, &message);
        return;
    }

    let hasher_filter = std::env::var("PLUM_HOST_HASHER").ok();
    let run_sha3 = hasher_filter.as_deref().map_or(true, |s| s == "sha3");
    let run_griffin = hasher_filter.as_deref().map_or(true, |s| s == "griffin");

    let mut results: Vec<VariantResult> = Vec::new();

    if run_sha3 {
        info!("running SHA3 variant");
        results.push(run_variant_sha3(&pp, &sk, &pk, &message));
    }
    if run_griffin {
        info!("running Griffin variant");
        results.push(run_variant_griffin(&pp, &sk, &pk, &message));
    }

    print_three_level_attribution(&results);
}

fn run_variant_sha3(
    pp: &PlumPublicParams,
    sk: &PlumSecretKey,
    pk: &PlumPublicKey,
    message: &[u8],
) -> VariantResult {
    let mut sign_rng = ChaCha20Rng::seed_from_u64(0x504C_554D_5348_4133);
    let (signature, sign_counters, sign_elapsed_ms) = sign_with::<PlumSha3Hasher>(
        pp, sk, message, &mut sign_rng,
    );
    let signature_bytes = bincode::serialize(&signature)
        .map(|v| v.len())
        .unwrap_or(0);

    let (verified, verify_counters, invoke_ms, total_cycles) = invoke_guest(
        PLUM_VERIFY_ELF,
        PLUM_VERIFY_ID,
        pp,
        pk,
        message,
        &signature,
    );

    VariantResult {
        label: "SHA3",
        verified,
        sign_elapsed_ms,
        invoke_elapsed_ms: invoke_ms,
        total_cycles,
        sign_counters,
        verify_counters,
        signature_bytes,
    }
}

fn run_variant_griffin(
    pp: &PlumPublicParams,
    sk: &PlumSecretKey,
    pk: &PlumPublicKey,
    message: &[u8],
) -> VariantResult {
    let mut sign_rng = ChaCha20Rng::seed_from_u64(0x504C_554D_4752_4946);
    let (signature, sign_counters, sign_elapsed_ms) = sign_with::<PlumGriffinHasher>(
        pp, sk, message, &mut sign_rng,
    );
    let signature_bytes = bincode::serialize(&signature)
        .map(|v| v.len())
        .unwrap_or(0);

    let (verified, verify_counters, invoke_ms, total_cycles) = invoke_guest(
        PLUM_VERIFY_GRIFFIN_ELF,
        PLUM_VERIFY_GRIFFIN_ID,
        pp,
        pk,
        message,
        &signature,
    );

    VariantResult {
        label: "Griffin",
        verified,
        sign_elapsed_ms,
        invoke_elapsed_ms: invoke_ms,
        total_cycles,
        sign_counters,
        verify_counters,
        signature_bytes,
    }
}

fn sign_with<H: vc_pqc::plum::hasher::PlumHasher>(
    pp: &PlumPublicParams,
    sk: &PlumSecretKey,
    message: &[u8],
    rng: &mut ChaCha20Rng,
) -> (PlumSignature, PlumGuestCounters, f64) {
    reset_counters();
    let start = Instant::now();
    let signature = plum_sign::<H, _>(pp, sk, message, rng);
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let counters = read_counters_with_cycles(0);
    (signature, counters, elapsed_ms)
}

// ─── Adversarial soundness probe (risc0 side) ────────────────────────

/// One tamper case for the soundness probe. Same set as the SP1 host.
#[derive(Clone, Copy)]
enum Tamper {
    None,
    WrongPk,
    WrongMessage,
    FlipRootC,
    FlipTTag,
    BumpOResponse,
    BumpFinalCoef,
}

impl Tamper {
    fn name(&self) -> &'static str {
        match self {
            Tamper::None => "none (control)",
            Tamper::WrongPk => "wrong public key",
            Tamper::WrongMessage => "wrong message",
            Tamper::FlipRootC => "flip σ_1 root byte",
            Tamper::FlipTTag => "flip PRF t_tag byte",
            Tamper::BumpOResponse => "bump o_responses[0]",
            Tamper::BumpFinalCoef => "bump final_coefs[0]",
        }
    }
    fn expected_accept(&self) -> bool {
        matches!(self, Tamper::None)
    }
}

fn apply_tamper(
    case: Tamper,
    pk: &mut PlumPublicKey,
    message: &mut Vec<u8>,
    sig: &mut PlumSignature,
    alt_pk: &PlumPublicKey,
    alt_message: &[u8],
) {
    use vc_pqc::primitives::field::p192::Fp192;
    match case {
        Tamper::None => {}
        Tamper::WrongPk => *pk = alt_pk.clone(),
        Tamper::WrongMessage => *message = alt_message.to_vec(),
        Tamper::FlipRootC => sig.root_c[0] ^= 0x01,
        Tamper::FlipTTag => {
            if let Some(b) = sig.t_tags.first_mut() {
                *b ^= 0x01;
            }
        }
        Tamper::BumpOResponse => {
            if let Some(o) = sig.o_responses.first_mut() {
                *o = o.clone() + Fp192::from_u64(1);
            }
        }
        Tamper::BumpFinalCoef => {
            if let Some(c) = sig.final_coefs.first_mut() {
                *c = c.clone() + Fp192::from_u64(1);
            }
        }
    }
}

fn run_adversarial(
    pp: &PlumPublicParams,
    sk: &PlumSecretKey,
    pk: &PlumPublicKey,
    message: &[u8],
) {
    // Honest signature once (SHA3 hasher, mirrors SP1 host).
    let mut sign_rng = ChaCha20Rng::seed_from_u64(0x504C_554D_5348_4133);
    let signature = plum_sign::<PlumSha3Hasher, _>(pp, sk, message, &mut sign_rng);

    // Second keypair for the wrong-pk case.
    let mut alt_rng = ChaCha20Rng::seed_from_u64(0xA1_4504C554D_u64);
    let (_alt_sk, alt_pk) = plum_keygen(pp, &mut alt_rng);
    let alt_message = b"risc0 adversarial: a DIFFERENT message that was never signed".to_vec();

    let cases = [
        Tamper::None,
        Tamper::WrongPk,
        Tamper::WrongMessage,
        Tamper::FlipRootC,
        Tamper::FlipTTag,
        Tamper::BumpOResponse,
        Tamper::BumpFinalCoef,
    ];

    println!("\n=== PLUM Verify RISC0 adversarial soundness probe ===");
    println!(
        "control honest signature length: {} bytes",
        bincode::serialize(&signature).expect("serialize sig").len()
    );
    println!();

    let mut all_pass = true;
    for case in cases {
        let mut t_pk = pk.clone();
        let mut t_msg = message.to_vec();
        let mut t_sig = signature.clone();
        apply_tamper(case, &mut t_pk, &mut t_msg, &mut t_sig, &alt_pk, &alt_message);

        let (verified, _counters, invoke_ms, total_cycles) = invoke_guest(
            PLUM_VERIFY_ELF,
            PLUM_VERIFY_ID,
            pp,
            &t_pk,
            &t_msg,
            &t_sig,
        );

        let expected = case.expected_accept();
        let pass = verified == expected;
        if !pass {
            all_pass = false;
        }
        println!(
            "{:24}  expected={:5}  got={:5}  {:>4}  total_cycles={:>11}  elapsed={:.0}ms",
            case.name(),
            expected,
            verified,
            if pass { "PASS" } else { "FAIL" },
            total_cycles.unwrap_or(0),
            invoke_ms,
        );
    }
    println!();
    if all_pass {
        println!("=== ALL {} CASES PASS — adversarial probe held ===", cases.len());
    } else {
        println!("=== ADVERSARIAL PROBE FAILED — at least one case did not match expected outcome ===");
        std::process::exit(1);
    }
}

fn invoke_guest(
    elf: &[u8],
    id: impl Into<risc0_zkvm::Digest>,
    pp: &PlumPublicParams,
    pk: &PlumPublicKey,
    message: &[u8],
    signature: &PlumSignature,
) -> (bool, PlumGuestCounters, f64, Option<u64>) {
    let guest_input = GuestInput {
        pp: pp.clone(),
        pk: pk.clone(),
        message: message.to_vec(),
        signature: signature.clone(),
    };
    let env = ExecutorEnv::builder()
        .write(&guest_input)
        .expect("serialise guest input")
        .build()
        .expect("build executor env");

    let start = Instant::now();
    let prover = default_prover();
    let prove_info = prover.prove(env, elf).expect("guest execution");
    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;
    let receipt = prove_info.receipt;
    let _ = receipt.verify(id.into());
    let journal: GuestOutput = receipt.journal.decode().expect("decode journal");

    (
        journal.verified,
        journal.counters,
        elapsed_ms,
        Some(prove_info.stats.total_cycles),
    )
}

fn reset_counters() {
    FP192_MUL_COUNT.store(0, Ordering::SeqCst);
    FP192_ADD_COUNT.store(0, Ordering::SeqCst);
    PLUM_GRIFFIN_PERM_COUNT.store(0, Ordering::SeqCst);
    PLUM_PRF_EVAL_COUNT.store(0, Ordering::SeqCst);
    PLUM_HASHER_COMPRESS_COUNT.store(0, Ordering::SeqCst);
}

fn read_counters_with_cycles(verify_cycles: u64) -> PlumGuestCounters {
    PlumGuestCounters {
        fp192_muls: FP192_MUL_COUNT.load(Ordering::SeqCst),
        fp192_adds: FP192_ADD_COUNT.load(Ordering::SeqCst),
        griffin_perms: PLUM_GRIFFIN_PERM_COUNT.load(Ordering::SeqCst),
        prf_evals: PLUM_PRF_EVAL_COUNT.load(Ordering::SeqCst),
        hasher_compresses: PLUM_HASHER_COMPRESS_COUNT.load(Ordering::SeqCst),
        verify_cycles_self_reported: verify_cycles,
    }
}

fn print_three_level_attribution(results: &[VariantResult]) {
    println!();
    println!("════ PLUM zkVM Phase 11 — three-level cycle attribution ════");
    println!();

    // ─── Level 1: top-line totals ───
    println!("─── Level 1: top-line ───");
    println!(
        "{:<10} {:>10} {:>14} {:>14} {:>14} {:>12}",
        "hasher", "verified", "total cycles", "verify cyc.", "guest invoke", "sig bytes"
    );
    for r in results {
        println!(
            "{:<10} {:>10} {:>14} {:>14} {:>13.0} ms {:>12}",
            r.label,
            r.verified,
            r.total_cycles.map_or("n/a".to_string(), |c| c.to_string()),
            r.verify_counters.verify_cycles_self_reported,
            r.invoke_elapsed_ms,
            r.signature_bytes,
        );
    }
    println!();

    // ─── Level 2: per-operation counts ───
    println!("─── Level 2: per-operation counts (verify, in-guest) ───");
    println!(
        "{:<10} {:>12} {:>12} {:>12} {:>10} {:>12}",
        "hasher", "Fp192 muls", "Fp192 adds", "Griffin", "PRF evals", "hash compr"
    );
    for r in results {
        println!(
            "{:<10} {:>12} {:>12} {:>12} {:>10} {:>12}",
            r.label,
            r.verify_counters.fp192_muls,
            r.verify_counters.fp192_adds,
            r.verify_counters.griffin_perms,
            r.verify_counters.prf_evals,
            r.verify_counters.hasher_compresses,
        );
    }
    println!();

    // ─── Level 3: implied cycles per operation ───
    println!("─── Level 3: implied cycles per operation ───");
    println!("(verify_cycles_self_reported / count; '-' if count = 0)");
    println!(
        "{:<10} {:>14} {:>14} {:>14} {:>14} {:>14}",
        "hasher", "cyc/Fp192mul", "cyc/Fp192add", "cyc/Griffin", "cyc/PRFeval", "cyc/hash"
    );
    for r in results {
        let vc = r.verify_counters.verify_cycles_self_reported as f64;
        println!(
            "{:<10} {:>14} {:>14} {:>14} {:>14} {:>14}",
            r.label,
            format_ratio(vc, r.verify_counters.fp192_muls),
            format_ratio(vc, r.verify_counters.fp192_adds),
            format_ratio(vc, r.verify_counters.griffin_perms),
            format_ratio(vc, r.verify_counters.prf_evals),
            format_ratio(vc, r.verify_counters.hasher_compresses),
        );
    }
    println!();

    // ─── Level 3b: dominant-class attribution ───
    // For each variant, show the share of cycles plausibly attributable
    // to the dominant op (Fp192 muls) assuming a uniform cost per mul.
    if results.len() == 2 {
        println!("─── Cross-variant deltas ───");
        let sha3 = results.iter().find(|r| r.label == "SHA3").unwrap();
        let griffin = results.iter().find(|r| r.label == "Griffin").unwrap();
        println!(
            "verify cycles  Griffin / SHA3 = {:.2}×  ({} vs {})",
            griffin.verify_counters.verify_cycles_self_reported as f64
                / sha3.verify_counters.verify_cycles_self_reported as f64,
            griffin.verify_counters.verify_cycles_self_reported,
            sha3.verify_counters.verify_cycles_self_reported,
        );
        println!(
            "Fp192 muls     Griffin / SHA3 = {:.2}×  ({} vs {})",
            griffin.verify_counters.fp192_muls as f64
                / sha3.verify_counters.fp192_muls as f64,
            griffin.verify_counters.fp192_muls,
            sha3.verify_counters.fp192_muls,
        );
        println!(
            "Griffin perms  Griffin only   = {}  (SHA3 has 0)",
            griffin.verify_counters.griffin_perms
        );
        println!(
            "hash compresses Griffin / SHA3 = {:.2}×  ({} vs {})",
            griffin.verify_counters.hasher_compresses as f64
                / sha3.verify_counters.hasher_compresses as f64,
            griffin.verify_counters.hasher_compresses,
            sha3.verify_counters.hasher_compresses,
        );
        println!();
    }

    // ─── Reference: sign-side counters ───
    println!("─── Reference: sign-side counters (host-native, not in guest) ───");
    println!(
        "{:<10} {:>12} {:>12} {:>12} {:>10} {:>12} {:>10}",
        "hasher", "Fp192 muls", "Fp192 adds", "Griffin", "PRF evals", "hash compr", "sign ms"
    );
    for r in results {
        println!(
            "{:<10} {:>12} {:>12} {:>12} {:>10} {:>12} {:>9.0}",
            r.label,
            r.sign_counters.fp192_muls,
            r.sign_counters.fp192_adds,
            r.sign_counters.griffin_perms,
            r.sign_counters.prf_evals,
            r.sign_counters.hasher_compresses,
            r.sign_elapsed_ms,
        );
    }
}

fn format_ratio(cycles: f64, count: u64) -> String {
    if count == 0 {
        "-".to_string()
    } else {
        format!("{:.0}", cycles / count as f64)
    }
}
