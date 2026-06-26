//! SP1 BDEC CreGen host — execute-mode A/B (Griffin syscall vs rv32im).
//!
//! Generates a valid CreGen witness (2 PLUM-Griffin signatures under one
//! hidden `sk_U`), then executes the `bdec_cregen` guest under both the
//! syscall (precompile) and emulated (rv32im) ELFs, reporting cycles +
//! `GRIFFIN_FP192_PERMUTE` + `UINT256_MUL` counts and the
//! with/without-precompile delta. The 2-verification analogue of
//! `plum_host.rs`'s compare mode.
//!
//! Env knobs: `BDEC_HOST_SECURITY` (PLUM lambda, default 80);
//! `BDEC_HOST_MODE` (`compare` = execute-mode A/B, the default;
//! `prove` = succinct prove of the syscall arm, the 2-verification
//! analogue of `plum_host`'s prove mode).
//!
//! ANTI-OVERCLAIM (prove mode): the produced receipt is a succinct STARK,
//! NOT zero-knowledge; single run; wall-clock depends on the memory-tuning
//! env (SHARD_SIZE etc.), which must be recorded alongside any reported
//! number.

use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::{PlumSignature, plum_sign};

// Paths set by build.rs (dedicated dirs so the two arms don't collide in
// target/elf-compilation — cf. build.rs doc-comment).
const SYSCALL_ELF: &[u8] = include_bytes!(env!("BDEC_CREGEN_SYSCALL_ELF_PATH"));
const EMULATED_ELF: &[u8] = include_bytes!(env!("BDEC_CREGEN_EMULATED_ELF_PATH"));

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    h_u_ta: Vec<u8>,
    c_u_ta: PlumSignature,
    ppk_u_ta: Vec<u8>,
    psk_u_ta: PlumSignature,
}

fn count_syscall(report: &sp1_sdk::ExecutionReport, code_name: &str) -> u64 {
    report
        .syscall_counts
        .iter()
        .find(|(code, _)| format!("{:?}", code) == code_name)
        .map(|(_, &n)| n)
        .unwrap_or(0)
}

/// Returns (cycles, griffin_fp192, uint256_mul, elapsed_ms, accepted).
fn execute_once(client: &impl Prover, elf: Elf, bytes: &[u8]) -> (u64, u64, u64, u64, bool) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.to_vec());
    let t = Instant::now();
    let (output, report) = client.execute(elf, stdin).run().expect("execute failed");
    let ms = t.elapsed().as_millis() as u64;
    let accepted: bool = bincode::deserialize(output.as_slice()).expect("decode commit");
    (
        report.total_instruction_count(),
        count_syscall(&report, "GRIFFIN_FP192_PERMUTE"),
        count_syscall(&report, "UINT256_MUL"),
        ms,
        accepted,
    )
}

/// Succinct prove of the syscall arm. Mirrors plum_host/loquat_host
/// run_prove: setup(elf) -> prove -> verify, reporting setup/prove/verify
/// wall-clock and proof size.
fn run_prove(client: &impl Prover, security: usize, bytes: &[u8]) {
    println!(
        "=== BDEC CreGen \u{3bb}={security} on SP1 (PROVE mode, succinct STARK, NOT zero-knowledge) ==="
    );
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.to_vec());

    let t = Instant::now();
    let pk_proof = client.setup(Elf::Static(SYSCALL_ELF)).expect("setup failed");
    println!("setup_ms={}", t.elapsed().as_millis());

    let t = Instant::now();
    // Succinct STARK core proof via .run() — explicitly NOT .groth16()
    // / .plonk(); per Succinct docs the core proof is NOT ZK.
    let proof = client.prove(&pk_proof, stdin).run().expect("prove failed");
    let prove_ms = t.elapsed().as_millis();
    println!(
        "prove_ms={prove_ms} (= {:.2} min)",
        prove_ms as f64 / 60_000.0
    );

    let t = Instant::now();
    client
        .verify(&proof, pk_proof.verifying_key(), None)
        .expect("verify failed");
    let verify_ms = t.elapsed().as_millis();

    let proof_bytes = bincode::serialize(&proof).expect("serialize proof").len();
    let accepted: bool =
        bincode::deserialize(proof.public_values.as_slice()).expect("decode commit");

    println!("--- BDEC CreGen \u{3bb}={security} PROVE-mode result (succinct STARK, NOT ZK, single run) ---");
    println!("accepted={accepted} prove_ms={prove_ms} verify_ms={verify_ms} proof_bytes={proof_bytes}");
    assert!(accepted, "guest rejected an honest CreGen witness (PROVE mode)");
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let mut rng = ChaCha20Rng::seed_from_u64(0x4244_4543_4352_4547); // "BDECCREG"
    let pp = plum_setup(security).expect("setup");
    let (sk_u, pk_u) = plum_keygen(&pp, &mut rng);

    // CreGen witness: credential signature over an attribute hash, plus a
    // pseudonym-ownership signature, both under the same hidden sk_U.
    let h_u_ta = {
        let mut h = Sha256::new();
        h.update(b"sp1-bdec-cregen-attribute-hash-v1");
        h.finalize().to_vec()
    };
    let c_u_ta = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &h_u_ta, &mut rng);
    let ppk_u_ta = {
        let mut h = Sha256::new();
        h.update(b"sp1-bdec-cregen-pseudonym-v1");
        h.finalize().to_vec()
    };
    let psk_u_ta = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_ta, &mut rng);

    let input = GuestInput { pp, pk_u, h_u_ta, c_u_ta, ppk_u_ta, psk_u_ta };
    let bytes = bincode::serialize(&input).expect("serialize");
    println!("=== BDEC CreGen on SP1 (PLUM-{security}-Griffin, 2 verifications) ===");
    println!("input bytes: {}", bytes.len());

    let client = ProverClient::from_env();

    let mode = std::env::var("BDEC_HOST_MODE").unwrap_or_else(|_| "compare".into());
    if mode == "prove" {
        run_prove(&client, security, &bytes);
        return;
    }

    println!("\n--- arm A: Griffin via GRIFFIN_FP192_PERMUTE syscall (precompile) ---");
    let (cyc_a, grf_a, mul_a, ms_a, acc_a) =
        execute_once(&client, Elf::Static(SYSCALL_ELF), &bytes);
    println!(
        "accepted={acc_a} cycles={cyc_a} elapsed_ms={ms_a} griffin_fp192={grf_a} uint256_mul={mul_a}"
    );

    println!("\n--- arm B: Griffin via rv32im emulation (no Griffin precompile) ---");
    let (cyc_b, grf_b, mul_b, ms_b, acc_b) =
        execute_once(&client, Elf::Static(EMULATED_ELF), &bytes);
    println!(
        "accepted={acc_b} cycles={cyc_b} elapsed_ms={ms_b} griffin_fp192={grf_b} uint256_mul={mul_b}"
    );

    assert!(acc_a, "syscall arm rejected the honest CreGen witness");
    assert!(acc_b, "emulated arm rejected the honest CreGen witness");
    assert!(grf_a > 0, "syscall arm fired 0 Griffin syscalls (precompile inactive?)");
    assert_eq!(grf_b, 0, "emulated arm fired {grf_b} Griffin syscalls (should be 0)");

    let delta = cyc_b as i64 - cyc_a as i64;
    let pct = if cyc_b > 0 { delta as f64 / cyc_b as f64 * 100.0 } else { 0.0 };
    println!("\n--- delta (precompile effect on the 2-verification relation) ---");
    println!("griffin permutations (syscall arm): {grf_a}");
    println!("cycle delta (emulated - syscall): {delta:+} ({pct:+.2}% of emulated)");
    println!(
        "cycles saved per griffin perm: {}",
        if grf_a > 0 { delta / grf_a as i64 } else { 0 }
    );
}
