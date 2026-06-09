//! SP1 Loquat-verify EXECUTE-mode host (Step 1 of the same-scheme
//! cross-substrate workstream).
//!
//! Builds a Loquat λ=80 workload (setup → keygen → sign), serialises the
//! guest input exactly as `program_loquat/src/main.rs` deserialises it
//! (`GuestInput { message, signature, public_key, params }`), loads the
//! `loquat_verify` ELF, and runs `client.execute(...)` ONLY. No prove.
//!
//! Loquat here is the ORIGINAL paper instantiation: Mersenne-127 field
//! (Fp127), Legendre PRF, in-tree Griffin hash. There is NO Fp127 Griffin
//! precompile in this stack, so every Griffin permutation runs EMULATED in
//! rv32im. We confirm this by counting syscalls: GRIFFIN_FP192_PERMUTE is
//! the Fp192 (PLUM) precompile and must read zero here.
//!
//! ANTI-OVERCLAIM: the number this prints is a Loquat-verify, λ=80,
//! EXECUTE-mode cycle count (emulated Griffin), single run. It is NOT a
//! prove-mode wall-clock, NOT a PLUM number, and NOT yet a substrate
//! comparison — the scope-matched Aurora leg is a later step.

use std::time::Instant;

use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

use vc_pqc::signatures::loquat::field_utils::F;
use vc_pqc::signatures::loquat::keygen::keygen_with_params;
use vc_pqc::signatures::loquat::setup::{LoquatPublicParams, loquat_setup};
use vc_pqc::signatures::loquat::sign::{LoquatSignature, loquat_sign};

/// Bytes of the Loquat-verify ELF. Path is set by `build.rs`
/// (`LOQUAT_VERIFY_ELF_PATH`, output `../program_loquat/elf-out/loquat_verify`).
const LOQUAT_VERIFY_ELF_BYTES: &[u8] = include_bytes!(env!("LOQUAT_VERIFY_ELF_PATH"));

/// Must match `program_loquat/src/main.rs` field order EXACTLY — bincode
/// is positional, so any reorder silently corrupts the decode.
#[derive(Serialize, Deserialize)]
struct GuestInput {
    message: Vec<u8>,
    signature: LoquatSignature,
    public_key: Vec<F>,
    params: LoquatPublicParams,
}

fn count_syscall(report: &sp1_sdk::ExecutionReport, code_name: &str) -> u64 {
    report
        .syscall_counts
        .iter()
        .find(|(code, _)| format!("{:?}", code) == code_name)
        .map(|(_, &n)| n)
        .unwrap_or(0)
}

/// PROVE-mode leg. Mirrors plum_host::run_prove: setup(elf) →
/// prove(&pk, stdin).run() (succinct STARK core proof, NOT
/// zero-knowledge — no Groth16/PLONK wrap) → verify. Reports prove
/// wall-clock, verify time, core-proof size (full bincode), and the
/// committed accept bool read from the proof's public values.
///
/// ANTI-OVERCLAIM: this is a Loquat-verify, λ=80, PROVE mode, succinct
/// STARK (NOT zero-knowledge), emulated Griffin (no Fp127 precompile),
/// single run, SP1. It is NOT a like-for-like comparison against PLUM's
/// prove time (PLUM used a precompiled hash + different field/scheme)
/// and is NOT the substrate comparison (that needs a scope-matched
/// Loquat-in-Aurora single-verify number, a separate later step).
fn run_prove(client: &impl Prover, lambda: usize, stdin: SP1Stdin) {
    println!("=== Loquat-verify λ={lambda} on SP1 (PROVE mode, succinct STARK, NOT zero-knowledge) ===");

    let t_setup = Instant::now();
    let pk_proof = client
        .setup(Elf::Static(LOQUAT_VERIFY_ELF_BYTES))
        .expect("setup elf failed");
    println!("setup_ms={}", t_setup.elapsed().as_millis() as u64);

    let t_prove = Instant::now();
    // Succinct STARK core proof via .run() — explicitly NOT .groth16()
    // / .plonk(); per Succinct docs the core proof is NOT ZK.
    let proof = client
        .prove(&pk_proof, stdin)
        .run()
        .expect("prove (core) failed");
    let prove_ms = t_prove.elapsed().as_millis() as u64;
    println!(
        "prove_ms={prove_ms} (= {:.2} min = {:.2} h)",
        prove_ms as f64 / 60_000.0,
        prove_ms as f64 / 3_600_000.0,
    );

    let t_verify = Instant::now();
    client
        .verify(&proof, pk_proof.verifying_key(), None)
        .expect("verify failed");
    println!("verify_ms={}", t_verify.elapsed().as_millis() as u64);

    // Core-proof size: full bincode of SP1ProofWithPublicValues. (.bytes()
    // is the onchain Groth16/PLONK encoding and is NOT meaningful for a
    // core STARK proof, so we serialise the whole proof object instead.)
    let proof_bytes = bincode::serialize(&proof).expect("serialize proof");
    println!("proof_size_bytes={}", proof_bytes.len());

    // Committed accept bool, read from the proof's public values (the
    // verified output) — not from an execute-mode buffer.
    let mut public_values = proof.public_values.clone();
    let accepted: bool = public_values.read();
    println!("committed_accepted={accepted}");

    println!();
    println!("--- Loquat-verify λ={lambda} PROVE-mode result (succinct STARK, NOT ZK, single run) ---");
    println!("prove_ms={prove_ms}");
    println!("proof_size_bytes={}", proof_bytes.len());
    println!("committed_accepted={accepted}");

    // Honest signature MUST verify inside the proof. A reject means the
    // workload or guest input encoding is wrong and the wall-clock is
    // meaningless.
    assert!(accepted, "guest rejected an honest Loquat signature (PROVE mode)");
}

fn main() {
    sp1_sdk::utils::setup_logger();

    // λ = 80 — pinned for this step (NOT 128). Supported levels per
    // src/signatures/loquat/setup.rs::SUPPORTED_SECURITY_LEVELS = [80,100,128].
    let lambda: usize = 80;

    // Mode switch (mirrors plum_host's env-var selector). Default is
    // execute (the existing anchor). LOQUAT_MODE=prove runs the
    // succinct-STARK prove leg.
    let mode = std::env::var("LOQUAT_MODE").unwrap_or_else(|_| "execute".into());

    println!("=== Loquat-verify λ={lambda} on SP1 (mode={mode}, emulated Griffin) ===");

    let params: LoquatPublicParams = loquat_setup(lambda).expect("loquat: setup");
    let keypair = keygen_with_params(&params).expect("loquat: keygen");

    let message =
        b"step1 loquat-verify lambda=80 execute-mode anchor (Fp127, Legendre PRF)".to_vec();
    let signature: LoquatSignature =
        loquat_sign(&message, &keypair, &params).expect("loquat: sign");

    let input = GuestInput {
        message,
        signature,
        public_key: keypair.public_key,
        params,
    };
    let bytes = bincode::serialize(&input).expect("loquat: serialize guest input");
    println!("input bytes: {}", bytes.len());

    let client = ProverClient::from_env();

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);

    if mode == "prove" {
        run_prove(&client, lambda, stdin);
        return;
    }

    let t = Instant::now();
    let (output, report) = client
        .execute(Elf::Static(LOQUAT_VERIFY_ELF_BYTES), stdin)
        .run()
        .expect("execute failed");
    let elapsed_ms = t.elapsed().as_millis() as u64;

    let accepted: bool =
        bincode::deserialize(output.as_slice()).expect("decode committed bool");

    let cycles = report.total_instruction_count();
    let total_syscalls = report.total_syscall_count();
    let griffin_fp192 = count_syscall(&report, "GRIFFIN_FP192_PERMUTE");
    let uint256_mul = count_syscall(&report, "UINT256_MUL");

    println!();
    println!("--- Loquat-verify λ={lambda} EXECUTE-mode result (single run) ---");
    println!("accepted={accepted}");
    println!("cycles={cycles}");
    println!("elapsed_ms={elapsed_ms}");
    println!("total_syscalls={total_syscalls}");
    println!("griffin_fp192_permute={griffin_fp192} (expected 0 — no Fp127 Griffin precompile)");
    println!("uint256_mul={uint256_mul}");
    println!();
    println!("--- full syscall histogram ---");
    let mut counts: Vec<(String, u64)> = report
        .syscall_counts
        .iter()
        .map(|(code, &n)| (format!("{:?}", code), n))
        .collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    for (code, n) in &counts {
        println!("  {code:<28} {n}");
    }

    // Honest signature MUST verify. A reject here means the workload or the
    // guest input encoding is wrong, and the cycle count is meaningless.
    assert!(accepted, "guest rejected an honest Loquat signature");
    // Sanity: the Fp192 Griffin precompile must be dormant on the Fp127
    // Loquat path. Non-zero here would mean we measured the wrong scheme.
    assert_eq!(
        griffin_fp192, 0,
        "GRIFFIN_FP192_PERMUTE fired on the Fp127 Loquat path; got {griffin_fp192}",
    );
}
