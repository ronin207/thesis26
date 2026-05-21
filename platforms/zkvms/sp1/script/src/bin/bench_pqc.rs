//! Phase B6 PQ-scheme + classical benchmark host.
//!
//! Dispatches a single signature-verification workload to one of four
//! SP1 guest ELFs (ECDSA-secp256k1 / SPHINCS+ / Dilithium / Loquat),
//! generates a valid test triple natively, ships it to the guest via
//! `SP1Stdin`, and reports cycles + syscall counts (execute mode) or
//! prove/verify wall times (prove mode).
//!
//! Selection:
//!   - `SCHEME=ecdsa|sphincs|dilithium|loquat`  (default: ecdsa)
//!   - `MODE=execute|prove`                      (default: execute)
//!
//! The shape mirrors `plum_host.rs` so the four-scheme + PLUM
//! benchmark table can be produced from one driver pattern.
//!
//! Successive Phase B6 commits add the SPHINCS+ / Dilithium / Loquat
//! arms; ECDSA lands first as the classical anchor.

use std::time::Instant;

use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

const ECDSA_VERIFY_ELF_BYTES: &[u8] =
    include_bytes!(env!("ECDSA_VERIFY_ELF_PATH"));

// ─── Per-scheme guest-input encodings ────────────────────────────────

#[derive(Serialize, Deserialize)]
struct EcdsaGuestInput {
    pub_sec1: Vec<u8>,
    message: Vec<u8>,
    sig_der: Vec<u8>,
}

// ─── Scheme dispatch ────────────────────────────────────────────────

/// Produces a (scheme-label, ELF, bincode-serialised guest input)
/// triple for the selected scheme.
fn build_workload(scheme: &str) -> (&'static str, Elf, Vec<u8>) {
    match scheme {
        "ecdsa" => {
            let (label, bytes) = build_ecdsa_workload();
            (label, Elf::Static(ECDSA_VERIFY_ELF_BYTES), bytes)
        }
        // SPHINCS+, Dilithium, Loquat arms — wired in successive
        // Phase B6 commits.
        other => panic!(
            "unknown SCHEME={other:?}; supported: ecdsa (sphincs/dilithium/loquat pending)"
        ),
    }
}

fn build_ecdsa_workload() -> (&'static str, Vec<u8>) {
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

    // Deterministic seed so every run produces the same workload —
    // matters for execute-mode reproducibility of cycle counts.
    let mut rng = StdRng::seed_from_u64(0x5043_4F45_4344_5341u64); // "PCOECDSA"
    let sk = SigningKey::random(&mut rng);
    let vk: VerifyingKey = (&sk).into();

    let message = b"phase-B6 ecdsa classical anchor: 32 byte message ok".to_vec();
    let sig: Signature = sk.sign(&message);

    // SEC1 uncompressed encoding (65-byte 0x04 || x || y) via the
    // inherent VerifyingKey method.
    let pub_sec1 = vk.to_encoded_point(false).as_bytes().to_vec();
    let sig_der = sig.to_der().as_bytes().to_vec();

    let input = EcdsaGuestInput { pub_sec1, message, sig_der };
    let bytes = bincode::serialize(&input).expect("ecdsa: serialize guest input");
    ("ecdsa-secp256k1 + sha256", bytes)
}

// ─── Modes ──────────────────────────────────────────────────────────

fn main() {
    sp1_sdk::utils::setup_logger();

    let scheme = std::env::var("SCHEME").unwrap_or_else(|_| "ecdsa".into());
    let mode = std::env::var("MODE").unwrap_or_else(|_| "execute".into());

    let (label, elf, input_bytes) = build_workload(&scheme);
    println!("=== bench_pqc — scheme: {label} ===");
    println!("input bytes: {}", input_bytes.len());

    let client = ProverClient::from_env();

    match mode.as_str() {
        "execute" => run_execute(&client, elf, &input_bytes, &scheme),
        "prove" => run_prove(&client, elf, &input_bytes, &scheme),
        other => panic!("unknown MODE={other:?}; use execute or prove"),
    }
}

fn count_syscall(report: &sp1_sdk::ExecutionReport, code_name: &str) -> u64 {
    report
        .syscall_counts
        .iter()
        .find(|(code, _)| format!("{:?}", code) == code_name)
        .map(|(_, &n)| n)
        .unwrap_or(0)
}

fn run_execute(client: &impl Prover, elf: Elf, input_bytes: &[u8], scheme: &str) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input_bytes.to_vec());

    let t = Instant::now();
    let (output, report) = client.execute(elf, stdin).run().expect("execute failed");
    let elapsed_ms = t.elapsed().as_millis() as u64;
    let accepted: bool =
        bincode::deserialize(output.as_slice()).expect("decode commit");

    let cycles = report.total_instruction_count();
    let total_syscalls = report.total_syscall_count();
    let secp_add = count_syscall(&report, "SECP256K1_ADD");
    let secp_double = count_syscall(&report, "SECP256K1_DOUBLE");
    let secp_decompress = count_syscall(&report, "SECP256K1_DECOMPRESS");
    let sha_compress = count_syscall(&report, "SHA_COMPRESS");
    let sha_extend = count_syscall(&report, "SHA_EXTEND");
    let keccak = count_syscall(&report, "KECCAK_PERMUTE");
    let uint256_mul = count_syscall(&report, "UINT256_MUL");

    println!(
        "scheme={scheme} accepted={accepted} cycles={cycles} elapsed_ms={elapsed_ms} \
         total_syscalls={total_syscalls}",
    );
    println!(
        "precompile use:  SECP256K1_ADD={secp_add}  SECP256K1_DOUBLE={secp_double}  \
         SECP256K1_DECOMPRESS={secp_decompress}",
    );
    println!(
        "                 SHA_COMPRESS={sha_compress}  SHA_EXTEND={sha_extend}  \
         KECCAK_PERMUTE={keccak}  UINT256_MUL={uint256_mul}",
    );
    assert!(accepted, "guest rejected an honest signature ({scheme})");
}

fn run_prove(client: &impl Prover, elf: Elf, input_bytes: &[u8], scheme: &str) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input_bytes.to_vec());

    let t_setup = Instant::now();
    let pk_proof = client.setup(elf).expect("setup elf failed");
    println!("setup_ms={}", t_setup.elapsed().as_millis() as u64);

    let t_prove = Instant::now();
    let proof = client.prove(&pk_proof, stdin).run().expect("prove failed");
    let prove_ms = t_prove.elapsed().as_millis() as u64;
    println!(
        "scheme={scheme} prove_ms={prove_ms} (= {:.2} min = {:.2} h)",
        prove_ms as f64 / 60_000.0,
        prove_ms as f64 / 3_600_000.0,
    );

    let t_verify = Instant::now();
    client
        .verify(&proof, pk_proof.verifying_key(), None)
        .expect("verify failed");
    println!("verify_ms={}", t_verify.elapsed().as_millis() as u64);
}
