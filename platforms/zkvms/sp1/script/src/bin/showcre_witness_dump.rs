//! Witness-dump helper for the BDEC ShowCre zk-wrap end-to-end probe
//! (uncommitted, scratch — mirrors `bdec_showcre_host` main() witness
//! construction EXACTLY so the dumped bytes reproduce the measured
//! ShowCre workload). Sibling of `cregen_witness_dump.rs`.
//!
//! `BDEC_SHOWCRE_K` selects k (teaching-authority pseudonyms); the guest
//! then performs k+2 PLUM-Griffin verifications. Measured SP1 execute-mode
//! reference (docs/measurements/sp1_bdec_execute_20260602/RESULT.md,
//! syscall arm):
//!   k=1: cycles=362,637,683  GRIFFIN_FP192_PERMUTE=3156  (3 verifies)
//!   k=2: cycles=481,746,640  GRIFFIN_FP192_PERMUTE=4208  (4 verifies)
//!
//! Produces the exact `bincode::serialize(&GuestInput)` bytes that
//! `bdec_showcre_host` feeds via `stdin.write_vec(..)`, writes them to
//! argv[1]. Before dumping it EXECUTES the syscall ELF once and asserts
//! `accepted == true` plus the measured Griffin/cycle counts for the
//! selected k, so the witness is validated as the real measured ShowCre
//! workload at generation time (before the sp1-prover probe spends hours).
//!
//! Seed / hasher / message tags / lambda are copied verbatim from
//! `bdec_showcre_host.rs` (0x4244_4543_5348_4f57 "BDECSHOW",
//! PlumGriffinHasher, det() pseudonym seeds, "sp1-bdec-showcre-A-down-v1"
//! shown-credential tag, BDEC_HOST_SECURITY default 80).

use std::time::Instant;

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, SP1Stdin,
    blocking::{Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::{PlumSignature, plum_sign};

const BDEC_SHOWCRE_SYSCALL_ELF_BYTES: &[u8] =
    include_bytes!(env!("BDEC_SHOWCRE_SYSCALL_ELF_PATH"));

/// Field order MUST match `bdec_showcre_host::GuestInput` (bincode is
/// field-order sensitive; field names are not serialized).
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

fn count_syscall(report: &sp1_sdk::ExecutionReport, code_name: &str) -> u64 {
    report
        .syscall_counts
        .iter()
        .find(|(code, _)| format!("{:?}", code) == code_name)
        .map(|(_, &n)| n)
        .unwrap_or(0)
}

fn det(seed: u64, n: usize) -> Vec<u8> {
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    let mut b = vec![0u8; n];
    r.fill_bytes(&mut b);
    b
}

/// Measured SP1 execute-mode reference for the selected k (syscall arm).
/// Returns (expected_cycles, expected_griffin). Only k in {1,2} is
/// pre-validated; other k dumps but skips the equality asserts.
fn expected_for_k(k: usize) -> Option<(u64, u64)> {
    match k {
        // Updated 2026-07-08 to the standard-Griffin ShowCre workload measured by
        // docs/measurements/sp1_bdec_execute_20260707 (arm=syscall), cross-checked
        // against this dumper's own WITNESS_VALIDATE line. The prior
        // (362_637_683, 3156)/(481_746_640, 4208) predated the standard-Griffin fix;
        // the BDEC ShowCre relation carries ~6603 Griffin perms/verify (credential
        // machinery beyond the raw verifies), not the ~1052 of a standalone verify.
        1 => Some((433_087_189, 19_809)),
        2 => Some((575_089_654, 26_412)),
        _ => None,
    }
}

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .expect("usage: showcre_witness_dump <out_path>");

    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let k: usize = std::env::var("BDEC_SHOWCRE_K")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&k: &usize| k >= 1)
        .unwrap_or(2);

    // === witness construction: verbatim from bdec_showcre_host.rs main() ===
    let mut rng = ChaCha20Rng::seed_from_u64(0x4244_4543_5348_4f57); // "BDECSHOW"
    let pp = plum_setup(security).expect("setup");
    let (sk_u, pk_u) = plum_keygen(&pp, &mut rng);

    let nym_msgs: Vec<Vec<u8>> = (0..k).map(|j| det(0x5441_0000 ^ j as u64, 32)).collect();
    let nym_sigs: Vec<PlumSignature> = nym_msgs
        .iter()
        .map(|m| plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, m, &mut rng))
        .collect();
    let nym_uv_msg = det(0x5556_0001, 32);
    let nym_uv_sig = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &nym_uv_msg, &mut rng);
    let show_msg = {
        let mut h = Sha256::new();
        h.update(b"sp1-bdec-showcre-A-down-v1");
        h.finalize().to_vec()
    };
    let show_sig = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &show_msg, &mut rng);

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
    let bytes = bincode::serialize(&input).expect("serialize");
    let mut sh = Sha256::new();
    sh.update(&bytes);
    let witness_sha256: String = sh.finalize().iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "ShowCre-{security} k={k} syscall witness bytes: {} sha256={witness_sha256}",
        bytes.len()
    );

    // Validate: execute the syscall ELF once, confirm real measured workload.
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let t = Instant::now();
    let (output, report) = client
        .execute(Elf::Static(BDEC_SHOWCRE_SYSCALL_ELF_BYTES), stdin)
        .run()
        .expect("execute failed");
    let elapsed_ms = t.elapsed().as_millis() as u64;
    let accepted: bool = bincode::deserialize(output.as_slice()).expect("decode commit");
    let cycles = report.total_instruction_count();
    let griffin = count_syscall(&report, "GRIFFIN_FP192_PERMUTE");
    let uint256 = count_syscall(&report, "UINT256_MUL");
    println!(
        "WITNESS_VALIDATE k={k} accepted={accepted} cycles={cycles} elapsed_ms={elapsed_ms} \
         griffin_fp192={griffin} uint256_mul={uint256}"
    );
    assert!(accepted, "guest rejected honest ShowCre witness — witness is wrong");
    if let Some((exp_cycles, exp_griffin)) = expected_for_k(k) {
        assert_eq!(
            griffin, exp_griffin,
            "expected {exp_griffin} Griffin permutations (measured ShowCre k={k}); got {griffin}"
        );
        assert_eq!(
            cycles, exp_cycles,
            "expected {exp_cycles} cycles (measured ShowCre k={k}); got {cycles} — NOT the measured config, STOP"
        );
    } else {
        println!("NOTE: k={k} has no pre-validated reference counts; dumping without equality asserts");
    }

    std::fs::write(&out_path, &bytes).expect("write witness file");
    println!("WITNESS_DUMPED path={out_path} bytes={} k={k}", bytes.len());
}
