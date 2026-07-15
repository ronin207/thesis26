//! Witness-dump helper for the BDEC CreGen zk-wrap end-to-end probe
//! (uncommitted, scratch — mirrors `bdec_cregen_host` main() witness
//! construction EXACTLY so the dumped bytes reproduce the measured
//! CreGen workload: cycles=289,221,111, GRIFFIN_FP192_PERMUTE=13206,
//! UINT256_MUL=137971 — R2_cregen_syscall/execute_sanity.log 2026-07-05).
//!
//! Produces the exact `bincode::serialize(&GuestInput)` bytes that
//! `bdec_cregen_host` feeds via `stdin.write_vec(..)`, writes them to
//! argv[1]. Before dumping it EXECUTES the syscall ELF once and asserts
//! `accepted == true`, `GRIFFIN_FP192_PERMUTE == 13206`, and
//! `cycles == 289221111`, so the witness is validated as the real
//! measured CreGen workload at generation time.
//!
//! Seed / hasher / attribute+pseudonym tags / lambda are copied verbatim
//! from `bdec_cregen_host.rs` (0x4244_4543_4352_4547 "BDECCREG",
//! PlumGriffinHasher, "sp1-bdec-cregen-attribute-hash-v1" /
//! "sp1-bdec-cregen-pseudonym-v1", BDEC_HOST_SECURITY default 80).

use std::time::Instant;

use rand::SeedableRng;
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

const BDEC_CREGEN_SYSCALL_ELF_BYTES: &[u8] =
    include_bytes!(env!("BDEC_CREGEN_SYSCALL_ELF_PATH"));

/// Field order MUST match `bdec_cregen_host::GuestInput` (bincode is
/// field-order sensitive; field names are not serialized).
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

fn main() {
    let out_path = std::env::args()
        .nth(1)
        .expect("usage: cregen_witness_dump <out_path>");

    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);

    // === witness construction: verbatim from bdec_cregen_host.rs main() ===
    let mut rng = ChaCha20Rng::seed_from_u64(0x4244_4543_4352_4547); // "BDECCREG"
    let pp = plum_setup(security).expect("setup");
    let (sk_u, pk_u) = plum_keygen(&pp, &mut rng);

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
    let mut sh = Sha256::new();
    sh.update(&bytes);
    let witness_sha256: String = sh.finalize().iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "CreGen-{security} syscall witness bytes: {} sha256={witness_sha256}",
        bytes.len()
    );

    // Validate: execute the syscall ELF once, confirm real measured workload.
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let t = Instant::now();
    let (output, report) = client
        .execute(Elf::Static(BDEC_CREGEN_SYSCALL_ELF_BYTES), stdin)
        .run()
        .expect("execute failed");
    let elapsed_ms = t.elapsed().as_millis() as u64;
    let accepted: bool = bincode::deserialize(output.as_slice()).expect("decode commit");
    let cycles = report.total_instruction_count();
    let griffin = count_syscall(&report, "GRIFFIN_FP192_PERMUTE");
    let uint256 = count_syscall(&report, "UINT256_MUL");
    println!(
        "WITNESS_VALIDATE accepted={accepted} cycles={cycles} elapsed_ms={elapsed_ms} \
         griffin_fp192={griffin} uint256_mul={uint256}"
    );
    assert!(accepted, "guest rejected honest CreGen witness — witness is wrong");
    assert_eq!(
        cycles, 289_221_111,
        "expected 289,221,111 cycles (measured CreGen R2); got {cycles} — NOT the measured config, STOP"
    );
    assert_eq!(
        griffin, 13_206,
        "expected 13206 Griffin permutations (measured CreGen R2); got {griffin}"
    );
    assert_eq!(
        uint256, 137_971,
        "expected 137971 UINT256_MUL (measured CreGen R2); got {uint256}"
    );

    std::fs::write(&out_path, &bytes).expect("write witness file");
    println!("WITNESS_DUMPED path={out_path} bytes={}", bytes.len());
}
