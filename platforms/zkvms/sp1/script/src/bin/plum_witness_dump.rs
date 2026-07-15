//! Witness-dump helper for the PLUM-verify zk-wrap end-to-end probe
//! (uncommitted, scratch — mirrors `plum_host` run_prove witness
//! construction EXACTLY so the dumped bytes reproduce the measured
//! Cell-2 workload).
//!
//! Produces the exact `bincode::serialize(&GuestInput)` bytes that
//! `plum_host` PROVE arm=syscall feeds via `stdin.write_vec(..)`, and
//! writes them to the path given in argv[1]. Before dumping it EXECUTES
//! the syscall ELF once and asserts `accepted == true` and
//! `GRIFFIN_FP192_PERMUTE == 1052`, so the witness is validated as the
//! real Cell-2 workload at generation time (where vc_pqc + the ELF are
//! available), before the sp1-prover probe test spends ~40 min on it.
//!
//! Seed / message / hasher / lambda are copied verbatim from
//! `plum_host.rs` (0x504C554D5F535031, b"sp1 phase3f: plum verify",
//! PlumGriffinShakeFsHasher, PLUM_SECURITY default 80).

use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, SP1Stdin,
    blocking::{Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinShakeFsHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, PlumSecretKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::{PlumSignature, plum_sign};

const PLUM_VERIFY_SYSCALL_ELF_BYTES: &[u8] =
    include_bytes!(env!("PLUM_VERIFY_SYSCALL_ELF_PATH"));

/// Field order MUST match `plum_host::GuestInput` (bincode is
/// field-order sensitive; field names are not serialized).
#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk: PlumPublicKey,
    message: Vec<u8>,
    signature: PlumSignature,
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
        .expect("usage: plum_witness_dump <out_path>");

    sp1_sdk::utils::setup_logger();

    let mut rng = ChaCha20Rng::seed_from_u64(0x504C554D5F535031);
    let security_level: usize = std::env::var("PLUM_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let pp: PlumPublicParams = plum_setup(security_level).expect("setup");
    let (sk, pk): (PlumSecretKey, PlumPublicKey) = plum_keygen(&pp, &mut rng);

    let message = b"sp1 phase3f: plum verify".to_vec();
    let signature: PlumSignature =
        plum_sign::<PlumGriffinShakeFsHasher, _>(&pp, &sk, &message, &mut rng);

    let input = GuestInput {
        pp: pp.clone(),
        pk: pk.clone(),
        message: message.clone(),
        signature: signature.clone(),
    };
    let bytes = bincode::serialize(&input).expect("serialize input");
    println!("PLUM-{security_level} syscall witness bytes: {}", bytes.len());

    // Validate: execute the syscall ELF once, confirm real Cell-2 workload.
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let t = Instant::now();
    let (output, report) = client
        .execute(Elf::Static(PLUM_VERIFY_SYSCALL_ELF_BYTES), stdin)
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
    assert!(accepted, "guest rejected honest PLUM signature — witness is wrong");
    assert_eq!(
        griffin, 1052,
        "expected 1052 Griffin permutations (Cell-2 signature); got {griffin}"
    );

    std::fs::write(&out_path, &bytes).expect("write witness file");
    println!("WITNESS_DUMPED path={out_path} bytes={}", bytes.len());
}
