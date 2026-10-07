//! SP1 BDEC ShowCre k-sweep leakage driver (for `zkleak report`).
//!
//! Secret axis = `k`, the number of pseudonym-ownership checks in ShowCre
//! (total `k+2` PLUM verifies). For each k in 1..=KMAX we build S ShowCre
//! witnesses with FRESH signing randomness, execute-only (machine-independent,
//! seconds each), and emit `k<K>,<cycles>` CSV rows to stdout for zkleak.
//!
//! Unlike the witness-randomness axis (`plum_leakage_host`), k is an
//! ENUMERABLE, control-flow-driving secret — the analog of message-length in
//! zkleak's SHA-256 example. Input size grows WITH k by construction: k IS the
//! secret that drives the work, not a size confound.
//!
//! Witness construction copied VERBATIM from `bdec_execute_report::showcre_witness`,
//! parameterised by k and a per-sample seed. Uses the bool-only SYSCALL ELF
//! (`BDEC_SHOWCRE_SYSCALL_ELF_PATH`), same as `bdec_execute_report`.
//!
//! Env: `BDEC_HOST_SECURITY` (80), `BDEC_KSCAN_KMAX` (8), `BDEC_KSCAN_SAMPLES` (4).

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

const SHOWCRE_SYSCALL_ELF: &[u8] = include_bytes!(env!("BDEC_SHOWCRE_SYSCALL_ELF_PATH"));

#[derive(Serialize, Deserialize)]
struct ShowcreInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    nym_msgs: Vec<Vec<u8>>,
    nym_sigs: Vec<PlumSignature>,
    nym_uv_msg: Vec<u8>,
    nym_uv_sig: PlumSignature,
    show_msg: Vec<u8>,
    show_sig: PlumSignature,
}

fn det(seed: u64, n: usize) -> Vec<u8> {
    let mut r = ChaCha20Rng::seed_from_u64(seed);
    let mut b = vec![0u8; n];
    r.fill_bytes(&mut b);
    b
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
    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let kmax: usize = std::env::var("BDEC_KSCAN_KMAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);

    eprintln!(
        "=== BDEC ShowCre k-sweep (PLUM-{security}-Griffin syscall ELF), k=1..={kmax} ==="
    );

    // Setup + keygen + all signing done ONCE; each k reuses a prefix of the
    // pre-signed pseudonyms. Every input is deterministic, so the execute is
    // deterministic -> one sample per k is the exact cycle count for that k.
    let mut rng = ChaCha20Rng::seed_from_u64(0x5348_4f57_4b53_4341); // "SHOWKSCA"
    let pp = plum_setup(security).expect("setup");
    let (sk_u, pk_u) = plum_keygen(&pp, &mut rng);

    // kmax distinct pseudonym messages, signed once; k reuses the first k.
    let nym_msgs_full: Vec<Vec<u8>> =
        (0..kmax).map(|j| det(0x5441_0000 ^ j as u64, 32)).collect();
    let nym_sigs_full: Vec<PlumSignature> = nym_msgs_full
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
    eprintln!("signing done; executing k=1..={kmax}");

    // CSV for zkleak: secret = k (label), observable = total cycles.
    println!("secret,cycles");

    let client = ProverClient::from_env();

    for k in 1..=kmax {
        let input = ShowcreInput {
            pp: pp.clone(),
            pk_u: pk_u.clone(),
            nym_msgs: nym_msgs_full[..k].to_vec(),
            nym_sigs: nym_sigs_full[..k].to_vec(),
            nym_uv_msg: nym_uv_msg.clone(),
            nym_uv_sig: nym_uv_sig.clone(),
            show_msg: show_msg.clone(),
            show_sig: show_sig.clone(),
        };
        let bytes = bincode::serialize(&input).expect("serialize showcre");
        let input_bytes = bytes.len();
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes);
        let (output, report) = client
            .execute(Elf::Static(SHOWCRE_SYSCALL_ELF), stdin)
            .run()
            .expect("execute failed");
        let accepted: bool =
            bincode::deserialize(output.as_slice()).expect("decode commit");
        let cycles = report.total_instruction_count();
        let griffin = count_syscall(&report, "GRIFFIN_FP192_PERMUTE");
        let mul = count_syscall(&report, "UINT256_MUL");
        assert!(accepted, "witness rejected at k={k}");
        println!("k{k},{cycles}");
        eprintln!(
            "k={k} verifies={} cycles={cycles} griffin_fp192={griffin} uint256_mul={mul} \
             input_bytes={input_bytes} accepted={accepted}",
            k + 2
        );
    }
}
