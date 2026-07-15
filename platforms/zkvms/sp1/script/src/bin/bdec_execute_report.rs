//! SP1 BDEC execute-mode FULL-REPORT driver (§6 per-op breakdown).
//!
//! The existing `sp1_bdec_execute_20260602/RESULT.md` records total cycles +
//! GRIFFIN_FP192_PERMUTE + UINT256_MUL counts per relation. This driver adds
//! the FULL `ExecutionReport` — every nonzero `opcode_counts` entry and every
//! nonzero `syscall_counts` entry — for CreGen and ShowCre (k=1, k=2), both
//! the syscall (precompile) and emulated (rv32im) arms, so §6 can cite a
//! per-op cycle/opcode breakdown from the SP1 cost model (NOT the stale
//! RISC-Zero 9.40e9 / 1.41e10 / 1.88e10 figures, which are wrong for an SP1
//! thesis). Execute mode is machine-independent and terminates in seconds.
//!
//! Witness construction is copied VERBATIM from `bdec_cregen_host.rs` and
//! `bdec_showcre_host.rs` main() so the measured host bins stay untouched.
//!
//! Run with: `cargo run --release --bin bdec_execute_report`.
//! Env: `BDEC_HOST_SECURITY` (default 80); `BDEC_REPORT_ARMS`
//! (`both` [default] | `syscall` | `emulated`).

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

const CREGEN_SYSCALL_ELF: &[u8] = include_bytes!(env!("BDEC_CREGEN_SYSCALL_ELF_PATH"));
const CREGEN_EMULATED_ELF: &[u8] = include_bytes!(env!("BDEC_CREGEN_EMULATED_ELF_PATH"));
const SHOWCRE_SYSCALL_ELF: &[u8] = include_bytes!(env!("BDEC_SHOWCRE_SYSCALL_ELF_PATH"));
const SHOWCRE_EMULATED_ELF: &[u8] = include_bytes!(env!("BDEC_SHOWCRE_EMULATED_ELF_PATH"));

#[derive(Serialize, Deserialize)]
struct CregenInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    h_u_ta: Vec<u8>,
    c_u_ta: PlumSignature,
    ppk_u_ta: Vec<u8>,
    psk_u_ta: PlumSignature,
}

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

fn cregen_witness(security: usize) -> Vec<u8> {
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
    let input = CregenInput { pp, pk_u, h_u_ta, c_u_ta, ppk_u_ta, psk_u_ta };
    bincode::serialize(&input).expect("serialize cregen")
}

fn showcre_witness(security: usize, k: usize) -> Vec<u8> {
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
    let input = ShowcreInput {
        pp, pk_u, nym_msgs, nym_sigs, nym_uv_msg, nym_uv_sig, show_msg, show_sig,
    };
    bincode::serialize(&input).expect("serialize showcre")
}

fn dump_report(client: &impl Prover, label: &str, elf: &'static [u8], bytes: &[u8]) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.to_vec());
    let (output, report) = client
        .execute(Elf::Static(elf), stdin)
        .run()
        .expect("execute failed");
    let accepted: bool = bincode::deserialize(output.as_slice()).expect("decode commit");
    let total = report.total_instruction_count();

    println!("\n================ {label} ================");
    println!("accepted={accepted} total_instruction_count={total}");
    println!("touched_memory_addresses={}", report.touched_memory_addresses);

    println!("--- opcode_counts (nonzero) ---");
    let mut ops: Vec<(String, u64)> = report
        .opcode_counts
        .iter()
        .filter(|(_, &n)| n > 0)
        .map(|(op, &n)| (format!("{op:?}"), n))
        .collect();
    ops.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, n) in &ops {
        println!("opcode {op:<20} {n:>14}");
    }

    println!("--- syscall_counts (nonzero) ---");
    let mut sys: Vec<(String, u64)> = report
        .syscall_counts
        .iter()
        .filter(|(_, &n)| n > 0)
        .map(|(sc, &n)| (format!("{sc:?}"), n))
        .collect();
    sys.sort_by(|a, b| b.1.cmp(&a.1));
    for (sc, n) in &sys {
        println!("syscall {sc:<24} {n:>14}");
    }
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let arms = std::env::var("BDEC_REPORT_ARMS").unwrap_or_else(|_| "both".into());
    let do_sys = arms == "both" || arms == "syscall";
    let do_emu = arms == "both" || arms == "emulated";

    println!("=== SP1 BDEC execute-mode FULL-REPORT (PLUM-{security}-Griffin) ===");
    println!("arms={arms}  (per-op breakdown for §6; SP1 cost model, NOT RISC-Zero)");

    let client = ProverClient::from_env();

    let cregen = cregen_witness(security);
    let showcre_k1 = showcre_witness(security, 1);
    let showcre_k2 = showcre_witness(security, 2);

    if do_sys {
        dump_report(&client, "CreGen  arm=syscall", CREGEN_SYSCALL_ELF, &cregen);
        dump_report(&client, "ShowCre k=1 arm=syscall", SHOWCRE_SYSCALL_ELF, &showcre_k1);
        dump_report(&client, "ShowCre k=2 arm=syscall", SHOWCRE_SYSCALL_ELF, &showcre_k2);
    }
    if do_emu {
        dump_report(&client, "CreGen  arm=emulated", CREGEN_EMULATED_ELF, &cregen);
        dump_report(&client, "ShowCre k=1 arm=emulated", SHOWCRE_EMULATED_ELF, &showcre_k1);
        dump_report(&client, "ShowCre k=2 arm=emulated", SHOWCRE_EMULATED_ELF, &showcre_k2);
    }
}
