//! SP1 PLUM leakage / data-independence micro-experiment (A2).
//!
//! Anonymity micro-result: does the PLUM-verify *execution trace* depend
//! on the specific signature (the private witness), holding the public
//! statement class fixed? We keygen ONCE (fixed pp, pk), fix the message,
//! then sign the SAME message `N` times with FRESH signing randomness each
//! iteration (the shared ChaCha20 rng advances per `plum_sign`), producing
//! N distinct valid signatures over the SAME public statement Verify(pk, M, ·).
//! Each witness runs through the Cell-2 (Griffin-syscall) ELF in EXECUTE
//! mode; we record {cycles, GRIFFIN_FP192_PERMUTE count, UINT256_MUL count,
//! sig bytes, accepted}. If those are invariant across witnesses (0 spread),
//! the verifier's work is data-independent — a POSITIVE anonymity micro-
//! result. Nonzero spread LOCATES a leak.
//!
//! Modes (env `PLUM_LEAK_MODE`, default `execute`):
//!   - `execute`  — N witnesses, execute-only, cycle/syscall/size variance.
//!                  N from `PLUM_LEAK_N` (default 20).
//!   - `prove`    — N witnesses, full core prove; proof-size variance.
//!                  N from `PLUM_LEAK_N` (default 3). Honours the SHARD_SIZE
//!                  etc. memory-tuning env via ProverClient::from_env().
//!
//! Reuses the SYSCALL-arm ELF (`PLUM_VERIFY_SYSCALL_ELF_PATH`, set by
//! build.rs) — NO new guest. Griffin-for-hash + SHAKE256-for-FS, the
//! faithful Cell-2 config (matches plum_host's Griffin arm).

use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinShakeFsHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, PlumSecretKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::{PlumSignature, plum_sign};

const PLUM_VERIFY_SYSCALL_ELF_BYTES: &[u8] =
    include_bytes!(env!("PLUM_VERIFY_SYSCALL_ELF_PATH"));

fn syscall_elf() -> Elf {
    Elf::Static(PLUM_VERIFY_SYSCALL_ELF_BYTES)
}

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

fn serialize_input(
    pp: &PlumPublicParams,
    pk: &PlumPublicKey,
    message: &[u8],
    signature: &PlumSignature,
) -> Vec<u8> {
    let input = GuestInput {
        pp: pp.clone(),
        pk: pk.clone(),
        message: message.to_vec(),
        signature: signature.clone(),
    };
    bincode::serialize(&input).expect("serialize input")
}

/// distinct-count / min / max over a slice of u64.
fn spread(xs: &[u64]) -> (usize, u64, u64) {
    let mut sorted = xs.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let min = *xs.iter().min().unwrap_or(&0);
    let max = *xs.iter().max().unwrap_or(&0);
    (sorted.len(), min, max)
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let security_level: usize = std::env::var("PLUM_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let mode = std::env::var("PLUM_LEAK_MODE").unwrap_or_else(|_| "execute".into());
    let default_n = if mode == "prove" { 3 } else { 20 };
    let n: usize = std::env::var("PLUM_LEAK_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&k: &usize| k >= 1)
        .unwrap_or(default_n);

    // Fixed seed -> the WHOLE run is reproducible, but each plum_sign draws
    // fresh randomness (rng advances), so the N signatures differ.
    let mut rng = ChaCha20Rng::seed_from_u64(0x504C554D_4C45414B); // "PLUMLEAK"
    let pp: PlumPublicParams = plum_setup(security_level).expect("setup");
    let (sk, pk): (PlumSecretKey, PlumPublicKey) = plum_keygen(&pp, &mut rng);
    let message = b"sp1 A2 leakage: same public statement, varied signature randomness".to_vec();

    println!(
        "=== PLUM-{} A2 leakage micro-experiment (mode={}, N={}, Cell-2 Griffin-syscall ELF) ===",
        security_level, mode, n
    );
    println!("public statement class: Verify(pk, M, .) with FIXED pk, FIXED M; witness = signature");

    let client = ProverClient::from_env();

    if mode == "execute" {
        run_execute(&client, &pp, &sk, &pk, &message, &mut rng, n);
    } else if mode == "prove" {
        run_prove(&client, &pp, &sk, &pk, &message, &mut rng, n);
    } else {
        panic!("unknown PLUM_LEAK_MODE={mode:?}; use execute or prove");
    }
}

fn run_execute(
    client: &impl Prover,
    pp: &PlumPublicParams,
    sk: &PlumSecretKey,
    pk: &PlumPublicKey,
    message: &[u8],
    rng: &mut ChaCha20Rng,
    n: usize,
) {
    let mut cycles_v = Vec::with_capacity(n);
    let mut griffin_v = Vec::with_capacity(n);
    let mut mul_v = Vec::with_capacity(n);
    let mut sigbytes_v = Vec::with_capacity(n);
    let mut all_accepted = true;

    for i in 0..n {
        let signature: PlumSignature =
            plum_sign::<PlumGriffinShakeFsHasher, _>(pp, sk, message, rng);
        let sig_bytes = bincode::serialize(&signature).expect("serialize sig").len() as u64;
        let bytes = serialize_input(pp, pk, message, &signature);

        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes);
        let t = Instant::now();
        let (output, report) = client
            .execute(syscall_elf(), stdin)
            .run()
            .expect("execute failed");
        let elapsed_ms = t.elapsed().as_millis() as u64;
        let accepted: bool =
            bincode::deserialize(output.as_slice()).expect("decode commit");
        let cycles = report.total_instruction_count();
        let griffin = count_syscall(&report, "GRIFFIN_FP192_PERMUTE");
        let mul = count_syscall(&report, "UINT256_MUL");

        println!(
            "witness={i} accepted={accepted} cycles={cycles} griffin_fp192={griffin} \
             uint256_mul={mul} sig_bytes={sig_bytes} elapsed_ms={elapsed_ms}"
        );
        cycles_v.push(cycles);
        griffin_v.push(griffin);
        mul_v.push(mul);
        sigbytes_v.push(sig_bytes);
        all_accepted &= accepted;
    }

    let (c_d, c_lo, c_hi) = spread(&cycles_v);
    let (g_d, g_lo, g_hi) = spread(&griffin_v);
    let (m_d, m_lo, m_hi) = spread(&mul_v);
    let (s_d, s_lo, s_hi) = spread(&sigbytes_v);

    println!("=== A2 LEAKAGE VARIANCE (N={n}) ===");
    println!("cycles:        distinct={c_d} min={c_lo} max={c_hi} spread={}", c_hi - c_lo);
    println!("griffin_fp192: distinct={g_d} min={g_lo} max={g_hi} spread={}", g_hi - g_lo);
    println!("uint256_mul:   distinct={m_d} min={m_lo} max={m_hi} spread={}", m_hi - m_lo);
    println!("sig_bytes:     distinct={s_d} min={s_lo} max={s_hi} spread={}", s_hi - s_lo);

    // Data-independence = trace metrics invariant across witnesses.
    let data_independent = c_d == 1 && g_d == 1 && m_d == 1;
    println!(
        "A2_VERDICT: data_independent={data_independent} all_accepted={all_accepted} \
         (trace invariant across witnesses => positive anonymity micro-result; \
          nonzero spread => located leak)"
    );
    assert!(all_accepted, "A2: a witness was rejected (honest signature must accept)");
}

fn run_prove(
    client: &impl Prover,
    pp: &PlumPublicParams,
    sk: &PlumSecretKey,
    pk: &PlumPublicKey,
    message: &[u8],
    rng: &mut ChaCha20Rng,
    n: usize,
) {
    println!("A2 PROVE mode: succinct STARK core proofs (NOT ZK); proof-size variance.");
    let t_setup = Instant::now();
    let pk_proof = client.setup(syscall_elf()).expect("setup elf failed");
    println!("setup_ms={}", t_setup.elapsed().as_millis() as u64);

    let mut pbytes_v = Vec::with_capacity(n);
    let mut all_accepted = true;

    for i in 0..n {
        let signature: PlumSignature =
            plum_sign::<PlumGriffinShakeFsHasher, _>(pp, sk, message, rng);
        let bytes = serialize_input(pp, pk, message, &signature);
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes);

        let t = Instant::now();
        let proof = client.prove(&pk_proof, stdin).run().expect("prove (core) failed");
        let prove_ms = t.elapsed().as_millis() as u64;
        client
            .verify(&proof, pk_proof.verifying_key(), None)
            .expect("verify failed");
        let proof_bytes = bincode::serialize(&proof).expect("serialize proof").len() as u64;
        let accepted: bool =
            bincode::deserialize(proof.public_values.as_slice()).expect("decode commit");
        // First occurrence prints in the driver-greppable `prove_ms=`/`proof_bytes=` form.
        println!(
            "witness={i} accepted={accepted} prove_ms={prove_ms} proof_bytes={proof_bytes}"
        );
        pbytes_v.push(proof_bytes);
        all_accepted &= accepted;
    }

    let (p_d, p_lo, p_hi) = spread(&pbytes_v);
    println!("=== A2 PROOF-SIZE VARIANCE (N={n}) ===");
    println!("proof_bytes:   distinct={p_d} min={p_lo} max={p_hi} spread={}", p_hi - p_lo);
    println!(
        "A2_PROVE_VERDICT: proof_size_data_independent={} all_accepted={all_accepted}",
        p_d == 1
    );
    assert!(all_accepted, "A2 prove: a witness was rejected");
}
