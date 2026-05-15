//! Griffin microbench host: drives the griffin_microbench guest in dev mode
//! to measure cycles-per-Griffin-permutation in zkVM rv32im.
//!
//! Usage: cargo run --release --bin griffin_microbench -- [--n 10000]

use methods::{GRIFFIN_MICROBENCH_ELF, GRIFFIN_MICROBENCH_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct GriffinBenchInput {
    n_perms: u64,
}

#[derive(Serialize, Deserialize)]
struct GriffinBenchOutput {
    n_perms: u64,
    start_cycle: u64,
    end_cycle: u64,
    total_cycles: u64,
    cycles_per_perm: u64,
    final_state_hash: u64,
}

#[derive(Serialize)]
struct Report {
    n_perms: u64,
    total_cycles: u64,
    cycles_per_perm: u64,
    receipt_kind: String,
}

fn parse_n() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    let mut n: u64 = 10_000;
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--n" => {
                if let Some(v) = args.get(i + 1).and_then(|s| s.parse::<u64>().ok()) {
                    if v > 0 {
                        n = v;
                    }
                }
                i += 2;
            }
            flag if flag.starts_with("--n=") => {
                if let Some(v) = flag.split_once('=').and_then(|(_, s)| s.parse::<u64>().ok())
                {
                    if v > 0 {
                        n = v;
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    n
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let n_perms = parse_n();
    unsafe { std::env::set_var("RISC0_DEV_MODE", "1") };

    let input = GriffinBenchInput { n_perms };
    let env = ExecutorEnv::builder()
        .write(&input)
        .expect("write input")
        .build()
        .expect("build env");

    let prover = default_prover();
    let prove_info = prover
        .prove(env, GRIFFIN_MICROBENCH_ELF)
        .expect("guest execution failed");

    let receipt_kind = match &prove_info.receipt.inner {
        InnerReceipt::Fake(_) => "fake",
        InnerReceipt::Succinct(_) => "succinct",
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Groth16(_) => "groth16",
        _ => "unknown",
    };

    let journal: GriffinBenchOutput = prove_info
        .receipt
        .journal
        .decode()
        .expect("decode journal");

    let _ = GRIFFIN_MICROBENCH_ID;

    println!(
        "{}",
        serde_json::to_string(&Report {
            n_perms: journal.n_perms,
            total_cycles: journal.total_cycles,
            cycles_per_perm: journal.cycles_per_perm,
            receipt_kind: String::from(receipt_kind),
        })
        .expect("serialize")
    );
}
