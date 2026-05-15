//! Fp127::mul microbench host: drives the fp_mul_microbench guest in dev
//! mode to measure cycles-per-Fp127-multiplication in zkVM rv32im.
//!
//! Usage: cargo run --release --bin fp_mul_microbench -- [--n 100000]

use methods::{FP_MUL_MICROBENCH_ELF, FP_MUL_MICROBENCH_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct FpBenchInput {
    n_muls: u64,
}

#[derive(Serialize, Deserialize)]
struct FpBenchOutput {
    n_muls: u64,
    fp127_muls_recorded: u64,
    start_cycle: u64,
    end_cycle: u64,
    total_cycles: u64,
    cycles_per_mul: u64,
    final_hash: u128,
}

fn parse_n() -> u64 {
    let args: Vec<String> = std::env::args().collect();
    let mut n: u64 = 100_000;
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
            _ => i += 1,
        }
    }
    n
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let n = parse_n();
    unsafe { std::env::set_var("RISC0_DEV_MODE", "1") };

    let env = ExecutorEnv::builder()
        .write(&FpBenchInput { n_muls: n })
        .expect("write")
        .build()
        .expect("build env");

    let prover = default_prover();
    let prove_info = prover
        .prove(env, FP_MUL_MICROBENCH_ELF)
        .expect("guest exec failed");

    let journal: FpBenchOutput = prove_info
        .receipt
        .journal
        .decode()
        .expect("decode journal");

    let _ = FP_MUL_MICROBENCH_ID;

    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "n_muls": journal.n_muls,
            "fp127_muls_recorded": journal.fp127_muls_recorded,
            "total_cycles": journal.total_cycles,
            "cycles_per_mul": journal.cycles_per_mul,
        }))
        .unwrap()
    );
}
