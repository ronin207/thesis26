//! Fp2 microbench host: drives the fp2_microbench guest in dev mode.
//! Usage: cargo run --release --bin fp2_microbench -- [--n 100000]

use methods::{FP2_MICROBENCH_ELF, FP2_MICROBENCH_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Fp2BenchInput {
    n_ops: u64,
}

#[derive(Serialize, Deserialize)]
struct Fp2BenchOutput {
    n_ops: u64,
    add_cycles: u64,
    sub_cycles: u64,
    mul_cycles: u64,
    add_count_recorded: u64,
    sub_count_recorded: u64,
    mul_count_recorded: u64,
    fp127_muls_during_fp2_mul: u64,
    cycles_per_add: u64,
    cycles_per_sub: u64,
    cycles_per_mul: u64,
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
    let n = parse_n();
    unsafe { std::env::set_var("RISC0_DEV_MODE", "1") };

    let env = ExecutorEnv::builder()
        .write(&Fp2BenchInput { n_ops: n })
        .expect("write")
        .build()
        .expect("build env");

    let prove_info = default_prover()
        .prove(env, FP2_MICROBENCH_ELF)
        .expect("exec");

    let journal: Fp2BenchOutput = prove_info
        .receipt
        .journal
        .decode()
        .expect("decode");

    let _ = FP2_MICROBENCH_ID;

    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "n_ops": journal.n_ops,
            "cycles_per_add": journal.cycles_per_add,
            "cycles_per_sub": journal.cycles_per_sub,
            "cycles_per_mul": journal.cycles_per_mul,
            "fp127_muls_per_fp2_mul": journal.fp127_muls_during_fp2_mul as f64 / journal.n_ops.max(1) as f64,
        }))
        .unwrap()
    );
}
