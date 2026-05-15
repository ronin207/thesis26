//! Fp127::mul microbench: time N invocations on rotating non-trivial operands
//! to measure cycles-per-Fp127-multiplication in zkVM rv32im.

#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use vc_pqc::loquat::field_p127::{Fp127, FP127_MUL_COUNT};

risc0_zkvm::guest::entry!(main);

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

fn main() {
    let input: FpBenchInput = env::read();
    let n: u64 = input.n_muls;

    // Use rotating non-trivial operands so the compiler cannot fold or skip.
    let mut a = Fp127(0xDEADBEEFCAFEBABE_DEADBEEFCAFEBABE_u128);
    let b = Fp127(0x0123456789ABCDEF_0123456789ABCDEF_u128);

    let mul_count_before = FP127_MUL_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let start_cycle = env::cycle_count() as u64;
    for _ in 0..n {
        a = a * b;
    }
    let end_cycle = env::cycle_count() as u64;
    let mul_count_after = FP127_MUL_COUNT.load(core::sync::atomic::Ordering::Relaxed);

    let total_cycles = end_cycle.saturating_sub(start_cycle);
    let cycles_per_mul = if n > 0 { total_cycles / n } else { 0 };

    env::commit(&FpBenchOutput {
        n_muls: n,
        fp127_muls_recorded: mul_count_after.saturating_sub(mul_count_before),
        start_cycle,
        end_cycle,
        total_cycles,
        cycles_per_mul,
        final_hash: a.0,
    });
}
