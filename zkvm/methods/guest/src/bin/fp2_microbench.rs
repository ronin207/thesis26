//! Fp2 microbench: time N invocations each of Fp2::add, Fp2::sub, Fp2::mul
//! on rotating operands to measure cycles-per-op in zkVM rv32im.

#![no_main]
#![no_std]

extern crate alloc;

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use vc_pqc::loquat::field_p127::{
    Fp127, Fp2, FP127_MUL_COUNT, FP2_ADD_COUNT, FP2_MUL_COUNT, FP2_SUB_COUNT,
};

risc0_zkvm::guest::entry!(main);

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

fn main() {
    let input: Fp2BenchInput = env::read();
    let n: u64 = input.n_ops;

    let a = Fp2::new(
        Fp127(0x1234_5678_9ABC_DEF0_1234_5678_9ABC_DEF0_u128),
        Fp127(0x0FED_CBA9_8765_4321_0FED_CBA9_8765_4321_u128),
    );
    let b = Fp2::new(
        Fp127(0xDEAD_BEEF_CAFE_BABE_DEAD_BEEF_CAFE_BABE_u128),
        Fp127(0x0123_4567_89AB_CDEF_0123_4567_89AB_CDEF_u128),
    );

    // Add
    let add0 = FP2_ADD_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let t0 = env::cycle_count() as u64;
    let mut acc = a;
    for _ in 0..n {
        acc = acc + b;
    }
    let t1 = env::cycle_count() as u64;
    let add1 = FP2_ADD_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let add_cycles = t1 - t0;
    let add_recorded = add1 - add0;

    // Sub
    let sub0 = FP2_SUB_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let t0 = env::cycle_count() as u64;
    let mut acc2 = a;
    for _ in 0..n {
        acc2 = acc2 - b;
    }
    let t1 = env::cycle_count() as u64;
    let sub1 = FP2_SUB_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let sub_cycles = t1 - t0;
    let sub_recorded = sub1 - sub0;

    // Mul (also touches FP127_MUL_COUNT)
    let mul0 = FP2_MUL_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let fp127_0 = FP127_MUL_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let t0 = env::cycle_count() as u64;
    let mut acc3 = a;
    for _ in 0..n {
        acc3 = acc3 * b;
    }
    let t1 = env::cycle_count() as u64;
    let mul1 = FP2_MUL_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let fp127_1 = FP127_MUL_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let mul_cycles = t1 - t0;
    let mul_recorded = mul1 - mul0;
    let fp127_muls_during = fp127_1 - fp127_0;

    // Anti-DCE
    let _ = (acc, acc2, acc3);

    env::commit(&Fp2BenchOutput {
        n_ops: n,
        add_cycles,
        sub_cycles,
        mul_cycles,
        add_count_recorded: add_recorded,
        sub_count_recorded: sub_recorded,
        mul_count_recorded: mul_recorded,
        fp127_muls_during_fp2_mul: fp127_muls_during,
        cycles_per_add: if n > 0 { add_cycles / n } else { 0 },
        cycles_per_sub: if n > 0 { sub_cycles / n } else { 0 },
        cycles_per_mul: if n > 0 { mul_cycles / n } else { 0 },
    });
}
