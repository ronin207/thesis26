//! Griffin microbench: time N invocations of griffin_permutation_raw on a
//! fresh-each-time state to measure cycles-per-permutation in zkVM rv32im.
//! Output: total_cycles, n_perms, cycles_per_perm.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use vc_pqc::loquat::field_utils::{field_to_bytes, u128_to_field, F};
use vc_pqc::loquat::griffin::{griffin_permutation_raw, GRIFFIN_STATE_WIDTH};

risc0_zkvm::guest::entry!(main);

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

fn main() {
    let input: GriffinBenchInput = env::read();
    let n: u64 = input.n_perms;

    // Initialise a state with deterministic non-zero values so the compiler
    // can't fold or skip any of the permutation work.
    let mut state: [F; GRIFFIN_STATE_WIDTH] = core::array::from_fn(|i| {
        u128_to_field(((i as u128) * 0xDEADBEEFCAFEBABE_u128).wrapping_add(1))
    });

    let start_cycle = env::cycle_count() as u64;
    for _ in 0..n {
        griffin_permutation_raw(&mut state);
    }
    let end_cycle = env::cycle_count() as u64;

    let total_cycles = end_cycle.saturating_sub(start_cycle);
    let cycles_per_perm = if n > 0 { total_cycles / n } else { 0 };

    // Hash the final state into a single u64 so the output depends on the
    // work (prevents dead-code elimination).
    let mut h: u64 = 0;
    for lane in state.iter() {
        let bytes = field_to_bytes(lane);
        h ^= u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        h ^= u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
    }

    env::commit(&GriffinBenchOutput {
        n_perms: n,
        start_cycle,
        end_cycle,
        total_cycles,
        cycles_per_perm,
        final_state_hash: h,
    });

    // Silence unused warnings
    let _ = String::new;
    let _: Vec<u8> = Vec::new();
}
