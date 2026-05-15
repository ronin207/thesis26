//! Loquat-only guest: runs `n` `loquat_verify` calls in sequence with
//! cycle-count AND Griffin-permutation-count snapshots at each Algorithm-7
//! sub-phase boundary. Per-phase totals are summed across all `n` verifies
//! before being committed. All `n` verifies share the same `LoquatPublicParams`;
//! each has its own (message, signature, public_key). No BDEC scaffolding.

#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use vc_pqc::loquat::{
    field_p127::{FP127_MUL_COUNT, FP2_ADD_COUNT, FP2_MUL_COUNT, FP2_SUB_COUNT},
    field_utils::F,
    griffin::GRIFFIN_PERM_COUNT,
    loquat_verify_phased, LoquatPublicParams, LoquatSignature,
};

risc0_zkvm::guest::entry!(main);

const PHASE_NAMES: &[&str] = &[
    "message_commitment",
    "absorb_sigma1",
    "absorb_sigma2",
    "legendre_constraints",
    "sumcheck",
    "absorb_sigma3_sigma4",
    "ldt_openings",
];

#[derive(Serialize, Deserialize)]
struct LoquatItem {
    message: Vec<u8>,
    signature: LoquatSignature,
    public_key: Vec<F>,
}

#[derive(Serialize, Deserialize)]
struct LoquatOnlyInput {
    items: Vec<LoquatItem>,
    params: LoquatPublicParams,
}

#[derive(Serialize, Deserialize)]
struct LoquatOnlyOutput {
    status: String,
    n_sigs: usize,
    n_accepted: usize,
    start_cycle: u64,
    end_cycle: u64,
    /// Per-phase totals summed across all n verifies, in PHASE_NAMES order.
    /// Tuple: (name, cycles, griffin_perms, fp127_muls, fp2_adds, fp2_subs, fp2_muls)
    phase_totals: Vec<(String, u64, u64, u64, u64, u64, u64)>,
    /// Per-verify total cycles.
    per_verify_cycles: Vec<u64>,
    /// Total Griffin permutations across all verifies.
    total_griffin_perms: u64,
    /// Total Fp127 multiplications across all verifies.
    total_fp127_muls: u64,
    /// Total Fp2 additions/subtractions/multiplications across all verifies.
    total_fp2_adds: u64,
    total_fp2_subs: u64,
    total_fp2_muls: u64,
}

fn main() {
    let input: LoquatOnlyInput = env::read();
    let n = input.items.len();

    GRIFFIN_PERM_COUNT.store(0, Ordering::Relaxed);
    FP127_MUL_COUNT.store(0, Ordering::Relaxed);
    FP2_ADD_COUNT.store(0, Ordering::Relaxed);
    FP2_SUB_COUNT.store(0, Ordering::Relaxed);
    FP2_MUL_COUNT.store(0, Ordering::Relaxed);
    let start_cycle = env::cycle_count() as u64;
    let mut phase_cycle_totals: [u64; 7] = [0; 7];
    let mut phase_griffin_totals: [u64; 7] = [0; 7];
    let mut phase_fp127_totals: [u64; 7] = [0; 7];
    let mut phase_fp2_add_totals: [u64; 7] = [0; 7];
    let mut phase_fp2_sub_totals: [u64; 7] = [0; 7];
    let mut phase_fp2_mul_totals: [u64; 7] = [0; 7];
    let mut per_verify_cycles: Vec<u64> = Vec::with_capacity(n);
    let mut n_accepted: usize = 0;
    let mut any_error = false;

    for item in &input.items {
        let verify_start = env::cycle_count() as u64;
        // Snapshot tuple: (cycle, griffin, fp127, fp2_add, fp2_sub, fp2_mul)
        let mut snapshots: Vec<(u64, u64, u64, u64, u64, u64)> = Vec::with_capacity(8);

        let result = loquat_verify_phased(
            &item.message,
            &item.signature,
            &item.public_key,
            &input.params,
            |_name: &'static str| {
                let c = env::cycle_count() as u64;
                let g = GRIFFIN_PERM_COUNT.load(Ordering::Relaxed);
                let f = FP127_MUL_COUNT.load(Ordering::Relaxed);
                let aa = FP2_ADD_COUNT.load(Ordering::Relaxed);
                let ss = FP2_SUB_COUNT.load(Ordering::Relaxed);
                let mm = FP2_MUL_COUNT.load(Ordering::Relaxed);
                snapshots.push((c, g, f, aa, ss, mm));
            },
        );

        let verify_end = env::cycle_count() as u64;
        per_verify_cycles.push(verify_end.saturating_sub(verify_start));

        match result {
            Ok(true) => n_accepted += 1,
            Ok(false) => {}
            Err(_) => any_error = true,
        }

        let len = snapshots.len();
        if len >= 2 {
            let take = core::cmp::min(len - 1, 7);
            for i in 0..take {
                let a = snapshots[i];
                let b = snapshots[i + 1];
                phase_cycle_totals[i] = phase_cycle_totals[i].saturating_add(b.0.saturating_sub(a.0));
                phase_griffin_totals[i] = phase_griffin_totals[i].saturating_add(b.1.saturating_sub(a.1));
                phase_fp127_totals[i] = phase_fp127_totals[i].saturating_add(b.2.saturating_sub(a.2));
                phase_fp2_add_totals[i] = phase_fp2_add_totals[i].saturating_add(b.3.saturating_sub(a.3));
                phase_fp2_sub_totals[i] = phase_fp2_sub_totals[i].saturating_add(b.4.saturating_sub(a.4));
                phase_fp2_mul_totals[i] = phase_fp2_mul_totals[i].saturating_add(b.5.saturating_sub(a.5));
            }
        }
    }

    let end_cycle = env::cycle_count() as u64;
    let total_griffin_perms = GRIFFIN_PERM_COUNT.load(Ordering::Relaxed);
    let total_fp127_muls = FP127_MUL_COUNT.load(Ordering::Relaxed);
    let total_fp2_adds = FP2_ADD_COUNT.load(Ordering::Relaxed);
    let total_fp2_subs = FP2_SUB_COUNT.load(Ordering::Relaxed);
    let total_fp2_muls = FP2_MUL_COUNT.load(Ordering::Relaxed);

    let status = if any_error {
        "error"
    } else if n_accepted == n {
        "ok"
    } else {
        "rejected"
    };

    let phase_totals_vec: Vec<(String, u64, u64, u64, u64, u64, u64)> = (0..7)
        .map(|i| {
            (
                String::from(PHASE_NAMES[i]),
                phase_cycle_totals[i],
                phase_griffin_totals[i],
                phase_fp127_totals[i],
                phase_fp2_add_totals[i],
                phase_fp2_sub_totals[i],
                phase_fp2_mul_totals[i],
            )
        })
        .collect();

    env::commit(&LoquatOnlyOutput {
        status: String::from(status),
        n_sigs: n,
        n_accepted,
        start_cycle,
        end_cycle,
        phase_totals: phase_totals_vec,
        per_verify_cycles,
        total_griffin_perms,
        total_fp127_muls,
        total_fp2_adds,
        total_fp2_subs,
        total_fp2_muls,
    });
}
