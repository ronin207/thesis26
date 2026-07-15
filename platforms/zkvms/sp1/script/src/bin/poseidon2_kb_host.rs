//! Poseidon2-over-KoalaBear matched-field control host driver (execute mode).
//!
//! Measures the per-permutation cost of a native-field (KoalaBear, ℓ=1)
//! algebraic hash, WITH SP1's shipped Poseidon2 precompile (mode 0) and
//! WITHOUT it (software rv32im, mode 1), in EXECUTE mode (guest instruction
//! count, machine-independent, NOT prove time). This places the ℓ=1 point on
//! the cost-criterion curve of `prop:field-match` (§4); the Griffin-Fp192
//! emulated arm already supplies the ℓ=7 point (~6.7M cyc/perm).
//!
//! For each mode we run N_LO and N_HI permutations and take the slope
//!   c = (cyc(N_HI) - cyc(N_LO)) / (N_HI - N_LO)
//! which cancels fixed loop/IO/setup overhead (same method as fmt_keystone).
//!
//! Run with: `cargo run --release --bin poseidon2_kb_host`.
//! Env: `POSEIDON2_KB_N_LO` (default 10000), `POSEIDON2_KB_N_HI` (default 20000).

use sp1_sdk::{
    blocking::{Prover, ProverClient},
    Elf, SP1Stdin,
};

/// Bytes of the poseidon2_kb ELF. Path is set by `build.rs`.
const POSEIDON2_KB_ELF_BYTES: &[u8] = include_bytes!(env!("POSEIDON2_KB_ELF_PATH"));

fn poseidon2_kb_elf() -> Elf {
    Elf::Static(POSEIDON2_KB_ELF_BYTES)
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

    println!("=== Poseidon2-KoalaBear matched-field control (execute mode, ℓ=1) ===");

    let client = ProverClient::from_env();

    let n_lo: u64 = std::env::var("POSEIDON2_KB_N_LO")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);
    let n_hi: u64 = std::env::var("POSEIDON2_KB_N_HI")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);
    assert!(n_hi > n_lo, "N_HI must exceed N_LO");
    let delta = n_hi - n_lo;

    // Returns (cycles, poseidon2_syscalls).
    let run = |mode: u8, n: u64| -> (u64, u64) {
        let mut stdin = SP1Stdin::new();
        stdin.write(&mode);
        stdin.write(&n);
        let (_output, report) = client
            .execute(poseidon2_kb_elf(), stdin)
            .run()
            .expect("execute failed");
        (
            report.total_instruction_count(),
            count_syscall(&report, "POSEIDON2"),
        )
    };

    // mode 0 = PRECOMPILE arm (POSEIDON2 syscall).
    let (pre_lo, pre_sys_lo) = run(0, n_lo);
    let (pre_hi, pre_sys_hi) = run(0, n_hi);
    // mode 1 = SOFTWARE arm (rv32im).
    let (soft_lo, soft_sys_lo) = run(1, n_lo);
    let (soft_hi, soft_sys_hi) = run(1, n_hi);

    let per_perm_pre = (pre_hi - pre_lo) as f64 / delta as f64;
    let per_perm_soft = (soft_hi - soft_lo) as f64 / delta as f64;

    println!("\n--- Raw execute-mode cycle counts (total_instruction_count) ---");
    println!("precompile (mode 0)  N={:>7}: {:>12} cycles  POSEIDON2 syscalls={}", n_lo, pre_lo, pre_sys_lo);
    println!("precompile (mode 0)  N={:>7}: {:>12} cycles  POSEIDON2 syscalls={}", n_hi, pre_hi, pre_sys_hi);
    println!("software   (mode 1)  N={:>7}: {:>12} cycles  POSEIDON2 syscalls={}", n_lo, soft_lo, soft_sys_lo);
    println!("software   (mode 1)  N={:>7}: {:>12} cycles  POSEIDON2 syscalls={}", n_hi, soft_hi, soft_sys_hi);

    // Sanity: the precompile arm must fire exactly N POSEIDON2 syscalls; the
    // software arm must fire ZERO (a broken cfg fails loudly, not silently).
    assert_eq!(pre_sys_lo, n_lo, "precompile arm fired {pre_sys_lo} POSEIDON2 syscalls, expected {n_lo}");
    assert_eq!(pre_sys_hi, n_hi, "precompile arm fired {pre_sys_hi} POSEIDON2 syscalls, expected {n_hi}");
    assert_eq!(soft_sys_lo, 0, "software arm fired {soft_sys_lo} POSEIDON2 syscalls (should be 0)");
    assert_eq!(soft_sys_hi, 0, "software arm fired {soft_sys_hi} POSEIDON2 syscalls (should be 0)");

    println!("\n--- Per-permutation cost (slope, ΔN = {}) ---", delta);
    println!("precompile (POSEIDON2 syscall) per-perm: {:>12.4} cycles/perm", per_perm_pre);
    println!("software   (rv32im, ℓ=1)       per-perm: {:>12.4} cycles/perm", per_perm_soft);

    let benefit = per_perm_soft - per_perm_pre;
    let ratio = if per_perm_pre > 0.0 { per_perm_soft / per_perm_pre } else { 0.0 };
    println!("\n--- ℓ=1 precompile benefit (software - precompile) ---");
    println!("benefit = {:.4} cycles/perm   software/precompile = {:.4}x", benefit, ratio);
    println!(
        "Interpretation: this is the ℓ=1 point of prop:field-match; contrast with the"
    );
    println!(
        "ℓ=7 Griffin-Fp192 emulated cost (~6.7M cyc/perm, sp1_bdec_execute_20260602)."
    );
    println!(
        "NOTE: software arm = reference-scheduled Poseidon2-KB (width 16, x^3, R_F=8,"
    );
    println!(
        "R_P=20), naive %p reduction — an UPPER BOUND on true native cost; family differs"
    );
    println!(
        "from Griffin (Poseidon2 vs Griffin) — a disclosed confound, not a matched hash."
    );
}
