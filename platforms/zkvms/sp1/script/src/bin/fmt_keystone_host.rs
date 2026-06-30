//! Keystone matched-field control host driver (execute mode).
//!
//! Measures the per-multiplication field-mismatch tax: software (non-
//! precompile, multi-limb num_bigint) Fp192 multiplication (ℓ=7) vs a
//! native single-limb KoalaBear multiplication (ℓ=1), counting guest
//! cycles in EXECUTE mode (instruction count, NOT prove time).
//!
//! For each mode in {0 = Fp192, 1 = KoalaBear} we run the guest at
//! M = 10000 and M = 20000 multiplications. The per-mult cost is
//!   c_F = (cyc(20000) - cyc(10000)) / 10000
//! which cancels fixed loop / IO / setup overhead. The reported ratio is
//!   c_Fp192 / c_KoalaBear.
//!
//! Run with: `cargo run --release --bin fmt_keystone_host`.

use sp1_sdk::{
    blocking::{Prover, ProverClient},
    Elf, SP1Stdin,
};

/// Bytes of the keystone ELF. Path is set by `build.rs`.
const FMT_KEYSTONE_ELF_BYTES: &[u8] = include_bytes!(env!("FMT_KEYSTONE_ELF_PATH"));

fn keystone_elf() -> Elf {
    Elf::Static(FMT_KEYSTONE_ELF_BYTES)
}

fn main() {
    sp1_sdk::utils::setup_logger();

    println!("=== Keystone matched-field control (execute mode) ===");

    let client = ProverClient::from_env();

    const M_LO: u64 = 10_000;
    const M_HI: u64 = 20_000;
    const DELTA: u64 = M_HI - M_LO; // 10_000

    let run_cycles = |mode: u8, m: u64| -> u64 {
        let mut stdin = SP1Stdin::new();
        stdin.write(&mode);
        stdin.write(&m);
        let (_output, report) = client
            .execute(keystone_elf(), stdin)
            .run()
            .expect("execute failed");
        report.total_instruction_count()
    };

    // mode 0 = Fp192 (software multi-limb, ℓ=7).
    let fp192_lo = run_cycles(0, M_LO);
    let fp192_hi = run_cycles(0, M_HI);
    // mode 1 = KoalaBear (native single-limb, ℓ=1).
    let kb_lo = run_cycles(1, M_LO);
    let kb_hi = run_cycles(1, M_HI);

    let per_mult_fp192 = (fp192_hi - fp192_lo) as f64 / DELTA as f64;
    let per_mult_kb = (kb_hi - kb_lo) as f64 / DELTA as f64;
    let ratio = per_mult_fp192 / per_mult_kb;

    println!("\n--- Raw execute-mode cycle counts (total_instruction_count) ---");
    println!("Fp192     (mode 0)  M={:>6}: {:>12} cycles", M_LO, fp192_lo);
    println!("Fp192     (mode 0)  M={:>6}: {:>12} cycles", M_HI, fp192_hi);
    println!("KoalaBear (mode 1)  M={:>6}: {:>12} cycles", M_LO, kb_lo);
    println!("KoalaBear (mode 1)  M={:>6}: {:>12} cycles", M_HI, kb_hi);

    println!("\n--- Per-multiplication cost (slope, ΔM = {}) ---", DELTA);
    println!("Fp192     per-mult: {:>10.4} cycles/mul", per_mult_fp192);
    println!("KoalaBear per-mult: {:>10.4} cycles/mul", per_mult_kb);

    println!("\n--- Field-mismatch tax ratio ---");
    println!(
        "ratio = c_Fp192 / c_KoalaBear = {:.4}  (ℓ=7 baseline; ℓ²=49)",
        ratio
    );
    println!(
        "necessity direction of prop:field-match: {}",
        if ratio >= 7.0 {
            "CONFIRMED (ratio >= ℓ=7)"
        } else {
            "NOT confirmed (ratio < ℓ=7)"
        }
    );
}
