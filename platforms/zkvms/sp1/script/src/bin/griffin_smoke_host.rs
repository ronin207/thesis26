//! Griffin Fp192 precompile **smoke-prove** host driver.
//!
//! End-to-end validation that the Griffin chip activated at C4 produces
//! a valid proof. Three stages:
//!
//! 1. **Execute** — run the guest under the executor, validate the
//!    committed permuted state byte-matches what
//!    `sp1_core_executor::griffin_fp192_compute::permute_in_place`
//!    produces in native Rust. Confirms the syscall handler + executor
//!    side work.
//! 2. **Prove** — run the full STARK prover. This is the load-bearing
//!    step: it exercises the per-round chip's algebra + the controller
//!    chip's memory binding + cross-chip lookup + every trace generator
//!    we wrote in F1 / C3.
//! 3. **Verify** — verifier accepts the proof.
//!
//! If all three pass: the Griffin chip works end-to-end. Next step is
//! Cell 2 PLUM-verify with the same precompile active.
//!
//! Run with: `cargo run --release --bin griffin_smoke_host`.

use std::time::Instant;

use sp1_core_executor::griffin_fp192_compute::permute_in_place;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    Elf, ProvingKey, SP1Stdin,
};

/// Bytes of the Griffin smoke-test ELF. Path is set by `build.rs`.
const GRIFFIN_SMOKE_ELF_BYTES: &[u8] = include_bytes!(env!("GRIFFIN_SMOKE_ELF_PATH"));

fn smoke_elf() -> Elf {
    Elf::Static(GRIFFIN_SMOKE_ELF_BYTES)
}

/// The same hardcoded input the guest uses. Kept in sync with
/// `program_griffin_smoke/src/main.rs`. If the guest's input changes,
/// update here too — the reference comparison below depends on it.
fn smoke_input_state() -> [u64; 16] {
    [
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x0000_0000_0000_0042,
        0x0000_0000_0000_0000,
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x0000_0000_0000_0003,
        0x0000_0000_0000_0000,
        0x9999_aaaa_bbbb_cccc,
        0xdddd_eeee_ffff_0000,
        0x0000_0000_0000_0017,
        0x0000_0000_0000_0000,
        0xdead_beef_cafe_babe,
        0xfeed_face_b00b_5aac,
        0x0000_0000_0000_002a,
        0x0000_0000_0000_0000,
    ]
}

fn main() {
    sp1_sdk::utils::setup_logger();

    println!("=== Griffin Fp192 smoke prove ===");

    // Reference output: run permute_in_place on the host CPU.
    let mut reference = smoke_input_state();
    permute_in_place(&mut reference);
    println!("reference output computed (permute_in_place on host)");

    let client = ProverClient::from_env();
    let stdin = SP1Stdin::new(); // guest reads no input

    // ─── Stage 1: execute ───────────────────────────────────────────
    println!("\n--- Stage 1: execute ---");
    let t = Instant::now();
    let (output, report) = client
        .execute(smoke_elf(), stdin.clone())
        .run()
        .expect("execute failed");
    let exec_ms = t.elapsed().as_millis() as u64;

    let committed: [u64; 16] = decode_committed_u64x16(output.as_slice());
    assert_eq!(
        committed, reference,
        "executor committed state mismatched host permute_in_place reference",
    );

    let cycles = report.total_instruction_count();
    let total_syscalls = report.total_syscall_count();
    let griffin = count_syscall(&report, "GRIFFIN_FP192_PERMUTE");
    println!(
        "execute: PASS  cycles={} elapsed_ms={} syscalls={} griffin_fp192={}",
        cycles, exec_ms, total_syscalls, griffin,
    );
    assert_eq!(
        griffin, 1,
        "smoke guest should fire exactly 1 GRIFFIN_FP192_PERMUTE syscall; got {griffin}",
    );

    // ─── Stage 2: prove ─────────────────────────────────────────────
    println!("\n--- Stage 2: prove ---");
    let t_setup = Instant::now();
    let pk = client.setup(smoke_elf()).expect("setup elf failed");
    println!("setup_ms={}", t_setup.elapsed().as_millis() as u64);

    let t_prove = Instant::now();
    let proof = client.prove(&pk, stdin).run().expect("prove failed");
    let prove_ms = t_prove.elapsed().as_millis() as u64;
    println!(
        "prove: PASS  prove_ms={prove_ms} (= {:.2} s)",
        prove_ms as f64 / 1000.0,
    );

    // ─── Stage 3: verify ────────────────────────────────────────────
    println!("\n--- Stage 3: verify ---");
    let t_verify = Instant::now();
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("verify failed");
    let verify_ms = t_verify.elapsed().as_millis() as u64;
    println!("verify: PASS  verify_ms={verify_ms}");

    println!("\n=== Griffin Fp192 smoke prove: ALL STAGES PASSED ===");
    println!("  execute_ms = {}", exec_ms);
    println!("  prove_ms   = {} ({:.2} s)", prove_ms, prove_ms as f64 / 1000.0);
    println!("  verify_ms  = {}", verify_ms);
    println!(
        "  total_ms   = {} ({:.2} s)",
        exec_ms + prove_ms + verify_ms,
        (exec_ms + prove_ms + verify_ms) as f64 / 1000.0,
    );
}

fn decode_committed_u64x16(bytes: &[u8]) -> [u64; 16] {
    // The guest commits 16 individual u64s sequentially. Each commit
    // call serializes one value as little-endian bytes. With bincode
    // (SP1's default), each u64 takes 8 bytes; the total is 128 bytes.
    assert_eq!(
        bytes.len(),
        128,
        "expected 128 bytes of committed output (16 u64), got {}",
        bytes.len(),
    );
    let mut out = [0u64; 16];
    for (i, chunk) in bytes.chunks_exact(8).enumerate() {
        out[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

fn count_syscall(report: &sp1_sdk::ExecutionReport, code_name: &str) -> u64 {
    report
        .syscall_counts
        .iter()
        .find(|(code, _)| format!("{:?}", code) == code_name)
        .map(|(_, &n)| n)
        .unwrap_or(0)
}
