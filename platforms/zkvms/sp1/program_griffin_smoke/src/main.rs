//! Griffin Fp192 precompile **smoke-prove** guest.
//!
//! Minimal end-to-end validation that the SP1 fork's
//! `GRIFFIN_FP192_PERMUTE` syscall + per-round chip + controller chip
//! produce a VALID PROOF for any Griffin syscall invocation. Released
//! at the end of Phase 3d-stage-3 C4 (2026-05-19), when the chip
//! activated via `included() = true`.
//!
//! ### What this exercises
//!
//! - The syscall ABI (a single u64 ptr arg + a zero "len" arg per
//!   `crates/zkvm/entrypoint/src/syscalls/griffin_fp192.rs`).
//! - The executor's syscall handler emitting a
//!   `GriffinFp192PrecompileEvent`.
//! - The controller chip's memory binding + cross-chip lookup.
//! - The per-round chip's 14-row trace (B-1 through B-8 algebra,
//!   F1 audit fixes, C3 polynomial-expression cell populate).
//! - Final memory commit matching what `permute_in_place` would
//!   produce in the executor.
//!
//! ### Why so minimal
//!
//! The full PLUM-verify guest (`../program/`) calls Griffin ~977 times
//! per verification, plus many `UINT256_MUL` precompile calls, plus a
//! large amount of native rv32im work for FFT / IFFT / hash chain.
//! Proving it cleanly requires the Griffin chip to be working AND every
//! pre-existing precompile to be working AND ~24 GB of memory headroom.
//! This guest proves only the Griffin chip — if THIS fails, we know
//! the Griffin chip is broken; if THIS succeeds, we have a clean
//! signal to attempt Cell 2 PLUM-verify next.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::syscall_griffin_fp192_permute;

pub fn main() {
    // Hardcoded high-entropy input. Same vector used by
    // `griffin_fp192_compute::tests::round_traces_match_permute_in_place`
    // and `poly_cells_populate_matches_round_trace_for_all_rounds` —
    // the C3 audit-critical drift detector — so a passing smoke prove
    // tells us the chip handles the SAME input both in-test and
    // in-proving.
    //
    // Canonicality: every 4th u64 (positions 3, 7, 11, 15 — the high
    // limb of each Fp192 lane) is zero, satisfying the syscall's
    // entry precondition (each Fp192 < 2^200 so the top 56 bits of
    // its u256 representation are zero, and we drop the unused 64-bit
    // top limb entirely to keep the layout aligned to `[u64; 16]`).
    //
    // Note: We pick lower 3 u64s freely; for true canonicality the
    // 192-bit value < p ≈ 2^199 + a bit. The chosen pattern below
    // gives values well below p so canonicality holds without
    // arithmetic on our side.
    let mut state: [u64; 16] = [
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x0000_0000_0000_0042, // top limb < 2^7
        0x0000_0000_0000_0000, // canonicality slot, MUST be 0
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x0000_0000_0000_0003, // top limb < 2^2
        0x0000_0000_0000_0000, // canonicality slot
        0x9999_aaaa_bbbb_cccc,
        0xdddd_eeee_ffff_0000,
        0x0000_0000_0000_0017, // top limb < 2^5
        0x0000_0000_0000_0000, // canonicality slot
        0xdead_beef_cafe_babe,
        0xfeed_face_b00b_5aac,
        0x0000_0000_0000_002a, // top limb < 2^6
        0x0000_0000_0000_0000, // canonicality slot
    ];

    // Single syscall — minimal surface. The chip handles cross-row
    // state threading across the 14 rounds internally; we don't need
    // multiple calls to exercise that.
    unsafe {
        syscall_griffin_fp192_permute(&mut state as *mut [u64; 16]);
    }

    // Commit the permuted state. The host will check it against
    // `permute_in_place` to validate the proof's claim matches the
    // canonical Griffin reference.
    for word in state.iter() {
        sp1_zkvm::io::commit(word);
    }
}
