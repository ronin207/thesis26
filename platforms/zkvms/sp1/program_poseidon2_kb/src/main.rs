//! Poseidon2-over-KoalaBear matched-field control guest (ℓ=1 point).
//!
//! Places the `ℓ=1` point on the cost-criterion curve of `prop:field-match`
//! (§4). The Griffin-Fp192 emulated arm already gives the `ℓ=7` permutation
//! cost (~6.7M cyc/perm, docs/measurements/sp1_bdec_execute_20260602); this
//! guest measures a native-field (KoalaBear, `ℓ=1`) algebraic-hash
//! permutation, both WITH SP1's shipped Poseidon2 precompile and WITHOUT it
//! (software rv32im), so the precompile benefit at `ℓ=1` can be read off and
//! contrasted with the `ℓ=7` benefit.
//!
//! Input (via SP1Stdin): `mode: u8`, then `n: u64`.
//!   mode 0 → PRECOMPILE arm: `n` invocations of SP1's Poseidon2-KoalaBear
//!            permutation via the POSEIDON2 syscall (`Poseidon2State::permute`).
//!   mode 1 → SOFTWARE arm: `n` invocations of a reference-scheduled
//!            Poseidon2-KoalaBear permutation in plain rv32im.
//!
//! Chaining (each permutation feeds the next, single commit at the end)
//! defeats dead-code elimination, so the cycle count reflects `n` real
//! permutations. The host runs `n = N_LO` and `n = N_HI` per mode and takes
//! the difference / (N_HI - N_LO) as the per-permutation cost, cancelling
//! fixed IO/loop/setup overhead (same slope method as `fmt_keystone`).
//!
//! FAITHFULNESS / SCOPE (software arm). The purpose of the software arm is
//! the per-permutation CYCLE COST at `ℓ=1`, NOT a reference hash digest. Its
//! arithmetic STRUCTURE is taken verbatim from slop-koala-bear's `KoalaPerm`
//! (`Poseidon2<KoalaBear, .., 16, 3>`): width 16, S-box `x^3`, `R_F = 8` full
//! rounds (128 S-boxes), `R_P = 20` partial rounds (20 S-boxes) = 148 S-boxes,
//! standard Poseidon2 external (M4 + column-sum) and internal (sum + diagonal)
//! linear layers. Round constants and the internal diagonal are fixed
//! placeholders (cost-neutral: they do not change the operation count, hence
//! not the cycle count). The naive `% p` reduction after each operation makes
//! this an UPPER BOUND on the true native-field cost (same caveat as the
//! `fmt_keystone` KoalaBear baseline). The PRECOMPILE arm (mode 0) is SP1's
//! exact Poseidon2-KoalaBear, so it is the ground-truth `ℓ=1` precompile cost.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_zkvm::syscalls::Poseidon2State;

/// KoalaBear prime: p = 2^31 - 2^24 + 1 = 0x7f000001 = 2130706433.
const P: u64 = 0x7f00_0001;
const WIDTH: usize = 16;

#[inline(always)]
fn add(a: u64, b: u64) -> u64 {
    // a, b < P < 2^31, so a + b < 2^32 fits u64; single conditional subtract.
    let s = a + b;
    if s >= P {
        s - P
    } else {
        s
    }
}

#[inline(always)]
fn mul(a: u64, b: u64) -> u64 {
    // a, b < P < 2^31, so the product < 2^62 fits u64 before reduction.
    (a * b) % P
}

/// S-box x -> x^3 (KoalaBear Poseidon2 uses degree D = 3).
#[inline(always)]
fn sbox(x: u64) -> u64 {
    let x2 = mul(x, x);
    mul(x2, x)
}

/// Poseidon2 optimized M4 on a 4-lane block (matrix circ-derived
/// [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]).
#[inline(always)]
fn apply_mat4(x0: u64, x1: u64, x2: u64, x3: u64) -> (u64, u64, u64, u64) {
    let t0 = add(x0, x1);
    let t1 = add(x2, x3);
    let t2 = add(add(x1, x1), t1); // 2*x1 + t1
    let t3 = add(add(x3, x3), t0); // 2*x3 + t0
    let t1_4 = add(add(t1, t1), add(t1, t1)); // 4*t1
    let t0_4 = add(add(t0, t0), add(t0, t0)); // 4*t0
    let t4 = add(t1_4, t3);
    let t5 = add(t0_4, t2);
    let y0 = add(t3, t5);
    let y1 = t5;
    let y2 = add(t2, t4);
    let y3 = t4;
    (y0, y1, y2, y3)
}

/// External (full-round) linear layer: M4 on each of the 4 blocks, then add
/// the per-position column sum across blocks (standard Poseidon2 M_E, width 16).
#[inline(always)]
fn ext_linear(s: &mut [u64; WIDTH]) {
    let mut z = [0u64; WIDTH];
    for b in 0..4 {
        let o = b * 4;
        let (y0, y1, y2, y3) = apply_mat4(s[o], s[o + 1], s[o + 2], s[o + 3]);
        z[o] = y0;
        z[o + 1] = y1;
        z[o + 2] = y2;
        z[o + 3] = y3;
    }
    for j in 0..4 {
        let colsum = add(add(z[j], z[j + 4]), add(z[j + 8], z[j + 12]));
        s[j] = add(z[j], colsum);
        s[j + 4] = add(z[j + 4], colsum);
        s[j + 8] = add(z[j + 8], colsum);
        s[j + 12] = add(z[j + 12], colsum);
    }
}

/// Internal (partial-round) linear layer: out[i] = sum + diag[i]*s[i]
/// (DiffusionMatrixKoalaBear shape; diagonal is a fixed cost-neutral placeholder).
#[inline(always)]
fn int_linear(s: &mut [u64; WIDTH]) {
    // Fixed nonzero diagonal (placeholder — only the op count is load-bearing).
    const DIAG: [u64; WIDTH] = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
    ];
    let mut sum = 0u64;
    for &v in s.iter() {
        sum = add(sum, v);
    }
    for i in 0..WIDTH {
        s[i] = add(sum, mul(DIAG[i], s[i]));
    }
}

/// One reference-scheduled Poseidon2-KoalaBear permutation
/// (width 16, x^3, R_F=8, R_P=20). `rc` is a running counter used to derive
/// fixed round constants cheaply (cost-neutral placeholder schedule).
fn poseidon2_kb_permute(s: &mut [u64; WIDTH], rc: &mut u64) {
    // Weyl-sequence round constant (fixed, deterministic, cost-neutral).
    let next_rc = |rc: &mut u64| -> u64 {
        *rc = (*rc).wrapping_add(0x9e37_79b9) % P;
        *rc
    };

    // Initial external linear layer.
    ext_linear(s);

    // First half: R_F/2 = 4 full rounds.
    for _ in 0..4 {
        for i in 0..WIDTH {
            s[i] = add(s[i], next_rc(rc));
            s[i] = sbox(s[i]);
        }
        ext_linear(s);
    }

    // R_P = 20 partial rounds (S-box on lane 0 only).
    for _ in 0..20 {
        s[0] = add(s[0], next_rc(rc));
        s[0] = sbox(s[0]);
        int_linear(s);
    }

    // Second half: R_F/2 = 4 full rounds.
    for _ in 0..4 {
        for i in 0..WIDTH {
            s[i] = add(s[i], next_rc(rc));
            s[i] = sbox(s[i]);
        }
        ext_linear(s);
    }
}

pub fn main() {
    let mode: u8 = sp1_zkvm::io::read::<u8>();
    let n: u64 = sp1_zkvm::io::read::<u64>();

    if mode == 0 {
        // PRECOMPILE arm: SP1's shipped Poseidon2-KoalaBear via POSEIDON2 syscall.
        // Chaining is intrinsic — `permute()` is in-place and opaque, so each of
        // the n calls depends on the previous state and none can be hoisted.
        let mut state = Poseidon2State::default();
        for _ in 0..n {
            state.permute();
        }
        let out = state.output();
        for w in out.iter() {
            sp1_zkvm::io::commit(w);
        }
    } else {
        // SOFTWARE arm: reference-scheduled Poseidon2-KoalaBear in rv32im.
        let mut s: [u64; WIDTH] = [
            0x0123_4567, 0x89ab_cdef, 0x1111_2222, 0x3333_4444,
            0x5555_6666, 0x7777_0088, 0x0000_0003, 0x1234_5678,
            0x2233_4455, 0x6677_8899, 0x0aab_bccd, 0x0011_2233,
            0x4455_6677, 0x0899_aabb, 0x0ccd_deef, 0x0000_002a,
        ];
        for v in s.iter_mut() {
            *v %= P;
        }
        let mut rc = 0u64;
        for k in 0..n {
            // Inject the loop counter so nothing can be precomputed / hoisted.
            s[0] = add(s[0], k % P);
            poseidon2_kb_permute(&mut s, &mut rc);
        }
        let out = (s[0] ^ (s[1] << 1)) as u32;
        sp1_zkvm::io::commit(&out);
    }
}
