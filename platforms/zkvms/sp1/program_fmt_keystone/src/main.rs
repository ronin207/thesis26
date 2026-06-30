//! Keystone matched-field control guest.
//!
//! Measures the per-multiplication FIELD-mismatch tax in execute mode:
//! guest cycles for a software (non-precompile, multi-limb) Fp192
//! multiplication (ℓ=7 on the 31-bit KoalaBear prover) vs a native
//! single-limb KoalaBear multiplication (ℓ=1).
//!
//! Input (via SP1Stdin): `mode: u8`, then `m: u64`.
//!   mode 0 → chain `x = x * c` over Fp192, `m` times, software path.
//!   mode 1 → chain `x = (x * c) % p` over KoalaBear u64, `m` times.
//!
//! Chaining (each iteration depends on the previous result, single commit
//! at the end) defeats dead-code elimination so the cycle count reflects
//! `m` real multiplications. The host runs `m = 10000` and `m = 20000`
//! per mode and takes the difference / 10000 as the per-mult cost,
//! cancelling fixed IO / loop / setup overhead.

#![no_main]
sp1_zkvm::entrypoint!(main);

use vc_pqc::primitives::field::p192::Fp192;

/// KoalaBear prime: p = 2^31 - 2^24 + 1 = 0x7f000001 = 2130706433.
const KB_P: u64 = 0x7f00_0001;

/// Single-limb native KoalaBear multiplication. Operands kept < p so the
/// product fits in u64 (< 2^62) before reduction. Naive `%` reduction is
/// an upper bound on the true native-field cost.
#[inline(never)]
fn kb_mul(a: u64, b: u64) -> u64 {
    (a * b) % KB_P
}

pub fn main() {
    let mode: u8 = sp1_zkvm::io::read::<u8>();
    let m: u64 = sp1_zkvm::io::read::<u64>();

    if mode == 0 {
        // Fp192 software multi-limb path (ℓ=7). Nontrivial constants.
        let c = Fp192::from_u64(0x9e37_79b9_7f4a_7c15);
        let mut x = Fp192::from_u64(0x0123_4567_89ab_cdef);
        for _ in 0..m {
            x = x.clone() * c.clone();
        }
        // Commit a u32 derived from the final state so the chain is live.
        let out = x.to_limbs()[0] as u32;
        sp1_zkvm::io::commit(&out);
    } else {
        // KoalaBear native single-limb path (ℓ=1). Nontrivial constants < p.
        let c: u64 = 0x6f00_0123 % KB_P;
        let mut x: u64 = 0x1234_5678 % KB_P;
        for _ in 0..m {
            x = kb_mul(x, c);
        }
        let out = x as u32;
        sp1_zkvm::io::commit(&out);
    }
}
