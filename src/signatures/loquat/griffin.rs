use crate::signatures::loquat::field_utils::{field_to_bytes, F};
#[cfg(not(feature = "std"))]
use alloc::{format, vec, vec::Vec};
#[cfg(not(feature = "std"))]
use core::cmp::{max, min};
#[cfg(not(feature = "std"))]
use core::mem::MaybeUninit;
#[cfg(feature = "std")]
use num_bigint::BigUint;
#[cfg(feature = "std")]
use num_traits::{One, ToPrimitive, Zero};
#[cfg(feature = "std")]
use once_cell::sync::Lazy;
use sha3::{
    Shake256,
    digest::ExtendableOutput,
};
#[cfg(feature = "std")]
use std::cmp::{max, min};
#[cfg(feature = "std")]
use std::vec::Vec;

const FIELD_MODULUS: u128 = (1u128 << 127) - 1;
const STATE_WIDTH: usize = 4;
const CAPACITY: usize = 2;
const RATE: usize = STATE_WIDTH - CAPACITY;
const SECURITY_LEVEL: usize = 128;
const DIGEST_ELEMENTS: usize = 2; // 2 * 16 bytes = 32-byte digest

pub const GRIFFIN_FIELD_MODULUS: u128 = FIELD_MODULUS;

/// Global counter incremented on every Griffin permutation invocation.
/// Used by attribution measurements in the RISC0 guest. Negligible
/// overhead vs the ~thousands of field ops per permutation.
pub static GRIFFIN_PERM_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
pub const GRIFFIN_STATE_WIDTH: usize = STATE_WIDTH;
pub const GRIFFIN_CAPACITY: usize = CAPACITY;
pub const GRIFFIN_RATE: usize = RATE;
pub const GRIFFIN_SECURITY_LEVEL: usize = SECURITY_LEVEL;
pub const GRIFFIN_DIGEST_ELEMENTS: usize = DIGEST_ELEMENTS;

#[derive(Clone, Debug)]
pub struct GriffinParams {
    pub matrix: [[F; STATE_WIDTH]; STATE_WIDTH],
    pub round_constants: Vec<F>,
    pub alphas: Vec<F>,
    pub betas: Vec<F>,
    pub rounds: usize,
    pub d: u128,
    pub d_inv: u128,
}

#[derive(Clone, Debug)]
pub struct GriffinState {
    lanes: [F; STATE_WIDTH],
}

#[cfg(feature = "std")]
static GRIFFIN_PARAMS: Lazy<GriffinParams> = Lazy::new(compute_griffin_params);

#[cfg(not(feature = "std"))]
static mut GRIFFIN_PARAMS: MaybeUninit<GriffinParams> = MaybeUninit::uninit();
#[cfg(not(feature = "std"))]
static mut GRIFFIN_PARAMS_INIT: bool = false;

#[cfg(feature = "std")]
pub fn get_griffin_params() -> &'static GriffinParams {
    &GRIFFIN_PARAMS
}

#[cfg(not(feature = "std"))]
pub fn get_griffin_params() -> &'static GriffinParams {
    // Single-threaded guest: unsafe lazy init is acceptable here.
    #[allow(static_mut_refs)]
    unsafe {
        if !GRIFFIN_PARAMS_INIT {
            GRIFFIN_PARAMS.write(compute_griffin_params());
            GRIFFIN_PARAMS_INIT = true;
        }
        &*GRIFFIN_PARAMS.as_ptr()
    }
}

pub fn griffin_hash(data: &[u8]) -> Vec<u8> {
    let params = get_griffin_params();
    let elements = bytes_to_field_elements(data);
    let outputs = griffin_sponge(params, elements, DIGEST_ELEMENTS);
    field_elements_to_bytes(&outputs)
}

pub fn griffin_hash_default(data: &[u8]) -> Vec<u8> {
    griffin_hash(data)
}

pub fn griffin_sponge(params: &GriffinParams, mut inputs: Vec<F>, output_len: usize) -> Vec<F> {
    let mut state = GriffinState {
        lanes: [F::zero(); STATE_WIDTH],
    };
    if inputs.len() % RATE != 0 {
        state.lanes[RATE] = F::one();
        inputs.push(F::one());
    }
    while inputs.len() % RATE != 0 {
        inputs.push(F::zero());
    }

    let mut absorb_idx = 0;
    while absorb_idx < inputs.len() {
        for lane in 0..RATE {
            state.lanes[lane] += inputs[absorb_idx];
            absorb_idx += 1;
        }
        griffin_permutation(params, &mut state);
    }

    let mut outputs = Vec::with_capacity(output_len);
    let mut squeeze_idx = 0;
    loop {
        for lane in 0..RATE {
            outputs.push(state.lanes[lane]);
            squeeze_idx += 1;
            if squeeze_idx == output_len {
                return outputs;
            }
        }
        griffin_permutation(params, &mut state);
    }
}

fn griffin_permutation(params: &GriffinParams, state: &mut GriffinState) {
    GRIFFIN_PERM_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    for r in 0..params.rounds - 1 {
        nonlinear_layer(params, state);
        linear_layer(params, state);
        additive_constants_layer(params, state, r);
    }
    nonlinear_layer(params, state);
    linear_layer(params, state);
}

/// Low-level permutation wrapper over a raw lane array.
///
/// This is used by the Merkle-tree implementation to guarantee that leaf/internal-node
/// compression uses exactly one permutation invocation.
pub fn griffin_permutation_raw(state: &mut [F; GRIFFIN_STATE_WIDTH]) {
    let params = get_griffin_params();
    let mut s = GriffinState { lanes: *state };
    griffin_permutation(params, &mut s);
    *state = s.lanes;
}

fn nonlinear_layer(params: &GriffinParams, state: &mut GriffinState) {
    state.lanes[0] = state.lanes[0].pow(params.d_inv);
    state.lanes[1] = state.lanes[1].pow(params.d);

    let l = li(state.lanes[0], state.lanes[1], F::zero(), 2);
    state.lanes[2] *= l * l + params.alphas[0] * l + params.betas[0];
    for idx in 3..STATE_WIDTH {
        let l = li(state.lanes[0], state.lanes[1], state.lanes[idx - 1], idx);
        state.lanes[idx] *= l * l + params.alphas[idx - 2] * l + params.betas[idx - 2];
    }
}

fn linear_layer(params: &GriffinParams, state: &mut GriffinState) {
    let mut next = [F::zero(); STATE_WIDTH];
    for row in 0..STATE_WIDTH {
        for col in 0..STATE_WIDTH {
            next[row] += params.matrix[row][col] * state.lanes[col];
        }
    }
    state.lanes = next;
}

fn additive_constants_layer(params: &GriffinParams, state: &mut GriffinState, round: usize) {
    for lane in 0..STATE_WIDTH {
        state.lanes[lane] += params.round_constants[round * STATE_WIDTH + lane];
    }
}

fn li(z0: F, z1: F, z2: F, i: usize) -> F {
    F::new((i as u128 - 1) as u128) * z0 + z1 + z2
}

fn bytes_to_field_elements(bytes: &[u8]) -> Vec<F> {
    const LIMB_BYTES: usize = 16;
    if bytes.is_empty() {
        return vec![F::zero()];
    }
    let mut elems = Vec::with_capacity((bytes.len() + LIMB_BYTES - 1) / LIMB_BYTES);
    let mut chunk = [0u8; LIMB_BYTES];
    for (i, &byte) in bytes.iter().enumerate() {
        chunk[i % LIMB_BYTES] = byte;
        if i % LIMB_BYTES == LIMB_BYTES - 1 {
            elems.push(chunk_to_field(&chunk));
            chunk = [0u8; LIMB_BYTES];
        }
    }
    let remainder = bytes.len() % LIMB_BYTES;
    if remainder != 0 {
        elems.push(chunk_to_field(&chunk));
    }
    elems
}

fn field_elements_to_bytes(elements: &[F]) -> Vec<u8> {
    let mut out = Vec::with_capacity(elements.len() * 16);
    for elem in elements {
        out.extend_from_slice(&field_to_bytes(elem));
    }
    out
}

fn chunk_to_field(chunk: &[u8; 16]) -> F {
    let mut value = 0u128;
    for (i, byte) in chunk.iter().enumerate() {
        value |= (*byte as u128) << (8 * i);
    }
    F::new(value)
}

fn compute_griffin_params() -> GriffinParams {
    let (d, d_inv) = get_powers();
    let rounds = get_number_of_rounds(d);
    let bytes_per_int = ((127 + 7) / 8) + 1;
    let num_elements = STATE_WIDTH * (rounds - 1) + 2;
    let mut shake = Shake256::default();
    sha3::digest::Update::update(
        &mut shake,
        format!(
            "Griffin({},{},{},{})",
            FIELD_MODULUS, STATE_WIDTH, CAPACITY, SECURITY_LEVEL
        )
        .as_bytes(),
    );
    let mut reader = shake.finalize_xof();
    let mut buf = vec![0u8; bytes_per_int * num_elements];
    sha3::digest::XofReader::read(&mut reader, &mut buf);

    let mut offset = 0;
    let alpha = bytes_chunk_to_field(&buf[offset..offset + bytes_per_int]);
    offset += bytes_per_int;
    let beta = bytes_chunk_to_field(&buf[offset..offset + bytes_per_int]);
    offset += bytes_per_int;

    let mut alphas = Vec::with_capacity(max(1, STATE_WIDTH.saturating_sub(2)));
    let mut betas = Vec::with_capacity(max(1, STATE_WIDTH.saturating_sub(2)));
    alphas.push(alpha);
    betas.push(beta);
    for i in 3..STATE_WIDTH {
        alphas.push(F::new((i as u128 - 1) as u128) * alpha);
        betas.push(F::new(((i as u128 - 1).pow(2)) as u128) * beta);
    }

    let mut round_constants = Vec::with_capacity(STATE_WIDTH * (rounds - 1));
    while round_constants.len() < STATE_WIDTH * (rounds - 1) {
        let elem = bytes_chunk_to_field(&buf[offset..offset + bytes_per_int]);
        round_constants.push(elem);
        offset += bytes_per_int;
    }

    GriffinParams {
        matrix: build_matrix(),
        round_constants,
        alphas,
        betas,
        rounds,
        d,
        d_inv,
    }
}

#[cfg(feature = "std")]
fn bytes_chunk_to_field(bytes: &[u8]) -> F {
    let mut acc = BigUint::zero();
    for (i, byte) in bytes.iter().enumerate() {
        acc += BigUint::from(*byte) << (8 * i);
    }
    let modulus = BigUint::from(FIELD_MODULUS);
    let reduced = acc % modulus;
    F::new(reduced.to_u128().unwrap())
}

#[cfg(not(feature = "std"))]
fn bytes_chunk_to_field(bytes: &[u8]) -> F {
    // Same result as the BigUint version but using u128 arithmetic.
    // Input is at most 17 bytes (ceil(127/8) + 1 = 17), fits in 136 bits.
    let mut lo = 0u128;
    let mut hi = 0u128;
    for (i, &byte) in bytes.iter().enumerate() {
        if i < 16 {
            lo |= (byte as u128) << (8 * i);
        } else {
            hi |= (byte as u128) << (8 * (i - 16));
        }
    }
    // Reduce mod p = 2^127 - 1.
    // 2^128 ≡ 2 (mod p), 2^127 ≡ 1 (mod p)
    let p = FIELD_MODULUS;
    let mut reduced = (lo & p) + (lo >> 127) + 2 * hi;
    while reduced >= p {
        reduced = (reduced & p) + (reduced >> 127);
    }
    if reduced == p {
        reduced = 0;
    }
    F::new(reduced)
}

fn get_powers() -> (u128, u128) {
    for d in 3..256 {
        if gcd_u128(d, FIELD_MODULUS - 1) == 1 {
            let inv = mod_inverse(d as i128, (FIELD_MODULUS - 1) as i128);
            return (d as u128, inv as u128);
        }
    }
    (5, 0)
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let tmp = b;
        b = a % b;
        a = tmp;
    }
    a
}

fn mod_inverse(a: i128, modulus: i128) -> i128 {
    let (mut t, mut new_t) = (0i128, 1i128);
    let (mut r, mut new_r) = (modulus, a.rem_euclid(modulus));
    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }
    if t < 0 {
        t += modulus;
    }
    t
}

#[cfg(feature = "std")]
fn get_number_of_rounds(d: u128) -> usize {
    let target = BigUint::one() << (SECURITY_LEVEL / 2);
    let mut rgb = 1usize;
    loop {
        let left = binomial(
            rgb * (d as usize + STATE_WIDTH) + 1,
            1 + STATE_WIDTH * rgb,
        );
        let right = binomial(
            (d as usize).pow(rgb as u32) + 1 + rgb,
            1 + rgb,
        );
        if min(left.clone(), right.clone()) >= target {
            break;
        }
        rgb += 1;
        if rgb > 25 {
            break;
        }
    }
    let base = (rgb + 1).max(6);
    ((base as f64 * 1.2).ceil()) as usize
}

#[cfg(not(feature = "std"))]
fn get_number_of_rounds(d: u128) -> usize {
    // Same algorithm as the BigUint version, but using u128 saturating arithmetic.
    // binomial values that exceed u128::MAX are treated as >= target.
    let target = 1u128 << (SECURITY_LEVEL / 2); // 2^64
    let mut rgb = 1usize;
    loop {
        let left = binomial_u128(
            rgb * (d as usize + STATE_WIDTH) + 1,
            1 + STATE_WIDTH * rgb,
        );
        let right = binomial_u128(
            (d as usize).pow(rgb as u32) + 1 + rgb,
            1 + rgb,
        );
        if min(left, right) >= target {
            break;
        }
        rgb += 1;
        if rgb > 25 {
            break;
        }
    }
    let base = (rgb + 1).max(6);
    // (base * 1.2) rounded up
    (base * 6 + 4) / 5
}

#[cfg(feature = "std")]
fn binomial(n: usize, k: usize) -> BigUint {
    if k == 0 || k == n {
        return BigUint::one();
    }
    let k = min(k, n - k);
    let mut numerator = BigUint::one();
    let mut denominator = BigUint::one();
    for i in 0..k {
        numerator *= BigUint::from((n - i) as u64);
        denominator *= BigUint::from((i + 1) as u64);
    }
    numerator / denominator
}

#[cfg(not(feature = "std"))]
fn binomial_u128(n: usize, k: usize) -> u128 {
    if k == 0 || k == n {
        return 1;
    }
    let k = min(k, n - k);
    let mut result = 1u128;
    for i in 0..k {
        result = result.saturating_mul((n - i) as u128) / ((i + 1) as u128);
    }
    result
}

fn build_matrix() -> [[F; STATE_WIDTH]; STATE_WIDTH] {
    // Simple circulant MDS-like matrix. For STATE_WIDTH=4, this is I + J (diagonal 2, off-diagonal 1),
    // which is invertible over our field since 5 ≠ 0 mod p.
    circulant([F::new(2), F::new(1), F::new(1), F::new(1)])
}

fn circulant(first_row: [F; STATE_WIDTH]) -> [[F; STATE_WIDTH]; STATE_WIDTH] {
    let mut matrix = [[F::zero(); STATE_WIDTH]; STATE_WIDTH];
    for row in 0..STATE_WIDTH {
        for col in 0..STATE_WIDTH {
            let idx = (row + col) % STATE_WIDTH;
            matrix[row][col] = first_row[idx];
        }
    }
    matrix
}
