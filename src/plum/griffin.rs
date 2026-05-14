//! Griffin algebraic hash function, re-instantiated for PLUM's `F_p192`.
//!
//! Mirrors the construction Loquat uses at `src/loquat/griffin.rs` — state
//! width 4, capacity 2, sponge mode, SHAKE256-derived round constants —
//! but parameterised over PLUM's 199-bit prime instead of the 127-bit
//! Mersenne. Two material differences from the Loquat instantiation:
//!
//!   - **S-box exponent `d` = 3**, not 5. The Griffin construction picks
//!     the smallest integer ≥ 3 with `gcd(d, p-1) = 1`. For the Mersenne
//!     prime that's 5; for our 199-bit prime that's 3.
//!   - **`d_inv` is a 199-bit `BigUint`**, not a `u128`. The inverse-S-box
//!     therefore raises through `Fp192::pow_biguint`.
//!
//! Round count is computed by the same Griffin-paper security argument as
//! Loquat's (`get_number_of_rounds`), scaled for the new `d`. Empirically
//! this lands a few rounds higher than Loquat's 11.
//!
//! ## Instrumentation
//!
//! `PLUM_GRIFFIN_PERM_COUNT` increments on every full permutation call.
//! Parallels Loquat's `GRIFFIN_PERM_COUNT` and is the counter the
//! zkVM-attribution measurement reads.

use core::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::cmp::{max, min};
use std::vec::Vec;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use once_cell::sync::Lazy;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update as Sha3Update, XofReader},
};

use super::field_p192::{Fp192, MODULUS_BITS};

/// Counter incremented on every full Griffin permutation. Mirrors
/// `loquat::griffin::GRIFFIN_PERM_COUNT` from the Loquat side.
pub static PLUM_GRIFFIN_PERM_COUNT: AtomicU64 = AtomicU64::new(0);

pub const PLUM_GRIFFIN_STATE_WIDTH: usize = 4;
pub const PLUM_GRIFFIN_CAPACITY: usize = 2;
pub const PLUM_GRIFFIN_RATE: usize = PLUM_GRIFFIN_STATE_WIDTH - PLUM_GRIFFIN_CAPACITY;
pub const PLUM_GRIFFIN_SECURITY_LEVEL: usize = 128;
/// Number of output field elements per `griffin_hash` call. Two 199-bit
/// elements → 64-byte digest after `field_elements_to_bytes`.
pub const PLUM_GRIFFIN_DIGEST_ELEMENTS: usize = 2;
/// Bytes per field element in the canonical byte serialisation.
const FIELD_BYTES: usize = 32;
/// Bytes consumed per absorb step. We pack 24 bytes (192 bits) per field
/// element; 192 < 199, so the value is always canonical (< p) without
/// rejection.
const ABSORB_BYTES_PER_ELEM: usize = 24;

#[derive(Clone, Debug)]
pub struct PlumGriffinParams {
    pub matrix: [[Fp192; PLUM_GRIFFIN_STATE_WIDTH]; PLUM_GRIFFIN_STATE_WIDTH],
    pub round_constants: Vec<Fp192>,
    pub alphas: Vec<Fp192>,
    pub betas: Vec<Fp192>,
    pub rounds: usize,
    pub d: u64,
    pub d_inv: BigUint,
}

#[derive(Clone, Debug)]
pub struct PlumGriffinState {
    lanes: [Fp192; PLUM_GRIFFIN_STATE_WIDTH],
}

impl PlumGriffinState {
    pub fn new() -> Self {
        Self {
            lanes: core::array::from_fn(|_| Fp192::zero()),
        }
    }

    pub fn from_lanes(lanes: [Fp192; PLUM_GRIFFIN_STATE_WIDTH]) -> Self {
        Self { lanes }
    }

    pub fn lanes(&self) -> &[Fp192; PLUM_GRIFFIN_STATE_WIDTH] {
        &self.lanes
    }

    pub fn into_lanes(self) -> [Fp192; PLUM_GRIFFIN_STATE_WIDTH] {
        self.lanes
    }
}

impl Default for PlumGriffinState {
    fn default() -> Self {
        Self::new()
    }
}

static PLUM_GRIFFIN_PARAMS: Lazy<PlumGriffinParams> = Lazy::new(compute_plum_griffin_params);

pub fn plum_griffin_params() -> &'static PlumGriffinParams {
    &PLUM_GRIFFIN_PARAMS
}

/// Hash a byte string to a 64-byte digest (2 × Fp192 elements).
pub fn plum_griffin_hash(data: &[u8]) -> Vec<u8> {
    let params = plum_griffin_params();
    let elements = bytes_to_field_elements(data);
    let outputs = plum_griffin_sponge(params, elements, PLUM_GRIFFIN_DIGEST_ELEMENTS);
    field_elements_to_bytes(&outputs)
}

/// Sponge construction: absorb `inputs`, squeeze `output_len` elements.
pub fn plum_griffin_sponge(
    params: &PlumGriffinParams,
    mut inputs: Vec<Fp192>,
    output_len: usize,
) -> Vec<Fp192> {
    let mut state = PlumGriffinState::new();

    // Padding: append a "1" element and zero-fill to a multiple of RATE.
    if inputs.len() % PLUM_GRIFFIN_RATE != 0 {
        state.lanes[PLUM_GRIFFIN_RATE] = Fp192::one();
        inputs.push(Fp192::one());
    }
    while inputs.len() % PLUM_GRIFFIN_RATE != 0 {
        inputs.push(Fp192::zero());
    }

    let mut absorb_idx = 0;
    while absorb_idx < inputs.len() {
        for lane in 0..PLUM_GRIFFIN_RATE {
            state.lanes[lane] = state.lanes[lane].clone() + inputs[absorb_idx].clone();
            absorb_idx += 1;
        }
        plum_griffin_permutation(params, &mut state);
    }

    let mut outputs = Vec::with_capacity(output_len);
    let mut squeeze_idx = 0;
    loop {
        for lane in 0..PLUM_GRIFFIN_RATE {
            outputs.push(state.lanes[lane].clone());
            squeeze_idx += 1;
            if squeeze_idx == output_len {
                return outputs;
            }
        }
        plum_griffin_permutation(params, &mut state);
    }
}

/// One full Griffin permutation. Increments `PLUM_GRIFFIN_PERM_COUNT`.
pub fn plum_griffin_permutation(params: &PlumGriffinParams, state: &mut PlumGriffinState) {
    PLUM_GRIFFIN_PERM_COUNT.fetch_add(1, AtomicOrdering::Relaxed);

    for r in 0..params.rounds - 1 {
        nonlinear_layer(params, state);
        linear_layer(params, state);
        additive_constants_layer(params, state, r);
    }
    nonlinear_layer(params, state);
    linear_layer(params, state);
}

/// Raw-array entry point — same shape as `loquat::griffin::griffin_permutation_raw`.
pub fn plum_griffin_permutation_raw(lanes: &mut [Fp192; PLUM_GRIFFIN_STATE_WIDTH]) {
    let params = plum_griffin_params();
    let mut state = PlumGriffinState {
        lanes: lanes.clone(),
    };
    plum_griffin_permutation(params, &mut state);
    *lanes = state.lanes;
}

fn nonlinear_layer(params: &PlumGriffinParams, state: &mut PlumGriffinState) {
    // Lane 0: inverse S-box (raise to d_inv).
    state.lanes[0] = state.lanes[0].pow_biguint(&params.d_inv);
    // Lane 1: forward S-box (raise to d).
    state.lanes[1] = state.lanes[1].pow_u128(params.d as u128);

    // Lanes 2..STATE_WIDTH: quadratic factor on a linear combination.
    let l_first = li(&state.lanes[0], &state.lanes[1], &Fp192::zero(), 2);
    state.lanes[2] = state.lanes[2].clone()
        * (l_first.clone() * l_first.clone()
            + params.alphas[0].clone() * l_first
            + params.betas[0].clone());

    for idx in 3..PLUM_GRIFFIN_STATE_WIDTH {
        let l = li(
            &state.lanes[0],
            &state.lanes[1],
            &state.lanes[idx - 1],
            idx,
        );
        state.lanes[idx] = state.lanes[idx].clone()
            * (l.clone() * l.clone()
                + params.alphas[idx - 2].clone() * l
                + params.betas[idx - 2].clone());
    }
}

fn linear_layer(params: &PlumGriffinParams, state: &mut PlumGriffinState) {
    let mut next: [Fp192; PLUM_GRIFFIN_STATE_WIDTH] =
        core::array::from_fn(|_| Fp192::zero());
    for row in 0..PLUM_GRIFFIN_STATE_WIDTH {
        for col in 0..PLUM_GRIFFIN_STATE_WIDTH {
            next[row] = next[row].clone()
                + params.matrix[row][col].clone() * state.lanes[col].clone();
        }
    }
    state.lanes = next;
}

fn additive_constants_layer(
    params: &PlumGriffinParams,
    state: &mut PlumGriffinState,
    round: usize,
) {
    for lane in 0..PLUM_GRIFFIN_STATE_WIDTH {
        state.lanes[lane] = state.lanes[lane].clone()
            + params.round_constants[round * PLUM_GRIFFIN_STATE_WIDTH + lane].clone();
    }
}

fn li(z0: &Fp192, z1: &Fp192, z2: &Fp192, i: usize) -> Fp192 {
    Fp192::from_u64((i - 1) as u64) * z0.clone() + z1.clone() + z2.clone()
}

// ---------------------------------------------------------------------------
// Byte ↔ field conversion (sponge I/O)
// ---------------------------------------------------------------------------

fn bytes_to_field_elements(bytes: &[u8]) -> Vec<Fp192> {
    if bytes.is_empty() {
        return std::vec![Fp192::zero()];
    }
    let mut elems = Vec::with_capacity(bytes.len().div_ceil(ABSORB_BYTES_PER_ELEM));
    let mut chunk = [0u8; ABSORB_BYTES_PER_ELEM];
    let mut chunk_len = 0usize;
    for &byte in bytes {
        chunk[chunk_len] = byte;
        chunk_len += 1;
        if chunk_len == ABSORB_BYTES_PER_ELEM {
            elems.push(absorb_chunk_to_field(&chunk));
            chunk = [0u8; ABSORB_BYTES_PER_ELEM];
            chunk_len = 0;
        }
    }
    if chunk_len > 0 {
        elems.push(absorb_chunk_to_field(&chunk));
    }
    elems
}

fn absorb_chunk_to_field(chunk: &[u8; ABSORB_BYTES_PER_ELEM]) -> Fp192 {
    // 24 bytes → 192-bit value. Always < p (since p > 2^198), no rejection.
    let mut bytes = [0u8; FIELD_BYTES];
    bytes[..ABSORB_BYTES_PER_ELEM].copy_from_slice(chunk);
    Fp192::from_bytes_le(&bytes).expect("absorb chunk should always fit in F_p192")
}

fn field_elements_to_bytes(elements: &[Fp192]) -> Vec<u8> {
    let mut out = Vec::with_capacity(elements.len() * FIELD_BYTES);
    for elem in elements {
        out.extend_from_slice(&elem.to_bytes_le());
    }
    out
}

// ---------------------------------------------------------------------------
// Parameter derivation (SHAKE256 seed, Griffin paper bounds)
// ---------------------------------------------------------------------------

fn compute_plum_griffin_params() -> PlumGriffinParams {
    let (d, d_inv) = pick_d_and_inverse();
    let rounds = get_number_of_rounds(d);

    // Bytes per field element from the SHAKE seed. The Loquat version
    // uses `((127 + 7) / 8) + 1 = 17`. We use `((199 + 7) / 8) + 1 = 26`
    // for the same safety margin (extra byte makes the reduction land
    // uniformly modulo p).
    let bytes_per_elem = MODULUS_BITS.div_ceil(8) + 1;
    let num_elements = PLUM_GRIFFIN_STATE_WIDTH * (rounds - 1) + 2;

    let mut shake = Shake256::default();
    Sha3Update::update(
        &mut shake,
        format!(
            "PlumGriffin({},{},{},{})",
            Fp192::modulus(),
            PLUM_GRIFFIN_STATE_WIDTH,
            PLUM_GRIFFIN_CAPACITY,
            PLUM_GRIFFIN_SECURITY_LEVEL,
        )
        .as_bytes(),
    );
    let mut reader = shake.finalize_xof();
    let mut buf = std::vec![0u8; bytes_per_elem * num_elements];
    XofReader::read(&mut reader, &mut buf);

    let mut offset = 0usize;
    let alpha = bytes_chunk_to_field(&buf[offset..offset + bytes_per_elem]);
    offset += bytes_per_elem;
    let beta = bytes_chunk_to_field(&buf[offset..offset + bytes_per_elem]);
    offset += bytes_per_elem;

    let alpha_count = max(1usize, PLUM_GRIFFIN_STATE_WIDTH.saturating_sub(2));
    let mut alphas = Vec::with_capacity(alpha_count);
    let mut betas = Vec::with_capacity(alpha_count);
    alphas.push(alpha.clone());
    betas.push(beta.clone());
    for i in 3..PLUM_GRIFFIN_STATE_WIDTH {
        alphas.push(Fp192::from_u64((i - 1) as u64) * alpha.clone());
        betas.push(Fp192::from_u64(((i - 1) * (i - 1)) as u64) * beta.clone());
    }

    let mut round_constants =
        Vec::with_capacity(PLUM_GRIFFIN_STATE_WIDTH * (rounds - 1));
    while round_constants.len() < PLUM_GRIFFIN_STATE_WIDTH * (rounds - 1) {
        let elem = bytes_chunk_to_field(&buf[offset..offset + bytes_per_elem]);
        round_constants.push(elem);
        offset += bytes_per_elem;
    }

    PlumGriffinParams {
        matrix: build_matrix(),
        round_constants,
        alphas,
        betas,
        rounds,
        d,
        d_inv,
    }
}

fn bytes_chunk_to_field(bytes: &[u8]) -> Fp192 {
    let acc = BigUint::from_bytes_le(bytes);
    Fp192::from_biguint(acc)
}

fn pick_d_and_inverse() -> (u64, BigUint) {
    let pm1 = Fp192::modulus() - 1u32;
    for d in 3u64..256 {
        if gcd_biguint(&BigUint::from(d), &pm1) == BigUint::one() {
            let d_inv = modular_inverse(d, &pm1);
            return (d, d_inv);
        }
    }
    panic!("PLUM Griffin: no small d coprime to p-1 found");
}

fn gcd_biguint(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let r = &a % &b;
        a = b;
        b = r;
    }
    a
}

/// Extended Euclidean algorithm: find x such that d · x ≡ 1 (mod n).
fn modular_inverse(d: u64, n: &BigUint) -> BigUint {
    // Work over signed BigInts (num-bigint provides BigInt but we don't
    // depend on it here; reuse BigUint arithmetic and track sign via flag.)
    // Iterative extended Euclidean over the pair (n, d).
    use num_bigint::BigInt;
    use num_traits::Signed;

    let n_int = BigInt::from(n.clone());
    let mut t = BigInt::from(0);
    let mut new_t = BigInt::from(1);
    let mut r = n_int.clone();
    let mut new_r = BigInt::from(d);
    while !new_r.is_zero() {
        let q = &r / &new_r;
        let next_t = &t - &q * &new_t;
        t = std::mem::replace(&mut new_t, next_t);
        let next_r = &r - &q * &new_r;
        r = std::mem::replace(&mut new_r, next_r);
    }
    if t.is_negative() {
        t += &n_int;
    }
    t.to_biguint()
        .expect("modular_inverse: result should be non-negative")
}

fn get_number_of_rounds(d: u64) -> usize {
    let target = BigUint::one() << (PLUM_GRIFFIN_SECURITY_LEVEL / 2);
    let mut rgb = 1usize;
    loop {
        let left = binomial(
            rgb * (d as usize + PLUM_GRIFFIN_STATE_WIDTH) + 1,
            1 + PLUM_GRIFFIN_STATE_WIDTH * rgb,
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

fn build_matrix() -> [[Fp192; PLUM_GRIFFIN_STATE_WIDTH]; PLUM_GRIFFIN_STATE_WIDTH] {
    // Same circulant `[2, 1, 1, 1]` as Loquat (= I + J, MDS over our field
    // since the determinant 5 is nonzero mod p).
    circulant([
        Fp192::from_u64(2),
        Fp192::from_u64(1),
        Fp192::from_u64(1),
        Fp192::from_u64(1),
    ])
}

fn circulant(
    first_row: [Fp192; PLUM_GRIFFIN_STATE_WIDTH],
) -> [[Fp192; PLUM_GRIFFIN_STATE_WIDTH]; PLUM_GRIFFIN_STATE_WIDTH] {
    let mut matrix: [[Fp192; PLUM_GRIFFIN_STATE_WIDTH]; PLUM_GRIFFIN_STATE_WIDTH] =
        core::array::from_fn(|_| core::array::from_fn(|_| Fp192::zero()));
    for row in 0..PLUM_GRIFFIN_STATE_WIDTH {
        for col in 0..PLUM_GRIFFIN_STATE_WIDTH {
            let idx = (row + col) % PLUM_GRIFFIN_STATE_WIDTH;
            matrix[row][col] = first_row[idx].clone();
        }
    }
    matrix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_have_expected_shape() {
        let params = plum_griffin_params();
        assert_eq!(params.matrix.len(), PLUM_GRIFFIN_STATE_WIDTH);
        assert_eq!(params.alphas.len(), max(1, PLUM_GRIFFIN_STATE_WIDTH - 2));
        assert_eq!(params.betas.len(), max(1, PLUM_GRIFFIN_STATE_WIDTH - 2));
        assert_eq!(
            params.round_constants.len(),
            PLUM_GRIFFIN_STATE_WIDTH * (params.rounds - 1)
        );
        assert!(params.rounds >= 6, "round count looks too low");
    }

    #[test]
    fn d_and_d_inv_invert_modulo_p_minus_1() {
        let params = plum_griffin_params();
        let pm1 = Fp192::modulus() - 1u32;
        let lhs = (&params.d_inv * BigUint::from(params.d)) % &pm1;
        assert_eq!(lhs, BigUint::one());
    }

    #[test]
    fn d_is_three_for_plum_prime() {
        // Loquat picks d=5 for the Mersenne; PLUM's prime admits d=3.
        // Document this explicitly so future parameter tweaks notice.
        let params = plum_griffin_params();
        assert_eq!(params.d, 3);
    }

    #[test]
    fn permutation_is_deterministic() {
        let params = plum_griffin_params();
        let mut state_a = PlumGriffinState {
            lanes: core::array::from_fn(|i| Fp192::from_u64(i as u64 + 1)),
        };
        let mut state_b = state_a.clone();
        plum_griffin_permutation(params, &mut state_a);
        plum_griffin_permutation(params, &mut state_b);
        assert_eq!(state_a.lanes, state_b.lanes);
    }

    #[test]
    fn permutation_changes_state() {
        let params = plum_griffin_params();
        let mut state = PlumGriffinState {
            lanes: core::array::from_fn(|i| Fp192::from_u64(i as u64 + 1)),
        };
        let before = state.lanes.clone();
        plum_griffin_permutation(params, &mut state);
        assert_ne!(state.lanes, before);
    }

    #[test]
    fn hash_is_deterministic() {
        let data = b"PLUM Griffin test message";
        let h1 = plum_griffin_hash(data);
        let h2 = plum_griffin_hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), PLUM_GRIFFIN_DIGEST_ELEMENTS * FIELD_BYTES);
    }

    #[test]
    fn hash_input_difference_changes_output() {
        let h1 = plum_griffin_hash(b"hello");
        let h2 = plum_griffin_hash(b"hellp");
        assert_ne!(h1, h2);
    }

    #[test]
    fn perm_counter_ticks_once_per_permutation() {
        let params = plum_griffin_params();
        let mut state = PlumGriffinState::new();
        let before = PLUM_GRIFFIN_PERM_COUNT.load(AtomicOrdering::Relaxed);
        plum_griffin_permutation(params, &mut state);
        plum_griffin_permutation(params, &mut state);
        plum_griffin_permutation(params, &mut state);
        let after = PLUM_GRIFFIN_PERM_COUNT.load(AtomicOrdering::Relaxed);
        assert!(after >= before + 3, "expected at least 3 increments");
    }

    #[test]
    fn raw_permutation_matches_struct_permutation() {
        let params = plum_griffin_params();
        let initial: [Fp192; PLUM_GRIFFIN_STATE_WIDTH] =
            core::array::from_fn(|i| Fp192::from_u64((i as u64) * 31 + 7));

        let mut via_struct = PlumGriffinState {
            lanes: initial.clone(),
        };
        plum_griffin_permutation(params, &mut via_struct);

        let mut via_raw = initial;
        plum_griffin_permutation_raw(&mut via_raw);

        assert_eq!(via_struct.lanes, via_raw);
    }
}
