//! Stage 4c-2: in-circuit Fiat–Shamir challenge derivation for PLUM, replayed
//! with the GRIFFIN sponge instead of SHAKE256.
//!
//! The Rust transcript (`src/signatures/plum/transcript.rs`) derives every
//! challenge as `SHAKE256(state ‖ "squeeze:" ‖ squeeze_counter ‖ label)` over a
//! byte-serialised running state, then rejection-samples the bytes down to a
//! field element (`challenge_field`) or a bounded index (`challenge_index`).
//! That construction is circuit-hostile: SHAKE256 over a byte string is a
//! Keccak permutation per squeeze, and the rejection loop is a byte-level mask.
//!
//! This module ships the algebraic replacement the circuit baseline consumes:
//!
//!   - [`griffin_fs_challenge_field`] / [`griffin_fs_challenge_index`] — the
//!     SOFTWARE Griffin-FS reference. Same absorb ORDER, same label/counter
//!     discipline as `transcript.rs`; only the underlying hash changes from
//!     SHAKE256 to the Griffin sponge (`plum_griffin_sponge`). Absorbed data is
//!     a vector of `Fp192` field elements (roots are Griffin digests, already
//!     field elements), absorbed DIRECTLY — no byte serialisation.
//!   - [`griffin_fs_challenge_field_circuit`] / [`griffin_fs_challenge_index_circuit`]
//!     — the R1CS gadget that derives the SAME challenge from the absorbed-data
//!     WIRES, binding the challenge to the committed data and constraining the
//!     rejection-sampling witness.
//!
//! ## Griffin-FS transcript spec (the intended modeling — read before auditing)
//!
//! This gadget is a DELIBERATE, documented re-modeling of PLUM's Fiat–Shamir
//! transcript, not a byte-compatible re-implementation. Three things are
//! intentional and MUST NOT be "fixed" into SHAKE-byte compatibility:
//!
//!   1. **Absorb ORDER mirrors `verify.rs:196-223` exactly.** The software
//!      reference and the circuit gadget absorb the committed data in the same
//!      sequence the verifier replays: `M`, `root_c`, `T`, then
//!      `challenge_indices(phase2/indices)`, `o_responses`,
//!      `challenge_fields(phase3/lambda/j)` for each `j`,
//!      `challenge_fields(phase3/epsilon)`, `root_s`, `s_sum`,
//!      `challenge_field(phase4/z)`, `root_h`, `challenge_field(phase5/r)`,
//!      `challenge_field(phase5/r0_fold)`, query indices. Each challenge here is
//!      derived from the running absorbed-data vector `D` plus the
//!      (tag, squeeze_counter, attempt) counter block. The ORDER is the
//!      load-bearing transcript invariant; the gadget preserves it.
//!   2. **The hash is deliberately swapped SHAKE256 → Griffin.** PLUM's software
//!      transcript (`transcript.rs:77-86`) is `SHAKE256(state ‖ ctr ‖ label)`
//!      over a byte serialisation. That is circuit-hostile (a Keccak permutation
//!      per squeeze). This module replaces it with the Griffin sponge
//!      (`plum_griffin_sponge`). This is a MODEL CHANGE, justified by Griffin
//!      being the in-circuit hash; it is NOT an attempt to reproduce SHAKE bytes.
//!   3. **Field-element absorbs + integer tags are the intended modeling, NOT
//!      byte-SHAKE compat.** Roots are Griffin digests (already `Fp192`), so they
//!      are absorbed directly as field elements; the domain-separation `label`
//!      and counters become small integer field elements (`FS_TAG_*`,
//!      `squeeze_counter`, `attempt`). There is NO byte serialisation and NO
//!      attempt to match `transcript.rs`'s little-endian byte layout. The
//!      counter DISCIPLINE (monotone squeeze counter, per-attempt rejection
//!      counter) is mirrored; the byte ENCODING is not.
//!
//! Attempt caps are aligned to `transcript.rs`: `MAX_ATTEMPTS_FIELD = 64`
//! mirrors `transcript.rs:106` (`counter > 64`) and `MAX_ATTEMPTS_INDEX = 128`
//! mirrors `transcript.rs:150` (`counter > 128`). The circuit `challenge_field`
//! gadget likewise caps field attempts at 64.
//!
//! ## Squeeze model (faithful to transcript.rs, Griffin-native)
//!
//! For a derivation with absorbed field elements `D = [d_0, …, d_{n-1}]`, a
//! domain-separation tag `tag` (a small integer label id), a monotone global
//! `squeeze_counter` `s`, and a per-attempt rejection counter `c`, the
//! candidate at attempt `c` is:
//!
//!   ```text
//!   e_c   = plum_griffin_sponge( D ‖ [TAG, s, c], 1 )[0]      // one Fp192
//!   cand  = e_c  mod  2^w                                     // low w bits
//!   ```
//!
//! mirroring `transcript.rs`'s "squeeze 25/needed bytes, mask, interpret as an
//! integer candidate". `TAG`, `s`, `c` are absorbed as field elements, so two
//! successive challenges (different `s`) and two successive attempts (different
//! `c`) draw independent sponge outputs — exactly the counter discipline of
//! `squeeze_bytes` (`transcript.rs:77-86`) and the per-attempt `counter` of
//! `challenge_field` / `challenge_index` (`transcript.rs:96-110`, `137-157`).
//!
//!   - **`challenge_field`** (`transcript.rs:90-110`): window `w = MODULUS_BITS`
//!     (= 199), accept `cand` iff `cand < p`. NB: the Griffin sponge codomain is
//!     already `[0, p)`, so `cand = e_c mod 2^199 = e_c < p` ALWAYS for our
//!     sponge; honest field-challenge rejection count is therefore 0. The
//!     `cand < p` constraint on the accepted candidate is still enforced and is
//!     the load-bearing soundness content (a malicious prover may not present an
//!     out-of-range "accepted" value). Genuine multi-attempt rejection is
//!     exercised by the index sampler below.
//!   - **`challenge_index`** (`transcript.rs:125-157`): `pow = next_pow2(bound)`,
//!     `w = log2(pow)`, `cand = e_c mod pow` (the low `w` bits), accept iff
//!     `cand < bound`. When `bound` is not a power of two, a real fraction of
//!     candidates land in `[bound, pow)` and are rejected — the genuine
//!     rejection-sampling case.
//!
//! ## Two soundness traps (both handled; see the gate tests)
//!
//! 1. **Challenges bound to absorbed data.** The challenge wire is the sponge
//!    output over the absorbed-data WIRES `D` and the (constant) counter wires;
//!    it is NOT a free witness. `griffin_fp192_sponge_circuit` constrains the
//!    full permutation chain, so a prover cannot choose a challenge independent
//!    of `D`. The gate's `*_challenge_not_bound_fails` test corrupts the claimed
//!    challenge and shows a constraint breaks.
//! 2. **Rejection sampling without a loop.** A fixed circuit cannot loop until
//!    accept. We witness the rejection count `r` (number of rejected attempts)
//!    and, for each attempt `c = 0..=r`, re-derive `e_c` in-circuit and split
//!    `e_c`'s low-`w`-bit candidate via a constrained bit decomposition. For
//!    `c < r` (rejected) we constrain `cand_c >= B`; for `c = r` (accepted) we
//!    constrain `cand_r < B`. A prover that skips a valid earlier candidate
//!    (claims it rejected when `cand < B`) fails the `cand_c >= B` constraint.
//!
//! The range argument is a bit decomposition: `cand` is decomposed into `w`
//! boolean wires (`Σ b_k 2^k`, each `b*b=b`), and the comparison `cand </>= B`
//! is enforced by witnessing `B - 1 - cand` (accepted) / `cand - B` (rejected)
//! as a non-negative `w`-bit value, itself bit-decomposed. Because every value
//! involved is `< 2^w <= 2^MODULUS_BITS < p`, the `w`-bit decomposition is a
//! true integer-range proof (no field wraparound): a `w`-bit number and its
//! complement against `B` cannot both fit unless the claimed ordering holds.

use crate::primitives::field::p192::{Fp192, MODULUS_BITS};
use crate::primitives::hash::griffin_p192::{
    plum_griffin_params, plum_griffin_sponge, PlumGriffinParams,
};
use crate::primitives::r1cs::griffin_fp192_gadget::{
    Fp192R1cs, Fp192R1csBuilder, Fp192Var,
};
use crate::primitives::r1cs::sponge_fp192_gadget::griffin_fp192_sponge_circuit;
use num_bigint::BigUint;

/// Domain-separation tag ids for the two challenge kinds, absorbed as the first
/// counter-block element. Mirrors the distinct `label` arguments in
/// `transcript.rs` (here reduced to a stable integer so the gadget and the
/// software reference agree on the absorbed value bit-for-bit).
pub const FS_TAG_FIELD: u64 = 0x46_49_45_4c_44; // "FIELD"
pub const FS_TAG_INDEX: u64 = 0x49_4e_44_45_58; // "INDEX"

/// Safety cap on honest rejection attempts for `challenge_field`. Mirrors the
/// `counter > 64` cap in `transcript.rs:106`. Honest field derivations accept
/// on attempt 0 (the Griffin codomain is already `[0,p)`), so this is never hit.
const MAX_ATTEMPTS_FIELD: u64 = 64;
/// Safety cap on honest rejection attempts for `challenge_index`. Mirrors the
/// `counter > 128` cap in `transcript.rs:150`.
const MAX_ATTEMPTS_INDEX: u64 = 128;

// ===========================================================================
// (a) SOFTWARE Griffin-FS reference
// ===========================================================================

/// Result of a software Griffin-FS derivation: the accepted challenge plus the
/// rejection witness the gadget needs to reproduce (number of rejected attempts
/// and the raw squeezed sponge element per attempt `c = 0..=rejections`).
#[derive(Clone, Debug)]
pub struct FsChallengeTrace {
    /// Accepted challenge value (a field element; for an index it is the
    /// accepted index embedded in `Fp192`).
    pub value: Fp192,
    /// Number of rejected attempts before acceptance (`r`); the accepted
    /// attempt is index `r`.
    pub rejections: u64,
    /// Raw squeezed sponge element `e_c` for every attempt `c = 0..=r`.
    pub squeezed: Vec<Fp192>,
    /// Window width `w` (candidate = `e_c mod 2^w`).
    pub window_bits: usize,
    /// Acceptance bound `B` (candidate accepted iff `< B`).
    pub bound: BigUint,
}

/// Squeeze one Fp192 element for attempt `c` of a derivation, matching the
/// Griffin-native squeeze model documented above:
/// `plum_griffin_sponge(absorbed ‖ [tag, squeeze_counter, c], 1)[0]`.
fn squeeze_once(
    params: &PlumGriffinParams,
    absorbed: &[Fp192],
    tag: u64,
    squeeze_counter: u64,
    attempt: u64,
) -> Fp192 {
    let mut inputs = Vec::with_capacity(absorbed.len() + 3);
    inputs.extend_from_slice(absorbed);
    inputs.push(Fp192::from_u64(tag));
    inputs.push(Fp192::from_u64(squeeze_counter));
    inputs.push(Fp192::from_u64(attempt));
    plum_griffin_sponge(params, inputs, 1).remove(0)
}

/// `value mod 2^w` as a BigUint (the low-`w`-bit candidate window).
fn low_window(value: &Fp192, w: usize) -> BigUint {
    let v = value.to_biguint();
    let modulus = BigUint::from(1u8) << w;
    v % modulus
}

/// SOFTWARE Griffin-FS `challenge_field`: mirrors `transcript.rs:90-110`.
/// Window `w = MODULUS_BITS`, accept iff `cand < p`. Returns the accepted
/// field element and the full rejection trace.
pub fn griffin_fs_challenge_field(
    absorbed: &[Fp192],
    squeeze_counter: u64,
) -> FsChallengeTrace {
    let params = plum_griffin_params();
    let w = MODULUS_BITS;
    let p = Fp192::modulus();
    let mut squeezed = Vec::new();
    let mut c = 0u64;
    loop {
        let e = squeeze_once(params, absorbed, FS_TAG_FIELD, squeeze_counter, c);
        squeezed.push(e.clone());
        let cand = low_window(&e, w);
        if cand < p {
            // cand == e (e < p), so the accepted challenge is e itself.
            return FsChallengeTrace {
                value: Fp192::from_biguint(cand),
                rejections: c,
                squeezed,
                window_bits: w,
                bound: p,
            };
        }
        c += 1;
        assert!(c < MAX_ATTEMPTS_FIELD, "challenge_field exceeded attempt cap");
    }
}

/// SOFTWARE Griffin-FS `challenge_index`: mirrors `transcript.rs:125-157`.
/// `pow = next_pow2(bound)`, window `w = log2(pow)`, accept iff `cand < bound`.
pub fn griffin_fs_challenge_index(
    absorbed: &[Fp192],
    squeeze_counter: u64,
    bound: usize,
) -> FsChallengeTrace {
    assert!(bound > 0, "challenge_index needs bound > 0");
    let params = plum_griffin_params();
    let pow = bound.next_power_of_two();
    let w = pow.trailing_zeros() as usize;
    let bound_big = BigUint::from(bound as u64);
    let mut squeezed = Vec::new();
    let mut c = 0u64;
    if bound == 1 {
        // Degenerate: w = 0, every candidate is 0 < 1. Single accepting attempt.
        let e = squeeze_once(params, absorbed, FS_TAG_INDEX, squeeze_counter, 0);
        squeezed.push(e);
        return FsChallengeTrace {
            value: Fp192::zero(),
            rejections: 0,
            squeezed,
            window_bits: 0,
            bound: bound_big,
        };
    }
    loop {
        let e = squeeze_once(params, absorbed, FS_TAG_INDEX, squeeze_counter, c);
        squeezed.push(e.clone());
        let cand = low_window(&e, w);
        if cand < bound_big {
            return FsChallengeTrace {
                value: Fp192::from_biguint(cand),
                rejections: c,
                squeezed,
                window_bits: w,
                bound: bound_big,
            };
        }
        c += 1;
        assert!(c < MAX_ATTEMPTS_INDEX, "challenge_index exceeded attempt cap");
    }
}

// ===========================================================================
// (b) R1CS gadget matching (a)
// ===========================================================================

/// In-circuit bit decomposition of the LOW `w` bits of `value`'s canonical
/// field representative, LSB first, each pinned `b*b=b`. Returns the bit wires
/// AND a wire equal to `Σ b_k 2^k` (the recomposed low-`w`-bit value), which the
/// caller binds to its source with an equality constraint.
///
/// CRITICAL for soundness: `value` is the canonical `[0,p)` representative of a
/// field element computed in-circuit (NOT an integer subtraction). When the
/// caller binds `recomposed == source`, the binding holds iff `source`'s field
/// representative is `< 2^w`. If a malicious witness makes `source` a field
/// element `>= 2^w` (e.g. a negative slack `≈ p`), no choice of `w` boolean bits
/// can recompose to it (`Σ b_k 2^k < 2^w <= 2^MODULUS_BITS < p`), so the
/// equality constraint fails. This is what makes the order check a genuine
/// integer-range proof with no field wraparound.
fn bit_decompose(
    builder: &mut Fp192R1csBuilder,
    value: &BigUint,
    w: usize,
) -> (Vec<Fp192Var>, Fp192Var) {
    let low = value & ((BigUint::from(1u8) << w) - BigUint::from(1u8));
    let mut bits = Vec::with_capacity(w);
    for k in 0..w {
        let bit = (&low >> k) & BigUint::from(1u8) == BigUint::from(1u8);
        bits.push(builder.alloc_bool_pub(bit));
    }
    // Recompose Σ b_k · 2^k by folding weighted bits. We build the weighted
    // sum with add_vars over scaled bit wires. Scaling a bit by 2^k uses a
    // mul against a constant wire.
    let recomposed = recompose_bits(builder, &bits);
    (bits, recomposed)
}

/// Σ_k bits[k] · 2^k as a single constrained wire.
fn recompose_bits(builder: &mut Fp192R1csBuilder, bits: &[Fp192Var]) -> Fp192Var {
    if bits.is_empty() {
        return builder.constant_pub(Fp192::zero());
    }
    // acc = Σ b_k 2^k via running add of (b_k * 2^k).
    let mut acc: Option<Fp192Var> = None;
    for (k, b) in bits.iter().enumerate() {
        let weight = builder.constant_pub(pow2(k));
        let term = builder.mul_pub(b, &weight); // b_k * 2^k
        acc = Some(match acc {
            None => term,
            Some(a) => builder.add_vars(&a, &term),
        });
    }
    acc.unwrap()
}

fn pow2(k: usize) -> Fp192 {
    Fp192::from_biguint(BigUint::from(1u8) << k)
}

/// Canonical extraction of the low `w` bits of the data-bound field element
/// `e_c`, with NO mod-`p` wraparound alternate.
///
/// ## The soundness hole this closes
///
/// The previous extraction witnessed `cand ∈ [0,2^w)` and `high` in
/// `MODULUS_BITS - w + 1 = 200 - w` bits and enforced `cand + high·2^w == e_c`
/// MOD p. Because `high·2^w` can reach `≈ 2^200 > p`, a SECOND decomposition
/// exists: take the integer `e_c + p` (`< 2p < 2^200`, equal to `e_c` mod p)
/// and split it as `cand_alt = (e_c+p) mod 2^w`, `high_alt = (e_c+p) div 2^w`.
/// Then `high_alt < 2^(200-w) = 2^(high_w)` fits the budget (the "+1 bit" was
/// exactly the wraparound budget), `cand_alt + high_alt·2^w == e_c (mod p)`
/// holds, yet `cand_alt != e_c mod 2^w`. A prover grinds the attempt counter to
/// bias the index challenge — the FS challenge stops being a function of the
/// committed data. `constrain_order` then certifies the forged candidate
/// honestly, so the old rejection tests miss it.
///
/// ## The fix: a UNIQUE sub-`p` representation
///
/// Decompose `e_c` into ALL `MODULUS_BITS` (= 199) boolean bits `b_0..b_198`,
/// enforce `Σ b_i·2^i == e_c`, AND enforce the bit-string is `< p` (a
/// lexicographic comparison against the constant bits of `p`, so no value
/// `>= p` is representable). Because `e_c ∈ [0,p)` has a UNIQUE 199-bit
/// representation under `< p`, there is exactly one bit assignment, hence
/// exactly one `cand = Σ_{i<w} b_i·2^i = e_c mod 2^w`. The `e_c + p` alternate
/// is unrepresentable (its 199-bit low part recomposes to `e_c + p - 2^199·…`
/// which is `>= p`, rejected by the `< p` gate). No `high` witness, no
/// wraparound budget, no alternate.
///
/// Returns `cand`, the wire equal to `e_c mod 2^w`.
fn canonical_low_window(
    builder: &mut Fp192R1csBuilder,
    e_c: &Fp192Var,
    w: usize,
) -> Fp192Var {
    let bits_source = e_c.value().to_biguint();
    canonical_low_window_with_bits_source(builder, e_c, w, &bits_source)
}

/// `canonical_low_window`, but the integer whose bits are WITNESSED is supplied
/// explicitly as `bits_source` (the honest path passes `e_c`'s value). A
/// malicious prover chooses `bits_source`; the constraints (full recomposition
/// `== e_c`, every `b*b=b`, and `< p`) are what force `bits_source ≡ e_c`'s
/// unique `[0,p)` representative. Injecting `bits_source = e_c + p` here is the
/// EXACT wraparound forgery the canonical extraction must reject — see the
/// `wraparound_forgery_rejected` test.
fn canonical_low_window_with_bits_source(
    builder: &mut Fp192R1csBuilder,
    e_c: &Fp192Var,
    w: usize,
    bits_source: &BigUint,
) -> Fp192Var {
    let e_big = bits_source.clone();
    // Full canonical bit decomposition over all MODULUS_BITS bits.
    let n = MODULUS_BITS;
    let mut bits = Vec::with_capacity(n);
    for k in 0..n {
        let bit = (&e_big >> k) & BigUint::from(1u8) == BigUint::from(1u8);
        bits.push(builder.alloc_bool_pub(bit));
    }
    // Bind the full recomposition Σ b_i·2^i to e_c (forces the bits to BE e_c's
    // integer value, with each b_i ∈ {0,1}). Since the field representative of
    // e_c is < p < 2^199, the full recomposition equals that representative.
    let recomposed = recompose_bits(builder, &bits);
    builder.enforce_eq_pub(&recomposed, e_c);
    // Enforce the bit-string is strictly < p, pinning e_c to its UNIQUE [0,p)
    // representation (eliminates the e_c+p wraparound alternate).
    enforce_bits_lt_modulus(builder, &bits);
    // cand = low w bits of the canonical decomposition.
    recompose_bits(builder, &bits[..w])
}

/// Enforce that the little-endian boolean wires `bits` (length `MODULUS_BITS`,
/// each already pinned `b*b=b`) encode an integer strictly less than the prime
/// modulus `p`. Standard lexicographic less-than against the CONSTANT bits of
/// `p`, MSB-first.
///
/// Idea: scan from the most-significant bit down. Maintain `gt`, a boolean wire
/// that is 1 once a more-significant position has had `b_i = 1` while `p_i = 0`
/// (i.e. the value already exceeded `p` in a higher position). At every
/// position where `p_i = 0` we must forbid `b_i = 1` UNLESS some strictly-higher
/// position already made the value smaller (`b_j = 0, p_j = 1`). The clean,
/// constraint-light encoding: track `eq_prefix` (all higher bits equal so far);
/// while `eq_prefix` holds, at a position with `p_i = 0` the bit `b_i` must be 0
/// (it cannot be 1, else value >= p with an equal prefix). A position with
/// `p_i = 1` may take `b_i ∈ {0,1}`; if `b_i = 0` the prefix is no longer equal
/// (value is now strictly smaller — all lower bits unconstrained).
///
/// `eq_prefix_{i}` = "bits strictly above i all equal p's bits". Recurrence
/// (MSB-first), with `eq_prefix` starting at 1:
///   - at p_i = 1: enforce nothing on b_i directly; next eq_prefix =
///     eq_prefix · b_i  (prefix stays equal only if b_i is also 1).
///   - at p_i = 0: enforce `eq_prefix · b_i == 0` (cannot set this bit while the
///     prefix is still equal); next eq_prefix = eq_prefix · (1 - b_i) =
///     eq_prefix (since b_i forced 0 under eq_prefix; but b_i may be 1 once
///     eq_prefix already 0, so use eq_prefix·(1-b_i) to stay correct).
///
/// This is sound: the value exceeds p iff at the first differing bit (MSB-first)
/// the value's bit is 1 and p's is 0. The constraint `eq_prefix·b_i == 0` at
/// every p_i = 0 position forbids exactly the strict-">" cases, since `eq_prefix`
/// is 1 precisely while no higher bit has gone strictly-smaller.
///
/// The all-equal case (value == p) is NOT forbidden by the per-position
/// constraints alone: matching p's 0-bit (b_i = 0 where p_i = 0) satisfies
/// `eq_prefix·b_i == 0` and KEEPS `eq_prefix = 1` (next eq_prefix =
/// eq_prefix·(1-b_i) = eq_prefix·1), so the bit-string equal to p drives
/// `eq_prefix` to 1 all the way down and passes every per-position check.
/// Matching a 0-bit does not make the value smaller — it keeps it equal.
/// Therefore a TERMINAL constraint `eq_prefix == 0` is required: it forces at
/// least one strictly-smaller divergence (b_j = 0 at some p_j = 1 position), so
/// the value is < p, never == p. `eq_prefix_final = 1` iff every bit matched p
/// iff value == p; constraining it to 0 excludes exactly that case and no
/// value < p (each of which already drives eq_prefix to 0 at its first
/// strict-below divergence). This completes the strict less-than check.
fn enforce_bits_lt_modulus(builder: &mut Fp192R1csBuilder, bits: &[Fp192Var]) {
    debug_assert_eq!(bits.len(), MODULUS_BITS, "expect full-width decomposition");
    let p = Fp192::modulus();
    // eq_prefix starts at the constant 1 (no higher bits yet, vacuously equal).
    let mut eq_prefix = builder.constant_pub(Fp192::one());
    let one = builder.constant_pub(Fp192::one());
    // MSB-first.
    for i in (0..MODULUS_BITS).rev() {
        let p_i = (&p >> i) & BigUint::from(1u8) == BigUint::from(1u8);
        let b_i = &bits[i];
        if p_i {
            // next eq_prefix = eq_prefix · b_i.
            eq_prefix = builder.mul_pub(&eq_prefix, b_i);
        } else {
            // Forbid b_i = 1 while still equal to the prefix: eq_prefix·b_i == 0.
            let prod = builder.mul_pub(&eq_prefix, b_i);
            let zero = builder.constant_pub(Fp192::zero());
            builder.enforce_eq_pub(&prod, &zero);
            // next eq_prefix = eq_prefix · (1 - b_i).
            let one_minus_b = builder.sub_vars(&one, b_i);
            eq_prefix = builder.mul_pub(&eq_prefix, &one_minus_b);
        }
    }
    // TERMINAL constraint: force a strict divergence so value == p is excluded.
    // After the loop, eq_prefix == 1 iff every bit matched p's bits (value == p);
    // for any value < p eq_prefix is already 0 (it dropped at the first p_j = 1,
    // b_j = 0 position). Constraining eq_prefix == 0 therefore rejects exactly
    // value == p and accepts every value < p. This completes the strict `< p`
    // check; without it the bit-string equal to p is admitted (the per-position
    // constraints alone do not force any strict-below divergence — see doc).
    let zero = builder.constant_pub(Fp192::zero());
    builder.enforce_eq_pub(&eq_prefix, &zero);
}

/// Constrain that the `w`-bit `cand` wire (already bit-decomposed and bound to
/// its source) satisfies `cand < bound` (`accept = true`) or `cand >= bound`
/// (`accept = false`), via a complementary `w`-bit non-negativity witness.
///
///   - accept:  witness `slack = bound - 1 - cand`, prove `slack` is a
///     non-negative `w`-bit value. `cand < bound  ⟺  bound-1-cand ∈ [0, 2^w)`.
///   - reject:  witness `slack = cand - bound`, prove `slack` is a
///     non-negative `w`-bit value. `cand >= bound  ⟺  cand-bound ∈ [0, 2^w)`.
///
/// The slack wire is computed in the FIELD first (never an integer
/// subtraction, so witness generation cannot panic on a malicious trace), then
/// its canonical representative is bit-decomposed to `w` bits and bound back to
/// the slack wire. An honest slack is `< 2^w` and the binding holds; a
/// malicious order claim makes the field slack `≈ p` (the negative wrapped to
/// `[0,p)`), which exceeds `2^w` and cannot match any `w`-bit recomposition, so
/// a constraint breaks. This is the genuine integer-range proof.
fn constrain_order(
    builder: &mut Fp192R1csBuilder,
    cand: &Fp192Var,
    _cand_value: &BigUint,
    bound: &BigUint,
    w: usize,
    accept: bool,
) {
    // slack wire, built with field ops:
    //   accept: slack = (bound - 1) - cand   (in field)
    //   reject: slack = cand - bound          (in field)
    let slack = if accept {
        let bm1 = builder.constant_pub(Fp192::from_biguint(bound - BigUint::from(1u8)));
        builder.sub_vars(&bm1, cand)
    } else {
        let bound_var = builder.constant_pub(Fp192::from_biguint(bound.clone()));
        builder.sub_vars(cand, &bound_var)
    };
    // Decompose the slack's canonical field representative to w bits and bind.
    // The decomposition uses the LOW w bits; the equality binding then forces
    // the field slack to actually be < 2^w (else no match -> constraint fails).
    let slack_repr = slack.value().to_biguint();
    let (_bits, slack_recomposed) = bit_decompose(builder, &slack_repr, w);
    builder.enforce_eq_pub(&slack, &slack_recomposed);
}

/// Shared core of both challenge gadgets. `absorbed` are the committed-data
/// wires; `trace` is the software reference's witness (rejection count + raw
/// squeezed elements). Builds, for each attempt `0..=rejections`:
///   - the sponge derivation `e_c` over `absorbed ‖ [tag, s, c]` (challenge
///     bound to data — trap 1), with the squeezed wire bound to `e_c`;
///   - the low-`w`-bit candidate `cand_c` (bit-decomposed, bound to `e_c`'s low
///     bits — see note below);
///   - the order constraint `cand_c >= B` (rejected) / `cand_r < B` (accepted)
///     — trap 2.
/// Returns the accepted candidate wire.
fn challenge_core(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    absorbed: &[Fp192Var],
    tag: u64,
    squeeze_counter: u64,
    trace: &FsChallengeTrace,
) -> Fp192Var {
    let w = trace.window_bits;
    let tag_w = builder.constant_pub(Fp192::from_u64(tag));
    let sc_w = builder.constant_pub(Fp192::from_u64(squeeze_counter));

    let mut accepted: Option<Fp192Var> = None;

    for c in 0..=trace.rejections {
        // ----- trap 1: derive e_c from the absorbed-data WIRES + counters -----
        let attempt_w = builder.constant_pub(Fp192::from_u64(c));
        let mut sponge_in: Vec<Fp192Var> = Vec::with_capacity(absorbed.len() + 3);
        sponge_in.extend_from_slice(absorbed);
        sponge_in.push(tag_w.clone());
        sponge_in.push(sc_w.clone());
        sponge_in.push(attempt_w);
        let e_c = griffin_fp192_sponge_circuit(builder, params, &sponge_in, 1)
            .into_iter()
            .next()
            .expect("sponge squeezes >= 1 element");

        // e_c value MUST equal the software's squeezed element (the gadget
        // recomputes it; this is an internal consistency anchor).
        debug_assert_eq!(
            e_c.value(),
            &trace.squeezed[c as usize],
            "gadget sponge output diverged from software trace at attempt {c}",
        );

        // ----- candidate = e_c mod 2^w, via CANONICAL extraction (no wraparound)
        // `canonical_low_window` pins e_c to its UNIQUE [0,p) bit representation
        // (full 199-bit decomposition + `< p` gate) and returns the low-w-bit
        // recomposition. This is `e_c mod 2^w` with NO mod-p wraparound
        // alternate (the old `cand + high·2^w == e_c (mod p)` form admitted a
        // second `(cand_alt, high_alt)` from `e_c + p` and let a prover grind
        // the index challenge — see `canonical_low_window` docs).
        let e_big = e_c.value().to_biguint();
        let cand_big = &e_big % (BigUint::from(1u8) << w);
        let cand = canonical_low_window(builder, &e_c, w);

        // ----- trap 2: order constraint for this attempt -----
        let is_accept = c == trace.rejections;
        constrain_order(builder, &cand, &cand_big, &trace.bound, w, is_accept);

        if is_accept {
            accepted = Some(cand);
        }
    }

    accepted.expect("loop runs at least once (c = 0..=rejections)")
}

/// R1CS gadget: derive the `challenge_field` value from the absorbed-data wires,
/// matching [`griffin_fs_challenge_field`]. Returns the accepted challenge wire.
pub fn griffin_fs_challenge_field_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    absorbed: &[Fp192Var],
    squeeze_counter: u64,
    trace: &FsChallengeTrace,
) -> Fp192Var {
    challenge_core(builder, params, absorbed, FS_TAG_FIELD, squeeze_counter, trace)
}

/// R1CS gadget: derive the `challenge_index` value from the absorbed-data wires,
/// matching [`griffin_fs_challenge_index`]. Returns the accepted index wire.
pub fn griffin_fs_challenge_index_circuit(
    builder: &mut Fp192R1csBuilder,
    params: &PlumGriffinParams,
    absorbed: &[Fp192Var],
    squeeze_counter: u64,
    trace: &FsChallengeTrace,
) -> Fp192Var {
    challenge_core(builder, params, absorbed, FS_TAG_INDEX, squeeze_counter, trace)
}

/// Build a full standalone R1CS for one `challenge_field` derivation.
pub fn build_griffin_fs_challenge_field(
    absorbed_values: &[Fp192],
    squeeze_counter: u64,
) -> (Fp192R1cs, usize, FsChallengeTrace) {
    let params = plum_griffin_params();
    let trace = griffin_fs_challenge_field(absorbed_values, squeeze_counter);
    let mut builder = Fp192R1csBuilder::new();
    let absorbed: Vec<Fp192Var> = absorbed_values
        .iter()
        .map(|v| builder.alloc_input(v.clone()))
        .collect();
    let out =
        griffin_fs_challenge_field_circuit(&mut builder, params, &absorbed, squeeze_counter, &trace);
    let out_idx = out.index();
    (builder.finalize(), out_idx, trace)
}

/// Build a full standalone R1CS for one `challenge_index` derivation.
pub fn build_griffin_fs_challenge_index(
    absorbed_values: &[Fp192],
    squeeze_counter: u64,
    bound: usize,
) -> (Fp192R1cs, usize, FsChallengeTrace) {
    let params = plum_griffin_params();
    let trace = griffin_fs_challenge_index(absorbed_values, squeeze_counter, bound);
    let mut builder = Fp192R1csBuilder::new();
    let absorbed: Vec<Fp192Var> = absorbed_values
        .iter()
        .map(|v| builder.alloc_input(v.clone()))
        .collect();
    let out =
        griffin_fs_challenge_index_circuit(&mut builder, params, &absorbed, squeeze_counter, &trace);
    let out_idx = out.index();
    (builder.finalize(), out_idx, trace)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(seed: &[u64]) -> Vec<Fp192> {
        seed.iter().map(|&x| Fp192::from_u64(x)).collect()
    }

    /// GATE (1)+(2): the FIELD gadget's derived challenge equals the software
    /// Griffin-FS reference on >= 4 distinct absorbed-data sequences, and the
    /// honest witness satisfies every constraint.
    #[test]
    fn field_gadget_matches_software_and_is_satisfied() {
        let cases: Vec<(Vec<Fp192>, u64)> = vec![
            (data(&[7]), 0),
            (data(&[11, 13]), 1),
            (data(&[1, 2, 3]), 2),
            (data(&[10, 20, 30, 40]), 5),
            (data(&[123456789, 987654321, 42]), 9),
        ];
        for (ci, (absorbed, sc)) in cases.iter().enumerate() {
            let expected = griffin_fs_challenge_field(absorbed, *sc);
            let (r1cs, out_idx, _trace) = build_griffin_fs_challenge_field(absorbed, *sc);

            if let Err(bad) = r1cs.check_satisfied() {
                panic!("FIELD case {ci}: constraint #{bad} unsatisfied");
            }
            assert_eq!(
                r1cs.assignment[out_idx], expected.value,
                "FIELD case {ci}: gadget challenge != software reference",
            );
            eprintln!(
                "FIELD case {ci}: |absorbed|={}, sc={sc}, rejections={} -> {} constraints, {} vars",
                absorbed.len(),
                expected.rejections,
                r1cs.num_constraints(),
                r1cs.num_variables,
            );
        }
    }

    /// GATE (1)+(2): the INDEX gadget matches the software reference on >= 4
    /// distinct absorbed-data sequences and bounds, honest witness satisfied.
    /// Includes a non-power-of-two bound so genuine rejection can occur.
    #[test]
    fn index_gadget_matches_software_and_is_satisfied() {
        let cases: Vec<(Vec<Fp192>, u64, usize)> = vec![
            (data(&[7]), 0, 4096),
            (data(&[11, 13]), 1, 4096),
            (data(&[1, 2, 3]), 2, 26),    // not a power of two -> real rejections possible
            (data(&[9, 8, 7, 6]), 3, 100),// not a power of two
            (data(&[42]), 7, 3),          // small odd bound
        ];
        let mut saw_rejection = false;
        for (ci, (absorbed, sc, bound)) in cases.iter().enumerate() {
            let expected = griffin_fs_challenge_index(absorbed, *sc, *bound);
            let (r1cs, out_idx, _trace) = build_griffin_fs_challenge_index(absorbed, *sc, *bound);

            if let Err(bad) = r1cs.check_satisfied() {
                panic!("INDEX case {ci}: constraint #{bad} unsatisfied");
            }
            assert_eq!(
                r1cs.assignment[out_idx], expected.value,
                "INDEX case {ci}: gadget challenge != software reference",
            );
            let idx_int = expected.value.to_biguint();
            assert!(
                idx_int < BigUint::from(*bound as u64),
                "INDEX case {ci}: derived index {idx_int} not < bound {bound}",
            );
            if expected.rejections > 0 {
                saw_rejection = true;
            }
            eprintln!(
                "INDEX case {ci}: |absorbed|={}, sc={sc}, bound={bound}, rejections={} -> {} constraints, {} vars",
                absorbed.len(),
                expected.rejections,
                r1cs.num_constraints(),
                r1cs.num_variables,
            );
        }
        // Force at least one genuine rejection so the rejection arm of the
        // gadget is actually exercised by the gate. Search seeds if none of the
        // fixed cases above rejected.
        if !saw_rejection {
            for sc in 0..200u64 {
                let t = griffin_fs_challenge_index(&data(&[1]), sc, 26);
                if t.rejections > 0 {
                    let (r1cs, out_idx, _) = build_griffin_fs_challenge_index(&data(&[1]), sc, 26);
                    assert!(r1cs.check_satisfied().is_ok());
                    assert!(t.value.to_biguint() < BigUint::from(26u64));
                    eprintln!(
                        "INDEX rejection-exercise: sc={sc} rejections={} -> {} constraints (out wire {out_idx})",
                        t.rejections,
                        r1cs.num_constraints(),
                    );
                    saw_rejection = true;
                    break;
                }
            }
        }
        assert!(
            saw_rejection,
            "no genuine rejection observed across all index cases — rejection arm untested",
        );
    }

    /// SOUNDNESS trap 1 (challenge bound to data): replace the accepted
    /// challenge wire with a different value (a "free" challenge). A
    /// constraint MUST break — the challenge is a constrained sponge output,
    /// not a free witness.
    #[test]
    fn forged_field_challenge_fails() {
        let absorbed = data(&[1, 2, 3]);
        let (mut r1cs, out_idx, _trace) = build_griffin_fs_challenge_field(&absorbed, 0);
        assert!(r1cs.check_satisfied().is_ok(), "baseline must satisfy");
        // Forge: bump the accepted challenge wire (the recomposed cand). This
        // is the wire that must equal the sponge-derived value.
        r1cs.assignment[out_idx] = r1cs.assignment[out_idx].clone() + Fp192::one();
        assert!(
            r1cs.check_satisfied().is_err(),
            "forged challenge accepted — challenge NOT bound to sponge output",
        );
        eprintln!("forged FIELD challenge correctly rejected (challenge bound to data)");
    }

    /// SOUNDNESS trap 1, also checks data-binding: perturbing an ABSORBED
    /// input wire while leaving the rest of the witness fixed must break a
    /// constraint (the sponge chain depends on every absorbed wire).
    #[test]
    fn perturbed_absorbed_data_fails() {
        let absorbed = data(&[5, 6]);
        let (mut r1cs, _out_idx, _trace) = build_griffin_fs_challenge_field(&absorbed, 0);
        assert!(r1cs.check_satisfied().is_ok());
        // Absorbed inputs are alloc_input wires at indices 1..=|absorbed|.
        r1cs.assignment[1] = r1cs.assignment[1].clone() + Fp192::one();
        assert!(
            r1cs.check_satisfied().is_err(),
            "perturbed absorbed data still satisfied — challenge not bound to data",
        );
        eprintln!("perturbed absorbed-data input correctly rejected");
    }

    /// SOUNDNESS trap 2 (rejection sampling): a malicious prover that SKIPS a
    /// valid (< bound) candidate — i.e. claims attempt c rejected when its
    /// candidate was actually < bound — must fail the `cand_c >= bound`
    /// constraint. We construct a witness that forces an extra "rejected"
    /// attempt whose candidate is genuinely < bound, then check it cannot be
    /// made to satisfy the constraints.
    ///
    /// Concretely: take a derivation whose attempt 0 ACCEPTS (rejections = 0).
    /// Build the same R1CS but with a forged trace claiming rejections = 1
    /// (skipping the valid attempt-0 candidate and pretending attempt 1 is the
    /// accept). The forged system's attempt-0 order constraint demands
    /// `cand_0 >= bound`, but cand_0 < bound by construction, so it must fail.
    #[test]
    fn skipping_valid_candidate_fails() {
        // Find a case where attempt 0 already accepts (the common case).
        let absorbed = data(&[1, 2, 3]);
        let bound = 26usize;
        let honest = griffin_fs_challenge_index(&absorbed, 0, bound);
        assert_eq!(
            honest.rejections, 0,
            "test precondition: pick a derivation that accepts on attempt 0",
        );

        // Forge a trace that claims attempt 0 REJECTED (skipping the valid
        // candidate) and attempt 1 is the accept. We must supply a squeezed
        // element for attempt 1; recompute it the same way the software would.
        let params = plum_griffin_params();
        let e1 = squeeze_once(params, &absorbed, FS_TAG_INDEX, 0, 1);
        let pow = bound.next_power_of_two();
        let w = pow.trailing_zeros() as usize;
        let cand1 = &e1.to_biguint() % (BigUint::from(1u8) << w);
        // The accepted candidate of the forged trace is attempt-1's candidate;
        // it may or may not be < bound, but the forgery is detected at attempt
        // 0 regardless (cand_0 < bound but claimed rejected).
        let forged = FsChallengeTrace {
            value: Fp192::from_biguint(cand1.clone()),
            rejections: 1,
            squeezed: vec![honest.squeezed[0].clone(), e1],
            window_bits: w,
            bound: BigUint::from(bound as u64),
        };

        // Build the gadget against the FORGED trace. The gadget's
        // constrain_order for attempt 0 will be the REJECT arm (since c=0 <
        // rejections=1), demanding cand_0 >= bound. But cand_0 < bound, so the
        // slack = cand_0 - bound is negative; the gadget computes it as a field
        // element which is huge and CANNOT be a w-bit value -> bit
        // decomposition recomposition will not match -> constraint fails.
        let mut builder = Fp192R1csBuilder::new();
        let absorbed_vars: Vec<Fp192Var> =
            absorbed.iter().map(|v| builder.alloc_input(v.clone())).collect();
        let _out = griffin_fs_challenge_index_circuit(
            &mut builder, params, &absorbed_vars, 0, &forged,
        );
        let r1cs = builder.finalize();
        assert!(
            r1cs.check_satisfied().is_err(),
            "forged trace skipping a valid candidate was accepted — rejection sampling unsound",
        );
        eprintln!(
            "skip-valid-candidate forgery correctly rejected (honest cand_0={} < bound {bound})",
            honest.value.to_biguint(),
        );
    }

    /// SOUNDNESS trap 2, accept arm: a witness claiming the accepted candidate
    /// is < bound when it is actually >= bound must fail. We forge the accepted
    /// candidate wire to an out-of-range value.
    #[test]
    fn out_of_range_accept_fails() {
        let absorbed = data(&[9, 8, 7, 6]);
        let bound = 100usize;
        let (mut r1cs, out_idx, trace) = build_griffin_fs_challenge_index(&absorbed, 3, bound);
        assert!(r1cs.check_satisfied().is_ok());
        // The accept-arm slack = bound-1-cand is bit-decomposed. Forcing the
        // accepted candidate wire to bound itself (>= bound) makes slack
        // negative -> the slack decomposition cannot hold.
        let _ = trace;
        r1cs.assignment[out_idx] = Fp192::from_u64(bound as u64);
        assert!(
            r1cs.check_satisfied().is_err(),
            "out-of-range accepted candidate was accepted — acceptance bound unsound",
        );
        eprintln!("out-of-range accept correctly rejected");
    }

    /// SOUNDNESS, the wraparound-forgery negative control (the defect this fix
    /// closes). The OLD extraction enforced `cand + high·2^w == e_c (mod p)`
    /// with `high` given a `200 - w`-bit budget. That admitted a SECOND
    /// decomposition of the integer `e_c + p`, letting a prover bias the index
    /// challenge. We model the attacker faithfully: build a standalone canonical
    /// extraction whose WITNESSED bits come from `e_c + p` (the wraparound
    /// value), with the candidate output overwritten to `cand_alt = (e_c+p) mod
    /// 2^w != e_c mod 2^w`. The canonical `< p` gate (and/or recomposition
    /// binding) MUST reject it: at least one constraint fails.
    #[test]
    fn wraparound_forgery_rejected() {
        let absorbed = data(&[1, 2, 3]);
        let bound = 4096usize; // power of two -> w = 12, no honest rejection noise
        let params = plum_griffin_params();
        // The data-bound sponge output e_c of attempt 0.
        let e_c_val = squeeze_once(params, &absorbed, FS_TAG_INDEX, 0, 0);
        let pow = bound.next_power_of_two();
        let w = pow.trailing_zeros() as usize;

        let e_big = e_c_val.to_biguint();
        let p = Fp192::modulus();
        let cand_honest = &e_big % (BigUint::from(1u8) << w);
        // The wraparound alternate: bits of (e_c + p).
        let wrap = &e_big + &p;
        let cand_alt = &wrap % (BigUint::from(1u8) << w);

        // Precondition: the forgery is only meaningful if the alternate low
        // window actually differs from the honest one (else nothing to bias).
        assert_ne!(
            cand_alt, cand_honest,
            "test precondition: e_c+p must change the low {w} bits (pick another e_c)",
        );

        // Build a standalone circuit: allocate e_c as an input wire (its TRUE
        // field value), then run canonical extraction but with the WITNESSED
        // bits sourced from the wraparound integer e_c + p — the attacker's
        // choice. An honest prover would pass `bits_source = e_c`'s value.
        let mut builder = Fp192R1csBuilder::new();
        let e_c_wire = builder.alloc_input(e_c_val.clone());
        let cand_wire = super::canonical_low_window_with_bits_source(
            &mut builder, &e_c_wire, w, &wrap,
        );
        let r1cs = builder.finalize();

        // The forged candidate wire indeed carries cand_alt (the biased value).
        assert_eq!(
            r1cs.assignment[cand_wire.index()].to_biguint(),
            cand_alt,
            "forged extraction did not yield the wraparound candidate",
        );
        // ...and the constraint system MUST reject the forgery.
        assert!(
            r1cs.check_satisfied().is_err(),
            "WRAPAROUND FORGERY ACCEPTED: canonical extraction failed to pin e_c \
             to its unique [0,p) representation (cand_alt={cand_alt} != honest \
             {cand_honest})",
        );
        eprintln!(
            "wraparound forgery correctly rejected (cand_alt={cand_alt} != honest {cand_honest}, w={w})",
        );

        // Sanity: the HONEST source (bits of e_c) on the SAME wire satisfies.
        let mut hb = Fp192R1csBuilder::new();
        let e_c_wire2 = hb.alloc_input(e_c_val.clone());
        let _ = super::canonical_low_window_with_bits_source(
            &mut hb, &e_c_wire2, w, &e_big,
        );
        let honest = hb.finalize();
        assert!(
            honest.check_satisfied().is_ok(),
            "honest canonical extraction unexpectedly failed",
        );
    }

    /// SOUNDNESS (helper in isolation): `enforce_bits_lt_modulus` must accept a
    /// full-width little-endian bit-string iff it encodes an integer in [0, p),
    /// and reject value == p and value > p. This directly hardens the strict
    /// `< p` completeness fix (terminal `eq_prefix == 0`): before the fix, the
    /// bit-string equal to p was wrongly ADMITTED.
    #[test]
    fn enforce_bits_lt_modulus_rejects_p_and_above() {
        let p = Fp192::modulus();

        // Build the full-width (MODULUS_BITS) boolean wires for `v`, run the
        // helper in isolation, and return whether ALL constraints hold.
        fn accepts(v: &BigUint) -> bool {
            let mut b = Fp192R1csBuilder::new();
            let mut bits = Vec::with_capacity(MODULUS_BITS);
            for k in 0..MODULUS_BITS {
                let bit = (v >> k) & BigUint::from(1u8) == BigUint::from(1u8);
                bits.push(b.alloc_bool_pub(bit));
            }
            super::enforce_bits_lt_modulus(&mut b, &bits);
            b.finalize().check_satisfied().is_ok()
        }

        let zero = BigUint::from(0u8);
        let one = BigUint::from(1u8);
        let p_minus_1 = &p - &one;
        let p_plus_1 = &p + &one;

        // ACCEPTED: 0 and p-1 are the in-range extremes.
        assert!(accepts(&zero), "value == 0 must be ACCEPTED (< p)");
        assert!(accepts(&p_minus_1), "value == p-1 must be ACCEPTED (< p)");

        // REJECTED: exactly p (the defect that was admitted before the fix), and
        // p+1 (a genuine value > p that still fits in MODULUS_BITS).
        assert!(
            !accepts(&p),
            "value == p must be REJECTED — strict `< p` check is incomplete",
        );
        assert!(!accepts(&p_plus_1), "value == p+1 must be REJECTED (> p)");

        // Report which constraint catches value == p, for the record.
        let mut b = Fp192R1csBuilder::new();
        let mut bits = Vec::with_capacity(MODULUS_BITS);
        for k in 0..MODULUS_BITS {
            let bit = (&p >> k) & BigUint::from(1u8) == BigUint::from(1u8);
            bits.push(b.alloc_bool_pub(bit));
        }
        super::enforce_bits_lt_modulus(&mut b, &bits);
        let r1cs = b.finalize();
        match r1cs.check_satisfied() {
            Err(idx) => eprintln!(
                "enforce_bits_lt_modulus(value==p): rejected at constraint #{idx} \
                 of {} total",
                r1cs.num_constraints(),
            ),
            Ok(()) => panic!("value == p unexpectedly satisfied all constraints"),
        }
    }

    /// Report constraint counts for the canonical PLUM challenge shapes.
    #[test]
    fn report_constraint_counts() {
        let absorbed = data(&[1, 2, 3, 4]);
        let (rf, _, tf) = build_griffin_fs_challenge_field(&absorbed, 0);
        let (rix, _, ti) = build_griffin_fs_challenge_index(&absorbed, 0, 4096);
        eprintln!(
            "COUNTS field(|D|=4,rej={}): {} constraints, {} vars",
            tf.rejections, rf.num_constraints(), rf.num_variables,
        );
        eprintln!(
            "COUNTS index(|D|=4,bound=4096,rej={}): {} constraints, {} vars",
            ti.rejections, rix.num_constraints(), rix.num_variables,
        );
    }
}
