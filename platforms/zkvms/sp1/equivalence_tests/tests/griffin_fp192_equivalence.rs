//! Cross-codebase Griffin-Fp192 equivalence test (Phase 3d-stage-2
//! audit).
//!
//! The SP1 executor's vendored `griffin_fp192_compute::permute_in_place`
//! (in `submodules/sp1/crates/core/executor/src/griffin_fp192_compute.rs`)
//! MUST compute the same permutation as the reference at
//! `src/primitives/hash/griffin_p192.rs::plum_griffin_permutation_raw`.
//! If they ever diverge, the SP1 zkvm trace produced by the
//! `GRIFFIN_FP192_PERMUTE` syscall will silently disagree with what
//! the guest expects, and proof-gen (Phase 3d-stage-3 onward) will
//! fail in confusing ways.
//!
//! This test is the drift detector. It runs natively on the host
//! (no zkVM involved), exercising both paths on identical input.
//!
//! ### What "identical compute" means here
//!
//! Both sides:
//!   - Use the same `MODULUS_LIMBS` (asserted explicitly).
//!   - Derive Griffin params (round constants, alphas, betas, d,
//!     d_inv, rounds) from `SHAKE256("PlumGriffin({mod},{w},{c},{l})")`
//!     — same seed string, FIPS 202 output. Source library differs
//!     (`sha3` vs `tiny-keccak`), but both implement the same
//!     standard.
//!   - Apply the same permutation: `rounds-1` × (nonlinear + linear +
//!     constants), then a final (nonlinear + linear).
//!
//! Lane encoding in the syscall I/O format: lane `i` is
//! `state_words[4*i .. 4*i + 4]`, little-endian u64 limbs. Both
//! sides agree by construction.

use sp1_core_executor::griffin_fp192_compute;
use vc_pqc::primitives::field::p192::Fp192;
use vc_pqc::primitives::hash::griffin_p192::{plum_griffin_permutation_raw, PLUM_GRIFFIN_STATE_WIDTH};

/// Compose four `u64` limbs (little-endian) into a single state slot
/// in the syscall I/O layout. Mirror of the executor side's
/// `Fp192::from_limbs([l0, l1, l2, l3])`.
fn lane_words_from_fp192(elem: &Fp192) -> [u64; 4] {
    elem.to_limbs()
}

fn state_words_from_lanes(lanes: &[Fp192; PLUM_GRIFFIN_STATE_WIDTH]) -> [u64; 16] {
    let mut out = [0u64; 16];
    for (i, lane) in lanes.iter().enumerate() {
        let limbs = lane_words_from_fp192(lane);
        out[i * 4..i * 4 + 4].copy_from_slice(&limbs);
    }
    out
}

fn lanes_from_state_words(state: &[u64; 16]) -> [Fp192; PLUM_GRIFFIN_STATE_WIDTH] {
    core::array::from_fn(|i| {
        Fp192::from_limbs([state[i * 4], state[i * 4 + 1], state[i * 4 + 2], state[i * 4 + 3]])
    })
}

#[test]
fn modulus_limbs_agree() {
    // First defense: if anyone drifts MODULUS_LIMBS on one side, the
    // SHAKE seed diverges and the entire param set goes out of sync.
    // Check the constants directly so the failure is localized
    // rather than buried in a later "permutations differ".
    assert_eq!(
        griffin_fp192_compute::MODULUS_LIMBS,
        Fp192::modulus_limbs(),
        "MODULUS_LIMBS drift between SP1 executor and vc-pqc reference",
    );
}

#[test]
fn permutation_matches_reference_on_simple_vector() {
    // Input: lanes = [1, 2, 3, 4]. Non-zero, non-symmetric, well
    // inside Fp192. Anything wrong in the param derivation, the
    // S-box exponent, the matrix, or the round count will show up
    // in the output.
    let mut reference_lanes: [Fp192; PLUM_GRIFFIN_STATE_WIDTH] =
        core::array::from_fn(|i| Fp192::from_u64((i as u64) + 1));
    let mut state_words = state_words_from_lanes(&reference_lanes);

    plum_griffin_permutation_raw(&mut reference_lanes);
    griffin_fp192_compute::permute_in_place(&mut state_words);

    let executor_lanes = lanes_from_state_words(&state_words);

    assert_eq!(
        executor_lanes, reference_lanes,
        "Griffin permutation diverged between SP1 executor and vc-pqc reference",
    );
}

#[test]
fn permutation_matches_reference_on_zero_input() {
    // Zero is a useful adversarial input: it exercises the
    // round-constants layer in isolation (linear and S-box layers
    // map zero to zero, so non-zero output here means the round
    // constants were actually injected). Drift in `compute_plum_griffin_params`'s
    // SHAKE seed would land here.
    let mut reference_lanes: [Fp192; PLUM_GRIFFIN_STATE_WIDTH] =
        core::array::from_fn(|_| Fp192::from_u64(0));
    let mut state_words = [0u64; 16];

    plum_griffin_permutation_raw(&mut reference_lanes);
    griffin_fp192_compute::permute_in_place(&mut state_words);

    let executor_lanes = lanes_from_state_words(&state_words);
    assert_eq!(executor_lanes, reference_lanes, "zero-input Griffin permutation diverged");
    assert_ne!(state_words, [0u64; 16], "executor produced zero output (round constants missing?)");
}

#[test]
fn permutation_matches_reference_on_high_entropy_input() {
    // 16 pseudo-random u64s — every limb position non-zero. Catches
    // limb-ordering bugs in the from_limbs/to_limbs conversion that
    // a uniform input wouldn't catch.
    let initial: [u64; 16] = [
        0x0123_4567_89ab_cdef,
        0xfedc_ba98_7654_3210,
        0x1111_2222_3333_4444,
        0x5555_6666_7777_8888,
        0x9999_aaaa_bbbb_cccc,
        0xdddd_eeee_ffff_0000,
        0x1357_9bdf_2468_ace0,
        0x0eca_8642_fdb9_7531,
        0x0101_0202_0303_0404,
        0x0505_0606_0707_0808,
        0xa0a0_b0b0_c0c0_d0d0,
        0xe0e0_f0f0_1010_2020,
        0xdead_beef_cafe_babe,
        0xfeed_face_b00b_5aac,
        0x4141_4242_4343_4444,
        0x4545_4646_4747_4848,
    ];

    let mut reference_lanes = lanes_from_state_words(&initial);
    let mut state_words = state_words_from_lanes(&reference_lanes);

    plum_griffin_permutation_raw(&mut reference_lanes);
    griffin_fp192_compute::permute_in_place(&mut state_words);

    let executor_lanes = lanes_from_state_words(&state_words);
    assert_eq!(
        executor_lanes, reference_lanes,
        "high-entropy Griffin permutation diverged (suspect: limb ordering)",
    );
}

#[test]
fn permutation_matches_reference_on_random_inputs() {
    // Phase 3d-stage-3 prep: address audit finding A-2
    // (`docs/precompile_soundness/griffin_fp192.md`). The three
    // hand-picked vectors above can in principle agree by coincidence
    // if the executor and reference share a subtle bug that only
    // shows up on inputs they don't exercise (e.g., a limb-position
    // mistake that happens to be self-cancelling on the chosen
    // patterns).
    //
    // This test draws 256 random valid `Fp192` states and asserts
    // byte-equality after one permutation each. With 4 lanes × 199
    // bits = ~796 bits of input entropy per state, the probability of
    // a directional bug surviving 256 random vectors is negligible
    // (any limb/round/parameter mistake produces a uniformly different
    // output on random inputs, so the false-pass probability per
    // vector is at most ~1/p ≈ 2^-199, times 256 vectors).
    //
    // Deterministic seed: a CI failure is reproducible locally
    // without flake.
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const VECTORS: usize = 256;
    let mut rng = ChaCha20Rng::seed_from_u64(0x6772_6966_6669_6e21); // "griffin!"

    for vector_idx in 0..VECTORS {
        // Sample 4 random Fp192 lanes (rejection sampling on a 200-bit
        // candidate; `Fp192::rand` does this internally).
        let mut reference_lanes: [Fp192; PLUM_GRIFFIN_STATE_WIDTH] =
            core::array::from_fn(|_| Fp192::rand(&mut rng));
        let mut state_words = state_words_from_lanes(&reference_lanes);

        plum_griffin_permutation_raw(&mut reference_lanes);
        griffin_fp192_compute::permute_in_place(&mut state_words);

        let executor_lanes = lanes_from_state_words(&state_words);
        assert_eq!(
            executor_lanes, reference_lanes,
            "Griffin permutation diverged at random vector index {vector_idx}; \
             reproduce by seeding ChaCha20Rng with 0x6772_6966_6669_6e21 \
             and consuming {vector_idx} prior states",
        );
    }
}
