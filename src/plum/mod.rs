//! PLUM: Power Residue PRF-based SNARK-friendly Post-Quantum Signature.
//!
//! Implementation of the PLUM signature scheme from Zhang, Fu, Steinfeld,
//! Liu, Yuen, Au — *"Plum: SNARK-Friendly Post-Quantum Signature Based on
//! Power Residue PRFs"*, ProvSec 2025 (LNCS 16172).
//!
//! PLUM is a member of the same family as Loquat (Zhang et al., CRYPTO
//! 2024) — same Algorithm-7-style phased verification, same Fiat–Shamir
//! + Merkle commitment scaffolding — but differs from Loquat in three
//! material ways:
//!
//!   1. **Field**: 199-bit smooth prime `p = 2^64 · p_0 + 1` (instead of
//!      the Mersenne prime `2^127 - 1` Loquat uses).
//!   2. **PRF**: t-th power residue PRF with **t = 256** (instead of
//!      Loquat's Legendre PRF, which is the t = 2 case).
//!   3. **Low-degree test**: STIR (Arnon–Chiesa–Fenzi–Yogev 2024) in
//!      place of FRI; at λ=128 PLUM only needs 1 round of STIR folding
//!      vs Loquat's 4 rounds of FRI.
//!
//! Because the field is chosen smoothly, PLUM avoids the F_p² extension
//! Loquat requires inside the sumcheck.
//!
//! ## Status
//!
//! This module is under active construction per
//! `spec/plum_implementation_plan.md`. As of the last `cargo test plum::`
//! run (97 unit tests, all passing under `VC_PQC_SKIP_LIBIOP=1`) plus 6
//! `tests/plum_field_primality.rs` integration tests:
//!
//!   - **Phase 1** — `Fp192` arithmetic, oracle-tested vs `num_bigint`.
//!     Prime substitution audited end-to-end against the paper PDF — see
//!     `field_p192` doc-comment and `tests/plum_field_primality.rs`.
//!   - **Phase 2** — `prf` t-th power-residue PRF (Def. 1), with the
//!     `Z_t` discrete-log table and multiplicative-homomorphism check.
//!   - **Phase 3** — `griffin` permutation re-instantiated for `Fp192`
//!     (S-box exponent `d = 3`, not Loquat's 5), with permutation counter.
//!   - **Phase 4** — `hasher` (Griffin + SHA3), `merkle`, and Fiat–Shamir
//!     `transcript`, all generic over `PlumHasher`.
//!   - **Phase 6** — `fft` (coset Cooley-Tukey radix-2 over Fp192) and
//!     `sumcheck` (BCRSVW univariate decomposition `f = g + Z_H · h`
//!     per Algorithm 4 line 10, paper p. 120), audited by proof-checker
//!     against Algorithms 3/4/6.
//!   - **Phase 7** — `setup` materialises `PlumPublicParams` at
//!     λ ∈ {80, 100, 128}; `keygen` implements Algorithm 2 (paper p. 118)
//!     with the `{-I_1, ..., -I_L}` exclusion set, audited by the
//!     proof-checker subagent against the paper PDF directly.
//!
//! TODO from the plan: Phase 5 (STIR), Phase 8 (sign), Phase 9 (verify),
//! Phase 10 (zkVM).

#[cfg(feature = "std")]
pub mod fft;
#[cfg(feature = "std")]
pub mod field_p192;
#[cfg(feature = "std")]
pub mod griffin;
#[cfg(feature = "std")]
pub mod hasher;
#[cfg(feature = "std")]
pub mod keygen;
#[cfg(feature = "std")]
pub mod merkle;
#[cfg(feature = "std")]
pub mod prf;
#[cfg(feature = "std")]
pub mod setup;
#[cfg(feature = "std")]
pub mod sumcheck;
#[cfg(feature = "std")]
pub mod transcript;
