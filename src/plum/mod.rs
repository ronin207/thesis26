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
//! run (67 unit tests, all passing under `VC_PQC_SKIP_LIBIOP=1`):
//!
//!   - **Phase 1** — `Fp192` arithmetic, oracle-tested vs `num_bigint`.
//!   - **Phase 2** — `prf` t-th power-residue PRF (Def. 1), with the
//!     `Z_t` discrete-log table and multiplicative-homomorphism check.
//!   - **Phase 3** — `griffin` permutation re-instantiated for `Fp192`
//!     (S-box exponent `d = 3`, not Loquat's 5), with permutation counter.
//!   - **Phase 4** — `hasher` (Griffin + SHA3), `merkle`, and Fiat–Shamir
//!     `transcript`, all generic over `PlumHasher`.
//!   - **Phase 7 (partial)** — `setup` materialises `PlumPublicParams`
//!     at λ ∈ {80, 100, 128}; keygen (Algorithm 2) is not yet implemented.
//!
//! TODO from the plan: Phase 5 (STIR), Phase 6 (univariate sumcheck),
//! Phase 7 (keygen), Phase 8 (sign), Phase 9 (verify), Phase 10 (zkVM).

#[cfg(feature = "std")]
pub mod field_p192;
#[cfg(feature = "std")]
pub mod griffin;
#[cfg(feature = "std")]
pub mod hasher;
#[cfg(feature = "std")]
pub mod merkle;
#[cfg(feature = "std")]
pub mod prf;
#[cfg(feature = "std")]
pub mod setup;
#[cfg(feature = "std")]
pub mod transcript;
