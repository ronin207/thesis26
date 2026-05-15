//! Transparent SNARK proof-of-concept implementations inspired by
//! Aurora (IACR 2018/828) and Fractal (IACR 2019/1076).
//!
//! The goal of this module is to provide a Rust-native playground that
//! mirrors the multi-oracle IOP structure described in the papers:
//! - Rank-1 Constraint System (R1CS) front-end with explicit witness commitments.
//! - Sumcheck + low-degree style checks instantiated with the reusable Loquat
//!   sumcheck/LDT components.
//! - Recursive folding (à la Fractal) that compresses Aurora proofs via
//!   challenge-driven linking constraints.
//!
//! These proofs are *not* production SNARKs, but every stage aligns with the
//! numbered steps in the original specifications so that future work can
//! swap the simplified gadgets with fully optimised polynomial commitments.

#[cfg(not(feature = "std"))]
compile_error!("The SNARK prototypes require the `std` feature.");

pub mod aurora;
pub mod fractal;
#[cfg(not(vc_pqc_skip_libiop))]
pub mod libiop_bridge;

pub use aurora::{
    AuroraParams, AuroraProof, AuroraProverOptions, AuroraVerificationHints,
    AuroraVerificationResult, aurora_prove, aurora_prove_with_options, aurora_verify,
    aurora_verify_with_public_inputs,
};
pub use fractal::{FractalParams, FractalProof, fractal_prove, fractal_verify};
// R1CS types now live in `crate::primitives::r1cs`; re-exported here
// for callers that import via `vc_pqc::snarks::*`.
pub use crate::primitives::r1cs::{R1csConstraint, R1csInstance, R1csWitness};
// Loquat-specific R1CS lowering now lives at
// `crate::signatures::loquat::r1cs_circuit`; re-exported here for callers
// that import via `vc_pqc::snarks::*`.
pub use crate::signatures::loquat::r1cs_circuit::{
    build_loquat_r1cs_pk_witness, build_loquat_r1cs_pk_witness_instance,
    build_loquat_r1cs_pk_sig_witness, build_loquat_r1cs_pk_sig_witness_instance,
    build_revocation_r1cs_pk_witness, build_revocation_r1cs_pk_witness_instance,
    take_last_r1cs_breakdown,
};
