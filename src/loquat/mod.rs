//! Core Loquat Post-Quantum Signature Scheme
//!
//! Implementation of the Loquat signature scheme from "Loquat: A SNARK-Friendly
//! Post-Quantum Signature based on the Legendre PRF" by Zhang et al.
//!
//! This module contains the complete implementation of Algorithms 1-7 from the paper:
//! - Algorithm 1: IOP-based Key Identification
//! - Algorithm 2: Public Parameter Setup
//! - Algorithm 3: Key Generation
//! - Algorithm 4-6: Signature Generation Workflow
//! - Algorithm 7: Signature Verification
//!
//! ## Hash Function
//!
//! This implementation uses Griffin as the default hash function instead of SHA256.
//! Griffin is a SNARK-friendly algebraic hash function that operates natively over
//! prime fields, making it significantly more efficient in zero-knowledge proof circuits.
//!
//! The hash abstraction layer (`hasher` module) allows switching between Griffin and
//! SHA256 if needed for compatibility.

pub mod encoding;
pub mod errors;
pub mod fft;
pub mod field_p127;
pub mod field_utils;
pub mod griffin;
#[cfg(feature = "guest")]
pub mod guest;
pub mod hasher;
#[cfg(feature = "std")]
pub mod iop_key_id;
#[cfg(feature = "std")]
pub mod keygen;
pub mod ldt;
pub mod merkle;
pub mod setup;
pub mod sign;
pub mod sumcheck;
pub mod transcript;
pub mod verify;

#[cfg(feature = "std")]
pub mod benchmark;
#[cfg(feature = "std")]
pub mod tests;

// Re-export core types for convenience
pub use errors::{LoquatError, LoquatResult};
pub use setup::LoquatPublicParams;
#[cfg(feature = "std")]
pub use setup::loquat_setup;

#[cfg(feature = "std")]
pub use benchmark::{BenchmarkConfig, HashType, LoquatBenchmark, PerformanceMetrics};
#[cfg(feature = "guest")]
pub use guest::loquat_verify_guest;
#[cfg(feature = "std")]
pub use iop_key_id::{IOPInstance, IOPProof, IOPWitness, iop_key_identification, verify_iop_proof};
#[cfg(feature = "std")]
pub use keygen::{LoquatKeyPair, keygen_with_params};
#[cfg(feature = "std")]
pub use sign::flatten_signature_for_hash;
#[cfg(feature = "std")]
pub use sign::loquat_sign;
pub use sign::{LoquatSignature, LoquatSignatureArtifact, LoquatSigningTranscript};
#[cfg(feature = "std")]
pub use sumcheck::generate_sumcheck_proof;
pub use sumcheck::{UnivariateSumcheckProof, verify_sumcheck_proof};
pub use transcript::Transcript;
pub use verify::loquat_verify;
