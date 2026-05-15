#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

// VC-PQC: Post-Quantum Verifiable Credentials
//
// This library provides two main components:
//
// 1. **Loquat**: A SNARK-friendly post-quantum signature scheme based on the Legendre PRF
// 2. **Anonymous Credentials**: Privacy-preserving verifiable credentials built on Loquat
//
// ## Core Loquat Signature Scheme
//
// The `loquat` module implements the complete Loquat signature scheme from the paper
// "Loquat: A SNARK-Friendly Post-Quantum Signature based on the Legendre PRF".
//
// ```rust
// use vc_pqc::{loquat_setup, keygen_with_params, loquat_sign, loquat_verify};
// # fn main() -> Result<(), Box<dyn std::error::Error>> {
//
// // Setup with 128-bit security
// let params = loquat_setup(128)?;
// let keypair = keygen_with_params(&params)?;
//
// // Sign and verify
// let message = b"Hello, post-quantum world!";
// let signature = loquat_sign(message, &keypair, &params)?;
// let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)?;
// assert!(is_valid);
// # Ok(())
// # }
// ```
//
// ## Anonymous Credentials
//
// The `anoncreds` module provides W3C Verifiable Credentials compatible anonymous
// credentials with selective disclosure and zero-knowledge proofs.
//
// ```rust,ignore
// use vc_pqc::anoncreds::{CredentialIssuer, CredentialAttribute};
// use vc_pqc::loquat::loquat_setup;
//
// // Setup issuer
// let params = loquat_setup(128)?;
// let mut issuer = CredentialIssuer::new("Government_ID", &params)?;
//
// // Issue credential
// let attributes = vec![
//     CredentialAttribute::new("age", 25, false), // Hidden
//     CredentialAttribute::new("citizenship", 840, false), // Hidden (USA)
// ];
// let credential = issuer.issue_credential(
//     b"holder_pseudonym".to_vec(),
//     attributes,
//     "identity_v1"
// )?;
// ```

#[cfg(feature = "std")]
macro_rules! loquat_debug {
    ($($arg:tt)*) => {
        tracing::debug!($($arg)*);
    };
}

#[cfg(not(feature = "std"))]
macro_rules! loquat_debug {
    ($($arg:tt)*) => {
        ()
    };
}

#[cfg(feature = "std")]
pub mod anoncreds;
#[cfg(feature = "std")]
pub mod bench;
#[cfg(feature = "std")]
pub mod evaluation;
#[cfg(feature = "std")]
pub mod noir_backend;
pub mod signatures;
#[cfg(feature = "std")]
pub mod snarks;

// Backwards-compatible path aliases so external callers (tests, bin/, zkvm
// guests) can continue to use `vc_pqc::loquat::*`, `vc_pqc::plum::*`,
// `vc_pqc::bdec::*` after the src/ reorg (loquat+plum moved under
// `signatures::`, bdec moved under `anoncreds::`).
pub use signatures::loquat;
#[cfg(feature = "std")]
pub use signatures::plum;
#[cfg(feature = "std")]
pub use anoncreds::bdec;

// Re-export commonly used types for convenience
#[cfg(feature = "std")]
pub use bdec::{
    BdecAttributeCommitmentType, BdecAttributeMerkleProof, BdecCredential, BdecCredentialProof,
    BdecLinkProof, BdecPseudonymKey, BdecPublicParams, BdecRevocationAccumulator,
    BdecRevocationProof, BdecShownCredentialPaper, BdecSystem, bdec_attribute_merkle_proof,
    bdec_attribute_merkle_root, bdec_build_showver_instance_paper,
    bdec_build_showver_instance_with_policy_paper, bdec_issue_credential,
    bdec_issue_credential_merkle_attrs, bdec_link_pseudonyms, bdec_nym_key, bdec_prigen,
    bdec_public_key_prefix_index, bdec_revoke, bdec_setup, bdec_setup_zk,
    bdec_show_credential_paper, bdec_show_credential_paper_merkle,
    bdec_show_credential_with_policy_paper, bdec_synthetic_public_key_with_prefix,
    bdec_verify_credential, bdec_verify_link_proof, bdec_verify_show_proof_paper,
    bdec_verify_shown_credential_paper, bdec_verify_shown_credential_with_policy_paper,
};
#[cfg(feature = "std")]
pub use evaluation::{
    D1ChurnEntry, D2CostMetrics, D3PrivacyResult, PhaseSpan, PhaseTimer, PolicyInput,
    PolicyPredicate, Pp2AuroraBenchmarkResult, Pp2AuroraRunConfig, Pp3AuroraBenchmarkResult,
    default_pp3_policies, evaluate_policy_input, parse_attribute_map,
    pp3_policy_only_d1_churn_rows, run_pp2_aurora_cli, run_pp2_aurora_single,
    run_pp2_aurora_single_opts, run_pp3_aurora_single, run_pp3_aurora_single_opts,
    run_pp3_default_policy_comparison,
};
#[cfg(feature = "std")]
pub use loquat::keygen::{LoquatKeyPair, keygen_with_params};
pub use loquat::{
    LoquatError, LoquatPublicParams, LoquatResult, LoquatSignature, LoquatSignatureArtifact,
    LoquatSigningTranscript, Transcript, loquat_verify,
};
#[cfg(feature = "std")]
pub use loquat::{loquat_setup, loquat_setup_tiny, loquat_sign};
#[cfg(feature = "std")]
pub use noir_backend::{
    AcirR1csBuild, NoirAuroraBackend, compile_acir_json_to_r1cs, convert_acir_to_r1cs,
};

// Re-export Griffin hash module
pub use loquat::griffin::{
    GriffinParams, GriffinState, get_griffin_params, griffin_hash, griffin_hash_default,
    griffin_sponge,
};
pub use loquat::hasher::{GriffinHasher, HashType, LoquatHasher, Sha256Hasher, hash};
#[cfg(feature = "std")]
pub use snarks::{
    AuroraParams, AuroraProof, AuroraProverOptions, AuroraVerificationHints,
    AuroraVerificationResult, FractalParams, FractalProof, R1csConstraint, R1csInstance,
    R1csWitness, aurora_prove, aurora_prove_with_options, aurora_verify, fractal_prove,
    fractal_verify,
};

/*
pub use anoncreds::{
    CredentialIssuer, CredentialAttribute, AnonymousCredential,
    SelectiveDisclosureRequest, SelectiveDisclosureVerifier
};
*/
