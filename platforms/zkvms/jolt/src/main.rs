//! Jolt Loquat verification host (smoke).
//!
//! Generates a Loquat keypair, signs a fixed message, and drives the
//! Jolt `loquat_smoke` provable function. Mirrors the SP1 PLUM smoke
//! pattern but on Loquat (PLUM-on-Jolt is blocked on a `no_std` refactor
//! of the PLUM module — see workspace README).

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tracing::info;

use vc_pqc::signatures::loquat::{
    LoquatPublicParams, LoquatSignature, field_utils::F, keygen_with_params, loquat_setup,
    loquat_sign,
};

#[derive(Serialize, Deserialize)]
struct LoquatGuestInput {
    params: LoquatPublicParams,
    message: Vec<u8>,
    public_key: Vec<F>,
    signature: LoquatSignature,
}

pub fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut rng = ChaCha20Rng::seed_from_u64(0x4C4F51554154u64); // "LOQUAT"
    let params: LoquatPublicParams = loquat_setup(128).expect("setup");
    let keypair = keygen_with_params(&params).expect("keygen");
    let message = b"jolt smoke: loquat verify".to_vec();
    let signature: LoquatSignature =
        loquat_sign(&message, &keypair, &params).expect("sign");

    let public_key: Vec<F> = keypair.public_key.clone();
    let input = LoquatGuestInput {
        params,
        message,
        public_key,
        signature,
    };
    let bytes = postcard::to_allocvec(&input).expect("postcard encode");
    info!(input_bytes = bytes.len(), "input serialized");

    let target_dir = "/tmp/jolt-loquat-targets";
    let mut program = guest::compile_loquat_smoke(target_dir);

    let shared = guest::preprocess_shared_loquat_smoke(&mut program).expect("preprocess shared");
    let prover_pp = guest::preprocess_prover_loquat_smoke(shared.clone());
    let verifier_setup = prover_pp.generators.to_verifier_setup();
    let verifier_pp = guest::preprocess_verifier_loquat_smoke(shared, verifier_setup, None);

    let prove = guest::build_prover_loquat_smoke(program, prover_pp);
    let verify = guest::build_verifier_loquat_smoke(verifier_pp);

    let (accepted, proof, io_device) = prove(&bytes);
    let proof_valid = verify(&bytes, accepted, io_device.panic, proof);

    info!(accepted, proof_valid, "jolt smoke done");
    assert!(accepted, "guest rejected an honest Loquat signature");
    assert!(proof_valid, "Jolt proof failed to verify");
}
