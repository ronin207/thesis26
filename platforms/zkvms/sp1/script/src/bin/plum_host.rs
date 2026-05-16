//! SP1 PLUM verification host (smoke).
//!
//! Generates a PLUM keypair, signs a fixed message with `PlumSha3Hasher`,
//! and drives the SP1 `plum_verify` program. Default mode is `execute`
//! (no proof, fast — just confirms the guest runs). Set
//! `PLUM_HOST_MODE=prove` to generate and verify a real proof.

use std::time::Instant;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf,
};

use vc_pqc::signatures::plum::hasher::PlumSha3Hasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, PlumSecretKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::{PlumSignature, plum_sign};

const PLUM_VERIFY_ELF: Elf = include_elf!("plum_verify");

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk: PlumPublicKey,
    message: Vec<u8>,
    signature: PlumSignature,
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let mut rng = ChaCha20Rng::seed_from_u64(0x504C554D5F535031);
    let pp: PlumPublicParams = plum_setup(128).expect("setup");
    let (sk, pk): (PlumSecretKey, PlumPublicKey) = plum_keygen(&pp, &mut rng);
    let message = b"sp1 smoke: plum verify with SHA3 hasher".to_vec();
    let signature: PlumSignature =
        plum_sign::<PlumSha3Hasher, _>(&pp, &sk, &message, &mut rng);

    let input = GuestInput {
        pp,
        pk,
        message,
        signature,
    };
    let bytes = bincode::serialize(&input).expect("serialize input");
    println!("input bytes: {}", bytes.len());

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);

    let client = ProverClient::from_env();
    let mode = std::env::var("PLUM_HOST_MODE").unwrap_or_else(|_| "execute".into());

    match mode.as_str() {
        "execute" => {
            let t = Instant::now();
            let (output, report) = client
                .execute(PLUM_VERIFY_ELF, stdin)
                .run()
                .expect("execute failed");
            let accepted: bool =
                bincode::deserialize(output.as_slice()).expect("decode commit");
            println!(
                "accepted={} cycles={} elapsed_ms={}",
                accepted,
                report.total_instruction_count(),
                t.elapsed().as_millis() as u64,
            );
            assert!(accepted, "guest rejected an honest PLUM signature");
        }
        "prove" => {
            let t_setup = Instant::now();
            let pk_proof = client.setup(PLUM_VERIFY_ELF).expect("setup elf failed");
            println!("setup_ms={}", t_setup.elapsed().as_millis() as u64);

            let t_prove = Instant::now();
            let proof = client
                .prove(&pk_proof, stdin)
                .run()
                .expect("prove failed");
            println!("prove_ms={}", t_prove.elapsed().as_millis() as u64);

            let t_verify = Instant::now();
            client
                .verify(&proof, pk_proof.verifying_key(), None)
                .expect("verify failed");
            println!("verify_ms={}", t_verify.elapsed().as_millis() as u64);
        }
        other => panic!("unknown PLUM_HOST_MODE={other:?}; use execute or prove"),
    }
}
