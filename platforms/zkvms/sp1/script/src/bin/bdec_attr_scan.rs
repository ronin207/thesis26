//! SP1 BDEC attribute-axis sweep — Test 2 of HANDOFF-linkability-test.md
//! (axes 1 and 4: attribute byte-length and number of disclosed attributes).
//!
//! Deployed-pipeline instantiation: attributes NEVER enter the guest raw; the
//! host hashes them (h = SHA-256(encode(A)), always 32 bytes) and the guest
//! verifies a PLUM signature on that 32-byte digest. So the attribute axis is
//! STRUCTURALLY normalized before the guest sees it; this sweep is the
//! empirical confirmation.
//!
//! Design note (why this is NOT a pure zkleak-deterministic sweep): each
//! attribute set requires its own signature, and signing draws fresh
//! randomness, so cycles inherit the +-1% witness noise. Per the handoff
//! brief's own scoping ("for anything not randomized"), the analysis is
//! distributional: M samples per secret, interleaved; KS + permutation test
//! host-side. zkleak's exact mode applies only to axes where the observable
//! is a function of the secret (cf. the k-sweep).
//!
//! Secrets (6): len8 / len64 / len512 = one attribute of 8/64/512 bytes;
//! cnt2 / cnt4 / cnt8 = 2/4/8 attributes of 32 bytes each. One fixed keypair;
//! ONLY the attribute set varies (the brief's "vary only the secret" rule).
//! Message = SHA-256 of the encoded set -> input size fixed (asserted).
//!
//! Env: `PLUM_SECURITY` (80), `ATTR_SAMPLES` (12).

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_sdk::{
    Elf, SP1Stdin,
    blocking::{Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinShakeFsHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::plum_sign;

const PLUM_VERIFY_SYSCALL_ELF_BYTES: &[u8] =
    include_bytes!(env!("PLUM_VERIFY_SYSCALL_ELF_PATH"));

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk: PlumPublicKey,
    message: Vec<u8>,
    signature: vc_pqc::signatures::plum::sign::PlumSignature,
}

/// (label, attribute set) — the swept secret. `axis` selects which family
/// (Test B splits the two axes into separate files; "both" = round-1 behaviour).
fn attribute_sets(axis: &str) -> Vec<(&'static str, Vec<Vec<u8>>)> {
    let attr = |tag: u8, n: usize| -> Vec<u8> { vec![tag; n] };
    let length = vec![
        ("len8", vec![attr(0xA1, 8)]),
        ("len64", vec![attr(0xA2, 64)]),
        ("len512", vec![attr(0xA3, 512)]),
        ("len4096", vec![attr(0xA4, 4096)]),
    ];
    let count = vec![
        ("cnt2", (0..2).map(|i| attr(0xB0 + i, 32)).collect()),
        ("cnt4", (0..4).map(|i| attr(0xC0 + i, 32)).collect()),
        ("cnt8", (0..8).map(|i| attr(0xD0 + i, 32)).collect()),
    ];
    match axis {
        "length" => length,
        "count" => count,
        _ => length.into_iter().chain(count).collect(),
    }
}

/// Length-prefixed encoding, then one SHA-256 digest — the h_{U,TA} / h_{U,V}
/// pattern of the deployed CreGen/ShowCre pipeline.
fn encode_and_hash(attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut h = Sha256::new();
    for a in attrs {
        h.update((a.len() as u64).to_le_bytes());
        h.update(a);
    }
    h.finalize().to_vec()
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("PLUM_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let samples: usize = std::env::var("ATTR_SAMPLES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);
    let axis = std::env::var("ATTR_AXIS").unwrap_or_else(|_| "both".into());

    let sets = attribute_sets(&axis);
    eprintln!(
        "=== PLUM-{security} attribute-axis sweep: {} secrets x {samples} samples, interleaved ===",
        sets.len()
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0x4154_5452_5343_414e); // "ATTRSCAN"
    let pp: PlumPublicParams = plum_setup(security).expect("setup");
    let (sk, pk) = plum_keygen(&pp, &mut rng);
    eprintln!("keygen done (one keypair; only the attribute set varies)");

    let client = ProverClient::from_env();
    let mut fixed_input_size: Option<usize> = None;

    println!("secret,cycles");

    for m in 0..samples {
        for (label, attrs) in &sets {
            let message = encode_and_hash(attrs);
            assert_eq!(message.len(), 32, "digest must be 32 bytes");
            let signature =
                plum_sign::<PlumGriffinShakeFsHasher, _>(&pp, &sk, &message, &mut rng);
            let input = GuestInput {
                pp: pp.clone(),
                pk: pk.clone(),
                message,
                signature,
            };
            let bytes = bincode::serialize(&input).expect("serialize");
            match fixed_input_size {
                None => fixed_input_size = Some(bytes.len()),
                Some(n) => assert_eq!(
                    n,
                    bytes.len(),
                    "input size varied at secret={label} sample={m} — sweep invalid"
                ),
            }
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(bytes);
            let (output, report) = client
                .execute(Elf::Static(PLUM_VERIFY_SYSCALL_ELF_BYTES), stdin)
                .run()
                .expect("execute failed");
            let accepted: bool =
                bincode::deserialize(output.as_slice()).expect("decode commit");
            assert!(accepted, "rejected at secret={label} sample={m}");
            println!("{label},{}", report.total_instruction_count());
        }
        eprintln!(
            "progress: sample {}/{} per secret (input_bytes={})",
            m + 1,
            samples,
            fixed_input_size.unwrap_or(0)
        );
    }
    eprintln!("sweep complete: {} rows", sets.len() * samples);
}
