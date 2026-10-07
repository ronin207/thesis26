//! SP1 PLUM linkability sweep — Test 1 of HANDOFF-linkability-test.md.
//!
//! Question: given T cycle-count observations of showings from ONE credential,
//! can an observer identify WHICH credential? Distinguishes (a) no per-key
//! component from (b) a per-key component masked by per-showing randomness —
//! the case zkleak's deterministic model cannot see and value-overlap cannot
//! exclude.
//!
//! Protocol (per the handoff brief):
//!   - C >= 3 credentials (fresh PLUM keypair each), shared pp, fixed message.
//!   - M >= 200 showings per credential; each showing = ONE fresh PLUM
//!     signature (fresh randomness; the rng advances per sign) verified by the
//!     Cell-2 Griffin-syscall ELF in execute mode.
//!   - INTERLEAVED: outer loop over showing index, inner over credentials.
//!   - Input size asserted CONSTANT across all rows (PLUM signatures are
//!     constant-size); any deviation aborts the run.
//!   - CSV `credential,cycles` on stdout for linkability.py; progress on stderr.
//!
//! Proxy note (stated, not hidden): a full BDEC showing executes k+2 such
//! verifies; this sweep measures ONE verify per showing. A per-key component
//! in the verify distribution would appear in every term of the k+2 sum, so
//! the single-verify sweep is the more sensitive instrument per unit time.
//!
//! Env: `PLUM_SECURITY` (80), `LINK_CREDS` (3), `LINK_SHOWINGS` (200).

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, SP1Stdin,
    blocking::{Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinShakeFsHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, PlumSecretKey, plum_keygen};
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

fn main() {
    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("PLUM_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let creds: usize = std::env::var("LINK_CREDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let showings: usize = std::env::var("LINK_SHOWINGS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    eprintln!(
        "=== PLUM-{security} linkability sweep: {creds} credentials x {showings} showings, \
         interleaved, fixed message, syscall ELF ==="
    );

    let pp: PlumPublicParams = plum_setup(security).expect("setup");
    let message = b"linkability test: fixed showing statement across all credentials".to_vec();

    // One keypair per credential; per-credential rng advances across showings
    // so every signature uses fresh randomness (never reused, never reseeded).
    let mut rngs: Vec<ChaCha20Rng> = (0..creds)
        .map(|c| ChaCha20Rng::seed_from_u64(0x4c49_4e4b_0000_0000 ^ c as u64))
        .collect();
    let keys: Vec<(PlumSecretKey, PlumPublicKey)> = rngs
        .iter_mut()
        .map(|rng| plum_keygen(&pp, rng))
        .collect();
    eprintln!("keygen done for {creds} credentials");

    let client = ProverClient::from_env();
    let mut fixed_input_size: Option<usize> = None;

    println!("credential,cycles");

    // Interleaved: showing m of every credential before showing m+1 of any.
    for m in 0..showings {
        for c in 0..creds {
            let (sk, pk) = &keys[c];
            let signature =
                plum_sign::<PlumGriffinShakeFsHasher, _>(&pp, sk, &message, &mut rngs[c]);
            let input = GuestInput {
                pp: pp.clone(),
                pk: pk.clone(),
                message: message.clone(),
                signature,
            };
            let bytes = bincode::serialize(&input).expect("serialize");
            match fixed_input_size {
                None => fixed_input_size = Some(bytes.len()),
                Some(n) => assert_eq!(
                    n,
                    bytes.len(),
                    "input size varied at cred={c} showing={m} — sweep invalid"
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
            assert!(accepted, "rejected at cred={c} showing={m}");
            let cycles = report.total_instruction_count();
            println!("cred_{c},{cycles}");
        }
        if (m + 1) % 10 == 0 {
            eprintln!(
                "progress: showing {}/{} per credential (input_bytes={})",
                m + 1,
                showings,
                fixed_input_size.unwrap_or(0)
            );
        }
    }
    eprintln!("sweep complete: {} rows, input_bytes={:?}", creds * showings, fixed_input_size);
}
