//! SP1 PLUM identity-axis leakage sweep (for `zkleak report`).
//!
//! THE anonymity-relevant question Wu's zkleak can answer: does the PLUM-verify
//! cycle count leak WHICH USER produced the signature? Secret = user index
//! (fresh keypair per user), observable = execute-mode cycle count of the
//! Cell-2 Griffin-syscall ELF. Same fixed message for every user; PLUM
//! signatures are constant-size (47,976 bytes at lambda=80, measured), and pp/pk
//! are fixed-size, so input size is held fixed across the sweep (zkleak's
//! "one mistake" guard).
//!
//! Per user u: keygen once, then S fresh signatures of the SAME message;
//! each executes once. CSV rows `u<u>,<cycles>` on stdout for zkleak;
//! diagnostics on stderr. A 3x repeated execution of the first witness checks
//! executor determinism (the negative control) before the sweep.
//!
//! Env: `PLUM_SECURITY` (80), `PLUM_IDSCAN_USERS` (8), `PLUM_IDSCAN_SIGS` (8).

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, SP1Stdin,
    blocking::{Prover, ProverClient},
};

use vc_pqc::signatures::plum::hasher::PlumGriffinShakeFsHasher;
use vc_pqc::signatures::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::signatures::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::signatures::plum::sign::{PlumSignature, plum_sign};

const PLUM_VERIFY_SYSCALL_ELF_BYTES: &[u8] =
    include_bytes!(env!("PLUM_VERIFY_SYSCALL_ELF_PATH"));

#[derive(Serialize, Deserialize)]
struct GuestInput {
    pp: PlumPublicParams,
    pk: PlumPublicKey,
    message: Vec<u8>,
    signature: PlumSignature,
}

fn execute_cycles(client: &impl Prover, bytes: Vec<u8>) -> (bool, u64, usize) {
    let n = bytes.len();
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);
    let (output, report) = client
        .execute(Elf::Static(PLUM_VERIFY_SYSCALL_ELF_BYTES), stdin)
        .run()
        .expect("execute failed");
    let accepted: bool = bincode::deserialize(output.as_slice()).expect("decode commit");
    (accepted, report.total_instruction_count(), n)
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("PLUM_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let users: usize = std::env::var("PLUM_IDSCAN_USERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);
    let sigs: usize = std::env::var("PLUM_IDSCAN_SIGS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8);

    eprintln!(
        "=== PLUM-{security} identity-axis sweep: {users} users x {sigs} sigs, fixed message, syscall ELF ==="
    );

    // pp shared by all users (system parameter, public); message fixed.
    let mut setup_rng = ChaCha20Rng::seed_from_u64(0x4944_5343_414e_5050); // "IDSCANPP"
    let pp: PlumPublicParams = plum_setup(security).expect("setup");
    let message = b"zkleak identity axis: fixed message across all users".to_vec();
    let _ = &mut setup_rng;

    let client = ProverClient::from_env();

    // Negative control: the SAME witness executed 3x must give identical cycles.
    {
        let mut rng = ChaCha20Rng::seed_from_u64(0x4944_5343_414e_0000);
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        let sig = plum_sign::<PlumGriffinShakeFsHasher, _>(&pp, &sk, &message, &mut rng);
        let input = GuestInput {
            pp: pp.clone(),
            pk: pk.clone(),
            message: message.clone(),
            signature: sig,
        };
        let bytes = bincode::serialize(&input).expect("serialize");
        let runs: Vec<u64> = (0..3)
            .map(|_| execute_cycles(&client, bytes.clone()).1)
            .collect();
        eprintln!("negative-control (same witness 3x): cycles={runs:?}");
        assert!(
            runs.windows(2).all(|w| w[0] == w[1]),
            "executor nondeterminism detected — sweep would be invalid"
        );
    }

    println!("secret,cycles");

    for u in 0..users {
        // Fresh keypair per user; per-user rng so the sweep is reproducible.
        let mut rng = ChaCha20Rng::seed_from_u64(0x4944_5343_414e_0000 ^ (1000 + u as u64));
        let (sk, pk) = plum_keygen(&pp, &mut rng);
        for s in 0..sigs {
            let sig = plum_sign::<PlumGriffinShakeFsHasher, _>(&pp, &sk, &message, &mut rng);
            let input = GuestInput {
                pp: pp.clone(),
                pk: pk.clone(),
                message: message.clone(),
                signature: sig,
            };
            let bytes = bincode::serialize(&input).expect("serialize");
            let (accepted, cycles, input_bytes) = execute_cycles(&client, bytes);
            assert!(accepted, "rejected at user={u} sig={s}");
            println!("u{u},{cycles}");
            eprintln!("user={u} sig={s} cycles={cycles} input_bytes={input_bytes}");
        }
    }
    eprintln!("sweep complete");
}
