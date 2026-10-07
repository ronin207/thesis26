//! SP1 PLUM message-axis sweep — Test A of HANDOFF-2-followup-tests.md (priority).
//!
//! Question: does the verify cycle count depend on WHAT is being signed/proven?
//! Round 1 fixed one message for all 600 showings, isolating the credential;
//! this sweep fixes ONE credential and varies the MESSAGE. If cost tracks the
//! message, a session becomes recognisable across contexts — a different
//! privacy property from unlinkability, untested until now. Also the candidate
//! explanation for the unexplained 904,587-cycle per-showing sd.
//!
//! Protocol (per the handoff):
//!   - ONE credential (keygen once); pp fixed; fresh randomness per showing.
//!   - 6 messages, all EXACTLY 32 bytes (length cannot confound):
//!       flip1 / flip2 / flip4 — the base message with 1, 2, 4 bits flipped
//!       rndA / rndB / rndC   — independent random 32-byte strings
//!   - M showings per message (default 200), INTERLEAVED: showing m of every
//!     message before showing m+1 of any.
//!   - Serialized input asserted byte-identical across all rows.
//!   - CSV `message_label,cycles` on stdout for linkability.py.
//!
//! Reading: accuracy flat at 16.7% baseline through T=50 => cost is
//! message-independent. Climbing => cost tracks the message (a finding, not a
//! defect). Flips clustering apart from randoms => tracks CONTENT.
//!
//! Env: `PLUM_SECURITY` (80), `MSG_SHOWINGS` (200).

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
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

/// Flip `bits` distinct bits of `base`, spread across the buffer.
fn flip_bits(base: &[u8; 32], bits: usize) -> Vec<u8> {
    let mut m = base.to_vec();
    for i in 0..bits {
        let bit_index = i * 61 % 256; // distinct, spread positions
        m[bit_index / 8] ^= 1 << (bit_index % 8);
    }
    m
}

fn main() {
    sp1_sdk::utils::setup_logger();

    let security: usize = std::env::var("PLUM_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let showings: usize = std::env::var("MSG_SHOWINGS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    // Deterministic message set, all exactly 32 bytes.
    let mut msg_rng = ChaCha20Rng::seed_from_u64(0x4d53_4753_4341_4e00); // "MSGSCAN"
    let mut base = [0u8; 32];
    msg_rng.fill_bytes(&mut base);
    let mut rnd = || {
        let mut b = vec![0u8; 32];
        msg_rng.fill_bytes(&mut b);
        b
    };
    let messages: Vec<(&'static str, Vec<u8>)> = vec![
        ("flip1", flip_bits(&base, 1)),
        ("flip2", flip_bits(&base, 2)),
        ("flip4", flip_bits(&base, 4)),
        ("rndA", rnd()),
        ("rndB", rnd()),
        ("rndC", rnd()),
    ];
    for (l, m) in &messages {
        assert_eq!(m.len(), 32, "message {l} must be exactly 32 bytes");
    }

    eprintln!(
        "=== PLUM-{security} message-axis sweep (Test A): 1 credential, 6 messages x {showings} showings, interleaved ==="
    );

    let mut rng = ChaCha20Rng::seed_from_u64(0x4d53_4753_4341_4e01);
    let pp: PlumPublicParams = plum_setup(security).expect("setup");
    let (sk, pk) = plum_keygen(&pp, &mut rng);
    eprintln!("keygen done (ONE credential; only the message varies)");

    let client = ProverClient::from_env();
    let mut fixed_input_size: Option<usize> = None;

    println!("message_label,cycles");

    for m in 0..showings {
        for (label, message) in &messages {
            let signature =
                plum_sign::<PlumGriffinShakeFsHasher, _>(&pp, &sk, message, &mut rng);
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
                    "input size varied at message={label} showing={m} — sweep invalid"
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
            assert!(accepted, "rejected at message={label} showing={m}");
            println!("{label},{}", report.total_instruction_count());
        }
        if (m + 1) % 10 == 0 {
            eprintln!(
                "progress: showing {}/{} per message (input_bytes={})",
                m + 1,
                showings,
                fixed_input_size.unwrap_or(0)
            );
        }
    }
    eprintln!(
        "sweep complete: {} rows, input_bytes={:?}",
        6 * showings,
        fixed_input_size
    );
}
