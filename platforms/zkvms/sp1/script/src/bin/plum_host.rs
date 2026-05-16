//! SP1 PLUM verification host (smoke + adversarial soundness probe).
//!
//! Three modes (selected via `PLUM_HOST_MODE`, default `execute`):
//!
//!   - `execute` — single honest verify in executor mode (no proof).
//!     Used for cycle-count measurement; baseline measurement target.
//!   - `prove` — full prove + verify round-trip. Slow.
//!   - `adversarial` — run the soundness probe: an honest verify (must
//!     accept) followed by seven tamper cases (each must reject).
//!     Empirical evidence for row (f) of the soundness property table
//!     in `docs/precompile_soundness/uint256_mul_for_fp192.md` and a
//!     regression net against precompile-introduced false-accept bugs.

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
    // Security-level sweep: λ=80 fits on 24 GB M5 Pro; λ=128 OOMs
    // (per docs/precompile_soundness measurements, May 2026).
    // Override at runtime via PLUM_SECURITY env var (80/100/128).
    let security_level: usize = std::env::var("PLUM_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let pp: PlumPublicParams = plum_setup(security_level).expect("setup");
    println!("=== PLUM-{} verify on SP1 ===", security_level);
    let (sk, pk): (PlumSecretKey, PlumPublicKey) = plum_keygen(&pp, &mut rng);

    let message = b"sp1 smoke: plum verify with SHA3 hasher".to_vec();
    let signature: PlumSignature =
        plum_sign::<PlumSha3Hasher, _>(&pp, &sk, &message, &mut rng);

    let client = ProverClient::from_env();
    let mode = std::env::var("PLUM_HOST_MODE").unwrap_or_else(|_| "execute".into());

    match mode.as_str() {
        "execute" => run_execute(&client, &pp, &pk, &message, &signature),
        "prove" => run_prove(&client, &pp, &pk, &message, &signature),
        "adversarial" => run_adversarial(&client, &pp, &sk, &pk, &message, &signature, &mut rng),
        other => panic!("unknown PLUM_HOST_MODE={other:?}; use execute, prove, or adversarial"),
    }
}

fn run_execute(
    client: &impl Prover,
    pp: &PlumPublicParams,
    pk: &PlumPublicKey,
    message: &[u8],
    signature: &PlumSignature,
) {
    let input = GuestInput {
        pp: pp.clone(),
        pk: pk.clone(),
        message: message.to_vec(),
        signature: signature.clone(),
    };
    let bytes = bincode::serialize(&input).expect("serialize input");
    println!("input bytes: {}", bytes.len());

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);

    let t = Instant::now();
    let (output, report) = client
        .execute(PLUM_VERIFY_ELF, stdin)
        .run()
        .expect("execute failed");
    let accepted: bool = bincode::deserialize(output.as_slice()).expect("decode commit");
    let total_syscalls = report.total_syscall_count();
    let uint256_mul_count = report
        .syscall_counts
        .iter()
        .find(|(code, _)| format!("{:?}", code) == "UINT256_MUL")
        .map(|(_, &n)| n)
        .unwrap_or(0);
    println!(
        "accepted={} cycles={} elapsed_ms={} syscalls={} uint256_mul={}",
        accepted,
        report.total_instruction_count(),
        t.elapsed().as_millis() as u64,
        total_syscalls,
        uint256_mul_count,
    );
    assert!(accepted, "guest rejected an honest PLUM signature");
}

fn run_prove(
    client: &impl Prover,
    pp: &PlumPublicParams,
    pk: &PlumPublicKey,
    message: &[u8],
    signature: &PlumSignature,
) {
    let input = GuestInput {
        pp: pp.clone(),
        pk: pk.clone(),
        message: message.to_vec(),
        signature: signature.clone(),
    };
    let bytes = bincode::serialize(&input).expect("serialize input");
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes);

    let t_setup = Instant::now();
    let pk_proof = client.setup(PLUM_VERIFY_ELF).expect("setup elf failed");
    println!("setup_ms={}", t_setup.elapsed().as_millis() as u64);

    let t_prove = Instant::now();
    let proof = client.prove(&pk_proof, stdin).run().expect("prove failed");
    println!("prove_ms={}", t_prove.elapsed().as_millis() as u64);

    let t_verify = Instant::now();
    client
        .verify(&proof, pk_proof.verifying_key(), None)
        .expect("verify failed");
    println!("verify_ms={}", t_verify.elapsed().as_millis() as u64);
}

// ─── Adversarial soundness probe ──────────────────────────────────────

/// One tamper case for the soundness probe. Each case applies a
/// minimal modification to one of (pk, message, signature) and asserts
/// the guest still rejects. "None" is the control (no tamper, must
/// accept) and protects against the trivial bug where the guest
/// rejects everything.
#[derive(Clone, Copy)]
enum Tamper {
    /// Control — no modification. Guest must accept.
    None,
    /// Swap pk for an unrelated keypair's pk. Guest must reject.
    WrongPk,
    /// Verify under a different message. Guest must reject.
    WrongMessage,
    /// Flip one byte in the σ_1 commitment root. Guest must reject.
    FlipRootC,
    /// Flip one byte in the first PRF tag. Guest must reject.
    FlipTTag,
    /// Perturb the first residuosity response (`o_responses[0] += 1`).
    /// Guest must reject.
    BumpOResponse,
    /// Flip the final-polynomial leading coefficient
    /// (`final_coefs[0] += 1`). Guest must reject.
    BumpFinalCoef,
}

impl Tamper {
    fn name(&self) -> &'static str {
        match self {
            Tamper::None => "none (control)",
            Tamper::WrongPk => "wrong public key",
            Tamper::WrongMessage => "wrong message",
            Tamper::FlipRootC => "flip σ_1 root byte",
            Tamper::FlipTTag => "flip PRF t_tag byte",
            Tamper::BumpOResponse => "bump o_responses[0]",
            Tamper::BumpFinalCoef => "bump final_coefs[0]",
        }
    }

    /// What the guest is supposed to return for this case.
    fn expected_accept(&self) -> bool {
        matches!(self, Tamper::None)
    }
}

fn run_adversarial(
    client: &impl Prover,
    pp: &PlumPublicParams,
    _sk: &PlumSecretKey,
    pk: &PlumPublicKey,
    message: &[u8],
    signature: &PlumSignature,
    rng: &mut ChaCha20Rng,
) {
    // Build a second, unrelated keypair for the wrong-pk case.
    let (_sk2, pk2) = plum_keygen(pp, rng);
    let alt_message = b"sp1 smoke: a DIFFERENT message that was never signed".to_vec();

    let cases = [
        Tamper::None,
        Tamper::WrongPk,
        Tamper::WrongMessage,
        Tamper::FlipRootC,
        Tamper::FlipTTag,
        Tamper::BumpOResponse,
        Tamper::BumpFinalCoef,
    ];

    println!("\n=== PLUM Verify SP1 adversarial soundness probe ===");
    println!("control honest signature length: {} bytes",
        bincode::serialize(signature).expect("serialize sig").len());
    println!();

    let mut all_pass = true;
    for case in cases {
        let mut tampered_pk = pk.clone();
        let mut tampered_msg = message.to_vec();
        let mut tampered_sig = signature.clone();
        apply_tamper(case, &mut tampered_pk, &mut tampered_msg, &mut tampered_sig, &pk2, &alt_message);

        let input = GuestInput {
            pp: pp.clone(),
            pk: tampered_pk,
            message: tampered_msg,
            signature: tampered_sig,
        };
        let bytes = bincode::serialize(&input).expect("serialize input");
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(bytes);

        let t = Instant::now();
        let (output, report) = client
            .execute(PLUM_VERIFY_ELF, stdin)
            .run()
            .expect("execute failed");
        let accepted: bool = bincode::deserialize(output.as_slice()).expect("decode commit");
        let expected = case.expected_accept();
        let pass = accepted == expected;
        if !pass {
            all_pass = false;
        }
        println!(
            "{:24}  expected={:5}  got={:5}  {:>4}  cycles={:>11}  elapsed={}ms",
            case.name(),
            expected,
            accepted,
            if pass { "PASS" } else { "FAIL" },
            report.total_instruction_count(),
            t.elapsed().as_millis() as u64,
        );
    }
    println!();
    if all_pass {
        println!("=== ALL {} CASES PASS — adversarial probe held ===", cases.len());
    } else {
        println!("=== ADVERSARIAL PROBE FAILED — at least one case did not match expected outcome ===");
        std::process::exit(1);
    }
}

fn apply_tamper(
    case: Tamper,
    pk: &mut PlumPublicKey,
    message: &mut Vec<u8>,
    sig: &mut PlumSignature,
    alt_pk: &PlumPublicKey,
    alt_message: &[u8],
) {
    use vc_pqc::primitives::field::p192::Fp192;
    match case {
        Tamper::None => {}
        Tamper::WrongPk => {
            *pk = alt_pk.clone();
        }
        Tamper::WrongMessage => {
            *message = alt_message.to_vec();
        }
        Tamper::FlipRootC => {
            sig.root_c[0] ^= 0x01;
        }
        Tamper::FlipTTag => {
            if let Some(byte) = sig.t_tags.first_mut() {
                *byte ^= 0x01;
            }
        }
        Tamper::BumpOResponse => {
            if let Some(o) = sig.o_responses.first_mut() {
                *o = o.clone() + Fp192::from_u64(1);
            }
        }
        Tamper::BumpFinalCoef => {
            if let Some(c) = sig.final_coefs.first_mut() {
                *c = c.clone() + Fp192::from_u64(1);
            }
        }
    }
}
