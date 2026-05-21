//! Phase B6 PQ-scheme + classical benchmark host.
//!
//! Dispatches a single signature-verification workload to one of four
//! SP1 guest ELFs (ECDSA-secp256k1 / SPHINCS+ / Dilithium / Loquat),
//! generates a valid test triple natively, ships it to the guest via
//! `SP1Stdin`, and reports cycles + syscall counts (execute mode) or
//! prove/verify wall times (prove mode).
//!
//! Selection:
//!   - `SCHEME=ecdsa|sphincs|dilithium|loquat`  (default: ecdsa)
//!   - `MODE=execute|prove`                      (default: execute)
//!
//! The shape mirrors `plum_host.rs` so the four-scheme + PLUM
//! benchmark table can be produced from one driver pattern.
//!
//! Successive Phase B6 commits add the SPHINCS+ / Dilithium / Loquat
//! arms; ECDSA lands first as the classical anchor.

use std::time::Instant;

use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    Elf, ProvingKey, SP1Stdin,
    blocking::{ProveRequest, Prover, ProverClient},
};

const ECDSA_VERIFY_ELF_BYTES: &[u8] =
    include_bytes!(env!("ECDSA_VERIFY_ELF_PATH"));
const SPHINCS_VERIFY_ELF_BYTES: &[u8] =
    include_bytes!(env!("SPHINCS_VERIFY_ELF_PATH"));
const DILITHIUM_VERIFY_ELF_BYTES: &[u8] =
    include_bytes!(env!("DILITHIUM_VERIFY_ELF_PATH"));
const LOQUAT_VERIFY_ELF_BYTES: &[u8] =
    include_bytes!(env!("LOQUAT_VERIFY_ELF_PATH"));

// ─── Per-scheme guest-input encodings ────────────────────────────────

#[derive(Serialize, Deserialize)]
struct EcdsaGuestInput {
    pub_sec1: Vec<u8>,
    message: Vec<u8>,
    sig_der: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SphincsGuestInput {
    leaf: [u8; 32],
    siblings: Vec<[u8; 32]>,
    directions: Vec<u8>,
    expected_root: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct DilithiumGuestInput {
    seed: [u8; 32],
    expected_checksum: i64,
}

#[derive(Serialize, Deserialize)]
struct LoquatGuestInput {
    message: Vec<u8>,
    signature: vc_pqc::signatures::loquat::sign::LoquatSignature,
    public_key: Vec<vc_pqc::signatures::loquat::field_utils::F>,
    params: vc_pqc::signatures::loquat::setup::LoquatPublicParams,
}

// ─── Scheme dispatch ────────────────────────────────────────────────

/// Produces a (scheme-label, ELF, bincode-serialised guest input)
/// triple for the selected scheme.
fn build_workload(scheme: &str) -> (&'static str, Elf, Vec<u8>) {
    match scheme {
        "ecdsa" => {
            let (label, bytes) = build_ecdsa_workload();
            (label, Elf::Static(ECDSA_VERIFY_ELF_BYTES), bytes)
        }
        "sphincs" => {
            let (label, bytes) = build_sphincs_workload();
            (label, Elf::Static(SPHINCS_VERIFY_ELF_BYTES), bytes)
        }
        "dilithium" => {
            let (label, bytes) = build_dilithium_workload();
            (label, Elf::Static(DILITHIUM_VERIFY_ELF_BYTES), bytes)
        }
        "loquat" => {
            let (label, bytes) = build_loquat_workload();
            (label, Elf::Static(LOQUAT_VERIFY_ELF_BYTES), bytes)
        }
        other => panic!(
            "unknown SCHEME={other:?}; supported: ecdsa, sphincs, dilithium, loquat"
        ),
    }
}

fn build_ecdsa_workload() -> (&'static str, Vec<u8>) {
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

    // Deterministic seed so every run produces the same workload —
    // matters for execute-mode reproducibility of cycle counts.
    let mut rng = StdRng::seed_from_u64(0x5043_4F45_4344_5341u64); // "PCOECDSA"
    let sk = SigningKey::random(&mut rng);
    let vk: VerifyingKey = (&sk).into();

    let message = b"phase-B6 ecdsa classical anchor: 32 byte message ok".to_vec();
    let sig: Signature = sk.sign(&message);

    // SEC1 uncompressed encoding (65-byte 0x04 || x || y) via the
    // inherent VerifyingKey method.
    let pub_sec1 = vk.to_encoded_point(false).as_bytes().to_vec();
    let sig_der = sig.to_der().as_bytes().to_vec();

    let input = EcdsaGuestInput { pub_sec1, message, sig_der };
    let bytes = bincode::serialize(&input).expect("ecdsa: serialize guest input");
    ("ecdsa-secp256k1 + sha256", bytes)
}

fn build_sphincs_workload() -> (&'static str, Vec<u8>) {
    use sha2::{Digest, Sha256};

    // Build a 22-level SHA-256 Merkle authentication path. Mirrors
    // the SLH-DSA-128f FORS-tree height; the workload shape is the
    // dominant cost of SLH-DSA verification.
    const DEPTH: usize = 22;
    let mut rng = StdRng::seed_from_u64(0x5350_4849_4E43_5350u64); // "SPHINCSP"
    let leaf: [u8; 32] = {
        let mut b = [0u8; 32];
        use rand::RngCore;
        rng.fill_bytes(&mut b);
        b
    };
    let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(DEPTH);
    let mut directions: Vec<u8> = Vec::with_capacity(DEPTH);
    use rand::RngCore;
    for _ in 0..DEPTH {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        siblings.push(s);
        directions.push((rng.next_u32() & 1) as u8);
    }
    // Compute expected root via the same logic the guest will run.
    let mut acc = leaf;
    for (sib, dir) in siblings.iter().zip(directions.iter()) {
        let mut h = Sha256::new();
        if *dir == 0 {
            h.update(acc);
            h.update(sib);
        } else {
            h.update(sib);
            h.update(acc);
        }
        let out = h.finalize();
        acc.copy_from_slice(&out);
    }
    let expected_root = acc;

    let input = SphincsGuestInput { leaf, siblings, directions, expected_root };
    let bytes = bincode::serialize(&input).expect("sphincs: serialize guest input");
    ("sphincs+/slh-dsa proxy (sha256 Merkle path, depth 22)", bytes)
}

fn build_dilithium_workload() -> (&'static str, Vec<u8>) {
    // Pre-compute the expected NTT-style checksum so the guest can
    // verify its work. Mirror of the guest's poly_mul_mod / seed
    // loop; identical arithmetic produces identical checksums.
    const Q: i64 = 8_380_417;
    const N: usize = 256;
    const NUM_POLYS_PER_VERIFY: usize = 17;

    let seed: [u8; 32] = [0x42; 32];

    fn fill_poly_from_seed(seed: &[u8; 32], salt: u8, poly: &mut [i64; N]) {
        let mut state: u64 = u64::from_le_bytes(seed[..8].try_into().unwrap())
            ^ ((salt as u64) << 56);
        for v in poly.iter_mut() {
            state =
                state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *v = (state as i64).rem_euclid(Q);
        }
    }
    fn poly_mul_mod(a: &[i64; N], b: &[i64; N], out: &mut [i64; N]) {
        *out = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let k = (i + j) % N;
                let sign = if i + j >= N { -1 } else { 1 };
                let prod = (a[i].wrapping_mul(b[j])) % Q;
                out[k] = (out[k] + sign * prod).rem_euclid(Q);
            }
        }
    }

    let mut polys: [[i64; N]; NUM_POLYS_PER_VERIFY] = [[0; N]; NUM_POLYS_PER_VERIFY];
    for (i, poly) in polys.iter_mut().enumerate() {
        fill_poly_from_seed(&seed, i as u8, poly);
    }
    let mut acc = polys[0];
    let mut tmp = [0i64; N];
    for i in 1..NUM_POLYS_PER_VERIFY {
        poly_mul_mod(&acc, &polys[i], &mut tmp);
        acc = tmp;
    }
    let mut checksum = 0i64;
    for v in acc.iter() {
        checksum = (checksum + *v).rem_euclid(Q);
    }

    let input = DilithiumGuestInput { seed, expected_checksum: checksum };
    let bytes = bincode::serialize(&input).expect("dilithium: serialize guest input");
    ("ml-dsa proxy (ntt-style poly mul over q=8380417, 17 polys)", bytes)
}

fn build_loquat_workload() -> (&'static str, Vec<u8>) {
    use vc_pqc::signatures::loquat::keygen::keygen_with_params;
    use vc_pqc::signatures::loquat::setup::loquat_setup;
    use vc_pqc::signatures::loquat::sign::loquat_sign;

    // λ = 128 is the smallest fully paper-validated Loquat parameter
    // surface in the in-tree implementation (tests use λ=128).
    let params = loquat_setup(128).expect("loquat: setup");
    let keypair = keygen_with_params(&params).expect("loquat: keygen");

    let message = b"phase-B6 loquat same-family anchor (Legendre-PRF + in-tree hash)".to_vec();
    let signature =
        loquat_sign(&message, &keypair, &params).expect("loquat: sign");

    let input = LoquatGuestInput {
        message,
        signature,
        public_key: keypair.public_key,
        params,
    };
    let bytes = bincode::serialize(&input).expect("loquat: serialize guest input");
    ("loquat λ=128 (in-tree implementation; Legendre-PRF + Griffin hash)", bytes)
}

// ─── Modes ──────────────────────────────────────────────────────────

fn main() {
    sp1_sdk::utils::setup_logger();

    let scheme = std::env::var("SCHEME").unwrap_or_else(|_| "ecdsa".into());
    let mode = std::env::var("MODE").unwrap_or_else(|_| "execute".into());

    let (label, elf, input_bytes) = build_workload(&scheme);
    println!("=== bench_pqc — scheme: {label} ===");
    println!("input bytes: {}", input_bytes.len());

    let client = ProverClient::from_env();

    match mode.as_str() {
        "execute" => run_execute(&client, elf, &input_bytes, &scheme),
        "prove" => run_prove(&client, elf, &input_bytes, &scheme),
        other => panic!("unknown MODE={other:?}; use execute or prove"),
    }
}

fn count_syscall(report: &sp1_sdk::ExecutionReport, code_name: &str) -> u64 {
    report
        .syscall_counts
        .iter()
        .find(|(code, _)| format!("{:?}", code) == code_name)
        .map(|(_, &n)| n)
        .unwrap_or(0)
}

fn run_execute(client: &impl Prover, elf: Elf, input_bytes: &[u8], scheme: &str) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input_bytes.to_vec());

    let t = Instant::now();
    let (output, report) = client.execute(elf, stdin).run().expect("execute failed");
    let elapsed_ms = t.elapsed().as_millis() as u64;
    let accepted: bool =
        bincode::deserialize(output.as_slice()).expect("decode commit");

    let cycles = report.total_instruction_count();
    let total_syscalls = report.total_syscall_count();
    let secp_add = count_syscall(&report, "SECP256K1_ADD");
    let secp_double = count_syscall(&report, "SECP256K1_DOUBLE");
    let secp_decompress = count_syscall(&report, "SECP256K1_DECOMPRESS");
    let sha_compress = count_syscall(&report, "SHA_COMPRESS");
    let sha_extend = count_syscall(&report, "SHA_EXTEND");
    let keccak = count_syscall(&report, "KECCAK_PERMUTE");
    let uint256_mul = count_syscall(&report, "UINT256_MUL");

    println!(
        "scheme={scheme} accepted={accepted} cycles={cycles} elapsed_ms={elapsed_ms} \
         total_syscalls={total_syscalls}",
    );
    println!(
        "precompile use:  SECP256K1_ADD={secp_add}  SECP256K1_DOUBLE={secp_double}  \
         SECP256K1_DECOMPRESS={secp_decompress}",
    );
    println!(
        "                 SHA_COMPRESS={sha_compress}  SHA_EXTEND={sha_extend}  \
         KECCAK_PERMUTE={keccak}  UINT256_MUL={uint256_mul}",
    );
    assert!(accepted, "guest rejected an honest signature ({scheme})");
}

fn run_prove(client: &impl Prover, elf: Elf, input_bytes: &[u8], scheme: &str) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input_bytes.to_vec());

    let t_setup = Instant::now();
    let pk_proof = client.setup(elf).expect("setup elf failed");
    println!("setup_ms={}", t_setup.elapsed().as_millis() as u64);

    let t_prove = Instant::now();
    let proof = client.prove(&pk_proof, stdin).run().expect("prove failed");
    let prove_ms = t_prove.elapsed().as_millis() as u64;
    println!(
        "scheme={scheme} prove_ms={prove_ms} (= {:.2} min = {:.2} h)",
        prove_ms as f64 / 60_000.0,
        prove_ms as f64 / 3_600_000.0,
    );

    let t_verify = Instant::now();
    client
        .verify(&proof, pk_proof.verifying_key(), None)
        .expect("verify failed");
    println!("verify_ms={}", t_verify.elapsed().as_millis() as u64);
}
