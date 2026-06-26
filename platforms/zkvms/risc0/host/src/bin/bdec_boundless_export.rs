//! Export a BDEC guest ELF + serde-encoded input to files for submission to the
//! Boundless proving network (docs.boundless.network).
//!
//! This tool does NO wallet / funding / payment / network work. It only:
//!   1. generates the witness+statement for a chosen relation (native PLUM),
//!   2. serde-encodes it exactly as the guest's `env::read()` expects,
//!   3. writes `guest.elf` and `input.bin`, and
//!   4. validates them locally with the executor (free, no proof) so a *paid*
//!      Boundless submission is never wasted on a malformed input.
//!
//! The wallet, Sepolia funds, storage credentials, and the paid `boundless`
//! submit are the operator's to run. See the printed manifest for the exact
//! request command and the image ID (needed for on-chain receipt verification).
//!
//! Usage:
//!   BDEC_RELATION=plum-verify|cregen|showcre [BDEC_SHOWCRE_K=2] \
//!   [BDEC_HOST_SECURITY=80] bdec_boundless_export
//!
//! Recommended order: `plum-verify` first (smallest, cheapest Boundless smoke
//! test of the whole submit->prove->Groth16 pipeline), then `cregen`, then
//! `showcre`.

use std::fs;
use std::path::PathBuf;

use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use risc0_zkvm::{ExecutorEnv, default_executor};
use serde::Serialize;
use sha2::{Digest, Sha256};

use methods::{
    BDEC_CREDGEN_PLUM_GRIFFIN_ELF, BDEC_CREDGEN_PLUM_GRIFFIN_ID, BDEC_SHOWCRE_PLUM_GRIFFIN_ELF,
    BDEC_SHOWCRE_PLUM_GRIFFIN_ID, PLUM_VERIFY_GRIFFIN_ELF, PLUM_VERIFY_GRIFFIN_ID,
};
use vc_pqc::plum::hasher::PlumGriffinHasher;
use vc_pqc::plum::keygen::{PlumPublicKey, plum_keygen};
use vc_pqc::plum::setup::{PlumPublicParams, plum_setup};
use vc_pqc::plum::sign::{PlumSignature, plum_sign};

// Input structs must match each guest's `GuestInput` field-for-field and in
// order, because risc0 serde encodes by declaration order.

#[derive(Serialize)]
struct PlumVerifyInput {
    pp: PlumPublicParams,
    pk: PlumPublicKey,
    message: Vec<u8>,
    signature: PlumSignature,
}

#[derive(Serialize)]
struct CredGenInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    h_u_ta: Vec<u8>,
    c_u_ta: PlumSignature,
    ppk_u_ta: Vec<u8>,
    psk_u_ta: PlumSignature,
}

#[derive(Serialize)]
struct ShowCreInput {
    pp: PlumPublicParams,
    pk_u: PlumPublicKey,
    nym_msgs: Vec<Vec<u8>>,
    nym_sigs: Vec<PlumSignature>,
    nym_uv_msg: Vec<u8>,
    nym_uv_sig: PlumSignature,
    show_msg: Vec<u8>,
    show_sig: PlumSignature,
}

fn det_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut buf = vec![0u8; n];
    rng.fill_bytes(&mut buf);
    buf
}

fn sha(tag: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(tag);
    h.finalize().to_vec()
}

fn main() {
    let relation = std::env::var("BDEC_RELATION").unwrap_or_else(|_| "plum-verify".to_string());
    let security: usize = std::env::var("BDEC_HOST_SECURITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(80);
    let k: usize = std::env::var("BDEC_SHOWCRE_K")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&k: &usize| k >= 1)
        .unwrap_or(2);

    let pp = plum_setup(security).expect("plum_setup failed");
    let mut kg = ChaCha20Rng::seed_from_u64(0x424F_554E_444C_0001); // "BOUNDL\0\x01"
    let (sk_u, pk_u) = plum_keygen(&pp, &mut kg);
    let mut sr = ChaCha20Rng::seed_from_u64(0x424F_554E_444C_0003);

    // Build the relation-specific input, serde-encode it, and pick the ELF/ID.
    let (words, elf, image_id, label): (Vec<u32>, &[u8], [u32; 8], String) = match relation
        .as_str()
    {
        "plum-verify" => {
            let message = sha(b"boundless-plum-verify-message-v1");
            let signature = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &message, &mut sr);
            let input = PlumVerifyInput {
                pp: pp.clone(),
                pk: pk_u.clone(),
                message,
                signature,
            };
            let w = risc0_zkvm::serde::to_vec(&input).expect("serde encode");
            (
                w,
                PLUM_VERIFY_GRIFFIN_ELF,
                PLUM_VERIFY_GRIFFIN_ID,
                "plum-verify (1 verification)".into(),
            )
        }
        "cregen" => {
            let h_u_ta = sha(b"bdec-cregen-attribute-hash-v1");
            let ppk_u_ta = det_bytes(0x4352_4547_0000_0002, 32);
            let c_u_ta = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &h_u_ta, &mut sr);
            let psk_u_ta = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &ppk_u_ta, &mut sr);
            let input = CredGenInput {
                pp: pp.clone(),
                pk_u: pk_u.clone(),
                h_u_ta,
                c_u_ta,
                ppk_u_ta,
                psk_u_ta,
            };
            let w = risc0_zkvm::serde::to_vec(&input).expect("serde encode");
            (
                w,
                BDEC_CREDGEN_PLUM_GRIFFIN_ELF,
                BDEC_CREDGEN_PLUM_GRIFFIN_ID,
                "cregen (2 verifications)".into(),
            )
        }
        "showcre" => {
            let nym_msgs: Vec<Vec<u8>> =
                (0..k).map(|j| det_bytes(0x5359_4D00 ^ j as u64, 32)).collect();
            let nym_uv_msg = det_bytes(0x5359_4D5F_5556, 32);
            let show_msg = sha(b"bdec-showcre-disclosed-attributes-A-down-v1");
            let nym_sigs: Vec<PlumSignature> = nym_msgs
                .iter()
                .map(|m| plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, m, &mut sr))
                .collect();
            let nym_uv_sig = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &nym_uv_msg, &mut sr);
            let show_sig = plum_sign::<PlumGriffinHasher, _>(&pp, &sk_u, &show_msg, &mut sr);
            let input = ShowCreInput {
                pp: pp.clone(),
                pk_u: pk_u.clone(),
                nym_msgs,
                nym_sigs,
                nym_uv_msg,
                nym_uv_sig,
                show_msg,
                show_sig,
            };
            let w = risc0_zkvm::serde::to_vec(&input).expect("serde encode");
            (
                w,
                BDEC_SHOWCRE_PLUM_GRIFFIN_ELF,
                BDEC_SHOWCRE_PLUM_GRIFFIN_ID,
                format!("showcre k={k} ({} verifications)", k + 2),
            )
        }
        other => panic!("unknown BDEC_RELATION={other:?}; use plum-verify | cregen | showcre"),
    };

    // Serde words -> little-endian bytes (the raw stdin Boundless feeds the guest).
    let input_bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();

    // Local validation: feed the EXACT encoded words to the executor and run the
    // guest. If this rejects, the bytes are malformed and a paid submit would be
    // wasted. Execute mode is free and machine-independent.
    println!("validating exported input locally against {label} ...");
    let env = ExecutorEnv::builder()
        .write_slice(&words)
        .build()
        .expect("build env");
    let session = default_executor()
        .execute(env, elf)
        .expect("local execute of exported input FAILED — input bytes are malformed");
    let cycles = session.cycles();

    // Write the artifacts.
    let dir = PathBuf::from("boundless_export").join(relation.replace("plum-verify", "plum_verify"));
    fs::create_dir_all(&dir).expect("mkdir");
    fs::write(dir.join("guest.elf"), elf).expect("write elf");
    fs::write(dir.join("input.bin"), &input_bytes).expect("write input");

    let image_id_hex: String = image_id.iter().map(|w| format!("{w:08x}")).collect();
    let manifest = format!(
        "Boundless export — {label}\n\
         relation         = {relation}\n\
         security_level   = {security}\n\
         guest.elf bytes  = {}\n\
         input.bin bytes  = {}\n\
         execute cycles   = {cycles}\n\
         image_id (hex)   = {image_id_hex}\n\
         \n\
         Files validated locally (executor accepted the input). To request a\n\
         Groth16 proof on Boundless (you run this; it signs an on-chain tx and\n\
         pays), with your funded Sepolia wallet:\n\
         \n\
           export RPC_URL=...           # e.g. an Alchemy Sepolia endpoint\n\
           export PRIVATE_KEY=...        # YOUR throwaway funded wallet key\n\
           export PINATA_JWT=...         # or S3/GCS; needed to upload the >1kB ELF\n\
           boundless request-proof \\\n\
             --program {}/guest.elf \\\n\
             --stdin   {}/input.bin \\\n\
             --groth16\n\
         \n\
         Or via the boundless-market Rust SDK:\n\
           client.new_request().with_program(<elf>).with_stdin(<input>).with_groth16_proof()\n\
         then client.submit(req) and client.wait_for_request_fulfillment(...).\n",
        elf.len(),
        input_bytes.len(),
        dir.display(),
        dir.display(),
    );
    fs::write(dir.join("manifest.txt"), &manifest).expect("write manifest");

    println!("\n{manifest}");
    println!("exported to: {}/", dir.display());
}
