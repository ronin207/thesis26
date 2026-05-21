//! SP1 ECDSA-secp256k1 verification guest (Phase B6, classical anchor).
//!
//! Verifies a single ECDSA-secp256k1 signature over SHA-256 against a
//! provided public key and message. Commits a `bool` indicating the
//! verification outcome.
//!
//! ### Why this exists
//!
//! Anchors the thesis's four-scheme benchmark with a *classical*
//! pre-quantum primitive that the zkVM was actually built to handle
//! efficiently. The `k256` crate is patched at the workspace level
//! to route curve operations through SP1's native precompiles:
//!
//!   - `SECP256K1_ADD`, `SECP256K1_DOUBLE`, `SECP256K1_DECOMPRESS`
//!     for scalar multiplication and point recovery, and
//!   - `SHA_COMPRESS` / `SHA_EXTEND` (via patched sha2 v0.10.x) for
//!     the digest under the signature.
//!
//! Expected cost regime: **seconds**, not minutes — this is the
//! "what zkVMs do well" baseline against which PLUM's 32.53 min sits.

#![no_main]
sp1_zkvm::entrypoint!(main);

use serde::{Deserialize, Serialize};

use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};

/// Host-encoded inputs. We deserialise three byte buffers — encoding
/// conventions chosen for round-trip robustness: SEC1 (uncompressed
/// 65-byte form) for the public key, raw ASN.1 DER for the
/// signature, raw bytes for the message.
#[derive(Serialize, Deserialize)]
struct GuestInput {
    /// SEC1-encoded public key (uncompressed, 65 bytes: `0x04 || x || y`).
    pub_sec1: Vec<u8>,
    /// Arbitrary-length message that was signed.
    message: Vec<u8>,
    /// ASN.1 DER-encoded ECDSA signature.
    sig_der: Vec<u8>,
}

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input: GuestInput =
        bincode::deserialize(&bytes).expect("ecdsa guest: bincode decode failed");

    let vk = VerifyingKey::from_sec1_bytes(&input.pub_sec1)
        .expect("ecdsa guest: invalid SEC1 public key");
    let sig =
        Signature::from_der(&input.sig_der).expect("ecdsa guest: invalid DER signature");

    let accepted = vk.verify(&input.message, &sig).is_ok();
    sp1_zkvm::io::commit(&accepted);
}
