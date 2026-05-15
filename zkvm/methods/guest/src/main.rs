#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vc_pqc::loquat::{
    field_utils::{self, F},
    griffin::{GRIFFIN_STATE_WIDTH, griffin_permutation_raw},
    loquat_verify,
    merkle::MerkleTree,
    LoquatPublicParams,
    LoquatSignature,
};

risc0_zkvm::guest::entry!(main);

#[derive(Serialize, Deserialize)]
struct BdecPseudonymKeyInput {
    public: Vec<u8>,
    signature: LoquatSignature,
}

#[derive(Serialize, Deserialize, Copy, Clone)]
enum AttributeCommitmentTypeInput {
    HashListSha256,
    MerkleRootGriffin,
}

#[derive(Serialize, Deserialize)]
struct BdecCredentialInput {
    pseudonym: BdecPseudonymKeyInput,
    attributes: Vec<String>,
    attribute_hash: [u8; 32],
    attribute_commitment_type: AttributeCommitmentTypeInput,
    credential_signature: LoquatSignature,
}

#[derive(Serialize, Deserialize)]
struct BdecAttributeMerkleProofInput {
    credential_index: usize,
    attribute: String,
    leaf_index: usize,
    auth_path: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
enum PolicyPredicateInput {
    GteI64 { key: String, min_value: i64 },
    OneOf { key: String, allowed_values: Vec<String> },
}

#[derive(Default, Serialize, Deserialize)]
struct PolicyInputData {
    predicates: Vec<PolicyPredicateInput>,
}

#[derive(Serialize, Deserialize)]
struct GuestInput {
    params: LoquatPublicParams,
    user_public_key: Vec<F>,
    credentials: Vec<BdecCredentialInput>,
    verifier_pseudonym: BdecPseudonymKeyInput,
    disclosed_attributes: Vec<String>,
    attribute_proofs: Vec<BdecAttributeMerkleProofInput>,
    disclosure_hash: [u8; 32],
    shown_credential_signature: LoquatSignature,
    revocation_root: [u8; 32],
    revocation_depth: usize,
    revocation_auth_path: Vec<[u8; 32]>,
    policy: Option<PolicyInputData>,
}

#[derive(Default, Serialize, Deserialize)]
struct Counters {
    loquat_verifies: u32,
    hash_calls: u32,
    merkle_nodes: u32,
}

#[derive(Serialize, Deserialize)]
struct GuestOutput {
    statement: PublicStatement,
    credential_checks_passed: bool,
    attribute_checks_passed: bool,
    revocation_check_passed: bool,
    policy_checks_passed: bool,
    counters: Counters,
}

#[derive(Serialize, Deserialize)]
struct PublicStatement {
    verifier_pseudonym_public: Vec<u8>,
    shown_credential_signature_hash: [u8; 32],
    disclosure_hash: [u8; 32],
    disclosed_attributes: Vec<String>,
    ta_pseudonym_publics: Vec<Vec<u8>>,
}

fn main() {
    let input: GuestInput = env::read();
    let mut counters = Counters::default();

    if input.credentials.is_empty() {
        panic!("at least one credential is required");
    }

    let mut credential_checks_passed = true;
    for credential in &input.credentials {
        if matches!(
            credential.attribute_commitment_type,
            AttributeCommitmentTypeInput::HashListSha256
        ) {
            let expected = hash_attributes(&credential.attributes, &mut counters);
            if expected != credential.attribute_hash {
                credential_checks_passed = false;
                break;
            }
        }

        verify_loquat_signature(
            &credential.attribute_hash,
            &credential.credential_signature,
            &input.user_public_key,
            &input.params,
            &mut counters,
        );

        verify_loquat_signature(
            &credential.pseudonym.public,
            &credential.pseudonym.signature,
            &input.user_public_key,
            &input.params,
            &mut counters,
        );
    }

    verify_loquat_signature(
        &input.verifier_pseudonym.public,
        &input.verifier_pseudonym.signature,
        &input.user_public_key,
        &input.params,
        &mut counters,
    );

    let recomputed_hash = hash_attributes(&input.disclosed_attributes, &mut counters);
    if recomputed_hash != input.disclosure_hash {
        panic!("disclosure hash mismatch");
    }

    verify_loquat_signature(
        &input.disclosure_hash,
        &input.shown_credential_signature,
        &input.user_public_key,
        &input.params,
        &mut counters,
    );

    let attribute_checks_passed = if input.attribute_proofs.is_empty() {
        if input.credentials.iter().any(|credential| {
            matches!(
                credential.attribute_commitment_type,
                AttributeCommitmentTypeInput::MerkleRootGriffin
            )
        }) {
            false
        } else {
            ensure_disclosure_subset(&input.credentials, &input.disclosed_attributes)
        }
    } else {
        verify_attribute_proofs(
            &input.credentials,
            &input.attribute_proofs,
            &input.disclosed_attributes,
            &mut counters,
        )
    };

    let revocation_check_passed = verify_non_revocation(
        &input.user_public_key,
        &input.revocation_root,
        input.revocation_depth,
        &input.revocation_auth_path,
        &mut counters,
    );

    let policy_checks_passed = match input.policy.as_ref() {
        Some(policy) => evaluate_policy(&input.disclosed_attributes, policy),
        None => true,
    };

    if !credential_checks_passed
        || !attribute_checks_passed
        || !revocation_check_passed
        || !policy_checks_passed
    {
        panic!("BDEC ShowVer checks failed");
    }

    let sig_hash: [u8; 32] = {
        let sig_bytes = bincode::serialize(&input.shown_credential_signature)
            .expect("signature serialization");
        Sha256::digest(&sig_bytes).into()
    };

    let statement = PublicStatement {
        verifier_pseudonym_public: input.verifier_pseudonym.public.clone(),
        shown_credential_signature_hash: sig_hash,
        disclosure_hash: input.disclosure_hash,
        disclosed_attributes: input.disclosed_attributes.clone(),
        ta_pseudonym_publics: input
            .credentials
            .iter()
            .map(|credential| credential.pseudonym.public.clone())
            .collect(),
    };

    let output = GuestOutput {
        statement,
        credential_checks_passed: true,
        attribute_checks_passed,
        revocation_check_passed,
        policy_checks_passed,
        counters,
    };

    env::commit(&output);
}

fn verify_loquat_signature(
    message: &[u8],
    signature: &LoquatSignature,
    public_key: &Vec<F>,
    params: &LoquatPublicParams,
    counters: &mut Counters,
) {
    counters.loquat_verifies = counters.loquat_verifies.saturating_add(1);
    match loquat_verify(message, signature, public_key, params) {
        Ok(true) => {}
        Ok(false) => panic!("Loquat signature rejected"),
        Err(_) => panic!("Loquat verification error"),
    }
}

fn verify_attribute_proofs(
    credentials: &[BdecCredentialInput],
    proofs: &[BdecAttributeMerkleProofInput],
    disclosed_attributes: &[String],
    counters: &mut Counters,
) -> bool {
    if proofs.len() != disclosed_attributes.len() {
        return false;
    }

    for (attr, proof) in disclosed_attributes.iter().zip(proofs.iter()) {
        if &proof.attribute != attr {
            return false;
        }
        let credential = match credentials.get(proof.credential_index) {
            Some(credential) => credential,
            None => return false,
        };
        if !matches!(
            credential.attribute_commitment_type,
            AttributeCommitmentTypeInput::MerkleRootGriffin
        ) {
            return false;
        }
        counters.merkle_nodes = counters
            .merkle_nodes
            .saturating_add(1 + proof.auth_path.len() as u32);
        if !MerkleTree::verify_auth_path(
            &credential.attribute_hash,
            proof.attribute.as_bytes(),
            proof.leaf_index,
            &proof.auth_path,
        ) {
            return false;
        }
    }

    true
}

fn hash_attributes(attributes: &[String], counters: &mut Counters) -> [u8; 32] {
    counters.hash_calls = counters.hash_calls.saturating_add(1);
    let mut hasher = Sha256::new();
    for attribute in attributes {
        hasher.update(attribute.as_bytes());
        hasher.update(&[0u8]);
    }
    hasher.finalize().into()
}

fn ensure_disclosure_subset(
    credentials: &[BdecCredentialInput],
    disclosed: &[String],
) -> bool {
    for attribute in disclosed {
        let mut found = false;
        for credential in credentials {
            if credential.attributes.iter().any(|value| value == attribute) {
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}

fn evaluate_policy(disclosed_attributes: &[String], policy: &PolicyInputData) -> bool {
    for predicate in &policy.predicates {
        match predicate {
            PolicyPredicateInput::GteI64 { key, min_value } => {
                let Some(raw) = find_attribute_value(disclosed_attributes, key) else {
                    return false;
                };
                let Ok(value) = raw.parse::<i64>() else {
                    return false;
                };
                if value < *min_value {
                    return false;
                }
            }
            PolicyPredicateInput::OneOf {
                key,
                allowed_values,
            } => {
                let Some(raw) = find_attribute_value(disclosed_attributes, key) else {
                    return false;
                };
                if !allowed_values.iter().any(|allowed| allowed == raw) {
                    return false;
                }
            }
        }
    }
    true
}

fn find_attribute_value<'a>(attributes: &'a [String], key: &str) -> Option<&'a str> {
    for entry in attributes {
        let Some((entry_key, entry_value)) = entry.split_once(':') else {
            continue;
        };
        if entry_key.trim() == key {
            return Some(entry_value.trim());
        }
    }
    None
}

fn verify_non_revocation(
    user_public_key: &[F],
    revocation_root: &[u8; 32],
    revocation_depth: usize,
    revocation_auth_path: &[[u8; 32]],
    counters: &mut Counters,
) -> bool {
    if revocation_depth == 0
        || revocation_auth_path.len() != revocation_depth
        || user_public_key.len() < revocation_depth
    {
        return false;
    }

    counters.merkle_nodes = counters
        .merkle_nodes
        .saturating_add(1 + revocation_depth as u32);

    let mut prefix_index = 0u64;
    for bit_idx in 0..revocation_depth {
        if !user_public_key[bit_idx].is_zero() {
            prefix_index |= 1u64 << bit_idx;
        }
    }

    let mut current = revocation_leaf_digest(F::zero());
    for (level, sibling) in revocation_auth_path.iter().enumerate() {
        let node_index = prefix_index >> level;
        let is_right_child = (node_index & 1u64) == 1u64;
        current = if is_right_child {
            revocation_internal_digest(sibling, &current)
        } else {
            revocation_internal_digest(&current, sibling)
        };
    }
    &current == revocation_root
}

fn revocation_leaf_digest(value: F) -> [u8; 32] {
    // Must match host-side accumulator leaf hashing.
    let mut state = [F::zero(); GRIFFIN_STATE_WIDTH];
    state[0] = value;
    state[1] = F::zero();
    state[2] = F::one();
    griffin_permutation_raw(&mut state);

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&field_utils::field_to_bytes(&state[0]));
    out[16..].copy_from_slice(&field_utils::field_to_bytes(&state[1]));
    out
}

fn revocation_internal_digest(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Must match host-side accumulator internal hashing.
    let l0 = field_utils::bytes_to_field_element(&left[0..16]);
    let l1 = field_utils::bytes_to_field_element(&left[16..32]);
    let r0 = field_utils::bytes_to_field_element(&right[0..16]);
    let r1 = field_utils::bytes_to_field_element(&right[16..32]);

    let mut state = [F::zero(); GRIFFIN_STATE_WIDTH];
    state[0] = l0;
    state[1] = l1;
    state[2] = r0;
    state[3] = r1;
    griffin_permutation_raw(&mut state);

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&field_utils::field_to_bytes(&state[0]));
    out[16..].copy_from_slice(&field_utils::field_to_bytes(&state[1]));
    out
}
