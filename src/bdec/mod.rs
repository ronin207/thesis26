//! BDEC Proof-of-Concept Layer aligned with the ProSec 2024 specification.
//!
//! The implementation follows the generic construction described in
//! *BDEC: Enhancing Learning Credibility via Post-Quantum Digital Credentials*.
//! It reuses the Loquat signature scheme (Crypto 2024) for long-term keys,
//! pseudonym signatures, and credential signatures, while modelling the zkSNARK
//! proofs mandated by the paper via hash-based commitments so the interfaces
//! match the formal algorithms: `Setup`, `PriGen`, `NymKey`, `CreGen`,
//! `CreVer`, `ShowCre`, `ShowVer`, and `RevCre`.

use crate::loquat::field_utils::F;
use crate::loquat::{
    LoquatPublicParams, LoquatSignature, loquat_setup, loquat_sign, loquat_verify,
};
use crate::loquat::field_utils;
use crate::loquat::griffin::{griffin_permutation_raw, GRIFFIN_STATE_WIDTH};
use crate::loquat::merkle::MerkleTree;
use crate::snarks::{
    AuroraParams, AuroraProof, R1csConstraint, R1csInstance, R1csWitness, aurora_prove, aurora_verify,
    build_loquat_r1cs_pk_witness, build_loquat_r1cs_pk_witness_instance,
    build_loquat_r1cs_pk_sig_witness,
    build_revocation_r1cs_pk_witness, build_revocation_r1cs_pk_witness_instance,
};
use crate::{LoquatError, LoquatKeyPair, LoquatResult, keygen_with_params};
use bincode::Options;
use rand::{Rng, distributions::Standard};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Public parameters for the BDEC layer (`par` in the paper).
#[derive(Debug, Clone)]
pub struct BdecPublicParams {
    pub loquat_params: LoquatPublicParams,
    pub max_attributes: usize,
    pub crs_digest: [u8; 32],
    pub aurora_params: AuroraParams,
}

/// How a credential commits to its attributes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BdecAttributeCommitmentType {
    /// Commit to the *full* attribute list by hashing the concatenation (legacy PoC behaviour).
    HashListSha256,
    /// Commit to a Merkle root over attributes (ProSec 2024 Appendix 0.B suggestion).
    MerkleRootGriffin,
}

/// Revocation list storing serialized Loquat public keys (`LR`).
#[derive(Debug, Clone, Default)]
pub struct BdecRevocationList {
    entries: HashSet<Vec<u8>>,
}

impl BdecRevocationList {
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
        }
    }

    pub fn add(&mut self, public_key: &[F]) -> LoquatResult<()> {
        let encoded = serialize_public_key(public_key)?;
        self.entries.insert(encoded);
        Ok(())
    }

    pub fn contains(&self, public_key: &[F]) -> LoquatResult<bool> {
        let encoded = serialize_public_key(public_key)?;
        Ok(self.entries.contains(&encoded))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.entries.iter()
    }
}

/// Complete system state returned by `Setup` (parameters plus revocation list).
#[derive(Debug, Clone)]
pub struct BdecSystem {
    pub params: BdecPublicParams,
    pub revocation_list: BdecRevocationList,
    /// Optional sparse-Merkle revocation accumulator (revocation checked in-ZK for ShowVer/Link).
    pub revocation_accumulator: Option<BdecRevocationAccumulator>,
}

/// Pseudonym key pair (`ppk`, `psk`) per the paper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BdecPseudonymKey {
    pub public: Vec<u8>,
    pub signature: LoquatSignature,
}

/// Placeholder for zkSNARK proofs (hash commitment in the PoC).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BdecCredentialProof {
    pub commitment: [u8; 32],
    pub aurora_proof: AuroraProof,
}

/// Credential record produced by `CreGen`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BdecCredential {
    pub pseudonym: BdecPseudonymKey,
    pub attributes: Vec<String>,
    pub attribute_hash: [u8; 32],
    pub attribute_commitment_type: BdecAttributeCommitmentType,
    pub credential_signature: LoquatSignature,
    pub proof: BdecCredentialProof,
}

/// Paper-aligned bundle produced by `ShowCre` / verified by `ShowVer` (ProSec 2024, §4.1).
///
/// Note: In the formal construction, `pk_U` is hidden and only revealed on revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BdecShownCredentialPaper {
    pub credentials: Vec<BdecCredential>,
    pub verifier_pseudonym: BdecPseudonymKey,
    pub disclosed_attributes: Vec<String>,
    /// Optional membership proofs for each disclosed attribute (for Merkle-root committed credentials).
    pub attribute_proofs: Vec<BdecAttributeMerkleProof>,
    pub disclosure_hash: [u8; 32],
    pub shown_credential_signature: LoquatSignature,
    pub show_proof: AuroraProof,
    /// If present, indicates the show proof also enforces “not revoked” under this revocation root.
    pub revocation_proof: Option<BdecRevocationProof>,
}

/// Sparse Merkle revocation accumulator (host-side), keyed by the first `depth` bits of `pk_U`.
///
/// The corresponding R1CS gadget is `build_revocation_r1cs_pk_witness` in `snarks/loquat_r1cs.rs`.
#[derive(Debug, Clone)]
pub struct BdecRevocationAccumulator {
    depth: usize,
    default_hashes: Vec<[u8; 32]>,
    nodes: HashMap<(usize, u64), [u8; 32]>,
}

/// Public metadata indicating which revocation root/depth a ZK revocation check was bound to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BdecRevocationProof {
    pub root: [u8; 32],
    pub depth: usize,
}

/// Merkle membership proof for a disclosed attribute against a credential's `attribute_hash` root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BdecAttributeMerkleProof {
    /// Which credential (in the shown bundle) this attribute belongs to.
    pub credential_index: usize,
    /// The disclosed attribute value (leaf payload).
    pub attribute: String,
    /// Leaf index in the padded power-of-two attribute tree used to compute the root.
    pub leaf_index: usize,
    /// Sibling digests from leaf level upward (standard Merkle authentication path).
    pub auth_path: Vec<Vec<u8>>,
}

impl BdecRevocationAccumulator {
    pub fn new(depth: usize) -> LoquatResult<Self> {
        if depth == 0 {
            return Err(LoquatError::invalid_parameters(
                "revocation accumulator depth must be > 0",
            ));
        }
        if depth > 63 {
            return Err(LoquatError::invalid_parameters(
                "revocation depth too large for u64 indexing",
            ));
        }
        let mut default_hashes = Vec::with_capacity(depth + 1);
        default_hashes.push(revocation_leaf_digest(F::zero()));
        for level in 0..depth {
            let prev = default_hashes[level];
            default_hashes.push(revocation_internal_digest(&prev, &prev));
        }
        Ok(Self {
            depth,
            default_hashes,
            nodes: HashMap::new(),
        })
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn root(&self) -> [u8; 32] {
        self.node_digest(self.depth, 0)
    }

    pub fn auth_path(&self, public_key: &[F]) -> LoquatResult<Vec<[u8; 32]>> {
        let idx = pk_prefix_index(public_key, self.depth)?;
        let mut path = Vec::with_capacity(self.depth);
        for level in 0..self.depth {
            let node_index = idx >> level;
            let sibling_index = node_index ^ 1;
            path.push(self.node_digest(level, sibling_index));
        }
        Ok(path)
    }

    pub fn revoke(&mut self, public_key: &[F]) -> LoquatResult<()> {
        let idx = pk_prefix_index(public_key, self.depth)?;
        self.set_node(0, idx, revocation_leaf_digest(F::one()));

        for level in 0..self.depth {
            let node_index = idx >> level;
            let parent_index = node_index >> 1;
            let left_index = parent_index * 2;
            let right_index = left_index + 1;
            let left = self.node_digest(level, left_index);
            let right = self.node_digest(level, right_index);
            let parent = revocation_internal_digest(&left, &right);
            self.set_node(level + 1, parent_index, parent);
        }
        Ok(())
    }

    fn node_digest(&self, level: usize, index: u64) -> [u8; 32] {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or_else(|| self.default_hashes[level])
    }

    fn set_node(&mut self, level: usize, index: u64, digest: [u8; 32]) {
        if digest == self.default_hashes[level] {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), digest);
        }
    }
}

fn pk_prefix_index(public_key: &[F], depth: usize) -> LoquatResult<u64> {
    if public_key.len() < depth {
        return Err(LoquatError::invalid_parameters(
            "public key shorter than revocation accumulator depth",
        ));
    }
    let mut idx = 0u64;
    for bit_idx in 0..depth {
        if !public_key[bit_idx].is_zero() {
            idx |= 1u64 << bit_idx;
        }
    }
    Ok(idx)
}

fn revocation_leaf_digest(value: F) -> [u8; 32] {
    // Matches the circuit leaf compression: Griffin perm over (value, 0, len_tag=1, 0).
    let mut state = [F::zero(); GRIFFIN_STATE_WIDTH];
    state[0] = value;
    state[1] = F::zero();
    state[2] = F::one(); // one field element in the leaf payload
    griffin_permutation_raw(&mut state);

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&field_utils::field_to_bytes(&state[0]));
    out[16..].copy_from_slice(&field_utils::field_to_bytes(&state[1]));
    out
}

fn revocation_internal_digest(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    // Matches the circuit internal compression: Griffin perm over (L0,L1,R0,R1).
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

const ATTRIBUTE_PAD_PREFIX: &str = "__BDEC_PAD__";

fn attribute_merkle_root(attributes: &[String]) -> LoquatResult<([u8; 32], Vec<String>)> {
    if attributes.is_empty() {
        return Err(LoquatError::invalid_parameters("empty attribute list"));
    }
    if attributes
        .iter()
        .any(|attr| attr.as_str().starts_with(ATTRIBUTE_PAD_PREFIX))
    {
        return Err(LoquatError::invalid_parameters(
            "attribute value reserved for internal padding",
        ));
    }

    // Deterministic ordering for reproducible commitments.
    let mut ordered = attributes.to_vec();
    ordered.sort();

    let padded_len = ordered.len().next_power_of_two().max(1);
    let mut leaves: Vec<Vec<u8>> = ordered.iter().map(|s| s.as_bytes().to_vec()).collect();
    for i in leaves.len()..padded_len {
        leaves.push(format!("{ATTRIBUTE_PAD_PREFIX}{i}").into_bytes());
    }

    let tree = MerkleTree::new(&leaves);
    let root_vec = tree
        .root()
        .ok_or_else(|| LoquatError::invalid_parameters("failed to build attribute Merkle root"))?;
    if root_vec.len() != 32 {
        return Err(LoquatError::invalid_parameters(
            "Merkle root must be 32 bytes",
        ));
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_vec);
    Ok((root, ordered))
}

/// Helper: build a Merkle membership proof for an attribute, using the same canonicalisation
/// and padding rules as `bdec_issue_credential_merkle_attrs`.
pub fn bdec_attribute_merkle_proof(
    credential_index: usize,
    attributes: &[String],
    attribute: &str,
) -> LoquatResult<BdecAttributeMerkleProof> {
    if attributes.is_empty() {
        return Err(LoquatError::invalid_parameters("empty attribute list"));
    }
    if attribute.starts_with(ATTRIBUTE_PAD_PREFIX) {
        return Err(LoquatError::invalid_parameters(
            "attribute value reserved for internal padding",
        ));
    }

    let mut ordered = attributes.to_vec();
    ordered.sort();
    let leaf_index = ordered
        .iter()
        .position(|a| a == attribute)
        .ok_or_else(|| LoquatError::invalid_parameters("attribute not present"))?;

    let padded_len = ordered.len().next_power_of_two().max(1);
    let mut leaves: Vec<Vec<u8>> = ordered.iter().map(|s| s.as_bytes().to_vec()).collect();
    for i in leaves.len()..padded_len {
        leaves.push(format!("{ATTRIBUTE_PAD_PREFIX}{i}").into_bytes());
    }
    let tree = MerkleTree::new(&leaves);
    let auth_path = tree.generate_auth_path(leaf_index);

    Ok(BdecAttributeMerkleProof {
        credential_index,
        attribute: attribute.to_string(),
        leaf_index,
        auth_path,
    })
}

/// Conditional linkability proof (ProSec 2024, §4.1, “Conditional Linkability”).
///
/// Proves that two pseudonym public keys were generated under the same (hidden) long-term
/// public key by proving validity of both pseudonym signatures under one pk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BdecLinkProof {
    pub old_pseudonym: BdecPseudonymKey,
    pub new_pseudonym: BdecPseudonymKey,
    pub proof: AuroraProof,
    pub revocation_proof: Option<BdecRevocationProof>,
}

/// Run `Setup`, returning public parameters and an empty revocation list.
pub fn bdec_setup(lambda: usize, max_attributes: usize) -> LoquatResult<BdecSystem> {
    let loquat_params = loquat_setup(lambda)?;
    let mut hasher = Sha256::new();
    hasher.update(b"BDEC_CRS");
    hasher.update(lambda.to_le_bytes());
    hasher.update(max_attributes.to_le_bytes());
    let crs_digest: [u8; 32] = hasher.finalize().into();
    Ok(BdecSystem {
        params: BdecPublicParams {
            loquat_params,
            max_attributes,
            crs_digest,
            aurora_params: AuroraParams::default(),
        },
        revocation_list: BdecRevocationList::new(),
        revocation_accumulator: None,
    })
}

/// Run `Setup` with an additional sparse-Merkle revocation accumulator (revocation checked in ZK).
pub fn bdec_setup_zk(lambda: usize, max_attributes: usize, revocation_depth: usize) -> LoquatResult<BdecSystem> {
    let mut system = bdec_setup(lambda, max_attributes)?;
    system.revocation_accumulator = Some(BdecRevocationAccumulator::new(revocation_depth)?);
    Ok(system)
}

/// Generate a long-term Loquat key pair (`PriGen`).
pub fn bdec_prigen(system: &BdecSystem) -> LoquatResult<LoquatKeyPair> {
    keygen_with_params(&system.params.loquat_params)
}

/// Sample a pseudonym public key and sign it with the user's long-term secret (`NymKey`).
pub fn bdec_nym_key(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
) -> LoquatResult<BdecPseudonymKey> {
    let public: Vec<u8> = rand::thread_rng().sample_iter(Standard).take(32).collect();
    let signature = loquat_sign(&public, user_keypair, &system.params.loquat_params)?;
    Ok(BdecPseudonymKey { public, signature })
}

/// Issue a credential and accompanying proof (`CreGen`).
pub fn bdec_issue_credential(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
    pseudonym: &BdecPseudonymKey,
    attributes: Vec<String>,
) -> LoquatResult<BdecCredential> {
    if attributes.len() > system.params.max_attributes {
        return Err(LoquatError::invalid_parameters(
            "too many attributes for credential",
        ));
    }

    let attribute_hash = hash_attributes(&attributes);
    let credential_signature =
        loquat_sign(&attribute_hash, user_keypair, &system.params.loquat_params)?;
    let commitment = credential_commitment(pseudonym, &credential_signature, &attribute_hash)?;

    // ProSec 2024 CreGen statement proves *two* Sig.Verify instances under a hidden pk_U:
    //  1) Verify(pk_U, h_U,TA, c_U,TA) = 1
    //  2) Verify(pk_U, ppk_U,TA, psk_U,TA) = 1
    //
    // In this PoC, we instantiate the zkSNARK with Aurora over an R1CS that is the
    // conjunction of two Loquat-verification circuits by merging their instances.
    let (sig_instance, sig_witness) = build_loquat_r1cs_pk_witness(
        &attribute_hash,
        &credential_signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    let (nym_instance, nym_witness) = build_loquat_r1cs_pk_witness(
        &pseudonym.public,
        &pseudonym.signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    let (r1cs_instance, r1cs_witness) = merge_r1cs_instances_shared_pk(
        vec![(sig_instance, sig_witness), (nym_instance, nym_witness)],
        system.params.loquat_params.l,
    )?;
    let aurora_proof = aurora_prove(&r1cs_instance, &r1cs_witness, &system.params.aurora_params)?;

    Ok(BdecCredential {
        pseudonym: pseudonym.clone(),
        attributes,
        attribute_hash,
        attribute_commitment_type: BdecAttributeCommitmentType::HashListSha256,
        credential_signature,
        proof: BdecCredentialProof {
            commitment,
            aurora_proof,
        },
    })
}

/// Issue a credential whose attribute commitment is a Merkle root (ProSec 2024 Appendix 0.B).
///
/// This is an opt-in variant that keeps the overall BDEC flow identical but allows hiding
/// undisclosed attributes by publishing only the Merkle root on-chain and later showing
/// membership paths for disclosed attributes.
pub fn bdec_issue_credential_merkle_attrs(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
    pseudonym: &BdecPseudonymKey,
    attributes: Vec<String>,
) -> LoquatResult<BdecCredential> {
    if attributes.is_empty() {
        return Err(LoquatError::invalid_parameters("empty attribute list"));
    }
    if attributes.len() > system.params.max_attributes {
        return Err(LoquatError::invalid_parameters(
            "too many attributes for credential",
        ));
    }

    // Build a Griffin-Merkle commitment over the attribute leaves.
    let (attribute_root, _padded_attributes) = attribute_merkle_root(&attributes)?;

    // Sign the Merkle root (32 bytes) as the credential signature.
    let credential_signature =
        loquat_sign(&attribute_root, user_keypair, &system.params.loquat_params)?;
    let commitment = credential_commitment(pseudonym, &credential_signature, &attribute_root)?;

    // Same paper-style SNARK statement as CreGen, but with message = attribute_root.
    let (sig_instance, sig_witness) = build_loquat_r1cs_pk_witness(
        &attribute_root,
        &credential_signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    let (nym_instance, nym_witness) = build_loquat_r1cs_pk_witness(
        &pseudonym.public,
        &pseudonym.signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    let (r1cs_instance, r1cs_witness) = merge_r1cs_instances_shared_pk(
        vec![(sig_instance, sig_witness), (nym_instance, nym_witness)],
        system.params.loquat_params.l,
    )?;
    let aurora_proof = aurora_prove(&r1cs_instance, &r1cs_witness, &system.params.aurora_params)?;

    // Note: to model “hidden attributes on-chain”, callers can strip `attributes` before publishing.
    Ok(BdecCredential {
        pseudonym: pseudonym.clone(),
        attributes,
        attribute_hash: attribute_root,
        attribute_commitment_type: BdecAttributeCommitmentType::MerkleRootGriffin,
        credential_signature,
        proof: BdecCredentialProof {
            commitment,
            aurora_proof,
        },
    })
}

/// Verify a credential against public parameters (`CreVer`).
pub fn bdec_verify_credential(
    system: &BdecSystem,
    credential: &BdecCredential,
) -> LoquatResult<bool> {
    match credential.attribute_commitment_type {
        BdecAttributeCommitmentType::HashListSha256 => {
            if !attributes_match_hash(&credential.attributes, &credential.attribute_hash) {
                return Ok(false);
            }
        }
        BdecAttributeCommitmentType::MerkleRootGriffin => {
            // If attributes are present locally, sanity-check they match the committed Merkle root.
            // (In the hidden-attribute setting, attributes may be omitted from the published credential.)
            if !credential.attributes.is_empty() {
                let (root, _padded) = attribute_merkle_root(&credential.attributes)?;
                if root != credential.attribute_hash {
                    return Ok(false);
                }
            }
        }
    }

    // Paper-style revocation check: if any revoked pk verifies either signature, reject.
    if is_signature_from_revoked_key(
        system,
        &credential.attribute_hash,
        &credential.credential_signature,
    )? {
        return Ok(false);
    }
    if is_signature_from_revoked_key(system, &credential.pseudonym.public, &credential.pseudonym.signature)? {
        return Ok(false);
    }

    let expected_commitment = credential_commitment(
        &credential.pseudonym,
        &credential.credential_signature,
        &credential.attribute_hash,
    )?;
    if expected_commitment != credential.proof.commitment {
        return Ok(false);
    }

    let sig_instance = build_loquat_r1cs_pk_witness_instance(
        &credential.attribute_hash,
        &credential.credential_signature,
        &system.params.loquat_params,
    )?;
    let nym_instance = build_loquat_r1cs_pk_witness_instance(
        &credential.pseudonym.public,
        &credential.pseudonym.signature,
        &system.params.loquat_params,
    )?;
    let r1cs_instance = merge_r1cs_instances_shared_pk_instance_only(
        &[sig_instance, nym_instance],
        system.params.loquat_params.l,
    )?;
    let proof_ok = aurora_verify(
        &r1cs_instance,
        &credential.proof.aurora_proof,
        &system.params.aurora_params,
        None,
    )?
    .is_some();
    if !proof_ok {
        return Ok(false);
    }
    Ok(true)
}

/// Revoke a user's long-term public key (`RevCre`).
pub fn bdec_revoke(system: &mut BdecSystem, public_key: &[F]) -> LoquatResult<()> {
    system.revocation_list.add(public_key)?;
    if let Some(acc) = system.revocation_accumulator.as_mut() {
        acc.revoke(public_key)?;
    }
    Ok(())
}

/// Produce a conditional linkability proof for reusing an already-accepted shown credential.
///
/// This matches the paper’s “2-verification” idea: prove both pseudonyms are signed under
/// the *same* hidden pk_U.
pub fn bdec_link_pseudonyms(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
    old_pseudonym: &BdecPseudonymKey,
    new_pseudonym: &BdecPseudonymKey,
) -> LoquatResult<BdecLinkProof> {
    let (old_inst, old_wit) = build_loquat_r1cs_pk_witness(
        &old_pseudonym.public,
        &old_pseudonym.signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    let (new_inst, new_wit) = build_loquat_r1cs_pk_witness(
        &new_pseudonym.public,
        &new_pseudonym.signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;

    let mut circuits = vec![(old_inst, old_wit), (new_inst, new_wit)];

    // Optional: prove not revoked under the current revocation root.
    let revocation_proof = if let Some(acc) = system.revocation_accumulator.as_ref() {
        let root = acc.root();
        let depth = acc.depth();
        let auth_path = acc.auth_path(&user_keypair.public_key)?;
        let (rev_inst, rev_wit) =
            build_revocation_r1cs_pk_witness(&user_keypair.public_key, &root, &auth_path, depth)?;
        circuits.push((rev_inst, rev_wit));
        Some(BdecRevocationProof { root, depth })
    } else {
        None
    };

    let (instance, witness) = merge_r1cs_instances_shared_pk(
        circuits,
        system.params.loquat_params.l,
    )?;
    let proof = aurora_prove(&instance, &witness, &system.params.aurora_params)?;

    Ok(BdecLinkProof {
        old_pseudonym: old_pseudonym.clone(),
        new_pseudonym: new_pseudonym.clone(),
        proof,
        revocation_proof,
    })
}

/// Verify a conditional linkability proof.
pub fn bdec_verify_link_proof(system: &BdecSystem, link: &BdecLinkProof) -> LoquatResult<bool> {
    // Revocation scan: reject if any revoked pk verifies either pseudonym signature.
    if is_signature_from_revoked_key(system, &link.old_pseudonym.public, &link.old_pseudonym.signature)?
        || is_signature_from_revoked_key(
            system,
            &link.new_pseudonym.public,
            &link.new_pseudonym.signature,
        )?
    {
        return Ok(false);
    }

    let old_inst = build_loquat_r1cs_pk_witness_instance(
        &link.old_pseudonym.public,
        &link.old_pseudonym.signature,
        &system.params.loquat_params,
    )?;
    let new_inst = build_loquat_r1cs_pk_witness_instance(
        &link.new_pseudonym.public,
        &link.new_pseudonym.signature,
        &system.params.loquat_params,
    )?;
    let mut instances = vec![old_inst, new_inst];
    if let Some(meta) = link.revocation_proof {
        let acc = match system.revocation_accumulator.as_ref() {
            Some(a) => a,
            None => return Ok(false),
        };
        if meta.root != acc.root() || meta.depth != acc.depth() {
            return Ok(false);
        }
        instances.push(build_revocation_r1cs_pk_witness_instance(
            &meta.root,
            meta.depth,
            system.params.loquat_params.l,
        )?);
    }
    let instance =
        merge_r1cs_instances_shared_pk_instance_only(&instances, system.params.loquat_params.l)?;

    let ok = aurora_verify(&instance, &link.proof, &system.params.aurora_params, None)?.is_some();
    Ok(ok)
}

/// Paper-aligned `ShowCre` (ProSec 2024, §4.1).
///
/// Generates a fresh verifier pseudonym key for the target verifier, signs the hash of the
/// disclosed attributes, and produces an Aurora proof asserting ownership of all included
/// TA pseudonyms plus the verifier pseudonym under the same long-term public key.
pub fn bdec_show_credential_paper(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
    credentials: &[BdecCredential],
    disclosed_attributes: Vec<String>,
) -> LoquatResult<BdecShownCredentialPaper> {
    if credentials.is_empty() {
        return Err(LoquatError::invalid_parameters(
            "at least one credential is required",
        ));
    }

    for credential in credentials {
        if !bdec_verify_credential(system, credential)? {
            return Err(LoquatError::verification_failure(
                "credential failed verification during ShowCre",
            ));
        }
    }

    let canonical_disclosure = canonicalise_attributes(&disclosed_attributes)?;
    ensure_disclosure_subset(credentials, &canonical_disclosure)?;
    let disclosure_hash = hash_attributes(&canonical_disclosure);

    // Generate verifier pseudonym keys (ppk_U,V, psk_U,V) via NymKey(par, sk_U).
    let verifier_pseudonym = bdec_nym_key(system, user_keypair)?;

    // Generate shown credential signature c_U,V = Sig.Sign(sk_U, H(A↓)).
    let shown_credential_signature =
        loquat_sign(&disclosure_hash, user_keypair, &system.params.loquat_params)?;

    // Prove conjunction of:
    //  (1) For each TA credential j: Verify(pk_U, ppk_U,TA^(j), psk_U,TA^(j)) = 1
    //  (2) Verify(pk_U, ppk_U,V, psk_U,V) = 1
    //  (3) Verify(pk_U, H(A↓), c_U,V) = 1
    let mut circuits = Vec::with_capacity(credentials.len() + 2);
    for credential in credentials {
        let (inst, wit) = build_loquat_r1cs_pk_witness(
            &credential.pseudonym.public,
            &credential.pseudonym.signature,
            &user_keypair.public_key,
            &system.params.loquat_params,
        )?;
        circuits.push((inst, wit));
    }
    let (ver_inst, ver_wit) = build_loquat_r1cs_pk_witness(
        &verifier_pseudonym.public,
        &verifier_pseudonym.signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    circuits.push((ver_inst, ver_wit));
    let (shown_inst, shown_wit) = build_loquat_r1cs_pk_witness(
        &disclosure_hash,
        &shown_credential_signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    circuits.push((shown_inst, shown_wit));

    // Optional: revocation checked inside the SNARK via sparse-Merkle non-membership.
    let revocation_proof = if let Some(acc) = system.revocation_accumulator.as_ref() {
        let root = acc.root();
        let depth = acc.depth();
        let auth_path = acc.auth_path(&user_keypair.public_key)?;
        let (rev_inst, rev_wit) =
            build_revocation_r1cs_pk_witness(&user_keypair.public_key, &root, &auth_path, depth)?;
        circuits.push((rev_inst, rev_wit));
        Some(BdecRevocationProof { root, depth })
    } else {
        None
    };

    let (r1cs_instance, r1cs_witness) = merge_r1cs_instances_shared_pk(circuits, system.params.loquat_params.l)?;
    let show_proof = aurora_prove(&r1cs_instance, &r1cs_witness, &system.params.aurora_params)?;

    Ok(BdecShownCredentialPaper {
        credentials: credentials.to_vec(),
        verifier_pseudonym,
        disclosed_attributes: canonical_disclosure,
        attribute_proofs: Vec::new(),
        disclosure_hash,
        shown_credential_signature,
        show_proof,
        revocation_proof,
    })
}

/// Paper-aligned `ShowCre` variant that supports **hidden attributes** via Merkle membership proofs.
///
/// Callers provide membership proofs for each disclosed attribute (Appendix 0.B style), so the
/// verifier can validate disclosures without learning undisclosed attributes.
pub fn bdec_show_credential_paper_merkle(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
    credentials: &[BdecCredential],
    disclosed_attributes: Vec<String>,
    mut attribute_proofs: Vec<BdecAttributeMerkleProof>,
) -> LoquatResult<BdecShownCredentialPaper> {
    if credentials.is_empty() {
        return Err(LoquatError::invalid_parameters(
            "at least one credential is required",
        ));
    }

    for credential in credentials {
        if !bdec_verify_credential(system, credential)? {
            return Err(LoquatError::verification_failure(
                "credential failed verification during ShowCre",
            ));
        }
    }

    let canonical_disclosure = canonicalise_attributes(&disclosed_attributes)?;
    let disclosure_hash = hash_attributes(&canonical_disclosure);

    // Align proofs with canonical disclosure order.
    attribute_proofs.sort_by(|a, b| a.attribute.cmp(&b.attribute));
    if attribute_proofs.len() != canonical_disclosure.len() {
        return Err(LoquatError::invalid_parameters(
            "attribute proof count mismatch for disclosed attributes",
        ));
    }
    for (attr, proof) in canonical_disclosure.iter().zip(attribute_proofs.iter()) {
        if &proof.attribute != attr {
            return Err(LoquatError::invalid_parameters(
                "attribute proofs do not match disclosed attributes",
            ));
        }
        let cred = credentials
            .get(proof.credential_index)
            .ok_or_else(|| LoquatError::invalid_parameters("invalid credential index in proof"))?;
        if cred.attribute_commitment_type != BdecAttributeCommitmentType::MerkleRootGriffin {
            return Err(LoquatError::invalid_parameters(
                "Merkle attribute proof provided for non-Merkle credential",
            ));
        }
        if !MerkleTree::verify_auth_path(
            &cred.attribute_hash,
            attr.as_bytes(),
            proof.leaf_index,
            &proof.auth_path,
        ) {
            return Err(LoquatError::verification_failure(
                "attribute Merkle membership proof failed",
            ));
        }
    }

    // Generate verifier pseudonym keys (ppk_U,V, psk_U,V) via NymKey(par, sk_U).
    let verifier_pseudonym = bdec_nym_key(system, user_keypair)?;

    // Generate shown credential signature c_U,V = Sig.Sign(sk_U, H(A↓)).
    let shown_credential_signature =
        loquat_sign(&disclosure_hash, user_keypair, &system.params.loquat_params)?;

    // Prove conjunction of:
    //  (1) For each TA credential j: Verify(pk_U, ppk_U,TA^(j), psk_U,TA^(j)) = 1
    //  (2) Verify(pk_U, ppk_U,V, psk_U,V) = 1
    //  (3) Verify(pk_U, H(A↓), c_U,V) = 1
    let mut circuits = Vec::with_capacity(credentials.len() + 3);
    for credential in credentials {
        let (inst, wit) = build_loquat_r1cs_pk_witness(
            &credential.pseudonym.public,
            &credential.pseudonym.signature,
            &user_keypair.public_key,
            &system.params.loquat_params,
        )?;
        circuits.push((inst, wit));
    }
    let (ver_inst, ver_wit) = build_loquat_r1cs_pk_witness(
        &verifier_pseudonym.public,
        &verifier_pseudonym.signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    circuits.push((ver_inst, ver_wit));
    let (shown_inst, shown_wit) = build_loquat_r1cs_pk_witness(
        &disclosure_hash,
        &shown_credential_signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;
    circuits.push((shown_inst, shown_wit));

    // Optional: revocation checked inside the SNARK via sparse-Merkle non-membership.
    let revocation_proof = if let Some(acc) = system.revocation_accumulator.as_ref() {
        let root = acc.root();
        let depth = acc.depth();
        let auth_path = acc.auth_path(&user_keypair.public_key)?;
        let (rev_inst, rev_wit) =
            build_revocation_r1cs_pk_witness(&user_keypair.public_key, &root, &auth_path, depth)?;
        circuits.push((rev_inst, rev_wit));
        Some(BdecRevocationProof { root, depth })
    } else {
        None
    };

    let (r1cs_instance, r1cs_witness) =
        merge_r1cs_instances_shared_pk(circuits, system.params.loquat_params.l)?;
    let show_proof = aurora_prove(&r1cs_instance, &r1cs_witness, &system.params.aurora_params)?;

    Ok(BdecShownCredentialPaper {
        credentials: credentials.to_vec(),
        verifier_pseudonym,
        disclosed_attributes: canonical_disclosure,
        attribute_proofs,
        disclosure_hash,
        shown_credential_signature,
        show_proof,
        revocation_proof,
    })
}

/// Paper-aligned `ShowVer` (ProSec 2024, §4.1).
pub fn bdec_verify_shown_credential_paper(
    system: &BdecSystem,
    shown: &BdecShownCredentialPaper,
    expected_verifier_pseudonym: &[u8],
) -> LoquatResult<bool> {
    if shown.verifier_pseudonym.public != expected_verifier_pseudonym {
        return Ok(false);
    }
    // Paper-style revocation scan: reject if any published (revoked) pk verifies the shown signature.
    if is_signature_from_revoked_key(
        system,
        &shown.disclosure_hash,
        &shown.shown_credential_signature,
    )? {
        return Ok(false);
    }
    let recomputed_hash = hash_attributes(&shown.disclosed_attributes);
    if recomputed_hash != shown.disclosure_hash {
        return Ok(false);
    }

    // Disclosed attributes can be validated either by:
    // - legacy “attributes list included in credential” subset checking, or
    // - Merkle membership proofs (Appendix 0.B).
    if shown.attribute_proofs.is_empty() {
        if let Err(_) = ensure_disclosure_subset(&shown.credentials, &shown.disclosed_attributes) {
            return Ok(false);
        }
    } else {
        // Enforce a stable 1:1 mapping between disclosed attributes and proofs.
        if shown.attribute_proofs.len() != shown.disclosed_attributes.len() {
            return Ok(false);
        }
        for (attr, proof) in shown
            .disclosed_attributes
            .iter()
            .zip(shown.attribute_proofs.iter())
        {
            if &proof.attribute != attr {
                return Ok(false);
            }
            let cred = match shown.credentials.get(proof.credential_index) {
                Some(c) => c,
                None => return Ok(false),
            };
            if cred.attribute_commitment_type != BdecAttributeCommitmentType::MerkleRootGriffin {
                return Ok(false);
            }
            if !MerkleTree::verify_auth_path(
                &cred.attribute_hash,
                attr.as_bytes(),
                proof.leaf_index,
                &proof.auth_path,
            ) {
                return Ok(false);
            }
        }
    }

    for credential in &shown.credentials {
        if !bdec_verify_credential(system, credential)? {
            return Ok(false);
        }
    }

    // Rebuild the paper statement circuit (k + 2 signature verifications [+ optional revocation]), pk hidden.
    let extra = if shown.revocation_proof.is_some() { 1 } else { 0 };
    let mut instances = Vec::with_capacity(shown.credentials.len() + 2 + extra);
    for credential in &shown.credentials {
        instances.push(build_loquat_r1cs_pk_witness_instance(
            &credential.pseudonym.public,
            &credential.pseudonym.signature,
            &system.params.loquat_params,
        )?);
    }
    instances.push(build_loquat_r1cs_pk_witness_instance(
        &shown.verifier_pseudonym.public,
        &shown.verifier_pseudonym.signature,
        &system.params.loquat_params,
    )?);
    instances.push(build_loquat_r1cs_pk_witness_instance(
        &shown.disclosure_hash,
        &shown.shown_credential_signature,
        &system.params.loquat_params,
    )?);

    if let Some(meta) = shown.revocation_proof {
        let acc = match system.revocation_accumulator.as_ref() {
            Some(a) => a,
            None => return Ok(false),
        };
        // Ensure the proof is bound to the *current* published revocation root.
        if meta.root != acc.root() || meta.depth != acc.depth() {
            return Ok(false);
        }
        instances.push(build_revocation_r1cs_pk_witness_instance(
            &meta.root,
            meta.depth,
            system.params.loquat_params.l,
        )?);
    }
    let r1cs_instance =
        merge_r1cs_instances_shared_pk_instance_only(&instances, system.params.loquat_params.l)?;
    let proof_ok = aurora_verify(
        &r1cs_instance,
        &shown.show_proof,
        &system.params.aurora_params,
        None,
    )?
    .is_some();
    if !proof_ok {
        return Ok(false);
    }
    Ok(true)
}

fn credential_commitment(
    pseudonym: &BdecPseudonymKey,
    credential_signature: &LoquatSignature,
    attribute_hash: &[u8; 32],
) -> LoquatResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(attribute_hash);
    hasher.update(&pseudonym.public);
    hasher.update(&serialize_signature(&pseudonym.signature)?);
    hasher.update(&serialize_signature(credential_signature)?);
    Ok(hasher.finalize().into())
}

fn hash_attributes(attributes: &[String]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for attribute in attributes {
        hasher.update(attribute.as_bytes());
        hasher.update(&[0u8]);
    }
    hasher.finalize().into()
}

fn attributes_match_hash(attributes: &[String], expected: &[u8; 32]) -> bool {
    hash_attributes(attributes) == *expected
}

fn canonicalise_attributes(attributes: &[String]) -> LoquatResult<Vec<String>> {
    let mut unique = HashSet::new();
    for value in attributes {
        if !unique.insert(value.clone()) {
            return Err(LoquatError::invalid_parameters(
                "duplicate attribute in disclosure set",
            ));
        }
    }
    let mut ordered: Vec<String> = unique.into_iter().collect();
    ordered.sort();
    Ok(ordered)
}

fn ensure_disclosure_subset(
    credentials: &[BdecCredential],
    disclosed: &[String],
) -> LoquatResult<()> {
    let mut attribute_index: HashMap<&str, usize> = HashMap::new();
    for credential in credentials {
        for attribute in &credential.attributes {
            *attribute_index.entry(attribute).or_insert(0) += 1;
        }
    }

    for attribute in disclosed {
        if !attribute_index.contains_key(attribute.as_str()) {
            return Err(LoquatError::invalid_parameters(
                "disclosed attribute not present in credentials",
            ));
        }
    }
    Ok(())
}

fn serialize_signature(signature: &LoquatSignature) -> LoquatResult<Vec<u8>> {
    bincode_options().serialize(signature).map_err(|err| {
        LoquatError::serialization_error(&format!("failed to encode signature: {err}"))
    })
}

fn serialize_public_key(public_key: &[F]) -> LoquatResult<Vec<u8>> {
    bincode_options().serialize(public_key).map_err(|err| {
        LoquatError::serialization_error(&format!("failed to encode public key: {err}"))
    })
}

fn deserialize_public_key(bytes: &[u8]) -> LoquatResult<Vec<F>> {
    bincode_options()
        .deserialize(bytes)
        .map_err(|err| LoquatError::serialization_error(&format!("failed to decode public key: {err}")))
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

fn merge_r1cs_instances_shared_pk(
    circuits: Vec<(R1csInstance, R1csWitness)>,
    pk_len: usize,
) -> LoquatResult<(R1csInstance, R1csWitness)> {
    let (merged, witness, offsets) = merge_r1cs_instances_with_offsets(circuits)?;
    if pk_len == 0 || offsets.len() <= 1 {
        return Ok((merged, witness));
    }

    let mut constraints = merged.constraints;
    for &offset in offsets.iter().skip(1) {
        for j in 0..pk_len {
            // pk^{(0)}_j == pk^{(i)}_j
            let left_idx = 1 + j;
            let right_idx = offset + 1 + j;
            constraints.push(R1csConstraint::from_sparse(
                vec![(left_idx, F::one()), (right_idx, -F::one())],
                vec![(0, F::one())],
                vec![],
            ));
        }
    }

    let instance = R1csInstance::new(merged.num_variables, constraints)?;
    witness.validate(&instance)?;
    Ok((instance, witness))
}

fn merge_r1cs_instances_with_offsets(
    circuits: Vec<(R1csInstance, R1csWitness)>,
) -> LoquatResult<(R1csInstance, R1csWitness, Vec<usize>)> {
    if circuits.is_empty() {
        return Err(LoquatError::invalid_parameters(
            "expected at least one R1CS instance to merge",
        ));
    }
    
    let mut offsets = Vec::with_capacity(circuits.len());
    let mut offset = 0usize;
    let mut num_variables = 1usize;
    let mut constraints = Vec::new();
    let mut assignment = Vec::new();

    for (instance, witness) in circuits {
        witness.validate(&instance)?;
        offsets.push(offset);

        for c in &instance.constraints {
            constraints.push(R1csConstraint {
                a: offset_sparse_terms(&c.a, offset),
                b: offset_sparse_terms(&c.b, offset),
                c: offset_sparse_terms(&c.c, offset),
            });
        }

        assignment.extend_from_slice(&witness.assignment);
        let delta = instance
            .num_variables
            .checked_sub(1)
            .ok_or_else(|| LoquatError::invalid_parameters("R1CS instance has zero variables"))?;
        offset = offset.saturating_add(delta);
        num_variables = num_variables.saturating_add(delta);
    }

    let instance = R1csInstance::new(num_variables, constraints)?;
    let witness = R1csWitness::new(assignment);
    witness.validate(&instance)?;
    Ok((instance, witness, offsets))
}

fn merge_r1cs_instances_shared_pk_instance_only(
    instances: &[R1csInstance],
    pk_len: usize,
) -> LoquatResult<R1csInstance> {
    let (merged, offsets) = merge_r1cs_instances_instance_only(instances)?;
    if pk_len == 0 || offsets.len() <= 1 {
        return Ok(merged);
    }

    let mut constraints = merged.constraints;
    for &offset in offsets.iter().skip(1) {
        for j in 0..pk_len {
            let left_idx = 1 + j;
            let right_idx = offset + 1 + j;
            constraints.push(R1csConstraint::from_sparse(
                vec![(left_idx, F::one()), (right_idx, -F::one())],
                vec![(0, F::one())],
                vec![],
            ));
        }
    }
    R1csInstance::new(merged.num_variables, constraints)
}

fn merge_r1cs_instances_instance_only(instances: &[R1csInstance]) -> LoquatResult<(R1csInstance, Vec<usize>)> {
    if instances.is_empty() {
        return Err(LoquatError::invalid_parameters(
            "expected at least one R1CS instance to merge",
        ));
    }

    let mut offsets = Vec::with_capacity(instances.len());
    let mut offset = 0usize;
    let mut num_variables = 1usize;
    let mut constraints = Vec::new();

    for instance in instances {
        offsets.push(offset);
        for c in &instance.constraints {
            constraints.push(R1csConstraint {
                a: offset_sparse_terms(&c.a, offset),
                b: offset_sparse_terms(&c.b, offset),
                c: offset_sparse_terms(&c.c, offset),
            });
        }
        let delta = instance
            .num_variables
            .checked_sub(1)
            .ok_or_else(|| LoquatError::invalid_parameters("R1CS instance has zero variables"))?;
        offset = offset.saturating_add(delta);
        num_variables = num_variables.saturating_add(delta);
    }

    let instance = R1csInstance::new(num_variables, constraints)?;
    Ok((instance, offsets))
}

fn offset_sparse_terms(values: &[(usize, F)], offset: usize) -> Vec<(usize, F)> {
    values
        .iter()
        .map(|(idx, coeff)| {
            if *idx == 0 {
                (0, *coeff)
            } else {
                (*idx + offset, *coeff)
            }
        })
        .collect()
}

fn is_signature_from_revoked_key(
    system: &BdecSystem,
    message: &[u8],
    signature: &LoquatSignature,
) -> LoquatResult<bool> {
    for encoded_pk in system.revocation_list.iter() {
        let pk: Vec<F> = deserialize_public_key(encoded_pk)?;
        if loquat_verify(message, signature, &pk, &system.params.loquat_params)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalise_attributes_rejects_duplicates_and_sorts() {
        let attrs = vec![
            "year:2025".to_string(),
            "degree:CS".to_string(),
            "year:2025".to_string(),
        ];
        assert!(canonicalise_attributes(&attrs).is_err());

        let attrs = vec![
            "year:2025".to_string(),
            "degree:CS".to_string(),
            "issuer:TA1".to_string(),
        ];
        let canonical = canonicalise_attributes(&attrs).expect("canonicalise should succeed");
        assert_eq!(
            canonical,
            vec![
                "degree:CS".to_string(),
                "issuer:TA1".to_string(),
                "year:2025".to_string()
            ]
        );
    }

    #[test]
    fn revocation_list_add_and_contains_round_trip() {
        let params = loquat_setup(80).expect("setup");
        let keypair = keygen_with_params(&params).expect("keygen");
        let mut list = BdecRevocationList::new();
        assert!(!list.contains(&keypair.public_key).expect("contains"));
        list.add(&keypair.public_key).expect("add");
        assert!(list.contains(&keypair.public_key).expect("contains"));
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn bdec_demo_flow_matches_expected() {
        let mut system = bdec_setup(128, 8).expect("setup");
        let user = bdec_prigen(&system).expect("prigen");

        let nym_ta = bdec_nym_key(&system, &user).expect("nymkey");
        let attrs = vec![
            "degree:ComputerScience".to_string(),
            "year:2024".to_string(),
            "issuer:TA1".to_string(),
        ];
        let cred = bdec_issue_credential(&system, &user, &nym_ta, attrs.clone()).expect("cregen");
        assert!(bdec_verify_credential(&system, &cred).expect("crever"));

        let disclosed = vec![attrs[0].clone(), attrs[1].clone()];
        let shown =
            bdec_show_credential_paper(&system, &user, &[cred.clone()], disclosed).expect("showcre");
        assert!(
            bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
                .expect("showver")
        );

        bdec_revoke(&mut system, &user.public_key).expect("revoke");
        assert!(!bdec_verify_credential(&system, &cred).expect("crever after revoke"));
        assert!(
            !bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
                .expect("showver after revoke")
        );
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn bdec_link_proof_accepts_then_rejects_after_revoke() {
        let mut system = bdec_setup(128, 8).expect("setup");
        let user = bdec_prigen(&system).expect("prigen");

        let old_pseudonym = bdec_nym_key(&system, &user).expect("nymkey old");
        let new_pseudonym = bdec_nym_key(&system, &user).expect("nymkey new");
        let link = bdec_link_pseudonyms(&system, &user, &old_pseudonym, &new_pseudonym)
            .expect("link proof");
        assert!(bdec_verify_link_proof(&system, &link).expect("link verify"));

        bdec_revoke(&mut system, &user.public_key).expect("revoke");
        assert!(!bdec_verify_link_proof(&system, &link).expect("link verify after revoke"));
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn bdec_merkle_attrs_and_zk_revocation_flow() {
        let mut system = bdec_setup_zk(128, 8, 20).expect("setup");
        let user = bdec_prigen(&system).expect("prigen");
        let nym_ta = bdec_nym_key(&system, &user).expect("nymkey");

        let attrs = vec![
            "degree:ComputerScience".to_string(),
            "year:2024".to_string(),
            "issuer:TA1".to_string(),
        ];
        let cred = bdec_issue_credential_merkle_attrs(&system, &user, &nym_ta, attrs.clone())
            .expect("cregen merkle");
        assert!(bdec_verify_credential(&system, &cred).expect("crever"));

        let disclosed = vec![attrs[0].clone(), attrs[1].clone()];
        let mut proofs = Vec::new();
        for attr in &disclosed {
            proofs.push(bdec_attribute_merkle_proof(0, &cred.attributes, attr).expect("proof"));
        }
        let shown = bdec_show_credential_paper_merkle(
            &system,
            &user,
            &[cred.clone()],
            disclosed,
            proofs,
        )
        .expect("showcre merkle");
        assert!(
            bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
                .expect("showver")
        );

        bdec_revoke(&mut system, &user.public_key).expect("revoke");
        assert!(
            !bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
                .expect("showver after revoke")
        );
    }
}

// ============================================================================
// New "Paper" API: Minimal credential publishing (ppk, h, c, ε)
// ============================================================================

/// Minimal paper-aligned credential that publishes only (ppk, h, c, ε).
///
/// This credential format uses the new `build_loquat_r1cs_pk_sig_witness_inner` function
/// to prove knowledge of a valid Loquat signature without revealing the full signature.
/// Only the essential public components are published:
/// - ppk: pseudonym public key
/// - h: message commitment hash
/// - c: Aurora commitment
/// - ε: Aurora proof of knowledge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BdecPaperCredential {
    /// Pseudonym public key (ppk)
    pub pseudonym_public: Vec<u8>,
    /// Message commitment hash (h)
    pub message_commitment: [u8; 32],
    /// Aurora commitment (c)
    pub aurora_commitment: [u8; 32],
    /// Aurora proof (ε)
    pub aurora_proof: AuroraProof,
}

/// Create a minimal paper-aligned credential from a user's Loquat signature.
///
/// This function uses the new witness builder that enforces the full Loquat verification
/// circuit including LDT queries, producing an Aurora proof that attests to signature validity
/// without revealing the signature itself.
///
/// # Arguments
/// * `system` - BDEC system parameters
/// * `user_keypair` - User's long-term keypair (sk_U, pk_U)
/// * `message` - Message being signed (e.g., attribute commitment)
/// * `signature` - Valid Loquat signature on the message
///
/// # Returns
/// A `BdecPaperCredential` containing only (ppk, h, c, ε)
pub fn bdec_paper_create_credential(
    system: &BdecSystem,
    user_keypair: &LoquatKeyPair,
    message: &[u8],
    signature: &LoquatSignature,
) -> LoquatResult<BdecPaperCredential> {
    // Verify the signature is valid before creating the credential
    if !loquat_verify(message, signature, &user_keypair.public_key, &system.params.loquat_params)? {
        return Err(LoquatError::verification_failure(
            "signature verification failed during paper credential creation",
        ));
    }

    // Build the R1CS instance and witness using the new extended witness builder
    let (r1cs_instance, r1cs_witness) = crate::snarks::build_loquat_r1cs_pk_sig_witness(
        message,
        signature,
        &user_keypair.public_key,
        &system.params.loquat_params,
    )?;

    // Generate Aurora proof
    let aurora_proof = aurora_prove(&r1cs_instance, &r1cs_witness, &system.params.aurora_params)?;

    // Extract message commitment from signature
    let message_commitment: [u8; 32] = signature
        .message_commitment
        .as_slice()
        .try_into()
        .map_err(|_| LoquatError::verification_failure("invalid message commitment length"))?;

    // Compute Aurora commitment (hash of instance)
    let mut hasher = Sha256::new();
    hasher.update(&system.params.crs_digest);
    for constraint in &r1cs_instance.constraints {
        // Simplified commitment - in production, use a proper binding commitment
        hasher.update(&[constraint.a.len() as u8]);
    }
    let aurora_commitment = hasher.finalize().into();

    // Generate pseudonym public key (serialized)
    let pseudonym = bdec_nym_key(system, user_keypair)?;

    Ok(BdecPaperCredential {
        pseudonym_public: pseudonym.public,
        message_commitment,
        aurora_commitment,
        aurora_proof,
    })
}

/// Verify a minimal paper-aligned credential.
///
/// This function verifies the Aurora proof without requiring access to the full signature.
/// It reconstructs the R1CS instance from public information and verifies the proof.
///
/// # Arguments
/// * `system` - BDEC system parameters
/// * `credential` - Paper credential to verify
/// * `message` - Message that was signed
///
/// # Returns
/// `true` if the credential is valid, `false` otherwise
pub fn bdec_paper_verify_credential(
    system: &BdecSystem,
    credential: &BdecPaperCredential,
    message: &[u8],
) -> LoquatResult<bool> {
    // Build the R1CS instance (instance-only generation)
    let r1cs_instance = crate::snarks::build_loquat_r1cs_pk_sig_witness_instance(
        message,
        &system.params.loquat_params,
    )?;

    // Verify the Aurora proof (pass None for verification hints)
    let result = aurora_verify(&r1cs_instance, &credential.aurora_proof, &system.params.aurora_params, None)?;
    // If aurora_verify returns Some(_), the verification succeeded; None indicates failure
    Ok(result.is_some())
}

#[cfg(test)]
mod paper_api_tests {
    use super::*;

    #[test]
    fn test_bdec_paper_credential_create_and_verify() {
        // Setup BDEC system
        let system = bdec_setup(128, 3).expect("setup");

        // Generate user keypair
        let user = bdec_prigen(&system).expect("prigen");

        // Create a message (e.g., attribute commitment)
        let message = b"test_message_for_paper_credential";

        // Create a Loquat signature on the message
        let signature = loquat_sign(message, &user, &system.params.loquat_params).expect("sign");

        // Create paper credential using new API
        let credential = bdec_paper_create_credential(&system, &user, message, &signature)
            .expect("paper credential creation");

        // Verify the paper credential
        assert!(
            bdec_paper_verify_credential(&system, &credential, message).expect("paper verify"),
            "Paper credential verification failed"
        );

        // Verify that tampering with the message causes verification to fail
        let tampered_message = b"tampered_message";
        assert!(
            !bdec_paper_verify_credential(&system, &credential, tampered_message)
                .expect("paper verify tampered"),
            "Tampered credential should not verify"
        );
    }

    #[test]
    fn test_bdec_vc_like_credential_flow() {
        println!("\n=== BDEC VC-like Credential Flow Test ===\n");

        // =========================================================================
        // Step 1: Setup (corresponds to Setup in paper)
        // =========================================================================
        println!("Step 1: BDEC System Setup");
        let system = bdec_setup(128, 5).expect("setup");
        println!("  ✓ System parameters initialized");
        println!("  ✓ Loquat params: λ={}, max_attributes={}", 128, 5);

        // =========================================================================
        // Step 2: PriGen (User generates long-term keypair)
        // =========================================================================
        println!("\nStep 2: User Key Generation (PriGen)");
        let user_keypair = bdec_prigen(&system).expect("prigen");
        println!("  ✓ Generated (sk_U, pk_U)");
        println!("  ✓ pk_U length: {} bits", user_keypair.public_key.len());

        // =========================================================================
        // Step 3: NymKey (Generate pseudonym for TA)
        // =========================================================================
        println!("\nStep 3: Pseudonym Generation (NymKey for TA)");
        let pseudonym_ta = bdec_nym_key(&system, &user_keypair).expect("nym_key");
        println!("  ✓ Generated pseudonym (ppk_U_TA, psk_U_TA)");
        println!("  ✓ ppk_U_TA length: {} bytes", pseudonym_ta.public.len());

        // =========================================================================
        // Step 4: CreGen (Issue credential with attributes)
        // =========================================================================
        println!("\nStep 4: Credential Generation (CreGen)");
        let attributes = vec![
            "Name:Alice".to_string(),
            "University:XYZ University".to_string(),
            "Degree:Bachelor of Software Engineering".to_string(),
            "Year:2023".to_string(),
            "GPA:4.8/5".to_string(),
        ];
        println!("  Attributes:");
        for attr in &attributes {
            println!("    - {}", attr);
        }

        let credential = bdec_issue_credential(&system, &user_keypair, &pseudonym_ta, attributes.clone())
            .expect("issue credential");

        println!("  ✓ Generated credential signature c_U_TA");
        println!("  ✓ Computed attribute hash h_U_TA");
        println!("  ✓ Generated zkSNARK proof ε_c_U_TA");

        // Map to VC-like structure
        println!("\n  VC-like structure mapping:");
        println!("  {{");
        println!("    \"type\": [\"BDECApprovedCredential\"],");
        println!("    \"issuer\": {{ \"id\": \"did:example:TA-XYZ-University\" }},");
        println!("    \"credentialSubject\": {{");
        let ppk_sample = &pseudonym_ta.public[..8.min(pseudonym_ta.public.len())];
        println!("      \"id\": \"bdec:ppk:{}\",", hex_encode_sample(ppk_sample));
        println!("      \"attributes\": {{ ... {} attributes ... }},", attributes.len());
        println!("      \"commitment\": {{");
        println!("        \"digest\": \"{}...\"", hex_encode_sample(&credential.attribute_hash[..8]));
        println!("      }}");
        println!("    }},");
        println!("    \"bdecArtifacts\": {{");
        println!("      \"ppk_U_TA\": \"{}...\",", hex_encode_sample(ppk_sample));
        println!("      \"c_U_TA\": \"<signature bytes>\",");
        println!("      \"epsilon_c_U_TA\": \"<proof bytes>\"");
        println!("    }}");
        println!("  }}");

        // =========================================================================
        // Step 5: CreVer (Verify the credential - simulates TA verification)
        // =========================================================================
        println!("\nStep 5: Credential Verification (CreVer)");
        let verification_result = bdec_verify_credential(&system, &credential).expect("verify credential");
        assert!(verification_result, "Credential verification failed");
        println!("  ✓ TA verified credential successfully");
        println!("  ✓ Ready for on-chain publication");

        // =========================================================================
        // Step 6: ShowCre (Create presentation for verifier)
        // =========================================================================
        println!("\nStep 6: Presentation Generation (ShowCre)");
        let disclosed = vec![
            "Degree:Bachelor of Software Engineering".to_string(),
            "University:XYZ University".to_string(),
        ];
        println!("  Disclosed attributes:");
        for attr in &disclosed {
            println!("    - {}", attr);
        }

        let shown_credential = bdec_show_credential_paper(
            &system,
            &user_keypair,
            &[credential.clone()],
            disclosed.clone(),
        ).expect("show credential");

        println!("  ✓ Generated verifier pseudonym ppk_U_V");
        println!("  ✓ Computed disclosure hash h_U_V");
        println!("  ✓ Generated shown credential signature c_U_V");
        println!("  ✓ Generated zkSNARK proof ε_c_U_V");

        // Map to VC-like shown credential structure
        println!("\n  Shown credential VC-like structure:");
        println!("  {{");
        println!("    \"type\": [\"BDECShownCredential\"],");
        println!("    \"holderPseudonym\": {{");
        let vpk_sample = &shown_credential.verifier_pseudonym.public[..8.min(shown_credential.verifier_pseudonym.public.len())];
        println!("      \"id\": \"bdec:ppk:{}\",", hex_encode_sample(vpk_sample));
        println!("      \"forVerifier\": \"did:example:Company-V\"");
        println!("    }},");
        println!("    \"disclosedAttributes\": {{ ... {} attributes ... }},", disclosed.len());
        println!("    \"commitment\": {{");
        println!("      \"digest\": \"{}...\"", hex_encode_sample(&shown_credential.disclosure_hash[..8]));
        println!("    }},");
        println!("    \"bdecArtifacts\": {{");
        println!("      \"c_U_V\": \"<signature bytes>\",");
        println!("      \"epsilon_c_U_V\": \"<proof bytes>\"");
        println!("    }}");
        println!("  }}");

        // =========================================================================
        // Step 7: ShowVer (Verifier checks the presentation)
        // =========================================================================
        println!("\nStep 7: Presentation Verification (ShowVer)");
        let show_verification_result = bdec_verify_shown_credential_paper(
            &system,
            &shown_credential,
            &shown_credential.verifier_pseudonym.public,
        ).expect("verify shown credential");
        assert!(show_verification_result, "Shown credential verification failed");
        println!("  ✓ Verifier confirmed presentation validity");
        println!("  ✓ Pseudonym ppk_U_V verified");
        println!("  ✓ Disclosed attributes confirmed");

        // =========================================================================
        // Step 8: Demonstrate revocation
        // =========================================================================
        println!("\nStep 8: Revocation Test");
        let mut system_mut = system.clone();
        bdec_revoke(&mut system_mut, &user_keypair.public_key).expect("revoke");
        println!("  ✓ User pk_U added to revocation list");

        let revoked_verification = bdec_verify_shown_credential_paper(
            &system_mut,
            &shown_credential,
            &shown_credential.verifier_pseudonym.public,
        ).expect("verify after revocation");
        assert!(!revoked_verification, "Revoked credential should not verify");
        println!("  ✓ Revoked credential correctly rejected");

        println!("\n=== Test Complete ===");
        println!("All BDEC operations verified successfully!");
        println!("\nKey insights:");
        println!("  • Credentials contain cryptographic artifacts (ppk, c, ε), not JSON signatures");
        println!("  • Attributes are hashed into commitments (h = H(A))");
        println!("  • zkSNARK proofs bind pseudonyms to hidden pk_U");
        println!("  • Selective disclosure via commitment to H(A↓)");
        println!("  • Revocation via pk_U publication (privacy-preserving until revoked)");
    }
}

// Helper functions for test output formatting
fn hex_encode_sample(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()
}