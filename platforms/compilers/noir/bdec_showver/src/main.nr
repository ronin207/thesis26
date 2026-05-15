use dep::loquat_lib::{LoquatPublicKey, LoquatSignature, loquat_verify, merkle_non_member};

struct Credential {
    pseudonym_public: [u8; 32],
    pseudonym_signature: LoquatSignature,
    attribute_hash: [u8; 32],
    credential_signature: LoquatSignature,
}

fn degree_allowed(degree_code: u8, allow_cs: bool, allow_ee: bool) -> bool {
    (allow_cs & (degree_code == 1)) | (allow_ee & (degree_code == 2))
}

fn main(
    verifier_pseudonym_public: pub [u8; 32],
    disclosure_hash: pub [u8; 32],
    revocation_root: pub [u8; 32],
    policy_gpa_min: pub u32,
    policy_allow_cs: pub bool,
    policy_allow_ee: pub bool,
    user_pk: LoquatPublicKey,
    credential: Credential,
    verifier_pseudonym_sig: LoquatSignature,
    shown_credential_sig: LoquatSignature,
    revocation_path: [[u8; 32]; 20],
    gpa_tenths: u32,
    degree_code: u8,
) {
    assert(loquat_verify(
        credential.attribute_hash,
        credential.credential_signature,
        user_pk,
    ));

    assert(loquat_verify(
        credential.pseudonym_public,
        credential.pseudonym_signature,
        user_pk,
    ));

    assert(loquat_verify(
        verifier_pseudonym_public,
        verifier_pseudonym_sig,
        user_pk,
    ));

    assert(loquat_verify(
        disclosure_hash,
        shown_credential_sig,
        user_pk,
    ));

    assert(merkle_non_member(user_pk, revocation_root, revocation_path));
    assert(gpa_tenths >= policy_gpa_min);
    assert(degree_allowed(degree_code, policy_allow_cs, policy_allow_ee));
}
