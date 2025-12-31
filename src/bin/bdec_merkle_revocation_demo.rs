use vc_pqc::{
    BdecAttributeMerkleProof, bdec_attribute_merkle_proof, bdec_issue_credential_merkle_attrs,
    bdec_nym_key, bdec_prigen, bdec_revoke, bdec_setup_zk, bdec_show_credential_paper_merkle,
    bdec_verify_credential, bdec_verify_shown_credential_paper,
};

fn main() -> vc_pqc::LoquatResult<()> {
    println!("[bdec_merkle_revocation_demo] setup (zk revocation enabled)...");
    let mut system = bdec_setup_zk(128, 8, 20)?;

    println!("[bdec_merkle_revocation_demo] prigen...");
    let user = bdec_prigen(&system)?;

    println!("[bdec_merkle_revocation_demo] nymkey (for TA)...");
    let nym_ta = bdec_nym_key(&system, &user)?;

    println!("[bdec_merkle_revocation_demo] cregen (merkle attrs)...");
    let attrs = vec![
        "degree:ComputerScience".to_string(),
        "year:2024".to_string(),
        "issuer:TA1".to_string(),
    ];
    let cred = bdec_issue_credential_merkle_attrs(&system, &user, &nym_ta, attrs.clone())?;

    println!("[bdec_merkle_revocation_demo] crever...");
    let ok = bdec_verify_credential(&system, &cred)?;
    println!("  credential ok = {ok}");

    println!("[bdec_merkle_revocation_demo] showcre (merkle attrs + zk revocation)...");
    let disclosed = vec![attrs[0].clone(), attrs[1].clone()];
    let mut proofs: Vec<BdecAttributeMerkleProof> = Vec::new();
    for attr in &disclosed {
        proofs.push(bdec_attribute_merkle_proof(0, &cred.attributes, attr)?);
    }
    let shown = bdec_show_credential_paper_merkle(&system, &user, &[cred.clone()], disclosed, proofs)?;

    println!("[bdec_merkle_revocation_demo] showver...");
    let ok = bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)?;
    println!("  shown ok = {ok}");

    println!("[bdec_merkle_revocation_demo] revoke...");
    bdec_revoke(&mut system, &user.public_key)?;

    println!("[bdec_merkle_revocation_demo] showver after revoke...");
    let ok = bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)?;
    println!("  shown ok after revoke = {ok}");

    Ok(())
}














