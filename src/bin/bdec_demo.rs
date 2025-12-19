use vc_pqc::{
    BdecShownCredentialPaper, bdec_issue_credential, bdec_prigen, bdec_revoke, bdec_setup,
    bdec_show_credential_paper, bdec_verify_credential, bdec_verify_shown_credential_paper,
};

fn main() -> vc_pqc::LoquatResult<()> {
    println!("[bdec_demo] setup...");
    let mut system = bdec_setup(128, 8)?;

    println!("[bdec_demo] prigen...");
    let user = bdec_prigen(&system)?;

    // TA pseudonym (ppk_U,TA, psk_U,TA)
    println!("[bdec_demo] nymkey (for TA)...");
    let nym_ta = vc_pqc::bdec_nym_key(&system, &user)?;

    println!("[bdec_demo] cregen...");
    let attrs = vec![
        "degree:ComputerScience".to_string(),
        "year:2024".to_string(),
        "issuer:TA1".to_string(),
    ];
    let cred = bdec_issue_credential(&system, &user, &nym_ta, attrs.clone())?;

    println!("[bdec_demo] crever...");
    let ok = bdec_verify_credential(&system, &cred)?;
    println!("  credential ok = {ok}");
    if !ok {
        return Err(vc_pqc::LoquatError::verification_failure(
            "credential verification failed",
        ));
    }

    println!("[bdec_demo] showcre (paper-aligned)...");
    let disclosed = vec![attrs[0].clone(), attrs[1].clone()];
    let shown: BdecShownCredentialPaper =
        bdec_show_credential_paper(&system, &user, &[cred.clone()], disclosed)?;

    println!("[bdec_demo] showver (paper-aligned)...");
    let ok = bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)?;
    println!("  shown ok = {ok}");
    if !ok {
        return Err(vc_pqc::LoquatError::verification_failure(
            "shown credential verification failed",
        ));
    }

    println!("[bdec_demo] revoke...");
    bdec_revoke(&mut system, &user.public_key)?;

    println!("[bdec_demo] crever after revoke...");
    let ok = bdec_verify_credential(&system, &cred)?;
    println!("  credential ok after revoke = {ok}");

    println!("[bdec_demo] showver after revoke...");
    let ok = bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)?;
    println!("  shown ok after revoke = {ok}");

    Ok(())
}







