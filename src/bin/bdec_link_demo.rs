use vc_pqc::{bdec_link_pseudonyms, bdec_nym_key, bdec_prigen, bdec_revoke, bdec_setup, bdec_verify_link_proof};

fn main() -> vc_pqc::LoquatResult<()> {
    println!("[bdec_link_demo] setup...");
    let mut system = bdec_setup(128, 8)?;

    println!("[bdec_link_demo] prigen...");
    let user = bdec_prigen(&system)?;

    println!("[bdec_link_demo] nymkey (old)...");
    let old_pseudonym = bdec_nym_key(&system, &user)?;

    println!("[bdec_link_demo] nymkey (new)...");
    let new_pseudonym = bdec_nym_key(&system, &user)?;

    println!("[bdec_link_demo] link...");
    let link = bdec_link_pseudonyms(&system, &user, &old_pseudonym, &new_pseudonym)?;

    println!("[bdec_link_demo] linkver...");
    let ok = bdec_verify_link_proof(&system, &link)?;
    println!("  link ok = {ok}");

    println!("[bdec_link_demo] revoke...");
    bdec_revoke(&mut system, &user.public_key)?;

    println!("[bdec_link_demo] linkver after revoke...");
    let ok = bdec_verify_link_proof(&system, &link)?;
    println!("  link ok after revoke = {ok}");

    Ok(())
}



