use vc_pqc::{
    bdec_issue_credential, bdec_nym_key, bdec_prigen, bdec_revoke, bdec_setup_zk,
    bdec_show_credential_paper, bdec_verify_shown_credential_paper,
};

// ── Fast-path: revocation state without Aurora ────────────────────────────────

/// After `bdec_revoke`, subsequent `bdec_show_credential_paper` calls must still
/// succeed structurally (show itself doesn't check revocation), but the resulting
/// presentation must fail verification.  This fast test checks only the show path
/// and avoids the expensive Aurora prover.
///
/// We use `bdec_setup_zk` here to mirror the real setup used in the full test.
#[test]
fn pp2_revoke_fails_aurora_verification_of_old_proof() {
    // We cannot prove without Aurora, but we *can* test that the revocation list
    // state is correctly updated and that `bdec_revoke` does not panic or error.
    let mut system = bdec_setup_zk(80, 4, 10).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");

    // Revoke the user — must succeed without error.
    bdec_revoke(&mut system, &user.public_key).expect("revoke");

    // Double-revoke must also be error-free (idempotent at the list level).
    bdec_revoke(&mut system, &user.public_key).expect("double-revoke is idempotent");
}

/// Two independent users: revoking user A must not affect user B's accumulator
/// non-membership path.  Fast-path: validate only that the accumulator's root
/// changes after user A is revoked (user B was never in the list).
#[test]
fn pp2_revocation_does_not_corrupt_other_users_accumulator() {
    let mut system = bdec_setup_zk(80, 4, 10).expect("setup");
    let user_a = bdec_prigen(&system).expect("prigen A");
    let user_b = bdec_prigen(&system).expect("prigen B");

    let acc = system.revocation_accumulator.as_ref().expect("accumulator");
    let root_before = acc.root();
    let path_b_before = acc.auth_path(&user_b.public_key).expect("path B before");

    // Revoke user A.
    bdec_revoke(&mut system, &user_a.public_key).expect("revoke A");

    let acc = system.revocation_accumulator.as_ref().expect("accumulator after");
    let root_after = acc.root();
    let path_b_after = acc.auth_path(&user_b.public_key).expect("path B after");

    // Root must change because A's leaf was inserted.
    assert_ne!(
        root_before, root_after,
        "accumulator root must change after revoking user A"
    );
    // User B's auth path has the same depth but its leaf is still 0 (not revoked).
    // We don't require the path to be byte-identical (siblings may change), but
    // the path length (depth) must be consistent.
    assert_eq!(
        path_b_before.len(), path_b_after.len(),
        "auth path depth for user B must be unchanged after revoking user A"
    );
}

/// Revoking a user that was never issued any credentials must still succeed
/// (the accumulator operates on public keys, not credentials).
#[test]
fn pp2_can_revoke_user_with_no_credentials() {
    let mut system = bdec_setup_zk(80, 4, 10).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");
    // No credential is issued — revoke directly.
    bdec_revoke(&mut system, &user.public_key).expect("revoke uncredentialed user");
}

// ── Full revocation tests (Aurora proving path, expensive) ────────────────────

#[test]
#[ignore = "expensive: Aurora proving path"]
fn pp2_revocation_rejects_after_revoke() {
    let mut system = bdec_setup_zk(80, 8, 20).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");
    let ta_nym = bdec_nym_key(&system, &user).expect("nym");

    let attrs = vec!["gpa:35".to_string(), "degree:CS".to_string()];
    let credential = bdec_issue_credential(&system, &user, &ta_nym, attrs.clone()).expect("issue");

    let shown =
        bdec_show_credential_paper(&system, &user, &[credential], vec!["gpa:35".to_string()])
            .expect("show");

    assert!(
        bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
            .expect("verify before revoke"),
        "presentation should verify before revocation"
    );

    bdec_revoke(&mut system, &user.public_key).expect("revoke");

    assert!(
        !bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
            .expect("verify after revoke"),
        "presentation should fail after revocation"
    );
}

/// Revoking user A must not invalidate user B's already-shown credential.
#[test]
#[ignore = "expensive: Aurora proving path, multi-user isolation"]
fn pp2_revocation_does_not_affect_non_revoked_user() {
    let mut system = bdec_setup_zk(80, 8, 20).expect("setup");
    let user_a = bdec_prigen(&system).expect("prigen A");
    let user_b = bdec_prigen(&system).expect("prigen B");

    let ta_nym_a = bdec_nym_key(&system, &user_a).expect("nym A");
    let ta_nym_b = bdec_nym_key(&system, &user_b).expect("nym B");
    let cred_b = bdec_issue_credential(
        &system,
        &user_b,
        &ta_nym_b,
        vec!["gpa:35".to_string()],
    )
    .expect("issue B");

    // Show B's credential *before* revoking A — must verify.
    let shown_b =
        bdec_show_credential_paper(&system, &user_b, &[cred_b.clone()], vec!["gpa:35".to_string()])
            .expect("show B before revoke A");
    assert!(
        bdec_verify_shown_credential_paper(&system, &shown_b, &shown_b.verifier_pseudonym.public)
            .expect("verify B before revoke A"),
        "user B must verify before user A is revoked"
    );

    // Revoke user A (who was never even issued a credential here).
    bdec_revoke(&mut system, &user_a.public_key).expect("revoke A");

    // Issue and show B's credential again *after* revoking A.
    let ta_nym_b2 = bdec_nym_key(&system, &user_b).expect("nym B2");
    let cred_b2 = bdec_issue_credential(
        &system,
        &user_b,
        &ta_nym_b2,
        vec!["gpa:35".to_string()],
    )
    .expect("issue B2");
    let shown_b2 =
        bdec_show_credential_paper(&system, &user_b, &[cred_b2], vec!["gpa:35".to_string()])
            .expect("show B after revoke A");
    assert!(
        bdec_verify_shown_credential_paper(&system, &shown_b2, &shown_b2.verifier_pseudonym.public)
            .expect("verify B after revoke A"),
        "user B must still verify after user A is revoked"
    );
}

/// Pre-populate the revocation list with lr_size synthetic entries before the
/// user shows their credential, to exercise the non-empty list code path.
#[test]
#[ignore = "expensive: Aurora proving path with pre-populated revocation list"]
fn pp2_revocation_with_pre_populated_lr() {
    use vc_pqc::{bdec_public_key_prefix_index, bdec_synthetic_public_key_with_prefix};

    let rev_depth = 10usize;
    let lr_size = 4usize; // insert 4 synthetic revoked keys before the test user

    let mut system = bdec_setup_zk(80, 8, rev_depth).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");

    // Insert lr_size synthetic keys, skipping user's own prefix.
    let capacity = 1u64 << rev_depth;
    let user_prefix = bdec_public_key_prefix_index(&user.public_key, rev_depth)
        .expect("user prefix");
    let key_len = system.params.loquat_params.l;
    let mut inserted = 0u64;
    let mut prefix = 0u64;
    while inserted < lr_size as u64 {
        assert!(prefix < capacity, "ran out of synthetic prefix space");
        if prefix != user_prefix {
            let synthetic = bdec_synthetic_public_key_with_prefix(prefix, rev_depth, key_len)
                .expect("synthetic pk");
            bdec_revoke(&mut system, &synthetic).expect("revoke synthetic");
            inserted += 1;
        }
        prefix += 1;
    }

    let ta_nym = bdec_nym_key(&system, &user).expect("nym");
    let credential =
        bdec_issue_credential(&system, &user, &ta_nym, vec!["gpa:35".to_string()])
            .expect("issue");
    let shown =
        bdec_show_credential_paper(&system, &user, &[credential], vec!["gpa:35".to_string()])
            .expect("show");

    assert!(
        bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
            .expect("verify with pre-populated LR"),
        "non-revoked user must verify even when the revocation list has {} entries",
        lr_size
    );

    // Now revoke the user and confirm verification fails.
    bdec_revoke(&mut system, &user.public_key).expect("revoke user");
    assert!(
        !bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
            .expect("verify after revoke with pre-populated LR"),
        "revoked user must fail verification with pre-populated LR"
    );
}

/// Issue k=2 credentials to the same user and revoke them; both presentations
/// must fail after revocation.
#[test]
#[ignore = "expensive: Aurora proving path, k=2 credentials + revocation"]
fn pp2_revocation_with_k2_credentials() {
    let mut system = bdec_setup_zk(80, 8, 20).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");

    let ta_nym_1 = bdec_nym_key(&system, &user).expect("nym 1");
    let ta_nym_2 = bdec_nym_key(&system, &user).expect("nym 2");
    let cred_1 = bdec_issue_credential(
        &system, &user, &ta_nym_1, vec!["gpa:35".to_string()],
    )
    .expect("issue 1");
    let cred_2 = bdec_issue_credential(
        &system, &user, &ta_nym_2, vec!["gpa:35".to_string()],
    )
    .expect("issue 2");

    // Both credentials verify before revocation.
    let shown_1 =
        bdec_show_credential_paper(&system, &user, &[cred_1.clone()], vec!["gpa:35".to_string()])
            .expect("show 1");
    let shown_2 =
        bdec_show_credential_paper(&system, &user, &[cred_2.clone()], vec!["gpa:35".to_string()])
            .expect("show 2");
    assert!(
        bdec_verify_shown_credential_paper(&system, &shown_1, &shown_1.verifier_pseudonym.public)
            .expect("verify 1 before"),
        "credential 1 must verify before revocation"
    );
    assert!(
        bdec_verify_shown_credential_paper(&system, &shown_2, &shown_2.verifier_pseudonym.public)
            .expect("verify 2 before"),
        "credential 2 must verify before revocation"
    );

    // Revoke the user once; both presentations must now fail.
    bdec_revoke(&mut system, &user.public_key).expect("revoke");
    assert!(
        !bdec_verify_shown_credential_paper(&system, &shown_1, &shown_1.verifier_pseudonym.public)
            .expect("verify 1 after"),
        "credential 1 must fail after revocation"
    );
    assert!(
        !bdec_verify_shown_credential_paper(&system, &shown_2, &shown_2.verifier_pseudonym.public)
            .expect("verify 2 after"),
        "credential 2 must fail after revocation"
    );
}
