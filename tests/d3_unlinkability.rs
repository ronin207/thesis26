use vc_pqc::{
    bdec_issue_credential, bdec_nym_key, bdec_prigen, bdec_setup,
    bdec_show_credential_paper, bdec_verify_shown_credential_paper,
};

// ── Fast-path: pseudonym key diversity (no Aurora proving needed) ─────────────

/// Each call to `bdec_nym_key` samples a fresh random 32-byte public value.
/// This test verifies that the randomness is working as expected without
/// requiring a full Aurora proof.
#[test]
fn d3_pseudonym_keys_are_always_fresh() {
    let system = bdec_setup(80, 4).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");

    let nym1 = bdec_nym_key(&system, &user).expect("nym 1");
    let nym2 = bdec_nym_key(&system, &user).expect("nym 2");
    let nym3 = bdec_nym_key(&system, &user).expect("nym 3");

    assert_ne!(nym1.public, nym2.public, "consecutive pseudonym keys must differ");
    assert_ne!(nym2.public, nym3.public, "consecutive pseudonym keys must differ");
    assert_ne!(nym1.public, nym3.public, "all three pseudonym keys must differ");
}

/// Even with k > 1 credentials (issued under distinct pseudonyms), the verifier
/// pseudonym generated at show-time is fresh and unrelated to the issuer pseudonyms.
#[test]
fn d3_verifier_pseudonym_differs_from_issuer_pseudonyms() {
    let system = bdec_setup(80, 4).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");

    let ta_nym_1 = bdec_nym_key(&system, &user).expect("ta nym 1");
    let ta_nym_2 = bdec_nym_key(&system, &user).expect("ta nym 2");

    // Verifier pseudonym is also freshly sampled; it must differ from both TA pseudonyms.
    let verifier_nym = bdec_nym_key(&system, &user).expect("verifier nym");

    assert_ne!(
        verifier_nym.public, ta_nym_1.public,
        "verifier pseudonym must differ from TA pseudonym 1"
    );
    assert_ne!(
        verifier_nym.public, ta_nym_2.public,
        "verifier pseudonym must differ from TA pseudonym 2"
    );
}

// ── Full unlinkability tests (Aurora proving path, expensive) ─────────────────

#[test]
#[ignore = "expensive: Aurora proving path"]
fn d3_fresh_verifier_pseudonyms_prevent_accidental_linkability() {
    let system = bdec_setup(80, 8).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");
    let ta_nym = bdec_nym_key(&system, &user).expect("nym");

    let attrs = vec!["gpa:35".to_string(), "degree:CS".to_string()];
    let credential = bdec_issue_credential(&system, &user, &ta_nym, attrs.clone()).expect("issue");

    let shown_one = bdec_show_credential_paper(
        &system,
        &user,
        &[credential.clone()],
        vec!["gpa:35".to_string()],
    )
    .expect("show one");

    let shown_two =
        bdec_show_credential_paper(&system, &user, &[credential], vec!["gpa:35".to_string()])
            .expect("show two");

    assert_ne!(
        shown_one.verifier_pseudonym.public, shown_two.verifier_pseudonym.public,
        "verifier pseudonym should rotate across presentations"
    );

    assert!(
        bdec_verify_shown_credential_paper(
            &system,
            &shown_one,
            &shown_one.verifier_pseudonym.public
        )
        .expect("verify one")
    );
    assert!(
        bdec_verify_shown_credential_paper(
            &system,
            &shown_two,
            &shown_two.verifier_pseudonym.public
        )
        .expect("verify two")
    );
}

/// Show the same credential four times and assert all four verifier pseudonyms
/// are mutually distinct.  Tests the "more than two shows" requirement.
#[test]
#[ignore = "expensive: Aurora proving path, 4 × show + verify"]
fn d3_verifier_pseudonyms_distinct_across_four_presentations() {
    let system = bdec_setup(80, 8).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");
    let ta_nym = bdec_nym_key(&system, &user).expect("nym");
    let credential =
        bdec_issue_credential(&system, &user, &ta_nym, vec!["gpa:35".to_string()])
            .expect("issue");

    let mut nyms: Vec<Vec<u8>> = Vec::new();
    for i in 0..4 {
        let shown = bdec_show_credential_paper(
            &system,
            &user,
            &[credential.clone()],
            vec!["gpa:35".to_string()],
        )
        .unwrap_or_else(|e| panic!("show {} failed: {e}", i));
        assert!(
            bdec_verify_shown_credential_paper(
                &system,
                &shown,
                &shown.verifier_pseudonym.public,
            )
            .unwrap_or_else(|e| panic!("verify {} failed: {e}", i)),
            "presentation {} must verify",
            i
        );
        nyms.push(shown.verifier_pseudonym.public.clone());
    }
    // All 4 pseudonyms must be pairwise distinct.
    for i in 0..nyms.len() {
        for j in (i + 1)..nyms.len() {
            assert_ne!(
                nyms[i], nyms[j],
                "pseudonyms at show {} and show {} must differ",
                i, j
            );
        }
    }
}

/// k = 2 credentials issued to the same user; both presentations must verify and
/// the two verifier pseudonyms must differ.
#[test]
#[ignore = "expensive: Aurora proving path, k=2 credentials"]
fn d3_unlinkability_with_k2_credentials() {
    let system = bdec_setup(80, 8).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");

    let ta_nym_1 = bdec_nym_key(&system, &user).expect("ta nym 1");
    let ta_nym_2 = bdec_nym_key(&system, &user).expect("ta nym 2");
    let cred_1 = bdec_issue_credential(
        &system, &user, &ta_nym_1, vec!["issuer:A".to_string(), "gpa:35".to_string()],
    )
    .expect("issue 1");
    let cred_2 = bdec_issue_credential(
        &system, &user, &ta_nym_2, vec!["issuer:B".to_string(), "gpa:35".to_string()],
    )
    .expect("issue 2");

    let shown_1 = bdec_show_credential_paper(
        &system, &user, &[cred_1.clone()], vec!["gpa:35".to_string()],
    )
    .expect("show cred 1");
    let shown_2 = bdec_show_credential_paper(
        &system, &user, &[cred_2.clone()], vec!["gpa:35".to_string()],
    )
    .expect("show cred 2");

    assert_ne!(
        shown_1.verifier_pseudonym.public, shown_2.verifier_pseudonym.public,
        "presentations from distinct credentials must yield distinct verifier pseudonyms"
    );
    assert!(
        bdec_verify_shown_credential_paper(&system, &shown_1, &shown_1.verifier_pseudonym.public)
            .expect("verify 1"),
        "credential 1 presentation must verify"
    );
    assert!(
        bdec_verify_shown_credential_paper(&system, &shown_2, &shown_2.verifier_pseudonym.public)
            .expect("verify 2"),
        "credential 2 presentation must verify"
    );
}

/// Test with varying attribute counts to ensure pseudonym freshness is
/// independent of how many attributes are disclosed.
#[test]
#[ignore = "expensive: Aurora proving path, attribute-count sweep"]
fn d3_unlinkability_across_attribute_counts() {
    // Attribute counts to sweep: 1, 2, 4 (each within the max_attributes=8 limit).
    for attr_count in [1usize, 2, 4] {
        let system = bdec_setup(80, 8).expect("setup");
        let user = bdec_prigen(&system).expect("prigen");
        let ta_nym = bdec_nym_key(&system, &user).expect("ta nym");
        let all_attrs: Vec<String> = (0..attr_count)
            .map(|i| format!("attr-{i}:val-{i}"))
            .collect();
        let credential =
            bdec_issue_credential(&system, &user, &ta_nym, all_attrs.clone()).expect("issue");

        let shown_a = bdec_show_credential_paper(
            &system, &user, &[credential.clone()], all_attrs.clone(),
        )
        .expect("show A");
        let shown_b = bdec_show_credential_paper(
            &system, &user, &[credential.clone()], all_attrs.clone(),
        )
        .expect("show B");

        assert_ne!(
            shown_a.verifier_pseudonym.public, shown_b.verifier_pseudonym.public,
            "attr_count={}: verifier pseudonyms must differ across presentations",
            attr_count
        );
        assert!(
            bdec_verify_shown_credential_paper(
                &system, &shown_a, &shown_a.verifier_pseudonym.public,
            )
            .expect("verify A"),
            "attr_count={}: presentation A must verify",
            attr_count
        );
        assert!(
            bdec_verify_shown_credential_paper(
                &system, &shown_b, &shown_b.verifier_pseudonym.public,
            )
            .expect("verify B"),
            "attr_count={}: presentation B must verify",
            attr_count
        );
    }
}
