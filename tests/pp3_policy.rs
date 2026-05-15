use vc_pqc::{
    PolicyInput, PolicyPredicate, bdec_issue_credential, bdec_nym_key, bdec_prigen, bdec_setup_zk,
    bdec_show_credential_with_policy_paper, bdec_verify_shown_credential_with_policy_paper,
    evaluate_policy_input,
};

#[test]
fn pp3_policy_only_update_accepts_same_holder() {
    let disclosed = vec!["gpa:35".to_string(), "degree:CS".to_string()];

    let v1 = PolicyInput {
        predicates: vec![PolicyPredicate::GteI64 {
            key: "gpa".to_string(),
            min_value: 30,
        }],
    };

    let v2 = PolicyInput {
        predicates: vec![
            PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: 30,
            },
            PolicyPredicate::OneOf {
                key: "degree".to_string(),
                allowed_values: vec!["CS".to_string(), "EE".to_string()],
            },
        ],
    };

    assert!(evaluate_policy_input(&disclosed, &v1));
    assert!(evaluate_policy_input(&disclosed, &v2));
}

#[test]
fn pp3_schema_gap_rejects_when_required_field_missing() {
    let disclosed = vec!["gpa:35".to_string()];

    let policy = PolicyInput {
        predicates: vec![
            PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: 30,
            },
            PolicyPredicate::OneOf {
                key: "degree".to_string(),
                allowed_values: vec!["CS".to_string(), "EE".to_string()],
            },
        ],
    };

    assert!(!evaluate_policy_input(&disclosed, &policy));
}

#[test]
#[ignore = "expensive: Aurora proving path"]
fn pp3_policy_is_enforced_inside_showver_proof() {
    let system = bdec_setup_zk(80, 8, 20).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");
    let ta_nym = bdec_nym_key(&system, &user).expect("nym");
    let credential = bdec_issue_credential(
        &system,
        &user,
        &ta_nym,
        vec![
            "issuer:demo".to_string(),
            "gpa:35".to_string(),
            "degree:CS".to_string(),
        ],
    )
    .expect("issue");

    let policy_v2 = PolicyInput {
        predicates: vec![
            PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: 30,
            },
            PolicyPredicate::OneOf {
                key: "degree".to_string(),
                allowed_values: vec!["CS".to_string(), "EE".to_string()],
            },
        ],
    };

    let shown = bdec_show_credential_with_policy_paper(
        &system,
        &user,
        &[credential],
        vec!["gpa:35".to_string(), "degree:CS".to_string()],
        &policy_v2,
    )
    .expect("show with policy");

    assert!(
        bdec_verify_shown_credential_with_policy_paper(
            &system,
            &shown,
            &shown.verifier_pseudonym.public,
            &policy_v2,
        )
        .expect("verify policy-bound proof")
    );

    let stricter = PolicyInput {
        predicates: vec![PolicyPredicate::GteI64 {
            key: "gpa".to_string(),
            min_value: 40,
        }],
    };

    assert!(
        !bdec_verify_shown_credential_with_policy_paper(
            &system,
            &shown,
            &shown.verifier_pseudonym.public,
            &stricter,
        )
        .expect("verify with mismatched policy"),
        "proof should not verify against a different policy instance"
    );
}

// ── Fast-path policy evaluation tests (no Aurora proving needed) ──────────────

/// A vacuous policy with zero predicates must accept every attribute set,
/// including an empty one.  This is the identity / trivially-satisfied case.
#[test]
fn pp3_vacuous_policy_always_passes() {
    let empty_policy = PolicyInput { predicates: vec![] };

    assert!(
        evaluate_policy_input(&[], &empty_policy),
        "vacuous policy must accept an empty attribute set"
    );
    assert!(
        evaluate_policy_input(&["gpa:35".to_string(), "degree:CS".to_string()], &empty_policy),
        "vacuous policy must accept a non-empty attribute set"
    );
}

/// `GteI64` must reject when the disclosed value is strictly below the
/// minimum threshold, and accept when it equals or exceeds the threshold.
#[test]
fn pp3_gte_i64_rejects_value_below_threshold() {
    let policy = PolicyInput {
        predicates: vec![PolicyPredicate::GteI64 {
            key: "gpa".to_string(),
            min_value: 35,
        }],
    };

    // Value == threshold: accept.
    assert!(
        evaluate_policy_input(&["gpa:35".to_string()], &policy),
        "GteI64 must accept value equal to the threshold"
    );

    // Value strictly below threshold: reject.
    assert!(
        !evaluate_policy_input(&["gpa:29".to_string()], &policy),
        "GteI64 must reject value strictly below the threshold"
    );

    // Value above threshold: accept.
    assert!(
        evaluate_policy_input(&["gpa:40".to_string()], &policy),
        "GteI64 must accept value above the threshold"
    );
}

/// `OneOf` with an empty allowed-values list can never match any disclosed
/// value, so it must always evaluate to false.
#[test]
fn pp3_one_of_empty_allowed_set_always_rejects() {
    let policy = PolicyInput {
        predicates: vec![PolicyPredicate::OneOf {
            key: "degree".to_string(),
            allowed_values: vec![],
        }],
    };

    assert!(
        !evaluate_policy_input(&["degree:CS".to_string()], &policy),
        "OneOf with empty allowed set must reject even a disclosed value"
    );
    assert!(
        !evaluate_policy_input(&[], &policy),
        "OneOf with empty allowed set must reject an empty attribute set"
    );
}

/// Fast structural check: a policy that passes on a set of attributes must
/// fail if the key is absent from the disclosed attributes entirely.
#[test]
fn pp3_gte_i64_rejects_missing_key() {
    let policy = PolicyInput {
        predicates: vec![PolicyPredicate::GteI64 {
            key: "gpa".to_string(),
            min_value: 30,
        }],
    };

    // "degree:CS" is disclosed but "gpa" is absent.
    assert!(
        !evaluate_policy_input(&["degree:CS".to_string()], &policy),
        "GteI64 must reject when the required key is absent from disclosed attributes"
    );
}

// ── Cross-policy-version rejection (Aurora proving path, expensive) ───────────

/// A presentation produced under policy v1 must not verify under policy v2
/// (even when the underlying credentials would satisfy v2).  The Aurora proof
/// binds to the exact policy commitment, so any policy change must invalidate
/// the prior proof.
#[test]
#[ignore = "expensive: Aurora proving path, cross-policy-version binding check"]
fn pp3_cross_policy_version_rejection() {
    let system = bdec_setup_zk(80, 8, 20).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");
    let ta_nym = bdec_nym_key(&system, &user).expect("nym");
    let credential = bdec_issue_credential(
        &system,
        &user,
        &ta_nym,
        vec![
            "gpa:35".to_string(),
            "degree:CS".to_string(),
        ],
    )
    .expect("issue");

    // v1: only a GPA check.
    let policy_v1 = PolicyInput {
        predicates: vec![PolicyPredicate::GteI64 {
            key: "gpa".to_string(),
            min_value: 30,
        }],
    };

    // v2: GPA + degree membership check.
    let policy_v2 = PolicyInput {
        predicates: vec![
            PolicyPredicate::GteI64 {
                key: "gpa".to_string(),
                min_value: 30,
            },
            PolicyPredicate::OneOf {
                key: "degree".to_string(),
                allowed_values: vec!["CS".to_string(), "EE".to_string()],
            },
        ],
    };

    // Produce a proof bound to v1.
    let shown_v1 = bdec_show_credential_with_policy_paper(
        &system,
        &user,
        &[credential],
        vec!["gpa:35".to_string(), "degree:CS".to_string()],
        &policy_v1,
    )
    .expect("show under policy v1");

    // The proof verifies under v1 (the policy it was built with).
    assert!(
        bdec_verify_shown_credential_with_policy_paper(
            &system,
            &shown_v1,
            &shown_v1.verifier_pseudonym.public,
            &policy_v1,
        )
        .expect("verify under v1"),
        "proof must verify under the policy it was produced with"
    );

    // The same proof must NOT verify under v2, even though the credential
    // would satisfy v2's predicates — the Aurora proof is bound to v1's
    // commitment. Acceptable rejection signals are either `Ok(false)` (clean
    // policy mismatch) or `Err(_)` (sumcheck/transcript inconsistency surfaced
    // by Aurora/Loquat — also a rejection from the verifier's standpoint).
    let cross_check = bdec_verify_shown_credential_with_policy_paper(
        &system,
        &shown_v1,
        &shown_v1.verifier_pseudonym.public,
        &policy_v2,
    );
    let rejected = match cross_check {
        Ok(false) => true,
        Ok(true) => false,
        Err(_) => true,
    };
    assert!(
        rejected,
        "proof produced under policy v1 must not verify under policy v2"
    );
}
