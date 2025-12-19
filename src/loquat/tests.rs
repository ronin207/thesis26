/// Comprehensive Test Suite for Loquat Implementation
///
/// This module contains comprehensive tests that validate the security,
/// correctness, and robustness of the Loquat signature scheme implementation.
/// Tests are organized by functionality and include both positive and
/// negative test cases.

#[cfg(test)]
mod integration_tests {
    use crate::LoquatError;
    use crate::bdec::{
        bdec_issue_credential, bdec_nym_key, bdec_prigen, bdec_revoke, bdec_setup,
        bdec_show_credential_paper, bdec_verify_credential, bdec_verify_shown_credential_paper,
    };
    use crate::loquat::field_p127::Fp2;
    use crate::loquat::field_utils::{F, F2, legendre_prf_secure, u128_to_field};
    use crate::loquat::keygen::keygen_with_params;
    use crate::loquat::setup::loquat_setup;
    use crate::loquat::sign::loquat_sign;
    use crate::loquat::verify::loquat_verify;
    // Note: Earlier iterations of this repo integrated RISC0 receipts into BDEC tests.
    // The current paper-aligned BDEC implementation does not include zkVM receipts, so
    // these integration tests exercise the host-side BDEC flow directly.

    /// Test complete signature generation and verification flow
    #[test]
    fn test_complete_signature_flow() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"Integration test message for complete flow";

        let signature =
            loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");

        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)
            .expect("Signature verification should complete");

        assert!(is_valid, "Valid signature should verify successfully");
    }

    /// Test signature unforgeability (wrong key rejection)
    #[test]
    fn test_signature_unforgeability() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair1 = keygen_with_params(&params).expect("Key generation 1 should succeed");
        let keypair2 = keygen_with_params(&params).expect("Key generation 2 should succeed");
        let message = b"Unforgeability test message";

        let signature =
            loquat_sign(message, &keypair1, &params).expect("Signature generation should succeed");

        let is_valid = loquat_verify(message, &signature, &keypair2.public_key, &params)
            .expect("Verification should complete");

        assert!(
            !is_valid,
            "Signature should not verify with wrong public key"
        );
    }

    /// Test message binding (signature changes with different messages)
    #[test]
    fn test_message_binding() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message1 = b"Original message";
        let message2 = b"Modified message";

        let signature =
            loquat_sign(message1, &keypair, &params).expect("Signature generation should succeed");

        let is_valid = loquat_verify(message2, &signature, &keypair.public_key, &params)
            .expect("Verification should complete");

        assert!(
            !is_valid,
            "Signature should not verify for different message"
        );
    }

    /// Test malformed signature rejection
    #[test]
    fn test_malformed_signature_rejection() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"Malformed signature test";

        let mut signature =
            loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");

        // Tamper with residuosity symbols
        if !signature.o_values.is_empty() && !signature.o_values[0].is_empty() {
            signature.o_values[0][0] = signature.o_values[0][0] + F::one();
            let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)
                .expect("Verification should complete");
            assert!(!is_valid, "Tampered residuosity symbols should be rejected");
            signature.o_values[0][0] = signature.o_values[0][0] - F::one(); // Restore
        }
    }

    /// Test field arithmetic edge cases
    #[test]
    fn test_field_arithmetic_edge_cases() {
        // Test with 0 (should always return 0)
        assert_eq!(
            legendre_prf_secure(F::zero()),
            F::zero(),
            "Legendre PRF of 0 should be 0"
        );

        // Test with 1 (should always return 0 for quadratic residue)
        assert_eq!(
            legendre_prf_secure(F::one()),
            F::zero(),
            "Legendre PRF of 1 should be 0"
        );

        // Test determinism
        let test_val = u128_to_field(42);
        let result1 = legendre_prf_secure(test_val);
        let result2 = legendre_prf_secure(test_val);
        assert_eq!(result1, result2, "Legendre PRF should be deterministic");
    }

    #[test]
    fn test_empty_message_signature() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"";

        let signature = loquat_sign(message, &keypair, &params)
            .expect("Signing an empty message should succeed");
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)
            .expect("Verification should complete");
        assert!(is_valid, "Signature for empty message should be valid");
    }

    #[test]
    fn test_large_message_signature() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = vec![0u8; 10 * 1024]; // 10 KB message

        let signature = loquat_sign(&message, &keypair, &params)
            .expect("Signing a large message should succeed");
        let is_valid = loquat_verify(&message, &signature, &keypair.public_key, &params)
            .expect("Verification should complete");
        assert!(is_valid, "Signature for large message should be valid");
    }

    #[test]
    fn test_tampered_signature_components() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"Tampering test";
        let mut signature =
            loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");

        // Tamper with Merkle root
        signature.root_c[0] ^= 1;
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)
            .expect("Verification should complete");
        assert!(
            !is_valid,
            "Signature with tampered Merkle root should be invalid"
        );
        signature.root_c[0] ^= 1; // Restore

        // Tamper with sumcheck proof
        signature.pi_us.claimed_sum = signature.pi_us.claimed_sum + Fp2::one();
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)
            .expect("Verification should complete");
        assert!(
            !is_valid,
            "Signature with tampered sumcheck proof should be invalid"
        );

        // Tamper with FRI layer commitment
        let mut signature =
            loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");
        signature.ldt_proof.commitments[1][0] ^= 1;
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)
            .expect("Verification should complete");
        assert!(
            !is_valid,
            "Signature with tampered FRI commitment should be invalid"
        );

        // Tamper with LDT opening codeword chunk (openings-only signature format).
        let mut signature =
            loquat_sign(message, &keypair, &params).expect("Signature generation should succeed");
        signature.ldt_proof.openings[0].codeword_chunks[0][0] =
            signature.ldt_proof.openings[0].codeword_chunks[0][0] + F2::one();
        let is_valid = loquat_verify(message, &signature, &keypair.public_key, &params)
            .expect("Verification should complete");
        assert!(
            !is_valid,
            "Signature with tampered LDT codeword chunk should be invalid"
        );
    }

    #[test]
    fn test_bdec_attribute_bound_and_revocation_enforcement() {
        // Use the smallest supported paper level to keep SNARK-heavy BDEC tests tractable.
        let system = bdec_setup(80, 2).expect("Setup should succeed");
        let user_keypair = bdec_prigen(&system).expect("Key generation should succeed");
        let user_nym = bdec_nym_key(&system, &user_keypair).expect("Pseudonym generation failed");

        let valid_attributes = vec!["role:member".to_string(), "status:gold".to_string()];
        let credential =
            bdec_issue_credential(&system, &user_keypair, &user_nym, valid_attributes.clone())
                .expect("Credential issuance within bound should succeed");

        assert!(
            bdec_verify_credential(&system, &credential)
                .expect("Credential verification should succeed"),
            "Fresh credential should verify"
        );

        let too_many_attributes = vec![
            "role:member".to_string(),
            "status:gold".to_string(),
            "extra:field".to_string(),
        ];
        let err = bdec_issue_credential(&system, &user_keypair, &user_nym, too_many_attributes)
            .expect_err("Issuing beyond attribute bound must fail");
        match err {
            LoquatError::InvalidParameters { constraint } => {
                assert_eq!(
                    constraint, "too many attributes for credential",
                    "Error message should indicate attribute overflow"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }

        let mut revoked_system = system.clone();
        bdec_revoke(&mut revoked_system, &user_keypair.public_key)
            .expect("Revocation should succeed");
        assert!(
            !bdec_verify_credential(&revoked_system, &credential)
                .expect("Revocation verification should succeed"),
            "Revoked credential must fail verification"
        );
    }

    #[test]
    fn test_invalid_setup_parameters() {
        assert!(
            loquat_setup(96).is_err(),
            "Setup should fail for unsupported security level"
        );
    }

    #[test]
    fn test_public_key_mismatch() {
        let params = loquat_setup(128).expect("Setup should succeed");
        let keypair1 = keygen_with_params(&params).expect("Keygen should succeed");
        let keypair2 = keygen_with_params(&params).expect("Keygen should succeed");
        let message = b"Public key mismatch test";

        let signature = loquat_sign(message, &keypair1, &params).expect("Signing should succeed");
        let is_valid = loquat_verify(message, &signature, &keypair2.public_key, &params)
            .expect("Verification should complete");
        assert!(
            !is_valid,
            "Verification should fail with a different public key"
        );
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn test_bdec_sign_verify() {
        let system = bdec_setup(80, 8).expect("Setup should succeed");
        let user_keypair = bdec_prigen(&system).expect("Key generation should succeed");
        let user_nym = bdec_nym_key(&system, &user_keypair).expect("Pseudonym generation failed");
        let attributes = vec![
            "degree:ComputerScience".to_string(),
            "year:2024".to_string(),
        ];

        let credential =
            bdec_issue_credential(&system, &user_keypair, &user_nym, attributes.clone())
                .expect("Credential issuance should succeed");
        let valid_credential = bdec_verify_credential(&system, &credential)
            .expect("Credential verification should succeed");
        assert!(valid_credential, "Credential should verify");

        let credential_bundle = vec![credential.clone()];
        let revealed = vec![attributes[0].clone()];

        let shown = bdec_show_credential_paper(
            &system,
            &user_keypair,
            &credential_bundle,
            revealed.clone(),
        )
        .expect("Show credential should succeed");

        let valid_show = bdec_verify_shown_credential_paper(
            &system,
            &shown,
            &shown.verifier_pseudonym.public,
        )
        .expect("Shown credential verification should succeed");
        assert!(valid_show, "Shown credential should verify");

        let mut tampered = shown.clone();
        tampered.verifier_pseudonym.public[0] ^= 1;
        let is_valid = bdec_verify_shown_credential_paper(
            &system,
            &tampered,
            &shown.verifier_pseudonym.public,
        )
        .expect("Tampered verification should complete");
        assert!(!is_valid, "Tampered proof should be rejected");
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn test_bdec_multi_credentials_and_revocation() {
        let mut system = bdec_setup(80, 8).expect("Setup should succeed");
        let user_keypair = bdec_prigen(&system).expect("Key generation should succeed");
        let user_nym_one =
            bdec_nym_key(&system, &user_keypair).expect("Pseudonym generation failed");
        let user_nym_two =
            bdec_nym_key(&system, &user_keypair).expect("Second pseudonym generation failed");

        let attributes_one = vec!["degree:CS".to_string(), "year:2024".to_string()];
        let attributes_two = vec!["issuer:TA2".to_string(), "level:advanced".to_string()];

        let credential_one = bdec_issue_credential(
            &system,
            &user_keypair,
            &user_nym_one,
            attributes_one.clone(),
        )
        .expect("Credential issuance should succeed");
        let credential_two = bdec_issue_credential(
            &system,
            &user_keypair,
            &user_nym_two,
            attributes_two.clone(),
        )
        .expect("Credential issuance should succeed");

        assert!(bdec_verify_credential(&system, &credential_one).unwrap());
        assert!(bdec_verify_credential(&system, &credential_two).unwrap());

        let credential_bundle = vec![credential_one.clone(), credential_two.clone()];
        let revealed = vec![attributes_one[0].clone()];

        let shown = bdec_show_credential_paper(
            &system,
            &user_keypair,
            &credential_bundle,
            revealed.clone(),
        )
        .expect("Show credential should succeed");

        assert!(
            bdec_verify_shown_credential_paper(
                &system,
                &shown,
                &shown.verifier_pseudonym.public,
            )
            .unwrap()
        );

        // Revocation edge case
        bdec_revoke(&mut system, &user_keypair.public_key).expect("revocation should succeed");
        assert!(
            !bdec_verify_shown_credential_paper(
                &system,
                &shown,
                &shown.verifier_pseudonym.public,
            )
            .unwrap()
        );
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn test_secret_key_witness_mismatch() {
        let system = bdec_setup(80, 8).expect("Setup should succeed");
        let user_keypair = bdec_prigen(&system).expect("Key generation should succeed");
        let user_nym = bdec_nym_key(&system, &user_keypair).expect("Pseudonym generation failed");
        let attributes = vec![
            "degree:ComputerScience".to_string(),
            "year:2024".to_string(),
        ];

        let credential =
            bdec_issue_credential(&system, &user_keypair, &user_nym, attributes.clone())
                .expect("Credential issuance should succeed");

        let credential_bundle = vec![credential.clone()];
        let revealed = vec![attributes[0].clone()];

        let shown =
            bdec_show_credential_paper(&system, &user_keypair, &credential_bundle, revealed)
                .expect("Show credential should succeed");

        // Tamper with the SNARK proof to simulate a malformed witness/proof pair.
        let mut tampered = shown.clone();
        tampered.show_proof.witness_root[0] ^= 1;

        let is_valid = bdec_verify_shown_credential_paper(
            &system,
            &tampered,
            &shown.verifier_pseudonym.public,
        )
        .expect("verification should run");
        assert!(!is_valid, "Verifier must reject when the SNARK proof is tampered");
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn test_bdec_show_credential_rejects_mismatched_owner() {
        let system = bdec_setup(80, 4).expect("Setup should succeed");
        let user_a = bdec_prigen(&system).expect("Key generation for user A should succeed");
        let user_b = bdec_prigen(&system).expect("Key generation for user B should succeed");

        let pseudonym_a = bdec_nym_key(&system, &user_a).expect("Pseudonym A generation failed");
        let pseudonym_b = bdec_nym_key(&system, &user_b).expect("Pseudonym B generation failed");

        let credential_a = bdec_issue_credential(
            &system,
            &user_a,
            &pseudonym_a,
            vec!["attr:alpha".to_string()],
        )
        .expect("Credential for user A should succeed");

        let credential_b = bdec_issue_credential(
            &system,
            &user_b,
            &pseudonym_b,
            vec!["attr:beta".to_string()],
        )
        .expect("Credential for user B should succeed");

        let result = bdec_show_credential_paper(
            &system,
            &user_a,
            &[credential_a.clone(), credential_b.clone()],
            vec!["attr:alpha".to_string()],
        );

        match result {
            Ok(shown) => {
                // If the prover attempts to combine credentials from different owners, the
                // resulting SNARK statement should be rejected by ShowVer.
                assert!(
                    !bdec_verify_shown_credential_paper(
                        &system,
                        &shown,
                        &shown.verifier_pseudonym.public,
                    )
                    .expect("ShowVer should run"),
                    "mixed-owner shown credential must be rejected"
                );
            }
            Err(_) => {
                // Either behavior is acceptable here (early failure or later ShowVer rejection).
            }
        }
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn test_bdec_verify_shown_credential_rejects_invalid_journal() {
        let system = bdec_setup(80, 6).expect("Setup should succeed");
        let user_keypair = bdec_prigen(&system).expect("Key generation should succeed");
        let user_nym = bdec_nym_key(&system, &user_keypair).expect("Pseudonym generation failed");
        let attributes = vec!["grade:A".to_string(), "year:2024".to_string()];

        let credential =
            bdec_issue_credential(&system, &user_keypair, &user_nym, attributes.clone())
                .expect("Credential issuance should succeed");

        let credential_bundle = vec![credential.clone()];
        let disclosed = vec![attributes[0].clone()];

        let shown =
            bdec_show_credential_paper(&system, &user_keypair, &credential_bundle, disclosed)
                .expect("Show credential should succeed");

        assert!(
            bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
                .expect("verification should run")
        );

        // Tamper with the disclosed attributes without updating the hash/proof.
        let mut invalid_shown = shown.clone();
        invalid_shown
            .disclosed_attributes
            .push("grade:forged".to_string());

        assert!(
            !bdec_verify_shown_credential_paper(
                &system,
                &invalid_shown,
                &shown.verifier_pseudonym.public,
            )
            .expect("verification should run"),
            "Tampered disclosure must be rejected"
        );
    }

    #[test]
    #[ignore = "expensive matrix: runs multiple Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn test_bdec_attribute_variation_matrix() {
        let system = bdec_setup(80, 16).expect("Setup should succeed");
        let user_keypair = bdec_prigen(&system).expect("Key generation should succeed");
        let user_nym = bdec_nym_key(&system, &user_keypair).expect("Pseudonym generation failed");

        let parameter_sets = &[(1usize, 1usize), (3, 1), (5, 2), (8, 3), (10, 5)];

        for (attribute_count, reveal_count) in parameter_sets {
            let attributes: Vec<String> = (0..*attribute_count)
                .map(|i| format!("attr:{i:02}"))
                .collect();
            let credential =
                bdec_issue_credential(&system, &user_keypair, &user_nym, attributes.clone())
                    .expect("Credential issuance should succeed");

            assert!(
                bdec_verify_credential(&system, &credential).expect("Verification should succeed"),
                "Credential should verify for attribute count {attribute_count}"
            );

            let credential_bundle = vec![credential.clone()];
            let revealed: Vec<String> = attributes.iter().take(*reveal_count).cloned().collect();
            let shown = bdec_show_credential_paper(&system, &user_keypair, &credential_bundle, revealed.clone())
                .expect("Show credential should succeed");

            assert!(
                bdec_verify_shown_credential_paper(&system, &shown, &shown.verifier_pseudonym.public)
                    .expect("Shown credential verification should succeed"),
                "Shown credential should verify for attribute count {attribute_count}"
            );

            let mut tampered_attributes = shown.clone();
            tampered_attributes.credentials[0].attributes[0].push_str(":tamper");
            assert!(
                !bdec_verify_shown_credential_paper(
                    &system,
                    &tampered_attributes,
                    &shown.verifier_pseudonym.public,
                )
                .expect("Tampered verification should run"),
                "Tampered credential must fail verification"
            );

            let mut tampered_disclosure = shown.clone();
            tampered_disclosure
                .disclosed_attributes
                .push("attr:bogus".to_string());
            assert!(
                !bdec_verify_shown_credential_paper(
                    &system,
                    &tampered_disclosure,
                    &shown.verifier_pseudonym.public,
                )
                .expect("Tampered disclosure verification should run"),
                "Disclosure outside attribute set must be rejected"
            );
        }
    }

    #[test]
    #[ignore = "expensive: runs Aurora proofs; run with `cargo test --release -- --ignored`"]
    fn test_bdec_shown_credential_unlinkability_via_fresh_pseudonyms() {
        let system = bdec_setup(80, 8).expect("Setup should succeed");
        let user_keypair = bdec_prigen(&system).expect("Key generation should succeed");
        let user_nym = bdec_nym_key(&system, &user_keypair).expect("Pseudonym generation failed");

        let attributes = vec![
            "attr:alpha".to_string(),
            "attr:beta".to_string(),
            "attr:gamma".to_string(),
        ];

        let credential =
            bdec_issue_credential(&system, &user_keypair, &user_nym, attributes.clone())
                .expect("Credential issuance should succeed");

        let credential_bundle = vec![credential.clone()];
        let revealed = vec![attributes[0].clone()];
        let shown_a =
            bdec_show_credential_paper(&system, &user_keypair, &credential_bundle, revealed.clone())
                .expect("Show credential A should succeed");

        let shown_b =
            bdec_show_credential_paper(&system, &user_keypair, &credential_bundle, revealed.clone())
                .expect("Show credential B should succeed");

        assert_ne!(
            shown_a.verifier_pseudonym.public, shown_b.verifier_pseudonym.public,
            "Verifier pseudonyms must differ for unlinkability"
        );

        assert!(
            bdec_verify_shown_credential_paper(
                &system,
                &shown_a,
                &shown_a.verifier_pseudonym.public
            )
            .expect("Verification for shown A should succeed")
        );
        assert!(
            bdec_verify_shown_credential_paper(
                &system,
                &shown_b,
                &shown_b.verifier_pseudonym.public
            )
            .expect("Verification for shown B should succeed")
        );
    }
    #[test]
    fn test_different_security_levels() {
        // Paper-supported levels for this repo.
        for &lambda in &[80, 100, 128] {
            let params = loquat_setup(lambda).expect(&format!("Setup for {}-bit failed", lambda));
            let keypair =
                keygen_with_params(&params).expect(&format!("Keygen for {}-bit failed", lambda));
            let message = format!("Test message for {}-bit security", lambda).into_bytes();

            let signature = loquat_sign(&message, &keypair, &params)
                .expect(&format!("Signing for {}-bit failed", lambda));
            let is_valid = loquat_verify(&message, &signature, &keypair.public_key, &params)
                .expect(&format!("Verification for {}-bit failed", lambda));
            assert!(
                is_valid,
                "Signature should be valid for {}-bit security level",
                lambda
            );
        }
    }
}
