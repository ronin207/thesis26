#![cfg(feature = "snark_harness")]

use std::sync::OnceLock;

extern crate bincode;

use vc_pqc::{
    bdec::{
        BdecRevocationAccumulator, bdec_issue_credential, bdec_nym_key, bdec_prigen, bdec_setup,
        bdec_setup_zk, bdec_show_credential_paper, bdec_show_credential_with_policy_paper,
        bdec_verify_shown_credential_with_policy_paper,
    },
    evaluation::{PolicyInput, PolicyPredicate},
    loquat::{
        LoquatKeyPair, LoquatPublicParams, LoquatSignature, field_utils::F,
        keygen::keygen_with_params, loquat_setup, loquat_sign,
    },
    snarks::{
        AuroraParams, AuroraProof, AuroraProverOptions, FractalParams, R1csInstance, R1csWitness,
        aurora_prove_with_options, aurora_verify, aurora_verify_with_public_inputs,
        build_loquat_r1cs_pk_witness, build_loquat_r1cs_pk_witness_instance,
        build_revocation_r1cs_pk_witness, fractal_prove, fractal_verify,
    },
};

const HARNESS_SECURITY_LEVEL: usize = 80;

struct HarnessFixture {
    params: LoquatPublicParams,
    keypair: LoquatKeyPair,
    message: Vec<u8>,
    signature: LoquatSignature,
    instance: R1csInstance,
    witness: R1csWitness,
    aurora_params: AuroraParams,
}

static FIXTURE: OnceLock<HarnessFixture> = OnceLock::new();

fn harness_fixture() -> &'static HarnessFixture {
    FIXTURE.get_or_init(|| {
        let params = loquat_setup(HARNESS_SECURITY_LEVEL).expect("Loquat setup should succeed");
        let keypair = keygen_with_params(&params).expect("Key generation should succeed");
        let message = b"SNARK harness message for aggregate soundness".to_vec();
        let signature =
            loquat_sign(&message, &keypair, &params).expect("Signature generation must succeed");
        let (instance, witness) =
            build_loquat_r1cs_pk_witness(&message, &signature, &keypair.public_key, &params)
                .expect("R1CS construction must succeed for valid signature");
        let aurora_params = AuroraParams {
            constraint_query_count: 8,
            witness_query_count: 8,
        };
        HarnessFixture {
            params,
            keypair,
            message,
            signature,
            instance,
            witness,
            aurora_params,
        }
    })
}

#[test]
fn aurora_accepts_valid_signature_witness() {
    let fixture = harness_fixture();
    let proof = aurora_prove_with_options(
        &fixture.instance,
        &fixture.witness,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("Aurora prover should succeed for honest witness");
    let verification = aurora_verify(&fixture.instance, &proof, &fixture.aurora_params, None)
        .expect("Aurora verification should not error");
    assert!(
        verification.is_some(),
        "Valid witness must yield an accepting Aurora proof"
    );
}

#[test]
fn tampered_signature_cannot_enter_snark() {
    let fixture = harness_fixture();
    let mut signature = fixture.signature.clone();
    signature.root_c[0] ^= 1;
    let build_result = build_loquat_r1cs_pk_witness(
        &fixture.message,
        &signature,
        &fixture.keypair.public_key,
        &fixture.params,
    );
    assert!(
        build_result.is_err(),
        "Tampered signature should fail before R1CS construction"
    );
}

/// **Phase 7 — the headline thesis demonstration: compile once, verify many.**
///
/// Build the R1CS instance for *two different Loquat signatures* (same params,
/// same key pair, different messages), and verify:
///
///   1. The R1CS instance digests are **identical** — i.e., the constraint
///      matrix structure (A, B, C) does not depend on the signature being
///      verified. This realizes the SNARK circuit compiler's "compile once"
///      claim: a single set of matrices serves any (message, signature) pair.
///
///   2. **Both** signatures' Aurora proofs verify with their respective public
///      inputs (signature components flow through the PI section). This is
///      "verify many."
///
///   3. **Cross-verification rejects**: a proof generated for signature A,
///      verified with public inputs from signature B, must reject. This
///      demonstrates that the PI enforcement actually binds the proof to a
///      specific signature.
///
/// This is enabled by Phases 5 (in-circuit FS, in-circuit Q̂, in-circuit pk
/// multiplexer) + 6 (Aurora PI enforcement) + 6.2c (drop signature-specific
/// const bindings from the FS function — soundness now flows through Aurora
/// PI + FS chain consistency).
#[test]
#[ignore = "expensive: two Loquat-scale Aurora proves + cross-verification"]
fn aurora_compile_once_verify_many() {
    let params = loquat_setup(HARNESS_SECURITY_LEVEL).expect("Loquat setup");
    let keypair = keygen_with_params(&params).expect("keygen");
    // Use same-length messages — the message-commitment Griffin hash circuit
    // emits a Griffin permutation count that scales with message length, so
    // matrix structure independence requires a fixed message-byte length.
    // (For variable-length deployments, the message would be hashed into a
    // fixed-size commitment outside the circuit before Loquat verification.)
    let message_a = b"compile-once-verify-many message A___".to_vec(); // 37 bytes
    let message_b = b"compile-once-verify-many message B___".to_vec(); // 37 bytes
    assert_eq!(message_a.len(), message_b.len());

    let signature_a = loquat_sign(&message_a, &keypair, &params).expect("sign A");
    let signature_b = loquat_sign(&message_b, &keypair, &params).expect("sign B");

    let (instance_a, witness_a) =
        build_loquat_r1cs_pk_witness(&message_a, &signature_a, &keypair.public_key, &params)
            .expect("build A");
    let (instance_b, witness_b) =
        build_loquat_r1cs_pk_witness(&message_b, &signature_b, &keypair.public_key, &params)
            .expect("build B");

    // (1) **Metadata + digest match** — `num_variables`, `num_inputs`,
    // constraint count, and `instance.digest()` are all identical across two
    // different (message, signature) pairs. This proves the *full R1CS matrix*
    // is signature-independent — the same compiled circuit serves any
    // signature, and the verifier needs to publish only one circuit digest.
    assert_eq!(
        instance_a.num_variables, instance_b.num_variables,
        "num_variables must match across signatures"
    );
    assert_eq!(
        instance_a.num_inputs, instance_b.num_inputs,
        "num_inputs must match across signatures"
    );
    assert_eq!(
        instance_a.constraints.len(),
        instance_b.constraints.len(),
        "constraint count must match across signatures"
    );
    // Phase 7-cleanup: full instance digest equality. After migrating cap-root
    // binding + cap-by-index lookups to PI (with a multiplexer over PI cap-node
    // F²Vars), no signature-specific bytes leak into the constraint matrix.
    assert_eq!(
        instance_a.digest(),
        instance_b.digest(),
        "instance.digest() must match across signatures — circuit is now fully \
         signature-independent and `compile-once, verify-many` is correctly \
         realised at the matrix level"
    );

    let aurora_params = AuroraParams {
        constraint_query_count: 12,
        witness_query_count: 12,
    };

    let proof_a = aurora_prove_with_options(
        &instance_a,
        &witness_a,
        &aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("Aurora prove A");
    let proof_b = aurora_prove_with_options(
        &instance_b,
        &witness_b,
        &aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("Aurora prove B");

    let public_inputs_a: Vec<vc_pqc::loquat::field_utils::F> =
        witness_a.assignment[..instance_a.num_inputs].to_vec();
    let public_inputs_b: Vec<vc_pqc::loquat::field_utils::F> =
        witness_b.assignment[..instance_b.num_inputs].to_vec();

    // (2) Each proof verifies with its own PI vector.
    let verdict_a = aurora_verify_with_public_inputs(
        &instance_a,
        &proof_a,
        &aurora_params,
        None,
        &public_inputs_a,
    )
    .expect("verify A");
    assert!(
        verdict_a.is_some(),
        "proof A must verify with public_inputs_a"
    );

    let verdict_b = aurora_verify_with_public_inputs(
        &instance_b,
        &proof_b,
        &aurora_params,
        None,
        &public_inputs_b,
    )
    .expect("verify B");
    assert!(
        verdict_b.is_some(),
        "proof B must verify with public_inputs_b"
    );

    // (3) Cross-verification: proof A with PI from B → reject. Same instance
    // digest, but the prover's witness Merkle tree commits to PI_A values, so
    // PI_B values won't match the Merkle openings → Aurora rejects.
    let cross_a_with_b_pi = aurora_verify_with_public_inputs(
        &instance_a, // same digest as instance_b
        &proof_a,
        &aurora_params,
        None,
        &public_inputs_b, // wrong PI
    )
    .expect("cross-verify should not error");
    assert!(
        cross_a_with_b_pi.is_none(),
        "proof A with PI_B must reject — Aurora PI enforcement binds proof to specific signature"
    );

    // Symmetric cross check.
    let cross_b_with_a_pi = aurora_verify_with_public_inputs(
        &instance_b,
        &proof_b,
        &aurora_params,
        None,
        &public_inputs_a,
    )
    .expect("cross-verify should not error");
    assert!(
        cross_b_with_a_pi.is_none(),
        "proof B with PI_A must reject"
    );
}

/// Phase 6 (Loquat-scale): demonstrate Aurora PI enforcement on the actual
/// Loquat verification circuit. The PI section (signature components) flows
/// through `aurora_verify_with_public_inputs`. Mismatched PI must reject —
/// proving the cryptographic enforcement (not just structural distinction)
/// works end-to-end on the real circuit.
#[test]
#[ignore = "expensive: Loquat-scale Aurora prove + PI enforcement"]
fn aurora_public_input_enforcement_loquat_scale() {
    let fixture = harness_fixture();
    let proof = aurora_prove_with_options(
        &fixture.instance,
        &fixture.witness,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("Aurora prover should succeed");

    // Extract PI from the witness assignment: positions [0, num_inputs) of
    // `witness.assignment` correspond to assignment positions [1, num_inputs+1]
    // (after the implicit constant-1 at index 0).
    let num_inputs = fixture.instance.num_inputs;
    assert!(
        num_inputs > 0,
        "Loquat-scale instance must have num_inputs > 0 after Phase 5"
    );
    let public_inputs: Vec<vc_pqc::loquat::field_utils::F> =
        fixture.witness.assignment[..num_inputs].to_vec();

    // Matching PI: accept.
    let ok = aurora_verify_with_public_inputs(
        &fixture.instance,
        &proof,
        &fixture.aurora_params,
        None,
        &public_inputs,
    )
    .expect("verification should not error");
    assert!(
        ok.is_some(),
        "PI-matching Aurora verification on Loquat-scale circuit must accept"
    );

    // Mismatched PI: reject. Flip the first PI value.
    let mut bad_pi = public_inputs.clone();
    bad_pi[0] = bad_pi[0] + vc_pqc::loquat::field_utils::F::one();
    let bad = aurora_verify_with_public_inputs(
        &fixture.instance,
        &proof,
        &fixture.aurora_params,
        None,
        &bad_pi,
    )
    .expect("verification should not error on bad PI");
    assert!(
        bad.is_none(),
        "PI-mismatching Aurora verification on Loquat-scale circuit must reject"
    );
}

#[test]
fn tampered_witness_fails_aurora_verification() {
    let fixture = harness_fixture();
    let instance = &fixture.instance;
    let witness = &fixture.witness;

    // Produce a proof for the honest witness.
    let mut proof = aurora_prove_with_options(
        instance,
        witness,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("Aurora prover should succeed for honest inputs");

    // Corrupt the proof: tamper with the residual root commitment.
    proof.residual_root[0] ^= 0xff;

    let verification =
        aurora_verify(instance, &proof, &fixture.aurora_params, None).expect("verification step");
    assert!(
        verification.is_none(),
        "Corrupted proof must be rejected by Aurora"
    );
}

#[test]
fn pk_witness_instance_matches_instance_only_digest() {
    let params = loquat_setup(HARNESS_SECURITY_LEVEL).expect("Loquat setup should succeed");
    let keypair = keygen_with_params(&params).expect("Key generation should succeed");
    let message = b"pk-witness instance digest check".to_vec();
    let signature = loquat_sign(&message, &keypair, &params).expect("Signature generation");

    let (with_pk_instance, _with_pk_witness) =
        build_loquat_r1cs_pk_witness(&message, &signature, &keypair.public_key, &params)
            .expect("pk-witness circuit should build");
    let instance_only = build_loquat_r1cs_pk_witness_instance(&message, &signature, &params)
        .expect("instance-only build");

    assert_eq!(
        with_pk_instance.num_variables, instance_only.num_variables,
        "instance-only builder must match prover instance variable count"
    );
    assert_eq!(
        with_pk_instance.constraints.len(),
        instance_only.constraints.len(),
        "instance-only builder must match prover instance constraint count"
    );
    assert_eq!(
        with_pk_instance.digest(),
        instance_only.digest(),
        "verifier instance digest must match prover instance digest"
    );
}

// ── Additional security-level fixtures ───────────────────────────────────────

struct LevelFixture {
    params: LoquatPublicParams,
    keypair: LoquatKeyPair,
    message: Vec<u8>,
    signature: LoquatSignature,
    instance: R1csInstance,
    witness: R1csWitness,
    aurora_params: AuroraParams,
}

fn make_level_fixture(lambda: usize) -> LevelFixture {
    let params = loquat_setup(lambda).expect("Loquat setup");
    let keypair = keygen_with_params(&params).expect("keygen");
    let message = format!("SNARK harness level-{lambda}").into_bytes();
    let signature = loquat_sign(&message, &keypair, &params).expect("sign");
    let (instance, witness) =
        build_loquat_r1cs_pk_witness(&message, &signature, &keypair.public_key, &params)
            .expect("R1CS construction");
    let aurora_params = AuroraParams {
        constraint_query_count: 8,
        witness_query_count: 8,
    };
    LevelFixture { params, keypair, message, signature, instance, witness, aurora_params }
}

#[test]
#[ignore = "expensive: Aurora proving path at security level 100"]
fn aurora_accepts_valid_signature_at_level_100() {
    let f = make_level_fixture(100);
    let proof = aurora_prove_with_options(
        &f.instance,
        &f.witness,
        &f.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("prove level-100");
    let result = aurora_verify(&f.instance, &proof, &f.aurora_params, None)
        .expect("verify level-100");
    assert!(result.is_some(), "valid level-100 witness must yield accepting proof");
}

#[test]
#[ignore = "expensive: Aurora proving path at security level 128"]
fn aurora_accepts_valid_signature_at_level_128() {
    let f = make_level_fixture(128);
    let proof = aurora_prove_with_options(
        &f.instance,
        &f.witness,
        &f.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("prove level-128");
    let result = aurora_verify(&f.instance, &proof, &f.aurora_params, None)
        .expect("verify level-128");
    assert!(result.is_some(), "valid level-128 witness must yield accepting proof");
}

// ── Multi-credential (k = 2) ──────────────────────────────────────────────────

#[test]
#[ignore = "expensive: two independent Aurora proving paths"]
fn aurora_proves_two_independent_credentials_same_keypair() {
    // For each credential the prover builds a fresh pk-witness circuit and proves it
    // independently.  A merged proof (à la the ShowVer circuit) is tested in the BDEC
    // integration tests; here we verify that the underlying Aurora primitive is correct
    // for two distinct signature-over-different-messages scenarios.
    let fixture = harness_fixture();
    let msg_a = b"credential-0-message".to_vec();
    let msg_b = b"credential-1-message".to_vec();
    let sig_a = loquat_sign(&msg_a, &fixture.keypair, &fixture.params).expect("sign cred 0");
    let sig_b = loquat_sign(&msg_b, &fixture.keypair, &fixture.params).expect("sign cred 1");

    let (inst_a, wit_a) =
        build_loquat_r1cs_pk_witness(&msg_a, &sig_a, &fixture.keypair.public_key, &fixture.params)
            .expect("r1cs cred 0");
    let (inst_b, wit_b) =
        build_loquat_r1cs_pk_witness(&msg_b, &sig_b, &fixture.keypair.public_key, &fixture.params)
            .expect("r1cs cred 1");

    let proof_a = aurora_prove_with_options(
        &inst_a,
        &wit_a,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("prove cred 0");
    let proof_b = aurora_prove_with_options(
        &inst_b,
        &wit_b,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("prove cred 1");

    assert!(
        aurora_verify(&inst_a, &proof_a, &fixture.aurora_params, None)
            .expect("verify cred 0")
            .is_some(),
        "credential-0 proof must verify"
    );
    assert!(
        aurora_verify(&inst_b, &proof_b, &fixture.aurora_params, None)
            .expect("verify cred 1")
            .is_some(),
        "credential-1 proof must verify"
    );
    // Cross-verify: proof_a must not validate against credential-1's *PI*.
    //
    // Phase 7-cleanup: `inst_a.digest() == inst_b.digest()` — the R1CS matrix is
    // now fully signature-independent (compile-once-verify-many). So `aurora_verify`
    // (no PI) cannot discriminate between the two credentials at the matrix
    // level. The cryptographic discrimination flows through the public-input
    // mechanism: Aurora binds the proof's witness Merkle openings to the
    // verifier-supplied PI vector, and the prover's PI for credential-0 differs
    // from credential-1's PI. We therefore use `aurora_verify_with_public_inputs`
    // and supply credential-1's PI; the proof must reject.
    let public_inputs_b: Vec<vc_pqc::loquat::field_utils::F> =
        wit_b.assignment[..inst_b.num_inputs].to_vec();
    assert!(
        aurora_verify_with_public_inputs(
            &inst_b,
            &proof_a,
            &fixture.aurora_params,
            None,
            &public_inputs_b,
        )
        .expect("cross-verify with PI must not error")
        .is_none(),
        "proof for credential-0 must not verify under credential-1's PI"
    );
}

// ── Revocation non-membership via Aurora ─────────────────────────────────────

#[test]
#[ignore = "expensive: Aurora proving path for revocation R1CS"]
fn aurora_proves_revocation_non_membership() {
    // Set up a ZK-revocation-enabled system (depth 10 leaves ~1024 capacity).
    let system = bdec_setup_zk(HARNESS_SECURITY_LEVEL, 8, 10).expect("bdec_setup_zk");
    let user = bdec_prigen(&system).expect("prigen");
    let acc = system.revocation_accumulator.as_ref().expect("accumulator");

    let root = acc.root();
    let depth = acc.depth();
    let auth_path = acc.auth_path(&user.public_key).expect("auth path");

    // The revocation accumulator is empty (user is not revoked); the auth path proves
    // the leaf for this user's prefix-index is 0 (vacant).
    let (instance, witness) =
        build_revocation_r1cs_pk_witness(&user.public_key, &root, &auth_path, depth)
            .expect("build revocation r1cs");

    let aurora_params = AuroraParams {
        constraint_query_count: 4,
        witness_query_count: 4,
    };
    let proof = aurora_prove_with_options(
        &instance,
        &witness,
        &aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("prove revocation non-membership");
    let result = aurora_verify(&instance, &proof, &aurora_params, None)
        .expect("verify revocation non-membership");
    assert!(
        result.is_some(),
        "revocation non-membership proof must be accepted by Aurora verifier"
    );
}

// ── Policy constraint through BDEC ShowVer ────────────────────────────────────

#[test]
#[ignore = "expensive: Aurora proving path for policy-bound ShowVer circuit"]
fn aurora_proves_policy_constraint_inside_showver() {
    // Use the full BDEC layer to issue a credential and show it under a policy.
    // This exercises the Aurora sub-proof inside ShowVer that enforces predicates.
    let system = bdec_setup_zk(HARNESS_SECURITY_LEVEL, 8, 10).expect("setup");
    let user = bdec_prigen(&system).expect("prigen");
    let ta_nym = bdec_nym_key(&system, &user).expect("ta nym");
    let credential = bdec_issue_credential(
        &system,
        &user,
        &ta_nym,
        vec!["gpa:35".to_string(), "degree:CS".to_string()],
    )
    .expect("issue credential");

    let policy = PolicyInput {
        predicates: vec![
            PolicyPredicate::GteI64 { key: "gpa".to_string(), min_value: 30 },
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
        &policy,
    )
    .expect("show with policy");

    assert!(
        bdec_verify_shown_credential_with_policy_paper(
            &system,
            &shown,
            &shown.verifier_pseudonym.public,
            &policy,
        )
        .expect("verify policy-bound proof"),
        "ShowVer Aurora proof must verify when policy predicate is satisfied"
    );

    // A mismatched policy must not verify against the same proof.
    let different_policy = PolicyInput {
        predicates: vec![PolicyPredicate::GteI64 {
            key: "gpa".to_string(),
            min_value: 40, // stricter than the credential's gpa:35
        }],
    };
    assert!(
        !bdec_verify_shown_credential_with_policy_paper(
            &system,
            &shown,
            &shown.verifier_pseudonym.public,
            &different_policy,
        )
        .expect("verify with stricter policy"),
        "ShowVer proof must not verify when policy predicate is not satisfied"
    );
}

// ── Fractal (recursive Aurora) ────────────────────────────────────────────────

#[test]
#[ignore = "expensive: Fractal recursive Aurora proving path"]
fn fractal_proves_loquat_signature_witness() {
    let fixture = harness_fixture();
    // Use a lighter Aurora configuration inside Fractal to keep the test tractable.
    let params = FractalParams {
        aurora: AuroraParams {
            constraint_query_count: 4,
            witness_query_count: 4,
        },
        recursion_layers: 1,
    };
    let proof = fractal_prove(&fixture.instance, &fixture.witness, &params)
        .expect("Fractal prove should succeed for a valid Loquat witness");
    assert!(
        fractal_verify(&fixture.instance, &proof, &params)
            .expect("Fractal verify should not error"),
        "Fractal proof for valid Loquat witness must be accepted"
    );
}

#[test]
#[ignore = "expensive: Fractal recursive Aurora proving path"]
fn fractal_rejects_tampered_witness() {
    let fixture = harness_fixture();
    // Build with a different keypair so the constraints are violated.
    let other_keypair = keygen_with_params(&fixture.params).expect("keygen other");
    match build_loquat_r1cs_pk_witness(
        &fixture.message,
        &fixture.signature,
        &other_keypair.public_key, // wrong pk
        &fixture.params,
    ) {
        Ok((wrong_instance, wrong_witness)) => {
            let params = FractalParams {
                aurora: AuroraParams {
                    constraint_query_count: 4,
                    witness_query_count: 4,
                },
                recursion_layers: 1,
            };
            // Prove under the wrong instance (may succeed — prover is honest about residuals).
            if let Ok(proof) = fractal_prove(&wrong_instance, &wrong_witness, &params) {
                // The proof is valid for the wrong instance but not for the correct one.
                let correct_verdict =
                    fractal_verify(&fixture.instance, &proof, &params).unwrap_or(false);
                assert!(!correct_verdict, "Fractal proof for wrong pk must not verify under correct instance");
            }
        }
        Err(_) => {
            // If R1CS build itself fails for the wrong pk, that is a valid outcome.
        }
    }
}

// ── Proof size bounds ─────────────────────────────────────────────────────────

#[test]
#[ignore = "expensive: Aurora proving path for proof-size measurement"]
fn aurora_proof_size_is_within_expected_bounds() {
    // Measure serialised proof size for a λ=80 Loquat circuit.
    // Lower bound: a non-trivial Merkle+sumcheck proof must exceed 1 KiB.
    // Upper bound: guard against accidental O(n²) blowup.
    let fixture = harness_fixture();
    let proof = aurora_prove_with_options(
        &fixture.instance,
        &fixture.witness,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("prove for size measurement");
    let bytes =
        bincode::serialize(&proof).expect("bincode serialization of AuroraProof must succeed");
    assert!(
        bytes.len() >= 1_024,
        "Aurora proof ({} B) is suspiciously small; expected ≥ 1 KiB",
        bytes.len()
    );
    assert!(
        bytes.len() <= 64 * 1024 * 1024,
        "Aurora proof ({} B) exceeds 64 MiB; likely an O(n²) blowup",
        bytes.len()
    );
    // Print for manual inspection so paper figures can be cross-checked.
    eprintln!(
        "[proof-size] λ=80 Aurora proof: {} bytes ({:.1} KiB)",
        bytes.len(),
        bytes.len() as f64 / 1024.0
    );
}

// ── Wrong public key negative test ────────────────────────────────────────────

#[test]
#[ignore = "expensive: Aurora proving path for wrong-pk negative test"]
fn wrong_public_key_fails_aurora_verification() {
    // The Aurora transcript commits to the R1CS instance digest (which depends on the pk
    // used to build the circuit).  A proof built for instance_A cannot verify under
    // instance_B even if both were built from the same message and signature.
    let fixture = harness_fixture();

    // Honest proof under fixture.instance (built with fixture.keypair.public_key).
    let honest_proof = aurora_prove_with_options(
        &fixture.instance,
        &fixture.witness,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("honest prove");

    // Build an instance with a different keypair's public key.
    let other_keypair = keygen_with_params(&fixture.params).expect("keygen other");
    match build_loquat_r1cs_pk_witness(
        &fixture.message,
        &fixture.signature,
        &other_keypair.public_key,
        &fixture.params,
    ) {
        Ok((wrong_instance, _)) => {
            // The instance digest differs from fixture.instance → transcript mismatch.
            let result = aurora_verify(&wrong_instance, &honest_proof, &fixture.aurora_params, None)
                .expect("verify under wrong instance should not error");
            assert!(
                result.is_none(),
                "proof built for keypair A must not verify under keypair B's instance"
            );
        }
        Err(_) => {
            // If build_loquat_r1cs fails at build time for the wrong pk, that too is a
            // sound outcome (the circuit builder detects the key mismatch).
        }
    }
}

#[test]
fn pk_witness_instance_structure_does_not_depend_on_pk_values() {
    let params = loquat_setup(HARNESS_SECURITY_LEVEL).expect("Loquat setup should succeed");
    let keypair_a = keygen_with_params(&params).expect("keygen A");
    let keypair_b = keygen_with_params(&params).expect("keygen B");
    let message = b"pk-witness structural check".to_vec();

    let signature_a = loquat_sign(&message, &keypair_a, &params).expect("sign A");
    let signature_b = loquat_sign(&message, &keypair_b, &params).expect("sign B");

    let (instance_a, _) =
        build_loquat_r1cs_pk_witness(&message, &signature_a, &keypair_a.public_key, &params)
            .expect("pk-witness circuit (A)");
    let (instance_b, _) =
        build_loquat_r1cs_pk_witness(&message, &signature_b, &keypair_b.public_key, &params)
            .expect("pk-witness circuit (B)");

    assert_eq!(
        instance_a.num_variables, instance_b.num_variables,
        "pk-witness circuit variable count must be pk-independent"
    );
    assert_eq!(
        instance_a.constraints.len(),
        instance_b.constraints.len(),
        "pk-witness circuit constraint count must be pk-independent"
    );
}
