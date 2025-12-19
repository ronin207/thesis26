#![cfg(feature = "snark_harness")]

use std::sync::OnceLock;

use vc_pqc::{
    loquat::{
        LoquatKeyPair, LoquatPublicParams, LoquatSignature, field_utils::F,
        keygen::keygen_with_params, loquat_setup, loquat_sign,
    },
    snarks::{
        AuroraParams, AuroraProverOptions, R1csInstance, R1csWitness, aurora_prove_with_options,
        aurora_verify, build_loquat_r1cs, build_loquat_r1cs_pk_witness,
        build_loquat_r1cs_pk_witness_instance,
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
            build_loquat_r1cs(&message, &signature, &keypair.public_key, &params)
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
    let build_result = build_loquat_r1cs(
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

#[test]
fn tampered_witness_fails_aurora_verification() {
    let fixture = harness_fixture();
    let instance = &fixture.instance;
    let mut witness = fixture.witness.clone();
    if let Some(slot) = witness.assignment.get_mut(0) {
        *slot += F::one();
    }

    let proof = aurora_prove_with_options(
        &instance,
        &witness,
        &fixture.aurora_params,
        &AuroraProverOptions::default(),
    )
    .expect("Aurora prover should emit a proof even for malformed witnesses");
    let verification = aurora_verify(&instance, &proof, &fixture.aurora_params, None)
        .expect("Aurora verification should not error");
    assert!(
        verification.is_none(),
        "Aggregated proof with inconsistent witness must be rejected"
    );
}

#[test]
fn pk_witness_instance_matches_instance_only_digest() {
    let params = loquat_setup(HARNESS_SECURITY_LEVEL).expect("Loquat setup should succeed");
    let keypair = keygen_with_params(&params).expect("Key generation should succeed");
    let message = b"pk-witness instance digest check".to_vec();
    let signature = loquat_sign(&message, &keypair, &params).expect("Signature generation");

    let (with_pk_instance, _with_pk_witness) = build_loquat_r1cs_pk_witness(
        &message,
        &signature,
        &keypair.public_key,
        &params,
    )
    .expect("pk-witness circuit should build");
    let instance_only =
        build_loquat_r1cs_pk_witness_instance(&message, &signature, &params).expect("instance-only build");

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

#[test]
fn pk_witness_instance_digest_is_independent_of_pk_values() {
    let params = loquat_setup(HARNESS_SECURITY_LEVEL).expect("Loquat setup should succeed");
    let keypair = keygen_with_params(&params).expect("Key generation should succeed");
    let message = b"pk-witness digest independence".to_vec();
    let signature = loquat_sign(&message, &keypair, &params).expect("Signature generation");

    let (instance_a, _) = build_loquat_r1cs_pk_witness(&message, &signature, &keypair.public_key, &params)
        .expect("pk-witness circuit build A");

    // Flip one pk bit to ensure a different witness value, then rebuild the instance.
    // The resulting *instance* must be identical: circuit structure must not depend on pk witness values.
    let mut pk_b = keypair.public_key.clone();
    if let Some(bit) = pk_b.get_mut(0) {
        *bit = if bit.is_zero() { F::one() } else { F::zero() };
    }
    let (instance_b, _) = build_loquat_r1cs_pk_witness(&message, &signature, &pk_b, &params)
        .expect("pk-witness circuit build B");

    assert_eq!(
        instance_a.digest(),
        instance_b.digest(),
        "pk-witness circuit structure must not depend on pk values"
    );
}
